//! Configuration file support (`redan.toml`).
//!
//! Looks for `redan.toml` in the current directory, then
//! `~/.config/redan/config.toml`. CLI flags override file values.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Top-level config file structure.
///
/// ```toml
/// image = "claude-code"
/// command = "claude --dangerously-skip-permissions"
/// timeout = 3600
///
/// [network]
/// allow = ["api.anthropic.com"]
///
/// [secrets.ANTHROPIC_API_KEY]
/// value = "sk-ant-..."
/// hosts = ["api.anthropic.com"]
///
/// [mount.workspace]
/// source = "."
/// ```
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Named image (from `redan image create`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Root filesystem path (alternative to image)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<String>,
    /// Command to run in the guest
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Proxy timeout in seconds (0 = no timeout)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Interactive mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interactive: Option<bool>,
    /// Path for structured audit log
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_log: Option<String>,
    /// Path for proxy/VM debug logs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,

    /// Network policy
    #[serde(default, skip_serializing_if = "NetworkConfig::is_empty")]
    pub network: NetworkConfig,

    /// Secret definitions, keyed by environment variable name
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, SecretConfig>,

    /// Mount definitions, keyed by tag name
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mount: BTreeMap<String, MountConfig>,

    /// Extra environment variables for the guest
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Allowed outbound hosts. Empty = deny all (default-deny).
    #[serde(default)]
    pub allow: Vec<String>,
}

impl NetworkConfig {
    fn is_empty(&self) -> bool {
        self.allow.is_empty()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretConfig {
    /// Literal value or provider URI (vault://...).
    pub value: String,
    /// Hosts this secret may be injected for.
    pub hosts: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountConfig {
    /// Host path to mount.
    pub source: String,
    /// Guest mount point (default: /workspace).
    pub target: Option<String>,
}

impl Config {
    /// Convert secrets map to CLI --secret spec format.
    /// Skips secrets with empty hosts (invalid spec).
    pub fn secret_specs(&self) -> Vec<String> {
        self.secrets
            .iter()
            .filter(|(_, s)| !s.hosts.is_empty())
            .map(|(name, s)| format!("{name}={}:{}", s.value, s.hosts.join(",")))
            .collect()
    }

    /// Convert mounts map to CLI --mount spec format.
    pub fn mount_specs(&self) -> Vec<String> {
        self.mount
            .values()
            .map(|m| match &m.target {
                Some(t) => format!("{}:{t}", m.source),
                None => m.source.clone(),
            })
            .collect()
    }

    /// Serialize to TOML string.
    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(self).map_err(|e| e.to_string())
    }
}

/// Search for a config file. Returns the path and parsed config,
/// or None if no config file exists.
pub fn find_and_load() -> Option<(PathBuf, Config)> {
    let candidates = config_paths();
    for path in candidates {
        if path.is_file() {
            match load(&path) {
                Ok(config) => return Some((path, config)),
                Err(e) => {
                    eprintln!("warning: failed to parse {}: {e}", path.display());
                    return None;
                }
            }
        }
    }
    None
}

fn config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("redan.toml")];
    if let Some(config_dir) = dirs_path() {
        paths.push(config_dir.join("config.toml"));
    }
    paths
}

fn dirs_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| Path::new(&h).join(".config/redan"))
}

fn load(path: &Path) -> Result<Config, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    toml::from_str(&content).map_err(|e| format!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.image.is_none());
        assert!(config.secrets.is_empty());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
image = "claude-code"
command = "claude --print 'hello'"
timeout = 3600
interactive = false

[network]
allow = ["registry.npmjs.org"]

[secrets.API_KEY]
value = "sk-ant-123"
hosts = ["api.anthropic.com"]

[secrets.GH_TOKEN]
value = "vault://ci/github#token"
hosts = ["api.github.com", "github.com"]

[mount.workspace]
source = "."
target = "/workspace"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.image.as_deref(), Some("claude-code"));
        assert_eq!(config.secrets.len(), 2);

        let specs = config.secret_specs();
        assert!(specs.contains(&"API_KEY=sk-ant-123:api.anthropic.com".to_string()));

        let mounts = config.mount_specs();
        assert_eq!(mounts, vec![".:/workspace"]);

        assert_eq!(config.network.allow, vec!["registry.npmjs.org"]);
    }

    #[test]
    fn reject_unknown_fields() {
        let result: Result<Config, _> = toml::from_str("[bogus]\nfoo = 1");
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_to_toml() {
        let mut config = Config::default();
        config.image = Some("dev".into());
        config.command = Some("bash".into());
        config.network.allow.push("api.github.com".into());
        config.secrets.insert(
            "TOKEN".into(),
            SecretConfig {
                value: "ghp_abc".into(),
                hosts: vec!["api.github.com".into()],
            },
        );
        config.mount.insert(
            "workspace".into(),
            MountConfig {
                source: ".".into(),
                target: Some("/workspace".into()),
            },
        );

        let toml_str = config.to_toml().unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.image.as_deref(), Some("dev"));
        assert_eq!(parsed.secrets.len(), 1);
        assert_eq!(parsed.mount.len(), 1);
    }

    #[test]
    fn image_only_config() {
        let config: Config = toml::from_str("image = \"dev\"").unwrap();
        assert_eq!(config.image.as_deref(), Some("dev"));
        assert!(config.secrets.is_empty());
        assert!(config.network.allow.is_empty());
    }
}
