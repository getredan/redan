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
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    pub image: Option<String>,
    pub rootfs: Option<String>,
    pub command: Option<String>,
    pub timeout: Option<u64>,
    pub interactive: Option<bool>,
    pub audit_log: Option<String>,
    pub log_file: Option<String>,

    #[serde(default)]
    pub network: NetworkConfig,

    #[serde(default)]
    pub secrets: BTreeMap<String, SecretConfig>,

    #[serde(default)]
    pub mount: BTreeMap<String, MountConfig>,

    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SecretConfig {
    pub value: String,
    pub hosts: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MountConfig {
    pub source: String,
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
                    eprintln!("error: failed to parse {}: {e}", path.display());
                    std::process::exit(1);
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
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
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
    fn image_only_config() {
        let config: Config = toml::from_str("image = \"dev\"").unwrap();
        assert_eq!(config.image.as_deref(), Some("dev"));
        assert!(config.secrets.is_empty());
        assert!(config.network.allow.is_empty());
    }

    #[test]
    fn unknown_fields_ignored() {
        let config: Config = toml::from_str("image = \"dev\"\ncustom_field = true").unwrap();
        assert_eq!(config.image.as_deref(), Some("dev"));
    }
}
