//! Configuration file support (`redan.toml`).
//!
//! Looks for `redan.toml` in the current directory, then
//! `~/.config/redan/config.toml`. CLI flags override file values.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Top-level config file structure.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub image: Option<ImageConfig>,
    pub exec: Option<ExecConfig>,

    #[serde(default)]
    pub mount: Vec<MountConfig>,

    #[serde(default)]
    pub secret: Vec<SecretConfig>,

    #[serde(default)]
    pub allow_host: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageConfig {
    pub name: Option<String>,
    pub rootfs: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecConfig {
    pub command: Option<String>,
    pub timeout: Option<u64>,
    pub interactive: Option<bool>,
    pub log_file: Option<String>,
    pub audit_log: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountConfig {
    pub source: String,
    pub target: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretConfig {
    pub env: String,
    /// Literal value or provider URI (vault://...).
    pub value: String,
    pub hosts: Vec<String>,
}

impl SecretConfig {
    /// Convert to the CLI --secret format: `ENV=value:host1,host2`
    pub fn to_spec(&self) -> String {
        format!("{}={}:{}", self.env, self.value, self.hosts.join(","))
    }
}

impl MountConfig {
    /// Convert to the CLI --mount format: `source:target`
    pub fn to_spec(&self) -> String {
        match &self.target {
            Some(t) => format!("{}:{}", self.source, t),
            None => self.source.clone(),
        }
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
        assert!(config.secret.is_empty());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
allow_host = ["registry.npmjs.org"]

[image]
name = "claude-code"

[exec]
command = "claude --print 'hello'"
timeout = 3600
interactive = false

[[mount]]
source = "."
target = "/workspace"

[[secret]]
env = "API_KEY"
value = "sk-ant-123"
hosts = ["api.anthropic.com"]

[[secret]]
env = "GH_TOKEN"
value = "vault://ci/github#token"
hosts = ["api.github.com", "github.com"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.image.unwrap().name.unwrap(), "claude-code");
        assert_eq!(config.secret.len(), 2);
        assert_eq!(
            config.secret[0].to_spec(),
            "API_KEY=sk-ant-123:api.anthropic.com"
        );
        assert_eq!(config.mount[0].to_spec(), ".:/workspace");
        assert_eq!(config.allow_host, vec!["registry.npmjs.org"]);
    }

    #[test]
    fn reject_unknown_fields() {
        let result: Result<Config, _> = toml::from_str("[bogus]\nfoo = 1");
        assert!(result.is_err());
    }

    #[test]
    fn secret_to_spec_multiple_hosts() {
        let s = SecretConfig {
            env: "KEY".into(),
            value: "val".into(),
            hosts: vec!["a.com".into(), "b.com".into()],
        };
        assert_eq!(s.to_spec(), "KEY=val:a.com,b.com");
    }
}
