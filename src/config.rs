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
/// value = "env://ANTHROPIC_API_KEY"
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
    /// TCP port forwards: `"9222"` or `"9222:3000"` (`guest_port:host_port`).
    #[serde(default)]
    pub forward: Vec<String>,
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
    #[serde(default)]
    pub read_only: bool,
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
            .map(|m| {
                let base = m
                    .target
                    .as_ref()
                    .map_or_else(|| m.source.clone(), |t| format!("{}:{t}", m.source));
                if m.read_only {
                    format!("{base}:ro")
                } else {
                    base
                }
            })
            .collect()
    }
}

/// Layer `top` over `base`, returning the merged config (`top` wins conflicts).
///
/// Used so `redan run <agent>` honors a project `redan.toml`: the agent profile
/// is the `base` (a set of defaults) and the file is `top`, so explicit project
/// config overrides the agent's defaults. This matches the usual precedence of
/// built-in defaults < config file < CLI flags.
///
/// Merge rules:
/// - Scalar fields (`image`, `command`, `timeout`, ...): `top` wins when it
///   sets the field, otherwise `base` is kept.
/// - `network.allow` / `network.forward`: unioned, preserving order, `base`
///   entries first, duplicates dropped.
/// - `secrets` / `mount` / `env` maps: unioned, with `top` winning on key
///   collisions.
#[must_use]
pub fn overlay(base: Config, top: Config) -> Config {
    let mut allow = base.network.allow;
    for host in top.network.allow {
        if !allow.contains(&host) {
            allow.push(host);
        }
    }
    let mut forward = base.network.forward;
    for spec in top.network.forward {
        if !forward.contains(&spec) {
            forward.push(spec);
        }
    }

    let mut secrets = base.secrets;
    secrets.extend(top.secrets);
    let mut mount = base.mount;
    mount.extend(top.mount);
    let mut env = base.env;
    env.extend(top.env);

    Config {
        // Scalars: `top` wins when set, else `base` is kept. This deliberately
        // includes `image` and `command`: for `redan run`, the agent profile is
        // only a default (`base`), so a project `redan.toml` (`top`) may override
        // even those. Precedence stays agent defaults < redan.toml < CLI.
        image: top.image.or(base.image),
        rootfs: top.rootfs.or(base.rootfs),
        command: top.command.or(base.command),
        timeout: top.timeout.or(base.timeout),
        interactive: top.interactive.or(base.interactive),
        audit_log: top.audit_log.or(base.audit_log),
        log_file: top.log_file.or(base.log_file),
        network: NetworkConfig { allow, forward },
        secrets,
        mount,
        env,
    }
}

/// Read `sandbox.network.allowedDomains` from Claude Code settings.
/// Checks project-level `.claude/settings.local.json` first, then
/// user-level `~/.claude/settings.json`. Returns the merged domain list.
pub fn claude_allowed_domains() -> Vec<String> {
    let mut domains = Vec::new();

    // Project-level (higher specificity, checked first)
    if let Some(d) = read_claude_settings(Path::new(".claude/settings.local.json")) {
        domains.extend(d);
    }
    if let Some(d) = read_claude_settings(Path::new(".claude/settings.json")) {
        domains.extend(d);
    }

    // User-level
    if let Some(home) = std::env::var_os("HOME") {
        let home = Path::new(&home);
        if let Some(d) = read_claude_settings(&home.join(".claude/settings.local.json")) {
            domains.extend(d);
        }
        if let Some(d) = read_claude_settings(&home.join(".claude/settings.json")) {
            domains.extend(d);
        }
    }

    domains.sort();
    domains.dedup();
    domains
}

fn read_claude_settings(path: &Path) -> Option<Vec<String>> {
    let content = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;
    let domains = value
        .get("sandbox")?
        .get("network")?
        .get("allowedDomains")?
        .as_array()?;
    Some(
        domains
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
    )
}

/// Where a discovered config came from.
///
/// Project configs (a cwd `redan.toml`) are trust-gated; user configs
/// (`~/.config/redan/config.toml`) are implicitly trusted, since you placed
/// them in your own home directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    Project,
    User,
}

/// A config file found on disk.
///
/// Read once, so the raw bytes are available for the trust hash.
pub struct DiscoveredConfig {
    pub path: PathBuf,
    pub content: String,
    pub config: Config,
    pub source: ConfigSource,
}

/// Find and read the first existing config file.
///
/// Looks for a cwd `redan.toml`, then `~/.config/redan/config.toml`, reading it
/// once so the raw content is available alongside the parsed config. Exits on a
/// parse error; returns `None` if no config file exists.
///
/// This is raw discovery: a project config is **not** trust-checked here.
/// Callers that act on a cwd config must go through the trust gate
/// (`cmd::trust::load_config`) rather than calling this directly.
pub fn discover() -> Option<DiscoveredConfig> {
    for (path, source) in config_candidates() {
        if !path.is_file() {
            continue;
        }
        let content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("error: cannot read {}: {e}", path.display());
            std::process::exit(1);
        });
        let config: Config = toml::from_str(&content).unwrap_or_else(|e| {
            eprintln!("error: failed to parse {}: {e}", path.display());
            std::process::exit(1);
        });
        if !config.secrets.is_empty() {
            warn_if_world_readable(&path);
        }
        return Some(DiscoveredConfig {
            path,
            content,
            config,
            source,
        });
    }
    None
}

/// Warn if a file containing secrets is readable by other users.
#[cfg(unix)]
fn warn_if_world_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            eprintln!(
                "warning: {} contains secrets and is accessible by other users (mode {:o}). \
                 Consider chmod 600.",
                path.display(),
                mode & 0o777
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_world_readable(_path: &Path) {}

fn config_candidates() -> Vec<(PathBuf, ConfigSource)> {
    let mut paths = vec![(PathBuf::from("redan.toml"), ConfigSource::Project)];
    if let Some(config_dir) = dirs_path() {
        paths.push((config_dir.join("config.toml"), ConfigSource::User));
    }
    paths
}

fn dirs_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| Path::new(&home).join(".config/redan"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    #[test]
    fn read_claude_settings_with_domains() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"sandbox": {"network": {"allowedDomains": ["github.com", "*.npmjs.org"]}}}"#,
        )
        .unwrap();
        let domains = read_claude_settings(&path).unwrap();
        assert_eq!(domains, vec!["github.com", "*.npmjs.org"]);
    }

    #[test]
    fn read_claude_settings_no_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"permissions": {}}"#).unwrap();
        assert_eq!(read_claude_settings(&path), None);
    }

    #[test]
    fn read_claude_settings_missing_file() {
        assert_eq!(read_claude_settings(Path::new("/nonexistent")), None);
    }

    // --- overlay (config layering) ---

    #[test]
    fn overlay_scalar_top_wins_when_set() {
        let base = Config {
            image: Some("base-img".into()),
            timeout: Some(60),
            ..Config::default()
        };
        let top = Config {
            image: Some("top-img".into()),
            ..Config::default()
        };
        let merged = overlay(base, top);
        assert_eq!(merged.image.as_deref(), Some("top-img"));
        // top left timeout unset, so the base value survives
        assert_eq!(merged.timeout, Some(60));
    }

    #[test]
    fn overlay_scalar_falls_back_to_base() {
        let base = Config {
            command: Some("base-cmd".into()),
            ..Config::default()
        };
        let merged = overlay(base, Config::default());
        assert_eq!(merged.command.as_deref(), Some("base-cmd"));
    }

    #[test]
    fn overlay_empty_base_is_noop() {
        let mut top = Config {
            image: Some("img".into()),
            ..Config::default()
        };
        top.env.insert("A".into(), "b".into());
        let merged = overlay(Config::default(), top);
        assert_eq!(merged.image.as_deref(), Some("img"));
        assert_eq!(merged.env.get("A").map(String::as_str), Some("b"));
    }

    #[test]
    fn overlay_allow_hosts_union_dedup() {
        let base = Config {
            network: NetworkConfig {
                allow: vec!["a.com".into(), "b.com".into()],
                ..NetworkConfig::default()
            },
            ..Config::default()
        };
        let top = Config {
            network: NetworkConfig {
                allow: vec!["b.com".into(), "c.com".into()],
                ..NetworkConfig::default()
            },
            ..Config::default()
        };
        let merged = overlay(base, top);
        assert_eq!(merged.network.allow, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn overlay_forward_union() {
        let base = Config {
            network: NetworkConfig {
                allow: vec![],
                forward: vec!["9222".into()],
            },
            ..Config::default()
        };
        let top = Config {
            network: NetworkConfig {
                allow: vec![],
                forward: vec!["8080:3000".into()],
            },
            ..Config::default()
        };
        let merged = overlay(base, top);
        assert_eq!(merged.network.forward, vec!["9222", "8080:3000"]);
    }

    #[test]
    fn overlay_secrets_top_wins_on_collision() {
        let mut base = Config::default();
        base.secrets.insert(
            "K".into(),
            SecretConfig {
                value: "base".into(),
                hosts: vec!["h".into()],
            },
        );
        base.secrets.insert(
            "ONLY_BASE".into(),
            SecretConfig {
                value: "b".into(),
                hosts: vec!["h".into()],
            },
        );
        let mut top = Config::default();
        top.secrets.insert(
            "K".into(),
            SecretConfig {
                value: "top".into(),
                hosts: vec!["h2".into()],
            },
        );
        let merged = overlay(base, top);
        assert_eq!(merged.secrets.get("K").unwrap().value, "top");
        assert!(merged.secrets.contains_key("ONLY_BASE"));
    }

    #[test]
    fn overlay_env_merges_top_wins() {
        let mut base = Config::default();
        base.env.insert("HOME".into(), "/root".into());
        base.env.insert("FOO".into(), "1".into());
        let mut top = Config::default();
        top.env.insert("HOME".into(), "/home/dev".into());
        let merged = overlay(base, top);
        assert_eq!(
            merged.env.get("HOME").map(String::as_str),
            Some("/home/dev")
        );
        assert_eq!(merged.env.get("FOO").map(String::as_str), Some("1"));
    }

    #[test]
    fn overlay_mount_union_top_wins() {
        let mut base = Config::default();
        base.mount.insert(
            "workspace".into(),
            MountConfig {
                source: "/base".into(),
                target: None,
                read_only: false,
            },
        );
        base.mount.insert(
            "data".into(),
            MountConfig {
                source: "/data".into(),
                target: None,
                read_only: true,
            },
        );
        let mut top = Config::default();
        top.mount.insert(
            "workspace".into(),
            MountConfig {
                source: "/top".into(),
                target: Some("/workspace".into()),
                read_only: false,
            },
        );
        let merged = overlay(base, top);
        assert_eq!(merged.mount.get("workspace").unwrap().source, "/top");
        assert!(merged.mount.contains_key("data"));
    }
}
