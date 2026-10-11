//! Configuration file support (`redan.toml`).
//!
//! Looks for `redan.toml` in the current directory, then
//! `~/.config/redan/config.toml`. CLI flags override file values.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::proxy::is_host_pattern;

/// The allowlist entry that turns the allowlist off, so the guest can reach
/// any host.
pub const ALLOW_ALL_HOSTS: &str = "*";

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
    #[must_use]
    pub fn secret_specs(&self) -> Vec<String> {
        self.secrets
            .iter()
            .filter(|(_, s)| !s.hosts.is_empty())
            .map(|(name, s)| format!("{name}={}:{}", s.value, s.hosts.join(",")))
            .collect()
    }

    /// Convert mounts map to CLI --mount spec format.
    #[must_use]
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

/// What redan takes from `sandbox.network.allowedDomains` in Claude Code's
/// settings.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ClaudeDomains {
    /// Hostnames and `*.domain` patterns to add to the allowlist.
    pub hosts: Vec<String>,
    /// One line for each entry that was left out, saying why.
    pub warnings: Vec<String>,
}

/// Read `sandbox.network.allowedDomains` from Claude Code's settings.
///
/// The files are `.claude/settings.local.json` and `.claude/settings.json` in
/// `project`, then the same two under `home`. When the project's `.claude`
/// is your home's, because the project is your home or links it there, each
/// file is read once.
#[must_use]
pub fn claude_allowed_domains(project: &Path, home: Option<&Path>) -> ClaudeDomains {
    let claude_dir = |dir: &Path| dir.join(".claude").canonicalize().ok();
    let home = home.filter(|home| claude_dir(home) != claude_dir(project));
    let mut domains = ClaudeDomains::default();
    for dir in std::iter::once(project).chain(home) {
        for name in ["settings.local.json", "settings.json"] {
            if let Some(found) = read_claude_settings(&dir.join(".claude").join(name)) {
                domains.hosts.extend(found.hosts);
                domains.warnings.extend(found.warnings);
            }
        }
    }
    domains.hosts.sort();
    domains.hosts.dedup();
    domains
}

/// Largest settings file redan reads, far above any real one.
const MAX_CLAUDE_SETTINGS_BYTES: u64 = 1 << 20;

/// Skipped entries in one settings file that get a warning of their own. The
/// rest are counted, since the guest can fill the project's settings.
const MAX_SKIP_WARNINGS: usize = 5;

fn read_claude_settings(path: &Path) -> Option<ClaudeDomains> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    // The guest can write the project's `.claude/`, and a FIFO or a link to a
    // device there would block or never end before the session starts. So
    // the file is opened without blocking, and that same handle has to be a
    // regular file, since a check on the path could be raced by a second
    // session on the project.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut content = String::new();
    file.take(MAX_CLAUDE_SETTINGS_BYTES)
        .read_to_string(&mut content)
        .ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;
    let entries = value
        .get("sandbox")?
        .get("network")?
        .get("allowedDomains")?
        .as_array()?;
    // Imported settings can add hosts but not turn redan's allowlist off: a
    // project's `.claude/settings*.json` comes with the repo, and a `"*"`
    // meant for Claude Code's own sandbox shouldn't switch off redan's.
    let mut domains = ClaudeDomains::default();
    let mut skipped = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in entries.iter().filter_map(serde_json::Value::as_str) {
        if is_host_pattern(entry) {
            domains.hosts.push(entry.to_string());
        } else if seen.insert(entry) {
            skipped.push(entry);
        }
    }
    for entry in skipped.iter().take(MAX_SKIP_WARNINGS) {
        let reason = if *entry == ALLOW_ALL_HOSTS {
            "Claude Code settings can't turn off redan's allowlist, pass --allow-host '*' for that"
        } else {
            "redan's allowlist only takes hostnames and *.domain patterns"
        };
        domains.warnings.push(format!(
            "ignoring {entry:?} in {}: {reason}",
            path.display()
        ));
    }
    let more = skipped.len().saturating_sub(MAX_SKIP_WARNINGS);
    if more > 0 {
        domains.warnings.push(format!(
            "ignoring {more} more entries in {} that aren't hostnames or *.domain patterns",
            path.display()
        ));
    }
    Some(domains)
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
#[must_use]
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
        assert!(
            config.network.allow.is_empty(),
            "{:?}",
            config.network.allow
        );
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
        assert_eq!(domains.hosts, vec!["github.com", "*.npmjs.org"]);
        assert_eq!(domains.warnings, Vec::<String>::new());
    }

    #[test]
    fn read_claude_settings_imports_only_hostnames_and_wildcards() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.local.json");
        std::fs::write(
            &path,
            r#"{"sandbox": {"network": {"allowedDomains": ["github.com", "*", "*.npmjs.org", "localhost:3000"]}}}"#,
        )
        .unwrap();
        let domains = read_claude_settings(&path).unwrap();
        assert_eq!(domains.hosts, vec!["github.com", "*.npmjs.org"]);
        let path = path.display();
        assert_eq!(
            domains.warnings,
            vec![
                format!(
                    "ignoring \"*\" in {path}: Claude Code settings can't turn off redan's \
                     allowlist, pass --allow-host '*' for that"
                ),
                format!(
                    "ignoring \"localhost:3000\" in {path}: redan's allowlist only takes \
                     hostnames and *.domain patterns"
                ),
            ]
        );
    }

    /// The guest can write the project's settings, so a file full of entries
    /// redan skips gets one warning for each of the first few and a count for
    /// the rest, instead of a line for every entry before each session.
    #[test]
    fn read_claude_settings_warns_about_the_first_few_skipped_entries() {
        let dir = tempfile::tempdir().unwrap();
        let entries: Vec<String> = std::iter::repeat_n(r#""*""#.to_string(), 1000)
            .chain((0..100).map(|i| format!(r#""host:{i}""#)))
            .collect();
        write_claude_settings(
            dir.path(),
            "settings.json",
            &format!("[{}]", entries.join(", ")),
        );
        let path = dir.path().join(".claude").join("settings.json");

        let domains = read_claude_settings(&path).unwrap();

        assert_eq!(domains.warnings.len(), 6, "{:?}", domains.warnings);
        assert!(domains.warnings[0].starts_with(r#"ignoring "*" in"#));
        assert!(domains.warnings[4].starts_with(r#"ignoring "host:3" in"#));
        assert_eq!(
            domains.warnings[5],
            format!(
                "ignoring 96 more entries in {} that aren't hostnames or *.domain patterns",
                path.display()
            )
        );
    }

    fn write_claude_settings(dir: &Path, name: &str, domains: &str) {
        std::fs::create_dir_all(dir.join(".claude")).unwrap();
        std::fs::write(
            dir.join(".claude").join(name),
            format!(r#"{{"sandbox": {{"network": {{"allowedDomains": {domains}}}}}}}"#),
        )
        .unwrap();
    }

    #[test]
    fn claude_allowed_domains_merges_project_and_home_settings() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        write_claude_settings(project.path(), "settings.local.json", r#"["*.npmjs.org"]"#);
        write_claude_settings(project.path(), "settings.json", r#"["github.com"]"#);
        write_claude_settings(
            home.path(),
            "settings.json",
            r#"["github.com", "pypi.org"]"#,
        );

        let domains = claude_allowed_domains(project.path(), Some(home.path()));

        assert_eq!(domains.hosts, vec!["*.npmjs.org", "github.com", "pypi.org"]);
    }

    #[test]
    fn claude_allowed_domains_reads_a_file_once_when_the_project_is_your_home() {
        let home = tempfile::tempdir().unwrap();
        write_claude_settings(home.path(), "settings.json", r#"["*", "github.com"]"#);

        let domains = claude_allowed_domains(home.path(), Some(home.path()));

        assert_eq!(domains.hosts, vec!["github.com"]);
        assert_eq!(domains.warnings.len(), 1, "{:?}", domains.warnings);
    }

    #[test]
    fn claude_allowed_domains_reads_a_project_claude_dir_linked_to_your_home_once() {
        let home = tempfile::tempdir().unwrap();
        write_claude_settings(home.path(), "settings.json", r#"["*", "github.com"]"#);
        let project = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(home.path().join(".claude"), project.path().join(".claude"))
            .unwrap();

        let domains = claude_allowed_domains(project.path(), Some(home.path()));

        assert_eq!(domains.hosts, vec!["github.com"]);
        assert_eq!(domains.warnings.len(), 1, "{:?}", domains.warnings);
    }

    /// The guest can leave a FIFO in the project, which would block redan
    /// before the session starts, or a link to `/dev/stdin`, which would read
    /// redan's own input when you pipe something into it. A pipe that holds
    /// valid settings stands in for the second.
    #[test]
    fn claude_allowed_domains_skips_settings_that_are_not_regular_files() {
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;

        let project = tempfile::tempdir().unwrap();
        let claude = project.path().join(".claude");
        std::fs::create_dir(&claude).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(claude.join("settings.local.json"))
            .status()
            .unwrap();
        assert!(status.success());
        let (stdin, mut piped) = std::io::pipe().unwrap();
        piped
            .write_all(br#"{"sandbox": {"network": {"allowedDomains": ["example.com"]}}}"#)
            .unwrap();
        drop(piped);
        let stdin_link = format!("/proc/self/fd/{}", stdin.as_raw_fd());
        std::os::unix::fs::symlink(stdin_link, claude.join("settings.json")).unwrap();

        let domains = claude_allowed_domains(project.path(), None);

        assert_eq!(domains, ClaudeDomains::default());
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
