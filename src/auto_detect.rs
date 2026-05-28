//! Zero-config auto-detection for `redan exec`.
//!
//! When no `redan.toml` exists and no CLI flags are given, redan probes the
//! environment for known coding agents and builds a sandboxed Config
//! automatically.
//!
//! Each agent is defined as a static `AgentDef` with its auth methods, required
//! hosts, and runtime settings. Adding support for a new agent means adding a
//! new entry to `AGENTS`; the detection and config-building logic is generic.

use std::path::{Path, PathBuf};

use crate::config::{Config, MountConfig, NetworkConfig, SecretConfig};
use crate::image;

// ---------------------------------------------------------------------------
// Agent registry
// ---------------------------------------------------------------------------

/// All known agents, ordered by detection priority.
/// `detect()` returns the first match; `detect_all()` returns every match
/// (for a future interactive picker).
static AGENTS: &[&AgentDef] = &[&CLAUDE_CODE];

static CLAUDE_CODE: AgentDef = AgentDef {
    name: "Claude Code",
    image: "claude-code",
    command: "claude --dangerously-skip-permissions",
    hosts: &[
        "api.anthropic.com",
        "statsig.anthropic.com",
        "sentry.io",
        "platform.claude.com",
        "raw.githubusercontent.com",
    ],
    interactive: true,
    timeout_secs: 3600,
    run_as: Some("dev"),
    guest_env: &[("HOME", "/home/dev")],
    api_key: Some(ApiKeyDef {
        env_var: "ANTHROPIC_API_KEY",
        inject_hosts: &["api.anthropic.com"],
        guest_env: &[("CLAUDE_CONFIG_DIR", "/workspace/.claude")],
    }),
    oauth: Some(OAuthDef {
        home_dir: ".claude",
        credentials_file: ".credentials.json",
        guest_credentials_dir: "/tmp/.claude",
        guest_env: &[("CLAUDE_CONFIG_DIR", "/tmp/.claude")],
        extra_hosts: &["auth.anthropic.com", "console.anthropic.com"],
    }),
};

// ---------------------------------------------------------------------------
// Agent definition types
// ---------------------------------------------------------------------------

/// A coding agent that redan can auto-detect and sandbox.
pub struct AgentDef {
    pub name: &'static str,
    pub image: &'static str,
    pub command: &'static str,
    /// Network hosts the agent needs to reach.
    pub hosts: &'static [&'static str],
    pub interactive: bool,
    pub timeout_secs: u64,
    /// Run the user command as this OS user (via `runuser`).
    /// None means run as root (libkrun default).
    pub run_as: Option<&'static str>,
    /// Extra guest env vars (set regardless of auth method).
    pub guest_env: &'static [(&'static str, &'static str)],
    /// API-key-based auth (tried first).
    pub api_key: Option<ApiKeyDef>,
    /// OAuth/stored-credentials auth (fallback when no API key).
    pub oauth: Option<OAuthDef>,
}

/// Auth via an environment variable injected as a redan secret.
pub struct ApiKeyDef {
    /// Host env var to read (e.g., `ANTHROPIC_API_KEY`).
    pub env_var: &'static str,
    /// Hosts the secret is injected into.
    pub inject_hosts: &'static [&'static str],
    /// Guest env vars to set when using this auth path.
    pub guest_env: &'static [(&'static str, &'static str)],
}

/// Auth via credentials stored in a config directory on the host.
///
/// The credentials file is staged into the guest rootfs before boot
/// (same pattern as CA cert installation), so no mount or runtime
/// copy is needed.
pub struct OAuthDef {
    /// Config directory relative to `$HOME` (e.g., `.claude`).
    pub home_dir: &'static str,
    /// File that signals credentials exist (e.g., `.credentials.json`).
    pub credentials_file: &'static str,
    /// Guest directory to stage the credentials file into.
    pub guest_credentials_dir: &'static str,
    /// Guest env vars to set when using this auth path.
    pub guest_env: &'static [(&'static str, &'static str)],
    /// Extra network hosts for token exchange.
    pub extra_hosts: &'static [&'static str],
}

// ---------------------------------------------------------------------------
// Detection result types
// ---------------------------------------------------------------------------

/// Result of auto-detection: a Config plus messages about what was detected.
pub struct AutoDetected {
    pub config: Config,
    /// Human-readable lines describing what was detected and chosen.
    pub messages: Vec<String>,
    /// Whether the agent's image needs to be built first.
    pub needs_image_build: bool,
    /// Run the user command as this OS user (via `runuser`).
    pub run_as: Option<&'static str>,
    /// Credentials file to stage into the guest rootfs before boot.
    /// (`host_path`, `guest_dir`, `filename`)
    pub stage_credentials: Option<(PathBuf, String, String)>,
}

/// A detected agent with its resolved auth method.
pub struct DetectedAgent {
    pub agent: &'static AgentDef,
    pub auth: ResolvedAuth,
    pub image_exists: bool,
}

/// The auth method that was actually found in the environment.
pub enum ResolvedAuth {
    ApiKey,
    OAuth { host_config_dir: PathBuf },
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Auto-detect: return a Config for the first detected agent.
pub fn detect() -> Option<AutoDetected> {
    detect_all().into_iter().next().map(|d| build_config(&d))
}

/// Detect all agents whose auth requirements are satisfied.
/// Returns them in registry order (highest priority first).
pub fn detect_all() -> Vec<DetectedAgent> {
    let home = std::env::var("HOME").ok();
    AGENTS
        .iter()
        .filter_map(|agent| {
            let api_key_val = agent
                .api_key
                .as_ref()
                .and_then(|a| std::env::var(a.env_var).ok());
            let oauth_creds = home.as_ref().and_then(|h| {
                let oauth = agent.oauth.as_ref()?;
                let path = Path::new(h)
                    .join(oauth.home_dir)
                    .join(oauth.credentials_file);
                path.exists().then_some(path)
            });
            probe_with_env(agent, api_key_val.as_deref(), oauth_creds.as_deref(), None)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// CLI flag detection (unchanged)
// ---------------------------------------------------------------------------

/// Config-level fields from CLI that indicate the user wants manual control
/// (not auto-detect). Mode flags like --detach and --name are excluded;
/// they modify how the session runs, not what it runs.
pub struct ExecFlags<'a> {
    pub image: &'a Option<String>,
    pub rootfs: &'a Option<String>,
    pub command: &'a [String],
    pub secrets: &'a [String],
    pub secret_file: &'a Option<String>,
    pub mounts: &'a [String],
    pub discover: bool,
}

pub const fn has_explicit_flags(f: &ExecFlags<'_>) -> bool {
    f.image.is_some()
        || f.rootfs.is_some()
        || !f.command.is_empty()
        || !f.secrets.is_empty()
        || f.secret_file.is_some()
        || !f.mounts.is_empty()
        || f.discover
}

// ---------------------------------------------------------------------------
// Internal: probing and config building
// ---------------------------------------------------------------------------

/// Check whether an agent's auth requirements are met.
/// API key is tried first; OAuth is the fallback.
fn probe_with_env(
    agent: &'static AgentDef,
    api_key_value: Option<&str>,
    oauth_credentials: Option<&Path>,
    has_image: Option<bool>,
) -> Option<DetectedAgent> {
    let image_exists = has_image.unwrap_or_else(|| image_exists(agent.image));

    if agent.api_key.is_some()
        && let Some(key) = api_key_value
        && !key.trim().is_empty()
    {
        return Some(DetectedAgent {
            agent,
            auth: ResolvedAuth::ApiKey,
            image_exists,
        });
    }

    if agent.oauth.is_some()
        && let Some(creds_path) = oauth_credentials
    {
        let config_dir = creds_path.parent().unwrap_or(creds_path).to_path_buf();
        return Some(DetectedAgent {
            agent,
            auth: ResolvedAuth::OAuth {
                host_config_dir: config_dir,
            },
            image_exists,
        });
    }

    None
}

/// Turn a detected agent into a ready-to-use Config.
fn build_config(detected: &DetectedAgent) -> AutoDetected {
    let agent = detected.agent;
    let mut messages = Vec::new();
    let mut stage_credentials: Option<(PathBuf, String, String)> = None;
    let needs_image_build = !detected.image_exists;

    if detected.image_exists {
        messages.push(format!("Using image: {}", agent.image));
    } else {
        messages.push(format!(
            "Image {} not found, will build from bundled Dockerfile",
            agent.image
        ));
    }

    let mut config = Config {
        image: Some(agent.image.into()),
        command: Some(agent.command.into()),
        interactive: Some(agent.interactive),
        timeout: Some(agent.timeout_secs),
        ..Config::default()
    };

    let mut allow: Vec<String> = agent.hosts.iter().map(|&h| h.to_string()).collect();

    for &(key, val) in agent.guest_env {
        config.env.insert(key.into(), val.into());
    }

    match &detected.auth {
        ResolvedAuth::ApiKey => {
            if let Some(api) = agent.api_key.as_ref() {
                messages.push(format!(
                    "Injecting {} for {}",
                    api.env_var,
                    api.inject_hosts.join(", ")
                ));
                config.secrets.insert(
                    api.env_var.into(),
                    SecretConfig {
                        value: format!("env://{}", api.env_var),
                        hosts: api.inject_hosts.iter().map(|&h| h.into()).collect(),
                    },
                );
                for &(key, val) in api.guest_env {
                    config.env.insert(key.into(), val.into());
                }
            }
        }
        ResolvedAuth::OAuth { host_config_dir } => {
            if let Some(oauth) = agent.oauth.as_ref() {
                let cred_file = host_config_dir.join(oauth.credentials_file);
                messages.push(format!(
                    "Staging {} → {}/{}",
                    cred_file.display(),
                    oauth.guest_credentials_dir,
                    oauth.credentials_file
                ));
                stage_credentials = Some((
                    cred_file,
                    oauth.guest_credentials_dir.into(),
                    oauth.credentials_file.into(),
                ));
                for &(key, val) in oauth.guest_env {
                    config.env.insert(key.into(), val.into());
                }
                for &host in oauth.extra_hosts {
                    allow.push(host.to_string());
                }
            }
        }
    }

    let git_hosts = git_remote_hosts();
    if !git_hosts.is_empty() {
        messages.push(format!(
            "Allowing git remote hosts: {}",
            git_hosts.join(", ")
        ));
        allow.extend(git_hosts);
    }
    config.network = NetworkConfig {
        allow,
        ..NetworkConfig::default()
    };

    config.mount.insert(
        "workspace".into(),
        MountConfig {
            source: ".".into(),
            target: Some("/workspace".into()),
            read_only: false,
        },
    );
    messages.push("Mounting current directory → /workspace".into());

    if crate::browser::find_chrome().is_some() {
        messages.push("Chrome found: use --browser to enable headless browser access".into());
    }

    AutoDetected {
        config,
        messages,
        needs_image_build,
        run_as: agent.run_as,
        stage_credentials,
    }
}

fn image_exists(name: &str) -> bool {
    image::image_path(name).map(|p| p.exists()).unwrap_or(false)
}

/// Extract hostnames from git remote URLs in the current directory.
fn git_remote_hosts() -> Vec<String> {
    let output = std::process::Command::new("git")
        .args(["remote", "-v"])
        .stderr(std::process::Stdio::null())
        .output();
    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut hosts: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let url = line.split_whitespace().nth(1)?;
            host_from_remote_url(url)
        })
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Extract hostname from a git remote URL.
/// Handles HTTPS, HTTP, ssh://, and SCP-style (git@host:path) formats.
fn host_from_remote_url(url: &str) -> Option<String> {
    if let Some(rest) = url.strip_prefix("ssh://") {
        let authority = rest.rsplit_once('@').map_or(rest, |(_, a)| a);
        let host = authority.split('/').next()?;
        return Some(host.split(':').next().unwrap_or(host).to_string());
    }
    if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        return rest
            .split('/')
            .next()
            .map(|h| h.split(':').next().unwrap_or(h).to_string());
    }
    if let Some((_user, host_and_path)) = url.split_once('@') {
        return host_and_path.split(':').next().map(String::from);
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn detect_api_key_produces_correct_config() {
        let detected = probe_with_env(&CLAUDE_CODE, Some("sk-ant-test123"), None, Some(true))
            .expect("should detect via API key");
        assert!(matches!(detected.auth, ResolvedAuth::ApiKey));

        let auto = build_config(&detected);
        assert_eq!(auto.config.image.as_deref(), Some("claude-code"));
        assert!(auto.config.command.as_deref().unwrap().contains("claude"));
        assert_eq!(auto.config.interactive, Some(true));
        assert_eq!(auto.run_as, Some("dev"));
        assert_eq!(
            auto.config.env.get("HOME").map(String::as_str),
            Some("/home/dev")
        );

        let secret = auto.config.secrets.get("ANTHROPIC_API_KEY").unwrap();
        assert_eq!(secret.value, "env://ANTHROPIC_API_KEY");
        assert_eq!(secret.hosts, vec!["api.anthropic.com"]);

        assert!(
            auto.config
                .network
                .allow
                .contains(&"api.anthropic.com".to_string())
        );
        assert!(
            auto.config
                .network
                .allow
                .contains(&"statsig.anthropic.com".to_string())
        );

        assert_eq!(
            auto.config.env.get("CLAUDE_CONFIG_DIR").map(String::as_str),
            Some("/workspace/.claude")
        );

        assert!(auto.config.mount.contains_key("workspace"));
        assert!(
            auto.messages
                .iter()
                .any(|m| m.contains("ANTHROPIC_API_KEY"))
        );
    }

    #[test]
    fn detect_oauth_produces_correct_config() {
        let tmp = std::env::temp_dir().join("redan-test-oauth-refactor");
        let _ = std::fs::create_dir_all(&tmp);
        let creds = tmp.join(".credentials.json");
        std::fs::write(&creds, "{}").unwrap();

        let detected = probe_with_env(&CLAUDE_CODE, None, Some(&creds), Some(true))
            .expect("should detect via OAuth");
        assert!(matches!(detected.auth, ResolvedAuth::OAuth { .. }));

        let auto = build_config(&detected);
        assert_eq!(auto.config.image.as_deref(), Some("claude-code"));
        assert!(auto.config.secrets.is_empty());

        // CLAUDE_CONFIG_DIR points to guest-only tmp dir
        assert_eq!(
            auto.config.env.get("CLAUDE_CONFIG_DIR").map(String::as_str),
            Some("/tmp/.claude")
        );

        // Credentials staged into rootfs before boot (no mount, no runtime copy)
        let (host_path, guest_dir, filename) = auto.stage_credentials.as_ref().unwrap();
        assert_eq!(host_path, &creds);
        assert_eq!(guest_dir, "/tmp/.claude");
        assert_eq!(filename, ".credentials.json");

        // No config-dir mount (credentials are pre-staged)
        assert!(!auto.config.mount.contains_key("claude-code-config"));

        assert!(
            auto.config
                .network
                .allow
                .contains(&"auth.anthropic.com".to_string())
        );
        assert!(auto.messages.iter().any(|m| m.contains("Staging")));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn api_key_takes_precedence_over_oauth() {
        let tmp = std::env::temp_dir().join("redan-test-precedence-refactor");
        let _ = std::fs::create_dir_all(&tmp);
        let creds = tmp.join(".credentials.json");
        std::fs::write(&creds, "{}").unwrap();

        let detected = probe_with_env(&CLAUDE_CODE, Some("sk-ant-test"), Some(&creds), Some(true))
            .expect("should detect");
        assert!(matches!(detected.auth, ResolvedAuth::ApiKey));

        let auto = build_config(&detected);
        assert!(auto.config.secrets.contains_key("ANTHROPIC_API_KEY"));
        assert!(!auto.config.mount.contains_key("claude-code-config"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn no_auth_returns_none() {
        assert!(probe_with_env(&CLAUDE_CODE, None, None, Some(true)).is_none());
    }

    #[test]
    fn empty_api_key_falls_through_to_oauth() {
        let tmp = std::env::temp_dir().join("redan-test-empty-key");
        let _ = std::fs::create_dir_all(&tmp);
        let creds = tmp.join(".credentials.json");
        std::fs::write(&creds, "{}").unwrap();

        let detected = probe_with_env(&CLAUDE_CODE, Some(""), Some(&creds), Some(true))
            .expect("should fall through to OAuth");
        assert!(matches!(detected.auth, ResolvedAuth::OAuth { .. }));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn empty_api_key_no_oauth_returns_none() {
        assert!(probe_with_env(&CLAUDE_CODE, Some("  "), None, Some(true)).is_none());
    }

    #[test]
    fn needs_image_build_when_image_missing() {
        let detected = probe_with_env(&CLAUDE_CODE, Some("sk-ant-test"), None, Some(false))
            .expect("should detect");
        let auto = build_config(&detected);
        assert!(auto.needs_image_build);
        assert!(auto.messages.iter().any(|m| m.contains("will build")));
    }

    fn empty_flags() -> ExecFlags<'static> {
        ExecFlags {
            image: &None,
            rootfs: &None,
            command: &[],
            secrets: &[],
            secret_file: &None,
            mounts: &[],
            discover: false,
        }
    }

    #[test]
    fn explicit_flags_none_when_empty() {
        assert!(!has_explicit_flags(&empty_flags()));
    }

    #[test]
    fn explicit_flags_detects_image() {
        let img = Some("myimage".into());
        assert!(has_explicit_flags(&ExecFlags {
            image: &img,
            ..empty_flags()
        }));
    }

    #[test]
    fn explicit_flags_detects_command() {
        let cmd = vec!["echo".into(), "hello".into()];
        assert!(has_explicit_flags(&ExecFlags {
            command: &cmd,
            ..empty_flags()
        }));
    }

    #[test]
    fn explicit_flags_detects_discover() {
        assert!(has_explicit_flags(&ExecFlags {
            discover: true,
            ..empty_flags()
        }));
    }

    #[test]
    fn host_from_https_url() {
        assert_eq!(
            host_from_remote_url("https://github.com/user/repo.git"),
            Some("github.com".into())
        );
    }

    #[test]
    fn host_from_ssh_url() {
        assert_eq!(
            host_from_remote_url("git@github.com:user/repo.git"),
            Some("github.com".into())
        );
    }

    #[test]
    fn host_from_https_with_port() {
        assert_eq!(
            host_from_remote_url("https://gitlab.example.com:8443/group/repo.git"),
            Some("gitlab.example.com".into())
        );
    }

    #[test]
    fn host_from_ssh_custom_host() {
        assert_eq!(
            host_from_remote_url("git@gitlab.internal.corp:team/project.git"),
            Some("gitlab.internal.corp".into())
        );
    }

    #[test]
    fn host_from_ssh_scheme() {
        assert_eq!(
            host_from_remote_url("ssh://git@github.com/org/repo.git"),
            Some("github.com".into())
        );
    }

    #[test]
    fn host_from_ssh_scheme_with_port() {
        assert_eq!(
            host_from_remote_url("ssh://git@gitlab.example.com:2222/group/repo.git"),
            Some("gitlab.example.com".into())
        );
    }

    #[test]
    fn host_from_nonsense_returns_none() {
        assert_eq!(host_from_remote_url("not-a-url"), None);
    }
}
