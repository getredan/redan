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
static AGENTS: &[&AgentDef] = &[&CLAUDE_CODE, &PI];

static CLAUDE_CODE: AgentDef = AgentDef {
    slug: "claude",
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
    // ANTHROPIC_API_KEY first to match Claude Code's own auth precedence
    // (API key over OAuth token). CLAUDE_CODE_OAUTH_TOKEN is the reliable
    // subscription path for sandboxes: a 1-year token from `claude
    // setup-token`. Both beat staging .credentials.json, which goes stale.
    auth: &[
        AuthMethod::EnvSecret {
            env_var: "ANTHROPIC_API_KEY",
            hosts: &["api.anthropic.com"],
            guest_env: &[("CLAUDE_CONFIG_DIR", "/workspace/.claude")],
        },
        AuthMethod::EnvSecret {
            env_var: "CLAUDE_CODE_OAUTH_TOKEN",
            hosts: &["api.anthropic.com"],
            guest_env: &[("CLAUDE_CONFIG_DIR", "/workspace/.claude")],
        },
        AuthMethod::StagedFiles {
            dir: ".claude",
            probe: ".credentials.json",
            files: &[".credentials.json"],
            guest_dir: "/tmp/.claude",
            hosts: &["auth.anthropic.com", "console.anthropic.com"],
            guest_env: &[("CLAUDE_CONFIG_DIR", "/tmp/.claude")],
        },
    ],
};

static PI: AgentDef = AgentDef {
    slug: "pi",
    name: "Pi",
    image: "pi",
    command: "pi",
    hosts: &["api.anthropic.com"],
    interactive: true,
    timeout_secs: 3600,
    run_as: Some("dev"),
    guest_env: &[("HOME", "/home/dev")],
    auth: &[
        AuthMethod::EnvSecret {
            env_var: "ANTHROPIC_API_KEY",
            hosts: &["api.anthropic.com"],
            guest_env: &[],
        },
        AuthMethod::StagedFiles {
            dir: ".pi/agent",
            probe: "auth.json",
            files: &["auth.json", "settings.json", "models.json"],
            guest_dir: "/home/dev/.pi/agent",
            hosts: &[],
            guest_env: &[],
        },
    ],
};

// ---------------------------------------------------------------------------
// Agent definition types
// ---------------------------------------------------------------------------

/// A coding agent that redan can auto-detect and sandbox.
pub struct AgentDef {
    /// Short, stable identifier for `redan run <slug>` (e.g. "claude").
    pub slug: &'static str,
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
    /// Credential supply methods, in priority order. The first method
    /// whose source is present (env var set, probe file exists) is used.
    pub auth: &'static [AuthMethod],
}

/// One way to supply an agent's credential.
pub enum AuthMethod {
    /// A host env var injected as a redan secret. The real value never
    /// enters the guest: a placeholder is set inside, the proxy swaps in
    /// the real value for requests to `hosts` and scrubs it from
    /// responses. Present when the env var is set to a non-empty value.
    /// Covers API keys (`ANTHROPIC_API_KEY`) and long-lived OAuth tokens
    /// (`CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token`).
    EnvSecret {
        env_var: &'static str,
        /// Hosts the secret is injected into (and allowed).
        hosts: &'static [&'static str],
        /// Guest env vars to set when this method is used.
        guest_env: &'static [(&'static str, &'static str)],
    },
    /// Credential files staged from `$HOME/dir` into the guest rootfs
    /// (same pattern as CA cert install). The real files enter the guest
    /// as plaintext. Present when `probe` exists under `$HOME/dir`.
    StagedFiles {
        /// Config dir relative to `$HOME` (e.g. `.claude`).
        dir: &'static str,
        /// File whose existence signals this method applies.
        probe: &'static str,
        /// Files to stage from `dir`. Empty stages just `probe`.
        files: &'static [&'static str],
        /// Guest directory to stage files into.
        guest_dir: &'static str,
        /// Extra hosts to allow (e.g. token-exchange endpoints).
        hosts: &'static [&'static str],
        /// Guest env vars to set when this method is used.
        guest_env: &'static [(&'static str, &'static str)],
    },
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
    /// Files to stage into the guest rootfs before boot.
    /// Each entry: (`host_path`, `guest_dir`, `filename`)
    pub stage_files: Vec<(PathBuf, String, String)>,
}

/// A detected agent with its resolved auth method.
pub struct DetectedAgent {
    pub agent: &'static AgentDef,
    pub auth: ResolvedAuth,
    pub image_exists: bool,
}

/// The auth method that resolved against the environment.
pub struct ResolvedAuth {
    pub method: &'static AuthMethod,
    /// For `StagedFiles`, the host dir the probe was found in.
    pub host_dir: Option<PathBuf>,
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
    AGENTS
        .iter()
        .filter_map(|&agent| detect_one(agent))
        .collect()
}

/// Look up an agent by its `redan run` slug (e.g. "claude", "pi").
pub fn agent_by_slug(slug: &str) -> Option<&'static AgentDef> {
    AGENTS.iter().find(|a| a.slug == slug).copied()
}

/// All known agent slugs, in registry order.
pub fn agent_slugs() -> Vec<&'static str> {
    AGENTS.iter().map(|a| a.slug).collect()
}

/// Why [`resolve_by_slug`] could not produce a Config.
pub enum ResolveError {
    /// No agent registered under that slug.
    Unknown,
    /// The agent exists but its auth requirements aren't met.
    NoAuth(&'static AgentDef),
}

/// Resolve a single named agent, probing its auth against the environment.
/// This is the `redan run <slug>` entry point: unlike [`detect`], the agent
/// is chosen explicitly rather than by registry priority.
pub fn resolve_by_slug(slug: &str) -> Result<AutoDetected, ResolveError> {
    let agent = agent_by_slug(slug).ok_or(ResolveError::Unknown)?;
    let detected = detect_one(agent).ok_or(ResolveError::NoAuth(agent))?;
    Ok(build_config(&detected))
}

/// Probe a single agent's auth requirements against the current environment.
fn detect_one(agent: &'static AgentDef) -> Option<DetectedAgent> {
    let home = std::env::var("HOME").ok();
    let auth = resolve_auth(
        agent,
        |var| std::env::var(var).ok(),
        home.as_deref().map(Path::new),
    )?;
    Some(DetectedAgent {
        agent,
        auth,
        image_exists: image_exists(agent.image),
    })
}

/// The agent's first available auth method: the first `EnvSecret` whose
/// env var is set to a non-empty value, or the first `StagedFiles` whose
/// probe file exists under `$HOME`. `env` reads an env var and `home` is
/// `$HOME` (both injected in tests).
fn resolve_auth(
    agent: &'static AgentDef,
    env: impl Fn(&str) -> Option<String>,
    home: Option<&Path>,
) -> Option<ResolvedAuth> {
    agent.auth.iter().find_map(|method| match method {
        AuthMethod::EnvSecret { env_var, .. } => {
            env(env_var)
                .filter(|v| !v.trim().is_empty())
                .map(|_| ResolvedAuth {
                    method,
                    host_dir: None,
                })
        }
        AuthMethod::StagedFiles { dir, probe, .. } => {
            let dir = home?.join(dir);
            dir.join(probe).exists().then_some(ResolvedAuth {
                method,
                host_dir: Some(dir),
            })
        }
    })
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
    pub command: &'a Option<String>,
    pub secrets: &'a [String],
    pub secret_file: &'a Option<String>,
    pub mounts: &'a [String],
    pub discover: bool,
}

pub const fn has_explicit_flags(f: &ExecFlags<'_>) -> bool {
    f.image.is_some()
        || f.rootfs.is_some()
        || f.command.is_some()
        || !f.secrets.is_empty()
        || f.secret_file.is_some()
        || !f.mounts.is_empty()
        || f.discover
}

// ---------------------------------------------------------------------------
// Internal: probing and config building
// ---------------------------------------------------------------------------

fn apply_auth(
    auth: &ResolvedAuth,
    config: &mut Config,
    messages: &mut Vec<String>,
    stage_files: &mut Vec<(PathBuf, String, String)>,
    allow: &mut Vec<String>,
) {
    match auth.method {
        AuthMethod::EnvSecret {
            env_var,
            hosts,
            guest_env,
        } => {
            messages.push(format!("Injecting {env_var} for {}", hosts.join(", ")));
            config.secrets.insert(
                (*env_var).into(),
                SecretConfig {
                    value: format!("env://{env_var}"),
                    hosts: hosts.iter().map(|&h| h.into()).collect(),
                },
            );
            for &(key, val) in *guest_env {
                config.env.insert(key.into(), val.into());
            }
        }
        AuthMethod::StagedFiles {
            probe,
            files,
            guest_dir,
            hosts,
            guest_env,
            ..
        } => {
            // host_dir is set by resolve_auth for StagedFiles.
            let Some(host_dir) = auth.host_dir.as_ref() else {
                return;
            };
            let to_stage: Vec<&str> = if files.is_empty() {
                vec![probe]
            } else {
                files.to_vec()
            };
            for filename in to_stage {
                let host_path = host_dir.join(filename);
                if host_path.exists() {
                    messages.push(format!(
                        "Staging {} → {guest_dir}/{filename}",
                        host_path.display()
                    ));
                    stage_files.push((host_path, (*guest_dir).into(), filename.into()));
                }
            }
            for &(key, val) in *guest_env {
                config.env.insert(key.into(), val.into());
            }
            for &host in *hosts {
                allow.push(host.to_string());
            }
        }
    }
}

/// Turn a detected agent into a ready-to-use Config.
fn build_config(detected: &DetectedAgent) -> AutoDetected {
    let agent = detected.agent;
    let mut messages = Vec::new();
    let mut stage_files: Vec<(PathBuf, String, String)> = Vec::new();
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

    apply_auth(
        &detected.auth,
        &mut config,
        &mut messages,
        &mut stage_files,
        &mut allow,
    );

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
        stage_files,
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

    /// Build a `DetectedAgent` from a fake env lookup + home (test helper).
    fn detect(
        agent: &'static AgentDef,
        env: impl Fn(&str) -> Option<String>,
        home: Option<&Path>,
        image_exists: bool,
    ) -> Option<DetectedAgent> {
        resolve_auth(agent, env, home).map(|auth| DetectedAgent {
            agent,
            auth,
            image_exists,
        })
    }

    /// An env lookup returning `val` for `name` and nothing else.
    fn only(name: &'static str, val: &'static str) -> impl Fn(&str) -> Option<String> {
        move |var| (var == name).then(|| val.to_string())
    }

    /// The env var of a resolved `EnvSecret` method, if any.
    fn resolved_env_var(r: &ResolvedAuth) -> Option<&'static str> {
        match r.method {
            AuthMethod::EnvSecret { env_var, .. } => Some(env_var),
            AuthMethod::StagedFiles { .. } => None,
        }
    }

    #[test]
    fn detect_api_key_produces_correct_config() {
        let detected = detect(
            &CLAUDE_CODE,
            only("ANTHROPIC_API_KEY", "sk-ant-test123"),
            None,
            true,
        )
        .expect("should detect via API key");
        assert!(matches!(detected.auth.method, AuthMethod::EnvSecret { .. }));

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
        let home = std::env::temp_dir().join("redan-test-oauth-refactor");
        let claude = home.join(".claude");
        let _ = std::fs::create_dir_all(&claude);
        let creds = claude.join(".credentials.json");
        std::fs::write(&creds, "{}").unwrap();

        let detected =
            detect(&CLAUDE_CODE, |_| None, Some(&home), true).expect("should detect via OAuth");
        assert!(matches!(
            detected.auth.method,
            AuthMethod::StagedFiles { .. }
        ));

        let auto = build_config(&detected);
        assert_eq!(auto.config.image.as_deref(), Some("claude-code"));
        assert!(auto.config.secrets.is_empty());

        // CLAUDE_CONFIG_DIR points to guest-only tmp dir
        assert_eq!(
            auto.config.env.get("CLAUDE_CONFIG_DIR").map(String::as_str),
            Some("/tmp/.claude")
        );

        // Credentials staged into rootfs before boot (no mount, no runtime copy)
        assert_eq!(auto.stage_files.len(), 1);
        let (host_path, guest_dir, filename) = &auto.stage_files[0];
        assert_eq!(host_path, &creds);
        assert_eq!(guest_dir, "/tmp/.claude");
        assert_eq!(filename, ".credentials.json");

        assert!(
            auto.config
                .network
                .allow
                .contains(&"auth.anthropic.com".to_string())
        );
        assert!(auto.messages.iter().any(|m| m.contains("Staging")));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn api_key_takes_precedence_over_staged_files() {
        // Env var is earlier in the auth list than StagedFiles, so it wins
        // even when the credentials file also exists.
        let home = std::env::temp_dir().join("redan-test-precedence-refactor");
        let claude = home.join(".claude");
        let _ = std::fs::create_dir_all(&claude);
        std::fs::write(claude.join(".credentials.json"), "{}").unwrap();

        let detected = detect(
            &CLAUDE_CODE,
            only("ANTHROPIC_API_KEY", "sk"),
            Some(&home),
            true,
        )
        .expect("should detect");
        assert!(matches!(detected.auth.method, AuthMethod::EnvSecret { .. }));

        let auto = build_config(&detected);
        assert!(auto.config.secrets.contains_key("ANTHROPIC_API_KEY"));
        assert!(auto.stage_files.is_empty());

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn no_auth_returns_none() {
        assert!(detect(&CLAUDE_CODE, |_| None, None, true).is_none());
    }

    #[test]
    fn resolve_prefers_api_key_over_oauth_token() {
        // Both env vars set -> API key wins (it's first in the auth list,
        // matching Claude Code's own precedence).
        let r = resolve_auth(&CLAUDE_CODE, |_| Some("value".into()), None).unwrap();
        assert_eq!(resolved_env_var(&r), Some("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn resolve_falls_to_oauth_token_when_only_it_is_set() {
        let r = resolve_auth(&CLAUDE_CODE, only("CLAUDE_CODE_OAUTH_TOKEN", "tok"), None).unwrap();
        assert_eq!(resolved_env_var(&r), Some("CLAUDE_CODE_OAUTH_TOKEN"));
    }

    #[test]
    fn resolve_ignores_empty_env_values() {
        assert!(resolve_auth(&CLAUDE_CODE, only("ANTHROPIC_API_KEY", "  "), None).is_none());
    }

    #[test]
    fn oauth_token_injects_as_secret() {
        let detected = detect(
            &CLAUDE_CODE,
            only("CLAUDE_CODE_OAUTH_TOKEN", "tok"),
            None,
            true,
        )
        .unwrap();
        let auto = build_config(&detected);
        let secret = auto.config.secrets.get("CLAUDE_CODE_OAUTH_TOKEN").unwrap();
        assert_eq!(secret.value, "env://CLAUDE_CODE_OAUTH_TOKEN");
        assert_eq!(secret.hosts, vec!["api.anthropic.com"]);
        // No credentials file staged when an env token is present.
        assert!(auto.stage_files.is_empty());
    }

    #[test]
    fn empty_api_key_falls_through_to_staged_files() {
        let home = std::env::temp_dir().join("redan-test-empty-key");
        let claude = home.join(".claude");
        let _ = std::fs::create_dir_all(&claude);
        std::fs::write(claude.join(".credentials.json"), "{}").unwrap();

        // Empty env vars don't match; fall back to staged credentials.
        let detected = detect(&CLAUDE_CODE, |_| Some(String::new()), Some(&home), true)
            .expect("should fall through to staged files");
        assert!(matches!(
            detected.auth.method,
            AuthMethod::StagedFiles { .. }
        ));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn empty_api_key_no_files_returns_none() {
        assert!(detect(&CLAUDE_CODE, |_| Some("  ".into()), None, true).is_none());
    }

    #[test]
    fn needs_image_build_when_image_missing() {
        let detected =
            detect(&CLAUDE_CODE, only("ANTHROPIC_API_KEY", "sk"), None, false).expect("detect");
        let auto = build_config(&detected);
        assert!(auto.needs_image_build);
        assert!(auto.messages.iter().any(|m| m.contains("will build")));
    }

    #[test]
    fn pi_api_key_produces_correct_config() {
        let detected = detect(&PI, only("ANTHROPIC_API_KEY", "sk-ant-test123"), None, true)
            .expect("should detect Pi via API key");
        assert!(matches!(detected.auth.method, AuthMethod::EnvSecret { .. }));

        let auto = build_config(&detected);
        assert_eq!(auto.config.image.as_deref(), Some("pi"));
        assert_eq!(auto.config.command.as_deref(), Some("pi"));
        assert_eq!(auto.run_as, Some("dev"));
        assert_eq!(
            auto.config.env.get("HOME").map(String::as_str),
            Some("/home/dev")
        );

        let secret = auto.config.secrets.get("ANTHROPIC_API_KEY").unwrap();
        assert_eq!(secret.value, "env://ANTHROPIC_API_KEY");
        assert_eq!(secret.hosts, vec!["api.anthropic.com"]);
    }

    #[test]
    fn pi_staged_files_stages_only_present_files() {
        let home = std::env::temp_dir().join("redan-test-pi-creds");
        let agent_dir = home.join(".pi/agent");
        let _ = std::fs::create_dir_all(&agent_dir);
        std::fs::write(agent_dir.join("auth.json"), "{}").unwrap();
        std::fs::write(agent_dir.join("settings.json"), "{}").unwrap();
        // models.json intentionally absent: only existing files get staged

        let detected = detect(&PI, |_| None, Some(&home), true)
            .expect("should detect Pi via staged credentials");
        let auto = build_config(&detected);

        assert_eq!(auto.stage_files.len(), 2);
        let filenames: Vec<&str> = auto
            .stage_files
            .iter()
            .map(|(_, _, f)| f.as_str())
            .collect();
        assert!(filenames.contains(&"auth.json"));
        assert!(filenames.contains(&"settings.json"));
        assert!(!filenames.contains(&"models.json"));

        for (_, dir, _) in &auto.stage_files {
            assert_eq!(dir, "/home/dev/.pi/agent");
        }

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn agent_by_slug_resolves_known() {
        assert_eq!(agent_by_slug("claude").map(|a| a.name), Some("Claude Code"));
        assert_eq!(agent_by_slug("pi").map(|a| a.name), Some("Pi"));
    }

    #[test]
    fn agent_by_slug_unknown_is_none() {
        assert!(agent_by_slug("nope").is_none());
    }

    #[test]
    fn agent_slugs_lists_registry() {
        let slugs = agent_slugs();
        assert!(slugs.contains(&"claude"));
        assert!(slugs.contains(&"pi"));
    }

    #[test]
    fn resolve_unknown_slug_errors() {
        assert!(matches!(
            resolve_by_slug("nope"),
            Err(ResolveError::Unknown)
        ));
    }

    fn empty_flags() -> ExecFlags<'static> {
        ExecFlags {
            image: &None,
            rootfs: &None,
            command: &None,
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
        let cmd = Some("echo hello".into());
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
