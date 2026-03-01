//! Zero-config auto-detection for `redan exec`.
//!
//! When no `redan.toml` exists and no CLI flags are given, redan tries to
//! detect a usable configuration automatically. Currently detects Claude Code
//! setups: if the `claude-code` image exists and `ANTHROPIC_API_KEY` is set,
//! redan runs Claude Code with smart defaults.

use std::path::Path;

use crate::config::{Config, MountConfig, NetworkConfig, SecretConfig};
use crate::image;

/// Hosts required for Claude Code to function.
const CLAUDE_HOSTS: &[&str] = &[
    "api.anthropic.com",
    "statsig.anthropic.com",
    "sentry.io",
    "platform.claude.com",
    "raw.githubusercontent.com",
];

/// Result of auto-detection: a Config plus messages about what was detected.
pub struct AutoDetected {
    pub config: Config,
    /// Human-readable lines describing what was detected and chosen.
    pub messages: Vec<String>,
    /// Whether the claude-code image needs to be built first.
    pub needs_image_build: bool,
}

/// Attempt to build a Config from environment detection.
///
/// Returns `None` if auto-detection can't produce a usable config
/// (e.g., no known image, no API key).
pub fn detect() -> Option<AutoDetected> {
    let home = home_dir();
    detect_with_env(
        std::env::var("ANTHROPIC_API_KEY").ok(),
        image_exists("claude-code"),
        home.as_deref(),
    )
}

/// Testable inner function with injected environment.
fn detect_with_env(
    anthropic_key: Option<String>,
    claude_image_exists: bool,
    home: Option<&str>,
) -> Option<AutoDetected> {
    // For now, we only auto-detect Claude Code setups.
    // Future: detect other agent types (Codex, etc.)
    let api_key = anthropic_key?;
    if api_key.is_empty() {
        return None;
    }

    let mut messages = Vec::new();
    let needs_image_build = !claude_image_exists;

    if claude_image_exists {
        messages.push("Using image: claude-code".into());
    } else {
        messages.push("Image claude-code not found, will build from bundled Dockerfile".into());
    }

    messages.push("Injecting ANTHROPIC_API_KEY for api.anthropic.com".into());

    let mut config = Config {
        image: Some("claude-code".into()),
        command: Some("claude --dangerously-skip-permissions".into()),
        interactive: Some(true),
        timeout: Some(3600),
        ..Config::default()
    };

    // Network: Claude's required hosts
    config.network = NetworkConfig {
        allow: CLAUDE_HOSTS.iter().map(|&h| h.to_string()).collect(),
    };

    // Secret: ANTHROPIC_API_KEY via env://
    config.secrets.insert(
        "ANTHROPIC_API_KEY".into(),
        SecretConfig {
            value: "env://ANTHROPIC_API_KEY".to_string(),
            hosts: vec!["api.anthropic.com".into()],
        },
    );

    // Mount: current directory → /workspace
    config.mount.insert(
        "workspace".into(),
        MountConfig {
            source: ".".into(),
            target: Some("/workspace".into()),
        },
    );

    // Claude Code config dir in workspace
    config
        .env
        .insert("CLAUDE_CONFIG_DIR".into(), "/workspace/.claude".into());

    // Git/SSH identity mounts
    if let Some(home) = home {
        let gitconfig = Path::new(home).join(".gitconfig");
        if gitconfig.exists() {
            config.mount.insert(
                "gitconfig".into(),
                MountConfig {
                    source: gitconfig.to_string_lossy().into_owned(),
                    target: Some("/home/dev/.gitconfig".into()),
                },
            );
            messages.push("Mounting ~/.gitconfig (read-only)".into());
        }

        let ssh_dir = Path::new(home).join(".ssh");
        if ssh_dir.is_dir() {
            config.mount.insert(
                "ssh".into(),
                MountConfig {
                    source: ssh_dir.to_string_lossy().into_owned(),
                    target: Some("/home/dev/.ssh".into()),
                },
            );
            messages.push("Mounting ~/.ssh (read-only)".into());
        }
    }

    // Summarize mount
    messages.push("Mounting current directory → /workspace".into());

    Some(AutoDetected {
        config,
        messages,
        needs_image_build,
    })
}

/// Check if a named image exists.
fn image_exists(name: &str) -> bool {
    image::image_path(name).map(|p| p.exists()).unwrap_or(false)
}

fn home_dir() -> Option<String> {
    std::env::var("HOME").ok()
}

/// Fields from CLI that indicate the user wants manual control (not auto-detect).
pub struct ExecFlags<'a> {
    pub image: &'a Option<String>,
    pub rootfs: &'a Option<String>,
    pub command: &'a [String],
    pub secrets: &'a [String],
    pub secret_file: &'a Option<String>,
    pub mounts: &'a [String],
    pub discover: bool,
    pub detach: bool,
}

/// Check if any explicit exec flags were provided on the CLI.
pub const fn has_explicit_flags(f: &ExecFlags<'_>) -> bool {
    f.image.is_some()
        || f.rootfs.is_some()
        || !f.command.is_empty()
        || !f.secrets.is_empty()
        || f.secret_file.is_some()
        || !f.mounts.is_empty()
        || f.discover
        || f.detach
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn detect_claude_code_with_key_and_image() {
        let result = detect_with_env(Some("sk-ant-test123".into()), true, Some("/home/testuser"));
        let auto = result.expect("should detect");
        assert_eq!(auto.config.image.as_deref(), Some("claude-code"));
        assert!(auto.config.command.as_deref().unwrap().contains("claude"));
        assert_eq!(auto.config.interactive, Some(true));
        assert!(!auto.needs_image_build);

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

        assert!(auto.config.mount.contains_key("workspace"));
        assert!(auto.messages.iter().any(|m| m.contains("claude-code")));
        assert!(
            auto.messages
                .iter()
                .any(|m| m.contains("ANTHROPIC_API_KEY"))
        );
    }

    #[test]
    fn detect_needs_image_build_when_missing() {
        let result = detect_with_env(Some("sk-ant-test123".into()), false, Some("/home/testuser"));
        let auto = result.expect("should detect");
        assert!(auto.needs_image_build);
        assert!(auto.messages.iter().any(|m| m.contains("will build")));
    }

    #[test]
    fn detect_returns_none_without_api_key() {
        assert!(detect_with_env(None, true, Some("/home/testuser")).is_none());
    }

    #[test]
    fn detect_returns_none_with_empty_api_key() {
        assert!(detect_with_env(Some(String::new()), true, Some("/home/testuser")).is_none());
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
            detach: false,
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
    fn explicit_flags_detects_detach() {
        assert!(has_explicit_flags(&ExecFlags {
            detach: true,
            ..empty_flags()
        }));
    }
}
