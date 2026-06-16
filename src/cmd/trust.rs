//! Trust gate for working-directory configs, plus `redan trust` / `untrust`.
//!
//! `load_config` is the only blessed way to load a cwd config: it classifies
//! the config and, if it reaches host authority, requires trust (granted via an
//! interactive prompt here or out of band with `redan trust`). `config::discover`
//! is raw and must not be acted on directly.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use redan::config::{self, ConfigSource};
use redan::trust::{self, Capability, Decision};

/// Discover the config and apply the trust gate.
///
/// Returns the `(path, config)` to use, or `None` only when there is no config
/// file at all. A project config that is present but needs trust it doesn't have
/// is a hard stop (the process exits), never a silent fall-through to
/// auto-detect: a `redan.toml` you can see should be used or refused, not
/// quietly replaced by something else.
pub(crate) fn load_config() -> Option<(PathBuf, config::Config)> {
    let config::DiscoveredConfig {
        path,
        content,
        config,
        source,
    } = config::discover()?;

    // The user's own config (~/.config/redan/config.toml) is implicitly trusted.
    if source == ConfigSource::User {
        return Some((path, config));
    }

    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let caps = trust::analyze(&config, &project_root);
    let already_trusted = trust::is_trusted(&path, content.as_bytes());
    let interactive = redan::terminal::stdin_is_tty();

    match trust::decide(!caps.is_empty(), already_trusted, interactive) {
        Decision::Load => Some((path, config)),
        Decision::Prompt => {
            print_capabilities(&path, &caps);
            if confirm("Trust this config and continue?") {
                if let Err(e) = trust::trust(&path, content.as_bytes()) {
                    eprintln!("warning: could not record trust: {e}");
                }
                Some((path, config))
            } else {
                eprintln!("{} left untrusted; not running.", path.display());
                std::process::exit(1);
            }
        }
        Decision::Skip => {
            eprintln!(
                "{} needs trust and this is a non-interactive session.",
                path.display()
            );
            print_capabilities(&path, &caps);
            eprintln!("Review it, then run `redan trust` to allow it.");
            std::process::exit(1);
        }
    }
}

/// `redan trust [path]`: review what a config grants, then record it as trusted.
pub(crate) fn trust_cmd(path_arg: Option<&str>) {
    let path = resolve_config_path(path_arg);
    let content = read_or_exit(&path);
    let cfg: config::Config = toml::from_str(&content).unwrap_or_else(|e| {
        eprintln!("error: failed to parse {}: {e}", path.display());
        std::process::exit(1);
    });

    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let caps = trust::analyze(&cfg, &project_root);
    if caps.is_empty() {
        eprintln!(
            "{} uses only safe settings (no host access).",
            path.display()
        );
    } else {
        print_capabilities(&path, &caps);
    }

    match trust::trust(&path, content.as_bytes()) {
        Ok(()) => eprintln!("trusted {}", path.display()),
        Err(e) => {
            eprintln!("error: cannot record trust: {e}");
            std::process::exit(1);
        }
    }
}

/// `redan untrust [path]`: remove a config from the trust store.
pub(crate) fn untrust_cmd(path_arg: Option<&str>) {
    let path = resolve_config_path(path_arg);
    match trust::untrust(&path) {
        Ok(()) => eprintln!("no longer trusting {}", path.display()),
        Err(e) => {
            eprintln!("error: cannot update trust store: {e}");
            std::process::exit(1);
        }
    }
}

fn resolve_config_path(path_arg: Option<&str>) -> PathBuf {
    PathBuf::from(path_arg.unwrap_or("redan.toml"))
}

fn read_or_exit(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("error: cannot read {}: {e}", path.display());
        std::process::exit(1);
    })
}

fn print_capabilities(path: &Path, caps: &[Capability]) {
    eprintln!("{} would be allowed to:", path.display());
    for line in describe_all(caps) {
        eprintln!("  - {line}");
    }
}

/// Human-readable summary lines for a capability list.
fn describe_all(caps: &[Capability]) -> Vec<String> {
    caps.iter().map(describe).collect()
}

fn describe(cap: &Capability) -> String {
    match cap {
        Capability::Rootfs(p) => {
            format!("use {p} as the guest root  [exposes that host directory to the guest]")
        }
        Capability::AuditLog(p) => format!("write an audit log to host path {p}"),
        Capability::LogFile(p) => format!("write logs to host path {p}"),
        Capability::Forward(s) => {
            format!("forward port {s} to a host-local service  [reachable from the guest]")
        }
        Capability::EnvSecret { name, var } => {
            format!("read host env var ${var} (secret {name})  [reads your shell environment]")
        }
        Capability::VaultSecret { name, reference } => {
            format!("fetch {reference} from Vault (secret {name})  [uses your Vault token]")
        }
        Capability::OutOfTreeMount { source, target, .. } => {
            format!("mount {source} -> {target}  [path OUTSIDE the project directory]")
        }
    }
}

fn confirm(question: &str) -> bool {
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_flags_dangerous_capabilities() {
        let caps = vec![
            Capability::EnvSecret {
                name: "K".into(),
                var: "AWS_SECRET".into(),
            },
            Capability::OutOfTreeMount {
                name: "m".into(),
                source: "/home/u/.ssh".into(),
                target: "/ssh".into(),
            },
        ];
        let lines = describe_all(&caps);
        assert!(lines[0].contains("AWS_SECRET"));
        assert!(lines[0].contains("shell environment"));
        assert!(lines[1].contains("/home/u/.ssh"));
        assert!(lines[1].contains("OUTSIDE"));
    }
}
