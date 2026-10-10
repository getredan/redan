//! Embedded templates rendered with minijinja.
//!
//! Template sources live in `templates/*.j2` and are included at
//! compile time via `include_str!`. Adding or modifying a `.j2` file
//! triggers a rebuild (see `build.rs`).
//!
//! Template registration and rendering panic on failure because the templates
//! are compiled in and validated by tests. A syntax error is a build bug.

use std::sync::LazyLock;

use minijinja::{Environment, context};

use crate::config::Config;

/// Template name and compiled-in source, in registration order.
const TEMPLATES: [(&str, &str); 4] = [
    ("redan.toml", include_str!("../templates/redan.toml.j2")),
    (
        "claude.dockerfile",
        include_str!("../templates/claude.dockerfile.j2"),
    ),
    (
        "devcontainer.json",
        include_str!("../templates/devcontainer.json.j2"),
    ),
    ("guest-policy", include_str!("../templates/guest-policy.j2")),
];

static ENV: LazyLock<Environment<'static>> = LazyLock::new(build_env);

#[expect(
    clippy::unwrap_used,
    reason = "the templates are compiled in and checked by tests, so a syntax error is a build bug"
)]
fn build_env() -> Environment<'static> {
    let mut env = Environment::new();
    for (name, source) in TEMPLATES {
        env.add_template(name, source).unwrap();
    }
    env
}

#[expect(
    clippy::unwrap_used,
    reason = "every name is registered in `ENV` and the contexts are built from plain data, so a failure is a build bug"
)]
fn render(name: &str, ctx: minijinja::Value) -> String {
    ENV.get_template(name).unwrap().render(ctx).unwrap()
}

/// Render `redan.toml` from a Config and mode flag.
///
/// # Panics
///
/// Panics if the compiled-in template fails to render, which is a build bug.
#[must_use]
pub fn redan_toml(cfg: &Config, claude: bool) -> String {
    let mounts: Vec<(&String, &crate::config::MountConfig)> = cfg.mount.iter().collect();
    let env_vars: Vec<(&String, &String)> = cfg.env.iter().collect();

    render(
        "redan.toml",
        context! {
            image => cfg.image,
            command => cfg.command,
            interactive => cfg.interactive,
            timeout => cfg.timeout,
            claude,
            allow_hosts => cfg.network.allow,
            forwards => cfg.network.forward,
            mounts,
            env => env_vars,
        },
    )
}

/// Render the Claude Code Dockerfile.
///
/// # Panics
///
/// Panics if the compiled-in template fails to render, which is a build bug.
#[must_use]
pub fn claude_dockerfile(
    base_image: &str,
    apt_packages: &[&str],
    needs_node: bool,
    has_python: bool,
) -> String {
    render(
        "claude.dockerfile",
        context! {
            base_image,
            apt_packages,
            needs_node,
            has_python,
        },
    )
}

/// Render devcontainer.json (static for now, but templated for future fields).
///
/// # Panics
///
/// Panics if the compiled-in template fails to render, which is a build bug.
#[must_use]
pub fn devcontainer_json() -> String {
    render("devcontainer.json", context! {})
}

/// Render the guest `/etc/redan/policy` file.
///
/// # Panics
///
/// Panics if the compiled-in template fails to render, which is a build bug.
#[must_use]
pub fn guest_policy(allowed_hosts: Option<&Vec<String>>) -> String {
    let (mode, hosts) = match allowed_hosts {
        None => ("allow-all", vec![]),
        Some(h) if h.is_empty() => ("deny-all", vec![]),
        Some(h) => ("restrict", h.iter().map(String::as_str).collect()),
    };

    render("guest-policy", context! { mode, hosts })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, MountConfig, NetworkConfig};

    #[test]
    fn redan_toml_claude_mode() {
        let mut cfg = Config {
            image: Some("test-project".into()),
            command: Some("claude --dangerously-skip-permissions".into()),
            interactive: Some(true),
            network: NetworkConfig {
                allow: vec!["api.anthropic.com".into(), "pypi.org".into()],
                ..NetworkConfig::default()
            },
            ..Config::default()
        };
        cfg.mount.insert(
            "workspace".into(),
            MountConfig {
                source: ".".into(),
                target: Some("/workspace".into()),
                read_only: false,
            },
        );
        cfg.env
            .insert("CLAUDE_CONFIG_DIR".into(), "/home/dev/.claude".into());

        let out = redan_toml(&cfg, true);
        assert!(out.contains("--dangerously-skip-permissions"));
        assert!(out.contains("# Remove --dangerously-skip-permissions"));
        assert!(out.contains("CLAUDE_CONFIG_DIR"));
        assert!(out.contains("[mount.workspace]"));
        assert!(out.contains("\"api.anthropic.com\""));
    }

    #[test]
    fn redan_toml_plain_mode() {
        let mut cfg = Config {
            image: Some("myapp".into()),
            command: Some("/bin/sh".into()),
            network: NetworkConfig {
                allow: vec!["registry.npmjs.org".into()],
                ..NetworkConfig::default()
            },
            ..Config::default()
        };
        cfg.mount.insert(
            "workspace".into(),
            MountConfig {
                source: ".".into(),
                target: Some("/workspace".into()),
                read_only: false,
            },
        );

        let out = redan_toml(&cfg, false);
        assert!(out.contains("command = \"/bin/sh\""));
        assert!(out.contains("# Allowed outbound hosts"));
        assert!(!out.contains("dangerously"));
        assert!(!out.contains("CLAUDE_CONFIG_DIR"));
    }

    #[test]
    fn redan_toml_with_forwards() {
        let cfg = Config {
            image: Some("myapp".into()),
            command: Some("/bin/sh".into()),
            network: NetworkConfig {
                allow: vec![],
                forward: vec!["9222".into(), "8080:3000".into()],
            },
            ..Config::default()
        };

        let out = redan_toml(&cfg, false);
        assert!(out.contains("\"9222\""));
        assert!(out.contains("\"8080:3000\""));
        assert!(out.contains("forward = ["));
    }

    #[test]
    fn claude_dockerfile_renders() {
        let out = claude_dockerfile("ubuntu:24.04", &["curl", "git"], true, true);
        assert!(out.contains("FROM ubuntu:24.04"));
        assert!(out.contains("curl"));
        assert!(out.contains("nodesource"));
        assert!(out.contains("astral-sh/uv"));
    }

    #[test]
    fn guest_policy_restrict() {
        let hosts = Some(vec!["api.example.com".into(), "cdn.example.com".into()]);
        let out = guest_policy(hosts.as_ref());
        assert!(out.contains("network: restrict"));
        assert!(out.contains("- api.example.com"));
        assert!(out.contains("- cdn.example.com"));
    }

    #[test]
    fn guest_policy_deny_all() {
        let empty: Vec<String> = vec![];
        let out = guest_policy(Some(&empty));
        assert!(out.contains("network: deny-all"));
    }

    #[test]
    fn guest_policy_allow_all() {
        let out = guest_policy(None);
        assert!(out.contains("network: allow-all"));
    }
}
