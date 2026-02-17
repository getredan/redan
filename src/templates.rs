//! Embedded templates rendered with minijinja.
//!
//! Template sources live in `templates/*.j2` and are included at
//! compile time via `include_str!`. Adding or modifying a `.j2` file
//! triggers a rebuild (see `build.rs`).

use minijinja::{context, Environment};

use crate::config::Config;

const REDAN_TOML: &str = include_str!("../templates/redan.toml.j2");
const CLAUDE_DOCKERFILE: &str = include_str!("../templates/claude.dockerfile.j2");
const DEVCONTAINER_JSON: &str = include_str!("../templates/devcontainer.json.j2");
const GUEST_POLICY: &str = include_str!("../templates/guest-policy.j2");

fn env() -> Environment<'static> {
    let mut env = Environment::new();
    env.add_template("redan.toml", REDAN_TOML).unwrap();
    env.add_template("claude.dockerfile", CLAUDE_DOCKERFILE)
        .unwrap();
    env.add_template("devcontainer.json", DEVCONTAINER_JSON)
        .unwrap();
    env.add_template("guest-policy", GUEST_POLICY).unwrap();
    env
}

/// Render `redan.toml` from a Config and mode flag.
pub fn redan_toml(cfg: &Config, claude: bool) -> String {
    let mounts: Vec<(&String, &crate::config::MountConfig)> = cfg.mount.iter().collect();
    let env_vars: Vec<(&String, &String)> = cfg.env.iter().collect();

    env()
        .get_template("redan.toml")
        .unwrap()
        .render(context! {
            image => cfg.image,
            command => cfg.command,
            interactive => cfg.interactive,
            timeout => cfg.timeout,
            claude,
            allow_hosts => cfg.network.allow,
            mounts,
            env => env_vars,
        })
        .unwrap()
}

/// Render the Claude Code Dockerfile.
pub fn claude_dockerfile(
    base_image: &str,
    apt_packages: &[&str],
    needs_node: bool,
    has_python: bool,
) -> String {
    env()
        .get_template("claude.dockerfile")
        .unwrap()
        .render(context! {
            base_image,
            apt_packages,
            needs_node,
            has_python,
        })
        .unwrap()
}

/// Render devcontainer.json (static for now, but templated for future fields).
pub fn devcontainer_json() -> String {
    env()
        .get_template("devcontainer.json")
        .unwrap()
        .render(context! {})
        .unwrap()
}

/// Render the guest `/etc/redan/policy` file.
pub fn guest_policy(allowed_hosts: &Option<Vec<String>>) -> String {
    let (mode, hosts) = match allowed_hosts {
        None => ("allow-all", vec![]),
        Some(h) if h.is_empty() => ("deny-all", vec![]),
        Some(h) => ("restrict", h.iter().map(|s| s.as_str()).collect()),
    };

    env()
        .get_template("guest-policy")
        .unwrap()
        .render(context! { mode, hosts })
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, MountConfig, NetworkConfig};
    use std::collections::BTreeMap;

    #[test]
    fn redan_toml_claude_mode() {
        let mut cfg = Config::default();
        cfg.image = Some("test-project".into());
        cfg.command = Some("claude --dangerously-skip-permissions".into());
        cfg.interactive = Some(true);
        cfg.network = NetworkConfig {
            allow: vec!["api.anthropic.com".into(), "pypi.org".into()],
        };
        cfg.mount.insert(
            "workspace".into(),
            MountConfig {
                source: ".".into(),
                target: Some("/workspace".into()),
            },
        );
        cfg.env
            .insert("CLAUDE_CONFIG_DIR".into(), "/workspace/.claude".into());

        let out = redan_toml(&cfg, true);
        assert!(out.contains("--dangerously-skip-permissions"));
        assert!(out.contains("# Remove --dangerously-skip-permissions"));
        assert!(out.contains("CLAUDE_CONFIG_DIR"));
        assert!(out.contains("[mount.workspace]"));
        assert!(out.contains("\"api.anthropic.com\""));
    }

    #[test]
    fn redan_toml_plain_mode() {
        let mut cfg = Config::default();
        cfg.image = Some("myapp".into());
        cfg.command = Some("/bin/sh".into());
        cfg.network = NetworkConfig {
            allow: vec!["registry.npmjs.org".into()],
        };
        cfg.mount.insert(
            "workspace".into(),
            MountConfig {
                source: ".".into(),
                target: Some("/workspace".into()),
            },
        );

        let out = redan_toml(&cfg, false);
        assert!(out.contains("command = \"/bin/sh\""));
        assert!(out.contains("# Allowed outbound hosts"));
        assert!(!out.contains("dangerously"));
        assert!(!out.contains("CLAUDE_CONFIG_DIR"));
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
        let out = guest_policy(&hosts);
        assert!(out.contains("network: restrict"));
        assert!(out.contains("- api.example.com"));
        assert!(out.contains("- cdn.example.com"));
    }

    #[test]
    fn guest_policy_deny_all() {
        let out = guest_policy(&Some(vec![]));
        assert!(out.contains("network: deny-all"));
    }

    #[test]
    fn guest_policy_allow_all() {
        let out = guest_policy(&None);
        assert!(out.contains("network: allow-all"));
    }
}
