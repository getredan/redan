//! Trust for working-directory `redan.toml` files.
//!
//! A `redan.toml` discovered in the current directory is a host-context input:
//! the host process reads it, before the VM boots, with the operator's own
//! authority. It can read host env vars and Vault (`env://` / `vault://`
//! secrets), mount host paths into the guest, set a host `rootfs`, forward
//! host-local ports, and write host log files. So a config that reaches for any
//! of that must be explicitly trusted before redan acts on it. A config that
//! stays within a safe subset (image, command, guest env, allowlist, a project
//! workspace mount) needs no trust, since none of it touches host authority.
//!
//! Trust is a machine-local consent record, **not** a cryptographic signature.
//! The store is `~/.local/state/redan/trust.json`, protected only by filesystem
//! permissions. It defends against the sandboxed guest agent (which can edit the
//! mounted `redan.toml` but cannot reach the host-side store, and any edit
//! changes the content hash, so trust is invalidated) and against accidentally
//! using an unreviewed config. It does **not** defend against a process already
//! running as your user on the host, which has won by other means. See
//! `docs/security-model.md`.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::config::Config;

/// A capability in a config that reaches host authority and therefore needs
/// trust. The list doubles as the summary shown when granting trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// `rootfs = "<path>"`: a host directory used as the guest root.
    Rootfs(String),
    /// `audit_log = "<path>"`: a host file redan writes to.
    AuditLog(String),
    /// `log_file = "<path>"`: a host file redan writes to.
    LogFile(String),
    /// `[network] forward`: exposes a host-local port to the guest.
    Forward(String),
    /// `[secrets.<name>] value = "env://<var>"`: reads a host env var.
    EnvSecret { name: String, var: String },
    /// `[secrets.<name>] value = "vault://<ref>"`: reads from Vault.
    VaultSecret { name: String, reference: String },
    /// `[mount.<name>]` whose source resolves outside the project directory.
    OutOfTreeMount {
        name: String,
        source: String,
        target: String,
    },
}

/// The capabilities in `cfg` that require trust. Empty means the config is
/// within the safe subset and may load without trust.
///
/// `project_root` is the directory the config was loaded from; a mount whose
/// source resolves inside it is project-local and safe.
#[must_use]
pub fn analyze(cfg: &Config, project_root: &Path) -> Vec<Capability> {
    // Exhaustive destructure, intentionally without `..`: adding a field to
    // Config forces a classification decision right here. Do NOT add `..` to
    // silence a future compile error -- that would let a new capability load
    // without trust (fail-open). Anything not provably sandbox-safe must be
    // pushed as a Capability.
    let Config {
        // Safe: sandbox-confined, or policy that cannot exfiltrate on its own.
        image: _,       // a named local image
        command: _,     // runs inside the VM
        timeout: _,     // tuning
        interactive: _, // tuning
        env: _,         // guest-side env vars
        rootfs,
        audit_log,
        log_file,
        network,
        secrets,
        mount,
    } = cfg;

    let mut caps = Vec::new();

    if let Some(path) = rootfs {
        caps.push(Capability::Rootfs(path.clone()));
    }
    if let Some(path) = audit_log {
        caps.push(Capability::AuditLog(path.clone()));
    }
    if let Some(path) = log_file {
        caps.push(Capability::LogFile(path.clone()));
    }
    // network.allow only widens reachable hosts; without a secret it cannot
    // exfiltrate, so it is safe. forward exposes a host-local port to the guest.
    for spec in &network.forward {
        caps.push(Capability::Forward(spec.clone()));
    }
    for (name, secret) in secrets {
        // Schemes per provider::resolve_secret_value. A literal value is the
        // config author's own data and reads nothing from the host, so it is
        // safe; env:// and vault:// read the operator's ambient credentials.
        if let Some(var) = secret.value.strip_prefix("env://") {
            caps.push(Capability::EnvSecret {
                name: name.clone(),
                var: var.to_string(),
            });
        } else if let Some(reference) = secret.value.strip_prefix("vault://") {
            caps.push(Capability::VaultSecret {
                name: name.clone(),
                reference: reference.to_string(),
            });
        }
    }
    for (name, m) in mount {
        if !is_within_project(project_root, &m.source) {
            caps.push(Capability::OutOfTreeMount {
                name: name.clone(),
                source: m.source.clone(),
                target: m.target.clone().unwrap_or_else(|| "/workspace".into()),
            });
        }
    }

    caps
}

/// Whether `source` (resolved relative to `project_root`) lies inside
/// `project_root`. Fails safe: if either path cannot be canonicalized, returns
/// `false`, so the mount is treated as out-of-tree and requires trust.
fn is_within_project(project_root: &Path, source: &str) -> bool {
    let Ok(root) = project_root.canonicalize() else {
        return false;
    };
    let raw = Path::new(source);
    let candidate = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        root.join(raw)
    };
    candidate.canonicalize().is_ok_and(|c| c.starts_with(&root))
}

/// What to do with a discovered config once it has been classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Safe subset, or already trusted: load and use it.
    Load,
    /// Needs trust, interactive session: ask the user (show the summary, prompt).
    Prompt,
    /// Needs trust but it isn't trusted and we can't ask: do not use the file.
    Skip,
}

/// Decide what to do with a discovered config.
///
/// `needs_trust` is `!analyze(...).is_empty()`. A safe or already-trusted config
/// just loads; otherwise an interactive session prompts and a non-interactive
/// one skips. Trust is granted only via the prompt or `redan trust`; a config
/// is never auto-trusted without a TTY.
#[must_use]
pub const fn decide(needs_trust: bool, already_trusted: bool, interactive: bool) -> Decision {
    if !needs_trust || already_trusted {
        Decision::Load
    } else if interactive {
        Decision::Prompt
    } else {
        Decision::Skip
    }
}

// --- Trust store ---

/// canonical config path -> `"sha256:<hex>"` of the trusted contents.
type Store = BTreeMap<String, String>;

const STORE_FILE: &str = "trust.json";

/// `~/.local/state/redan/trust.json` (honoring `XDG_STATE_HOME`).
fn store_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("redan").join(STORE_FILE))
}

/// SHA-256 of `content`, prefixed for algorithm agility.
#[must_use]
pub fn fingerprint(content: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, content);
    let mut hex = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        let _ = write!(hex, "{byte:02x}");
    }
    format!("sha256:{hex}")
}

/// Canonical absolute path as the store key, or `None` if it can't resolve.
fn canonical_key(path: &Path) -> Option<String> {
    path.canonicalize()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn read_store(store_path: &Path) -> Store {
    let Ok(content) = std::fs::read_to_string(store_path) else {
        return Store::new();
    };
    serde_json::from_str(&content).unwrap_or_else(|e| {
        log::warn!(
            "trust store {} is unreadable ({e}); treating all configs as untrusted",
            store_path.display()
        );
        Store::new()
    })
}

fn write_store(store_path: &Path, store: &Store) -> io::Result<()> {
    if let Some(dir) = store_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_string_pretty(store).map_err(io::Error::other)?;

    // Write to a temp sibling then rename, so a crash mid-write can't corrupt
    // the store. 0600: the store isn't secret, but there's no reason for other
    // users on a shared host to read or poke it.
    let tmp = store_path.with_file_name(format!("{STORE_FILE}.tmp"));
    {
        use std::io::Write as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, store_path)
}

fn is_trusted_in(store_path: &Path, config_path: &Path, content: &[u8]) -> bool {
    let Some(key) = canonical_key(config_path) else {
        return false;
    };
    read_store(store_path)
        .get(&key)
        .is_some_and(|stored| *stored == fingerprint(content))
}

fn trust_in(store_path: &Path, config_path: &Path, content: &[u8]) -> io::Result<()> {
    let key = canonical_key(config_path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot resolve {}", config_path.display()),
        )
    })?;
    let mut store = read_store(store_path);
    store.insert(key, fingerprint(content));
    write_store(store_path, &store)
}

fn untrust_in(store_path: &Path, config_path: &Path) -> io::Result<()> {
    let key = canonical_key(config_path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot resolve {}", config_path.display()),
        )
    })?;
    let mut store = read_store(store_path);
    store.remove(&key);
    write_store(store_path, &store)
}

fn no_store_dir() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "cannot determine state directory (set HOME or XDG_STATE_HOME)",
    )
}

/// Whether `config_path` with these exact `content` bytes is trusted.
///
/// Hash the same bytes you go on to parse, so the trust decision and the load
/// see identical content (no check-then-read gap).
#[must_use]
pub fn is_trusted(config_path: &Path, content: &[u8]) -> bool {
    store_path().is_some_and(|sp| is_trusted_in(&sp, config_path, content))
}

/// Record `config_path` with these `content` bytes as trusted.
pub fn trust(config_path: &Path, content: &[u8]) -> io::Result<()> {
    let sp = store_path().ok_or_else(no_store_dir)?;
    trust_in(&sp, config_path, content)
}

/// Remove `config_path` from the trust store.
pub fn untrust(config_path: &Path) -> io::Result<()> {
    let sp = store_path().ok_or_else(no_store_dir)?;
    untrust_in(&sp, config_path)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::{Config, MountConfig, NetworkConfig, SecretConfig};

    fn write(path: &Path, content: &str) {
        std::fs::write(path, content).unwrap();
    }

    // --- fingerprint ---

    #[test]
    fn fingerprint_is_stable_and_prefixed() {
        let a = fingerprint(b"hello");
        let b = fingerprint(b"hello");
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
        // SHA-256 hex is 64 chars after the prefix.
        assert_eq!(a.len(), "sha256:".len() + 64);
    }

    #[test]
    fn fingerprint_changes_with_content() {
        assert_ne!(fingerprint(b"hello"), fingerprint(b"hello!"));
    }

    // --- decide ---

    #[test]
    fn safe_config_always_loads() {
        for trusted in [false, true] {
            for tty in [false, true] {
                assert_eq!(decide(false, trusted, tty), Decision::Load);
            }
        }
    }

    #[test]
    fn trusted_config_loads() {
        assert_eq!(decide(true, true, false), Decision::Load);
    }

    #[test]
    fn untrusted_interactive_prompts() {
        assert_eq!(decide(true, false, true), Decision::Prompt);
    }

    #[test]
    fn untrusted_noninteractive_skips() {
        // Never auto-trust without a TTY (grant via the prompt or `redan trust`).
        assert_eq!(decide(true, false, false), Decision::Skip);
    }

    // --- store round-trip via the *_in cores (no env mutation) ---

    #[test]
    fn trust_then_is_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("trust.json");
        let cfg = dir.path().join("redan.toml");
        write(&cfg, "image = \"x\"\n");
        let content = std::fs::read(&cfg).unwrap();

        assert!(!is_trusted_in(&store, &cfg, &content));
        trust_in(&store, &cfg, &content).unwrap();
        assert!(is_trusted_in(&store, &cfg, &content));
    }

    #[test]
    fn editing_content_invalidates_trust() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("trust.json");
        let cfg = dir.path().join("redan.toml");
        write(&cfg, "image = \"x\"\n");
        trust_in(&store, &cfg, &std::fs::read(&cfg).unwrap()).unwrap();

        // An edit (e.g. by the guest agent) changes the bytes -> not trusted.
        write(&cfg, "image = \"x\"\nrootfs = \"/\"\n");
        assert!(!is_trusted_in(&store, &cfg, &std::fs::read(&cfg).unwrap()));
    }

    #[test]
    fn untrust_removes_trust() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("trust.json");
        let cfg = dir.path().join("redan.toml");
        write(&cfg, "image = \"x\"\n");
        let content = std::fs::read(&cfg).unwrap();
        trust_in(&store, &cfg, &content).unwrap();
        untrust_in(&store, &cfg).unwrap();
        assert!(!is_trusted_in(&store, &cfg, &content));
    }

    #[test]
    fn missing_store_is_untrusted_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("does-not-exist.json");
        let cfg = dir.path().join("redan.toml");
        write(&cfg, "image = \"x\"\n");
        assert!(!is_trusted_in(&store, &cfg, &std::fs::read(&cfg).unwrap()));
    }

    #[test]
    fn corrupt_store_is_untrusted_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("trust.json");
        write(&store, "{ this is not valid json");
        let cfg = dir.path().join("redan.toml");
        write(&cfg, "image = \"x\"\n");
        assert!(!is_trusted_in(&store, &cfg, &std::fs::read(&cfg).unwrap()));
    }

    #[test]
    fn store_written_with_owner_only_perms() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("trust.json");
        let cfg = dir.path().join("redan.toml");
        write(&cfg, "image = \"x\"\n");
        trust_in(&store, &cfg, &std::fs::read(&cfg).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&store).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "got mode {:o}", mode & 0o777);
        }
    }

    // --- analyze (capability classification) ---

    fn empty_config() -> Config {
        Config::default()
    }

    #[test]
    fn safe_subset_needs_no_trust() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config {
            image: Some("claude-code".into()),
            command: Some("claude".into()),
            interactive: Some(true),
            timeout: Some(3600),
            network: NetworkConfig {
                allow: vec!["api.anthropic.com".into()],
                forward: vec![],
            },
            ..empty_config()
        };
        cfg.env.insert("HOME".into(), "/home/dev".into());
        // A literal secret reads nothing from the host.
        cfg.secrets.insert(
            "K".into(),
            SecretConfig {
                value: "sk-literal".into(),
                hosts: vec!["api.anthropic.com".into()],
            },
        );
        // The project workspace mount.
        cfg.mount.insert(
            "workspace".into(),
            MountConfig {
                source: ".".into(),
                target: Some("/workspace".into()),
                read_only: false,
            },
        );
        assert!(analyze(&cfg, dir.path()).is_empty());
    }

    #[test]
    fn env_and_vault_secrets_require_trust() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = empty_config();
        cfg.secrets.insert(
            "A".into(),
            SecretConfig {
                value: "env://AWS_SECRET_ACCESS_KEY".into(),
                hosts: vec!["evil.example".into()],
            },
        );
        cfg.secrets.insert(
            "B".into(),
            SecretConfig {
                value: "vault://ci/github#token".into(),
                hosts: vec!["github.com".into()],
            },
        );
        let caps = analyze(&cfg, dir.path());
        assert!(caps.contains(&Capability::EnvSecret {
            name: "A".into(),
            var: "AWS_SECRET_ACCESS_KEY".into(),
        }));
        assert!(caps.contains(&Capability::VaultSecret {
            name: "B".into(),
            reference: "ci/github#token".into(),
        }));
    }

    #[test]
    fn rootfs_audit_log_and_forward_require_trust() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            rootfs: Some("/srv/rootfs".into()),
            audit_log: Some("/var/log/redan.jsonl".into()),
            log_file: Some("/tmp/redan.log".into()),
            network: NetworkConfig {
                allow: vec![],
                forward: vec!["9222".into()],
            },
            ..empty_config()
        };
        let caps = analyze(&cfg, dir.path());
        assert!(caps.contains(&Capability::Rootfs("/srv/rootfs".into())));
        assert!(caps.contains(&Capability::AuditLog("/var/log/redan.jsonl".into())));
        assert!(caps.contains(&Capability::LogFile("/tmp/redan.log".into())));
        assert!(caps.contains(&Capability::Forward("9222".into())));
    }

    #[test]
    fn in_tree_mount_is_safe_out_of_tree_needs_trust() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        // A real subdirectory of the project (must exist to canonicalize).
        let sub = project.path().join("src");
        std::fs::create_dir(&sub).unwrap();

        let mut cfg = empty_config();
        cfg.mount.insert(
            "workspace".into(),
            MountConfig {
                source: ".".into(),
                target: Some("/workspace".into()),
                read_only: false,
            },
        );
        cfg.mount.insert(
            "code".into(),
            MountConfig {
                source: "src".into(),
                target: Some("/code".into()),
                read_only: false,
            },
        );
        cfg.mount.insert(
            "secrets".into(),
            MountConfig {
                source: outside.path().to_string_lossy().into_owned(),
                target: Some("/host".into()),
                read_only: false,
            },
        );

        let caps = analyze(&cfg, project.path());
        // Only the out-of-tree mount is flagged.
        assert_eq!(caps.len(), 1, "caps: {caps:?}");
        assert!(matches!(
            &caps[0],
            Capability::OutOfTreeMount { name, target, .. }
                if name == "secrets" && target == "/host"
        ));
    }

    #[test]
    fn unresolvable_mount_source_fails_safe_as_out_of_tree() {
        let project = tempfile::tempdir().unwrap();
        let mut cfg = empty_config();
        cfg.mount.insert(
            "ghost".into(),
            MountConfig {
                source: "does-not-exist-yet".into(),
                target: Some("/ghost".into()),
                read_only: false,
            },
        );
        // Can't canonicalize -> treated as out-of-tree (requires trust).
        assert_eq!(analyze(&cfg, project.path()).len(), 1);
    }
}
