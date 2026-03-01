use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use redan::ca::MitmCa;
use redan::proxy;
use redan::secret::SecretBinding;
use redan::session;
use redan::templates;
use redan::vm;

pub(crate) struct ExecConfig<'a> {
    pub rootfs: &'a str,
    pub command: &'a str,
    pub interactive: bool,
    pub timeout_secs: u64,
    pub secret_specs: &'a [String],
    pub allow_host_specs: &'a [String],
    pub mount_specs: &'a [String],
    pub audit_log_path: Option<&'a str>,
    pub image_name: Option<&'a str>,
    pub guest_env: &'a BTreeMap<String, String>,
    pub discover: bool,
    pub session_name: Option<&'a str>,
    /// Pre-existing session ID (for daemon mode). If None, creates a new session.
    pub session_id: Option<&'a str>,
}

pub(crate) fn run(cfg: &ExecConfig<'_>) {
    // Create or reuse session
    let session_id = cfg.session_id.map_or_else(session::new_id, Into::into);
    let mut meta = if cfg.session_id.is_some() {
        // Daemon mode: reload existing metadata (written by exec_detached)
        let meta_path = session::session_dir(&session_id).join("meta.json");
        std::fs::read_to_string(&meta_path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_else(|| {
                session::SessionMeta::new(&session_id, cfg.image_name, Some(cfg.command))
            })
    } else {
        let mut m = session::SessionMeta::new(&session_id, cfg.image_name, Some(cfg.command));
        m.name = cfg.session_name.map(Into::into);
        if let Err(e) = m.save() {
            log::warn!("cannot save session metadata: {e}");
        }
        m
    };
    log::info!("session {session_id} started");

    // In interactive mode, redirect logs to a file so they don't
    // interleave with the guest TUI.
    if cfg.interactive {
        let log_path = session::session_dir(&session_id).join("redan.log");
        eprintln!("session: {session_id} (logs: {})", log_path.display());
        crate::redirect_logs_to_file(&log_path);
    }

    // Use session audit log if no explicit --audit-log
    let session_audit = session::audit_log_path(&session_id);
    let audit_log_path = cfg.audit_log_path.map_or_else(
        || session_audit.to_string_lossy().into_owned(),
        str::to_string,
    );
    let audit_log_path = Some(audit_log_path.as_str());

    let ca = MitmCa::generate();
    log::info!("MITM CA generated");

    // Install CA cert in guest rootfs
    if let Err(e) = vm::install_ca_cert(Path::new(cfg.rootfs), ca.ca_cert_pem()) {
        eprintln!("failed to install CA cert in rootfs: {e}");
        std::process::exit(1);
    }
    log::info!("CA cert installed in guest trust store");

    // Parse secrets: generate placeholders, collect bindings
    let mut secrets: Vec<SecretBinding> = Vec::new();
    let mut secret_env: Vec<(String, String)> = Vec::new();
    for spec in cfg.secret_specs {
        match parse_secret(spec) {
            Ok((env_name, binding)) => {
                log::info!(
                    "secret: {env_name} -> placeholder {} for [{}]",
                    binding.placeholder(),
                    binding.allowed_hosts().join(", ")
                );
                secret_env.push((env_name, binding.placeholder().to_string()));
                secrets.push(binding);
            }
            Err(e) => {
                let redacted = redact_secret_spec(spec);
                eprintln!("invalid --secret spec '{redacted}': {e}");
                std::process::exit(1);
            }
        }
    }

    // Validate --allow-host values
    for host in cfg.allow_host_specs {
        if host == "*" {
            continue;
        }
        if host.contains("://") || host.contains('/') || host.contains(':') {
            eprintln!("error: --allow-host takes a hostname, not a URL or host:port: {host}");
            std::process::exit(1);
        }
    }

    // Default-deny: all outbound HTTPS blocked unless explicitly allowed.
    let allowed_hosts: Option<Vec<String>> = if cfg.allow_host_specs.iter().any(|spec| spec == "*")
    {
        None
    } else {
        let mut hosts: Vec<String> = cfg
            .allow_host_specs
            .iter()
            .map(|host| host.to_ascii_lowercase())
            .collect();
        // Include secret hosts automatically
        for s in &secrets {
            for h in s.allowed_hosts() {
                let lower = h.to_ascii_lowercase();
                if !hosts.contains(&lower) {
                    hosts.push(lower);
                }
            }
        }
        if hosts.is_empty() {
            log::info!("network: default-deny (no hosts allowed)");
        } else {
            log::info!("allowed hosts: {}", hosts.join(", "));
        }
        Some(hosts)
    };

    // Parse mounts
    let mut virtiofs_mounts: Vec<(String, String)> = Vec::new();
    let mut mount_commands: Vec<String> = Vec::new();
    for (i, spec) in cfg.mount_specs.iter().enumerate() {
        let (host_path, guest_path) = parse_mount(spec);
        if !Path::new(&host_path).exists() {
            eprintln!("mount source does not exist: {host_path}");
            std::process::exit(1);
        }
        let tag = format!("fs{i}");
        log::info!("mount: {host_path} -> {guest_path} (tag={tag})");

        let mp = Path::new(cfg.rootfs).join(guest_path.trim_start_matches('/'));
        std::fs::create_dir_all(&mp).ok();

        virtiofs_mounts.push((tag.clone(), host_path));
        mount_commands.push(format!("mount -t virtiofs {tag} {guest_path}"));
    }

    // Build guest command: network setup + CA trust + mounts + user command
    let net_setup = vm::net_setup_commands(&proxy::GATEWAY_IP.to_string(), proxy::GUEST_IP);
    let ca_update = vm::ca_update_commands();
    let mount_setup = mount_commands.join("; ");
    let full_command = if mount_setup.is_empty() {
        format!("{net_setup}; {ca_update}; {}", cfg.command)
    } else {
        format!("{net_setup}; {ca_update}; {mount_setup}; {}", cfg.command)
    };

    let mut env: Vec<String> = vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        "TERM=xterm".into(),
        "SSL_CERT_FILE=/etc/ssl/certs/redan-ca.pem".into(),
        "NODE_EXTRA_CA_CERTS=/etc/ssl/certs/redan-ca.pem".into(),
        "REDAN=1".into(),
    ];

    // Tell the guest about network policy
    match &allowed_hosts {
        None => {
            env.push("REDAN_NETWORK=allow-all".into());
        }
        Some(hosts) if hosts.is_empty() => {
            env.push("REDAN_NETWORK=deny-all".into());
            env.push("REDAN_ALLOWED_HOSTS=".into());
        }
        Some(hosts) => {
            env.push("REDAN_NETWORK=restrict".into());
            env.push(format!("REDAN_ALLOWED_HOSTS={}", hosts.join(",")));
        }
    }

    // Write /etc/redan/policy in the guest rootfs
    write_guest_policy(Path::new(cfg.rootfs), allowed_hosts.as_ref());

    // Add secret placeholders as env vars
    for (name, placeholder) in &secret_env {
        env.push(format!("{name}={placeholder}"));
    }

    // Add user-defined env vars from config
    for (name, value) in cfg.guest_env {
        env.push(format!("{name}={value}"));
    }

    let vm_config = vm::VmConfig {
        rootfs: cfg.rootfs.into(),
        vcpus: 1,
        ram_mib: 256,
        command: full_command,
        env,
        virtiofs_mounts,
        interactive: cfg.interactive,
    };

    // In interactive mode, set the host terminal to raw mode
    let _raw_guard = if cfg.interactive {
        Some(redan::terminal::RawTerminalGuard::enter())
    } else {
        None
    };

    let vm_handle = vm::Vm::boot(vm_config);

    let net_sock = match vm_handle.net_sock.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to clone VM network socket: {e}");
            std::process::exit(1);
        }
    };

    let discovered = proxy::run(proxy::ProxyConfig {
        host_sock: net_sock,
        ca: std::sync::Arc::new(std::sync::Mutex::new(ca)),
        secrets: &secrets,
        timeout: Duration::from_secs(cfg.timeout_secs),
        allowed_hosts,
        audit_log_path,
        discover: cfg.discover,
    });

    if cfg.discover && !discovered.is_empty() {
        eprintln!("\n--- discovered hosts ---");
        eprintln!("The agent connected to these hosts:\n");
        for host in &discovered {
            eprintln!("  {host}");
        }
        eprintln!("\nSuggested redan.toml:\n");
        eprintln!("[network]");
        eprintln!("allow = [");
        for host in &discovered {
            eprintln!("    \"{host}\",");
        }
        eprintln!("]");
    }

    meta.finish(true);
    log::info!("session {session_id} finished");
}

/// Redact a secret spec for error messages. Shows `ENV_VAR=<redacted>:hosts`.
fn redact_secret_spec(spec: &str) -> String {
    let Some((name, rest)) = spec.split_once('=') else {
        return "<malformed>".into();
    };
    rest.rsplit_once(':').map_or_else(
        || format!("{name}=<redacted>"),
        |(_, hosts)| format!("{name}=<redacted>:{hosts}"),
    )
}

/// Parse secret spec: `ENV_VAR=real_value:host1,host2`
///
/// The last `:` separates value from hosts (values may contain colons).
pub(crate) fn parse_secret(spec: &str) -> Result<(String, SecretBinding), String> {
    let (name_value, hosts) = spec
        .rsplit_once(':')
        .ok_or("expected ENV_VAR=value:hosts")?;
    let (env_name, value_ref) = name_value.split_once('=').ok_or("expected ENV_VAR=value")?;

    if env_name.is_empty() || value_ref.is_empty() || hosts.is_empty() {
        return Err("empty env name, value, or hosts".into());
    }

    if env_name.len() > 256 {
        return Err("env name too long (max 256 bytes)".into());
    }

    let real_value = redan::provider::resolve_secret_value(value_ref)
        .map_err(|e| format!("failed to resolve secret: {e}"))?;

    let allowed_hosts: Vec<String> = hosts
        .split(',')
        .map(|host| host.trim().to_string())
        .collect();
    let binding =
        SecretBinding::new(env_name, real_value, allowed_hosts).map_err(|e| e.to_string())?;

    Ok((env_name.to_string(), binding))
}

/// Read secret specs from a file. One spec per line, `#` comments, blank lines skipped.
pub(crate) fn read_secret_file(path: &str) -> Result<Vec<String>, String> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat {path}: {e}"))?;

    if !meta.is_file() {
        return Err(format!("{path}: not a regular file"));
    }
    if meta.len() > 1_048_576 {
        return Err(format!("{path}: too large (max 1MB)"));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            eprintln!(
                "warning: {path} is accessible by other users (mode {:o}). Consider chmod 600.",
                mode & 0o777
            );
        }
    }

    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("cannot read {path}: {e}"))?;

    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect())
}

/// Merge `--secret` and `--secret-file` into a single list.
pub(crate) fn collect_secret_specs(
    cli_secrets: &[String],
    secret_file: Option<&str>,
) -> Vec<String> {
    let mut specs: Vec<String> = cli_secrets.to_vec();
    if let Some(path) = secret_file {
        match read_secret_file(path) {
            Ok(file_specs) => specs.extend(file_specs),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
    specs
}

/// Parse mount spec: `/host/path:/guest/path` or `/host/path` (defaults to `/workspace`)
pub(crate) fn parse_mount(spec: &str) -> (String, String) {
    spec.split_once(':').map_or_else(
        || (spec.to_string(), "/workspace".to_string()),
        |(host, guest)| (host.to_string(), guest.to_string()),
    )
}

fn write_guest_policy(rootfs: &Path, allowed_hosts: Option<&Vec<String>>) {
    let dir = rootfs.join("etc/redan");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let _ = std::fs::write(dir.join("policy"), templates::guest_policy(allowed_hosts));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_secret_basic() {
        let (name, binding) = parse_secret("TOKEN=secret123:api.github.com").unwrap();
        assert_eq!(name, "TOKEN");
        assert_eq!(binding.real_value(), "secret123");
        assert_eq!(binding.allowed_hosts(), &["api.github.com"]);
        assert!(binding.placeholder().starts_with("redan_ph_token_"));
    }

    #[test]
    fn parse_secret_value_with_colons() {
        let (name, binding) =
            parse_secret("DB_URL=postgres://user:pass@host:5432:db.example.com").unwrap();
        assert_eq!(name, "DB_URL");
        assert_eq!(binding.real_value(), "postgres://user:pass@host:5432");
        assert_eq!(binding.allowed_hosts(), &["db.example.com"]);
    }

    #[test]
    fn parse_secret_multiple_hosts() {
        let (_, binding) = parse_secret("KEY=val:api.github.com, registry.npmjs.org").unwrap();
        assert_eq!(
            binding.allowed_hosts(),
            &["api.github.com", "registry.npmjs.org"]
        );
    }

    #[test]
    fn parse_secret_empty_name_fails() {
        assert!(parse_secret("=value:host.com").is_err());
    }

    #[test]
    fn parse_secret_empty_value_fails() {
        assert!(parse_secret("KEY=:host.com").is_err());
    }

    #[test]
    fn parse_secret_empty_hosts_fails() {
        assert!(parse_secret("KEY=value:").is_err());
    }

    #[test]
    fn parse_secret_no_colon_fails() {
        assert!(parse_secret("KEY=value").is_err());
    }

    #[test]
    fn parse_secret_crlf_in_value_rejected() {
        assert!(parse_secret("KEY=val\r\nue:host.com").is_err());
        assert!(parse_secret("KEY=val\nue:host.com").is_err());
        assert!(parse_secret("KEY=val\rue:host.com").is_err());
    }

    #[test]
    #[ignore = "requires running Vault"]
    fn parse_secret_vault_scheme() {
        let (name, binding) =
            parse_secret("TOKEN=vault://redan/test#github_token:api.github.com").unwrap();
        assert_eq!(name, "TOKEN");
        assert_eq!(binding.real_value(), "ghp_test123");
        assert_eq!(binding.allowed_hosts(), &["api.github.com"]);
    }

    #[test]
    fn parse_mount_with_guest_path() {
        let (host, guest) = parse_mount("/home/chris/project:/workspace");
        assert_eq!(host, "/home/chris/project");
        assert_eq!(guest, "/workspace");
    }

    #[test]
    fn parse_mount_default_guest_path() {
        let (host, guest) = parse_mount("/home/chris/project");
        assert_eq!(host, "/home/chris/project");
        assert_eq!(guest, "/workspace");
    }

    #[test]
    fn read_secret_file_parses_lines() {
        let dir = std::env::temp_dir().join("redan-test-secret-file");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secrets.conf");
        std::fs::write(
            &path,
            "# comment\nTOKEN=abc:api.github.com\n\n  KEY=xyz:host.com  \n# another comment\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let specs = read_secret_file(path.to_str().unwrap()).unwrap();
        assert_eq!(specs, vec!["TOKEN=abc:api.github.com", "KEY=xyz:host.com"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
