use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use redan::ca::MitmCa;
use redan::proxy;
use redan::secret::SecretBinding;
use redan::session;
use redan::templates;
use redan::vm;

pub(crate) fn run(
    rootfs: &str,
    command: &str,
    interactive: bool,
    timeout_secs: u64,
    secret_specs: &[String],
    allow_host_specs: &[String],
    mount_specs: &[String],
    audit_log_path: Option<&str>,
    image_name: Option<&str>,
    guest_env: &BTreeMap<String, String>,
    discover: bool,
) {
    // Create session
    let session_id = session::new_id();
    let mut meta = session::SessionMeta::new(&session_id, image_name, Some(command));
    if let Err(e) = meta.save() {
        log::warn!("cannot save session metadata: {e}");
    }
    log::info!("session {session_id} started");

    // In interactive mode, redirect logs to a file so they don't
    // interleave with the guest TUI.
    if interactive {
        let log_path = session::session_dir(&session_id).join("redan.log");
        eprintln!("session: {session_id} (logs: {})", log_path.display());
        crate::redirect_logs_to_file(&log_path);
    }

    // Use session audit log if no explicit --audit-log
    let session_audit = session::audit_log_path(&session_id);
    let audit_log_path = audit_log_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| session_audit.to_string_lossy().into_owned());
    let audit_log_path = Some(audit_log_path.as_str());

    let ca = MitmCa::generate();
    log::info!("MITM CA generated");

    // Install CA cert in guest rootfs
    if let Err(e) = vm::install_ca_cert(Path::new(rootfs), ca.ca_cert_pem()) {
        eprintln!("failed to install CA cert in rootfs: {e}");
        std::process::exit(1);
    }
    log::info!("CA cert installed in guest trust store");

    // Parse secrets: generate placeholders, collect bindings
    let mut secrets: Vec<SecretBinding> = Vec::new();
    let mut secret_env: Vec<(String, String)> = Vec::new();
    for spec in secret_specs {
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
                // Redact the value -- only show ENV_NAME=<redacted>:hosts
                let redacted = match spec.split_once('=') {
                    Some((name, rest)) => match rest.rfind(':') {
                        Some(i) => format!("{name}=<redacted>:{}", &rest[i + 1..]),
                        None => format!("{name}=<redacted>"),
                    },
                    None => "<malformed>".into(),
                };
                eprintln!("invalid --secret spec '{redacted}': {e}");
                std::process::exit(1);
            }
        }
    }

    // Validate --allow-host values
    for host in allow_host_specs {
        if host == "*" {
            continue;
        }
        if host.contains("://") || host.contains('/') || host.contains(':') {
            eprintln!("error: --allow-host takes a hostname, not a URL or host:port: {host}");
            std::process::exit(1);
        }
    }

    // Default-deny: all outbound HTTPS blocked unless explicitly allowed.
    let allowed_hosts: Option<Vec<String>> = if allow_host_specs.iter().any(|h| h == "*") {
        None
    } else {
        let mut hosts: Vec<String> = allow_host_specs
            .iter()
            .map(|h| h.to_ascii_lowercase())
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
    for (i, spec) in mount_specs.iter().enumerate() {
        let (host_path, guest_path) = parse_mount(spec);
        if !Path::new(&host_path).exists() {
            eprintln!("mount source does not exist: {host_path}");
            std::process::exit(1);
        }
        let tag = format!("fs{i}");
        log::info!("mount: {host_path} -> {guest_path} (tag={tag})");

        let mp = Path::new(rootfs).join(guest_path.trim_start_matches('/'));
        std::fs::create_dir_all(&mp).ok();

        virtiofs_mounts.push((tag.clone(), host_path));
        mount_commands.push(format!("mount -t virtiofs {tag} {guest_path}"));
    }

    // Build guest command: network setup + CA trust + mounts + user command
    let net_setup = vm::net_setup_commands(&proxy::GATEWAY_IP.to_string(), proxy::GUEST_IP);
    let ca_update = vm::ca_update_commands();
    let mount_setup = mount_commands.join("; ");
    let full_command = if mount_setup.is_empty() {
        format!("{net_setup}; {ca_update}; {command}")
    } else {
        format!("{net_setup}; {ca_update}; {mount_setup}; {command}")
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
    write_guest_policy(Path::new(rootfs), &allowed_hosts);

    // Add secret placeholders as env vars
    for (name, placeholder) in &secret_env {
        env.push(format!("{name}={placeholder}"));
    }

    // Add user-defined env vars from config
    for (name, value) in guest_env {
        env.push(format!("{name}={value}"));
    }

    let config = vm::VmConfig {
        rootfs: rootfs.into(),
        vcpus: 1,
        ram_mib: 256,
        command: full_command,
        env,
        virtiofs_mounts,
        interactive,
    };

    // In interactive mode, set the host terminal to raw mode
    let _raw_guard = if interactive {
        Some(RawTerminalGuard::enter())
    } else {
        None
    };

    let vm = vm::Vm::boot(config);

    let discovered = proxy::run(proxy::ProxyConfig {
        host_sock: vm
            .net_sock
            .try_clone()
            .expect("failed to clone VM network socket"),
        ca: std::sync::Arc::new(std::sync::Mutex::new(ca)),
        secrets: &secrets,
        timeout: Duration::from_secs(timeout_secs),
        allowed_hosts,
        audit_log_path,
        discover,
    });

    if discover && !discovered.is_empty() {
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

/// Parse secret spec: `ENV_VAR=real_value:host1,host2`
pub(crate) fn parse_secret(spec: &str) -> Result<(String, SecretBinding), String> {
    let colon_pos = spec.rfind(':').ok_or("expected ENV_VAR=value:hosts")?;
    let (name_value, hosts) = (&spec[..colon_pos], &spec[colon_pos + 1..]);

    let eq_pos = name_value.find('=').ok_or("expected ENV_VAR=value")?;
    let (env_name, value_ref) = (&name_value[..eq_pos], &name_value[eq_pos + 1..]);

    if env_name.is_empty() || value_ref.is_empty() || hosts.is_empty() {
        return Err("empty env name, value, or hosts".into());
    }

    if env_name.len() > 256 {
        return Err("env name too long (max 256 bytes)".into());
    }

    let real_value = redan::provider::resolve_secret_value(value_ref)
        .map_err(|e| format!("failed to resolve secret: {e}"))?;

    let allowed_hosts: Vec<String> = hosts.split(',').map(|h| h.trim().to_string()).collect();
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
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}

/// Merge --secret and --secret-file into a single list.
pub(crate) fn collect_secret_specs(cli_secrets: &[String], secret_file: Option<&str>) -> Vec<String> {
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

/// Parse mount spec: `/host/path:/guest/path` or `/host/path` (defaults to /workspace)
pub(crate) fn parse_mount(spec: &str) -> (String, String) {
    if let Some((host, guest)) = spec.split_once(':') {
        (host.to_string(), guest.to_string())
    } else {
        (spec.to_string(), "/workspace".to_string())
    }
}

fn write_guest_policy(rootfs: &Path, allowed_hosts: &Option<Vec<String>>) {
    let dir = rootfs.join("etc/redan");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let _ = std::fs::write(
        dir.join("policy"),
        templates::guest_policy(allowed_hosts.as_ref()),
    );
}

/// RAII guard: raw terminal mode on creation, restore on drop.
struct RawTerminalGuard {
    original: libc::termios,
}

impl RawTerminalGuard {
    fn enter() -> Self {
        unsafe {
            let mut original: libc::termios = std::mem::zeroed();
            libc::tcgetattr(libc::STDIN_FILENO, &mut original);
            let mut raw = original;
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw);
            Self { original }
        }
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

#[cfg(test)]
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
