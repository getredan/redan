use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use redan::ca::MitmCa;
use redan::proxy;
use redan::secret::SecretBinding;
use redan::session;
use redan::templates;
use redan::vm;

#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ExecConfig<'a> {
    pub rootfs: &'a str,
    pub command: &'a str,
    pub interactive: bool,
    pub timeout_secs: u64,
    pub secret_specs: &'a [String],
    pub allow_host_specs: &'a [String],
    pub forward_specs: &'a [String],
    pub mount_specs: &'a [String],
    pub audit_log_path: Option<&'a str>,
    pub image_name: Option<&'a str>,
    pub guest_env: &'a BTreeMap<String, String>,
    pub discover: bool,
    pub session_name: Option<&'a str>,
    /// Pre-existing session ID (for daemon mode). If None, creates a new session.
    pub session_id: Option<&'a str>,
    /// Run the user command as this OS user (via `runuser`).
    pub run_as: Option<&'a str>,
    /// Guest directory to chown to `run_as` user before the user command runs.
    /// Used for staged credentials that the agent needs to write back to.
    pub chown_dir: Option<&'a str>,
    /// Redirect logs to session file (avoids interleaving with guest output).
    /// True whenever stdin is a TTY.
    pub redirect_logs: bool,
    /// Launch headless Chrome with CDP and an allowlist proxy.
    pub browser: bool,
}

/// Run a sandboxed VM session to completion.
/// Returns the guest exit code, which the caller should propagate.
pub(crate) fn run(cfg: &ExecConfig<'_>) -> i32 {
    // Create or reuse session
    let session_id = cfg.session_id.map_or_else(session::new_id, Into::into);
    if cfg.session_id.is_some() && !session::valid_session_id(&session_id) {
        eprintln!("invalid session ID: {session_id}");
        std::process::exit(1);
    }
    let mut meta = if cfg.session_id.is_some() {
        // Daemon mode: reload existing metadata (written by exec_detached)
        let meta_path = session::session_dir(&session_id).join("meta.json");
        let json = std::fs::read_to_string(&meta_path).unwrap_or_else(|e| {
            eprintln!("cannot read session metadata {}: {e}", meta_path.display());
            std::process::exit(1);
        });
        serde_json::from_str(&json).unwrap_or_else(|e| {
            eprintln!("invalid session metadata {}: {e}", meta_path.display());
            std::process::exit(1);
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

    // Redirect logs to a file so they don't interleave with guest output.
    if cfg.redirect_logs {
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
    let mut virtiofs_mounts: Vec<(String, String, bool)> = Vec::new();
    let mut mount_commands: Vec<String> = Vec::new();
    // The mount of the host's current directory becomes the guest working
    // directory, so the agent starts in the project (sees its git repo,
    // relative paths) instead of in `/`.
    let cwd = std::env::current_dir().and_then(std::fs::canonicalize).ok();
    let mut workdir: Option<String> = None;
    for (i, spec) in cfg.mount_specs.iter().enumerate() {
        let (host_path, guest_path, read_only) = parse_mount(spec);
        if let Err(msg) = validate_guest_path(&guest_path) {
            eprintln!("invalid mount '{spec}': {msg}");
            std::process::exit(1);
        }
        if !Path::new(&host_path).exists() {
            eprintln!("mount source does not exist: {host_path}");
            std::process::exit(1);
        }
        if workdir.is_none()
            && let Some(cwd) = &cwd
            && std::fs::canonicalize(&host_path).is_ok_and(|p| &p == cwd)
        {
            workdir = Some(guest_path.clone());
        }
        let tag = format!("fs{i}");
        let ro_label = if read_only { " (ro)" } else { "" };
        log::info!("mount: {host_path} -> {guest_path}{ro_label} (tag={tag})");

        // guest_path is validated above (absolute, no `..`), so this join
        // stays within the rootfs.
        let mp = Path::new(cfg.rootfs).join(guest_path.trim_start_matches('/'));
        std::fs::create_dir_all(&mp).ok();

        virtiofs_mounts.push((tag.clone(), host_path, read_only));
        let mount_opts = if read_only { " -o ro" } else { "" };
        mount_commands.push(format!("mount -t virtiofs{mount_opts} {tag} {guest_path}"));
    }

    // Validate run_as username before interpolating into shell commands
    if let Some(user) = cfg.run_as
        && let Err(msg) = validate_username(user)
    {
        eprintln!("invalid --run-as username: {msg}");
        std::process::exit(1);
    }

    // Build guest command: network setup + CA trust + mounts + user command
    let net_setup = vm::net_setup_commands(&proxy::GATEWAY_IP.to_string(), proxy::GUEST_IP);
    let ca_update = vm::ca_update_commands();
    let mount_setup = mount_commands.join("; ");
    let ensure_user = cfg.run_as.map(ensure_user_command);
    // `cd` runs in the boot shell after the virtio-fs mount, so the cwd
    // resolves to the mounted directory (not the empty pre-mount inode);
    // `runuser` then inherits it. Keeps the no-extra-`sh -c` TTY passthrough.
    let user_command = with_workdir(wrap_run_as(cfg.command, cfg.run_as), workdir.as_deref());

    let mut parts = vec![net_setup, ca_update.to_string()];
    if !mount_setup.is_empty() {
        parts.push(mount_setup);
    }
    if let Some(cmd) = ensure_user {
        parts.push(cmd);
    }
    if let (Some(_), Some(dir)) = (cfg.run_as, cfg.chown_dir) {
        // chown doesn't work through virtiofs (host user != VM root), so
        // open permissions instead. Single-user VM, so this is safe.
        // Use find instead of glob: shell `*` skips dotfiles like .credentials.json.
        parts.push(format!(
            "chmod 777 {dir} && find {dir} -maxdepth 1 -type f -exec chmod 666 {{}} +; true"
        ));
    }
    parts.push(user_command);
    let full_command = parts.join("; ");

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

    if cfg.browser {
        env.push("REDAN_BROWSER=1".into());
        env.push(format!("REDAN_BROWSER_HOST={}", proxy::GATEWAY_IP));
        env.push(format!(
            "REDAN_BROWSER_CDP_PORT={}",
            redan::browser::CDP_PORT
        ));
    }

    let vm_config = vm::VmConfig {
        rootfs: cfg.rootfs.into(),
        vcpus: 4,
        ram_mib: 4096,
        command: full_command,
        env,
        virtiofs_mounts,
        interactive: cfg.interactive,
    };

    // libkrun handles raw terminal mode inside krun_start_enter via its
    // implicit console setup (setup_terminal_raw_mode). Calling cfmakeraw
    // here before libkrun breaks console output due to interaction between
    // the pre-existing raw mode and libkrun's make_non_blocking on dup'd fds.
    // Save the state so the parent can restore it after reaping the VM
    // child; libkrun raw-modes the TTY whenever stdin is one, not just
    // in interactive mode.
    redan::terminal::save_terminal();

    let vm_handle = vm::Vm::boot(vm_config);

    // Ignore SIGINT in the parent. Ctrl-C must reach the guest, not kill
    // redan: the terminal delivers SIGINT to the whole foreground process
    // group, and the VM child (libkrun) forwards it to the guest console.
    // The guest agent handles it (or its shell exits), the VM child dies,
    // and the parent cleans up through the normal reap path.
    // SAFETY: SIG_IGN disposition change, no handler code involved.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }

    let net_sock = match vm_handle.net_sock.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to clone VM network socket: {e}");
            std::process::exit(1);
        }
    };

    let mut forwards: Vec<proxy::ForwardSpec> = Vec::new();
    for spec in cfg.forward_specs {
        match proxy::parse_forward_spec(spec) {
            Ok(fwd) => {
                if forwards.iter().any(|f| f.guest_port == fwd.guest_port) {
                    eprintln!("duplicate forward guest port: {}", fwd.guest_port);
                    std::process::exit(1);
                }
                log::info!(
                    "forward: :{} -> 127.0.0.1:{}",
                    fwd.guest_port,
                    fwd.host_port
                );
                forwards.push(fwd);
            }
            Err(e) => {
                eprintln!("invalid --forward spec '{spec}': {e}");
                std::process::exit(1);
            }
        }
    }

    // Launch headless Chrome if requested. Held until proxy::run returns.
    let _browser = if cfg.browser {
        match redan::browser::Browser::launch(redan::browser::BrowserConfig {
            allowed_hosts: allowed_hosts.clone(),
        }) {
            Ok(b) => {
                // Chrome shares the agent's allowlist. Make the scope explicit
                // so an agent that can't reach a site reads it as policy, not breakage.
                match &allowed_hosts {
                    Some(h) if h.is_empty() => log::info!(
                        "browser: Chrome egress blocked (default-deny); pass --allow-host to let Chrome reach sites"
                    ),
                    Some(h) => log::info!("browser: Chrome egress limited to {}", h.join(", ")),
                    None => log::info!("browser: Chrome egress unrestricted (--allow-host '*')"),
                }

                // Add CDP forward so the guest can reach Chrome
                let cdp_fwd = proxy::ForwardSpec {
                    guest_port: redan::browser::CDP_PORT,
                    host_port: redan::browser::CDP_PORT,
                };
                match forwards.iter().find(|f| f.guest_port == cdp_fwd.guest_port) {
                    Some(existing) if existing.host_port != cdp_fwd.host_port => {
                        eprintln!(
                            "error: --browser reserves guest port {} for Chrome CDP, \
                             but it is already forwarded to host port {}",
                            cdp_fwd.guest_port, existing.host_port
                        );
                        std::process::exit(1);
                    }
                    Some(_) => {}
                    None => {
                        log::info!(
                            "forward: :{} -> 127.0.0.1:{} (CDP)",
                            cdp_fwd.guest_port,
                            cdp_fwd.host_port
                        );
                        forwards.push(cdp_fwd);
                    }
                }
                Some(b)
            }
            Err(e) => {
                eprintln!("error: failed to launch browser: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let discovered = proxy::run(proxy::ProxyConfig {
        host_sock: net_sock,
        ca: std::sync::Arc::new(std::sync::Mutex::new(ca)),
        secrets: &secrets,
        timeout: Duration::from_secs(cfg.timeout_secs),
        allowed_hosts,
        audit_log_path,
        discover: cfg.discover,
        forwards: &forwards,
    });

    // Reap the VM child (kills it first if the proxy hit its timeout
    // while the guest was still running) and restore the terminal.
    // libkrun restores it on clean guest shutdown, but not when killed.
    let guest_code = vm_handle.shutdown();
    redan::terminal::restore_saved_terminal();

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

    meta.finish(guest_code == 0);
    log::info!("session {session_id} finished (guest exit code {guest_code})");
    guest_code
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

/// Parse a mount spec: `host[:guest[:ro]]`.
/// Returns `(host_path, guest_path, read_only)`.
pub(crate) fn parse_mount(spec: &str) -> (String, String, bool) {
    let (base, read_only) = spec
        .strip_suffix(":ro")
        .map_or((spec, false), |s| (s, true));

    match base.split_once(':') {
        Some((host, guest)) if !guest.is_empty() => {
            (host.to_string(), guest.to_string(), read_only)
        }
        _ => (base.to_string(), "/workspace".to_string(), read_only),
    }
}

fn validate_username(user: &str) -> Result<(), String> {
    if user.is_empty() {
        return Err("username must not be empty".into());
    }
    if user.len() > 32 {
        return Err(format!("username too long ({} chars, max 32)", user.len()));
    }
    if !user
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!("username contains invalid characters: {user:?}"));
    }
    Ok(())
}

/// Validate a guest mount target before it is used.
///
/// The guest path is interpolated into the guest's root boot shell
/// (`mount -t virtiofs <tag> <guest_path>`, `cd <workdir>`) and joined onto
/// the host rootfs to create the mountpoint. Requiring an absolute path over a
/// shell-safe character set with no `..` segments keeps the value out of
/// shell-injection range and stops the mountpoint `create_dir_all` from
/// escaping the rootfs via `..`.
fn validate_guest_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("guest mount path must not be empty".into());
    }
    if !path.starts_with('/') {
        return Err(format!("guest mount path must be absolute: {path:?}"));
    }
    if path.len() > 256 {
        return Err(format!(
            "guest mount path too long ({} chars, max 256)",
            path.len()
        ));
    }
    if !path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    {
        return Err(format!(
            "guest mount path has invalid characters: {path:?} (allowed: letters, digits, / . _ -)"
        ));
    }
    if path.split('/').any(|segment| segment == "..") {
        return Err(format!("guest mount path must not contain '..': {path:?}"));
    }
    Ok(())
}

/// Shell command that creates the target user if it doesn't exist.
/// Runs as root in the init script, before `runuser` drops privileges.
/// Tries useradd (shadow-utils), Debian adduser, then Alpine/BusyBox
/// adduser. Stderr suppressed so failed attempts don't spew into the
/// terminal.
fn ensure_user_command(user: &str) -> String {
    format!(
        "id -u {user} >/dev/null 2>&1 || \
         useradd -m -s /bin/sh {user} 2>/dev/null || \
         adduser --disabled-password --gecos '' {user} 2>/dev/null || \
         adduser -D -h /home/{user} {user} 2>/dev/null"
    )
}

/// Wrap a command with `runuser -u {user} -- {command}` when `run_as` is set.
/// Network, CA, and mount setup run as root; only the user command drops privileges.
/// Uses `--` to separate runuser flags from the command; no extra sh -c layer
/// so the guest TTY passes through for interactive agents.
fn wrap_run_as(command: &str, run_as: Option<&str>) -> String {
    let Some(user) = run_as else {
        return command.to_string();
    };
    format!("runuser -u {user} -- {command}")
}

/// Prepend `cd <workdir> &&` so the agent starts in the mounted project
/// directory. No-op when there's no working directory or it's root.
fn with_workdir(command: String, workdir: Option<&str>) -> String {
    match workdir {
        Some(dir) if dir != "/" => format!("cd {dir} && {command}"),
        _ => command,
    }
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
    fn parse_secret_wildcard_host_rejected() {
        // Wildcard secret hosts never inject (injection is exact-match on SNI),
        // so the spec must be rejected rather than silently no-op.
        assert!(parse_secret("KEY=val:*.github.com").is_err());
    }

    #[test]
    fn parse_secret_vault_scheme() {
        let (name, binding) =
            parse_secret("TOKEN=vault://redan/test#github_token:api.github.com").unwrap();
        assert_eq!(name, "TOKEN");
        assert_eq!(binding.real_value(), "ghp_test123");
        assert_eq!(binding.allowed_hosts(), &["api.github.com"]);
    }

    #[test]
    fn parse_mount_with_guest_path() {
        let (host, guest, ro) = parse_mount("/home/chris/project:/workspace");
        assert_eq!(host, "/home/chris/project");
        assert_eq!(guest, "/workspace");
        assert!(!ro);
    }

    #[test]
    fn parse_mount_default_guest_path() {
        let (host, guest, ro) = parse_mount("/home/chris/project");
        assert_eq!(host, "/home/chris/project");
        assert_eq!(guest, "/workspace");
        assert!(!ro);
    }

    #[test]
    fn parse_mount_read_only() {
        let (host, guest, ro) = parse_mount("/home/chris/.claude:/claude-config:ro");
        assert_eq!(host, "/home/chris/.claude");
        assert_eq!(guest, "/claude-config");
        assert!(ro);
    }

    #[test]
    fn parse_mount_read_only_no_guest_path() {
        let (host, guest, ro) = parse_mount("/home/chris/.claude:ro");
        assert_eq!(host, "/home/chris/.claude");
        assert_eq!(guest, "/workspace");
        assert!(ro);
    }

    #[test]
    fn wrap_run_as_none_passthrough() {
        assert_eq!(wrap_run_as("echo hello", None), "echo hello");
    }

    #[test]
    fn wrap_run_as_wraps_with_runuser() {
        let result = wrap_run_as("claude --dangerously-skip-permissions", Some("dev"));
        assert_eq!(
            result,
            "runuser -u dev -- claude --dangerously-skip-permissions"
        );
    }

    #[test]
    fn wrap_run_as_preserves_command_verbatim() {
        let result = wrap_run_as("echo 'hello world'", Some("dev"));
        assert_eq!(result, "runuser -u dev -- echo 'hello world'");
    }

    #[test]
    fn with_workdir_prepends_cd() {
        assert_eq!(
            with_workdir("runuser -u dev -- claude".into(), Some("/workspace")),
            "cd /workspace && runuser -u dev -- claude"
        );
    }

    #[test]
    fn with_workdir_root_is_noop() {
        assert_eq!(with_workdir("claude".into(), Some("/")), "claude");
    }

    #[test]
    fn with_workdir_none_is_noop() {
        assert_eq!(with_workdir("claude".into(), None), "claude");
    }

    #[test]
    fn ensure_user_command_creates_user() {
        let cmd = ensure_user_command("dev");
        assert!(cmd.starts_with("id -u dev"));
        // useradd tried first, then Debian adduser, then Alpine adduser
        assert!(cmd.contains("useradd -m -s /bin/sh dev"));
        assert!(cmd.contains("adduser --disabled-password --gecos '' dev"));
        assert!(cmd.contains("adduser -D -h /home/dev dev"));
    }

    #[test]
    fn validate_username_accepts_valid() {
        assert!(validate_username("dev").is_ok());
        assert!(validate_username("claude-code").is_ok());
        assert!(validate_username("user_123").is_ok());
        assert!(validate_username("a").is_ok());
    }

    #[test]
    fn validate_username_rejects_empty() {
        assert!(validate_username("").is_err());
    }

    #[test]
    fn validate_username_rejects_shell_injection() {
        assert!(validate_username("dev; rm -rf /").is_err());
        assert!(validate_username("$(whoami)").is_err());
        assert!(validate_username("dev\nroot").is_err());
    }

    #[test]
    fn validate_username_rejects_too_long() {
        let long = "a".repeat(33);
        assert!(validate_username(&long).is_err());
    }

    #[test]
    fn validate_guest_path_accepts_normal_mountpoints() {
        assert!(validate_guest_path("/workspace").is_ok());
        assert!(validate_guest_path("/home/dev/.claude").is_ok());
        assert!(validate_guest_path("/a/b-c_d.e2").is_ok());
        assert!(validate_guest_path("/").is_ok());
    }

    #[test]
    fn validate_guest_path_rejects_empty_or_relative() {
        assert!(validate_guest_path("").is_err());
        assert!(validate_guest_path("workspace").is_err());
        assert!(validate_guest_path("./workspace").is_err());
    }

    #[test]
    fn validate_guest_path_rejects_shell_metacharacters() {
        // These flow into the guest's root boot shell; none may pass.
        assert!(validate_guest_path("/work space").is_err());
        assert!(validate_guest_path("/x; rm -rf /").is_err());
        assert!(validate_guest_path("/x$(whoami)").is_err());
        assert!(validate_guest_path("/x`id`").is_err());
        assert!(validate_guest_path("/a|b").is_err());
        assert!(validate_guest_path("/a\nb").is_err());
        assert!(validate_guest_path("/a&b").is_err());
    }

    #[test]
    fn validate_guest_path_rejects_parent_traversal() {
        // Prevents the mountpoint create_dir_all from escaping the rootfs.
        assert!(validate_guest_path("/..").is_err());
        assert!(validate_guest_path("/a/../etc").is_err());
        assert!(validate_guest_path("/../../etc/cron.d").is_err());
    }

    #[test]
    fn validate_guest_path_rejects_too_long() {
        let long = format!("/{}", "a".repeat(256));
        assert!(validate_guest_path(&long).is_err());
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
