use std::path::Path;
use std::time::Duration;

use clap::Parser;

use redan::ca::MitmCa;
use redan::image;
use redan::proxy;
use redan::secret::SecretBinding;
use redan::vm;

#[derive(Parser)]
#[command(name = "redan", about = "Secure execution environment for AI agents")]
enum Cli {
    /// Execute a command inside a microVM
    Exec {
        /// Named image to use (from `redan image create`).
        /// Mutually exclusive with --rootfs.
        #[arg(long, conflicts_with = "rootfs")]
        image: Option<String>,

        /// Root filesystem path (for manual rootfs management).
        #[arg(long)]
        rootfs: Option<String>,

        /// Shell command to run in the guest.
        /// If omitted in interactive mode, defaults to /bin/sh.
        #[arg(long)]
        command: Option<String>,

        /// Interactive mode: attach terminal to guest console.
        #[arg(long, short = 'i')]
        interactive: bool,

        /// Proxy timeout in seconds
        #[arg(long, default_value = "60")]
        timeout: u64,

        /// Inject a secret: ENV_VAR=real_value:host1,host2
        /// The real value is replaced with a placeholder in the guest.
        /// The proxy injects the real value only for requests to allowed hosts.
        #[arg(long = "secret", value_name = "SPEC")]
        secrets: Vec<String>,

        /// Mount a host directory into the guest via virtio-fs.
        /// Format: /host/path:/guest/path (default guest path: /workspace)
        #[arg(long = "mount", value_name = "HOST:GUEST")]
        mounts: Vec<String>,
    },

    /// Manage rootfs images
    Image {
        #[command(subcommand)]
        action: ImageAction,
    },
}

#[derive(clap::Subcommand)]
enum ImageAction {
    /// Create a new image from Alpine base
    Create {
        /// Image name
        name: String,

        /// Packages to install via apk (space-separated)
        #[arg(long, value_delimiter = ' ', num_args = 1..)]
        packages: Vec<String>,

        /// Additional commands to run during build
        #[arg(long = "run", value_name = "CMD")]
        run_commands: Vec<String>,
    },

    /// List local images
    List,

    /// Remove an image
    Remove {
        /// Image name
        name: String,
    },
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli {
        Cli::Exec {
            image: image_name,
            rootfs,
            command,
            interactive,
            timeout,
            secrets,
            mounts,
        } => {
            let rootfs_path = match (&image_name, &rootfs) {
                (Some(name), _) => {
                    let p = match image::image_path(name) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    if !p.exists() {
                        eprintln!("image '{name}' not found. Run: redan image create {name} ...");
                        std::process::exit(1);
                    }
                    p.to_string_lossy().into_owned()
                }
                (_, Some(path)) => path.clone(),
                (None, None) => {
                    eprintln!("specify --image <name> or --rootfs <path>");
                    std::process::exit(1);
                }
            };
            let command = command.unwrap_or_else(|| {
                if interactive {
                    "/bin/sh".to_string()
                } else {
                    "echo 'no --command specified'".to_string()
                }
            });
            exec(
                &rootfs_path,
                &command,
                interactive,
                timeout,
                &secrets,
                &mounts,
            );
        }

        Cli::Image { action } => match action {
            ImageAction::Create {
                name,
                packages,
                run_commands,
            } => match image::create(&name, &packages, &run_commands) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("image create failed: {e}");
                    std::process::exit(1);
                }
            },
            ImageAction::List => {
                let images = image::list();
                if images.is_empty() {
                    eprintln!(
                        "no images. Create one with: redan image create <name> --packages 'nodejs npm'"
                    );
                } else {
                    for name in images {
                        let path = image::image_path(&name).expect("listed image has invalid name");
                        let size = dir_size(&path).unwrap_or(0);
                        println!("{name:20} {}", humanize_bytes(size));
                    }
                }
            }
            ImageAction::Remove { name } => match image::remove(&name) {
                Ok(()) => eprintln!("removed image \'{name}\'"),
                Err(e) => {
                    eprintln!("remove failed: {e}");
                    std::process::exit(1);
                }
            },
        },
    }
}

fn dir_size(path: &std::path::Path) -> std::io::Result<u64> {
    let mut total = 0;
    for entry in walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    Ok(total)
}

fn humanize_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    }
}

/// Parse secret spec: `ENV_VAR=real_value:host1,host2`
///
/// The value can be a literal or a provider URI:
/// - `ENV_VAR=ghp_abc123:api.github.com` (literal)
/// - `ENV_VAR=vault://path#field:api.github.com` (Vault KV v2)
fn parse_secret(spec: &str) -> Result<(String, SecretBinding), String> {
    // Split on last ':' to separate hosts from value (value may contain ':')
    let colon_pos = spec.rfind(':').ok_or("expected ENV_VAR=value:hosts")?;
    let (name_value, hosts) = (&spec[..colon_pos], &spec[colon_pos + 1..]);

    let eq_pos = name_value.find('=').ok_or("expected ENV_VAR=value")?;
    let (env_name, value_ref) = (&name_value[..eq_pos], &name_value[eq_pos + 1..]);

    if env_name.is_empty() || value_ref.is_empty() || hosts.is_empty() {
        return Err("empty env name, value, or hosts".into());
    }

    // Cap env name length to prevent oversized placeholders that
    // would slow down inject/scrub scanning.
    if env_name.len() > 256 {
        return Err("env name too long (max 256 bytes)".into());
    }

    // Resolve the value through the provider system
    let real_value = redan::provider::resolve_secret_value(value_ref)
        .map_err(|e| format!("failed to resolve secret: {e}"))?;

    // CWE-93: CRLF in secret values would corrupt HTTP framing when
    // injected into headers. Reject at configuration time.
    if real_value.contains('\r') || real_value.contains('\n') {
        return Err("secret value contains CRLF (would corrupt HTTP headers)".into());
    }

    let allowed_hosts: Vec<String> = hosts.split(',').map(|h| h.trim().to_string()).collect();
    let binding = SecretBinding::new(env_name, real_value, allowed_hosts);

    Ok((env_name.to_string(), binding))
}

/// Parse mount spec: `/host/path:/guest/path` or `/host/path` (defaults to /workspace)
fn parse_mount(spec: &str) -> (String, String) {
    if let Some((host, guest)) = spec.split_once(':') {
        (host.to_string(), guest.to_string())
    } else {
        (spec.to_string(), "/workspace".to_string())
    }
}

fn exec(
    rootfs: &str,
    command: &str,
    interactive: bool,
    timeout_secs: u64,
    secret_specs: &[String],
    mount_specs: &[String],
) {
    let mut ca = MitmCa::generate();
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
                    binding.placeholder,
                    binding.allowed_hosts.join(", ")
                );
                secret_env.push((env_name, binding.placeholder.clone()));
                secrets.push(binding);
            }
            Err(e) => {
                eprintln!("invalid --secret spec '{spec}': {e}");
                std::process::exit(1);
            }
        }
    }

    // Parse mounts
    let mut virtiofs_mounts: Vec<(String, String)> = Vec::new();
    let mut mount_commands: Vec<String> = Vec::new();
    for (i, spec) in mount_specs.iter().enumerate() {
        let (host_path, guest_path) = parse_mount(spec);
        let tag = format!("fs{i}");
        log::info!("mount: {host_path} -> {guest_path} (tag={tag})");

        // Create mount point in the rootfs
        let mp = Path::new(rootfs).join(guest_path.trim_start_matches('/'));
        std::fs::create_dir_all(&mp).ok();

        virtiofs_mounts.push((tag.clone(), host_path));
        mount_commands.push(format!("mount -t virtiofs {tag} {guest_path}"));
    }

    // Build guest command: network setup + mounts + user command
    let net_setup = vm::net_setup_commands(&proxy::GATEWAY_IP.to_string(), proxy::GUEST_IP);
    let mount_setup = mount_commands.join("; ");
    let full_command = if mount_setup.is_empty() {
        format!("{net_setup}; {command}")
    } else {
        format!("{net_setup}; {mount_setup}; {command}")
    };

    let mut env: Vec<String> = vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        "TERM=xterm".into(),
        "SSL_CERT_FILE=/etc/ssl/certs/redan-ca.pem".into(),
        "NODE_EXTRA_CA_CERTS=/etc/ssl/certs/redan-ca.pem".into(),
    ];

    // Add secret placeholders as env vars in the guest
    for (name, placeholder) in &secret_env {
        env.push(format!("{name}={placeholder}"));
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

    // In interactive mode, set the host terminal to raw mode so
    // keypresses are forwarded directly to the guest PTY.
    let _raw_guard = if interactive {
        Some(RawTerminalGuard::enter())
    } else {
        None
    };

    let vm = vm::Vm::boot(config);

    // Run the MITM proxy on the host side.
    // When the proxy returns (timeout or VM socket closes), we're done.
    // The VM thread may still be alive (krun_start_enter blocks indefinitely)
    // but the process exit will clean it up.
    proxy::run(
        vm.net_sock
            .try_clone()
            .expect("failed to clone VM network socket"),
        &mut ca,
        &secrets,
        Duration::from_secs(timeout_secs),
    );
    // _raw_guard drops here, restoring terminal settings.
}

/// RAII guard that puts the terminal into raw mode on creation and
/// restores the original settings on drop.
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
        assert_eq!(*binding.real_value, "secret123");
        assert_eq!(binding.allowed_hosts, vec!["api.github.com"]);
        assert!(binding.placeholder.starts_with("redan_ph_token_"));
    }

    #[test]
    fn parse_secret_value_with_colons() {
        // Colon in value: `KEY=postgres://user:pass@host:5432:db.example.com`
        let (name, binding) =
            parse_secret("DB_URL=postgres://user:pass@host:5432:db.example.com").unwrap();
        assert_eq!(name, "DB_URL");
        assert_eq!(*binding.real_value, "postgres://user:pass@host:5432");
        assert_eq!(binding.allowed_hosts, vec!["db.example.com"]);
    }

    #[test]
    fn parse_secret_multiple_hosts() {
        let (_, binding) = parse_secret("KEY=val:api.github.com, registry.npmjs.org").unwrap();
        assert_eq!(
            binding.allowed_hosts,
            vec!["api.github.com", "registry.npmjs.org"]
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
        // Requires: VAULT_ADDR + VAULT_TOKEN set, redan/test secret seeded
        let (name, binding) =
            parse_secret("TOKEN=vault://redan/test#github_token:api.github.com").unwrap();
        assert_eq!(name, "TOKEN");
        assert_eq!(*binding.real_value, "ghp_test123");
        assert_eq!(binding.allowed_hosts, vec!["api.github.com"]);
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
}
