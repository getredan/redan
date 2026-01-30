use std::path::Path;
use std::time::Duration;

use clap::Parser;

use redan::ca::MitmCa;
use redan::proxy;
use redan::secret::SecretBinding;
use redan::vm;

#[derive(Parser)]
#[command(name = "redan", about = "Secure execution environment for AI agents")]
enum Cli {
    /// Execute a command inside a microVM
    Exec {
        /// Root filesystem path
        #[arg(long, default_value = "/tmp/redan-rootfs")]
        rootfs: String,

        /// Shell command to run in the guest
        #[arg(long)]
        command: String,

        /// Proxy timeout in seconds
        #[arg(long, default_value = "60")]
        timeout: u64,

        /// Inject a secret: ENV_VAR=real_value:host1,host2
        /// The real value is replaced with a placeholder in the guest.
        /// The proxy injects the real value only for requests to allowed hosts.
        #[arg(long = "secret", value_name = "SPEC")]
        secrets: Vec<String>,
    },
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli {
        Cli::Exec {
            rootfs,
            command,
            timeout,
            secrets,
        } => exec(&rootfs, &command, timeout, &secrets),
    }
}

/// Parse secret spec: `ENV_VAR=real_value:host1,host2`
fn parse_secret(spec: &str) -> Result<(String, SecretBinding), String> {
    // Split on last ':' to separate hosts from value (value may contain ':')
    let colon_pos = spec.rfind(':').ok_or("expected ENV_VAR=value:hosts")?;
    let (name_value, hosts) = (&spec[..colon_pos], &spec[colon_pos + 1..]);

    let eq_pos = name_value.find('=').ok_or("expected ENV_VAR=value")?;
    let (env_name, real_value) = (&name_value[..eq_pos], &name_value[eq_pos + 1..]);

    if env_name.is_empty() || real_value.is_empty() || hosts.is_empty() {
        return Err("empty env name, value, or hosts".into());
    }

    let allowed_hosts: Vec<String> = hosts.split(',').map(|h| h.trim().to_string()).collect();

    // Generate a deterministic-looking placeholder
    let placeholder = format!("redan_ph_{}_{:08x}", env_name.to_lowercase(), {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        env_name.hash(&mut hasher);
        (hasher.finish() & 0xFFFF_FFFF) as u32
    });

    let binding = SecretBinding {
        placeholder: placeholder.clone(),
        real_value: real_value.to_string(),
        allowed_hosts,
    };

    Ok((env_name.to_string(), binding))
}

fn exec(rootfs: &str, command: &str, timeout_secs: u64, secret_specs: &[String]) {
    let ca = MitmCa::generate();
    log::info!("MITM CA generated");

    // Install CA cert in guest rootfs
    vm::install_ca_cert(Path::new(rootfs), ca.ca_cert_pem());
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

    // Build guest command: network setup + user command
    let net_setup = vm::net_setup_commands(&proxy::GATEWAY_IP.to_string(), proxy::GUEST_IP);
    let full_command = format!("{net_setup}; {command}");

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
        virtiofs_mounts: vec![],
    };

    let vm = vm::Vm::boot(config);

    // Run the MITM proxy on the host side.
    // When the proxy returns (timeout or VM socket closes), we're done.
    // The VM thread may still be alive (krun_start_enter blocks indefinitely)
    // but the process exit will clean it up.
    proxy::run(
        vm.net_sock.try_clone().expect("clone net_sock"),
        &ca,
        &secrets,
        Duration::from_secs(timeout_secs),
    );
}
