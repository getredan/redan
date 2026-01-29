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
        } => exec(&rootfs, &command, timeout),
    }
}

fn exec(rootfs: &str, command: &str, timeout_secs: u64) {
    let ca = MitmCa::generate();
    log::info!("MITM CA generated");

    // Install CA cert in guest rootfs
    vm::install_ca_cert(Path::new(rootfs), ca.ca_cert_pem());
    log::info!("CA cert installed in guest trust store");

    // TODO: load secrets from redan.toml
    let secrets: Vec<SecretBinding> = vec![];

    // Build guest command: network setup + user command
    let net_setup = vm::net_setup_commands(&proxy::GATEWAY_IP.to_string(), proxy::GUEST_IP);
    let full_command = format!("{net_setup}; {command}");

    let env = vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        "TERM=xterm".into(),
        "SSL_CERT_FILE=/etc/ssl/certs/redan-ca.pem".into(),
    ];

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
