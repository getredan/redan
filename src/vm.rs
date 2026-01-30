/// libkrun microVM lifecycle.
///
/// Handles VM creation, configuration, and execution. The VM runs in a
/// separate thread; the caller gets back a unix socket for virtio-net
/// communication.
use std::ffi::CString;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread::JoinHandle;

use crate::ffi;

const GUEST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Like assert!, but logs at error level before panicking.
/// VM thread panics are silently swallowed (thread is never joined),
/// so we need the log message to reach stderr.
macro_rules! krun_check {
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            log::error!($($arg)+);
            panic!($($arg)+);
        }
    };
}

/// Configuration for a VM instance.
pub struct VmConfig {
    /// Path to the guest root filesystem.
    pub rootfs: String,
    /// Number of vCPUs.
    pub vcpus: u8,
    /// RAM in MiB.
    pub ram_mib: u32,
    /// Shell command to execute in the guest.
    pub command: String,
    /// Environment variables for the guest process.
    pub env: Vec<String>,
    /// Host directories to mount via virtio-fs: `(tag, host_path)`.
    pub virtiofs_mounts: Vec<(String, String)>,
    /// Interactive mode: attach host terminal to guest console.
    /// When true, stdin/stdout/stderr are passed to the VM via
    /// virtio-console so the user gets an interactive shell.
    pub interactive: bool,
}

/// A running VM. Owns the host end of the virtio-net socket and the VM thread.
pub struct Vm {
    /// Host-side unix socket for virtio-net frame I/O.
    pub net_sock: UnixStream,
    /// VM thread handle. Note: `krun_start_enter` blocks until the VM is
    /// destroyed, which may not happen when the guest process exits.
    /// Joining this thread may block indefinitely.
    _thread: JoinHandle<i32>,
}

impl Vm {
    /// Boot a VM with the given configuration.
    ///
    /// Returns immediately with a `Vm` handle. The VM runs in a background thread.
    /// Use `net_sock` to communicate via smoltcp.
    pub fn boot(config: VmConfig) -> Self {
        let (host_sock, guest_sock) = UnixStream::pair().expect("socketpair failed");
        let guest_fd = guest_sock.as_raw_fd();

        let thread = std::thread::spawn(move || {
            let ret = unsafe {
                ffi::krun_init_log(
                    ffi::KRUN_LOG_TARGET_DEFAULT,
                    ffi::KRUN_LOG_LEVEL_OFF,
                    ffi::KRUN_LOG_STYLE_AUTO,
                    0,
                )
            };
            krun_check!(ret >= 0, "krun_init_log failed: {ret}");

            let ctx_id = unsafe { ffi::krun_create_ctx() };
            krun_check!(ctx_id >= 0, "krun_create_ctx failed: {ctx_id}");
            let ctx_id = ctx_id as u32;

            unsafe {
                let ret = ffi::krun_set_vm_config(ctx_id, config.vcpus, config.ram_mib);
                krun_check!(ret >= 0, "krun_set_vm_config failed: {ret}");

                let root = CString::new(config.rootfs).unwrap();
                let ret = ffi::krun_set_root(ctx_id, root.as_ptr());
                krun_check!(ret >= 0, "krun_set_root failed: {ret}");

                let workdir = CString::new("/").unwrap();
                let ret = ffi::krun_set_workdir(ctx_id, workdir.as_ptr());
                krun_check!(ret >= 0, "krun_set_workdir failed: {ret}");
            }

            // virtio-net
            let ret = unsafe {
                ffi::krun_add_net_unixstream(
                    ctx_id,
                    std::ptr::null(),
                    guest_fd,
                    GUEST_MAC.as_ptr(),
                    0,
                    0,
                )
            };
            krun_check!(ret >= 0, "krun_add_net_unixstream failed: {ret}");

            // virtio-fs mounts
            for (tag, path) in &config.virtiofs_mounts {
                let c_tag = CString::new(tag.as_str()).unwrap();
                let c_path = CString::new(path.as_str()).unwrap();
                let ret =
                    unsafe { ffi::krun_add_virtiofs(ctx_id, c_tag.as_ptr(), c_path.as_ptr()) };
                krun_check!(ret >= 0, "krun_add_virtiofs({tag}, {path}) failed: {ret}");
            }

            // The implicit console uses the host process's stdio.
            // Interactive mode adds raw terminal on the host (caller handles).
            // Non-interactive: console output goes to host stdout as-is.

            // exec: ash -c "<command>"
            let exec_path = CString::new("/bin/busybox").unwrap();
            let arg0 = CString::new("ash").unwrap();
            let arg1 = CString::new("-c").unwrap();
            let arg2 = CString::new(config.command).unwrap();
            let argv: Vec<*const i8> = vec![
                arg0.as_ptr(),
                arg1.as_ptr(),
                arg2.as_ptr(),
                std::ptr::null(),
            ];

            let env_cstrings: Vec<CString> = config
                .env
                .iter()
                .map(|e| CString::new(e.as_str()).unwrap())
                .collect();
            let mut envp: Vec<*const i8> = env_cstrings.iter().map(|e| e.as_ptr()).collect();
            envp.push(std::ptr::null());

            let ret = unsafe {
                ffi::krun_set_exec(ctx_id, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr())
            };
            krun_check!(ret >= 0, "krun_set_exec failed: {ret}");

            // Keep guest_sock alive for the duration of the VM.
            // ManuallyDrop over mem::forget to make intent explicit.
            let _guest_sock = std::mem::ManuallyDrop::new(guest_sock);

            log::info!("entering VM");
            unsafe { ffi::krun_start_enter(ctx_id) }
        });

        Self {
            net_sock: host_sock,
            _thread: thread,
        }
    }
}

/// Build the network setup commands for a guest with static IP config.
pub fn net_setup_commands(gateway_ip: &str, guest_ip: &str) -> String {
    format!(
        "ip link set eth0 up; \
         ip addr add {guest_ip}/24 dev eth0; \
         ip route add default via {gateway_ip}; \
         echo 'nameserver {gateway_ip}' > /etc/resolv.conf"
    )
}

/// Install a CA certificate PEM into a guest rootfs.
///
/// Writes the PEM to `<rootfs>/etc/ssl/certs/redan-ca.pem` and appends it
/// to the CA bundle. Safe to call multiple times (replaces previous cert).
pub fn install_ca_cert(rootfs: &Path, pem: &str) {
    let ssl_dir = rootfs.join("etc/ssl/certs");
    std::fs::create_dir_all(&ssl_dir).ok();

    std::fs::write(ssl_dir.join("redan-ca.pem"), pem).expect("failed to write CA PEM");

    let bundle_path = ssl_dir.join("ca-certificates.crt");
    let bundle = std::fs::read_to_string(&bundle_path).unwrap_or_default();
    let base = bundle.split("# Redan MITM CA").next().unwrap_or(&bundle);
    let new_bundle = format!("{base}# Redan MITM CA\n{pem}\n");
    std::fs::write(bundle_path, new_bundle).expect("failed to write CA bundle");
}
