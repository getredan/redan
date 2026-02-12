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
/// VM thread panics are caught by catch_unwind and abort,
/// so we need the log message to reach stderr first.
macro_rules! krun_check {
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            let msg = format!($($arg)+);
            log::error!("{msg}");
            panic!("{msg}");
        }
    };
}

/// Configuration for a VM instance.
#[derive(Debug)]
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
    #[must_use]
    pub fn boot(config: VmConfig) -> Self {
        let (host_sock, guest_sock) = UnixStream::pair().expect("socketpair failed");
        let guest_fd = guest_sock.as_raw_fd();

        let thread = std::thread::spawn(move || {
            // Catch panics to prevent unwinding across the FFI boundary
            // into libkrun's C code, which would be undefined behavior.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Self::run_vm(config, guest_sock, guest_fd)
            }));
            match result {
                Ok(code) => code,
                Err(_) => {
                    log::error!("VM thread panicked, aborting to prevent UB");
                    std::process::abort();
                }
            }
        });

        Self {
            net_sock: host_sock,
            _thread: thread,
        }
    }

    fn run_vm(config: VmConfig, guest_sock: UnixStream, guest_fd: i32) -> i32 {
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
            let ret = unsafe { ffi::krun_add_virtiofs(ctx_id, c_tag.as_ptr(), c_path.as_ptr()) };
            krun_check!(ret >= 0, "krun_add_virtiofs({tag}, {path}) failed: {ret}");
        }

        // The implicit console uses the host process's stdio.
        // Interactive mode adds raw terminal on the host (caller handles).
        // Non-interactive: console output goes to host stdout as-is.

        // exec: /bin/sh -c "<command>"
        // /bin/sh exists on every distro (ash on Alpine, bash/dash elsewhere).
        // libkrun's init uses exec_path as argv[0] (via KRUN_INIT), so
        // argv here contains only the arguments after argv[0].
        let exec_path = CString::new("/bin/sh").unwrap();
        let arg1 = CString::new("-c").unwrap();
        let arg2 = CString::new(config.command).unwrap();
        let argv: Vec<*const i8> = vec![arg1.as_ptr(), arg2.as_ptr(), std::ptr::null()];

        let env_cstrings: Vec<CString> = config
            .env
            .iter()
            .map(|e| CString::new(e.as_str()).unwrap())
            .collect();
        let mut envp: Vec<*const i8> = env_cstrings.iter().map(|e| e.as_ptr()).collect();
        envp.push(std::ptr::null());

        let ret =
            unsafe { ffi::krun_set_exec(ctx_id, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        krun_check!(ret >= 0, "krun_set_exec failed: {ret}");

        // Keep guest_sock alive for the duration of the VM.
        // ManuallyDrop over mem::forget to make intent explicit.
        let _guest_sock = std::mem::ManuallyDrop::new(guest_sock);

        log::info!("entering VM");
        unsafe { ffi::krun_start_enter(ctx_id) }
    }
}

/// Build the network setup commands for a guest with static IP config.
pub fn net_setup_commands(gateway_ip: &str, guest_ip: &str) -> String {
    format!(
        "ulimit -n 65536; \
         ip link set eth0 up; \
         ip addr add {guest_ip}/24 dev eth0; \
         ip route add default via {gateway_ip}; \
         echo 'nameserver {gateway_ip}' > /etc/resolv.conf"
    )
}

/// Install a CA certificate PEM into a guest rootfs.
///
/// Drops the PEM into each distro's CA source directory (the place
/// where you're *supposed* to put custom CAs). The actual trust store
/// update (`update-ca-trust`, `update-ca-certificates`) runs inside
/// the VM via `ca_update_commands()`.
///
/// Also writes a standalone copy at `/etc/ssl/certs/redan-ca.pem`
/// for tools that use `SSL_CERT_FILE`.
///
/// Safe to call multiple times (replaces previous cert).
pub fn install_ca_cert(rootfs: &Path, pem: &str) -> std::io::Result<()> {
    // Standalone PEM for SSL_CERT_FILE.
    // Fedora has /etc/ssl/certs as a broken symlink; replace it.
    let ssl_dir = rootfs.join("etc/ssl/certs");
    if ssl_dir.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
        std::fs::remove_file(&ssl_dir)?;
    }
    std::fs::create_dir_all(&ssl_dir)?;
    let pem_path = ssl_dir.join("redan-ca.pem");
    // update-ca-certificates may have replaced our file with an absolute
    // symlink (e.g. -> /usr/local/share/ca-certificates/redan-ca.crt)
    // which is broken from the host. Remove it before writing.
    if pem_path.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
        std::fs::remove_file(&pem_path)?;
    }
    std::fs::write(&pem_path, pem)?;

    // Drop into each distro's CA source directory.
    // The distro's update tool reads from these and regenerates the
    // trust store (bundle files, hash dirs, etc).
    let source_dirs = [
        "usr/local/share/ca-certificates", // Debian, Ubuntu, Alpine
        "etc/pki/ca-trust/source/anchors", // Fedora, RHEL, CentOS
        "usr/share/pki/trust/anchors",     // openSUSE
        "etc/ca-certificates/trust-source/anchors", // Arch
    ];

    for rel in source_dirs {
        let dir = rootfs.join(rel);
        if dir.is_dir() {
            std::fs::write(dir.join("redan-ca.crt"), pem)?;
        }
    }

    Ok(())
}

/// Shell commands to update the CA trust store inside the guest.
/// Tries both Debian-style and Fedora-style; each is a no-op if
/// the tool doesn't exist.
pub fn ca_update_commands() -> &'static str {
    "update-ca-certificates 2>/dev/null; update-ca-trust 2>/dev/null; true"
}
