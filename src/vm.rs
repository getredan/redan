/// libkrun microVM lifecycle.
///
/// Handles VM creation, configuration, and execution. The VM runs in a
/// forked child process; the caller gets back a unix socket for
/// virtio-net communication.
///
/// Fork, not a thread: libkrun's `krun_start_enter` terminates its
/// process via `libc::_exit` on guest shutdown (`Vmm::stop` in
/// libkrun's vmm crate), bypassing Rust Drop impls AND atexit handlers.
/// Running it in a child confines the `_exit` to that child; the parent
/// reaps the guest exit code with waitpid and cleans up normally. This
/// is the pattern smolvm uses and the libkrun maintainer endorses until
/// the 2.0 API adds a returning entry point.
/// See <https://github.com/libkrun/libkrun/issues/561>
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::ffi;

const GUEST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Like assert!, but logs at error level before panicking.
/// VM thread panics are caught by `catch_unwind` and abort,
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
    /// Host directories to mount via virtio-fs: `(tag, host_path, read_only)`.
    pub virtiofs_mounts: Vec<(String, String, bool)>,
    /// Interactive mode: attach host terminal to guest console.
    /// When true, stdin/stdout/stderr are passed to the VM via
    /// virtio-console so the user gets an interactive shell.
    pub interactive: bool,
}

/// A running VM. Owns the host end of the virtio-net socket and the
/// child process running libkrun.
pub struct Vm {
    /// Host-side unix socket for virtio-net frame I/O.
    pub net_sock: UnixStream,
    /// PID of the forked child running `krun_start_enter`. The child
    /// `_exit`s with the guest's exit code on shutdown.
    child: libc::pid_t,
}

/// Exit code libkrun reserves for VMM-level errors (see libkrun.h).
const EXIT_VMM_ERROR: i32 = 125;

/// Decode a waitpid status into a shell-style exit code:
/// the exit code for normal exits, 128 + signal for signal deaths.
const fn exit_code_from_wait_status(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        EXIT_VMM_ERROR
    }
}

impl Vm {
    /// Boot a VM with the given configuration.
    ///
    /// Forks a child to host libkrun and returns immediately with a `Vm`
    /// handle. Use `net_sock` to communicate via smoltcp; when the guest
    /// exits, the child closes its socket end and the peer sees EOF.
    /// Call `shutdown()` to reap the child and get the guest exit code.
    ///
    /// Must be called before the process spawns any threads: the child
    /// inherits only the calling thread, and a lock held by another
    /// thread at fork time would deadlock the child.
    #[must_use]
    #[allow(clippy::expect_used, clippy::unwrap_used)] // FFI setup; failures are unrecoverable
    pub fn boot(config: VmConfig) -> Self {
        let (host_sock, guest_sock) = UnixStream::pair().expect("socketpair failed");
        let guest_fd = guest_sock.as_raw_fd();

        // SAFETY: fork + prctl + getppid are async-signal-safe; the
        // child does allocate afterwards, which is sound because no
        // other threads exist yet (see doc comment).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

        if pid == 0 {
            // Child: this process belongs to libkrun now.
            unsafe {
                // Die with the parent so VMs are never orphaned.
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                // Close the race where the parent died before prctl.
                if libc::getppid() == 1 {
                    libc::_exit(EXIT_VMM_ERROR);
                }
            }
            // Close the host end so the parent's proxy sees EOF when
            // this child dies, not a silently held-open socket.
            drop(host_sock);

            // Catch panics (krun_check! panics on FFI errors) to avoid
            // unwinding into the parent's inherited stack frames.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Self::run_vm(config, guest_sock, guest_fd)
            }));
            // run_vm only returns if krun_start_enter failed pre-boot;
            // on guest shutdown libkrun _exits this child directly.
            // _exit, not exit: don't flush stdio buffers inherited from
            // the parent or run its atexit handlers.
            let _ = result;
            unsafe { libc::_exit(EXIT_VMM_ERROR) }
        }

        // Parent: close the guest end. virtio-net must be the only
        // holder so EOF propagates when the child exits.
        drop(guest_sock);

        Self {
            net_sock: host_sock,
            child: pid,
        }
    }

    /// Reap the VM child and return the guest exit code.
    ///
    /// If the child is still running (e.g. proxy timeout rather than
    /// guest exit), kill it first. Blocks until the child is reaped.
    pub fn shutdown(&self) -> i32 {
        let mut status: libc::c_int = 0;
        unsafe {
            // Fast path: child already exited (the normal case, the
            // proxy loop breaks on socket EOF after the child dies).
            let reaped = libc::waitpid(self.child, &raw mut status, libc::WNOHANG);
            if reaped == self.child {
                return exit_code_from_wait_status(status);
            }
            // Child still alive: kill it. SIGKILL, not SIGTERM; libkrun
            // has no graceful-shutdown path on Linux and the rootfs is
            // host-managed, so there's nothing to flush guest-side.
            libc::kill(self.child, libc::SIGKILL);
            if libc::waitpid(self.child, &raw mut status, 0) == self.child {
                exit_code_from_wait_status(status)
            } else {
                EXIT_VMM_ERROR
            }
        }
    }

    #[allow(clippy::unwrap_used, clippy::expect_used)] // FFI setup; failures are unrecoverable
    fn run_vm(config: VmConfig, guest_sock: UnixStream, guest_fd: i32) -> i32 {
        // Raise host process fd limit to hard max. libkrun needs fds
        // for KVM vcpus, virtio devices, etc. (Same as smolvm.)
        unsafe {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) == 0 {
                limit.rlim_cur = limit.rlim_max;
                libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit);
            }
        }
        let krun_log_level = match std::env::var("RUST_LOG").as_deref() {
            Ok("trace") => ffi::KRUN_LOG_LEVEL_TRACE,
            Ok("debug") => ffi::KRUN_LOG_LEVEL_DEBUG,
            Ok(s) if s.contains("trace") => ffi::KRUN_LOG_LEVEL_TRACE,
            Ok(s) if s.contains("debug") => ffi::KRUN_LOG_LEVEL_DEBUG,
            _ => ffi::KRUN_LOG_LEVEL_OFF,
        };
        let ret = unsafe {
            ffi::krun_init_log(
                ffi::KRUN_LOG_TARGET_DEFAULT,
                krun_log_level,
                ffi::KRUN_LOG_STYLE_AUTO,
                0,
            )
        };
        krun_check!(ret >= 0, "krun_init_log failed: {ret}");

        let ctx_id = unsafe { ffi::krun_create_ctx() };
        krun_check!(ctx_id >= 0, "krun_create_ctx failed: {ctx_id}");
        #[allow(clippy::cast_sign_loss)] // Checked non-negative above
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
        for (tag, path, read_only) in &config.virtiofs_mounts {
            let c_tag = CString::new(tag.as_str()).unwrap();
            let c_path = CString::new(path.as_str()).unwrap();
            let ret = unsafe {
                ffi::krun_add_virtiofs3(ctx_id, c_tag.as_ptr(), c_path.as_ptr(), 0, *read_only)
            };
            krun_check!(ret >= 0, "krun_add_virtiofs3({tag}, {path}) failed: {ret}");
        }

        // The implicit console uses the host process's stdio.
        // Interactive mode adds raw terminal on the host (caller handles).
        // Non-interactive: console output goes to host stdout as-is.

        // Set guest RLIMIT_NOFILE via libkrun (before init runs).
        // Format per libkrun.h: "RESOURCE=RLIM_CUR:RLIM_MAX"
        // RLIMIT_NOFILE = 7 on Linux (libc::RLIMIT_NOFILE).
        let nofile = CString::new(format!("{}={}:{}", libc::RLIMIT_NOFILE, 65536, 65536)).unwrap();
        let rlimits: Vec<*const c_char> = vec![nofile.as_ptr(), std::ptr::null()];
        let ret = unsafe { ffi::krun_set_rlimits(ctx_id, rlimits.as_ptr()) };
        if ret < 0 {
            log::warn!("krun_set_rlimits returned {ret}");
        }

        // exec: /bin/sh -c "<command>"
        // /bin/sh exists on every distro (ash on Alpine, bash/dash elsewhere).
        // libkrun's init uses exec_path as argv[0] (via KRUN_INIT), so
        // argv here contains only the arguments after argv[0].
        let exec_path = CString::new("/bin/sh").unwrap();
        let flag = CString::new("-c").unwrap();
        let cmd = CString::new(config.command).unwrap();
        let argv: Vec<*const c_char> = vec![flag.as_ptr(), cmd.as_ptr(), std::ptr::null()];

        let env_cstrings: Vec<CString> = config
            .env
            .iter()
            .map(|e| CString::new(e.as_str()).unwrap())
            .collect();
        let mut envp: Vec<*const c_char> = env_cstrings.iter().map(|e| e.as_ptr()).collect();
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
        "ulimit -n 65536 2>/dev/null; \
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
pub const fn ca_update_commands() -> &'static str {
    "update-ca-certificates 2>/dev/null; update-ca-trust 2>/dev/null; true"
}

#[cfg(test)]
mod tests {
    use super::*;

    // Linux wait status encoding: normal exit code N is N << 8,
    // death by signal S is S in the low 7 bits.

    #[test]
    fn exit_code_zero_from_clean_exit() {
        assert_eq!(exit_code_from_wait_status(0), 0);
    }

    #[test]
    fn exit_code_preserved_from_nonzero_exit() {
        assert_eq!(exit_code_from_wait_status(42 << 8), 42);
        assert_eq!(exit_code_from_wait_status(1 << 8), 1);
        assert_eq!(exit_code_from_wait_status(255 << 8), 255);
    }

    #[test]
    fn exit_code_128_plus_signal_when_killed() {
        assert_eq!(exit_code_from_wait_status(libc::SIGKILL), 137);
        assert_eq!(exit_code_from_wait_status(libc::SIGTERM), 143);
        assert_eq!(exit_code_from_wait_status(libc::SIGINT), 130);
    }
}
