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
use std::io::Write as _;
use std::os::raw::c_char;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::ffi;
use crate::rootfs::Rootfs;

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
    ///
    /// # Errors
    ///
    /// Returns the OS error if the socketpair for virtio-net cannot be
    /// created or if `fork` fails. Failures inside the forked child never
    /// reach the caller: they make the child exit with the VMM error code,
    /// which `shutdown()` reports.
    pub fn boot(config: &VmConfig) -> std::io::Result<Self> {
        let (host_sock, guest_sock) = UnixStream::pair()?;
        let guest_fd = guest_sock.as_raw_fd();

        // SAFETY: getpid takes no arguments and has no preconditions.
        let parent_pid = unsafe { libc::getpid() };

        // SAFETY: fork takes no arguments. In a multi-threaded process the
        // child may only call async-signal-safe functions, and this child
        // allocates, so it relies on the doc comment's contract that no
        // other threads exist when `boot` is called. That contract is on
        // the callers and is not checked here.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error());
        }

        if pid == 0 {
            // Child: this process belongs to libkrun now.
            // Die with the parent so VMs are never orphaned.
            // SAFETY: PR_SET_PDEATHSIG takes a signal number as its only
            // argument, no pointers, and SIGKILL is a valid signal.
            let armed = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == 0;
            // Close the race where the parent died before prctl. A reparented
            // child has a different parent pid, whether the new parent is
            // init, a subreaper, or the init of a pid namespace.
            // SAFETY: getppid takes no arguments and has no preconditions.
            if !armed || unsafe { libc::getppid() } != parent_pid {
                // SAFETY: _exit has no preconditions. Skipping destructors
                // and atexit handlers is intended in the forked child.
                unsafe { libc::_exit(EXIT_VMM_ERROR) };
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
            // SAFETY: _exit has no preconditions. Skipping destructors
            // and atexit handlers is intended in the forked child.
            unsafe { libc::_exit(EXIT_VMM_ERROR) }
        }

        // Parent: close the guest end. virtio-net must be the only
        // holder so EOF propagates when the child exits.
        drop(guest_sock);

        Ok(Self {
            net_sock: host_sock,
            child: pid,
        })
    }

    /// Reap the VM child and return the guest exit code.
    ///
    /// If the child is still running (e.g. proxy timeout rather than
    /// guest exit), kill it first. Blocks until the child is reaped.
    #[must_use]
    pub fn shutdown(&self) -> i32 {
        let mut status: libc::c_int = 0;
        // Fast path: child already exited (the normal case, the
        // proxy loop breaks on socket EOF after the child dies).
        // SAFETY: `status` is a live, aligned, writable `c_int` for the
        // duration of the call, and WNOHANG is a valid option. `self.child`
        // is the pid `fork` returned in `boot`.
        let reaped = unsafe { libc::waitpid(self.child, &raw mut status, libc::WNOHANG) };
        if reaped == self.child {
            return exit_code_from_wait_status(status);
        }
        // An error here (ECHILD) means the child was already reaped or is
        // not ours, so its pid may belong to an unrelated process by now.
        if reaped < 0 {
            log::error!(
                "waitpid({}) failed: {}",
                self.child,
                std::io::Error::last_os_error()
            );
            return EXIT_VMM_ERROR;
        }
        // Child still alive: kill it. SIGKILL, not SIGTERM; libkrun
        // has no graceful-shutdown path on Linux and the rootfs is
        // host-managed, so there's nothing to flush guest-side.
        // SAFETY: kill takes no pointers and SIGKILL is a valid signal.
        // `self.child` is positive (`boot` only builds a `Vm` in the
        // parent, where fork returned the child's pid) and the waitpid
        // above returned 0, so the pid is our unreaped child and cannot
        // have been reused.
        unsafe { libc::kill(self.child, libc::SIGKILL) };
        // SAFETY: same `status` and `self.child` as the first waitpid.
        // Option 0 blocks until the child terminates.
        if unsafe { libc::waitpid(self.child, &raw mut status, 0) } == self.child {
            exit_code_from_wait_status(status)
        } else {
            EXIT_VMM_ERROR
        }
    }

    fn run_vm(config: &VmConfig, guest_sock: UnixStream, guest_fd: i32) -> i32 {
        // Raise host process fd limit to hard max. libkrun needs fds
        // for KVM vcpus, virtio devices, etc. (Same as smolvm.)
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a live, aligned, writable `rlimit` for the
        // duration of the call, and RLIMIT_NOFILE is a valid resource.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } == 0 {
            limit.rlim_cur = limit.rlim_max;
            // SAFETY: `limit` is a live, initialized `rlimit` that is only
            // read, and RLIMIT_NOFILE is a valid resource.
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) };
        }
        let krun_log_level = match std::env::var("RUST_LOG").as_deref() {
            Ok("trace") => ffi::KRUN_LOG_LEVEL_TRACE,
            Ok("debug") => ffi::KRUN_LOG_LEVEL_DEBUG,
            Ok(s) if s.contains("trace") => ffi::KRUN_LOG_LEVEL_TRACE,
            Ok(s) if s.contains("debug") => ffi::KRUN_LOG_LEVEL_DEBUG,
            _ => ffi::KRUN_LOG_LEVEL_OFF,
        };
        // SAFETY: krun_init_log takes no pointers. -1 is
        // KRUN_LOG_TARGET_DEFAULT (stderr), the level is one of the
        // KRUN_LOG_LEVEL_* constants, the style is KRUN_LOG_STYLE_AUTO and
        // 0 is the documented default for the options bitmask.
        let ret = unsafe {
            ffi::krun_init_log(
                ffi::KRUN_LOG_TARGET_DEFAULT,
                krun_log_level,
                ffi::KRUN_LOG_STYLE_AUTO,
                0,
            )
        };
        krun_check!(ret >= 0, "krun_init_log failed: {ret}");

        // SAFETY: krun_create_ctx takes no arguments.
        let ctx_id = unsafe { ffi::krun_create_ctx() };
        let Ok(ctx_id) = u32::try_from(ctx_id) else {
            log::error!("krun_create_ctx failed: {ctx_id}");
            return EXIT_VMM_ERROR;
        };

        let Some(root) = to_cstring("rootfs path", &config.rootfs) else {
            return EXIT_VMM_ERROR;
        };

        // SAFETY: `ctx_id` came from krun_create_ctx and krun_start_enter
        // has not been called, so the context is still configurable. The
        // other arguments are plain integers.
        let ret = unsafe { ffi::krun_set_vm_config(ctx_id, config.vcpus, config.ram_mib) };
        krun_check!(ret >= 0, "krun_set_vm_config failed: {ret}");

        // SAFETY: `ctx_id` is as above. `root` is a NUL-terminated C
        // string owned by this frame, so it is valid for the call and
        // stays alive until run_vm returns.
        let ret = unsafe { ffi::krun_set_root(ctx_id, root.as_ptr()) };
        krun_check!(ret >= 0, "krun_set_root failed: {ret}");

        // SAFETY: `ctx_id` is as above. The C string literal is
        // NUL-terminated and 'static.
        let ret = unsafe { ffi::krun_set_workdir(ctx_id, c"/".as_ptr()) };
        krun_check!(ret >= 0, "krun_set_workdir failed: {ret}");

        // virtio-net
        // SAFETY: `ctx_id` is as above. libkrun.h requires exactly one of
        // `c_path` and `fd` to be set: `c_path` is null and `fd` is
        // `guest_fd`, the raw fd of `guest_sock`, which is open here and
        // kept alive past krun_start_enter below. `GUEST_MAC` is a const
        // array of the 6 bytes the MAC argument points to. The header types
        // the pointee as mutable but documents no write to it, so this
        // relies on libkrun only reading the MAC.
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
            let Some(c_tag) = to_cstring("virtiofs tag", tag) else {
                return EXIT_VMM_ERROR;
            };
            let Some(c_path) = to_cstring("virtiofs path", path) else {
                return EXIT_VMM_ERROR;
            };
            // SAFETY: `ctx_id` is as above. `c_tag` and `c_path` are
            // NUL-terminated C strings that live until the end of this
            // iteration, past the call. The remaining arguments are plain
            // integers and a bool.
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
        let Some(nofile) = to_cstring(
            "rlimit entry",
            &format!("{}={}:{}", libc::RLIMIT_NOFILE, 65536, 65536),
        ) else {
            return EXIT_VMM_ERROR;
        };
        let rlimits: Vec<*const c_char> = vec![nofile.as_ptr(), std::ptr::null()];
        // SAFETY: `ctx_id` is as above. `rlimits` is a null-terminated
        // array of pointers, and its only non-null entry points into
        // `nofile`, a NUL-terminated C string. Both live past the call.
        let ret = unsafe { ffi::krun_set_rlimits(ctx_id, rlimits.as_ptr()) };
        if ret < 0 {
            log::warn!("krun_set_rlimits returned {ret}");
        }

        // exec: /bin/sh -c "<command>"
        // /bin/sh exists on every distro (ash on Alpine, bash/dash elsewhere).
        // libkrun's init uses exec_path as argv[0] (via KRUN_INIT), so
        // argv here contains only the arguments after argv[0].
        let exec_path = c"/bin/sh";
        let Some(cmd) = to_cstring("command", &config.command) else {
            return EXIT_VMM_ERROR;
        };
        let argv: Vec<*const c_char> = vec![c"-c".as_ptr(), cmd.as_ptr(), std::ptr::null()];

        // Env entries can carry secrets, so only the label is logged.
        let Some(env_cstrings) = config
            .env
            .iter()
            .map(|e| to_cstring("environment entry", e))
            .collect::<Option<Vec<CString>>>()
        else {
            return EXIT_VMM_ERROR;
        };
        let mut envp: Vec<*const c_char> = env_cstrings.iter().map(|e| e.as_ptr()).collect();
        envp.push(std::ptr::null());

        // SAFETY: `ctx_id` is as above. `exec_path` is a NUL-terminated
        // 'static C string. `argv` and `envp` are null-terminated arrays
        // of pointers to NUL-terminated C strings (`c"-c"`, `cmd`,
        // `env_cstrings`) that all live past the call. `envp` is never
        // null, so libkrun does not fall back to the host environment.
        let ret =
            unsafe { ffi::krun_set_exec(ctx_id, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        krun_check!(ret >= 0, "krun_set_exec failed: {ret}");

        // Keep guest_sock alive for the duration of the VM.
        // ManuallyDrop over mem::forget to make intent explicit.
        let _guest_sock = std::mem::ManuallyDrop::new(guest_sock);

        log::info!("entering VM");
        // SAFETY: `ctx_id` is as above and is consumed by this call, which
        // is its only use after configuration. This runs in the forked
        // child, which libkrun may take over and `_exit` (see the module
        // doc comment). It only returns if the configuration was rejected.
        unsafe { ffi::krun_start_enter(ctx_id) }
    }
}

/// Convert `value` to a C string for libkrun. Returns `None` after logging
/// an error if it contains a NUL byte. Only `what` and the position are
/// logged, since values can carry secrets.
fn to_cstring(what: &str, value: &str) -> Option<CString> {
    CString::new(value)
        .map_err(|e| log::error!("{what} contains a NUL byte at offset {}", e.nul_position()))
        .ok()
}

/// Build the network setup commands for a guest with static IP config.
#[must_use]
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
/// Paths resolve the way the guest sees them (see [`Rootfs`]), so an
/// absolute link in the image, like Fedora's `/etc/ssl/certs`, points into
/// the rootfs, and a link the guest planted can't point out of it.
///
/// Safe to call multiple times (replaces previous cert).
///
/// # Errors
///
/// Returns the I/O error if the rootfs can't be opened, if `etc/ssl/certs`
/// can't be created, or if the PEM can't be written to the standalone path
/// or to any of the distro CA source directories that exist.
pub fn install_ca_cert(rootfs: &Path, pem: &str) -> std::io::Result<()> {
    let root = Rootfs::open(rootfs)?;

    // Standalone PEM for SSL_CERT_FILE.
    root.create_dir_all(Path::new("etc/ssl/certs"))?;
    root.create(Path::new("etc/ssl/certs/redan-ca.pem"))?
        .write_all(pem.as_bytes())?;

    // Drop into each distro's CA source directory.
    // The distro's update tool reads from these and regenerates the
    // trust store (bundle files, hash dirs, etc).
    let source_dirs = [
        "usr/local/share/ca-certificates", // Debian, Ubuntu, Alpine
        "etc/pki/ca-trust/source/anchors", // Fedora, RHEL, CentOS
        "usr/share/pki/trust/anchors",     // openSUSE
        "etc/ca-certificates/trust-source/anchors", // Arch
    ];

    for dir in source_dirs.map(Path::new) {
        if root.is_dir(dir) {
            root.create(&dir.join("redan-ca.crt"))?
                .write_all(pem.as_bytes())?;
        }
    }

    Ok(())
}

/// Shell commands to update the CA trust store inside the guest.
/// Tries both Debian-style and Fedora-style; each is a no-op if
/// the tool doesn't exist.
#[must_use]
pub const fn ca_update_commands() -> &'static str {
    "update-ca-certificates 2>/dev/null; update-ca-trust 2>/dev/null; true"
}

#[cfg(test)]
mod tests {
    use super::*;

    // Linux wait status encoding: normal exit code N is N << 8,
    // death by signal S is S in the low 7 bits.

    #[test]
    fn shutdown_returns_vmm_error_without_signalling_a_pid_that_is_not_our_child() {
        // waitpid on a pid that is not our child fails with ECHILD, so the
        // pid may belong to an unrelated process and must not be killed.
        let (net_sock, _peer) = UnixStream::pair().unwrap();
        let vm = Vm {
            net_sock,
            child: i32::MAX,
        };
        assert_eq!(vm.shutdown(), EXIT_VMM_ERROR);
    }

    #[test]
    fn to_cstring_rejects_interior_nul() {
        assert!(to_cstring("test value", "ab\0cd").is_none());
    }

    #[test]
    fn to_cstring_keeps_bytes_without_nul() {
        let c = to_cstring("test value", "KEY=value").unwrap();
        assert_eq!(c.to_bytes(), b"KEY=value");
    }

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

    /// The guest can replace anything in its rootfs with a symlink, and the
    /// host installs the CA into that rootfs before the next boot. A link
    /// that points out of the rootfs, absolute or relative, must not carry
    /// that write to your files.
    #[test]
    fn install_ca_cert_never_writes_outside_the_rootfs() {
        let host = tempfile::tempdir().unwrap();
        let victim = host.path().join("victim");
        let host_name = host.path().file_name().unwrap();
        for (link, target) in [
            ("etc/ssl", host.path().to_path_buf()),
            ("etc/ssl", Path::new("../..").join(host_name)),
            ("usr/local/share/ca-certificates", host.path().to_path_buf()),
            (
                "usr/local/share/ca-certificates/redan-ca.crt",
                victim.clone(),
            ),
            ("etc/ssl/certs/redan-ca.pem", victim.clone()),
        ] {
            std::fs::write(&victim, "yours").unwrap();
            let rootfs = tempfile::tempdir().unwrap();
            let link = rootfs.path().join(link);
            std::fs::create_dir_all(link.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();

            let _ = install_ca_cert(rootfs.path(), "PEM");

            let left: Vec<_> = std::fs::read_dir(host.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert_eq!(left, ["victim"], "{link:?} -> {target:?}");
            assert_eq!(std::fs::read_to_string(&victim).unwrap(), "yours");
        }
    }

    /// Fedora links `/etc/ssl/certs` to `/etc/pki/tls/certs`. The link is
    /// absolute, so it only makes sense inside the guest, and that's where
    /// the CA has to end up.
    #[test]
    fn install_ca_cert_follows_absolute_links_inside_the_rootfs() {
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(rootfs.path().join("etc/pki/tls/certs")).unwrap();
        std::fs::create_dir_all(rootfs.path().join("etc/ssl")).unwrap();
        std::os::unix::fs::symlink("/etc/pki/tls/certs", rootfs.path().join("etc/ssl/certs"))
            .unwrap();

        install_ca_cert(rootfs.path(), "PEM").unwrap();

        assert_eq!(
            std::fs::read_to_string(rootfs.path().join("etc/pki/tls/certs/redan-ca.pem")).unwrap(),
            "PEM"
        );
    }
}
