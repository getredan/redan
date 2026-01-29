mod ffi;

use std::ffi::CString;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let test = args.get(1).map(|s| s.as_str()).unwrap_or("boot");

    match test {
        "boot" => test_boot(),
        "network" => test_network(),
        "max-vcpus" => test_max_vcpus(),
        _ => {
            eprintln!("Usage: ps1-libkrun [boot|network|max-vcpus]");
            std::process::exit(1);
        }
    }
}

/// Helper: create a VM context with Alpine rootfs, run a shell command, return exit code.
fn run_guest_cmd(cmd: &str) -> i32 {
    let ret = unsafe {
        ffi::krun_init_log(
            ffi::KRUN_LOG_TARGET_DEFAULT,
            ffi::KRUN_LOG_LEVEL_ERROR,
            ffi::KRUN_LOG_STYLE_AUTO,
            0,
        )
    };
    assert!(ret >= 0, "krun_init_log failed: {ret}");

    let ctx_id = unsafe { ffi::krun_create_ctx() };
    assert!(ctx_id >= 0, "krun_create_ctx failed: {ctx_id}");
    let ctx_id = ctx_id as u32;

    let ret = unsafe { ffi::krun_set_vm_config(ctx_id, 1, 256) };
    assert!(ret >= 0, "krun_set_vm_config failed: {ret}");

    let root = CString::new("/tmp/redan-rootfs").unwrap();
    let ret = unsafe { ffi::krun_set_root(ctx_id, root.as_ptr()) };
    assert!(ret >= 0, "krun_set_root failed: {ret}");

    let workdir = CString::new("/").unwrap();
    let ret = unsafe { ffi::krun_set_workdir(ctx_id, workdir.as_ptr()) };
    assert!(ret >= 0, "krun_set_workdir failed: {ret}");

    // exec_path = /bin/busybox, argv = {"ash", "-c", cmd}
    let exec_path = CString::new("/bin/busybox").unwrap();
    let arg0 = CString::new("ash").unwrap();
    let arg1 = CString::new("-c").unwrap();
    let arg2 = CString::new(cmd).unwrap();
    let argv: Vec<*const i8> = vec![
        arg0.as_ptr(), arg1.as_ptr(), arg2.as_ptr(), std::ptr::null()
    ];

    let path = CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin").unwrap();
    let term = CString::new("TERM=xterm").unwrap();
    let envp: Vec<*const i8> = vec![path.as_ptr(), term.as_ptr(), std::ptr::null()];

    let ret = unsafe {
        ffi::krun_set_exec(ctx_id, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr())
    };
    assert!(ret >= 0, "krun_set_exec failed: {ret}");

    unsafe { ffi::krun_start_enter(ctx_id) }
}

fn test_max_vcpus() {
    let max = unsafe { ffi::krun_get_max_vcpus() };
    println!("max vCPUs: {max}");
}

fn test_boot() {
    println!("PS-1: boot test");

    let start = Instant::now();
    let exit_code = run_guest_cmd("echo REDAN_BOOT_OK; uname -a; cat /etc/alpine-release");
    let elapsed = start.elapsed();

    println!("---");
    println!("exit code: {exit_code}");
    println!("total time: {elapsed:?}");
}

fn test_network() {
    println!("PS-1: TSI network test");
    println!("======================");
    println!("TSI is enabled by default (no krun_add_net_* calls).");
    println!("Guest sockets are forwarded to host process as-is.");
    println!();

    // Avoid special chars that trigger InvalidAscii in libkrun's arg parser
    let exit_code = run_guest_cmd(
        "echo NET_INTERFACES; ip addr 2>/dev/null; \
         echo DNS_TEST; nslookup api.github.com 2>/dev/null; \
         echo HTTPS_TEST; wget -q -O - https://api.github.com/ 2>/dev/null; \
         echo DONE"
    );

    println!("---");
    println!("exit code: {exit_code}");
}
