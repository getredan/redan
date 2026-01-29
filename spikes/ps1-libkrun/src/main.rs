mod ffi;

use std::ffi::CString;
use std::time::Instant;

/// PS-1: Can we boot a libkrun microVM and does TSI networking work?
///
/// This spike answers:
/// 1. Does krun_start_enter work on this system?
/// 2. How fast does the VM boot?
/// 3. What does TSI networking look like from the guest?
///
/// Usage: cargo run
/// Requires: libkrun + libkrunfw installed, /dev/kvm accessible
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

fn test_max_vcpus() {
    let max = unsafe { ffi::krun_get_max_vcpus() };
    println!("max vCPUs: {max}");
}

fn test_boot() {
    println!("PS-1: libkrun boot test");
    println!("=======================");

    let start = Instant::now();

    // Init logging
    let ret = unsafe {
        ffi::krun_init_log(
            ffi::KRUN_LOG_TARGET_DEFAULT,
            ffi::KRUN_LOG_LEVEL_INFO,
            ffi::KRUN_LOG_STYLE_AUTO,
            0,
        )
    };
    assert!(ret >= 0, "krun_init_log failed: {ret}");

    // Create context
    let ctx_id = unsafe { ffi::krun_create_ctx() };
    assert!(ctx_id >= 0, "krun_create_ctx failed: {ctx_id}");
    let ctx_id = ctx_id as u32;

    // 2 vCPUs, 512MB RAM (minimal)
    let ret = unsafe { ffi::krun_set_vm_config(ctx_id, 2, 512) };
    assert!(ret >= 0, "krun_set_vm_config failed: {ret}");

    // Use host root filesystem as guest root (simplest possible test)
    let root = CString::new("/").unwrap();
    let ret = unsafe { ffi::krun_set_root(ctx_id, root.as_ptr()) };
    assert!(ret >= 0, "krun_set_root failed: {ret}");

    // Run a simple command
    let exec_path = CString::new("/bin/sh").unwrap();
    let arg0 = CString::new("sh").unwrap();
    let arg1 = CString::new("-c").unwrap();
    let cmd = CString::new("echo 'REDAN_BOOT_OK'; uname -a; echo \"boot_time: ready\"").unwrap();
    let argv: Vec<*const i8> = vec![arg0.as_ptr(), arg1.as_ptr(), cmd.as_ptr(), std::ptr::null()];

    let ret = unsafe {
        ffi::krun_set_exec(
            ctx_id,
            exec_path.as_ptr(),
            argv.as_ptr(),
            std::ptr::null(), // inherit env
        )
    };
    assert!(ret >= 0, "krun_set_exec failed: {ret}");

    let setup_time = start.elapsed();
    println!("setup time: {setup_time:?}");
    println!("entering VM...");

    // This blocks until the guest process exits
    let ret = unsafe { ffi::krun_start_enter(ctx_id) };
    let total_time = start.elapsed();
    println!("---");
    println!("krun_start_enter returned: {ret}");
    println!("total time: {total_time:?}");
}

fn test_network() {
    println!("PS-1: TSI network test");
    println!("======================");

    let ret = unsafe {
        ffi::krun_init_log(
            ffi::KRUN_LOG_TARGET_DEFAULT,
            ffi::KRUN_LOG_LEVEL_INFO,
            ffi::KRUN_LOG_STYLE_AUTO,
            0,
        )
    };
    assert!(ret >= 0, "krun_init_log failed: {ret}");

    let ctx_id = unsafe { ffi::krun_create_ctx() };
    assert!(ctx_id >= 0, "krun_create_ctx failed: {ctx_id}");
    let ctx_id = ctx_id as u32;

    let ret = unsafe { ffi::krun_set_vm_config(ctx_id, 2, 512) };
    assert!(ret >= 0, "krun_set_vm_config failed: {ret}");

    let root = CString::new("/").unwrap();
    let ret = unsafe { ffi::krun_set_root(ctx_id, root.as_ptr()) };
    assert!(ret >= 0, "krun_set_root failed: {ret}");

    // TSI is the default (no krun_add_net_* calls).
    // Test what the guest sees for networking.
    let exec_path = CString::new("/bin/sh").unwrap();
    let arg0 = CString::new("sh").unwrap();
    let arg1 = CString::new("-c").unwrap();

    // Test sequence:
    // 1. Show network interfaces
    // 2. Try DNS resolution
    // 3. Try HTTP connection
    // 4. Show what process sees for its own connections
    let script = r#"
echo '=== NETWORK INTERFACES ==='
ip addr 2>/dev/null || ifconfig 2>/dev/null || echo 'no ip/ifconfig'

echo ''
echo '=== DNS TEST ==='
getent hosts api.github.com 2>/dev/null || echo 'getent failed'
cat /etc/resolv.conf 2>/dev/null || echo 'no resolv.conf'

echo ''
echo '=== HTTP TEST (curl) ==='
curl -sI --max-time 5 https://api.github.com/ 2>&1 | head -5 || echo 'curl failed'

echo ''
echo '=== RAW IP TEST ==='
curl -sI --max-time 5 https://140.82.121.6/ 2>&1 | head -3 || echo 'raw IP curl failed'

echo ''
echo '=== DONE ==='
"#;
    let cmd = CString::new(script).unwrap();
    let argv: Vec<*const i8> = vec![arg0.as_ptr(), arg1.as_ptr(), cmd.as_ptr(), std::ptr::null()];

    let ret = unsafe {
        ffi::krun_set_exec(
            ctx_id,
            exec_path.as_ptr(),
            argv.as_ptr(),
            std::ptr::null(),
        )
    };
    assert!(ret >= 0, "krun_set_exec failed: {ret}");

    println!("entering VM with TSI networking...");
    let start = Instant::now();
    let ret = unsafe { ffi::krun_start_enter(ctx_id) };
    let total = start.elapsed();
    println!("---");
    println!("krun_start_enter returned: {ret}");
    println!("total time: {total:?}");
}
