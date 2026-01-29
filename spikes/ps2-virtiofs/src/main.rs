mod ffi;

use std::ffi::CString;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let test = args.get(1).map(|s| s.as_str()).unwrap_or("mount");

    match test {
        "mount" => test_mount(),
        "symlink" => test_symlink(),
        "perf" => test_perf(),
        "mapped" => test_mapped_volumes(),
        _ => {
            eprintln!("Usage: ps2-virtiofs [mount|symlink|perf|mapped]");
            std::process::exit(1);
        }
    }
}

/// Helper: boot VM with a virtiofs mount and run a command.
/// The mount appears at /workspace inside the guest.
fn run_with_mount(host_dir: &str, cmd: &str) -> i32 {
    let ret = unsafe {
        ffi::krun_init_log(
            ffi::KRUN_LOG_TARGET_DEFAULT,
            ffi::KRUN_LOG_LEVEL_ERROR,
            ffi::KRUN_LOG_STYLE_AUTO,
            0,
        )
    };
    assert!(ret >= 0);

    let ctx_id = unsafe { ffi::krun_create_ctx() };
    assert!(ctx_id >= 0);
    let ctx_id = ctx_id as u32;

    let ret = unsafe { ffi::krun_set_vm_config(ctx_id, 1, 256) };
    assert!(ret >= 0);

    let root = CString::new("/tmp/redan-rootfs").unwrap();
    let ret = unsafe { ffi::krun_set_root(ctx_id, root.as_ptr()) };
    assert!(ret >= 0);

    let workdir = CString::new("/").unwrap();
    let ret = unsafe { ffi::krun_set_workdir(ctx_id, workdir.as_ptr()) };
    assert!(ret >= 0);

    // Add virtiofs mount: host_dir tagged as "workspace"
    let tag = CString::new("workspace").unwrap();
    let path = CString::new(host_dir).unwrap();
    let ret = unsafe { ffi::krun_add_virtiofs(ctx_id, tag.as_ptr(), path.as_ptr()) };
    assert!(ret >= 0, "krun_add_virtiofs failed: {ret}");

    // The guest command must mount the tagged filesystem.
    // libkrun's init mounts krun_set_root as /, but additional
    // virtiofs devices need explicit mount inside the guest.
    let full_cmd = format!(
        "mkdir -p /workspace; mount -t virtiofs workspace /workspace; {cmd}"
    );

    let exec_path = CString::new("/bin/busybox").unwrap();
    let arg0 = CString::new("ash").unwrap();
    let arg1 = CString::new("-c").unwrap();
    let arg2 = CString::new(full_cmd.as_str()).unwrap();
    let argv: Vec<*const i8> = vec![
        arg0.as_ptr(),
        arg1.as_ptr(),
        arg2.as_ptr(),
        std::ptr::null(),
    ];

    let path_env =
        CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin").unwrap();
    let term = CString::new("TERM=xterm").unwrap();
    let envp: Vec<*const i8> = vec![path_env.as_ptr(), term.as_ptr(), std::ptr::null()];

    let ret = unsafe {
        ffi::krun_set_exec(ctx_id, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr())
    };
    assert!(ret >= 0);

    unsafe { ffi::krun_start_enter(ctx_id) }
}

/// Test 1: basic mount - can we see host files?
fn test_mount() {
    println!("PS-2: virtiofs mount test");
    println!("========================");

    let exit_code = run_with_mount(
        "/tmp/redan-test-project",
        "echo MOUNT_OK; ls /workspace/; \
         echo FILE_CONTENT; cat /workspace/README.md; \
         echo WRITE_TEST; echo guest_wrote_this > /workspace/guest-file.txt; \
         cat /workspace/guest-file.txt; \
         echo DONE",
    );

    println!("---");
    println!("exit code: {exit_code}");

    // Check if guest write is visible on host
    match std::fs::read_to_string("/tmp/redan-test-project/guest-file.txt") {
        Ok(content) => println!("host sees guest file: {}", content.trim()),
        Err(e) => println!("host cannot read guest file: {e}"),
    }
    // Clean up
    std::fs::remove_file("/tmp/redan-test-project/guest-file.txt").ok();
}

/// Test 2: symlink traversal - can guest escape through symlinks?
fn test_symlink() {
    println!("PS-2: symlink traversal test");
    println!("============================");

    let exit_code = run_with_mount(
        "/tmp/redan-test-project",
        // Test 1: internal symlink (should work)
        "echo INTERNAL_SYMLINK; cat /workspace/readme-link 2>&1; \
         \
         echo EXTERNAL_SYMLINK_PASSWD; cat /workspace/evil-passwd-link 2>&1; \
         echo EXIT_PASSWD=$?; \
         \
         echo EXTERNAL_SYMLINK_SSH; ls /workspace/evil-ssh-link/ 2>&1; \
         echo EXIT_SSH=$?; \
         \
         echo DOTDOT_TRAVERSAL; cat /workspace/../etc/passwd 2>&1; \
         echo EXIT_DOTDOT=$?; \
         \
         echo PROC_ACCESS; cat /proc/1/environ 2>&1; \
         echo EXIT_PROC=$?; \
         \
         echo DONE",
    );

    println!("---");
    println!("exit code: {exit_code}");
}

/// Test 3: performance benchmarks
fn test_perf() {
    println!("PS-2: virtiofs performance test");
    println!("===============================");

    // First, run the same operations on the host for comparison
    println!("[host] running host baseline...");
    let host_start = Instant::now();
    let _count = walkdir("/tmp/redan-test-project");
    let host_find = host_start.elapsed();
    println!("[host] find: {host_find:?}");

    let host_start = Instant::now();
    grep_files("/tmp/redan-test-project");
    let host_grep = host_start.elapsed();
    println!("[host] grep: {host_grep:?}");

    println!();

    let exit_code = run_with_mount(
        "/tmp/redan-test-project",
        // time each operation separately using shell builtins
        "echo PERF_FIND_START; \
         BEFORE=$(date +%s%N 2>/dev/null || echo 0); \
         find /workspace -type f | wc -l; \
         AFTER=$(date +%s%N 2>/dev/null || echo 0); \
         echo PERF_FIND_MS; \
         \
         echo PERF_GREP_START; \
         grep -r code /workspace/src/ | wc -l; \
         echo PERF_GREP_DONE; \
         \
         echo PERF_SEQ_READ_START; \
         for f in /workspace/src/module_0/*.rs; do cat $f > /dev/null; done; \
         echo PERF_SEQ_READ_DONE; \
         \
         echo PERF_WRITE_START; \
         i=0; while [ $i -lt 50 ]; do echo test > /workspace/bench_$i.tmp; i=$((i+1)); done; \
         echo PERF_WRITE_DONE; \
         \
         echo PERF_CLEANUP; \
         rm -f /workspace/bench_*.tmp; \
         echo DONE",
    );

    println!("---");
    println!("exit code: {exit_code}");
}

/// Test 4: krun_set_mapped_volumes (legacy API, format "host_path:guest_path")
fn test_mapped_volumes() {
    println!("PS-2: mapped volumes test (legacy API)");
    println!("======================================");

    let ret = unsafe {
        ffi::krun_init_log(
            ffi::KRUN_LOG_TARGET_DEFAULT,
            ffi::KRUN_LOG_LEVEL_ERROR,
            ffi::KRUN_LOG_STYLE_AUTO,
            0,
        )
    };
    assert!(ret >= 0);

    let ctx_id = unsafe { ffi::krun_create_ctx() };
    assert!(ctx_id >= 0);
    let ctx_id = ctx_id as u32;

    let ret = unsafe { ffi::krun_set_vm_config(ctx_id, 1, 256) };
    assert!(ret >= 0);

    let root = CString::new("/tmp/redan-rootfs").unwrap();
    let ret = unsafe { ffi::krun_set_root(ctx_id, root.as_ptr()) };
    assert!(ret >= 0);

    let workdir = CString::new("/").unwrap();
    let ret = unsafe { ffi::krun_set_workdir(ctx_id, workdir.as_ptr()) };
    assert!(ret >= 0);

    // Legacy API: "host_path:guest_path" pairs
    let vol = CString::new("/tmp/redan-test-project:/workspace").unwrap();
    let volumes: Vec<*const i8> = vec![vol.as_ptr(), std::ptr::null()];
    let ret = unsafe { ffi::krun_set_mapped_volumes(ctx_id, volumes.as_ptr() as *const *const i8) };
    assert!(ret >= 0, "krun_set_mapped_volumes failed: {ret}");

    let exec_path = CString::new("/bin/busybox").unwrap();
    let arg0 = CString::new("ash").unwrap();
    let arg1 = CString::new("-c").unwrap();
    let arg2 = CString::new("echo MAPPED_OK; ls /workspace/; cat /workspace/README.md; echo DONE")
        .unwrap();
    let argv: Vec<*const i8> = vec![
        arg0.as_ptr(),
        arg1.as_ptr(),
        arg2.as_ptr(),
        std::ptr::null(),
    ];

    let path_env =
        CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin").unwrap();
    let term = CString::new("TERM=xterm").unwrap();
    let envp: Vec<*const i8> = vec![path_env.as_ptr(), term.as_ptr(), std::ptr::null()];

    let ret = unsafe {
        ffi::krun_set_exec(ctx_id, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr())
    };
    assert!(ret >= 0);

    let exit_code = unsafe { ffi::krun_start_enter(ctx_id) };
    println!("---");
    println!("exit code: {exit_code}");
}

fn walkdir(path: &str) -> usize {
    let mut count = 0;
    for entry in std::fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            count += walkdir(&entry.path().to_string_lossy());
        } else {
            count += 1;
        }
    }
    count
}

fn grep_files(path: &str) {
    for entry in std::fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            grep_files(&entry.path().to_string_lossy());
        } else if entry.path().extension().map_or(false, |e| e == "rs") {
            let content = std::fs::read_to_string(entry.path()).unwrap_or_default();
            let _ = content.contains("code");
        }
    }
}
