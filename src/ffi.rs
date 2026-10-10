/// libkrun FFI bindings.
///
/// Hand-written rather than using krun-sys to avoid a bindgen build
/// dependency. Only the functions redan uses.
use std::os::raw::{c_char, c_int};

pub const KRUN_LOG_LEVEL_OFF: u32 = 0;
pub const KRUN_LOG_LEVEL_ERROR: u32 = 1;
pub const KRUN_LOG_LEVEL_WARN: u32 = 2;
pub const KRUN_LOG_LEVEL_INFO: u32 = 3;
pub const KRUN_LOG_LEVEL_DEBUG: u32 = 4;
pub const KRUN_LOG_LEVEL_TRACE: u32 = 5;
pub const KRUN_LOG_STYLE_AUTO: u32 = 0;
pub const KRUN_LOG_TARGET_DEFAULT: c_int = -1;

// Declarations for the libkrun C API, as documented in `libkrun.h`.
//
// Every function is `unsafe` to call. None is declared `safe fn`, because
// we make no soundness claims about libkrun's C code beyond what its
// header documents. In general, callers must uphold:
//
// - Every `*const c_char` is a valid, NUL-terminated C string that stays
//   alive for the duration of the call.
// - Every `*const *const c_char` points to an array of such strings,
//   terminated by a null pointer, that stays alive for the call.
// - `ctx_id` comes from `krun_create_ctx` and its configuration has not
//   been consumed by `krun_start_enter`.
// - File descriptors handed over (`krun_add_net_unixstream`) are open and
//   stay open for as long as the VM runs.
unsafe extern "C" {
    pub fn krun_init_log(target_fd: c_int, level: u32, style: u32, options: u32) -> i32;
    pub fn krun_create_ctx() -> i32;
    pub fn krun_set_vm_config(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32;
    pub fn krun_set_root(ctx_id: u32, root_path: *const c_char) -> i32;
    pub fn krun_set_exec(
        ctx_id: u32,
        exec_path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> i32;
    pub fn krun_set_workdir(ctx_id: u32, workdir: *const c_char) -> i32;
    pub fn krun_start_enter(ctx_id: u32) -> i32;
    pub fn krun_add_net_unixstream(
        ctx_id: u32,
        c_path: *const c_char,
        fd: c_int,
        c_mac: *const u8,
        features: u32,
        flags: u32,
    ) -> i32;
    pub fn krun_add_virtiofs(ctx_id: u32, c_tag: *const c_char, c_path: *const c_char) -> i32;
    pub fn krun_add_virtiofs3(
        ctx_id: u32,
        c_tag: *const c_char,
        c_path: *const c_char,
        shm_size: u64,
        read_only: bool,
    ) -> i32;
    pub fn krun_set_rlimits(ctx_id: u32, rlimits: *const *const c_char) -> i32;
}
