/// Minimal libkrun FFI bindings.
///
/// Hand-written because krun-sys crate (1.10.1) lags behind the installed
/// libkrun (1.17.1). Only binds the functions redan uses.
use std::os::raw::{c_char, c_int};

pub const KRUN_LOG_LEVEL_OFF: u32 = 0;
pub const KRUN_LOG_STYLE_AUTO: u32 = 0;
pub const KRUN_LOG_TARGET_DEFAULT: c_int = -1;

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
    pub fn krun_add_virtio_console_default(
        ctx_id: u32,
        input_fd: c_int,
        output_fd: c_int,
        err_fd: c_int,
    ) -> i32;
}
