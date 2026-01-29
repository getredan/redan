// Minimal libkrun FFI bindings for PS-1 spike.
// Only what we need to boot a VM and test networking.

use std::os::raw::{c_char, c_int};

// Log levels
pub const KRUN_LOG_LEVEL_ERROR: u32 = 1;
pub const KRUN_LOG_LEVEL_INFO: u32 = 3;
pub const KRUN_LOG_LEVEL_DEBUG: u32 = 4;
pub const KRUN_LOG_LEVEL_TRACE: u32 = 5;

// Log style
pub const KRUN_LOG_STYLE_AUTO: u32 = 0;

// TSI features
pub const KRUN_TSI_HIJACK_INET: u32 = 1 << 0;
#[allow(dead_code)]
pub const KRUN_TSI_HIJACK_UNIX: u32 = 1 << 1;

// Log target
pub const KRUN_LOG_TARGET_DEFAULT: c_int = -1;

unsafe extern "C" {
    pub fn krun_init_log(target_fd: c_int, level: u32, style: u32, options: u32) -> i32;
    pub fn krun_create_ctx() -> i32;
    pub fn krun_free_ctx(ctx_id: u32) -> i32;
    pub fn krun_set_vm_config(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32;
    pub fn krun_set_root(ctx_id: u32, root_path: *const c_char) -> i32;
    pub fn krun_set_mapped_volumes(ctx_id: u32, mapped_volumes: *const *const c_char) -> i32;
    pub fn krun_set_exec(
        ctx_id: u32,
        exec_path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> i32;
    pub fn krun_set_env(ctx_id: u32, envp: *const *const c_char) -> i32;
    pub fn krun_set_workdir(ctx_id: u32, workdir: *const c_char) -> i32;
    pub fn krun_start_enter(ctx_id: u32) -> i32;
    pub fn krun_get_max_vcpus() -> i32;

    // Explicit vsock/TSI control
    pub fn krun_disable_implicit_vsock(ctx_id: u32) -> i32;
    pub fn krun_add_vsock(ctx_id: u32, tsi_features: u32) -> i32;
    pub fn krun_add_vsock_port(ctx_id: u32, port: u32, filepath: *const c_char) -> i32;

    // Console output
    pub fn krun_set_console_output(ctx_id: u32, filepath: *const c_char) -> i32;

    // virtio-net with unix stream socket (replaces TSI)
    pub fn krun_add_net_unixstream(
        ctx_id: u32,
        c_path: *const c_char,
        fd: c_int,
        c_mac: *const u8,
        features: u32,
        flags: u32,
    ) -> i32;
}
