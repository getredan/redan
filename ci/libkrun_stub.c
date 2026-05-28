// Stub for linking against libkrun in CI.
// Exports the symbols redan's FFI bindings reference. The real
// libkrun is only needed at runtime.
//
// Signatures should match src/ffi.rs declarations (C ABI).

#include <stdbool.h>
#include <stdint.h>

int krun_init_log(int target_fd, uint32_t level, uint32_t style, uint32_t options) { return 0; }
int krun_create_ctx(void) { return 0; }
int krun_set_vm_config(uint32_t ctx_id, uint8_t num_vcpus, uint32_t ram_mib) { return 0; }
int krun_set_root(uint32_t ctx_id, const char *root_path) { return 0; }
int krun_set_workdir(uint32_t ctx_id, const char *workdir) { return 0; }
int krun_set_exec(uint32_t ctx_id, const char *exec_path, const char **argv, const char **envp) { return 0; }
int krun_start_enter(uint32_t ctx_id) { return 0; }
int krun_add_net_unixstream(uint32_t ctx_id, const char *c_path, int fd, const uint8_t *c_mac, uint32_t features, uint32_t flags) { return 0; }
int krun_add_virtiofs(uint32_t ctx_id, const char *c_tag, const char *c_path) { return 0; }
int krun_add_virtiofs3(uint32_t ctx_id, const char *c_tag, const char *c_path, uint64_t shm_size, bool read_only) { return 0; }
int krun_set_console_output(void) { return 0; }
int krun_set_rlimits(uint32_t ctx_id, const char **rlimits) { return 0; }
