// Stub for linking against libkrun in CI.
// Exports the symbols redan's FFI bindings reference. The real
// libkrun is only needed at runtime.
int krun_init_log(void) { return 0; }
int krun_create_ctx(void) { return 0; }
int krun_set_vm_config(void) { return 0; }
int krun_set_root(void) { return 0; }
int krun_set_workdir(void) { return 0; }
int krun_set_exec(void) { return 0; }
int krun_start_enter(void) { return 0; }
int krun_add_net_unixstream(void) { return 0; }
int krun_add_virtiofs(void) { return 0; }
int krun_add_virtiofs3(void) { return 0; }
int krun_set_console_output(void) { return 0; }
int krun_set_rlimits(void) { return 0; }
