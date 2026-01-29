# redan

Secure, local-first AI agent execution environment. Rust + libkrun microVMs + network-layer secret injection.

## Repos

| Repo | License | Purpose |
|------|---------|---------|
| **getredan/redan** (this) | BSD-3-Clause | Open core. CLI, VM, proxy, secret backends, audit. |
| getredan/redan-enterprise | FSL-1.1-MIT | Enterprise. Policy server, remote audit, compliance. |
| getredan/redan-ai-slop | Private | AI-generated planning docs, oracle reviews, research. |

## Rules

- **NEVER run the VM binary directly.** Always use tmux. `krun_start_enter` blocks forever and you can't Ctrl-C it. This includes `cargo run`, `strace`, or anything that invokes the binary. Use `tmux send-keys` to launch, `tmux capture-pane` to read output, `pkill -9` to stop.
- `git -c commit.gpgsign=false commit` (GPG signing unavailable on this machine)
- Spikes go in `spikes/ps<N>-<name>/` as disposable Cargo projects
- Document all spike findings in `~/Projects/redan-ai-slop/docs/spikes/` so context survives compaction
