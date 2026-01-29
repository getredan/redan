# redan

Secure, local-first AI agent execution environment. Rust + libkrun microVMs + network-layer secret injection.

## Repos

| Repo | License | Purpose |
|------|---------|---------|
| **getredan/redan** (this) | BSD-3-Clause | Open core. CLI, VM, proxy, secret backends, audit. |
| getredan/redan-enterprise | FSL-1.1-MIT | Enterprise. Policy server, remote audit, compliance. |
| getredan/redan-ai-slop | Private | AI-generated planning docs, oracle reviews, research. |

## Rules

- Always run `cargo run`, `cargo test`, and any long-running process inside tmux. Never run directly - you can't monitor or kill a hanging process otherwise.
- `git -c commit.gpgsign=false commit` (GPG signing unavailable on this machine)
- Spikes go in `spikes/ps<N>-<name>/` as disposable Cargo projects
