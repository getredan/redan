# redan - Agent Instructions

Secure, local-first AI agent execution environment. Rust + libkrun microVMs + network-layer secret injection.

## Repo structure

| Repo | Path | Purpose |
|------|------|---------|
| **getredan/redan** (this) | `~/Projects/redan/` | Open core (BSD-3-Clause). CLI, VM, proxy, secret backends, audit. |
| getredan/redan-enterprise | `~/Projects/redan-enterprise/` | Enterprise management (BSL-1.1). Policy server, remote audit, compliance. |
| getredan/redan-ai-slop | `~/Projects/redan-ai-slop/` | Private. AI-generated planning docs, oracle reviews, research. |

## Planning docs

All AI-maintained planning, architecture, and review docs live in `~/Projects/redan-ai-slop/docs/planning/`. Read those before making architectural decisions. Key files:

- `03-architecture.md` - CLI design, zero-config, redan.toml, error UX
- `04-security-model.md` - MITM proxy, threat model, network policy
- `04a-secret-management.md` - secret backends, injection modes, bootstrap flows
- `05-mvp-scope.md` - MVP constraints, user stories, repo/license split
- `08-risk-register.md` - 20 risks, mitigations, spike assignments
- `09-prototype-plan.md` - 6 spikes over 4 weeks, decision gates

## Tech stack

- **Language:** Rust (strict clippy, no unsafe without comment)
- **VM:** libkrun (dynamic linking for v1)
- **Proxy:** tokio + hyper + rustls + rcgen
- **Config:** toml (serde)
- **CLI:** clap (derive API)
- **Audit:** serde_json (JSONL to `$XDG_STATE_HOME/redan/sessions/`)

## MVP scope

- `redan exec`, `redan init`, `redan doctor`, `redan audit`
- Secret backends: env, Vault, AWS Secrets Manager
- Zero-config auto-detection (Node/Python/Rust/Go)
- MITM proxy with allowlist, Host validation, response header scrubbing
- Executable file modification warnings on session teardown
- Linux x86_64 primary, macOS aarch64 conditional

## Key constraints

- **No daemon.** `redan exec` manages VM lifecycle inline.
- **No `--no-sandbox`.** Can't fully disable security.
- **All secret backends in open core.** Enterprise repo handles policy/audit management only.
- **Audit log on host only.** `$XDG_STATE_HOME/redan/sessions/<id>/audit.jsonl`. Agent can't touch it.
- **Raw IPs always blocked.** Policy is hostname-based.

## Git

- `git -c commit.gpgsign=false commit` (GPG signing not available on this machine)
- Commit frequently, even mid-task
