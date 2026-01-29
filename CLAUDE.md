# redan

Secure, local-first AI agent execution environment. Rust + libkrun microVMs + network-layer secret injection.

## Repos

| Repo | License | Purpose |
|------|---------|---------|
| **getredan/redan** (this) | BSD-3-Clause | Open core: CLI, VM, proxy, secret backends, audit |
| getredan/redan-enterprise | FSL-1.1-MIT | Enterprise: policy server, remote audit, compliance |
| getredan/redan-ai-slop | Private | AI planning docs, oracle reviews, research |

## Dev Setup

Requires: Rust 1.92+, libkrun 1.17+, KVM (`/dev/kvm`), mise.

```bash
mise trust                      # Trust mise.toml on first clone
mise run check                  # Format + lint + unit tests
mise run test-integration       # VM tests (needs KVM + /tmp/redan-rootfs)
```

## mise Tasks

| Task | What it does |
|------|-------------|
| `mise run check` | Full local gate: format, lint, test |
| `mise run format` | `cargo fmt` |
| `mise run format-check` | Verify formatting (CI) |
| `mise run lint` | `cargo clippy -- -D warnings` |
| `mise run test` | Unit tests only (`cargo test --lib`) |
| `mise run test-integration` | VM integration tests (`--ignored`, needs KVM) |
| `mise run build` | Release build |
| `mise run clean` | `cargo clean` |

**Always run `mise run check` before committing.** Tests must pass, clippy must be clean, formatting must be applied.

## Commits

Use conventional commits. `git -c commit.gpgsign=false commit` (GPG signing unavailable on this machine).

```
feat(proxy): Add secret injection to HTTPS requests
fix(dns): Handle AAAA queries without panic
test(secret): Add scrubbing tests for binary response bodies
refactor(vm): Extract net setup into helper function
chore: Update dependencies
docs: Document mise tasks in CLAUDE.md
```

## VM Safety

**NEVER run the VM binary directly.** `krun_start_enter` blocks forever and can't be Ctrl-C'd. Always use tmux:

```bash
SOCKET="/tmp/claude-tmux-sockets/claude.sock"
tmux -S "$SOCKET" send-keys -t ps1:0.0 "cargo run -- exec ..." Enter
tmux -S "$SOCKET" capture-pane -p -J -t ps1:0.0 -S -40
pkill -9 redan  # to stop
```

## Testing Philosophy

This is a security-critical project. Tests are load-bearing, not decorative.

- **Unit tests** for all pure logic: DNS parsing, SNI extraction, secret injection/scrubbing, cert generation. These run fast, no VM needed.
- **Integration tests** boot real VMs and validate the full chain. Marked `#[ignore]` (need KVM). Run via `mise run test-integration`.
- **Test names describe scenarios**: `inject_skips_disallowed_host`, not `test_inject_2`.
- Tests must be **deterministic**. No sleep-based timing, no network assumptions in unit tests.
- **Never mock security boundaries.** If a test needs TLS, use real TLS. If it needs a VM, boot a real VM.
- **Capture and validate errors.** If a test intentionally triggers an error, assert on the error, don't ignore it.
- Pristine test output: no warnings, no unexpected stderr.

## Code Reviews

For tests and security-sensitive code, get second opinions from oracle models:

```bash
# Via tmux (claude and codex block)
SOCKET="/tmp/claude-tmux-sockets/claude.sock"
tmux -S "$SOCKET" send-keys -t review:0.0 "claude -p 'Review this for security issues: ...' < src/proxy.rs" Enter

# Kimi (direct CLI)
kimi -p "Review for security issues" < src/proxy.rs
```

Use at least two independent reviewers for: proxy logic, secret handling, VM isolation, TLS implementation.

## Architecture

```
libkrun VM (guest)
  |  virtio-net (unix socket, BE length-prefixed Ethernet frames)
  v
smoltcp (userspace TCP/IP)
  |  UDP :53 -> synthetic DNS (all names -> gateway)
  |  TCP :80 -> HTTP interception
  |  TCP :443 -> TLS MITM (SNI routing, ephemeral certs)
  v
redan proxy (secret injection, response scrubbing)
  |  rustls ClientConnection (real upstream TLS)
  v
Internet
```

## Module Map

| Module | Purpose |
|--------|---------|
| `ca.rs` | Ephemeral MITM CA + per-hostname leaf certs (rcgen) |
| `dns.rs` | Synthetic DNS resolver (all A queries -> gateway IP) |
| `net.rs` | smoltcp Device impl for libkrun virtio-net socket |
| `tls.rs` | SNI extraction, upstream TLS, request relay |
| `secret.rs` | Placeholder injection + response scrubbing |
| `proxy.rs` | smoltcp event loop, connection state machine |
| `vm.rs` | libkrun FFI wrappers, VM lifecycle, CA install |
| `ffi.rs` | Hand-written libkrun bindings (krun-sys lags behind) |

## Spikes

Experimental code goes in `spikes/ps<N>-<name>/` as disposable Cargo projects.
Spike findings go in `~/Projects/redan-ai-slop/docs/spikes/`.
Once validated, spike code moves into `src/` with proper tests.

## Coding Standards

- **KISS and YAGNI.** Security dies with unnecessary complexity.
- **Strong typing.** No shortcuts on types.
- **Guard clauses.** Return early, avoid nesting.
- **No mocks for security boundaries.** Test real TLS, real VMs, real DNS.
- **Workarounds marked clearly**: `// WORKAROUND: <description>. See <link>`
- **Match surrounding style.** Consistency within a file trumps external standards.
