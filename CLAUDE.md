# redan

Secure, local-first AI agent execution environment. Rust + libkrun microVMs + network-layer secret injection.

## Repos

| Repo | License | Purpose |
|------|---------|---------|
| **getredan/redan** (this) | BSD-3-Clause | Open core: CLI, VM, proxy, secret providers |
| getredan/redan-enterprise | FSL-1.1-MIT | Enterprise: policy, audit, compliance |

## Dev Setup

Requires: Rust 1.92+, libkrun 1.17+, KVM (`/dev/kvm`), mise.

```bash
mise trust
mise run check          # format + lint + unit tests
mise run test-integration  # needs KVM + /tmp/redan-rootfs
```

## Tasks

| Task | What |
|------|------|
| `mise run check` | Full gate: format, lint, test |
| `mise run format` | `cargo fmt` |
| `mise run format-check` | CI formatting check |
| `mise run lint` | `cargo clippy -- -D warnings` |
| `mise run test` | Unit tests (`cargo test --lib`) |
| `mise run test-integration` | VM tests (`--ignored`, needs KVM) |
| `mise run bench` | Boot-to-proxy benchmark (needs KVM + image) |
| `mise run build` | Release build |

## Commits

Conventional commits. Sign with GPG when available.

```
feat(proxy): Add secret injection to HTTPS requests
fix(dns): Handle AAAA queries without panic
test(secret): Scrubbing tests for binary response bodies
```

## VM Safety

`krun_start_enter` blocks and ignores Ctrl-C. Always run via tmux:

```bash
SOCKET="/tmp/claude-tmux-sockets/claude.sock"
tmux -S "$SOCKET" send-keys -t session:0.0 "cargo run -- exec ..." Enter
pkill -9 redan  # to stop
```

## Testing

Security-critical project. Tests are load-bearing.

- Unit tests for pure logic: DNS, SNI, injection, scrubbing, certs.
- Integration tests boot real VMs. Marked `#[ignore]`, need KVM.
- Test names describe scenarios: `inject_skips_disallowed_host`.
- Deterministic. No sleeps, no network in unit tests.
- Never mock security boundaries.
- Capture and assert on expected errors.

## Architecture

```
libkrun VM (guest)
  |  virtio-net (unix socket, length-prefixed Ethernet frames)
  v
smoltcp (userspace TCP/IP)
  |  UDP :53 -> synthetic DNS (all names -> gateway)
  |  TCP :80 -> rejected (HTTPS only)
  |  TCP :443 -> TLS MITM (SNI, ephemeral certs)
  v
proxy (injection, scrubbing)
  |  rustls (upstream TLS)
  v
internet
```

## Modules

| Module | What |
|--------|------|
| `ca.rs` | Ephemeral MITM CA, per-hostname leaf certs |
| `dns.rs` | Synthetic DNS (A queries -> gateway IP) |
| `error.rs` | Error types |
| `ffi.rs` | libkrun FFI bindings |
| `image.rs` | Alpine rootfs image management |
| `net.rs` | smoltcp Device for virtio-net socket |
| `provider.rs` | Secret providers (literal, Vault KV v2) |
| `proxy.rs` | smoltcp event loop, connection state machine |
| `secret.rs` | Injection and scrubbing |
| `tls.rs` | SNI extraction, upstream relay |
| `vm.rs` | VM lifecycle |

## Style

- KISS. YAGNI.
- Guard clauses. Return early.
- Strong typing.
- Workarounds marked: `// WORKAROUND: <description>. See <link>`
- Match surrounding style.
