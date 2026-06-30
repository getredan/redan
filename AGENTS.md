# redan

Secure, local-first AI agent execution environment. Rust + libkrun microVMs + network-layer secret injection.

| Repo | License | Purpose |
|------|---------|---------|
| **getredan/redan** (this) | BSD-3-Clause | Open core: CLI, VM, proxy, secret providers |
| getredan/redan-enterprise | FSL-1.1-MIT | Enterprise: policy, audit, compliance |

## Dev Setup

Requires: Rust 1.92+, libkrun 1.17+, KVM (`/dev/kvm`), Docker, mise.

```bash
mise trust
mise run test-setup       # create test image + start Vault
mise run check            # format + lint + all tests
```

## Tasks

| Task | What |
|------|------|
| `mise run check` | Full gate: format, lint, test |
| `mise run format` | `cargo fmt` |
| `mise run format-check` | CI formatting check |
| `mise run lint` | Clippy with `-D warnings`, pedantic, nursery, and strict panic/unwrap lints |
| `mise run test` | All tests (requires KVM + test image + Vault) |
| `mise run test-setup` | Create test image and start Vault dev server |
| `mise run vault-up` | Start Vault dev server and seed test data |
| `mise run bench` | Boot-to-proxy benchmark (needs KVM + image) |
| `mise run build` | Release build |

## Workflow

- `main` is protected; all changes go through PRs (squash or rebase, linear history)
- `mise run check` before every commit (same gate as CI)
- Conventional commits, GPG-signed: `feat(proxy): Add secret injection`

## VM Safety

`krun_start_enter` blocks and ignores Ctrl-C. Always run via tmux:

```bash
SOCKET="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/redan-tmux.sock"
tmux -S "$SOCKET" send-keys -t session:0.0 "cargo run -- exec ..." Enter
pkill -9 redan  # SIGKILL required: krun_start_enter ignores SIGTERM
```

## Testing

Security-critical project. Tests are load-bearing.

- Unit tests for pure logic: DNS, SNI, injection, scrubbing, certs, templates
- Integration tests boot real VMs (KVM + test image via `redan image create test`)
- Vault tests require a running Vault (`mise run vault-up`)
- Test names describe scenarios: `inject_skips_disallowed_host`
- Deterministic: no sleeps, no network in unit tests
- Never mock security boundaries
- Capture and assert on expected errors

## Architecture

```text
libkrun VM (guest)
  |  virtio-net (unix socket, length-prefixed Ethernet frames)
  v
smoltcp (userspace TCP/IP)
  |  UDP :53 -> synthetic DNS (all names -> gateway)
  |  TCP :80 -> rejected (HTTPS only)
  |  TCP :443 -> TLS MITM (SNI, ephemeral certs)
  v
proxy (injection, scrubbing, host allowlist)
  |  rustls (upstream TLS)
  v
internet (only allowed hosts)
```

## Modules

| Module | What |
|--------|------|
| `ca.rs` | Ephemeral MITM CA, per-hostname leaf certs |
| `config.rs` | `redan.toml` parsing: `[secrets]`, `[network]`, `[mount]`, `[env]` |
| `dns.rs` | Synthetic DNS (A queries -> gateway IP) |
| `error.rs` | Error types |
| `ffi.rs` | libkrun FFI bindings |
| `image.rs` | Image management: create, import, docker, dockerfile, devcontainer, compose |
| `net.rs` | smoltcp Device for virtio-net socket |
| `provider.rs` | Secret providers (literal, env, Vault KV v2) |
| `proxy.rs` | smoltcp event loop, connection state machine, host allowlist |
| `secret.rs` | Injection and scrubbing |
| `session.rs` | Session lifecycle, metadata, listing |
| `templates.rs` | Minijinja templates (`templates/*.j2`, embedded via `include_str!`) |
| `tls.rs` | SNI extraction, upstream relay |
| `vm.rs` | VM lifecycle |

## Style

- KISS. YAGNI. Guard clauses. Return early.
- Strong typing. Match surrounding style.
- Workarounds marked: `// WORKAROUND: <description>. See <link>`
