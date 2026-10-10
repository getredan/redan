# redan

Secure, local-first AI agent execution environment. Rust + libkrun microVMs + network-layer secret injection.

| Repo | License | Purpose |
|------|---------|---------|
| **getredan/redan** (this) | BSD-3-Clause | Open core: CLI, VM, proxy, secret providers |
| getredan/redan-enterprise | FSL-1.1-MIT | Enterprise: policy, audit, compliance |

## Dev Setup

Requires: Rust 1.99 (pinned in `rust-toolchain.toml`), libkrun 1.17+, KVM (`/dev/kvm`), Docker, curl, mise.

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
| `mise run lint` | Clippy with `-D warnings`. Lint levels live in `Cargo.toml` under `[lints]` |
| `mise run test` | All tests (requires KVM + test image + Vault) |
| `mise run e2e` | Claude Code evals against the real API (needs the `claude-code` image and `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`) |
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
- `tests/e2e.rs` runs the `redan` binary in a throwaway project and home. Its Claude Code evals are `#[ignore]`d because they use a real token and the real API, so run them yourself with `mise run e2e`
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

## Rust

Edition 2024 on the toolchain pinned in `rust-toolchain.toml`. Lint levels live in `Cargo.toml` under `[lints.clippy]` and `mise run lint` and CI run the same command, so don't add `-W` flags to either. Clippy already checks most idiom rules (`single_match`, `while_let_loop`, `uninlined_format_args`, ...), so this list only covers what it can't check.

- Guard clauses use `let ... else`. Chained conditions use let chains (`if let Some(a) = x && let Some(b) = y`) instead of nesting.
- Propagate errors with `?`. Use `map_err` only to add context that a `From` impl can't carry.
- Every `unsafe` block does one operation and has a `// SAFETY:` comment that names the callee's preconditions and says why they hold here (both are linted). If you can't write that comment truthfully, the code is wrong: validate or return an error. Use the safe std API when there is one: `std::io::IsTerminal` over `libc::isatty`, `Command::process_group` over `setpgid`, `c"/bin/sh"` over `CString::new("/bin/sh").unwrap()`.
- Fix the cause instead of suppressing a lint. `#[allow]` is denied by `allow_attributes`. When a fix really would make the code worse, use `#[expect(lint, reason = "...")]` on the one item, and the compiler tells you when it stops being needed. Tests may unwrap, expect and panic (`clippy.toml`).
- Don't mutate the process environment (`std::env::set_var`) in tests. Pass the value in as an argument and test the function that takes it.
- Types that hold secret values don't derive `Debug`. Write a redacting `Debug` by hand and keep the value in `Zeroizing`, like `secret::SecretBinding`.
- Bytes from the guest or the network are untrusted. New parsing code uses `.get(..)` over `buf[i]`, `try_from` over `as`, and checked arithmetic on lengths, so a crafted packet can't panic the proxy.
- Keep a `for` loop when the body has early exits, `?`, or mutable state. Use an iterator chain for a plain filter/map/collect.
- The code is sync: a smoltcp poll loop plus threads. Adding an async runtime is an architecture change, so raise it first.
- Internal functions take `&str`, `&Path`, `&[u8]`, not `impl AsRef<_>`.
