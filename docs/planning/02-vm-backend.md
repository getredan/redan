# 2. VM Backend & Dependencies

## 2.1 Architectural Decision: libkrun, Not Gondolin

**Decision:** Use libkrun directly as the microVM backend. Adopt Gondolin's network-layer secret injection as a design pattern, reimplemented in Rust.

**Rationale:**

| Factor | Gondolin | libkrun (direct) |
|--------|----------|-------------------|
| Language | TypeScript/JS | Rust (C API with Rust bindings) |
| VM backend | QEMU (spawns process) | KVM/HVF (library call) |
| Architecture | ARM64 only | x86_64 + ARM64 |
| Distribution | npm package | Static link into binary |
| Network stack | JS-based (programmable, flexible) | We build our own (more work, full control) |
| Secret injection | Built-in (`createHttpHooks`) | We reimplement the pattern |
| Maturity | Experimental, single maintainer | v1.0+ stable API, Red Hat maintained |
| Users | Armin Ronacher + small community | Podman, crun, microsandbox, muvm |

**What we take from Gondolin (design patterns, not code):**
- Network-layer secret injection: guest sees placeholder, host injects real value only for allowed hosts
- Per-secret host scoping: `GITHUB_TOKEN` only injected for `api.github.com`
- Programmable HTTP hooks: intercept, inspect, modify requests at the host network boundary
- The philosophy: "the VM is untrusted compute, the host is the policy enforcement point"

**What we build ourselves:**
- Network proxy in Rust (tokio-based) replacing Gondolin's JS network stack
- Secret management with pluggable backends (Gondolin only supports `process.env`)
- Policy engine with declarative config (Gondolin uses programmatic JS)
- Audit logging (Gondolin has none)
- Single binary distribution (Gondolin requires npm + Node.js)

## 2.2 libkrun Deep-Dive

### API Surface

libkrun exposes a C API (`libkrun.h`). Key functions:

```
krun_create_ctx()          — Create VM context
krun_set_vm_config()       — Set vCPUs, RAM
krun_set_root_disk()       — Set root filesystem (OCI image layer)
krun_set_mapped_volumes()  — Mount host directories into guest (virtio-fs)
krun_set_port_map()        — Port forwarding
krun_set_exec()            — Set command to execute inside VM
krun_set_env()             — Set environment variables in guest
krun_set_workdir()         — Set working directory
krun_start_enter()         — Boot and enter VM (blocks)
```

Networking modes:
- **TSI (Transparent Socket Impersonation):** Guest sockets transparently map to host sockets via virtio-vsock. Simple, low overhead. Our network proxy hooks in here.
- **passt/gvproxy:** Full virtual network via virtio-net. More isolation, slightly more overhead. Allows raw packet-level control.

**Recommendation for Redan:** Start with TSI for simplicity. TSI means all guest network calls route through the host's network stack — our proxy sits at this boundary naturally. If we need packet-level control later, switch to passt.

### Rust Bindings

libkrun provides a C API. Options for Rust:
1. **bindgen** — Auto-generate Rust FFI from `libkrun.h`. Standard approach.
2. **Safe wrapper crate** — Build a Rust API on top of bindgen output.
3. **microsandbox's approach** — They already have Rust bindings. Study their `microsandbox-core` crate.

**Recommendation:** Write our own safe wrapper. microsandbox's code is Apache-2.0 so we can reference it, but their abstraction layer includes concepts we don't need (server daemon, project manifests). Our wrapper should be thin: create VM, configure, boot, attach I/O, teardown.

### Build & Linking

libkrun can be:
- **Dynamically linked** — User installs libkrun separately. Simpler builds, but adds a dependency.
- **Statically linked** — Bundle into our binary. True single-binary distribution but requires building libkrun from source.

**Recommendation:** Dynamic linking for v1 (libkrun available via package managers on supported platforms). Provide install scripts that handle the dependency. Evaluate static linking for v1.1 release once we've stabilized.

Platform availability:
| Platform | Package | Notes |
|----------|---------|-------|
| Fedora/RHEL | `libkrun-devel` | First-class, maintained by libkrun author |
| Ubuntu/Debian | Build from source or PPA | No official package yet |
| Arch | AUR `libkrun` | Community maintained |
| macOS (Homebrew) | `brew install libkrun` | Available via formula |
| Nix | `nixpkgs#libkrun` | Available |

For platforms without packages, our install script builds from source (Rust toolchain required — acceptable for a Rust-based tool).

## 2.3 Platform Support Matrix

### v1 Targets

| Platform | Hypervisor | libkrun support | Priority | Notes |
|----------|-----------|-----------------|----------|-------|
| Linux x86_64 | KVM | ✅ Stable | P0 | Primary dev platform, CI |
| Linux aarch64 | KVM | ✅ Stable | P1 | ARM servers, Graviton |
| macOS aarch64 | HVF | ✅ Stable | P0 | Apple Silicon dev laptops |
| macOS x86_64 | HVF | ⚠️ Untested | P2 | Intel Macs, declining market |

### v2 Targets

| Platform | Approach | Notes |
|----------|----------|-------|
| Windows x86_64 | WSL2 bridge | Run Redan inside WSL2, which provides KVM. Not native Windows. |
| Windows ARM64 | WSL2 bridge | Same approach, ARM64 WSL2 |
| CI (GitHub Actions) | Nested virt or direct KVM | GHA runners support KVM on larger runners. Standard runners need testing. |
| Docker/container | Requires `/dev/kvm` passthrough | Works if host provides KVM device. Breaks in most cloud container runtimes. |

### CI Environment Concerns

**Problem:** Many CI environments don't expose `/dev/kvm`. This means Redan can't run inside standard GitHub Actions runners, Docker containers without device passthrough, or most cloud CI.

**Implications:**
- Redan is primarily a developer workstation tool, not a CI sandbox (for v1)
- CI use requires self-hosted runners with KVM access, or larger GHA runners
- This is the same constraint microsandbox has
- Document clearly: "Redan requires hardware virtualization (KVM on Linux, HVF on macOS)"

## 2.4 Guest Image Strategy

### OCI Compatibility

libkrun supports OCI container images as root filesystems. This means users can run standard Docker images:

```
redan run --image python:3.12-slim -- python script.py
redan run --image node:22-alpine -- npm test
redan run --image ubuntu:24.04 -- bash
```

**This is critical for adoption.** Users bring their existing images. No proprietary format.

### Base Images

We should provide optimized base images for common agent workflows:

| Image | Contents | Use Case |
|-------|----------|----------|
| `redan/base` | Minimal Linux, redan-agent helper | Foundation |
| `redan/python` | base + Python 3.12+, pip, common libs | Python agents |
| `redan/node` | base + Node.js 22+, npm | JS/TS agents |
| `redan/dev` | base + Python + Node + Go + Rust + git + common tools | General agent work |

The `redan-agent` helper inside images handles:
- Reporting readiness to host
- Structured output for audit log
- Graceful shutdown on host signal

**v1:** Don't build custom images. Use stock OCI images. The agent runs inside whatever image the user specifies. Custom images are a v1.1 optimization.

## 2.5 Network Architecture

This is where we reimplement Gondolin's key insight in Rust.

### TSI Mode (v1)

```
┌─────────────────────────────────────┐
│           Guest VM (microVM)        │
│                                     │
│  Agent process                      │
│    ↓ connect("api.github.com:443")  │
│  Guest kernel                       │
│    ↓ virtio-vsock                   │
└─────────┬───────────────────────────┘
          │ TSI (socket impersonation)
┌─────────┴───────────────────────────┐
│         Host (Redan process)        │
│                                     │
│  ┌─────────────────────────────┐    │
│  │     Network Policy Engine   │    │
│  │                             │    │
│  │  1. Check: is host allowed? │    │
│  │  2. Check: TLS SNI/CONNECT │    │
│  │  3. Inject secrets if match │    │
│  │  4. Log decision            │    │
│  │  5. Forward or drop         │    │
│  └─────────────┬───────────────┘    │
│                │                    │
│  ┌─────────────┴───────────────┐    │
│  │     Secret Manager          │    │
│  │  (retrieve from backend)    │    │
│  └─────────────┬───────────────┘    │
│                │                    │
│         Host network stack          │
│                ↓                    │
│         api.github.com:443          │
└─────────────────────────────────────┘
```

### Secret Injection Flow

1. Guest agent makes HTTPS request to `api.github.com`
2. TSI routes the TCP connection to host Redan process
3. Redan sees TLS ClientHello → extracts SNI (`api.github.com`)
4. Policy check: `api.github.com` is in allowlist → proceed
5. For HTTPS: Redan acts as MITM proxy with its own CA cert (installed in guest)
   - Terminates TLS from guest
   - Reads HTTP request headers
   - If `Authorization: Bearer $GITHUB_TOKEN` (placeholder) → replace with real token from secret manager
   - Opens new TLS connection to real `api.github.com`
   - Forwards request with real token
6. Response flows back through the same path
7. Audit log entry: `{timestamp, guest_pid, dest: "api.github.com", secret_injected: "GITHUB_TOKEN", policy: "allow", latency_ms: 42}`

### Alternative: Connect Proxy (No MITM)

MITM has drawbacks (CA trust, certificate pinning breakage). Alternative approach:

1. Guest uses HTTP CONNECT proxy (configured via environment)
2. Redan proxy receives CONNECT request → checks host against allowlist
3. If allowed, establishes tunnel. Redan can inject secrets into the CONNECT handshake headers but NOT into the tunneled TLS stream.
4. For secret injection: agent must use Redan-provided auth headers at the proxy level, or we need the MITM approach.

**Decision needed (deferred to Section 4):** MITM with in-VM CA vs CONNECT proxy with limited injection. MITM gives full secret injection capability but is more complex. CONNECT proxy is simpler but can only enforce host allowlists, not inject secrets transparently.

### Non-HTTP Protocols

| Protocol | Handling |
|----------|---------|
| HTTP/HTTPS | Full proxy with optional secret injection |
| SSH | Allow/deny by host. Secret injection possible via agent forwarding from host. |
| DNS | Resolve on host side. Guest DNS queries routed to host resolver. No direct external DNS. |
| WebSocket | Treated as HTTP upgrade. Same host allowlist applies. |
| gRPC | HTTP/2 based. Same handling as HTTPS. |
| Raw TCP | Allow/deny by host:port. No content inspection. |
| UDP | Block by default. Allow specific host:port if configured. |

## 2.6 Comparison with microsandbox's Approach

microsandbox is the closest existing project. Understanding their architecture informs ours.

| Aspect | microsandbox | Redan |
|--------|-------------|-------|
| VM backend | libkrun (same) | libkrun (same) |
| Architecture | Server daemon (`msb server`) + CLI client | Single process (no daemon) |
| Config | `Sandboxfile` (TOML) | `redan.toml` (TOML) |
| Networking | Basic port mapping | Full network proxy with policy + secret injection |
| Secrets | None | Core feature — pluggable backends, network-layer injection |
| State | `./menv` directory | VM state in `$XDG_STATE_HOME/redan/` |
| MCP | MCP server for AI agents | MCP server (v1.1) |
| Distribution | Server binary + CLI binary + SDKs | Single binary |

**Key architectural difference:** microsandbox runs a background server daemon that manages VMs, with CLI and SDKs as clients. Redan is a single process — you run `redan exec` and it manages the VM lifecycle inline. No daemon to start, no ports to manage, no IPC complexity.

This is a deliberate trade-off:
- **Daemon (microsandbox):** Can manage multiple VMs, warm pools, shared state. More complex to install and operate.
- **Inline (Redan):** Simpler mental model. One command, one VM. Multiple sessions = multiple processes. Warm pools are harder but achievable via a lightweight background process spawned on-demand (like `ssh-agent`).

## Key Decisions

1. **TSI vs passt networking:** TSI is simpler and sufficient for our proxy model. **Decision: TSI for v1.** ✅ Confirmed by architecture above.

2. **Dynamic vs static libkrun linking:** Dynamic for v1 (easier, acceptable dependency). **Decision: Dynamic for v1, evaluate static for v1.1.**

3. **Daemon vs inline VM management:** Inline (single process). Simpler to reason about, simpler to distribute, simpler to secure. **Decision: Inline.** Warm pool via optional background helper later if boot time is a problem.

4. **Guest images:** Stock OCI images for v1. No custom base images yet. **Decision: OCI only for v1.**

5. **MITM vs CONNECT proxy:** Deferred to Section 4 (Security Model). Both have trade-offs. Need to analyze secret injection requirements in detail.

## Open Questions

1. **TSI + secret injection compatibility:** Does TSI give us enough visibility into the connection to do secret injection? TSI impersonates sockets — we need to confirm we can intercept at the right layer. If TSI is too transparent (passes connections through without inspection), we may need passt mode for the proxy to work. **Needs prototype spike.**

2. **libkrun virtio-fs performance:** What's the latency and throughput for file operations through virtio-fs on both Linux and macOS? Agent workflows are filesystem-heavy (reading source files, writing output). **Needs benchmarking.**

3. **libkrun macOS HVF stability:** microsandbox claims macOS support. How stable is it in practice? Any known issues with Apple Silicon + HVF + virtio-fs? **Needs testing.**

4. **OCI image pull:** Do we handle image pulling ourselves, or shell out to a container runtime? Options: `skopeo` / `umoci` for OCI operations, or vendor a Rust OCI client crate. **Research needed.**

5. **VM boot time budget:** Research says <200ms achievable. What's realistic for a VM with virtio-fs mounts + network proxy + OCI image? If >500ms, we need a warm pool strategy for v1. **Needs prototype spike.**
