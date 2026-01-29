# 9. Prototype Plan

## 9.1 Spike Overview

Five focused spikes, ordered by dependency and risk retirement. Each spike is a standalone Rust binary (not the final product codebase) that answers a specific question.

```
PS-1: libkrun + network interception
  ↓ (determines networking approach)
PS-2: virtio-fs performance ←── can run parallel with PS-1
  ↓
PS-3: agent transparency (depends on PS-1 + PS-2 for working VM)
  ↓
PS-4: MITM proxy + secret injection (depends on PS-1)
  ↓
PS-5: end-to-end secret flow (depends on PS-4)
```

---

## PS-1: libkrun VM Boot + Network Interception

**Question:** Can we boot a libkrun microVM, route its network traffic through our host process, and intercept TCP connections with enough visibility to implement a MITM proxy?

**What to build:**
- Rust binary that creates a libkrun VM context
- Boot a minimal Linux image (Alpine or similar)
- Configure TSI networking
- Intercept a TCP connection from guest to an external host
- Log the connection details (destination host, port)
- If TSI doesn't allow interception: try passt/gvproxy mode
- Measure boot time (target: <300ms)

**Success criteria:**
- VM boots successfully on Linux (x86_64) and macOS (aarch64)
- Guest can make a TCP connection that routes through host process
- Host process can see destination host and port before forwarding
- Boot time <300ms on both platforms

**Failure criteria:**
- Cannot intercept connections in any networking mode → MITM approach needs rethink
- Boot time >1s → warm pool required for MVP

**Expected time:** 3-5 days

**Risks retired:** R1 (TSI networking), R5 (macOS stability), R6 (boot time)

---

## PS-2: virtio-fs Performance

**Question:** What's the filesystem performance overhead of virtio-fs for typical agent workflows?

**What to build:**
- Use the VM from PS-1 (or a parallel minimal setup)
- Mount a real-world project directory (~10K-50K files) via virtio-fs
- Benchmark inside the VM:
  - `find . -name "*.py" | wc -l` (tree walk)
  - `grep -r "import" --include="*.py" | wc -l` (content search)
  - Sequential read of 100 files
  - Write 100 files
  - `git status` (exercises filesystem metadata heavily)
- Compare to same operations on host natively

**Success criteria:**
- Overhead <2x for all operations
- `git status` completes in reasonable time (<5s for 10K file repo)
- No errors or data corruption

**Failure criteria:**
- Overhead >5x for common operations → need alternative (9p, copy-in model)
- Data corruption or consistency issues → blocker

**Expected time:** 2-3 days (can run parallel with PS-1 if using microsandbox's existing VM setup for initial testing)

**Risks retired:** R2 (virtio-fs performance)

---

## PS-3: Agent Transparency

**Question:** Can Claude Code, Codex, and a basic shell run transparently inside a libkrun microVM?

**What to build:**
- Use the VM from PS-1/PS-2 with a `node:22` image (for Claude Code) and stock `ubuntu:24.04`
- Install Claude Code inside the VM
- Run Claude Code with a simple task: "Create a Python file that prints hello world and run it"
- Document everything that works and everything that breaks
- Repeat with Codex (in non-sandboxed mode)
- Repeat with interactive bash (developer manual testing)

**Observe:**
- Does the agent's terminal I/O work correctly (colors, cursor, interactive prompts)?
- Does the agent detect it's in a VM? Does it behave differently?
- Do `git` operations work with virtio-fs?
- What errors or warnings appear?
- What files does the agent try to access outside `/workspace`?

**Success criteria:**
- Claude Code completes a basic coding task without errors
- Interactive bash session works (colors, tab completion, vim/nano)
- git operations work on the mounted project directory

**Failure criteria:**
- Claude Code can't start or crashes inside VM → need compatibility investigation
- Terminal I/O is broken → need PTY configuration work
- >50% of typical agent operations fail → Layer 1 may not be viable as primary

**Expected time:** 3-4 days

**Risks retired:** R3 (agent transparency), R12 (agent execution model)

**Dependencies:** PS-1 (working VM), PS-2 (working filesystem)

---

## PS-4: MITM Proxy with Secret Injection

**Question:** Can we build a Rust MITM proxy that terminates TLS from the guest, injects secrets into HTTP headers, and forwards to the real destination — and does this work with npm, pip, cargo, and git?

**What to build:**
- Rust binary using `tokio` + `rustls` + `rcgen`
- Generate ephemeral CA on startup
- Accept TCP connections from guest (via TSI or passt)
- For TLS connections: extract SNI, generate leaf cert, terminate guest TLS
- Parse HTTP request, scan for placeholder tokens in headers
- Replace placeholder with real value if destination is in allowed hosts
- Open real TLS connection to destination, forward modified request
- Stream response back
- Install CA cert in guest trust store
- Test with: `curl`, `npm install`, `pip install`, `cargo build`, `git clone`

**Success criteria:**
- MITM proxy works for HTTPS traffic
- Placeholder in `Authorization` header correctly replaced with real value
- npm, pip, cargo, git all work through the proxy (accept the ephemeral CA)
- Latency overhead <100ms per request

**Failure criteria:**
- Major package managers reject ephemeral CA despite `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, etc. → fall back to CONNECT proxy + env injection
- Latency >500ms per request → proxy architecture needs optimization
- HTTP/2 or streaming responses break → need more sophisticated proxy

**Expected time:** 5-7 days (most complex spike)

**Risks retired:** R1 (network interception for MITM), R4 (CA compatibility)

**Dependencies:** PS-1 (network routing from VM through host)

---

## PS-5: End-to-End Secret Flow

**Question:** Can we demonstrate the full secret lifecycle — retrieve from a backend, inject via MITM, verify the agent inside the VM can use the API without seeing the real secret?

**What to build:**
- Extend PS-4 with a secret backend integration
- Start simple: `env` backend (read from host environment)
- Configure: `GITHUB_TOKEN` from env, inject for `api.github.com`
- Inside VM: run `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user`
- Verify:
  - `echo $GITHUB_TOKEN` inside VM prints placeholder (not real token)
  - The curl request succeeds (real token injected by proxy)
  - Audit log shows: secret configured, secret injected, destination host
- Then add one enterprise backend: HashiCorp Vault (dev mode)
  - Run Vault in dev mode on host
  - Store a test secret
  - Configure Redan to read from Vault
  - Verify same flow

**Success criteria:**
- env backend: secret injected, API call succeeds, guest never sees real value
- Vault backend: same, with Vault authentication working
- Audit log captures all events
- Secret zeroized from host memory on session teardown (verify with memory dump)

**Failure criteria:**
- Secret injection doesn't work reliably → architecture needs rethink
- Vault integration is too complex for the benefit → defer enterprise backends

**Expected time:** 3-4 days

**Risks retired:** R9 (backend authentication), validates entire secret injection model

**Dependencies:** PS-4 (MITM proxy)

---

## 9.2 Spike Schedule

```
Week 1:
├── PS-1: libkrun VM boot + networking (3-5 days)
└── PS-2: virtio-fs performance (2-3 days, parallel)

Week 2:
├── PS-3: Agent transparency (3-4 days, after PS-1/PS-2)
└── PS-4: MITM proxy start (begins mid-week after PS-1 networking confirmed)

Week 3:
├── PS-4: MITM proxy complete (continued)
└── PS-5: End-to-end secret flow (3-4 days, after PS-4)
```

**Total: ~3 weeks** to retire all major technical risks.

After spikes: review findings, update architecture (Section 3) and risk register (Section 8), then begin v1 implementation.

## 9.3 Spike Outputs

Each spike produces:
1. **Working code** in `spikes/ps-N/` (disposable, not production code)
2. **Findings document** in `docs/spikes/ps-N-findings.md`:
   - What worked
   - What didn't
   - Performance measurements
   - Architecture implications
   - Updated risk assessment
3. **Go/no-go recommendation** for the approach it validates

## Key Decisions

1. **Spikes are disposable code.** Don't architect them. Get answers fast. ✅

2. **PS-1 is the gating spike.** Everything else depends on being able to boot a VM and route network traffic. If PS-1 fails, stop and reassess. ✅

3. **PS-4 (MITM) is the highest-effort spike.** Budget extra time. If it partially fails (some tools don't work with MITM), we have a fallback (CONNECT proxy + env injection). ✅

4. **Test on both Linux and macOS from spike 1.** Don't defer macOS to later — it's a primary platform. Discover issues early. ✅

## Open Questions

1. **Spike environment:** Do we test on a physical macOS machine and a Linux VM? Or use CI for Linux testing? Physical machines give more accurate perf numbers.

2. **Which Vault auth method for PS-5?** Token auth is simplest for dev mode. AppRole is more realistic for production. Recommendation: token for the spike, AppRole for v1.

3. **Should spikes use the same Cargo workspace as the eventual product?** Recommendation: no. Separate directory, separate crate. Spikes are throwaway. Don't let spike code infect the product.
