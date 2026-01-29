# 8. Technical Risk Register

## Risk Assessment Matrix

| Likelihood | Impact | Rating |
|-----------|--------|--------|
| High | High | 🔴 Critical |
| High | Medium | 🟠 High |
| Medium | High | 🟠 High |
| Medium | Medium | 🟡 Medium |
| Low | High | 🟡 Medium |
| Low | Medium | 🟢 Low |

---

## R1: libkrun TSI Networking Insufficient for MITM Proxy

**Risk:** TSI (Transparent Socket Impersonation) may not give us enough control to intercept, terminate TLS, and inject secrets. TSI is designed to transparently map guest sockets to host sockets — it may not support interception at the right layer.

| | |
|---|---|
| Likelihood | Medium |
| Impact | High |
| Rating | 🟠 High |
| Mitigation | Prototype spike (PS-1). If TSI doesn't work, use passt/gvproxy mode with virtio-net, which gives full packet-level control. This is more complex but definitely supports MITM. |
| Kill criteria | If neither TSI nor passt mode supports reliable MITM proxying with <50ms added latency per request, reconsider the secret injection model entirely. |

## R2: virtio-fs Performance on Large Projects

**Risk:** virtio-fs adds overhead vs native filesystem. Agent workflows are filesystem-heavy (tree-walking, grep, multiple file reads/writes per tool call). If overhead is noticeable (>2x slowdown), developer experience degrades.

| | |
|---|---|
| Likelihood | Medium |
| Impact | Medium |
| Rating | 🟡 Medium |
| Mitigation | Benchmark during spike PS-2. If slow: implement `.redanignore` to exclude large directories, use read-only cache layers for unchanged files, consider 9p as alternative to virtio-fs. |
| Kill criteria | If filesystem operations are >5x slower than native for typical agent workflows (grep across 10K files, read 100 files sequentially), need a fundamentally different approach. |

## R3: Agents Don't Run Transparently in MicroVM

**Risk:** Claude Code, Codex, or other agents make assumptions about the host environment that break inside a microVM — specific filesystem paths, kernel features, `/proc` layout, hardware detection, container detection heuristics.

| | |
|---|---|
| Likelihood | High |
| Impact | Medium |
| Rating | 🟠 High |
| Mitigation | Prototype spike PS-3. Test each target agent. Build compatibility shims for common issues. Document known incompatibilities. |
| Kill criteria | If >50% of agent operations fail inside the VM and can't be fixed with environment setup or shims, Layer 1 (environment injection) is not viable as the primary approach. Pivot to MCP-only (Layer 3). |

## R4: MITM Proxy Breaks Package Managers

**Risk:** npm, pip, cargo, or git reject our ephemeral CA cert due to certificate pinning, bundled CA stores, or hardcoded CA expectations. This breaks package installation inside the VM.

| | |
|---|---|
| Likelihood | Medium |
| Impact | High |
| Rating | 🟠 High |
| Mitigation | Prototype spike PS-4. Test all major package managers with custom CA. Most respect system CA store. For those that don't: set per-tool environment variables (e.g., `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`). |
| Kill criteria | If major package managers can't be made to work with MITM, switch to CONNECT proxy + `inject_mode = "env"` for all secrets. Weaker guarantees but functional. |

## R5: libkrun macOS HVF Instability

**Risk:** libkrun on macOS (Apple Silicon, HVF) may be less stable or have different behavior than Linux KVM. Crashes, hangs, or subtle VM behavior differences.

| | |
|---|---|
| Likelihood | Medium |
| Impact | Medium |
| Rating | 🟡 Medium |
| Mitigation | Prototype spike PS-5. Stress test on macOS. Report issues upstream (Red Hat maintains libkrun). Have a fallback: macOS-only users can still use Redan with Linux VMs via Colima/Lima if native HVF is problematic. |
| Kill criteria | If macOS crashes >5% of sessions and upstream is unresponsive, drop macOS from v1 and position as Linux-first. |

## R6: Boot Time Exceeds Usable Threshold

**Risk:** VM boot + image load + network proxy setup + virtio-fs mount exceeds 500ms, making `redan exec` feel sluggish compared to running commands directly.

| | |
|---|---|
| Likelihood | Low |
| Impact | Medium |
| Rating | 🟢 Low |
| Mitigation | microsandbox achieves <200ms. We should too. Optimize: pre-extract OCI layers, minimize guest kernel, lazy-init network proxy. If still slow: implement warm pool (background pre-booted VM). |
| Kill criteria | If boot time can't get below 1 second even with warm pool, the product is not viable for interactive use. |

## R7: Competitor Feature Convergence

**Risk:** microsandbox adds secret management. Gondolin stabilizes and adds x86_64. Either makes Redan redundant.

| | |
|---|---|
| Likelihood | Medium |
| Impact | High |
| Rating | 🟠 High |
| Mitigation | Ship fast. The competitive moat is the combination: single binary + secret injection + pluggable backends + enterprise-ready. Neither competitor has signaled enterprise direction. Even if they add features, the integration and UX can differentiate. |
| Kill criteria | If a competitor ships everything Redan offers before our v1, evaluate: contribute upstream instead of competing. |

## R8: OCI Image Handling Without Docker

**Risk:** Pulling, unpacking, and managing OCI images without a Docker daemon is non-trivial. Existing Rust crates for OCI operations may be immature or buggy.

| | |
|---|---|
| Likelihood | Medium |
| Impact | Medium |
| Rating | 🟡 Medium |
| Mitigation | Evaluate `oci-distribution` and `containers-image-proxy` Rust crates. Fallback: shell out to `skopeo pull` + `umoci unpack` (both are single binaries, easy to bundle). microsandbox handles this — study their approach. |
| Kill criteria | None — this is solvable, just a question of how much effort. |

## R9: Secret Management Backend Authentication (Bootstrap)

**Risk:** Host needs credentials to authenticate to Vault/AWS/Azure to fetch agent secrets. If these bootstrap credentials are misconfigured, expired, or unavailable, the agent can't access any secrets.

| | |
|---|---|
| Likelihood | High |
| Impact | Medium |
| Rating | 🟠 High |
| Mitigation | Clear error messages when backend auth fails. `redan secret test` command for pre-flight checks. For enterprise: document SSO/OIDC flows for bootstrap. For solo devs: `env` backend has no bootstrap — it's just env vars. |
| Kill criteria | None — this is a UX problem, not a fundamental limitation. |

## R10: JS Network Stack as Attack Surface (Gondolin-specific, informational)

**Not applicable to Redan** (we use Rust, not Gondolin's JS stack). Noted for completeness: Gondolin's network stack is written in JavaScript, which introduces a larger attack surface than a Rust implementation. Our Rust proxy benefits from memory safety and smaller attack surface.

## R11: Host Process Memory Exposure

**Risk:** Real secret values live in host process memory during the session. Local privilege escalation on the host could read `/proc/<redan_pid>/mem` and extract secrets.

| | |
|---|---|
| Likelihood | Low |
| Impact | High |
| Rating | 🟡 Medium |
| Mitigation | Use `mlock()` to prevent secret pages from being swapped to disk. Use `madvise(MADV_DONTDUMP)` to exclude from core dumps. Use `zeroize` crate to clear secrets on drop. These are defense-in-depth — if the host is compromised, the attacker has bigger problems. |
| Kill criteria | None — this is a known limitation of any process-based secret handling. Document it. |

## R12: Agent Execution Model Changes

**Risk:** Claude Code, Codex, Cursor, or other agents change their execution model in ways that break VM compatibility. New sandboxing approaches, new tool execution patterns, new assumptions about the environment.

| | |
|---|---|
| Likelihood | High |
| Impact | Medium |
| Rating | 🟠 High |
| Mitigation | Track agent changelogs. Run compatibility tests in CI against latest agent versions. Layer 1 (environment injection) is the most resilient — if it runs in Linux, it runs in our VM. Layer 3 (MCP) is protocol-stable. |
| Kill criteria | None — adapt and maintain. This is ongoing product work, not a fundamental risk. |

## Risk Summary

| Rating | Count | Risks |
|--------|-------|-------|
| 🔴 Critical | 0 | — |
| 🟠 High | 6 | R1, R3, R4, R7, R9, R12 |
| 🟡 Medium | 4 | R2, R5, R8, R11 |
| 🟢 Low | 1 | R6 |

**No critical risks.** Six high risks, all addressable via prototype spikes or execution speed. The biggest existential risk is R7 (competitor convergence) — mitigated by shipping fast and focusing on the enterprise secret management angle that no competitor has.
