# 8. Technical Risk Register

*Updated with oracle review findings. 8 new risks added (R13–R20). R6 revised to High.*

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

## Original Risks (updated)

### R1: TSI Networking Insufficient for MITM Proxy
| | |
|---|---|
| Rating | 🟠 High |
| Mitigation | PS-1 is do-or-die. If TSI doesn't work, use passt/gvproxy mode (full packet control). |
| Kill criteria | If neither TSI nor passt supports reliable MITM with <50ms added latency. |
| Validated by | PS-1 |

### R2: virtio-fs Performance on Large Projects
| | |
|---|---|
| Rating | 🟡 Medium |
| Mitigation | PS-2 benchmarking. If slow: `.redanignore`, read-only cache layers, 9p alternative. |
| Kill criteria | >5x slowdown for typical agent workflows (grep 10K files, sequential reads). |
| Validated by | PS-2 |

### R3: Agents Don't Run Transparently in MicroVM
| | |
|---|---|
| Rating | 🟠 High |
| Mitigation | PS-3: test Claude Code, Codex, bash. Build shims for common issues. |
| Kill criteria | >50% of agent operations fail and can't be shimmed → pivot to MCP-only (Layer 3). |
| Validated by | PS-3 |

### R4: MITM Proxy Breaks Package Managers
| | |
|---|---|
| Rating | 🟠 High |
| Mitigation | PS-4: test npm, pip, cargo, git with ephemeral CA. Set `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`. |
| Kill criteria | Major package managers can't work with MITM → fall back to CONNECT proxy + env injection. |
| Validated by | PS-4 |

### R5: libkrun macOS HVF Instability
| | |
|---|---|
| Rating | 🟡 Medium |
| Mitigation | PS-1 stress test on macOS. Report upstream. Fallback: Linux-only MVP. |
| Kill criteria | macOS crashes >5% of sessions and upstream unresponsive → drop macOS from MVP. |
| Validated by | PS-1 |

### R6: Boot Time Exceeds Usable Threshold *(revised from 🟢 to 🟠)*
| | |
|---|---|
| Rating | 🟠 High |
| Rationale for upgrade | Sonnet review: real-world estimate 500-800ms cold start including OCI layer extraction, proxy init, secret backend auth, guest kernel boot. Original 🟢 was optimistic. |
| Mitigation | Target <500ms. If >500ms: implement warm pool for v1.0, not deferred to v1.1. |
| Kill criteria | >1s even with warm pool → product not viable for interactive use. |
| Validated by | PS-1 |

### R7: Competitor Feature Convergence
| | |
|---|---|
| Rating | 🟠 High |
| Mitigation | Ship fast. Focus on enterprise secret management + single binary as differentiators. Codex review: "gap may be real but pain may not be" — validate with user feedback early. |
| Kill criteria | Competitor ships everything Redan offers before v1 → evaluate contributing upstream. |

### R8: OCI Image Handling Without Docker
| | |
|---|---|
| Rating | 🟡 Medium |
| Mitigation | Evaluate Rust OCI crates. Fallback: bundle `skopeo` + `umoci`. Study microsandbox's approach. |
| Kill criteria | None — solvable, question of effort. |
| Validated by | PS-1 (OCI evaluation) |

### R9: Secret Management Backend Authentication (Bootstrap)
| | |
|---|---|
| Rating | 🟠 High |
| Mitigation | Clear error messages. `redan secret test` for pre-flight. Concrete bootstrap flows documented (Section 4a.4). For MVP: env backend has no bootstrap. |
| Kill criteria | None — UX problem, not fundamental. |

### R10: (Informational) JS Network Stack as Attack Surface
Not applicable to Redan (Rust proxy, not Gondolin's JS stack).

### R11: Host Process Memory Exposure
| | |
|---|---|
| Rating | 🟡 Medium |
| Mitigation | `mlock()`, `madvise(MADV_DONTDUMP)`, `zeroize` crate. Defense-in-depth — if host is compromised, attacker has bigger problems. |
| Kill criteria | None — inherent to any process-based secret handling. Document it. |

### R12: Agent Execution Model Changes
| | |
|---|---|
| Rating | 🟠 High |
| Mitigation | Track changelogs. CI compat tests against latest agent versions. Layer 1 is most resilient. |
| Kill criteria | None — ongoing product work. |

---

## New Risks (from oracle reviews)

### R13: Git Hooks Persistence Attack *(Opus Finding 2)*
| | |
|---|---|
| Rating | 🔴 Critical |
| Description | Compromised agent writes malicious `.git/hooks/pre-commit` → VM tears down → developer runs `git commit` → hook executes on host with developer's full identity → credential exfiltration outside Redan. |
| Extends to | `.github/workflows/`, `.vscode/tasks.json`, `Makefile`, `.husky/`, `package.json` scripts. |
| Mitigation | Snapshot executable files at session start, diff at teardown, warn developer (Section 3.6.1). v1.1: mount `.git/hooks/` read-only. |
| Kill criteria | None — mitigated by detection. Cannot fully prevent without breaking legitimate hook creation. |

### R14: Symlink Traversal via virtio-fs *(Opus Finding 1)*
| | |
|---|---|
| Rating | 🟠 High |
| Description | Pre-existing symlinks in project directory point to host paths outside mount (e.g., `node_modules/` symlink → `~/`). If virtiofsd follows them, agent reads host files. |
| Mitigation | Configure virtiofsd in chroot mode. Adversarial test in PS-2. (Section 2.2.1) |
| Kill criteria | If libkrun's virtio-fs doesn't support symlink restriction → need alternative mount strategy. |
| Validated by | PS-2 |

### R15: Audit Log in Agent-Writable Directory *(Opus Finding 8)*
| | |
|---|---|
| Rating | 🟠 High *(mitigated — moved to host-only path)* |
| Description | Original design stored audit at `.redan/audit.jsonl` (inside project dir mounted in VM). Agent could tamper with own audit trail. |
| Status | **FIXED.** Audit log moved to `$XDG_STATE_HOME/redan/sessions/<id>/audit.jsonl` (Section 3.7). Agent has no access. |

### R16: OCI Image Supply Chain *(Opus Finding 19)*
| | |
|---|---|
| Rating | 🟠 High |
| Description | Stock OCI images from public registries could be compromised (registry takeover, typosquatting). Compromised image = compromised guest from the start. |
| Mitigation | v1: document image integrity as user responsibility. Recommend digest pinning (`python:3.12@sha256:...`). v1.1: cosign/sigstore verification. |
| Kill criteria | None — standard supply chain risk. |

### R17: Raw IP Connections Bypass Hostname Policy *(Opus Finding 3)*
| | |
|---|---|
| Rating | 🟠 High *(mitigated — raw IPs now blocked)* |
| Description | Guest connects by IP address, bypassing hostname-based allowlist. |
| Status | **FIXED.** All raw IP connections blocked by default (Section 3.3 network policy semantics). |

### R18: Response Reflection Exposes Secrets *(All security oracles)*
| | |
|---|---|
| Rating | 🟡 Medium |
| Description | Authorized API echoes injected secret in response body → agent reads → writes to project file → persists on host disk. |
| Mitigation | Response header scrubbing (v1). Body scrubbing deferred (v1.1). Documented residual risk: secrets may appear in response bodies. Combined with executable file warnings and network policy. |
| Kill criteria | None — defense-in-depth. |

### R19: Domain Fronting via Allowed Hosts *(Opus Finding 4)*
| | |
|---|---|
| Rating | 🟡 Medium |
| Description | Agent connects to allowed host but sends HTTP `Host: evil.com` header → CDN routes to attacker's backend. |
| Mitigation | **FIXED.** Host header validation: proxy verifies `Host`/`:authority` matches TCP destination (Section 3.3). |

### R20: HTTP Request Smuggling Through Proxy *(Opus Finding 7)*
| | |
|---|---|
| Rating | 🟡 Medium |
| Description | CL/TE desync between proxy and destination could allow crafted requests to bypass injection/policy. |
| Mitigation | Use `hyper` for all HTTP parsing (well-tested, Rust). No custom parsers. Run OWASP smuggling test suite in CI. |
| Kill criteria | None — standard proxy hardening. |

---

## Risk Summary

| Rating | Count | Risks |
|--------|-------|-------|
| 🔴 Critical | 1 | R13 (git hooks persistence) |
| 🟠 High | 8 | R1, R3, R4, R6, R7, R9, R12, R16 |
| 🟠 High (mitigated) | 3 | R14 (symlinks), R15 (audit log), R17 (raw IP) |
| 🟡 Medium | 5 | R2, R5, R8, R11, R18, R19, R20 |
| 🟢 Low | 0 | — |

**One critical risk (R13).** Mitigated by detection/warning — the architecture can't prevent all project file writes without breaking legitimate agent workflows. Six high risks requiring spike validation (R1, R3, R4, R6). Three high risks already mitigated by architectural changes from oracle review (R14, R15, R17).
