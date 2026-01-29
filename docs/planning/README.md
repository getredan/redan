# Redan — Product Planning

**Redan** — secure, local-first execution environment for AI agents. MicroVM isolation with network-layer secret injection. Single Rust binary. No cloud required.

*redan (n.): a V-shaped fieldwork forming a salient angle toward the enemy.*

## Status: Planning Complete — Ready for Prototype Spikes

All sections drafted, oracle-reviewed by 4 models, findings integrated. Next step: PS-1 (libkrun VM boot + network interception).

## Planning Index

| # | Section | Status | Summary |
|---|---------|--------|---------|
| 1 | [Problem Analysis](01-problem-analysis.md) | ✅ Final | 6 attack vectors, 8 invariants (restated with caveats), agent gap analysis |
| 2 | [VM Backend & Dependencies](02-vm-backend.md) | ✅ Final | libkrun, symlink prevention, IPv6 blocking, protocol table |
| 3 | [Technical Architecture (v1)](03-architecture.md) | ✅ Final | Zero-config, minimal TOML, doctor, error UX, executable file protection |
| 4 | [Security Model](04-security-model.md) | ✅ Final | MITM proxy, response scrubbing, no --no-sandbox, Host validation |
| 4a | [Secret Management](04a-secret-management.md) | ✅ Final | env as separate tier, concrete bootstrap flows, pluggable backends |
| 5 | [MVP Scope](05-mvp-scope.md) | ✅ Final | 9 must-have stories, zero-config, one agent, one backend, honest messaging |
| 6 | [Agent Integration](06-agent-integration.md) | ✅ Final | Layer 1 (env injection) primary, MCP v1.1, Pi v1.1 |
| 7 | [v2+ Architecture](07-v2-architecture.md) | ✅ Draft | Crux Core/Shell, Tauri desktop, mobile monitoring |
| 8 | [Risk Register](08-risk-register.md) | ✅ Final | 1 critical (git hooks), 8 high, 5 medium. 3 mitigated. |
| 9 | [Prototype Plan](09-prototype-plan.md) | ✅ Final | 6 spikes, 4 weeks, adversarial test suite, decision gates |

## Oracle Reviews

| Reviewer | Focus | File |
|----------|-------|------|
| Codex (o3) | Skeptical engineer: scope, DX, competitive reality | [review-codex.md](review-codex.md) |
| Kimi 2.5 | Product/UX: adoption funnel, config complexity, env trap | [review-kimi.md](review-kimi.md) |
| Sonnet 4.5 | Security architect: threat gaps, MITM risks, env injection | [review-claude.md](review-claude.md) |
| Opus 4.6 | Deep security: attack trees, invariant violations, git hooks | [review-opus.md](review-opus.md) |
| **Synthesis** | Consolidated findings, actions, risk updates | [review-synthesis.md](review-synthesis.md) |

## Key Architectural Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| VM backend | libkrun (not Gondolin) | Library API, cross-platform, stable, Rust |
| Secret model | Network-layer injection (Gondolin pattern) | Secrets never in VM (for header/query mode) |
| Distribution | Single Rust binary | Zero deps, cargo-dist |
| Config | Optional TOML + zero-config auto-detection | Low friction, progressive disclosure |
| Audit | Host-only JSONL (tamper-proof from guest) | Agent can't modify audit trail |
| Escape hatches | --allow-all-hosts (logged), NO --no-sandbox | Can't fully disable security |
| License | BSD-3-Clause (open core) | Tailscale/Sentry model |
| MVP backends | env, Vault, AWS SM | Three backends cover most users |
| Enterprise | Separate repo (BSL-1.1) | Policy server, remote audit, compliance |

## Repository Structure

| Repo | License | Purpose |
|------|---------|---------|
| **redan** (this repo) | BSD-3-Clause | CLI, VM, proxy, all secret backends, local audit |
| **redan-enterprise** | BSL-1.1 | Policy server, remote audit, HMAC signing, org enforcement |

See [redan-enterprise planning](../../../redan-enterprise/docs/planning/) for enterprise specs.

## References

- [Competitive Landscape Research](../COMPETITIVE_LANDSCAPE_RESEARCH.md)
- [libkrun](https://github.com/containers/libkrun)
- [Gondolin](https://github.com/earendel-works/gondolin) (design inspiration)
- [microsandbox](https://github.com/zerocore-ai/microsandbox) (closest competitor)
