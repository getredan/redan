# Redan — Product Planning

**Redan** — secure, local-first execution environment for AI agents. MicroVM isolation with network-layer secret injection. Single Rust binary. No cloud required.

*redan (n.): a V-shaped fieldwork forming a salient angle toward the enemy.*

## Planning Index

| # | Section | Status | File |
|---|---------|--------|------|
| 1 | [Problem Analysis](01-problem-analysis.md) | ✅ Draft | Attack vectors, current mitigations, target invariants |
| 2 | [VM Backend & Dependencies](02-vm-backend.md) | ✅ Draft | libkrun analysis, Gondolin model adoption, platform matrix |
| 3 | [Technical Architecture (v1)](03-architecture.md) | ✅ Draft | Components, policy model, secret flow, agent integration |
| 4 | [Security Model](04-security-model.md) | ✅ Draft | Threat model, trust boundaries, secret isolation proofs |
| 4a | [Agent Identity & Secret Management](04a-secret-management.md) | ✅ Draft | Pluggable backends, lifecycle, audit, policy format |
| 5 | [MVP Scope](05-mvp-scope.md) | ✅ Draft | User stories, happy path, unknowns, non-goals |
| 6 | [Agent Integration Deep-Dive](06-agent-integration.md) | ✅ Draft | Layers 1-3, per-agent analysis, test plan |
| 7 | [v2+ Architecture](07-v2-architecture.md) | ✅ Draft | Crux-based split, mobile/desktop shells, migration |
| 8 | [Technical Risk Register](08-risk-register.md) | ✅ Draft | Risks, mitigations, kill criteria |
| 9 | [Prototype Plan](09-prototype-plan.md) | ✅ Draft | Spikes, order, success criteria |
| R1 | [Review: Codex (Skeptical Engineer)](review-codex.md) | ✅ | 13 findings, 2 Critical |
| R2 | [Review: Kimi 2.5 (Product/UX)](review-kimi.md) | ✅ | 8 sections, adoption focus |
| R3 | [Review: Sonnet 4.5 (Security Architect)](review-claude.md) | ✅ | 4 Critical, 11 High |
| R4 | [Review: Opus 4.6 (Deep Security)](review-opus.md) | ✅ | 22 findings, attack trees |
| R5 | [**Review Synthesis**](review-synthesis.md) | ✅ | Consolidated actions, risk updates |

## Architectural Decision Record

**Key divergence from initial planning prompt:** The competitive research (Feb 2026) recommends Rust + libkrun over building on Gondolin directly. This planning follows that recommendation while adopting Gondolin's network-layer secret injection model as a design pattern. See [Section 2](02-vm-backend.md) for full rationale.

## References

- [Competitive Landscape Research](../../COMPETITIVE_LANDSCAPE_RESEARCH.md) (local copy)
- [libkrun](https://github.com/containers/libkrun)
- [Gondolin](https://github.com/earendel-works/gondolin) (design inspiration)
- [microsandbox](https://github.com/zerocore-ai/microsandbox) (closest competitor)
