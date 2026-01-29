# Integrate Oracle Findings into Cohesive Planning

Incorporate all oracle review findings into the planning documents. Resolve disagreements, update architecture, fix invariants, revise scope, improve DX. Produce a final, coherent set of planning docs that address every valid concern.

## Goals
- Update all 9 planning sections with oracle findings
- Resolve oracle disagreements (escalate only true impasses)
- Restate invariants honestly
- Tighten MVP scope per Codex/Kimi feedback
- Add architectural mitigations for critical findings (git hooks, audit log, IP blocking, symlinks)
- Improve DX (zero-config, minimal init, error messages, doctor command)
- Revise risk register with new risks from oracles
- Revise prototype plan (4 weeks, expanded spikes, new PS-6)
- Final coherence pass: no contradictions between sections

## Checklist

### Phase 1: Critical Architectural Fixes
- [x] 1. Audit log → host-only `$XDG_STATE_HOME`, expanded schema, `redan audit` CLI
- [x] 2. Git hooks protection: 3.6.1 snapshot/diff/warn, monitored paths
- [x] 3. Raw IP blocked, Host header validation, full IPv4+IPv6 blocked ranges
- [x] 4. virtio-fs symlink traversal: added 2.2.1 with chroot mode, adversarial test
- [x] 5. Host header validation: added inline with item 3
- [x] 6. Removed --no-sandbox, documented rationale
- [x] 7. Response header scrubbing: exact match headers, bodies deferred

### Phase 2: Invariant & Security Honesty
- [x] 8. Invariants restated: I-3, I-5 with caveats; I-7, I-8 rewritten for honesty
- [x] 9. env injection: explicit weaker tier, warning in config, distinct audit logging
- [x] 10. Lambda comparison: "same class, not same posture", detailed differences
- [x] 11. Bootstrap flows: concrete per-backend (Vault, AWS, 1Password, env)

### Phase 3: DX & Scope Improvements
- [ ] 12. Update 05-mvp-scope.md: tighten MVP scope per synthesis (one agent, one backend, conditional macOS)
- [ ] 13. Update 03-architecture.md: add zero-config mode (auto-detect from project files)
- [ ] 14. Update 03-architecture.md: simplify redan.toml default template (6-10 lines)
- [ ] 15. Update 03-architecture.md: design `redan doctor` command
- [ ] 16. Update 03-architecture.md: design actionable error messages for common failures

### Phase 4: Risk & Prototype Updates
- [ ] 17. Update 08-risk-register.md: add R13-R20 from synthesis, revise R6 to High
- [ ] 18. Update 09-prototype-plan.md: expand PS-1, PS-2, PS-4, PS-5; add PS-6 adversarial suite; 4-week schedule
- [ ] 19. Update 02-vm-backend.md: add IPv6 blocking (link-local, unique-local, multicast)

### Phase 5: Coherence Pass
- [ ] 20. Cross-reference all sections: no contradictions, no stale text, consistent terminology
- [ ] 21. Update README.md with final status

## Verification
- Each updated file: note what changed and why
- Cross-check: invariants table in 01 matches 04's threat model
- Cross-check: MVP scope in 05 matches architecture in 03
- Cross-check: risk register in 08 matches prototype plan in 09

## Notes
- Disagreements resolved in synthesis: use those decisions unless truly stuck
- Escalate to Chris only if a decision materially changes the product direction
