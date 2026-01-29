# PS-4: Synthetic DNS for MITM Proxy

## Status: COMPLETE

## Checklist
- [x] Document DNS design in findings
- [x] Implement DNS parser (extract QNAME from query)
- [x] Implement DNS response builder (synthetic A record)
- [x] Add UDP socket to smoltcp event loop
- [x] Update guest config: /etc/resolv.conf instead of /etc/hosts
- [x] Remove /etc/hosts hack from guest command
- [x] Test: guest resolves arbitrary hostnames
- [x] Test: full HTTPS flow with DNS resolution (no /etc/hosts)
- [x] Test: secret injection still works end-to-end
- [x] Commit and push
- [x] Write PS-4 DNS findings doc

## Commits
- `03f5c14` Add synthetic DNS resolver (redan)
- `95eadfd` Update PS-4/PS-5 findings: synthetic DNS documented (redan-ai-slop)

## Key files
- `spikes/ps4-mitm/src/dns.rs` -- DNS parser + response builder + 5 unit tests
- `spikes/ps4-mitm/src/main.rs` -- UDP socket on port 53, `process_dns()` in poll loop
- `redan-ai-slop/docs/spikes/ps4-ps5-findings.md` -- findings doc updated
