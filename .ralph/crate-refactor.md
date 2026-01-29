# Refactor: Spike Code -> Production Crate

## Status: COMPLETE

## Checklist
- [x] Create Cargo.toml at repo root with all dependencies (latest versions)
- [x] Create mise.toml with dev tasks
- [x] Move ca.rs (updated for rcgen 0.14 Issuer API)
- [x] Move dns.rs (5 unit tests)
- [x] Move net.rs (VirtioNetDevice)
- [x] Create vm.rs (libkrun FFI + VM boot)
- [x] Create secret.rs (injection + scrubbing, 5 unit tests)
- [x] Create proxy.rs (smoltcp event loop + connection handling)
- [x] Create tls.rs (SNI extraction + upstream relay, 4 unit tests)
- [x] Create lib.rs (module declarations)
- [x] Create main.rs (thin CLI with clap)
- [x] Create tests/integration.rs (2 tests: DNS + end-to-end)
- [x] cargo check passes
- [x] cargo test passes (14 unit tests)
- [x] Integration tests pass (DNS + secret injection)
- [x] cargo clippy clean
- [x] mise check passes (format + lint + test)
- [x] Commit and push

## Dependency versions (Feb 2026)
smoltcp 0.12.0, rustls 0.23.36, rcgen 0.14.7, webpki-roots 1.0.6,
clap 4.5.57, serde 1.0.228, toml 0.9.11, env_logger 0.11.8, log 0.4.29
