# Oracle Review Round 3 -- Synthesis

**Date:** 2026-02-10
**Models:** Claude Opus 4.6, Claude Sonnet 4.5, Kimi K2.5
**Note:** Mistral Large 2512 was unavailable (429 rate limits). Three models completed.

Raw reviews archived at `/tmp/redan-reviews/`.

---

## Consensus Findings (2+ models agree)

### 1. Replace hand-rolled Vault JSON parser [CRITICAL]

All three models flag `extract_json_string()` / `find_nested_data()` /
`extract_vault_field()` in `provider.rs`. The parser does not handle JSON
string escapes (`\"`, `\\`, `\uXXXX`). A Vault secret containing a
double-quote character is silently truncated. This is data corruption in
the secret-fetch path.

**Fix:** Add `serde` + `serde_json`. Define typed structs for Vault KV v2
response format. Remove ~60 lines of hand-rolled JSON parsing.

### 2. Replace hand-rolled Vault HTTP client [CRITICAL]

All three flag `http_get()` in `provider.rs`. Issues:
- Status code check (`response.contains("HTTP/1.1 4")`) scans the body
- No HTTPS support (Vault token sent in cleartext)
- No redirect handling, no chunked encoding, no Content-Length validation

**Fix:** Add `ureq` (blocking HTTP client, uses rustls). Gets HTTPS for
free. Remove ~70 lines of hand-rolled HTTP.

### 3. Replace hand-rolled HTTP header parsing [HIGH]

All three flag the multiple HTTP parsers across `secret.rs` and `proxy.rs`.
Four separate functions parse HTTP headers by hand. Vulnerable to obsolete
line folding (RFC 7230 3.2.4) which could bypass Accept-Encoding stripping
or Connection:close rewriting.

**Fix:** Add `httparse`. Zero-copy, SIMD-optimized, handles all RFC 7230
edge cases. Used by hyper, actix, warp.

### 4. Add zeroize for secrets [HIGH]

All three recommend `zeroize` crate for `SecretBinding.real_value` and
Vault token. Secrets persist in heap memory after drop. Defense-in-depth
for core dumps, swap, memory forensics.

**Fix:** Add `zeroize`. Wrap secret strings in `Zeroizing<String>`.

### 5. `image_path` panics instead of returning Result [LOW]

All three note the `assert!` in a `pub` library function is not idiomatic.

**Fix:** Return `Result`, let callers decide.

### 6. DNS qd_count validation [MEDIUM]

Sonnet flags, Opus notes tangentially. Parser accepts multi-question
packets but only handles the first question. Malformed response possible.

**Fix:** Reject `qd_count != 1`.

### 7. Hostname cert caching [MEDIUM]

Opus flags directly, Sonnet notes CA modification concern. Per-connection
key generation is wasteful. 30+ keygen for same hostname during npm install.

**Fix:** `HashMap<String, Arc<rustls::ServerConfig>>` cache on `MitmCa`.

### 8. Error type inconsistency [LOW]

Sonnet and Opus note mix of `io::Error`, `Box<dyn Error>`, `String`.

**Decision:** Accept for now. Unified error type is a nice-to-have, not
blocking. Revisit when adding more providers.

---

## Unique Findings Worth Acting On

### 9. FFI panic safety (Kimi)

VM thread crosses FFI boundary into `krun_start_enter()`. Panic would
unwind across C code -- undefined behavior.

**Fix:** Wrap VM thread body with `std::panic::catch_unwind()` + abort.

### 10. CA cert validity hardcoded 2020-2030 (Kimi)

Fixed dates look odd and create unnecessarily long-lived certs.

**Fix:** Use `now()` to `now() + 1 year` (or shorter). Ephemeral per-run
anyway.

### 11. inject() replacement count is wrong (Opus)

`byte_replace()` replaces all occurrences but `count += 1` per secret, not
per replacement. Misleading audit log.

**Fix:** Return replacement count from `byte_replace()`.

### 12. `rewrite_request_headers` edge case (Opus)

When `find_header_end` returns `None`, `header_end = data.len()`, then
`data[header_end - 2..]` produces garbage.

**Fix:** Guard the `None` case -- return data as-is or reject.

### 13. Content-Length not bounds-checked (Sonnet)

`parse::<usize>()` on Content-Length without checking against max size.

**Fix:** Reject Content-Length > MAX_RESPONSE_SIZE before use. Will be
addressed naturally by httparse migration.

---

## Findings Rejected or Accepted As-Is

### Replace TLS SNI parser (Sonnet says HIGH, Opus says keep)

Opus explicitly reviewed and recommends keeping: correct, minimal (70
lines), well-tested, bounds-checked, adversarial inputs covered. The
alternatives (tls-parser, tls-client_hello-parser) add weight for no gain.
**Decision: Keep.**

### Replace DNS parser with hickory-dns (Sonnet says HIGH, Opus says keep)

Opus explicitly reviewed and recommends keeping: custom logic needed
(localhost -> 127.0.0.1, everything else -> gateway, empty for non-A),
hickory-dns is massive overkill. 135 lines vs 6.1K+ SLoC dependency.
**Decision: Keep.** Add qd_count check and total name length check.

### Spectre/side-channel mitigations (Kimi)

Theoretical. Guest is isolated in microVM with no shared memory.
Constant-time comparisons for secret handling are overkill at this stage.
**Decision: Document as out-of-scope in security model.**

### Certificate revocation CRL/OCSP (Kimi)

rustls does not do CRL/OCSP by default. Standard practice for Rust TLS.
**Decision: Document, don't fix.**

### SecretInjector trait / async provider (Sonnet)

Over-engineering for current stage. One proxy, one codepath, synchronous
startup. **Decision: Reject.**

### DNS rate limiting (Sonnet)

Guest is sandboxed. DNS resolves to gateway IP regardless of query. CPU
cost is negligible. **Decision: Reject.**

### Scrubbing overlap bug (Sonnet CRITICAL)

Sonnet misread the code. The overlap bytes are held back (not sent) until
the next chunk arrives. The overlap buffer plus next chunk are concatenated
and re-scrubbed. The implementation is correct. **Decision: Reject (false
positive).**

---

## Action Plan (Priority Order)

| # | Finding | Severity | New deps | Est. lines changed |
|---|---------|----------|----------|--------------------|
| 1 | Vault JSON parser -> serde_json | CRITICAL | serde, serde_json | -60, +30 |
| 2 | Vault HTTP client -> ureq | CRITICAL | ureq | -70, +20 |
| 3 | HTTP header parsing -> httparse | HIGH | httparse | -80, +60 |
| 4 | Add zeroize for secrets | HIGH | zeroize | +15 |
| 5 | FFI panic safety | HIGH | -- | +10 |
| 6 | DNS qd_count != 1 | MEDIUM | -- | +3 |
| 7 | Hostname cert cache | MEDIUM | -- | +25 |
| 8 | CA cert validity dates | MEDIUM | -- | +5 |
| 9 | inject() replacement count | LOW | -- | +10 |
| 10 | rewrite_request_headers guard | LOW | -- | +5 |
| 11 | image_path returns Result | LOW | -- | +10 |

Items 1-5 are pre-release blockers. Items 6-11 are improvements.
