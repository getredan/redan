# Security Model

## Threat model

Redan assumes the guest VM may be compromised or running malicious code.
The proxy is the trust boundary. Secrets exist only in the host process
and are injected into HTTP requests at the network layer.

### What redan protects against

- **Secret exfiltration via file system**: secrets never touch the guest
  filesystem. The guest sees placeholder tokens in environment variables.
- **Secret exfiltration via unauthorized hosts**: the host allowlist
  gates injection. A request to `evil.com` carrying a GitHub placeholder
  gets the placeholder, not the token.
- **Guest DNS exfiltration**: all guest DNS queries resolve to the
  gateway IP via synthetic DNS. No guest DNS queries leave the host.
  However, the host proxy makes real DNS queries (via the system
  resolver) when connecting upstream to the hostname specified in
  TLS SNI. A guest cannot exfiltrate secrets this way (it only has
  placeholders), but it could encode other data (source code, file
  contents) in DNS labels of hostnames it connects to. The upstream
  connection will fail (no server), but the DNS query reaches the
  attacker's authoritative nameserver.
- **Unauthorized outbound connections**: default-deny networking blocks
  connections to hosts not in the allowlist. The guest can only reach
  hosts explicitly permitted via `--allow-host` or `[network] allow`
  in `redan.toml`. Secret hosts are auto-included.
- **Secret exposure in logs**: `Debug` formatting on `SecretBinding`
  prints `[REDACTED]`. Secrets are wrapped in `Zeroizing<String>`
  and overwritten on drop.

### What redan does NOT protect against

#### Response scrubbing bypasses

Scrubbing matches literal secret bytes in HTTP response bodies.
Secrets reflected in any encoded form will not be caught:

- Base64 encoding
- URL-encoding (percent-encoding)
- JSON unicode escapes (`\u0041`)
- HTML entity encoding
- Compression (gzip, brotli) -- mitigated by stripping Accept-Encoding
- Chunked Transfer-Encoding framing in responses (chunk headers can
  split a secret across chunk boundaries)

#### Chunked Transfer-Encoding

Redan rejects incoming requests with `Transfer-Encoding: chunked`
(responds with HTTP 411 Length Required). The proxy reads request
bodies using `Content-Length`; chunked encoding has no length, so
the body would be truncated.

For upstream responses, servers may use chunked encoding regardless
of the request. Chunk framing bytes embedded in the response stream
can split a secret across chunk boundaries, preventing literal
match during scrubbing. This is a documented scrubbing limitation.

Scrubbing is a safety net, not the load-bearing wall. The primary
defense is that secrets are only injected for allowed hosts.

#### Side-channel attacks

Redan does not implement constant-time operations for secret handling.

**Network timing**: `byte_replace()` scans linearly through HTTP data.
In `inject()`, the needle is the placeholder token (already known to
the guest), so timing reveals nothing about the secret value.
In `scrub()`, the needle is the secret value. A guest measuring
response arrival times could theoretically infer the secret length,
since `byte_replace()` runtime is proportional to `haystack.len() *
needle.len()`. In practice this is unexploitable: network latency
through the virtio-net socket, smoltcp TCP stack, and upstream TLS
connection adds orders of magnitude more jitter than the scan time
difference between a 20-byte and a 40-byte secret.

**Speculative execution (Spectre/Meltdown class)**: The guest runs in
a KVM virtual machine with hardware-enforced address space isolation
(EPT/NPT). There is no shared memory between the host proxy process
and the guest. Modern Linux kernels enable Spectre mitigations by
default (IBPB on context switch, IBRS, STIBP) which protect the
branch predictor state across VM boundaries. libkrun inherits these
mitigations from KVM.

For environments where speculative execution attacks are a concern
(multi-tenant, hostile workloads), ensure the host kernel has
`spectre_v2=on` and `spec_store_bypass_disable=on`. These are
default on most distributions since 2019.

**Cache timing**: No shared caches between host proxy and guest.
KVM provides hardware cache partitioning on CPUs that support it
(Intel CAT/CDP). On CPUs without cache partitioning, cross-VM
cache timing attacks are theoretically possible but require the
guest to evict and measure cache lines with microsecond precision
while the host proxy runs -- the attack window is too small for
the one-shot nature of redan's secret injection.

#### Certificate revocation

Redan's upstream TLS client (rustls 0.23) does not check certificate
revocation status by default. If an upstream server's private key is
compromised and the certificate revoked, redan will still connect and
inject secrets.

rustls supports CRL-based revocation via `ServerCertVerifierBuilder::
with_crls()`, but this requires the caller to supply CRL data. There
is no automatic CRL fetching or OCSP stapling verification.

This matches the behavior of most TLS clients in the ecosystem:
curl, reqwest, ureq, and Go's net/http all skip revocation checks
by default. Browsers handle revocation through proprietary mechanisms
(Chrome's CRLSets, Firefox's OneCRL) that are not available to
library consumers.

Mitigations:
- Use short-lived API tokens with expiry rather than long-lived keys
- Rotate secrets regularly
- Monitor upstream certificate transparency logs for mis-issuance

If CRL checking is required for your environment, redan can be extended
with a custom `ServerCertVerifier` that fetches and caches CRLs. This
is not implemented because the operational complexity (CRL fetch
failures, stale CRL handling, OCSP responder availability) outweighs
the benefit for redan's primary use case of short-lived agent sessions
with API tokens.

#### HTTP/2 and HTTP/3

Redan forces ALPN negotiation to `http/1.1` and rejects any connection
that would use HTTP/2 or HTTP/3 binary framing. This is a deliberate
security decision: the inject/scrub path parses HTTP/1.1 headers as
text. Binary framing would bypass this parsing entirely.

#### WebSocket and protocol upgrades

Redan rejects HTTP Upgrade requests (including WebSocket) with
HTTP 501. After a `101 Switching Protocols` response, the connection
switches to an opaque binary protocol that bypasses HTTP scrubbing.

#### Domain fronting

The proxy injects secrets based on TLS SNI hostname and connects
upstream to that hostname. The HTTP Host header is not validated
against the SNI. On shared CDN infrastructure (Cloudflare, AWS
CloudFront), the CDN may route based on the Host header, not SNI.
A malicious guest could set SNI to an allowed host on a shared CDN
and Host to an attacker-controlled origin, causing the CDN to
forward the request (with injected secrets) to the attacker.

Mitigations:
- Use direct API endpoints, not CDN-fronted ones, in allowed_hosts
- Avoid allowing CDN domains that host untrusted origins
- Future: optional `--strict-host` flag to reject Host/SNI mismatches
