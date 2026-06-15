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

Redan rejects requests where the Host header does not match the TLS
SNI hostname (HTTP 421 Misdirected Request). This blocks domain
fronting in most cases. Residual risk: if the allowed host itself
routes internally based on other headers or path components.

## Configuration trust

A `redan.toml` in the working directory is not like the guest: redan's host
process reads it, before the VM boots, with your own authority. It can read host
environment variables and Vault (`env://` / `vault://` secrets), mount host
paths into the guest, set a host `rootfs`, forward host-local ports, and write
host log files. So it is a second trust boundary. A hostile `redan.toml` in a
repo you cloned could exfiltrate your credentials or expose host files, none of
which the VM sandbox would stop, because the config runs before the sandbox.

Redan gates this. A config that stays within a safe subset (`image`, `command`,
guest `env`, `[network] allow`, and a project-workspace mount) needs no trust,
since none of it touches host authority. A config that reaches for any of the
above must be trusted first:

- Interactively, redan prints exactly what the config would be allowed to do and
  asks before acting on it.
- Out of band, `redan trust` records the config (and `redan untrust` removes it).
- Without a terminal and without prior trust (CI, detached runs), redan does not
  use the config and tells you to run `redan trust`. It is never auto-trusted.

Trust is keyed by a SHA-256 of the file's contents, so editing the file (for
example, a compromised agent rewriting the mounted `redan.toml`) invalidates
trust until you review and trust it again. The safe subset is enforced by
exhaustively classifying every config field, so a field added in a future
release cannot silently load without trust.

### What configuration trust does NOT protect against

Trust is a machine-local consent record, not a cryptographic signature. The
store (`~/.local/state/redan/trust.json`, mode 0600) is protected only by
filesystem permissions. It defends against two things: the sandboxed guest
agent, which can edit the mounted `redan.toml` but cannot reach the host-side
store (and any edit changes the content hash, so trust drops); and accidentally
acting on a config you never reviewed.

It does **not** defend against a process already running as your user on the
host. That process can rewrite the store, re-trust a malicious file, or read
your secrets and `~/.ssh` directly without going near redan; it has won by other
means, and no trust record would stop it. This is the same posture as direnv,
mise, and git's `safe.directory`. Signing the config would defend a
*legitimately signed* file against tampering, but redan's actual risk is a
config you have not reviewed, which a signature you happen to trust does not
address.

#### Staged credentials in the guest

When redan stages an agent's credential files (Claude's `.credentials.json`,
Pi's `auth.json`) into the guest rootfs, those are real secrets written to the
guest filesystem as plaintext. This is the one exception to "secrets never touch
the guest": a deliberate fallback for agents that need their own credential
files. The network-injected path (`ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`)
keeps the secret host-side and is preferred.

#### Literal secrets on disk in detached mode

A detached session (`--detach`) serializes its resolved config to
`daemon_config.json` (mode 0600, in a 0700 directory) until the daemon reads and
unlinks it. A literal `--secret VALUE:host` therefore touches disk briefly;
`env://` and `vault://` references do not, since only the reference is written.
