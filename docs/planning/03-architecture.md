# 3. Technical Architecture (v1: CLI)

## 3.1 Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        redan (single binary)                        │
│                                                                     │
│  ┌───────────────┐                                                  │
│  │   CLI (clap)  │  redan exec, redan policy, redan secret, ...    │
│  └───────┬───────┘                                                  │
│          │                                                          │
│  ┌───────┴───────────────────────────────────────────────────────┐  │
│  │                      Session Manager                          │  │
│  │  Creates/manages VM sessions. Owns lifecycle:                 │  │
│  │  configure → boot → attach I/O → run → teardown               │  │
│  └───────┬──────────────┬──────────────┬────────────────────────┘  │
│          │              │              │                            │
│  ┌───────┴───────┐ ┌───┴──────┐ ┌─────┴────────┐                  │
│  │  VM Manager   │ │ Network  │ │   Secret     │                  │
│  │  (libkrun)    │ │ Proxy    │ │   Manager    │                  │
│  │               │ │ (tokio)  │ │  (pluggable) │                  │
│  │ - Create ctx  │ │          │ │              │                  │
│  │ - Set config  │ │ - Host   │ │ - Backends:  │                  │
│  │ - Mount vfs   │ │   allow  │ │   env, vault │                  │
│  │ - Boot/stop   │ │ - Secret │ │   aws, 1pw   │                  │
│  │ - I/O attach  │ │   inject │ │ - Retrieve   │                  │
│  └───────────────┘ │ - Audit  │ │ - Cache      │                  │
│                    │   log    │ │ - Rotate     │                  │
│  ┌─────────────┐   └──────────┘ └──────────────┘                  │
│  │   Policy    │                                                   │
│  │   Engine    │  Evaluates rules from redan.toml:                 │
│  │             │  - network allowlist                              │
│  │             │  - secret → host mapping                         │
│  │             │  - filesystem mounts                             │
│  │             │  - resource limits                               │
│  └─────────────┘                                                   │
│                                                                     │
│  ┌─────────────┐                                                   │
│  │ Audit Log   │  Structured JSONL to host-only path (not in VM)   │
│  └─────────────┘                                                   │
└─────────────────────────────────────────────────────────────────────┘
          │ virtio-vsock (TSI)     │ virtio-fs
          │ network traffic        │ project files
          ▼                        ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Guest microVM                                │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │  Agent process (Claude Code, Codex, shell, whatever)       │     │
│  │                                                            │     │
│  │  Sees:                                                     │     │
│  │  - /workspace (project files via virtio-fs)                │     │
│  │  - Standard Linux filesystem (from OCI image)              │     │
│  │  - Environment variables with placeholder secrets          │     │
│  │  - Network that routes through host proxy                  │     │
│  │                                                            │     │
│  │  Does NOT see:                                             │     │
│  │  - Host filesystem (no ~/.ssh, ~/.aws, etc.)               │     │
│  │  - Real secret values (only placeholders)                  │     │
│  │  - Hosts not on the allowlist                              │     │
│  └────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────┘
```

## 3.2 CLI Design

```
redan exec [OPTIONS] [--] <COMMAND>
redan exec -- claude                        # zero-config: auto-detect project, boot VM
redan exec --image python:3.12 -- python script.py
redan exec --allow-host api.example.com -- bash
redan exec --policy ./redan.toml -- claude

redan init                         # interactive setup wizard → minimal redan.toml
redan doctor                       # check prerequisites (KVM/HVF, libkrun, etc.)

redan secret list                  # list configured secrets (names only, never values)
redan secret test                  # verify secret backends are reachable

redan image pull <image>           # pre-pull OCI image for faster boot
redan image list                   # list cached images

redan audit show [session_id]      # show audit log (latest or specific session)
redan audit tail                   # stream current session's audit log
```

**Design principles:**
- `redan exec` works with zero config. Everything else is optional.
- Policy file adds precision. CLI flags add overrides. Neither is required.
- Interactive by default — stdin/stdout/stderr attached to guest process.
- Exit code from guest process propagated to host.

### 3.2.1 Zero-Config Mode (Kimi review)

When no `redan.toml` exists, `redan exec` auto-detects the project type and applies sensible defaults:

| Detection signal | Image | Auto-allowed hosts |
|-----------------|-------|-------------------|
| `package.json` | `node:22` | `registry.npmjs.org`, `nodejs.org` |
| `requirements.txt` / `pyproject.toml` | `python:3.12` | `pypi.org`, `files.pythonhosted.org` |
| `Cargo.toml` | `rust:latest` | `crates.io`, `static.crates.io` |
| `go.mod` | `golang:latest` | `proxy.golang.org`, `sum.golang.org` |
| `.git/config` with github remote | (from above) | `github.com`, `api.github.com` |
| `.git/config` with gitlab remote | (from above) | `gitlab.com` |
| None of the above | `ubuntu:24.04` | (none — fully isolated) |

**Behavior:**
```
redan exec -- bash
# redan: no redan.toml found
# redan: detected Node.js project (package.json)
# redan: auto-allowing: registry.npmjs.org, github.com
# redan: image: node:22 (auto-detected)
# redan: no secrets configured
# redan: booting... 210ms
```

Auto-detection is additive to default-deny. Only well-known package registries and code hosts are added. The developer can refine with `redan init` or a `redan.toml`.

### 3.2.2 `redan doctor`

Prerequisite checker. Run before first use or when troubleshooting.

```
redan doctor
# ✓ redan 0.1.0
# ✓ libkrun 1.6.0 (/usr/lib/libkrun.so)
# ✓ KVM available (/dev/kvm, user in kvm group)
# ✓ OCI tools available (skopeo 1.14.0)
# ✓ Ready to use
```

**Error cases:**

```
redan doctor
# ✓ redan 0.1.0
# ✗ libkrun not found
#   Install: sudo dnf install libkrun-devel  (Fedora)
#            brew install libkrun            (macOS)
#            See https://redan.dev/install
# ✗ KVM not available
#   Linux: sudo modprobe kvm && sudo usermod -aG kvm $USER
#          Then log out and back in.
#   macOS: KVM not used. HVF should be available automatically.
#          If this persists, check System Settings → Privacy & Security.
```

### 3.2.3 Error Messages (Kimi review)

All Redan errors follow a pattern: **what happened → why → how to fix.**

**Blocked host:**
```
redan: ✗ blocked: api.npmjs.org:443 (not in allowlist)

  The agent tried to reach api.npmjs.org which isn't allowed.

  Quick fix (this session only):
    redan exec --allow-host api.npmjs.org -- claude

  Permanent fix (add to redan.toml):
    [network]
    allow = ["api.npmjs.org"]
```

**Secret backend unreachable:**
```
redan: ✗ Vault unreachable: https://vault.company.com (timeout 5s)

  redan.toml configures Vault for STAGING_DB_PASSWORD,
  but the server didn't respond.

  Common fixes:
    1. Connect to VPN
    2. Check: vault status
    3. Use local override: redan exec --secret STAGING_DB_PASSWORD=local ...
```

**VM boot failure (no KVM):**
```
redan: ✗ Cannot start VM: KVM not available

  Hardware virtualization is required. Run 'redan doctor' for details.

  Linux: sudo modprobe kvm && sudo usermod -aG kvm $USER
  macOS: Requires Apple Silicon with macOS 14+
```

**MITM CA rejected:**
```
redan: ✗ npm install failed: certificate error

  npm doesn't trust Redan's session certificate.
  This is needed for network policy and secret injection.

  Fix: redan will set NODE_EXTRA_CA_CERTS automatically.
  If this persists, report at https://github.com/.../redan/issues
```

## 3.3 Policy Model

### redan.toml

**Minimal example** (generated by `redan init`):

```toml
# redan.toml — what this project's agents can access
image = "node:22"

[network]
allow = ["api.github.com", "api.openai.com", "registry.npmjs.org"]

[secrets.GITHUB_TOKEN]
source = "env"
for = ["api.github.com"]
```

That's it. 6 lines. Everything else has sensible defaults (2 vCPU, 2GB RAM, project dir mounted at `/workspace`).

**Full reference** (all options, for docs — not generated by `redan init`):

```toml
# redan.toml — full reference

image = "python:3.12-slim"     # OCI image (default: auto-detected or ubuntu:24.04)
cpus = 2                       # vCPU count (default: 2)
memory = "2G"                  # RAM (default: 2G)

[network]
allow = [                      # Hostnames only. Raw IPs always blocked.
    "api.github.com",
    "api.openai.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
]
# deny = ["internal.github.com"]  # Overrides allow (useful for subdomains)

[secrets.GITHUB_TOKEN]
source = "env"                 # "env" | "1password" | "vault" | "aws-sm" | "keychain"
for = ["api.github.com"]       # Only inject for these hosts
header = "Authorization"       # HTTP header to inject into (default: Authorization)
format = "Bearer {value}"      # Header value format (default: Bearer {value})

[secrets.OPENAI_API_KEY]
source = "env"
for = ["api.openai.com"]

# inject_mode = "env" secrets (weaker — visible inside VM):
# [secrets.DATABASE_URL]
# source = "env"
# inject_mode = "env"          # ⚠️ Real value visible in VM
# env_var = "DATABASE_URL"

# Enterprise backends (v1.0):
# [secrets.STAGING_KEY]
# source = "vault"
# vault_path = "secret/data/staging/api"
# for = ["staging-api.company.com"]

[audit]
level = "decisions"            # "all" | "decisions" | "errors"

[audit.display]
blocked_requests = true        # Show blocked connections on stderr
secret_injections = true       # Show injection events on stderr (name only)

[audit]
# Audit logs written to $XDG_STATE_HOME/redan/sessions/<id>/audit.jsonl
# NOT in the project directory (agent cannot tamper with its own audit trail)
level = "decisions"                      # "all" | "decisions" | "secrets" | "errors"

[audit.display]
# Show blocked requests to the user in real-time (stderr)
blocked_requests = true
# Show secret injections (name only, never value)
secret_injections = true
```

### Policy Resolution Order

1. Built-in defaults (deny all network, no secrets, 2 vCPU, 2GB RAM)
2. Global config: `$XDG_CONFIG_HOME/redan/config.toml`
3. Project config: `./redan.toml`
4. CLI flags (override everything)
5. Environment variables: `REDAN_*` prefix

### Network Policy Semantics

- Default deny: no network access unless explicitly allowed
- Allow is a list of **hostnames** (not IPs — DNS resolution happens on the host)
- **Raw IP connections always blocked.** Guest connecting to `93.184.216.34:443` is denied even if a hostname resolving to that IP is allowlisted. Connections must go through hostname → DNS → IP resolution on the host side. This prevents policy bypass via direct IP addressing.
- Wildcards: `*.github.com` matches `api.github.com`, `raw.github.com`, etc.
- Port defaults to 443 for HTTPS, 80 for HTTP. Explicit: `api.github.com:8443`
- Deny list takes precedence over allow list
- **Host header validation:** MITM proxy verifies HTTP `Host`/`:authority` header matches the TCP-level destination hostname. Mismatches are blocked and logged as suspicious (prevents domain fronting).
- Blocked address ranges (always, not configurable):
  - IPv4 localhost: `127.0.0.0/8`
  - IPv4 private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - IPv4 link-local: `169.254.0.0/16`
  - IPv6 localhost: `::1/128`
  - IPv6 link-local: `fe80::/10`
  - IPv6 unique-local: `fc00::/7`
  - IPv6 multicast: `ff00::/8`
  - CGNAT: `100.64.0.0/10`

### Secret Injection Semantics

- Each secret has a name, source, allowed injection hosts, and injection format
- Guest environment gets `SECRET_NAME=<placeholder>` — a random token, not the real value
- When the network proxy sees a request to an allowed host, it scans headers for the placeholder and replaces with the real value
- If an agent sends the placeholder to an unauthorized host, the host receives a meaningless random string
- Secrets are retrieved lazily (on first use) and cached in host memory for the session duration
- Secret values never written to disk on the host (in-memory only during session)

## 3.4 Agent Integration Model

### Primary: Environment Injection (v1)

The agent runs inside the VM. No agent-specific integration required. Any agent that can run in a Linux environment works.

```bash
# Claude Code
redan exec -- claude

# Codex
redan exec -- codex

# Interactive shell (for any agent)
redan exec -- bash

# Custom script
redan exec -- python my_agent.py
```

**How it works:**
1. `redan exec` boots a microVM with the configured OCI image
2. Project directory mounted at `/workspace` via virtio-fs
3. Agent process started inside VM with configured env vars (placeholder secrets)
4. Agent's stdin/stdout/stderr connected to host terminal
5. Agent runs normally — reads files, executes code, makes network requests
6. Network requests filtered and secrets injected transparently
7. Agent exits → VM tears down → audit log finalized

**What agents see:**
- Normal Linux filesystem (whatever the OCI image provides)
- Project files at `/workspace`
- Network that works for allowed hosts, times out for blocked hosts (or returns clear error if in-VM proxy configured)
- Environment variables with placeholder values for secrets

**What breaks:**
- Agents that need Docker (Redan is the VM, no Docker inside)
- Agents that inspect `/proc` or kernel details (microVM kernel differs)
- Agents that need GUI (no display server in VM)
- Agents expecting specific host paths (e.g., `/home/user/.config/...`)

### Secondary: MCP Server (v1.1)

Expose sandboxed execution as MCP tools. Any MCP-capable agent can request sandboxed command execution.

```json
{
    "tools": [
        {
            "name": "sandboxed_exec",
            "description": "Execute a command in a secure microVM sandbox",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": { "type": "string" },
                    "working_dir": { "type": "string" },
                    "timeout_seconds": { "type": "integer" }
                },
                "required": ["command"]
            }
        },
        {
            "name": "sandboxed_write",
            "description": "Write a file inside the sandbox",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" }
                },
                "required": ["path", "content"]
            }
        },
        {
            "name": "sandboxed_read",
            "description": "Read a file from the sandbox",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" }
                },
                "required": ["path"]
            }
        }
    ]
}
```

**Trade-off vs environment injection:** MCP gives per-tool-call granularity (each call runs in sandbox) but requires the agent to use MCP. Environment injection works with any agent but sandboxes the whole session.

### Tertiary: Pi Extension (v1.1)

Pi's extension system allows intercepting tool calls. A Redan extension would:
1. Hook `tool_call` events for `bash`, `write`, `edit`, `read`
2. Redirect execution to a running Redan VM session
3. Return results back to Pi

```typescript
// Conceptual Pi extension
import { defineExtension } from "@anthropic/pi-sdk";

export default defineExtension({
    name: "redan",
    hooks: {
        tool_call: async (call, context) => {
            if (["bash", "write", "read", "edit"].includes(call.tool)) {
                return redan.execInSession(context.sessionId, call);
            }
            return call; // pass through non-sandboxed tools
        }
    }
});
```

This is the deepest integration — the agent doesn't know it's sandboxed. Deferred to v1.1.

## 3.5 Filesystem Model

### virtio-fs Mounts

```
Guest filesystem:
/                          ← OCI image root (read-only layer)
├── workspace/             ← Project directory (virtio-fs, read-write)
├── tmp/                   ← Guest tmpfs (ephemeral, fast)
├── home/agent/            ← Agent home directory (in-VM, ephemeral)
└── etc/                   ← OCI image /etc (includes proxy CA cert)
```

**Project sync:** virtio-fs provides real-time bidirectional access. Changes made by the agent are immediately visible on the host. Changes made on the host (e.g., git pull in another terminal) are immediately visible to the agent. No sync step needed.

**Ephemeral state:** Everything outside `/workspace` is ephemeral. When the VM shuts down, package installs, caches, and agent state are lost. This is intentional — each session starts clean.

**Persistent caches (v1.1):** Common request will be to persist npm/pip caches across sessions. Solution: additional named volumes stored on host, mounted at package manager cache paths. Separate from project files.

### File Ownership

Guest processes run as a non-root user (`agent`, UID 1000). virtio-fs maps this to the host user's UID. Files created by the agent in `/workspace` appear owned by the host user. No permission issues.

## 3.6 Session Lifecycle

```
redan exec -- claude

1. INIT
   ├─ Parse redan.toml (or auto-detect project type if no config)
   ├─ Resolve policy (defaults → global → project → CLI)
   ├─ Initialize secret manager (connect to backends, prefetch if configured)
   ├─ Pull OCI image if not cached
   └─ Snapshot executable project files (see 3.6.1)

2. BOOT
   ├─ Create libkrun VM context
   ├─ Configure: vCPUs, RAM, network (TSI/passt), virtio-fs mounts
   ├─ Set guest environment variables (placeholders for secrets)
   ├─ Start network proxy (tokio task)
   ├─ Boot VM (krun_start_enter or background thread)
   └─ Wait for guest ready signal

3. RUN
   ├─ Attach host stdin/stdout/stderr to guest process
   ├─ Network proxy handles all guest traffic:
   │   ├─ Policy check per connection (hostname AND Host header match)
   │   ├─ Secret injection per request (header scrubbing on response)
   │   └─ Audit logging per decision
   └─ Agent runs until exit or timeout

4. TEARDOWN
   ├─ Guest process exits → capture exit code
   ├─ Diff executable project files against snapshot (see 3.6.1)
   ├─ Warn if executable files modified
   ├─ Flush audit log (to host-only path)
   ├─ Stop network proxy
   ├─ Destroy VM context
   ├─ Clear secret cache from memory (zeroize)
   └─ Exit with guest process exit code
```

### 3.6.1 Executable File Protection

**Problem (Opus Finding 2 — Critical):** A compromised agent can write malicious git hooks or CI configs that execute on the host AFTER the Redan session ends. The VM boundary doesn't help because these files run outside Redan.

**Mechanism:** On session start, Redan snapshots (hashes) executable project files. On teardown, it diffs against the snapshot and warns:

**Monitored paths:**
```
.git/hooks/*
.github/workflows/*
.gitlab-ci.yml
.vscode/tasks.json
Makefile, Justfile, Taskfile.yml
.husky/*
package.json (scripts section)
pyproject.toml (scripts section)
```

**On modification detected:**
```
redan: ⚠️  SECURITY: Modified files that execute on your host:
  .git/hooks/pre-commit  (NEW — did not exist before session)
  .github/workflows/deploy.yml  (CHANGED)

  These files run OUTSIDE Redan when you use git, make, npm, etc.
  Review before running any project commands:
    git diff .git/hooks/pre-commit
    git diff .github/workflows/deploy.yml
```

**Audit log entry:**
```jsonl
{"ts":"...","event":"executable_file_modified","session_id":"abc123","files":[".git/hooks/pre-commit",".github/workflows/deploy.yml"],"action":"warned_user"}
```

**v1.1 enhancement:** Option to mount `.git/hooks/` read-only. Configurable monitored paths via `redan.toml`.

### Signal Handling

| Host signal | Action |
|-------------|--------|
| SIGINT (Ctrl+C) | Forward to guest process |
| SIGTERM | Forward to guest, wait 10s, force kill VM |
| SIGWINCH | Forward terminal resize to guest |
| SIGHUP | Forward to guest |

## 3.7 Audit Log

### Storage

Audit logs are written to a **host-only path** inaccessible from inside the VM:

```
$XDG_STATE_HOME/redan/sessions/<session_id>/audit.jsonl
```

This prevents a compromised agent from tampering with its own audit trail. The project directory (`.redan/`) is NOT used for logs — only for config.

View logs via CLI:
```bash
redan audit show                    # latest session
redan audit show <session_id>       # specific session
redan audit tail                    # stream current session
```

### Format

JSONL (one JSON object per line). Expanded schema per oracle review feedback:

```jsonl
{"ts":"2026-02-08T10:30:00Z","event":"session_start","session_id":"abc123","image":"python:3.12","policy":"./redan.toml"}
{"ts":"2026-02-08T10:30:00.150Z","event":"vm_boot","session_id":"abc123","boot_ms":148}
{"ts":"2026-02-08T10:30:05Z","event":"net_allow","session_id":"abc123","host":"api.github.com","port":443,"method":"GET","path":"/repos/owner/repo","status":200,"latency_ms":42}
{"ts":"2026-02-08T10:30:05Z","event":"secret_inject","session_id":"abc123","secret":"GITHUB_TOKEN","host":"api.github.com","inject_mode":"header"}
{"ts":"2026-02-08T10:30:10Z","event":"net_deny","session_id":"abc123","host":"evil.com","port":443,"reason":"not_in_allowlist"}
{"ts":"2026-02-08T10:30:11Z","event":"net_deny","session_id":"abc123","host":"93.184.216.34","port":443,"reason":"raw_ip_blocked"}
{"ts":"2026-02-08T10:35:00Z","event":"session_end","session_id":"abc123","exit_code":0,"duration_s":300,"files_modified":["src/main.py"],"executable_files_modified":[".git/hooks/pre-commit"]}
```

Fields added per Sonnet/Opus review: `method`, `path` (no query string — may contain secrets), `status`, `latency_ms`, `inject_mode`, `files_modified`, `executable_files_modified`.

### Real-time Display (stderr)

```
redan: ✗ blocked connection to evil.com:443 (not in allowlist)
redan: ✗ blocked connection to 93.184.216.34:443 (raw IP blocked)
redan: ✗ blocked connection to 169.254.169.254:80 (private range)
redan: ✓ GITHUB_TOKEN injected for api.github.com
```

Always displayed on stderr. Configurable verbosity via `audit.display` in config.

## 3.8 Configuration Layering

```
Built-in defaults
     ↓ (merge)
$XDG_CONFIG_HOME/redan/config.toml     # global defaults
     ↓ (merge)
./redan.toml                            # project policy
     ↓ (override)
CLI flags: --allow-host, --secret, --image, --cpus, --memory
     ↓ (override)
REDAN_* env vars: REDAN_IMAGE, REDAN_CPUS, etc.
```

**Merge semantics:**
- Scalars (image, cpus, memory): later value wins
- Lists (network.allow): concatenated (project adds to global)
- Maps (secrets): merged by key (project can add secrets, override source)
- network.deny always wins over network.allow at every level

## Key Decisions

1. **Single process, no daemon.** `redan exec` boots VM inline. Simplifies everything. Warm pools deferred. ✅

2. **Environment injection as primary integration model.** Agent runs inside VM, no agent-specific code needed. MCP and Pi extensions are additive for v1.1. ✅

3. **TOML for config.** Matches Rust ecosystem conventions. Human-readable. Well-supported by `serde`. ✅

4. **JSONL for audit log.** Structured, appendable, greppable, streamable. Standard for observability tooling. ✅

5. **Default deny network.** No network access unless explicitly allowed. Conservative default. Developers opt in to each host. ✅

6. **Ephemeral VM per session.** Clean slate each time. Persistent caches via named volumes (v1.1). ✅

## Open Questions

1. **Terminal multiplexing inside VM:** If an agent spawns background processes or uses tmux inside the VM, does I/O attachment work correctly? Needs testing with real agents.

2. **Large project directories:** virtio-fs with a monorepo (100K+ files). What's the performance? Do we need `.redanignore` for excluding `node_modules`, `.git/objects`, etc.?

3. **Image caching location:** `$XDG_CACHE_HOME/redan/images/`? How much disk space? Do we need garbage collection?

4. **Warm pool vs cold boot UX:** If boot time is >300ms, developers will feel it on every invocation. How do we communicate boot progress without cluttering agent output? A brief `redan: booting vm...` on stderr?

5. **How does Ctrl+C behave?** If the agent is mid-tool-call inside the VM and the user hits Ctrl+C, what's the expected behavior? Forward SIGINT to guest, let the agent handle it? Or kill the VM immediately?
