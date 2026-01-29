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
│  │ Audit Log   │  Structured JSONL to file or stdout               │
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
redan exec --image python:3.12 -- python script.py
redan exec --image node:22 -- npm test
redan exec -- bash                          # interactive shell, default image
redan exec --policy ./redan.toml -- claude  # run claude code inside VM

redan policy init                  # generate redan.toml with sensible defaults
redan policy check                 # validate redan.toml
redan policy show                  # display effective policy (merged defaults + overrides)

redan secret list                  # list configured secrets (names only, never values)
redan secret test                  # verify secret backends are reachable

redan image pull <image>           # pre-pull OCI image for faster boot
redan image list                   # list cached images

redan audit show                   # show audit log for current/recent sessions
redan audit tail                   # stream audit log
```

**Design principles:**
- `redan exec` is the primary command. Everything else is secondary.
- Minimal flags for the common case. Policy file provides the config.
- Interactive by default — stdin/stdout/stderr attached to guest process.
- Exit code from guest process propagated to host.

## 3.3 Policy Model

### redan.toml

```toml
# redan.toml — project-level policy for Redan sessions

[vm]
image = "python:3.12-slim"    # OCI image for guest
cpus = 2                       # vCPU count
memory = "2G"                  # RAM allocation

[vm.mounts]
# Host paths mounted into guest via virtio-fs
"/workspace" = { host = ".", writable = true }
# Additional read-only mounts
# "/data" = { host = "/shared/datasets", writable = false }

[network]
# Default: deny all. Only listed hosts are reachable.
allow = [
    "api.github.com",
    "api.openai.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
]

[network.deny]
# Explicit deny (overrides allow, useful for blocking subdomains)
# deny = ["internal.github.com"]

[secrets]
# Each secret: name, backend source, and which hosts it can be injected for.
# The guest sees $GITHUB_TOKEN as a placeholder. The real value is injected
# by the host network proxy only when the request targets an allowed host.

[secrets.GITHUB_TOKEN]
source = "env"                           # read from host env var
inject_for = ["api.github.com"]          # only inject for these hosts
header = "Authorization"                 # inject as this header
format = "Bearer {value}"                # header value format

[secrets.OPENAI_API_KEY]
source = "env"
inject_for = ["api.openai.com"]
header = "Authorization"
format = "Bearer {value}"

# Enterprise example: HashiCorp Vault
# [secrets.STAGING_DB_PASSWORD]
# source = "vault"
# vault_path = "secret/data/staging/db"
# vault_key = "password"
# inject_for = ["staging-db.internal.company.com"]

# Enterprise example: AWS Secrets Manager
# [secrets.API_KEY]
# source = "aws-sm"
# aws_secret_id = "prod/api-key"
# inject_for = ["api.internal.company.com"]

[audit]
enabled = true
file = ".redan/audit.jsonl"             # relative to project root
# stdout = true                         # also print policy decisions to stderr
level = "decisions"                      # "all" | "decisions" | "secrets" | "errors"

[audit.display]
# Show blocked requests to the user in real-time (stderr)
blocked_requests = true
# Show secret injections (name only, never value)
secret_injections = false
```

### Policy Resolution Order

1. Built-in defaults (deny all network, no secrets, 2 vCPU, 2GB RAM)
2. Global config: `$XDG_CONFIG_HOME/redan/config.toml`
3. Project config: `./redan.toml`
4. CLI flags (override everything)
5. Environment variables: `REDAN_*` prefix

### Network Policy Semantics

- Default deny: no network access unless explicitly allowed
- Allow is a list of hostnames (not IPs — DNS resolution happens on the host)
- Wildcards: `*.github.com` matches `api.github.com`, `raw.github.com`, etc.
- Port defaults to 443 for HTTPS, 80 for HTTP. Explicit: `api.github.com:8443`
- Deny list takes precedence over allow list
- Localhost/private ranges always blocked (prevent SSRF to host services)

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
   ├─ Parse redan.toml (or defaults)
   ├─ Resolve policy (defaults → global → project → CLI)
   ├─ Initialize secret manager (connect to backends, prefetch if configured)
   └─ Pull OCI image if not cached

2. BOOT
   ├─ Create libkrun VM context
   ├─ Configure: vCPUs, RAM, network (TSI), virtio-fs mounts
   ├─ Set guest environment variables (placeholders for secrets)
   ├─ Start network proxy (tokio task)
   ├─ Boot VM (krun_start_enter or background thread)
   └─ Wait for guest ready signal

3. RUN
   ├─ Attach host stdin/stdout/stderr to guest process
   ├─ Network proxy handles all guest traffic:
   │   ├─ Policy check per connection
   │   ├─ Secret injection per request
   │   └─ Audit logging per decision
   └─ Agent runs until exit or timeout

4. TEARDOWN
   ├─ Guest process exits → capture exit code
   ├─ Flush audit log
   ├─ Stop network proxy
   ├─ Destroy VM context
   ├─ Clear secret cache from memory (zeroize)
   └─ Exit with guest process exit code
```

### Signal Handling

| Host signal | Action |
|-------------|--------|
| SIGINT (Ctrl+C) | Forward to guest process |
| SIGTERM | Forward to guest, wait 10s, force kill VM |
| SIGWINCH | Forward terminal resize to guest |
| SIGHUP | Forward to guest |

## 3.7 Audit Log Format

JSONL (one JSON object per line), written to configured file and optionally to stderr for real-time display.

```jsonl
{"ts":"2026-02-08T10:30:00Z","event":"session_start","session_id":"abc123","image":"python:3.12","policy":"./redan.toml"}
{"ts":"2026-02-08T10:30:00.150Z","event":"vm_boot","session_id":"abc123","boot_ms":148}
{"ts":"2026-02-08T10:30:05Z","event":"net_allow","session_id":"abc123","host":"api.github.com","port":443}
{"ts":"2026-02-08T10:30:05Z","event":"secret_inject","session_id":"abc123","secret":"GITHUB_TOKEN","host":"api.github.com"}
{"ts":"2026-02-08T10:30:10Z","event":"net_deny","session_id":"abc123","host":"evil.com","port":443,"reason":"not_in_allowlist"}
{"ts":"2026-02-08T10:35:00Z","event":"session_end","session_id":"abc123","exit_code":0,"duration_s":300}
```

**Blocked request display** (when `audit.display.blocked_requests = true`):

```
redan: ✗ blocked connection to evil.com:443 (not in allowlist)
redan: ✗ blocked connection to 169.254.169.254:80 (private range)
redan: ✓ GITHUB_TOKEN injected for api.github.com
```

This gives the developer visibility without cluttering the agent's output. Displayed on stderr so it doesn't interfere with agent stdout.

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
