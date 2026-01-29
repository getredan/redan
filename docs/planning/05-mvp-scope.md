# 5. MVP Scope

*Revised per oracle reviews. Tighter scope, honest security story, improved DX.*

## 5.1 What "MVP Done" Looks Like

A developer installs Redan, runs `redan exec -- claude` in their project directory, and gets a Claude Code session where:
- The agent can read and write project files normally
- The agent can reach explicitly allowed hosts (or auto-detected ones if no config exists)
- The agent's API tokens are injected transparently via MITM proxy
- The agent cannot read `~/.ssh`, `~/.aws`, or any host credentials
- The agent cannot reach hosts not on the allowlist (including raw IPs and private ranges)
- The developer sees blocked requests and secret injections on stderr
- Everything is logged to a tamper-proof host-only audit log
- On session end, the developer is warned if executable project files were modified

One command. Real security. No cloud account. No daemon.

## 5.2 User Stories

### Must-Have (MVP)

**US-1: Zero-config first run**
> As a developer, I run `redan exec -- bash` with no `redan.toml`. Redan auto-detects my project type (Node, Python, etc.), suggests a default allowlist, and boots a sandboxed session with sensible defaults. I see what was auto-configured on stderr.

**US-2: Config initialization**
> As a developer, I run `redan init` and get an interactive prompt: "What agent? What package manager? Need API access?" The result is a minimal `redan.toml` (6-10 lines), not a reference manual.

**US-3: Network allowlist**
> As a developer, my `redan.toml` specifies `network.allow = ["api.github.com", "registry.npmjs.org"]`. My sandboxed session can reach those hosts and nothing else. Raw IP connections are blocked. Private ranges are blocked.

**US-4: Secret injection from environment**
> As a developer, I configure a secret with `source = "env"` and `for = ["api.github.com"]`. Inside the sandbox, `$GITHUB_TOKEN` contains a placeholder. The real token is injected by the proxy only when the request targets `api.github.com`.

**US-5: Run a coding agent sandboxed**
> As a developer, I run `redan exec -- claude` and Claude Code runs inside the VM. I interact with it normally. It cannot access my host credentials or unauthorized hosts.

**US-6: See what Redan is doing**
> As a developer, I see blocked requests, secret injections, and policy decisions on stderr in real-time. After the session, I use `redan audit show` to review the full log.

**US-7: Executable file warnings**
> As a developer, when the session ends, Redan warns me if the agent modified `.git/hooks/`, `.github/workflows/`, `Makefile`, or other files that execute on my host machine.

**US-8: Prerequisite checking**
> As a developer, I run `redan doctor` and it tells me if KVM/HVF is available, if libkrun is installed, and if my system is ready.

**US-9: Image selection**
> As a developer, I specify `--image python:3.12` or rely on auto-detection (project has `package.json` → node image).

**US-10: Vault backend**
> As a platform engineer, I configure `source = "vault"` with agent-scoped policies. Redan authenticates via `VAULT_TOKEN` or AppRole.

**US-11: AWS Secrets Manager backend**
> As a platform engineer, I configure `source = "aws-sm"` with agent-specific IAM role. Redan uses standard AWS credential chain.

**US-12: Secret health check**
> As a developer, `redan secret test` verifies backends are reachable and secrets are retrievable before starting a session.

### Should-Have (v1.0, post-MVP)

**US-13: 1Password CLI backend**
> As a solo developer, I configure `source = "1password"` and my secrets are retrieved via `op` CLI with biometric unlock. No secrets in shell environment.

**US-14: Global config**
> As a developer, I set defaults in `~/.config/redan/config.toml` that apply to all projects unless overridden.

**US-15: Azure Key Vault / GCP Secret Manager**
> As a platform engineer, I configure `source = "azure-kv"` or `source = "gcp-sm"` with native IAM.

### Nice-to-Have (v1.x)

**US-16: MCP server** — expose sandboxed execution as MCP tools.
**US-17: Pi extension** — transparent tool call interception for Pi users.
**US-18: Warm pool** — pre-booted VM for instant startup.
**US-19: Named volumes** — persistent package caches across sessions.
**US-20: `.redanignore`** — exclude large directories from virtio-fs mount.

## 5.3 Happy Path Walkthrough

```bash
# 1. Install
curl -sSf https://redan.dev/install.sh | sh
# ✓ Detected Linux x86_64
# ✓ KVM available (/dev/kvm)
# → Installing libkrun... done
# → Installing redan 0.1.0... done
# ✓ Run 'redan doctor' to verify

# 2. Verify
redan doctor
# ✓ redan 0.1.0
# ✓ libkrun 1.6.0
# ✓ KVM available
# ✓ Ready to use

# 3. Navigate to project
cd ~/Projects/my-app

# 4a. Quick start (no config file)
redan exec -- bash
# redan: no redan.toml found
# redan: detected Node.js project (package.json)
# redan: auto-allowing: registry.npmjs.org, github.com
# redan: image: node:22
# redan: no secrets configured (use 'redan init' to set up)
# redan: booting... 210ms
# redan: session a1b2c3 started
#
# Interactive shell inside VM. Project at /workspace.

# 4b. Or: set up config first
redan init
# ? What agent are you using? Claude Code
# ? Package manager? npm
# ? Need API access? GitHub, OpenAI
# ? GitHub token source? Environment variable ($GITHUB_TOKEN)
# ✓ Created redan.toml (8 lines)

cat redan.toml
# image = "node:22"
#
# [network]
# allow = ["api.github.com", "api.openai.com", "registry.npmjs.org"]
#
# [secrets.GITHUB_TOKEN]
# source = "env"
# for = ["api.github.com"]

# 5. Run with secrets
GITHUB_TOKEN=ghp_xxx redan exec -- claude
# redan: booting... 210ms
# redan: 3 hosts allowed, 1 secret configured
# redan: session a1b2c3 started
#
# Claude Code starts. Developer works normally.
#
# redan: ✓ GITHUB_TOKEN injected for api.github.com
# redan: ✗ blocked: evil.com:443 (not in allowlist)
#        → to allow: redan exec --allow-host evil.com ...
#        → or add to redan.toml [network] allow
#
# Session ends:
# redan: session a1b2c3 ended (12m34s, exit 0)
# redan: audit: redan audit show a1b2c3 (47 entries)
```

## 5.4 Hard Technical Unknowns (Need Spikes)

| # | Unknown | Risk | Spike |
|---|---------|------|-------|
| TU-1 | TSI interception depth for MITM proxy | **Highest risk.** If TSI doesn't support interception, need passt mode. | PS-1: boot VM, intercept TCP, terminate TLS. |
| TU-2 | virtio-fs performance + symlink safety | If slow or symlinks escape, need alternative. | PS-2: benchmark + adversarial symlink test. |
| TU-3 | Claude Code transparency in microVM | If Claude Code won't run, MVP is in trouble. | PS-3: install and run Claude Code in VM. |
| TU-4 | MITM CA + package manager compatibility | If npm/pip/cargo reject CA, MITM approach broken. | PS-4: test with real registries. |
| TU-5 | macOS HVF stability | If flaky, defer macOS to v1.0. | PS-1: test on Apple Silicon. |
| TU-6 | OCI image handling in Rust | Solvable, question is effort. | PS-1: evaluate crates or skopeo. |

## 5.5 MVP Constraints

**One command:** `redan exec`
**One config format:** `redan.toml` (optional — zero-config works)
**Three secret backends:** `env`, Vault, AWS Secrets Manager
**One agent verified:** Claude Code (others may work but aren't tested)
**One primary platform:** Linux x86_64 (macOS aarch64 conditional on spike results)
**One protocol class:** HTTPS via MITM proxy (non-HTTP blocked in MVP)

## 5.6 What's NOT in MVP

| Feature | Why Not | When | Repo |
|---------|---------|------|------|
| 1Password CLI backend | Fast-follow after MVP | v1.0 | redan |
| Azure Key Vault | Fast-follow | v1.0 | redan |
| GCP Secret Manager | Fast-follow | v1.0 | redan |
| macOS Keychain | Fast-follow | v1.0 | redan |
| MCP server | Layer 1 is the MVP | v1.1 | redan |
| Pi extension | Requires tracking Pi's extension API | v1.1 | redan |
| Warm pool | Boot time acceptable for MVP | v1.1 | redan |
| Central policy server | Enterprise feature | v1.0 | redan-enterprise |
| Remote audit forwarding | Enterprise feature | v1.0 | redan-enterprise |
| HMAC-chained audit logs | Enterprise feature | v1.0 | redan-enterprise |
| Org-wide policy enforcement | Enterprise feature | v1.0 | redan-enterprise |
| Agent identity management | Enterprise feature | v1.1 | redan-enterprise |
| Compliance dashboards | Enterprise feature | v1.1 | redan-enterprise |
| Crux architecture | v2 refactor | v2 | redan |
| Desktop GUI (Tauri) | Let feedback drive this | v2 | redan |
| Windows native | WSL2 is interim | v2 | redan |
| Docker-in-VM | Different use case | Out of scope | — |

## 5.7 Repository & License Structure

| Repo | License | Contains |
|------|---------|----------|
| `redan/redan` | BSD-3-Clause | CLI, VM, proxy, all secret backends, local audit, MCP server |
| `redan/redan-enterprise` | BSL-1.1 | Policy server, remote audit, HMAC signing, org enforcement, compliance |

**Principle:** Every feature a developer or small team needs is in the open-source core. Enterprise adds organizational management and compliance — things that only matter when you have 50+ developers using Redan and need central policy, audit forwarding, and reporting.

**Backend boundary:** All secret backends (env, Vault, AWS SM, Azure KV, GCP SM, 1Password, Keychain) are in the open core. The enterprise repo never touches secret retrieval — it manages policies and audit streams.

## Key Decisions

1. **Zero-config mode is MVP.** `redan exec` works without `redan.toml`. Config is additive. ✅

2. **Three secret backends in MVP:** env, Vault, AWS SM. Others fast-follow. ✅

3. **BSD-3-Clause for open core.** Following Tailscale/Sentry model. ✅

4. **BSL-1.1 for enterprise.** Prevents competitors from hosting as SaaS. Converts to open source after change date. ✅

5. **Linux x86_64 primary. macOS conditional.** Don't hold MVP for cross-platform parity. ✅

6. **Boot time target <500ms.** Acceptable for interactive use. ✅

7. **redan.toml committed to repo** (default). Policy as code. No secrets in the file. ✅
