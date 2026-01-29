# 5. MVP Scope

## 5.1 What "MVP Done" Looks Like

A developer installs Redan, runs `redan exec -- claude` in their project directory, and gets a Claude Code session where:
- The agent can read and write project files normally
- The agent can reach explicitly allowed hosts (GitHub, npm, OpenAI)
- The agent's API tokens are injected transparently — the agent doesn't know or care
- The agent cannot read `~/.ssh`, `~/.aws`, or any host credentials
- The agent cannot reach hosts not on the allowlist
- The developer sees blocked requests in their terminal
- Everything is logged

That's it. One command. Real security. No cloud account. No daemon to manage.

## 5.2 User Stories

### Must-Have (MVP)

**US-1: First run with sensible defaults**
> As a developer, I run `redan exec -- bash` in my project directory and get an interactive shell inside a sandboxed VM with my project files at `/workspace`, no network access, and no host credentials visible.

**US-2: Network allowlist**
> As a developer, I create a `redan.toml` with `network.allow = ["api.github.com", "registry.npmjs.org"]` and my sandboxed session can reach those hosts and nothing else.

**US-3: Secret injection from environment**
> As a developer, I configure a secret in `redan.toml` with `source = "env"` and `inject_for = ["api.github.com"]`. Inside the sandbox, `$GITHUB_TOKEN` contains a placeholder. When the agent makes a request to `api.github.com`, the real token is injected transparently.

**US-4: Run a coding agent sandboxed**
> As a developer, I run `redan exec -- claude` and Claude Code runs inside the VM. I interact with it normally. It can access my project files and allowed APIs. It cannot access my host credentials or unauthorized hosts.

**US-5: See blocked requests**
> As a developer, when the agent tries to reach a blocked host, I see `redan: ✗ blocked connection to evil.com:443` in my terminal so I know the policy is working.

**US-6: Audit log**
> As a developer, I can review `.redan/audit.jsonl` after a session to see every network connection, secret injection, and policy decision.

**US-7: Policy initialization**
> As a developer, I run `redan policy init` and get a `redan.toml` template with comments explaining every option.

**US-8: Image selection**
> As a developer, I specify `--image python:3.12` and my session uses that OCI image. If I don't specify, a reasonable default (Ubuntu or Alpine-based) is used.

### Should-Have (v1.0, not MVP)

**US-9: Vault backend**
> As a platform engineer, I configure `source = "vault"` for secrets, and the agent gets credentials from our HashiCorp Vault without the developer needing Vault access directly.

**US-10: AWS Secrets Manager backend**
> As a platform engineer, I configure `source = "aws-sm"` with an agent-specific IAM role.

**US-11: Secret health check**
> As a developer, I run `redan secret test` and see which backends are reachable and which secrets are retrievable, without revealing values.

**US-12: Global config**
> As a developer, I set defaults in `~/.config/redan/config.toml` (preferred image, default network rules) that apply to all projects unless overridden.

**US-13: macOS Keychain backend**
> As a solo developer on macOS, I store secrets in Keychain and reference them from `redan.toml`.

### Nice-to-Have (v1.x)

**US-14: MCP server**
> As a developer using an MCP-capable agent, I start `redan mcp` and the agent can call sandboxed execution tools.

**US-15: Pi extension**
> As a Pi user, I install the Redan extension and all tool calls are transparently sandboxed.

**US-16: Warm pool**
> As a developer who runs `redan exec` frequently, a background helper keeps a pre-booted VM ready so startup is instant.

**US-17: Named volumes for caches**
> As a developer, I configure persistent volumes for `~/.cache/pip` and `node_modules/.cache` so package installs don't re-download every session.

**US-18: `.redanignore`**
> As a developer with a large monorepo, I exclude `node_modules` and `.git/objects` from the virtio-fs mount to improve performance.

## 5.3 Happy Path Walkthrough

```bash
# 1. Install
curl -sSf https://redan.dev/install.sh | sh
# Installs redan binary + ensures libkrun is available

# 2. Verify
redan --version
# redan 0.1.0

# 3. Navigate to project
cd ~/Projects/my-app

# 4. Initialize policy
redan policy init
# Created redan.toml with default settings.
# Edit to configure network access and secrets.

# 5. Edit policy
cat redan.toml
# [vm]
# image = "ubuntu:24.04"
# ...
# [network]
# allow = []     # ← add hosts here
# ...

# Developer edits redan.toml:
# [network]
# allow = ["api.github.com", "api.openai.com", "registry.npmjs.org"]
#
# [secrets.GITHUB_TOKEN]
# source = "env"
# inject_for = ["api.github.com"]
# header = "Authorization"
# format = "token {value}"

# 6. Verify secrets are accessible
GITHUB_TOKEN=ghp_xxx redan secret test
# ✓ GITHUB_TOKEN: env var present, 40 chars
# ✓ All backends reachable

# 7. Run sandboxed session
GITHUB_TOKEN=ghp_xxx redan exec -- claude
# redan: booting vm... (148ms)
# redan: mounted ./  →  /workspace (read-write)
# redan: network: 3 hosts allowed, 1 secret configured
# redan: session abc123 started
#
# Claude Code starts inside VM, interactive session begins.
# Developer uses Claude normally.
#
# If Claude tries to reach an unauthorized host:
# redan: ✗ blocked connection to evil.com:443 (not in allowlist)
#
# If Claude uses the GitHub token:
# redan: ✓ GITHUB_TOKEN injected for api.github.com
#
# Session ends (Claude exits or Ctrl+C):
# redan: session abc123 ended (duration: 12m34s, exit code: 0)
# redan: audit log: .redan/audit.jsonl (47 entries)
```

## 5.4 Hard Technical Unknowns (Need Spikes)

| # | Unknown | Risk | Spike |
|---|---------|------|-------|
| TU-1 | Does TSI give us enough control to intercept and MITM connections? | If not, we need passt mode (more complex networking). | Build minimal libkrun VM, route TCP through host, terminate TLS, inject a header. |
| TU-2 | virtio-fs performance with large project directories | If too slow, agents become unusable. | Mount a real project (~50K files), measure `find`, `grep`, `cat` latency vs native. |
| TU-3 | Can Claude Code / Codex / Cursor run transparently inside a microVM? | If agents make assumptions about the host that break in a VM, we need compatibility shims. | Boot a VM, install Claude Code, run it. Note what breaks. |
| TU-4 | MITM proxy with ephemeral CA — does it work with npm, pip, cargo, git? | If these tools reject the CA or pin certs, MITM breaks package installs. | Boot VM with custom CA, run `npm install`, `pip install`, `git clone` over HTTPS. |
| TU-5 | libkrun macOS HVF stability and boot time | macOS is a primary platform. If libkrun is flaky on macOS, we have a problem. | Build and run libkrun on Apple Silicon. Measure boot time. Stress test. |
| TU-6 | OCI image handling without Docker daemon | We need to pull and unpack OCI images. Do existing Rust crates handle this? | Evaluate `oci-distribution`, `containers-image-proxy`, or shell out to `skopeo`/`umoci`. |

## 5.5 What's NOT in v1

| Feature | Why Not |
|---------|---------|
| Crux-based architecture | v2+. v1 is CLI only. |
| Mobile monitoring app | v2+. Requires Crux. |
| Desktop GUI (Tauri) | v2+. CLI is sufficient for developers. |
| Team/org management | v2+. v1 is single-developer. |
| Hosted/cloud offering | Never (local-first is the identity). Maybe a management plane for enterprise. |
| Windows native | v2. WSL2 is the interim story. |
| Docker-in-VM | Out of scope. Agents that need Docker are a different use case. |
| Multi-VM orchestration | v1 is one `redan exec` = one VM. Parallel sessions = parallel processes. |
| Custom OCI base images | v1.1. Stock images are fine for MVP. |
| GUI agent support (Cursor IDE) | Out of scope for v1. CLI agents only. |
| Billing / usage tracking | Never for open source. Maybe for enterprise add-on. |

## Key Decisions

1. **MVP is US-1 through US-8.** Eight user stories. One command (`redan exec`), one config file (`redan.toml`), one secret backend (`env`). ✅

2. **Default image: Ubuntu 24.04.** Broadest compatibility with agent tooling. Alpine is smaller but causes too many compatibility issues (musl vs glibc). ✅

3. **`env` is the only secret backend for MVP.** Vault, AWS SM, etc. are v1.0 (post-MVP). This massively reduces scope while still demonstrating the secret injection model. ✅

4. **No warm pool for MVP.** Accept cold boot latency (<300ms target). If >500ms, add a brief progress indicator. ✅

5. **MVP targets Linux x86_64 and macOS aarch64 only.** Two platforms. If macOS is unstable during spikes, drop to Linux-only for MVP. ✅

## Open Questions

1. **Install experience:** `curl | sh` is standard but requires building packages for multiple platforms. For MVP, is "clone and `cargo install --path .`" acceptable? Or do we need pre-built binaries from day one?

2. **Default image pull:** First `redan exec` needs to pull the OCI image. This could take 30+ seconds. Do we prompt the user? Pull automatically? Require `redan image pull` first?

3. **redan.toml in `.gitignore`?** The file contains no secrets but does reveal infrastructure (which hosts the project talks to, which Vault paths are used). Some teams want this committed (policy as code), others want it private. Default: commit it (encourage policy transparency). Document the choice.
