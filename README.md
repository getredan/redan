<p align="center">
  <img src="assets/logo.jpg" alt="Redan" width="600">
  <p align="center">Your agents run free. Your secrets stay put.</p>
</p>

# What's Redan?

Redan runs AI coding agents inside [libkrun] microVMs with network-layer
secret injection. Agents get a real dev environment -- node, git, python,
your project files -- but can't see host credentials and never observe
the real values of injected secrets. Secrets are only injected for hosts
you explicitly allow.

> *redan (/ɹɪˈdan/): a V-shaped fieldwork forming a salient angle toward
> the enemy.*

## Install

Redan requires Linux x86_64 with KVM and libkrun.

```bash
# Arch Linux
pacman -S libkrun

# Fedora
dnf install libkrun-devel

# Then:
cargo install redan
```

## Quick start

### 1. Create an image

```bash
redan image create claude-code \
  --packages "nodejs npm git openssh-client" \
  --run "npm install -g @anthropic-ai/claude-code"
```

This downloads Alpine Linux, boots a microVM, installs packages, and
saves the result. Takes about 5 minutes.

### 2. Run an agent

```bash
redan exec --image claude-code \
  --secret "ANTHROPIC_API_KEY=sk-ant-...:api.anthropic.com" \
  --mount ./my-project \
  --command "claude --print 'review this project'"
```

The agent sees `$ANTHROPIC_API_KEY` as a placeholder token. The proxy
injects the real key only in HTTPS requests to `api.anthropic.com`.
Responses are scrubbed of the real value before the agent sees them.

**Note:** `--secret` values are visible in process listings (`ps`).
For production use, prefer `--secret-file`, the Vault provider
(`vault://`), or pass secrets from environment variables:
`--secret "KEY=$(cat /path/to/secret):host"`.

### 3. Interactive mode

```bash
redan exec --image claude-code -i \
  --secret "ANTHROPIC_API_KEY=sk-ant-...:api.anthropic.com" \
  --mount ./my-project
```

Drops you into a shell inside the VM. Same secret injection, same
network isolation.

### 4. Check prerequisites

```bash
redan doctor                         # system checks
redan doctor --image myimage         # check a specific image exists
redan doctor --secret "KEY=val:host" # validate secret syntax + providers
```

Checks for /dev/kvm, libkrun, libkrunfw, and available images.

## How it works

```
Guest VM (libkrun, <1s boot)
  |
  |  virtio-fs (project dir read-write)
  |  virtio-net (ethernet frames over unix socket)
  v
smoltcp (userspace TCP/IP on host)
  |
  |-- UDP :53  -> synthetic DNS (all names resolve locally)
  |-- TCP :80  -> rejected (HTTPS only)
  |-- TCP :443 -> TLS MITM proxy
        |
        |-- SNI extraction
        |-- ephemeral cert (signed by per-session CA)
        |-- secret injection (headers only, host-allowlisted)
        |-- request forwarded to real upstream
        |-- response scrubbed of secret values
        |-- streamed back to guest
```

**Key properties:**
- Guest never sees real secret values (only placeholders)
- Secrets are injected only for explicitly allowed hosts
- Injection is restricted to HTTP headers (not URLs, not bodies)
- DNS is synthetic -- no queries reach the internet
- All traffic routes through the gateway IP (no direct IP access)
- Default-deny outbound networking
- Response scrubbing is best-effort (literal byte match)

## Secrets

Format: `ENV_VAR=value:allowed_host1,allowed_host2`

The value can be a literal or a provider URI:

```bash
# Literal value
--secret "GITHUB_TOKEN=ghp_abc123:api.github.com"

# From HashiCorp Vault (KV v2)
--secret "GITHUB_TOKEN=vault://secret/myapp#github_token:api.github.com"

# Multiple hosts
--secret "API_KEY=sk-abc:api.example.com,cdn.example.com"

# From a file (one spec per line, # comments)
--secret-file .redan-secrets

# Multiple secrets
--secret "GITHUB_TOKEN=ghp_abc:api.github.com" \
--secret "NPM_TOKEN=vault://secret/myapp#npm_token:registry.npmjs.org"
```

### Vault integration

Redan reads secrets from HashiCorp Vault KV v2 via `vault://path#field`.
Configure with standard Vault environment variables:

```bash
export VAULT_ADDR='https://vault.example.com:8200'
export VAULT_TOKEN='hvs.xxx'

redan exec --image claude-code \
  --secret "API_KEY=vault://myapp/prod#api_key:api.example.com"
```

Falls back to `~/.vault-token` if `VAULT_TOKEN` is not set.

### Provider architecture

Secret resolution is pluggable via the `SecretProvider` trait. The open
core ships with `Literal` and `Vault`. Enterprise adapters (Keycloak
OIDC, AWS Secrets Manager, etc.) implement the same trait.

The value can contain colons (splits on the last `:`). The guest
receives a `redan_ph_<name>_<hex>` placeholder via environment variable.

## Mounts

```bash
# Mount to /workspace (default)
--mount /home/chris/project

# Mount to specific guest path
--mount /home/chris/project:/code
```

Uses virtio-fs. The guest has read-write access. Git is your safety net.

## Image management

```bash
redan image create myimage --packages "python3 pip" --run "pip install flask"
redan image import myimage --from ubuntu:24.04
redan image import myimage --dockerfile path/to/Dockerfile
redan image import myimage --devcontainer .devcontainer
redan image list
redan image remove myimage
```

`create` builds Alpine-based images. `import` supports Docker images,
Dockerfiles, and devcontainers (all three spec modes: `build.dockerfile`,
`image`, `dockerComposeFile`).

Images are rootfs directories stored at `~/.local/share/redan/images/`.
Base tarballs cached at `~/.cache/redan/`.

## Requirements

- Linux x86_64 with KVM (`/dev/kvm`)
- [libkrun] >= 1.9.0 and [libkrunfw]
- Rust 1.85+ (edition 2024)

## Configuration

Use `redan.toml` instead of long CLI invocations. `redan init` generates
one from project detection:

```bash
redan init          # detect project type, generate config
redan init --claude # generate config + devcontainer for Claude Code
```

Example `redan.toml`:

```toml
image = "myproject"
command = "claude --dangerously-skip-permissions"
interactive = true

[network]
allow = ["api.anthropic.com", "pypi.org"]

[secrets.ANTHROPIC_API_KEY]
value = "sk-ant-..."
hosts = ["api.anthropic.com"]

[mount.workspace]
source = "."
target = "/workspace"

[env]
CLAUDE_CONFIG_DIR = "/workspace/.claude"
```

Looks for `redan.toml` in the current directory, then
`~/.config/redan/config.toml`. CLI flags override file values.

## Network policy

Redan defaults to **deny-all** outbound networking. You must explicitly
allow hosts:

```toml
[network]
allow = ["api.anthropic.com", "registry.npmjs.org"]
```

Or on the CLI:

```bash
redan exec --allow-host api.anthropic.com --allow-host registry.npmjs.org
```

Wildcard patterns are supported: `"*.amazonaws.com"` matches any
subdomain. Hosts required by secrets are automatically included.
Use `"*"` to allow all outbound connections (not recommended).

Connections to private IP ranges (RFC 1918, link-local, cloud metadata
endpoints) are blocked by default, even in allow-all mode. Hosts
explicitly in the allowlist may resolve to private IPs -- add
`"localhost"` if you need local services.

Domain fronting is blocked: requests where the HTTP Host header doesn't
match the TLS SNI hostname are rejected (HTTP 421).

### Discover mode

Don't know what hosts your agent needs? Run once in discover mode:

```bash
redan exec --image myimage --discover --command "claude --print 'build this project'"
```

Redan allows all connections and prints the observed hosts at exit:

```
--- discovered hosts ---
The agent connected to these hosts:

  api.anthropic.com
  registry.npmjs.org

Suggested redan.toml:

[network]
allow = [
    "api.anthropic.com",
    "registry.npmjs.org",
]
```

Copy the output into your `redan.toml` and subsequent runs enforce it.

### Claude Code integration

Redan reads `sandbox.network.allowedDomains` from Claude Code settings
(`.claude/settings.json`, `.claude/settings.local.json`, and user-level
`~/.claude/settings.json`). Domains are merged into the allowlist
automatically, so you define network policy once and redan enforces it
with VM isolation.

```json
{
  "sandbox": {
    "network": {
      "allowedDomains": ["api.anthropic.com", "*.npmjs.org"]
    }
  }
}
```

## Sessions

Each `redan exec` creates a session with a unique ID. Session metadata,
logs, and audit events are stored at `~/.local/state/redan/sessions/`.

```bash
redan sessions                # list all sessions
redan sessions show <id>      # session details
redan sessions remove         # remove all exited sessions
redan sessions remove <id>    # remove a specific session
redan logs                    # logs from most recent session
redan logs -f                 # tail -f
redan logs <id>               # logs from a specific session
```

## Audit log

```bash
redan exec --audit-log events.jsonl ...
```

Structured JSON-lines event log for security audit and debugging:

```json
{"ts":"...","event":"connect","host":"api.github.com"}
{"ts":"...","event":"inject","host":"api.github.com","env":"API_KEY"}
{"ts":"...","event":"scrub","host":"api.github.com"}
{"ts":"...","event":"reject","host":"evil.com","reason":"not_allowed"}
```

Audit logs are also stored per-session automatically.

## Agent awareness

Redan exposes network policy to the guest so AI agents can understand
their environment instead of guessing "the internet is broken":

**Environment variables:**
- `REDAN=1` -- running inside a redan sandbox
- `REDAN_NETWORK=restrict|deny-all|allow-all` -- policy mode
- `REDAN_ALLOWED_HOSTS=host1,host2,...` -- permitted outbound hosts

**Policy file:** `/etc/redan/policy` -- human-readable description of
what's allowed and what's blocked.

Agents that check `$REDAN` can adapt their behavior: skip web searches,
avoid fetching URLs outside the allowlist, and give users clear error
messages instead of "connection failed".

**Planned: Agent config integration.** redan will read agent-native
sandbox configs (e.g. `.claude/settings.json` `sandbox.allowedDomains`)
and enforce them at the network layer. This means teams define network
policy once in their agent config, and redan enforces it in the VM where
it can't be bypassed. redan can also generate agent configs that tell the
agent it's running in a trusted sandbox (e.g. Claude Code's
`--dangerously-skip-permissions`), reducing permission prompts while
maintaining real isolation. The goal: agent-native configs as the
single source of truth, redan as the enforcement layer.

## Setup with Claude Code

```bash
redan init --claude
redan image import myproject --devcontainer .devcontainer/redan
redan exec
```

`redan init --claude` generates a devcontainer with Claude Code, Node.js,
and project-appropriate tooling (Python/uv, Rust, Go, etc.) plus a
`redan.toml` with Anthropic API hosts pre-configured.

Devcontainer support works with all three spec modes: `build.dockerfile`,
`image`, and `dockerComposeFile`.

## Security model

Redan's threat model: a compromised or malicious AI agent running inside
the VM tries to exfiltrate secrets or access unauthorized resources.

**What redan prevents:**
- Agent reading real secret values from environment
- Agent sending secrets to unauthorized hosts
- Agent making DNS queries to the internet
- Agent connecting directly to IP addresses (all traffic goes through proxy)
- Agent reaching hosts not in the allowlist (default-deny networking)

**Known limitations:**
- Scrubbing doesn't catch encoded secrets (base64, URL-encoding, etc.)
- Domain fronting could route secrets to attacker-controlled backends
  behind CDNs
- No HTTP request body inspection (secrets in headers only)

Primary defense is the host allowlist, not scrubbing. Scrubbing reduces
accidental exposure; it's not a hard security boundary.

See [docs/security-model.md](docs/security-model.md) for the full
threat model, side-channel analysis, and known limitations.

## Status

**Alpha.** The full chain works end-to-end: `redan init --claude` through
interactive Claude Code sessions with network policy enforcement. Not
yet packaged for binary distribution.

## Acknowledgments

- [libkrun] and [libkrunfw] -- microVM engine and guest firmware
- [smoltcp] -- userspace TCP/IP stack
- [rustls] and [rcgen] -- TLS implementation and certificate generation
- [Gondolin] -- network-layer secret injection pattern for agent sandboxes

## License

[BSD-3-Clause](LICENSE)

[libkrun]: https://github.com/containers/libkrun
[libkrunfw]: https://github.com/containers/libkrunfw
[smoltcp]: https://github.com/smoltcp-rs/smoltcp
[rustls]: https://github.com/rustls/rustls
[rcgen]: https://github.com/rustls/rcgen
[Gondolin]: https://github.com/earendil-works/gondolin
