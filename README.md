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

## Installation

Redan requires Linux with KVM (`/dev/kvm`) and libkrun.

### Arch Linux

```bash
pacman -S libkrun
```

### Fedora

```bash
dnf install libkrun-devel
```

### Ubuntu / Debian

libkrun is not yet in the Ubuntu/Debian repositories. Build from source:

```bash
apt install build-essential libkrunfw-dev
git clone https://github.com/containers/libkrun
cd libkrun && make && sudo make install
```

### Then install redan

[Pre-built binaries for Linux x86_64 and aarch64 are available on the
releases page.](https://github.com/getredan/redan/releases) Download,
extract, and move to your `$PATH`:

```bash
tar xzf redan-*.tar.gz
sudo mv redan /usr/local/bin/
```

Or build from source (requires Rust 1.85+, edition 2024):

```bash
cargo install --git https://github.com/getredan/redan.git
```

Verify everything works:

```bash
redan doctor
```

## Setup with Claude Code

### Zero-config (recommended)

Set your API key and run:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
cd ~/my-project
redan exec
```

That's it. Redan auto-detects Claude Code: picks up your API key,
builds the `claude-code` image if needed, mounts the current directory,
allows Anthropic's API hosts, and drops you into an interactive session.
It prints what it chose so nothing is silent:

```text
  Using image: claude-code
  Injecting ANTHROPIC_API_KEY for api.anthropic.com
  Mounting ~/.gitconfig
  Mounting ~/.ssh
  Mounting current directory → /workspace
```

Auto-detect kicks in when there's no `redan.toml` and no explicit CLI
flags. Your `~/.gitconfig` and `~/.ssh` are mounted into the VM
automatically so git works out of the box.

### With redan.toml

For repeatable setups, use `redan init`:

```bash
redan init --claude
redan image import myproject --devcontainer .devcontainer/redan
redan exec
```

`redan init --claude` generates a devcontainer with Claude Code, Node.js,
and project-appropriate tooling (Python/uv, Rust, Go, etc.) plus a
`redan.toml` with Anthropic API hosts pre-configured.

### Manual

```bash
redan image import claude-code --dockerfile dockerfiles/claude-code.dockerfile
redan exec --image claude-code -i \
  --secret "ANTHROPIC_API_KEY=sk-ant-...:api.anthropic.com" \
  --mount ./my-project
```

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

Redan also reads `sandbox.network.allowedDomains` from Claude Code
settings (`.claude/settings.json` and `~/.claude/settings.json`) and
merges them into the network allowlist automatically.

## Quick start

### Run an agent (zero-config)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
redan exec
```

The agent sees `$ANTHROPIC_API_KEY` as a placeholder token. The proxy
injects the real key only in HTTPS requests to `api.anthropic.com`.
Responses are scrubbed of the real value before the agent sees them.

### Run in the background

```bash
redan exec -d --name my-agent
redan logs my-agent -f           # tail the logs
redan stop my-agent              # stop when done
```

### Run with explicit config

```bash
redan exec --image claude-code \
  --secret "ANTHROPIC_API_KEY=sk-ant-...:api.anthropic.com" \
  --mount ./my-project \
  -- claude --print "review this project"
```

**Note:** `--secret` literal values are visible in process listings (`ps`).
For production use, prefer `env://`, `vault://`, or `--secret-file`,
which keep secrets out of process listings by having redan read them
internally.

### Check prerequisites

```bash
redan doctor                         # system checks
redan doctor --image myimage         # check a specific image exists
redan doctor --secret "KEY=val:host" # validate secret syntax + providers
```

Checks for /dev/kvm, libkrun, libkrunfw, available images, and
whether `ANTHROPIC_API_KEY` is set (for zero-config Claude Code).

## How it works

```
Guest VM (libkrun, <1s boot)
  |
  |  virtio-fs (project dir read-write)
  |  virtio-net (ethernet frames over unix socket)
  v
smoltcp (userspace TCP/IP on host)
  |
  |-- UDP :53  -> synthetic DNS (per-host IP allocation)
  |-- TCP :22  -> transparent relay (allowlist checked, no injection)
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
- DNS is synthetic -- each hostname gets a unique IP, no queries leave the host
- All traffic routes through the gateway IP (no direct IP access)
- Default-deny outbound networking
- Response scrubbing is best-effort (literal byte match)

## Secrets

Format: `ENV_VAR=value:allowed_host1,allowed_host2`

The value can be a literal or a provider URI:

```bash
# Literal value
--secret "GITHUB_TOKEN=ghp_abc123:api.github.com"

# From host environment variable
--secret "GITHUB_TOKEN=env://GITHUB_TOKEN:api.github.com"

# From HashiCorp Vault (KV v2)
--secret "GITHUB_TOKEN=vault://secret/myapp#github_token:api.github.com"

# Multiple hosts
--secret "API_KEY=sk-abc:api.example.com,cdn.example.com"

# From a file (one spec per line, # comments)
--secret-file .redan-secrets

# Multiple secrets
--secret "GITHUB_TOKEN=env://GITHUB_TOKEN:api.github.com" \
--secret "NPM_TOKEN=vault://secret/myapp#npm_token:registry.npmjs.org"
```

In `redan.toml`:

```toml
[secrets.GITHUB_TOKEN]
value = "env://GITHUB_TOKEN"
hosts = ["api.github.com"]
```

### Environment variable provider

`env://VAR_NAME` reads the secret from a host environment variable at
session start. The variable is read on the host and never passed into
the VM.

```bash
export GITHUB_TOKEN=ghp_abc123
redan exec --secret "GITHUB_TOKEN=env://GITHUB_TOKEN:api.github.com"
```

Fails loudly if the variable is not set or is empty.

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
core ships with `Literal`, `Env`, and `Vault` providers. The trait is
designed for extension -- additional backends (AWS Secrets Manager,
1Password, etc.) can be added in the future.

The value can contain colons (splits on the last `:`). The guest
receives a `redan_ph_<name>_<hex>` placeholder via environment variable.

## Mounts

```bash
# Mount to /workspace (default)
--mount /home/chris/project

# Mount to specific guest path
--mount /home/chris/project:/code
```

Uses virtio-fs for host directory sharing. The guest has read-write
access, and git is your safety net for recovering from unwanted changes.

## Image management

```bash
redan image create myimage --packages "python3 pip" --run "pip install flask"
redan image import myimage --from ubuntu:24.04
redan image import myimage --dockerfile path/to/Dockerfile
redan image import myimage --devcontainer .devcontainer
redan image list
redan image update myimage
redan image remove myimage
```

`create` builds Alpine-based images with apk packages. `import` pulls
from Docker images, builds from Dockerfiles, or reads devcontainer
configs (`build.dockerfile`, `image`, and `dockerComposeFile` are all
supported).

Images are rootfs directories stored at `~/.local/share/redan/images/`
and base tarballs are cached at `~/.cache/redan/`.

### Image freshness

Redan tracks when images were built and from what source. `redan image
list` shows the age of each image, `redan doctor` warns about images
older than 30 days, and `redan exec` prints a non-blocking warning
before launching.

```bash
redan image update claude-code   # rebuild from the original Dockerfile
```

`redan image update` remembers how the image was built (Dockerfile,
Docker image, devcontainer, or `create` args) and rebuilds from
the same source.

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
redan exec --image myimage --discover -- claude --print "build this project"
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

## Sessions

Each `redan exec` creates a session with a unique ID. Session metadata,
logs, and audit events are stored at `~/.local/state/redan/sessions/`.

### Detached sessions

Run agents in the background:

```bash
redan exec -d                    # detach, auto-generated ID
redan exec -d --name my-agent    # detach with a name
```

### Session management

```bash
redan sessions                # list all sessions (shows name, status, age)
redan sessions show <id>      # session details
redan sessions remove         # remove all exited sessions
redan sessions remove <id>    # remove a specific session
```

### Attach and stop

```bash
redan attach                  # attach to most recent running session
redan attach my-agent         # attach by name or ID prefix
redan stop                    # stop most recent running session
redan stop my-agent           # stop by name or ID prefix
```

`redan stop` sends SIGTERM, waits 3 seconds, then SIGKILL.

### Logs

```bash
redan logs                    # logs from most recent session
redan logs -f                 # tail -f
redan logs my-agent           # logs by name or session ID
```

## Audit log

```bash
redan exec --audit-log events.jsonl ...
```

Structured JSON-lines event log for security audit and debugging:

```jsonl
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
- No HTTP request body inspection (secrets in headers only)

Primary defense is the host allowlist, not scrubbing. Scrubbing reduces
accidental exposure; it's not a hard security boundary.

See [docs/security-model.md](docs/security-model.md) for the full
threat model, side-channel analysis, and known limitations.

## Limitations

Be aware of what redan does and doesn't support before deploying it.

### Supported auth patterns

- `Authorization: Bearer <token>` -- standard API key injection
- Custom headers (`X-Api-Key`, etc.) -- any header-based auth
- Multiple secrets to multiple hosts in one session

### Unsupported auth patterns

These patterns require secrets in places redan currently can't inject:

- **OAuth flows** -- token exchanges happen in request/response bodies
- **AWS SigV4** -- request signing requires the secret at the call site
  to compute HMAC over headers and body
- **Client certificates** -- mTLS requires the cert in the TLS handshake,
  which redan terminates
- **Body-embedded tokens** -- GraphQL variables, form fields, JSON bodies
  carrying auth tokens
- **Cookie-based auth** -- `Set-Cookie` from login flows, session tokens

If your API requires one of these, redan can still provide VM isolation
and network restriction, but can't inject or scrub the credential.
Pass it via environment variable (the guest sees the real value).

### Protocol constraints

- **HTTP/1.1 only.** Redan forces ALPN to `http/1.1`. All major APIs
  (Anthropic, OpenAI, GitHub, npm) support HTTP/1.1. If a server
  requires HTTP/2, it won't work through redan.
- **No WebSocket.** Upgrade requests return 501. Binary framing after
  the upgrade would bypass scrubbing.
- **SSH is transparent.** Port 22 connections are forwarded as-is to
  the real upstream server. No secret injection or scrubbing -- SSH
  handles its own authentication. The allowlist still applies.
- **No other raw TCP/UDP.** Database connections, gRPC (over H2), and
  other protocols are not currently supported.
- **HTTPS only.** Plain HTTP on port 80 is rejected.

### Platform

- **Linux only.** Requires KVM (`/dev/kvm`). libkrun supports macOS
  via Hypervisor.framework but this is untested.
- **x86_64 and aarch64.** Other architectures are untested.
- **No Windows.** WSL2 with KVM passthrough may work but is untested.

## Status

**Alpha.** The full chain works end-to-end: `redan init --claude` through
interactive Claude Code sessions with network policy enforcement.
Pre-built binaries for Linux x86_64 and aarch64 on
[GitHub Releases](https://github.com/getredan/redan/releases).

This code has not been through an independent security audit. Use at
your own risk and report vulnerabilities responsibly.

## Support

If redan is useful to you, consider [buying me a coffee](https://buymeacoffee.com/cgrebs).

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
