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
For production use, prefer the Vault provider (`vault://`) or set
secrets in environment variables and pass them through:
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
redan doctor
```

Checks for /dev/kvm, libkrun, libkrunfw, and lists available images.

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
--secret "API_KEY=sk-abc:api.example.com, cdn.example.com"

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
redan image list
redan image remove myimage
```

Images are Alpine-based rootfs directories stored at
`~/.local/share/redan/images/`. Base tarballs cached at `~/.cache/redan/`.

## Requirements

- Linux x86_64 with KVM (`/dev/kvm`)
- [libkrun] >= 1.9.0 and [libkrunfw]
- Rust 1.85+ (edition 2024)

## Security model

Redan's threat model: a compromised or malicious AI agent running inside
the VM tries to exfiltrate secrets or access unauthorized resources.

**What redan prevents:**
- Agent reading real secret values from environment
- Agent sending secrets to unauthorized hosts
- Agent making DNS queries to the internet
- Agent connecting directly to IP addresses (all traffic goes through proxy)

**Known limitations (documented, not bugs):**
- Scrubbing doesn't catch encoded secrets (base64, URL-encoding, etc.)
- Domain fronting could route secrets to attacker-controlled backends
  behind CDNs
- No HTTP request body inspection (secrets in headers only)

Primary defense is the host allowlist, not scrubbing. Scrubbing reduces
accidental exposure; it's not a hard security boundary.

## Status

**Alpha.** The full chain works end-to-end. 95 tests (unit,
integration, adversarial). Not yet packaged for binary distribution.

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
