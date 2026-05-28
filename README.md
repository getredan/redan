<p align="center">
  <img src="assets/logo.jpg" alt="Redan" width="600">
  <p align="center">Your agents run free. Your secrets stay put.</p>
</p>

<p align="center">
  <a href="https://github.com/getredan/redan/actions/workflows/ci.yml"><img src="https://github.com/getredan/redan/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/getredan/redan/actions/workflows/security-audit.yml"><img src="https://github.com/getredan/redan/actions/workflows/security-audit.yml/badge.svg" alt="Security Audit"></a>
  <a href="https://github.com/getredan/redan/releases"><img src="https://img.shields.io/github/v/release/getredan/redan" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSD--3--Clause-blue.svg" alt="License: BSD-3-Clause"></a>
</p>

## Why redan?

AI coding agents have your shell, your filesystem, your API keys, and
full network access. That's fine until:

- A prompt injection hidden in a dependency's README or issue comment
  tells the agent to exfiltrate your API keys
- The agent modifies `~/.ssh/authorized_keys`, `~/.gitconfig`, or
  installs packages on your host
- Malicious instructions in code the agent reads make it open
  connections to hosts you never approved

These aren't hypothetical. Every file the agent reads is a potential
injection vector, and LLM prompt injection is an open problem with no
general solution.

Redan puts the agent in a [libkrun] microVM that boots in under a second.
The agent gets a real Linux dev environment with your project mounted in,
but it's isolated from your host: own filesystem, own network, only the
hosts you allow. Your API keys never enter the VM. Redan injects them at
the network layer, only for the hosts you permit. Even if the agent is
fully compromised, it has no secret to steal and nowhere to send it.

> *redan (/ɹɪˈdan/): a V-shaped fieldwork forming a salient angle toward
> the enemy.*

## Getting started

Redan requires Linux with KVM (`/dev/kvm`) and [libkrun].

**Install libkrun:**

```bash
# Arch
pacman -S libkrun

# Fedora
dnf install libkrun-devel

# Ubuntu/Debian (not yet in repos, build from source)
apt install build-essential libkrunfw-dev
git clone https://github.com/containers/libkrun
cd libkrun && make && sudo make install
```

**Install redan:**

[Pre-built binaries](https://github.com/getredan/redan/releases) for
Linux x86_64 and aarch64, or build from source (Rust 1.92+):

```bash
cargo install --git https://github.com/getredan/redan.git
```

**Verify:**

```bash
redan doctor
```

## Claude Code (zero-config)

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
  Mounting current directory → /workspace
```

Git remote hosts are added to the network allowlist automatically so
git push/pull works out of the box. The agent runs as an unprivileged
user inside the VM (not root), matching how Claude Code expects to
operate.

Auto-detect kicks in when there's no `redan.toml` and no explicit CLI
flags. For OAuth-based auth (Claude Max/Team/Enterprise), redan detects
your `~/.claude` credentials and mounts them read-only instead.

## Any agent

Redan works with any command-line AI agent. Build an image, tell redan
what to run and what hosts to allow:

```bash
redan image create myimage --packages "python3 nodejs npm"
redan exec --image myimage \
  --secret "API_KEY=env://MY_API_KEY:api.example.com" \
  --mount ./my-project \
  -- my-agent --some-flag
```

Or use `redan.toml` for repeatable setups:

```toml
image = "myimage"
command = "my-agent --some-flag"
interactive = true

[network]
allow = ["api.example.com", "registry.npmjs.org"]

[secrets.API_KEY]
value = "env://MY_API_KEY"
hosts = ["api.example.com"]

[mount.workspace]
source = "."
target = "/workspace"

[env]
MY_SETTING = "value"
```

`redan init` generates a config from project detection. `redan init --claude`
adds a devcontainer with Claude Code, Node.js, and project-appropriate
tooling.

## Secrets

Secrets are injected into HTTPS request headers by the proxy on the host
side. The agent only sees placeholder tokens. Format:
`ENV_VAR=value:allowed_hosts`

```bash
# Literal
--secret "GITHUB_TOKEN=ghp_abc123:api.github.com"

# From host env var (read at startup, never passed to VM)
--secret "GITHUB_TOKEN=env://GITHUB_TOKEN:api.github.com"

# From HashiCorp Vault KV v2
--secret "API_KEY=vault://secret/myapp#api_key:api.example.com"

# Multiple hosts
--secret "API_KEY=sk-abc:api.example.com,cdn.example.com"

# From a file (one spec per line, # comments)
--secret-file .redan-secrets
```

`env://` and `vault://` keep secrets out of process listings. Vault
falls back to `~/.vault-token` if `VAULT_TOKEN` is not set.

**Note:** Redan injects into HTTP headers only. Auth patterns that need
secrets in request bodies (OAuth token exchanges, AWS SigV4), TLS
handshakes (mTLS), or cookies are not supported for injection. Redan
still provides VM isolation and network restriction for those cases,
you just pass the credential via environment variable.

## Network policy

Default-deny outbound. You must explicitly allow hosts:

```bash
redan exec --allow-host api.anthropic.com --allow-host registry.npmjs.org
```

Wildcard patterns work: `"*.amazonaws.com"` matches any subdomain.
Hosts required by secrets are included automatically. Connections to
private IP ranges (RFC 1918, link-local, cloud metadata) are blocked
even in allow-all mode. Domain fronting is blocked: HTTP Host must
match TLS SNI.

**Discover mode** lets you figure out what hosts the agent needs:

```bash
redan exec --discover -- my-agent --some-flag
```

Redan allows all connections, prints the observed hosts at exit, and
generates a `[network]` config block you can paste into `redan.toml`.

## Browser support

For agents that need web access (research, testing, scraping), redan
can launch headless Chrome on the host with CDP (Chrome DevTools
Protocol) access from the guest:

```bash
redan exec --browser --allow-host "*.example.com"
```

Chrome runs on the host, not in the VM. Its outbound traffic goes
through an allowlist proxy that enforces the same host restrictions
as the main proxy, including SSRF protection for private IPs. The
agent controls Chrome via CDP through port forwarding.

The guest gets these env vars:
- `REDAN_BROWSER=1`
- `REDAN_BROWSER_HOST` (gateway IP to connect to)
- `REDAN_BROWSER_CDP_PORT` (CDP port, default 9222)

Chrome's sandbox stays enabled. The VM isolates the agent, Chrome's
sandbox protects the host.

Requires Chromium or Google Chrome installed on the host.
`redan doctor` checks for it.

## Port forwarding

Forward TCP ports from guest to host, useful for dev servers, databases,
or services running on the host that the agent needs to reach:

```bash
# Same port both sides
redan exec --forward 8080

# Different ports: guest connects to 3000, redan relays to host 8080
redan exec --forward 3000:8080
```

In `redan.toml`:

```toml
[network]
forward = ["8080", "3000:8080"]
```

The guest connects to the gateway IP on the guest port; redan relays
to `127.0.0.1` on the host port.

## Mounts

```bash
--mount /home/chris/project              # mounts to /workspace
--mount /home/chris/project:/code        # custom guest path
--mount /home/chris/.config/tool:ro      # read-only
--mount /home/chris/.ssh:/ssh-keys:ro    # host config, read-only
```

Uses virtio-fs for host directory sharing. The guest has read-write
access by default. Append `:ro` for read-only. Git is your safety net
for recovering from unwanted changes to mounted directories.

## Image management

```bash
redan image create myimage --packages "python3 pip" --run "pip install flask"
redan image import myimage --from ubuntu:24.04
redan image import myimage --dockerfile path/to/Dockerfile
redan image import myimage --devcontainer .devcontainer
redan image list
redan image update myimage    # rebuild from original source
redan image remove myimage
```

`create` builds Alpine-based images. `import` pulls from Docker images,
Dockerfiles, or devcontainer configs. `update` remembers how the image
was built and rebuilds from the same source. `redan doctor` warns about
images older than 30 days.

## Sessions

```bash
redan exec -d --name my-agent    # run in background
redan logs my-agent -f           # tail the logs
redan attach my-agent            # reconnect
redan stop my-agent              # SIGTERM, wait 3s, SIGKILL

redan sessions                   # list all
redan sessions show <id>         # details
redan sessions remove            # clean up exited sessions
```

## Audit log

```bash
redan exec --audit-log events.jsonl
```

JSON-lines event log: connections, injections, scrubs, rejections.
Also stored per-session automatically.

## Agent awareness

Redan tells the guest about its environment so agents can adapt
instead of hitting mysterious "connection failed" errors:

- `REDAN=1` (running in a redan sandbox)
- `REDAN_NETWORK=restrict|deny-all|allow-all` (policy mode)
- `REDAN_ALLOWED_HOSTS=host1,host2,...` (permitted hosts)
- `/etc/redan/policy` (human-readable policy file)

## How it works

```text
Guest VM (libkrun, <1s boot)
  |
  |  virtio-fs (project dir)
  |  virtio-net (ethernet frames over unix socket)
  v
smoltcp (userspace TCP/IP on host)
  |
  |-- UDP :53  -> synthetic DNS (per-host IP allocation)
  |-- TCP :22  -> transparent relay (allowlist checked)
  |-- TCP :80  -> rejected (HTTPS only)
  |-- TCP :443 -> TLS MITM proxy
  |     |-- SNI extraction, ephemeral cert
  |     |-- secret injection (headers, host-scoped)
  |     |-- response scrubbing (literal byte match)
  |     '-- forwarded to real upstream
  |-- TCP fwd -> port forwarding to host localhost
  v
internet (allowed hosts only)
```

DNS is synthetic (no queries leave the host), all traffic routes through
the gateway (no direct IP access), and HTTP/1.1 only (HTTP/2 binary
framing would bypass header parsing). SSH on port 22 is forwarded as-is
with allowlist enforcement but no injection/scrubbing.

## Security model

Redan's threat model: a compromised or malicious AI agent inside the VM
tries to exfiltrate secrets or access unauthorized resources.

**What redan prevents:** agent reading real secret values, sending
secrets to unauthorized hosts, making DNS queries to the internet,
connecting directly to IP addresses, reaching hosts not in the
allowlist.

**Known limitations:** scrubbing is literal byte match (doesn't catch
base64/URL-encoded secrets), no request body inspection, HTTP/1.1 only.
Primary defense is the host allowlist, not scrubbing. Scrubbing reduces
accidental exposure; it's not a hard security boundary.

See [docs/security-model.md](docs/security-model.md) for the full
threat model and side-channel analysis.

## Platform

Linux only. Requires KVM (`/dev/kvm`). x86_64 and aarch64.

libkrun supports macOS via Hypervisor.framework but this is untested.
No Windows support (WSL2 with KVM passthrough may work, untested).

## Status

Alpha. The full chain works end-to-end: `redan init --claude` through
interactive Claude Code sessions with network policy enforcement.
Pre-built binaries on
[GitHub Releases](https://github.com/getredan/redan/releases).

This code has not been through an independent security audit. Use at
your own risk and report vulnerabilities responsibly.

## Support

If redan is useful to you, consider [buying me a coffee](https://buymeacoffee.com/cgrebs).

## Acknowledgments

- [libkrun] and [libkrunfw] for the microVM engine and guest firmware
- [smoltcp] for the userspace TCP/IP stack
- [rustls] and [rcgen] for TLS and certificate generation
- [Gondolin] for the network-layer secret injection pattern

## License

[BSD-3-Clause](LICENSE)

[libkrun]: https://github.com/containers/libkrun
[libkrunfw]: https://github.com/containers/libkrunfw
[smoltcp]: https://github.com/smoltcp-rs/smoltcp
[rustls]: https://github.com/rustls/rustls
[rcgen]: https://github.com/rustls/rcgen
[Gondolin]: https://github.com/earendil-works/gondolin
