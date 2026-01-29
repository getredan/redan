# redan

Secure, local-first execution environment for AI coding agents.

MicroVM isolation with network-layer secret injection. One binary. No cloud. No daemon.

> *redan (n.): a V-shaped fieldwork forming a salient angle toward the enemy.*

## What it does

Your AI agent runs inside a lightweight VM (libkrun). It can read and write your project files normally, but:

- **Can't see** your `~/.ssh`, `~/.aws`, shell history, or any host credentials
- **Can't reach** hosts you didn't explicitly allow
- **Can't leak** your API tokens - they're injected at the network layer, invisible to the agent
- **Can't hide** what it did - everything is logged to a tamper-proof audit trail

```bash
redan exec -- claude
# ✓ Agent runs in VM. Project files via virtio-fs.
# ✓ API tokens injected by MITM proxy. Agent sees placeholders.
# ✓ Network limited to allowlist. Raw IPs blocked.
# ✓ Audit log on host. Agent can't touch it.
```

## Quick start

```bash
# Install
curl -sSf https://redan.dev/install.sh | sh

# Verify
redan doctor

# Run (zero-config - auto-detects project type)
cd ~/my-project
redan exec -- claude
```

## Configuration

Optional. Zero-config works for common setups. Add `redan.toml` for precision:

```toml
image = "node:22"

[network]
allow = ["api.github.com", "api.openai.com", "registry.npmjs.org"]

[secrets.GITHUB_TOKEN]
source = "env"
for = ["api.github.com"]
```

Or generate one interactively:

```bash
redan init
```

## Secret backends

| Backend | Status | Use case |
|---------|--------|----------|
| Environment variables | MVP | Solo dev, CI |
| HashiCorp Vault | MVP | Teams, enterprises |
| AWS Secrets Manager | MVP | AWS-native teams |
| 1Password CLI | v1.0 | Solo dev, biometric unlock |
| Azure Key Vault | v1.0 | Azure-native teams |
| GCP Secret Manager | v1.0 | GCP-native teams |
| macOS Keychain | v1.0 | macOS developers |

## How it works

1. `redan exec` boots a libkrun microVM (~200-500ms)
2. Your project directory is mounted via virtio-fs (read-write)
3. All network traffic routes through a host-side MITM proxy
4. The proxy enforces your allowlist and injects secrets into HTTP headers
5. The agent sees placeholder tokens, never real values
6. Everything is logged to `$XDG_STATE_HOME/redan/sessions/`

See [docs/planning/](docs/planning/) for the full architecture.

## Requirements

- Linux x86_64 with KVM (primary)
- macOS aarch64 with HVF (conditional - validating in prototype)
- libkrun

## Status

**Pre-alpha.** Architecture designed, oracle-reviewed. Running prototype spikes.

See [docs/planning/](docs/planning/) for:
- [Architecture](docs/planning/03-architecture.md)
- [Security model](docs/planning/04-security-model.md)
- [MVP scope](docs/planning/05-mvp-scope.md)
- [Risk register](docs/planning/08-risk-register.md)
- [Prototype plan](docs/planning/09-prototype-plan.md)

## Enterprise

[redan-enterprise](https://github.com/TODO/redan-enterprise) adds organizational management:

- Central policy server - push configs to developer machines
- Remote audit forwarding - syslog, SIEM, CloudWatch, Datadog
- Tamper-evident audit logs (HMAC chain)
- Organization-wide policy enforcement
- Agent identity management
- Compliance reporting

## Acknowledgments

Redan builds on great work by others:

- **[libkrun](https://github.com/containers/libkrun)** - the microVM engine at the heart of Redan. Created by Sergio Lopez and the containers team. libkrun's TSI (Transparent Socket Impersonation) networking and virtio-fs support make the "invisible VM" experience possible.
- **[libkrunfw](https://github.com/containers/libkrunfw)** - the guest kernel firmware bundled with libkrun.
- **[Gondolin](https://github.com/earendil-works/gondolin)** - Nicholas Charriere's agent sandbox that pioneered network-layer secret injection. Redan adopts Gondolin's core insight: inject secrets at the network proxy, not in the execution environment. Different implementation (Rust + libkrun vs JS + Apple Virtualization), same security model.
- **[microsandbox](https://github.com/zerocore-ai/microsandbox)** - closest existing project to Redan. Demonstrated that libkrun works well for AI agent sandboxing. Their daemon architecture informed our decision to go the other way (single process, no daemon).
- **[krunvm](https://github.com/containers/krunvm)** - CLI tool for managing libkrun microVMs. Reference for how to use the libkrun API.
- **[passt](https://passt.top/)** - userspace network stack that provides an alternative to TSI when full packet-level control is needed.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
