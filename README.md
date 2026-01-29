<p align="center">
  <img src="assets/logo.jpg" alt="Redan" width="600">
  <p align="center">Your agents run free. Your secrets stay put.</p>
</p>

# What's Redan?

Redan runs AI coding agents inside [libkrun] microVMs with network-layer
secret injection. Agents get a real dev environment -- node, git, python,
your project files -- but can't see host credentials, can't reach hosts
you didn't allow, and never observe the real values of injected secrets.

> *redan (/ɹɪˈdan/): a V-shaped fieldwork forming a salient angle toward
> the enemy.*

## How it works

1. `redan exec` boots a [libkrun] microVM (<1s)
2. Your project directory is mounted read-write via virtio-fs
3. All network traffic routes through a userspace TCP/IP stack ([smoltcp])
4. A MITM proxy intercepts TLS, injects secrets, enforces an allowlist
5. The agent sees placeholder tokens, never real values
6. An audit log on the host records every network request


## Status

**Pre-alpha.** The prototype chain is proven end-to-end: VM boot,
virtio-fs mounts, synthetic DNS, TLS MITM, secret injection/scrubbing,
and Claude Code making API calls through the proxy. Not yet packaged
for distribution.

## Requirements

- Linux x86_64 with KVM
- [libkrun] and [libkrunfw]
- Rust 1.75+

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
