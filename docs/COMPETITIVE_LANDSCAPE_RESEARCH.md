# Agent Sandbox Security: Competitive Landscape & Technical Research

**Date:** February 8, 2026  
**Status:** Research Complete — Ready for Planning  
**Author:** Deep research session for Chris @ Kaiko Systems side project

---

## Executive Summary

The AI agent sandboxing market is bifurcating into **cloud-hosted** (E2B, Northflank, Modal, Vercel, Cloudflare) and **self-hosted/local** (microsandbox, Gondolin, Anthropic sandbox-runtime) solutions. A critical gap exists: **no existing solution addresses enterprise secret management for agents combined with local-first microVM isolation and single-binary distribution.**

The recommended approach is a **Rust-based CLI + SDK** using **libkrun** for microVM isolation, with a pluggable secret management layer. This positions the product as the missing piece between cloud-hosted platforms (which require moving off your infrastructure) and existing self-hosted tools (which lack enterprise secret management).

**Key insight:** "Your laptop is compute. Your agent has its own identity. Your security team controls the policy. Nobody moves to the cloud."

---

## 1. Competitive Landscape

### 1.1 Cloud-Hosted Solutions

#### E2B (https://e2b.dev/)
- **Isolation:** Firecracker microVMs
- **Startup:** ~150ms
- **SDKs:** Python, JavaScript
- **Session limit:** 24 hours (major constraint for long-running agents)
- **Deployment:** Cloud-only, no self-hosted option
- **License:** Open-source components
- **Pricing:** Usage-based
- **Strengths:** AI-first developer experience, polished SDKs, strong community
- **Weaknesses:** Session time limit, cloud lock-in, no BYOC

#### Northflank (https://northflank.com/)
- **Isolation:** Kata Containers (Cloud Hypervisor) OR gVisor — user choice
- **Startup:** ~200ms (Kata), faster with gVisor
- **Scale:** 2M+ isolated workloads monthly since 2019
- **Session limit:** Unlimited
- **Deployment:** BYOC (bring your own cloud)
- **Pricing:** GPU ~62% cheaper than competitors (CPU/RAM included)
- **Strengths:** Production-grade, multiple isolation options, complete platform (databases, GPU, CI/CD), active contributor to Kata/QEMU/containerd/Cloud Hypervisor
- **Weaknesses:** Full platform complexity when you only need sandboxes, cloud-focused
- **Enterprise users:** Sentry, governments, cto.new (30K+ users)

#### Daytona (https://www.daytona.io/)
- **Isolation:** Docker by default (weaker), Kata Containers available
- **Startup:** Sub-90ms cold starts (fastest in market)
- **Session limit:** Unlimited (stateful sandboxes)
- **License:** AGPL-3.0 (strong copyleft — network use triggers requirements, creates enterprise friction)
- **Funding:** Significant mid-2024 round
- **GitHub:** 21K+ stars
- **Strengths:** Fastest sandbox creation, stateful persistence, LSP support, desktop environments
- **Weaknesses:** Docker isolation by default is weaker than microVMs, AGPL license friction for enterprises, young platform still evolving
- **Pivot:** Early 2025 from dev environments to AI agent infrastructure

#### Modal
- **Isolation:** gVisor only (no microVM option)
- **Focus:** Python-centric ML workloads
- **Strengths:** Strong autoscaling, good Python DX
- **Weaknesses:** No BYOC, no on-prem, no microVM isolation, Python-only optimization

#### Vercel Sandbox (Beta)
- **Type:** Ephemeral compute primitive
- **Limits:** 45min (Hobby), 5hr (Pro/Enterprise)
- **Pricing:** Usage-based ($0.128/CPU-hr, $0.60/M sandbox creations)
- **Strengths:** Vercel ecosystem integration
- **Weaknesses:** Beta, time limits, Vercel lock-in

#### Cloudflare Sandboxes
- **Isolation:** Browser isolates (V8 isolates)
- **Languages:** Python, Node.js
- **Strengths:** Global edge distribution, free tier
- **Weaknesses:** V8 isolate model is weaker than microVMs, limited language support

### 1.2 Self-Hosted / Local Solutions

#### microsandbox (https://github.com/zerocore-ai/microsandbox)
- **Stars:** ~4.5K GitHub (launched May 2025, v0.1.x)
- **License:** Apache-2.0 (permissive — enterprise-friendly)
- **Language:** Rust
- **Isolation:** libkrun (KVM-based microVMs as library)
- **Startup:** Sub-200ms boot times
- **Platforms:** macOS (Apple Silicon via HVF), Linux (KVM)
- **OCI compatible:** Runs standard container images
- **AI integration:** MCP server for AI agents
- **Workflow:** Project-based (Sandboxfile manifest, like package.json)
- **CLI tools:** `msb` (management), `msx` (ephemeral), `msr` (project-based), `msi` (system-wide)
- **SDKs:** Python, Rust
- **State:** Persistent in `./menv` directory
- **Strengths:** Self-hosted only (core identity: "Your Infrastructure"), hardware-level VM isolation, permissive license, Rust-based
- **Weaknesses:** Early/experimental, no secret management, no Windows support (requested in #47), limited enterprise features, no network policy engine
- **Missing:** Windows support, secret management, enterprise policy, audit logging

#### Gondolin (https://github.com/earendil-works/gondolin)
- **Creator:** Armin Ronacher (mitsuhiko — Flask/Sentry creator), Berlin-based
- **Isolation:** QEMU micro-VMs
- **Control plane:** TypeScript/JavaScript (network stack + VFS entirely in JS)
- **Startup:** Sub-second boot
- **Architecture:** ARM64 only currently (x86_64 needed for broader adoption)
- **Key innovation:** Secret injection at network layer — guest never sees real API keys, only placeholders. Actual secrets injected by host only when making requests to approved hosts.
- **Network policy:** `allowedHosts` + per-secret host restrictions
- **Status:** Experimental, API stability uncertain
- **Usage:** Actively used by Armin Ronacher with Pi coding agent
- **Design choice:** QEMU over Firecracker because Firecracker cannot run on Macs
- **Strengths:** Brilliant secret injection model, JS-programmable network/filesystem, Mac+Linux parity
- **Weaknesses:** ARM64 only, experimental, bus factor (single creator), uncertain API stability

#### Anthropic sandbox-runtime (https://github.com/anthropic-experimental/sandbox-runtime)
- **Language:** TypeScript/Node.js
- **Isolation:** NOT microVM — uses OS primitives (bubblewrap on Linux, sandbox-exec/Seatbelt on macOS)
- **Weight:** Lightweight, no container overhead
- **Mechanism:** Filesystem isolation + network proxy filtering
- **Status:** Research preview, APIs may evolve
- **Package:** `@anthropic-ai/sandbox-runtime` (npm), CLI: `srt`
- **Usage:** Powers Claude Code sandboxed bash tool, 84% reduction in permission prompts
- **Web version:** Git proxy with scoped credentials, validates branch/repo before attaching real tokens
- **Limitations:**
  - Linux proxy bypass via environment variables (HTTP_PROXY) — programs can ignore
  - `enableWeakerNestedSandbox` mode for Docker environments considerably weakens security
- **Strengths:** Lightweight, no VM overhead, good enough for trusted developer use
- **Weaknesses:** Not microVM (weaker isolation), TypeScript (not single binary), proxy can be bypassed, research preview

#### Agent Sandbox (Kubernetes SIG Apps)
- **Repo:** kubernetes-sigs/agent-sandbox
- **Type:** Kubernetes controller for stateful pods with stable identity
- **API:** Declarative — Sandbox, SandboxTemplate, SandboxClaim resources
- **Feature:** WarmPools for <1s cold start
- **Announced:** November 2025 (Kubecon Atlanta)
- **Led by:** Google
- **Scale:** Designed for tens of thousands of parallel sandboxes
- **Strengths:** Kubernetes-native, standardized API, Google backing, enterprise scale
- **Weaknesses:** Requires Kubernetes (heavy), not for local developer use

#### UK AISI Inspect Sandboxing Toolkit
- **Purpose:** AI model evaluations, not production agents
- **Design:** Model execution outside sandbox, commands sent in
- **Isolation axes:** Tooling, host, network (modular)
- **Strengths:** Well-thought-out isolation taxonomy
- **Weaknesses:** Evaluation-focused, not production runtime

### 1.3 Competitive Landscape Summary Table

| Solution | Isolation | Local-first | Secret Mgmt | Single Binary | License | Maturity |
|----------|-----------|-------------|-------------|---------------|---------|----------|
| E2B | Firecracker microVM | ❌ Cloud-only | ❌ | N/A (SaaS) | Open-source | ✅ Production |
| Northflank | Kata/gVisor | ❌ Cloud/BYOC | ❌ | N/A (SaaS) | Proprietary | ✅ Production |
| Daytona | Docker/Kata | ❌ Cloud | ❌ | N/A (SaaS) | AGPL-3.0 | ⚠️ Young |
| microsandbox | libkrun microVM | ✅ | ❌ | ❌ (server+CLI) | Apache-2.0 | ⚠️ v0.1.x |
| Gondolin | QEMU microVM | ✅ | ✅ (network-layer) | ❌ (npm) | MIT | ⚠️ Experimental |
| Anthropic srt | OS primitives | ✅ | ❌ | ❌ (Node.js) | Research | ⚠️ Preview |
| K8s Agent Sandbox | Pod-level | ❌ Requires K8s | ❌ | N/A | Apache-2.0 | ⚠️ New |
| **Our product** | **microVM** | **✅** | **✅** | **✅** | **Permissive** | **Planned** |

---

## 2. MicroVM Technology Deep Dive

### 2.1 Firecracker
- **Origin:** AWS-developed, powers Lambda and Fargate
- **Performance:** ~125ms boot, <5 MiB overhead per VM, up to 150 VMs/sec/host
- **Isolation:** Hardware-level (dedicated kernel per workload). Attack requires escaping guest kernel AND hypervisor.
- **Language:** Rust
- **Limitation:** Linux only — cannot run on macOS (this is why Gondolin chose QEMU)
- **Status:** Industry standard for untrusted code execution

### 2.2 Kata Containers
- **Design:** Orchestrates multiple VMMs (Firecracker, Cloud Hypervisor, QEMU)
- **Integration:** Kubernetes-native, standard container APIs
- **Performance:** ~200ms boot
- **Behavior:** From K8s perspective: normal container. Under hood: full VM with hardware isolation.
- **Users:** Northflank, enterprise deployments

### 2.3 libkrun ⭐ (Recommended for our product)
- **Type:** Library-based virtualization (KVM on Linux, HVF on macOS/ARM64)
- **Developer:** Sergio Lopez Pascual (Senior Principal at Red Hat, Automotive Team)
- **Language:** Rust (94.1%)
- **Performance:** Sub-200ms startup, minimal overhead
- **API:** Simple C API, stable since v1.0.0 (SemVer)
- **Networking:** Two modes — virtio-vsock + TSI (Transparent Socket Impersonation) or virtio-net + passt/gvproxy
- **Platforms:** Linux (x86_64, aarch64), macOS (aarch64 via HVF)
- **Heritage:** Incorporates code from Firecracker, rust-vmm, and Cloud Hypervisor
- **Users:** microsandbox, Podman, crun (OCI runtime), RamaLama (AI model serving), muvm (gaming)
- **Variants:** libkrun (generic), libkrun-sev (AMD SEV), libkrun-tdx (Intel TDX), libkrun-efi (OVMF/EDK2 on macOS)
- **Strengths:** Virtualization as a library (embed in applications), cross-platform (Mac+Linux), active Red Hat maintenance, OCI-compatible through crun, mature (v1.0+)
- **Why chosen:** Only microVM solution that works on both macOS and Linux with a library API suitable for embedding

### 2.4 gVisor
- **Type:** User-space kernel, syscall interception
- **Isolation:** No full VM overhead, but shares host kernel (weaker than microVMs)
- **Users:** Modal, Northflank (as option), Google Cloud
- **Strengths:** Lower overhead than microVMs, good for trusted workloads
- **Weaknesses:** Kernel shared with host means kernel vulnerabilities could be exploited

### 2.5 Cloud Hypervisor
- **Type:** Modern VMM, part of rust-vmm project
- **Language:** Rust
- **Users:** Kata Containers, Northflank
- **Focus:** Cloud workloads, Rust ecosystem

### 2.6 Technology Comparison

| Technology | Boot Time | Memory Overhead | Isolation Level | Mac Support | Library API |
|------------|-----------|-----------------|-----------------|-------------|-------------|
| Firecracker | ~125ms | <5 MiB/VM | Hardware (strongest) | ❌ | ❌ (daemon) |
| Kata Containers | ~200ms | Moderate | Hardware (strongest) | ❌ | ❌ (K8s) |
| libkrun | <200ms | Minimal | Hardware (strongest) | ✅ (HVF) | ✅ (C API) |
| gVisor | Fast | Low | Kernel (medium) | ❌ | ❌ (runtime) |
| QEMU (Gondolin) | <1s | Moderate | Hardware (strongest) | ✅ (HVF) | ❌ (process) |
| OS primitives (Anthropic) | Instant | None | Process (weakest) | ✅ | ✅ |

**Winner for our use case: libkrun** — Only option with hardware-level isolation + macOS support + library API for embedding.

---

## 3. Security Analysis

### 3.1 Threat Model Consensus (Industry-Wide)

The industry has converged on several key security principles:

1. **Containers (Docker) are insufficient for untrusted AI-generated code.** They share the host kernel; kernel vulnerabilities allow container escape.
2. **Prompt injection is the primary attack vector.** Not just code bugs — agents can be manipulated to execute malicious operations.
3. **Defense-in-depth is required:** Filesystem isolation + network isolation together. Without network isolation: SSH key exfiltration. Without filesystem isolation: backdoor system resources for network access.
4. **All AI-generated code should be treated as potentially malicious** — zero-trust by default.
5. **83% of companies plan to deploy AI agents** — the attack surface is expanding rapidly.

### 3.2 Real-World Security Incidents

| Incident | Description | What Sandbox Would Prevent |
|----------|-------------|---------------------------|
| langflow RCE | Remote code execution discovered by Horizon3 | Code execution isolation |
| Cursor auto-execution | Vulnerability allowing RCE through auto-execution | Filesystem + network isolation |
| Replit database wipe-out | AI agent wiped production database | Filesystem + permission isolation |
| AWS Log4Shell Hot Patch | Container escape via Log4Shell | microVM isolation (kernel boundary) |

### 3.3 Gondolin's Secret Management Model (Best-in-Class)

Gondolin introduces a novel approach worth adopting:

```javascript
const { httpHooks, env } = createHttpHooks({
  allowedHosts: ["api.openai.com"],
  secrets: {
    OPENAI_API_KEY: {
      hosts: ["api.openai.com"],
      value: process.env.OPENAI_API_KEY,
    },
  },
});
```

**How it works:**
1. Guest VM receives only a **placeholder** for the API key
2. Host network layer **intercepts** outgoing HTTP requests
3. Only when the request targets an **approved host**, the real secret is injected
4. If prompt-injected code tries to exfiltrate the placeholder to an unauthorized server, it **cannot access the real secret**
5. Secrets **never touch the VM filesystem**

**This is the model we should implement**, extended with pluggable backends (Vault, AWS Secrets Manager, Azure Key Vault, 1Password CLI).

### 3.4 Claude Code Sandbox Model (Reference Implementation)

The Anthropic sandbox-runtime provides a lighter-weight model:

- **Filesystem:** Read-only except CWD, explicit allow/deny lists
- **Network:** Proxy-based filtering, domain allowlists
- **Permissions:** Auto-allow safe commands within boundaries, prompt only for out-of-bounds
- **Result:** 84% reduction in permission prompts in internal usage
- **Web version:** Git proxy with scoped credentials — validates branch/repo before attaching real tokens

**Limitation:** OS-level primitives (bubblewrap/Seatbelt) are weaker than microVMs, and the HTTP_PROXY mechanism can be bypassed by programs that ignore it.

---

## 4. Language & Runtime Analysis for Single Binary Distribution

### 4.1 Rust ⭐ (RECOMMENDED)

**Why Rust wins for this product:**

- **Proven for VM orchestration:** Firecracker, Cloud Hypervisor, microsandbox all written in Rust
- **Single binary distribution:** `cargo build --release` with static linking produces dependency-free executables
- **Cross-compilation:** Mature toolchain (cross, cargo-zigbuild)
- **rust-vmm ecosystem:** KVM bindings (kvm-ioctls, kvm-bindings), virtio-devices, vhost — building blocks for VM management
- **Memory safety:** Critical for a security product — no GC pauses, no use-after-free
- **Performance:** Comparable to C/C++, excellent for hot paths (network proxying, VM lifecycle)
- **Async runtime:** tokio provides excellent network I/O for proxy/filtering
- **Ecosystem:** clap (CLI), indicatif (progress), dialoguer (prompts), serde (serialization)
- **Distribution:** cargo-dist, GitHub releases with pre-built binaries
- **Precedent:** OpenAI rewrote Codex CLI from TypeScript to Rust in 2025 for performance

**Concerns:**
- Steeper learning curve than Go
- Longer compile times
- Async ecosystem complexity (tokio vs async-std)
- Team hiring pool smaller than Go

### 4.2 Go (Strong Alternative)

**Case for Go:**
- Fastest time-to-first-feature for CLI tools
- Single binary with excellent cross-compilation (`GOOS=linux GOARCH=amd64`)
- Dominant in DevOps/infrastructure tooling (Docker, Kubernetes, Terraform)
- Larger hiring pool, gentler learning curve
- Fast compile times, good developer iteration speed

**Case against Go for this product:**
- No existing VM orchestration ecosystem comparable to rust-vmm
- GC pauses (minor but real for VM lifecycle management)
- Less natural fit for low-level VM/hypervisor code
- Would need CGO for libkrun integration (complicates cross-compilation)

### 4.3 Zig (Niche Alternative)

- **Best-in-class cross-compilation** (even better than Rust): `zig build -target aarch64-linux`
- **Smallest binaries possible:** 2.5KB hello world with optimization flags
- **zig cc:** Drop-in GCC/Clang replacement, can cross-compile C/C++ projects trivially
- **Cons:** Language still evolving (breaking changes), smaller ecosystem, less mature for VM orchestration, smaller community
- **Verdict:** Consider for cross-compilation assistance (cargo-zigbuild), not as primary language

### 4.4 .NET NativeAOT (Not Recommended)

- **Precedent:** Aspire CLI is first major Microsoft CLI tool using NativeAOT (~15MB, instant startup)
- **.NET 10:** NativeAOT for dotnet tools, 50% startup reduction
- **Cons:** Windows-centric ecosystem, less proven for low-level VM work, larger binaries than Rust, ecosystem gaps for systems programming
- **Verdict:** Viable for CLI tools generally, but wrong ecosystem for VM orchestration

### 4.5 TypeScript/Node.js (Not Recommended for Single Binary)

- **Current Anthropic choice** for sandbox-runtime (TypeScript)
- **Current Claude Code / Gemini CLI choice** (TypeScript + React/Ink for TUI)
- **Reasoning:** "We wanted an 'on distribution' tech stack for Claude that it was already good at"
- **Cons:** Requires Node.js runtime, not true single binary, slower startup, less suitable for VM orchestration
- **Verdict:** Good for rapid prototyping, wrong for production security infrastructure

### 4.6 Language Decision Matrix

| Factor | Rust | Go | Zig | .NET NativeAOT | TypeScript |
|--------|------|-----|-----|-----------------|------------|
| VM ecosystem | ✅ rust-vmm | ❌ CGO needed | ❌ Immature | ❌ None | ❌ None |
| Single binary | ✅ Static linking | ✅ Native | ✅ Best size | ⚠️ ~15MB | ❌ Requires runtime |
| Cross-compilation | ✅ Good | ✅ Excellent | ✅ Best | ⚠️ Limited | ❌ N/A |
| Memory safety | ✅ Ownership model | ⚠️ GC | ✅ Manual+safe | ✅ GC | ⚠️ GC |
| Dev velocity | ⚠️ Slower initially | ✅ Fast | ⚠️ Evolving | ✅ Fast | ✅ Fastest |
| Hiring pool | ⚠️ Growing | ✅ Large | ❌ Small | ✅ Large | ✅ Largest |
| Precedent in space | ✅ Firecracker etc. | ⚠️ Docker/K8s | ❌ None | ❌ None | ⚠️ Anthropic srt |

**Recommendation: Rust** — the VM orchestration ecosystem (rust-vmm, libkrun) makes it the only language where you're not fighting against the grain.

---

## 5. Market Gaps & Product Positioning

### 5.1 Identified Gaps

1. **Local-first microVM + enterprise secret management** — NO ONE is doing this. microsandbox has microVMs but no secret management. Gondolin has secret management but is experimental/ARM64-only.

2. **Single binary distribution for agent sandboxing** — Every existing solution requires either a cloud account (E2B, Northflank), a server daemon + SDK (microsandbox, Daytona), npm (Gondolin, Anthropic srt), or Kubernetes (Agent Sandbox).

3. **Developer laptop as pure compute** — No solution fully embraces the model where secrets never land on disk and the laptop is treated as untrusted compute.

4. **Agent identity separate from developer identity** — Current solutions conflate the agent's permissions with the developer's credentials. No solution provides per-agent identity with scoped permissions.

5. **Open-source with commercial enterprise layer** — microsandbox (Apache-2.0) is closest but lacks enterprise features. Daytona uses AGPL (enterprise friction). E2B's open-source components don't cover the full stack.

### 5.2 Competitive Positioning

**vs. E2B / Northflank / Modal:** "Run locally. No cloud account. No session limits. No usage fees. Your infrastructure, your control."

**vs. microsandbox:** "Same microVM isolation, plus: enterprise secret management, network-layer secret injection, single binary distribution, pluggable policy engine."

**vs. Gondolin:** "Production-ready, not experimental. x86_64 + ARM64. Rust (not TypeScript). Single binary (not npm). Enterprise backends (Vault, AWS SM)."

**vs. Anthropic sandbox-runtime:** "Hardware-level isolation (microVM), not OS-level sandboxing. Secrets never touch the VM. Cannot be bypassed by ignoring HTTP_PROXY."

**vs. K8s Agent Sandbox:** "No Kubernetes required. Works on your laptop. Same security guarantees."

### 5.3 Timing

- Agent execution is moving from "developer toy" to "enterprise workflow" NOW
- Kubernetes SIG Apps launched Agent Sandbox (November 2025)
- 83% of companies plan to deploy AI agents
- Cursor generates ~1 billion lines of accepted code daily
- Security incidents increasing (langflow, Cursor, Replit)
- NVIDIA published sandbox security guidance 2 days ago (February 6, 2026)

---

## 6. Recommended Architecture (v1)

### 6.1 Core Components

```
┌─────────────────────────────────────────────┐
│                 Single Rust Binary           │
│                                              │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  │
│  │  CLI      │  │ SDK (lib) │  │ MCP      │  │
│  │  (clap)   │  │ (tokio)   │  │ Server   │  │
│  └─────┬─────┘  └─────┬─────┘  └────┬─────┘  │
│        │              │              │        │
│  ┌─────┴──────────────┴──────────────┴─────┐  │
│  │          Policy Engine                   │  │
│  │  (filesystem rules, network rules,       │  │
│  │   secret scoping, resource limits)       │  │
│  └─────────────────┬───────────────────────┘  │
│                    │                          │
│  ┌─────────────────┴───────────────────────┐  │
│  │          VM Manager (libkrun)            │  │
│  │  (lifecycle, networking, filesystem)     │  │
│  └─────────────────┬───────────────────────┘  │
│                    │                          │
│  ┌─────────────────┴───────────────────────┐  │
│  │      Secret Manager (pluggable)          │  │
│  │  HashiCorp Vault │ AWS SM │ Azure KV │   │  │
│  │  1Password CLI │ env vars │ file      │  │
│  └─────────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

### 6.2 Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Rust | rust-vmm ecosystem, memory safety for security product, single binary |
| VM backend | libkrun | Library API, Mac+Linux, sub-200ms boot, Red Hat maintained |
| Secret model | Gondolin-style network injection | Secrets never touch VM filesystem, strongest protection |
| Distribution | Single binary (cargo-dist) | Zero dependencies, `curl \| sh` install |
| License | Apache-2.0 | Enterprise-friendly (like microsandbox), avoid AGPL friction |
| Config format | TOML (Sandboxfile) | Familiar to Rust ecosystem, human-readable |
| Network proxy | HTTP/SOCKS5 (tokio) | Secret injection point, domain allowlists |
| OCI images | Yes (standard containers) | User brings existing images, no proprietary format |

### 6.3 Agent Integration Layers

1. **Layer 1 — Standalone CLI:** `sandbox run --image python:3.12 --allow-net api.openai.com -- python script.py`
2. **Layer 2 — SDK:** Rust library for programmatic sandbox management from host applications
3. **Layer 3 — MCP Server:** AI agents (Claude Code, Cursor, Pi) request sandboxed execution via MCP protocol
4. **Layer 4 — CI/CD:** GitHub Actions / GitLab CI integration for sandboxed test execution

### 6.4 Platform Support

| Platform | Backend | Status |
|----------|---------|--------|
| Linux x86_64 | KVM | v1 (primary) |
| Linux aarch64 | KVM | v1 |
| macOS aarch64 (Apple Silicon) | HVF | v1 |
| macOS x86_64 | HVF | v1 (if demand) |
| Windows | WSL2 / Hyper-V | v2 (via WSL2 bridge initially) |

---

## 7. Technical Risks

### 7.1 libkrun Dependency
- **Risk:** Single library dependency for core VM functionality
- **Mitigation:** libkrun is Red Hat-maintained (Sergio Lopez Pascual, Senior Principal), stable API since v1.0, used by Podman/crun. If abandoned, fork is viable (Rust, Apache-2.0).

### 7.2 Agent Transparency
- **Risk:** Agents may not run transparently inside microVM (filesystem layout assumptions, network expectations, tool outputs)
- **Mitigation:** Extensive testing with Claude Code, Cursor, Codex, Pi. Build compatibility layer for common agent patterns.

### 7.3 Platform Differences
- **Risk:** macOS (HVF) vs Linux (KVM) behavioral differences
- **Mitigation:** libkrun already abstracts this. Test matrix across platforms.

### 7.4 Performance Overhead
- **Risk:** Boot time + runtime overhead alienates developers
- **Mitigation:** Sub-200ms achievable (microsandbox proves this). Warm pool for repeat invocations. Benchmark early, optimize hot paths.

### 7.5 Gondolin/microsandbox Convergence
- **Risk:** Either project adds the features we're building, making us redundant
- **Mitigation:** Ship fast. Focus on enterprise secret management + single binary as core differentiators. Neither project has signaled enterprise direction.

---

## 8. Connections & Outreach

### 8.1 Armin Ronacher (Gondolin Creator)
- **Location:** Berlin (same city as Chris)
- **Background:** Creator of Flask, works at Sentry
- **Current:** Actively using Gondolin with Pi coding agent
- **Opportunity:** Potential collaboration on Pi integration, feedback on architecture
- **Why reach out:** Shared interest in local-first agent security, complementary approaches (his JS/QEMU vs our Rust/libkrun)

### 8.2 microsandbox Team (zerocore-ai)
- **Relationship:** Potential competitor OR collaborator
- **Evaluate:** Is contributing upstream (adding secret management to microsandbox) better than building from scratch?
- **License:** Apache-2.0 allows forking if needed

---

## 9. Next Steps

### Immediate (Prototype Spikes)

1. **microVM Backend Spike:** Test libkrun directly — measure boot time, memory overhead, I/O performance on macOS + Linux
2. **Agent Transparency Spike:** Run Claude Code, Cursor, Pi inside a microVM — identify broken assumptions
3. **Secret Management Spike:** End-to-end flow: Vault → host layer → network injection → agent HTTP request
4. **microsandbox Deep Dive:** Read the Rust codebase, identify gaps, evaluate contribute vs. compete

### Short-term (Weeks 1-4)

5. **User Interviews:** Validate problem with developers running agents with full credentials
6. **MVP CLI:** `sandbox run` with basic filesystem + network isolation + one secret backend
7. **Benchmark Suite:** Boot time, runtime overhead, network latency through proxy

### Medium-term (Months 2-3)

8. **MCP Server:** Agent integration via MCP protocol
9. **Policy Engine:** Declarative rules for filesystem, network, secrets
10. **Distribution:** cargo-dist, GitHub releases, homebrew tap

---

## 10. Key Sources

| Source | URL | Relevance |
|--------|-----|-----------|
| microsandbox | https://github.com/zerocore-ai/microsandbox | Closest competitor, Rust + libkrun |
| Gondolin | https://github.com/earendil-works/gondolin | Secret injection model to adopt |
| Anthropic sandbox-runtime | https://github.com/anthropic-experimental/sandbox-runtime | Claude Code sandboxing |
| libkrun | https://github.com/containers/libkrun | VM backend library |
| K8s Agent Sandbox | https://github.com/kubernetes-sigs/agent-sandbox | Enterprise/K8s approach |
| awesome-sandbox | https://github.com/restyler/awesome-sandbox | Comprehensive ecosystem overview |
| Northflank sandboxing guide | https://northflank.com/blog/how-to-sandbox-ai-agents | Security threat model |
| NVIDIA sandboxing guidance | https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/ | Published Feb 6, 2026 |
| AISI Inspect Toolkit | https://www.aisi.gov.uk/blog/the-inspect-sandboxing-toolkit-scalable-and-secure-ai-agent-evaluations | Isolation taxonomy |
| AI CLI Tools Comparison | https://mer.vin/2025/12/ai-cli-tools-comparison-why-openai-switched-to-rust-while-claude-code-stays-with-typescript/ | Language choice precedents |
