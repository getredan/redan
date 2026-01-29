# Product Planning Prompt — Secure Agent Execution Platform

Use this prompt in Claude Code to kick off a structured product planning session. Copy everything below the line into Claude Code.

---

You are acting as a technical product architect. Help me plan an open-source tool for secure AI agent execution. Work through each section methodically, producing concrete artifacts. Ask me clarifying questions when you need my input before proceeding to the next section.

## Context

I want to build an open-source tool on top of Gondolin (https://github.com/earendil-works/gondolin) — lightweight QEMU micro-VMs with a JavaScript-based network stack and VFS that provide sandboxed execution for AI agents with network egress control and secret isolation.

The problem: AI coding agents (Claude Code, Codex, Copilot, etc.) run with the developer's full credentials and network access. There is no practical, local-first tool that lets developers define security policies for what agents can access, which secrets they can use, and which hosts they can reach — while keeping the DX fast and frictionless.

The competitive landscape:
- Cloud-hosted sandboxes: E2B, Northflank (not local-first)
- Raw building blocks: Gondolin itself, Firecracker (SDK/library level, not end-user tools)
- Convenience tools: Solo (process management, no security model)
- Docker (not a real security boundary for this threat model)

Architecture vision: Rust core using Crux (https://redbadger.github.io/crux/) for cross-platform behavior reuse with platform-native shells — but this is v2+. v1 is CLI + JS/TS SDK.

Before you begin, read and familiarize yourself with:
- Gondolin docs: https://earendil-works.github.io/gondolin/
- Gondolin repo (especially AGENTS.md, security docs, network stack): https://github.com/earendil-works/gondolin
- Crux overview: https://redbadger.github.io/crux/

## Planning Sections — Work Through These In Order

### 1. Problem Analysis

- Map the concrete attack vectors when AI agents execute code with developer credentials today
- For each vector, describe the current state (unmitigated, partially mitigated, mitigated by what)
- Define what "solved" looks like technically — what invariants must hold
- Identify which agent tools (Claude Code, Codex, Cursor, Amp, etc.) expose which attack surfaces and how they currently handle (or don't handle) sandboxing

### 2. Gondolin Dependency Analysis

- Deep-dive into Gondolin's architecture: what it provides, what's missing for our use case
- Platform support matrix: what works today (ARM64), what's needed (x86_64, CI environments)
- Performance characteristics: boot time, memory overhead, network latency through the JS mediation layer
- Stability assessment: API surface maturity, breaking change risk, bus factor
- What we'd need to contribute upstream vs build on top vs work around
- Risk: what happens if Gondolin's direction diverges from our needs — forking viability

### 3. Technical Architecture (v1: CLI + SDK)

- Component diagram showing all major pieces and their interactions
- The policy model: how do developers express "this agent can reach github.com and npmjs.org, inject my GITHUB_TOKEN only for github.com requests, block everything else" — config format, defaults, overrides
- Secret management: how secrets flow from backend (local env, Vault, AWS SM, etc.) → host secret management layer → Gondolin network mediation → injected into agent HTTP requests. The developer's machine is pure compute — secrets never land on the filesystem or inside the VM. Design the full lifecycle: discovery, retrieval, injection, rotation, expiration, revocation, audit.
- Agent integration layer: how does this plug into Claude Code, Codex, and other agents — be specific:
  - MCP server approach (agent calls our tool)
  - CLI wrapper approach (we wrap the agent invocation)
  - Environment injection approach (we set up the VM, agent runs inside it)
  - Evaluate trade-offs of each, recommend a primary approach for MVP
- Filesystem model: how project files get into the VM, how outputs get back, persistence between runs
- Audit/observability: what do we log, where, in what format — every network request, every policy decision, every secret injection
- Configuration format: per-project config file (like solo.yml or .gondolin.yml), global defaults, environment overrides

### 4. Security Model

- Formal threat model: what are we protecting against, what's in scope, what's explicitly out of scope
- Trust boundaries: draw them precisely — host, VM, network mediation layer, agent, user, secret management backend
- Secret isolation guarantees: prove (or document the assumptions for) why the guest can't exfiltrate secrets
- Network policy enforcement: how do we handle edge cases — websockets, streaming responses, TLS inspection, non-HTTP protocols
- Escape hatches: when and how can a developer intentionally bypass restrictions (e.g. for debugging)
- Comparison with existing models: how does our security story compare to Docker, gVisor, Firecracker, E2B

#### 4a. Agent Identity & Secret Management Architecture

This is a core differentiator. The agent should never use the developer's personal credentials. Instead, the agent gets its own scoped identity with secrets sourced from external secret management infrastructure — never touching the developer's machine.

**The personal problem:** a developer's `~/.ssh`, `~/.gnupg`, `~/.aws/credentials`, `~/.kube/config`, `~/.netrc`, `~/.docker/config.json` etc. are all readable by any agent running as their user. An agent with access to these can push to production repos, sign commits as the developer, access production databases, deploy to Kubernetes clusters, authenticate to private registries. The VM must have zero access to the host's home directory secrets by default.

**The enterprise problem:** companies need agents to access infrastructure (AWS, Azure, GCP, staging databases, internal APIs, CI/CD systems) in a controlled, auditable, policy-driven way — without funneling everything through the developer's personal credentials and without forcing developers off local machines onto cloud-hosted dev environments.

Design the secret management layer as pluggable backends:

**Solo developer backends:**
- Environment variables (simplest, explicit opt-in per secret)
- Local keychain (macOS Keychain, Linux secret-service)
- 1Password CLI / Bitwarden CLI integration
- Dotenv files (scoped, never the developer's global ones)

**Enterprise backends:**
- AWS Secrets Manager / AWS SSM Parameter Store (via IAM roles, STS assume-role for agent-specific identity)
- Azure Key Vault (via managed identity or service principal scoped to agent)
- HashiCorp Vault (AppRole, Kubernetes auth, or token-based)
- GCP Secret Manager
- OIDC/JWT-based short-lived token issuance for agent sessions

For each backend, analyze:
- How does the host authenticate to the secret backend (the host itself needs some bootstrap credential)
- How are secrets scoped — per project, per agent session, per task
- Secret lifecycle: rotation, expiration, revocation mid-session
- Audit trail: who requested what secret, when, for which agent session, which host injected it
- Policy format: how does a team express "agents working on project X can access staging DB credentials and GitHub API, nothing else"
- How this integrates with Gondolin's `createHttpHooks` pattern — extending `secrets` config to support remote sources instead of just `process.env`

**Key architectural question:** the developer's laptop becomes pure compute — project files and CPU. Secrets flow from infrastructure the security team controls, through the host's secret management layer, into the Gondolin network mediation layer, and are injected into agent HTTP requests without ever being visible inside the VM or on the developer's filesystem. Map out this flow end-to-end with trust boundaries at each hop.

**Comparison point:** how do cloud-hosted dev environments (Codespaces, Gitpod, Cloud9) handle this today? What can we learn from their IAM integration, and how does our local-first approach differ in threat model and DX?

### 5. MVP Scope

- User stories for MVP, organized by priority (must-have / should-have / nice-to-have)
- Define what "MVP done" looks like — the smallest thing that's useful and gets feedback
- The "happy path" walkthrough: step by step, what does a developer do from install to running their first sandboxed agent session
- List hard technical unknowns that need prototyping/spiking before committing to the architecture
- What explicitly is NOT in v1 (Crux, mobile, team features, hosted anything)

### 6. Agent Integration Deep-Dive

The tool must work as a general-purpose sandboxed execution environment — not locked to any single agent. A developer should be able to use this with Claude Code, Codex, Cursor, Amp, or any future agent directly. Think of it like Solo is a general process manager that happens to have an MCP integration — we're a general sandboxed execution environment that happens to integrate well with specific agents.

That said, Pi (https://github.com/badlogic/pi-mono, @mariozechner/pi-coding-agent) is a priority integration target because:
- Its SDK (`createAgentSession()`) gives full programmatic control over tool execution
- Its RPC mode (JSON over stdin/stdout) enables agent-agnostic proxying
- Its extension system allows hooking `tool_call` events to redirect execution into sandboxed VMs
- It's cross-compatible with Claude Code and Codex skill directories
- Its own docs explicitly warn about the exact threat we're solving: "Pi packages run with full system access. Extensions execute arbitrary code."
- Armin Ronacher (Gondolin's author) actively uses and champions Pi

However, requiring Pi as a middleman to use other agents would be a non-starter. The architecture must support:

**Layer 1: Standalone sandboxed shell (agent-agnostic)**
- Any agent (or human) can run inside a Gondolin VM with policy enforcement
- This is the foundation — a developer should be able to `ourtool exec claude-code` or `ourtool exec cursor` and get a sandboxed session
- Analyze: how do Claude Code, Codex, Cursor, and Amp each handle execution environments — can they run inside a VM transparently, what breaks, what assumptions do they make about the host

**Layer 2: Pi SDK/extension integration (deep integration)**
- For Pi users: an extension that intercepts tool calls and routes them through Gondolin VMs
- For SDK consumers: wrapper around `createAgentSession()` that transparently sandboxes execution
- Analyze Pi's extension API: `pi.on("tool_call", ...)` — what's the hook surface, can we intercept and redirect bash/write/edit without Pi knowing
- Analyze Pi's RPC mode as a proxy insertion point

**Layer 3: MCP server (universal but shallow)**
- Expose sandboxed execution as MCP tools that any MCP-capable agent can call
- This is the "works with everything" fallback but gives less control than Layer 1 or 2

For each layer:
- What guarantees can we make about secret isolation and network policy
- What are the DX trade-offs (setup friction, latency, compatibility)
- What breaks or degrades compared to unsandboxed execution

Test plan: how do we verify that sandboxing actually works across all layers — automated tests that confirm secret isolation, network policy enforcement, filesystem boundaries. Include adversarial tests: agent code that actively tries to exfiltrate secrets, reach blocked hosts, escape the VM.

### 7. v2+ Architecture (Crux-based)

- How the Rust core / platform shell split maps onto this problem domain
- What belongs in the Core (policy engine, audit logic, configuration parsing, security rules)
- What belongs in the Shell (VM orchestration, filesystem operations, network I/O, UI)
- Mobile shell use case: remote monitoring and approval — what capabilities does it need
- Desktop shell (Tauri): how it wraps the CLI functionality with a UI for policy management and live monitoring
- Migration path: how do we get from v1 (CLI + JS SDK) to v2 (Crux) without breaking users

### 8. Technical Risk Register

- Gondolin risks: stability, platform gaps, upstream changes, performance
- QEMU risks: macOS HVF vs Linux KVM behavior differences, nested virtualization in CI
- Agent integration risks: agents change their execution model, MCP evolves, new agents appear
- Performance risks: overhead makes the tool unusable for fast iteration cycles
- Security risks: our own vulnerabilities, the JS network stack as attack surface, QEMU escape, secret management backend authentication bootstrap (the host needs credentials to fetch agent credentials — turtles all the way down)
- Secret management risks: backend availability (agent can't work if Vault is down), credential leakage through host process memory, bootstrap credential storage on developer laptop
- For each risk: likelihood, impact, mitigation strategy, and "kill criteria" (when do we abandon this approach)

### 9. Prototype Plan

- Define 4-5 focused prototyping spikes that would retire the biggest technical risks
- One spike must cover the secret management flow end-to-end: host authenticates to a backend (start with AWS Secrets Manager or HashiCorp Vault), retrieves a scoped credential, injects it via Gondolin's httpHooks, and verify the agent inside the VM can use it without ever seeing the raw secret
- For each spike: what question it answers, what to build, expected time, success/failure criteria
- Recommended order and dependencies between spikes
- What we learn from each spike that feeds into the architecture

## Workflow Mode

Start in **planning mode**. Do not write any code. Work through each section producing documentation artifacts only. Ask clarifying questions between sections. Do not proceed to the next section until I confirm.

## Output Format

For each section, produce:
1. The concrete artifact (architecture diagrams in mermaid, config examples, threat models, user stories, etc.)
2. A "key decisions" callout listing decisions I need to make, with your recommendation and reasoning
3. An "open questions" list of things you couldn't resolve without more input from me

Write everything to a `docs/planning/` directory structure with one markdown file per section. Also produce a `docs/planning/README.md` as an index linking to each section.

Be specific and technical throughout. Reference actual Gondolin APIs, actual Claude Code behaviors, actual MCP protocol details. No hand-waving, no generic advice. If you don't know something, say so and tell me what to investigate.

## Final Step: Oracle Review

After all sections are complete and written to `docs/planning/`, take three steps back from the work. Then use tmux to spin up parallel oracle review sessions:

1. **Codex review** — open a tmux pane running `codex` and feed it the complete `docs/planning/` directory. Prompt it:
   ```
   Review this product planning documentation for a secure AI agent execution platform built on Gondolin micro-VMs. Act as a skeptical senior engineer. Identify: architectural blind spots, unrealistic assumptions, missing threat vectors, scope creep, and anything that would fail in practice. Be brutal. Write your review to docs/planning/review-codex.md.
   ```

2. **Claude review via `code`** — open a second tmux pane running `code` (Claude Code) and feed it the same directory. Prompt it:
   ```
   Review this product planning documentation for a secure AI agent execution platform built on Gondolin micro-VMs. Act as a security architect who has shipped similar infrastructure. Identify: gaps in the threat model, secret management edge cases, integration risks with real-world agent tools, and where the proposed architecture diverges from how these systems actually behave in production. Write your review to docs/planning/review-claude.md.
   ```

3. **Synthesis** — after both reviews are written, read both review files. Produce a `docs/planning/review-synthesis.md` that:
   - Lists every valid concern raised by either oracle
   - For each concern: assess severity, determine if it changes the architecture, and recommend a concrete action
   - Identifies where the oracles disagree and your assessment of who's right
   - Updates the risk register (section 8) with any new risks surfaced
   - Proposes changes to the prototype plan (section 9) if the reviews shift priorities

Do not consider the planning complete until the oracle review cycle is done.
