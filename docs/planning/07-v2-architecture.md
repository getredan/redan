# 7. v2+ Architecture

## 7.1 Crux-Based Split

[Crux](https://redbadger.github.io/crux/) separates application behavior (Core, in Rust) from platform I/O (Shell, per-platform). This maps well to Redan's domain.

### Why Crux for v2

v1 is a CLI binary. It works. But:
- Desktop monitoring UI (see live policy decisions, audit stream) requires a GUI
- Mobile monitoring (approve/deny secret access on phone) requires iOS/Android
- All platforms need the **same** policy logic, audit format, secret management rules

Crux lets us write the policy engine, audit logic, and session management once in Rust, then drive it from CLI, Tauri desktop, and mobile shells.

### Core vs Shell Split

```
┌─────────────────────────────────────────────────────────┐
│                    Crux Core (Rust)                      │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐  │
│  │ Policy      │  │ Audit       │  │ Session        │  │
│  │ Engine      │  │ Manager     │  │ Manager        │  │
│  │             │  │             │  │                │  │
│  │ - Parse     │  │ - Format    │  │ - State        │  │
│  │   config    │  │   entries   │  │   machine      │  │
│  │ - Evaluate  │  │ - Query    │  │ - Events       │  │
│  │   rules     │  │ - Filter   │  │ - Commands     │  │
│  │ - Merge     │  │ - Export   │  │                │  │
│  │   layers    │  │            │  │                │  │
│  └─────────────┘  └─────────────┘  └────────────────┘  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │              Secret Manager (logic only)         │    │
│  │  - Placeholder generation                       │    │
│  │  - Injection decision (which secret, which host)│    │
│  │  - Rotation logic                               │    │
│  │  - Audit trail generation                       │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  Core emits Effects (I/O requests) to the Shell:        │
│  - VMBoot { config }                                    │
│  - NetworkConnect { host, port }                        │
│  - SecretRetrieve { backend, key }                      │
│  - AuditWrite { entry }                                 │
│  - Render { view_model }                                │
└─────────────────────────────────────────────────────────┘

┌───────────────────┐ ┌───────────────────┐ ┌────────────────┐
│   CLI Shell       │ │  Desktop Shell    │ │  Mobile Shell  │
│   (v1 code)       │ │  (Tauri)          │ │  (Swift/Kotlin)│
│                   │ │                   │ │                │
│ Handles Effects:  │ │ Handles Effects:  │ │ Handles:       │
│ - libkrun VM ops  │ │ - libkrun VM ops  │ │ - Remote API   │
│ - tokio network   │ │ - tokio network   │ │   to host      │
│ - file I/O        │ │ - file I/O        │ │ - Push notif   │
│ - terminal UI     │ │ - Native UI       │ │ - Approve/deny │
│                   │ │   (webview)       │ │   prompts      │
└───────────────────┘ └───────────────────┘ └────────────────┘
```

## 7.2 What Belongs Where

### Core (Rust, platform-independent, no I/O)

| Component | Rationale |
|-----------|-----------|
| Policy engine | Same rules everywhere. Parse, evaluate, merge. Pure logic. |
| Audit log format | Consistent format across all shells. |
| Session state machine | Session lifecycle (init → boot → run → teardown) as state machine. |
| Secret injection decisions | "Should this placeholder be replaced for this host?" — pure function. |
| Configuration parsing | TOML parsing, validation, defaults. |
| Placeholder generation | Deterministic (seeded) or random token generation. |
| View models | What the UI should display, regardless of platform. |

### Shell (Platform-specific, handles I/O)

| Component | Rationale |
|-----------|-----------|
| libkrun VM operations | System calls, hardware interaction. |
| Network proxy (tokio) | Async I/O, socket operations. |
| Secret backend clients | HTTP calls to Vault, AWS, etc. |
| File I/O | Reading config, writing audit log. |
| Terminal I/O | stdin/stdout/stderr attachment. |
| Native UI rendering | Tauri webview, SwiftUI, Jetpack Compose. |

## 7.3 Mobile Shell Use Case

The mobile app is a remote monitoring and approval tool. It does NOT run VMs.

**Capabilities:**
- View active Redan sessions (on the developer's machine)
- Stream audit log in real-time
- Receive push notifications for policy decisions
- Approve/deny secret access requests (if configured for manual approval)
- View session summary after completion

**Architecture:**
- Developer's machine runs Redan with a lightweight API server (localhost + optional tunnel)
- Mobile app connects via authenticated WebSocket
- Core processes events and generates view models
- Mobile shell renders native UI from view models

**Why this matters:** Enterprise security teams want visibility into what agents are doing. A mobile dashboard lets a security engineer monitor agent sessions from their phone.

**This is v2+ and optional.** Don't over-invest in the architecture now. The Crux split naturally supports it when/if we build it.

## 7.4 Desktop Shell (Tauri)

A native desktop app wrapping the CLI functionality with a GUI.

**Capabilities:**
- Visual policy editor (edit `redan.toml` with a form UI)
- Live session monitor (network requests, secret injections, blocks — real-time)
- Audit log viewer (search, filter, export)
- Image management (pull, list, remove)
- Multiple session tabs

**Why Tauri:** Rust backend (shares code with Core), small binary size, native look. Electron would work too but is heavyweight and we're already in Rust.

## 7.5 Migration Path: v1 → v2

The key constraint: v1 users have `redan.toml` files and expect `redan exec` to work.

**Step 1: Extract Core**
- Move policy engine, audit format, session state machine into a separate Rust crate
- CLI shell calls Core functions. Behavior doesn't change.
- This is a refactor, not a rewrite.

**Step 2: Add Crux Effects**
- Core functions return Effect values instead of doing I/O directly
- CLI shell handles effects (same I/O code, now driven by effects)
- Still just a refactor. No user-visible change.

**Step 3: Add Desktop Shell**
- Tauri app imports Core crate
- Implements same effect handlers as CLI
- New distribution: `redan` (CLI) and `redan-desktop` (Tauri app)
- Same config file, same policy, same behavior

**Step 4: Add Mobile Shell**
- Swift/Kotlin shell imports Core (via FFI or compiled as static lib)
- Implements remote-only effect handlers (API calls to host)
- Separate app store distribution

**No breaking changes at any step.** v1 users keep using `redan exec`. Desktop/mobile are additive.

## Key Decisions

1. **Don't design for Crux in v1.** Write clean Rust with clear separation of concerns, but don't add Crux abstractions until v2. The refactor path is straightforward if the code is well-structured. ✅

2. **Mobile is remote monitoring only, not VM management.** The phone doesn't run microVMs. It watches and approves. ✅

3. **Tauri over Electron for desktop.** Rust ecosystem alignment, smaller footprint. ✅

## Open Questions

1. **Crux maturity:** Crux is still relatively young. Is it production-ready for a security-critical application by the time we reach v2? Need to evaluate closer to v2 development.

2. **Mobile API server security:** Exposing a monitoring API from the developer's machine introduces a new attack surface. Authentication, encryption, and network binding (localhost-only by default) need careful design.

3. **Is the desktop app actually needed?** If the CLI + audit log is sufficient for developers, the desktop app may be over-engineering. Let user feedback from v1 drive this decision.
