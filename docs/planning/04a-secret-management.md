# 4a. Agent Identity & Secret Management Architecture

## 4a.1 The Core Principle

**The developer's laptop is compute. Nothing else.**

Secrets flow from infrastructure the security team controls → through the Redan host process → injected into HTTP requests at the network layer → never visible inside the VM, never on the developer's filesystem.

The agent has its own identity. The developer has theirs. They don't mix.

## 4a.2 End-to-End Secret Flow

```
┌──────────────────┐
│  Secret Backend   │  Vault, AWS SM, env, keychain, 1Password
│  (Trust Level 0)  │
└────────┬─────────┘
         │ Authenticated retrieval
         │ (IAM role, AppRole token, CLI auth, etc.)
         │
┌────────┴─────────────────────────────────────────────────────┐
│  Redan Host Process (Trust Level 1)                          │
│                                                              │
│  SecretManager                                               │
│  ├─ On session start:                                        │
│  │   ├─ Read redan.toml [secrets] config                     │
│  │   ├─ For each secret: resolve backend, authenticate       │
│  │   ├─ Generate placeholder token per secret                │
│  │   │   (random, e.g. "redan_ph_<32 hex chars>")           │
│  │   └─ Store mapping: placeholder → {real_value, hosts}     │
│  │                                                           │
│  ├─ On network request from VM:                              │
│  │   ├─ MITM terminates TLS, reads HTTP headers              │
│  │   ├─ Scan headers for any placeholder token               │
│  │   ├─ If found AND destination ∈ secret.inject_for:        │
│  │   │   └─ Replace placeholder with real_value              │
│  │   ├─ If found AND destination ∉ secret.inject_for:        │
│  │   │   └─ Leave placeholder (meaningless to recipient)     │
│  │   └─ Forward to destination                               │
│  │                                                           │
│  ├─ On secret rotation signal:                               │
│  │   ├─ Retrieve new value from backend                      │
│  │   ├─ Update mapping (same placeholder, new real_value)    │
│  │   └─ No VM restart needed — next request gets new value   │
│  │                                                           │
│  └─ On session teardown:                                     │
│      ├─ Zeroize all real_values in memory                    │
│      ├─ Drop placeholder mapping                             │
│      └─ Revoke short-lived credentials if applicable         │
│                                                              │
└──────────────────────────────────────────────────────────────┘
         │
    ═════╪═════  VM BOUNDARY
         │
┌────────┴─────────────────────────────────────────────────────┐
│  Guest VM (Trust Level 2 — untrusted)                        │
│                                                              │
│  Agent sees:                                                 │
│  $GITHUB_TOKEN = "redan_ph_a1b2c3d4e5f6..."                │
│  $OPENAI_API_KEY = "redan_ph_f6e5d4c3b2a1..."              │
│                                                              │
│  Agent makes request:                                        │
│  curl -H "Authorization: Bearer $GITHUB_TOKEN" \            │
│       https://api.github.com/repos/...                       │
│                                                              │
│  The placeholder leaves the VM, hits the host proxy,         │
│  gets replaced with the real token, reaches GitHub.          │
│  The agent never sees the real token.                        │
└──────────────────────────────────────────────────────────────┘
```

## 4a.3 Pluggable Backends

### Backend Trait (Rust)

```rust
#[async_trait]
trait SecretBackend: Send + Sync {
    /// Retrieve a secret value. Returns the raw secret string.
    async fn get(&self, config: &SecretConfig) -> Result<SecretValue>;

    /// Check if the backend is reachable and authenticated.
    async fn health_check(&self) -> Result<()>;

    /// Human-readable backend name for audit logs.
    fn name(&self) -> &str;
}

/// Secret value with metadata.
struct SecretValue {
    value: Zeroizing<String>,    // zeroize on drop
    expires_at: Option<DateTime<Utc>>,
    version: Option<String>,
}
```

### Solo Developer Backends

#### Environment Variables (`env`)

Simplest backend. Reads from host process environment.

```toml
[secrets.GITHUB_TOKEN]
source = "env"                       # read $GITHUB_TOKEN from host env
inject_for = ["api.github.com"]
header = "Authorization"
format = "Bearer {value}"
```

**Host authentication:** None needed — the env var is already there.
**Scoping:** Per-secret in redan.toml. Developer decides which env vars to expose.
**Lifecycle:** Static for session duration. No rotation.
**Audit:** `{backend: "env", var: "GITHUB_TOKEN", retrieved_at: "..."}`

#### macOS Keychain / Linux secret-service (`keychain`)

```toml
[secrets.GITHUB_TOKEN]
source = "keychain"
keychain_service = "redan"
keychain_account = "github-token"
inject_for = ["api.github.com"]
header = "Authorization"
format = "Bearer {value}"
```

**Host authentication:** OS-level auth (Touch ID, password prompt, D-Bus secret-service).
**Scoping:** Per-service/account in keychain.
**Lifecycle:** Persistent until user changes. No automatic rotation.
**Audit:** `{backend: "keychain", service: "redan", account: "github-token"}`

#### 1Password CLI (`op`)

```toml
[secrets.GITHUB_TOKEN]
source = "1password"
op_item = "GitHub API Token"
op_field = "credential"
op_vault = "Development"
inject_for = ["api.github.com"]
header = "Authorization"
format = "Bearer {value}"
```

**Host authentication:** 1Password CLI session (biometric or master password).
**Scoping:** Per-item/field/vault. 1Password access controls apply.
**Lifecycle:** Managed in 1Password. Redan retrieves on each session start.
**Audit:** `{backend: "1password", item: "GitHub API Token", vault: "Development"}`

**Implementation:** Shell out to `op read "op://Development/GitHub API Token/credential"`. Requires `op` CLI installed. No native API needed.

#### Dotenv Files (`dotenv`)

```toml
[secrets.STAGING_KEY]
source = "dotenv"
dotenv_file = ".env.staging"         # relative to project root
dotenv_key = "API_KEY"
inject_for = ["staging-api.example.com"]
header = "X-API-Key"
format = "{value}"
```

**Important:** This reads from a specific dotenv file, NOT the developer's global environment. The file should be in `.gitignore`. This is a step up from raw env vars — the secret is at least scoped to a file that can be rotated independently.

### Enterprise Backends

#### HashiCorp Vault (`vault`)

```toml
[secrets.backend.vault]
address = "https://vault.company.com"
auth = "approle"                      # approle | token | kubernetes | oidc
role_id_env = "VAULT_ROLE_ID"        # or role_id = "..."
secret_id_env = "VAULT_SECRET_ID"

[secrets.STAGING_DB_PASSWORD]
source = "vault"
vault_path = "secret/data/staging/db"
vault_key = "password"
inject_for = ["staging-db.company.com"]
# For DB connections: inject as part of connection string, not HTTP header
inject_mode = "env"                   # "header" | "env"
env_var = "DATABASE_URL"
format = "postgres://agent:{value}@staging-db.company.com:5432/app"
```

**Host authentication flow:**
1. Redan reads `VAULT_ROLE_ID` and `VAULT_SECRET_ID` from host env
2. Authenticates to Vault using AppRole method
3. Receives a Vault token scoped to the agent's policy
4. Uses token to read secrets from configured paths
5. Token is short-lived and auto-renewed during session

**Scoping:** Vault policies control which paths the agent role can access. Security team manages policies.
**Lifecycle:** Vault handles rotation. Redan can re-read on configurable interval.
**Audit:** Vault's own audit log captures all reads. Redan logs: `{backend: "vault", path: "secret/data/staging/db", key: "password"}`

#### AWS Secrets Manager (`aws-sm`)

```toml
[secrets.backend.aws]
region = "eu-central-1"
# Auth: uses standard AWS credential chain
# For agent-specific identity: assume a role
assume_role = "arn:aws:iam::123456789:role/redan-agent-staging"

[secrets.API_KEY]
source = "aws-sm"
aws_secret_id = "staging/api-key"
aws_secret_key = "api_key"           # for JSON secrets
inject_for = ["api.staging.company.com"]
header = "X-API-Key"
format = "{value}"
```

**Host authentication flow:**
1. Redan uses standard AWS credential chain on host (env vars, `~/.aws/credentials`, instance profile)
2. Calls `sts:AssumeRole` to get temporary credentials for the agent-specific role
3. Uses temporary credentials to call `secretsmanager:GetSecretValue`
4. Temporary credentials expire after session (default 1hr, configurable)

**Scoping:** IAM policies on the assumed role restrict which secrets are accessible.
**Lifecycle:** AWS handles rotation. Redan can poll for changes.
**Audit:** CloudTrail logs all API calls. Redan logs: `{backend: "aws-sm", secret_id: "staging/api-key", role: "redan-agent-staging"}`

#### Azure Key Vault (`azure-kv`)

```toml
[secrets.backend.azure]
vault_url = "https://mycompany.vault.azure.net"
# Auth: DefaultAzureCredential chain
# For agent identity: use a service principal
client_id_env = "REDAN_AZURE_CLIENT_ID"
client_secret_env = "REDAN_AZURE_CLIENT_SECRET"
tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

[secrets.INTERNAL_API_KEY]
source = "azure-kv"
secret_name = "internal-api-key"
inject_for = ["api.internal.company.com"]
header = "Authorization"
format = "Bearer {value}"
```

#### GCP Secret Manager (`gcp-sm`)

```toml
[secrets.backend.gcp]
project = "my-company-staging"
# Auth: Application Default Credentials
# For agent identity: impersonate a service account
impersonate_service_account = "redan-agent@my-company-staging.iam.gserviceaccount.com"

[secrets.GCP_API_KEY]
source = "gcp-sm"
secret_name = "api-key"
version = "latest"
inject_for = ["api.company.com"]
header = "X-API-Key"
format = "{value}"
```

## 4a.4 The Bootstrap Problem

**The turtles:** The host process needs credentials to fetch agent credentials. Where do the host's credentials come from?

| Backend | Host Bootstrap Credential | Where It Lives |
|---------|--------------------------|----------------|
| env | N/A (secret IS the env var) | Host process environment |
| keychain | OS user session | OS keychain, unlocked by login |
| 1password | 1Password CLI session | Biometric / master password |
| vault | AppRole role_id + secret_id | Host env vars or file |
| aws-sm | AWS credentials | `~/.aws/credentials`, env vars, or instance profile |
| azure-kv | Service principal or managed identity | Env vars or workload identity |
| gcp-sm | Application Default Credentials | `~/.config/gcloud/` or workload identity |

**This is inherently recursive.** The host must have SOME credential to start the chain. The key insight is that the **host's bootstrap credential is broad** (can access many secrets) while the **agent's injected credentials are narrow** (scoped per-host, per-session). Redan reduces the attack surface even though it can't eliminate the bootstrap.

The bootstrap credential lives on the host filesystem or in the developer's session. This is inherent and cannot be solved — document it, don't hide it.

### Concrete Bootstrap Flows (per Opus/Sonnet review)

**Vault (enterprise):**
1. Developer runs `vault login -method=oidc` → browser SSO flow → short-lived Vault token
2. Token cached at `~/.vault-token` (on host disk — inherent, documented)
3. Redan reads `~/.vault-token`, uses it to read agent secrets from configured paths
4. **Scoping option A (MVP/v1.0):** Redan uses the developer's Vault token directly. Simple, but Redan has the developer's full Vault permissions.
5. **Scoping option B (v1.1):** Redan exchanges the developer's token for a scoped agent token via Vault's token creation with restricted policies. Requires Vault policy setup by security team.
6. **Risk:** If `~/.vault-token` is readable by the agent (it isn't — host home dir not mounted in VM), the agent could access Vault directly. Since the VM can't see `~/.vault-token`, this is safe.

**AWS (enterprise):**
1. Developer runs `aws sso login` → browser SSO → cached session token in `~/.aws/sso/cache/`
2. Redan uses standard AWS credential chain: SSO cache → env vars → credentials file → instance profile
3. Redan calls `sts:AssumeRole` to get temporary credentials for the agent-specific IAM role
4. **Recommendation:** Use SSO + assume_role. Don't fall back to `~/.aws/credentials` (long-lived keys). Redan should short-circuit the credential chain: check SSO cache first, then env vars, skip credentials file unless explicitly configured.

**1Password (solo developer, v1.0):**
1. Developer runs `op signin` or uses biometric unlock
2. Redan calls `op read "op://vault/item/field"` to retrieve secrets
3. 1Password session is tied to the developer's OS session (Touch ID, etc.)
4. **No bootstrap credential on disk** — 1Password uses biometric/password unlock

**env (MVP):**
1. Developer exports `GITHUB_TOKEN=ghp_xxx` in their shell
2. Redan reads from `process.env`
3. **Honest limitation:** The secret exists in the developer's shell environment. Redan prevents the agent from reading it directly and prevents exfiltration via network, but a compromised shell session already has the value.

**Solo developer mitigation:** env or keychain are acceptable. The developer already has these credentials — Redan's job is to prevent the AGENT from accessing them directly, not to protect against a compromised developer workstation.

## 4a.5 Injection Modes

Not all secrets are HTTP headers. Some are connection strings, query parameters, or environment variables.

### Header Injection (primary)

```toml
[secrets.GITHUB_TOKEN]
inject_mode = "header"               # default
header = "Authorization"
format = "Bearer {value}"
inject_for = ["api.github.com"]
```

Proxy replaces placeholder in the specified header before forwarding.

### URL Query Parameter Injection

```toml
[secrets.API_KEY]
inject_mode = "query"
query_param = "api_key"
inject_for = ["api.example.com"]
```

Proxy appends `?api_key=<real_value>` (or `&api_key=...` if query string exists).

### Environment Variable Injection (for non-HTTP) — WEAKER SECURITY TIER

> **⚠️ This injection mode provides weaker guarantees than header/query injection.**
> Invariant I-3 (secrets not visible in VM) does NOT hold for env-injected secrets.
> Use only when no network-layer alternative exists.

```toml
[secrets.DATABASE_URL]
inject_mode = "env"                  # ← explicit opt-in to weaker mode
env_var = "DATABASE_URL"
format = "postgres://agent:{value}@staging-db.company.com:5432/app"
```

For database connections and other non-HTTP protocols, the real value is set as a guest environment variable via `krun_set_env()`.

**What this means in practice:**
- The secret IS visible to `env`, `/proc/self/environ`, `os.environ` inside the VM
- A compromised agent can read the value and attempt to persist it (write to project files)
- The network policy still prevents exfiltration to unauthorized hosts
- The secret could end up in project files, git commits, or terminal output

**When to use:** Database connections where IAM auth isn't available, non-HTTP APIs, model provider API keys (ANTHROPIC_API_KEY, OPENAI_API_KEY) where the agent's HTTP client can't be proxied.

**When NOT to use:** Any secret that can be injected via HTTP headers or query parameters. The config parser warns if an env-mode secret has `inject_for` hosts that suggest header injection would work.

**Audit log:** Env-injected secrets are logged distinctly:
```jsonl
{"event":"secret_configured","secret":"DATABASE_URL","inject_mode":"env","security_tier":"reduced","warning":"secret visible in guest environment"}
```

**v1.1 investigation:** Host-side protocol proxies (like pgbouncer for Postgres, or an HTTP proxy for model APIs) that eliminate the need for env injection in common cases.

## 4a.6 Policy Format for Teams

Teams need to express: "agents working on project X can access these secrets, nothing else."

```toml
# redan.toml for project "frontend-app"

[metadata]
project = "frontend-app"
team = "web-platform"

[network]
allow = [
    "api.github.com",
    "registry.npmjs.org",
    "api.openai.com",
    "staging-api.company.com",
]

[secrets.GITHUB_TOKEN]
source = "vault"
vault_path = "secret/data/teams/web-platform/github"
vault_key = "token"
inject_for = ["api.github.com"]
header = "Authorization"
format = "token {value}"

[secrets.OPENAI_API_KEY]
source = "vault"
vault_path = "secret/data/shared/openai"
vault_key = "api_key"
inject_for = ["api.openai.com"]
header = "Authorization"
format = "Bearer {value}"

[secrets.STAGING_API_KEY]
source = "vault"
vault_path = "secret/data/teams/web-platform/staging"
vault_key = "api_key"
inject_for = ["staging-api.company.com"]
header = "X-API-Key"
format = "{value}"
```

**The security team controls:** Vault policies that determine which paths `web-platform`'s agent role can read. The `redan.toml` in the repo declares intent; Vault enforces access.

**Version control:** `redan.toml` is committed to the repo. Secret values are never in the file — only references to backends. Code review applies to policy changes just like code changes.

## 4a.7 Comparison with Cloud Dev Environments

| Aspect | Codespaces / Gitpod | Redan |
|--------|---------------------|-------|
| Where compute runs | Cloud VM | Developer's laptop |
| Secret injection | Env vars in cloud VM (visible to code) | Network-layer injection (invisible to VM) |
| Network policy | No egress control by default | Default deny, explicit allowlist |
| Identity model | User's PATs configured per-repo | Agent identity per-project from secret backend |
| Audit | Platform audit logs | Local JSONL + backend audit (Vault, CloudTrail) |
| Offline capability | None | Full (with `env` or `keychain` backend) |
| Cost | Per-hour compute charges | Free (your laptop) |
| Data residency | Cloud provider's region | Your machine |

**Key difference:** Cloud dev environments put secrets into the VM as environment variables — code inside can read and exfiltrate them (the network is wide open). Redan keeps secrets outside the VM and enforces network policy. This is strictly stronger isolation.

## 4a.8 Secret Lifecycle

### Discovery
- On `redan exec`, read `[secrets]` from redan.toml
- Validate: every secret has a source, inject_for, and injection config
- Warn if a configured backend is unreachable (`redan secret test`)

### Retrieval
- Lazy by default: retrieve on first matching network request
- Optional eager retrieval on session start (`prefetch = true` in config)
- Cache in host memory for session duration
- Respect TTL from backend (Vault lease duration, AWS rotation schedule)

### Injection
- Per network request, per header match
- Placeholder → real value substitution in MITM proxy
- Never log real values (log placeholder name, target host, timestamp)

### Rotation
- If backend signals rotation (Vault lease expiry, AWS rotation event):
  - Retrieve new value
  - Update cache (same placeholder, new real value)
  - No VM restart — transparent to agent
- For `env` backend: no rotation (static for session)

### Expiration
- Session-scoped: secrets cleared on session teardown
- Backend-scoped: respect Vault lease, AWS credential expiration
- If a credential expires mid-session: re-authenticate to backend, retrieve fresh value
- If re-authentication fails: log error, block requests that need the expired secret

### Revocation
- If the admin revokes a secret in the backend mid-session:
  - Next retrieval/refresh fails
  - Redan logs the revocation
  - Requests that need this secret fail with a clear error
  - Other secrets continue working
- Emergency revocation: `redan exec` watches for a kill signal (e.g., Vault dynamic secret revocation notification)

### Audit Trail

Every secret operation is logged:

```jsonl
{"ts":"...","event":"secret_configured","secret":"GITHUB_TOKEN","backend":"vault","path":"secret/data/teams/web/github"}
{"ts":"...","event":"secret_retrieved","secret":"GITHUB_TOKEN","backend":"vault","version":"3","expires_at":"2026-02-08T11:30:00Z"}
{"ts":"...","event":"secret_injected","secret":"GITHUB_TOKEN","host":"api.github.com","method":"GET","path":"/repos/..."}
{"ts":"...","event":"secret_rotated","secret":"GITHUB_TOKEN","backend":"vault","old_version":"3","new_version":"4"}
{"ts":"...","event":"secret_expired","secret":"STAGING_KEY","backend":"aws-sm","action":"re-retrieving"}
{"ts":"...","event":"secret_revoked","secret":"STAGING_KEY","backend":"vault","action":"blocking_requests"}
```

## Key Decisions

1. **Three injection modes: header (default), query, env.** Header is strongest (secret never in VM). Env is weakest but necessary for non-HTTP. Document the trade-off clearly. ✅

2. **Backend trait as the abstraction.** Clean separation. New backends are a struct implementing 3 methods. ✅

3. **Lazy retrieval by default.** Don't fetch secrets we never use. Avoids unnecessary backend calls and reduces audit noise. ✅

4. **Session-scoped placeholders.** Each `redan exec` generates new random placeholders. No placeholder reuse across sessions. Prevents any kind of replay. ✅

5. **redan.toml committed to repo.** Policy is versioned and reviewable. Secret values never in the file. ✅

## Open Questions

1. **Multiple secrets for the same host:** What if both `GITHUB_TOKEN` and `GITHUB_APP_KEY` are configured for `api.github.com`? Which gets injected? Answer: both, in different headers. The config must specify different `header` values. Validate this at config parse time.

2. **Backend authentication failure at session start:** If Vault is down, should `redan exec` fail immediately or start the VM without those secrets (and fail when they're needed)? Recommendation: fail fast for `prefetch = true` secrets, lazy failure for others.

3. **Secret value size limits:** Some secrets are large (TLS certificates, JSON blobs). Does the MITM proxy handle multi-KB header values correctly? Probably yes but needs testing.

4. **Mutual TLS (mTLS):** Some enterprise APIs require client certificates. How does this work with the MITM proxy? The proxy would need to present the client cert to the destination. This is a different injection mode — cert injection, not header injection. Defer to v1.1.
