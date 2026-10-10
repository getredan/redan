//! Secret providers: pluggable backends for resolving secret values.
//!
//! The proxy needs real secret values to inject into requests. Where those
//! values come from is the provider's concern. The open-source CLI ships
//! with `Literal` (inline value) and `Vault` (`HashiCorp` Vault KV v2).
//!
//! ## Adding a provider
//!
//! Implement [`SecretProvider`] and register it in `resolve_secret_value`
//! in main.rs. The trait is deliberately simple: one method, no async.

use std::collections::HashMap;
use std::io;

use serde::Deserialize;

/// Resolves a secret reference to its real value.
///
/// Providers are stateless per call. Connection pooling or caching is
/// the provider's responsibility if needed.
pub trait SecretProvider {
    /// Fetch the secret value for the given reference.
    ///
    /// The reference format is provider-specific:
    /// - Literal: the value itself
    /// - Vault: `path#field` (e.g., `secret/redan/test#github_token`)
    fn resolve(&self, reference: &str) -> Result<String, io::Error>;
}

/// Returns the value as-is. Used for `--secret ENV=value:hosts`.
pub struct Literal;

impl SecretProvider for Literal {
    fn resolve(&self, reference: &str) -> Result<String, io::Error> {
        Ok(reference.to_string())
    }
}

/// Reads a secret from a host environment variable.
///
/// The reference is the variable name. The variable is read at resolve
/// time from the host environment, not from inside the VM.
///
/// Fails if the variable is not set or is empty.
pub struct Env;

impl SecretProvider for Env {
    fn resolve(&self, reference: &str) -> Result<String, io::Error> {
        resolve_env_with(reference, |name| std::env::var(name).ok())
    }
}

/// Applies the `Env` provider rules on top of `lookup`, which returns the
/// variable's value, or `None` when it is unset or not valid Unicode.
fn resolve_env_with(
    reference: &str,
    lookup: impl FnOnce(&str) -> Option<String>,
) -> Result<String, io::Error> {
    if reference.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "env:// variable name cannot be empty",
        ));
    }
    let value = lookup(reference).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("environment variable '{reference}' is not set"),
        )
    })?;
    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("environment variable '{reference}' is set but empty"),
        ));
    }
    Ok(value)
}

/// Fetches secrets from `HashiCorp` Vault KV v2.
///
/// Reference format: `path#field` where path is the KV path and field
/// is the JSON key within the secret data.
///
/// Configuration via standard Vault environment variables:
/// - `VAULT_ADDR`: Vault server URL (default: `http://127.0.0.1:8200`)
/// - `VAULT_TOKEN`: authentication token
///
/// Falls back to `~/.vault-token` if `VAULT_TOKEN` is not set.
pub struct Vault {
    addr: String,
    token: zeroize::Zeroizing<String>,
}

impl Vault {
    /// Create from environment. Returns an error if no token is available.
    pub fn from_env() -> Result<Self, io::Error> {
        let addr =
            std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());

        let token = std::env::var("VAULT_TOKEN").or_else(|_| {
            let home = std::env::var("HOME")
                .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "$HOME not set"))?;
            std::fs::read_to_string(format!("{home}/.vault-token"))
                .map(|token| token.trim().to_string())
        })?;

        if token.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no Vault token: set VAULT_TOKEN or write to ~/.vault-token",
            ));
        }

        Ok(Self {
            addr,
            token: zeroize::Zeroizing::new(token),
        })
    }

    /// Create with explicit address and token (for testing).
    #[must_use]
    pub fn new(addr: &str, token: &str) -> Self {
        Self {
            addr: addr.to_string(),
            token: zeroize::Zeroizing::new(token.to_string()),
        }
    }
}

/// Vault KV v2 response envelope: `{"data": {"data": {"field": "value"}}}`.
#[derive(Deserialize)]
struct VaultKv2Response {
    data: VaultKv2Wrapper,
}

#[derive(Deserialize)]
struct VaultKv2Wrapper {
    data: HashMap<String, String>,
}

impl SecretProvider for Vault {
    fn resolve(&self, reference: &str) -> Result<String, io::Error> {
        let (path, field) = reference.split_once('#').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("vault reference must be path#field, got: {reference}"),
            )
        })?;

        // Vault KV v2: GET /v1/secret/data/<path>
        // The mount point is "secret" by default. If the path already
        // starts with the mount, the user can use the full API path.
        let api_path = path.strip_prefix("secret/").map_or_else(
            || format!("secret/data/{path}"),
            |rest| format!("secret/data/{rest}"),
        );

        let url = format!("{}/v1/{api_path}", self.addr);

        let mut response = ureq::get(&url)
            .header("X-Vault-Token", self.token.as_str())
            .call()
            .map_err(|e| io::Error::other(format!("vault request failed: {e}")))?;

        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|e| io::Error::other(format!("vault response read failed: {e}")))?;

        let envelope: VaultKv2Response = serde_json::from_str(&body)
            .map_err(|e| io::Error::other(format!("vault response parse failed: {e}")))?;

        envelope.data.data.get(field).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("field '{field}' not found at vault path '{path}'"),
            )
        })
    }
}

/// Parse a secret value reference and resolve it via the appropriate provider.
///
/// Scheme detection:
/// - `vault://path#field` -> Vault KV v2
/// - `env://VAR_NAME`    -> host environment variable
/// - anything else       -> literal value (backward compatible)
pub fn resolve_secret_value(reference: &str) -> Result<String, io::Error> {
    resolve_secret_value_with(reference, |name| std::env::var(name).ok())
}

/// Same as [`resolve_secret_value`], with the `env://` lookup supplied by the
/// caller so tests don't have to touch the process environment.
fn resolve_secret_value_with(
    reference: &str,
    env_lookup: impl FnOnce(&str) -> Option<String>,
) -> Result<String, io::Error> {
    if let Some(vault_ref) = reference.strip_prefix("vault://") {
        let vault = Vault::from_env()?;
        vault.resolve(vault_ref)
    } else if let Some(var_name) = reference.strip_prefix("env://") {
        resolve_env_with(var_name, env_lookup)
    } else {
        Literal.resolve(reference)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Builds an env lookup over a fixed list of variables, so tests never
    /// touch the process environment.
    fn lookup_in<'a>(vars: &'a [(&'a str, &'a str)]) -> impl FnOnce(&str) -> Option<String> + 'a {
        move |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn literal_returns_value() {
        let provider = Literal;
        assert_eq!(provider.resolve("my-secret").unwrap(), "my-secret");
    }

    #[test]
    fn literal_preserves_special_chars() {
        let provider = Literal;
        assert_eq!(
            provider.resolve("ghp_abc123!@#$%").unwrap(),
            "ghp_abc123!@#$%"
        );
    }

    #[test]
    fn vault_reference_requires_hash() {
        let vault = Vault::new("http://127.0.0.1:8200", "test-token");
        let err = vault.resolve("no-field-separator").unwrap_err();
        assert!(err.to_string().contains("path#field"));
    }

    #[test]
    fn serde_parses_kv2_response() {
        let json = r#"{"request_id":"abc","data":{"data":{"github_token":"ghp_test123","npm_token":"npm_test456"},"metadata":{"version":1}}}"#;
        let envelope: VaultKv2Response = serde_json::from_str(json).unwrap();
        assert_eq!(
            envelope.data.data.get("github_token").unwrap(),
            "ghp_test123"
        );
        assert_eq!(envelope.data.data.get("npm_token").unwrap(), "npm_test456");
        assert!(!envelope.data.data.contains_key("nonexistent"));
    }

    #[test]
    fn serde_parses_kv2_with_whitespace() {
        let json = r#"{
            "data": {
                "data": {
                    "key": "value with spaces"
                }
            }
        }"#;
        let envelope: VaultKv2Response = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.data.data.get("key").unwrap(), "value with spaces");
    }

    #[test]
    fn serde_handles_json_escapes_in_values() {
        // Escaped quotes in JSON values must round-trip correctly.
        let json = r#"{"data":{"data":{"token":"value\"with\\escapes"}}}"#;
        let envelope: VaultKv2Response = serde_json::from_str(json).unwrap();
        assert_eq!(
            envelope.data.data.get("token").unwrap(),
            r#"value"with\escapes"#
        );
    }

    #[test]
    fn serde_handles_unicode_escapes() {
        let json = r#"{"data":{"data":{"emoji":"\u0041\u0042\u0043"}}}"#;
        let envelope: VaultKv2Response = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.data.data.get("emoji").unwrap(), "ABC");
    }

    #[test]
    fn env_reads_set_variable() {
        let vars = [("_REDAN_TEST_VAR", "test-secret-value")];
        assert_eq!(
            resolve_env_with("_REDAN_TEST_VAR", lookup_in(&vars)).unwrap(),
            "test-secret-value"
        );
    }

    #[test]
    fn env_errors_on_unset_variable() {
        let err = resolve_env_with("_REDAN_TEST_UNSET", lookup_in(&[])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            err.to_string(),
            "environment variable '_REDAN_TEST_UNSET' is not set"
        );
    }

    #[test]
    fn env_errors_on_empty_variable() {
        let vars = [("_REDAN_TEST_EMPTY", "")];
        let err = resolve_env_with("_REDAN_TEST_EMPTY", lookup_in(&vars)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            err.to_string(),
            "environment variable '_REDAN_TEST_EMPTY' is set but empty"
        );
    }

    #[test]
    fn env_errors_on_empty_var_name() {
        let err = resolve_env_with("", |_| panic!("lookup must not run")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("empty"));
    }

    // Reads the real environment, which this test only reads. The name is
    // never set by anything in the test suite.
    #[test]
    fn env_provider_errors_on_unset_variable() {
        let err = Env.resolve("_REDAN_TEST_NEVER_SET_6F1C2D").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn resolve_env_scheme() {
        let vars = [("_REDAN_TEST_SCHEME", "from-env")];
        assert_eq!(
            resolve_secret_value_with("env://_REDAN_TEST_SCHEME", lookup_in(&vars)).unwrap(),
            "from-env"
        );
    }

    #[test]
    fn resolve_env_scheme_unset_errors() {
        let err = resolve_secret_value_with("env://_REDAN_TEST_SCHEME_UNSET", lookup_in(&[]))
            .unwrap_err();
        assert!(err.to_string().contains("not set"));
    }

    #[test]
    fn resolve_literal_no_scheme() {
        assert_eq!(resolve_secret_value("plain-value").unwrap(), "plain-value");
    }

    // Live Vault integration tests are in tests/vault.rs.
}
