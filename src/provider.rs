//! Secret providers: pluggable backends for resolving secret values.
//!
//! The proxy needs real secret values to inject into requests. Where those
//! values come from is the provider's concern. The open-source CLI ships
//! with `Literal` (inline value) and `Vault` (HashiCorp Vault KV v2).
//!
//! ## Adding a provider
//!
//! Implement [`SecretProvider`] and register it in `resolve_secret_value`
//! in main.rs. The trait is deliberately simple: one method, no async.

use std::io::{self, Read};

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

/// Fetches secrets from HashiCorp Vault KV v2.
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
    token: String,
}

impl Vault {
    /// Create from environment. Returns an error if no token is available.
    pub fn from_env() -> Result<Self, io::Error> {
        let addr =
            std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());

        let token = std::env::var("VAULT_TOKEN").or_else(|_| {
            let home = std::env::var("HOME")
                .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "$HOME not set"))?;
            std::fs::read_to_string(format!("{home}/.vault-token")).map(|t| t.trim().to_string())
        })?;

        if token.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no Vault token: set VAULT_TOKEN or write to ~/.vault-token",
            ));
        }

        Ok(Self { addr, token })
    }

    /// Create with explicit address and token (for testing).
    pub fn new(addr: &str, token: &str) -> Self {
        Self {
            addr: addr.to_string(),
            token: token.to_string(),
        }
    }
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
        let api_path = if let Some(rest) = path.strip_prefix("secret/") {
            // Already has mount prefix: secret/foo -> secret/data/foo
            format!("secret/data/{rest}")
        } else {
            format!("secret/data/{path}")
        };

        let url = format!("{}/v1/{api_path}", self.addr);

        // Minimal HTTP client. No dependency on reqwest/ureq -- redan
        // links against rustls already, but for Vault (localhost or
        // internal network) plain HTTP is fine and simpler.
        let response = http_get(&url, &self.token)?;

        // Parse JSON response. Vault KV v2 wraps data in:
        // { "data": { "data": { "field": "value" } } }
        let value = extract_vault_field(&response, field).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("field '{field}' not found at vault path '{path}'"),
            )
        })?;

        Ok(value)
    }
}

/// Minimal HTTP GET with a Vault token header.
fn http_get(url: &str, token: &str) -> Result<String, io::Error> {
    use std::net::TcpStream;

    let url_without_scheme = url
        .strip_prefix("http://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "only http:// supported"))?;

    let (host_port, path) = url_without_scheme
        .split_once('/')
        .unwrap_or((url_without_scheme, ""));

    let mut stream = TcpStream::connect(host_port)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;

    let request = format!(
        "GET /{path} HTTP/1.1\r\n\
         Host: {host_port}\r\n\
         X-Vault-Token: {token}\r\n\
         Connection: close\r\n\
         \r\n"
    );

    io::Write::write_all(&mut stream, request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    // Strip HTTP headers
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or(&response);

    // Check for HTTP errors (crude but sufficient)
    if response.contains("HTTP/1.1 4") || response.contains("HTTP/1.1 5") {
        return Err(io::Error::other(format!(
            "vault returned error: {}",
            response.lines().next().unwrap_or("")
        )));
    }

    Ok(body.to_string())
}

/// Extract a field from Vault KV v2 JSON response.
///
/// Vault wraps KV v2 data as: `{"data": {"data": {"field": "value"}}}`.
/// We parse with a minimal JSON approach: no serde dependency.
fn extract_vault_field(json: &str, field: &str) -> Option<String> {
    // Find the inner data object. Vault KV v2 nests it as data.data.
    // Strategy: find `"data":{` twice (outer and inner), then find our field.
    //
    // This is intentionally simple. A full JSON parser would be more
    // correct but adds complexity for a well-defined response format.
    let inner = find_nested_data(json)?;
    extract_json_string(inner, field)
}

/// Find the inner `"data": { ... }` within Vault's response.
fn find_nested_data(json: &str) -> Option<&str> {
    // Find first "data": which is the wrapper
    let first = json.find("\"data\"")?;
    let after_first = &json[first + 6..];
    // Skip to the value (past whitespace and colon)
    let brace = after_first.find('{')?;
    let inner_json = &after_first[brace..];

    // Find second "data": which is the actual secret data
    let second = inner_json.find("\"data\"")?;
    let after_second = &inner_json[second + 6..];
    let brace2 = after_second.find('{')?;
    let data_start = &after_second[brace2..];

    // Find the matching closing brace
    let mut depth = 0;
    for (i, ch) in data_start.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&data_start[..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract a string value from a flat JSON object.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let pos = json.find(&needle)?;
    let after_key = &json[pos + needle.len()..];
    // Skip : and whitespace
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    // Expect a quoted string
    if !after_colon.starts_with('"') {
        return None;
    }
    let value_start = 1; // skip opening quote
    let value_end = after_colon[value_start..].find('"')?;
    Some(after_colon[value_start..value_start + value_end].to_string())
}

/// Parse a secret value reference and resolve it via the appropriate provider.
///
/// Scheme detection:
/// - `vault://path#field` -> Vault KV v2
/// - anything else -> literal value (backward compatible)
pub fn resolve_secret_value(reference: &str) -> Result<String, io::Error> {
    if let Some(vault_ref) = reference.strip_prefix("vault://") {
        let vault = Vault::from_env()?;
        vault.resolve(vault_ref)
    } else {
        Literal.resolve(reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn extract_vault_field_parses_kv2_response() {
        let json = r#"{"request_id":"abc","data":{"data":{"github_token":"ghp_test123","npm_token":"npm_test456"},"metadata":{"version":1}}}"#;
        assert_eq!(
            extract_vault_field(json, "github_token"),
            Some("ghp_test123".to_string())
        );
        assert_eq!(
            extract_vault_field(json, "npm_token"),
            Some("npm_test456".to_string())
        );
        assert_eq!(extract_vault_field(json, "nonexistent"), None);
    }

    #[test]
    fn extract_vault_field_handles_whitespace() {
        let json = r#"{
            "data": {
                "data": {
                    "key": "value with spaces"
                }
            }
        }"#;
        assert_eq!(
            extract_vault_field(json, "key"),
            Some("value with spaces".to_string())
        );
    }

    #[test]
    fn resolve_literal_no_scheme() {
        assert_eq!(resolve_secret_value("plain-value").unwrap(), "plain-value");
    }

    // Integration tests against real Vault (require VAULT_ADDR + VAULT_TOKEN)

    #[test]
    #[ignore = "requires running Vault"]
    fn vault_fetch_real_secret() {
        let vault = Vault::from_env().expect("Vault env not configured");
        let value = vault.resolve("redan/test#github_token").unwrap();
        assert_eq!(value, "ghp_test123");
    }

    #[test]
    #[ignore = "requires running Vault"]
    fn vault_fetch_second_field() {
        let vault = Vault::from_env().expect("Vault env not configured");
        let value = vault.resolve("redan/test#npm_token").unwrap();
        assert_eq!(value, "npm_test456");
    }

    #[test]
    #[ignore = "requires running Vault"]
    fn vault_missing_field_errors() {
        let vault = Vault::from_env().expect("Vault env not configured");
        let err = vault.resolve("redan/test#nonexistent").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    #[ignore = "requires running Vault"]
    fn vault_missing_path_errors() {
        let vault = Vault::from_env().expect("Vault env not configured");
        let err = vault.resolve("nonexistent/path#field").unwrap_err();
        assert!(err.to_string().contains("error"));
    }

    #[test]
    #[ignore = "requires running Vault"]
    fn vault_via_resolve_function() {
        let value = resolve_secret_value("vault://redan/test#github_token").unwrap();
        assert_eq!(value, "ghp_test123");
    }
}
