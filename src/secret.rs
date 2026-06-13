//! Secret injection and response scrubbing.
//!
//! Secrets are defined as bindings between a placeholder token (visible to
//! the guest) and a real value (only in host memory). The proxy replaces
//! placeholders with real values in outbound HTTP request headers and scrubs
//! real values from inbound responses.
//!
//! ## Limitations
//!
//! Response scrubbing is best-effort. It matches the literal secret bytes.
//! Secrets reflected in encoded forms will not be caught, including:
//!
//! - Base64 encoding
//! - URL-encoding (percent-encoding)
//! - JSON unicode escapes (`\u0041` etc.)
//! - HTML entity encoding
//! - Compression (gzip, brotli, zstd, deflate)
//!
//! Primary defense against compression bypass: outgoing requests have
//! `Accept-Encoding` stripped, forcing upstream to return uncompressed
//! responses.
//!
//! Scrubbing reduces accidental exposure; it is not a hard security
//! boundary. The primary protection is host-based allowlisting -- secrets
//! are only injected for requests to explicitly permitted hosts.

use zeroize::{Zeroize, Zeroizing};

/// A secret the proxy knows how to inject.
///
/// `real_value` is wrapped in `Zeroizing<String>` so the secret bytes
/// are overwritten with zeros when the binding is dropped. This prevents
/// secrets from lingering in freed heap memory (core dumps, swap, etc.).
#[derive(Clone)]
pub struct SecretBinding {
    placeholder: String,
    real_value: Zeroizing<String>,
    allowed_hosts: Vec<String>,
}

impl SecretBinding {
    pub fn placeholder(&self) -> &str {
        &self.placeholder
    }

    pub fn real_value(&self) -> &str {
        &self.real_value
    }

    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }
}

impl SecretBinding {
    /// Create a binding with an auto-generated placeholder.
    ///
    /// Returns `Err` if `real_value` contains CR or LF (header injection risk),
    /// or if any allowed host contains a wildcard. Placeholder embeds env name
    /// (lowercased) + hash suffix.
    pub fn new(
        env_name: &str,
        real_value: String,
        allowed_hosts: Vec<String>,
    ) -> Result<Self, crate::error::Error> {
        if real_value.contains('\r') || real_value.contains('\n') {
            return Err(
                format!("secret for {env_name} contains CR/LF (header injection risk)").into(),
            );
        }

        // Injection matches the TLS SNI by exact (case-insensitive) hostname,
        // not by wildcard. A wildcard host would be added to the connection
        // allowlist (which does match wildcards) yet never inject, failing
        // silently. Reject it so the misconfiguration surfaces.
        if let Some(host) = allowed_hosts.iter().find(|h| h.contains('*')) {
            return Err(format!(
                "secret for {env_name} has wildcard host {host:?}; secret hosts must be exact \
                 hostnames (injection matches the TLS SNI exactly, not by wildcard)"
            )
            .into());
        }

        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf).map_err(|e| format!("failed to generate placeholder: {e}"))?;
        let suffix = buf.map(|b| format!("{b:02x}")).join("");

        Ok(Self {
            placeholder: format!("redan_ph_{}_{suffix}", env_name.to_lowercase()),
            real_value: Zeroizing::new(real_value),
            allowed_hosts,
        })
    }
}

impl std::fmt::Debug for SecretBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBinding")
            .field("placeholder", &self.placeholder)
            .field("real_value", &"[REDACTED]")
            .field("allowed_hosts", &self.allowed_hosts())
            .finish()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl SecretBinding {
    /// Construct with explicit fields, bypassing CRLF validation.
    ///
    /// Available only under `#[cfg(test)]` or the `test-support` feature.
    /// Production code should use `new()` which validates.
    pub fn new_unchecked(
        placeholder: String,
        real_value: String,
        allowed_hosts: Vec<String>,
    ) -> Self {
        Self {
            placeholder,
            real_value: Zeroizing::new(real_value),
            allowed_hosts,
        }
    }
}

impl Drop for SecretBinding {
    fn drop(&mut self) {
        // Zeroizing<String> handles real_value automatically.
        // Also zeroize the placeholder since it could aid reverse-engineering.
        self.placeholder.zeroize();
    }
}

/// Replace placeholder tokens with real values in HTTP request headers only.
///
/// The request line and body are left untouched to prevent secrets from
/// leaking into URL paths, query strings, or request bodies that could
/// end up in server logs, CDN caches, or Referer headers.
///
/// Two passes run in sequence:
/// 1. Literal byte replacement (handles `Authorization: Bearer <ph>`, etc.)
/// 2. Base64 Basic auth: decode `Authorization: Basic <b64>`, replace any
///    placeholder inside the decoded credentials, re-encode.
///
/// Returns the (possibly modified) request data and the number of injections.
#[must_use]
pub fn inject(data: &[u8], hostname: &str, secrets: &[SecretBinding]) -> (Vec<u8>, usize) {
    let header_end = find_header_end(data).unwrap_or(data.len());
    // Find end of request line (first \r\n)
    let request_line_end = data[..header_end]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map_or(0, |p| p + 2);

    // Only operate on headers (between request line and body)
    let headers = &data[request_line_end..header_end];
    let mut header_bytes = headers.to_vec();
    let mut count = 0;

    for secret in secrets {
        if !secret
            .allowed_hosts()
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(hostname))
        {
            continue;
        }
        if let Some((replaced, n)) = byte_replace(
            &header_bytes,
            secret.placeholder().as_bytes(),
            secret.real_value().as_bytes(),
        ) {
            header_bytes = replaced;
            count += n;
        }
    }

    // Reassemble after literal pass (even if count == 0, Basic auth pass may
    // still find something below).
    let intermediate = if count > 0 {
        let mut buf = Vec::with_capacity(data.len());
        buf.extend_from_slice(&data[..request_line_end]);
        buf.extend_from_slice(&header_bytes);
        buf.extend_from_slice(&data[header_end..]);
        buf
    } else {
        data.to_vec()
    };

    // Pass 2: Base64 Basic auth injection.
    let (result, basic_count) = inject_basic_auth(&intermediate, hostname, secrets);
    let total = count + basic_count;
    if total == 0 {
        return (data.to_vec(), 0);
    }
    (result, total)
}

/// Decode `Authorization: Basic <b64>`, replace placeholders, re-encode.
///
/// Handles the common pattern where an agent passes a placeholder as the
/// username or password of HTTP Basic credentials. The decoded credentials
/// are treated as an opaque string -- both username and password fields are
/// eligible for replacement.
///
/// Returns (data, injections). Returns `(data.to_vec(), 0)` if nothing
/// changed, so the caller never sees a spurious allocation.
fn inject_basic_auth(data: &[u8], hostname: &str, secrets: &[SecretBinding]) -> (Vec<u8>, usize) {
    let applicable: Vec<&SecretBinding> = secrets
        .iter()
        .filter(|s| {
            s.allowed_hosts()
                .iter()
                .any(|h| h.eq_ignore_ascii_case(hostname))
        })
        .collect();

    if applicable.is_empty() {
        return (data.to_vec(), 0);
    }

    let mut parsed_headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut parsed_headers);
    let Ok(httparse::Status::Complete(body_offset)) = req.parse(data) else {
        return (data.to_vec(), 0);
    };

    let method = req.method.unwrap_or("GET");
    let path = req.path.unwrap_or("/");
    let version = req.version.unwrap_or(1);

    let mut result = Vec::with_capacity(data.len());
    result.extend_from_slice(format!("{method} {path} HTTP/1.{version}\r\n").as_bytes());

    let mut total = 0;
    let mut any_injected = false;

    for header in req.headers.iter() {
        if header.name.eq_ignore_ascii_case("authorization")
            && let Some((new_b64, n)) = try_inject_basic(header.value, &applicable)
        {
            result.extend_from_slice(b"Authorization: Basic ");
            result.extend_from_slice(new_b64.as_bytes());
            result.extend_from_slice(b"\r\n");
            total += n;
            any_injected = true;
            continue;
        }
        result.extend_from_slice(header.name.as_bytes());
        result.extend_from_slice(b": ");
        result.extend_from_slice(header.value);
        result.extend_from_slice(b"\r\n");
    }
    result.extend_from_slice(b"\r\n");
    result.extend_from_slice(&data[body_offset..]);

    if !any_injected {
        return (data.to_vec(), 0);
    }
    (result, total)
}

/// Try to inject secrets into a single `Authorization: Basic` header value.
///
/// `value` is the raw header value bytes (e.g. `Basic dXNlcjpwYXNz`).
/// Returns `Some((new_b64, count))` if any placeholder was replaced,
/// `None` if the header is not Basic auth or no placeholder was found.
fn try_inject_basic(value: &[u8], secrets: &[&SecretBinding]) -> Option<(String, usize)> {
    let value_str = std::str::from_utf8(value).ok()?;
    let encoded = value_str.strip_prefix("Basic ")?.trim();

    let decoded_bytes =
        base64::engine::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    let mut decoded = String::from_utf8(decoded_bytes).ok()?;

    let mut count = 0;
    for secret in secrets {
        if decoded.contains(secret.placeholder()) {
            decoded = decoded.replace(secret.placeholder(), secret.real_value());
            count += 1;
        }
    }

    if count == 0 {
        return None;
    }

    let re_encoded =
        base64::engine::Engine::encode(&base64::engine::general_purpose::STANDARD, &decoded);
    Some((re_encoded, count))
}

/// Replace real secret values with placeholders in an HTTP response.
///
/// Only secrets whose `allowed_hosts` include `hostname` are scrubbed, so a
/// response from one host can't expose a secret scoped to another. Mirrors
/// the host filtering in [`inject`].
///
/// Best-effort: matches literal bytes only. See module docs for limitations.
///
/// Returns the (possibly modified) response data and the number of scrubs.
pub fn scrub(data: &[u8], hostname: &str, secrets: &[SecretBinding]) -> (Vec<u8>, usize) {
    let mut result = data.to_vec();
    let mut count = 0;

    for secret in secrets {
        if !secret
            .allowed_hosts()
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(hostname))
        {
            continue;
        }
        if let Some((replaced, n)) = byte_replace(
            &result,
            secret.real_value().as_bytes(),
            secret.placeholder().as_bytes(),
        ) {
            result = replaced;
            count += n;
        }
    }

    (result, count)
}

/// Rewrite outgoing request headers.
///
/// Strips Accept-Encoding (forces uncompressed responses for scrubbing)
/// and forces Connection: close (so upstream closes after the response,
/// preventing keep-alive stalls on responses with no Content-Length or
/// Transfer-Encoding).
///
/// Uses httparse for header parsing to handle RFC 7230 edge cases
/// (obs-fold, case-insensitive names). The body is passed through
/// as raw bytes.
pub fn rewrite_request_headers(data: &[u8]) -> Vec<u8> {
    let mut parsed_headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut parsed_headers);
    // Incomplete or malformed: return data as-is (safe default)
    let Ok(httparse::Status::Complete(body_offset)) = req.parse(data) else {
        return data.to_vec();
    };

    // Rebuild: request line + filtered headers + body
    let method = req.method.unwrap_or("GET");
    let path = req.path.unwrap_or("/");
    let version = req.version.unwrap_or(1);
    let mut result = Vec::with_capacity(data.len());
    result.extend_from_slice(format!("{method} {path} HTTP/1.{version}\r\n").as_bytes());

    let mut has_connection = false;
    for header in req.headers.iter() {
        if header.name.eq_ignore_ascii_case("accept-encoding") {
            continue;
        }
        if header.name.eq_ignore_ascii_case("connection") {
            result.extend_from_slice(b"Connection: close\r\n");
            has_connection = true;
            continue;
        }
        result.extend_from_slice(header.name.as_bytes());
        result.extend_from_slice(b": ");
        result.extend_from_slice(header.value);
        result.extend_from_slice(b"\r\n");
    }
    if !has_connection {
        result.extend_from_slice(b"Connection: close\r\n");
    }
    result.extend_from_slice(b"\r\n");
    result.extend_from_slice(&data[body_offset..]);
    result
}

/// Find the byte offset past \r\n\r\n (header/body separator).
pub(crate) fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

/// Replace all occurrences of `needle` in `haystack` with `replacement`.
/// Returns `None` if needle is not found (avoids allocation).
/// Returns `Some((result, count))` with the number of replacements made.
/// Operates on raw bytes -- no UTF-8 assumptions.
fn byte_replace(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Option<(Vec<u8>, usize)> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }

    let mut result = Vec::new();
    let mut last_end = 0;
    let mut count = 0;
    let mut i = 0;

    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            count += 1;
            result.extend_from_slice(&haystack[last_end..i]);
            result.extend_from_slice(replacement);
            i += needle.len();
            last_end = i;
        } else {
            i += 1;
        }
    }

    if count == 0 {
        return None;
    }

    result.extend_from_slice(&haystack[last_end..]);
    Some((result, count))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_binding() -> SecretBinding {
        SecretBinding::new_unchecked(
            "redan_ph_test_1234".into(),
            "ghp_RealSecretValue99".into(),
            vec!["api.github.com".into(), "httpbin.org".into()],
        )
    }

    #[test]
    fn inject_replaces_placeholder_in_headers() {
        let secrets = vec![test_binding()];
        let req = b"POST /api HTTP/1.1\r\nAuthorization: Bearer redan_ph_test_1234\r\nHost: api.github.com\r\n\r\nbody";
        let (result, count) = inject(req, "api.github.com", &secrets);
        assert_eq!(count, 1);
        let text = String::from_utf8_lossy(&result);
        assert!(text.contains("ghp_RealSecretValue99"));
        assert!(!text.contains("redan_ph_test_1234"));
        // Body preserved
        assert!(text.ends_with("body"));
    }

    #[test]
    fn inject_does_not_touch_url_path() {
        let secrets = vec![test_binding()];
        let req = b"GET /log?token=redan_ph_test_1234 HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
        let (result, count) = inject(req, "api.github.com", &secrets);
        assert_eq!(count, 0);
        // Placeholder must remain in the URL
        assert!(result.windows(18).any(|w| w == b"redan_ph_test_1234"));
    }

    #[test]
    fn inject_does_not_touch_body() {
        let secrets = vec![test_binding()];
        let req = b"POST /api HTTP/1.1\r\nHost: api.github.com\r\n\r\nredan_ph_test_1234";
        let (result, count) = inject(req, "api.github.com", &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, req);
    }

    #[test]
    fn inject_skips_disallowed_host() {
        let secrets = vec![test_binding()];
        let req = b"GET / HTTP/1.1\r\nAuthorization: Bearer redan_ph_test_1234\r\n\r\n";
        let (result, count) = inject(req, "evil.com", &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, req);
    }

    #[test]
    fn inject_no_match_returns_unchanged() {
        let secrets = vec![test_binding()];
        let req = b"GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
        let (result, count) = inject(req, "api.github.com", &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, req);
    }

    #[test]
    fn scrub_removes_real_value() {
        let secrets = vec![test_binding()];
        let resp = b"Token: ghp_RealSecretValue99 is active";
        let (result, count) = scrub(resp, "api.github.com", &secrets);
        assert_eq!(count, 1);
        assert!(result.windows(18).any(|w| w == b"redan_ph_test_1234"));
        assert!(!result.windows(21).any(|w| w == b"ghp_RealSecretValue99"));
    }

    #[test]
    fn scrub_no_match_returns_unchanged() {
        let secrets = vec![test_binding()];
        let resp = b"HTTP/1.1 200 OK\r\n\r\nno secrets here";
        let (result, count) = scrub(resp, "api.github.com", &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, resp);
    }

    #[test]
    fn scrub_handles_binary_data() {
        let secrets = vec![test_binding()];
        let resp: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x01]; // invalid UTF-8
        let (result, count) = scrub(&resp, "api.github.com", &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, resp); // must not corrupt
    }

    #[test]
    fn scrub_skips_disallowed_host() {
        // A response from a host the secret is not bound to must not be
        // scrubbed: scrub() filters on allowed_hosts the way inject() does.
        let secrets = vec![test_binding()];
        let resp = b"Token: ghp_RealSecretValue99 is active";
        let (result, count) = scrub(resp, "evil.com", &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, resp);
    }

    #[test]
    fn byte_replace_finds_needle() {
        let (result, count) = byte_replace(b"hello world", b"world", b"rust").unwrap();
        assert_eq!(result, b"hello rust");
        assert_eq!(count, 1);
    }

    #[test]
    fn byte_replace_multiple_occurrences() {
        let (result, count) = byte_replace(b"aa bb aa cc aa", b"aa", b"xx").unwrap();
        assert_eq!(result, b"xx bb xx cc xx");
        assert_eq!(count, 3);
    }

    #[test]
    fn byte_replace_no_match() {
        assert!(byte_replace(b"hello world", b"xyz", b"abc").is_none());
    }

    #[test]
    fn debug_redacts_real_value() {
        let b = test_binding();
        let debug = format!("{b:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("ghp_RealSecretValue99"));
    }

    // --- Basic auth injection ---

    fn basic_b64(user: &str, pass: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
    }

    #[test]
    fn inject_basic_auth_placeholder_as_password() {
        let secrets = vec![test_binding()];
        let b64 = basic_b64("user", "redan_ph_test_1234");
        let req =
            format!("GET / HTTP/1.1\r\nAuthorization: Basic {b64}\r\nHost: api.github.com\r\n\r\n");
        let (result, count) = inject(req.as_bytes(), "api.github.com", &secrets);
        assert_eq!(count, 1);
        let expected_b64 = basic_b64("user", "ghp_RealSecretValue99");
        let text = String::from_utf8_lossy(&result);
        assert!(text.contains(&expected_b64), "re-encoded b64 not found");
        assert!(!text.contains(&b64), "original b64 still present");
    }

    #[test]
    fn inject_basic_auth_placeholder_as_username() {
        let secrets = vec![test_binding()];
        let b64 = basic_b64("redan_ph_test_1234", "");
        let req =
            format!("GET / HTTP/1.1\r\nAuthorization: Basic {b64}\r\nHost: api.github.com\r\n\r\n");
        let (result, count) = inject(req.as_bytes(), "api.github.com", &secrets);
        assert_eq!(count, 1);
        let expected_b64 = basic_b64("ghp_RealSecretValue99", "");
        let text = String::from_utf8_lossy(&result);
        assert!(text.contains(&expected_b64));
    }

    #[test]
    fn inject_basic_auth_wrong_host_no_injection() {
        let secrets = vec![test_binding()];
        let b64 = basic_b64("user", "redan_ph_test_1234");
        let req = format!("GET / HTTP/1.1\r\nAuthorization: Basic {b64}\r\nHost: evil.com\r\n\r\n");
        let (result, count) = inject(req.as_bytes(), "evil.com", &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, req.as_bytes());
    }

    #[test]
    fn inject_basic_auth_bearer_unchanged() {
        // Bearer headers must not be decoded as if they were Basic
        let secrets = vec![test_binding()];
        let req = b"GET / HTTP/1.1\r\nAuthorization: Bearer redan_ph_test_1234\r\nHost: api.github.com\r\n\r\n";
        let (result, count) = inject(req, "api.github.com", &secrets);
        // The Bearer placeholder is caught by the literal pass, not the Basic pass
        assert_eq!(count, 1);
        let text = String::from_utf8_lossy(&result);
        assert!(text.contains("ghp_RealSecretValue99"));
        assert!(!text.contains("redan_ph_test_1234"));
    }

    #[test]
    fn inject_basic_auth_invalid_b64_unchanged() {
        let secrets = vec![test_binding()];
        let req = b"GET / HTTP/1.1\r\nAuthorization: Basic not-valid-b64!!!\r\nHost: api.github.com\r\n\r\n";
        let (result, count) = inject(req, "api.github.com", &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, req.to_vec());
    }

    #[test]
    fn inject_basic_auth_no_placeholder_in_credentials_unchanged() {
        let secrets = vec![test_binding()];
        let b64 = basic_b64("user", "unrelated-password");
        let req =
            format!("GET / HTTP/1.1\r\nAuthorization: Basic {b64}\r\nHost: api.github.com\r\n\r\n");
        let (result, count) = inject(req.as_bytes(), "api.github.com", &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, req.as_bytes());
    }

    #[test]
    fn new_rejects_wildcard_host() {
        // Injection matches the SNI exactly, so a wildcard host would silently
        // never inject. Reject it loudly at construction instead.
        let err = SecretBinding::new("TOKEN", "val".into(), vec!["*.github.com".into()])
            .expect_err("wildcard host must be rejected");
        assert!(err.to_string().contains("wildcard"), "got: {err}");
    }

    #[test]
    fn new_accepts_exact_hosts() {
        let binding = SecretBinding::new(
            "TOKEN",
            "val".into(),
            vec!["api.github.com".into(), "github.com".into()],
        )
        .expect("exact hosts must be accepted");
        assert_eq!(binding.allowed_hosts(), &["api.github.com", "github.com"]);
    }
}
