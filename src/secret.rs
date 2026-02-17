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
    /// Returns `Err` if `real_value` contains CR or LF (header injection risk).
    /// Placeholder embeds env name (lowercased) + hash suffix.
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

    if count == 0 {
        return (data.to_vec(), 0);
    }

    // Reassemble: request line + modified headers + body
    let mut result = Vec::with_capacity(data.len());
    result.extend_from_slice(&data[..request_line_end]);
    result.extend_from_slice(&header_bytes);
    result.extend_from_slice(&data[header_end..]);
    (result, count)
}

/// Replace real secret values with placeholders in an HTTP response.
///
/// Best-effort: matches literal bytes only. See module docs for limitations.
///
/// Returns the (possibly modified) response data and the number of scrubs.
pub fn scrub(data: &[u8], secrets: &[SecretBinding]) -> (Vec<u8>, usize) {
    let mut result = data.to_vec();
    let mut count = 0;

    for secret in secrets {
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
        let (result, count) = scrub(resp, &secrets);
        assert_eq!(count, 1);
        assert!(result.windows(18).any(|w| w == b"redan_ph_test_1234"));
        assert!(!result.windows(21).any(|w| w == b"ghp_RealSecretValue99"));
    }

    #[test]
    fn scrub_no_match_returns_unchanged() {
        let secrets = vec![test_binding()];
        let resp = b"HTTP/1.1 200 OK\r\n\r\nno secrets here";
        let (result, count) = scrub(resp, &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, resp);
    }

    #[test]
    fn scrub_handles_binary_data() {
        let secrets = vec![test_binding()];
        let resp: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x01]; // invalid UTF-8
        let (result, count) = scrub(&resp, &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, resp); // must not corrupt
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
}
