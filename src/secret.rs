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

/// A secret the proxy knows how to inject.
#[derive(Clone)]
pub struct SecretBinding {
    /// Placeholder token visible to the guest (e.g., `redan_ph_github_a1b2c3d4`)
    pub placeholder: String,
    /// Real secret value, only in host memory.
    pub real_value: String,
    /// Hosts this secret may be injected for (e.g., `["api.github.com"]`).
    pub allowed_hosts: Vec<String>,
}

impl std::fmt::Debug for SecretBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBinding")
            .field("placeholder", &self.placeholder)
            .field("real_value", &"[REDACTED]")
            .field("allowed_hosts", &self.allowed_hosts)
            .finish()
    }
}

/// Replace placeholder tokens with real values in HTTP request headers only.
///
/// The request line and body are left untouched to prevent secrets from
/// leaking into URL paths, query strings, or request bodies that could
/// end up in server logs, CDN caches, or Referer headers.
///
/// Returns the (possibly modified) request data and the number of injections.
pub fn inject(data: &[u8], hostname: &str, secrets: &[SecretBinding]) -> (Vec<u8>, usize) {
    let header_end = find_header_end(data).unwrap_or(data.len());
    // Find end of request line (first \r\n)
    let request_line_end = data[..header_end]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| p + 2)
        .unwrap_or(0);

    // Only operate on headers (between request line and body)
    let headers = &data[request_line_end..header_end];
    let mut header_bytes = headers.to_vec();
    let mut count = 0;

    for secret in secrets {
        if !secret.allowed_hosts.iter().any(|h| h == hostname) {
            continue;
        }
        if let Some(replaced) = byte_replace(
            &header_bytes,
            secret.placeholder.as_bytes(),
            secret.real_value.as_bytes(),
        ) {
            header_bytes = replaced;
            count += 1;
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
        if let Some(replaced) = byte_replace(
            &result,
            secret.real_value.as_bytes(),
            secret.placeholder.as_bytes(),
        ) {
            result = replaced;
            count += 1;
        }
    }

    (result, count)
}

/// Strip `Accept-Encoding` header from an HTTP request.
///
/// Forces upstream to return uncompressed responses so that scrub()
/// can match literal secret bytes. Without this, gzip/br/zstd encoded
/// responses bypass scrubbing entirely.
pub fn strip_accept_encoding(data: &[u8]) -> Vec<u8> {
    let header_end = find_header_end(data).unwrap_or(data.len());
    let request_line_end = data[..header_end]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| p + 2)
        .unwrap_or(0);

    let mut result = Vec::with_capacity(data.len());
    result.extend_from_slice(&data[..request_line_end]);

    // Copy headers, skipping Accept-Encoding (case-insensitive)
    let headers = &data[request_line_end..header_end];
    let headers_str = String::from_utf8_lossy(headers);
    for line in headers_str.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if line.to_lowercase().starts_with("accept-encoding:") {
            continue;
        }
        result.extend_from_slice(line.as_bytes());
        result.extend_from_slice(b"\r\n");
    }

    // Body separator + body
    result.extend_from_slice(&data[header_end - 2..]);
    result
}

/// Find the byte offset of \r\n\r\n (header/body separator).
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

/// Replace all occurrences of `needle` in `haystack` with `replacement`.
/// Returns `None` if needle is not found (avoids allocation).
/// Operates on raw bytes -- no UTF-8 assumptions.
fn byte_replace(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Option<Vec<u8>> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }

    let mut result = Vec::new();
    let mut last_end = 0;
    let mut found = false;
    let mut i = 0;

    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            found = true;
            result.extend_from_slice(&haystack[last_end..i]);
            result.extend_from_slice(replacement);
            i += needle.len();
            last_end = i;
        } else {
            i += 1;
        }
    }

    if !found {
        return None;
    }

    result.extend_from_slice(&haystack[last_end..]);
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_binding() -> SecretBinding {
        SecretBinding {
            placeholder: "redan_ph_test_1234".into(),
            real_value: "ghp_RealSecretValue99".into(),
            allowed_hosts: vec!["api.github.com".into(), "httpbin.org".into()],
        }
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
        let result = byte_replace(b"hello world", b"world", b"rust").unwrap();
        assert_eq!(result, b"hello rust");
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
