//! Secret injection and response scrubbing.
//!
//! Secrets are defined as bindings between a placeholder token (visible to
//! the guest) and a real value (only in host memory). The proxy replaces
//! placeholders with real values in outbound requests and scrubs real values
//! from inbound responses.

/// A secret the proxy knows how to inject.
#[derive(Debug, Clone)]
pub struct SecretBinding {
    /// Placeholder token visible to the guest (e.g., `redan_ph_github_a1b2c3d4`)
    pub placeholder: String,
    /// Real secret value, only in host memory
    pub real_value: String,
    /// Hosts this secret may be injected for (e.g., `["api.github.com"]`)
    pub allowed_hosts: Vec<String>,
}

/// Replace placeholder tokens with real values in an HTTP request.
///
/// Returns the (possibly modified) request data and the number of injections.
pub fn inject(data: &[u8], hostname: &str, secrets: &[SecretBinding]) -> (Vec<u8>, usize) {
    let mut result = data.to_vec();
    let mut count = 0;

    for secret in secrets {
        if !secret.allowed_hosts.iter().any(|h| h == hostname) {
            continue;
        }
        let text = String::from_utf8_lossy(&result);
        if text.contains(&secret.placeholder) {
            let replaced = text.replace(&secret.placeholder, &secret.real_value);
            result = replaced.into_bytes();
            count += 1;
        }
    }

    (result, count)
}

/// Replace real secret values with placeholders in an HTTP response.
///
/// Returns the (possibly modified) response data and the number of scrubs.
pub fn scrub(data: &[u8], secrets: &[SecretBinding]) -> (Vec<u8>, usize) {
    let mut result = data.to_vec();
    let mut count = 0;

    for secret in secrets {
        let text = String::from_utf8_lossy(&result);
        if text.contains(&secret.real_value) {
            let cleaned = text.replace(&secret.real_value, &secret.placeholder);
            result = cleaned.into_bytes();
            count += 1;
        }
    }

    (result, count)
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
    fn inject_replaces_placeholder() {
        let secrets = vec![test_binding()];
        let req = b"Authorization: Bearer redan_ph_test_1234\r\n";
        let (result, count) = inject(req, "api.github.com", &secrets);
        assert_eq!(count, 1);
        assert!(String::from_utf8_lossy(&result).contains("ghp_RealSecretValue99"));
        assert!(!String::from_utf8_lossy(&result).contains("redan_ph_test_1234"));
    }

    #[test]
    fn inject_skips_disallowed_host() {
        let secrets = vec![test_binding()];
        let req = b"Authorization: Bearer redan_ph_test_1234\r\n";
        let (result, count) = inject(req, "evil.com", &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, req);
    }

    #[test]
    fn inject_no_match_returns_unchanged() {
        let secrets = vec![test_binding()];
        let req = b"GET / HTTP/1.1\r\nHost: api.github.com\r\n";
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
        let text = String::from_utf8_lossy(&result);
        assert!(text.contains("redan_ph_test_1234"));
        assert!(!text.contains("ghp_RealSecretValue99"));
    }

    #[test]
    fn scrub_no_match_returns_unchanged() {
        let secrets = vec![test_binding()];
        let resp = b"HTTP/1.1 200 OK\r\n\r\nno secrets here";
        let (result, count) = scrub(resp, &secrets);
        assert_eq!(count, 0);
        assert_eq!(result, resp);
    }
}
