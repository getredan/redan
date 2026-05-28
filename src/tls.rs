/// TLS utilities: upstream connection and SNI extraction (test only).
use std::net::TcpStream;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

/// Shared TLS client config with system root certificates.
/// Built once, reused for all upstream connections.
static UPSTREAM_TLS_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // Force HTTP/1.1 only. HTTP/2 binary framing would bypass our
    // HTTP/1.1 header parsing in inject() and scrub().
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
});

/// Connect to an upstream server over TLS, returning the TCP stream and
/// rustls client connection.
pub fn connect_upstream(
    hostname: &str,
    port: u16,
    allow_private: bool,
) -> Result<(TcpStream, rustls::ClientConnection), crate::error::Error> {
    use std::net::ToSocketAddrs;

    let addr = format!("{hostname}:{port}")
        .to_socket_addrs()?
        .find(std::net::SocketAddr::is_ipv4)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "DNS resolution failed")
        })?;

    // Block connections to private/reserved IP ranges unless the
    // host was explicitly in the allowlist. Prevents SSRF to cloud
    // metadata (169.254.169.254) and internal networks via DNS rebinding.
    // Hosts in the allowlist are trusted -- the user explicitly chose them.
    //
    // IPv4-only today: the .find(is_ipv4) above filters out AAAA records.
    // If IPv6 support is added, is_private_ipv6() must also be checked
    // to cover ::1, fe80::/10, fd00::/8, and ::ffff:169.254.169.254.
    if !allow_private
        && let std::net::SocketAddr::V4(v4) = &addr
        && is_private_ip(*v4.ip())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("blocked connection to private IP: {}", v4.ip()),
        )
        .into());
    }

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    stream.set_nonblocking(false)?;

    let server_name = hostname
        .to_owned()
        .try_into()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let tls_conn = rustls::ClientConnection::new(Arc::clone(&UPSTREAM_TLS_CONFIG), server_name)?;

    Ok((stream, tls_conn))
}

/// Returns true if the IP is in a private, loopback, or link-local range.
/// Used to block SSRF to cloud metadata endpoints and internal services.
#[allow(clippy::unnested_or_patterns)] // Nesting destroys per-range comments
pub const fn is_private_ip(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    matches!(
        octets,
        [10, ..]              // 10.0.0.0/8 (RFC 1918)
        | [172, 16..=31, ..]  // 172.16.0.0/12 (RFC 1918)
        | [192, 168, ..]      // 192.168.0.0/16 (RFC 1918)
        | [169, 254, ..]      // 169.254.0.0/16 (link-local, cloud metadata)
        | [127, ..]           // 127.0.0.0/8 (loopback)
        | [0, ..]             // 0.0.0.0/8 (this network)
        | [100, 64..=127, ..] // 100.64.0.0/10 (CGN, RFC 6598)
        | [192, 0, 0, ..]     // 192.0.0.0/24 (IETF protocol assignments)
        | [198, 18..=19, ..]  // 198.18.0.0/15 (benchmarking)
        | [224..=239, ..] // 224.0.0.0/4 (multicast)
    )
}

/// Extract SNI hostname from a TLS `ClientHello` message.
///
/// Hand-rolled parser used only by tests. Production code uses
/// `rustls::ServerConnection::server_name()` after the handshake.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record: type(1) + version(2) + length(2) + handshake
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    let hs = &data[5..];
    if hs.is_empty() || hs[0] != 0x01 {
        return None; // Not ClientHello
    }

    // Skip: handshake type(1) + length(3) + version(2) + random(32)
    if hs.len() < 38 {
        return None;
    }
    let mut pos = 38;

    // Session ID
    if pos >= hs.len() {
        return None;
    }
    let sess_len = hs[pos] as usize;
    pos += 1 + sess_len;

    // Cipher suites
    if pos + 2 > hs.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Compression methods
    if pos >= hs.len() {
        return None;
    }
    let comp_len = hs[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > hs.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;

    while pos + 4 <= ext_end && pos + 4 <= hs.len() {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            if ext_data_len >= 5 && pos + ext_data_len <= hs.len() {
                let name_len = u16::from_be_bytes([hs[pos + 3], hs[pos + 4]]) as usize;
                if pos + 5 + name_len <= hs.len() {
                    return String::from_utf8(hs[pos + 5..pos + 5 + name_len].to_vec()).ok();
                }
            }
        }

        pos += ext_data_len;
    }

    None
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::ip_constant
)]
mod tests {
    use super::*;

    #[test]
    fn extract_sni_from_real_client_hello() {
        // Minimal TLS 1.2 ClientHello with SNI "example.com"
        let mut hello = Vec::new();

        // TLS record header
        hello.push(0x16); // Handshake
        hello.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 (record layer)
        // Length placeholder (fill later)
        let len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);

        let hs_start = hello.len();

        // Handshake header
        hello.push(0x01); // ClientHello
        // Length placeholder (fill later)
        let hs_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        let ch_start = hello.len();

        // Client version
        hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        // Random (32 bytes)
        hello.extend_from_slice(&[0x00; 32]);
        // Session ID length
        hello.push(0x00);
        // Cipher suites: length(2) + one suite
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]);
        // Compression methods: length(1) + null
        hello.extend_from_slice(&[0x01, 0x00]);

        // Extensions
        let ext_start = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]); // extensions length (fill later)

        let ext_data_start = hello.len();

        // SNI extension (type 0x0000)
        hello.extend_from_slice(&[0x00, 0x00]); // extension type
        let hostname = b"example.com";
        let sni_data_len = 2 + 1 + 2 + hostname.len();
        hello.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
        // SNI list length
        hello.extend_from_slice(&((1 + 2 + hostname.len()) as u16).to_be_bytes());
        hello.push(0x00); // host_name type
        hello.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        hello.extend_from_slice(hostname);

        // Fill in lengths
        let ext_len = hello.len() - ext_data_start;
        hello[ext_start] = (ext_len >> 8) as u8;
        hello[ext_start + 1] = ext_len as u8;

        let hs_body_len = hello.len() - ch_start;
        hello[hs_len_pos] = (hs_body_len >> 16) as u8;
        hello[hs_len_pos + 1] = (hs_body_len >> 8) as u8;
        hello[hs_len_pos + 2] = hs_body_len as u8;

        let record_len = hello.len() - hs_start;
        hello[len_pos] = (record_len >> 8) as u8;
        hello[len_pos + 1] = record_len as u8;

        assert_eq!(extract_sni(&hello), Some("example.com".to_string()));
    }

    #[test]
    fn extract_sni_rejects_non_tls() {
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn private_ip_blocked() {
        use std::net::Ipv4Addr;
        // Cloud metadata
        assert!(is_private_ip(Ipv4Addr::new(169, 254, 169, 254)));
        // RFC1918
        assert!(is_private_ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(is_private_ip(Ipv4Addr::new(192, 168, 1, 1)));
        // Loopback
        assert!(is_private_ip(Ipv4Addr::new(127, 0, 0, 1)));
        // CGN
        assert!(is_private_ip(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(100, 127, 255, 255)));
        // Multicast
        assert!(is_private_ip(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(239, 255, 255, 255)));
    }

    #[test]
    fn public_ip_allowed() {
        use std::net::Ipv4Addr;
        assert!(!is_private_ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ip(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ip(Ipv4Addr::new(104, 18, 0, 1)));
        // Edge of RFC1918 ranges
        assert!(!is_private_ip(Ipv4Addr::new(172, 15, 255, 255)));
        assert!(!is_private_ip(Ipv4Addr::new(172, 32, 0, 0)));
        assert!(!is_private_ip(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_private_ip(Ipv4Addr::new(100, 128, 0, 0)));
    }
}
