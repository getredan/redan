/// TLS utilities: upstream TLS connection and SSRF address checks.
use std::net::TcpStream;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

/// Shared TLS client config with system root certificates.
/// Built once, reused for all upstream connections.
static UPSTREAM_TLS_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    crate::ensure_crypto_provider();
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
        | [192, 88, 99, ..]   // 192.88.99.0/24 (6to4 relay anycast, RFC 7526)
        | [198, 18..=19, ..]  // 198.18.0.0/15 (benchmarking)
        | [224..=239, ..] // 224.0.0.0/4 (multicast)
        | [240..=255, ..] // 240.0.0.0/4 (reserved; includes 255.255.255.255 broadcast)
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::ip_constant)]
mod tests {
    use super::*;

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
        // Reserved 240.0.0.0/4 (includes limited broadcast 255.255.255.255)
        assert!(is_private_ip(Ipv4Addr::new(240, 0, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(250, 1, 2, 3)));
        assert!(is_private_ip(Ipv4Addr::new(255, 255, 255, 255)));
        // 6to4 relay anycast (RFC 7526)
        assert!(is_private_ip(Ipv4Addr::new(192, 88, 99, 1)));
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
        // Just outside 6to4 192.88.99.0/24
        assert!(!is_private_ip(Ipv4Addr::new(192, 88, 98, 255)));
        assert!(!is_private_ip(Ipv4Addr::new(192, 88, 100, 0)));
        // 223.0.0.0/8 is public unicast, just below the multicast block
        assert!(!is_private_ip(Ipv4Addr::new(223, 255, 255, 255)));
    }
}
