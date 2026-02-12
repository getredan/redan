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
) -> Result<(TcpStream, rustls::ClientConnection), crate::error::Error> {
    use std::net::ToSocketAddrs;

    let addr = format!("{hostname}:{port}")
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "DNS resolution failed")
        })?;

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    stream.set_nonblocking(false)?;

    let server_name = hostname
        .to_owned()
        .try_into()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let tls_conn = rustls::ClientConnection::new(Arc::clone(&UPSTREAM_TLS_CONFIG), server_name)?;

    Ok((stream, tls_conn))
}

/// Extract SNI hostname from a TLS ClientHello message.
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
}
