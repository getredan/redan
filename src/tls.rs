/// TLS utilities: SNI extraction and upstream connection.
use std::io::{Read, Write};
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

/// Extract SNI hostname from a TLS ClientHello message.
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

/// Connect to an upstream server over TLS, returning the TCP stream and
/// rustls client connection.
pub fn connect_upstream(
    hostname: &str,
    port: u16,
) -> Result<(TcpStream, rustls::ClientConnection), Box<dyn std::error::Error>> {
    use std::net::ToSocketAddrs;

    let addr = format!("{hostname}:{port}")
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .ok_or("DNS resolution failed")?;

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    stream.set_nonblocking(false)?;

    let server_name = hostname.to_owned().try_into()?;
    let tls_conn = rustls::ClientConnection::new(Arc::clone(&UPSTREAM_TLS_CONFIG), server_name)?;

    Ok((stream, tls_conn))
}

/// Complete a TLS handshake, send request, read full response.
///
/// Handles both Content-Length and chunked Transfer-Encoding responses.
/// For chunked encoding (including SSE streams), reads until the terminal
/// chunk (`0\r\n\r\n`) or the peer closes the connection.
pub fn relay_upstream(
    stream: &mut TcpStream,
    tls: &mut rustls::ClientConnection,
    request: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    stream.set_nonblocking(false)?;
    // Per-read timeout. Large responses (multi-MB tarballs) may have
    // gaps between chunks from CDNs. 120s is generous but prevents
    // infinite hangs.
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;

    // Complete TLS handshake
    while tls.is_handshaking() {
        if tls.wants_write() {
            tls.write_tls(stream)?;
        }
        if tls.wants_read() {
            tls.read_tls(stream)?;
            tls.process_new_packets()?;
        }
    }

    // Send the HTTP request in chunks, flushing TLS records between
    // writes. Large requests (>64KB) overflow rustls internal buffers
    // if written all at once.
    for chunk in request.chunks(16384) {
        tls.writer().write_all(chunk)?;
        while tls.wants_write() {
            tls.write_tls(stream)?;
        }
        stream.flush()?;
    }

    // Read the full response
    let mut response = Vec::new();
    let mut buf = vec![0u8; 16384];
    loop {
        match tls.read_tls(stream) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e.into()),
        }

        let state = tls.process_new_packets()?;

        loop {
            match tls.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        if state.peer_has_closed() {
            // Drain remaining plaintext
            loop {
                match tls.reader().read(&mut buf) {
                    Ok(n) if n > 0 => response.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            }
            break;
        }

        if response_complete(&response) {
            break;
        }
    }

    Ok(response)
}

/// Check if a buffer contains a complete HTTP response.
///
/// Supports Content-Length and chunked Transfer-Encoding. For chunked
/// responses, looks for the terminal chunk marker `0\r\n\r\n`.
fn response_complete(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    let Some(header_end) = text.find("\r\n\r\n") else {
        return false;
    };
    let headers = &text[..header_end].to_lowercase();
    let body_start = header_end + 4;

    // Content-Length: exact byte count
    if let Some(cl_line) = headers.lines().find(|l| l.starts_with("content-length:"))
        && let Ok(cl) = cl_line
            .split(':')
            .nth(1)
            .unwrap_or("0")
            .trim()
            .parse::<usize>()
    {
        return data.len() - body_start >= cl;
    }

    // Chunked Transfer-Encoding: terminal chunk is "0\r\n\r\n"
    if headers.contains("transfer-encoding: chunked") {
        return data[body_start..].ends_with(b"0\r\n\r\n");
    }

    false
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

    #[test]
    fn response_complete_with_content_length() {
        let body = "x".repeat(80);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert!(response_complete(resp.as_bytes()));
    }

    #[test]
    fn response_incomplete_body() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\nhello";
        assert!(!response_complete(resp));
    }

    #[test]
    fn response_complete_chunked() {
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                      5\r\nhello\r\n0\r\n\r\n";
        assert!(response_complete(resp));
    }

    #[test]
    fn response_incomplete_chunked() {
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                      5\r\nhello\r\n";
        assert!(!response_complete(resp));
    }

    #[test]
    fn response_complete_no_headers_yet() {
        assert!(!response_complete(b"HTTP/1.1 200 OK\r\n"));
    }
}
