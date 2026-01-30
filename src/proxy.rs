/// MITM proxy: smoltcp event loop with DNS, HTTP, and TLS interception.
///
/// Listens on the gateway side of a virtio-net link. Handles:
/// - UDP port 53: synthetic DNS (all names -> gateway IP)
/// - TCP port 80: HTTP interception
/// - TCP port 443: TLS MITM (SNI extraction, ephemeral cert, upstream relay)
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Address};

use crate::ca::MitmCa;
use crate::dns;
use crate::net::VirtioNetDevice;
use crate::secret::SecretBinding;
use crate::tls;

pub const GATEWAY_IP: Ipv4Address = Ipv4Address::new(192, 168, 127, 1);
pub const GATEWAY_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
pub const GUEST_IP: &str = "192.168.127.2";

/// Run the MITM proxy until the timeout expires.
pub fn run(host_sock: UnixStream, ca: &MitmCa, secrets: &[SecretBinding], timeout: Duration) {
    let mut device = VirtioNetDevice::new(host_sock);

    let config = Config::new(GATEWAY_MAC.into());
    let mut iface = Interface::new(config, &mut device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(GATEWAY_IP.into(), 24)).unwrap();
    });

    let mut sockets = SocketSet::new(vec![]);
    let mut connections: HashMap<u16, ProxyConn> = HashMap::new();

    // DNS
    let dns_handle = add_udp_listener(&mut sockets, 53);
    // HTTP + HTTPS
    let http_handle = add_tcp_listener(&mut sockets, 80);
    let https_handle = add_tcp_listener(&mut sockets, 443);

    log::info!("proxy listening on :53 (dns), :80, :443");

    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            log::info!("proxy timeout");
            break;
        }

        let timestamp = SmolInstant::now();
        let result = iface.poll(timestamp, &mut device, &mut sockets);
        device.flush_tx();

        if matches!(result, PollResult::SocketStateChanged) {
            process_dns(&mut sockets, dns_handle);
            check_accept(&mut sockets, http_handle, 80, false, &mut connections);
            check_accept(&mut sockets, https_handle, 443, true, &mut connections);

            let mut done_ports: Vec<u16> = Vec::new();
            for (&port, conn) in connections.iter_mut() {
                process_connection(&mut sockets, conn, ca, secrets);
                if conn.state == ConnState::Done {
                    done_ports.push(port);
                }
            }

            for port in done_ports {
                let conn = connections.remove(&port).unwrap();
                // Re-listen: smoltcp TCP sockets can't accept new connections
                // after the previous one closes. We must abort + re-listen.
                let sock = sockets.get_mut::<tcp::Socket>(conn.handle);
                sock.abort();
                sock.listen(port).unwrap();
            }
        }

        std::thread::sleep(Duration::from_millis(1));
    }
}

// --- DNS ---

fn add_udp_listener(sockets: &mut SocketSet, port: u16) -> SocketHandle {
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]);
    let mut sock = udp::Socket::new(rx, tx);
    sock.bind(port).unwrap();
    sockets.add(sock)
}

fn process_dns(sockets: &mut SocketSet, handle: SocketHandle) {
    let sock = sockets.get_mut::<udp::Socket>(handle);
    while sock.can_recv() {
        if let Ok((data, sender)) = sock.recv()
            && let Some((hostname, response)) = dns::handle_query(data, GATEWAY_IP)
        {
            log::info!("DNS: {hostname} -> {GATEWAY_IP}");
            sock.send_slice(&response, sender).ok();
        }
    }
}

// --- TCP ---

fn add_tcp_listener(sockets: &mut SocketSet, port: u16) -> SocketHandle {
    let rx_buf = tcp::SocketBuffer::new(vec![0; 65535]);
    let tx_buf = tcp::SocketBuffer::new(vec![0; 65535]);
    let mut sock = tcp::Socket::new(rx_buf, tx_buf);
    sock.listen(port).unwrap();
    sockets.add(sock)
}

fn check_accept(
    sockets: &mut SocketSet,
    listen_handle: SocketHandle,
    port: u16,
    is_tls: bool,
    connections: &mut HashMap<u16, ProxyConn>,
) {
    let sock = sockets.get_mut::<tcp::Socket>(listen_handle);
    if sock.may_recv() && !connections.contains_key(&port) {
        log::info!("connection on :{port} from {:?}", sock.remote_endpoint());
        connections.insert(
            port,
            ProxyConn {
                handle: listen_handle,
                upstream: None,
                upstream_tls: None,
                guest_tls: None,
                sni: None,
                is_tls,
                pending_guest_data: Vec::new(),
                state: ConnState::WaitingForData,
            },
        );
    }
}

// --- Connection state machine ---

struct ProxyConn {
    handle: SocketHandle,
    upstream: Option<TcpStream>,
    upstream_tls: Option<rustls::ClientConnection>,
    guest_tls: Option<rustls::ServerConnection>,
    sni: Option<String>,
    is_tls: bool,
    pending_guest_data: Vec<u8>,
    state: ConnState,
}

#[derive(Debug, PartialEq)]
enum ConnState {
    WaitingForData,
    TlsHandshake,
    Proxying,
    /// sock.close() called, waiting for TCP FIN exchange to complete.
    Closing,
    Done,
}

fn process_connection(
    sockets: &mut SocketSet,
    conn: &mut ProxyConn,
    ca: &MitmCa,
    secrets: &[SecretBinding],
) {
    let sock = sockets.get_mut::<tcp::Socket>(conn.handle);

    match conn.state {
        ConnState::WaitingForData => {
            if !sock.may_recv() {
                return;
            }
            let mut buf = vec![0u8; 4096];
            let n = match sock.recv_slice(&mut buf) {
                Ok(n) => n,
                Err(_) => return,
            };
            if n == 0 {
                return;
            }
            conn.pending_guest_data.extend_from_slice(&buf[..n]);

            if conn.is_tls {
                handle_tls_start(sock, conn, ca);
            } else {
                handle_http(sock, conn, secrets);
            }
        }

        ConnState::TlsHandshake | ConnState::Proxying => {
            handle_tls_data(sock, conn, secrets);
        }

        ConnState::Closing => {
            // Wait for TCP close sequence to complete
            if !sock.is_active() {
                conn.state = ConnState::Done;
            }
        }

        ConnState::Done => {}
    }
}

fn handle_http(sock: &mut tcp::Socket<'_>, conn: &mut ProxyConn, _secrets: &[SecretBinding]) {
    let request = String::from_utf8_lossy(&conn.pending_guest_data);
    log::info!("HTTP request: {}", request.lines().next().unwrap_or(""));

    // TODO: forward to upstream with secret injection when HTTP proxying is implemented.
    // For now, respond with a static marker. No secret injection on plaintext HTTP.
    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nREDAN_HTTP_INTERCEPT_OK\n";
    sock.send_slice(response.as_bytes()).ok();
    sock.close();
    conn.pending_guest_data.clear();
    conn.state = ConnState::Done;
}

fn handle_tls_start(sock: &mut tcp::Socket<'_>, conn: &mut ProxyConn, ca: &MitmCa) {
    let Some(sni) = tls::extract_sni(&conn.pending_guest_data) else {
        return;
    };

    log::info!("TLS SNI: {sni}");
    conn.sni = Some(sni.clone());

    // Guest-facing TLS (we are the server)
    let server_config = ca.server_config_for(&sni);
    let server_conn = rustls::ServerConnection::new(server_config).expect("server TLS failed");
    conn.guest_tls = Some(server_conn);

    // Upstream TLS
    match tls::connect_upstream(&sni, 443) {
        Ok((stream, tls_conn)) => {
            conn.upstream = Some(stream);
            conn.upstream_tls = Some(tls_conn);
            conn.state = ConnState::TlsHandshake;
        }
        Err(e) => {
            log::warn!("upstream connect failed: {e}");
            sock.close();
            conn.state = ConnState::Done;
            return;
        }
    }

    // Feed ClientHello to our server TLS
    let guest_tls = conn.guest_tls.as_mut().unwrap();
    let mut cursor = &conn.pending_guest_data[..];
    if let Err(e) = guest_tls.read_tls(&mut cursor) {
        log::warn!("ClientHello read_tls failed: {e}");
    }
    conn.pending_guest_data.clear();

    if let Err(e) = guest_tls.process_new_packets() {
        log::warn!("guest TLS process error: {e}");
    }

    // Write ServerHello back to guest
    let mut out = Vec::new();
    if let Ok(n) = guest_tls.write_tls(&mut out)
        && n > 0
        && let Err(e) = sock.send_slice(&out)
    {
        log::warn!("ServerHello send failed: {e}");
    }
}

/// Rewrite `Connection: keep-alive` to `Connection: close` in HTTP
/// response headers (case-insensitive). We close the smoltcp socket
/// after each response, so the client must not attempt to reuse.
fn rewrite_connection_close(data: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(data);
    let Some(header_end) = text.find("\r\n\r\n") else {
        return data.to_vec();
    };
    let headers_str = String::from_utf8_lossy(&data[..header_end]);
    let body = &data[header_end..];

    // Case-insensitive replacement
    let mut rewritten = String::with_capacity(headers_str.len());
    for line in headers_str.split("\r\n") {
        if line.to_lowercase().starts_with("connection:") {
            rewritten.push_str("Connection: close");
        } else {
            rewritten.push_str(line);
        }
        rewritten.push_str("\r\n");
    }
    // Remove trailing \r\n (we'll get it from body which starts with \r\n\r\n)
    if rewritten.ends_with("\r\n") {
        rewritten.truncate(rewritten.len() - 2);
    }

    let mut result = rewritten.into_bytes();
    result.extend_from_slice(body);
    result
}

/// Check if accumulated data contains a complete HTTP request.
/// Looks for headers ending with \r\n\r\n, then checks Content-Length
/// to determine if the full body has arrived. Requests with no
/// Content-Length (e.g. GET) are complete once headers end.
fn http_request_complete(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    let Some(header_end) = text.find("\r\n\r\n") else {
        return false;
    };
    let headers = &text[..header_end].to_lowercase();

    if let Some(cl_line) = headers.lines().find(|l| l.starts_with("content-length:"))
        && let Ok(cl) = cl_line
            .split(':')
            .nth(1)
            .unwrap_or("0")
            .trim()
            .parse::<usize>()
    {
        let body_start = header_end + 4;
        return data.len() - body_start >= cl;
    }

    // No Content-Length: request is complete once headers are done
    true
}

fn handle_tls_data(sock: &mut tcp::Socket<'_>, conn: &mut ProxyConn, secrets: &[SecretBinding]) {
    let guest_tls = match conn.guest_tls.as_mut() {
        Some(t) => t,
        None => {
            conn.state = ConnState::Done;
            return;
        }
    };

    // Read encrypted data from guest
    let mut buf = vec![0u8; 65535];
    let guest_bytes = sock.recv_slice(&mut buf).unwrap_or(0);
    if guest_bytes > 0 {
        let mut cursor = &buf[..guest_bytes];
        guest_tls.read_tls(&mut cursor).ok();
        match guest_tls.process_new_packets() {
            Ok(_) => {}
            Err(e) => {
                log::warn!("guest TLS error: {e}");
                sock.close();
                conn.state = ConnState::Done;
                return;
            }
        }
    }

    // Read all available decrypted plaintext into pending buffer
    let mut plaintext = vec![0u8; 65535];
    loop {
        match guest_tls.reader().read(&mut plaintext) {
            Ok(0) => break,
            Ok(n) => conn.pending_guest_data.extend_from_slice(&plaintext[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }

    if !conn.pending_guest_data.is_empty() && conn.state == ConnState::TlsHandshake {
        conn.state = ConnState::Proxying;
    }

    // Wait until we have the full HTTP request before forwarding
    if conn.state != ConnState::Proxying || !http_request_complete(&conn.pending_guest_data) {
        // Flush pending TLS data to guest (handshake messages etc.)
        let mut out = Vec::new();
        if let Ok(n) = guest_tls.write_tls(&mut out)
            && n > 0
        {
            sock.send_slice(&out).ok();
        }
        if !sock.is_active() {
            conn.state = ConnState::Done;
        }
        return;
    }

    let request = std::mem::take(&mut conn.pending_guest_data);
    let text = String::from_utf8_lossy(&request);
    log::info!(
        "DECRYPTED from guest ({} bytes): {}",
        request.len(),
        text.lines().next().unwrap_or("")
    );

    let hostname = conn.sni.as_deref().unwrap_or("");
    let (request_data, inject_count) = crate::secret::inject(&request, hostname, secrets);
    if inject_count > 0 {
        log::info!("SECRET INJECTED: {inject_count} replacement(s) for {hostname}");
    }

    // Forward to upstream
    if let (Some(stream), Some(tls_conn)) = (conn.upstream.as_mut(), conn.upstream_tls.as_mut()) {
        match tls::relay_upstream(stream, tls_conn, &request_data) {
            Ok(response) => {
                let (scrubbed, scrub_count) = crate::secret::scrub(&response, secrets);
                if scrub_count > 0 {
                    log::info!("RESPONSE SCRUBBED: {scrub_count} value(s) removed");
                }

                log::info!(
                    "upstream response ({} bytes): {}",
                    scrubbed.len(),
                    String::from_utf8_lossy(&scrubbed)
                        .lines()
                        .next()
                        .unwrap_or("")
                );

                // Rewrite Connection header: we close after each
                // request, so tell the client not to reuse.
                let scrubbed = rewrite_connection_close(&scrubbed);

                // Write response back through guest TLS
                if let Err(e) = guest_tls.writer().write_all(&scrubbed) {
                    log::warn!("guest TLS write failed: {e}");
                }
                let mut guest_out = Vec::new();
                if let Err(e) = guest_tls.write_tls(&mut guest_out) {
                    log::warn!("guest TLS encrypt failed: {e}");
                }

                for chunk in guest_out.chunks(65535) {
                    if let Err(e) = sock.send_slice(chunk) {
                        log::warn!("smoltcp send failed: {e}");
                        break;
                    }
                }

                // Send TLS close_notify so the client knows we're done
                guest_tls.send_close_notify();
                let mut close_out = Vec::new();
                if let Err(e) = guest_tls.write_tls(&mut close_out) {
                    log::warn!("close_notify encrypt failed: {e}");
                }
                if let Err(e) = sock.send_slice(&close_out) {
                    log::warn!("close_notify send failed: {e}");
                }
            }
            Err(e) => {
                log::warn!("upstream relay error: {e}");
            }
        }
    }

    // Initiate graceful TCP close. Transitions to Closing state
    // to let smoltcp finish the FIN exchange before we re-listen.
    sock.close();
    conn.state = ConnState::Closing;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request_complete_get() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(http_request_complete(req));
    }

    #[test]
    fn http_request_complete_post_with_body() {
        let req = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        assert!(http_request_complete(req));
    }

    #[test]
    fn http_request_incomplete_post() {
        let req = b"POST /api HTTP/1.1\r\nContent-Length: 100\r\n\r\nhello";
        assert!(!http_request_complete(req));
    }

    #[test]
    fn http_request_incomplete_no_headers_end() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com";
        assert!(!http_request_complete(req));
    }

    #[test]
    fn rewrite_connection_close_case_insensitive() {
        let resp = b"HTTP/1.1 200 OK\r\nconnection: keep-alive\r\n\r\nbody";
        let result = rewrite_connection_close(resp);
        let text = String::from_utf8_lossy(&result);
        assert!(text.contains("Connection: close"));
        assert!(!text.to_lowercase().contains("keep-alive"));
        assert!(text.ends_with("body"));
    }

    #[test]
    fn rewrite_connection_close_no_header() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
        let result = rewrite_connection_close(resp);
        assert_eq!(result, resp);
    }
}
