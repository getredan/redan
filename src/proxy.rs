/// MITM proxy: smoltcp event loop with DNS, HTTP, and TLS interception.
///
/// Listens on the gateway side of a virtio-net link. Handles:
/// - UDP port 53: synthetic DNS (all names -> gateway IP)
/// - TCP port 80: HTTP interception
/// - TCP port 443: TLS MITM (SNI extraction, ephemeral cert, upstream relay)
///
/// ## Network model
///
/// The guest can reach arbitrary internet hosts through the proxy. The
/// proxy does NOT restrict which hosts the guest connects to. It only
/// controls whether secrets are injected (host allowlist). This is by
/// design: agents need internet access to do useful work.
///
/// ## DNS rebinding risk
///
/// `connect_upstream()` in tls.rs performs real DNS resolution on the
/// host side. If an attacker controls an allowed host's DNS records,
/// they could DNS-rebind to internal IPs. Mitigated by: the allowlist
/// is user-controlled, so users should only allow trusted hosts.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
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

/// Per-socket buffer size for smoltcp TCP sockets. 256 KB is enough
/// for TLS record reassembly and HTTP header buffering without
/// excessive memory per connection.
const TCP_SOCKET_BUF: usize = 256 * 1024;

/// Maximum Content-Length we accept in a guest HTTP request.
/// Requests larger than this are treated as incomplete (never proxied).
/// 16 MB is generous for API requests; file uploads go through the
/// upstream connection directly after headers are proxied.
const MAX_REQUEST_BODY: usize = 16 * 1024 * 1024;

/// Remove completed connections from the map and release their sockets.
fn reap_done(connections: &mut HashMap<SocketHandle, ProxyConn>, sockets: &mut SocketSet) {
    connections.retain(|handle, conn| {
        if conn.state == ConnState::Done {
            sockets.remove(*handle);
            false
        } else {
            true
        }
    });
}

/// Run the MITM proxy until the timeout expires.
pub fn run(host_sock: UnixStream, ca: &mut MitmCa, secrets: &[SecretBinding], timeout: Duration) {
    let mut device = VirtioNetDevice::new(host_sock);

    let config = Config::new(GATEWAY_MAC.into());
    let mut iface = Interface::new(config, &mut device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(GATEWAY_IP.into(), 24)).unwrap();
    });

    let mut sockets = SocketSet::new(vec![]);
    let mut connections: HashMap<SocketHandle, ProxyConn> = HashMap::new();

    // DNS
    let dns_handle = add_udp_listener(&mut sockets, 53);

    // Listener sockets: each port has a dedicated socket that stays in
    // LISTEN state. When a connection arrives, the listener transitions
    // to ESTABLISHED; we move it to `connections` and create a fresh
    // listener for the next connection.
    // Port 80 gets a small backlog -- we reject plaintext HTTP but
    // some tools probe it. Port 443 needs the full backlog for npm's
    // 30+ concurrent TLS connections.
    let mut backlogs: Vec<ListenBacklog> = vec![
        ListenBacklog {
            port: 80,
            is_tls: false,
            handles: (0..4).map(|_| add_tcp_listener(&mut sockets, 80)).collect(),
        },
        ListenBacklog {
            port: 443,
            is_tls: true,
            handles: (0..LISTEN_BACKLOG)
                .map(|_| add_tcp_listener(&mut sockets, 443))
                .collect(),
        },
    ];

    log::info!("proxy listening on :53 (dns), :80, :443");

    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            log::info!("proxy timeout ({timeout:?})");
            break;
        }
        if device.peer_closed && connections.is_empty() {
            log::info!("guest exited (socket closed)");
            break;
        }
        let mut has_pending = false;

        let timestamp = SmolInstant::now();
        let result = iface.poll(timestamp, &mut device, &mut sockets);
        device.flush_tx();

        if matches!(result, PollResult::SocketStateChanged) {
            process_dns(&mut sockets, dns_handle);

            // Promote established backlog sockets to active connections.
            // Replace each promoted socket to maintain the backlog depth.
            for backlog in &mut backlogs {
                let mut i = 0;
                while i < backlog.handles.len() {
                    let handle = backlog.handles[i];
                    let sock = sockets.get_mut::<tcp::Socket>(handle);
                    if sock.may_recv() && sock.state() != tcp::State::Listen {
                        log::info!(
                            "connection on :{} from {:?}",
                            backlog.port,
                            sock.remote_endpoint()
                        );
                        connections.insert(handle, ProxyConn::new(handle, backlog.is_tls));
                        // Replace with a fresh listener
                        backlog.handles[i] = add_tcp_listener(&mut sockets, backlog.port);
                    }
                    i += 1;
                }
            }

            for conn in connections.values_mut() {
                process_connection(&mut sockets, conn, ca, secrets);
            }
            reap_done(&mut connections, &mut sockets);
        }

        // Process connections that need attention regardless of socket
        // state changes: response drains need poll() to advance the TCP
        // window, and upstream waits need channel checks.
        for conn in connections.values_mut() {
            if conn.state == ConnState::SendingResponse
                || conn.state == ConnState::WaitingForUpstream
            {
                process_connection(&mut sockets, conn, ca, secrets);
                has_pending = true;
            }
        }
        reap_done(&mut connections, &mut sockets);

        if has_pending {
            // Yield briefly to avoid burning CPU, but stay responsive.
            // Pure busy-loop wastes 100% CPU; 100us is enough for the
            // TCP window to advance without noticeable throughput loss.
            std::thread::sleep(Duration::from_micros(100));
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// TCP listen backlog for a port. Multiple sockets in LISTEN state so
/// bursts of concurrent SYNs (e.g. npm downloading 30 tarballs) don't
/// get RST'd while a single listener is being promoted.
struct ListenBacklog {
    port: u16,
    is_tls: bool,
    handles: Vec<SocketHandle>,
}

const LISTEN_BACKLOG: usize = 32;

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
    // 256KB buffers: smoltcp doesn't support buffer resizing after
    // socket creation, so we allocate generously upfront. Total:
    // 256KB * 2 * 36 sockets = ~18MB. Acceptable for a CLI tool;
    // the TCP window size drives throughput during large downloads.
    let rx_buf = tcp::SocketBuffer::new(vec![0; TCP_SOCKET_BUF]);
    let tx_buf = tcp::SocketBuffer::new(vec![0; TCP_SOCKET_BUF]);
    let mut sock = tcp::Socket::new(rx_buf, tx_buf);
    sock.listen(port).unwrap();
    sockets.add(sock)
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
    /// Buffered data waiting to be sent to the guest.
    /// Drained incrementally as smoltcp's TCP window allows.
    pending_response: Vec<u8>,
    /// How many bytes of pending_response have been sent.
    response_offset: usize,
    /// Channel for receiving streamed upstream messages.
    upstream_rx: Option<mpsc::Receiver<tls::UpstreamMsg>>,
    /// Overlap buffer for scrubbing secrets that span chunk boundaries.
    scrub_overlap: Vec<u8>,
    /// Longest secret real_value, determines overlap buffer size.
    max_secret_len: usize,
    /// Whether HTTP response headers have been processed.
    headers_done: bool,
    /// Whether the upstream relay has finished (Done received).
    upstream_done: bool,
    state: ConnState,
}

impl ProxyConn {
    fn new(handle: SocketHandle, is_tls: bool) -> Self {
        Self {
            handle,
            upstream: None,
            upstream_tls: None,
            guest_tls: None,
            sni: None,
            is_tls,
            pending_guest_data: Vec::new(),
            pending_response: Vec::new(),
            response_offset: 0,
            upstream_rx: None,
            scrub_overlap: Vec::new(),
            max_secret_len: 0,
            headers_done: false,
            upstream_done: false,
            state: ConnState::WaitingForData,
        }
    }
}

#[derive(Debug, PartialEq)]
enum ConnState {
    WaitingForData,
    TlsHandshake,
    Proxying,
    /// Upstream relay running in background thread.
    WaitingForUpstream,
    /// Response buffered, draining to guest through smoltcp.
    SendingResponse,
    /// sock.close() called, waiting for TCP FIN exchange to complete.
    Closing,
    Done,
}

fn process_connection(
    sockets: &mut SocketSet,
    conn: &mut ProxyConn,
    ca: &mut MitmCa,
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

        ConnState::WaitingForUpstream => {
            handle_upstream_messages(sock, conn, secrets);
        }

        ConnState::SendingResponse => {
            drain_response(sock, conn);
            // If drain finished all pending data but upstream isn't done,
            // go back to waiting for more chunks.
            if conn.state == ConnState::SendingResponse
                && conn.response_offset >= conn.pending_response.len()
                && !conn.upstream_done
            {
                // Reset buffer for next batch of chunks
                conn.pending_response.clear();
                conn.response_offset = 0;
                conn.state = ConnState::WaitingForUpstream;
            }
        }

        ConnState::Closing => {
            // Wait for TCP close sequence to complete
            if !sock.is_active() {
                // Zeroize overlap buffer -- may contain secret bytes from
                // response scrubbing that haven't been flushed yet.
                zeroize::Zeroize::zeroize(&mut conn.scrub_overlap);
                conn.state = ConnState::Done;
            }
        }

        ConnState::Done => {}
    }
}

fn handle_http(sock: &mut tcp::Socket<'_>, conn: &mut ProxyConn, _secrets: &[SecretBinding]) {
    let request = String::from_utf8_lossy(&conn.pending_guest_data);
    log::info!(
        "HTTP request (plaintext): {}",
        request.lines().next().unwrap_or("")
    );

    // Plaintext HTTP is not proxied. Secret injection requires TLS MITM
    // so the proxy can inspect and modify headers. Respond with 421 to
    // tell the client to use HTTPS instead.
    let response = "HTTP/1.1 421 Misdirected Request\r\n\
                     Content-Type: text/plain\r\n\
                     Connection: close\r\n\r\n\
                     redan: use HTTPS. Plaintext HTTP is not proxied.\n";
    sock.send_slice(response.as_bytes()).ok();
    sock.close();
    conn.pending_guest_data.clear();
    conn.state = ConnState::Closing;
}

fn handle_tls_start(sock: &mut tcp::Socket<'_>, conn: &mut ProxyConn, ca: &mut MitmCa) {
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
///
/// Uses httparse for header parsing but rebuilds on raw bytes to
/// avoid corrupting binary response bodies.
fn rewrite_connection_close(data: &[u8]) -> Vec<u8> {
    let mut parsed_headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut parsed_headers);
    let body_offset = match resp.parse(data) {
        Ok(httparse::Status::Complete(n)) => n,
        _ => return data.to_vec(),
    };

    // Rebuild: status line + headers with Connection replaced + body
    let mut result = Vec::with_capacity(data.len());

    let version = resp.version.unwrap_or(1);
    let code = resp.code.unwrap_or(200);
    let reason = resp.reason.unwrap_or("OK");
    result.extend_from_slice(format!("HTTP/1.{version} {code} {reason}\r\n").as_bytes());

    let mut has_connection = false;
    for header in resp.headers.iter() {
        if header.name.eq_ignore_ascii_case("connection") {
            result.extend_from_slice(b"Connection: close\r\n");
            has_connection = true;
        } else {
            result.extend_from_slice(header.name.as_bytes());
            result.extend_from_slice(b": ");
            result.extend_from_slice(header.value);
            result.extend_from_slice(b"\r\n");
        }
    }
    if !has_connection {
        result.extend_from_slice(b"Connection: close\r\n");
    }
    result.extend_from_slice(b"\r\n");
    result.extend_from_slice(&data[body_offset..]);
    result
}

/// Check if an HTTP request contains an Upgrade header (case-insensitive).
/// Used to reject WebSocket and other protocol upgrades.
fn request_has_upgrade(data: &[u8]) -> bool {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(data).is_err() {
        return false;
    }
    req.headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("upgrade"))
}

/// Check if accumulated data contains a complete HTTP request.
/// Uses httparse for header parsing, then checks Content-Length
/// to determine if the full body has arrived. Requests with no
/// Content-Length (e.g. GET) are complete once headers end.
fn http_request_complete(data: &[u8]) -> bool {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let body_offset = match req.parse(data) {
        Ok(httparse::Status::Complete(n)) => n,
        _ => return false,
    };

    // Check Content-Length to see if full body has arrived
    for header in req.headers.iter() {
        if header.name.eq_ignore_ascii_case("content-length")
            && let Ok(cl) = std::str::from_utf8(header.value)
                .unwrap_or("0")
                .trim()
                .parse::<usize>()
        {
            if cl > MAX_REQUEST_BODY {
                return false; // reject absurd Content-Length
            }
            return data.len() - body_offset >= cl;
        }
    }

    // No Content-Length: complete once headers are done
    true
}

fn handle_tls_data(sock: &mut tcp::Socket<'_>, conn: &mut ProxyConn, secrets: &[SecretBinding]) {
    let Some(guest_tls) = conn.guest_tls.as_mut() else {
        conn.state = ConnState::Done;
        return;
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

    // Reject WebSocket upgrades. After 101 Switching Protocols, the
    // connection carries binary frames that bypass HTTP scrubbing.
    // RFC 6455, CWE-444.
    if request_has_upgrade(&request) {
        log::warn!("rejected WebSocket/Upgrade request");
        let resp = b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n";
        if let Err(e) = guest_tls.writer().write_all(resp) {
            log::warn!("upgrade rejection write failed: {e}");
        }
        let mut out = Vec::new();
        if let Err(e) = guest_tls.write_tls(&mut out) {
            log::warn!("upgrade rejection encrypt failed: {e}");
        }
        for chunk in out.chunks(65535) {
            if let Err(e) = sock.send_slice(chunk) {
                log::warn!("upgrade rejection send failed: {e}");
                break;
            }
        }
        sock.close();
        conn.state = ConnState::Closing;
        return;
    }

    let hostname = conn.sni.as_deref().unwrap_or("");
    // Rewrite headers: strip Accept-Encoding (uncompressed for scrubbing),
    // force Connection: close (upstream closes after response, preventing
    // keep-alive stalls on responses with no Content-Length).
    let request = crate::secret::rewrite_request_headers(&request);
    let (request_data, inject_count) = crate::secret::inject(&request, hostname, secrets);
    if inject_count > 0 {
        log::info!("SECRET INJECTED: {inject_count} replacement(s) for {hostname}");
    }

    // Forward to upstream in a background thread so the smoltcp event
    // loop keeps running (other connections, DNS, etc.). Response
    // streams back via channel: Headers, Body chunks, Done.
    //
    // Thread lifecycle: runs until upstream completes or times out
    // (120s read timeout). Orphaned on process exit (acceptable for CLI).
    if let (Some(stream), Some(tls_conn)) = (conn.upstream.take(), conn.upstream_tls.take()) {
        let (tx, rx) = mpsc::channel();

        conn.max_secret_len = secrets
            .iter()
            .map(|s| s.real_value.len())
            .max()
            .unwrap_or(0);

        let sni = conn.sni.clone().unwrap_or_default();
        std::thread::spawn(move || {
            log::info!("upstream thread started for {sni}");
            let mut stream = stream;
            let mut tls_conn = tls_conn;
            if let Err(e) =
                tls::relay_upstream_streaming(&mut stream, &mut tls_conn, &request_data, &tx)
            {
                log::warn!("upstream thread error for {sni}: {e}");
                let _ = tx.send(tls::UpstreamMsg::Error(e.to_string()));
            }
        });

        conn.upstream_rx = Some(rx);
        conn.state = ConnState::WaitingForUpstream;
    } else {
        sock.close();
        conn.state = ConnState::Closing;
    }
}

/// Process streamed messages from the upstream relay thread.
///
/// Handles headers (rewrite Connection, start draining), body chunks
/// (scrub with overlap, append to pending_response), and completion.
fn handle_upstream_messages(
    sock: &mut tcp::Socket<'_>,
    conn: &mut ProxyConn,
    secrets: &[SecretBinding],
) {
    let Some(rx) = &conn.upstream_rx else { return };

    // Drain all available messages from the channel
    loop {
        match rx.try_recv() {
            Ok(tls::UpstreamMsg::Headers(headers)) => {
                log::info!(
                    "upstream headers ({} bytes): {}",
                    headers.len(),
                    String::from_utf8_lossy(&headers)
                        .lines()
                        .next()
                        .unwrap_or("")
                );
                // Scrub headers and rewrite Connection: close
                let (scrubbed, scrub_count) = crate::secret::scrub(&headers, secrets);
                if scrub_count > 0 {
                    log::info!("HEADERS SCRUBBED: {scrub_count} value(s)");
                }
                let rewritten = rewrite_connection_close(&scrubbed);
                conn.pending_response.extend_from_slice(&rewritten);
                conn.headers_done = true;
            }
            Ok(tls::UpstreamMsg::Body(chunk)) => {
                if conn.max_secret_len == 0 || secrets.is_empty() {
                    // No secrets to scrub, pass through directly
                    conn.pending_response.extend_from_slice(&chunk);
                } else {
                    // Scrub with overlap: prepend leftover from previous
                    // chunk to catch secrets that span boundaries.
                    let mut window = std::mem::take(&mut conn.scrub_overlap);
                    window.extend_from_slice(&chunk);

                    let (scrubbed, scrub_count) = crate::secret::scrub(&window, secrets);
                    if scrub_count > 0 {
                        log::info!("BODY SCRUBBED: {scrub_count} value(s)");
                    }

                    // Keep the last max_secret_len-1 bytes as overlap
                    let overlap_size = conn.max_secret_len.saturating_sub(1);
                    if scrubbed.len() > overlap_size {
                        let safe_end = scrubbed.len() - overlap_size;
                        conn.pending_response
                            .extend_from_slice(&scrubbed[..safe_end]);
                        conn.scrub_overlap = scrubbed[safe_end..].to_vec();
                    } else {
                        // Chunk smaller than overlap -- hold it all
                        conn.scrub_overlap = scrubbed;
                    }
                }
            }
            // Done (clean) or Disconnected (thread crashed) -- same
            // cleanup. Flush overlap, mark upstream finished, start
            // draining if we have data.
            Ok(tls::UpstreamMsg::Done) | Err(mpsc::TryRecvError::Disconnected) => {
                if !conn.scrub_overlap.is_empty() {
                    let overlap = std::mem::take(&mut conn.scrub_overlap);
                    conn.pending_response.extend_from_slice(&overlap);
                }
                conn.upstream_done = true;
                conn.upstream_rx = None;
                if conn.pending_response.is_empty() {
                    sock.close();
                    conn.state = ConnState::Closing;
                } else {
                    conn.state = ConnState::SendingResponse;
                }
                break;
            }
            Ok(tls::UpstreamMsg::Error(e)) => {
                log::warn!("upstream relay error: {e}");
                conn.upstream_rx = None;
                sock.close();
                conn.state = ConnState::Closing;
                return;
            }
            Err(mpsc::TryRecvError::Empty) => break,
        }
    }

    // If we have buffered data and headers are done, start draining
    // even before upstream is fully complete (streaming!)
    if conn.headers_done
        && !conn.pending_response.is_empty()
        && conn.state == ConnState::WaitingForUpstream
    {
        conn.state = ConnState::SendingResponse;
    }

    if conn.state == ConnState::SendingResponse {
        drain_response(sock, conn);
    }
}

/// Drain buffered response data to the guest through TLS + smoltcp.
///
/// Called repeatedly from the main poll loop. Each call writes as much
/// as the smoltcp TCP send buffer will accept, then returns. The next
/// iface.poll() transmits that data, advancing the TCP window for the
/// next drain_response() call.
fn drain_response(sock: &mut tcp::Socket<'_>, conn: &mut ProxyConn) {
    let Some(guest_tls) = conn.guest_tls.as_mut() else {
        conn.state = ConnState::Done;
        return;
    };

    // Write as many 16KB chunks as the TCP send buffer will accept.
    // Each call fills the buffer, then returns. The next iface.poll()
    // transmits the data and opens the window for more.
    loop {
        let remaining = &conn.pending_response[conn.response_offset..];
        if remaining.is_empty() {
            if conn.upstream_done {
                // All data sent and upstream finished. Close cleanly.
                guest_tls.send_close_notify();
                let mut close_out = Vec::new();
                if let Err(e) = guest_tls.write_tls(&mut close_out) {
                    log::warn!("close_notify encrypt failed: {e}");
                }
                sock.send_slice(&close_out).ok();
                sock.close();
                conn.state = ConnState::Closing;
            }
            // If upstream not done, caller will switch back to WaitingForUpstream
            return;
        }

        let send_cap = sock.send_capacity() - sock.send_queue();
        // TLS adds ~40 bytes overhead per record
        let chunk_size = remaining.len().min(16384).min(send_cap.saturating_sub(256));
        if chunk_size == 0 {
            log::trace!(
                "drain stalled: {}/{} bytes sent, send_cap={}, queue={}",
                conn.response_offset,
                conn.pending_response.len(),
                send_cap,
                sock.send_queue()
            );
            return; // TCP window full, try again after next poll
        }

        let chunk = &remaining[..chunk_size];
        if let Err(e) = guest_tls.writer().write_all(chunk) {
            log::warn!("guest TLS write failed: {e}");
            sock.close();
            conn.state = ConnState::Closing;
            return;
        }
        conn.response_offset += chunk_size;

        // Encrypt and push to smoltcp
        let mut out = Vec::new();
        if let Err(e) = guest_tls.write_tls(&mut out) {
            log::warn!("guest TLS encrypt failed: {e}");
            sock.close();
            conn.state = ConnState::Closing;
            return;
        }
        for tcp_chunk in out.chunks(65535) {
            if let Err(e) = sock.send_slice(tcp_chunk) {
                log::warn!("smoltcp send failed: {e}");
                return;
            }
        }
    }
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
    fn rewrite_connection_close_adds_when_missing() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
        let result = rewrite_connection_close(resp);
        let text = String::from_utf8_lossy(&result);
        assert!(text.contains("Connection: close"));
        assert!(text.contains("Content-Type: text/plain"));
        assert!(text.ends_with("body"));
    }

    #[test]
    fn request_has_upgrade_websocket() {
        let req = b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert!(request_has_upgrade(req));
    }

    #[test]
    fn request_has_upgrade_case_insensitive() {
        let req = b"GET /ws HTTP/1.1\r\nupgrade: websocket\r\n\r\n";
        assert!(request_has_upgrade(req));
    }

    #[test]
    fn request_has_upgrade_none() {
        let req = b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!request_has_upgrade(req));
    }

    #[test]
    fn rewrite_connection_close_preserves_binary_body() {
        let mut resp = b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n".to_vec();
        let binary: Vec<u8> = (0..=255).collect();
        resp.extend_from_slice(&binary);

        let result = rewrite_connection_close(&resp);
        let text = String::from_utf8_lossy(&result[..50]);
        assert!(text.contains("Connection: close"));
        // Binary body must be byte-identical
        assert_eq!(
            &result[result.len() - 256..],
            &binary[..],
            "binary body corrupted by rewrite"
        );
    }
}
