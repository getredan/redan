/// MITM proxy: smoltcp event loop with DNS, HTTP, and TLS interception.
///
/// Listens on the gateway side of a virtio-net link. Handles:
/// - UDP port 53: synthetic DNS (all names -> gateway IP)
/// - TCP port 80: HTTP interception (rejects with 421)
/// - TCP port 443: TLS MITM via per-connection threads
///
/// ## Architecture
///
/// The smoltcp poll loop handles L3/L4: IP routing, TCP state, DNS.
/// Each TLS connection spawns a thread that owns the full pipeline:
/// TLS handshake (via rustls StreamOwned) -> HTTP parsing -> upstream
/// relay -> secret injection/scrubbing -> response streaming.
///
/// The poll loop shuttles encrypted bytes between smoltcp TCP sockets
/// and per-connection channels. No manual TLS state machine.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Address};

use crate::ca::{self, MitmCa, MitmCertResolver};
use crate::dns;
use crate::net::VirtioNetDevice;
use crate::secret::SecretBinding;
use crate::tls;

pub const GATEWAY_IP: Ipv4Address = Ipv4Address::new(192, 168, 127, 1);
pub const GATEWAY_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
pub const GUEST_IP: &str = "192.168.127.2";

const TCP_SOCKET_BUF: usize = 256 * 1024;
const MAX_REQUEST_BODY: usize = 16 * 1024 * 1024;
const MAX_RESPONSE_SIZE: usize = 256 * 1024 * 1024;
/// Max active TLS connections. Each spawns a thread (~8MB stack).
/// 128 connections = ~1GB stack memory worst case.
const MAX_CONNECTIONS: usize = 128;

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

pub fn run(host_sock: UnixStream, ca: Arc<Mutex<MitmCa>>, secrets: &[SecretBinding], timeout: Duration) {
    let resolver = Arc::new(MitmCertResolver { ca: Arc::clone(&ca) });
    let server_config = ca::mitm_server_config(resolver);
    let secrets: Arc<[SecretBinding]> = secrets.into();

    let mut device = VirtioNetDevice::new(host_sock);
    let config = Config::new(GATEWAY_MAC.into());
    let mut iface = Interface::new(config, &mut device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(GATEWAY_IP.into(), 24)).unwrap();
    });

    let mut sockets = SocketSet::new(vec![]);
    let mut connections: HashMap<SocketHandle, ProxyConn> = HashMap::new();

    let dns_handle = add_udp_listener(&mut sockets, 53);

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

        let timestamp = SmolInstant::now();
        let result = iface.poll(timestamp, &mut device, &mut sockets);
        device.flush_tx();

        if matches!(result, PollResult::SocketStateChanged) {
            process_dns(&mut sockets, dns_handle);

            for backlog in &mut backlogs {
                let mut i = 0;
                while i < backlog.handles.len() {
                    let handle = backlog.handles[i];
                    let sock = sockets.get_mut::<tcp::Socket>(handle);
                    if sock.may_recv() && sock.state() != tcp::State::Listen {
                        if connections.len() >= MAX_CONNECTIONS {
                            log::warn!("connection limit ({MAX_CONNECTIONS}), rejecting");
                            sock.close();
                            backlog.handles[i] = add_tcp_listener(&mut sockets, backlog.port);
                            i += 1;
                            continue;
                        }
                        log::info!(
                            "connection on :{} from {:?}",
                            backlog.port,
                            sock.remote_endpoint()
                        );
                        connections.insert(handle, ProxyConn::new(handle, backlog.is_tls, &server_config, &secrets));
                        backlog.handles[i] = add_tcp_listener(&mut sockets, backlog.port);
                    }
                    i += 1;
                }
            }
        }

        // Shuttle bytes for all active connections.
        for conn in connections.values_mut() {
            let sock = sockets.get_mut::<tcp::Socket>(conn.handle);
            shuttle_bytes(sock, conn);
        }
        reap_done(&mut connections, &mut sockets);

        let has_pending = connections.values().any(|c| {
            matches!(c.state, ConnState::Shuttling | ConnState::Draining)
        });

        if has_pending {
            std::thread::sleep(Duration::from_micros(100));
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

}

struct ListenBacklog {
    port: u16,
    is_tls: bool,
    handles: Vec<SocketHandle>,
}

const LISTEN_BACKLOG: usize = 32;

// --- DNS (unchanged) ---

fn add_udp_listener(sockets: &mut SocketSet, port: u16) -> SocketHandle {
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 32 * 512]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 32 * 512]);
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
    let rx_buf = tcp::SocketBuffer::new(vec![0; TCP_SOCKET_BUF]);
    let tx_buf = tcp::SocketBuffer::new(vec![0; TCP_SOCKET_BUF]);
    let mut sock = tcp::Socket::new(rx_buf, tx_buf);
    sock.listen(port).unwrap();
    sockets.add(sock)
}

// --- Connection handling ---

struct ProxyConn {
    handle: SocketHandle,
    is_tls: bool,
    /// Channel: poll loop sends encrypted bytes from smoltcp to the thread.
    to_thread: Option<mpsc::Sender<Vec<u8>>>,
    /// Channel: thread sends encrypted bytes back to smoltcp.
    from_thread: Option<mpsc::Receiver<Vec<u8>>>,
    /// Buffered bytes from the thread waiting to be written to smoltcp.
    pending_send: Vec<u8>,
    send_offset: usize,

    state: ConnState,
}

#[derive(Debug, PartialEq)]
enum ConnState {
    /// Waiting for first data to determine protocol (TLS vs HTTP).
    WaitingForData,
    /// TLS: thread is running, shuttling bytes between smoltcp and channels.
    Shuttling,
    /// Thread finished, draining remaining response bytes to smoltcp.
    Draining,
    /// TCP close in progress.
    Closing,
    Done,
}

impl ProxyConn {
    fn new(
        handle: SocketHandle,
        is_tls: bool,
        server_config: &Arc<rustls::ServerConfig>,
        secrets: &Arc<[SecretBinding]>,
    ) -> Self {
        let mut conn = Self {
            handle,
            is_tls,
            to_thread: None,
            from_thread: None,
            pending_send: Vec::new(),
            send_offset: 0,
            state: ConnState::WaitingForData,
        };

        if is_tls {
            // Pre-create channels and spawn the handler thread.
            // The thread blocks on rx until the poll loop feeds it data.
            let (to_tx, to_rx) = mpsc::channel::<Vec<u8>>();
            // Bounded: backpressure when guest TCP window is full.
            // 64 * 16KB chunks = ~1MB buffered before thread blocks.
            let (from_tx, from_rx) = mpsc::sync_channel::<Vec<u8>>(64);
            conn.to_thread = Some(to_tx);
            conn.from_thread = Some(from_rx);
            conn.state = ConnState::Shuttling;

            let config = Arc::clone(server_config);
            let secrets = Arc::clone(secrets);
            std::thread::spawn(move || {
                if let Err(e) = tls_connection_thread(to_rx, from_tx, config, &secrets) {
                    log::warn!("TLS connection thread error: {e}");
                }
            });
        }

        conn
    }
}

/// Shuttle bytes between smoltcp TCP socket and the per-connection thread.
fn shuttle_bytes(sock: &mut tcp::Socket<'_>, conn: &mut ProxyConn) {
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

            if !conn.is_tls {
                // HTTP/80: reject immediately
                let request = String::from_utf8_lossy(&buf[..n]);
                log::info!(
                    "HTTP request (plaintext): {}",
                    request.lines().next().unwrap_or("")
                );
                let response = b"HTTP/1.1 421 Misdirected Request\r\n\
                    Content-Type: text/plain\r\n\
                    Connection: close\r\n\r\n\
                    redan: use HTTPS. Plaintext HTTP is not proxied.\n";
                conn.pending_send = response.to_vec();
                conn.send_offset = 0;
                conn.state = ConnState::Draining;
                return;
            }

            // TLS: forward to the thread
            if let Some(tx) = &conn.to_thread {
                tx.send(buf[..n].to_vec()).ok();
            }
        }

        ConnState::Shuttling => {
            // Guest -> Thread: read from smoltcp, send to thread
            let mut buf = vec![0u8; 65535];
            let n = sock.recv_slice(&mut buf).unwrap_or(0);
            if n > 0 {
                if let Some(tx) = &conn.to_thread {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        // Thread died
                        conn.to_thread = None;
                    }
                }
            }

            // Thread -> Guest: recv from thread, buffer for sending
            if let Some(rx) = &conn.from_thread {
                loop {
                    match rx.try_recv() {
                        Ok(data) => conn.pending_send.extend_from_slice(&data),
                        Err(mpsc::TryRecvError::Empty) => break,
                        Err(mpsc::TryRecvError::Disconnected) => {
                            // Thread finished. Drain remaining data then close.
                            conn.from_thread = None;
                            conn.to_thread = None;
                            if conn.pending_send.is_empty() {
                                sock.close();
                                conn.state = ConnState::Closing;
                            } else {
                                conn.state = ConnState::Draining;
                            }
                            break;
                        }
                    }
                }
            }

            // Flush pending_send to smoltcp
            drain_to_socket(sock, conn);

            // Check if socket was closed by guest
            if !sock.is_active() && !sock.may_recv() {
                conn.to_thread = None; // drop sender, thread will see BrokenPipe
                conn.from_thread = None;
                conn.state = ConnState::Done;
            }
        }

        ConnState::Draining => {
            drain_to_socket(sock, conn);
            if conn.send_offset >= conn.pending_send.len() {
                sock.close();
                conn.state = ConnState::Closing;
            }
        }

        ConnState::Closing => {
            if !sock.is_active() {
                conn.state = ConnState::Done;
            }
        }

        ConnState::Done => {}
    }
}

/// Write buffered bytes to the smoltcp socket, respecting the TCP window.
fn drain_to_socket(sock: &mut tcp::Socket<'_>, conn: &mut ProxyConn) {
    loop {
        let remaining = &conn.pending_send[conn.send_offset..];
        if remaining.is_empty() {
            return;
        }
        let can_send = sock.send_capacity() - sock.send_queue();
        if can_send == 0 {
            break;
        }
        let n = remaining.len().min(can_send).min(65535);
        match sock.send_slice(&remaining[..n]) {
            Ok(sent) => conn.send_offset += sent,
            Err(_) => break,
        }
    }

    // Compact: reclaim already-sent bytes to bound memory
    if conn.send_offset > conn.pending_send.len() / 2 && conn.send_offset > 65536 {
        conn.pending_send.drain(..conn.send_offset);
        conn.send_offset = 0;
    }
}

// --- Per-connection TLS thread ---

/// Read/Write adapter over mpsc channels. Lets rustls::StreamOwned
/// drive the TLS state machine over channel-transported bytes.
struct ChannelStream {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::SyncSender<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl ChannelStream {
    fn new(rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::SyncSender<Vec<u8>>) -> Self {
        Self {
            rx,
            tx,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl Read for ChannelStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Drain current buffer first
        if self.read_pos < self.read_buf.len() {
            let available = &self.read_buf[self.read_pos..];
            let n = buf.len().min(available.len());
            buf[..n].copy_from_slice(&available[..n]);
            self.read_pos += n;
            return Ok(n);
        }

        // Block until more data arrives, with timeout to prevent
        // a malicious guest from holding threads indefinitely with
        // partial TLS handshakes.
        self.read_buf = self
            .rx
            .recv_timeout(Duration::from_secs(30))
            .map_err(|e| match e {
                mpsc::RecvTimeoutError::Timeout => {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "channel read timeout")
                }
                mpsc::RecvTimeoutError::Disconnected => {
                    std::io::Error::new(std::io::ErrorKind::ConnectionReset, "channel closed")
                }
            })?;
        self.read_pos = 0;

        let n = buf.len().min(self.read_buf.len());
        buf[..n].copy_from_slice(&self.read_buf[..n]);
        self.read_pos = n;
        Ok(n)
    }
}

impl Write for ChannelStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx.send(buf.to_vec()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel closed")
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Per-connection thread: TLS handshake, HTTP parsing, upstream relay,
/// secret injection and response scrubbing. rustls::StreamOwned drives
/// the TLS state machine automatically.
fn tls_connection_thread(
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::SyncSender<Vec<u8>>,
    server_config: Arc<rustls::ServerConfig>,
    secrets: &[SecretBinding],
) -> Result<(), crate::error::Error> {
    let stream = ChannelStream::new(rx, tx.clone());
    let server_conn = rustls::ServerConnection::new(server_config)?;
    let mut tls = rustls::StreamOwned::new(server_conn, stream);

    // Read the full HTTP request through TLS. The first read() drives
    // the handshake to completion automatically.
    let mut request = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        let n = tls.read(&mut buf)?;
        if n == 0 {
            return Ok(()); // Client closed before sending a request
        }
        request.extend_from_slice(&buf[..n]);
        if http_request_complete(&request) {
            break;
        }
        if request.len() > MAX_REQUEST_BODY {
            return Err("request too large".to_string().into());
        }
    }

    // Get SNI from the completed handshake
    let sni = tls
        .conn
        .server_name()
        .unwrap_or("")
        .to_string();

    if sni.is_empty() {
        return Err("no SNI in ClientHello".to_string().into());
    }

    log::info!(
        "DECRYPTED from guest ({} bytes): {}",
        request.len(),
        String::from_utf8_lossy(&request)
            .lines()
            .next()
            .unwrap_or("")
    );

    // Reject WebSocket upgrades (binary framing bypasses HTTP scrubbing)
    if request_has_upgrade(&request) {
        log::warn!("rejected WebSocket/Upgrade request");
        let resp = b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n";
        tls.write_all(resp)?;
        return Ok(());
    }

    // Reject chunked Transfer-Encoding. We read until Content-Length
    // is satisfied or headers are complete (for bodyless requests).
    // Chunked bodies have no Content-Length, so the body would be
    // truncated. Reject with 411 Length Required.
    if request_has_chunked_te(&request) {
        log::warn!("rejected chunked Transfer-Encoding request");
        let resp = b"HTTP/1.1 411 Length Required\r\nConnection: close\r\n\r\n";
        tls.write_all(resp)?;
        return Ok(());
    }

    // Rewrite headers and inject secrets
    let request = crate::secret::rewrite_request_headers(&request);
    let (request_data, inject_count) = crate::secret::inject(&request, &sni, secrets);
    if inject_count > 0 {
        log::info!("SECRET INJECTED: {inject_count} replacement(s) for {sni}");
    }

    // Connect upstream
    log::info!("upstream connect for {sni}");
    let (mut upstream_tcp, mut upstream_tls) = tls::connect_upstream(&sni, 443)?;

    // Set timeouts before handshake to prevent slowloris-style stalls
    upstream_tcp.set_nonblocking(false)?;
    upstream_tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    upstream_tcp.set_write_timeout(Some(Duration::from_secs(30)))?;

    // Complete TLS handshake with upstream
    while upstream_tls.is_handshaking() {
        if upstream_tls.wants_write() {
            upstream_tls.write_tls(&mut upstream_tcp)?;
        }
        if upstream_tls.wants_read() {
            upstream_tls.read_tls(&mut upstream_tcp)?;
            upstream_tls.process_new_packets()?;
        }
    }

    // Relax timeout for data transfer (large responses may be slow)
    upstream_tcp.set_read_timeout(Some(Duration::from_secs(120)))?;

    // Send request
    for chunk in request_data.chunks(16384) {
        upstream_tls.writer().write_all(chunk)?;
        while upstream_tls.wants_write() {
            upstream_tls.write_tls(&mut upstream_tcp)?;
        }
        upstream_tcp.flush()?;
    }

    // Read response and stream back to guest
    let max_secret_len = secrets
        .iter()
        .map(|s| s.real_value().len())
        .max()
        .unwrap_or(0);
    // Not wrapped in Zeroizing: upstream response buffers (header_buf,
    // upstream_buf, etc.) aren't zeroized either. Scrubbing is a safety
    // net; primary defense is host allowlisting.
    let mut scrub_overlap: Vec<u8> = Vec::new();
    let mut header_buf = Vec::new();
    let mut headers_sent = false;
    let mut total_bytes: usize = 0;
    let mut upstream_buf = vec![0u8; 16384];

    loop {
        match upstream_tls.read_tls(&mut upstream_tcp) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e.into()),
        }

        let state = upstream_tls.process_new_packets()?;

        loop {
            match upstream_tls.reader().read(&mut upstream_buf) {
                Ok(0) => break,
                Ok(n) => {
                    total_bytes += n;
                    if total_bytes > MAX_RESPONSE_SIZE {
                        return Err("response too large".to_string().into());
                    }

                    if !headers_sent {
                        header_buf.extend_from_slice(&upstream_buf[..n]);
                        if let Some(end) = header_end_offset(&header_buf) {
                            let headers = header_buf[..end].to_vec();
                            let body_remainder = header_buf[end..].to_vec();

                            log::info!(
                                "upstream headers ({} bytes): {}",
                                headers.len(),
                                String::from_utf8_lossy(&headers)
                                    .lines()
                                    .next()
                                    .unwrap_or("")
                            );

                            let (scrubbed, scrub_count) =
                                crate::secret::scrub(&headers, secrets);
                            if scrub_count > 0 {
                                log::info!("HEADERS SCRUBBED: {scrub_count} value(s)");
                            }
                            let rewritten = rewrite_connection_close(&scrubbed);
                            tls.write_all(&rewritten)?;
                            headers_sent = true;

                            if !body_remainder.is_empty() {
                                write_scrubbed_chunk(
                                    &mut tls,
                                    &body_remainder,
                                    secrets,
                                    max_secret_len,
                                    &mut scrub_overlap,
                                )?;
                            }
                            header_buf = Vec::new();
                        }
                    } else {
                        write_scrubbed_chunk(
                            &mut tls,
                            &upstream_buf[..n],
                            secrets,
                            max_secret_len,
                            &mut scrub_overlap,
                        )?;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        if state.peer_has_closed() {
            // Drain remaining plaintext
            loop {
                match upstream_tls.reader().read(&mut upstream_buf) {
                    Ok(n) if n > 0 => {
                        if headers_sent {
                            write_scrubbed_chunk(
                                &mut tls,
                                &upstream_buf[..n],
                                secrets,
                                max_secret_len,
                                &mut scrub_overlap,
                            )?;
                        } else {
                            header_buf.extend_from_slice(&upstream_buf[..n]);
                        }
                    }
                    _ => break,
                }
            }
            if !headers_sent && !header_buf.is_empty() {
                let (scrubbed, _) = crate::secret::scrub(&header_buf, secrets);
                let rewritten = rewrite_connection_close(&scrubbed);
                tls.write_all(&rewritten)?;
            }
            break;
        }
    }

    // Flush remaining overlap bytes
    if !scrub_overlap.is_empty() {
        tls.write_all(&scrub_overlap)?;
    }

    // Close TLS cleanly
    tls.conn.send_close_notify();
    // StreamOwned::flush drives write_tls
    tls.flush().ok();

    Ok(())
}

/// Write a body chunk with secret scrubbing. Maintains an overlap
/// buffer to catch secrets spanning chunk boundaries.
fn write_scrubbed_chunk(
    out: &mut impl Write,
    chunk: &[u8],
    secrets: &[SecretBinding],
    max_secret_len: usize,
    scrub_overlap: &mut Vec<u8>,
) -> Result<(), crate::error::Error> {
    if max_secret_len == 0 || secrets.is_empty() {
        out.write_all(chunk)?;
        return Ok(());
    }

    let mut window = std::mem::take(scrub_overlap);
    window.extend_from_slice(chunk);

    let (scrubbed, scrub_count) = crate::secret::scrub(&window, secrets);
    if scrub_count > 0 {
        log::info!("BODY SCRUBBED: {scrub_count} value(s)");
    }

    let overlap_size = max_secret_len.saturating_sub(1);
    if scrubbed.len() > overlap_size {
        let safe_end = scrubbed.len() - overlap_size;
        out.write_all(&scrubbed[..safe_end])?;
        *scrub_overlap = scrubbed[safe_end..].to_vec();
    } else {
        *scrub_overlap = scrubbed;
    }

    Ok(())
}

// --- HTTP helpers ---

fn http_request_complete(data: &[u8]) -> bool {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    let body_offset = match req.parse(data) {
        Ok(httparse::Status::Complete(n)) => n,
        _ => return false,
    };

    for header in req.headers.iter() {
        if header.name.eq_ignore_ascii_case("content-length")
            && let Ok(cl) = std::str::from_utf8(header.value)
                .unwrap_or("0")
                .trim()
                .parse::<usize>()
        {
            if cl > MAX_REQUEST_BODY {
                return false;
            }
            return data.len() - body_offset >= cl;
        }
    }

    true
}

fn request_has_chunked_te(data: &[u8]) -> bool {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(data).is_err() {
        return false;
    }
    req.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(h.value)
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains("chunked")
    })
}

fn request_has_upgrade(data: &[u8]) -> bool {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(data).is_err() {
        return false;
    }
    req.headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("upgrade"))
}

fn header_end_offset(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

fn rewrite_connection_close(data: &[u8]) -> Vec<u8> {
    let mut parsed_headers = [httparse::EMPTY_HEADER; 128];
    let mut resp = httparse::Response::new(&mut parsed_headers);
    let body_offset = match resp.parse(data) {
        Ok(httparse::Status::Complete(n)) => n,
        _ => return data.to_vec(),
    };

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
        assert_eq!(
            &result[result.len() - 256..],
            &binary[..],
            "binary body corrupted by rewrite"
        );
    }

    #[test]
    fn chunked_te_detected() {
        let req = b"POST /api HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(request_has_chunked_te(req));
    }

    #[test]
    fn chunked_te_case_insensitive() {
        let req = b"POST /api HTTP/1.1\r\ntransfer-encoding: Chunked\r\n\r\n";
        assert!(request_has_chunked_te(req));
    }

    #[test]
    fn chunked_te_absent() {
        let req = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        assert!(!request_has_chunked_te(req));
    }

    // --- write_scrubbed_chunk overlap tests ---

    fn make_secret(placeholder: &str, real: &str) -> SecretBinding {
        SecretBinding::new_unchecked(
            placeholder.to_string(),
            real.to_string(),
            vec![],
        )
    }

    #[test]
    fn scrub_chunk_single_chunk() {
        let secret = make_secret("ph", "SECRET123");
        let mut out = Vec::new();
        let mut overlap = Vec::new();
        write_scrubbed_chunk(&mut out, b"prefix SECRET123 suffix", &[secret], 9, &mut overlap).unwrap();
        // Flush remaining overlap
        out.extend_from_slice(&overlap);
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("ph"), "secret should be replaced with placeholder");
        assert!(!text.contains("SECRET123"), "secret must not appear in output");
    }

    #[test]
    fn scrub_chunk_secret_spans_boundary() {
        let secret = make_secret("ph", "ABCDEFGHIJ");
        let mut out = Vec::new();
        let mut overlap = Vec::new();
        // Split secret: "ABCDE" in chunk 1, "FGHIJ" in chunk 2
        write_scrubbed_chunk(&mut out, b"prefix ABCDE", &[secret.clone()], 10, &mut overlap).unwrap();
        write_scrubbed_chunk(&mut out, b"FGHIJ suffix", &[secret], 10, &mut overlap).unwrap();
        out.extend_from_slice(&overlap);
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains("ABCDEFGHIJ"), "secret spanning chunks must be scrubbed");
        assert!(text.contains("ph"), "placeholder should appear");
    }

    #[test]
    fn scrub_chunk_secret_at_end_of_stream() {
        let secret = make_secret("ph", "TOKEN");
        let mut out = Vec::new();
        let mut overlap = Vec::new();
        write_scrubbed_chunk(&mut out, b"data TOKEN", &[secret], 5, &mut overlap).unwrap();
        // Flush overlap (may contain the tail)
        out.extend_from_slice(&overlap);
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains("TOKEN"), "secret at end must be scrubbed");
    }

    #[test]
    fn scrub_chunk_no_secrets_passthrough() {
        let mut out = Vec::new();
        let mut overlap = Vec::new();
        write_scrubbed_chunk(&mut out, b"hello world", &[], 0, &mut overlap).unwrap();
        assert_eq!(out, b"hello world");
        assert!(overlap.is_empty());
    }

    #[test]
    fn scrub_chunk_multiple_secrets() {
        let s1 = make_secret("P1", "ALPHA");
        let s2 = make_secret("P2", "BETA");
        let mut out = Vec::new();
        let mut overlap = Vec::new();
        let max_len = 5;
        write_scrubbed_chunk(&mut out, b"got ALPHA and BETA here", &[s1, s2], max_len, &mut overlap).unwrap();
        out.extend_from_slice(&overlap);
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains("ALPHA"), "first secret must be scrubbed");
        assert!(!text.contains("BETA"), "second secret must be scrubbed");
    }
}
