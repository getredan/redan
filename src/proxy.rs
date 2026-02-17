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
/// TLS handshake (via rustls `StreamOwned`) -> HTTP parsing -> upstream
/// relay -> secret injection/scrubbing -> response streaming.
///
/// The poll loop shuttles encrypted bytes between smoltcp TCP sockets
/// and per-connection channels. No manual TLS state machine.
use std::collections::HashMap;
use std::io::{BufWriter, Read, Write};
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

/// Shared audit log writer. None = no audit logging.
type AuditLog = Option<Arc<Mutex<BufWriter<std::fs::File>>>>;

/// Write a JSON-lines audit event. Logs a warning on write failure.
fn audit(log: &AuditLog, event: &str, fields: &[(&str, &str)]) {
    let Some(log) = log else { return };
    let ts = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let mut map = serde_json::Map::new();
    map.insert("ts".into(), serde_json::Value::String(ts));
    map.insert("event".into(), serde_json::Value::String(event.into()));
    for (k, v) in fields {
        map.insert((*k).into(), serde_json::Value::String((*v).into()));
    }
    if let Ok(mut w) = log.lock()
        && (serde_json::to_writer(&mut *w, &serde_json::Value::Object(map)).is_err()
            || writeln!(w).is_err())
    {
        log::warn!("failed to write audit event: {event}");
    }
}

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

pub struct ProxyConfig<'a> {
    pub host_sock: UnixStream,
    pub ca: Arc<Mutex<MitmCa>>,
    pub secrets: &'a [SecretBinding],
    pub timeout: Duration,
    pub allowed_hosts: Option<Vec<String>>,
    pub audit_log_path: Option<&'a str>,
    /// Discover mode: allow all connections, collect hostnames.
    pub discover: bool,
}

/// Hosts observed during a discover-mode run.
type DiscoveredHosts = Arc<Mutex<std::collections::BTreeSet<String>>>;

/// Hosts discovered during a `--discover` run. Returned to the caller.
#[allow(clippy::too_many_lines)] // Event loop; splitting would obscure control flow
pub fn run(cfg: ProxyConfig<'_>) -> Vec<String> {
    let ProxyConfig {
        host_sock,
        ca,
        secrets,
        timeout,
        allowed_hosts,
        audit_log_path,
        discover,
    } = cfg;
    let resolver = Arc::new(MitmCertResolver {
        ca: Arc::clone(&ca),
    });
    let server_config = ca::mitm_server_config(resolver);
    let secrets: Arc<[SecretBinding]> = secrets.into();

    // In discover mode, allow all connections so we can observe what
    // the agent tries to reach.
    let allowed_hosts: Option<Arc<[String]>> = if discover {
        None
    } else {
        allowed_hosts.map(Into::into)
    };
    let discovered: DiscoveredHosts = Arc::new(Mutex::new(std::collections::BTreeSet::new()));

    let audit_log: AuditLog = audit_log_path.map(|path| {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| {
                eprintln!("cannot open audit log {path}: {e}");
                std::process::exit(1);
            });
        Arc::new(Mutex::new(BufWriter::new(file)))
    });

    let mut device = VirtioNetDevice::new(host_sock);
    let config = Config::new(GATEWAY_MAC.into());
    let mut iface = Interface::new(config, &mut device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        #[allow(clippy::unwrap_used)] // Single address on fresh interface
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
        if !timeout.is_zero() && start.elapsed() > timeout {
            log::info!("proxy timeout ({timeout:?}). Use --timeout 0 for no limit.");
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
            process_dns(&mut sockets, dns_handle, &audit_log);

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
                        connections.insert(
                            handle,
                            ProxyConn::new(
                                handle,
                                backlog.is_tls,
                                &server_config,
                                &secrets,
                                allowed_hosts.as_ref(),
                                &audit_log,
                                &discovered,
                            ),
                        );
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

        let has_pending = connections
            .values()
            .any(|c| matches!(c.state, ConnState::Shuttling | ConnState::Draining));

        if has_pending {
            std::thread::sleep(Duration::from_micros(100));
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    // Return discovered hosts (empty if not in discover mode)
    discovered
        .lock()
        .map(|h| h.iter().cloned().collect())
        .unwrap_or_default()
}

struct ListenBacklog {
    port: u16,
    is_tls: bool,
    handles: Vec<SocketHandle>,
}

const LISTEN_BACKLOG: usize = 32;

// --- DNS (unchanged) ---

#[allow(clippy::unwrap_used)] // Fresh socket bind cannot fail
fn add_udp_listener(sockets: &mut SocketSet, port: u16) -> SocketHandle {
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 32 * 512]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 32 * 512]);
    let mut sock = udp::Socket::new(rx, tx);
    sock.bind(port).unwrap();
    sockets.add(sock)
}

fn process_dns(sockets: &mut SocketSet, handle: SocketHandle, audit_log: &AuditLog) {
    let sock = sockets.get_mut::<udp::Socket>(handle);
    while sock.can_recv() {
        if let Ok((data, sender)) = sock.recv()
            && let Some((hostname, response)) = dns::handle_query(data, GATEWAY_IP)
        {
            log::info!("DNS: {hostname} -> {GATEWAY_IP}");
            audit(audit_log, "dns", &[("hostname", &hostname)]);
            sock.send_slice(&response, sender).ok();
        }
    }
}

// --- TCP ---

#[allow(clippy::unwrap_used)] // Fresh socket listen cannot fail
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
        allowed_hosts: Option<&Arc<[String]>>,
        audit_log: &AuditLog,
        discovered: &DiscoveredHosts,
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
            let allowed = allowed_hosts.cloned();
            let alog = audit_log.clone();
            let disc = Arc::clone(discovered);
            std::thread::spawn(move || {
                if let Err(e) = tls_connection_thread(
                    to_rx,
                    from_tx,
                    config,
                    &secrets,
                    allowed.as_deref(),
                    &alog,
                    &disc,
                ) {
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
            let Ok(n) = sock.recv_slice(&mut buf) else {
                return;
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
            if n > 0
                && let Some(tx) = &conn.to_thread
                && tx.send(buf[..n].to_vec()).is_err()
            {
                // Thread died
                conn.to_thread = None;
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

/// Read/Write adapter over mpsc channels. Lets rustls `StreamOwned`
/// drive the TLS state machine over channel-transported bytes.
struct ChannelStream {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::SyncSender<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl ChannelStream {
    const fn new(rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::SyncSender<Vec<u8>>) -> Self {
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
        self.tx
            .send(buf.to_vec())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Per-connection thread: TLS handshake, HTTP parsing, upstream relay,
/// secret injection and response scrubbing. Rustls `StreamOwned` drives
/// the TLS state machine automatically.
#[allow(clippy::too_many_lines)] // TLS pipeline; splitting would obscure the flow
fn tls_connection_thread(
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::SyncSender<Vec<u8>>,
    server_config: Arc<rustls::ServerConfig>,
    secrets: &[SecretBinding],
    allowed_hosts: Option<&[String]>,
    audit_log: &AuditLog,
    discovered: &DiscoveredHosts,
) -> Result<(), crate::error::Error> {
    // Cap at 8KB: secrets longer than this won't be scrubbed from
    // response bodies (still injected into request headers). The overlap
    // buffer between chunks is max_secret_len - 1, so this bounds memory.
    const MAX_SCRUB_SECRET_LEN: usize = 8192;

    let stream = ChannelStream::new(rx, tx);
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
    let sni = tls.conn.server_name().unwrap_or("").to_string();

    if sni.is_empty() {
        return Err("no SNI in ClientHello".to_string().into());
    }

    // Validate SNI is a reasonable hostname. Guest controls this value;
    // reject anything that isn't DNS-safe to prevent log injection
    // (ANSI escapes) or weird resolver behavior.
    if sni.len() > 253
        || !sni
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        log::warn!("rejected invalid SNI: {sni:?}");
        return Err("invalid SNI hostname".to_string().into());
    }

    // Enforce outbound host allowlist. When set, only SNI hostnames
    // matching the list may connect upstream. Supports wildcards:
    // "*.example.com" matches "api.example.com" but not "example.com".
    if let Some(hosts) = allowed_hosts
        && !hosts.iter().any(|h| host_matches(h, &sni))
    {
        log::warn!("blocked connection to {sni}: not in --allow-host list");
        audit(
            audit_log,
            "reject",
            &[("host", &sni), ("reason", "not_allowed")],
        );
        let body = format!(
            "redan: connection to {sni} blocked by network policy.\n\
             Host is not in the allowlist. Add it to redan.toml:\n\n\
             [network]\n\
             allow = [\"{sni}\"]\n"
        );
        let resp = format!(
            "HTTP/1.1 403 Forbidden\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {body}",
            body.len()
        );
        let _ = tls.write_all(resp.as_bytes());
        return Ok(());
    }

    log::info!(
        "DECRYPTED from guest ({} bytes): {}",
        request.len(),
        String::from_utf8_lossy(&request)
            .lines()
            .next()
            .unwrap_or("")
    );

    // Reject CONNECT method. Currently non-exploitable (we're post-TLS
    // termination so CONNECT is nonsensical), but if the architecture
    // ever supports non-TLS upstream, CONNECT becomes a tunnel bypass.
    if request_is_connect(&request) {
        log::warn!("rejected CONNECT request to {sni}");
        let resp = b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n";
        tls.write_all(resp)?;
        return Ok(());
    }

    // Reject WebSocket upgrades (binary framing bypasses HTTP scrubbing)
    if request_has_upgrade(&request) {
        log::warn!("rejected WebSocket/Upgrade request");
        let resp = b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n";
        tls.write_all(resp)?;
        return Ok(());
    }

    // Reject duplicate Content-Length headers (request smuggling vector)
    if has_duplicate_content_length(&request) {
        log::warn!("rejected request with conflicting Content-Length headers");
        let resp = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
        tls.write_all(resp)?;
        return Ok(());
    }

    // Reject Host/SNI mismatch (domain fronting).
    // A malicious guest could set SNI to an allowed CDN host but Host
    // to an attacker-controlled origin. The CDN routes on Host, so the
    // secret ends up at the attacker. Reject unless they match.
    if let Some(host) = extract_host_header(&request) {
        // Strip port if present (Host: example.com:443)
        let host_name = host.split(':').next().unwrap_or(&host);
        if !host_name.eq_ignore_ascii_case(&sni) {
            log::warn!("rejected domain fronting: SNI={sni}, Host={host_name}");
            audit(
                audit_log,
                "reject",
                &[("host", &sni), ("reason", "domain_fronting")],
            );
            let resp = b"HTTP/1.1 421 Misdirected Request\r\nConnection: close\r\n\r\n";
            tls.write_all(resp)?;
            return Ok(());
        }
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
        audit(
            audit_log,
            "inject",
            &[("host", &sni), ("count", &inject_count.to_string())],
        );
    }

    // Connect upstream
    log::info!("upstream connect for {sni}");
    audit(audit_log, "connect", &[("host", &sni)]);

    // Record host for discover mode
    if let Ok(mut hosts) = discovered.lock() {
        hosts.insert(sni.to_ascii_lowercase());
    }
    // Allow private IPs only for hosts explicitly in the allowlist.
    // Blocks DNS rebinding attacks to cloud metadata / internal services,
    // but lets users reach localhost or internal hosts they opted into.
    let explicitly_allowed = allowed_hosts
        .as_ref()
        .is_some_and(|hosts| hosts.iter().any(|h| host_matches(h, &sni)));
    let (mut upstream_tcp, mut upstream_tls) =
        tls::connect_upstream(&sni, 443, explicitly_allowed)?;

    // Set timeouts before handshake to prevent slowloris-style stalls
    upstream_tcp.set_nonblocking(false)?;
    upstream_tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    upstream_tcp.set_write_timeout(Some(Duration::from_secs(30)))?;

    // Complete TLS handshake with upstream.
    // TCP socket has 30s read/write timeout so read_tls/write_tls
    // won't block indefinitely. Iteration cap as defense in depth.
    for _ in 0..1000 {
        if !upstream_tls.is_handshaking() {
            break;
        }
        if upstream_tls.wants_write() {
            upstream_tls.write_tls(&mut upstream_tcp)?;
        }
        if upstream_tls.wants_read() {
            upstream_tls.read_tls(&mut upstream_tcp)?;
            upstream_tls.process_new_packets()?;
        }
    }
    if upstream_tls.is_handshaking() {
        return Err("upstream TLS handshake did not complete".to_string().into());
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
        .unwrap_or(0)
        .min(MAX_SCRUB_SECRET_LEN);
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

                            // Warn if upstream sent compressed despite
                            // Accept-Encoding being stripped. Some CDNs
                            // compress unconditionally.
                            if has_content_encoding(&headers) {
                                log::warn!(
                                    "upstream {sni} sent Content-Encoding despite \
                                     Accept-Encoding removal; scrubbing may miss \
                                     secrets in compressed body"
                                );
                                audit(
                                    audit_log,
                                    "warn",
                                    &[("host", &sni), ("reason", "compressed_response")],
                                );
                            }

                            let (scrubbed, scrub_count) = crate::secret::scrub(&headers, secrets);
                            if scrub_count > 0 {
                                log::info!("HEADERS SCRUBBED: {scrub_count} value(s)");
                                audit(
                                    audit_log,
                                    "scrub",
                                    &[
                                        ("host", &sni),
                                        ("count", &scrub_count.to_string()),
                                        ("location", "headers"),
                                    ],
                                );
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
    let Ok(httparse::Status::Complete(body_offset)) = req.parse(data) else {
        return false;
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

/// Reject requests with multiple Content-Length headers whose values disagree.
/// Per RFC 7230 3.3.3, a recipient MUST reject such messages.
fn has_duplicate_content_length(data: &[u8]) -> bool {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(data).is_err() {
        return false;
    }
    let mut seen: Option<&[u8]> = None;
    for header in req.headers.iter() {
        if header.name.eq_ignore_ascii_case("content-length") {
            let val = header.value;
            match seen {
                None => seen = Some(val),
                Some(prev) if prev == val => {} // identical, OK
                Some(_) => return true,         // conflicting
            }
        }
    }
    false
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

/// Returns true if the response has a Content-Encoding header other
/// than "identity". Indicates scrubbing may not catch secrets in the body.
fn has_content_encoding(data: &[u8]) -> bool {
    let mut parsed_headers = [httparse::EMPTY_HEADER; 128];
    let mut resp = httparse::Response::new(&mut parsed_headers);
    if resp.parse(data).is_err() {
        return false;
    }
    resp.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("content-encoding")
            && !std::str::from_utf8(h.value)
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("identity")
    })
}

fn request_is_connect(data: &[u8]) -> bool {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(data).is_err() {
        return false;
    }
    req.method
        .is_some_and(|m| m.eq_ignore_ascii_case("CONNECT"))
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

/// Check if a hostname matches an allowlist pattern.
/// Supports exact match (case-insensitive) and wildcard prefix:
/// - `"api.example.com"` matches `"api.example.com"` and `"API.EXAMPLE.COM"`
/// - `"*.example.com"` matches `"api.example.com"` and `"foo.bar.example.com"`
/// - `"*.example.com"` does NOT match `"example.com"` (must have a subdomain)
pub(crate) fn host_matches(pattern: &str, hostname: &str) -> bool {
    pattern.strip_prefix("*.").map_or_else(
        || pattern.eq_ignore_ascii_case(hostname),
        |suffix| {
            // Wildcard: hostname must end with .suffix and have something before it
            let hostname_lower = hostname.to_ascii_lowercase();
            let suffix_lower = suffix.to_ascii_lowercase();
            hostname_lower.ends_with(&format!(".{suffix_lower}"))
        },
    )
}

/// Extract the Host header value from an HTTP request.
fn extract_host_header(data: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(data).is_err() {
        return None;
    }
    req.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .map(|h| String::from_utf8_lossy(h.value).into_owned())
}

use crate::secret::find_header_end as header_end_offset;

fn rewrite_connection_close(data: &[u8]) -> Vec<u8> {
    let mut parsed_headers = [httparse::EMPTY_HEADER; 128];
    let mut resp = httparse::Response::new(&mut parsed_headers);
    let Ok(httparse::Status::Complete(body_offset)) = resp.parse(data) else {
        return data.to_vec();
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cloned_ref_to_slice_refs
)]
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
        SecretBinding::new_unchecked(placeholder.to_string(), real.to_string(), vec![])
    }

    #[test]
    fn scrub_chunk_single_chunk() {
        let secret = make_secret("ph", "SECRET123");
        let mut out = Vec::new();
        let mut overlap = Vec::new();
        write_scrubbed_chunk(
            &mut out,
            b"prefix SECRET123 suffix",
            &[secret],
            9,
            &mut overlap,
        )
        .unwrap();
        // Flush remaining overlap
        out.extend_from_slice(&overlap);
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("ph"),
            "secret should be replaced with placeholder"
        );
        assert!(
            !text.contains("SECRET123"),
            "secret must not appear in output"
        );
    }

    #[test]
    fn scrub_chunk_secret_spans_boundary() {
        let secret = make_secret("ph", "ABCDEFGHIJ");
        let mut out = Vec::new();
        let mut overlap = Vec::new();
        // Split secret: "ABCDE" in chunk 1, "FGHIJ" in chunk 2
        write_scrubbed_chunk(
            &mut out,
            b"prefix ABCDE",
            &[secret.clone()],
            10,
            &mut overlap,
        )
        .unwrap();
        write_scrubbed_chunk(&mut out, b"FGHIJ suffix", &[secret], 10, &mut overlap).unwrap();
        out.extend_from_slice(&overlap);
        let text = String::from_utf8_lossy(&out);
        assert!(
            !text.contains("ABCDEFGHIJ"),
            "secret spanning chunks must be scrubbed"
        );
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
        write_scrubbed_chunk(
            &mut out,
            b"got ALPHA and BETA here",
            &[s1, s2],
            max_len,
            &mut overlap,
        )
        .unwrap();
        out.extend_from_slice(&overlap);
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains("ALPHA"), "first secret must be scrubbed");
        assert!(!text.contains("BETA"), "second secret must be scrubbed");
    }

    #[test]
    fn duplicate_content_length_detected() {
        let req = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello";
        assert!(has_duplicate_content_length(req));
    }

    #[test]
    fn identical_content_length_ok() {
        let req = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
        assert!(!has_duplicate_content_length(req));
    }

    #[test]
    fn single_content_length_ok() {
        let req = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        assert!(!has_duplicate_content_length(req));
    }

    #[test]
    fn wildcard_host_match() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "foo.bar.example.com"));
        assert!(host_matches("*.example.com", "API.EXAMPLE.COM"));
        assert!(host_matches("*.EXAMPLE.COM", "api.example.com"));
    }

    #[test]
    fn wildcard_no_match_bare_domain() {
        // *.example.com should NOT match example.com itself
        assert!(!host_matches("*.example.com", "example.com"));
    }

    #[test]
    fn wildcard_no_match_different_domain() {
        assert!(!host_matches("*.example.com", "api.evil.com"));
        assert!(!host_matches("*.example.com", "example.com.evil.com"));
    }

    #[test]
    fn exact_host_match() {
        assert!(host_matches("api.example.com", "api.example.com"));
        assert!(host_matches("api.example.com", "API.EXAMPLE.COM"));
        assert!(!host_matches("api.example.com", "other.example.com"));
    }

    #[test]
    fn extract_host_from_request() {
        let req = b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        assert_eq!(extract_host_header(req).as_deref(), Some("api.example.com"));
    }

    #[test]
    fn extract_host_with_port() {
        let req = b"GET / HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n";
        assert_eq!(
            extract_host_header(req).as_deref(),
            Some("api.example.com:443")
        );
    }

    #[test]
    fn connect_method_detected() {
        let req = b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        assert!(request_is_connect(req));
    }

    #[test]
    fn connect_method_case_insensitive() {
        let req = b"connect api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        assert!(request_is_connect(req));
    }

    #[test]
    fn get_is_not_connect() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!request_is_connect(req));
    }

    #[test]
    fn content_encoding_gzip_detected() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n";
        assert!(has_content_encoding(resp));
    }

    #[test]
    fn content_encoding_identity_ignored() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\n\r\n";
        assert!(!has_content_encoding(resp));
    }

    #[test]
    fn no_content_encoding_ok() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
        assert!(!has_content_encoding(resp));
    }

    #[test]
    fn extract_host_missing() {
        let req = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        assert_eq!(extract_host_header(req), None);
    }
}
