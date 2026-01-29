mod ca;
mod ffi;
mod net;

use std::collections::HashMap;
use std::ffi::CString;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

use ca::MitmCa;
use net::VirtioNetDevice;

const GATEWAY_IP: Ipv4Address = Ipv4Address::new(192, 168, 127, 1);
const GATEWAY_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);

fn main() {
    env_logger::init();
    println!("PS-4: MITM proxy test");
    println!("=====================");

    // Generate ephemeral CA
    let mitm_ca = MitmCa::generate();
    println!("[host] MITM CA generated");

    // Write CA cert to a temp file that we'll inject into the guest rootfs
    let ca_pem_path = "/tmp/redan-ca.pem";
    std::fs::write(ca_pem_path, mitm_ca.ca_cert_pem()).unwrap();

    // Install CA cert in guest trust store. The CA is ephemeral (new each run),
    // so we must replace any previously installed one.
    std::fs::write(
        "/tmp/redan-rootfs/etc/ssl/certs/redan-ca.pem",
        mitm_ca.ca_cert_pem(),
    )
    .unwrap();

    // Rebuild the ca-certificates bundle: original certs + our CA
    let bundle_path = "/tmp/redan-rootfs/etc/ssl/certs/ca-certificates.crt";
    let bundle = std::fs::read_to_string(bundle_path).unwrap_or_default();
    // Strip any previously appended Redan cert (everything after the marker)
    let base_bundle = bundle
        .split("# Redan MITM CA")
        .next()
        .unwrap_or(&bundle);
    let new_bundle = format!(
        "{}# Redan MITM CA\n{}\n",
        base_bundle,
        mitm_ca.ca_cert_pem()
    );
    std::fs::write(bundle_path, &new_bundle).unwrap();
    println!("[host] CA cert installed in guest trust store");

    // Create unix socket pair for virtio-net
    let (host_sock, guest_sock) = UnixStream::pair().expect("socketpair failed");
    let guest_fd = guest_sock.as_raw_fd();

    // Spawn VM thread
    let vm_thread = std::thread::spawn(move || {
        let ret = unsafe {
            ffi::krun_init_log(
                ffi::KRUN_LOG_TARGET_DEFAULT,
                ffi::KRUN_LOG_LEVEL_ERROR,
                ffi::KRUN_LOG_STYLE_AUTO,
                0,
            )
        };
        assert!(ret >= 0);

        let ctx_id = unsafe { ffi::krun_create_ctx() };
        assert!(ctx_id >= 0);
        let ctx_id = ctx_id as u32;

        unsafe {
            assert!(ffi::krun_set_vm_config(ctx_id, 1, 256) >= 0);
            let root = CString::new("/tmp/redan-rootfs").unwrap();
            assert!(ffi::krun_set_root(ctx_id, root.as_ptr()) >= 0);
            let workdir = CString::new("/").unwrap();
            assert!(ffi::krun_set_workdir(ctx_id, workdir.as_ptr()) >= 0);
        }

        // virtio-net
        let mac: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ret = unsafe {
            ffi::krun_add_net_unixstream(ctx_id, std::ptr::null(), guest_fd, mac.as_ptr(), 0, 0)
        };
        assert!(ret >= 0);

        // Guest: configure network, make HTTPS request through our proxy.
        // DNS not available (no UDP handler yet), so use /etc/hosts.
        let exec_path = CString::new("/bin/busybox").unwrap();
        let arg0 = CString::new("ash").unwrap();
        let arg1 = CString::new("-c").unwrap();
        let arg2 = CString::new(
            "ip link set eth0 up; \
             ip addr add 192.168.127.2/24 dev eth0; \
             ip route add default via 192.168.127.1; \
             echo '192.168.127.1 httpbin.org' >> /etc/hosts; \
             echo GUEST_NET_UP; \
             \
             echo CA_CHECK; \
             grep -c BEGIN /etc/ssl/certs/ca-certificates.crt; \
             tail -5 /etc/ssl/certs/ca-certificates.crt; \
             \
             echo TEST_HTTP; \
             wget -q -O - http://192.168.127.1:80/ 2>&1; \
             \
             echo TEST_HTTPS; \
             wget -q -O - https://httpbin.org/get 2>&1; \
             \
             echo GUEST_DONE",
        )
        .unwrap();
        let argv: Vec<*const i8> =
            vec![arg0.as_ptr(), arg1.as_ptr(), arg2.as_ptr(), std::ptr::null()];

        let path_env = CString::new(
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .unwrap();
        let term = CString::new("TERM=xterm").unwrap();
        // Point directly at our CA cert for the spike.
        // In production, we'd prepend to the full bundle.
        let ssl_cert = CString::new("SSL_CERT_FILE=/etc/ssl/certs/redan-ca.pem").unwrap();
        let envp: Vec<*const i8> = vec![
            path_env.as_ptr(),
            term.as_ptr(),
            ssl_cert.as_ptr(),
            std::ptr::null(),
        ];

        let ret = unsafe {
            ffi::krun_set_exec(ctx_id, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        };
        assert!(ret >= 0);

        std::mem::forget(guest_sock);

        println!("[vm] entering VM...");
        let exit_code = unsafe { ffi::krun_start_enter(ctx_id) };
        println!("[vm] exit code: {exit_code}");
        exit_code
    });

    // Host side: smoltcp + MITM proxy
    run_proxy(host_sock, &mitm_ca);

    println!("[host] waiting for VM...");
    match vm_thread.join() {
        Ok(code) => println!("[host] VM exited: {code}"),
        Err(_) => println!("[host] VM thread panicked"),
    }
    println!("DONE");
}

/// Tracks a proxied TCP connection from the guest.
struct ProxyConn {
    /// Guest-side smoltcp TCP socket handle
    handle: SocketHandle,
    /// Upstream TCP connection (to real server)
    upstream: Option<TcpStream>,
    /// TLS state for the upstream connection
    upstream_tls: Option<rustls::ClientConnection>,
    /// TLS state for the guest-facing side (we are the server)
    guest_tls: Option<rustls::ServerConnection>,
    /// Destination IP:port as seen by the guest
    dst: (Ipv4Address, u16),
    /// SNI hostname extracted from TLS ClientHello
    sni: Option<String>,
    /// Whether this is a TLS connection (port 443)
    is_tls: bool,
    /// Buffer for data from guest before TLS is established
    pending_guest_data: Vec<u8>,
    /// State
    state: ConnState,
}

#[derive(Debug, PartialEq)]
enum ConnState {
    /// Waiting for guest data (TLS ClientHello or HTTP request)
    WaitingForData,
    /// TLS handshake in progress
    TlsHandshake,
    /// Proxying data bidirectionally
    Proxying,
    /// Done
    Done,
}

fn run_proxy(host_sock: UnixStream, ca: &MitmCa) {
    let mut device = VirtioNetDevice::new(host_sock);

    let config = Config::new(GATEWAY_MAC.into());
    let mut iface = Interface::new(config, &mut device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(GATEWAY_IP.into(), 24))
            .unwrap();
    });

    let mut sockets = SocketSet::new(vec![]);
    let mut connections: HashMap<u16, ProxyConn> = HashMap::new();

    // Listen on ports 80 and 443
    let http_handle = add_tcp_listener(&mut sockets, 80);
    let https_handle = add_tcp_listener(&mut sockets, 443);

    println!("[host] proxy listening on :80 and :443");

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(45);

    loop {
        if start.elapsed() > timeout {
            println!("[host] timeout");
            break;
        }

        let timestamp = SmolInstant::now();
        let result = iface.poll(timestamp, &mut device, &mut sockets);
        device.flush_tx();

        if matches!(result, PollResult::SocketStateChanged) {
            // Check for new connections on port 80
            check_accept(&mut sockets, http_handle, 80, false, &mut connections);
            // Check for new connections on port 443
            check_accept(&mut sockets, https_handle, 443, true, &mut connections);

            // Process active connections
            let mut done_ports: Vec<u16> = Vec::new();
            for (&port, conn) in connections.iter_mut() {
                process_connection(&mut sockets, conn, ca);
                if conn.state == ConnState::Done {
                    done_ports.push(port);
                }
            }

            for port in done_ports {
                connections.remove(&port);
            }
        }

        // Check if guest is done (both listener sockets idle, no active connections)
        // For the spike, just rely on the timeout

        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

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
        let remote = sock.remote_endpoint();
        println!(
            "[host] new connection on :{port} from {:?}",
            remote
        );

        // We can't easily move the accepted socket out of smoltcp's listener model.
        // Instead, track it by the listen handle itself.
        // smoltcp doesn't have accept() -- the listening socket becomes the connected socket.
        // To handle multiple connections we'd need to re-create the listener.
        // For this spike, handle one connection at a time per port.

        connections.insert(
            port,
            ProxyConn {
                handle: listen_handle,
                upstream: None,
                upstream_tls: None,
                guest_tls: None,
                dst: (Ipv4Address::UNSPECIFIED, port),
                sni: None,
                is_tls,
                pending_guest_data: Vec::new(),
                state: ConnState::WaitingForData,
            },
        );
    }
}

fn process_connection(sockets: &mut SocketSet, conn: &mut ProxyConn, ca: &MitmCa) {
    let sock = sockets.get_mut::<tcp::Socket>(conn.handle);

    match conn.state {
        ConnState::WaitingForData => {
            if !sock.may_recv() {
                return;
            }
            // Read data from guest
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
                // Try to extract SNI from ClientHello
                if let Some(sni) = extract_sni(&conn.pending_guest_data) {
                    println!("[host] TLS SNI: {sni}");
                    conn.sni = Some(sni.clone());

                    // Set up guest-facing TLS (we are the server)
                    let server_config = ca.server_config_for(&sni);
                    let server_conn =
                        rustls::ServerConnection::new(server_config).expect("server TLS failed");
                    conn.guest_tls = Some(server_conn);

                    // Connect upstream
                    match connect_upstream(&sni, 443) {
                        Ok((stream, tls_conn)) => {
                            conn.upstream = Some(stream);
                            conn.upstream_tls = Some(tls_conn);
                            conn.state = ConnState::TlsHandshake;
                        }
                        Err(e) => {
                            println!("[host] upstream connect failed: {e}");
                            sock.close();
                            conn.state = ConnState::Done;
                            return;
                        }
                    }

                    // Feed the ClientHello data to our server TLS
                    let guest_tls = conn.guest_tls.as_mut().unwrap();
                    let mut cursor = &conn.pending_guest_data[..];
                    if let Err(e) = guest_tls.read_tls(&mut cursor) {
                        println!("[host] guest TLS read error: {e}");
                    }
                    conn.pending_guest_data.clear();

                    // Process the TLS state machine
                    if let Err(e) = guest_tls.process_new_packets() {
                        println!("[host] guest TLS process error: {e}");
                    }

                    // Write TLS response (ServerHello etc) back to guest
                    let mut out = Vec::new();
                    if let Ok(n) = guest_tls.write_tls(&mut out) {
                        if n > 0 {
                            sock.send_slice(&out).ok();
                        }
                    }
                }
            } else {
                // Plain HTTP -- parse the request
                let request = String::from_utf8_lossy(&conn.pending_guest_data);
                println!("[host] HTTP request:");
                for line in request.lines().take(5) {
                    println!("[host]   {line}");
                }

                // For the spike, just respond directly
                let response =
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nREDAN_HTTP_INTERCEPT_OK\n";
                sock.send_slice(response.as_bytes()).ok();
                sock.close();
                conn.pending_guest_data.clear();
                conn.state = ConnState::Done;
            }
        }

        ConnState::TlsHandshake | ConnState::Proxying => {
            let guest_tls = match conn.guest_tls.as_mut() {
                Some(t) => t,
                None => {
                    conn.state = ConnState::Done;
                    return;
                }
            };

            // Read encrypted data from guest
            let mut buf = vec![0u8; 16384];
            let guest_bytes = sock.recv_slice(&mut buf).unwrap_or(0);
            if guest_bytes > 0 {
                let mut cursor = &buf[..guest_bytes];
                guest_tls.read_tls(&mut cursor).ok();
                match guest_tls.process_new_packets() {
                    Ok(_) => {}
                    Err(e) => {
                        println!("[host] guest TLS error: {e}");
                        sock.close();
                        conn.state = ConnState::Done;
                        return;
                    }
                }
            }

            // Read decrypted plaintext from guest TLS
            let mut plaintext = vec![0u8; 16384];
            let pt_bytes = match guest_tls.reader().read(&mut plaintext) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
                Err(_) => 0,
            };

            if pt_bytes > 0 && conn.state == ConnState::TlsHandshake {
                conn.state = ConnState::Proxying;
            }

            if pt_bytes > 0 {
                let text = String::from_utf8_lossy(&plaintext[..pt_bytes]);
                println!("[host] DECRYPTED from guest ({pt_bytes} bytes):");
                for line in text.lines().take(5) {
                    println!("[host]   {line}");
                }

                // Forward to upstream via a blocking helper.
                // This is fine for a spike (one request at a time).
                if let (Some(stream), Some(tls)) =
                    (conn.upstream.as_mut(), conn.upstream_tls.as_mut())
                {
                    match relay_upstream(stream, tls, &plaintext[..pt_bytes]) {
                        Ok(response) => {
                            let resp_text = String::from_utf8_lossy(&response);
                            println!("[host] upstream response ({} bytes):", response.len());
                            for line in resp_text.lines().take(3) {
                                println!("[host]   {line}");
                            }

                            // Send back to guest through our server TLS
                            guest_tls.writer().write_all(&response).ok();
                            let mut guest_out = Vec::new();
                            guest_tls.write_tls(&mut guest_out).ok();
                            sock.send_slice(&guest_out).ok();
                        }
                        Err(e) => {
                            println!("[host] upstream relay error: {e}");
                        }
                    }
                }

                sock.close();
                conn.state = ConnState::Done;
            }

            // Flush any pending TLS data back to guest
            let mut out = Vec::new();
            if let Ok(n) = guest_tls.write_tls(&mut out) {
                if n > 0 {
                    sock.send_slice(&out).ok();
                }
            }

            // Check if socket is closed
            if !sock.is_active() {
                conn.state = ConnState::Done;
            }
        }

        ConnState::Done => {}
    }
}

/// Extract SNI from a TLS ClientHello message.
fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record: type(1) + version(2) + length(2) + handshake
    if data.len() < 5 || data[0] != 0x16 {
        return None; // Not a TLS handshake
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None; // Incomplete
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
                // SNI list length(2) + type(1) + name length(2) + name
                let name_len =
                    u16::from_be_bytes([hs[pos + 3], hs[pos + 4]]) as usize;
                if pos + 5 + name_len <= hs.len() {
                    return String::from_utf8(hs[pos + 5..pos + 5 + name_len].to_vec()).ok();
                }
            }
        }

        pos += ext_data_len;
    }

    None
}

/// Complete a TLS handshake, send request, read full response.
fn relay_upstream(
    stream: &mut TcpStream,
    tls: &mut rustls::ClientConnection,
    request: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;

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

    // Send the HTTP request
    tls.writer().write_all(request)?;
    tls.write_tls(stream)?;
    stream.flush()?;

    // Read the full response
    let mut response = Vec::new();
    loop {
        // Read encrypted data from upstream
        match tls.read_tls(stream) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e.into()),
        }

        let state = tls.process_new_packets()?;

        // Read decrypted plaintext
        let mut buf = vec![0u8; 16384];
        match tls.reader().read(&mut buf) {
            Ok(n) if n > 0 => response.extend_from_slice(&buf[..n]),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }

        // If the peer sent close_notify, we're done
        if state.peer_has_closed() {
            // Drain any remaining plaintext
            loop {
                match tls.reader().read(&mut buf) {
                    Ok(n) if n > 0 => response.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            }
            break;
        }

        // Simple heuristic: if we have data and it looks like a complete HTTP response
        // (has headers + body based on Content-Length or chunked), stop.
        if response.len() > 100 {
            let resp_str = String::from_utf8_lossy(&response);
            if resp_str.contains("\r\n\r\n") {
                // Check if we have Content-Length and got all the body
                if let Some(cl_line) = resp_str.lines().find(|l| l.to_lowercase().starts_with("content-length:")) {
                    if let Ok(cl) = cl_line.split(':').nth(1).unwrap_or("0").trim().parse::<usize>() {
                        if let Some(body_start) = resp_str.find("\r\n\r\n") {
                            let body_len = response.len() - body_start - 4;
                            if body_len >= cl {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(response)
}

/// Connect to an upstream server over TLS.
fn connect_upstream(
    hostname: &str,
    port: u16,
) -> Result<(TcpStream, rustls::ClientConnection), Box<dyn std::error::Error>> {
    // DNS resolve on host
    use std::net::ToSocketAddrs;
    let addr = format!("{hostname}:{port}")
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .ok_or("DNS resolution failed")?;

    let stream = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10))?;
    stream.set_nonblocking(false)?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = hostname.to_owned().try_into()?;
    let tls_conn = rustls::ClientConnection::new(std::sync::Arc::new(tls_config), server_name)?;

    Ok((stream, tls_conn))
}
