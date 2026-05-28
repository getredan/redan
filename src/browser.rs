//! Headless Chrome lifecycle and CDP allowlist proxy.
//!
//! Chrome runs on the host (not in the VM). The agent in the VM connects
//! to Chrome via CDP port forwarding. To prevent CDP from becoming a
//! network escape hatch, redan launches Chrome with `--proxy-server`
//! pointing to a lightweight HTTP CONNECT proxy that enforces the same
//! host allowlist as the main MITM proxy.
//!
//! SECURITY: Chrome's sandbox MUST stay enabled. The VM isolates the
//! agent, but Chrome runs on the host.

use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::proxy::host_matches;
use crate::tls::is_private_ip;

pub const CDP_PORT: u16 = 9222;

const CHROME_CANDIDATES: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome-stable",
    "google-chrome",
];

/// Find a Chrome/Chromium binary on PATH.
pub fn find_chrome() -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for candidate in CHROME_CANDIDATES {
        for dir in path_var.split(':') {
            let full = PathBuf::from(dir).join(candidate);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

pub struct BrowserConfig {
    pub allowed_hosts: Option<Vec<String>>,
}

pub struct Browser {
    child: std::process::Child,
    profile_dir: PathBuf,
    proxy_shutdown: Arc<AtomicBool>,
    proxy_thread: Option<JoinHandle<()>>,
    proxy_port: u16,
}

impl Browser {
    pub fn launch(config: BrowserConfig) -> Result<Self, String> {
        let chrome = find_chrome()
            .ok_or("no Chrome/Chromium binary found on PATH. Install chromium or google-chrome.")?;

        // Check CDP port is free (bind and immediately drop)
        TcpListener::bind(("127.0.0.1", CDP_PORT)).map_err(|_| {
            format!("port {CDP_PORT} is already in use. Stop the existing Chrome/CDP process.")
        })?;

        // Random profile directory
        let mut rng_buf = [0u8; 4];
        getrandom::fill(&mut rng_buf)
            .map_err(|e| format!("failed to generate random bytes: {e}"))?;
        let hex = rng_buf.map(|b| format!("{b:02x}")).join("");
        let profile_dir = std::env::temp_dir().join(format!("redan-chrome-{hex}"));
        std::fs::create_dir_all(&profile_dir)
            .map_err(|e| format!("failed to create profile dir: {e}"))?;

        // Bind the allowlist proxy
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("failed to bind allowlist proxy: {e}"))?;
        let proxy_port = listener
            .local_addr()
            .map_err(|e| format!("failed to get proxy address: {e}"))?
            .port();

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let allowed_hosts: Option<Arc<[String]>> = config.allowed_hosts.map(Into::into);

        listener
            .set_nonblocking(true)
            .map_err(|e| format!("failed to set listener non-blocking: {e}"))?;

        let proxy_thread = std::thread::Builder::new()
            .name("browser-proxy".into())
            .spawn(move || run_allowlist_proxy(listener, allowed_hosts, shutdown_clone))
            .map_err(|e| format!("failed to spawn proxy thread: {e}"))?;

        let mut child = std::process::Command::new(&chrome)
            .args([
                "--headless=new",
                &format!("--remote-debugging-port={CDP_PORT}"),
                "--remote-debugging-address=127.0.0.1",
                &format!("--user-data-dir={}", profile_dir.display()),
                "--no-first-run",
                "--disable-extensions",
                "--disable-sync",
                "--disable-background-networking",
                &format!("--proxy-server=http://127.0.0.1:{proxy_port}"),
                "--proxy-bypass-list=<-loopback>",
                "about:blank",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to launch Chrome at {}: {e}", chrome.display()))?;

        if !poll_cdp_ready(10) {
            if let Some(status) = child.try_wait().ok().flatten() {
                let mut stderr_buf = String::new();
                if let Some(ref mut pipe) = child.stderr {
                    let _ = pipe.read_to_string(&mut stderr_buf);
                }
                shutdown.store(true, Ordering::Relaxed);
                let _ = std::fs::remove_dir_all(&profile_dir);
                return Err(if stderr_buf.is_empty() {
                    format!("Chrome exited with {status} before CDP was ready")
                } else {
                    format!("Chrome exited with {status}: {}", stderr_buf.trim())
                });
            }
            shutdown.store(true, Ordering::Relaxed);
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&profile_dir);
            return Err("Chrome started but CDP endpoint did not respond within 10s".into());
        }

        log::info!("Chrome launched (pid {}, proxy :{proxy_port})", child.id());

        Ok(Self {
            child,
            profile_dir,
            proxy_shutdown: shutdown,
            proxy_thread: Some(proxy_thread),
            proxy_port,
        })
    }

    pub const fn proxy_port(&self) -> u16 {
        self.proxy_port
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        self.proxy_shutdown.store(true, Ordering::Relaxed);

        let pid = self.child.id();
        unsafe {
            libc::kill(pid.cast_signed(), libc::SIGTERM);
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if self.child.try_wait().ok().flatten().is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        if let Some(t) = self.proxy_thread.take() {
            let _ = t.join();
        }

        let _ = std::fs::remove_dir_all(&self.profile_dir);
        log::info!("Chrome stopped and profile cleaned up");
    }
}

fn poll_cdp_ready(timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    let url = format!("http://127.0.0.1:{CDP_PORT}/json/version");

    while std::time::Instant::now() < deadline {
        if let Ok(mut resp) = ureq::get(&url).call()
            && resp.status() == 200
        {
            let _ = resp.body_mut().read_to_string();
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

// ---------------------------------------------------------------------------
// Allowlist proxy
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_value)] // Owned values needed: moved into thread
fn run_allowlist_proxy(
    listener: TcpListener,
    allowed_hosts: Option<Arc<[String]>>,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let hosts = allowed_hosts.clone();
                let _ = std::thread::Builder::new()
                    .name("browser-proxy-conn".into())
                    .spawn(move || handle_proxy_connection(stream, hosts.as_deref()));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
}

fn handle_proxy_connection(mut client: TcpStream, allowed_hosts: Option<&[String]>) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));

    let mut buf = [0u8; 8192];
    let mut filled = 0;

    loop {
        if filled >= buf.len() {
            let _ = client.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n");
            return;
        }
        match client.read(&mut buf[filled..]) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                filled += n;
                if crate::secret::find_header_end(&buf[..filled]).is_some() {
                    break;
                }
            }
        }
    }

    let line_end = buf[..filled]
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(filled);

    let Ok(request_line) = std::str::from_utf8(&buf[..line_end]) else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };

    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(client, target, allowed_hosts);
    } else {
        handle_forward_http(client, &buf[..filled], method, target, allowed_hosts);
    }
}

fn handle_connect(mut client: TcpStream, target: &str, allowed_hosts: Option<&[String]>) {
    let Some((host, port)) = parse_connect_target(target) else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };

    if !is_host_allowed(host, allowed_hosts) {
        log::info!("browser proxy: blocked CONNECT to {host}:{port} (not in allowlist)");
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
        return;
    }

    let upstream = match resolve_and_connect(host, port) {
        Ok(s) => s,
        Err(msg) => {
            log::warn!("browser proxy: {msg}");
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };

    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }

    relay_bidirectional(client, upstream);
}

fn handle_forward_http(
    mut client: TcpStream,
    header_data: &[u8],
    method: &str,
    target: &str,
    allowed_hosts: Option<&[String]>,
) {
    let Some((host, port, path)) = parse_absolute_uri(target) else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };

    if !is_host_allowed(&host, allowed_hosts) {
        log::info!("browser proxy: blocked HTTP {method} to {host} (not in allowlist)");
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
        return;
    }

    let mut upstream = match resolve_and_connect(&host, port) {
        Ok(s) => s,
        Err(msg) => {
            log::warn!("browser proxy: {msg}");
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };

    // Rewrite the request line to use the relative path
    let line_end = header_data
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(header_data.len());

    let version_str = std::str::from_utf8(&header_data[..line_end])
        .ok()
        .and_then(|line| line.rsplit(' ').next())
        .unwrap_or("HTTP/1.1");

    let rewritten_line = format!("{method} {path} {version_str}\r\n");
    if upstream.write_all(rewritten_line.as_bytes()).is_err() {
        return;
    }

    // Forward remaining headers (everything after the first line)
    let after_first_line = line_end + 2; // skip past \r\n
    if after_first_line < header_data.len()
        && upstream
            .write_all(&header_data[after_first_line..])
            .is_err()
    {
        return;
    }

    // Relay remaining body + response
    relay_bidirectional(client, upstream);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_host_allowed(host: &str, allowed_hosts: Option<&[String]>) -> bool {
    let Some(hosts) = allowed_hosts else {
        return true;
    };
    hosts.iter().any(|pattern| host_matches(pattern, host))
}

/// Resolve a hostname to IPv4 addresses, check for SSRF, and connect.
/// Only uses IPv4 to match the main proxy's behavior.
fn resolve_and_connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddrV4> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?
        .filter_map(|addr| match addr {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
        .collect();

    if addrs.is_empty() {
        return Err(format!("no IPv4 addresses found for {host}"));
    }

    for addr in &addrs {
        if is_private_ip(*addr.ip()) {
            return Err(format!(
                "{host} resolves to private IP {addr} (SSRF blocked)"
            ));
        }
    }

    let sock_addrs: Vec<SocketAddr> = addrs.into_iter().map(SocketAddr::V4).collect();
    TcpStream::connect(&sock_addrs[..])
        .map_err(|e| format!("connection to {host}:{port} failed: {e}"))
}

fn relay_bidirectional(a: TcpStream, b: TcpStream) {
    let Ok(a_clone) = a.try_clone() else { return };
    let Ok(b_clone) = b.try_clone() else { return };

    // a -> b (spawned thread)
    let t = std::thread::spawn(move || {
        let mut reader = a_clone;
        let mut writer = b_clone;
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if writer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = writer.shutdown(std::net::Shutdown::Write);
    });

    // b -> a (this thread)
    let mut reader = b;
    let mut writer = a;
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if writer.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = writer.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
}

fn parse_connect_target(target: &str) -> Option<(&str, u16)> {
    let (host, port_str) = target.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let port: u16 = port_str.parse().ok()?;
    Some((host, port))
}

fn parse_absolute_uri(uri: &str) -> Option<(String, u16, String)> {
    let rest = uri.strip_prefix("http://")?;
    let (authority, path) = rest
        .split_once('/')
        .map_or_else(|| (rest, "/".to_string()), |(a, p)| (a, format!("/{p}")));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (authority, 80),
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port, path))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // -- parse_connect_target -------------------------------------------------

    #[test]
    fn parse_connect_target_valid() {
        assert_eq!(
            parse_connect_target("example.com:443"),
            Some(("example.com", 443))
        );
    }

    #[test]
    fn parse_connect_target_custom_port() {
        assert_eq!(
            parse_connect_target("cdn.example.com:8443"),
            Some(("cdn.example.com", 8443))
        );
    }

    #[test]
    fn parse_connect_target_no_port() {
        assert_eq!(parse_connect_target("example.com"), None);
    }

    #[test]
    fn parse_connect_target_empty_host() {
        assert_eq!(parse_connect_target(":443"), None);
    }

    #[test]
    fn parse_connect_target_invalid_port() {
        assert_eq!(parse_connect_target("example.com:notaport"), None);
    }

    #[test]
    fn parse_connect_target_port_overflow() {
        assert_eq!(parse_connect_target("example.com:99999"), None);
    }

    // -- parse_absolute_uri ---------------------------------------------------

    #[test]
    fn parse_absolute_uri_with_port() {
        let (host, port, path) = parse_absolute_uri("http://example.com:8080/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/path");
    }

    #[test]
    fn parse_absolute_uri_default_port() {
        let (host, port, path) = parse_absolute_uri("http://example.com/index.html").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/index.html");
    }

    #[test]
    fn parse_absolute_uri_no_path() {
        let (host, port, path) = parse_absolute_uri("http://example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_absolute_uri_rejects_https() {
        assert!(parse_absolute_uri("https://example.com/path").is_none());
    }

    #[test]
    fn parse_absolute_uri_rejects_relative() {
        assert!(parse_absolute_uri("/just/a/path").is_none());
    }

    // -- is_host_allowed ------------------------------------------------------

    #[test]
    fn host_allowed_when_no_restriction() {
        assert!(is_host_allowed("anything.com", None));
    }

    #[test]
    fn host_allowed_when_in_list() {
        let hosts = vec!["api.example.com".into(), "cdn.example.com".into()];
        assert!(is_host_allowed("api.example.com", Some(&hosts)));
    }

    #[test]
    fn host_blocked_when_not_in_list() {
        let hosts = vec!["api.example.com".into()];
        assert!(!is_host_allowed("evil.com", Some(&hosts)));
    }

    #[test]
    fn host_allowed_with_wildcard_pattern() {
        let hosts = vec!["*.example.com".into()];
        assert!(is_host_allowed("api.example.com", Some(&hosts)));
        assert!(!is_host_allowed("example.com", Some(&hosts)));
    }

    #[test]
    fn host_blocked_when_list_empty() {
        let hosts: Vec<String> = vec![];
        assert!(!is_host_allowed("anything.com", Some(&hosts)));
    }

    // -- find_chrome ----------------------------------------------------------

    #[test]
    fn find_chrome_empty_path_returns_none() {
        let original = std::env::var("PATH").ok();
        unsafe { std::env::set_var("PATH", "") };
        let result = find_chrome();
        if let Some(p) = original {
            unsafe { std::env::set_var("PATH", p) };
        }
        assert!(result.is_none());
    }

    // -- allowlist proxy integration ------------------------------------------

    #[test]
    fn proxy_blocks_non_allowlisted_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = listener.local_addr().unwrap().port();

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let hosts: Option<Arc<[String]>> = Some(vec!["allowed.example.com".into()].into());

        listener.set_nonblocking(true).unwrap();
        let proxy = std::thread::spawn(move || {
            run_allowlist_proxy(listener, hosts, shutdown_clone);
        });

        // Give the proxy a moment to start
        std::thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client
            .write_all(b"CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com:443\r\n\r\n")
            .unwrap();

        let mut response = vec![0u8; 4096];
        let n = client.read(&mut response).unwrap();
        let response_str = std::str::from_utf8(&response[..n]).unwrap();

        assert!(
            response_str.contains("403"),
            "expected 403 for blocked host, got: {response_str}"
        );

        shutdown.store(true, Ordering::Relaxed);
        let _ = proxy.join();
    }

    #[test]
    fn proxy_blocks_forward_http_non_allowlisted() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = listener.local_addr().unwrap().port();

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let hosts: Option<Arc<[String]>> = Some(vec!["allowed.example.com".into()].into());

        listener.set_nonblocking(true).unwrap();
        let proxy = std::thread::spawn(move || {
            run_allowlist_proxy(listener, hosts, shutdown_clone);
        });

        std::thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client
            .write_all(b"GET http://blocked.example.com/path HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n")
            .unwrap();

        let mut response = vec![0u8; 4096];
        let n = client.read(&mut response).unwrap();
        let response_str = std::str::from_utf8(&response[..n]).unwrap();

        assert!(
            response_str.contains("403"),
            "expected 403 for blocked host, got: {response_str}"
        );

        shutdown.store(true, Ordering::Relaxed);
        let _ = proxy.join();
    }

    #[test]
    fn proxy_connect_ssrf_blocks_private_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = listener.local_addr().unwrap().port();

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        listener.set_nonblocking(true).unwrap();
        // allow-all mode (None), but SSRF check should still block localhost
        let proxy = std::thread::spawn(move || {
            run_allowlist_proxy(listener, None, shutdown_clone);
        });

        std::thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n")
            .unwrap();

        let mut response = vec![0u8; 4096];
        let n = client.read(&mut response).unwrap();
        let response_str = std::str::from_utf8(&response[..n]).unwrap();

        assert!(
            response_str.contains("502"),
            "expected 502 for SSRF-blocked IP, got: {response_str}"
        );

        shutdown.store(true, Ordering::Relaxed);
        let _ = proxy.join();
    }
}
