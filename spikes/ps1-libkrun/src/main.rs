mod ffi;

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let test = args.get(1).map(|s| s.as_str()).unwrap_or("boot");

    match test {
        "boot" => test_boot(),
        "network" => test_network(),
        "intercept" => test_intercept(),
        _ => {
            eprintln!("Usage: ps1-libkrun [boot|network|intercept]");
            std::process::exit(1);
        }
    }
}

/// Run a shell command inside the VM using TSI networking.
fn run_guest_cmd(cmd: &str) -> i32 {
    let ret = unsafe {
        ffi::krun_init_log(
            ffi::KRUN_LOG_TARGET_DEFAULT,
            ffi::KRUN_LOG_LEVEL_ERROR,
            ffi::KRUN_LOG_STYLE_AUTO,
            0,
        )
    };
    assert!(ret >= 0, "krun_init_log failed: {ret}");

    let ctx_id = unsafe { ffi::krun_create_ctx() };
    assert!(ctx_id >= 0, "krun_create_ctx failed: {ctx_id}");
    let ctx_id = ctx_id as u32;

    let ret = unsafe { ffi::krun_set_vm_config(ctx_id, 1, 256) };
    assert!(ret >= 0, "krun_set_vm_config failed: {ret}");

    let root = CString::new("/tmp/redan-rootfs").unwrap();
    let ret = unsafe { ffi::krun_set_root(ctx_id, root.as_ptr()) };
    assert!(ret >= 0, "krun_set_root failed: {ret}");

    let workdir = CString::new("/").unwrap();
    let ret = unsafe { ffi::krun_set_workdir(ctx_id, workdir.as_ptr()) };
    assert!(ret >= 0, "krun_set_workdir failed: {ret}");

    let exec_path = CString::new("/bin/busybox").unwrap();
    let arg0 = CString::new("ash").unwrap();
    let arg1 = CString::new("-c").unwrap();
    let arg2 = CString::new(cmd).unwrap();
    let argv: Vec<*const i8> = vec![
        arg0.as_ptr(),
        arg1.as_ptr(),
        arg2.as_ptr(),
        std::ptr::null(),
    ];

    let path =
        CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin").unwrap();
    let term = CString::new("TERM=xterm").unwrap();
    let envp: Vec<*const i8> = vec![path.as_ptr(), term.as_ptr(), std::ptr::null()];

    let ret = unsafe {
        ffi::krun_set_exec(ctx_id, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr())
    };
    assert!(ret >= 0, "krun_set_exec failed: {ret}");

    unsafe { ffi::krun_start_enter(ctx_id) }
}

fn test_boot() {
    println!("PS-1: boot test");
    let start = Instant::now();
    let exit_code = run_guest_cmd("echo REDAN_BOOT_OK; uname -a; cat /etc/alpine-release");
    let elapsed = start.elapsed();
    println!("---");
    println!("exit code: {exit_code}");
    println!("total time: {elapsed:?}");
}

fn test_network() {
    println!("PS-1: TSI network test");
    let exit_code = run_guest_cmd(
        "echo NET_INTERFACES; ip addr 2>/dev/null; \
         echo DNS_TEST; nslookup api.github.com 2>/dev/null; \
         echo HTTPS_TEST; wget -q -O - https://api.github.com/ 2>/dev/null; \
         echo DONE",
    );
    println!("---");
    println!("exit code: {exit_code}");
}

/// The interesting one: libkrun VM with virtio-net connected to smoltcp.
/// We intercept all guest network traffic.
fn test_intercept() {
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
    use smoltcp::socket::tcp;
    use smoltcp::time::Instant as SmolInstant;
    use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Address};

    println!("PS-1: smoltcp intercept test");
    println!("============================");

    // Create unix socket pair. One end goes to libkrun, the other to smoltcp.
    let (host_sock, guest_sock) = UnixStream::pair().expect("socketpair failed");
    host_sock.set_nonblocking(true).unwrap();
    // guest_sock stays blocking - libkrun manages it internally.

    let guest_fd = guest_sock.as_raw_fd();

    // Spawn VM in a thread (krun_start_enter blocks)
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

        let ret = unsafe { ffi::krun_set_vm_config(ctx_id, 1, 256) };
        assert!(ret >= 0);

        let root = CString::new("/tmp/redan-rootfs").unwrap();
        let ret = unsafe { ffi::krun_set_root(ctx_id, root.as_ptr()) };
        assert!(ret >= 0);

        let workdir = CString::new("/").unwrap();
        let ret = unsafe { ffi::krun_set_workdir(ctx_id, workdir.as_ptr()) };
        assert!(ret >= 0);

        // Add virtio-net connected to our unix socket (disables TSI)
        let mac: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ret = unsafe {
            ffi::krun_add_net_unixstream(
                ctx_id,
                std::ptr::null(), // no path, use fd
                guest_fd,
                mac.as_ptr(),
                0, // features
                0, // flags
            )
        };
        assert!(ret >= 0, "krun_add_net_unixstream failed: {ret}");

        // Guest configures static IP, then talks to our smoltcp gateway
        let exec_path = CString::new("/bin/busybox").unwrap();
        let arg0 = CString::new("ash").unwrap();
        let arg1 = CString::new("-c").unwrap();
        let arg2 = CString::new(
            "ip link set eth0 up; \
             ip addr add 192.168.127.2/24 dev eth0; \
             ip route add default via 192.168.127.1; \
             echo NET_CONFIGURED; ip addr show eth0; \
             echo TRYING_HTTP; wget -q -O - http://192.168.127.1:8080/ 2>/dev/null; \
             echo GUEST_DONE",
        )
        .unwrap();
        let argv: Vec<*const i8> = vec![
            arg0.as_ptr(),
            arg1.as_ptr(),
            arg2.as_ptr(),
            std::ptr::null(),
        ];

        let path = CString::new(
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .unwrap();
        let term = CString::new("TERM=xterm").unwrap();
        let envp: Vec<*const i8> = vec![path.as_ptr(), term.as_ptr(), std::ptr::null()];

        let ret = unsafe {
            ffi::krun_set_exec(ctx_id, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        };
        assert!(ret >= 0);

        // Forget guest_sock so the fd isn't closed when guest_sock drops.
        // libkrun now owns this fd.
        std::mem::forget(guest_sock);

        println!("[vm] entering VM...");
        let exit_code = unsafe { ffi::krun_start_enter(ctx_id) };
        println!("[vm] exit code: {exit_code}");
        exit_code
    });

    // Host side: smoltcp network stack reading/writing Ethernet frames
    // from the unix socket.
    //
    // libkrun sends/receives raw Ethernet frames prefixed with a 4-byte
    // big-endian length (same as QEMU stream netdev protocol).

    struct VirtioNetDevice {
        sock: UnixStream,
        rx_buf: Vec<u8>,
        tx_buf: Vec<u8>,
    }

    impl VirtioNetDevice {
        fn new(sock: UnixStream) -> Self {
            Self {
                sock,
                rx_buf: vec![0u8; 65536],
                tx_buf: vec![0u8; 65536],
            }
        }

        /// Try to read one length-prefixed frame from the socket.
        fn try_recv_frame(&mut self) -> Option<Vec<u8>> {
            let mut len_buf = [0u8; 4];
            match self.sock.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return None,
                Err(e) => {
                    eprintln!("[net] recv error: {e}");
                    return None;
                }
            }
            let frame_len = u32::from_be_bytes(len_buf) as usize;
            if frame_len > self.rx_buf.len() {
                eprintln!("[net] frame too large: {frame_len}");
                return None;
            }
            // We got the length prefix, now we MUST read the full frame.
            // Temporarily set blocking for the frame body.
            self.sock.set_nonblocking(false).ok();
            let result = self.sock.read_exact(&mut self.rx_buf[..frame_len]);
            self.sock.set_nonblocking(true).ok();
            match result {
                Ok(()) => Some(self.rx_buf[..frame_len].to_vec()),
                Err(e) => {
                    eprintln!("[net] frame read error: {e}");
                    None
                }
            }
        }

        fn send_frame(&mut self, frame: &[u8]) {
            let len_buf = (frame.len() as u32).to_be_bytes();
            if let Err(e) = self.sock.write_all(&len_buf) {
                eprintln!("[net] send len error: {e}");
                return;
            }
            if let Err(e) = self.sock.write_all(frame) {
                eprintln!("[net] send frame error: {e}");
            }
        }
    }

    // smoltcp Device: reads/writes length-prefixed Ethernet frames from unix socket.
    // Uses a VecDeque for pending TX so RxToken and TxToken don't alias.
    struct SmolDevice {
        inner: VirtioNetDevice,
        pending_rx: Option<Vec<u8>>,
        pending_tx: std::collections::VecDeque<Vec<u8>>,
    }

    impl SmolDevice {
        fn new(dev: VirtioNetDevice) -> Self {
            Self {
                inner: dev,
                pending_rx: None,
                pending_tx: std::collections::VecDeque::new(),
            }
        }

        fn flush_tx(&mut self) {
            while let Some(frame) = self.pending_tx.pop_front() {
                self.inner.send_frame(&frame);
            }
        }
    }

    impl Device for SmolDevice {
        type RxToken<'a> = SmolRxToken;
        type TxToken<'a> = SmolTxToken<'a>;

        fn receive(
            &mut self,
            _timestamp: SmolInstant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            if self.pending_rx.is_none() {
                self.pending_rx = self.inner.try_recv_frame();
            }
            let frame = self.pending_rx.take()?;
            Some((
                SmolRxToken { frame },
                SmolTxToken {
                    queue: &mut self.pending_tx,
                },
            ))
        }

        fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
            Some(SmolTxToken {
                queue: &mut self.pending_tx,
            })
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.max_transmission_unit = 1500;
            caps.max_burst_size = Some(1);
            caps.medium = Medium::Ethernet;
            caps
        }
    }

    struct SmolRxToken {
        frame: Vec<u8>,
    }

    impl RxToken for SmolRxToken {
        fn consume<R, F>(self, f: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            f(&self.frame)
        }
    }

    struct SmolTxToken<'a> {
        queue: &'a mut std::collections::VecDeque<Vec<u8>>,
    }

    impl<'a> TxToken for SmolTxToken<'a> {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            let mut buf = vec![0u8; len];
            let result = f(&mut buf);
            self.queue.push_back(buf);
            result
        }
    }

    // --- Run the smoltcp event loop ---

    let gateway_mac = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let gateway_ip = Ipv4Address::new(192, 168, 127, 1);
    let guest_ip = Ipv4Address::new(192, 168, 127, 2);

    let mut device = SmolDevice::new(VirtioNetDevice::new(host_sock));

    let config = Config::new(gateway_mac.into());
    let mut iface = Interface::new(config, &mut device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(gateway_ip.into(), 24)).unwrap();
    });

    // Create a TCP socket to listen on port 8080 (our test endpoint)
    let tcp_rx_buf = tcp::SocketBuffer::new(vec![0; 4096]);
    let tcp_tx_buf = tcp::SocketBuffer::new(vec![0; 4096]);
    let tcp_socket = tcp::Socket::new(tcp_rx_buf, tcp_tx_buf);

    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);

    // Listen on port 8080
    {
        let sock = sockets.get_mut::<tcp::Socket>(tcp_handle);
        sock.listen(8080).unwrap();
    }

    println!("[host] smoltcp gateway at {gateway_ip}, listening on :8080");
    println!("[host] waiting for guest traffic...");

    let start = Instant::now();
    let timeout = std::time::Duration::from_secs(30);

    loop {
        if start.elapsed() > timeout {
            println!("[host] timeout reached");
            break;
        }

        let timestamp = SmolInstant::now();
        let result = iface.poll(timestamp, &mut device, &mut sockets);
        device.flush_tx();

        if matches!(result, smoltcp::iface::PollResult::SocketStateChanged) {
            let sock = sockets.get_mut::<tcp::Socket>(tcp_handle);

            if sock.may_recv() {
                let data = sock
                    .recv(|buf| {
                        let len = buf.len();
                        let text = String::from_utf8_lossy(buf);
                        if !text.is_empty() {
                            println!("[host] INTERCEPTED {} bytes:", len);
                            for line in text.lines().take(5) {
                                println!("[host]   {line}");
                            }
                        }
                        (len, ())
                    })
                    .ok();
                let _ = data;

                // Send a response
                if sock.can_send() {
                    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nREDAN_INTERCEPT_OK\n";
                    sock.send_slice(response.as_bytes()).ok();
                    sock.close();
                    println!("[host] sent response, closing");

                    // Give time for the response to be delivered
                    let flush_start = Instant::now();
                    while flush_start.elapsed() < std::time::Duration::from_secs(3) {
                        let ts = SmolInstant::now();
                        iface.poll(ts, &mut device, &mut sockets);
                        device.flush_tx();
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    break;
                }
            }

            // Re-listen if connection closed
            if !sock.is_open() {
                sock.listen(8080).ok();
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    println!("[host] waiting for VM to exit...");
    // VM thread will either finish naturally or we just report and exit
    match vm_thread.join() {
        Ok(code) => println!("[host] VM exited with code {code}"),
        Err(_) => println!("[host] VM thread panicked"),
    }
    println!("DONE");
}
