/// VirtioNet device for smoltcp.
///
/// Reads/writes length-prefixed Ethernet frames over a unix socket
/// connected to libkrun's virtio-net backend. The framing protocol
/// is 4-byte big-endian length prefix before each raw Ethernet frame
/// (same as QEMU's stream netdev).
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

pub struct VirtioNetDevice {
    sock: UnixStream,
    pending_rx: Option<Vec<u8>>,
    pending_tx: VecDeque<Vec<u8>>,
    /// Set when the socket reports an error (peer closed).
    pub peer_closed: bool,
}

impl VirtioNetDevice {
    pub fn new(sock: UnixStream) -> Self {
        sock.set_nonblocking(true).unwrap();
        Self {
            sock,
            pending_rx: None,
            pending_tx: VecDeque::new(),
            peer_closed: false,
        }
    }

    /// Write all pending TX frames to the socket.
    pub fn flush_tx(&mut self) {
        while let Some(frame) = self.pending_tx.pop_front() {
            let len_buf = (frame.len() as u32).to_be_bytes();
            if self.sock.write_all(&len_buf).is_err() {
                break;
            }
            if self.sock.write_all(&frame).is_err() {
                break;
            }
        }
    }

    fn try_recv_frame(&mut self) -> Option<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        match self.sock.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return None,
            Err(e) => {
                // UnexpectedEof = clean close, other errors = peer gone
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::ConnectionReset
                    || e.kind() == std::io::ErrorKind::BrokenPipe
                {
                    self.peer_closed = true;
                }
                return None;
            }
        }
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len > 65536 {
            return None;
        }
        // Got length prefix; must read full frame. Temporarily switch to
        // blocking mode. Safe because libkrun writes length-prefixed
        // frames atomically via the unix socketpair -- if the 4-byte
        // prefix arrived, the frame body is already in the kernel buffer.
        self.sock.set_nonblocking(false).ok();
        let mut buf = vec![0u8; frame_len];
        let result = self.sock.read_exact(&mut buf);
        self.sock.set_nonblocking(true).ok();
        result.ok().map(|_| buf)
    }
}

impl Device for VirtioNetDevice {
    type RxToken<'a> = VirtioRxToken;
    type TxToken<'a> = VirtioTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.pending_rx.is_none() {
            self.pending_rx = self.try_recv_frame();
        }
        let frame = self.pending_rx.take()?;
        Some((
            VirtioRxToken { frame },
            VirtioTxToken {
                queue: &mut self.pending_tx,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken {
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

pub struct VirtioRxToken {
    frame: Vec<u8>,
}

impl RxToken for VirtioRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

pub struct VirtioTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> TxToken for VirtioTxToken<'a> {
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
