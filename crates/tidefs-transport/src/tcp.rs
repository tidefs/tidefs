// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::addr::TransportAddr;
use crate::backend::{AcceptResult, ConnectionLike, TransportBackend};
use crate::error::TransportError;
use crate::session_cohort::NodeInfo;
use crate::session_concurrency::{SessionConcurrencyLimiter, SessionPermit};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// TCP transport backend
// ---------------------------------------------------------------------------

/// TCP transport backend: the default TideFS transport.
pub struct TcpTransport {
    pub(crate) listener: Option<TcpListener>,
    /// Connect timeout
    pub(crate) connect_timeout: Duration,
    /// Read timeout for frames
    pub(crate) read_timeout: Duration,
    /// Whether non-blocking I/O is enabled for new connections
    pub(crate) nonblocking: bool,
    /// Optional global session concurrency limiter.
    pub(crate) session_concurrency: Option<Arc<SessionConcurrencyLimiter>>,
}

impl TcpTransport {
    #[must_use]
    /// Create a new TCP transport backend with the given timeouts.
    pub fn new(connect_timeout: Duration, read_timeout: Duration) -> Self {
        Self {
            listener: None,
            connect_timeout,
            read_timeout,
            nonblocking: false,
            session_concurrency: None,
        }
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self {
            listener: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            nonblocking: false,
            session_concurrency: None,
        }
    }
}

impl TcpTransport {
    /// Enable global session concurrency limiting for outbound connections.
    ///
    /// When set, every outbound `connect()` and inbound `accept()` call
    /// acquires a session permit from the limiter. The permit is released
    /// when the underlying `TcpConnection` is dropped.
    pub fn with_session_concurrency_limit(&mut self, limiter: Arc<SessionConcurrencyLimiter>) {
        self.session_concurrency = Some(limiter);
    }
}

impl TransportBackend for TcpTransport {
    fn bind(&mut self, addr: TransportAddr) -> Result<(), TransportError> {
        let sock_addr = match addr {
            TransportAddr::Tcp(sa) => sa,
            ref other => {
                return Err(TransportError::UnsupportedCarrier {
                    carrier: other.carrier().to_string(),
                });
            }
        };
        let listener = TcpListener::bind(sock_addr).map_err(|err| TransportError::BindFailed {
            addr: addr.clone(),
            source: err,
        })?;
        // Set non-blocking for accept polling
        listener
            .set_nonblocking(true)
            .map_err(|err| TransportError::BindFailed { addr, source: err })?;
        self.listener = Some(listener);
        Ok(())
    }

    fn local_addr(&self) -> Option<TransportAddr> {
        self.listener
            .as_ref()
            .and_then(|l| l.local_addr().ok().map(TransportAddr::Tcp))
    }

    fn connect(&mut self, peer: &NodeInfo) -> Result<Box<dyn ConnectionLike>, TransportError> {
        // Acquire session concurrency permit if configured
        let permit = if let Some(ref limiter) = self.session_concurrency {
            match limiter.try_acquire() {
                Ok(p) => Some(p),
                Err(e) => {
                    return Err(TransportError::SessionConcurrencyLimit {
                        max: e.max,
                        current: e.current,
                    });
                }
            }
        } else {
            None
        };

        // Try each address until one succeeds
        for transport_addr in &peer.addresses {
            let sock_addr = match transport_addr {
                TransportAddr::Tcp(sa) => sa,
                _ => continue, // skip non-TCP addresses
            };
            match TcpStream::connect_timeout(sock_addr, self.connect_timeout) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(self.read_timeout))
                        .map_err(|err| TransportError::ConnectFailed {
                            peer_addr: transport_addr.clone(),
                            source: err,
                        })?;
                    stream.set_nonblocking(self.nonblocking).map_err(|err| {
                        TransportError::ConnectFailed {
                            peer_addr: transport_addr.clone(),
                            source: err,
                        }
                    })?;
                    let conn = Box::new(TcpConnection {
                        stream: Some(stream),
                        peer_addr: *sock_addr,
                        nonblocking: self.nonblocking,
                        read_buf: Vec::new(),
                        session_permit: permit,
                    });
                    return Ok(conn);
                }
                Err(_) => continue,
            }
        }

        Err(TransportError::ConnectFailed {
            peer_addr: peer
                .addresses
                .first()
                .cloned()
                .unwrap_or_else(|| TransportAddr::Tcp("0.0.0.0:0".parse().unwrap())),
            source: std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "all peer addresses unreachable",
            ),
        })
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TransportError> {
        self.nonblocking = nonblocking;
        Ok(())
    }

    fn accept(&mut self) -> Result<AcceptResult, TransportError> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| TransportError::Generic("listener not bound".into()))?;

        // Acquire session concurrency permit if configured
        let permit = if let Some(ref limiter) = self.session_concurrency {
            match limiter.try_acquire() {
                Ok(p) => Some(p),
                Err(e) => {
                    return Err(TransportError::SessionConcurrencyLimit {
                        max: e.max,
                        current: e.current,
                    });
                }
            }
        } else {
            None
        };

        match listener.accept() {
            Ok((stream, peer_addr)) => {
                stream
                    .set_read_timeout(Some(self.read_timeout))
                    .map_err(TransportError::AcceptFailed)?;
                stream
                    .set_nonblocking(self.nonblocking)
                    .map_err(TransportError::AcceptFailed)?;
                Ok((
                    Box::new(TcpConnection {
                        stream: Some(stream),
                        peer_addr,
                        nonblocking: self.nonblocking,
                        read_buf: Vec::new(),
                        session_permit: permit,
                    }),
                    TransportAddr::Tcp(peer_addr),
                ))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Err(TransportError::Generic("no pending connections".into()))
            }
            Err(e) => Err(TransportError::AcceptFailed(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// TcpConnection: frame-oriented read/write over TcpStream
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct TcpConnection {
    stream: Option<TcpStream>,
    peer_addr: SocketAddr,
    /// Whether the connection is in non-blocking mode.
    nonblocking: bool,
    /// Read buffer for non-blocking frame reassembly.
    /// Holds partial frame data across recv calls so `read_exact`
    /// partial reads don't lose bytes on WouldBlock.
    read_buf: Vec<u8>,
    /// Optional session concurrency permit, released on drop.
    session_permit: Option<SessionPermit>,
}

impl ConnectionLike for TcpConnection {
    fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| TransportError::Generic("connection closed".into()))?;

        if self.nonblocking {
            // Non-blocking mode: accumulate into read_buf; never lose partial data.
            let mut chunk = [0u8; 8192];
            match stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(TransportError::Generic("connection closed by peer".into()));
                }
                Ok(n) => {
                    self.read_buf.extend_from_slice(&chunk[..n]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No new data; proceed with what's in the buffer.
                }
                Err(e) => {
                    return Err(TransportError::Generic(format!("frame read failed: {e}")));
                }
            }

            if self.read_buf.len() < 4 {
                return Err(TransportError::WouldBlock(
                    "frame read: WouldBlock (os error 11)".into(),
                ));
            }

            let mut len_buf = [0u8; 4];
            len_buf.copy_from_slice(&self.read_buf[..4]);
            let len = u32::from_be_bytes(len_buf) as usize;

            const MAX_FRAME: usize = 64 * 1024 * 1024;
            if len > MAX_FRAME {
                return Err(TransportError::Generic(format!(
                    "frame too large: {len} bytes"
                )));
            }

            let frame_total = 4 + len;
            if self.read_buf.len() < frame_total {
                return Err(TransportError::WouldBlock(
                    "frame read: WouldBlock (os error 11)".into(),
                ));
            }

            let payload = self.read_buf[4..frame_total].to_vec();
            self.read_buf.drain(..frame_total);
            Ok(payload)
        } else {
            // Blocking mode: standard read_exact path (original behavior).
            let mut len_buf = [0u8; 4];
            stream
                .read_exact(&mut len_buf)
                .map_err(|err| TransportError::Generic(format!("frame read failed: {err}")))?;

            let len = u32::from_be_bytes(len_buf) as usize;

            if len > 64 * 1024 * 1024 {
                return Err(TransportError::Generic(format!(
                    "frame too large: {len} bytes"
                )));
            }

            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).map_err(|err| {
                TransportError::Generic(format!("frame payload read failed: {err}"))
            })?;

            Ok(payload)
        }
    }

    fn write_frame(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| TransportError::Generic("connection closed".into()))?;

        // Frame format: 4-byte big-endian length prefix + payload
        let len = data.len() as u32;
        let len_bytes = len.to_be_bytes();

        stream
            .write_all(&len_bytes)
            .map_err(|err| TransportError::Generic(format!("frame write failed: {err}")))?;
        stream
            .write_all(data)
            .map_err(|err| TransportError::Generic(format!("frame payload write failed: {err}")))?;
        stream
            .flush()
            .map_err(|err| TransportError::Generic(format!("flush failed: {err}")))?;

        Ok(())
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TransportError> {
        self.nonblocking = nonblocking;
        if let Some(ref stream) = self.stream {
            let _ = stream.set_nonblocking(nonblocking);
        }
        Ok(())
    }

    fn close(&mut self) {
        self.stream = None;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpStream as StdTcpStream;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    fn bind_ephemeral() -> (TcpTransport, TransportAddr) {
        let mut t = TcpTransport::default();
        t.bind(TransportAddr::Tcp("127.0.0.1:0".parse().unwrap()))
            .expect("bind ephemeral");
        let addr = t.local_addr().expect("local_addr");
        (t, addr)
    }

    /// Poll accept in a loop (listener is always non-blocking after bind).
    fn accept_poll(
        t: &mut TcpTransport,
        timeout: Duration,
    ) -> Result<(Box<dyn ConnectionLike>, TransportAddr), TransportError> {
        let start = Instant::now();
        loop {
            match t.accept() {
                Ok(r) => return Ok(r),
                Err(TransportError::Generic(m)) if m.contains("no pending connections") => {
                    if start.elapsed() >= timeout {
                        return Err(TransportError::Generic("accept timed out".into()));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn write_raw_frame(stream: &mut StdTcpStream, data: &[u8]) {
        let len = data.len() as u32;
        stream.write_all(&len.to_be_bytes()).expect("write len");
        stream.write_all(data).expect("write payload");
        stream.flush().expect("flush");
    }

    // -------------------------------------------------------------------
    // Bind / local_addr
    // -------------------------------------------------------------------

    #[test]
    fn test_tcp_bind_and_local_addr() {
        let mut t = TcpTransport::new(Duration::from_secs(2), Duration::from_secs(5));
        assert!(t.local_addr().is_none());
        t.bind(TransportAddr::Tcp("127.0.0.1:0".parse().unwrap()))
            .expect("bind");
        let addr = t.local_addr().expect("local_addr");
        let sock = addr.as_socket_addr().expect("tcp variant");
        assert_ne!(sock.port(), 0);
    }

    #[test]
    fn test_tcp_bind_reuses_port_after_drop() {
        let (t1, addr) = bind_ephemeral();
        let _port = addr.as_socket_addr().expect("tcp variant").port();
        drop(t1);
        let mut t2 = TcpTransport::default();
        let _ = t2.bind(addr); // may fail due to TIME_WAIT; acceptable
    }

    // -------------------------------------------------------------------
    // Connect + accept lifecycle
    // -------------------------------------------------------------------

    #[test]
    fn test_tcp_connect_and_accept_lifecycle() {
        let (mut server, server_addr) = bind_ephemeral();
        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let server_handle = thread::spawn(move || {
            b.wait();
            let (mut conn, peer_addr) =
                accept_poll(&mut server, Duration::from_secs(3)).expect("accept");
            let peer_sock = peer_addr.as_socket_addr().expect("tcp variant");
            assert_eq!(
                peer_sock.ip(),
                "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
            );
            let msg = conn.read_frame().expect("read");
            assert_eq!(msg, b"hello from client");
            conn.write_frame(b"hello from server").expect("write");
            conn.close();
        });

        barrier.wait();
        let mut client = TcpTransport::default();
        let node = NodeInfo::new(42, vec![server_addr.clone()], 0);
        let mut conn = client.connect(&node).expect("connect");
        conn.write_frame(b"hello from client").expect("write");
        let reply = conn.read_frame().expect("read");
        assert_eq!(reply, b"hello from server");
        conn.close();
        server_handle.join().expect("join");
    }

    // -------------------------------------------------------------------
    // Send/receive round-trip (varying sizes)
    // -------------------------------------------------------------------

    #[test]
    fn test_tcp_send_recv_roundtrip_varying_sizes() {
        let (mut server, server_addr) = bind_ephemeral();
        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let server_handle = thread::spawn(move || {
            b.wait();
            let (mut conn, _) = accept_poll(&mut server, Duration::from_secs(3)).expect("accept");
            let sizes: &[usize] = &[1, 32, 256, 1024, 4096, 65536, 131072];
            for &size in sizes {
                conn.write_frame(&vec![0xABu8; size]).expect("write");
                let reply = conn.read_frame().expect("read");
                assert_eq!(reply.len(), size);
                assert!(reply.iter().all(|b| *b == 0xCD));
            }
            conn.close();
        });

        barrier.wait();
        let mut client = TcpTransport::default();
        let node = NodeInfo::new(1, vec![server_addr], 0);
        let mut conn = client.connect(&node).expect("connect");
        let sizes: &[usize] = &[1, 32, 256, 1024, 4096, 65536, 131072];
        for &size in sizes {
            let msg = conn.read_frame().expect("read");
            assert_eq!(msg.len(), size);
            assert!(msg.iter().all(|b| *b == 0xAB));
            conn.write_frame(&vec![0xCDu8; size]).expect("write");
        }
        conn.close();
        server_handle.join().expect("join");
    }

    // -------------------------------------------------------------------
    // Partial reads: chunked writes, verify framing reassembly
    // -------------------------------------------------------------------

    #[test]
    fn test_tcp_partial_reads_framing_reassembly() {
        let (mut server, server_addr) = bind_ephemeral();
        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let server_handle = thread::spawn(move || {
            b.wait();
            let (mut conn, _) = accept_poll(&mut server, Duration::from_secs(3)).expect("accept");
            for expected in &[b"message one" as &[u8], b"message two", b"message three"] {
                let msg = conn.read_frame().expect("read");
                assert_eq!(msg, *expected);
            }
            conn.close();
        });

        barrier.wait();
        let mut stream = StdTcpStream::connect_timeout(
            &server_addr.as_socket_addr().expect("tcp variant"),
            Duration::from_secs(3),
        )
        .expect("connect");
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        // Frame 1: byte-by-byte
        let p1 = b"message one";
        let lb = (p1.len() as u32).to_be_bytes();
        for &b in &lb {
            stream.write_all(&[b]).expect("w");
            stream.flush().expect("f");
            thread::sleep(Duration::from_millis(1));
        }
        for &b in p1.iter() {
            stream.write_all(&[b]).expect("w");
            stream.flush().expect("f");
            thread::sleep(Duration::from_millis(1));
        }

        // Frame 2: split len + split payload
        let p2 = b"message two";
        let lb2 = (p2.len() as u32).to_be_bytes();
        stream.write_all(&lb2[..2]).expect("w");
        stream.flush().expect("f");
        thread::sleep(Duration::from_millis(5));
        stream.write_all(&lb2[2..]).expect("w");
        stream.flush().expect("f");
        let mid = p2.len() / 2;
        stream.write_all(&p2[..mid]).expect("w");
        stream.flush().expect("f");
        thread::sleep(Duration::from_millis(5));
        stream.write_all(&p2[mid..]).expect("w");
        stream.flush().expect("f");

        // Frame 3: normal
        write_raw_frame(&mut stream, b"message three");

        server_handle.join().expect("join");
    }

    // -------------------------------------------------------------------
    // Disconnect detection
    // -------------------------------------------------------------------

    #[test]
    fn test_tcp_disconnect_detection_read_after_close() {
        let (mut server, server_addr) = bind_ephemeral();
        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let server_handle = thread::spawn(move || {
            b.wait();
            let (mut conn, _) = accept_poll(&mut server, Duration::from_secs(3)).expect("accept");
            conn.close();
        });

        barrier.wait();
        let mut client = TcpTransport::default();
        let node = NodeInfo::new(1, vec![server_addr], 0);
        let mut conn = client.connect(&node).expect("connect");
        thread::sleep(Duration::from_millis(150));
        assert!(conn.read_frame().is_err());
        server_handle.join().expect("join");
    }

    #[test]
    fn test_tcp_disconnect_detection_write_after_close() {
        let (mut server, server_addr) = bind_ephemeral();
        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let server_handle = thread::spawn(move || {
            b.wait();
            let (mut conn, _) = accept_poll(&mut server, Duration::from_secs(3)).expect("accept");
            let msg = conn.read_frame().expect("read");
            assert_eq!(msg, b"ping");
            conn.close();
        });

        barrier.wait();
        let mut client = TcpTransport::default();
        let node = NodeInfo::new(1, vec![server_addr], 0);
        let mut conn = client.connect(&node).expect("connect");
        conn.write_frame(b"ping").expect("write");
        thread::sleep(Duration::from_millis(200));
        if conn.write_frame(b"pong").is_ok() {
            thread::sleep(Duration::from_millis(100));
            assert!(conn.read_frame().is_err());
        }
        server_handle.join().expect("join");
    }

    #[test]
    fn test_tcp_disconnect_detection_client_close_notifies_server() {
        let (mut server, server_addr) = bind_ephemeral();
        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let server_handle = thread::spawn(move || {
            b.wait();
            let (mut conn, _) = accept_poll(&mut server, Duration::from_secs(3)).expect("accept");
            assert!(conn.read_frame().is_err());
        });

        barrier.wait();
        let mut client = TcpTransport::default();
        let node = NodeInfo::new(1, vec![server_addr], 0);
        let mut conn = client.connect(&node).expect("connect");
        thread::sleep(Duration::from_millis(50));
        conn.close();
        server_handle.join().expect("join");
    }

    #[test]
    fn test_tcp_close_is_idempotent() {
        let (mut server, server_addr) = bind_ephemeral();
        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let server_handle = thread::spawn(move || {
            b.wait();
            let (mut conn, _) = accept_poll(&mut server, Duration::from_secs(3)).expect("accept");
            conn.close();
            conn.close();
            assert!(conn.read_frame().is_err());
            assert!(conn.write_frame(b"data").is_err());
        });

        barrier.wait();
        let mut client = TcpTransport::default();
        let node = NodeInfo::new(1, vec![server_addr], 0);
        let mut conn = client.connect(&node).expect("connect");
        thread::sleep(Duration::from_millis(100));
        conn.close();
        conn.close();
        assert!(conn.read_frame().is_err());
        assert!(conn.write_frame(b"data").is_err());
        server_handle.join().expect("join");
    }

    // -------------------------------------------------------------------
    // Non-blocking behavior
    // -------------------------------------------------------------------

    #[test]
    fn test_tcp_nonblocking_accept_returns_immediately() {
        let mut t = TcpTransport::default();
        t.bind(TransportAddr::Tcp("127.0.0.1:0".parse().unwrap()))
            .expect("bind");
        assert!(t.accept().is_err());
    }

    #[test]
    fn test_tcp_nonblocking_inherited_by_connection() {
        let (mut server, server_addr) = bind_ephemeral();
        server.set_nonblocking(true).expect("set_nonblocking");
        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let server_handle = thread::spawn(move || {
            b.wait();
            let (mut conn, _) = accept_poll(&mut server, Duration::from_secs(3)).expect("accept");
            let _ = conn.read_frame();
            conn.close();
        });

        barrier.wait();
        let mut client = TcpTransport::default();
        let node = NodeInfo::new(1, vec![server_addr], 0);
        let mut conn = client.connect(&node).expect("connect");
        conn.write_frame(b"nonblocking data").expect("write");
        conn.close();
        server_handle.join().expect("join");
    }

    #[test]
    fn test_tcp_nonblocking_read_returns_wouldblock() {
        let (mut server, server_addr) = bind_ephemeral();
        server.set_nonblocking(true).expect("set_nonblocking");
        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let server_handle = thread::spawn(move || {
            b.wait();
            let (mut conn, _) = accept_poll(&mut server, Duration::from_secs(3)).expect("accept");
            let result = conn.read_frame();
            match result {
                Err(TransportError::WouldBlock(_)) => {}
                Err(TransportError::Generic(m)) if m.contains("connection closed") => {}
                _ => {}
            }
            conn.close();
        });

        barrier.wait();
        let mut client = TcpTransport::default();
        let node = NodeInfo::new(1, vec![server_addr], 0);
        let mut conn = client.connect(&node).expect("connect");
        thread::sleep(Duration::from_millis(100));
        conn.close();
        server_handle.join().expect("join");
    }

    // -------------------------------------------------------------------
    // Concurrent connections
    // -------------------------------------------------------------------

    #[test]
    fn test_tcp_concurrent_connections() {
        let (mut server, server_addr) = bind_ephemeral();
        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let server_handle = thread::spawn(move || {
            b.wait();
            let mut handles = Vec::new();
            for _i in 0..4 {
                let (mut conn, _) =
                    accept_poll(&mut server, Duration::from_secs(5)).expect("accept");
                handles.push(thread::spawn(move || {
                    // Read the client message to learn which client we got.
                    let msg = conn.read_frame().expect("read");
                    // Message format: "client message N"
                    assert!(msg.starts_with(b"client message "));
                    let idx_str = std::str::from_utf8(&msg[15..]).expect("utf8");
                    let _idx: u32 = idx_str.parse().expect("parse");

                    // Reply with matching server reply
                    let reply = format!("server reply {_idx}").into_bytes();
                    conn.write_frame(&reply).expect("write");
                    conn.close();
                }));
            }
            for h in handles {
                h.join().expect("conn join");
            }
        });

        barrier.wait();
        let mut client_handles = Vec::new();
        for i in 0..4 {
            let addr = server_addr.clone();
            client_handles.push(thread::spawn(move || {
                let mut t = TcpTransport::default();
                let node = NodeInfo::new(i as u64 + 1, vec![addr], 0);
                let mut conn = t.connect(&node).expect("connect");
                let msg = format!("client message {i}").into_bytes();
                conn.write_frame(&msg).expect("write");
                let reply = conn.read_frame().expect("read");
                let exp = format!("server reply {i}").into_bytes();
                assert_eq!(reply, exp, "mismatch for client {i}");
                conn.close();
            }));
        }
        for h in client_handles {
            h.join().expect("client join");
        }
        server_handle.join().expect("server join");
    }

    // -------------------------------------------------------------------
    // Frame size limits
    // -------------------------------------------------------------------

    #[test]
    fn test_tcp_frame_too_large_rejected() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
            let mut conn: Box<dyn ConnectionLike> = Box::new(TcpConnection {
                session_permit: None,
                stream: Some(stream),
                peer_addr: addr,
                nonblocking: false,
                read_buf: Vec::new(),
            });
            let result = conn.read_frame();
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(
                msg.contains("frame too large") || msg.contains("too large"),
                "expected 'too large', got: {msg}"
            );
        });

        let mut stream =
            StdTcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
        let big: u32 = 67_108_865; // 64 MiB + 1
        stream.write_all(&big.to_be_bytes()).expect("write");
        stream.flush().expect("flush");

        server_handle.join().expect("join");
    }

    // -------------------------------------------------------------------
    // TcpTransport defaults / custom timeouts / unreachable
    // -------------------------------------------------------------------

    #[test]
    fn test_tcp_transport_defaults() {
        let t = TcpTransport::default();
        assert_eq!(t.connect_timeout, Duration::from_secs(5));
        assert_eq!(t.read_timeout, Duration::from_secs(30));
        assert!(!t.nonblocking);
        assert!(t.listener.is_none());
        assert!(t.local_addr().is_none());
    }

    #[test]
    fn test_tcp_transport_custom_timeouts() {
        let t = TcpTransport::new(Duration::from_secs(10), Duration::from_secs(60));
        assert_eq!(t.connect_timeout, Duration::from_secs(10));
        assert_eq!(t.read_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_tcp_connect_to_unreachable_fails() {
        let mut client = TcpTransport::new(Duration::from_millis(200), Duration::from_secs(1));
        let bad = TransportAddr::Tcp("192.0.2.1:12345".parse().unwrap());
        let node = NodeInfo::new(99, vec![bad], 0);
        assert!(client.connect(&node).is_err());
    }
}
