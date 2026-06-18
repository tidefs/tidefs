// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! TCP listener bound to a [`TransportAddr`] that accepts framed transport
//! connections.
//!
//! [`TransportListener`] provides the server-side accept path for multi-node
//! transport: bind a TCP socket, accept inbound connections, and feed the
//! resulting [`TransportConnection`] into the existing connection lifecycle
//! (epoch fencing, keepalive, message codec).
//!
//! ## Lifecycle
//!
//! ```text
//! TransportListener::bind(addr)
//!   |
//!   v
//! TransportListener
//!   |-- local_addr() --> bound address for discovery
//!   |-- accept()     --> TransportConnection (blocking)
//!   |                    |-- read_frame / write_frame
//!   |                    |-- close()
//! ```
//!
//! ## Overload Protection
//!
//! Optionally enable listener overload protection via
//! [`TransportListener::with_overload_protection`] to guard against
//! connection floods, partition-rejoin storms, and multi-node boot races:
//!
//! - **Token-bucket rate limiter**: bounds sustained accept rate (default
//!   100 accepts/sec, 2x burst).
//! - **Pending-handshake counter**: bounds concurrent accepted-but-not-yet-
//!   established connections (default 64).
//!
//! When overload protection is active, rejected connections return
//! [`TransportError::ListenerOverloaded`] with a reason string, and the
//! caller should back off or log the event for operator observability.
//!
//! See [`listener_overload`](crate::listener_overload) for the guard types.
//!
//! ## Relationship to other modules
//!
//! - [`TransportListener`] is the inbound counterpart to outbound `connect()`
//!   in [`TcpTransport`](crate::tcp::TcpTransport).
//! - Accepted [`TransportConnection`]s implement [`ConnectionLike`] and are
//!   compatible with the epoch fence, keepalive engine, and message codec
//!   machinery.
//! - For async/tokio-based connection management, see
//!   [`ConnectionManager`](crate::connection::ConnectionManager).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

use crate::addr::TransportAddr;
use crate::backend::ConnectionLike;
use crate::error::TransportError;
use crate::listener_overload::{ListenerOverloadConfig, OverloadGuard};
use crate::session_concurrency::{
    SessionConcurrencyConfig, SessionConcurrencyLimiter, SessionPermit,
};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// TransportConnection
// ---------------------------------------------------------------------------

/// A framed TCP connection produced by [`TransportListener::accept`].
///
/// Wraps a [`TcpStream`] and provides frame-oriented read/write via the
/// 4-byte big-endian length-prefix wire format. Implements [`ConnectionLike`]
/// for integration with the transport envelope and codec layers.
pub struct TransportConnection {
    stream: TcpStream,
    peer_addr: SocketAddr,
    /// Optional session concurrency permit, released on drop.
    #[allow(dead_code)]
    session_permit: Option<SessionPermit>,
}

impl TransportConnection {
    /// The remote peer's socket address.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Read a complete length-delimited frame from the connection.
    ///
    /// Frame format: 4-byte big-endian length prefix followed by payload.
    /// Frames exceeding 64 MiB are rejected.
    pub fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        read_frame_from(&mut self.stream)
    }

    /// Write a complete length-delimited frame to the connection.
    ///
    /// Frame format: 4-byte big-endian length prefix followed by payload.
    pub fn write_frame(&mut self, data: &[u8]) -> Result<(), TransportError> {
        write_frame_to(&mut self.stream, data)
    }

    /// Close the connection (shuts down both directions of the TCP stream).
    pub fn close(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

impl ConnectionLike for TransportConnection {
    fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        self.read_frame()
    }

    fn write_frame(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.write_frame(data)
    }

    fn close(&mut self) {
        self.close();
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TransportError> {
        self.stream
            .set_nonblocking(nonblocking)
            .map_err(|e| TransportError::Generic(format!("set_nonblocking failed: {e}")))
    }
}

impl std::fmt::Debug for TransportConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportConnection")
            .field("peer_addr", &self.peer_addr)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// TransportListener
// ---------------------------------------------------------------------------

/// TCP listener bound to a [`TransportAddr`] that accepts inbound framed
/// transport connections.
///
/// Created via [`TransportListener::bind`], which binds a TCP socket to the
/// given address and begins listening. Each call to [`accept`](TransportListener::accept)
/// blocks until a new connection arrives and returns a [`TransportConnection`]
/// ready for frame-oriented I/O.
///
/// ## Example
///
/// ```no_run
/// use tidefs_transport::listener::TransportListener;
/// use tidefs_transport::TransportAddr;
///
/// let addr: TransportAddr = "tcp://127.0.0.1:0".parse().unwrap();
/// let mut listener = TransportListener::bind(addr).unwrap();
/// println!("listening on {}", listener.local_addr());
///
/// let mut conn = listener.accept().unwrap();
/// conn.write_frame(b"hello").unwrap();
/// let reply = conn.read_frame().unwrap();
/// conn.close();
/// ```
pub struct TransportListener {
    listener: TcpListener,
    local_addr: TransportAddr,
    /// Optional overload protection guard.
    overload: Option<Arc<OverloadGuard>>,
    /// Optional global session concurrency limiter.
    session_concurrency: Option<Arc<SessionConcurrencyLimiter>>,
}

impl TransportListener {
    /// Bind a TCP socket to the given [`TransportAddr`] and start listening.
    ///
    /// Only the `Tcp` variant of `TransportAddr` is supported. Non-TCP
    /// addresses return [`TransportError::UnsupportedCarrier`].
    ///
    /// The backlog is set to the OS default (typically 128 on Linux).
    pub fn bind(addr: TransportAddr) -> Result<Self, TransportError> {
        let sock_addr = match addr {
            TransportAddr::Tcp(sa) => sa,
            ref other => {
                return Err(TransportError::UnsupportedCarrier {
                    carrier: other.carrier().to_string(),
                });
            }
        };
        let listener =
            TcpListener::bind(sock_addr).map_err(|source| TransportError::BindFailed {
                addr: addr.clone(),
                source,
            })?;
        let actual_addr = listener
            .local_addr()
            .map_err(|source| TransportError::BindFailed {
                addr: addr.clone(),
                source,
            })?;
        Ok(Self {
            listener,
            local_addr: TransportAddr::Tcp(actual_addr),
            overload: None,
            session_concurrency: None,
        })
    }

    /// Enable listener overload protection.
    ///
    /// Adds token-bucket accept-rate limiting and concurrent-pending-handshake
    /// bounding to the accept path. See [`listener_overload`](crate::listener_overload)
    /// for details on the two guard mechanisms.
    ///
    /// Must be called after [`bind`](Self::bind) and before the first
    /// [`accept`](Self::accept) call.
    pub fn with_overload_protection(mut self, config: ListenerOverloadConfig) -> Self {
        self.overload = Some(Arc::new(OverloadGuard::new(&config)));
        self
    }

    /// Enable global session concurrency limiting.
    ///
    /// Adds a global cap on the total number of concurrently established
    /// transport sessions across all listeners and outbound connectors.
    /// Each successful accept acquires a permit; the permit is released
    /// when the [`TransportConnection`] is dropped.
    ///
    /// Must be called after [`bind`](Self::bind) and before the first
    /// [`accept`](Self::accept) call.
    pub fn with_session_concurrency_limit(
        mut self,
        config: SessionConcurrencyConfig,
        limiter: Arc<SessionConcurrencyLimiter>,
    ) -> Self {
        self.session_concurrency = Some(limiter);
        let _ = config; // consumed for API consistency
        self
    }

    /// Accept an inbound connection, blocking until one arrives.
    ///
    /// When overload protection is enabled, this method:
    /// 1. Checks the token-bucket rate limiter (before accept).
    /// 2. Calls the underlying `TcpListener::accept()`.
    /// 3. Checks the pending-handshake counter (after accept).
    ///
    /// If either guard rejects the connection, returns
    /// [`TransportError::ListenerOverloaded`] with the rejection reason.
    ///
    /// Returns a [`TransportConnection`] wrapping the accepted TCP stream,
    /// ready for frame read/write.
    pub fn accept(&mut self) -> Result<TransportConnection, TransportError> {
        // Pre-accept: rate-limit check
        if let Some(ref guard) = self.overload {
            guard
                .pre_accept()
                .map_err(|reason| TransportError::ListenerOverloaded {
                    reason: reason.to_string(),
                })?;
        }

        let (stream, peer_addr) = self
            .listener
            .accept()
            .map_err(TransportError::AcceptFailed)?;

        // Post-accept: pending-handshake check
        if let Some(ref guard) = self.overload {
            if let Err(reason) = guard.post_accept(peer_addr) {
                // Close the accepted stream since we're rejecting it
                drop(stream);
                return Err(TransportError::ListenerOverloaded {
                    reason: reason.to_string(),
                });
            }
        }

        // Acquire session concurrency permit if configured
        let permit = if let Some(ref limiter) = self.session_concurrency {
            match limiter.try_acquire() {
                Ok(permit) => Some(permit),
                Err(e) => {
                    // Release any pending-handshake slot acquired above
                    if self.overload.is_some() {
                        if let Some(ref guard) = self.overload {
                            guard.release();
                        }
                    }
                    drop(stream);
                    return Err(TransportError::SessionConcurrencyLimit {
                        max: e.max,
                        current: e.current,
                    });
                }
            }
        } else {
            None
        };

        Ok(TransportConnection {
            stream,
            peer_addr,
            session_permit: permit,
        })
    }

    /// Release a pending-handshake slot.
    ///
    /// Call this after the handshake (session establishment) completes or
    /// fails for a connection obtained via [`accept`](Self::accept).
    /// Must be paired with each successful [`accept`](Self::accept) call
    /// when overload protection is enabled.
    ///
    /// When overload protection is not enabled, this is a no-op.
    pub fn release_pending(&self) {
        if let Some(ref guard) = self.overload {
            guard.release();
        }
    }

    /// Return the bound address for discovery.
    #[must_use]
    pub fn local_addr(&self) -> TransportAddr {
        self.local_addr.clone()
    }

    /// Set the listener to non-blocking mode.
    ///
    /// When non-blocking is enabled, [`accept`](Self::accept) returns
    /// immediately with an error if no connection is pending, rather than
    /// blocking.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), TransportError> {
        self.listener
            .set_nonblocking(nonblocking)
            .map_err(|e| TransportError::Generic(format!("set_nonblocking on listener: {e}")))
    }

    /// Return whether overload protection is enabled.
    pub fn overload_protection_enabled(&self) -> bool {
        self.overload.is_some()
    }

    /// Return a reference to the overload guard, if enabled.
    pub fn overload_guard(&self) -> Option<&OverloadGuard> {
        self.overload.as_deref()
    }
}

impl std::fmt::Debug for TransportListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportListener")
            .field("local_addr", &self.local_addr)
            .field("overload_enabled", &self.overload_protection_enabled())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Shared frame I/O helpers
// ---------------------------------------------------------------------------

/// Maximum frame payload size (64 MiB).
const MAX_FRAME_PAYLOAD: usize = 64 * 1024 * 1024;

/// Read a complete length-delimited frame from a reader.
fn read_frame_from(reader: &mut impl Read) -> Result<Vec<u8>, TransportError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .map_err(|e| TransportError::Generic(format!("frame read failed: {e}")))?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_PAYLOAD {
        return Err(TransportError::Generic(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_PAYLOAD})"
        )));
    }

    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .map_err(|e| TransportError::Generic(format!("frame payload read failed: {e}")))?;

    Ok(payload)
}

/// Write a complete length-delimited frame to a writer.
fn write_frame_to(writer: &mut impl Write, data: &[u8]) -> Result<(), TransportError> {
    let len = data.len() as u32;
    let len_bytes = len.to_be_bytes();
    writer
        .write_all(&len_bytes)
        .map_err(|e| TransportError::Generic(format!("frame write failed: {e}")))?;
    writer
        .write_all(data)
        .map_err(|e| TransportError::Generic(format!("frame payload write failed: {e}")))?;
    writer
        .flush()
        .map_err(|e| TransportError::Generic(format!("flush failed: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream as StdTcpStream;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    fn bind_ephemeral() -> TransportListener {
        TransportListener::bind(TransportAddr::Tcp("127.0.0.1:0".parse().unwrap()))
            .expect("bind ephemeral")
    }

    fn connect_raw(addr: &TransportAddr) -> StdTcpStream {
        let sock = addr.as_socket_addr().expect("tcp addr");
        StdTcpStream::connect(sock).expect("connect")
    }

    fn write_raw_frame(stream: &mut StdTcpStream, data: &[u8]) {
        let len = data.len() as u32;
        stream.write_all(&len.to_be_bytes()).expect("write len");
        stream.write_all(data).expect("write payload");
        stream.flush().expect("flush");
    }

    fn read_raw_frame(stream: &mut StdTcpStream) -> Vec<u8> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).expect("read len");
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).expect("read payload");
        payload
    }

    // -------------------------------------------------------------------
    // bind / local_addr
    // -------------------------------------------------------------------

    #[test]
    fn test_bind_ephemeral_port() {
        let listener = bind_ephemeral();
        let addr = listener.local_addr();
        let sock = addr.as_socket_addr().expect("tcp variant");
        assert_ne!(sock.port(), 0);
    }

    #[test]
    fn test_bind_unsupported_carrier_rdma() {
        let addr = TransportAddr::Rdma {
            gid: [0; 16],
            qpn: 1,
            service_id: 0,
        };
        let result = TransportListener::bind(addr);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported carrier"));
    }

    #[test]
    fn test_bind_unsupported_carrier_unix() {
        let addr = TransportAddr::Unix(std::path::PathBuf::from("/tmp/sock"));
        let result = TransportListener::bind(addr);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported carrier"));
    }

    #[test]
    fn test_bind_specific_port() {
        let listener = bind_ephemeral();
        let port = listener.local_addr().as_socket_addr().unwrap().port();
        drop(listener);
        thread::sleep(Duration::from_millis(50));
        let addr = TransportAddr::Tcp(format!("127.0.0.1:{port}").parse().unwrap());
        // May fail due to TIME_WAIT; accept either outcome
        let _ = TransportListener::bind(addr);
    }

    // -------------------------------------------------------------------
    // accept + connect round-trip
    // -------------------------------------------------------------------

    #[test]
    fn test_accept_connect_round_trip() {
        let mut listener = bind_ephemeral();
        let server_addr = listener.local_addr();

        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let client_handle = thread::spawn(move || {
            b.wait();
            let mut stream = connect_raw(&server_addr);
            write_raw_frame(&mut stream, b"ping");
            let reply = read_raw_frame(&mut stream);
            assert_eq!(reply, b"pong");
        });

        barrier.wait();
        let mut conn = listener.accept().expect("accept");
        let msg = conn.read_frame().expect("read");
        assert_eq!(msg, b"ping");
        conn.write_frame(b"pong").expect("write");
        conn.close();
        client_handle.join().expect("join");
    }

    // -------------------------------------------------------------------
    // Varying frame sizes
    // -------------------------------------------------------------------

    #[test]
    fn test_varying_frame_sizes() {
        let mut listener = bind_ephemeral();
        let server_addr = listener.local_addr();

        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let sizes = vec![1, 32, 256, 1024, 4096, 65536, 131072];
        let sizes_clone = sizes.clone();
        let client_handle = thread::spawn(move || {
            b.wait();
            let mut stream = connect_raw(&server_addr);
            for &size in &sizes_clone {
                write_raw_frame(&mut stream, &vec![0xABu8; size]);
                let reply = read_raw_frame(&mut stream);
                assert_eq!(reply.len(), size);
                assert!(reply.iter().all(|b| *b == 0xCD));
            }
        });

        barrier.wait();
        let mut conn = listener.accept().expect("accept");
        for &size in &sizes {
            let msg = conn.read_frame().expect("read");
            assert_eq!(msg.len(), size);
            assert!(msg.iter().all(|b| *b == 0xAB));
            conn.write_frame(&vec![0xCDu8; size]).expect("write");
        }
        conn.close();
        client_handle.join().expect("join");
    }

    // -------------------------------------------------------------------
    // Concurrent accept
    // -------------------------------------------------------------------

    #[test]
    fn test_concurrent_accept() {
        let mut listener = bind_ephemeral();
        let server_addr = listener.local_addr();

        let num_clients = 4;

        let clients: Vec<_> = (0..num_clients)
            .map(|i| {
                let addr = server_addr.clone();
                thread::spawn(move || {
                    let mut stream = connect_raw(&addr);
                    write_raw_frame(&mut stream, format!("client {i}").as_bytes());
                    let reply = read_raw_frame(&mut stream);
                    format!("reply {i}: {}", String::from_utf8_lossy(&reply))
                })
            })
            .collect();

        let mut handles = Vec::new();
        for _ in 0..num_clients {
            let mut conn = listener.accept().expect("accept");
            let handle = thread::spawn(move || {
                let msg = conn.read_frame().expect("read");
                let reply = format!("ack {}", String::from_utf8_lossy(&msg));
                conn.write_frame(reply.as_bytes()).expect("write");
                conn.close();
            });
            handles.push(handle);
        }

        for client in clients {
            let result = client.join().expect("client join");
            assert!(result.starts_with("reply "), "unexpected: {result}");
        }
        for handle in handles {
            handle.join().expect("handler join");
        }
    }

    // -------------------------------------------------------------------
    // Non-blocking accept
    // -------------------------------------------------------------------

    #[test]
    fn test_nonblocking_accept_with_pending() {
        let mut listener = bind_ephemeral();
        let server_addr = listener.local_addr();

        listener.set_nonblocking(true).expect("set_nonblocking");

        // No connection pending -- should return an error
        let result = listener.accept();
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(
                msg.contains("accept") || msg.contains("block"),
                "unexpected error: {msg}"
            );
        }

        // Connect a client
        let client_handle = thread::spawn(move || {
            let _stream = connect_raw(&server_addr);
        });

        // Poll accept until it succeeds or times out
        let start = std::time::Instant::now();
        loop {
            match listener.accept() {
                Ok(mut conn) => {
                    conn.close();
                    break;
                }
                Err(_) => {
                    if start.elapsed() > Duration::from_secs(5) {
                        panic!("accept timed out");
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
        client_handle.join().expect("join");
    }

    // -------------------------------------------------------------------
    // Frame size limit
    // -------------------------------------------------------------------

    #[test]
    fn test_frame_too_large_rejected() {
        let mut listener = bind_ephemeral();
        let server_addr = listener.local_addr();

        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let client_handle = thread::spawn(move || {
            b.wait();
            let mut stream = connect_raw(&server_addr);
            // Send a frame length > 64 MiB
            let big_len: u32 = 67_108_865u32; // 64 MiB + 1
            stream.write_all(&big_len.to_be_bytes()).expect("write len");
            stream.flush().expect("flush");
        });

        barrier.wait();
        let mut conn = listener.accept().expect("accept");
        let result = conn.read_frame();
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("too large"),
            "expected 'too large', got: {msg}"
        );
        conn.close();
        client_handle.join().expect("join");
    }

    // -------------------------------------------------------------------
    // Close idempotency
    // -------------------------------------------------------------------

    #[test]
    fn test_close_is_idempotent() {
        let mut listener = bind_ephemeral();
        let server_addr = listener.local_addr();

        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let client_handle = thread::spawn(move || {
            b.wait();
            let mut stream = connect_raw(&server_addr);
            let _ = read_raw_frame(&mut stream);
            // Second read should fail (connection closed)
            let mut buf = [0u8; 4];
            let result = stream.read_exact(&mut buf);
            assert!(result.is_err());
        });

        barrier.wait();
        let mut conn = listener.accept().expect("accept");
        conn.write_frame(b"data").expect("write");
        conn.close();
        conn.close(); // idempotent
        assert!(conn.read_frame().is_err());
        assert!(conn.write_frame(b"more").is_err());
        client_handle.join().expect("join");
    }

    // -------------------------------------------------------------------
    // ConnectionLike trait compliance
    // -------------------------------------------------------------------

    #[test]
    fn test_connection_like_trait_round_trip() {
        let mut listener = bind_ephemeral();
        let server_addr = listener.local_addr();

        let barrier = Arc::new(Barrier::new(2));
        let b = Arc::clone(&barrier);

        let client_handle = thread::spawn(move || {
            b.wait();
            let mut stream = connect_raw(&server_addr);
            write_raw_frame(&mut stream, b"hello via trait");
            let reply = read_raw_frame(&mut stream);
            assert_eq!(reply, b"ack via trait");
        });

        barrier.wait();
        let mut conn: Box<dyn ConnectionLike> = Box::new(listener.accept().expect("accept"));
        let msg = conn.read_frame().expect("read");
        assert_eq!(msg, b"hello via trait");
        conn.write_frame(b"ack via trait").expect("write");
        conn.close();
        client_handle.join().expect("join");
    }

    // -------------------------------------------------------------------
    // Debug output
    // -------------------------------------------------------------------

    #[test]
    fn test_debug_output_listener() {
        let listener = bind_ephemeral();
        let s = format!("{listener:?}");
        assert!(s.contains("TransportListener"));
        assert!(s.contains("127.0.0.1"));
    }

    #[test]
    fn test_debug_output_connection() {
        let mut listener = bind_ephemeral();
        let server_addr = listener.local_addr();

        let client_handle = thread::spawn(move || {
            let _stream = connect_raw(&server_addr);
        });

        let conn = listener.accept().expect("accept");
        let s = format!("{conn:?}");
        assert!(s.contains("TransportConnection"));
        client_handle.join().expect("join");
    }
}
