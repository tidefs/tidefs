//! Loopback v2: TransportBackend and ConnectionLike backed by in-memory queues.
//!
//! Unlike the harness `LoopbackTransport` which uses a custom `SimMessage`,
//! this module implements the production `ConnectionLike` trait so the
//! loopback can serve as a transparent drop-in backend for the full
//! `Transport` / `Session` / envelope stack.
//!
//! ## Architecture
//!
//! - `LoopbackConnection`: a pair of `VecDeque<Vec<u8>>` frame buffers
//!   (inbound / outbound) implementing `ConnectionLike`.
//! - `LoopbackTransportBackend`: a `TransportBackend` that creates
//!   `LoopbackConnection` instances wired to peer transport backends via
//!   shared cross-connection Queues.
//!
//! The connection reads frames written by its peer and writes frames into
//! the peer's read buffer — all deterministic, in-process, zero-copy-safe.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::addr::TransportAddr;
use crate::backend::{AcceptResult, ConnectionLike, TransportBackend, TransportBackendKind};
use crate::error::TransportError;
use crate::session_cohort::NodeInfo;

// ---------------------------------------------------------------------------
// Shared queues between two loopback connections
// ---------------------------------------------------------------------------

/// The link between two `LoopbackConnection` peers.
///
/// Each direction gets its own queue. When A writes a frame, it is pushed
/// into B's `read_queue` and vice-versa.
pub(crate) struct LoopbackLink {
    /// Frames written by peer and ready for this side to read.
    read_queue: Mutex<VecDeque<Vec<u8>>>,
}

impl LoopbackLink {
    fn new() -> Self {
        Self {
            read_queue: Mutex::new(VecDeque::new()),
        }
    }
}

/// The two ends of a loopback pair.
///
/// `a_to_b` is the queue that carries frames from A to B (B reads from it).
/// `b_to_a` is the queue that carries frames from B to A (A reads from it).
struct LoopbackPair {
    a_to_b: Arc<LoopbackLink>,
    b_to_a: Arc<LoopbackLink>,
}

impl LoopbackPair {
    fn new() -> Self {
        Self {
            a_to_b: Arc::new(LoopbackLink::new()),
            b_to_a: Arc::new(LoopbackLink::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// LoopbackConnection
// ---------------------------------------------------------------------------

/// A `ConnectionLike` backed by in-memory `VecDeque<Vec<u8>>` queues.
///
/// Each connection has its own write queue (to the peer's read queue) and
/// reads from the peer's write queue. The `LoopbackPair` establishes the
/// cross-wiring.
pub struct LoopbackConnection {
    /// Frames sent by the peer and waiting to be read by this connection.
    read_link: Arc<LoopbackLink>,
    /// Frames written by this connection that the peer will read.
    write_link: Arc<LoopbackLink>,
    /// Non-blocking mode: when true, `read_frame` returns `WouldBlock`
    /// instead of blocking when the read queue is empty.
    nonblocking: bool,
    /// Whether the connection is closed.
    closed: bool,
}

impl LoopbackConnection {
    /// Create one end of a loopback pair. Returns the new connection and
    /// the link that the peer should use for its write direction.
    ///
    /// The caller creates a `LoopbackPair` and passes the appropriate links
    /// to each constructor.
    pub(crate) fn new(
        read_link: Arc<LoopbackLink>,
        write_link: Arc<LoopbackLink>,
        _local_addr: SocketAddr,
    ) -> Self {
        Self {
            read_link,
            write_link,
            nonblocking: false,
            closed: false,
        }
    }
}

impl ConnectionLike for LoopbackConnection {
    fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.closed {
            return Err(TransportError::Generic(
                "loopback connection is closed".into(),
            ));
        }
        let mut queue = self.read_link.read_queue.lock().unwrap();
        if let Some(frame) = queue.pop_front() {
            Ok(frame)
        } else if self.nonblocking {
            Err(TransportError::WouldBlock(
                "no frames available in loopback read queue".into(),
            ))
        } else {
            // Blocking mode: this is an in-process loopback, so if the queue
            // is empty there's nothing to wait for. The caller must interleave
            // reads with the peer's writes (e.g. via threads or step-driven
            // event loops like LoopbackNetwork).
            Err(TransportError::WouldBlock(
                "loopback read queue empty (blocking mode)".into(),
            ))
        }
    }

    fn write_frame(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Generic(
                "loopback connection is closed".into(),
            ));
        }
        // Push into the peer's read queue via our write link.
        self.write_link
            .read_queue
            .lock()
            .unwrap()
            .push_back(data.to_vec());
        Ok(())
    }

    fn close(&mut self) {
        self.closed = true;
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TransportError> {
        self.nonblocking = nonblocking;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LoopbackPair factory
// ---------------------------------------------------------------------------

/// A pair of cross-wired `LoopbackConnection` instances representing the
/// two ends of an in-process link.
pub struct LoopbackConnectionPair {
    /// Initiator-side connection.
    pub initiator: LoopbackConnection,
    /// Responder-side connection.
    pub responder: LoopbackConnection,
}

impl LoopbackConnectionPair {
    /// Create a cross-wired pair of `LoopbackConnection` instances.
    ///
    /// The initiator writes to the responder's read queue and vice-versa.
    /// Both connections use the loopback address `127.0.0.1:0`.
    #[must_use]
    pub fn new() -> Self {
        let pair = LoopbackPair::new();
        let loopback_addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            0,
        );
        Self {
            initiator: LoopbackConnection::new(
                Arc::clone(&pair.b_to_a), // reads from B→A
                Arc::clone(&pair.a_to_b), // writes to A→B
                loopback_addr,
            ),
            responder: LoopbackConnection::new(
                Arc::clone(&pair.a_to_b), // reads from A→B
                Arc::clone(&pair.b_to_a), // writes to B→A
                loopback_addr,
            ),
        }
    }
}

impl Default for LoopbackConnectionPair {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LoopbackTransportBackend
// ---------------------------------------------------------------------------

/// A `TransportBackend` that creates `LoopbackConnection` instances.
///
/// Each `connect()` call returns a new `Box<dyn ConnectionLike>` backed
/// by an in-memory `VecDeque` pair, allowing protocol tests to exercise
/// the full `Transport` / `Session` / envelope stack without TCP.
///
/// NOTE: This backend is intended for single-process protocol testing.
/// Connections created by `connect()` are isolated — they do not share
/// queues with any listener or other connections. For multi-node testing
/// across the loopback network, use the `LoopbackNetwork` harness.
pub struct LoopbackTransportBackend {
    bound_addr: Option<TransportAddr>,
    nonblocking: bool,
    /// Connections created by `connect()` whose peer end is waiting for `accept()`.
    pending_accepts: VecDeque<Box<dyn ConnectionLike>>,
    /// Shared pending queue for multi-backend coordination.
    /// When set, `connect()` pushes the responder here and `accept()` pops from here.
    shared_pending: Option<SharedPendingConnections>,
}

type SharedPendingConnections = Arc<Mutex<VecDeque<Box<dyn ConnectionLike>>>>;

impl LoopbackTransportBackend {
    /// Create a new loopback transport backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bound_addr: None,
            nonblocking: false,
            pending_accepts: VecDeque::new(),
            shared_pending: None,
        }
    }

    /// Create a pair of `LoopbackTransportBackend` instances sharing a
    /// pending-accept queue so that `connect()` on one backend makes a
    /// connection available for `accept()` on the other.
    ///
    /// Returns `(client_backend, server_backend)`.
    #[must_use]
    pub fn new_shared_pair() -> (Self, Self) {
        let shared: Arc<Mutex<VecDeque<Box<dyn ConnectionLike>>>> =
            Arc::new(Mutex::new(VecDeque::new()));
        let client = Self {
            bound_addr: None,
            nonblocking: false,
            pending_accepts: VecDeque::new(),
            shared_pending: Some(Arc::clone(&shared)),
        };
        let server = Self {
            bound_addr: None,
            nonblocking: false,
            pending_accepts: VecDeque::new(),
            shared_pending: Some(shared),
        };
        (client, server)
    }
}

impl Default for LoopbackTransportBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportBackend for LoopbackTransportBackend {
    fn bind(&mut self, addr: TransportAddr) -> Result<(), TransportError> {
        self.bound_addr = Some(addr);
        Ok(())
    }

    fn connect(&mut self, _peer: &NodeInfo) -> Result<Box<dyn ConnectionLike>, TransportError> {
        // Create a cross-wired connection pair.
        // The initiator is returned to the caller; the responder is queued
        // for the next `accept()` call so a server-side Transport can
        // pick it up.
        let pair = LoopbackConnectionPair::new();
        let mut conn = pair.initiator;
        if self.nonblocking {
            conn.set_nonblocking(true)?;
        }
        if let Some(ref shared) = self.shared_pending {
            shared.lock().unwrap().push_back(Box::new(pair.responder));
        } else {
            self.pending_accepts.push_back(Box::new(pair.responder));
        }
        Ok(Box::new(conn))
    }

    fn local_addr(&self) -> Option<TransportAddr> {
        self.bound_addr.clone()
    }

    fn accept(&mut self) -> Result<AcceptResult, TransportError> {
        let conn = if let Some(ref shared) = self.shared_pending {
            shared.lock().unwrap().pop_front()
        } else {
            self.pending_accepts.pop_front()
        };
        conn.map(|conn| {
            let addr = TransportAddr::Tcp(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                0,
            ));
            (conn, addr)
        })
        .ok_or(TransportError::Generic(
            "no pending loopback connections to accept".into(),
        ))
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TransportError> {
        self.nonblocking = nonblocking;
        Ok(())
    }

    fn backend_kind(&self) -> TransportBackendKind {
        TransportBackendKind::Tcp // loopback behaves like TCP
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_connection_pair_read_write_roundtrip() {
        let mut pair = LoopbackConnectionPair::new();

        pair.initiator
            .write_frame(b"hello from initiator")
            .expect("write_frame");
        let frame = pair.responder.read_frame().expect("read_frame");
        assert_eq!(frame, b"hello from initiator");

        pair.responder
            .write_frame(b"hello from responder")
            .expect("write_frame");
        let frame = pair.initiator.read_frame().expect("read_frame");
        assert_eq!(frame, b"hello from responder");
    }

    #[test]
    fn loopback_connection_pair_multiple_frames() {
        let mut pair = LoopbackConnectionPair::new();

        for i in 0..5u8 {
            pair.initiator.write_frame(&[i; 4]).expect("write_frame");
        }

        for i in 0..5u8 {
            let frame = pair.responder.read_frame().expect("read_frame");
            assert_eq!(frame, vec![i; 4]);
        }
    }

    #[test]
    fn loopback_connection_empty_read_returns_would_block() {
        let mut pair = LoopbackConnectionPair::new();
        let result = pair.responder.read_frame();
        assert!(matches!(result, Err(TransportError::WouldBlock(_))));
    }

    #[test]
    fn loopback_connection_nonblocking_mode() {
        let mut pair = LoopbackConnectionPair::new();

        pair.responder
            .set_nonblocking(true)
            .expect("set_nonblocking");

        let result = pair.responder.read_frame();
        assert!(matches!(result, Err(TransportError::WouldBlock(_))));
    }

    #[test]
    fn loopback_connection_closed_returns_error() {
        let mut pair = LoopbackConnectionPair::new();
        pair.initiator.close();

        let result = pair.initiator.read_frame();
        assert!(matches!(result, Err(TransportError::Generic(_))));

        let result = pair.initiator.write_frame(b"data");
        assert!(matches!(result, Err(TransportError::Generic(_))));
    }

    #[test]
    fn loopback_connection_pair_deterministic_replay() {
        fn run_sequence() -> Vec<Vec<u8>> {
            let mut pair = LoopbackConnectionPair::new();
            let mut received = Vec::new();

            pair.initiator.write_frame(b"msg1").unwrap();
            pair.initiator.write_frame(b"msg2").unwrap();

            received.push(pair.responder.read_frame().unwrap());
            received.push(pair.responder.read_frame().unwrap());

            pair.responder.write_frame(b"ack1").unwrap();
            received.push(pair.initiator.read_frame().unwrap());

            received
        }

        let first = run_sequence();
        for _ in 0..5 {
            assert_eq!(run_sequence(), first);
        }
    }

    #[test]
    fn loopback_transport_backend_connect_returns_connection() {
        let mut backend = LoopbackTransportBackend::new();
        let peer = NodeInfo::new(2, vec![], 0);
        let conn = backend.connect(&peer).expect("connect");
        assert!(matches!(conn.backend_kind(), TransportBackendKind::Tcp));
    }

    #[test]
    fn loopback_transport_backend_bind_and_local_addr() {
        let mut backend = LoopbackTransportBackend::new();
        let addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            9876,
        );
        let transport_addr = TransportAddr::Tcp(addr);
        backend.bind(transport_addr.clone()).expect("bind");
        assert_eq!(backend.local_addr(), Some(transport_addr));
    }

    #[test]
    fn loopback_transport_backend_accept_after_connect() {
        let mut backend = LoopbackTransportBackend::new();
        let peer = NodeInfo::new(2, vec![], 0);

        let _client_conn = backend.connect(&peer).expect("connect");
        let (server_conn, _addr) = backend.accept().expect("accept after connect");

        assert!(matches!(
            server_conn.backend_kind(),
            TransportBackendKind::Tcp
        ));

        let result = backend.accept();
        assert!(result.is_err(), "second accept should fail with no pending");
    }
}
