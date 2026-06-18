// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport backend abstraction — the physical layer that creates and manages
//! connections underlying P8-01 transport endpoints.
//!
//! ## Endpoint lifecycle from the backend perspective
//!
//! The [`TransportBackend`] trait is the bottommost layer in the transport
//! stack. Every endpoint begins as a connection returned by
//! [`TransportBackend::accept`] (server side) or
//! [`TransportBackend::connect`] (client side). The transport layer wraps
//! that connection in a [`Connection`](crate::transport::Connection) and
//! then binds it to a [`Session`](crate::session::Session) with an assigned
//! [`EndpointFamily`](tidefs_types_transport_session::EndpointFamily).
//!
//! The backend's lifecycle role:
//!
//! **1. Bind & listen** — `bind()` opens the listener. The bound address
//! becomes the local endpoint for incoming connections. A backend must be
//! bound before any accept or connect succeeds.
//!
//! **2. Accept or connect** — `accept()` returns a new connection + peer
//! address. `connect()` establishes an outgoing connection to a peer node.
//! At this point the connection has no endpoint family; the transport layer
//! assigns the family during session creation.
//!
//! **3. Frame read/write** — the [`ConnectionLike`] trait provides the
//! frame-oriented I/O that the envelope layer needs. Each connection
//! carries framed transport envelopes with the 4-byte big-endian length
//! prefix wire format.
//!
//! **4. Non-blocking mode** — `set_nonblocking()` on both the backend and
//! individual connections enables asynchronous accept and read paths.
//! When enabled, `read_frame()` returns [`TransportError::WouldBlock`]
//! instead of blocking, and `accept()` returns immediately with no
//! pending connections.
//!
//! **5. Close** — `close()` drops the underlying stream. The session
//! layer handles the protocol-level drain and closure receipt.
//!
//! ### Backend-kind invariants
//!
//! | Invariant | Rule |
//! |---|---|
//! | **kind-stable** | The backend kind ([`TransportBackendKind`]) is set at creation and never changes. A TCP backend cannot become an RDMA backend mid-lifecycle. |
//! | **rdma-may-fallback** | RDMA backends may fall back to TCP when the carrier is unavailable; the fallback is transparent to upper layers. |
//! | **single-listener** | At most one listener is active per backend at any time. Calling `bind()` again replaces the previous listener. |
//! | **frame-integrity** | Every frame carries the 4-byte big-endian length prefix. Frames exceeding 64 MiB are rejected. |
//! | **nonblocking-propagates** | When `set_nonblocking(true)` is called on the backend, every future connection created by `accept()` or `connect()` inherits non-blocking mode. |
//!
//! ### Endpoint family → backend mapping
//!
//! The backend itself is endpoint-family-agnostic — the same backend
//! multiplexes all four endpoint families over its single listener and
//! connection pool. The transport layer assigns the correct
//! [`EndpointFamily`](tidefs_types_transport_session::EndpointFamily)
//! to each session based on the handshake message.
//!
//! | EndpointFamily | Backend | Notes |
//! |---|---|---|
//! | `LocalEmbed` (e0) | TCP loopback | Co-resident service communication within a single node. |
//! | `Control` (e1) | TCP / TLS | Bootstrap, control, replication metadata, transition orchestration. |
//! | `Data` (e2) | TCP / (future: RDMA) | Bulk transfer sessions. |
//! | `Shadow` (e3) | TCP | Shadow validation sessions. |
//!
use crate::addr::TransportAddr;

use crate::error::TransportError;
use crate::session_cohort::NodeInfo;

// ---------------------------------------------------------------------------
// TransportBackend trait: TCP (default), TLS, and RDMA (experimental, OW-308)
// ---------------------------------------------------------------------------

/// Result of accepting an incoming connection.
pub type AcceptResult = (Box<dyn ConnectionLike>, TransportAddr);

/// Identifies which transport backend a session or connection uses.
/// Enables backend-specific error handling, reconnect strategies, and
/// resource cleanup (e.g., RDMA memory-region deregistration).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportBackendKind {
    /// Plain TCP (default fallback).
    Tcp,
    /// TLS over TCP.
    Tls,
    /// RDMA carrier (experimental, OW-308).
    Rdma,
}

impl TransportBackendKind {
    #[must_use]
    /// Whether this backend requires RDMA hardware or software support.
    pub fn is_rdma(&self) -> bool {
        matches!(self, Self::Rdma)
    }

    #[must_use]
    /// Whether this backend may fall back to TCP when the carrier is unavailable.
    pub fn may_fallback_to_tcp(&self) -> bool {
        matches!(self, Self::Rdma)
    }

    /// The preferred carrier name for this backend kind.
    ///
    /// Returns the name of the carrier this backend would ideally select
    /// (e.g. `"rdma"` for `Rdma`, `"tcp"` for `Tcp` and `Tls`).
    /// Used in carrier disclosure for deterministic choice observability.
    #[must_use]
    pub fn preferred_carrier_name(&self) -> &'static str {
        match self {
            Self::Rdma => "rdma",
            Self::Tcp | Self::Tls => "tcp",
        }
    }
}

impl std::fmt::Display for TransportBackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Tls => write!(f, "tls"),
            Self::Rdma => write!(f, "rdma"),
        }
    }
}

/// Transport backend abstraction — the physical layer for creating and
/// managing connections that underlie P8-01 transport endpoints.
///
/// See the [module-level documentation](self) for the endpoint lifecycle
/// from the backend perspective, including bind/listen, accept/connect,
/// frame I/O, non-blocking mode, and backend-kind invariants.
///
/// Supports TCP (default), TLS, and RDMA (experimental, OW-308).
///
/// Preserved as a trait per DESIGN_OVERFITTING_POLICY.md §5: this is
/// legitimate open-set polymorphism with multiple production backends
/// (TCP, TLS, RDMA, loopback).
pub trait TransportBackend: Send + Sync {
    /// Bind to a local address and start listening.
    fn bind(&mut self, addr: TransportAddr) -> Result<(), TransportError>;

    /// Connect to a peer node.
    fn connect(&mut self, peer: &NodeInfo) -> Result<Box<dyn ConnectionLike>, TransportError>;

    /// Return the actual local address this backend is bound to, if bound.
    fn local_addr(&self) -> Option<TransportAddr>;

    /// Accept an incoming connection.
    fn accept(&mut self) -> Result<AcceptResult, TransportError>;

    /// Enable or disable non-blocking I/O on this backend and all future connections.
    ///
    /// When enabled, `read_frame` on connections created by this backend will
    /// return immediately with [`TransportError::WouldBlock`] instead of blocking.
    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TransportError>;

    /// Return the kind of this backend (e.g., Tcp, Tls, Rdma).
    fn backend_kind(&self) -> TransportBackendKind {
        TransportBackendKind::Tcp
    }
}

/// Abstract connection — read/write frames.
pub trait ConnectionLike: Send + Sync {
    /// Read a complete frame from the connection.
    fn read_frame(&mut self) -> Result<Vec<u8>, TransportError>;

    /// Write a complete frame to the connection.
    fn write_frame(&mut self, data: &[u8]) -> Result<(), TransportError>;

    /// Zero-copy write (sendfile/splice for TCP, RDMA write for RDMA).
    /// Default implementation falls back to write_frame.
    fn write_zero_copy(&mut self, buffer: &[u8]) -> Result<(), TransportError> {
        self.write_frame(buffer)
    }

    /// Close the connection.
    fn close(&mut self);

    /// Enable or disable non-blocking I/O on this connection.
    ///
    /// When enabled, `read_frame` returns immediately with
    /// [`TransportError::WouldBlock`] instead of blocking when no data is available.
    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TransportError>;

    /// Return the backend kind of this connection, if distinguishable.
    /// Defaults to Tcp for backward compatibility.
    fn backend_kind(&self) -> TransportBackendKind {
        TransportBackendKind::Tcp
    }
}
