use thiserror::Error;

use crate::addr::TransportAddr;
use crate::types::{ChunkId, ChunkTransferId, SessionId};

// ---------------------------------------------------------------------------
// Transport-level errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
/// Errors from the transport layer.
pub enum TransportError {
    #[error("failed to bind listener on {addr}: {source}")]
    BindFailed {
        addr: TransportAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to connect to peer {peer_addr}: {source}")]
    ConnectFailed {
        peer_addr: TransportAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to accept connection: {0}")]
    AcceptFailed(#[source] std::io::Error),

    #[error("session {session_id} not found in session table")]
    SessionNotFound { session_id: SessionId },

    #[error("session {session_id} is not in expected state: expected {expected}, actual {actual}")]
    SessionInWrongState {
        session_id: SessionId,
        expected: &'static str,
        actual: &'static str,
    },

    #[error("session {session_id} handshake failed: {reason}")]
    HandshakeFailed {
        session_id: SessionId,
        reason: String,
    },

    #[error("max sessions ({max}) reached, cannot establish session to {peer}")]
    MaxSessionsReached { max: usize, peer: u64 },

    #[error("peer {peer} not found in cohort graph")]
    PeerNotFound { peer: u64 },

    #[error("node identity mismatch: expected {expected}, got {got}")]
    IdentityMismatch { expected: u64, got: u64 },

    #[error("I/O error on session {session_id}: {source}")]
    Io {
        session_id: SessionId,
        #[source]
        source: std::io::Error,
    },

    #[error("RDMA is not available on this host: {reason}")]
    RdmaNotAvailable { reason: String },

    #[error("RDMA memory registration failed for session {session_id}: {reason}")]
    RdmaRegistrationFailed {
        session_id: SessionId,
        reason: String,
    },

    #[error("RDMA connection failed for session {session_id}: {reason}")]
    RdmaConnectionFailed {
        session_id: SessionId,
        reason: String,
    },

    #[error("RDMA carrier degraded for session {session_id}: falling back to TCP ({reason})")]
    RdmaDegraded {
        session_id: SessionId,
        reason: String,
    },

    #[error("unsupported carrier for this backend: {carrier}")]
    UnsupportedCarrier { carrier: String },

    #[error("{0}")]
    Generic(String),

    #[error("I/O would block: {0}")]
    WouldBlock(String),

    #[error("TDMA transmit window closed for node {node_id}: current slot {current_slot}, assigned slot {assigned_slot}")]
    TdmaWindowClosed {
        node_id: u64,
        current_slot: u16,
        assigned_slot: u16,
    },

    /// Per-peer send buffer is at capacity (soft backpressure).
    /// Callers should slow down or drop, not open the circuit.
    #[error("send buffer full for session {session_id}: capacity {capacity}, needed {needed}")]
    SendBufferFull {
        session_id: SessionId,
        capacity: u64,
        needed: u64,
    },

    /// Per-peer send buffer has been shut down (peer departed or closed).
    #[error("send buffer shut down for session {session_id}")]
    SendBufferShutdown { session_id: SessionId },

    /// Connection rejected by listener overload protection.
    #[error("listener overload: connection rejected ({reason})")]
    ListenerOverloaded { reason: String },

    /// Connection admission rejected: peer is not authorized to join the
    /// cluster data path according to the current membership roster.
    #[error("admission rejected for peer {peer_id}: {reason}")]
    AdmissionRejected { peer_id: u64, reason: String },

    /// Connection rejected due to global session concurrency limit.
    #[error("session concurrency limit reached: {current}/{max} sessions active")]
    SessionConcurrencyLimit { max: usize, current: usize },

    /// Outbound send rejected: the send-concurrency limit has been reached.
    /// The caller should retry after in-flight sends complete.
    #[error("send concurrency limit exceeded: max_inflight={max} (session {session_id})")]
    SendConcurrencyLimitExceeded { max: usize, session_id: SessionId },

    /// Outbound send rejected: peer is not in the current committed
    /// membership roster.
    #[error("peer {peer_id} not in committed membership roster (session {session_id})")]
    PeerNotInRoster { peer_id: u64, session_id: SessionId },
}

// ---------------------------------------------------------------------------
// Session errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
/// Errors from session operations.
pub enum SessionError {
    #[error("session {session_id} not yet established (state: {state:?})")]
    NotEstablished {
        session_id: SessionId,
        state: crate::session::SessionState,
    },

    #[error("session {session_id} invalid state transition from {from:?} to {to:?}")]
    InvalidTransition {
        session_id: SessionId,
        from: crate::session::SessionState,
        to: crate::session::SessionState,
    },

    #[error("session {session_id} RDMA carrier degraded, falling back to TCP: {reason}")]
    RdmaDegraded {
        session_id: SessionId,
        reason: String,
    },

    #[error("session {session_id} RDMA carrier lost: {reason}")]
    RdmaCarrierLost {
        session_id: SessionId,
        reason: String,
    },

    #[error("session {session_id} RDMA-to-TCP fallback failed: {reason}")]
    RdmaFallbackFailed {
        session_id: SessionId,
        reason: String,
    },

    #[error("session {session_id} reconnect gate refused: {reason}")]
    ReconnectGateRefused {
        session_id: SessionId,
        reason: String,
    },

    #[error("session {session_id} epoch mismatch: session bound to {session_epoch} but expected {expected_epoch}")]
    EpochMismatch {
        session_id: SessionId,
        session_epoch: u64,
        expected_epoch: u64,
    },
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

impl From<SessionError> for TransportError {
    fn from(err: SessionError) -> Self {
        TransportError::Generic(err.to_string())
    }
}

// ---------------------------------------------------------------------------
// Chunk shipping errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
/// Errors from chunk shipping operations.
pub enum ChunkError {
    #[error("chunk transfer {transfer_id} not found")]
    TransferNotFound { transfer_id: ChunkTransferId },

    #[error("chunk transfer {transfer_id} in wrong state: {state}")]
    TransferInWrongState {
        transfer_id: ChunkTransferId,
        state: &'static str,
    },

    #[error("checksum mismatch on chunk {chunk_id}: expected {expected}, got {got}")]
    ChecksumMismatch {
        chunk_id: ChunkId,
        expected: String,
        got: String,
    },

    #[error("max concurrent transfers ({max}) reached on session {session_id}")]
    MaxConcurrentReached { max: usize, session_id: SessionId },

    #[error("chunk {chunk_id} transfer failed: {reason}")]
    TransferFailed { chunk_id: ChunkId, reason: String },

    #[error("chunk {chunk_id} refused by peer: {reason}")]
    Refused {
        chunk_id: ChunkId,
        reason: crate::chunk_shipper::RefuseReason,
    },

    #[error("I/O error during chunk transfer {transfer_id}: {source}")]
    Io {
        transfer_id: ChunkTransferId,
        #[source]
        source: std::io::Error,
    },
}

/// Detailed reason for a single chunk transfer failure.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ChunkTransferError {
    #[error("connection lost during transfer at offset {at_offset}")]
    ConnectionLost { at_offset: u64 },

    #[error("transfer timed out at offset {at_offset}")]
    Timeout { at_offset: u64 },

    #[error("insufficient disk space: needed {needed}, available {available}")]
    NoSpace { needed: u64, available: u64 },

    #[error("freshness fence violated: peer has version {peer_version} >= our {our_version}")]
    FenceViolated { peer_version: u64, our_version: u64 },

    #[error("I/O error at offset {at_offset}: {source}")]
    Io {
        at_offset: u64,
        #[source]
        source: IoErrorWrapper,
    },
}

/// Wrapper to make std::io::Error clonable and comparable.
#[derive(Debug)]
pub struct IoErrorWrapper(pub std::io::ErrorKind, pub String);

impl IoErrorWrapper {
    /// Create an IoErrorWrapper from an `std::io::Error`.
    pub fn from_err(err: &std::io::Error) -> Self {
        Self(err.kind(), err.to_string())
    }
}

impl Clone for IoErrorWrapper {
    fn clone(&self) -> Self {
        Self(self.0, self.1.clone())
    }
}

impl PartialEq for IoErrorWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}

impl Eq for IoErrorWrapper {}

impl std::fmt::Display for IoErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}

impl std::error::Error for IoErrorWrapper {}
