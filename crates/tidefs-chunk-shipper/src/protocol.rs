// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Chunk-shipper wire protocol using canonical binary-schema framing.
//!
//! Defines ChunkShippingRequest and ChunkShippingResponse message types
//! encoded as binary-schema envelopes (P2-03 §2). Each message carries a
//! BLAKE3-256 strong digest profile in its envelope header, and payload
//! integrity is verified via CRC32C fast checksum on the body.
//!
//! ## Wire format
//!
//! Every message is a single framed binary-schema envelope:
//!
//! ```text
//! [64-byte EnvelopeHeader][N-byte body]
//! ```
//!
//! The envelope header declares:
//! - family_id = SCHEMA_FAMILY_CHUNK_SHIPPER (12)
//! - type_id = SCHEMA_TYPE_CHUNK_REQUEST (1) or SCHEMA_TYPE_CHUNK_RESPONSE (2)
//! - fast_checksum_profile = Crc32c
//! - strong_digest_profile = Blake3_256
//!
//! Request body layout (24 bytes):
//!   offset  size  field
//!   0       8     object_id (LE u64)
//!   8       8     offset (LE u64)
//!   16      8     length (LE u64)
//!
//! Response body layout (variable):
//!   offset  size  field
//!   0       1     status (u8: 0=ok, non-zero=error)
//!   1       8     payload_len (LE u64)
//!   9       N     payload bytes
//!   9+N     32    blake3_digest of payload

use tidefs_binary_schema_core::{ChecksumProfile, SchemaFamilyId, SchemaTypeId, SchemaVersion};
use tidefs_binary_schema_framing::{
    EnvelopeBuilder, EnvelopeHeader, FramedMessage, FramingDecoder,
};

// ── Schema identifiers ──────────────────────────────────────────────────

/// Schema family for chunk-shipper messages.
pub const SCHEMA_FAMILY_CHUNK_SHIPPER: SchemaFamilyId = SchemaFamilyId(12);

/// Schema type for chunk shipping request messages.
pub const SCHEMA_TYPE_CHUNK_REQUEST: SchemaTypeId = SchemaTypeId(1);

/// Schema type for chunk shipping response messages.
pub const SCHEMA_TYPE_CHUNK_RESPONSE: SchemaTypeId = SchemaTypeId(2);

/// Schema version for chunk-shipper protocol v1.0.
pub const SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Request body size: object_id + offset + length (3 × u64 = 24 bytes).
const REQUEST_BODY_SIZE: u64 = 24;

/// Minimum response body size: status + payload_len (1 + 8 = 9 bytes).
const RESPONSE_MIN_BODY_SIZE: usize = 9;

/// Size of a BLAKE3 digest appended to response payloads.
const BLAKE3_DIGEST_BYTES: usize = 32;

// ── ChunkShippingRequest ────────────────────────────────────────────────

/// A request to ship a specific byte range of an object.
///
/// Sent by the target (or coordinator) to the source node holding the data.
/// The source should respond with one or more [`ChunkShippingResponse`]
/// messages covering the requested range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkShippingRequest {
    /// Object identifier.
    pub object_id: u64,
    /// Starting byte offset within the object (inclusive).
    pub offset: u64,
    /// Number of bytes requested.
    pub length: u64,
}

impl ChunkShippingRequest {
    /// Create a new chunk shipping request.
    #[must_use]
    pub fn new(object_id: u64, offset: u64, length: u64) -> Self {
        Self {
            object_id,
            offset,
            length,
        }
    }

    /// Encode this request into a framed binary-schema envelope.
    ///
    /// The returned bytes are a complete framed message: a 64-byte
    /// [`EnvelopeHeader`] followed by the 24-byte body, suitable for
    /// transmission over a transport session.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body = self.encode_body();
        let header = Self::build_envelope(body.len() as u64).encode();
        let mut frame = header.to_vec();
        frame.extend_from_slice(&body);
        frame
    }

    /// Encode just the body bytes (no envelope header).
    #[must_use]
    pub fn encode_body(&self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&self.object_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.offset.to_le_bytes());
        buf[16..24].copy_from_slice(&self.length.to_le_bytes());
        buf
    }

    /// Decode a [`ChunkShippingRequest`] from a [`FramedMessage`].
    ///
    /// Verifies the envelope header has the correct family and type IDs.
    /// Returns `None` if the envelope metadata is wrong or the body is
    /// the wrong size.
    #[must_use]
    pub fn decode_from_framed(msg: &FramedMessage) -> Option<Self> {
        if msg.header.family_id != SCHEMA_FAMILY_CHUNK_SHIPPER {
            return None;
        }
        if msg.header.type_id != SCHEMA_TYPE_CHUNK_REQUEST {
            return None;
        }
        if msg.body.len() != REQUEST_BODY_SIZE as usize {
            return None;
        }
        let object_id = u64::from_le_bytes(msg.body[0..8].try_into().ok()?);
        let offset = u64::from_le_bytes(msg.body[8..16].try_into().ok()?);
        let length = u64::from_le_bytes(msg.body[16..24].try_into().ok()?);
        Some(Self {
            object_id,
            offset,
            length,
        })
    }

    /// Decode from raw bytes (envelope header + body).
    ///
    /// Uses a [`FramingDecoder`] to extract the framed message, then
    /// delegates to [`decode_from_framed`].
    #[must_use]
    pub fn decode(raw: &[u8]) -> Option<Self> {
        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(raw);
        frames.first().and_then(Self::decode_from_framed)
    }

    /// Build the envelope header for a request message.
    fn build_envelope(body_bytes: u64) -> EnvelopeHeader {
        EnvelopeBuilder::new(
            SCHEMA_FAMILY_CHUNK_SHIPPER,
            SCHEMA_TYPE_CHUNK_REQUEST,
            SCHEMA_VERSION,
        )
        .with_checksum_profiles(ChecksumProfile::Crc32c, ChecksumProfile::Blake3_256)
        .build(0, body_bytes)
    }
}

// ── ChunkShippingResponse ───────────────────────────────────────────────

/// Response status for a chunk shipping operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ChunkResponseStatus {
    /// Chunk shipped successfully; payload is valid.
    Ok = 0,
    /// Requested object not found on source node.
    ObjectNotFound = 1,
    /// Requested byte range is out of bounds for the object.
    RangeOutOfBounds = 2,
    /// Source node is temporarily unable to serve the request.
    SourceBusy = 3,
    /// An internal error occurred on the source.
    InternalError = 4,
}

impl ChunkResponseStatus {
    /// Convert from a u8 discriminant.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Ok),
            1 => Some(Self::ObjectNotFound),
            2 => Some(Self::RangeOutOfBounds),
            3 => Some(Self::SourceBusy),
            4 => Some(Self::InternalError),
            _ => None,
        }
    }

    /// True if this status represents a successful transfer.
    #[must_use]
    pub fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// A response to a chunk shipping request, carrying payload data.
///
/// Sent by the source node back to the requester. For successful transfers
/// (status == Ok), the payload contains the requested bytes and the
/// blake3_digest covers those bytes. For error statuses, payload is empty
/// and blake3_digest is zero-filled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkShippingResponse {
    /// Transfer status.
    pub status: ChunkResponseStatus,
    /// The payload data (empty on error).
    pub payload: Vec<u8>,
    /// BLAKE3-256 digest of the payload bytes.
    pub blake3_digest: [u8; 32],
}

impl ChunkShippingResponse {
    /// Create a successful response with the given payload.
    ///
    /// The BLAKE3 digest is computed automatically from the payload.
    #[must_use]
    pub fn ok(payload: Vec<u8>) -> Self {
        let blake3_digest = blake3::hash(&payload);
        Self {
            status: ChunkResponseStatus::Ok,
            payload,
            blake3_digest: *blake3_digest.as_bytes(),
        }
    }

    /// Create an error response with the given status.
    #[must_use]
    pub fn error(status: ChunkResponseStatus) -> Self {
        debug_assert!(!status.is_ok(), "use ok() for success responses");
        Self {
            status,
            payload: Vec::new(),
            blake3_digest: [0u8; 32],
        }
    }

    /// Verify the payload against the embedded BLAKE3 digest.
    ///
    /// Returns `true` if the payload's BLAKE3 hash matches `blake3_digest`.
    #[must_use]
    pub fn verify(&self) -> bool {
        let computed = blake3::hash(&self.payload);
        *computed.as_bytes() == self.blake3_digest
    }

    /// Encode this response into a framed binary-schema envelope.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body = self.encode_body();
        let header = Self::build_envelope(body.len() as u64).encode();
        let mut frame = header.to_vec();
        frame.extend_from_slice(&body);
        frame
    }

    /// Encode just the body bytes.
    #[must_use]
    pub fn encode_body(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u64;
        let mut buf = Vec::with_capacity(1 + 8 + self.payload.len() + BLAKE3_DIGEST_BYTES);
        buf.push(self.status as u8);
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&self.blake3_digest);
        buf
    }

    /// Decode a [`ChunkShippingResponse`] from a [`FramedMessage`].
    #[must_use]
    pub fn decode_from_framed(msg: &FramedMessage) -> Option<Self> {
        if msg.header.family_id != SCHEMA_FAMILY_CHUNK_SHIPPER {
            return None;
        }
        if msg.header.type_id != SCHEMA_TYPE_CHUNK_RESPONSE {
            return None;
        }
        if msg.body.len() < RESPONSE_MIN_BODY_SIZE + BLAKE3_DIGEST_BYTES {
            return None;
        }
        let status = ChunkResponseStatus::from_u8(msg.body[0])?;
        let payload_len = u64::from_le_bytes(msg.body[1..9].try_into().ok()?) as usize;
        let expected_len = 9 + payload_len + BLAKE3_DIGEST_BYTES;
        if msg.body.len() != expected_len {
            return None;
        }
        let payload = msg.body[9..9 + payload_len].to_vec();
        let digest_start = 9 + payload_len;
        let blake3_digest: [u8; 32] = msg.body[digest_start..digest_start + 32].try_into().ok()?;

        Some(Self {
            status,
            payload,
            blake3_digest,
        })
    }

    /// Decode from raw bytes (envelope header + body).
    #[must_use]
    pub fn decode(raw: &[u8]) -> Option<Self> {
        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(raw);
        frames.first().and_then(Self::decode_from_framed)
    }

    /// Build the envelope header for a response message.
    fn build_envelope(body_bytes: u64) -> EnvelopeHeader {
        EnvelopeBuilder::new(
            SCHEMA_FAMILY_CHUNK_SHIPPER,
            SCHEMA_TYPE_CHUNK_RESPONSE,
            SCHEMA_VERSION,
        )
        .with_checksum_profiles(ChecksumProfile::Crc32c, ChecksumProfile::Blake3_256)
        .build(0, body_bytes)
    }
}

// ── ChunkAggregateHasher ────────────────────────────────────────────────

/// Streaming BLAKE3 aggregate hasher for chunk transfer verification.
///
/// Accumulates a single aggregate digest across all chunks in a transfer
/// session. Both sender and receiver maintain a hasher; when the transfer
/// completes they compare aggregate digests to detect any corruption or
/// truncation.
///
/// ## Usage
///
/// ```text
/// Sender                          Receiver
/// ──────                          ────────
/// hasher.update(chunk_payload)    hasher.update(received_payload)
///    ...                             ...
/// send(hasher.finalize())  ──▶  compare aggregates
/// ```
// Manual Debug and Clone impls below.
pub struct ChunkAggregateHasher {
    inner: blake3::Hasher,
    chunks_hashed: u64,
    total_bytes_hashed: u64,
}

impl Default for ChunkAggregateHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkAggregateHasher {
    /// Create a new aggregate hasher, keyed with a domain-separation context.
    #[must_use]
    pub fn new() -> Self {
        let mut inner = blake3::Hasher::new();
        // Domain-separate the aggregate hasher from per-chunk digests.
        inner.update(b"tidefs-chunk-shipper-aggregate-v1");
        Self {
            inner,
            chunks_hashed: 0,
            total_bytes_hashed: 0,
        }
    }

    /// Feed a chunk payload into the aggregate.
    pub fn update(&mut self, payload: &[u8]) {
        // Include chunk length prefix for domain separation between chunks.
        let len_prefix = (payload.len() as u64).to_le_bytes();
        self.inner.update(&len_prefix);
        self.inner.update(payload);
        self.chunks_hashed += 1;
        self.total_bytes_hashed += payload.len() as u64;
    }

    /// Finalize and return the aggregate BLAKE3 digest.
    #[must_use]
    pub fn finalize(&self) -> [u8; 32] {
        let mut hasher = self.inner.clone();
        // Finalize with chunk count for additional domain separation.
        hasher.update(&self.chunks_hashed.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Number of chunks fed into this hasher.
    #[must_use]
    pub fn chunks_hashed(&self) -> u64 {
        self.chunks_hashed
    }

    /// Total bytes fed into this hasher.
    #[must_use]
    pub fn total_bytes_hashed(&self) -> u64 {
        self.total_bytes_hashed
    }

    /// Reset the hasher for a new transfer.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}
// ── ChunkTransport: production-bound transport abstraction ─────────────

/// Error type for chunk transport operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChunkTransportError {
    /// The transport channel is full (backpressure).
    ChannelFull,
    /// The transport has been closed or shut down.
    Closed,
    /// No data is currently available for receive (non-blocking poll).
    NoData,
    /// An I/O-level transport error occurred.
    IoError(String),
}

impl std::fmt::Display for ChunkTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChannelFull => write!(f, "transport channel full"),
            Self::Closed => write!(f, "transport closed"),
            Self::NoData => write!(f, "no data available"),
            Self::IoError(msg) => write!(f, "transport I/O error: {msg}"),
        }
    }
}

impl std::error::Error for ChunkTransportError {}

/// Production-bound transport trait for chunk-shipper protocol messages.
///
/// Abstracts the transport layer so that [`ChunkShippingSender`] and
/// [`ChunkShippingReceiver`] can operate over a real
/// `tidefs_transport::Session` or an in-memory test channel without
/// coupling to a specific transport backend.
///
/// Implementors must be `Send` so that the transport can be handed off
/// across async task boundaries in production.
pub trait ChunkTransport: Send {
    /// Send raw framed bytes to the peer.
    ///
    /// Returns `Err(ChunkTransportError::ChannelFull)` when backpressure
    /// prevents immediate enqueue, `Err(ChunkTransportError::Closed)` when
    /// the transport is shut down.
    fn send(&self, data: Vec<u8>) -> Result<(), ChunkTransportError>;

    /// Non-blocking poll for incoming raw bytes from the peer.
    ///
    /// Returns `Ok(Some(bytes))` when data is available,
    /// `Ok(None)` when no data is currently buffered, or
    /// `Err(ChunkTransportError::Closed)` when the transport is shut down.
    fn try_recv(&mut self) -> Result<Option<Vec<u8>>, ChunkTransportError>;

    /// Return the session identifier for logging and diagnostics.
    fn session_id(&self) -> u64;
}

// ── MemoryChunkTransport: in-memory transport for tests ────────────────

/// An in-memory channel-based [`ChunkTransport`] for unit testing.
///
/// Each direction (send and receive) is backed by a `Vec<Vec<u8>>` queue.
/// Call [`MemoryChunkTransport::inject_recv`] to simulate incoming data
/// on the receive side.
#[derive(Clone, Debug)]
pub struct MemoryChunkTransport {
    session_id: u64,
    /// Outbound queue: bytes that have been sent.
    sent: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    /// Inbound queue: bytes waiting to be received.
    recv: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl MemoryChunkTransport {
    /// Create a new in-memory transport pair for the given session.
    #[must_use]
    pub fn new(session_id: u64) -> Self {
        Self {
            session_id,
            sent: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            recv: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Inject raw bytes into the receive queue, simulating an inbound message.
    pub fn inject_recv(&self, data: Vec<u8>) {
        self.recv.lock().unwrap().push(data);
    }

    /// Drain all sent bytes from the outbound queue.
    pub fn drain_sent(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }

    /// Count of pending outbound messages.
    #[must_use]
    pub fn sent_count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// Count of pending inbound messages.
    #[must_use]
    pub fn recv_count(&self) -> usize {
        self.recv.lock().unwrap().len()
    }
}

impl ChunkTransport for MemoryChunkTransport {
    fn send(&self, data: Vec<u8>) -> Result<(), ChunkTransportError> {
        self.sent.lock().unwrap().push(data);
        Ok(())
    }

    fn try_recv(&mut self) -> Result<Option<Vec<u8>>, ChunkTransportError> {
        let mut queue = self.recv.lock().unwrap();
        if queue.is_empty() {
            Ok(None)
        } else {
            Ok(Some(queue.remove(0)))
        }
    }

    fn session_id(&self) -> u64 {
        self.session_id
    }
}

// ── SessionChunkTransport: production transport session adapter ────────

/// Production [`ChunkTransport`] adapter backed by a real
/// `tidefs_transport::Session` send pipeline.
///
/// Wraps a [`SendPipelineHandle`](tidefs_transport::outbound_send::SendPipelineHandle)
/// for outbound sends and a `tokio::mpsc::UnboundedReceiver<Vec<u8>>` for
/// inbound receives. The caller is responsible for feeding decoded chunk-shipper
/// frames into the receiver via the paired [`UnboundedSender`](std::sync::mpsc::Sender)
/// returned by [`SessionChunkTransport::new`].
///
/// Outbound sends use [`MessageFamily::ReplicaTransferVerify`] (m7: "replica
/// chunk movement, verification, rebuild/relocation updates") to route through
/// the transport envelope dispatch. The chunk-shipper protocol already
/// encodes its own binary-schema envelope; this adapter treats the
/// chunk-shipper encoded frame as the transport payload.
///
/// # Integration
///
/// The transport receive loop dispatches inbound `ReplicaTransferVerify`
/// messages to a registered handler. That handler should call
/// send bytes into the paired
/// `UnboundedSender` so [`try_recv`](ChunkTransport::try_recv) can drain them.
///
/// # Example (sketch)
///
/// ```ignore
/// use tidefs_transport::outbound_send::SendPipelineHandle;
/// use tidefs_transport::envelope::MessageFamily;
///
/// let (mut session_transport, rx) = SessionChunkTransport::new(
///     send_handle,
///     42, // session_id
/// );
/// // ... register rx with transport dispatch for MessageFamily::ReplicaTransferVerify ...
/// let sender = ChunkShippingSender::new(Box::new(session_transport));
/// ```
#[derive(Debug)]
pub struct SessionChunkTransport {
    /// Transport send pipeline handle for outbound messages.
    send_handle: std::sync::Arc<tidefs_transport::outbound_send::SendPipelineHandle>,
    /// Receive queue: inbound chunk-shipper frames delivered by the transport
    /// dispatch handler.
    recv_queue: std::sync::mpsc::Receiver<Vec<u8>>,
    /// Transport session identifier.
    session_id: u64,
}

impl SessionChunkTransport {
    /// Create a new session transport adapter.
    ///
    /// Returns the adapter and the paired [`UnboundedSender`](std::sync::mpsc::Sender)
    /// that the transport dispatch handler should use to deliver inbound
    /// chunk-shipper frames.
    #[must_use]
    pub fn new(
        send_handle: std::sync::Arc<tidefs_transport::outbound_send::SendPipelineHandle>,
        session_id: u64,
    ) -> (Self, std::sync::mpsc::Sender<Vec<u8>>) {
        let (tx, rx) = std::sync::mpsc::channel();
        (
            Self {
                send_handle,
                recv_queue: rx,
                session_id,
            },
            tx,
        )
    }
}

impl ChunkTransport for SessionChunkTransport {
    fn send(&self, data: Vec<u8>) -> Result<(), ChunkTransportError> {
        self.send_handle
            .try_send(
                tidefs_transport::envelope::MessageFamily::ReplicaTransferVerify,
                &data,
            )
            .map_err(|e| match e {
                tidefs_transport::outbound_send::SendPipelineError::ChannelFull(_) => {
                    ChunkTransportError::ChannelFull
                }
                tidefs_transport::outbound_send::SendPipelineError::ConnectionStateClosed(_)
                | tidefs_transport::outbound_send::SendPipelineError::Shutdown => {
                    ChunkTransportError::Closed
                }
                other => ChunkTransportError::IoError(other.to_string()),
            })
    }

    fn try_recv(&mut self) -> Result<Option<Vec<u8>>, ChunkTransportError> {
        // TryRecvError imported inline

        match self.recv_queue.try_recv() {
            Ok(data) => Ok(Some(data)),
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Err(ChunkTransportError::Closed),
        }
    }

    fn session_id(&self) -> u64 {
        self.session_id
    }
}

// ── Transport session-backed sender / receiver ─────────────────────────

/// A chunk-shipper sender bound to a transport.
///
/// Holds a boxed [`ChunkTransport`] for sending [`ChunkShippingResponse`]
/// messages. Production wiring passes a real transport session adapter;
/// tests use [`MemoryChunkTransport`].
pub struct ChunkShippingSender {
    transport: Box<dyn ChunkTransport>,
}

impl std::fmt::Debug for ChunkShippingSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkShippingSender")
            .field("session_id", &self.transport.session_id())
            .finish()
    }
}

impl ChunkShippingSender {
    /// Create a sender bound to the given transport.
    #[must_use]
    pub fn new(transport: Box<dyn ChunkTransport>) -> Self {
        Self { transport }
    }

    /// Send a response through the transport.
    ///
    /// Encodes the response and transmits it through the bound transport.
    /// Returns `Ok(())` on success or a [`ChunkTransportError`] on failure.
    ///
    /// # Errors
    ///
    /// Returns [`ChunkTransportError::ChannelFull`] under backpressure,
    /// [`ChunkTransportError::Closed`] when the transport is shut down.
    pub fn send_response(&self, resp: &ChunkShippingResponse) -> Result<(), ChunkTransportError> {
        let encoded = resp.encode();
        self.transport.send(encoded)
    }

    /// Return the session identifier from the underlying transport.
    #[must_use]
    pub fn session_id(&self) -> u64 {
        self.transport.session_id()
    }
}

/// A chunk-shipper receiver bound to a transport.
///
/// Holds a boxed [`ChunkTransport`] for receiving [`ChunkShippingRequest`]
/// and [`ChunkShippingResponse`] messages. Polls the transport via
/// [`try_recv`] and feeds bytes through a [`FramingDecoder`].
pub struct ChunkShippingReceiver {
    transport: Box<dyn ChunkTransport>,
    /// Framing decoder for extracting messages from the byte stream.
    pub decoder: FramingDecoder,
}

impl std::fmt::Debug for ChunkShippingReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkShippingReceiver")
            .field("session_id", &self.transport.session_id())
            .field("frames_emitted", &self.decoder.frames_emitted_count())
            .field("bytes_fed", &self.decoder.total_bytes_fed())
            .finish()
    }
}

impl ChunkShippingReceiver {
    /// Create a receiver bound to the given transport.
    #[must_use]
    pub fn new(transport: Box<dyn ChunkTransport>) -> Self {
        Self {
            transport,
            decoder: FramingDecoder::new(),
        }
    }

    /// Poll the transport for incoming bytes and feed them into the decoder.
    ///
    /// Returns any complete framed messages that were decoded from data
    /// received since the last poll.  Callers should call this repeatedly
    /// until it returns an empty `Vec`.
    ///
    /// Returns `Err(ChunkTransportError::Closed)` when the transport is
    /// shut down with unprocessed frames still buffered in the decoder.
    pub fn poll(&mut self) -> Result<Vec<FramedMessage>, ChunkTransportError> {
        let mut all_frames = Vec::new();
        loop {
            match self.transport.try_recv() {
                Ok(Some(data)) => {
                    let frames = self.decoder.feed(&data);
                    all_frames.extend(frames);
                }
                Ok(None) => break,
                Err(e) => {
                    // Drain any remaining frames from the decoder buffer
                    // before propagating the error.
                    let remaining = self.decoder.feed(&[]);
                    all_frames.extend(remaining);
                    return if all_frames.is_empty() {
                        Err(e)
                    } else {
                        // Return frames so far; caller can retry the error.
                        Ok(all_frames)
                    };
                }
            }
        }
        // Also drain any frames already buffered in the decoder.
        let buffered = self.decoder.feed(&[]);
        all_frames.extend(buffered);
        Ok(all_frames)
    }

    /// Feed raw bytes directly into the decoder (bypasses transport poll).
    ///
    /// Returns any complete framed messages. Useful when the caller already
    /// has bytes from an external source (e.g., a received buffer).
    pub fn feed(&mut self, data: &[u8]) -> Vec<FramedMessage> {
        self.decoder.feed(data)
    }

    /// Return the session identifier from the underlying transport.
    #[must_use]
    pub fn session_id(&self) -> u64 {
        self.transport.session_id()
    }

    /// Try to extract a [`ChunkShippingResponse`] from the first framed message.
    #[must_use]
    pub fn try_decode_response(msg: &FramedMessage) -> Option<ChunkShippingResponse> {
        ChunkShippingResponse::decode_from_framed(msg)
    }

    /// Try to extract a [`ChunkShippingRequest`] from the first framed message.
    #[must_use]
    pub fn try_decode_request(msg: &FramedMessage) -> Option<ChunkShippingRequest> {
        ChunkShippingRequest::decode_from_framed(msg)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ChunkShippingRequest tests ─────────────────────────────────────

    #[test]
    fn request_encode_decode_round_trip() {
        let req = ChunkShippingRequest::new(42, 1024, 4096);
        let encoded = req.encode();
        let decoded = ChunkShippingRequest::decode(&encoded).expect("decode failed");
        assert_eq!(decoded.object_id, 42);
        assert_eq!(decoded.offset, 1024);
        assert_eq!(decoded.length, 4096);
    }

    #[test]
    fn request_encode_decode_zero_length() {
        let req = ChunkShippingRequest::new(7, 0, 0);
        let encoded = req.encode();
        let decoded = ChunkShippingRequest::decode(&encoded).expect("decode failed");
        assert_eq!(decoded.object_id, 7);
        assert_eq!(decoded.offset, 0);
        assert_eq!(decoded.length, 0);
    }

    #[test]
    fn request_encode_decode_max_values() {
        let req = ChunkShippingRequest::new(u64::MAX, u64::MAX, u64::MAX);
        let encoded = req.encode();
        let decoded = ChunkShippingRequest::decode(&encoded).expect("decode failed");
        assert_eq!(decoded.object_id, u64::MAX);
        assert_eq!(decoded.offset, u64::MAX);
        assert_eq!(decoded.length, u64::MAX);
    }

    #[test]
    fn request_decode_wrong_family_rejected() {
        // Build a frame with wrong family_id using body from a real request
        let req = ChunkShippingRequest::new(1, 0, 100);
        let body = req.encode_body();
        let header = EnvelopeBuilder::new(
            SchemaFamilyId(99), // wrong family
            SCHEMA_TYPE_CHUNK_REQUEST,
            SCHEMA_VERSION,
        )
        .with_checksum_profiles(ChecksumProfile::Crc32c, ChecksumProfile::Blake3_256)
        .build(0, body.len() as u64)
        .encode();
        let mut frame = header.to_vec();
        frame.extend_from_slice(&body);
        assert!(ChunkShippingRequest::decode(&frame).is_none());
    }

    #[test]
    fn request_decode_wrong_type_rejected() {
        let req = ChunkShippingRequest::new(1, 0, 100);
        let body = req.encode_body();
        let header = EnvelopeBuilder::new(
            SCHEMA_FAMILY_CHUNK_SHIPPER,
            SCHEMA_TYPE_CHUNK_RESPONSE, // wrong type: response, not request
            SCHEMA_VERSION,
        )
        .with_checksum_profiles(ChecksumProfile::Crc32c, ChecksumProfile::Blake3_256)
        .build(0, body.len() as u64)
        .encode();
        let mut frame = header.to_vec();
        frame.extend_from_slice(&body);
        assert!(ChunkShippingRequest::decode(&frame).is_none());
    }

    #[test]
    fn request_decode_corrupt_body_size_rejected() {
        let req = ChunkShippingRequest::new(1, 0, 100);
        let mut encoded = req.encode();
        // Truncate body
        encoded.truncate(64 + 20); // header + partial body
        assert!(ChunkShippingRequest::decode(&encoded).is_none());
    }

    #[test]
    fn request_decode_corrupt_envelope_magic_rejected() {
        let req = ChunkShippingRequest::new(1, 0, 100);
        let mut encoded = req.encode();
        encoded[0] ^= 0xFF; // corrupt magic
        assert!(ChunkShippingRequest::decode(&encoded).is_none());
    }

    #[test]
    fn request_encode_body_is_24_bytes() {
        let req = ChunkShippingRequest::new(1, 2, 3);
        assert_eq!(req.encode_body().len(), 24);
    }

    #[test]
    fn request_total_frame_size_is_88() {
        let req = ChunkShippingRequest::new(1, 0, 100);
        // 64 byte envelope + 24 byte body
        assert_eq!(req.encode().len(), 88);
    }

    // ── ChunkShippingResponse tests ────────────────────────────────────

    #[test]
    fn response_ok_encode_decode_round_trip() {
        let payload = b"hello chunk shipper".to_vec();
        let resp = ChunkShippingResponse::ok(payload.clone());
        let encoded = resp.encode();
        let decoded = ChunkShippingResponse::decode(&encoded).expect("decode failed");
        assert_eq!(decoded.status, ChunkResponseStatus::Ok);
        assert_eq!(decoded.payload, payload);
        assert!(decoded.verify());
    }

    #[test]
    fn response_error_encode_decode_round_trip() {
        let resp = ChunkShippingResponse::error(ChunkResponseStatus::ObjectNotFound);
        let encoded = resp.encode();
        let decoded = ChunkShippingResponse::decode(&encoded).expect("decode failed");
        assert_eq!(decoded.status, ChunkResponseStatus::ObjectNotFound);
        assert!(decoded.payload.is_empty());
        assert_eq!(decoded.blake3_digest, [0u8; 32]);
        // An empty payload's BLAKE3 digest is non-zero, but our error
        // constructor sets the digest to zero — verify catches this
        assert!(!decoded.verify());
    }

    #[test]
    fn response_ok_verify_matches() {
        let resp = ChunkShippingResponse::ok(b"verify me".to_vec());
        assert!(resp.verify());
    }

    #[test]
    fn response_verify_fails_on_tampered_payload() {
        let mut resp = ChunkShippingResponse::ok(b"original".to_vec());
        resp.payload = b"tampered!".to_vec();
        assert!(!resp.verify());
    }

    #[test]
    fn response_verify_fails_on_tampered_digest() {
        let mut resp = ChunkShippingResponse::ok(b"original".to_vec());
        resp.blake3_digest[0] ^= 0xFF;
        assert!(!resp.verify());
    }

    #[test]
    fn response_ok_empty_payload() {
        let resp = ChunkShippingResponse::ok(Vec::new());
        assert!(resp.verify());
        let encoded = resp.encode();
        let decoded = ChunkShippingResponse::decode(&encoded).expect("decode failed");
        assert_eq!(decoded.payload.len(), 0);
        assert!(decoded.verify());
    }

    #[test]
    fn response_large_payload() {
        let payload = vec![0xABu8; 65536];
        let resp = ChunkShippingResponse::ok(payload.clone());
        let encoded = resp.encode();
        let decoded = ChunkShippingResponse::decode(&encoded).expect("decode failed");
        assert_eq!(decoded.payload, payload);
        assert!(decoded.verify());
    }

    #[test]
    fn response_all_error_statuses() {
        let statuses = [
            ChunkResponseStatus::ObjectNotFound,
            ChunkResponseStatus::RangeOutOfBounds,
            ChunkResponseStatus::SourceBusy,
            ChunkResponseStatus::InternalError,
        ];
        for st in &statuses {
            let resp = ChunkShippingResponse::error(*st);
            let encoded = resp.encode();
            let decoded = ChunkShippingResponse::decode(&encoded).expect("decode failed");
            assert_eq!(decoded.status, *st);
            assert!(decoded.payload.is_empty());
        }
    }

    #[test]
    fn response_decode_wrong_family_rejected() {
        let resp = ChunkShippingResponse::ok(b"data".to_vec());
        let body = resp.encode_body();
        let header = EnvelopeBuilder::new(
            SchemaFamilyId(77),
            SCHEMA_TYPE_CHUNK_RESPONSE,
            SCHEMA_VERSION,
        )
        .with_checksum_profiles(ChecksumProfile::Crc32c, ChecksumProfile::Blake3_256)
        .build(0, body.len() as u64)
        .encode();
        let mut frame = header.to_vec();
        frame.extend_from_slice(&body);
        assert!(ChunkShippingResponse::decode(&frame).is_none());
    }

    #[test]
    fn response_decode_truncated_body_rejected() {
        let resp = ChunkShippingResponse::ok(b"data".to_vec());
        let mut encoded = resp.encode();
        // Truncate to header + partial body (less than 9 + 32)
        encoded.truncate(64 + 20);
        assert!(ChunkShippingResponse::decode(&encoded).is_none());
    }

    #[test]
    fn response_decode_invalid_status_rejected() {
        let resp = ChunkShippingResponse::ok(b"data".to_vec());
        let mut encoded = resp.encode();
        // Corrupt the status byte (byte 64 = first body byte)
        encoded[64] = 0xFF; // invalid status discriminant
        assert!(ChunkShippingResponse::decode(&encoded).is_none());
    }

    // ── ChunkAggregateHasher tests ─────────────────────────────────────

    #[test]
    fn aggregate_hasher_empty_finalize_is_deterministic() {
        let h1 = ChunkAggregateHasher::new();
        let h2 = ChunkAggregateHasher::new();
        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn aggregate_hasher_same_chunks_produce_same_digest() {
        let mut h1 = ChunkAggregateHasher::new();
        let mut h2 = ChunkAggregateHasher::new();

        h1.update(b"chunk-a");
        h1.update(b"chunk-b");
        h2.update(b"chunk-a");
        h2.update(b"chunk-b");

        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn aggregate_hasher_different_chunks_produce_different_digest() {
        let mut h1 = ChunkAggregateHasher::new();
        let mut h2 = ChunkAggregateHasher::new();

        h1.update(b"chunk-a");
        h1.update(b"chunk-b");
        h2.update(b"chunk-a");
        h2.update(b"chunk-x"); // different

        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn aggregate_hasher_order_matters() {
        let mut h1 = ChunkAggregateHasher::new();
        let mut h2 = ChunkAggregateHasher::new();

        h1.update(b"first");
        h1.update(b"second");
        h2.update(b"second");
        h2.update(b"first");

        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn aggregate_hasher_counts_are_accurate() {
        let mut h = ChunkAggregateHasher::new();
        assert_eq!(h.chunks_hashed(), 0);
        assert_eq!(h.total_bytes_hashed(), 0);

        h.update(b"abc"); // 3 bytes
        assert_eq!(h.chunks_hashed(), 1);
        assert_eq!(h.total_bytes_hashed(), 3);

        h.update(b"12345"); // 5 bytes
        assert_eq!(h.chunks_hashed(), 2);
        assert_eq!(h.total_bytes_hashed(), 8);
    }

    #[test]
    fn aggregate_hasher_reset_clears_state() {
        let mut h = ChunkAggregateHasher::new();
        h.update(b"some data");
        let d1 = h.finalize();

        h.reset();
        h.update(b"different");
        let d2 = h.finalize();

        assert_ne!(d1, d2);

        // After reset, should match a fresh hasher with same data
        let mut fresh = ChunkAggregateHasher::new();
        fresh.update(b"different");
        assert_eq!(h.finalize(), fresh.finalize());
    }

    #[test]
    fn aggregate_hasher_different_lengths_differ() {
        let mut h1 = ChunkAggregateHasher::new();
        let mut h2 = ChunkAggregateHasher::new();

        h1.update(b"short");
        h2.update(b"shortlonger");

        assert_ne!(h1.finalize(), h2.finalize());
    }

    // ── Full round-trip: request + response cycle ─────────────────────

    #[test]
    fn full_request_response_round_trip() {
        // Source: receives a ChunkShippingRequest
        let req = ChunkShippingRequest::new(99, 4096, 256);
        let req_encoded = req.encode();

        // Transport delivers the bytes; receiver decodes
        let decoded_req =
            ChunkShippingRequest::decode(&req_encoded).expect("request decode failed");
        assert_eq!(decoded_req.object_id, 99);
        assert_eq!(decoded_req.offset, 4096);
        assert_eq!(decoded_req.length, 256);

        // Source builds a response with the requested data
        let data = vec![0xCDu8; 256];
        let resp = ChunkShippingResponse::ok(data.clone());
        let resp_encoded = resp.encode();

        // Requester decodes the response
        let decoded_resp =
            ChunkShippingResponse::decode(&resp_encoded).expect("response decode failed");
        assert_eq!(decoded_resp.status, ChunkResponseStatus::Ok);
        assert_eq!(decoded_resp.payload, data);
        assert!(decoded_resp.verify());
    }

    #[test]
    fn full_round_trip_with_aggregate_digest_match() {
        // Sender hasher
        let mut sender_hasher = ChunkAggregateHasher::new();
        // Receiver hasher
        let mut receiver_hasher = ChunkAggregateHasher::new();

        let chunks: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("chunk-{i:02}-payload-data").into_bytes())
            .collect();

        // Encode and feed each chunk
        for chunk in &chunks {
            sender_hasher.update(chunk);

            let resp = ChunkShippingResponse::ok(chunk.clone());
            let encoded = resp.encode();

            // Decode on receiver side
            let decoded = ChunkShippingResponse::decode(&encoded).expect("decode failed");
            assert!(decoded.verify());
            receiver_hasher.update(&decoded.payload);
        }

        // Aggregate digests must match
        assert_eq!(sender_hasher.finalize(), receiver_hasher.finalize());
        assert_eq!(sender_hasher.chunks_hashed(), 5);
        assert_eq!(receiver_hasher.chunks_hashed(), 5);
    }

    #[test]
    fn aggregate_digest_mismatch_detected_on_truncated_transfer() {
        let mut sender_hasher = ChunkAggregateHasher::new();
        let mut receiver_hasher = ChunkAggregateHasher::new();

        let all_chunks: Vec<Vec<u8>> = (0..3).map(|i| format!("chunk-{i}").into_bytes()).collect();

        // Sender hashes all 3
        for chunk in &all_chunks {
            sender_hasher.update(chunk);
        }

        // Receiver only gets 2 (simulated loss)
        for chunk in &all_chunks[..2] {
            receiver_hasher.update(chunk);
        }

        assert_ne!(sender_hasher.finalize(), receiver_hasher.finalize());
    }

    // ── ChunkResponseStatus tests ──────────────────────────────────────

    #[test]
    fn response_status_from_u8_round_trips() {
        for v in 0..=4u8 {
            let st = ChunkResponseStatus::from_u8(v).expect("valid status");
            assert_eq!(st as u8, v);
        }
    }

    #[test]
    fn response_status_from_u8_invalid_returns_none() {
        assert!(ChunkResponseStatus::from_u8(5).is_none());
        assert!(ChunkResponseStatus::from_u8(255).is_none());
    }

    #[test]
    fn response_status_is_ok() {
        assert!(ChunkResponseStatus::Ok.is_ok());
        assert!(!ChunkResponseStatus::ObjectNotFound.is_ok());
        assert!(!ChunkResponseStatus::InternalError.is_ok());
    }

    // ── FramingDecoder integration: multi-frame stream ────────────────

    #[test]
    fn decoder_multi_request_stream() {
        let req1 = ChunkShippingRequest::new(1, 0, 100);
        let req2 = ChunkShippingRequest::new(2, 200, 50);

        let mut stream = req1.encode();
        stream.extend_from_slice(&req2.encode());

        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(&stream);
        assert_eq!(frames.len(), 2);

        let d1 = ChunkShippingRequest::decode_from_framed(&frames[0]).unwrap();
        assert_eq!(d1.object_id, 1);

        let d2 = ChunkShippingRequest::decode_from_framed(&frames[1]).unwrap();
        assert_eq!(d2.object_id, 2);
    }

    #[test]
    fn decoder_multi_response_stream() {
        let r1 = ChunkShippingResponse::ok(b"first".to_vec());
        let r2 = ChunkShippingResponse::ok(b"second".to_vec());

        let mut stream = r1.encode();
        stream.extend_from_slice(&r2.encode());

        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(&stream);
        assert_eq!(frames.len(), 2);

        let d1 = ChunkShippingResponse::decode_from_framed(&frames[0]).unwrap();
        assert!(d1.verify());
        assert_eq!(d1.payload, b"first");

        let d2 = ChunkShippingResponse::decode_from_framed(&frames[1]).unwrap();
        assert!(d2.verify());
        assert_eq!(d2.payload, b"second");
    }

    #[test]
    fn decoder_mixed_request_response_stream() {
        let req = ChunkShippingRequest::new(7, 0, 64);
        let resp = ChunkShippingResponse::ok(vec![0x42u8; 64]);

        let mut stream = req.encode();
        stream.extend_from_slice(&resp.encode());

        let mut decoder = FramingDecoder::new();
        let frames = decoder.feed(&stream);
        assert_eq!(frames.len(), 2);

        // First frame is the request
        let d_req = ChunkShippingRequest::decode_from_framed(&frames[0]).unwrap();
        assert_eq!(d_req.object_id, 7);

        // Second frame is the response
        let d_resp = ChunkShippingResponse::decode_from_framed(&frames[1]).unwrap();
        assert!(d_resp.verify());
    }

    #[test]
    fn decoder_split_across_feed_calls() {
        let resp = ChunkShippingResponse::ok(b"split payload test".to_vec());
        let encoded = resp.encode();

        let mut decoder = FramingDecoder::new();

        // Feed first half
        let frames = decoder.feed(&encoded[..30]);
        assert!(frames.is_empty());

        // Feed second half
        let frames = decoder.feed(&encoded[30..]);
        assert_eq!(frames.len(), 1);

        let decoded = ChunkShippingResponse::decode_from_framed(&frames[0]).unwrap();
        assert!(decoded.verify());
    }

    // ── ChunkShippingSender / Receiver transport-backed tests ────────

    #[test]
    fn sender_send_response_through_transport() {
        let transport = MemoryChunkTransport::new(42);
        let sender = ChunkShippingSender::new(Box::new(transport.clone()));

        let resp = ChunkShippingResponse::ok(b"via transport".to_vec());
        sender
            .send_response(&resp)
            .expect("send through transport failed");

        // Verify bytes were delivered to the transport outbound queue
        let sent = transport.drain_sent();
        assert_eq!(sent.len(), 1);

        // The sent frame should be a decodable response
        let decoded = ChunkShippingResponse::decode(&sent[0]).expect("decode failed");
        assert!(decoded.verify());
        assert_eq!(decoded.payload, b"via transport");
    }

    #[test]
    fn sender_send_response_error_response() {
        let transport = MemoryChunkTransport::new(7);
        let sender = ChunkShippingSender::new(Box::new(transport.clone()));

        let err_resp = ChunkShippingResponse::error(ChunkResponseStatus::ObjectNotFound);
        sender
            .send_response(&err_resp)
            .expect("send through transport failed");

        let sent = transport.drain_sent();
        assert_eq!(sent.len(), 1);
        let decoded = ChunkShippingResponse::decode(&sent[0]).expect("decode failed");
        assert_eq!(decoded.status, ChunkResponseStatus::ObjectNotFound);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn receiver_poll_decodes_injected_response() {
        let transport = MemoryChunkTransport::new(7);
        let resp = ChunkShippingResponse::ok(b"injected via transport".to_vec());
        transport.inject_recv(resp.encode());

        let mut receiver = ChunkShippingReceiver::new(Box::new(transport));
        let frames = receiver.poll().expect("poll failed");
        assert_eq!(frames.len(), 1);
        let decoded = ChunkShippingReceiver::try_decode_response(&frames[0]).unwrap();
        assert!(decoded.verify());
        assert_eq!(decoded.payload, b"injected via transport");
    }

    #[test]
    fn receiver_poll_decodes_injected_request() {
        let transport = MemoryChunkTransport::new(77);
        let req = ChunkShippingRequest::new(55, 1024, 512);
        transport.inject_recv(req.encode());

        let mut receiver = ChunkShippingReceiver::new(Box::new(transport));
        let frames = receiver.poll().expect("poll failed");
        assert_eq!(frames.len(), 1);
        let decoded = ChunkShippingReceiver::try_decode_request(&frames[0]).unwrap();
        assert_eq!(decoded.object_id, 55);
        assert_eq!(decoded.offset, 1024);
        assert_eq!(decoded.length, 512);
    }

    #[test]
    fn receiver_poll_no_data_returns_empty() {
        let transport = MemoryChunkTransport::new(1);
        let mut receiver = ChunkShippingReceiver::new(Box::new(transport));
        let frames = receiver.poll().expect("poll failed");
        assert!(frames.is_empty());
    }

    #[test]
    fn receiver_poll_multiple_messages() {
        let transport = MemoryChunkTransport::new(2);
        transport.inject_recv(ChunkShippingRequest::new(1, 0, 100).encode());
        transport.inject_recv(ChunkShippingResponse::ok(b"msg2".to_vec()).encode());

        let mut receiver = ChunkShippingReceiver::new(Box::new(transport));
        let frames = receiver.poll().expect("poll failed");
        assert_eq!(frames.len(), 2);
        assert!(ChunkShippingReceiver::try_decode_request(&frames[0]).is_some());
        assert!(ChunkShippingReceiver::try_decode_response(&frames[1]).is_some());
    }

    #[test]
    fn receiver_feed_direct_bytes_still_works() {
        let transport = MemoryChunkTransport::new(7);
        let mut receiver = ChunkShippingReceiver::new(Box::new(transport));
        let resp = ChunkShippingResponse::ok(b"direct feed".to_vec());
        let encoded = resp.encode();

        // feed() bypasses transport poll, decodes directly
        let frames = receiver.feed(&encoded);
        assert_eq!(frames.len(), 1);
        let decoded = ChunkShippingReceiver::try_decode_response(&frames[0]).unwrap();
        assert!(decoded.verify());
    }

    #[test]
    fn receiver_partial_frame_handling() {
        let transport = MemoryChunkTransport::new(99);
        let resp = ChunkShippingResponse::ok(vec![0xABu8; 256]);
        let encoded = resp.encode();

        // Inject first half of the frame
        let mid = encoded.len() / 2;
        transport.inject_recv(encoded[..mid].to_vec());
        // Inject second half
        transport.inject_recv(encoded[mid..].to_vec());

        let mut receiver = ChunkShippingReceiver::new(Box::new(transport));
        let frames = receiver.poll().expect("poll failed");
        // Partial frame in first poll: decoder buffers, emits nothing
        // Second poll completes the frame
        assert!(
            !frames.is_empty(),
            "should have at least one complete frame"
        );
        // The decoder feeds both halves and should emit the full frame
        let decoded = ChunkShippingReceiver::try_decode_response(&frames[0]).unwrap();
        assert!(decoded.verify());
        assert_eq!(decoded.payload, vec![0xABu8; 256]);
    }

    #[test]
    fn sender_session_id_from_transport() {
        let transport = MemoryChunkTransport::new(12345);
        let sender = ChunkShippingSender::new(Box::new(transport));
        assert_eq!(sender.session_id(), 12345);
    }

    #[test]
    fn receiver_session_id_from_transport() {
        let transport = MemoryChunkTransport::new(9999);
        let receiver = ChunkShippingReceiver::new(Box::new(transport));
        assert_eq!(receiver.session_id(), 9999);
    }

    #[test]
    fn transport_error_display() {
        assert_eq!(
            ChunkTransportError::ChannelFull.to_string(),
            "transport channel full"
        );
        assert_eq!(ChunkTransportError::Closed.to_string(), "transport closed");
        assert_eq!(ChunkTransportError::NoData.to_string(), "no data available");
        assert_eq!(
            ChunkTransportError::IoError("broken pipe".into()).to_string(),
            "transport I/O error: broken pipe"
        );
    }

    // ── SessionChunkTransport production adapter tests ─────────────────

    #[test]
    fn session_transport_send_delivers_to_pipeline() {
        use std::sync::Arc;
        use tidefs_transport::connection_registry::ConnectionState;
        use tidefs_transport::outbound_send::{OutboundFrame, SendPipelineHandle};
        use tidefs_transport::send_scheduler::SendPriority;
        use tokio::sync::RwLock;

        // Create a real SendPipelineHandle backed by a channel
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(SendPriority, OutboundFrame)>(4);
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let handle = Arc::new(SendPipelineHandle::new(state, tx, 4));

        let (transport, _recv_tx) = SessionChunkTransport::new(handle, 99);

        // Send a chunk-shipper response through the transport
        let resp = ChunkShippingResponse::ok(b"production transport test".to_vec());
        let encoded = resp.encode();
        transport
            .send(encoded.clone())
            .expect("send should succeed");

        // Verify the frame arrived on the pipeline channel
        let (priority, frame) = rx.try_recv().expect("should have one frame");
        assert_eq!(priority, SendPriority::Data);

        // The framed data contains a transport envelope header + the chunk-shipper payload
        // The payload should contain our encoded response
        let payload_start = 64; // envelope header size
        assert!(frame.data.len() > payload_start);
        assert_eq!(&frame.data[payload_start..], encoded);
    }

    #[test]
    fn session_transport_try_recv_returns_none_when_empty() {
        use std::sync::Arc;
        use tidefs_transport::connection_registry::ConnectionState;
        use tidefs_transport::outbound_send::{OutboundFrame, SendPipelineHandle};
        use tidefs_transport::send_scheduler::SendPriority;
        use tokio::sync::RwLock;

        let (tx, _rx) = tokio::sync::mpsc::channel::<(SendPriority, OutboundFrame)>(4);
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let handle = Arc::new(SendPipelineHandle::new(state, tx, 4));

        let (mut transport, _recv_tx) = SessionChunkTransport::new(handle, 42);

        // No data injected into recv side
        let result = transport.try_recv().expect("try_recv should not error");
        assert!(result.is_none());
    }

    #[test]
    fn session_transport_try_recv_returns_injected_data() {
        use std::sync::Arc;
        use tidefs_transport::connection_registry::ConnectionState;
        use tidefs_transport::outbound_send::{OutboundFrame, SendPipelineHandle};
        use tidefs_transport::send_scheduler::SendPriority;
        use tokio::sync::RwLock;

        let (tx, _rx) = tokio::sync::mpsc::channel::<(SendPriority, OutboundFrame)>(4);
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let handle = Arc::new(SendPipelineHandle::new(state, tx, 4));

        let (mut transport, recv_tx) = SessionChunkTransport::new(handle, 1);

        // Inject data via the paired sender
        let test_data = b"inbound chunk frame".to_vec();
        recv_tx
            .send(test_data.clone())
            .expect("send should succeed");

        // Poll should return the injected data
        let result = transport.try_recv().expect("try_recv should not error");
        assert_eq!(result, Some(test_data));

        // Second poll returns None
        let result2 = transport.try_recv().expect("try_recv should not error");
        assert!(result2.is_none());
    }

    #[test]
    fn session_transport_session_id() {
        use std::sync::Arc;
        use tidefs_transport::connection_registry::ConnectionState;
        use tidefs_transport::outbound_send::{OutboundFrame, SendPipelineHandle};
        use tidefs_transport::send_scheduler::SendPriority;
        use tokio::sync::RwLock;

        let (tx, _rx) = tokio::sync::mpsc::channel::<(SendPriority, OutboundFrame)>(4);
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let handle = Arc::new(SendPipelineHandle::new(state, tx, 4));

        let (transport, _recv_tx) = SessionChunkTransport::new(handle, 8675309);
        assert_eq!(transport.session_id(), 8675309);
    }

    #[test]
    fn session_transport_send_error_maps_to_chunk_transport_error() {
        use std::sync::Arc;
        use tidefs_transport::connection_registry::ConnectionState;
        use tidefs_transport::outbound_send::{OutboundFrame, SendPipelineHandle};
        use tidefs_transport::send_scheduler::SendPriority;
        use tokio::sync::RwLock;

        // Channel capacity 0 -> immediate ChannelFull on send
        let (tx, _rx) = tokio::sync::mpsc::channel::<(SendPriority, OutboundFrame)>(1);
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let handle = Arc::new(SendPipelineHandle::new(state, tx, 1));

        let (transport, _recv_tx) = SessionChunkTransport::new(handle, 1);

        // Fill the channel
        let resp = ChunkShippingResponse::ok(vec![0xAA; 1024]);
        let encoded = resp.encode();
        transport
            .send(encoded.clone())
            .expect("first send should succeed");

        // Second send should fail with backpressure (ChannelFull)
        let result = transport.send(encoded);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ChunkTransportError::ChannelFull);
    }

    #[test]
    fn session_transport_try_recv_disconnected_returns_closed() {
        use std::sync::Arc;
        use tidefs_transport::connection_registry::ConnectionState;
        use tidefs_transport::outbound_send::{OutboundFrame, SendPipelineHandle};
        use tidefs_transport::send_scheduler::SendPriority;
        use tokio::sync::RwLock;

        let (tx, _rx) = tokio::sync::mpsc::channel::<(SendPriority, OutboundFrame)>(4);
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let handle = Arc::new(SendPipelineHandle::new(state, tx, 4));

        let (mut transport, recv_tx) = SessionChunkTransport::new(handle, 1);

        // Drop the sender to disconnect
        drop(recv_tx);

        // Poll should return Closed error
        let result = transport.try_recv();
        assert_eq!(result, Err(ChunkTransportError::Closed));
    }
}
