//! Object payload transfer over transport sessions.
//!
//! ## Relationship to StateTransfer
//!
//! The existing `StateTransferRequest`/`StateTransferChunk` types in
//! `messages.rs` serve node catch-up: they carry `epoch_id`,
//! `requesting_node`, and `object_ids` for bulk state transfer from
//! an existing node to a joining node.  They assume the receiver
//! already knows the object IDs and just needs data.
//!
//! `ObjectTransferMessage` serves the general object I/O data path:
//! read requests ask for arbitrary byte ranges, write requests push
//! data with acknowledgements, and `transfer_id` provides per-operation
//! correlation independent of epoch/object identity.  Write semantics
//! (`WriteRequest` + `WriteAck`) have no equivalent in `StateTransfer*`.
//!
//! Both families use the same `tidefs-binary_schema-checksum`
//! domain-separated BLAKE3 primitives for payload integrity, and both
//! are routed through `Transport::send_message`/`recv_message`.
//!
//! Defines the wire message types for object read and write requests,
//! their responses, and a `TransferHandle` that pairs requests with
//! responses over an established transport session with chunking for
//! large payloads and timeout/retry guards.
//!
//! ## Message flow
//!
//! ```text
//! Client                          Server
//!   |                                |
//!   |-- ReadRequest(transfer_id) --> |
//!   |                                |
//!   |<-- ReadResponse(chunk 0..N) --|
//!   |                                |
//!   |-- WriteRequest(chunk 0..N) -> |
//!   |                                |
//!   |<-- WriteAck(transfer_id) -----|
//! ```
//!
//! ## Chunking
//!
//! Payloads exceeding `MAX_CHUNK_PAYLOAD` are split across multiple
//! messages. Each chunk carries `chunk_index` and `total_chunks` for
//! reassembly. The receiver reassembles chunks in order and verifies
//! the BLAKE3 domain-separated digest of each chunk before acceptance.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tidefs_binary_schema_checksum::{blake3_domain_digest, blake3_domain_verify};
use tidefs_binary_schema_core::{
    BinarySchemaError, DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion,
};

// ---------------------------------------------------------------------------
// Domain constants for object transfer payload integrity.
// ---------------------------------------------------------------------------

/// Schema family for object transfer messages ("VFOBTX").
const OT_FAMILY: SchemaFamilyId = SchemaFamilyId(0x5646_4F42_5458_0001);

/// Schema type for object transfer payloads.
const OT_TYPE: SchemaTypeId = SchemaTypeId(1);

/// Schema version for object transfer v1.0.
const OT_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Domain tag: ObjectPayloadChunk.
const OT_DOMAIN_TAG: DomainTag = DomainTag::ObjectPayloadChunk;

// ---------------------------------------------------------------------------
// Maximum chunk payload size (1 MiB default).
// ---------------------------------------------------------------------------

/// Maximum payload bytes per chunk message. Payloads larger than this are
/// split across multiple messages.
pub const MAX_CHUNK_PAYLOAD: usize = 1_048_576; // 1 MiB

/// Default request timeout.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum retries for a failed transfer.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

// ---------------------------------------------------------------------------
// ObjectTransferMessage — wire message types
// ---------------------------------------------------------------------------

/// Wire message for object read/write transfer operations.
///
/// Each variant is independently encodable/decodable via bincode.
/// Variants carrying payload data include a BLAKE3 domain-separated
/// digest for per-chunk integrity verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectTransferMessage {
    /// Request to read bytes from an object.
    ReadRequest {
        /// Locally-unique identifier to correlate request with response.
        transfer_id: u64,
        /// Object content key.
        object_key: [u8; 32],
        /// Byte offset within the object.
        offset: u64,
        /// Number of bytes to read.
        length: u64,
    },
    /// Response carrying one chunk of object read data.
    ReadResponse {
        /// Correlates with the originating ReadRequest.
        transfer_id: u64,
        /// Index of this chunk (0-based).
        chunk_index: u32,
        /// Total number of chunks in this response.
        total_chunks: u32,
        /// Total object size in bytes (same across all chunks).
        #[allow(dead_code)]
        total_size: u64,
        /// Chunk payload data.
        payload: Vec<u8>,
        /// Domain-separated BLAKE3 digest of the payload (32 bytes).
        payload_digest: [u8; 32],
    },
    /// Request to write bytes to an object.
    WriteRequest {
        /// Locally-unique identifier to correlate request with response.
        transfer_id: u64,
        /// Object content key.
        object_key: [u8; 32],
        /// Byte offset within the object.
        offset: u64,
        /// Total object size in bytes (same across all chunks).
        #[allow(dead_code)]
        total_size: u64,
        /// Index of this chunk (0-based).
        chunk_index: u32,
        /// Total number of chunks in this write.
        total_chunks: u32,
        /// Chunk payload data.
        payload: Vec<u8>,
        /// Domain-separated BLAKE3 digest of the payload (32 bytes).
        payload_digest: [u8; 32],
    },
    /// Acknowledgement of a completed write.
    WriteAck {
        /// Correlates with the originating WriteRequest.
        transfer_id: u64,
        /// Total bytes written.
        bytes_written: u64,
        /// Status of the write operation.
        status: WriteStatus,
    },
    /// Request to delete an object across replicas.
    DeleteObjectRequest {
        /// Locally-unique identifier to correlate request with response.
        transfer_id: u64,
        /// Object content key.
        object_key: [u8; 32],
        /// Monotonic generation counter to prevent delete-write races.
        generation: u64,
    },
    /// Response confirming or denying a delete.
    DeleteObjectResponse {
        transfer_id: u64,
        object_key: [u8; 32],
        /// Whether the object was found and deleted.
        deleted: bool,
        /// The current generation counter of the object on this replica.
        generation: u64,
    },
}

/// Outcome of a write operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WriteStatus {
    /// Write completed successfully.
    Ok,
    /// Write failed due to insufficient space.
    NoSpace { available: u64, needed: u64 },
    /// Write failed due to an I/O error.
    IoError,
    /// Write failed: object key collision (object already exists with different content).
    KeyCollision,
    /// Write rejected by policy.
    Rejected,
}

impl ObjectTransferMessage {
    /// Encode to binary via bincode.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Decode from binary via bincode.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Return true if this message carries payload data.
    pub fn has_payload(&self) -> bool {
        matches!(self, Self::ReadResponse { .. } | Self::WriteRequest { .. })
    }

    /// Verify the payload digest for messages that carry payloads.
    ///
    /// Returns `Ok(())` if the payload matches its digest, or
    /// `BinarySchemaError::DigestMismatch` on failure.
    /// Messages without payloads trivially return `Ok(())`.
    pub fn verify_payload(&self) -> Result<(), BinarySchemaError> {
        let (payload, digest) = match self {
            Self::ReadResponse {
                ref payload,
                payload_digest,
                ..
            }
            | Self::WriteRequest {
                ref payload,
                payload_digest,
                ..
            } => (payload, payload_digest),
            _ => return Ok(()),
        };
        blake3_domain_verify(
            payload,
            digest,
            OT_FAMILY,
            OT_TYPE,
            OT_VERSION,
            OT_DOMAIN_TAG,
        )
    }

    /// Return the transfer_id for this message.
    pub fn transfer_id(&self) -> u64 {
        match self {
            Self::ReadRequest { transfer_id, .. }
            | Self::ReadResponse { transfer_id, .. }
            | Self::WriteRequest { transfer_id, .. }
            | Self::WriteAck { transfer_id, .. }
            | Self::DeleteObjectRequest { transfer_id, .. }
            | Self::DeleteObjectResponse { transfer_id, .. } => *transfer_id,
        }
    }

    /// Discriminant label for logging/tracing.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ReadRequest { .. } => "ReadRequest",
            Self::ReadResponse { .. } => "ReadResponse",
            Self::WriteRequest { .. } => "WriteRequest",
            Self::WriteAck { .. } => "WriteAck",
            Self::DeleteObjectRequest { .. } => "DeleteObjectRequest",
            Self::DeleteObjectResponse { .. } => "DeleteObjectResponse",
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers for constructing messages with BLAKE3 payload digests
// ---------------------------------------------------------------------------

/// Compute the domain-separated BLAKE3 digest for a chunk payload.
fn compute_payload_digest(payload: &[u8]) -> [u8; 32] {
    blake3_domain_digest(payload, OT_FAMILY, OT_TYPE, OT_VERSION, OT_DOMAIN_TAG)
}

impl ObjectTransferMessage {
    /// Create a new ReadRequest.
    #[must_use]
    pub fn read_request(transfer_id: u64, object_key: [u8; 32], offset: u64, length: u64) -> Self {
        Self::ReadRequest {
            transfer_id,
            object_key,
            offset,
            length,
        }
    }

    /// Create a new ReadResponse with payload, computing the BLAKE3 digest.
    #[must_use]
    pub fn read_response(
        transfer_id: u64,
        chunk_index: u32,
        total_chunks: u32,
        total_size: u64,
        payload: Vec<u8>,
    ) -> Self {
        let payload_digest = compute_payload_digest(&payload);
        Self::ReadResponse {
            transfer_id,
            chunk_index,
            total_chunks,
            total_size,
            payload,
            payload_digest,
        }
    }

    /// Create a new WriteRequest with payload, computing the BLAKE3 digest.
    #[must_use]
    pub fn write_request(
        transfer_id: u64,
        object_key: [u8; 32],
        offset: u64,
        total_size: u64,
        chunk_index: u32,
        total_chunks: u32,
        payload: Vec<u8>,
    ) -> Self {
        let payload_digest = compute_payload_digest(&payload);
        Self::WriteRequest {
            transfer_id,
            object_key,
            offset,
            total_size,
            chunk_index,
            total_chunks,
            payload,
            payload_digest,
        }
    }

    /// Create a new WriteAck.
    #[must_use]
    pub fn write_ack(transfer_id: u64, bytes_written: u64, status: WriteStatus) -> Self {
        Self::WriteAck {
            transfer_id,
            bytes_written,
            status,
        }
    }

    /// Create a new DeleteObjectRequest.
    #[must_use]
    pub fn delete_request(transfer_id: u64, object_key: [u8; 32], generation: u64) -> Self {
        Self::DeleteObjectRequest {
            transfer_id,
            object_key,
            generation,
        }
    }

    /// Create a new DeleteObjectResponse.
    #[must_use]
    pub fn delete_response(
        transfer_id: u64,
        object_key: [u8; 32],
        deleted: bool,
        generation: u64,
    ) -> Self {
        Self::DeleteObjectResponse {
            transfer_id,
            object_key,
            deleted,
            generation,
        }
    }
}

// ---------------------------------------------------------------------------
// Chunking helpers
// ---------------------------------------------------------------------------

/// Split a payload into chunked ReadResponse messages.
///
/// Returns a vector of `(chunk_index, total_chunks, payload)` tuples.
/// If the payload is smaller than `max_chunk`, returns a single chunk.
#[must_use]
pub fn chunk_payload(payload: &[u8], max_chunk: usize) -> Vec<(u32, u32, Vec<u8>)> {
    if payload.is_empty() {
        return vec![(0, 1, vec![])];
    }
    let total_chunks = payload.len().div_ceil(max_chunk).max(1);
    let total_chunks_u32 = total_chunks as u32;
    let mut chunks = Vec::with_capacity(total_chunks);
    for (i, chunk_bytes) in payload.chunks(max_chunk).enumerate() {
        chunks.push((i as u32, total_chunks_u32, chunk_bytes.to_vec()));
    }
    chunks
}

/// Reassemble chunks into a single payload, verifying each chunk's digest.
///
/// Expects chunks to arrive in order (`chunk_index` must be the next
/// expected index). Returns the fully assembled payload on success.
///
/// # Errors
///
/// Returns an error if a chunk fails digest verification, arrives out
/// of order, or has an unexpected chunk count.
pub struct ChunkReassembler {
    total_chunks: u32,
    next_index: u32,
    #[allow(dead_code)]
    total_size: u64,
    buffer: Vec<u8>,
}

impl ChunkReassembler {
    /// Start reassembly from the first chunk.
    #[must_use]
    pub fn new(total_chunks: u32, total_size: u64) -> Self {
        Self {
            total_chunks,
            next_index: 0,
            total_size,
            buffer: Vec::with_capacity(total_size as usize),
        }
    }

    /// Feed a chunk into the reassembler.
    ///
    /// Verifies the payload digest and checks ordering. Returns
    /// `Ok(true)` if reassembly is complete, `Ok(false)` if more
    /// chunks are expected, or an error on digest/order failure.
    pub fn feed(
        &mut self,
        chunk_index: u32,
        total_chunks: u32,
        payload: &[u8],
        digest: &[u8; 32],
    ) -> Result<bool, ChunkReassemblyError> {
        if total_chunks != self.total_chunks {
            return Err(ChunkReassemblyError::TotalChunksChanged {
                expected: self.total_chunks,
                got: total_chunks,
            });
        }
        if chunk_index != self.next_index {
            return Err(ChunkReassemblyError::OutOfOrder {
                expected: self.next_index,
                got: chunk_index,
            });
        }
        // Verify digest
        blake3_domain_verify(
            payload,
            digest,
            OT_FAMILY,
            OT_TYPE,
            OT_VERSION,
            OT_DOMAIN_TAG,
        )
        .map_err(|_| ChunkReassemblyError::DigestMismatch { chunk_index })?;
        self.buffer.extend_from_slice(payload);
        self.next_index += 1;
        Ok(self.next_index >= self.total_chunks)
    }

    /// Return the assembled payload (only valid after `feed` returned `Ok(true)`).
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.buffer
    }
}

/// Errors during chunk reassembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkReassemblyError {
    /// Total chunks count changed between messages.
    TotalChunksChanged { expected: u32, got: u32 },
    /// Chunk arrived out of order.
    OutOfOrder { expected: u32, got: u32 },
    /// Chunk payload digest verification failed.
    DigestMismatch { chunk_index: u32 },
}

impl std::fmt::Display for ChunkReassemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TotalChunksChanged { expected, got } => {
                write!(f, "total chunks changed: expected {expected}, got {got}")
            }
            Self::OutOfOrder { expected, got } => {
                write!(f, "chunk out of order: expected {expected}, got {got}")
            }
            Self::DigestMismatch { chunk_index } => {
                write!(f, "digest mismatch in chunk {chunk_index}")
            }
        }
    }
}

impl std::error::Error for ChunkReassemblyError {}

// ---------------------------------------------------------------------------
// TransferHandle — request/response pairing with timeout
// ---------------------------------------------------------------------------

/// State of a single in-flight transfer.
#[derive(Debug, Clone)]
pub(crate) struct PendingTransfer {
    /// When this transfer was initiated.
    started_at: Instant,
    /// Number of retries so far.
    retries: u32,
    /// Transfer timeout.
    timeout: Duration,
    /// Maximum retries.
    max_retries: u32,
    /// The original request message (for retransmission).
    request: ObjectTransferMessage,
}

/// Handles request/response pairing for object transfers over a transport.
///
/// Tracks in-flight requests, enforces timeouts, and handles retry logic.
/// The actual send/recv operations are performed by the caller; this
/// struct manages the correlation and state machine.
pub struct TransferHandle {
    /// Next transfer ID to assign.
    next_transfer_id: u64,
    /// Pending outbound transfers keyed by transfer_id.
    pending: BTreeMap<u64, PendingTransfer>,
    /// Default timeout for new transfers.
    default_timeout: Duration,
    /// Default max retries.
    default_max_retries: u32,
}

impl TransferHandle {
    /// Create a new TransferHandle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_transfer_id: 1,
            pending: BTreeMap::new(),
            default_timeout: DEFAULT_REQUEST_TIMEOUT,
            default_max_retries: DEFAULT_MAX_RETRIES,
        }
    }

    /// Create with custom timeout and retry limits.
    #[must_use]
    pub fn with_limits(timeout: Duration, max_retries: u32) -> Self {
        Self {
            next_transfer_id: 1,
            pending: BTreeMap::new(),
            default_timeout: timeout,
            default_max_retries: max_retries,
        }
    }

    /// Allocate the next transfer ID and register a pending request.
    ///
    /// Returns the transfer_id that must be embedded in the request message.
    /// The caller is responsible for serializing and sending the message.
    pub fn register_request(&mut self, request: ObjectTransferMessage) -> u64 {
        let transfer_id = self.next_transfer_id;
        self.next_transfer_id = self.next_transfer_id.wrapping_add(1);
        self.pending.insert(
            transfer_id,
            PendingTransfer {
                started_at: Instant::now(),
                retries: 0,
                timeout: self.default_timeout,
                max_retries: self.default_max_retries,
                request,
            },
        );
        transfer_id
    }

    /// Register a response received from the peer.
    ///
    /// If the response matches a pending request, returns the original
    /// request and the response (both parsed). The pending entry is
    /// removed on success.
    ///
    /// Returns `None` if the `transfer_id` is not in the pending set
    /// (stale or duplicate response).
    /// Look up a pending transfer by its transfer_id.
    ///
    /// Returns a clone of the original request if found (for the caller to
    /// correlate with the response), or None if no pending transfer matches
    /// this id (stale or duplicate response).
    pub fn lookup_pending(&self, transfer_id: u64) -> Option<ObjectTransferMessage> {
        self.pending.get(&transfer_id).map(|p| p.request.clone())
    }

    /// Complete a transfer (remove from pending).
    pub fn complete(&mut self, transfer_id: u64) -> Option<ObjectTransferMessage> {
        self.pending.remove(&transfer_id).map(|p| p.request)
    }

    /// Check for timed-out transfers. Returns a list of `(transfer_id,
    /// &request)` pairs that have exceeded their timeout and should be
    /// retried (if retries remain) or failed.
    pub fn check_timeouts(&mut self) -> Vec<(u64, TransferTimeoutAction)> {
        let now = Instant::now();
        let mut actions = Vec::new();
        let mut completed = Vec::new();

        for (&id, pending) in &self.pending {
            if now.duration_since(pending.started_at) >= pending.timeout {
                if pending.retries < pending.max_retries {
                    actions.push((
                        id,
                        TransferTimeoutAction::Retry {
                            attempt: pending.retries + 1,
                        },
                    ));
                } else {
                    actions.push((
                        id,
                        TransferTimeoutAction::Failed {
                            reason: format!(
                                "timeout after {} retries ({:?})",
                                pending.retries, pending.timeout
                            ),
                        },
                    ));
                    completed.push(id);
                }
            }
        }

        for id in completed {
            self.pending.remove(&id);
        }

        actions
    }

    /// Retry a transfer: resets its timer and increments the retry counter.
    ///
    /// Returns the original request message for retransmission.
    pub fn retry(&mut self, transfer_id: u64) -> Option<ObjectTransferMessage> {
        let pending = self.pending.get_mut(&transfer_id)?;
        pending.started_at = Instant::now();
        pending.retries += 1;
        Some(pending.request.clone())
    }

    /// Number of pending transfers.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Whether there are any pending transfers.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Get the next transfer ID without allocating.
    #[must_use]
    pub fn next_id(&self) -> u64 {
        self.next_transfer_id
    }
}

impl Default for TransferHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TransferHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferHandle")
            .field("next_transfer_id", &self.next_transfer_id)
            .field("pending_count", &self.pending.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// TransferTimeoutAction
// ---------------------------------------------------------------------------

/// Action to take when a transfer times out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferTimeoutAction {
    /// Retry the request.
    Retry {
        /// Which retry attempt this is (1-based).
        attempt: u32,
    },
    /// The transfer has failed permanently.
    Failed {
        /// Human-readable failure reason.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Send/receive helpers for chunked object transfers
// ---------------------------------------------------------------------------

/// Chunk a read request's payload into ReadResponse messages.
///
/// Convenience wrapper: creates a slice of ReadResponse messages from
/// a full payload with the given transfer_id.
#[must_use]
pub fn build_read_responses(
    transfer_id: u64,
    total_size: u64,
    payload: &[u8],
    max_chunk: usize,
) -> Vec<ObjectTransferMessage> {
    let chunks = chunk_payload(payload, max_chunk);
    let total = chunks.first().map(|c| c.1).unwrap_or(0);
    chunks
        .into_iter()
        .map(|(idx, _total, data)| {
            ObjectTransferMessage::read_response(transfer_id, idx, total, total_size, data)
        })
        .collect()
}

/// Chunk a write payload into WriteRequest messages.
#[must_use]
pub fn build_write_requests(
    transfer_id: u64,
    object_key: [u8; 32],
    offset: u64,
    total_size: u64,
    payload: &[u8],
    max_chunk: usize,
) -> Vec<ObjectTransferMessage> {
    let chunks = chunk_payload(payload, max_chunk);
    let total = chunks.first().map(|c| c.1).unwrap_or(0);
    chunks
        .into_iter()
        .map(|(idx, _total, data)| {
            ObjectTransferMessage::write_request(
                transfer_id,
                object_key,
                offset + (idx as u64 * max_chunk as u64),
                total_size,
                idx,
                total,
                data,
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Message encode/decode round-trip ────────────────────────────

    #[test]
    fn read_request_roundtrip() {
        let req = ObjectTransferMessage::read_request(42, [0xAB; 32], 4096, 8192);
        let encoded = req.encode().unwrap();
        let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(decoded.transfer_id(), 42);
        assert_eq!(decoded.kind(), "ReadRequest");
    }

    #[test]
    fn read_response_roundtrip() {
        let payload = b"test read response payload".to_vec();
        let resp = ObjectTransferMessage::read_response(7, 0, 1, payload.len() as u64, payload);
        let encoded = resp.encode().unwrap();
        let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);
        assert!(decoded.verify_payload().is_ok());
    }

    #[test]
    fn write_request_roundtrip() {
        let payload = b"write chunk data".to_vec();
        let req = ObjectTransferMessage::write_request(
            99,
            [0xCD; 32],
            0,
            payload.len() as u64,
            0,
            1,
            payload,
        );
        let encoded = req.encode().unwrap();
        let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
        assert!(decoded.verify_payload().is_ok());
    }

    #[test]
    fn write_ack_roundtrip() {
        let ack = ObjectTransferMessage::write_ack(10, 4096, WriteStatus::Ok);
        let encoded = ack.encode().unwrap();
        let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, ack);
        assert_eq!(decoded.transfer_id(), 10);
        assert_eq!(decoded.kind(), "WriteAck");
    }

    #[test]
    fn write_ack_nospace_roundtrip() {
        let ack = ObjectTransferMessage::write_ack(
            3,
            0,
            WriteStatus::NoSpace {
                available: 1024,
                needed: 8192,
            },
        );
        let encoded = ack.encode().unwrap();
        let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
        assert!(matches!(
            decoded,
            ObjectTransferMessage::WriteAck {
                status: WriteStatus::NoSpace {
                    available: 1024,
                    needed: 8192
                },
                ..
            }
        ));
    }

    #[test]
    fn empty_payload_roundtrip() {
        let req = ObjectTransferMessage::write_request(1, [0; 32], 0, 0, 0, 1, vec![]);
        let encoded = req.encode().unwrap();
        let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
        assert!(decoded.verify_payload().is_ok());
    }

    // ── Payload digest verification ──────────────────────────────────

    #[test]
    fn verify_payload_succeeds() {
        let resp = ObjectTransferMessage::read_response(1, 0, 1, 4, b"data".to_vec());
        assert!(resp.verify_payload().is_ok());
    }

    #[test]
    fn verify_payload_fails_for_tampered_data() {
        let mut resp = ObjectTransferMessage::read_response(1, 0, 1, 4, b"data".to_vec());
        match &mut resp {
            ObjectTransferMessage::ReadResponse { payload, .. } => {
                payload[0] ^= 0xFF;
            }
            _ => unreachable!(),
        }
        assert!(resp.verify_payload().is_err());
    }

    #[test]
    fn verify_payload_trivial_for_non_payload_messages() {
        let req = ObjectTransferMessage::read_request(1, [0; 32], 0, 1024);
        assert!(req.verify_payload().is_ok());

        let ack = ObjectTransferMessage::write_ack(1, 0, WriteStatus::Ok);
        assert!(ack.verify_payload().is_ok());
    }

    #[test]
    fn has_payload_detects_correctly() {
        assert!(!ObjectTransferMessage::read_request(1, [0; 32], 0, 1).has_payload());
        assert!(ObjectTransferMessage::read_response(1, 0, 1, 4, b"x".to_vec()).has_payload());
        assert!(
            ObjectTransferMessage::write_request(1, [0; 32], 0, 4, 0, 1, b"x".to_vec())
                .has_payload()
        );
        assert!(!ObjectTransferMessage::write_ack(1, 0, WriteStatus::Ok).has_payload());
    }

    // ── Chunking ──────────────────────────────────────────────────────

    #[test]
    fn chunk_payload_single_exact() {
        let data = vec![0xAAu8; 1024];
        let chunks = chunk_payload(&data, 1024);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[0].1, 1);
        assert_eq!(chunks[0].2, data);
    }

    #[test]
    fn chunk_payload_single_small() {
        let data = b"hello".to_vec();
        let chunks = chunk_payload(&data, 1024);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].2, b"hello");
    }

    #[test]
    fn chunk_payload_multi() {
        let data = vec![0xBBu8; 2500];
        let chunks = chunk_payload(&data, 1024);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[0].1, 3);
        assert_eq!(chunks[0].2.len(), 1024);
        assert_eq!(chunks[1].0, 1);
        assert_eq!(chunks[1].1, 3);
        assert_eq!(chunks[1].2.len(), 1024);
        assert_eq!(chunks[2].0, 2);
        assert_eq!(chunks[2].1, 3);
        assert_eq!(chunks[2].2.len(), 452);
    }

    #[test]
    fn chunk_payload_empty() {
        let chunks = chunk_payload(&[], 1024);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[0].1, 1);
        assert!(chunks[0].2.is_empty());
    }

    #[test]
    fn chunk_payload_boundary_exact_multiple() {
        let data = vec![0xCCu8; 2048];
        let chunks = chunk_payload(&data, 1024);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].2.len(), 1024);
        assert_eq!(chunks[1].2.len(), 1024);
    }

    // ── ChunkReassembler ──────────────────────────────────────────────

    #[test]
    fn reassembler_single_chunk() {
        let payload = b"single chunk data".to_vec();
        let digest = compute_payload_digest(&payload);
        let mut reassembler = ChunkReassembler::new(1, payload.len() as u64);
        let done = reassembler.feed(0, 1, &payload, &digest).unwrap();
        assert!(done);
        assert_eq!(reassembler.into_payload(), payload);
    }

    #[test]
    fn reassembler_multi_chunk() {
        let part1 = vec![0x11u8; 500];
        let part2 = vec![0x22u8; 500];
        let part3 = vec![0x33u8; 200];
        let d1 = compute_payload_digest(&part1);
        let d2 = compute_payload_digest(&part2);
        let d3 = compute_payload_digest(&part3);

        let total_size = (part1.len() + part2.len() + part3.len()) as u64;
        let mut reassembler = ChunkReassembler::new(3, total_size);

        assert!(!reassembler.feed(0, 3, &part1, &d1).unwrap());
        assert!(!reassembler.feed(1, 3, &part2, &d2).unwrap());
        assert!(reassembler.feed(2, 3, &part3, &d3).unwrap());

        let assembled = reassembler.into_payload();
        assert_eq!(assembled.len(), 1200);
        assert_eq!(&assembled[..500], &part1[..]);
        assert_eq!(&assembled[500..1000], &part2[..]);
        assert_eq!(&assembled[1000..], &part3[..]);
    }

    #[test]
    fn reassembler_wrong_digest_rejected() {
        let payload = b"legit".to_vec();
        let mut digest = compute_payload_digest(&payload);
        digest[0] ^= 0xFF; // tamper
        let mut reassembler = ChunkReassembler::new(1, 5);
        let err = reassembler.feed(0, 1, &payload, &digest).unwrap_err();
        assert!(matches!(err, ChunkReassemblyError::DigestMismatch { .. }));
    }

    #[test]
    fn reassembler_out_of_order_rejected() {
        let p1 = b"first".to_vec();
        let _d1 = compute_payload_digest(&p1);
        let p2 = b"second".to_vec();
        let d2 = compute_payload_digest(&p2);
        let mut reassembler = ChunkReassembler::new(2, 11);
        // Feed chunk 1 before chunk 0
        let err = reassembler.feed(1, 2, &p2, &d2).unwrap_err();
        assert!(matches!(
            err,
            ChunkReassemblyError::OutOfOrder {
                expected: 0,
                got: 1
            }
        ));
    }

    #[test]
    fn reassembler_total_chunks_changed_rejected() {
        let p1 = b"first".to_vec();
        let d1 = compute_payload_digest(&p1);
        let mut reassembler = ChunkReassembler::new(2, 10);
        let err = reassembler.feed(0, 3, &p1, &d1).unwrap_err();
        assert!(matches!(
            err,
            ChunkReassemblyError::TotalChunksChanged {
                expected: 2,
                got: 3
            }
        ));
    }

    // ── TransferHandle ────────────────────────────────────────────────

    #[test]
    fn transfer_handle_register_and_complete() {
        let mut handle = TransferHandle::new();
        let req = ObjectTransferMessage::read_request(0, [0; 32], 0, 4096);
        let id = handle.register_request(req.clone());
        assert_eq!(id, 1);
        assert_eq!(handle.pending_count(), 1);

        let completed = handle.complete(id);
        assert_eq!(completed, Some(req));
        assert_eq!(handle.pending_count(), 0);
    }

    #[test]
    fn transfer_handle_ids_are_monotonic() {
        let mut handle = TransferHandle::new();
        let req = ObjectTransferMessage::read_request(0, [0; 32], 0, 1);
        assert_eq!(handle.register_request(req.clone()), 1);
        assert_eq!(handle.register_request(req.clone()), 2);
        assert_eq!(handle.register_request(req.clone()), 3);
        assert_eq!(handle.pending_count(), 3);
    }

    #[test]
    fn transfer_handle_complete_stale_returns_none() {
        let mut handle = TransferHandle::new();
        assert!(handle.complete(999).is_none());
    }

    #[test]
    fn transfer_handle_response_registration() {
        let mut handle = TransferHandle::new();
        let req = ObjectTransferMessage::read_request(0, [0; 32], 0, 1);
        let id = handle.register_request(req.clone());
        let pending = handle.lookup_pending(id);
        assert!(pending.is_some());
        assert_eq!(pending.unwrap(), req);
    }

    #[test]
    fn transfer_handle_retry() {
        let mut handle = TransferHandle::new();
        let req = ObjectTransferMessage::read_request(0, [0; 32], 0, 1);
        let id = handle.register_request(req.clone());
        let retried = handle.retry(id);
        assert_eq!(retried, Some(req));
        // Should still be pending
        assert_eq!(handle.pending_count(), 1);
    }

    #[test]
    fn transfer_handle_retry_stale_returns_none() {
        let mut handle = TransferHandle::new();
        assert!(handle.retry(999).is_none());
    }

    #[test]
    fn transfer_handle_timeout_with_zero_duration() {
        let mut handle = TransferHandle::with_limits(Duration::from_millis(0), 2);
        let req = ObjectTransferMessage::read_request(0, [0; 32], 0, 1);
        handle.register_request(req);
        // Small sleep to get past zero timeout
        std::thread::sleep(Duration::from_millis(1));
        let actions = handle.check_timeouts();
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0].1,
            TransferTimeoutAction::Retry { attempt: 1 }
        ));
    }

    #[test]
    fn transfer_handle_timeout_exhausts_retries() {
        // Use zero timeout and zero max retries
        let mut handle = TransferHandle::with_limits(Duration::from_millis(0), 0);
        let req = ObjectTransferMessage::read_request(0, [0; 32], 0, 1);
        handle.register_request(req);
        std::thread::sleep(Duration::from_millis(1));
        let actions = handle.check_timeouts();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0].1, TransferTimeoutAction::Failed { .. }));
        // Transfer should be removed from pending
        assert_eq!(handle.pending_count(), 0);
    }

    #[test]
    fn transfer_handle_normal_timeout_does_not_fire() {
        let mut handle = TransferHandle::with_limits(Duration::from_secs(3600), 3);
        let req = ObjectTransferMessage::read_request(0, [0; 32], 0, 1);
        handle.register_request(req);
        let actions = handle.check_timeouts();
        assert!(actions.is_empty());
    }

    #[test]
    fn transfer_handle_has_pending() {
        let mut handle = TransferHandle::new();
        assert!(!handle.has_pending());
        handle.register_request(ObjectTransferMessage::read_request(0, [0; 32], 0, 1));
        assert!(handle.has_pending());
        handle.complete(1);
        assert!(!handle.has_pending());
    }

    // ── build_read_responses / build_write_requests ───────────────────

    #[test]
    fn build_read_responses_single_chunk() {
        let payload = b"hello".to_vec();
        let msgs = build_read_responses(1, payload.len() as u64, &payload, 1024);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            ObjectTransferMessage::ReadResponse {
                transfer_id,
                chunk_index,
                total_chunks,
                total_size,
                payload: p,
                ..
            } => {
                assert_eq!(*transfer_id, 1);
                assert_eq!(*chunk_index, 0);
                assert_eq!(*total_chunks, 1);
                assert_eq!(*total_size, 5);
                assert_eq!(p, b"hello");
            }
            _ => panic!("expected ReadResponse"),
        }
    }

    #[test]
    fn build_read_responses_multi_chunk() {
        let payload = vec![0xDDu8; 2500];
        let msgs = build_read_responses(42, payload.len() as u64, &payload, 1024);
        assert_eq!(msgs.len(), 3);
        for (i, msg) in msgs.iter().enumerate() {
            match msg {
                ObjectTransferMessage::ReadResponse {
                    transfer_id,
                    chunk_index,
                    total_chunks,
                    ..
                } => {
                    assert_eq!(*transfer_id, 42);
                    assert_eq!(*chunk_index, i as u32);
                    assert_eq!(*total_chunks, 3);
                }
                _ => panic!("expected ReadResponse"),
            }
        }
    }

    #[test]
    fn build_write_requests_multi_chunk() {
        let payload = vec![0xEEu8; 3000];
        let msgs = build_write_requests(7, [0x99; 32], 0, payload.len() as u64, &payload, 1024);
        assert_eq!(msgs.len(), 3);
        for msg in &msgs {
            assert!(msg.verify_payload().is_ok());
        }
    }

    // ── WriteStatus variants ──────────────────────────────────────────

    #[test]
    fn write_status_all_variants_roundtrip() {
        let variants = vec![
            WriteStatus::Ok,
            WriteStatus::NoSpace {
                available: 100,
                needed: 200,
            },
            WriteStatus::IoError,
            WriteStatus::KeyCollision,
            WriteStatus::Rejected,
        ];
        for status in variants {
            let msg = ObjectTransferMessage::write_ack(1, 0, status);
            let encoded = msg.encode().unwrap();
            let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    // ── Large payload chunking ────────────────────────────────────────

    #[test]
    fn chunk_reassembly_large_50_chunks() {
        let payload = vec![0xABu8; 50 * 1024]; // 50 chunks of 1024
        let chunks = chunk_payload(&payload, 1024);
        assert_eq!(chunks.len(), 50);

        let mut reassembler = ChunkReassembler::new(50, payload.len() as u64);
        for (i, (_chunk_idx, _total, chunk_data)) in chunks.iter().enumerate() {
            let digest = compute_payload_digest(chunk_data);
            let done = reassembler.feed(i as u32, 50, chunk_data, &digest).unwrap();
            if i == 49 {
                assert!(done, "reassembly should complete on last chunk");
            } else {
                assert!(!done, "reassembly should not be done before last chunk");
            }
        }
        assert_eq!(reassembler.into_payload(), payload);
    }

    // ── Concurrent transfers ──────────────────────────────────────────

    #[test]
    fn transfer_handle_concurrent_transfers() {
        let mut handle = TransferHandle::new();
        let req = ObjectTransferMessage::read_request(0, [0; 32], 0, 1);
        for i in 0..4 {
            handle.register_request(req.clone());
            assert_eq!(handle.next_id(), i + 2);
        }
        assert_eq!(handle.pending_count(), 4);
        handle.complete(1);
        handle.complete(2);
        handle.complete(3);
        handle.complete(4);
        assert_eq!(handle.pending_count(), 0);
    }

    // ── ObjectTransferMessage kind ────────────────────────────────────

    #[test]
    fn message_kind_labels() {
        assert_eq!(
            ObjectTransferMessage::read_request(1, [0; 32], 0, 1).kind(),
            "ReadRequest"
        );
        assert_eq!(
            ObjectTransferMessage::read_response(1, 0, 1, 0, vec![]).kind(),
            "ReadResponse"
        );
        assert_eq!(
            ObjectTransferMessage::write_request(1, [0; 32], 0, 0, 0, 1, vec![]).kind(),
            "WriteRequest"
        );
        assert_eq!(
            ObjectTransferMessage::write_ack(1, 0, WriteStatus::Ok).kind(),
            "WriteAck"
        );
    }

    // ── Delete message round-trip tests ───────────────────────────

    #[test]
    fn delete_request_roundtrip() {
        let req = ObjectTransferMessage::delete_request(99, [0xCD; 32], 7);
        let encoded = req.encode().unwrap();
        let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(decoded.transfer_id(), 99);
        assert_eq!(decoded.kind(), "DeleteObjectRequest");
        assert!(!decoded.has_payload());
        assert!(decoded.verify_payload().is_ok());
    }

    #[test]
    fn delete_response_roundtrip() {
        let resp = ObjectTransferMessage::delete_response(99, [0xCD; 32], true, 7);
        let encoded = resp.encode().unwrap();
        let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);
        assert_eq!(decoded.transfer_id(), 99);
        assert_eq!(decoded.kind(), "DeleteObjectResponse");
        assert!(!decoded.has_payload());
        assert!(decoded.verify_payload().is_ok());
    }

    #[test]
    fn delete_response_not_found_roundtrip() {
        let resp = ObjectTransferMessage::delete_response(42, [0xAB; 32], false, 0);
        let encoded = resp.encode().unwrap();
        let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.kind(), "DeleteObjectResponse");
        // deleted=false, generation=0
        assert!(!decoded.has_payload());
    }

    #[test]
    fn delete_request_generation_distinct() {
        let req1 = ObjectTransferMessage::delete_request(1, [0xFF; 32], 5);
        let req2 = ObjectTransferMessage::delete_request(1, [0xFF; 32], 6);
        let enc1 = req1.encode().unwrap();
        let enc2 = req2.encode().unwrap();
        assert_ne!(
            enc1, enc2,
            "different generations must produce different encodings"
        );
    }

    #[test]
    fn delete_transfer_id_correlation() {
        let resp = ObjectTransferMessage::delete_response(77, [0xEE; 32], true, 3);
        assert_eq!(resp.transfer_id(), 77);
        let write_req =
            ObjectTransferMessage::write_request(77, [0xEE; 32], 0, 100, 0, 1, vec![1, 2, 3]);
        assert_eq!(write_req.transfer_id(), resp.transfer_id());
        assert_ne!(write_req.kind(), resp.kind());
    }
}

// ---------------------------------------------------------------------------
// TransferDispatch — production wire path over Transport sessions
// ---------------------------------------------------------------------------

/// Error type for transfer dispatch operations.
#[derive(Debug)]
pub enum TransferDispatchError {
    /// Underlying transport error.
    Transport(String),
    /// Message encode error (bincode).
    Encode(String),
    /// Message decode error (bincode).
    Decode(String),
    /// No pending transfer matches the received response.
    StaleTransfer(u64),
    /// Chunk reassembly failed.
    Reassembly(ChunkReassemblyError),
    /// Transfer timed out.
    Timeout(u64),
    /// Payload digest verification failed.
    DigestMismatch,
    /// Write was rejected by the peer.
    WriteRejected(WriteStatus),
}

impl std::fmt::Display for TransferDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::Encode(e) => write!(f, "encode error: {e}"),
            Self::Decode(e) => write!(f, "decode error: {e}"),
            Self::StaleTransfer(id) => write!(f, "stale transfer {id}"),
            Self::Reassembly(e) => write!(f, "reassembly error: {e}"),
            Self::Timeout(id) => write!(f, "transfer {id} timed out"),
            Self::DigestMismatch => write!(f, "payload digest mismatch"),
            Self::WriteRejected(s) => write!(f, "write rejected: {s:?}"),
        }
    }
}

impl std::error::Error for TransferDispatchError {}

impl From<crate::error::TransportError> for TransferDispatchError {
    fn from(e: crate::error::TransportError) -> Self {
        Self::Transport(e.to_string())
    }
}

impl From<ChunkReassemblyError> for TransferDispatchError {
    fn from(e: ChunkReassemblyError) -> Self {
        Self::Reassembly(e)
    }
}

/// Dispatch a read request over a transport session.
///
/// Encodes a `ReadRequest` and sends it via `Transport::send_message`.
/// Returns the `transfer_id` for correlating with the response.
///
/// The caller must later call `recv_read_response` to collect chunks
/// and reassemble the payload, or call `handle.check_timeouts()` to
/// detect timed-out transfers.
pub fn dispatch_read_request(
    transport: &mut crate::transport::Transport,
    handle: &mut TransferHandle,
    session_id: crate::types::SessionId,
    object_key: [u8; 32],
    offset: u64,
    length: u64,
) -> Result<u64, TransferDispatchError> {
    let msg = ObjectTransferMessage::read_request(0, object_key, offset, length);
    let tid = handle.register_request(msg.clone());

    let req = ObjectTransferMessage::read_request(tid, object_key, offset, length);
    let encoded = req
        .encode()
        .map_err(|e| TransferDispatchError::Encode(e.to_string()))?;
    transport.send_message(session_id, &encoded)?;
    Ok(tid)
}

/// Receive read response chunks over a transport session and reassemble
/// the full payload.
///
/// Blocks until all chunks for `transfer_id` are received or a timeout
/// occurs. Verifies per-chunk BLAKE3 digests and completes the transfer
/// in the handle on success.
pub fn recv_read_response(
    transport: &mut crate::transport::Transport,
    handle: &mut TransferHandle,
    session_id: crate::types::SessionId,
    transfer_id: u64,
) -> Result<Vec<u8>, TransferDispatchError> {
    // Verify the transfer is pending
    if handle.lookup_pending(transfer_id).is_none() {
        return Err(TransferDispatchError::StaleTransfer(transfer_id));
    }

    let mut reassembler: Option<ChunkReassembler> = None;
    let assembled;

    loop {
        let raw = transport.recv_message(session_id)?;
        let msg = ObjectTransferMessage::decode(&raw)
            .map_err(|e| TransferDispatchError::Decode(e.to_string()))?;

        match msg {
            ObjectTransferMessage::ReadResponse {
                transfer_id: tid,
                chunk_index,
                total_chunks,
                total_size,
                ref payload,
                payload_digest,
            } => {
                if tid != transfer_id {
                    // Response for a different transfer — skip
                    continue;
                }
                msg.verify_payload()
                    .map_err(|_| TransferDispatchError::DigestMismatch)?;

                if reassembler.is_none() {
                    reassembler = Some(ChunkReassembler::new(total_chunks, total_size));
                }
                let done = reassembler.as_mut().unwrap().feed(
                    chunk_index,
                    total_chunks,
                    payload,
                    &payload_digest,
                )?;
                if done {
                    assembled = reassembler.take().unwrap().into_payload();
                    handle.complete(transfer_id);
                    return Ok(assembled);
                }
            }
            _ => {
                // Non-response message on this session — ignore
            }
        }
    }
}

/// Dispatch a write request (possibly chunked) over a transport session.
///
/// Splits `data` into chunks at `MAX_CHUNK_PAYLOAD`, sends each as a
/// `WriteRequest`, and returns the `transfer_id`. The caller should
/// then call `recv_write_ack` to get the peer's acknowledgement.
pub fn dispatch_write_request(
    transport: &mut crate::transport::Transport,
    handle: &mut TransferHandle,
    session_id: crate::types::SessionId,
    object_key: [u8; 32],
    offset: u64,
    data: &[u8],
) -> Result<u64, TransferDispatchError> {
    let total_size = data.len() as u64;
    let chunks = build_write_requests(0, object_key, offset, total_size, data, MAX_CHUNK_PAYLOAD);

    // Register a sentinel request for response correlation
    let sentinel = ObjectTransferMessage::read_request(0, object_key, offset, total_size);
    let tid = handle.register_request(sentinel);

    for chunk in &chunks {
        // Rebuild with the correct transfer_id
        let msg = rebuild_write_chunk(chunk, tid);
        let encoded = msg
            .encode()
            .map_err(|e| TransferDispatchError::Encode(e.to_string()))?;
        transport.send_message(session_id, &encoded)?;
    }

    Ok(tid)
}

/// Rebuild a WriteRequest chunk with the assigned transfer_id.
fn rebuild_write_chunk(
    original: &ObjectTransferMessage,
    transfer_id: u64,
) -> ObjectTransferMessage {
    match original {
        ObjectTransferMessage::WriteRequest {
            object_key,
            offset,
            total_size,
            chunk_index,
            total_chunks,
            payload,
            ..
        } => ObjectTransferMessage::write_request(
            transfer_id,
            *object_key,
            *offset,
            *total_size,
            *chunk_index,
            *total_chunks,
            payload.clone(),
        ),
        _ => original.clone(),
    }
}

/// Receive a write acknowledgement over a transport session.
///
/// Blocks until a `WriteAck` for `transfer_id` is received. On success,
/// completes the transfer and returns `(bytes_written, status)`.
pub fn recv_write_ack(
    transport: &mut crate::transport::Transport,
    handle: &mut TransferHandle,
    session_id: crate::types::SessionId,
    transfer_id: u64,
) -> Result<(u64, WriteStatus), TransferDispatchError> {
    loop {
        let raw = transport.recv_message(session_id)?;
        let msg = ObjectTransferMessage::decode(&raw)
            .map_err(|e| TransferDispatchError::Decode(e.to_string()))?;

        match msg {
            ObjectTransferMessage::WriteAck {
                transfer_id: tid,
                bytes_written,
                status,
            } => {
                if tid != transfer_id {
                    continue;
                }
                handle.complete(transfer_id);
                if status != WriteStatus::Ok {
                    return Err(TransferDispatchError::WriteRejected(status));
                }
                return Ok((bytes_written, status));
            }
            _ => continue,
        }
    }
}

/// Receive a write request over a transport session, reassemble the
/// payload from chunks, and return `(transfer_id, payload, object_key, offset)`.
///
/// The caller is responsible for writing the data and sending the
/// `WriteAck` back via `send_write_ack`.
pub fn recv_write_request(
    transport: &mut crate::transport::Transport,
    session_id: crate::types::SessionId,
) -> Result<(u64, Vec<u8>, [u8; 32], u64), TransferDispatchError> {
    let mut reassembler: Option<ChunkReassembler> = None;
    let assembled;
    let mut transfer_id = 0u64;
    let mut object_key = [0u8; 32];
    let mut base_offset = 0u64;

    loop {
        let raw = transport.recv_message(session_id)?;
        let msg = ObjectTransferMessage::decode(&raw)
            .map_err(|e| TransferDispatchError::Decode(e.to_string()))?;

        match msg {
            ObjectTransferMessage::WriteRequest {
                transfer_id: tid,
                object_key: ok,
                offset,
                total_size,
                chunk_index,
                total_chunks,
                ref payload,
                payload_digest,
            } => {
                msg.verify_payload()
                    .map_err(|_| TransferDispatchError::DigestMismatch)?;

                if reassembler.is_none() {
                    transfer_id = tid;
                    object_key = ok;
                    base_offset = offset;
                    reassembler = Some(ChunkReassembler::new(total_chunks, total_size));
                }
                let done = reassembler.as_mut().unwrap().feed(
                    chunk_index,
                    total_chunks,
                    payload,
                    &payload_digest,
                )?;
                if done {
                    assembled = reassembler.take().unwrap().into_payload();
                    return Ok((transfer_id, assembled, object_key, base_offset));
                }
            }
            _ => continue,
        }
    }
}

/// Send a write acknowledgement over a transport session.
pub fn send_write_ack(
    transport: &mut crate::transport::Transport,
    session_id: crate::types::SessionId,
    transfer_id: u64,
    bytes_written: u64,
    status: WriteStatus,
) -> Result<(), TransferDispatchError> {
    let ack = ObjectTransferMessage::write_ack(transfer_id, bytes_written, status);
    let encoded = ack
        .encode()
        .map_err(|e| TransferDispatchError::Encode(e.to_string()))?;
    transport.send_message(session_id, &encoded)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Transfer dispatch integration tests (TCP loopback)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use crate::transport::Transport;
    use crate::NodeInfo;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::thread;
    use std::time::Duration;

    fn listening_transport(node_id: u64) -> (Transport, crate::TransportAddr) {
        let mut transport = Transport::new(node_id);
        let addr =
            crate::TransportAddr::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0));
        transport.bind(addr).expect("bind");
        let bound_addr = transport.bind_addr.clone().expect("bind_addr");
        (transport, bound_addr)
    }

    fn blocking_accept(transport: &mut Transport) -> crate::types::SessionId {
        for _ in 0..100 {
            match transport.accept_incoming() {
                Ok(sid) => return sid,
                Err(crate::TransportError::Generic(ref e))
                    if e.contains("no pending connections") =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("accept error: {e}"),
            }
        }
        panic!("timeout waiting for incoming connection");
    }

    #[test]
    fn tcp_read_request_response_roundtrip_4kib() {
        // Set up two transport instances
        let (mut node_a, addr_a) = listening_transport(1);
        let mut node_b = Transport::new(2);

        node_a.add_node(NodeInfo::new(2, vec![addr_a.clone()], 0));
        node_b.add_node(NodeInfo::new(1, vec![addr_a], 0));

        // Establish session: B connects to A
        let sid_a = {
            node_b.connect(1).expect("B connect");
            blocking_accept(&mut node_a)
        };
        assert!(sid_a.0 > 0);

        // Side B: dispatch a read request
        let mut handle = TransferHandle::new();
        let payload = vec![0xBFu8; 4096];
        let key = <[u8; 32]>::from(blake3::hash(&payload));

        // Side A (server): handle the read in a separate thread
        let server_payload = payload.clone();
        let server_key = key;
        let server_handle = std::thread::spawn(move || {
            let sid = sid_a;
            let mut transport = node_a;

            // Receive read request
            let raw = transport.recv_message(sid).expect("recv read request");
            let req = ObjectTransferMessage::decode(&raw).expect("decode read request");
            let (tid, ok, off, len) = match &req {
                ObjectTransferMessage::ReadRequest {
                    transfer_id,
                    object_key,
                    offset,
                    length,
                } => (*transfer_id, *object_key, *offset, *length),
                _ => panic!("expected ReadRequest"),
            };
            assert_eq!(ok, server_key);
            assert_eq!(off, 0);
            assert_eq!(len, server_payload.len() as u64);

            // Send chunked read response
            let responses = build_read_responses(
                tid,
                server_payload.len() as u64,
                &server_payload,
                MAX_CHUNK_PAYLOAD,
            );
            for resp in &responses {
                let encoded = resp.encode().expect("encode response");
                transport
                    .send_message(sid, &encoded)
                    .expect("send response");
            }
        });

        // Side B (client): send request and receive response
        let tid = dispatch_read_request(
            &mut node_b,
            &mut handle,
            crate::types::SessionId::new(sid_a.0),
            key,
            0,
            payload.len() as u64,
        )
        .expect("dispatch read request");

        let assembled = recv_read_response(
            &mut node_b,
            &mut handle,
            crate::types::SessionId::new(sid_a.0),
            tid,
        )
        .expect("recv read response");

        assert_eq!(assembled, payload);
        server_handle.join().expect("server thread");
    }

    #[test]
    fn tcp_write_request_ack_roundtrip_4kib() {
        let (mut node_a, addr_a) = listening_transport(1);
        let mut node_b = Transport::new(2);

        node_a.add_node(NodeInfo::new(2, vec![addr_a.clone()], 0));
        node_b.add_node(NodeInfo::new(1, vec![addr_a], 0));

        let sid_a = {
            node_b.connect(1).expect("B connect");
            blocking_accept(&mut node_a)
        };

        let payload = b"TCP write roundtrip data".to_vec();
        let key = <[u8; 32]>::from(blake3::hash(&payload));

        let server_payload = payload.clone();
        let server_thread = std::thread::spawn(move || {
            let mut transport = node_a;
            let sid = sid_a;

            // Receive write request
            let (tid, assembled, ok, _off) =
                recv_write_request(&mut transport, crate::types::SessionId::new(sid.0))
                    .expect("recv write request");
            assert_eq!(assembled, server_payload);
            assert_eq!(ok, <[u8; 32]>::from(blake3::hash(&server_payload)));

            // Send ack
            send_write_ack(
                &mut transport,
                crate::types::SessionId::new(sid.0),
                tid,
                assembled.len() as u64,
                WriteStatus::Ok,
            )
            .expect("send write ack");
        });

        // Client: dispatch write
        let mut handle = TransferHandle::new();
        let tid = dispatch_write_request(
            &mut node_b,
            &mut handle,
            crate::types::SessionId::new(sid_a.0),
            key,
            0,
            &payload,
        )
        .expect("dispatch write request");

        let (bw, st) = recv_write_ack(
            &mut node_b,
            &mut handle,
            crate::types::SessionId::new(sid_a.0),
            tid,
        )
        .expect("recv write ack");

        assert_eq!(bw, payload.len() as u64);
        assert_eq!(st, WriteStatus::Ok);

        server_thread.join().expect("server thread");
    }
    // ── Delete message round-trip tests ───────────────────────────

    #[test]
    fn delete_request_roundtrip() {
        let req = ObjectTransferMessage::delete_request(99, [0xCD; 32], 7);
        let encoded = req.encode().unwrap();
        let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(decoded.transfer_id(), 99);
        assert_eq!(decoded.kind(), "DeleteObjectRequest");
        assert!(!decoded.has_payload());
        assert!(decoded.verify_payload().is_ok());
    }

    #[test]
    fn delete_response_roundtrip() {
        let resp = ObjectTransferMessage::delete_response(99, [0xCD; 32], true, 7);
        let encoded = resp.encode().unwrap();
        let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);
        assert_eq!(decoded.transfer_id(), 99);
        assert_eq!(decoded.kind(), "DeleteObjectResponse");
        assert!(!decoded.has_payload());
        assert!(decoded.verify_payload().is_ok());
    }

    #[test]
    fn delete_response_not_found_roundtrip() {
        let resp = ObjectTransferMessage::delete_response(42, [0xAB; 32], false, 0);
        let encoded = resp.encode().unwrap();
        let decoded = ObjectTransferMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);
        assert_eq!(decoded.kind(), "DeleteObjectResponse");
    }

    #[test]
    fn delete_request_different_generations_are_distinct() {
        let req1 = ObjectTransferMessage::delete_request(1, [0xFF; 32], 5);
        let req2 = ObjectTransferMessage::delete_request(1, [0xFF; 32], 6);
        let enc1 = req1.encode().unwrap();
        let enc2 = req2.encode().unwrap();
        assert_ne!(
            enc1, enc2,
            "different generations must produce different encodings"
        );
    }

    #[test]
    fn delete_response_matches_by_transfer_id() {
        let resp = ObjectTransferMessage::delete_response(77, [0xEE; 32], true, 3);
        assert_eq!(resp.transfer_id(), 77);
        // Verify it doesn't match a write's transfer_id pattern
        let write_req =
            ObjectTransferMessage::write_request(77, [0xEE; 32], 0, 100, 0, 1, vec![1, 2, 3]);
        assert_eq!(write_req.transfer_id(), resp.transfer_id());
        assert_ne!(write_req.kind(), resp.kind());
    }
}
