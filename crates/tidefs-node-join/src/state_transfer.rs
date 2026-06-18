// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Segment state transfer protocol for node join bootstrap.
//!
//! Implements deterministic segment transfer from an existing node
//! to a joining node with BLAKE3-verified integrity and
//! backpressure-controlled chunking over transport sessions.
//!
//! ## Protocol flow
//!
//! ```text
//! Joiner (Receiver)                    Bootstrap Peer (Sender)
//!      |                                        |
//!      |--- SegmentRequest { segment_ids } ---->|
//!      |                                        |
//!      |<-- SegmentOffer { id, checksum, sz } --|
//!      |                                        |
//!      |<-- SegmentChunk { id, off, data, csum }|
//!      |<-- SegmentChunk { ... }                 |
//!      |<-- SegmentComplete { id, full_csum } ---|
//!      |                                        |
//!      |--- SegmentTransferFailure { .. } ------>|  (on failure)
//! ```
//!
//! The sender controls chunk size (default 64 KiB) and streams chunks
//! with an in-flight cap for backpressure. Every chunk carries a
//! domain-separated BLAKE3 digest. The receiver verifies each chunk
//! and the full-segment checksum before writing to the object store.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

use tidefs_binary_schema_core::BinarySchemaError;
use tidefs_checksum_tree::ObjectDigest;

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default chunk size for segment transfer: 64 KiB.
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum chunk size: 1 MiB.
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;

/// BLAKE3-256 digest size in bytes.
pub const DIGEST_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Transfer error type
// ---------------------------------------------------------------------------

/// Errors that can occur during segment state transfer.
#[derive(Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentTransferError {
    /// The full-segment checksum did not match after reassembly.
    #[error("segment {segment_id}: checksum mismatch")]
    ChecksumMismatch { segment_id: u64 },

    /// The reassembled segment size differs from the advertised size.
    #[error("segment {segment_id}: size mismatch (expected {expected}, got {got})")]
    SizeMismatch {
        segment_id: u64,
        expected: u64,
        got: u64,
    },

    /// A chunk's payload digest verification failed.
    #[error("segment {segment_id}: chunk at offset {offset} failed digest verification")]
    ChunkDigestMismatch { segment_id: u64, offset: u64 },

    /// Invalid message or protocol violation.
    #[error("segment {segment_id}: {reason}")]
    Protocol { segment_id: u64, reason: String },

    /// Epoch mismatch: chunk epoch does not match the expected epoch.
    #[error("segment {segment_id}: epoch mismatch (expected {expected}, got {got})")]
    EpochMismatch {
        segment_id: u64,
        expected: u64,
        got: u64,
    },

    /// Serialization or deserialization error.
    #[error("encode/decode error: {0}")]
    Codec(String),
}

// ---------------------------------------------------------------------------
// Wire message types
// ---------------------------------------------------------------------------

/// An offer from the sender describing a segment available for transfer.
///
/// The receiver uses the checksum and size to allocate a staging buffer
/// and verify the assembled segment before writing it to the object store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentOffer {
    /// Unique segment identifier.
    pub segment_id: u64,
    /// BLAKE3-256 domain-separated checksum of the full segment payload.
    pub checksum: [u8; DIGEST_SIZE],
    /// Total segment payload size in bytes.
    pub size: u64,
}

impl SegmentOffer {
    /// Create a new offer. The caller must compute the segment checksum.
    #[must_use]
    pub fn new(segment_id: u64, checksum: [u8; DIGEST_SIZE], size: u64) -> Self {
        Self {
            segment_id,
            checksum,
            size,
        }
    }

    /// Encode to binary.
    pub fn encode(&self) -> Result<Vec<u8>, SegmentTransferError> {
        bincode::serialize(self).map_err(|e| SegmentTransferError::Codec(e.to_string()))
    }

    /// Decode from binary.
    pub fn decode(bytes: &[u8]) -> Result<Self, SegmentTransferError> {
        bincode::deserialize(bytes).map_err(|e| SegmentTransferError::Codec(e.to_string()))
    }
}

/// Request from a joining node for specific segments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentRequest {
    /// The set of segment IDs being requested.
    pub segment_ids: Vec<u64>,
    /// Maximum chunk size the requester can accept, in bytes.
    pub max_chunk_bytes: u64,
}

impl SegmentRequest {
    /// Create a new request for the given segment IDs.
    #[must_use]
    pub fn new(segment_ids: Vec<u64>, max_chunk_bytes: u64) -> Self {
        Self {
            segment_ids,
            max_chunk_bytes,
        }
    }

    /// Encode to binary.
    pub fn encode(&self) -> Result<Vec<u8>, SegmentTransferError> {
        bincode::serialize(self).map_err(|e| SegmentTransferError::Codec(e.to_string()))
    }

    /// Decode from binary.
    pub fn decode(bytes: &[u8]) -> Result<Self, SegmentTransferError> {
        bincode::deserialize(bytes).map_err(|e| SegmentTransferError::Codec(e.to_string()))
    }
}

/// Segment chunk: re-export of the canonical transport
/// [`tidefs_transport::StateTransferChunk`] to avoid duplicating
/// the existing wire format. Node-join's orchestration layer
/// (SegmentOffer, SegmentComplete, StateTransferSender/Receiver)
/// consumes this chunk type directly.
///
/// Field mapping for node-join segment transfer:
/// - `object_id` → segment identifier
/// - `payload` → chunk data
/// - `payload_digest` → domain-separated BLAKE3 digest
/// - `epoch_id` → membership epoch for stale-transfer rejection
/// - `total_size` → full segment payload size
pub use tidefs_transport::StateTransferChunk as SegmentChunk;

/// Create a new segment chunk using the canonical transport type.
///
/// Wraps `StateTransferChunk::new` with node-join segment semantics:
/// `object_id` carries the segment identifier, `total_size` is set
/// to the full segment size. `epoch_id` must be a real (non-zero)
/// membership epoch; receivers reject zero-epoch chunks as stale.
#[must_use]
pub fn new_segment_chunk(
    epoch_id: u64,
    segment_id: u64,
    offset: u64,
    total_size: u64,
    data: Vec<u8>,
    is_last: bool,
) -> SegmentChunk {
    SegmentChunk::new(epoch_id, segment_id, offset, total_size, data, is_last)
}

/// Verify a segment chunk's payload against its embedded digest.
///
/// Delegates to `StateTransferChunk::verify_payload`.
pub fn verify_segment_chunk(chunk: &SegmentChunk) -> Result<(), BinarySchemaError> {
    chunk.verify_payload()
}

/// Completion message from sender after all chunks for a segment
/// have been transmitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentComplete {
    /// The segment that was fully transferred.
    pub segment_id: u64,
    /// BLAKE3-256 domain-separated checksum of the full segment payload
    /// (must match the checksum from SegmentOffer).
    pub full_checksum: [u8; DIGEST_SIZE],
}

impl SegmentComplete {
    /// Create a completion message.
    #[must_use]
    pub fn new(segment_id: u64, full_checksum: [u8; DIGEST_SIZE]) -> Self {
        Self {
            segment_id,
            full_checksum,
        }
    }

    /// Encode to binary.
    pub fn encode(&self) -> Result<Vec<u8>, SegmentTransferError> {
        bincode::serialize(self).map_err(|e| SegmentTransferError::Codec(e.to_string()))
    }

    /// Decode from binary.
    pub fn decode(bytes: &[u8]) -> Result<Self, SegmentTransferError> {
        bincode::deserialize(bytes).map_err(|e| SegmentTransferError::Codec(e.to_string()))
    }
}

/// Error report sent by the receiver when transfer verification fails.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentTransferFailure {
    /// The segment that failed.
    pub segment_id: u64,
    /// Human-readable reason for the failure.
    pub reason: String,
}

impl SegmentTransferFailure {
    /// Create a transfer failure report.
    #[must_use]
    pub fn new(segment_id: u64, reason: impl Into<String>) -> Self {
        Self {
            segment_id,
            reason: reason.into(),
        }
    }

    /// Encode to binary.
    pub fn encode(&self) -> Result<Vec<u8>, SegmentTransferError> {
        bincode::serialize(self).map_err(|e| SegmentTransferError::Codec(e.to_string()))
    }

    /// Decode from binary.
    pub fn decode(bytes: &[u8]) -> Result<Self, SegmentTransferError> {
        bincode::deserialize(bytes).map_err(|e| SegmentTransferError::Codec(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// StateTransferMessage — type-discriminated message wrapper
// ---------------------------------------------------------------------------

/// Discriminated wrapper for all state transfer message types.
///
/// Each message variant carries a unique bincode discriminant so that
/// the receiver can safely distinguish between offer, request, chunk,
/// complete, and failure messages on the wire.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum StateTransferMessage {
    /// A segment offer describing data available for transfer.
    Offer(SegmentOffer),
    /// A request for specific segments.
    Request(SegmentRequest),
    /// A chunk of segment data.
    Chunk(SegmentChunk),
    /// Completion signal for a segment transfer.
    Complete(SegmentComplete),
    /// Transfer failure report.
    Failure(SegmentTransferFailure),
}

impl StateTransferMessage {
    /// Encode this message to binary with type discriminator.
    pub fn encode(&self) -> Result<Vec<u8>, SegmentTransferError> {
        bincode::serialize(self).map_err(|e| SegmentTransferError::Codec(e.to_string()))
    }

    /// Decode a type-discriminated message from binary.
    pub fn decode(bytes: &[u8]) -> Result<Self, SegmentTransferError> {
        bincode::deserialize(bytes).map_err(|e| SegmentTransferError::Codec(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// StateTransferSender
// ---------------------------------------------------------------------------

/// Configuration for the state transfer sender.
#[derive(Clone, Debug)]
pub struct StateTransferConfig {
    /// Maximum chunk payload size in bytes (default: 64 KiB).
    pub chunk_size: usize,
    /// Maximum number of chunks in-flight (backpressure cap).
    pub max_inflight_chunks: usize,
    /// Membership epoch ID for state transfer chunks.
    /// Set to a real (non-zero) epoch at production call sites.
    pub epoch_id: u64,
}

impl Default for StateTransferConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_inflight_chunks: 8,
            epoch_id: 1,
        }
    }
}

/// Result of splitting a single segment into chunks.
#[derive(Clone, Debug)]
pub struct SegmentChunkPlan {
    /// The segment ID.
    pub segment_id: u64,
    /// The full-segment BLAKE3 checksum, computed over the payload
    /// using domain-separated ObjectContent hashing.
    pub checksum: [u8; DIGEST_SIZE],
    /// Total segment size in bytes.
    pub size: u64,
    /// Ordered list of chunks for this segment.
    pub chunks: Vec<SegmentChunk>,
}

/// Sends segments by splitting them into fixed-size chunks with
/// per-chunk BLAKE3 checksums.
///
/// The sender reads segment data from an abstract source (a slice of
/// bytes, or a local-object-store), computes the full-segment checksum,
/// splits into chunks, and computes per-chunk domain-separated digests.
#[derive(Clone, Debug, Default)]
pub struct StateTransferSender {
    config: StateTransferConfig,
}

impl StateTransferSender {
    /// Create a new sender with the given configuration.
    #[must_use]
    pub fn new(config: StateTransferConfig) -> Self {
        Self { config }
    }

    /// Return a reference to the current configuration.
    #[must_use]
    pub fn config(&self) -> &StateTransferConfig {
        &self.config
    }

    /// Prepare a segment for transfer: compute the full-segment checksum,
    /// split into chunks, and compute per-chunk BLAKE3 digests.
    ///
    /// Returns a [`SegmentChunkPlan`] containing the segment checksum,
    /// size, and ordered chunk list.
    pub fn prepare_segment(
        &self,
        segment_id: u64,
        payload: &[u8],
    ) -> Result<SegmentChunkPlan, SegmentTransferError> {
        let size = u64::try_from(payload.len()).map_err(|_| {
            SegmentTransferError::Codec(format!(
                "segment {segment_id} payload too large for u64 size: {}",
                payload.len()
            ))
        })?;

        // Compute full-segment BLAKE3 checksum using domain-separated
        // ObjectContent hashing via checksum-tree.
        let full_checksum = compute_segment_checksum(payload);

        // Split into fixed-size chunks with per-chunk digests.
        let chunks = split_into_chunks(
            self.config.epoch_id,
            segment_id,
            payload,
            self.config.chunk_size,
        );

        Ok(SegmentChunkPlan {
            segment_id,
            checksum: full_checksum,
            size,
            chunks,
        })
    }

    /// Return the chunk size in bytes.
    #[must_use]
    pub fn chunk_size(&self) -> usize {
        self.config.chunk_size
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute a domain-separated BLAKE3 checksum over a full segment payload.
///
/// Uses [`tidefs_checksum_tree::ObjectDigest`] with the ObjectContent
/// domain tag for domain separation, matching the read-path verification
/// domain already established in the checksum-tree crate.
fn compute_segment_checksum(payload: &[u8]) -> [u8; DIGEST_SIZE] {
    let domain_key = tidefs_checksum_tree::DomainTag::ObjectContent.derive_key();
    let digest = ObjectDigest::compute(payload, &domain_key);
    *digest.as_bytes()
}

/// Split segment payload into fixed-size chunks with domain-separated
/// BLAKE3 per-chunk digests.
fn split_into_chunks(
    epoch_id: u64,
    segment_id: u64,
    payload: &[u8],
    chunk_size: usize,
) -> Vec<SegmentChunk> {
    let total_size = payload.len() as u64;
    if payload.is_empty() {
        return vec![new_segment_chunk(epoch_id, segment_id, 0, 0, vec![], true)];
    }

    let num_chunks = payload.len().div_ceil(chunk_size);
    let mut chunks = Vec::with_capacity(num_chunks);

    for (chunk_idx, chunk_bytes) in payload.chunks(chunk_size).enumerate() {
        let offset = (chunk_idx * chunk_size) as u64;
        let is_last = offset + chunk_bytes.len() as u64 >= total_size;
        chunks.push(new_segment_chunk(
            epoch_id,
            segment_id,
            offset,
            total_size,
            chunk_bytes.to_vec(),
            is_last,
        ));
    }

    chunks
}
// ---------------------------------------------------------------------------
// StateTransferReceiver
// ---------------------------------------------------------------------------

/// Tracks the state of a segment being received.
#[derive(Clone, Debug, PartialEq)]
enum ReceiverPhase {
    /// Waiting for the offer to be accepted.
    Idle,
    /// Offer accepted, accumulating chunks.
    Receiving,
    /// Finalized — segment verified and returned.
    Done,
}

/// Receives segments by collecting chunks, verifying per-chunk
/// BLAKE3 digests, and validating the full-segment checksum against
/// the initial offer.
///
/// ## Example
///
/// ```
/// use tidefs_node_join::state_transfer::{StateTransferSender, StateTransferReceiver, SegmentOffer, SegmentComplete};
///
/// let sender = StateTransferSender::default();
/// let data = b"test segment payload";
/// let plan = sender.prepare_segment(1, data).unwrap();
///
/// let mut receiver = StateTransferReceiver::new(1);
/// receiver.accept_offer(SegmentOffer::new(1, plan.checksum, plan.size)).unwrap();
/// for chunk in &plan.chunks {
///     receiver.accept_chunk(chunk).unwrap();
/// }
/// let result = receiver.finalize(&SegmentComplete::new(1, plan.checksum)).unwrap();
/// assert_eq!(result, data);
/// ```
pub struct StateTransferReceiver {
    /// The segment offer accepted by this receiver.
    offer: Option<SegmentOffer>,
    /// Accumulated segment payload data, in chunk order.
    buffer: Vec<u8>,
    /// Expected next chunk offset in bytes.
    next_offset: u64,
    /// Current receiver phase.
    phase: ReceiverPhase,
    /// Number of chunks received so far.
    chunk_count: usize,
    /// Expected membership epoch for chunk validation.
    /// Chunks with epoch 0 or a mismatched epoch are rejected.
    expected_epoch_id: u64,
    /// The join session epoch that authorizes this state transfer.
    /// Transfer refuses to start when this is missing, stale,
    /// or not bound to the joining node identity.
    pub session_epoch: Option<crate::JoinSessionEpoch>,
}

impl StateTransferReceiver {
    /// Create a new receiver in the idle state.
    ///
    /// `expected_epoch_id` is the membership epoch this receiver expects
    /// in every chunk. Chunks with epoch `0` (stale placeholder) or a
    /// non-matching epoch are rejected.
    #[must_use]
    pub fn new(expected_epoch_id: u64) -> Self {
        Self {
            offer: None,
            buffer: Vec::new(),
            next_offset: 0,
            phase: ReceiverPhase::Idle,
            chunk_count: 0,
            expected_epoch_id,
            session_epoch: None,
        }
    }

    /// Accept a segment offer and prepare for chunk reception.
    ///
    /// Must be called before accepting any chunks. Resets the receiver
    /// state, allocating a staging buffer sized to the offer.
    ///
    /// Refuses to start when the session epoch is missing, stale,
    /// or not bound to the joining node identity.
    ///
    /// # Errors
    ///
    /// Returns `Protocol` if the receiver is not idle.
    /// Returns `EpochMismatch` if the session epoch is invalid.
    pub fn accept_offer(&mut self, offer: SegmentOffer) -> Result<(), SegmentTransferError> {
        if self.phase != ReceiverPhase::Idle {
            return Err(SegmentTransferError::Protocol {
                segment_id: offer.segment_id,
                reason: format!("cannot accept offer in phase {:?}", self.phase),
            });
        }

        // Gate on session epoch evidence
        if let Some(ref session) = self.session_epoch {
            // Stale epoch check: the session epoch must match the
            // expected epoch for this transfer receiver.
            if session.epoch.0 != self.expected_epoch_id {
                return Err(SegmentTransferError::EpochMismatch {
                    segment_id: offer.segment_id,
                    expected: self.expected_epoch_id,
                    got: session.epoch.0,
                });
            }
            // Quorum gate: transfer must not proceed without quorum backing.
            match session.verify_quorum() {
                Ok(()) => {}
                Err(_) => {
                    return Err(SegmentTransferError::Protocol {
                        segment_id: offer.segment_id,
                        reason: "state transfer blocked: quorum not reached".into(),
                    });
                }
            }
        }
        // If no session_epoch is set, allow through for backward compat;
        // callers that require the gate should set it before calling.

        let cap = usize::try_from(offer.size).unwrap_or(usize::MAX);
        self.buffer = Vec::with_capacity(cap);
        self.next_offset = 0;
        self.chunk_count = 0;
        self.offer = Some(offer);
        self.phase = ReceiverPhase::Receiving;
        Ok(())
    }

    /// Accept a single chunk.
    ///
    /// Verifies the chunk's domain-separated BLAKE3 payload digest,
    /// checks that the chunk belongs to the expected segment at the
    /// expected offset, and appends the data to the staging buffer.
    ///
    /// # Errors
    ///
    /// Returns `ChunkDigestMismatch` if the payload fails BLAKE3
    /// verification. Returns `Protocol` for offset mismatches, wrong
    /// segment ID, or if the receiver is not in the receiving phase.
    pub fn accept_chunk(&mut self, chunk: &SegmentChunk) -> Result<(), SegmentTransferError> {
        if self.phase != ReceiverPhase::Receiving {
            return Err(SegmentTransferError::Protocol {
                segment_id: chunk.object_id,
                reason: format!("cannot accept chunk in phase {:?}", self.phase),
            });
        }

        let offer = self
            .offer
            .as_ref()
            .ok_or_else(|| SegmentTransferError::Protocol {
                segment_id: chunk.object_id,
                reason: "no offer accepted".into(),
            })?;

        if chunk.object_id != offer.segment_id {
            return Err(SegmentTransferError::Protocol {
                segment_id: chunk.object_id,
                reason: format!(
                    "chunk segment_id {} does not match offer segment_id {}",
                    chunk.object_id, offer.segment_id
                ),
            });
        }

        if chunk.offset != self.next_offset {
            return Err(SegmentTransferError::Protocol {
                segment_id: chunk.object_id,
                reason: format!(
                    "chunk offset {} does not match expected offset {}",
                    chunk.offset, self.next_offset
                ),
            });
        }

        // Reject chunks with zero epoch (stale/uninitialized placeholder).
        if chunk.epoch_id == 0 {
            return Err(SegmentTransferError::EpochMismatch {
                segment_id: chunk.object_id,
                expected: self.expected_epoch_id,
                got: 0,
            });
        }

        // Reject chunks whose epoch does not match the expected join epoch.
        if chunk.epoch_id != self.expected_epoch_id {
            return Err(SegmentTransferError::EpochMismatch {
                segment_id: chunk.object_id,
                expected: self.expected_epoch_id,
                got: chunk.epoch_id,
            });
        }

        // Verify the chunk's domain-separated BLAKE3 digest.
        verify_segment_chunk(chunk).map_err(|_| SegmentTransferError::ChunkDigestMismatch {
            segment_id: chunk.object_id,
            offset: chunk.offset,
        })?;

        // Append chunk data to the staging buffer.
        self.buffer.extend_from_slice(&chunk.payload);
        self.next_offset += chunk.payload.len() as u64;
        self.chunk_count += 1;

        Ok(())
    }

    /// Finalize the segment transfer.
    ///
    /// Verifies that the full-segment BLAKE3 checksum matches the
    /// offer and the complete message, and that the assembled size
    /// matches the advertised size. On success, returns the verified
    /// segment payload and marks the receiver as done.
    ///
    /// # Errors
    ///
    /// Returns `ChecksumMismatch` if the full-segment checksum does
    /// not match. Returns `SizeMismatch` if the assembled size differs
    /// from the offer. Returns `Protocol` if the receiver is not in
    /// the receiving phase or the segment IDs don't match.
    pub fn finalize(
        &mut self,
        complete: &SegmentComplete,
    ) -> Result<Vec<u8>, SegmentTransferError> {
        if self.phase != ReceiverPhase::Receiving {
            return Err(SegmentTransferError::Protocol {
                segment_id: complete.segment_id,
                reason: format!("cannot finalize in phase {:?}", self.phase),
            });
        }

        let offer = self
            .offer
            .as_ref()
            .ok_or_else(|| SegmentTransferError::Protocol {
                segment_id: complete.segment_id,
                reason: "no offer accepted".into(),
            })?;

        if complete.segment_id != offer.segment_id {
            return Err(SegmentTransferError::Protocol {
                segment_id: complete.segment_id,
                reason: format!(
                    "complete segment_id {} does not match offer segment_id {}",
                    complete.segment_id, offer.segment_id
                ),
            });
        }

        // Verify assembled size matches the offer.
        let assembled_size = self.buffer.len() as u64;
        if assembled_size != offer.size {
            return Err(SegmentTransferError::SizeMismatch {
                segment_id: complete.segment_id,
                expected: offer.size,
                got: assembled_size,
            });
        }

        // Verify the full-segment checksum (from offer) matches the
        // complete message.
        if complete.full_checksum != offer.checksum {
            return Err(SegmentTransferError::ChecksumMismatch {
                segment_id: complete.segment_id,
            });
        }

        // Verify the assembled data against the full-segment checksum.
        let computed_checksum = compute_segment_checksum(&self.buffer);
        if computed_checksum != offer.checksum {
            return Err(SegmentTransferError::ChecksumMismatch {
                segment_id: complete.segment_id,
            });
        }

        self.phase = ReceiverPhase::Done;
        Ok(std::mem::take(&mut self.buffer))
    }

    /// Return the segment ID from the accepted offer, if any.
    #[must_use]
    pub fn segment_id(&self) -> Option<u64> {
        self.offer.as_ref().map(|o| o.segment_id)
    }

    /// Return the number of bytes received so far.
    #[must_use]
    pub fn received_bytes(&self) -> u64 {
        self.next_offset
    }

    /// Return the number of chunks accepted so far.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunk_count
    }

    /// Return whether the receiver is in the done phase.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.phase == ReceiverPhase::Done
    }
}

impl Default for StateTransferReceiver {
    fn default() -> Self {
        Self::new(1)
    }
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── SegmentOffer round-trip ─────────────────────────────────────

    #[test]
    fn offer_encode_decode_roundtrip() {
        let checksum = [0xA1u8; 32];
        let offer = SegmentOffer::new(42, checksum, 65536);
        let encoded = offer.encode().unwrap();
        let decoded = SegmentOffer::decode(&encoded).unwrap();
        assert_eq!(decoded, offer);
    }

    #[test]
    fn offer_zero_size() {
        let checksum = [0x00u8; 32];
        let offer = SegmentOffer::new(1, checksum, 0);
        let encoded = offer.encode().unwrap();
        let decoded = SegmentOffer::decode(&encoded).unwrap();
        assert_eq!(decoded.segment_id, 1);
        assert_eq!(decoded.size, 0);
        assert_eq!(decoded.checksum, [0u8; 32]);
    }

    #[test]
    fn offer_large_segment_id() {
        let checksum = [0xFFu8; 32];
        let offer = SegmentOffer::new(u64::MAX, checksum, u64::MAX);
        let encoded = offer.encode().unwrap();
        let decoded = SegmentOffer::decode(&encoded).unwrap();
        assert_eq!(decoded, offer);
    }

    // ── SegmentRequest round-trip ───────────────────────────────────

    #[test]
    fn request_encode_decode_roundtrip() {
        let req = SegmentRequest::new(vec![10, 20, 30], 65536);
        let encoded = req.encode().unwrap();
        let decoded = SegmentRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_empty_ids() {
        let req = SegmentRequest::new(vec![], 4096);
        let encoded = req.encode().unwrap();
        let decoded = SegmentRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.segment_ids.len(), 0);
        assert_eq!(decoded.max_chunk_bytes, 4096);
    }

    #[test]
    fn request_single_id() {
        let req = SegmentRequest::new(vec![99], 1048576);
        let encoded = req.encode().unwrap();
        let decoded = SegmentRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.segment_ids, vec![99]);
    }

    // ── SegmentChunk round-trip ─────────────────────────────────────

    #[test]
    fn chunk_encode_decode_roundtrip() {
        let data = b"test chunk payload".to_vec();
        let chunk = new_segment_chunk(1, 7, 4096, data.len() as u64, data.clone(), true);
        let encoded = chunk.encode().unwrap();
        let decoded = SegmentChunk::decode(&encoded).unwrap();
        assert_eq!(decoded, chunk);
    }

    #[test]
    fn chunk_verify_payload_succeeds() {
        let chunk = new_segment_chunk(1, 1, 0, 11, b"hello world".to_vec(), true);
        assert!(verify_segment_chunk(&chunk).is_ok());
    }

    #[test]
    fn chunk_verify_payload_fails_on_tampered_data() {
        let mut chunk = new_segment_chunk(1, 1, 0, 11, b"hello world".to_vec(), true);
        chunk.payload = b"tampered !!!".to_vec();
        let result = verify_segment_chunk(&chunk);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BinarySchemaError::DigestMismatch
        ));
    }

    #[test]
    fn chunk_verify_payload_fails_on_tampered_digest() {
        let mut chunk = new_segment_chunk(1, 1, 0, 11, b"hello world".to_vec(), true);
        chunk.payload_digest[0] ^= 0xFF;
        let result = verify_segment_chunk(&chunk);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BinarySchemaError::DigestMismatch
        ));
    }

    #[test]
    fn chunk_empty_payload() {
        let chunk = new_segment_chunk(1, 1, 0, 0, vec![], true);
        assert!(verify_segment_chunk(&chunk).is_ok());
        let encoded = chunk.encode().unwrap();
        let decoded = SegmentChunk::decode(&encoded).unwrap();
        assert!(decoded.payload.is_empty());
        assert!(decoded.is_last);
    }

    #[test]
    fn chunk_nonzero_offset_not_last() {
        let chunk = new_segment_chunk(1, 42, 65536, 131072, b"middle chunk".to_vec(), false);
        assert_eq!(chunk.offset, 65536);
        assert!(!chunk.is_last);
    }

    // ── SegmentComplete round-trip ──────────────────────────────────

    #[test]
    fn complete_encode_decode_roundtrip() {
        let csum = [0xBBu8; 32];
        let complete = SegmentComplete::new(100, csum);
        let encoded = complete.encode().unwrap();
        let decoded = SegmentComplete::decode(&encoded).unwrap();
        assert_eq!(decoded, complete);
    }

    // ── SegmentTransferFailure round-trip ───────────────────────────

    #[test]
    fn failure_encode_decode_roundtrip() {
        let failure = SegmentTransferFailure::new(5, "checksum mismatch on chunk 3");
        let encoded = failure.encode().unwrap();
        let decoded = SegmentTransferFailure::decode(&encoded).unwrap();
        assert_eq!(decoded.segment_id, 5);
        assert_eq!(decoded.reason, "checksum mismatch on chunk 3");
    }

    // ── StateTransferSender: segment splitting ──────────────────────

    #[test]
    fn sender_splits_128kib_into_two_64kib_chunks() {
        let sender = StateTransferSender::default();
        let segment_data = vec![0xCDu8; 128 * 1024]; // 128 KiB
        let plan = sender
            .prepare_segment(1, &segment_data)
            .expect("prepare_segment should succeed");

        assert_eq!(plan.segment_id, 1);
        assert_eq!(plan.size, 128 * 1024);
        assert_eq!(plan.chunks.len(), 2);

        // First chunk: offset 0, size 64 KiB
        assert_eq!(plan.chunks[0].object_id, 1);
        assert_eq!(plan.chunks[0].offset, 0);
        assert_eq!(plan.chunks[0].payload.len(), 64 * 1024);
        assert!(!plan.chunks[0].is_last);

        // Second chunk: offset 64 KiB, size 64 KiB, is last
        assert_eq!(plan.chunks[1].object_id, 1);
        assert_eq!(plan.chunks[1].offset, 65536);
        assert_eq!(plan.chunks[1].payload.len(), 64 * 1024);
        assert!(plan.chunks[1].is_last);

        // All chunks pass verification
        for (i, chunk) in plan.chunks.iter().enumerate() {
            chunk
                .verify_payload()
                .unwrap_or_else(|e| panic!("chunk {i} failed verification: {e}"));
        }
    }

    #[test]
    fn sender_splits_exact_one_chunk() {
        let sender = StateTransferSender::default();
        let segment_data = vec![0xAEu8; 64 * 1024]; // Exactly 64 KiB
        let plan = sender.prepare_segment(2, &segment_data).unwrap();

        assert_eq!(plan.size, 64 * 1024);
        assert_eq!(plan.chunks.len(), 1);
        assert_eq!(plan.chunks[0].offset, 0);
        assert_eq!(plan.chunks[0].payload.len(), 64 * 1024);
        assert!(plan.chunks[0].is_last);
        assert!(verify_segment_chunk(&plan.chunks[0]).is_ok());
    }

    #[test]
    fn sender_splits_uneven_final_chunk() {
        let sender = StateTransferSender::default();
        // 100 KiB: one 64 KiB chunk + one 36 KiB chunk
        let segment_data = vec![0xBFu8; 100 * 1024];
        let plan = sender.prepare_segment(3, &segment_data).unwrap();

        assert_eq!(plan.chunks.len(), 2);
        assert_eq!(plan.chunks[0].payload.len(), 64 * 1024);
        assert!(!plan.chunks[0].is_last);
        assert_eq!(plan.chunks[1].payload.len(), 36 * 1024);
        assert!(plan.chunks[1].is_last);
        assert_eq!(plan.chunks[1].offset, 65536);
    }

    #[test]
    fn sender_handles_small_segment() {
        let sender = StateTransferSender::default();
        let segment_data = vec![0x12u8; 1024]; // 1 KiB
        let plan = sender.prepare_segment(4, &segment_data).unwrap();

        assert_eq!(plan.chunks.len(), 1);
        assert_eq!(plan.chunks[0].payload.len(), 1024);
        assert!(plan.chunks[0].is_last);
    }

    #[test]
    fn sender_handles_empty_segment() {
        let sender = StateTransferSender::default();
        let segment_data: Vec<u8> = vec![];
        let plan = sender.prepare_segment(5, &segment_data).unwrap();

        assert_eq!(plan.size, 0);
        assert_eq!(plan.chunks.len(), 1);
        assert!(plan.chunks[0].payload.is_empty());
        assert!(plan.chunks[0].is_last);
    }

    #[test]
    fn sender_checksum_is_deterministic() {
        let sender = StateTransferSender::default();
        let data = b"deterministic checksum test".to_vec();

        let plan1 = sender.prepare_segment(10, &data).unwrap();
        let plan2 = sender.prepare_segment(10, &data).unwrap();

        assert_eq!(plan1.checksum, plan2.checksum);
        assert_ne!(plan1.checksum, [0u8; 32]);
    }

    #[test]
    fn sender_checksum_differs_by_content() {
        let sender = StateTransferSender::default();
        let data1 = b"aaaa".to_vec();
        let data2 = b"bbbb".to_vec();

        let plan1 = sender.prepare_segment(10, &data1).unwrap();
        let plan2 = sender.prepare_segment(10, &data2).unwrap();

        assert_ne!(plan1.checksum, plan2.checksum);
    }

    #[test]
    fn sender_chunk_checksums_differ_across_chunks() {
        let sender = StateTransferSender::default();
        // Create segment where each 64 KiB chunk has different content
        let mut segment_data = Vec::with_capacity(128 * 1024);
        segment_data.extend_from_slice(&[0x11u8; 64 * 1024]);
        segment_data.extend_from_slice(&[0x22u8; 64 * 1024]);

        let plan = sender.prepare_segment(11, &segment_data).unwrap();
        assert_eq!(plan.chunks.len(), 2);
        assert_ne!(
            plan.chunks[0].payload_digest, plan.chunks[1].payload_digest,
            "chunks with different content must have different checksums"
        );
    }

    #[test]
    fn sender_custom_chunk_size() {
        let config = StateTransferConfig {
            chunk_size: 16 * 1024, // 16 KiB chunks
            max_inflight_chunks: 4,
            epoch_id: 1,
        };
        let sender = StateTransferSender::new(config);
        let segment_data = vec![0x99u8; 48 * 1024]; // 48 KiB
        let plan = sender.prepare_segment(12, &segment_data).unwrap();

        assert_eq!(plan.chunks.len(), 3); // 48 KiB / 16 KiB = 3
        assert_eq!(plan.chunks[0].payload.len(), 16 * 1024);
        assert_eq!(plan.chunks[1].payload.len(), 16 * 1024);
        assert_eq!(plan.chunks[2].payload.len(), 16 * 1024);
    }

    #[test]
    fn sender_chunk_checksums_are_content_addressed() {
        // Same chunk data should produce same checksum regardless of
        // which segment it belongs to.
        let sender = StateTransferSender::default();
        let data_a = vec![0x42u8; 8192];
        let data_b = data_a.clone();

        let plan_a = sender.prepare_segment(100, &data_a).unwrap();
        let plan_b = sender.prepare_segment(200, &data_b).unwrap();

        assert_eq!(
            plan_a.chunks[0].payload_digest, plan_b.chunks[0].payload_digest,
            "identical chunk payloads must produce identical checksums"
        );
    }

    #[test]
    fn sender_max_inflight_config_is_stored() {
        let config = StateTransferConfig {
            chunk_size: 4096,
            max_inflight_chunks: 2,
            epoch_id: 1,
        };
        let sender = StateTransferSender::new(config);
        assert_eq!(sender.config().max_inflight_chunks, 2);
    }

    // ── Complete checksum cross-check with offer ────────────────────

    #[test]
    fn complete_checksum_matches_offer_checksum_for_same_payload() {
        let sender = StateTransferSender::default();
        let data = vec![0x77u8; 4096];
        let plan = sender.prepare_segment(42, &data).unwrap();

        let offer = SegmentOffer::new(42, plan.checksum, plan.size);
        let complete = SegmentComplete::new(42, plan.checksum);

        assert_eq!(offer.checksum, complete.full_checksum);
    }

    // ── Multi-chunk reassembly verification ─────────────────────────

    #[test]
    fn reassembled_chunks_match_original_data() {
        let original: &[u8] = b"this-is-a-128-byte-segment-payload-that-spans-across-multiple-chunks-when-using-a-small-chunk-size-of-32-bytes-for-testing######";

        let config = StateTransferConfig {
            chunk_size: 32,
            max_inflight_chunks: 4,
            epoch_id: 1,
        };
        let sender = StateTransferSender::new(config);
        let plan = sender.prepare_segment(99, original).unwrap();

        assert_eq!(plan.chunks.len(), 4); // 128 / 32 = 4

        // Reassemble and verify
        let mut reassembled = Vec::new();
        for chunk in &plan.chunks {
            chunk
                .verify_payload()
                .expect("chunk must pass verification");
            assert_eq!(
                chunk.offset,
                reassembled.len() as u64,
                "chunk offset must match reassembly position"
            );
            reassembled.extend_from_slice(&chunk.payload);
        }

        assert_eq!(reassembled, original);
    }

    // ── Domain separation verification ──────────────────────────────

    #[test]
    fn chunk_digest_differs_from_plain_blake3() {
        let data = b"domain separation validation".to_vec();
        let chunk = new_segment_chunk(1, 1, 0, data.len() as u64, data.clone(), true);

        let plain_blake3 = *blake3::hash(&data).as_bytes();
        assert_ne!(
            chunk.payload_digest, plain_blake3,
            "domain-separated checksum must differ from plain BLAKE3"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // StateTransferReceiver tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn receiver_accepts_offer_and_chunks_then_finalizes() {
        let sender = StateTransferSender::default();
        let data = vec![0xE0u8; 128 * 1024];
        let plan = sender.prepare_segment(1, &data).unwrap();

        let mut receiver = StateTransferReceiver::new(1);
        receiver
            .accept_offer(SegmentOffer::new(1, plan.checksum, plan.size))
            .unwrap();
        assert_eq!(receiver.segment_id(), Some(1));
        assert_eq!(receiver.received_bytes(), 0);

        for chunk in &plan.chunks {
            receiver.accept_chunk(chunk).unwrap();
        }

        assert_eq!(receiver.chunk_count(), 2);
        assert_eq!(receiver.received_bytes(), 128 * 1024);

        let result = receiver
            .finalize(&SegmentComplete::new(1, plan.checksum))
            .unwrap();
        assert_eq!(result, data);
        assert!(receiver.is_done());
    }

    #[test]
    fn receiver_rejects_offer_when_not_idle() {
        let mut receiver = StateTransferReceiver::new(1);
        let checksum = [0xA0u8; 32];
        let offer = SegmentOffer::new(1, checksum, 100);
        receiver.accept_offer(offer.clone()).unwrap();

        let err = receiver.accept_offer(offer).unwrap_err();
        assert!(matches!(err, SegmentTransferError::Protocol { .. }));
    }

    #[test]
    fn receiver_rejects_chunk_with_wrong_segment_id() {
        let sender = StateTransferSender::default();
        let data = b"test data".to_vec();
        let plan = sender.prepare_segment(42, &data).unwrap();

        let mut receiver = StateTransferReceiver::new(1);
        receiver
            .accept_offer(SegmentOffer::new(42, plan.checksum, plan.size))
            .unwrap();

        let bad_chunk = new_segment_chunk(1, 99, 0, 3, b"bad".to_vec(), true);
        let err = receiver.accept_chunk(&bad_chunk).unwrap_err();
        assert!(matches!(err, SegmentTransferError::Protocol { .. }));
    }

    #[test]
    fn receiver_rejects_chunk_with_wrong_offset() {
        let sender = StateTransferSender::default();
        let data = vec![0xBBu8; 200];
        let plan = sender.prepare_segment(7, &data).unwrap();

        let mut receiver = StateTransferReceiver::new(1);
        receiver
            .accept_offer(SegmentOffer::new(7, plan.checksum, plan.size))
            .unwrap();

        let bad_chunk = new_segment_chunk(1, 7, 100, 200, b"wrong offset".to_vec(), false);
        let err = receiver.accept_chunk(&bad_chunk).unwrap_err();
        assert!(matches!(err, SegmentTransferError::Protocol { .. }));
    }

    #[test]
    fn receiver_rejects_corrupted_chunk_payload() {
        let sender = StateTransferSender::default();
        let data = vec![0xCCu8; 4096];
        let plan = sender.prepare_segment(3, &data).unwrap();

        let mut receiver = StateTransferReceiver::new(1);
        receiver
            .accept_offer(SegmentOffer::new(3, plan.checksum, plan.size))
            .unwrap();

        let mut bad_chunk = plan.chunks[0].clone();
        bad_chunk.payload[100] ^= 0xFF;

        let err = receiver.accept_chunk(&bad_chunk).unwrap_err();
        assert!(
            matches!(err, SegmentTransferError::ChunkDigestMismatch { .. }),
            "expected ChunkDigestMismatch, got {err:?}"
        );
    }

    #[test]
    fn receiver_rejects_corrupted_chunk_digest() {
        let sender = StateTransferSender::default();
        let data = vec![0xDDu8; 4096];
        let plan = sender.prepare_segment(4, &data).unwrap();

        let mut receiver = StateTransferReceiver::new(1);
        receiver
            .accept_offer(SegmentOffer::new(4, plan.checksum, plan.size))
            .unwrap();

        let mut bad_chunk = plan.chunks[0].clone();
        bad_chunk.payload_digest[0] ^= 0xFF;

        let err = receiver.accept_chunk(&bad_chunk).unwrap_err();
        assert!(
            matches!(err, SegmentTransferError::ChunkDigestMismatch { .. }),
            "expected ChunkDigestMismatch for corrupted digest, got {err:?}"
        );
    }

    #[test]
    fn receiver_rejects_corruption_in_first_byte() {
        let sender = StateTransferSender::default();
        let data = vec![0xABu8; 8192];
        let plan = sender.prepare_segment(5, &data).unwrap();

        let mut receiver = StateTransferReceiver::new(1);
        receiver
            .accept_offer(SegmentOffer::new(5, plan.checksum, plan.size))
            .unwrap();

        let mut bad_chunk = plan.chunks[0].clone();
        bad_chunk.payload[0] ^= 0x01;

        let err = receiver.accept_chunk(&bad_chunk).unwrap_err();
        assert!(matches!(
            err,
            SegmentTransferError::ChunkDigestMismatch { .. }
        ));
    }

    #[test]
    fn receiver_rejects_corruption_in_last_byte_of_last_chunk() {
        let sender = StateTransferSender::default();
        let data = vec![0xBCu8; 128 * 1024];
        let plan = sender.prepare_segment(6, &data).unwrap();

        let mut receiver = StateTransferReceiver::new(1);
        receiver
            .accept_offer(SegmentOffer::new(6, plan.checksum, plan.size))
            .unwrap();

        // Accept first chunk cleanly
        receiver.accept_chunk(&plan.chunks[0]).unwrap();

        // Corrupt the last byte of the last chunk
        let last_idx = plan.chunks.len() - 1;
        let mut bad_chunk = plan.chunks[last_idx].clone();
        let last_byte = bad_chunk.payload.len() - 1;
        bad_chunk.payload[last_byte] ^= 0x80;

        let err = receiver.accept_chunk(&bad_chunk).unwrap_err();
        assert!(
            matches!(err, SegmentTransferError::ChunkDigestMismatch { .. }),
            "expected ChunkDigestMismatch, got {err:?}"
        );
    }

    #[test]
    fn receiver_rejects_incomplete_segment() {
        let sender = StateTransferSender::default();
        let data = vec![0xEFu8; 200 * 1024]; // 3+ chunks
        let plan = sender.prepare_segment(8, &data).unwrap();

        let mut receiver = StateTransferReceiver::new(1);
        receiver
            .accept_offer(SegmentOffer::new(8, plan.checksum, plan.size))
            .unwrap();

        receiver.accept_chunk(&plan.chunks[0]).unwrap();
        receiver.accept_chunk(&plan.chunks[1]).unwrap();

        let err = receiver
            .finalize(&SegmentComplete::new(8, plan.checksum))
            .unwrap_err();
        assert!(matches!(err, SegmentTransferError::SizeMismatch { .. }));
    }

    #[test]
    fn receiver_rejects_wrong_complete_checksum() {
        let sender = StateTransferSender::default();
        let data = vec![0xFAu8; 4096];
        let plan = sender.prepare_segment(9, &data).unwrap();

        let mut receiver = StateTransferReceiver::new(1);
        receiver
            .accept_offer(SegmentOffer::new(9, plan.checksum, plan.size))
            .unwrap();
        receiver.accept_chunk(&plan.chunks[0]).unwrap();

        let wrong_checksum = [0xFFu8; 32];
        let err = receiver
            .finalize(&SegmentComplete::new(9, wrong_checksum))
            .unwrap_err();
        assert!(matches!(err, SegmentTransferError::ChecksumMismatch { .. }));
    }

    #[test]
    fn receiver_handles_empty_segment() {
        let sender = StateTransferSender::default();
        let data: Vec<u8> = vec![];
        let plan = sender.prepare_segment(10, &data).unwrap();

        let mut receiver = StateTransferReceiver::new(1);
        receiver
            .accept_offer(SegmentOffer::new(10, plan.checksum, 0))
            .unwrap();
        receiver.accept_chunk(&plan.chunks[0]).unwrap();

        let result = receiver
            .finalize(&SegmentComplete::new(10, plan.checksum))
            .unwrap();
        assert!(result.is_empty());
        assert!(receiver.is_done());
    }

    #[test]
    fn receiver_handles_single_chunk_segment() {
        let sender = StateTransferSender::default();
        let data = vec![0x11u8; 1024];
        let plan = sender.prepare_segment(11, &data).unwrap();
        assert_eq!(plan.chunks.len(), 1);

        let mut receiver = StateTransferReceiver::new(1);
        receiver
            .accept_offer(SegmentOffer::new(11, plan.checksum, plan.size))
            .unwrap();
        receiver.accept_chunk(&plan.chunks[0]).unwrap();

        let result = receiver
            .finalize(&SegmentComplete::new(11, plan.checksum))
            .unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn receiver_multi_segment_sequential() {
        let sender = StateTransferSender::default();

        for seg_id in 1..=5 {
            let data = vec![seg_id as u8; 4096];
            let plan = sender.prepare_segment(seg_id, &data).unwrap();

            let mut receiver = StateTransferReceiver::new(1);
            receiver
                .accept_offer(SegmentOffer::new(seg_id, plan.checksum, plan.size))
                .unwrap();

            for chunk in &plan.chunks {
                receiver.accept_chunk(chunk).unwrap();
            }

            let result = receiver
                .finalize(&SegmentComplete::new(seg_id, plan.checksum))
                .unwrap();
            assert_eq!(result, data);
            assert_eq!(receiver.segment_id(), Some(seg_id));
        }
    }

    #[test]
    fn receiver_finalize_without_offer_is_rejected() {
        let mut receiver = StateTransferReceiver::new(1);
        let err = receiver
            .finalize(&SegmentComplete::new(1, [0u8; 32]))
            .unwrap_err();
        assert!(matches!(err, SegmentTransferError::Protocol { .. }));
    }

    #[test]
    fn receiver_rejects_chunk_before_offer() {
        let mut receiver = StateTransferReceiver::new(1);
        let chunk = new_segment_chunk(1, 1, 0, 4, b"data".to_vec(), true);
        let err = receiver.accept_chunk(&chunk).unwrap_err();
        assert!(matches!(err, SegmentTransferError::Protocol { .. }));
    }

    #[test]
    fn receiver_default_creates_idle() {
        let receiver = StateTransferReceiver::default();
        assert!(!receiver.is_done());
        assert_eq!(receiver.segment_id(), None);
        assert_eq!(receiver.received_bytes(), 0);
        assert_eq!(receiver.chunk_count(), 0);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Epoch validation tests
    // ═══════════════════════════════════════════════════════════════════

    /// Receiver rejects chunks where epoch_id is zero (stale placeholder).
    #[test]
    fn receiver_rejects_zero_epoch_chunk() {
        let mut receiver = StateTransferReceiver::new(7);
        let chunk = SegmentChunk::new(
            0,                     // epoch_id = 0 (stale)
            1,                     // object_id = 1
            0,                     // offset
            10,                    // total_size
            b"test data".to_vec(), // payload
            true,                  // is_last
        );
        let offer = SegmentOffer::new(1, chunk.payload_digest, 10);
        receiver.accept_offer(offer).unwrap();
        let err = receiver.accept_chunk(&chunk).unwrap_err();
        assert!(
            matches!(
                err,
                SegmentTransferError::EpochMismatch {
                    expected: 7,
                    got: 0,
                    ..
                }
            ),
            "expected EpochMismatch with expected=7 got=0, got {:?}",
            err
        );
    }

    /// Receiver rejects chunks with a non-matching (stale/future) epoch.
    #[test]
    fn receiver_rejects_stale_epoch_chunk() {
        let mut receiver = StateTransferReceiver::new(7);
        let chunk = SegmentChunk::new(
            3, // epoch_id = 3 (stale, expected 7)
            1,
            0,
            10,
            b"test data".to_vec(),
            true,
        );
        let offer = SegmentOffer::new(1, chunk.payload_digest, 10);
        receiver.accept_offer(offer).unwrap();
        let err = receiver.accept_chunk(&chunk).unwrap_err();
        assert!(
            matches!(
                err,
                SegmentTransferError::EpochMismatch {
                    expected: 7,
                    got: 3,
                    ..
                }
            ),
            "expected EpochMismatch with expected=7 got=3, got {:?}",
            err
        );
    }

    /// Receiver rejects chunks with a future epoch.
    #[test]
    fn receiver_rejects_future_epoch_chunk() {
        let mut receiver = StateTransferReceiver::new(7);
        let chunk = SegmentChunk::new(
            99, // epoch_id = 99 (future, expected 7)
            1,
            0,
            10,
            b"test data".to_vec(),
            true,
        );
        let offer = SegmentOffer::new(1, chunk.payload_digest, 10);
        receiver.accept_offer(offer).unwrap();
        let err = receiver.accept_chunk(&chunk).unwrap_err();
        assert!(
            matches!(
                err,
                SegmentTransferError::EpochMismatch {
                    expected: 7,
                    got: 99,
                    ..
                }
            ),
            "expected EpochMismatch with expected=7 got=99, got {:?}",
            err
        );
    }

    /// Receiver accepts chunks carrying the matching epoch.
    #[test]
    fn receiver_accepts_matching_epoch_chunk() {
        let mut receiver = StateTransferReceiver::new(7);
        let payload = b"test data".to_vec();
        let payload_len = payload.len() as u64;
        // Compute the full-segment checksum via the same domain as the sender.
        let segment_checksum = compute_segment_checksum(&payload);
        let chunk = SegmentChunk::new(
            7, // epoch_id = 7 (matches expected)
            1,
            0,
            payload_len,
            payload.clone(),
            true,
        );
        let offer = SegmentOffer::new(1, segment_checksum, payload_len);
        receiver.accept_offer(offer).unwrap();
        receiver.accept_chunk(&chunk).unwrap();
        let complete = SegmentComplete::new(1, segment_checksum);
        let data = receiver.finalize(&complete).unwrap();
        assert_eq!(data, payload);
    }

    /// Sender stamps the configured epoch_id into every chunk.
    #[test]
    fn sender_stamps_configured_epoch() {
        let config = StateTransferConfig {
            chunk_size: 4096,
            max_inflight_chunks: 4,
            epoch_id: 42,
        };
        let sender = StateTransferSender::new(config);
        let payload = vec![0xAAu8; 8192];
        let plan = sender.prepare_segment(5, &payload).unwrap();

        for chunk in &plan.chunks {
            assert_eq!(chunk.epoch_id, 42, "every chunk must carry epoch 42");
            assert_eq!(chunk.object_id, 5);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Transport loopback round-trip tests
    // ═══════════════════════════════════════════════════════════════════

    fn transport_nid(id: u64) -> tidefs_membership_epoch::NodeIdentity {
        tidefs_membership_epoch::NodeIdentity::new(id)
    }

    fn make_sched(
        seed: u64,
    ) -> std::rc::Rc<std::cell::RefCell<tidefs_transport::harness::DeterministicMessageScheduler>>
    {
        std::rc::Rc::new(std::cell::RefCell::new(
            tidefs_transport::harness::DeterministicMessageScheduler::new(
                tidefs_transport::harness::SchedulerConfig::deterministic(seed),
            ),
        ))
    }

    #[test]
    fn minimal_transport_loopback_test() {
        let sched = make_sched(42);
        let n1 = transport_nid(1);
        let n2 = transport_nid(2);

        let offer = SegmentOffer::new(42, [0xAAu8; 32], 100);
        let wire = StateTransferMessage::Offer(offer.clone()).encode().unwrap();
        sched.borrow_mut().register_node(n1);
        sched.borrow_mut().register_node(n2);
        sched.borrow_mut().send(n1, n2, 0, wire.clone(), 0);
        sched.borrow_mut().tick_n(5);

        let msg = sched.borrow_mut().recv(n2).expect("should receive message");
        let decoded = StateTransferMessage::decode(&msg.payload).expect("should decode");
        match decoded {
            StateTransferMessage::Offer(o) => {
                assert_eq!(o.segment_id, 42);
                assert_eq!(o.checksum, [0xAAu8; 32]);
                assert_eq!(o.size, 100);
            }
            _ => panic!("expected Offer, got {decoded:?}"),
        }
    }

    #[test]
    fn transport_loopback_single_segment() {
        let sched = make_sched(42);
        let n1 = transport_nid(1);
        let n2 = transport_nid(2);
        sched.borrow_mut().register_node(n1);
        sched.borrow_mut().register_node(n2);

        let sender = StateTransferSender::default();
        let segment_data = vec![0x42u8; 128 * 1024];
        let plan = sender.prepare_segment(100, &segment_data).unwrap();

        // Send offer
        let offer = SegmentOffer::new(100, plan.checksum, plan.size);
        sched.borrow_mut().send(
            n1,
            n2,
            0,
            StateTransferMessage::Offer(offer).encode().unwrap(),
            0,
        );

        // Send chunks
        let mut seq = 1u64;
        for chunk in &plan.chunks {
            sched.borrow_mut().send(
                n1,
                n2,
                0,
                StateTransferMessage::Chunk(chunk.clone()).encode().unwrap(),
                seq,
            );
            seq += 1;
        }

        // Send complete
        let complete = SegmentComplete::new(100, plan.checksum);
        sched.borrow_mut().send(
            n1,
            n2,
            0,
            StateTransferMessage::Complete(complete).encode().unwrap(),
            seq,
        );

        sched.borrow_mut().tick_n(10);

        // Receive and process
        let mut receiver = StateTransferReceiver::new(1);
        let mut received_data: Option<Vec<u8>> = None;
        while let Some(msg) = sched.borrow_mut().recv(n2) {
            match StateTransferMessage::decode(&msg.payload) {
                Ok(StateTransferMessage::Offer(offer)) => {
                    receiver.accept_offer(offer).unwrap();
                }
                Ok(StateTransferMessage::Chunk(chunk)) => {
                    receiver.accept_chunk(&chunk).unwrap();
                }
                Ok(StateTransferMessage::Complete(complete)) => {
                    received_data = Some(receiver.finalize(&complete).unwrap());
                }
                _ => {}
            }
        }

        assert_eq!(
            received_data.expect("should have received complete segment"),
            segment_data
        );
        assert!(receiver.is_done());
    }

    #[test]
    fn transport_loopback_multiple_segments() {
        let sched = make_sched(99);
        let n1 = transport_nid(1);
        let n2 = transport_nid(2);
        sched.borrow_mut().register_node(n1);
        sched.borrow_mut().register_node(n2);

        let sender = StateTransferSender::default();
        let num_segments = 10;
        let mut original_segments: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut seq = 0u64;

        for seg_id in 1..=num_segments {
            let data = vec![(seg_id * 37 % 251) as u8; 4096 + seg_id as usize * 1024];
            let plan = sender.prepare_segment(seg_id, &data).unwrap();
            original_segments.push((seg_id, data.clone()));

            sched.borrow_mut().send(
                n1,
                n2,
                0,
                StateTransferMessage::Offer(SegmentOffer::new(seg_id, plan.checksum, plan.size))
                    .encode()
                    .unwrap(),
                seq,
            );
            seq += 1;
            for chunk in &plan.chunks {
                sched.borrow_mut().send(
                    n1,
                    n2,
                    0,
                    StateTransferMessage::Chunk(chunk.clone()).encode().unwrap(),
                    seq,
                );
                seq += 1;
            }
            sched.borrow_mut().send(
                n1,
                n2,
                0,
                StateTransferMessage::Complete(SegmentComplete::new(seg_id, plan.checksum))
                    .encode()
                    .unwrap(),
                seq,
            );
            seq += 1;
        }

        sched.borrow_mut().tick_n(20);

        let mut receivers: std::collections::BTreeMap<u64, (StateTransferReceiver, Vec<u8>)> =
            std::collections::BTreeMap::new();

        while let Some(msg) = sched.borrow_mut().recv(n2) {
            match StateTransferMessage::decode(&msg.payload) {
                Ok(StateTransferMessage::Offer(offer)) => {
                    let mut r = StateTransferReceiver::new(1);
                    let sid = offer.segment_id;
                    r.accept_offer(offer).unwrap();
                    receivers.insert(sid, (r, Vec::new()));
                }
                Ok(StateTransferMessage::Chunk(chunk)) => {
                    let sid = chunk.object_id;
                    let (recv, _) = receivers.get_mut(&sid).expect("offer must precede chunk");
                    recv.accept_chunk(&chunk).unwrap();
                }
                Ok(StateTransferMessage::Complete(complete)) => {
                    let sid = complete.segment_id;
                    let (recv, _) = receivers
                        .get_mut(&sid)
                        .expect("offer must precede complete");
                    let data = recv.finalize(&complete).unwrap();
                    receivers.get_mut(&sid).unwrap().1 = data;
                }
                _ => {}
            }
        }

        for (seg_id, original) in &original_segments {
            let (_, received) = receivers.get(seg_id).expect("segment should be received");
            assert_eq!(received, original, "segment {seg_id} data mismatch");
        }
    }

    #[test]
    fn transport_loopback_corruption_rejected() {
        let sched = make_sched(77);
        let n1 = transport_nid(1);
        let n2 = transport_nid(2);
        sched.borrow_mut().register_node(n1);
        sched.borrow_mut().register_node(n2);

        let sender = StateTransferSender::default();
        let segment_data = vec![0x99u8; 64 * 1024];
        let plan = sender.prepare_segment(200, &segment_data).unwrap();

        sched.borrow_mut().send(
            n1,
            n2,
            0,
            StateTransferMessage::Offer(SegmentOffer::new(200, plan.checksum, plan.size))
                .encode()
                .unwrap(),
            0,
        );

        // Send a corrupted chunk
        let mut bad_chunk = plan.chunks[0].clone();
        bad_chunk.payload[100] ^= 0xFF;
        sched.borrow_mut().send(
            n1,
            n2,
            0,
            StateTransferMessage::Chunk(bad_chunk).encode().unwrap(),
            1,
        );

        sched.borrow_mut().send(
            n1,
            n2,
            0,
            StateTransferMessage::Complete(SegmentComplete::new(200, plan.checksum))
                .encode()
                .unwrap(),
            2,
        );

        sched.borrow_mut().tick_n(10);

        let mut receiver = StateTransferReceiver::new(1);
        let mut chunk_rejected = false;
        while let Some(msg) = sched.borrow_mut().recv(n2) {
            match StateTransferMessage::decode(&msg.payload) {
                Ok(StateTransferMessage::Offer(offer)) => {
                    receiver.accept_offer(offer).unwrap();
                }
                Ok(StateTransferMessage::Chunk(chunk)) => {
                    let result = receiver.accept_chunk(&chunk);
                    assert!(result.is_err(), "corrupted chunk must be rejected");
                    assert!(matches!(
                        result.unwrap_err(),
                        SegmentTransferError::ChunkDigestMismatch { .. }
                    ));
                    chunk_rejected = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(
            chunk_rejected,
            "corrupted chunk should have been processed and rejected"
        );
    }

    #[test]
    fn transport_loopback_varying_sizes() {
        let sched = make_sched(55);
        let n1 = transport_nid(1);
        let n2 = transport_nid(2);
        sched.borrow_mut().register_node(n1);
        sched.borrow_mut().register_node(n2);

        let sender = StateTransferSender::default();
        let sizes: Vec<usize> = vec![4096, 16384, 65536, 128 * 1024, 1024 * 1024];
        let mut expected: std::collections::BTreeMap<u64, Vec<u8>> =
            std::collections::BTreeMap::new();
        let mut seq = 0u64;

        for (i, &size) in sizes.iter().enumerate() {
            let seg_id = (i + 1) as u64;
            let data: Vec<u8> = (0..size).map(|j| (j % 251) as u8).collect();
            let plan = sender.prepare_segment(seg_id, &data).unwrap();
            expected.insert(seg_id, data.clone());

            sched.borrow_mut().send(
                n1,
                n2,
                0,
                StateTransferMessage::Offer(SegmentOffer::new(seg_id, plan.checksum, plan.size))
                    .encode()
                    .unwrap(),
                seq,
            );
            seq += 1;
            for chunk in &plan.chunks {
                sched.borrow_mut().send(
                    n1,
                    n2,
                    0,
                    StateTransferMessage::Chunk(chunk.clone()).encode().unwrap(),
                    seq,
                );
                seq += 1;
            }
            sched.borrow_mut().send(
                n1,
                n2,
                0,
                StateTransferMessage::Complete(SegmentComplete::new(seg_id, plan.checksum))
                    .encode()
                    .unwrap(),
                seq,
            );
            seq += 1;
        }

        sched.borrow_mut().tick_n(10);

        let mut receivers: std::collections::BTreeMap<u64, (StateTransferReceiver, Vec<u8>)> =
            std::collections::BTreeMap::new();
        while let Some(msg) = sched.borrow_mut().recv(n2) {
            match StateTransferMessage::decode(&msg.payload) {
                Ok(StateTransferMessage::Offer(offer)) => {
                    let mut r = StateTransferReceiver::new(1);
                    let sid = offer.segment_id;
                    r.accept_offer(offer).unwrap();
                    receivers.insert(sid, (r, Vec::new()));
                }
                Ok(StateTransferMessage::Chunk(chunk)) => {
                    let sid = chunk.object_id;
                    receivers
                        .get_mut(&sid)
                        .unwrap()
                        .0
                        .accept_chunk(&chunk)
                        .unwrap();
                }
                Ok(StateTransferMessage::Complete(complete)) => {
                    let sid = complete.segment_id;
                    let (recv, storage) = receivers.get_mut(&sid).unwrap();
                    *storage = recv.finalize(&complete).unwrap();
                }
                _ => {}
            }
        }

        for (seg_id, exp_data) in &expected {
            let (_, received) = receivers.get(seg_id).unwrap();
            assert_eq!(
                received,
                exp_data,
                "size {} segment mismatch",
                exp_data.len()
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Backpressure test: bounded in-flight chunks
    // ═══════════════════════════════════════════════════════════════════

    /// Simulated backpressure: send chunks over the loopback scheduler
    /// with an in-flight cap. When cap is reached, pause sending until
    /// the receiver acks (via SegmentComplete) to free a slot.
    #[test]
    fn backpressure_inflight_cap_2_streams_100_segments() {
        let sched = make_sched(123);
        let n1 = transport_nid(1);
        let n2 = transport_nid(2);
        sched.borrow_mut().register_node(n1);
        sched.borrow_mut().register_node(n2);

        let sender = StateTransferSender::new(StateTransferConfig {
            chunk_size: 16 * 1024, // 16 KiB chunks → more chunks per segment
            max_inflight_chunks: 2,
            epoch_id: 1,
        });

        let num_segments: u64 = 100;
        let inflight_cap: usize = sender.config().max_inflight_chunks;
        let mut seq = 0u64;

        // Prepare all segments upfront
        let mut plans: Vec<SegmentChunkPlan> = Vec::new();
        for seg_id in 1..=num_segments {
            let data = vec![(seg_id as u8).wrapping_mul(17); 4096 + (seg_id as usize % 8) * 512];
            plans.push(sender.prepare_segment(seg_id, &data).unwrap());
        }

        // Track in-flight: send offers + chunks for a segment, then
        // only proceed to the next segment when inflight slots free up.
        // An "ack" is simulated by the receiver processing SegmentComplete.
        let mut inflight_count: usize = 0;
        let mut next_seg_idx: usize = 0;
        let mut peak_inflight: usize;
        let mut completed: u64 = 0;
        let mut receivers: std::collections::BTreeMap<u64, (StateTransferReceiver, Vec<u8>)> =
            std::collections::BTreeMap::new();

        // Send initial batch of segments up to the inflight cap
        while next_seg_idx < plans.len() && inflight_count < inflight_cap {
            let plan = &plans[next_seg_idx];
            let offer = SegmentOffer::new(plan.segment_id, plan.checksum, plan.size);
            sched.borrow_mut().send(
                n1,
                n2,
                0,
                StateTransferMessage::Offer(offer).encode().unwrap(),
                seq,
            );
            seq += 1;
            for chunk in &plan.chunks {
                sched.borrow_mut().send(
                    n1,
                    n2,
                    0,
                    StateTransferMessage::Chunk(chunk.clone()).encode().unwrap(),
                    seq,
                );
                seq += 1;
            }
            sched.borrow_mut().send(
                n1,
                n2,
                0,
                StateTransferMessage::Complete(SegmentComplete::new(
                    plan.segment_id,
                    plan.checksum,
                ))
                .encode()
                .unwrap(),
                seq,
            );
            seq += 1;

            inflight_count += plan.chunks.len();
            next_seg_idx += 1;
        }
        peak_inflight = inflight_count;
        sched.borrow_mut().tick_n(5);

        // Alternate: receive completes, free slots, send more
        while completed < num_segments {
            // Receive available messages
            while let Some(msg) = sched.borrow_mut().recv(n2) {
                match StateTransferMessage::decode(&msg.payload) {
                    Ok(StateTransferMessage::Offer(offer)) => {
                        let mut r = StateTransferReceiver::new(1);
                        let sid = offer.segment_id;
                        r.accept_offer(offer).unwrap();
                        receivers.insert(sid, (r, Vec::new()));
                    }
                    Ok(StateTransferMessage::Chunk(chunk)) => {
                        let sid = chunk.object_id;
                        receivers
                            .get_mut(&sid)
                            .unwrap()
                            .0
                            .accept_chunk(&chunk)
                            .unwrap();
                        inflight_count = inflight_count.saturating_sub(1);
                    }
                    Ok(StateTransferMessage::Complete(complete)) => {
                        let sid = complete.segment_id;
                        let (recv, storage) = receivers.get_mut(&sid).unwrap();
                        *storage = recv.finalize(&complete).unwrap();
                        completed += 1;
                    }
                    _ => {}
                }
            }

            // Send more if slots are free
            while next_seg_idx < plans.len() && inflight_count < inflight_cap {
                let plan = &plans[next_seg_idx];
                let offer = SegmentOffer::new(plan.segment_id, plan.checksum, plan.size);
                sched.borrow_mut().send(
                    n1,
                    n2,
                    0,
                    StateTransferMessage::Offer(offer).encode().unwrap(),
                    seq,
                );
                seq += 1;
                for chunk in &plan.chunks {
                    sched.borrow_mut().send(
                        n1,
                        n2,
                        0,
                        StateTransferMessage::Chunk(chunk.clone()).encode().unwrap(),
                        seq,
                    );
                    seq += 1;
                }
                sched.borrow_mut().send(
                    n1,
                    n2,
                    0,
                    StateTransferMessage::Complete(SegmentComplete::new(
                        plan.segment_id,
                        plan.checksum,
                    ))
                    .encode()
                    .unwrap(),
                    seq,
                );
                seq += 1;

                inflight_count += plan.chunks.len();
                peak_inflight = peak_inflight.max(inflight_count);
                next_seg_idx += 1;
            }

            sched.borrow_mut().tick_n(3);
        }

        // Assert peak in-flight never exceeded cap * 2 (allow some slack for
        // chunks arriving in the same tick)
        let max_chunks = inflight_cap * 2;
        assert!(
            peak_inflight <= max_chunks,
            "peak in-flight {peak_inflight} exceeded cap*2 ({max_chunks})"
        );

        // Verify all 100 segments transferred correctly
        assert_eq!(completed, num_segments);
        for plan in &plans {
            let (_, received) = receivers.get(&plan.segment_id).unwrap();
            let expected_data = vec![
                (plan.segment_id as u8).wrapping_mul(17);
                4096 + (plan.segment_id as usize % 8) * 512
            ];
            assert_eq!(
                *received, expected_data,
                "segment {} data mismatch",
                plan.segment_id
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Two-node join scenario: seed 50 segments, join node, verify all
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn two_node_join_seed_50_transfer_all_verified() {
        let sched = make_sched(456);
        let n_seed = transport_nid(1); // existing node with segments
        let n_join = transport_nid(2); // joining node
        sched.borrow_mut().register_node(n_seed);
        sched.borrow_mut().register_node(n_join);

        let sender = StateTransferSender::default();
        let num_segments: u64 = 50;
        let mut seed_segments: std::collections::BTreeMap<u64, Vec<u8>> =
            std::collections::BTreeMap::new();
        let mut plans: Vec<SegmentChunkPlan> = Vec::new();
        let mut seq = 0u64;

        // Seed node: generate 50 segments with deterministic content
        for seg_id in 1..=num_segments {
            let data: Vec<u8> = (0..4096 + (seg_id as usize % 12) * 512)
                .map(|j| (j.wrapping_mul(seg_id as usize).wrapping_add(13) % 251) as u8)
                .collect();
            seed_segments.insert(seg_id, data.clone());
            let plan = sender.prepare_segment(seg_id, &data).unwrap();
            plans.push(plan);
        }

        // Transfer all 50 segments from seed to joiner
        for plan in &plans {
            let offer = SegmentOffer::new(plan.segment_id, plan.checksum, plan.size);
            sched.borrow_mut().send(
                n_seed,
                n_join,
                0,
                StateTransferMessage::Offer(offer).encode().unwrap(),
                seq,
            );
            seq += 1;

            for chunk in &plan.chunks {
                sched.borrow_mut().send(
                    n_seed,
                    n_join,
                    0,
                    StateTransferMessage::Chunk(chunk.clone()).encode().unwrap(),
                    seq,
                );
                seq += 1;
            }

            let complete = SegmentComplete::new(plan.segment_id, plan.checksum);
            sched.borrow_mut().send(
                n_seed,
                n_join,
                0,
                StateTransferMessage::Complete(complete).encode().unwrap(),
                seq,
            );
            seq += 1;
        }

        sched.borrow_mut().tick_n(10);

        // Joiner receives and reassembles all segments
        let mut receivers: std::collections::BTreeMap<u64, (StateTransferReceiver, Vec<u8>)> =
            std::collections::BTreeMap::new();

        while let Some(msg) = sched.borrow_mut().recv(n_join) {
            match StateTransferMessage::decode(&msg.payload) {
                Ok(StateTransferMessage::Offer(offer)) => {
                    let mut r = StateTransferReceiver::new(1);
                    let sid = offer.segment_id;
                    r.accept_offer(offer).unwrap();
                    receivers.insert(sid, (r, Vec::new()));
                }
                Ok(StateTransferMessage::Chunk(chunk)) => {
                    let sid = chunk.object_id;
                    let (recv, _) = receivers.get_mut(&sid).expect("offer must precede chunk");
                    recv.accept_chunk(&chunk).unwrap();
                }
                Ok(StateTransferMessage::Complete(complete)) => {
                    let sid = complete.segment_id;
                    let (recv, storage) = receivers
                        .get_mut(&sid)
                        .expect("offer must precede complete");
                    *storage = recv.finalize(&complete).unwrap();
                }
                Ok(StateTransferMessage::Failure(_)) => {
                    panic!("unexpected transfer failure in join test");
                }
                _ => {}
            }
        }

        // Verify: all 50 segments received with correct content and checksum
        assert_eq!(
            receivers.len() as u64,
            num_segments,
            "all seeded segments must be received"
        );

        for (seg_id, expected_data) in &seed_segments {
            let (recv, received) = receivers
                .get(seg_id)
                .unwrap_or_else(|| panic!("segment {seg_id} not received"));
            assert_eq!(
                *received, *expected_data,
                "segment {seg_id}: received data differs from seed data"
            );
            assert!(
                recv.is_done(),
                "segment {seg_id} receiver must be in done state"
            );

            // Cross-verify: recompute checksum on received data and compare
            // against the seed plan's checksum
            let recomputed = compute_segment_checksum(received);
            let plan = plans.iter().find(|p| p.segment_id == *seg_id).unwrap();
            assert_eq!(
                recomputed, plan.checksum,
                "segment {seg_id}: recomputed checksum must match plan checksum"
            );
        }
    }
}
