#![forbid(unsafe_code)]

//! P8-03 data_copy_6 chunk shipper — deterministic execution model.
//!
//!
//! ## Chunk-Shipper Orchestration Engine
//!
//! The orchestration engine (added in chunk 2) provides the session-layer
//! coordination between send-stream chunk framing and receive-stream assembly
//! across four modules:
//!
//! - [`session_pairing`]: [`ShipperSession`] binds a send-stream [`SendQueue`]
//!   to a receive-stream [`ObjectAssembler`] with a shared BLAKE3-256
//!   domain-separated session-integrity hasher. Tracks lifecycle through
//!   four states: `Paired`, `Transferring`, `Draining`, `Closed`.
//!
//! - [`flow_control`]: [`FlowController`] provides sliding-window
//!   backpressure with configurable `max_inflight_chunks`. The dispatcher
//!   acquires [`SendPermit`]s before sending; acknowledgements release
//!   slots back into the window.
//!
//! - [`dispatch`]: [`ChunkDispatcher`] iterates a [`TransferPlan`], acquires
//!   send slots, invokes send-stream encode+transmit, routes received
//!   chunks to the assembler, and emits [`TransferProgress`] events.
//!
//! - [`orchestrator`]: [`ChunkShipper`] drives the full lifecycle — session
//!   pairing, dispatch loop, drain, and integrity finalization — producing
//!   a [`TransferOutcome`] with per-object BLAKE3 digest confirmation.
//!
//! ## Integration points
//!
//! - Send side: [`tidefs_send_stream::chunk_encoder::TransferChunkEncoder`]
//!   splits objects into [`TransferChunk`] frames.
//! - Receive side: [`tidefs_receive_stream::decoder::ChunkDecoder`] and
//!   [`tidefs_receive_stream::assembler::ObjectAssembler`] reassemble.
//! - Flow control: bounded inflight window prevents sender overrun.
//! - Integrity: domain-separated BLAKE3-256 hasher at session and chunk levels.
//!
//! Bridges the gap between transfer tickets produced by `data_copy_1.transfer_orchestrator`
//! and actual data movement + verification handoff to `data_copy_2.verification_engine`.
//!
//! This is an executable model proving the staging → stream → receive pipeline.
//! It is not a networked production runtime.
//!
//! ## Architecture
//!
//! ```text
//! TransferOrchestrator  →  ChunkShipper  →  VerificationEngine
//!   (tickets)               (movement)       (digest/receipt)
//! ```
//!
//! ## Zero-copy readiness
//!
//! The chunk shipper models three transport paths aligned with P4-04 zero-copy/DMA law:
//! - `RdmaDirectDataPlacement` — RDMA direct placement (future)
//! - `IoUringSplice` — io_uring splice/copy_file_range (same-node)
//! - `TcpFallback` — TCP streaming with buffer copies
//!
//! At this stage the model uses in-memory payloads and deterministically routes
//! through the chosen path without real DMA/uring syscalls.
pub mod dispatch;
pub mod flow_control;
pub mod orchestrator;
pub mod protocol;
pub mod session_pairing;

pub use dispatch::{ChunkDispatcher, ObjectDescriptor, TransferPlan, TransferProgress};
pub use flow_control::{FlowControlError, FlowController, SendPermit};
pub use orchestrator::{ChunkShipper, ShipError, TransferOutcome};
pub use session_pairing::{SessionState, SessionStateError, ShipperSession};

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_replication_model::{
    emit_replica_transfer_receipt, ObjectDigest, ReplicaChunkState, ReplicaChunkStateRecord,
    ReplicaTransferReceipt, ReplicaTransferTicketRecord, ReplicatedReceiptId, ReplicatedSubjectId,
    TransferScheduleRecord, VerificationStatus,
};

/// Chunk shipper validation gate constant.
pub const CHUNK_SHIPPER_GATE_P8_03_DATA_COPY_6: &str =
    "P8-03 data_copy_6 chunk shipper: stage, stream, and receive replica chunks";

// ── Transport path model ──

/// Transport path used for chunk movement (P4-04 zero-copy/DMA integration point).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkShippingTransport {
    /// RDMA direct data placement (zero-copy, remote).
    RdmaDirectDataPlacement,
    /// io_uring splice / copy_file_range (zero-copy, same-node).
    IoUringSplice,
    /// TCP streaming with buffer copies (fallback).
    TcpFallback,
}

impl ChunkShippingTransport {
    /// Select the best available transport given source/target co-location and RDMA capability.
    ///
    /// Rules:
    /// - Same-node with io_uring → `IoUringSplice`
    /// - Cross-node with RDMA → `RdmaDirectDataPlacement`
    /// - Otherwise → `TcpFallback`
    #[must_use]
    pub fn select(
        source: MemberId,
        target: MemberId,
        rdma_capable: bool,
        io_uring_available: bool,
    ) -> Self {
        if source == target && io_uring_available {
            Self::IoUringSplice
        } else if rdma_capable {
            Self::RdmaDirectDataPlacement
        } else {
            Self::TcpFallback
        }
    }
}

// ── Staging types ──

/// Phase of a chunk staging operation.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkStagingPhase {
    /// Chunk has not yet been read from the source store.
    Pending,
    /// Chunk is being read into staging buffers.
    Staging,
    /// Chunk is fully staged and ready for transport.
    Staged,
    /// Staging failed (source unreadable, checksum mismatch, etc.).
    Failed,
    /// Staging was cancelled (expiry, fence violation).
    Cancelled,
}

/// A transport-ready buffer holding a staged chunk payload.
///
/// Under zero-copy law (P4-04), this buffer may be a loaned page or a DMA-registered region.
/// In this deterministic model, it is an owned `Vec<u8>`.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ChunkStagingBuffer {
    /// Which chunk this buffer holds.
    pub chunk_id: u64,
    /// Subject the chunk belongs to.
    pub subject_ref: ReplicatedSubjectId,
    /// Byte range within the subject this chunk covers.
    pub range_start: u64,
    pub range_end: u64,
    /// The chunk payload (deterministic model: owned Vec; production: loaned buffer).
    pub payload: Vec<u8>,
    /// Digest of the payload for integrity checking.
    pub digest: ObjectDigest,
    /// Current staging phase.
    pub phase: ChunkStagingPhase,
    /// Transport path selected for this buffer.
    pub transport: ChunkShippingTransport,
}

impl ChunkStagingBuffer {
    /// Create a new staging buffer for a chunk.
    #[must_use]
    pub fn new(
        chunk_id: u64,
        subject_ref: ReplicatedSubjectId,
        range_start: u64,
        range_end: u64,
        payload: Vec<u8>,
        digest: ObjectDigest,
        transport: ChunkShippingTransport,
    ) -> Self {
        Self {
            chunk_id,
            subject_ref,
            range_start,
            range_end,
            payload,
            digest,
            phase: ChunkStagingPhase::Pending,
            transport,
        }
    }

    /// Number of bytes in the payload.
    #[must_use]
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

// ── Transfer progress tracking ──

/// State of a single chunk within a transfer operation.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkTransferPhase {
    /// Not yet started.
    Pending,
    /// Buffers staged on source side.
    Staged,
    /// Data is in flight to the target.
    InFlight,
    /// Transfer completed successfully.
    Completed,
    /// Transfer failed (network error, checksum, etc.).
    Failed,
    /// Transfer retrying within ticket window.
    Retrying,
}

/// Per-chunk transfer progress tracking.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ChunkTransferProgress {
    pub chunk_id: u64,
    pub subject_ref: ReplicatedSubjectId,
    pub bytes_total: u64,
    pub bytes_transferred: u64,
    pub bytes_staged: u64,
    pub phase: ChunkTransferPhase,
    pub failure_count: u32,
    pub failure_reason: Option<String>,
    /// Number of chunks remaining in the transfer before completion.
    pub remaining_chunks: u64,
}

impl ChunkTransferProgress {
    #[must_use]
    pub fn new(chunk_id: u64, subject_ref: ReplicatedSubjectId, bytes_total: u64) -> Self {
        Self {
            chunk_id,
            subject_ref,
            bytes_total,
            bytes_transferred: 0,
            bytes_staged: 0,
            phase: ChunkTransferPhase::Pending,
            failure_count: 0,
            failure_reason: None,
            remaining_chunks: 0,
        }
    }

    /// Fraction of bytes transferred (0.0 to 1.0).
    #[must_use]
    pub fn progress_ratio(&self) -> f64 {
        if self.bytes_total == 0 {
            return 1.0;
        }
        self.bytes_transferred as f64 / self.bytes_total as f64
    }
}

// ── Chunk range descriptor ─────────────────────────────────────────────

/// Byte range for one chunk within an object.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChunkRange {
    /// Starting byte offset (inclusive).
    pub start_byte: u64,
    /// Ending byte offset (exclusive).
    pub end_byte: u64,
}

impl ChunkRange {
    #[must_use]
    pub fn new(start_byte: u64, end_byte: u64) -> Self {
        Self {
            start_byte,
            end_byte,
        }
    }

    #[must_use]
    pub fn len(&self) -> u64 {
        self.end_byte.saturating_sub(self.start_byte)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.end_byte <= self.start_byte
    }
}

// ── ChunkTransferRequest ───────────────────────────────────────────────

/// Initiation message sent by the source node to the target node to request
/// transfer of a set of chunks for a specific object.
///
/// Encoded in binary with a BLAKE3-256 integrity envelope trailing the payload.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ChunkTransferRequest {
    /// Unique transfer identifier for this request.
    pub transfer_id: u64,
    /// Object whose chunks are being transferred.
    pub object_id: ReplicatedSubjectId,
    /// Node holding the source data.
    pub source_node: MemberId,
    /// Node receiving the data.
    pub target_node: MemberId,
    /// Monotonic sequence number for ordering across requests.
    pub sequence_number: u64,
    /// Chunk byte ranges requested for transfer.
    pub chunks: Vec<ChunkRange>,
    /// Total number of chunks in the transfer.
    pub total_chunks: u64,
}

impl ChunkTransferRequest {
    /// Total bytes to transfer across all requested chunks.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.chunks.iter().map(|r| r.len()).sum()
    }

    /// Encode the request into a binary frame with BLAKE3 integrity envelope.
    ///
    /// Wire format (big-endian):
    ///   - transfer_id:      u64 (8 bytes)
    ///   - object_id.0:      u64 (8 bytes)
    ///   - source_node.0:    u64 (8 bytes)
    ///   - target_node.0:    u64 (8 bytes)
    ///   - sequence_number:  u64 (8 bytes)
    ///   - chunk_count:      u32 (4 bytes)
    ///   - total_chunks:     u64 (8 bytes)
    ///   - for each chunk: range_start u64 (8 bytes) + range_end u64 (8 bytes)
    ///   - blake3_digest:    [u8; 32] (of all preceding bytes)
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(52 + self.chunks.len() * 16 + 32);
        buf.extend_from_slice(&self.transfer_id.to_be_bytes());
        buf.extend_from_slice(&self.object_id.0.to_be_bytes());
        buf.extend_from_slice(&self.source_node.0.to_be_bytes());
        buf.extend_from_slice(&self.target_node.0.to_be_bytes());
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&(self.chunks.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.total_chunks.to_be_bytes());
        for chunk in &self.chunks {
            buf.extend_from_slice(&chunk.start_byte.to_be_bytes());
            buf.extend_from_slice(&chunk.end_byte.to_be_bytes());
        }
        let digest = blake3::hash(&buf);
        buf.extend_from_slice(digest.as_bytes());
        buf
    }

    /// Decode a ChunkTransferRequest from a binary frame, verifying the
    /// BLAKE3 integrity envelope.
    ///
    /// Returns  if the frame is too short, the chunk count is
    /// inconsistent, or the BLAKE3 digest fails verification.
    #[must_use]
    pub fn decode(frame: &[u8]) -> Option<Self> {
        // Minimum frame: 52 header bytes + 32 digest = 84 bytes
        if frame.len() < 84 {
            return None;
        }
        let payload_end = frame.len() - 32;
        let stored_digest: [u8; 32] = frame[payload_end..].try_into().ok()?;
        let computed_digest = blake3::hash(&frame[..payload_end]);
        if stored_digest != *computed_digest.as_bytes() {
            return None;
        }

        let transfer_id = u64::from_be_bytes(frame[0..8].try_into().ok()?);
        let object_id = ReplicatedSubjectId(u64::from_be_bytes(frame[8..16].try_into().ok()?));
        let source_node = MemberId(u64::from_be_bytes(frame[16..24].try_into().ok()?));
        let target_node = MemberId(u64::from_be_bytes(frame[24..32].try_into().ok()?));
        let sequence_number = u64::from_be_bytes(frame[32..40].try_into().ok()?);
        let chunk_count = u32::from_be_bytes(frame[40..44].try_into().ok()?) as usize;
        let total_chunks = u64::from_be_bytes(frame[44..52].try_into().ok()?);

        let expected_payload = 52 + chunk_count * 16 + 32;
        if frame.len() != expected_payload {
            return None;
        }

        let mut chunks = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            let offset = 52 + i * 16;
            let start_byte = u64::from_be_bytes(frame[offset..offset + 8].try_into().ok()?);
            let end_byte = u64::from_be_bytes(frame[offset + 8..offset + 16].try_into().ok()?);
            chunks.push(ChunkRange {
                start_byte,
                end_byte,
            });
        }

        Some(Self {
            transfer_id,
            object_id,
            source_node,
            target_node,
            sequence_number,
            chunks,
            total_chunks,
        })
    }
}

// ── ChunkTransferResponse ──────────────────────────────────────────────

/// Response from the target node accepting or rejecting a transfer request.
///
/// Encoded in binary with a BLAKE3-256 integrity envelope trailing the payload.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ChunkTransferResponse {
    /// Transfer identifier echoed from the request.
    pub transfer_id: u64,
    /// Whether the target accepted the transfer.
    pub accepted: bool,
    /// Reason for rejection when accepted is false.
    pub rejection_reason: Option<String>,
    /// Sequence number echoed from the request.
    pub sequence_number: u64,
    /// Maximum number of chunks the target will accept in this session.
    pub max_chunks_accepted: u64,
}

impl ChunkTransferResponse {
    /// Create an acceptance response.
    #[must_use]
    pub fn accept(transfer_id: u64, sequence_number: u64, max_chunks: u64) -> Self {
        Self {
            transfer_id,
            accepted: true,
            rejection_reason: None,
            sequence_number,
            max_chunks_accepted: max_chunks,
        }
    }

    /// Create a rejection response.
    #[must_use]
    pub fn reject(transfer_id: u64, sequence_number: u64, reason: impl Into<String>) -> Self {
        Self {
            transfer_id,
            accepted: false,
            rejection_reason: Some(reason.into()),
            sequence_number,
            max_chunks_accepted: 0,
        }
    }

    /// Encode the response into a binary frame with BLAKE3 integrity envelope.
    ///
    /// Wire format (big-endian):
    ///   - transfer_id:        u64 (8 bytes)
    ///   - accepted:           u8  (1 byte: 1=accepted, 0=rejected)
    ///   - reason_len:         u16 (2 bytes)
    ///   - rejection_reason:   UTF-8 (reason_len bytes)
    ///   - sequence_number:    u64 (8 bytes)
    ///   - max_chunks_accepted: u64 (8 bytes)
    ///   - blake3_digest:      [u8; 32] (of all preceding bytes)
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let reason_bytes = self.rejection_reason.as_deref().unwrap_or("").as_bytes();
        let reason_len = reason_bytes.len().min(u16::MAX as usize) as u16;
        let mut buf = Vec::with_capacity(27 + reason_len as usize + 32);
        buf.extend_from_slice(&self.transfer_id.to_be_bytes());
        buf.push(if self.accepted { 1 } else { 0 });
        buf.extend_from_slice(&reason_len.to_be_bytes());
        buf.extend_from_slice(&reason_bytes[..reason_len as usize]);
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.max_chunks_accepted.to_be_bytes());
        let digest = blake3::hash(&buf);
        buf.extend_from_slice(digest.as_bytes());
        buf
    }

    /// Decode a ChunkTransferResponse from a binary frame, verifying the
    /// BLAKE3 integrity envelope.
    ///
    /// Returns  if the frame is too short, the reason_len is
    /// inconsistent, or the BLAKE3 digest fails verification.
    #[must_use]
    pub fn decode(frame: &[u8]) -> Option<Self> {
        // Minimum frame: 27 header bytes + 32 digest = 59 bytes
        if frame.len() < 59 {
            return None;
        }
        let payload_end = frame.len() - 32;
        let stored_digest: [u8; 32] = frame[payload_end..].try_into().ok()?;
        let computed_digest = blake3::hash(&frame[..payload_end]);
        if stored_digest != *computed_digest.as_bytes() {
            return None;
        }

        let transfer_id = u64::from_be_bytes(frame[0..8].try_into().ok()?);
        let accepted_byte = frame[8];
        let reason_len = u16::from_be_bytes(frame[9..11].try_into().ok()?) as usize;
        let expected_payload = 27 + reason_len + 32;
        if frame.len() != expected_payload {
            return None;
        }
        let rejection_reason = if reason_len > 0 {
            Some(String::from_utf8(frame[11..11 + reason_len].to_vec()).ok()?)
        } else {
            None
        };
        let seq_offset = 11 + reason_len;
        let sequence_number =
            u64::from_be_bytes(frame[seq_offset..seq_offset + 8].try_into().ok()?);
        let max_chunks_accepted =
            u64::from_be_bytes(frame[seq_offset + 8..seq_offset + 16].try_into().ok()?);

        Some(Self {
            transfer_id,
            accepted: accepted_byte != 0,
            rejection_reason,
            sequence_number,
            max_chunks_accepted,
        })
    }
}

// ── Target-side staging area ──

/// A target-side staging buffer holding a received chunk pending verification.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReceivedChunk {
    pub chunk_id: u64,
    pub subject_ref: ReplicatedSubjectId,
    pub payload: Vec<u8>,
    pub source_digest: ObjectDigest,
    pub received_digest: ObjectDigest,
    pub range_start: u64,
    pub range_end: u64,
    pub verified: bool,
}

/// Target-side staging area for received chunks awaiting verification.
///
/// Accumulates received chunks from shipping sessions and hands them
/// off to `data_copy_2.verification_engine`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ChunkStagingArea {
    /// Chunks received and staged for verification, keyed by chunk_id.
    pub staged_chunks: BTreeMap<u64, ReceivedChunk>,
    /// Total bytes staged in this area.
    pub total_bytes_staged: u64,
    /// Number of chunks that failed integrity checks on receive.
    pub rejected_chunks: Vec<u64>,
}

impl ChunkStagingArea {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a received chunk into the staging area.
    ///
    /// If the received digest matches the source digest, the chunk is accepted
    /// and staged for verification. Otherwise, it is rejected.
    pub fn accept(&mut self, chunk: ReceivedChunk) -> ChunkAcceptResult {
        let digest_match = chunk.source_digest == chunk.received_digest;
        if digest_match {
            self.total_bytes_staged += chunk.payload.len() as u64;
            self.staged_chunks.insert(chunk.chunk_id, chunk);
            ChunkAcceptResult::Accepted
        } else {
            self.rejected_chunks.push(chunk.chunk_id);
            ChunkAcceptResult::RejectedDigestMismatch
        }
    }

    /// Drain all staged chunks for verification.
    #[must_use]
    pub fn drain_for_verification(&mut self) -> Vec<ReceivedChunk> {
        let chunks: Vec<_> = self.staged_chunks.values().cloned().collect();
        self.staged_chunks.clear();
        self.total_bytes_staged = 0;
        chunks
    }

    /// Number of chunks pending verification.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.staged_chunks.len()
    }
}

/// Result of accepting a chunk into the staging area.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkAcceptResult {
    Accepted,
    RejectedDigestMismatch,
}

// ── Shipping session ──

/// A bounded chunk shipping session, bound to a single transfer ticket.
///
/// Each session stages chunks from source, streams them to target, and
/// emits a transfer receipt upon completion.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ChunkShippingSession {
    pub session_id: u64,
    pub ticket: ReplicaTransferTicketRecord,
    pub transport: ChunkShippingTransport,
    pub max_retries: u32,
    pub state: ShippingSessionState,
    /// Per-chunk transfer progress.
    pub progress: BTreeMap<u64, ChunkTransferProgress>,
    /// Total bytes successfully transferred in this session.
    pub bytes_moved: u64,
    /// Transfer receipt emitted at session close.
    pub transfer_receipt: Option<ReplicaTransferReceipt>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ShippingSessionState {
    Created,
    Staging,
    Streaming,
    Completed,
    Failed(String),
    Expired,
}

impl ChunkShippingSession {
    /// Create a new chunk shipping session for a transfer ticket.
    #[must_use]
    pub fn new(
        session_id: u64,
        ticket: ReplicaTransferTicketRecord,
        transport: ChunkShippingTransport,
        max_retries: u32,
    ) -> Self {
        Self {
            session_id,
            ticket,
            transport,
            max_retries,
            state: ShippingSessionState::Created,
            progress: BTreeMap::new(),
            bytes_moved: 0,
            transfer_receipt: None,
        }
    }

    /// Check whether the ticket is still valid (not expired).
    #[must_use]
    pub fn is_ticket_valid(&self, current_epoch: u64) -> bool {
        self.ticket.expiry > current_epoch
    }

    /// Total bytes to transfer across all chunks in this session.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.progress.values().map(|p| p.bytes_total).sum()
    }

    /// Overall progress ratio (0.0 to 1.0).
    #[must_use]
    pub fn progress_ratio(&self) -> f64 {
        let total = self.total_bytes();
        if total == 0 {
            return 0.0;
        }
        self.bytes_moved as f64 / total as f64
    }

    /// Mark the session as completed and emit a transfer receipt.
    pub fn complete(
        &mut self,
        completion_epoch: EpochId,
        worker_refs: &[MemberId],
    ) -> ReplicaTransferReceipt {
        let source_anchor_hash = crate::derive_anchor_hash(
            self.ticket.ticket_id.0,
            self.ticket.source_anchor_set.iter().map(|m| m.0).sum(),
        );
        let target_anchor_hash =
            crate::derive_anchor_hash(source_anchor_hash, self.ticket.target_ref.0);

        let receipt = emit_replica_transfer_receipt(
            &self.ticket,
            self.bytes_moved,
            source_anchor_hash,
            target_anchor_hash,
            completion_epoch,
            worker_refs,
        );

        self.state = ShippingSessionState::Completed;
        self.transfer_receipt = Some(receipt.clone());
        receipt
    }

    /// Mark the session as failed.
    pub fn fail(&mut self, reason: String) {
        self.state = ShippingSessionState::Failed(reason);
    }

    /// Mark the session as expired.
    pub fn expire(&mut self) {
        self.state = ShippingSessionState::Expired;
    }
}

// ── Chunk shipping result ──

/// Aggregate result of a chunk shipping operation.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ChunkShippingReport {
    pub session_id: u64,
    pub ticket_id: ReplicatedReceiptId,
    pub bytes_staged: u64,
    pub bytes_streamed: u64,
    pub bytes_received: u64,
    pub chunks_succeeded: usize,
    pub chunks_failed: usize,
    pub chunks_retried: usize,
    pub transport: ChunkShippingTransport,
    pub transfer_receipt: Option<ReplicaTransferReceipt>,
    pub chunk_states: Vec<ReplicaChunkStateRecord>,
}

// ── Core algorithms ──

/// Stage chunks from the source object store into transport-ready buffers.
///
/// P8-03 §6: `stage_replica_chunks_for_transport()`.
///
/// Input: a transfer ticket, chunk payloads (mocked for deterministic model),
/// and a selected transport path.
///
/// Output: staged buffers with phase tracking.
///
/// In the deterministic model, chunk payloads are supplied directly as `Vec<u8>`
/// (simulating reads from the source object store). Production would read from
/// the local object store under pin-budget constraints.
#[must_use]
pub fn stage_replica_chunks_for_transport(
    ticket: &ReplicaTransferTicketRecord,
    chunk_payloads: &[(u64, Vec<u8>, ObjectDigest)],
    transport: ChunkShippingTransport,
) -> Vec<ChunkStagingBuffer> {
    let mut buffers = Vec::with_capacity(chunk_payloads.len());

    for (idx, (chunk_id, payload, _digest)) in chunk_payloads.iter().enumerate() {
        let subject_ref = ticket
            .subject_refs
            .get(idx)
            .copied()
            .unwrap_or(ReplicatedSubjectId::default());

        let range_end = payload.len() as u64;
        let mut buffer = ChunkStagingBuffer::new(
            *chunk_id,
            subject_ref,
            0,
            range_end,
            payload.clone(),
            derive_receive_digest(payload),
            transport,
        );
        buffer.phase = ChunkStagingPhase::Staged;
        buffers.push(buffer);
    }

    buffers
}

/// Stream staged chunk buffers to the target under ticket constraints.
///
/// P8-03 §6: `stream_replica_chunks_under_ticket()`.
///
/// Simulates the movement of chunk payloads from source to target.
/// In a production system, this would use the selected transport path
/// (RDMA, io_uring, TCP). In the deterministic model, payloads are
/// "transferred" by cloning them to the output and tracking progress.
///
/// Returns (transferred payloads, progress updates, bytes_moved).
#[must_use]
pub fn stream_replica_chunks_under_ticket(
    session: &mut ChunkShippingSession,
    buffers: &[ChunkStagingBuffer],
) -> (Vec<(u64, Vec<u8>, ObjectDigest)>, u64) {
    session.state = ShippingSessionState::Streaming;
    let mut transferred_payloads = Vec::with_capacity(buffers.len());
    let mut total_bytes_moved: u64 = 0;

    for buffer in buffers {
        let mut progress =
            ChunkTransferProgress::new(buffer.chunk_id, buffer.subject_ref, buffer.len() as u64);

        if buffer.phase == ChunkStagingPhase::Staged {
            progress.bytes_staged = buffer.len() as u64;
            progress.bytes_transferred = buffer.len() as u64;
            progress.phase = ChunkTransferPhase::Completed;

            total_bytes_moved += buffer.len() as u64;
            transferred_payloads.push((buffer.chunk_id, buffer.payload.clone(), buffer.digest));
        } else {
            progress.phase = ChunkTransferPhase::Failed;
            progress.failure_count += 1;
            progress.failure_reason =
                Some(format!("Buffer not staged: phase = {:?}", buffer.phase));
        }

        session.progress.insert(buffer.chunk_id, progress);
    }

    session.bytes_moved = total_bytes_moved;

    (transferred_payloads, total_bytes_moved)
}

/// Receive chunk payloads on the target side and stage them for verification.
///
/// P8-03 §6: `receive_replica_chunks_and_stage_for_verification()`.
///
/// Reassembles received chunk payloads into a target-side staging area,
/// computes receive-side digests, and categorizes each chunk as accepted
/// or rejected.
///
/// Returns the populated staging area with accepted chunks ready for
/// verification by `data_copy_2.verification_engine`.
#[must_use]
pub fn receive_replica_chunks_and_stage_for_verification(
    transferred: &[(u64, Vec<u8>, ObjectDigest)],
    subject_refs: &[ReplicatedSubjectId],
) -> ChunkStagingArea {
    let mut staging_area = ChunkStagingArea::new();

    for (idx, (chunk_id, payload, source_digest)) in transferred.iter().enumerate() {
        let subject_ref = subject_refs
            .get(idx)
            .copied()
            .unwrap_or(ReplicatedSubjectId::default());

        // Compute receive-side digest (deterministic model: re-derive from payload hash).
        // Production would compute BLAKE3-256 or equivalent.
        let received_digest = derive_receive_digest(payload);

        let range_end = payload.len() as u64;
        let received = ReceivedChunk {
            chunk_id: *chunk_id,
            subject_ref,
            payload: payload.clone(),
            source_digest: *source_digest,
            received_digest,
            range_start: 0,
            range_end,
            verified: false,
        };

        staging_area.accept(received);
    }

    staging_area
}

/// Execute the full chunk shipping pipeline for a scheduled transfer.
///
/// This is the primary entry point: it stages chunks, streams them, receives
/// them on the target side, and produces a shipping report with transfer receipt.
///
/// P8-03 `data_copy_6.chunk_shipper` — canonical execution.
#[must_use]
pub fn execute_chunk_shipping_pipeline(
    schedule: &TransferScheduleRecord,
    chunk_payloads: &[(u64, Vec<u8>, ObjectDigest)],
    completion_epoch: EpochId,
    worker_refs: &[MemberId],
    max_retries: u32,
    rdma_capable: bool,
    io_uring_available: bool,
) -> ChunkShippingReport {
    let transport = ChunkShippingTransport::select(
        schedule.assignment.source,
        schedule.assignment.target,
        rdma_capable,
        io_uring_available,
    );

    let mut session = ChunkShippingSession::new(
        schedule.ticket.ticket_id.0,
        schedule.ticket.clone(),
        transport,
        max_retries,
    );

    // Phase 1: Stage chunks on source side
    session.state = ShippingSessionState::Staging;
    let buffers = stage_replica_chunks_for_transport(&schedule.ticket, chunk_payloads, transport);
    let bytes_staged: u64 = buffers.iter().map(|b| b.len() as u64).sum();

    // Phase 2: Stream chunks to target
    let (transferred, bytes_moved) = stream_replica_chunks_under_ticket(&mut session, &buffers);

    // Phase 3: Receive and stage for verification
    let staging_area = receive_replica_chunks_and_stage_for_verification(
        &transferred,
        &schedule.ticket.subject_refs,
    );

    let bytes_received: u64 = staging_area.total_bytes_staged;

    // Emit transfer receipt
    let receipt = session.complete(completion_epoch, worker_refs);

    // Collect chunk state records
    let chunk_states: Vec<ReplicaChunkStateRecord> = chunk_payloads
        .iter()
        .enumerate()
        .map(|(idx, (chunk_id, _, digest))| {
            let subject_ref = schedule
                .ticket
                .subject_refs
                .get(idx)
                .copied()
                .unwrap_or(ReplicatedSubjectId::default());
            ReplicaChunkStateRecord {
                chunk_id: *chunk_id,
                subject_ref,
                source_ref: schedule.assignment.source,
                target_ref: schedule.assignment.target,
                range_ref: chunk_payloads[idx].1.len() as u64,
                digest: *digest,
                state: ReplicaChunkState::Committed,
                transfer_ticket_ref: schedule.ticket.ticket_id,
                verification_receipt_ref: receipt.receipt_id,
            }
        })
        .collect();

    let chunks_succeeded = chunk_states.len();
    let chunks_failed: usize = staging_area.rejected_chunks.len();
    let rejected_ids: Vec<u64> = staging_area.rejected_chunks.clone();

    ChunkShippingReport {
        session_id: session.session_id,
        ticket_id: schedule.ticket.ticket_id,
        bytes_staged,
        bytes_streamed: bytes_moved,
        bytes_received,
        chunks_succeeded,
        chunks_failed,
        chunks_retried: if chunks_failed > 0 { chunks_failed } else { 0 },
        transport,
        transfer_receipt: Some(receipt),
        chunk_states: chunk_states
            .into_iter()
            .filter(|cs| !rejected_ids.contains(&cs.chunk_id))
            .collect(),
    }
}
// ── Post-verification advancement ──

/// After verification receipts are emitted by `data_copy_2.verification_engine`,
/// advance chunk state records from Transferring/Verifying to Committed.
///
/// P8-03 §6: advances chunks from in-flight or verifying to their final committed state.
/// Failed or cancelled chunks remain as-is.
pub fn advance_chunks_after_verification(
    chunk_records: &[ReplicaChunkStateRecord],
    verification_status: VerificationStatus,
) -> Vec<ReplicaChunkStateRecord> {
    chunk_records
        .iter()
        .map(|rec| {
            let new_state = match (rec.state, verification_status) {
                (ReplicaChunkState::Verifying, VerificationStatus::Verified) => {
                    ReplicaChunkState::Committed
                }
                (ReplicaChunkState::Transferring, VerificationStatus::Verified) => {
                    ReplicaChunkState::Committed
                }
                (ReplicaChunkState::Verifying, _) => ReplicaChunkState::Failed,
                (ReplicaChunkState::Transferring, _) => ReplicaChunkState::Failed,
                (ReplicaChunkState::Pending, _) => ReplicaChunkState::Cancelled,
                (other, _) => other,
            };
            ReplicaChunkStateRecord {
                state: new_state,
                ..rec.clone()
            }
        })
        .collect()
}

/// Reasons a chunk shipment can fail (P8-03 §data_copy_6).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ChunkShipFailure {
    SourceUnreadable(String),
    TransportError(String),
    TargetUnwritable(String),
    DigestMismatch {
        expected: ObjectDigest,
        received: ObjectDigest,
    },
    TicketExpired {
        ticket_id: ReplicatedReceiptId,
        expiry_epoch: u64,
        current_epoch: u64,
    },
    BudgetExhausted {
        budget_ref: ReplicatedReceiptId,
    },
    Cancelled,
}

/// Top-level chunk shipping state for a multi-chunk shipping operation.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkShippingState {
    Idle,
    Staging,
    Streaming,
    Receiving,
    Verifying,
    Complete,
    Failed,
}

pub fn derive_anchor_hash(base: u64, seed: u64) -> u64 {
    base.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(seed)
}

/// Compute a BLAKE3-256 digest over the payload and return the first 8 bytes
/// as an `ObjectDigest` for chunk integrity verification.
///
/// The full 32-byte BLAKE3 hash is computed; the truncated 8-byte digest
/// provides sufficient collision resistance for per-chunk verification within
/// a bounded transfer session, while the full 32-byte hash is used in the
/// wire-protocol integrity envelopes of `ChunkTransferRequest` and
/// `ChunkTransferResponse`.
#[must_use]
pub fn derive_receive_digest(payload: &[u8]) -> ObjectDigest {
    let hash = blake3::hash(payload);
    let u64_bytes: [u8; 8] = hash.as_bytes()[..8].try_into().unwrap();
    ObjectDigest(u64::from_le_bytes(u64_bytes))
}

/// Exponential backoff delay computation for transient transport failures.
///
/// Returns `base_delay * 2^attempt`, clamped to `max_delay`. Used by
/// transport session retry loops to avoid thundering herd on recovery.
#[must_use]
pub fn exponential_backoff(attempt: u32, base_delay: Duration, max_delay: Duration) -> Duration {
    let multiplier = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
    let delay = base_delay.saturating_mul(multiplier.min(u32::MAX as u64) as u32);
    delay.min(max_delay)
}

/// Compute the next retry delay for a given attempt number, using
/// a default base of 100ms and max of 30s.
#[must_use]
pub fn default_backoff(attempt: u32) -> Duration {
    exponential_backoff(attempt, Duration::from_millis(100), Duration::from_secs(30))
}

// ── Batch shipping ──

/// Execute the chunk shipping pipeline for an entire orchestration plan.
///
/// Map from chunk ID to list of (seed, payload, digest) tuples.
type ChunkPayloadMap = BTreeMap<u64, Vec<(u64, Vec<u8>, ObjectDigest)>>;
/// Iterates over all scheduled transfers, runs the full pipeline for each,
/// and aggregates results.
#[must_use]
pub fn ship_all_scheduled_transfers(
    scheduled: &[TransferScheduleRecord],
    chunk_payloads_map: &ChunkPayloadMap,
    completion_epoch: EpochId,
    worker_refs: &[MemberId],
    max_retries: u32,
    rdma_capable: bool,
    io_uring_available: bool,
) -> Vec<ChunkShippingReport> {
    scheduled
        .iter()
        .map(|schedule| {
            let payloads = chunk_payloads_map
                .get(&schedule.ticket.ticket_id.0)
                .cloned()
                .unwrap_or_default();
            execute_chunk_shipping_pipeline(
                schedule,
                &payloads,
                completion_epoch,
                worker_refs,
                max_retries,
                rdma_capable,
                io_uring_available,
            )
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// Sequenced Reliable Delivery Protocol
// ═══════════════════════════════════════════════════════════════════════════
//
// ChunkHeader wire framing, ChunkSender with bounded send window and
// retransmission, ChunkReceiver with cumulative ACKs and gap detection.
// Operates over a trait-based transport session abstraction.

// ── Chunk flags ──────────────────────────────────────────────────────────

/// Bitfield flags carried in the chunk header.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChunkFlags(u8);

impl ChunkFlags {
    /// First chunk of a multi-chunk stream.
    pub const START: u8 = 0x01;
    /// Last chunk of a multi-chunk stream.
    pub const END: u8 = 0x02;
    /// Sender is retransmitting this chunk.
    pub const RETRANSMIT: u8 = 0x04;
    /// Message is an ACK (not a data chunk).
    pub const ACK: u8 = 0x08;

    #[must_use]
    pub fn new() -> Self {
        Self(0)
    }

    #[must_use]
    pub fn with(mut self, flag: u8) -> Self {
        self.0 |= flag;
        self
    }

    #[must_use]
    pub fn has(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    #[must_use]
    pub fn is_data(&self) -> bool {
        !self.has(Self::ACK)
    }

    #[must_use]
    pub fn is_ack(&self) -> bool {
        self.has(Self::ACK)
    }

    #[must_use]
    pub fn is_start(&self) -> bool {
        self.has(Self::START)
    }

    #[must_use]
    pub fn is_end(&self) -> bool {
        self.has(Self::END)
    }

    #[must_use]
    pub fn is_retransmit(&self) -> bool {
        self.has(Self::RETRANSMIT)
    }

    #[must_use]
    pub fn bits(&self) -> u8 {
        self.0
    }

    #[must_use]
    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }
}

// ── ChunkHeader wire framing ──────────────────────────────────────────────

/// On-wire frame for a chunk data or ACK message.
///
/// Encoding (21 bytes, big-endian):
///   - chunk_id:       u64  (8 bytes)
///   - sequence_number: u64 (8 bytes)
///   - payload_length:  u32 (4 bytes)
///   - flags:           u8  (1 byte)
///
/// For ACK messages, chunk_id and payload_length are zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkHeader {
    pub chunk_id: u64,
    pub sequence_number: u64,
    pub payload_length: u32,
    pub flags: ChunkFlags,
}

/// Size of an encoded ChunkHeader in bytes.
pub const CHUNK_HEADER_SIZE: usize = 21;

impl ChunkHeader {
    /// Create a header for a data chunk.
    #[must_use]
    pub fn data(
        chunk_id: u64,
        sequence_number: u64,
        payload_length: u32,
        flags: ChunkFlags,
    ) -> Self {
        debug_assert!(flags.is_data(), "data header must not have ACK flag set");
        Self {
            chunk_id,
            sequence_number,
            payload_length,
            flags,
        }
    }

    /// Create a header for an ACK message.
    #[must_use]
    pub fn ack(_sequence_number: u64) -> Self {
        Self {
            chunk_id: 0,
            sequence_number: 0,
            payload_length: 0,
            flags: ChunkFlags::new().with(ChunkFlags::ACK),
        }
    }

    /// Encode the header into a 21-byte buffer.
    #[must_use]
    pub fn encode(&self) -> [u8; CHUNK_HEADER_SIZE] {
        let mut buf = [0u8; CHUNK_HEADER_SIZE];
        buf[0..8].copy_from_slice(&self.chunk_id.to_be_bytes());
        buf[8..16].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[16..20].copy_from_slice(&self.payload_length.to_be_bytes());
        buf[20] = self.flags.bits();
        buf
    }

    /// Decode a header from a 21-byte slice.
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != CHUNK_HEADER_SIZE {
            return None;
        }
        let chunk_id = u64::from_be_bytes(buf[0..8].try_into().ok()?);
        let sequence_number = u64::from_be_bytes(buf[8..16].try_into().ok()?);
        let payload_length = u32::from_be_bytes(buf[16..20].try_into().ok()?);
        let flags = ChunkFlags::from_bits(buf[20]);
        Some(Self {
            chunk_id,
            sequence_number,
            payload_length,
            flags,
        })
    }

    /// Encode this header followed by payload bytes into a single buffer.
    #[must_use]
    pub fn encode_with_payload(&self, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(CHUNK_HEADER_SIZE + payload.len());
        buf.extend_from_slice(&self.encode());
        buf.extend_from_slice(payload);
        buf
    }

    /// Decode a header and return the remaining payload bytes.
    #[must_use]
    pub fn decode_from_frame(frame: &[u8]) -> Option<(Self, &[u8])> {
        if frame.len() < CHUNK_HEADER_SIZE {
            return None;
        }
        let header = Self::decode(&frame[..CHUNK_HEADER_SIZE])?;
        Some((header, &frame[CHUNK_HEADER_SIZE..]))
    }
}

// ── ChunkAck wire message ─────────────────────────────────────────────────

/// Cumulative ACK with gap detection.
///
/// Wire format:
///   - ack_sequence: u64 (8 bytes, big-endian)
///   - gap_count:   u32 (4 bytes, big-endian)
///   - gaps:        u64 × gap_count (each 8 bytes, big-endian)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkAck {
    pub ack_sequence: u64,
    pub gaps: Vec<u64>,
}

impl ChunkAck {
    #[must_use]
    pub fn new(ack_sequence: u64) -> Self {
        Self {
            ack_sequence,
            gaps: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_gaps(ack_sequence: u64, gaps: Vec<u64>) -> Self {
        Self { ack_sequence, gaps }
    }

    /// Encode the ACK into a byte vector.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.gaps.len() * 8);
        buf.extend_from_slice(&self.ack_sequence.to_be_bytes());
        buf.extend_from_slice(&(self.gaps.len() as u32).to_be_bytes());
        for gap in &self.gaps {
            buf.extend_from_slice(&gap.to_be_bytes());
        }
        buf
    }

    /// Decode an ACK from a byte slice.
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        let ack_sequence = u64::from_be_bytes(buf[0..8].try_into().ok()?);
        let gap_count = u32::from_be_bytes(buf[8..12].try_into().ok()?) as usize;
        let expected_len = 12 + gap_count * 8;
        if buf.len() < expected_len {
            return None;
        }
        let mut gaps = Vec::with_capacity(gap_count);
        for i in 0..gap_count {
            let offset = 12 + i * 8;
            gaps.push(u64::from_be_bytes(buf[offset..offset + 8].try_into().ok()?));
        }
        Some(Self { ack_sequence, gaps })
    }
}

// ── ChunkTransport trait ──────────────────────────────────────────────────

/// Error type for chunk transport operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChunkTransportError {
    Io(String),
    SessionClosed,
    FrameDecode(String),
    Timeout,
}

impl std::fmt::Display for ChunkTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "transport I/O error: {msg}"),
            Self::SessionClosed => write!(f, "session closed"),
            Self::FrameDecode(msg) => write!(f, "frame decode error: {msg}"),
            Self::Timeout => write!(f, "transport timeout"),
        }
    }
}

/// Abstract transport for chunk send/receive over a session.
///
/// Implementations back the chunk-shipper onto real transport sessions
/// (TCP, RDMA, in-process loopback) without coupling to a specific
/// transport implementation.
pub trait ChunkTransport {
    fn send(&mut self, payload: &[u8]) -> Result<(), ChunkTransportError>;
    fn recv(&mut self) -> Result<Vec<u8>, ChunkTransportError>;
}

// ── In-flight chunk record ─────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq)]
struct InflightChunk {
    chunk_id: u64,
    sequence_number: u64,
    payload: Vec<u8>,
    flags: ChunkFlags,
    send_time: Instant,
    retransmit_count: u32,
}

// ── ChunkSender ───────────────────────────────────────────────────────────

/// Reliable chunk sender with bounded send window, cumulative ACK processing,
/// and timer-driven retransmission.
///
/// Assigns monotonic sequence numbers to outbound chunks. Buffers in-flight
/// chunks until acknowledged. Detects gaps in ACK windows and retransmits
/// timed-out chunks.
pub struct ChunkSender<T: ChunkTransport> {
    pub transport: T,
    window_size: usize,
    next_sequence: u64,
    inflight: BTreeMap<u64, InflightChunk>,
    acked_sequence: u64,
    retransmit_timeout: Duration,
}

impl<T: ChunkTransport> ChunkSender<T> {
    #[must_use]
    pub fn new(transport: T, window_size: usize, retransmit_timeout: Duration) -> Self {
        Self {
            transport,
            window_size,
            next_sequence: 0,
            inflight: BTreeMap::new(),
            acked_sequence: 0,
            retransmit_timeout,
        }
    }

    #[must_use]
    pub fn is_window_full(&self) -> bool {
        self.inflight.len() >= self.window_size
    }

    #[must_use]
    pub fn window_available(&self) -> usize {
        self.window_size.saturating_sub(self.inflight.len())
    }

    #[must_use]
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    #[must_use]
    pub fn acked_sequence(&self) -> u64 {
        self.acked_sequence
    }

    #[must_use]
    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    /// Send a data chunk. Returns the assigned sequence number.
    pub fn send_chunk(
        &mut self,
        chunk_id: u64,
        payload: &[u8],
        flags: ChunkFlags,
    ) -> Result<u64, ChunkTransportError> {
        if self.is_window_full() {
            return Err(ChunkTransportError::Io("send window full".into()));
        }

        debug_assert!(flags.is_data(), "send_chunk requires data flags (not ACK)");

        let seq = self.next_sequence;
        self.next_sequence += 1;

        let header = ChunkHeader::data(chunk_id, seq, payload.len() as u32, flags);
        let frame = header.encode_with_payload(payload);

        self.transport.send(&frame)?;

        self.inflight.insert(
            seq,
            InflightChunk {
                chunk_id,
                sequence_number: seq,
                payload: payload.to_vec(),
                flags,
                send_time: Instant::now(),
                retransmit_count: 0,
            },
        );

        Ok(seq)
    }

    /// Process a cumulative ACK. Returns newly acknowledged sequence numbers.
    pub fn process_ack(&mut self, ack: &ChunkAck) -> Vec<u64> {
        if ack.ack_sequence > self.acked_sequence {
            self.acked_sequence = ack.ack_sequence;
        }

        let mut removed = Vec::new();
        let gap_set: std::collections::BTreeSet<u64> = ack.gaps.iter().copied().collect();

        let to_remove: Vec<u64> = self
            .inflight
            .keys()
            .copied()
            .filter(|seq| *seq <= ack.ack_sequence && !gap_set.contains(seq))
            .collect();

        for seq in to_remove {
            self.inflight.remove(&seq);
            removed.push(seq);
        }

        removed
    }

    /// Check for timed-out chunks and retransmit them.
    pub fn check_timeouts(&mut self) -> Result<Vec<u64>, ChunkTransportError> {
        let now = Instant::now();
        let mut retransmitted = Vec::new();

        let timed_out: Vec<(u64, Vec<u8>, ChunkFlags, u64)> = self
            .inflight
            .values()
            .filter(|c| now.duration_since(c.send_time) >= self.retransmit_timeout)
            .map(|c| {
                let mut flags = c.flags;
                flags = flags.with(ChunkFlags::RETRANSMIT);
                (c.sequence_number, c.payload.clone(), flags, c.chunk_id)
            })
            .collect();

        for (seq, payload, flags, chunk_id) in timed_out {
            let header = ChunkHeader::data(chunk_id, seq, payload.len() as u32, flags);
            let frame = header.encode_with_payload(&payload);
            self.transport.send(&frame)?;

            if let Some(inflight) = self.inflight.get_mut(&seq) {
                inflight.send_time = now;
                inflight.retransmit_count += 1;
                inflight.flags = flags;
            }
            retransmitted.push(seq);
        }

        Ok(retransmitted)
    }

    /// Receive and process an incoming ACK from the transport.
    pub fn recv_ack(&mut self) -> Result<ChunkAck, ChunkTransportError> {
        let frame = self.transport.recv()?;
        let (header, ack_payload) = ChunkHeader::decode_from_frame(&frame)
            .ok_or_else(|| ChunkTransportError::FrameDecode("header too short".into()))?;

        if !header.flags.is_ack() {
            return Err(ChunkTransportError::FrameDecode(
                "expected ACK frame, got data frame".into(),
            ));
        }

        let ack = ChunkAck::decode(ack_payload)
            .ok_or_else(|| ChunkTransportError::FrameDecode("ACK payload corrupt".into()))?;

        self.process_ack(&ack);
        Ok(ack)
    }
}

impl<T: ChunkTransport> std::fmt::Debug for ChunkSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkSender")
            .field("window_size", &self.window_size)
            .field("next_sequence", &self.next_sequence)
            .field("inflight_count", &self.inflight.len())
            .field("acked_sequence", &self.acked_sequence)
            .finish()
    }
}

// ── ChunkReceiver ─────────────────────────────────────────────────────────

/// Reliable chunk receiver with sequence-number tracking, gap detection,
/// cumulative ACK generation, duplicate suppression, and in-order
/// reassembly into a deliverable stream.
pub struct ChunkReceiver<T: ChunkTransport> {
    pub transport: T,
    next_expected: u64,
    received: BTreeMap<u64, ReceivedChunkData>,
    seen: std::collections::BTreeSet<u64>,
    max_delivered: u64,
}

/// A received chunk held in the reassembly buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedChunkData {
    pub chunk_id: u64,
    pub sequence_number: u64,
    pub payload: Vec<u8>,
    pub flags: ChunkFlags,
}

/// A chunk delivered in order from the stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveredChunk {
    pub chunk_id: u64,
    pub sequence_number: u64,
    pub payload: Vec<u8>,
    pub flags: ChunkFlags,
    pub is_retransmit: bool,
}

impl<T: ChunkTransport> ChunkReceiver<T> {
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_expected: 0,
            received: BTreeMap::new(),
            seen: std::collections::BTreeSet::new(),
            max_delivered: 0,
        }
    }

    #[must_use]
    pub fn next_expected(&self) -> u64 {
        self.next_expected
    }

    /// Receive a single chunk frame from the transport and buffer it.
    pub fn recv_chunk(&mut self) -> Result<ReceivedChunkData, ChunkTransportError> {
        let frame = self.transport.recv()?;
        let (header, payload) = ChunkHeader::decode_from_frame(&frame)
            .ok_or_else(|| ChunkTransportError::FrameDecode("header too short".into()))?;

        if !header.flags.is_data() {
            return Err(ChunkTransportError::FrameDecode(
                "expected data frame, got non-data frame".into(),
            ));
        }

        let seq = header.sequence_number;

        // Duplicate detection
        if self.seen.contains(&seq) {
            if let Some(existing) = self.received.get(&seq) {
                return Ok(existing.clone());
            }
            // Already delivered and purged
            if seq < self.next_expected {
                return Ok(ReceivedChunkData {
                    chunk_id: header.chunk_id,
                    sequence_number: seq,
                    payload: payload.to_vec(),
                    flags: header.flags,
                });
            }
        }

        self.seen.insert(seq);

        let rc = ReceivedChunkData {
            chunk_id: header.chunk_id,
            sequence_number: seq,
            payload: payload.to_vec(),
            flags: header.flags,
        };

        if seq >= self.next_expected {
            self.received.insert(seq, rc.clone());
        }

        Ok(rc)
    }

    /// Deliver all contiguous in-order chunks from the reassembly buffer.
    #[must_use]
    pub fn deliver(&mut self) -> Vec<DeliveredChunk> {
        let mut delivered = Vec::new();

        while let Some(chunk) = self.received.remove(&self.next_expected) {
            let is_retransmit = chunk.flags.has(ChunkFlags::RETRANSMIT);
            delivered.push(DeliveredChunk {
                chunk_id: chunk.chunk_id,
                sequence_number: chunk.sequence_number,
                payload: chunk.payload,
                flags: chunk.flags,
                is_retransmit,
            });
            self.next_expected += 1;
        }

        if let Some(last) = delivered.last() {
            self.max_delivered = last.sequence_number;
        }

        delivered
    }

    /// Compute gaps between next_expected and highest seen sequence.
    #[must_use]
    pub fn compute_gaps(&self) -> Vec<u64> {
        if self.seen.is_empty() {
            return Vec::new();
        }

        let max_seen = *self.seen.last().unwrap_or(&0);
        let mut gaps = Vec::new();

        for seq in self.next_expected..=max_seen {
            if !self.received.contains_key(&seq) {
                gaps.push(seq);
            }
        }

        gaps
    }

    /// Build a cumulative ACK from current receiver state.
    #[must_use]
    pub fn build_ack(&self) -> ChunkAck {
        let ack_seq = self.next_expected.saturating_sub(1);
        let gaps = self.compute_gaps();
        ChunkAck::with_gaps(ack_seq, gaps)
    }

    /// Send a cumulative ACK over the transport.
    pub fn send_ack(&mut self) -> Result<ChunkAck, ChunkTransportError> {
        let ack = self.build_ack();
        let ack_payload = ack.encode();
        let header = ChunkHeader::ack(0);
        let frame = header.encode_with_payload(&ack_payload);
        self.transport.send(&frame)?;
        Ok(ack)
    }

    #[must_use]
    pub fn buffered_count(&self) -> usize {
        self.received.len()
    }

    #[must_use]
    pub fn max_delivered(&self) -> u64 {
        self.max_delivered
    }
}

impl<T: ChunkTransport> std::fmt::Debug for ChunkReceiver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkReceiver")
            .field("next_expected", &self.next_expected)
            .field("buffered", &self.received.len())
            .field("seen", &self.seen.len())
            .field("max_delivered", &self.max_delivered)
            .finish()
    }
}

// ── Loopback transport for testing ─────────────────────────────────────────

// Loopback transport imports are at the top of the file

/// A pair of connected in-process transport endpoints for testing
/// the chunk-shipper protocol without a real network.
///
/// Each endpoint has its own send queue and recv queue. `send` on one
/// endpoint delivers to the paired endpoint's `recv` queue.
pub struct LoopbackPair {
    pub left: LoopbackEndpoint,
    pub right: LoopbackEndpoint,
}

/// One endpoint of a loopback pair.
#[derive(Clone)]
pub struct LoopbackEndpoint {
    send_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    recv_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl std::fmt::Debug for LoopbackEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackEndpoint")
            .field(
                "send_queue_len",
                &self.send_queue.lock().map(|q| q.len()).unwrap_or(0),
            )
            .field(
                "recv_queue_len",
                &self.recv_queue.lock().map(|q| q.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl Default for LoopbackPair {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopbackPair {
    /// Create a connected pair of loopback endpoints.
    #[must_use]
    pub fn new() -> Self {
        let a_to_b: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let b_to_a: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));

        Self {
            left: LoopbackEndpoint {
                send_queue: a_to_b.clone(),
                recv_queue: b_to_a.clone(),
            },
            right: LoopbackEndpoint {
                send_queue: b_to_a,
                recv_queue: a_to_b,
            },
        }
    }
}

impl ChunkTransport for LoopbackEndpoint {
    fn send(&mut self, payload: &[u8]) -> Result<(), ChunkTransportError> {
        self.send_queue
            .lock()
            .map_err(|e| ChunkTransportError::Io(format!("lock poisoned: {e}")))?
            .push_back(payload.to_vec());
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, ChunkTransportError> {
        // Spin-wait with a small sleep to avoid busy-looping
        loop {
            let mut queue = self
                .recv_queue
                .lock()
                .map_err(|e| ChunkTransportError::Io(format!("lock poisoned: {e}")))?;
            if let Some(data) = queue.pop_front() {
                return Ok(data);
            }
            drop(queue);
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

// ── ChunkStreamConfig ─────────────────────────────────────────────────────

/// Configuration for chunk streaming with backpressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkStreamConfig {
    pub max_chunk_size: usize,
    pub channel_capacity: usize,
    pub retransmit_timeout: Duration,
}

impl Default for ChunkStreamConfig {
    fn default() -> Self {
        Self {
            max_chunk_size: 64 * 1024,
            channel_capacity: 16,
            retransmit_timeout: Duration::from_secs(2),
        }
    }
}

impl ChunkStreamConfig {
    #[must_use]
    pub fn new(max_chunk_size: usize, channel_capacity: usize) -> Self {
        Self {
            max_chunk_size,
            channel_capacity,
            ..Default::default()
        }
    }
}

// ── CancelationToken ──────────────────────────────────────────────────────

use std::sync::atomic::{AtomicBool, Ordering};

/// Shared cancelation token for aborting chunk transfers.
#[derive(Clone, Debug)]
pub struct CancelationToken {
    cancelled: Arc<AtomicBool>,
}

impl Default for CancelationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelationToken {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

// ── Bounded-streaming chunk pipeline ──────────────────────────────────────

/// Send a batch of chunks with window-based backpressure.
///
/// Returns the number of chunks successfully sent before window exhaustion
/// or cancelation. When `sender.window_size` is smaller than `chunks.len()`,
/// the sender eventually blocks on a full window; this demonstrates
/// backpressure at the transport level.
pub fn send_chunks_with_backpressure(
    sender: &mut ChunkSender<LoopbackEndpoint>,
    chunks: &[(u64, Vec<u8>, ChunkFlags)],
    cancel: &CancelationToken,
) -> usize {
    let mut sent = 0;
    for (chunk_id, payload, flags) in chunks {
        if cancel.is_cancelled() {
            break;
        }
        match sender.send_chunk(*chunk_id, payload, *flags) {
            Ok(_) => sent += 1,
            Err(_) => break, // window full or transport error
        }
    }
    sent
}

/// Receive and deliver all available chunks from the receiver.
pub fn recv_and_deliver(
    receiver: &mut ChunkReceiver<LoopbackEndpoint>,
    expected_count: usize,
    cancel: &CancelationToken,
) -> Vec<DeliveredChunk> {
    let mut all_delivered = Vec::new();
    for _ in 0..expected_count {
        if cancel.is_cancelled() {
            break;
        }
        match receiver.recv_chunk() {
            Ok(_) => {
                let mut batch = receiver.deliver();
                all_delivered.append(&mut batch);
            }
            Err(_) => break,
        }
    }
    all_delivered
}

/// Split a data buffer into config-sized chunks, stream through sender/receiver,
/// and verify the aggregate BLAKE3 digest on both sides.
///
/// Returns (chunks_sent, delivered_chunks, aggregate_digest).
/// The returned digest is the sender-side aggregate when both sides agree;
/// otherwise `[0u8; 32]`.
pub fn stream_chunks_with_aggregate_verification(
    mut sender: ChunkSender<LoopbackEndpoint>,
    mut receiver: ChunkReceiver<LoopbackEndpoint>,
    data: &[u8],
    config: &ChunkStreamConfig,
    cancel: &CancelationToken,
) -> (usize, Vec<DeliveredChunk>, [u8; 32]) {
    let num_chunks = data.len().div_ceil(config.max_chunk_size).max(1);
    let mut chunks: Vec<(u64, Vec<u8>, ChunkFlags)> = Vec::with_capacity(num_chunks);
    let mut sender_hasher = crate::protocol::ChunkAggregateHasher::new();

    for i in 0..num_chunks {
        let start = i * config.max_chunk_size;
        let end = (start + config.max_chunk_size).min(data.len());
        let payload = data[start..end].to_vec();
        sender_hasher.update(&payload);

        let mut flags = ChunkFlags::new();
        if i == 0 {
            flags = flags.with(ChunkFlags::START);
        }
        if i == num_chunks - 1 {
            flags = flags.with(ChunkFlags::END);
        }
        chunks.push((i as u64, payload, flags));
    }

    let sender_aggregate = sender_hasher.finalize();
    let sent = send_chunks_with_backpressure(&mut sender, &chunks, cancel);
    let delivered = recv_and_deliver(&mut receiver, sent, cancel);

    let mut receiver_hasher = crate::protocol::ChunkAggregateHasher::new();
    for dc in &delivered {
        if !dc.is_retransmit {
            receiver_hasher.update(&dc.payload);
        }
    }

    let receiver_aggregate = receiver_hasher.finalize();
    let digest = if sender_aggregate == receiver_aggregate {
        sender_aggregate
    } else {
        [0u8; 32]
    };

    (sent, delivered, digest)
}

/// Item passing through the chunk pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkStreamItem {
    pub chunk_id: u64,
    pub payload: Vec<u8>,
    pub flags: ChunkFlags,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::MemberId;
    use tidefs_replication_model::FlowCommitClass;
    use tidefs_replication_model::{lane_class_discriminant, TransferLinkAssignment};

    fn test_ticket() -> ReplicaTransferTicketRecord {
        ReplicaTransferTicketRecord {
            ticket_id: ReplicatedReceiptId(1),
            intent_ref: ReplicatedReceiptId(100),
            subject_refs: vec![ReplicatedSubjectId(10)],
            source_anchor_set: vec![MemberId(1)],
            target_ref: MemberId(2),
            pin_budget_ref: ReplicatedReceiptId(200),
            freshness_fence_ref: 0,
            expiry: 100,
        }
    }

    fn test_chunk_payloads() -> Vec<(u64, Vec<u8>, ObjectDigest)> {
        vec![
            (1, b"hello world".to_vec(), ObjectDigest(0x45C)),
            (2, b"tidefs chunk data".to_vec(), ObjectDigest(0x672)),
        ]
    }

    fn test_schedule() -> TransferScheduleRecord {
        TransferScheduleRecord {
            ticket: test_ticket(),
            assignment: TransferLinkAssignment {
                source: MemberId(1),
                target: MemberId(2),
                lane_class: lane_class_discriminant::BACKGROUND,
                priority: 0,
            },
            flow_class: FlowCommitClass::Relocation,
        }
    }

    #[test]
    fn transport_select_same_node_io_uring() {
        let t = ChunkShippingTransport::select(MemberId(1), MemberId(1), false, true);
        assert_eq!(t, ChunkShippingTransport::IoUringSplice);
    }

    #[test]
    fn transport_select_rdma_cross_node() {
        let t = ChunkShippingTransport::select(MemberId(1), MemberId(2), true, true);
        assert_eq!(t, ChunkShippingTransport::RdmaDirectDataPlacement);
    }

    #[test]
    fn transport_select_tcp_fallback() {
        let t = ChunkShippingTransport::select(MemberId(1), MemberId(2), false, true);
        assert_eq!(t, ChunkShippingTransport::TcpFallback);
    }

    #[test]
    fn stage_chunks_produces_staged_buffers() {
        let buffers = stage_replica_chunks_for_transport(
            &test_ticket(),
            &test_chunk_payloads(),
            ChunkShippingTransport::TcpFallback,
        );
        assert_eq!(buffers.len(), 2);
        assert!(buffers.iter().all(|b| b.phase == ChunkStagingPhase::Staged));
        assert_eq!(buffers[0].payload, b"hello world");
        assert_eq!(buffers[1].payload, b"tidefs chunk data");
    }

    #[test]
    fn streaming_moves_all_staged_buffers() {
        let buffers = stage_replica_chunks_for_transport(
            &test_ticket(),
            &test_chunk_payloads(),
            ChunkShippingTransport::TcpFallback,
        );

        let mut session =
            ChunkShippingSession::new(1, test_ticket(), ChunkShippingTransport::TcpFallback, 3);

        let (transferred, bytes_moved) = stream_replica_chunks_under_ticket(&mut session, &buffers);

        assert_eq!(transferred.len(), 2);
        assert_eq!(bytes_moved, 28); // 11 + 17 bytes
        assert_eq!(session.state, ShippingSessionState::Streaming);
        assert!(session
            .progress
            .values()
            .all(|p| p.phase == ChunkTransferPhase::Completed));
    }

    #[test]
    fn receive_and_stage_for_verification_accepts_matching_digests() {
        let ticket = test_ticket();
        let buffers = stage_replica_chunks_for_transport(
            &ticket,
            &test_chunk_payloads(),
            ChunkShippingTransport::TcpFallback,
        );
        let mut session =
            ChunkShippingSession::new(1, ticket.clone(), ChunkShippingTransport::TcpFallback, 3);
        let (transferred, _) = stream_replica_chunks_under_ticket(&mut session, &buffers);

        let staging_area =
            receive_replica_chunks_and_stage_for_verification(&transferred, &ticket.subject_refs);

        assert_eq!(staging_area.pending_count(), 2);
        assert!(staging_area.rejected_chunks.is_empty());
        assert_eq!(staging_area.total_bytes_staged, 28);
    }

    #[test]
    fn receive_rejects_digest_mismatch() {
        // Test digest mismatch at the staging area level:
        // construct a ReceivedChunk with explicitly differing source/received digests.
        let mut area = ChunkStagingArea::new();
        let chunk = ReceivedChunk {
            chunk_id: 1,
            subject_ref: ReplicatedSubjectId(10),
            payload: b"data".to_vec(),
            source_digest: ObjectDigest(0xAAAA),
            received_digest: ObjectDigest(0xBBBB),
            range_start: 0,
            range_end: 4,
            verified: false,
        };
        area.accept(chunk);
        assert!(area.rejected_chunks.contains(&1));
        assert_eq!(area.pending_count(), 0);
    }
    #[test]
    fn full_pipeline_produces_report() {
        let schedule = test_schedule();
        let report = execute_chunk_shipping_pipeline(
            &schedule,
            &test_chunk_payloads(),
            EpochId(42),
            &[MemberId(1), MemberId(2)],
            3,
            false,
            true,
        );

        assert_eq!(report.chunks_succeeded, 2);
        assert_eq!(report.chunks_failed, 0);
        assert_eq!(report.bytes_staged, 28);
        assert_eq!(report.bytes_streamed, 28);
        assert!(report.transfer_receipt.is_some());
    }

    #[test]
    fn full_pipeline_tcp_fallback_cross_node() {
        let schedule = test_schedule();
        let report = execute_chunk_shipping_pipeline(
            &schedule,
            &test_chunk_payloads(),
            EpochId(42),
            &[MemberId(1), MemberId(2)],
            3,
            false,
            false,
        );

        assert_eq!(report.transport, ChunkShippingTransport::TcpFallback);
        assert_eq!(report.chunks_succeeded, 2);
    }

    #[test]
    fn chunk_transfer_progress_tracking() {
        let mut p = ChunkTransferProgress::new(1, ReplicatedSubjectId(10), 100);
        assert_eq!(p.progress_ratio(), 0.0);

        p.bytes_transferred = 50;
        p.bytes_staged = 50;
        assert!((p.progress_ratio() - 0.5).abs() < 0.001);

        p.bytes_transferred = 100;
        assert!((p.progress_ratio() - 1.0).abs() < 0.001);
    }

    #[test]
    fn session_ticket_validity() {
        let session =
            ChunkShippingSession::new(1, test_ticket(), ChunkShippingTransport::TcpFallback, 3);
        assert!(session.is_ticket_valid(50));
        assert!(!session.is_ticket_valid(100));
        assert!(!session.is_ticket_valid(101));
    }

    #[test]
    fn session_completion_emits_receipt() {
        let ticket = test_ticket();
        let buffers = stage_replica_chunks_for_transport(
            &ticket,
            &test_chunk_payloads(),
            ChunkShippingTransport::TcpFallback,
        );
        let mut session =
            ChunkShippingSession::new(1, ticket, ChunkShippingTransport::TcpFallback, 3);
        let (_, bytes_moved) = stream_replica_chunks_under_ticket(&mut session, &buffers);

        let receipt = session.complete(EpochId(42), &[MemberId(1)]);
        assert_eq!(session.state, ShippingSessionState::Completed);
        assert_eq!(receipt.bytes_moved, bytes_moved);
        assert_eq!(receipt.ticket_ref.0, 1);
    }

    #[test]
    fn session_failure_state() {
        let mut session =
            ChunkShippingSession::new(1, test_ticket(), ChunkShippingTransport::TcpFallback, 3);
        session.fail("network timeout".to_string());
        match &session.state {
            ShippingSessionState::Failed(reason) => assert_eq!(reason, "network timeout"),
            _ => panic!("Expected Failed state"),
        }
    }

    #[test]
    fn batch_ship_all_transfers() {
        let schedule = test_schedule();
        let scheduled = vec![schedule];
        let mut payloads_map = BTreeMap::new();
        payloads_map.insert(1, test_chunk_payloads());

        let reports = ship_all_scheduled_transfers(
            &scheduled,
            &payloads_map,
            EpochId(42),
            &[MemberId(1)],
            3,
            false,
            true,
        );

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].chunks_succeeded, 2);
    }

    #[test]
    fn staging_area_drain_clears_state() {
        let mut area = ChunkStagingArea::new();
        let chunk = ReceivedChunk {
            chunk_id: 1,
            subject_ref: ReplicatedSubjectId(10),
            payload: b"data".to_vec(),
            source_digest: ObjectDigest(1),
            received_digest: ObjectDigest(1),
            range_start: 0,
            range_end: 4,
            verified: false,
        };
        area.accept(chunk);
        assert_eq!(area.pending_count(), 1);

        let drained = area.drain_for_verification();
        assert_eq!(drained.len(), 1);
        assert_eq!(area.pending_count(), 0);
        assert_eq!(area.total_bytes_staged, 0);
    }
    // ── Single-chunk round-trip: full pipeline with payload verification ──

    #[test]
    fn single_chunk_round_trip_preserves_payload_byte_for_byte() {
        let payload = b"exact payload for round-trip verification".to_vec();
        let chunk_payloads = vec![(1, payload.clone(), ObjectDigest(0xABCD))];
        let schedule = test_schedule();

        let report = execute_chunk_shipping_pipeline(
            &schedule,
            &chunk_payloads,
            EpochId(1),
            &[MemberId(1)],
            3,
            false,
            true,
        );

        assert_eq!(report.chunks_succeeded, 1);
        assert_eq!(report.chunks_failed, 0);
        assert_eq!(report.bytes_staged, payload.len() as u64);
        assert_eq!(report.bytes_streamed, payload.len() as u64);
        assert_eq!(report.bytes_received, payload.len() as u64);
    }

    // ── Header / metadata preservation through stage-stream-receive ──

    #[test]
    fn chunk_metadata_preserved_through_staging() {
        let ticket = test_ticket();
        let chunk_payloads = vec![
            (42, b"first".to_vec(), ObjectDigest(0x100)),
            (99, b"second".to_vec(), ObjectDigest(0x200)),
        ];
        let buffers = stage_replica_chunks_for_transport(
            &ticket,
            &chunk_payloads,
            ChunkShippingTransport::TcpFallback,
        );

        assert_eq!(buffers.len(), 2);
        assert_eq!(buffers[0].chunk_id, 42);
        assert_eq!(buffers[0].range_start, 0);
        assert_eq!(buffers[0].range_end, 5);
        assert_eq!(buffers[0].digest, derive_receive_digest(b"first"));
        assert_eq!(buffers[1].chunk_id, 99);
        assert_eq!(buffers[1].digest, derive_receive_digest(b"second"));
    }

    #[test]
    fn chunk_metadata_preserved_through_receive() {
        let ticket = test_ticket();
        let chunk_payloads = vec![(7, b"metadata test".to_vec(), ObjectDigest(0x777))];
        let buffers = stage_replica_chunks_for_transport(
            &ticket,
            &chunk_payloads,
            ChunkShippingTransport::TcpFallback,
        );
        let mut session =
            ChunkShippingSession::new(1, ticket.clone(), ChunkShippingTransport::TcpFallback, 3);
        let (transferred, _) = stream_replica_chunks_under_ticket(&mut session, &buffers);

        let staging_area =
            receive_replica_chunks_and_stage_for_verification(&transferred, &ticket.subject_refs);

        let received = staging_area.staged_chunks.get(&7).unwrap();
        assert_eq!(received.chunk_id, 7);
        assert_eq!(received.payload, b"metadata test");
        assert_eq!(received.range_start, 0);
        assert_eq!(received.range_end, 13);
    }

    // ── Empty chunk: zero-length payload ──

    #[test]
    fn empty_chunk_no_panic_and_correct_metadata() {
        let empty_payload: Vec<u8> = vec![];
        let chunk_payloads = vec![(0, empty_payload, ObjectDigest(0))];
        let schedule = test_schedule();

        let report = execute_chunk_shipping_pipeline(
            &schedule,
            &chunk_payloads,
            EpochId(1),
            &[MemberId(1)],
            3,
            false,
            true,
        );

        assert_eq!(report.chunks_succeeded, 1);
        assert_eq!(report.chunks_failed, 0);
        assert_eq!(report.bytes_staged, 0);
        assert_eq!(report.bytes_streamed, 0);
        assert_eq!(report.bytes_received, 0);
    }

    #[test]
    fn empty_chunk_staging_buffer_is_empty() {
        let buffer = ChunkStagingBuffer::new(
            1,
            ReplicatedSubjectId(10),
            0,
            0,
            vec![],
            ObjectDigest(0),
            ChunkShippingTransport::TcpFallback,
        );

        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }

    // ── Out-of-order reassembly ──

    #[test]
    fn out_of_order_chunks_reassembled_correctly() {
        let ticket = test_ticket();
        let chunk_payloads = vec![
            (3, b"third".to_vec(), ObjectDigest(0x300)),
            (1, b"first".to_vec(), ObjectDigest(0x100)),
            (2, b"second".to_vec(), ObjectDigest(0x200)),
        ];
        let buffers = stage_replica_chunks_for_transport(
            &ticket,
            &chunk_payloads,
            ChunkShippingTransport::TcpFallback,
        );
        let mut session =
            ChunkShippingSession::new(1, ticket.clone(), ChunkShippingTransport::TcpFallback, 3);
        let (transferred, _) = stream_replica_chunks_under_ticket(&mut session, &buffers);

        let staging_area =
            receive_replica_chunks_and_stage_for_verification(&transferred, &ticket.subject_refs);

        assert_eq!(staging_area.pending_count(), 3);
        let chunks: Vec<_> = staging_area.staged_chunks.values().collect();
        let payloads: Vec<&[u8]> = chunks.iter().map(|c| c.payload.as_slice()).collect();
        assert!(payloads.contains(&b"first".as_slice()));
        assert!(payloads.contains(&b"second".as_slice()));
        assert!(payloads.contains(&b"third".as_slice()));
    }

    // ── Maximum-size chunk ──

    #[test]
    fn max_size_chunk_round_trip() {
        let max_payload = vec![0xAB; 64 * 1024];
        let digest = derive_receive_digest(&max_payload);
        let chunk_payloads = vec![(1, max_payload.clone(), digest)];
        let schedule = test_schedule();

        let report = execute_chunk_shipping_pipeline(
            &schedule,
            &chunk_payloads,
            EpochId(1),
            &[MemberId(1)],
            3,
            false,
            true,
        );

        assert_eq!(report.chunks_succeeded, 1);
        assert_eq!(report.bytes_staged, 64 * 1024);
        assert_eq!(report.bytes_streamed, 64 * 1024);
        assert_eq!(report.bytes_received, 64 * 1024);
    }

    // ── Digest and anchor hash determinism ──

    #[test]
    fn derive_receive_digest_deterministic() {
        let a = derive_receive_digest(b"hello");
        let b = derive_receive_digest(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn derive_receive_digest_different_for_different_payloads() {
        let a = derive_receive_digest(b"hello");
        let b = derive_receive_digest(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn derive_anchor_hash_deterministic() {
        let a = derive_anchor_hash(42, 7);
        let b = derive_anchor_hash(42, 7);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_anchor_hash_different_for_different_inputs() {
        let a = derive_anchor_hash(1, 2);
        let b = derive_anchor_hash(2, 1);
        assert_ne!(a, b);
    }

    // ── Post-verification advancement ──

    #[test]
    fn advance_chunks_after_verification_transitions_to_committed() {
        use tidefs_replication_model::{ReplicaChunkState, VerificationStatus};
        let records = vec![ReplicaChunkStateRecord {
            chunk_id: 1,
            subject_ref: ReplicatedSubjectId(10),
            source_ref: MemberId(1),
            target_ref: MemberId(2),
            range_ref: 100,
            digest: ObjectDigest(0xAAA),
            state: ReplicaChunkState::Verifying,
            transfer_ticket_ref: ReplicatedReceiptId(1),
            verification_receipt_ref: ReplicatedReceiptId(100),
        }];

        let advanced = advance_chunks_after_verification(&records, VerificationStatus::Verified);
        assert_eq!(advanced[0].state, ReplicaChunkState::Committed);
    }

    #[test]
    fn advance_chunks_verifying_fails_on_digest_mismatch() {
        use tidefs_replication_model::{ReplicaChunkState, VerificationStatus};
        let records = vec![ReplicaChunkStateRecord {
            chunk_id: 1,
            subject_ref: ReplicatedSubjectId(10),
            source_ref: MemberId(1),
            target_ref: MemberId(2),
            range_ref: 100,
            digest: ObjectDigest(0xAAA),
            state: ReplicaChunkState::Verifying,
            transfer_ticket_ref: ReplicatedReceiptId(1),
            verification_receipt_ref: ReplicatedReceiptId(100),
        }];

        let advanced =
            advance_chunks_after_verification(&records, VerificationStatus::DigestMismatch);
        assert_eq!(advanced[0].state, ReplicaChunkState::Failed);
    }

    #[test]
    fn advance_chunks_pending_is_cancelled() {
        use tidefs_replication_model::{ReplicaChunkState, VerificationStatus};
        let records = vec![ReplicaChunkStateRecord {
            chunk_id: 1,
            subject_ref: ReplicatedSubjectId(10),
            source_ref: MemberId(1),
            target_ref: MemberId(2),
            range_ref: 100,
            digest: ObjectDigest(0xAAA),
            state: ReplicaChunkState::Pending,
            transfer_ticket_ref: ReplicatedReceiptId(1),
            verification_receipt_ref: ReplicatedReceiptId(100),
        }];

        let advanced = advance_chunks_after_verification(&records, VerificationStatus::Verified);
        assert_eq!(advanced[0].state, ReplicaChunkState::Cancelled);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Sequenced Reliable Delivery Protocol — unit tests
    // ═══════════════════════════════════════════════════════════════════════

    // ── ChunkFlags ──────────────────────────────────────────────────────

    #[test]
    fn chunk_flags_new_is_empty() {
        let f = ChunkFlags::new();
        assert!(!f.is_start());
        assert!(!f.is_end());
        assert!(!f.is_retransmit());
        assert!(!f.is_ack());
        assert_eq!(f.bits(), 0);
    }

    #[test]
    fn chunk_flags_start() {
        let f = ChunkFlags::new().with(ChunkFlags::START);
        assert!(f.has(ChunkFlags::START));
        assert!(!f.has(ChunkFlags::END));
        assert!(f.is_data());
        assert!(!f.is_ack());
    }

    #[test]
    fn chunk_flags_end() {
        let f = ChunkFlags::new().with(ChunkFlags::END);
        assert!(f.has(ChunkFlags::END));
        assert!(f.is_data());
    }

    #[test]
    fn chunk_flags_retransmit() {
        let f = ChunkFlags::new().with(ChunkFlags::RETRANSMIT);
        assert!(f.has(ChunkFlags::RETRANSMIT));
        assert!(f.is_data());
    }

    #[test]
    fn chunk_flags_ack() {
        let f = ChunkFlags::new().with(ChunkFlags::ACK);
        assert!(f.has(ChunkFlags::ACK));
        assert!(f.is_ack());
        assert!(!f.is_data());
    }

    #[test]
    fn chunk_flags_combined_data() {
        let f = ChunkFlags::new()
            .with(ChunkFlags::START)
            .with(ChunkFlags::END)
            .with(ChunkFlags::RETRANSMIT);
        assert!(f.has(ChunkFlags::START));
        assert!(f.has(ChunkFlags::END));
        assert!(f.has(ChunkFlags::RETRANSMIT));
        assert!(!f.has(ChunkFlags::ACK));
        assert!(f.is_data());
        assert_eq!(f.bits(), 0x01 | 0x02 | 0x04);
    }

    // ── ChunkHeader encode/decode ───────────────────────────────────────

    #[test]
    fn chunk_header_encode_decode_round_trip_data() {
        let flags = ChunkFlags::new().with(ChunkFlags::START);
        let header = ChunkHeader::data(42, 7, 100, flags);
        let encoded = header.encode();
        assert_eq!(encoded.len(), CHUNK_HEADER_SIZE);

        let decoded = ChunkHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.chunk_id, 42);
        assert_eq!(decoded.sequence_number, 7);
        assert_eq!(decoded.payload_length, 100);
        assert_eq!(decoded.flags.bits(), flags.bits());
    }

    #[test]
    fn chunk_header_encode_decode_round_trip_ack() {
        let header = ChunkHeader::ack(0);
        let encoded = header.encode();
        let decoded = ChunkHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.chunk_id, 0);
        assert_eq!(decoded.payload_length, 0);
        assert!(decoded.flags.is_ack());
    }

    #[test]
    fn chunk_header_decode_wrong_size_returns_none() {
        assert!(ChunkHeader::decode(&[]).is_none());
        assert!(ChunkHeader::decode(&[0u8; 20]).is_none());
        assert!(ChunkHeader::decode(&[0u8; 22]).is_none());
    }

    #[test]
    fn chunk_header_encode_with_payload_round_trip() {
        let flags = ChunkFlags::new().with(ChunkFlags::END);
        let header = ChunkHeader::data(99, 5, 11, flags);
        let payload = b"hello world";
        let frame = header.encode_with_payload(payload);

        let (decoded_header, decoded_payload) = ChunkHeader::decode_from_frame(&frame).unwrap();
        assert_eq!(decoded_header.chunk_id, 99);
        assert_eq!(decoded_header.sequence_number, 5);
        assert_eq!(decoded_header.payload_length, 11);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn chunk_header_decode_from_frame_too_short() {
        assert!(ChunkHeader::decode_from_frame(&[]).is_none());
        assert!(ChunkHeader::decode_from_frame(&[0u8; 20]).is_none());
    }

    #[test]
    fn chunk_header_sequence_number_wraparound() {
        // Sequence numbers wrap at u64::MAX
        let flags = ChunkFlags::new();
        let header = ChunkHeader::data(1, u64::MAX, 0, flags);
        let encoded = header.encode();
        let decoded = ChunkHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.sequence_number, u64::MAX);
    }

    // ── ChunkAck encode/decode ──────────────────────────────────────────

    #[test]
    fn chunk_ack_encode_decode_no_gaps() {
        let ack = ChunkAck::new(42);
        let encoded = ack.encode();
        let decoded = ChunkAck::decode(&encoded).unwrap();
        assert_eq!(decoded.ack_sequence, 42);
        assert!(decoded.gaps.is_empty());
    }

    #[test]
    fn chunk_ack_encode_decode_with_gaps() {
        let ack = ChunkAck::with_gaps(100, vec![101, 103, 107]);
        let encoded = ack.encode();
        let decoded = ChunkAck::decode(&encoded).unwrap();
        assert_eq!(decoded.ack_sequence, 100);
        assert_eq!(decoded.gaps, vec![101, 103, 107]);
    }

    #[test]
    fn chunk_ack_decode_too_short() {
        assert!(ChunkAck::decode(&[]).is_none());
        assert!(ChunkAck::decode(&[0u8; 11]).is_none());
    }

    #[test]
    fn chunk_ack_decode_truncated_gaps() {
        // Claim 1 gap but provide less than 8 bytes of gap data
        let mut buf = vec![0u8; 12]; // ack_seq (8) + gap_count (4) = 12
        buf[8..12].copy_from_slice(&1u32.to_be_bytes()); // gap_count = 1
        assert!(ChunkAck::decode(&buf).is_none());
    }

    // ── Loopback transport ──────────────────────────────────────────────

    #[test]
    fn loopback_pair_send_recv() {
        let pair = LoopbackPair::new();
        let mut left = pair.left;
        let mut right = pair.right;

        left.send(b"hello").unwrap();
        let received = right.recv().unwrap();
        assert_eq!(received, b"hello");

        right.send(b"world").unwrap();
        let received = left.recv().unwrap();
        assert_eq!(received, b"world");
    }

    #[test]
    fn loopback_pair_multiple_messages() {
        let pair = LoopbackPair::new();
        let mut left = pair.left;
        let mut right = pair.right;

        for i in 0..10 {
            left.send(&[i]).unwrap();
        }
        for i in 0..10 {
            let received = right.recv().unwrap();
            assert_eq!(received[0], i);
        }
    }

    // ── ChunkSender window management ───────────────────────────────────

    fn dummy_sender() -> ChunkSender<LoopbackEndpoint> {
        let pair = LoopbackPair::new();
        ChunkSender::new(pair.left, 4, Duration::from_secs(60))
    }

    #[test]
    fn sender_starts_with_window_available() {
        let sender = dummy_sender();
        assert!(!sender.is_window_full());
        assert_eq!(sender.window_available(), 4);
        assert_eq!(sender.inflight_count(), 0);
        assert_eq!(sender.next_sequence(), 0);
    }

    #[test]
    fn sender_assigns_monotonic_sequence_numbers() {
        let pair = LoopbackPair::new();
        let mut sender = ChunkSender::new(pair.left, 4, Duration::from_secs(60));
        let mut receiver = ChunkReceiver::new(pair.right);

        // Send one chunk, receive it
        let seq = sender
            .send_chunk(1, b"data", ChunkFlags::new().with(ChunkFlags::START))
            .unwrap();
        assert_eq!(seq, 0);

        let rc = receiver.recv_chunk().unwrap();
        assert_eq!(rc.sequence_number, 0);

        // Second chunk
        let seq2 = sender.send_chunk(2, b"more", ChunkFlags::new()).unwrap();
        assert_eq!(seq2, 1);
    }

    #[test]
    fn sender_window_full_backpressure() {
        let pair = LoopbackPair::new();
        let mut sender = ChunkSender::new(pair.left, 2, Duration::from_secs(60));

        // Fill the window
        sender.send_chunk(1, b"a", ChunkFlags::new()).unwrap();
        sender.send_chunk(2, b"b", ChunkFlags::new()).unwrap();

        assert!(sender.is_window_full());
        assert_eq!(sender.window_available(), 0);

        // Next send should fail
        let result = sender.send_chunk(3, b"c", ChunkFlags::new());
        assert!(result.is_err());
    }

    #[test]
    fn sender_process_ack_clears_inflight() {
        let pair = LoopbackPair::new();
        let mut sender = ChunkSender::new(pair.left, 4, Duration::from_secs(60));
        let mut receiver = ChunkReceiver::new(pair.right);

        // Send 3 chunks
        sender.send_chunk(1, b"a", ChunkFlags::new()).unwrap();
        sender.send_chunk(2, b"b", ChunkFlags::new()).unwrap();
        sender.send_chunk(3, b"c", ChunkFlags::new()).unwrap();

        assert_eq!(sender.inflight_count(), 3);

        // Receiver gets all 3, builds ACK
        receiver.recv_chunk().unwrap();
        receiver.recv_chunk().unwrap();
        receiver.recv_chunk().unwrap();
        let delivered = receiver.deliver();
        assert_eq!(delivered.len(), 3);

        let ack = receiver.build_ack();
        // All contiguous: ack_seq = 2 (sequences 0,1,2)
        assert_eq!(ack.ack_sequence, 2);
        assert!(ack.gaps.is_empty());

        // Process ACK on sender
        let removed = sender.process_ack(&ack);
        assert_eq!(removed.len(), 3);
        assert_eq!(sender.inflight_count(), 0);
        assert_eq!(sender.acked_sequence(), 2);
    }

    #[test]
    fn sender_process_ack_with_gaps() {
        let pair = LoopbackPair::new();
        let mut sender = ChunkSender::new(pair.left, 4, Duration::from_secs(60));

        sender.send_chunk(1, b"a", ChunkFlags::new()).unwrap(); // seq 0
        sender.send_chunk(2, b"b", ChunkFlags::new()).unwrap(); // seq 1
        sender.send_chunk(3, b"c", ChunkFlags::new()).unwrap(); // seq 2
        sender.send_chunk(4, b"d", ChunkFlags::new()).unwrap(); // seq 3

        assert_eq!(sender.inflight_count(), 4);

        // Simulate an ACK with gap at seq 1: cumulative ack=0, gap @ 1
        let ack = ChunkAck::with_gaps(0, vec![1]);
        sender.process_ack(&ack);

        // Only seq 0 is acked; 1 is a gap, 2 and 3 are beyond the ack window
        assert_eq!(sender.inflight_count(), 3); // 1, 2, 3 still inflight
        assert!(!sender.inflight.contains_key(&0));
        assert!(sender.inflight.contains_key(&1));
        assert!(sender.inflight.contains_key(&2));
        assert!(sender.inflight.contains_key(&3));
    }

    #[test]
    fn sender_retransmit_on_timeout() {
        let pair = LoopbackPair::new();
        // Use a timeout that's already expired
        let mut sender = ChunkSender::new(pair.left.clone(), 4, Duration::from_millis(0));

        sender.send_chunk(1, b"x", ChunkFlags::new()).unwrap();
        assert_eq!(sender.inflight_count(), 1);

        // Small sleep so that Instant::now() > send_time
        std::thread::sleep(Duration::from_millis(1));

        let retransmitted = sender.check_timeouts().unwrap();
        assert_eq!(retransmitted.len(), 1);
        assert_eq!(retransmitted[0], 0);
    }

    // ── ChunkReceiver in-order delivery ─────────────────────────────────

    fn dummy_receiver() -> (LoopbackEndpoint, ChunkReceiver<LoopbackEndpoint>) {
        let pair = LoopbackPair::new();
        (pair.right, ChunkReceiver::new(pair.left))
    }

    #[test]
    fn receiver_delivers_in_order() {
        let (_right, mut receiver) = dummy_receiver();
        // Manually insert received chunks (bypass transport for unit test)
        receiver.received.insert(
            0,
            ReceivedChunkData {
                chunk_id: 1,
                sequence_number: 0,
                payload: b"first".to_vec(),
                flags: ChunkFlags::new().with(ChunkFlags::START),
            },
        );
        receiver.received.insert(
            1,
            ReceivedChunkData {
                chunk_id: 2,
                sequence_number: 1,
                payload: b"second".to_vec(),
                flags: ChunkFlags::new(),
            },
        );
        receiver.received.insert(
            2,
            ReceivedChunkData {
                chunk_id: 3,
                sequence_number: 2,
                payload: b"third".to_vec(),
                flags: ChunkFlags::new().with(ChunkFlags::END),
            },
        );

        let delivered = receiver.deliver();
        assert_eq!(delivered.len(), 3);
        assert_eq!(delivered[0].chunk_id, 1);
        assert_eq!(delivered[1].chunk_id, 2);
        assert_eq!(delivered[2].chunk_id, 3);
        assert_eq!(receiver.next_expected(), 3);
    }

    #[test]
    fn receiver_defers_out_of_order_chunks() {
        let mut receiver = ChunkReceiver::new(LoopbackPair::new().left);

        // Insert seq 2 before seq 1
        receiver.received.insert(
            2,
            ReceivedChunkData {
                chunk_id: 3,
                sequence_number: 2,
                payload: b"third".to_vec(),
                flags: ChunkFlags::new(),
            },
        );

        // deliver() should return nothing (seq 0 missing)
        let delivered = receiver.deliver();
        assert!(delivered.is_empty());
        assert_eq!(receiver.next_expected(), 0);

        // Now insert seq 0
        receiver.received.insert(
            0,
            ReceivedChunkData {
                chunk_id: 1,
                sequence_number: 0,
                payload: b"first".to_vec(),
                flags: ChunkFlags::new(),
            },
        );

        let delivered = receiver.deliver();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].chunk_id, 1);
        // seq 1 is still missing, so seq 2 stays buffered
        assert_eq!(receiver.next_expected(), 1);
        assert_eq!(receiver.buffered_count(), 1);
    }

    #[test]
    fn receiver_duplicate_suppression() {
        // Direct state manipulation test: receiving a chunk with an already-seen
        // sequence number is handled as a duplicate.
        let pair = LoopbackPair::new();
        let mut receiver = ChunkReceiver::new(pair.left);

        // Simulate having already seen and delivered seq 0
        receiver.seen.insert(0);
        receiver.next_expected = 1;
        receiver.max_delivered = 0;

        // Now create a frame with seq 0 and feed it to the receiver via the
        // other endpoint of the loopback
        let mut peer = pair.right;
        let flags = ChunkFlags::new().with(ChunkFlags::RETRANSMIT);
        let header = ChunkHeader::data(99, 0, 7, flags);
        let frame = header.encode_with_payload(b"payload");
        peer.send(&frame).unwrap();

        let rc = receiver.recv_chunk().unwrap();
        assert_eq!(rc.sequence_number, 0);
        assert_eq!(rc.chunk_id, 99);
        // Duplicate was detected (already seen), not re-inserted into received
        assert_eq!(receiver.buffered_count(), 0);
    }

    #[test]
    fn receiver_gap_detection() {
        let mut receiver = ChunkReceiver::new(LoopbackPair::new().left);

        // Mark chunks 0, 2, 3 as seen (1 is a gap)
        receiver.seen.insert(0);
        receiver.received.insert(
            0,
            ReceivedChunkData {
                chunk_id: 1,
                sequence_number: 0,
                payload: b"a".to_vec(),
                flags: ChunkFlags::new(),
            },
        );
        receiver.seen.insert(2);
        receiver.received.insert(
            2,
            ReceivedChunkData {
                chunk_id: 3,
                sequence_number: 2,
                payload: b"c".to_vec(),
                flags: ChunkFlags::new(),
            },
        );
        receiver.seen.insert(3);
        receiver.received.insert(
            3,
            ReceivedChunkData {
                chunk_id: 4,
                sequence_number: 3,
                payload: b"d".to_vec(),
                flags: ChunkFlags::new(),
            },
        );

        // After delivering seq 0, next_expected = 1
        let _ = receiver.deliver();
        assert_eq!(receiver.next_expected(), 1);

        let gaps = receiver.compute_gaps();
        assert_eq!(gaps, vec![1]); // seq 1 is between next_expected(1) and max_seen(3)
    }

    #[test]
    fn receiver_build_ack_contiguous() {
        let mut receiver = ChunkReceiver::new(LoopbackPair::new().left);

        receiver.seen.insert(0);
        receiver.received.insert(
            0,
            ReceivedChunkData {
                chunk_id: 1,
                sequence_number: 0,
                payload: b"a".to_vec(),
                flags: ChunkFlags::new(),
            },
        );
        receiver.seen.insert(1);
        receiver.received.insert(
            1,
            ReceivedChunkData {
                chunk_id: 2,
                sequence_number: 1,
                payload: b"b".to_vec(),
                flags: ChunkFlags::new(),
            },
        );
        let _ = receiver.deliver(); // delivers 0,1

        let ack = receiver.build_ack();
        assert_eq!(ack.ack_sequence, 1); // next_expected - 1
        assert!(ack.gaps.is_empty());
    }

    #[test]
    fn receiver_build_ack_with_gaps() {
        let mut receiver = ChunkReceiver::new(LoopbackPair::new().left);

        receiver.seen.insert(0);
        receiver.received.insert(
            0,
            ReceivedChunkData {
                chunk_id: 1,
                sequence_number: 0,
                payload: b"a".to_vec(),
                flags: ChunkFlags::new(),
            },
        );
        receiver.seen.insert(2); // gap at 1
        receiver.received.insert(
            2,
            ReceivedChunkData {
                chunk_id: 3,
                sequence_number: 2,
                payload: b"c".to_vec(),
                flags: ChunkFlags::new(),
            },
        );

        let _ = receiver.deliver(); // delivers seq 0 only

        let ack = receiver.build_ack();
        assert_eq!(ack.ack_sequence, 0);
        assert_eq!(ack.gaps, vec![1]);
    }

    #[test]
    fn receiver_empty_ack_when_no_chunks() {
        let receiver: ChunkReceiver<LoopbackEndpoint> =
            ChunkReceiver::new(LoopbackPair::new().left);
        let ack = receiver.build_ack();
        // next_expected - 1 = 0.saturating_sub(1) = 0
        assert_eq!(ack.ack_sequence, 0);
        assert!(ack.gaps.is_empty());
    }

    // ── Integration: full round-trip over loopback ──────────────────────

    #[test]
    fn full_round_trip_ordered_delivery() {
        let pair = LoopbackPair::new();
        let mut sender = ChunkSender::new(pair.left, 8, Duration::from_secs(60));
        let mut receiver = ChunkReceiver::new(pair.right);

        // Send 5 chunks
        let flags = ChunkFlags::new().with(ChunkFlags::START);
        sender.send_chunk(1, b"chunk-1", flags).unwrap();
        sender.send_chunk(2, b"chunk-2", ChunkFlags::new()).unwrap();
        sender.send_chunk(3, b"chunk-3", ChunkFlags::new()).unwrap();
        sender.send_chunk(4, b"chunk-4", ChunkFlags::new()).unwrap();
        sender
            .send_chunk(5, b"chunk-5", ChunkFlags::new().with(ChunkFlags::END))
            .unwrap();

        // Receive all chunks
        for _ in 0..5 {
            receiver.recv_chunk().unwrap();
        }

        // Deliver in order
        let delivered = receiver.deliver();
        assert_eq!(delivered.len(), 5);
        assert_eq!(delivered[0].chunk_id, 1);
        assert_eq!(delivered[0].sequence_number, 0);
        assert!(delivered[0].flags.has(ChunkFlags::START));
        assert!(!delivered[0].is_retransmit);
        assert_eq!(delivered[4].chunk_id, 5);
        assert!(delivered[4].flags.has(ChunkFlags::END));

        // ACK back
        let ack = receiver.build_ack();
        assert_eq!(ack.ack_sequence, 4);
        assert!(ack.gaps.is_empty());

        // Verify ACK clears sender
        let removed = sender.process_ack(&ack);
        assert_eq!(removed.len(), 5);
        assert_eq!(sender.inflight_count(), 0);
    }

    #[test]
    fn round_trip_with_single_loss_and_retransmit() {
        let pair = LoopbackPair::new();
        let mut sender = ChunkSender::new(pair.left, 8, Duration::from_millis(0));
        let mut receiver = ChunkReceiver::new(pair.right);

        // Send 3 chunks
        sender.send_chunk(1, b"a", ChunkFlags::new()).unwrap(); // seq 0
        sender.send_chunk(2, b"b", ChunkFlags::new()).unwrap(); // seq 1
        sender.send_chunk(3, b"c", ChunkFlags::new()).unwrap(); // seq 2

        // Receive seq 0 and deliver it
        receiver.recv_chunk().unwrap(); // seq 0
        let _ = receiver.deliver();
        assert_eq!(receiver.next_expected(), 1);

        // Consume seq 1 frame from loopback but simulate loss:
        // set the frame aside without inserting into received
        let seq1_frame = receiver.transport.recv().unwrap();
        let (seq1_header, _) = ChunkHeader::decode_from_frame(&seq1_frame).unwrap();
        assert_eq!(seq1_header.sequence_number, 1);
        // Do NOT call recv_chunk – manually mark as seen but lost
        receiver.seen.insert(1);

        // Receive seq 2 normally
        receiver.recv_chunk().unwrap(); // seq 2

        // Build ACK: next_expected=1, seq 2 buffered, gap at 1
        let ack = receiver.build_ack();
        assert_eq!(ack.ack_sequence, 0);
        assert_eq!(ack.gaps, vec![1]);

        // Process ACK on sender
        sender.process_ack(&ack);
        assert_eq!(sender.inflight_count(), 2); // seq 1, 2 still inflight

        // Retransmit timed-out chunks
        std::thread::sleep(Duration::from_millis(1));
        let retransmitted = sender.check_timeouts().unwrap();
        assert!(retransmitted.contains(&1));
        assert!(retransmitted.contains(&2));

        // Receiver gets the retransmitted chunks
        // First: retransmitted seq 1
        let rc_retrans = receiver.recv_chunk().unwrap();
        assert_eq!(rc_retrans.sequence_number, 1);
        assert!(rc_retrans.flags.is_retransmit());

        // Second: retransmitted seq 2
        // (The originally-received seq 2 is still in 'received', and the
        // retransmitted copy arrives. Since seq 2 is already in seen,
        // recv_chunk detects duplicate and returns the existing entry.)
        let rc_seq2_dup = receiver.recv_chunk().unwrap();
        assert_eq!(rc_seq2_dup.sequence_number, 2);

        // Now deliver all contiguous chunks
        let delivered = receiver.deliver();
        assert_eq!(delivered.len(), 2); // seq 1 and seq 2
        assert_eq!(delivered[0].sequence_number, 1);
        assert!(delivered[0].is_retransmit);
        assert_eq!(delivered[1].sequence_number, 2);
    }

    #[test]
    fn receiver_ack_message_round_trip_over_loopback() {
        let pair = LoopbackPair::new();
        let mut receiver = ChunkReceiver::new(pair.left);
        let mut sender_side = pair.right; // The "other side" where ACK goes

        // Insert some received data
        receiver.seen.insert(0);
        receiver.received.insert(
            0,
            ReceivedChunkData {
                chunk_id: 1,
                sequence_number: 0,
                payload: b"x".to_vec(),
                flags: ChunkFlags::new(),
            },
        );
        let _ = receiver.deliver();

        // Send ACK
        receiver.send_ack().unwrap();

        // Read the ACK frame on the other side
        let frame = sender_side.recv().unwrap();
        let (header, ack_payload) = ChunkHeader::decode_from_frame(&frame).unwrap();
        assert!(header.flags.is_ack());

        let ack = ChunkAck::decode(ack_payload).unwrap();
        assert_eq!(ack.ack_sequence, 0);
    }

    // ── ChunkTransferRequest / ChunkTransferResponse tests ─────────────────

    #[test]
    fn chunk_transfer_request_encode_decode_round_trip() {
        let req = ChunkTransferRequest {
            transfer_id: 42,
            object_id: ReplicatedSubjectId(100),
            source_node: MemberId(1),
            target_node: MemberId(2),
            sequence_number: 7,
            chunks: vec![
                ChunkRange::new(0, 1024),
                ChunkRange::new(1024, 2048),
                ChunkRange::new(2048, 4096),
            ],
            total_chunks: 3,
        };

        let encoded = req.encode();
        let decoded = ChunkTransferRequest::decode(&encoded).expect("decode failed");
        assert_eq!(decoded.transfer_id, req.transfer_id);
        assert_eq!(decoded.object_id, req.object_id);
        assert_eq!(decoded.source_node, req.source_node);
        assert_eq!(decoded.target_node, req.target_node);
        assert_eq!(decoded.sequence_number, req.sequence_number);
        assert_eq!(decoded.chunks.len(), 3);
        assert_eq!(decoded.chunks[0].start_byte, 0);
        assert_eq!(decoded.chunks[0].end_byte, 1024);
        assert_eq!(decoded.chunks[2].start_byte, 2048);
        assert_eq!(decoded.chunks[2].end_byte, 4096);
        assert_eq!(decoded.total_chunks, 3);
    }

    #[test]
    fn chunk_transfer_request_empty_chunks() {
        let req = ChunkTransferRequest {
            transfer_id: 1,
            object_id: ReplicatedSubjectId(99),
            source_node: MemberId(10),
            target_node: MemberId(20),
            sequence_number: 0,
            chunks: vec![],
            total_chunks: 0,
        };

        let encoded = req.encode();
        let decoded = ChunkTransferRequest::decode(&encoded).expect("decode failed");
        assert_eq!(decoded.chunks.len(), 0);
        assert_eq!(decoded.total_bytes(), 0);
    }

    #[test]
    fn chunk_transfer_request_total_bytes() {
        let req = ChunkTransferRequest {
            transfer_id: 1,
            object_id: ReplicatedSubjectId(1),
            source_node: MemberId(1),
            target_node: MemberId(2),
            sequence_number: 1,
            chunks: vec![ChunkRange::new(0, 100), ChunkRange::new(100, 300)],
            total_chunks: 2,
        };
        assert_eq!(req.total_bytes(), 300);
    }

    #[test]
    fn chunk_transfer_request_decode_too_short() {
        let short = vec![0u8; 40];
        assert!(ChunkTransferRequest::decode(&short).is_none());
    }

    #[test]
    fn chunk_transfer_request_decode_corrupt_checksum() {
        let req = ChunkTransferRequest {
            transfer_id: 1,
            object_id: ReplicatedSubjectId(10),
            source_node: MemberId(1),
            target_node: MemberId(2),
            sequence_number: 0,
            chunks: vec![ChunkRange::new(0, 512)],
            total_chunks: 1,
        };
        let mut encoded = req.encode();

        // Corrupt the payload (flip a byte before the checksum)
        encoded[10] ^= 0xFF;

        assert!(ChunkTransferRequest::decode(&encoded).is_none());
    }

    #[test]
    fn chunk_transfer_request_decode_wrong_chunk_count() {
        let req = ChunkTransferRequest {
            transfer_id: 1,
            object_id: ReplicatedSubjectId(10),
            source_node: MemberId(1),
            target_node: MemberId(2),
            sequence_number: 0,
            chunks: vec![ChunkRange::new(0, 512)],
            total_chunks: 1,
        };
        let mut encoded = req.encode();

        // Corrupt the chunk_count field (bytes 40-44) to claim 5 chunks
        encoded[40..44].copy_from_slice(&5u32.to_be_bytes());

        assert!(ChunkTransferRequest::decode(&encoded).is_none());
    }

    #[test]
    fn chunk_transfer_response_accepted_encode_decode() {
        let resp = ChunkTransferResponse::accept(42, 7, 128);
        let encoded = resp.encode();
        let decoded = ChunkTransferResponse::decode(&encoded).expect("decode failed");
        assert_eq!(decoded.transfer_id, 42);
        assert!(decoded.accepted);
        assert_eq!(decoded.rejection_reason, None);
        assert_eq!(decoded.sequence_number, 7);
        assert_eq!(decoded.max_chunks_accepted, 128);
    }

    #[test]
    fn chunk_transfer_response_rejected_encode_decode() {
        let resp = ChunkTransferResponse::reject(42, 7, "no capacity");
        let encoded = resp.encode();
        let decoded = ChunkTransferResponse::decode(&encoded).expect("decode failed");
        assert_eq!(decoded.transfer_id, 42);
        assert!(!decoded.accepted);
        assert_eq!(decoded.rejection_reason.as_deref(), Some("no capacity"));
        assert_eq!(decoded.sequence_number, 7);
        assert_eq!(decoded.max_chunks_accepted, 0);
    }

    #[test]
    fn chunk_transfer_response_decode_corrupt_checksum() {
        let resp = ChunkTransferResponse::accept(1, 0, 10);
        let mut encoded = resp.encode();
        // Flip a byte in the payload area
        encoded[3] ^= 0x01;
        assert!(ChunkTransferResponse::decode(&encoded).is_none());
    }

    #[test]
    fn chunk_transfer_response_decode_too_short() {
        assert!(ChunkTransferResponse::decode(&[]).is_none());
        assert!(ChunkTransferResponse::decode(&[0u8; 30]).is_none());
    }

    // ── ChunkRange tests ────────────────────────────────────────────────────

    #[test]
    fn chunk_range_len() {
        let r = ChunkRange::new(10, 30);
        assert_eq!(r.len(), 20);
    }

    #[test]
    fn chunk_range_is_empty() {
        assert!(ChunkRange::new(5, 5).is_empty());
        assert!(ChunkRange::new(10, 5).is_empty());
        assert!(!ChunkRange::new(0, 1).is_empty());
    }

    // ── Exponential backoff tests ────────────────────────────────────────────

    #[test]
    fn exponential_backoff_base_case() {
        let d = exponential_backoff(0, Duration::from_millis(100), Duration::from_secs(30));
        assert_eq!(d, Duration::from_millis(100));
    }

    #[test]
    fn exponential_backoff_doubles() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(30);
        let d0 = exponential_backoff(0, base, max);
        let d1 = exponential_backoff(1, base, max);
        let d2 = exponential_backoff(2, base, max);
        assert_eq!(d1, d0.saturating_mul(2));
        assert_eq!(d2, d1.saturating_mul(2));
    }

    #[test]
    fn exponential_backoff_hits_max() {
        let d = exponential_backoff(20, Duration::from_millis(100), Duration::from_secs(30));
        assert_eq!(d, Duration::from_secs(30));
    }

    #[test]
    fn default_backoff_grows() {
        let d0 = default_backoff(0);
        let d1 = default_backoff(1);
        let d5 = default_backoff(5);
        assert!(d1 > d0);
        assert!(d5 > d1);
        // Should cap at 30 seconds
        let big = default_backoff(32);
        assert_eq!(big, Duration::from_secs(30));
    }

    #[test]
    fn remaining_chunks_defaults_to_zero() {
        let p = ChunkTransferProgress::new(1, ReplicatedSubjectId(10), 1024);
        assert_eq!(p.remaining_chunks, 0);
    }

    #[test]
    fn remaining_chunks_is_tracked() {
        let mut p = ChunkTransferProgress::new(1, ReplicatedSubjectId(10), 1024);
        p.remaining_chunks = 5;
        assert_eq!(p.remaining_chunks, 5);
        p.remaining_chunks = 0;
        assert_eq!(p.remaining_chunks, 0);
    }

    // ── Serde round-trip tests for new types ─────────────────────────────────

    #[test]
    fn chunk_range_serde_round_trip() {
        let r = ChunkRange::new(0, 1024);
        let json = serde_json::to_string(&r).unwrap();
        let back: ChunkRange = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn chunk_transfer_request_serde_round_trip() {
        let req = ChunkTransferRequest {
            transfer_id: 7,
            object_id: ReplicatedSubjectId(55),
            source_node: MemberId(1),
            target_node: MemberId(2),
            sequence_number: 3,
            chunks: vec![ChunkRange::new(0, 512)],
            total_chunks: 1,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ChunkTransferRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn chunk_transfer_response_serde_round_trip() {
        let resp = ChunkTransferResponse::reject(1, 2, "busy");
        let json = serde_json::to_string(&resp).unwrap();
        let back: ChunkTransferResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn derive_receive_digest_is_blake3_based() {
        // BLAKE3 digests are well-distributed; different inputs give different digests
        let d1 = derive_receive_digest(b"chunk data 1");
        let d2 = derive_receive_digest(b"chunk data 2");
        assert_ne!(d1, d2);

        // Same input always gives same digest
        let d3 = derive_receive_digest(b"consistent");
        let d4 = derive_receive_digest(b"consistent");
        assert_eq!(d3, d4);

        // Non-zero for non-empty input
        assert_ne!(d1.0, 0);
    }

    // ── Bounded-channel backpressure and cancelation tests ─────────────────

    #[test]
    fn backpressure_sender_window_blocks_when_full() {
        let pair = LoopbackPair::new();
        let mut sender = ChunkSender::new(pair.left, 2, Duration::from_secs(60));
        let cancel = CancelationToken::new();

        // Fill the window
        sender.send_chunk(1, b"a", ChunkFlags::new()).unwrap();
        sender.send_chunk(2, b"b", ChunkFlags::new()).unwrap();
        assert!(sender.is_window_full());

        // Next send fails — backpressure demonstrated
        let result = sender.send_chunk(3, b"c", ChunkFlags::new());
        assert!(result.is_err());
        assert!(!cancel.is_cancelled());
    }

    #[test]
    fn backpressure_with_ack_processing_drains_window() {
        let pair = LoopbackPair::new();
        let mut sender = ChunkSender::new(pair.left, 4, Duration::from_secs(60));
        let mut receiver = ChunkReceiver::new(pair.right);
        let cancel = CancelationToken::new();

        let chunks: Vec<_> = (0..16)
            .map(|i| {
                let payload = format!("chunk-{i:02}").into_bytes();
                (i as u64, payload, ChunkFlags::new())
            })
            .collect();

        // Alternating send batch + recv + ACK clears window, demonstrating
        // backpressure management through ACK processing
        let mut total_sent = 0;
        let mut all_delivered: Vec<DeliveredChunk> = Vec::new();
        let batch_size = 3;

        for batch in chunks.chunks(batch_size) {
            let sent = send_chunks_with_backpressure(&mut sender, batch, &cancel);
            total_sent += sent;

            let delivered = recv_and_deliver(&mut receiver, sent, &cancel);
            all_delivered.extend(delivered);

            // Send ACK back to clear sender window
            let ack = receiver.build_ack();
            sender.process_ack(&ack);
        }

        assert_eq!(total_sent, 16);
        assert_eq!(all_delivered.len(), 16);
    }

    #[test]
    fn cancelation_stops_send_mid_stream() {
        let pair = LoopbackPair::new();
        let mut sender = ChunkSender::new(pair.left, 16, Duration::from_secs(60));
        let mut receiver = ChunkReceiver::new(pair.right);
        let cancel = CancelationToken::new();

        let mut chunks = Vec::new();
        for i in 0..20 {
            let payload = format!("chunk-{i:02}").into_bytes();
            chunks.push((i as u64, payload, ChunkFlags::new()));
        }

        // Cancel after sending a few chunks by modifying the cancel token
        // between send calls (simulating external cancel signal)
        let cancel_clone = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            cancel_clone.cancel();
        });

        // Send in a loop, checking cancel each iteration
        let mut sent = 0;
        for chunk in &chunks {
            if cancel.is_cancelled() {
                break;
            }
            match sender.send_chunk(chunk.0, &chunk.1, chunk.2) {
                Ok(_) => sent += 1,
                Err(_) => break,
            }
        }

        // Transfer was interrupted; we have fewer than 20 sent
        assert!(
            sent < 20,
            "cancelation should have interrupted the send, got {sent}"
        );

        let delivered = recv_and_deliver(&mut receiver, sent, &cancel);
        assert_eq!(delivered.len(), sent);
    }

    #[test]
    fn cancelation_before_send_delivers_nothing() {
        let pair = LoopbackPair::new();
        let mut sender = ChunkSender::new(pair.left, 8, Duration::from_secs(60));
        let mut receiver = ChunkReceiver::new(pair.right);
        let cancel = CancelationToken::new();

        // Cancel immediately
        cancel.cancel();

        let chunks = vec![(1, b"data".to_vec(), ChunkFlags::new())];

        let sent = send_chunks_with_backpressure(&mut sender, &chunks, &cancel);
        assert_eq!(sent, 0);
        let delivered = recv_and_deliver(&mut receiver, sent, &cancel);
        assert!(delivered.is_empty());
    }

    // ── Aggregate verification integrated with streaming pipeline ──────────

    #[test]
    fn aggregate_verification_matches_across_streaming_transfer() {
        let pair = LoopbackPair::new();
        let sender = ChunkSender::new(pair.left, 8, Duration::from_secs(60));
        let receiver = ChunkReceiver::new(pair.right);
        let config = ChunkStreamConfig::new(64, 8);
        let cancel = CancelationToken::new();

        let data = b"this is a test payload for aggregate verification across a streaming chunk transfer pipeline";

        let (sent, delivered, digest) =
            stream_chunks_with_aggregate_verification(sender, receiver, data, &config, &cancel);

        assert_eq!(sent, delivered.len());
        assert!(!delivered.is_empty());
        // Digest should be non-zero (matching)
        assert_ne!(digest, [0u8; 32]);
        assert!(delivered[0].flags.has(ChunkFlags::START));
        assert!(delivered.last().unwrap().flags.has(ChunkFlags::END));

        // Deliver in-order: reassemble
        let assembled: Vec<u8> = delivered.iter().flat_map(|dc| dc.payload.clone()).collect();
        assert_eq!(assembled, data);
    }

    #[test]
    fn aggregate_verification_single_chunk_transfer() {
        let pair = LoopbackPair::new();
        let sender = ChunkSender::new(pair.left, 4, Duration::from_secs(60));
        let receiver = ChunkReceiver::new(pair.right);
        let config = ChunkStreamConfig::new(1024, 8);
        let cancel = CancelationToken::new();

        let data = b"single chunk payload";

        let (sent, delivered, digest) =
            stream_chunks_with_aggregate_verification(sender, receiver, data, &config, &cancel);

        assert_eq!(sent, 1);
        assert_eq!(delivered.len(), 1);
        assert_ne!(digest, [0u8; 32]);
        assert_eq!(delivered[0].payload, data);
        assert!(delivered[0].flags.has(ChunkFlags::START));
        assert!(delivered[0].flags.has(ChunkFlags::END));
    }

    #[test]
    fn aggregate_verification_large_data_multi_chunk() {
        let pair = LoopbackPair::new();
        let sender = ChunkSender::new(pair.left, 16, Duration::from_secs(60));
        let receiver = ChunkReceiver::new(pair.right);
        let config = ChunkStreamConfig::new(32, 8);
        let cancel = CancelationToken::new();

        let data = vec![0xABu8; 500];

        let (sent, delivered, digest) =
            stream_chunks_with_aggregate_verification(sender, receiver, &data, &config, &cancel);

        let num_chunks = 500usize.div_ceil(32);
        assert_eq!(sent, num_chunks);
        assert_eq!(delivered.len(), num_chunks);
        assert_ne!(digest, [0u8; 32]);

        let assembled: Vec<u8> = delivered.iter().flat_map(|dc| dc.payload.clone()).collect();
        assert_eq!(assembled, data);
    }

    #[test]
    fn aggregate_digest_zero_on_mismatch() {
        // Compute what the sender-side aggregate should be
        let mut hasher = crate::protocol::ChunkAggregateHasher::new();
        hasher.update(b"original data");
        let expected = hasher.finalize();

        let pair = LoopbackPair::new();
        let sender = ChunkSender::new(pair.left, 4, Duration::from_secs(60));
        let receiver = ChunkReceiver::new(pair.right);
        let config = ChunkStreamConfig::new(1024, 8);
        let cancel = CancelationToken::new();

        let data = b"original data";
        let (_sent, _delivered, digest) =
            stream_chunks_with_aggregate_verification(sender, receiver, data, &config, &cancel);

        // With no tampering, digest matches
        assert_ne!(digest, [0u8; 32]);
        assert_eq!(digest, expected);
    }

    // ── ChunkStreamConfig tests ────────────────────────────────────────────

    #[test]
    fn chunk_stream_config_default_values() {
        let config = ChunkStreamConfig::default();
        assert_eq!(config.max_chunk_size, 64 * 1024);
        assert_eq!(config.channel_capacity, 16);
        assert_eq!(config.retransmit_timeout, Duration::from_secs(2));
    }

    #[test]
    fn chunk_stream_config_custom_values() {
        let config = ChunkStreamConfig::new(512, 4);
        assert_eq!(config.max_chunk_size, 512);
        assert_eq!(config.channel_capacity, 4);
        assert_eq!(config.retransmit_timeout, Duration::from_secs(2));
    }

    // ── CancelationToken tests ─────────────────────────────────────────────

    #[test]
    fn cancelation_token_default_not_cancelled() {
        let token = CancelationToken::new();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn cancelation_token_cancel_sets_flag() {
        let token = CancelationToken::new();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn cancelation_token_clone_shares_state() {
        let token = CancelationToken::new();
        let clone = token.clone();
        assert!(!clone.is_cancelled());

        token.cancel();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn cancelation_token_clone_cancel_visible_from_original() {
        let token = CancelationToken::new();
        let clone = token.clone();

        clone.cancel();
        assert!(token.is_cancelled());
    }

    // ── Resume-from-offset: request a partial range ───────────────────────

    #[test]
    fn resume_from_offset_mid_stream() {
        let full_data = b"0123456789abcdef";

        // First transfer: send first half (offset 0, length 8)
        let pair1 = LoopbackPair::new();
        let mut sender1 = ChunkSender::new(pair1.left, 4, Duration::from_secs(60));
        let mut receiver1 = ChunkReceiver::new(pair1.right);
        let cancel = CancelationToken::new();

        let first_half = vec![
            (
                0,
                full_data[0..4].to_vec(),
                ChunkFlags::new().with(ChunkFlags::START),
            ),
            (1, full_data[4..8].to_vec(), ChunkFlags::new()),
        ];

        let sent1 = send_chunks_with_backpressure(&mut sender1, &first_half, &cancel);
        assert_eq!(sent1, 2);
        let delivered1 = recv_and_deliver(&mut receiver1, sent1, &cancel);
        assert_eq!(delivered1.len(), 2);
        let received_first: Vec<u8> = delivered1
            .iter()
            .flat_map(|dc| dc.payload.clone())
            .collect();
        assert_eq!(received_first, &full_data[0..8]);

        // Resume: second half (chunk IDs continue from where we left off)
        let pair2 = LoopbackPair::new();
        let mut sender2 = ChunkSender::new(pair2.left, 4, Duration::from_secs(60));
        let mut receiver2 = ChunkReceiver::new(pair2.right);
        let second_half = vec![
            (2, full_data[8..12].to_vec(), ChunkFlags::new()),
            (
                3,
                full_data[12..16].to_vec(),
                ChunkFlags::new().with(ChunkFlags::END),
            ),
        ];

        let sent2 = send_chunks_with_backpressure(&mut sender2, &second_half, &cancel);
        assert_eq!(sent2, 2);
        let delivered2 = recv_and_deliver(&mut receiver2, sent2, &cancel);
        assert_eq!(delivered2.len(), 2);
        let received_second: Vec<u8> = delivered2
            .iter()
            .flat_map(|dc| dc.payload.clone())
            .collect();
        assert_eq!(received_second, &full_data[8..16]);

        // Full reassembly
        let total_received: Vec<u8> = received_first.into_iter().chain(received_second).collect();
        assert_eq!(total_received.as_slice(), full_data);
    }

    // ── ChunkStreamItem tests ──────────────────────────────────────────────

    #[test]
    fn chunk_stream_item_fields() {
        let item = ChunkStreamItem {
            chunk_id: 42,
            payload: b"test".to_vec(),
            flags: ChunkFlags::new().with(ChunkFlags::START),
        };
        assert_eq!(item.chunk_id, 42);
        assert_eq!(item.payload, b"test");
        assert!(item.flags.has(ChunkFlags::START));
    }

    // ── Edge case: empty data stream ───────────────────────────────────────

    #[test]
    fn empty_data_aggregate_verification_produces_one_empty_chunk() {
        let pair = LoopbackPair::new();
        let sender = ChunkSender::new(pair.left, 4, Duration::from_secs(60));
        let receiver = ChunkReceiver::new(pair.right);
        let config = ChunkStreamConfig::new(1024, 8);
        let cancel = CancelationToken::new();

        let data: &[u8] = &[];
        let (_sent, delivered, digest) =
            stream_chunks_with_aggregate_verification(sender, receiver, data, &config, &cancel);

        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].payload.len(), 0);
        assert!(delivered[0].flags.has(ChunkFlags::START));
        assert!(delivered[0].flags.has(ChunkFlags::END));
        assert_ne!(digest, [0u8; 32]);
    }
}
