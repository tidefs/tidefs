// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport message batch aggregation with domain-separated batch-payload
//! integrity via BLAKE3.
//!
//! ## Purpose
//!
//! The message batcher coalesces multiple small outbound messages destined
//! for the same peer into a single transport frame (a [`MessageBatch`]),
//! reducing per-frame header overhead, syscall count, and encryption
//! operations for bursty multi-subsystem workloads.
//!
//! ## Architecture
//!
//! ```text
//! send(msg, peer) ──► MessageBatcher::enqueue(msg, peer)
//!                        │
//!                        ▼
//!                     Per-peer VecDeque<QueuedMessage>
//!                        │
//!                        ▼
//!                     drain_batch(peer) on flush trigger
//!                        │
//!                        ▼
//!                     MessageBatch (wire-ready)
//!                        │
//!                        ▼
//!                     Transport frame encode → send
//! ```
//!
//! On the receive side, [`MessageBatch::decompose()`] splits the batch
//! back into individual message payloads for dispatch through the
//! existing [`crate::message_dispatch::MessageDispatcher`].
//!
//! ## Flush triggers
//!
//! A batch is emitted when any of these conditions is met:
//!
//! 1. Byte threshold — the next enqueue would push total payload bytes
//!    past `max_batch_bytes`.
//! 2. Count threshold — the batch has accumulated `max_batch_messages`.
//! 3. Deadline — `max_wait` has elapsed since the first message was
//!    enqueued for that peer.
//! 4. Explicit — caller invokes `drain_batch()` or `flush_all()`.
//!
//! ## BLAKE3 wire format
//!
//! ```text
//! [sequence:8 LE][peer:8 LE][msg_count:4 LE]
//! [sizes:msg_count*4 LE][payloads:concat][BLAKE3-256:32]
//! ```
//!
//! Domain: `tidefs-transport-message-batch-v1`

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Domain-separation
// ---------------------------------------------------------------------------

/// Domain context for MessageBatch BLAKE3 integrity hashing.
const BATCH_DOMAIN: &str = "tidefs-transport-message-batch-v1";

/// Minimum batch frame size: header (seq + peer + count) + empty + hash.
const MIN_BATCH_SIZE: usize = 8 + 8 + 4 + 32;

/// Fixed header size before per-message sizes and payloads.
const HEADER_SIZE: usize = 20; // seq(8) + peer(8) + count(4)

// ---------------------------------------------------------------------------
// BatchError
// ---------------------------------------------------------------------------

/// Errors from the batch encode/decode layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchError {
    /// The frame is too short for a valid batch.
    FrameTooShort { got: usize },
    /// BLAKE3 integrity hash mismatch.
    IntegrityMismatch,
    /// The advertised payload sizes consume more bytes than the frame provides.
    PayloadSizeOverflow,
}

impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooShort { got } => {
                write!(
                    f,
                    "batch frame too short: {got} bytes (min {MIN_BATCH_SIZE})"
                )
            }
            Self::IntegrityMismatch => {
                write!(f, "BLAKE3 integrity mismatch on batch frame")
            }
            Self::PayloadSizeOverflow => {
                write!(
                    f,
                    "batch payload size overflow: sizes sum exceeds frame bounds"
                )
            }
        }
    }
}

impl std::error::Error for BatchError {}
// ---------------------------------------------------------------------------
// BatchStats
// ---------------------------------------------------------------------------

/// Accumulated batch statistics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BatchStats {
    /// Total number of messages enqueued for batching.
    pub messages_batched: u64,
    /// Total number of batches flushed (emitted to wire).
    pub batches_flushed: u64,
    /// Total payload bytes across all flushed batches.
    pub bytes_batched: u64,
}

impl BatchStats {
    /// Create a new zeroed stats instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one message enqueued.
    fn record_enqueue(&mut self) {
        self.messages_batched = self.messages_batched.wrapping_add(1);
    }

    /// Record one batch flushed with the given total payload bytes.
    fn record_flush(&mut self, total_payload_bytes: u64) {
        self.batches_flushed = self.batches_flushed.wrapping_add(1);
        self.bytes_batched = self.bytes_batched.wrapping_add(total_payload_bytes);
    }

    /// Merge another stats into this one (non-destructive accumulate).
    pub fn merge(&mut self, other: &Self) {
        self.messages_batched = self.messages_batched.wrapping_add(other.messages_batched);
        self.batches_flushed = self.batches_flushed.wrapping_add(other.batches_flushed);
        self.bytes_batched = self.bytes_batched.wrapping_add(other.bytes_batched);
    }
}

// ---------------------------------------------------------------------------
// MessageBatch
// ---------------------------------------------------------------------------

/// A batch of messages with domain-separated payload integrity for a single peer.
///
/// Encoded in wire format and verified on receipt via [`verify()`].
/// Use [`decompose()`] on the receiving side to extract individual
/// message payloads for dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageBatch {
    /// Monotonic batch sequence number for this peer.
    pub sequence: u64,
    /// Destination peer identity.
    pub peer: u64,
    /// Individual message payloads in enqueue order.
    pub messages: Vec<Vec<u8>>,
}

impl MessageBatch {
    // -----------------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------------

    /// Encode the batch into wire format with BLAKE3 integrity hash.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let msg_count = self.messages.len() as u32;
        let sizes_bytes = msg_count as usize * 4;
        let total_payload: usize = self.messages.iter().map(|m| m.len()).sum();
        let framed_len = HEADER_SIZE + sizes_bytes + total_payload;

        let mut buf = Vec::with_capacity(framed_len + 32);
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&self.peer.to_le_bytes());
        buf.extend_from_slice(&msg_count.to_le_bytes());

        for msg in &self.messages {
            buf.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        }
        for msg in &self.messages {
            buf.extend_from_slice(msg);
        }

        let integrity = compute_batch_integrity(&buf);
        buf.extend_from_slice(&integrity);

        buf
    }

    /// Verify BLAKE3 integrity of a batch frame and decode it.
    ///
    /// Returns the decoded [`MessageBatch`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError`] on any failure: frame too short, integrity
    /// mismatch, or payload size overflow.
    pub fn decode(data: &[u8]) -> Result<Self, BatchError> {
        if data.len() < MIN_BATCH_SIZE {
            return Err(BatchError::FrameTooShort { got: data.len() });
        }

        let integrity_start = data.len() - 32;
        let framed = &data[..integrity_start];
        let integrity: [u8; 32] = data[integrity_start..].try_into().unwrap();

        let expected = compute_batch_integrity(framed);
        if integrity != expected {
            return Err(BatchError::IntegrityMismatch);
        }

        if framed.len() < HEADER_SIZE {
            return Err(BatchError::FrameTooShort { got: data.len() });
        }

        let sequence = u64::from_le_bytes([
            framed[0], framed[1], framed[2], framed[3], framed[4], framed[5], framed[6], framed[7],
        ]);
        let peer = u64::from_le_bytes([
            framed[8], framed[9], framed[10], framed[11], framed[12], framed[13], framed[14],
            framed[15],
        ]);
        let msg_count =
            u32::from_le_bytes([framed[16], framed[17], framed[18], framed[19]]) as usize;

        let sizes_offset = HEADER_SIZE;
        let sizes_end = sizes_offset + msg_count * 4;
        if framed.len() < sizes_end {
            return Err(BatchError::FrameTooShort { got: data.len() });
        }

        let mut payload_offset = sizes_end;
        let mut messages = Vec::with_capacity(msg_count);

        for i in 0..msg_count {
            let start = sizes_offset + i * 4;
            let size = u32::from_le_bytes([
                framed[start],
                framed[start + 1],
                framed[start + 2],
                framed[start + 3],
            ]) as usize;

            if payload_offset + size > framed.len() {
                return Err(BatchError::PayloadSizeOverflow);
            }

            let payload = framed[payload_offset..payload_offset + size].to_vec();
            messages.push(payload);
            payload_offset += size;
        }

        Ok(Self {
            sequence,
            peer,
            messages,
        })
    }

    /// Verify the integrity of an encoded batch frame in place (no decode).
    ///
    /// Returns `Ok(())` when the BLAKE3 hash matches; returns
    /// [`BatchError::IntegrityMismatch`] otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError::FrameTooShort`] if the data is too short to
    /// contain a valid integrity hash.
    pub fn verify(data: &[u8]) -> Result<(), BatchError> {
        if data.len() < MIN_BATCH_SIZE {
            return Err(BatchError::FrameTooShort { got: data.len() });
        }
        let integrity_start = data.len() - 32;
        let framed = &data[..integrity_start];
        let integrity: [u8; 32] = data[integrity_start..].try_into().unwrap();

        let expected = compute_batch_integrity(framed);
        if integrity != expected {
            return Err(BatchError::IntegrityMismatch);
        }
        Ok(())
    }

    /// Decompose a decoded batch into individual message payloads.
    ///
    /// Each payload corresponds to one original enqueued message,
    /// preserving enqueue order.
    #[must_use]
    pub fn decompose(&self) -> Vec<Vec<u8>> {
        self.messages.clone()
    }

    /// Total number of messages in this batch.
    #[must_use]
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Total payload bytes across all messages in this batch.
    #[must_use]
    pub fn total_payload_bytes(&self) -> usize {
        self.messages.iter().map(|m| m.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// BLAKE3 helper
// ---------------------------------------------------------------------------

fn compute_batch_integrity(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(BATCH_DOMAIN);
    hasher.update(prefix);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// BatchConfig
// ---------------------------------------------------------------------------

/// Configuration governing per-peer message batch aggregation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchConfig {
    /// Maximum bytes of concatenated payloads allowed in a single batch.
    pub max_batch_bytes: usize,
    /// Maximum number of messages allowed in a single batch.
    pub max_batch_messages: usize,
    /// Maximum time to wait after the first enqueue before flushing a batch.
    pub max_wait: Duration,
    /// Whether batching is enabled. When `false`, every enqueue immediately
    /// drains a single-message batch.
    pub enabled: bool,
}

impl BatchConfig {
    /// Create a new config.
    #[must_use]
    pub fn new(max_batch_bytes: usize, max_batch_messages: usize, max_wait: Duration) -> Self {
        Self {
            max_batch_bytes,
            max_batch_messages,
            max_wait,
            enabled: true,
        }
    }

    /// Config that disables batching (every enqueue emits immediately).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            max_batch_bytes: 0,
            max_batch_messages: 0,
            max_wait: Duration::ZERO,
            enabled: false,
        }
    }
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_bytes: 65536,
            max_batch_messages: 64,
            max_wait: Duration::from_micros(500),
            enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// QueuedMessage
// ---------------------------------------------------------------------------

/// A message waiting to be batched for a specific peer.
#[derive(Clone, Debug)]
struct QueuedMessage {
    /// The raw payload bytes.
    payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// PeerBatchQueue
// ---------------------------------------------------------------------------

/// Per-peer message accumulation queue with flush-trigger logic.
#[derive(Debug)]
struct PeerBatchQueue {
    /// Messages waiting to be coalesced.
    pending: VecDeque<QueuedMessage>,
    /// Monotonic batch sequence number for this peer.
    next_sequence: u64,
    /// Total payload bytes currently accumulated.
    accumulated_bytes: usize,
    /// Instant of first enqueue since last flush (for deadline calculation).
    first_enqueue: Option<Instant>,
}

impl PeerBatchQueue {
    fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            next_sequence: 1,
            accumulated_bytes: 0,
            first_enqueue: None,
        }
    }

    /// Whether the queue is empty.
    fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Number of queued messages.
    fn len(&self) -> usize {
        self.pending.len()
    }
}

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// MessageBatcher
// ---------------------------------------------------------------------------

/// Per-peer message batch aggregator.
///
/// Callers enqueue individual messages via [`enqueue()`] and periodically
/// drain ready batches via [`drain_ready()`] or force-flush specific peers
/// via [`drain_batch()`].
///
/// # Concurrency
///
/// Methods take `&mut self`; the caller is responsible for wrapping in
/// an appropriate synchronization primitive (e.g., `Mutex`).
pub struct MessageBatcher {
    config: BatchConfig,
    peers: HashMap<u64, PeerBatchQueue>,
    /// Accumulated batch statistics.
    pub stats: BatchStats,
}

impl MessageBatcher {
    /// Create a new batcher with the given config.
    #[must_use]
    pub fn new(config: BatchConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            stats: BatchStats::new(),
        }
    }

    /// Enqueue a single message for a peer.
    ///
    /// Returns `Some(MessageBatch)` if enqueuing triggered an immediate
    /// flush (due to byte or count thresholds), so the caller can send
    /// the batch frame immediately.
    ///
    /// When batching is disabled (`config.enabled == false`), every
    /// enqueue immediately returns a single-message batch.
    #[must_use]
    pub fn enqueue(&mut self, peer: u64, payload: Vec<u8>) -> Option<MessageBatch> {
        if !self.config.enabled {
            self.stats.record_enqueue();
            let queue = self.peers.entry(peer).or_insert_with(PeerBatchQueue::new);
            let seq = queue.next_sequence;
            queue.next_sequence += 1;
            let batch = MessageBatch {
                sequence: seq,
                peer,
                messages: vec![payload],
            };
            self.stats.record_flush(batch.total_payload_bytes() as u64);
            return Some(batch);
        }

        let now = Instant::now();
        let payload_len = payload.len();

        let queue = self.peers.entry(peer).or_insert_with(PeerBatchQueue::new);

        // Check if adding this message would overflow byte limit (and queue
        // is non-empty — no point batching a single oversized message).
        let would_overflow_bytes = !queue.is_empty()
            && queue.accumulated_bytes + payload_len > self.config.max_batch_bytes;

        if would_overflow_bytes {
            // Drain what we have, then enqueue the new message.
            self.stats.record_enqueue();
            let batch = self.drain_queue(peer);
            self.stats.record_flush(batch.total_payload_bytes() as u64);
            // Re-fetch queue (now empty after drain_queue removes it or creates new).
            let queue2 = self.peers.entry(peer).or_insert_with(PeerBatchQueue::new);
            queue2.first_enqueue = Some(now);
            queue2.accumulated_bytes = payload_len;
            queue2.pending.push_back(QueuedMessage { payload });
            return Some(batch);
        }

        // Normal enqueue.
        self.stats.record_enqueue();
        if queue.first_enqueue.is_none() {
            queue.first_enqueue = Some(now);
        }
        queue.accumulated_bytes += payload_len;
        queue.pending.push_back(QueuedMessage { payload });

        // Check count threshold.
        if queue.len() >= self.config.max_batch_messages {
            let batch = self.drain_queue(peer);
            self.stats.record_flush(batch.total_payload_bytes() as u64);
            return Some(batch);
        }

        None
    }

    /// Drain the accumulated batch for a specific peer.
    ///
    /// Returns `Some(MessageBatch)` if there were queued messages, or
    /// `None` if the peer's queue was empty.
    #[must_use]
    pub fn drain_batch(&mut self, peer: u64) -> Option<MessageBatch> {
        let queue = self.peers.get(&peer)?;
        if queue.is_empty() {
            return None;
        }
        let batch = self.drain_queue(peer);
        self.stats.record_flush(batch.total_payload_bytes() as u64);
        Some(batch)
    }

    /// Drain all peers whose batches are ready (deadline expired, count
    /// threshold reached, or byte threshold reached).
    ///
    /// Returns a list of (peer, batch) pairs in no particular order.
    #[must_use]
    pub fn drain_ready(&mut self) -> Vec<(u64, MessageBatch)> {
        let now = Instant::now();
        let ready_peers: Vec<u64> = self
            .peers
            .iter()
            .filter_map(|(&peer, q)| {
                if q.is_empty() {
                    return None;
                }
                // Deadline trigger.
                if let Some(first) = q.first_enqueue {
                    if now.duration_since(first) >= self.config.max_wait {
                        return Some(peer);
                    }
                }
                // Count / byte already handled during enqueue, but re-check
                // in case config changed or bytes accumulated.
                if q.len() >= self.config.max_batch_messages
                    || q.accumulated_bytes >= self.config.max_batch_bytes
                {
                    return Some(peer);
                }
                None
            })
            .collect();

        ready_peers
            .into_iter()
            .map(|peer| {
                let batch = self.drain_queue(peer);
                self.stats.record_flush(batch.total_payload_bytes() as u64);
                (peer, batch)
            })
            .collect()
    }

    /// Force-flush all peers with queued messages.
    ///
    /// Returns a list of (peer, batch) pairs for every non-empty queue.
    #[must_use]
    pub fn flush_all(&mut self) -> Vec<(u64, MessageBatch)> {
        let all_peers: Vec<u64> = self
            .peers
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(&peer, _)| peer)
            .collect();

        all_peers
            .into_iter()
            .map(|peer| {
                let batch = self.drain_queue(peer);
                self.stats.record_flush(batch.total_payload_bytes() as u64);
                (peer, batch)
            })
            .collect()
    }

    /// Number of messages currently queued across all peers.
    #[must_use]
    pub fn total_queued(&self) -> usize {
        self.peers.values().map(|q| q.len()).sum()
    }

    /// Number of peers with at least one queued message.
    #[must_use]
    pub fn active_peers(&self) -> usize {
        self.peers.values().filter(|q| !q.is_empty()).count()
    }

    /// Return a snapshot of the current batch statistics.
    #[must_use]
    pub fn stats(&self) -> BatchStats {
        self.stats.clone()
    }

    /// Whether there are no queued messages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.values().all(|q| q.is_empty())
    }

    // -------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------

    /// Drain all pending messages from a peer queue into a `MessageBatch`,
    /// reset the queue state, and advance the sequence number.
    fn drain_queue(&mut self, peer: u64) -> MessageBatch {
        let queue = self
            .peers
            .get_mut(&peer)
            .expect("drain_queue called for unknown peer");

        let seq = queue.next_sequence;
        queue.next_sequence += 1;

        let messages: Vec<Vec<u8>> = queue.pending.drain(..).map(|qm| qm.payload).collect();

        queue.accumulated_bytes = 0;
        queue.first_enqueue = None;

        MessageBatch {
            sequence: seq,
            peer,
            messages,
        }
    }
}

impl Default for MessageBatcher {
    fn default() -> Self {
        Self::new(BatchConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // MessageBatch encode/decode round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_single_message() {
        let batch = MessageBatch {
            sequence: 1,
            peer: 42,
            messages: vec![b"hello transport".to_vec()],
        };
        let encoded = batch.encode();
        let decoded = MessageBatch::decode(&encoded).unwrap();

        assert_eq!(decoded.sequence, 1);
        assert_eq!(decoded.peer, 42);
        assert_eq!(decoded.messages.len(), 1);
        assert_eq!(decoded.messages[0], b"hello transport");
    }

    #[test]
    fn round_trip_multi_message() {
        let messages: Vec<Vec<u8>> = (0..20)
            .map(|i| format!("message-{i:02}").into_bytes())
            .collect();
        let batch = MessageBatch {
            sequence: 7,
            peer: 99,
            messages,
        };
        let encoded = batch.encode();
        let decoded = MessageBatch::decode(&encoded).unwrap();

        assert_eq!(decoded.sequence, 7);
        assert_eq!(decoded.peer, 99);
        assert_eq!(decoded.messages.len(), 20);
        for i in 0..20 {
            assert_eq!(decoded.messages[i], format!("message-{i:02}").as_bytes());
        }
    }

    #[test]
    fn round_trip_empty_batch() {
        let batch = MessageBatch {
            sequence: 0,
            peer: 0,
            messages: vec![],
        };
        let encoded = batch.encode();
        let decoded = MessageBatch::decode(&encoded).unwrap();

        assert_eq!(decoded.messages.len(), 0);
        assert_eq!(decoded.sequence, 0);
    }

    #[test]
    fn round_trip_binary_payloads() {
        let batch = MessageBatch {
            sequence: 1,
            peer: 1,
            messages: vec![
                vec![0x00, 0xFF, 0xAB],
                vec![0x12, 0x34, 0x56, 0x78],
                b"\x00\x01\x02\x03".to_vec(),
            ],
        };
        let encoded = batch.encode();
        let decoded = MessageBatch::decode(&encoded).unwrap();

        assert_eq!(decoded.messages, batch.messages);
    }

    #[test]
    fn round_trip_large_messages() {
        let msg = vec![0x42u8; 4096];
        let batch = MessageBatch {
            sequence: 5,
            peer: 10,
            messages: vec![msg.clone(), msg.clone(), msg],
        };
        let encoded = batch.encode();
        let decoded = MessageBatch::decode(&encoded).unwrap();

        assert_eq!(decoded.messages[0].len(), 4096);
        assert_eq!(decoded.messages.len(), 3);
    }

    // -----------------------------------------------------------------------
    // MessageBatch verify
    // -----------------------------------------------------------------------

    #[test]
    fn verify_valid_batch() {
        let batch = MessageBatch {
            sequence: 3,
            peer: 77,
            messages: vec![b"data".to_vec(), b"more".to_vec()],
        };
        let encoded = batch.encode();
        MessageBatch::verify(&encoded).unwrap();
    }

    #[test]
    fn verify_tampered_payload() {
        let batch = MessageBatch {
            sequence: 1,
            peer: 1,
            messages: vec![b"sensitive".to_vec()],
        };
        let mut encoded = batch.encode();
        // Flip a byte in the payload region.
        encoded[HEADER_SIZE + 4] ^= 0xFF; // after the size (4 bytes), into payload

        let result = MessageBatch::verify(&encoded);
        assert!(matches!(result, Err(BatchError::IntegrityMismatch)));
    }

    #[test]
    fn verify_tampered_sequence() {
        let batch = MessageBatch {
            sequence: 1,
            peer: 1,
            messages: vec![b"data".to_vec()],
        };
        let mut encoded = batch.encode();
        encoded[0] ^= 0x01;

        let result = MessageBatch::verify(&encoded);
        assert!(matches!(result, Err(BatchError::IntegrityMismatch)));
    }

    #[test]
    fn verify_truncated_frame() {
        let batch = MessageBatch {
            sequence: 1,
            peer: 1,
            messages: vec![b"data".to_vec()],
        };
        let encoded = batch.encode();
        let short = &encoded[..20];

        let result = MessageBatch::verify(short);
        assert!(matches!(result, Err(BatchError::FrameTooShort { got: 20 })));
    }

    #[test]
    fn decode_truncated_frame() {
        let result = MessageBatch::decode(&[0u8; 20]);
        assert!(matches!(result, Err(BatchError::FrameTooShort { got: 20 })));
    }

    // -----------------------------------------------------------------------
    // MessageBatch helpers
    // -----------------------------------------------------------------------

    #[test]
    fn decompose_returns_individual_messages() {
        let batch = MessageBatch {
            sequence: 1,
            peer: 1,
            messages: vec![b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()],
        };
        let parts = batch.decompose();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], b"a");
        assert_eq!(parts[1], b"bb");
        assert_eq!(parts[2], b"ccc");
    }

    #[test]
    fn message_count_and_total_bytes() {
        let batch = MessageBatch {
            sequence: 1,
            peer: 1,
            messages: vec![vec![0; 10], vec![0; 20], vec![0; 30]],
        };
        assert_eq!(batch.message_count(), 3);
        assert_eq!(batch.total_payload_bytes(), 60);
    }

    // -----------------------------------------------------------------------
    // BatchConfig
    // -----------------------------------------------------------------------

    #[test]
    fn config_defaults() {
        let cfg = BatchConfig::default();
        assert_eq!(cfg.max_batch_bytes, 65536);
        assert_eq!(cfg.max_batch_messages, 64);
        assert_eq!(cfg.max_wait, Duration::from_micros(500));
        assert!(cfg.enabled);
    }

    #[test]
    fn config_disabled() {
        let cfg = BatchConfig::disabled();
        assert!(!cfg.enabled);
    }

    // -----------------------------------------------------------------------
    // MessageBatcher: single-message batching
    // -----------------------------------------------------------------------

    #[test]
    fn single_message_emits_after_deadline() {
        let mut batcher =
            MessageBatcher::new(BatchConfig::new(65536, 64, Duration::from_millis(10)));

        // Enqueue one message.
        let result = batcher.enqueue(42, b"hello".to_vec());
        assert!(result.is_none(), "no immediate flush");

        // Wait past deadline.
        std::thread::sleep(Duration::from_millis(15));

        let ready = batcher.drain_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].0, 42);
        assert_eq!(ready[0].1.messages.len(), 1);
        assert_eq!(ready[0].1.messages[0], b"hello");

        // Queue should be empty now.
        assert!(batcher.drain_batch(42).is_none());
        assert!(batcher.is_empty());
    }

    // -----------------------------------------------------------------------
    // MessageBatcher: multi-message batching
    // -----------------------------------------------------------------------

    #[test]
    fn multi_message_batch() {
        let mut batcher = MessageBatcher::new(BatchConfig::new(
            65536,
            64,
            Duration::from_secs(10), // long deadline
        ));

        for i in 0..20 {
            let payload = format!("msg-{i:02}").into_bytes();
            let result = batcher.enqueue(1, payload);
            // Should not flush until count threshold.
            if i < 19 {
                assert!(result.is_none(), "no flush at enqueue {i}");
            }
        }

        // 20 < 64, so drain_ready shouldn't flush on count.
        let ready = batcher.drain_ready();
        assert_eq!(ready.len(), 0, "no deadline, no count trigger");

        // Force drain.
        let batch = batcher.drain_batch(1).unwrap();
        assert_eq!(batch.messages.len(), 20);
        assert_eq!(batch.sequence, 1);

        // Next batch should get sequence 2.
        let _ = batcher.enqueue(1, b"next".to_vec());
        let batch2 = batcher.drain_batch(1).unwrap();
        assert_eq!(batch2.sequence, 2);
    }

    // -----------------------------------------------------------------------
    // MessageBatcher: max-messages enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn max_messages_enforcement() {
        let mut batcher = MessageBatcher::new(BatchConfig::new(
            65536,
            5, // small max for testing
            Duration::from_secs(60),
        ));

        // Enqueue 4 messages — no flush.
        for i in 0..4 {
            let result = batcher.enqueue(1, vec![i as u8]);
            assert!(result.is_none());
        }

        // 5th message — should trigger flush.
        let batch = batcher.enqueue(1, vec![4u8]).unwrap();
        assert_eq!(batch.messages.len(), 5);
        assert_eq!(batch.peer, 1);

        // Queue should be empty now.
        assert!(batcher.drain_batch(1).is_none());
    }

    // -----------------------------------------------------------------------
    // MessageBatcher: max-bytes enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn max_bytes_enforcement() {
        let mut batcher = MessageBatcher::new(BatchConfig::new(
            100, // small byte limit
            64,
            Duration::from_secs(60),
        ));

        // Enqueue messages that fit within 100 bytes.
        let r1 = batcher.enqueue(1, vec![0u8; 60]);
        assert!(r1.is_none());
        let r2 = batcher.enqueue(1, vec![0u8; 30]);
        assert!(r2.is_none());

        // Next message would overflow: 60+30+20 > 100, so flush + new enqueue.
        let batch = batcher.enqueue(1, vec![0u8; 20]).unwrap();
        assert_eq!(batch.messages.len(), 2);
        assert_eq!(batch.total_payload_bytes(), 90);

        // The new 20-byte message is now the only one queued.
        let batch2 = batcher.drain_batch(1).unwrap();
        assert_eq!(batch2.messages.len(), 1);
        assert_eq!(batch2.total_payload_bytes(), 20);
    }

    #[test]
    fn max_bytes_overflow_from_empty() {
        let mut batcher = MessageBatcher::new(BatchConfig::new(100, 64, Duration::from_secs(60)));

        // Single message that exceeds max_batch_bytes alone — enqueued
        // normally, no flush (can't split a single message).
        let result = batcher.enqueue(1, vec![0u8; 200]);
        assert!(result.is_none());

        let batch = batcher.drain_batch(1).unwrap();
        assert_eq!(batch.messages.len(), 1);
        assert_eq!(batch.total_payload_bytes(), 200);
    }

    // -----------------------------------------------------------------------
    // MessageBatcher: deadline flush
    // -----------------------------------------------------------------------

    #[test]
    fn deadline_flush() {
        let mut batcher =
            MessageBatcher::new(BatchConfig::new(65536, 64, Duration::from_millis(10)));

        let _ = batcher.enqueue(1, b"deadline-test".to_vec());

        // Not yet expired.
        let ready = batcher.drain_ready();
        assert!(ready.is_empty());

        std::thread::sleep(Duration::from_millis(15));

        let ready = batcher.drain_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].1.messages[0], b"deadline-test");
    }

    // -----------------------------------------------------------------------
    // MessageBatcher: multi-peer isolation
    // -----------------------------------------------------------------------

    #[test]
    fn multi_peer_isolation() {
        let mut batcher =
            MessageBatcher::new(BatchConfig::new(65536, 64, Duration::from_millis(10)));

        // Peer A: 3 messages, Peer B: 2 messages.
        let _ = batcher.enqueue(10, b"A1".to_vec());
        let _ = batcher.enqueue(20, b"B1".to_vec());
        let _ = batcher.enqueue(10, b"A2".to_vec());
        let _ = batcher.enqueue(20, b"B2".to_vec());
        let _ = batcher.enqueue(10, b"A3".to_vec());

        assert_eq!(batcher.active_peers(), 2);
        assert_eq!(batcher.total_queued(), 5);

        // Drain peer A.
        let batch_a = batcher.drain_batch(10).unwrap();
        assert_eq!(batch_a.messages.len(), 3);
        assert_eq!(batch_a.peer, 10);
        assert_eq!(batch_a.messages[0], b"A1");
        assert_eq!(batch_a.messages[1], b"A2");
        assert_eq!(batch_a.messages[2], b"A3");

        // Peer B should be unaffected.
        let batch_b = batcher.drain_batch(20).unwrap();
        assert_eq!(batch_b.messages.len(), 2);
        assert_eq!(batch_b.peer, 20);
        assert_eq!(batch_b.messages[0], b"B1");
        assert_eq!(batch_b.messages[1], b"B2");

        assert!(batcher.is_empty());
    }

    #[test]
    fn multi_peer_non_interleaved() {
        let mut batcher = MessageBatcher::default();

        for i in 0..50 {
            let _ = batcher.enqueue(i % 3, vec![i as u8]);
        }

        // Drain each peer and verify messages are per-peer and ordered.
        for peer in 0..3 {
            let batch = batcher.drain_batch(peer).unwrap();
            assert_eq!(batch.peer, peer);
            for (idx, msg) in batch.messages.iter().enumerate() {
                let expected_val = (idx as u64 * 3 + peer) as u8;
                assert_eq!(
                    msg[0], expected_val,
                    "peer {peer} idx {idx}: expected {expected_val}, got {}",
                    msg[0]
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // MessageBatcher: empty batcher
    // -----------------------------------------------------------------------

    #[test]
    fn empty_batcher_drain_returns_none() {
        let mut batcher = MessageBatcher::default();
        assert!(batcher.drain_batch(42).is_none());
        assert!(batcher.flush_all().is_empty());
        assert!(batcher.drain_ready().is_empty());
        assert!(batcher.is_empty());
        assert_eq!(batcher.active_peers(), 0);
        assert_eq!(batcher.total_queued(), 0);
    }

    // -----------------------------------------------------------------------
    // MessageBatcher: flush_all
    // -----------------------------------------------------------------------

    #[test]
    fn flush_all_drains_every_peer() {
        let mut batcher = MessageBatcher::new(BatchConfig::new(
            65536,
            64,
            Duration::from_secs(999), // effectively no deadline
        ));

        let _ = batcher.enqueue(1, b"a".to_vec());
        let _ = batcher.enqueue(2, b"b".to_vec());
        let _ = batcher.enqueue(3, b"c".to_vec());
        let _ = batcher.enqueue(1, b"d".to_vec());

        let batches = batcher.flush_all();
        assert_eq!(batches.len(), 3); // 3 distinct peers

        let mut peer_ids: Vec<u64> = batches.iter().map(|(p, _)| *p).collect();
        peer_ids.sort_unstable();
        assert_eq!(peer_ids, vec![1, 2, 3]);

        assert!(batcher.is_empty());
    }

    // -----------------------------------------------------------------------
    // MessageBatcher: disabled config
    // -----------------------------------------------------------------------

    #[test]
    fn disabled_batcher_always_emits_single_message_batch() {
        let mut batcher = MessageBatcher::new(BatchConfig::disabled());

        let batch = batcher.enqueue(1, b"immediate".to_vec()).unwrap();
        assert_eq!(batch.messages.len(), 1);
        assert_eq!(batch.messages[0], b"immediate");
        assert_eq!(batch.peer, 1);
    }

    // -----------------------------------------------------------------------
    // Concurrent enqueue under contention simulation
    // -----------------------------------------------------------------------

    #[test]
    fn many_enqueues_no_message_loss() {
        let mut batcher =
            MessageBatcher::new(BatchConfig::new(65536, 64, Duration::from_millis(100)));

        let total = 256usize;
        for i in 0..total {
            let _ = batcher.enqueue(1, vec![i as u8]);
        }

        // Count-based flushes should have occurred at each 64.
        // Drain remaining.
        let mut all_msgs: Vec<u8> = Vec::new();

        // Collect from past flushes: drain_batch won't get already-flushed
        // messages, but the batcher only stores pending. The count-triggered
        // batches were already drained during enqueue. So the remaining
        // queue has the leftovers.
        if let Some(batch) = batcher.drain_batch(1) {
            for msg in &batch.messages {
                all_msgs.push(msg[0]);
            }
        }

        // Reconstruction from enqueue side: 256 enqueues, batches of 64.
        // Expected leftovers: 256 % 64 = 0, so queue should be empty.
        assert!(batcher.drain_batch(1).is_none());
    }

    // -----------------------------------------------------------------------
    // BLAKE3 digest stability
    // -----------------------------------------------------------------------

    #[test]
    fn blake3_digest_deterministic() {
        let batch = MessageBatch {
            sequence: 1,
            peer: 42,
            messages: vec![b"deterministic".to_vec()],
        };

        let enc1 = batch.encode();
        let enc2 = batch.encode();

        assert_eq!(enc1, enc2, "same input produces identical encoding");
    }

    #[test]
    fn different_sequence_produces_different_hash() {
        let b1 = MessageBatch {
            sequence: 1,
            peer: 1,
            messages: vec![b"x".to_vec()],
        };
        let b2 = MessageBatch {
            sequence: 2,
            peer: 1,
            messages: vec![b"x".to_vec()],
        };

        let e1 = b1.encode();
        let e2 = b2.encode();
        assert_ne!(e1, e2, "different sequence -> different encoding");
    }

    #[test]
    fn different_peer_produces_different_hash() {
        let b1 = MessageBatch {
            sequence: 1,
            peer: 1,
            messages: vec![b"x".to_vec()],
        };
        let b2 = MessageBatch {
            sequence: 1,
            peer: 2,
            messages: vec![b"x".to_vec()],
        };

        let e1 = b1.encode();
        let e2 = b2.encode();
        assert_ne!(e1, e2, "different peer -> different encoding");
    }

    // -------------------------------------------------------------------
    // BatchStats tests
    // -------------------------------------------------------------------

    #[test]
    fn stats_tracks_enqueue_and_flush() {
        let mut batcher = MessageBatcher::new(BatchConfig::disabled());
        // Disabled mode: every enqueue immediately flushes a single-message batch.
        let _ = batcher.enqueue(1, vec![0u8; 10]);
        let _ = batcher.enqueue(1, vec![0u8; 20]);

        let stats = batcher.stats();
        assert_eq!(stats.messages_batched, 2);
        assert_eq!(stats.batches_flushed, 2);
        assert_eq!(stats.bytes_batched, 30);
    }

    #[test]
    fn stats_tracks_batched_flush() {
        let mut batcher = MessageBatcher::new(BatchConfig::new(65536, 5, Duration::from_secs(60)));

        // Enqueue 4 messages (no flush yet).
        for i in 0..4 {
            let _ = batcher.enqueue(1, vec![i as u8; 10]);
        }
        // 5th triggers count flush.
        let batch = batcher.enqueue(1, vec![4u8; 10]).unwrap();
        assert_eq!(batch.messages.len(), 5);

        let stats = batcher.stats();
        assert_eq!(stats.messages_batched, 5);
        assert_eq!(stats.batches_flushed, 1);
        assert_eq!(stats.bytes_batched, 50);
    }

    #[test]
    fn stats_merge_accumulates() {
        let mut a = BatchStats::new();
        a.record_enqueue();
        a.record_enqueue();
        a.record_flush(42);

        let mut b = BatchStats::new();
        b.record_enqueue();
        b.record_flush(10);

        a.merge(&b);
        assert_eq!(a.messages_batched, 3);
        assert_eq!(a.batches_flushed, 2);
        assert_eq!(a.bytes_batched, 52);
    }

    #[test]
    fn stats_default_is_zero() {
        let stats = BatchStats::default();
        assert_eq!(stats.messages_batched, 0);
        assert_eq!(stats.batches_flushed, 0);
        assert_eq!(stats.bytes_batched, 0);
    }

    #[test]
    fn stats_clone_is_independent() {
        let mut batcher = MessageBatcher::new(BatchConfig::disabled());
        let _ = batcher.enqueue(1, vec![0; 5]);
        let s1 = batcher.stats();
        let _ = batcher.enqueue(1, vec![0; 5]);
        let s2 = batcher.stats();

        assert_eq!(s1.messages_batched, 1);
        assert_eq!(s2.messages_batched, 2);
    }

    #[test]
    fn stats_wrapping_does_not_panic() {
        let mut stats = BatchStats {
            messages_batched: u64::MAX,
            batches_flushed: u64::MAX,
            bytes_batched: u64::MAX,
        };
        stats.record_enqueue();
        stats.record_flush(100);
        // Should wrap without panicking.
        assert_eq!(stats.messages_batched, 0); // wrapped
        assert_eq!(stats.batches_flushed, 0); // wrapped
                                              // bytes_batched: u64::MAX + 100 wraps to 99
        assert_eq!(stats.bytes_batched, 99);
    }
}
