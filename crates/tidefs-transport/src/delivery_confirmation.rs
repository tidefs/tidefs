// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport message delivery confirmation with per-peer sequence
//! acknowledgment, send-completion notification, and domain-separated
//! acknowledgment-frame integrity via BLAKE3.
//!
//! ## Purpose
//!
//! Provides a generic reliability primitive: any sending subsystem can
//! request delivery confirmation for a specific message and receive
//! notification when the peer's transport layer acknowledges receipt.
//! This is the foundation that intent-log replication, membership
//! proposals, lease operations, and chunk transfers rely on to know
//! their messages are safely delivered.
//!
//! ## Architecture
//!
//! ```text
//! Sender                                        Receiver
//!   |                                              |
//!   +-- register(delivery_seq) -> Receiver<Outcome> |
//!   +-- send(message with delivery_seq in envelope) |
//!   |                                              |
//!   |         ---- message delivered ----          |
//!   |                                              |
//!   |         <--- AcknowledgmentFrame --------    |
//!   |                                              |
//!   +-- record_ack(delivery_seq) -> Delivered      |
//!   +-- resolve Receiver<Outcome> with Delivered   |
//! ```
//!
//! ## Wire format
//!
//! The AcknowledgmentFrame is a fixed-size frame:
//!
//! ```text
//! [0..4)    magic       u32 LE ("VDAC" = 0x43414456)
//! [4..36)   peer_id     [u8; 32]  sender peer identity (BLAKE3 node hash)
//! [36..44)  ack_seq     u64 LE    acknowledged delivery sequence number
//! [44..76)  digest      [u8; 32]  BLAKE3-256 domain-separated hash
//! ```
//!
//! Total frame size: 76 bytes.
//!
//! ## BLAKE3 domain separation
//!
//! Acknowledgment frames use domain `tidefs-transport-delivery-ack-v1`
//! in family `VDAC` (0x56444143) to prevent cross-type replay. The
//! digest covers the 44-byte prefix (magic + peer_id + ack_seq).
//!
//! ## DeliveryTracker
//!
//! Per-peer `HashMap<DeliverySequence, oneshot::Sender<DeliveryOutcome>>`
//! mapping pending sequence numbers to completion channels. Supports:
//! - `register(seq)` → `oneshot::Receiver<DeliveryOutcome>`
//! - `record_ack(seq)` → resolves to `Delivered`
//! - `timeout_pending(duration)` → resolves expired entries to `TimedOut`
//! - concurrent registrations from multiple sender threads
//!
//! ## DeliveryConfirmationEngine
//!
//! - **Send side**: callers opt in by calling `register()` and embedding
//!   the returned `DeliverySequence` in the message envelope flags.
//! - **Receive side**: after message dispatch completes, the engine
//!   constructs and sends an `AcknowledgmentFrame` back to the sender.
//! - **Ack processing**: inbound `AcknowledgmentFrame` values are routed
//!   to the `DeliveryTracker` via `record_ack()`, resolving the
//!   corresponding oneshot channels.
//!
//! ## Integration points
//!
//! - Sent through the message envelope flags extension (delivery_seq
//!   presence signals the receiver to emit an acknowledgment).
//! - Received ack frames are identified by the `VDAC` magic and routed
//!   to `DeliveryConfirmationEngine::process_inbound_ack()`.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use tidefs_binary_schema_checksum::{blake3_domain_digest, blake3_domain_verify};
use tidefs_binary_schema_core::{
    BinarySchemaError, DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion,
};

use crate::epoch_fence::CommittedEpochSnapshot;

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------

/// Magic bytes for delivery acknowledgment frames: "VDAC".
pub const DELIVERY_ACK_MAGIC: [u8; 4] = [b'V', b'D', b'A', b'C'];

/// Total size of an acknowledgment frame:
/// magic (4) + peer_id (32) + ack_seq (8) + digest (32) = 76 bytes.
pub const ACK_FRAME_SIZE: usize = 76;

/// Size of the plaintext prefix covered by the BLAKE3 digest.
const ACK_PREFIX_SIZE: usize = 44; // magic(4) + peer_id(32) + ack_seq(8)

// ---------------------------------------------------------------------------
// Domain-separation constants
// ---------------------------------------------------------------------------

/// Schema family for delivery acknowledgment.
const ACK_FAMILY: SchemaFamilyId = SchemaFamilyId(0x5644_4143); // "VDAC"

/// Schema type for acknowledgment frame.
const ACK_TYPE: SchemaTypeId = SchemaTypeId(1);

/// Schema version for acknowledgment v1.0.
const ACK_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Domain tag for delivery acknowledgment digest.
const ACK_DOMAIN_TAG: DomainTag = DomainTag::TransferStream;

/// Domain context string for keyed BLAKE3 hashing.
const ACK_DOMAIN: &str = "tidefs-transport-delivery-ack-v1";

// ---------------------------------------------------------------------------
// DeliverySequence
// ---------------------------------------------------------------------------

/// Monotonic per-peer message sequence number assigned by the sender at
/// enqueue time and carried in the message envelope flags extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeliverySequence(pub u64);

impl DeliverySequence {
    /// Create a new delivery sequence from a raw u64.
    pub fn new(seq: u64) -> Self {
        Self(seq)
    }
}

impl fmt::Display for DeliverySequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeliverySequence({})", self.0)
    }
}

// ---------------------------------------------------------------------------
// DeliveryOutcome
// ---------------------------------------------------------------------------

/// The result of a delivery confirmation wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// The peer acknowledged receipt of the message.
    Delivered,
    /// The acknowledgment did not arrive within the configured timeout.
    TimedOut,
    /// The delivery tracker was dropped before the outcome resolved.
    Cancelled,
}

impl fmt::Display for DeliveryOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeliveryOutcome::Delivered => write!(f, "Delivered"),
            DeliveryOutcome::TimedOut => write!(f, "TimedOut"),
            DeliveryOutcome::Cancelled => write!(f, "Cancelled"),
        }
    }
}

// ---------------------------------------------------------------------------
// AcknowledgmentFrame
// ---------------------------------------------------------------------------

/// Wire type for receiver-to-sender acknowledgment.
///
/// Frame layout:
/// ```text
/// [0..4)    magic       u32 LE
/// [4..36)   peer_id     [u8; 32]
/// [36..44)  ack_seq     u64 LE
/// [44..76)  digest      [u8; 32] BLAKE3-256
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcknowledgmentFrame {
    /// 32-byte peer identifier (BLAKE3 hash of node identity).
    pub peer_id: [u8; 32],
    /// The delivery sequence number being acknowledged.
    pub ack_seq: u64,
}

impl AcknowledgmentFrame {
    /// Create a new acknowledgment frame targeting a specific peer and
    /// sequence number. The digest is computed via `encode()`.
    pub fn new(peer_id: [u8; 32], ack_seq: u64) -> Self {
        Self { peer_id, ack_seq }
    }

    /// Encode the frame into a 76-byte buffer.
    ///
    /// The BLAKE3-256 digest covers the 44-byte prefix (magic + peer_id +
    /// ack_seq) with domain `tidefs-transport-delivery-ack-v1`.
    pub fn encode(&self) -> [u8; ACK_FRAME_SIZE] {
        let mut buf = [0u8; ACK_FRAME_SIZE];

        // Magic
        buf[0..4].copy_from_slice(&DELIVERY_ACK_MAGIC);

        // Peer ID
        buf[4..36].copy_from_slice(&self.peer_id);

        // Ack sequence (LE)
        buf[36..44].copy_from_slice(&self.ack_seq.to_le_bytes());

        // Compute BLAKE3-256 domain-separated digest over the prefix
        let digest = blake3_domain_digest(
            &buf[..ACK_PREFIX_SIZE],
            ACK_FAMILY,
            ACK_TYPE,
            ACK_VERSION,
            ACK_DOMAIN_TAG,
        );
        buf[44..76].copy_from_slice(&digest);

        buf
    }

    /// Decode a frame from a 76-byte buffer.
    ///
    /// Returns `None` if the magic does not match or the BLAKE3 digest
    /// verification fails (tampered or corrupt frame).
    pub fn decode(buf: &[u8; ACK_FRAME_SIZE]) -> Option<Self> {
        // Check magic
        if buf[0..4] != DELIVERY_ACK_MAGIC {
            return None;
        }

        // Verify BLAKE3 digest
        let digest_bytes: [u8; 32] = match buf[44..76].try_into() {
            Ok(d) => d,
            Err(_) => return None,
        };
        if blake3_domain_verify(
            &buf[..ACK_PREFIX_SIZE],
            &digest_bytes,
            ACK_FAMILY,
            ACK_TYPE,
            ACK_VERSION,
            ACK_DOMAIN_TAG,
        )
        .is_err()
        {
            return None;
        }

        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(&buf[4..36]);

        let ack_seq = u64::from_le_bytes(buf[36..44].try_into().unwrap());

        Some(Self { peer_id, ack_seq })
    }

    /// Verify the frame's BLAKE3-256 digest against the payload.
    ///
    /// Returns `Ok(())` if the digest matches, `Err(BinarySchemaError)` otherwise.
    pub fn verify_full(&self, encoded: &[u8; ACK_FRAME_SIZE]) -> Result<(), BinarySchemaError> {
        if encoded[0..4] != DELIVERY_ACK_MAGIC {
            return Err(BinarySchemaError::ChecksumMismatch);
        }

        let digest_bytes: [u8; 32] = encoded[44..76]
            .try_into()
            .map_err(|_| BinarySchemaError::DigestMismatch)?;

        blake3_domain_verify(
            &encoded[..ACK_PREFIX_SIZE],
            &digest_bytes,
            ACK_FAMILY,
            ACK_TYPE,
            ACK_VERSION,
            ACK_DOMAIN_TAG,
        )
    }

    /// Returns the domain context string for this acknowledgment frame type.
    pub fn domain() -> &'static str {
        ACK_DOMAIN
    }

    /// Returns the total wire size of an acknowledgment frame.
    pub fn wire_size() -> usize {
        ACK_FRAME_SIZE
    }
}

// ---------------------------------------------------------------------------
// DeliveryTracker
// ---------------------------------------------------------------------------

/// Per-peer tracker on the sender side mapping pending delivery sequence
/// numbers to completion channels.
///
/// Supports concurrent registrations from multiple sender threads through
/// interior mutability (`Mutex<HashMap<...>>`).
#[derive(Debug)]
pub struct DeliveryTracker {
    /// Pending delivery confirmations keyed by sequence number.
    pending: Mutex<HashMap<DeliverySequence, PendingEntry>>,
}

#[derive(Debug)]
struct PendingEntry {
    /// Channel to signal delivery outcome.
    sender: oneshot::Sender<DeliveryOutcome>,
    /// When this entry was registered (for timeout tracking).
    registered_at: Instant,
}

impl DeliveryTracker {
    /// Create a new empty delivery tracker.
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Register a delivery sequence for acknowledgment tracking.
    ///
    /// Returns a `oneshot::Receiver` that will resolve when the peer
    /// acknowledges this sequence (`Delivered`) or when the entry times
    /// out (`TimedOut`).
    ///
    /// If the sequence is already registered, the previous entry is
    /// cancelled (`Cancelled`) and replaced.
    pub fn register(&self, seq: DeliverySequence) -> oneshot::Receiver<DeliveryOutcome> {
        let (tx, rx) = oneshot::channel();
        let mut pending = self.pending.lock().unwrap();

        // Cancel any previously registered entry for the same sequence
        if let Some(old) = pending.remove(&seq) {
            let _ = old.sender.send(DeliveryOutcome::Cancelled);
        }

        pending.insert(
            seq,
            PendingEntry {
                sender: tx,
                registered_at: Instant::now(),
            },
        );

        rx
    }

    /// Record an acknowledgment for a delivery sequence.
    ///
    /// Resolves the corresponding oneshot channel with `Delivered`.
    /// Returns `true` if the sequence was found and resolved, `false`
    /// if the sequence was unknown (already resolved, timed out, or
    /// never registered — this is not an error).
    pub fn record_ack(&self, seq: DeliverySequence) -> bool {
        let entry = {
            let mut pending = self.pending.lock().unwrap();
            pending.remove(&seq)
        };

        match entry {
            Some(e) => {
                let _ = e.sender.send(DeliveryOutcome::Delivered);
                true
            }
            None => false,
        }
    }

    /// Time out all pending entries older than `max_age`.
    ///
    /// Returns the sequences that were timed out. Entries resolved via
    /// `record_ack` before this call are unaffected.
    pub fn timeout_pending(&self, max_age: Duration) -> Vec<DeliverySequence> {
        let now = Instant::now();
        let mut pending = self.pending.lock().unwrap();

        let expired: Vec<DeliverySequence> = pending
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.registered_at) >= max_age)
            .map(|(&seq, _)| seq)
            .collect();

        let mut timed_out = Vec::new();
        for seq in &expired {
            if let Some(entry) = pending.remove(seq) {
                let _ = entry.sender.send(DeliveryOutcome::TimedOut);
                timed_out.push(*seq);
            }
        }

        timed_out
    }

    /// Cancel all pending entries (e.g., on session close).
    ///
    /// Returns the number of entries cancelled.
    pub fn cancel_all(&self) -> usize {
        let mut pending = self.pending.lock().unwrap();
        let count = pending.len();
        for (_, entry) in pending.drain() {
            let _ = entry.sender.send(DeliveryOutcome::Cancelled);
        }
        count
    }

    /// Return the number of currently pending delivery confirmations.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Check whether a specific sequence is pending.
    pub fn is_pending(&self, seq: DeliverySequence) -> bool {
        self.pending.lock().unwrap().contains_key(&seq)
    }
}

impl Default for DeliveryTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DeliveryConfirmationEngine
// ---------------------------------------------------------------------------

/// Engine that wires delivery confirmation into the transport send and
/// receive paths.
///
/// ## Send side
///
/// Callers register a delivery sequence via `register()` on a per-peer
/// `DeliveryTracker`. The returned `DeliverySequence` is embedded in the
/// message envelope to signal the receiver that an acknowledgment is
/// expected.
///
/// ## Receive side
///
/// After message dispatch completes, the engine is asked to
/// `build_ack_frame()` if the message carried a delivery sequence. The
/// caller is responsible for transmitting the resulting frame back to
/// the sender.
///
/// ## Inbound ack processing
///
/// `process_inbound_ack()` routes received acknowledgment frames to the
/// correct `DeliveryTracker` and resolves the pending entry.
#[derive(Debug)]
pub struct DeliveryConfirmationEngine {
    /// Per-peer delivery trackers, keyed by peer_id bytes.
    trackers: Mutex<HashMap<[u8; 32], Arc<DeliveryTracker>>>,
}

/// Reasons a delivery confirmation was rejected by committed membership
/// evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryConfirmationAdmissionError {
    /// No committed members are available for this epoch.
    EmptyRoster { epoch: u64 },
    /// The peer is not in the committed member set.
    PeerNotInRoster { peer_id: u64, epoch: u64 },
}

impl std::fmt::Display for DeliveryConfirmationAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyRoster { epoch } => {
                write!(f, "delivery confirmation roster empty at epoch {epoch}")
            }
            Self::PeerNotInRoster { peer_id, epoch } => write!(
                f,
                "delivery confirmation peer {peer_id} not in committed roster at epoch {epoch}"
            ),
        }
    }
}

impl std::error::Error for DeliveryConfirmationAdmissionError {}

impl DeliveryConfirmationEngine {
    /// Create a new delivery confirmation engine.
    pub fn new() -> Self {
        Self {
            trackers: Mutex::new(HashMap::new()),
        }
    }

    /// Get or create a `DeliveryTracker` for the given peer.
    ///
    /// Returns an `Arc<DeliveryTracker>` that can be shared across
    /// sender threads.
    pub fn get_or_create_tracker(&self, peer_id: [u8; 32]) -> Arc<DeliveryTracker> {
        let mut trackers = self.trackers.lock().unwrap();
        trackers
            .entry(peer_id)
            .or_insert_with(|| Arc::new(DeliveryTracker::new()))
            .clone()
    }

    /// Build an acknowledgment frame for a successfully dispatched message.
    ///
    /// `receiver_peer_id` is the identity of the node building the ack
    /// (i.e., the receiver sending the acknowledgment back).
    ///
    /// Returns `None` if `delivery_seq` is zero (no confirmation requested).
    pub fn build_ack_frame(
        &self,
        receiver_peer_id: [u8; 32],
        delivery_seq: DeliverySequence,
    ) -> Option<AcknowledgmentFrame> {
        if delivery_seq.0 == 0 {
            return None; // sequence 0 means no confirmation requested
        }
        Some(AcknowledgmentFrame::new(receiver_peer_id, delivery_seq.0))
    }

    /// Build an acknowledgment frame only if the receiver node is still in
    /// the committed member set.
    ///
    /// This keeps delivery confirmations on the same membership-driven epoch
    /// evidence as reconnect admission.
    pub fn build_ack_frame_with_evidence(
        &self,
        receiver_peer_id: [u8; 32],
        receiver_node_id: u64,
        delivery_seq: DeliverySequence,
        evidence: &CommittedEpochSnapshot,
    ) -> Result<Option<AcknowledgmentFrame>, DeliveryConfirmationAdmissionError> {
        Self::check_peer_evidence(receiver_node_id, evidence)?;
        Ok(self.build_ack_frame(receiver_peer_id, delivery_seq))
    }

    /// Process an inbound acknowledgment frame.
    ///
    /// Looks up the tracker for the peer that sent the ack and resolves
    /// the pending entry for the acknowledged sequence.
    ///
    /// Returns `true` if the acknowledgment was successfully processed
    /// (the sequence was found and resolved), `false` if the peer has no
    /// tracker or the sequence was not pending.
    pub fn process_inbound_ack(&self, frame: &AcknowledgmentFrame) -> bool {
        let tracker = {
            let trackers = self.trackers.lock().unwrap();
            trackers.get(&frame.peer_id).cloned()
        };

        match tracker {
            Some(t) => t.record_ack(DeliverySequence(frame.ack_seq)),
            None => false,
        }
    }

    /// Process an inbound acknowledgment only if the sending peer is in the
    /// committed member set.
    pub fn process_inbound_ack_with_evidence(
        &self,
        frame: &AcknowledgmentFrame,
        ack_peer_node_id: u64,
        evidence: &CommittedEpochSnapshot,
    ) -> Result<bool, DeliveryConfirmationAdmissionError> {
        Self::check_peer_evidence(ack_peer_node_id, evidence)?;
        Ok(self.process_inbound_ack(frame))
    }

    fn check_peer_evidence(
        peer_node_id: u64,
        evidence: &CommittedEpochSnapshot,
    ) -> Result<(), DeliveryConfirmationAdmissionError> {
        if evidence.roster.is_empty() {
            return Err(DeliveryConfirmationAdmissionError::EmptyRoster {
                epoch: evidence.epoch,
            });
        }
        if !evidence.contains(peer_node_id) {
            return Err(DeliveryConfirmationAdmissionError::PeerNotInRoster {
                peer_id: peer_node_id,
                epoch: evidence.epoch,
            });
        }
        Ok(())
    }

    /// Remove and cancel all trackers for a specific peer (e.g., on
    /// session close or peer departure).
    ///
    /// Returns the number of pending entries cancelled.
    pub fn remove_peer(&self, peer_id: &[u8; 32]) -> usize {
        let tracker = {
            let mut trackers = self.trackers.lock().unwrap();
            trackers.remove(peer_id)
        };

        match tracker {
            Some(t) => t.cancel_all(),
            None => 0,
        }
    }

    /// Return the number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.trackers.lock().unwrap().len()
    }
}

impl Default for DeliveryConfirmationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    // -----------------------------------------------------------------------
    // AcknowledgmentFrame tests
    // -----------------------------------------------------------------------

    #[test]
    fn ack_frame_encode_decode_roundtrip() {
        let peer_id = {
            let mut h = [0u8; 32];
            h[0..8].copy_from_slice(&42u64.to_le_bytes());
            h
        };
        let frame = AcknowledgmentFrame::new(peer_id, 7);
        let encoded = frame.encode();
        let decoded = AcknowledgmentFrame::decode(&encoded);
        assert!(decoded.is_some());
        let decoded = decoded.unwrap();
        assert_eq!(decoded.peer_id, peer_id);
        assert_eq!(decoded.ack_seq, 7);
    }

    #[test]
    fn ack_frame_tamper_detection() {
        let peer_id = [0xAAu8; 32];
        let frame = AcknowledgmentFrame::new(peer_id, 42);
        let mut encoded = frame.encode();

        // Flip a byte in the payload (not the digest)
        encoded[20] ^= 0xFF;

        let decoded = AcknowledgmentFrame::decode(&encoded);
        assert!(decoded.is_none(), "tampered frame should be rejected");
    }

    #[test]
    fn ack_frame_wrong_magic_rejected() {
        let peer_id = [0xBBu8; 32];
        let mut encoded = AcknowledgmentFrame::new(peer_id, 1).encode();
        encoded[0] = 0x00; // corrupt magic

        let decoded = AcknowledgmentFrame::decode(&encoded);
        assert!(decoded.is_none());
    }

    #[test]
    fn ack_frame_digest_tamper_rejected() {
        let peer_id = [0xCCu8; 32];
        let mut encoded = AcknowledgmentFrame::new(peer_id, 99).encode();
        encoded[60] ^= 0x01; // flip a bit in the digest

        let decoded = AcknowledgmentFrame::decode(&encoded);
        assert!(decoded.is_none());
    }

    #[test]
    fn ack_frame_verify_full_ok() {
        let peer_id = [0x11u8; 32];
        let frame = AcknowledgmentFrame::new(peer_id, 5);
        let encoded = frame.encode();
        assert!(frame.verify_full(&encoded).is_ok());
    }

    #[test]
    fn ack_frame_verify_full_mismatch() {
        let peer_id = [0x11u8; 32];
        let frame = AcknowledgmentFrame::new(peer_id, 5);
        let mut encoded = frame.encode();
        encoded[10] ^= 0x01;
        assert!(frame.verify_full(&encoded).is_err());
    }

    #[test]
    fn ack_frame_sequence_zero_encodes() {
        let peer_id = [0x00u8; 32];
        let frame = AcknowledgmentFrame::new(peer_id, 0);
        let encoded = frame.encode();
        let decoded = AcknowledgmentFrame::decode(&encoded);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap().ack_seq, 0);
    }

    // -----------------------------------------------------------------------
    // DeliveryTracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn tracker_register_and_ack() {
        let tracker = DeliveryTracker::new();
        let seq = DeliverySequence(1);

        let mut rx = tracker.register(seq);
        assert_eq!(tracker.pending_count(), 1);

        // Should not be resolved yet
        assert!(rx.try_recv().is_err());

        // Ack the sequence
        assert!(tracker.record_ack(seq));
        assert_eq!(tracker.pending_count(), 0);

        // Now resolved
        match rx.try_recv().unwrap() {
            DeliveryOutcome::Delivered => {}
            other => panic!("expected Delivered, got {other:?}"),
        }
    }

    #[test]
    fn tracker_register_timeout() {
        let tracker = DeliveryTracker::new();
        let seq = DeliverySequence(2);

        let mut rx = tracker.register(seq);
        assert_eq!(tracker.pending_count(), 1);

        // Timeout with zero duration — should expire immediately
        let expired = tracker.timeout_pending(Duration::ZERO);
        assert_eq!(expired, vec![seq]);
        assert_eq!(tracker.pending_count(), 0);

        match rx.try_recv().unwrap() {
            DeliveryOutcome::TimedOut => {}
            other => panic!("expected TimedOut, got {other:?}"),
        }
    }

    #[test]
    fn tracker_duplicate_ack_idempotent() {
        let tracker = DeliveryTracker::new();
        let seq = DeliverySequence(3);

        let mut rx = tracker.register(seq);
        assert!(tracker.record_ack(seq));
        // Second ack for the same (now resolved) sequence is harmless
        assert!(!tracker.record_ack(seq));

        match rx.try_recv().unwrap() {
            DeliveryOutcome::Delivered => {}
            other => panic!("expected Delivered, got {other:?}"),
        }
    }

    #[test]
    fn tracker_unknown_sequence_no_panic() {
        let tracker = DeliveryTracker::new();
        // Ack a sequence that was never registered
        assert!(!tracker.record_ack(DeliverySequence(999)));
    }

    #[test]
    fn tracker_concurrent_registrations() {
        let tracker = Arc::new(DeliveryTracker::new());
        let mut handles = Vec::new();

        for thread_id in 0..4 {
            let t = tracker.clone();
            handles.push(thread::spawn(move || {
                let seq = DeliverySequence(thread_id as u64);
                let mut rx = t.register(seq);
                // Simulate some work
                thread::sleep(Duration::from_millis(10));
                t.record_ack(seq);
                rx.try_recv().unwrap()
            }));
        }

        for h in handles {
            let outcome = h.join().unwrap();
            assert_eq!(outcome, DeliveryOutcome::Delivered);
        }

        assert_eq!(tracker.pending_count(), 0);
    }

    #[test]
    fn tracker_cancel_all() {
        let tracker = DeliveryTracker::new();
        let mut rx1 = tracker.register(DeliverySequence(1));
        let mut rx2 = tracker.register(DeliverySequence(2));
        let mut rx3 = tracker.register(DeliverySequence(3));

        assert_eq!(tracker.pending_count(), 3);
        assert_eq!(tracker.cancel_all(), 3);
        assert_eq!(tracker.pending_count(), 0);

        for rx in [&mut rx1, &mut rx2, &mut rx3] {
            match rx.try_recv().unwrap() {
                DeliveryOutcome::Cancelled => {}
                other => panic!("expected Cancelled, got {other:?}"),
            }
        }
    }

    #[test]
    fn tracker_re_register_same_seq_cancels_old() {
        let tracker = DeliveryTracker::new();
        let seq = DeliverySequence(10);

        let mut rx1 = tracker.register(seq);
        let mut rx2 = tracker.register(seq); // re-register same seq

        // First receiver gets Cancelled
        match rx1.try_recv().unwrap() {
            DeliveryOutcome::Cancelled => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }

        // Second receiver is pending
        assert!(rx2.try_recv().is_err());
        assert!(tracker.record_ack(seq));
        match rx2.try_recv().unwrap() {
            DeliveryOutcome::Delivered => {}
            other => panic!("expected Delivered, got {other:?}"),
        }
    }

    #[test]
    fn tracker_is_pending() {
        let tracker = DeliveryTracker::new();
        let seq = DeliverySequence(42);
        assert!(!tracker.is_pending(seq));

        let _rx = tracker.register(seq);
        assert!(tracker.is_pending(seq));

        tracker.record_ack(seq);
        assert!(!tracker.is_pending(seq));
    }

    // -----------------------------------------------------------------------
    // DeliveryConfirmationEngine tests
    // -----------------------------------------------------------------------

    #[test]
    fn engine_build_ack_frame_for_nonzero_seq() {
        let engine = DeliveryConfirmationEngine::new();
        let peer_id = [0xABu8; 32];
        let seq = DeliverySequence(5);

        let frame = engine.build_ack_frame(peer_id, seq);
        assert!(frame.is_some());
        let frame = frame.unwrap();
        assert_eq!(frame.peer_id, peer_id);
        assert_eq!(frame.ack_seq, 5);

        // Verify round-trip
        let encoded = frame.encode();
        let decoded = AcknowledgmentFrame::decode(&encoded);
        assert!(decoded.is_some());
    }

    #[test]
    fn engine_build_ack_frame_zero_seq_returns_none() {
        let engine = DeliveryConfirmationEngine::new();
        let peer_id = [0xCDu8; 32];

        let frame = engine.build_ack_frame(peer_id, DeliverySequence(0));
        assert!(frame.is_none());
    }

    #[test]
    fn engine_process_inbound_ack_resolves_tracker() {
        let engine = DeliveryConfirmationEngine::new();
        let peer_id = [0xEFu8; 32];

        let tracker = engine.get_or_create_tracker(peer_id);
        let seq = DeliverySequence(7);
        let mut rx = tracker.register(seq);

        // Build the ack frame as if from the peer
        let ack_frame = AcknowledgmentFrame::new(peer_id, seq.0);
        assert!(engine.process_inbound_ack(&ack_frame));

        match rx.try_recv().unwrap() {
            DeliveryOutcome::Delivered => {}
            other => panic!("expected Delivered, got {other:?}"),
        }
    }

    #[test]
    fn engine_process_inbound_ack_unknown_peer() {
        let engine = DeliveryConfirmationEngine::new();
        let peer_id = [0xDEu8; 32];

        let ack_frame = AcknowledgmentFrame::new(peer_id, 1);
        assert!(!engine.process_inbound_ack(&ack_frame));
    }

    #[test]
    fn engine_process_inbound_ack_unknown_seq() {
        let engine = DeliveryConfirmationEngine::new();
        let peer_id = [0xADu8; 32];

        // Create tracker for peer but no registered sequences
        let _tracker = engine.get_or_create_tracker(peer_id);
        let ack_frame = AcknowledgmentFrame::new(peer_id, 999);
        assert!(!engine.process_inbound_ack(&ack_frame));
    }

    #[test]
    fn engine_process_inbound_ack_with_evidence_resolves_member_ack() {
        let engine = DeliveryConfirmationEngine::new();
        let peer_id = [0x45u8; 32];
        let tracker = engine.get_or_create_tracker(peer_id);
        let seq = DeliverySequence(11);
        let mut rx = tracker.register(seq);
        let evidence = CommittedEpochSnapshot::new(5, [1, 2]);
        let ack_frame = AcknowledgmentFrame::new(peer_id, seq.0);

        assert_eq!(
            engine.process_inbound_ack_with_evidence(&ack_frame, 2, &evidence),
            Ok(true)
        );
        assert_eq!(rx.try_recv().unwrap(), DeliveryOutcome::Delivered);
    }

    #[test]
    fn engine_process_inbound_ack_with_evidence_rejects_departed_peer() {
        let engine = DeliveryConfirmationEngine::new();
        let peer_id = [0x46u8; 32];
        let evidence = CommittedEpochSnapshot::new(5, [1, 2]);
        let ack_frame = AcknowledgmentFrame::new(peer_id, 1);

        assert_eq!(
            engine.process_inbound_ack_with_evidence(&ack_frame, 3, &evidence),
            Err(DeliveryConfirmationAdmissionError::PeerNotInRoster {
                peer_id: 3,
                epoch: 5,
            })
        );
    }

    #[test]
    fn engine_build_ack_frame_with_evidence_rejects_empty_roster() {
        let engine = DeliveryConfirmationEngine::new();
        let evidence = CommittedEpochSnapshot::new(5, []);

        assert_eq!(
            engine.build_ack_frame_with_evidence([0x47u8; 32], 1, DeliverySequence(1), &evidence),
            Err(DeliveryConfirmationAdmissionError::EmptyRoster { epoch: 5 })
        );
    }

    #[test]
    fn engine_remove_peer_cancels_all() {
        let engine = DeliveryConfirmationEngine::new();
        let peer_id = [0xBEu8; 32];

        let tracker = engine.get_or_create_tracker(peer_id);
        let mut rx = tracker.register(DeliverySequence(1));
        assert_eq!(engine.peer_count(), 1);

        let cancelled = engine.remove_peer(&peer_id);
        assert_eq!(cancelled, 1);
        assert_eq!(engine.peer_count(), 0);

        match rx.try_recv().unwrap() {
            DeliveryOutcome::Cancelled => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }

    #[test]
    fn engine_multiple_peers_independent_trackers() {
        let engine = DeliveryConfirmationEngine::new();
        let peer_a = [0xAAu8; 32];
        let peer_b = [0xBBu8; 32];

        let tracker_a = engine.get_or_create_tracker(peer_a);
        let tracker_b = engine.get_or_create_tracker(peer_b);

        let mut rx_a = tracker_a.register(DeliverySequence(1));
        let mut rx_b = tracker_b.register(DeliverySequence(1)); // same seq, different peer

        assert_eq!(engine.peer_count(), 2);

        // Ack peer A only
        let ack_a = AcknowledgmentFrame::new(peer_a, 1);
        assert!(engine.process_inbound_ack(&ack_a));

        match rx_a.try_recv().unwrap() {
            DeliveryOutcome::Delivered => {}
            other => panic!("expected Delivered, got {other:?}"),
        }

        // Peer B still pending
        assert!(rx_b.try_recv().is_err());

        // Ack peer B
        let ack_b = AcknowledgmentFrame::new(peer_b, 1);
        assert!(engine.process_inbound_ack(&ack_b));

        match rx_b.try_recv().unwrap() {
            DeliveryOutcome::Delivered => {}
            other => panic!("expected Delivered, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Integration tests: multi-peer exchange
    // -----------------------------------------------------------------------

    #[test]
    fn integration_two_peers_exchange_with_delivery_confirmation() {
        let engine_a = DeliveryConfirmationEngine::new();
        let engine_b = DeliveryConfirmationEngine::new();
        let peer_a = [0xAAu8; 32];
        let peer_b = [0xBBu8; 32];

        // Peer A sends to B with delivery confirmation
        let tracker_a_to_b = engine_a.get_or_create_tracker(peer_b);
        let seq_1 = DeliverySequence(100);
        let mut rx_1 = tracker_a_to_b.register(seq_1);

        // Peer B "receives" and builds ack
        let ack_1 = engine_b
            .build_ack_frame(peer_b, seq_1)
            .expect("should build ack for nonzero seq");
        assert_eq!(ack_1.peer_id, peer_b);
        assert_eq!(ack_1.ack_seq, 100);

        // Wire encode/decode round-trip (simulates network transit)
        let wire = ack_1.encode();
        let decoded = AcknowledgmentFrame::decode(&wire).expect("round-trip decode should succeed");

        // Peer A processes inbound ack and resolves tracker
        assert!(engine_a.process_inbound_ack(&decoded));
        assert_eq!(rx_1.try_recv().unwrap(), DeliveryOutcome::Delivered);

        // Bidirectional: peer B sends to A with confirmation
        let tracker_b_to_a = engine_b.get_or_create_tracker(peer_a);
        let seq_2 = DeliverySequence(200);
        let mut rx_2 = tracker_b_to_a.register(seq_2);

        let ack_2 = engine_a.build_ack_frame(peer_a, seq_2).unwrap();
        let wire_2 = ack_2.encode();
        let decoded_2 = AcknowledgmentFrame::decode(&wire_2).unwrap();
        assert!(engine_b.process_inbound_ack(&decoded_2));
        assert_eq!(rx_2.try_recv().unwrap(), DeliveryOutcome::Delivered);
    }

    #[test]
    fn integration_ack_wrong_peer_does_not_resolve_wrong_tracker() {
        let engine_a = DeliveryConfirmationEngine::new();
        let _peer_a = [0x11u8; 32];
        let peer_b = [0x22u8; 32];
        let peer_c = [0x33u8; 32];

        // Peer A registers a delivery confirmation targeting peer B
        let tracker_a_to_b = engine_a.get_or_create_tracker(peer_b);
        let seq = DeliverySequence(1);
        let mut rx_b = tracker_a_to_b.register(seq);

        // An ack arrives claiming to be from peer C (different peer)
        let ack_from_c = AcknowledgmentFrame::new(peer_c, 1);
        // process_inbound_ack looks up tracker by peer_id; peer_c has no
        // tracker, so this should return false and NOT resolve peer_b's entry
        assert!(!engine_a.process_inbound_ack(&ack_from_c));
        assert!(rx_b.try_recv().is_err()); // still pending

        // Correct ack from peer B resolves it
        let ack_from_b = AcknowledgmentFrame::new(peer_b, 1);
        assert!(engine_a.process_inbound_ack(&ack_from_b));
        assert_eq!(rx_b.try_recv().unwrap(), DeliveryOutcome::Delivered);
    }

    #[test]
    fn engine_remove_unknown_peer_returns_zero() {
        let engine = DeliveryConfirmationEngine::new();
        let unknown = [0xFFu8; 32];
        assert_eq!(engine.remove_peer(&unknown), 0);
    }
}
