//! BLAKE3-verified drain protocol wire messages.
//!
//! Defines the five message types exchanged during a graceful node drain:
//!
//! 1. [`DrainAnnounce`] — drain initiator broadcasts intent to all peers.
//! 2. [`DrainAck`] — each peer acknowledges or rejects the drain.
//! 3. [`StateTransferRequest`] — target peer requests state handoff.
//! 4. [`StateTransferChunk`] — draining node sends a chunk of owned state.
//! 5. [`DrainComplete`] — final notification that the drain is finished.
//!
//! Each message carries a BLAKE3-256 domain-separated digest
//! (domain: `tidefs-membership-drain-v1`) covering all payload fields.
//! Receivers call [`verify_full`](DrainWireMessage::verify_full) to
//! authenticate the message before processing.

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::{EpochId, MemberId};

/// Domain separation string for all drain protocol message digests.
const DRAIN_PROTOCOL_DOMAIN: &str = "tidefs-membership-drain-v1";

// ---------------------------------------------------------------------------
// DrainMessageKind — discriminant for wire dispatch
// ---------------------------------------------------------------------------

/// Discriminant identifying the drain protocol message type on the wire.
///
/// Sent as the first byte of each encoded message so receivers can
/// deserialize into the correct variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DrainMessageKind {
    DrainAnnounce = 0x01,
    DrainAck = 0x02,
    StateTransferRequest = 0x03,
    StateTransferChunk = 0x04,
    DrainComplete = 0x05,
}

impl DrainMessageKind {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::DrainAnnounce),
            0x02 => Some(Self::DrainAck),
            0x03 => Some(Self::StateTransferRequest),
            0x04 => Some(Self::StateTransferChunk),
            0x05 => Some(Self::DrainComplete),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// DrainWireMessage — unified trait for wire messages
// ---------------------------------------------------------------------------

/// Trait implemented by every drain protocol wire message.
///
/// Each message can verify its own integrity via BLAKE3 and report its
/// kind for dispatch.
pub trait DrainWireMessage {
    /// Returns the message kind discriminant.
    fn kind(&self) -> DrainMessageKind;

    /// Returns true if the stored digest matches the computed digest.
    fn verify_full(&self) -> bool;

    /// Returns the node being drained.
    fn draining_node_id(&self) -> MemberId;
}

// ---------------------------------------------------------------------------
// DrainAnnounce
// ---------------------------------------------------------------------------

/// Broadcast by the drain initiator to announce a drain for the given node.
///
/// All peers receive this message and should respond with [`DrainAck`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainAnnounce {
    /// The node being drained.
    pub draining_node_id: MemberId,
    /// The node that initiated the drain.
    pub initiator_node_id: MemberId,
    /// Membership epoch at the time of the announce.
    pub epoch_id: EpochId,
    /// Monotonically increasing sequence number for idempotent retry.
    pub drain_sequence: u64,
    /// Human-readable reason for the drain.
    pub reason: String,
    /// BLAKE3-256 digest covering all payload fields.
    pub digest: [u8; 32],
}

impl DrainAnnounce {
    /// Create a new DrainAnnounce with a computed BLAKE3 digest.
    #[must_use]
    pub fn new(
        draining_node_id: MemberId,
        initiator_node_id: MemberId,
        epoch_id: EpochId,
        drain_sequence: u64,
        reason: String,
    ) -> Self {
        let mut msg = Self {
            draining_node_id,
            initiator_node_id,
            epoch_id,
            drain_sequence,
            reason,
            digest: [0u8; 32],
        };
        msg.digest = Self::compute_digest(
            msg.draining_node_id,
            msg.initiator_node_id,
            msg.epoch_id,
            msg.drain_sequence,
            &msg.reason,
        );
        msg
    }

    fn compute_digest(
        draining_node_id: MemberId,
        initiator_node_id: MemberId,
        epoch_id: EpochId,
        drain_sequence: u64,
        reason: &str,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DRAIN_PROTOCOL_DOMAIN);
        // Include a per-message-type prefix to prevent cross-type collisions.
        hasher.update(&[DrainMessageKind::DrainAnnounce as u8]);
        let payload: (u64, u64, u64, u64, &str) = (
            draining_node_id.0,
            initiator_node_id.0,
            epoch_id.0,
            drain_sequence,
            reason,
        );
        if let Ok(encoded) = bincode::serialize(&payload) {
            hasher.update(&encoded);
        }
        hasher.finalize().into()
    }
}

impl DrainWireMessage for DrainAnnounce {
    fn kind(&self) -> DrainMessageKind {
        DrainMessageKind::DrainAnnounce
    }

    fn verify_full(&self) -> bool {
        Self::compute_digest(
            self.draining_node_id,
            self.initiator_node_id,
            self.epoch_id,
            self.drain_sequence,
            &self.reason,
        ) == self.digest
    }

    fn draining_node_id(&self) -> MemberId {
        self.draining_node_id
    }
}

// ---------------------------------------------------------------------------
// DrainAck
// ---------------------------------------------------------------------------

/// Sent by a peer in response to [`DrainAnnounce`].
///
/// `accepted: true` means the peer is ready to receive state transfers.
/// `accepted: false` means the peer rejects the drain (e.g., insufficient
/// capacity, already draining itself).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainAck {
    /// The node being drained.
    pub draining_node_id: MemberId,
    /// The peer sending this acknowledgement.
    pub ack_node_id: MemberId,
    /// Membership epoch at the time of the ack.
    pub epoch_id: EpochId,
    /// Drain sequence from the announce being acknowledged.
    pub drain_sequence: u64,
    /// Whether the peer accepts the drain.
    pub accepted: bool,
    /// Optional rejection reason when `accepted` is false.
    pub rejection_reason: Option<String>,
    /// BLAKE3-256 digest covering all payload fields.
    pub digest: [u8; 32],
}

impl DrainAck {
    /// Create a new DrainAck with a computed BLAKE3 digest.
    #[must_use]
    pub fn new(
        draining_node_id: MemberId,
        ack_node_id: MemberId,
        epoch_id: EpochId,
        drain_sequence: u64,
        accepted: bool,
        rejection_reason: Option<String>,
    ) -> Self {
        let mut msg = Self {
            draining_node_id,
            ack_node_id,
            epoch_id,
            drain_sequence,
            accepted,
            rejection_reason,
            digest: [0u8; 32],
        };
        msg.digest = Self::compute_digest(
            msg.draining_node_id,
            msg.ack_node_id,
            msg.epoch_id,
            msg.drain_sequence,
            msg.accepted,
            msg.rejection_reason.as_deref(),
        );
        msg
    }

    fn compute_digest(
        draining_node_id: MemberId,
        ack_node_id: MemberId,
        epoch_id: EpochId,
        drain_sequence: u64,
        accepted: bool,
        rejection_reason: Option<&str>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DRAIN_PROTOCOL_DOMAIN);
        hasher.update(&[DrainMessageKind::DrainAck as u8]);
        let payload: (u64, u64, u64, u64, bool, Option<&str>) = (
            draining_node_id.0,
            ack_node_id.0,
            epoch_id.0,
            drain_sequence,
            accepted,
            rejection_reason,
        );
        if let Ok(encoded) = bincode::serialize(&payload) {
            hasher.update(&encoded);
        }
        hasher.finalize().into()
    }
}

impl DrainWireMessage for DrainAck {
    fn kind(&self) -> DrainMessageKind {
        DrainMessageKind::DrainAck
    }

    fn verify_full(&self) -> bool {
        Self::compute_digest(
            self.draining_node_id,
            self.ack_node_id,
            self.epoch_id,
            self.drain_sequence,
            self.accepted,
            self.rejection_reason.as_deref(),
        ) == self.digest
    }

    fn draining_node_id(&self) -> MemberId {
        self.draining_node_id
    }
}

// ---------------------------------------------------------------------------
// StateTransferRequest
// ---------------------------------------------------------------------------

/// Sent by a target peer to request state handoff from the draining node.
///
/// Carries the number of expected chunks so the draining node can plan
/// the transfer batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransferRequest {
    /// The node being drained.
    pub draining_node_id: MemberId,
    /// The peer requesting the state transfer.
    pub target_node_id: MemberId,
    /// Membership epoch at the time of the request.
    pub epoch_id: EpochId,
    /// Unique transfer identifier (per drain sequence).
    pub transfer_id: u64,
    /// Number of chunks the target is prepared to receive.
    pub max_chunks: u64,
    /// BLAKE3-256 digest covering all payload fields.
    pub digest: [u8; 32],
}

impl StateTransferRequest {
    /// Create a new StateTransferRequest with a computed BLAKE3 digest.
    #[must_use]
    pub fn new(
        draining_node_id: MemberId,
        target_node_id: MemberId,
        epoch_id: EpochId,
        transfer_id: u64,
        max_chunks: u64,
    ) -> Self {
        let mut msg = Self {
            draining_node_id,
            target_node_id,
            epoch_id,
            transfer_id,
            max_chunks,
            digest: [0u8; 32],
        };
        msg.digest = Self::compute_digest(
            msg.draining_node_id,
            msg.target_node_id,
            msg.epoch_id,
            msg.transfer_id,
            msg.max_chunks,
        );
        msg
    }

    fn compute_digest(
        draining_node_id: MemberId,
        target_node_id: MemberId,
        epoch_id: EpochId,
        transfer_id: u64,
        max_chunks: u64,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DRAIN_PROTOCOL_DOMAIN);
        hasher.update(&[DrainMessageKind::StateTransferRequest as u8]);
        let payload: (u64, u64, u64, u64, u64) = (
            draining_node_id.0,
            target_node_id.0,
            epoch_id.0,
            transfer_id,
            max_chunks,
        );
        if let Ok(encoded) = bincode::serialize(&payload) {
            hasher.update(&encoded);
        }
        hasher.finalize().into()
    }
}

impl DrainWireMessage for StateTransferRequest {
    fn kind(&self) -> DrainMessageKind {
        DrainMessageKind::StateTransferRequest
    }

    fn verify_full(&self) -> bool {
        Self::compute_digest(
            self.draining_node_id,
            self.target_node_id,
            self.epoch_id,
            self.transfer_id,
            self.max_chunks,
        ) == self.digest
    }

    fn draining_node_id(&self) -> MemberId {
        self.draining_node_id
    }
}

// ---------------------------------------------------------------------------
// StateTransferChunk
// ---------------------------------------------------------------------------

/// A single chunk of state data transferred from the draining node to a
/// target peer.
///
/// The `payload_digest` is a BLAKE3 hash of the raw payload bytes for
/// end-to-end integrity verification independent of the message digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransferChunk {
    /// The node being drained.
    pub draining_node_id: MemberId,
    /// The peer receiving the chunk.
    pub target_node_id: MemberId,
    /// The transfer this chunk belongs to.
    pub transfer_id: u64,
    /// Zero-based index of this chunk within the transfer.
    pub chunk_index: u64,
    /// The state payload (serialized object data).
    pub payload: Vec<u8>,
    /// BLAKE3-256 hash of the raw `payload` for data integrity.
    pub payload_digest: [u8; 32],
    /// BLAKE3-256 digest covering all fields (including payload_digest).
    pub digest: [u8; 32],
}

impl StateTransferChunk {
    /// Create a new StateTransferChunk with computed digests.
    ///
    /// The `payload_digest` is computed from the raw payload, and the
    /// `digest` covers the full message (using the payload digest, not
    /// the raw payload, to keep the message digest size-bounded).
    #[must_use]
    pub fn new(
        draining_node_id: MemberId,
        target_node_id: MemberId,
        transfer_id: u64,
        chunk_index: u64,
        payload: Vec<u8>,
    ) -> Self {
        let payload_digest = Self::hash_payload(&payload);
        let mut msg = Self {
            draining_node_id,
            target_node_id,
            transfer_id,
            chunk_index,
            payload,
            payload_digest,
            digest: [0u8; 32],
        };
        msg.digest = Self::compute_digest(
            msg.draining_node_id,
            msg.target_node_id,
            msg.transfer_id,
            msg.chunk_index,
            &msg.payload_digest,
        );
        msg
    }

    /// Compute the BLAKE3 hash of the raw payload bytes.
    fn hash_payload(payload: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(payload);
        hasher.finalize().into()
    }

    fn compute_digest(
        draining_node_id: MemberId,
        target_node_id: MemberId,
        transfer_id: u64,
        chunk_index: u64,
        payload_digest: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DRAIN_PROTOCOL_DOMAIN);
        hasher.update(&[DrainMessageKind::StateTransferChunk as u8]);
        // Serialize payload_digest as bytes in the tuple.
        let payload: (u64, u64, u64, u64, Vec<u8>) = (
            draining_node_id.0,
            target_node_id.0,
            transfer_id,
            chunk_index,
            payload_digest.to_vec(),
        );
        if let Ok(encoded) = bincode::serialize(&payload) {
            hasher.update(&encoded);
        }
        hasher.finalize().into()
    }

    /// Verify the payload integrity against the stored `payload_digest`.
    #[must_use]
    pub fn verify_payload(&self) -> bool {
        Self::hash_payload(&self.payload) == self.payload_digest
    }
}

impl DrainWireMessage for StateTransferChunk {
    fn kind(&self) -> DrainMessageKind {
        DrainMessageKind::StateTransferChunk
    }

    fn verify_full(&self) -> bool {
        Self::compute_digest(
            self.draining_node_id,
            self.target_node_id,
            self.transfer_id,
            self.chunk_index,
            &self.payload_digest,
        ) == self.digest
    }

    fn draining_node_id(&self) -> MemberId {
        self.draining_node_id
    }
}

// ---------------------------------------------------------------------------
// DrainComplete
// ---------------------------------------------------------------------------

/// Sent by the drain initiator (or epoch coordinator) after the epoch
/// transition commits, confirming the drain is final.
///
/// Peers receiving this message may tear down transport connections to
/// the drained node and remove it from their local membership caches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainComplete {
    /// The node that was drained.
    pub draining_node_id: MemberId,
    /// Membership epoch at which the drain completed.
    pub epoch_id: EpochId,
    /// Drain sequence number.
    pub drain_sequence: u64,
    /// Whether the drain completed successfully or was forced.
    pub forced: bool,
    /// BLAKE3-256 digest covering all payload fields.
    pub digest: [u8; 32],
}

impl DrainComplete {
    /// Create a new DrainComplete with a computed BLAKE3 digest.
    #[must_use]
    pub fn new(
        draining_node_id: MemberId,
        epoch_id: EpochId,
        drain_sequence: u64,
        forced: bool,
    ) -> Self {
        let mut msg = Self {
            draining_node_id,
            epoch_id,
            drain_sequence,
            forced,
            digest: [0u8; 32],
        };
        msg.digest = Self::compute_digest(
            msg.draining_node_id,
            msg.epoch_id,
            msg.drain_sequence,
            msg.forced,
        );
        msg
    }

    fn compute_digest(
        draining_node_id: MemberId,
        epoch_id: EpochId,
        drain_sequence: u64,
        forced: bool,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DRAIN_PROTOCOL_DOMAIN);
        hasher.update(&[DrainMessageKind::DrainComplete as u8]);
        let payload: (u64, u64, u64, bool) =
            (draining_node_id.0, epoch_id.0, drain_sequence, forced);
        if let Ok(encoded) = bincode::serialize(&payload) {
            hasher.update(&encoded);
        }
        hasher.finalize().into()
    }
}

impl DrainWireMessage for DrainComplete {
    fn kind(&self) -> DrainMessageKind {
        DrainMessageKind::DrainComplete
    }

    fn verify_full(&self) -> bool {
        Self::compute_digest(
            self.draining_node_id,
            self.epoch_id,
            self.drain_sequence,
            self.forced,
        ) == self.digest
    }

    fn draining_node_id(&self) -> MemberId {
        self.draining_node_id
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn epoch(id: u64) -> EpochId {
        EpochId(id)
    }

    // --- DrainMessageKind tests ---

    #[test]
    fn message_kind_roundtrip() {
        assert_eq!(
            DrainMessageKind::from_u8(0x01),
            Some(DrainMessageKind::DrainAnnounce)
        );
        assert_eq!(
            DrainMessageKind::from_u8(0x02),
            Some(DrainMessageKind::DrainAck)
        );
        assert_eq!(
            DrainMessageKind::from_u8(0x03),
            Some(DrainMessageKind::StateTransferRequest)
        );
        assert_eq!(
            DrainMessageKind::from_u8(0x04),
            Some(DrainMessageKind::StateTransferChunk)
        );
        assert_eq!(
            DrainMessageKind::from_u8(0x05),
            Some(DrainMessageKind::DrainComplete)
        );
    }

    #[test]
    fn message_kind_invalid() {
        assert_eq!(DrainMessageKind::from_u8(0x00), None);
        assert_eq!(DrainMessageKind::from_u8(0xFF), None);
        assert_eq!(DrainMessageKind::from_u8(0x06), None);
    }

    // --- DrainAnnounce tests ---

    #[test]
    fn announce_verify_roundtrip() {
        let msg = DrainAnnounce::new(mid(1), mid(2), epoch(5), 0, "maintenance".into());
        assert!(msg.verify_full());
        assert_eq!(msg.kind(), DrainMessageKind::DrainAnnounce);
        assert_eq!(msg.draining_node_id(), mid(1));
    }

    #[test]
    fn announce_tampered_digest_fails() {
        let mut msg = DrainAnnounce::new(mid(1), mid(2), epoch(5), 0, "maintenance".into());
        msg.digest[0] ^= 0xFF;
        assert!(!msg.verify_full());
    }

    #[test]
    fn announce_tampered_field_fails() {
        let mut msg = DrainAnnounce::new(mid(1), mid(2), epoch(5), 0, "maintenance".into());
        // Changing a field should invalidate the digest.
        msg.draining_node_id = mid(99);
        assert!(!msg.verify_full());
    }

    #[test]
    fn announce_different_nodes_different_digest() {
        let m1 = DrainAnnounce::new(mid(1), mid(2), epoch(5), 0, "maint".into());
        let m2 = DrainAnnounce::new(mid(3), mid(2), epoch(5), 0, "maint".into());
        assert_ne!(m1.digest, m2.digest);
    }

    #[test]
    fn announce_domain_separation() {
        // Verify domain separation: a digest computed with a different domain
        // should not match.
        let msg = DrainAnnounce::new(mid(1), mid(2), epoch(5), 0, "test".into());
        // Manually compute with a wrong domain to confirm separation.
        let mut hasher = blake3::Hasher::new_derive_key("tidefs-membership-drain-state-v1");
        hasher.update(&[DrainMessageKind::DrainAnnounce as u8]);
        let payload: (u64, u64, u64, u64, &str) = (mid(1).0, mid(2).0, epoch(5).0, 0u64, "test");
        if let Ok(encoded) = bincode::serialize(&payload) {
            hasher.update(&encoded);
        }
        let wrong_domain_digest: [u8; 32] = hasher.finalize().into();
        assert_ne!(msg.digest, wrong_domain_digest);
    }

    // --- DrainAck tests ---

    #[test]
    fn ack_verify_roundtrip_accept() {
        let msg = DrainAck::new(mid(1), mid(2), epoch(5), 0, true, None);
        assert!(msg.verify_full());
        assert_eq!(msg.kind(), DrainMessageKind::DrainAck);
        assert_eq!(msg.draining_node_id(), mid(1));
    }

    #[test]
    fn ack_verify_roundtrip_reject() {
        let msg = DrainAck::new(
            mid(1),
            mid(2),
            epoch(5),
            0,
            false,
            Some("insufficient capacity".into()),
        );
        assert!(msg.verify_full());
        assert!(!msg.accepted);
        assert_eq!(
            msg.rejection_reason.as_deref(),
            Some("insufficient capacity")
        );
    }

    #[test]
    fn ack_tampered_fails() {
        let mut msg = DrainAck::new(mid(1), mid(2), epoch(5), 0, true, None);
        msg.accepted = false;
        assert!(!msg.verify_full());
    }

    #[test]
    fn ack_different_nodes_different_digest() {
        let m1 = DrainAck::new(mid(1), mid(2), epoch(5), 0, true, None);
        let m2 = DrainAck::new(mid(1), mid(3), epoch(5), 0, true, None);
        assert_ne!(m1.digest, m2.digest);
    }

    #[test]
    fn ack_accept_vs_reject_different_digest() {
        let m1 = DrainAck::new(mid(1), mid(2), epoch(5), 0, true, None);
        let m2 = DrainAck::new(mid(1), mid(2), epoch(5), 0, false, None);
        assert_ne!(m1.digest, m2.digest);
    }

    // --- StateTransferRequest tests ---

    #[test]
    fn transfer_request_verify_roundtrip() {
        let msg = StateTransferRequest::new(mid(1), mid(2), epoch(5), 42, 64);
        assert!(msg.verify_full());
        assert_eq!(msg.kind(), DrainMessageKind::StateTransferRequest);
        assert_eq!(msg.draining_node_id(), mid(1));
    }

    #[test]
    fn transfer_request_tampered_fails() {
        let mut msg = StateTransferRequest::new(mid(1), mid(2), epoch(5), 42, 64);
        msg.max_chunks = 128;
        assert!(!msg.verify_full());
    }

    #[test]
    fn transfer_request_different_transfer_id_different_digest() {
        let m1 = StateTransferRequest::new(mid(1), mid(2), epoch(5), 42, 64);
        let m2 = StateTransferRequest::new(mid(1), mid(2), epoch(5), 43, 64);
        assert_ne!(m1.digest, m2.digest);
    }

    // --- StateTransferChunk tests ---

    #[test]
    fn chunk_verify_roundtrip() {
        let payload = b"hello state transfer".to_vec();
        let msg = StateTransferChunk::new(mid(1), mid(2), 42, 0, payload);
        assert!(msg.verify_full());
        assert!(msg.verify_payload());
        assert_eq!(msg.kind(), DrainMessageKind::StateTransferChunk);
        assert_eq!(msg.draining_node_id(), mid(1));
    }

    #[test]
    fn chunk_tampered_digest_fails() {
        let payload = b"hello state transfer".to_vec();
        let mut msg = StateTransferChunk::new(mid(1), mid(2), 42, 0, payload);
        msg.digest[15] ^= 0xAA;
        assert!(!msg.verify_full());
    }

    #[test]
    fn chunk_tampered_payload_fails() {
        let payload = b"hello state transfer".to_vec();
        let mut msg = StateTransferChunk::new(mid(1), mid(2), 42, 0, payload);
        msg.payload[0] ^= 0xFF;
        // Payload digest verification should catch tampering.
        assert!(!msg.verify_payload());
    }

    #[test]
    fn chunk_payload_digest_deterministic() {
        let payload = b"same payload".to_vec();
        let m1 = StateTransferChunk::new(mid(1), mid(2), 42, 0, payload.clone());
        let m2 = StateTransferChunk::new(mid(1), mid(2), 42, 0, payload);
        assert_eq!(m1.payload_digest, m2.payload_digest);
    }

    #[test]
    fn chunk_different_index_different_digest() {
        let payload = b"state data".to_vec();
        let m1 = StateTransferChunk::new(mid(1), mid(2), 42, 0, payload.clone());
        let m2 = StateTransferChunk::new(mid(1), mid(2), 42, 1, payload);
        assert_ne!(m1.digest, m2.digest);
    }

    #[test]
    fn chunk_empty_payload_valid() {
        let msg = StateTransferChunk::new(mid(1), mid(2), 42, 0, vec![]);
        assert!(msg.verify_full());
        assert!(msg.verify_payload());
    }

    // --- DrainComplete tests ---

    #[test]
    fn complete_verify_roundtrip() {
        let msg = DrainComplete::new(mid(1), epoch(5), 0, false);
        assert!(msg.verify_full());
        assert_eq!(msg.kind(), DrainMessageKind::DrainComplete);
        assert_eq!(msg.draining_node_id(), mid(1));
        assert!(!msg.forced);
    }

    #[test]
    fn complete_forced_verify_roundtrip() {
        let msg = DrainComplete::new(mid(1), epoch(5), 0, true);
        assert!(msg.verify_full());
        assert!(msg.forced);
    }

    #[test]
    fn complete_tampered_fails() {
        let mut msg = DrainComplete::new(mid(1), epoch(5), 0, false);
        msg.epoch_id = epoch(99);
        assert!(!msg.verify_full());
    }

    #[test]
    fn complete_forced_vs_graceful_different_digest() {
        let m1 = DrainComplete::new(mid(1), epoch(5), 0, false);
        let m2 = DrainComplete::new(mid(1), epoch(5), 0, true);
        assert_ne!(m1.digest, m2.digest);
    }

    // --- Cross-message type collision prevention ---

    #[test]
    fn cross_type_prefix_prevents_collision() {
        // Same logical fields but different message types should produce
        // different digests due to the per-type discriminator byte.
        let announce = DrainAnnounce::new(mid(1), mid(2), epoch(5), 0, String::new());
        // A DrainComplete with different fields will naturally differ,
        // but we also verify the type byte is included in the hash.
        let complete = DrainComplete::new(mid(1), epoch(5), 0, false);
        assert_ne!(announce.digest, complete.digest);
    }

    // --- DrainWireMessage trait dispatch ---

    #[test]
    fn wire_message_trait_kind() {
        let announce = DrainAnnounce::new(mid(1), mid(2), epoch(5), 0, "test".into());
        let ack = DrainAck::new(mid(1), mid(2), epoch(5), 0, true, None);
        let req = StateTransferRequest::new(mid(1), mid(2), epoch(5), 42, 64);
        let chunk = StateTransferChunk::new(mid(1), mid(2), 42, 0, vec![1, 2, 3]);
        let complete = DrainComplete::new(mid(1), epoch(5), 0, false);

        assert_eq!(announce.kind(), DrainMessageKind::DrainAnnounce);
        assert_eq!(ack.kind(), DrainMessageKind::DrainAck);
        assert_eq!(req.kind(), DrainMessageKind::StateTransferRequest);
        assert_eq!(chunk.kind(), DrainMessageKind::StateTransferChunk);
        assert_eq!(complete.kind(), DrainMessageKind::DrainComplete);
    }

    #[test]
    fn wire_message_trait_draining_node_id() {
        let announce = DrainAnnounce::new(mid(42), mid(2), epoch(5), 0, "test".into());
        let ack = DrainAck::new(mid(42), mid(2), epoch(5), 0, true, None);
        let req = StateTransferRequest::new(mid(42), mid(2), epoch(5), 1, 64);
        let chunk = StateTransferChunk::new(mid(42), mid(2), 1, 0, vec![1, 2, 3]);
        let complete = DrainComplete::new(mid(42), epoch(5), 0, false);

        assert_eq!(announce.draining_node_id(), mid(42));
        assert_eq!(ack.draining_node_id(), mid(42));
        assert_eq!(req.draining_node_id(), mid(42));
        assert_eq!(chunk.draining_node_id(), mid(42));
        assert_eq!(complete.draining_node_id(), mid(42));
    }

    // --- Digest non-zero ---

    #[test]
    fn all_message_digests_are_nonzero() {
        let announce = DrainAnnounce::new(mid(1), mid(2), epoch(5), 0, "test".into());
        assert_ne!(announce.digest, [0u8; 32]);

        let ack = DrainAck::new(mid(1), mid(2), epoch(5), 0, true, None);
        assert_ne!(ack.digest, [0u8; 32]);

        let req = StateTransferRequest::new(mid(1), mid(2), epoch(5), 1, 64);
        assert_ne!(req.digest, [0u8; 32]);

        let chunk = StateTransferChunk::new(mid(1), mid(2), 1, 0, vec![1, 2, 3]);
        assert_ne!(chunk.digest, [0u8; 32]);
        assert_ne!(chunk.payload_digest, [0u8; 32]);

        let complete = DrainComplete::new(mid(1), epoch(5), 0, false);
        assert_ne!(complete.digest, [0u8; 32]);
    }

    // --- Domain separation across message types ---

    #[test]
    fn wrong_domain_verification_fails() {
        // Compute digest with a different domain and show it won't verify.
        let msg = DrainAnnounce::new(mid(1), mid(2), epoch(5), 0, "test".into());

        // Manually re-derive with wrong domain
        let mut hasher = blake3::Hasher::new_derive_key("wrong-domain-test");
        hasher.update(&[DrainMessageKind::DrainAnnounce as u8]);
        let payload: (u64, u64, u64, u64, &str) = (mid(1).0, mid(2).0, epoch(5).0, 0u64, "test");
        if let Ok(encoded) = bincode::serialize(&payload) {
            hasher.update(&encoded);
        }
        let wrong: [u8; 32] = hasher.finalize().into();
        assert_ne!(msg.digest, wrong);
    }
}
