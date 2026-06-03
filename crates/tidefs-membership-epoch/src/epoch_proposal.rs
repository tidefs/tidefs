//! Wire types for epoch proposal and acknowledgment messages with
//! BLAKE3-verified integrity.
//!
//! This module defines the network-facing message types for the
//! epoch transition protocol: [`EpochProposalMessage`] carries a
//! proposed membership delta to peers, and [`EpochAckMessage`] is
//! each peer's signed response. Both types include domain-separated
//! BLAKE3-256 hashes for tamper detection.
//!
//! The [`MembershipDelta`] enum captures the specific membership
//! change (join, drain, failure, suspicion) that drives an epoch
//! transition.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── MembershipDelta ─────────────────────────────────────────────────

/// The specific membership change that triggers an epoch transition.
///
/// Carries the affected node's identity. Used by the epoch state
/// machine to determine the new member set and as a gossip payload
/// for multi-node dissemination.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MembershipDelta {
    /// A node joined the membership (confirmed join handshake).
    NodeJoined(u64),
    /// A node drained gracefully (completed drain state machine).
    NodeDrained(u64),
    /// A node failed (SWIM failure confirmation).
    NodeFailed(u64),
    /// A node is suspected of failure (SWIM suspicion, not yet confirmed).
    NodeSuspected(u64),
}

impl MembershipDelta {
    /// Return the node identifier for this delta.
    #[must_use]
    pub fn node_id(&self) -> u64 {
        match self {
            Self::NodeJoined(id)
            | Self::NodeDrained(id)
            | Self::NodeFailed(id)
            | Self::NodeSuspected(id) => *id,
        }
    }

    /// Whether this delta implies removal from the member set.
    #[must_use]
    pub fn is_removal(&self) -> bool {
        matches!(self, Self::NodeDrained(_) | Self::NodeFailed(_))
    }

    /// Whether this delta implies addition to the member set.
    #[must_use]
    pub fn is_addition(&self) -> bool {
        matches!(self, Self::NodeJoined(_))
    }

    /// Discriminant tag for serialization / domain separation.
    pub fn discriminant(&self) -> u8 {
        match self {
            Self::NodeJoined(_) => 0x01,
            Self::NodeDrained(_) => 0x02,
            Self::NodeFailed(_) => 0x03,
            Self::NodeSuspected(_) => 0x04,
        }
    }
}

impl fmt::Display for MembershipDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodeJoined(id) => write!(f, "NodeJoined({id})"),
            Self::NodeDrained(id) => write!(f, "NodeDrained({id})"),
            Self::NodeFailed(id) => write!(f, "NodeFailed({id})"),
            Self::NodeSuspected(id) => write!(f, "NodeSuspected({id})"),
        }
    }
}

// ── EpochProposalMessage ────────────────────────────────────────────

/// A network-facing epoch proposal message carrying a membership delta.
///
/// Broadcast by a proposer to all peers to initiate an epoch transition.
/// The embedded BLAKE3-256 hash covers the full message payload so any
/// peer can independently verify integrity before voting.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochProposalMessage {
    /// The proposer's node identity.
    pub proposer_id: u64,
    /// The current epoch before the transition.
    pub current_epoch: u64,
    /// The proposed next epoch (must equal current_epoch + 1).
    pub proposed_epoch: u64,
    /// The membership change driving this proposal.
    pub delta: MembershipDelta,
    /// Sorted, deduplicated member node ids after applying the delta.
    pub resulting_members: Vec<u64>,
    /// BLAKE3-256 hash covering the full payload (domain-tagged).
    pub blake3_hash: [u8; 32],
    /// Optional serialized catalog delta (dataset create/destroy/rename)
    /// proposed alongside or independently of the membership change.
    /// `None` when this proposal carries no catalog mutation.
    pub catalog_delta_bytes: Option<Vec<u8>>,
}

impl EpochProposalMessage {
    /// Domain separation tag for proposal message hashing.
    pub const DOMAIN_TAG: &[u8] = b"tidefs-membership-epoch-proposal-v1";

    /// Compute the BLAKE3 hash for a proposal message.
    ///
    /// Covers proposer_id, current_epoch, proposed_epoch,
    /// delta discriminant + node_id, and each resulting member
    /// in sorted order.
    pub fn compute_hash(
        proposer_id: u64,
        current_epoch: u64,
        proposed_epoch: u64,
        delta: &MembershipDelta,
        resulting_members: &[u64],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_TAG);
        hasher.update(&proposer_id.to_le_bytes());
        hasher.update(&current_epoch.to_le_bytes());
        hasher.update(&proposed_epoch.to_le_bytes());
        hasher.update(&[delta.discriminant()]);
        hasher.update(&delta.node_id().to_le_bytes());
        hasher.update(b"|members|");
        for id in resulting_members {
            hasher.update(&id.to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// Create a new proposal message with a computed BLAKE3 hash.
    ///
    /// The caller must ensure `resulting_members` is sorted and
    /// deduplicated before calling.
    #[must_use]
    pub fn new(
        proposer_id: u64,
        current_epoch: u64,
        proposed_epoch: u64,
        delta: MembershipDelta,
        resulting_members: &[u64],
    ) -> Self {
        let blake3_hash = Self::compute_hash(
            proposer_id,
            current_epoch,
            proposed_epoch,
            &delta,
            resulting_members,
        );
        Self {
            proposer_id,
            current_epoch,
            proposed_epoch,
            delta,
            resulting_members: resulting_members.to_vec(),
            blake3_hash,
            catalog_delta_bytes: None,
        }
    }

    /// Verify that the embedded hash matches the computed hash.
    #[must_use]
    pub fn verify(&self) -> bool {
        Self::compute_hash(
            self.proposer_id,
            self.current_epoch,
            self.proposed_epoch,
            &self.delta,
            &self.resulting_members,
        ) == self.blake3_hash
    }
}

// ── EpochAckMessage ─────────────────────────────────────────────────

/// A peer's acknowledgment of an epoch proposal.
///
/// Each peer responds with an ack that signs the proposal hash,
/// binding the peer's vote to the specific proposal. The embedded
/// BLAKE3 hash prevents forgery and replay.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochAckMessage {
    /// The acknowledging peer's node identity.
    pub acker_id: u64,
    /// Hash of the proposal this ack targets.
    pub proposal_hash: [u8; 32],
    /// Whether the peer approves (true) or rejects (false).
    pub approved: bool,
    /// BLAKE3-256 hash covering the full ack payload (domain-tagged).
    pub blake3_hash: [u8; 32],
}

impl EpochAckMessage {
    /// Domain separation tag for ack message hashing.
    pub const DOMAIN_TAG: &[u8] = b"tidefs-membership-epoch-ack-v1";

    /// Compute the BLAKE3 hash for an ack message.
    pub fn compute_hash(acker_id: u64, proposal_hash: &[u8; 32], approved: bool) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_TAG);
        hasher.update(&acker_id.to_le_bytes());
        hasher.update(proposal_hash);
        hasher.update(&[if approved { 0x01u8 } else { 0x00u8 }]);
        hasher.finalize().into()
    }

    /// Create an approval ack with BLAKE3 integrity proof.
    #[must_use]
    pub fn approve(acker_id: u64, proposal_hash: &[u8; 32]) -> Self {
        Self {
            acker_id,
            proposal_hash: *proposal_hash,
            approved: true,
            blake3_hash: Self::compute_hash(acker_id, proposal_hash, true),
        }
    }

    /// Create a rejection ack with BLAKE3 integrity proof.
    #[must_use]
    pub fn reject(acker_id: u64, proposal_hash: &[u8; 32]) -> Self {
        Self {
            acker_id,
            proposal_hash: *proposal_hash,
            approved: false,
            blake3_hash: Self::compute_hash(acker_id, proposal_hash, false),
        }
    }

    /// Verify that the embedded hash matches the computed hash.
    #[must_use]
    pub fn verify(&self) -> bool {
        Self::compute_hash(self.acker_id, &self.proposal_hash, self.approved) == self.blake3_hash
    }
}

// ── Errors ──────────────────────────────────────────────────────────

/// Errors that can occur during epoch proposal/ack processing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalError {
    /// The proposed epoch is not equal to current_epoch + 1.
    NonConsecutive { current: u64, proposed: u64 },
    /// The resulting member set is empty.
    EmptyMemberSet,
    /// The proposal's BLAKE3 integrity check failed (tampered).
    ProposalVerificationFailed,
    /// The ack's BLAKE3 integrity check failed (tampered).
    AckVerificationFailed,
    /// A proposal hash mismatch between the proposal and ack.
    ProposalHashMismatch,
    /// Duplicate ack from the same peer.
    DuplicateAck(u64),
}

impl fmt::Display for ProposalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonConsecutive { current, proposed } => {
                write!(
                    f,
                    "non-consecutive epoch: current={current}, proposed={proposed}"
                )
            }
            Self::EmptyMemberSet => write!(f, "resulting member set is empty"),
            Self::ProposalVerificationFailed => {
                write!(f, "proposal BLAKE3 verification failed")
            }
            Self::AckVerificationFailed => {
                write!(f, "ack BLAKE3 verification failed")
            }
            Self::ProposalHashMismatch => {
                write!(f, "ack proposal hash does not match")
            }
            Self::DuplicateAck(id) => {
                write!(f, "duplicate ack from peer {id}")
            }
        }
    }
}

impl std::error::Error for ProposalError {}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MembershipDelta ──────────────────────────────────────────────

    #[test]
    fn delta_node_id_returns_correct_id() {
        assert_eq!(MembershipDelta::NodeJoined(42).node_id(), 42);
        assert_eq!(MembershipDelta::NodeDrained(7).node_id(), 7);
        assert_eq!(MembershipDelta::NodeFailed(99).node_id(), 99);
        assert_eq!(MembershipDelta::NodeSuspected(1).node_id(), 1);
    }

    #[test]
    fn delta_is_removal() {
        assert!(MembershipDelta::NodeDrained(1).is_removal());
        assert!(MembershipDelta::NodeFailed(1).is_removal());
        assert!(!MembershipDelta::NodeJoined(1).is_removal());
        assert!(!MembershipDelta::NodeSuspected(1).is_removal());
    }

    #[test]
    fn delta_is_addition() {
        assert!(MembershipDelta::NodeJoined(1).is_addition());
        assert!(!MembershipDelta::NodeDrained(1).is_addition());
        assert!(!MembershipDelta::NodeFailed(1).is_addition());
        assert!(!MembershipDelta::NodeSuspected(1).is_addition());
    }

    #[test]
    fn delta_discriminants_are_unique() {
        let discriminants: std::collections::BTreeSet<u8> = [
            MembershipDelta::NodeJoined(1).discriminant(),
            MembershipDelta::NodeDrained(1).discriminant(),
            MembershipDelta::NodeFailed(1).discriminant(),
            MembershipDelta::NodeSuspected(1).discriminant(),
        ]
        .into_iter()
        .collect();
        assert_eq!(discriminants.len(), 4);
    }

    #[test]
    fn delta_serde_roundtrip() {
        let deltas = [
            MembershipDelta::NodeJoined(10),
            MembershipDelta::NodeDrained(20),
            MembershipDelta::NodeFailed(30),
            MembershipDelta::NodeSuspected(40),
        ];
        for delta in &deltas {
            let json = serde_json::to_string(delta).unwrap();
            let restored: MembershipDelta = serde_json::from_str(&json).unwrap();
            assert_eq!(*delta, restored);
        }
    }

    #[test]
    fn delta_display_format() {
        assert_eq!(
            format!("{}", MembershipDelta::NodeJoined(1)),
            "NodeJoined(1)"
        );
        assert_eq!(
            format!("{}", MembershipDelta::NodeDrained(2)),
            "NodeDrained(2)"
        );
        assert_eq!(
            format!("{}", MembershipDelta::NodeFailed(3)),
            "NodeFailed(3)"
        );
        assert_eq!(
            format!("{}", MembershipDelta::NodeSuspected(4)),
            "NodeSuspected(4)"
        );
    }

    // ── EpochProposalMessage ─────────────────────────────────────────

    fn make_proposal(
        proposer: u64,
        current: u64,
        delta: MembershipDelta,
        members: &[u64],
    ) -> EpochProposalMessage {
        EpochProposalMessage::new(proposer, current, current + 1, delta, members)
    }

    #[test]
    fn proposal_verify_accepts_valid() {
        let p = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        assert!(p.verify());
    }

    #[test]
    fn proposal_verify_rejects_tampered_epoch() {
        let mut p = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        p.proposed_epoch = 99;
        assert!(!p.verify());
    }

    #[test]
    fn proposal_verify_rejects_tampered_members() {
        let mut p = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        p.resulting_members.push(99);
        assert!(!p.verify());
    }

    #[test]
    fn proposal_verify_rejects_tampered_delta() {
        let mut p = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        p.delta = MembershipDelta::NodeFailed(3);
        assert!(!p.verify());
    }

    #[test]
    fn proposal_verify_rejects_tampered_proposer() {
        let mut p = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        p.proposer_id = 99;
        assert!(!p.verify());
    }

    #[test]
    fn proposal_hash_deterministic() {
        let p1 = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        let p2 = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        assert_eq!(p1.blake3_hash, p2.blake3_hash);
    }

    #[test]
    fn proposal_hash_differs_by_delta() {
        let p1 = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        let p2 = make_proposal(1, 0, MembershipDelta::NodeDrained(2), &[1]);
        assert_ne!(p1.blake3_hash, p2.blake3_hash);
    }

    #[test]
    fn proposal_hash_differs_by_members() {
        let p1 = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        let p2 = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3, 4]);
        assert_ne!(p1.blake3_hash, p2.blake3_hash);
    }

    #[test]
    fn proposal_serde_roundtrip() {
        let p = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        let json = serde_json::to_string(&p).unwrap();
        let restored: EpochProposalMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, p);
        assert!(restored.verify());
    }

    #[test]
    fn proposal_with_drain_delta() {
        let p = make_proposal(1, 5, MembershipDelta::NodeDrained(2), &[1, 3]);
        assert!(p.verify());
        assert_eq!(p.current_epoch, 5);
        assert_eq!(p.proposed_epoch, 6);
        assert!(p.delta.is_removal());
    }

    #[test]
    fn proposal_with_failure_delta() {
        let p = make_proposal(1, 10, MembershipDelta::NodeFailed(5), &[1, 2, 3]);
        assert!(p.verify());
        assert_eq!(p.delta, MembershipDelta::NodeFailed(5));
    }

    // ── EpochAckMessage ──────────────────────────────────────────────

    #[test]
    fn approve_ack_verifies() {
        let ph = [42u8; 32];
        let ack = EpochAckMessage::approve(1, &ph);
        assert!(ack.verify());
        assert!(ack.approved);
        assert_eq!(ack.acker_id, 1);
    }

    #[test]
    fn reject_ack_verifies() {
        let ph = [42u8; 32];
        let ack = EpochAckMessage::reject(2, &ph);
        assert!(ack.verify());
        assert!(!ack.approved);
        assert_eq!(ack.acker_id, 2);
    }

    #[test]
    fn ack_rejects_tampered_approval() {
        let ph = [42u8; 32];
        let ack = EpochAckMessage::approve(1, &ph);
        let mut tampered = ack.clone();
        tampered.approved = false;
        // Hash should fail since approved flag changed
        assert!(!tampered.verify());
    }

    #[test]
    fn ack_rejects_tampered_id() {
        let ph = [42u8; 32];
        let ack = EpochAckMessage::approve(1, &ph);
        let mut tampered = ack.clone();
        tampered.acker_id = 99;
        assert!(!tampered.verify());
    }

    #[test]
    fn ack_rejects_tampered_proposal_hash() {
        let ph = [42u8; 32];
        let ack = EpochAckMessage::approve(1, &ph);
        let mut tampered = ack.clone();
        tampered.proposal_hash = [0u8; 32];
        assert!(!tampered.verify());
    }

    #[test]
    fn approve_and_reject_have_different_hashes() {
        let ph = [42u8; 32];
        let a1 = EpochAckMessage::approve(1, &ph);
        let a2 = EpochAckMessage::reject(1, &ph);
        assert_ne!(a1.blake3_hash, a2.blake3_hash);
    }

    #[test]
    fn ack_hash_deterministic() {
        let ph = [42u8; 32];
        let a1 = EpochAckMessage::approve(1, &ph);
        let a2 = EpochAckMessage::approve(1, &ph);
        assert_eq!(a1.blake3_hash, a2.blake3_hash);
    }

    #[test]
    fn ack_serde_roundtrip() {
        let ph = [42u8; 32];
        let ack = EpochAckMessage::approve(1, &ph);
        let json = serde_json::to_string(&ack).unwrap();
        let restored: EpochAckMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, ack);
        assert!(restored.verify());
    }

    // ── ProposalError ────────────────────────────────────────────────

    #[test]
    fn proposal_error_display() {
        let e = ProposalError::NonConsecutive {
            current: 1,
            proposed: 5,
        };
        assert!(format!("{e}").contains("non-consecutive"));

        let e = ProposalError::DuplicateAck(42);
        assert!(format!("{e}").contains("42"));

        let e = ProposalError::EmptyMemberSet;
        assert!(format!("{e}").contains("empty"));

        let e = ProposalError::ProposalVerificationFailed;
        assert!(format!("{e}").contains("verification"));
    }
}
