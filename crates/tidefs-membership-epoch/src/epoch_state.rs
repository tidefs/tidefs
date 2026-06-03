//! Epoch lifecycle state machine with BLAKE3-verified proposals.
//!
//! Defines the [`EpochState`] enum governing the four-phase epoch
//! transition lifecycle and the [`EpochProposal`] struct that
//! wraps a membership delta with a domain-separated BLAKE3-256 proof.
//!
//! State transitions are validated against a table of permissible
//! edges to prevent illegal state progressions (e.g., committing
//! without acks, or proposing while already proposing).

use serde::{Deserialize, Serialize};
use std::fmt;

use super::epoch_proposal::MembershipDelta;

// ── EpochState ──────────────────────────────────────────────────────

/// The four-phase lifecycle of an epoch transition.
///
/// ```text
/// Stable ──propose()──▶ Proposing ──broadcast──▶ AwaitingAcks ──quorum──▶ Committed
///    ▲                                             │                          │
///    │               timeout/abort                 │                          │
///    └─────────────────────────────────────────────┘                          │
///    ▲                                                                       │
///    └───────────────────────────reset()─────────────────────────────────────┘
/// ```text
///
/// - **Stable**: no transition in progress; the current epoch is settled.
/// - **Proposing**: a proposal has been created but not yet broadcast to peers.
/// - **AwaitingAcks**: the proposal is broadcast; collecting peer acknowledgments.
/// - **Committed**: quorum reached; epoch can be finalized.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EpochState {
    Stable,
    Proposing,
    AwaitingAcks,
    Committed,
}

impl EpochState {
    /// Whether the state machine is currently in a transition.
    #[must_use]
    pub const fn is_in_transition(self) -> bool {
        !matches!(self, Self::Stable)
    }

    /// Whether ack collection is active.
    #[must_use]
    pub const fn is_collecting_acks(self) -> bool {
        matches!(self, Self::AwaitingAcks)
    }

    /// Whether the state represents a terminal phase of the current
    /// transition (commit succeeded or can be reset).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Committed)
    }

    /// Validate a transition from `self` to `next`.
    ///
    /// Returns `Ok(())` if the transition is legal, or an
    /// [`InvalidStateTransition`] error describing the invalid edge.
    pub fn validate_transition(self, next: Self) -> Result<(), InvalidStateTransition> {
        let valid = matches!(
            (self, next),
            (Self::Stable, Self::Proposing)
                | (Self::Proposing, Self::AwaitingAcks)
                | (Self::Proposing, Self::Stable) // abort before broadcast
                | (Self::AwaitingAcks, Self::Committed)
                | (Self::AwaitingAcks, Self::Stable) // timeout abort
                | (Self::Committed, Self::Stable) // reset after commit
        );
        if valid {
            Ok(())
        } else {
            Err(InvalidStateTransition {
                from: self,
                to: next,
            })
        }
    }
}

impl fmt::Display for EpochState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stable => write!(f, "Stable"),
            Self::Proposing => write!(f, "Proposing"),
            Self::AwaitingAcks => write!(f, "AwaitingAcks"),
            Self::Committed => write!(f, "Committed"),
        }
    }
}

impl Default for EpochState {
    fn default() -> Self {
        Self::Stable
    }
}

// ── InvalidStateTransition ──────────────────────────────────────────

/// Error returned when an illegal state transition is attempted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidStateTransition {
    pub from: EpochState,
    pub to: EpochState,
}

impl fmt::Display for InvalidStateTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid state transition: {} -> {}", self.from, self.to)
    }
}

impl std::error::Error for InvalidStateTransition {}

// ── EpochProposal ───────────────────────────────────────────────────

/// A high-level epoch transition proposal carrying a membership delta.
///
/// Unlike the low-level [`quorum::EpochProposal`](crate::quorum::EpochProposal)
/// which handles cryptographic voting, this struct captures the
/// *intent* of the transition: what membership change triggered it,
/// what the resulting member set looks like, and a BLAKE3-256 proof
/// binding all fields together.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochProposal {
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
    /// BLAKE3-256 hash covering the full proposal (domain-tagged).
    pub blake3_hash: [u8; 32],
}

impl EpochProposal {
    /// Domain separation tag for epoch-proposal hashing.
    pub const DOMAIN_TAG: &[u8] = b"tidefs-membership-epoch-proposal-v1";

    /// Compute the BLAKE3 hash for an epoch proposal.
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

    /// Create a new proposal with a computed BLAKE3 hash.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `proposed_epoch != current_epoch + 1` or if
    /// `resulting_members` is empty.
    pub fn new(
        proposer_id: u64,
        current_epoch: u64,
        proposed_epoch: u64,
        delta: MembershipDelta,
        resulting_members: &[u64],
    ) -> Result<Self, super::epoch_proposal::ProposalError> {
        if proposed_epoch != current_epoch + 1 {
            return Err(super::epoch_proposal::ProposalError::NonConsecutive {
                current: current_epoch,
                proposed: proposed_epoch,
            });
        }
        let mut sorted = resulting_members.to_vec();
        sorted.sort();
        sorted.dedup();
        if sorted.is_empty() {
            return Err(super::epoch_proposal::ProposalError::EmptyMemberSet);
        }
        let blake3_hash =
            Self::compute_hash(proposer_id, current_epoch, proposed_epoch, &delta, &sorted);
        Ok(Self {
            proposer_id,
            current_epoch,
            proposed_epoch,
            delta,
            resulting_members: sorted,
            blake3_hash,
        })
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

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EpochState transitions ──────────────────────────────────────

    #[test]
    fn stable_to_proposing_valid() {
        assert!(EpochState::Stable
            .validate_transition(EpochState::Proposing)
            .is_ok());
    }

    #[test]
    fn proposing_to_awaiting_acks_valid() {
        assert!(EpochState::Proposing
            .validate_transition(EpochState::AwaitingAcks)
            .is_ok());
    }

    #[test]
    fn proposing_to_stable_abort_valid() {
        assert!(EpochState::Proposing
            .validate_transition(EpochState::Stable)
            .is_ok());
    }

    #[test]
    fn awaiting_acks_to_committed_valid() {
        assert!(EpochState::AwaitingAcks
            .validate_transition(EpochState::Committed)
            .is_ok());
    }

    #[test]
    fn awaiting_acks_to_stable_timeout_valid() {
        assert!(EpochState::AwaitingAcks
            .validate_transition(EpochState::Stable)
            .is_ok());
    }

    #[test]
    fn committed_to_stable_reset_valid() {
        assert!(EpochState::Committed
            .validate_transition(EpochState::Stable)
            .is_ok());
    }

    #[test]
    fn stable_to_awaiting_acks_invalid() {
        let result = EpochState::Stable.validate_transition(EpochState::AwaitingAcks);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.from, EpochState::Stable);
        assert_eq!(err.to, EpochState::AwaitingAcks);
    }

    #[test]
    fn stable_to_committed_invalid() {
        assert!(EpochState::Stable
            .validate_transition(EpochState::Committed)
            .is_err());
    }

    #[test]
    fn proposing_to_committed_invalid() {
        // Cannot commit without collecting acks first
        assert!(EpochState::Proposing
            .validate_transition(EpochState::Committed)
            .is_err());
    }

    #[test]
    fn awaiting_acks_to_proposing_invalid() {
        assert!(EpochState::AwaitingAcks
            .validate_transition(EpochState::Proposing)
            .is_err());
    }

    #[test]
    fn committed_to_proposing_invalid() {
        assert!(EpochState::Committed
            .validate_transition(EpochState::Proposing)
            .is_err());
    }

    #[test]
    fn committed_to_awaiting_acks_invalid() {
        assert!(EpochState::Committed
            .validate_transition(EpochState::AwaitingAcks)
            .is_err());
    }

    #[test]
    fn stable_to_stable_noop_valid() {
        // Not explicitly listed as valid; staying in same state is not in the table
        assert!(EpochState::Stable
            .validate_transition(EpochState::Stable)
            .is_err());
    }

    // ── EpochState helpers ──────────────────────────────────────────

    #[test]
    fn is_in_transition() {
        assert!(!EpochState::Stable.is_in_transition());
        assert!(EpochState::Proposing.is_in_transition());
        assert!(EpochState::AwaitingAcks.is_in_transition());
        assert!(EpochState::Committed.is_in_transition());
    }

    #[test]
    fn is_collecting_acks() {
        assert!(!EpochState::Stable.is_collecting_acks());
        assert!(!EpochState::Proposing.is_collecting_acks());
        assert!(EpochState::AwaitingAcks.is_collecting_acks());
        assert!(!EpochState::Committed.is_collecting_acks());
    }

    #[test]
    fn is_terminal() {
        assert!(!EpochState::Stable.is_terminal());
        assert!(!EpochState::Proposing.is_terminal());
        assert!(!EpochState::AwaitingAcks.is_terminal());
        assert!(EpochState::Committed.is_terminal());
    }

    #[test]
    fn default_is_stable() {
        assert_eq!(EpochState::default(), EpochState::Stable);
    }

    #[test]
    fn epoch_state_display() {
        assert_eq!(format!("{}", EpochState::Stable), "Stable");
        assert_eq!(format!("{}", EpochState::Proposing), "Proposing");
        assert_eq!(format!("{}", EpochState::AwaitingAcks), "AwaitingAcks");
        assert_eq!(format!("{}", EpochState::Committed), "Committed");
    }

    #[test]
    fn epoch_state_serde_roundtrip() {
        for state in &[
            EpochState::Stable,
            EpochState::Proposing,
            EpochState::AwaitingAcks,
            EpochState::Committed,
        ] {
            let json = serde_json::to_string(state).unwrap();
            let restored: EpochState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, restored);
        }
    }

    // ── InvalidStateTransition ──────────────────────────────────────

    #[test]
    fn invalid_transition_display() {
        let err = InvalidStateTransition {
            from: EpochState::Stable,
            to: EpochState::Committed,
        };
        let msg = format!("{err}");
        assert!(msg.contains("Stable"));
        assert!(msg.contains("Committed"));
    }

    // ── EpochProposal ───────────────────────────────────────────────

    fn make_proposal(
        proposer: u64,
        current: u64,
        delta: MembershipDelta,
        members: &[u64],
    ) -> EpochProposal {
        EpochProposal::new(proposer, current, current + 1, delta, members).unwrap()
    }

    #[test]
    fn proposal_new_sorts_and_dedups_members() {
        let p =
            EpochProposal::new(1, 0, 1, MembershipDelta::NodeJoined(3), &[3, 1, 3, 2, 1]).unwrap();
        assert_eq!(p.resulting_members, vec![1, 2, 3]);
        assert!(p.verify());
    }

    #[test]
    fn proposal_verify_accepts_valid_join() {
        let p = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        assert!(p.verify());
    }

    #[test]
    fn proposal_verify_accepts_valid_drain() {
        let p = make_proposal(1, 5, MembershipDelta::NodeDrained(2), &[1, 3]);
        assert!(p.verify());
    }

    #[test]
    fn proposal_verify_accepts_valid_failure() {
        let p = make_proposal(1, 10, MembershipDelta::NodeFailed(5), &[1, 2]);
        assert!(p.verify());
    }

    #[test]
    fn proposal_verify_rejects_tampered_epoch() {
        let mut p = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        p.proposed_epoch = 99;
        assert!(!p.verify());
    }

    #[test]
    fn proposal_verify_rejects_tampered_delta() {
        let mut p = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        p.delta = MembershipDelta::NodeFailed(3);
        assert!(!p.verify());
    }

    #[test]
    fn proposal_verify_rejects_tampered_members() {
        let mut p = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        p.resulting_members.push(99);
        assert!(!p.verify());
    }

    #[test]
    fn proposal_verify_rejects_tampered_proposer() {
        let mut p = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        p.proposer_id = 99;
        assert!(!p.verify());
    }

    #[test]
    fn proposal_new_rejects_non_consecutive() {
        let result = EpochProposal::new(
            1,
            0,
            5, // proposed is 5, not 1
            MembershipDelta::NodeJoined(3),
            &[1, 2, 3],
        );
        assert!(matches!(
            result,
            Err(crate::epoch_proposal::ProposalError::NonConsecutive {
                current: 0,
                proposed: 5
            })
        ));
    }

    #[test]
    fn proposal_new_rejects_empty_members() {
        let result = EpochProposal::new(1, 0, 1, MembershipDelta::NodeJoined(3), &[]);
        assert!(matches!(
            result,
            Err(crate::epoch_proposal::ProposalError::EmptyMemberSet)
        ));
    }

    #[test]
    fn proposal_new_accepts_single_member() {
        let p = EpochProposal::new(1, 0, 1, MembershipDelta::NodeJoined(2), &[2]).unwrap();
        assert!(p.verify());
        assert_eq!(p.resulting_members, vec![2]);
    }

    #[test]
    fn proposal_hash_deterministic() {
        let p1 = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        let p2 = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        assert_eq!(p1.blake3_hash, p2.blake3_hash);
    }

    #[test]
    fn proposal_hash_differs_by_current_epoch() {
        let p1 = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        let p2 = make_proposal(1, 1, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        assert_ne!(p1.blake3_hash, p2.blake3_hash);
    }

    #[test]
    fn proposal_serde_roundtrip() {
        let p = make_proposal(1, 0, MembershipDelta::NodeJoined(3), &[1, 2, 3]);
        let json = serde_json::to_string(&p).unwrap();
        let restored: EpochProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, p);
        assert!(restored.verify());
    }
}
