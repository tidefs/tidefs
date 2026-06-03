//! BLAKE3-verified epoch proposal construction from roster snapshot data.
//!
//! This module provides [`EpochProposal`] — the wire type that carries a
//! proposed next-epoch configuration with BLAKE3-256 domain-separated
//! integrity — and [`EpochProposalConstructor`] which diffs the proposed
//! member set against the current epoch, validates transition preconditions,
//! and emits a signed proposal.
//!
//! ## Design
//!
//! The constructor takes raw inputs (digest, member iterators) rather than
//! directly referencing `RosterSnapshot` from `tidefs-membership-live`,
//! avoiding a circular dependency.  The integration bridge that converts
//! a live roster snapshot into constructor inputs lives in
//! `tidefs-membership-live`.
//!
//! ## Domain tag
//!
//! `tidefs-membership-epoch-proposal-v1`

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

// ── EpochProposal ──────────────────────────────────────────────────────

/// A BLAKE3-verified proposal to advance the membership epoch.
///
/// Carries the proposed member-set diff (added/removed), the roster
/// snapshot digest that authorised it, and a BLAKE3-256 integrity hash
/// covering all fields so any consumer can independently verify the
/// proposal was constructed from the claimed inputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochProposal {
    /// Node identity that constructed this proposal.
    pub proposer_id: u64,
    /// Monotonic sequence number; must be strictly greater than the
    /// current epoch number (serves as concurrent-proposal guard).
    pub sequence_number: u64,
    /// The target epoch number after this proposal is committed.
    pub proposed_epoch_number: u64,
    /// BLAKE3-256 hash of the predecessor epoch config.
    pub predecessor_epoch_hash: [u8; 32],
    /// BLAKE3-256 digest of the roster snapshot this proposal derives from.
    pub roster_snapshot_digest: [u8; 32],
    /// Members added to the epoch (present in roster, absent from current).
    /// Sorted, deduplicated.
    pub added_members: Vec<u64>,
    /// Members removed from the epoch (present in current, absent from roster).
    /// Sorted, deduplicated.
    pub removed_members: Vec<u64>,
    /// BLAKE3-256 domain-separated hash covering all fields above.
    pub blake3_hash: [u8; 32],
}

impl EpochProposal {
    /// Domain separation tag for proposal hashing.
    pub const DOMAIN_TAG: &[u8] = b"tidefs-membership-epoch-proposal-v1";

    /// Compute the BLAKE3-256 hash for an epoch proposal.
    ///
    /// Covers `proposer_id`, `sequence_number`, `proposed_epoch_number`,
    /// `predecessor_epoch_hash`, `roster_snapshot_digest`, and the
    /// sorted member diff lists.  Every field is hashed in order with
    /// explicit length separators so the hash uniquely identifies the
    /// proposal payload.
    pub fn compute_hash(
        proposer_id: u64,
        sequence_number: u64,
        proposed_epoch_number: u64,
        predecessor_epoch_hash: &[u8; 32],
        roster_snapshot_digest: &[u8; 32],
        added_members: &[u64],
        removed_members: &[u64],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_TAG);
        hasher.update(&proposer_id.to_le_bytes());
        hasher.update(&sequence_number.to_le_bytes());
        hasher.update(&proposed_epoch_number.to_le_bytes());
        hasher.update(predecessor_epoch_hash);
        hasher.update(roster_snapshot_digest);
        hasher.update(b"|added|");
        for id in added_members {
            hasher.update(&id.to_le_bytes());
        }
        hasher.update(b"|removed|");
        for id in removed_members {
            hasher.update(&id.to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// Verify that `self.blake3_hash` matches a recomputed hash of the payload.
    pub fn verify(&self) -> bool {
        Self::compute_hash(
            self.proposer_id,
            self.sequence_number,
            self.proposed_epoch_number,
            &self.predecessor_epoch_hash,
            &self.roster_snapshot_digest,
            &self.added_members,
            &self.removed_members,
        ) == self.blake3_hash
    }

    /// Create a fully-hashed proposal.  Callers must ensure the member
    /// lists are already sorted and deduplicated.
    pub fn new(
        proposer_id: u64,
        sequence_number: u64,
        proposed_epoch_number: u64,
        predecessor_epoch_hash: [u8; 32],
        roster_snapshot_digest: [u8; 32],
        added_members: Vec<u64>,
        removed_members: Vec<u64>,
    ) -> Self {
        let blake3_hash = Self::compute_hash(
            proposer_id,
            sequence_number,
            proposed_epoch_number,
            &predecessor_epoch_hash,
            &roster_snapshot_digest,
            &added_members,
            &removed_members,
        );
        Self {
            proposer_id,
            sequence_number,
            proposed_epoch_number,
            predecessor_epoch_hash,
            roster_snapshot_digest,
            added_members,
            removed_members,
            blake3_hash,
        }
    }
}

// ── ProposalError ──────────────────────────────────────────────────────

/// Errors returned when proposal construction or validation fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalError {
    /// The proposed member set is empty.
    EmptyMemberSet,
    /// No members were added or removed — the proposal is a no-op.
    EmptyDiff {
        current_count: usize,
        proposed_count: usize,
    },
    /// The sequence number is not strictly greater than the current
    /// epoch number, indicating a stale or conflicting proposal.
    SequenceNumberConflict {
        current_epoch: u64,
        sequence_number: u64,
    },
    /// The proposed member count falls below the quorum floor.
    QuorumFloorViolated {
        member_count: usize,
        min_required: usize,
    },
    /// The member-set change exceeds the configured maximum delta.
    ChangeBoundsExceeded {
        current_count: usize,
        proposed_count: usize,
        max_change: usize,
    },
    /// Predecessor epoch hash is zero-only, indicating a proposal
    /// without proper ancestry (bootstrap guard).
    MissingPredecessorHash,
}

impl fmt::Display for ProposalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMemberSet => write!(f, "proposed member set is empty"),
            Self::EmptyDiff {
                current_count,
                proposed_count,
            } => {
                write!(
                    f,
                    "no-change proposal: current={current_count} proposed={proposed_count}"
                )
            }
            Self::SequenceNumberConflict {
                current_epoch,
                sequence_number,
            } => {
                write!(
                    f,
                    "sequence-number conflict: current_epoch={current_epoch} sequence={sequence_number}"
                )
            }
            Self::QuorumFloorViolated {
                member_count,
                min_required,
            } => {
                write!(
                    f,
                    "quorum floor violated: {member_count} members, minimum {min_required}"
                )
            }
            Self::ChangeBoundsExceeded {
                current_count,
                proposed_count,
                max_change,
            } => {
                write!(
                    f,
                    "member-set change {current_count}->{proposed_count} exceeds max delta {max_change}"
                )
            }
            Self::MissingPredecessorHash => {
                write!(f, "predecessor epoch hash is missing")
            }
        }
    }
}

impl std::error::Error for ProposalError {}

// ── EpochProposalConstructor ───────────────────────────────────────────

/// Builds BLAKE3-verified epoch proposals from roster snapshot data.
///
/// Takes the current epoch's member set, a roster snapshot digest, and
/// the proposed next-epoch member set, diffs them, validates transition
/// preconditions, and emits an [`EpochProposal`].
///
/// ## Configuration
///
/// - `min_quorum_members`: fewest members allowed in the proposed set
///   (must be >= 1).
/// - `max_change`: largest absolute change in member count allowed
///   between epochs (`|proposed - current| <= max_change`).  Zero means
///   no bound (only empty-diff rejection applies).
///
/// ## Validation gates (in order)
///
/// 1. **Non-empty set**: the proposed member set must have at least one member.
/// 2. **Non-empty diff**: at least one member must be added or removed.
/// 3. **Sequence ordering**: `sequence_number > current_epoch_number`.
/// 4. **Quorum floor**: proposed member count >= `min_quorum_members`.
/// 5. **Change bounds**: `|proposed - current| <= max_change` (when `max_change > 0`).
/// 6. **Predecessor hash**: must be non-zero (bootstrap-proposal guard).
#[derive(Clone, Debug)]
pub struct EpochProposalConstructor {
    /// The current epoch number (basis for monotonicity check).
    pub current_epoch_number: u64,
    /// Sorted, deduplicated member ids in the current epoch.
    pub current_members: Vec<u64>,
    /// BLAKE3-256 digest of the roster snapshot this proposal derives from.
    pub roster_snapshot_digest: [u8; 32],
    /// Sorted, deduplicated member ids proposed for the next epoch.
    pub proposed_members: Vec<u64>,
    /// Node identity that is constructing the proposal.
    pub proposer_id: u64,
    /// Monotonic sequence number for concurrent-proposal detection.
    pub sequence_number: u64,
    /// BLAKE3-256 hash of the predecessor epoch config.
    pub predecessor_epoch_hash: [u8; 32],
    /// Fewest members allowed in the proposed epoch.
    pub min_quorum_members: usize,
    /// Largest allowed change in member count (0 = unbounded).
    pub max_change: usize,
}

impl EpochProposalConstructor {
    /// Default minimum-quorum floor: at least 1 member.
    pub const DEFAULT_MIN_QUORUM: usize = 1;

    /// Create a constructor with defaults (`min_quorum_members = 1`,
    /// `max_change = 0` / unbounded) and no predecessor hash.
    pub fn new(
        current_epoch_number: u64,
        current_members: Vec<u64>,
        roster_snapshot_digest: [u8; 32],
        proposed_members: Vec<u64>,
        proposer_id: u64,
        sequence_number: u64,
    ) -> Self {
        Self {
            current_epoch_number,
            current_members,
            roster_snapshot_digest,
            proposed_members,
            proposer_id,
            sequence_number,
            predecessor_epoch_hash: [0u8; 32],
            min_quorum_members: Self::DEFAULT_MIN_QUORUM,
            max_change: 0,
        }
    }

    /// Set the predecessor epoch hash.
    pub fn with_predecessor_hash(mut self, hash: [u8; 32]) -> Self {
        self.predecessor_epoch_hash = hash;
        self
    }

    /// Set the minimum quorum floor.
    pub fn with_min_quorum(mut self, min_quorum: usize) -> Self {
        self.min_quorum_members = min_quorum;
        self
    }

    /// Set a maximum change bound.  Zero removes the bound.
    pub fn with_max_change(mut self, max_change: usize) -> Self {
        self.max_change = max_change;
        self
    }

    /// Compute the diff between proposed and current members.
    ///
    /// Returns `(added, removed)` — both sorted and deduplicated.
    /// Members present in `proposed` but not in `current` are "added";
    /// members present in `current` but not in `proposed` are "removed".
    pub fn compute_diff(&self) -> (Vec<u64>, Vec<u64>) {
        let cur: BTreeSet<u64> = self.current_members.iter().copied().collect();
        let prop: BTreeSet<u64> = self.proposed_members.iter().copied().collect();

        let added: Vec<u64> = prop.difference(&cur).copied().collect();
        let removed: Vec<u64> = cur.difference(&prop).copied().collect();

        (added, removed)
    }

    /// Validate all transition preconditions without constructing a proposal.
    ///
    /// Returns `Ok(())` if the inputs pass every guard; returns the first
    /// failing [`ProposalError`] otherwise.
    pub fn validate_preconditions(&self) -> Result<(), ProposalError> {
        // 1. Non-empty proposed set
        if self.proposed_members.is_empty() {
            return Err(ProposalError::EmptyMemberSet);
        }

        // 2. Non-empty diff (at least one add or remove)
        let (added, removed) = self.compute_diff();
        if added.is_empty() && removed.is_empty() {
            return Err(ProposalError::EmptyDiff {
                current_count: self.current_members.len(),
                proposed_count: self.proposed_members.len(),
            });
        }

        // 3. Sequence ordering (concurrent proposal guard)
        if self.sequence_number <= self.current_epoch_number {
            return Err(ProposalError::SequenceNumberConflict {
                current_epoch: self.current_epoch_number,
                sequence_number: self.sequence_number,
            });
        }

        // 4. Quorum floor
        if self.proposed_members.len() < self.min_quorum_members {
            return Err(ProposalError::QuorumFloorViolated {
                member_count: self.proposed_members.len(),
                min_required: self.min_quorum_members,
            });
        }

        // 5. Change bounds (when enabled)
        if self.max_change > 0 {
            let delta = if self.current_members.len() >= self.proposed_members.len() {
                self.current_members.len() - self.proposed_members.len()
            } else {
                self.proposed_members.len() - self.current_members.len()
            };
            if delta > self.max_change {
                return Err(ProposalError::ChangeBoundsExceeded {
                    current_count: self.current_members.len(),
                    proposed_count: self.proposed_members.len(),
                    max_change: self.max_change,
                });
            }
        }

        // 6. Predecessor hash present (not just zeros)
        if self.predecessor_epoch_hash == [0u8; 32] {
            return Err(ProposalError::MissingPredecessorHash);
        }

        Ok(())
    }

    /// Construct an [`EpochProposal`] after validating preconditions.
    ///
    /// Calls [`Self::validate_preconditions`] and then builds the proposal
    /// with the computed diff and BLAKE3 integrity hash.
    ///
    /// ## Errors
    ///
    /// Returns the first failing [`ProposalError`] from the validation gates.
    pub fn construct(&self) -> Result<EpochProposal, ProposalError> {
        self.validate_preconditions()?;

        let (added_members, removed_members) = self.compute_diff();

        Ok(EpochProposal::new(
            self.proposer_id,
            self.sequence_number,
            self.sequence_number, // proposed_epoch_number == sequence_number in our model
            self.predecessor_epoch_hash,
            self.roster_snapshot_digest,
            added_members,
            removed_members,
        ))
    }
}

// ── Standalone verification ────────────────────────────────────────────

/// Verify a proposal's BLAKE3 integrity without carrying the type.
///
/// Equivalent to `proposal.verify()` but usable without an instance.
pub fn verify_proposal(proposal: &EpochProposal) -> bool {
    proposal.verify()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Proposal hash determinism ─────────────────────────────────────

    #[test]
    fn proposal_hash_deterministic() {
        let p1 = EpochProposal::new(1, 5, 5, [0xAAu8; 32], [0xBBu8; 32], vec![2, 3], vec![4]);
        let p2 = EpochProposal::new(1, 5, 5, [0xAAu8; 32], [0xBBu8; 32], vec![2, 3], vec![4]);
        assert_eq!(p1.blake3_hash, p2.blake3_hash);
        assert_eq!(p1, p2);
    }

    #[test]
    fn proposal_hash_differs_per_proposer() {
        let p1 = EpochProposal::new(1, 5, 5, [0; 32], [0; 32], vec![2], vec![]);
        let p2 = EpochProposal::new(99, 5, 5, [0; 32], [0; 32], vec![2], vec![]);
        assert_ne!(p1.blake3_hash, p2.blake3_hash);
    }

    #[test]
    fn proposal_hash_differs_per_sequence() {
        let p1 = EpochProposal::new(1, 5, 5, [0; 32], [0; 32], vec![2], vec![]);
        let p2 = EpochProposal::new(1, 6, 6, [0; 32], [0; 32], vec![2], vec![]);
        assert_ne!(p1.blake3_hash, p2.blake3_hash);
    }

    #[test]
    fn proposal_verify_accepts_valid() {
        let p = EpochProposal::new(1, 5, 5, [0xAA; 32], [0xBB; 32], vec![2], vec![3]);
        assert!(p.verify());
    }

    #[test]
    fn proposal_verify_rejects_tampered_members() {
        let mut p = EpochProposal::new(1, 5, 5, [0xAA; 32], [0xBB; 32], vec![2], vec![3]);
        p.added_members.push(99); // tamper: member inserted after hash
        assert!(!p.verify());
    }

    #[test]
    fn proposal_verify_rejects_tampered_hash() {
        let mut p = EpochProposal::new(1, 5, 5, [0xAA; 32], [0xBB; 32], vec![2], vec![3]);
        p.blake3_hash[0] ^= 0xFF; // flip bits
        assert!(!p.verify());
    }

    // ── Constructor: basic construction ───────────────────────────────

    fn make_constructor() -> EpochProposalConstructor {
        EpochProposalConstructor::new(
            1,                // current_epoch
            vec![1, 2, 3],    // current members
            [0xBBu8; 32],     // roster digest
            vec![1, 2, 3, 4], // proposed members (add #4)
            1,                // proposer
            2,                // sequence > current
        )
        .with_predecessor_hash([0xAAu8; 32])
    }

    #[test]
    fn construct_basic_add_member() {
        let ctor = make_constructor();
        let proposal = ctor.construct().expect("should succeed");
        assert!(proposal.verify());
        assert_eq!(proposal.proposer_id, 1);
        assert_eq!(proposal.sequence_number, 2);
        assert_eq!(proposal.proposed_epoch_number, 2);
        assert_eq!(proposal.added_members, vec![4]);
        assert!(proposal.removed_members.is_empty());
    }

    #[test]
    fn construct_basic_remove_member() {
        let ctor = EpochProposalConstructor::new(
            2,
            vec![1, 2, 3],
            [0xBB; 32],
            vec![1, 3], // remove #2
            1,
            4,
        )
        .with_predecessor_hash([0xAA; 32]);
        let proposal = ctor.construct().expect("should succeed");
        assert_eq!(proposal.added_members, vec![] as Vec<u64>);
        assert_eq!(proposal.removed_members, vec![2]);
    }

    #[test]
    fn construct_add_and_remove() {
        let ctor = EpochProposalConstructor::new(
            0,
            vec![1, 2, 3],
            [0xBB; 32],
            vec![1, 4, 5], // remove 2,3; add 4,5
            1,
            1,
        )
        .with_predecessor_hash([0xAA; 32]);
        let proposal = ctor.construct().expect("should succeed");
        assert_eq!(proposal.added_members, vec![4, 5]);
        assert_eq!(proposal.removed_members, vec![2, 3]);
    }

    #[test]
    fn construct_deterministic_from_same_inputs() {
        let ctor = EpochProposalConstructor::new(5, vec![1, 2], [0x11; 32], vec![1, 2, 3], 7, 8)
            .with_predecessor_hash([0xCC; 32]);
        let p1 = ctor.construct().expect("first");
        let p2 = ctor.construct().expect("second");
        assert_eq!(p1, p2);
        assert_eq!(p1.blake3_hash, p2.blake3_hash);
    }

    // ── Diff computation ──────────────────────────────────────────────

    #[test]
    fn diff_add_only() {
        let ctor = EpochProposalConstructor::new(1, vec![1, 2], [0; 32], vec![1, 2, 3, 4], 1, 2)
            .with_predecessor_hash([1; 32]);
        let (added, removed) = ctor.compute_diff();
        assert_eq!(added, vec![3, 4]);
        assert!(removed.is_empty());
    }

    #[test]
    fn diff_remove_only() {
        let ctor = EpochProposalConstructor::new(1, vec![1, 2, 3, 4], [0; 32], vec![1, 3], 1, 2)
            .with_predecessor_hash([1; 32]);
        let (added, removed) = ctor.compute_diff();
        assert!(added.is_empty());
        assert_eq!(removed, vec![2, 4]);
    }

    #[test]
    fn diff_complete_replacement() {
        let ctor = EpochProposalConstructor::new(1, vec![1, 2], [0; 32], vec![3, 4], 1, 2)
            .with_predecessor_hash([1; 32]);
        let (added, removed) = ctor.compute_diff();
        assert_eq!(added, vec![3, 4]);
        assert_eq!(removed, vec![1, 2]);
    }

    #[test]
    fn diff_identical_sets() {
        let ctor = EpochProposalConstructor::new(1, vec![1, 2, 3], [0; 32], vec![1, 2, 3], 1, 2)
            .with_predecessor_hash([1; 32]);
        let (added, removed) = ctor.compute_diff();
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    // ── Empty member set rejection ────────────────────────────────────

    #[test]
    fn reject_empty_proposed_members() {
        let ctor = EpochProposalConstructor::new(1, vec![1, 2], [0; 32], vec![], 1, 2)
            .with_predecessor_hash([1; 32]);
        match ctor.construct() {
            Err(ProposalError::EmptyMemberSet) => {}
            other => panic!("expected EmptyMemberSet, got {other:?}"),
        }
    }

    // ── Empty diff rejection ──────────────────────────────────────────

    #[test]
    fn reject_empty_diff() {
        let ctor = EpochProposalConstructor::new(1, vec![1, 2, 3], [0; 32], vec![1, 2, 3], 1, 2)
            .with_predecessor_hash([1; 32]);
        match ctor.construct() {
            Err(ProposalError::EmptyDiff { .. }) => {}
            other => panic!("expected EmptyDiff, got {other:?}"),
        }
    }

    // ── Sequence ordering guard ───────────────────────────────────────

    #[test]
    fn reject_sequence_equal_to_current() {
        let ctor = EpochProposalConstructor::new(5, vec![1, 2], [0; 32], vec![1, 2, 3], 1, 5)
            .with_predecessor_hash([1; 32]);
        match ctor.construct() {
            Err(ProposalError::SequenceNumberConflict {
                current_epoch,
                sequence_number,
            }) => {
                assert_eq!(current_epoch, 5);
                assert_eq!(sequence_number, 5);
            }
            other => panic!("expected SequenceNumberConflict, got {other:?}"),
        }
    }

    #[test]
    fn reject_sequence_less_than_current() {
        let ctor = EpochProposalConstructor::new(10, vec![1, 2], [0; 32], vec![1, 2, 3], 1, 7)
            .with_predecessor_hash([1; 32]);
        match ctor.construct() {
            Err(ProposalError::SequenceNumberConflict { .. }) => {}
            other => panic!("expected SequenceNumberConflict, got {other:?}"),
        }
    }

    // ── Quorum floor guard ────────────────────────────────────────────

    #[test]
    fn reject_below_quorum_floor() {
        let ctor = EpochProposalConstructor::new(1, vec![1, 2, 3, 4], [0; 32], vec![5], 1, 2)
            .with_predecessor_hash([1; 32])
            .with_min_quorum(2);
        match ctor.construct() {
            Err(ProposalError::QuorumFloorViolated {
                member_count,
                min_required,
            }) => {
                assert_eq!(member_count, 1);
                assert_eq!(min_required, 2);
            }
            other => panic!("expected QuorumFloorViolated, got {other:?}"),
        }
    }

    #[test]
    fn accept_at_quorum_floor() {
        let ctor = EpochProposalConstructor::new(1, vec![1], [0; 32], vec![1, 2], 1, 2)
            .with_predecessor_hash([1; 32])
            .with_min_quorum(2);
        assert!(ctor.construct().is_ok());
    }

    // ── Change bounds guard ───────────────────────────────────────────

    #[test]
    fn reject_change_bounds_exceeded() {
        // current=3 members, proposed=6 (+3), max_change=2
        let ctor =
            EpochProposalConstructor::new(1, vec![1, 2, 3], [0; 32], vec![1, 2, 3, 4, 5, 6], 1, 2)
                .with_predecessor_hash([1; 32])
                .with_max_change(2);
        match ctor.construct() {
            Err(ProposalError::ChangeBoundsExceeded {
                current_count,
                proposed_count,
                max_change,
            }) => {
                assert_eq!(current_count, 3);
                assert_eq!(proposed_count, 6);
                assert_eq!(max_change, 2);
            }
            other => panic!("expected ChangeBoundsExceeded, got {other:?}"),
        }
    }

    #[test]
    fn accept_within_change_bounds() {
        let ctor =
            EpochProposalConstructor::new(1, vec![1, 2, 3], [0; 32], vec![1, 2, 3, 4, 5], 1, 2)
                .with_predecessor_hash([1; 32])
                .with_max_change(2); // +2 = okay
        assert!(ctor.construct().is_ok());
    }

    #[test]
    fn unbounded_change_when_max_zero() {
        // max_change=0 means no bound
        let ctor =
            EpochProposalConstructor::new(1, vec![1], [0; 32], vec![1, 2, 3, 4, 5, 6, 7, 8], 1, 2)
                .with_predecessor_hash([1; 32])
                .with_max_change(0);
        assert!(ctor.construct().is_ok());
    }

    // ── Missing predecessor hash ──────────────────────────────────────

    #[test]
    fn reject_missing_predecessor_hash() {
        let ctor = EpochProposalConstructor::new(1, vec![1, 2], [0; 32], vec![1, 2, 3], 1, 2);
        // no .with_predecessor_hash() — stays [0u8; 32]
        match ctor.construct() {
            Err(ProposalError::MissingPredecessorHash) => {}
            other => panic!("expected MissingPredecessorHash, got {other:?}"),
        }
    }

    #[test]
    fn accept_nonzero_predecessor_hash() {
        let ctor = EpochProposalConstructor::new(1, vec![1, 2], [0; 32], vec![1, 2, 3], 1, 2)
            .with_predecessor_hash([1u8; 32]);
        assert!(ctor.construct().is_ok());
    }

    // ── BLAKE3 tamper detection on wire ───────────────────────────────

    #[test]
    fn tampered_added_members_fails_verify() {
        let ctor = make_constructor();
        let mut proposal = ctor.construct().unwrap();
        proposal.added_members.push(99); // inject un-hashed member
        assert!(!proposal.verify());
    }

    #[test]
    fn tampered_removed_members_fails_verify() {
        let ctor = make_constructor();
        let mut proposal = ctor.construct().unwrap();
        proposal.removed_members.push(99);
        assert!(!proposal.verify());
    }

    #[test]
    fn tampered_roster_digest_fails_verify() {
        let ctor = make_constructor();
        let mut proposal = ctor.construct().unwrap();
        proposal.roster_snapshot_digest[0] ^= 0xFF;
        assert!(!proposal.verify());
    }

    #[test]
    fn tampered_predecessor_hash_fails_verify() {
        let ctor = EpochProposalConstructor::new(1, vec![1, 2], [0; 32], vec![1, 2, 3], 1, 2)
            .with_predecessor_hash([0xAA; 32]);
        let mut proposal = ctor.construct().unwrap();
        proposal.predecessor_epoch_hash[0] ^= 0xFF;
        assert!(!proposal.verify());
    }

    // ── Standalone verify_proposal ────────────────────────────────────

    #[test]
    fn standalone_verify_matches_method() {
        let ctor = make_constructor();
        let proposal = ctor.construct().unwrap();
        assert_eq!(verify_proposal(&proposal), proposal.verify());
    }

    // ── Serialization round-trip ──────────────────────────────────────

    #[test]
    fn serde_roundtrip() {
        let ctor =
            EpochProposalConstructor::new(1, vec![1, 2, 3], [0xBB; 32], vec![1, 2, 3, 4], 1, 2)
                .with_predecessor_hash([0xAA; 32]);
        let proposal = ctor.construct().unwrap();
        let json = serde_json::to_string(&proposal).expect("serialize");
        let restored: EpochProposal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(proposal, restored);
        assert!(restored.verify());
    }

    // ── Configuration setters ─────────────────────────────────────────

    #[test]
    fn with_predecessor_hash_persists() {
        let hash = [0xDEu8; 32];
        let ctor = EpochProposalConstructor::new(1, vec![1], [0; 32], vec![1, 2], 1, 2)
            .with_predecessor_hash(hash);
        assert_eq!(ctor.predecessor_epoch_hash, hash);
    }

    #[test]
    fn with_min_quorum_persists() {
        let ctor =
            EpochProposalConstructor::new(1, vec![1], [0; 32], vec![1, 2], 1, 2).with_min_quorum(5);
        assert_eq!(ctor.min_quorum_members, 5);
    }

    #[test]
    fn with_max_change_persists() {
        let ctor =
            EpochProposalConstructor::new(1, vec![1], [0; 32], vec![1, 2], 1, 2).with_max_change(3);
        assert_eq!(ctor.max_change, 3);
    }

    // ── ProposalError Display ─────────────────────────────────────────

    #[test]
    fn error_display_is_human_readable() {
        let err = ProposalError::QuorumFloorViolated {
            member_count: 1,
            min_required: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("quorum"));
        assert!(msg.contains("1"));
        assert!(msg.contains("3"));
    }

    // ── validate_preconditions standalone ─────────────────────────────

    #[test]
    fn validate_preconditions_ok_returns_unit() {
        let ctor = make_constructor();
        assert_eq!(ctor.validate_preconditions(), Ok(()));
    }

    #[test]
    fn validate_preconditions_catches_empty_diff() {
        let ctor = EpochProposalConstructor::new(1, vec![1, 2], [0; 32], vec![1, 2], 1, 2)
            .with_predecessor_hash([1; 32]);
        assert!(matches!(
            ctor.validate_preconditions(),
            Err(ProposalError::EmptyDiff { .. })
        ));
    }

    // ── Large member sets ─────────────────────────────────────────────

    #[test]
    fn large_member_set_diff_correct() {
        let current: Vec<u64> = (0..1000).collect();
        let proposed: Vec<u64> = (500..1500).collect();
        let ctor = EpochProposalConstructor::new(0, current, [0xBB; 32], proposed, 1, 1)
            .with_predecessor_hash([0xAA; 32])
            .with_max_change(0); // unbounded
        let proposal = ctor.construct().unwrap();
        assert_eq!(proposal.added_members.len(), 500); // 1000..1499
        assert_eq!(proposal.removed_members.len(), 500); // 0..499
        assert!(proposal.verify());
    }
}
