// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Epoch-chain verification with deterministic fork detection.
//!
//! [`EpochChainVerifier`] validates that an incoming epoch proposal forms
//! a valid chain extending from the locally committed epoch. It enforces:
//!
//! - **Monotonicity**: the proposed epoch must be strictly greater than the
//!   committed epoch.
//! - **Consecutive transition**: the proposed epoch must equal the committed
//!   epoch plus one (no gaps).
//! - **Fork detection**: if two different peers propose conflicting member
//!   sets for the same successor epoch, the second proposal is flagged as a
//!   fork.
//!
//! The verifier is a local validation step executed before the
//! [`MembershipEpochAgreement`](crate::agreement::MembershipEpochAgreement)
//! accepts a proposal. It does not modify the wire format.

use std::collections::HashMap;

// ── ChainError ──────────────────────────────────────────────────────

/// Errors returned by epoch-chain verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainError {
    /// The proposed epoch is not strictly greater than the committed epoch.
    NotMonotonic { committed: u64, proposed: u64 },
    /// The proposed epoch is not exactly committed + 1 (gap in the chain).
    InvalidTransition { committed: u64, proposed: u64 },
    /// Another peer proposed a conflicting member set for the same epoch.
    ForkDetected {
        /// The peer that previously proposed this epoch.
        conflicting_peer: u64,
        /// The local committed member set at the time of verification.
        our_view: Vec<u64>,
        /// The conflicting member set proposed by the other peer.
        their_view: Vec<u64>,
    },
    /// The proposal's parent epoch is ahead of the locally committed epoch.
    GapDetected {
        proposal_parent: u64,
        local_committed: u64,
    },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotMonotonic {
                committed,
                proposed,
            } => {
                write!(
                    f,
                    "proposed epoch {proposed} is not greater than committed epoch {committed}"
                )
            }
            Self::InvalidTransition {
                committed,
                proposed,
            } => {
                write!(
                    f,
                    "invalid epoch transition: committed={committed}, proposed={proposed} (must be exactly committed+1)"
                )
            }
            Self::ForkDetected {
                conflicting_peer,
                our_view: _,
                their_view: _,
            } => {
                write!(
                    f,
                    "fork detected: peer {conflicting_peer} proposed a conflicting member set"
                )
            }
            Self::GapDetected {
                proposal_parent,
                local_committed,
            } => {
                write!(
                    f,
                    "gap detected: proposal parent epoch {proposal_parent} is ahead of local committed epoch {local_committed}"
                )
            }
        }
    }
}

impl std::error::Error for ChainError {}

// ── ProposalRecord ──────────────────────────────────────────────────

/// A record of a proposal seen by the verifier, used for fork detection.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProposalRecord {
    /// The peer that proposed this epoch.
    proposer_id: u64,
    /// Sorted, deduplicated member set in the proposal.
    member_set: Vec<u64>,
}

// ── EpochChainVerifier ──────────────────────────────────────────────

/// Verifies that an incoming epoch proposal forms a valid chain extending
/// from the locally committed epoch.
///
/// The verifier is stateful: it tracks proposals seen for each successor
/// epoch to detect forks. Call [`reset`](EpochChainVerifier::reset) between
/// agreement rounds to clear fork-detection state.
///
/// # Fork detection rules
///
/// - If two different peers propose the **same** member set for the same
///   successor epoch, the second is silently accepted (non-fork dedup).
/// - If two different peers propose **different** member sets for the same
///   successor epoch, the second is rejected as [`ChainError::ForkDetected`].
/// - The same peer re-proposing the same epoch with the same member set is
///   accepted (idempotent re-proposal).
#[derive(Clone, Debug, Default)]
pub struct EpochChainVerifier {
    /// Proposals seen indexed by successor epoch number.
    seen: HashMap<u64, ProposalRecord>,
}

impl EpochChainVerifier {
    /// Create a new, empty verifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// Reset fork-detection state. Call between agreement rounds so that
    /// previously-seen proposals do not interfere with new rounds.
    pub fn reset(&mut self) {
        self.seen.clear();
    }

    /// Verify that a proposed epoch is a valid chain successor to the
    /// locally committed epoch.
    ///
    /// # Arguments
    ///
    /// * `proposer_id` — node identity of the proposing peer.
    /// * `proposed_epoch` — the epoch number being proposed.
    /// * `proposed_members` — sorted, deduplicated member ids in the proposal.
    /// * `committed_epoch` — the locally committed epoch number.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::NotMonotonic`] if `proposed_epoch <= committed_epoch`.
    /// Returns [`ChainError::InvalidTransition`] if `proposed_epoch != committed_epoch + 1`.
    /// Returns [`ChainError::ForkDetected`] if a different peer already proposed
    /// a conflicting member set for `proposed_epoch`.
    pub fn verify_proposal(
        &mut self,
        proposer_id: u64,
        proposed_epoch: u64,
        proposed_members: &[u64],
        committed_epoch: u64,
    ) -> Result<(), ChainError> {
        // Monotonicity: proposed must be strictly greater than committed.
        if proposed_epoch <= committed_epoch {
            return Err(ChainError::NotMonotonic {
                committed: committed_epoch,
                proposed: proposed_epoch,
            });
        }

        // Consecutive transition: proposed must be exactly committed + 1.
        if proposed_epoch != committed_epoch + 1 {
            return Err(ChainError::InvalidTransition {
                committed: committed_epoch,
                proposed: proposed_epoch,
            });
        }

        // Fork detection: check if this successor epoch was already proposed.
        let mut sorted = proposed_members.to_vec();
        sorted.sort();
        sorted.dedup();

        if let Some(existing) = self.seen.get(&proposed_epoch) {
            // Same peer re-proposing the same member set: accept (idempotent).
            if existing.proposer_id == proposer_id && existing.member_set == sorted {
                return Ok(());
            }

            // Different peer, same member set: non-fork dedup, accept.
            if existing.member_set == sorted {
                return Ok(());
            }

            // Different member set → fork.
            return Err(ChainError::ForkDetected {
                conflicting_peer: existing.proposer_id,
                our_view: sorted.clone(),
                their_view: existing.member_set.clone(),
            });
        }

        // Record this proposal for future fork detection.
        self.seen.insert(
            proposed_epoch,
            ProposalRecord {
                proposer_id,
                member_set: sorted,
            },
        );

        Ok(())
    }

    /// The number of proposals currently tracked.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.seen.len()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Valid successor ──────────────────────────────────────────────

    #[test]
    fn valid_successor_is_accepted() {
        let mut verifier = EpochChainVerifier::new();
        let result = verifier.verify_proposal(
            1,          // proposer_id
            6,          // proposed_epoch
            &[1, 2, 3], // proposed_members
            5,          // committed_epoch
        );
        assert!(result.is_ok());
        assert_eq!(verifier.tracked_count(), 1);
    }

    #[test]
    fn valid_successor_with_single_member() {
        let mut verifier = EpochChainVerifier::new();
        let result = verifier.verify_proposal(1, 1, &[42], 0);
        assert!(result.is_ok());
    }

    // ── Non-monotonic ───────────────────────────────────────────────

    #[test]
    fn proposed_less_than_committed_is_rejected() {
        let mut verifier = EpochChainVerifier::new();
        let result = verifier.verify_proposal(1, 3, &[1, 2], 5);
        assert!(matches!(
            result,
            Err(ChainError::NotMonotonic {
                committed: 5,
                proposed: 3,
            })
        ));
    }

    #[test]
    fn proposed_equal_to_committed_is_rejected() {
        let mut verifier = EpochChainVerifier::new();
        let result = verifier.verify_proposal(1, 5, &[1, 2], 5);
        assert!(matches!(
            result,
            Err(ChainError::NotMonotonic {
                committed: 5,
                proposed: 5,
            })
        ));
    }

    // ── Invalid transition (gap) ─────────────────────────────────────

    #[test]
    fn gap_in_epoch_chain_is_rejected() {
        let mut verifier = EpochChainVerifier::new();
        // committed=3, proposed=7 (should be 4)
        let result = verifier.verify_proposal(1, 7, &[1, 2], 3);
        assert!(matches!(
            result,
            Err(ChainError::InvalidTransition {
                committed: 3,
                proposed: 7,
            })
        ));
    }

    #[test]
    fn gap_of_two_is_rejected() {
        let mut verifier = EpochChainVerifier::new();
        let result = verifier.verify_proposal(1, 5, &[1, 2], 3);
        assert!(matches!(
            result,
            Err(ChainError::InvalidTransition {
                committed: 3,
                proposed: 5,
            })
        ));
    }

    // ── Fork detection ──────────────────────────────────────────────

    #[test]
    fn fork_is_detected_when_different_peers_propose_different_member_sets() {
        let mut verifier = EpochChainVerifier::new();
        // Peer 1 proposes epoch 4 with members [1, 2, 3]
        verifier.verify_proposal(1, 4, &[1, 2, 3], 3).unwrap();
        // Peer 2 proposes epoch 4 with members [1, 2, 4] → fork
        let result = verifier.verify_proposal(2, 4, &[1, 2, 4], 3);
        assert!(matches!(
            result,
            Err(ChainError::ForkDetected {
                conflicting_peer: 1,
                ..
            })
        ));
    }

    #[test]
    fn fork_is_detected_when_different_peers_propose_different_size_member_sets() {
        let mut verifier = EpochChainVerifier::new();
        // Peer 1 proposes with 3 members
        verifier.verify_proposal(1, 4, &[1, 2, 3], 3).unwrap();
        // Peer 2 proposes with 2 members (different set) → fork
        let result = verifier.verify_proposal(2, 4, &[1, 2], 3);
        assert!(matches!(result, Err(ChainError::ForkDetected { .. })));
    }

    #[test]
    fn non_fork_dedup_same_member_set_different_peer() {
        let mut verifier = EpochChainVerifier::new();
        // Peer 1 proposes epoch 4 with members [1, 2, 3]
        verifier.verify_proposal(1, 4, &[1, 2, 3], 3).unwrap();
        // Peer 2 proposes epoch 4 with same members [1, 2, 3] → not a fork
        let result = verifier.verify_proposal(2, 4, &[1, 2, 3], 3);
        assert!(result.is_ok());
        // Only one entry tracked (non-fork dedup doesn't add a new one)
        assert_eq!(verifier.tracked_count(), 1);
    }

    #[test]
    fn idempotent_reproposal_by_same_peer_is_accepted() {
        let mut verifier = EpochChainVerifier::new();
        verifier.verify_proposal(1, 4, &[1, 2, 3], 3).unwrap();
        // Same peer, same epoch, same members → idempotent
        let result = verifier.verify_proposal(1, 4, &[1, 2, 3], 3);
        assert!(result.is_ok());
        assert_eq!(verifier.tracked_count(), 1);
    }

    #[test]
    fn fork_detection_is_per_epoch_independent() {
        let mut verifier = EpochChainVerifier::new();
        // Epoch 4 proposed by peer 1
        verifier.verify_proposal(1, 4, &[1, 2, 3], 3).unwrap();
        // Epoch 5 proposed by peer 2 with different members — different epoch, no fork
        let result = verifier.verify_proposal(2, 5, &[1, 2, 4], 4);
        assert!(result.is_ok());
    }

    #[test]
    fn committed_epoch_zero_valid_transition_to_one() {
        let mut verifier = EpochChainVerifier::new();
        let result = verifier.verify_proposal(1, 1, &[1, 2, 3], 0);
        assert!(result.is_ok());
    }

    // ── Reset ────────────────────────────────────────────────────────

    #[test]
    fn reset_clears_fork_detection_state() {
        let mut verifier = EpochChainVerifier::new();
        verifier.verify_proposal(1, 4, &[1, 2, 3], 3).unwrap();
        assert_eq!(verifier.tracked_count(), 1);
        verifier.reset();
        assert_eq!(verifier.tracked_count(), 0);
        // After reset, peer 2 can propose a different set without fork error
        let result = verifier.verify_proposal(2, 4, &[1, 2, 4], 3);
        assert!(result.is_ok());
    }

    // ── Unsorted input ──────────────────────────────────────────────

    #[test]
    fn unsorted_member_set_is_sorted_internally() {
        let mut verifier = EpochChainVerifier::new();
        verifier.verify_proposal(1, 4, &[3, 1, 2], 3).unwrap();
        // Peer 2 proposes same set but in different order → non-fork dedup
        let result = verifier.verify_proposal(2, 4, &[2, 3, 1], 3);
        assert!(result.is_ok());
    }

    #[test]
    fn duplicate_members_are_deduplicated() {
        let mut verifier = EpochChainVerifier::new();
        verifier.verify_proposal(1, 4, &[1, 1, 2, 2, 3], 3).unwrap();
        let result = verifier.verify_proposal(2, 4, &[1, 2, 3], 3);
        assert!(result.is_ok());
    }
}
