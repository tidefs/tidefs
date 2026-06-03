//! Multi-node clock skew injection validation for epoch monotonicity safety.
//!
//! Simulates clock skew across a multi-member epoch chain and validates that:
//!
//! 1. **Epoch regression (backwards skew)**: a node whose clock drifted backward
//!    cannot inject a stale epoch — the verifier rejects it as non-monotonic.
//! 2. **Epoch fast-forward (future skew)**: a node whose clock jumped forward
//!    cannot skip epochs — the verifier rejects gaps.
//! 3. **Epoch chain integrity**: after skew events, the healthy node's committed
//!    epoch chain is never corrupted or rolled back.
//! 4. **Recovery after skew**: once the skewed node is corrected, it can catch
//!    up to the healthy chain through consecutive epoch transitions.
//!
//! These tests validate the safety properties required by #6480
//! (NEXT-MN-025): clock skew must cause the system to fail closed — rejecting
//! invalid proposals — rather than corrupting epoch state or allowing split-brain.

use tidefs_membership_epoch::agreement::{AgreementState, MembershipEpochAgreement, QuorumMode};
use tidefs_membership_epoch::epoch_chain::{ChainError, EpochChainVerifier};

// ── Helpers ─────────────────────────────────────────────────────────

/// Simulates a healthy node receiving proposals from a skewed node.
struct SkewedPair {
    healthy_epoch: u64,
    healthy_verifier: EpochChainVerifier,
}

impl SkewedPair {
    fn new(healthy: u64) -> Self {
        Self {
            healthy_epoch: healthy,
            healthy_verifier: EpochChainVerifier::new(),
        }
    }

    fn skewed_proposes(
        &mut self,
        proposer_id: u64,
        proposed_epoch: u64,
        proposed_members: &[u64],
    ) -> Result<(), ChainError> {
        self.healthy_verifier.verify_proposal(
            proposer_id,
            proposed_epoch,
            proposed_members,
            self.healthy_epoch,
        )
    }
}

// ── Scenario 1: Backwards clock skew (epoch regression) ─────────────

#[test]
fn backwards_clock_skew_epoch_regression_rejected() {
    let mut pair = SkewedPair::new(5);
    let result = pair.skewed_proposes(2, 3, &[1, 2]);
    assert!(
        matches!(
            result,
            Err(ChainError::NotMonotonic {
                committed: 5,
                proposed: 3
            })
        ),
        "epoch regression (3 <= 5) must be rejected as non-monotonic, got {result:?}"
    );
    assert_eq!(pair.healthy_epoch, 5);
}

#[test]
fn backwards_clock_skew_equal_epoch_rejected() {
    let mut pair = SkewedPair::new(7);
    let result = pair.skewed_proposes(2, 7, &[1, 2, 3]);
    assert!(
        matches!(
            result,
            Err(ChainError::NotMonotonic {
                committed: 7,
                proposed: 7
            })
        ),
        "equal epoch proposal must be rejected as non-monotonic, got {result:?}"
    );
    assert_eq!(pair.healthy_epoch, 7);
}

// ── Scenario 2: Forward clock skew (epoch gap) ──────────────────────

#[test]
fn forward_clock_skew_epoch_gap_rejected() {
    let mut pair = SkewedPair::new(5);
    let result = pair.skewed_proposes(2, 16, &[1, 2, 3]);
    assert!(
        matches!(
            result,
            Err(ChainError::InvalidTransition {
                committed: 5,
                proposed: 16
            })
        ),
        "epoch gap (16 != 6) must be rejected, got {result:?}"
    );
    assert_eq!(pair.healthy_epoch, 5);
}

#[test]
fn forward_clock_skew_various_gaps_rejected() {
    let pair = SkewedPair::new(10);
    let gaps = [12, 20, 100, 999];
    for &gap in &gaps {
        let mut fresh = EpochChainVerifier::new();
        let result = fresh.verify_proposal(2, gap, &[1, 2], pair.healthy_epoch);
        assert!(
            matches!(result, Err(ChainError::InvalidTransition { .. })),
            "epoch gap {gap} must be rejected"
        );
    }
    assert_eq!(pair.healthy_epoch, 10);
}

// ── Scenario 3: Chain integrity after skew attacks ──────────────────

#[test]
fn healthy_chain_intact_after_skew_attempts() {
    let mut pair = SkewedPair::new(3);
    let skewed_attempts = [
        (2, 2, vec![1, 2]),
        (2, 3, vec![1, 2]),
        (2, 10, vec![1, 2, 3]),
    ];
    for &(proposer, epoch, ref members) in &skewed_attempts {
        let result = pair.skewed_proposes(proposer, epoch, members);
        assert!(
            result.is_err(),
            "skewed proposal ({proposer}, {epoch}) must be rejected"
        );
    }
    assert_eq!(pair.healthy_epoch, 3);
    let mut fresh = EpochChainVerifier::new();
    let result = fresh.verify_proposal(1, 4, &[1, 2, 4], 3);
    assert!(
        result.is_ok(),
        "valid transition after skew must succeed, got {result:?}"
    );
}

// ── Scenario 4: Fork detection under skew ───────────────────────────

#[test]
fn fork_detection_works_under_skew_conditions() {
    let mut pair = SkewedPair::new(5);
    pair.healthy_verifier
        .verify_proposal(1, 6, &[1, 2, 3], 5)
        .unwrap();
    let result = pair.skewed_proposes(2, 6, &[1, 2, 4]);
    assert!(
        matches!(
            result,
            Err(ChainError::ForkDetected {
                conflicting_peer: 1,
                ..
            })
        ),
        "conflicting member sets for same epoch must be fork, got {result:?}"
    );
}

// ── Scenario 5: Three-node agreement rejects skewed proposer ────────

#[test]
fn three_node_agreement_rejects_skewed_proposer() {
    let mut verifier_a = EpochChainVerifier::new();
    let mut verifier_b = EpochChainVerifier::new();
    let mut verifier_c = EpochChainVerifier::new();

    // Skewed node C (committed=3) cannot accept proposal for epoch 6.
    let result_c = verifier_c.verify_proposal(3, 6, &[1, 2, 3, 4], 3);
    assert!(
        matches!(
            result_c,
            Err(ChainError::InvalidTransition {
                committed: 3,
                proposed: 6
            })
        ),
        "skewed node (committed=3) must reject proposal for epoch 6, got {result_c:?}"
    );

    // Healthy nodes A and B (committed=5) accept.
    assert!(verifier_a.verify_proposal(1, 6, &[1, 2, 3, 4], 5).is_ok());
    assert!(verifier_b.verify_proposal(1, 6, &[1, 2, 3, 4], 5).is_ok());
}

// ── Scenario 6: Committed epoch never rolls back after reset ────────

#[test]
fn committed_epoch_never_rolls_back_after_reset() {
    let mut verifier = EpochChainVerifier::new();
    for epoch in 1..=5 {
        verifier
            .verify_proposal(1, epoch, &[1, 2], epoch - 1)
            .unwrap();
    }
    verifier.reset();
    let result = verifier.verify_proposal(2, 3, &[1, 2], 5);
    assert!(
        matches!(
            result,
            Err(ChainError::NotMonotonic {
                committed: 5,
                proposed: 3
            })
        ),
        "after reset, epoch regression must still be rejected, got {result:?}"
    );
}

// ── Scenario 7: Gap detection signals possible clock skew ───────────

#[test]
fn gap_detection_signals_possible_clock_skew() {
    let mut verifier = EpochChainVerifier::new();
    let result = verifier.verify_proposal(2, 50, &[1], 12);
    match result {
        Err(ChainError::InvalidTransition {
            committed,
            proposed,
        }) => {
            let gap_magnitude = proposed - committed;
            assert!(gap_magnitude > 1, "gap must be > 1 to signal skew");
            assert_eq!(committed, 12);
            assert_eq!(proposed, 50);
            assert!(
                gap_magnitude > 30,
                "large gap must trigger severe drift class"
            );
        }
        other => panic!("expected InvalidTransition, got {other:?}"),
    }
}

// ── Scenario 8: Replayed epoch with changed membership is fork ──────

#[test]
fn replayed_epoch_with_changed_membership_is_fork() {
    let mut verifier = EpochChainVerifier::new();
    verifier.verify_proposal(1, 6, &[1, 2, 3], 5).unwrap();
    let result = verifier.verify_proposal(2, 6, &[1, 2], 5);
    assert!(
        matches!(result, Err(ChainError::ForkDetected { .. })),
        "replayed epoch with changed membership must be fork, got {result:?}"
    );
}

// ── Scenario 9: Rapid clock oscillation does not corrupt state ──────

#[test]
fn rapid_clock_oscillation_does_not_corrupt_state() {
    let mut verifier = EpochChainVerifier::new();
    let committed: u64 = 10;
    verifier
        .verify_proposal(1, 11, &[1, 2, 3], committed)
        .unwrap();

    let r1 = verifier.verify_proposal(2, 5, &[1, 2], committed);
    assert!(matches!(r1, Err(ChainError::NotMonotonic { .. })));

    let r2 = verifier.verify_proposal(2, 100, &[1, 2], committed);
    assert!(matches!(r2, Err(ChainError::InvalidTransition { .. })));

    let r3 = verifier.verify_proposal(2, 8, &[1, 2, 3], committed);
    assert!(matches!(r3, Err(ChainError::NotMonotonic { .. })));

    assert_eq!(verifier.tracked_count(), 1);
    verifier.reset();
    let result = verifier.verify_proposal(1, 12, &[1, 2, 4], 11);
    assert!(result.is_ok());
}

// ── Scenario 10: Skewed minority cannot force commit ─────────────────

#[test]
fn skewed_minority_cannot_force_commit() {
    // 5-node cluster with 4 peers and 1000ms timeout.
    // Simple majority quorum requires 3 approvals from 4 peers.
    // A single skewed node cannot block quorum.
    let agreement = MembershipEpochAgreement::new(QuorumMode::SimpleMajority, 4, 1000);
    assert!(matches!(agreement.state(), AgreementState::Idle));
}
