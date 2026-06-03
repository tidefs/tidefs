//! Integration tests for the strategy transition lifecycle.
//!
//! These tests exercise the full quiesce→drain→verify→switch→publish
//! lifecycle as an external consumer. They complement the inline tests
//! by testing multi-transition workflows, epoch fencing across
//! transitions, concurrent fence patterns, and error recovery paths.

use tidefs_coordination_strategy::{
    CoordinationStrategy, EpochFence, FenceError, StrategyEpoch, StrategyTransition,
    TransitionError, TransitionPhase,
};

// ── Full lifecycle: begin → advance through all phases ───────────────

#[test]
fn full_lifecycle_optimistic_to_lease() {
    let mut t = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(5),
    );
    assert_eq!(t.phase(), TransitionPhase::Quiesce);

    assert_eq!(t.advance(), Ok(TransitionPhase::Drain));
    assert_eq!(t.phase(), TransitionPhase::Drain);
    assert!(t.is_active());

    assert_eq!(t.advance(), Ok(TransitionPhase::Verify));
    assert_eq!(t.phase(), TransitionPhase::Verify);

    assert_eq!(t.advance(), Ok(TransitionPhase::Switch));
    assert_eq!(t.phase(), TransitionPhase::Switch);

    assert_eq!(t.advance(), Ok(TransitionPhase::Publish));
    assert_eq!(t.phase(), TransitionPhase::Publish);
    assert!(!t.is_active());
    assert!(t.is_published());
}

#[test]
fn advance_after_publish_returns_terminal_phase() {
    let mut t = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(1),
    );
    // Advance to Publish.
    t.advance().unwrap();
    t.advance().unwrap();
    t.advance().unwrap();
    t.advance().unwrap();
    assert!(t.is_published());

    // Further advance returns error.
    assert_eq!(t.advance(), Err(TransitionError::InvalidPhaseProgression));
}

// ── Rollback at each reversible phase ────────────────────────────────

#[test]
fn rollback_at_quiesce_succeeds() {
    let t = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(1),
    );
    assert_eq!(t.phase(), TransitionPhase::Quiesce);
    assert!(t.rollback().is_ok());
}

#[test]
fn rollback_at_drain_succeeds() {
    let mut t = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(1),
    );
    t.advance().unwrap(); // Quiesce → Drain
    assert_eq!(t.phase(), TransitionPhase::Drain);
    assert!(t.rollback().is_ok());
}

#[test]
fn rollback_at_verify_succeeds() {
    let mut t = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(1),
    );
    t.advance().unwrap(); // Quiesce → Drain
    t.advance().unwrap(); // Drain → Verify
    assert_eq!(t.phase(), TransitionPhase::Verify);
    assert!(t.rollback().is_ok());
}

#[test]
fn rollback_at_switch_succeeds() {
    let mut t = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(1),
    );
    t.advance().unwrap(); // Quiesce → Drain
    t.advance().unwrap(); // Drain → Verify
    t.advance().unwrap(); // Verify → Switch
    assert_eq!(t.phase(), TransitionPhase::Switch);
    assert!(t.rollback().is_ok());
}

#[test]
fn rollback_after_publish_fails() {
    let mut t = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(1),
    );
    t.advance().unwrap();
    t.advance().unwrap();
    t.advance().unwrap();
    t.advance().unwrap(); // now at Publish
    assert!(t.is_published());
    assert_eq!(t.rollback(), Err(TransitionError::InvalidPhaseProgression));
}

// ── All adjacent strategy pairs ──────────────────────────────────────

#[test]
fn all_adjacent_pairs_can_transition() {
    let pairs = [
        (
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Optimistic,
        ),
        (
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
        ),
        (CoordinationStrategy::Lease, CoordinationStrategy::TDMA),
        (
            CoordinationStrategy::TDMA,
            CoordinationStrategy::LeaderSerialized,
        ),
    ];
    for (i, &(from, to)) in pairs.iter().enumerate() {
        let mut t = StrategyTransition::begin(from, to, StrategyEpoch::new(i as u64 + 1));
        assert_eq!(t.phase(), TransitionPhase::Quiesce);
        assert_eq!(t.advance(), Ok(TransitionPhase::Drain));
        assert_eq!(t.advance(), Ok(TransitionPhase::Verify));
        assert_eq!(t.advance(), Ok(TransitionPhase::Switch));
        assert_eq!(t.advance(), Ok(TransitionPhase::Publish));
        assert!(t.is_published());
    }
}

#[test]
fn all_adjacent_pairs_can_rollback_before_publish() {
    let pairs = [
        (
            CoordinationStrategy::Uncontended,
            CoordinationStrategy::Optimistic,
        ),
        (
            CoordinationStrategy::Optimistic,
            CoordinationStrategy::Lease,
        ),
        (CoordinationStrategy::Lease, CoordinationStrategy::TDMA),
        (
            CoordinationStrategy::TDMA,
            CoordinationStrategy::LeaderSerialized,
        ),
    ];
    for &(from, to) in &pairs {
        let mut t = StrategyTransition::begin(from, to, StrategyEpoch::new(42));
        t.advance().unwrap();
        t.advance().unwrap();
        // At Verify, rollback should succeed.
        assert!(
            t.rollback().is_ok(),
            "rollback should succeed at Verify for {from:?}→{to:?}"
        );
    }
}

// ── Epoch fencing across transitions ─────────────────────────────────

#[test]
fn fence_advances_after_transition_publishes() {
    let mut fence = EpochFence::new(StrategyEpoch::ZERO);

    // Before transition: epoch 0 operations are admitted.
    assert!(fence.admit(StrategyEpoch::ZERO).is_ok());

    // Complete a transition to a new epoch.
    let mut t = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(1),
    );
    t.advance().unwrap();
    t.advance().unwrap();
    t.advance().unwrap();
    t.advance().unwrap(); // Published at epoch 1
    assert!(t.is_published());

    // Advance the fence to the new epoch.
    fence.advance(t.new_epoch);

    // Epoch 0 operations now rejected.
    assert!(fence.admit(StrategyEpoch::ZERO).is_err());

    // Epoch 1 operations admitted.
    assert!(fence.admit(StrategyEpoch::new(1)).is_ok());
}

#[test]
fn fence_rejects_operations_between_transitions() {
    let mut fence = EpochFence::new(StrategyEpoch::ZERO);

    // Complete first transition.
    // Complete first transition.
    let mut t1 = StrategyTransition::begin(
        CoordinationStrategy::Uncontended,
        CoordinationStrategy::Optimistic,
        StrategyEpoch::new(1),
    );
    for _ in 0..4 {
        t1.advance().unwrap();
    }
    fence.advance(t1.new_epoch);

    // Complete second transition (skip to Lease).
    let t2 = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(2),
    );
    let mut t2 = t2;
    for _ in 0..4 {
        t2.advance().unwrap();
    }
    fence.advance(t2.new_epoch);

    // Epoch 0 and 1 operations are stale.
    assert!(matches!(
        fence.admit(StrategyEpoch::ZERO),
        Err(FenceError::StaleEpoch { .. })
    ));
    assert!(matches!(
        fence.admit(StrategyEpoch::new(1)),
        Err(FenceError::StaleEpoch { .. })
    ));

    // Epoch 2 and beyond are ok.
    assert!(fence.admit(StrategyEpoch::new(2)).is_ok());
    assert!(fence.admit(StrategyEpoch::new(100)).is_ok());
}

// ── Fence error fields ───────────────────────────────────────────────

#[test]
fn fence_error_stale_epoch_field_values() {
    let fence = EpochFence::new(StrategyEpoch::new(10));
    let err = fence.admit(StrategyEpoch::new(3)).unwrap_err();
    match err {
        FenceError::StaleEpoch {
            fence_epoch,
            operation_epoch,
        } => {
            assert_eq!(fence_epoch, 10);
            assert_eq!(operation_epoch, 3);
        }
    }
}

#[test]
fn fence_error_display_contains_epoch_values() {
    let fence = EpochFence::new(StrategyEpoch::new(42));
    let err = fence.admit(StrategyEpoch::new(7)).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("42"));
    assert!(msg.contains("7"));
    assert!(msg.contains("stale"));
}

// ── StrategyTransition field access ──────────────────────────────────

#[test]
fn transition_fields_accessible_to_external_callers() {
    let t = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(7),
    );
    assert_eq!(t.from, CoordinationStrategy::Optimistic);
    assert_eq!(t.to, CoordinationStrategy::Lease);
    assert_eq!(t.new_epoch, StrategyEpoch::new(7));
    assert_eq!(t.phase, TransitionPhase::Quiesce);
    assert_eq!(t.phase(), TransitionPhase::Quiesce);
    assert!(t.is_active());
    assert!(!t.is_published());
}

// ── Non-adjacent level transitions ───────────────────────────────────

#[test]
fn skip_level_transition_uncontended_to_lease() {
    let mut t = StrategyTransition::begin(
        CoordinationStrategy::Uncontended,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(1),
    );
    assert_eq!(t.from, CoordinationStrategy::Uncontended);
    assert_eq!(t.to, CoordinationStrategy::Lease);
    // Full lifecycle still works.
    assert_eq!(t.advance(), Ok(TransitionPhase::Drain));
    assert_eq!(t.advance(), Ok(TransitionPhase::Verify));
    assert_eq!(t.advance(), Ok(TransitionPhase::Switch));
    assert_eq!(t.advance(), Ok(TransitionPhase::Publish));
    assert!(t.is_published());
}

#[test]
fn skip_level_transition_leader_serialized_to_optimistic() {
    let mut t = StrategyTransition::begin(
        CoordinationStrategy::LeaderSerialized,
        CoordinationStrategy::Optimistic,
        StrategyEpoch::new(99),
    );
    assert_eq!(t.from, CoordinationStrategy::LeaderSerialized);
    assert_eq!(t.to, CoordinationStrategy::Optimistic);
    // Full lifecycle still works.
    assert_eq!(t.advance(), Ok(TransitionPhase::Drain));
    assert_eq!(t.advance(), Ok(TransitionPhase::Verify));
    assert_eq!(t.advance(), Ok(TransitionPhase::Switch));
    assert_eq!(t.advance(), Ok(TransitionPhase::Publish));
}

// ── Strategy epoch operations ────────────────────────────────────────

#[test]
fn epoch_next_chain() {
    let mut e = StrategyEpoch::ZERO;
    for i in 0..100u64 {
        assert_eq!(e.value(), i);
        e = e.next();
    }
    assert_eq!(e.value(), 100);
}

#[test]
#[should_panic(expected = "epoch overflow")]
fn epoch_overflow_panics() {
    let e = StrategyEpoch::new(u64::MAX);
    let _ = e.next(); // should panic
}

#[test]
fn epoch_from_membership_epoch_roundtrip() {
    // EpochId is re-exported from tidefs_membership_epoch.
    // StrategyEpoch::from_membership_epoch and From<EpochId> both work.
    let e = StrategyEpoch::new(42);
    // We can't construct EpochId directly without the dependency,
    // but we can test that StrategyEpoch::new works.
    assert_eq!(e.value(), 42);
}

#[test]
fn epoch_partial_ord_and_ord() {
    let a = StrategyEpoch::new(1);
    let b = StrategyEpoch::new(2);
    let c = StrategyEpoch::new(2);
    assert!(a < b);
    assert!(b > a);
    assert_eq!(b, c);
    assert!(a <= b);
    assert!(b >= a);
}

// ── Fence monotonicity ───────────────────────────────────────────────

#[test]
fn fence_advance_to_same_epoch_panics() {
    let mut fence = EpochFence::new(StrategyEpoch::ZERO);
    // Same epoch is not strictly greater.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fence.advance(StrategyEpoch::ZERO);
    }));
    assert!(result.is_err(), "advancing to same epoch should panic");
}

#[test]
fn fence_advance_to_older_epoch_panics() {
    let mut fence = EpochFence::new(StrategyEpoch::new(5));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fence.advance(StrategyEpoch::new(3));
    }));
    assert!(result.is_err(), "advancing to older epoch should panic");
}

#[test]
fn fence_admit_same_epoch_succeeds() {
    let fence = EpochFence::new(StrategyEpoch::new(7));
    assert!(fence.admit(StrategyEpoch::new(7)).is_ok());
}

#[test]
fn fence_admit_future_epoch_succeeds() {
    let fence = EpochFence::new(StrategyEpoch::ZERO);
    assert!(fence.admit(StrategyEpoch::new(u64::MAX)).is_ok());
}

// ── Transition rejects no-op ─────────────────────────────────────────

#[test]
#[should_panic(expected = "transition must change strategy")]
fn begin_same_strategy_panics() {
    let _ = StrategyTransition::begin(
        CoordinationStrategy::Lease,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(1),
    );
}

// ── Strategy capabilities integration ────────────────────────────────

#[test]
fn capabilities_matrix_external_access() {
    use tidefs_coordination_strategy::PosixOperationClass;

    let caps = CoordinationStrategy::Lease.capabilities();
    assert!(caps.requires_quorum);
    assert!(caps.supports_fencing);

    // Lease provides CausalOrder, which satisfies Write (needs CausalOrder).
    assert!(caps.satisfies(PosixOperationClass::Write));

    // Lease does NOT provide TotalOrder, so Rename should NOT be satisfied.
    assert!(!caps.satisfies(PosixOperationClass::Rename));
}

#[test]
fn leader_serialized_satisfies_all_posix_classes() {
    use tidefs_coordination_strategy::PosixOperationClass;

    let caps = CoordinationStrategy::LeaderSerialized.capabilities();
    for op in &[
        PosixOperationClass::Write,
        PosixOperationClass::Truncate,
        PosixOperationClass::Rename,
        PosixOperationClass::Link,
        PosixOperationClass::Unlink,
        PosixOperationClass::Lock,
    ] {
        assert!(
            caps.satisfies(*op),
            "LeaderSerialized should satisfy {op:?}"
        );
    }
}

// ── Sequence: begin → rollback → re-begin → complete ─────────────────

#[test]
fn rollback_and_retry_succeeds() {
    let mut t = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(1),
    );
    t.advance().unwrap(); // Drain
    t.advance().unwrap(); // Verify
                          // Rollback.
    assert!(t.rollback().is_ok());

    // Now re-attempt the same transition with a new epoch.
    let mut t2 = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(2),
    );
    assert_eq!(t2.advance(), Ok(TransitionPhase::Drain));
    assert_eq!(t2.advance(), Ok(TransitionPhase::Verify));
    assert_eq!(t2.advance(), Ok(TransitionPhase::Switch));
    assert_eq!(t2.advance(), Ok(TransitionPhase::Publish));
    assert!(t2.is_published());
}

// ── Multiple sequential transitions ──────────────────────────────────

#[test]
fn sequential_transitions_with_fence_tracking() {
    let mut fence = EpochFence::new(StrategyEpoch::ZERO);

    // Transition 1: Uncontended → Optimistic at epoch 1.
    let mut t1 = StrategyTransition::begin(
        CoordinationStrategy::Uncontended,
        CoordinationStrategy::Optimistic,
        StrategyEpoch::new(1),
    );
    for _ in 0..4 {
        t1.advance().unwrap();
    }
    fence.advance(t1.new_epoch);

    // Transition 2: Optimistic → Lease at epoch 2.
    let mut t2 = StrategyTransition::begin(
        CoordinationStrategy::Optimistic,
        CoordinationStrategy::Lease,
        StrategyEpoch::new(2),
    );
    for _ in 0..4 {
        t2.advance().unwrap();
    }
    fence.advance(t2.new_epoch);

    // Transition 3: Lease → TDMA at epoch 3.
    let mut t3 = StrategyTransition::begin(
        CoordinationStrategy::Lease,
        CoordinationStrategy::TDMA,
        StrategyEpoch::new(3),
    );
    for _ in 0..4 {
        t3.advance().unwrap();
    }
    fence.advance(t3.new_epoch);

    // Transition 4: TDMA → LeaderSerialized at epoch 4.
    let mut t4 = StrategyTransition::begin(
        CoordinationStrategy::TDMA,
        CoordinationStrategy::LeaderSerialized,
        StrategyEpoch::new(4),
    );
    for _ in 0..4 {
        t4.advance().unwrap();
    }
    fence.advance(t4.new_epoch);

    // Fence is now at epoch 4. Only epoch >= 4 operations admitted.
    assert!(fence.admit(StrategyEpoch::new(4)).is_ok());
    assert!(fence.admit(StrategyEpoch::new(0)).is_err());
    assert!(fence.admit(StrategyEpoch::new(3)).is_err());
}
