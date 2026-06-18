// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for error paths, edge cases, and poison escalation
//! across the DatasetLifecycle state machine. Exercises combinations that
//! are not covered by the basic creation, destroy, or mount tests.

use tidefs_dataset_lifecycle::{DatasetLifecycle, LifecycleError};
use tidefs_types_dataset_lifecycle_core::{
    BlockPointer, DatasetOpenResult, DatasetStateV1, DestroyFlags, PoisonState, TraversalRoot,
    TraversalRootType,
};

fn root() -> TraversalRoot {
    TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(100), 500)
}

// ---------------------------------------------------------------------------
// Poison escalation from every poison state
// ---------------------------------------------------------------------------

#[test]
fn escalate_from_mount_ok_is_noop() {
    let mut lc = DatasetLifecycle::new();
    assert_eq!(lc.poison_state(), PoisonState::MountOk);
    lc.escalate_poison();
    // MountOk → stays MountOk (escalation is for destroy path only)
    assert_eq!(lc.poison_state(), PoisonState::MountOk);
}

#[test]
fn escalate_from_poison_pending_to_active() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert_eq!(lc.poison_state(), PoisonState::PoisonPending);
    lc.escalate_poison();
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
}

#[test]
fn escalate_from_poison_active_is_idempotent() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::FORCE_UNMOUNT, &[])
        .unwrap();
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
    lc.escalate_poison();
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
    lc.escalate_poison(); // second time still idempotent
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
}

#[test]
fn escalate_from_mount_dead_is_noop() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    assert_eq!(lc.poison_state(), PoisonState::MountDead);
    lc.escalate_poison();
    assert_eq!(lc.poison_state(), PoisonState::MountDead);
}

// ---------------------------------------------------------------------------
// Escalate poison without being in destroying — still works gracefully
// ---------------------------------------------------------------------------

#[test]
fn escalate_poison_in_active_stays_healthy() {
    let mut lc = DatasetLifecycle::new();
    assert_eq!(lc.poison_state(), PoisonState::MountOk);
    lc.escalate_poison();
    assert_eq!(lc.poison_state(), PoisonState::MountOk);
    assert!(lc.is_mountable());
}

// ---------------------------------------------------------------------------
// Double-escalate after force_unmount stays active
// ---------------------------------------------------------------------------

#[test]
fn double_escalate_after_force_unmount_stays_active() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::FORCE_UNMOUNT, &[])
        .unwrap();
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
    lc.escalate_poison();
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
    lc.escalate_poison();
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
}

// ---------------------------------------------------------------------------
// All invalid transition combos — systematic coverage
// ---------------------------------------------------------------------------

#[test]
fn every_invalid_direct_transition() {
    // Active→Tombstone: not valid
    let mut lc = DatasetLifecycle::new();
    let err = lc.transition_to_tombstone().unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));

    // Tombstone→Destroying: not valid (need recovery first)
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Tombstone, PoisonState::MountDead);
    let mut lc_mut = lc.clone();
    // Can't go straight to destroying from tombstone
    let err = lc_mut
        .transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap_err();
    // Tombstone→Destroying returns AlreadyInState per implementation
    assert!(matches!(err, LifecycleError::AlreadyInState { .. }));
}

#[test]
fn active_cannot_abort_destroy() {
    let mut lc = DatasetLifecycle::new();
    let err = lc.abort_destroy().unwrap_err();
    assert!(matches!(err, LifecycleError::AlreadyInState { .. }));
}

#[test]
fn active_cannot_recover_tombstone() {
    let mut lc = DatasetLifecycle::new();
    let err = lc.recover_tombstone().unwrap_err();
    assert!(matches!(err, LifecycleError::AlreadyInState { .. }));
}

#[test]
fn destroying_cannot_recover_tombstone() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    let err = lc.recover_tombstone().unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn tombstone_cannot_abort_destroy() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    let err = lc.abort_destroy().unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

// ---------------------------------------------------------------------------
// AlreadyInState errors return the current state
// ---------------------------------------------------------------------------

#[test]
fn already_in_state_contains_correct_state() {
    let lc = DatasetLifecycle::new();
    let err = lc.validate_transition(DatasetStateV1::Active).unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::AlreadyInState {
            state: DatasetStateV1::Active
        }
    ));
}

#[test]
fn already_in_state_after_tombstone() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    let err = lc
        .validate_transition(DatasetStateV1::Tombstone)
        .unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::AlreadyInState {
            state: DatasetStateV1::Tombstone
        }
    ));
}

// ---------------------------------------------------------------------------
// InvalidTransition errors include from/to states
// ---------------------------------------------------------------------------

#[test]
fn invalid_transition_error_has_from_to() {
    let lc = DatasetLifecycle::new();
    let err = lc
        .validate_transition(DatasetStateV1::Tombstone)
        .unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::InvalidTransition {
            from: DatasetStateV1::Active,
            to: DatasetStateV1::Tombstone,
        }
    ));
}

// ---------------------------------------------------------------------------
// check_mount error for each non-mountable state
// ---------------------------------------------------------------------------

#[test]
fn check_mount_destroying_error_is_invalid_transition() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Destroying, PoisonState::MountOk);
    let err = lc.check_mount("ds").unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::InvalidTransition {
            from: DatasetStateV1::Destroying,
            ..
        }
    ));
}

#[test]
fn check_mount_tombstone_error_is_invalid_transition() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Tombstone, PoisonState::MountDead);
    let err = lc.check_mount("ds").unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::InvalidTransition {
            from: DatasetStateV1::Tombstone,
            ..
        }
    ));
}

#[test]
fn check_mount_active_poisoned_error_is_poisoned() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::PoisonActive);
    let err = lc.check_mount("ds").unwrap_err();
    assert!(matches!(err, LifecycleError::Poisoned { .. }));
    let msg = format!("{err}");
    assert!(msg.contains("POISON_ACTIVE"));
}

// ---------------------------------------------------------------------------
// Grace period edge cases
// ---------------------------------------------------------------------------

#[test]
fn grace_secs_zero_transition_to_destroying() {
    let mut lc = DatasetLifecycle::new().with_grace_secs(0);
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert_eq!(lc.grace_secs(), 0);
    assert_eq!(lc.poison_state(), PoisonState::PoisonPending);
}

#[test]
fn grace_secs_u32_max_transition_to_destroying() {
    let mut lc = DatasetLifecycle::new().with_grace_secs(u32::MAX);
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert_eq!(lc.grace_secs(), u32::MAX);
}

// ---------------------------------------------------------------------------
// Destroy job init — MAX_TRAVERSAL_ROOTS overflow
// ---------------------------------------------------------------------------

#[test]
fn init_destroy_job_exceeds_max_roots_returns_none() {
    use tidefs_types_dataset_lifecycle_core::MAX_TRAVERSAL_ROOTS;

    let mut lc = DatasetLifecycle::new();
    // Create more roots than MAX_TRAVERSAL_ROOTS
    let too_many: Vec<TraversalRoot> = (0..(MAX_TRAVERSAL_ROOTS + 1))
        .map(|i| {
            TraversalRoot::new(
                TraversalRootType::InodeTable,
                BlockPointer((100 + i) as u64),
                100,
            )
        })
        .collect();

    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    let job = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &too_many, 1000);
    assert!(job.is_none());
}

#[test]
fn init_destroy_job_exactly_max_roots_succeeds() {
    use tidefs_types_dataset_lifecycle_core::MAX_TRAVERSAL_ROOTS;

    let mut lc = DatasetLifecycle::new();
    let roots: Vec<TraversalRoot> = (0..MAX_TRAVERSAL_ROOTS)
        .map(|i| {
            TraversalRoot::new(
                TraversalRootType::InodeTable,
                BlockPointer((100 + i) as u64),
                100,
            )
        })
        .collect();

    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let job = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 1000);
    assert!(job.is_some());
}

// ---------------------------------------------------------------------------
// Init destroy job — zero objects
// ---------------------------------------------------------------------------

#[test]
fn init_destroy_job_zero_objects_total() {
    let mut lc = DatasetLifecycle::new();
    let roots = [root()];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let job = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 0);
    assert!(job.is_some());
    assert_eq!(job.unwrap().objects_total, 0);
}

// ---------------------------------------------------------------------------
// Update destroy progress — over-completion edge case
// ---------------------------------------------------------------------------

#[test]
fn update_destroy_progress_beyond_total_marks_complete() {
    let mut lc = DatasetLifecycle::new();
    let roots = [TraversalRoot::new(
        TraversalRootType::InodeTable,
        BlockPointer(100),
        100,
    )];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(1, 1, DestroyFlags::NONE, &roots, 100);
    let done = lc.update_destroy_progress(200, 9999); // 200 > 100
    assert!(done);
    assert_eq!(lc.destroy_progress_ppm(), 1_000_000);
}

// ---------------------------------------------------------------------------
// Transition to tombstone without poison escalation
// ---------------------------------------------------------------------------

#[test]
fn transition_to_tombstone_without_escalate_succeeds() {
    // The code does not require escalate_poison before tombstone transition
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    // Skip escalate_poison — poison is still PoisonPending
    let result = lc.transition_to_tombstone();
    assert!(result.is_ok());
    assert_eq!(lc.poison_state(), PoisonState::MountDead);
}

// ---------------------------------------------------------------------------
// Recover tombstone without prior destroy
// ---------------------------------------------------------------------------

#[test]
fn recover_tombstone_from_parts_tombstone() {
    let mut lc = DatasetLifecycle::from_parts(DatasetStateV1::Tombstone, PoisonState::MountDead);
    let result = lc.recover_tombstone();
    assert!(result.is_ok());
    assert_eq!(lc.state(), DatasetStateV1::Active);
    assert_eq!(lc.poison_state(), PoisonState::MountOk);
}

// ---------------------------------------------------------------------------
// Abort destroy then re-destroy — full roundtrip
// ---------------------------------------------------------------------------

#[test]
fn abort_and_redestroy_multiple_times() {
    let mut lc = DatasetLifecycle::new();
    for _ in 0..5 {
        lc.transition_to_destroying(DestroyFlags::NONE, &[])
            .unwrap();
        assert!(!lc.is_mountable());
        lc.abort_destroy().unwrap();
        assert!(lc.is_mountable());
        assert_eq!(lc.state(), DatasetStateV1::Active);
    }
}

// ---------------------------------------------------------------------------
// Destroy with empty pinned roots
// ---------------------------------------------------------------------------

#[test]
fn transition_to_destroying_empty_roots() {
    let mut lc = DatasetLifecycle::new();
    let empty: &[TraversalRoot] = &[];
    lc.transition_to_destroying(DestroyFlags::NONE, empty)
        .unwrap();
    assert_eq!(lc.state(), DatasetStateV1::Destroying);
}

// ---------------------------------------------------------------------------
// check_mount with various dataset names (string argument)
// ---------------------------------------------------------------------------

#[test]
fn check_mount_accepts_various_names() {
    let lc = DatasetLifecycle::new();
    for name in &["a", "pool/ds", "very/long/path/to/dataset"] {
        let r = lc.check_mount(name);
        assert!(r.is_ok(), "name '{name}' should be mountable");
    }
}

// ---------------------------------------------------------------------------
// Poison notification — error path through check_mount
// ---------------------------------------------------------------------------

#[test]
fn check_mount_poison_pending_active_state_errors() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::PoisonPending);
    let err = lc.check_mount("ds").unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::Poisoned {
            poison: PoisonState::PoisonPending,
        }
    ));
}

// ---------------------------------------------------------------------------
// Validate transition from all source states to all target states
// ---------------------------------------------------------------------------

#[test]
fn validate_all_transitions_systematic() {
    // All (from, to) pairs, marking which are valid
    // Valid transitions: Active→Destroying, Destroying→Tombstone,
    //                    Destroying→Active (abort), Tombstone→Active (recover)
    let states = [
        DatasetStateV1::Active,
        DatasetStateV1::Destroying,
        DatasetStateV1::Tombstone,
    ];
    for &from in &states {
        for &to in &states {
            let lc = DatasetLifecycle::from_parts(from, PoisonState::MountOk);
            let result = lc.validate_transition(to);
            match (from, to) {
                // Valid transitions
                (DatasetStateV1::Active, DatasetStateV1::Destroying)
                | (DatasetStateV1::Destroying, DatasetStateV1::Tombstone)
                | (DatasetStateV1::Destroying, DatasetStateV1::Active)
                | (DatasetStateV1::Tombstone, DatasetStateV1::Active) => {
                    assert!(result.is_ok(), "{from}→{to} should be valid");
                }
                // Same state → AlreadyInState
                (a, b) if a == b => {
                    assert!(
                        matches!(result.unwrap_err(), LifecycleError::AlreadyInState { .. }),
                        "{from}→{to} should be AlreadyInState"
                    );
                }
                // Invalid transitions
                _ => {
                    assert!(
                        matches!(
                            result.unwrap_err(),
                            LifecycleError::InvalidTransition { .. }
                        ),
                        "{from}→{to} should be InvalidTransition"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AlreadyInState err messages include state name
// ---------------------------------------------------------------------------

#[test]
fn already_in_state_error_display_names_state() {
    let tests = [
        (DatasetStateV1::Active, "active"),
        (DatasetStateV1::Destroying, "destroying"),
        (DatasetStateV1::Tombstone, "tombstone"),
    ];
    for (state, label) in &tests {
        let err = LifecycleError::AlreadyInState { state: *state };
        let msg = format!("{err}");
        assert!(msg.contains(label), "msg '{msg}' should contain '{label}'");
    }
}

// ---------------------------------------------------------------------------
// InvalidTransition error messages contain both states
// ---------------------------------------------------------------------------

#[test]
fn invalid_transition_error_display_names_both_states() {
    let err = LifecycleError::InvalidTransition {
        from: DatasetStateV1::Active,
        to: DatasetStateV1::Tombstone,
    };
    let msg = format!("{err}");
    assert!(msg.contains("active"));
    assert!(msg.contains("tombstone"));
}

// ---------------------------------------------------------------------------
// Poisoned errors — all poison variants display correctly
// ---------------------------------------------------------------------------

#[test]
fn poisoned_error_display_all_variants() {
    let variants = [
        PoisonState::MountOk,
        PoisonState::MountDead,
        PoisonState::PoisonPending,
        PoisonState::PoisonActive,
    ];
    for &p in &variants {
        let err = LifecycleError::Poisoned { poison: p };
        let msg = format!("{err}");
        assert!(!msg.is_empty(), "display for {p} should not be empty");
    }
}

// ---------------------------------------------------------------------------
// Reap tombstone from every non-tombstone state
// ---------------------------------------------------------------------------

#[test]
fn reap_tombstone_from_destroying_is_error() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    let err = lc.reap_tombstone().unwrap_err();
    assert!(matches!(
        err,
        tidefs_types_dataset_lifecycle_core::LifecycleError::NotTombstone { .. }
    ));
}

#[test]
fn reap_tombstone_from_active_is_error() {
    let mut lc = DatasetLifecycle::new();
    let err = lc.reap_tombstone().unwrap_err();
    assert!(matches!(
        err,
        tidefs_types_dataset_lifecycle_core::LifecycleError::NotTombstone { .. }
    ));
}

// ---------------------------------------------------------------------------
// from_parts with every state/poison pairing — construction doesn't fail
// ---------------------------------------------------------------------------

#[test]
fn from_parts_all_state_poison_combos_construct() {
    let states = [
        DatasetStateV1::Active,
        DatasetStateV1::Destroying,
        DatasetStateV1::Tombstone,
    ];
    let poisons = [
        PoisonState::MountOk,
        PoisonState::MountDead,
        PoisonState::PoisonPending,
        PoisonState::PoisonActive,
    ];
    for &state in &states {
        for &poison in &poisons {
            let lc = DatasetLifecycle::from_parts(state, poison);
            assert_eq!(lc.state(), state);
            assert_eq!(lc.poison_state(), poison);
        }
    }
}

// ---------------------------------------------------------------------------
// Display output for all legal states
// ---------------------------------------------------------------------------

#[test]
fn display_all_states_non_empty() {
    let lc = DatasetLifecycle::new();
    assert!(!format!("{lc}").is_empty());

    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert!(!format!("{lc}").is_empty());

    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    assert!(!format!("{lc}").is_empty());
}

// ---------------------------------------------------------------------------
// Debug output for all legal states
// ---------------------------------------------------------------------------

#[test]
fn debug_all_states_non_empty() {
    let lc = DatasetLifecycle::new();
    assert!(!format!("{lc:?}").is_empty());

    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert!(!format!("{lc:?}").is_empty());

    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    assert!(!format!("{lc:?}").is_empty());
}

// ---------------------------------------------------------------------------
// Recover tombstone after from_parts tombstone
// ---------------------------------------------------------------------------

#[test]
fn recover_tombstone_from_parts_tombstone_mount_ok() {
    let mut lc = DatasetLifecycle::from_parts(DatasetStateV1::Tombstone, PoisonState::MountOk);
    assert!(lc.recover_tombstone().is_ok());
    assert!(lc.is_mountable());
}

// ---------------------------------------------------------------------------
// DatasetOpenResult properties
// ---------------------------------------------------------------------------

#[test]
fn dataset_open_result_read_write_variant() {
    assert!(!DatasetOpenResult::ReadWrite.is_read_only());
}

#[test]
fn dataset_open_result_read_only_variant() {
    assert!(DatasetOpenResult::ReadOnly.is_read_only());
}

// ---------------------------------------------------------------------------
// LifecycleError Debug format
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_error_debug_non_empty() {
    let err = LifecycleError::InvalidTransition {
        from: DatasetStateV1::Active,
        to: DatasetStateV1::Tombstone,
    };
    assert!(!format!("{err:?}").is_empty());
}

// ---------------------------------------------------------------------------
// TraversalRoot null pointer edge cases
// ---------------------------------------------------------------------------

#[test]
fn traversal_root_null_pointer_rejected() {
    let root = TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(0), 100);
    assert!(!root.is_valid());
}

#[test]
fn traversal_root_non_null_pointer_accepted() {
    let root = TraversalRoot::new(TraversalRootType::ExtentMap, BlockPointer(1), 100);
    assert!(root.is_valid());
}

// ---------------------------------------------------------------------------
// DestroyFlags::from_bits round-trips all individual flags
// ---------------------------------------------------------------------------

#[test]
fn destroy_flags_from_bits_roundtrip() {
    let flag_values = [
        DestroyFlags::FORCE_UNMOUNT.bits(),
        DestroyFlags::SKIP_ORPHANS.bits(),
        DestroyFlags::NO_TOMBSTONE.bits(),
        DestroyFlags::DRY_RUN.bits(),
    ];
    for &bits in &flag_values {
        let flags = DestroyFlags::from_bits(bits);
        assert_eq!(flags.bits(), bits);
    }
}

// ---------------------------------------------------------------------------
// DestroyFlags bitwise combinations
// ---------------------------------------------------------------------------

#[test]
fn destroy_flags_all_flags_combined() {
    let all = DestroyFlags::from_bits(
        DestroyFlags::FORCE_UNMOUNT.bits()
            | DestroyFlags::SKIP_ORPHANS.bits()
            | DestroyFlags::NO_TOMBSTONE.bits()
            | DestroyFlags::DRY_RUN.bits(),
    );
    assert!(all.force_unmount());
    assert!(all.skip_orphans());
    assert!(all.no_tombstone());
    assert!(all.is_dry_run());
    assert!(!all.is_empty());
    assert_eq!(
        all.bits(),
        DestroyFlags::FORCE_UNMOUNT.bits()
            | DestroyFlags::SKIP_ORPHANS.bits()
            | DestroyFlags::NO_TOMBSTONE.bits()
            | DestroyFlags::DRY_RUN.bits()
    );
}
