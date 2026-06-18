// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for mount eligibility, check_mount, poison gating,
//! and write acceptance across the lifecycle. These directly exercise
//! the DatasetOpenResult / DatasetOpenError path that the POSIX adapter
//! daemon and tidefsctl use to decide whether a dataset can be opened.

use tidefs_dataset_lifecycle::{DatasetLifecycle, LifecycleError};
use tidefs_types_dataset_lifecycle_core::{
    DatasetOpenResult, DatasetStateV1, DestroyFlags, PoisonState,
};

// ---------------------------------------------------------------------------
// is_mountable / accepts_writes — full state × poison matrix
// ---------------------------------------------------------------------------

#[test]
fn active_mount_ok_is_fully_operational() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::MountOk);
    assert!(lc.is_mountable());
    assert!(lc.accepts_writes());
}

#[test]
fn active_mount_dead_not_mountable() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::MountDead);
    assert!(!lc.is_mountable());
    assert!(!lc.accepts_writes());
}

#[test]
fn active_poison_pending_not_mountable() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::PoisonPending);
    assert!(!lc.is_mountable());
    assert!(!lc.accepts_writes());
}

#[test]
fn active_poison_active_not_mountable() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::PoisonActive);
    assert!(!lc.is_mountable());
    assert!(!lc.accepts_writes());
}

#[test]
fn destroying_any_poison_not_mountable() {
    for poison in &[
        PoisonState::MountOk,
        PoisonState::MountDead,
        PoisonState::PoisonPending,
        PoisonState::PoisonActive,
    ] {
        let lc = DatasetLifecycle::from_parts(DatasetStateV1::Destroying, *poison);
        assert!(
            !lc.is_mountable(),
            "Destroying+{poison} should not be mountable"
        );
        assert!(
            !lc.accepts_writes(),
            "Destroying+{poison} should not accept writes"
        );
    }
}

#[test]
fn tombstone_any_poison_not_mountable() {
    for poison in &[
        PoisonState::MountOk,
        PoisonState::MountDead,
        PoisonState::PoisonPending,
        PoisonState::PoisonActive,
    ] {
        let lc = DatasetLifecycle::from_parts(DatasetStateV1::Tombstone, *poison);
        assert!(
            !lc.is_mountable(),
            "Tombstone+{poison} should not be mountable"
        );
        assert!(
            !lc.accepts_writes(),
            "Tombstone+{poison} should not accept writes"
        );
    }
}

// ---------------------------------------------------------------------------
// check_mount — returns ReadWrite when healthy Active
// ---------------------------------------------------------------------------

#[test]
fn check_mount_active_healthy_ok() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::MountOk);
    let r = lc.check_mount("pool/dataset");
    assert!(r.is_ok());
    assert_eq!(r.unwrap(), DatasetOpenResult::ReadWrite);
}

// ---------------------------------------------------------------------------
// check_mount — refuses all non-Active states
// ---------------------------------------------------------------------------

#[test]
fn check_mount_destroying_is_error() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Destroying, PoisonState::MountOk);
    let r = lc.check_mount("ds");
    assert!(r.is_err());
    assert!(matches!(
        r.unwrap_err(),
        LifecycleError::InvalidTransition { .. }
    ));
}

#[test]
fn check_mount_tombstone_is_error() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Tombstone, PoisonState::MountDead);
    let r = lc.check_mount("ds");
    assert!(r.is_err());
    assert!(matches!(
        r.unwrap_err(),
        LifecycleError::InvalidTransition { .. }
    ));
}

// ---------------------------------------------------------------------------
// check_mount — refuses active-but-poisoned
// ---------------------------------------------------------------------------

#[test]
fn check_mount_active_poison_pending_is_error() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::PoisonPending);
    let r = lc.check_mount("ds");
    assert!(r.is_err());
    assert!(matches!(r.unwrap_err(), LifecycleError::Poisoned { .. }));
}

#[test]
fn check_mount_active_poison_active_is_error() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::PoisonActive);
    let r = lc.check_mount("ds");
    assert!(r.is_err());
    assert!(matches!(r.unwrap_err(), LifecycleError::Poisoned { .. }));
}

#[test]
fn check_mount_active_mount_dead_is_error() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::MountDead);
    let r = lc.check_mount("ds");
    assert!(r.is_err());
    assert!(matches!(r.unwrap_err(), LifecycleError::Poisoned { .. }));
}

// ---------------------------------------------------------------------------
// Mountability after transitions — real-world workflow
// ---------------------------------------------------------------------------

#[test]
fn mountable_before_destroy_not_after() {
    let mut lc = DatasetLifecycle::new();
    assert!(lc.is_mountable());
    assert!(lc.accepts_writes());

    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert!(!lc.is_mountable());
    assert!(!lc.accepts_writes());
}

#[test]
fn mountable_after_abort() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert!(!lc.is_mountable());

    lc.abort_destroy().unwrap();
    assert!(lc.is_mountable());
    assert!(lc.accepts_writes());
}

#[test]
fn mountable_after_tombstone_recovery() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    assert!(!lc.is_mountable());

    lc.recover_tombstone().unwrap();
    assert!(lc.is_mountable());
    assert!(lc.accepts_writes());
}

#[test]
fn check_mount_after_abort_succeeds() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.abort_destroy().unwrap();
    let r = lc.check_mount("ds");
    assert!(r.is_ok());
    assert_eq!(r.unwrap(), DatasetOpenResult::ReadWrite);
}

#[test]
fn check_mount_after_recover_tombstone_succeeds() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    lc.recover_tombstone().unwrap();
    let r = lc.check_mount("ds");
    assert!(r.is_ok());
    assert_eq!(r.unwrap(), DatasetOpenResult::ReadWrite);
}

// ---------------------------------------------------------------------------
// check_mount during poison escalation — mid-lifecycle
// ---------------------------------------------------------------------------

#[test]
fn check_mount_fails_during_destroying_with_pending_poison() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    // Poison is PoisonPending, state is Destroying — rejects via state check
    let r = lc.check_mount("ds");
    assert!(r.is_err());
    assert!(matches!(
        r.unwrap_err(),
        LifecycleError::InvalidTransition { .. }
    ));
}

#[test]
fn check_mount_fails_during_destroying_with_active_poison() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::FORCE_UNMOUNT, &[])
        .unwrap();
    // Poison is PoisonActive, state is Destroying
    let r = lc.check_mount("ds");
    assert!(r.is_err());
    assert!(matches!(
        r.unwrap_err(),
        LifecycleError::InvalidTransition { .. }
    ));
}

// ---------------------------------------------------------------------------
// Force-unmount skips grace period — mount is fenced immediately
// ---------------------------------------------------------------------------

#[test]
fn force_unmount_immediately_fences_mount() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::FORCE_UNMOUNT, &[])
        .unwrap();
    assert!(!lc.is_mountable());
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
}

#[test]
fn normal_destroy_allows_grace_before_active_poison() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    // Still not mountable because state is Destroying
    assert!(!lc.is_mountable());
    // Poison is pending, not yet active — grace period in effect
    assert_eq!(lc.poison_state(), PoisonState::PoisonPending);
}

// ---------------------------------------------------------------------------
// Write acceptance during destroy — ensured by is_mountable check
// ---------------------------------------------------------------------------

#[test]
fn write_acceptance_follows_mountability() {
    let mut lc = DatasetLifecycle::new();
    assert!(lc.accepts_writes());

    lc.transition_to_destroying(DestroyFlags::FORCE_UNMOUNT, &[])
        .unwrap();
    assert!(!lc.accepts_writes());

    lc.abort_destroy().unwrap();
    assert!(lc.accepts_writes());
}

// ---------------------------------------------------------------------------
// DatasetOpenResult — basic properties
// ---------------------------------------------------------------------------

#[test]
fn dataset_open_result_read_write_is_not_read_only() {
    assert!(!DatasetOpenResult::ReadWrite.is_read_only());
}

#[test]
fn dataset_open_result_read_only_is_read_only() {
    assert!(DatasetOpenResult::ReadOnly.is_read_only());
}
