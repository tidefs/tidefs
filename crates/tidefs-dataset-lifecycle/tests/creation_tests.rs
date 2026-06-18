// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for DatasetLifecycle construction, accessors, and
//! initial-state invariants. Exercises the public API surface from outside
//! the crate.

use tidefs_dataset_lifecycle::{DatasetLifecycle, LifecycleError, SyncGuarantee};
use tidefs_types_dataset_lifecycle_core::{
    BlockPointer, DatasetOpenResult, DatasetStateV1, DestroyFlags, PoisonState, TraversalRoot,
    TraversalRootType,
};

// ---------------------------------------------------------------------------
// Construction — new()
// ---------------------------------------------------------------------------

#[test]
fn new_defaults_to_active() {
    let lc = DatasetLifecycle::new();
    assert_eq!(lc.state(), DatasetStateV1::Active);
}

#[test]
fn new_defaults_to_mount_ok_poison() {
    let lc = DatasetLifecycle::new();
    assert_eq!(lc.poison_state(), PoisonState::MountOk);
}

#[test]
fn new_default_grace_secs_is_30() {
    let lc = DatasetLifecycle::new();
    assert_eq!(lc.grace_secs(), 30);
}

#[test]
fn new_is_mountable() {
    let lc = DatasetLifecycle::new();
    assert!(lc.is_mountable());
}

#[test]
fn new_accepts_writes() {
    let lc = DatasetLifecycle::new();
    assert!(lc.accepts_writes());
}

#[test]
fn new_has_no_destroy_job() {
    let lc = DatasetLifecycle::new();
    assert!(lc.destroy_job().is_none());
}

#[test]
fn new_destroy_progress_ppm_is_zero() {
    let lc = DatasetLifecycle::new();
    assert_eq!(lc.destroy_progress_ppm(), 0);
}

// ---------------------------------------------------------------------------
// Construction — from_parts()
// ---------------------------------------------------------------------------

#[test]
fn from_parts_active_mount_ok() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::MountOk);
    assert_eq!(lc.state(), DatasetStateV1::Active);
    assert_eq!(lc.poison_state(), PoisonState::MountOk);
    assert!(lc.is_mountable());
}

#[test]
fn from_parts_destroying_poison_pending() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Destroying, PoisonState::PoisonPending);
    assert_eq!(lc.state(), DatasetStateV1::Destroying);
    assert_eq!(lc.poison_state(), PoisonState::PoisonPending);
    assert!(!lc.is_mountable());
    assert!(!lc.accepts_writes());
}

#[test]
fn from_parts_tombstone_mount_dead() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Tombstone, PoisonState::MountDead);
    assert_eq!(lc.state(), DatasetStateV1::Tombstone);
    assert_eq!(lc.poison_state(), PoisonState::MountDead);
    assert!(!lc.is_mountable());
}

#[test]
fn from_parts_active_poison_active_not_mountable() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::PoisonActive);
    assert_eq!(lc.state(), DatasetStateV1::Active);
    assert!(!lc.is_mountable());
    assert!(!lc.accepts_writes());
}

#[test]
fn from_parts_preserves_default_grace() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::MountOk);
    assert_eq!(lc.grace_secs(), 30);
}

// ---------------------------------------------------------------------------
// Construction — with_grace_secs() builder
// ---------------------------------------------------------------------------

#[test]
fn with_grace_secs_overrides_default() {
    let lc = DatasetLifecycle::new().with_grace_secs(60);
    assert_eq!(lc.grace_secs(), 60);
}

#[test]
fn with_grace_secs_zero_allowed() {
    let lc = DatasetLifecycle::new().with_grace_secs(0);
    assert_eq!(lc.grace_secs(), 0);
}

#[test]
fn with_grace_secs_large_value() {
    let lc = DatasetLifecycle::new().with_grace_secs(86_400);
    assert_eq!(lc.grace_secs(), 86_400);
}

#[test]
fn with_grace_secs_does_not_change_state() {
    let lc = DatasetLifecycle::new().with_grace_secs(99);
    assert_eq!(lc.state(), DatasetStateV1::Active);
    assert_eq!(lc.poison_state(), PoisonState::MountOk);
}

// ---------------------------------------------------------------------------
// Accessor consistency across state/poison combos
// ---------------------------------------------------------------------------

#[test]
fn is_mountable_only_when_active_and_healthy() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::MountOk);
    assert!(lc.is_mountable());

    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::PoisonActive);
    assert!(!lc.is_mountable());

    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Destroying, PoisonState::MountOk);
    assert!(!lc.is_mountable());

    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Tombstone, PoisonState::MountOk);
    assert!(!lc.is_mountable());
}

#[test]
fn accepts_writes_only_when_active_and_healthy() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::MountOk);
    assert!(lc.accepts_writes());

    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::PoisonActive);
    assert!(!lc.accepts_writes());

    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Destroying, PoisonState::MountOk);
    assert!(!lc.accepts_writes());

    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Tombstone, PoisonState::MountOk);
    assert!(!lc.accepts_writes());
}

// ---------------------------------------------------------------------------
// check_mount() — dataset open gate
// ---------------------------------------------------------------------------

#[test]
fn check_mount_active_healthy_returns_read_write() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::MountOk);
    let result = lc.check_mount("test_ds");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), DatasetOpenResult::ReadWrite);
}

#[test]
fn check_mount_active_poisoned_errors() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::PoisonActive);
    let result = lc.check_mount("test_ds");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        LifecycleError::Poisoned { .. }
    ));
}

#[test]
fn check_mount_destroying_errors() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Destroying, PoisonState::MountOk);
    let result = lc.check_mount("test_ds");
    assert!(result.is_err());
}

#[test]
fn check_mount_tombstone_errors() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Tombstone, PoisonState::MountDead);
    let result = lc.check_mount("test_ds");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// validate_transition() — valid transitions
// ---------------------------------------------------------------------------

#[test]
fn validate_active_to_destroying_is_valid() {
    let lc = DatasetLifecycle::new();
    assert!(lc.validate_transition(DatasetStateV1::Destroying).is_ok());
}

#[test]
fn validate_destroying_to_tombstone_is_valid() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert!(lc.validate_transition(DatasetStateV1::Tombstone).is_ok());
}

#[test]
fn validate_destroying_to_active_abort_is_valid() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert!(lc.validate_transition(DatasetStateV1::Active).is_ok());
}

#[test]
fn validate_tombstone_to_active_recovery_is_valid() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    assert!(lc.validate_transition(DatasetStateV1::Active).is_ok());
}

// ---------------------------------------------------------------------------
// validate_transition() — invalid transitions
// ---------------------------------------------------------------------------

#[test]
fn validate_active_to_active_is_already_in_state() {
    let lc = DatasetLifecycle::new();
    let err = lc.validate_transition(DatasetStateV1::Active).unwrap_err();
    assert!(matches!(err, LifecycleError::AlreadyInState { .. }));
}

#[test]
fn validate_active_to_tombstone_is_invalid() {
    let lc = DatasetLifecycle::new();
    let err = lc
        .validate_transition(DatasetStateV1::Tombstone)
        .unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn validate_destroying_to_destroying_is_already_in_state() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    let err = lc
        .validate_transition(DatasetStateV1::Destroying)
        .unwrap_err();
    assert!(matches!(err, LifecycleError::AlreadyInState { .. }));
}

#[test]
fn validate_tombstone_to_tombstone_is_already_in_state() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    let err = lc
        .validate_transition(DatasetStateV1::Tombstone)
        .unwrap_err();
    assert!(matches!(err, LifecycleError::AlreadyInState { .. }));
}

#[test]
fn validate_tombstone_to_destroying_is_invalid() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    let err = lc
        .validate_transition(DatasetStateV1::Destroying)
        .unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

// ---------------------------------------------------------------------------
// Validate transition after recover_tombstone — re-validates
// ---------------------------------------------------------------------------

#[test]
fn validate_after_recover_tombstone_allows_destroy_again() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    lc.recover_tombstone().unwrap();
    assert!(lc.validate_transition(DatasetStateV1::Destroying).is_ok());
}

// ---------------------------------------------------------------------------
// Clone / PartialEq / Debug
// ---------------------------------------------------------------------------

#[test]
fn clone_equality() {
    let lc1 = DatasetLifecycle::new();
    let lc2 = lc1.clone();
    assert_eq!(lc1, lc2);
}

#[test]
fn clone_preserves_state() {
    let mut lc1 = DatasetLifecycle::new();
    lc1.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    let lc2 = lc1.clone();
    assert_eq!(lc2.state(), DatasetStateV1::Destroying);
    assert_eq!(lc2.poison_state(), PoisonState::PoisonPending);
}

#[test]
fn clone_is_independent() {
    let lc1 = DatasetLifecycle::new();
    let mut lc2 = lc1.clone();
    lc2.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert_eq!(lc1.state(), DatasetStateV1::Active);
    assert_eq!(lc2.state(), DatasetStateV1::Destroying);
}

#[test]
fn debug_format_includes_state() {
    let lc = DatasetLifecycle::new();
    let s = format!("{lc:?}");
    assert!(s.contains("Active") || s.contains("active"));
}

#[test]
fn display_format_includes_state() {
    let lc = DatasetLifecycle::new();
    let s = format!("{lc}");
    assert!(s.contains("active") || s.contains("Active"));
}

// ---------------------------------------------------------------------------
// Grace period accessor — non-default values
// ---------------------------------------------------------------------------

#[test]
fn grace_secs_persists_after_transition() {
    let mut lc = DatasetLifecycle::new().with_grace_secs(45);
    assert_eq!(lc.grace_secs(), 45);
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert_eq!(lc.grace_secs(), 45);
}

// ---------------------------------------------------------------------------
// Reaper policy defaults on construction
// ---------------------------------------------------------------------------

#[test]
fn new_reaper_policy_defaults() {
    let lc = DatasetLifecycle::new();
    let p = lc.reaper_policy();
    assert_eq!(p.min_age_secs, 86_400);
    assert_eq!(p.max_per_scan, 128);
    assert_eq!(p.scan_interval_secs, 60);
}

#[test]
fn from_parts_reaper_policy_defaults() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Tombstone, PoisonState::MountDead);
    let p = lc.reaper_policy();
    assert_eq!(p.min_age_secs, 86_400);
}

// ---------------------------------------------------------------------------
// cluster_consensus_granted — initial state
// ---------------------------------------------------------------------------

#[test]
fn new_cluster_consensus_not_granted() {
    let lc = DatasetLifecycle::new();
    assert!(!lc.cluster_consensus_granted());
}

#[test]
fn set_cluster_consensus_granted() {
    let mut lc = DatasetLifecycle::new();
    assert!(!lc.cluster_consensus_granted());
    lc.set_cluster_consensus_granted();
    assert!(lc.cluster_consensus_granted());
}

// ---------------------------------------------------------------------------
// Construction edge cases
// ---------------------------------------------------------------------------

#[test]
fn from_parts_with_active_poison_pending() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Active, PoisonState::PoisonPending);
    assert_eq!(lc.state(), DatasetStateV1::Active);
    assert!(!lc.is_mountable());
    assert!(!lc.accepts_writes());
}

#[test]
fn from_parts_with_tombstone_mount_ok() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Tombstone, PoisonState::MountOk);
    assert!(!lc.is_mountable());
    assert!(!lc.accepts_writes());
}

#[test]
fn from_parts_with_destroying_poison_active() {
    let lc = DatasetLifecycle::from_parts(DatasetStateV1::Destroying, PoisonState::PoisonActive);
    assert_eq!(lc.state(), DatasetStateV1::Destroying);
    assert!(!lc.is_mountable());
}

// ---------------------------------------------------------------------------
// LifecycleError Display
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_error_display_invalid_transition() {
    let err = LifecycleError::InvalidTransition {
        from: DatasetStateV1::Active,
        to: DatasetStateV1::Tombstone,
    };
    let s = format!("{err}");
    assert!(s.contains("active"));
    assert!(s.contains("tombstone"));
}

#[test]
fn lifecycle_error_display_already_in_state() {
    let err = LifecycleError::AlreadyInState {
        state: DatasetStateV1::Active,
    };
    let s = format!("{err}");
    assert!(s.contains("active"));
    assert!(s.contains("already"));
}

#[test]
fn lifecycle_error_display_precondition_failed() {
    let err = LifecycleError::PreconditionFailed {
        from: DatasetStateV1::Active,
        to: DatasetStateV1::Destroying,
        reason: "clone children exist",
    };
    let s = format!("{err}");
    assert!(s.contains("clone children exist"));
}

#[test]
fn lifecycle_error_display_poisoned() {
    let err = LifecycleError::Poisoned {
        poison: PoisonState::PoisonActive,
    };
    let s = format!("{err}");
    assert!(s.contains("POISON_ACTIVE"));
}

// ---------------------------------------------------------------------------
// DestroyFlags
// ---------------------------------------------------------------------------

#[test]
fn destroy_flags_none_is_empty() {
    assert!(DestroyFlags::NONE.is_empty());
}

#[test]
fn destroy_flags_none_no_force_unmount() {
    assert!(!DestroyFlags::NONE.force_unmount());
}

#[test]
fn destroy_flags_force_unmount_is_set() {
    assert!(DestroyFlags::FORCE_UNMOUNT.force_unmount());
    assert!(!DestroyFlags::FORCE_UNMOUNT.is_empty());
}

#[test]
fn destroy_flags_all_combinations() {
    let flags = DestroyFlags::FORCE_UNMOUNT;
    assert!(flags.force_unmount());
    assert!(!flags.skip_orphans());
    assert!(!flags.no_tombstone());
    assert!(!flags.is_dry_run());

    let flags = DestroyFlags::from_bits(
        DestroyFlags::FORCE_UNMOUNT.bits()
            | DestroyFlags::SKIP_ORPHANS.bits()
            | DestroyFlags::NO_TOMBSTONE.bits()
            | DestroyFlags::DRY_RUN.bits(),
    );
    assert!(flags.force_unmount());
    assert!(flags.skip_orphans());
    assert!(flags.no_tombstone());
    assert!(flags.is_dry_run());
}

// ---------------------------------------------------------------------------
// TraversalRoot construction and validation
// ---------------------------------------------------------------------------

#[test]
fn traversal_root_new_valid() {
    let root = TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(42), 100);
    assert!(root.is_valid());
}

#[test]
fn traversal_root_new_null_pointer_is_invalid() {
    let root = TraversalRoot::new(TraversalRootType::ExtentMap, BlockPointer(0), 100);
    assert!(!root.is_valid());
}

#[test]
fn traversal_root_type_all_variants_have_valid_u8() {
    let types = [
        TraversalRootType::InodeTable,
        TraversalRootType::ExtentMap,
        TraversalRootType::DirectoryIndex,
        TraversalRootType::XattrStore,
        TraversalRootType::SnapshotCatalog,
        TraversalRootType::FeatureFlags,
    ];
    for &t in &types {
        let byte = t.to_u8();
        let roundtripped = TraversalRootType::from_u8(byte);
        assert_eq!(roundtripped, Some(t));
    }
}

// ---------------------------------------------------------------------------
// DatasetLifecycle::create() --- catalog-backed creation
// ---------------------------------------------------------------------------

#[test]
fn create_inserts_into_catalog_and_returns_handle() {
    let mut cat = tidefs_dataset_catalog::DatasetCatalog::new();
    cat.create(
        "pool",
        tidefs_dataset_catalog::DatasetId::from_bytes([1u8; 16]),
        tidefs_dataset_catalog::DatasetType::Filesystem,
        1,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();

    let _handle = tidefs_dataset_lifecycle::DatasetLifecycle::create(
        &mut cat,
        "pool",
        "testfs",
        tidefs_dataset_catalog::DatasetType::Filesystem,
        10,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::default_create(),
        SyncGuarantee::default(),
    )
    .unwrap();

    assert!(
        _handle.lifecycle.state() == tidefs_types_dataset_lifecycle_core::DatasetStateV1::Active
    );
    assert!(cat.contains("pool/testfs"));
    assert_eq!(_handle.path, "pool/testfs");
    assert_eq!(_handle.creation_commit_group, 10);
}

#[test]
fn create_duplicate_name_fails() {
    let mut cat = tidefs_dataset_catalog::DatasetCatalog::new();
    cat.create(
        "pool",
        tidefs_dataset_catalog::DatasetId::from_bytes([1u8; 16]),
        tidefs_dataset_catalog::DatasetType::Filesystem,
        1,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();

    let _ = tidefs_dataset_lifecycle::DatasetLifecycle::create(
        &mut cat,
        "pool",
        "dup",
        tidefs_dataset_catalog::DatasetType::Filesystem,
        10,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();

    let err = tidefs_dataset_lifecycle::DatasetLifecycle::create(
        &mut cat,
        "pool",
        "dup",
        tidefs_dataset_catalog::DatasetType::Filesystem,
        11,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap_err();
    assert_eq!(err, tidefs_dataset_catalog::CatalogError::AlreadyExists);
}

#[test]
fn create_missing_parent_fails() {
    let mut cat = tidefs_dataset_catalog::DatasetCatalog::new();
    let err = tidefs_dataset_lifecycle::DatasetLifecycle::create(
        &mut cat,
        "nopool",
        "orphan",
        tidefs_dataset_catalog::DatasetType::Filesystem,
        10,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap_err();
    assert_eq!(err, tidefs_dataset_catalog::CatalogError::ParentNotFound);
}

// ---------------------------------------------------------------------------
// DatasetLifecycle::destroy() --- catalog-backed destroy
// ---------------------------------------------------------------------------

#[test]
fn destroy_removes_from_catalog_and_returns_destroying_lifecycle() {
    let mut cat = tidefs_dataset_catalog::DatasetCatalog::new();
    cat.create(
        "pool",
        tidefs_dataset_catalog::DatasetId::from_bytes([1u8; 16]),
        tidefs_dataset_catalog::DatasetType::Filesystem,
        1,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();

    let _ = tidefs_dataset_lifecycle::DatasetLifecycle::create(
        &mut cat,
        "pool",
        "leaf",
        tidefs_dataset_catalog::DatasetType::Filesystem,
        10,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();

    let destroyed =
        tidefs_dataset_lifecycle::DatasetLifecycle::destroy(&mut cat, "pool/leaf").unwrap();

    assert_eq!(
        destroyed.state(),
        tidefs_types_dataset_lifecycle_core::DatasetStateV1::Destroying
    );
    assert!(!cat.contains("pool/leaf"));
}

#[test]
fn destroy_nonexistent_fails() {
    let mut cat = tidefs_dataset_catalog::DatasetCatalog::new();
    let err = tidefs_dataset_lifecycle::DatasetLifecycle::destroy(&mut cat, "pool/nonexistent")
        .unwrap_err();
    assert_eq!(err, tidefs_dataset_catalog::CatalogError::NotFound);
}

#[test]
fn destroy_with_children_fails() {
    let mut cat = tidefs_dataset_catalog::DatasetCatalog::new();
    cat.create(
        "pool",
        tidefs_dataset_catalog::DatasetId::from_bytes([1u8; 16]),
        tidefs_dataset_catalog::DatasetType::Filesystem,
        1,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();
    cat.create(
        "pool/parent",
        tidefs_dataset_catalog::DatasetId::from_bytes([2u8; 16]),
        tidefs_dataset_catalog::DatasetType::Filesystem,
        2,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();
    cat.create(
        "pool/parent/child",
        tidefs_dataset_catalog::DatasetId::from_bytes([3u8; 16]),
        tidefs_dataset_catalog::DatasetType::Filesystem,
        3,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();

    let err =
        tidefs_dataset_lifecycle::DatasetLifecycle::destroy(&mut cat, "pool/parent").unwrap_err();
    assert_eq!(err, tidefs_dataset_catalog::CatalogError::HasChildren);
}

// ---------------------------------------------------------------------------
// DatasetLifecycle::list() --- catalog-backed list
// ---------------------------------------------------------------------------

#[test]
fn list_returns_children_with_details() {
    let mut cat = tidefs_dataset_catalog::DatasetCatalog::new();
    cat.create(
        "pool",
        tidefs_dataset_catalog::DatasetId::from_bytes([1u8; 16]),
        tidefs_dataset_catalog::DatasetType::Filesystem,
        1,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();
    let _ = tidefs_dataset_lifecycle::DatasetLifecycle::create(
        &mut cat,
        "pool",
        "a",
        tidefs_dataset_catalog::DatasetType::Filesystem,
        10,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();
    let _ = tidefs_dataset_lifecycle::DatasetLifecycle::create(
        &mut cat,
        "pool",
        "b",
        tidefs_dataset_catalog::DatasetType::Volume,
        20,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::READONLY,
        SyncGuarantee::default(),
    )
    .unwrap();

    let children = tidefs_dataset_lifecycle::DatasetLifecycle::list(&cat, "pool").unwrap();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0].0, "a");
    assert_eq!(
        children[0].2,
        tidefs_dataset_catalog::DatasetType::Filesystem
    );
    assert_eq!(children[1].0, "b");
    assert_eq!(children[1].2, tidefs_dataset_catalog::DatasetType::Volume);
}

#[test]
fn list_empty_parent_returns_empty() {
    let mut cat = tidefs_dataset_catalog::DatasetCatalog::new();
    cat.create(
        "pool",
        tidefs_dataset_catalog::DatasetId::from_bytes([1u8; 16]),
        tidefs_dataset_catalog::DatasetType::Filesystem,
        1,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();
    let children = tidefs_dataset_lifecycle::DatasetLifecycle::list(&cat, "pool").unwrap();
    assert!(children.is_empty());
}

// ---------------------------------------------------------------------------
// Create-then-destroy idempotency
// ---------------------------------------------------------------------------

#[test]
fn create_after_destroy_reuses_slot() {
    let mut cat = tidefs_dataset_catalog::DatasetCatalog::new();
    cat.create(
        "pool",
        tidefs_dataset_catalog::DatasetId::from_bytes([1u8; 16]),
        tidefs_dataset_catalog::DatasetType::Filesystem,
        1,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();

    let h1 = tidefs_dataset_lifecycle::DatasetLifecycle::create(
        &mut cat,
        "pool",
        "reused",
        tidefs_dataset_catalog::DatasetType::Filesystem,
        10,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();
    let _ = tidefs_dataset_lifecycle::DatasetLifecycle::destroy(&mut cat, "pool/reused").unwrap();

    let h2 = tidefs_dataset_lifecycle::DatasetLifecycle::create(
        &mut cat,
        "pool",
        "reused",
        tidefs_dataset_catalog::DatasetType::Filesystem,
        20,
        vec![],
        tidefs_dataset_catalog::DatasetFlags::NONE,
        SyncGuarantee::default(),
    )
    .unwrap();

    assert_eq!(h2.path, "pool/reused");
    assert_eq!(h2.creation_commit_group, 20);
    assert_ne!(h1.dataset_id, h2.dataset_id);
}
