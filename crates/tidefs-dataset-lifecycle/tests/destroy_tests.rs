//! Integration tests for destroy lifecycle: transition_to_destroying,
//! transition_to_tombstone, abort_destroy, destroy job tracking, and
//! tombstone reaper integration. All tests use only the public API.

use tidefs_dataset_lifecycle::{DatasetLifecycle, LifecycleError};
use tidefs_types_dataset_lifecycle_core::{
    BlockPointer, DatasetStateV1, DestroyFlags, PoisonState, ReapEligibility,
    TombstoneReaperPolicy, TraversalRoot, TraversalRootType,
};

fn make_root() -> TraversalRoot {
    TraversalRoot::new(TraversalRootType::InodeTable, BlockPointer(100), 500)
}

fn make_roots(n: usize) -> Vec<TraversalRoot> {
    let types = [
        TraversalRootType::InodeTable,
        TraversalRootType::ExtentMap,
        TraversalRootType::DirectoryIndex,
        TraversalRootType::XattrStore,
        TraversalRootType::SnapshotCatalog,
        TraversalRootType::FeatureFlags,
    ];
    types
        .iter()
        .take(n)
        .enumerate()
        .map(|(i, &t)| TraversalRoot::new(t, BlockPointer((100 + i * 100) as u64), 500))
        .collect()
}

// -- transition_to_destroying basic --

#[test]
fn transition_to_destroying_changes_state() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert_eq!(lc.state(), DatasetStateV1::Destroying);
}

#[test]
fn transition_to_destroying_sets_poison_pending() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert_eq!(lc.poison_state(), PoisonState::PoisonPending);
}

#[test]
fn transition_to_destroying_not_mountable() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert!(!lc.is_mountable());
}

#[test]
fn transition_to_destroying_no_longer_accepts_writes() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert!(!lc.accepts_writes());
}

#[test]
fn transition_to_destroying_with_force_unmount_sets_poison_active() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::FORCE_UNMOUNT, &[])
        .unwrap();
    assert_eq!(lc.state(), DatasetStateV1::Destroying);
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
}

#[test]
fn transition_to_destroying_with_pinned_roots() {
    let mut lc = DatasetLifecycle::new();
    let roots = make_roots(2);
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    assert_eq!(lc.state(), DatasetStateV1::Destroying);
}

// -- transition_to_destroying errors --

#[test]
fn transition_to_destroying_twice_is_already_in_state() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    let err = lc
        .transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap_err();
    assert!(matches!(err, LifecycleError::AlreadyInState { .. }));
}

#[test]
fn transition_to_destroying_from_tombstone_is_already_in_state() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    let err = lc
        .transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap_err();
    assert!(matches!(err, LifecycleError::AlreadyInState { .. }));
}

// -- escalate_poison --

#[test]
fn escalate_poison_from_pending_to_active() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert_eq!(lc.poison_state(), PoisonState::PoisonPending);
    lc.escalate_poison();
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
}

#[test]
fn escalate_poison_is_idempotent() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::FORCE_UNMOUNT, &[])
        .unwrap();
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
    lc.escalate_poison();
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
}

// -- transition_to_tombstone basic --

#[test]
fn transition_to_tombstone_from_destroying() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    assert_eq!(lc.state(), DatasetStateV1::Tombstone);
    assert_eq!(lc.poison_state(), PoisonState::MountDead);
}

#[test]
fn transition_to_tombstone_not_mountable() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    assert!(!lc.is_mountable());
    assert!(!lc.accepts_writes());
}

#[test]
fn transition_to_tombstone_completes_destroy_job() {
    let mut lc = DatasetLifecycle::new();
    let roots = [make_root()];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 500);
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();

    let job = lc.destroy_job().unwrap();
    assert!(job.is_completed());
    assert_eq!(lc.destroy_progress_ppm(), 1_000_000);
}

// -- transition_to_tombstone errors --

#[test]
fn transition_to_tombstone_from_active_is_invalid() {
    let mut lc = DatasetLifecycle::new();
    let err = lc.transition_to_tombstone().unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn transition_to_tombstone_twice_is_already_in_state() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    let err = lc.transition_to_tombstone().unwrap_err();
    assert!(matches!(err, LifecycleError::AlreadyInState { .. }));
}

// -- abort_destroy --

#[test]
fn abort_destroy_returns_to_active() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.abort_destroy().unwrap();
    assert_eq!(lc.state(), DatasetStateV1::Active);
    assert_eq!(lc.poison_state(), PoisonState::MountOk);
}

#[test]
fn abort_destroy_restores_mountability() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.abort_destroy().unwrap();
    assert!(lc.is_mountable());
    assert!(lc.accepts_writes());
}

#[test]
fn abort_destroy_after_force_unmount() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::FORCE_UNMOUNT, &[])
        .unwrap();
    lc.abort_destroy().unwrap();
    assert_eq!(lc.state(), DatasetStateV1::Active);
    assert_eq!(lc.poison_state(), PoisonState::MountOk);
}

#[test]
fn abort_destroy_clears_destroy_job() {
    let mut lc = DatasetLifecycle::new();
    let roots = [make_root()];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 500);
    assert!(lc.destroy_job().is_some());
    lc.abort_destroy().unwrap();
    assert!(lc.destroy_job().is_none());
    assert_eq!(lc.destroy_progress_ppm(), 0);
}

#[test]
fn abort_destroy_from_active_is_already_in_state() {
    let mut lc = DatasetLifecycle::new();
    let err = lc.abort_destroy().unwrap_err();
    assert!(matches!(err, LifecycleError::AlreadyInState { .. }));
}

#[test]
fn abort_destroy_from_tombstone_is_invalid() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    let err = lc.abort_destroy().unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

// -- recover_tombstone --

#[test]
fn recover_tombstone_returns_to_active() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    lc.recover_tombstone().unwrap();
    assert_eq!(lc.state(), DatasetStateV1::Active);
    assert_eq!(lc.poison_state(), PoisonState::MountOk);
}

#[test]
fn recover_tombstone_is_mountable_again() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    lc.recover_tombstone().unwrap();
    assert!(lc.is_mountable());
    assert!(lc.accepts_writes());
}

#[test]
fn recover_tombstone_from_active_is_already_in_state() {
    let mut lc = DatasetLifecycle::new();
    let err = lc.recover_tombstone().unwrap_err();
    assert!(matches!(err, LifecycleError::AlreadyInState { .. }));
}

#[test]
fn recover_tombstone_from_destroying_is_invalid() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    let err = lc.recover_tombstone().unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

// -- destroy job tracking --

#[test]
fn init_destroy_job_sets_correct_fields() {
    let mut lc = DatasetLifecycle::new();
    let roots = make_roots(2);
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let job = lc.init_destroy_job(42, 1000, DestroyFlags::NONE, &roots, 800);
    assert!(job.is_some());
    let job = job.unwrap();
    assert_eq!(job.destroy_job_id, 42);
    assert_eq!(job.destroy_commit_group, 1000);
    assert_eq!(job.objects_total, 800);
    assert_eq!(job.objects_reclaimed, 0);
    assert!(!job.is_completed());
}

#[test]
fn init_destroy_job_refuses_when_not_destroying() {
    let mut lc = DatasetLifecycle::new();
    let roots = [make_root()];
    let job = lc.init_destroy_job(42, 1000, DestroyFlags::NONE, &roots, 500);
    assert!(job.is_none());
}

#[test]
fn init_destroy_job_refuses_after_tombstone() {
    let mut lc = DatasetLifecycle::new();
    let roots = [make_root()];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    let job = lc.init_destroy_job(42, 1000, DestroyFlags::NONE, &roots, 500);
    assert!(job.is_none());
}

#[test]
fn update_destroy_progress_partial() {
    let mut lc = DatasetLifecycle::new();
    let roots = [TraversalRoot::new(
        TraversalRootType::InodeTable,
        BlockPointer(100),
        1000,
    )];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(1, 1, DestroyFlags::NONE, &roots, 1000);

    let done = lc.update_destroy_progress(500, 1024 * 1024);
    assert!(!done);
    assert_eq!(lc.destroy_progress_ppm(), 500_000);
}

#[test]
fn update_destroy_progress_complete() {
    let mut lc = DatasetLifecycle::new();
    let roots = [TraversalRoot::new(
        TraversalRootType::InodeTable,
        BlockPointer(100),
        1000,
    )];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(1, 1, DestroyFlags::NONE, &roots, 1000);

    let done = lc.update_destroy_progress(1000, 2 * 1024 * 1024);
    assert!(done);
    assert_eq!(lc.destroy_progress_ppm(), 1_000_000);
    assert!(lc.destroy_job().unwrap().is_completed());
}

#[test]
fn update_destroy_progress_over_tracks_last_values() {
    let mut lc = DatasetLifecycle::new();
    let roots = [TraversalRoot::new(
        TraversalRootType::InodeTable,
        BlockPointer(100),
        1000,
    )];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(1, 1, DestroyFlags::NONE, &roots, 1000);
    let _ = lc.update_destroy_progress(100, 5000);
    let _ = lc.update_destroy_progress(300, 15000);
    let _ = lc.update_destroy_progress(600, 30000);
    assert_eq!(lc.destroy_progress_ppm(), 600_000);
    let job = lc.destroy_job().unwrap();
    assert_eq!(job.objects_reclaimed, 600);
    assert_eq!(job.bytes_reclaimed, 30000);
}

#[test]
fn destroy_progress_ppm_zero_for_empty_objects_total() {
    let mut lc = DatasetLifecycle::new();
    let roots = [TraversalRoot::new(
        TraversalRootType::InodeTable,
        BlockPointer(100),
        0,
    )];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(1, 1, DestroyFlags::NONE, &roots, 0);
    assert_eq!(lc.destroy_progress_ppm(), 0);
}

// -- tombstone reaper --

#[test]
fn is_reap_eligible_active_returns_eligible() {
    let lc = DatasetLifecycle::new();
    assert_eq!(lc.is_reap_eligible(0), ReapEligibility::Eligible);
}

#[test]
fn is_reap_eligible_no_destroy_job_eligible() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    assert_eq!(lc.is_reap_eligible(0), ReapEligibility::Eligible);
}

#[test]
fn is_reap_eligible_completed_job_too_young() {
    let mut lc = DatasetLifecycle::new();
    let roots = [make_root()];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 500);
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    // completion_commit_group = u64::MAX, so age at commit_group=100 = 0 < 100 => TooYoung
    let eligibility = lc.is_reap_eligible(100);
    assert!(matches!(eligibility, ReapEligibility::TooYoung { .. }));
}

#[test]
fn is_reap_eligible_completed_job_with_consensus_still_too_young() {
    let mut lc = DatasetLifecycle::new();
    let roots = [make_root()];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 500);
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    lc.set_cluster_consensus_granted();
    // completion_commit_group = u64::MAX, age at commit_group=100 = 0 < 100 => TooYoung
    let eligibility = lc.is_reap_eligible(100);
    assert!(matches!(eligibility, ReapEligibility::TooYoung { .. }));
}

#[test]
fn reap_tombstone_clears_destroy_job() {
    let mut lc = DatasetLifecycle::new();
    let roots = [make_root()];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 500);
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    assert!(lc.destroy_job().is_some());
    lc.reap_tombstone().unwrap();
    assert!(lc.destroy_job().is_none());
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

#[test]
fn reap_tombstone_idempotent() {
    let mut lc = DatasetLifecycle::new();
    let roots = [make_root()];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(1, 100, DestroyFlags::NONE, &roots, 500);
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    lc.reap_tombstone().unwrap();
    assert!(lc.reap_tombstone().is_ok());
}

// -- reaper policy --

#[test]
fn reaper_policy_set_and_get() {
    let mut lc = DatasetLifecycle::new();
    let policy = TombstoneReaperPolicy::new(3600, 50, 10);
    lc.set_reaper_policy(policy);
    let p = lc.reaper_policy();
    assert_eq!(p.min_age_secs, 3600);
    assert_eq!(p.max_per_scan, 50);
    assert_eq!(p.scan_interval_secs, 10);
}

#[test]
fn reaper_policy_zero_values_allowed() {
    let mut lc = DatasetLifecycle::new();
    let policy = TombstoneReaperPolicy::new(0, 0, 0);
    lc.set_reaper_policy(policy);
    let p = lc.reaper_policy();
    assert_eq!(p.min_age_secs, 0);
    assert_eq!(p.max_per_scan, 0);
    assert_eq!(p.scan_interval_secs, 0);
}

// -- full lifecycle roundtrip --

#[test]
fn full_lifecycle_active_to_tombstone_to_recover() {
    let mut lc = DatasetLifecycle::new();
    assert!(lc.is_mountable());

    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert!(!lc.is_mountable());

    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    assert!(!lc.is_mountable());

    lc.recover_tombstone().unwrap();
    assert!(lc.is_mountable());
    assert_eq!(lc.state(), DatasetStateV1::Active);
}

#[test]
fn full_lifecycle_with_abort() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.abort_destroy().unwrap();
    assert!(lc.is_mountable());

    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    assert!(!lc.is_mountable());
}

#[test]
fn full_lifecycle_with_destroy_job_tracking() {
    let mut lc = DatasetLifecycle::new();
    let roots = [TraversalRoot::new(
        TraversalRootType::InodeTable,
        BlockPointer(100),
        1000,
    )];

    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(1, 1, DestroyFlags::NONE, &roots, 1000);
    let _ = lc.update_destroy_progress(300, 5000);
    let _ = lc.update_destroy_progress(600, 10000);
    let _ = lc.update_destroy_progress(1000, 20000);
    assert!(lc.destroy_job().unwrap().is_completed());

    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    lc.recover_tombstone().unwrap();

    assert!(lc.destroy_job().is_none());
    assert_eq!(lc.destroy_progress_ppm(), 0);
}

// -- DestroyFlags combinations --

#[test]
fn destroy_flags_force_unmount_skips_grace() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::FORCE_UNMOUNT, &[])
        .unwrap();
    assert_eq!(lc.poison_state(), PoisonState::PoisonActive);
}

#[test]
fn destroy_flags_dry_run_still_transitions() {
    let flags =
        DestroyFlags::from_bits(DestroyFlags::DRY_RUN.bits() | DestroyFlags::FORCE_UNMOUNT.bits());
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(flags, &[]).unwrap();
    assert_eq!(lc.state(), DatasetStateV1::Destroying);
}

// -- Display format --

#[test]
fn display_shows_destroying_state() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    let s = format!("{lc}");
    assert!(s.contains("destroying"));
}

#[test]
fn display_shows_tombstone_state() {
    let mut lc = DatasetLifecycle::new();
    lc.transition_to_destroying(DestroyFlags::NONE, &[])
        .unwrap();
    lc.escalate_poison();
    lc.transition_to_tombstone().unwrap();
    let s = format!("{lc}");
    assert!(s.contains("tombstone"));
}

#[test]
fn display_includes_destroy_job_info() {
    let mut lc = DatasetLifecycle::new();
    let roots = [make_root()];
    lc.transition_to_destroying(DestroyFlags::NONE, &roots)
        .unwrap();
    let _ = lc.init_destroy_job(42, 1000, DestroyFlags::NONE, &roots, 500);
    let s = format!("{lc}");
    assert!(s.contains("job_id=42"));
}
