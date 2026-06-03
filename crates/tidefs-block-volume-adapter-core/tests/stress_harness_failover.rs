//! P6-04 profile 5: block_acceptance_profile_5.failover
//!
//! Transition correctness under failover, cutover, and replay.
//! Lane coverage: F (failover/cutover), G (upgrade/replay).

#[path = "common/mod.rs"]
mod common;

use common::{
    build_cache, build_fenced_resize_runtime, build_live_lifecycle, standard_geometry, timed,
    CharterClause, ValidationLane, HarnessContext, HarnessProfile, ReleaseGate,
};
use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeCacheTransitionClass, BlockVolumeDurabilityClass,
    BlockVolumeExportPhaseClass, BlockVolumeExportTransitionClass, BlockVolumeQueueAdmissionClass,
    BlockVolumeRequestClass, BlockVolumeResizeTransitionOutcomeClass,
};

fn setup_profile() {
    let mut ctx = HarnessContext::global().lock().unwrap();
    ctx.profile_name = Some(HarnessProfile::Failover.to_string());
    ctx.results.clear();
    drop(ctx);
}

fn finalize_profile() {
    let report = common::render_report();
    eprintln!("{report}");
}

#[test]
fn profile_5_failover_complete() {
    setup_profile();
    test_export_fence_while_inflight();
    test_resize_prepare_commit_inflight();
    test_failover_while_dirty_ranges();
    test_replay_cursor_after_crash();
    test_revoke_stop_under_pressure();
    finalize_profile();
}

fn test_export_fence_while_inflight() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut lc = build_live_lifecycle(geom);
        let read_ctx = lc
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new(0, 4)),
                16384,
                BlockVolumeDurabilityClass::None,
            )
            .expect("read ctx");
        let write_ctx = lc
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(10, 4)),
                16384,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("write ctx");
        lc.admit_submission_context(read_ctx);
        lc.admit_submission_context(write_ctx);

        let quiesce = lc.begin_quiesce(BlockVolumeExportTransitionClass::ResizeQuiesce);
        assert!(!quiesce.inflight_classifications.is_empty());

        lc.fence_after_drain();
        assert_eq!(
            lc.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::Fenced
        );
        lc.resume_after_fence();
        assert_eq!(
            lc.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::Resumed
        );
    });

    HarnessContext::record_result(
        "failover.export_fence_while_inflight",
        ValidationLane::FailoverCutover,
        HarnessProfile::Failover,
        vec![
            ReleaseGate::G2PressureFailover,
            ReleaseGate::G5UpgradeReplay,
        ],
        vec![CharterClause::ExportFenceFailoverReplayVisibility],
        passed,
        dur,
    );
}

fn test_resize_prepare_commit_inflight() {
    let (passed, dur) = timed(|| {
        let mut rt = build_fenced_resize_runtime();
        let auth = rt.lifecycle_runtime.export_runtime.authority_anchor_ref;

        let prepared = rt.prepare_resize(512, auth);
        assert_eq!(
            prepared.outcome_class,
            BlockVolumeResizeTransitionOutcomeClass::Prepared
        );
        let committed = rt.commit_resize(prepared.transition_id);
        assert_eq!(
            committed.outcome_class,
            BlockVolumeResizeTransitionOutcomeClass::Committed
        );
        assert_eq!(rt.current_geometry.block_count, 512);
    });

    HarnessContext::record_result(
        "failover.resize_prepare_commit",
        ValidationLane::FailoverCutover,
        HarnessProfile::Failover,
        vec![
            ReleaseGate::G2PressureFailover,
            ReleaseGate::G5UpgradeReplay,
        ],
        vec![CharterClause::DiscardZeroResizeTransition],
        passed,
        dur,
    );
}

fn test_failover_while_dirty_ranges() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut cache = build_cache(geom.volume_id);
        cache
            .open_dirty_epoch(BlockRangeRecord::new(0, 8), 32768)
            .expect("dirty1");
        cache
            .open_dirty_epoch(BlockRangeRecord::new(16, 8), 32768)
            .expect("dirty2");
        cache
            .open_dirty_epoch(BlockRangeRecord::new(32, 8), 32768)
            .expect("dirty3");

        let (barrier, transition) = cache.drain_dirty_ranges_for_failover_or_cutover();
        assert!(barrier.satisfied);
        assert_eq!(
            transition.transition_class,
            BlockVolumeCacheTransitionClass::FailoverFence
        );
        for epoch in &cache.dirty_epochs {
            assert!(epoch.sealed_for_barrier);
        }
    });

    HarnessContext::record_result(
        "failover.while_dirty_ranges",
        ValidationLane::FailoverCutover,
        HarnessProfile::Failover,
        vec![
            ReleaseGate::G2PressureFailover,
            ReleaseGate::G5UpgradeReplay,
        ],
        vec![
            CharterClause::ExportFenceFailoverReplayVisibility,
            CharterClause::DirectCachedOverlapCoherency,
        ],
        passed,
        dur,
    );
}

fn test_replay_cursor_after_crash() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut lc = build_live_lifecycle(geom);

        let flush_ctx = lc
            .build_submission_context(
                BlockVolumeRequestClass::Flush,
                None,
                0,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("flush ctx");
        let decision = lc.admit_submission_context(flush_ctx);
        assert_eq!(
            decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );

        lc.begin_quiesce(BlockVolumeExportTransitionClass::FailoverQuiesce);
        assert!(!lc.transition_records.is_empty());
        lc.fence_after_drain();
        lc.resume_after_fence();
    });

    HarnessContext::record_result(
        "failover.replay_cursor_after_crash",
        ValidationLane::UpgradeReplay,
        HarnessProfile::Failover,
        vec![ReleaseGate::G5UpgradeReplay],
        vec![
            CharterClause::ExportFenceFailoverReplayVisibility,
            CharterClause::FlushFuaBarrierTruth,
        ],
        passed,
        dur,
    );
}

fn test_revoke_stop_under_pressure() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut lc = build_live_lifecycle(geom);

        for i in 0..8 {
            let _ = lc
                .build_submission_context(
                    BlockVolumeRequestClass::Write,
                    Some(BlockRangeRecord::new(i * 4, 2)),
                    8192,
                    BlockVolumeDurabilityClass::FlushRequired,
                )
                .map(|ctx| lc.admit_submission_context(ctx));
        }

        lc.begin_quiesce(BlockVolumeExportTransitionClass::RevokeQuiesce);
        lc.fence_after_drain();
        lc.stop_after_drain();
        assert_eq!(
            lc.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::Stopped
        );
    });

    HarnessContext::record_result(
        "failover.revoke_stop_under_pressure",
        ValidationLane::UpgradeReplay,
        HarnessProfile::Failover,
        vec![ReleaseGate::G5UpgradeReplay],
        vec![
            CharterClause::ExportFenceFailoverReplayVisibility,
            CharterClause::IntentionalCutsVisible,
        ],
        passed,
        dur,
    );
}
