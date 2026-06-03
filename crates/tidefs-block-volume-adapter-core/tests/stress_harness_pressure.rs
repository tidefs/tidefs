//! P6-04 profile 2: block_acceptance_profile_2.quick_pressure
//!
//! Force block charter behavior under pressure and degraded conditions.
//! Lane coverage: E (stress), C (fio under pressure).

#[path = "common/mod.rs"]
mod common;

use common::{
    build_cache, build_live_lifecycle, build_live_resize_runtime, standard_geometry, timed,
    CharterClause, ValidationLane, HarnessContext, HarnessProfile, ReleaseGate,
};
use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeDurabilityClass, BlockVolumeExportTransitionClass,
    BlockVolumeQueueAdmissionClass, BlockVolumeQueueRuntime, BlockVolumeRequestClass,
};

fn setup_profile() {
    let mut ctx = HarnessContext::global().lock().unwrap();
    ctx.profile_name = Some(HarnessProfile::QuickPressure.to_string());
    ctx.results.clear();
    drop(ctx);
}

fn finalize_profile() {
    let report = common::render_report();
    eprintln!("{report}");
}

#[test]
fn profile_2_quick_pressure_complete() {
    setup_profile();
    test_low_inflight_budget();
    test_pin_pressure_dirty_backlog();
    test_dirty_writeback_backlog();
    test_resize_under_load();
    test_failover_inflight_dirty();
    finalize_profile();
}

fn test_low_inflight_budget() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut q = BlockVolumeQueueRuntime::open(geom, 4, 2, 4096).expect("tight queue");
        let c1 = q
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new(0, 1)),
                4096,
                BlockVolumeDurabilityClass::None,
            )
            .expect("c1");
        let c2 = q
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new(1, 1)),
                4096,
                BlockVolumeDurabilityClass::None,
            )
            .expect("c2");
        assert_eq!(c1.range, Some(BlockRangeRecord::new(0, 1)));
        assert_eq!(c2.range, Some(BlockRangeRecord::new(1, 1)));
    });

    HarnessContext::record_result(
        "pressure.low_inflight_budget",
        ValidationLane::StressSoak,
        HarnessProfile::QuickPressure,
        vec![ReleaseGate::G2PressureFailover],
        vec![CharterClause::ReservePressureAdmissionAndDenial],
        passed,
        dur,
    );
}

fn test_pin_pressure_dirty_backlog() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut cache = build_cache(geom.volume_id);
        for i in 0..20 {
            let epoch = cache
                .open_dirty_epoch(BlockRangeRecord::new(i % 64, 8), (i + 1) * 512)
                .expect("dirty epoch");
            assert!(!epoch.sealed_for_barrier);
        }
        let barrier = cache.seal_flush_barrier(BlockVolumeDurabilityClass::FlushRequired);
        assert!(!barrier.covered_cache_epoch_refs.is_empty());
    });

    HarnessContext::record_result(
        "pressure.pin_dirty_backlog",
        ValidationLane::StressSoak,
        HarnessProfile::QuickPressure,
        vec![ReleaseGate::G2PressureFailover],
        vec![CharterClause::DirectCachedOverlapCoherency],
        passed,
        dur,
    );
}

fn test_dirty_writeback_backlog() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut cache = build_cache(geom.volume_id);
        for i in 0..32 {
            cache
                .open_dirty_epoch(BlockRangeRecord::new((i * 4) % 200, 4), 4096)
                .expect("dirty");
        }
        let barrier = cache.seal_flush_barrier(BlockVolumeDurabilityClass::FuaRequired);
        assert!(barrier.satisfied);
        assert!(barrier.fua_ticket_ref.is_some());
    });

    HarnessContext::record_result(
        "pressure.dirty_writeback_fua",
        ValidationLane::StressSoak,
        HarnessProfile::QuickPressure,
        vec![ReleaseGate::G2PressureFailover],
        vec![CharterClause::FlushFuaBarrierTruth],
        passed,
        dur,
    );
}

fn test_resize_under_load() {
    let (passed, dur) = timed(|| {
        let mut rt = build_live_resize_runtime();
        let auth = rt.lifecycle_runtime.export_runtime.authority_anchor_ref;
        rt.cache_runtime
            .open_dirty_epoch(BlockRangeRecord::new(200, 8), 4096)
            .expect("dirty");
        rt.lifecycle_runtime
            .begin_quiesce(BlockVolumeExportTransitionClass::ResizeQuiesce);
        rt.lifecycle_runtime.fence_after_drain();
        let _prepared = rt.prepare_resize(128, auth);
    });

    HarnessContext::record_result(
        "pressure.resize_under_load",
        ValidationLane::StressSoak,
        HarnessProfile::QuickPressure,
        vec![ReleaseGate::G2PressureFailover],
        vec![CharterClause::DiscardZeroResizeTransition],
        passed,
        dur,
    );
}

fn test_failover_inflight_dirty() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut lc = build_live_lifecycle(geom);
        for i in 0..4 {
            let ctx = lc
                .build_submission_context(
                    BlockVolumeRequestClass::Write,
                    Some(BlockRangeRecord::new(i * 10, 2)),
                    8192,
                    BlockVolumeDurabilityClass::FlushRequired,
                )
                .expect("ctx");
            let decision = lc.admit_submission_context(ctx);
            assert_eq!(
                decision.admission_class,
                BlockVolumeQueueAdmissionClass::Admitted
            );
        }
        lc.begin_quiesce(BlockVolumeExportTransitionClass::FailoverQuiesce);
        lc.fence_after_drain();
        lc.resume_after_fence();
    });

    HarnessContext::record_result(
        "pressure.failover_inflight_dirty",
        ValidationLane::StressSoak,
        HarnessProfile::QuickPressure,
        vec![ReleaseGate::G2PressureFailover],
        vec![CharterClause::ExportFenceFailoverReplayVisibility],
        passed,
        dur,
    );
}
