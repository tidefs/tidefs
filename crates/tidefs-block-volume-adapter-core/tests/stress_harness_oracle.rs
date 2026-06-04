//! P6-04 profile 3: block_acceptance_profile_3.oracle
//!
//! Differential confirmation against model-internal oracle (cache vs
//! queue runtime coherence, resize fence vs lifecycle state agreement).
//! Lane coverage: D (differential oracle).

#[path = "common/mod.rs"]
mod common;

use common::{
    build_cache, build_live_lifecycle, build_live_resize_runtime, standard_geometry, timed,
    CharterClause, HarnessContext, HarnessProfile, ReleaseGate, ValidationLane,
};
use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeDurabilityClass, BlockVolumeExportPhaseClass,
    BlockVolumeExportTransitionClass, BlockVolumeQueueAdmissionClass, BlockVolumeRequestClass,
    BlockVolumeResizeTransitionOutcomeClass,
};

fn setup_profile() {
    let mut ctx = HarnessContext::global().lock().unwrap();
    ctx.profile_name = Some(HarnessProfile::Oracle.to_string());
    ctx.results.clear();
    drop(ctx);
}

fn finalize_profile() {
    let report = common::render_report();
    eprintln!("{report}");
}

#[test]
fn profile_3_oracle_complete() {
    setup_profile();
    test_oracle_cache_vs_queue_coherence();
    test_oracle_resize_vs_lifecycle_phase();
    test_oracle_flush_barrier_vs_integrity();
    test_oracle_discard_zero_visibility();
    test_oracle_failover_classification_consistency();
    finalize_profile();
}

fn test_oracle_cache_vs_queue_coherence() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut cache = build_cache(geom.volume_id);
        let mut lc = build_live_lifecycle(geom);

        let dirty = cache
            .open_dirty_epoch(BlockRangeRecord::new(8, 4), 16384)
            .expect("dirty");
        assert!(!dirty.sealed_for_barrier);

        let wctx = lc
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(8, 4)),
                16384,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("wctx");
        let decision = lc.admit_submission_context(wctx);
        assert_eq!(
            decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );

        assert!(!cache.dirty_epochs.is_empty());
        assert!(!lc.queue_runtime.inflight_contexts.is_empty());
    });

    HarnessContext::record_result(
        "oracle.cache_vs_queue_coherence",
        ValidationLane::DifferentialOracle,
        HarnessProfile::Oracle,
        vec![ReleaseGate::G3Oracle],
        vec![
            CharterClause::ReadWriteOrderingAndCompletion,
            CharterClause::DirectCachedOverlapCoherency,
        ],
        passed,
        dur,
    );
}

fn test_oracle_resize_vs_lifecycle_phase() {
    let (passed, dur) = timed(|| {
        let mut rt = build_live_resize_runtime();
        let auth = rt.lifecycle_runtime.export_runtime.authority_anchor_ref;

        let refused = rt.prepare_resize(128, auth);
        assert_eq!(
            refused.outcome_class,
            BlockVolumeResizeTransitionOutcomeClass::RefusedNotFenced
        );

        rt.lifecycle_runtime
            .begin_quiesce(BlockVolumeExportTransitionClass::ResizeQuiesce);
        rt.lifecycle_runtime.fence_after_drain();
        assert_eq!(
            rt.lifecycle_runtime.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::Fenced
        );

        let prepared = rt.prepare_resize(128, auth);
        assert_eq!(
            prepared.outcome_class,
            BlockVolumeResizeTransitionOutcomeClass::Prepared
        );
    });

    HarnessContext::record_result(
        "oracle.resize_vs_lifecycle_phase",
        ValidationLane::DifferentialOracle,
        HarnessProfile::Oracle,
        vec![ReleaseGate::G3Oracle],
        vec![CharterClause::DiscardZeroResizeTransition],
        passed,
        dur,
    );
}

fn test_oracle_flush_barrier_vs_integrity() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut cache = build_cache(geom.volume_id);
        let mut lc = build_live_lifecycle(geom);

        let flush_ctx = lc
            .build_submission_context(
                BlockVolumeRequestClass::Flush,
                None,
                0,
                BlockVolumeDurabilityClass::FuaRequired,
            )
            .expect("flush ctx");
        let decision = lc.admit_submission_context(flush_ctx);
        assert_eq!(
            decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );

        let _ = cache.open_dirty_epoch(BlockRangeRecord::new(0, 4), 16384);
        let barrier = cache.seal_flush_barrier(BlockVolumeDurabilityClass::FuaRequired);
        assert!(barrier.satisfied);
        assert!(barrier.fua_ticket_ref.is_some());
    });

    HarnessContext::record_result(
        "oracle.flush_barrier_integrity",
        ValidationLane::DifferentialOracle,
        HarnessProfile::Oracle,
        vec![ReleaseGate::G3Oracle],
        vec![CharterClause::FlushFuaBarrierTruth],
        passed,
        dur,
    );
}

fn test_oracle_discard_zero_visibility() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut cache = build_cache(geom.volume_id);

        let window = cache
            .fill_read_cache_window(BlockRangeRecord::new(0, 4), 16384, false)
            .expect("window");
        assert_eq!(window.cached_bytes, 16384);

        let invalidation = cache
            .issue_discard_or_zero_invalidation(
                BlockVolumeRequestClass::Discard,
                BlockRangeRecord::new(0, 2),
            )
            .expect("invalidation");
        assert_eq!(
            invalidation.affected_cache_window_refs,
            vec![window.cache_window_id]
        );
        assert!(cache.read_cache_hit(BlockRangeRecord::new(0, 2)).is_none());
    });

    HarnessContext::record_result(
        "oracle.discard_zero_visibility",
        ValidationLane::DifferentialOracle,
        HarnessProfile::Oracle,
        vec![ReleaseGate::G3Oracle],
        vec![CharterClause::DiscardZeroResizeTransition],
        passed,
        dur,
    );
}

fn test_oracle_failover_classification_consistency() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut lc = build_live_lifecycle(geom);

        for i in 0..3 {
            let _ = lc
                .build_submission_context(
                    BlockVolumeRequestClass::Write,
                    Some(BlockRangeRecord::new(i * 4, 1)),
                    4096,
                    BlockVolumeDurabilityClass::None,
                )
                .map(|ctx| lc.admit_submission_context(ctx));
        }
        for i in 0..2 {
            let _ = lc
                .build_submission_context(
                    BlockVolumeRequestClass::Read,
                    Some(BlockRangeRecord::new(100 + i, 1)),
                    4096,
                    BlockVolumeDurabilityClass::None,
                )
                .map(|ctx| lc.admit_submission_context(ctx));
        }

        let quiesce = lc.begin_quiesce(BlockVolumeExportTransitionClass::FailoverQuiesce);
        assert!(!quiesce.inflight_classifications.is_empty());
    });

    HarnessContext::record_result(
        "oracle.failover_classification_consistency",
        ValidationLane::DifferentialOracle,
        HarnessProfile::Oracle,
        vec![ReleaseGate::G3Oracle],
        vec![CharterClause::ExportFenceFailoverReplayVisibility],
        passed,
        dur,
    );
}
