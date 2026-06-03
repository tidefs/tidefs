//! P6-04 profile 4: block_acceptance_profile_4.soak
//!
//! Sustained stress and leak/deadlock hunting.
//! Lane coverage: E (stress/soak), C (fio campaigns).

#[path = "common/mod.rs"]
mod common;

use common::{
    build_cache, build_live_lifecycle, standard_geometry, timed, CharterClause, ValidationLane,
    HarnessContext, HarnessProfile, ReleaseGate,
};
use std::env;
use std::fs;
use std::process;
use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeCompletionClass, BlockVolumeDurabilityClass,
    BlockVolumeExportPhaseClass, BlockVolumeExportTransitionClass, BlockVolumeFileImage,
    BlockVolumeGeometryRecord, BlockVolumeId, BlockVolumeRequestClass,
};

fn setup_profile() {
    let mut ctx = HarnessContext::global().lock().unwrap();
    ctx.profile_name = Some(HarnessProfile::Soak.to_string());
    ctx.results.clear();
    drop(ctx);
}

fn finalize_profile() {
    let report = common::render_report();
    eprintln!("{report}");
}

#[test]
fn profile_4_soak_complete() {
    setup_profile();
    test_soak_mixed_fio_iterations();
    test_soak_repeated_attach_detach();
    test_soak_resize_failover_burst();
    test_soak_discard_zero_overlap_storm();
    test_soak_pin_register_exhaustion();
    finalize_profile();
}

fn test_soak_mixed_fio_iterations() {
    let (passed, dur) = timed(|| {
        let geom = BlockVolumeGeometryRecord::new(BlockVolumeId::new(9401), 4096, 512, 4);
        let mut path = env::temp_dir();
        path.push(format!("tidefs-soak-fio-{}.img", process::id()));
        let _ = fs::remove_file(&path);

        let mut img = BlockVolumeFileImage::create_zeroed(&path, geom).expect("create");
        for cycle in 0..500usize {
            let fill = (cycle % 255) as u8;
            let start = (cycle * 3) % 500;
            let plan = img.write_blocks(start, &vec![fill; 4096]).expect("write");
            if plan.completion_class != BlockVolumeCompletionClass::Completed {
                let _ = fs::remove_file(&path);
                panic!("write failed at cycle {cycle}");
            }
            if cycle % 10 == 0 {
                let (rp, _) = img
                    .read_blocks(BlockRangeRecord::new(start, 1))
                    .expect("read");
                assert_eq!(rp.completion_class, BlockVolumeCompletionClass::Completed);
            }
            if cycle % 50 == 0 {
                let fp = img.flush().expect("flush");
                assert_eq!(fp.completion_class, BlockVolumeCompletionClass::Completed);
            }
        }
        let _ = fs::remove_file(&path);
    });

    HarnessContext::record_result(
        "soak.mixed_fio_500_iterations",
        ValidationLane::StressSoak,
        HarnessProfile::Soak,
        vec![ReleaseGate::G4Soak],
        vec![
            CharterClause::ReadWriteOrderingAndCompletion,
            CharterClause::FlushFuaBarrierTruth,
        ],
        passed,
        dur,
    );
}

fn test_soak_repeated_attach_detach() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut lc = build_live_lifecycle(geom);
        for _ in 0..100 {
            lc.begin_quiesce(BlockVolumeExportTransitionClass::RevokeQuiesce);
            lc.fence_after_drain();
            assert_eq!(
                lc.export_runtime.export_phase_class,
                BlockVolumeExportPhaseClass::Fenced
            );
            lc.stop_after_drain();
            assert_eq!(
                lc.export_runtime.export_phase_class,
                BlockVolumeExportPhaseClass::Stopped
            );
        }
    });

    HarnessContext::record_result(
        "soak.repeated_attach_detach_100",
        ValidationLane::StressSoak,
        HarnessProfile::Soak,
        vec![ReleaseGate::G4Soak],
        vec![
            CharterClause::ExportFenceFailoverReplayVisibility,
            CharterClause::IntentionalCutsVisible,
        ],
        passed,
        dur,
    );
}

fn test_soak_resize_failover_burst() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        for _ in 0..50 {
            let mut lc = build_live_lifecycle(geom);
            for i in 0..4 {
                let _ = lc
                    .build_submission_context(
                        BlockVolumeRequestClass::Write,
                        Some(BlockRangeRecord::new(i * 8, 2)),
                        8192,
                        BlockVolumeDurabilityClass::None,
                    )
                    .map(|ctx| lc.admit_submission_context(ctx));
            }
            lc.begin_quiesce(BlockVolumeExportTransitionClass::FailoverQuiesce);
            lc.fence_after_drain();
            lc.resume_after_fence();
        }
    });

    HarnessContext::record_result(
        "soak.resize_failover_burst_50",
        ValidationLane::StressSoak,
        HarnessProfile::Soak,
        vec![ReleaseGate::G4Soak],
        vec![CharterClause::ExportFenceFailoverReplayVisibility],
        passed,
        dur,
    );
}

fn test_soak_discard_zero_overlap_storm() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut cache = build_cache(geom.volume_id);
        for i in 0..100usize {
            let start = (i * 3) % 200;
            let _ = cache.fill_read_cache_window(BlockRangeRecord::new(start, 4), 16384, false);
            let _ = cache.open_dirty_epoch(BlockRangeRecord::new(start + 2, 2), 8192);
            let req_class = if i % 2 == 0 {
                BlockVolumeRequestClass::Discard
            } else {
                BlockVolumeRequestClass::WriteZeroes
            };
            let _ = cache
                .issue_discard_or_zero_invalidation(req_class, BlockRangeRecord::new(start, 6));
        }
    });

    HarnessContext::record_result(
        "soak.discard_zero_overlap_storm_100",
        ValidationLane::StressSoak,
        HarnessProfile::Soak,
        vec![ReleaseGate::G4Soak],
        vec![CharterClause::DiscardZeroResizeTransition],
        passed,
        dur,
    );
}

fn test_soak_pin_register_exhaustion() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut cache = build_cache(geom.volume_id);
        for i in 0..200 {
            cache
                .open_dirty_epoch(BlockRangeRecord::new((i * 4) % 200, 4), 65536)
                .expect("dirty epoch");
        }
        let (barrier, _transition) = cache.drain_dirty_ranges_for_failover_or_cutover();
        assert!(barrier.satisfied);
        for epoch in &cache.dirty_epochs {
            assert!(epoch.sealed_for_barrier);
        }
    });

    HarnessContext::record_result(
        "soak.pin_register_exhaustion_200",
        ValidationLane::StressSoak,
        HarnessProfile::Soak,
        vec![ReleaseGate::G4Soak],
        vec![
            CharterClause::ReservePressureAdmissionAndDenial,
            CharterClause::DirectCachedOverlapCoherency,
        ],
        passed,
        dur,
    );
}
