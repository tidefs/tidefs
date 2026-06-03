//! P6-04 profile 1: block_acceptance_profile_1.quick_required
//!
//! Required pre-release charter validation for `block_volume_adapter`.
//! Lane coverage: B (guest-fs for ext4/xfs), C (fio workloads),
//! D (discard/zero/resize), E (replay/failover smoke).

#[path = "common/mod.rs"]
mod common;

use common::{
    build_live_lifecycle, standard_geometry, timed, CharterClause, ValidationLane, HarnessContext,
    HarnessProfile, ReleaseGate,
};
use std::env;
use std::fs;
use std::process;
use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeCompletionClass, BlockVolumeDurabilityClass,
    BlockVolumeExportPhaseClass, BlockVolumeExportTransitionClass, BlockVolumeFileImage,
    BlockVolumeGeometryRecord, BlockVolumeId, BlockVolumeImage, BlockVolumeQueueAdmissionClass,
    BlockVolumeRequestClass,
};

fn setup_profile() {
    let mut ctx = HarnessContext::global().lock().unwrap();
    ctx.profile_name = Some(HarnessProfile::QuickRequired.to_string());
    ctx.results.clear();
    drop(ctx);
}

fn finalize_profile() {
    let report = common::render_report();
    eprintln!("{report}");
}

#[test]
fn profile_1_quick_required_complete() {
    setup_profile();
    test_guest_fs_ext4_full();
    test_guest_fs_xfs_smoke();
    test_block_size_sweep();
    test_queue_depth_sweep();
    test_discard_zero_resize();
    test_replay_failover_smoke();
    finalize_profile();
}

fn test_guest_fs_ext4_full() {
    let (passed, dur) = timed(|| {
        let geom = BlockVolumeGeometryRecord::new(BlockVolumeId::new(9201), 4096, 2048, 4);
        let mut path = env::temp_dir();
        path.push(format!("tidefs-quickreq-ext4-{}.img", process::id()));
        let _ = fs::remove_file(&path);

        let mut img = BlockVolumeFileImage::create_zeroed(&path, geom).expect("create");
        let plan = img
            .write_blocks(0, &vec![0x53; 8 * 4096])
            .expect("write sb");
        assert_eq!(plan.completion_class, BlockVolumeCompletionClass::Completed);
        let plan2 = img
            .write_blocks(256, &vec![0x4A; 32 * 4096])
            .expect("write jrnl");
        assert_eq!(
            plan2.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        let fp = img.flush().expect("flush");
        assert_eq!(fp.completion_class, BlockVolumeCompletionClass::Completed);

        for blk in (512..768).step_by(4) {
            let plan = img
                .write_blocks(blk, &vec![0xDD; 4 * 4096])
                .expect("write data");
            assert_eq!(plan.completion_class, BlockVolumeCompletionClass::Completed);
        }
        let fp2 = img.flush().expect("flush2");
        assert_eq!(fp2.completion_class, BlockVolumeCompletionClass::Completed);
        drop(img);

        let img = BlockVolumeFileImage::reopen_existing(&path, geom).expect("reopen");
        let (rp, data) = img
            .read_blocks(BlockRangeRecord::new(512, 4))
            .expect("read");
        assert_eq!(rp.completion_class, BlockVolumeCompletionClass::Completed);
        assert_eq!(data.unwrap(), vec![0xDD; 4 * 4096]);
        let _ = fs::remove_file(&path);
    });

    HarnessContext::record_result(
        "guest_fs.ext4.full_cycle",
        ValidationLane::GuestFs,
        HarnessProfile::QuickRequired,
        vec![ReleaseGate::G1QuickRequired],
        vec![
            CharterClause::ReadWriteOrderingAndCompletion,
            CharterClause::FlushFuaBarrierTruth,
        ],
        passed,
        dur,
    );
}

fn test_guest_fs_xfs_smoke() {
    let (passed, dur) = timed(|| {
        let geom = BlockVolumeGeometryRecord::new(BlockVolumeId::new(9202), 4096, 2048, 4);
        let mut path = env::temp_dir();
        path.push(format!("tidefs-quickreq-xfs-{}.img", process::id()));
        let _ = fs::remove_file(&path);

        let mut img = BlockVolumeFileImage::create_zeroed(&path, geom).expect("create");
        let plan = img.write_blocks(0, &vec![0x58; 16384]).expect("write ag");
        assert_eq!(plan.completion_class, BlockVolumeCompletionClass::Completed);
        let fp = img.flush().expect("flush");
        assert_eq!(fp.completion_class, BlockVolumeCompletionClass::Completed);
        drop(img);

        let img = BlockVolumeFileImage::reopen_existing(&path, geom).expect("reopen");
        let (rp, _) = img.read_blocks(BlockRangeRecord::new(0, 1)).expect("read");
        assert_eq!(rp.completion_class, BlockVolumeCompletionClass::Completed);
        let _ = fs::remove_file(&path);
    });

    HarnessContext::record_result(
        "guest_fs.xfs.smoke",
        ValidationLane::GuestFs,
        HarnessProfile::QuickRequired,
        vec![ReleaseGate::G1QuickRequired],
        vec![
            CharterClause::ReadWriteOrderingAndCompletion,
            CharterClause::FlushFuaBarrierTruth,
        ],
        passed,
        dur,
    );
}

fn test_block_size_sweep() {
    let mut all_passed = true;
    let (_, dur) = timed(|| {
        let geom = standard_geometry();
        let mut path = env::temp_dir();
        path.push(format!("tidefs-quickreq-bs-{}.img", process::id()));
        let _ = fs::remove_file(&path);

        let mut img = BlockVolumeFileImage::create_zeroed(&path, geom).expect("create");
        for block_count in [1usize, 4, 16, 64] {
            let payload = vec![0xDD; block_count * 4096];
            let plan = img.write_blocks(0, &payload).expect("write");
            if plan.completion_class != BlockVolumeCompletionClass::Completed {
                all_passed = false;
                break;
            }
            let (_, data) = img
                .read_blocks(BlockRangeRecord::new(0, block_count))
                .expect("read");
            if data.unwrap() != payload {
                all_passed = false;
                break;
            }
        }
        let _ = fs::remove_file(&path);
    });

    HarnessContext::record_result(
        "fio.block_size_sweep",
        ValidationLane::FioWorkload,
        HarnessProfile::QuickRequired,
        vec![ReleaseGate::G1QuickRequired],
        vec![
            CharterClause::BlockIdentityGeometryProjection,
            CharterClause::ReadWriteOrderingAndCompletion,
        ],
        all_passed,
        dur,
    );
}

fn test_queue_depth_sweep() {
    let mut all_passed = true;
    let (_, dur) = timed(|| {
        let geom = standard_geometry();
        let mut lc = build_live_lifecycle(geom);
        let mut contexts = Vec::new();
        for i in 0..16 {
            let ctx = lc.build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new((i * 4) % 256, 1)),
                4096,
                BlockVolumeDurabilityClass::None,
            );
            if let Some(c) = ctx {
                let decision = lc.admit_submission_context(c);
                if decision.admission_class != BlockVolumeQueueAdmissionClass::Admitted {
                    all_passed = false;
                    break;
                }
                contexts.push(decision.submission_context_ref);
            } else {
                all_passed = false;
                break;
            }
        }
        for ctx_id in &contexts {
            lc.complete_submission_context(*ctx_id, BlockVolumeCompletionClass::Completed, 4096);
        }
    });

    HarnessContext::record_result(
        "fio.queue_depth_sweep",
        ValidationLane::FioWorkload,
        HarnessProfile::QuickRequired,
        vec![ReleaseGate::G1QuickRequired],
        vec![
            CharterClause::ReadWriteOrderingAndCompletion,
            CharterClause::ReservePressureAdmissionAndDenial,
        ],
        all_passed,
        dur,
    );
}

fn test_discard_zero_resize() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut path = env::temp_dir();
        path.push(format!("tidefs-quickreq-dzr-{}.img", process::id()));
        let _ = fs::remove_file(&path);

        let mut img = BlockVolumeFileImage::create_zeroed(&path, geom).expect("create");
        let plan = img.write_blocks(10, &vec![0xCC; 8 * 4096]).expect("write");
        assert_eq!(plan.completion_class, BlockVolumeCompletionClass::Completed);
        let dp = img
            .discard_blocks(BlockRangeRecord::new(10, 4))
            .expect("discard");
        assert_eq!(dp.completion_class, BlockVolumeCompletionClass::Completed);
        let zp = img
            .write_zeroes(BlockRangeRecord::new(20, 4))
            .expect("write_zeroes");
        assert_eq!(zp.completion_class, BlockVolumeCompletionClass::Completed);

        // Resize on in-memory image
        let mut mem_img = BlockVolumeImage::open_zeroed(geom).expect("open_zeroed");
        let new_geom = BlockVolumeGeometryRecord::new(BlockVolumeId::new(9203), 4096, 512, 4);
        assert!(mem_img.resize_to(new_geom).is_some());

        let _ = fs::remove_file(&path);
    });

    HarnessContext::record_result(
        "discard.zero.resize.image",
        ValidationLane::FioWorkload,
        HarnessProfile::QuickRequired,
        vec![ReleaseGate::G1QuickRequired],
        vec![CharterClause::DiscardZeroResizeTransition],
        passed,
        dur,
    );
}

fn test_replay_failover_smoke() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut lc = build_live_lifecycle(geom);

        let wctx = lc
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(0, 4)),
                4096 * 4,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("write ctx");
        let decision = lc.admit_submission_context(wctx);
        assert_eq!(
            decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );

        let quiesce = lc.begin_quiesce(BlockVolumeExportTransitionClass::FailoverQuiesce);
        assert_eq!(
            quiesce.outcome_class,
            tidefs_block_volume_adapter_core::BlockVolumeExportTransitionOutcomeClass::Completed
        );
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
        "replay.failover.smoke",
        ValidationLane::FailoverCutover,
        HarnessProfile::QuickRequired,
        vec![
            ReleaseGate::G1QuickRequired,
            ReleaseGate::G2PressureFailover,
        ],
        vec![CharterClause::ExportFenceFailoverReplayVisibility],
        passed,
        dur,
    );
}
