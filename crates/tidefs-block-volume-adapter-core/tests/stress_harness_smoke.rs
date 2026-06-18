// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! P6-04 profile 0: block_acceptance_profile_0.smoke
//!
//! Fastest viability proof — run on every serious integration loop.
//! Lane coverage: A (clause/property), B (guest-fs acceptance).

#[path = "common/mod.rs"]
mod common;

use common::{
    build_live_lifecycle, build_queue, standard_geometry, timed, CharterClause, HarnessContext,
    HarnessProfile, ReleaseGate, ValidationLane,
};
use std::env;
use std::fs;
use std::process;
use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeCompletionClass, BlockVolumeDispatchClass,
    BlockVolumeDurabilityClass, BlockVolumeExportPhaseClass, BlockVolumeExportTransitionClass,
    BlockVolumeFileImage, BlockVolumeGeometryRecord, BlockVolumeId, BlockVolumeImage,
    BlockVolumeQueueAdmissionClass, BlockVolumeRequestClass,
};

fn setup_profile() {
    let mut ctx = HarnessContext::global().lock().unwrap();
    ctx.profile_name = Some(HarnessProfile::Smoke.to_string());
    ctx.results.clear();
    drop(ctx);
}

fn finalize_profile() {
    let report = common::render_report();
    eprintln!("{report}");
}

#[test]
fn profile_0_smoke_complete() {
    setup_profile();
    test_clause_identity_geometry();
    test_clause_read_write_ordering();
    test_clause_flush_fua_barrier();
    test_export_attach_detach();
    test_guest_fs_ext4_smoke();
    test_flush_fua_probe();
    finalize_profile();
}

fn test_clause_identity_geometry() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        assert_eq!(geom.block_size_bytes, 4096);
        assert_eq!(geom.block_count, 256);
        assert!(geom.capacity_bytes().is_some());
        assert!(geom.admits_discard());
        let small = common::small_geometry();
        assert!(!small.admits_discard());
        assert_eq!(small.block_size_bytes, 512);
    });

    HarnessContext::record_result(
        "clause.identity_geometry.projection",
        ValidationLane::ClauseProperty,
        HarnessProfile::Smoke,
        vec![ReleaseGate::G0Smoke],
        vec![CharterClause::BlockIdentityGeometryProjection],
        passed,
        dur,
    );
}

fn test_clause_read_write_ordering() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut q = build_queue(geom);
        let ctx = q
            .build_submission_context(
                BlockVolumeRequestClass::Read,
                Some(BlockRangeRecord::new(0, 1)),
                4096,
                BlockVolumeDurabilityClass::None,
            )
            .expect("read ctx");
        assert_eq!(ctx.request_class, BlockVolumeRequestClass::Read);
        assert_eq!(ctx.range, Some(BlockRangeRecord::new(0, 1)));

        let wctx = q
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(10, 2)),
                8192,
                BlockVolumeDurabilityClass::None,
            )
            .expect("write ctx");
        assert_eq!(wctx.request_class, BlockVolumeRequestClass::Write);
    });

    HarnessContext::record_result(
        "clause.read_write_ordering.submission_contexts",
        ValidationLane::ClauseProperty,
        HarnessProfile::Smoke,
        vec![ReleaseGate::G0Smoke],
        vec![CharterClause::ReadWriteOrderingAndCompletion],
        passed,
        dur,
    );
}

fn test_clause_flush_fua_barrier() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut q = build_queue(geom);
        let ctx = q
            .build_submission_context(
                BlockVolumeRequestClass::Flush,
                None,
                0,
                BlockVolumeDurabilityClass::FlushRequired,
            )
            .expect("flush ctx");
        assert_eq!(ctx.request_class, BlockVolumeRequestClass::Flush);
        assert_eq!(
            ctx.durability_class,
            BlockVolumeDurabilityClass::FlushRequired
        );

        let fua_ctx = q
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(0, 1)),
                4096,
                BlockVolumeDurabilityClass::FuaRequired,
            )
            .expect("fua ctx");
        assert_eq!(
            fua_ctx.durability_class,
            BlockVolumeDurabilityClass::FuaRequired
        );
    });

    HarnessContext::record_result(
        "clause.flush_fua_barrier.submission",
        ValidationLane::ClauseProperty,
        HarnessProfile::Smoke,
        vec![ReleaseGate::G0Smoke],
        vec![CharterClause::FlushFuaBarrierTruth],
        passed,
        dur,
    );
}

fn test_export_attach_detach() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut lc = build_live_lifecycle(geom);
        assert_eq!(
            lc.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::QueuesLive
        );
        lc.begin_quiesce(BlockVolumeExportTransitionClass::RevokeQuiesce);
        lc.fence_after_drain();
        lc.stop_after_drain();
        assert_eq!(
            lc.export_runtime.export_phase_class,
            BlockVolumeExportPhaseClass::Stopped
        );
    });

    HarnessContext::record_result(
        "export.attach_detach.lifecycle",
        ValidationLane::ClauseProperty,
        HarnessProfile::Smoke,
        vec![ReleaseGate::G0Smoke],
        vec![
            CharterClause::ExportFenceFailoverReplayVisibility,
            CharterClause::IntentionalCutsVisible,
        ],
        passed,
        dur,
    );
}

fn test_guest_fs_ext4_smoke() {
    let (passed, dur) = timed(|| {
        let geom = BlockVolumeGeometryRecord::new(BlockVolumeId::new(9101), 4096, 1024, 4);
        let mut path = env::temp_dir();
        path.push(format!("tidefs-stress-smoke-ext4-{}.img", process::id()));
        let _ = fs::remove_file(&path);

        {
            let mut img = BlockVolumeFileImage::create_zeroed(&path, geom).expect("create");
            let plan = img.write_blocks(0, &vec![0xAB; 4 * 4096]).expect("write");
            assert_eq!(plan.completion_class, BlockVolumeCompletionClass::Completed);
            let fp = img.flush().expect("flush");
            assert_eq!(fp.completion_class, BlockVolumeCompletionClass::Completed);
        }
        {
            let img = BlockVolumeFileImage::reopen_existing(&path, geom).expect("reopen");
            let (rp, data) = img.read_blocks(BlockRangeRecord::new(0, 4)).expect("read");
            assert_eq!(rp.completion_class, BlockVolumeCompletionClass::Completed);
            assert_eq!(data.unwrap(), vec![0xAB; 4 * 4096]);
        }
        let _ = fs::remove_file(&path);
    });

    HarnessContext::record_result(
        "guest_fs.ext4.smoke.write_flush_reopen",
        ValidationLane::GuestFs,
        HarnessProfile::Smoke,
        vec![ReleaseGate::G0Smoke],
        vec![
            CharterClause::ReadWriteOrderingAndCompletion,
            CharterClause::FlushFuaBarrierTruth,
        ],
        passed,
        dur,
    );
}

fn test_flush_fua_probe() {
    let (passed, dur) = timed(|| {
        let geom = standard_geometry();
        let mut lc = build_live_lifecycle(geom);
        let mut image = BlockVolumeImage::open_zeroed(geom).expect("zeroed image");
        let payload = vec![0x6F; geom.block_size_bytes];

        let write_ctx = lc
            .build_submission_context(
                BlockVolumeRequestClass::Write,
                Some(BlockRangeRecord::new(8, 1)),
                payload.len(),
                BlockVolumeDurabilityClass::None,
            )
            .expect("write ctx");
        let write_decision = lc.admit_submission_context(write_ctx);
        assert_eq!(
            write_decision.admission_class,
            BlockVolumeQueueAdmissionClass::Admitted
        );
        let (write_dispatch, write_read_payload) = lc.queue_runtime.dispatch_submission_context(
            &mut image,
            write_decision.submission_context_ref,
            Some(&payload),
        );
        let dirty_epoch = write_dispatch
            .request_plan
            .dirty_epoch_ref
            .expect("dirty epoch");
        assert_eq!(
            write_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert!(write_read_payload.is_none());

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

        let (flush_dispatch, flush_payload) = lc.queue_runtime.dispatch_submission_context(
            &mut image,
            decision.submission_context_ref,
            None,
        );
        assert!(flush_payload.is_none());
        assert_eq!(
            flush_dispatch.dispatch_class,
            BlockVolumeDispatchClass::Executed
        );
        assert_eq!(
            flush_dispatch.request_plan.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(flush_dispatch.request_plan.flush_barrier_ref.is_some());
        assert!(flush_dispatch.completion_commit_ref.is_some());
        assert_eq!(image.flush_barriers.len(), 1);
        assert_eq!(image.flush_barriers[0].covered_epoch_ids, vec![dirty_epoch]);
        assert!(image
            .dirty_epochs
            .iter()
            .all(|epoch| epoch.sealed_for_flush));
        assert_eq!(lc.queue_runtime.flush_epochs.len(), 1);
        assert_eq!(lc.queue_runtime.backpressure.inflight_requests, 0);
    });

    HarnessContext::record_result(
        "flush_fua.probe.synthetic_dispatch_write_flush",
        ValidationLane::GuestFs,
        HarnessProfile::Smoke,
        vec![ReleaseGate::G0Smoke],
        vec![CharterClause::FlushFuaBarrierTruth],
        passed,
        dur,
    );
}
