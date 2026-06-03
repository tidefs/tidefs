//! Block-volume-adapter-core smoke: deterministic runtime checks for the
//! OW-301A block-volume model and file-backed image surface.
//!
//! Gated on `feature = "ublk"`.

use crate::smoke::SmokeHarness;
use crate::trace::{deserialize_trace, serialize_trace, TraceEvent};
use tidefs_block_volume_adapter_core::{
    plan_discard_request_bounds, plan_read_write_request_bounds, BlockRangeRecord,
    BlockVolumeCompletionClass, BlockVolumeFileImage, BlockVolumeFlushBarrierClass,
    BlockVolumeGeometryRecord, BlockVolumeId, BlockVolumeRequestClass,
    BLOCK_VOLUME_ADAPTER_CORE_GATE_OW_301A,
};

/// Run the full ublk smoke sequence and return the harness.
#[must_use]
pub fn run_block_volume_adapter_core_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("ublk/smoke");
    smoke_core_types_and_bounds(&mut h);
    smoke_file_image_read_write_flush_discard(&mut h);
    h.scenario_end("ublk/smoke");

    let trace_before_round_trip = h.trace.clone();
    let serialized = serialize_trace(&trace_before_round_trip)
        .expect("block-volume smoke trace should serialize");
    let decoded =
        deserialize_trace(&serialized).expect("block-volume smoke trace should deserialize");
    h.assert_eq_ev(
        "block-volume smoke trace round-trips",
        decoded,
        trace_before_round_trip,
    );

    h
}

fn smoke_core_types_and_bounds(h: &mut SmokeHarness) {
    let volume_id = BlockVolumeId::new(42);
    let geometry = smoke_geometry(volume_id);
    let two_blocks = BlockRangeRecord::new(1, 2);

    record_block_volume_op(
        h,
        "block_volume.types",
        volume_id,
        BLOCK_VOLUME_ADAPTER_CORE_GATE_OW_301A.as_bytes(),
    );
    h.assert_eq_ev("volume id newtype is stable", volume_id, BlockVolumeId(42));
    h.assert_eq_ev(
        "range constructor preserves start block",
        two_blocks.start_block,
        1usize,
    );
    h.assert_eq_ev(
        "range constructor preserves block count",
        two_blocks.block_count,
        2usize,
    );
    h.assert_eq_ev(
        "geometry capacity is block size times count",
        geometry.capacity_bytes(),
        Some(4096usize),
    );
    h.assert_ev("geometry admits discard", geometry.admits_discard());

    let request_classes = [
        BlockVolumeRequestClass::Read,
        BlockVolumeRequestClass::Write,
        BlockVolumeRequestClass::Flush,
        BlockVolumeRequestClass::Discard,
        BlockVolumeRequestClass::WriteZeroes,
    ];
    h.assert_eq_ev(
        "request class catalog includes write-zeroes",
        request_classes.len(),
        5usize,
    );
    h.assert_eq_ev(
        "completion class is matchable",
        BlockVolumeCompletionClass::Completed,
        BlockVolumeCompletionClass::Completed,
    );
    h.assert_eq_ev(
        "flush barrier class is matchable",
        BlockVolumeFlushBarrierClass::Satisfied,
        BlockVolumeFlushBarrierClass::Satisfied,
    );

    record_block_volume_op(
        h,
        "block_volume.plan.read_write",
        volume_id,
        b"offset=512 len=1024",
    );
    let write_plan =
        plan_read_write_request_bounds(geometry, BlockVolumeRequestClass::Write, 512, 1024);
    h.assert_eq_ev(
        "aligned write plan completes",
        write_plan.completion_class,
        BlockVolumeCompletionClass::Completed,
    );
    h.assert_eq_ev(
        "write plan range is exact",
        write_plan.range,
        Some(two_blocks),
    );
    h.assert_eq_ev(
        "write plan payload length is exact",
        write_plan.payload_len,
        1024usize,
    );

    record_block_volume_op(
        h,
        "block_volume.plan.discard",
        volume_id,
        b"offset=1024 len=512",
    );
    let discard_plan =
        plan_discard_request_bounds(geometry, BlockVolumeRequestClass::Discard, 1024, 512);
    h.assert_eq_ev(
        "aligned discard plan completes",
        discard_plan.completion_class,
        BlockVolumeCompletionClass::Completed,
    );
    h.assert_eq_ev(
        "discard plan range is exact",
        discard_plan.range,
        Some(BlockRangeRecord::new(2, 1)),
    );
}

fn smoke_file_image_read_write_flush_discard(h: &mut SmokeHarness) {
    let volume_id = BlockVolumeId::new(77);
    let geometry = smoke_geometry(volume_id);
    let dir = tempfile::TempDir::new().expect("tempdir for block-volume image smoke");
    let path = dir.path().join("block-volume.img");

    record_block_volume_op(h, "block_volume.file_image.create", volume_id, b"zeroed");
    let mut image =
        BlockVolumeFileImage::create_zeroed(&path, geometry).expect("create block-volume image");
    h.assert_eq_ev(
        "file image stores requested geometry",
        image.geometry,
        geometry,
    );

    let payload: Vec<u8> = (0..1024).map(|idx| (idx % 251) as u8).collect();
    record_block_volume_op(
        h,
        "block_volume.file_image.write",
        volume_id,
        b"start=1 blocks=2",
    );
    let write = image
        .write_blocks(1, &payload)
        .expect("write file-backed blocks");
    h.assert_eq_ev(
        "file image write completes",
        write.completion_class,
        BlockVolumeCompletionClass::Completed,
    );
    h.assert_eq_ev(
        "file image write range is exact",
        write.range,
        Some(BlockRangeRecord::new(1, 2)),
    );
    h.assert_eq_ev(
        "file image write records dirty epoch",
        write.dirty_epoch_ref.is_some(),
        true,
    );
    h.assert_eq_ev(
        "file image has one dirty epoch",
        image.dirty_epochs.len(),
        1usize,
    );

    record_block_volume_op(
        h,
        "block_volume.file_image.read",
        volume_id,
        b"start=1 blocks=2",
    );
    let (read_plan, read_payload) = image
        .read_blocks(BlockRangeRecord::new(1, 2))
        .expect("read file-backed blocks");
    h.assert_eq_ev(
        "file image read completes",
        read_plan.completion_class,
        BlockVolumeCompletionClass::Completed,
    );
    h.assert_eq_ev(
        "file image read returns written bytes",
        read_payload.expect("read payload"),
        payload.clone(),
    );

    record_block_volume_op(
        h,
        "block_volume.file_image.discard",
        volume_id,
        b"start=2 blocks=1",
    );
    let discard = image
        .discard_blocks(BlockRangeRecord::new(2, 1))
        .expect("discard file-backed block");
    h.assert_eq_ev(
        "file image discard completes",
        discard.completion_class,
        BlockVolumeCompletionClass::Completed,
    );
    h.assert_ev(
        "discard records intent",
        discard.discard_intent_ref.is_some() && image.discard_intents.len() == 1,
    );
    h.assert_eq_ev(
        "discard invalidates overlapping write epoch",
        image.discard_intents[0].invalidated_epoch_ids.len(),
        1usize,
    );

    let (_, after_discard) = image
        .read_blocks(BlockRangeRecord::new(1, 2))
        .expect("read after discard");
    let after_discard = after_discard.expect("read payload after discard");
    h.assert_eq_ev(
        "discard preserves untouched first block",
        after_discard[..512].to_vec(),
        payload[..512].to_vec(),
    );
    h.assert_eq_ev(
        "discard makes second block zero-visible",
        after_discard[512..].to_vec(),
        vec![0; 512],
    );

    record_block_volume_op(
        h,
        "block_volume.file_image.flush",
        volume_id,
        b"after-discard",
    );
    let flush = image.flush().expect("flush file-backed image");
    h.assert_eq_ev(
        "file image flush completes",
        flush.completion_class,
        BlockVolumeCompletionClass::Completed,
    );
    h.assert_ev("flush records barrier", flush.flush_barrier_ref.is_some());
    h.assert_eq_ev(
        "file image has one flush barrier",
        image.flush_barriers.len(),
        1usize,
    );
    h.assert_eq_ev(
        "flush barrier is satisfied",
        image.flush_barriers[0].barrier_class,
        BlockVolumeFlushBarrierClass::Satisfied,
    );

    record_block_volume_op(
        h,
        "block_volume.file_image.read_oob",
        volume_id,
        b"start=8 blocks=1",
    );
    let (oob_read, payload) = image
        .read_blocks(BlockRangeRecord::new(8, 1))
        .expect("out-of-bounds read plan");
    h.assert_eq_ev(
        "out-of-bounds read is refused",
        oob_read.completion_class,
        BlockVolumeCompletionClass::RefusedOutOfBounds,
    );
    h.assert_ev("out-of-bounds read returns no payload", payload.is_none());

    drop(image);
    dir.close().ok();
}

fn smoke_geometry(volume_id: BlockVolumeId) -> BlockVolumeGeometryRecord {
    BlockVolumeGeometryRecord::new(volume_id, 512, 8, 1)
}

fn record_block_volume_op(
    h: &mut SmokeHarness,
    op_name: &str,
    volume_id: BlockVolumeId,
    payload: &[u8],
) {
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: volume_id.0,
        op_name: op_name.to_string(),
        payload: payload.to_vec(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_volume_adapter_core_smoke_passes() {
        let h = run_block_volume_adapter_core_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert {
                passed,
                ref condition,
            } = event
            {
                assert!(passed, "assertion failed: {condition}");
            }
        }
    }
}
