// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Comprehensive backing-file tests for the block volume adapter daemon.
//!
//! Exercises `BlockVolumeFileImage` against real on-disk backing files
//! covering sequential/random I/O, flush ordering, discard, write-zeroes,
//! reopen persistence, and out-of-bounds refusal.
//!
//! Gate: `BLOCK_VOLUME_FILE_IMAGE_BACKING_GATE_OW_301N`

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeCompletionClass, BlockVolumeFileImage, BlockVolumeFileImageError,
    BlockVolumeGeometryRecord, BlockVolumeId, BlockVolumeRequestPlan,
};

// ── Temp file helper ───────────────────────────────────────────────────

struct TempBackingFile {
    path: PathBuf,
}

impl TempBackingFile {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut path = env::temp_dir();
        path.push(format!(
            "tidefs-bv-backing-test-{}-{nonce}.img",
            process::id()
        ));
        let _ = fs::remove_file(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn remove(self) -> bool {
        match fs::remove_file(&self.path) {
            Ok(()) => !self.path.exists(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        }
    }
}

impl Drop for TempBackingFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

// ── Shared helpers ─────────────────────────────────────────────────────

fn test_geometry() -> BlockVolumeGeometryRecord {
    BlockVolumeGeometryRecord::new(BlockVolumeId::new(901), 4096, 256, 4)
}

fn block_size(g: BlockVolumeGeometryRecord) -> usize {
    g.block_size_bytes
}

fn payload_fill(byte: u8, blocks: usize, geom: BlockVolumeGeometryRecord) -> Vec<u8> {
    vec![byte; blocks * block_size(geom)]
}

fn assert_completed(plan: &BlockVolumeRequestPlan, ctx: &str) {
    assert_eq!(
        plan.completion_class,
        BlockVolumeCompletionClass::Completed,
        "{ctx}: expected Completed, got {:?}",
        plan.completion_class
    );
}

// ── 1. Sequential read/write spanning multiple block boundaries ─────────

#[test]
fn sequential_write_then_read_spans_multiple_blocks() {
    let geom = test_geometry();
    let b = TempBackingFile::new();
    let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");

    let payload = payload_fill(0x5A, 5, geom);
    let plan = img.write_blocks(10, &payload).expect("write 5@10");
    assert_completed(&plan, "write");

    let (rp, data) = img.read_blocks(BlockRangeRecord::new(10, 5)).expect("read");
    assert_completed(&rp, "read");
    assert_eq!(data.unwrap(), payload);

    let p2 = payload_fill(0x6B, 1, geom);
    assert_completed(&img.write_blocks(20, &p2).expect("write2"), "write2");

    let (_, d2) = img
        .read_blocks(BlockRangeRecord::new(20, 1))
        .expect("read 20");
    assert_eq!(d2.unwrap(), p2);

    let (_, d3) = img
        .read_blocks(BlockRangeRecord::new(10, 1))
        .expect("read 10");
    assert_eq!(d3.unwrap(), payload_fill(0x5A, 1, geom));

    drop(img);
    assert!(b.remove());
}

// ── 2. Random-access read/write across non-contiguous blocks ────────────

#[test]
fn random_access_read_write_non_contiguous_blocks() {
    let geom = test_geometry();
    let b = TempBackingFile::new();
    let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");

    for (block, fill) in [(0, 0x11u8), (50, 0x22), (200, 0x33), (255, 0x44)] {
        let p = payload_fill(fill, 1, geom);
        assert_completed(
            &img.write_blocks(block, &p).expect("write"),
            &format!("write @ {block}"),
        );
    }

    for (block, fill) in [(0, 0x11u8), (50, 0x22), (200, 0x33), (255, 0x44)] {
        let (_, data) = img
            .read_blocks(BlockRangeRecord::new(block, 1))
            .expect("read");
        assert_eq!(data.unwrap(), payload_fill(fill, 1, geom), "block {block}");
    }

    let (_, data) = img
        .read_blocks(BlockRangeRecord::new(100, 1))
        .expect("read unwritten");
    assert_eq!(data.unwrap(), vec![0u8; block_size(geom)]);

    drop(img);
    assert!(b.remove());
}

// ── 3. Flush barrier ordering ───────────────────────────────────────────

#[test]
fn flush_persists_dirty_writes_before_reopen() {
    let geom = test_geometry();
    let b = TempBackingFile::new();
    let payload = payload_fill(0x7E, 8, geom);
    {
        let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");
        assert_completed(&img.write_blocks(5, &payload).expect("write"), "write");
        let fp = img.flush().expect("flush");
        assert_completed(&fp, "flush");
        assert!(fp.flush_barrier_ref.is_some(), "flush barrier present");
    }
    {
        let img = BlockVolumeFileImage::reopen_existing(b.path(), geom).expect("reopen");
        let (_, data) = img.read_blocks(BlockRangeRecord::new(5, 8)).expect("read");
        assert_eq!(data.unwrap(), payload);
    }
    assert!(b.remove());
}

#[test]
fn flush_with_no_dirty_data_returns_no_barrier() {
    let geom = test_geometry();
    let b = TempBackingFile::new();
    let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");
    let fp = img.flush().expect("flush");
    assert_completed(&fp, "flush");
    assert!(fp.flush_barrier_ref.is_none(), "no barrier for clean flush");
    drop(img);
    assert!(b.remove());
}

// ── 4. Discard hole-punch ───────────────────────────────────────────────

#[test]
fn discard_range_reads_back_as_zeroes() {
    let geom = test_geometry();
    let b = TempBackingFile::new();
    let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");

    let payload = payload_fill(0x99, 4, geom);
    assert_completed(&img.write_blocks(32, &payload).expect("write"), "write");

    let dp = img
        .discard_blocks(BlockRangeRecord::new(32, 4))
        .expect("discard");
    assert_eq!(dp.completion_class, BlockVolumeCompletionClass::Completed);
    assert!(dp.discard_intent_ref.is_some());

    let (_, data) = img.read_blocks(BlockRangeRecord::new(32, 4)).expect("read");
    assert_eq!(data.unwrap(), vec![0u8; 4 * block_size(geom)]);

    drop(img);
    assert!(b.remove());
}

#[test]
fn discard_rejected_when_unsupported() {
    let geom = BlockVolumeGeometryRecord::new(BlockVolumeId::new(902), 4096, 64, 0);
    let b = TempBackingFile::new();
    let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");

    let dp = img
        .discard_blocks(BlockRangeRecord::new(0, 4))
        .expect("discard");
    assert_eq!(
        dp.completion_class,
        BlockVolumeCompletionClass::RefusedDiscardUnsupported
    );

    drop(img);
    assert!(b.remove());
}

// ── 5. Write-zeroes ────────────────────────────────────────────────────

#[test]
fn write_zeroes_range_reads_back_as_zeroes() {
    let geom = test_geometry();
    let b = TempBackingFile::new();
    let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");

    let payload = payload_fill(0xCC, 4, geom);
    assert_completed(&img.write_blocks(60, &payload).expect("write"), "write");

    let zp = img
        .write_zeroes(BlockRangeRecord::new(61, 2))
        .expect("write_zeroes");
    assert_eq!(zp.completion_class, BlockVolumeCompletionClass::Completed);
    assert!(zp.dirty_epoch_ref.is_some());

    let (_, d60) = img
        .read_blocks(BlockRangeRecord::new(60, 1))
        .expect("read 60");
    assert_eq!(d60.unwrap(), payload_fill(0xCC, 1, geom));

    let (_, dz) = img
        .read_blocks(BlockRangeRecord::new(61, 2))
        .expect("read zeroed");
    assert_eq!(dz.unwrap(), vec![0u8; 2 * block_size(geom)]);

    let (_, d63) = img
        .read_blocks(BlockRangeRecord::new(63, 1))
        .expect("read 63");
    assert_eq!(d63.unwrap(), payload_fill(0xCC, 1, geom));

    drop(img);
    assert!(b.remove());
}

#[test]
fn write_zeroes_works_without_discard_support() {
    let geom = BlockVolumeGeometryRecord::new(BlockVolumeId::new(903), 4096, 64, 0);
    let b = TempBackingFile::new();
    let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");

    let zp = img
        .write_zeroes(BlockRangeRecord::new(0, 4))
        .expect("write_zeroes");
    assert_eq!(zp.completion_class, BlockVolumeCompletionClass::Completed);

    let (_, data) = img.read_blocks(BlockRangeRecord::new(0, 4)).expect("read");
    assert_eq!(data.unwrap(), vec![0u8; 4 * 4096]);

    drop(img);
    assert!(b.remove());
}

// ── 6. Reopen persistence ──────────────────────────────────────────────

#[test]
fn write_flush_reopen_read_preserves_data() {
    let geom = test_geometry();
    let b = TempBackingFile::new();
    let payload = payload_fill(0xAD, 8, geom);
    {
        let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");
        assert_completed(&img.write_blocks(0, &payload).expect("write"), "write");
        assert_completed(&img.flush().expect("flush"), "flush");
    }
    {
        let img = BlockVolumeFileImage::reopen_existing(b.path(), geom).expect("reopen");
        let (_, data) = img.read_blocks(BlockRangeRecord::new(0, 8)).expect("read");
        assert_eq!(data.unwrap(), payload);
    }
    assert!(b.remove());
}

// ── 7. Write-past-end refusal ──────────────────────────────────────────

#[test]
fn write_past_geometry_end_is_refused() {
    let geom = test_geometry(); // 256 blocks, indices 0..255
    let b = TempBackingFile::new();
    let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");

    let p = payload_fill(0xBB, 1, geom);
    assert_completed(&img.write_blocks(255, &p).expect("write@255"), "write@255");

    let plan = img.write_blocks(256, &p).expect("write@256");
    assert_eq!(
        plan.completion_class,
        BlockVolumeCompletionClass::RefusedOutOfBounds
    );

    let p3 = payload_fill(0xCC, 3, geom);
    let plan2 = img.write_blocks(254, &p3).expect("write@254x3");
    assert_eq!(
        plan2.completion_class,
        BlockVolumeCompletionClass::RefusedOutOfBounds
    );

    let (rp, data) = img
        .read_blocks(BlockRangeRecord::new(256, 1))
        .expect("read@256");
    assert_eq!(
        rp.completion_class,
        BlockVolumeCompletionClass::RefusedOutOfBounds
    );
    assert!(data.is_none());

    drop(img);
    assert!(b.remove());
}

#[test]
fn misaligned_write_is_refused() {
    let geom = test_geometry();
    let b = TempBackingFile::new();
    let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");

    let plan = img.write_blocks(0, &[]).expect("empty write");
    assert_eq!(
        plan.completion_class,
        BlockVolumeCompletionClass::RefusedMisalignedRange
    );

    let bad = vec![0xAA; block_size(geom) + 1];
    let plan2 = img.write_blocks(0, &bad).expect("misaligned write");
    assert_eq!(
        plan2.completion_class,
        BlockVolumeCompletionClass::RefusedMisalignedRange
    );

    drop(img);
    assert!(b.remove());
}

// ── 8. Combined write + discard + zeroes + flush + reopen cycle ─────────

#[test]
fn full_write_discard_zeroes_flush_reopen_cycle() {
    let geom = test_geometry();
    let b = TempBackingFile::new();

    {
        let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");
        let p = payload_fill(0x77, 10, geom);
        assert_completed(&img.write_blocks(10, &p).expect("write"), "write");

        let dp = img
            .discard_blocks(BlockRangeRecord::new(12, 4))
            .expect("discard");
        assert_eq!(dp.completion_class, BlockVolumeCompletionClass::Completed);

        let zp = img
            .write_zeroes(BlockRangeRecord::new(16, 2))
            .expect("write_zeroes");
        assert_eq!(zp.completion_class, BlockVolumeCompletionClass::Completed);

        assert_completed(&img.flush().expect("flush"), "flush");
    }

    {
        let img = BlockVolumeFileImage::reopen_existing(b.path(), geom).expect("reopen");

        let (_, d1) = img.read_blocks(BlockRangeRecord::new(10, 2)).expect("r1");
        assert_eq!(d1.unwrap(), payload_fill(0x77, 2, geom));

        let (_, d2) = img.read_blocks(BlockRangeRecord::new(12, 4)).expect("r2");
        assert_eq!(d2.unwrap(), vec![0u8; 4 * block_size(geom)]);

        let (_, d3) = img.read_blocks(BlockRangeRecord::new(16, 2)).expect("r3");
        assert_eq!(d3.unwrap(), vec![0u8; 2 * block_size(geom)]);

        let (_, d4) = img.read_blocks(BlockRangeRecord::new(18, 2)).expect("r4");
        assert_eq!(d4.unwrap(), payload_fill(0x77, 2, geom));
    }

    assert!(b.remove());
}

// ── 9. reopen_existing rejects mismatched file size ────────────────────

#[test]
fn reopen_existing_rejects_wrong_sized_file() {
    let geom = test_geometry();
    let b = TempBackingFile::new();
    fs::write(b.path(), vec![0u8; 100]).expect("small file");

    let result = BlockVolumeFileImage::reopen_existing(b.path(), geom);
    assert!(result.is_err());
    match result.unwrap_err() {
        BlockVolumeFileImageError::BackingLengthMismatch { .. } => {}
        other => panic!("expected BackingLengthMismatch, got {other}"),
    }
    assert!(b.remove());
}

// ── 10. Dirty epoch and discard intent tracking ────────────────────────

#[test]
fn dirty_epochs_and_discard_intents_are_recorded() {
    let geom = test_geometry();
    let b = TempBackingFile::new();
    let mut img = BlockVolumeFileImage::create_zeroed(b.path(), geom).expect("create");

    assert!(img.dirty_epochs.is_empty());
    assert!(img.discard_intents.is_empty());

    assert_completed(
        &img.write_blocks(0, &payload_fill(0x55, 2, geom))
            .expect("w"),
        "w",
    );
    assert_eq!(img.dirty_epochs.len(), 1);

    let _ = img.discard_blocks(BlockRangeRecord::new(0, 4));
    assert_eq!(img.discard_intents.len(), 1);
    assert_eq!(img.dirty_epochs.len(), 2);

    let _ = img.write_zeroes(BlockRangeRecord::new(10, 2));
    assert_eq!(img.discard_intents.len(), 2);
    assert_eq!(img.dirty_epochs.len(), 3);

    assert_completed(&img.flush().expect("flush"), "flush");
    for e in &img.dirty_epochs {
        assert!(e.sealed_for_flush || e.invalidated_by_discard);
    }

    drop(img);
    assert!(b.remove());
}
