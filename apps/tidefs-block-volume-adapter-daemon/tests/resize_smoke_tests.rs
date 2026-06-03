//! Resize smoke tests for tidefs-block-volume-adapter-daemon.
//!
//! Exercises BlockVolumeFileImage::resize_to() for grow and shrink,
//! verifies content integrity across resize transitions, out-of-bounds
//! refusal after resize, and BlockVolumeResizeStats aggregation.
//!
//! Gate: BLOCK_VOLUME_RESIZE_FENCE_GATE_OW_301F

use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeCompletionClass, BlockVolumeFileImage, BlockVolumeFileImageError,
    BlockVolumeGeometryRecord, BlockVolumeId, BlockVolumeResizeDirectionClass,
    BlockVolumeResizeStats,
};

// ── Temp file helper ───────────────────────────────────────────────────

struct TempBackingFile {
    path: PathBuf,
}

impl TempBackingFile {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("tidefs-resize-smoke-{nonce}.dat"));
        Self { path }
    }

    fn remove(self) -> bool {
        let _ = std::fs::remove_file(&self.path);
        !self.path.exists()
    }
}

fn resize_geometry() -> BlockVolumeGeometryRecord {
    BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_200), 4096, 8, 1)
}

// ── File-image resize tests ────────────────────────────────────────────

#[test]
fn file_image_grow_preserves_original_data() {
    let geometry = resize_geometry();
    let _bs = geometry.block_size_bytes;
    let backing = TempBackingFile::new();
    let mut image = BlockVolumeFileImage::create_zeroed(&backing.path, geometry).expect("create");

    image
        .write_blocks(0, &[0xAA; 4096 * 2])
        .expect("write blocks 0-1");
    image.flush().expect("flush");

    let big_geometry = BlockVolumeGeometryRecord {
        block_count: 16,
        ..geometry
    };
    image.resize_to(big_geometry).expect("grow resize");

    assert_eq!(image.geometry.block_count, 16);

    // original data still readable
    let (plan, payload) = image
        .read_blocks(BlockRangeRecord::new(0, 2))
        .expect("read original");
    assert_eq!(plan.completion_class, BlockVolumeCompletionClass::Completed);
    assert_eq!(payload.as_deref(), Some(&[0xAA; 4096 * 2][..]));

    // expanded tail readable (zero-filled by OS)
    let (_, expanded) = image
        .read_blocks(BlockRangeRecord::new(10, 2))
        .expect("read expanded tail");
    assert!(expanded.is_some());

    // new blocks are writable
    image
        .write_blocks(12, &[0xBB; 4096])
        .expect("write expanded block");

    backing.remove();
}

#[test]
fn file_image_shrink_truncates_tail() {
    let geometry = resize_geometry();
    let _bs = geometry.block_size_bytes;
    let backing = TempBackingFile::new();
    let mut image = BlockVolumeFileImage::create_zeroed(&backing.path, geometry).expect("create");

    image
        .write_blocks(0, &[0xCC; 4096 * 6])
        .expect("write 6 blocks");
    image.flush().expect("flush");

    let small_geometry = BlockVolumeGeometryRecord {
        block_count: 4,
        ..geometry
    };
    image.resize_to(small_geometry).expect("shrink resize");

    assert_eq!(image.geometry.block_count, 4);

    // blocks 0-3 preserved
    let (_, kept) = image
        .read_blocks(BlockRangeRecord::new(0, 4))
        .expect("read kept");
    assert_eq!(kept.as_deref(), Some(&[0xCC; 4096 * 4][..]));

    // OOB after shrink
    let (plan, _) = image
        .read_blocks(BlockRangeRecord::new(4, 1))
        .expect("read OOB");
    assert_eq!(
        plan.completion_class,
        BlockVolumeCompletionClass::RefusedOutOfBounds
    );

    backing.remove();
}

#[test]
fn file_image_grow_then_shrink_roundtrip() {
    let geometry = resize_geometry();
    let _bs = geometry.block_size_bytes;
    let backing = TempBackingFile::new();
    let mut image = BlockVolumeFileImage::create_zeroed(&backing.path, geometry).expect("create");

    image
        .write_blocks(0, &[0x11; 4096 * 4])
        .expect("write first 4");
    image.flush().expect("flush");

    // grow 8 -> 12
    let grow12 = BlockVolumeGeometryRecord {
        block_count: 12,
        ..geometry
    };
    image.resize_to(grow12).expect("grow to 12");
    assert_eq!(image.geometry.block_count, 12);

    // write into expanded region
    image
        .write_blocks(10, &[0x22; 4096])
        .expect("write block 10");
    image.flush().expect("flush after grow-write");

    // shrink 12 -> 6
    let shrink6 = BlockVolumeGeometryRecord {
        block_count: 6,
        ..geometry
    };
    image.resize_to(shrink6).expect("shrink to 6");
    assert_eq!(image.geometry.block_count, 6);

    // original blocks 0-3 preserved
    let (_, orig) = image
        .read_blocks(BlockRangeRecord::new(0, 4))
        .expect("read orig");
    assert_eq!(orig.as_deref(), Some(&[0x11; 4096 * 4][..]));

    // OOB at block 6
    let (plan, _) = image
        .read_blocks(BlockRangeRecord::new(6, 1))
        .expect("read OOB post-shrink");
    assert_eq!(
        plan.completion_class,
        BlockVolumeCompletionClass::RefusedOutOfBounds
    );

    backing.remove();
}

#[test]
fn file_image_resize_refuses_invalid_geometry() {
    let geometry = resize_geometry();
    let backing = TempBackingFile::new();
    let mut image = BlockVolumeFileImage::create_zeroed(&backing.path, geometry).expect("create");

    // zero block size
    let bad = BlockVolumeGeometryRecord::new(BlockVolumeId::new(999), 0, 8, 1);
    assert!(matches!(
        image.resize_to(bad),
        Err(BlockVolumeFileImageError::InvalidGeometry)
    ));

    // zero block count
    let bad2 = BlockVolumeGeometryRecord::new(BlockVolumeId::new(999), 4096, 0, 1);
    assert!(matches!(
        image.resize_to(bad2),
        Err(BlockVolumeFileImageError::InvalidGeometry)
    ));

    backing.remove();
}

#[test]
fn file_image_resize_to_self_is_noop() {
    let geometry = resize_geometry();
    let backing = TempBackingFile::new();
    let mut image = BlockVolumeFileImage::create_zeroed(&backing.path, geometry).expect("create");

    image.write_blocks(0, &[0x99; 4096]).expect("write");
    image.flush().expect("flush");

    image.resize_to(geometry).expect("resize to same geometry");
    assert_eq!(image.geometry.block_count, 8);

    let (_, payload) = image
        .read_blocks(BlockRangeRecord::new(0, 1))
        .expect("read");
    assert_eq!(payload.as_deref(), Some(&[0x99; 4096][..]));

    backing.remove();
}

#[test]
fn file_image_oob_after_grow() {
    let geometry = resize_geometry();
    let backing = TempBackingFile::new();
    let mut image = BlockVolumeFileImage::create_zeroed(&backing.path, geometry).expect("create");

    let big = BlockVolumeGeometryRecord {
        block_count: 16,
        ..geometry
    };
    image.resize_to(big).expect("grow");

    // write past new end (block 16) should refuse
    let plan = image.write_blocks(16, &[0xEE; 4096]).expect("write OOB");
    assert_eq!(
        plan.completion_class,
        BlockVolumeCompletionClass::RefusedOutOfBounds
    );

    backing.remove();
}

// ── ResizeStats tests ──────────────────────────────────────────────────

#[test]
fn resize_stats_default_zero() {
    let stats = BlockVolumeResizeStats::default();
    assert_eq!(stats.from_block_count, 0);
    assert_eq!(stats.to_block_count, 0);
    assert_eq!(stats.total_time_us(), 0);
    assert_eq!(stats.block_delta(), 0);
}

#[test]
fn resize_stats_grow_delta_positive() {
    let stats = BlockVolumeResizeStats {
        from_block_count: 8,
        to_block_count: 16,
        block_size_bytes: 4096,
        direction: Some(BlockVolumeResizeDirectionClass::Grow),
        quiesce_time_us: 100,
        fence_time_us: 200,
        commit_time_us: 50,
    };
    assert_eq!(stats.block_delta(), 8);
    assert_eq!(stats.total_time_us(), 350);
}

#[test]
fn resize_stats_shrink_delta_negative() {
    let stats = BlockVolumeResizeStats {
        from_block_count: 16,
        to_block_count: 4,
        block_size_bytes: 4096,
        direction: Some(BlockVolumeResizeDirectionClass::Shrink),
        quiesce_time_us: 50,
        fence_time_us: 150,
        commit_time_us: 25,
    };
    assert_eq!(stats.block_delta(), -12);
    assert_eq!(stats.total_time_us(), 225);
}

#[test]
fn resize_stats_total_time_saturating() {
    let stats = BlockVolumeResizeStats {
        quiesce_time_us: u64::MAX,
        fence_time_us: 1,
        commit_time_us: 0,
        ..Default::default()
    };
    assert_eq!(stats.total_time_us(), u64::MAX);
}

#[test]
fn resize_stats_no_direction_yields_zero_delta() {
    let stats = BlockVolumeResizeStats {
        from_block_count: 8,
        to_block_count: 8,
        block_size_bytes: 4096,
        direction: None,
        ..Default::default()
    };
    assert_eq!(stats.block_delta(), 0);
}
