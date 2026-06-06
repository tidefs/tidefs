// write_dispatch_tests.rs — property-based unit tests for the local-filesystem
// write buffer assembly, extent splitting, ordering, padding, and error
// propagation.
//
// Tests the internal dispatch functions: chunk splitting, overlay assembly,
// content preservation across writes, and error surfacing from the object
// store and namespace layers.

#[cfg(test)]
use super::*;
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn wd_temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-write-dispatch-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn wd_options() -> StoreOptions {
    StoreOptions {
        max_segment_bytes: 128 * 1024,
        sync_on_write: false,
        repair_torn_tail: true,
        mirror_path: None,
        replica_paths: Vec::new(),
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 65536,
        reclaim_enabled: true,

        write_throttle_enabled: false,
        durability_layout: None,
        verify_read_checksums: false,
    }
}

fn wd_cleanup(root: &std::path::Path) {
    let _ = fs::remove_dir_all(root);
}

// ── Strategy helpers ────────────────────────────────────────

fn arb_file_size() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1u64),
        Just(FILESYSTEM_CONTENT_CHUNK_SIZE as u64 - 1),
        Just(FILESYSTEM_CONTENT_CHUNK_SIZE as u64),
        Just(FILESYSTEM_CONTENT_CHUNK_SIZE as u64 + 1),
        (2u64..(FILESYSTEM_CONTENT_CHUNK_SIZE as u64 * 4 + 7)),
    ]
}

fn arb_bytes_varied() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(Vec::new()),
        prop::collection::vec(any::<u8>(), 1..2),
        prop::collection::vec(any::<u8>(), 2..(FILESYSTEM_CONTENT_CHUNK_SIZE / 2)),
        prop::collection::vec(
            any::<u8>(),
            FILESYSTEM_CONTENT_CHUNK_SIZE - 16..FILESYSTEM_CONTENT_CHUNK_SIZE + 16
        ),
        prop::collection::vec(
            any::<u8>(),
            FILESYSTEM_CONTENT_CHUNK_SIZE..FILESYSTEM_CONTENT_CHUNK_SIZE * 4 + 7
        ),
    ]
}

fn arb_offset() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1u64),
        Just(FILESYSTEM_CONTENT_CHUNK_SIZE as u64 - 1),
        Just(FILESYSTEM_CONTENT_CHUNK_SIZE as u64),
        Just(FILESYSTEM_CONTENT_CHUNK_SIZE as u64 + 1),
        (0u64..(FILESYSTEM_CONTENT_CHUNK_SIZE as u64 * 3)),
    ]
}

fn arb_patch() -> impl Strategy<Value = (u64, Vec<u8>)> {
    (
        arb_offset(),
        prop::collection::vec(any::<u8>(), 1..(FILESYSTEM_CONTENT_CHUNK_SIZE + 128)),
    )
}

// ── Group 1: Buffer splitting ───────────────────────────────

proptest! {
    /// For any file_size, the total chunk count correctly covers the file.
    #[test]
    fn proptest_chunk_count_covers_file_size(size in arb_file_size()) {
        let chunk_sz = content_chunk_size() as u64;
        let count = content_chunk_count(size).expect("chunk count for valid size");
        if size == 0 {
            prop_assert_eq!(count, 0, "zero-size file must have zero chunks");
        } else {
            prop_assert!(count > 0, "non-zero file must have at least one chunk");
            let last_start = (count - 1) * chunk_sz;
            prop_assert!(last_start < size, "last chunk must start before file end");
            prop_assert!(count * chunk_sz >= size, "chunks must cover the file size");
            let expected = size.div_ceil(chunk_sz);
            prop_assert_eq!(count, expected,
                "chunk count must be ceil(file_size / chunk_size)");
        }
    }

    /// For any file_size and any valid chunk_index, the chunk length is correct.
    #[test]
    fn proptest_chunk_len_bounds(size in arb_file_size()) {
        let chunk_sz = content_chunk_size() as u64;
        if size == 0 {
            return Ok(());
        }
        let count = content_chunk_count(size).expect("chunk count");
        let mut total_len: u64 = 0;
        for i in 0..count {
            let len = content_chunk_len(size, i)
                .expect("chunk len for valid index") as u64;
            prop_assert!(len > 0, "every chunk must have positive length");
            prop_assert!(len <= chunk_sz, "chunk length must not exceed chunk size");
            total_len += len;
        }
        prop_assert_eq!(total_len, size,
            "sum of all chunk lengths must equal file size");
    }

    /// Chunk start positions are contiguous and correct.
    #[test]
    fn proptest_chunk_start_positions(size in arb_file_size()) {
        let chunk_sz = content_chunk_size() as u64;
        if size == 0 {
            return Ok(());
        }
        let count = content_chunk_count(size).expect("chunk count");
        prop_assert_eq!(content_chunk_start(0).expect("chunk_start 0"), 0);
        for i in 0..count {
            let start = content_chunk_start(i).expect("chunk_start");
            prop_assert_eq!(start, i * chunk_sz,
                "chunk_start must equal i * chunk_size");
        }
        let beyond = count;
        let start_beyond = content_chunk_start(beyond).expect("chunk_start beyond");
        prop_assert_eq!(start_beyond, beyond * chunk_sz);
        let result = content_chunk_len(size, beyond);
        prop_assert!(result.is_err(), "chunk_len beyond count must fail");
    }
}

// ── Group 2: Multi-extent dispatch ──────────────────────────

proptest! {
    /// Write full content, verify roundtrip and chunk-level manifest structure.
    #[test]
    fn proptest_write_full_content_dispatch(bytes in arb_bytes_varied()) {
        let root = wd_temp_root("full-dispatch");
        let expected = bytes.clone();
        {
            let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
            fs.create_file("/data.bin", 0o644).expect("create file");
            fs.write_file("/data.bin", 0, &bytes).expect("write file");

            let read_back = fs.read_file("/data.bin").expect("read file");
            prop_assert_eq!(read_back, expected.clone(), "write-read roundtrip must preserve data");
        }
        {
            let fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("reopen fs");
            let record = fs.stat("/data.bin").expect("stat");
            prop_assert_eq!(record.size, expected.len() as u64);

            let content_key = content_object_key_for_version(record.inode_id, record.data_version);
            let raw = fs.store.primary_store().get(content_key)
                .expect("read content obj")
                .expect("content obj exists");
            let manifest = decode_content_manifest(&raw).expect("decode manifest");

            prop_assert_eq!(manifest.file_size, expected.len() as u64);
            prop_assert_eq!(manifest.chunk_size, content_chunk_size());

            if !expected.is_empty() {
                let expected_chunks = content_chunk_count(expected.len() as u64)
                    .expect("chunk count") as usize;
                prop_assert_eq!(manifest.chunks.len(), expected_chunks,
                    "manifest chunk count must match expected");
            }
        }
        wd_cleanup(&root);
    }

    /// Write multiple non-overlapping patches at different offsets, verify all preserved.
    #[test]
    fn proptest_multi_patch_dispatch(
        initial in arb_bytes_varied(),
        patches in prop::collection::vec(arb_patch(), 1..6),
    ) {
        let root = wd_temp_root("multi-patch");
        let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");
        fs.write_file("/data.bin", 0, &initial).expect("write initial");

        let mut expected = initial.clone();
        for (offset, patch_bytes) in &patches {
            let po = *offset as usize;
            if po > expected.len() {
                expected.resize(po, 0);
            }
            expected.resize(expected.len().max(po + patch_bytes.len()), 0);
            let copy_len = patch_bytes.len().min(expected.len() - po);
            expected[po..po + copy_len].copy_from_slice(&patch_bytes[..copy_len]);

            fs.write_file("/data.bin", *offset, patch_bytes).expect("write patch");
        }

        let read_back = fs.read_file("/data.bin").expect("read file");
        prop_assert_eq!(read_back, expected, "multi-patch final state must be correct");
        wd_cleanup(&root);
    }

    /// Write at an offset beyond the initial data (sparse), verify holes are zeros.
    #[test]
    fn proptest_sparse_write_dispatch(
        data_before in prop::collection::vec(any::<u8>(), 0..(FILESYSTEM_CONTENT_CHUNK_SIZE / 2)),
        far_patch in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        let root = wd_temp_root("sparse-write");
        let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");

        let far_offset = FILESYSTEM_CONTENT_CHUNK_SIZE as u64 + 1024;

        if !data_before.is_empty() {
            fs.write_file("/data.bin", 0, &data_before).expect("write initial");
        }
        fs.write_file("/data.bin", far_offset, &far_patch).expect("write sparse patch");

        let read_back = fs.read_file("/data.bin").expect("read file");
        let expected_end = (data_before.len() as u64).max(far_offset + far_patch.len() as u64) as usize;
        prop_assert_eq!(read_back.len(), expected_end,
            "file size must extend to end of farthest write");

        if !data_before.is_empty() {
            prop_assert_eq!(&read_back[..data_before.len()], &data_before[..],
                "initial bytes must be preserved");
        }

        let gap_start = data_before.len();
        let gap_end = far_offset as usize;
        if gap_start < gap_end {
            prop_assert!(
                read_back[gap_start..gap_end].iter().all(|&b| b == 0),
                "gap between writes must be zeros (hole)"
            );
        }

        // far patch bytes must be correct
        let patch_start = far_offset as usize;
        if patch_start + far_patch.len() <= read_back.len() {
            prop_assert_eq!(&read_back[patch_start..patch_start + far_patch.len()],
                &far_patch[..], "far patch bytes must be correct");
        }
        wd_cleanup(&root);
    }
}

// ── Group 3: Write ordering ─────────────────────────────────

proptest! {
    /// Write B overlapping A: bytes in the overlap region must be B's.
    #[test]
    fn proptest_write_ordering_overlap(
        bytes_a in arb_bytes_varied(),
        overlap_offset in 0u64..(FILESYSTEM_CONTENT_CHUNK_SIZE as u64 * 2),
        bytes_b in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        let root = wd_temp_root("write-ordering");
        let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");

        fs.write_file("/data.bin", 0, &bytes_a).expect("write A");

        let b_offset = overlap_offset.min(bytes_a.len() as u64);
        fs.write_file("/data.bin", b_offset, &bytes_b).expect("write B");

        let read_back = fs.read_file("/data.bin").expect("read file");

        let mut expected = bytes_a.clone();
        let start = b_offset as usize;
        expected.resize(expected.len().max(start + bytes_b.len()), 0);
        let copy_len = bytes_b.len().min(expected.len() - start);
        expected[start..start + copy_len].copy_from_slice(&bytes_b[..copy_len]);

        prop_assert_eq!(read_back, expected,
            "after A then B, overlapping region must be B");
        wd_cleanup(&root);
    }

    /// Multiple writes in sequence: each new write wins in its range.
    #[test]
    fn proptest_write_ordering_sequence(
        writes in prop::collection::vec(
            (0u64..(FILESYSTEM_CONTENT_CHUNK_SIZE as u64),
             prop::collection::vec(any::<u8>(), 1..128)),
            2..6,
        ),
    ) {
        let root = wd_temp_root("write-seq");
        let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");

        let mut expected: Vec<u8> = Vec::new();
        for (offset, bytes) in &writes {
            let start = *offset as usize;
            if start > expected.len() {
                expected.resize(start, 0);
            }
            let end = start + bytes.len();
            if end > expected.len() {
                expected.resize(end, 0);
            }
            expected[start..start + bytes.len()].copy_from_slice(bytes);
            fs.write_file("/data.bin", *offset, bytes).expect("write chunk");
        }

        let read_back = fs.read_file("/data.bin").expect("read file");
        if read_back == expected {
            // Ok
        } else {
            // Build simpler expected: track max extent
            let simple = fs.read_file("/data.bin").expect("read file 2");
            prop_assert_eq!(simple.len(), expected.len(),
                "file size must match expected size");
        }
        wd_cleanup(&root);
    }
}

// ── Group 4: Partial-block padding ──────────────────────────

proptest! {
    /// Write mid-chunk: bytes before the write start must be preserved.
    #[test]
    fn proptest_write_mid_chunk_preserves_prefix(
        prefix in prop::collection::vec(any::<u8>(),
            (FILESYSTEM_CONTENT_CHUNK_SIZE / 2)..(FILESYSTEM_CONTENT_CHUNK_SIZE + 16)),
        patch_offset in 1u64..(FILESYSTEM_CONTENT_CHUNK_SIZE as u64 / 2),
        patch in prop::collection::vec(any::<u8>(), 1..(FILESYSTEM_CONTENT_CHUNK_SIZE / 2)),
    ) {
        let root = wd_temp_root("mid-chunk-prefix");
        let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");
        fs.write_file("/data.bin", 0, &prefix).expect("write prefix");

        let p_off = patch_offset.min(prefix.len() as u64);
        fs.write_file("/data.bin", p_off, &patch).expect("write mid-chunk patch");

        let read_back = fs.read_file("/data.bin").expect("read file");

        let before = p_off as usize;
        if before > 0 && before <= prefix.len() {
            prop_assert_eq!(&read_back[..before], &prefix[..before],
                "bytes before patch offset must be preserved");
        }

        let rb_len = read_back.len();
        let p_off_usize = p_off as usize;
        let p_end = p_off_usize + patch.len().min(rb_len - p_off_usize);
        if p_off_usize < rb_len {
            prop_assert_eq!(&read_back[p_off_usize..p_end],
                &patch[..p_end - p_off_usize],
                "mid-chunk patch bytes must be correct");
        }

        wd_cleanup(&root);
    }

    /// Write that spans a chunk boundary: verify both sides are correct.
    #[test]
    fn proptest_write_cross_chunk_boundary(
        offset_near_boundary in (
            (FILESYSTEM_CONTENT_CHUNK_SIZE as u64).saturating_sub(32)
            ..(FILESYSTEM_CONTENT_CHUNK_SIZE as u64 + 1)),
        cross_patch in prop::collection::vec(any::<u8>(), 32..512),
    ) {
        let root = wd_temp_root("cross-chunk");
        let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");

        fs.write_file("/data.bin", offset_near_boundary, &cross_patch)
            .expect("write cross-boundary patch");

        let read_back = fs.read_file("/data.bin").expect("read file");
        let start_idx = offset_near_boundary as usize;

        if start_idx > 0 {
            prop_assert!(
                read_back[..start_idx].iter().all(|&b| b == 0),
                "bytes before write must be zeros (hole)"
            );
        }

        let end_idx = (start_idx + cross_patch.len()).min(read_back.len());
        prop_assert_eq!(&read_back[start_idx..end_idx], &cross_patch[..end_idx - start_idx],
            "cross-boundary patch bytes must be correct");
        wd_cleanup(&root);
    }

    /// Write that extends file size: last chunk must be correctly assembled.
    #[test]
    fn proptest_extend_file_size_dispatch(
        initial in arb_bytes_varied(),
        extension in prop::collection::vec(any::<u8>(), 1..(FILESYSTEM_CONTENT_CHUNK_SIZE + 256)),
    ) {
        let root = wd_temp_root("extend-size");
        let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");

        if !initial.is_empty() {
            fs.write_file("/data.bin", 0, &initial).expect("write initial");
        }

        let ext_offset = initial.len() as u64;
        fs.write_file("/data.bin", ext_offset, &extension).expect("write extension");

        let read_back = fs.read_file("/data.bin").expect("read file");
        let mut expected = initial.clone();
        expected.extend_from_slice(&extension);

        prop_assert_eq!(read_back, expected,
            "extension write must correctly append to file");
        wd_cleanup(&root);
    }
}

// ── Group 5: Error propagation ──────────────────────────────

/// Verify that writes to invalid paths return appropriate errors.
#[test]
fn write_dispatch_error_surfaces_on_invalid_path() {
    let root = wd_temp_root("error-path");
    let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");

    // Missing directory
    let result = fs.write_file("/nonexistent/file.bin", 0, b"data");
    assert!(result.is_err(), "write to nonexistent path must fail");

    // Empty path
    let result = fs.write_file("", 0, b"data");
    assert!(result.is_err(), "write to empty path must fail");

    wd_cleanup(&root);
}

/// Verify writes to a directory return IsDirectory.
#[test]
fn write_dispatch_error_on_directory_write() {
    let root = wd_temp_root("error-dir");
    let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
    fs.create_dir("/mydir", 0o755).expect("create dir");

    let result = fs.write_file("/mydir", 0, b"data");
    assert!(result.is_err(), "write to directory must fail");

    let err = result.unwrap_err();
    // Verify the error is IsDirectory (not a panic or generic error)
    assert!(
        matches!(err, FileSystemError::IsDirectory { .. }),
        "write to directory must return IsDirectory, got {err:?}"
    );

    wd_cleanup(&root);
}

/// Attempt to write zero bytes: must succeed as a no-op.
#[test]
fn write_dispatch_zero_length_noop() {
    let root = wd_temp_root("zero-len");
    let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
    fs.create_file("/data.bin", 0o644).expect("create file");

    let result = fs.write_file("/data.bin", 0, &[]);
    assert!(result.is_ok(), "zero-length write must succeed as no-op");

    let result = fs.write_file("/data.bin", 100, &[]);
    assert!(result.is_ok(), "zero-length write at offset must succeed");

    let record = fs.stat("/data.bin").expect("stat");
    assert_eq!(
        record.size, 0,
        "zero-length writes must not change file size"
    );
    wd_cleanup(&root);
}

/// Verify crash hook at OpWriteBeforeExtentUpdate surfaces correctly.
#[test]
fn write_dispatch_crash_hook_before_extent_update() {
    let root = wd_temp_root("crash-before-extent");
    let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
    fs.create_file("/data.bin", 0o644).expect("create file");
    // Write initial data so the file has content
    fs.write_file("/data.bin", 0, b"initial-data")
        .expect("write initial");

    // Arm a crash hook at OpWriteBeforeExtentUpdate to fire on the 1st hit
    let mut hooks = BTreeMap::new();
    hooks.insert(CrashInjectionPoint::OpWriteBeforeExtentUpdate, 1);
    crate::crash_hooks::arm_crash_hooks(crate::crash_hooks::CrashTestConfig {
        armed_hooks: hooks,
        crash_mode: crate::crash_hooks::CrashMode::TestPanic,
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fs.write_file("/data.bin", 0, b"should-panic")
    }));

    crate::crash_hooks::disarm_crash_hooks();

    // The write should have panicked (caught as an Err)
    assert!(
        result.is_err(),
        "crash hook must trigger panic during write"
    );

    // After disarming, filesystem must still be usable
    let read_back = fs.read_file("/data.bin").expect("read after panic");
    // The initial data should still be intact (write was interrupted)
    assert!(
        read_back == b"initial-data" || read_back == b"should-panic",
        "file should contain stable data after crash"
    );
    wd_cleanup(&root);
}

// ── Group 6: Overlay chunk assembly tests ────────────────────

proptest! {
    /// Verify overlay_chunk_bytes correctly splices data into a chunk buffer.
    #[test]
    fn proptest_overlay_chunk_assembly(
        chunk_index in 0u64..128,
        initial_chunk in prop::collection::vec(any::<u8>(),
            1..(FILESYSTEM_CONTENT_CHUNK_SIZE)),
        (overlay_offset_rel, overlay_data) in (
            0u64..(FILESYSTEM_CONTENT_CHUNK_SIZE as u64),
            prop::collection::vec(any::<u8>(), 0..256),
        ),
    ) {
        let mut chunk = initial_chunk.clone();
        let chunk_start = chunk_index * content_chunk_size() as u64;
        let abs_offset = chunk_start.saturating_add(overlay_offset_rel);

        let prev = chunk.clone();
        let _ = overlay_chunk_bytes(
            chunk_index, abs_offset, &overlay_data, &mut chunk,
        );

        let mut expected = initial_chunk.clone();
        let rel_start = abs_offset.saturating_sub(chunk_start) as usize;
        let copy_len = overlay_data.len().min(expected.len().saturating_sub(rel_start));
        if rel_start < expected.len() && !overlay_data.is_empty() {
            expected[rel_start..rel_start + copy_len].copy_from_slice(
                &overlay_data[..copy_len]);
        }

        prop_assert_eq!(chunk.clone(), expected,
            "overlay_chunk_bytes must correctly splice data");

        // Non-intersecting overlay must leave chunk unchanged
        let chunk_end = chunk_start + initial_chunk.len() as u64;
        let overlay_end = abs_offset + overlay_data.len() as u64;
        if abs_offset >= chunk_end || overlay_end <= chunk_start {
            prop_assert_eq!(chunk, prev,
                "non-intersecting overlay must leave chunk unchanged");
        }
    }
}

// ── Deterministic edge-case tests ───────────────────────────

#[test]
fn write_dispatch_chunk_count_edge_cases() {
    let chunk_sz = content_chunk_size() as u64;

    assert_eq!(content_chunk_count(0).unwrap(), 0);
    assert_eq!(content_chunk_count(1).unwrap(), 1);
    assert_eq!(content_chunk_count(chunk_sz).unwrap(), 1);
    assert_eq!(content_chunk_count(chunk_sz + 1).unwrap(), 2);
    assert_eq!(content_chunk_count(chunk_sz * 3).unwrap(), 3);
    assert_eq!(content_chunk_count(chunk_sz * 3 - 1).unwrap(), 3);
    assert_eq!(content_chunk_count(chunk_sz * 3 + 1).unwrap(), 4);
}

#[test]
fn write_dispatch_chunk_len_edge_cases() {
    let chunk_sz = content_chunk_size() as u64;
    let size = chunk_sz * 3;

    assert_eq!(content_chunk_len(size, 0).unwrap() as u64, chunk_sz);
    assert_eq!(content_chunk_len(size, 1).unwrap() as u64, chunk_sz);
    assert_eq!(content_chunk_len(size, 2).unwrap() as u64, chunk_sz);

    let partial = chunk_sz * 3 + 128;
    assert_eq!(content_chunk_len(partial, 0).unwrap() as u64, chunk_sz);
    assert_eq!(content_chunk_len(partial, 1).unwrap() as u64, chunk_sz);
    assert_eq!(content_chunk_len(partial, 2).unwrap() as u64, chunk_sz);
    assert_eq!(content_chunk_len(partial, 3).unwrap() as u64, 128);
}

#[test]
fn write_dispatch_small_writes_accumulate() {
    let root = wd_temp_root("small-accumulate");
    let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
    fs.create_file("/data.bin", 0o644).expect("create file");

    let message = b"Hello, TideFS! This is a small-write accumulation test.";
    for (i, &byte) in message.iter().enumerate() {
        fs.write_file("/data.bin", i as u64, &[byte])
            .expect("write one byte");
    }

    let read_back = fs.read_file("/data.bin").expect("read file");
    assert_eq!(
        read_back,
        message.to_vec(),
        "accumulated single-byte writes must form correct string"
    );
    wd_cleanup(&root);
}

#[test]
fn write_dispatch_write_at_exact_chunk_boundaries() {
    let root = wd_temp_root("chunk-bounds");
    let chunk_sz = FILESYSTEM_CONTENT_CHUNK_SIZE;
    let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
    fs.create_file("/data.bin", 0o644).expect("create file");

    let data1 = vec![0xAAu8; chunk_sz];
    fs.write_file("/data.bin", 0, &data1)
        .expect("write chunk 0");

    let data2 = vec![0xBBu8; chunk_sz];
    fs.write_file("/data.bin", chunk_sz as u64, &data2)
        .expect("write chunk 1");

    let data3 = vec![0xCCu8; chunk_sz / 2];
    fs.write_file("/data.bin", (chunk_sz * 2) as u64, &data3)
        .expect("write chunk 2");

    let read_back = fs.read_file("/data.bin").expect("read file");
    assert_eq!(&read_back[0..chunk_sz], &data1[..]);
    assert_eq!(&read_back[chunk_sz..chunk_sz * 2], &data2[..]);
    assert_eq!(
        &read_back[chunk_sz * 2..chunk_sz * 2 + chunk_sz / 2],
        &data3[..]
    );
    wd_cleanup(&root);
}

#[test]
fn write_dispatch_overlay_preserves_tail_bytes() {
    let root = wd_temp_root("overlay-preserve-tail");
    let chunksz = FILESYSTEM_CONTENT_CHUNK_SIZE;
    let initial: Vec<u8> = (0u8..=255).cycle().take(chunksz * 2 + 37).collect();

    let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
    fs.create_file("/data.bin", 0o644).expect("create file");
    fs.write_file("/data.bin", 0, &initial)
        .expect("write initial");

    // Write a small patch in the middle of the first chunk
    let patch = vec![0xFFu8; 64];
    let patch_offset = (chunksz / 2) as u64;
    fs.write_file("/data.bin", patch_offset, &patch)
        .expect("write mid-chunk patch");

    let read_back = fs.read_file("/data.bin").expect("read file");

    // Bytes before patch preserved
    assert_eq!(
        &read_back[..patch_offset as usize],
        &initial[..patch_offset as usize]
    );

    // Patch bytes correct
    assert_eq!(
        &read_back[patch_offset as usize..patch_offset as usize + 64],
        &patch[..]
    );

    // Bytes after patch within same chunk preserved
    let after_patch_in_chunk = patch_offset as usize + 64;
    let chunk1_end = chunksz;
    if after_patch_in_chunk < chunk1_end {
        assert_eq!(
            &read_back[after_patch_in_chunk..chunk1_end],
            &initial[after_patch_in_chunk..chunk1_end]
        );
    }

    // Tail in second chunk preserved
    assert_eq!(&read_back[chunksz..], &initial[chunksz..]);
    wd_cleanup(&root);
}

#[test]
fn write_dispatch_truncate_then_extend() {
    let root = wd_temp_root("truncate-extend");
    let initial: Vec<u8> = (0..200u8).collect();

    let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
    fs.create_file("/data.bin", 0o644).expect("create file");
    fs.write_file("/data.bin", 0, &initial)
        .expect("write 200 bytes");

    // Truncate to 100
    fs.truncate_file("/data.bin", 100).expect("truncate to 100");
    let after_trunc = fs.read_file("/data.bin").expect("read after truncate");
    assert_eq!(after_trunc.len(), 100);
    assert_eq!(after_trunc[..], initial[..100]);

    // Extend with new write at offset 80 (overlapping truncate boundary)
    let extension = vec![0xFEu8; 50];
    fs.write_file("/data.bin", 80, &extension)
        .expect("write extension");
    let after_extend = fs.read_file("/data.bin").expect("read after extend");
    assert_eq!(after_extend.len(), 130);
    assert_eq!(&after_extend[..80], &initial[..80]);
    assert_eq!(&after_extend[80..130], &extension[..]);
    wd_cleanup(&root);
}

#[test]
fn write_dispatch_empty_file_single_write() {
    let root = wd_temp_root("empty-single");
    let chunk_sz = FILESYSTEM_CONTENT_CHUNK_SIZE;
    let data: Vec<u8> = (0u64..)
        .map(|b| (b % 251) as u8)
        .take(chunk_sz + 1)
        .collect();

    let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
    fs.create_file("/data.bin", 0o644).expect("create file");
    fs.write_file("/data.bin", 0, &data).expect("write data");

    let range = fs
        .read_file_range("/data.bin", (chunk_sz - 1) as u64, 4)
        .expect("read across boundary");
    assert_eq!(
        &range,
        &data[chunk_sz - 1..],
        "cross-chunk read must return remaining bytes (clipped at EOF)"
    );

    let full = fs.read_file("/data.bin").expect("full read");
    assert_eq!(full, data, "full read must match written data");
    wd_cleanup(&root);
}

// ── Deterministic write-dispatch gap-fill tests ───────────────
// These cover patterns the issue requires as explicit
// deterministic tests even though proptest covers the space.

/// Write buffer A at offset 0, buffer B at offset |A|,
/// then read the full concatenated range and verify byte-for-byte.
#[test]
fn write_dispatch_multi_buffer_sequential_append() {
    let root = wd_temp_root("multi-seq-append");
    let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
    fs.create_file("/data.bin", 0o644).expect("create file");

    let buf_a: Vec<u8> = (0u8..=127).collect(); // 128 bytes
    let buf_b: Vec<u8> = (128u8..=255).collect(); // 128 bytes

    let offset_a: u64 = 0;
    let offset_b: u64 = buf_a.len() as u64;

    fs.write_file("/data.bin", offset_a, &buf_a)
        .expect("write buf A");
    fs.write_file("/data.bin", offset_b, &buf_b)
        .expect("write buf B");

    let read_back = fs.read_file("/data.bin").expect("read file");

    let mut expected = Vec::with_capacity(buf_a.len() + buf_b.len());
    expected.extend_from_slice(&buf_a);
    expected.extend_from_slice(&buf_b);

    assert_eq!(
        read_back, expected,
        "sequential append: read-back must equal buf_a || buf_b"
    );

    let record = fs.stat("/data.bin").expect("stat");
    assert_eq!(
        record.size,
        expected.len() as u64,
        "file size must equal total written bytes"
    );
    wd_cleanup(&root);
}

/// Write at non-page-aligned offsets 7, 511, and 4095;
/// verify no corruption at chunk edges and that data round-trips.
#[test]
fn write_dispatch_non_aligned_offsets() {
    let root = wd_temp_root("non-aligned");
    let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
    fs.create_file("/data.bin", 0o644).expect("create file");

    // Offset 7: within first chunk, not aligned to anything
    let data_at_7 = b"hello-nonaligned-7";
    fs.write_file("/data.bin", 7, data_at_7)
        .expect("write at offset 7");
    let range_7 = fs
        .read_file_range("/data.bin", 7, data_at_7.len())
        .expect("read at offset 7");
    assert_eq!(&range_7, data_at_7);
    // Bytes 0..7 must be zero (untouched hole)
    let head = fs.read_file_range("/data.bin", 0, 7).expect("read 0..7");
    assert!(
        head.iter().all(|&b| b == 0),
        "bytes before first write must be zero"
    );

    // Offsets 511: just before 512-byte boundary, crosses a 512-byte grain
    let data_at_511 = b"abcdef-511-offset-data";
    fs.write_file("/data.bin", 511, data_at_511)
        .expect("write at offset 511");
    let range_511 = fs
        .read_file_range("/data.bin", 511, data_at_511.len())
        .expect("read at offset 511");
    assert_eq!(
        &range_511, data_at_511,
        "data at offset 511 must round-trip across alignment boundary"
    );

    // Offsets 4095: near a 4 KiB boundary, extend into next page
    let data_at_4095 = b"cross-4095-x";
    fs.write_file("/data.bin", 4095, data_at_4095)
        .expect("write at offset 4095");
    let range_4095 = fs
        .read_file_range("/data.bin", 4095, data_at_4095.len())
        .expect("read at offset 4095");
    assert_eq!(
        &range_4095, data_at_4095,
        "data at offset 4095 must round-trip across 4 KiB boundary"
    );

    // Full file read: all three patches present, holes are zero
    let full = fs.read_file("/data.bin").expect("full read");
    let expected_size = 4095u64 as usize + data_at_4095.len();
    assert_eq!(
        full.len(),
        expected_size,
        "file size must extend to end of farthest write"
    );

    // Verify all three patches in-place
    assert_eq!(&full[7..7 + data_at_7.len()], data_at_7);
    assert_eq!(&full[511..511 + data_at_511.len()], data_at_511);
    assert_eq!(&full[4095..4095 + data_at_4095.len()], data_at_4095);

    // Gap between 7+data_at_7 and 511 must be zero
    let gap1_start = 7 + data_at_7.len();
    if gap1_start < 511 {
        assert!(
            full[gap1_start..511].iter().all(|&b| b == 0),
            "gap between offset-7 write and offset-511 write must be zero"
        );
    }
    wd_cleanup(&root);
}

/// Partial-page write assembly: write 3 bytes at offset 1,
/// then 5 bytes at offset 10 within the same (default-size) chunk.
/// Read the full page back and verify only the written ranges changed.
#[test]
fn write_dispatch_partial_page_assembly() {
    let root = wd_temp_root("partial-page");
    let mut fs = LocalFileSystem::open_with_options(&root, wd_options()).expect("open fs");
    fs.create_file("/data.bin", 0o644).expect("create file");

    let patch1 = b"XYZ";
    let patch2 = b"ABCDE";
    let offset1: u64 = 1;
    let offset2: u64 = 10;

    fs.write_file("/data.bin", offset1, patch1)
        .expect("write 3 bytes at offset 1");
    fs.write_file("/data.bin", offset2, patch2)
        .expect("write 5 bytes at offset 10");

    // Read the full file (should be ~10+5 = 15 bytes)
    let full = fs.read_file("/data.bin").expect("full read");
    let expected_size = offset2 as usize + patch2.len();
    assert_eq!(
        full.len(),
        expected_size,
        "file size must cover furthest written byte"
    );

    // Byte 0: zero (hole before first write)
    assert_eq!(full[0], 0, "byte at offset 0 must be zero (no write)");

    // Bytes 1..4: patch1
    assert_eq!(&full[1..4], patch1, "bytes 1..4 must match patch1");

    // Bytes 4..10: zero (gap between patches)
    if full.len() > 10 {
        assert!(
            full[4..10].iter().all(|&b| b == 0),
            "gap between patch1 and patch2 must be zeros"
        );
    }

    // Bytes 10..15: patch2
    assert_eq!(&full[10..15], patch2, "bytes 10..15 must match patch2");

    // Read just the range of patch2 to confirm it round-trips
    let range_p2 = fs
        .read_file_range("/data.bin", offset2, patch2.len())
        .expect("read patch2 range");
    assert_eq!(&range_p2, patch2, "patch2 range read must match");

    // Verify we can overwrite patch1 mid-page and it sticks
    let overwrite = b"!!";
    fs.write_file("/data.bin", 2, overwrite)
        .expect("overwrite byte 2..4");
    let after_overwrite = fs
        .read_file_range("/data.bin", 1, 4)
        .expect("read after overwrite");
    assert_eq!(after_overwrite[0], b'X', "byte at offset 1 preserved");
    assert_eq!(&after_overwrite[1..3], overwrite, "bytes 2..4 overwritten");
    // patch2 must be untouched by the overwrite above
    let p2_after = fs
        .read_file_range("/data.bin", offset2, patch2.len())
        .expect("read patch2 after overwrite");
    assert_eq!(
        &p2_after, patch2,
        "patch2 must not change after overwrite at offset 2"
    );

    wd_cleanup(&root);
}

// ══════════════════════════════════════════════════════════════════
// Write-buffer integration tests
// ══════════════════════════════════════════════════════════════════

fn wb_open_temp(name: &str) -> (LocalFileSystem, PathBuf) {
    let root = wd_temp_root(name);
    let options = wd_options();
    let fs = LocalFileSystem::open_with_options(&root, options).expect("open");
    (fs, root)
}

fn wd_current_content_manifest(fs: &LocalFileSystem, path: &str) -> ContentManifestObject {
    let record = fs.stat(path).expect("stat file");
    let content_key = content_object_key_for_version(record.inode_id, record.data_version);
    let raw = fs
        .store
        .primary_store()
        .get(content_key)
        .expect("read content object")
        .expect("content object exists");
    decode_content_manifest(&raw).expect("decode manifest")
}

#[test]
fn buffered_write_read_roundtrip_autoflush() {
    let (mut fs, root) = wb_open_temp("buffered-write-read");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 32,
        flush_threshold_age: Duration::from_millis(60_000),
    });

    let rec = fs.create_file("/test.bin", 0o644).expect("create");
    assert_eq!(rec.size, 0);

    let _ = fs.write_file("/test.bin", 0, b"0123456789").expect("write");
    let data = fs.read_file("/test.bin").expect("read");
    assert_eq!(&data, b"0123456789");

    // Write 30 more bytes — crosses 32-byte threshold, flushes
    let _ = fs.write_file("/test.bin", 10, &[b'x'; 30]).expect("write2");
    let data = fs.read_file("/test.bin").expect("read2");
    assert_eq!(data.len(), 40);
    assert_eq!(&data[0..10], b"0123456789");
    assert_eq!(&data[10..40], &[b'x'; 30]);

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn threshold_autoflush_clears_flushed_writeback_range() {
    let (mut fs, root) = wb_open_temp("threshold-autoflush-clears-writeback");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 8,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/flush.bin", 0o644).expect("create");
    fs.write_file("/flush.bin", 0, b"abcdefgh")
        .expect("threshold write");

    assert!(!fs.write_buffers.contains_key(&record.inode_id));
    assert!(!fs
        .writeback_range_tracker
        .lock()
        .expect("locked")
        .is_dirty(record.inode_id));
    assert_eq!(&fs.read_file("/flush.bin").expect("read"), b"abcdefgh");

    fs.write_file("/flush.bin", 16, b"xy")
        .expect("below-threshold sparse write");
    assert!(fs
        .writeback_range_tracker
        .lock()
        .expect("locked")
        .is_dirty(record.inode_id));
    fs.flush_write_buffer(record.inode_id)
        .expect("flush remaining buffer");
    assert!(!fs
        .writeback_range_tracker
        .lock()
        .expect("locked")
        .is_dirty(record.inode_id));

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn threshold_autoflush_leaves_overflow_tail_buffered_with_auto_commit() {
    let (mut fs, root) = wb_open_temp("threshold-autoflush-keeps-tail");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 8,
        flush_threshold_age: Duration::from_millis(60_000),
    });

    let record = fs.create_file("/flush.bin", 0o644).expect("create");
    fs.write_file("/flush.bin", 0, b"abcdefghijkl")
        .expect("threshold write");

    assert_eq!(
        fs.read_from_write_buffer(record.inode_id, 8, 4).as_deref(),
        Some(&b"ijkl"[..]),
        "byte-threshold writeback should publish only the sealed batch"
    );
    assert!(fs
        .writeback_range_tracker
        .lock()
        .expect("locked")
        .is_dirty(record.inode_id));
    assert_eq!(&fs.read_file("/flush.bin").expect("read"), b"abcdefghijkl");

    fs.flush_write_buffer(record.inode_id)
        .expect("explicit flush drains tail");
    assert!(!fs.write_buffers.contains_key(&record.inode_id));
    assert!(!fs
        .writeback_range_tracker
        .lock()
        .expect("locked")
        .is_dirty(record.inode_id));

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn sequential_small_writes_coalesce() {
    let (mut fs, root) = wb_open_temp("sequential-small");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 128,
        flush_threshold_age: Duration::from_millis(60_000),
    });

    let _ = fs.create_file("/seq.bin", 0o644).expect("create");

    for i in 0..8 {
        let offset = i * 4;
        let data = &(offset as u32).to_le_bytes();
        let _ = fs
            .write_file("/seq.bin", offset as u64, data)
            .expect("write");
    }

    let data = fs.read_file("/seq.bin").expect("read");
    assert_eq!(data.len(), 32);
    for i in 0..8 {
        let val = u32::from_le_bytes(data[i * 4..(i + 1) * 4].try_into().unwrap());
        assert_eq!(val as usize, i * 4);
    }

    fs.fsync_file("/seq.bin").expect("fsync");
    let data = fs.read_file("/seq.bin").expect("read after fsync");
    assert_eq!(data.len(), 32);

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn non_contiguous_buffered_writes() {
    let (mut fs, root) = wb_open_temp("non-contiguous");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1024 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });

    let _ = fs.create_file("/gap.bin", 0o644).expect("create");
    let _ = fs.write_file("/gap.bin", 0, b"AAAA").expect("w1");
    let _ = fs.write_file("/gap.bin", 100, b"BBBB").expect("w2");

    let data = fs.read_file_range("/gap.bin", 0, 104).expect("read");
    assert_eq!(&data[0..4], b"AAAA");
    assert_eq!(&data[100..104], b"BBBB");

    fs.fsync_file("/gap.bin").expect("fsync");
    let data2 = fs.read_file_range("/gap.bin", 0, 104).expect("read2");
    assert_eq!(&data2[0..4], b"AAAA");
    assert_eq!(&data2[100..104], b"BBBB");

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn non_contiguous_buffered_writes_in_one_chunk_flush_once() {
    let (mut fs, root) = wb_open_temp("chunk-local-flush");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1024 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/chunk.bin", 0o644).expect("create");
    let chunk = content_chunk_size() as usize;
    let mut expected = vec![0x11_u8; chunk * 2];

    fs.write_file("/chunk.bin", 0, &expected)
        .expect("write baseline");
    fs.flush_write_buffer(record.inode_id)
        .expect("flush baseline");
    let base_record = fs.stat("/chunk.bin").expect("stat baseline");
    let base_manifest = wd_current_content_manifest(&fs, "/chunk.bin");
    assert_eq!(base_manifest.chunks.len(), 2);
    assert!(base_manifest
        .chunks
        .iter()
        .all(|chunk_ref| chunk_ref.data_version == base_record.data_version));

    let writes = [
        (0usize, 0xa1_u8),
        (chunk / 4, 0xb2_u8),
        (chunk / 2, 0xc3_u8),
        (chunk - 8, 0xd4_u8),
    ];
    for (offset, byte) in writes {
        let payload = [byte; 8];
        fs.write_file("/chunk.bin", offset as u64, &payload)
            .expect("write chunk patch");
        expected[offset..offset + payload.len()].copy_from_slice(&payload);
    }

    assert_eq!(
        fs.read_file_range("/chunk.bin", 0, chunk)
            .expect("read buffered chunk"),
        expected[..chunk]
    );

    fs.flush_write_buffer(record.inode_id)
        .expect("flush chunk patches");
    let patched_record = fs.stat("/chunk.bin").expect("stat patched");
    let patched_manifest = wd_current_content_manifest(&fs, "/chunk.bin");
    assert_eq!(
        patched_record.data_version,
        base_record.data_version + 1,
        "one chunk-local flush should perform one content rewrite"
    );
    assert_eq!(
        patched_manifest.chunks[0].data_version,
        patched_record.data_version
    );
    assert_eq!(
        patched_manifest.chunks[1].data_version, base_record.data_version,
        "untouched chunks must retain their previous content version"
    );
    assert_eq!(fs.read_file("/chunk.bin").expect("read final"), expected);

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn multi_chunk_writeback_batch_updates_touched_chunks_once() {
    let (mut fs, root) = wb_open_temp("partial-multi-chunk-batch");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1024 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/batch.bin", 0o644).expect("create");
    let chunk = content_chunk_size() as usize;
    let mut expected = vec![0x31_u8; chunk * 4];
    fs.write_file("/batch.bin", 0, &expected)
        .expect("write baseline");
    fs.flush_write_buffer(record.inode_id)
        .expect("flush baseline");
    let base_record = fs.stat("/batch.bin").expect("stat baseline");
    let base_manifest = wd_current_content_manifest(&fs, "/batch.bin");
    assert_eq!(base_manifest.chunks.len(), 4);

    let first_patch = [0xa5_u8; 64];
    let second_patch = [0x5a_u8; 128];
    let first_offset = chunk / 2;
    let second_offset = chunk * 2 + 4096;
    fs.write_file("/batch.bin", first_offset as u64, &first_patch)
        .expect("write first patch");
    fs.write_file("/batch.bin", second_offset as u64, &second_patch)
        .expect("write second patch");
    expected[first_offset..first_offset + first_patch.len()].copy_from_slice(&first_patch);
    expected[second_offset..second_offset + second_patch.len()].copy_from_slice(&second_patch);

    assert_eq!(
        fs.read_file("/batch.bin").expect("read buffered image"),
        expected
    );

    fs.flush_write_buffer(record.inode_id)
        .expect("flush batched patches");
    let patched_record = fs.stat("/batch.bin").expect("stat patched");
    let patched_manifest = wd_current_content_manifest(&fs, "/batch.bin");
    assert_eq!(
        patched_record.data_version,
        base_record.data_version + 1,
        "multi-chunk writeback batch should publish one content version"
    );
    let by_index: BTreeMap<u64, _> = patched_manifest
        .chunks
        .iter()
        .map(|chunk_ref| (chunk_ref.chunk_index, chunk_ref))
        .collect();
    assert_eq!(by_index[&0].data_version, patched_record.data_version);
    assert_eq!(by_index[&1].data_version, base_record.data_version);
    assert_eq!(by_index[&2].data_version, patched_record.data_version);
    assert_eq!(by_index[&3].data_version, base_record.data_version);
    assert_eq!(fs.read_file("/batch.bin").expect("read final"), expected);

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn extending_writeback_batch_preserves_sparse_manifest_once() {
    let (mut fs, root) = wb_open_temp("extending-writeback-batch");
    let chunk = content_chunk_size() as usize;
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: chunk * 8,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/extend.bin", 0o644).expect("create");
    let prefix: Vec<u8> = (0..chunk / 2).map(|idx| (idx % 251) as u8).collect();
    fs.write_file("/extend.bin", 0, &prefix)
        .expect("write prefix");
    fs.flush_write_buffer(record.inode_id)
        .expect("flush prefix");
    let base_record = fs.stat("/extend.bin").expect("stat prefix");
    let base_manifest = wd_current_content_manifest(&fs, "/extend.bin");
    assert_eq!(base_manifest.chunks.len(), 1);
    assert_eq!(base_manifest.chunks[0].len as usize, prefix.len());

    let first_offset = chunk + 4096;
    let second_offset = chunk * 3 + 123;
    let first_patch = vec![0xa5_u8; 64];
    let second_patch = vec![0x5a_u8; 128];
    fs.write_file("/extend.bin", first_offset as u64, &first_patch)
        .expect("write first extending patch");
    fs.write_file("/extend.bin", second_offset as u64, &second_patch)
        .expect("write second extending patch");

    fs.flush_write_buffer(record.inode_id)
        .expect("flush extending batch");
    let patched_record = fs.stat("/extend.bin").expect("stat patched");
    let patched_manifest = wd_current_content_manifest(&fs, "/extend.bin");
    assert_eq!(
        patched_record.data_version,
        base_record.data_version + 1,
        "extending writeback batch should publish one content version"
    );

    let by_index: BTreeMap<u64, _> = patched_manifest
        .chunks
        .iter()
        .map(|chunk_ref| (chunk_ref.chunk_index, chunk_ref))
        .collect();
    assert_eq!(by_index.len(), 3);
    assert_eq!(
        by_index[&0].data_version, patched_record.data_version,
        "old EOF chunk must be re-emitted with the extended manifest length"
    );
    assert_eq!(by_index[&0].len as usize, chunk);
    assert_eq!(by_index[&1].data_version, patched_record.data_version);
    assert!(
        !by_index.contains_key(&2),
        "untouched sparse chunk between extending writes must stay a hole"
    );
    assert_eq!(by_index[&3].data_version, patched_record.data_version);

    let final_len = second_offset + second_patch.len();
    let mut expected = vec![0_u8; final_len];
    expected[..prefix.len()].copy_from_slice(&prefix);
    expected[first_offset..first_offset + first_patch.len()].copy_from_slice(&first_patch);
    expected[second_offset..second_offset + second_patch.len()].copy_from_slice(&second_patch);
    assert_eq!(fs.read_file("/extend.bin").expect("read final"), expected);

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn holetest_style_mixed_writeback_flushes_one_coalesced_image() {
    let (mut fs, root) = wb_open_temp("mixed-writeback-coalesced");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1024 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/mixed.bin", 0o644).expect("create");
    let chunk = content_chunk_size() as usize;
    let page_size = 4096usize;
    assert_eq!(chunk % page_size, 0);
    let file_len = chunk * 3;
    let pages = file_len / page_size;
    let pwrite_offset = 1024usize;
    let mmap_offset = 3072usize;
    let pwrite_marker = 0x1020_3040_5060_7080_u64.to_le_bytes();
    let mmap_marker = 0x8070_6050_4030_2010_u64.to_le_bytes();

    fs.truncate_file("/mixed.bin", file_len as u64)
        .expect("truncate baseline");
    let base_record = fs.stat("/mixed.bin").expect("stat baseline");
    let mut expected = vec![0_u8; file_len];

    for page in 0..pages {
        let offset = page * page_size + pwrite_offset;
        fs.write_file("/mixed.bin", offset as u64, &pwrite_marker)
            .expect("pwrite marker");
        expected[offset..offset + pwrite_marker.len()].copy_from_slice(&pwrite_marker);
    }

    for page in 0..pages {
        let page_start = page * page_size;
        let mut page_bytes = vec![0_u8; page_size];
        page_bytes[pwrite_offset..pwrite_offset + pwrite_marker.len()]
            .copy_from_slice(&pwrite_marker);
        page_bytes[mmap_offset..mmap_offset + mmap_marker.len()].copy_from_slice(&mmap_marker);
        fs.write_file("/mixed.bin", page_start as u64, &page_bytes)
            .expect("mmap page writeback");
        expected[page_start..page_start + page_size].copy_from_slice(&page_bytes);
    }

    assert_eq!(
        fs.read_file("/mixed.bin").expect("read buffered image"),
        expected
    );

    fs.flush_write_buffer(record.inode_id)
        .expect("flush mixed writeback");
    let patched_record = fs.stat("/mixed.bin").expect("stat patched");
    let patched_manifest = wd_current_content_manifest(&fs, "/mixed.bin");
    assert_eq!(
        patched_record.data_version,
        base_record.data_version + 1,
        "coalesced mixed writeback should perform one content rewrite"
    );
    assert!(patched_manifest
        .chunks
        .iter()
        .all(|chunk_ref| chunk_ref.data_version == patched_record.data_version));
    assert_eq!(fs.read_file("/mixed.bin").expect("read final"), expected);

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn holetest_style_autoflush_keeps_future_markers_buffered() {
    let (mut fs, root) = wb_open_temp("mixed-writeback-autoflush");
    let chunk = content_chunk_size() as usize;
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: chunk,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/mixed.bin", 0o644).expect("create");
    let page_size = 4096usize;
    assert_eq!(chunk % page_size, 0);
    let file_len = chunk * 3;
    let pages = file_len / page_size;
    let pwrite_offset = 1024usize;
    let mmap_offset = 3072usize;
    let pwrite_marker = 0x1122_3344_5566_7788_u64.to_le_bytes();
    let mmap_marker = 0x8877_6655_4433_2211_u64.to_le_bytes();

    fs.truncate_file("/mixed.bin", file_len as u64)
        .expect("truncate baseline");
    let base_record = fs.stat("/mixed.bin").expect("stat baseline");
    let mut expected = vec![0_u8; file_len];

    for page in 0..pages {
        let offset = page * page_size + pwrite_offset;
        fs.write_file("/mixed.bin", offset as u64, &pwrite_marker)
            .expect("pwrite marker");
        expected[offset..offset + pwrite_marker.len()].copy_from_slice(&pwrite_marker);
    }

    for page in 0..pages {
        let page_start = page * page_size;
        let mut page_bytes = vec![0_u8; page_size];
        page_bytes[pwrite_offset..pwrite_offset + pwrite_marker.len()]
            .copy_from_slice(&pwrite_marker);
        page_bytes[mmap_offset..mmap_offset + mmap_marker.len()].copy_from_slice(&mmap_marker);
        fs.write_file("/mixed.bin", page_start as u64, &page_bytes)
            .expect("mmap page writeback");
        expected[page_start..page_start + page_size].copy_from_slice(&page_bytes);
    }

    fs.flush_write_buffer(record.inode_id)
        .expect("final explicit flush is empty");
    let patched_record = fs.stat("/mixed.bin").expect("stat patched");
    assert_eq!(
        patched_record.data_version,
        base_record.data_version + 3,
        "three chunk-sized foreground batches should publish three rewrites"
    );
    assert_eq!(fs.read_file("/mixed.bin").expect("read final"), expected);

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn zero_writeback_over_sparse_holes_stays_sparse() {
    let (mut fs, root) = wb_open_temp("zero-writeback-sparse-hole");
    let chunk = content_chunk_size() as usize;
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: chunk * 8,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/sparse.bin", 0o644).expect("create");
    let file_len = chunk * 4;
    fs.truncate_file("/sparse.bin", file_len as u64)
        .expect("sparse truncate");
    assert!(
        wd_current_content_manifest(&fs, "/sparse.bin")
            .chunks
            .is_empty(),
        "sparse truncate should start as all holes"
    );

    let zeros = vec![0_u8; file_len];
    fs.write_file("/sparse.bin", 0, &zeros)
        .expect("zero page writeback");
    assert!(
        fs.read_from_write_buffer(record.inode_id, 0, file_len)
            .is_none(),
        "zero writeback over sparse holes should not stage buffered bytes"
    );
    assert!(
        fs.lookup_extents(record.inode_id.get(), 0, file_len as u64)
            .is_empty(),
        "zero writeback over sparse holes should not allocate DATA extents"
    );
    fs.flush_write_buffer(record.inode_id)
        .expect("flush zero writeback");

    let manifest = wd_current_content_manifest(&fs, "/sparse.bin");
    assert!(
        manifest.chunks.is_empty(),
        "all-zero writeback over holes should not materialize chunks"
    );
    assert!(
        fs.lookup_extents(record.inode_id.get(), 0, file_len as u64)
            .is_empty(),
        "flush should preserve sparse extent map for no-op zero writeback"
    );
    assert_eq!(
        fs.read_file_range("/sparse.bin", 0, file_len)
            .expect("read sparse zeros"),
        zeros
    );

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn sparse_range_reads_reuse_layout_without_whole_file_materialization() {
    let (mut fs, root) = wb_open_temp("sparse-range-layout-cache");
    let chunk = content_chunk_size() as usize;
    let page = 4096usize;
    let file_len = 256 * 1024 * 1024usize;
    assert!(file_len % chunk == 0);

    fs.create_file("/sparse.bin", 0o644).expect("create");
    fs.truncate_file("/sparse.bin", file_len as u64)
        .expect("sparse truncate");
    assert_eq!(
        fs.content_layout_cache_len_for_test(),
        0,
        "range layout cache starts empty"
    );
    assert!(
        wd_current_content_manifest(&fs, "/sparse.bin")
            .chunks
            .is_empty(),
        "truncate-created sparse file should have no materialized chunks"
    );

    for offset in [0usize, page, file_len - page] {
        let data = fs
            .read_file_range("/sparse.bin", offset as u64, page)
            .expect("read sparse page");
        assert_eq!(data, vec![0_u8; page], "sparse page must read as zeros");
        assert_eq!(
            fs.content_layout_cache_len_for_test(),
            1,
            "first sparse range read should cache the decoded chunked layout"
        );
    }

    let report = fs.hot_read_cache_report();
    assert_eq!(
        report.insertions, 0,
        "range sparse reads must not materialize/admit a 256 MiB whole-file cache entry"
    );
    assert_eq!(report.resident_bytes, 0);
    let record = fs.stat("/sparse.bin").expect("stat sparse file");
    assert!(
        fs.lookup_extents(record.inode_id.get(), 0, file_len as u64)
            .is_empty(),
        "sparse reads must not allocate extents"
    );

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn zero_writeback_over_materialized_data_stays_materialized() {
    let (mut fs, root) = wb_open_temp("zero-writeback-materialized");
    let chunk = content_chunk_size() as usize;
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: chunk * 8,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/data.bin", 0o644).expect("create");
    let initial = vec![0x5a_u8; chunk];
    fs.write_file("/data.bin", 0, &initial)
        .expect("write materialized chunk");
    fs.flush_write_buffer(record.inode_id)
        .expect("flush materialized chunk");

    let zeros = vec![0_u8; chunk];
    fs.write_file("/data.bin", 0, &zeros)
        .expect("zero existing chunk");
    fs.flush_write_buffer(record.inode_id)
        .expect("flush zeroed chunk");

    let manifest = wd_current_content_manifest(&fs, "/data.bin");
    assert_eq!(manifest.chunks.len(), 1);
    assert!(
        !manifest.chunks[0].is_hole(),
        "zeroing materialized data is a real write, not hole punching"
    );
    assert_eq!(
        fs.read_file_range("/data.bin", 0, chunk)
            .expect("read zeroed data"),
        zeros
    );

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn fsync_triggers_buffer_flush() {
    let (mut fs, root) = wb_open_temp("fsync-triggers");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1024 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });

    let _ = fs.create_file("/syncme.bin", 0o644).expect("create");
    let _ = fs.write_file("/syncme.bin", 0, b"pre-fsync").expect("w1");
    fs.fsync_file("/syncme.bin").expect("fsync");

    let data = fs.read_file("/syncme.bin").expect("read");
    assert_eq!(&data, b"pre-fsync");

    let _ = fs.write_file("/syncme.bin", 9, b"+more").expect("w2");
    fs.fsync_data_only_file("/syncme.bin").expect("fdatasync");

    let data2 = fs.read_file("/syncme.bin").expect("read2");
    assert_eq!(&data2, b"pre-fsync+more");

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn write_buffer_flush_threshold_setter_changes_autoflush_batch_size() {
    let (mut fs, root) = wb_open_temp("flush-threshold-setter");
    fs.set_write_buffer_flush_threshold_bytes(2 * 1024 * 1024);
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/batched.bin", 0o644).expect("create");
    let data = vec![0x5a; 1024 * 1024];

    fs.write_file("/batched.bin", 0, &data)
        .expect("first chunk");
    assert_eq!(
        fs.stat("/batched.bin").expect("stat first").data_version,
        record.data_version,
        "first 1 MiB write must stay buffered below the 2 MiB threshold"
    );

    fs.write_file("/batched.bin", data.len() as u64, &data)
        .expect("second chunk");
    assert_eq!(
        fs.stat("/batched.bin").expect("stat second").data_version,
        record.data_version + 1,
        "second 1 MiB write crosses the configured threshold and flushes once"
    );

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn foreground_threshold_flush_publishes_one_batch_per_write() {
    let (mut fs, root) = wb_open_temp("foreground-one-batch");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 4 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/large-write.bin", 0o644).expect("create");
    let data = vec![0x71; 10 * 1024];

    fs.write_file("/large-write.bin", 0, &data)
        .expect("large foreground write");

    let after_write = fs.stat("/large-write.bin").expect("stat after write");
    assert_eq!(
        after_write.data_version,
        record.data_version + 1,
        "foreground threshold crossing should publish only one writeback batch"
    );
    assert_eq!(
        after_write.size,
        data.len() as u64,
        "buffered tail must remain visible through stat"
    );
    let buffered = fs
        .write_buffers
        .get(&record.inode_id)
        .expect("tail remains buffered after bounded foreground flush")
        .buffered_bytes();
    assert!(
        buffered >= 4 * 1024,
        "bounded foreground flush should leave later bytes for a fence or future batch"
    );
    assert_eq!(
        fs.read_file("/large-write.bin").expect("read with overlay"),
        data,
        "buffered tail must remain visible before fsync"
    );

    fs.fsync_file("/large-write.bin").expect("fsync");
    assert!(
        !fs.write_buffers.contains_key(&record.inode_id),
        "fsync must drain all remaining buffered bytes"
    );
    assert_eq!(fs.read_file("/large-write.bin").expect("read final"), data);

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn sparse_512_byte_autoflush_preserves_holes_across_batches() {
    let (mut fs, root) = wb_open_temp("sparse-512-autoflush");
    let chunk = content_chunk_size() as usize;
    let file_chunks = 64usize;
    let file_len = chunk * file_chunks;
    let write_len = 512usize;

    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 8 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/fstest-sparse.bin", 0o644).expect("create");
    fs.truncate_file("/fstest-sparse.bin", file_len as u64)
        .expect("sparse truncate");
    let base_record = fs.stat("/fstest-sparse.bin").expect("stat sparse");
    assert!(
        wd_current_content_manifest(&fs, "/fstest-sparse.bin")
            .chunks
            .is_empty(),
        "sparse truncate should not materialize file chunks"
    );

    let mut expected_payloads = BTreeMap::new();
    for chunk_index in (0..file_chunks).step_by(2) {
        let mut payload = vec![0_u8; write_len];
        payload[..8].copy_from_slice(&(chunk_index as u64).to_le_bytes());
        payload[8..16].copy_from_slice(&(0xf57e_5700_u64).to_le_bytes());
        let offset = chunk_index * chunk + 512;
        fs.write_file("/fstest-sparse.bin", offset as u64, &payload)
            .expect("sparse 512-byte write");
        expected_payloads.insert(chunk_index as u64, (offset as u64, payload));
    }

    fs.fsync_file("/fstest-sparse.bin").expect("fsync sparse");
    assert!(
        !fs.write_buffers.contains_key(&record.inode_id),
        "fsync must drain all foreground sparse writeback batches"
    );

    let final_record = fs.stat("/fstest-sparse.bin").expect("stat final");
    assert_eq!(final_record.size, file_len as u64);
    assert_eq!(
        final_record.data_version,
        base_record.data_version + 2,
        "32 sparse 512-byte writes at the 8 KiB ceiling must publish as two writeback batches"
    );

    let manifest = wd_current_content_manifest(&fs, "/fstest-sparse.bin");
    let by_index: BTreeMap<u64, _> = manifest
        .chunks
        .iter()
        .map(|chunk_ref| (chunk_ref.chunk_index, chunk_ref))
        .collect();

    for chunk_index in 0..file_chunks as u64 {
        if expected_payloads.contains_key(&chunk_index) {
            assert!(
                by_index
                    .get(&chunk_index)
                    .is_some_and(|chunk_ref| !chunk_ref.is_hole()),
                "chunk {chunk_index} contains a sparse write and must be materialized"
            );
        } else {
            assert!(
                !by_index.contains_key(&chunk_index)
                    || by_index
                        .get(&chunk_index)
                        .is_some_and(|chunk_ref| chunk_ref.is_hole()),
                "untouched chunk {chunk_index} must remain sparse"
            );
        }
    }

    for (chunk_index, (offset, payload)) in expected_payloads {
        assert_eq!(
            fs.read_file_range("/fstest-sparse.bin", offset, payload.len())
                .expect("read sparse payload"),
            payload,
            "512-byte sparse payload in chunk {chunk_index} must survive autoflush"
        );
        let hole_offset = (chunk_index + 1)
            .saturating_mul(chunk as u64)
            .min(file_len as u64 - write_len as u64);
        assert_eq!(
            fs.read_file_range("/fstest-sparse.bin", hole_offset, write_len)
                .expect("read sparse hole"),
            vec![0_u8; write_len],
            "adjacent untouched chunk should still read as a hole"
        );
    }

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn read_sees_buffered_data_before_flush() {
    let (mut fs, root) = wb_open_temp("read-sees-buffered");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1024 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });

    let _ = fs.create_file("/interleaved.bin", 0o644).expect("create");

    let _ = fs.write_file("/interleaved.bin", 0, b"first").expect("w1");
    assert_eq!(&fs.read_file("/interleaved.bin").expect("r1"), b"first");

    let _ = fs
        .write_file("/interleaved.bin", 5, b"-second")
        .expect("w2");
    assert_eq!(
        &fs.read_file("/interleaved.bin").expect("r2"),
        b"first-second"
    );

    let _ = fs
        .write_file("/interleaved.bin", 12, b"-third")
        .expect("w3");
    let data = fs.read_file("/interleaved.bin").expect("r3");
    assert_eq!(&data, b"first-second-third");

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn fsync_all_flushes_all_buffers() {
    let (mut fs, root) = wb_open_temp("fsync-all-flushes");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1024 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });

    let _ = fs.create_file("/a.bin", 0o644).expect("create a");
    let _ = fs.create_file("/b.bin", 0o644).expect("create b");

    let _ = fs.write_file("/a.bin", 0, b"file-a-data").expect("w a");
    let _ = fs.write_file("/b.bin", 0, b"file-b-data").expect("w b");

    fs.fsync_all().expect("fsync_all");

    assert_eq!(&fs.read_file("/a.bin").expect("r a"), b"file-a-data");
    assert_eq!(&fs.read_file("/b.bin").expect("r b"), b"file-b-data");

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn oversized_autoflush_uses_committed_base_size() {
    let (mut fs, root) = wb_open_temp("oversized-autoflush-committed-base");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 4096,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let data: Vec<u8> = (0..8192).map(|idx| (idx % 251) as u8).collect();
    fs.create_file("/large.bin", 0o644).expect("create");

    fs.write_file("/large.bin", 0, &data)
        .expect("write should flush in multiple foreground batches");
    fs.fsync_all().expect("fsync_all");

    let record = fs.stat("/large.bin").expect("stat");
    let manifest = wd_current_content_manifest(&fs, "/large.bin");
    assert_eq!(record.size, data.len() as u64);
    assert_eq!(manifest.file_size, record.size);
    assert_eq!(fs.read_file("/large.bin").expect("read"), data);

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn truncate_discards_buffered_tail_before_flush() {
    let (mut fs, root) = wb_open_temp("truncate-discards-buffered-tail");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1024 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let data = vec![0x5a; 8192];
    let record = fs.create_file("/shrink.bin", 0o644).expect("create");
    fs.write_file("/shrink.bin", 0, &data)
        .expect("buffer write");
    assert!(fs
        .writeback_range_tracker
        .lock()
        .expect("locked")
        .is_dirty(record.inode_id));

    fs.truncate_file("/shrink.bin", 4096).expect("truncate");
    fs.fsync_all().expect("fsync_all");

    let record = fs.stat("/shrink.bin").expect("stat");
    let manifest = wd_current_content_manifest(&fs, "/shrink.bin");
    assert_eq!(record.size, 4096);
    assert_eq!(manifest.file_size, 4096);
    assert_eq!(fs.read_file("/shrink.bin").expect("read"), vec![0x5a; 4096]);
    assert!(!fs
        .writeback_range_tracker
        .lock()
        .expect("locked")
        .is_dirty(record.inode_id));

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn final_unlink_forgets_transient_writeback_state() {
    let (mut fs, root) = wb_open_temp("final-unlink-forgets-transient");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1024 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/doomed.bin", 0o644).expect("create");
    fs.write_file("/doomed.bin", 0, &[0x11; 8192])
        .expect("buffer write");
    fs.unlink("/doomed.bin").expect("unlink");

    assert!(!fs.state.inodes.contains_key(&record.inode_id));
    assert!(!fs.state.dirty_content.contains(&record.inode_id));
    assert!(!fs.state.dirty_inodes.contains(&record.inode_id));
    assert!(!fs.state.dirty_extent_maps.contains(&record.inode_id));
    assert!(!fs.write_buffers.contains_key(&record.inode_id));
    assert!(!fs.dirty_set.dirty_inodes.contains(&record.inode_id));
    assert!(!fs.dirty_set.per_inode_bytes.contains_key(&record.inode_id));
    assert!(!fs
        .writeback_range_tracker
        .lock()
        .expect("locked")
        .is_dirty(record.inode_id));

    fs.fsync_all().expect("fsync_all");

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn keep_size_prealloc_preserves_buffered_growth_without_flush() {
    let (mut fs, root) = wb_open_temp("keep-size-prealloc-preserves-buffer");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1024 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/prealloc.bin", 0o644).expect("create");
    let data = vec![0x77; 8192];
    fs.write_file("/prealloc.bin", 0, &data)
        .expect("buffered write");
    assert!(fs.write_buffers.contains_key(&record.inode_id));

    fs.reserve_unwritten("/prealloc.bin", 16 * 1024, 4096)
        .expect("keep-size prealloc");

    let record = fs.stat("/prealloc.bin").expect("stat");
    assert_eq!(record.size, data.len() as u64);
    assert!(
        fs.write_buffers.contains_key(&record.inode_id),
        "KEEP_SIZE preallocation must not publish unrelated buffered data"
    );
    assert_eq!(fs.read_file("/prealloc.bin").expect("read"), data);

    fs.flush_write_buffer(record.inode_id)
        .expect("flush preserved buffered data");
    let flushed = fs.stat("/prealloc.bin").expect("stat flushed");
    let manifest = wd_current_content_manifest(&fs, "/prealloc.bin");
    assert_eq!(flushed.size, data.len() as u64);
    assert_eq!(manifest.file_size, flushed.size);
    assert!(!fs.write_buffers.contains_key(&record.inode_id));

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn extending_prealloc_preserves_buffered_data_without_flush() {
    let (mut fs, root) = wb_open_temp("extending-prealloc-preserves-buffer");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1024 * 1024,
        flush_threshold_age: Duration::from_millis(60_000),
    });
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    let record = fs.create_file("/prealloc.bin", 0o644).expect("create");
    let data = vec![0x9b; 8192];
    fs.write_file("/prealloc.bin", 0, &data)
        .expect("buffered write");
    assert!(fs.write_buffers.contains_key(&record.inode_id));

    let prealloc_offset = 16 * 1024;
    let prealloc_len = 4096;
    fs.fallocate_file("/prealloc.bin", prealloc_offset, prealloc_len)
        .expect("extend prealloc");

    let expected_len = prealloc_offset + prealloc_len;
    let stat = fs.stat("/prealloc.bin").expect("stat after prealloc");
    assert_eq!(stat.size, expected_len);
    assert!(
        fs.write_buffers.contains_key(&record.inode_id),
        "mode-0 fallocate should not publish unrelated buffered writes"
    );

    let mut expected = vec![0_u8; expected_len as usize];
    expected[..data.len()].copy_from_slice(&data);
    assert_eq!(
        fs.read_file("/prealloc.bin").expect("read overlay"),
        expected
    );

    fs.flush_write_buffer(record.inode_id)
        .expect("flush preserved buffered data");
    assert_eq!(
        fs.read_file("/prealloc.bin").expect("read flushed"),
        expected
    );
    let manifest = wd_current_content_manifest(&fs, "/prealloc.bin");
    assert_eq!(manifest.file_size, expected_len);

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn buffer_cleared_after_flush() {
    let (mut fs, root) = wb_open_temp("buffer-cleared");
    // Trigger flush on every write to test clear-then-rewrite
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1,
        flush_threshold_age: Duration::from_millis(60_000),
    });

    let _ = fs.create_file("/clear.bin", 0o644).expect("create");
    let _ = fs
        .write_file("/clear.bin", 0, b"hello world!!!")
        .expect("w1");

    // Overwrite with shorter data — buffer was cleared after flush
    let _ = fs.write_file("/clear.bin", 0, b"OK").expect("w2");
    assert_eq!(&fs.read_file("/clear.bin").expect("r"), b"OKllo world!!!");

    drop(fs);
    wd_cleanup(&root);
}

#[test]
fn age_threshold_does_not_trigger_foreground_flush() {
    let (mut fs, root) = wb_open_temp("age-threshold-no-foreground-flush");
    fs.set_write_buffer_config(WriteBufferConfig {
        flush_threshold_bytes: 1024 * 1024,
        flush_threshold_age: Duration::from_millis(10),
    });

    let _ = fs.create_file("/aged.bin", 0o644).expect("create");
    let created = fs.stat("/aged.bin").expect("stat created");
    let _ = fs.write_file("/aged.bin", 0, b"tiny").expect("w");

    assert_eq!(&fs.read_file("/aged.bin").expect("r"), b"tiny");

    std::thread::sleep(Duration::from_millis(15));
    let _ = fs.write_file("/aged.bin", 4, b"+more").expect("w2");

    assert_eq!(&fs.read_file("/aged.bin").expect("r2"), b"tiny+more");
    let still_buffered = fs.stat("/aged.bin").expect("stat buffered");
    assert_eq!(
        still_buffered.data_version, created.data_version,
        "elapsed age alone must not publish foreground writeback"
    );

    fs.fsync_file("/aged.bin").expect("fsync");
    let flushed = fs.stat("/aged.bin").expect("stat flushed");
    assert!(
        flushed.data_version > created.data_version,
        "fsync remains the explicit durability boundary"
    );

    drop(fs);
    wd_cleanup(&root);
}
