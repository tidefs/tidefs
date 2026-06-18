// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Writeback pipeline integration tests.
//!
//! Exercises the full writeback lifecycle across crate boundaries:
//! dirty-page tracking, flush dispatch, extent-map allocation, and
//! object-store persistence.
//!
//! # Test groups
//!
//! 1. **Dirty-track smoke** — write data, verify dirty-page tracking
//!    through the page cache public API (dirty count, per-inode dirty
//!    state).
//! 2. **Flush-to-object-store** — trigger writeback/flush and verify the
//!    object store contains the written data with correct extent mapping.
//! 3. **Multi-file writeback ordering** — write multiple files, trigger
//!    flush, verify all reach the object store with no cross-file
//!    corruption.
//! 4. **Large-write extent spanning** — write data that spans multiple
//!    extents; verify all extents are allocated and persisted correctly.
//!
//! ```bash
//! cargo test -p tidefs-local-filesystem --test writeback_pipeline
//! ```

use std::env;
use std::fs;

use tidefs_local_filesystem::page_cache::{CachedPage, PageKey};
use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};

// ── helpers ───────────────────────────────────────────────────────

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("tidefs-wbp-{label}-{ts}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn open_fs(dir: &std::path::Path) -> LocalFileSystem {
    LocalFileSystem::open(dir).expect("open filesystem")
}

// ═══════════════════════════════════════════════════════════════════
// Group 1: Dirty-track smoke
// ═══════════════════════════════════════════════════════════════════

/// Insert a page into the page cache, mark it dirty, and check
/// dirty tracking through the public `dirty_page_tracker_mut()` API.
#[test]
fn dirty_track_smoke_page_cache_mark_dirty() {
    set_test_key();
    let dir = temp_dir("dirty_page_cache");

    let mut fs = open_fs(&dir);
    let record = fs
        .create_file("/page.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");

    let ino = record.inode_id;

    // Insert a page into the page cache.
    let page_key = PageKey::new(ino, 0, 4096);
    let page_data = vec![0xABu8; 4096];
    let page = CachedPage::new(page_data.clone(), page_data.len());
    fs.insert_page_and_maybe_reclaim(page_key, page);

    // Mark the page dirty via the dirty page tracker.
    {
        let mut dt = fs.dirty_page_tracker_mut();
        assert!(!dt.is_dirty(&page_key), "page should be clean before mark");
        dt.mark_dirty(page_key);
        assert!(dt.is_dirty(&page_key), "page should be dirty after mark");
        assert_eq!(dt.dirty_page_count(), 1, "one dirty page");
        assert_eq!(dt.per_inode_dirty_count(ino), 1, "one dirty page for inode");
    }

    // Mark clean and verify.
    {
        let mut dt = fs.dirty_page_tracker_mut();
        dt.mark_clean(page_key);
        assert!(
            !dt.is_dirty(&page_key),
            "page should be clean after mark_clean"
        );
        assert_eq!(dt.dirty_page_count(), 0, "no dirty pages");
    }

    drop(fs);
}

/// Insert multiple pages for the same inode, mark some dirty, verify
/// per-inode dirty count.
#[test]
fn dirty_track_smoke_multi_page_per_inode() {
    set_test_key();
    let dir = temp_dir("dirty_multi_page");

    let mut fs = open_fs(&dir);
    let record = fs
        .create_file("/multi.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");

    let ino = record.inode_id;

    // Insert three pages: offset 0, 4096, 8192.
    let key0 = PageKey::new(ino, 0, 4096);
    let key1 = PageKey::new(ino, 4096, 4096);
    let key2 = PageKey::new(ino, 8192, 4096);

    fs.insert_page_and_maybe_reclaim(key0, CachedPage::new(vec![0x00u8; 4096], 4096));
    fs.insert_page_and_maybe_reclaim(key1, CachedPage::new(vec![0x11u8; 4096], 4096));
    fs.insert_page_and_maybe_reclaim(key2, CachedPage::new(vec![0x22u8; 4096], 4096));

    // Mark pages 0 and 2 dirty, leave page 1 clean.
    {
        let mut dt = fs.dirty_page_tracker_mut();
        dt.mark_dirty(key0);
        dt.mark_dirty(key2);
        assert_eq!(dt.dirty_page_count(), 2, "two dirty pages total");
        assert_eq!(
            dt.per_inode_dirty_count(ino),
            2,
            "two dirty pages for inode"
        );
    }

    // Verify dirty pages iterator.
    {
        let dt = fs.dirty_page_tracker_mut();
        let dirty: Vec<_> = dt.dirty_pages_for_inode(ino).cloned().collect();
        assert_eq!(dirty.len(), 2, "two dirty pages for inode");
        // Key1 (offset 4096) should NOT be dirty.
        assert!(!dt.is_dirty(&key1), "page 1 should be clean");
    }

    drop(fs);
}

/// After a write_file call, verify that the data survives a persistence
/// round-trip (the dirty data made it to the object store).
#[test]
fn dirty_track_smoke_write_persistence_roundtrip() {
    set_test_key();
    let dir = temp_dir("dirty_persist");

    let payload = b"roundtrip-payload-for-dirty-track";
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/persist.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.write_file("/persist.txt", 0, payload)
            .expect("write file");
        fs.sync_all().expect("sync all");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/persist.txt").expect("read file");
        assert_eq!(data, payload, "data must survive round-trip");
    }
}

/// Zero-length writes should not dirty any tracking state.
#[test]
fn dirty_track_smoke_zero_length_write_no_dirty() {
    set_test_key();
    let dir = temp_dir("dirty_zero");

    let mut fs = open_fs(&dir);
    let record = fs
        .create_file("/zero.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");

    let ino = record.inode_id;

    // Write zero bytes — this should be a no-op for dirty tracking.
    fs.write_file("/zero.bin", 0, &[])
        .expect("zero-length write");

    // Verify no dirty pages in the page_cache dirty tracker.
    {
        let dt = fs.dirty_page_tracker_mut();
        assert_eq!(
            dt.per_inode_dirty_count(ino),
            0,
            "zero-length write should not dirty pages"
        );
    }

    drop(fs);
}

// ═══════════════════════════════════════════════════════════════════
// Group 2: Flush-to-object-store
// ═══════════════════════════════════════════════════════════════════

/// Write data, sync, reopen — data must survive in the object store.
#[test]
fn flush_to_object_store_roundtrip() {
    set_test_key();
    let dir = temp_dir("flush_roundtrip");

    let payload: Vec<u8> = (0..64u8).cycle().take(8192).collect();
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/data.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.write_file("/data.bin", 0, &payload).expect("write data");
        fs.sync_all().expect("sync all");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/data.bin").expect("read file");
        assert_eq!(data, payload, "data must survive sync+reopen round-trip");
    }
}

/// Write data at a non-zero offset, sync, and verify the file size
/// includes the hole up to the written region.
#[test]
fn flush_to_object_store_offset_write() {
    set_test_key();
    let dir = temp_dir("flush_offset");

    let payload = b"offset-data";
    let offset: u64 = 4096;
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/offset.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.write_file("/offset.bin", offset, payload)
            .expect("write at offset");
        fs.sync_all().expect("sync all");
    }

    {
        let fs = open_fs(&dir);
        let record = fs.stat("/offset.bin").expect("stat file");
        assert_eq!(
            record.size,
            offset + payload.len() as u64,
            "file size should include offset"
        );

        let data = fs.read_file("/offset.bin").expect("read file");
        assert_eq!(data.len() as u64, offset + payload.len() as u64);
        assert_eq!(
            &data[0..offset as usize],
            &vec![0u8; offset as usize][..],
            "hole should be zeros"
        );
        assert_eq!(
            &data[offset as usize..offset as usize + payload.len()],
            payload,
            "payload at offset should match"
        );
    }
}

/// Verify that extent allocation is tracked after a write.
#[test]
fn flush_to_object_store_extent_allocation() {
    set_test_key();
    let dir = temp_dir("flush_extent");

    let mut fs = open_fs(&dir);
    let record = fs
        .create_file("/ext.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");

    fs.write_file("/ext.bin", 0, &[0xCCu8; 8192])
        .expect("write data");

    // Check extent allocator state via public lookup_extents.
    let extents = fs.lookup_extents(record.inode_id.0, 0, 8192);
    assert!(
        !extents.is_empty(),
        "extent allocator should have entries after write"
    );
    // Check extent allocator state via public lookup_extents (in-memory,
    // populated during write).
    let extents = fs.lookup_extents(record.inode_id.0, 0, 8192);
    assert!(
        !extents.is_empty(),
        "extent allocator should have entries after write"
    );

    // Sync and verify data survives round-trip.
    fs.sync_all().expect("sync all");
    let data = fs.read_file("/ext.bin").expect("read file");
    assert_eq!(data.len(), 8192, "data length should be 8192 after write");
    assert_eq!(data, vec![0xCCu8; 8192], "data content should match");
    drop(fs);
}

/// Write, sync, reopen — verify byte-for-byte equality.
#[test]
fn flush_to_object_store_direct_object_check() {
    set_test_key();
    let dir = temp_dir("flush_obj");

    let payload = b"object-store-direct-check";
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/obj.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.write_file("/obj.bin", 0, payload).expect("write data");
        fs.sync_all().expect("sync all");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/obj.bin").expect("read file");
        assert_eq!(data, payload, "data must survive at the object level");
    }
}

// ═══════════════════════════════════════════════════════════════════
// Group 3: Multi-file writeback ordering
// ═══════════════════════════════════════════════════════════════════

/// Write multiple files, sync, reopen — all files must be intact
/// with no cross-file corruption.
#[test]
fn multi_file_writeback_all_survive() {
    set_test_key();
    let dir = temp_dir("multi_all");

    let files: Vec<(&str, &[u8])> = vec![
        ("/alpha.bin", &[0x01u8; 512]),
        ("/beta.bin", &[0x02u8; 1024]),
        ("/gamma.bin", &[0x03u8; 2048]),
        ("/delta.bin", &[0x04u8; 4096]),
    ];

    {
        let mut fs = open_fs(&dir);
        for (path, data) in &files {
            fs.create_file(path, DEFAULT_FILE_PERMISSIONS)
                .expect("create file");
            fs.write_file(path, 0, data).expect("write file");
        }
        fs.sync_all().expect("sync all");
    }

    {
        let fs = open_fs(&dir);
        for (path, expected) in &files {
            let data = fs
                .read_file(path)
                .unwrap_or_else(|e| panic!("read {path}: {e}"));
            assert_eq!(data, *expected, "file {path} content mismatch");
        }
    }
}

/// Interleaved writes to multiple files, then verify ordering.
#[test]
fn multi_file_writeback_interleaved() {
    set_test_key();
    let dir = temp_dir("multi_interleaved");

    {
        let mut fs = open_fs(&dir);
        for i in 0u64..4 {
            fs.create_file(format!("/file_{i}.dat"), DEFAULT_FILE_PERMISSIONS)
                .expect("create file");
        }
        // Interleaved writes.
        fs.write_file("/file_0.dat", 0, b"zero").expect("write 0");
        fs.write_file("/file_1.dat", 0, b"one").expect("write 1");
        fs.write_file("/file_0.dat", 4, b"-more")
            .expect("write 0 again");
        fs.write_file("/file_2.dat", 0, b"two").expect("write 2");
        fs.write_file("/file_3.dat", 0, b"three").expect("write 3");
        fs.write_file("/file_1.dat", 3, b"-extra")
            .expect("write 1 again");

        fs.sync_all().expect("sync all");
    }

    {
        let fs = open_fs(&dir);
        assert_eq!(fs.read_file("/file_0.dat").expect("read 0"), b"zero-more");
        assert_eq!(fs.read_file("/file_1.dat").expect("read 1"), b"one-extra");
        assert_eq!(fs.read_file("/file_2.dat").expect("read 2"), b"two");
        assert_eq!(fs.read_file("/file_3.dat").expect("read 3"), b"three");
    }
}

/// Create and write files in separate subdirectories and verify.
#[test]
fn multi_file_writeback_subdirs() {
    set_test_key();
    let dir = temp_dir("multi_subdirs");

    {
        let mut fs = open_fs(&dir);
        fs.create_dir("/dir_a", 0o755).expect("create dir a");
        fs.create_dir("/dir_b", 0o755).expect("create dir b");

        fs.create_file("/dir_a/x.dat", DEFAULT_FILE_PERMISSIONS)
            .expect("create a/x");
        fs.create_file("/dir_b/y.dat", DEFAULT_FILE_PERMISSIONS)
            .expect("create b/y");

        fs.write_file("/dir_a/x.dat", 0, b"ax").expect("write a/x");
        fs.write_file("/dir_b/y.dat", 0, b"by").expect("write b/y");

        fs.sync_all().expect("sync all");
    }

    {
        let fs = open_fs(&dir);
        assert_eq!(fs.read_file("/dir_a/x.dat").expect("read a/x"), b"ax");
        assert_eq!(fs.read_file("/dir_b/y.dat").expect("read b/y"), b"by");
    }
}

/// Write files, then overwrite one mid-session, verify final state.
#[test]
fn multi_file_writeback_overwrite() {
    set_test_key();
    let dir = temp_dir("multi_overwrite");

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/victim.dat", DEFAULT_FILE_PERMISSIONS)
            .expect("create victim");
        fs.create_file("/bystander.dat", DEFAULT_FILE_PERMISSIONS)
            .expect("create bystander");

        fs.write_file("/victim.dat", 0, b"original")
            .expect("write original");
        fs.write_file("/bystander.dat", 0, b"untouched")
            .expect("write bystander");

        // Overwrite the victim.
        fs.write_file("/victim.dat", 0, b"replaced!")
            .expect("overwrite victim");

        fs.sync_all().expect("sync all");
    }

    {
        let fs = open_fs(&dir);
        assert_eq!(
            fs.read_file("/victim.dat").expect("read victim"),
            b"replaced!"
        );
        assert_eq!(
            fs.read_file("/bystander.dat").expect("read bystander"),
            b"untouched"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Group 5: Large-write extent spanning
// ═══════════════════════════════════════════════════════════════════

/// Write enough data to span multiple extents (128 KiB), verify all
/// extents are allocated and data survives round-trip.
#[test]
fn large_write_extent_spanning_roundtrip() {
    set_test_key();
    let dir = temp_dir("large_extent");

    let payload: Vec<u8> = (0..128u8).cycle().take(128 * 1024).collect();

    {
        let mut fs = open_fs(&dir);
        let record = fs
            .create_file("/big.dat", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");

        fs.write_file("/big.dat", 0, &payload)
            .expect("write large data");

        // Check that extents were allocated for the write.
        let extents = fs.lookup_extents(record.inode_id.0, 0, payload.len() as u64);
        assert!(
            !extents.is_empty(),
            "extent allocator should have entries after write"
        );

        // Every extent should cover some portion of the write.
        let total_covered: u64 = extents.iter().map(|e| e.length).sum();
        assert!(
            total_covered >= payload.len() as u64,
            "extents should cover at least the written range, got {} covering {}",
            extents.len(),
            total_covered,
        );

        fs.sync_all().expect("sync all");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/big.dat").expect("read large file");
        assert_eq!(data.len(), payload.len(), "size mismatch");
        assert_eq!(data, payload, "large data byte-for-byte mismatch");
    }
}

/// Write to a file at a high offset, causing a sparse file with
/// extent spanning across a hole.
#[test]
fn large_write_extent_with_hole() {
    set_test_key();
    let dir = temp_dir("large_hole");

    let block_size = 65536u64; // 64 KiB blocks
    let first = vec![0x11u8; block_size as usize];
    let second = vec![0x22u8; block_size as usize];

    {
        let mut fs = open_fs(&dir);
        let record = fs
            .create_file("/sparse.dat", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");

        // Write at offset 0 and offset 256K (leaving 192K hole).
        fs.write_file("/sparse.dat", 0, &first)
            .expect("write first block");
        fs.write_file("/sparse.dat", block_size * 4, &second)
            .expect("write second block");

        // Both written regions should have extents.
        let extents = fs.lookup_extents(record.inode_id.0, 0, block_size * 4 + block_size);
        assert!(
            extents.len() >= 2,
            "two disjoint writes should allocate at least 2 extents, got {}",
            extents.len()
        );

        fs.sync_all().expect("sync all");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/sparse.dat").expect("read sparse file");

        let expected_len = (block_size * 5) as usize; // offset 256K + 64K data
        assert_eq!(data.len(), expected_len, "sparse file size mismatch");

        // First block.
        assert_eq!(
            &data[0..block_size as usize],
            &first[..],
            "first block mismatch"
        );

        // Hole region (all zeros).
        let hole_region = &data[block_size as usize..(block_size * 4) as usize];
        assert!(
            hole_region.iter().all(|&b| b == 0),
            "hole region should be zeros"
        );

        // Second block.
        let second_start = (block_size * 4) as usize;
        assert_eq!(
            &data[second_start..second_start + block_size as usize],
            &second[..],
            "second block mismatch"
        );
    }
}

/// Write overlapping ranges that require extent splitting/merging,
/// then verify the full file is correct.
#[test]
fn large_write_extent_overlapping_writes() {
    set_test_key();
    let dir = temp_dir("large_overlap");

    let mut fs = open_fs(&dir);
    fs.create_file("/overlap.dat", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");

    // Write data across multiple non-overlapping regions.
    let block_a = vec![0xAAu8; 4096];
    let block_b = vec![0xBBu8; 4096];
    let block_c = vec![0xCCu8; 4096];

    fs.write_file("/overlap.dat", 0, &block_a)
        .expect("write block A");
    fs.write_file("/overlap.dat", 8192, &block_b)
        .expect("write block B");
    fs.write_file("/overlap.dat", 16384, &block_c)
        .expect("write block C");

    // Overwrite a portion of block A with different data.
    let overlay = vec![0x11u8; 2048];
    fs.write_file("/overlap.dat", 1024, &overlay)
        .expect("overlay write");

    fs.sync_all().expect("sync all");
    drop(fs);

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/overlap.dat").expect("read overlap file");

        // File should span from 0 to max(16384+4096, 4096) = 20480.
        assert_eq!(data.len(), 20480, "file size mismatch");

        // First 1024 bytes: block_a prefix.
        assert_eq!(&data[0..1024], &block_a[..1024], "prefix mismatch");
        // 1024..3072: overlay.
        assert_eq!(&data[1024..3072], &overlay[..], "overlay mismatch");
        // 3072..4096: block_a suffix (bytes after the overlay).
        assert_eq!(
            &data[3072..4096],
            &block_a[3072..4096],
            "block_a suffix mismatch"
        );
        // 4096..8192: hole (zeros).
        assert!(
            data[4096..8192].iter().all(|&b| b == 0),
            "hole should be zeros"
        );
        // 8192..12288: block_b.
        assert_eq!(&data[8192..12288], &block_b[..], "block B mismatch");
        // 12288..16384: hole (zeros).
        assert!(
            data[12288..16384].iter().all(|&b| b == 0),
            "second hole should be zeros"
        );
        // 16384..20480: block_c.
        assert_eq!(&data[16384..20480], &block_c[..], "block C mismatch");
    }
}

// ═══════════════════════════════════════════════════════════════════
// End-to-end pipeline synopsis test
// ═══════════════════════════════════════════════════════════════════

/// A single test that exercises the full pipeline: create, write,
/// flush, drop/reopen, and verify.
#[test]
fn end_to_end_writeback_pipeline_crash_recovery() {
    set_test_key();
    let dir = temp_dir("e2e_pipeline");

    // Phase 1: Write committed data.
    let committed_payload = b"pipeline-committed-data";
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/pipeline.dat", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.write_file("/pipeline.dat", 0, committed_payload)
            .expect("write committed");

        // Verify data is readable from the live filesystem.
        let data = fs.read_file("/pipeline.dat").expect("read file");
        assert_eq!(data, committed_payload);

        fs.sync_all().expect("sync committed");
    }

    // Phase 2: simulate an abrupt stop with an uncommitted handle. A normal
    // Drop is best-effort and commits dirty write buffers.
    let mut fs = open_fs(&dir);
    fs.set_auto_commit(false);
    fs.set_max_uncommitted_mutations(1_000_000);

    // Write uncommitted data (will be lost on crash).
    fs.write_file("/pipeline.dat", committed_payload.len() as u64, b"-lost")
        .expect("write uncommitted");
    std::mem::forget(fs);

    // Phase 3: Recover and verify.
    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/pipeline.dat").expect("read pipeline file");
        assert_eq!(
            data, committed_payload,
            "only committed data should survive crash"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Stress: many files, many writes
// ═══════════════════════════════════════════════════════════════════

/// Create and write 20 files in a loop; reopen and verify all survive.
#[test]
fn stress_many_files_roundtrip() {
    set_test_key();
    let dir = temp_dir("stress_many");

    let file_count = 20;
    {
        let mut fs = open_fs(&dir);
        for i in 0..file_count {
            let path = format!("/file_{i:02}.dat");
            fs.create_file(&path, DEFAULT_FILE_PERMISSIONS)
                .expect("create file");
            let data = format!("data-for-file-{i:02}").into_bytes();
            fs.write_file(&path, 0, &data).expect("write file");
        }
        fs.sync_all().expect("sync all");
    }

    {
        let fs = open_fs(&dir);
        for i in 0..file_count {
            let path = format!("/file_{i:02}.dat");
            let expected = format!("data-for-file-{i:02}").into_bytes();
            let data = fs
                .read_file(&path)
                .unwrap_or_else(|e| panic!("read {path}: {e}"));
            assert_eq!(data, expected, "file {i} data mismatch");
        }
    }
}
