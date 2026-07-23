// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Write→read-back integration tests for the local-filesystem layer.
//!
//! Exercises the core data path: create → write → sync → reopen → verify
//! with targeted coverage for single-page writes, sub-page partial writes,
//! append patterns, overwrite integrity, extent allocation, crash resilience,
//! and delete semantics. Uses a reusable TestHarness fixture.
//!
//! These tests validate the foundation that FUSE dispatch batches build on:
//! extent-map allocation, object-store persistence, and read-back resolution.

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};

const PAGE_SIZE: usize = 4096;

// ── Helpers ───────────────────────────────────────────────────────────────

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("tidefs-wri-{label}-{ts}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn open_fs(dir: &std::path::Path) -> LocalFileSystem {
    LocalFileSystem::open(dir).expect("open filesystem")
}

fn make_pattern_page(seed: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PAGE_SIZE);
    let mut val = seed;
    for _ in 0..PAGE_SIZE {
        buf.push(val);
        val = val.wrapping_add(1);
    }
    buf
}

fn make_data(seed: u8, len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    let mut val = seed;
    for _ in 0..len {
        buf.push(val);
        val = val.wrapping_add(1);
    }
    buf
}

// ── 1. Single-page write round-trip ───────────────────────────────────────

#[test]
fn single_page_write_readback_exact_match() {
    set_test_key();
    let dir = temp_dir("single_page_exact");
    let payload = make_pattern_page(0xAB);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/page.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/page.bin", 0, &payload).expect("write");
        assert_eq!(fs.stat("/page.bin").unwrap().size, PAGE_SIZE as u64);
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/page.bin").expect("read");
        assert_eq!(data.len(), PAGE_SIZE);
        assert_eq!(data, payload, "every byte must match after remount");
    }
}

#[test]
fn single_page_write_readback_range() {
    set_test_key();
    let dir = temp_dir("single_page_range");
    let payload = make_pattern_page(0x42);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/range.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/range.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let middle = fs
            .read_file_range("/range.bin", 1024, 512)
            .expect("read range");
        assert_eq!(middle.len(), 512);
        assert_eq!(middle, &payload[1024..1536]);

        let last = fs
            .read_file_range("/range.bin", (PAGE_SIZE - 1) as u64, 1)
            .expect("read last");
        assert_eq!(last.len(), 1);
        assert_eq!(last[0], payload[PAGE_SIZE - 1]);
    }
}

// ── 2. Sub-page partial write at non-zero offset ──────────────────────────

#[test]
fn sub_page_write_at_nonzero_offset_zero_fill() {
    set_test_key();
    let dir = temp_dir("subpage_nonzero");
    let sub_data = make_data(0x77, 512);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/subpage.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/subpage.bin", 1024, &sub_data)
            .expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/subpage.bin").expect("read");
        assert_eq!(data.len(), 1536);
        assert!(data[0..1024].iter().all(|&b| b == 0));
        assert_eq!(&data[1024..1536], &sub_data[..]);
    }
}

#[test]
fn sub_page_write_within_page() {
    set_test_key();
    let dir = temp_dir("subpage_edge");
    let sub = make_data(0x33, 256);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/edge.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/edge.bin", 3840, &sub).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/edge.bin").expect("read");
        assert_eq!(data.len(), 4096);
        assert!(data[0..3840].iter().all(|&b| b == 0));
        assert_eq!(&data[3840..4096], &sub[..]);
    }
}

#[test]
fn sub_page_write_crossing_page_boundary() {
    set_test_key();
    let dir = temp_dir("subpage_cross");
    let sub = make_data(0x55, 512);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/cross.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/cross.bin", 3840, &sub).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/cross.bin").expect("read");
        assert_eq!(data.len(), 4352);
        assert!(data[0..3840].iter().all(|&b| b == 0));
        assert_eq!(&data[3840..4352], &sub[..]);
    }
}

// ── 3. Append write pattern ───────────────────────────────────────────────

#[test]
fn append_write_concatenates_correctly() {
    set_test_key();
    let dir = temp_dir("append");
    let first = make_data(0x11, 1024);
    let second = make_data(0x22, 2048);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/append.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/append.bin", 0, &first).expect("write 1");
        fs.write_file("/append.bin", first.len() as u64, &second)
            .expect("write 2");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/append.bin").expect("read");
        assert_eq!(data.len(), first.len() + second.len());
        assert_eq!(&data[..first.len()], &first[..]);
        assert_eq!(&data[first.len()..], &second[..]);
    }
}

#[test]
fn append_write_with_gap_creates_sparse_hole() {
    set_test_key();
    let dir = temp_dir("append_gap");
    let initial = make_data(0xAA, 512);
    let appended = make_data(0xBB, 1024);
    let gap_start = 4096u64;

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/sparse_append.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/sparse_append.bin", 0, &initial)
            .expect("write 1");
        fs.write_file("/sparse_append.bin", gap_start, &appended)
            .expect("write 2");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/sparse_append.bin").expect("read");
        assert_eq!(data.len(), (gap_start + appended.len() as u64) as usize);
        assert_eq!(&data[..initial.len()], &initial[..]);
        assert!(data[initial.len()..gap_start as usize]
            .iter()
            .all(|&b| b == 0));
        assert_eq!(
            &data[gap_start as usize..gap_start as usize + appended.len()],
            &appended[..]
        );
    }
}

// ── 4. Overwrite mid-file integrity ───────────────────────────────────────

#[test]
fn overwrite_mid_file_preserves_surrounding_data() {
    set_test_key();
    let dir = temp_dir("overwrite_mid");
    let original = make_data(0x10, 4096);
    let overlay = make_data(0xFE, 512);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/overwrite.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/overwrite.bin", 0, &original)
            .expect("write");
        fs.write_file("/overwrite.bin", 1024, &overlay)
            .expect("overwrite");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/overwrite.bin").expect("read");
        assert_eq!(data.len(), 4096, "file size unchanged after overwrite");
        assert_eq!(&data[0..1024], &original[0..1024], "prefix intact");
        assert_eq!(&data[1024..1536], &overlay[..], "overwritten region");
        assert_eq!(&data[1536..4096], &original[1536..4096], "suffix intact");
    }
}

#[test]
fn overwrite_at_end_extends_file() {
    set_test_key();
    let dir = temp_dir("overwrite_end");
    let original = make_data(0x30, 1024);
    let overlay = make_data(0x40, 1024);
    let expected_size = 512 + 1024;

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/extend.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/extend.bin", 0, &original).expect("write");
        fs.write_file("/extend.bin", 512, &overlay)
            .expect("overwrite");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/extend.bin").expect("read");
        assert_eq!(data.len(), expected_size);
        assert_eq!(&data[0..512], &original[0..512]);
        assert_eq!(&data[512..expected_size], &overlay[..]);
    }
}

// ── 5. Extent allocation on overwrite ─────────────────────────────────────

#[test]
fn overwrite_within_existing_region_preserves_data_integrity() {
    set_test_key();
    let dir = temp_dir("extent_overwrite");
    let page = make_pattern_page(0x01);
    let overlay = make_data(0xFF, 256);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/reuse.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/reuse.bin", 0, &page).expect("write");

        // Verify extents exist after initial write.
        let ino = fs.lookup("/reuse.bin").unwrap().get();
        let ext_count_before = fs.lookup_extents(ino, 0, u64::MAX).len();
        assert!(
            ext_count_before >= 1,
            "at least one extent after initial write"
        );

        fs.write_file("/reuse.bin", 2048, &overlay)
            .expect("overwrite");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/reuse.bin").expect("read");
        assert_eq!(data.len(), PAGE_SIZE);
        assert_eq!(&data[0..2048], &page[0..2048], "prefix intact");
        assert_eq!(&data[2048..2304], &overlay[..], "overwritten region");
        assert_eq!(
            &data[2304..PAGE_SIZE],
            &page[2304..PAGE_SIZE],
            "suffix intact"
        );
    }
}

// ── 6. Crash resilience ───────────────────────────────────────────────────

/// Drop safety-net commits uncommitted write-buffer data.
///
/// When auto-commit is disabled, write_file buffers data without
/// committing.  Drop's best-effort do_commit() persists the buffered
/// data as a safety net, so the data survives a clean shutdown even
/// without an explicit commit.  This is a safety net, not a crash
/// simulation: real crashes that skip Drop do lose uncommitted data,
/// but the test harness cannot skip Drop.
///
/// True crash-safety coverage belongs in the crash-injection matrix.
#[test]
#[ignore = "Drop commits uncommitted write-buffer data (pre-existing safety-net behaviour); use crash-injection matrix for true crash tests"]
fn crash_before_commit_loses_uncommitted_data() {
    set_test_key();
    let dir = temp_dir("crash_no_commit");
    let committed = make_data(0xCA, 1024);

    // Phase 1: write and sync committed data.
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/crash.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/crash.bin", 0, &committed).expect("write");
        fs.sync_all().expect("sync");
    }

    // Phase 2: reopen, disable auto-commit, write uncommitted data, drop (crash).
    {
        let mut fs = open_fs(&dir);
        assert_eq!(fs.read_file("/crash.bin").unwrap(), committed);
        fs.set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        let uncommitted = make_data(0xFE, 2048);
        fs.write_file("/crash.bin", 0, &uncommitted)
            .expect("write uncommitted");
        assert_eq!(fs.read_file("/crash.bin").unwrap(), uncommitted);
        // Drop without commit = crash.
    }

    // Phase 3: reopen, only committed data should survive.
    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/crash.bin").expect("read after crash");
        assert_eq!(data, committed, "unsynced write lost after crash");
    }
}

#[test]
fn crash_after_sync_preserves_all_data() {
    set_test_key();
    let dir = temp_dir("crash_after_sync");
    let payload = make_data(0xDA, 4096);
    let more = make_data(0xDB, 1024);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/safe.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/safe.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let mut fs = open_fs(&dir);
        fs.write_file("/safe.bin", 4096, &more).expect("write more");
        fs.sync_all().expect("sync before crash");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/safe.bin").expect("read");
        assert_eq!(data.len(), 4096 + 1024);
        assert_eq!(&data[0..4096], &payload[..]);
        assert_eq!(&data[4096..5120], &more[..]);
    }
}

// ── 7. Delete semantics ───────────────────────────────────────────────────

#[test]
fn unlink_removes_file_from_listing() {
    set_test_key();
    let dir = temp_dir("unlink_listing");

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/tmp_file.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/tmp_file.txt", 0, b"temp").expect("write");
        fs.sync_all().expect("sync");

        let before = fs.list_dir("/").expect("list");
        assert!(before.iter().any(|e| e.name_lossy() == "tmp_file.txt"));

        fs.unlink("/tmp_file.txt").expect("unlink");
        fs.sync_all().expect("sync after unlink");

        let after = fs.list_dir("/").expect("list after");
        assert!(!after.iter().any(|e| e.name_lossy() == "tmp_file.txt"));
    }

    // Reopen to verify deletion survived.
    {
        let fs = open_fs(&dir);
        let after_remount = fs.list_dir("/").expect("list after reopen");
        assert!(!after_remount
            .iter()
            .any(|e| e.name_lossy() == "tmp_file.txt"));
    }
}

#[test]
fn delete_then_recreate_same_name_is_independent_file() {
    set_test_key();
    let dir = temp_dir("delete_recreate");

    let first_inode = {
        let mut fs = open_fs(&dir);
        fs.create_file("/reincarnate.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/reincarnate.bin", 0, b"first incarnation")
            .expect("write");
        let ino = fs.stat("/reincarnate.bin").unwrap().inode_id;
        fs.unlink("/reincarnate.bin").expect("unlink");
        fs.sync_all().expect("sync");
        ino
    };

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/reincarnate.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/reincarnate.bin", 0, b"second life")
            .expect("write");
        let second_inode = fs.stat("/reincarnate.bin").unwrap().inode_id;
        assert_ne!(first_inode, second_inode);
        assert_eq!(fs.read_file("/reincarnate.bin").unwrap(), b"second life");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        assert_eq!(fs.read_file("/reincarnate.bin").unwrap(), b"second life");
    }
}

// ── 8. Write at large offset (sparse file) ────────────────────────────────

#[test]
fn write_at_large_offset_creates_sparse_hole_with_zero_fill() {
    set_test_key();
    let dir = temp_dir("large_offset");
    let hole_size: u64 = 1024 * 1024;
    let data = make_data(0x99, 4096);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/sparse.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/sparse.bin", hole_size, &data)
            .expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let hole_prefix = fs
            .read_file_range("/sparse.bin", 0, 256)
            .expect("read hole");
        assert!(hole_prefix.iter().all(|&b| b == 0));

        let boundary = fs
            .read_file_range("/sparse.bin", hole_size - 4, 12)
            .expect("read boundary");
        assert_eq!(&boundary[0..4], &[0u8; 4]);
        assert_eq!(&boundary[4..12], &data[0..8]);
    }
}

// ── 9. Multi-page write ───────────────────────────────────────────────────

#[test]
fn multi_page_write_produces_contiguous_extent() {
    set_test_key();
    let dir = temp_dir("multi_page_extent");
    let payload = make_data(0x60, PAGE_SIZE * 3);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/big.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/big.bin", 0, &payload).expect("write");

        let ino = fs.lookup("/big.bin").unwrap().get();
        let ext_count = fs.lookup_extents(ino, 0, u64::MAX).len();
        assert_eq!(ext_count, 1, "contiguous multi-page write = 1 extent");

        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/big.bin").expect("read");
        assert_eq!(data.len(), PAGE_SIZE * 3);
        assert_eq!(data, payload);
    }
}

// ── 10. Non-contiguous writes ─────────────────────────────────────────────

#[test]
fn non_contiguous_writes_produce_two_extents_with_gap() {
    set_test_key();
    let dir = temp_dir("non_contiguous");
    let chunk_a = make_data(0xA0, PAGE_SIZE);
    let chunk_b = make_data(0xB0, PAGE_SIZE);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/disjoint.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/disjoint.bin", 0, &chunk_a)
            .expect("write a");
        fs.write_file("/disjoint.bin", PAGE_SIZE as u64 * 4, &chunk_b)
            .expect("write b");

        let ino = fs.lookup("/disjoint.bin").unwrap().get();
        let ext_count = fs.lookup_extents(ino, 0, u64::MAX).len();
        assert_eq!(ext_count, 2, "non-contiguous writes produce 2 extents");

        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/disjoint.bin").expect("read");
        let expected_size = PAGE_SIZE * 4 + PAGE_SIZE;
        assert_eq!(data.len(), expected_size);
        assert_eq!(&data[0..PAGE_SIZE], &chunk_a[..]);
        assert!(data[PAGE_SIZE..PAGE_SIZE * 4].iter().all(|&b| b == 0));
        assert_eq!(&data[PAGE_SIZE * 4..], &chunk_b[..]);
    }
}

// ── 11. Write zero bytes ──────────────────────────────────────────────────

#[test]
fn write_zero_bytes_is_noop() {
    set_test_key();
    let dir = temp_dir("zero_write");

    let mut fs = open_fs(&dir);
    fs.create_file("/zero.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    assert_eq!(fs.stat("/zero.bin").unwrap().size, 0);

    fs.write_file("/zero.bin", 0, &[]).expect("zero write");
    assert_eq!(fs.stat("/zero.bin").unwrap().size, 0);

    fs.write_file("/zero.bin", 1024, &[])
        .expect("zero write at offset");
    assert_eq!(fs.stat("/zero.bin").unwrap().size, 0);

    let ino = fs.lookup("/zero.bin").unwrap().get();
    let ext_count = fs.lookup_extents(ino, 0, u64::MAX).len();
    assert_eq!(ext_count, 0);
}

// ── 12. Truncate round-trip ───────────────────────────────────────────────

#[test]
fn truncate_shrink_then_read_back() {
    set_test_key();
    let dir = temp_dir("trunc_shrink");
    let original = make_data(0xE0, 4096);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/shrink.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/shrink.bin", 0, &original).expect("write");
        assert_eq!(fs.stat("/shrink.bin").unwrap().size, 4096);

        // Truncate from 4096 down to 1024.
        fs.truncate_file("/shrink.bin", 1024)
            .expect("truncate to 1024");
        assert_eq!(fs.stat("/shrink.bin").unwrap().size, 1024);
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/shrink.bin").expect("read");
        assert_eq!(data.len(), 1024, "truncated file is 1024 bytes");
        assert_eq!(&data[..], &original[..1024], "first 1024 bytes intact");

        // Reading past EOF with range read returns partial data up to EOF.
        let partial = fs
            .read_file_range("/shrink.bin", 512, 1024)
            .expect("read past EOF on truncated file should succeed with partial data");
        assert_eq!(
            partial.len(),
            512,
            "past-EOF read returns data up to EOF: offset 512 on 1024-byte file => 512 bytes"
        );
    }
}

#[test]
fn truncate_expand_zero_fills_tail() {
    set_test_key();
    let dir = temp_dir("trunc_expand");
    let initial = make_data(0xD0, 1024);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/expand.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/expand.bin", 0, &initial).expect("write");

        // Truncate from 1024 up to 4096.
        fs.truncate_file("/expand.bin", 4096)
            .expect("truncate to 4096");
        assert_eq!(fs.stat("/expand.bin").unwrap().size, 4096);
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/expand.bin").expect("read");
        assert_eq!(data.len(), 4096);
        assert_eq!(&data[0..1024], &initial[..], "original data intact");
        assert!(
            data[1024..].iter().all(|&b| b == 0),
            "extended region must be zero-filled"
        );
    }
}

#[test]
fn truncate_expand_then_write_new_data() {
    set_test_key();
    let dir = temp_dir("trunc_expand_write");
    let initial = make_data(0xC0, 512);
    let more = make_data(0xC1, 512);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/grow.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/grow.bin", 0, &initial)
            .expect("write initial");

        // Extend via truncate.
        fs.truncate_file("/grow.bin", 4096)
            .expect("truncate up to 4096");

        // Write into the zero-filled tail.
        fs.write_file("/grow.bin", 2048, &more)
            .expect("write into tail");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/grow.bin").expect("read");
        assert_eq!(data.len(), 4096);
        assert_eq!(&data[0..512], &initial[..], "initial data intact");
        assert!(
            data[512..2048].iter().all(|&b| b == 0),
            "zero-filled between writes"
        );
        assert_eq!(&data[2048..2560], &more[..], "new data in tail");
        assert!(data[2560..].iter().all(|&b| b == 0), "remainder still zero");
    }
}

// ── 13. Punch hole and extent-map interaction ─────────────────────────────

#[test]
fn punch_hole_mid_file_returns_zeros_and_preserves_size() {
    set_test_key();
    let dir = temp_dir("punch_hole_mid");
    let original = make_data(0xB0, 4096);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/hole.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/hole.bin", 0, &original).expect("write");
        fs.punch_hole("/hole.bin", 1024, 2048)
            .expect("punch hole 1024..3072");

        // Size must be preserved (KEEP_SIZE).
        assert_eq!(fs.stat("/hole.bin").unwrap().size, 4096);
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/hole.bin").expect("read");
        assert_eq!(data.len(), 4096, "size preserved after punch hole");
        assert_eq!(&data[0..1024], &original[0..1024], "prefix intact");
        assert!(
            data[1024..3072].iter().all(|&b| b == 0),
            "punched region must be zero-filled"
        );
        assert_eq!(&data[3072..4096], &original[3072..4096], "suffix intact");
    }
}

#[test]
fn punch_hole_then_write_into_hole_restores_content() {
    set_test_key();
    let dir = temp_dir("punch_then_write");
    let original = make_data(0xA0, 4096);
    let new_data = make_data(0xA1, 512);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/ph_write.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/ph_write.bin", 0, &original).expect("write");

        // Punch a hole in the middle.
        fs.punch_hole("/ph_write.bin", 1024, 2048)
            .expect("punch hole");

        // Write new data into the hole region.
        fs.write_file("/ph_write.bin", 1536, &new_data)
            .expect("write into hole");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/ph_write.bin").expect("read");
        assert_eq!(data.len(), 4096);
        assert_eq!(&data[0..1024], &original[0..1024], "prefix before hole");
        assert!(
            data[1024..1536].iter().all(|&b| b == 0),
            "hole portion before write"
        );
        assert_eq!(
            &data[1536..2048],
            &new_data[..],
            "new data written into hole"
        );
        assert_eq!(&data[3072..4096], &original[3072..4096], "suffix intact");
    }
}

#[test]
fn punch_hole_at_beginning_returns_zeros() {
    set_test_key();
    let dir = temp_dir("punch_hole_begin");
    let original = make_data(0x90, 4096);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/ph_begin.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/ph_begin.bin", 0, &original).expect("write");
        fs.punch_hole("/ph_begin.bin", 0, 1024)
            .expect("punch hole at 0");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/ph_begin.bin").expect("read");
        assert_eq!(data.len(), 4096);
        assert!(data[0..1024].iter().all(|&b| b == 0), "punched prefix zero");
        assert_eq!(&data[1024..4096], &original[1024..4096], "tail intact");
    }
}

#[test]
fn punch_hole_at_end_returns_zeros() {
    set_test_key();
    let dir = temp_dir("punch_hole_end");
    let original = make_data(0x80, 4096);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/ph_end.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/ph_end.bin", 0, &original).expect("write");
        fs.punch_hole("/ph_end.bin", 3072, 1024)
            .expect("punch hole at end");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/ph_end.bin").expect("read");
        assert_eq!(data.len(), 4096);
        assert_eq!(&data[0..3072], &original[0..3072], "prefix intact");
        assert!(
            data[3072..4096].iter().all(|&b| b == 0),
            "punched tail zero"
        );
    }
}

#[test]
fn punch_hole_then_verify_gap_in_extent_map() {
    set_test_key();
    let dir = temp_dir("ph_extent_gap");

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/ph_ext.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/ph_ext.bin", 0, &make_data(0x70, 8192))
            .expect("write 8K");

        // Verify extents before punch.
        let ino = fs.lookup("/ph_ext.bin").unwrap().get();
        let ext_before = fs.lookup_extents(ino, 0, u64::MAX).len();
        assert!(ext_before >= 1, "at least one extent before punch");

        // Punch hole in the middle (4096..6144).
        fs.punch_hole("/ph_ext.bin", 4096, 2048)
            .expect("punch middle");

        // Extent count may change due to punch splitting or freeing extents.
        let ext_after = fs.lookup_extents(ino, 0, u64::MAX).len();
        assert!(ext_after >= 1, "at least one extent remains after punch");

        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/ph_ext.bin").expect("read");
        assert_eq!(data.len(), 8192);
        assert_eq!(&data[0..4096], &make_data(0x70, 4096)[..], "prefix intact");
        assert!(data[4096..6144].iter().all(|&b| b == 0), "hole is zeros");
        // Suffix data: bytes 6144..8192 should be the continuation of the original pattern.
        assert_eq!(
            &data[6144..8192],
            &make_data(0x70, 8192)[6144..8192],
            "suffix intact"
        );
    }
}

// ── 14. Object-store persistence (re-open against same store) ──────────────

#[test]
fn reopen_same_store_preserves_all_files_and_content() {
    set_test_key();
    let dir = temp_dir("reopen_store");

    // Phase 1: Write multiple files, sync, drop.
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/alpha.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create alpha");
        fs.write_file("/alpha.bin", 0, &make_data(0xAA, 2048))
            .expect("write alpha");

        fs.create_dir("/sub", DEFAULT_FILE_PERMISSIONS)
            .expect("mkdir sub");
        fs.create_file("/sub/beta.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create beta");
        fs.write_file("/sub/beta.bin", 0, &make_data(0xBB, 1024))
            .expect("write beta");

        fs.sync_all().expect("sync");
    }

    // Phase 2: Reopen and verify content. Use multiple reopen cycles.
    for _cycle in 0..3 {
        let fs = open_fs(&dir);

        let alpha = fs.read_file("/alpha.bin").expect("read alpha");
        assert_eq!(alpha.len(), 2048);
        assert_eq!(alpha, make_data(0xAA, 2048));

        let beta = fs.read_file("/sub/beta.bin").expect("read beta");
        assert_eq!(beta.len(), 1024);
        assert_eq!(beta, make_data(0xBB, 1024));

        // Verify directory listing.
        let root_list = fs.list_dir("/").expect("list /");
        let names: Vec<String> = root_list.iter().map(|e| e.name_lossy()).collect();
        assert!(names.contains(&"alpha.bin".to_string()));
        assert!(names.contains(&"sub".to_string()));
    }
}

#[test]
fn reopen_same_store_preserves_sparse_file_layout() {
    set_test_key();
    let dir = temp_dir("reopen_sparse");

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/sparse.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        // Write only at beginnings and ends of pages 0, 2, and 4.
        fs.write_file("/sparse.bin", 0, &make_data(0x10, 256))
            .expect("write p0");
        fs.write_file("/sparse.bin", PAGE_SIZE as u64 * 2, &make_data(0x20, 256))
            .expect("write p2");
        fs.write_file("/sparse.bin", PAGE_SIZE as u64 * 4, &make_data(0x30, 256))
            .expect("write p4");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/sparse.bin").expect("read");
        let expected_size = PAGE_SIZE * 4 + 256;
        assert_eq!(data.len(), expected_size);

        assert_eq!(&data[0..256], &make_data(0x10, 256)[..], "page 0 head");
        assert!(
            data[256..PAGE_SIZE].iter().all(|&b| b == 0),
            "page 0 tail zeros"
        );

        assert!(
            data[PAGE_SIZE..PAGE_SIZE * 2].iter().all(|&b| b == 0),
            "page 1 zeros"
        );
        assert_eq!(
            &data[PAGE_SIZE * 2..PAGE_SIZE * 2 + 256],
            &make_data(0x20, 256)[..],
            "page 2 head"
        );

        assert!(
            data[PAGE_SIZE * 3..PAGE_SIZE * 4].iter().all(|&b| b == 0),
            "page 3 zeros"
        );
        assert_eq!(
            &data[PAGE_SIZE * 4..PAGE_SIZE * 4 + 256],
            &make_data(0x30, 256)[..],
            "page 4 head"
        );
    }
}

// ── 15. Read from empty file ──────────────────────────────────────────────

#[test]
fn read_empty_file_returns_zero_bytes() {
    set_test_key();
    let dir = temp_dir("read_empty");

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/empty.dat", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/empty.dat").expect("read empty");
        assert!(data.is_empty(), "empty file read must return 0 bytes");

        let stat = fs.stat("/empty.dat").expect("stat empty");
        assert_eq!(stat.size, 0, "empty file size is 0");
    }
}

// ── 16. Replace file content ──────────────────────────────────────────────

#[test]
fn replace_file_content_then_read_back() {
    set_test_key();
    let dir = temp_dir("replace_file");
    let initial = make_data(0xF0, 1024);
    let replacement = make_data(0xF1, 2048);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/replace.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/replace.bin", 0, &initial)
            .expect("write initial");
        fs.sync_all().expect("sync");
    }

    {
        let mut fs = open_fs(&dir);
        assert_eq!(fs.read_file("/replace.bin").unwrap(), initial);

        // Replace the entire file content.
        fs.replace_file("/replace.bin", &replacement)
            .expect("replace");
        assert_eq!(fs.stat("/replace.bin").unwrap().size, 2048);
        assert_eq!(fs.read_file("/replace.bin").unwrap(), replacement);
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let data = fs.read_file("/replace.bin").expect("read after reopen");
        assert_eq!(data.len(), 2048);
        assert_eq!(data, replacement);
    }
}
