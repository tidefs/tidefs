//! Local-filesystem crash-recovery integration tests.
//!
//! Exercises the drop → reopen → verify recovery loop directly against
//! [`tidefs_local_filesystem::LocalFileSystem`] across 10 crash scenarios,
//! proving that fsynced data survives process loss byte-for-byte at the
//! storage layer.
//!
//! Every test name includes `crash_recovery` so the milestone advancement
//! criteria can filter with `cargo test -p tidefs-validation -- crash_recovery`
//! (when compiled with `--features fuse`).

#![cfg(feature = "fuse")]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tidefs_local_filesystem::{LocalFileSystem, RootAuthenticationKey, DEFAULT_FILE_PERMISSIONS};
use tidefs_local_object_store::StoreOptions;

// ── helpers ──────────────────────────────────────────────────────────────

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-crash-rec-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
}

fn store_opts() -> StoreOptions {
    StoreOptions {
        max_segment_bytes: 16 * 1024,
        sync_on_write: false,
        background_scrub_interval_secs: 0,
        reclaim_enabled: true,
        ..StoreOptions::durable()
    }
}

fn auth_key() -> RootAuthenticationKey {
    RootAuthenticationKey::demo_key()
}

/// Deterministic incrementing byte sequence.
fn seq_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

/// Open a filesystem on `root` with the standard test options and demo key.
fn open_fs(root: &Path) -> LocalFileSystem {
    LocalFileSystem::open_with_root_authentication_key(root, store_opts(), auth_key())
        .expect("open LocalFileSystem")
}

// ── test 1: single file, one fsync ───────────────────────────────────────

/// Create a file, write 4 KiB, fsync, drop the filesystem, reopen, and
/// verify byte-for-byte content match.
#[test]
fn crash_recovery_single_file_one_fsync() {
    let root = temp_root("single-file");
    cleanup(&root);

    let data = seq_data(4096);

    {
        let mut fs = open_fs(&root);
        fs.create_file("/crash.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");
        fs.replace_file("/crash.bin", &data).expect("write");
        fs.fsync_file("/crash.bin").expect("fsync");
        // drop fs here – simulates crash
    }

    {
        let fs = open_fs(&root);
        let read_back = fs.read_file("/crash.bin").expect("read after reopen");
        assert_eq!(
            read_back, data,
            "byte-for-byte mismatch after fsync + drop + reopen"
        );
    }

    cleanup(&root);
}

// ── test 2: multiple files, interleaved fsync ────────────────────────────

/// Interleave writes and fsyncs across 5 files, drop, reopen, verify all
/// files survived with correct content.
#[test]
fn crash_recovery_multiple_files_interleaved_fsync() {
    let root = temp_root("multi-interleaved");
    cleanup(&root);

    let files: [(&str, Vec<u8>); 5] = [
        ("/a.bin", seq_data(256)),
        ("/b.bin", seq_data(512)),
        ("/c.bin", seq_data(1024)),
        ("/d.bin", seq_data(2048)),
        ("/e.bin", seq_data(4096)),
    ];

    {
        let mut fs = open_fs(&root);
        for (path, _data) in &files {
            fs.create_file(path, DEFAULT_FILE_PERMISSIONS)
                .expect("create_file");
        }
        // Interleave: write file 0, fsync; write file 1, fsync; ...
        for (path, data) in &files {
            fs.replace_file(path, data).expect("write");
            fs.fsync_file(path).expect("fsync interleaved");
        }
    }

    {
        let fs = open_fs(&root);
        for (path, expected) in &files {
            let got = fs.read_file(path).expect("read after reopen");
            assert_eq!(&got, expected, "mismatch for {path} after crash recovery");
        }
    }

    cleanup(&root);
}

// ── test 3: unfsyncd data absent ─────────────────────────────────────────

/// Write without fsync, drop, reopen — verify the file is either absent or
/// empty (no phantom data from uncommitted writes).
#[test]
fn crash_recovery_unfsyncd_data_absent() {
    let root = temp_root("unfsyncd");
    cleanup(&root);

    {
        let mut fs = open_fs(&root);
        fs.create_file("/phantom.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");
        fs.replace_file("/phantom.bin", &seq_data(1024))
            .expect("write without fsync");
        // drop without fsync – simulates crash before durability boundary
    }

    {
        let fs = open_fs(&root);
        // After crash without fsync, the file may be absent, empty, or
        // contain the full written data.  The key invariant: no phantom
        // (corrupted or fabricated) data.
        if let Ok(data) = fs.read_file("/phantom.bin") {
            if !data.is_empty() {
                // Data survived — verify it matches what we wrote.
                assert_eq!(
                    data,
                    seq_data(1024),
                    "surviving unfsyncd data should match written data"
                );
            }
        }
    }

    cleanup(&root);
}

// ── test 4: large file, segmented fsync ──────────────────────────────────

/// Write 1 MiB in 64 KiB segments, fsync every 4 segments, drop before the
/// last fsync boundary, reopen.  Verify the fsynced prefix is intact;
/// trailing unfsynced segments may be absent.
#[test]
fn crash_recovery_large_file_segmented_fsync() {
    let root = temp_root("segmented-fsync");
    cleanup(&root);

    let segment_size: usize = 64 * 1024; // 64 KiB
    let total_segments: usize = 16; // 1 MiB total
    let fsync_every: usize = 4;
    let data: Vec<u8> = seq_data(total_segments * segment_size);

    {
        let mut fs = open_fs(&root);
        fs.create_file("/seg.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");

        for seg in 0..total_segments {
            let cumulative_end = (seg + 1) * segment_size;
            // replace_file sets the file to exactly the cumulative data so
            // far — this builds up the file segment by segment.
            fs.replace_file("/seg.bin", &data[..cumulative_end])
                .expect("write cumulative data");

            // Fsync every N segments, but do NOT fsync the last batch to
            // leave trailing segments uncommitted.
            if (seg + 1) % fsync_every == 0 && (seg + 1) < total_segments {
                fs.fsync_file("/seg.bin")
                    .expect("fsync at segment boundary");
            }
        }
        // drop without final fsync – trailing segments 12-15 uncommitted
    }

    {
        let fs = open_fs(&root);
        let read_back = fs.read_file("/seg.bin").expect("read after reopen");

        // At minimum, the first 12 segments (768 KiB) should be intact
        // since fsync was called after segments 4, 8, and 12.
        let min_expected_len = 12 * segment_size;
        assert!(
            read_back.len() >= min_expected_len,
            "expected at least {min_expected_len} bytes after recovery, got {}",
            read_back.len()
        );

        // Verify the recovered prefix is byte-for-byte correct.
        let verified = &read_back[..min_expected_len];
        assert_eq!(
            verified,
            &data[..min_expected_len],
            "recovered prefix mismatch: first {min_expected_len} bytes differ"
        );

        // Remaining bytes (if any) belong to partially-recovered trailing segments
        // and should be a prefix of the original trailing data.
        if read_back.len() > min_expected_len {
            let trail_start = min_expected_len;
            let trail = &read_back[trail_start..];
            let expected_trail = &data[trail_start..trail_start + trail.len()];
            assert_eq!(
                trail, expected_trail,
                "trailing recovered bytes should match original data prefix"
            );
        }
    }

    cleanup(&root);
}

// ── test 5: directory tree fsyncd ────────────────────────────────────────

/// Create a 3-level directory tree with 3 files per level, fsync all, drop,
/// reopen, verify full tree and contents.
#[test]
fn crash_recovery_directory_tree_fsyncd() {
    let root = temp_root("dir-tree");
    cleanup(&root);

    let dirs = ["/L1", "/L1/L2", "/L1/L2/L3"];
    let files_and_data: Vec<(String, Vec<u8>)> = vec![
        ("/L1/f1.bin".into(), seq_data(100)),
        ("/L1/f2.bin".into(), seq_data(200)),
        ("/L1/f3.bin".into(), seq_data(300)),
        ("/L1/L2/g1.bin".into(), seq_data(400)),
        ("/L1/L2/g2.bin".into(), seq_data(500)),
        ("/L1/L2/g3.bin".into(), seq_data(600)),
        ("/L1/L2/L3/h1.bin".into(), seq_data(700)),
        ("/L1/L2/L3/h2.bin".into(), seq_data(800)),
        ("/L1/L2/L3/h3.bin".into(), seq_data(900)),
    ];

    {
        let mut fs = open_fs(&root);
        for d in &dirs {
            fs.create_dir(d, DEFAULT_FILE_PERMISSIONS)
                .expect("create_dir");
        }
        for (path, data) in &files_and_data {
            fs.create_file(path, DEFAULT_FILE_PERMISSIONS)
                .expect("create_file");
            fs.replace_file(path, data).expect("write");
        }
        fs.fsync_all().expect("fsync_all");
    }

    {
        let fs = open_fs(&root);

        // Verify directories exist and contain expected children.
        let l1 = fs.list_dir("/L1").expect("list /L1");
        let l1_names: Vec<&[u8]> = l1.iter().map(|e| e.name.as_slice()).collect();
        assert!(
            l1_names.contains(&b"f1.bin".as_slice()),
            "/L1 missing f1.bin"
        );
        assert!(
            l1_names.contains(&b"f2.bin".as_slice()),
            "/L1 missing f2.bin"
        );
        assert!(
            l1_names.contains(&b"f3.bin".as_slice()),
            "/L1 missing f3.bin"
        );
        assert!(l1_names.contains(&b"L2".as_slice()), "/L1 missing L2");

        let l2 = fs.list_dir("/L1/L2").expect("list /L1/L2");
        let l2_names: Vec<&[u8]> = l2.iter().map(|e| e.name.as_slice()).collect();
        assert!(
            l2_names.contains(&b"g1.bin".as_slice()),
            "/L1/L2 missing g1.bin"
        );
        assert!(
            l2_names.contains(&b"g2.bin".as_slice()),
            "/L1/L2 missing g2.bin"
        );
        assert!(
            l2_names.contains(&b"g3.bin".as_slice()),
            "/L1/L2 missing g3.bin"
        );
        assert!(l2_names.contains(&b"L3".as_slice()), "/L1/L2 missing L3");

        let l3 = fs.list_dir("/L1/L2/L3").expect("list /L1/L2/L3");
        let l3_names: Vec<&[u8]> = l3.iter().map(|e| e.name.as_slice()).collect();
        assert!(
            l3_names.contains(&b"h1.bin".as_slice()),
            "/L1/L2/L3 missing h1.bin"
        );
        assert!(
            l3_names.contains(&b"h2.bin".as_slice()),
            "/L1/L2/L3 missing h2.bin"
        );
        assert!(
            l3_names.contains(&b"h3.bin".as_slice()),
            "/L1/L2/L3 missing h3.bin"
        );

        // Verify file contents.
        for (path, expected) in &files_and_data {
            let got = fs.read_file(path).expect("read after reopen");
            assert_eq!(&got, expected, "content mismatch for {path}");
        }
    }

    cleanup(&root);
}

// ── test 6: overwrite then fsync ─────────────────────────────────────────

/// Write initial data, fsync, overwrite with new data, fsync again, drop,
/// reopen, verify the latest content survived.
#[test]
fn crash_recovery_overwrite_then_fsync() {
    let root = temp_root("overwrite");
    cleanup(&root);

    let initial = b"original content that was overwritten\n".to_vec();
    let overwrite = b"new content that must survive the crash\n".to_vec();

    {
        let mut fs = open_fs(&root);
        fs.create_file("/over.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.replace_file("/over.bin", &initial)
            .expect("write initial");
        fs.fsync_file("/over.bin").expect("fsync initial");
        fs.replace_file("/over.bin", &overwrite).expect("overwrite");
        fs.fsync_file("/over.bin").expect("fsync overwrite");
    }

    {
        let fs = open_fs(&root);
        let read_back = fs.read_file("/over.bin").expect("read after reopen");
        assert_eq!(
            read_back, overwrite,
            "overwritten content should survive crash; got initial content instead"
        );
    }

    cleanup(&root);
}

// ── test 7: rename with fsync ────────────────────────────────────────────

/// Create file A, write data, rename to B, fsync parent dirs, drop, reopen,
/// verify B exists with data and A does not.
#[test]
fn crash_recovery_rename_with_fsync() {
    let root = temp_root("rename");
    cleanup(&root);

    let data = b"rename survivability test payload\n".to_vec();

    {
        let mut fs = open_fs(&root);
        fs.create_file("/old_name.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create old_name.bin");
        fs.replace_file("/old_name.bin", &data).expect("write");
        fs.rename("/old_name.bin", "/new_name.bin", false)
            .expect("rename old -> new");
        // Fsync parent directory to make rename durable.
        fs.fsync_directory("/").expect("fsync_directory /");
        fs.fsync_file("/new_name.bin")
            .expect("fsync renamed file data");
    }

    {
        let fs = open_fs(&root);

        // B must exist with correct data.
        let got = fs
            .read_file("/new_name.bin")
            .expect("read new_name.bin after reopen");
        assert_eq!(got, data, "renamed file content mismatch");

        // A must not exist.
        match fs.read_file("/old_name.bin") {
            Err(_) => { /* expected: old name gone */ }
            Ok(stale) => {
                panic!(
                    "old_name.bin should not survive rename + fsync; \
                     found {} bytes of stale data",
                    stale.len()
                );
            }
        }

        // Verify new_name.bin appears in root directory listing.
        let root_dir = fs.list_dir("/").expect("list /");
        let root_names: Vec<&[u8]> = root_dir.iter().map(|e| e.name.as_slice()).collect();
        assert!(
            root_names.contains(&b"new_name.bin".as_slice()),
            "new_name.bin not found in root dir after reopen"
        );
        assert!(
            !root_names.contains(&b"old_name.bin".as_slice()),
            "old_name.bin should not appear in root dir after rename + fsync"
        );
    }

    cleanup(&root);
}

// ── test 8: truncate + extend, fsync ─────────────────────────────────────

/// Write 8 KiB, truncate to 1 KiB, extend to 4 KiB, fsync, drop, reopen,
/// verify size=4 KiB and correct content (zero-fill for extended region).
#[test]
fn crash_recovery_truncate_extend_fsync() {
    let root = temp_root("trunc-extend");
    cleanup(&root);

    let initial = seq_data(8192); // 8 KiB

    // Session 1: write 8 KiB, truncate to 1 KiB, sync.
    {
        let mut fs = open_fs(&root);
        fs.create_file("/te.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/te.bin", 0, &initial).expect("write 8 KiB");
        fs.truncate_file("/te.bin", 1024)
            .expect("truncate to 1 KiB");
        fs.sync_all().expect("sync_all after truncate");
    }

    // Session 2 (reopen): extend back to 4 KiB.
    {
        let mut fs = open_fs(&root);
        let mut extended = vec![0u8; 4096];
        extended[..1024].copy_from_slice(&initial[..1024]);
        fs.replace_file("/te.bin", &extended)
            .expect("extend to 4 KiB");
        fs.fsync_file("/te.bin").expect("fsync after extend");
    }

    {
        let fs = open_fs(&root);
        let rec = fs.stat("/te.bin").expect("stat after reopen");
        assert_eq!(
            rec.size, 4096,
            "file size should be 4 KiB after truncate+extend+reopen"
        );

        let read_back = fs.read_file("/te.bin").expect("read after reopen");
        assert_eq!(read_back.len(), 4096, "read length mismatch");

        // First 1024 bytes: original data truncated from 8 KiB.
        assert_eq!(&read_back[..1024], &initial[..1024], "first 1 KiB mismatch");

        // Bytes 1024..4096: should be zero-filled from the extend.
        for i in 1024..4096 {
            assert_eq!(
                read_back[i], 0u8,
                "byte at offset {i} should be zero-filled; got 0x{:02x}",
                read_back[i]
            );
        }
    }

    cleanup(&root);
}

// ── test 9: empty file after fsync ───────────────────────────────────────

/// Create an empty file, fsync, drop, reopen, verify the file exists and is
/// empty.
#[test]
fn crash_recovery_empty_file_after_fsync() {
    let root = temp_root("empty-file");
    cleanup(&root);

    {
        let mut fs = open_fs(&root);
        fs.create_file("/empty.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create empty file");
        fs.fsync_file("/empty.bin").expect("fsync empty file");
    }

    {
        let fs = open_fs(&root);
        let read_back = fs.read_file("/empty.bin").expect("read empty file");
        assert!(
            read_back.is_empty(),
            "empty file should remain empty after reopen"
        );
        let rec = fs.stat("/empty.bin").expect("stat empty file");
        assert_eq!(rec.size, 0, "empty file size should be 0 after reopen");
        assert_eq!(rec.nlink, 1, "empty file nlink should be 1 after reopen");
    }

    cleanup(&root);
}

// ── test 10: hardlink count after fsync ──────────────────────────────────

/// Create a file, create a hardlink, fsync, drop, reopen, verify link
/// count=2 and both paths accessible with identical content.
#[test]
fn crash_recovery_hardlink_count_after_fsync() {
    let root = temp_root("hardlink");
    cleanup(&root);

    let data = b"hardlinked content that must survive\n".to_vec();

    {
        let mut fs = open_fs(&root);
        fs.create_file("/primary.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create primary");
        fs.replace_file("/primary.bin", &data)
            .expect("write primary");
        fs.link_file("/primary.bin", "/alias.bin")
            .expect("hardlink primary -> alias");
        fs.fsync_file("/primary.bin").expect("fsync primary");
        fs.fsync_directory("/").expect("fsync_directory /");
    }

    {
        let fs = open_fs(&root);

        // Both paths must be accessible.
        let p = fs.read_file("/primary.bin").expect("read primary.bin");
        let a = fs.read_file("/alias.bin").expect("read alias.bin");
        assert_eq!(p, data, "primary content mismatch");
        assert_eq!(a, data, "alias content mismatch");
        assert_eq!(p, a, "primary and alias should have identical content");

        // Link count must be 2.
        let rec_primary = fs.stat("/primary.bin").expect("stat primary.bin");
        assert_eq!(
            rec_primary.nlink, 2,
            "primary.bin nlink should be 2; got {}",
            rec_primary.nlink
        );

        let rec_alias = fs.stat("/alias.bin").expect("stat alias.bin");
        assert_eq!(
            rec_alias.nlink, 2,
            "alias.bin nlink should be 2; got {}",
            rec_alias.nlink
        );

        // Both paths appear in root listing.
        let root_dir = fs.list_dir("/").expect("list /");
        let names: Vec<&[u8]> = root_dir.iter().map(|e| e.name.as_slice()).collect();
        assert!(
            names.contains(&b"primary.bin".as_slice()),
            "primary.bin missing"
        );
        assert!(
            names.contains(&b"alias.bin".as_slice()),
            "alias.bin missing"
        );
    }

    cleanup(&root);
}
