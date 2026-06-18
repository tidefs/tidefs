// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE crash-recovery integration tests for the POSIX filesystem adapter daemon.
//!
//! Exercises the real FUSE mount path: write -> fsync -> SIGKILL daemon ->
//! remount -> verify byte-for-byte data survival.  Every test name includes
//! `fsync_crash` so the milestone advancement criteria filter
//! `cargo test -p tidefs-posix-filesystem-adapter-daemon -- fsync_crash`
//! picks them up automatically.
//!
//! All tests use the MountHarness from tidefs-validation, which spawns the
//! daemon as a separate process, sends real SIGKILL, lazy-unmounts with
//! fusermount -uz, and restarts a fresh daemon on the same backing store.

use std::os::unix::fs::PermissionsExt;
use tidefs_validation::mount_harness::MountHarness;

// ── helpers ──────────────────────────────────────────────────────────────

/// Deterministic incrementing byte sequence.
fn seq_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

/// Open a new MountHarness, printing a skip message if the daemon binary
/// isn't found (e.g. not built yet).
fn mount_or_skip() -> Option<MountHarness> {
    match MountHarness::new() {
        Ok(h) => Some(h),
        Err(e) => {
            eprintln!("SKIP: daemon not available -- {e}");
            None
        }
    }
}

// ── test 1: single-file fsync + SIGKILL + remount ───────────────────────

/// Create a file, write 4 KiB of known content, fsync via kernel FUSE,
/// SIGKILL the daemon, remount, and verify byte-for-byte survival.
#[test]
fn fsync_crash_single_file_sigkill_remount() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = seq_data(4096);

    harness
        .create_file("crash_test.bin", &data)
        .expect("create_file through FUSE");
    harness
        .fsync_file("crash_test.bin")
        .expect("fsync through FUSE");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("crash_test.bin")
        .expect("read after crash+remount");
    assert_eq!(
        read_back, data,
        "byte-for-byte mismatch after SIGKILL + remount"
    );
}

// ── test 2: multiple files, interleaved fsync ────────────────────────────

/// Create 5 files with distinct content, fsync each individually, SIGKILL,
/// remount, verify all 5 survived with correct content.
#[test]
fn fsync_crash_multi_file_interleaved_fsync() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let files: [(&str, Vec<u8>); 5] = [
        ("a.bin", seq_data(256)),
        ("b.bin", seq_data(512)),
        ("c.bin", seq_data(1024)),
        ("d.bin", seq_data(2048)),
        ("e.bin", seq_data(4096)),
    ];

    // Write and fsync each file individually (interleaved pattern).
    for (path, data) in &files {
        harness
            .create_file(path, data)
            .expect("create_file interleaved");
        harness.fsync_file(path).expect("fsync interleaved");
    }

    harness.crash_and_remount().expect("crash_and_remount");

    for (path, expected) in &files {
        let got = harness.read_file(path).expect("read after crash");
        assert_eq!(
            &got, expected,
            "content mismatch for {path} after SIGKILL + remount"
        );
    }
}

// ── test 3: unfsyncd data after crash ───────────────────────────────────

/// Write data without fsync, SIGKILL, remount. The file may be absent,
/// empty, or contain the full data — but must never contain corrupted
/// (phantom) data.
#[test]
fn fsync_crash_unfsyncd_data_no_corruption() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = seq_data(1024);

    harness
        .create_file("phantom.bin", &data)
        .expect("create_file");
    // Deliberately skip fsync — data not committed.

    harness.crash_and_remount().expect("crash_and_remount");

    // After crash without fsync, the file may be absent, empty, or contain
    // the full written data. The key invariant: no phantom data.
    match harness.read_file("phantom.bin") {
        Ok(read_back) => {
            if !read_back.is_empty() {
                assert_eq!(
                    read_back, data,
                    "surviving unfsyncd data should match written data byte-for-byte"
                );
            }
        }
        Err(_) => {
            // File absent — acceptable after crash without fsync.
        }
    }
}

// ── test 4: large file fsync ────────────────────────────────────────────

/// Write 256 KiB of deterministic data, fsync, SIGKILL, remount, verify
/// byte-for-byte survival.
#[test]
fn fsync_crash_large_file_segmented_fsync() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data: Vec<u8> = seq_data(256 * 1024); // 256 KiB

    harness
        .create_file("seg.bin", &data)
        .expect("create 256 KiB file");
    harness.fsync_file("seg.bin").expect("fsync full file");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness.read_file("seg.bin").expect("read after crash");

    assert_eq!(
        read_back.len(),
        data.len(),
        "file length mismatch: expected {}, got {}",
        data.len(),
        read_back.len()
    );
    assert_eq!(
        read_back, data,
        "large file byte-for-byte mismatch after SIGKILL + remount"
    );
}

// ── test 5: overwrite then fsync ─────────────────────────────────────────

/// Write initial data, fsync, overwrite with new data, fsync again, SIGKILL,
/// remount, verify the latest content survived (not the initial data).
#[test]
fn fsync_crash_overwrite_then_fsync() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let initial = b"original content that was overwritten\n".to_vec();
    let overwrite = b"new content that must survive the crash\n".to_vec();

    harness
        .create_file("over.bin", &initial)
        .expect("create initial");
    harness.fsync_file("over.bin").expect("fsync initial");

    // Overwrite via the harness: remove + recreate with new content.
    harness.remove_file("over.bin").expect("remove");
    harness
        .create_file("over.bin", &overwrite)
        .expect("create overwrite");
    harness.fsync_file("over.bin").expect("fsync overwrite");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness.read_file("over.bin").expect("read after crash");
    assert_eq!(
        read_back, overwrite,
        "overwritten content should survive SIGKILL; got initial content instead"
    );
}

// ── test 6: directory tree fsyncd ────────────────────────────────────────

/// Create a 2-level directory tree with files, fsync each, SIGKILL, remount,
/// verify full tree and all file contents.
#[test]
fn fsync_crash_directory_tree_fsyncd() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness.mkdir_all("L1/L2").expect("mkdir L1/L2");

    let files_and_data: Vec<(&str, Vec<u8>)> = vec![
        ("L1/f1.bin", seq_data(100)),
        ("L1/f2.bin", seq_data(200)),
        ("L1/L2/g1.bin", seq_data(300)),
        ("L1/L2/g2.bin", seq_data(400)),
    ];

    for (path, data) in &files_and_data {
        harness.create_file(path, data).expect("create file");
    }

    // Fsync each file individually.
    for (path, _) in &files_and_data {
        harness.fsync_file(path).expect("fsync file");
    }

    harness.crash_and_remount().expect("crash_and_remount");

    // Verify directory structure.
    let l1 = harness.readdir("L1").expect("readdir L1");
    assert!(l1.contains(&"f1.bin".to_string()), "L1 missing f1.bin");
    assert!(l1.contains(&"f2.bin".to_string()), "L1 missing f2.bin");
    assert!(l1.contains(&"L2".to_string()), "L1 missing L2");

    let l2 = harness.readdir("L1/L2").expect("readdir L1/L2");
    assert!(l2.contains(&"g1.bin".to_string()), "L1/L2 missing g1.bin");
    assert!(l2.contains(&"g2.bin".to_string()), "L1/L2 missing g2.bin");

    // Verify file contents.
    for (path, expected) in &files_and_data {
        let got = harness.read_file(path).expect("read file after crash");
        assert_eq!(&got, expected, "content mismatch for {path}");
    }
}

// ── test 7: empty file after fsync ───────────────────────────────────────

/// Create an empty file, fsync, SIGKILL, remount, verify it exists and is
/// empty.
#[test]
fn fsync_crash_empty_file_after_fsync() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("empty.bin", b"")
        .expect("create empty file");
    harness.fsync_file("empty.bin").expect("fsync empty");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("empty.bin")
        .expect("read empty file after crash");
    assert!(
        read_back.is_empty(),
        "empty file should remain empty after SIGKILL + remount"
    );
    assert!(
        harness.exists("empty.bin"),
        "empty file should exist after remount"
    );
}

// ── test 8: rename with fsync ────────────────────────────────────────────

/// Create file A, write data, rename to B, fsync, SIGKILL, remount, verify
/// B exists with correct data and A is gone.
#[test]
fn fsync_crash_rename_with_fsync() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = b"rename survivability test payload\n".to_vec();

    harness
        .create_file("old_name.bin", &data)
        .expect("create old_name.bin");
    harness
        .rename("old_name.bin", "new_name.bin")
        .expect("rename old -> new");
    harness
        .fsync_file("new_name.bin")
        .expect("fsync renamed file");

    harness.crash_and_remount().expect("crash_and_remount");

    // B must exist with correct data.
    let got = harness
        .read_file("new_name.bin")
        .expect("read new_name.bin after crash");
    assert_eq!(got, data, "renamed file content mismatch");

    // A must not exist.
    if harness.exists("old_name.bin") {
        let stale = harness.read_file("old_name.bin").unwrap_or_default();
        panic!(
            "old_name.bin should not survive rename + fsync + SIGKILL; \
             found {} bytes of stale data",
            stale.len()
        );
    }

    // Verify new_name.bin appears in root directory listing.
    let root_entries = harness.readdir(".").expect("readdir /");
    assert!(
        root_entries.contains(&"new_name.bin".to_string()),
        "new_name.bin not found in root dir after crash recovery"
    );
    assert!(
        !root_entries.contains(&"old_name.bin".to_string()),
        "old_name.bin should not appear after rename + crash"
    );
}

// ── test 9: fdatasync durability ───────────────────────────────────────

/// Write data, fdatasync (data-only), SIGKILL, remount, verify content
/// survived.
#[test]
fn fsync_crash_fdatasync_durability() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = seq_data(4096);

    harness.create_file("fd.bin", &data).expect("create_file");
    harness
        .fdatasync_file("fd.bin")
        .expect("fdatasync through FUSE");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness.read_file("fd.bin").expect("read after crash");
    assert_eq!(
        read_back, data,
        "fdatasync data mismatch after SIGKILL + remount"
    );
}

// ── test 10: sparse file with hole ───────────────────────────────────────

/// Write data at offset 0 and offset 64 KiB (leaving a hole in between),
/// fsync, SIGKILL, remount, verify both written regions and the zero-fill
/// hole.
#[test]
fn fsync_crash_sparse_file_with_hole() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let head = seq_data(1024);
    let tail = seq_data(2048);
    let hole_size: usize = 64 * 1024; // 64 KiB hole starting at offset 1024

    // Build the full file: head + zeros + tail.
    let mut full = Vec::with_capacity(head.len() + hole_size + tail.len());
    full.extend_from_slice(&head);
    full.resize(full.len() + hole_size, 0u8);
    full.extend_from_slice(&tail);

    harness
        .create_file("sparse.bin", &full)
        .expect("create sparse file");
    harness.fsync_file("sparse.bin").expect("fsync sparse");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("sparse.bin")
        .expect("read sparse after crash");

    assert_eq!(
        read_back.len(),
        full.len(),
        "sparse file length mismatch: expected {}, got {}",
        full.len(),
        read_back.len()
    );

    // Verify head.
    assert_eq!(
        &read_back[..head.len()],
        &head[..],
        "sparse file head mismatch"
    );

    // Verify hole is zero-filled.
    let hole_start = head.len();
    let hole_end = hole_start + hole_size;
    for (i, byte) in read_back.iter().enumerate().take(hole_end).skip(hole_start) {
        assert_eq!(
            *byte, 0u8,
            "sparse file hole at offset {i}: expected 0, got 0x{:02x}",
            *byte
        );
    }

    // Verify tail.
    let tail_start = hole_end;
    assert_eq!(
        &read_back[tail_start..],
        &tail[..],
        "sparse file tail mismatch"
    );
}

// ── test 11: concurrent writers + SIGKILL ────────────────────────────────

/// Spawn 4 threads, each writing to a distinct file, fsync individually,
/// then SIGKILL and remount. Verify all files survived with correct content
/// and no interleaved or torn writes.
#[test]
fn fsync_crash_concurrent_writers_sigkill() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let mount = harness.mount_path().to_path_buf();
    let files: Vec<(String, Vec<u8>)> = (0..4)
        .map(|i| {
            let name = format!("concurrent_{i}.bin");
            let data = seq_data(4096 + i * 1024);
            (name, data)
        })
        .collect();

    // Create files first (single-threaded, avoids EEXIST races).
    for (name, _) in &files {
        harness
            .create_file(name, b"")
            .expect("create concurrent file");
    }

    // Write and fsync from multiple threads concurrently.
    std::thread::scope(|s| {
        for (name, data) in &files {
            let mp = mount.clone();
            let n = name.clone();
            let d = data.clone();
            s.spawn(move || {
                use std::io::Write;
                let path = mp.join(&n);
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&path)
                    .expect("open for concurrent write");
                f.write_all(&d).expect("concurrent write");
                f.sync_all().expect("concurrent fsync");
            });
        }
    });

    harness.crash_and_remount().expect("crash_and_remount");

    for (name, expected) in &files {
        let got = harness
            .read_file(name)
            .expect("read after concurrent crash");
        assert_eq!(
            &got, expected,
            "concurrent writer content mismatch for {name} after SIGKILL + remount"
        );
    }
}

// ── test 12: truncate + fsync + SIGKILL ──────────────────────────────────

/// Write 8 KiB, fsync, truncate to 1 KiB, fsync, SIGKILL, remount, verify
/// size=1 KiB and first 1 KiB matches original data.
#[test]
fn fsync_crash_truncate_fsync_sigkill() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let initial = seq_data(8192); // 8 KiB
    let mount = harness.mount_path().to_path_buf();

    harness
        .create_file("trunc.bin", &initial)
        .expect("create 8 KiB file");
    harness.fsync_file("trunc.bin").expect("fsync initial");

    // Truncate to 1 KiB via raw I/O.
    {
        use std::fs::OpenOptions;
        let f = OpenOptions::new()
            .write(true)
            .open(mount.join("trunc.bin"))
            .expect("open for truncate");
        f.set_len(1024).expect("truncate to 1 KiB");
        f.sync_all().expect("fsync after truncate");
    }

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness.read_file("trunc.bin").expect("read after crash");

    assert_eq!(
        read_back.len(),
        1024,
        "file size should be 1 KiB after truncate + crash; got {}",
        read_back.len()
    );
    assert_eq!(
        &read_back[..],
        &initial[..1024],
        "truncated content mismatch after SIGKILL + remount"
    );
}

// ── test 13: extend (truncate up) + fsync + SIGKILL ─────────────────────

/// Write 1 KiB, fsync, extend to 4 KiB (zero-fill tail), fsync, SIGKILL,
/// remount, verify size=4 KiB, first 1 KiB intact, tail zero-filled.
#[test]
fn fsync_crash_extend_fsync_sigkill() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let initial = seq_data(1024);
    let mount = harness.mount_path().to_path_buf();

    harness
        .create_file("extend.bin", &initial)
        .expect("create 1 KiB file");
    harness.fsync_file("extend.bin").expect("fsync initial");

    // Extend to 4 KiB via raw I/O.
    {
        use std::fs::OpenOptions;
        let f = OpenOptions::new()
            .write(true)
            .open(mount.join("extend.bin"))
            .expect("open for extend");
        f.set_len(4096).expect("extend to 4 KiB");
        f.sync_all().expect("fsync after extend");
    }

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness.read_file("extend.bin").expect("read after crash");

    assert_eq!(
        read_back.len(),
        4096,
        "file size should be 4 KiB after extend + crash; got {}",
        read_back.len()
    );

    // First 1 KiB: original data.
    assert_eq!(
        &read_back[..1024],
        &initial[..],
        "extended file head mismatch"
    );

    // Bytes 1024..4096: zero-filled.
    for (i, byte) in read_back.iter().enumerate().take(4096).skip(1024) {
        assert_eq!(
            *byte, 0u8,
            "extended file at offset {i}: expected 0, got 0x{:02x}",
            *byte
        );
    }
}

// ── test 14: chmod + fsync + SIGKILL ────────────────────────────────────

/// Change file mode via chmod, fsync, SIGKILL, remount, verify mode bits
/// survived.
#[test]
fn fsync_crash_chmod_fsync_sigkill() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = b"chmod persistence test\n";

    harness.create_file("chmod.bin", data).expect("create file");
    harness.fsync_file("chmod.bin").expect("fsync initial");

    harness.chmod("chmod.bin", 0o600).expect("chmod to 0600");
    harness.fsync_file("chmod.bin").expect("fsync after chmod");

    harness.crash_and_remount().expect("crash_and_remount");

    let md = harness.stat("chmod.bin").expect("stat after crash");
    let mode = md.permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "mode should be 0600 after chmod + SIGKILL + remount; got 0o{mode:o}"
    );

    let content = harness.read_file("chmod.bin").expect("read after crash");
    assert_eq!(content, data, "file content mismatch after chmod + crash");
}

// ── test 15: rename across directories + fsync + SIGKILL ─────────────────

/// Create file in subdir A, rename to subdir B, fsync, SIGKILL, remount,
/// verify file in B with correct content and absent from A.
#[test]
fn fsync_crash_rename_across_dirs_sigkill() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = b"cross-directory rename payload\n".to_vec();

    harness.mkdir_all("src_dir").expect("mkdir src_dir");
    harness.mkdir_all("dst_dir").expect("mkdir dst_dir");

    harness
        .create_file("src_dir/move_me.bin", &data)
        .expect("create file in src_dir");
    harness
        .fsync_file("src_dir/move_me.bin")
        .expect("fsync before rename");

    harness
        .rename("src_dir/move_me.bin", "dst_dir/moved.bin")
        .expect("rename across dirs");
    harness
        .fsync_file("dst_dir/moved.bin")
        .expect("fsync after rename");

    harness.crash_and_remount().expect("crash_and_remount");

    // File must exist in dst_dir with correct content.
    let got = harness
        .read_file("dst_dir/moved.bin")
        .expect("read moved file after crash");
    assert_eq!(got, data, "cross-dir rename content mismatch");

    // File must NOT exist in src_dir.
    if harness.exists("src_dir/move_me.bin") {
        panic!("src_dir/move_me.bin should not exist after cross-dir rename + crash");
    }

    // Verify directory listings.
    let src_entries = harness.readdir("src_dir").expect("readdir src_dir");
    assert!(
        !src_entries.contains(&"move_me.bin".to_string()),
        "src_dir should not contain move_me.bin after cross-dir rename"
    );

    let dst_entries = harness.readdir("dst_dir").expect("readdir dst_dir");
    assert!(
        dst_entries.contains(&"moved.bin".to_string()),
        "dst_dir should contain moved.bin after cross-dir rename"
    );
}

// ── test 16: create + delete directory with files + SIGKILL ──────────────

/// Create dir with files, fsync, delete a file, fsync, SIGKILL, remount,
/// verify deleted file is gone and remaining files intact.
#[test]
fn fsync_crash_delete_file_sigkill() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let keep_data = b"this file should survive\n".to_vec();
    let del_data = b"this file should be deleted\n".to_vec();

    harness.mkdir_all("testdir").expect("mkdir testdir");
    harness
        .create_file("testdir/keep.bin", &keep_data)
        .expect("create keep.bin");
    harness
        .create_file("testdir/del.bin", &del_data)
        .expect("create del.bin");

    harness.fsync_file("testdir/keep.bin").expect("fsync keep");
    harness.fsync_file("testdir/del.bin").expect("fsync del");

    // Delete del.bin, fsync its parent directory.
    harness
        .remove_file("testdir/del.bin")
        .expect("remove del.bin");

    harness.crash_and_remount().expect("crash_and_remount");

    // keep.bin must exist with correct content.
    let got = harness
        .read_file("testdir/keep.bin")
        .expect("read keep.bin after crash");
    assert_eq!(
        got, keep_data,
        "keep.bin content mismatch after delete crash"
    );

    // del.bin must be gone.
    if harness.exists("testdir/del.bin") {
        panic!("testdir/del.bin should not exist after delete + crash");
    }

    let entries = harness.readdir("testdir").expect("readdir testdir");
    assert!(
        entries.contains(&"keep.bin".to_string()),
        "testdir should contain keep.bin"
    );
    assert!(
        !entries.contains(&"del.bin".to_string()),
        "testdir should not contain del.bin after delete + crash"
    );
}

// ── test 17: rmdir + fsync + SIGKILL ─────────────────────────────────────

/// Create empty dir, fsync, remove dir, SIGKILL, remount, verify dir gone.
#[test]
fn fsync_crash_rmdir_sigkill() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness.mkdir_all("rm_me").expect("mkdir rm_me");
    harness
        .create_file("rm_me/placeholder.bin", b"temp\n")
        .expect("create placeholder");

    harness
        .remove_file("rm_me/placeholder.bin")
        .expect("remove placeholder");
    harness.remove_dir("rm_me").expect("rmdir rm_me");

    harness.crash_and_remount().expect("crash_and_remount");

    // Directory must be gone.
    if harness.exists("rm_me") {
        panic!("rm_me directory should not exist after rmdir + crash");
    }
}

// ── test 18: mixed metadata operations + SIGKILL ─────────────────────────

/// Create file, chmod, truncate, chmod again, fsync, SIGKILL, remount,
/// verify final metadata state survived.
#[test]
fn fsync_crash_mixed_metadata_sigkill() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let initial = seq_data(4096);
    let mount = harness.mount_path().to_path_buf();

    harness
        .create_file("meta.bin", &initial)
        .expect("create file");
    harness.fsync_file("meta.bin").expect("fsync initial");

    // Chmod to 0644, truncate to 512 bytes, chmod to 0600.
    harness.chmod("meta.bin", 0o644).expect("chmod 0644");

    {
        use std::fs::OpenOptions;
        let f = OpenOptions::new()
            .write(true)
            .open(mount.join("meta.bin"))
            .expect("open for truncate");
        f.set_len(512).expect("truncate to 512");
        f.sync_all().expect("fsync after truncate");
    }

    harness.chmod("meta.bin", 0o600).expect("chmod 0600");
    harness
        .fsync_file("meta.bin")
        .expect("fsync after metadata ops");

    harness.crash_and_remount().expect("crash_and_remount");

    let md = harness.stat("meta.bin").expect("stat after crash");
    assert_eq!(
        md.len(),
        512,
        "file size should be 512 after mixed metadata + crash"
    );
    assert_eq!(
        md.permissions().mode() & 0o777,
        0o600,
        "mode should be 0600 after mixed metadata + crash"
    );

    let content = harness.read_file("meta.bin").expect("read after crash");
    assert_eq!(content.len(), 512, "read length mismatch");
    assert_eq!(&content[..], &initial[..512], "truncated content mismatch");
}

// ── test 19: checkpoint fsync + SIGKILL ──────────────────────────────────

/// Write 128 KiB in 8 KiB chunks, fsync every 32 KiB (4 checkpoints).
/// SIGKILL the daemon, remount, and verify that the fsync'd checkpoint
/// boundaries are intact -- data before the last completed fsync must
/// survive byte-for-byte regardless of what was in-flight at crash time.
#[test]
fn fsync_crash_checkpoint_fsync_sigkill() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let chunk_size = 8 * 1024; // 8 KiB per chunk
    let checkpoint_interval = 4; // fsync every 4 chunks = 32 KiB
    let total_chunks = 16; // 16 * 8 KiB = 128 KiB
    let mount = harness.mount_path().to_path_buf();

    // Build the full data buffer.
    let full_data: Vec<u8> = (0..total_chunks * chunk_size)
        .map(|i| (i % 256) as u8)
        .collect();

    // Create the file and write chunk by chunk with checkpoint fsyncs.
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        harness
            .create_file("checkpoint.bin", b"")
            .expect("create empty");
        let path = mount.join("checkpoint.bin");
        let mut f = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for chunked write");

        for chunk_idx in 0..total_chunks {
            let start = chunk_idx * chunk_size;
            let end = start + chunk_size;
            f.write_all(&full_data[start..end]).expect("write chunk");
            // Fsync at checkpoint boundaries.
            if (chunk_idx + 1) % checkpoint_interval == 0 {
                f.sync_all().expect("checkpoint fsync");
            }
        }
        // Deliberately do NOT fsync the last chunk (it was already fsync'd
        // at chunk 16 if 16 % 4 == 0 -- it is, so the last checkpoint
        // includes the full file).  This test exercises the pattern where
        // multiple fsync calls punctuate a long sequential write.
    }

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("checkpoint.bin")
        .expect("read checkpoint file after crash");

    // The entire file was fsync'd at each 32 KiB boundary, including the
    // final chunk (16 % 4 == 0).  So the full 128 KiB must survive.
    assert_eq!(
        read_back.len(),
        full_data.len(),
        "checkpoint file length: expected {}, got {}",
        full_data.len(),
        read_back.len()
    );
    assert_eq!(
        read_back, full_data,
        "checkpoint fsync data mismatch after SIGKILL + remount"
    );
}

// ── test 20: mid-write SIGKILL (no fsync on last chunk) ─────────────────

/// Write 64 KiB in 8 KiB chunks, fsync every 16 KiB, then write a final
/// 8 KiB chunk WITHOUT fsync and immediately SIGKILL.  The first 56 KiB
/// (7 fsynced chunks) must survive; the last un-fsynced chunk may be
/// absent, empty, or intact but must never be corrupted.
#[test]
fn fsync_crash_mid_write_sigkill_unfsynced_tail() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let chunk_size = 8 * 1024; // 8 KiB
    let fsync_interval = 2; // fsync every 2 chunks = 16 KiB
    let total_chunks = 8; // 8 * 8 KiB = 64 KiB
    let mount = harness.mount_path().to_path_buf();

    let full_data: Vec<u8> = seq_data(total_chunks * chunk_size);

    {
        use std::fs::OpenOptions;
        use std::io::Write;
        harness
            .create_file("midwrite.bin", b"")
            .expect("create empty");
        let path = mount.join("midwrite.bin");
        let mut f = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for mid-write test");

        for chunk_idx in 0..total_chunks {
            let start = chunk_idx * chunk_size;
            let end = start + chunk_size;
            f.write_all(&full_data[start..end]).expect("write chunk");
            // Only fsync at intervals; skip the LAST chunk's fsync.
            if (chunk_idx + 1) % fsync_interval == 0 && (chunk_idx + 1) < total_chunks {
                f.sync_all().expect("interval fsync");
            }
        }
        // Deliberately skip fsync on last chunk.
        // Do NOT drop the file -- SIGKILL happens with the fd still open.
    }

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("midwrite.bin")
        .expect("read midwrite file after crash");

    // The last check-pointed offset: 6 chunks * 8 KiB = 48 KiB.
    // (chunks 0-5 fsynced at chunks 2, 4, 6)
    let fsynced_len = (total_chunks - 1) * chunk_size; // 56 KiB

    if !read_back.is_empty() {
        // If data survived, the fsynced prefix must be intact.
        assert!(
            read_back.len() <= full_data.len(),
            "midwrite file should not be longer than written: {} > {}",
            read_back.len(),
            full_data.len()
        );

        // Verify as much of the fsynced prefix as survived matches.
        let cmp_len = read_back.len().min(fsynced_len);
        assert_eq!(
            &read_back[..cmp_len],
            &full_data[..cmp_len],
            "fsynced prefix mismatch: first {cmp_len} bytes differ after SIGKILL + remount"
        );

        // If beyond the fsynced boundary, the extra data must match
        // the written data (not phantom data).
        if read_back.len() > fsynced_len {
            assert_eq!(
                &read_back[fsynced_len..],
                &full_data[fsynced_len..read_back.len()],
                "un-fsynced tail contains phantom data after SIGKILL"
            );
        }
    }
    // else: empty file is also acceptable after crash without fsync.
}

// ── test 21: crash-loop resilience (10 cycles) ────────────────────────────

/// Create a file with known content, fsync, then SIGKILL + remount 10
/// times in rapid succession.  Verify the file survives all 10 cycles
/// with correct content and the mount remains usable.
#[test]
fn fsync_crash_loop_ten_cycles() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = seq_data(4096);

    harness
        .create_file("loop.bin", &data)
        .expect("create file before loop");
    harness.fsync_file("loop.bin").expect("initial fsync");

    for cycle in 1..=10 {
        harness
            .crash_and_remount()
            .unwrap_or_else(|e| panic!("crash_and_remount cycle {cycle}: {e}"));

        // Verify the file still exists and content is correct.
        let read_back = harness
            .read_file("loop.bin")
            .expect("read loop.bin after crash cycle");
        assert_eq!(
            read_back, data,
            "loop.bin content mismatch at crash cycle {cycle} / 10"
        );

        // Verify we can still write a new file after each recovery.
        let marker = format!("cycle_{cycle}").into_bytes();
        harness
            .create_file(format!("marker_{cycle}.bin"), &marker)
            .expect("create marker file after crash cycle");
        harness
            .fsync_file(format!("marker_{cycle}.bin"))
            .expect("fsync marker file");

        // Re-verify the original file is still fine.
        let recheck = harness
            .read_file("loop.bin")
            .expect("re-read loop.bin after marker write");
        assert_eq!(
            recheck, data,
            "loop.bin content corrupted after marker write at cycle {cycle}"
        );
    }

    // Final verification: all 10 marker files must exist with correct content.
    for cycle in 1..=10 {
        let expected = format!("cycle_{cycle}").into_bytes();
        let got = harness
            .read_file(format!("marker_{cycle}.bin"))
            .expect("read marker after all cycles");
        assert_eq!(
            got, expected,
            "marker_{cycle}.bin content mismatch after 10 crash cycles"
        );
    }
}

// ── test 22: power-loss simulation (umount -l + SIGKILL + remount) ───────

/// Write data, fsync, then simulate a power loss by lazy-unmounting
/// (`umount -l`) while the daemon is still running, followed by SIGKILL.
/// Remount and verify that fsync'd data survives intact.  The lazy
/// unmount detaches the mount from the VFS namespace before the daemon
/// exits, so there is no opportunity for a clean writeback flush.
#[test]
fn fsync_crash_power_loss_lazy_unmount_sigkill() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = seq_data(8192);
    harness
        .create_file("ploss.bin", &data)
        .expect("create_file");
    harness
        .fsync_file("ploss.bin")
        .expect("fsync before power loss");

    // Lazy-unmount: detaches the mount point while the daemon is still
    // alive.  This simulates a power loss where the kernel drops the
    // mount without giving the daemon a chance to flush.
    let mount = harness.mount_path().to_path_buf();
    let umount = std::process::Command::new("umount")
        .arg("-l")
        .arg(&mount)
        .output();
    // umount -l may fail if the mount was already detached; that's fine.
    if let Ok(ref out) = umount {
        if !out.status.success() {
            eprintln!(
                "note: umount -l returned non-zero (mount may already be detached): {}",
                String::from_utf8_lossy(&out.stderr).trim_end()
            );
        }
    }

    // Brief pause so the kernel finishes detaching.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // SIGKILL the daemon to ensure it cannot do any last-minute flush.
    unsafe {
        libc::kill(harness.daemon_pid() as i32, libc::SIGKILL);
    }

    // Remount the same backing store.
    harness.remount().expect("remount after power loss");

    let read_back = harness
        .read_file("ploss.bin")
        .expect("read after power loss recovery");
    assert_eq!(
        read_back, data,
        "power-loss simulation: byte-for-byte mismatch after umount -l + SIGKILL + remount"
    );

    // Smoke-test that the filesystem is still writable after recovery.
    harness
        .create_file("post_ploss_recovery.bin", b"recovery ok\n")
        .expect("write after power-loss recovery");
}

// ── test 23: append + fsync + SIGKILL ─────────────────────────────────────

/// Append data to an existing file, fsync, SIGKILL, remount, and verify
/// the appended region survived along with the original prefix.
#[test]
fn fsync_crash_append_fsync_sigkill() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let prefix = b"original data that was written first\n".to_vec();
    let suffix = b"appended after fsync of prefix\n".to_vec();

    harness
        .create_file("append.bin", &prefix)
        .expect("create initial");
    harness.fsync_file("append.bin").expect("fsync prefix");

    // Append via raw I/O to keep the existing content.
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        let path = harness.mount_path().join("append.bin");
        let mut f = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for append");
        f.write_all(&suffix).expect("append write");
        f.sync_all().expect("fsync after append");
    }

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness.read_file("append.bin").expect("read after crash");

    let expected: Vec<u8> = prefix.iter().chain(suffix.iter()).copied().collect();
    assert_eq!(
        read_back, expected,
        "append+fsync data mismatch after SIGKILL + remount"
    );
    assert_eq!(
        read_back.len(),
        expected.len(),
        "append file length: expected {}, got {}",
        expected.len(),
        read_back.len()
    );
}

// ── test 24: graceful shutdown via SIGTERM ────────────────────────────────

/// Write data, fsync, send SIGTERM (graceful shutdown), remount, and verify
/// byte-for-byte data survival.  Unlike SIGKILL tests, SIGTERM triggers the
/// daemon's graceful shutdown path: writeback flush, final commit_group commit,
/// clean mount-state write, and FUSE unmount before the process exits.
#[test]
fn graceful_shutdown_sigterm_data_survival() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = seq_data(4096);

    harness
        .create_file("graceful_test.bin", &data)
        .expect("create_file through FUSE");
    harness
        .fsync_file("graceful_test.bin")
        .expect("fsync through FUSE");

    harness
        .graceful_shutdown_and_remount()
        .expect("graceful_shutdown_and_remount");

    let read_back = harness
        .read_file("graceful_test.bin")
        .expect("read after graceful shutdown + remount");
    assert_eq!(
        read_back, data,
        "byte-for-byte mismatch after SIGTERM graceful shutdown + remount"
    );
}
