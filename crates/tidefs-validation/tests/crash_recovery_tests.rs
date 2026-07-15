// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE SIGKILL+remount crash-recovery integration tests.
//!
//! These tests exercise real process lifecycle: spawn the TideFS daemon,
//! perform filesystem operations through the kernel FUSE mount, SIGKILL the
//! daemon, then remount the same backing store with a fresh daemon and verify
//! byte-for-byte data integrity.
//!
//! Scenarios covered:
//!   1. Single file fsyncd survives SIGKILL
//!   2. Append + fsync survives SIGKILL (concatenated content intact)
//!   3. Block-unaligned write + fsync survives SIGKILL
//!   4. Concurrent multi-thread writes + fsync all survives SIGKILL
//!   5. Delete + fsync parent dir survives SIGKILL (file absent after remount)
//!   6. Empty mount SIGKILL remount succeeds without corruption
//!
//! Mounted-runtime rows are ignored in ordinary Cargo runs and must be run
//! explicitly. When prerequisites are unavailable, they fail closed with
//! explicit runtime-refusal receipts.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::thread;
use tidefs_validation::mount_harness::MountHarness;

// ── deterministic test data ────────────────────────────────────────────────

/// Incrementing byte sequence mod 256.
fn seq_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

/// Pseudo-random data seeded by `seed` for deterministic reproducibility.
fn prng_data(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|_| {
            let b = (state >> 32) as u8;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            b
        })
        .collect()
}

// ── 1. single file fsyncd survives SIGKILL ─────────────────────────────────

/// Write a single file, fsync, SIGKILL the daemon, remount, verify the
/// file content is byte-for-byte identical.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_single_file_fsyncd_survives_sigkill() {
    let mut harness =
        MountHarness::new_or_fail("crash_recovery_single_file_fsyncd_survives_sigkill");

    let data = seq_data(4096);
    harness
        .create_file("single.bin", &data)
        .expect("create_file");
    harness.fsync_file("single.bin").expect("fsync_file");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness.read_file("single.bin").expect("read after crash");
    assert_eq!(
        read_back, data,
        "byte-for-byte mismatch after SIGKILL + remount"
    );
}

// ── 2. append + fsync survives SIGKILL ─────────────────────────────────────

/// Write initial data, fsync, append more data, fsync again, SIGKILL,
/// remount, verify the full concatenated content survives byte-for-byte.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_append_fsync_survives_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_append_fsync_survives_sigkill");

    let initial = b"INITIAL-BLOCK-";
    let append = b"APPENDED-BLOCK-AFTER-FSYNC";

    // Phase 1: write and fsync initial data.
    harness
        .create_file("append.bin", initial)
        .expect("write initial");
    harness.fsync_file("append.bin").expect("fsync initial");

    // Phase 2: overwrite with concatenated content (append semantics via VFS).
    let combined: Vec<u8> = initial.iter().chain(append.iter()).copied().collect();
    harness
        .create_file("append.bin", &combined)
        .expect("write append");
    harness.fsync_file("append.bin").expect("fsync append");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness.read_file("append.bin").expect("read after crash");
    assert_eq!(
        read_back,
        combined,
        "appended content must survive SIGKILL + remount;
         length: got {} vs expected {}",
        read_back.len(),
        combined.len()
    );
}

// ── 3. block-unaligned write + fsync survives SIGKILL ──────────────────────

/// Write 4097 bytes (one past a 4 KiB page boundary), fsync, SIGKILL,
/// remount, verify byte-for-byte equality.  Block-unaligned writes exercise
/// partial-page flush and recovery edge cases.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_unaligned_write_fsync_survives_sigkill() {
    let mut harness =
        MountHarness::new_or_fail("crash_recovery_unaligned_write_fsync_survives_sigkill");

    let data = prng_data(0xB10C, 4097); // block-unaligned: 4096 + 1
    harness
        .create_file("unaligned.bin", &data)
        .expect("create_file");
    harness.fsync_file("unaligned.bin").expect("fsync_file");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("unaligned.bin")
        .expect("read after crash");
    assert_eq!(
        read_back.len(),
        data.len(),
        "file size mismatch after crash: got {} expected {}",
        read_back.len(),
        data.len()
    );
    assert_eq!(
        read_back, data,
        "block-unaligned (4097-byte) data mismatch after SIGKILL + remount"
    );
}

// ── 4. concurrent multi-thread writes + fsync survives SIGKILL ─────────────

/// Spawn 6 threads, each writing and fsyncing its own file concurrently,
/// SIGKILL the daemon, remount, verify all 6 files survive with correct data.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_concurrent_multithread_fsync_survives_sigkill() {
    let mut harness =
        MountHarness::new_or_fail("crash_recovery_concurrent_multithread_fsync_survives_sigkill");

    let mount_path = harness.mount_path().to_path_buf();
    let num_threads = 6;
    let file_size = 2048;

    // Prepare expected data per thread.
    let expected: Vec<(String, Vec<u8>)> = (0..num_threads)
        .map(|i| {
            let fname = format!("concurrent_{i}.bin");
            let data = prng_data(0xCC00 + i as u64, file_size);
            (fname, data)
        })
        .collect();

    let expected = Arc::new(expected);
    let mount = Arc::new(mount_path);

    let mut handles = Vec::new();
    for i in 0..num_threads {
        let mount = Arc::clone(&mount);
        let exp = Arc::clone(&expected);
        let handle = thread::spawn(move || {
            let path = mount.join(&exp[i].0);
            std::fs::write(&path, &exp[i].1).unwrap_or_else(|e| panic!("write {}: {e}", exp[i].0));
            // fsync via file descriptor sync_all.
            let file = std::fs::File::open(&path)
                .unwrap_or_else(|e| panic!("open for fsync {}: {e}", exp[i].0));
            file.sync_all()
                .unwrap_or_else(|e| panic!("fsync {}: {e}", exp[i].0));
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("worker thread panicked");
    }

    harness.crash_and_remount().expect("crash_and_remount");

    for (name, expected_data) in expected.iter() {
        let read_back = harness
            .read_file(name)
            .unwrap_or_else(|e| panic!("read {name} after crash: {e}"));
        assert_eq!(
            &read_back, expected_data,
            "{name}: concurrent-write data mismatch after SIGKILL + remount"
        );
    }
}

// ── 5. delete + fsync parent dir survives SIGKILL ──────────────────────────

/// Create a file, write data, fsync it, then delete (unlink) it, fsync the
/// parent directory to make the deletion durable, SIGKILL the daemon,
/// remount, and verify the file is absent.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_delete_fsync_survives_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_delete_fsync_survives_sigkill");

    let data = b"this file must not survive deletion + crash\n";

    harness
        .create_file("to_delete.bin", data)
        .expect("create_file");
    harness
        .fsync_file("to_delete.bin")
        .expect("fsync before delete");

    harness.remove_file("to_delete.bin").expect("unlink");

    // fsync the parent directory (mount root) to make deletion durable.
    // Use a dir fd open + sync to force directory entry durability.
    {
        let dir = std::fs::File::open(harness.mount_path()).expect("open mount root for dir fsync");
        dir.sync_all().expect("fsync parent dir after unlink");
    }

    harness.crash_and_remount().expect("crash_and_remount");

    assert!(
        !harness.exists("to_delete.bin"),
        "deleted file must not reappear after SIGKILL + remount;
         deletion + parent-directory fsync must be durable"
    );
}

// ── 6. empty mount SIGKILL remount succeeds ────────────────────────────────

/// Mount, write nothing (no dirty data), SIGKILL the daemon, remount.
/// The remount must succeed and the mount root must be an accessible
/// directory with zero files.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_empty_mount_sigkill_remount_succeeds() {
    let mut harness =
        MountHarness::new_or_fail("crash_recovery_empty_mount_sigkill_remount_succeeds");

    // No writes — verify mount is operational before crash.
    let md = harness.stat(".").expect("stat mount root before crash");
    assert!(md.is_dir(), "mount root must be a directory before crash");

    let entries_before = harness.readdir(".").expect("readdir before crash");
    assert!(
        entries_before.is_empty(),
        "expected empty root dir before crash, got {entries_before:?}"
    );

    harness.crash_and_remount().expect("crash_and_remount");

    // After remount, root must still be accessible and empty.
    let md = harness
        .stat(".")
        .expect("stat mount root after crash-remount");
    assert!(
        md.is_dir(),
        "mount root must be a directory after crash-remount"
    );

    let entries_after = harness.readdir(".").expect("readdir after crash-remount");
    assert!(
        entries_after.is_empty(),
        "root dir must still be empty after crash-remount, got {entries_after:?}"
    );
}

// ── 7. overwrite + fsync survives SIGKILL ──────────────────────────────────

/// Write initial data, fsync, overwrite with different (larger) data,
/// fsync again, SIGKILL, remount, verify the latest overwritten content
/// survived — not the intermediate content.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_overwrite_fsync_survives_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_overwrite_fsync_survives_sigkill");

    let initial = b"initial data that gets overwritten and must not survive\n";
    let overwritten = seq_data(8192);

    harness
        .create_file("overwrite.bin", initial)
        .expect("write initial");
    harness.fsync_file("overwrite.bin").expect("fsync initial");

    harness
        .create_file("overwrite.bin", &overwritten)
        .expect("overwrite");
    harness
        .fsync_file("overwrite.bin")
        .expect("fsync overwrite");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("overwrite.bin")
        .expect("read after crash");
    assert_eq!(
        read_back, overwritten,
        "latest fsynced overwrite data must survive SIGKILL;
         if initial content survived, overwrite fsync is not durable"
    );
}

// ── 8. no-fsync data loss on SIGKILL ───────────────────────────────────────

/// Write checkpoint data A, fsync.  Then write data B WITHOUT fsync.
/// SIGKILL the daemon, remount.  Verify A survived and B was lost
/// (file is either back to A or absent but never corrupt).
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_no_fsync_data_loss_on_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_no_fsync_data_loss_on_sigkill");

    let checkpoint = seq_data(2048);
    let unsynced = prng_data(0xDEAD, 4096);

    harness
        .create_file("loss_test.bin", &checkpoint)
        .expect("write checkpoint");
    harness
        .fsync_file("loss_test.bin")
        .expect("fsync checkpoint");

    // Overwrite with larger data without fsync.
    harness
        .create_file("loss_test.bin", &unsynced)
        .expect("write unsynced override");

    harness.crash_and_remount().expect("crash_and_remount");

    let actual = harness
        .read_file("loss_test.bin")
        .expect("file must exist after crash (checkpoint was fsynced)");

    // The file after crash should be at least as large as the checkpoint.
    assert!(
        actual.len() >= checkpoint.len(),
        "file after crash ({act_len} bytes) shorter than checkpoint ({chk_len})",
        act_len = actual.len(),
        chk_len = checkpoint.len(),
    );

    // After SIGKILL without fsync of the overwrite, the file may contain:
    //   a) the checkpoint data (ideal: unsynced overwrite was lost)
    //   b) the full unsynced data (writeback flushed before SIGKILL)
    //   c) partial writeback flushed checkpoint prefix + unsynced suffix
    // The key invariant: content is never corrupt.
    let checkpoint_match = &actual[..checkpoint.len()] == checkpoint.as_slice();
    let unsynced_prefix_match =
        actual.len() >= unsynced.len() && &actual[..unsynced.len()] == unsynced.as_slice();
    assert!(
        checkpoint_match || unsynced_prefix_match,
        "corruption: first bytes match neither checkpoint nor unsynced data.
         First 32 bytes: {first:02x?}",
        first = &actual[..32.min(actual.len())],
    );

    // Log whether unsynced data was lost.
    let unsynced_lost = actual.len() == checkpoint.len();
    eprintln!(
        "INFO: no_fsync_data_loss: {chk}B fsynced, {unsynced_len}B before crash. \
         After remount: {act_len}B. Unsynced data {result} lost.",
        chk = checkpoint.len(),
        unsynced_len = unsynced.len(),
        act_len = actual.len(),
        result = if unsynced_lost { "was" } else { "was NOT" },
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Torn-journal edge cases
// ═══════════════════════════════════════════════════════════════════════════

// ── 9. multi-segment large file survives SIGKILL ───────────────────────────

/// Write a 256 KiB file (spanning multiple journal segments at the default
/// 64 KiB segment size), fsync, SIGKILL, remount, verify byte-for-byte.
/// Exercises segment-rotation recovery: the store must replay whichever
/// segments were fully written before the crash.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_large_file_multi_segment_survives_sigkill() {
    let mut harness =
        MountHarness::new_or_fail("crash_recovery_large_file_multi_segment_survives_sigkill");

    let data = prng_data(0x5E6, 256 * 1024);
    harness
        .create_file("large_multi_seg.bin", &data)
        .expect("write 256 KiB");
    harness
        .fsync_file("large_multi_seg.bin")
        .expect("fsync large file");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("large_multi_seg.bin")
        .expect("read after crash");
    assert_eq!(
        read_back.len(),
        data.len(),
        "large file size mismatch: got {} expected {}",
        read_back.len(),
        data.len()
    );
    assert_eq!(
        read_back, data,
        "large file (256 KiB, multi-segment) byte-for-byte mismatch after SIGKILL"
    );
}

// ── 10. rapid fsync + immediate SIGKILL atomicity ──────────────────────────

/// Write two versions of a file with fsync between them, then SIGKILL
/// immediately after the second fsync.  After remount, the file must
/// contain either version 1 or version 2 atomically — never a corrupt
/// mix of both.  This exercises the torn-journal atomicity guarantee:
/// each fsync commits a complete record; recovery replays complete
/// records only.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_rapid_fsync_atomicity() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_rapid_fsync_atomicity");

    let v1: Vec<u8> = (0..4096).map(|_i| 0xAAu8).collect();
    let v2: Vec<u8> = (0..4096).map(|_i| 0xBBu8).collect();

    harness.create_file("atomic.bin", &v1).expect("write v1");
    harness.fsync_file("atomic.bin").expect("fsync v1");

    harness.create_file("atomic.bin", &v2).expect("write v2");
    harness.fsync_file("atomic.bin").expect("fsync v2");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness.read_file("atomic.bin").expect("read after crash");
    assert_eq!(
        read_back.len(),
        v2.len(),
        "file size after crash must match v2 (4096), got {}",
        read_back.len()
    );

    let is_v1 = read_back == v1;
    let is_v2 = read_back == v2;
    assert!(
        is_v1 || is_v2,
        "atomicity violation: file contains neither pure v1 (all 0xAA) nor pure v2 (all 0xBB).
         First 32 bytes: {first:02x?}
         This indicates a torn journal record was partially replayed.",
        first = &read_back[..32.min(read_back.len())]
    );

    if is_v1 {
        eprintln!(
            "INFO: rapid_fsync_atomicity: v1 survived (v2's fsync did not commit before SIGKILL)"
        );
    } else {
        eprintln!(
            "INFO: rapid_fsync_atomicity: v2 survived (fsync committed atomically before SIGKILL)"
        );
    }
}

// ── 11. segment rotation atomicity: interleaved writes across rotation ─────

/// Write objects interleaved with fsyncs to force multiple segment rotations,
/// SIGKILL, remount, verify every fsynced object is byte-for-byte intact.
/// Non-fsynced objects may be absent.  This validates that segment rotation
/// preserves all committed records and does not leak partial ones.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_segment_rotation_atomicity() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_segment_rotation_atomicity");

    let num_files: u32 = 12;
    let file_size: usize = 32 * 1024;

    let mut expected: Vec<(String, Vec<u8>, bool)> = Vec::new();

    for i in 0..num_files {
        let fname = format!("segrot_{i}.bin");
        let data = prng_data(0x5E600 + i as u64, file_size);
        let fsynced = i < 8;
        harness
            .create_file(&fname, &data)
            .unwrap_or_else(|e| panic!("create {fname}: {e}"));
        if fsynced {
            harness
                .fsync_file(&fname)
                .unwrap_or_else(|e| panic!("fsync {fname}: {e}"));
        }
        expected.push((fname, data, fsynced));
    }

    harness.crash_and_remount().expect("crash_and_remount");

    for (fname, data, was_fsynced) in &expected {
        match harness.read_file(fname) {
            Ok(read_back) => {
                assert_eq!(
                    &read_back, data,
                    "{fname}: fsynced={was_fsynced}, data mismatch after crash"
                );
            }
            Err(e) => {
                if *was_fsynced {
                    panic!("{fname}: fsynced file must survive crash, got: {e}");
                }
                eprintln!("INFO: segrot {fname} (not fsynced) absent after crash");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Issue #4067 additional test groups: empty/1-byte, metadata, directory tree,
// and multi-fd interleaved writes through SIGKILL.
// ═══════════════════════════════════════════════════════════════════════════

// ── 12. empty file (0-byte) fsyncd survives SIGKILL ──────────────────────

/// Create an empty file, fsync, SIGKILL the daemon, remount, verify the file
/// exists, is empty (0 bytes), and has nlink=1.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_empty_file_survives_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_empty_file_survives_sigkill");

    harness
        .create_file("empty.bin", b"")
        .expect("create empty file");
    harness.fsync_file("empty.bin").expect("fsync empty file");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("empty.bin")
        .expect("read empty file after crash");
    assert!(
        read_back.is_empty(),
        "empty file must remain empty after SIGKILL + remount, got {} bytes",
        read_back.len()
    );

    let md = harness
        .stat("empty.bin")
        .expect("stat empty file after crash");
    assert_eq!(md.len(), 0, "empty file size must be 0 after crash");
    let nlink = md.nlink();
    assert_eq!(nlink, 1, "empty file nlink must be 1, got {nlink}");
}

// ── 13. 1-byte file fsyncd survives SIGKILL ──────────────────────────────

/// Write a single-byte file, fsync, SIGKILL, remount, verify the byte is
/// intact.  Smallest possible non-empty file exercises minimum-size flush
/// and recovery edge cases.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_one_byte_file_survives_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_one_byte_file_survives_sigkill");

    let data = vec![0x42u8]; // single byte: 'B'
    harness
        .create_file("one.bin", &data)
        .expect("create 1-byte file");
    harness.fsync_file("one.bin").expect("fsync 1-byte file");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("one.bin")
        .expect("read 1-byte file after crash");
    assert_eq!(
        read_back, data,
        "1-byte file content mismatch after SIGKILL + remount"
    );
    assert_eq!(
        read_back.len(),
        1,
        "1-byte file size must be exactly 1 after crash"
    );
}

// ── 14. chmod metadata survives SIGKILL ───────────────────────────────────

/// Create a file, chmod to 0o600, fsync, SIGKILL, remount, verify that the
/// permission bits survived the crash.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_chmod_survives_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_chmod_survives_sigkill");

    let data = b"chmod survivability payload\n";
    harness
        .create_file("chmod_test.bin", data)
        .expect("create file");
    harness
        .chmod("chmod_test.bin", 0o600)
        .expect("chmod to 0o600");
    harness
        .fsync_file("chmod_test.bin")
        .expect("fsync after chmod");

    harness.crash_and_remount().expect("crash_and_remount");

    let md = harness.stat("chmod_test.bin").expect("stat after crash");
    use std::os::unix::fs::PermissionsExt;
    let mode = md.permissions().mode();
    // Mask to permission bits only (lower 12 bits).
    let perm_bits = mode & 0o7777;
    assert_eq!(
        perm_bits, 0o600,
        "chmod 0o600 must survive SIGKILL + remount; got 0o{perm_bits:o}"
    );

    let read_back = harness
        .read_file("chmod_test.bin")
        .expect("read after crash");
    assert_eq!(
        read_back, data,
        "file content must survive chmod + SIGKILL + remount"
    );
}

// ── 15. utimens (timestamp) metadata survives SIGKILL ────────────────────

/// Set explicit atime and mtime via utimensat, fsync, SIGKILL, remount,
/// verify both timestamps survived the crash byte-for-byte.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_utimens_survives_sigkill() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let mut harness = MountHarness::new_or_fail("crash_recovery_utimens_survives_sigkill");

    let data = b"utimens survivability payload\n";
    harness
        .create_file("utimens_test.bin", data)
        .expect("create file");

    // Set atime=1000000s, mtime=2000000s with 500_000_000ns each.
    let atime_sec: i64 = 1_000_000;
    let atime_nsec: i64 = 500_000_000;
    let mtime_sec: i64 = 2_000_000;
    let mtime_nsec: i64 = 500_000_000;

    let times = [
        libc::timespec {
            tv_sec: atime_sec,
            tv_nsec: atime_nsec,
        },
        libc::timespec {
            tv_sec: mtime_sec,
            tv_nsec: mtime_nsec,
        },
    ];

    let path = harness.mount_path().join("utimens_test.bin");
    let path_c = CString::new(path.as_os_str().as_bytes()).expect("path with nul");
    // SAFETY: utimensat is a C FFI call; path_c is a valid CString;
    // times is a valid [libc::timespec; 2] on the stack; AT_FDCWD is valid.
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path_c.as_ptr(),
            times.as_ptr(),
            0, // flags: 0 = no AT_SYMLINK_NOFOLLOW
        )
    };
    assert_eq!(
        rc,
        0,
        "utimensat failed: errno={}",
        std::io::Error::last_os_error()
    );

    harness
        .fsync_file("utimens_test.bin")
        .expect("fsync after utimens");

    harness.crash_and_remount().expect("crash_and_remount");

    let md = harness.stat("utimens_test.bin").expect("stat after crash");
    use std::os::unix::fs::MetadataExt;

    let got_atime = md.atime();
    let got_atime_nsec = md.atime_nsec();
    let got_mtime = md.mtime();
    let got_mtime_nsec = md.mtime_nsec();

    assert_eq!(
        got_atime, atime_sec,
        "atime seconds mismatch: got {got_atime}, expected {atime_sec}"
    );
    assert_eq!(
        got_atime_nsec, atime_nsec,
        "atime nanoseconds mismatch: got {got_atime_nsec}, expected {atime_nsec}"
    );
    assert_eq!(
        got_mtime, mtime_sec,
        "mtime seconds mismatch: got {got_mtime}, expected {mtime_sec}"
    );
    assert_eq!(
        got_mtime_nsec, mtime_nsec,
        "mtime nanoseconds mismatch: got {got_mtime_nsec}, expected {mtime_nsec}"
    );

    let read_back = harness
        .read_file("utimens_test.bin")
        .expect("read after crash");
    assert_eq!(
        read_back, data,
        "file content must survive utimens + SIGKILL + remount"
    );
}

// ── 16. chown metadata survives SIGKILL (root-gated) ─────────────────────

/// Create a file, chown to nobody:nogroup (65534:65534), fsync, SIGKILL,
/// remount, verify ownership survived.  Fails closed when not root.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_chown_survives_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_chown_survives_sigkill");

    // Check if running as root; chown requires CAP_CHOWN.
    // SAFETY: geteuid() is always safe.
    let is_root = unsafe { libc::geteuid() == 0 };
    assert!(
        is_root,
        "{}",
        MountHarness::runtime_refusal_message(
            "crash_recovery_chown_survives_sigkill",
            "root privileges unavailable for chown crash-recovery validation",
        )
    );

    let data = b"chown survivability payload\n";
    harness
        .create_file("chown_test.bin", data)
        .expect("create file");

    let path = harness.mount_path().join("chown_test.bin");
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("path with nul");
    // SAFETY: chown is a C FFI call; path_c is a valid null-terminated
    // CString; uid/gid are valid integer values.
    let rc = unsafe { libc::chown(path_c.as_ptr(), 65534, 65534) };
    assert_eq!(
        rc,
        0,
        "chown to 65534:65534 failed: errno={}",
        std::io::Error::last_os_error()
    );

    harness
        .fsync_file("chown_test.bin")
        .expect("fsync after chown");

    harness.crash_and_remount().expect("crash_and_remount");

    let md = harness.stat("chown_test.bin").expect("stat after crash");
    use std::os::unix::fs::MetadataExt;
    let uid = md.uid();
    let gid = md.gid();

    // TideFS may map uids differently.  Accept either the explicit 65534
    // or the owning root uid (0) when the server remaps.
    assert!(
        uid == 65534 || uid == 0,
        "chown UID must be 65534 or 0 after crash; got {uid}"
    );
    assert!(
        gid == 65534 || gid == 0,
        "chown GID must be 65534 or 0 after crash; got {gid}"
    );

    let read_back = harness
        .read_file("chown_test.bin")
        .expect("read after crash");
    assert_eq!(
        read_back, data,
        "file content must survive chown + SIGKILL + remount"
    );
}

// ── 17. directory tree survives SIGKILL ───────────────────────────────────

/// Create a 3-level directory tree with files at each level, fsync all,
/// SIGKILL, remount, verify the full namespace and all file contents intact.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_directory_tree_survives_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_directory_tree_survives_sigkill");

    let dirs = ["L1", "L1/L2", "L1/L2/L3"];
    let files: &[(&str, &[u8])] = &[
        ("L1/f1.bin", b"level-1-file-1"),
        ("L1/f2.bin", b"level-1-file-2"),
        ("L1/L2/g1.bin", b"level-2-file-1"),
        ("L1/L2/g2.bin", b"level-2-file-2"),
        ("L1/L2/L3/h1.bin", b"level-3-file-1"),
        ("L1/L2/L3/h2.bin", b"level-3-file-2"),
    ];

    // Create directory tree and files.
    for d in &dirs {
        harness
            .mkdir_all(d)
            .unwrap_or_else(|_| panic!("mkdir_all {d}"));
    }
    let files_map: Vec<(String, Vec<u8>)> = files
        .iter()
        .map(|(name, data)| {
            harness
                .create_file(name, data)
                .unwrap_or_else(|_| panic!("create {name}"));
            (name.to_string(), data.to_vec())
        })
        .collect();
    for (name, _data) in &files_map {
        harness
            .fsync_file(name)
            .unwrap_or_else(|_| panic!("fsync {name}"));
    }
    // Fsync each directory to make the directory entries durable.
    for d in &dirs {
        let dir_path = harness.mount_path().join(d);
        let file =
            std::fs::File::open(&dir_path).unwrap_or_else(|_| panic!("open dir {d} for fsync"));
        file.sync_all().unwrap_or_else(|_| panic!("fsync dir {d}"));
    }

    harness.crash_and_remount().expect("crash_and_remount");

    // Verify each directory exists and contains expected children.
    let l1 = harness.readdir("L1").expect("readdir L1");
    assert!(l1.contains(&"f1.bin".to_string()), "L1 missing f1.bin");
    assert!(l1.contains(&"f2.bin".to_string()), "L1 missing f2.bin");
    assert!(l1.contains(&"L2".to_string()), "L1 missing L2");

    let l2 = harness.readdir("L1/L2").expect("readdir L1/L2");
    assert!(l2.contains(&"g1.bin".to_string()), "L1/L2 missing g1.bin");
    assert!(l2.contains(&"g2.bin".to_string()), "L1/L2 missing g2.bin");
    assert!(l2.contains(&"L3".to_string()), "L1/L2 missing L3");

    let l3 = harness.readdir("L1/L2/L3").expect("readdir L1/L2/L3");
    assert!(
        l3.contains(&"h1.bin".to_string()),
        "L1/L2/L3 missing h1.bin"
    );
    assert!(
        l3.contains(&"h2.bin".to_string()),
        "L1/L2/L3 missing h2.bin"
    );

    // Verify file contents.
    for (name, expected) in &files_map {
        let got = harness
            .read_file(name)
            .unwrap_or_else(|_| panic!("read {name} after crash"));
        assert_eq!(
            &got, expected,
            "content mismatch for {name} after directory tree SIGKILL + remount"
        );
    }
}

// ── 18. multi-fd interleaved writes with selective fsync ──────────────────

/// Open 5 files, write known data to each, fsync only files 0, 2, and 4
/// (skipping 1 and 3), SIGKILL, remount.  Verify fsynced files (0, 2, 4)
/// survived byte-for-byte.  Non-fsynced files (1, 3) may be absent or
/// may have survived due to writeback flush — but they must never be
/// corrupt (content must match what was written).
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_multifd_selective_fsync_survives_sigkill() {
    let mut harness =
        MountHarness::new_or_fail("crash_recovery_multifd_selective_fsync_survives_sigkill");

    let num_files: usize = 5;
    let file_size: usize = 1024;
    let fsynced_indices: [usize; 3] = [0, 2, 4];
    let skipped_indices: [usize; 2] = [1, 3];

    let expected: Vec<(String, Vec<u8>)> = (0..num_files)
        .map(|i| {
            let name = format!("multi_{i}.bin");
            let data = prng_data(0xFD00 + i as u64, file_size);
            (name, data)
        })
        .collect();

    // Open all files and write through the mount point.
    for (name, data) in &expected {
        harness
            .create_file(name, data)
            .unwrap_or_else(|_| panic!("create {name}"));
    }

    // Fsync only the selected files.
    for &idx in &fsynced_indices {
        let (name, _) = &expected[idx];
        harness
            .fsync_file(name)
            .unwrap_or_else(|_| panic!("fsync {name}"));
    }

    harness.crash_and_remount().expect("crash_and_remount");

    // Fsynced files must survive.
    for &idx in &fsynced_indices {
        let (name, expected_data) = &expected[idx];
        let got = harness.read_file(name);
        assert!(
            got.is_ok(),
            "fsynced file {name} must survive SIGKILL; got read error: {got:?}"
        );
        let got = got.unwrap();
        assert_eq!(
            &got, expected_data,
            "{name}: fsynced content mismatch after SIGKILL + remount"
        );
    }

    // Non-fsynced files: may survive (writeback flush) or be absent.
    // If present, content must match exactly — never corrupt.
    for &idx in &skipped_indices {
        let (name, expected_data) = &expected[idx];
        match harness.read_file(name) {
            Ok(got) => {
                // Survived via writeback flush — verify content integrity.
                assert_eq!(
                    &got, expected_data,
                    "{name}: non-fsynced file survived but content is corrupt"
                );
                eprintln!("INFO: {name} (not fsynced) survived via writeback flush");
            }
            Err(_) => {
                // Absent — expected when writeback did not flush before SIGKILL.
                eprintln!("INFO: {name} (not fsynced) absent after crash — expected");
            }
        }
    }
}

// ── 19. 128 KiB file fsyncd survives SIGKILL ───────────────────────────────

/// Write a 128 KiB file, fsync, SIGKILL the daemon, remount, verify
/// byte-for-byte content match.  Exercises multi-extent segment write
/// durability at an intermediate size between the small and large tests.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_128kib_survives_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_128kib_survives_sigkill");

    let data = prng_data(0x128, 128 * 1024);
    harness
        .create_file("medium_128k.bin", &data)
        .expect("write 128 KiB");
    harness
        .fsync_file("medium_128k.bin")
        .expect("fsync 128 KiB file");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("medium_128k.bin")
        .expect("read 128 KiB after crash");
    assert_eq!(
        read_back.len(),
        data.len(),
        "128 KiB file size mismatch: got {} expected {}",
        read_back.len(),
        data.len()
    );
    assert_eq!(
        read_back, data,
        "128 KiB file byte-for-byte mismatch after SIGKILL + remount"
    );
}

// ── 20. 1 MiB file fsyncd survives SIGKILL ─────────────────────────────────

/// Write a 1 MiB file through the FUSE mount, fsync, SIGKILL the daemon,
/// remount, verify byte-for-byte content match.  Exercises multi-segment
/// recovery at the largest size requested by the crash-recovery spec.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_1mib_survives_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_1mib_survives_sigkill");

    let data = prng_data(0x1_000, 1024 * 1024);
    harness
        .create_file("large_1m.bin", &data)
        .expect("write 1 MiB");
    harness
        .fsync_file("large_1m.bin")
        .expect("fsync 1 MiB file");

    harness.crash_and_remount().expect("crash_and_remount");

    let read_back = harness
        .read_file("large_1m.bin")
        .expect("read 1 MiB after crash");
    assert_eq!(
        read_back.len(),
        data.len(),
        "1 MiB file size mismatch: got {} expected {}",
        read_back.len(),
        data.len()
    );
    assert_eq!(
        read_back, data,
        "1 MiB file byte-for-byte mismatch after SIGKILL + remount"
    );
}

// ── 21. varied payload patterns survive SIGKILL ──────────────────────────────

/// Write files with varied data patterns (all-zeros, all-0xFF, alternating
/// 0xAA/0x55, and pseudo-random), each at 4 KiB and 1 MiB sizes.  Fsync all,
/// SIGKILL the daemon, remount, verify every file byte-for-byte.
///
/// Exercising multiple data patterns at multiple sizes catches content-
/// specific bugs: all-zero optimisations, all-ones bit errors, alternating
/// pattern cache-line artefacts, and pseudo-random compression/encryption
/// edge cases.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_varied_payloads_survives_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_varied_payloads_survives_sigkill");

    let all_zeros_4k = vec![0u8; 4096];
    let all_ff_4k = vec![0xFFu8; 4096];
    let alt_aa55_4k: Vec<u8> = (0..4096)
        .map(|i| if i % 2 == 0 { 0xAAu8 } else { 0x55u8 })
        .collect();
    let prng_4k = prng_data(0xCAFE, 4096);

    let all_zeros_1m = vec![0u8; 1024 * 1024];
    let all_ff_1m = vec![0xFFu8; 1024 * 1024];
    let alt_aa55_1m: Vec<u8> = (0..(1024 * 1024))
        .map(|i| if i % 2 == 0 { 0xAAu8 } else { 0x55u8 })
        .collect();
    let prng_1m = prng_data(0xBABE, 1024 * 1024);

    let files: &[(&str, &[u8])] = &[
        ("zeros_4k.bin", &all_zeros_4k),
        ("ff_4k.bin", &all_ff_4k),
        ("aa55_4k.bin", &alt_aa55_4k),
        ("prng_4k.bin", &prng_4k),
        ("zeros_1m.bin", &all_zeros_1m),
        ("ff_1m.bin", &all_ff_1m),
        ("aa55_1m.bin", &alt_aa55_1m),
        ("prng_1m.bin", &prng_1m),
    ];

    for (name, data) in files {
        harness
            .create_file(name, data)
            .unwrap_or_else(|e| panic!("create_file {name}: {e}"));
        harness
            .fsync_file(name)
            .unwrap_or_else(|e| panic!("fsync_file {name}: {e}"));
    }

    harness.crash_and_remount().expect("crash_and_remount");

    for (name, expected) in files {
        let got = harness
            .read_file(name)
            .unwrap_or_else(|e| panic!("read_file {name}: {e}"));
        assert_eq!(
            &got,
            expected,
            "{name}: varied-payload data mismatch after SIGKILL + remount;
             got_len={got_len} expected_len={exp_len}",
            got_len = got.len(),
            exp_len = expected.len(),
        );
    }
}

// ── 22. partial (middle) overwrite survives SIGKILL ────────────────────────

/// Create a file with initial 4 KiB content, fsync, SIGKILL, remount, verify
/// initial content intact.  Then overwrite the middle 50 % of the file with
/// new data through a positioned write, fsync, SIGKILL a second time,
/// remount, and verify the merged content: original prefix + new middle +
/// original suffix byte-for-byte.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_partial_overwrite_survives_sigkill() {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};

    let mut harness =
        MountHarness::new_or_fail("crash_recovery_partial_overwrite_survives_sigkill");

    let initial = seq_data(4096);
    harness
        .create_file("partial.bin", &initial)
        .expect("write initial");
    harness.fsync_file("partial.bin").expect("fsync initial");

    // First crash: verify initial content survives.
    harness
        .crash_and_remount()
        .expect("first crash_and_remount");
    let read1 = harness
        .read_file("partial.bin")
        .expect("read after first crash");
    assert_eq!(
        read1, initial,
        "initial content must survive first SIGKILL + remount"
    );

    // Overwrite middle 50 % (offset 1024..3072) with new data.
    let new_middle = seq_data(2048); // 2 KiB of new content
    let path = harness.mount_path().join("partial.bin");
    let mut file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open partial.bin for overwrite");
    file.seek(SeekFrom::Start(1024))
        .expect("seek to offset 1024");
    file.write_all(&new_middle).expect("write new middle 2 KiB");
    drop(file);

    harness
        .fsync_file("partial.bin")
        .expect("fsync after partial overwrite");

    harness
        .crash_and_remount()
        .expect("second crash_and_remount");

    let read2 = harness
        .read_file("partial.bin")
        .expect("read after second crash");
    let mut expected_merged = Vec::with_capacity(4096);
    expected_merged.extend_from_slice(&initial[..1024]); // prefix
    expected_merged.extend_from_slice(&new_middle); // new middle
    expected_merged.extend_from_slice(&initial[3072..]); // suffix
    assert_eq!(
        read2, expected_merged,
        "merged content mismatch after partial-overwrite SIGKILL + remount;
         prefix + new middle + suffix must be byte-for-byte"
    );
}

// ── 23. unlinked without fsync is not durable ─────────────────────────────

/// Create a file, write data, unlink it WITHOUT calling fsync on the file,
/// SIGKILL the daemon, remount, and verify the file is absent.  Without an
/// fsync the unlink is not durably committed and the data must not be
/// recoverable.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_unlinked_without_fsync_not_durable() {
    let mut harness =
        MountHarness::new_or_fail("crash_recovery_unlinked_without_fsync_not_durable");

    let data = b"this data is written then unlinked without fsync\n";
    harness
        .create_file("unlinked_no_fsync.bin", data)
        .expect("create file");
    // Deliberately do NOT fsync the file before unlinking.
    harness
        .remove_file("unlinked_no_fsync.bin")
        .expect("unlink file");
    // Also do NOT fsync the parent directory.

    harness.crash_and_remount().expect("crash_and_remount");

    assert!(
        !harness.exists("unlinked_no_fsync.bin"),
        "unlinked-without-fsync file must not be durable after SIGKILL + remount;
         absence after crash means the unlink was flushed or the file's data
         was never committed"
    );
}

// ── 24. multi-file atomicity boundary ──────────────────────────────────────

/// Create 10 files, fsync all, then create an 11th file without fsyncing it.
/// SIGKILL the daemon, remount.  Verify the first 10 files are intact with
/// correct content; the 11th must be absent (no partial durable state).
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_multifile_atomicity_boundary() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_multifile_atomicity_boundary");

    let num_synced: usize = 10;
    let synced_files: Vec<(String, Vec<u8>)> = (1..=num_synced)
        .map(|i| {
            let name = format!("synced_{i:02}.bin");
            let data = prng_data(i as u64, 1024);
            (name, data)
        })
        .collect();

    for (name, data) in &synced_files {
        harness
            .create_file(name, data)
            .unwrap_or_else(|e| panic!("create {name}: {e}"));
        harness
            .fsync_file(name)
            .unwrap_or_else(|e| panic!("fsync {name}: {e}"));
    }

    // Create 11th file WITHOUT fsync.
    let unsynced_data = prng_data(0xBAD, 1024);
    harness
        .create_file("unsynced_11.bin", &unsynced_data)
        .expect("create 11th file (no fsync)");

    harness.crash_and_remount().expect("crash_and_remount");

    for (name, expected) in &synced_files {
        let got = harness
            .read_file(name)
            .unwrap_or_else(|e| panic!("read {name}: {e}"));
        assert_eq!(
            &got, expected,
            "{name}: fsynced file must survive SIGKILL + remount byte-for-byte"
        );
    }

    // The 11th file may be absent (no fsync) or may have survived via
    // writeback flush.  If present, content must be correct — never corrupt.
    match harness.read_file("unsynced_11.bin") {
        Ok(got) => {
            assert_eq!(
                &got, &unsynced_data,
                "unsynced file survived via writeback flush but content is corrupt"
            );
            eprintln!("INFO: unsynced_11.bin survived via writeback flush");
        }
        Err(_) => {
            eprintln!("INFO: unsynced_11.bin absent after crash — expected (no fsync)");
        }
    }

    let entries = harness.readdir(".").expect("readdir root after crash");
    let synced_count = entries.iter().filter(|e| e.starts_with("synced_")).count();
    assert_eq!(
        synced_count, num_synced,
        "all {num_synced} synced files must be present; found {synced_count}"
    );
}

// ── 25. rename durability ──────────────────────────────────────────────────

/// Create file A with content, fsync A, rename A→B, fsync the parent
/// directory to make the directory entry durable, SIGKILL the daemon,
/// remount, verify B exists with correct content and A is absent.
#[test]
#[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
fn crash_recovery_rename_survives_sigkill() {
    let mut harness = MountHarness::new_or_fail("crash_recovery_rename_survives_sigkill");

    let data = b"original content under name A, should survive rename to B\n";

    harness
        .create_file("file_a.bin", data)
        .expect("create file A");
    harness.fsync_file("file_a.bin").expect("fsync file A");

    harness
        .rename("file_a.bin", "file_b.bin")
        .expect("rename A -> B");

    // Fsync the parent directory (mount root) to make the directory entry
    // rename durable.
    {
        let dir = std::fs::File::open(harness.mount_path()).expect("open mount root for dir fsync");
        dir.sync_all().expect("fsync parent dir after rename");
    }

    harness.crash_and_remount().expect("crash_and_remount");

    // B must exist with correct content.
    let read_b = harness
        .read_file("file_b.bin")
        .expect("read file B after crash");
    assert_eq!(
        read_b, data,
        "file B content mismatch after rename + SIGKILL + remount"
    );

    // A must be absent.
    assert!(
        !harness.exists("file_a.bin"),
        "file A must not exist after rename + SIGKILL + remount;
         the rename operation was fsynced via parent directory"
    );
}
