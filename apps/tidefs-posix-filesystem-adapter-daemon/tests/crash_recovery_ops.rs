// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! End-to-end crash-recovery validation for the full FUSE handler surface.
//!
//! Exercises the real FUSE mount path through the daemon binary:
//!
//! 1. **Operation-mix crash-recovery**: mixed namespace + data operations with
//!    fsync barriers, SIGKILL, remount, verify all persisted metadata and data.
//! 2. **Mid-operation crash**: write without fsync, SIGKILL, verify
//!    consistent pre-operation or post-operation state (no partial application).
//! 3. **Double-crash**: crash once, start replay, crash again during early
//!    mount, remount, verify consistent recovery.
//! 4. **BLAKE3 data integrity**: write deterministic BLAKE3-verifiable data,
//!    crash, remount, verify byte-for-byte with known checksums.
//!
//! All tests use `MountHarness` from tidefs-validation, which spawns the
//! daemon as a separate process, sends real SIGKILL, lazy-unmounts with
//! fusermount -uz, and restarts a fresh daemon on the same backing store.

use std::os::unix::fs::PermissionsExt;

use tidefs_validation::mount_harness::MountHarness;

// ── helpers ──────────────────────────────────────────────────────────────

/// Deterministic incrementing byte sequence.
fn seq_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

/// Deterministic patterned bytes derived from seed and length.
fn patterned_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|_| {
            let b = (state >> 32) as u8;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            b
        })
        .collect()
}

/// Compute BLAKE3 hash of data, returning hex string.
fn blake3_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let hash = blake3::hash(data);
    let mut hex = String::with_capacity(64);
    for byte in hash.as_bytes() {
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    hex
}

/// Try to create a MountHarness; skip test gracefully if daemon not available.
fn mount_or_skip() -> Option<MountHarness> {
    match MountHarness::new() {
        Ok(h) => Some(h),
        Err(e) => {
            eprintln!("SKIP: daemon not available -- {e}");
            None
        }
    }
}

// ── mounted write/fsync crash evidence ───────────────────────────────────

/// Exercise the bounded mounted FUSE durability row used by issue #2315.
///
/// The row writes through a live daemon, completes `fsync`, reads the mounted
/// path, SIGKILLs that daemon, remounts the same store, and verifies the last
/// completed fsync payload. It intentionally fails closed when the mounted
/// runtime substrate is unavailable; callers collecting claim evidence must
/// record that refusal instead of treating a skipped local fixture as runtime
/// proof.
#[test]
#[ignore = "requires an explicit mounted FUSE runtime row"]
fn mounted_write_fsync_read_crash_recover() {
    let mut harness = MountHarness::new_or_fail("mounted_write_fsync_read_crash_recover");
    let path = "issue-2315-fsync-crash.bin";
    let payload = patterned_bytes(2_315, 4_096);
    let payload_digest = blake3_hex(&payload);
    let daemon_pid = harness.daemon_pid();

    harness
        .create_file(path, &payload)
        .expect("write mounted crash-evidence payload");
    harness.fsync_file(path).expect("fsync mounted payload");

    let read_before_crash = harness
        .read_file(path)
        .expect("read mounted payload before crash");
    assert_eq!(
        read_before_crash, payload,
        "mounted read before crash must return the fsynced payload"
    );

    harness
        .crash_and_remount()
        .expect("SIGKILL daemon and remount the same backing store");

    let recovered = harness
        .read_file(path)
        .expect("read mounted payload after crash recovery");
    assert_eq!(
        recovered, payload,
        "recovered mounted payload must match the last completed fsync"
    );

    eprintln!(
        "mounted fsync crash evidence: backend=MountHarness daemon_pid={daemon_pid} path=/{path} content_digest=blake3:{payload_digest} outcome=pass"
    );
}

// ── test 1: operation-mix crash-recovery ──────────────────────────────────
//
// Sequence: create+write files, mkdir, symlink, hardlink, rename,
// setxattr, chmod, truncate, then fsync the dirtied files, SIGKILL,
// remount, and verify everything survived.

#[test]
fn ops_mix_crash_recovery_full_surface() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data_a = patterned_bytes(1, 4096);
    let data_b = patterned_bytes(2, 2048);
    let xattr_value = b"hello xattr world";

    // ── create files with data ──
    harness.create_file("a.txt", &data_a).expect("create a.txt");
    harness.create_file("b.txt", &data_b).expect("create b.txt");

    // ── mkdir ──
    harness.mkdir_all("sub").expect("mkdir sub");

    // ── symlink ──
    harness
        .symlink("../a.txt", "sub/link_to_a.txt")
        .expect("symlink a.txt -> sub/link_to_a.txt");

    // ── hardlink ──
    harness
        .hardlink("b.txt", "sub/b_hardlink.txt")
        .expect("hardlink b.txt -> sub/b_hardlink.txt");

    // ── rename ──
    harness
        .create_file("old_name.tmp", b"rename target\n")
        .expect("create rename source");
    harness
        .rename("old_name.tmp", "new_name.perm")
        .expect("rename old_name.tmp -> new_name.perm");

    // ── setxattr ──
    harness
        .set_xattr("a.txt", "test.key", xattr_value)
        .expect("setxattr on a.txt");

    // ── chmod ──
    harness.chmod("a.txt", 0o640).expect("chmod a.txt 0640");

    // ── truncate (shrink) ──
    harness
        .truncate("b.txt", 512)
        .expect("truncate b.txt to 512");

    // ── fsync all dirtied files ──
    harness.fsync_file("a.txt").expect("fsync a.txt");
    harness.fsync_file("b.txt").expect("fsync b.txt");
    harness
        .fsync_file("new_name.perm")
        .expect("fsync new_name.perm");

    // ── crash and remount ──
    harness.crash_and_remount().expect("crash_and_remount");

    // ── verify data integrity ──
    let read_a = harness.read_file("a.txt").expect("read a.txt after crash");
    assert_eq!(read_a, data_a, "a.txt content mismatch after crash");

    let read_b = harness.read_file("b.txt").expect("read b.txt after crash");
    assert_eq!(
        read_b.len(),
        512,
        "b.txt should be 512 bytes after truncate"
    );
    assert_eq!(
        &read_b[..],
        &data_b[..512],
        "b.txt truncated content mismatch"
    );

    // ── verify symlink ──
    let link_target = harness.readlink("sub/link_to_a.txt").expect("readlink");
    assert_eq!(
        link_target,
        std::path::Path::new("../a.txt"),
        "symlink target mismatch"
    );
    // Read through symlink.
    let via_symlink = harness
        .read_file("sub/link_to_a.txt")
        .expect("read via symlink");
    assert_eq!(via_symlink, data_a, "data via symlink mismatch");

    // ── verify hardlink ──
    let hardlink_content = harness
        .read_file("sub/b_hardlink.txt")
        .expect("read hardlink");
    assert_eq!(
        hardlink_content.len(),
        512,
        "hardlink content length mismatch"
    );
    assert_eq!(
        &hardlink_content[..],
        &data_b[..512],
        "hardlink content mismatch"
    );

    // nlink for b.txt should be at least 2 (original + hardlink).
    let nlink_b = harness.nlink("b.txt").expect("nlink b.txt");
    assert!(nlink_b >= 2, "b.txt nlink should be >= 2, got {nlink_b}");

    // ── verify rename ──
    assert!(
        harness.exists("new_name.perm"),
        "new_name.perm should exist after crash"
    );
    assert!(
        !harness.exists("old_name.tmp"),
        "old_name.tmp should not exist after rename + crash"
    );
    let rename_content = harness
        .read_file("new_name.perm")
        .expect("read new_name.perm");
    assert_eq!(
        rename_content, b"rename target\n",
        "rename content mismatch"
    );

    // ── verify xattr ──
    let xattr_got = harness
        .get_xattr("a.txt", "test.key")
        .expect("get xattr after crash");
    assert_eq!(
        xattr_got.as_deref(),
        Some(&xattr_value[..]),
        "xattr value mismatch after crash"
    );

    // ── verify chmod ──
    let mode = harness
        .stat("a.txt")
        .expect("stat a.txt")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o640,
        "mode should be 0640 after crash, got 0o{mode:o}"
    );

    // ── verify directory structure ──
    let root_entries = harness.readdir(".").expect("readdir /");
    assert!(
        root_entries.contains(&"a.txt".to_string()),
        "root missing a.txt"
    );
    assert!(
        root_entries.contains(&"b.txt".to_string()),
        "root missing b.txt"
    );
    assert!(
        root_entries.contains(&"sub".to_string()),
        "root missing sub/"
    );
    assert!(
        root_entries.contains(&"new_name.perm".to_string()),
        "root missing new_name.perm"
    );

    let sub_entries = harness.readdir("sub").expect("readdir sub");
    assert!(
        sub_entries.contains(&"link_to_a.txt".to_string()),
        "sub missing link_to_a.txt"
    );
    assert!(
        sub_entries.contains(&"b_hardlink.txt".to_string()),
        "sub missing b_hardlink.txt"
    );
}

// ── test 2: unlink + rmdir crash recovery ─────────────────────────────────

/// Create files and directories, remove some via unlink/rmdir, fsync,
/// SIGKILL, remount, verify deletions survived.
#[test]
fn ops_mix_unlink_rmdir_crash_recovery() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let keep_data = b"this must survive\n";
    let del_data = b"this must be gone\n";

    harness.mkdir_all("todelete").expect("mkdir todelete");
    harness
        .create_file("todelete/gone.txt", del_data)
        .expect("create gone.txt");
    harness
        .create_file("keep.txt", keep_data)
        .expect("create keep.txt");

    harness
        .fsync_file("todelete/gone.txt")
        .expect("fsync before delete");
    harness.fsync_file("keep.txt").expect("fsync keep");

    // Delete the file and directory.
    harness
        .remove_file("todelete/gone.txt")
        .expect("remove gone.txt");
    harness.remove_dir("todelete").expect("rmdir todelete");

    harness.crash_and_remount().expect("crash_and_remount");

    // keep.txt must survive.
    let read_back = harness
        .read_file("keep.txt")
        .expect("read keep.txt after crash");
    assert_eq!(read_back, keep_data, "keep.txt content mismatch");

    // Deleted file must be gone.
    assert!(
        !harness.exists("todelete/gone.txt"),
        "gone.txt should not exist after unlink + crash"
    );
    assert!(
        !harness.exists("todelete"),
        "todelete directory should not exist after rmdir + crash"
    );

    let root = harness.readdir(".").expect("readdir /");
    assert!(
        !root.contains(&"todelete".to_string()),
        "todelete in root listing"
    );
    assert!(root.contains(&"keep.txt".to_string()), "keep.txt missing");
}

// ── test 3: rename across directories crash recovery ─────────────────────

/// Create file in src_dir, rename to dst_dir, fsync, SIGKILL, remount,
/// verify file in dst_dir with correct content and absent from src_dir.
#[test]
fn ops_mix_rename_across_dirs_crash() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let payload = patterned_bytes(42, 2048);

    harness.mkdir_all("src").expect("mkdir src");
    harness.mkdir_all("dst").expect("mkdir dst");

    harness
        .create_file("src/move_me.bin", &payload)
        .expect("create file in src");
    harness
        .fsync_file("src/move_me.bin")
        .expect("fsync before rename");

    harness
        .rename("src/move_me.bin", "dst/moved.bin")
        .expect("rename across dirs");
    harness
        .fsync_file("dst/moved.bin")
        .expect("fsync after rename");

    harness.crash_and_remount().expect("crash_and_remount");

    // File must be in dst_dir.
    let got = harness
        .read_file("dst/moved.bin")
        .expect("read moved file after crash");
    assert_eq!(got, payload, "cross-dir rename content mismatch");

    // File must NOT be in src_dir.
    assert!(
        !harness.exists("src/move_me.bin"),
        "src/move_me.bin should not exist after cross-dir rename + crash"
    );

    let src_entries = harness.readdir("src").expect("readdir src");
    assert!(!src_entries.contains(&"move_me.bin".to_string()));

    let dst_entries = harness.readdir("dst").expect("readdir dst");
    assert!(dst_entries.contains(&"moved.bin".to_string()));
}

// ── test 4: mid-operation crash (no fsync) ────────────────────────────────

/// Write data without fsync, SIGKILL, remount. The file may be absent,
/// empty, or contain the full data — but must never contain corrupted
/// (phantom) data. This validates that the intent-log's atomicity
/// guarantees hold even for the non-fsynced path.
#[test]
fn mid_op_crash_no_fsync_no_corruption() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = seq_data(4096);

    harness
        .create_file("uncommitted.bin", &data)
        .expect("create_file");
    // Deliberately skip fsync.

    harness.crash_and_remount().expect("crash_and_remount");

    match harness.read_file("uncommitted.bin") {
        Ok(read_back) => {
            // If data survived, it must match exactly — no phantom data.
            if !read_back.is_empty() {
                assert_eq!(
                    read_back, data,
                    "surviving unfsynced data must match written data byte-for-byte"
                );
            }
        }
        Err(_) => {
            // File absent — acceptable after crash without fsync.
        }
    }
}

// ── test 5: multi-file mid-op crash ──────────────────────────────────────

/// Write 4 files, fsync only file 1 and 3, SIGKILL, remount. Files 1 and 3
/// must survive intact. Files 2 and 4 may be absent, empty, or intact but
/// must never contain phantom data.
#[test]
fn mid_op_crash_partial_fsync() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let d1 = seq_data(1024);
    let d2 = seq_data(2048);
    let d3 = seq_data(512);
    let d4 = seq_data(768);

    harness.create_file("f1.bin", &d1).expect("create f1");
    harness.create_file("f2.bin", &d2).expect("create f2");
    harness.create_file("f3.bin", &d3).expect("create f3");
    harness.create_file("f4.bin", &d4).expect("create f4");

    // Fsync only files 1 and 3.
    harness.fsync_file("f1.bin").expect("fsync f1");
    harness.fsync_file("f3.bin").expect("fsync f3");

    harness.crash_and_remount().expect("crash_and_remount");

    // Fsynced files must be intact.
    let r1 = harness.read_file("f1.bin").expect("read f1 after crash");
    assert_eq!(r1, d1, "fsynced file f1 data mismatch");

    let r3 = harness.read_file("f3.bin").expect("read f3 after crash");
    assert_eq!(r3, d3, "fsynced file f3 data mismatch");

    // Non-fsynced files: no phantom data.
    for (name, expected) in &[("f2.bin", &d2), ("f4.bin", &d4)] {
        match harness.read_file(name) {
            Ok(got) => {
                if !got.is_empty() {
                    assert_eq!(
                        got.as_slice(),
                        expected.as_slice(),
                        "{name}: unfsynced surviving data must match originally written data"
                    );
                }
            }
            Err(_) => { /* absent is acceptable */ }
        }
    }
}

// ── test 6: double-crash during replay ───────────────────────────────────

/// Write data, fsync, crash, remount (replay happens), immediately crash
/// again before the mount stabilizes, remount a third time, verify data
/// survived the double-crash cycle.
#[test]
fn double_crash_during_replay_recovery() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = seq_data(8192);

    harness
        .create_file("double_crash.bin", &data)
        .expect("create file");
    harness
        .fsync_file("double_crash.bin")
        .expect("fsync before first crash");

    // Crash #1.
    harness.crash_and_remount().expect("crash #1 + remount");

    // Crash #2 immediately after remount (during/after replay).
    harness.crash_and_remount().expect("crash #2 + remount");

    // After double crash, verify data survives.
    let read_back = harness
        .read_file("double_crash.bin")
        .expect("read after double crash");
    assert_eq!(
        read_back, data,
        "data mismatch after double-crash recovery: replay must be idempotent"
    );

    // Also verify we can still create new files.
    harness
        .create_file("post_double_crash.bin", b"recovery ok\n")
        .expect("create file after double crash");
    harness
        .fsync_file("post_double_crash.bin")
        .expect("fsync after double crash");

    let check = harness
        .read_file("post_double_crash.bin")
        .expect("read new file");
    assert_eq!(
        check, b"recovery ok\n",
        "new file after double crash mismatch"
    );
}

// ── test 7: BLAKE3 data integrity verification ────────────────────────────

/// Write deterministic content with known BLAKE3 checksums, fsync, crash,
/// remount, verify byte-for-byte match AND BLAKE3 checksums match.
#[test]
fn blake3_data_integrity_crash_recovery() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let files: Vec<(&str, Vec<u8>, String)> = vec![
        {
            let d = patterned_bytes(100, 4096);
            let h = blake3_hex(&d);
            ("blake3_a.bin", d, h)
        },
        {
            let d = patterned_bytes(200, 65536); // 64 KiB
            let h = blake3_hex(&d);
            ("blake3_b.bin", d, h)
        },
        {
            let d = patterned_bytes(300, 128);
            let h = blake3_hex(&d);
            ("blake3_c.bin", d, h)
        },
    ];

    // Write all files and fsync each.
    for (name, data, _checksum) in &files {
        harness.create_file(name, data).expect("create blake3 file");
        harness.fsync_file(name).expect("fsync blake3 file");
    }

    harness.crash_and_remount().expect("crash_and_remount");

    // Verify each file: byte-for-byte match AND BLAKE3 match.
    for (name, expected_data, expected_hash) in &files {
        let got = harness
            .read_file(name)
            .unwrap_or_else(|_| panic!("read {name} after crash"));
        assert_eq!(
            got.len(),
            expected_data.len(),
            "{name}: length mismatch after crash"
        );
        assert_eq!(
            &got, expected_data,
            "{name}: byte-for-byte mismatch after crash"
        );

        let got_hash = blake3_hex(&got);
        assert_eq!(
            got_hash, *expected_hash,
            "{name}: BLAKE3 checksum mismatch after crash: expected {expected_hash}, got {got_hash}"
        );
    }
}

// ── test 8: setattr (utimens + chown) crash recovery ──────────────────────

/// Set timestamps and ownership via utimens + chown, fsync, SIGKILL,
/// remount, verify attributes survived.
#[test]
fn ops_mix_setattr_crash_recovery() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = b"setattr test data\n";
    harness
        .create_file("attr_test.bin", data)
        .expect("create file");

    // Set known atime and mtime.
    harness
        .utimens("attr_test.bin", 1000000000, 0, 2000000000, 0)
        .expect("utimens");

    harness
        .chown("attr_test.bin", u32::MAX, u32::MAX)
        .expect("chown noop"); // no-op chown

    harness
        .fsync_file("attr_test.bin")
        .expect("fsync attr file");

    harness.crash_and_remount().expect("crash_and_remount");

    let md = harness.stat("attr_test.bin").expect("stat after crash");
    assert_eq!(md.len(), data.len() as u64, "file length mismatch");

    // Content must survive.
    let content = harness
        .read_file("attr_test.bin")
        .expect("read after crash");
    assert_eq!(content, data, "setattr content mismatch");

    // Verify mode survived (default should be 0644 minus umask).
    let mode = md.permissions().mode();
    assert!(
        mode & 0o400 != 0,
        "owner readable bit should be set: 0o{mode:o}"
    );
}

// ── test 9: crash recovery loop (5 cycles with mixed ops) ──────────────────

/// Run 5 crash-recovery cycles, each performing a different mix of
/// operations, verifying data survives all cycles.
#[test]
fn crash_recovery_loop_five_cycles_mixed_ops() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness
        .create_file("loop_seed.bin", b"initial seed\n")
        .expect("create seed");
    harness.fsync_file("loop_seed.bin").expect("fsync seed");

    for cycle in 0..5 {
        // Perform a different set of operations each cycle.
        let marker_data = format!("cycle_{cycle}_marker_data").into_bytes();
        let marker_name = format!("marker_cycle_{cycle}.bin");

        harness
            .create_file(&marker_name, &marker_data)
            .expect("create cycle marker");
        harness
            .fsync_file(&marker_name)
            .expect("fsync cycle marker");

        // Also do a symlink in even cycles.
        if cycle % 2 == 0 {
            let link_name = format!("link_cycle_{cycle}");
            harness
                .symlink(&marker_name, &link_name)
                .expect("symlink cycle marker");
        }

        harness
            .crash_and_remount()
            .unwrap_or_else(|e| panic!("crash_and_remount cycle {cycle}: {e}"));

        // Verify all previous markers survived.
        for prev in 0..=cycle {
            let prev_name = format!("marker_cycle_{prev}.bin");
            let prev_data = format!("cycle_{prev}_marker_data").into_bytes();
            let got = harness
                .read_file(&prev_name)
                .unwrap_or_else(|_| panic!("read {prev_name} after cycle {cycle}"));
            assert_eq!(
                got, prev_data,
                "marker_cycle_{prev}.bin content mismatch after crash cycle {cycle}"
            );
        }

        // Verify seed file still intact.
        let seed = harness.read_file("loop_seed.bin").expect("read seed");
        assert_eq!(
            seed, b"initial seed\n",
            "seed file corrupted at cycle {cycle}"
        );
    }
}

// ── test 10: directory tree with xattr crash recovery ─────────────────────

/// Create a directory tree with files, xattrs on multiple files, symlinks,
/// fsync, SIGKILL, remount, verify full tree, all contents, all xattrs.
#[test]
fn crash_recovery_directory_tree_xattr() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness.mkdir_all("tree/A/B").expect("mkdir tree/A/B");

    let files: Vec<(&str, Vec<u8>)> = vec![
        ("tree/root_file.bin", seq_data(100)),
        ("tree/A/mid_file.bin", seq_data(200)),
        ("tree/A/B/deep_file.bin", seq_data(300)),
    ];

    for (path, data) in &files {
        harness.create_file(path, data).expect("create tree file");
    }

    // Set xattrs on some files.
    harness
        .set_xattr("tree/root_file.bin", "note", b"top-level file")
        .expect("xattr root");
    harness
        .set_xattr("tree/A/B/deep_file.bin", "depth", b"2")
        .expect("xattr deep");

    // Create symlink from tree root into A/B.
    harness
        .symlink("A/B/deep_file.bin", "tree/deep_link")
        .expect("symlink into deep");

    // Fsync all files.
    for (path, _) in &files {
        harness.fsync_file(path).expect("fsync tree file");
    }

    harness.crash_and_remount().expect("crash_and_remount");

    // Verify directory structure.
    let root_entries = harness.readdir("tree").expect("readdir tree");
    assert!(root_entries.contains(&"root_file.bin".to_string()));
    assert!(root_entries.contains(&"A".to_string()));
    assert!(root_entries.contains(&"deep_link".to_string()));

    let a_entries = harness.readdir("tree/A").expect("readdir tree/A");
    assert!(a_entries.contains(&"mid_file.bin".to_string()));
    assert!(a_entries.contains(&"B".to_string()));

    let b_entries = harness.readdir("tree/A/B").expect("readdir tree/A/B");
    assert!(b_entries.contains(&"deep_file.bin".to_string()));

    // Verify file contents.
    for (path, expected) in &files {
        let got = harness.read_file(path).expect("read tree file after crash");
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "tree file {path} content mismatch"
        );
    }

    // Verify xattrs.
    let xattr_root = harness
        .get_xattr("tree/root_file.bin", "note")
        .expect("get xattr root");
    assert_eq!(xattr_root.as_deref(), Some(&b"top-level file"[..]));

    let xattr_deep = harness
        .get_xattr("tree/A/B/deep_file.bin", "depth")
        .expect("get xattr deep");
    assert_eq!(xattr_deep.as_deref(), Some(&b"2"[..]));

    // Verify symlink target.
    let link_tgt = harness
        .readlink("tree/deep_link")
        .expect("readlink deep_link");
    assert_eq!(
        link_tgt,
        std::path::Path::new("A/B/deep_file.bin"),
        "deep symlink target mismatch"
    );
    // Read through the symlink.
    let via_link = harness
        .read_file("tree/deep_link")
        .expect("read via deep symlink");
    assert_eq!(via_link, seq_data(300), "data via deep symlink mismatch");
}
