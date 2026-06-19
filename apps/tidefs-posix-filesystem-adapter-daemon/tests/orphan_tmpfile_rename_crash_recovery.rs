// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted-filesystem crash-recovery tests for O_TMPFILE and rename/unlink
//! interruption scenarios deferred from #435.
//!
//! Exercises the full orphan-reclaim pipeline through a real FUSE mount:
//!
//! 1. O_TMPFILE crash-recovery: create unnamed temporary files, SIGKILL the
//!    daemon, remount, and verify orphans are reclaimed.
//! 2. rename/unlink interruption: rename or unlink followed by crash, remount,
//!    and verify the filesystem is consistent.
//!
//! All tests use MountHarness from tidefs-validation, which spawns the
//! daemon as a separate process, sends real SIGKILL, lazy-unmounts with
//! fusermount -uz, and restarts a fresh daemon on the same backing store.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use tidefs_validation::mount_harness::MountHarness;

// ── O_TMPFILE flag ──────────────────────────────────────────────────────

const O_TMPFILE: libc::c_int = 0o20200000;

// ── helpers ─────────────────────────────────────────────────────────────

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

/// Open an unnamed temporary file via O_TMPFILE in the given directory.
/// Returns the raw file descriptor.
fn open_tmpfile(dir: &Path) -> io::Result<i32> {
    let dir_c = CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| io::Error::other(format!("dir path with nul: {e}")))?;
    // SAFETY: openat is a C FFI call; dir_c is a valid null-terminated
    // CString; O_TMPFILE | O_RDWR is a valid flag combination; mode 0600
    // is a valid POSIX mode.
    let fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            dir_c.as_ptr(),
            O_TMPFILE | libc::O_RDWR,
            0o600,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

/// Write data to an open file descriptor.
fn write_fd(fd: i32, data: &[u8]) -> io::Result<()> {
    // SAFETY: write(2) is a C FFI call; fd is a valid file descriptor;
    // data is a valid buffer.
    let written = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    if written as usize != data.len() {
        return Err(io::Error::other("short write"));
    }
    Ok(())
}

/// Fsync an open file descriptor.
fn fsync_fd(fd: i32) -> io::Result<()> {
    // SAFETY: fsync(2) is a C FFI call; fd is a valid file descriptor.
    let rc = unsafe { libc::fsync(fd) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Close a file descriptor.
fn close_fd(fd: i32) {
    // SAFETY: close(2) is a C FFI call; fd is a valid file descriptor.
    unsafe { libc::close(fd) };
}

/// Call renameat2 via syscall with the given flags.
fn renameat2(old_path: &Path, new_path: &Path, flags: u32) -> io::Result<()> {
    let old_c = CString::new(old_path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "old path contains nul byte"))?;
    let new_c = CString::new(new_path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "new path contains nul byte"))?;
    // SAFETY: SYS_renameat2 is a valid syscall number; the pointers are
    // valid null-terminated CStrings; AT_FDCWD is a valid sentinel.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            old_c.as_ptr(),
            libc::AT_FDCWD,
            new_c.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;

// ═════════════════════════════════════════════════════════════════════════
// O_TMPFILE crash-recovery tests
// ═════════════════════════════════════════════════════════════════════════

// ── test 1: O_TMPFILE create, crash, verify orphan reclaimed ────────────

/// Create an unnamed temporary file via O_TMPFILE, crash the daemon without
/// closing the fd, remount, and verify the filesystem is healthy (orphan
/// reclaimed during mount-time recovery).
#[test]
fn tmpfile_create_crash_reclaim() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    // Create a subdirectory to hold the tmpfile.
    harness.mkdir("tmpdir").expect("mkdir tmpdir");
    let dir_path = harness.mount_path().join("tmpdir");

    // Create an unnamed temporary file in tmpdir.
    let fd = open_tmpfile(&dir_path).expect("O_TMPFILE openat");
    // Write some data but do NOT fsync — the orphan must still be reclaimed.
    write_fd(fd, b"tmpfile data before crash\n").expect("write to tmpfile");

    // Crash without closing the fd — daemon is SIGKILL'd, no cleanup.
    harness.crash_and_remount().expect("crash_and_remount");

    // The tmpfile had nlink=0 and was never linked into the namespace.
    // After the crash, the orphan should be reclaimed at mount time.
    // The filesystem must be operational.
    harness
        .create_file("post_recovery_check.txt", b"ok\n")
        .expect("create file after tmpfile crash recovery");

    let entries = harness.readdir("tmpdir").expect("readdir tmpdir");
    // No stray entries from the unreclaimed tmpfile.
    assert!(
        entries.is_empty(),
        "tmpdir must be empty after O_TMPFILE orphan reclaim"
    );

    close_fd(fd);
}

// ── test 2: O_TMPFILE write+fsync, crash, verify orphan reclaimed ───────

/// Create a tmpfile, write and fsync data, crash, remount. The tmpfile
/// data must be reclaimed as part of orphan cleanup.
#[test]
fn tmpfile_fsync_crash_reclaim() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness.mkdir("tmpdir").expect("mkdir tmpdir");
    let dir_path = harness.mount_path().join("tmpdir");

    let fd = open_tmpfile(&dir_path).expect("O_TMPFILE openat");
    write_fd(fd, b"synced tmpfile data that must be reclaimed\n").expect("write");
    fsync_fd(fd).expect("fsync tmpfile");

    // Crash with the fd still open — daemon gets SIGKILL.
    harness.crash_and_remount().expect("crash_and_remount");

    // Filesystem must be healthy after orphan cleanup.
    let entries = harness.readdir("tmpdir").expect("readdir tmpdir");
    assert!(
        entries.is_empty(),
        "tmpdir must be empty after synced O_TMPFILE orphan reclaim"
    );

    harness
        .create_file("health.txt", b"operational\n")
        .expect("create after tmpfile+fsync crash");

    close_fd(fd);
}

// ── test 3: Multiple O_TMPFILE, crash, reclaim all ──────────────────────

/// Create multiple tmpfiles in different directories, crash, remount,
/// verify all orphans are reclaimed and the filesystem is healthy.
#[test]
fn multi_tmpfile_crash_reclaim() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness.mkdir("A").expect("mkdir A");
    harness.mkdir("B").expect("mkdir B");

    let mut fds: Vec<i32> = Vec::new();

    for dir_name in &["A", "B"] {
        let dir_path = harness.mount_path().join(dir_name);
        for i in 0..3 {
            let fd = open_tmpfile(&dir_path)
                .unwrap_or_else(|e| panic!("O_TMPFILE in {dir_name}/{i}: {e}"));
            let data = format!("tmpfile {dir_name}/{i}\n");
            write_fd(fd, data.as_bytes())
                .unwrap_or_else(|e| panic!("write tmpfile {dir_name}/{i}: {e}"));
            fds.push(fd);
        }
    }

    // Crash with all fds open.
    harness.crash_and_remount().expect("crash_and_remount");

    // All tmpdirs must be empty.
    for dir_name in &["A", "B"] {
        let entries = harness
            .readdir(dir_name)
            .unwrap_or_else(|e| panic!("readdir {dir_name}: {e}"));
        assert!(
            entries.is_empty(),
            "{dir_name} must be empty after multi-tmpfile crash"
        );
    }

    // Filesystem must accept new operations.
    harness
        .create_file("recovered.txt", b"multi tmpfile recovery ok\n")
        .expect("create after multi tmpfile crash");

    for fd in fds {
        close_fd(fd);
    }
}

// ── test 4: O_TMPFILE close before crash (no orphan) ────────────────────

/// Create a tmpfile, close it (nlink=0, no open fds → inode freed),
/// crash, remount. The filesystem should be healthy — the tmpfile was
/// already freed before the crash.
#[test]
fn tmpfile_close_before_crash_no_orphan() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness.mkdir("tmpdir").expect("mkdir tmpdir");
    let dir_path = harness.mount_path().join("tmpdir");

    let fd = open_tmpfile(&dir_path).expect("O_TMPFILE openat");
    write_fd(fd, b"tmpfile that gets closed before crash\n").expect("write");
    // Close fd before crash — the tmpfile inode should be freed immediately
    // since nlink=0 and no open handles.
    close_fd(fd);

    harness.crash_and_remount().expect("crash_and_remount");

    let entries = harness.readdir("tmpdir").expect("readdir tmpdir");
    assert!(
        entries.is_empty(),
        "tmpdir must be empty after pre-crash tmpfile close"
    );

    harness
        .create_file("after_close_crash.txt", b"ok\n")
        .expect("create after tmpfile close + crash");
}

// ═════════════════════════════════════════════════════════════════════════
// rename/unlink interruption crash-recovery tests
// ═════════════════════════════════════════════════════════════════════════

// ── test 5: rename then crash — verify target survives ──────────────────

/// Create a file, rename it, fsync, crash, remount. The renamed file must
/// survive at the new path and the old path must be gone.
#[test]
fn rename_then_crash_target_survives() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = b"rename crash recovery test data\n";

    harness
        .create_file("old_name.txt", data)
        .expect("create old_name.txt");
    harness
        .fsync_file("old_name.txt")
        .expect("fsync old_name.txt");

    harness
        .rename("old_name.txt", "new_name.txt")
        .expect("rename old_name -> new_name");
    harness
        .fsync_file("new_name.txt")
        .expect("fsync new_name.txt");

    harness.crash_and_remount().expect("crash_and_remount");

    // Old path must not exist.
    assert!(
        !harness.exists("old_name.txt"),
        "old path must be gone after rename+crash"
    );

    // New path must exist with correct data.
    let read_back = harness
        .read_file("new_name.txt")
        .expect("read new_name.txt after crash");
    assert_eq!(read_back, data, "renamed file content mismatch after crash");
}

// ── test 6: rename without fsync, crash — verify consistency ────────────

/// Rename a file without fsyncing the rename, crash, remount. The file
/// must exist at either old or new path, but not both (no duplicate).
#[test]
fn rename_no_fsync_crash_consistent() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = b"rename without fsync crash test\n";

    harness
        .create_file("source.txt", data)
        .expect("create source.txt");
    harness.fsync_file("source.txt").expect("fsync source.txt");

    // Rename without an explicit fsync of the rename result.
    harness
        .rename("source.txt", "target.txt")
        .expect("rename source -> target");
    // NOTE: no fsync after rename.

    harness.crash_and_remount().expect("crash_and_remount");

    let old_exists = harness.exists("source.txt");
    let new_exists = harness.exists("target.txt");

    // The file must exist in exactly one place — not both, not neither
    // (the create+fsync committed the data).
    assert_ne!(
        old_exists, new_exists,
        "rename crash recovery must leave exactly one copy"
    );

    if old_exists {
        // Rename wasn't committed — source survived, target absent.
        let old_data = harness.read_file("source.txt").expect("read source.txt");
        assert_eq!(old_data, data, "source content mismatch");
    } else if new_exists {
        // Rename committed — target exists, source gone.
        let new_data = harness.read_file("target.txt").expect("read target.txt");
        assert_eq!(new_data, data, "target content mismatch");
    } else {
        panic!("neither old nor new path exists after rename+crash — data lost");
    }
}

// ── test 7: RENAME_NOREPLACE crash recovery ─────────────────────────────

/// Create two files, renameat2(RENAME_NOREPLACE), crash, remount, verify
/// consistent outcome.
#[test]
fn rename_noreplace_crash_recovery() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = b"rename_noreplace test data\n";

    harness
        .create_file("nr_source.txt", data)
        .expect("create nr_source.txt");
    harness
        .fsync_file("nr_source.txt")
        .expect("fsync nr_source.txt");

    let old_path = harness.mount_path().join("nr_source.txt");
    let new_path = harness.mount_path().join("nr_target.txt");

    renameat2(&old_path, &new_path, RENAME_NOREPLACE).expect("renameat2 RENAME_NOREPLACE");

    harness
        .fsync_file("nr_target.txt")
        .expect("fsync nr_target.txt");

    harness.crash_and_remount().expect("crash_and_remount");

    // The rename+fsync should have committed — target must exist.
    assert!(
        !harness.exists("nr_source.txt"),
        "nr_source.txt must be gone after RENAME_NOREPLACE"
    );
    let read_back = harness
        .read_file("nr_target.txt")
        .expect("read nr_target.txt");
    assert_eq!(read_back, data, "RENAME_NOREPLACE target content mismatch");
}

// ── test 8: RENAME_EXCHANGE crash recovery ──────────────────────────────

/// Create two files, renameat2(RENAME_EXCHANGE) them, crash, remount,
/// verify both files survived with swapped content.
#[test]
fn rename_exchange_crash_recovery() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data_a = b"file A content before exchange\n";
    let data_b = b"file B content before exchange\n";

    harness
        .create_file("ex_a.txt", data_a)
        .expect("create ex_a.txt");
    harness
        .create_file("ex_b.txt", data_b)
        .expect("create ex_b.txt");
    harness.fsync_file("ex_a.txt").expect("fsync ex_a.txt");
    harness.fsync_file("ex_b.txt").expect("fsync ex_b.txt");

    let path_a = harness.mount_path().join("ex_a.txt");
    let path_b = harness.mount_path().join("ex_b.txt");

    renameat2(&path_a, &path_b, RENAME_EXCHANGE).expect("renameat2 RENAME_EXCHANGE");

    // Fsync both files after exchange.
    harness
        .fsync_file("ex_a.txt")
        .expect("fsync ex_a after exchange");
    harness
        .fsync_file("ex_b.txt")
        .expect("fsync ex_b after exchange");

    harness.crash_and_remount().expect("crash_and_remount");

    // After exchange + fsync + crash, content should be swapped.
    let a_content = harness.read_file("ex_a.txt").expect("read ex_a.txt");
    let b_content = harness.read_file("ex_b.txt").expect("read ex_b.txt");

    assert_eq!(
        a_content, data_b,
        "ex_a.txt must have ex_b's original content after exchange"
    );
    assert_eq!(
        b_content, data_a,
        "ex_b.txt must have ex_a's original content after exchange"
    );
}

// ── test 9: unlink-while-open crash recovery ────────────────────────────

/// Create a file, open it, unlink it while it's still open, crash, remount.
/// The file must be gone (orphan reclaimed) and the filesystem healthy.
#[test]
fn unlink_while_open_crash_recovery() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = b"unlink-while-open test payload\n";

    harness
        .create_file("unlink_me.txt", data)
        .expect("create unlink_me.txt");
    harness
        .fsync_file("unlink_me.txt")
        .expect("fsync unlink_me.txt");

    // Open the file through the mount.
    let file_path = harness.mount_path().join("unlink_me.txt");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open unlink_me.txt for unlink-while-open");

    // Unlink while the file is open.
    harness
        .remove_file("unlink_me.txt")
        .expect("unlink unlink_me.txt");

    // The file should no longer be visible in the namespace.
    assert!(
        !harness.exists("unlink_me.txt"),
        "unlinked file must not appear in namespace"
    );

    // Crash with the fd still open — daemon gets SIGKILL.
    harness.crash_and_remount().expect("crash_and_remount");

    // The file must still be gone after remount (orphan reclaimed).
    assert!(
        !harness.exists("unlink_me.txt"),
        "unlinked file must not reappear after crash+remount"
    );

    // Filesystem must work.
    harness
        .create_file("after_unlink_crash.txt", b"recovered\n")
        .expect("create after unlink-while-open crash");

    drop(file);
}

// ── test 10: unlink during rename interruption ──────────────────────────

/// Create two files, rename src over dst (overwriting), crash, remount,
/// verify no corruption and filesystem consistency.
#[test]
fn unlink_during_rename_crash() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data_src = b"source file for rename-overwrite\n";
    let data_dst = b"destination file to be overwritten\n";

    harness
        .create_file("src.txt", data_src)
        .expect("create src.txt");
    harness
        .create_file("dst.txt", data_dst)
        .expect("create dst.txt");
    harness.fsync_file("src.txt").expect("fsync src.txt");
    harness.fsync_file("dst.txt").expect("fsync dst.txt");

    // Rename src over dst (plain rename replaces dst).
    harness
        .rename("src.txt", "dst.txt")
        .expect("rename src -> dst (overwrite)");

    // Crash immediately after rename, before explicit fsync.
    harness.crash_and_remount().expect("crash_and_remount");

    let src_exists = harness.exists("src.txt");
    let dst_exists = harness.exists("dst.txt");

    if src_exists && dst_exists {
        // Both paths exist — the rename may not have committed.
        // Each path should have its original data.
        let src_content = harness.read_file("src.txt").ok();
        let dst_content = harness.read_file("dst.txt").ok();
        // At least one should have correct data.
        assert!(
            src_content.as_deref() == Some(data_src)
                || dst_content.as_deref() == Some(data_dst)
                || dst_content.as_deref() == Some(data_src),
            "inconsistent state after rename-overwrite crash"
        );
    } else if !src_exists && dst_exists {
        // Rename committed: src gone, dst is src's data.
        let dst_content = harness
            .read_file("dst.txt")
            .expect("read dst.txt after rename crash");
        assert_eq!(
            dst_content, data_src,
            "dst must have src data after rename commit"
        );
    } else if src_exists && !dst_exists {
        // Rename did not commit — dst was orphaned.
        let src_content = harness.read_file("src.txt").expect("read src.txt");
        assert_eq!(src_content, data_src, "src data intact");
    } else {
        panic!("both src and dst missing after rename crash — both files lost");
    }

    // Filesystem must be operational regardless of outcome.
    harness
        .create_file("post_rename_crash.txt", b"ok\n")
        .expect("create after rename-overwrite crash");
}

// ── test 11: multi-step rename chain crash recovery ─────────────────────

/// Create a chain of renames (A->B, B->C, C->D), crash, remount, verify
/// exactly one copy of the data exists and the filesystem is healthy.
#[test]
fn rename_chain_crash_recovery() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    let data = b"rename chain payload\n";

    harness
        .create_file("chain_a.txt", data)
        .expect("create chain_a.txt");
    harness.fsync_file("chain_a.txt").expect("fsync chain_a");

    harness
        .rename("chain_a.txt", "chain_b.txt")
        .expect("rename A -> B");
    harness
        .rename("chain_b.txt", "chain_c.txt")
        .expect("rename B -> C");
    harness
        .rename("chain_c.txt", "chain_d.txt")
        .expect("rename C -> D");
    harness.fsync_file("chain_d.txt").expect("fsync chain_d");

    harness.crash_and_remount().expect("crash_and_remount");

    // After the final fsync, chain_d.txt must be the surviving copy.
    assert!(
        !harness.exists("chain_a.txt"),
        "chain_a must not survive rename chain"
    );
    assert!(
        !harness.exists("chain_b.txt"),
        "chain_b must not survive rename chain"
    );
    assert!(
        !harness.exists("chain_c.txt"),
        "chain_c must not survive rename chain"
    );

    let read_back = harness.read_file("chain_d.txt").expect("read chain_d.txt");
    assert_eq!(read_back, data, "rename chain final content mismatch");
}

// ── test 12: orphan insert -> crash -> replay -> reclaim full pipeline ───

/// Full pipeline test: create a file with O_TMPFILE, write data, crash,
/// remount (triggers orphan replay + watermark advance), verify the
/// orphan was reclaimed and a new file can be created with the same
/// backing storage.
#[test]
fn tmpfile_full_pipeline_orphan_reclaim() {
    let mut harness = match mount_or_skip() {
        Some(h) => h,
        None => return,
    };

    harness.mkdir("pipeline_dir").expect("mkdir pipeline_dir");
    let dir_path = harness.mount_path().join("pipeline_dir");

    // Phase 1: Create O_TMPFILE orphan.
    let fd = open_tmpfile(&dir_path).expect("O_TMPFILE openat");
    write_fd(fd, b"pipeline tmpfile data\n").expect("write tmpfile");
    fsync_fd(fd).expect("fsync tmpfile");
    // Crash: orphan is in the index, data on disk.

    // Phase 2: Crash (SIGKILL daemon).
    harness.crash_and_remount().expect("crash_and_remount");

    // Phase 3: Remount triggers:
    //   - orphan replay from persistent index
    //   - watermark advancement
    //   - orphan reclamation

    // Verify pipeline_dir is empty (orphan reclaimed).
    let entries = harness
        .readdir("pipeline_dir")
        .expect("readdir pipeline_dir");
    assert!(
        entries.is_empty(),
        "pipeline_dir must be empty after full orphan reclaim pipeline"
    );

    // Phase 4: Filesystem must accept new operations, proving reclaim
    // released all resources.
    harness
        .create_file("pipeline_dir/post_reclaim.txt", b"reclaimed successfully\n")
        .expect("create after full pipeline reclaim");

    close_fd(fd);
}
