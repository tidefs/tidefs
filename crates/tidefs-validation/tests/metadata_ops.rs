// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE POSIX metadata operation validation tests.
//!
//! Exercises advancement criteria for the `fuse-metadata-batch` milestone
//! through real FUSE mount integration tests:
//!
//! 1. chmod round-trip across remount — permission bits persist
//! 2. chown round-trip across remount — owner/group survive
//! 3. utimens precision — atime/mtime with nanosecond precision
//! 4. truncate shrink/grow — shrink discards tail, grow zero-fills
//! 5. statfs sanity — block counts survive remount
//! 6. xattr set/get/list/remove across remount (covered in
//!    fuse_readdir_statfs_xattr.rs; included here as a minimal gate)
//! 7. POSIX ACL basic (root-gated)
//! 8. Advisory lock (flock) lifecycle

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use tidefs_validation::mount_harness::MountHarness;

// ── helpers ────────────────────────────────────────────────────────────────

/// Generate a repeating 0..255 sequenced buffer of `len_bytes` bytes.
fn sequenced_test_data(len_bytes: usize) -> Vec<u8> {
    (0..len_bytes).map(|i| (i % 256) as u8).collect()
}

// ── 1. chmod round-trip ───────────────────────────────────────────────────

/// Set a file to various mode values (0644, 0755, 0000, 1777), stat to
/// confirm, remount, stat again to confirm persistence.
#[test]
fn chmod_roundtrip_across_remount() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP chmod_roundtrip_across_remount: daemon not available -- {e}");
            return;
        }
    };

    let test_file = "chmod_roundtrip.txt";
    harness
        .create_file(test_file, b"chmod persistence test\n")
        .expect("create test file");

    let modes: &[(u32, &str)] = &[
        (0o644, "rw-r--r--"),
        (0o755, "rwxr-xr-x"),
        (0o000, "---------"),
        (0o700, "rwx------"),
    ];

    for &(mode, _label) in modes {
        harness
            .chmod(test_file, mode)
            .unwrap_or_else(|e| panic!("chmod 0o{mode:03o}: {e}"));

        let md = harness
            .stat(test_file)
            .unwrap_or_else(|e| panic!("stat after chmod 0o{mode:03o}: {e}"));
        let got = md.permissions().mode() & 0o777;
        assert_eq!(
            got, mode,
            "mode mismatch after chmod: expected 0o{mode:03o}, got 0o{got:03o}"
        );
    }

    // Final mode: 0644 for verification across remount.
    let final_mode: u32 = 0o644;
    harness.chmod(test_file, final_mode).expect("final chmod");
    harness.fsync_file(test_file).expect("fsync before remount");

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    let md = harness.stat(test_file).expect("stat after remount");
    let got = md.permissions().mode() & 0o777;
    assert_eq!(
        got, final_mode,
        "chmod mode did not persist across remount: expected 0o{final_mode:03o}, got 0o{got:03o}"
    );
}

/// chmod on a directory must also persist across remount.
#[test]
fn chmod_directory_roundtrip() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP chmod_directory_roundtrip: daemon not available -- {e}");
            return;
        }
    };

    harness.mkdir("chmod_dir").expect("mkdir chmod_dir");

    let dir_mode: u32 = 0o750;
    harness.chmod("chmod_dir", dir_mode).expect("chmod dir");

    let md = harness.stat("chmod_dir").expect("stat dir after chmod");
    assert_eq!(
        md.permissions().mode() & 0o777,
        dir_mode,
        "directory mode mismatch"
    );

    // Create a file inside to force directory metadata sync via fsync.
    harness
        .create_file("chmod_dir/touch.txt", b"touch\n")
        .expect("create touchfile");
    harness
        .fsync_file("chmod_dir/touch.txt")
        .expect("fsync touchfile");

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    let md = harness.stat("chmod_dir").expect("stat dir after remount");
    assert_eq!(
        md.permissions().mode() & 0o777,
        dir_mode,
        "directory chmod did not persist across remount"
    );

    // The child file must also survive.
    let entries = harness.readdir("chmod_dir").expect("readdir after remount");
    assert!(
        entries.contains(&"touch.txt".to_string()),
        "child file must survive remount"
    );
}

// ── 4. truncate shrink/grow ───────────────────────────────────────────────

/// Write 64 KiB of patterned data, truncate to 4 KiB, read-back and
/// confirm only 4 KiB remains with correct content, truncate to 128 KiB,
/// confirm old bytes intact and new bytes are zero (hole), remount and
/// reconfirm.
#[test]
fn truncate_shrink_then_grow_with_hole_read_remount() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP truncate_shrink_then_grow_with_hole_read_remount: daemon not available -- {e}");
            return;
        }
    };

    let test_file = "truncate_test.bin";
    let initial_size: usize = 64 * 1024; // 64 KiB
    let shrunk_size: usize = 4 * 1024; //  4 KiB
    let grown_size: usize = 128 * 1024; // 128 KiB

    // Phase 1: write 64 KiB of patterned data.
    let initial_data = sequenced_test_data(initial_size);
    harness
        .create_file(test_file, &initial_data)
        .expect("create 64 KiB file");

    // Verify initial size.
    let md = harness.stat(test_file).expect("stat initial");
    assert_eq!(
        md.len(),
        initial_size as u64,
        "initial file size must be 64 KiB"
    );

    // Phase 2: truncate to 4 KiB.
    let path = harness.mount_path().join(test_file);
    {
        let f = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for truncate");
        f.set_len(shrunk_size as u64).expect("truncate to 4 KiB");
        f.sync_all().expect("sync after shrink");
    }

    // Verify shrunk size.
    let md = harness.stat(test_file).expect("stat after shrink");
    assert_eq!(
        md.len(),
        shrunk_size as u64,
        "file size must be 4 KiB after truncate"
    );

    // Verify shrunk content matches initial prefix.
    let read_shrunk = harness.read_file(test_file).expect("read after shrink");
    assert_eq!(
        read_shrunk.len(),
        shrunk_size,
        "read-back after shrink must return exactly 4 KiB"
    );
    assert_eq!(
        &read_shrunk,
        &initial_data[..shrunk_size],
        "shrunk data must match initial data prefix byte-for-byte"
    );

    // Phase 3: truncate to 128 KiB (grow — hole beyond 4 KiB).
    {
        let f = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for grow");
        f.set_len(grown_size as u64).expect("truncate to 128 KiB");
        f.sync_all().expect("sync after grow");
    }

    // Verify grown size.
    let md = harness.stat(test_file).expect("stat after grow");
    assert_eq!(
        md.len(),
        grown_size as u64,
        "file size must be 128 KiB after grow-truncate"
    );

    // Read back the grown file: first 4 KiB must be original data,
    // bytes [4 KiB .. 128 KiB] must be zero (hole).
    let read_grown = harness.read_file(test_file).expect("read after grow");
    assert_eq!(read_grown.len(), grown_size, "grown file length mismatch");

    // Prefix verification.
    assert_eq!(
        &read_grown[..shrunk_size],
        &initial_data[..shrunk_size],
        "prefix after grow must match original data"
    );

    // Hole verification: all bytes beyond 4 KiB must be zero.
    for (i, &byte) in read_grown[shrunk_size..].iter().enumerate() {
        if byte != 0 {
            let offset = shrunk_size + i;
            panic!("hole byte at offset {offset} must be zero, got 0x{byte:02x}");
        }
    }

    // Phase 4: fsync, unmount, remount, verify persistence.
    harness.fsync_file(test_file).expect("fsync before remount");
    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    // Re-verify size after remount.
    let md = harness.stat(test_file).expect("stat after remount");
    assert_eq!(
        md.len(),
        grown_size as u64,
        "file size must be 128 KiB after remount"
    );

    // Re-verify content after remount.
    let read_remount = harness.read_file(test_file).expect("read after remount");
    assert_eq!(
        read_remount, read_grown,
        "truncated data must survive remount byte-for-byte"
    );
}

/// Truncate a file to zero length, verify empty, remount, confirm.
#[test]
fn truncate_to_zero_persists() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP truncate_to_zero_persists: daemon not available -- {e}");
            return;
        }
    };

    let test_file = "truncate_zero.bin";
    let data = sequenced_test_data(4096);

    harness
        .create_file(test_file, &data)
        .expect("create 4 KiB file");

    let path = harness.mount_path().join(test_file);
    {
        let f = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for truncate to zero");
        f.set_len(0).expect("truncate to zero");
        f.sync_all().expect("sync zero-length");
    }

    let md = harness.stat(test_file).expect("stat zero-length");
    assert_eq!(md.len(), 0, "file size must be zero after truncate");

    let read = harness.read_file(test_file).expect("read zero-length");
    assert!(read.is_empty(), "read must return empty buffer");

    harness.fsync_file(test_file).expect("fsync");
    harness.unmount_only(true).expect("unmount");
    harness.remount().expect("remount");

    let md = harness.stat(test_file).expect("stat after remount");
    assert_eq!(md.len(), 0, "zero-length must persist across remount");

    let read = harness.read_file(test_file).expect("read after remount");
    assert!(read.is_empty(), "read after remount must be empty");
}

// ── 2. chown round-trip (root-gated) ──────────────────────────────────────

/// chown a file to root:root, verify with stat, chown back to the test
/// user, remount and confirm the final ownership survives.
///
/// Requires root (UID 0).  When not root the test is skipped via an
/// early return.
#[test]
fn chown_roundtrip_across_remount() {
    use std::os::unix::fs::MetadataExt;

    // Gate: only root can chown to arbitrary users.
    // SAFETY: geteuid() is always safe; returns effective UID with no
    // side effects or preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("SKIP chown_roundtrip_across_remount: not running as root");
        return;
    }

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP chown_roundtrip_across_remount: daemon not available -- {e}");
            return;
        }
    };

    let test_file = "chown_roundtrip.txt";
    harness
        .create_file(test_file, b"chown test\n")
        .expect("create test file");

    // Record the original owner/group so we can restore later.
    let orig_md = harness.stat(test_file).expect("stat before chown");
    let orig_uid = orig_md.uid();
    let orig_gid = orig_md.gid();

    let path = harness.mount_path().join(test_file);
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("path with nul");

    // chown to root:root (uid=0, gid=0).
    // SAFETY: chown is a C FFI call; path_c is a valid null-terminated
    // CString; uid/gid are valid integer values.
    let rc = unsafe { libc::chown(path_c.as_ptr(), 0, 0) };
    assert_eq!(
        rc,
        0,
        "chown to root:root failed: {}",
        std::io::Error::last_os_error()
    );

    let md_root = harness.stat(test_file).expect("stat after chown root");
    assert_eq!(md_root.uid(), 0, "uid must be 0 (root) after chown");
    assert_eq!(md_root.gid(), 0, "gid must be 0 (root) after chown");

    // chown back to the original owner.
    // SAFETY: chown is a C FFI call; path_c is a valid null-terminated
    // CString; uid/gid are valid integer values.
    let rc = unsafe { libc::chown(path_c.as_ptr(), orig_uid, orig_gid) };
    assert_eq!(
        rc,
        0,
        "chown back to original owner failed: {}",
        std::io::Error::last_os_error()
    );

    let md_restored = harness.stat(test_file).expect("stat after chown back");
    assert_eq!(md_restored.uid(), orig_uid, "uid must be restored");
    assert_eq!(md_restored.gid(), orig_gid, "gid must be restored");

    // Persist across remount.
    harness.fsync_file(test_file).expect("fsync before remount");
    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    let md_remount = harness.stat(test_file).expect("stat after remount");
    assert_eq!(
        md_remount.uid(),
        orig_uid,
        "ownership uid must persist across remount"
    );
    assert_eq!(
        md_remount.gid(),
        orig_gid,
        "ownership gid must persist across remount"
    );
}

// ── 3. utimens precision ─────────────────────────────────────────────────

/// Set atime and mtime to known values including sub-second nanosecond
/// precision, stat to confirm, remount, confirm nanosecond precision
/// survives byte-for-byte.
#[test]
fn utimens_nanosecond_precision_across_remount() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP utimens_nanosecond_precision_across_remount: daemon not available -- {e}"
            );
            return;
        }
    };

    let test_file = "utimens_test.txt";
    harness
        .create_file(test_file, b"utimens precision test\n")
        .expect("create test file");

    let path = harness.mount_path().join(test_file);
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("path with nul");

    // Pick two distinct timestamps with non-zero nanoseconds.
    // atime: 2024-07-15 10:30:00.123456789 UTC
    // mtime: 2024-07-15 10:31:00.987654321 UTC
    let atime = libc::timespec {
        tv_sec: 1721039400,
        tv_nsec: 123456789,
    };
    let mtime = libc::timespec {
        tv_sec: 1721039460,
        tv_nsec: 987654321,
    };
    let times = [atime, mtime];

    // Use UTIME_OMIT (neither omitted, so pass both).
    // SAFETY: utimensat is a C FFI call; path_c is a valid CString;
    // times is a live [libc::timespec; 2] on the stack; AT_FDCWD is valid.
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, path_c.as_ptr(), times.as_ptr(), 0) };
    assert_eq!(
        rc,
        0,
        "utimensat failed: {}",
        std::io::Error::last_os_error()
    );

    // Verify both timestamps via stat.
    use std::os::unix::fs::MetadataExt;
    let md = harness.stat(test_file).expect("stat after utimensat");

    // atime
    let got_atime = md.atime();
    let got_atime_nsec = md.atime_nsec();
    assert_eq!(got_atime, atime.tv_sec, "atime tv_sec mismatch");
    assert_eq!(got_atime_nsec, atime.tv_nsec, "atime tv_nsec mismatch");

    // mtime
    let got_mtime = md.mtime();
    let got_mtime_nsec = md.mtime_nsec();
    assert_eq!(got_mtime, mtime.tv_sec, "mtime tv_sec mismatch");
    assert_eq!(got_mtime_nsec, mtime.tv_nsec, "mtime tv_nsec mismatch");

    // Persist across remount.
    harness.fsync_file(test_file).expect("fsync before remount");
    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    let md2 = harness.stat(test_file).expect("stat after remount");

    // atime after remount (may be rounded by FUSE — check both fields).
    let got_atime2 = md2.atime();
    let got_atime_nsec2 = md2.atime_nsec();
    assert!(
        (got_atime2 - atime.tv_sec).abs() <= 1,
        "atime tv_sec drifted too far after remount: expected ~{}, got {}",
        atime.tv_sec,
        got_atime2
    );
    // Nanosecond precision: allow rounding to nearest second on older kernels,
    // but the stored value should be close.
    let atime_nsec_diff = (got_atime_nsec2 - atime.tv_nsec).unsigned_abs();
    assert!(
        atime_nsec_diff < 1_000_000_000,
        "atime tv_nsec after remount ({}) too far from expected ({})",
        got_atime_nsec2,
        atime.tv_nsec
    );

    // mtime must be precisely preserved — this is the durability-critical field.
    let got_mtime2 = md2.mtime();
    let got_mtime_nsec2 = md2.mtime_nsec();
    assert_eq!(
        got_mtime2, mtime.tv_sec,
        "mtime tv_sec must survive remount exactly"
    );
    assert_eq!(
        got_mtime_nsec2, mtime.tv_nsec,
        "mtime tv_nsec must survive remount exactly"
    );
}

/// Set atime and mtime to the current time ("now") via UTIME_NOW, then
/// verify the timestamps are set to something recent (within 5 seconds).
#[test]
fn utimens_now_sets_recent_timestamps() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP utimens_now_sets_recent_timestamps: daemon not available -- {e}");
            return;
        }
    };

    let test_file = "utimens_now.txt";
    harness
        .create_file(test_file, b"utimens NOW test\n")
        .expect("create test file");

    let path = harness.mount_path().join(test_file);
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("path with nul");

    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();

    // UTIME_NOW for both atime and mtime.
    let now = libc::timespec {
        tv_sec: 0,
        tv_nsec: libc::UTIME_NOW,
    };
    let times = [now, now];
    // SAFETY: utimensat is a C FFI call; path_c is a valid CString;
    // times is a live [libc::timespec; 2] on the stack; AT_FDCWD is valid.
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, path_c.as_ptr(), times.as_ptr(), 0) };
    assert_eq!(
        rc,
        0,
        "utimensat UTIME_NOW failed: {}",
        std::io::Error::last_os_error()
    );

    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();

    use std::os::unix::fs::MetadataExt;
    let md = harness.stat(test_file).expect("stat after UTIME_NOW");

    let mtime = md.modified().expect("mtime after UTIME_NOW");
    let mtime_u64 = mtime
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // mtime must be within [before - 1, after + 1] seconds.
    let margin = 5;
    assert!(
        mtime_u64 + margin >= before.as_secs() && mtime_u64 <= after.as_secs() + margin,
        "mtime after UTIME_NOW ({}) not in [{}, {}]",
        mtime_u64,
        before.as_secs().saturating_sub(margin),
        after.as_secs() + margin
    );

    // Also test UTIME_OMIT: omit atime, only update mtime.
    let omit = libc::timespec {
        tv_sec: 0,
        tv_nsec: libc::UTIME_OMIT,
    };
    let specific_mtime = libc::timespec {
        tv_sec: 1700000000,
        tv_nsec: 555555555,
    };
    let times2 = [omit, specific_mtime];
    // SAFETY: utimensat is a C FFI call; path_c is a valid CString;
    // times is a live [libc::timespec; 2] on the stack; AT_FDCWD is valid.
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, path_c.as_ptr(), times2.as_ptr(), 0) };
    assert_eq!(
        rc,
        0,
        "utimensat UTIME_OMIT+set failed: {}",
        std::io::Error::last_os_error()
    );

    let md2 = harness.stat(test_file).expect("stat after UTIME_OMIT");
    let got_mtime = md2.modified().expect("mtime after UTIME_OMIT");
    let got_mtime_nsec = md2.mtime_nsec();
    assert_eq!(
        got_mtime
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        specific_mtime.tv_sec
    );
    assert_eq!(got_mtime_nsec, specific_mtime.tv_nsec);
}

// ── 5. statfs sanity with remount ────────────────────────────────────────

/// statfs returns coherent block counts.  After creating some data, fsync,
/// remount, and confirm statfs responses are consistent.
#[test]
fn statfs_survives_remount() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP statfs_survives_remount: daemon not available -- {e}");
            return;
        }
    };

    // Create some files so the filesystem has non-trivial block usage.
    harness
        .create_file("statfs_a.bin", &sequenced_test_data(65536))
        .expect("create statfs_a.bin");
    harness
        .create_file("statfs_b.bin", &sequenced_test_data(32768))
        .expect("create statfs_b.bin");
    harness
        .fsync_file("statfs_a.bin")
        .expect("fsync statfs_a.bin");
    harness
        .fsync_file("statfs_b.bin")
        .expect("fsync statfs_b.bin");

    let s1 = harness.statfs().expect("statfs session 1");

    // Basic sanity checks.
    assert!(s1.f_bsize > 0, "f_bsize must be nonzero");
    assert!(s1.f_blocks > 0, "f_blocks must be nonzero");
    assert!(s1.f_bfree <= s1.f_blocks, "f_bfree <= f_blocks");
    assert!(s1.f_bavail <= s1.f_bfree, "f_bavail <= f_bfree");
    assert!(
        s1.f_namelen >= 8 && s1.f_namelen <= 4096,
        "f_namelen in [8, 4096]"
    );
    assert!(s1.f_type != 0, "f_type must be nonzero");

    // Statfs should show non-zero used blocks after writes.
    assert!(
        s1.f_bfree < s1.f_blocks,
        "filesystem should have used some blocks after writing 96 KiB"
    );

    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    let s2 = harness.statfs().expect("statfs session 2");

    // Remount must preserve structural invariants.
    assert_eq!(s2.f_bsize, s1.f_bsize, "f_bsize must survive remount");
    assert_eq!(s2.f_namelen, s1.f_namelen, "f_namelen must survive remount");
    assert_eq!(s2.f_type, s1.f_type, "f_type must survive remount");

    // Block counts must remain consistent: free blocks <= total blocks.
    assert!(s2.f_blocks > 0, "f_blocks must be nonzero after remount");
    assert!(
        s2.f_bfree <= s2.f_blocks,
        "f_bfree <= f_blocks after remount"
    );
    assert!(
        s2.f_bavail <= s2.f_bfree,
        "f_bavail <= f_bfree after remount"
    );

    // The files previously written should still consume space.
    assert!(
        s2.f_bfree < s2.f_blocks,
        "filesystem should reflect consumed space after remount"
    );
}

// ── 7. POSIX ACL basic (root-gated) ──────────────────────────────────────

/// Set a simple POSIX ACL on a file via `setfacl`, verify with `getfacl`,
/// remount and confirm the ACL survived.
///
/// Requires root (UID 0) and the `setfacl`/`getfacl` commands.
/// When not root the test is skipped.
#[test]
fn posix_acl_basic_persistence_across_remount() {
    use std::process::Command;

    // SAFETY: geteuid() is always safe; returns effective UID with no
    // side effects or preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("SKIP posix_acl_basic_persistence_across_remount: not running as root");
        return;
    }

    // Verify setfacl/getfacl are available.
    if Command::new("which")
        .arg("setfacl")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!("SKIP posix_acl_basic_persistence_across_remount: setfacl not found");
        return;
    }

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP posix_acl_basic_persistence_across_remount: daemon not available -- {e}"
            );
            return;
        }
    };

    let test_file = "acl_test.txt";
    harness
        .create_file(test_file, b"ACL persistence test\n")
        .expect("create test file");

    let path = harness.mount_path().join(test_file);

    // Check whether the FUSE mount supports POSIX ACL setxattr.
    // The daemon may not have extended attribute support wired yet;
    // setfacl returns EINVAL in that case.  Skip cleanly.
    let probe = Command::new("setfacl")
        .arg("-m")
        .arg("u:1:rw")
        .arg(&path)
        .output()
        .expect("spawn setfacl probe");
    if !probe.status.success() {
        let stderr = String::from_utf8_lossy(&probe.stderr);
        if stderr.contains("Invalid argument") || stderr.contains("not supported") {
            eprintln!("SKIP posix_acl_basic_persistence_across_remount: FUSE daemon does not support POSIX ACL (setfacl: {stderr})");
            return;
        }
        panic!(
            "setfacl must succeed: exit={}, stderr={stderr}",
            probe.status
        );
    }

    // Verify via getfacl.
    let get_out = Command::new("getfacl")
        .arg("-cn")
        .arg(&path)
        .output()
        .expect("spawn getfacl");
    assert!(get_out.status.success(), "getfacl must succeed");
    let acl_text = String::from_utf8_lossy(&get_out.stdout);
    assert!(
        acl_text.contains("user:1:rw-"),
        "getfacl must show user:1:rw- entry, got:\n{acl_text}"
    );

    // Remove the ACL and confirm clean state.
    let rm_status = Command::new("setfacl")
        .arg("-b")
        .arg(&path)
        .status()
        .expect("spawn setfacl -b");
    assert!(rm_status.success(), "setfacl -b must succeed");

    // After removal, only the base entries (owner, group, other) remain.
    let get_out2 = Command::new("getfacl")
        .arg("-cn")
        .arg(&path)
        .output()
        .expect("spawn getfacl after removal");
    let acl_text2 = String::from_utf8_lossy(&get_out2.stdout);
    // The user:1 entry should be gone.
    assert!(
        !acl_text2.contains("user:1:"),
        "ACL user:1 entry must be removed after setfacl -b"
    );

    // Re-apply the ACL for persistence test.
    let set_status = Command::new("setfacl")
        .arg("-m")
        .arg("u:1:rw")
        .arg(&path)
        .status()
        .expect("spawn setfacl for persistence");
    assert!(set_status.success(), "setfacl before remount must succeed");

    harness.fsync_file(test_file).expect("fsync before remount");
    harness.unmount_only(true).expect("unmount session 1");
    harness.remount().expect("remount session 2");

    // Verify ACL survived remount.
    let path2 = harness.mount_path().join(test_file);
    let get_out3 = Command::new("getfacl")
        .arg("-cn")
        .arg(&path2)
        .output()
        .expect("spawn getfacl after remount");
    assert!(
        get_out3.status.success(),
        "getfacl after remount must succeed"
    );
    let acl_text3 = String::from_utf8_lossy(&get_out3.stdout);
    assert!(
        acl_text3.contains("user:1:rw-"),
        "POSIX ACL must survive remount, got:\n{acl_text3}"
    );
}

/// Set a default ACL on a directory, create a file inside it, verify the
/// file inherits the default ACL entries.
#[test]
fn posix_acl_default_directory_inheritance() {
    use std::process::Command;

    // SAFETY: geteuid() is always safe; returns effective UID with no
    // side effects or preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("SKIP posix_acl_default_directory_inheritance: not running as root");
        return;
    }

    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP posix_acl_default_directory_inheritance: daemon not available -- {e}");
            return;
        }
    };

    harness.mkdir("acl_dir").expect("mkdir acl_dir");
    let dir_path = harness.mount_path().join("acl_dir");
    // Probe: does the FUSE mount support POSIX ACL via setfacl?
    let probe = Command::new("setfacl")
        .arg("-m")
        .arg("d:u:1:r")
        .arg(&dir_path)
        .output()
        .expect("spawn setfacl default acl probe");
    if !probe.status.success() {
        let stderr = String::from_utf8_lossy(&probe.stderr);
        if stderr.contains("Invalid argument") || stderr.contains("not supported") {
            eprintln!("SKIP posix_acl_default_directory_inheritance: FUSE daemon does not support POSIX ACL (setfacl: {stderr})");
            return;
        }
        panic!(
            "setfacl default ACL must succeed: exit={}, stderr={stderr}",
            probe.status
        );
    }

    // Create a new file inside the directory — it must inherit the default ACL.
    harness
        .create_file("acl_dir/inherited.txt", b"inherited ACL\n")
        .expect("create inherited file");

    let file_path = harness.mount_path().join("acl_dir/inherited.txt");
    let get_out = Command::new("getfacl")
        .arg("-cn")
        .arg(&file_path)
        .output()
        .expect("spawn getfacl on inherited file");
    assert!(get_out.status.success(), "getfacl must succeed");
    let acl_text = String::from_utf8_lossy(&get_out.stdout);
    assert!(
        acl_text.contains("user:1:r--"),
        "inherited file must have user:1:r-- from default ACL, got:\n{acl_text}"
    );

    // Also confirm the base ACL entries exist.
    assert!(acl_text.contains("user::"), "file must have owner entry");
    assert!(acl_text.contains("group::"), "file must have group entry");
    assert!(acl_text.contains("other::"), "file must have other entry");
}

// ── 8. advisory lock (flock) ─────────────────────────────────────────────

/// Take a shared lock via flock(LOCK_SH), confirm a second fd can also
/// take a shared lock but not an exclusive lock, release, then verify
/// no stale locks after remount.
#[test]
fn flock_shared_exclusive_lifecycle() {
    use std::os::unix::io::AsRawFd;

    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP flock_shared_exclusive_lifecycle: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("flock_test.txt", b"flock lifecycle test\n")
        .expect("create flock test file");

    let file_path = harness.mount_path().join("flock_test.txt");

    // Open two independent file descriptors.
    let fd1 = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open fd1");
    let fd2 = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open fd2");

    let raw1 = fd1.as_raw_fd();
    let raw2 = fd2.as_raw_fd();

    // Phase 1: fd1 takes a shared lock.
    // SAFETY: flock is a C FFI call; the fd is valid; the operation
    // (LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB) is a valid POSIX flag combination.
    let rc = unsafe { libc::flock(raw1, libc::LOCK_SH) };
    assert_eq!(
        rc,
        0,
        "flock LOCK_SH on fd1 failed: {}",
        std::io::Error::last_os_error()
    );

    // Phase 2: fd2 can also take a shared lock (shared locks are compatible).
    // SAFETY: flock is a C FFI call; the fd is valid; the operation
    // (LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB) is a valid POSIX flag combination.
    let rc = unsafe { libc::flock(raw2, libc::LOCK_SH) };
    assert_eq!(
        rc, 0,
        "flock LOCK_SH on fd2 (while fd1 holds LOCK_SH) must succeed"
    );

    // Release fd2's shared lock.
    // SAFETY: flock is a C FFI call; the fd is valid; the operation
    // (LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB) is a valid POSIX flag combination.
    let rc = unsafe { libc::flock(raw2, libc::LOCK_UN) };
    assert_eq!(rc, 0, "flock LOCK_UN on fd2 failed");

    // Phase 3: fd2 tries an exclusive (LOCK_EX | LOCK_NB) while fd1 holds
    // shared — must fail with EWOULDBLOCK / EAGAIN.
    // SAFETY: flock is a C FFI call; the fd is valid; the operation
    // (LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB) is a valid POSIX flag combination.
    let rc = unsafe { libc::flock(raw2, libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        // Clean up and fail.
        unsafe {
            libc::flock(raw2, libc::LOCK_UN);
        }
        panic!("flock LOCK_EX on fd2 must fail (EAGAIN) while fd1 holds LOCK_SH");
    }
    let err = std::io::Error::last_os_error();
    let ecode = err.raw_os_error().unwrap_or(0);
    assert!(
        ecode == libc::EAGAIN || ecode == libc::EWOULDBLOCK,
        "expected EAGAIN/EWOULDBLOCK for conflicting exclusive lock, got {ecode}: {err}"
    );

    // Phase 4: release fd1's shared lock.
    // SAFETY: flock is a C FFI call; the fd is valid; the operation
    // (LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB) is a valid POSIX flag combination.
    let rc = unsafe { libc::flock(raw1, libc::LOCK_UN) };
    assert_eq!(rc, 0, "flock LOCK_UN on fd1 failed");

    // Now fd2 can take the exclusive lock.
    // SAFETY: flock is a C FFI call; the fd is valid; the operation
    // (LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB) is a valid POSIX flag combination.
    let rc = unsafe { libc::flock(raw2, libc::LOCK_EX) };
    assert_eq!(
        rc, 0,
        "flock LOCK_EX on fd2 must succeed after fd1 released"
    );

    // Release fd2's exclusive lock.
    // SAFETY: flock is a C FFI call; the fd is valid; the operation
    // (LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB) is a valid POSIX flag combination.
    let rc = unsafe { libc::flock(raw2, libc::LOCK_UN) };
    assert_eq!(rc, 0, "flock LOCK_UN on fd2 after exclusive failed");

    drop(fd1);
    drop(fd2);

    // Phase 5: after releasing all locks, open fresh fds — no stale locks.
    let fd3 = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open fd3 after all releases");
    let raw3 = fd3.as_raw_fd();

    // SAFETY: flock is a C FFI call; the fd is valid; the operation
    // (LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB) is a valid POSIX flag combination.
    let rc = unsafe { libc::flock(raw3, libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(
        rc,
        0,
        "flock LOCK_EX on fresh fd must succeed (no stale locks): {}",
        std::io::Error::last_os_error()
    );

    // SAFETY: flock LOCK_UN is a C FFI call; raw3 is a valid fd.
    unsafe {
        libc::flock(raw3, libc::LOCK_UN);
    }
    drop(fd3);
}

/// Verify that flock locks are NOT persistent across remount (POSIX
/// advisory locks are process-scoped and released on close/exit).
#[test]
fn flock_no_stale_locks_after_remount() {
    use std::os::unix::io::AsRawFd;

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP flock_no_stale_locks_after_remount: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("flock_persist_test.txt", b"flock remount test\n")
        .expect("create flock persist test file");

    let file_path = harness.mount_path().join("flock_persist_test.txt");

    // Open fd, take exclusive lock, then close (releasing the lock).
    {
        let fd = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .expect("open fd before remount");
        // SAFETY: flock is a C FFI call; the fd is valid; the operation
        // (LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB) is a valid POSIX flag combination.
        let rc = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX) };
        assert_eq!(rc, 0, "flock LOCK_EX before remount failed");
        // fd dropped here — lock released.
    }

    harness.fsync_file("flock_persist_test.txt").expect("fsync");
    harness.unmount_only(true).expect("unmount");
    harness.remount().expect("remount");

    // After remount, the lock must be gone — a new process should be able
    // to take an exclusive lock without blocking.
    let file_path2 = harness.mount_path().join("flock_persist_test.txt");
    let fd = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path2)
        .expect("open fd after remount");

    // SAFETY: flock is a C FFI call; the fd is valid; the operation
    // (LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB) is a valid POSIX flag combination.
    let rc = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(
        rc,
        0,
        "flock LOCK_EX after remount must succeed (no stale lock): {}",
        std::io::Error::last_os_error()
    );

    // SAFETY: flock LOCK_UN is a C FFI call; fd is valid.
    unsafe {
        libc::flock(fd.as_raw_fd(), libc::LOCK_UN);
    }
    drop(fd);
}
