//! POSIX error-code regression tests for mkdir, rmdir, unlink, and rename
//! through the FUSE-mounted adapter daemon.
//!
//! Each test case mounts a temporary FUSE filesystem, performs the
//! operation through the kernel VFS, and asserts the returned errno
//! matches POSIX expectations.
//!
//! rmdir error codes (ENOTEMPTY, ENOENT, ENOTDIR, EBUSY) are covered
//! by the existing `rmdir_smoke.rs` suite and are not duplicated here.

#![cfg(target_os = "linux")]

mod fuse_mount_harness;

use fuse_mount_harness::MountedVfs;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

macro_rules! require_fuse {
    () => {
        if !fuse_mount_harness::fuse_available() {
            eprintln!(
                "SKIP: /dev/fuse not available -- integration test requires FUSE kernel module"
            );
            return;
        }
    };
}

fn assert_raw_errno(err: &io::Error, expected: i32) {
    assert_eq!(
        err.raw_os_error(),
        Some(expected),
        "expected errno {expected}, got: {err}"
    );
}

fn write_and_sync(path: &Path, data: &[u8]) {
    {
        let mut f = File::create_new(path).expect("create file");
        f.write_all(data).expect("write data");
    }
    File::open(path)
        .expect("reopen for fsync")
        .sync_all()
        .expect("fsync");
}

// ===========================================================================
// mkdir error codes
// ===========================================================================

#[test]
fn mkdir_eexist_when_target_exists() {
    require_fuse!();
    let mnt = MountedVfs::new("err-mkdir-eexist", &[], &[]);

    let dir = mnt.path("/exists");
    fs::create_dir(&dir).expect("mkdir first time");

    let err = fs::create_dir(&dir).expect_err("mkdir on existing dir should fail");
    assert_raw_errno(&err, libc::EEXIST);

    assert!(dir.is_dir(), "existing dir must survive failed mkdir");
}

#[test]
fn mkdir_eexist_when_file_with_same_name() {
    require_fuse!();
    let mnt = MountedVfs::new("err-mkdir-eexist-file", &[], &[]);

    let path = mnt.path("/collision");
    write_and_sync(&path, b"regular file blocking mkdir\n");

    let err = fs::create_dir(&path).expect_err("mkdir over existing file should fail");
    assert_raw_errno(&err, libc::EEXIST);

    assert!(path.is_file(), "file must survive failed mkdir");
}

#[test]
fn mkdir_enoent_when_parent_missing() {
    require_fuse!();
    let mnt = MountedVfs::new("err-mkdir-enoent", &[], &[]);

    let child = mnt.path("/nonexistent-parent/child");

    let err = fs::create_dir(&child).expect_err("mkdir with missing parent should fail");
    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn mkdir_enametoolong_name_exceeds_limit() {
    require_fuse!();
    let mnt = MountedVfs::new("err-mkdir-long", &[], &[]);

    // NAME_MAX is 255 bytes; construct a 256-byte filename.
    let long_name = "a".repeat(256);
    let path = mnt.path(&long_name);

    let err = fs::create_dir(&path).expect_err("mkdir with >NAME_MAX name should fail");
    assert_raw_errno(&err, libc::ENAMETOOLONG);
}

// ===========================================================================
// unlink error codes
// ===========================================================================

#[test]
fn unlink_enoent_when_target_missing() {
    require_fuse!();
    let mnt = MountedVfs::new("err-unlink-enoent", &[], &[]);

    let missing = mnt.path("/no-such-file");

    let err = fs::remove_file(&missing).expect_err("unlink missing file should fail");
    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn unlink_eisdir_when_target_is_directory() {
    require_fuse!();
    let mnt = MountedVfs::new("err-unlink-eisdir", &[], &[]);

    let dir = mnt.path("/a-directory");
    fs::create_dir(&dir).expect("mkdir");

    let err = fs::remove_file(&dir).expect_err("unlink on directory should fail");
    assert_raw_errno(&err, libc::EISDIR);

    assert!(dir.is_dir(), "directory must survive failed unlink");
}

#[test]
fn unlink_enoent_when_parent_missing() {
    require_fuse!();
    let mnt = MountedVfs::new("err-unlink-parent", &[], &[]);

    let child = mnt.path("/nonexistent-parent/child.txt");

    let err = fs::remove_file(&child).expect_err("unlink with missing parent should fail");
    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn unlink_removes_entry_and_frees_name() {
    require_fuse!();
    let mnt = MountedVfs::new("err-unlink-ok", &[], &[]);

    let path = mnt.path("/removable.txt");
    write_and_sync(&path, b"to be removed\n");

    assert!(path.is_file(), "file must exist before unlink");
    fs::remove_file(&path).expect("unlink should succeed");

    let err = fs::metadata(&path).expect_err("removed file should not be stat-able");
    assert_raw_errno(&err, libc::ENOENT);
}

// ===========================================================================
// rename error codes
// ===========================================================================

#[test]
fn rename_enoent_when_source_missing() {
    require_fuse!();
    let mnt = MountedVfs::new("err-rename-enoent", &[], &[]);

    let src = mnt.path("/missing-source");
    let dst = mnt.path("/unused-target");

    let err = fs::rename(&src, &dst).expect_err("rename with missing source should fail");
    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn rename_enoent_when_source_parent_missing() {
    require_fuse!();
    let mnt = MountedVfs::new("err-rename-src-parent", &[], &[]);

    let src = mnt.path("/nonexistent-dir/source.txt");
    let dst = mnt.path("/target.txt");

    let err = fs::rename(&src, &dst).expect_err("rename with missing source parent should fail");
    assert_raw_errno(&err, libc::ENOENT);
}

#[test]
fn rename_enoent_when_dst_parent_missing() {
    require_fuse!();
    let mnt = MountedVfs::new("err-rename-dst-parent", &[], &[]);

    // Seed the source under a real directory.
    let src = mnt.path("/real-source.txt");
    write_and_sync(&src, b"source data\n");
    let dst = mnt.path("/nonexistent-parent/target.txt");

    let err = fs::rename(&src, &dst).expect_err("rename with missing dst parent should fail");
    assert_raw_errno(&err, libc::ENOENT);

    // Source must survive the failed rename.
    assert!(
        src.is_file(),
        "source must survive failed cross-parent rename"
    );
}

// ===========================================================================
// rename: cross-directory nlink tracking
// ===========================================================================

#[test]
fn rename_cross_dir_adjusts_parent_nlink() {
    require_fuse!();
    let mnt = MountedVfs::new("err-rename-nlink", &[], &[]);

    let src_dir = mnt.path("/src");
    let dst_dir = mnt.path("/dst");
    fs::create_dir(&src_dir).expect("mkdir src");
    fs::create_dir(&dst_dir).expect("mkdir dst");

    let src_file = src_dir.join("mover.txt");
    write_and_sync(&src_file, b"data\n");

    // Record pre-rename nlink on both parent directories.
    let src_nlink_before = fs::metadata(&src_dir).expect("stat src dir").nlink();
    let dst_nlink_before = fs::metadata(&dst_dir).expect("stat dst dir").nlink();

    let dst_file = dst_dir.join("mover.txt");
    fs::rename(&src_file, &dst_file).expect("cross-dir rename");

    let src_nlink_after = fs::metadata(&src_dir).expect("stat src dir after").nlink();
    let dst_nlink_after = fs::metadata(&dst_dir).expect("stat dst dir after").nlink();

    // src dir loses one entry -> nlink should decrease by 1.
    assert_eq!(
        src_nlink_after,
        src_nlink_before.saturating_sub(1),
        "src parent nlink must decrease after entry moved out"
    );
    // dst dir gains one entry -> nlink should increase by 1.
    assert_eq!(
        dst_nlink_after,
        dst_nlink_before.saturating_add(1),
        "dst parent nlink must increase after entry moved in"
    );

    // Verify the file is accessible at the new location.
    assert!(dst_file.is_file(), "moved file must exist at dst");
    assert!(!src_file.exists(), "moved file must not exist at src");
}

// ===========================================================================
// Stress: repeated create+unlink in the same directory does not leak
// ===========================================================================

#[test]
fn repeated_create_unlink_same_name_no_leak() {
    require_fuse!();
    let mnt = MountedVfs::new("err-create-unlink", &[], &[]);

    let path = mnt.path("/reusable");

    for _ in 0..50 {
        write_and_sync(&path, b"ephemeral\n");
        assert!(path.is_file());
        fs::remove_file(&path).expect("unlink");
        let err = fs::metadata(&path).expect_err("entry must be gone after unlink");
        assert_raw_errno(&err, libc::ENOENT);
    }
}
