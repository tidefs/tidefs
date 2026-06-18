// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mounted FUSE integration smoke for statfs through the VFS adapter.
//!
//! Tests skip gracefully when /dev/fuse is unavailable.

mod fuse_mount_harness;

use fuse_mount_harness::MountedVfs;
use std::ffi::CString;
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// ---------------------------------------------------------------------------
// Skip guard
// ---------------------------------------------------------------------------

/// Skip the current test when FUSE is unavailable.
macro_rules! require_fuse {
    () => {
        if !fuse_mount_harness::fuse_available() {
            eprintln!(
                "SKIP: /dev/fuse not available — integration test requires FUSE kernel module"
            );
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// statfs syscall wrapper
// ---------------------------------------------------------------------------

fn statfs(path: &Path) -> io::Result<libc::statfs> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains nul byte"))?;
    let mut statfs = MaybeUninit::<libc::statfs>::uninit();
    let rc = unsafe { libc::statfs(cpath.as_ptr(), statfs.as_mut_ptr()) };
    if rc == 0 {
        Ok(unsafe { statfs.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

// ---------------------------------------------------------------------------
// Invariant checks
// ---------------------------------------------------------------------------

fn assert_statfs_invariants(st: &libc::statfs) {
    assert!(
        st.f_bsize > 0,
        "f_bsize must be positive, got {}",
        st.f_bsize
    );
    assert!(
        st.f_frsize > 0,
        "f_frsize must be positive, got {}",
        st.f_frsize
    );
    assert!(
        st.f_blocks > 0,
        "f_blocks must be positive, got {}",
        st.f_blocks
    );
    assert!(
        st.f_bfree <= st.f_blocks,
        "f_bfree {} <= f_blocks {}",
        st.f_bfree,
        st.f_blocks
    );
    assert!(
        st.f_bavail <= st.f_bfree,
        "f_bavail {} <= f_bfree {}",
        st.f_bavail,
        st.f_bfree
    );
    assert!(
        st.f_files > 0,
        "f_files must be positive, got {}",
        st.f_files
    );
    assert!(
        st.f_ffree <= st.f_files,
        "f_ffree {} <= f_files {}",
        st.f_ffree,
        st.f_files
    );
    assert!(
        st.f_namelen > 0,
        "f_namelen must be positive, got {}",
        st.f_namelen
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn statfs_on_vfs_mount_reports_capacity_fields() {
    require_fuse!();
    let mnt = MountedVfs::new("tidefs-vfs-statfs-smoke", &[], &[]);

    let before = statfs(&mnt.mount).expect("statfs before write through FUSE mount");
    assert_statfs_invariants(&before);

    let payload = vec![0x5a; 16 * 1024];
    fs::write(mnt.path("/statfs-data.bin"), payload).expect("write file through FUSE mount");

    let after = statfs(&mnt.mount).expect("statfs after write through FUSE mount");
    assert_statfs_invariants(&after);
    assert_eq!(after.f_bsize, before.f_bsize, "block size must be stable");
    assert_eq!(
        after.f_frsize, before.f_frsize,
        "fragment size must be stable"
    );
    assert_eq!(
        after.f_namelen, before.f_namelen,
        "maximum name length must be stable"
    );
    assert!(
        after.f_bfree <= before.f_bfree,
        "free blocks must not increase after writing data"
    );
    assert!(
        after.f_bavail <= before.f_bavail,
        "available blocks must not increase after writing data"
    );
}

#[test]
fn statfs_on_empty_vfs_mount_reports_plausible_invariants() {
    require_fuse!();
    let mnt = MountedVfs::new("tidefs-vfs-statfs-smoke-empty", &[], &[]);
    let st = statfs(&mnt.mount).expect("statfs on empty FUSE mount");
    assert_statfs_invariants(&st);
    // On an empty filesystem free blocks should be close to total blocks.
    assert!(st.f_bfree >= st.f_bavail, "f_bfree >= f_bavail");
}

#[test]
fn statfs_after_multiple_file_creations_updates_inode_counters() {
    require_fuse!();
    let mnt = MountedVfs::new("tidefs-vfs-statfs-smoke-inode", &[], &[]);
    let before = statfs(&mnt.mount).expect("statfs before file creation");
    assert_statfs_invariants(&before);

    // Create several files.
    for i in 0..5 {
        fs::write(mnt.path(&format!("/statfs-f{i}.bin")), [0x7f; 1024]).expect("write small file");
    }

    let after = statfs(&mnt.mount).expect("statfs after file creation");
    assert_statfs_invariants(&after);
    // Free inode count must not increase after creating files.
    assert!(
        after.f_ffree <= before.f_ffree,
        "f_ffree must not increase after creating files"
    );
    // File count must be stable.
    assert_eq!(
        after.f_files, before.f_files,
        "total inode count must remain stable"
    );
}

#[test]
fn statfs_fields_remain_stable_across_consecutive_calls() {
    require_fuse!();
    let mnt = MountedVfs::new("tidefs-vfs-statfs-smoke-stable", &[], &[]);
    let first = statfs(&mnt.mount).expect("first statfs");
    let second = statfs(&mnt.mount).expect("second statfs");
    assert_statfs_invariants(&first);
    assert_statfs_invariants(&second);
    // Structural fields must be identical across consecutive calls.
    assert_eq!(first.f_bsize, second.f_bsize);
    assert_eq!(first.f_frsize, second.f_frsize);
    assert_eq!(first.f_namelen, second.f_namelen);
    assert_eq!(first.f_files, second.f_files);
}
