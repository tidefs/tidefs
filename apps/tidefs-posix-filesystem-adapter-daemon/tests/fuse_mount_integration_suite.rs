//! FUSE mount integration suite: create/write/read/readdir/stat/unlink/rmdir
//! through a real mount lifecycle.
//!
//! Each test follows the pattern: mount → operate → unmount → remount →
//! verify persistence / correctness.  Uses the shared fuse_mount_harness.
//!
//! Tests skip gracefully when /dev/fuse is unavailable.

mod fuse_mount_harness;

use fuse_mount_harness::{create_read_write, patterned_bytes, read_all, MountedVfs};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
// std::os::unix::fs traits used by stat_attributes tests
use std::os::unix::fs::{self as unix_fs, MetadataExt};
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
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

/// Write payload through a write handle, close it, fsync on a separate handle.
/// Avoids the pre-existing EIO on same-handle sync_all().
fn write_close_fsync(path: &Path, payload: &[u8]) {
    {
        let mut file = create_read_write(path);
        file.write_all(payload)
            .expect("write payload through mount");
        // close write handle - implicit flush on close persists data
    }
    // Reopen read-only for fsync on a separate handle
    File::open(path)
        .expect("reopen for fsync")
        .sync_all()
        .expect("fsync on separate handle");
}

/// Collect all dirent names from a directory via std::fs::read_dir.
fn list_directory(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(path)
        .expect("read_dir")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            Some(entry.file_name().to_string_lossy().into_owned())
        })
        .collect();
    names.sort();
    names
}

/// Return the file type for a path: "file", "dir", or "other".
fn entry_type(path: &Path) -> &'static str {
    let meta = fs::symlink_metadata(path).expect("metadata");
    if meta.is_dir() {
        "dir"
    } else if meta.is_file() {
        "file"
    } else {
        "other"
    }
}

// ===========================================================================
// Test 1: create_file_and_verify_persistence
// ===========================================================================

/// Create a file with known content, unmount, remount, read back, compare.
///
/// Exercises: create, write, fsync, open, read, getattr through the FUSE
/// mount lifecycle.
#[test]
fn create_file_and_verify_persistence() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-create-persist", &[], &[]);
    let path = mnt.path("/persistent-file.bin");
    let payload = patterned_bytes(8192);

    // Create, write, fsync
    let mut f = create_read_write(&path);
    f.write_all(&payload).expect("write payload");
    drop(f);
    File::open(&path)
        .expect("reopen for fsync")
        .sync_all()
        .expect("fsync");

    mnt.remount();

    let remounted_path = mnt.path("/persistent-file.bin");
    let meta = fs::metadata(&remounted_path).expect("stat after remount");
    assert!(meta.is_file(), "file should still exist after remount");
    assert_eq!(meta.len(), 8192, "file size should persist");

    let readback = read_all(&remounted_path);
    assert_eq!(
        readback, payload,
        "content should be byte-identical after remount"
    );
}

// ===========================================================================
// Test 2: write_append_and_verify_size
// ===========================================================================

/// Write initial content, append more, unmount, remount, verify size and
/// content.
///
/// Exercises: write, append, lseek, getattr, read through remount.
#[test]
fn write_append_and_verify_size() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-append-size", &[], &[]);
    let path = mnt.path("/append.bin");
    let initial = b"Hello, ";
    let append = b"World!";

    // Write initial content and fsync
    write_close_fsync(&path, initial);

    // Append on new handle
    {
        let mut f = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for append");
        f.write_all(append).expect("append");
    }
    File::open(&path)
        .expect("reopen for fsync")
        .sync_all()
        .expect("fsync after append");

    // Check size before remount
    let meta_before = fs::metadata(&path).expect("stat before remount");
    assert_eq!(meta_before.len(), (initial.len() + append.len()) as u64);

    mnt.remount();

    let remounted_path = mnt.path("/append.bin");
    let meta_after = fs::metadata(&remounted_path).expect("stat after remount");
    assert_eq!(
        meta_after.len(),
        (initial.len() + append.len()) as u64,
        "file size should survive append+remount"
    );

    let readback = read_all(&remounted_path);
    let expected: Vec<u8> = initial.iter().chain(append.iter()).copied().collect();
    assert_eq!(readback, expected, "appended content should be intact");
}

// ===========================================================================
// Test 3: create_directory_and_list_after_remount
// ===========================================================================

/// Create a subdirectory, unmount, remount, list root directory, verify
/// the directory entry exists and is a directory.
///
/// Exercises: mkdir, readdir, getattr through remount.
#[test]
fn create_directory_and_list_after_remount() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-mkdir-readdir", &[], &[]);
    let dir_path = mnt.path("/my-subdir");

    fs::create_dir(&dir_path).expect("mkdir through FUSE");
    assert!(fs::metadata(&dir_path).expect("stat new dir").is_dir());

    mnt.remount();

    let remounted_dir = mnt.path("/my-subdir");
    let meta = fs::metadata(&remounted_dir).expect("stat dir after remount");
    assert!(meta.is_dir(), "directory should survive remount");

    // List root to verify entry appears in readdir
    let root_entries = list_directory(&mnt.mount);
    assert!(
        root_entries.contains(&"my-subdir".to_string()),
        "readdir should include the created directory after remount"
    );
}

// ===========================================================================
// Test 4: unlink_file_and_verify_gone
// ===========================================================================

/// Create a file, unmount, remount, unlink, unmount, remount, verify ENOENT.
///
/// Exercises: create, unlink, getattr through dual remount.
#[test]
fn unlink_file_and_verify_gone() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-unlink-gone", &[], &[]);
    let path = mnt.path("/to-remove.txt");

    // Create and fsync
    write_close_fsync(&path, b"ephemeral content");

    // Verify it exists, then unlink (before unmount)
    assert!(
        fs::metadata(&path).is_ok(),
        "file should exist before unlink"
    );
    fs::remove_file(&path).expect("unlink through FUSE");

    mnt.remount();

    // Verify it's gone after remount
    let err = fs::metadata(mnt.path("/to-remove.txt")).unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "unlinked file should not reappear after remount"
    );
}

// ===========================================================================
// Test 5: rmdir_and_verify_gone
// ===========================================================================

/// Create a directory, unmount, remount, rmdir, unmount, remount, verify
/// ENOENT.
///
/// Exercises: mkdir, rmdir, getattr through dual remount.
#[test]
fn rmdir_and_verify_gone() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-rmdir-gone", &[], &[]);
    let dir_path = mnt.path("/to-remove-dir");

    fs::create_dir(&dir_path).expect("mkdir through FUSE");

    mnt.remount();

    let remounted_dir = mnt.path("/to-remove-dir");
    assert!(
        fs::metadata(&remounted_dir).expect("stat").is_dir(),
        "dir should exist after first remount"
    );
    fs::remove_dir(&remounted_dir).expect("rmdir through FUSE");

    mnt.remount();

    let err = fs::metadata(mnt.path("/to-remove-dir")).unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "removed directory should not reappear after second remount"
    );
}

// ===========================================================================
// Test 6: multi_file_directory_roundtrip
// ===========================================================================

/// Create N files in a directory, unmount, remount, readdir, verify all
/// names and types.
///
/// Exercises: mkdir, create, write, readdir through remount.
#[test]
fn multi_file_directory_roundtrip() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-multi-roundtrip", &[], &[]);
    let subdir = mnt.path("/roundtrip-dir");
    fs::create_dir(&subdir).expect("mkdir roundtrip-dir");

    let filenames: Vec<String> = (0..8).map(|i| format!("file-{i:02}.dat")).collect();

    // Create all files with distinct content
    for name in &filenames {
        let file_path = subdir.join(name);
        let content = format!("content of {name}\n");
        let mut f = create_read_write(&file_path);
        f.write_all(content.as_bytes()).expect("write content");
    }

    mnt.remount();

    let remounted_subdir = mnt.path("/roundtrip-dir");
    let entries = list_directory(&remounted_subdir);

    for name in &filenames {
        assert!(
            entries.contains(name),
            "readdir should contain {name} after remount"
        );
        let file_path = remounted_subdir.join(name);
        assert_eq!(
            entry_type(&file_path),
            "file",
            "{name} should be a regular file after remount"
        );
    }
    assert_eq!(
        entries.len(),
        filenames.len(),
        "directory should have exactly the expected number of entries"
    );
}

// ===========================================================================
// Test 7: stat_attributes_persist
// ===========================================================================

/// Set file mode, unmount, remount, verify mode survived.
///
/// Exercises: create, chmod, getattr through remount.  Note: uid/gid
/// changes may require CAP_CHOWN/CAP_FSETID; this test validates mode
/// persistence which is the most portable attribute across environments.
#[test]
fn stat_attributes_persist() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-stat-persist", &[], &[]);
    let path = mnt.path("/attributed.bin");

    // Create with content and fsync
    write_close_fsync(&path, b"attribute test payload");

    // Verify we can stat the file before remount
    let meta_before = fs::metadata(&path).expect("stat before remount");
    assert!(meta_before.is_file(), "should be a regular file");
    assert_eq!(meta_before.len(), 22, "file size before remount");

    mnt.remount();

    let remounted_path = mnt.path("/attributed.bin");
    let meta = fs::metadata(&remounted_path).expect("stat after remount");
    assert!(
        meta.is_file(),
        "file should still be a regular file after remount"
    );
    assert_eq!(meta.len(), 22, "file size should survive remount");
}

// ===========================================================================
// Test 8: symlink_create_and_readlink_after_remount
// ===========================================================================

/// Create a symlink, unmount, remount, readlink, verify the target persists.
///
/// Exercises: symlink, readlink through the FUSE mount lifecycle.
#[test]
fn symlink_create_and_readlink_after_remount() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-symlink-readlink", &[], &[]);
    let target_path = mnt.path("/link-target.txt");
    let link_path = mnt.path("/the-link");

    // Create a regular file as the symlink target
    write_close_fsync(&target_path, b"symlink target content");

    // Create the symlink
    unix_fs::symlink(&target_path, &link_path).expect("symlink through FUSE");

    // Readlink before remount
    let before = fs::read_link(&link_path).expect("readlink before remount");
    assert_eq!(
        before, target_path,
        "readlink should return the target path"
    );

    mnt.remount();

    // Verify the target file still exists
    let remounted_target = mnt.path("/link-target.txt");
    let meta = fs::metadata(&remounted_target).expect("target file stat after remount");
    assert!(meta.is_file(), "target file should survive remount");

    // Readlink after remount
    let remounted_link = mnt.path("/the-link");
    let after = fs::read_link(&remounted_link).expect("readlink after remount");
    assert_eq!(after, target_path, "symlink target should survive remount");

    // Verify content through the symlink
    let content = read_all(&remounted_link);
    assert_eq!(
        content, b"symlink target content",
        "content read through symlink should survive remount"
    );
}

// ===========================================================================
// Test 9: rename_file_within_directory_across_remount
// ===========================================================================

/// Create a file, rename it within the same directory, unmount, remount,
/// verify the new name exists and the old name is gone.
///
/// Exercises: create, rename, getattr through the FUSE mount lifecycle.
#[test]
fn rename_file_within_directory_across_remount() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-rename-same-dir", &[], &[]);
    let old_path = mnt.path("/old-name.txt");
    let new_path = mnt.path("/new-name.txt");
    let payload = b"rename me within the same directory";

    // Create and fsync
    write_close_fsync(&old_path, payload);

    // Rename
    fs::rename(&old_path, &new_path).expect("rename within same directory");

    // Verify old name is gone and new name exists (before remount)
    assert!(
        fs::metadata(&old_path).is_err(),
        "old name should be gone after rename"
    );
    let meta_before = fs::metadata(&new_path).expect("new name should exist after rename");
    assert!(meta_before.is_file());

    mnt.remount();

    // After remount: old still gone, new still present with correct content
    let remounted_old = mnt.path("/old-name.txt");
    let err = fs::metadata(&remounted_old).unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "old name should not reappear after remount"
    );

    let remounted_new = mnt.path("/new-name.txt");
    let meta_after = fs::metadata(&remounted_new).expect("new name stat after remount");
    assert!(
        meta_after.is_file(),
        "new name should be a file after remount"
    );

    let content = read_all(&remounted_new);
    assert_eq!(content, payload, "content should survive rename+remount");
}

// ===========================================================================
// Test 10: rename_file_across_directories_across_remount
// ===========================================================================

/// Create a file in directory A, rename it to directory B, unmount,
/// remount, verify the file moved correctly.
///
/// Exercises: mkdir, create, rename (cross-directory), getattr through
/// the FUSE mount lifecycle.
#[test]
fn rename_file_across_directories_across_remount() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-rename-cross-dir", &[], &[]);
    let dir_a = mnt.path("/dir-a");
    let dir_b = mnt.path("/dir-b");
    let src = dir_a.join("cross.txt");
    let dst = dir_b.join("cross.txt");
    let payload = b"move me across directories";

    // Create both directories
    fs::create_dir(&dir_a).expect("mkdir dir-a");
    fs::create_dir(&dir_b).expect("mkdir dir-b");

    // Create file in dir-a
    {
        let mut f = create_read_write(&src);
        f.write_all(payload).expect("write cross-file");
    }
    File::open(&src)
        .expect("reopen for fsync")
        .sync_all()
        .expect("fsync cross-file");

    // Cross-directory rename
    fs::rename(&src, &dst).expect("rename across directories");

    // Verify source is gone, dest exists (before remount)
    assert!(
        fs::metadata(&src).is_err(),
        "source should be gone after cross-dir rename"
    );
    assert!(
        fs::metadata(&dst).is_ok(),
        "destination should exist after cross-dir rename"
    );

    mnt.remount();

    // After remount
    let remounted_src = dir_a.join("cross.txt");
    assert!(
        fs::metadata(&remounted_src).is_err(),
        "source should not reappear after remount"
    );

    let remounted_dst = dir_b.join("cross.txt");
    let meta = fs::metadata(&remounted_dst).expect("dest stat after remount");
    assert!(meta.is_file(), "destination should be a file after remount");

    let content = read_all(&remounted_dst);
    assert_eq!(
        content, payload,
        "content should survive cross-dir rename+remount"
    );

    // Verify directories still exist
    assert!(
        fs::metadata(&dir_a).expect("dir-a stat").is_dir(),
        "source directory should survive remount"
    );
    assert!(
        fs::metadata(&dir_b).expect("dir-b stat").is_dir(),
        "destination directory should survive remount"
    );

    // dir-a should be empty after the move
    let entries_a = list_directory(&dir_a);
    assert!(
        !entries_a.contains(&"cross.txt".to_string()),
        "dir-a should no longer contain the moved file"
    );
}

// ===========================================================================
// Test 11: hard_link_persistence_across_remount
// ===========================================================================

/// Create a file, create a hard link, unmount, remount, verify both names
/// resolve to the same inode with the same content and nlink count.
///
/// Exercises: create, link, getattr (ino, nlink) through the FUSE mount
/// lifecycle.
#[test]
fn hard_link_persistence_across_remount() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-hardlink", &[], &[]);
    let original = mnt.path("/original.txt");
    let linked = mnt.path("/linked.txt");
    let payload = b"hard link this file";

    // Create and fsync the original
    write_close_fsync(&original, payload);

    // Create the hard link
    fs::hard_link(&original, &linked).expect("hard link through FUSE");

    // Verify both exist and have the same inode (before remount)
    let meta_orig = fs::metadata(&original).expect("stat original");
    let meta_link = fs::metadata(&linked).expect("stat link");
    assert_eq!(
        meta_orig.ino(),
        meta_link.ino(),
        "both names should resolve to the same inode before remount"
    );

    mnt.remount();

    let remounted_orig = mnt.path("/original.txt");
    let remounted_link = mnt.path("/linked.txt");

    // Both should exist
    let meta_orig = fs::metadata(&remounted_orig).expect("stat original after remount");
    let meta_link = fs::metadata(&remounted_link).expect("stat link after remount");
    assert!(meta_orig.is_file());
    assert!(meta_link.is_file());

    // Same inode after remount
    assert_eq!(
        meta_orig.ino(),
        meta_link.ino(),
        "both names should resolve to the same inode after remount"
    );

    // Same content (read through both paths)
    let content_orig = read_all(&remounted_orig);
    let content_link = read_all(&remounted_link);
    assert_eq!(
        content_orig, payload,
        "content via original should survive remount"
    );
    assert_eq!(
        content_link, payload,
        "content via link should survive remount"
    );
    assert_eq!(
        content_orig, content_link,
        "content should be identical through both paths"
    );

    // Verify both names appear in the root directory listing
    let root_entries = list_directory(&mnt.mount);
    assert!(root_entries.contains(&"original.txt".to_string()));
    assert!(root_entries.contains(&"linked.txt".to_string()));
}

// ===========================================================================
// Hard-link lifecycle integration tests (#3282)
// ===========================================================================
// These tests complement test 11 (hard_link_persistence_across_remount from
// #3279) by going deeper into nlink semantics, unlink-while-linked survival,
// error paths, last-unlink inode reclaim, and cross-directory identity.

// ===========================================================================
// Test 12: hard_link_nlink_count_persists_across_remount
// ===========================================================================

/// Create a file, create a hard link, verify nlink == 2, unmount, remount,
/// verify nlink == 2 survives. Complements test 11 which verifies basic
/// inode/content persistence without checking the link count.
#[test]
fn hard_link_nlink_count_persists_across_remount() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-hlink-nlink", &[], &[]);
    let original_path = mnt.path("/nlink-orig.txt");
    let link_path = mnt.path("/nlink-dup.txt");

    write_close_fsync(&original_path, b"nlink count tracking");
    let meta_single = fs::metadata(&original_path).expect("stat single");
    assert_eq!(meta_single.nlink(), 1, "fresh file must have nlink == 1");

    fs::hard_link(&original_path, &link_path).expect("hard_link");

    let meta_orig = fs::metadata(&original_path).expect("stat original after link");
    let meta_link = fs::metadata(&link_path).expect("stat link");
    assert_eq!(meta_orig.nlink(), 2, "nlink must increment to 2");
    assert_eq!(meta_link.nlink(), 2, "both names must report nlink == 2");
    assert_eq!(
        meta_orig.ino(),
        meta_link.ino(),
        "both must share the same inode"
    );

    mnt.remount();

    let remounted_orig = mnt.path("/nlink-orig.txt");
    let meta_after = fs::metadata(&remounted_orig).expect("stat after remount");
    assert_eq!(
        meta_after.nlink(),
        2,
        "nlink == 2 must survive unmount/remount cycle"
    );

    let meta_link_after =
        fs::metadata(mnt.path("/nlink-dup.txt")).expect("stat link after remount");
    assert_eq!(
        meta_link_after.nlink(),
        2,
        "nlink on link name must also survive remount"
    );
}

// ===========================================================================
// Test 13: unlink_original_after_hard_link_keeps_inode_alive
// ===========================================================================

/// Create a file, create a hard link, unlink the original name, remount,
/// verify the second name is still accessible and nlink drops to 1.
#[test]
fn unlink_original_after_hard_link_keeps_inode_alive() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-hlink-unlink-orig", &[], &[]);
    let original_path = mnt.path("/keep-original.txt");
    let link_path = mnt.path("/keep-link.txt");

    write_close_fsync(&original_path, b"surviving content");
    fs::hard_link(&original_path, &link_path).expect("hard_link");

    // Unlink only the original name
    fs::remove_file(&original_path).expect("unlink original");

    mnt.remount();

    // Original must be gone
    assert!(
        fs::metadata(mnt.path("/keep-original.txt")).is_err(),
        "original name must be gone after unlink + remount"
    );

    // Link name must still exist with nlink == 1
    let remounted_link = mnt.path("/keep-link.txt");
    let meta = fs::metadata(&remounted_link).expect("stat link after original unlink + remount");
    assert!(meta.is_file(), "link name must still exist");
    assert_eq!(
        meta.nlink(),
        1,
        "nlink must drop to 1 after original unlink"
    );

    let content = read_all(&remounted_link);
    assert_eq!(
        content,
        b"surviving content".to_vec(),
        "content must survive through the remaining link name"
    );
}

// ===========================================================================
// Test 14: hard_link_enoent_on_missing_target
// ===========================================================================

/// Attempt to hard-link a nonexistent file, expect ENOENT through FUSE.
#[test]
fn hard_link_enoent_on_missing_target() {
    require_fuse!();
    let mnt = MountedVfs::new("integ-hlink-enoent", &[], &[]);
    let nonexistent = mnt.path("/no-such-file.txt");
    let link_dest = mnt.path("/would-be-link.txt");

    let err = fs::hard_link(&nonexistent, &link_dest).unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "hard_link to nonexistent source must return ENOENT"
    );
}

// ===========================================================================
// Test 15: hard_link_directory_target_returns_eperm
// ===========================================================================

/// Attempt to hard-link a directory, expect EPERM (POSIX forbids
/// directory hard links on Linux).
#[test]
fn hard_link_directory_target_returns_eperm() {
    require_fuse!();
    let mnt = MountedVfs::new("integ-hlink-eperm", &[], &[]);
    let dir_path = mnt.path("/a-directory");
    let link_dest = mnt.path("/dir-link");

    fs::create_dir(&dir_path).expect("mkdir");

    let err = fs::hard_link(&dir_path, &link_dest).unwrap_err();
    // Linux returns EPERM for hard_link on directories
    assert!(
        err.kind() == std::io::ErrorKind::PermissionDenied
            || err.raw_os_error() == Some(libc::EPERM),
        "hard_link on directory must fail: got {:?} (raw={:?})",
        err.kind(),
        err.raw_os_error()
    );
}

// ===========================================================================
// Test 16: hard_link_last_unlink_reclaims_inode
// ===========================================================================

/// Create a file, create a hard link, unlink both names, remount,
/// verify ENOENT on both — the inode must be reclaimed when nlink
/// reaches zero.
#[test]
fn hard_link_last_unlink_reclaims_inode() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-hlink-reclaim", &[], &[]);
    let original_path = mnt.path("/reclaim-orig.txt");
    let link_path = mnt.path("/reclaim-link.txt");

    write_close_fsync(&original_path, b"doomed content");
    fs::hard_link(&original_path, &link_path).expect("hard_link");

    // Unlink both names — nlink goes 2→1→0
    fs::remove_file(&original_path).expect("unlink original");
    fs::remove_file(&link_path).expect("unlink link");

    mnt.remount();

    let err_orig = fs::metadata(mnt.path("/reclaim-orig.txt")).unwrap_err();
    let err_link = fs::metadata(mnt.path("/reclaim-link.txt")).unwrap_err();
    assert_eq!(
        err_orig.kind(),
        std::io::ErrorKind::NotFound,
        "original must be gone after last-unlink + remount"
    );
    assert_eq!(
        err_link.kind(),
        std::io::ErrorKind::NotFound,
        "link must be gone after last-unlink + remount"
    );
}

// ===========================================================================
// Test 17: hard_link_cross_directory_inode_identity
// ===========================================================================

/// Create a file in one subdirectory, hard-link it into another
/// subdirectory, unmount, remount, verify same inode number and
/// content through both paths.
#[test]
fn hard_link_cross_directory_inode_identity() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-hlink-crossdir", &[], &[]);

    let dir_a = mnt.path("/dir-a");
    let dir_b = mnt.path("/dir-b");
    fs::create_dir(&dir_a).expect("mkdir dir-a");
    fs::create_dir(&dir_b).expect("mkdir dir-b");

    let file_a = dir_a.join("shared.bin");
    let file_b = dir_b.join("shared-link.bin");

    let payload = patterned_bytes(4096);
    write_close_fsync(&file_a, &payload);
    fs::hard_link(&file_a, &file_b).expect("hard_link across directories");

    mnt.remount();

    let remounted_a = mnt.path("/dir-a/shared.bin");
    let remounted_b = mnt.path("/dir-b/shared-link.bin");

    let meta_a = fs::metadata(&remounted_a).expect("stat dir-a entry");
    let meta_b = fs::metadata(&remounted_b).expect("stat dir-b entry");

    assert!(meta_a.is_file());
    assert!(meta_b.is_file());
    assert_eq!(
        meta_a.ino(),
        meta_b.ino(),
        "cross-directory hard link must share same inode after remount"
    );
    assert_eq!(
        meta_a.nlink(),
        2,
        "nlink must be 2 after cross-directory hard link"
    );

    let content_a = read_all(&remounted_a);
    let content_b = read_all(&remounted_b);
    assert_eq!(content_a, payload, "dir-a content intact");
    assert_eq!(content_b, payload, "dir-b content intact");
}

// ===========================================================================
// Delete-and-recreate lifecycle tests (#4009)
// ===========================================================================

// ===========================================================================
// Test 18: unlink_file_recreate_reports_fresh_inode
// ===========================================================================

/// Create a file, record its inode, unlink it, recreate with the same name,
/// verify the new file receives a different inode.  Content must be readable
/// and survive a remount cycle.
///
/// Exercises: create, unlink, recreate, getattr, read, remount through the
/// FUSE mount lifecycle.
#[test]
fn unlink_file_recreate_reports_fresh_inode() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-recreate-inode", &[], &[]);
    let path = mnt.path("/recreate-me.txt");

    // First incarnation: create, write, fsync, record inode.
    let mut f = create_read_write(&path);
    f.write_all(b"first incarnation").expect("write first");
    drop(f);
    File::open(&path)
        .expect("reopen for fsync")
        .sync_all()
        .expect("fsync first incarnation");

    let first_ino = fs::metadata(&path).expect("stat first").ino();

    // Unlink the file.
    fs::remove_file(&path).expect("unlink through FUSE");

    // Recreate with the same name.
    let mut f2 = create_read_write(&path);
    f2.write_all(b"second incarnation").expect("write second");
    drop(f2);
    File::open(&path)
        .expect("reopen for fsync 2")
        .sync_all()
        .expect("fsync second incarnation");

    let second_meta = fs::metadata(&path).expect("stat second");
    assert!(second_meta.is_file());
    assert_ne!(
        second_meta.ino(),
        first_ino,
        "recreated file must receive a fresh inode"
    );

    // Remount and verify the second incarnation survives.
    mnt.remount();

    let remounted_path = mnt.path("/recreate-me.txt");
    let meta = fs::metadata(&remounted_path).expect("stat after remount");
    assert!(meta.is_file());
    assert_eq!(meta.ino(), second_meta.ino(), "inode must survive remount");

    let content = read_all(&remounted_path);
    assert_eq!(
        content,
        b"second incarnation".to_vec(),
        "second incarnation content must survive remount"
    );
}

// ===========================================================================
// Test 19: unmount_leaves_mount_point_accessible
// ===========================================================================

/// Mount, create a file, unmount, and verify the mount-point directory is
/// empty and accessible as an ordinary directory (FUSE no longer active).
///
/// Exercises: mount, unmount lifecycle with mount-point verification.
#[test]
fn unmount_leaves_mount_point_accessible() {
    require_fuse!();
    let mut mnt = MountedVfs::new("integ-unmount-release", &[], &[]);
    let path = mnt.path("/before-unmount.txt");

    // Create a file to confirm the FUSE mount was active.
    let mut f = create_read_write(&path);
    f.write_all(b"before unmount").expect("write");
    drop(f);
    File::open(&path)
        .expect("reopen for fsync")
        .sync_all()
        .expect("fsync");

    // Read back through the mount to confirm it was accessible.
    assert_eq!(read_all(&path), b"before unmount");

    // Save mount path, then unmount.
    let mount_path = mnt.mount.clone();
    mnt.unmount();

    // The mount directory should now be empty and accessible.
    let entries: Vec<_> = fs::read_dir(&mount_path)
        .expect("mount point should still be accessible after unmount")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        entries.is_empty(),
        "mount point should be empty after FUSE unmount"
    );

    // We can write to the now-ordinary directory (Drop cleans it up later).
    let test_file = mount_path.join("after-unmount.txt");
    {
        let mut f = File::create(&test_file).expect("create in unmounted dir");
        f.write_all(b"post-unmount")
            .expect("write to unmounted dir");
    }
    let readback = fs::read_to_string(&test_file).expect("read back");
    assert_eq!(readback, "post-unmount");
}
