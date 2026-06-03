//! FUSE directory operation integration tests with remount-persistence
//! verification.
//!
//! Exercises mkdir, rmdir, readdir, and rename through a real FUSE mount,
//! verifying correctness before and after an unmount/remount cycle.
//! Each test guards against missing /dev/fuse by skipping gracefully.

mod fuse_mount_harness;

use fuse_mount_harness::MountedVfs;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Collect directory entry names into a sorted BTreeSet.
fn list_dir(path: &Path) -> BTreeSet<String> {
    fs::read_dir(path)
        .expect("read_dir")
        .filter_map(|e| {
            let entry = e.ok()?;
            Some(entry.file_name().to_string_lossy().into_owned())
        })
        .collect()
}

/// Write data to a file and fsync through a separate handle.
fn write_and_fsync(path: &Path, data: &[u8]) {
    {
        let mut f = File::create_new(path).expect("create file");
        f.write_all(data).expect("write");
    }
    File::open(path)
        .expect("reopen for fsync")
        .sync_all()
        .expect("fsync");
}

/// Return "d" for directories, "f" for files.
fn entry_kind(path: &Path) -> &'static str {
    let meta = fs::symlink_metadata(path).expect("symlink_metadata");
    if meta.is_dir() {
        "d"
    } else if meta.is_file() {
        "f"
    } else {
        "?"
    }
}

/// Recursively collect directory tree info as (relative_path, kind)
/// tuples, sorted by path. "relative_path" is computed from `base`.
fn tree_snapshot(base: &Path) -> Vec<(String, &'static str)> {
    let mut result = Vec::new();
    let mut stack: Vec<(PathBuf, String)> = vec![(base.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read_dir") {
            let entry = entry.expect("entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let path = entry.path();
            let kind = entry_kind(&path);
            result.push((rel.clone(), kind));
            if kind == "d" {
                stack.push((path, rel));
            }
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

// ===========================================================================
// Test 1: Nested directory tree survives remount
// ===========================================================================

/// Creates a 3-level nested directory tree (2 subdirs per level),
/// verifies readdir at each level, remounts, and re-verifies the full tree.
#[test]
fn test_directory_create_readdir_remount() {
    require_fuse!();
    let mut mnt = MountedVfs::new("dir-ops-1", &[], &[]);

    // Build: root / L1-a, L1-b
    //        L1-a / L2-a-a, L2-a-b
    //        L1-b / L2-b-a, L2-b-b
    //        each L2 / L3-1, L3-2
    let root = mnt.path("/");
    let l1a = mnt.path("/L1-a");
    let l1b = mnt.path("/L1-b");
    fs::create_dir(&l1a).expect("mkdir L1-a");
    fs::create_dir(&l1b).expect("mkdir L1-b");

    let l2aa = l1a.join("L2-a-a");
    let l2ab = l1a.join("L2-a-b");
    let l2ba = l1b.join("L2-b-a");
    let l2bb = l1b.join("L2-b-b");
    fs::create_dir(&l2aa).expect("mkdir L2-a-a");
    fs::create_dir(&l2ab).expect("mkdir L2-a-b");
    fs::create_dir(&l2ba).expect("mkdir L2-b-a");
    fs::create_dir(&l2bb).expect("mkdir L2-b-b");

    for l2 in &[&l2aa, &l2ab, &l2ba, &l2bb] {
        fs::create_dir(l2.join("L3-1")).expect("mkdir L3-1");
        fs::create_dir(l2.join("L3-2")).expect("mkdir L3-2");
    }

    // Verify root readdir: exactly L1-a and L1-b
    let root_entries = list_dir(&root);
    assert_eq!(root_entries.len(), 2);
    assert!(root_entries.contains("L1-a"));
    assert!(root_entries.contains("L1-b"));

    // Verify L1-a readdir
    let l1a_entries = list_dir(&l1a);
    assert_eq!(l1a_entries.len(), 2);
    assert!(l1a_entries.contains("L2-a-a"));
    assert!(l1a_entries.contains("L2-a-b"));

    // Verify L2-a-a readdir
    let l2aa_entries = list_dir(&l2aa);
    assert_eq!(l2aa_entries.len(), 2);
    assert!(l2aa_entries.contains("L3-1"));
    assert!(l2aa_entries.contains("L3-2"));

    // Snapshot full tree before remount
    let before = tree_snapshot(&root);
    for (_name, kind) in &before {
        assert_eq!(
            *kind, "d",
            "all entries in nested-dir tree must be directories"
        );
    }

    // Remount
    mnt.remount();

    // Re-verify full tree matches
    let after = tree_snapshot(&root);
    assert_eq!(
        after, before,
        "directory tree must be identical after remount"
    );
}

// ===========================================================================
// Test 2: Atomic rename within same directory survives remount
// ===========================================================================

/// Creates a file, renames it within the same directory, verifies old
/// name is gone and new name is present via readdir, remounts and re-verifies.
#[test]
fn test_rename_atomic_same_dir() {
    require_fuse!();
    let mut mnt = MountedVfs::new("dir-ops-2", &[], &[]);

    let old_path = mnt.path("/pre-rename.txt");
    let new_path = mnt.path("/post-rename.txt");
    let payload = b"rename me within the same directory\n";

    write_and_fsync(&old_path, payload);

    // Verify both names before rename
    let before = list_dir(&mnt.mount);
    assert!(
        before.contains("pre-rename.txt"),
        "old name must exist before rename"
    );
    assert!(
        !before.contains("post-rename.txt"),
        "new name must not exist before rename"
    );

    // Atomic rename
    fs::rename(&old_path, &new_path).expect("rename within same dir");

    // Verify after rename
    let after_rename = list_dir(&mnt.mount);
    assert!(
        !after_rename.contains("pre-rename.txt"),
        "old name must be gone after rename"
    );
    assert!(
        after_rename.contains("post-rename.txt"),
        "new name must exist after rename"
    );
    assert!(
        fs::metadata(&new_path).is_ok(),
        "new path must be stat-able"
    );
    assert!(
        fs::metadata(&old_path).is_err(),
        "old path must return ENOENT"
    );

    // Content accessible at new name
    let content = fs::read(&new_path).expect("read at new name");
    assert_eq!(content, payload);

    mnt.remount();

    // Re-verify after remount
    let after_remount = list_dir(&mnt.mount);
    assert!(
        !after_remount.contains("pre-rename.txt"),
        "old name must not reappear after remount"
    );
    assert!(
        after_remount.contains("post-rename.txt"),
        "new name must persist after remount"
    );

    let content_remounted = fs::read(mnt.path("/post-rename.txt")).expect("read after remount");
    assert_eq!(
        content_remounted, payload,
        "content must survive rename + remount"
    );
}

// ===========================================================================
// Test 3: Atomic rename across directories survives remount
// ===========================================================================

/// Creates source and target directories each with content, renames a file
/// across directories, verifies readdir results for both directories,
/// remounts and re-verifies.
#[test]
fn test_rename_atomic_cross_dir() {
    require_fuse!();
    let mut mnt = MountedVfs::new("dir-ops-3", &[], &[]);

    let src_dir = mnt.path("/src-dir");
    let dst_dir = mnt.path("/dst-dir");
    fs::create_dir(&src_dir).expect("mkdir src-dir");
    fs::create_dir(&dst_dir).expect("mkdir dst-dir");

    // Populate source directory with two files: one to move, one to keep
    let mover_src = src_dir.join("mover.txt");
    let keeper_src = src_dir.join("keeper.txt");
    let mover_dst = dst_dir.join("mover.txt");

    write_and_fsync(&mover_src, b"file to be moved across directories\n");
    write_and_fsync(&keeper_src, b"file that stays behind\n");

    // Seed the destination directory with an existing file
    let existing_dst = dst_dir.join("already-here.txt");
    write_and_fsync(&existing_dst, b"pre-existing destination file\n");

    // Verify initial state
    let src_before = list_dir(&src_dir);
    assert!(src_before.contains("mover.txt"));
    assert!(src_before.contains("keeper.txt"));
    let dst_before = list_dir(&dst_dir);
    assert!(dst_before.contains("already-here.txt"));
    assert!(!dst_before.contains("mover.txt"));

    // Cross-directory rename
    fs::rename(&mover_src, &mover_dst).expect("rename across directories");

    // Verify after rename
    let src_after = list_dir(&src_dir);
    assert!(
        !src_after.contains("mover.txt"),
        "mover must be gone from src"
    );
    assert!(
        src_after.contains("keeper.txt"),
        "keeper must remain in src"
    );
    let dst_after = list_dir(&dst_dir);
    assert!(dst_after.contains("mover.txt"), "mover must appear in dst");
    assert!(
        dst_after.contains("already-here.txt"),
        "existing dst file must remain"
    );

    // Content verification through new path
    let content = fs::read(&mover_dst).expect("read mover at dst");
    assert_eq!(content, b"file to be moved across directories\n");

    mnt.remount();

    // Re-verify after remount
    let src_remount = list_dir(&mnt.path("/src-dir"));
    assert!(
        !src_remount.contains("mover.txt"),
        "mover must not reappear in src after remount"
    );
    assert!(
        src_remount.contains("keeper.txt"),
        "keeper must survive remount"
    );

    let dst_remount = list_dir(&mnt.path("/dst-dir"));
    assert!(
        dst_remount.contains("mover.txt"),
        "mover must persist in dst after remount"
    );
    assert!(
        dst_remount.contains("already-here.txt"),
        "existing dst file must survive remount"
    );

    let content_remounted =
        fs::read(mnt.path("/dst-dir/mover.txt")).expect("read mover after remount");
    assert_eq!(
        content_remounted, b"file to be moved across directories\n",
        "content must survive cross-dir rename + remount"
    );
}

// ===========================================================================
// Test 4: rmdir on non-empty directory fails, then succeeds after cleanup
// ===========================================================================

/// Creates a directory with a file inside, attempts rmdir and asserts
/// ENOTEMPTY, removes the file, then retries rmdir successfully.
#[test]
fn test_rmdir_nonempty_fails() {
    require_fuse!();
    let mnt = MountedVfs::new("dir-ops-4", &[], &[]);

    let dir = mnt.path("/nonempty-dir");
    fs::create_dir(&dir).expect("mkdir");
    let child = dir.join("child.txt");
    write_and_fsync(&child, b"blocking child file\n");

    // Attempt to rmdir a non-empty directory
    let err = fs::remove_dir(&dir).expect_err("rmdir non-empty should fail");
    let raw = err.raw_os_error();
    assert!(
        raw == Some(libc::ENOTEMPTY) || raw == Some(libc::EEXIST),
        "expected ENOTEMPTY or EEXIST, got raw={raw:?} kind={:?}",
        err.kind()
    );

    // Directory and child must survive the failed rmdir
    assert!(fs::metadata(&dir).is_ok(), "dir must survive failed rmdir");
    assert!(
        fs::metadata(&child).is_ok(),
        "child must survive failed rmdir"
    );

    // Remove the blocking child
    fs::remove_file(&child).expect("unlink child");

    // Now rmdir should succeed
    fs::remove_dir(&dir).expect("rmdir after removing child");

    // Verify the directory is gone
    let err_after = fs::metadata(&dir).unwrap_err();
    assert_eq!(
        err_after.kind(),
        std::io::ErrorKind::NotFound,
        "dir must be gone after successful rmdir"
    );
}

// ===========================================================================
// Test 5: Large directory (1000 entries) survives remount
// ===========================================================================

/// Creates 1000 files in a single directory, verifies readdir returns
/// exactly 1000 entries, spot-checks 10 random entries after remount.
#[test]
fn test_readdir_large_directory() {
    require_fuse!();
    let mut mnt = MountedVfs::new("dir-ops-5", &[], &[]);

    let dir = mnt.path("/large-dir");
    fs::create_dir(&dir).expect("mkdir large-dir");

    const COUNT: usize = 1000;
    let mut created: BTreeSet<String> = BTreeSet::new();
    for i in 0..COUNT {
        let name = format!("entry_{i:04}.dat");
        let path = dir.join(&name);
        write_and_fsync(&path, format!("content {i}\n").as_bytes());
        created.insert(name);
    }

    // Verify all 1000 entries visible through readdir
    let found = list_dir(&dir);
    assert_eq!(
        found.len(),
        COUNT,
        "readdir must return exactly {COUNT} entries"
    );
    assert_eq!(found, created, "all created entries must be visible");

    // Spot-check a few file sizes
    let samples: [usize; 10] = [0, 111, 222, 333, 444, 555, 666, 777, 888, 999];
    for idx in samples {
        let name = format!("entry_{idx:04}.dat");
        let path = dir.join(&name);
        let meta = fs::metadata(&path).expect("stat sample file");
        assert!(meta.is_file(), "entry {idx:04} must be a file");
    }

    mnt.remount();

    // Re-verify all 1000 entries after remount
    let remounted_dir = mnt.path("/large-dir");
    let found_after = list_dir(&remounted_dir);
    assert_eq!(
        found_after.len(),
        COUNT,
        "readdir must return exactly {COUNT} entries after remount"
    );
    assert_eq!(
        found_after, created,
        "all created entries must survive remount"
    );

    // Spot-check 10 entries after remount (different indices)
    let samples_after: [usize; 10] = [1, 100, 200, 300, 400, 500, 600, 700, 800, 900];
    for idx in samples_after {
        let name = format!("entry_{idx:04}.dat");
        let path = remounted_dir.join(&name);
        let meta = fs::metadata(&path).expect("stat sample after remount");
        assert!(meta.is_file(), "entry {idx:04} must survive remount");
        let content = fs::read_to_string(&path).expect("read sample after remount");
        assert_eq!(
            content,
            format!("content {idx}\n"),
            "content for entry {idx:04} must survive remount"
        );
    }
}
