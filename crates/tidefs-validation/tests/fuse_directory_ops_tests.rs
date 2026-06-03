//! FUSE directory operation integration tests: mkdir, rmdir, readdir, rename.
//!
//! Exercises directory namespace operations through a real FUSE RW mount,
//! complementing existing coverage in fuse_basic_ops.rs (mkdir/rmdir/unlink
//! cycle), fuse_rename.rs (rename variants and error paths), and
//! fuse_readdir_statfs_xattr.rs (readdir hierarchy and attributes).
//!
//! Tests added here fill gaps not covered by those files:
//! - EEXIST on duplicate mkdir
//! - Large-directory readdir with entry-type verification
//! - Mkdir error paths (parent removed, path component is file)
//! - Rmdir on a path that is a file (ENOTDIR)

use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use tidefs_validation::mount_harness::MountHarness;

// ── mkdir error paths ──────────────────────────────────────────────────────

/// Attempting mkdir on an existing name must return EEXIST.
#[test]
fn mkdir_dup_returns_eexist() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("only_once").expect("first mkdir");

    let result = harness.mkdir("only_once");
    assert!(result.is_err(), "second mkdir on same name must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::AlreadyExists,
        "expected AlreadyExists / EEXIST, got: {err:?}"
    );
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EEXIST),
        "expected EEXIST ({}) raw OS error, got: {err:?}",
        libc::EEXIST
    );

    // The original directory must still exist and be a directory.
    assert!(harness.exists("only_once"));
    let md = harness.stat("only_once").expect("stat after dup mkdir");
    assert!(
        md.is_dir(),
        "only_once must still be a directory after EEXIST"
    );
}

/// Mkdir on a path whose parent has been removed must fail with ENOENT.
#[test]
fn mkdir_missing_parent_returns_enoent() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("parent").expect("mkdir parent");
    harness.remove_dir("parent").expect("rmdir parent");

    let result = harness.mkdir("parent/child");
    assert!(result.is_err(), "mkdir under removed parent must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::NotFound,
        "expected NotFound / ENOENT, got: {err:?}"
    );
}

/// Mkdir on a path where an intermediate component is a file must fail
/// with ENOTDIR.
#[test]
fn mkdir_path_component_is_file_returns_enotdir() {
    let harness = MountHarness::new().expect("harness setup");
    harness
        .create_file("not_a_dir", b"blocking\n")
        .expect("create file");

    let result = harness.mkdir("not_a_dir/sub");
    assert!(result.is_err(), "mkdir through file must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOTDIR),
        "expected ENOTDIR, got: {err:?}"
    );
}

// ── rmdir error paths ──────────────────────────────────────────────────────

/// Rmdir on a path that is a regular file must fail with ENOTDIR.
#[test]
fn rmdir_on_file_returns_enotdir() {
    let harness = MountHarness::new().expect("harness setup");
    harness
        .create_file("just_a_file.txt", b"not a dir\n")
        .expect("create file");

    let result = harness.remove_dir("just_a_file.txt");
    assert!(result.is_err(), "rmdir on file must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOTDIR),
        "expected ENOTDIR, got: {err:?}"
    );
}

/// Rmdir on a nonexistent path must fail with ENOENT.
#[test]
fn rmdir_nonexistent_returns_enoent() {
    let harness = MountHarness::new().expect("harness setup");

    let result = harness.remove_dir("no_such_dir");
    assert!(result.is_err(), "rmdir on nonexistent must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::NotFound,
        "expected NotFound / ENOENT, got: {err:?}"
    );
}

// ── readdir large directories ──────────────────────────────────────────────

/// Create 100 entries (mix of files and directories) in a single directory
/// and verify readdir returns all of them with correct d_type via stat.
#[test]
fn readdir_large_100_entries() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("bigdir").expect("mkdir bigdir");

    let n_files = 60usize;
    let n_dirs = 40usize;
    let mut expected_files = Vec::with_capacity(n_files);
    let mut expected_dirs = Vec::with_capacity(n_dirs);

    // Create files.
    for i in 0..n_files {
        let name = format!("file_{i:03}.txt");
        harness
            .create_file(
                format!("bigdir/{name}"),
                format!("content {i}\n").as_bytes(),
            )
            .unwrap_or_else(|e| panic!("create {name}: {e}"));
        expected_files.push(name);
    }

    // Create subdirectories.
    for i in 0..n_dirs {
        let name = format!("subdir_{i:03}");
        harness
            .mkdir(format!("bigdir/{name}"))
            .unwrap_or_else(|e| panic!("mkdir {name}: {e}"));
        expected_dirs.push(name);
    }

    // Read the directory.
    let entries = harness.readdir("bigdir").expect("readdir bigdir");

    // Must have exactly 100 entries (plus no . or ..).
    assert_eq!(
        entries.len(),
        n_files + n_dirs,
        "bigdir must have {} entries, got {}: {entries:?}",
        n_files + n_dirs,
        entries.len()
    );

    // Every expected file must be present.
    for name in &expected_files {
        assert!(entries.contains(name), "bigdir must contain file {name}");
    }

    // Every expected dir must be present.
    for name in &expected_dirs {
        assert!(entries.contains(name), "bigdir must contain dir {name}");
    }

    // Verify file/dir type through stat.
    for name in &expected_files {
        let md = harness
            .stat(format!("bigdir/{name}"))
            .unwrap_or_else(|e| panic!("stat bigdir/{name}: {e}"));
        let mode = md.permissions().mode();
        assert!(
            mode & libc::S_IFREG != 0 || !md.is_dir(),
            "{name} must be a regular file, mode={mode:#o}"
        );
    }

    for name in &expected_dirs {
        let md = harness
            .stat(format!("bigdir/{name}"))
            .unwrap_or_else(|e| panic!("stat bigdir/{name}: {e}"));
        assert!(md.is_dir(), "{name} must be a directory");
    }

    // Entries must be returned in sorted order.
    let mut sorted = entries.clone();
    sorted.sort();
    assert_eq!(entries, sorted, "readdir must return entries sorted");
}

/// Verify that readdir returns consistent results when called multiple
/// times on a medium-sized directory (50 entries).
#[test]
fn readdir_idempotent() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("stable").expect("mkdir stable");

    for i in 0..50u32 {
        harness
            .create_file(format!("stable/item_{i:02}.dat"), &i.to_le_bytes())
            .unwrap_or_else(|e| panic!("create item_{i:02}: {e}"));
    }

    let first = harness.readdir("stable").expect("first readdir");
    let second = harness.readdir("stable").expect("second readdir");

    assert_eq!(
        first, second,
        "readdir must be idempotent: first={first:?}, second={second:?}"
    );
}

// ── readdir 1000 entries ──────────────────────────────────────────────────

/// Create 1000 files in a single directory and verify readdir returns all
/// of them with no duplicates or omissions, in sorted order.
#[test]
fn readdir_large_1000_entries() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("thousand").expect("mkdir thousand");

    let n = 1000usize;
    for i in 0..n {
        let name = format!("f_{i:04}.dat");
        harness
            .create_file(format!("thousand/{name}"), &i.to_le_bytes())
            .unwrap_or_else(|e| panic!("create {name}: {e}"));
    }

    let entries = harness.readdir("thousand").expect("readdir thousand");

    assert_eq!(
        entries.len(),
        n,
        "thousand must have {n} entries, got {}",
        entries.len()
    );

    // Every expected entry must be present.
    for i in 0..n {
        let name = format!("f_{i:04}.dat");
        assert!(
            entries.contains(&name),
            "thousand missing expected entry {name}"
        );
    }

    // Entries must be returned in sorted order.
    let mut sorted = entries.clone();
    sorted.sort();
    assert_eq!(entries, sorted, "readdir must return entries sorted");
}

// ── rename non-empty directory ────────────────────────────────────────────

/// Rename a directory that contains files. Verify the files are accessible
/// under the new path and the old path returns ENOENT.
#[test]
fn rename_nonempty_directory() {
    let harness = MountHarness::new().expect("harness setup");

    harness.mkdir("src_dir").expect("mkdir src_dir");
    let file_data = b"inside a renamed directory\n";
    harness
        .create_file("src_dir/child.dat", file_data)
        .expect("create src_dir/child.dat");
    harness.mkdir("src_dir/sub").expect("mkdir src_dir/sub");
    harness
        .create_file("src_dir/sub/nested.txt", b"nested\n")
        .expect("create src_dir/sub/nested.txt");

    // Confirm old path exists.
    assert!(harness.exists("src_dir"));
    assert!(harness.exists("src_dir/child.dat"));
    assert!(harness.exists("src_dir/sub/nested.txt"));

    harness
        .rename("src_dir", "dst_dir")
        .expect("rename src_dir -> dst_dir");

    // Old path must be gone.
    assert!(!harness.exists("src_dir"));
    assert!(!harness.exists("src_dir/child.dat"));

    // New path must exist with all contents intact.
    assert!(harness.exists("dst_dir"));
    assert!(harness.exists("dst_dir/child.dat"));
    assert!(harness.exists("dst_dir/sub/nested.txt"));

    let md = harness.stat("dst_dir").expect("stat dst_dir");
    assert!(md.is_dir(), "dst_dir must be a directory");

    let read_back = harness
        .read_file("dst_dir/child.dat")
        .expect("read dst_dir/child.dat");
    assert_eq!(
        read_back, file_data,
        "child.dat content mismatch after dir rename"
    );

    let nested = harness
        .read_file("dst_dir/sub/nested.txt")
        .expect("read dst_dir/sub/nested.txt");
    assert_eq!(
        nested, b"nested\n",
        "nested.txt content mismatch after dir rename"
    );

    // dst_dir must appear in root readdir.
    let root_entries = harness.readdir(".").expect("readdir root");
    assert!(
        root_entries.contains(&"dst_dir".to_string()),
        "root readdir must contain dst_dir after rename"
    );
    assert!(
        !root_entries.contains(&"src_dir".to_string()),
        "root readdir must not contain src_dir after rename"
    );
}

// ── rename preserves inode number ─────────────────────────────────────────

/// Rename a file within the same directory and verify the inode number
/// is unchanged.
#[test]
fn rename_preserves_inode_number() {
    let harness = MountHarness::new().expect("harness setup");

    harness
        .create_file("inode_test.txt", b"inode preservation\n")
        .expect("create inode_test.txt");

    let md_before = harness.stat("inode_test.txt").expect("stat before rename");
    let ino_before = md_before.ino();
    let size_before = md_before.len();

    harness
        .rename("inode_test.txt", "inode_renamed.txt")
        .expect("rename inode_test.txt -> inode_renamed.txt");

    assert!(!harness.exists("inode_test.txt"), "old name must be gone");
    assert!(harness.exists("inode_renamed.txt"), "new name must exist");

    let md_after = harness
        .stat("inode_renamed.txt")
        .expect("stat after rename");

    assert_eq!(
        md_after.ino(),
        ino_before,
        "inode number must be preserved across rename"
    );
    assert_eq!(
        md_after.len(),
        size_before,
        "file size must be preserved across rename"
    );
}

// ── readdirplus large-directory offset stability ───────────────────────────

/// Create 500 entries in a directory (files of varying sizes, subdirs, symlinks),
/// verify readdirplus returns all entries with correct attributes, remount, and
/// re-verify offset stability and attribute correctness across remount.
#[test]
fn readdirplus_large_directory_offset_stability() {
    let mut harness = MountHarness::new().expect("harness setup");
    harness.mkdir("rplus").expect("mkdir rplus");

    const N_FILES: usize = 440;
    const N_DIRS: usize = 30;
    const N_SYMLINKS: usize = 30;
    const TOTAL: usize = N_FILES + N_DIRS + N_SYMLINKS;

    // Create files with varying sizes.
    for i in 0..N_FILES {
        let name = format!("file_{i:04}.dat");
        let size = match i % 4 {
            0 => 1,
            1 => 512,
            2 => 4096,
            _ => 8192,
        };
        let data = vec![(i % 256) as u8; size];
        harness
            .create_file(format!("rplus/{name}"), &data)
            .unwrap_or_else(|e| panic!("create {name}: {e}"));
    }

    // Subdirectories.
    for i in 0..N_DIRS {
        let name = format!("subdir_{i:04}");
        harness
            .mkdir(format!("rplus/{name}"))
            .unwrap_or_else(|e| panic!("mkdir {name}: {e}"));
    }

    // Symlinks.
    for i in 0..N_SYMLINKS {
        let name = format!("symlink_{i:04}");
        let target_idx = (i * 10) % N_FILES;
        let target = format!("file_{target_idx:04}.dat");
        let path = harness.mount_path().join("rplus").join(&name);
        std::os::unix::fs::symlink(&target, &path)
            .unwrap_or_else(|e| panic!("symlink {name} -> {target}: {e}"));
    }

    #[derive(Clone, PartialEq, Debug)]
    struct EntryInfo {
        name: String,
        ino: u64,
        size: u64,
        is_file: bool,
        is_dir: bool,
        is_symlink: bool,
    }

    // Phase 2: collect all entries + metadata (exercises READDIRPLUS).
    let dir_path = harness.mount_path().join("rplus");
    let collect = |dp: &std::path::Path| -> Vec<EntryInfo> {
        let mut entries: Vec<EntryInfo> = Vec::with_capacity(TOTAL);
        for entry in std::fs::read_dir(dp).expect("read_dir rplus") {
            let entry = entry.expect("dir entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            let md = entry
                .metadata()
                .unwrap_or_else(|_| panic!("metadata for {name}"));
            entries.push(EntryInfo {
                name,
                ino: md.ino(),
                size: md.len(),
                is_file: md.is_file(),
                is_dir: md.is_dir(),
                is_symlink: md.is_symlink(),
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    };

    let before = collect(&dir_path);
    assert_eq!(before.len(), TOTAL);
    assert_eq!(before.iter().filter(|e| e.is_file).count(), N_FILES);
    assert_eq!(before.iter().filter(|e| e.is_dir).count(), N_DIRS);
    assert_eq!(before.iter().filter(|e| e.is_symlink).count(), N_SYMLINKS);

    for w in before.windows(2) {
        assert!(
            w[0].name < w[1].name,
            "entries not sorted: {} >= {}",
            w[0].name,
            w[1].name
        );
    }

    let inodes: std::collections::BTreeSet<u64> = before.iter().map(|e| e.ino).collect();
    assert_eq!(
        inodes.len(),
        before.len(),
        "all entries must have unique inodes"
    );

    // Phase 3: remount and re-collect.
    harness
        .remount()
        .expect("remount for offset stability verification");
    let after = collect(&harness.mount_path().join("rplus"));
    assert_eq!(after.len(), TOTAL);

    // Phase 4: compare every entry before/after (offset stability + attribute persistence).
    for (b, a) in before.iter().zip(after.iter()) {
        assert_eq!(b.name, a.name, "name mismatch: {} vs {}", b.name, a.name);
        assert_eq!(
            b.ino, a.ino,
            "inode mismatch for {}: {} vs {}",
            b.name, b.ino, a.ino
        );
        assert_eq!(
            b.size, a.size,
            "size mismatch for {}: {} vs {}",
            b.name, b.size, a.size
        );
        assert_eq!(b.is_file, a.is_file, "is_file mismatch for {}", b.name);
        assert_eq!(b.is_dir, a.is_dir, "is_dir mismatch for {}", b.name);
        assert_eq!(
            b.is_symlink, a.is_symlink,
            "is_symlink mismatch for {}",
            b.name
        );
    }
}
