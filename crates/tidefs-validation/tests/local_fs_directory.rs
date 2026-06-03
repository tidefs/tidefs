#![cfg(feature = "fuse")]

//! Local-filesystem directory operation integration tests.
//!
//! Exercises the LocalFileSystem directory API end-to-end: mkdir, rmdir,
//! readdir, and rename within a single session. Covers basic lifecycle,
//! nested directories, and rename within the same parent directory.
//!
//! No FUSE mount required — these tests exercise the in-memory harness
//! directly against the [`tidefs_local_filesystem::LocalFileSystem`] API.
//!
//! Filters:
//! - `cargo test -p tidefs-validation --features fuse -- local_fs_dir`

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tidefs_local_filesystem::{
    LocalFileSystem, RootAuthenticationKey, DEFAULT_DIRECTORY_PERMISSIONS, DEFAULT_FILE_PERMISSIONS,
};
use tidefs_local_object_store::StoreOptions;

// ── Helpers ──────────────────────────────────────────────────────────────

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-lfs-dir-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
}

fn store_opts() -> StoreOptions {
    StoreOptions {
        max_segment_bytes: 16 * 1024,
        sync_on_write: false,
        background_scrub_interval_secs: 0,
        reclaim_enabled: true,
        ..StoreOptions::durable()
    }
}

fn auth_key() -> RootAuthenticationKey {
    RootAuthenticationKey::demo_key()
}

fn open_fs(root: &Path) -> LocalFileSystem {
    LocalFileSystem::open_with_root_authentication_key(root, store_opts(), auth_key())
        .expect("open LocalFileSystem")
}

/// Collect entry names from a directory listing into a Vec<String>.
fn dir_entry_names(fs: &LocalFileSystem, path: &str) -> Vec<String> {
    fs.list_dir(path)
        .expect("list_dir")
        .iter()
        .map(|e| String::from_utf8_lossy(&e.name).to_string())
        .collect()
}

/// Assert an entry named `name` exists in a directory listing (any type).
fn assert_dir_has_entry(fs: &LocalFileSystem, dir: &str, name: &str) {
    let entries = fs.list_dir(dir).expect("list_dir");
    let found = entries.iter().find(|e| e.name == name.as_bytes());
    assert!(
        found.is_some(),
        "directory {dir} must contain entry '{name}'"
    );
    let entry = found.unwrap();
    assert!(
        (entry.mode & S_IFMT) == S_IFDIR,
        "entry '{name}' in {dir} must be a directory (mode=0o{mode:o})",
        mode = entry.mode
    );
}

// ═══════════════════════════════════════════════════════════════════════════
/// Assert an entry named `name` exists in a directory listing (any type).
fn assert_entry_exists(fs: &LocalFileSystem, dir: &str, name: &str) {
    let entries = fs.list_dir(dir).expect("list_dir");
    let found = entries.iter().find(|e| e.name == name.as_bytes());
    assert!(
        found.is_some(),
        "directory {dir} must contain entry '{name}'"
    );
}
// Category 1: Basic directory lifecycle
// ═══════════════════════════════════════════════════════════════════════════

/// Create a directory via mkdir and verify it appears in the root listing.
#[test]
fn local_fs_dir_mkdir_creates_entry() {
    let root = temp_root("mkdir");
    cleanup(&root);

    let mut fs = open_fs(&root);
    let rec = fs
        .create_dir("/newdir", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir");

    assert!(
        (rec.mode & S_IFMT) == S_IFDIR,
        "create_dir must return a directory inode, mode=0o{mode:o}",
        mode = rec.mode
    );
    assert_eq!(rec.mode & 0o777, DEFAULT_DIRECTORY_PERMISSIONS);

    let names = dir_entry_names(&fs, "/");
    assert!(
        names.contains(&"newdir".to_string()),
        "root listing must contain 'newdir', got: {names:?}"
    );

    // Verify via stat_path the entry is directory-typed.
    let stat_rec = fs.stat("/newdir").expect("stat");
    assert!(
        (stat_rec.mode & S_IFMT) == S_IFDIR,
        "stat must report directory kind, mode=0o{mode:o}",
        mode = stat_rec.mode
    );

    // Verify via lookup the entry is reachable.
    let inode_id = fs.lookup("/newdir").expect("lookup");
    assert_eq!(
        inode_id, rec.inode_id,
        "lookup must return the same inode id as create_dir"
    );

    cleanup(&root);
}

/// List a newly created directory: it must be empty (only `.` and `..`
/// are maintained internally, but list_dir returns only user-visible entries).
#[test]
fn local_fs_dir_readdir_empty_dir() {
    let root = temp_root("readdir-empty");
    cleanup(&root);

    let mut fs = open_fs(&root);
    fs.create_dir("/empty", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir");

    let entries = fs.list_dir("/empty").expect("list_dir");
    assert!(
        entries.is_empty(),
        "newly created directory must have zero user-visible entries, got {} entries",
        entries.len()
    );

    cleanup(&root);
}

/// Remove an empty directory via rmdir and verify it disappears from the
/// parent listing.
#[test]
fn local_fs_dir_rmdir_removes_entry() {
    let root = temp_root("rmdir");
    cleanup(&root);

    let mut fs = open_fs(&root);
    fs.create_dir("/todelete", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir");

    // Confirm it exists before removal.
    let names_before = dir_entry_names(&fs, "/");
    assert!(names_before.contains(&"todelete".to_string()));

    fs.remove_dir("/todelete").expect("remove_dir");

    // Confirm it is gone from parent listing.
    let names_after = dir_entry_names(&fs, "/");
    assert!(
        !names_after.contains(&"todelete".to_string()),
        "rmdir must remove the entry; still found in root listing"
    );

    // Lookup must fail after removal.
    let lookup_err = fs.lookup("/todelete").unwrap_err();
    assert!(
        lookup_err.to_string().contains("todelete"),
        "lookup after rmdir must fail with NotFound: {lookup_err}"
    );

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// Category 2: Nested directories
// ═══════════════════════════════════════════════════════════════════════════

/// Create a/b/c incrementally and verify each level is visible via readdir.
#[test]
fn local_fs_dir_nested_mkdir_incremental() {
    let root = temp_root("nested-mkdir");
    cleanup(&root);

    let mut fs = open_fs(&root);

    // Level 1
    fs.create_dir("/a", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /a");
    assert_dir_has_entry(&fs, "/", "a");

    // Level 2
    fs.create_dir("/a/b", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /a/b");
    assert_dir_has_entry(&fs, "/a", "b");

    // Level 3
    fs.create_dir("/a/b/c", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /a/b/c");
    assert_dir_has_entry(&fs, "/a/b", "c");

    // /a/b/c must be empty.
    let entries_c = fs.list_dir("/a/b/c").expect("list_dir /a/b/c");
    assert!(
        entries_c.is_empty(),
        "/a/b/c must be empty, got {} entries",
        entries_c.len()
    );

    cleanup(&root);
}

/// rmdir must reject a non-empty directory.
#[test]
fn local_fs_dir_rmdir_rejects_non_empty() {
    let root = temp_root("rmdir-nonempty");
    cleanup(&root);

    let mut fs = open_fs(&root);
    fs.create_dir("/parent", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /parent");
    fs.create_dir("/parent/child", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /parent/child");

    let err = fs.remove_dir("/parent").unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("empty") || err_msg.contains("not empty"),
        "rmdir on non-empty dir must return DirectoryNotEmpty: {err_msg}"
    );

    // Parent must still exist after failed rmdir.
    let names = dir_entry_names(&fs, "/");
    assert!(
        names.contains(&"parent".to_string()),
        "parent must still exist after rejected rmdir"
    );

    // Child must still exist.
    assert_dir_has_entry(&fs, "/parent", "child");

    cleanup(&root);
}

/// Recursive leaf-to-root delete: remove /a/b/c, then /a/b, then /a.
#[test]
fn local_fs_dir_recursive_leaf_to_root_delete() {
    let root = temp_root("recursive-delete");
    cleanup(&root);

    let mut fs = open_fs(&root);
    fs.create_dir("/a", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /a");
    fs.create_dir("/a/b", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /a/b");
    fs.create_dir("/a/b/c", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /a/b/c");

    // Delete leaf.
    fs.remove_dir("/a/b/c").expect("remove_dir /a/b/c");
    assert!(
        fs.list_dir("/a/b").expect("list_dir /a/b").is_empty(),
        "/a/b must be empty after removing c"
    );

    // Delete middle.
    fs.remove_dir("/a/b").expect("remove_dir /a/b");

    // Verify /a is now empty via listing.
    let a_entries = fs.list_dir("/a").expect("list_dir /a");
    assert!(
        a_entries.is_empty(),
        "/a must be empty after removing b, got {} entries",
        a_entries.len()
    );

    // Delete root-level dir.
    fs.remove_dir("/a").expect("remove_dir /a");

    let root_names = dir_entry_names(&fs, "/");
    assert!(
        !root_names.contains(&"a".to_string()),
        "/ must not contain 'a' after recursive delete"
    );

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// Category 3: Rename within directory
// ═══════════════════════════════════════════════════════════════════════════

/// Rename a file within the same parent directory.
/// Old name is removed, new name is present, inode identity is preserved.
#[test]
fn local_fs_dir_rename_within_same_parent() {
    let root = temp_root("rename-same-parent");
    cleanup(&root);

    let mut fs = open_fs(&root);
    let rec = fs
        .create_file("/old.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");
    let old_inode = rec.inode_id;

    fs.write_file("/old.txt", 0, b"hello").expect("write_file");

    fs.rename("/old.txt", "/new.txt", false).expect("rename");

    // Old name must be gone.
    let root_names = dir_entry_names(&fs, "/");
    assert!(
        !root_names.contains(&"old.txt".to_string()),
        "old name must not appear after rename"
    );
    assert!(
        root_names.contains(&"new.txt".to_string()),
        "new name must appear after rename"
    );

    // Inode identity must be preserved.
    let new_inode = fs.lookup("/new.txt").expect("lookup new");
    assert_eq!(new_inode, old_inode, "rename must preserve inode identity");

    // Content must survive rename.
    let content = fs.read_file("/new.txt").expect("read_file");
    assert_eq!(
        content, b"hello",
        "file content must survive rename unchanged"
    );

    // Old path must not exist.
    let old_err = fs.lookup("/old.txt").unwrap_err();
    assert!(
        old_err.to_string().contains("old.txt"),
        "old path must not be reachable after rename: {old_err}"
    );

    cleanup(&root);
}

/// Rename a file to itself (same source and destination path) is a no-op.
#[test]
fn local_fs_dir_rename_self_noop() {
    let root = temp_root("rename-self");
    cleanup(&root);

    let mut fs = open_fs(&root);
    let rec = fs
        .create_file("/self.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");
    fs.write_file("/self.txt", 0, b"self").expect("write_file");

    // Rename to self must succeed (no-op).
    fs.rename("/self.txt", "/self.txt", false)
        .expect("rename to self");

    // Entry must still exist.
    let names = dir_entry_names(&fs, "/");
    assert!(
        names.contains(&"self.txt".to_string()),
        "entry must still exist after self-rename"
    );

    // Content must be unchanged.
    let content = fs.read_file("/self.txt").expect("read_file");
    assert_eq!(
        content, b"self",
        "content must be unchanged after self-rename"
    );

    // Inode id must be unchanged.
    let inode_after = fs.lookup("/self.txt").expect("lookup");
    assert_eq!(
        inode_after, rec.inode_id,
        "inode id must be unchanged after self-rename"
    );

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// Category 4: Rename across directories
// ═══════════════════════════════════════════════════════════════════════════

/// Rename a file from one parent directory to another.
/// The entry must move: old name gone, new name present in target directory,
/// inode identity and content preserved.
#[test]
fn local_fs_dir_rename_across_dirs_file() {
    let root = temp_root("rename-across");
    cleanup(&root);

    let mut fs = open_fs(&root);
    fs.create_dir("/src", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /src");
    fs.create_dir("/dst", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /dst");

    let rec = fs
        .create_file("/src/x.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");
    let old_inode = rec.inode_id;
    fs.write_file("/src/x.txt", 0, b"across-dirs")
        .expect("write_file");

    fs.rename("/src/x.txt", "/dst/y.txt", false)
        .expect("rename");

    // Source directory must lose the entry.
    let src_names = dir_entry_names(&fs, "/src");
    assert!(
        !src_names.contains(&"x.txt".to_string()),
        "/src must not contain 'x.txt' after rename, got: {src_names:?}"
    );

    // Target directory must gain the entry.
    let dst_names = dir_entry_names(&fs, "/dst");
    assert!(
        dst_names.contains(&"y.txt".to_string()),
        "/dst must contain 'y.txt' after rename, got: {dst_names:?}"
    );

    // Inode identity must be preserved.
    let new_inode = fs.lookup("/dst/y.txt").expect("lookup new");
    assert_eq!(
        new_inode, old_inode,
        "inode identity must survive cross-directory rename"
    );

    // Content must survive.
    let content = fs.read_file("/dst/y.txt").expect("read_file");
    assert_eq!(
        content, b"across-dirs",
        "file content must survive cross-directory rename"
    );

    // Old path must not be reachable.
    let old_err = fs.lookup("/src/x.txt").unwrap_err();
    assert!(
        old_err.to_string().contains("x.txt"),
        "old path must not be reachable after rename: {old_err}"
    );

    cleanup(&root);
}

/// Rename a subdirectory from one parent to another.
/// The directory entry moves, source parent loses it, target parent gains it.
#[test]
fn local_fs_dir_rename_across_dirs_subdir() {
    let root = temp_root("rename-dir-across");
    cleanup(&root);

    let mut fs = open_fs(&root);
    fs.create_dir("/a", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /a");
    fs.create_dir("/b", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /b");
    fs.create_dir("/a/sub", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /a/sub");
    // Place a file inside so we can verify the subtree moves intact.
    fs.create_file("/a/sub/child.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");
    fs.write_file("/a/sub/child.txt", 0, b"subtree")
        .expect("write_file");

    let sub_rec = fs.stat("/a/sub").expect("stat /a/sub");
    let sub_inode = sub_rec.inode_id;

    fs.rename("/a/sub", "/b/moved", false)
        .expect("rename dir across");

    // Source parent must lose the entry.
    let a_names = dir_entry_names(&fs, "/a");
    assert!(
        !a_names.contains(&"sub".to_string()),
        "/a must not contain 'sub' after rename, got: {a_names:?}"
    );

    // Target parent must gain the entry.
    assert_dir_has_entry(&fs, "/b", "moved");

    // Inode identity preserved.
    let moved_inode = fs.lookup("/b/moved").expect("lookup moved");
    assert_eq!(
        moved_inode, sub_inode,
        "subdir inode identity must survive cross-directory rename"
    );

    // Subtree content must survive.
    let child_content = fs.read_file("/b/moved/child.txt").expect("read child");
    assert_eq!(
        child_content, b"subtree",
        "subtree file content must survive rename"
    );

    // Old path must not be reachable.
    let old_err = fs.lookup("/a/sub").unwrap_err();
    assert!(
        old_err.to_string().contains("/a/sub"),
        "old subdir path must not be reachable: {old_err}"
    );

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// Category 5: Rename overwrite
// ═══════════════════════════════════════════════════════════════════════════

/// Rename a file over an existing file target: target is replaced,
/// source name disappears, new name has source content.
#[test]
fn local_fs_dir_rename_overwrite_file() {
    let root = temp_root("rename-overwrite-file");
    cleanup(&root);

    let mut fs = open_fs(&root);
    let src_rec = fs
        .create_file("/src.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file src");
    fs.write_file("/src.txt", 0, b"source-content")
        .expect("write src");

    let _tgt_rec = fs
        .create_file("/tgt.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file tgt");
    fs.write_file("/tgt.txt", 0, b"target-content")
        .expect("write tgt");

    fs.rename("/src.txt", "/tgt.txt", false)
        .expect("rename overwrite");

    // Old source name must be gone.
    let names = dir_entry_names(&fs, "/");
    assert!(
        !names.contains(&"src.txt".to_string()),
        "'src.txt' must not exist after overwriting rename"
    );

    // Target name must have source content and inode.
    let content = fs.read_file("/tgt.txt").expect("read tgt");
    assert_eq!(
        content, b"source-content",
        "target must contain source content after overwrite rename"
    );

    let tgt_inode = fs.lookup("/tgt.txt").expect("lookup tgt");
    assert_eq!(
        tgt_inode, src_rec.inode_id,
        "target inode must be the source inode after overwrite"
    );

    // Source path must no longer exist.
    let src_err = fs.lookup("/src.txt").unwrap_err();
    assert!(
        src_err.to_string().contains("src.txt"),
        "src path must not exist after rename: {src_err}"
    );

    cleanup(&root);
}

/// Rename a file over an existing non-empty directory target must fail.
#[test]
fn local_fs_dir_rename_file_over_nonempty_dir_fails() {
    let root = temp_root("rename-file-over-dir");
    cleanup(&root);

    let mut fs = open_fs(&root);
    fs.create_file("/a.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");
    fs.create_dir("/d", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir /d");
    fs.create_file("/d/child.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file inside dir");

    let err = fs.rename("/a.txt", "/d", false).unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("directory") || err_msg.contains("IsDirectory"),
        "rename file over non-empty dir must fail with IsDirectory: {err_msg}"
    );

    // Source file must still exist.
    let names = dir_entry_names(&fs, "/");
    assert!(
        names.contains(&"a.txt".to_string()),
        "source file must still exist after failed rename"
    );

    // Target directory and its child must still exist.
    assert_dir_has_entry(&fs, "/", "d");
    assert_entry_exists(&fs, "/d", "child.txt");

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// Category 6: Directory durability
// ═══════════════════════════════════════════════════════════════════════════

/// Create a directory tree, fsync each level, reopen, verify all entries
/// survive the remount cycle byte-for-byte.
#[test]
fn local_fs_dir_durability_tree_survives_reopen() {
    let root = temp_root("dur-tree");
    cleanup(&root);

    {
        let mut fs = open_fs(&root);
        fs.create_dir("/a", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create_dir /a");
        fs.create_dir("/a/b", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create_dir /a/b");
        fs.create_file("/a/b/f1.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");
        fs.write_file("/a/b/f1.txt", 0, b"leaf-content")
            .expect("write_file");
        fs.create_file("/a/f2.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");
        fs.write_file("/a/f2.txt", 0, b"mid-content")
            .expect("write_file");

        // fsync the directories bottom-up.
        fs.fsync_directory("/a/b").expect("fsync /a/b");
        fs.fsync_directory("/a").expect("fsync /a");
        fs.fsync_file("/a/b/f1.txt").expect("fsync /a/b/f1.txt");
        fs.fsync_file("/a/f2.txt").expect("fsync /a/f2.txt");
    }

    {
        let fs = open_fs(&root);

        // Verify directory tree structure survived.
        assert_dir_has_entry(&fs, "/", "a");
        assert_dir_has_entry(&fs, "/a", "b");
        let a_entries = dir_entry_names(&fs, "/a");
        assert!(
            a_entries.contains(&"b".to_string()),
            "/a must contain 'b' after reopen"
        );
        assert!(
            a_entries.contains(&"f2.txt".to_string()),
            "/a must contain 'f2.txt' after reopen"
        );

        let b_entries = dir_entry_names(&fs, "/a/b");
        assert!(
            b_entries.contains(&"f1.txt".to_string()),
            "/a/b must contain 'f1.txt' after reopen"
        );

        // Verify file content survived.
        let f1 = fs.read_file("/a/b/f1.txt").expect("read f1");
        assert_eq!(f1, b"leaf-content", "leaf file content must survive reopen");

        let f2 = fs.read_file("/a/f2.txt").expect("read f2");
        assert_eq!(f2, b"mid-content", "mid file content must survive reopen");
    }

    cleanup(&root);
}

/// Remove a directory, fsync the parent, reopen, and confirm the directory
/// is truly gone.
#[test]
fn local_fs_dir_durability_rmdir_survives_reopen() {
    let root = temp_root("dur-rmdir");
    cleanup(&root);

    {
        let mut fs = open_fs(&root);
        fs.create_dir("/todel", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create_dir");
        fs.create_file("/todel/f.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file inside todel");
        fs.write_file("/todel/f.txt", 0, b"inside").expect("write");

        // Remove the file, then the directory.
        fs.unlink("/todel/f.txt").expect("unlink");
        fs.remove_dir("/todel").expect("remove_dir");
        // fsync the parent directory to persist the removal.
        fs.fsync_directory("/").expect("fsync root after rmdir");
    }

    {
        let fs = open_fs(&root);

        // Directory must not exist after remount.
        let names = dir_entry_names(&fs, "/");
        assert!(
            !names.contains(&"todel".to_string()),
            "'todel' must not exist after rmdir + reopen, got: {names:?}"
        );

        let err = fs.lookup("/todel").unwrap_err();
        assert!(
            err.to_string().contains("todel"),
            "lookup after rmdir+reopen must fail: {err}"
        );
    }

    cleanup(&root);
}

/// Mid-rename crash recovery: rename without fsync, reopen, verify state
/// is either pre-rename or post-rename — never partial.
#[test]
fn local_fs_dir_durability_rename_atomicity() {
    let root = temp_root("dur-rename-atomic");
    cleanup(&root);

    // Phase 1: set up two files, fsync both, then rename without fsync.
    {
        let mut fs = open_fs(&root);
        fs.create_file("/alpha.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file alpha");
        fs.write_file("/alpha.txt", 0, b"alpha-data")
            .expect("write alpha");
        fs.fsync_file("/alpha.txt").expect("fsync alpha");

        fs.create_file("/beta.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file beta");
        fs.write_file("/beta.txt", 0, b"beta-data")
            .expect("write beta");
        fs.fsync_file("/beta.txt").expect("fsync beta");

        // Rename alpha over beta without fsyncing.
        fs.rename("/alpha.txt", "/beta.txt", false).expect("rename");
        // Do NOT fsync — drop the filesystem here to simulate a crash.
    }

    // Phase 2: reopen and verify state is consistent.
    {
        let fs = open_fs(&root);
        let names = dir_entry_names(&fs, "/");
        let has_alpha = names.contains(&"alpha.txt".to_string());
        let has_beta = names.contains(&"beta.txt".to_string());

        // The state must be one of:
        // - Pre-rename: both alpha and beta exist, beta has "beta-data"
        // - Post-rename: only beta exists, has "alpha-data"
        // Partial/inconsistent state (both gone, or alpha present with beta gone and wrong content) is a bug.

        if has_alpha && has_beta {
            // Pre-rename state: beta should have original beta-data.
            let beta_content = fs.read_file("/beta.txt").expect("read beta pre-rename");
            assert_eq!(
                beta_content, b"beta-data",
                "pre-rename state: beta must have beta-data"
            );
        } else if has_beta && !has_alpha {
            // Post-rename state: beta should have alpha-data.
            let beta_content = fs.read_file("/beta.txt").expect("read beta post-rename");
            assert_eq!(
                beta_content, b"alpha-data",
                "post-rename state: beta must have alpha-data"
            );
        } else {
            panic!(
                "inconsistent rename recovery: alpha={has_alpha}, beta={has_beta}, names={names:?}"
            );
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// Category 7: Edge cases
// ═══════════════════════════════════════════════════════════════════════════

/// mkdir must fail with AlreadyExists when a file already exists at the path.
#[test]
fn local_fs_dir_edge_mkdir_existing_file() {
    let root = temp_root("edge-mkdir-file");
    cleanup(&root);

    let mut fs = open_fs(&root);
    fs.create_file("/collision", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");

    let err = fs
        .create_dir("/collision", DEFAULT_DIRECTORY_PERMISSIONS)
        .unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("collision") && (err_msg.contains("exist") || err_msg.contains("Already")),
        "mkdir on existing file must fail with AlreadyExists: {err_msg}"
    );

    // Existing file must remain intact.
    let rec = fs.stat("/collision").expect("stat collision");
    assert!(
        (rec.mode & S_IFMT) != S_IFDIR,
        "/collision must still be a file after rejected mkdir"
    );

    cleanup(&root);
}

/// mkdir must fail with AlreadyExists when a directory already exists at the path.
#[test]
fn local_fs_dir_edge_mkdir_existing_dir() {
    let root = temp_root("edge-mkdir-dir");
    cleanup(&root);

    let mut fs = open_fs(&root);
    let first = fs
        .create_dir("/dup", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("create_dir first");

    let err = fs
        .create_dir("/dup", DEFAULT_DIRECTORY_PERMISSIONS)
        .unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("dup") && (err_msg.contains("exist") || err_msg.contains("Already")),
        "mkdir on existing directory must fail with AlreadyExists: {err_msg}"
    );

    // Original directory must remain intact.
    let rec = fs.stat("/dup").expect("stat dup");
    assert_eq!(
        rec.inode_id, first.inode_id,
        "original directory inode must be preserved"
    );

    cleanup(&root);
}

/// rmdir on a non-existent path must fail with NotFound.
#[test]
fn local_fs_dir_edge_rmdir_nonexistent() {
    let root = temp_root("edge-rmdir-nonexistent");
    cleanup(&root);

    let mut fs = open_fs(&root);
    let err = fs.remove_dir("/no/such/dir").unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("no/such/dir") || err_msg.contains("no/such"),
        "rmdir on non-existent path must fail with NotFound: {err_msg}"
    );

    cleanup(&root);
}

/// rmdir on a file (not a directory) must fail with NotDirectory.
#[test]
fn local_fs_dir_edge_rmdir_on_file() {
    let root = temp_root("edge-rmdir-file");
    cleanup(&root);

    let mut fs = open_fs(&root);
    fs.create_file("/notadir", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");

    let err = fs.remove_dir("/notadir").unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("notadir")
            && (err_msg.contains("directory") || err_msg.contains("NotDirectory")),
        "rmdir on file must fail with NotDirectory: {err_msg}"
    );

    // File must still exist.
    let names = dir_entry_names(&fs, "/");
    assert!(
        names.contains(&"notadir".to_string()),
        "file must still exist after failed rmdir"
    );

    cleanup(&root);
}
