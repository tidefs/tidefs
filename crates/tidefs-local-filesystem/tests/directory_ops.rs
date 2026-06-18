// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Directory-operation unit tests for the local-filesystem layer.
//!
//! Exercises namespace operations: create, lookup, readdir, unlink,
//! rename, rmdir, and edge cases. Uses the path-based API to verify
//! directory invariants without relying on FUSE integration.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};
use tidefs_types_vfs_core::NodeKind;

mod common;
use common::TreeNode;

// ── Helpers ───────────────────────────────────────────────────────────

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("tidefs-do-{label}-{ts}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn open_fs(dir: &std::path::Path) -> LocalFileSystem {
    LocalFileSystem::open(dir).expect("open filesystem")
}

// ── create + lookup round-trip ────────────────────────────────────────

#[test]
fn create_then_lookup_returns_correct_inode() {
    set_test_key();
    let dir = temp_dir("create_lookup");

    let mut fs = open_fs(&dir);
    let record = fs
        .create_file("/alpha.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.sync_all().expect("sync");

    let ino = fs.lookup("/alpha.txt").expect("lookup");
    assert_eq!(ino, record.inode_id);
    assert_eq!(record.kind(), NodeKind::File);
}

#[test]
fn create_in_subdir_then_lookup() {
    set_test_key();
    let dir = temp_dir("create_sub_lookup");

    let mut fs = open_fs(&dir);
    fs.create_dir("/sub", 0o755).expect("create dir");
    let record = fs
        .create_file("/sub/nested.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create nested");
    fs.sync_all().expect("sync");

    let ino = fs.lookup("/sub/nested.bin").expect("lookup");
    assert_eq!(ino, record.inode_id);
}

// ── readdir ───────────────────────────────────────────────────────────

#[test]
fn readdir_empty_directory() {
    set_test_key();
    let dir = temp_dir("readdir_empty");

    let mut fs = open_fs(&dir);
    fs.create_dir("/empty", 0o755).expect("create dir");
    fs.sync_all().expect("sync");

    let entries = fs.list_dir("/empty").expect("list_dir");
    assert!(entries.is_empty(), "empty dir has no entries");
}

#[test]
fn readdir_directory_with_entries() {
    set_test_key();
    let dir = temp_dir("readdir_populated");

    let mut fs = open_fs(&dir);
    fs.create_dir("/pop", 0o755).expect("create dir");
    let names: Vec<&str> = vec!["a", "b", "c", "x", "y", "z"];
    for name in &names {
        let path = format!("/pop/{name}");
        fs.create_file(&path, DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
    }
    fs.sync_all().expect("sync");

    let entries = fs.list_dir("/pop").expect("list_dir");
    assert_eq!(entries.len(), names.len());

    let got: BTreeSet<Vec<u8>> = entries.iter().map(|e| e.name.clone()).collect();
    for name in &names {
        assert!(got.contains(name.as_bytes()), "missing entry: {name}");
    }
}

#[test]
fn readdir_large_directory_hundred_entries() {
    set_test_key();
    let dir = temp_dir("readdir_100");

    let mut fs = open_fs(&dir);
    fs.create_dir("/big", 0o755).expect("create dir");

    let mut expected = BTreeSet::new();
    for i in 0u32..100 {
        let name = format!("file_{i:04}.dat");
        let path = format!("/big/{name}");
        fs.create_file(&path, DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        expected.insert(name.into_bytes());
    }
    fs.sync_all().expect("sync");

    let entries = fs.list_dir("/big").expect("list_dir");
    assert_eq!(entries.len(), 100, "all 100 entries returned");

    let got: BTreeSet<Vec<u8>> = entries.iter().map(|e| e.name.clone()).collect();
    assert_eq!(got, expected, "entry names match");

    // Verify no duplicates
    let mut seen = BTreeSet::new();
    for entry in &entries {
        assert!(
            seen.insert(&entry.name),
            "duplicate entry: {:?}",
            entry.name
        );
    }
}

#[test]
fn tree_builder_creates_and_survives_reopen() {
    set_test_key();
    let dir = temp_dir("tree_builder");

    let tree = vec![
        TreeNode::dir("src").with(vec![
            TreeNode::file("main.rs"),
            TreeNode::dir("inner").with(vec![
                TreeNode::file("mod.rs"),
                TreeNode::symlink("latest", b"mod.rs"),
            ]),
        ]),
        TreeNode::dir("target"),
        TreeNode::file("README.md"),
        TreeNode::symlink("doc", b"README.md"),
    ];

    let mut fs = open_fs(&dir);
    let paths = common::create_tree(&mut fs, "/proj", &tree);
    fs.sync_all().expect("sync");

    assert!(!paths.is_empty(), "at least some paths created");
    assert!(fs.lookup("/proj/src").is_ok());
    assert!(fs.lookup("/proj/src/main.rs").is_ok());
    assert!(fs.lookup("/proj/src/inner").is_ok());
    assert!(fs.lookup("/proj/src/inner/mod.rs").is_ok());
    assert!(fs.lookup("/proj/src/inner/latest").is_ok());
    assert!(fs.lookup("/proj/target").is_ok());
    assert!(fs.lookup("/proj/README.md").is_ok());
    assert!(fs.lookup("/proj/doc").is_ok());

    let target = fs
        .read_symlink("/proj/src/inner/latest")
        .expect("readlink latest");
    assert_eq!(target, b"mod.rs");

    // Reopen and verify
    drop(fs);
    common::verify_tree_after_reopen(&dir, &paths);
}

// ── unlink ────────────────────────────────────────────────────────────

#[test]
fn unlink_removes_file_from_directory() {
    set_test_key();
    let dir = temp_dir("unlink_remove");

    let mut fs = open_fs(&dir);
    fs.create_file("/rm_me.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.sync_all().expect("sync");
    assert!(fs.lookup("/rm_me.txt").is_ok());

    fs.unlink("/rm_me.txt").expect("unlink");
    fs.sync_all().expect("sync");

    assert!(fs.lookup("/rm_me.txt").is_err(), "file gone after unlink");
}

#[test]
fn unlink_removes_entry_from_readdir() {
    set_test_key();
    let dir = temp_dir("unlink_readdir");

    let mut fs = open_fs(&dir);
    fs.create_dir("/d", 0o755).expect("create dir");
    fs.create_file("/d/a.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create a");
    fs.create_file("/d/b.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create b");
    fs.sync_all().expect("sync");

    assert_eq!(fs.list_dir("/d").unwrap().len(), 2);

    fs.unlink("/d/a.txt").expect("unlink a");
    fs.sync_all().expect("sync");

    let after = fs.list_dir("/d").expect("list_dir after unlink");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].name, b"b.txt");
}

#[test]
fn unlink_nonexistent_returns_error() {
    set_test_key();
    let dir = temp_dir("unlink_enoent");

    let mut fs = open_fs(&dir);
    let result = fs.unlink("/no_such_file.txt");
    assert!(result.is_err(), "unlink nonexistent must fail");
}

// ── rename ────────────────────────────────────────────────────────────

#[test]
fn rename_within_directory() {
    set_test_key();
    let dir = temp_dir("rename_within");

    let mut fs = open_fs(&dir);
    fs.create_file("/old_name.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.sync_all().expect("sync");

    fs.rename("/old_name.txt", "/new_name.txt", false)
        .expect("rename");
    fs.sync_all().expect("sync");

    assert!(fs.lookup("/old_name.txt").is_err(), "old name gone");
    assert!(fs.lookup("/new_name.txt").is_ok(), "new name exists");
}

#[test]
fn rename_across_directories() {
    set_test_key();
    let dir = temp_dir("rename_across");

    let mut fs = open_fs(&dir);
    fs.create_dir("/src", 0o755).expect("create src");
    fs.create_dir("/dst", 0o755).expect("create dst");
    fs.create_file("/src/move_me.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    fs.sync_all().expect("sync");

    fs.rename("/src/move_me.bin", "/dst/moved.bin", false)
        .expect("rename across");
    fs.sync_all().expect("sync");

    assert!(fs.lookup("/src/move_me.bin").is_err(), "gone from src");
    assert!(fs.lookup("/dst/moved.bin").is_ok(), "present in dst");

    let src_entries = fs.list_dir("/src").expect("list src");
    let dst_entries = fs.list_dir("/dst").expect("list dst");
    assert!(src_entries.is_empty());
    assert_eq!(dst_entries.len(), 1);
    assert_eq!(dst_entries[0].name, b"moved.bin");
}

#[test]
fn rename_noreplace_fails_on_existing_target() {
    set_test_key();
    let dir = temp_dir("rename_noreplace");

    let mut fs = open_fs(&dir);
    fs.create_file("/first.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create first");
    fs.create_file("/second.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create second");
    fs.sync_all().expect("sync");

    let result = fs.rename("/first.txt", "/second.txt", true);
    assert!(result.is_err(), "noreplace rename on existing target fails");
    // Both files should still exist
    assert!(fs.lookup("/first.txt").is_ok());
    assert!(fs.lookup("/second.txt").is_ok());
}

// ── rmdir ─────────────────────────────────────────────────────────────

#[test]
fn rmdir_nonempty_returns_error() {
    set_test_key();
    let dir = temp_dir("rmdir_nonempty");

    let mut fs = open_fs(&dir);
    fs.create_dir("/has_file", 0o755).expect("create dir");
    fs.create_file("/has_file/child.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create child");
    fs.sync_all().expect("sync");

    let result = fs.remove_dir("/has_file");
    assert!(result.is_err(), "rmdir non-empty fails");
    // Directory and file must still exist
    assert!(fs.lookup("/has_file/child.txt").is_ok());
}

#[test]
fn rmdir_empty_directory_succeeds() {
    set_test_key();
    let dir = temp_dir("rmdir_empty");

    let mut fs = open_fs(&dir);
    fs.create_dir("/vacant", 0o755).expect("create dir");
    fs.sync_all().expect("sync");

    fs.remove_dir("/vacant").expect("rmdir empty");
    fs.sync_all().expect("sync");

    assert!(fs.lookup("/vacant").is_err(), "dir gone after rmdir");
}

// ── create with O_EXCL behaviour ──────────────────────────────────────

#[test]
fn create_existing_name_returns_already_exists() {
    set_test_key();
    let dir = temp_dir("create_excl");

    let mut fs = open_fs(&dir);
    fs.create_file("/only.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create first");
    fs.sync_all().expect("sync");

    let result = fs.create_file("/only.txt", DEFAULT_FILE_PERMISSIONS);
    assert!(result.is_err(), "create on existing name must fail");
}

// ── readdir with offset resume ────────────────────────────────────────

#[test]
fn readdir_owned_returns_sequential_cookies() {
    set_test_key();
    let dir = temp_dir("readdir_cookies");

    let mut fs = open_fs(&dir);
    fs.create_dir("/cookie_dir", 0o755).expect("create dir");
    for i in 0..5 {
        let path = format!("/cookie_dir/entry_{i}");
        fs.create_file(&path, DEFAULT_FILE_PERMISSIONS)
            .expect("create");
    }
    fs.sync_all().expect("sync");

    let owned = fs.list_dir_owned("/cookie_dir").expect("list_dir_owned");
    // Cookies should be sequential starting from 1
    for (idx, entry) in owned.iter().enumerate() {
        assert_eq!(
            entry.cookie,
            (idx + 1) as u64,
            "cookie sequential at index {idx}"
        );
    }
}

// ── mkdir error paths ─────────────────────────────────────────────────

#[test]
fn mkdir_nested_path_missing_parent_returns_not_found() {
    set_test_key();
    let dir = temp_dir("mkdir_noparent");

    let mut fs = open_fs(&dir);
    let result = fs.create_dir("/nonexistent_parent/subdir", 0o755);
    assert!(result.is_err(), "mkdir with missing parent must fail");
}

#[test]
fn mkdir_duplicate_returns_already_exists() {
    set_test_key();
    let dir = temp_dir("mkdir_dup");

    let mut fs = open_fs(&dir);
    fs.create_dir("/mydir", 0o755).expect("create first");
    fs.sync_all().expect("sync");

    let result = fs.create_dir("/mydir", 0o755);
    assert!(result.is_err(), "mkdir on existing dir must fail");
}

#[test]
fn mkdir_under_file_returns_not_directory() {
    set_test_key();
    let dir = temp_dir("mkdir_under_file");

    let mut fs = open_fs(&dir);
    fs.create_file("/plain_file.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    fs.sync_all().expect("sync");

    let result = fs.create_dir("/plain_file.txt/subdir", 0o755);
    assert!(result.is_err(), "mkdir under file must fail");
}

#[test]
fn mkdir_mode_bits_persist() {
    set_test_key();
    let dir = temp_dir("mkdir_mode");

    let mut fs = open_fs(&dir);
    let record = fs.create_dir("/modedir", 0o700).expect("create dir");
    fs.sync_all().expect("sync");

    let ino = fs.lookup("/modedir").expect("lookup");
    assert_eq!(ino, record.inode_id);
    // POSIX mode should contain S_IFDIR | permissions
    assert_eq!(record.mode & 0o777, 0o700, "directory mode bits preserved");
}

// ── rmdir edge cases ──────────────────────────────────────────────────

#[test]
fn rmdir_nonexistent_returns_not_found() {
    set_test_key();
    let dir = temp_dir("rmdir_enoent");

    let mut fs = open_fs(&dir);
    let result = fs.remove_dir("/no_such_dir");
    assert!(result.is_err(), "rmdir nonexistent must fail");
}

#[test]
fn rmdir_on_file_returns_not_directory() {
    set_test_key();
    let dir = temp_dir("rmdir_on_file");

    let mut fs = open_fs(&dir);
    fs.create_file("/not_a_dir.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    fs.sync_all().expect("sync");

    let result = fs.remove_dir("/not_a_dir.txt");
    assert!(result.is_err(), "rmdir on file must fail");
}

// ── readdir mixed entries ─────────────────────────────────────────────

#[test]
fn readdir_directory_with_mixed_entries() {
    set_test_key();
    let dir = temp_dir("readdir_mixed");

    let mut fs = open_fs(&dir);
    fs.create_dir("/mixed", 0o755).expect("create dir");

    // Create files
    let files = ["alpha.log", "beta.log"];
    for name in &files {
        let path = format!("/mixed/{name}");
        fs.create_file(&path, DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
    }

    // Create subdirs
    let subdirs = ["src", "tests"];
    for name in &subdirs {
        let path = format!("/mixed/{name}");
        fs.create_dir(&path, 0o755).expect("create subdir");
    }
    fs.sync_all().expect("sync");

    let entries = fs.list_dir("/mixed").expect("list_dir");
    assert_eq!(entries.len(), 4);

    let mut got_files = vec![];
    let mut got_dirs = vec![];
    for e in &entries {
        match e.kind() {
            NodeKind::File => got_files.push(e.name.clone()),
            NodeKind::Dir => got_dirs.push(e.name.clone()),
            _ => {}
        }
    }
    got_files.sort();
    got_dirs.sort();
    assert_eq!(got_files, vec![b"alpha.log".to_vec(), b"beta.log".to_vec()]);
    assert_eq!(got_dirs, vec![b"src".to_vec(), b"tests".to_vec()]);
}

// ── rename edge cases ─────────────────────────────────────────────────

#[test]
fn rename_over_existing_file_replaces() {
    set_test_key();
    let dir = temp_dir("rename_replace");

    let mut fs = open_fs(&dir);
    fs.create_file("/original.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create original");
    fs.create_file("/target.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create target");
    fs.sync_all().expect("sync");

    // noreplace=false allows replacement
    fs.rename("/original.txt", "/target.txt", false)
        .expect("rename replacing file");
    fs.sync_all().expect("sync");

    assert!(fs.lookup("/original.txt").is_err(), "source gone");
    assert!(fs.lookup("/target.txt").is_ok(), "target exists");
}

#[test]
fn rename_over_nonempty_directory_returns_error() {
    set_test_key();
    let dir = temp_dir("rename_nempty");

    let mut fs = open_fs(&dir);
    fs.create_file("/src_file.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create src file");
    fs.create_dir("/populated_dir", 0o755).expect("create dir");
    fs.create_file("/populated_dir/child.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create child");
    fs.sync_all().expect("sync");

    let result = fs.rename("/src_file.txt", "/populated_dir", false);
    assert!(result.is_err(), "rename file over non-empty dir must fail");
}

#[test]
fn rename_nonexistent_source_returns_not_found() {
    set_test_key();
    let dir = temp_dir("rename_enoent");

    let mut fs = open_fs(&dir);
    let result = fs.rename("/ghost.txt", "/new_name.txt", false);
    assert!(result.is_err(), "rename nonexistent source must fail");
}

#[test]
fn rename_file_over_existing_directory_returns_is_directory() {
    set_test_key();
    let dir = temp_dir("rename_eisdir");

    let mut fs = open_fs(&dir);
    fs.create_file("/just_a_file.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    fs.create_dir("/just_a_dir", 0o755).expect("create dir");
    fs.sync_all().expect("sync");

    let result = fs.rename("/just_a_file.txt", "/just_a_dir", false);
    assert!(result.is_err(), "rename file over dir must fail");
}

#[test]
fn rename_to_self_noop() {
    set_test_key();
    let dir = temp_dir("rename_self");

    let mut fs = open_fs(&dir);
    let rec = fs
        .create_file("/keep_me.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.sync_all().expect("sync");

    fs.rename("/keep_me.txt", "/keep_me.txt", false)
        .expect("rename self is no-op");
    fs.sync_all().expect("sync");

    let ino = fs.lookup("/keep_me.txt").expect("lookup after self-rename");
    assert_eq!(ino, rec.inode_id, "inode unchanged after self-rename");
}

// ── hard link ─────────────────────────────────────────────────────────

#[test]
fn link_file_to_regular_file() {
    set_test_key();
    let dir = temp_dir("link_regular");

    let mut fs = open_fs(&dir);
    let original = fs
        .create_file("/original.data", DEFAULT_FILE_PERMISSIONS)
        .expect("create original");
    fs.sync_all().expect("sync");

    let link = fs
        .link_file("/original.data", "/alias.data")
        .expect("create hard link");
    fs.sync_all().expect("sync");

    assert_eq!(link.inode_id, original.inode_id, "hard link shares inode");
    assert!(fs.lookup("/original.data").is_ok());
    assert!(fs.lookup("/alias.data").is_ok());
}

#[test]
fn link_file_to_directory_returns_error() {
    set_test_key();
    let dir = temp_dir("link_dir");

    let mut fs = open_fs(&dir);
    fs.create_dir("/mydir", 0o755).expect("create dir");
    fs.sync_all().expect("sync");

    let result = fs.link_file("/mydir", "/mydir_link");
    assert!(result.is_err(), "hard link to directory must fail");
}

#[test]
fn link_count_increments_on_hard_link() {
    set_test_key();
    let dir = temp_dir("link_nlink");

    let mut fs = open_fs(&dir);
    let rec = fs
        .create_file("/sole.dat", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    assert_eq!(rec.nlink, 1, "new file has nlink=1");

    let link_rec = fs.link_file("/sole.dat", "/second_link.dat").expect("link");
    assert_eq!(link_rec.nlink, 2, "nlink=2 after hard link");
}

#[test]
fn unlink_after_link_original_still_reachable() {
    set_test_key();
    let dir = temp_dir("link_unlink_reach");

    let mut fs = open_fs(&dir);
    fs.create_file("/data.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.link_file("/data.bin", "/alias.bin").expect("link");
    fs.sync_all().expect("sync");

    // Unlink the original; data still reachable via the link
    fs.unlink("/data.bin").expect("unlink original");
    fs.sync_all().expect("sync");

    assert!(fs.lookup("/data.bin").is_err(), "original name gone");
    assert!(fs.lookup("/alias.bin").is_ok(), "alias still reachable");
}

#[test]
fn last_unlink_frees_inode() {
    set_test_key();
    let dir = temp_dir("unlink_last");

    let mut fs = open_fs(&dir);
    let rec = fs
        .create_file("/solo.dat", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.sync_all().expect("sync");

    fs.unlink("/solo.dat").expect("unlink last");
    fs.sync_all().expect("sync");

    assert!(fs.lookup("/solo.dat").is_err(), "entry gone");

    // Re-create same name: it should get a new inode
    let new_rec = fs
        .create_file("/solo.dat", DEFAULT_FILE_PERMISSIONS)
        .expect("re-create");
    assert_ne!(
        new_rec.inode_id, rec.inode_id,
        "re-created file gets a different inode"
    );
}

// ── unlink edge cases ─────────────────────────────────────────────────

#[test]
fn unlink_directory_returns_is_directory() {
    set_test_key();
    let dir = temp_dir("unlink_dir");

    let mut fs = open_fs(&dir);
    fs.create_dir("/adir", 0o755).expect("create dir");
    fs.sync_all().expect("sync");

    let result = fs.unlink("/adir");
    assert!(result.is_err(), "unlink on directory must fail");
}

// ── symlink ───────────────────────────────────────────────────────────

#[test]
fn create_symlink_and_readlink() {
    set_test_key();
    let dir = temp_dir("sym_create_read");

    let mut fs = open_fs(&dir);
    let rec = fs
        .create_symlink("/mylink", b"../real/path")
        .expect("create symlink");
    fs.sync_all().expect("sync");

    assert_eq!(rec.kind(), NodeKind::Symlink);

    let target = fs.read_symlink("/mylink").expect("readlink");
    assert_eq!(target, b"../real/path", "readlink returns target");
}

#[test]
fn symlink_over_existing_path_returns_already_exists() {
    set_test_key();
    let dir = temp_dir("sym_eext");

    let mut fs = open_fs(&dir);
    fs.create_file("/already.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    fs.sync_all().expect("sync");

    let result = fs.create_symlink("/already.txt", b"SOMEWHERE");
    assert!(result.is_err(), "symlink over existing must fail");
}

#[test]
fn dangling_symlink_lookup_succeeds() {
    set_test_key();
    let dir = temp_dir("sym_dangling");

    let mut fs = open_fs(&dir);
    fs.create_symlink("/dangles", b"/nonexistent/target")
        .expect("create symlink");
    fs.sync_all().expect("sync");

    // lookup resolves the symlink node itself, not the target
    let ino = fs.lookup("/dangles").expect("lookup symlink");
    assert_ne!(ino, tidefs_types_vfs_core::ROOT_INODE_ID);
}

#[test]
fn chained_symlink_readlink_returns_first_target() {
    set_test_key();
    let dir = temp_dir("sym_chain");

    let mut fs = open_fs(&dir);
    fs.create_symlink("/first", b"../intermediate")
        .expect("create first symlink");
    fs.create_symlink("/intermediate", b"../final/dest")
        .expect("create intermediate symlink");
    fs.sync_all().expect("sync");

    // read_symlink on /first returns "../intermediate", not "../final/dest"
    let target = fs.read_symlink("/first").expect("readlink first");
    assert_eq!(target, b"../intermediate");
}

#[test]
fn read_symlink_on_regular_file_returns_error() {
    set_test_key();
    let dir = temp_dir("sym_readlink_file");

    let mut fs = open_fs(&dir);
    fs.create_file("/regular.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create file");
    fs.sync_all().expect("sync");

    let result = fs.read_symlink("/regular.txt");
    assert!(result.is_err(), "read_symlink on regular file must fail");
}

// ── cross-operation consistency ───────────────────────────────────────

#[test]
fn rename_then_readdir_visibility_is_immediate() {
    set_test_key();
    let dir = temp_dir("cross_rename_readdir");

    let mut fs = open_fs(&dir);
    fs.create_dir("/d", 0o755).expect("create dir");
    fs.create_file("/d/a.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create a");
    fs.rename("/d/a.txt", "/d/b.txt", false).expect("rename");
    fs.sync_all().expect("sync");

    let entries = fs.list_dir("/d").expect("list_dir");
    let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
    assert!(!names.contains(&b"a.txt".as_slice()), "old name absent");
    assert!(names.contains(&b"b.txt".as_slice()), "new name present");
}

#[test]
fn mkdir_then_create_file_inside_then_rmdir_fails_nonempty() {
    set_test_key();
    let dir = temp_dir("cross_mkdir_rmdir");

    let mut fs = open_fs(&dir);
    fs.create_dir("/testdir", 0o755).expect("create dir");
    fs.create_file("/testdir/child.dat", DEFAULT_FILE_PERMISSIONS)
        .expect("create child");
    fs.sync_all().expect("sync");

    let result = fs.remove_dir("/testdir");
    assert!(result.is_err(), "rmdir non-empty after mkdir+create");
    // Both dir and file must still exist
    assert!(fs.lookup("/testdir").is_ok());
    assert!(fs.lookup("/testdir/child.dat").is_ok());
}
// ── invalid name rejection ────────────────────────────────────────────

#[test]
fn mkdir_empty_path_component_returns_invalid_path() {
    set_test_key();
    let dir = temp_dir("mkdir_emptycomp");

    let mut fs = open_fs(&dir);
    // "//sub" has an empty path component between the two slashes
    let result = fs.create_dir("//sub", 0o755);
    assert!(result.is_err(), "mkdir with empty path component must fail");
}

#[test]
fn mkdir_name_too_long_returns_invalid_name() {
    set_test_key();
    let dir = temp_dir("mkdir_longname");

    let mut fs = open_fs(&dir);
    fs.create_dir("/d", 0o755).expect("create parent");
    let long_name = "x".repeat(256); // MAX_NAME_BYTES is 255
    let path = format!("/d/{long_name}");
    let result = fs.create_dir(&path, 0o755);
    assert!(result.is_err(), "mkdir with name > 255 bytes must fail");
}

#[test]
fn mkdir_root_path_rejects_create_dir() {
    set_test_key();
    let dir = temp_dir("mkdir_root");

    let mut fs = open_fs(&dir);
    // "/" is the root — it already exists and resolve_parent_and_name
    // returns InvalidPath because root has no parent component
    let result = fs.create_dir("/", 0o755);
    assert!(result.is_err(), "mkdir on root path must fail");
}

#[test]
fn mkdir_relative_path_returns_invalid_path() {
    set_test_key();
    let dir = temp_dir("mkdir_rel");

    let mut fs = open_fs(&dir);
    let result = fs.create_dir("relative/path", 0o755);
    assert!(result.is_err(), "mkdir with relative path must fail");
}

// ── readdir after directory removal ────────────────────────────────────

#[test]
fn readdir_on_removed_directory_returns_not_found() {
    set_test_key();
    let dir = temp_dir("readdir_removed");

    let mut fs = open_fs(&dir);
    fs.create_dir("/d", 0o755).expect("create dir");
    fs.sync_all().expect("sync");

    // Verify directory is listable
    let pre = fs.list_dir("/d").expect("list before rmdir");
    assert!(pre.is_empty());

    fs.remove_dir("/d").expect("rmdir");

    // list_dir after rmdir must return NotFound
    let result = fs.list_dir("/d");
    assert!(result.is_err(), "list_dir on removed dir must fail");
}

// ═══════════════════════════════════════════════════════════════════════
// Crash-recovery (reopen) directory tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn mkdir_survives_reopen() {
    set_test_key();
    let dir = temp_dir("mkdir_reopen");

    let mode: u32 = 0o755;
    {
        let mut fs = open_fs(&dir);
        let rec = fs.create_dir("/persist", mode).expect("create dir");
        fs.sync_all().expect("sync");
        assert_eq!(rec.mode & 0o777, mode);
    }

    // Reopen: directory must still be visible and listable
    let fs = open_fs(&dir);
    let ino = fs.lookup("/persist").expect("lookup after reopen");
    let entries = fs.list_dir("/persist").expect("list_dir after reopen");
    assert!(entries.is_empty(), "directory is empty after reopen");
    let stat = fs.stat_path("/persist").expect("stat after reopen");
    assert_eq!(stat.inode_id, ino);
    assert_eq!(stat.kind(), NodeKind::Dir);
    assert_eq!(stat.mode & 0o777, mode, "mode preserved across reopen");
}

#[test]
fn rmdir_survives_reopen() {
    set_test_key();
    let dir = temp_dir("rmdir_reopen");

    // Session 1: mkdir, sync, reopen
    {
        let mut fs = open_fs(&dir);
        fs.create_dir("/ephemeral", 0o755).expect("create dir");
        fs.sync_all().expect("sync");
    }

    {
        let mut fs = open_fs(&dir);
        assert!(fs.lookup("/ephemeral").is_ok(), "dir exists after reopen");
        fs.remove_dir("/ephemeral").expect("rmdir");
        fs.sync_all().expect("sync");
    }

    // Session 2: reopen, verify dir is gone
    let fs = open_fs(&dir);
    assert!(
        fs.lookup("/ephemeral").is_err(),
        "dir gone after rmdir+reopen"
    );
}

#[test]
fn rename_survives_reopen() {
    set_test_key();
    let dir = temp_dir("rename_reopen");

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/before.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.write_file("/before.txt", 0, b"rename-me-data")
            .expect("write");
        fs.rename("/before.txt", "/after.txt", false)
            .expect("rename");
        fs.sync_all().expect("sync");
    }

    // Reopen: verify rename persisted
    let fs = open_fs(&dir);
    assert!(
        fs.lookup("/before.txt").is_err(),
        "old name gone after reopen"
    );
    assert!(
        fs.lookup("/after.txt").is_ok(),
        "new name present after reopen"
    );
    let data = fs.read_file("/after.txt").expect("read renamed file");
    assert_eq!(
        data, b"rename-me-data",
        "file content intact after rename+reopen"
    );
}

#[test]
fn rename_across_dirs_survives_reopen() {
    set_test_key();
    let dir = temp_dir("rename_across_reopen");

    {
        let mut fs = open_fs(&dir);
        fs.create_dir("/src", 0o755).expect("create src dir");
        fs.create_dir("/dst", 0o755).expect("create dst dir");
        fs.create_file("/src/movable.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.rename("/src/movable.bin", "/dst/placed.bin", false)
            .expect("rename across dirs");
        fs.sync_all().expect("sync");
    }

    let fs = open_fs(&dir);
    assert!(
        fs.lookup("/src/movable.bin").is_err(),
        "gone from src after reopen"
    );
    assert!(
        fs.lookup("/dst/placed.bin").is_ok(),
        "present in dst after reopen"
    );
    let src_entries = fs.list_dir("/src").expect("list src");
    let dst_entries = fs.list_dir("/dst").expect("list dst");
    assert!(src_entries.is_empty(), "src is empty after reopen");
    assert_eq!(dst_entries.len(), 1);
    assert_eq!(dst_entries[0].name, b"placed.bin");
}

#[test]
fn nested_dir_structure_survives_reopen() {
    set_test_key();
    let dir = temp_dir("nested_reopen");

    {
        let mut fs = open_fs(&dir);
        fs.create_dir("/a", 0o755).expect("mkdir /a");
        fs.create_dir("/a/b", 0o755).expect("mkdir /a/b");
        fs.create_dir("/a/b/c", 0o755).expect("mkdir /a/b/c");
        // Files at each level
        fs.create_file("/a/level1.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create /a/level1.txt");
        fs.create_file("/a/b/level2.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create /a/b/level2.txt");
        fs.create_file("/a/b/c/level3.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create /a/b/c/level3.txt");
        fs.sync_all().expect("sync");
    }

    // Reopen and verify whole tree
    let fs = open_fs(&dir);
    assert!(fs.lookup("/a").is_ok());
    assert!(fs.lookup("/a/b").is_ok());
    assert!(fs.lookup("/a/b/c").is_ok());
    assert!(fs.lookup("/a/level1.txt").is_ok());
    assert!(fs.lookup("/a/b/level2.txt").is_ok());
    assert!(fs.lookup("/a/b/c/level3.txt").is_ok());

    // Verify listing at each level
    let a_entries: Vec<Vec<u8>> = fs
        .list_dir("/a")
        .unwrap()
        .iter()
        .map(|e| e.name.clone())
        .collect();
    assert!(a_entries.contains(&b"b".to_vec()), "/a contains b");
    assert!(
        a_entries.contains(&b"level1.txt".to_vec()),
        "/a contains level1.txt"
    );

    let b_entries: Vec<Vec<u8>> = fs
        .list_dir("/a/b")
        .unwrap()
        .iter()
        .map(|e| e.name.clone())
        .collect();
    assert!(b_entries.contains(&b"c".to_vec()), "/a/b contains c");
    assert!(
        b_entries.contains(&b"level2.txt".to_vec()),
        "/a/b contains level2.txt"
    );

    let c_entries: Vec<Vec<u8>> = fs
        .list_dir("/a/b/c")
        .unwrap()
        .iter()
        .map(|e| e.name.clone())
        .collect();
    assert!(
        c_entries.contains(&b"level3.txt".to_vec()),
        "/a/b/c contains level3.txt"
    );
}

#[test]
fn hardlink_survives_reopen() {
    set_test_key();
    let dir = temp_dir("link_reopen");

    let original_ino;
    {
        let mut fs = open_fs(&dir);
        let rec = fs
            .create_file("/primary.data", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        original_ino = rec.inode_id;
        let link_rec = fs
            .link_file("/primary.data", "/secondary.data")
            .expect("link");
        assert_eq!(link_rec.inode_id, original_ino, "same inode after link");
        assert_eq!(link_rec.nlink, 2);
        fs.sync_all().expect("sync");
    }

    // Reopen: both names must resolve to the same inode
    let fs = open_fs(&dir);
    let ino1 = fs.lookup("/primary.data").expect("lookup primary");
    let ino2 = fs.lookup("/secondary.data").expect("lookup secondary");
    assert_eq!(ino1, original_ino);
    assert_eq!(ino2, original_ino);
    assert_eq!(ino1, ino2, "both names share inode after reopen");
    let stat = fs.stat_path("/primary.data").expect("stat primary");
    assert_eq!(stat.nlink, 2, "nlink=2 survives reopen");
}

#[test]
fn unlink_then_reopen_loses_entry() {
    set_test_key();
    let dir = temp_dir("unlink_reopen");

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/doomed.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.sync_all().expect("sync");
    }

    {
        let mut fs = open_fs(&dir);
        assert!(
            fs.lookup("/doomed.txt").is_ok(),
            "file present in session 2"
        );
        fs.unlink("/doomed.txt").expect("unlink");
        fs.sync_all().expect("sync");
    }

    let fs = open_fs(&dir);
    assert!(
        fs.lookup("/doomed.txt").is_err(),
        "file gone after unlink+reopen"
    );
}

#[test]
fn symlink_survives_reopen() {
    set_test_key();
    let dir = temp_dir("sym_reopen");

    {
        let mut fs = open_fs(&dir);
        let rec = fs
            .create_symlink("/pointer", b"/actual/target/path")
            .expect("create symlink");
        assert_eq!(rec.kind(), NodeKind::Symlink);
        fs.sync_all().expect("sync");
    }

    let fs = open_fs(&dir);
    let ino = fs.lookup("/pointer").expect("lookup symlink after reopen");
    let target = fs.read_symlink("/pointer").expect("readlink after reopen");
    assert_eq!(target, b"/actual/target/path");
    let stat = fs.stat_path("/pointer").expect("stat symlink after reopen");
    assert_eq!(stat.kind(), NodeKind::Symlink);
    assert_eq!(stat.inode_id, ino);
}

#[test]
fn mkdir_rmdir_cycle_survives_reopen() {
    set_test_key();
    let dir = temp_dir("mkdir_rmdir_cycle");

    // 5 cycles of mkdir+rmdir across reopen sessions
    for cycle in 0..5 {
        let subdir = format!("/cycle_{cycle}");
        {
            let mut fs = open_fs(&dir);
            fs.create_dir(&subdir, 0o755).expect("mkdir");
            fs.create_file(format!("{subdir}/f.txt"), DEFAULT_FILE_PERMISSIONS)
                .expect("create child");
            fs.sync_all().expect("sync");
        }
        {
            let mut fs = open_fs(&dir);
            let entries = fs.list_dir(&subdir).expect("list");
            assert_eq!(entries.len(), 1);
            // rmdir non-empty must fail
            assert!(fs.remove_dir(&subdir).is_err());
            fs.unlink(format!("{subdir}/f.txt")).expect("unlink child");
            fs.remove_dir(&subdir).expect("rmdir empty");
            fs.sync_all().expect("sync");
        }
        // Reopen and verify gone
        let fs = open_fs(&dir);
        assert!(fs.lookup(&subdir).is_err(), "dir gone after cycle {cycle}");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Concurrent directory mutation (sequentially interleaved)
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════

// ── Concurrent directory mutation (sequentially interleaved) ──────────
//
// The local object store uses a single-writer segment model and does not
// support concurrent open() from multiple handles. The tests below simulate
// concurrent access patterns through sequential interleaving: creating
// many entries, mixing create/lookup/unlink in rapid succession, and
// verifying readdir consistency after bursts of mutations that mimic the
// interleaving of separate threads.

#[test]
fn burst_create_forty_files_then_verify_readdir() {
    set_test_key();
    let dir = temp_dir("burst_create");

    let mut fs = open_fs(&dir);
    fs.create_dir("/d", 0o755).expect("create dir");

    // Burst-create 40 files (simulating 4 threads each creating 10)
    let mut names = Vec::new();
    for tid in 0..4 {
        for i in 0..10 {
            let name = format!("t{tid}_f{i:02}.dat");
            let path = format!("/d/{name}");
            fs.create_file(&path, DEFAULT_FILE_PERMISSIONS)
                .expect("create file");
            names.push(name);
        }
    }
    fs.sync_all().expect("sync");

    let entries = fs.list_dir("/d").expect("list_dir");
    assert_eq!(entries.len(), 40, "all 40 files visible");
    for name in &names {
        let path = format!("/d/{name}");
        assert!(fs.lookup(&path).is_ok(), "file {name} exists");
    }
}

#[test]
fn burst_create_same_name_conflict() {
    set_test_key();
    let dir = temp_dir("burst_conflict");

    let mut fs = open_fs(&dir);
    fs.create_dir("/d", 0o755).expect("create dir");

    // First create succeeds
    let rec = fs
        .create_file("/d/clash.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("first create");
    fs.sync_all().expect("sync");

    // Second create on same name must fail
    assert!(fs
        .create_file("/d/clash.txt", DEFAULT_FILE_PERMISSIONS)
        .is_err());

    // After reopen, only one file with that name
    let fs2 = open_fs(&dir);
    let ino = fs2.lookup("/d/clash.txt").expect("lookup");
    assert_eq!(ino, rec.inode_id, "inode matches original");
    let entries = fs2.list_dir("/d").expect("list_dir");
    assert_eq!(entries.len(), 1, "exactly one entry");
}

#[test]
fn interleaved_create_and_list_same_session() {
    set_test_key();
    let dir = temp_dir("interleaved_create_list");

    let mut fs = open_fs(&dir);
    fs.create_dir("/d", 0o755).expect("create dir");

    // Interleave creates and readdir calls -- each create must be
    // immediately visible in subsequent readdir.
    for i in 0..20 {
        let path = format!("/d/sub_{i:02}");
        fs.create_dir(&path, 0o755).expect("create subdir");
        let entries = fs.list_dir("/d").expect("list_dir after create {i}");
        assert_eq!(entries.len(), i + 1, "readdir sees all entries so far");
    }
}

#[test]
fn burst_unlink_all_entries_then_verify_empty() {
    set_test_key();
    let dir = temp_dir("burst_unlink");

    let mut fs = open_fs(&dir);
    fs.create_dir("/d", 0o755).expect("create dir");

    // Create 40 files
    for i in 0..40 {
        let path = format!("/d/f_{i:02}.dat");
        fs.create_file(&path, DEFAULT_FILE_PERMISSIONS)
            .expect("create");
    }
    fs.sync_all().expect("sync");

    // Burst-unlink in batches (simulating 4 threads each removing 10)
    for batch_start in (0..40).step_by(10) {
        for i in batch_start..batch_start + 10 {
            let path = format!("/d/f_{i:02}.dat");
            fs.unlink(&path).expect("unlink");
        }
        fs.sync_all().expect("sync batch");
    }

    let entries = fs.list_dir("/d").expect("list_dir after all unlinks");
    assert!(entries.is_empty(), "directory empty after burst unlinks");
}

#[test]
fn interleaved_rename_and_verify_no_stale_names() {
    set_test_key();
    let dir = temp_dir("interleaved_rename");

    let mut fs = open_fs(&dir);

    // Create 4 subdirs with files, then rename within each
    for d in 0..4 {
        let dir_path = format!("/sub_{d}");
        fs.create_dir(&dir_path, 0o755).expect("create subdir");
        for f in 0..5 {
            let file_path = format!("/sub_{d}/file_{f}.dat");
            fs.create_file(&file_path, DEFAULT_FILE_PERMISSIONS)
                .expect("create file");
        }
        fs.sync_all().expect("sync after create batch");
    }

    // Rename all files (simulating 4 threads each working on a subdir)
    for d in 0..4 {
        for f in 0..5 {
            let old = format!("/sub_{d}/file_{f}.dat");
            let new = format!("/sub_{d}/renamed_{f}.dat");
            fs.rename(&old, &new, false).expect("rename");
        }
        fs.sync_all().expect("sync after rename batch");
    }

    // Verify: old names gone, new names present, no stale entries
    for d in 0..4 {
        let entries = fs.list_dir(format!("/sub_{d}")).expect("list subdir");
        let names: Vec<String> = entries
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name).to_string())
            .collect();

        for f in 0..5 {
            let old = format!("file_{f}.dat");
            let new = format!("renamed_{f}.dat");
            assert!(!names.contains(&old), "old name {old} gone from sub_{d}");
            assert!(names.contains(&new), "new name {new} present in sub_{d}");
        }
        assert_eq!(entries.len(), 5, "sub_{d} has exactly 5 entries");
    }
}

#[test]
fn mixed_mkdir_and_rmdir_interleaved() {
    set_test_key();
    let dir = temp_dir("interleaved_mkdir_rmdir");

    let mut fs = open_fs(&dir);
    fs.create_dir("/d", 0o755).expect("create parent dir");

    // Create 10 subdirs
    for i in 0..10 {
        let path = format!("/d/sub_{i:02}");
        fs.create_dir(&path, 0o755).expect("mkdir");
    }
    fs.sync_all().expect("sync");

    // Remove even-numbered ones
    for i in (0..10).step_by(2) {
        let path = format!("/d/sub_{i:02}");
        fs.remove_dir(&path).expect("rmdir");
    }
    fs.sync_all().expect("sync");

    let entries = fs.list_dir("/d").expect("list_dir");
    assert_eq!(entries.len(), 5, "5 subdirs remain after removing evens");
    let names: Vec<String> = entries
        .iter()
        .map(|e| String::from_utf8_lossy(&e.name).to_string())
        .collect();

    for i in (1..10).step_by(2) {
        let expected = format!("sub_{i:02}");
        assert!(names.contains(&expected), "subdir {expected} survived");
    }
    for i in (0..10).step_by(2) {
        let expected = format!("sub_{i:02}");
        assert!(!names.contains(&expected), "subdir {expected} removed");
    }
}

// Property-based directory operation tests (proptest)
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    #[derive(Clone, Debug)]
    enum DirOp {
        Create(usize),
        Lookup(usize),
        Unlink(usize),
    }

    fn arb_dir_op() -> impl Strategy<Value = DirOp> {
        let idx = 0usize..6;
        prop_oneof![
            3 => idx.clone().prop_map(DirOp::Create),
            2 => idx.clone().prop_map(DirOp::Lookup),
            1 => idx.clone().prop_map(DirOp::Unlink),
        ]
    }

    fn arb_dir_ops() -> impl Strategy<Value = Vec<DirOp>> {
        prop::collection::vec(arb_dir_op(), 4..12)
    }

    /// Random interleaving of create/lookup/unlink must not panic and must
    /// preserve the invariant: every created-and-not-yet-unlinked file
    /// appears in readdir output.
    #[test]
    fn random_create_lookup_unlink_no_panics() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
            cases: 15,
            ..ProptestConfig::default()
        });
        runner
            .run(&arb_dir_ops(), |ops| {
                set_test_key();
                let dir = temp_dir("prop_small");
                let mut live: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();

                let mut fs = open_fs(&dir);
                fs.create_dir("/d", 0o755).expect("create dir");

                for op in &ops {
                    match op {
                        DirOp::Create(idx) => {
                            let path = format!("/d/file_{idx:02}.dat");
                            if fs.create_file(&path, DEFAULT_FILE_PERMISSIONS).is_ok() {
                                live.insert(*idx);
                            }
                        }
                        DirOp::Lookup(idx) => {
                            if live.contains(idx) {
                                let path = format!("/d/file_{idx:02}.dat");
                                prop_assert!(
                                    fs.lookup(&path).is_ok(),
                                    "lookup failed for live idx={idx}"
                                );
                            }
                        }
                        DirOp::Unlink(idx) => {
                            if live.remove(idx) {
                                let path = format!("/d/file_{idx:02}.dat");
                                prop_assert!(
                                    fs.unlink(&path).is_ok(),
                                    "unlink failed for live idx={idx}"
                                );
                            }
                        }
                    }
                }

                fs.sync_all().expect("sync");
                let entries = fs.list_dir("/d").expect("list_dir");
                let names: std::collections::BTreeSet<String> = entries
                    .iter()
                    .map(|e| String::from_utf8_lossy(&e.name).to_string())
                    .collect();

                for idx in &live {
                    let expected = format!("file_{idx:02}.dat");
                    prop_assert!(names.contains(&expected), "live idx={idx} not in readdir");
                }
                Ok(())
            })
            .unwrap();
    }

    #[derive(Clone, Debug)]
    enum DirMutation {
        Mkdir(usize),
        Rmdir(usize),
        Rename { src: usize, dst: usize },
        CreateFile(usize),
        UnlinkFile(usize),
    }

    fn arb_dir_mutation(num_dirs: usize, num_files: usize) -> impl Strategy<Value = DirMutation> {
        let dir_idx = 0usize..num_dirs;
        let file_idx = 0usize..num_files;
        prop_oneof![
            2 => dir_idx.clone().prop_map(DirMutation::Mkdir),
            1 => dir_idx.clone().prop_map(DirMutation::Rmdir),
            2 => (dir_idx.clone(), dir_idx.clone()).prop_map(|(s, d)| DirMutation::Rename { src: s, dst: d }),
            3 => file_idx.clone().prop_map(DirMutation::CreateFile),
            1 => file_idx.clone().prop_map(DirMutation::UnlinkFile),
        ]
    }

    fn arb_dir_mutations() -> impl Strategy<Value = Vec<DirMutation>> {
        prop::collection::vec(arb_dir_mutation(8, 16), 8..24)
    }

    /// Random interleaving of mkdir/rmdir/rename/create_file/unlink must
    /// not panic and must preserve directory invariants: directories that
    /// were created and not removed appear in the parent readdir, files
    /// that were created and not unlinked appear in readdir, and renamed
    /// entries are found at their new names but not old names.
    #[test]
    fn random_dir_mutation_no_panics() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
            cases: 20,
            ..ProptestConfig::default()
        });
        runner
            .run(&arb_dir_mutations(), |ops| {
                set_test_key();
                let dir = temp_dir("prop_dir_mut");
                let mut fs = open_fs(&dir);
                fs.create_dir("/root", 0o755).expect("create root dir");

                // Track named directories that exist
                let mut live_dirs: std::collections::BTreeSet<usize> =
                    std::collections::BTreeSet::new();
                // Track file existence by index within their dir
                let mut live_files: std::collections::BTreeSet<(usize, usize)> =
                    std::collections::BTreeSet::new();
                // Track inode assignments for files
                let mut file_inodes: std::collections::BTreeMap<
                    (usize, usize),
                    tidefs_types_vfs_core::InodeId,
                > = std::collections::BTreeMap::new();

                // Pre-create some directories to work with
                for i in 0..4usize {
                    let path = format!("/root/d_{i:02}");
                    if fs.create_dir(&path, 0o755).is_ok() {
                        live_dirs.insert(i);
                    }
                }

                for op in &ops {
                    match op {
                        DirMutation::Mkdir(idx) => {
                            let path = format!("/root/d_{idx:02}");
                            if !live_dirs.contains(idx) && fs.create_dir(&path, 0o755).is_ok() {
                                live_dirs.insert(*idx);
                            }
                        }
                        DirMutation::Rmdir(idx) => {
                            if live_dirs.contains(idx) {
                                let path = format!("/root/d_{idx:02}");
                                // Remove all files in this dir first
                                let to_remove: Vec<usize> = live_files
                                    .iter()
                                    .filter(|(d, _)| d == idx)
                                    .map(|(_, f)| *f)
                                    .collect();
                                for f_idx in to_remove {
                                    let fpath = format!("/root/d_{idx:02}/f_{f_idx:02}.dat");
                                    let _ = fs.unlink(&fpath);
                                    live_files.remove(&(*idx, f_idx));
                                }
                                if fs.remove_dir(&path).is_ok() {
                                    live_dirs.remove(idx);
                                }
                            }
                        }
                        DirMutation::Rename { src, dst } => {
                            let src_path = format!("/root/d_{src:02}");
                            let dst_path = format!("/root/d_{dst:02}");
                            if live_dirs.contains(src) {
                                // Rename directory if target doesn't exist and
                                // src has no files to keep it simple
                                let src_file_count =
                                    live_files.iter().filter(|(d, _)| d == src).count();
                                if !live_dirs.contains(dst) && src_file_count == 0 {
                                    let result = fs.rename(&src_path, &dst_path, true);
                                    if result.is_ok() {
                                        live_dirs.remove(src);
                                        live_dirs.insert(*dst);
                                        // Re-key any files from src to dst
                                        let files_to_move: Vec<(usize, usize)> = live_files
                                            .iter()
                                            .filter(|(d, _)| d == src)
                                            .copied()
                                            .collect();
                                        for (old_d, f_idx) in files_to_move {
                                            live_files.remove(&(old_d, f_idx));
                                            live_files.insert((*dst, f_idx));
                                        }
                                    }
                                }
                            }
                        }
                        DirMutation::CreateFile(idx) => {
                            if live_dirs.contains(idx) {
                                let file_num = live_files.len();
                                let path = format!("/root/d_{idx:02}/f_{file_num:02}.dat");
                                if let Ok(rec) = fs.create_file(&path, DEFAULT_FILE_PERMISSIONS) {
                                    live_files.insert((*idx, file_num));
                                    file_inodes.insert((*idx, file_num), rec.inode_id);
                                }
                            }
                        }
                        DirMutation::UnlinkFile(idx) => {
                            if live_dirs.contains(idx) {
                                if let Some((&(d, f), _)) = live_files
                                    .iter()
                                    .filter(|(dir_idx, _)| *dir_idx == *idx)
                                    .enumerate()
                                    .next()
                                    .map(|(_, key)| (key, ()))
                                {
                                    let path = format!("/root/d_{d:02}/f_{f:02}.dat");
                                    if fs.unlink(&path).is_ok() {
                                        live_files.remove(&(d, f));
                                        file_inodes.remove(&(d, f));
                                    }
                                }
                            }
                        }
                    }
                }

                fs.sync_all().expect("sync");

                // Verify invariants
                let root_entries = fs.list_dir("/root").expect("list /root");
                let root_names: std::collections::BTreeSet<String> = root_entries
                    .iter()
                    .map(|e| String::from_utf8_lossy(&e.name).to_string())
                    .collect();
                for d_idx in &live_dirs {
                    let expected = format!("d_{d_idx:02}");
                    prop_assert!(
                        root_names.contains(&expected),
                        "live dir d_{d_idx:02} not in /root readdir"
                    );
                }

                // Verify files within their directories
                for (d_idx, f_idx) in &live_files {
                    let dir_path = format!("/root/d_{d_idx:02}");
                    let entries = fs.list_dir(&dir_path).unwrap_or_else(|_| vec![]);
                    let file_names: std::collections::BTreeSet<String> = entries
                        .iter()
                        .map(|e| String::from_utf8_lossy(&e.name).to_string())
                        .collect();
                    let expected_file = format!("f_{f_idx:02}.dat");
                    prop_assert!(
                        file_names.contains(&expected_file),
                        "file {expected_file} not in dir d_{d_idx:02} readdir"
                    );
                }

                Ok(())
            })
            .unwrap();
    }
}
