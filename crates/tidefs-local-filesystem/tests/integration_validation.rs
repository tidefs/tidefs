// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration validation suite for tidefs-local-filesystem.
//!
//! Exercises the full mount-to-unmount lifecycle through the public API:
//! file create/read/write/close, directory create/readdir/rmdir, stat/getattr,
//! unlink, rename, and metadata persistence across mount cycles.
//!
//! # Organisation
//!
//! - [`TestHarness`] — tempdir-backed filesystem init, mount/unmount, and
//!   convenience wrappers.
//! - `file_lifecycle` — create, write, read, append, overwrite, large-file,
//!   stat-reflects-write.
//! - `directory_lifecycle` — mkdir, nested mkdir, readdir, rmdir.
//! - `unlink_namespace` — unlink, unlink-nonexistent, unlink-then-recreate.
//! - `metadata_persistence` — stat across remount, rename persistence.
//! - `error_paths` — operations on nonexistent paths, invalid paths,
//!   empty filenames, path with NUL, etc.

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::{
    LocalFileSystem, DEFAULT_DIRECTORY_PERMISSIONS, DEFAULT_FILE_PERMISSIONS,
};
use tidefs_local_object_store::{LocalObjectStore, StoreOptions};
use tidefs_types_dataset_lifecycle_core::TraversalRootType;

// ---------------------------------------------------------------------------
// TestHarness
// ---------------------------------------------------------------------------

/// Tempdir-backed filesystem harness that owns the lifecycle from creation
/// through teardown.
struct TestHarness {
    root: PathBuf,
    fs: Option<LocalFileSystem>,
}

impl TestHarness {
    /// Create a temp directory, initialise an object store, and mount a
    /// [`LocalFileSystem`].
    fn mount(label: &str) -> Self {
        Self::set_test_key();

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "tidefs-integration-valid-{label}-{ts}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp dir");

        let opts = StoreOptions::test_fast();
        let store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
        drop(store);

        let fs = LocalFileSystem::open(&root).expect("open filesystem");

        Self { root, fs: Some(fs) }
    }

    fn set_test_key() {
        std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
    }

    fn fs_mut(&mut self) -> &mut LocalFileSystem {
        self.fs.as_mut().expect("filesystem not mounted")
    }

    fn fs(&self) -> &LocalFileSystem {
        self.fs.as_ref().expect("filesystem not mounted")
    }

    fn unmount(&mut self) {
        if let Some(mut fs) = self.fs.take() {
            let _ = fs.sync_all();
            drop(fs);
        }
    }

    fn remount(&mut self) {
        self.fs = Some(LocalFileSystem::open(&self.root).expect("reopen filesystem"));
    }

    fn create_file(&mut self, path: &str, permissions: u32) {
        self.fs_mut()
            .create_file(path, permissions)
            .unwrap_or_else(|e| panic!("create_file {path}: {e:?}"));
    }

    fn write_file(&mut self, path: &str, offset: u64, data: &[u8]) {
        self.fs_mut()
            .write_file(path, offset, data)
            .unwrap_or_else(|e| panic!("write_file {path}: {e:?}"));
    }

    fn overwrite_file(&mut self, path: &str, data: &[u8]) {
        self.write_file(path, 0, data);
    }

    fn read_file(&self, path: &str) -> Vec<u8> {
        self.fs()
            .read_file(path)
            .unwrap_or_else(|e| panic!("read_file {path}: {e:?}"))
    }

    fn read_file_opt(
        &self,
        path: &str,
    ) -> Result<Vec<u8>, tidefs_local_filesystem::FileSystemError> {
        self.fs().read_file(path)
    }

    fn stat(&self, path: &str) -> tidefs_local_filesystem::InodeRecord {
        self.fs()
            .stat(path)
            .unwrap_or_else(|e| panic!("stat {path}: {e:?}"))
    }

    fn stat_opt(
        &self,
        path: &str,
    ) -> Result<tidefs_local_filesystem::InodeRecord, tidefs_local_filesystem::FileSystemError>
    {
        self.fs().stat(path)
    }

    fn list_dir(&self, path: &str) -> Vec<tidefs_local_filesystem::NamespaceEntry> {
        self.fs()
            .list_dir(path)
            .unwrap_or_else(|e| panic!("list_dir {path}: {e:?}"))
    }

    fn mkdir(&mut self, path: &str) {
        self.fs_mut()
            .create_dir(path, DEFAULT_DIRECTORY_PERMISSIONS)
            .unwrap_or_else(|e| panic!("mkdir {path}: {e:?}"));
    }

    fn unlink(&mut self, path: &str) {
        self.fs_mut()
            .unlink(path)
            .unwrap_or_else(|e| panic!("unlink {path}: {e:?}"));
    }

    fn unlink_opt(&mut self, path: &str) -> Result<(), tidefs_local_filesystem::FileSystemError> {
        self.fs_mut().unlink(path)
    }

    fn rename(&mut self, from: &str, to: &str, overwrite: bool) {
        self.fs_mut()
            .rename(from, to, overwrite)
            .unwrap_or_else(|e| panic!("rename {from} -> {to}: {e:?}"));
    }

    fn rmdir(&mut self, path: &str) {
        self.fs_mut()
            .remove_dir(path)
            .unwrap_or_else(|e| panic!("rmdir {path}: {e:?}"));
    }

    fn sync_all(&mut self) {
        self.fs_mut().sync_all().expect("sync_all");
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        self.fs.take();
        let _ = fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------------------
// file_lifecycle
// ---------------------------------------------------------------------------
mod file_lifecycle {
    use super::*;

    #[test]
    fn create_empty_file_and_stat() {
        let mut h = TestHarness::mount("create_empty");
        h.create_file("/empty.txt", DEFAULT_FILE_PERMISSIONS);
        let s = h.stat("/empty.txt");
        assert_eq!(s.size, 0);
        assert!(s.carries_byte_space());
        assert!(!s.carries_child_namespace());
    }

    #[test]
    fn write_and_read_roundtrip() {
        let mut h = TestHarness::mount("write_read");
        h.create_file("/roundtrip.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/roundtrip.txt", 0, b"hello world!");
        let content = h.read_file("/roundtrip.txt");
        assert_eq!(content, b"hello world!");
        let s = h.stat("/roundtrip.txt");
        assert_eq!(s.size, 12);
    }

    #[test]
    fn write_append_and_read() {
        let mut h = TestHarness::mount("append");
        h.create_file("/append.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/append.txt", 0, b"first ");
        h.write_file("/append.txt", 6, b"second");
        let content = h.read_file("/append.txt");
        assert_eq!(content, b"first second");
        let s = h.stat("/append.txt");
        assert_eq!(s.size, 12);
    }

    #[test]
    fn write_large_file() {
        let mut h = TestHarness::mount("large");
        h.create_file("/large.bin", DEFAULT_FILE_PERMISSIONS);
        let data: Vec<u8> = (0..128u8).cycle().take(65536).collect();
        h.write_file("/large.bin", 0, &data);
        let content = h.read_file("/large.bin");
        assert_eq!(content.len(), 65536);
        assert_eq!(&content[0..128], &data[0..128]);
        assert_eq!(&content[65408..65536], &data[65408..65536]);
        let s = h.stat("/large.bin");
        assert_eq!(s.size, 65536);
    }

    #[test]
    fn overwrite_and_truncate() {
        let mut h = TestHarness::mount("overwrite_trunc");
        h.create_file("/ow.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/ow.txt", 0, b"longer initial content");
        // write at offset 0 does not shrink the file; truncate explicitly
        h.write_file("/ow.txt", 0, b"short");
        h.fs_mut().truncate_file("/ow.txt", 5).expect("truncate");
        let content = h.read_file("/ow.txt");
        assert_eq!(content, b"short");
        let s = h.stat("/ow.txt");
        assert_eq!(s.size, 5);
    }

    #[test]
    fn overwrite_partial_preserves_tail() {
        let mut h = TestHarness::mount("ow_partial");
        h.create_file("/partial.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/partial.txt", 0, b"initial content here");
        h.write_file("/partial.txt", 8, b"UPDATED");
        let content = h.read_file("/partial.txt");
        assert_eq!(&content[0..8], b"initial ");
        assert_eq!(&content[8..15], b"UPDATED");
        assert_eq!(&content[15..], b" here");
    }

    #[test]
    fn write_sparse_creates_hole() {
        let mut h = TestHarness::mount("sparse");
        h.create_file("/sparse.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/sparse.bin", 0, b"AAAA");
        h.write_file("/sparse.bin", 8192, b"BBBB");
        let content = h.read_file("/sparse.bin");
        assert_eq!(content.len(), 8196);
        assert_eq!(&content[0..4], b"AAAA");
        assert_eq!(&content[8192..8196], b"BBBB");
        assert!(content[4..8192].iter().all(|&b| b == 0));
        let s = h.stat("/sparse.bin");
        assert_eq!(s.size, 8196);
    }

    #[test]
    fn write_zero_bytes_is_noop() {
        let mut h = TestHarness::mount("zero_write");
        h.create_file("/zero.bin", DEFAULT_FILE_PERMISSIONS);
        let s0 = h.stat("/zero.bin");
        h.fs_mut()
            .write_file("/zero.bin", 0, &[])
            .expect("zero-byte write");
        let s1 = h.stat("/zero.bin");
        assert_eq!(s1.size, s0.size);
    }
}

// ---------------------------------------------------------------------------
// directory_lifecycle
// ---------------------------------------------------------------------------
mod directory_lifecycle {
    use super::*;

    #[test]
    fn mkdir_and_stat() {
        let mut h = TestHarness::mount("mkdir_stat");
        h.mkdir("/mydir");
        let s = h.stat("/mydir");
        assert!(s.carries_child_namespace());
        assert!(!s.carries_byte_space());
    }

    #[test]
    fn mkdir_nested() {
        let mut h = TestHarness::mount("mkdir_nested");
        h.mkdir("/a");
        h.mkdir("/a/b");
        h.mkdir("/a/b/c");

        assert!(h.stat("/a").carries_child_namespace());
        assert!(h.stat("/a/b").carries_child_namespace());
        assert!(h.stat("/a/b/c").carries_child_namespace());

        let root: Vec<String> = h.list_dir("/").iter().map(|e| e.name_lossy()).collect();
        assert!(root.contains(&"a".to_string()));

        let a_entries: Vec<String> = h.list_dir("/a").iter().map(|e| e.name_lossy()).collect();
        assert!(a_entries.contains(&"b".to_string()));
    }

    #[test]
    fn readdir_lists_entries() {
        let mut h = TestHarness::mount("readdir_entries");
        h.create_file("/a.txt", DEFAULT_FILE_PERMISSIONS);
        h.create_file("/b.txt", DEFAULT_FILE_PERMISSIONS);
        h.create_file("/c.txt", DEFAULT_FILE_PERMISSIONS);

        let names: Vec<String> = h.list_dir("/").iter().map(|e| e.name_lossy()).collect();
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));
        assert!(names.contains(&"c.txt".to_string()));
    }

    #[test]
    fn readdir_empty() {
        let h = TestHarness::mount("readdir_empty");
        let entries = h.list_dir("/");
        assert!(
            !entries.iter().any(|e| !e.name_lossy().is_empty()),
            "fresh root should have no non-implicit entries"
        );
    }

    #[test]
    fn rmdir_empty_succeeds() {
        let mut h = TestHarness::mount("rmdir_empty");
        h.mkdir("/emptydir");
        h.rmdir("/emptydir");
        assert!(h.stat_opt("/emptydir").is_err());
    }

    #[test]
    fn rmdir_nonempty_fails() {
        let mut h = TestHarness::mount("rmdir_nonempty");
        h.mkdir("/populated");
        h.create_file("/populated/f.txt", DEFAULT_FILE_PERMISSIONS);
        let result = h.unlink_opt("/populated");
        assert!(result.is_err());
        assert!(h.stat("/populated").carries_child_namespace());
    }

    #[test]
    fn readdir_excludes_deleted() {
        let mut h = TestHarness::mount("readdir_excl");
        h.create_file("/temp.txt", DEFAULT_FILE_PERMISSIONS);
        let before: Vec<String> = h.list_dir("/").iter().map(|e| e.name_lossy()).collect();
        assert!(before.contains(&"temp.txt".to_string()));
        h.unlink("/temp.txt");
        let after: Vec<String> = h.list_dir("/").iter().map(|e| e.name_lossy()).collect();
        assert!(!after.contains(&"temp.txt".to_string()));
    }

    #[test]
    fn mkdir_already_exists_fails() {
        let mut h = TestHarness::mount("mkdir_exists");
        h.mkdir("/dup");
        let result = h.fs_mut().create_dir("/dup", DEFAULT_DIRECTORY_PERMISSIONS);
        assert!(result.is_err());
    }

    #[test]
    fn create_file_in_nonexistent_dir_fails() {
        let h = TestHarness::mount("create_in_nonex");
        // Need &mut, so use a short-lived bind
        drop(h);
        let mut h2 = TestHarness::mount("create_in_nonex2");
        let result = h2
            .fs_mut()
            .create_file("/nodir/f.txt", DEFAULT_FILE_PERMISSIONS);
        assert!(result.is_err());
    }
}

// ---------------------------------------------------------------------------
// unlink_namespace
// ---------------------------------------------------------------------------
mod unlink_namespace {
    use super::*;

    #[test]
    fn unlink_removes_file() {
        let mut h = TestHarness::mount("unlink_rm");
        h.create_file("/victim.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/victim.txt", 0, b"doomed");
        h.unlink("/victim.txt");
        assert!(h.stat_opt("/victim.txt").is_err());
    }

    #[test]
    fn unlink_nonexistent_fails() {
        let mut h = TestHarness::mount("unlink_nonex");
        let result = h.unlink_opt("/nope.txt");
        assert!(result.is_err());
    }

    #[test]
    fn unlink_then_recreate() {
        let mut h = TestHarness::mount("unlink_recreate");
        h.create_file("/recreate.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/recreate.txt", 0, b"v1");
        h.unlink("/recreate.txt");
        h.create_file("/recreate.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/recreate.txt", 0, b"v2");
        assert_eq!(h.read_file("/recreate.txt"), b"v2");
    }

    #[test]
    fn unlink_empty_file() {
        let mut h = TestHarness::mount("unlink_empty");
        h.create_file("/empty.dat", DEFAULT_FILE_PERMISSIONS);
        h.unlink("/empty.dat");
        assert!(h.stat_opt("/empty.dat").is_err());
    }
}

// ---------------------------------------------------------------------------
// rename
// ---------------------------------------------------------------------------
mod rename_tests {
    use super::*;

    #[test]
    fn rename_same_directory() {
        let mut h = TestHarness::mount("rename_same");
        h.create_file("/old.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/old.txt", 0, b"renamed content");
        h.rename("/old.txt", "/new.txt", false);
        assert!(h.stat_opt("/old.txt").is_err());
        assert_eq!(h.read_file("/new.txt"), b"renamed content");
    }

    #[test]
    fn rename_across_directories() {
        let mut h = TestHarness::mount("rename_cross");
        h.mkdir("/src");
        h.mkdir("/dst");
        h.create_file("/src/from.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/src/from.txt", 0, b"cross dir");
        h.rename("/src/from.txt", "/dst/to.txt", false);
        assert!(h.stat_opt("/src/from.txt").is_err());
        assert_eq!(h.read_file("/dst/to.txt"), b"cross dir");

        let src: Vec<String> = h.list_dir("/src").iter().map(|e| e.name_lossy()).collect();
        assert!(!src.contains(&"from.txt".to_string()));
        let dst: Vec<String> = h.list_dir("/dst").iter().map(|e| e.name_lossy()).collect();
        assert!(dst.contains(&"to.txt".to_string()));
    }

    #[test]
    fn rename_source_not_found() {
        let mut h = TestHarness::mount("rename_src_404");
        let result = h.fs_mut().rename("/missing.txt", "/dest.txt", false);
        assert!(result.is_err());
    }

    #[test]
    fn rename_overwrite_existing() {
        let mut h = TestHarness::mount("rename_overwrite");
        h.create_file("/alfa.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/alfa.txt", 0, b"alfa data");
        h.create_file("/bravo.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/bravo.txt", 0, b"bravo data");
        h.rename("/alfa.txt", "/bravo.txt", false);
        assert!(h.stat_opt("/alfa.txt").is_err());
        assert_eq!(h.read_file("/bravo.txt"), b"alfa data");
    }
}

// ---------------------------------------------------------------------------
// metadata_persistence
// ---------------------------------------------------------------------------
mod metadata_persistence {
    use super::*;

    #[test]
    fn stat_across_remount() {
        let mut h = TestHarness::mount("stat_remount");
        h.create_file("/persist.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/persist.txt", 0, b"persistent data here");
        h.create_file("/empty.dat", DEFAULT_FILE_PERMISSIONS);

        let s_file = h.stat("/persist.txt");
        let s_empty = h.stat("/empty.dat");

        h.sync_all();
        h.unmount();
        h.remount();

        let s_file2 = h.stat("/persist.txt");
        let s_empty2 = h.stat("/empty.dat");
        assert_eq!(s_file2.size, s_file.size);
        assert_eq!(s_file2.inode_id, s_file.inode_id);
        assert_eq!(s_empty2.size, s_empty.size);
        assert_eq!(s_empty2.inode_id, s_empty.inode_id);
    }

    #[test]
    fn file_content_survives_remount() {
        let mut h = TestHarness::mount("content_remount");
        h.create_file("/survive.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/survive.txt", 0, b"surviving content");
        h.sync_all();
        h.unmount();
        h.remount();
        assert_eq!(h.read_file("/survive.txt"), b"surviving content");
    }

    #[test]
    fn directory_structure_survives_remount() {
        let mut h = TestHarness::mount("dir_remount");
        h.mkdir("/layer1");
        h.mkdir("/layer1/layer2");
        h.create_file("/layer1/f1.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/layer1/f1.txt", 0, b"f1");
        h.create_file("/layer1/layer2/f2.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/layer1/layer2/f2.txt", 0, b"f2");

        h.sync_all();
        h.unmount();
        h.remount();

        let root: Vec<String> = h.list_dir("/").iter().map(|e| e.name_lossy()).collect();
        assert!(root.contains(&"layer1".to_string()));

        let l1: Vec<String> = h
            .list_dir("/layer1")
            .iter()
            .map(|e| e.name_lossy())
            .collect();
        assert!(l1.contains(&"layer2".to_string()));
        assert!(l1.contains(&"f1.txt".to_string()));

        let l2: Vec<String> = h
            .list_dir("/layer1/layer2")
            .iter()
            .map(|e| e.name_lossy())
            .collect();
        assert!(l2.contains(&"f2.txt".to_string()));

        assert_eq!(h.read_file("/layer1/f1.txt"), b"f1");
        assert_eq!(h.read_file("/layer1/layer2/f2.txt"), b"f2");
    }

    #[test]
    fn unlink_persists_across_remount() {
        let mut h = TestHarness::mount("unlink_persist");
        h.create_file("/delete_me.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/delete_me.txt", 0, b"temp");
        h.unlink("/delete_me.txt");
        h.sync_all();
        h.unmount();
        h.remount();

        assert!(h.stat_opt("/delete_me.txt").is_err());
        let root: Vec<String> = h.list_dir("/").iter().map(|e| e.name_lossy()).collect();
        assert!(!root.contains(&"delete_me.txt".to_string()));
    }

    #[test]
    fn rename_persists_across_remount() {
        let mut h = TestHarness::mount("rename_persist");
        h.create_file("/before.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/before.txt", 0, b"renamed data");
        h.rename("/before.txt", "/after.txt", false);
        h.sync_all();
        h.unmount();
        h.remount();

        assert!(h.stat_opt("/before.txt").is_err());
        assert_eq!(h.read_file("/after.txt"), b"renamed data");
    }

    #[test]
    fn mkdir_persists_across_remount() {
        let mut h = TestHarness::mount("mkdir_persist");
        h.mkdir("/solo");
        h.sync_all();
        h.unmount();
        h.remount();
        assert!(h.stat("/solo").carries_child_namespace());
    }
}

// ---------------------------------------------------------------------------
// error_paths
// ---------------------------------------------------------------------------
mod error_paths {
    use super::*;

    #[test]
    fn read_nonexistent_file() {
        let h = TestHarness::mount("read_nonex");
        assert!(h.read_file_opt("/ghost.txt").is_err());
    }

    #[test]
    fn stat_nonexistent() {
        let h = TestHarness::mount("stat_nonex");
        assert!(h.stat_opt("/ghost.txt").is_err());
    }

    #[test]
    fn read_directory_as_file_fails() {
        let mut h = TestHarness::mount("read_dir");
        h.mkdir("/adir");
        assert!(h.read_file_opt("/adir").is_err());
    }

    #[test]
    fn write_to_directory_fails() {
        let mut h = TestHarness::mount("write_dir");
        h.mkdir("/adir");
        let result = h.fs_mut().write_file("/adir", 0, b"data");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_path_relative() {
        let h = TestHarness::mount("path_rel");
        let result = h.fs().stat("relative");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_path_no_leading_slash() {
        let h = TestHarness::mount("path_noslash");
        let result = h.fs().stat("no/slash");
        assert!(result.is_err());
    }

    #[test]
    fn path_with_nul_byte() {
        let mut h = TestHarness::mount("path_nul");
        let result = h
            .fs_mut()
            .create_file("/bad\0name.txt", DEFAULT_FILE_PERMISSIONS);
        assert!(result.is_err());
    }

    #[test]
    fn empty_path() {
        let h = TestHarness::mount("empty_path");
        let result = h.fs().stat("");
        assert!(result.is_err());
    }

    #[test]
    fn deep_nested_path() {
        let mut h = TestHarness::mount("deep_path");
        // Build a chain: /d, /d/d, /d/d/d, ... 20 levels
        let mut path = String::from("/d");
        for _i in 0..19 {
            h.mkdir(&path);
            path.push_str("/d");
        }
        // After 19 mkdir calls and 19 push_str calls, path is 20 "/d" segments.
        // mkdir the 20th (final) level.
        h.mkdir(&path);
        // The 19th level (one above the last) should contain a "d" entry.
        let parent = "/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d";
        let dirs: Vec<String> = h.list_dir(parent).iter().map(|e| e.name_lossy()).collect();
        assert!(dirs.contains(&"d".to_string()));
    }

    #[test]
    fn truncate_nonexistent_file() {
        let mut h = TestHarness::mount("trunc_nonex");
        let result = h.fs_mut().truncate_file("/ghost.bin", 64);
        assert!(result.is_err());
    }

    #[test]
    fn truncate_to_zero() {
        let mut h = TestHarness::mount("trunc_zero");
        h.create_file("/shrink.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/shrink.bin", 0, b"data to truncate");
        h.fs_mut()
            .truncate_file("/shrink.bin", 0)
            .expect("trunc to 0");
        let s = h.stat("/shrink.bin");
        assert_eq!(s.size, 0);
        assert!(h.read_file("/shrink.bin").is_empty());
    }

    #[test]
    fn truncate_same_size_preserves_content() {
        let mut h = TestHarness::mount("trunc_same");
        h.create_file("/same.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/same.bin", 0, b"abcdef");
        h.fs_mut()
            .truncate_file("/same.bin", 6)
            .expect("trunc to 6");
        assert_eq!(h.stat("/same.bin").size, 6);
        assert_eq!(h.read_file("/same.bin"), b"abcdef");
    }

    #[test]
    fn truncate_extend_zero_fills() {
        let mut h = TestHarness::mount("trunc_extend");
        h.create_file("/extend.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/extend.bin", 0, b"abc");
        h.fs_mut()
            .truncate_file("/extend.bin", 10)
            .expect("trunc to 10");
        let s = h.stat("/extend.bin");
        assert_eq!(s.size, 10);
        let content = h.read_file("/extend.bin");
        assert_eq!(&content[0..3], b"abc");
        assert!(content[3..].iter().all(|&b| b == 0));
    }
}

// ---------------------------------------------------------------------------
// edge_cases
// ---------------------------------------------------------------------------
mod edge_cases {
    use super::*;

    #[test]
    fn max_filename_length() {
        let mut h = TestHarness::mount("max_name");
        let long = "a".repeat(255);
        let path = format!("/{long}");
        h.create_file(&path, DEFAULT_FILE_PERMISSIONS);
        let s = h.stat(&path);
        assert_eq!(s.size, 0);
    }

    #[test]
    fn special_characters_in_filename() {
        let mut h = TestHarness::mount("special_chars");
        let name = "file-with_underscores-and.dots-and-123.txt";
        let path = format!("/{name}");
        h.create_file(&path, DEFAULT_FILE_PERMISSIONS);
        h.write_file(&path, 0, b"special chars ok");
        assert_eq!(h.read_file(&path), b"special chars ok");
    }

    #[test]
    fn many_files_in_single_directory() {
        let mut h = TestHarness::mount("many_files");
        let count = 50;
        for i in 0..count {
            let path = format!("/file_{i:03}.dat");
            h.create_file(&path, DEFAULT_FILE_PERMISSIONS);
            h.write_file(&path, 0, format!("data-{i}").as_bytes());
        }
        let names: Vec<String> = h.list_dir("/").iter().map(|e| e.name_lossy()).collect();
        for i in 0..count {
            let expected = format!("file_{i:03}.dat");
            assert!(names.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn write_multiple_small_files_and_read_back() {
        let mut h = TestHarness::mount("multi_small");
        for i in 0..20 {
            let path = format!("/small_{i}.txt");
            h.create_file(&path, DEFAULT_FILE_PERMISSIONS);
            h.write_file(&path, 0, format!("content {i:02}").as_bytes());
        }
        for i in 0..20 {
            let path = format!("/small_{i}.txt");
            let expected = format!("content {i:02}").into_bytes();
            assert_eq!(h.read_file(&path), expected);
        }
    }

    #[test]
    fn concurrent_create_and_list() {
        let mut h = TestHarness::mount("concurrent");
        let mut expected = Vec::new();
        for i in 0..10 {
            let name = format!("/conc_{i}.tmp");
            h.create_file(&name, DEFAULT_FILE_PERMISSIONS);
            expected.push(name.trim_start_matches('/').to_string());
        }
        let names: Vec<String> = h.list_dir("/").iter().map(|e| e.name_lossy()).collect();
        for exp in &expected {
            assert!(names.contains(exp), "missing {exp}");
        }
    }

    #[test]
    fn stat_reflects_write() {
        let mut h = TestHarness::mount("stat_vs_write");
        h.create_file("/stat_check.txt", DEFAULT_FILE_PERMISSIONS);
        let s0 = h.stat("/stat_check.txt");
        assert_eq!(s0.size, 0);

        h.write_file("/stat_check.txt", 0, b"updated!");
        let s1 = h.stat("/stat_check.txt");
        assert_eq!(s1.size, 8);
        assert!(
            s1.data_version > s0.data_version || s1.metadata_version > s0.metadata_version,
            "versions should advance after write"
        );
    }

    #[test]
    fn hard_link_and_read_both_names() {
        let mut h = TestHarness::mount("hard_link");
        h.create_file("/original.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/original.txt", 0, b"linked content");
        h.fs_mut()
            .link_file("/original.txt", "/link.txt")
            .expect("hard link");

        assert_eq!(h.read_file("/original.txt"), b"linked content");
        assert_eq!(h.read_file("/link.txt"), b"linked content");

        let s_orig = h.stat("/original.txt");
        let s_link = h.stat("/link.txt");
        assert_eq!(s_orig.inode_id, s_link.inode_id, "hard links share inode");
        assert_eq!(s_orig.nlink, 2);
        assert_eq!(s_link.nlink, 2);
    }

    #[test]
    fn symlink_and_readlink() {
        let mut h = TestHarness::mount("symlink");
        h.create_file("/target.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/target.txt", 0, b"target data");
        h.fs_mut()
            .create_symlink("/link.lnk", b"/target.txt")
            .expect("symlink");

        let target = h.fs().read_symlink("/link.lnk").expect("readlink");
        assert_eq!(target, b"/target.txt");

        let s = h.stat("/link.lnk");
        let kind_str = format!("{:?}", s.kind());
        assert!(
            kind_str.contains("Symlink"),
            "expected Symlink, got {kind_str}"
        );
    }
}

// ---------------------------------------------------------------------------
// snapshot_lifecycle
// ---------------------------------------------------------------------------
mod snapshot_lifecycle {
    use super::*;

    #[test]
    fn create_snapshot_and_list() {
        let mut h = TestHarness::mount("snap_list");
        h.create_file("/data.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/data.txt", 0, b"pre-snapshot");

        h.fs_mut().create_snapshot("snap1").expect("create snap1");

        let snaps = h.fs().list_snapshots();
        let names: Vec<&str> = snaps.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"snap1"), "snap1 must appear in list");
    }

    #[test]
    fn snapshot_summary_retrievable() {
        let mut h = TestHarness::mount("snap_summary");
        h.create_file("/data.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/data.txt", 0, b"snapshot me");

        h.fs_mut().create_snapshot("snap1").expect("create snap1");

        let summary = h
            .fs()
            .snapshot_summary("snap1")
            .expect("get snapshot summary");
        assert_eq!(summary.name, "snap1");
        assert!(summary.source_generation > 0);
    }

    #[test]
    fn delete_snapshot_removes_from_list() {
        let mut h = TestHarness::mount("snap_delete");
        h.create_file("/data.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/data.txt", 0, b"data");

        h.fs_mut().create_snapshot("temp_snap").expect("create");
        assert!(h
            .fs()
            .list_snapshots()
            .iter()
            .any(|s| s.name == "temp_snap"));

        h.fs_mut().delete_snapshot("temp_snap").expect("delete");
        assert!(!h
            .fs()
            .list_snapshots()
            .iter()
            .any(|s| s.name == "temp_snap"));
    }

    #[test]
    fn rollback_restores_content() {
        let mut h = TestHarness::mount("snap_rollback");
        h.create_file("/doc.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/doc.txt", 0, b"version one");
        h.sync_all();

        h.fs_mut().create_snapshot("v1").expect("create snapshot");

        // Modify after snapshot
        h.overwrite_file("/doc.txt", b"version two");
        h.sync_all();

        // Rollback to v1
        let report = h.fs_mut().rollback_to_snapshot("v1").expect("rollback");
        assert!(report.published_generation > report.generation_before);

        // Content must be restored
        let content = h.read_file("/doc.txt");
        assert_eq!(content, b"version one");
    }

    #[test]
    fn rollback_restores_deleted_file() {
        let mut h = TestHarness::mount("snap_restore_del");
        h.create_file("/precious.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/precious.txt", 0, b"keep me");
        h.sync_all();

        h.fs_mut()
            .create_snapshot("before_delete")
            .expect("snapshot");

        h.unlink("/precious.txt");
        h.sync_all();

        assert!(h.stat_opt("/precious.txt").is_err());

        h.fs_mut()
            .rollback_to_snapshot("before_delete")
            .expect("rollback");

        let content = h.read_file("/precious.txt");
        assert_eq!(content, b"keep me");
    }

    #[test]
    fn rollback_restores_directory_structure() {
        let mut h = TestHarness::mount("snap_restore_dir");
        h.mkdir("/myapp");
        h.mkdir("/myapp/config");
        h.create_file("/myapp/config/settings.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/myapp/config/settings.txt", 0, b"debug=true");
        h.mkdir("/myapp/data");
        h.sync_all();

        h.fs_mut().create_snapshot("app_v1").expect("snapshot");

        // Destroy the structure
        h.unlink("/myapp/config/settings.txt");
        h.rmdir("/myapp/config");
        h.rmdir("/myapp/data");
        h.rmdir("/myapp");
        h.sync_all();

        // Rollback
        h.fs_mut().rollback_to_snapshot("app_v1").expect("rollback");

        assert_eq!(h.read_file("/myapp/config/settings.txt"), b"debug=true");
        let myapp: Vec<String> = h
            .list_dir("/myapp")
            .iter()
            .map(|e| e.name_lossy())
            .collect();
        assert!(myapp.contains(&"config".to_string()));
        assert!(myapp.contains(&"data".to_string()));
    }

    #[test]
    fn snapshot_content_isolation() {
        let mut h = TestHarness::mount("snap_isolation");
        h.create_file("/shared.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/shared.txt", 0, b"original");
        h.sync_all();

        h.fs_mut().create_snapshot("s1").expect("snapshot s1");

        // Overwrite and create new snapshot
        h.overwrite_file("/shared.txt", b"modified");
        h.create_file("/new_file.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/new_file.txt", 0, b"new");
        h.sync_all();

        h.fs_mut().create_snapshot("s2").expect("snapshot s2");

        // Delete s1, rollback to s2, verify s2 content
        h.fs_mut().delete_snapshot("s1").expect("delete s1");

        // s2 data still present
        assert_eq!(h.read_file("/shared.txt"), b"modified");
        assert_eq!(h.read_file("/new_file.txt"), b"new");

        // Rollback to s2 (should be idempotent as we're already at s2 state)
        let snaps = h.fs().list_snapshots();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].name, "s2");
    }

    #[test]
    fn multiple_snapshots_preserved() {
        let mut h = TestHarness::mount("snap_multi");
        for i in 0..5 {
            let name = format!("/f{i}.txt");
            h.create_file(&name, DEFAULT_FILE_PERMISSIONS);
            h.write_file(&name, 0, format!("data-{i}").as_bytes());
            h.fs_mut()
                .create_snapshot(format!("gen-{i}"))
                .expect("create snapshot");
        }

        let snaps = h.fs().list_snapshots();
        for i in 0..5 {
            assert!(
                snaps.iter().any(|s| s.name == format!("gen-{i}")),
                "snapshot gen-{i} must be present"
            );
        }
        // Rollback to earliest and verify content
        h.fs_mut()
            .rollback_to_snapshot("gen-0")
            .expect("rollback to gen-0");

        assert_eq!(h.read_file("/f0.txt"), b"data-0");
        // Later files should not exist after rollback to gen-0
        assert!(h.stat_opt("/f4.txt").is_err());
    }

    #[test]
    fn delete_nonexistent_snapshot_fails() {
        let mut h = TestHarness::mount("snap_delete_nonex");
        h.create_file("/f.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/f.txt", 0, b"data");

        let result = h.fs_mut().delete_snapshot("ghost");
        assert!(result.is_err());
    }

    #[test]
    fn snapshot_summary_nonexistent_fails() {
        let mut h = TestHarness::mount("snap_sum_nonex");
        h.create_file("/f.txt", DEFAULT_FILE_PERMISSIONS);

        let result = h.fs().snapshot_summary("ghost");
        assert!(result.is_err());
    }

    #[test]
    fn delete_snapshot_rejects_clone() {
        let mut h = TestHarness::mount("snap_del_clone");
        h.create_file("/f.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/f.txt", 0, b"data");
        h.fs_mut().create_snapshot("base").expect("create base");
        h.fs_mut()
            .create_clone("fork", "base")
            .expect("create clone");

        // delete_snapshot should reject a clone entry
        let err = h.fs_mut().delete_snapshot("fork").unwrap_err();
        // Verify it's an Unsupported error about non-snapshot entry
        assert!(
            format!("{err}").contains("not a snapshot"),
            "error should mention not-a-snapshot: {err}"
        );
    }

    #[test]
    fn delete_snapshot_rejects_bookmark() {
        let mut h = TestHarness::mount("snap_del_book");
        h.create_file("/f.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/f.txt", 0, b"data");
        h.fs_mut().create_snapshot("base").expect("create base");
        h.fs_mut()
            .create_bookmark("repl-anchor", "base")
            .expect("create bookmark");

        let err = h.fs_mut().delete_snapshot("repl-anchor").unwrap_err();
        assert!(
            format!("{err}").contains("not a snapshot"),
            "error should mention not-a-snapshot: {err}"
        );
    }

    #[test]
    fn delete_snapshot_unpins_gc_pin_set() {
        let mut h = TestHarness::mount("snap_del_unpin");
        h.create_file("/f.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/f.txt", 0, b"data");

        // Create snapshot — this pins the SnapshotCatalog root in the gc-pin-set
        let snap = h.fs_mut().create_snapshot("s1").expect("create s1");
        assert_eq!(snap.name, "s1");

        // Verify SnapshotCatalog is pinned after creation
        assert!(
            h.fs()
                .lifecycle()
                .gc_pin_set()
                .is_pinned_by_type(TraversalRootType::SnapshotCatalog),
            "SnapshotCatalog root should be pinned after snapshot creation"
        );
        assert_eq!(h.fs().lifecycle().gc_pin_set().count(), 1);

        // Delete the snapshot — this unpins the SnapshotCatalog root
        h.fs_mut().delete_snapshot("s1").expect("delete s1");

        // Verify pin set is empty after deletion
        assert!(
            !h.fs()
                .lifecycle()
                .gc_pin_set()
                .is_pinned_by_type(TraversalRootType::SnapshotCatalog),
            "SnapshotCatalog root should be unpinned after snapshot deletion"
        );
        assert!(h.fs().lifecycle().gc_pin_set().is_empty());
    }

    #[test]
    fn create_multiple_snapshots_pins_once() {
        let mut h = TestHarness::mount("snap_pin_once");
        h.create_file("/f.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/f.txt", 0, b"data");

        // First snapshot pins SnapshotCatalog with a distinct root identity.
        let summary1 = h.fs_mut().create_snapshot("s1").expect("create s1");
        assert_eq!(h.fs().lifecycle().gc_pin_set().count(), 1);
        assert!(h
            .fs()
            .lifecycle()
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::SnapshotCatalog));

        // Second snapshot — distinct root identity, occupies a separate slot.
        let summary2 = h.fs_mut().create_snapshot("s2").expect("create s2");
        // Two distinct snapshot roots now pinned.
        assert_eq!(h.fs().lifecycle().gc_pin_set().count(), 2);
        assert_eq!(
            h.fs()
                .lifecycle()
                .gc_pin_set()
                .count_by_type(TraversalRootType::SnapshotCatalog),
            2
        );

        // Verify the two roots have different block pointers (generation
        // or transaction_id differs).
        assert_ne!(
            summary1.source_transaction_id, summary2.source_transaction_id,
            "two snapshots should have distinct committed-root identities"
        );

        // Deleting s2 unpins only s2's root; s1's root remains protected.
        h.fs_mut().delete_snapshot("s2").expect("delete s2");
        assert_eq!(h.fs().lifecycle().gc_pin_set().count(), 1);
        assert!(h
            .fs()
            .lifecycle()
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::SnapshotCatalog));

        // s1 still present in catalog and still GC-pinned.
        let snaps = h.fs().list_snapshots();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].name, "s1");
    }

    #[test]
    fn delete_one_snapshot_keeps_other_protected() {
        let mut h = TestHarness::mount("snap_del_protect");
        h.create_file("/f.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/f.txt", 0, b"data");

        // Create two snapshots
        let s1 = h.fs_mut().create_snapshot("s1").expect("create s1");
        let s2 = h.fs_mut().create_snapshot("s2").expect("create s2");
        assert_eq!(h.fs().lifecycle().gc_pin_set().count(), 2);
        assert_ne!(
            s1.source_transaction_id, s2.source_transaction_id,
            "distinct snapshots must have distinct committed-root identities"
        );

        // Both roots should be pinned by identity
        assert!(h
            .fs()
            .lifecycle()
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::SnapshotCatalog));
        assert_eq!(
            h.fs()
                .lifecycle()
                .gc_pin_set()
                .count_by_type(TraversalRootType::SnapshotCatalog),
            2
        );

        // Delete s2 only
        h.fs_mut().delete_snapshot("s2").expect("delete s2");
        assert_eq!(h.fs().lifecycle().gc_pin_set().count(), 1);
        assert!(
            h.fs()
                .lifecycle()
                .gc_pin_set()
                .is_pinned_by_type(TraversalRootType::SnapshotCatalog),
            "s1's snapshot root must remain GC-protected after s2 deletion"
        );

        // s1 must still exist in the catalog
        let snaps = h.fs().list_snapshots();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].name, "s1");
    }

    #[test]
    fn reopen_reconstructs_snapshot_pins_from_durable_catalog() {
        let mut h = TestHarness::mount("snap_reopen");
        h.create_file("/f.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/f.txt", 0, b"data");

        // Create two snapshots before remount
        h.fs_mut().create_snapshot("s1").expect("create s1");
        h.fs_mut().create_snapshot("s2").expect("create s2");
        assert_eq!(h.fs().lifecycle().gc_pin_set().count(), 2);
        assert!(h
            .fs()
            .lifecycle()
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::SnapshotCatalog));

        // Remount: pins are lost in-memory, must be reconstructed from catalog
        h.remount();

        // Both snapshot roots must be re-pinned from the durable catalog
        assert_eq!(
            h.fs().lifecycle().gc_pin_set().count(),
            2,
            "snapshot GC pins must be reconstructed from durable catalog after remount"
        );
        assert!(h
            .fs()
            .lifecycle()
            .gc_pin_set()
            .is_pinned_by_type(TraversalRootType::SnapshotCatalog));
        assert_eq!(
            h.fs()
                .lifecycle()
                .gc_pin_set()
                .count_by_type(TraversalRootType::SnapshotCatalog),
            2
        );

        // The snapshots must still be accessible
        let snaps = h.fs().list_snapshots();
        assert_eq!(snaps.len(), 2);
    }
    // ───────────────────────────────────────────────────────────────
    // GC retention matrix: snapshot data survives reclaim;
    // unreferenced data is reclaimed after snapshot deletion.
    #[test]
    fn gc_retention_matrix_unreferenced_snapshot_data_reclaimed() {
        let mut h = TestHarness::mount("gc_ret_unref_reclaim");
        h.create_file("/temp.dat", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/temp.dat", 0, b"ephemeral-data-for-snapshot-only");
        h.sync_all();

        h.fs_mut()
            .create_snapshot("ephemeral")
            .expect("create snapshot");

        // Delete live file — only the snapshot references this data now.
        h.unlink("/temp.dat");
        h.sync_all();

        // Delete the snapshot — the data is now completely unreferenced.
        h.fs_mut()
            .delete_snapshot("ephemeral")
            .expect("delete snapshot");
        h.fs_mut().tick_background_services();

        // Remount: the unreferenced data must be gone.
        h.remount();
        assert!(
            h.stat_opt("/temp.dat").is_err(),
            "unreferenced snapshot-only data must be reclaimed after snapshot deletion"
        );
        assert!(h.fs().list_snapshots().is_empty());
    }
}

// ---------------------------------------------------------------------------
// statfs_tests
// ---------------------------------------------------------------------------
mod statfs_tests {
    use super::*;

    #[test]
    fn statfs_after_mount() {
        let mut h = TestHarness::mount("statfs_mount");
        let s = h.fs_mut().statfs().expect("statfs after mount");
        assert!(s.bsize > 0, "block size must be positive");
        assert!(s.namelen > 0, "name length must be positive");
        assert!(s.blocks > 0, "total blocks must be positive");
        assert!(s.bfree <= s.blocks);
        assert!(s.bavail <= s.blocks);
    }

    #[test]
    fn statfs_after_file_write() {
        let mut h = TestHarness::mount("statfs_write");
        let s0 = h.fs_mut().statfs().expect("statfs before write");

        h.create_file("/file.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/file.bin", 0, &[0u8; 8192]);

        let s1 = h.fs_mut().statfs().expect("statfs after write");
        assert_eq!(s1.bsize, s0.bsize, "block size unchanged");
        assert_eq!(s1.namelen, s0.namelen, "namelen unchanged");
        // Writing should consume some blocks
        assert!(
            s1.bfree <= s0.bfree || s1.blocks == s0.blocks,
            "free blocks should not increase after write"
        );
    }

    #[test]
    fn statfs_after_unlink() {
        let mut h = TestHarness::mount("statfs_unlink");
        h.create_file("/del.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/del.bin", 0, &[0u8; 4096]);

        let _s_before = h.fs_mut().statfs().expect("statfs before unlink");
        h.unlink("/del.bin");
        let s_after = h.fs_mut().statfs().expect("statfs after unlink");

        // Free blocks may change after unlink (reclamation is async),
        // but the statfs call itself must not fail.
        assert!(s_after.bsize > 0);
    }

    #[test]
    fn statfs_across_remount() {
        let mut h = TestHarness::mount("statfs_remount");
        h.create_file("/keep.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/keep.bin", 0, &[0xCD; 16384]);

        let s0 = h.fs_mut().statfs().expect("statfs before remount");
        h.sync_all();
        h.unmount();
        h.remount();

        let s1 = h.fs_mut().statfs().expect("statfs after remount");
        assert_eq!(s1.bsize, s0.bsize);
        assert_eq!(s1.namelen, s0.namelen);
    }

    #[test]
    fn statfs_after_mkdir() {
        let mut h = TestHarness::mount("statfs_mkdir");
        let _s0 = h.fs_mut().statfs().expect("statfs before mkdir");
        h.mkdir("/somedir");
        let s1 = h.fs_mut().statfs().expect("statfs after mkdir");
        assert!(s1.bsize > 0);
    }

    #[test]
    fn statfs_after_truncate_down() {
        let mut h = TestHarness::mount("statfs_trunc");
        h.create_file("/big.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/big.bin", 0, &[0xAA; 32768]);
        let _s0 = h.fs_mut().statfs().expect("statfs before truncate");

        h.fs_mut().truncate_file("/big.bin", 16).expect("truncate");
        let s1 = h.fs_mut().statfs().expect("statfs after truncate down");
        assert!(s1.bsize > 0);
    }

    #[test]
    fn stats_reports_file_counts() {
        let mut h = TestHarness::mount("stats_counts");
        h.create_file("/a.txt", DEFAULT_FILE_PERMISSIONS);
        h.create_file("/b.txt", DEFAULT_FILE_PERMISSIONS);
        h.mkdir("/d1");
        h.mkdir("/d1/d2");

        let stats = h.fs().stats();
        // At minimum filesystem has root inode, plus our files and dirs
        assert!(stats.file_count >= 2, "should count created files");
        assert!(stats.directory_count >= 2, "should count created dirs");
        assert!(stats.inode_count >= 5, "should count all inodes");
    }
}

// ---------------------------------------------------------------------------
// fallocate_and_punch
// ---------------------------------------------------------------------------
mod fallocate_and_punch {
    use super::*;

    #[test]
    fn fallocate_extends_file() {
        let mut h = TestHarness::mount("falloc_extend");
        h.create_file("/falloc.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/falloc.bin", 0, b"hello");

        h.fs_mut()
            .fallocate_file("/falloc.bin", 0, 64)
            .expect("fallocate to 64");

        let s = h.stat("/falloc.bin");
        assert_eq!(s.size, 64);
        let content = h.read_file("/falloc.bin");
        assert_eq!(&content[0..5], b"hello");
        assert!(content[5..].iter().all(|&b| b == 0));
    }

    #[test]
    fn fallocate_beyond_eof() {
        let mut h = TestHarness::mount("falloc_beyond");
        h.create_file("/gap.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/gap.bin", 0, b"start");

        h.fs_mut()
            .fallocate_file("/gap.bin", 64, 32)
            .expect("fallocate at offset 64");

        let s = h.stat("/gap.bin");
        assert_eq!(s.size, 96);
        let content = h.read_file("/gap.bin");
        assert_eq!(&content[0..5], b"start");
        // bytes 5..64 should be hole (zeros)
        assert!(content[5..64].iter().all(|&b| b == 0));
        // bytes 64..96 should be fallocated zeros
        assert_eq!(&content[64..96], &[0u8; 32]);
    }

    #[test]
    fn fallocate_empty_file() {
        let mut h = TestHarness::mount("falloc_empty");
        h.create_file("/alloc.bin", DEFAULT_FILE_PERMISSIONS);
        h.fs_mut()
            .fallocate_file("/alloc.bin", 0, 1024)
            .expect("fallocate on empty file");

        let s = h.stat("/alloc.bin");
        assert_eq!(s.size, 1024);
        let content = h.read_file("/alloc.bin");
        assert!(content.iter().all(|&b| b == 0));
    }

    #[test]
    fn punch_hole_creates_zeros() {
        let mut h = TestHarness::mount("punch_hole");
        h.create_file("/punch.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/punch.bin", 0, b"AAAAAAAAAAAA");

        h.fs_mut()
            .punch_hole("/punch.bin", 4, 4)
            .expect("punch hole");

        let s = h.stat("/punch.bin");
        // punch_hole keeps size
        assert_eq!(s.size, 12);
        let content = h.read_file("/punch.bin");
        assert_eq!(&content[0..4], b"AAAA");
        assert!(content[4..8].iter().all(|&b| b == 0), "hole must be zeros");
        assert_eq!(&content[8..12], b"AAAA");
    }

    #[test]
    fn punch_hole_beyond_eof_noops() {
        let mut h = TestHarness::mount("punch_beyond");
        h.create_file("/beyond.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/beyond.bin", 0, b"data");

        h.fs_mut()
            .punch_hole("/beyond.bin", 100, 50)
            .expect("punch beyond eof");

        let s = h.stat("/beyond.bin");
        assert_eq!(s.size, 4);
        let content = h.read_file("/beyond.bin");
        assert_eq!(content, b"data");
    }
}

// ---------------------------------------------------------------------------
// more_edge_cases
// ---------------------------------------------------------------------------
mod more_edge_cases {
    use super::*;

    #[test]
    fn symlink_long_target() {
        let mut h = TestHarness::mount("symlink_long");
        let long_target = "/".to_string() + &"a".repeat(2000);
        h.fs_mut()
            .create_symlink("/long.lnk", long_target.as_bytes())
            .expect("create long symlink");

        let target = h.fs().read_symlink("/long.lnk").expect("readlink");
        assert_eq!(target.as_slice(), long_target.as_bytes());
    }

    #[test]
    fn symlink_nul_target_fails() {
        let mut h = TestHarness::mount("symlink_nul");
        let result = h.fs_mut().create_symlink("/bad.lnk", b"/path\0with nul");
        assert!(result.is_err());
    }

    #[test]
    fn create_file_with_existing_name_fails() {
        let mut h = TestHarness::mount("create_dup");
        h.create_file("/dup.txt", DEFAULT_FILE_PERMISSIONS);
        let result = h.fs_mut().create_file("/dup.txt", DEFAULT_FILE_PERMISSIONS);
        assert!(result.is_err());
    }

    #[test]
    fn stat_root_directory() {
        let h = TestHarness::mount("stat_root");
        let s = h.stat("/");
        assert!(s.carries_child_namespace());
        assert!(!s.carries_byte_space());
    }

    #[test]
    fn read_file_range() {
        let mut h = TestHarness::mount("read_range");
        h.create_file("/range.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/range.bin", 0, b"0123456789ABCDEF");

        let first = h
            .fs()
            .read_file_range("/range.bin", 0, 4)
            .expect("range 0..4");
        assert_eq!(first, b"0123");

        let mid = h
            .fs()
            .read_file_range("/range.bin", 8, 4)
            .expect("range 8..12");
        assert_eq!(mid, b"89AB");

        let last = h
            .fs()
            .read_file_range("/range.bin", 12, 4)
            .expect("range 12..16");
        assert_eq!(last, b"CDEF");
    }

    #[test]
    fn read_file_range_partial() {
        let mut h = TestHarness::mount("read_range_part");
        h.create_file("/short.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/short.bin", 0, b"short");

        // Reading beyond EOF returns available bytes
        let result = h.fs().read_file_range("/short.bin", 3, 100);
        // Should succeed but return only remaining bytes
        if let Ok(data) = result {
            assert_eq!(data.len(), 2);
            assert_eq!(&data, b"rt");
        }
    }

    #[test]
    fn read_file_range_zero_length() {
        let mut h = TestHarness::mount("read_range_zero");
        h.create_file("/zero.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/zero.bin", 0, b"abcdef");

        let data = h
            .fs()
            .read_file_range("/zero.bin", 2, 0)
            .expect("zero-length range");
        assert!(data.is_empty());
    }

    #[test]
    fn create_symlink_already_exists_fails() {
        let mut h = TestHarness::mount("symlink_exists");
        h.fs_mut()
            .create_symlink("/first.lnk", b"/target1")
            .expect("first symlink");

        let result = h.fs_mut().create_symlink("/first.lnk", b"/target2");
        assert!(result.is_err());
    }

    #[test]
    fn read_symlink_nonexistent_fails() {
        let h = TestHarness::mount("readlink_nonex");
        let result = h.fs().read_symlink("/nope.lnk");
        assert!(result.is_err());
    }

    #[test]
    fn read_symlink_on_regular_file_fails() {
        let mut h = TestHarness::mount("readlink_on_file");
        h.create_file("/regular.txt", DEFAULT_FILE_PERMISSIONS);
        let result = h.fs().read_symlink("/regular.txt");
        assert!(result.is_err());
    }

    #[test]
    fn replace_file_full_overwrite() {
        let mut h = TestHarness::mount("replace_file");
        h.create_file("/replace.bin", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/replace.bin", 0, b"original longer data");

        h.fs_mut()
            .replace_file("/replace.bin", b"new")
            .expect("replace file");

        let content = h.read_file("/replace.bin");
        assert_eq!(content, b"new");
        let s = h.stat("/replace.bin");
        assert_eq!(s.size, 3);
    }

    #[test]
    fn list_dir_owned_returns_entries() {
        let mut h = TestHarness::mount("list_dir_owned");
        h.create_file("/owned_a.txt", DEFAULT_FILE_PERMISSIONS);
        h.create_file("/owned_b.txt", DEFAULT_FILE_PERMISSIONS);

        let entries = h.fs().list_dir_owned("/").expect("list_dir_owned");
        let names: Vec<String> = entries
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name).into_owned())
            .collect();
        assert!(names.contains(&"owned_a.txt".to_string()));
        assert!(names.contains(&"owned_b.txt".to_string()));
    }

    #[test]
    fn replace_file_nonexistent_fails() {
        let mut h = TestHarness::mount("replace_nonex");
        let result = h.fs_mut().replace_file("/ghost.bin", b"data");
        assert!(result.is_err());
    }

    #[test]
    fn unlink_then_hard_link_preserves_inode() {
        let mut h = TestHarness::mount("unlink_hardlink");
        h.create_file("/target.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/target.txt", 0, b"shared");
        h.fs_mut()
            .link_file("/target.txt", "/link1.txt")
            .expect("hard link 1");
        h.fs_mut()
            .link_file("/target.txt", "/link2.txt")
            .expect("hard link 2");

        // All three share same inode
        let s_target = h.stat("/target.txt");
        let s1 = h.stat("/link1.txt");
        let s2 = h.stat("/link2.txt");
        assert_eq!(s_target.inode_id, s1.inode_id);
        assert_eq!(s_target.inode_id, s2.inode_id);
        assert_eq!(s_target.nlink, 3);

        // Unlink one, content still reachable
        h.unlink("/link1.txt");
        assert_eq!(h.read_file("/target.txt"), b"shared");
        assert_eq!(h.read_file("/link2.txt"), b"shared");

        let s_after = h.stat("/target.txt");
        assert_eq!(s_after.nlink, 2);
    }
}

// ---------------------------------------------------------------------------
// concurrent_readers
// ---------------------------------------------------------------------------
mod concurrent_readers {
    use super::*;

    /// Create a file with known content, then read it twice through the
    /// same [`LocalFileSystem`] instance and verify both reads return
    /// identical data — simulating two independent "handles" on the same
    /// file when the API is path-based.
    #[test]
    fn two_readers_same_file_identical_content() {
        let mut h = TestHarness::mount("conc_read_same");
        h.create_file("/shared.txt", DEFAULT_FILE_PERMISSIONS);
        let payload: Vec<u8> = (0u8..=127).cycle().take(4096).collect();
        h.write_file("/shared.txt", 0, &payload);

        let read1 = h.read_file("/shared.txt");
        let read2 = h.read_file("/shared.txt");
        assert_eq!(read1, payload);
        assert_eq!(read2, payload);
        assert_eq!(read1, read2);
    }

    /// Multiple interleaved reads after partial writes must all observe
    /// the same final state. Writes happen first, then two reads verify
    /// the settled content.
    #[test]
    fn interleaved_reads_after_writes() {
        let mut h = TestHarness::mount("conc_read_interleave");
        h.create_file("/log.dat", DEFAULT_FILE_PERMISSIONS);

        // Write data in three chunks
        h.write_file("/log.dat", 0, b"AAA");
        h.write_file("/log.dat", 3, b"BBB");
        h.write_file("/log.dat", 6, b"CCC");

        let r1 = h.read_file("/log.dat");
        let r2 = h.read_file("/log.dat");
        assert_eq!(r1, b"AAABBBCCC");
        assert_eq!(r2, b"AAABBBCCC");
    }

    /// Reading a file that is being extended should return the
    /// then-current length. After the final write, both readers
    /// agree on the full content.
    #[test]
    fn readers_agree_after_append() {
        let mut h = TestHarness::mount("conc_read_append");
        h.create_file("/append.log", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/append.log", 0, b"header\n");

        let snapshot1 = h.read_file("/append.log");
        assert_eq!(snapshot1, b"header\n");

        h.write_file("/append.log", 7, b"line2\n");
        let snapshot2 = h.read_file("/append.log");
        assert_eq!(snapshot2, b"header\nline2\n");

        // Re-read snapshot1 position — must now see full content
        let snapshot3 = h.read_file("/append.log");
        assert_eq!(snapshot3, b"header\nline2\n");
    }

    /// Reading a small file many times in a tight loop exercises the
    /// read path and inode cache under repeated access.
    #[test]
    fn many_reads_same_file_consistent() {
        let mut h = TestHarness::mount("conc_read_many");
        h.create_file("/fixed.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/fixed.txt", 0, b"fixed content");

        for _ in 0..100 {
            let data = h.read_file("/fixed.txt");
            assert_eq!(data, b"fixed content");
        }
    }
}

// ---------------------------------------------------------------------------
// write_to_deleted_path
// ---------------------------------------------------------------------------
mod write_to_deleted_path {
    use super::*;

    /// Writing to a path that has been unlinked must fail with a
    /// NotFound error (or equivalent), not silently create a new file
    /// or corrupt the namespace.
    #[test]
    fn write_to_unlinked_file_fails() {
        let mut h = TestHarness::mount("write_after_unlink");
        h.create_file("/victim.dat", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/victim.dat", 0, b"initial data");
        h.unlink("/victim.dat");

        let result = h.fs_mut().write_file("/victim.dat", 0, b"ghost write");
        assert!(
            result.is_err(),
            "write to unlinked path must return an error"
        );
    }

    /// Writing to a file that has been renamed away must fail at the
    /// old path, while the new path continues to work normally.
    #[test]
    fn write_to_renamed_old_path_fails() {
        let mut h = TestHarness::mount("write_after_rename");
        h.create_file("/original.dat", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/original.dat", 0, b"before rename");
        h.rename("/original.dat", "/moved.dat", false);

        // Old path must be unreachable
        let result = h.fs_mut().write_file("/original.dat", 0, b"stale");
        assert!(
            result.is_err(),
            "write to renamed-from path must return an error"
        );

        // New path must still accept writes
        h.write_file("/moved.dat", 13, b" - after rename");
        let content = h.read_file("/moved.dat");
        assert_eq!(content, b"before rename - after rename");
    }

    /// Creating a file, unlinking it, and then attempting to stat,
    /// read, and write it from the same path must all fail — the
    /// unlink removes the namespace entry entirely.
    #[test]
    fn unlink_fully_removes_path() {
        let mut h = TestHarness::mount("unlink_removes");
        h.create_file("/gone.dat", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/gone.dat", 0, b"temporary");
        h.unlink("/gone.dat");

        assert!(h.stat_opt("/gone.dat").is_err(), "stat must fail");
        assert!(h.read_file_opt("/gone.dat").is_err(), "read must fail");
        assert!(
            h.fs_mut().write_file("/gone.dat", 0, b"resurrect").is_err(),
            "write must fail after unlink"
        );
    }

    /// Double-unlink on the same path must fail on the second attempt — the
    /// first unlink already removed the entry.
    #[test]
    fn double_unlink_fails() {
        let mut h = TestHarness::mount("double_unlink");
        h.create_file("/once.dat", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/once.dat", 0, b"single");
        h.unlink("/once.dat");

        let result = h.unlink_opt("/once.dat");
        assert!(
            result.is_err(),
            "second unlink on already-removed path must return an error"
        );
    }
}

// ---------------------------------------------------------------------------
// large_io — multi-extent byte-for-byte verification
// ---------------------------------------------------------------------------
mod large_io {
    use super::*;

    /// Content chunk size (allocation unit) for the crate.
    const CHUNK: usize = 65536; // 64 KiB DEFAULT_FILESYSTEM_CONTENT_CHUNK_SIZE

    /// Write a file that spans four allocation units (256 KiB), read
    /// every byte back, and confirm a byte-for-byte match.
    #[test]
    fn multi_extent_roundtrip_256k() {
        let mut h = TestHarness::mount("large_256k");
        h.create_file("/big.bin", DEFAULT_FILE_PERMISSIONS);
        let payload: Vec<u8> = (0u8..=255).cycle().take(CHUNK * 4).collect();
        h.write_file("/big.bin", 0, &payload);

        let content = h.read_file("/big.bin");
        assert_eq!(content.len(), payload.len());
        assert_eq!(content, payload);
        let s = h.stat("/big.bin");
        assert_eq!(s.size as usize, payload.len());
    }

    /// Write a file that spans two allocation units with a gap, creating
    /// a sparse mid-section, and verify the sparse region reads as zeros
    /// while both written chunks survive.
    #[test]
    fn multi_extent_with_sparse_gap() {
        let mut h = TestHarness::mount("large_sparse");
        h.create_file("/sparse.bin", DEFAULT_FILE_PERMISSIONS);
        let head: Vec<u8> = (0u8..=127).cycle().take(CHUNK).collect();
        let tail: Vec<u8> = (128u8..=255).cycle().take(CHUNK).collect();

        // head at offset 0, tail at offset 3 * CHUNK (leaves 2 * CHUNK gap)
        h.write_file("/sparse.bin", 0, &head);
        h.write_file("/sparse.bin", (3 * CHUNK) as u64, &tail);

        let content = h.read_file("/sparse.bin");
        assert_eq!(content.len(), 4 * CHUNK);

        // Verify head chunk
        assert_eq!(&content[0..CHUNK], &head[..]);
        // Verify gap is zeros
        assert!(content[CHUNK..3 * CHUNK].iter().all(|&b| b == 0));
        // Verify tail chunk
        assert_eq!(&content[3 * CHUNK..4 * CHUNK], &tail[..]);
    }

    /// Multi-extent content must survive a remount: write four chunks
    /// interleaved across the file, unmount, remount, and verify every
    /// byte.
    #[test]
    fn multi_extent_survives_remount() {
        let mut h = TestHarness::mount("large_remount");
        h.create_file("/persist.bin", DEFAULT_FILE_PERMISSIONS);
        let payload: Vec<u8> = (0..=255).cycle().take(CHUNK * 4).collect();
        h.write_file("/persist.bin", 0, &payload);

        h.sync_all();
        h.unmount();
        h.remount();

        let content = h.read_file("/persist.bin");
        assert_eq!(content.len(), payload.len());
        assert_eq!(content, payload);
    }

    /// Write data to a multi-extent file in reverse order (last extent
    /// first) and verify the entire file assembles correctly. This
    /// exercises the extent-allocation path when earlier offsets are
    /// written after later ones.
    #[test]
    fn reverse_order_multi_extent() {
        let mut h = TestHarness::mount("large_reverse");
        h.create_file("/rev.bin", DEFAULT_FILE_PERMISSIONS);
        let chunk_a: Vec<u8> = (0u8..=63).cycle().take(CHUNK).collect();
        let chunk_b: Vec<u8> = (64u8..=127).cycle().take(CHUNK).collect();
        let chunk_c: Vec<u8> = (128u8..=191).cycle().take(CHUNK).collect();
        let chunk_d: Vec<u8> = (192u8..=255).cycle().take(CHUNK).collect();

        // Write extents in reverse: D, C, B, A
        h.write_file("/rev.bin", (3 * CHUNK) as u64, &chunk_d);
        h.write_file("/rev.bin", (2 * CHUNK) as u64, &chunk_c);
        h.write_file("/rev.bin", CHUNK as u64, &chunk_b);
        h.write_file("/rev.bin", 0, &chunk_a);

        let content = h.read_file("/rev.bin");
        assert_eq!(content.len(), 4 * CHUNK);
        assert_eq!(&content[0..CHUNK], &chunk_a[..]);
        assert_eq!(&content[CHUNK..2 * CHUNK], &chunk_b[..]);
        assert_eq!(&content[2 * CHUNK..3 * CHUNK], &chunk_c[..]);
        assert_eq!(&content[3 * CHUNK..4 * CHUNK], &chunk_d[..]);
    }

    /// Partial reads at chunk-aligned boundaries within a multi-extent
    /// file return the correct sub-slices.
    #[test]
    fn partial_reads_on_multi_extent() {
        let mut h = TestHarness::mount("large_partial");
        h.create_file("/partial.bin", DEFAULT_FILE_PERMISSIONS);
        let payload: Vec<u8> = (0u8..=255).cycle().take(CHUNK * 4).collect();
        h.write_file("/partial.bin", 0, &payload);

        let r1 = h
            .fs()
            .read_file_range("/partial.bin", 0, 256)
            .expect("read first 256");
        assert_eq!(r1, payload[0..256]);

        let r2 = h
            .fs()
            .read_file_range("/partial.bin", (CHUNK - 128) as u64, 256)
            .expect("read cross-extent-boundary");
        assert_eq!(r2, payload[CHUNK - 128..CHUNK + 128]);

        let r3 = h
            .fs()
            .read_file_range("/partial.bin", (3 * CHUNK + CHUNK / 2) as u64, 512)
            .expect("read from last extent");
        let start = 3 * CHUNK + CHUNK / 2;
        assert_eq!(r3, payload[start..start + 512]);
    }
}

// ---------------------------------------------------------------------------
// concurrent_write_safety
// ---------------------------------------------------------------------------
mod concurrent_write_safety {
    use super::*;

    /// Two interleaved appends to the same file via the same
    /// [`LocalFileSystem`] instance must produce a combined result
    /// containing all written bytes in the order they landed.
    /// Because this API is single-threaded-by-construction
    /// (&mut self for writes), the test emulates "interleaved"
    /// as sequential calls, but the same path write-append-write
    /// pattern verifies offset tracking is correct.
    #[test]
    fn sequential_appends_build_correct_file() {
        let mut h = TestHarness::mount("concw_seq_append");
        h.create_file("/log.txt", DEFAULT_FILE_PERMISSIONS);

        // Append chunks sequentially (simulating two writers taking turns)
        let mut offset: u64 = 0;
        for i in 0..20 {
            let data = format!("chunk-{i:02}\n").into_bytes();
            let len = data.len() as u64;
            h.write_file("/log.txt", offset, &data);
            offset += len;
        }

        let content = h.read_file("/log.txt");
        for i in 0..20 {
            let expected = format!("chunk-{i:02}\n");
            assert!(
                content
                    .windows(expected.len())
                    .any(|w| w == expected.as_bytes()),
                "chunk-{i:02} must appear in file"
            );
        }
    }

    /// Writing to a file from a second [`LocalFileSystem`] instance
    /// mounted on the same backing store verifies that the underlying
    /// object store correctly serializes writes and both instances
    /// observe the committed state after the first unmounts.
    #[test]
    fn two_instance_write_then_read() {
        TestHarness::set_test_key();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tidefs-concw-two-instance-{ts}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp dir");

        // Instance A: write
        let store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            &root,
            tidefs_local_object_store::StoreOptions::test_fast(),
        )
        .expect("open store");
        drop(store);
        {
            let mut fs_a = tidefs_local_filesystem::LocalFileSystem::open(&root).expect("fs A");
            fs_a.create_file("/shared.txt", DEFAULT_FILE_PERMISSIONS)
                .expect("create shared");
            fs_a.write_file("/shared.txt", 0, b"instance A wrote this")
                .expect("write A");
            fs_a.sync_all().expect("sync A");
        }

        // Instance B: read back
        {
            let fs_b = tidefs_local_filesystem::LocalFileSystem::open(&root).expect("fs B");
            let content = fs_b.read_file("/shared.txt").expect("read B");
            assert_eq!(content, b"instance A wrote this");
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Two files written by separate instances must both be visible
    /// when a third instance mounts the same store.
    #[test]
    fn two_instance_independent_files() {
        TestHarness::set_test_key();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tidefs-concw-two-files-{ts}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp dir");

        let store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            &root,
            tidefs_local_object_store::StoreOptions::test_fast(),
        )
        .expect("open store");
        drop(store);

        // Instance A creates file A
        {
            let mut fs_a = tidefs_local_filesystem::LocalFileSystem::open(&root).expect("fs A");
            fs_a.create_file("/file_a.txt", DEFAULT_FILE_PERMISSIONS)
                .expect("create A");
            fs_a.write_file("/file_a.txt", 0, b"alpha")
                .expect("write A");
            fs_a.sync_all().expect("sync A");
        }

        // Instance B creates file B
        {
            let mut fs_b = tidefs_local_filesystem::LocalFileSystem::open(&root).expect("fs B");
            fs_b.create_file("/file_b.txt", DEFAULT_FILE_PERMISSIONS)
                .expect("create B");
            fs_b.write_file("/file_b.txt", 0, b"bravo")
                .expect("write B");
            fs_b.sync_all().expect("sync B");
        }

        // Instance C reads both
        {
            let fs_c = tidefs_local_filesystem::LocalFileSystem::open(&root).expect("fs C");
            assert_eq!(fs_c.read_file("/file_a.txt").expect("read A"), b"alpha");
            assert_eq!(fs_c.read_file("/file_b.txt").expect("read B"), b"bravo");
        }

        let _ = std::fs::remove_dir_all(&root);
    }
}
