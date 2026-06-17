//! Persistence round-trip validation: inode attributes, directory entries,
//! and metadata dirty/clean tracking across mount cycles.
//!
//! Exercises the full lifecycle: open → mutate → commit → close → reopen → verify.
//! Tests inode attribute survival (mode, uid, gid, nlink, metadata_version,
//! data_version), directory entry survival (names, inode IDs, generations),
//! and dirty/clean state tracking through commit boundaries.

use std::env;
use std::fs;

use tidefs_local_filesystem::{
    LocalFileSystem, DEFAULT_DIRECTORY_PERMISSIONS, DEFAULT_FILE_PERMISSIONS,
};
use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

// ---------------------------------------------------------------------------
// PersistenceHarness
// ---------------------------------------------------------------------------

/// Tempdir-backed filesystem harness that owns the lifecycle from creation
/// through teardown. Mirrors `TestHarness` from integration_validation.rs
/// but focused on metadata persistence assertions.
struct PersistenceHarness {
    root: std::path::PathBuf,
    fs: Option<LocalFileSystem>,
}

impl PersistenceHarness {
    fn mount(label: &str) -> Self {
        Self::set_test_key();

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "tidefs-persist-{label}-{ts}-{}",
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

    fn sync_and_remount(&mut self) {
        self.fs_mut().sync_all().expect("sync_all");
        self.fs = None;
        self.fs = Some(LocalFileSystem::open(&self.root).expect("reopen filesystem"));
    }

    fn create_file(
        &mut self,
        path: &str,
        permissions: u32,
    ) -> tidefs_local_filesystem::InodeRecord {
        self.fs_mut()
            .create_file(path, permissions)
            .unwrap_or_else(|e| panic!("create_file {path}: {e:?}"))
    }

    fn create_dir(&mut self, path: &str, permissions: u32) -> tidefs_local_filesystem::InodeRecord {
        self.fs_mut()
            .create_dir(path, permissions)
            .unwrap_or_else(|e| panic!("create_dir {path}: {e:?}"))
    }

    fn write_file(&mut self, path: &str, offset: u64, data: &[u8]) {
        self.fs_mut()
            .write_file(path, offset, data)
            .unwrap_or_else(|e| panic!("write_file {path}: {e:?}"));
    }

    fn read_file(&self, path: &str) -> Vec<u8> {
        self.fs()
            .read_file(path)
            .unwrap_or_else(|e| panic!("read_file {path}: {e:?}"))
    }

    fn stat(&self, path: &str) -> tidefs_local_filesystem::InodeRecord {
        self.fs()
            .stat(path)
            .unwrap_or_else(|e| panic!("stat {path}: {e:?}"))
    }

    fn list_dir(&self, path: &str) -> Vec<tidefs_local_filesystem::NamespaceEntry> {
        self.fs()
            .list_dir(path)
            .unwrap_or_else(|e| panic!("list_dir {path}: {e:?}"))
    }

    fn link_file(&mut self, existing: &str, new: &str) -> tidefs_local_filesystem::InodeRecord {
        self.fs_mut()
            .link_file(existing, new)
            .unwrap_or_else(|e| panic!("link_file {existing} -> {new}: {e:?}"))
    }

    fn create_symlink(
        &mut self,
        path: &str,
        target: &[u8],
    ) -> tidefs_local_filesystem::InodeRecord {
        self.fs_mut()
            .create_symlink(path, target)
            .unwrap_or_else(|e| panic!("create_symlink {path}: {e:?}"))
    }

    fn read_symlink(&self, path: &str) -> Vec<u8> {
        self.fs()
            .read_symlink(path)
            .unwrap_or_else(|e| panic!("read_symlink {path}: {e:?}"))
    }

    fn has_dirty_metadata(&self) -> bool {
        self.fs().has_dirty_metadata()
    }

    fn commit(&mut self) {
        self.fs_mut().commit().expect("commit");
    }

    fn sync_all(&mut self) {
        self.fs_mut().sync_all().expect("sync_all");
    }

    /// Close the filesystem and return the root path without cleanup.
    /// The caller is responsible for cleanup.
    fn into_root(mut self) -> std::path::PathBuf {
        self.fs.take();
        let root = self.root.clone();
        // Prevent Drop from cleaning up
        std::mem::forget(self);
        root
    }
}

impl Drop for PersistenceHarness {
    fn drop(&mut self) {
        self.fs.take();
        let _ = fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------------------
// 1. Inode attribute survival
// ---------------------------------------------------------------------------
mod inode_attribute_survival {
    use super::*;

    #[test]
    fn mode_survives_remount() {
        let mut h = PersistenceHarness::mount("mode_survive");
        // Create files with distinct permission modes
        let r1 = h.create_file("/r--------.txt", 0o400);
        let r2 = h.create_file("/rw-------.txt", 0o600);
        let r3 = h.create_file("/rwx------.txt", 0o700);
        let r4 = h.create_file("/rw-r--r--.txt", 0o644);
        assert_eq!(r1.mode & 0o777, 0o400);
        assert_eq!(r2.mode & 0o777, 0o600);
        assert_eq!(r3.mode & 0o777, 0o700);
        assert_eq!(r4.mode & 0o777, 0o644);

        h.sync_and_remount();

        let s1 = h.stat("/r--------.txt");
        let s2 = h.stat("/rw-------.txt");
        let s3 = h.stat("/rwx------.txt");
        let s4 = h.stat("/rw-r--r--.txt");
        // Permission bits must survive
        assert_eq!(s1.mode & 0o777, 0o400);
        assert_eq!(s2.mode & 0o777, 0o600);
        assert_eq!(s3.mode & 0o777, 0o700);
        assert_eq!(s4.mode & 0o777, 0o644);
        // File type bits must be preserved
        assert!(s1.carries_byte_space() && !s1.carries_child_namespace());
        assert!(s2.carries_byte_space() && !s2.carries_child_namespace());
        assert!(s3.carries_byte_space() && !s3.carries_child_namespace());
        assert!(s4.carries_byte_space() && !s4.carries_child_namespace());
    }

    #[test]
    fn uid_gid_survives_remount() {
        let mut h = PersistenceHarness::mount("uid_gid_survive");
        // uid and gid both default to 0 in the current implementation
        let created = h.create_file("/owned.txt", DEFAULT_FILE_PERMISSIONS);
        assert_eq!(created.uid, 0);
        assert_eq!(created.gid, 0);

        h.sync_and_remount();

        let s = h.stat("/owned.txt");
        assert_eq!(s.uid, 0, "uid must survive remount");
        assert_eq!(s.gid, 0, "gid must survive remount");
    }

    #[test]
    fn metadata_version_survives_remount() {
        let mut h = PersistenceHarness::mount("metaver_survive");
        let created = h.create_file("/versioned.txt", DEFAULT_FILE_PERMISSIONS);
        let initial_mv = created.metadata_version;
        assert!(initial_mv > 0, "metadata_version must be set at creation");

        // Write to bump data_version (metadata_version may also change)
        h.write_file("/versioned.txt", 0, b"some data");
        let after_write = h.stat("/versioned.txt");
        let dv = after_write.data_version;
        let mv = after_write.metadata_version;

        h.sync_and_remount();

        let s = h.stat("/versioned.txt");
        assert_eq!(s.data_version, dv, "data_version must survive remount");
        assert_eq!(
            s.metadata_version, mv,
            "metadata_version must survive remount"
        );
    }

    #[test]
    fn inode_id_and_generation_survive_remount() {
        let mut h = PersistenceHarness::mount("inode_id_survive");
        let created = h.create_file("/ident.txt", DEFAULT_FILE_PERMISSIONS);
        let original_inode_id = created.inode_id;
        let original_generation = created.generation;

        h.sync_and_remount();

        let s = h.stat("/ident.txt");
        assert_eq!(s.inode_id, original_inode_id);
        assert_eq!(s.generation, original_generation);
    }

    #[test]
    fn nlink_survives_remount_after_hard_link() {
        let mut h = PersistenceHarness::mount("nlink_survive");
        h.create_file("/original.txt", DEFAULT_FILE_PERMISSIONS);
        let s0 = h.stat("/original.txt");
        assert_eq!(s0.nlink, 1);

        h.link_file("/original.txt", "/alias.txt");
        let s1 = h.stat("/original.txt");
        assert_eq!(s1.nlink, 2);

        h.sync_and_remount();

        let s2 = h.stat("/original.txt");
        assert_eq!(s2.nlink, 2, "nlink must survive remount after hard link");
        // Both paths must still resolve to the same inode
        let alias = h.stat("/alias.txt");
        assert_eq!(alias.inode_id, s2.inode_id);
    }

    #[test]
    fn dir_mode_survives_remount() {
        let mut h = PersistenceHarness::mount("dir_mode_survive");
        let created = h.create_dir("/mydir", 0o750);
        assert_eq!(created.mode & 0o777, 0o750);
        assert!(created.carries_child_namespace());

        h.sync_and_remount();

        let s = h.stat("/mydir");
        assert_eq!(s.mode & 0o777, 0o750);
        assert!(s.carries_child_namespace());
    }

    #[test]
    fn size_survives_remount() {
        let mut h = PersistenceHarness::mount("size_survive");
        h.create_file("/sized.bin", DEFAULT_FILE_PERMISSIONS);
        assert_eq!(h.stat("/sized.bin").size, 0);

        let data = b"persistent size check data block";
        h.write_file("/sized.bin", 0, data);
        let before = h.stat("/sized.bin");
        assert_eq!(before.size, data.len() as u64);

        h.sync_and_remount();

        let after = h.stat("/sized.bin");
        assert_eq!(after.size, before.size);
        assert_eq!(after.size, data.len() as u64);
        assert_eq!(h.read_file("/sized.bin"), data);
    }
}

// ---------------------------------------------------------------------------
// 2. Directory entry survival
// ---------------------------------------------------------------------------
mod directory_entry_survival {
    use super::*;

    #[test]
    fn flat_directory_entries_survive_remount() {
        let mut h = PersistenceHarness::mount("flat_dir_survive");
        let file_a = h.create_file("/a.txt", DEFAULT_FILE_PERMISSIONS);
        let file_b = h.create_file("/b.txt", DEFAULT_FILE_PERMISSIONS);
        let file_c = h.create_file("/c.txt", DEFAULT_FILE_PERMISSIONS);

        h.sync_and_remount();

        let entries = h.list_dir("/");
        let names: Vec<String> = entries.iter().map(|e| e.name_lossy()).collect();
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));
        assert!(names.contains(&"c.txt".to_string()));

        // Verify each entry's inode_id and generation match the original
        for entry in &entries {
            match entry.name_lossy().as_str() {
                "a.txt" => {
                    assert_eq!(entry.inode_id, file_a.inode_id);
                    assert_eq!(entry.generation, file_a.generation);
                }
                "b.txt" => {
                    assert_eq!(entry.inode_id, file_b.inode_id);
                    assert_eq!(entry.generation, file_b.generation);
                }
                "c.txt" => {
                    assert_eq!(entry.inode_id, file_c.inode_id);
                    assert_eq!(entry.generation, file_c.generation);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn deep_hierarchy_survives_remount() {
        let mut h = PersistenceHarness::mount("deep_hier_survive");
        h.create_dir("/l1", DEFAULT_DIRECTORY_PERMISSIONS);
        h.create_dir("/l1/l2", DEFAULT_DIRECTORY_PERMISSIONS);
        h.create_dir("/l1/l2/l3", DEFAULT_DIRECTORY_PERMISSIONS);
        let leaf_file = h.create_file("/l1/l2/l3/deep.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/l1/l2/l3/deep.txt", 0, b"deep content");

        h.sync_and_remount();

        // Verify the full hierarchy
        let root = h.list_dir("/");
        let root_names: Vec<String> = root.iter().map(|e| e.name_lossy()).collect();
        assert!(root_names.contains(&"l1".to_string()));

        let l1 = h.list_dir("/l1");
        let l1_names: Vec<String> = l1.iter().map(|e| e.name_lossy()).collect();
        assert!(l1_names.contains(&"l2".to_string()));

        let l2 = h.list_dir("/l1/l2");
        let l2_names: Vec<String> = l2.iter().map(|e| e.name_lossy()).collect();
        assert!(l2_names.contains(&"l3".to_string()));

        let l3 = h.list_dir("/l1/l2/l3");
        let l3_names: Vec<String> = l3.iter().map(|e| e.name_lossy()).collect();
        assert!(l3_names.contains(&"deep.txt".to_string()));

        // Verify the leaf file's content and inode identity
        let s = h.stat("/l1/l2/l3/deep.txt");
        assert_eq!(s.inode_id, leaf_file.inode_id);
        assert_eq!(s.size, b"deep content".len() as u64);
        assert_eq!(h.read_file("/l1/l2/l3/deep.txt"), b"deep content");
    }

    #[test]
    fn directory_entries_preserve_kind() {
        let mut h = PersistenceHarness::mount("dir_kind_survive");
        h.create_file("/file.txt", DEFAULT_FILE_PERMISSIONS);
        h.create_dir("/subdir", DEFAULT_DIRECTORY_PERMISSIONS);

        h.sync_and_remount();

        let entries = h.list_dir("/");
        for entry in &entries {
            match entry.name_lossy().as_str() {
                "file.txt" => {
                    assert!(entry.facets().carries_byte_space());
                    assert!(!entry.facets().carries_child_namespace());
                }
                "subdir" => {
                    assert!(entry.facets().carries_child_namespace());
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Multi-inode attribute update
// ---------------------------------------------------------------------------
mod multi_inode_attribute_update {
    use super::*;

    #[test]
    fn only_modified_inodes_persist_changes() {
        let mut h = PersistenceHarness::mount("multi_inode_mod");

        // Create three files
        let _f1 = h.create_file("/static.txt", DEFAULT_FILE_PERMISSIONS);
        let _f2 = h.create_file("/modified.txt", DEFAULT_FILE_PERMISSIONS);
        let _f3 = h.create_file("/also_static.txt", DEFAULT_FILE_PERMISSIONS);

        // Snapshot state of all three before modification
        let s1_before = h.stat("/static.txt");
        let s2_before = h.stat("/modified.txt");
        let s3_before = h.stat("/also_static.txt");

        // Commit the initial state
        h.sync_and_remount();

        // Verify we came back clean with the same state
        assert_eq!(h.stat("/static.txt").data_version, s1_before.data_version);

        // Now modify only the middle file (this is a fresh mount, so directly)
        h.write_file("/modified.txt", 0, b"modified content here");
        let s2_after = h.stat("/modified.txt");
        assert_ne!(
            s2_after.data_version, s2_before.data_version,
            "writing must bump data_version"
        );
        assert!(s2_after.size > s2_before.size, "writing must change size");

        h.sync_and_remount();

        // Verify only modified.txt changed
        let s1 = h.stat("/static.txt");
        let s2 = h.stat("/modified.txt");
        let s3 = h.stat("/also_static.txt");

        // Static files must be unchanged
        assert_eq!(s1.inode_id, s1_before.inode_id);
        assert_eq!(s1.data_version, s1_before.data_version);
        assert_eq!(s1.size, s1_before.size);

        assert_eq!(s3.inode_id, s3_before.inode_id);
        assert_eq!(s3.data_version, s3_before.data_version);
        assert_eq!(s3.size, s3_before.size);

        // Modified file must reflect the changes
        assert_eq!(s2.inode_id, s2_after.inode_id);
        assert_eq!(s2.data_version, s2_after.data_version);
        assert_eq!(s2.size, s2_after.size);
        assert_eq!(h.read_file("/modified.txt"), b"modified content here");
    }

    #[test]
    fn multiple_modified_inodes_all_persist() {
        let mut h = PersistenceHarness::mount("multi_all_mod");

        h.create_file("/a.txt", DEFAULT_FILE_PERMISSIONS);
        h.create_file("/b.txt", DEFAULT_FILE_PERMISSIONS);
        h.create_file("/c.txt", DEFAULT_FILE_PERMISSIONS);

        h.sync_and_remount(); // Commit and reopen

        // Modify all three
        h.write_file("/a.txt", 0, b"aaa");
        h.write_file("/b.txt", 0, b"bbb");
        h.write_file("/c.txt", 0, b"ccc");

        let a_after = h.stat("/a.txt");
        let b_after = h.stat("/b.txt");
        let c_after = h.stat("/c.txt");

        h.sync_and_remount();

        let a = h.stat("/a.txt");
        let b = h.stat("/b.txt");
        let c = h.stat("/c.txt");

        assert_eq!(a.data_version, a_after.data_version);
        assert_eq!(b.data_version, b_after.data_version);
        assert_eq!(c.data_version, c_after.data_version);
        assert_eq!(h.read_file("/a.txt"), b"aaa");
        assert_eq!(h.read_file("/b.txt"), b"bbb");
        assert_eq!(h.read_file("/c.txt"), b"ccc");
    }

    #[test]
    fn directory_and_file_modifications_coexist() {
        let mut h = PersistenceHarness::mount("dir_file_coexist");

        h.create_dir("/d", DEFAULT_DIRECTORY_PERMISSIONS);
        h.sync_and_remount();

        // Add a file inside the directory and modify a root-level file
        h.create_file("/d/f.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/d/f.txt", 0, b"inside dir");
        h.create_file("/root_f.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/root_f.txt", 0, b"at root");

        h.sync_and_remount();

        // Both modifications must survive
        assert_eq!(h.read_file("/d/f.txt"), b"inside dir");
        assert_eq!(h.read_file("/root_f.txt"), b"at root");

        let d_entries = h.list_dir("/d");
        let d_names: Vec<String> = d_entries.iter().map(|e| e.name_lossy()).collect();
        assert!(d_names.contains(&"f.txt".to_string()));

        let root_entries = h.list_dir("/");
        let root_names: Vec<String> = root_entries.iter().map(|e| e.name_lossy()).collect();
        assert!(root_names.contains(&"d".to_string()));
        assert!(root_names.contains(&"root_f.txt".to_string()));
    }
}

// ---------------------------------------------------------------------------
// 4. Empty filesystem remount
// ---------------------------------------------------------------------------
mod empty_filesystem_remount {
    use super::*;

    #[test]
    fn root_directory_intact_after_remount() {
        let mut h = PersistenceHarness::mount("empty_remount");
        // A fresh mount has only the root inode
        let root = h.stat("/");
        assert!(root.carries_child_namespace(), "root must be a directory");

        h.sync_and_remount();

        let root2 = h.stat("/");
        assert!(root2.carries_child_namespace());
        assert_eq!(root2.inode_id, root.inode_id);
        assert_eq!(root2.generation, root.generation);

        // Root listing should not error
        let _entries = h.list_dir("/");
    }

    #[test]
    fn double_remount_preserves_emptiness() {
        let mut h = PersistenceHarness::mount("double_empty");
        h.sync_and_remount();
        h.sync_and_remount();

        // After two remounts we can still stat root
        let root = h.stat("/");
        assert!(root.carries_child_namespace());
    }

    #[test]
    fn empty_remount_does_not_create_spurious_entries() {
        let mut h = PersistenceHarness::mount("spurious_check");
        let before = h.list_dir("/");

        h.sync_and_remount();

        let after = h.list_dir("/");
        assert_eq!(
            after.len(),
            before.len(),
            "no spurious entries after empty remount"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Attribute dirty/clean tracking
// ---------------------------------------------------------------------------
mod dirty_clean_tracking {
    use super::*;

    #[test]
    fn mutation_sets_dirty_commit_clears() {
        let mut h = PersistenceHarness::mount("dirty_clear");
        h.fs_mut().set_auto_commit(false);
        // Commit any initial dirty state
        h.commit();

        // After commit, should be clean
        assert!(
            !h.has_dirty_metadata(),
            "expected clean after commit on fresh filesystem"
        );

        // Creating a file marks inode+dir dirty
        h.create_file("/dirty_test.txt", DEFAULT_FILE_PERMISSIONS);
        assert!(
            h.has_dirty_metadata(),
            "creating a file must set dirty metadata"
        );

        // Commit clears dirty state
        h.commit();
        assert!(!h.has_dirty_metadata(), "commit must clear dirty metadata");

        // Writing should dirty again
        h.write_file("/dirty_test.txt", 0, b"data");
        assert!(h.has_dirty_metadata(), "writing must set dirty metadata");

        h.commit();
        assert!(
            !h.has_dirty_metadata(),
            "commit after write must clear dirty metadata"
        );
    }

    #[test]
    fn dirty_state_does_not_survive_commit_across_remount() {
        let mut h = PersistenceHarness::mount("dirty_remount");
        h.fs_mut().set_auto_commit(false);

        // Get to clean state
        h.commit();

        // Make dirty
        h.create_file("/persist_dirty.txt", DEFAULT_FILE_PERMISSIONS);
        assert!(h.has_dirty_metadata());

        // Commit and verify clean
        h.commit();
        assert!(!h.has_dirty_metadata());

        // Remount and verify clean
        h.sync_and_remount();
        assert!(
            !h.has_dirty_metadata(),
            "after remount following commit, must be clean"
        );

        // Created file must exist
        let s = h.stat("/persist_dirty.txt");
        assert!(s.carries_byte_space());
    }

    #[test]
    fn mkdir_sets_dirty_commit_clears() {
        let mut h = PersistenceHarness::mount("mkdir_dirty");
        h.fs_mut().set_auto_commit(false);
        h.commit();
        assert!(!h.has_dirty_metadata());

        h.create_dir("/newdir", DEFAULT_DIRECTORY_PERMISSIONS);
        assert!(h.has_dirty_metadata(), "mkdir must set dirty metadata");

        h.commit();
        assert!(
            !h.has_dirty_metadata(),
            "commit after mkdir must clear dirty metadata"
        );

        // Directory must survive
        h.sync_and_remount();
        let s = h.stat("/newdir");
        assert!(s.carries_child_namespace());
    }

    #[test]
    fn hard_link_sets_dirty() {
        let mut h = PersistenceHarness::mount("link_dirty");
        h.fs_mut().set_auto_commit(false);
        h.create_file("/link_src.txt", DEFAULT_FILE_PERMISSIONS);
        h.commit();
        assert!(!h.has_dirty_metadata());

        h.link_file("/link_src.txt", "/link_dst.txt");
        assert!(h.has_dirty_metadata(), "hard link must set dirty metadata");

        h.commit();
        assert!(!h.has_dirty_metadata());

        // Both paths and nlink must survive
        h.sync_and_remount();
        let s = h.stat("/link_src.txt");
        assert_eq!(s.nlink, 2);
        assert_eq!(h.stat("/link_dst.txt").inode_id, s.inode_id);
    }
}
// ---------------------------------------------------------------------------
// 6. Symlink target persistence
// ---------------------------------------------------------------------------
mod symlink_persistence {
    use super::*;

    #[test]
    fn symlink_target_survives_remount() {
        let mut h = PersistenceHarness::mount("symlink_survive");
        let created = h.create_symlink("/link1", b"../target");
        assert!(created.carries_byte_space() && !created.carries_child_namespace());
        assert_eq!(h.read_symlink("/link1"), b"../target");

        h.sync_and_remount();

        let s = h.stat("/link1");
        assert!(s.carries_byte_space() && !s.carries_child_namespace());
        assert_eq!(s.inode_id, created.inode_id);
        assert_eq!(h.read_symlink("/link1"), b"../target");
    }

    #[test]
    fn absolute_symlink_target_survives_remount() {
        let mut h = PersistenceHarness::mount("symlink_abs");
        h.create_symlink("/abs_link", b"/absolute/path/to/target");
        assert_eq!(h.read_symlink("/abs_link"), b"/absolute/path/to/target");

        h.sync_and_remount();

        assert_eq!(h.read_symlink("/abs_link"), b"/absolute/path/to/target");
    }

    #[test]
    fn empty_symlink_target_survives_remount() {
        let mut h = PersistenceHarness::mount("symlink_empty");
        h.create_symlink("/empty_link", b"");
        assert_eq!(h.read_symlink("/empty_link"), b"");

        h.sync_and_remount();

        assert_eq!(h.read_symlink("/empty_link"), b"");
    }

    #[test]
    fn long_symlink_target_survives_remount() {
        let mut h = PersistenceHarness::mount("symlink_long");
        let target = b"/a/very/long/symlink/target/path/with/many/components/that/should/survive/persistence/roundtrip";
        h.create_symlink("/long_link", target);
        assert_eq!(h.read_symlink("/long_link"), target);

        h.sync_and_remount();

        assert_eq!(h.read_symlink("/long_link"), target);
    }

    #[test]
    fn multiple_symlinks_survive_remount() {
        let mut h = PersistenceHarness::mount("symlink_multi");
        h.create_symlink("/link_a", b"target_a");
        h.create_symlink("/link_b", b"target_b");
        h.create_symlink("/link_c", b"target_c");

        h.sync_and_remount();

        assert_eq!(h.read_symlink("/link_a"), b"target_a");
        assert_eq!(h.read_symlink("/link_b"), b"target_b");
        assert_eq!(h.read_symlink("/link_c"), b"target_c");

        // All three must be listed
        let entries = h.list_dir("/");
        let names: Vec<String> = entries.iter().map(|e| e.name_lossy()).collect();
        assert!(names.contains(&"link_a".to_string()));
        assert!(names.contains(&"link_b".to_string()));
        assert!(names.contains(&"link_c".to_string()));
    }

    #[test]
    fn symlink_size_equals_target_length_across_remount() {
        let mut h = PersistenceHarness::mount("symlink_size");
        let target = b"exact target length";
        let created = h.create_symlink("/sized_link", target);
        assert_eq!(created.size, target.len() as u64);

        h.sync_and_remount();

        let s = h.stat("/sized_link");
        assert_eq!(s.size, target.len() as u64);
        assert_eq!(h.read_symlink("/sized_link"), target);
    }
}

// ---------------------------------------------------------------------------
// 7. Corruption detection on remount
// ---------------------------------------------------------------------------
mod corruption_detection {
    use super::*;
    use std::fs;

    use tidefs_local_filesystem::LocalFileSystem;
    use tidefs_local_object_store::StoreOptions;

    /// List all keys in the object store and overwrite each with garbage.
    /// Returns the number of corrupted keys.
    fn corrupt_all_keys(root: &std::path::Path) -> usize {
        let opts = StoreOptions::test_fast();
        let mut pool = tidefs_local_filesystem::LocalFileSystem::default_development_pool(
            root, &opts, None, None,
        )
        .expect("open pool for corruption");
        let store = pool.raw_primary_store_mut();
        let keys = store.list_keys();
        let count = keys.len();
        for key in keys {
            let _ = store.put(key, b"corrupted-by-test-garbage-bytes");
        }
        count
    }

    #[test]
    fn corrupt_all_objects_prevents_filesystem_open() {
        PersistenceHarness::set_test_key();

        let mut h = PersistenceHarness::mount("corrupt_all");
        h.create_file("/data.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/data.txt", 0, b"important data");
        h.sync_all();

        let root = h.into_root();

        let corrupted_count = corrupt_all_keys(&root);
        assert!(corrupted_count > 0, "must corrupt at least one object");

        // Opening the filesystem on a fully corrupted store must fail
        let result = LocalFileSystem::open(&root);
        assert!(
            result.is_err(),
            "filesystem open must fail on fully corrupted store, got {:?}",
            result.ok()
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_after_commit_detected_on_reopen() {
        PersistenceHarness::set_test_key();

        let mut h = PersistenceHarness::mount("corrupt_reopen");
        h.create_file("/survivor.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/survivor.txt", 0, b"will be corrupted");
        h.sync_all();

        let root = h.into_root();

        let corrupted_count = corrupt_all_keys(&root);
        assert!(corrupted_count > 0, "must corrupt at least one object");

        // Reopen must fail
        let result = LocalFileSystem::open(&root);
        assert!(
            result.is_err(),
            "filesystem open must fail after corruption, got {:?}",
            result.ok()
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_filesystem_corruption_detected() {
        PersistenceHarness::set_test_key();

        let mut h = PersistenceHarness::mount("corrupt_empty");
        // Just mount and commit the empty filesystem
        h.sync_all();

        let root = h.into_root();

        let corrupted_count = corrupt_all_keys(&root);
        assert!(corrupted_count > 0, "even empty filesystem has objects");

        let result = LocalFileSystem::open(&root);
        assert!(
            result.is_err(),
            "corrupted empty filesystem open must fail, got {:?}",
            result.ok()
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_with_multi_level_directory_tree() {
        PersistenceHarness::set_test_key();

        let mut h = PersistenceHarness::mount("corrupt_tree");
        h.create_dir("/a", DEFAULT_DIRECTORY_PERMISSIONS);
        h.create_dir("/a/b", DEFAULT_DIRECTORY_PERMISSIONS);
        h.create_file("/a/b/f.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/a/b/f.txt", 0, b"nested");
        h.create_file("/root_f.txt", DEFAULT_FILE_PERMISSIONS);
        h.write_file("/root_f.txt", 0, b"root");
        h.sync_all();

        let root = h.into_root();

        let corrupted_count = corrupt_all_keys(&root);
        assert!(corrupted_count > 0);

        let result = LocalFileSystem::open(&root);
        assert!(
            result.is_err(),
            "corrupted tree filesystem open must fail, got {:?}",
            result.ok()
        );

        let _ = fs::remove_dir_all(&root);
    }
}
