// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE basic-ops integration test: validates create/mkdir/rmdir/unlink/rename
//! through a real FUSE mount, remount persistence, and the full basic-ops cycle.
//!
//! Uses `MountHarness` for daemon lifecycle and mountpoint operations.
//! Gated on `feature = "fuse"` which includes `local-filesystem`.

#[cfg(test)]
mod tests {
    use crate::mount_harness::MountHarness;
    use std::fs;

    /// Full basic-ops cycle: mkdir → create → write → read → unlink → rmdir
    /// → remount → verify directory is empty.
    ///
    /// Advancement criteria 1, 3, 5:
    ///   - create/mkdir/rmdir/unlink complete successfully via real FUSE mount
    ///   - namespace mutations survive remount
    ///   - integration test validates the full basic-ops cycle
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn test_basic_ops_cycle_with_remount() {
        let mut harness = MountHarness::new_or_fail(module_path!());

        // ── mkdir ───────────────────────────────────────────────────
        harness.mkdir("testdir").expect("mkdir testdir");
        let md = harness.stat("testdir").expect("stat testdir");
        assert!(md.is_dir(), "testdir must be a directory after mkdir");

        // ── create + write ──────────────────────────────────────────
        let data = b"hello basic-ops cycle\n";
        harness
            .create_file("testdir/hello.txt", data)
            .expect("create hello.txt");
        let md = harness.stat("testdir/hello.txt").expect("stat hello.txt");
        assert!(md.is_file(), "hello.txt must be a regular file");

        // ── read + verify ───────────────────────────────────────────
        let read_back = harness
            .read_file("testdir/hello.txt")
            .expect("read hello.txt");
        assert_eq!(read_back, data, "data round-trip mismatch");

        // ── verify readdir sees the entry ───────────────────────────
        let entries = harness.readdir("testdir").expect("readdir testdir");
        assert_eq!(
            entries,
            vec!["hello.txt"],
            "testdir should contain hello.txt"
        );

        // ── unlink ──────────────────────────────────────────────────
        harness
            .remove_file("testdir/hello.txt")
            .expect("unlink hello.txt");
        assert!(
            !harness.exists("testdir/hello.txt"),
            "file must not exist after unlink"
        );
        let entries = harness.readdir("testdir").expect("readdir after unlink");
        assert!(entries.is_empty(), "testdir must be empty after unlink");

        // ── rmdir ───────────────────────────────────────────────────
        harness.remove_dir("testdir").expect("rmdir testdir");
        assert!(!harness.exists("testdir"), "dir must not exist after rmdir");

        // ── remount ─────────────────────────────────────────────────
        harness.remount().expect("remount");

        // ── verify directory is empty after remount ─────────────────
        let root_entries = harness.readdir(".").expect("readdir root after remount");
        assert!(
            root_entries.is_empty(),
            "root must be empty after remount, found: {root_entries:?}"
        );
    }

    /// Rename test: mkdir → rename directory → remount →
    /// verify new name exists and old name is gone.
    ///
    /// Advancement criterion 2:
    ///   - rename completes successfully via real FUSE mount
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn test_rename_directory_with_remount() {
        let mut harness = MountHarness::new_or_fail(module_path!());

        // ── create source directory ─────────────────────────────────
        harness.mkdir("olddir").expect("mkdir olddir");
        harness
            .create_file("olddir/file.txt", b"rename persistence")
            .expect("create file in olddir");

        // ── verify old name exists ──────────────────────────────────
        assert!(harness.exists("olddir"), "olddir must exist");
        assert!(
            harness.exists("olddir/file.txt"),
            "olddir/file.txt must exist"
        );
        assert!(!harness.exists("newdir"), "newdir must not exist yet");

        // ── rename olddir → newdir ──────────────────────────────────
        let old_path = harness.mount_path().join("olddir");
        let new_path = harness.mount_path().join("newdir");
        fs::rename(&old_path, &new_path).expect("rename olddir → newdir");

        // ── verify old name is gone, new name exists ────────────────
        assert!(
            !harness.exists("olddir"),
            "olddir must not exist after rename"
        );
        assert!(harness.exists("newdir"), "newdir must exist after rename");
        assert!(
            harness.exists("newdir/file.txt"),
            "newdir/file.txt must exist after rename"
        );

        // ── verify file content survived rename ─────────────────────
        let read_back = harness
            .read_file("newdir/file.txt")
            .expect("read newdir/file.txt");
        assert_eq!(
            read_back, b"rename persistence",
            "file content mismatch after rename"
        );

        // ── remount ─────────────────────────────────────────────────
        harness.remount().expect("remount after rename");

        // ── verify rename survived remount ──────────────────────────
        assert!(
            !harness.exists("olddir"),
            "olddir must not exist after remount"
        );
        assert!(harness.exists("newdir"), "newdir must exist after remount");
        let read_back2 = harness
            .read_file("newdir/file.txt")
            .expect("read newdir/file.txt after remount");
        assert_eq!(
            read_back2, b"rename persistence",
            "file content mismatch after remount"
        );
    }

    /// Edge case: rmdir on a non-empty directory must fail.
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn test_rmdir_nonempty_fails() {
        let harness = MountHarness::new_or_fail(module_path!());

        harness.mkdir("dir").expect("mkdir dir");
        harness
            .create_file("dir/file.txt", b"block rmdir")
            .expect("create file");

        let full_path = harness.mount_path().join("dir");
        let result = fs::remove_dir(&full_path);
        assert!(result.is_err(), "rmdir on non-empty dir must fail");
    }

    /// Edge case: ENOENT on rmdir of non-existent directory.
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn test_rmdir_nonexistent_fails() {
        let harness = MountHarness::new_or_fail(module_path!());

        let full_path = harness.mount_path().join("nonexistent");
        let result = fs::remove_dir(&full_path);
        assert!(result.is_err(), "rmdir on non-existent dir must fail");
    }
}
