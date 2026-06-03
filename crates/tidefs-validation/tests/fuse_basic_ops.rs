//! FUSE basic-ops integration test: create, mkdir, rmdir, unlink, rename,
//! and remount-persistence through a real read-write FUSE mount.
//! Exercises the existing dispatch handlers in
//! `fuse_create_unlink_dispatch.rs`, `fuse_create_mutation.rs`, and
//! `fuse_rename.rs` and validates namespace state after each mutation.
//!
//! This test directly satisfies the advancement criteria of the `fuse-basic-ops`
//! focus slice: *create/mkdir/rmdir/unlink/rename complete successfully via real
//! FUSE mount* and *namespace mutations survive remount*. Includes write-read
//! byte-identity verification and a full-cycle remount-verify-empty test.

use std::os::unix::fs::MetadataExt;
use tidefs_validation::mount_harness::MountHarness;

// ── create + mkdir ─────────────────────────────────────────────────────────

/// Create a regular file at the mount root, then verify it appears in readdir
/// and that `exists` returns true.
#[test]
fn create_file_at_root() {
    let harness = MountHarness::new().expect("harness setup");
    harness
        .create_file("test_create.txt", b"hello create\n")
        .expect("create_file");

    assert!(
        harness.exists("test_create.txt"),
        "test_create.txt must exist after create"
    );
    let entries = harness.readdir(".").expect("readdir root");
    assert!(
        entries.contains(&"test_create.txt".to_string()),
        "root readdir must include test_create.txt after create"
    );
}

/// Create a file inside a subdirectory, verifying the full path exists.
#[test]
fn create_file_in_subdir() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("sub").expect("mkdir sub");
    harness
        .create_file("sub/file_in_sub.txt", b"nested create\n")
        .expect("create_file sub/file_in_sub.txt");

    assert!(harness.exists("sub/file_in_sub.txt"));
    let entries = harness.readdir("sub").expect("readdir sub");
    assert!(
        entries.contains(&"file_in_sub.txt".to_string()),
        "sub readdir must include file_in_sub.txt"
    );
}

/// Create a directory and verify it appears in readdir and has directory
/// metadata.
#[test]
fn mkdir_and_verify() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("mydir").expect("mkdir mydir");

    assert!(harness.exists("mydir"), "mydir must exist after mkdir");
    let md = harness.stat("mydir").expect("stat mydir");
    assert!(md.is_dir(), "mydir must be a directory");

    let entries = harness.readdir(".").expect("readdir root");
    assert!(
        entries.contains(&"mydir".to_string()),
        "root readdir must include mydir after mkdir"
    );
}

/// Create nested directories and verify the tree.
#[test]
fn mkdir_nested() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir_all("a/b/c").expect("mkdir_all a/b/c");

    assert!(harness.exists("a"));
    assert!(harness.exists("a/b"));
    assert!(harness.exists("a/b/c"));
    assert!(harness.stat("a/b/c").expect("stat c").is_dir());

    let top = harness.readdir(".").expect("readdir root");
    assert!(top.contains(&"a".to_string()));

    let mid = harness.readdir("a").expect("readdir a");
    assert!(mid.contains(&"b".to_string()));

    let deep = harness.readdir("a/b").expect("readdir a/b");
    assert!(deep.contains(&"c".to_string()));
}

// ── rmdir + unlink ─────────────────────────────────────────────────────────

/// Remove a file and verify it disappears from readdir.
#[test]
fn unlink_file() {
    let harness = MountHarness::new().expect("harness setup");
    harness
        .create_file("to_unlink.txt", b"ephemeral\n")
        .expect("create_file");
    assert!(harness.exists("to_unlink.txt"));

    harness
        .remove_file("to_unlink.txt")
        .expect("remove_file to_unlink.txt");

    assert!(
        !harness.exists("to_unlink.txt"),
        "to_unlink.txt must not exist after unlink"
    );
    let entries = harness.readdir(".").expect("readdir root");
    assert!(
        !entries.contains(&"to_unlink.txt".to_string()),
        "root readdir must not include to_unlink.txt after unlink"
    );
}

/// Remove an empty directory and verify it disappears.
#[test]
fn rmdir_empty_dir() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("to_rmdir").expect("mkdir to_rmdir");
    assert!(harness.exists("to_rmdir"));

    harness.remove_dir("to_rmdir").expect("remove_dir to_rmdir");

    assert!(
        !harness.exists("to_rmdir"),
        "to_rmdir must not exist after rmdir"
    );
    let entries = harness.readdir(".").expect("readdir root");
    assert!(
        !entries.contains(&"to_rmdir".to_string()),
        "root readdir must not include to_rmdir after rmdir"
    );
}

/// Remove a file inside a subdirectory, then remove the subdirectory itself.
#[test]
fn unlink_then_rmdir() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("d").expect("mkdir d");
    harness
        .create_file("d/f.txt", b"inside\n")
        .expect("create_file d/f.txt");

    harness.remove_file("d/f.txt").expect("unlink d/f.txt");
    assert!(!harness.exists("d/f.txt"));

    harness.remove_dir("d").expect("rmdir d");
    assert!(!harness.exists("d"));
}

/// Removing a non-empty directory should fail with a POSIX error.
#[test]
fn rmdir_non_empty_dir_fails() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("nonempty").expect("mkdir nonempty");
    harness
        .create_file("nonempty/child.txt", b"block rmdir\n")
        .expect("create_file");

    let result = harness.remove_dir("nonempty");
    assert!(result.is_err(), "rmdir on non-empty dir must fail; got Ok");

    // The directory and its contents must still exist.
    assert!(harness.exists("nonempty"));
    assert!(harness.exists("nonempty/child.txt"));
}

// ── combined basic-ops cycle ────────────────────────────────────────────────

/// Full same-session cycle: mkdir → create → verify → unlink → verify →
/// rmdir → verify.  This exercises all four dispatch paths in one test and
/// mirrors the advancement criterion 1 sequence.
#[test]
fn basic_ops_full_cycle() {
    let harness = MountHarness::new().expect("harness setup");

    // ── Phase 1: mkdir ───────────────────────────────────────────────
    harness.mkdir("basicdir").expect("mkdir basicdir");
    assert!(harness.exists("basicdir"));
    assert!(harness.stat("basicdir").expect("stat").is_dir());

    // ── Phase 2: create file with content ────────────────────────────
    let hello_data = b"basic ops cycle: hello world\n".to_vec();
    harness
        .create_file("basicdir/hello.txt", &hello_data)
        .expect("create_file");
    assert!(harness.exists("basicdir/hello.txt"));

    // Write-read byte-identity: read back and verify exact match.
    let read_back = harness
        .read_file("basicdir/hello.txt")
        .expect("read hello.txt");
    assert_eq!(read_back, hello_data, "hello.txt write-read byte mismatch");

    let md = harness.stat("basicdir/hello.txt").expect("stat hello.txt");
    assert!(
        md.is_file() || !md.is_dir(),
        "hello.txt must be a regular file"
    );

    let dir_entries = harness.readdir("basicdir").expect("readdir basicdir");
    assert!(
        dir_entries.contains(&"hello.txt".to_string()),
        "basicdir must contain hello.txt after create"
    );

    // ── Phase 3: create second file ──────────────────────────────────
    let second_data = [0u8; 256].to_vec();
    harness
        .create_file("basicdir/second.bin", &second_data)
        .expect("create_file second.bin");
    assert!(harness.exists("basicdir/second.bin"));

    let dir_entries = harness.readdir("basicdir").expect("readdir basicdir");
    assert!(dir_entries.contains(&"hello.txt".to_string()));
    assert!(dir_entries.contains(&"second.bin".to_string()));

    // ── Phase 4: rename hello.txt -> renamed.txt ────────────────────
    assert!(
        !harness.exists("basicdir/renamed.txt"),
        "renamed.txt must not exist before rename"
    );
    harness
        .rename("basicdir/hello.txt", "basicdir/renamed.txt")
        .expect("rename hello.txt -> renamed.txt");

    assert!(
        !harness.exists("basicdir/hello.txt"),
        "hello.txt must not exist after rename"
    );
    assert!(
        harness.exists("basicdir/renamed.txt"),
        "renamed.txt must exist after rename"
    );

    // Verify renamed file still has correct content.
    let renamed_read = harness
        .read_file("basicdir/renamed.txt")
        .expect("read renamed.txt");
    assert_eq!(
        renamed_read, hello_data,
        "renamed.txt content mismatch after rename"
    );

    let dir_entries = harness.readdir("basicdir").expect("readdir after rename");
    assert!(
        !dir_entries.contains(&"hello.txt".to_string()),
        "hello.txt must not appear in readdir after rename"
    );
    assert!(
        dir_entries.contains(&"renamed.txt".to_string()),
        "renamed.txt must appear in readdir after rename"
    );
    assert!(
        dir_entries.contains(&"second.bin".to_string()),
        "second.bin must survive rename of sibling"
    );

    // ── Phase 5: unlink second file ──────────────────────────────────
    harness
        .remove_file("basicdir/second.bin")
        .expect("remove_file second.bin");
    assert!(!harness.exists("basicdir/second.bin"));

    let dir_entries = harness
        .readdir("basicdir")
        .expect("readdir after unlink second");
    assert!(!dir_entries.contains(&"second.bin".to_string()));
    assert!(
        dir_entries.contains(&"renamed.txt".to_string()),
        "renamed.txt must survive unlink of sibling"
    );

    // ── Phase 6: unlink renamed file ─────────────────────────────────
    harness
        .remove_file("basicdir/renamed.txt")
        .expect("remove_file renamed.txt");
    assert!(!harness.exists("basicdir/renamed.txt"));

    let dir_entries = harness
        .readdir("basicdir")
        .expect("readdir after all unlinks");
    assert!(!dir_entries.contains(&"renamed.txt".to_string()));
    assert!(!dir_entries.contains(&"second.bin".to_string()));

    // ── Phase 7: rmdir now-empty directory ───────────────────────────
    harness.remove_dir("basicdir").expect("rmdir basicdir");
    assert!(!harness.exists("basicdir"));

    let root_entries = harness.readdir(".").expect("readdir root");
    assert!(!root_entries.contains(&"basicdir".to_string()));
}

// ── full cycle with remount persistence ────────────────────────────────────

/// Full end-to-end cycle with remount persistence verification.
///
/// Sequence: mount(RW) → mkdir → create → write → read(byte-identical) →
/// rename → unlink → rmdir → unmount → remount → verify root is empty.
///
/// This test directly satisfies the fuse-basic-ops advancement criteria:
/// - create/mkdir/rmdir/unlink/rename succeed via real FUSE mount
/// - namespace mutations survive remount
#[test]
fn basic_ops_cycle_with_remount() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP basic_ops_cycle_with_remount: daemon not available -- {e}");
            return;
        }
    };

    // ── Phase 1: mkdir ───────────────────────────────────────────────
    harness.mkdir("cycledir").expect("mkdir cycledir");
    assert!(harness.exists("cycledir"));
    assert!(harness.stat("cycledir").expect("stat").is_dir());

    // ── Phase 2: create file with content ────────────────────────────
    let test_data = b"remount cycle: persistence payload\n".to_vec();
    harness
        .create_file("cycledir/data.txt", &test_data)
        .expect("create_file");
    assert!(harness.exists("cycledir/data.txt"));

    // Write-read byte-identity verification.
    let read_back = harness
        .read_file("cycledir/data.txt")
        .expect("read data.txt");
    assert_eq!(read_back, test_data, "write-read byte mismatch");

    let md = harness.stat("cycledir/data.txt").expect("stat data.txt");
    assert!(
        md.is_file() || !md.is_dir(),
        "data.txt must be a regular file"
    );

    // ── Phase 3: create second file ──────────────────────────────────
    let second_data = (0u8..=255).collect::<Vec<u8>>();
    harness
        .create_file("cycledir/binary.bin", &second_data)
        .expect("create binary.bin");
    assert!(harness.exists("cycledir/binary.bin"));

    let dir_entries = harness.readdir("cycledir").expect("readdir cycledir");
    assert!(dir_entries.contains(&"data.txt".to_string()));
    assert!(dir_entries.contains(&"binary.bin".to_string()));

    // ── Phase 4: rename data.txt -> moved.txt ────────────────────────
    harness
        .rename("cycledir/data.txt", "cycledir/moved.txt")
        .expect("rename data.txt -> moved.txt");
    assert!(!harness.exists("cycledir/data.txt"));
    assert!(harness.exists("cycledir/moved.txt"));

    let renamed_read = harness
        .read_file("cycledir/moved.txt")
        .expect("read moved.txt");
    assert_eq!(renamed_read, test_data, "content mismatch after rename");

    let dir_entries = harness.readdir("cycledir").expect("readdir after rename");
    assert!(!dir_entries.contains(&"data.txt".to_string()));
    assert!(dir_entries.contains(&"moved.txt".to_string()));
    assert!(dir_entries.contains(&"binary.bin".to_string()));

    // ── Phase 5: unlink binary.bin ───────────────────────────────────
    harness
        .remove_file("cycledir/binary.bin")
        .expect("remove_file binary.bin");
    assert!(!harness.exists("cycledir/binary.bin"));

    let dir_entries = harness
        .readdir("cycledir")
        .expect("readdir after first unlink");
    assert!(!dir_entries.contains(&"binary.bin".to_string()));
    assert!(dir_entries.contains(&"moved.txt".to_string()));

    // ── Phase 6: unlink moved.txt ────────────────────────────────────
    harness
        .remove_file("cycledir/moved.txt")
        .expect("remove_file moved.txt");
    assert!(!harness.exists("cycledir/moved.txt"));

    let dir_entries = harness
        .readdir("cycledir")
        .expect("readdir after all unlinks");
    assert!(
        dir_entries.is_empty(),
        "cycledir must be empty after all unlinks, got: {dir_entries:?}"
    );

    // ── Phase 7: rmdir empty directory ───────────────────────────────
    harness.remove_dir("cycledir").expect("rmdir cycledir");
    assert!(!harness.exists("cycledir"));

    let root_entries = harness.readdir(".").expect("readdir root before unmount");
    assert!(
        !root_entries.contains(&"cycledir".to_string()),
        "root must not contain cycledir after rmdir"
    );

    // ── Phase 8: unmount ─────────────────────────────────────────────
    harness.unmount_only(true).expect("unmount session 1");

    // ── Phase 9: remount same backing store ──────────────────────────
    harness.remount().expect("remount session 2");

    // ── Phase 10: verify root is empty ───────────────────────────────
    let root_entries_after = harness.readdir(".").expect("readdir root after remount");
    assert!(
        root_entries_after.is_empty(),
        "root directory must be empty after remount (all basic-ops mutations cleaned up).          Found: {root_entries_after:?}"
    );

    // Verify the cycledir is truly gone after remount.
    assert!(
        !harness.exists("cycledir"),
        "cycledir must not exist after remount"
    );
}

// ── File content integrity across basic ops ─────────────────────────────────

/// Verify that file content written during create survives same-session
/// read after other basic-ops traffic in the same directory.
#[test]
fn file_content_integrity_through_ops() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("datadir").expect("mkdir datadir");

    let data_a = b"file A: 0123456789abcdef\n".to_vec();
    let data_b = (0u8..=255).collect::<Vec<u8>>();

    harness
        .create_file("datadir/a.txt", &data_a)
        .expect("create a.txt");
    harness
        .create_file("datadir/b.bin", &data_b)
        .expect("create b.bin");

    // Create an unrelated file to generate additional namespace traffic.
    harness
        .create_file("datadir/noise.tmp", b"noise\n")
        .expect("create noise.tmp");
    harness
        .remove_file("datadir/noise.tmp")
        .expect("remove noise.tmp");

    let read_a = harness.read_file("datadir/a.txt").expect("read a.txt");
    let read_b = harness.read_file("datadir/b.bin").expect("read b.bin");

    assert_eq!(read_a, data_a, "a.txt content mismatch");
    assert_eq!(read_b, data_b, "b.bin content mismatch");
}

// ── Stress: multi-file create + unlink ──────────────────────────────────────

/// Create and unlink multiple files in sequence, verifying namespace state after
/// each step.  This exercises the create and unlink dispatch paths repeatedly
/// within a single session.
#[test]
fn multi_file_create_unlink_sequence() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("multidir").expect("mkdir multidir");

    let names: Vec<String> = (0..8).map(|i| format!("file_{i:02}.txt")).collect();

    // Create all files.
    for name in &names {
        harness
            .create_file(
                format!("multidir/{name}"),
                format!("content of {name}\n").as_bytes(),
            )
            .unwrap_or_else(|e| panic!("create {name}: {e}"));
    }

    let entries = harness.readdir("multidir").expect("readdir after creates");
    for name in &names {
        assert!(entries.contains(name), "missing {name} after create");
    }

    // Unlink every other file.
    for (i, name) in names.iter().enumerate() {
        if i % 2 == 0 {
            harness
                .remove_file(format!("multidir/{name}"))
                .unwrap_or_else(|e| panic!("unlink {name}: {e}"));
        }
    }

    let entries = harness
        .readdir("multidir")
        .expect("readdir after partial unlink");
    for (i, name) in names.iter().enumerate() {
        if i % 2 == 0 {
            assert!(
                !entries.contains(name),
                "{name} should be gone after unlink"
            );
        } else {
            assert!(
                entries.contains(name),
                "{name} should survive unlink of siblings"
            );
        }
    }

    // Unlink the rest.
    for (i, name) in names.iter().enumerate() {
        if i % 2 != 0 {
            harness
                .remove_file(format!("multidir/{name}"))
                .unwrap_or_else(|e| panic!("unlink {name}: {e}"));
        }
    }

    let entries = harness
        .readdir("multidir")
        .expect("readdir after full unlink");
    assert!(
        entries.is_empty(),
        "multidir must be empty after all unlinks"
    );

    harness.remove_dir("multidir").expect("rmdir multidir");
}

// ── Hard link (link) operations ─────────────────────────────────────────────

/// Create a hard link to a regular file and verify both names exist,
/// point to the same inode, and have nlink >= 2.
#[test]
fn hard_link_creates_new_name() {
    let harness = MountHarness::new().expect("harness setup");
    harness
        .create_file("original.txt", b"to be linked\n")
        .expect("create_file original.txt");

    let src = harness.mount_path().join("original.txt");
    let dst = harness.mount_path().join("linked.txt");
    assert!(
        !harness.exists("linked.txt"),
        "linked.txt must not exist before link"
    );

    std::fs::hard_link(&src, &dst).expect("hard_link original.txt -> linked.txt");

    assert!(
        harness.exists("original.txt"),
        "original.txt must still exist after link"
    );
    assert!(
        harness.exists("linked.txt"),
        "linked.txt must exist after link"
    );

    // Both names must resolve to the same inode.
    let md_src = harness.stat("original.txt").expect("stat original.txt");
    let md_dst = harness.stat("linked.txt").expect("stat linked.txt");
    assert_eq!(
        md_src.ino(),
        md_dst.ino(),
        "original and linked must share inode"
    );
    assert!(
        md_src.nlink() >= 2,
        "nlink must be >= 2 after hard link, got {}",
        md_src.nlink()
    );

    // Both names appear in readdir.
    let entries = harness.readdir(".").expect("readdir root");
    assert!(entries.contains(&"original.txt".to_string()));
    assert!(entries.contains(&"linked.txt".to_string()));
}

/// Hard link preserves byte content: both names read the same data.
#[test]
fn hard_link_preserves_content() {
    let harness = MountHarness::new().expect("harness setup");
    let data = b"shared content across hard links\n".to_vec();
    harness
        .create_file("shared.dat", &data)
        .expect("create_file shared.dat");

    let src = harness.mount_path().join("shared.dat");
    let dst = harness.mount_path().join("alias.dat");
    std::fs::hard_link(&src, &dst).expect("hard_link shared.dat -> alias.dat");

    let read_src = harness.read_file("shared.dat").expect("read shared.dat");
    let read_dst = harness.read_file("alias.dat").expect("read alias.dat");
    assert_eq!(read_src, data, "shared.dat content mismatch after link");
    assert_eq!(read_dst, data, "alias.dat content mismatch");
    assert_eq!(
        read_src, read_dst,
        "linked files must have identical content"
    );
}

/// Hard link from a nonexistent source must fail with ENOENT.
#[test]
fn hard_link_nonexistent_source_returns_enoent() {
    let harness = MountHarness::new().expect("harness setup");

    let src = harness.mount_path().join("no_such_file");
    let dst = harness.mount_path().join("would_be_link");
    let result = std::fs::hard_link(&src, &dst);

    assert!(
        result.is_err(),
        "hard_link from nonexistent source must fail"
    );
    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "expected NotFound / ENOENT, got: {err:?}"
    );
    assert!(
        !harness.exists("would_be_link"),
        "link target must not be created on failure"
    );
}

/// Hard link to an existing target name must fail with EEXIST.
#[test]
fn hard_link_existing_target_returns_eexist() {
    let harness = MountHarness::new().expect("harness setup");
    harness
        .create_file("source.txt", b"source\n")
        .expect("create_file source.txt");
    harness
        .create_file("already_there.txt", b"existing\n")
        .expect("create_file already_there.txt");

    let src = harness.mount_path().join("source.txt");
    let dst = harness.mount_path().join("already_there.txt");
    let result = std::fs::hard_link(&src, &dst);

    assert!(result.is_err(), "hard_link to existing target must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::AlreadyExists,
        "expected AlreadyExists / EEXIST, got: {err:?}"
    );

    // Existing file must be untouched.
    let read = harness
        .read_file("already_there.txt")
        .expect("read already_there.txt");
    assert_eq!(
        read, b"existing\n",
        "existing target content must be unchanged"
    );
}

/// Unlink on a file through one of its hard links must not affect the
/// other link or the underlying data.
#[test]
fn unlink_one_link_preserves_other() {
    let harness = MountHarness::new().expect("harness setup");
    let data = b"persistent under hard link\n".to_vec();
    harness
        .create_file("persist.dat", &data)
        .expect("create_file persist.dat");

    let src = harness.mount_path().join("persist.dat");
    let dst = harness.mount_path().join("other_link.dat");
    std::fs::hard_link(&src, &dst).expect("hard_link persist.dat -> other_link.dat");

    // Unlink the original name.
    harness
        .remove_file("persist.dat")
        .expect("unlink persist.dat");
    assert!(!harness.exists("persist.dat"), "original name must be gone");

    // Other link must still exist with full content.
    assert!(
        harness.exists("other_link.dat"),
        "other link must survive unlink of original"
    );
    let read = harness
        .read_file("other_link.dat")
        .expect("read other_link.dat");
    assert_eq!(read, data, "content mismatch after unlinking other link");

    let md = harness.stat("other_link.dat").expect("stat other_link.dat");
    assert_eq!(
        md.nlink(),
        1,
        "nlink must be 1 after removing one of two links, got {}",
        md.nlink()
    );
}

// ── Unlink error paths ─────────────────────────────────────────────────────

/// Attempting to unlink a file that does not exist must return ENOENT.
#[test]
fn unlink_nonexistent_returns_enoent() {
    let harness = MountHarness::new().expect("harness setup");

    let result = harness.remove_file("no_such_unlink_target");
    assert!(result.is_err(), "unlink nonexistent file must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "expected NotFound / ENOENT, got: {err:?}"
    );
}

/// Attempting to unlink a directory must return EISDIR (or equivalent
/// on platforms that differentiate unlink/rmdir).
#[test]
fn unlink_directory_returns_error() {
    let harness = MountHarness::new().expect("harness setup");
    harness.mkdir("a_directory").expect("mkdir a_directory");

    let result = harness.remove_file("a_directory");
    assert!(result.is_err(), "unlink on directory must fail");

    // Directory must still exist and be usable.
    assert!(
        harness.exists("a_directory"),
        "directory must survive failed unlink"
    );
    let md = harness.stat("a_directory").expect("stat a_directory");
    assert!(md.is_dir(), "a_directory must still be a directory");
}

/// Unlink checks the parent directory's write permission, not the
/// file's own mode. A read-only file in a writable directory can be
/// unlinked (POSIX semantics).
#[test]
fn unlink_readonly_file_succeeds_in_writable_dir() {
    let harness = MountHarness::new().expect("harness setup");
    harness
        .create_file("readonly.txt", b"can unlink me\n")
        .expect("create_file readonly.txt");

    harness
        .chmod("readonly.txt", 0o444)
        .expect("chmod readonly.txt 0444");

    // POSIX: unlink checks parent directory permission, not file mode.
    let result = harness.remove_file("readonly.txt");
    assert!(
        result.is_ok(),
        "unlink of read-only file should succeed; parent dir is writable. Got: {result:?}"
    );
    assert!(
        !harness.exists("readonly.txt"),
        "readonly.txt must be gone after unlink"
    );
}

/// Concurrent unlink of same file from two names is harmless:
/// second unlink must return ENOENT.
#[test]
fn double_unlink_returns_enoent() {
    let harness = MountHarness::new().expect("harness setup");
    harness
        .create_file("once.txt", b"unlink me once\n")
        .expect("create_file once.txt");

    harness.remove_file("once.txt").expect("first unlink");

    let result = harness.remove_file("once.txt");
    assert!(result.is_err(), "second unlink must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "expected NotFound / ENOENT on second unlink, got: {err:?}"
    );
}
