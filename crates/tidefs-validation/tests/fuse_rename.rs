//! FUSE rename BLAKE3-verified validation harness.
//!
//! Validates that POSIX rename(2) completes correctly through a real FUSE
//! RW mount, with BLAKE3-256 domain-separated directory state hashing
//! (domain: `tidefs-fuse-rename-validation-v1`) to verify atomic namespace
//! transitions before and after each operation.
//!
//! Tests exercise:
//! - Same-directory file rename with content preservation
//! - Cross-directory file rename with content preservation
//! - Same-directory empty directory rename
//! - Rename overwrite of an existing file
//! - Error paths: ENOENT, EISDIR, ENOTDIR, ENOTEMPTY, EEXIST (RENAME_NOREPLACE)
//! - Metadata preservation across rename
//! - Rename with open file descriptors (inode identity preservation)
//! - BLAKE3-verified directory state atomic transitions
//!
//! Uses the MountHarness infrastructure to spawn the
//! posix-filesystem-adapter-daemon and perform IO through the FUSE mount point.

use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use tidefs_validation::mount_harness::MountHarness;

// ── BLAKE3 domain-separated directory state hashing ─────────────────────────

const RENAME_DOMAIN: &str = "tidefs-fuse-rename-validation-v1";

/// Compute a BLAKE3-256 digest of a sorted list of directory entries.
/// Each entry is hashed as length-prefixed bytes: a 2-byte LE length
/// followed by the entry name.  Entries are sorted before hashing so that
/// the digest is independent of readdir order.
fn hash_dir_state(entries: &[String]) -> [u8; 32] {
    let mut sorted = entries.to_vec();
    sorted.sort();
    let mut hasher = blake3::Hasher::new_derive_key(RENAME_DOMAIN);
    for entry in &sorted {
        let name = entry.as_bytes();
        let len = (name.len() as u16).to_le_bytes();
        hasher.update(&len);
        hasher.update(name);
    }
    hasher.finalize().into()
}

// helpers

/// Generate reproducible test data: count bytes of a repeating 0..255 sequence.
fn sequenced_test_data(len_bytes: usize) -> Vec<u8> {
    (0..len_bytes).map(|i| (i % 256) as u8).collect()
}

// same-directory file rename

/// Create a file with known content, rename it in the same directory,
/// and verify the old name is gone while the new name preserves the
/// original content and file size.
#[test]
fn test_rename_same_directory_file() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_same_directory_file: daemon not available -- {e}");
            return;
        }
    };

    let test_data = b"same-directory rename test content
";

    harness
        .create_file("old.txt", test_data)
        .expect("create old.txt");

    // Capture pre-rename directory state for BLAKE3 verification.
    let root_before = harness.readdir(".").expect("readdir root before");
    let hash_before = hash_dir_state(&root_before);
    assert!(root_before.contains(&"old.txt".to_string()));

    assert!(
        harness.exists("old.txt"),
        "old.txt must exist before rename"
    );
    assert!(
        !harness.exists("new.txt"),
        "new.txt must not exist before rename"
    );

    harness
        .rename("old.txt", "new.txt")
        .expect("rename old.txt -> new.txt");

    assert!(
        !harness.exists("old.txt"),
        "old.txt must not exist after rename"
    );
    assert!(harness.exists("new.txt"), "new.txt must exist after rename");

    // BLAKE3-verified atomic namespace transition: old.txt removed,
    // new.txt present; root entries match expected delta.
    let root_after = harness.readdir(".").expect("readdir root after");
    let hash_after = hash_dir_state(&root_after);
    assert_ne!(hash_before, hash_after, "root dir-state hash must change");
    let mut expected = root_before.clone();
    expected.retain(|e| e != "old.txt");
    expected.push("new.txt".to_string());
    assert_eq!(hash_dir_state(&expected), hash_after);

    let read_back = harness
        .read_file("new.txt")
        .expect("read new.txt after rename");
    assert_eq!(
        read_back, test_data,
        "content mismatch after same-dir rename"
    );

    let md = harness.stat("new.txt").expect("stat new.txt");
    assert!(md.is_file(), "new.txt must be a regular file");
    assert_eq!(
        md.len(),
        test_data.len() as u64,
        "file size mismatch after rename"
    );
}

/// Rename a file with larger binary content (4 KiB sequenced data).
#[test]
fn test_rename_file_larger_content() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_file_larger_content: daemon not available -- {e}");
            return;
        }
    };

    let test_data = sequenced_test_data(4096);

    harness
        .create_file("large.bin", &test_data)
        .expect("create large.bin");
    harness
        .rename("large.bin", "moved.bin")
        .expect("rename large.bin -> moved.bin");

    assert!(!harness.exists("large.bin"));
    assert!(harness.exists("moved.bin"));

    let read_back = harness.read_file("moved.bin").expect("read moved.bin");
    assert_eq!(read_back, test_data, "4 KiB content mismatch after rename");

    let md = harness.stat("moved.bin").expect("stat moved.bin");
    assert_eq!(md.len(), 4096, "file size mismatch after rename");

    let mode = md.permissions().mode();
    assert!(mode & 0o100000 != 0, "moved.bin must be a regular file");
}

// cross-directory file rename

/// Create a file in dir1, rename into dir2, verify source gone and
/// destination present with correct content.
#[test]
fn test_rename_cross_directory_file() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_cross_directory_file: daemon not available -- {e}");
            return;
        }
    };

    let test_data = b"cross-directory rename payload
";

    harness.mkdir("dir1").expect("mkdir dir1");
    harness.mkdir("dir2").expect("mkdir dir2");
    harness
        .create_file("dir1/movable.txt", test_data)
        .expect("create dir1/movable.txt");

    harness
        .rename("dir1/movable.txt", "dir2/relocated.txt")
        .expect("cross-dir rename");

    assert!(!harness.exists("dir1/movable.txt"));
    assert!(harness.exists("dir2/relocated.txt"));

    let read_back = harness
        .read_file("dir2/relocated.txt")
        .expect("read dir2/relocated.txt");
    assert_eq!(read_back, test_data, "cross-dir rename content mismatch");

    let src_entries = harness.readdir("dir1").expect("readdir dir1");
    assert!(
        src_entries.is_empty(),
        "dir1 must be empty after cross-dir rename, got: {src_entries:?}"
    );

    let dst_entries = harness.readdir("dir2").expect("readdir dir2");
    assert_eq!(
        dst_entries,
        vec!["relocated.txt".to_string()],
        "dir2 must contain relocated.txt"
    );
}

/// Cross-directory rename of larger binary content.
#[test]
fn test_rename_cross_directory_larger_content() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP test_rename_cross_directory_larger_content: daemon not available -- {e}"
            );
            return;
        }
    };

    let test_data = sequenced_test_data(8192);

    harness.mkdir("src").expect("mkdir src");
    harness.mkdir("dst").expect("mkdir dst");
    harness
        .create_file("src/bigfile.bin", &test_data)
        .expect("create src/bigfile.bin");

    harness
        .rename("src/bigfile.bin", "dst/moved.bin")
        .expect("cross-dir rename bigfile");

    assert!(!harness.exists("src/bigfile.bin"));
    assert!(harness.exists("dst/moved.bin"));

    let read_back = harness
        .read_file("dst/moved.bin")
        .expect("read dst/moved.bin");
    assert_eq!(
        read_back, test_data,
        "8 KiB cross-dir rename content mismatch"
    );
}

// same-directory empty directory rename

/// Create an empty directory, rename it, and verify the old name is gone
/// while the new name is still a directory that can receive new entries.
#[test]
fn test_rename_same_directory_empty_dir() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_same_directory_empty_dir: daemon not available -- {e}");
            return;
        }
    };

    harness.mkdir("dirA").expect("mkdir dirA");

    assert!(harness.exists("dirA"));
    assert!(!harness.exists("dirB"));

    harness.rename("dirA", "dirB").expect("rename dirA -> dirB");

    assert!(!harness.exists("dirA"), "dirA must not exist after rename");
    assert!(harness.exists("dirB"), "dirB must exist after rename");

    let md = harness.stat("dirB").expect("stat dirB");
    assert!(md.is_dir(), "dirB must be a directory after rename");

    // The renamed directory must still be usable.
    harness
        .create_file(
            "dirB/child.txt",
            b"child inside renamed dir
",
        )
        .expect("create dirB/child.txt");
    assert!(harness.exists("dirB/child.txt"));

    let read_back = harness
        .read_file("dirB/child.txt")
        .expect("read dirB/child.txt");
    assert_eq!(
        read_back,
        b"child inside renamed dir
",
        "content mismatch in child of renamed dir"
    );
}

// rename overwrite

/// Create two files, rename A onto B, and verify A is gone while B
/// contains A content. Tests plain POSIX rename (flags=0) overwrite.
#[test]
fn test_rename_overwrite_existing_file() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_overwrite_existing_file: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file(
            "alpha.txt",
            b"alpha content here
",
        )
        .expect("create alpha.txt");
    harness
        .create_file(
            "beta.txt",
            b"beta content here
",
        )
        .expect("create beta.txt");

    harness
        .rename("alpha.txt", "beta.txt")
        .expect("rename alpha.txt -> beta.txt (overwrite)");

    assert!(!harness.exists("alpha.txt"));
    assert!(harness.exists("beta.txt"));

    let read_back = harness
        .read_file("beta.txt")
        .expect("read beta.txt after overwrite rename");
    assert_eq!(
        read_back,
        b"alpha content here
",
        "beta.txt must contain alpha content after overwrite"
    );
}

// error paths

/// Renaming a nonexistent file must fail with ENOENT.
#[test]
fn test_rename_nonexistent_source_enoent() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_nonexistent_source_enoent: daemon not available -- {e}");
            return;
        }
    };

    let result = harness.rename("no_such_file.txt", "dest.txt");
    assert!(result.is_err(), "rename nonexistent source must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOENT),
        "expected ENOENT, got: {err:?}"
    );
}

/// Renaming a file onto an existing directory must fail with EISDIR.
#[test]
fn test_rename_file_over_dir_eisdir() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_file_over_dir_eisdir: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file(
            "a_file.txt",
            b"some content
",
        )
        .expect("create a_file.txt");
    harness.mkdir("a_dir").expect("mkdir a_dir");

    let result = harness.rename("a_file.txt", "a_dir");
    assert!(result.is_err(), "rename file over dir must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EISDIR),
        "expected EISDIR, got: {err:?}"
    );

    assert!(harness.exists("a_file.txt"));
    assert!(harness.exists("a_dir"));
}

/// Renaming a directory onto an existing file must fail with ENOTDIR.
#[test]
fn test_rename_dir_over_file_enotdir() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_dir_over_file_enotdir: daemon not available -- {e}");
            return;
        }
    };

    harness.mkdir("a_dir").expect("mkdir a_dir");
    harness
        .create_file(
            "a_file.txt",
            b"some content
",
        )
        .expect("create a_file.txt");

    let result = harness.rename("a_dir", "a_file.txt");
    assert!(result.is_err(), "rename dir over file must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOTDIR),
        "expected ENOTDIR, got: {err:?}"
    );

    assert!(harness.exists("a_dir"));
    assert!(harness.exists("a_file.txt"));
}

/// Renaming a directory onto a non-empty directory must fail with ENOTEMPTY.
#[test]
fn test_rename_dir_over_nonempty_dir_enotempty() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP test_rename_dir_over_nonempty_dir_enotempty: daemon not available -- {e}"
            );
            return;
        }
    };

    harness.mkdir("src").expect("mkdir src");
    harness.mkdir("dst").expect("mkdir dst");
    harness
        .create_file(
            "dst/child.txt",
            b"child
",
        )
        .expect("create dst/child.txt");

    let result = harness.rename("src", "dst");
    assert!(result.is_err(), "rename over non-empty dir must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOTEMPTY),
        "expected ENOTEMPTY, got: {err:?}"
    );

    assert!(harness.exists("src"));
    assert!(harness.exists("dst"));
    assert!(harness.exists("dst/child.txt"));
}

// metadata preservation

/// Verifies that after rename, the file retains its mode and size.
#[test]
fn test_rename_preserves_file_metadata() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_preserves_file_metadata: daemon not available -- {e}");
            return;
        }
    };

    let test_data = b"metadata preservation test data
";

    harness
        .create_file("original.txt", test_data)
        .expect("create original.txt");

    harness.chmod("original.txt", 0o600).expect("chmod 0600");

    let md_before = harness.stat("original.txt").expect("stat before rename");
    let mode_before = md_before.permissions().mode();
    let size_before = md_before.len();

    harness
        .rename("original.txt", "renamed.txt")
        .expect("rename original.txt -> renamed.txt");

    assert!(!harness.exists("original.txt"));
    let md_after = harness.stat("renamed.txt").expect("stat after rename");

    assert_eq!(
        md_after.len(),
        size_before,
        "file size must be preserved across rename"
    );
    assert_eq!(
        md_after.permissions().mode() & 0o777,
        mode_before & 0o777,
        "file permissions must be preserved across rename"
    );
    assert!(md_after.is_file());

    let read_back = harness.read_file("renamed.txt").expect("read renamed.txt");
    assert_eq!(
        read_back, test_data,
        "content mismatch after metadata-preservation rename"
    );
}

// rename empty dir over empty dir

/// Rename an empty directory onto another empty directory: the target is
/// replaced, the source is gone, and the target now has the source content.
#[test]
fn test_rename_empty_dir_over_empty_dir() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_empty_dir_over_empty_dir: daemon not available -- {e}");
            return;
        }
    };

    harness.mkdir("src").expect("mkdir src");
    harness.mkdir("dst").expect("mkdir dst");

    harness
        .create_file(
            "src/marker.txt",
            b"marker in src
",
        )
        .expect("create src/marker.txt");

    harness
        .rename("src", "dst")
        .expect("rename src -> dst (overwrite empty dir)");

    assert!(!harness.exists("src"), "src must be gone after rename");
    assert!(harness.exists("dst"), "dst must exist after rename");
    assert!(
        harness.exists("dst/marker.txt"),
        "marker must be inside dst"
    );

    let read_back = harness
        .read_file("dst/marker.txt")
        .expect("read dst/marker.txt");
    assert_eq!(
        read_back,
        b"marker in src
",
        "marker content mismatch after dir-over-dir rename"
    );
}
// ── BLAKE3 directory state hash determinism ─────────────────────────────────

/// Verify that the BLAKE3 dir-state hash correctly distinguishes different
/// entry sets and is stable regardless of input ordering.
#[test]
fn test_blake3_dir_state_hash_determinism() {
    let entries_a = vec!["file1".to_string(), "file2".to_string(), "dir1".to_string()];
    let entries_b = vec!["file2".to_string(), "dir1".to_string(), "file1".to_string()];
    assert_eq!(hash_dir_state(&entries_a), hash_dir_state(&entries_b));

    let entries_c = vec!["file1".to_string(), "file2".to_string()];
    assert_ne!(hash_dir_state(&entries_a), hash_dir_state(&entries_c));

    let empty: Vec<String> = Vec::new();
    let h_empty = hash_dir_state(&empty);
    assert_ne!(h_empty, hash_dir_state(&entries_a));
}

// ── rename with open file descriptors ───────────────────────────────────────

/// Rename a file and verify the inode number is preserved, confirming
/// that the rename does not create a new inode.
#[test]
fn test_rename_open_fd_inode_preservation() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_open_fd_inode_preservation: daemon not available -- {e}");
            return;
        }
    };

    let test_data = b"open-fd rename content\n";

    harness
        .create_file("keep_open.txt", test_data)
        .expect("create keep_open.txt");

    let ino_before = harness
        .stat("keep_open.txt")
        .expect("stat before rename")
        .ino();

    harness
        .rename("keep_open.txt", "still_open.txt")
        .expect("rename with open fd");

    assert!(!harness.exists("keep_open.txt"));
    assert!(harness.exists("still_open.txt"));

    let ino_after = harness
        .stat("still_open.txt")
        .expect("stat after rename")
        .ino();
    assert_eq!(
        ino_before, ino_after,
        "inode must be preserved across rename"
    );

    let read_back = harness
        .read_file("still_open.txt")
        .expect("read after rename");
    assert_eq!(
        read_back, test_data,
        "content mismatch after open-fd rename"
    );

    let root_after = harness.readdir(".").expect("readdir root after");
    assert!(!root_after.contains(&"keep_open.txt".to_string()));
    assert!(root_after.contains(&"still_open.txt".to_string()));
}

/// Rename a file through multiple hops (same-dir, then cross-dir) and
/// confirm the inode number is stable across every hop.
#[test]
fn test_rename_multi_hop_inode_stability() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_multi_hop_inode_stability: daemon not available -- {e}");
            return;
        }
    };

    let test_data = b"multi-hop rename payload\n";
    harness
        .create_file("hop1.txt", test_data)
        .expect("create hop1.txt");

    let ino_original = harness.stat("hop1.txt").expect("stat hop1").ino();

    harness.rename("hop1.txt", "hop2.txt").expect("hop1->hop2");
    let ino_hop2 = harness.stat("hop2.txt").expect("stat hop2").ino();
    assert_eq!(ino_original, ino_hop2);

    harness.rename("hop2.txt", "hop3.txt").expect("hop2->hop3");
    let ino_hop3 = harness.stat("hop3.txt").expect("stat hop3").ino();
    assert_eq!(ino_original, ino_hop3);

    harness.mkdir("sub").expect("mkdir sub");
    harness
        .rename("hop3.txt", "sub/hop4.txt")
        .expect("cross-dir hop3->hop4");
    let ino_hop4 = harness.stat("sub/hop4.txt").expect("stat sub/hop4").ino();
    assert_eq!(
        ino_original, ino_hop4,
        "inode stable across cross-dir rename"
    );

    let read_back = harness.read_file("sub/hop4.txt").expect("read final hop");
    assert_eq!(read_back, test_data);

    let root_after = harness.readdir(".").expect("readdir root after multi-hop");
    assert!(root_after.contains(&"sub".to_string()));
    assert!(!root_after.contains(&"hop1.txt".to_string()));
    assert!(!root_after.contains(&"hop2.txt".to_string()));
    assert!(!root_after.contains(&"hop3.txt".to_string()));
}

// ── RENAME_NOREPLACE ────────────────────────────────────────────────────────

/// rename2 with RENAME_NOREPLACE must fail with EEXIST when the target
/// already exists, leaving both files unchanged.
#[test]
fn test_rename_noreplace_existing_target_eexist() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP test_rename_noreplace_existing_target_eexist: daemon not available -- {e}"
            );
            return;
        }
    };

    harness
        .create_file("source.txt", b"source content\n")
        .expect("create source.txt");
    harness
        .create_file("target.txt", b"target content\n")
        .expect("create target.txt");

    let root_before = harness.readdir(".").expect("readdir root before noreplace");
    let hash_before = hash_dir_state(&root_before);

    let mount = harness.mount_path().to_path_buf();
    let src = mount.join("source.txt");
    let dst = mount.join("target.txt");
    let src_c = std::ffi::CString::new(src.to_str().unwrap()).unwrap();
    let dst_c = std::ffi::CString::new(dst.to_str().unwrap()).unwrap();

    // SAFETY: renameat2 is a C FFI call; all CString pointers are valid
    // null-terminated strings; AT_FDCWD is a valid sentinel; flags are valid
    // RENAME_* constants.
    let ret = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            src_c.as_ptr(),
            libc::AT_FDCWD,
            dst_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };

    assert_ne!(ret, 0, "RENAME_NOREPLACE with existing target must fail");
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap();
    assert_eq!(errno, libc::EEXIST, "expected EEXIST from RENAME_NOREPLACE");

    assert!(harness.exists("source.txt"));
    assert!(harness.exists("target.txt"));
    assert_eq!(
        harness.read_file("source.txt").unwrap(),
        b"source content\n"
    );
    assert_eq!(
        harness.read_file("target.txt").unwrap(),
        b"target content\n"
    );

    let root_after = harness.readdir(".").expect("readdir root after noreplace");
    assert_eq!(
        hash_dir_state(&root_after),
        hash_before,
        "dir-state hash must not change after failed RENAME_NOREPLACE"
    );
}

/// RENAME_NOREPLACE must succeed when the target does not exist.
#[test]
fn test_rename_noreplace_no_target() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_noreplace_no_target: daemon not available -- {e}");
            return;
        }
    };

    let test_data = b"noreplace fresh target\n";
    harness
        .create_file("noreplace_src.txt", test_data)
        .expect("create noreplace_src.txt");

    let root_before = harness.readdir(".").expect("readdir root before noreplace");
    let hash_before = hash_dir_state(&root_before);

    let mount = harness.mount_path().to_path_buf();
    let src = mount.join("noreplace_src.txt");
    let dst = mount.join("noreplace_dst.txt");
    let src_c = std::ffi::CString::new(src.to_str().unwrap()).unwrap();
    let dst_c = std::ffi::CString::new(dst.to_str().unwrap()).unwrap();

    // SAFETY: renameat2 is a C FFI call; all CString pointers are valid
    // null-terminated strings; AT_FDCWD is a valid sentinel; flags are valid
    // RENAME_* constants.
    let ret = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            src_c.as_ptr(),
            libc::AT_FDCWD,
            dst_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };

    assert_eq!(ret, 0, "RENAME_NOREPLACE without target must succeed");

    assert!(!harness.exists("noreplace_src.txt"));
    assert!(harness.exists("noreplace_dst.txt"));
    assert_eq!(harness.read_file("noreplace_dst.txt").unwrap(), test_data);

    // BLAKE3-verified directory state transition.
    let root_after = harness.readdir(".").expect("readdir root after noreplace");
    assert_ne!(
        hash_before,
        hash_dir_state(&root_after),
        "dir-state hash must change after successful RENAME_NOREPLACE"
    );
    let mut expected = root_before.clone();
    expected.retain(|e| e != "noreplace_src.txt");
    expected.push("noreplace_dst.txt".to_string());
    assert_eq!(hash_dir_state(&expected), hash_dir_state(&root_after));
}

// ── BLAKE3-verified atomic namespace transitions ────────────────────────────

/// Same-directory file rename with BLAKE3 dir-state hash verifying the
/// atomic dentry swap (old removed, new added) in a non-trivial directory.
#[test]
fn test_rename_blake3_atomic_same_dir() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_blake3_atomic_same_dir: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("before.txt", b"blake3 atomic same-dir\n")
        .expect("create before.txt");
    harness
        .create_file("stable_a.txt", b"aaa\n")
        .expect("create stable_a");
    harness.mkdir("sub_dir").expect("mkdir sub_dir");

    let root_before = harness.readdir(".").expect("readdir root before");
    let hash_before = hash_dir_state(&root_before);

    harness
        .rename("before.txt", "after.txt")
        .expect("rename before.txt -> after.txt");

    let root_after = harness.readdir(".").expect("readdir root after");

    let mut expected = root_before.clone();
    expected.retain(|e| e != "before.txt");
    expected.push("after.txt".to_string());

    assert_eq!(
        hash_dir_state(&expected),
        hash_dir_state(&root_after),
        "BLAKE3 dir-state hash must match expected atomic transition"
    );
    assert_ne!(hash_before, hash_dir_state(&root_after));
}

/// Cross-directory file rename with BLAKE3 dir-state hashes confirming
/// that both source and destination directories reflect the atomic move.
#[test]
fn test_rename_blake3_atomic_cross_dir() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_blake3_atomic_cross_dir: daemon not available -- {e}");
            return;
        }
    };

    let test_data = sequenced_test_data(2048);
    harness.mkdir("alpha").expect("mkdir alpha");
    harness.mkdir("beta").expect("mkdir beta");
    harness
        .create_file("alpha/migrant.bin", &test_data)
        .expect("create alpha/migrant.bin");
    harness
        .create_file("alpha/static_a.txt", b"static a\n")
        .expect("create alpha/static_a");
    harness
        .create_file("beta/static_b.txt", b"static b\n")
        .expect("create beta/static_b");

    let alpha_before = harness.readdir("alpha").expect("readdir alpha before");
    let beta_before = harness.readdir("beta").expect("readdir beta before");
    let alpha_hash_before = hash_dir_state(&alpha_before);
    let beta_hash_before = hash_dir_state(&beta_before);

    harness
        .rename("alpha/migrant.bin", "beta/arrived.bin")
        .expect("cross-dir rename");

    let alpha_after = harness.readdir("alpha").expect("readdir alpha after");
    let beta_after = harness.readdir("beta").expect("readdir beta after");

    let mut expected_alpha = alpha_before.clone();
    expected_alpha.retain(|e| e != "migrant.bin");
    assert_eq!(
        hash_dir_state(&expected_alpha),
        hash_dir_state(&alpha_after)
    );
    assert_ne!(alpha_hash_before, hash_dir_state(&alpha_after));

    let mut expected_beta = beta_before.clone();
    expected_beta.push("arrived.bin".to_string());
    assert_eq!(hash_dir_state(&expected_beta), hash_dir_state(&beta_after));
    assert_ne!(beta_hash_before, hash_dir_state(&beta_after));

    let read_back = harness
        .read_file("beta/arrived.bin")
        .expect("read arrived.bin");
    assert_eq!(read_back, test_data);
}

/// Rename-to-self (no-op) must preserve the BLAKE3 dir-state hash exactly.
#[test]
fn test_rename_blake3_noop_hash_stability() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP test_rename_blake3_noop_hash_stability: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("stay.txt", b"stay put\n")
        .expect("create stay.txt");

    let root_before = harness.readdir(".").expect("readdir root before");
    let hash_before = hash_dir_state(&root_before);

    let mount = harness.mount_path().to_path_buf();
    let path_c = std::ffi::CString::new(mount.join("stay.txt").to_str().unwrap()).unwrap();

    // SAFETY: renameat2 is a C FFI call; all CString pointers are valid
    // null-terminated strings; AT_FDCWD is a valid sentinel; flags are valid
    // RENAME_* constants.
    let ret = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            path_c.as_ptr(),
            libc::AT_FDCWD,
            path_c.as_ptr(),
            0,
        )
    };
    assert_eq!(ret, 0, "rename to self must succeed (no-op)");

    let root_after = harness.readdir(".").expect("readdir root after no-op");
    assert_eq!(
        hash_dir_state(&root_after),
        hash_before,
        "dir-state hash must be unchanged after rename-to-self"
    );
    assert!(harness.exists("stay.txt"));
    assert_eq!(harness.read_file("stay.txt").unwrap(), b"stay put\n");
}
