// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE readdir/statfs/xattr integration test.
//!
//! Exercises the advancement criteria for the `fuse-readdir-statfs-xattr`
//! focus surface through a real read-write FUSE mount:
//!
//!   1. readdir returns correct entries for directories of varying depth
//!      and entry count.
//!   2. readdirplus returns entries with attributes (stat on returned
//!      entries verifies the inode/attribute path).
//!   3. statfs returns coherent filesystem statistics.
//!   4. getxattr/listxattr/setxattr/removexattr complete successfully.
//!
//! This test is the final advancement criterion for the
//! `fuse-readdir-statfs-xattr` focus surface.

use std::os::unix::fs::PermissionsExt;
use tidefs_validation::mount_harness::MountHarness;

// ── readdir: directory hierarchy ──────────────────────────────────────────

/// Create a small directory tree and verify readdir returns correct entries
/// including `.` and `..` (readdir filters those out, so we assert on the
/// filtered set) at each level.
#[test]
fn readdir_deep_hierarchy() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP readdir_deep_hierarchy: daemon not available -- {e}");
            return;
        }
    };

    // Build: a/ b/ c/ a/aa.txt a/ab.txt b/ba.txt b/bb.txt b/bc.txt c/ca.txt
    harness.mkdir("a").expect("mkdir a");
    harness.mkdir("b").expect("mkdir b");
    harness.mkdir("c").expect("mkdir c");
    harness
        .create_file("a/aa.txt", b"aa content\n")
        .expect("create a/aa.txt");
    harness
        .create_file("a/ab.txt", b"ab content\n")
        .expect("create a/ab.txt");
    harness
        .create_file("b/ba.txt", b"ba content\n")
        .expect("create b/ba.txt");
    harness
        .create_file("b/bb.txt", b"bb content\n")
        .expect("create b/bb.txt");
    harness
        .create_file("b/bc.txt", b"bc content\n")
        .expect("create b/bc.txt");
    harness
        .create_file("c/ca.txt", b"ca content\n")
        .expect("create c/ca.txt");

    // Read root directory — expect a, b, c (sorted).
    let root = harness.readdir(".").expect("readdir root");
    assert_eq!(
        root,
        vec!["a", "b", "c"],
        "root must contain three subdirs sorted"
    );

    // Read dir a.
    let a_entries = harness.readdir("a").expect("readdir a");
    assert_eq!(
        a_entries,
        vec!["aa.txt", "ab.txt"],
        "dir a must contain aa.txt and ab.txt"
    );

    // Read dir b.
    let b_entries = harness.readdir("b").expect("readdir b");
    assert_eq!(
        b_entries,
        vec!["ba.txt", "bb.txt", "bc.txt"],
        "dir b must contain three files sorted"
    );

    // Read dir c.
    let c_entries = harness.readdir("c").expect("readdir c");
    assert_eq!(c_entries, vec!["ca.txt"], "dir c must contain ca.txt");
}

/// readdir on an empty directory should return no entries (other than
/// `.` and `..`, which the harness filters).
#[test]
fn readdir_empty_directory() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP readdir_empty_directory: daemon not available -- {e}");
            return;
        }
    };

    harness.mkdir("empty").expect("mkdir empty");
    let entries = harness.readdir("empty").expect("readdir empty");
    assert!(entries.is_empty(), "empty dir must have zero entries");
}

/// readdir on root with multiple files and dirs.
#[test]
fn readdir_mixed_root() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP readdir_mixed_root: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("root_file_1.txt", b"r1\n")
        .expect("create root_file_1");
    harness.mkdir("sub_x").expect("mkdir sub_x");
    harness
        .create_file("root_file_2.txt", b"r2\n")
        .expect("create root_file_2");
    harness.mkdir("sub_y").expect("mkdir sub_y");

    let root = harness.readdir(".").expect("readdir root");
    assert_eq!(
        root,
        vec!["root_file_1.txt", "root_file_2.txt", "sub_x", "sub_y"],
        "root must contain files and dirs sorted"
    );
}

// ── readdirplus: attributes via stat ──────────────────────────────────────

/// readdirplus is exercised implicitly: after listing via readdir, stat each
/// returned entry to verify the inode attributes are reachable through the
/// FUSE path.  The kernel may or may not issue READDIRPLUS depending on
/// its heuristic, but stat on each entry proves the attribute path works.
#[test]
fn readdirplus_attributes_accessible() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP readdirplus_attributes_accessible: daemon not available -- {e}");
            return;
        }
    };

    harness.mkdir("d").expect("mkdir d");
    harness
        .create_file("d/f1.txt", b"file one\n")
        .expect("create f1.txt");
    harness
        .create_file("d/f2.txt", b"file two\n")
        .expect("create f2.txt");

    let entries = harness.readdir("d").expect("readdir d");
    assert!(!entries.is_empty(), "dir d must have entries");

    for name in &entries {
        let full = format!("d/{name}");
        let md = harness
            .stat(&full)
            .unwrap_or_else(|_| panic!("stat {full}"));

        // Each entry must resolve to either a regular file or directory.
        assert!(
            md.is_file() || md.is_dir(),
            "{full}: must be a file or directory"
        );

        // Permission bits must be nonzero.
        let mode = md.permissions().mode();
        assert!(mode != 0, "{full}: mode must be nonzero");

        // Size must be accessible (could be 0 for empty, but should be Ok).
        let _size = md.len();
    }
}

// ── statfs ────────────────────────────────────────────────────────────────

/// statfs on the mount root must return nonzero block counts, a reasonable
/// name-max length, and a nonzero filesystem type.
#[test]
fn statfs_coherent() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP statfs_coherent: daemon not available -- {e}");
            return;
        }
    };

    let s = harness.statfs().expect("statfs mount root");

    // Block size must be nonzero and a power of two (or at least >0).
    assert!(s.f_bsize > 0, "f_bsize must be nonzero, got {}", s.f_bsize);

    // Total blocks must be nonzero — the filesystem is non-empty.
    assert!(
        s.f_blocks > 0,
        "f_blocks must be nonzero (filesystem has blocks), got {}",
        s.f_blocks
    );

    // Free blocks should be <= total blocks.
    assert!(
        s.f_bfree <= s.f_blocks,
        "f_bfree ({}) must not exceed f_blocks ({})",
        s.f_bfree,
        s.f_blocks
    );

    // Available blocks should be <= free blocks.
    assert!(
        s.f_bavail <= s.f_bfree,
        "f_bavail ({}) must not exceed f_bfree ({})",
        s.f_bavail,
        s.f_bfree
    );

    // Name max must be at least 8 (POSIX minimum) and reasonable (< 4096).
    assert!(
        s.f_namelen >= 8,
        "f_namelen ({}) must be at least 8",
        s.f_namelen
    );
    assert!(
        s.f_namelen <= 4096,
        "f_namelen ({}) must be <= 4096",
        s.f_namelen
    );

    // Filesystem type must be nonzero (any mounted FS has a magic number).
    // FUSE filesystems typically report FUSE_SUPER_MAGIC (0x65735546).
    assert!(
        s.f_type != 0,
        "f_type must be nonzero (filesystem magic), got {:#x}",
        s.f_type
    );
}

/// statfs should be callable multiple times with consistent results.
#[test]
fn statfs_idempotent() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP statfs_idempotent: daemon not available -- {e}");
            return;
        }
    };

    let s1 = harness.statfs().expect("statfs call 1");
    let s2 = harness.statfs().expect("statfs call 2");

    assert_eq!(s1.f_bsize, s2.f_bsize, "f_bsize must be stable");
    assert_eq!(s1.f_namelen, s2.f_namelen, "f_namelen must be stable");
    assert_eq!(s1.f_type, s2.f_type, "f_type must be stable");
}

// ── xattr: round-trip cycle ───────────────────────────────────────────────

/// setxattr → getxattr → listxattr → removexattr cycle on a regular file.
#[test]
fn xattr_full_cycle() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_full_cycle: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("xattr_test.txt", b"xattr test file\n")
        .expect("create xattr_test.txt");

    let attr_name = "test.cycle";
    let attr_value = b"hello xattr value 42!";

    // Phase 1: set xattr.
    harness
        .set_xattr("xattr_test.txt", attr_name, attr_value)
        .expect("setxattr");

    // Phase 2: list xattrs — must include the newly set attribute.
    let list = harness.list_xattr("xattr_test.txt").expect("listxattr");
    assert!(
        list.contains(&attr_name.to_string()),
        "listxattr must contain '{attr_name}', got {list:?}"
    );

    // Phase 3: get xattr — must return exact value.
    let got = harness
        .get_xattr("xattr_test.txt", attr_name)
        .expect("getxattr");
    let got = got.expect("getxattr returned None for existing attribute");
    assert_eq!(got, attr_value, "getxattr value mismatch for '{attr_name}'");

    // Phase 4: remove xattr.
    harness
        .remove_xattr("xattr_test.txt", attr_name)
        .expect("removexattr");

    // Phase 5: confirm absent after removal.
    let list_after = harness
        .list_xattr("xattr_test.txt")
        .expect("listxattr after remove");
    assert!(
        !list_after.contains(&attr_name.to_string()),
        "listxattr after remove must not contain '{attr_name}'"
    );

    let got_after = harness
        .get_xattr("xattr_test.txt", attr_name)
        .expect("getxattr after remove");
    assert!(
        got_after.is_none(),
        "getxattr after remove must return None for '{attr_name}'"
    );
}

/// Multiple xattrs on the same file: set, list, verify, remove individually.
#[test]
fn xattr_multiple_attrs() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_multiple_attrs: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("multi_xattr.txt", b"multi xattr file\n")
        .expect("create multi_xattr.txt");

    let attrs: Vec<(&str, &[u8])> = vec![
        ("alpha", b"first attribute"),
        ("beta", b"second attribute"),
        ("gamma", &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
    ];

    // Set all.
    for (name, val) in &attrs {
        harness
            .set_xattr("multi_xattr.txt", name, val)
            .unwrap_or_else(|e| panic!("setxattr {name}: {e}"));
    }

    // List all — must contain every name.
    let list = harness.list_xattr("multi_xattr.txt").expect("listxattr");
    for (name, _) in &attrs {
        assert!(
            list.contains(&name.to_string()),
            "listxattr must contain '{name}'"
        );
    }

    // Get each and verify value.
    for (name, expected) in &attrs {
        let got = harness
            .get_xattr("multi_xattr.txt", name)
            .unwrap_or_else(|_| panic!("getxattr {name}"));
        let got = got.unwrap_or_else(|| panic!("getxattr {name} returned None"));
        assert_eq!(got, *expected, "getxattr value mismatch for '{name}'");
    }

    // Remove first attribute, verify others survive.
    harness
        .remove_xattr("multi_xattr.txt", "alpha")
        .expect("removexattr alpha");
    let list = harness
        .list_xattr("multi_xattr.txt")
        .expect("listxattr after remove");
    assert!(
        !list.contains(&"alpha".to_string()),
        "alpha must be removed"
    );
    assert!(list.contains(&"beta".to_string()), "beta must survive");
    assert!(list.contains(&"gamma".to_string()), "gamma must survive");

    // Remove remaining.
    harness
        .remove_xattr("multi_xattr.txt", "beta")
        .expect("removexattr beta");
    harness
        .remove_xattr("multi_xattr.txt", "gamma")
        .expect("removexattr gamma");

    let list = harness
        .list_xattr("multi_xattr.txt")
        .expect("listxattr after all removes");
    assert!(
        list.is_empty(),
        "xattr list must be empty after all removes"
    );
}

/// getxattr on a non-existent attribute must return None (not error).
#[test]
fn xattr_get_missing_returns_none() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_get_missing_returns_none: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("missing_xattr.txt", b"no xattrs here\n")
        .expect("create missing_xattr.txt");

    let result = harness
        .get_xattr("missing_xattr.txt", "nonexistent")
        .expect("getxattr call");
    assert!(
        result.is_none(),
        "getxattr on missing attribute must return None"
    );
}

/// listxattr on a file with no user xattrs must return empty list.
#[test]
fn xattr_list_empty_on_clean_file() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_list_empty_on_clean_file: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("clean.txt", b"no xattrs\n")
        .expect("create clean.txt");

    let list = harness.list_xattr("clean.txt").expect("listxattr");
    assert!(
        list.is_empty(),
        "listxattr on clean file must return empty list"
    );
}

// ── xattr: large value round-trip ─────────────────────────────────────

/// Set, get, and verify a 64 KiB extended attribute value through the
/// FUSE mount.  Larger xattrs stress the kernel buffer path and the
/// daemon's value-encoding path.
#[test]
fn xattr_large_value_roundtrip() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_large_value_roundtrip: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("large_xattr.bin", b"large xattr test\n")
        .expect("create large_xattr.bin");

    let attr_name = "large.64k";
    let large_value: Vec<u8> = (0..65536u32)
        .map(|i| ((i.wrapping_mul(0x9E3779B9).wrapping_add(0x7F4A7C13)) >> 16) as u8)
        .collect();
    assert_eq!(large_value.len(), 65536);

    harness
        .set_xattr("large_xattr.bin", attr_name, &large_value)
        .expect("setxattr 64KB value");

    let got = harness
        .get_xattr("large_xattr.bin", attr_name)
        .expect("getxattr 64KB value")
        .expect("getxattr 64KB returned None");
    assert_eq!(got.len(), 65536, "length mismatch for 64KB xattr");
    assert_eq!(got, large_value, "value mismatch for 64KB xattr");

    let list = harness
        .list_xattr("large_xattr.bin")
        .expect("listxattr after large set");
    assert!(
        list.contains(&attr_name.to_string()),
        "listxattr must contain '{attr_name}'"
    );
}

// ── xattr: empty value (zero-length) round-trip ───────────────────────

/// Setting an empty value must succeed, and getxattr must return a
/// zero-length buffer (not None and not an error).
#[test]
fn xattr_empty_value_set_and_get() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_empty_value_set_and_get: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("empty_xattr.txt", b"empty xattr test\n")
        .expect("create empty_xattr.txt");

    let attr_name = "empty.val";
    let empty: &[u8] = &[];

    harness
        .set_xattr("empty_xattr.txt", attr_name, empty)
        .expect("setxattr empty value");

    let got = harness
        .get_xattr("empty_xattr.txt", attr_name)
        .expect("getxattr empty value")
        .expect("getxattr empty returned None");
    assert!(
        got.is_empty(),
        "getxattr empty value must return zero-length buffer, got {} bytes",
        got.len()
    );

    // List must still include the key (empty value is a real attribute).
    let list = harness
        .list_xattr("empty_xattr.txt")
        .expect("listxattr after empty set");
    assert!(
        list.contains(&attr_name.to_string()),
        "listxattr must contain '{attr_name}' even with empty value"
    );

    // Remove and verify gone.
    harness
        .remove_xattr("empty_xattr.txt", attr_name)
        .expect("removexattr empty");
    let list_after = harness
        .list_xattr("empty_xattr.txt")
        .expect("listxattr after remove");
    assert!(!list_after.contains(&attr_name.to_string()));
}

// ── xattr: overwrite existing attribute ───────────────────────────────

/// setxattr with XATTR_CREATE flag 0 must overwrite an existing
/// attribute without error.
#[test]
fn xattr_overwrite_existing() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_overwrite_existing: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("overwrite_xattr.txt", b"overwrite test\n")
        .expect("create overwrite_xattr.txt");

    let attr_name = "overwrite.key";
    let first_value = b"first value 12345";
    let second_value = b"second value - overwritten!";

    harness
        .set_xattr("overwrite_xattr.txt", attr_name, first_value)
        .expect("first setxattr");

    harness
        .set_xattr("overwrite_xattr.txt", attr_name, second_value)
        .expect("second setxattr (overwrite)");

    let got = harness
        .get_xattr("overwrite_xattr.txt", attr_name)
        .expect("getxattr after overwrite")
        .expect("getxattr after overwrite returned None");
    assert_eq!(
        got, second_value,
        "value after overwrite must be the second value"
    );

    let list = harness
        .list_xattr("overwrite_xattr.txt")
        .expect("listxattr after overwrite");
    let count = list.iter().filter(|n| n.as_str() == attr_name).count();
    assert_eq!(
        count, 1,
        "key '{attr_name}' must appear exactly once after overwrite"
    );
}

// ── xattr: persistence across fsync + remount ─────────────────────────

/// Set xattrs on a file, fsync it, gracefully unmount, remount the same
/// backing store, and verify all xattr data survived.
#[test]
fn xattr_persistence_fsync_remount() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_persistence_fsync_remount: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("persist_xattr.bin", b"persistence test file\n")
        .expect("create persist_xattr.bin");

    let attrs: Vec<(&str, &[u8])> = vec![
        ("persist.alpha", b"alpha persistent value"),
        ("persist.beta", b"beta persistent value"),
        ("persist.gamma", &[0xDE, 0xAD, 0xBE, 0xEF]),
    ];

    for (name, val) in &attrs {
        harness
            .set_xattr("persist_xattr.bin", name, val)
            .unwrap_or_else(|e| panic!("setxattr {name}: {e}"));
    }

    harness
        .fsync_file("persist_xattr.bin")
        .expect("fsync persist_xattr.bin");

    harness.unmount_only(true).expect("unmount session 1");

    harness.remount().expect("remount session 2");

    for (name, expected) in &attrs {
        let got = harness
            .get_xattr("persist_xattr.bin", name)
            .unwrap_or_else(|e| panic!("getxattr {name} after remount: {e}"))
            .unwrap_or_else(|| panic!("getxattr {name} returned None after remount"));
        assert_eq!(
            got, *expected,
            "xattr '{name}' value mismatch after fsync + remount"
        );
    }

    let list = harness
        .list_xattr("persist_xattr.bin")
        .expect("listxattr after remount");
    for (name, _) in &attrs {
        assert!(
            list.contains(&name.to_string()),
            "listxattr after remount must contain '{name}'"
        );
    }
}

// ── xattr: crash recovery (SIGKILL + remount) ─────────────────────────

/// Set xattrs, fsync, SIGKILL the daemon, remount, and verify all xattr
/// data survived the crash byte-for-byte.
#[test]
fn xattr_crash_recovery_sigkill() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_crash_recovery_sigkill: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("crash_xattr.bin", b"crash recovery xattr test\n")
        .expect("create crash_xattr.bin");

    let attr_name = "crash.survive";
    let attr_value: Vec<u8> = (0..256).map(|i| (i as u8).wrapping_mul(3)).collect();

    harness
        .set_xattr("crash_xattr.bin", attr_name, &attr_value)
        .expect("setxattr before crash");

    harness
        .fsync_file("crash_xattr.bin")
        .expect("fsync before crash");

    harness.crash_and_remount().expect("crash_and_remount");

    let got = harness
        .get_xattr("crash_xattr.bin", attr_name)
        .expect("getxattr after crash")
        .unwrap_or_else(|| panic!("getxattr {attr_name} returned None after crash recovery"));
    assert_eq!(
        got, attr_value,
        "xattr value mismatch after SIGKILL + remount"
    );

    let list = harness
        .list_xattr("crash_xattr.bin")
        .expect("listxattr after crash recovery");
    assert!(
        list.contains(&attr_name.to_string()),
        "listxattr after crash must contain '{attr_name}'"
    );
}

// ── xattr: namespace rejection (trusted.* without CAP_SYS_ADMIN) ────────

/// Attempting to set a `trusted.*` xattr (without CAP_SYS_ADMIN) must
/// fail.  The harness helpers auto-prefix with `user.`, so this test
/// calls libc::setxattr directly with a raw `trusted.` prefix.
#[test]
fn xattr_namespace_rejection_trusted() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_namespace_rejection_trusted: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("reject_trusted.txt", b"trusted xattr rejection test\n")
        .expect("create reject_trusted.txt");

    let path = harness.mount_path().join("reject_trusted.txt");
    let path_c =
        std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("path with nul");
    let trusted_name = std::ffi::CString::new("trusted.reject.test").expect("name with nul");
    let val: &[u8] = b"should fail";

    // SAFETY: setxattr is a C FFI call; path_c and trusted_name are valid
    // CStrings; val is a valid slice; flags=0 per POSIX.
    let rc = unsafe {
        libc::setxattr(
            path_c.as_ptr(),
            trusted_name.as_ptr(),
            val.as_ptr() as *const libc::c_void,
            val.len(),
            0,
        )
    };

    assert_ne!(
        rc, 0,
        "setxattr with trusted.* must fail without CAP_SYS_ADMIN"
    );
    let err = std::io::Error::last_os_error();
    let ecode = err.raw_os_error().unwrap_or(0);
    assert!(
        ecode == libc::EPERM || ecode == libc::EACCES || ecode == libc::EOPNOTSUPP,
        "expected EPERM, EACCES, or EOPNOTSUPP for trusted.*, got {ecode}: {err}"
    );

    // User.* must still work on the same file (proving the file is valid).
    harness
        .set_xattr("reject_trusted.txt", "still.ok", b"user attrs work")
        .expect("user.* setxattr must succeed");

    let got = harness
        .get_xattr("reject_trusted.txt", "still.ok")
        .expect("getxattr user attr")
        .expect("getxattr user attr returned None");
    assert_eq!(got, b"user attrs work");
}

// ── xattr: listxattr excludes non-user namespaces ───────────────────────

/// The harness list_xattr helper strips the `user.` prefix.  This test
/// verifies that only user-namespace attributes are returned.
#[test]
fn xattr_listxattr_user_namespace_only() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_listxattr_user_namespace_only: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("ns_only.txt", b"namespace filter test\n")
        .expect("create ns_only.txt");

    let list = harness
        .list_xattr("ns_only.txt")
        .expect("listxattr on new file");
    assert!(
        list.is_empty(),
        "listxattr on fresh file must be empty, got {list:?}"
    );

    harness
        .set_xattr("ns_only.txt", "visible.key", b"visible")
        .expect("setxattr visible.key");

    let list = harness
        .list_xattr("ns_only.txt")
        .expect("listxattr after set");
    assert_eq!(list, vec!["visible.key".to_string()]);

    harness
        .remove_xattr("ns_only.txt", "visible.key")
        .expect("removexattr visible.key");

    let list = harness
        .list_xattr("ns_only.txt")
        .expect("listxattr after remove");
    assert!(list.is_empty(), "list must be empty after remove");
}

// ── xattr: concurrent operations on the same file ──────────────────────

/// Open the same file through two independent FDs (via the mount path),
/// set xattrs on each, and verify operations interleave correctly without
/// deadlocks, lost updates, or corruption.
#[test]
fn xattr_concurrent_two_fds() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_concurrent_two_fds: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("concurrent_xattr.txt", b"concurrent test\n")
        .expect("create concurrent_xattr.txt");

    let file_path = harness.mount_path().join("concurrent_xattr.txt");

    let fd1 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open fd1");
    let fd2 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open fd2");

    use std::os::unix::io::AsRawFd;
    let raw1 = fd1.as_raw_fd();
    let raw2 = fd2.as_raw_fd();

    let fset = |fd: i32, name: &str, val: &[u8]| -> bool {
        let full = std::ffi::CString::new(format!("user.{name}")).expect("name with nul");
        // SAFETY: fsetxattr is a C FFI call; fd is valid; full is a valid
        // CString; val is a valid slice.
        let rc = unsafe {
            libc::fsetxattr(
                fd,
                full.as_ptr(),
                val.as_ptr() as *const libc::c_void,
                val.len(),
                0,
            )
        };
        rc == 0
    };

    let fget = |fd: i32, name: &str| -> Option<Vec<u8>> {
        let full = std::ffi::CString::new(format!("user.{name}")).expect("name with nul");
        // SAFETY: fgetxattr with null buf and size=0 returns required size
        // per POSIX; fd is valid; full is a valid CString.
        let size = unsafe { libc::fgetxattr(fd, full.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENODATA) {
                return None;
            }
            panic!("fgetxattr {name} fd={fd}: {err}");
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: fgetxattr is a C FFI call; fd is valid; full is a valid
        // CString; buf size matches the prior size query result.
        let rc = unsafe {
            libc::fgetxattr(
                fd,
                full.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        assert!(rc >= 0, "fgetxattr read {name} fd={fd}");
        buf.truncate(rc as usize);
        Some(buf)
    };

    assert!(
        fset(raw1, "concurrent.a", b"value from fd1"),
        "fset A via fd1"
    );
    assert!(
        fset(raw2, "concurrent.b", b"value from fd2"),
        "fset B via fd2"
    );

    let a1 = fget(raw1, "concurrent.a").expect("fd1 get A");
    assert_eq!(a1, b"value from fd1");
    let b1 = fget(raw1, "concurrent.b").expect("fd1 get B");
    assert_eq!(b1, b"value from fd2");
    let a2 = fget(raw2, "concurrent.a").expect("fd2 get A");
    assert_eq!(a2, b"value from fd1");
    let b2 = fget(raw2, "concurrent.b").expect("fd2 get B");
    assert_eq!(b2, b"value from fd2");

    assert!(
        fset(raw2, "concurrent.a", b"overwritten via fd2"),
        "overwrite A via fd2"
    );
    let a1_upd = fget(raw1, "concurrent.a").expect("fd1 get A after overwrite");
    assert_eq!(
        a1_upd, b"overwritten via fd2",
        "fd1 must see fd2's overwrite of A"
    );

    let name_b = std::ffi::CString::new("user.concurrent.b").expect("name with nul");
    // SAFETY: fremovexattr is a C FFI call; raw1 is a valid fd; name_b
    // is a valid CString.
    let rc = unsafe { libc::fremovexattr(raw1, name_b.as_ptr()) };
    assert_eq!(rc, 0, "fremovexattr B via fd1");

    let b2_after = fget(raw2, "concurrent.b");
    assert!(
        b2_after.is_none(),
        "fd2 must not see B after fd1 removed it"
    );

    let a1_after = fget(raw1, "concurrent.a").expect("fd1 get A after B removed");
    assert_eq!(a1_after, b"overwritten via fd2");
    let a2_after = fget(raw2, "concurrent.a").expect("fd2 get A after B removed");
    assert_eq!(a2_after, b"overwritten via fd2");
}

// ── xattr: setxattr on a directory ─────────────────────────────────────

/// Extended attributes in the `user.` namespace must be settable on
/// directories as well as regular files.
#[test]
fn xattr_set_on_directory() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP xattr_set_on_directory: daemon not available -- {e}");
            return;
        }
    };

    harness.mkdir("xattr_dir").expect("mkdir xattr_dir");

    let attr_name = "dir.meta";
    let attr_value = b"directory metadata";

    harness
        .set_xattr("xattr_dir", attr_name, attr_value)
        .expect("setxattr on directory");

    let got = harness
        .get_xattr("xattr_dir", attr_name)
        .expect("getxattr on directory")
        .expect("getxattr on directory returned None");
    assert_eq!(got, attr_value, "xattr value mismatch on directory");

    let list = harness
        .list_xattr("xattr_dir")
        .expect("listxattr on directory");
    assert!(list.contains(&attr_name.to_string()));

    harness
        .remove_xattr("xattr_dir", attr_name)
        .expect("removexattr on directory");

    let after = harness
        .list_xattr("xattr_dir")
        .expect("listxattr after remove");
    assert!(!after.contains(&attr_name.to_string()));
}

/// Full cycle exercising all advancement criteria:
///   1. Create a directory hierarchy with files.
///   2. readdir on each directory, assert correct entries.
///   3. statfs and assert coherent fields.
///   4. setxattr on a file, listxattr, getxattr, verify round-trip.
///   5. removexattr, verify absent.
///   6. Repeat readdir to confirm mutations don't break directory listing.
#[test]
fn readdir_statfs_xattr_full_cycle() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP readdir_statfs_xattr_full_cycle: daemon not available -- {e}");
            return;
        }
    };

    // ── Phase 1: build directory hierarchy ──────────────────────────
    harness.mkdir("proj").expect("mkdir proj");
    harness.mkdir("proj/src").expect("mkdir proj/src");
    harness.mkdir("proj/doc").expect("mkdir proj/doc");
    harness
        .create_file("proj/src/main.rs", b"fn main() {}\n")
        .expect("create main.rs");
    harness
        .create_file("proj/src/lib.rs", b"pub fn answer() -> u8 { 42 }\n")
        .expect("create lib.rs");
    harness
        .create_file("proj/doc/README.md", b"# Project\n")
        .expect("create README.md");
    harness
        .create_file("proj/Cargo.toml", b"[package]\nname = \"p\"\n")
        .expect("create Cargo.toml");

    // ── Phase 2: readdir at each level ──────────────────────────────
    let root = harness.readdir(".").expect("readdir root");
    assert_eq!(root, vec!["proj"], "root must contain proj/");

    let proj = harness.readdir("proj").expect("readdir proj");
    assert_eq!(
        proj,
        vec!["Cargo.toml", "doc", "src"],
        "proj must contain Cargo.toml, doc/, src/"
    );

    let src = harness.readdir("proj/src").expect("readdir proj/src");
    assert_eq!(
        src,
        vec!["lib.rs", "main.rs"],
        "proj/src must contain lib.rs and main.rs"
    );

    let doc = harness.readdir("proj/doc").expect("readdir proj/doc");
    assert_eq!(doc, vec!["README.md"], "proj/doc must contain README.md");

    // ── Phase 3: statfs ─────────────────────────────────────────────
    let s = harness.statfs().expect("statfs");
    assert!(s.f_bsize > 0, "f_bsize must be nonzero");
    assert!(s.f_blocks > 0, "f_blocks must be nonzero");
    assert!(s.f_bfree <= s.f_blocks, "f_bfree <= f_blocks");
    assert!(s.f_bavail <= s.f_bfree, "f_bavail <= f_bfree");
    assert!(s.f_namelen >= 8, "f_namelen must be >= 8");
    assert!(s.f_namelen <= 4096, "f_namelen must be <= 4096");
    assert!(s.f_type != 0, "f_type must be nonzero");

    // ── Phase 4: xattr cycle on a file in the hierarchy ─────────────
    let xattr_file = "proj/src/main.rs";
    let xattr_name = "author.signature";
    let xattr_value = b"alice <alice@example.com>";

    harness
        .set_xattr(xattr_file, xattr_name, xattr_value)
        .expect("setxattr on main.rs");

    let list = harness.list_xattr(xattr_file).expect("listxattr main.rs");
    assert!(
        list.contains(&xattr_name.to_string()),
        "listxattr must contain '{xattr_name}'"
    );

    let got = harness
        .get_xattr(xattr_file, xattr_name)
        .expect("getxattr main.rs")
        .expect("getxattr returned None");
    assert_eq!(got, xattr_value, "xattr value round-trip mismatch");

    harness
        .remove_xattr(xattr_file, xattr_name)
        .expect("removexattr main.rs");

    let list_after = harness
        .list_xattr(xattr_file)
        .expect("listxattr after remove");
    assert!(
        !list_after.contains(&xattr_name.to_string()),
        "xattr '{xattr_name}' must be absent after remove"
    );

    // ── Phase 5: re-readdir to confirm namespace stability ──────────
    let src_after = harness
        .readdir("proj/src")
        .expect("readdir proj/src after xattr");
    assert_eq!(
        src_after,
        vec!["lib.rs", "main.rs"],
        "proj/src must be unchanged after xattr ops"
    );
}
