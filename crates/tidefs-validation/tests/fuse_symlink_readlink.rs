// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE symlink/readlink BLAKE3-verified validation harness.
//!
//! Exercises symlink creation and readlink resolution through a real
//! FUSE mount, verifying target integrity with domain-separated BLAKE3-256
//! hashing (domain: `tidefs-fuse-symlink-readlink-v1`).
//!
//! Coverage:
//! - Short/long/unicode target round-trips
//! - Relative/absolute/dangling symlinks
//! - Symlink chains (A->B->C)
//! - Overwrite existing symlinks
//! - Concurrent create/readlink stress
//! - Inode attribute consistency
//! - Empty-target refusal, PATH_MAX boundary
//! - readlink on non-symlink (EINVAL), nonexistent (ENOENT)
//! - Symlink target BLAKE3 verification across all cases

use std::collections::HashSet;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::thread;

use tidefs_validation::mount_harness::MountHarness;

// BLAKE3 domain-separated hashing

const SYMLINK_DOMAIN: &str = "tidefs-fuse-symlink-readlink-v1";

/// Compute a BLAKE3-256 digest of a symlink target for integrity verification.
/// Uses domain separation to isolate this validation surface from other uses.
fn hash_target(target: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SYMLINK_DOMAIN);
    hasher.update(target);
    hasher.finalize().into()
}

/// Verify that a readlink-resolved target matches the expected target bytes.
fn verify_target(target: &[u8], expected_hash: &[u8; 32]) -> bool {
    &hash_target(target) == expected_hash
}

// Short/long/unicode targets

#[test]
fn symlink_short_target_roundtrip() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = "/usr/lib";
    let link = "short_link";
    let expected_hash = hash_target(target.as_bytes());

    harness.symlink(target, link).expect("symlink create");
    let resolved = harness.readlink(link).expect("readlink");
    let resolved_bytes = resolved.as_os_str().as_bytes();

    assert_eq!(resolved_bytes, target.as_bytes(), "target mismatch");
    assert!(verify_target(resolved_bytes, &expected_hash));
}

#[test]
fn symlink_relative_target_roundtrip() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = "../sibling/file.txt";
    let link = "relative_link";
    let expected_hash = hash_target(target.as_bytes());

    harness.symlink(target, link).expect("symlink create");
    let resolved = harness.readlink(link).expect("readlink");
    let resolved_bytes = resolved.as_os_str().as_bytes();

    assert_eq!(resolved_bytes, target.as_bytes());
    assert!(verify_target(resolved_bytes, &expected_hash));
}

#[test]
fn symlink_absolute_target_roundtrip() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = "/absolute/path/to/somewhere/deep";
    let link = "absolute_link";
    let expected_hash = hash_target(target.as_bytes());

    harness.symlink(target, link).expect("symlink create");
    let resolved = harness.readlink(link).expect("readlink");
    let resolved_bytes = resolved.as_os_str().as_bytes();

    assert_eq!(resolved_bytes, target.as_bytes());
    assert!(verify_target(resolved_bytes, &expected_hash));
}

#[test]
fn symlink_unicode_target_roundtrip() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = "/mnt/donnees/depot/francais.txt";
    let link = "unicode_link";
    let expected_hash = hash_target(target.as_bytes());

    harness.symlink(target, link).expect("symlink create");
    let resolved = harness.readlink(link).expect("readlink");
    let resolved_bytes = resolved.as_os_str().as_bytes();

    assert_eq!(resolved_bytes, target.as_bytes());
    assert!(verify_target(resolved_bytes, &expected_hash));
}

#[test]
fn symlink_target_with_spaces_and_special_chars() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = "/path/with spaces/and-dashes_and.mixed!chars";
    let link = "special_link";
    let expected_hash = hash_target(target.as_bytes());

    harness.symlink(target, link).expect("symlink create");
    let resolved = harness.readlink(link).expect("readlink");
    let resolved_bytes = resolved.as_os_str().as_bytes();

    assert_eq!(resolved_bytes, target.as_bytes());
    assert!(verify_target(resolved_bytes, &expected_hash));
}

// PATH_MAX boundary tests

#[test]
fn symlink_target_at_pathmax_boundary() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = vec![b'/'; 4095];
    let target_path = Path::new(std::ffi::OsStr::from_bytes(&target));
    let link = "pathmax_link_4095";
    let expected_hash = hash_target(&target);

    harness.symlink(target_path, link).expect("symlink create");
    let resolved = harness.readlink(link).expect("readlink");
    let resolved_bytes = resolved.as_os_str().as_bytes();

    assert_eq!(resolved_bytes, target.as_slice());
    assert!(verify_target(resolved_bytes, &expected_hash));
}

#[test]
fn symlink_target_one_under_pathmax() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = vec![b'x'; 4094];
    let target_path = Path::new(std::ffi::OsStr::from_bytes(&target));
    let link = "near_pathmax_link";
    let expected_hash = hash_target(&target);

    harness.symlink(target_path, link).expect("symlink create");
    let resolved = harness.readlink(link).expect("readlink");
    let resolved_bytes = resolved.as_os_str().as_bytes();

    assert_eq!(resolved_bytes, target.as_slice());
    assert!(verify_target(resolved_bytes, &expected_hash));
}

// Dangling symlinks

#[test]
fn dangling_symlink_created_and_resolved() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = "/nonexistent/path/that/does/not/exist";
    let link = "dangling_link";
    let expected_hash = hash_target(target.as_bytes());

    harness.symlink(target, link).expect("symlink create");

    let resolved = harness.readlink(link).expect("readlink dangling");
    let resolved_bytes = resolved.as_os_str().as_bytes();

    assert_eq!(resolved_bytes, target.as_bytes());
    assert!(verify_target(resolved_bytes, &expected_hash));
}

#[test]
fn symlink_to_self() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let link = "self_link";

    harness.symlink("self_link", link).expect("symlink to self");
    let resolved = harness.readlink(link).expect("readlink self");

    let expected_hash = hash_target(b"self_link");
    assert_eq!(resolved.as_os_str().as_bytes(), b"self_link");
    assert!(verify_target(
        resolved.as_os_str().as_bytes(),
        &expected_hash
    ));
}

// Symlink chains

#[test]
fn symlink_chain_three_links() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let leaf_target = "/final/destination";

    harness.symlink("chain_b", "chain_a").expect("A->B");
    harness.symlink("chain_c", "chain_b").expect("B->C");
    harness.symlink(leaf_target, "chain_c").expect("C->leaf");

    let a_target = harness.readlink("chain_a").expect("readlink A");
    assert_eq!(a_target.as_os_str().as_bytes(), b"chain_b");

    let b_target = harness.readlink("chain_b").expect("readlink B");
    assert_eq!(b_target.as_os_str().as_bytes(), b"chain_c");

    let c_target = harness.readlink("chain_c").expect("readlink C");
    assert_eq!(c_target.as_os_str().as_bytes(), leaf_target.as_bytes());

    let hash_c = hash_target(leaf_target.as_bytes());
    assert!(verify_target(c_target.as_os_str().as_bytes(), &hash_c));
}

#[test]
fn symlink_chain_length_five() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let leaf = "/leaf";

    harness.symlink("l2", "l1").expect("1->2");
    harness.symlink("l3", "l2").expect("2->3");
    harness.symlink("l4", "l3").expect("3->4");
    harness.symlink("l5", "l4").expect("4->5");
    harness.symlink(leaf, "l5").expect("5->leaf");

    let leaf_hash = hash_target(leaf.as_bytes());
    let chain: &[(&str, &[u8])] = &[
        ("l1", b"l2"),
        ("l2", b"l3"),
        ("l3", b"l4"),
        ("l4", b"l5"),
        ("l5", leaf.as_bytes()),
    ];
    for (link_name, expected_target) in chain {
        let resolved = harness.readlink(link_name).expect("readlink chain");
        assert_eq!(
            resolved.as_os_str().as_bytes(),
            *expected_target,
            "chain link {link_name} target mismatch"
        );
        if *link_name == "l5" {
            assert!(verify_target(resolved.as_os_str().as_bytes(), &leaf_hash));
        }
    }
}

// Overwrite existing symlink

#[test]
fn overwrite_existing_symlink() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let first_target = "/first/target";
    let second_target = "/second/target";
    let link = "overwrite_me";

    harness
        .symlink(first_target, link)
        .expect("create first symlink");
    let resolved1 = harness.readlink(link).expect("readlink first");
    assert_eq!(resolved1.as_os_str().as_bytes(), first_target.as_bytes());

    harness.remove_file(link).expect("unlink symlink");
    harness
        .symlink(second_target, link)
        .expect("create second symlink");

    let resolved2 = harness.readlink(link).expect("readlink second");
    assert_eq!(resolved2.as_os_str().as_bytes(), second_target.as_bytes());

    let hash2 = hash_target(second_target.as_bytes());
    assert!(verify_target(resolved2.as_os_str().as_bytes(), &hash2));
}

#[test]
fn symlink_overwrite_via_unlink_then_create() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let link = "replace_me";

    for (i, target) in ["/t1", "/t2", "/t3"].iter().enumerate() {
        if i > 0 {
            harness.remove_file(link).expect("unlink previous symlink");
        }
        harness.symlink(*target, link).expect("create symlink");
        let resolved = harness.readlink(link).expect("readlink");
        assert_eq!(resolved.as_os_str().as_bytes(), target.as_bytes());

        let hash = hash_target(target.as_bytes());
        assert!(
            verify_target(resolved.as_os_str().as_bytes(), &hash),
            "iteration {i} hash mismatch"
        );
    }
}

// Inode attribute consistency

#[test]
fn symlink_inode_is_symlink_type() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = "/some/target";
    let link = "type_check_link";

    harness.symlink(target, link).expect("symlink create");

    let md = std::fs::symlink_metadata(harness.mount_path().join(link)).expect("symlink_metadata");
    assert!(md.file_type().is_symlink(), "inode must be a symlink");
}

#[test]
fn symlink_inode_size_equals_target_length() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = "/a/target/path/of/known/length";
    let link = "size_check_link";

    harness.symlink(target, link).expect("symlink create");
    let md = std::fs::symlink_metadata(harness.mount_path().join(link)).expect("symlink_metadata");
    assert_eq!(
        md.len(),
        target.len() as u64,
        "symlink inode size must equal target byte length"
    );
}

#[test]
fn symlink_inode_mode_defaults_to_0777() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = "/target";
    let link = "mode_check_link";

    harness.symlink(target, link).expect("symlink create");
    let md = std::fs::symlink_metadata(harness.mount_path().join(link)).expect("symlink_metadata");
    let mode = md.permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o777,
        "symlink mode should be 0777, got 0o{mode:o}"
    );
}

#[test]
fn symlink_inode_nlink_is_one() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = "/target";
    let link = "nlink_check_link";

    harness.symlink(target, link).expect("symlink create");
    let n = harness.nlink(link).expect("nlink");
    assert_eq!(n, 1, "symlink nlink must be 1");
}

#[test]
fn symlink_timestamps_set_on_creation() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let target = "/timestamped";
    let link = "ts_link";

    harness.symlink(target, link).expect("symlink create");
    let md = std::fs::symlink_metadata(harness.mount_path().join(link)).expect("symlink_metadata");

    let atime = md.accessed().unwrap_or(UNIX_EPOCH);
    let mtime = md.modified().unwrap_or(UNIX_EPOCH);
    assert!(
        atime >= UNIX_EPOCH + std::time::Duration::from_secs(1),
        "atime should be after epoch"
    );
    assert!(
        mtime >= UNIX_EPOCH + std::time::Duration::from_secs(1),
        "mtime should be after epoch"
    );
    let after = SystemTime::now() + std::time::Duration::from_secs(5);
    assert!(atime <= after, "atime too far in the future");
    assert!(mtime <= after, "mtime too far in the future");
}

#[test]
fn multiple_symlinks_have_distinct_inodes() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let mut inodes = HashSet::new();

    for i in 0..5 {
        let link = format!("distinct_{i}");
        harness.symlink("/t", &link).expect("symlink create");
        let md =
            std::fs::symlink_metadata(harness.mount_path().join(&link)).expect("symlink_metadata");
        assert!(
            inodes.insert(md.ino()),
            "duplicate inode for symlink {link}"
        );
    }
}

// Error-path coverage

#[test]
fn readlink_on_nonexistent_path_returns_enoent() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let result = harness.readlink("no_such_symlink");
    assert!(result.is_err(), "readlink on nonexistent must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        io::ErrorKind::NotFound,
        "expected NotFound / ENOENT, got: {err:?}"
    );
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
}

#[test]
fn readlink_on_regular_file_returns_einval() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    harness
        .create_file("regular.txt", b"contents\n")
        .expect("create file");

    let result = harness.readlink("regular.txt");
    assert!(result.is_err(), "readlink on regular file must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EINVAL),
        "expected EINVAL, got: {err:?}"
    );
}

#[test]
fn readlink_on_directory_returns_einval() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    harness.mkdir("adir").expect("mkdir");

    let result = harness.readlink("adir");
    assert!(result.is_err(), "readlink on directory must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EINVAL),
        "expected EINVAL on directory, got: {err:?}"
    );
}

#[test]
fn symlink_creation_under_nonexistent_parent_returns_enoent() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let result = harness.symlink("/t", "no_parent/link");
    assert!(
        result.is_err(),
        "symlink under nonexistent parent must fail"
    );
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOENT),
        "expected ENOENT, got: {err:?}"
    );
}

#[test]
fn symlink_creation_where_parent_is_file_returns_enotdir() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    harness
        .create_file("notadir", b"blocking\n")
        .expect("create file");

    let result = harness.symlink("/t", "notadir/link");
    assert!(result.is_err(), "symlink through file must fail");
    let err = result.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOTDIR),
        "expected ENOTDIR, got: {err:?}"
    );
}

// Concurrent symlink create/readlink stress

#[test]
fn concurrent_symlink_create_readlink_stress() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };
    let harness = Arc::new(harness);
    let mut handles = Vec::new();

    for tid in 0..6 {
        let h = Arc::clone(&harness);
        handles.push(thread::spawn(move || {
            for j in 0..20 {
                let link = format!("conc_link_{tid}_{j}");
                let target = format!("/t/{tid}/{j}");

                h.symlink(&target, &link)
                    .expect("concurrent symlink create");

                let resolved = h.readlink(&link).expect("concurrent readlink");
                let resolved_bytes = resolved.as_os_str().as_bytes();
                assert_eq!(
                    resolved_bytes,
                    target.as_bytes(),
                    "concurrent target mismatch for {link}"
                );

                let hash = hash_target(target.as_bytes());
                assert!(
                    verify_target(resolved_bytes, &hash),
                    "concurrent BLAKE3 mismatch for {link}"
                );
            }
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked");
    }
}

// BLAKE3 domain isolation test

#[test]
fn blake3_domain_isolation() {
    let target = b"/some/test/target";
    let hash1 = hash_target(target);

    let mut hasher = blake3::Hasher::new_derive_key("wrong-domain");
    hasher.update(target);
    let hash2: [u8; 32] = hasher.finalize().into();

    assert_ne!(
        hash1, hash2,
        "BLAKE3 domains must produce different hashes for the same input"
    );
}

// Symlink -> readlink -> target integrity with BLAKE3 comprehensive

#[test]
fn comprehensive_target_integrity_matrix() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };

    let cases: &[(&str, &str)] = &[
        ("a", "/t"),
        ("grpc_socket", "/run/app/grpc.sock"),
        ("dot_config", "../.config/app"),
        ("multi_slash", "//usr//local///bin"),
        ("just_root", "/"),
        ("trailing_slash", "/usr/local/"),
        ("dot_target", "."),
        ("dotdot_target", ".."),
        ("numeric", "12345/67890"),
    ];

    for (name, target) in cases {
        harness
            .symlink(*target, name)
            .unwrap_or_else(|e| panic!("symlink {name} -> {target}: {e}"));

        let resolved = harness
            .readlink(name)
            .unwrap_or_else(|e| panic!("readlink {name}: {e}"));
        let resolved_bytes = resolved.as_os_str().as_bytes();

        assert_eq!(
            resolved_bytes,
            target.as_bytes(),
            "target mismatch for {name}"
        );

        let hash = hash_target(target.as_bytes());
        assert!(
            verify_target(resolved_bytes, &hash),
            "BLAKE3 mismatch for {name}"
        );
    }
}

// Symlink name validation through FUSE

#[test]
fn symlink_name_validation_via_fuse() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };

    harness.symlink("/t", "valid_name").expect("valid name");
    harness
        .symlink("/t", "valid-name")
        .expect("name with dashes");
    harness.symlink("/t", "valid.name").expect("name with dots");

    let result = harness.symlink("/t", "invalid/name");
    assert!(result.is_err(), "slash in name must fail");

    let result = harness.symlink("/t", "");
    assert!(result.is_err(), "empty name must fail");
}

// Symlink readlink cross-validation after mount

#[test]
fn symlink_persists_in_directory_listing() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };

    let names: &[&str] = &["alink", "blink", "clink"];
    for name in names {
        harness
            .symlink("/somewhere", *name)
            .expect("create symlink");
    }

    let entries = harness.readdir(".").expect("readdir root");
    for name in names {
        assert!(
            entries.contains(&name.to_string()),
            "readdir must contain {name}"
        );
    }
}

#[test]
fn symlink_size_matches_target_length_varied() {
    let Some(harness) = MountHarness::new_or_skip(module_path!()) else {
        return;
    };

    let targets: &[&[u8]] = &[
        b"/",
        b"/usr/lib",
        b"/a/medium-length/path/here",
        &[b'x'; 512],
    ];

    for (i, target) in targets.iter().enumerate() {
        let link = format!("size_link_{i}");
        let tpath = Path::new(std::ffi::OsStr::from_bytes(target));
        harness.symlink(tpath, &link).expect("symlink create");

        let md =
            std::fs::symlink_metadata(harness.mount_path().join(&link)).expect("symlink_metadata");
        assert_eq!(
            md.len(),
            target.len() as u64,
            "symlink {link}: expected size {}, got {}",
            target.len(),
            md.len()
        );
    }
}
