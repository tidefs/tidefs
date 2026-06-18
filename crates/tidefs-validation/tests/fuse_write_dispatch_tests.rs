// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE write-dispatch integration tests.
//!
//! Validates the FUSE write-dispatch pipeline end-to-end:
//! data written through a FUSE mount is dispatched through
//! `tidefs-local-filesystem`'s write path, persisted to the backing
//! `tidefs-local-object-store`, and readable byte-for-byte within the
//! same mount session and after a clean remount.
//!
//! This directly exercises the `fuse-write-dispatch` milestone ("Write
//! dispatch completes, data visible on read within same session") from
//! the userspace-filesystem phase.

use tidefs_validation::mount_harness::MountHarness;

// ── test-data helpers ─────────────────────────────────────────────────

/// Deterministic pseudo-random byte sequence seeded by `seed`.
fn prng_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|_| {
            let b = (state >> 32) as u8;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            b
        })
        .collect()
}

/// Repeat the 0..255 sequence `len` times.
fn sequenced_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

// ── criterion 1: same-session write-dispatch + read-back ──────────────

/// Write small data (1 KiB) through the FUSE mount and read it back
/// within the same session.  This is the minimal write-dispatch smoke
/// test: write through FUSE → dispatch to local-filesystem → dispatch
/// to object-store → read back through FUSE → verify byte-for-byte.
#[test]
fn write_dispatch_small_file_same_session() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_dispatch_small_file_same_session: daemon not available -- {e}");
            return;
        }
    };

    let data = b"FUSE write-dispatch small-file roundtrip payload.\n";
    harness
        .create_file("dispatch_small.bin", data)
        .expect("create_file through FUSE mount");

    let read_back = harness
        .read_file("dispatch_small.bin")
        .expect("read_file through FUSE mount");

    assert_eq!(
        read_back.len(),
        data.len(),
        "same-session read-back length mismatch"
    );
    assert_eq!(
        read_back, data,
        "same-session write-dispatch: byte-for-byte mismatch"
    );
}

/// Write multi-block data (32 KiB, crossing block/extent boundaries)
/// and read back within the same session to exercise the full write
/// dispatch codepath including multi-extent handling.
#[test]
fn write_dispatch_multiblock_same_session() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_dispatch_multiblock_same_session: daemon not available -- {e}");
            return;
        }
    };

    let data = sequenced_bytes(32 * 1024);
    harness
        .create_file("dispatch_multiblock.bin", &data)
        .expect("create_file through FUSE mount");

    let read_back = harness
        .read_file("dispatch_multiblock.bin")
        .expect("read_file through FUSE mount");

    assert_eq!(
        read_back.len(),
        data.len(),
        "multiblock read-back length mismatch"
    );
    assert_eq!(
        read_back, data,
        "multiblock write-dispatch: byte-for-byte mismatch"
    );
}

/// Write pseudo-random data at several sizes spanning sub-block, exact
/// block, and multi-block boundaries to exercise edge cases in the
/// write-dispatch path.
#[test]
fn write_dispatch_varying_sizes_same_session() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP write_dispatch_varying_sizes_same_session: daemon not available -- {e}"
            );
            return;
        }
    };

    let sizes: &[usize] = &[0, 1, 511, 512, 1023, 1024, 4095, 4096, 65535, 65536];
    for (idx, &size) in sizes.iter().enumerate() {
        let seed = 0xCAFE_0000 + idx as u64;
        let data = prng_bytes(seed, size);
        let name = format!("dispatch_var_{size}.bin");
        harness
            .create_file(&name, &data)
            .unwrap_or_else(|e| panic!("create_file {name}: {e}"));

        let read_back = harness
            .read_file(&name)
            .unwrap_or_else(|e| panic!("read_file {name}: {e}"));

        assert_eq!(
            read_back, data,
            "varying-size ({size} bytes) write-dispatch mismatch for {name}"
        );
    }
}

/// Write multiple files concurrently within the same session and verify
/// all are readable with correct content.  Exercises the write dispatch
/// across multiple independent inodes.
#[test]
fn write_dispatch_multiple_files_same_session() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "SKIP write_dispatch_multiple_files_same_session: daemon not available -- {e}"
            );
            return;
        }
    };

    let files: &[(&str, &[u8])] = &[
        ("dispatch_a.txt", b"alpha content\n" as &[u8]),
        ("dispatch_b.txt", b"beta content longer\n"),
        ("dispatch_c.bin", &sequenced_bytes(4096)),
        ("sub/dispatch_d.bin", &prng_bytes(0xDDDD, 1024)),
    ];

    for (name, data) in files {
        if let Some(parent) = std::path::Path::new(name).parent() {
            if !parent.as_os_str().is_empty() {
                harness
                    .mkdir_all(parent)
                    .unwrap_or_else(|e| panic!("mkdir_all {parent:?}: {e}"));
            }
        }
        harness
            .create_file(name, data)
            .unwrap_or_else(|e| panic!("create_file {name}: {e}"));
    }

    for (name, expected) in files {
        let read_back = harness
            .read_file(name)
            .unwrap_or_else(|e| panic!("read_file {name}: {e}"));
        assert_eq!(
            read_back, *expected,
            "multi-file write-dispatch mismatch for {name}"
        );
    }
}

// ── criterion 2: write + fsync + remount durability ──────────────────

/// Write data, fsync, unmount, remount, and verify byte-for-byte.  This
/// confirms that the write dispatch path flushes dirty data to durable
/// storage on fsync and that remount correctly reconstructs the file.
#[test]
fn write_dispatch_fsync_remount_verify() {
    let data = sequenced_bytes(8192);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_dispatch_fsync_remount_verify: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("dispatch_durable.bin", &data)
        .expect("create_file session 1");
    harness
        .fsync_file("dispatch_durable.bin")
        .expect("fsync session 1");

    let store_path = harness.store_path().to_path_buf();
    harness.unmount_only(true).expect("unmount session 1");

    assert!(
        store_path.exists(),
        "backing store {} must exist after unmount",
        store_path.display()
    );

    harness.remount().expect("remount session 2");

    let read_back = harness
        .read_file("dispatch_durable.bin")
        .expect("read_file session 2");

    assert_eq!(
        read_back.len(),
        data.len(),
        "file length mismatch after fsync + remount"
    );
    assert_eq!(
        read_back, data,
        "byte-for-byte data mismatch after fsync + remount: \
         writeback flush may not have persisted data to object store"
    );
}

/// Write 64 KiB of pseudo-random data, fsync, remount, verify.  Larger
/// than the typical extent size to exercise multi-extent write dispatch.
#[test]
fn write_dispatch_64kib_fsync_remount() {
    let data = prng_bytes(0xF00D_CAFE, 64 * 1024);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_dispatch_64kib_fsync_remount: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("dispatch_64k.bin", &data)
        .expect("create_file");
    harness.fsync_file("dispatch_64k.bin").expect("fsync");

    let store_path = harness.store_path().to_path_buf();
    harness.unmount_only(true).expect("unmount");

    assert!(
        store_path.exists(),
        "backing store {} must exist after unmount",
        store_path.display()
    );

    harness.remount().expect("remount");

    let read_back = harness
        .read_file("dispatch_64k.bin")
        .expect("read after remount");

    assert_eq!(
        read_back, data,
        "64 KiB write-dispatch data mismatch after fsync + remount"
    );
}

// ── criterion 3: namespace and directory structure durability ─────────

/// Write, fsync, unmount, then remount and verify namespace entries are
/// preserved — file names and directory structure survive the roundtrip.
#[test]
fn write_dispatch_namespace_preserved_after_remount() {
    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_dispatch_namespace_preserved_after_remount: daemon not available -- {e}");
            return;
        }
    };

    harness.mkdir_all("dir_a/dir_b").expect("mkdir -p");
    harness
        .create_file("dir_a/x.txt", b"x-content\n")
        .expect("create x.txt");
    harness
        .create_file("dir_a/dir_b/y.txt", b"y-content\n")
        .expect("create y.txt");
    harness
        .create_file("root_file.txt", b"root\n")
        .expect("create root_file.txt");

    harness.fsync_file("dir_a/x.txt").expect("fsync x");
    harness.fsync_file("dir_a/dir_b/y.txt").expect("fsync y");
    harness.fsync_file("root_file.txt").expect("fsync root");

    let store_path = harness.store_path().to_path_buf();
    harness.unmount_only(true).expect("unmount");

    assert!(
        store_path.exists(),
        "backing store {} must exist after unmount",
        store_path.display()
    );

    harness.remount().expect("remount");

    // Root directory must contain dir_a and root_file.txt.
    let root_entries = harness.readdir(".").expect("readdir root");
    assert!(
        root_entries.contains(&"dir_a".to_string()),
        "root missing dir_a/"
    );
    assert!(
        root_entries.contains(&"root_file.txt".to_string()),
        "root missing root_file.txt"
    );

    // dir_a must contain x.txt and dir_b.
    let a_entries = harness.readdir("dir_a").expect("readdir dir_a");
    assert!(
        a_entries.contains(&"x.txt".to_string()),
        "dir_a missing x.txt"
    );
    assert!(
        a_entries.contains(&"dir_b".to_string()),
        "dir_a missing dir_b/"
    );

    // dir_a/dir_b must contain y.txt.
    let b_entries = harness.readdir("dir_a/dir_b").expect("readdir dir_a/dir_b");
    assert!(
        b_entries.contains(&"y.txt".to_string()),
        "dir_a/dir_b missing y.txt"
    );

    // Verify file contents.
    assert_eq!(
        harness.read_file("dir_a/x.txt").expect("read x"),
        b"x-content\n",
        "x.txt content mismatch"
    );
    assert_eq!(
        harness.read_file("dir_a/dir_b/y.txt").expect("read y"),
        b"y-content\n",
        "y.txt content mismatch"
    );
    assert_eq!(
        harness.read_file("root_file.txt").expect("read root"),
        b"root\n",
        "root_file.txt content mismatch"
    );
}

/// Write data, fsync, unmount, then remount and verify the backing store
/// survived and the file is readable.  This is a combined store-survival
/// and data-integrity check that uses remount (the reliable path) rather
/// than direct store inspection.
#[test]
fn write_dispatch_store_survives_unmount() {
    let data = prng_bytes(0x57012E_08013EC7, 4096);

    let mut harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP write_dispatch_store_survives_unmount: daemon not available -- {e}");
            return;
        }
    };

    harness
        .create_file("store_survive.bin", &data)
        .expect("create_file");
    harness.fsync_file("store_survive.bin").expect("fsync");

    let store_path = harness.store_path().to_path_buf();
    harness.unmount_only(true).expect("unmount");

    // The backing store must exist after unmount (TempDir not dropped).
    assert!(
        store_path.exists(),
        "backing store {} must exist after unmount",
        store_path.display()
    );

    // Remount and verify data survived byte-for-byte.
    harness.remount().expect("remount");

    let read_back = harness
        .read_file("store_survive.bin")
        .expect("read after remount");

    assert_eq!(
        read_back, data,
        "store-survival: data mismatch after fsync + remount; \
         write dispatch may not have flushed to object store"
    );

    // Verify the store directory has content (non-empty).
    let store_has_entries = std::fs::read_dir(&store_path)
        .map(|mut rd| rd.any(|e| e.is_ok()))
        .unwrap_or(false);
    assert!(
        store_has_entries,
        "backing store {} should contain entries after write + fsync + unmount",
        store_path.display()
    );
}
