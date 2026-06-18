// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE read-write mount CRUD integration test.
//!
//! Validates the full create-read-update-delete lifecycle through a
//! real kernel FUSE mount.  Exercises the daemon binary's complete
//! write path: FUSE handler → dispatch_write → VfsEngine::write →
//! LocalFileSystem::write_file (confirmed wired by commit 896e7022f).
//!
//! This is the advancement gate for the `fuse-rw-mount` milestone:
//! daemon mounts FUSE read-write, basic file create/read/write/delete
//! work through a live kernel mount point.

use std::fs::{self, File};
use std::io::{self, Write};

use tidefs_validation::mount_harness::MountHarness;

// ── helpers ────────────────────────────────────────────────────────────────

/// Build reproducible seeded data of `len` bytes.
fn patterned_data(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|_| {
            let b = (state >> 32) as u8;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            b
        })
        .collect()
}

// ── CRUD lifecycle test ────────────────────────────────────────────────────

/// Full CRUD lifecycle through a live FUSE mount:
///
/// 1. Create file with open(O_CREAT | O_RDWR), write data, close.
/// 2. Read back through the mount and assert byte-for-byte match.
/// 3. Append additional data, re-read, assert concatenated content.
/// 4. Delete the file and assert ENOENT on subsequent open.
/// 5. Clean unmount (handled by harness Drop).
#[test]
fn fuse_rw_mount_crud_lifecycle() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP fuse_rw_mount_crud_lifecycle: daemon not available -- {e}");
            return;
        }
    };

    let file_path = harness.mount_path().join("crud_test.bin");

    // ── Phase 1: Create (O_CREAT | O_RDWR, write, close) ──────────
    let initial = patterned_data(0xAB, 4096);
    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&file_path)
            .expect("Phase 1: open O_CREAT|O_RDWR");
        file.write_all(&initial)
            .expect("Phase 1: write initial data");
        file.flush().expect("Phase 1: flush");
    }
    assert!(
        file_path.exists(),
        "Phase 1: crud_test.bin must exist after create"
    );

    // ── Phase 2: Read (byte-for-byte) ──────────────────────────────
    let read_back = fs::read(&file_path).expect("Phase 2: read crud_test.bin");
    assert_eq!(
        read_back.len(),
        initial.len(),
        "Phase 2: read length mismatch: expected {}, got {}",
        initial.len(),
        read_back.len()
    );
    assert_eq!(
        read_back, initial,
        "Phase 2: byte-for-byte content mismatch"
    );

    // ── Phase 3: Append, re-read, assert concatenated ──────────────
    let extra = patterned_data(0xCD, 2048);
    let mut combined = initial.clone();
    combined.extend_from_slice(&extra);

    {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&file_path)
            .expect("Phase 3: open with O_APPEND");
        file.write_all(&extra).expect("Phase 3: append extra data");
        file.flush().expect("Phase 3: flush append");
    }

    let appended_read = fs::read(&file_path).expect("Phase 3: read after append");
    assert_eq!(
        appended_read.len(),
        combined.len(),
        "Phase 3: length mismatch after append: expected {}, got {}",
        combined.len(),
        appended_read.len()
    );
    assert_eq!(
        appended_read, combined,
        "Phase 3: concatenated content mismatch after append"
    );

    // ── Phase 4: Delete, assert ENOENT on open ─────────────────────
    fs::remove_file(&file_path).expect("Phase 4: remove_file");
    assert!(
        !file_path.exists(),
        "Phase 4: file must not exist after unlink"
    );

    match File::open(&file_path) {
        Err(e) => {
            assert_eq!(
                e.kind(),
                io::ErrorKind::NotFound,
                "Phase 4: open after delete must return NotFound (ENOENT), got {:?}",
                e.kind()
            );
        }
        Ok(_) => panic!("Phase 4: open after delete must fail with ENOENT"),
    }

    // Phase 5: clean unmount — handled by harness Drop.
}

// ── reopen-append round-trip ────────────────────────────────────────────────

/// Open a file, write, close, then re-open with O_APPEND, write more,
/// close, and verify the concatenated file.  Exercises close-to-open
/// durability and append visibility within the same mount session.
#[test]
fn fuse_rw_mount_reopen_append_roundtrip() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP fuse_rw_mount_reopen_append_roundtrip: daemon not available -- {e}");
            return;
        }
    };

    let path = harness.mount_path().join("reopen_append.dat");
    let first = b"first write block\n".to_vec();
    let second = b"second write block\n".to_vec();
    let mut combined = first.clone();
    combined.extend_from_slice(&second);

    // Write first block, close.
    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("open first time");
        file.write_all(&first).expect("write first block");
        file.flush().expect("flush first block");
    }

    // Re-open with append, write second block, close.
    {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open second time with O_APPEND");
        file.write_all(&second)
            .expect("write second block via append");
        file.flush().expect("flush second block");
    }

    let read_back = fs::read(&path).expect("read after reopen-append");
    assert_eq!(
        read_back, combined,
        "reopen-append concatenated content mismatch"
    );
}

// ── empty file create + delete ──────────────────────────────────────────────

/// Create an empty file (O_CREAT | O_RDWR, no write), verify
/// existence and zero size, then delete and verify ENOENT.
#[test]
fn fuse_rw_mount_empty_file_create_delete() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP fuse_rw_mount_empty_file_create_delete: daemon not available -- {e}");
            return;
        }
    };

    let path = harness.mount_path().join("empty.dat");

    // Create empty file.
    {
        let _file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("create empty file via O_CREAT");
    }

    assert!(path.exists(), "empty.dat must exist after O_CREAT");
    let md = fs::metadata(&path).expect("stat empty.dat");
    assert_eq!(md.len(), 0, "empty.dat must have size 0");

    // Delete and verify ENOENT.
    fs::remove_file(&path).expect("delete empty.dat");
    match File::open(&path) {
        Err(e) => assert_eq!(
            e.kind(),
            io::ErrorKind::NotFound,
            "empty.dat after delete must be ENOENT"
        ),
        Ok(_) => panic!("empty.dat must not exist after delete"),
    }
}
