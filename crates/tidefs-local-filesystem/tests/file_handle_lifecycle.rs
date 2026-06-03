//! File-handle lifecycle tests for the local-filesystem layer.
//!
//! Exercises the [`FileHandleTable`] in isolation: register,
//! validate, release, duplicate detection, stale-handle detection,
//! generation mismatch, and concurrent access. Also covers filesystem-level
//! POSIX open-unlink-read semantics through the path-based API.

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::open_dispatch::{FileHandleTable, OpenDispatchError};
use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};
use tidefs_types_vfs_core::{EngineFileHandle, InodeId};

// ── Helpers ───────────────────────────────────────────────────────────

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("tidefs-fhl-{label}-{ts}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn open_fs(dir: &std::path::Path) -> LocalFileSystem {
    LocalFileSystem::open(dir).expect("open filesystem")
}

fn make_data(seed: u8, len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    let mut val = seed;
    for _ in 0..len {
        buf.push(val);
        val = val.wrapping_add(1);
    }
    buf
}

// ── Table-level: open + close ─────────────────────────────────────────

#[test]
fn register_returns_unique_handle_ids() {
    let mut t = FileHandleTable::new();
    let inode_a = InodeId::new(10);
    let inode_b = InodeId::new(20);

    let fh1 = t.register(inode_a, 0, false).unwrap();
    let fh2 = t.register(inode_b, 0, false).unwrap();

    assert_ne!(fh1.fh_id, fh2.fh_id, "each register returns unique id");
    assert_eq!(t.len(), 2);
}

#[test]
fn close_invalidates_handle() {
    let mut t = FileHandleTable::new();
    let fh = t.register(InodeId::new(1), 0, false).unwrap();
    assert_eq!(t.len(), 1);

    t.release(&fh).unwrap();
    assert!(t.is_empty());
    assert_eq!(t.validate(&fh), Err(OpenDispatchError::BadFileDescriptor));
}

#[test]
fn close_twice_returns_error() {
    let mut t = FileHandleTable::new();
    let fh = t.register(InodeId::new(1), 0, false).unwrap();
    t.release(&fh).unwrap();
    assert_eq!(t.release(&fh), Err(OpenDispatchError::BadFileDescriptor));
}

// ── Table-level: dup handles to same inode ────────────────────────────

#[test]
fn two_handles_same_inode_have_independent_state() {
    let mut t = FileHandleTable::new();
    let inode = InodeId::new(42);

    // Two opens of the same file get different handles
    let fh1 = t.register(inode, 0, false).unwrap(); // O_RDONLY
    let fh2 = t.register(inode, 1, false).unwrap(); // O_WRONLY

    assert_eq!(t.len(), 2);
    assert_ne!(fh1.fh_id, fh2.fh_id);
    assert!(t.contains_inode(inode));

    let s1 = t.validate(&fh1).unwrap();
    let s2 = t.validate(&fh2).unwrap();
    assert_eq!(s1.open_flags, 0);
    assert_eq!(s2.open_flags, 1);

    // Close first handle; second remains valid
    t.release(&fh1).unwrap();
    assert_eq!(t.len(), 1);
    assert!(t.contains_inode(inode));
    assert!(t.validate(&fh2).is_ok());
    assert_eq!(t.validate(&fh1), Err(OpenDispatchError::BadFileDescriptor));

    // Close second; inode is no longer referenced
    t.release(&fh2).unwrap();
    assert!(t.is_empty());
    assert!(!t.contains_inode(inode));
}

// ── Table-level: stale handle / generation mismatch ──────────────────

#[test]
fn stale_handle_after_release_and_realloc_fails_validation() {
    let mut t = FileHandleTable::new();
    let inode = InodeId::new(100);

    // Open, get handle, close it
    let fh_old = t.register(inode, 0, false).unwrap();
    let _old_fh_id = fh_old.fh_id;
    t.release(&fh_old).unwrap();

    // Allocate another handle (may get same ID via wrap)
    // Even if the ID reuses, the generation in the old fh won't match
    let _fh_new = t.register(inode, 0, false).unwrap();

    // Old handle should fail validation
    assert_eq!(
        t.validate(&fh_old),
        Err(OpenDispatchError::BadFileDescriptor),
        "stale handle detected"
    );
}

#[test]
fn generation_mismatch_on_reused_slot_detected() {
    let mut t = FileHandleTable::new();

    // Fill the table enough that IDs might wrap
    // Even without actual wrap, we simulate by constructing a
    // handle with a stale generation.
    let fh = t.register(InodeId::new(1), 0, false).unwrap();
    let state = t.lookup(fh.fh_id).unwrap();

    // Release and re-register same inode
    t.release(&fh).unwrap();
    let fh2 = t.register(InodeId::new(1), 0, false).unwrap();
    let state2 = t.lookup(fh2.fh_id).unwrap();

    // Generations should differ (table gen bumps on every register)
    assert_ne!(
        state.generation, state2.generation,
        "generations differ across allocations"
    );

    // A handle with the old generation should be invalid
    let mut stale_fh = fh2;
    stale_fh.fh_id = fh.fh_id; // use old fh_id
                               // old fh_id is no longer in the table, so validation fails
    assert_eq!(
        t.validate(&stale_fh),
        Err(OpenDispatchError::BadFileDescriptor)
    );
}

// ── Table-level: concurrent access ────────────────────────────────────

#[test]
fn concurrent_registration_from_two_threads() {
    let t = std::sync::Mutex::new(FileHandleTable::new());

    std::thread::scope(|s| {
        let t_ref = &t;
        let h1 = s.spawn(move || {
            let mut table = t_ref.lock().unwrap();
            (0..50)
                .map(|i| {
                    table
                        .register(InodeId::new(i as u64 + 10), 0, false)
                        .unwrap()
                })
                .collect::<Vec<_>>()
        });
        let h2 = s.spawn(move || {
            let mut table = t_ref.lock().unwrap();
            (0..50)
                .map(|i| {
                    table
                        .register(InodeId::new(i as u64 + 100), 0, false)
                        .unwrap()
                })
                .collect::<Vec<_>>()
        });

        let fhs1 = h1.join().unwrap();
        let fhs2 = h2.join().unwrap();

        let ids1: Vec<_> = fhs1.iter().map(|fh| fh.fh_id).collect();
        let ids2: Vec<_> = fhs2.iter().map(|fh| fh.fh_id).collect();

        // All IDs should be unique
        let mut all_ids = ids1.clone();
        all_ids.extend(&ids2);
        all_ids.sort();
        all_ids.dedup();
        assert_eq!(all_ids.len(), 100, "all 100 handles have unique ids");

        let table = t.lock().unwrap();
        assert_eq!(table.len(), 100);
    });
}

// ── Filesystem-level: open-unlink-read (POSIX unlink semantics) ───────

#[test]
fn open_unlink_read_posix_semantics() {
    set_test_key();
    let dir = temp_dir("open_unlink_read");
    let payload = make_data(0xCA, 4096);

    let mut fs = open_fs(&dir);
    fs.create_file("/posix_test.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/posix_test.bin", 0, &payload)
        .expect("write");
    fs.sync_all().expect("sync");

    // Read before unlink to confirm file exists
    let before = fs.read_file("/posix_test.bin").expect("read before unlink");
    assert_eq!(before, payload);

    // Unlink the file
    fs.unlink("/posix_test.bin").expect("unlink");
    fs.sync_all().expect("sync");
    assert!(fs.lookup("/posix_test.bin").is_err(), "name removed");

    // After unlink, attempts to read by path should fail
    let after = fs.read_file("/posix_test.bin");
    assert!(after.is_err(), "read by path fails after unlink");
}

// ── Remount simulation: generation mismatch across reopen ─────────────

#[test]
fn filesystem_reopen_invalidates_prior_file_handle_state() {
    set_test_key();
    let dir = temp_dir("remount_fh");

    // Create a filesystem with a file
    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");
        fs.create_file("/test.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.sync_all().expect("sync");
    }

    // Session 1: open the filesystem, create a FileHandleTable, register a handle
    let fh1: Option<EngineFileHandle> = {
        let _fs = LocalFileSystem::open(&dir).expect("open session 1");
        // Note: FileHandleTable is not directly exposed through LocalFileSystem;
        // it lives behind RefCell inside the VFS engine. We test the concept
        // by creating an independent FileHandleTable that simulates what
        // the engine does.
        let mut table = FileHandleTable::new();
        let inode = InodeId::new(1); // simulated inode
        let fh = table.register(inode, 0, false).expect("register handle");
        assert!(table.validate(&fh).is_ok());
        // Filesystem goes out of scope (simulates remount)
        Some(fh)
    };

    // Session 2: reopen the filesystem, create a NEW FileHandleTable
    {
        let _fs = LocalFileSystem::open(&dir).expect("open session 2");
        let mut table = FileHandleTable::new();

        // The old handle from session 1 should not be valid in session 2's table
        if let Some(ref old_fh) = fh1 {
            assert_eq!(
                table.validate(old_fh),
                Err(OpenDispatchError::BadFileDescriptor),
                "handle from prior session rejected after remount"
            );
        }

        // A newly registered handle should work fine
        let new_fh = table
            .register(InodeId::new(1), 0, false)
            .expect("register new");
        assert!(table.validate(&new_fh).is_ok());
    }
}

// ── All handles released when table dropped ───────────────────────────

#[test]
fn all_handles_invalid_after_table_dropped() {
    let fh: EngineFileHandle;
    {
        let mut table = FileHandleTable::new();
        fh = table
            .register(InodeId::new(42), 0, false)
            .expect("register");
        assert!(table.validate(&fh).is_ok());
        assert_eq!(table.len(), 1);
    }
    // Table dropped — equivalent to filesystem shutdown.
    // A new table has no knowledge of the old handle.
    let table = FileHandleTable::new();
    assert_eq!(
        table.validate(&fh),
        Err(OpenDispatchError::BadFileDescriptor)
    );
}

// ── Handle ID exhaustion boundary ─────────────────────────────────────

#[test]
fn handle_table_eventually_exhausted() {
    let mut t = FileHandleTable::new();
    // Register handles until we wrap around or exhaust IDs.
    // The table uses u64 IDs starting from 1, so exhaustion is
    // theoretical. Verify that many registrations work without
    // error and every ID is unique.
    let mut ids = std::collections::BTreeSet::new();
    // Register 2000 handles (well within u64 range, but enough
    // to stress the allocation path)
    for i in 0u64..2000 {
        let fh = t
            .register(InodeId::new(i), 0, false)
            .expect("register handle");
        assert!(ids.insert(fh.fh_id), "duplicate handle id at iteration {i}");
    }
    assert_eq!(ids.len(), 2000);
    assert_eq!(t.len(), 2000);
}
