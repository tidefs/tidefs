// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg(feature = "std")]
//! Integration tests for inode-table allocation semantics.
//!
//! Exercises the public [`InodeTable`] API: sequential allocation, bulk
//! allocation, slot reuse via free-then-realloc, double-free rejection,
//! exhaustion boundaries, and concurrent allocation under contention.
//!
//! Uses [`SystemTimeSource`] — no object-store persistence in this module.

use std::sync::Arc;
use std::thread;
use tidefs_inode_table::{
    Ino, InodeAttributes, InodeKind, InodeTable, InodeTableError, SystemTimeSource,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_table(capacity: usize) -> InodeTable {
    InodeTable::new(capacity, Box::new(SystemTimeSource))
}

fn file_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 1000, 1000, InodeKind::File)
}

fn dir_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 1000, 1000, InodeKind::Directory)
}

// ---------------------------------------------------------------------------
// 1. Sequential allocation
// ---------------------------------------------------------------------------

#[test]
fn sequential_alloc_produces_unique_monotonic_inos() {
    let tbl = make_table(16);
    let mut prev = None;
    for i in 0..10 {
        let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
        if i == 0 {
            assert_eq!(ino, Ino::ROOT, "first alloc must be Ino(1)");
        }
        if let Some(p) = prev {
            assert!(ino.0 > p, "inos must be monotonic: {ino:?} after {p}");
        }
        prev = Some(ino.0);
    }
    assert_eq!(tbl.len(), 10);
}

// ---------------------------------------------------------------------------
// 2. Bulk allocation (1000 inodes)
// ---------------------------------------------------------------------------

#[test]
fn bulk_alloc_1000_all_unique_and_reachable() {
    let tbl = make_table(2000);
    let mut inos = Vec::with_capacity(1000);
    for i in 0..1000 {
        let mode = 0o600 | ((i as u32) & 0x1FF);
        let ino = tbl
            .create(
                InodeKind::File,
                InodeAttributes::new(mode, i as u32, 0, InodeKind::File),
            )
            .unwrap();
        inos.push(ino);
    }
    assert_eq!(tbl.len(), 1000);

    // All inos distinct
    let mut seen = std::collections::HashSet::new();
    for &ino in &inos {
        assert!(seen.insert(ino.0), "duplicate ino {}", ino.0);
    }

    // All reachable by lookup
    for (i, &ino) in inos.iter().enumerate() {
        let attrs = tbl.lookup(ino).expect("inode must exist");
        assert_eq!(attrs.uid, i as u32);
    }
}

// ---------------------------------------------------------------------------
// 3. Alloc-after-free (slot reuse via free list)
// ---------------------------------------------------------------------------

#[test]
fn alloc_after_free_reuses_slot() {
    let tbl = make_table(16);

    // Allocate 3 inodes
    let ino1 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let ino2 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let ino3 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    assert_eq!(tbl.len(), 3);

    // Free ino2 (file auto-remove via unlink)
    tbl.unlink(ino2).unwrap();
    assert!(tbl.lookup(ino2).is_none());
    assert_eq!(tbl.len(), 2);

    // Next allocation should reuse ino2's slot
    let reused = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    assert_eq!(reused.0, ino2.0, "free list should reuse slot 2");
    assert_eq!(tbl.len(), 3);

    // ino1 and ino3 should still be reachable
    assert!(tbl.lookup(ino1).is_some());
    assert!(tbl.lookup(ino3).is_some());
}

// ---------------------------------------------------------------------------
// 4. Free-then-realloc verifies clean state (no stale data leak)
// ---------------------------------------------------------------------------

#[test]
fn free_then_realloc_has_clean_attributes() {
    let tbl = make_table(16);

    let ino = tbl
        .create(
            InodeKind::File,
            InodeAttributes::new(0o644, 999, 888, InodeKind::File),
        )
        .unwrap();
    let old_gen = tbl.lookup(ino).unwrap().generation;

    // Free it
    tbl.unlink(ino).unwrap();
    assert!(tbl.lookup(ino).is_none());

    // Re-allocate with different attributes
    let new_ino = tbl
        .create(
            InodeKind::Directory,
            InodeAttributes::new(0o755, 111, 222, InodeKind::Directory),
        )
        .unwrap();
    assert_eq!(new_ino, ino, "should reuse same slot number");

    let stored = tbl.lookup(new_ino).unwrap();
    assert_eq!(stored.mode, 0o755);
    assert_eq!(stored.uid, 111);
    assert_eq!(stored.gid, 222);
    assert_eq!(stored.kind, InodeKind::Directory);
    assert_eq!(
        stored.size, 0,
        "size must be 0, not leaked from prior occupant"
    );
    assert!(
        stored.generation > old_gen,
        "generation must advance on reuse"
    );
    assert_eq!(stored.nlink, 1);
}

// ---------------------------------------------------------------------------
// 5. Double-free rejection
// ---------------------------------------------------------------------------

#[test]
fn double_free_rejected() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();

    // First free (unlink nlink→0 then delete)
    tbl.unlink(ino).unwrap();
    tbl.delete(ino).unwrap();
    assert!(tbl.lookup(ino).is_none());

    // Second free must fail (inode not found)
    assert_eq!(tbl.remove(ino), Err(InodeTableError::InodeNotFound));
    assert_eq!(tbl.delete(ino), Err(InodeTableError::InodeNotFound));
}

// ---------------------------------------------------------------------------
// 6. Free-nonexistent rejection
// ---------------------------------------------------------------------------

#[test]
fn free_nonexistent_rejected() {
    let tbl = make_table(16);

    assert_eq!(tbl.remove(Ino(99)), Err(InodeTableError::InodeNotFound));
    assert_eq!(tbl.delete(Ino(99)), Err(InodeTableError::InodeNotFound));
    assert_eq!(tbl.unlink(Ino(99)), Err(InodeTableError::InodeNotFound));

    // Also check free of ino 0 (reserved)
    assert_eq!(tbl.remove(Ino::NONE), Err(InodeTableError::InodeNotFound));
}

// ---------------------------------------------------------------------------
// 7. Alloc-exhaustion boundary
// ---------------------------------------------------------------------------

#[test]
fn alloc_exhaustion_at_max_capacity() {
    let cap = 5;
    let tbl = make_table(cap);

    // Fill to capacity
    for i in 0..cap {
        tbl.create(
            InodeKind::File,
            InodeAttributes::new(0o644, i as u32, 0, InodeKind::File),
        )
        .unwrap();
    }
    assert_eq!(tbl.len(), cap);

    // Next allocation must fail
    assert_eq!(
        tbl.create(InodeKind::File, file_attrs(0o755)),
        Err(InodeTableError::TableFull)
    );
}

#[test]
fn alloc_exhaustion_then_free_then_alloc_succeeds() {
    let cap = 4;
    let tbl = make_table(cap);

    let mut inos = Vec::new();
    for _ in 0..cap {
        inos.push(tbl.create(InodeKind::File, file_attrs(0o644)).unwrap());
    }
    assert_eq!(
        tbl.create(InodeKind::File, file_attrs(0o755)),
        Err(InodeTableError::TableFull)
    );

    // Free one
    tbl.unlink(inos[1]).unwrap();
    assert_eq!(tbl.len(), cap - 1);

    // Now allocation should succeed via free list
    let reused = tbl.create(InodeKind::File, file_attrs(0o600)).unwrap();
    assert_eq!(reused.0, inos[1].0, "should reuse freed slot");
    assert_eq!(tbl.len(), cap);
}

// ---------------------------------------------------------------------------
// 8. Concurrent allocation under contention
// ---------------------------------------------------------------------------

#[test]
fn concurrent_alloc_no_duplicate_inos() {
    let tbl = Arc::new(make_table(3000));
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = Vec::new();
    for _ in 0..4 {
        let tbl = Arc::clone(&tbl);
        let results = Arc::clone(&results);
        handles.push(thread::spawn(move || {
            let mut local = Vec::new();
            for j in 0..500 {
                match tbl.create(
                    InodeKind::File,
                    InodeAttributes::new(0o644, j as u32, 0, InodeKind::File),
                ) {
                    Ok(ino) => local.push(ino),
                    Err(InodeTableError::TableFull) => break,
                    Err(_) => {}
                }
            }
            results.lock().unwrap().extend(local);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let all_inos = results.lock().unwrap();
    let mut seen = std::collections::HashSet::new();
    let mut duplicate = false;
    for ino in all_inos.iter() {
        if !seen.insert(ino.0) {
            duplicate = true;
            break;
        }
    }
    assert!(
        !duplicate,
        "concurrent allocation produced duplicate inode numbers"
    );
    assert!(
        !all_inos.is_empty(),
        "at least some allocations should succeed"
    );
}

#[test]
fn concurrent_alloc_and_free_no_corruption() {
    let tbl = Arc::new(make_table(2000));
    let errors = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let mut handles = Vec::new();
    for _ in 0..4 {
        let tbl = Arc::clone(&tbl);
        let errors = Arc::clone(&errors);
        handles.push(thread::spawn(move || {
            for _ in 0..200 {
                match tbl.create(InodeKind::File, file_attrs(0o644)) {
                    Ok(ino) => {
                        // Immediately free via unlink (auto-remove for files)
                        if tbl.unlink(ino).is_err() {
                            errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    Err(InodeTableError::TableFull) => {
                        // Expected under contention — no error
                    }
                    Err(_) => {
                        errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        errors.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "no unexpected errors during concurrent alloc/free"
    );
}

// ---------------------------------------------------------------------------
// Supplementary: monotonic generation across allocations
// ---------------------------------------------------------------------------

#[test]
fn generation_monotonic_across_allocations() {
    let tbl = make_table(16);
    let mut last_gen = 0u64;

    for i in 0..20 {
        let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
        let gen = tbl.lookup(ino).unwrap().generation;
        assert!(
            gen > last_gen,
            "generation not monotonic at iteration {i}: {gen} <= {last_gen}"
        );
        last_gen = gen;

        // Free to trigger reuse on next iteration (except first few)
        if i > 0 {
            tbl.unlink(ino).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Supplementary: capacity reflects constructor argument
// ---------------------------------------------------------------------------

#[test]
fn capacity_matches_constructor() {
    for cap in [1, 2, 16, 64, 1024, 65536] {
        let tbl = make_table(cap);
        assert_eq!(tbl.capacity(), cap, "capacity mismatch for {cap}");
    }
}

// ---------------------------------------------------------------------------
// Supplementary: len and is_empty track allocation state
// ---------------------------------------------------------------------------

#[test]
fn len_and_is_empty_track_allocations() {
    let tbl = make_table(16);
    assert!(tbl.is_empty());
    assert_eq!(tbl.len(), 0);
    assert_eq!(tbl.count(), 0);

    let ino1 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    assert!(!tbl.is_empty());
    assert_eq!(tbl.len(), 1);
    assert_eq!(tbl.count(), 1);

    let ino2 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    assert_eq!(tbl.len(), 2);

    tbl.unlink(ino1).unwrap();
    assert_eq!(tbl.len(), 1);

    tbl.unlink(ino2).unwrap();
    assert!(tbl.is_empty());
    assert_eq!(tbl.len(), 0);
}
