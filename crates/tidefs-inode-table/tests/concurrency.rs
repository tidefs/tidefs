// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg(feature = "std")]
//! Integration tests for inode-table concurrency safety.
//!
//! Covers barrier-coordinated concurrent create, create/unlink/recreate
//! churn, high-contention mixed workloads (create, lookup, setattr, link,
//! unlink interleaved), and post-stress consistency invariants (len == iter
//! count, no leaked slots, live inodes reachable).
//!
//! Uses [`InodeTable`] wrapped in [`Arc`] with [`SystemTimeSource`].

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use tidefs_inode_table::{
    InodeAttributes, InodeKind, InodeTable, InodeTableError, SystemTimeSource,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_table(capacity: usize) -> Arc<InodeTable> {
    Arc::new(InodeTable::new(capacity, Box::new(SystemTimeSource)))
}

fn file_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 1000, 1000, InodeKind::File)
}

fn dir_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 0, 0, InodeKind::Directory)
}

// ---------------------------------------------------------------------------
// 1. Coordinated concurrent create — no duplicates
// ---------------------------------------------------------------------------

#[test]
fn barrier_coordinated_create_no_duplicates() {
    let tbl = make_table(8000);
    let barrier = Arc::new(Barrier::new(4));
    let all_inos = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = Vec::new();
    for w in 0..4u32 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let all_inos = Arc::clone(&all_inos);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut local = Vec::with_capacity(500);
            for i in 0..500 {
                match tbl.create(
                    InodeKind::File,
                    InodeAttributes::new(0o644, w * 2000 + i, 0, InodeKind::File),
                ) {
                    Ok(ino) => local.push(ino),
                    Err(InodeTableError::TableFull) => break,
                    Err(_) => {}
                }
            }
            all_inos.lock().unwrap().extend(local);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let all = all_inos.lock().unwrap();
    assert!(!all.is_empty(), "at least some allocations should succeed");

    // All allocated inos must be unique (no concurrent dupes)
    let mut seen = std::collections::HashSet::new();
    for ino in all.iter() {
        assert!(
            seen.insert(ino.0),
            "duplicate ino {} from concurrent create",
            ino.0
        );
    }

    // All must be reachable
    for ino in all.iter() {
        assert!(tbl.lookup(*ino).is_some(), "inode {ino:?} should exist");
    }

    // len must match count
    assert_eq!(tbl.len(), all.len());
    assert_eq!(tbl.count(), all.len());
}

// ---------------------------------------------------------------------------
// 2. Concurrent create/unlink churn — verify no errors and consistency
// ---------------------------------------------------------------------------

#[test]
fn concurrent_create_unlink_churn_consistent() {
    let tbl = make_table(6000);
    let barrier = Arc::new(Barrier::new(6));
    let errors = Arc::new(AtomicU32::new(0));

    let mut handles = Vec::new();
    for w in 0..6u32 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let errors = Arc::clone(&errors);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for j in 0..300u32 {
                match tbl.create(
                    InodeKind::File,
                    InodeAttributes::new(0o600 | (j & 0x1FF), w * 1000 + j, 0, InodeKind::File),
                ) {
                    Ok(ino) => {
                        // Immediately unlink (auto-remove for files)
                        if let Err(e) = tbl.unlink(ino) {
                            if e != InodeTableError::InodeNotFound {
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(InodeTableError::TableFull) => {}
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        errors.load(Ordering::Relaxed),
        0,
        "unexpected errors during concurrent churn"
    );

    // Verify consistency: live inodes match iter output
    let snapshot = tbl.iter();
    for (ino, _) in &snapshot {
        assert!(tbl.lookup(*ino).is_some(), "iter entry {ino:?} unreachable");
    }
    assert_eq!(tbl.len(), snapshot.len());
}

// ---------------------------------------------------------------------------
// 3. Concurrent mixed ops — create, lookup, setattr, link, unlink interleaved
// ---------------------------------------------------------------------------

#[test]
fn concurrent_mixed_ops_do_not_crash_or_corrupt() {
    let tbl = make_table(4000);
    let barrier = Arc::new(Barrier::new(8));
    let errors = Arc::new(AtomicU32::new(0));

    // Phase 1: pre-fill the table with 500 stable inodes
    let mut stable = Vec::new();
    for i in 0..500u32 {
        stable.push(
            tbl.create(
                InodeKind::File,
                InodeAttributes::new(0o644, i, 0, InodeKind::File),
            )
            .unwrap(),
        );
    }

    let stable_arc = Arc::new(stable);
    let mut handles = Vec::new();

    // 2 creator+unlinker threads
    for _ in 0..2 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let errors = Arc::clone(&errors);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _j in 0..400u32 {
                match tbl.create(InodeKind::File, file_attrs(0o644)) {
                    Ok(ino) => {
                        let _ = tbl.unlink(ino);
                    }
                    Err(InodeTableError::TableFull) => {}
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // 2 setattr threads: modify stable inodes
    for _ in 0..2 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let stable = Arc::clone(&stable_arc);
        let errors = Arc::clone(&errors);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _counter in 0..600u32 {
                for ino in stable.iter() {
                    if let Some(mut attrs) = tbl.lookup(*ino) {
                        attrs.size = attrs.size.wrapping_add(1);
                        if let Err(e) = tbl.setattr(*ino, attrs) {
                            if e != InodeTableError::InodeNotFound {
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }));
    }

    // 2 link/unlink threads: bump nlink on stable inodes
    for _ in 0..2 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let stable = Arc::clone(&stable_arc);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _counter in 0..600u32 {
                for ino in stable.iter() {
                    if tbl.link(*ino).is_ok() {
                        let _ = tbl.unlink(*ino);
                    }
                }
            }
        }));
    }

    // 2 lookup/iter threads: read-only
    for _ in 0..2 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let stable = Arc::clone(&stable_arc);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _counter in 0..1000u32 {
                for ino in stable.iter() {
                    let _ = tbl.lookup(*ino);
                }
                let _ = tbl.len();
                let _ = tbl.iter();
                let _ = tbl.dirty_count();
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        errors.load(Ordering::Relaxed),
        0,
        "unexpected errors during mixed ops"
    );
}

// ---------------------------------------------------------------------------
// 4. Consistency: len == iter count after concurrent stress
// ---------------------------------------------------------------------------

#[test]
fn len_equals_iter_count_after_concurrent_stress() {
    let tbl = make_table(8000);
    let barrier = Arc::new(Barrier::new(6));

    let mut handles = Vec::new();

    // 3 creator threads
    for w in 0..3u32 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for j in 0..600u32 {
                match tbl.create(
                    InodeKind::File,
                    InodeAttributes::new(0o644, w * 2000 + j, 0, InodeKind::File),
                ) {
                    Ok(ino) => {
                        if j % 3 == 0 {
                            let _ = tbl.unlink(ino);
                        }
                    }
                    Err(InodeTableError::TableFull) => break,
                    Err(_) => {}
                }
            }
        }));
    }

    // 2 unlink-only threads
    for _w2 in 0..2u32 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for j in 0..800u32 {
                let ino = tidefs_inode_table::Ino((j % 600) as u64 + 1);
                let _ = tbl.unlink(ino);
            }
        }));
    }

    // 1 link thread
    {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for j in 0..800u32 {
                let ino = tidefs_inode_table::Ino((j % 400) as u64 + 1);
                let _ = tbl.link(ino);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Post-stress invariants
    let live = tbl.len();
    let snapshot = tbl.iter();
    assert_eq!(
        snapshot.len(),
        live,
        "iter count {} must equal len {}",
        snapshot.len(),
        live
    );

    for (ino, _attrs) in &snapshot {
        assert!(
            tbl.lookup(*ino).is_some(),
            "iter entry {ino:?} not reachable"
        );
    }

    assert_eq!(tbl.count(), live);
}

// ---------------------------------------------------------------------------
// 5. Concurrent create with full exhaustion and recovery
// ---------------------------------------------------------------------------

#[test]
fn concurrent_create_exhaustion_then_free_then_create() {
    let cap = 100;
    let tbl = make_table(cap);

    // Phase 1: fill to capacity sequentially
    let mut inos = Vec::new();
    for _ in 0..cap {
        inos.push(tbl.create(InodeKind::File, file_attrs(0o644)).unwrap());
    }
    assert_eq!(tbl.len(), cap);
    assert_eq!(
        tbl.create(InodeKind::File, file_attrs(0o644)),
        Err(InodeTableError::TableFull)
    );

    // Phase 2: free half concurrently
    let mid = cap / 2;
    let to_free = inos.split_off(mid);
    let barrier = Arc::new(Barrier::new(4));

    let mut handles = Vec::new();
    let chunk_size = to_free.len() / 3;
    for chunk in to_free.chunks(chunk_size.max(1)) {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let chunk_vec: Vec<_> = chunk.to_vec();
        handles.push(thread::spawn(move || {
            barrier.wait();
            for ino in &chunk_vec {
                let _ = tbl.unlink(*ino);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert!(tbl.len() < cap, "len should decrease after concurrent free");

    // Phase 3: concurrent re-create, no duplicate ino assignments
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));
    let barrier2 = Arc::new(Barrier::new(4));

    let mut handles = Vec::new();
    for _ in 0..4 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier2);
        let results = Arc::clone(&results);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..20 {
                match tbl.create(InodeKind::Directory, dir_attrs(0o755)) {
                    Ok(ino) => results.lock().unwrap().push(ino),
                    Err(InodeTableError::TableFull) => break,
                    Err(_) => {}
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let new_inos = results.lock().unwrap();
    let mut seen = std::collections::HashSet::new();
    for ino in new_inos.iter() {
        assert!(
            seen.insert(ino.0),
            "duplicate ino {} during concurrent re-create after exhaustion",
            ino.0
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Concurrent create + lookup consistency: iterating while creating
// ---------------------------------------------------------------------------

#[test]
fn concurrent_create_and_iter_no_panics() {
    let tbl = make_table(10000);
    let barrier = Arc::new(Barrier::new(6));

    let mut handles = Vec::new();

    // 3 creator threads
    for w in 0..3u32 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for j in 0..800u32 {
                let _ = tbl.create(
                    InodeKind::File,
                    InodeAttributes::new(0o644, w * 3000 + j, 0, InodeKind::File),
                );
            }
        }));
    }

    // 3 iter/lookup threads
    for _ in 0..3 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..2000u32 {
                let snapshot = tbl.iter();
                for (ino, _) in &snapshot {
                    let _ = tbl.lookup(*ino);
                }
                let _ = tbl.len();
                let _ = tbl.count();
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let snapshot = tbl.iter();
    for (ino, _) in &snapshot {
        assert!(tbl.lookup(*ino).is_some(), "iter entry {ino:?} not found");
    }
    assert_eq!(tbl.len(), snapshot.len());
}

// ---------------------------------------------------------------------------
// 7. Concurrent generation-gated operations under contention
// ---------------------------------------------------------------------------

#[test]
fn concurrent_generation_guarded_ops() {
    let tbl = make_table(1000);
    let barrier = Arc::new(Barrier::new(4));

    let mut entries = Vec::new();
    for i in 0..50u32 {
        let ino = tbl
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, i, 0, InodeKind::File),
            )
            .unwrap();
        let gen = tbl.lookup(ino).unwrap().generation;
        entries.push((ino, gen));
    }

    let entries_arc = Arc::new(entries);
    let errors = Arc::new(AtomicU32::new(0));

    let mut handles = Vec::new();

    // 2 threads: setattr_if_generation with correct gen
    for _ in 0..2 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let entries = Arc::clone(&entries_arc);
        let errors = Arc::clone(&errors);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..300u32 {
                for (ino, gen) in entries.iter() {
                    if let Some(mut attrs) = tbl.lookup(*ino) {
                        attrs.size = attrs.size.wrapping_add(1);
                        if let Err(e) = tbl.setattr_if_generation(*ino, *gen, attrs) {
                            if e != InodeTableError::InodeNotFound {
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }));
    }

    // 2 threads: link_if_generation + unlink_if_generation
    for _ in 0..2 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let entries = Arc::clone(&entries_arc);
        let errors = Arc::clone(&errors);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..300u32 {
                for (ino, gen) in entries.iter() {
                    match tbl.link_if_generation(*ino, *gen) {
                        Ok(_) => {
                            let _ = tbl.unlink_if_generation(*ino, *gen);
                        }
                        Err(InodeTableError::InodeNotFound)
                        | Err(InodeTableError::GenerationMismatch) => {}
                        Err(_) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        errors.load(Ordering::Relaxed),
        0,
        "unexpected errors during generation-guarded ops"
    );
}

// ---------------------------------------------------------------------------
// 8. Dirty-count correctness under concurrent mutation
// ---------------------------------------------------------------------------

#[test]
fn concurrent_mutations_do_not_corrupt_dirty_count() {
    let tbl = make_table(2000);

    let mut inos = Vec::new();
    for i in 0..200u32 {
        inos.push(
            tbl.create(
                InodeKind::File,
                InodeAttributes::new(0o644, i, 0, InodeKind::File),
            )
            .unwrap(),
        );
    }

    let inos_arc = Arc::new(inos);
    let barrier = Arc::new(Barrier::new(4));

    let mut handles = Vec::new();
    for _ in 0..4 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let inos = Arc::clone(&inos_arc);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..100u32 {
                for ino in inos.iter() {
                    if let Some(mut attrs) = tbl.lookup(*ino) {
                        attrs.size = attrs.size.wrapping_add(1);
                        let _ = tbl.setattr(*ino, attrs);
                    }
                    let _ = tbl.link(*ino);
                    let _ = tbl.unlink(*ino);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let dirty = tbl.dirty_count();
    assert!(
        dirty <= tbl.len(),
        "dirty_count {dirty} cannot exceed len {}",
        tbl.len()
    );

    assert_eq!(tbl.len(), tbl.iter().len());
}

// ---------------------------------------------------------------------------
// 9. Concurrent create with distinct kinds — no cross-kind corruption
// ---------------------------------------------------------------------------

#[test]
fn concurrent_create_distinct_kinds_no_cross_corruption() {
    let tbl = make_table(3000);
    let barrier = Arc::new(Barrier::new(3));
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = Vec::new();

    // Thread 1: creates only files
    {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let results = Arc::clone(&results);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..400u32 {
                match tbl.create(
                    InodeKind::File,
                    InodeAttributes::new(0o644, i, 0, InodeKind::File),
                ) {
                    Ok(ino) => results.lock().unwrap().push((ino, InodeKind::File)),
                    Err(InodeTableError::TableFull) => break,
                    Err(_) => {}
                }
            }
        }));
    }

    // Thread 2: creates only directories
    {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let results = Arc::clone(&results);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..400u32 {
                match tbl.create(
                    InodeKind::Directory,
                    InodeAttributes::new(0o755, i, 0, InodeKind::Directory),
                ) {
                    Ok(ino) => results.lock().unwrap().push((ino, InodeKind::Directory)),
                    Err(InodeTableError::TableFull) => break,
                    Err(_) => {}
                }
            }
        }));
    }

    // Thread 3: creates only symlinks
    {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let results = Arc::clone(&results);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..400u32 {
                match tbl.create(
                    InodeKind::Symlink,
                    InodeAttributes::new(0o777, i, 0, InodeKind::Symlink),
                ) {
                    Ok(ino) => results.lock().unwrap().push((ino, InodeKind::Symlink)),
                    Err(InodeTableError::TableFull) => break,
                    Err(_) => {}
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let all = results.lock().unwrap();
    assert!(!all.is_empty());

    for (ino, expected_kind) in all.iter() {
        let attrs = tbl.lookup(*ino).expect("inode must exist");
        assert_eq!(
            attrs.kind, *expected_kind,
            "kind mismatch for {ino:?}: expected {expected_kind:?}, got {:?}",
            attrs.kind
        );
    }
}

// ---------------------------------------------------------------------------
// 10. Stress: 8-thread high-throughput churn loop
// ---------------------------------------------------------------------------

#[test]
fn high_throughput_churn_8_threads() {
    let tbl = make_table(8000);
    let barrier = Arc::new(Barrier::new(8));
    let ops = Arc::new(AtomicU32::new(0));
    let errors = Arc::new(AtomicU32::new(0));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let tbl = Arc::clone(&tbl);
        let barrier = Arc::clone(&barrier);
        let ops = Arc::clone(&ops);
        let errors = Arc::clone(&errors);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..250u32 {
                match tbl.create(InodeKind::File, file_attrs(0o644)) {
                    Ok(ino) => {
                        ops.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = tbl.unlink(ino) {
                            if e != InodeTableError::InodeNotFound {
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(InodeTableError::TableFull) => {}
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        errors.load(Ordering::Relaxed),
        0,
        "unexpected errors during 8-thread churn"
    );
    let _total = ops.load(Ordering::Relaxed);

    let snapshot = tbl.iter();
    for (ino, _) in &snapshot {
        assert!(tbl.lookup(*ino).is_some());
    }
    assert_eq!(tbl.len(), snapshot.len());
}
