//! Concurrent access validation tests.
//!
//! Exercises thread-safe mutation and read paths through InlineExtentMap
//! wrapped in Arc<Mutex<>>. Tests cover:
//! - Concurrent read-lookup during write-allocate
//! - Concurrent read-iterate during free
//! - Multi-threaded alloc/free stress with invariant validation
//!
//! NOTE: InlineExtentMap derives Clone but does not implement its own
//! synchronization. Callers are responsible for external synchronization
//! (Mutex, RwLock). These tests exercise the pattern used by the FUSE
//! dispatch layer.

use std::sync::{Arc, Mutex};
use std::thread;

use tidefs_extent_map::InlineExtentMap;
use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapOps, LocatorId};

// --- helpers ---

fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
    let cs = [0xCC; 32];
    ExtentMapEntryV2::new_data(off, len, LocatorId(loc), cs, 0)
}

fn collect_all(map: &InlineExtentMap) -> Vec<ExtentMapEntryV2> {
    map.lookup_range(0, u64::MAX).unwrap_or_default()
}

// =====================================================================
// 1. Concurrent read-lookup during write-allocate
// =====================================================================

#[test]
fn concurrent_read_lookup_during_write_allocate() {
    let map = Arc::new(Mutex::new(InlineExtentMap::new()));

    // Pre-populate with 3 extents.
    {
        let mut m = map.lock().unwrap();
        m.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
            .unwrap();
    }

    let writer_map = Arc::clone(&map);
    let writer = thread::spawn(move || {
        for i in 0..10u64 {
            let mut m = writer_map.lock().unwrap();
            let _ = m.insert_extent(&[data(16384 + i * 8192, 4096, 3 + i)]);
        }
    });

    let reader_map = Arc::clone(&map);
    let reader = thread::spawn(move || {
        for _ in 0..100 {
            let m = reader_map.lock().unwrap();
            let entries = collect_all(&m);
            // Invariant: no overlap.
            for w in entries.windows(2) {
                assert!(
                    w[0].end_offset() <= w[1].logical_offset,
                    "overlap at {} and {}",
                    w[0].logical_offset,
                    w[1].logical_offset
                );
            }
        }
    });

    writer.join().unwrap();
    reader.join().unwrap();

    let m = map.lock().unwrap();
    assert!(m.validate().is_ok());
}

// =====================================================================
// 2. Concurrent read-iterate during free
// =====================================================================

#[test]
fn concurrent_read_iterate_during_free() {
    let map = Arc::new(Mutex::new(InlineExtentMap::new()));

    // Populate with 6 extents (V1 limit).
    {
        let mut m = map.lock().unwrap();
        for i in 0..6u64 {
            m.insert_extent(&[data(i * 8192, 4096, i + 1)]).unwrap();
        }
    }

    let free_map = Arc::clone(&map);
    let freer = thread::spawn(move || {
        for _ in 0..20 {
            let mut m = free_map.lock().unwrap();
            // Try to free a middle extent; if already freed, just continue.
            let _ = m.punch_hole(8192, 4096);
            // Reallocate to keep something in the map.
            let _ = m.insert_extent(&[data(8192, 4096, 9)]);
        }
    });

    let read_map = Arc::clone(&map);
    let reader = thread::spawn(move || {
        for _ in 0..200 {
            let m = read_map.lock().unwrap();
            let entries = collect_all(&m);
            // All entry lengths must be > 0.
            for e in &entries {
                assert!(e.length > 0, "zero-length entry at {}", e.logical_offset);
            }
            // entry_count must match.
            assert_eq!(
                entries.len() as u64,
                m.header.entry_count,
                "count mismatch: header={}, collected={}",
                m.header.entry_count,
                entries.len()
            );
        }
    });

    freer.join().unwrap();
    reader.join().unwrap();

    let m = map.lock().unwrap();
    assert!(m.validate().is_ok());
}

// =====================================================================
// 3. Multi-threaded alloc/free stress
// =====================================================================

#[test]
fn multi_threaded_alloc_free_stress() {
    let map = Arc::new(Mutex::new(InlineExtentMap::new()));

    // Pre-populate with 3 extents for initial structure.
    {
        let mut m = map.lock().unwrap();
        m.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)])
            .unwrap();
    }

    let num_threads = 4;
    let mut handles = Vec::new();

    for t in 0..num_threads {
        let map = Arc::clone(&map);
        let handle = thread::spawn(move || {
            // Each thread does a mix of alloc, free, and read.
            for i in 0..50 {
                let mut m = map.lock().unwrap();
                let offset = 32768 + t as u64 * 65536 + i * 4096;
                // Try to allocate.
                let _ = m.insert_extent(&[data(offset, 4096, t as u64 + 10)]);

                // Try to free a region that may or may not exist.
                let _ = m.punch_hole(offset - 4096, 4096);

                // Read and validate invariants.
                let entries = collect_all(&m);
                for w in entries.windows(2) {
                    assert!(
                        w[0].end_offset() <= w[1].logical_offset,
                        "thread {}: overlap at {} and {}",
                        t,
                        w[0].logical_offset,
                        w[1].logical_offset
                    );
                }
                assert_eq!(
                    entries.len() as u64,
                    m.header.entry_count,
                    "thread {t}: count mismatch"
                );
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let m = map.lock().unwrap();
    assert!(m.validate().is_ok());
}

// =====================================================================
// 4. Concurrent clone and independent mutation
// =====================================================================

#[test]
fn concurrent_clone_and_independent_mutation() {
    let map = Arc::new(Mutex::new(InlineExtentMap::new()));

    {
        let mut m = map.lock().unwrap();
        m.insert_extent(&[data(0, 4096, 1), data(4096, 4096, 2), data(8192, 4096, 3)])
            .unwrap();
    }

    let map_a = Arc::clone(&map);
    let handle_a = thread::spawn(move || {
        let snapshot = map_a.lock().unwrap().clone();
        let mut m = snapshot;
        m.punch_hole(0, 4096).unwrap();
        m
    });

    let map_b = Arc::clone(&map);
    let handle_b = thread::spawn(move || {
        let snapshot = map_b.lock().unwrap().clone();
        let mut m = snapshot;
        m.punch_hole(8192, 4096).unwrap();
        m
    });

    let result_a = handle_a.join().unwrap();
    let result_b = handle_b.join().unwrap();

    // Both clones independently modified.
    assert_eq!(result_a.entries.len(), 2);
    assert_eq!(result_a.entries[0].logical_offset, 4096);
    assert_eq!(result_a.entries[0].locator_id, LocatorId(2));

    assert_eq!(result_b.entries.len(), 2);
    assert_eq!(result_b.entries[0].logical_offset, 0);
    assert_eq!(result_b.entries[0].locator_id, LocatorId(1));

    assert!(result_a.validate().is_ok());
    assert!(result_b.validate().is_ok());
}
