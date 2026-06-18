// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Concurrency safety tests for tidefs-gc-pin-set.
// Verifies correct behaviour under multi-threaded access via Arc<Mutex<GcPinSet>>.
// Updated for ref-counted pinning: pin() on same root increments count.

use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use tidefs_gc_pin_set::{GcPinError, GcPinSet};
use tidefs_types_dataset_lifecycle_core::{BlockPointer, TraversalRoot, TraversalRootType};

const ALL_TYPES: [TraversalRootType; 6] = [
    TraversalRootType::InodeTable,
    TraversalRootType::ExtentMap,
    TraversalRootType::DirectoryIndex,
    TraversalRootType::XattrStore,
    TraversalRootType::SnapshotCatalog,
    TraversalRootType::FeatureFlags,
];

fn make_root(rt: TraversalRootType, bp: u64) -> TraversalRoot {
    TraversalRoot::new(rt, BlockPointer(bp), (bp % 1000) + 1)
}

// ---------------------------------------------------------------------------
// Each thread pins its assigned root type, then unpins it.
// Final state must be empty with count 0.
// ---------------------------------------------------------------------------
#[test]
fn concurrent_pin_unpin_distinct_types() {
    let set = Arc::new(Mutex::new(GcPinSet::<6>::new()));
    let mut handles = Vec::new();

    for (i, &rt) in ALL_TYPES.iter().enumerate() {
        let set = Arc::clone(&set);
        let handle = thread::spawn(move || {
            let root = make_root(rt, (i + 1) as u64);
            {
                let mut s = set.lock().unwrap();
                s.pin(root).unwrap();
            }
            {
                let mut s = set.lock().unwrap();
                s.unpin(root).unwrap();
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let s = set.lock().unwrap();
    assert!(s.is_empty());
    assert_eq!(s.count(), 0);
}

// ---------------------------------------------------------------------------
// All threads pin concurrently via a barrier, then all unpin.
// ---------------------------------------------------------------------------
#[test]
fn concurrent_pin_then_unpin_all() {
    let n = 6usize;
    let set = Arc::new(Mutex::new(GcPinSet::<6>::new()));
    let barrier = Arc::new(Barrier::new(n));

    let mut handles = Vec::new();
    for (i, &rt) in ALL_TYPES.iter().enumerate() {
        let set = Arc::clone(&set);
        let barrier = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            let root = make_root(rt, (i + 1) as u64);
            barrier.wait(); // all threads start together
            {
                let mut s = set.lock().unwrap();
                let _ = s.pin(root);
            }
            barrier.wait(); // all threads pinned before unpin
            {
                let mut s = set.lock().unwrap();
                let _ = s.unpin(root);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let s = set.lock().unwrap();
    assert!(s.is_empty());
}

// ---------------------------------------------------------------------------
// Stress test: N threads randomly pin/unpin the same set of root types.
// Final invariant: count never exceeds capacity, and after all threads
// finish, the set has valid state.
// With ref-counted pinning, multiple threads can pin the same type.
// ---------------------------------------------------------------------------
#[test]
fn concurrent_stress_random_ops() {
    let set = Arc::new(Mutex::new(GcPinSet::<6>::new()));
    let n_threads = 8;
    let ops_per_thread = 200;
    let barrier = Arc::new(Barrier::new(n_threads));

    let mut handles = Vec::new();
    for tid in 0..n_threads {
        let set = Arc::clone(&set);
        let barrier = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            barrier.wait();
            for j in 0..ops_per_thread {
                let rt = ALL_TYPES[(tid + j) % 6];
                let root = make_root(rt, (tid * 1000 + j) as u64);
                {
                    let mut s = set.lock().unwrap();
                    match s.pin(root) {
                        Ok(()) => {
                            // Hold briefly, then release.
                            s.unpin(root).unwrap();
                        }
                        Err(GcPinError::Full { .. }) => {
                            // Set is full; unpin any exact root and retry.
                            let to_unpin = s.pinned_roots().next().copied();
                            if let Some(to_unpin) = to_unpin {
                                s.unpin(to_unpin).ok();
                            }
                            let _ = s.pin(root);
                        }
                        Err(_) => {}
                    }
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let s = set.lock().unwrap();
    assert!(s.count() <= 6);
    // With full-root identity, no duplicate-root check is needed here.
}

// ---------------------------------------------------------------------------
// Ref-counted duplicate pin: multiple threads pin the same exact root
// concurrently. All should succeed (refcount increments).
// ---------------------------------------------------------------------------
#[test]
fn concurrent_ref_counted_pin() {
    let set = Arc::new(Mutex::new(GcPinSet::<6>::new()));
    let n_threads = 6;
    let barrier = Arc::new(Barrier::new(n_threads));
    let success_count = Arc::new(Mutex::new(0usize));

    let mut handles = Vec::new();
    for _tid in 0..n_threads {
        let set = Arc::clone(&set);
        let barrier = Arc::clone(&barrier);
        let success_count = Arc::clone(&success_count);
        let handle = thread::spawn(move || {
            let root = make_root(TraversalRootType::InodeTable, 1);
            barrier.wait();
            {
                let mut s = set.lock().unwrap();
                if let Ok(()) = s.pin(root) {
                    let mut sc = success_count.lock().unwrap();
                    *sc += 1;
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let sc = *success_count.lock().unwrap();
    assert_eq!(sc, 6, "all threads should pin InodeTable (ref-counted)");

    let s = set.lock().unwrap();
    assert_eq!(s.count(), 1); // one slot
    assert_eq!(s.total_pins(), 6); // six refs
    assert!(s.is_pinned(make_root(TraversalRootType::InodeTable, 1)));
}

// ---------------------------------------------------------------------------
// Concurrent capacity stress: threads pin until full, then unpin.
// Verifies no panic under contention at capacity boundary.
// ---------------------------------------------------------------------------
#[test]
fn concurrent_capacity_boundary() {
    let set = Arc::new(Mutex::new(GcPinSet::<3>::new()));
    let n_threads = 6;
    let barrier = Arc::new(Barrier::new(n_threads));

    let mut handles = Vec::new();
    for tid in 0..n_threads {
        let set = Arc::clone(&set);
        let barrier = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            let rt = ALL_TYPES[tid % 6];
            let root = make_root(rt, tid as u64);
            barrier.wait();
            for _ in 0..100 {
                let mut s = set.lock().unwrap();
                match s.pin(root) {
                    Ok(()) => {}
                    Err(GcPinError::Full { .. }) => {
                        // Fallback: unpin someone else and retry.
                        let to_unpin = s.pinned_roots().next().copied();
                        if let Some(to_unpin) = to_unpin {
                            s.unpin(to_unpin).ok();
                        }
                        let _ = s.pin(root);
                    }
                    Err(_) => {}
                }
            }
            // Final cleanup: unpin own type
            let mut s = set.lock().unwrap();
            while s.is_pinned(root) {
                s.unpin(root).ok();
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    // No panic is the primary assertion; also verify state is valid.
    let s = set.lock().unwrap();
    assert!(s.count() <= 3);
}

// ---------------------------------------------------------------------------
// Drop behaviour under concurrency: all threads pin, then drop the Arc.
// Verify no panic on drop.
// ---------------------------------------------------------------------------
#[test]
fn concurrent_drop_no_panic() {
    let set = Arc::new(Mutex::new(GcPinSet::<6>::new()));
    let n_threads = 4;
    let barrier = Arc::new(Barrier::new(n_threads));

    let mut handles = Vec::new();
    for tid in 0..n_threads {
        let set = Arc::clone(&set);
        let barrier = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            let rt = ALL_TYPES[tid % 6];
            let root = make_root(rt, tid as u64);
            barrier.wait();
            {
                let mut s = set.lock().unwrap();
                let _ = s.pin(root);
            }
            // Do not explicitly unpin — drop will handle it.
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    // Drop the Arc<Mutex<GcPinSet>> — must not panic.
    drop(set);
}
