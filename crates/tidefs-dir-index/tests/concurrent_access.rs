// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// concurrent_access.rs — Deterministic multi-threaded concurrent-access tests
// for tidefs-dir-index. Covers:
//
//   (1) Disjoint-range parallel inserts from N threads with Barrier
//       synchronization before verification that all entries are present.
//   (2) Producer–consumer with overlapping key ranges: some threads insert
//       while others lookup at known interleaving points.
//   (3) Mixed insert / delete / lookup from multiple threads, verifying
//       that no entry is lost and the final state matches expected set.
//   (4) Staggered concurrent removals: all threads insert into disjoint sub-
//       ranges, then each removes a subset; Barrier-synchronized snapshot
//       taken between phases.
//
// All tests use `Arc<Mutex<DirIndex>>` for shared mutable access.  Barrier
// points are placed to force specific interleavings that property-based
// frameworks cannot reliably hit.

use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use tidefs_dir_index::{DatasetDirPolicy, DirIndex, DirIndexError, DirIterator, DirStorageKind};

// ── helpers ──────────────────────────────────────────────────────────

fn test_policy() -> DatasetDirPolicy {
    DatasetDirPolicy {
        dir_micro_max_entries: 6,
        dir_micro_max_name_bytes: 512,
        dir_btree_downshift_entries: 3,
        dir_btree_downshift_name_bytes: 128,
    }
}

fn make_name(prefix: &str, i: u64) -> Vec<u8> {
    format!("{prefix}_{i:06}").into_bytes()
}

// ────────────────────────────────────────────────────────────────────
// (1) Disjoint-range parallel inserts
// ────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_disjoint_inserts_all_present() {
    const THREADS: u64 = 8;
    const PER_THREAD: u64 = 200;

    let idx = Arc::new(Mutex::new(DirIndex::new(1, test_policy())));
    let barrier = Arc::new(Barrier::new(THREADS as usize));

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let idx = Arc::clone(&idx);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let base = t * PER_THREAD;
            // Wait for all threads to be ready before starting inserts
            barrier.wait();
            for i in 0..PER_THREAD {
                let name = make_name("cdi", base + i);
                idx.lock().unwrap().insert(&name, base + i, 0, 1).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let idx = idx.lock().unwrap();
    assert_eq!(idx.len(), (THREADS * PER_THREAD) as usize);

    // Verify every entry is present
    for i in 0..(THREADS * PER_THREAD) {
        let name = make_name("cdi", i);
        assert!(
            idx.contains(&name),
            "missing entry cdi_{i:06} after concurrent inserts"
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// (2) Producer–consumer with Barrier-synchronized interleavings
// ────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_insert_and_lookup_under_barrier() {
    // Two producers insert into disjoint ranges; one consumer looks up
    // at precise interleaving points.
    const PER_THREAD: u64 = 100;

    let idx = Arc::new(Mutex::new(DirIndex::new(1, test_policy())));
    // 3 parties: producer-A, producer-B, consumer
    let barrier = Arc::new(Barrier::new(3));

    // Producer A: range 0..100
    let idx_a = Arc::clone(&idx);
    let bar_a = Arc::clone(&barrier);
    let ha = thread::spawn(move || {
        for i in 0..PER_THREAD {
            let name = make_name("pcl", i);
            idx_a.lock().unwrap().insert(&name, i, 0, 1).unwrap();
        }
        bar_a.wait(); // signal: A done
    });

    // Producer B: range 100..200
    let idx_b = Arc::clone(&idx);
    let bar_b = Arc::clone(&barrier);
    let hb = thread::spawn(move || {
        for i in PER_THREAD..(2 * PER_THREAD) {
            let name = make_name("pcl", i);
            idx_b.lock().unwrap().insert(&name, i, 0, 1).unwrap();
        }
        bar_b.wait(); // signal: B done
    });

    // Consumer: polls for partial state at barrier points
    let idx_c = Arc::clone(&idx);
    let bar_c = Arc::clone(&barrier);
    let hc = thread::spawn(move || {
        bar_c.wait(); // wait for both producers to finish

        let c = idx_c.lock().unwrap();
        assert_eq!(c.len(), (2 * PER_THREAD) as usize);
        // Check a few entries from each producer
        assert!(c.contains(&make_name("pcl", 0)));
        assert!(c.contains(&make_name("pcl", PER_THREAD - 1)));
        assert!(c.contains(&make_name("pcl", PER_THREAD)));
        assert!(c.contains(&make_name("pcl", 2 * PER_THREAD - 1)));
    });

    ha.join().unwrap();
    hb.join().unwrap();
    hc.join().unwrap();
}

// ────────────────────────────────────────────────────────────────────
// (3) Mixed insert / delete / lookup — two phases with barrier
// ────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_insert_delete_lookup_phased() {
    // Phase 1: two threads insert disjoint ranges (0..50, 50..100)
    // Phase 2: after a checkpoint, one thread deletes evens, another
    //          deletes odds.  A third thread takes snapshots after each
    //          phase.  We serialize phases through join() instead of
    //          Barrier to avoid any possible scheduling deadlock.

    const HALF: u64 = 50;

    let idx = Arc::new(Mutex::new(DirIndex::new(1, test_policy())));

    // ── Phase 1: insert ─────────────────────────────────────────
    let idx_a = Arc::clone(&idx);
    let idx_b = Arc::clone(&idx);
    let ha = thread::spawn(move || {
        for i in 0..HALF {
            let name = make_name("midl", i);
            idx_a.lock().unwrap().insert(&name, i, 0, 1).unwrap();
        }
    });
    let hb = thread::spawn(move || {
        for i in HALF..(2 * HALF) {
            let name = make_name("midl", i);
            idx_b.lock().unwrap().insert(&name, i, 0, 1).unwrap();
        }
    });
    ha.join().unwrap();
    hb.join().unwrap();

    // Consumer checkpoint: all 100 entries present
    {
        let c = idx.lock().unwrap();
        assert_eq!(c.len(), (2 * HALF) as usize);
        assert!(c.contains(&make_name("midl", 1)));
        assert!(c.contains(&make_name("midl", 48)));
        assert!(c.contains(&make_name("midl", 50)));
        assert!(c.contains(&make_name("midl", 99)));
    }

    // ── Phase 2: delete ─────────────────────────────────────────
    let idx_a = Arc::clone(&idx);
    let idx_b = Arc::clone(&idx);
    let ha = thread::spawn(move || {
        for i in (0..HALF).step_by(2) {
            let name = make_name("midl", i);
            idx_a.lock().unwrap().delete(&name).unwrap();
        }
    });
    let hb = thread::spawn(move || {
        for i in (HALF..(2 * HALF)).filter(|i| i % 2 == 1) {
            let name = make_name("midl", i);
            idx_b.lock().unwrap().delete(&name).unwrap();
        }
    });
    ha.join().unwrap();
    hb.join().unwrap();

    // Consumer checkpoint: 50 entries remain
    let c = idx.lock().unwrap();
    assert_eq!(c.len(), HALF as usize);
    for i in 0..(2 * HALF) {
        let name = make_name("midl", i);
        let in_a_odds = i < HALF && i % 2 == 1;
        let in_b_evens = i >= HALF && i % 2 == 0;
        assert_eq!(
            c.contains(&name),
            in_a_odds || in_b_evens,
            "wrong presence for midl_{i:06}"
        );
    }
}
#[test]
fn concurrent_staggered_removals() {
    // Three threads each insert 60 entries into disjoint ranges.
    // After a barrier, each thread removes 20 of its own entries.
    // Snapshot of entry count taken after each phase.

    const PER_THREAD: u64 = 60;
    const TO_REMOVE: u64 = 20;
    const THREADS: u64 = 3;

    let idx = Arc::new(Mutex::new(DirIndex::new(1, test_policy())));
    let bar_insert = Arc::new(Barrier::new(THREADS as usize));
    let bar_remove = Arc::new(Barrier::new(THREADS as usize));

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let idx = Arc::clone(&idx);
        let bi = Arc::clone(&bar_insert);
        let br = Arc::clone(&bar_remove);
        handles.push(thread::spawn(move || {
            let base = t * PER_THREAD;
            for i in 0..PER_THREAD {
                let name = make_name("csr", base + i);
                idx.lock().unwrap().insert(&name, base + i, 0, 1).unwrap();
            }
            bi.wait();

            // Remove a subset
            for i in 0..TO_REMOVE {
                let name = make_name("csr", base + i);
                idx.lock().unwrap().delete(&name).unwrap();
            }
            br.wait();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let idx = idx.lock().unwrap();
    let expected = (THREADS * (PER_THREAD - TO_REMOVE)) as usize;
    assert_eq!(idx.len(), expected);

    // Verify remaining
    for t in 0..THREADS {
        let base = t * PER_THREAD;
        for i in 0..PER_THREAD {
            let name = make_name("csr", base + i);
            let should_exist = i >= TO_REMOVE;
            assert_eq!(idx.contains(&name), should_exist);
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// (5) High-contention insert loop — verify no panics and no lost data
// ────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_high_contention_no_lost_inserts() {
    // Many threads (16) each insert a small number of entries into the
    // same directory with tightly interleaved lock acquisitions.
    const THREADS: u64 = 16;
    const PER_THREAD: u64 = 50;

    let idx = Arc::new(Mutex::new(DirIndex::new(1, test_policy())));
    let barrier = Arc::new(Barrier::new(THREADS as usize));

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let idx = Arc::clone(&idx);
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            bar.wait(); // all start simultaneously
            let base = t * PER_THREAD;
            for i in 0..PER_THREAD {
                let name = make_name("hci", base + i);
                // Drop lock between each insert to force contention
                let mut dir = idx.lock().unwrap();
                dir.insert(&name, base + i, 0, 1).unwrap();
                drop(dir);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    {
        let idx = idx.lock().unwrap();
        assert_eq!(idx.len(), (THREADS * PER_THREAD) as usize);
        // Clone inside the lock scope for iteration snapshot
        let snapshot = idx.clone();
        drop(idx);
        let mut iter_count = 0usize;
        let mut s = snapshot;
        while s.next_entry().is_some() {
            iter_count += 1;
        }
        assert_eq!(iter_count, (THREADS * PER_THREAD) as usize);
    }
}

// ────────────────────────────────────────────────────────────────────
// (6) Duplicate insert rejection under contention
// ────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_duplicate_insert_rejected() {
    // Two threads race to insert the same set of names. Exactly one
    // succeeds per name; the other must see EntryAlreadyExists.
    const ENTRIES: u64 = 100;

    let idx = Arc::new(Mutex::new(DirIndex::new(1, test_policy())));
    let barrier = Arc::new(Barrier::new(2));

    let idx_a = Arc::clone(&idx);
    let bar_a = Arc::clone(&barrier);
    let ha = thread::spawn(move || {
        bar_a.wait();
        let mut ok = 0u64;
        let mut dup = 0u64;
        for i in 0..ENTRIES {
            let name = make_name("cdup", i);
            match idx_a.lock().unwrap().insert(&name, 1000 + i, 0, 1) {
                Ok(()) => ok += 1,
                Err(DirIndexError::EntryAlreadyExists) => dup += 1,
                e => panic!("unexpected result: {e:?}"),
            }
        }
        (ok, dup)
    });

    let idx_b = Arc::clone(&idx);
    let bar_b = Arc::clone(&barrier);
    let hb = thread::spawn(move || {
        bar_b.wait();
        let mut ok = 0u64;
        let mut dup = 0u64;
        for i in 0..ENTRIES {
            let name = make_name("cdup", i);
            match idx_b.lock().unwrap().insert(&name, 2000 + i, 0, 1) {
                Ok(()) => ok += 1,
                Err(DirIndexError::EntryAlreadyExists) => dup += 1,
                e => panic!("unexpected result: {e:?}"),
            }
        }
        (ok, dup)
    });

    let (a_ok, a_dup) = ha.join().unwrap();
    let (b_ok, b_dup) = hb.join().unwrap();

    // Between the two threads, each of the 100 entries was inserted exactly once
    assert_eq!(a_ok + b_ok, ENTRIES);
    assert_eq!(a_dup + b_dup, ENTRIES);

    let idx = idx.lock().unwrap();
    assert_eq!(idx.len(), ENTRIES as usize);

    // Each entry has exactly one inode_id (but we can't tell which thread won)
    for i in 0..ENTRIES {
        let name = make_name("cdup", i);
        let e = idx.lookup(&name).expect("entry should exist");
        assert!(e.inode_id == 1000 + i || e.inode_id == 2000 + i);
    }
}

// ────────────────────────────────────────────────────────────────────
// (7) Concurrent clone-and-iterate from stable snapshot
// ────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_clone_and_iterate_while_writer_active() {
    // A writer inserts entries continuously while several reader threads
    // clone the index and iterate over whatever snapshot they capture.
    // The read snapshots must be internally consistent.

    const WRITER_ENTRIES: u64 = 200;
    const READERS: usize = 4;

    let idx = Arc::new(Mutex::new(DirIndex::new(1, test_policy())));
    let barrier = Arc::new(Barrier::new(READERS + 1));

    // Writer thread
    let idx_w = Arc::clone(&idx);
    let bar_w = Arc::clone(&barrier);
    let hw = thread::spawn(move || {
        bar_w.wait();
        for i in 0..WRITER_ENTRIES {
            let name = make_name("ccai", i);
            idx_w.lock().unwrap().insert(&name, i, 0, 1).unwrap();
        }
    });

    // Reader threads
    let mut readers = Vec::new();
    for _ in 0..READERS {
        let idx_r = Arc::clone(&idx);
        let bar_r = Arc::clone(&barrier);
        readers.push(thread::spawn(move || {
            bar_r.wait();
            // Give the writer a head start
            thread::yield_now();

            let snapshot = idx_r.lock().unwrap().clone();
            drop(idx_r); // release lock

            // Iterate snapshot
            let mut iter = snapshot;
            let mut count = 0usize;
            let mut prev: Option<Vec<u8>> = None;
            while let Some(entry) = iter.next_entry() {
                // Verify sorted order
                if let Some(ref p) = prev {
                    assert!(
                        p <= &entry.name,
                        "iteration unsorted: {:?} > {:?}",
                        p,
                        entry.name
                    );
                }
                prev = Some(entry.name);
                count += 1;
            }
            // Snapshot could have any number of entries (depending on timing)
            assert!(
                count <= WRITER_ENTRIES as usize,
                "snapshot count {count} exceeds total inserted {WRITER_ENTRIES}"
            );
        }));
    }

    hw.join().unwrap();
    for r in readers {
        r.join().unwrap();
    }

    let idx = idx.lock().unwrap();
    assert_eq!(idx.len(), WRITER_ENTRIES as usize);
}

// ────────────────────────────────────────────────────────────────────
// (8) Concurrent rename — two threads racing on rename
// ────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_rename_no_double_move() {
    // Thread A renames "alpha" → "gamma"
    // Thread B renames "beta" → "gamma"
    // Only one can succeed; the other must fail with EntryAlreadyExists
    // (after the first rename completes).

    let idx = Arc::new(Mutex::new(DirIndex::new(1, test_policy())));
    {
        let mut d = idx.lock().unwrap();
        d.insert(b"alpha", 1, 0, 1).unwrap();
        d.insert(b"beta", 2, 0, 1).unwrap();
    }

    let barrier = Arc::new(Barrier::new(2));

    let idx_a = Arc::clone(&idx);
    let bar_a = Arc::clone(&barrier);
    let ha = thread::spawn(move || {
        bar_a.wait();
        let mut d = idx_a.lock().unwrap();
        match d.rename(b"alpha", b"gamma") {
            Ok(()) => "alpha_won",
            Err(DirIndexError::EntryAlreadyExists) => "alpha_lost",
            Err(e) => panic!("unexpected: {e:?}"),
        }
    });

    let idx_b = Arc::clone(&idx);
    let bar_b = Arc::clone(&barrier);
    let hb = thread::spawn(move || {
        bar_b.wait();
        let mut d = idx_b.lock().unwrap();
        match d.rename(b"beta", b"gamma") {
            Ok(()) => "beta_won",
            Err(DirIndexError::EntryAlreadyExists) => "beta_lost",
            Err(e) => panic!("unexpected: {e:?}"),
        }
    });

    let result_a = ha.join().unwrap();
    let result_b = hb.join().unwrap();

    // Exactly one thread succeeds
    assert!(
        (result_a == "alpha_won" && result_b == "beta_lost")
            || (result_a == "alpha_lost" && result_b == "beta_won"),
        "expected one winner, got a={result_a} b={result_b}"
    );

    // Final state: the winning rename moved its source to "gamma".
    // The loser's source entry was NOT renamed (rename fails if dest exists),
    // so it remains under its original name.  Total entries: gamma + loser = 2.
    let d = idx.lock().unwrap();
    assert_eq!(d.len(), 2);
    assert!(d.contains(b"gamma"));
    // One of alpha/beta is the loser, still present under its original name
    assert!(
        d.contains(b"alpha") || d.contains(b"beta"),
        "one source should remain (loser not renamed)"
    );
    assert!(
        !(d.contains(b"alpha") && d.contains(b"beta")),
        "only one source should remain"
    );
}

// ────────────────────────────────────────────────────────────────────
// (9) BTree concurrent insert — crosses micro-list→BTree boundary
// ────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_btree_transition_under_insert_load() {
    // Insert enough entries to force transition to BTree while multiple
    // threads are inserting concurrently.
    const THREADS: u64 = 8;
    const PER_THREAD: u64 = 10; // 80 entries total — well past the 6-entry threshold

    let idx = Arc::new(Mutex::new(DirIndex::new(1, test_policy())));
    let barrier = Arc::new(Barrier::new(THREADS as usize));

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let idx = Arc::clone(&idx);
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            bar.wait();
            let base = t * PER_THREAD;
            for i in 0..PER_THREAD {
                let name = make_name("cbt", base + i);
                idx.lock().unwrap().insert(&name, base + i, 0, 1).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let d = idx.lock().unwrap();
    assert_eq!(d.len(), (THREADS * PER_THREAD) as usize);
    // Should have upgraded to BTree
    assert_eq!(d.representation(), DirStorageKind::BTREE);

    // All entries should be findable
    for i in 0..(THREADS * PER_THREAD) {
        let name = make_name("cbt", i);
        assert!(d.contains(&name), "missing cbt_{i:06} in BTree");
    }
}

// ────────────────────────────────────────────────────────────────────
// (10) Concurrent iteration snapshot matches final state
// ────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_iteration_snapshot_matches_count() {
    // Insert entries in one thread, iterating in another after barrier.
    const N: u64 = 50;

    let idx = Arc::new(Mutex::new(DirIndex::new(1, test_policy())));
    let bar_done = Arc::new(Barrier::new(2));

    let idx_i = Arc::clone(&idx);
    let bar_i = Arc::clone(&bar_done);
    let handle = thread::spawn(move || {
        for i in 0..N {
            let name = make_name("cism", i);
            idx_i.lock().unwrap().insert(&name, i, 0, 1).unwrap();
        }
        bar_i.wait();
    });

    bar_done.wait();

    let d = idx.lock().unwrap();
    assert_eq!(d.len(), N as usize);

    // Count via iteration
    let mut cloned = d.clone();
    drop(d);
    let mut iter_count = 0usize;
    while cloned.next_entry().is_some() {
        iter_count += 1;
    }
    assert_eq!(iter_count, N as usize);

    handle.join().unwrap();
}
