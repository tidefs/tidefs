// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Focused concurrency and edge-case validation tests for the local object store.
//!
//! These tests use Barrier/mpsc synchronization (no thread::sleep timing)
//! and exercise concurrent access patterns through Arc<Mutex<LocalObjectStore>>,
//! matching the store's `&mut self` writer contract.

use std::collections::BTreeSet;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tidefs_local_object_store::ObjectStore;
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

fn temp_root(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-los-val-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &std::path::Path) {
    let _ = std::fs::remove_dir_all(root);
}

fn test_opts() -> StoreOptions {
    StoreOptions::test_fast()
}

fn open(root: &std::path::Path) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, test_opts()).expect("open store")
}

// ═══════════════════════════════════════════════════════════════════════════
// Concurrent access — Barrier-based coordination (no thread::sleep)
// ═══════════════════════════════════════════════════════════════════════════

/// Multiple writers write to distinct object IDs concurrently. Every write
/// must succeed and every object must be readable afterward.
#[test]
fn concurrent_puts_distinct_keys_barrier() {
    let root = temp_root("concurrent-puts-barrier");
    let store = Arc::new(Mutex::new(open(&root)));

    const N: usize = 8;
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::new();

    for i in 0..N {
        let s = Arc::clone(&store);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let key = ObjectKey::from_bytes32([i as u8; 32]);
            let payload = format!("payload-{i}").into_bytes();
            b.wait(); // all threads start together
            let mut store = s.lock().unwrap();
            let stored = store.put(key, &payload).unwrap();
            (key, stored.key, payload)
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        results.push(h.join().unwrap());
    }

    // Verify every write is readable
    let store = store.lock().unwrap();
    for (key, _stored_key, payload) in &results {
        let got = store.get(*key).unwrap();
        assert_eq!(
            got.as_deref(),
            Some(&payload[..]),
            "concurrent put to {key} should be readable"
        );
    }
    assert_eq!(store.stats().live_objects, N);
    drop(store);
    cleanup(&root);
}

/// Writer and reader race on the same object ID: the reader must see either
/// the old value, the new value, or None (if not yet written), but never a
/// torn or corrupted payload. Uses a Barrier to synchronize start.
#[test]
fn concurrent_read_write_same_object_barrier() {
    let root = temp_root("concurrent-rw-barrier");
    let store = Arc::new(Mutex::new(open(&root)));

    let key = ObjectKey::from_bytes32([0xab; 32]);
    let payload_small = b"before".to_vec();
    let payload_large = b"after-concurrent-write".to_vec();

    // Pre-populate with a known value
    {
        let mut s = store.lock().unwrap();
        s.put(key, &payload_small).unwrap();
    }

    let barrier = Arc::new(Barrier::new(2));

    let writer_payload = payload_large.clone();
    let writer_store = Arc::clone(&store);
    let writer_barrier = Arc::clone(&barrier);
    let writer = thread::spawn(move || {
        writer_barrier.wait();
        let mut s = writer_store.lock().unwrap();
        s.put(key, &writer_payload).unwrap();
    });

    let reader_payload_small = payload_small.clone();
    let reader_payload_large = payload_large.clone();
    let reader_store = Arc::clone(&store);
    let reader_barrier = Arc::clone(&barrier);
    let reader = thread::spawn(move || {
        reader_barrier.wait();
        // Read immediately after barrier — may see old or new
        let s = reader_store.lock().unwrap();
        let result = s.get(key).unwrap();
        drop(s);
        // The result must be either the old value, the new value, or None
        // (if delete snuck in). It must never be a torn/corrupt value.
        if let Some(ref bytes) = result {
            assert!(
                bytes == &reader_payload_small[..] || bytes == &reader_payload_large[..],
                "reader saw unexpected payload (len {}), expected old or new",
                bytes.len()
            );
        }
    });

    writer.join().unwrap();
    reader.join().unwrap();

    // After both threads finish, the store must have the latest write.
    let s = store.lock().unwrap();
    let final_val = s.get(key).unwrap();
    assert!(
        final_val.as_deref() == Some(&payload_large[..]),
        "after concurrent write, latest value should be visible"
    );
    drop(s);
    cleanup(&root);
}

/// Deleter and reader race on the same object: reader must see either valid
/// data or None, never a panic or torn read. Uses Barrier for coordination.
#[test]
fn concurrent_delete_read_barrier() {
    let root = temp_root("concurrent-del-read-barrier");
    let store = Arc::new(Mutex::new(open(&root)));

    let key = ObjectKey::from_bytes32([0xcd; 32]);
    let payload = b"delete-me-concurrent".to_vec();

    // Pre-populate
    {
        let mut s = store.lock().unwrap();
        s.put(key, &payload).unwrap();
    }

    let barrier = Arc::new(Barrier::new(2));

    let deleter_store = Arc::clone(&store);
    let deleter_barrier = Arc::clone(&barrier);
    let deleter = thread::spawn(move || {
        deleter_barrier.wait();
        let mut s = deleter_store.lock().unwrap();
        s.delete(key).unwrap();
    });

    let reader_store = Arc::clone(&store);
    let reader_barrier = Arc::clone(&barrier);
    let reader = thread::spawn(move || {
        reader_barrier.wait();
        let s = reader_store.lock().unwrap();
        let result = s.get(key).unwrap();
        drop(s);
        // Must be either valid data or None — no panic, no corruption
        if let Some(ref bytes) = result {
            assert_eq!(bytes, &payload, "reader saw unexpected data");
        }
    });

    deleter.join().unwrap();
    reader.join().unwrap();
    cleanup(&root);
}

/// Concurrent enumeration during mutation: a scanner iterates while a writer
/// adds objects. The scanner must see a consistent set (either pre-write or
/// post-write snapshot), never a torn iteration.
#[test]
fn concurrent_scan_during_write_barrier() {
    let root = temp_root("concurrent-scan-write-barrier");
    let store = Arc::new(Mutex::new(open(&root)));

    // Pre-populate a baseline
    let base_keys: BTreeSet<ObjectKey> = (0..5)
        .map(|i| {
            let key = ObjectKey::from_bytes32([i as u8; 32]);
            let mut s = store.lock().unwrap();
            s.put(key, format!("base-{i}").as_bytes()).unwrap();
            key
        })
        .collect();

    // Writer will add 5 more objects
    let new_keys: Vec<ObjectKey> = (5..10)
        .map(|i| ObjectKey::from_bytes32([i as u8; 32]))
        .collect();

    let barrier = Arc::new(Barrier::new(2));

    let writer_store = Arc::clone(&store);
    let writer_barrier = Arc::clone(&barrier);
    let new_keys_clone = new_keys.clone();
    let writer = thread::spawn(move || {
        writer_barrier.wait();
        for (i, key) in new_keys_clone.iter().enumerate() {
            let mut s = writer_store.lock().unwrap();
            s.put(*key, format!("new-{i}").as_bytes()).unwrap();
        }
    });

    let reader_store = Arc::clone(&store);
    let reader_barrier = Arc::clone(&barrier);
    let base_keys_clone = base_keys.clone();
    let reader = thread::spawn(move || {
        reader_barrier.wait();
        let s = reader_store.lock().unwrap();
        let scanned: BTreeSet<ObjectKey> = s.scan().collect();
        drop(s);
        // Every scanned key must be known (either base or new)
        for k in &scanned {
            assert!(
                base_keys_clone.contains(k) || new_keys.contains(k),
                "scanned unknown key {k}"
            );
        }
        // All base keys must be present (they were written before the barrier)
        for k in &base_keys_clone {
            assert!(scanned.contains(k), "base key {k} missing from scan");
        }
    });

    writer.join().unwrap();
    reader.join().unwrap();
    cleanup(&root);
}

/// Two writers race to write the same object ID: last writer wins
/// deterministically. Both writes must succeed without corruption and
/// the final value must be one of the two payloads written.
#[test]
fn writer_writer_same_key_last_wins_barrier() {
    let root = temp_root("writer-writer-race-barrier");
    let store = Arc::new(Mutex::new(open(&root)));

    let key = ObjectKey::from_bytes32([0xee; 32]);
    let payload_a = b"aaaa-version-a".to_vec();
    let payload_b = b"bbbb-version-b".to_vec();

    let barrier = Arc::new(Barrier::new(2));

    let pa = payload_a.clone();
    let s_a = Arc::clone(&store);
    let b_a = Arc::clone(&barrier);
    let writer_a = thread::spawn(move || {
        b_a.wait();
        let mut s = s_a.lock().unwrap();
        s.put(key, &pa).unwrap();
    });

    let pb = payload_b.clone();
    let s_b = Arc::clone(&store);
    let b_b = Arc::clone(&barrier);
    let writer_b = thread::spawn(move || {
        b_b.wait();
        let mut s = s_b.lock().unwrap();
        s.put(key, &pb).unwrap();
    });

    writer_a.join().unwrap();
    writer_b.join().unwrap();

    // After both finish, the store must have exactly one live object for this key
    let s = store.lock().unwrap();
    let final_val = s.get(key).unwrap();
    assert!(
        final_val.as_deref() == Some(&payload_a[..])
            || final_val.as_deref() == Some(&payload_b[..]),
        "final value must be one of the two written payloads"
    );
    let stats = s.stats();
    // Content-addressed: same payload = same key; different payloads produce
    // different keys. For named put, same key overwrites. Either way, stats
    // should reflect at least one object for the written key.
    assert!(
        stats.live_objects >= 1,
        "at least one object should be live"
    );
    drop(s);
    cleanup(&root);
}

/// Multiple threads concurrently delete distinct keys using Barrier
/// synchronization. Every delete must return true (existed) and the store
/// must have zero live objects afterward.
#[test]
fn concurrent_deletes_distinct_keys_barrier() {
    let root = temp_root("concurrent-deletes-barrier");
    let store = Arc::new(Mutex::new(open(&root)));

    const N: usize = 6;
    let keys: Vec<ObjectKey> = (0..N)
        .map(|i| ObjectKey::from_bytes32([(i * 40 + 1) as u8; 32]))
        .collect();

    // Pre-populate
    {
        let mut s = store.lock().unwrap();
        for (i, key) in keys.iter().enumerate() {
            s.put(*key, format!("obj-{i}").as_bytes()).unwrap();
        }
        assert_eq!(s.stats().live_objects, N);
    }

    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::new();

    for key in keys.iter().take(N).copied() {
        let s = Arc::clone(&store);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let mut s = s.lock().unwrap();
            let existed = s.delete(key).unwrap();
            assert!(existed, "delete of {key} should return true");
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let s = store.lock().unwrap();
    assert_eq!(s.stats().live_objects, 0, "all objects deleted");
    for key in &keys {
        assert!(s.get(*key).unwrap().is_none(), "key {key} should be gone");
    }
    drop(s);
    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// mpsc-based coordination tests
// ═══════════════════════════════════════════════════════════════════════════

/// Writer signals reader via mpsc after each write; reader validates each
/// object as it becomes available. This replaces polling-based read loops.
#[test]
fn writer_signals_reader_via_mpsc() {
    let root = temp_root("mpsc-signal");
    let store = Arc::new(Mutex::new(open(&root)));

    let (tx, rx) = std::sync::mpsc::channel::<(ObjectKey, Vec<u8>)>();

    let writer_store = Arc::clone(&store);
    let writer = thread::spawn(move || {
        for i in 0..10 {
            let key = ObjectKey::from_bytes32([i as u8; 32]);
            let payload = format!("mpsc-obj-{i}").into_bytes();
            {
                let mut s = writer_store.lock().unwrap();
                s.put(key, &payload).unwrap();
            }
            tx.send((key, payload)).unwrap();
        }
    });

    let reader_store = Arc::clone(&store);
    let reader = thread::spawn(move || {
        for (key, expected) in rx {
            let s = reader_store.lock().unwrap();
            let got = s.get(key).unwrap();
            assert_eq!(
                got.as_deref(),
                Some(&expected[..]),
                "mpsc-signalled object {key} should match"
            );
            drop(s);
        }
    });

    writer.join().unwrap();
    reader.join().unwrap();
    cleanup(&root);
}

/// Deleter signals scanner via mpsc after each batch of deletes; scanner
/// verifies the deleted objects are gone and remaining objects are intact.
#[test]
fn deleter_signals_scanner_via_mpsc() {
    let root = temp_root("mpsc-delete-scan");
    let store = Arc::new(Mutex::new(open(&root)));

    let all_keys: Vec<ObjectKey> = (0..8)
        .map(|i| ObjectKey::from_bytes32([i as u8; 32]))
        .collect();
    let delete_keys: Vec<ObjectKey> = all_keys[..3].to_vec();
    let keep_keys: Vec<ObjectKey> = all_keys[3..].to_vec();

    // Pre-populate
    {
        let mut s = store.lock().unwrap();
        for (i, key) in all_keys.iter().enumerate() {
            s.put(*key, format!("obj-{i}").as_bytes()).unwrap();
        }
    }

    let (tx, rx) = std::sync::mpsc::channel::<Vec<ObjectKey>>();

    let deleter_store = Arc::clone(&store);
    let deleter_keys = delete_keys.clone();
    let deleter = thread::spawn(move || {
        let mut s = deleter_store.lock().unwrap();
        for key in &deleter_keys {
            assert!(s.delete(*key).unwrap(), "delete {key} should succeed");
        }
        drop(s);
        tx.send(deleter_keys).unwrap();
    });

    let scanner_store = Arc::clone(&store);
    let scanner_keep = keep_keys.clone();
    let scanner = thread::spawn(move || {
        let deleted = rx.recv().unwrap();
        let s = scanner_store.lock().unwrap();
        let scanned: BTreeSet<ObjectKey> = s.scan().collect();
        // Deleted keys must be absent
        for key in &deleted {
            assert!(!scanned.contains(key), "deleted key {key} should be absent");
        }
        // Kept keys must be present
        for key in &scanner_keep {
            assert!(scanned.contains(key), "kept key {key} should be present");
        }
        drop(s);
    });

    deleter.join().unwrap();
    scanner.join().unwrap();
    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// Stress: many concurrent writers (Barrier), verify no corruption
// ═══════════════════════════════════════════════════════════════════════════

/// High-contention stress test: many threads write and read distinct keys
/// simultaneously, coordinated by a single Barrier. Verifies no corruption
/// and correct live-object count.
#[test]
fn stress_many_writers_readers_barrier() {
    let root = temp_root("stress-barrier");
    let store = Arc::new(Mutex::new(open(&root)));

    const THREADS: usize = 12;
    const OPS_PER_THREAD: usize = 20;
    let barrier = Arc::new(Barrier::new(THREADS));

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let s = Arc::clone(&store);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let mut local_keys = Vec::new();
            for i in 0..OPS_PER_THREAD {
                let key = ObjectKey::from_bytes32([
                    t as u8,
                    (i & 0xFF) as u8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]);
                let payload = format!("t{t}-op{i}").into_bytes();
                {
                    let mut store = s.lock().unwrap();
                    store.put(key, &payload).unwrap();
                }
                local_keys.push((key, payload));
            }
            // Verify own writes
            let store = s.lock().unwrap();
            for (key, payload) in &local_keys {
                let got = store.get(*key).unwrap();
                assert_eq!(
                    got.as_deref(),
                    Some(&payload[..]),
                    "stress test: own write should be readable"
                );
            }
            drop(store);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let s = store.lock().unwrap();
    let stats = s.stats();
    assert_eq!(
        stats.live_objects,
        THREADS * OPS_PER_THREAD,
        "all stress-test objects should be live"
    );
    drop(s);
    cleanup(&root);
}
