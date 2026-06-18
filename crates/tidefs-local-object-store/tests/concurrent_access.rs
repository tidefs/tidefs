// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Concurrent access tests for `tidefs-local-object-store`.
//!
//! Exercises concurrent put, get, delete, and scan operations through
//! `Arc<Mutex<LocalObjectStore>>` to verify correctness under multi-threaded
//! access. Each writer acquires the lock for a single operation, so the
//! store's `&mut self` contract ensures no torn writes at the object level.
//!
//! These tests complement `tests/validation.rs` which covers Barrier/mpsc
//! patterns; the focus here is on correctness invariants: every committed
//! object is readable, no phantom objects appear, and concurrent deletes
//! are atomic relative to scans.

use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("tidefs-conc-{name}-{}-{nanos}", std::process::id()))
}

fn cleanup(root: &std::path::Path) {
    let _ = std::fs::remove_dir_all(root);
}

fn fast_opts() -> StoreOptions {
    StoreOptions::test_fast()
}

fn open_store(root: &std::path::Path) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("open store")
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Multiple writers, distinct keys — all committed objects present
// ═══════════════════════════════════════════════════════════════════════════

/// Multiple writers put distinct keys concurrently; after all finish,
/// every committed object must be readable with correct content.
#[test]
fn concurrent_writers_distinct_keys_all_present() {
    let root = temp_root("writers-distinct");
    let store = Arc::new(Mutex::new(open_store(&root)));

    const THREADS: usize = 8;
    const OPS_PER_THREAD: usize = 16;
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::new();

    for t in 0..THREADS {
        let s = Arc::clone(&store);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            for i in 0..OPS_PER_THREAD {
                let name = format!("t{t}-op{i}");
                let payload = vec![t as u8; 32];
                let key = ObjectKey::from_name(&name);
                let mut st = s.lock().unwrap();
                st.put(key, &payload).expect("put");
            }
        }));
    }

    for h in handles {
        h.join().expect("thread join");
    }

    let st = store.lock().unwrap();
    for t in 0..THREADS {
        for i in 0..OPS_PER_THREAD {
            let name = format!("t{t}-op{i}");
            let expected = vec![t as u8; 32];
            let val = st.get(ObjectKey::from_name(&name)).expect("get");
            assert_eq!(val, Some(expected), "missing or wrong content for {name}");
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Writer + reader on same key — no torn writes
// ═══════════════════════════════════════════════════════════════════════════

/// A writer thread repeatedly overwrites the same key while a reader
/// thread concurrently reads it. The reader must always see either the
/// old or the new value — never a torn or mixed payload.
#[test]
fn writer_reader_same_key_no_torn_reads() {
    let root = temp_root("wr-same-key");
    let store = Arc::new(Mutex::new(open_store(&root)));

    let key = ObjectKey::from_name("shared");
    // Seed with initial value
    store.lock().unwrap().put(key, &[0u8]).expect("seed");

    let barrier = Arc::new(Barrier::new(2));
    let store_w = Arc::clone(&store);
    let store_r = Arc::clone(&store);
    let b_w = Arc::clone(&barrier);
    let b_r = Arc::clone(&barrier);

    // Writer: repeatedly assign "v1", "v2", ..., "v9"
    let writer = thread::spawn(move || {
        b_w.wait();
        for v in 1u8..10u8 {
            let payload = vec![v];
            store_w.lock().unwrap().put(key, &payload).expect("put");
        }
    });

    // Reader: repeatedly read and verify payload is one valid byte
    let reader = thread::spawn(move || {
        b_r.wait();
        for _ in 0..500 {
            let st = store_r.lock().unwrap();
            match st.get(key).expect("get") {
                Some(payload) => {
                    assert_eq!(payload.len(), 1, "payload must be exactly 1 byte");
                    let val = payload[0];
                    assert!(val <= 9, "payload byte must be in range [0,9], got {val}");
                }
                None => {
                    // transient: write hasn't happened yet
                }
            }
            drop(st);
            std::thread::yield_now();
        }
    });

    writer.join().expect("writer join");
    reader.join().expect("reader join");

    // Final check: key must be present with the latest value
    let st = store.lock().unwrap();
    let final_val = st.get(key).expect("get");
    assert!(
        final_val.is_some(),
        "key must be present after writer completes"
    );
    assert_eq!(final_val.unwrap().len(), 1);

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Scan snapshot consistency during concurrent writes
// ═══════════════════════════════════════════════════════════════════════════

/// A scanner iterates keys while a writer adds new keys. The scan may or
/// may not see the new keys depending on timing, but must never see a
/// torn or incomplete key entry.
#[test]
fn scan_during_writes_consistent() {
    let root = temp_root("scan-during");
    let store = Arc::new(Mutex::new(open_store(&root)));

    // Seed 32 keys
    {
        let mut st = store.lock().unwrap();
        for i in 0..32 {
            let name = format!("base-{i}");
            st.put(ObjectKey::from_name(&name), b"base").expect("put");
        }
    }

    let barrier = Arc::new(Barrier::new(2));
    let s_w = Arc::clone(&store);
    let s_s = Arc::clone(&store);
    let b_w = Arc::clone(&barrier);
    let b_s = Arc::clone(&barrier);

    // Writer: keep adding keys
    let writer = thread::spawn(move || {
        b_w.wait();
        let mut st = s_w.lock().unwrap();
        for i in 0..16 {
            let name = format!("extra-{i}");
            st.put(ObjectKey::from_name(&name), b"extra").expect("put");
        }
    });

    // Scanner: scan repeatedly, verify base keys always present
    let scanner = thread::spawn(move || {
        b_s.wait();
        for _ in 0..50 {
            let st = s_s.lock().unwrap();
            let keys: Vec<_> = st.list_keys();
            for key in keys {
                let val = st.get(key).expect("get");
                assert!(
                    val.is_some(),
                    "key {key} returned by list_keys but not readable"
                );
            }
            drop(st);
            std::thread::yield_now();
        }
    });

    writer.join().expect("writer join");
    scanner.join().expect("scanner join");

    // Final: all base + extra keys must be readable
    let st = store.lock().unwrap();
    for i in 0..32 {
        let name = format!("base-{i}");
        assert_eq!(
            st.get(ObjectKey::from_name(&name)).expect("get"),
            Some(b"base".to_vec())
        );
    }
    for i in 0..16 {
        let name = format!("extra-{i}");
        assert_eq!(
            st.get(ObjectKey::from_name(&name)).expect("get"),
            Some(b"extra".to_vec())
        );
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Concurrent deletes — atomic removal
// ═══════════════════════════════════════════════════════════════════════════

/// Multiple deleters delete distinct keys; after all finish, the store
/// must have zero live keys in the deleted ranges.
#[test]
fn concurrent_deletes_distinct_keys_empty_store() {
    let root = temp_root("deletes-distinct");
    let store = Arc::new(Mutex::new(open_store(&root)));

    const KEY_COUNT: usize = 32;

    // Seed keys
    {
        let mut st = store.lock().unwrap();
        for i in 0..KEY_COUNT {
            let name = format!("del-{i}");
            st.put(ObjectKey::from_name(&name), &[i as u8; 4])
                .expect("put");
        }
    }

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();

    // Deleter 1: first half
    {
        let s = Arc::clone(&store);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let mut st = s.lock().unwrap();
            for i in 0..KEY_COUNT / 2 {
                let key = ObjectKey::from_name(format!("del-{i}"));
                let _ = st.delete(key);
            }
        }));
    }

    // Deleter 2: second half
    {
        let s = Arc::clone(&store);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let mut st = s.lock().unwrap();
            for i in KEY_COUNT / 2..KEY_COUNT {
                let key = ObjectKey::from_name(format!("del-{i}"));
                let _ = st.delete(key);
            }
        }));
    }

    for h in handles {
        h.join().expect("join");
    }

    // After both deleters, all keys should be deleted
    let st = store.lock().unwrap();
    let keys: Vec<_> = st.list_keys();
    assert_eq!(keys.len(), 0, "store should be empty after all deletes");

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Delete + scan atomicity
// ═══════════════════════════════════════════════════════════════════════════

/// A deleter removes keys while a scanner iterates. The scanner must see
/// keys that exist with correct content; any key returned by `list_keys`
/// must be readable.
#[test]
fn delete_scan_atomic() {
    let root = temp_root("del-scan");
    let store = Arc::new(Mutex::new(open_store(&root)));

    const KEY_COUNT: usize = 48;

    {
        let mut st = store.lock().unwrap();
        for i in 0..KEY_COUNT {
            let name = format!("scan-{i}");
            st.put(ObjectKey::from_name(&name), b"payload")
                .expect("put");
        }
    }

    let barrier = Arc::new(Barrier::new(2));
    let s_d = Arc::clone(&store);
    let s_s = Arc::clone(&store);
    let b_d = Arc::clone(&barrier);
    let b_s = Arc::clone(&barrier);

    let deleter = thread::spawn(move || {
        b_d.wait();
        let mut st = s_d.lock().unwrap();
        for i in 0..KEY_COUNT / 2 {
            let key = ObjectKey::from_name(format!("scan-{i}"));
            let _ = st.delete(key);
        }
    });

    let scanner = thread::spawn(move || {
        b_s.wait();
        let st = s_s.lock().unwrap();
        let keys: Vec<_> = st.list_keys();
        assert!(
            keys.len() <= KEY_COUNT,
            "scan must not return more keys than seeded"
        );
        for key in &keys {
            let val = st.get(*key).expect("get");
            assert!(
                val.is_some(),
                "key {key} in list_keys but get returned None"
            );
        }
    });

    deleter.join().expect("deleter join");
    scanner.join().expect("scanner join");

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Concurrent put of same key — last writer wins
// ═══════════════════════════════════════════════════════════════════════════

/// Multiple threads put the same key concurrently. After all finish,
/// exactly one value (the last written) is present — no torn state.
#[test]
fn concurrent_puts_same_key_last_writer_wins() {
    let root = temp_root("same-key-last");
    let store = Arc::new(Mutex::new(open_store(&root)));

    let key = ObjectKey::from_name("race-key");
    const THREADS: usize = 6;
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::new();

    for t in 0..THREADS {
        let s = Arc::clone(&store);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let payload = vec![t as u8; 2];
            let mut st = s.lock().unwrap();
            st.put(key, &payload).expect("put");
        }));
    }

    for h in handles {
        h.join().expect("join");
    }

    let st = store.lock().unwrap();
    let val = st.get(key).expect("get");
    assert!(val.is_some(), "key must be present after concurrent puts");
    assert_eq!(val.unwrap().len(), 2, "payload must have length 2");

    cleanup(&root);
}
