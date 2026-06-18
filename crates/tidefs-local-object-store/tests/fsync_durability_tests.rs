// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Fsync durability validation tests for `tidefs-local-object-store`.
//!
//! Validates that `sync_all()` (the fsync primitive) commits data to durable
//! storage so it survives process restart. Complements `durability.rs` (which
//! tests write-then-read round-tripping within a single session) and
//! `crash_recovery.rs` (which tests torn-write repair). The focus here is on
//! explicit fsync semantics: what happens when sync_all is called between
//! writes, after overwrites, and under concurrent access.
//!
//! Test groups:
//! 1. Single-object write+sync+reopen: byte-for-byte survival
//! 2. Multi-object sync ordering: A then B, both survive
//! 3. Sync-after-overwrite: new data survives, old data is gone
//! 4. Mixed synced/unsynced: only synced objects survive reopen
//! 5. Multiple sync_all calls: incremental durability across writes
//! 6. Sync after delete: tombstone persists across reopen
//! 7. Concurrent write+sync+reopen: all synced objects survive
//! 8. Large payload sync: multi-KiB objects survive fsync+reopen
//! 9. sync and sync_all are equivalent (API contract)

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-fsync-dur-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

fn fast_opts() -> StoreOptions {
    // Keep sync_on_write false so explicit sync_all calls carry the durability
    // claim, while preserving production-equivalent read checksum verification.
    StoreOptions {
        max_segment_bytes: 16384,
        verify_read_checksums: true,
        ..StoreOptions::test_fast()
    }
}

fn open_store(root: &PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("open store")
}

fn reopen_store(root: &PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("reopen store")
}

/// Return a deterministic pseudo-random byte vector of `len` bytes.
fn pseudo_random_data(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
        out.push((state >> 24) as u8);
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Single-object write+sync+reopen
// ═══════════════════════════════════════════════════════════════════════════

/// Write a single object, fsync, drop the store, reopen, and verify the
/// object is byte-for-byte identical.
#[test]
fn single_object_sync_survives_reopen() {
    let root = temp_root("single-sync-reopen");

    let key = ObjectKey::from_name("solo");
    let payload = b"this payload must survive fsync and reopen";

    {
        let mut store = open_store(&root);
        store.put(key, payload).expect("put");
        store.sync_all().expect("sync_all");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 1);
        let got = store.get(key).expect("get").expect("object must exist");
        assert_eq!(
            got, payload,
            "payload must survive sync_all + reopen byte-for-byte"
        );
    }

    cleanup(&root);
}

/// Write, sync, reopen with no write in between (empty reopen after sync).
#[test]
fn sync_without_write_preserves_state() {
    let root = temp_root("sync-no-write");

    {
        let mut store = open_store(&root);
        store
            .put(ObjectKey::from_name("a"), b"data-a")
            .expect("put a");
        store.sync_all().expect("sync_all");
        // Second sync_all without an intervening write
        store.sync_all().expect("sync_all again");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 1);
        assert_eq!(
            store.get(ObjectKey::from_name("a")).expect("get"),
            Some(b"data-a".to_vec())
        );
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Multi-object fsync ordering
// ═══════════════════════════════════════════════════════════════════════════

/// Write A, sync, write B, sync — both must survive reopen.
#[test]
fn incremental_sync_preserves_both_objects() {
    let root = temp_root("incremental-sync");

    let key_a = ObjectKey::from_name("alpha");
    let key_b = ObjectKey::from_name("bravo");
    let payload_a = b"first-object-written";
    let payload_b = b"second-object-written";

    {
        let mut store = open_store(&root);
        store.put(key_a, payload_a).expect("put a");
        store.sync_all().expect("sync a");

        store.put(key_b, payload_b).expect("put b");
        store.sync_all().expect("sync b");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 2);

        let got_a = store.get(key_a).expect("get a").expect("a must exist");
        assert_eq!(got_a, payload_a, "object A must survive incremental sync");

        let got_b = store.get(key_b).expect("get b").expect("b must exist");
        assert_eq!(got_b, payload_b, "object B must survive incremental sync");
    }

    cleanup(&root);
}

/// Write A and B, then sync once — both must survive (single sync covers
/// all unsynced writes).
#[test]
fn batch_sync_preserves_multiple_objects() {
    let root = temp_root("batch-sync");

    let objects: Vec<(String, Vec<u8>)> = (0..5)
        .map(|i| {
            let name = format!("obj-{i}");
            let payload = pseudo_random_data(64, i as u64);
            (name, payload)
        })
        .collect();

    {
        let mut store = open_store(&root);
        for (name, payload) in &objects {
            store.put(ObjectKey::from_name(name), payload).expect("put");
        }
        store.sync_all().expect("sync_all after batch");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, objects.len());
        for (name, payload) in &objects {
            let got = store
                .get(ObjectKey::from_name(name))
                .expect("get")
                .unwrap_or_else(|| panic!("{name} must exist after batch sync"));
            assert_eq!(&got, payload, "{name} payload mismatch after batch sync");
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Sync-after-overwrite
// ═══════════════════════════════════════════════════════════════════════════

/// Overwrite an existing object, sync, reopen — new data persists, old is gone.
#[test]
fn overwrite_then_sync_preserves_new_data() {
    let root = temp_root("overwrite-sync");

    let key = ObjectKey::from_name("target");
    let old_data = b"original-data-that-gets-overwritten";
    let new_data = b"new-data-after-overwrite";

    {
        let mut store = open_store(&root);
        store.put(key, old_data).expect("put old");
        store.sync_all().expect("sync old");

        store.put(key, new_data).expect("put new (overwrite)");
        store.sync_all().expect("sync new");
    }

    {
        let store = reopen_store(&root);
        let got = store.get(key).expect("get").expect("object must exist");
        assert_eq!(
            got, new_data,
            "overwritten payload must survive sync+reopen"
        );
        assert_ne!(
            got, old_data,
            "old payload must not reappear after overwrite+sync"
        );
    }

    cleanup(&root);
}

/// Multiple overwrites of the same key, each followed by sync; the last
/// write must be the one that survives.
#[test]
fn repeated_overwrite_with_sync_keeps_last() {
    let root = temp_root("repeated-overwrite-sync");

    let key = ObjectKey::from_name("cycle");
    let v1 = pseudo_random_data(256, 1);
    let v2 = pseudo_random_data(256, 2);
    let v3 = pseudo_random_data(256, 3);
    let v4 = pseudo_random_data(256, 4);

    {
        let mut store = open_store(&root);
        for (payload, label) in &[(&v1, "v1"), (&v2, "v2"), (&v3, "v3"), (&v4, "v4")] {
            store.put(key, payload).expect(label);
            store.sync_all().unwrap_or_else(|_| panic!("sync {label}"));
        }
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 1);
        let got = store.get(key).expect("get").expect("key must exist");
        assert_eq!(&got, &v4, "last overwrite (v4) must survive all syncs");
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Mixed synced/unsynced: only synced objects survive reopen
// ═══════════════════════════════════════════════════════════════════════════

/// Write A, sync, write B (no sync), reopen — A survives, B may be absent.
/// With `sync_on_write: false`, unsynced writes are not guaranteed durable.
#[test]
fn only_synced_objects_guaranteed_after_reopen() {
    let root = temp_root("synced-vs-unsynced");

    let key_synced = ObjectKey::from_name("synced");
    let key_unsynced = ObjectKey::from_name("unsynced");
    let payload_synced = b"i-was-synced";
    let payload_unsynced = b"i-was-not-synced";

    {
        let mut store = open_store(&root);
        store.put(key_synced, payload_synced).expect("put synced");
        store.sync_all().expect("sync synced");

        store
            .put(key_unsynced, payload_unsynced)
            .expect("put unsynced");
        // No sync for the second write.
    }

    {
        let store = reopen_store(&root);

        // Synced object must survive.
        let got_synced = store
            .get(key_synced)
            .expect("get synced")
            .expect("synced object must survive");
        assert_eq!(got_synced, payload_synced);

        // Unsynced object may or may not survive (implementation-defined).
        // The test verifies that if it does survive, the data is correct.
        match store.get(key_unsynced) {
            Ok(Some(data)) => {
                assert_eq!(
                    data, payload_unsynced,
                    "if unsynced object survived, payload must be intact"
                );
            }
            Ok(None) => {} // Expected: unsynced write lost.
            Err(_) => {}   // Corruption detected — acceptable.
        }
    }

    cleanup(&root);
}

/// Write A, sync, write B, sync, write C (no sync), reopen.
/// A and B must survive; C may be absent.
#[test]
fn mixed_sync_state_across_three_writes() {
    let root = temp_root("mixed-three");

    let key_a = ObjectKey::from_name("a-synced");
    let key_b = ObjectKey::from_name("b-synced");
    let key_c = ObjectKey::from_name("c-unsynced");

    {
        let mut store = open_store(&root);
        store.put(key_a, b"payload-a").expect("put a");
        store.sync_all().expect("sync a");

        store.put(key_b, b"payload-b").expect("put b");
        store.sync_all().expect("sync b");

        store.put(key_c, b"payload-c").expect("put c");
        // No sync for C.
    }

    {
        let store = reopen_store(&root);

        // A and B are guaranteed.
        assert_eq!(
            store.get(key_a).expect("get a"),
            Some(b"payload-a".to_vec()),
            "A must survive (synced)"
        );
        assert_eq!(
            store.get(key_b).expect("get b"),
            Some(b"payload-b".to_vec()),
            "B must survive (synced)"
        );

        // C is not guaranteed.
        match store.get(key_c) {
            Ok(Some(data)) => assert_eq!(data, b"payload-c"),
            Ok(None) => {} // Expected loss.
            Err(_) => {}   // Acceptable.
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Multiple sync_all calls within a single session
// ═══════════════════════════════════════════════════════════════════════════

/// Write a batch, sync, write more, sync, write more, sync — all survive.
#[test]
fn incremental_sync_cadence_all_survive() {
    let root = temp_root("sync-cadence");

    let batches: &[&[(&str, usize)]] = &[
        &[("b0-a", 64), ("b0-b", 128)],
        &[("b1-a", 256), ("b1-b", 512), ("b1-c", 1024)],
        &[("b2-a", 2048)],
    ];

    let mut expected: Vec<(ObjectKey, Vec<u8>)> = Vec::new();

    {
        let mut store = open_store(&root);
        for batch in batches {
            for &(name, size) in *batch {
                let payload = pseudo_random_data(size, size as u64 * 3);
                store
                    .put(ObjectKey::from_name(name), &payload)
                    .expect("put");
                expected.push((ObjectKey::from_name(name), payload));
            }
            store.sync_all().expect("sync batch");
        }
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, expected.len());
        for (key, payload) in &expected {
            let got = store
                .get(*key)
                .expect("get")
                .unwrap_or_else(|| panic!("key {key} missing after incremental syncs"));
            assert_eq!(&got, payload, "payload mismatch for {key}");
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Sync after delete
// ═══════════════════════════════════════════════════════════════════════════

/// Delete an object, sync, reopen — the deletion must persist.
#[test]
fn delete_then_sync_persists_across_reopen() {
    let root = temp_root("delete-sync");

    let key = ObjectKey::from_name("doomed");

    {
        let mut store = open_store(&root);
        store.put(key, b"temporary-data").expect("put");
        store.sync_all().expect("sync put");
        assert!(store.contains_key(key));

        store.delete(key).expect("delete");
        store.sync_all().expect("sync delete");
        assert!(!store.contains_key(key));
    }

    {
        let store = reopen_store(&root);
        assert!(
            !store.contains_key(key),
            "deleted key must stay absent after reopen"
        );
        assert_eq!(store.stats().live_objects, 0);
    }

    cleanup(&root);
}

/// Delete one of two objects, sync, reopen — the non-deleted one survives.
#[test]
fn partial_delete_sync_preserves_undeleted() {
    let root = temp_root("partial-delete-sync");

    let key_a = ObjectKey::from_name("survivor");
    let key_b = ObjectKey::from_name("victim");

    {
        let mut store = open_store(&root);
        store.put(key_a, b"keep-me").expect("put a");
        store.put(key_b, b"delete-me").expect("put b");
        store.sync_all().expect("sync both");

        store.delete(key_b).expect("delete b");
        store.sync_all().expect("sync delete");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 1);
        assert!(store.contains_key(key_a), "undeleted key must survive");
        assert!(!store.contains_key(key_b), "deleted key must stay absent");
        assert_eq!(store.get(key_a).expect("get"), Some(b"keep-me".to_vec()));
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Concurrent write+sync+reopen
// ═══════════════════════════════════════════════════════════════════════════

/// Multiple threads write distinct objects to a shared store, each thread
/// syncing after its write. After all finish, reopen and verify every
/// object is present and byte-correct.
#[test]
fn concurrent_writers_with_sync_all_survive_reopen() {
    let root = temp_root("concurrent-sync");

    const THREADS: usize = 8;
    const OPS_PER_THREAD: usize = 8;

    let store = Arc::new(Mutex::new(open_store(&root)));
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::new();

    for t in 0..THREADS {
        let s = Arc::clone(&store);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait(); // Start together.
            for i in 0..OPS_PER_THREAD {
                let name = format!("t{t}-op{i}");
                let payload = vec![t as u8, i as u8];
                let mut guard = s.lock().expect("lock");
                guard
                    .put(ObjectKey::from_name(&name), &payload)
                    .expect("put");
                guard.sync_all().expect("sync_all");
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    // Drop the Arc to close the store.
    drop(store);

    {
        let store = reopen_store(&root);
        assert_eq!(
            store.stats().live_objects,
            THREADS * OPS_PER_THREAD,
            "all concurrently written objects must survive sync+reopen"
        );

        for t in 0..THREADS {
            for i in 0..OPS_PER_THREAD {
                let name = format!("t{t}-op{i}");
                let expected = vec![t as u8, i as u8];
                let got = store
                    .get(ObjectKey::from_name(&name))
                    .expect("get")
                    .unwrap_or_else(|| panic!("concurrent object t{t}-op{i} missing"));
                assert_eq!(got, expected, "concurrent payload mismatch for {name}");
            }
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Large payload sync
// ═══════════════════════════════════════════════════════════════════════════

/// Multi-KiB objects survive fsync+reopen intact.
#[test]
fn large_payload_sync_survives_reopen() {
    let root = temp_root("large-sync");

    // max_segment_bytes is 16384, so payload must fit within that.
    let payload = pseudo_random_data(12000, 0xB16);
    let key = ObjectKey::from_name("big-one");

    {
        let mut store = open_store(&root);
        store.put(key, &payload).expect("put large");
        store.sync_all().expect("sync large");
    }

    {
        let store = reopen_store(&root);
        let got = store
            .get(key)
            .expect("get")
            .expect("large object must exist");
        assert_eq!(
            got, payload,
            "large payload must survive sync+reopen byte-for-byte"
        );
    }

    cleanup(&root);
}

/// Multiple large objects, each synced independently, all survive.
#[test]
fn multiple_large_objects_sync_survive_reopen() {
    let root = temp_root("multi-large-sync");

    let sizes = [4096, 8192, 2048, 10000, 512];
    let mut expected: Vec<(ObjectKey, Vec<u8>)> = Vec::new();

    {
        let mut store = open_store(&root);
        for (i, &size) in sizes.iter().enumerate() {
            let name = format!("large-{i}");
            let payload = pseudo_random_data(size, size as u64);
            store
                .put(ObjectKey::from_name(&name), &payload)
                .expect("put");
            store.sync_all().expect("sync");
            expected.push((ObjectKey::from_name(&name), payload));
        }
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, sizes.len());
        for (key, payload) in &expected {
            let got = store.get(*key).expect("get").expect("object must exist");
            assert_eq!(&got, payload, "large payload mismatch for {key}");
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. sync and sync_all API equivalence
// ═══════════════════════════════════════════════════════════════════════════

/// `sync()` is an alias for `sync_all()` — verify they produce the same
/// durability outcome.
#[test]
fn sync_alias_equivalent_to_sync_all() {
    let root_a = temp_root("sync-alias-a");
    let root_b = temp_root("sync-alias-b");

    let key = ObjectKey::from_name("compare");
    let payload = b"testing-sync-method-equivalence";

    // Using sync_all()
    {
        let mut store_a = open_store(&root_a);
        store_a.put(key, payload).expect("put");
        store_a.sync_all().expect("sync_all");
    }

    // Using sync()
    {
        let mut store_b = open_store(&root_b);
        store_b.put(key, payload).expect("put");
        store_b.sync().expect("sync");
    }

    // Both stores should have identical state after reopen.
    {
        let store_a = reopen_store(&root_a);
        let store_b = reopen_store(&root_b);

        assert_eq!(store_a.stats().live_objects, 1);
        assert_eq!(store_b.stats().live_objects, 1);

        let got_a = store_a.get(key).expect("get a").expect("a must exist");
        let got_b = store_b.get(key).expect("get b").expect("b must exist");
        assert_eq!(got_a, payload);
        assert_eq!(got_b, payload);
        assert_eq!(
            got_a, got_b,
            "sync() and sync_all() must produce identical results"
        );
    }

    cleanup(&root_a);
    cleanup(&root_b);
}

/// Verify that multiple interleaved sync() and sync_all() calls work
/// without errors.
#[test]
fn interleaved_sync_and_sync_all() {
    let root = temp_root("interleaved-sync");

    {
        let mut store = open_store(&root);
        store
            .put(ObjectKey::from_name("x"), b"data-x")
            .expect("put x");
        store.sync().expect("sync");

        store
            .put(ObjectKey::from_name("y"), b"data-y")
            .expect("put y");
        store.sync_all().expect("sync_all");

        store
            .put(ObjectKey::from_name("z"), b"data-z")
            .expect("put z");
        store.sync().expect("sync");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 3);
        for (name, expected) in &[("x", b"data-x"), ("y", b"data-y"), ("z", b"data-z")] {
            let got = store
                .get(ObjectKey::from_name(name))
                .expect("get")
                .unwrap_or_else(|| panic!("{name} missing after interleaved syncs"));
            assert_eq!(&got[..], *expected);
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Durability after segment rotation with sync
// ═══════════════════════════════════════════════════════════════════════════

/// Write enough data to force segment rotation, sync between batches,
/// and verify all data survives.
#[test]
fn segment_rotation_with_sync_preserves_all_data() {
    let root = temp_root("segment-rot-sync");

    // Force rotation with a tiny segment size.
    let small_opts = StoreOptions {
        max_segment_bytes: 1024,
        ..fast_opts()
    };

    {
        let mut store = LocalObjectStore::open_with_options(&root, small_opts).expect("open small");

        for i in 0..8 {
            // ~200-byte payloads — segment fills after ~5 writes.
            let payload = pseudo_random_data(200, i as u64);
            store
                .put(ObjectKey::from_name(format!("seg-{i}")), &payload)
                .expect("put");
            store.sync_all().expect("sync after segment write");
        }
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 8);

        for i in 0..8 {
            let key = ObjectKey::from_name(format!("seg-{i}"));
            let expected = pseudo_random_data(200, i as u64);
            let got = store
                .get(key)
                .expect("get")
                .unwrap_or_else(|| panic!("seg-{i} missing after rotation+sync"));
            assert_eq!(
                got, expected,
                "payload mismatch for seg-{i} across segment rotation"
            );
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. Stress: many small objects with sync after each
// ═══════════════════════════════════════════════════════════════════════════

/// Write many small objects, each followed by sync_all, then verify
/// all survive reopen.
#[test]
fn many_small_objects_with_per_write_sync() {
    let root = temp_root("many-small-sync");

    const COUNT: usize = 50;
    let mut keys: Vec<(ObjectKey, Vec<u8>)> = Vec::with_capacity(COUNT);

    {
        let mut store = open_store(&root);
        for i in 0..COUNT {
            let payload = vec![i as u8; 16];
            let key = ObjectKey::from_name(format!("item-{i:04}"));
            store.put(key, &payload).expect("put");
            store.sync_all().expect("sync");
            keys.push((key, payload));
        }
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, COUNT);

        for (key, expected) in &keys {
            let got = store
                .get(*key)
                .expect("get")
                .unwrap_or_else(|| panic!("{key} missing after per-write sync"));
            assert_eq!(&got, expected, "{key} payload mismatch");
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. Empty store sync does not break subsequent writes
// ═══════════════════════════════════════════════════════════════════════════

/// Syncing an empty store (no writes) must succeed and not prevent
/// subsequent writes from being durable.
#[test]
fn sync_empty_store_then_write_survives() {
    let root = temp_root("sync-empty-then-write");

    {
        let mut store = open_store(&root);
        store.sync_all().expect("sync empty store");
        store
            .put(ObjectKey::from_name("after"), b"post-sync-data")
            .expect("put");
        store.sync_all().expect("sync after write");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 1);
        assert_eq!(
            store.get(ObjectKey::from_name("after")).expect("get"),
            Some(b"post-sync-data".to_vec())
        );
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 13. fdatasync vs fsync distinction (current behavior)
// ═══════════════════════════════════════════════════════════════════════════

/// The `LocalObjectStore` currently exposes a single durability primitive
/// (`sync_all` / `sync`) that flushes both data and metadata. There is no
/// separate `fdatasync` or `sync_data` method. This test documents the
/// current behavior: `sync_all` is equivalent to fsync, not fdatasync.
///
/// When a separate `fdatasync` method is added (per the fuse-fsync-durability
/// milestone), this test should be extended to verify the distinction:
/// fdatasync commits data but may skip metadata timestamp updates.
#[test]
fn sync_all_is_fsync_not_fdatasync() {
    let root = temp_root("fsync-not-fdatasync");

    let key = ObjectKey::from_name("data");
    let payload = b"fsync-data";

    {
        let mut store = open_store(&root);
        store.put(key, payload).expect("put");
        store.sync_all().expect("sync_all");
    }

    {
        let store = reopen_store(&root);
        // Data survived — this is fsync-level durability.
        let got = store.get(key).expect("get").expect("object must exist");
        assert_eq!(got, payload);

        // Verify that metadata attributes (size, etc.) are also durable.
        let attr = store.get_attr(&key).expect("get_attr");
        assert_eq!(attr.size, payload.len() as u64);
    }

    cleanup(&root);
}
