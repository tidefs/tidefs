// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for tidefs-local-object-store.
//!
//! Each test creates a fresh temp directory, constructs a store instance
//! through the public API, runs the scenario, and cleans up.
//!
//! Test groups:
//! 1. CRUD correctness — put, get, delete, list, contains
//! 2. Flush and durability — write, sync, close, reopen, verify
//! 3. Error paths — nonexistent keys, read-only guard, payload too large
//! 4. Concurrent access — multi-threaded puts/gets/deletes via Arc<Mutex<>>
//! 5. Edge cases — zero-length objects, many small objects, named vs key ops

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreError, StoreOptions};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-los-integration-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn fast_options() -> StoreOptions {
    StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 4096,
        sync_on_write: false,
        repair_torn_tail: true,
        segment_rotation_interval_secs: u64::MAX,
        segment_rotation_write_limit: 0,
        background_scrub_interval_secs: 0,
        mirror_path: None,
        replica_paths: Vec::new(),
        fault_injection_config: None,
        reclaim_enabled: false,
        segment_count: 256,
        durability_layout: None,
        write_throttle_enabled: false,
    }
}

fn verified_fast_options() -> StoreOptions {
    StoreOptions {
        verify_read_checksums: true,
        ..fast_options()
    }
}

fn cleanup(root: &std::path::Path) {
    let _ = fs::remove_dir_all(root);
}

fn put_bytes(store: &mut LocalObjectStore, key: &str, payload: &[u8]) {
    store
        .put(ObjectKey::from_name(key), payload)
        .expect("put should succeed");
}

fn get_bytes(store: &LocalObjectStore, key: &str) -> Option<Vec<u8>> {
    store
        .get(ObjectKey::from_name(key))
        .expect("get should not error")
}

// ── 1. CRUD correctness ───────────────────────────────────────────────────

#[test]
fn put_then_get_round_trips() {
    let root = temp_root("put-get");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    put_bytes(&mut store, "alpha", b"hello world");
    assert_eq!(get_bytes(&store, "alpha"), Some(b"hello world".to_vec()));

    cleanup(&root);
}

#[test]
fn put_multiple_keys_are_independent() {
    let root = temp_root("multiple-keys");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    put_bytes(&mut store, "a", b"value-a");
    put_bytes(&mut store, "b", b"value-b");
    put_bytes(&mut store, "c", b"value-c");

    assert_eq!(get_bytes(&store, "a"), Some(b"value-a".to_vec()));
    assert_eq!(get_bytes(&store, "b"), Some(b"value-b".to_vec()));
    assert_eq!(get_bytes(&store, "c"), Some(b"value-c".to_vec()));

    cleanup(&root);
}

#[test]
fn put_overwrites_existing_key() {
    let root = temp_root("overwrite");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    put_bytes(&mut store, "x", b"original");
    put_bytes(&mut store, "x", b"updated");
    assert_eq!(get_bytes(&store, "x"), Some(b"updated".to_vec()));

    cleanup(&root);
}

#[test]
fn delete_existing_key_removes_it() {
    let root = temp_root("delete-existing");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    put_bytes(&mut store, "keeper", b"stay");
    put_bytes(&mut store, "victim", b"go-away");
    let deleted = store
        .delete(ObjectKey::from_name("victim"))
        .expect("delete should succeed");
    assert!(deleted, "delete should return true for existing key");

    assert_eq!(get_bytes(&store, "keeper"), Some(b"stay".to_vec()));
    assert_eq!(get_bytes(&store, "victim"), None);

    cleanup(&root);
}

#[test]
fn delete_nonexistent_key_returns_false() {
    let root = temp_root("delete-nonexistent");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    let deleted = store
        .delete(ObjectKey::from_name("ghost"))
        .expect("delete should not error");
    assert!(!deleted, "delete should return false for missing key");

    cleanup(&root);
}

#[test]
fn list_keys_reflects_puts_and_deletes() {
    let root = temp_root("list-keys");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    put_bytes(&mut store, "k1", b"one");
    put_bytes(&mut store, "k2", b"two");
    put_bytes(&mut store, "k3", b"three");

    let keys: HashSet<ObjectKey> = store.list_keys().into_iter().collect();
    assert_eq!(keys.len(), 3);
    assert!(keys.contains(&ObjectKey::from_name("k1")));
    assert!(keys.contains(&ObjectKey::from_name("k2")));
    assert!(keys.contains(&ObjectKey::from_name("k3")));

    store.delete(ObjectKey::from_name("k2")).expect("delete k2");
    let keys_after: HashSet<ObjectKey> = store.list_keys().into_iter().collect();
    assert_eq!(keys_after.len(), 2);
    assert!(!keys_after.contains(&ObjectKey::from_name("k2")));

    cleanup(&root);
}

#[test]
fn contains_key_is_accurate() {
    let root = temp_root("contains");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    assert!(!store.contains_key(ObjectKey::from_name("absent")));
    put_bytes(&mut store, "present", b"here");
    assert!(store.contains_key(ObjectKey::from_name("present")));
    assert!(!store.contains_key(ObjectKey::from_name("absent")));

    cleanup(&root);
}

#[test]
fn stats_tracks_live_objects_and_bytes() {
    let root = temp_root("stats");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    put_bytes(&mut store, "obj1", b"abcd");
    put_bytes(&mut store, "obj2", b"12345678");

    let stats = store.stats();
    assert_eq!(stats.live_objects, 2);
    // live_bytes is at least the payload sum, though overhead adds more
    assert!(stats.live_bytes >= 12);

    store
        .delete(ObjectKey::from_name("obj1"))
        .expect("delete obj1");
    let stats2 = store.stats();
    assert_eq!(stats2.live_objects, 1);

    cleanup(&root);
}

#[test]
fn put_content_addressed_yields_key_from_payload_hash() {
    let root = temp_root("content-addressed");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    let payload = b"content-addressed-object";
    let key = store
        .put_content_addressed(payload)
        .expect("put_content_addressed succeeds");
    // Same payload should produce same key
    let key2 = store.put_content_addressed(payload).expect("second put");
    assert_eq!(key, key2, "same content should give same key");
    // Get by that key retrieves payload
    assert_eq!(store.get(key).unwrap(), Some(payload.to_vec()));

    cleanup(&root);
}

// ── 2. Flush and durability ───────────────────────────────────────────────

#[test]
fn objects_survive_close_reopen() {
    let root = temp_root("reopen");
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        put_bytes(&mut store, "survivor", b"persistent data");
        store.sync_all().expect("sync_all after writes");
    }
    {
        let store = LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        assert_eq!(
            get_bytes(&store, "survivor"),
            Some(b"persistent data".to_vec())
        );
    }
    cleanup(&root);
}

#[test]
fn multiple_objects_survive_reopen() {
    let root = temp_root("multi-reopen");
    let keys: Vec<String> = (0..20).map(|i| format!("key-{i:02x}")).collect();
    let values: Vec<Vec<u8>> = keys.iter().map(|k| k.as_bytes().to_vec()).collect();

    {
        let mut store =
            LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        for (k, v) in keys.iter().zip(values.iter()) {
            put_bytes(&mut store, k, v);
        }
        store.sync_all().expect("sync_all");
    }
    {
        let store = LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        let stats = store.stats();
        assert_eq!(stats.live_objects, 20);
        for (k, v) in keys.iter().zip(values.iter()) {
            assert_eq!(
                get_bytes(&store, k),
                Some(v.clone()),
                "mismatch for key {k}"
            );
        }
    }
    cleanup(&root);
}

#[test]
fn deletes_survive_reopen() {
    let root = temp_root("delete-reopen");
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        put_bytes(&mut store, "keep", b"still-here");
        put_bytes(&mut store, "tombstone", b"remove");
        store.sync_all().expect("sync_all after puts");
        store
            .delete(ObjectKey::from_name("tombstone"))
            .expect("delete tombstone");
        store.sync_all().expect("sync_all after delete");
    }
    {
        let store = LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        assert_eq!(get_bytes(&store, "keep"), Some(b"still-here".to_vec()));
        assert_eq!(get_bytes(&store, "tombstone"), None);
        let rep = store.replay_report();
        assert!(rep.deletes_seen >= 1, "replay should see delete tombstone");
    }
    cleanup(&root);
}

#[test]
fn overwrite_survives_reopen() {
    let root = temp_root("overwrite-reopen");
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        put_bytes(&mut store, "doc", b"v1");
        put_bytes(&mut store, "doc", b"v2");
        put_bytes(&mut store, "doc", b"v3-final");
        store.sync_all().expect("sync_all after overwrites");
    }
    {
        let store = LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        assert_eq!(get_bytes(&store, "doc"), Some(b"v3-final".to_vec()));
        let rep = store.replay_report();
        assert_eq!(rep.puts_seen, 3, "all three puts should replay");
    }
    cleanup(&root);
}

#[test]
fn binary_payload_survives_reopen() {
    let root = temp_root("binary-reopen");
    let binary = (0u8..=255u8).collect::<Vec<u8>>();
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        put_bytes(&mut store, "bin", &binary);
        store.sync_all().expect("sync_all");
    }
    {
        let store = LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        assert_eq!(get_bytes(&store, "bin"), Some(binary));
    }
    cleanup(&root);
}

#[test]
fn replay_report_is_accurate_after_reopen() {
    let root = temp_root("replay-report");
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        put_bytes(&mut store, "a", b"aa");
        put_bytes(&mut store, "b", b"bb");
        store.sync_all().expect("sync_all");
    }
    {
        let store = LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        let rep = store.replay_report();
        assert_eq!(rep.puts_seen, 2);
        assert!(rep.segment_count >= 1);
        assert_eq!(rep.highest_sequence, 2);
    }
    cleanup(&root);
}

// ── 3. Error paths ────────────────────────────────────────────────────────

#[test]
fn get_nonexistent_key_returns_none_not_error() {
    let root = temp_root("get-missing");
    let store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();
    let result = store.get(ObjectKey::from_name("absent"));
    assert!(result.is_ok(), "get should not error on missing key");
    assert_eq!(result.unwrap(), None);
    cleanup(&root);
}

#[test]
fn get_attr_on_missing_key_errors_with_not_found() {
    let root = temp_root("get-attr-missing");
    let store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();
    let key = ObjectKey::from_name("no-such-key");
    let result = store.get_attr(&key);
    assert!(result.is_err(), "get_attr on missing key should error");
    cleanup(&root);
}

#[test]
fn read_only_store_rejects_put() {
    let root = temp_root("read-only-put");
    // Set up store with data first
    {
        let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();
        put_bytes(&mut store, "existing", b"data");
        store.sync_all().expect("sync_all");
    }
    // Open read-only and try to write
    {
        let mut ro = LocalObjectStore::open_read_only_with_options(&root, fast_options())
            .unwrap()
            .expect("should find existing store");
        let err = ro.put(ObjectKey::from_name("new"), b"nope").unwrap_err();
        assert!(
            matches!(err, StoreError::ReadOnly { operation: "put" }),
            "expected ReadOnly error, got {err:?}"
        );
        // Existing data still readable
        assert_eq!(get_bytes(&ro, "existing"), Some(b"data".to_vec()));
    }
    cleanup(&root);
}

#[test]
fn read_only_store_rejects_delete() {
    let root = temp_root("read-only-delete");
    {
        let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();
        put_bytes(&mut store, "existing", b"keep");
        store.sync_all().expect("sync_all");
    }
    {
        let mut ro = LocalObjectStore::open_read_only_with_options(&root, fast_options())
            .unwrap()
            .expect("existing store");
        let err = ro.delete(ObjectKey::from_name("existing")).unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::ReadOnly {
                    operation: "delete"
                }
            ),
            "expected ReadOnly error, got {err:?}"
        );
    }
    cleanup(&root);
}

#[test]
fn payload_too_large_is_rejected() {
    let root = temp_root("payload-too-large");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 512,
        ..fast_options()
    };
    let max_obj = opts.max_object_bytes();
    let mut store = LocalObjectStore::open_with_options(&root, opts).unwrap();
    // Create a payload that is too big
    let big = vec![0xaa_u8; (max_obj + 1) as usize];
    let result = store.put(ObjectKey::from_name("big"), &big);
    assert!(result.is_err(), "oversized put should fail");
    let err = result.unwrap_err();
    assert!(
        matches!(err, StoreError::PayloadTooLarge { .. }),
        "expected PayloadTooLarge, got {err:?}"
    );
    cleanup(&root);
}

#[test]
fn delete_then_get_returns_none_without_error() {
    let root = temp_root("delete-then-get");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    put_bytes(&mut store, "temp", b"transient");
    store
        .delete(ObjectKey::from_name("temp"))
        .expect("first delete");
    // Second delete is idempotent — returns false
    let deleted = store
        .delete(ObjectKey::from_name("temp"))
        .expect("second delete");
    assert!(!deleted);
    assert_eq!(get_bytes(&store, "temp"), None);

    cleanup(&root);
}

#[test]
fn invalid_store_options_are_rejected() {
    let root = temp_root("invalid-options");
    let bad_opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 64, // below MIN_SEGMENT_BYTES (256)
        ..fast_options()
    };
    let result = LocalObjectStore::open_with_options(&root, bad_opts);
    assert!(result.is_err(), "store with too-small segment should fail");
    assert!(
        matches!(result.unwrap_err(), StoreError::InvalidOptions { .. }),
        "expected InvalidOptions"
    );
    cleanup(&root);
}

// ── 4. Concurrent access ──────────────────────────────────────────────────

#[test]
fn concurrent_puts_from_multiple_threads_no_corruption() {
    let root = temp_root("concurrent-puts");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 1024 * 1024, // plenty of room
        ..fast_options()
    };

    let store = LocalObjectStore::open_with_options(&root, opts).unwrap();
    let store = Arc::new(std::sync::Mutex::new(store));

    let n_threads = 4;
    let n_puts_per_thread = 25;

    let mut handles = Vec::new();
    for t in 0..n_threads {
        let store_clone = Arc::clone(&store);
        let handle = thread::spawn(move || {
            for i in 0..n_puts_per_thread {
                let name = format!("thread-{t}-obj-{i:03x}");
                let val = format!("v:{t}:{i:03x}").into_bytes();
                store_clone
                    .lock()
                    .unwrap()
                    .put(ObjectKey::from_name(&name), &val)
                    .unwrap();
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }

    // After all threads finish, verify every object
    let store_guard = store.lock().unwrap();
    for t in 0..n_threads {
        for i in 0..n_puts_per_thread {
            let name = format!("thread-{t}-obj-{i:03x}");
            let expected = format!("v:{t}:{i:03x}").into_bytes();
            assert_eq!(
                get_bytes(&store_guard, &name),
                Some(expected),
                "mismatch for {name}"
            );
        }
    }

    let stats = store_guard.stats();
    assert_eq!(stats.live_objects, (n_threads * n_puts_per_thread) as usize);

    cleanup(&root);
}

#[test]
fn concurrent_puts_deletes_no_corruption() {
    let root = temp_root("concurrent-mixed");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 1024 * 1024,
        ..fast_options()
    };

    let store = LocalObjectStore::open_with_options(&root, opts).unwrap();
    let store = Arc::new(std::sync::Mutex::new(store));

    // Pre-populate 50 objects
    {
        let mut guard = store.lock().unwrap();
        for i in 0..50 {
            let name = format!("pre-{i:03x}");
            guard.put(ObjectKey::from_name(&name), b"pre").unwrap();
        }
    }

    let store_writer = Arc::clone(&store);
    let writer = thread::spawn(move || {
        for i in 0..30 {
            let name = format!("writer-{i:03x}");
            store_writer
                .lock()
                .unwrap()
                .put(ObjectKey::from_name(&name), b"written")
                .unwrap();
        }
    });

    let store_deleter = Arc::clone(&store);
    let deleter = thread::spawn(move || {
        for i in 0..25 {
            store_deleter
                .lock()
                .unwrap()
                .delete(ObjectKey::from_name(format!("pre-{i:03x}")))
                .ok();
        }
    });

    writer.join().expect("writer thread ok");
    deleter.join().expect("deleter thread ok");

    let store_guard = store.lock().unwrap();
    // Verify writer objects exist
    for i in 0..30 {
        let name = format!("writer-{i:03x}");
        assert_eq!(get_bytes(&store_guard, &name), Some(b"written".to_vec()));
    }
    // Pre-populated objects 25-49 should still exist
    for i in 25..50 {
        let name = format!("pre-{i:03x}");
        assert_eq!(get_bytes(&store_guard, &name), Some(b"pre".to_vec()));
    }

    cleanup(&root);
}

// ── 5. Edge cases ─────────────────────────────────────────────────────────

#[test]
fn zero_length_object_round_trips() {
    let root = temp_root("zero-length");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    put_bytes(&mut store, "empty", b"");
    assert_eq!(get_bytes(&store, "empty"), Some(vec![]));

    // Should survive reopen
    store.sync_all().expect("sync_all");
    drop(store);
    {
        let store = LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        assert_eq!(get_bytes(&store, "empty"), Some(vec![]));
    }
    cleanup(&root);
}

#[test]
fn many_small_objects_rapid_succession() {
    let root = temp_root("many-small");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    let count = 500;
    for i in 0..count {
        put_bytes(&mut store, &format!("obj{i:05x}"), &[i as u8; 4]);
    }

    let stats = store.stats();
    assert_eq!(stats.live_objects, count as usize);

    // Spot-check a few
    assert_eq!(get_bytes(&store, "obj00000"), Some(vec![0u8; 4]));
    assert_eq!(get_bytes(&store, "obj001f3"), Some(vec![0xf3u8; 4]));

    // Survive reopen
    store.sync_all().expect("sync_all");
    drop(store);
    {
        let store = LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        assert_eq!(store.stats().live_objects, count as usize);
        assert_eq!(get_bytes(&store, "obj001f3"), Some(vec![0xf3u8; 4]));
    }
    cleanup(&root);
}

#[test]
fn large_payload_just_under_limit_succeeds() {
    let root = temp_root("large-near-limit");
    let opts = StoreOptions {
        verify_read_checksums: true,
        max_segment_bytes: 2048,
        ..fast_options()
    };
    let max_obj = opts.max_object_bytes();
    let mut store = LocalObjectStore::open_with_options(&root, opts).unwrap();
    let payload = vec![0x7e_u8; max_obj as usize];

    put_bytes(&mut store, "big", &payload);
    assert_eq!(get_bytes(&store, "big"), Some(payload.clone()));

    // Survive reopen
    store.sync_all().expect("sync_all");
    drop(store);
    {
        let store = LocalObjectStore::open_with_options(
            &root,
            StoreOptions {
                verify_read_checksums: true,
                max_segment_bytes: 2048,
                ..fast_options()
            },
        )
        .unwrap();
        assert_eq!(get_bytes(&store, "big"), Some(payload));
    }
    cleanup(&root);
}

#[test]
fn get_range_returns_subset_of_payload() {
    let root = temp_root("get-range");
    let mut store = LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
    let payload = b"abcdefghijklmnopqrstuvwxyz";
    put_bytes(&mut store, "alpha", payload);

    let range = store
        .get_range(ObjectKey::from_name("alpha"), 5, 6)
        .expect("get_range succeeds");
    assert_eq!(range, Some(b"fghijk".to_vec()));

    // range beyond EOF
    let beyond = store
        .get_range(ObjectKey::from_name("alpha"), 20, 20)
        .expect("get_range succeeds");
    assert_eq!(beyond, Some(b"uvwxyz".to_vec()));

    // range on nonexistent key
    let none = store
        .get_range(ObjectKey::from_name("nope"), 0, 10)
        .expect("get_range succeeds");
    assert_eq!(none, None);

    cleanup(&root);
}

#[test]
fn get_verified_checks_content_integrity() {
    let root = temp_root("get-verified");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    let payload = b"integrity-checked data";
    let key = store
        .put_content_addressed(payload)
        .expect("put_content_addressed succeeds");
    let verified = store.get_verified(key).expect("get_verified succeeds");
    assert_eq!(verified, Some(payload.to_vec()));

    // get_verified on missing key returns None
    let missing = store
        .get_verified(ObjectKey::from_content(b"no-such-content"))
        .expect("get_verified succeeds for missing key");
    assert_eq!(missing, None);

    cleanup(&root);
}

#[test]

fn location_of_and_get_at_location() {
    let root = temp_root("location");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    let key = ObjectKey::from_name("locate");
    let payload = b"located-object-data";
    store.put(key, payload).expect("put succeeds");

    let loc = store.location_of(key).expect("location should exist");
    assert_eq!(loc.key, key);
    assert_eq!(loc.payload_len, payload.len() as u64);

    let read_back = store
        .get_at_location(loc)
        .expect("get_at_location succeeds");
    assert_eq!(&read_back, payload);

    // Location for missing key
    let missing = store.location_of(ObjectKey::from_name("absent"));
    assert!(missing.is_none());

    cleanup(&root);
}

#[test]
fn version_locations_accumulates_history() {
    let root = temp_root("versions");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    let key = ObjectKey::from_name("versioned");
    store.put(key, b"v1").expect("put v1");
    store.put(key, b"v2").expect("put v2");
    store.put(key, b"v3").expect("put v3");

    let versions = store.version_locations_of(key);
    assert_eq!(versions.len(), 3, "should have 3 version locations");
    // Each version should be readable
    for (i, loc) in versions.iter().enumerate() {
        let data = store.get_at_location(*loc).expect("get version location");
        assert_eq!(data, format!("v{}", i + 1).into_bytes());
    }

    cleanup(&root);
}

#[test]
fn named_put_and_get_shortcuts() {
    let root = temp_root("named-ops");
    let mut store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();

    let stored = store
        .put_named("named-key", b"named-value")
        .expect("put_named succeeds");
    assert_eq!(stored.key, ObjectKey::from_name("named-key"));
    assert_eq!(stored.len, 11);

    let val = store.get_named("named-key").expect("get_named succeeds");
    assert_eq!(val, Some(b"named-value".to_vec()));

    let deleted = store
        .delete_named("named-key")
        .expect("delete_named succeeds");
    assert!(deleted);

    let after = store.get_named("named-key").expect("get after delete");
    assert_eq!(after, None);

    cleanup(&root);
}

#[test]
fn empty_store_opens_and_reopens() {
    let root = temp_root("empty-store");
    {
        let store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();
        assert_eq!(store.stats().live_objects, 0);
        assert!(store.list_keys().is_empty());
    }
    // Reopen empty
    {
        let store = LocalObjectStore::open_with_options(&root, fast_options()).unwrap();
        assert_eq!(store.stats().live_objects, 0);
    }
    cleanup(&root);
}

#[test]
fn sync_on_write_durable_option_flushes_every_write() {
    let root = temp_root("sync-on-write");
    {
        let mut store = LocalObjectStore::open_with_options(
            &root,
            StoreOptions {
                verify_read_checksums: true,
                sync_on_write: true,
                ..fast_options()
            },
        )
        .unwrap();
        put_bytes(&mut store, "durable", b"immediately-synced");
        // No explicit sync_all — sync_on_write should handle it
    }
    {
        let store = LocalObjectStore::open_with_options(&root, verified_fast_options()).unwrap();
        assert_eq!(
            get_bytes(&store, "durable"),
            Some(b"immediately-synced".to_vec())
        );
    }
    cleanup(&root);
}
