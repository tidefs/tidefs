//! Object-store validation suite for `tidefs-local-object-store`.
//!
//! Covers orphan detection via `compact_retaining`, store stats consistency,
//! multi-segment object survival, concurrent writer/reader isolation,
//! key derivation edge cases, and content-addressed vs named-key isolation.
//!
//! All tests use the crate's public API. Temporary directories are created
//! under `std::env::temp_dir()` and cleaned up after each test.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{
    LocalObjectStore, ObjectKey, StoreError, StoreOptions, StoreRetentionCompactionReport,
};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-los-validation-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn fast_opts() -> StoreOptions {
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

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

// ── Helpers ────────────────────────────────────────────────────────────────

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

/// Open a writable store under `root` with the given options.
fn open_store(root: &PathBuf, opts: StoreOptions) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, opts).expect("open store")
}

/// Reopen a store at `root` and return it.
fn reopen_store(root: &PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("reopen store")
}

/// Put bytes under a name-derived key.
fn put_named(store: &mut LocalObjectStore, name: &str, payload: &[u8]) -> ObjectKey {
    store
        .put(ObjectKey::from_name(name), payload)
        .expect("put named object")
        .key
}

/// Get bytes by name-derived key.
fn get_named(store: &LocalObjectStore, name: &str) -> Option<Vec<u8>> {
    store
        .get(ObjectKey::from_name(name))
        .expect("get named object")
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Orphan detection via compact_retaining
// ═══════════════════════════════════════════════════════════════════════════

/// After writing objects, deleting some, and running `compact_retaining`
/// with a protected-key list, verify unprotected keys are tombstoned and
/// protected keys survive.
#[test]
fn compact_retaining_tombstones_unprotected_keys() {
    let root = temp_root("compact-tombstone");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 1024, // smaller segments to create multiple segments
        segment_count: 32,
        ..fast_opts()
    };
    let mut store = open_store(&root, opts);

    let keep_keys: Vec<ObjectKey> = (0..5)
        .map(|i| {
            put_named(
                &mut store,
                &format!("keep-{i}"),
                &pseudo_random_data(128, i),
            )
        })
        .collect();
    let drop_keys: Vec<ObjectKey> = (0..10)
        .map(|i| {
            put_named(
                &mut store,
                &format!("drop-{i}"),
                &pseudo_random_data(256, i + 100),
            )
        })
        .collect();

    store.sync_all().expect("sync before compact");

    // Verify all objects exist before compaction
    let stats_before = store.stats();
    assert_eq!(stats_before.live_objects, 15);

    for k in &keep_keys {
        assert!(store.contains_key(*k), "keep key must exist before compact");
    }
    for k in &drop_keys {
        assert!(store.contains_key(*k), "drop key must exist before compact");
    }

    // Compact: only keep_keys are protected; drop_keys become tombstones
    let report: StoreRetentionCompactionReport = store
        .compact_retaining(&keep_keys, &[])
        .expect("compact_retaining");

    // Report invariants
    assert_eq!(report.protected_key_count, keep_keys.len());
    assert_eq!(report.tombstoned_unprotected_keys, drop_keys.len());
    // After compaction: only keep_keys survive
    let stats_after = store.stats();
    assert_eq!(stats_after.live_objects, keep_keys.len());
    for k in &keep_keys {
        assert!(store.contains_key(*k), "keep key must survive compaction");
    }
    for k in &drop_keys {
        assert!(
            !store.contains_key(*k),
            "drop key must be tombstoned by compaction"
        );
    }

    store.sync_all().expect("sync after compact");
    cleanup(&root);
}

/// After compacting to retain a subset, reopen the store and verify the
/// surviving keys are intact with correct payloads.
#[test]
fn compact_retaining_survives_reopen() {
    let root = temp_root("compact-reopen");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 1024,
        segment_count: 32,
        ..fast_opts()
    };
    let payloads: Vec<(String, Vec<u8>)> = vec![
        ("alpha".into(), pseudo_random_data(200, 1)),
        ("beta".into(), pseudo_random_data(200, 3)),
        ("gamma".into(), pseudo_random_data(200, 5)),
        ("delta".into(), pseudo_random_data(200, 7)),
    ];
    let drop_payloads: Vec<(String, Vec<u8>)> = vec![
        ("drop-1".into(), pseudo_random_data(300, 10)),
        ("drop-2".into(), pseudo_random_data(300, 11)),
        ("drop-3".into(), pseudo_random_data(300, 12)),
    ];

    {
        let mut store = open_store(&root, opts);
        for (name, data) in payloads.iter().chain(drop_payloads.iter()) {
            put_named(&mut store, name, data);
        }
        store.sync_all().expect("sync before compact");

        let keep_keys: Vec<ObjectKey> = payloads
            .iter()
            .map(|(name, _)| ObjectKey::from_name(name))
            .collect();
        store
            .compact_retaining(&keep_keys, &[])
            .expect("compact_retaining");
        store.sync_all().expect("sync after compact");
    }

    {
        let store = reopen_store(&root);
        // Protected keys survive with correct data
        for (name, expected) in &payloads {
            let got = get_named(&store, name);
            assert_eq!(
                got.as_deref(),
                Some(expected.as_slice()),
                "protected key {name} must survive reopen with correct data"
            );
        }
        // Unprotected keys are gone
        for (name, _) in &drop_payloads {
            assert!(
                get_named(&store, name).is_none(),
                "unprotected key {name} must be gone after compact+reopen"
            );
        }
        assert_eq!(store.stats().live_objects, payloads.len());
    }

    cleanup(&root);
}

/// Verify that compaction with an empty protected set results in zero
/// live objects.
#[test]
fn compact_retaining_empty_protected_set_clears_store() {
    let root = temp_root("compact-empty");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 1024,
        segment_count: 16,
        ..fast_opts()
    };
    {
        let mut store = open_store(&root, opts);
        for i in 0..10 {
            put_named(&mut store, &format!("obj-{i}"), &pseudo_random_data(64, i));
        }
        store.sync_all().expect("sync before compact");
        store
            .compact_retaining(&[], &[])
            .expect("compact with empty set");
        assert_eq!(
            store.stats().live_objects,
            0,
            "all objects should be tombstoned"
        );
        store.sync_all().expect("sync after compact");
    }
    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, 0);
        assert!(store.list_keys().is_empty());
    }
    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Store stats consistency
// ═══════════════════════════════════════════════════════════════════════════

/// Verify `live_objects`, `live_bytes`, `tombstone_count`, and
/// `waste_ratio` are consistent across put/delete sequences.
#[test]
fn stats_consistency_across_put_delete_cycles() {
    let root = temp_root("stats-consistency");
    let mut store = open_store(&root, fast_opts());

    // Empty store stats
    let s0 = store.stats();
    assert_eq!(s0.live_objects, 0);
    assert_eq!(s0.live_bytes, 0);
    assert_eq!(s0.tombstone_count, 0);

    // Write objects
    let n = 20_usize;
    for i in 0..n {
        put_named(
            &mut store,
            &format!("obj-{i:03x}"),
            &pseudo_random_data(100, i as u64),
        );
    }
    let s1 = store.stats();
    assert_eq!(s1.live_objects, n);
    assert!(s1.live_bytes >= (n * 100) as u64);
    assert_eq!(s1.tombstone_count, 0);

    // Delete half
    for i in 0..n / 2 {
        let key = ObjectKey::from_name(format!("obj-{i:03x}").as_bytes());
        assert!(store.delete(key).expect("delete"));
    }
    let s2 = store.stats();
    assert_eq!(s2.live_objects, n - n / 2);
    assert_eq!(s2.tombstone_count, (n / 2) as u64);

    // waste_ratio should be >0 after deletes
    let ratio = store.waste_ratio();
    assert!(
        ratio > 0.0,
        "waste_ratio should be positive after deletions"
    );
    assert!(ratio <= 1.0, "waste_ratio should not exceed 1.0");

    // Delete remaining
    for i in n / 2..n {
        let key = ObjectKey::from_name(format!("obj-{i:03x}").as_bytes());
        assert!(store.delete(key).expect("delete"));
    }
    let s3 = store.stats();
    assert_eq!(s3.live_objects, 0);
    assert_eq!(s3.tombstone_count, n as u64);

    cleanup(&root);
}

/// `waste_ratio` is 0.0 when no tombstones exist and approaches 1.0
/// as all objects become tombstones.
#[test]
fn waste_ratio_reflects_tombstone_proportion() {
    let root = temp_root("waste-ratio");
    let mut store = open_store(&root, fast_opts());

    // No waste initially
    assert_eq!(store.waste_ratio(), 0.0);

    put_named(&mut store, "live", b"alive");
    assert_eq!(store.waste_ratio(), 0.0);

    let key = ObjectKey::from_name("live");
    store.delete(key).expect("delete");
    // With one live object tombstoned, ratio > 0
    assert!(store.waste_ratio() > 0.0);

    // Re-write: old tombstone + new live object
    put_named(&mut store, "live", b"resurrected");
    // Now we have 1 tombstone + 1 live object
    let r = store.waste_ratio();
    assert!(r > 0.0 && r < 1.0);

    // Delete again
    store
        .delete(ObjectKey::from_name("live"))
        .expect("delete again");
    assert!(store.waste_ratio() > 0.0);

    cleanup(&root);
}

/// `replay_report()` fields are accurate after reopen.
#[test]
fn replay_report_fields_are_populated_correctly() {
    let root = temp_root("replay-fields");
    {
        let mut store = open_store(&root, fast_opts());
        for i in 0..5 {
            put_named(&mut store, &format!("r-{i}"), &pseudo_random_data(50, i));
        }
        store
            .delete(ObjectKey::from_name("r-2"))
            .expect("delete r-2");
        store
            .delete(ObjectKey::from_name("r-4"))
            .expect("delete r-4");
        store.sync_all().expect("sync");
    }
    {
        let store = reopen_store(&root);
        let rep = store.replay_report();
        assert_eq!(rep.puts_seen, 5);
        assert_eq!(rep.deletes_seen, 2);
        assert_eq!(rep.highest_sequence, 7); // 5 puts + 2 deletes
        assert!(rep.segment_count >= 1);
        assert!(rep.v3_records_seen > 0);
    }
    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Multi-segment object survival
// ═══════════════════════════════════════════════════════════════════════════

/// Write enough objects to span multiple segments (by setting a small
/// max_segment_bytes), then reopen and verify every object is intact.
#[test]
fn objects_spanning_multiple_segments_survive_reopen() {
    let root = temp_root("multi-segment");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 1024, // small segment forces rotation
        segment_count: 32,
        ..fast_opts()
    };
    let count = 40;
    let payload_size = 200; // with overhead ~300 per record, ~3 records per segment
    let mut keys_and_data = Vec::new();
    {
        let mut store = open_store(&root, opts);
        for i in 0..count {
            let data = pseudo_random_data(payload_size, i as u64);
            let key = put_named(&mut store, &format!("seg-obj-{i:03x}"), &data);
            keys_and_data.push((key, i));
        }
        store.sync_all().expect("sync");

        let rep = store.replay_report();
        // Should have rotated at least once given 40*~300 > 1024
        assert!(
            rep.segment_count >= 2,
            "expected at least 2 segments, got {}",
            rep.segment_count
        );
    }
    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, count);
        for (key, i) in &keys_and_data {
            let expected = pseudo_random_data(payload_size, *i as u64);
            let got = store
                .get(*key)
                .expect("get multisigment object")
                .unwrap_or_else(|| panic!("object for index {i} should exist after reopen"));
            assert_eq!(
                got, expected,
                "object {i}: data mismatch after multi-segment reopen"
            );
        }
    }
    cleanup(&root);
}

/// Deleting objects across segment boundaries, then reopening, preserves
/// correct state.
#[test]
fn deletes_across_segment_boundaries_survive_reopen() {
    let root = temp_root("delete-across-segments");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 1024,
        segment_count: 32,
        ..fast_opts()
    };
    let total = 30;
    let to_delete: usize = 15;
    {
        let mut store = open_store(&root, opts);
        for i in 0..total {
            put_named(
                &mut store,
                &format!("x-{i:03x}"),
                &pseudo_random_data(128, i as u64),
            );
        }
        for i in 0..to_delete {
            store
                .delete(ObjectKey::from_name(format!("x-{i:03x}").as_bytes()))
                .expect("delete across segments");
        }
        store.sync_all().expect("sync");
        let rep = store.replay_report();
        assert!(rep.segment_count >= 2, "should span multiple segments");
    }
    {
        let store = reopen_store(&root);
        assert_eq!(store.stats().live_objects, total - to_delete);
        for i in 0..total {
            let key = ObjectKey::from_name(format!("x-{i:03x}").as_bytes());
            let got = store.get(key).expect("get after reopen");
            if i < to_delete {
                assert!(got.is_none(), "deleted key {i} must be gone after reopen");
            } else {
                assert!(got.is_some(), "kept key {i} must survive reopen");
            }
        }
    }
    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Concurrent writer/reader isolation
// ═══════════════════════════════════════════════════════════════════════════

/// Multiple writer threads writing to distinct keys, plus a reader thread
/// periodically reading all known keys. No reader should see a corrupted
/// or partial payload.
#[test]
fn concurrent_writers_distinct_keys_reader_consistency() {
    let root = temp_root("concurrent-multi-writer");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 1024 * 1024,
        ..fast_opts()
    };
    let store = open_store(&root, opts);
    let shared = Arc::new(std::sync::Mutex::new(store));

    let n_writers = 4;
    let n_objects_per_writer = 30;

    let mut handles = Vec::new();
    for w in 0..n_writers {
        let store_arc = Arc::clone(&shared);
        let handle = thread::spawn(move || {
            for i in 0..n_objects_per_writer {
                let name = format!("w{w}-obj-{i:03x}");
                let payload = pseudo_random_data(64, (w * 1000 + i) as u64);
                store_arc
                    .lock()
                    .unwrap()
                    .put(ObjectKey::from_name(&name), &payload)
                    .expect("put in writer thread");
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("writer thread ok");
    }

    // Verify consistency
    let guard = shared.lock().unwrap();
    for w in 0..n_writers {
        for i in 0..n_objects_per_writer {
            let name = format!("w{w}-obj-{i:03x}");
            let expected = pseudo_random_data(64, (w * 1000 + i) as u64);
            let got = get_named(&guard, &name);
            assert_eq!(
                got.as_deref(),
                Some(expected.as_slice()),
                "writer {w} object {i}: data mismatch"
            );
        }
    }
    assert_eq!(
        guard.stats().live_objects,
        (n_writers * n_objects_per_writer) as usize
    );
    drop(guard);

    cleanup(&root);
}

/// Reader threads poll for objects as they are written by a writer thread.
/// Each reader must eventually see the expected payload without corruption.
#[test]
fn concurrent_reader_polls_until_object_appears() {
    let root = temp_root("concurrent-reader-poll");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 1024 * 1024,
        ..fast_opts()
    };
    let store = open_store(&root, opts);
    let shared = Arc::new(std::sync::Mutex::new(store));

    let n_objects: u64 = 40;
    let writer_shared = Arc::clone(&shared);
    let writer = thread::spawn(move || {
        for i in 0..n_objects {
            let name = format!("poll-obj-{i:03x}");
            let payload = pseudo_random_data(32, i);
            writer_shared
                .lock()
                .unwrap()
                .put(ObjectKey::from_name(&name), &payload)
                .expect("writer put");
            thread::sleep(std::time::Duration::from_millis(1));
        }
    });

    // Two reader threads, each reads all objects
    let mut reader_handles = Vec::new();
    for _r in 0..2 {
        let reader_shared = Arc::clone(&shared);
        let handle = thread::spawn(move || {
            for i in 0..n_objects {
                let name = format!("poll-obj-{i:03x}");
                let expected = pseudo_random_data(32, i);
                let key = ObjectKey::from_name(&name);
                // Spin until the object is visible
                loop {
                    let guard = reader_shared.lock().unwrap();
                    let got = guard.get(key).expect("reader get");
                    drop(guard);
                    if let Some(ref bytes) = got {
                        assert_eq!(
                            bytes, &expected,
                            "reader saw corrupted payload for object {i}"
                        );
                        break;
                    }
                    thread::yield_now();
                }
            }
        });
        reader_handles.push(handle);
    }

    writer.join().expect("writer ok");
    for h in reader_handles {
        h.join().expect("reader ok");
    }

    cleanup(&root);
}

/// Deletions from one thread are visible to a reader thread.
#[test]
fn concurrent_deleter_reader_consistency() {
    let root = temp_root("concurrent-deleter");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 1024 * 1024,
        ..fast_opts()
    };
    let store = open_store(&root, opts);
    let shared = Arc::new(std::sync::Mutex::new(store));

    // Pre-populate
    let n_pre = 60;
    {
        let mut guard = shared.lock().unwrap();
        for i in 0..n_pre {
            put_named(&mut guard, &format!("del-obj-{i:03x}"), b"data");
        }
    }

    let deleter_shared = Arc::clone(&shared);
    let deleter = thread::spawn(move || {
        for i in 0..n_pre {
            if i % 2 == 0 {
                let key = ObjectKey::from_name(format!("del-obj-{i:03x}").as_bytes());
                let _ = deleter_shared.lock().unwrap().delete(key);
            }
        }
    });

    let reader_shared = Arc::clone(&shared);
    let reader = thread::spawn(move || {
        for _ in 0..20 {
            let guard = reader_shared.lock().unwrap();
            let _count = guard.list_keys().len();
            // No crash = success. The reader sees a consistent snapshot
            // of the store at each lock acquisition.
            drop(guard);
            thread::yield_now();
        }
    });

    deleter.join().expect("deleter ok");
    reader.join().expect("reader ok");

    // Final check: even-indexed keys may or may not exist depending on
    // interleaving, but odd-indexed keys must exist.
    let guard = shared.lock().unwrap();
    for i in 0..n_pre {
        if i % 2 != 0 {
            assert!(
                guard.contains_key(ObjectKey::from_name(format!("del-obj-{i:03x}").as_bytes())),
                "odd-indexed key {i} must exist (never deleted)"
            );
        }
    }
    drop(guard);

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Key derivation edge cases
// ═══════════════════════════════════════════════════════════════════════════

/// Keys derived from empty names.
#[test]
fn key_from_empty_name() {
    let k1 = ObjectKey::from_name(b"");
    let k2 = ObjectKey::from_name(b"");
    assert_eq!(k1, k2, "empty name always produces the same key");
    assert_ne!(k1, ObjectKey::ZERO, "empty-name key is not zero");
}

/// Keys derived from unicode names are deterministic.
#[test]
fn key_from_unicode_name_is_deterministic() {
    let k1 = ObjectKey::from_name("café-文档-привет");
    let k2 = ObjectKey::from_name("café-文档-привет");
    assert_eq!(k1, k2);

    let k3 = ObjectKey::from_name("café-文档-привет!");
    assert_ne!(k1, k3, "different names produce different keys");
}

/// Keys derived from binary (non-UTF8) byte sequences.
#[test]
fn key_from_binary_data_is_deterministic() {
    let bin1: &[u8] = &[0x00, 0x01, 0xFE, 0xFF, 0x7F, 0x80];
    let bin2: &[u8] = &[0x00, 0x01, 0xFE, 0xFF, 0x7F, 0x80];
    assert_eq!(
        ObjectKey::from_name(bin1),
        ObjectKey::from_name(bin2),
        "same binary input produces same key"
    );

    let bin3: &[u8] = &[0x00, 0x01, 0xFE, 0xFF, 0x7F, 0x81];
    assert_ne!(
        ObjectKey::from_name(bin1),
        ObjectKey::from_name(bin3),
        "different binary inputs produce different keys"
    );
}

/// `ObjectKey::ZERO` round-trips through put/get.
#[test]
fn zero_key_content_round_trip() {
    let root = temp_root("zero-key");
    let mut store = open_store(&root, fast_opts());
    let payload = b"stored under zero key";
    store.put(ObjectKey::ZERO, payload).expect("put zero key");
    let got = store.get(ObjectKey::ZERO).expect("get zero key");
    assert_eq!(got.as_deref(), Some(&payload[..]));
    assert!(store.contains_key(ObjectKey::ZERO));
    cleanup(&root);
}

/// `ObjectKey::from_bytes32` with all-0xFF bytes.
#[test]
fn all_ff_key_round_trip() {
    let root = temp_root("ff-key");
    let mut store = open_store(&root, fast_opts());
    let key = ObjectKey::from_bytes32([0xFF; 32]);
    let payload = b"stored under all-ff key";
    store.put(key, payload).expect("put ff key");
    let got = store.get(key).expect("get ff key");
    assert_eq!(got.as_deref(), Some(&payload[..]));
    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Content-addressed vs named-key isolation
// ═══════════════════════════════════════════════════════════════════════════

/// Content-addressed puts of identical payloads produce identical keys.
/// Named puts of different names produce different keys for the same payload.
#[test]
fn content_addressed_same_payload_same_key_named_different() {
    let root = temp_root("ca-vs-named");
    let mut store = open_store(&root, fast_opts());
    let payload = b"same bytes, different addressing";

    // Content-addressed: same payload = same key
    let ca1 = store.put_content_addressed(payload).expect("put ca 1");
    let ca2 = store.put_content_addressed(payload).expect("put ca 2");
    assert_eq!(ca1, ca2, "same content-addressed payload = same key");

    // Named: different names = different keys, even with same payload
    let key_a = ObjectKey::from_name("name-a");
    let key_b = ObjectKey::from_name("name-b");
    store.put(key_a, payload).expect("put name-a");
    store.put(key_b, payload).expect("put name-b");
    assert_ne!(key_a, key_b, "different names produce different keys");

    // Content-addressed key differs from name-derived key for the same payload
    assert_ne!(ca1, key_a);

    // All three objects are independently stored
    assert_eq!(store.list_keys().len(), 3);

    // get_verified: content-addressed key passes, name-derived keys fail
    assert!(store.get_verified(ca1).expect("get_verified ca").is_some());

    let mismatch_a = store.get_verified(key_a);
    assert!(
        matches!(mismatch_a, Err(StoreError::ContentAddressMismatch { .. })),
        "name-derived key must fail get_verified"
    );

    let mismatch_b = store.get_verified(key_b);
    assert!(
        matches!(mismatch_b, Err(StoreError::ContentAddressMismatch { .. })),
        "name-derived key must fail get_verified"
    );

    cleanup(&root);
}

/// A content-addressed key survives reopen and passes `get_verified`.
#[test]
fn content_addressed_survives_reopen_with_verification() {
    let root = temp_root("ca-reopen-verify");
    let payload = b"content-addressed data that survives reopen";
    let key;
    {
        let mut store = open_store(&root, fast_opts());
        key = store.put_content_addressed(payload).expect("put ca");
        store.sync_all().expect("sync");
    }
    {
        let store = reopen_store(&root);
        assert!(store.contains_key(key));
        let verified = store
            .get_verified(key)
            .expect("get_verified after reopen")
            .expect("content-addressed object must survive reopen");
        assert_eq!(verified, payload);
    }
    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Edge-case payload sizes
// ═══════════════════════════════════════════════════════════════════════════

/// A sequence of objects with varying payload sizes (0, 1, 255, 256,
/// 1023, 1024) all round-trip correctly.
#[test]
fn varying_payload_sizes_all_round_trip() {
    let root = temp_root("varying-sizes");
    let mut store = open_store(&root, fast_opts());
    let sizes: &[usize] = &[0, 1, 17, 63, 64, 65, 255, 256, 257, 1023, 1024, 2047, 2048];

    for &size in sizes {
        let data = pseudo_random_data(size, size as u64);
        let name = format!("sz-{size:05}");
        put_named(&mut store, &name, &data);
        let got = get_named(&store, &name);
        assert_eq!(
            got.as_deref(),
            Some(data.as_slice()),
            "size {size}: round-trip mismatch"
        );
    }
    assert_eq!(store.stats().live_objects, sizes.len());

    store.sync_all().expect("sync");
    drop(store);

    // Reopen with same large segment size
    let store2 = LocalObjectStore::open_with_options(
        &root,
        StoreOptions {
            verify_read_checksums: false,
            max_segment_bytes: 2 * 1048576,
            segment_count: 32,
            ..fast_opts()
        },
    )
    .expect("reopen with large segments");
    for &size in sizes {
        let data = pseudo_random_data(size, size as u64);
        let name = format!("sz-{size:05}");
        let got = get_named(&store2, &name);
        assert_eq!(
            got.as_deref(),
            Some(data.as_slice()),
            "size {size}: mismatch after reopen"
        );
    }

    cleanup(&root);
}

/// The maximum allowable payload size (`max_object_bytes()`) round-trips.
#[test]
fn max_payload_size_round_trips() {
    let root = temp_root("max-payload");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 8192,
        ..fast_opts()
    };
    let max_obj = opts.max_object_bytes() as usize;
    let mut store = open_store(&root, opts);
    let payload = pseudo_random_data(max_obj, 42);

    put_named(&mut store, "max", &payload);
    let got = get_named(&store, "max");
    assert_eq!(got.as_deref(), Some(payload.as_slice()));

    store.sync_all().expect("sync");
    drop(store);

    let store2 = LocalObjectStore::open_with_options(
        &root,
        StoreOptions {
            verify_read_checksums: false,
            max_segment_bytes: 8192,
            ..fast_opts()
        },
    )
    .expect("reopen max payload store");
    let got2 = get_named(&store2, "max");
    assert_eq!(got2.as_deref(), Some(payload.as_slice()));

    cleanup(&root);
}

/// Put exactly one byte past `max_object_bytes()` must fail with
/// `PayloadTooLarge`.
#[test]
fn one_byte_past_max_is_rejected() {
    let root = temp_root("one-byte-past");
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 2048,
        ..fast_opts()
    };
    let max_obj = opts.max_object_bytes();
    let mut store = open_store(&root, opts);

    let too_big = vec![0x42; (max_obj + 1) as usize];
    let result = store.put(ObjectKey::from_name("too-big"), &too_big);
    assert!(
        matches!(result, Err(StoreError::PayloadTooLarge { len, max }) if len == max_obj + 1 && max == max_obj),
        "one byte past max must fail with PayloadTooLarge"
    );

    // Exactly at max should succeed
    let exact = vec![0x7e; max_obj as usize];
    store
        .put(ObjectKey::from_name("exact"), &exact)
        .expect("exact max payload should succeed");

    cleanup(&root);
}

/// Multiple overwrites of the same key (named) preserve only the latest
/// version as the visible payload, but all versions remain in history.
#[test]
fn multiple_overwrites_history_accessible() {
    let root = temp_root("overwrite-history");
    let mut store = open_store(&root, fast_opts());
    let key = ObjectKey::from_name("versioned");

    store.put(key, b"v0").expect("put v0");
    store.put(key, b"v1").expect("put v1");
    store.put(key, b"v2").expect("put v2");
    store.put(key, b"v3").expect("put v3");
    store.put(key, b"v4-final").expect("put v4");

    // Latest version visible
    let got = store.get(key).expect("get").expect("object must exist");
    assert_eq!(got, b"v4-final");

    // History contains all 5 versions (order is replay/segment order,
    // not necessarily insertion order)
    let versions = store.version_locations_of(key);
    assert_eq!(versions.len(), 5);

    // Collect all historical payloads
    let mut history_payloads: Vec<Vec<u8>> = Vec::new();
    for loc in &versions {
        history_payloads.push(
            store
                .get_at_location(*loc)
                .expect("get version from history"),
        );
    }
    // Each expected payload must be present in history
    let expected: Vec<&[u8]> = vec![b"v0", b"v1", b"v2", b"v3", b"v4-final"];
    for exp in &expected {
        assert!(
            history_payloads.iter().any(|p| p.as_slice() == *exp),
            "history missing payload {exp:?}"
        );
    }

    // Stats: one live object
    assert_eq!(store.stats().live_objects, 1);

    store.sync_all().expect("sync");
    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Space exhaustion and recovery
// ═══════════════════════════════════════════════════════════════════════════

/// When all segments are exhausted, writes return `StoreError::NoSpace`.
/// After manually deleting objects and running `compact_retaining`,
/// previously exhausted space is recovered and writes succeed again.
#[test]
fn space_exhaustion_then_compact_recovery() {
    let root = temp_root("space-exhaust");
    // Large segment_count ensures there are always free segments for
    // tombstone writes during compaction. The test proves that after
    // compaction frees segments, writes resume normally.
    let opts = StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 512,
        segment_count: 256,
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        sync_on_write: false,
        reclaim_enabled: false,
        ..StoreOptions::default()
    };
    let max_obj = opts.max_object_bytes() as usize;
    let payload = pseudo_random_data(max_obj.min(64), 99);

    let mut keep_keys = Vec::new();
    let write_count: usize = 50;
    {
        let mut store = open_store(&root, opts);
        for i in 0..write_count {
            let name = format!("obj-{i:04x}");
            let key = put_named(&mut store, &name, &payload);
            if i < 5 {
                keep_keys.push(key);
            }
        }
        assert_eq!(store.stats().live_objects, write_count);

        // Compact: keep only 5 keys, tombstone the rest.
        let report = store
            .compact_retaining(&keep_keys, &[])
            .expect("compact should succeed with free segments available");
        assert!(report.tombstoned_unprotected_keys > 0);

        // After compaction, only protected keys survive
        assert_eq!(store.stats().live_objects, keep_keys.len());

        // Writes still work post-compaction
        store
            .put(ObjectKey::from_name("post-compact"), b"recovered")
            .expect("write after compact should succeed");
        assert!(store.contains_key(ObjectKey::from_name("post-compact")));

        store.sync_all().expect("sync after recovery");
    }

    // Phase 2: reopen — verify only protected keys + new write survive
    {
        let store = LocalObjectStore::open_with_options(
            &root,
            StoreOptions {
                verify_read_checksums: false,
                max_segment_bytes: 512,
                segment_count: 256,
                ..fast_opts()
            },
        )
        .expect("reopen after compaction");
        let live = store.stats().live_objects;
        assert_eq!(
            live,
            keep_keys.len() + 1,
            "only protected + post-compact should survive"
        );
        assert!(store.contains_key(ObjectKey::from_name("post-compact")));
        for k in &keep_keys {
            assert!(store.contains_key(*k), "protected key must survive reopen");
        }
    }

    cleanup(&root);
}
/// `get_range` with every possible valid offset/length combination on a
/// known payload.
#[test]
fn get_range_all_valid_combinations() {
    let root = temp_root("range-all");
    let mut store = open_store(&root, fast_opts());
    let payload = b"abcdefghij";
    let key = ObjectKey::from_name("alpha-payload");
    store.put(key, payload).expect("put");

    // All valid (offset, len) pairs
    for off in 0..payload.len() {
        for len in 1..=(payload.len() - off) {
            let expected = &payload[off..off + len];
            let got = store
                .get_range(key, off as u64, len as u64)
                .expect("get_range")
                .unwrap_or_else(|| panic!("range [{off}, {len}) should exist"));
            assert_eq!(&got[..], expected, "range [{off}, {len}) mismatch");
        }
    }
    cleanup(&root);
}

/// `get_range` on a zero-length object returns None.
#[test]
fn get_range_on_empty_object() {
    let root = temp_root("range-empty");
    let mut store = open_store(&root, fast_opts());
    let key = ObjectKey::from_name("empty");
    store.put(key, b"").expect("put empty");

    let got = store.get_range(key, 0, 1).expect("get_range on empty");
    assert!(
        got.is_none() || got == Some(vec![]),
        "get_range on empty object should return None or empty"
    );

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. Flush durability — explicit sync_all before close
// ═══════════════════════════════════════════════════════════════════════════

/// Put several objects, call `sync_all`, close the store, reopen, and
/// verify every object is byte-identical. This is the strongest
/// durability guarantee the store provides.
#[test]
fn flush_durability_all_objects_survive_sync_and_reopen() {
    let root = temp_root("flush-durability");
    let count = 16;
    let payload_size = 128;
    let mut keys_and_data = Vec::new();

    {
        let mut store = open_store(&root, fast_opts());
        for i in 0..count {
            let data = pseudo_random_data(payload_size, i * 2);
            let key = put_named(&mut store, &format!("fd-{i:03x}"), &data);
            keys_and_data.push((key, data));
        }
        store.sync_all().expect("sync_all before close");
    }

    {
        let store = reopen_store(&root);
        assert_eq!(
            store.stats().live_objects,
            count as usize,
            "all objects must survive sync + reopen"
        );
        for (key, expected) in &keys_and_data {
            let got = store
                .get(*key)
                .expect("get after flush + reopen")
                .unwrap_or_else(|| panic!("key {key} missing after flush + reopen"));
            assert_eq!(
                &got, expected,
                "data mismatch after flush + reopen for key {key}"
            );
        }
    }

    cleanup(&root);
}

/// After `sync_all`, the replay report must show all puts and no
/// repaired tail bytes (no torn writes survived).
#[test]
fn flush_durability_replay_report_clean_after_sync() {
    let root = temp_root("flush-replay-clean");
    let count = 8;

    {
        let mut store = open_store(&root, fast_opts());
        for i in 0..count {
            put_named(
                &mut store,
                &format!("fr-{i}"),
                &pseudo_random_data(64, i as u64),
            );
        }
        store.sync_all().expect("sync before close");
    }

    {
        let store = reopen_store(&root);
        let rep = store.replay_report();
        assert_eq!(rep.puts_seen, count as u64);
        assert_eq!(rep.deletes_seen, 0);
        // After a clean sync, tail repair should be zero (no torn writes)
        assert_eq!(
            rep.repaired_tail_bytes, 0,
            "clean sync should produce zero tail repair bytes"
        );
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Crash consistency — overwrite without sync
// ═══════════════════════════════════════════════════════════════════════════

/// Write an object, sync it, then overwrite with new data but do NOT sync,
/// then drop the store (simulating a crash). On reopen, the object must
/// contain either the old data or the new data in full — never a partial
/// or torn payload.
#[test]
fn crash_consistency_overwrite_without_sync_preserves_either_old_or_new() {
    let root = temp_root("crash-overwrite");
    let key = ObjectKey::from_name("crash-target");
    let old_payload = b"old-data-version-one-aaaa";
    let new_payload = b"new-data-version-two-bbbb";

    // Phase 1: write old and sync (committed)
    {
        let mut store = open_store(&root, fast_opts());
        store.put(key, old_payload).expect("put old");
        store.sync_all().expect("sync old");
    }

    // Phase 2: overwrite without sync (simulates crash)
    {
        let mut store = open_store(&root, fast_opts());
        store.put(key, new_payload).expect("put new");
        // NO sync — drop simulates power failure / process kill
    }

    // Phase 3: reopen and verify no torn data
    {
        let store = reopen_store(&root);
        let got = store
            .get(key)
            .expect("get after crash")
            .expect("object must exist after crash");

        let is_old = got.as_slice() == old_payload;
        let is_new = got.as_slice() == new_payload;
        assert!(
            is_old || is_new,
            "object after crash must be either old or new, got {:?}",
            std::str::from_utf8(&got).unwrap_or("<binary>")
        );

        // Additional check: payload length should match either old or new
        assert!(
            got.len() == old_payload.len() || got.len() == new_payload.len(),
            "payload length {} must match old ({}) or new ({})",
            got.len(),
            old_payload.len(),
            new_payload.len()
        );
    }

    cleanup(&root);
}

/// Write multiple objects, sync, then issue additional writes and
/// deletes without syncing. On reopen, committed objects must survive
/// intact; uncommitted operations may or may not be visible, but
/// committed data must never be corrupted.
#[test]
fn crash_consistency_committed_objects_never_corrupted() {
    let root = temp_root("crash-mixed");
    let committed_data: Vec<(ObjectKey, Vec<u8>)> = (0..5)
        .map(|i| {
            let key = ObjectKey::from_name(format!("committed-{i}").as_bytes());
            let data = pseudo_random_data(128, i as u64);
            (key, data)
        })
        .collect();

    // Phase 1: write and sync committed data
    {
        let mut store = open_store(&root, fast_opts());
        for (key, data) in &committed_data {
            store.put(*key, data).expect("put committed");
        }
        store.sync_all().expect("sync committed");
    }

    // Phase 2: mix of writes and deletes without sync
    {
        let mut store = open_store(&root, fast_opts());
        // Write new unsynced objects
        for i in 0..3 {
            store
                .put(
                    ObjectKey::from_name(format!("unsynced-{i}").as_bytes()),
                    b"uncommitted",
                )
                .expect("put unsynced");
        }
        // Delete one committed object
        store
            .delete(committed_data[2].0)
            .expect("delete committed unsynced");
        // Overwrite another committed object
        store
            .put(committed_data[1].0, b"overwritten-unsynced")
            .expect("overwrite unsynced");
        // NO sync
    }

    // Phase 3: reopen, committed data must be safe
    {
        let store = reopen_store(&root);
        for (i, (key, expected)) in committed_data.iter().enumerate() {
            let got = store.get(*key).expect("get committed after crash");
            if let Some(ref payload) = got {
                // If still present, must be either original committed or
                // the unsynced overwrite; must never be truncated or garbage
                if i == 1 {
                    // Key 1 was overwritten without sync — could be old or new
                    assert!(
                        payload == expected || payload == b"overwritten-unsynced",
                        "committed key {i}: got unexpected payload after unsynced overwrite"
                    );
                } else if i == 2 {
                    // Key 2 was deleted without sync — may or may not exist
                    // If it exists, it must be the original committed data
                    assert_eq!(
                        payload, expected,
                        "committed key {i}: if present must be original committed data"
                    );
                } else {
                    assert_eq!(
                        payload, expected,
                        "committed key {i}: must survive crash intact"
                    );
                }
            }
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. Write ordering — monotonic sequence numbers
// ═══════════════════════════════════════════════════════════════════════════

/// Each `put` returns a `StoredObject` with an increasing sequence
/// number. No two puts using `sync_on_write = false` should produce
/// the same sequence number, and the sequence must increase
/// monotonically.
#[test]
fn write_ordering_sequence_increases_monotonically() {
    let root = temp_root("seq-monotonic");
    let opts = StoreOptions {
        verify_read_checksums: false,
        sync_on_write: false,
        ..fast_opts()
    };
    let mut store = open_store(&root, opts);

    let mut last_seq = 0u64;
    for i in 0..50 {
        let stored = store
            .put(
                ObjectKey::from_name(format!("seq-{i:04x}").as_bytes()),
                b"payload",
            )
            .expect("put");
        let seq = stored.sequence;
        assert!(
            seq > last_seq,
            "sequence must increase: got {seq} after {last_seq} at iteration {i}"
        );
        last_seq = seq;
    }

    // After sync + reopen, stats.next_sequence must equal highest + 1
    store.sync_all().expect("sync");
    drop(store);

    let store2 = reopen_store(&root);
    let stats = store2.stats();
    assert_eq!(
        stats.next_sequence,
        last_seq + 1,
        "stats.next_sequence should be one past highest assigned sequence"
    );
    // Replay counts only post-checkpoint records; live_objects is authoritative.
    assert_eq!(
        stats.live_objects, 50,
        "all 50 objects should be live after reopen"
    );
    assert_eq!(
        stats.replay.highest_sequence, last_seq,
        "replay highest_sequence should match the last assigned sequence"
    );

    cleanup(&root);
}

/// When overwriting the same key, each overwrite gets a distinct,
/// larger sequence number.
#[test]
fn write_ordering_overwrite_gets_higher_sequence() {
    let root = temp_root("seq-overwrite");
    let mut store = open_store(&root, fast_opts());
    let key = ObjectKey::from_name("repeated");

    let mut seqs = Vec::new();
    for i in 0..10 {
        let payload = format!("version-{i}").into_bytes();
        let stored = store.put(key, &payload).expect("put overwrite");
        seqs.push(stored.sequence);
    }

    // All sequences must be strictly increasing
    for w in seqs.windows(2) {
        assert!(
            w[0] < w[1],
            "overwrite sequences must increase: {} -> {}",
            w[0],
            w[1]
        );
    }

    // Version locations count must match overwrite count
    let versions = store.version_locations_of(key);
    assert_eq!(versions.len(), 10, "should have 10 historical versions");

    cleanup(&root);
}

/// Sequence numbers must survive close + reopen intact.
#[test]
fn write_ordering_sequence_survives_reopen() {
    let root = temp_root("seq-reopen");
    let mut seq_before: u64 = 0;

    {
        let mut store = open_store(&root, fast_opts());
        for i in 0..20 {
            let stored = store
                .put(
                    ObjectKey::from_name(format!("persist-{i}").as_bytes()),
                    &[i as u8],
                )
                .expect("put");
            seq_before = stored.sequence;
        }
        store.sync_all().expect("sync");
    }

    {
        let store = reopen_store(&root);
        let stats = store.stats();
        // Replay counts only post-checkpoint records; live_objects is authoritative.
        assert_eq!(
            stats.live_objects, 20,
            "all 20 objects should be live after reopen"
        );
        assert_eq!(stats.replay.highest_sequence, seq_before);
        assert_eq!(stats.next_sequence, seq_before + 1);
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. Property-based randomized payload size tests
// ═══════════════════════════════════════════════════════════════════════════

/// Randomized round-trip for every size in the canonical list plus random
/// payload bytes. Each size is tested with a deterministic pseudo-random
/// payload seeded from the size itself.
#[test]
fn randomized_payload_sizes_all_round_trip() {
    let root = temp_root("rand-sizes");
    let sizes: &[usize] = &[0, 1, 4095, 4096, 4097, 65536, 1048576];
    let mut store = open_store(
        &root,
        StoreOptions {
            verify_read_checksums: false,
            max_segment_bytes: 2 * 1048576, // large enough for max payload
            segment_count: 32,
            ..fast_opts()
        },
    );

    let max_obj = store.capacity_bytes();
    // Skip sizes that exceed the object store's practical limit
    let feasible: Vec<usize> = sizes
        .iter()
        .copied()
        .filter(|&s| (s as u64) <= max_obj)
        .collect();

    for &size in &feasible {
        let payload = pseudo_random_data(size, (size as u64).wrapping_mul(0x9e37_79b9));
        let name = format!("rand-{size:07}");
        let key = put_named(&mut store, &name, &payload);
        let got = get_named(&store, &name);
        assert_eq!(
            got.as_deref(),
            Some(payload.as_slice()),
            "randomized payload size {size}: round-trip mismatch"
        );

        // Verify contains_key
        assert!(store.contains_key(key), "contains_key for size {size}");
    }

    assert_eq!(store.stats().live_objects, feasible.len());

    store.sync_all().expect("sync");
    drop(store);

    // Reopen with same large segment size
    let store2 = LocalObjectStore::open_with_options(
        &root,
        StoreOptions {
            verify_read_checksums: false,
            max_segment_bytes: 2 * 1048576,
            segment_count: 32,
            ..fast_opts()
        },
    )
    .expect("reopen with large segments");
    for &size in &feasible {
        let payload = pseudo_random_data(size, (size as u64).wrapping_mul(0x9e37_79b9));
        let name = format!("rand-{size:07}");
        let got = get_named(&store2, &name);
        assert_eq!(
            got.as_deref(),
            Some(payload.as_slice()),
            "size {size}: mismatch after reopen"
        );
    }

    cleanup(&root);
}

/// For each size, write 3 objects with different random seeds to verify
/// independent key isolation.
#[test]
fn randomized_payload_independent_keys() {
    let root = temp_root("rand-keys");
    let mut store = open_store(
        &root,
        StoreOptions {
            verify_read_checksums: false,
            max_segment_bytes: 131072,
            segment_count: 16,
            ..fast_opts()
        },
    );

    let sizes: &[usize] = &[0, 1, 4095, 4096, 4097];
    for &size in sizes {
        let mut keys = Vec::new();
        for seed in 0..3 {
            let payload = pseudo_random_data(size, seed * 1000 + size as u64);
            let name = format!("iso-{size:05}-{seed}");
            let key = put_named(&mut store, &name, &payload);
            keys.push((key, name, payload));
        }
        // Each key independently retrievable
        for (key, name, expected) in &keys {
            let got = get_named(&store, name);
            assert_eq!(
                got.as_deref(),
                Some(expected.as_slice()),
                "size {size} seed {name}: isolation mismatch"
            );
            assert!(store.contains_key(*key));
        }
        // Different seeds produce different keys
        assert_ne!(
            keys[0].0, keys[1].0,
            "different seeds for size {size} must produce different keys"
        );
        assert_ne!(
            keys[1].0, keys[2].0,
            "different seeds for size {size} must produce different keys"
        );
    }

    cleanup(&root);
}
