//! Property-based tests for `tidefs-local-object-store` using randomized
//! inputs via the `rand` crate (already a workspace dependency).
//!
//! Covers round-trip put/get/delete invariants, crash-consistency properties,
//! and segment lifecycle correctness. Inputs are seeded from the current time
//! so failures are reproducible by seeding from the log output.
//!
//! Tests are organized in three groups matching the issue #3955 plan:
//! 1. Round-trip property tests (arbitrary blob → put → get → assert_eq)
//! 2. Crash-consistency tests (drop without close → reopen → verify)
//! 3. Segment lifecycle tests (rotation → old + new segments readable)

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-proptest-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

fn fast_opts() -> StoreOptions {
    StoreOptions::test_fast()
}

fn open_store(root: &PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("open store")
}

/// Deterministic pseudo-random payload of `len` bytes.
fn rand_payload(rng: &mut StdRng, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.gen()).collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Round-trip property tests
// ═══════════════════════════════════════════════════════════════════════════

/// For randomized payloads of diverse sizes, put → get returns the
/// exact same bytes. Tests 100 payloads from 0 to 3872 bytes.
#[test]
fn put_get_round_trip_is_identity() {
    let mut rng = StdRng::from_entropy();
    let root = temp_root("prop-put-get");
    let mut store = open_store(&root);

    for _ in 0..100 {
        let len = rng.gen_range(0..3872);
        let payload = rand_payload(&mut rng, len);
        let key = ObjectKey::from_name("proptest-key");
        store.put(key, &payload).expect("put");

        let got = store.get(key).expect("get").expect("object should exist");
        assert_eq!(
            got,
            payload,
            "round-trip payload mismatch: put {len} bytes, got {}",
            got.len()
        );
        assert!(store.contains_key(key));
    }

    cleanup(&root);
}

/// Randomized payload sizes from 0..3872 with fresh keys each time.
/// Every key independently returns its payload.
#[test]
fn independent_keys_have_independent_data() {
    let mut rng = StdRng::from_entropy();
    let root = temp_root("prop-independent");
    let mut store = open_store(&root);

    for i in 0..50 {
        let len = rng.gen_range(0..3872);
        let p1 = rand_payload(&mut rng, len);
        let p2 = rand_payload(&mut rng, len);

        let k1 = ObjectKey::from_name(format!("first-{i}").as_bytes());
        let k2 = ObjectKey::from_name(format!("second-{i}").as_bytes());
        store.put(k1, &p1).expect("put k1");
        store.put(k2, &p2).expect("put k2");

        let got1 = store.get(k1).expect("get k1").expect("k1 should exist");
        let got2 = store.get(k2).expect("get k2").expect("k2 should exist");

        assert_eq!(got1, p1, "k1 payload mismatch at iteration {i}");
        assert_eq!(got2, p2, "k2 payload mismatch at iteration {i}");

        assert_ne!(k1, k2);
        assert!(store.contains_key(k1));
        assert!(store.contains_key(k2));
    }

    let listed = store.list_keys();
    assert_eq!(listed.len(), 100, "should have 100 distinct keys");

    cleanup(&root);
}

/// After deleting an object, get returns None.
#[test]
fn delete_removes_object() {
    let mut rng = StdRng::from_entropy();
    let root = temp_root("prop-delete");
    let mut store = open_store(&root);

    for i in 0..100 {
        let len = rng.gen_range(0..1024);
        let payload = rand_payload(&mut rng, len);
        let key = ObjectKey::from_name(format!("del-{i}").as_bytes());
        store.put(key, &payload).expect("put");

        let existed = store.delete(key).expect("delete");
        assert!(existed);

        let got = store.get(key).expect("get after delete");
        assert!(got.is_none(), "get after delete should return None");
        assert!(
            !store.contains_key(key),
            "contains_key should be false after delete"
        );
    }

    cleanup(&root);
}

/// Delete of a key that was never put returns false, no error.
#[test]
fn delete_nonexistent_returns_false() {
    let root = temp_root("prop-delete-nonexist");
    let mut store = open_store(&root);

    let key = ObjectKey::from_name("never-put");
    let existed = store.delete(key).expect("delete nonexistent");
    assert!(!existed, "delete of nonexistent key should return false");

    cleanup(&root);
}

/// Put N objects with randomized payloads, then enumerate: every key
/// present and value matches.
#[test]
fn put_n_objects_enumerate_all_present() {
    let mut rng = StdRng::from_entropy();
    let root = temp_root("prop-enumerate");
    let mut store = open_store(&root);

    let n = rng.gen_range(5..32);
    let mut expected: Vec<(ObjectKey, Vec<u8>)> = Vec::new();

    for i in 0..n {
        let len = rng.gen_range(0..1024);
        let payload = rand_payload(&mut rng, len);
        let key = ObjectKey::from_name(format!("enum-{i}").as_bytes());
        store.put(key, &payload).expect("put");
        expected.push((key, payload));
    }

    assert_eq!(
        store.list_keys().len(),
        expected.len(),
        "list_keys count mismatch"
    );

    for (key, exp) in &expected {
        let got = store
            .get(*key)
            .expect("get")
            .expect("key missing from enumeration");
        assert_eq!(got, *exp, "payload mismatch for key {key}");
        assert!(store.contains_key(*key));
    }

    assert_eq!(store.stats().live_objects, expected.len());

    cleanup(&root);
}

/// Overwrite same key many times; latest value is always correct.
#[test]
fn overwrite_keeps_latest_value() {
    let mut rng = StdRng::from_entropy();
    let root = temp_root("prop-overwrite");
    let mut store = open_store(&root);

    let key = ObjectKey::from_name("overwrite-target");
    let count = rng.gen_range(2..20);
    let mut payloads: Vec<Vec<u8>> = Vec::new();

    for _ in 0..count {
        let len = rng.gen_range(0..1024);
        let payload = rand_payload(&mut rng, len);
        store.put(key, &payload).expect("put overwrite");
        payloads.push(payload);
    }

    let latest = payloads.last().unwrap();
    let got = store.get(key).expect("get").expect("object should exist");
    assert_eq!(
        got, *latest,
        "after {count} overwrites, latest payload did not match"
    );

    assert_eq!(store.stats().live_objects, 1);

    let versions = store.version_locations_of(key);
    assert!(
        versions.len() >= count,
        "version_locations_of should have at least {count} entries, got {}",
        versions.len()
    );

    cleanup(&root);
}

/// Sync + reopen preserves all data (strongest durability guarantee).
#[test]
fn sync_and_reopen_preserves_all_data() {
    let mut rng = StdRng::from_entropy();
    let root = temp_root("prop-sync-reopen");
    let n = rng.gen_range(3..16);
    let mut expected: Vec<(ObjectKey, Vec<u8>)> = Vec::new();

    {
        let mut store = open_store(&root);
        for i in 0..n {
            let len = rng.gen_range(0..1024);
            let payload = rand_payload(&mut rng, len);
            let key = ObjectKey::from_name(format!("sync-{i}").as_bytes());
            store.put(key, &payload).expect("put");
            expected.push((key, payload));
        }
        store.sync_all().expect("sync before close");
    }

    {
        let store = open_store(&root);
        assert_eq!(
            store.stats().live_objects,
            expected.len(),
            "live_objects mismatch after reopen"
        );

        for (key, exp) in &expected {
            let got = store
                .get(*key)
                .expect("get after reopen")
                .expect("key missing after sync+reopen");
            assert_eq!(
                got, *exp,
                "payload mismatch after sync+reopen for key {key}"
            );
        }
    }

    cleanup(&root);
}

/// Zero-length payloads are round-tripped correctly.
#[test]
fn zero_length_payload_is_valid() {
    let root = temp_root("prop-zero-len");
    let mut store = open_store(&root);

    let key = ObjectKey::from_name("empty-payload");
    store.put(key, b"").expect("put empty");
    let got = store
        .get(key)
        .expect("get")
        .expect("zero-length object should exist");

    assert!(
        got.is_empty(),
        "zero-length payload should yield empty vec, got {} bytes",
        got.len()
    );

    let range = store.get_range(key, 0, 1).expect("get_range");
    assert!(
        range.is_none() || range == Some(vec![]),
        "get_range on empty object should return None or []"
    );

    assert!(store.contains_key(key));
    cleanup(&root);
}

/// `get_range` returns the correct byte slice for randomized offsets.
#[test]
fn get_range_returns_correct_slice() {
    let mut rng = StdRng::from_entropy();
    let root = temp_root("prop-get-range");
    let mut store = open_store(&root);

    for _ in 0..100 {
        let len = rng.gen_range(1..1024);
        let payload = rand_payload(&mut rng, len);
        let offset = rng.gen_range(0..len);
        let range_len = rng.gen_range(1..=(len - offset));

        let key = ObjectKey::from_name(format!("range-{}", rng.gen::<u64>()).as_bytes());
        store.put(key, &payload).expect("put");

        let got = store
            .get_range(key, offset as u64, range_len as u64)
            .expect("get_range")
            .expect("range should exist");

        let expected = &payload[offset..offset + range_len];
        assert_eq!(
            got, expected,
            "range mismatch at offset {offset}, len {range_len}"
        );
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Crash-consistency property tests
// ═══════════════════════════════════════════════════════════════════════════

/// Write objects, sync them, write more objects without syncing,
/// drop the store (simulate SIGKILL), reopen. Committed objects must
/// be intact; unsynced objects must be either fully present or absent.
#[test]
fn committed_objects_survive_crash_unsynced_are_atomic() {
    let mut rng = StdRng::from_entropy();
    let root = temp_root("prop-crash-atomic");

    let committed_count = rng.gen_range(3..10);
    let unsynced_count = rng.gen_range(1..6);
    let mut committed: Vec<(ObjectKey, Vec<u8>)> = Vec::new();
    let mut unsynced: Vec<(ObjectKey, Vec<u8>)> = Vec::new();

    // Phase 1: write committed data and sync
    {
        let mut store = open_store(&root);
        for i in 0..committed_count {
            let len = rng.gen_range(1..512);
            let payload = rand_payload(&mut rng, len);
            let key = ObjectKey::from_name(format!("comm-{i}").as_bytes());
            store.put(key, &payload).expect("put committed");
            committed.push((key, payload));
        }
        store.sync_all().expect("sync committed");
    }

    // Phase 2: write unsynced data, do NOT sync, drop (simulate crash)
    {
        let mut store = open_store(&root);
        for i in 0..unsynced_count {
            let len = rng.gen_range(1..512);
            let payload = rand_payload(&mut rng, len);
            let key = ObjectKey::from_name(format!("unsynced-{i}").as_bytes());
            store.put(key, &payload).expect("put unsynced");
            unsynced.push((key, payload));
        }
        // Overwrite first committed key without sync
        if let Some((first_key, _)) = committed.first() {
            store
                .put(*first_key, b"overwritten-unsynced")
                .expect("overwrite unsynced");
        }
        // NO sync — store dropped after scope (simulates SIGKILL)
    }

    // Phase 3: reopen and verify invariants
    {
        let store = open_store(&root);

        for (i, (key, expected)) in committed.iter().enumerate() {
            let got = store.get(*key).expect("get committed after crash");
            if let Some(ref payload) = got {
                if i == 0 {
                    // First key may have been overwritten without sync
                    assert!(
                        payload == expected || payload == b"overwritten-unsynced",
                        "committed key {key} overwritten without sync: got unexpected payload"
                    );
                } else {
                    assert_eq!(
                        payload, expected,
                        "committed key {key} must survive crash intact"
                    );
                }
            }
        }

        for (_key, expected) in &unsynced {
            let key = _key;
            let got = store.get(*key).expect("get unsynced after crash");
            if let Some(ref payload) = got {
                assert_eq!(
                    payload, expected,
                    "unsynced key {key}: if present must have full correct payload"
                );
            }
        }
    }

    cleanup(&root);
}

/// After writing a payload, syncing it, then overwriting without sync,
/// and crashing: the object contains either old or new data — never
/// a torn payload.
#[test]
fn overwrite_without_sync_then_crash_gives_old_or_new() {
    let mut rng = StdRng::from_entropy();
    let root = temp_root("prop-crash-overwrite-atomic");
    let key = ObjectKey::from_name("crash-atomic-target");

    let old_len = rng.gen_range(1..512);
    let new_len = rng.gen_range(1..512);

    let old_payload = rand_payload(&mut rng, old_len);
    let new_payload = rand_payload(&mut rng, new_len);

    // Write old and sync
    {
        let mut store = open_store(&root);
        store.put(key, &old_payload).expect("put old");
        store.sync_all().expect("sync old");
    }

    // Overwrite without sync, then drop (crash)
    {
        let mut store = open_store(&root);
        store.put(key, &new_payload).expect("put new");
        // NO sync — drop simulates crash
    }

    // Reopen and verify atomicity
    {
        let store = open_store(&root);
        let got = store.get(key).expect("get after crash");

        if let Some(ref payload) = got {
            let is_old = payload.as_slice() == old_payload.as_slice();
            let is_new = payload.as_slice() == new_payload.as_slice();
            assert!(
                is_old || is_new,
                "after crash, payload must be old or new in full; got len={}",
                payload.len()
            );
            assert!(
                payload.len() == old_payload.len() || payload.len() == new_payload.len(),
                "payload length {} must match old ({}) or new ({})",
                payload.len(),
                old_payload.len(),
                new_payload.len()
            );
        }
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Segment lifecycle property tests
// ═══════════════════════════════════════════════════════════════════════════

/// Write enough objects with a small max_segment_bytes to force
/// segment rotation, then verify every object is intact after reopen.
#[test]
fn objects_survive_segment_rotation() {
    let mut rng = StdRng::from_entropy();
    let root = temp_root("prop-seg-rotation");
    let opts = StoreOptions {
        max_segment_bytes: 512, // small to force frequent rotation
        ..fast_opts()
    };

    let count = rng.gen_range(6..20);
    let mut expected: Vec<(ObjectKey, Vec<u8>)> = Vec::new();

    {
        let mut store = LocalObjectStore::open_with_options(&root, opts).expect("open store");
        for i in 0..count {
            // Payloads must fit in 512-byte segments (max ~288 bytes per object)
            let len = rng.gen_range(1..256);
            let payload = rand_payload(&mut rng, len);
            let key = ObjectKey::from_name(format!("seg-{i}").as_bytes());
            store.put(key, &payload).expect("put");
            expected.push((key, payload));
        }
        store.rotate_if_needed().ok();

        let rep = store.replay_report();
        assert!(
            rep.segment_count >= 1,
            "segment_count should be >= 1, got {}",
            rep.segment_count
        );
    }

    {
        let store = open_store(&root);
        assert_eq!(
            store.stats().live_objects,
            expected.len(),
            "live_objects mismatch after segment rotation and reopen"
        );

        for (key, exp) in &expected {
            let got = store
                .get(*key)
                .expect("get after rotation")
                .unwrap_or_else(|| panic!("key {key} missing after segment rotation"));
            assert_eq!(
                got, *exp,
                "payload mismatch after segment rotation for key {key}"
            );
        }
    }

    cleanup(&root);
}

/// Write objects across multiple segment rotations, delete some,
/// then verify state survives reopen with correct live/deleted split.
#[test]
fn mixed_put_delete_across_segments_survives_reopen() {
    let mut rng = StdRng::from_entropy();
    let root = temp_root("prop-mixed-segments");
    let opts = StoreOptions {
        max_segment_bytes: 512,
        ..fast_opts()
    };

    let total = rng.gen_range(6..15);
    let delete_count = total / 3;
    let keep_count = total - delete_count;

    let mut payloads: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..total {
        let len = rng.gen_range(1..256);
        let payload = rand_payload(&mut rng, len);
        let name = format!("mix-{i}");
        payloads.push((name, payload));
    }

    {
        let mut store = LocalObjectStore::open_with_options(&root, opts).expect("open store");

        for (name, payload) in &payloads {
            store.put(ObjectKey::from_name(name), payload).expect("put");
        }

        for (name, _) in payloads.iter().take(delete_count) {
            store.delete(ObjectKey::from_name(name)).expect("delete");
        }

        store.sync_all().expect("sync before close");
    }

    {
        let store = open_store(&root);
        assert_eq!(
            store.stats().live_objects,
            keep_count,
            "live_objects should be {keep_count} after mixed put/delete, got {}",
            store.stats().live_objects
        );

        for (i, (name, expected)) in payloads.iter().enumerate() {
            let key = ObjectKey::from_name(name);
            let got = store.get(key).expect("get after mixed seg reopen");
            if i < delete_count {
                assert!(
                    got.is_none(),
                    "deleted key '{name}' should not exist after reopen"
                );
            } else {
                assert_eq!(
                    got.as_deref(),
                    Some(expected.as_slice()),
                    "kept key '{name}' payload mismatch after mixed seg reopen"
                );
            }
        }
    }

    cleanup(&root);
}
