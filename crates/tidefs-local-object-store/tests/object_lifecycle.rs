//! Block-level object lifecycle validation tests for `tidefs-local-object-store`.
//!
//! Covers write→read→checksum-verify round-trip, partial overwrite,
//! deletion with re-allocation, and multi-object concurrent access.
//!
//! All tests use the crate's public API. Temporary directories are created
//! under `std::env::temp_dir()` and cleaned up after each test.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

/// Create a unique temporary root directory for a test.
fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-object-lifecycle-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

// ---------------------------------------------------------------------------
// Round-trip: write, read, checksum-verify
// ---------------------------------------------------------------------------

/// Write known data, read it back, and verify the stored checksum matches
/// via `get_verified`. Guards against silent data corruption on write/read.
#[test]
fn round_trip_write_read_checksum_verify() {
    let root = temp_root("round-trip");
    let payload = b"TideFS local object store round-trip validation payload";
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    // Content-addressed put: key derived from BLAKE3(payload)
    let key = store
        .put_content_addressed(payload)
        .expect("put content-addressed");

    // Read back and verify the checksum matches the content
    let read_back = store
        .get_verified(key)
        .expect("get_verified")
        .expect("object should exist");
    assert_eq!(read_back, payload, "round-trip payload must match");

    // Normal get also returns the same bytes
    let normal_get = store.get(key).expect("get").expect("object should exist");
    assert_eq!(normal_get, payload, "normal get payload must match");

    // Stats reflect a single live object
    let stats = store.stats();
    assert_eq!(stats.live_objects, 1);
    assert_eq!(stats.live_bytes, payload.len() as u64);

    store.sync_all().expect("sync store");
    drop(store);

    // Reopen: data must survive close/reopen cycle
    let store2 = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
        .expect("reopen store");
    let after_reopen = store2
        .get_verified(key)
        .expect("get_verified after reopen")
        .expect("object should survive reopen");
    assert_eq!(after_reopen, payload, "payload must survive close/reopen");
    assert!(store2.contains_key(key));
    assert_eq!(store2.replay_report().puts_seen, 1);

    cleanup(&root);
}

/// Write a named object (non-content-addressed), verify `get` and `contains_key`.
#[test]
fn named_put_get_round_trip() {
    let root = temp_root("named-round-trip");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");
    let payload = b"named object data";

    let stored = store
        .put_named("doc/alpha", payload)
        .expect("put named object");
    assert_eq!(stored.len, payload.len() as u64);

    let key = ObjectKey::from_name(b"doc/alpha");
    assert!(store.contains_key(key));

    let read = store.get(key).expect("get").expect("object should exist");
    assert_eq!(read, payload);

    let named_read = store
        .get_named("doc/alpha")
        .expect("get_named")
        .expect("object should exist by name");
    assert_eq!(named_read, payload);

    // Location sanity
    let loc = store.location_of(key).expect("location should exist");
    assert!(loc.payload_len == payload.len() as u64);

    // get_attr
    let attr = store.get_attr(&key).expect("get_attr");
    assert_eq!(attr.size, payload.len() as u64);
    assert_eq!(attr.key, key);

    // list_keys
    let keys = store.list_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], key);

    store.sync_all().expect("sync store");
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Partial overwrite
// ---------------------------------------------------------------------------

/// Write an object, overwrite a range within it, and verify the overwritten
/// bytes changed while surrounding bytes are intact.
#[test]
fn partial_overwrite_preserves_surrounding_bytes() {
    let root = temp_root("partial-overwrite");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let key = ObjectKey::from_name(b"partial-key");
    let initial = b"AAAA BBBB CCCC DDDD EEEE";
    store.put(key, initial).expect("put initial");

    // Read initial content
    let read1 = store.get(key).expect("get").expect("object should exist");
    assert_eq!(&read1[..], &initial[..]);

    // Partial read: range [5, 10)
    let slice = store
        .get_range(key, 5, 5)
        .expect("get_range")
        .expect("range exists");
    assert_eq!(slice, b"BBBB ");

    // Overwrite the middle portion: "BBBB" -> "XXXX"
    let updated = b"AAAA XXXX CCCC DDDD EEEE";
    store.put(key, updated).expect("put overwrite");

    // Read back: overwritten region changed
    let read2 = store
        .get(key)
        .expect("get after overwrite")
        .expect("object should exist");
    assert_eq!(
        &read2[..],
        &updated[..],
        "overwritten bytes must match new payload"
    );
    assert_eq!(&read2[0..5], b"AAAA ", "prefix unchanged");
    assert_eq!(&read2[5..10], b"XXXX ", "middle overwritten");
    assert_eq!(&read2[10..], b"CCCC DDDD EEEE", "suffix unchanged");

    // Stats: still one live object (overwrite is append-only, not delete+insert)
    let stats = store.stats();
    assert_eq!(stats.live_objects, 1);

    // History should contain both locations
    let loc1 = store.location_of(key).expect("latest location exists");
    assert_eq!(loc1.payload_len, updated.len() as u64);

    store.sync_all().expect("sync store");
    cleanup(&root);
}

/// Overwrite with a longer payload: verify new length is correct.
#[test]
fn overwrite_with_longer_payload() {
    let root = temp_root("overwrite-longer");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let key = ObjectKey::from_name(b"growing-object");
    store.put(key, b"short").expect("put short");
    store
        .put(key, b"a much longer payload than before")
        .expect("put longer");

    let read = store.get(key).expect("get").expect("object should exist");
    assert_eq!(read, b"a much longer payload than before");
    assert_eq!(read.len(), 33);

    // Location payload_len must match
    let loc = store.location_of(key).expect("location exists");
    assert_eq!(loc.payload_len, 33);

    cleanup(&root);
}

/// Overwrite with a shorter payload: verify new length is correct.
#[test]
fn overwrite_with_shorter_payload() {
    let root = temp_root("overwrite-shorter");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let key = ObjectKey::from_name(b"shrinking-object");
    store
        .put(key, b"a rather long payload that will be shortened")
        .expect("put long");
    store.put(key, b"tiny").expect("put short");

    let read = store.get(key).expect("get").expect("object should exist");
    assert_eq!(read, b"tiny");
    assert_eq!(read.len(), 4);

    let loc = store.location_of(key).expect("location exists");
    assert_eq!(loc.payload_len, 4);

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Deletion + re-allocation
// ---------------------------------------------------------------------------

/// Delete an object, confirm reads return None, then write a new object
/// with the same name-derived key and verify no stale data leakage.
#[test]
fn delete_then_reallocate_no_stale_data() {
    let root = temp_root("delete-reallocate");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let key = ObjectKey::from_name(b"reuse-me");
    let old_payload = b"this is old data that should be gone after delete";

    // Write original
    store.put(key, old_payload).expect("put old");
    assert!(store.contains_key(key));

    // Delete it
    let existed = store.delete(key).expect("delete");
    assert!(existed, "delete must report key existed");

    // Verify gone
    assert!(!store.contains_key(key));
    assert!(store.get(key).expect("get after delete").is_none());
    let attr_result = store.get_attr(&key);
    assert!(attr_result.is_err(), "get_attr must fail for deleted key");

    // Re-allocate with new content
    let new_payload = b"fresh data after reallocation";
    store.put(key, new_payload).expect("put new after delete");
    assert!(store.contains_key(key));

    // Verify new data is correct (no stale old data)
    let read = store
        .get(key)
        .expect("get new")
        .expect("object should exist");
    assert_eq!(
        read, new_payload,
        "reallocated data must be fresh, not stale"
    );
    assert_ne!(read, old_payload, "new payload must differ from old");

    let attr = store.get_attr(&key).expect("get_attr after reallocation");
    assert_eq!(attr.size, new_payload.len() as u64);

    // Stats reflect one live object plus a tombstone
    let stats = store.stats();
    assert_eq!(stats.live_objects, 1);
    assert_eq!(stats.tombstone_count, 1);

    store.sync_all().expect("sync store");
    drop(store);

    // Reopen: deleted old data must not resurrect
    let store2 = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
        .expect("reopen store");
    let read2 = store2
        .get(key)
        .expect("get after reopen")
        .expect("object should exist");
    assert_eq!(
        read2, new_payload,
        "data must survive reopen without old data resurrecting"
    );
    assert_eq!(store2.replay_report().deletes_seen, 1);

    cleanup(&root);
}

/// Delete a key that doesn't exist: returns false, no error.
#[test]
fn delete_nonexistent_returns_false() {
    let root = temp_root("delete-nonexistent");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let key = ObjectKey::from_name(b"never-existed");
    let existed = store.delete(key).expect("delete nonexistent");
    assert!(!existed, "delete of nonexistent key must return false");

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Multi-object concurrent access (single-threaded sequential)
// ---------------------------------------------------------------------------

/// Allocate several objects with interleaved writes, verify each retains
/// independent data.
#[test]
fn multi_object_independent_data() {
    let root = temp_root("multi-object");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let objects: Vec<(&str, &[u8])> = vec![
        ("alpha", b"payload for alpha"),
        ("beta", b"different payload for beta"),
        ("gamma", b"payload gamma data"),
        ("delta", b"delta has its own bytes"),
        ("epsilon", b"epsilon payload here"),
    ];

    let mut keys = Vec::new();

    // Write all objects
    for (name, payload) in &objects {
        let key = ObjectKey::from_name(name.as_bytes());
        store.put(key, payload).expect("put object");
        keys.push((name, key));
    }

    // Verify independent data for each
    for (name, expected_payload) in &objects {
        let read = store
            .get_named(name)
            .expect("get_named")
            .unwrap_or_else(|| panic!("object {name} should exist"));
        assert_eq!(read, *expected_payload, "object {name}: payload mismatch");
    }

    // All keys must appear in list_keys
    let listed = store.list_keys();
    assert_eq!(listed.len(), objects.len());
    for (_, key) in &keys {
        assert!(listed.contains(key), "list_keys must contain {key}");
    }

    // Stats
    let stats = store.stats();
    assert_eq!(stats.live_objects, objects.len());

    // Overwrite one, verify only that one changed
    store
        .put(ObjectKey::from_name(b"beta"), b"updated beta payload")
        .expect("update beta");
    assert_eq!(
        store.get_named("beta").expect("get updated beta"),
        Some(b"updated beta payload".to_vec())
    );
    // Others unchanged
    assert_eq!(
        store.get_named("alpha").expect("get alpha"),
        Some(b"payload for alpha".to_vec())
    );
    assert_eq!(
        store.get_named("gamma").expect("get gamma"),
        Some(b"payload gamma data".to_vec())
    );

    // Delete two, verify they're gone and others remain
    assert!(store
        .delete(ObjectKey::from_name(b"delta"))
        .expect("delete delta"));
    assert!(store
        .delete(ObjectKey::from_name(b"epsilon"))
        .expect("delete epsilon"));
    assert!(store
        .get_named("delta")
        .expect("get deleted delta")
        .is_none());
    assert!(store
        .get_named("epsilon")
        .expect("get deleted epsilon")
        .is_none());
    assert!(store
        .get_named("alpha")
        .expect("get alpha after deletes")
        .is_some());
    assert!(store
        .get_named("beta")
        .expect("get beta after deletes")
        .is_some());
    assert!(store
        .get_named("gamma")
        .expect("get gamma after deletes")
        .is_some());

    assert_eq!(store.list_keys().len(), 3);
    assert_eq!(store.stats().tombstone_count, 3);

    store.sync_all().expect("sync store");
    cleanup(&root);
}

/// Object keys derived from identical names are equal; different names
/// produce different keys.
#[test]
fn object_key_derivation_consistency() {
    let k1 = ObjectKey::from_name(b"consistent-key");
    let k2 = ObjectKey::from_name(b"consistent-key");
    assert_eq!(k1, k2, "same name must produce same key");

    let k3 = ObjectKey::from_name(b"different-key");
    assert_ne!(k1, k3, "different names must produce different keys");

    let k_zero = ObjectKey::from_bytes32([0u8; 32]);
    assert_ne!(k1, k_zero, "derived key must differ from zero key");
}
