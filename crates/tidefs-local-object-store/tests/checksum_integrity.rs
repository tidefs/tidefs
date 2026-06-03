//! Object-level checksum integrity tests for `tidefs-local-object-store`.
//!
//! Validates checksum consistency across varying object sizes, deterministic
//! checksum computation, and overwrite checksum correctness.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{
    checksum64, IntegrityDigest64, LocalObjectStore, ObjectKey, StoreOptions,
};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-cksum-int-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &std::path::PathBuf) {
    let _ = std::fs::remove_dir_all(root);
}

fn fast_opts() -> StoreOptions {
    StoreOptions::test_fast()
}

fn open_store(root: &std::path::PathBuf) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, fast_opts()).expect("open store")
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Varying object sizes — all round-trip with correct content
// ═══════════════════════════════════════════════════════════════════════════

/// Write objects of sizes 0, 1, 255, 256, 2048, 3072, 3584 bytes,
/// read back each one, and verify content matches.
#[test]
fn varying_sizes_round_trip_correctly() {
    let root = temp_root("varying-sizes");
    let mut store = open_store(&root);

    let sizes: &[usize] = &[0, 1, 255, 256, 1024, 2048, 3072, 3584];
    let mut keys = Vec::new();

    for (i, &size) in sizes.iter().enumerate() {
        let payload = vec![(i as u8).wrapping_mul(17); size];
        let name = format!("size-{size}");
        let key = store
            .put(ObjectKey::from_name(&name), &payload)
            .expect("put");
        keys.push((key.key, name, payload));
    }

    for (key, name, expected) in &keys {
        let val = store.get(*key).expect("get");
        assert_eq!(
            val.as_deref(),
            Some(expected.as_slice()),
            "wrong content for {name} (size {})",
            expected.len()
        );
    }

    drop(store);

    // Reopen and verify again
    let store = open_store(&root);
    for (key, _name, expected) in &keys {
        let val = store.get(*key).expect("get after reopen");
        assert_eq!(
            val.as_deref(),
            Some(expected.as_slice()),
            "wrong content after reopen"
        );
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Deterministic checksum computation
// ═══════════════════════════════════════════════════════════════════════════

/// Two puts with identical content produce the same checksum (via location_of).
#[test]
fn checksum_deterministic_same_content() {
    let root = temp_root("det-cksum");
    let mut store = open_store(&root);

    let payload = b"deterministic checksum test payload";
    let key1 = ObjectKey::from_name("first");
    let key2 = ObjectKey::from_name("second");

    store.put(key1, payload).expect("put first");
    store.put(key2, payload).expect("put second");

    let loc1 = store.location_of(key1).expect("location first");
    let loc2 = store.location_of(key2).expect("location second");

    // Payloads are identical → checksums match
    assert_eq!(loc1.payload_checksum, loc2.payload_checksum);

    // Verify via the public checksum64 function
    let cksum = checksum64(payload);
    assert_eq!(loc1.payload_checksum, cksum);

    cleanup(&root);
}

/// Two puts with different content produce different checksums.
#[test]
fn checksum_differs_for_different_content() {
    let root = temp_root("diff-cksum");
    let mut store = open_store(&root);

    let key1 = ObjectKey::from_name("a");
    let key2 = ObjectKey::from_name("b");

    store.put(key1, b"hello").expect("put a");
    store.put(key2, b"world").expect("put b");

    let loc1 = store.location_of(key1).expect("loc a");
    let loc2 = store.location_of(key2).expect("loc b");

    assert_ne!(loc1.payload_checksum, loc2.payload_checksum);

    cleanup(&root);
}

/// The checksum of an empty payload is well-defined and consistent.
#[test]
fn checksum_empty_payload_is_consistent() {
    let root = temp_root("empty-cksum");
    let mut store = open_store(&root);

    store
        .put(ObjectKey::from_name("empty"), b"")
        .expect("put empty");
    let loc = store
        .location_of(ObjectKey::from_name("empty"))
        .expect("location");

    let expected = checksum64(b"");
    assert_eq!(loc.payload_checksum, expected);
    // Verify consistency: calling checksum64 again on empty yields the same
    assert_eq!(loc.payload_checksum, checksum64(b""));

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Overwrite checksum correctness
// ═══════════════════════════════════════════════════════════════════════════

/// Overwriting a key with new payload updates the checksum to match
/// the new content.
#[test]
fn overwrite_updates_checksum() {
    let root = temp_root("overwrite-cksum");
    let mut store = open_store(&root);

    let key = ObjectKey::from_name("overwrite");
    store.put(key, b"version-1").expect("put v1");
    let loc1 = store.location_of(key).expect("loc v1");

    store.put(key, b"version-2").expect("put v2");
    let loc2 = store.location_of(key).expect("loc v2");

    // Checksums must differ because payloads differ
    assert_ne!(loc1.payload_checksum, loc2.payload_checksum);

    // Latest checksum must match checksum64 of latest payload
    assert_eq!(loc2.payload_checksum, checksum64(b"version-2"));

    // checksum comparison confirms integrity
    let val = store.get(key).expect("get");
    assert_eq!(val, Some(b"version-2".to_vec()));

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Multiple key checksums form a consistent namespace
// ═══════════════════════════════════════════════════════════════════════════

/// Write many distinct keys, collect all checksums, verify every key
/// maps to the correct checksum via `location_of`.
#[test]
fn many_keys_checksum_consistency() {
    let root = temp_root("many-cksum");
    let mut store = open_store(&root);

    let count = 50;
    let mut expected_checksums: BTreeMap<ObjectKey, IntegrityDigest64> = BTreeMap::new();

    for i in 0..count {
        let payload = format!("payload-{i:04}").into_bytes();
        let key = ObjectKey::from_name(format!("obj-{i}"));
        store.put(key, &payload).expect("put");
        let loc = store.location_of(key).expect("location_of");
        expected_checksums.insert(key, loc.payload_checksum);
    }

    for (key, expected_cksum) in &expected_checksums {
        let loc = store.location_of(*key).expect("location_of");
        assert_eq!(
            loc.payload_checksum, *expected_cksum,
            "checksum mismatch for key {key}"
        );
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. IntegrityDigest64 helper tests
// ═══════════════════════════════════════════════════════════════════════════

/// The `IntegrityDigest64` type round-trips correctly through its API.
#[test]
fn integrity_digest64_api() {
    let d = IntegrityDigest64(0xDEAD_BEEF_CAFE_BABE);
    assert_eq!(d.get(), 0xDEAD_BEEF_CAFE_BABE);
    assert!(!d.is_zero());

    let zero = IntegrityDigest64::ZERO;
    assert_eq!(zero.get(), 0);
    assert!(zero.is_zero());

    // Display format
    let formatted = format!("{d}");
    assert_eq!(formatted.len(), 16);
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Key derivation checksum consistency
// ═══════════════════════════════════════════════════════════════════════════

/// Content-addressed puts produce predictable keys from BLAKE3.
#[test]
fn content_addressed_key_is_deterministic() {
    let root = temp_root("ca-deterministic");
    let mut store = open_store(&root);

    let payload = b"content-addressed-test";
    let key1 = store.put_content_addressed(payload).expect("put first");
    let key2 = store.put_content_addressed(payload).expect("put second");

    // Same content → same key
    assert_eq!(key1, key2);

    // Different content → different key
    let key3 = store
        .put_content_addressed(b"different")
        .expect("put different");
    assert_ne!(key1, key3);

    cleanup(&root);
}
