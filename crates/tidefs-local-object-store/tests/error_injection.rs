//! Error-injection and error-path integration tests for `tidefs-local-object-store`.
//!
//! Validates that error conditions are surfaced correctly: payload too large,
//! read-only store rejects mutations, invalid options, and corrupt state.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{
    LocalObjectStore, ObjectKey, ObjectReadError, StoreError, StoreOptions,
};

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-error-injection-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

// ---------------------------------------------------------------------------
// PayloadTooLarge
// ---------------------------------------------------------------------------

/// Writing a payload larger than `max_object_bytes()` must fail with
/// `PayloadTooLarge`. `test_fast()` uses 4096-byte segments, so the
/// max object size (after overhead) is less than that.
#[test]
fn put_payload_too_large_is_rejected() {
    let root = temp_root("payload-too-large");
    let opts = StoreOptions::test_fast();
    // max_object_bytes is max_segment_bytes minus record overhead (~4KB minus ~300)
    let max_obj = opts.max_object_bytes();
    assert!(max_obj > 0, "max_object_bytes must be positive");

    let mut store = LocalObjectStore::open_with_options(&root, opts).expect("open store");

    let huge = vec![0xAA; (max_obj + 1) as usize];
    let result = store.put(ObjectKey::from_name(b"too-big"), &huge);
    match result {
        Err(StoreError::PayloadTooLarge { len, max: reported }) => {
            assert_eq!(len, max_obj + 1);
            assert_eq!(reported, max_obj);
        }
        Ok(_) => panic!("put with oversized payload should have failed"),
        Err(other) => panic!("expected PayloadTooLarge, got {other:?}"),
    }

    // Small payload still works
    store
        .put(ObjectKey::from_name(b"just-right"), b"ok")
        .expect("put small payload should succeed");

    cleanup(&root);
}

/// A zero-length payload is valid (empty object).
#[test]
fn put_zero_length_payload_is_valid() {
    let root = temp_root("zero-length");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let key = ObjectKey::from_name(b"empty-object");
    store.put(key, b"").expect("put empty payload");

    let read = store.get(key).expect("get empty").expect("must exist");
    assert!(read.is_empty(), "empty payload must be empty on read");

    let attr = store.get_attr(&key).expect("get_attr empty");
    assert_eq!(attr.size, 0);

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Read-only store rejects mutating operations
// ---------------------------------------------------------------------------

/// A store opened read-only must reject `put`, `delete`, `put_named`,
/// and `put_content_addressed`.
#[test]
fn read_only_store_rejects_writes() {
    let root = temp_root("read-only-rejects");
    let existing_key;
    {
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        existing_key = ObjectKey::from_name(b"existing");
        store.put(existing_key, b"stable").expect("put stable");
        store.sync_all().expect("sync store");
    }

    let mut ro = LocalObjectStore::open_read_only_with_options(&root, StoreOptions::test_fast())
        .expect("open read-only")
        .expect("existing store");

    // Reads still work
    assert_eq!(
        ro.get(existing_key).expect("read in ro"),
        Some(b"stable".to_vec())
    );

    // put rejected
    assert!(matches!(
        ro.put(ObjectKey::from_name(b"new"), b"nope"),
        Err(StoreError::ReadOnly { .. })
    ));

    // put_named rejected
    assert!(matches!(
        ro.put_named("new-named", b"nope"),
        Err(StoreError::ReadOnly { .. })
    ));

    // put_content_addressed rejected
    assert!(matches!(
        ro.put_content_addressed(b"nope"),
        Err(StoreError::ReadOnly { .. })
    ));

    // delete rejected
    assert!(matches!(
        ro.delete(existing_key),
        Err(StoreError::ReadOnly { .. })
    ));

    // Existing data still intact after rejected mutations
    assert_eq!(
        ro.get(existing_key).expect("read after rejected puts"),
        Some(b"stable".to_vec())
    );

    cleanup(&root);
}

/// read-only open on a nonexistent directory returns `None`.
#[test]
fn read_only_open_missing_store_returns_none() {
    let root = temp_root("read-only-missing");
    let store = LocalObjectStore::open_read_only_with_options(&root, StoreOptions::test_fast())
        .expect("read-only open");
    assert!(store.is_none(), "missing store must return None");
    assert!(
        !root.exists(),
        "store dir must not be created for read-only open"
    );
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Invalid options
// ---------------------------------------------------------------------------

/// `max_segment_bytes` below `MIN_SEGMENT_BYTES` is rejected.
#[test]
fn invalid_max_segment_bytes_is_rejected() {
    let root = temp_root("invalid-max-segment");
    let opts = StoreOptions {
        max_segment_bytes: 1,
        ..StoreOptions::test_fast()
    };
    let result = LocalObjectStore::open_with_options(&root, opts);
    assert!(matches!(result, Err(StoreError::InvalidOptions { .. })));
    cleanup(&root);
}

/// `segment_count` of zero is rejected.
#[test]
fn zero_segment_count_is_rejected() {
    let root = temp_root("zero-segments");
    let opts = StoreOptions {
        segment_count: 0,
        ..StoreOptions::test_fast()
    };
    let result = LocalObjectStore::open_with_options(&root, opts);
    assert!(matches!(result, Err(StoreError::InvalidOptions { .. })));
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// get_attr on nonexistent key
// ---------------------------------------------------------------------------

/// `get_attr` returns `ObjectReadError::NotFound` for a key not in the store.
#[test]
fn get_attr_nonexistent_returns_not_found() {
    let root = temp_root("attr-not-found");
    let store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let bogus = ObjectKey::from_name(b"no-such-key");
    let result = store.get_attr(&bogus);
    match result {
        Err(ObjectReadError::NotFound { key }) => {
            assert_eq!(key, bogus);
        }
        Ok(_) => panic!("get_attr on nonexistent key should fail"),
        Err(other) => panic!("expected NotFound, got {other:?}"),
    }

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Multi-write then reopen: integrity survives
// ---------------------------------------------------------------------------

/// Write many objects, reopen, verify all are intact.
#[test]
fn many_writes_survive_reopen_with_integrity() {
    let root = temp_root("many-writes");
    let count = 50;
    {
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        for i in 0..count {
            let key = ObjectKey::from_name(format!("obj-{i:04}").as_bytes());
            let payload = format!("payload for object {i:04}");
            store.put(key, payload.as_bytes()).expect("put object");
        }
        store.sync_all().expect("sync store");
    }
    {
        let store =
            LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("reopen");
        let stats = store.stats();
        assert_eq!(stats.live_objects, count as usize);
        for i in 0..count {
            let key = ObjectKey::from_name(format!("obj-{i:04}").as_bytes());
            let expected = format!("payload for object {i:04}");
            let read = store
                .get(key)
                .expect("get")
                .unwrap_or_else(|| panic!("object {i} should exist"));
            assert_eq!(
                read,
                expected.as_bytes(),
                "object {i}: payload mismatch after reopen"
            );
        }
    }
    cleanup(&root);
}

/// Content-addressed put + get_verified on many objects.
#[test]
fn many_content_addressed_objects_survive_reopen() {
    let root = temp_root("many-ca");
    let count = 30;
    let mut keys_and_payloads = Vec::new();
    {
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        for i in 0..count {
            let payload = format!("content-addressed payload {i:04}").into_bytes();
            let key = store
                .put_content_addressed(&payload)
                .expect("put ca object");
            keys_and_payloads.push((key, payload));
        }
        store.sync_all().expect("sync store");
    }
    {
        let store =
            LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("reopen");
        for (key, expected) in &keys_and_payloads {
            let verified = store
                .get_verified(*key)
                .expect("get_verified")
                .unwrap_or_else(|| panic!("key {key} should exist"));
            assert_eq!(&verified, expected, "content-addressed payload mismatch");
        }
    }
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// get_range edge cases
// ---------------------------------------------------------------------------

/// `get_range` with offset 0 and full length returns the complete object.
#[test]
fn get_range_full_object() {
    let root = temp_root("range-full");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let payload = b"get_range full object test payload";
    let key = ObjectKey::from_name(b"range-target");
    store.put(key, payload).expect("put object");

    let range = store
        .get_range(key, 0, payload.len() as u64)
        .expect("get_range")
        .expect("range should exist");
    assert_eq!(&range[..], &payload[..]);

    cleanup(&root);
}

/// `get_range` with offset past EOF returns empty.
#[test]
fn get_range_past_eof_returns_empty() {
    let root = temp_root("range-past-eof");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let key = ObjectKey::from_name(b"short-object");
    store.put(key, b"hi").expect("put short");

    let range = store
        .get_range(key, 100, 10)
        .expect("get_range past eof")
        .expect("range should exist but be empty");
    assert!(range.is_empty(), "past-eof range must be empty");

    cleanup(&root);
}

/// `get_range` extending past EOF returns available suffix.
#[test]
fn get_range_partial_past_eof_truncates() {
    let root = temp_root("range-truncate");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let payload = b"1234567890";
    let key = ObjectKey::from_name(b"ten-bytes");
    store.put(key, payload).expect("put object");

    // Request 5 bytes starting at offset 7 (only 3 bytes available)
    let range = store
        .get_range(key, 7, 5)
        .expect("get_range")
        .expect("range should exist");
    assert_eq!(&range[..], b"890");

    cleanup(&root);
}

/// `get_range` on nonexistent key returns `None`.
#[test]
fn get_range_nonexistent_returns_none() {
    let root = temp_root("range-nonexistent");
    let store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let bogus = ObjectKey::from_name(b"not-there");
    let result = store
        .get_range(bogus, 0, 1)
        .expect("get_range on unknown key");
    assert!(result.is_none());

    cleanup(&root);
}
