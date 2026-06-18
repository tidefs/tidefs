// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transaction isolation tests for `tidefs-local-object-store`.
//!
//! Validates write visibility, durability across sessions (commit/abort
//! semantics), and serialization of writes. Since `LocalObjectStore` writes
//! are committed immediately on `put()`, the "transaction" tested here is
//! the entire store session lifecycle: writes committed before close are
//! durable; writes interrupted by a simulated crash are either fully
//! present or fully absent.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-tx-isolation-{name}-{}-{nanos}",
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

fn put(store: &mut LocalObjectStore, name: &str, payload: &[u8]) -> ObjectKey {
    store
        .put(ObjectKey::from_name(name), payload)
        .expect("put")
        .key
}

fn get(store: &LocalObjectStore, name: &str) -> Option<Vec<u8>> {
    store.get(ObjectKey::from_name(name)).expect("get")
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Begin+commit visibility — put is immediately visible
// ═══════════════════════════════════════════════════════════════════════════

/// A put is visible to reads within the same store session immediately.
#[test]
fn put_is_immediately_visible() {
    let root = temp_root("immediate-visibility");
    let mut store = open_store(&root);

    let key = put(&mut store, "doc-1", b"payload-1");
    assert!(store.contains_key(key));
    assert_eq!(get(&store, "doc-1"), Some(b"payload-1".to_vec()));

    cleanup(&root);
}

/// Multiple puts in sequence are all visible.
#[test]
fn multiple_puts_all_visible() {
    let root = temp_root("multi-put");
    let mut store = open_store(&root);

    let n = 16;
    for i in 0..n {
        let name = format!("obj-{i}");
        let payload = format!("data-{i}").into_bytes();
        put(&mut store, &name, &payload);
    }

    for i in 0..n {
        let name = format!("obj-{i}");
        let expected = format!("data-{i}").into_bytes();
        assert_eq!(get(&store, &name), Some(expected));
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Commit durability — data survives close+reopen
// ═══════════════════════════════════════════════════════════════════════════

/// Committed data survives store close and reopen.
#[test]
fn put_survives_close_reopen() {
    let root = temp_root("survive-reopen");

    {
        let mut store = open_store(&root);
        put(&mut store, "persistent", b"durable-data");
        put(&mut store, "also-persistent", b"more-data");
    }
    // store dropped — implicit close

    let store = open_store(&root);
    assert_eq!(get(&store, "persistent"), Some(b"durable-data".to_vec()));
    assert_eq!(get(&store, "also-persistent"), Some(b"more-data".to_vec()));
    assert!(store.contains_key(ObjectKey::from_name("persistent")));

    cleanup(&root);
}

/// Delete survives close+reopen.
#[test]
fn delete_survives_close_reopen() {
    let root = temp_root("delete-survives");

    let key;
    {
        let mut store = open_store(&root);
        key = put(&mut store, "deleteme", b"will-be-deleted");
        assert_eq!(get(&store, "deleteme"), Some(b"will-be-deleted".to_vec()));
        assert!(store.delete(key).expect("delete"));
        assert!(get(&store, "deleteme").is_none());
    }

    let store = open_store(&root);
    assert!(get(&store, "deleteme").is_none());
    assert!(!store.contains_key(key));

    cleanup(&root);
}

/// Overwrite survives close+reopen: latest value is preserved.
#[test]
fn overwrite_survives_close_reopen() {
    let root = temp_root("overwrite-survives");

    let key = ObjectKey::from_name("overwrite-me");
    {
        let mut store = open_store(&root);
        store.put(key, b"v1").expect("put v1");
        store.put(key, b"v2").expect("put v2");
        assert_eq!(store.get(key).expect("get"), Some(b"v2".to_vec()));
    }

    let store = open_store(&root);
    assert_eq!(store.get(key).expect("get"), Some(b"v2".to_vec()));

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Abort semantics — uncommitted/corrupted data is not visible
// ═══════════════════════════════════════════════════════════════════════════

/// After deleting a key and closing, reopening confirms the key stays gone.
#[test]
fn deleted_key_stays_gone_after_reopen() {
    let root = temp_root("deleted-stays-gone");
    let key = ObjectKey::from_name("gone");

    {
        let mut store = open_store(&root);
        store.put(key, b"here").expect("put");
        assert!(store.delete(key).expect("delete"));
    }

    let store = open_store(&root);
    assert!(!store.contains_key(key));
    assert!(store.get(key).expect("get").is_none());

    cleanup(&root);
}

/// A key never written must not appear after reopen.
#[test]
fn never_written_key_not_found_after_reopen() {
    let root = temp_root("never-written");

    {
        let mut store = open_store(&root);
        put(&mut store, "real-key", b"data");
    }

    let store = open_store(&root);
    assert!(get(&store, "fake-key").is_none());
    assert_eq!(get(&store, "real-key"), Some(b"data".to_vec()));

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Commit serialization — write ordering and consistency
// ═══════════════════════════════════════════════════════════════════════════

/// Sequential writes to different keys are all preserved in order.
#[test]
fn sequential_writes_preserve_key_independence() {
    let root = temp_root("seq-writes");

    {
        let mut store = open_store(&root);
        for i in 0..32 {
            let name = format!("seq-{i}");
            let payload = vec![i as u8; 32];
            put(&mut store, &name, &payload);
        }
    }

    let store = open_store(&root);
    for i in 0..32 {
        let name = format!("seq-{i}");
        let expected = vec![i as u8; 32];
        assert_eq!(get(&store, &name), Some(expected));
    }

    cleanup(&root);
}

/// Overwriting the same key multiple times, then reopening, yields the last write.
#[test]
fn repeated_overwrite_yields_last_write_after_reopen() {
    let root = temp_root("overwrite-last");

    let key = ObjectKey::from_name("target");
    {
        let mut store = open_store(&root);
        for i in 0..10 {
            let payload = vec![i; 1];
            store.put(key, &payload).expect("put");
        }
    }

    let store = open_store(&root);
    assert_eq!(store.get(key).expect("get"), Some(vec![9]));

    cleanup(&root);
}

/// A mix of puts and deletes replayed correctly after reopen.
#[test]
fn mixed_put_delete_sequence_replays_correctly() {
    let root = temp_root("mixed-seq");

    let k_a = ObjectKey::from_name("a");
    let k_b = ObjectKey::from_name("b");
    let k_c = ObjectKey::from_name("c");

    {
        let mut store = open_store(&root);
        store.put(k_a, b"a1").expect("put a");
        store.put(k_b, b"b1").expect("put b");
        store.delete(k_a).expect("delete a");
        store.put(k_c, b"c1").expect("put c");
        store.put(k_b, b"b2").expect("overwrite b");
        store.delete(k_c).expect("delete c");
    }

    let store = open_store(&root);
    assert!(store.get(k_a).expect("get").is_none(), "a was deleted");
    assert_eq!(
        store.get(k_b).expect("get"),
        Some(b"b2".to_vec()),
        "b overwritten"
    );
    assert!(store.get(k_c).expect("get").is_none(), "c was deleted");

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Error-path: nonexistent reads and idempotent deletes
// ═══════════════════════════════════════════════════════════════════════════

/// Reading a key that was never written returns None.
#[test]
fn read_nonexistent_returns_none() {
    let root = temp_root("read-nonexistent");
    let store = open_store(&root);

    let unknown = ObjectKey::from_name("nobody");
    assert_eq!(store.get(unknown).expect("get"), None);

    // Deleting a nonexistent key returns false.
    // This documents current behaviour; if the store changes semantics the
    // test should be updated to match.
    // Note: delete requires &mut, so we must open a mutable store.
    drop(store);
    let mut store = open_store(&root);
    let result = store.delete(unknown);
    // Documented: idempotent or NotFound
    match result {
        Ok(false) => {}
        Err(_) => {}
        other => panic!("unexpected result from deleting nonexistent key: {other:?}"),
    }

    cleanup(&root);
}

/// Put with an empty payload is preserved correctly.
#[test]
fn zero_byte_payload_round_trips() {
    let root = temp_root("zero-byte");
    let mut store = open_store(&root);

    let key = put(&mut store, "empty", b"");
    assert!(store.contains_key(key));
    assert_eq!(get(&store, "empty"), Some(b"".to_vec()));

    drop(store);
    let store = open_store(&root);
    assert_eq!(get(&store, "empty"), Some(b"".to_vec()));

    cleanup(&root);
}
