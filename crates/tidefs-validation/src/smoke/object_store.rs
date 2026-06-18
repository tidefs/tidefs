// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Object-store smoke: deterministic sequence of put, get, delete, and list
//! operations against `LocalObjectStore`.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_local_object_store::ObjectKey;

/// Run the full object-store smoke sequence and return the harness.
#[must_use]
pub fn run_object_store_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("object-store/smoke");

    // Build a temporary store.
    let dir = tempfile::TempDir::new().expect("tempdir for object-store smoke");
    let root_path = dir.path().to_path_buf();

    let mut store = tidefs_local_object_store::LocalObjectStore::open(&root_path)
        .expect("open local object store");

    // Put an object.
    let key = ObjectKey::from_bytes32([1u8; 32]);
    let value: Vec<u8> = b"hello-object-store".to_vec();

    h.record(TraceEvent::ObjectPut {
        key_bytes: key.as_bytes().to_vec(),
        value: value.clone(),
    });
    let _stored = store
        .put(key, &value)
        .expect("object-store put should succeed");

    // Get it back.
    h.record(TraceEvent::ObjectGet {
        key_bytes: key.as_bytes().to_vec(),
    });
    let got = store.get(key).expect("object-store get should succeed");
    h.assert_ev("object-store get returns Some", got.is_some());
    h.assert_eq_ev("object-store get round-trip", got.unwrap(), value);

    // List keys.
    h.record(TraceEvent::ObjectScan {
        start_key: Some(key.as_bytes().to_vec()),
        limit: 10,
    });
    let keys = store.list_keys();
    h.assert_ev("list_keys contains put key", keys.contains(&key));

    // Delete.
    h.record(TraceEvent::ObjectDelete {
        key_bytes: key.as_bytes().to_vec(),
    });
    let deleted = store
        .delete(key)
        .expect("object-store delete should succeed");
    h.assert_ev("delete returns true", deleted);

    // Get after delete returns None.
    let after_del = store
        .get(key)
        .expect("get after delete should succeed (returns None)");
    h.assert_ev("object-store get after delete is None", after_del.is_none());

    // List after delete confirms absent.
    h.record(TraceEvent::ObjectScan {
        start_key: Some(key.as_bytes().to_vec()),
        limit: 10,
    });
    let keys2 = store.list_keys();
    h.assert_ev(
        "list_keys after delete does not contain key",
        !keys2.contains(&key),
    );

    drop(store);
    dir.close().ok();

    h.scenario_end("object-store/smoke");
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_store_smoke_passes() {
        let h = run_object_store_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert {
                passed,
                ref condition,
            } = event
            {
                assert!(passed, "assertion failed: {condition}");
            }
        }
    }
}
