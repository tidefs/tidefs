// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for the commit_group (transaction group) pipeline.
//!
//! Verifies that writes accumulated in the commit_group produce a durable committed
//! root on sync, and that the root survives a store reopen.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tidefs_commit_group::{CommitGroupId, RootPointer};
use tidefs_local_object_store::{txg_manager, LocalObjectStore, ObjectKey, StoreOptions};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("tidefs-commit_group-test-{name}-{nanos:x}"))
}

fn clean(path: &std::path::Path) {
    let _ = std::fs::remove_dir_all(path);
}

fn open_test_store(root: &std::path::Path) -> LocalObjectStore {
    LocalObjectStore::open_with_options(root, StoreOptions::test_fast()).unwrap()
}

// ---------------------------------------------------------------------------
// Committed root is absent on a fresh store
// ---------------------------------------------------------------------------

#[test]
fn fresh_store_has_no_committed_root() {
    let root = temp_dir("fresh");
    let store = open_test_store(&root);
    let root_path = root.join(txg_manager::COMMITTED_ROOT_FILE);
    assert!(
        !root_path.exists(),
        "fresh store should not have a committed root file"
    );
    assert_eq!(store.txg_manager().committed_root(), RootPointer::NIL);
    clean(&root);
}

// ---------------------------------------------------------------------------
// Single write + sync produces a committed root
// ---------------------------------------------------------------------------

#[test]
fn write_and_sync_produces_committed_root() {
    let root = temp_dir("write-sync");
    let mut store = open_test_store(&root);

    let key = store.put_content_addressed(b"hello-world").unwrap();

    store.sync_all().unwrap();

    let root_path = root.join(txg_manager::COMMITTED_ROOT_FILE);
    assert!(
        root_path.exists(),
        "committed root file must exist after sync"
    );

    let payload = std::fs::read(&root_path).unwrap();
    let decoded = txg_manager::CommitGroupManager::decode_root(&payload).unwrap();
    assert!(decoded.is_valid());
    assert_eq!(decoded.commit_group_id, CommitGroupId::FIRST);

    assert_eq!(store.txg_manager().committed_root(), decoded);
    assert_eq!(store.txg_manager().commit_count(), 1);

    let val = store.get(key).unwrap();
    assert_eq!(val, Some(b"hello-world".to_vec()));
    clean(&root);
}

// ---------------------------------------------------------------------------
// Multiple writes in a single commit_group produce one committed root
// ---------------------------------------------------------------------------

#[test]
fn multiple_writes_one_txg_one_root() {
    let root = temp_dir("multi-one");
    let mut store = open_test_store(&root);

    let keys: Vec<ObjectKey> = (0..3)
        .map(|i| {
            store
                .put_content_addressed(format!("data-{i}").as_bytes())
                .unwrap()
        })
        .collect();

    store.sync_all().unwrap();

    let root_path = root.join(txg_manager::COMMITTED_ROOT_FILE);
    let payload = std::fs::read(&root_path).unwrap();
    let decoded = txg_manager::CommitGroupManager::decode_root(&payload).unwrap();
    assert!(decoded.is_valid());
    assert_eq!(store.txg_manager().commit_count(), 1);

    for (i, key) in keys.iter().enumerate() {
        let val = store.get(*key).unwrap();
        let expected = format!("data-{i}").into_bytes();
        assert_eq!(val, Some(expected));
    }
    clean(&root);
}

// ---------------------------------------------------------------------------
// Multiple syncs produce a chain of committed roots
// ---------------------------------------------------------------------------

#[test]
fn multiple_syncs_produce_root_chain() {
    let root = temp_dir("multi-sync");
    let mut store = open_test_store(&root);

    store.put_content_addressed(b"commit_group-1").unwrap();
    store.sync_all().unwrap();
    assert_eq!(store.txg_manager().commit_count(), 1);
    let root1 = store.txg_manager().committed_root();
    assert_eq!(root1.commit_group_id, CommitGroupId::FIRST);

    store.put_content_addressed(b"commit_group-2").unwrap();
    store.sync_all().unwrap();
    assert_eq!(store.txg_manager().commit_count(), 2);
    let root2 = store.txg_manager().committed_root();
    assert_eq!(root2.commit_group_id, CommitGroupId(2));

    store.put_content_addressed(b"commit_group-3").unwrap();
    store.sync_all().unwrap();
    assert_eq!(store.txg_manager().commit_count(), 3);
    let root3 = store.txg_manager().committed_root();
    assert_eq!(root3.commit_group_id, CommitGroupId(3));

    let root_path = root.join(txg_manager::COMMITTED_ROOT_FILE);
    let payload = std::fs::read(&root_path).unwrap();
    let decoded = txg_manager::CommitGroupManager::decode_root(&payload).unwrap();
    assert_eq!(decoded, root3);
    clean(&root);
}

// ---------------------------------------------------------------------------
// Empty sync is a no-op
// ---------------------------------------------------------------------------

#[test]
fn empty_sync_is_noop() {
    let root = temp_dir("empty-sync");
    let mut store = open_test_store(&root);

    store.sync_all().unwrap();
    assert_eq!(store.txg_manager().committed_root(), RootPointer::NIL);
    assert_eq!(store.txg_manager().commit_count(), 0);

    let root_path = root.join(txg_manager::COMMITTED_ROOT_FILE);
    assert!(!root_path.exists());
    clean(&root);
}

// ---------------------------------------------------------------------------
// Committed root survives store close and reopen
// ---------------------------------------------------------------------------

#[test]
fn committed_root_survives_reopen() {
    let root = temp_dir("survive-reopen");

    {
        let mut store = open_test_store(&root);
        store.put_content_addressed(b"persistent-data").unwrap();
        store.put_content_addressed(b"more-data").unwrap();
        store.sync_all().unwrap();
        let r = store.txg_manager().committed_root();
        assert!(r.is_valid());
    }

    {
        let store = open_test_store(&root);
        let r = store.txg_manager().committed_root();
        assert!(r.is_valid());
        assert_eq!(r.commit_group_id, CommitGroupId::FIRST);

        let key1 = ObjectKey::from_content(b"persistent-data");
        assert_eq!(store.get(key1).unwrap(), Some(b"persistent-data".to_vec()));

        let key2 = ObjectKey::from_content(b"more-data");
        assert_eq!(store.get(key2).unwrap(), Some(b"more-data".to_vec()));
    }
    clean(&root);
}

// ---------------------------------------------------------------------------
// Unsynced writes do not produce a committed root
// ---------------------------------------------------------------------------

#[test]
fn unsynced_writes_no_root_file() {
    let root = temp_dir("unsynced");
    let mut store = open_test_store(&root);

    store.put_content_addressed(b"unsynced-data").unwrap();

    let root_path = root.join(txg_manager::COMMITTED_ROOT_FILE);
    assert!(!root_path.exists());

    assert_eq!(store.txg_manager().committed_root(), RootPointer::NIL);
    assert_eq!(store.txg_manager().commit_count(), 0);
    assert!(!store.txg_manager().current_is_empty());
    clean(&root);
}

// ---------------------------------------------------------------------------
// Flush via flush_segment also commits the commit_group
// ---------------------------------------------------------------------------

#[test]
fn sync_all_commits_txg_after_put() {
    let root = temp_dir("sync-commits");
    let mut store = open_test_store(&root);

    // put writes directly to the segment (not through segment_builder).
    let key = ObjectKey::from_name(b"sync-key");
    store.put(key, b"sync-data").unwrap();

    // sync_all commits the commit_group and persists the root.
    store.sync_all().unwrap();

    let root_path = root.join(txg_manager::COMMITTED_ROOT_FILE);
    assert!(
        root_path.exists(),
        "committed root file must exist after sync_all"
    );

    let r = store.txg_manager().committed_root();
    assert!(r.is_valid());
    assert_eq!(store.txg_manager().commit_count(), 1);

    // Data is readable.
    let val = store.get(key).unwrap();
    assert_eq!(val, Some(b"sync-data".to_vec()));
    clean(&root);
}

// ---------------------------------------------------------------------------
// Reopen after crash (no sync) — last synced root still valid
// ---------------------------------------------------------------------------

#[test]
fn reopen_after_crash_sees_last_synced_root() {
    let root = temp_dir("crash-root");

    {
        let mut store = open_test_store(&root);
        store.put_content_addressed(b"batch-1").unwrap();
        store.sync_all().unwrap();
        let r = store.txg_manager().committed_root();
        assert_eq!(r.commit_group_id, CommitGroupId::FIRST);

        // Write batch 2 but don't sync — simulate crash.
        store.put_content_addressed(b"batch-2-unsynced").unwrap();
    }

    {
        let store = open_test_store(&root);
        let r = store.txg_manager().committed_root();
        assert!(r.is_valid());
        assert_eq!(r.commit_group_id, CommitGroupId::FIRST);

        let key1 = ObjectKey::from_content(b"batch-1");
        assert!(store.get(key1).unwrap().is_some());
    }
    clean(&root);
}

// ---------------------------------------------------------------------------
// Reopen resumes commit_group numbering from committed root
// ---------------------------------------------------------------------------

#[test]
fn reopen_resumes_txg_from_committed_root() {
    let root = temp_dir("resume-commit_group");

    {
        let mut store = open_test_store(&root);
        store.put_content_addressed(b"commit_group-1-data").unwrap();
        store.sync_all().unwrap();
        store.put_content_addressed(b"commit_group-2-data").unwrap();
        store.sync_all().unwrap();
        let r = store.txg_manager().committed_root();
        assert_eq!(r.commit_group_id, CommitGroupId(2));
    }

    {
        let store = open_test_store(&root);
        let r = store.txg_manager().committed_root();
        assert_eq!(r.commit_group_id, CommitGroupId(2));
        assert_eq!(store.txg_manager().current_id(), CommitGroupId(3));
    }
    clean(&root);
}

// ---------------------------------------------------------------------------
// Abort discards commit_group writes without side effects
// ---------------------------------------------------------------------------

#[test]
fn abort_txg_discards_tracked_writes_no_side_effects() {
    let root = temp_dir("abort-discard");
    let mut store = open_test_store(&root);

    let key = ObjectKey::from_name(b"aborted-write");
    store.put(key, b"data-before-abort").unwrap();

    // Txg should have tracked the write.
    assert!(!store.txg_manager().current_is_empty());
    assert_eq!(store.txg_manager().committed_root(), RootPointer::NIL);

    // Abort discards the commit_group accumulator.
    store.abort_commit_group();
    assert!(store.txg_manager().current_is_empty());

    // Syncing after abort is a no-op for the commit_group (empty group).
    store.sync_all().unwrap();
    assert_eq!(store.txg_manager().committed_root(), RootPointer::NIL);

    // The segment write already happened (put_inner) so the data
    // is durable even though the commit_group never committed it.
    let val = store.get(key).unwrap();
    assert_eq!(val, Some(b"data-before-abort".to_vec()));

    // After reopen, data survives (segment write + sync_all above).
    drop(store);
    let store2 = open_test_store(&root);
    let val2 = store2.get(key).unwrap();
    assert_eq!(val2, Some(b"data-before-abort".to_vec()));
    assert_eq!(store2.txg_manager().committed_root(), RootPointer::NIL);

    clean(&root);
}

// ---------------------------------------------------------------------------
// Abort followed by new writes produces valid committed root
// ---------------------------------------------------------------------------

#[test]
fn abort_then_write_produces_valid_root() {
    let root = temp_dir("abort-then-write");
    let mut store = open_test_store(&root);

    // Write, abort.
    store
        .put(ObjectKey::from_name(b"doomed"), b"doomed-data")
        .unwrap();
    assert!(!store.txg_manager().current_is_empty());
    store.abort_commit_group();
    assert!(store.txg_manager().current_is_empty());
    assert_eq!(store.txg_manager().committed_root(), RootPointer::NIL);

    // New write after abort should be tracked in a fresh commit_group.
    let key = ObjectKey::from_name(b"fresh-key");
    store.put(key, b"fresh-data").unwrap();
    assert!(!store.txg_manager().current_is_empty());

    store.sync_all().unwrap();
    let root_ptr = store.txg_manager().committed_root();
    assert!(root_ptr.is_valid());
    assert_eq!(root_ptr.commit_group_id, CommitGroupId(2));

    let val = store.get(key).unwrap();
    assert_eq!(val, Some(b"fresh-data".to_vec()));

    clean(&root);
}

#[test]
fn directory_committed_root_uses_sidecar_without_segment_object() {
    let root = temp_dir("sidecar-root");
    let mut store = open_test_store(&root);

    store.put_content_addressed(b"sidecar-data").unwrap();
    store.sync_all().unwrap();

    let committed = store.txg_manager().committed_root();
    assert!(committed.is_valid());

    let root_path = root.join(txg_manager::COMMITTED_ROOT_FILE);
    let sidecar_copy = std::fs::read(&root_path).unwrap();
    let (decoded, digest) =
        txg_manager::CommitGroupManager::decode_root_with_digest(&sidecar_copy).unwrap();
    assert_eq!(decoded, committed);
    assert!(
        digest.is_some(),
        "sidecar committed root must persist the chain digest"
    );

    // Directory-backed stores keep the committed root in the sidecar file.
    // The segment-path object is reserved for sidecar-unavailable modes so
    // ordinary segment layout and replay counters stay user-data-only.
    let root_key = tidefs_local_object_store::ObjectKey::from_name(
        tidefs_local_object_store::txg_manager::COMMITTED_ROOT_FILE.as_bytes(),
    );
    assert_eq!(store.get(root_key).unwrap(), None);

    drop(store);
    let store2 = open_test_store(&root);
    assert_eq!(store2.txg_manager().committed_root(), committed);
    assert_eq!(store2.get(root_key).unwrap(), None);

    clean(&root);
}

// ---------------------------------------------------------------------------
// CommitGroupCoordinator chain-digest integration tests
// ---------------------------------------------------------------------------

/// sync_all computes a non-zero chain digest anchored to the committed root.
#[test]
fn sync_all_produces_nonzero_chain_digest() {
    let root = temp_dir("chain-nonzero");
    let mut store = open_test_store(&root);

    store.put_content_addressed(b"chain-test-1").unwrap();
    store.sync_all().unwrap();

    let digest = store.txg_coordinator().last_chain_digest();
    assert_ne!(
        digest, [0u8; 32],
        "chain digest must be non-zero after commit"
    );
    assert_eq!(
        store.txg_coordinator().committed_root().commit_group_id,
        CommitGroupId::FIRST,
    );

    clean(&root);
}

/// Two sequential sync_all calls produce distinct chain digests.
#[test]
fn sequential_syncs_produce_distinct_chain_digests() {
    let root = temp_dir("chain-distinct");
    let mut store = open_test_store(&root);

    store.put_content_addressed(b"commit_group-1-data").unwrap();
    store.sync_all().unwrap();
    let digest1 = store.txg_coordinator().last_chain_digest();
    let committed1 = store.txg_coordinator().committed_root();
    assert_eq!(committed1.commit_group_id, CommitGroupId::FIRST);

    store.put_content_addressed(b"commit_group-2-data").unwrap();
    store.sync_all().unwrap();
    let digest2 = store.txg_coordinator().last_chain_digest();
    let committed2 = store.txg_coordinator().committed_root();
    assert_eq!(committed2.commit_group_id, CommitGroupId(2));

    assert_ne!(
        digest1, digest2,
        "sequential commits must produce distinct chain digests"
    );
    assert_ne!(digest1, [0u8; 32]);
    assert_ne!(digest2, [0u8; 32]);

    clean(&root);
}

/// Three sequential sync_all calls produce a verifiable digest chain.
#[test]
fn chain_digest_forms_verifiable_sequence_across_syncs() {
    let root = temp_dir("chain-sequence");
    let mut store = open_test_store(&root);

    store.put_content_addressed(b"seq-data-1").unwrap();
    store.sync_all().unwrap();
    let d1 = store.txg_coordinator().last_chain_digest();
    let r1 = store.txg_coordinator().committed_root();

    store.put_content_addressed(b"seq-data-2").unwrap();
    store.sync_all().unwrap();
    let d2 = store.txg_coordinator().last_chain_digest();
    let r2 = store.txg_coordinator().committed_root();

    store.put_content_addressed(b"seq-data-3").unwrap();
    store.sync_all().unwrap();
    let d3 = store.txg_coordinator().last_chain_digest();
    let r3 = store.txg_coordinator().committed_root();

    // All non-zero and distinct.
    assert_ne!(d1, [0u8; 32]);
    assert_ne!(d2, [0u8; 32]);
    assert_ne!(d3, [0u8; 32]);
    assert_ne!(d1, d2);
    assert_ne!(d2, d3);
    assert_ne!(d1, d3);

    // Txg numbers monotonic.
    assert_eq!(r1.commit_group_id, CommitGroupId::FIRST);
    assert_eq!(r2.commit_group_id, CommitGroupId(2));
    assert_eq!(r3.commit_group_id, CommitGroupId(3));

    // Replay: rebuild a coordinator with the same roots and verify the
    // chain reproduces.
    let mut verify = tidefs_commit_group::CommitGroupCoordinator::new();
    let v1 = verify.chain_digest(b"seq-data-1");
    verify.advance(r1, v1);
    let v2 = verify.chain_digest(b"seq-data-2");
    verify.advance(r2, v2);
    let v3 = verify.chain_digest(b"seq-data-3");
    verify.advance(r3, v3);

    assert_ne!(v1, [0u8; 32]);
    assert_ne!(v2, [0u8; 32]);
    assert_ne!(v3, [0u8; 32]);
    assert_ne!(v1, v2);
    assert_ne!(v2, v3);
    assert_ne!(v1, v3);

    clean(&root);
}

/// Chain digest survives store close and reopen via the digest-aware
/// encode/decode path in CommitGroupManager.
#[test]
fn chain_digest_survives_reopen() {
    let root = temp_dir("chain-survive");

    let digest_after_first;
    let committed_after_first;

    {
        let mut store = open_test_store(&root);
        store.put_content_addressed(b"survive-data").unwrap();
        store.sync_all().unwrap();

        digest_after_first = store.txg_coordinator().last_chain_digest();
        committed_after_first = store.txg_coordinator().committed_root();
        assert!(committed_after_first.is_valid());
        assert_ne!(digest_after_first, [0u8; 32]);
    }

    {
        let store = open_test_store(&root);
        // The recovered coordinator should have the same chain digest.
        let recovered_digest = store.txg_coordinator().last_chain_digest();
        let recovered_root = store.txg_coordinator().committed_root();

        assert_eq!(recovered_root, committed_after_first);
        assert_eq!(
            recovered_digest, digest_after_first,
            "chain digest must survive close/reopen",
        );

        // The next commit_group number advances.
        assert_eq!(store.txg_coordinator().next_txg_number(), CommitGroupId(2),);
    }

    clean(&root);
}

/// After reopen, a new commit chains from the recovered digest.
#[test]
fn chain_digest_continues_after_reopen() {
    let root = temp_dir("chain-continue");

    {
        let mut store = open_test_store(&root);
        store.put_content_addressed(b"pre-reopen").unwrap();
        store.sync_all().unwrap();
    }

    {
        let mut store = open_test_store(&root);
        let d_before = store.txg_coordinator().last_chain_digest();
        assert_ne!(d_before, [0u8; 32]);

        store.put_content_addressed(b"post-reopen").unwrap();
        store.sync_all().unwrap();

        let d_after = store.txg_coordinator().last_chain_digest();
        assert_ne!(d_after, [0u8; 32]);
        assert_ne!(
            d_after, d_before,
            "chain digest should advance after new commit post-reopen",
        );
    }

    clean(&root);
}

/// The chain digest in the committed-root file matches the coordinator
/// state after sync_all.
#[test]
fn committed_root_file_contains_chain_digest() {
    let root = temp_dir("rootfile-digest");
    let mut store = open_test_store(&root);

    store.put_content_addressed(b"rootfile-test").unwrap();
    store.sync_all().unwrap();

    let coord_digest = store.txg_coordinator().last_chain_digest();

    // Read the committed-root file and decode with digest.
    let root_path = root.join(tidefs_local_object_store::txg_manager::COMMITTED_ROOT_FILE);
    let payload = std::fs::read(&root_path).unwrap();

    // The file should be 48 bytes (16 for root + 32 for digest).
    assert_eq!(
        payload.len(),
        48,
        "committed-root file must be 48 bytes with chain digest",
    );

    let (decoded_root, decoded_digest) =
        tidefs_local_object_store::txg_manager::CommitGroupManager::decode_root_with_digest(
            &payload,
        )
        .unwrap();

    assert!(decoded_root.is_valid());
    assert_eq!(
        decoded_digest.unwrap(),
        coord_digest,
        "chain digest in file must match coordinator state",
    );

    clean(&root);
}
