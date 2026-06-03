// dir_index_boundary.rs — Boundary-condition integration tests for DirIndex
// covering Send+Sync safety, entry overwrite semantics, and targeted patterns
// from issue #3992 that complement the existing test suite.
//
// The existing suite (dir_index_basic, hash_collision, large_directory,
// concurrent_access, naming_edge_cases, proptest_roundtrip, boundary,
// concurrent_readers, dir_iterator_*) already covers hash-collision chaining,
// large-directory iteration (500 entries), concurrent insert+lookup, and
// remove-and-reinsert. This file adds Send+Sync compile-time assertions
// and the specific overwrite/lifecycle patterns requested in #3992.

use tidefs_dir_index::{DatasetDirPolicy, DirIndex, DirIterator};

fn test_policy() -> DatasetDirPolicy {
    DatasetDirPolicy {
        dir_micro_max_entries: 6,
        dir_micro_max_name_bytes: 512,
        dir_btree_downshift_entries: 3,
        dir_btree_downshift_name_bytes: 128,
    }
}

// ── Compile-time Send + Sync safety ─────────────────────────────────

/// DirIndex must be Send + Sync so it can be shared across tokio tasks
/// and wrapped in Arc for concurrent access patterns.
#[test]
fn dir_index_is_send_and_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<DirIndex>();
    assert_sync::<DirIndex>();
}

// ── Entry overwrite: replace then verify iteration uniqueness ───────

/// Insert "key" → v1, replace with "key" → v2.
/// Lookup returns v2; iteration returns "key" exactly once.
#[test]
fn entry_overwrite_lookup_returns_latest_and_iteration_is_unique() {
    let mut idx = DirIndex::new(1, test_policy());

    idx.insert(b"key", 100, 1, 1).unwrap();
    idx.replace(b"key", 200, 2, 1);

    let entry = idx
        .lookup(b"key")
        .expect("key must be present after replace");
    assert_eq!(entry.inode_id, 200);
    assert_eq!(entry.generation, 2);

    let mut count = 0usize;
    while let Some(e) = idx.next_entry() {
        if e.name == b"key" {
            count += 1;
            assert_eq!(e.inode_id, 200, "iteration must see latest value");
        }
    }
    assert_eq!(count, 1, "key must appear exactly once in iteration");
}

/// Replace on a key not yet inserted acts as insert.
#[test]
fn replace_on_nonexistent_key_inserts() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.replace(b"fresh", 42, 0, 1);

    assert!(idx.contains(b"fresh"));
    assert_eq!(idx.lookup(b"fresh").unwrap().inode_id, 42);
    assert_eq!(idx.len(), 1);
}

/// Multiple replace across micro-list and BTree representations.
#[test]
fn replace_across_promotion_multiple_keys() {
    let mut idx = DirIndex::new(1, test_policy());

    for i in 0u64..10 {
        let name = format!("entry_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    for i in 0u64..5 {
        let name = format!("entry_{i:02}");
        idx.replace(name.as_bytes(), 1000 + i, 99, 1);
    }

    for i in 0u64..5 {
        let name = format!("entry_{i:02}");
        let e = idx.lookup(name.as_bytes()).unwrap();
        assert_eq!(e.inode_id, 1000 + i);
        assert_eq!(e.generation, 99);
    }
    for i in 5u64..10 {
        let name = format!("entry_{i:02}");
        let e = idx.lookup(name.as_bytes()).unwrap();
        assert_eq!(e.inode_id, i);
        assert_eq!(e.generation, 0);
    }
    assert_eq!(idx.len(), 10);
}

// ── Remove-nonexistent is a no-op ───────────────────────────────────

#[test]
fn remove_nonexistent_key_is_noop() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();

    let ver_before = idx.directory_version();
    let removed = idx.remove(b"nope");
    assert!(removed.is_none());
    assert_eq!(idx.len(), 2);
    assert_eq!(idx.directory_version(), ver_before);
}

// ── Insert-delete-reinsert sanity ───────────────────────────────────

#[test]
fn delete_then_reinsert_returns_new_value_not_stale() {
    let mut idx = DirIndex::new(1, test_policy());

    idx.insert(b"key", 1, 0, 1).unwrap();
    let removed = idx.remove(b"key").unwrap();
    assert_eq!(removed.inode_id, 1);

    idx.insert(b"key", 999, 5, 1).unwrap();

    let e = idx.lookup(b"key").unwrap();
    assert_eq!(e.inode_id, 999, "re-insert must not return stale value");
    assert_eq!(e.generation, 5);
    assert_eq!(idx.len(), 1);

    let mut seen = 0usize;
    while let Some(entry) = idx.next_entry() {
        if entry.name == b"key" {
            seen += 1;
            assert_eq!(entry.inode_id, 999);
        }
    }
    assert_eq!(seen, 1);
}

// ── Empty directory + single-entry directory iteration ──────────────

#[test]
fn empty_dir_next_entry_returns_none() {
    let mut idx = DirIndex::new(1, test_policy());
    assert!(idx.next_entry().is_none());
    assert!(idx.next_entry().is_none(), "iteration stays exhausted");
    assert_eq!(idx.len(), 0);
}

#[test]
fn single_entry_then_remove_iteration_is_empty() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"only", 1, 0, 1).unwrap();
    idx.remove(b"only");

    assert!(idx.next_entry().is_none());
    assert_eq!(idx.len(), 0);
}
