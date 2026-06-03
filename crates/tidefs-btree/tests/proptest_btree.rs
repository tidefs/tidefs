//! Property-based tests (proptest) for tidefs-btree.
//!
//! Validates BPlusTree invariants against std::collections::BTreeMap
//! as an oracle under randomized insert/delete/update operation sequences.
//!
//! Worker slot: s9
//! Review debt TFR-004: historical issue #4150 work queue item 1.

use std::collections::BTreeMap;

use proptest::prelude::*;
use tidefs_btree::BPlusTree;

/// Strategy: generate a sequence of operations (insert, delete, update).
#[derive(Clone, Debug)]
enum Op {
    Insert(u64, String),
    Delete(u64),
    Update(u64, String),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        // Insert with value derived from key for reproducibility
        (0u64..1000).prop_map(|k| Op::Insert(k, format!("v{k}"))),
        // Delete existing or non-existing key
        (0u64..1000).prop_map(Op::Delete),
        // Update existing or non-existing key
        (0u64..1000).prop_map(|k| Op::Update(k, format!("u{k}"))),
    ]
}

fn ops_strategy() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(op_strategy(), 0..500)
}

proptest! {
    /// The BPlusTree's get/contains_key/len/is_empty must match BTreeMap
    /// for any sequence of insert/delete operations.
    #[test]
    fn btree_matches_oracle_all_ops(
        ops in ops_strategy()
    ) {
        type BT = BPlusTree<u64, String, 12, 8>;
        let mut tree = BT::new();
        let mut oracle: BTreeMap<u64, String> = BTreeMap::new();

        for op in ops {
            match op {
                Op::Insert(k, v) => {
                    let t_old = tree.insert(k, v.clone());
                    let o_old = oracle.insert(k, v);
                    assert_eq!(t_old.as_deref(), o_old.as_deref(),
                        "insert({k}) return mismatch");
                }
                Op::Delete(k) => {
                    let t_old = tree.delete(&k);
                    let o_old = oracle.remove(&k);
                    assert_eq!(t_old.as_deref(), o_old.as_deref(),
                        "delete({k}) return mismatch");
                }
                Op::Update(k, v) => {
                    let t_found = tree.update(&k, |val| *val = v.clone());
                    let o_found = if let Some(o_val) = oracle.get_mut(&k) {
                        *o_val = v;
                        true
                    } else {
                        false
                    };
                    assert_eq!(t_found, o_found,
                        "update({k}) found mismatch");
                }
            }

            // After each operation, verify oracle-consistent state
            assert_eq!(tree.len(), oracle.len(), "len mismatch");
            assert_eq!(tree.is_empty(), oracle.is_empty(), "is_empty mismatch");

            // Spot-check a few keys from the oracle
            for (key, val) in oracle.iter().take(20) {
                assert_eq!(tree.get(key).map(String::as_str), Some(val.as_str()),
                    "get({key}) mismatch");
                assert!(tree.contains_key(key),
                    "contains_key({key}) should be true");
            }
        }

        // Final validation: tree must be structurally valid
        assert!(tree.validate().is_ok(),
            "tree failed structural validation");
    }

    /// Insert-only workload: entries() must match oracle's ordered iteration.
    #[test]
    fn insert_only_entries_matches_oracle(
        keys in prop::collection::vec(0u64..1000, 0..200)
    ) {
        let mut tree: BPlusTree<u64, String, 10, 5> = BPlusTree::new();
        let mut oracle: BTreeMap<u64, String> = BTreeMap::new();

        for k in keys {
            let v = format!("v{k}");
            tree.insert(k, v.clone());
            oracle.insert(k, v);
        }

        let t_entries = tree.entries();
        let o_entries: Vec<(u64, String)> = oracle.into_iter().collect();
        assert_eq!(t_entries, o_entries,
            "entries() must match oracle ordering (len={})", tree.len());
    }

    /// Range queries must match oracle for any valid RangeBounds.
    #[test]
    fn range_matches_oracle(
        keys in prop::collection::vec(0u64..200, 1..150),
        start in 0u64..200,
        end in 0u64..200
    ) {
        let mut tree: BPlusTree<u64, String, 8, 8> = BPlusTree::new();
        let mut oracle: BTreeMap<u64, String> = BTreeMap::new();

        for k in keys {
            let v = format!("v{k}");
            tree.insert(k, v.clone());
            oracle.insert(k, v);
        }

        let lo = start.min(end);
        let hi = start.max(end);
        let t_range = tree.range(lo..hi);
        let o_range: Vec<(u64, String)> = oracle.range(lo..hi)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        assert_eq!(t_range, o_range,
            "range({lo}..{hi}) mismatch (tree len={})", tree.len());
    }

    /// Delete all entries one by one: must reach empty state.
    #[test]
    fn delete_all_yields_empty(
        keys in prop::collection::vec(0u64..500, 1..200)
    ) {
        let mut tree: BPlusTree<u64, String, 6, 6> = BPlusTree::new();
        let mut oracle: BTreeMap<u64, String> = BTreeMap::new();

        for k in &keys {
            tree.insert(*k, format!("v{k}"));
            oracle.insert(*k, format!("v{k}"));
        }

        // Delete all keys present in oracle
        let all_keys: Vec<u64> = oracle.keys().copied().collect();
        for k in all_keys {
            let t_val = tree.delete(&k);
            let o_val = oracle.remove(&k);
            assert_eq!(t_val.as_deref(), o_val.as_deref(),
                "delete({k}) return mismatch");
        }

        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert_eq!(tree.depth(), 1);
        assert!(tree.validate().is_ok());
    }



    /// Insert-delete-reinsert cycle must reach original state.
    #[test]
    fn insert_delete_reinsert_cycle_returns_original(
        keys in prop::collection::vec(0u64..300, 1..120)
    ) {
        // Deduplicate: duplicates just replace, so use unique sorted keys
        let unique: Vec<u64> = keys.iter().copied().collect::<std::collections::BTreeSet<_>>()
            .into_iter().collect();
        prop_assume!(!unique.is_empty());
        let mut tree: BPlusTree<u64, u64, 5, 5> = BPlusTree::new();

        // Insert all unique keys
        for k in &unique {
            tree.insert(*k, *k * 10);
        }
        assert_eq!(tree.len(), unique.len());

        // Delete all
        for k in &unique {
            tree.delete(k);
        }
        assert!(tree.is_empty());

        // Re-insert all
        for k in &unique {
            tree.insert(*k, *k * 10);
        }

        assert_eq!(tree.len(), unique.len());
        for k in &unique {
            assert_eq!(tree.get(k).copied(), Some(*k * 10));
        }
        assert!(tree.validate().is_ok());
    }

    /// fill_percent must be in [0.0, 1.0] for any operation sequence.
    #[test]
    fn fill_percent_bounded(
        ops in ops_strategy().prop_filter("non-empty", |ops| !ops.is_empty())
    ) {
        let mut tree: BPlusTree<u64, String, 4, 4> = BPlusTree::new();

        for op in ops {
            match op {
                Op::Insert(k, v) => { tree.insert(k, v); }
                Op::Delete(k) => { tree.delete(&k); }
                Op::Update(k, v) => { tree.update(&k, |val| *val = v); }
            }

            let fp = tree.fill_percent();
            assert!((0.0..=1.0).contains(&fp),
                "fill_percent {fp} out of [0,1] range");
        }
    }

    /// depth and leaf_count must stay consistent through mutations.
    #[test]
    fn depth_and_leaf_count_consistent(
        ops in ops_strategy()
    ) {
        let mut tree: BPlusTree<u64, String, 4, 4> = BPlusTree::new();

        for op in ops {
            match op {
                Op::Insert(k, v) => { tree.insert(k, v); }
                Op::Delete(k) => { tree.delete(&k); }
                Op::Update(k, v) => { tree.update(&k, |val| *val = v); }
            }

            assert!(tree.depth() >= 1,
                "depth must be >= 1");
            assert!(tree.node_count() >= 1,
                "node_count must be >= 1");

            if tree.is_empty() {
                assert_eq!(tree.depth(), 1, "empty tree depth must be 1");
                assert_eq!(tree.leaf_count(), 1, "empty tree leaf_count must be 1");
                assert_eq!(tree.internal_count(), 0, "empty tree internal_count must be 0");
            }
        }
    }

    /// Clone must produce a structurally equivalent tree.
    #[test]
    fn clone_is_equivalent(
        ops in ops_strategy().prop_filter("non-empty", |ops| !ops.is_empty())
    ) {
        let mut tree: BPlusTree<u64, String, 4, 4> = BPlusTree::new();

        for op in ops {
            match op {
                Op::Insert(k, v) => { tree.insert(k, v); }
                Op::Delete(k) => { tree.delete(&k); }
                Op::Update(k, v) => { tree.update(&k, |val| *val = v); }
            }
        }

        let cloned = tree.clone();
        assert_eq!(tree.entries(), cloned.entries());
        assert_eq!(tree.len(), cloned.len());
        assert_eq!(tree.depth(), cloned.depth());
        assert_eq!(tree.leaf_count(), cloned.leaf_count());
        assert!(cloned.validate().is_ok());
    }

    /// clear() must produce empty state.
    #[test]
    fn clear_is_idempotent_empty(
        ops in ops_strategy()
    ) {
        let mut tree: BPlusTree<u64, String, 4, 4> = BPlusTree::new();

        for op in ops {
            match op {
                Op::Insert(k, v) => { tree.insert(k, v); }
                Op::Delete(k) => { tree.delete(&k); }
                Op::Update(k, v) => { tree.update(&k, |val| *val = v); }
            }
        }

        tree.clear();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert!(tree.validate().is_ok());

        // Double clear must be noop
        tree.clear();
        assert!(tree.is_empty());
    }
    /// After each op, the tree must pass BLAKE3 checksum verification.
    #[test]
    fn checksum_verification_after_random_ops(
        ops in ops_strategy()
    ) {
        type BT = BPlusTree<u64, String, 8, 8>;
        let mut tree = BT::new();
        for op in ops {
            match op {
                Op::Insert(k, v) => { tree.insert(k, v); }
                Op::Delete(k) => { tree.delete(&k); }
                Op::Update(k, v) => { tree.update(&k, |val| *val = v); }
            }
            assert!(tree.validate().is_ok());
            assert!(tree.verify_checksums().is_ok());
        }
    }

    /// compact() preserves checksum integrity.
    #[test]
    fn compact_preserves_checksums(
        ops in ops_strategy().prop_filter("non-empty", |ops| !ops.is_empty())
    ) {
        type BT = BPlusTree<u64, String, 5, 5>;
        let mut tree = BT::new();
        for op in &ops {
            match op {
                Op::Insert(k, v) => { tree.insert(*k, v.clone()); }
                Op::Delete(k) => { tree.delete(k); }
                Op::Update(k, v) => { tree.update(k, |val| *val = v.clone()); }
            }
        }
        assert!(tree.verify_checksums().is_ok());
        tree.compact();
        assert!(tree.verify_checksums().is_ok());
        tree.maybe_compact(0.9);
        assert!(tree.verify_checksums().is_ok());
    }

    /// clear() produces an empty tree with a valid checksum.
    #[test]
    fn clear_produces_valid_checksums(
        ops in ops_strategy().prop_filter("non-empty", |ops| !ops.is_empty())
    ) {
        type BT = BPlusTree<u64, String, 4, 4>;
        let mut tree = BT::new();
        for op in ops {
            match op {
                Op::Insert(k, v) => { tree.insert(k, v); }
                Op::Delete(k) => { tree.delete(&k); }
                Op::Update(k, v) => { tree.update(&k, |val| *val = v); }
            }
        }
        tree.clear();
        assert!(tree.is_empty());
        assert!(tree.validate().is_ok());
        assert!(tree.verify_checksums().is_ok());
    }

}

// ── rebuild oracle match (outside proptest to avoid shrinker issues) ─

#[test]
fn rebuild_from_oracle_sorted_entries_100() {
    use std::collections::BTreeMap;
    let mut oracle: BTreeMap<u64, String> = BTreeMap::new();
    // Insert with random order, duplicates overwrite
    let raw = vec![
        (5u64, "e"),
        (1, "a"),
        (3, "c1"),
        (3, "c2"),
        (10, "j"),
        (7, "g"),
        (2, "b"),
        (8, "h"),
        (4, "d"),
        (6, "f"),
        (9, "i"),
        (0, "zero"),
    ];
    for (k, v) in &raw {
        oracle.insert(*k, v.to_string());
    }
    let expected: Vec<(u64, String)> = oracle.into_iter().collect();

    let mut tree: BPlusTree<u64, String, 8, 8> = BPlusTree::new();
    tree.rebuild(&expected);

    assert_eq!(tree.len(), expected.len());
    let t_entries = tree.entries();
    assert_eq!(t_entries, expected, "rebuild entries must match oracle");
    // Validate after compact, which fixes underfilled leaves
    tree.compact();
    assert!(tree.validate().is_ok());
    // Entries must survive compaction
    assert_eq!(tree.entries(), expected);
}

// ── 10K+ split-cascade stress tests ─────────────────────────────────

#[test]
fn stress_insert_ascending_10k() {
    let mut tree: BPlusTree<u64, u64, 32, 16> = BPlusTree::new();
    let n = 10_000u64;
    for i in 0..n {
        tree.insert(i, i * 2);
    }
    assert_eq!(tree.len(), n as usize);
    assert!(tree.validate().is_ok());
    // Spot-check first, middle, last
    assert_eq!(tree.get(&0).copied(), Some(0));
    assert_eq!(tree.get(&5000).copied(), Some(10000));
    assert_eq!(tree.get(&9999).copied(), Some(19998));
    // Verify all keys findable
    for i in 0..n {
        assert_eq!(
            tree.get(&i).copied(),
            Some(i * 2),
            "key {i} missing after ascending insert"
        );
    }
}

#[test]
fn stress_insert_descending_10k() {
    let mut tree: BPlusTree<u64, u64, 32, 16> = BPlusTree::new();
    let n = 10_000u64;
    for i in (0..n).rev() {
        tree.insert(i, i * 3);
    }
    assert_eq!(tree.len(), n as usize);
    assert!(tree.validate().is_ok());
    assert_eq!(tree.get(&0).copied(), Some(0));
    assert_eq!(tree.get(&9999).copied(), Some(29997));
    for i in 0..n {
        assert_eq!(
            tree.get(&i).copied(),
            Some(i * 3),
            "key {i} missing after descending insert"
        );
    }
}

#[test]
fn stress_delete_lifo() {
    // Insert 5000 entries, then delete in reverse (LIFO) order.
    let mut tree: BPlusTree<u64, u64, 16, 8> = BPlusTree::new();
    let n = 5000u64;
    for i in 0..n {
        tree.insert(i, i * 10);
    }
    assert_eq!(tree.len(), n as usize);
    // Delete in reverse order: highest key first.
    for i in (0..n).rev() {
        assert_eq!(
            tree.delete(&i).unwrap(),
            i * 10,
            "delete({i}) LIFO returned wrong value"
        );
        // Validate after each 10% progress
        if i % 500 == 0 {
            assert!(
                tree.validate().is_ok(),
                "invariant broken after {} LIFO deletes",
                n - i
            );
        }
    }
    assert!(tree.is_empty());
    assert_eq!(tree.len(), 0);
    assert!(tree.validate().is_ok());
}

#[test]
fn stress_delete_fifo() {
    // Insert 5000 entries, then delete in forward (FIFO) order.
    let mut tree: BPlusTree<u64, u64, 16, 8> = BPlusTree::new();
    let n = 5000u64;
    for i in 0..n {
        tree.insert(i, i * 10);
    }
    assert_eq!(tree.len(), n as usize);
    for i in 0..n {
        assert_eq!(
            tree.delete(&i).unwrap(),
            i * 10,
            "delete({i}) FIFO returned wrong value"
        );
        if i % 500 == 0 {
            assert!(
                tree.validate().is_ok(),
                "invariant broken after {} FIFO deletes",
                i + 1
            );
        }
    }
    assert!(tree.is_empty());
    assert_eq!(tree.len(), 0);
    assert!(tree.validate().is_ok());
}

#[test]
fn stress_delete_random_order() {
    // Insert 5000 entries, then delete in a deterministic pseudo-random
    // permutation via multiplication by 3 modulo prime 5003.
    let mut tree: BPlusTree<u64, u64, 16, 8> = BPlusTree::new();
    let n: u64 = 5000;
    let p: u64 = 5003; // prime > n
    for i in 0..n {
        tree.insert(i, i * 10);
    }
    assert_eq!(tree.len(), n as usize);

    let multiplier: u64 = 3;
    // Iterate through all residues 0..p-1 so every key < n is visited
    // exactly once (multiplier is coprime to prime p, so the mapping
    // i -> (i * multiplier) % p is a permutation of Z_p).
    for i in 0..p {
        let key = (i.wrapping_mul(multiplier)) % p;
        if key < n {
            assert_eq!(
                tree.delete(&key).unwrap(),
                key * 10,
                "delete({key}) random-order returned wrong value"
            );
        }
        if i % 500 == 0 {
            assert!(
                tree.validate().is_ok(),
                "invariant broken after ~{i} random deletes"
            );
        }
    }
    assert!(tree.is_empty());
    assert_eq!(tree.len(), 0);
    assert!(tree.validate().is_ok());
}

// ── RangeScan proptests ─────────────────────────────────────────────

proptest! {
    /// Full-tree scan via RangeScan yields all keys in ascending order.
    #[test]
    fn range_scan_full_yields_all_keys_ordered(
        ops in ops_strategy()
    ) {
        type BT = BPlusTree<u64, String, 8, 8>;
        let mut tree = BT::new();
        let mut oracle: BTreeMap<u64, String> = BTreeMap::new();

        for op in ops {
            match op {
                Op::Insert(k, v) => { tree.insert(k, v.clone()); oracle.insert(k, v); }
                Op::Delete(k) => { tree.delete(&k); oracle.remove(&k); }
                Op::Update(k, v) => {
                    let _ = tree.update(&k, |val| *val = v.clone());
                    if let Some(o_val) = oracle.get_mut(&k) { *o_val = v; }
                }
            }
        }

        let scanned: Vec<(&u64, &String)> = tree.range_scan(..).collect();
        let expected: Vec<(&u64, &String)> = oracle.iter().collect();

        assert_eq!(scanned.len(), expected.len(),
            "RangeScan full-scan length mismatch");
        for (i, ((sk, sv), (ek, ev))) in scanned.iter().zip(expected.iter()).enumerate() {
            assert_eq!(*sk, *ek, "key mismatch at position {i}");
            assert_eq!(sv.as_str(), ev.as_str(), "value mismatch at position {i}");
            if i > 0 {
                assert!(scanned[i-1].0 < scanned[i].0,
                    "keys not strictly ascending at position {i}");
            }
        }
    }

    /// RangeScan within random sub-ranges matches the oracle filtered to the
    /// same bounds.
    #[test]
    fn range_scan_sub_range_matches_oracle(
        ops in ops_strategy(),
        start in 0u64..=1200,
        end in 0u64..=1200,
    ) {
        type BT = BPlusTree<u64, String, 12, 8>;
        let mut tree = BT::new();
        let mut oracle: BTreeMap<u64, String> = BTreeMap::new();

        for op in ops {
            match op {
                Op::Insert(k, v) => { tree.insert(k, v.clone()); oracle.insert(k, v); }
                Op::Delete(k) => { tree.delete(&k); oracle.remove(&k); }
                Op::Update(k, v) => {
                    let _ = tree.update(&k, |val| *val = v.clone());
                    if let Some(o_val) = oracle.get_mut(&k) { *o_val = v; }
                }
            }
        }

        let (lo, hi) = if start <= end { (start, end) } else { (end, start) };
        let scanned: Vec<(&u64, &String)> = tree.range_scan(lo..hi).collect();
        let expected: Vec<(&u64, &String)> = oracle.range(lo..hi).collect();

        assert_eq!(scanned.len(), expected.len(),
            "RangeScan range {lo}..{hi} length mismatch (tree len={})", tree.len());
        for (i, ((sk, sv), (ek, ev))) in scanned.iter().zip(expected.iter()).enumerate() {
            assert_eq!(*sk, *ek, "key mismatch at position {i}");
            assert_eq!(sv.as_str(), ev.as_str(), "value mismatch at position {i}");
            // All keys must be within bounds
            assert!(*sk >= &lo && *sk < &hi,
                "key {sk} outside range {lo}..{hi}");
            if i > 0 {
                assert!(scanned[i-1].0 < scanned[i].0,
                    "keys not strictly ascending at position {i}");
            }
        }
    }

    /// RangeScan with Included/Excluded bounds on both sides.
    #[test]
    fn range_scan_bound_variants(
        ops in ops_strategy(),
        start_key in 0u64..=1200,
        end_key in 0u64..=1200,
        include_start in proptest::bool::ANY,
        include_end in proptest::bool::ANY,
    ) {
        use core::ops::Bound;
        type BT = BPlusTree<u64, String, 6, 6>;
        let mut tree = BT::new();
        let mut oracle: BTreeMap<u64, String> = BTreeMap::new();

        for op in ops {
            match op {
                Op::Insert(k, v) => { tree.insert(k, v.clone()); oracle.insert(k, v); }
                Op::Delete(k) => { tree.delete(&k); oracle.remove(&k); }
                Op::Update(k, v) => {
                    let _ = tree.update(&k, |val| *val = v.clone());
                    if let Some(o_val) = oracle.get_mut(&k) { *o_val = v; }
                }
            }
        }

        let start = if include_start { Bound::Included(start_key) } else { Bound::Excluded(start_key) };
        let end = if include_end { Bound::Included(end_key) } else { Bound::Excluded(end_key) };

        let scanned: Vec<(&u64, &String)> = tree.range_scan((start, end)).collect();

        // Oracle: iterate and filter using RangeBounds-like semantics
        let oracle_keys: Vec<u64> = oracle.keys().copied().collect();
        let expected_indices: Vec<usize> = oracle_keys.iter().enumerate()
            .filter(|(_, k)| {
                let after_start = match start {
                    Bound::Included(s) => **k >= s,
                    Bound::Excluded(s) => **k > s,
                    Bound::Unbounded => true,
                };
                let before_end = match end {
                    Bound::Included(e) => **k <= e,
                    Bound::Excluded(e) => **k < e,
                    Bound::Unbounded => true,
                };
                after_start && before_end
            })
            .map(|(i, _)| i)
            .collect();

        assert_eq!(scanned.len(), expected_indices.len(),
            "RangeScan bound-variant length mismatch");

        for (i, idx) in expected_indices.iter().enumerate() {
            let (k, v) = oracle.iter().nth(*idx).unwrap();
            assert_eq!(scanned[i].0, k, "key mismatch at position {i}");
            assert_eq!(scanned[i].1.as_str(), v.as_str(), "value mismatch at position {i}");
            if i > 0 {
                assert!(scanned[i-1].0 < scanned[i].0,
                    "keys not strictly ascending at position {i}");
            }
        }
    }
}

/// Deterministic 1000-operation insert/delete sequence with BLAKE3
/// checksum verification at every 100-operation checkpoint.
///
/// Uses a multiplicative permutation of keys 0..999 for deterministic
/// coverage of insert, overwrite, delete, compact, and re-verify patterns.
#[test]
fn thousand_operation_checksum_verification() {
    use std::collections::BTreeMap;

    type BT = BPlusTree<u64, String, 6, 6>;
    let mut tree = BT::new();
    let mut oracle: BTreeMap<u64, String> = BTreeMap::new();

    let p: u64 = 1009;
    let mult: u64 = 7;

    // Phase 1: Insert 1000 keys in permuted order.
    for i in 0..1000u64 {
        let k = (i.wrapping_mul(mult)) % p;
        if k < 1000 {
            let v = format!("v{k}");
            let told = tree.insert(k, v.clone());
            let oold = oracle.insert(k, v);
            assert_eq!(told.as_deref(), oold.as_deref());
        }
        if (i + 1) % 100 == 0 {
            assert!(tree.validate().is_ok());
            assert!(tree.verify_checksums().is_ok());
            assert_eq!(tree.len(), oracle.len());
        }
    }

    // Phase 2: Delete even-indexed keys.
    for i in (0..1000u64).step_by(2) {
        let k = (i.wrapping_mul(mult)) % p;
        if k < 1000 {
            let told = tree.delete(&k);
            let oold = oracle.remove(&k);
            assert_eq!(told.as_deref(), oold.as_deref());
        }
    }

    assert!(tree.validate().is_ok());
    assert!(tree.verify_checksums().is_ok());
    assert_eq!(tree.len(), oracle.len());

    // Verify all remaining entries.
    for (k, v) in &oracle {
        assert_eq!(tree.get(k).map(String::as_str), Some(v.as_str()));
    }

    // Compact and re-verify.
    tree.compact();
    assert!(tree.validate().is_ok());
    assert!(tree.verify_checksums().is_ok());
    assert_eq!(tree.len(), oracle.len());
    for (k, v) in &oracle {
        assert_eq!(tree.get(k).map(String::as_str), Some(v.as_str()));
    }
}

/// Deterministic tests with small fanout to force multi-level trees.
#[test]
fn range_scan_small_fanout_multi_level() {
    // Fanout 3 means MAX_LEAF=3, so even a few entries force splits.
    type SmallTree = BPlusTree<u64, u64, 3, 3>;
    let mut t = SmallTree::new();
    for i in 0..20u64 {
        t.insert(i, i * 10);
    }
    assert!(
        t.depth() >= 3,
        "small fanout should produce multi-level tree"
    );

    // Full scan: all keys in order
    let all: Vec<(&u64, &u64)> = t.range_scan(..).collect();
    assert_eq!(all.len(), 20);
    for (i, (k, v)) in all.iter().enumerate() {
        assert_eq!(**k, i as u64);
        assert_eq!(**v, i as u64 * 10);
    }

    // Sub-range scan crossing leaf boundaries
    let mid: Vec<(&u64, &u64)> = t.range_scan(5..15).collect();
    assert_eq!(mid.len(), 10);
    for (i, (k, _)) in mid.iter().enumerate() {
        assert_eq!(**k, 5 + i as u64);
    }
}

#[test]
fn range_scan_fanout_4_multi_level() {
    type Fanout4 = BPlusTree<u64, u64, 4, 4>;
    let mut t = Fanout4::new();
    for i in 0..30u64 {
        t.insert(i, i * 100);
    }
    assert!(t.depth() >= 3);

    let all: Vec<(&u64, &u64)> = t.range_scan(..).collect();
    assert_eq!(all.len(), 30);
    for (i, (k, _)) in all.iter().enumerate() {
        assert_eq!(**k, i as u64);
    }
}

#[test]
fn range_scan_fanout_6_multi_level() {
    type Fanout6 = BPlusTree<u64, u64, 6, 6>;
    let mut t = Fanout6::new();
    // 6*6=36 leaf entries per internal; 6*6*6=216 for depth 3
    for i in 0..50u64 {
        t.insert(i, i * 1000);
    }
    assert!(t.depth() >= 3);
    let all: Vec<(&u64, &u64)> = t.range_scan(..).collect();
    assert_eq!(all.len(), 50);
}
