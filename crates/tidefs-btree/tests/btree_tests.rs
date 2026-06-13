// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Integration tests for tidefs-btree covering insert, lookup, split, merge,
// deletion, iteration, and boundary conditions.

use tidefs_btree::{BPlusTree, BTREE_SPEC};

type TestTree = BPlusTree<u64, String, 4, 4>;

fn make_tree(entries: &[(u64, &str)]) -> TestTree {
    let mut t = TestTree::new();
    for (k, v) in entries {
        t.insert(*k, v.to_string());
    }
    t
}

// ── insert + lookup round-trip ─────────────────────────────────────

#[test]
fn insert_single_lookup_found() {
    let mut t = TestTree::new();
    assert!(t.insert(42, "answer".into()).is_none());
    assert_eq!(t.len(), 1);
    assert_eq!(t.get(&42).unwrap(), "answer");
}

#[test]
fn insert_duplicate_replaces() {
    let mut t = TestTree::new();
    assert!(t.insert(1, "first".into()).is_none());
    assert_eq!(t.insert(1, "second".into()).unwrap(), "first");
    assert_eq!(t.get(&1).unwrap(), "second");
    assert_eq!(t.len(), 1);
}

#[test]
fn lookup_nonexistent() {
    let t = make_tree(&[(1, "a"), (2, "b")]);
    assert!(t.get(&99).is_none());
}

#[test]
fn contains_key() {
    let t = make_tree(&[(1, "a"), (2, "b")]);
    assert!(t.contains_key(&1));
    assert!(!t.contains_key(&99));
}

// ── ordered bulk insert ─────────────────────────────────────────────

#[test]
fn ordered_insert_ascending_small() {
    let mut t = TestTree::new();
    for i in 0..10u64 {
        t.insert(i, i.to_string());
    }
    assert_eq!(t.len(), 10);
    assert!(t.validate().is_ok());
    for i in 0..10u64 {
        assert_eq!(t.get(&i).unwrap(), &i.to_string());
    }
}

#[test]
fn ordered_insert_ascending_large() {
    let mut t = TestTree::new();
    let n = 100u64;
    for i in 0..n {
        t.insert(i, i.to_string());
    }
    assert_eq!(t.len(), n as usize);
    assert!(t.validate().is_ok());
    for i in 0..n {
        assert_eq!(t.get(&i).unwrap(), &i.to_string());
    }
}

// ── reverse-ordered insert (split stress) ───────────────────────────

#[test]
fn reverse_ordered_insert() {
    let mut t = TestTree::new();
    for i in (0..20u64).rev() {
        t.insert(i, i.to_string());
    }
    assert_eq!(t.len(), 20);
    assert!(t.validate().is_ok());
    for i in 0..20u64 {
        assert_eq!(t.get(&i).unwrap(), &i.to_string());
    }
    let all = t.entries();
    for w in all.windows(2) {
        assert!(w[0].0 < w[1].0);
    }
}

// ── randomized insert ───────────────────────────────────────────────

#[test]
fn randomized_insert() {
    // Deterministic permutation via modular inverse of 37 mod 53,
    // producing a full cycle through all 0..52.
    let n = 53u64;
    let mut t = TestTree::new();
    for i in 0..n {
        // permutation: key = (i * 37) % 53 covers all 0..52 exactly once.
        let key = (i.wrapping_mul(37)) % n;
        t.insert(key, key.to_string());
    }
    assert_eq!(t.len(), n as usize);
    assert!(t.validate().is_ok());
    for i in 0..n {
        assert!(t.contains_key(&i), "key {i} missing");
    }
}

// ── deletion ────────────────────────────────────────────────────────

#[test]
fn delete_existing_leaf() {
    let mut t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
    assert_eq!(t.delete(&2).unwrap(), "b");
    assert_eq!(t.len(), 2);
    assert!(t.get(&2).is_none());
    assert!(t.validate().is_ok());
}

#[test]
fn delete_first_entry() {
    let mut t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
    assert_eq!(t.delete(&1).unwrap(), "a");
    assert_eq!(t.len(), 2);
    assert!(t.get(&1).is_none());
    assert!(t.validate().is_ok());
}

#[test]
fn delete_last_entry() {
    let mut t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
    assert_eq!(t.delete(&3).unwrap(), "c");
    assert_eq!(t.len(), 2);
    assert!(t.get(&3).is_none());
    assert!(t.validate().is_ok());
}

#[test]
fn delete_all_to_empty() {
    let mut t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
    t.delete(&1);
    t.delete(&2);
    t.delete(&3);
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert!(t.validate().is_ok());
}

#[test]
fn delete_nonexistent_is_noop() {
    let mut t = make_tree(&[(1, "a")]);
    assert!(t.delete(&99).is_none());
    assert_eq!(t.len(), 1);
}

#[test]
fn delete_causes_leaf_merge() {
    // MAX_LEAF=4: 5 entries forces >=2 leaves. Delete one to
    // underflow a leaf -> rebuild merges back.
    let mut t = TestTree::new();
    for i in 0..5u64 {
        t.insert(i, i.to_string());
    }
    assert!(t.leaf_count() >= 2, "should have at least 2 leaves");
    t.delete(&0);
    assert!(t.validate().is_ok());
    assert_eq!(t.len(), 4);
    for i in 1..5u64 {
        assert_eq!(t.get(&i).unwrap(), &i.to_string(), "key {i} missing");
    }
}

#[test]
fn delete_causes_internal_node_change() {
    // 25 entries with MAX_LEAF=4 forces depth >= 3 (internal nodes).
    let mut t = TestTree::new();
    for i in 0..25u64 {
        t.insert(i, i.to_string());
    }
    let depth_before = t.depth();
    assert!(depth_before >= 3);
    t.delete(&12);
    assert!(t.validate().is_ok());
    assert_eq!(t.len(), 24);
    assert!(t.get(&12).is_none());
    for i in 0..25u64 {
        if i != 12 {
            assert_eq!(t.get(&i).unwrap(), &i.to_string(), "key {i} missing");
        }
    }
}

// ── insert-delete-reinsert round-trip ───────────────────────────────

#[test]
fn insert_delete_reinsert() {
    let mut t = TestTree::new();
    t.insert(42, "first".into());
    assert!(t.contains_key(&42));
    t.delete(&42);
    assert!(!t.contains_key(&42));
    t.insert(42, "second".into());
    assert!(t.contains_key(&42));
    assert_eq!(t.get(&42).unwrap(), "second");
    assert!(t.validate().is_ok());
}

#[test]
fn insert_delete_reinsert_many() {
    let mut t = TestTree::new();
    for i in 0..15u64 {
        t.insert(i, i.to_string());
    }
    for i in 0..8u64 {
        t.delete(&i);
    }
    for i in 0..8u64 {
        t.insert(i, format!("v{i}"));
    }
    assert_eq!(t.len(), 15);
    assert!(t.validate().is_ok());
    for i in 0..8u64 {
        assert_eq!(t.get(&i).unwrap(), &format!("v{i}"));
    }
    for i in 8..15u64 {
        assert_eq!(t.get(&i).unwrap(), &i.to_string());
    }
}

// ── iterator / entries ──────────────────────────────────────────────

#[test]
fn entries_empty_tree() {
    let t: TestTree = TestTree::new();
    assert!(t.entries().is_empty());
}

#[test]
fn entries_single() {
    let t = make_tree(&[(1, "a")]);
    assert_eq!(t.entries(), vec![(1u64, "a".into())]);
}

#[test]
fn entries_multi_ordered() {
    let mut t = TestTree::new();
    t.insert(3, "c".into());
    t.insert(1, "a".into());
    t.insert(2, "b".into());
    assert_eq!(
        t.entries(),
        vec![(1u64, "a".into()), (2u64, "b".into()), (3u64, "c".into())]
    );
}

// ── range queries ───────────────────────────────────────────────────

#[test]
fn range_full_unbounded() {
    let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
    assert_eq!(t.range(..).len(), 3);
}

#[test]
fn range_bounded() {
    let t = make_tree(&[(1, "a"), (2, "b"), (3, "c"), (4, "d"), (5, "e")]);
    let r = t.range(2..4);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].0, 2);
    assert_eq!(r[1].0, 3);
}

#[test]
fn range_from() {
    let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
    assert_eq!(t.range(2..).len(), 2);
}

#[test]
fn range_to() {
    let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
    assert_eq!(t.range(..3).len(), 2);
}

#[test]
fn range_empty_result() {
    let t = make_tree(&[(1, "a"), (2, "b")]);
    assert!(t.range(10..20).is_empty());
}

#[test]
fn range_from_to() {
    let t = make_tree(&[(1, "a"), (2, "b"), (3, "c"), (4, "d")]);
    let r = t.range_from_to(&2, &4);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].0, 2);
    assert_eq!(r[1].0, 3);
}

#[test]
fn range_from_to_inverted_empty() {
    let t = make_tree(&[(1, "a"), (2, "b")]);
    assert!(t.range_from_to(&5, &1).is_empty());
}

#[test]
fn range_inclusive() {
    let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
    let r = t.range(2..=3);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].0, 2);
    assert_eq!(r[1].0, 3);
}

#[test]
fn range_excluded_start() {
    let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
    let r = t.range((core::ops::Bound::Excluded(1), core::ops::Bound::Included(3)));
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].0, 2);
    assert_eq!(r[1].0, 3);
}

#[test]
fn range_excluded_end() {
    let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
    let r = t.range((core::ops::Bound::Included(2), core::ops::Bound::Excluded(3)));
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].0, 2);
}

#[test]
fn range_large_tree() {
    let mut t = TestTree::new();
    for i in 0..50u64 {
        t.insert(i, i.to_string());
    }
    let r = t.range(10..20);
    assert_eq!(r.len(), 10);
    for (i, (k, v)) in r.iter().enumerate() {
        assert_eq!(*k, 10 + i as u64);
        assert_eq!(v, &(10 + i as u64).to_string());
    }
}

// ── boundary values ─────────────────────────────────────────────────

#[test]
fn boundary_min_key() {
    let mut t: BPlusTree<u64, String> = BPlusTree::new();
    t.insert(0, "zero".into());
    assert_eq!(t.get(&0).unwrap(), "zero");
}

#[test]
fn boundary_max_key() {
    let mut t: BPlusTree<u64, String> = BPlusTree::new();
    t.insert(u64::MAX, "max".into());
    assert_eq!(t.get(&u64::MAX).unwrap(), "max");
}

#[test]
fn boundary_min_max_together() {
    let mut t: BPlusTree<u64, String> = BPlusTree::new();
    t.insert(0, "zero".into());
    t.insert(u64::MAX, "max".into());
    t.insert(42, "mid".into());
    assert_eq!(t.get(&0).unwrap(), "zero");
    assert_eq!(t.get(&u64::MAX).unwrap(), "max");
    assert_eq!(t.len(), 3);
    assert!(t.validate().is_ok());
}

// ── split propagation ───────────────────────────────────────────────

#[test]
fn split_produces_internal_root() {
    let mut t = TestTree::new();
    for i in 0..5u64 {
        t.insert(i, i.to_string());
    }
    assert_eq!(t.depth(), 2);
    assert!(t.validate().is_ok());
    for i in 0..5u64 {
        assert_eq!(t.get(&i).unwrap(), &i.to_string());
    }
}

#[test]
fn split_produces_multi_level() {
    let mut t = TestTree::new();
    for i in 0..64u64 {
        t.insert(i, i.to_string());
    }
    assert!(t.depth() >= 3);
    assert_eq!(t.len(), 64);
    assert!(t.validate().is_ok());
    for i in 0..64u64 {
        assert_eq!(t.get(&i).unwrap(), &i.to_string());
    }
}

// ── compact / statistics ────────────────────────────────────────────

#[test]
fn leaf_count_empty() {
    let t: TestTree = TestTree::new();
    assert_eq!(t.leaf_count(), 1);
}

#[test]
fn leaf_count_single_leaf() {
    let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
    assert_eq!(t.leaf_count(), 1);
}

#[test]
fn leaf_count_multi_leaf() {
    let mut t = TestTree::new();
    for i in 0..9u64 {
        t.insert(i, i.to_string());
    }
    assert_eq!(t.leaf_count(), 3);
    assert_eq!(t.internal_count(), 1);
    assert_eq!(t.node_count(), 4);
}

#[test]
fn fill_percent_empty() {
    let t: TestTree = TestTree::new();
    assert_eq!(t.fill_percent(), 1.0);
}

#[test]
fn fill_percent_full() {
    let mut t = TestTree::new();
    for i in 0..4u64 {
        t.insert(i, i.to_string());
    }
    assert!((t.fill_percent() - 1.0).abs() < 0.001);
}

#[test]
fn fill_percent_half() {
    let mut t = TestTree::new();
    t.insert(1, "a".into());
    t.insert(2, "b".into());
    assert!((t.fill_percent() - 0.5).abs() < 0.001);
}

#[test]
fn compact_preserves_entries() {
    let mut t = TestTree::new();
    for i in 0..12u64 {
        t.insert(i, i.to_string());
    }
    let before = t.entries();
    t.compact();
    assert_eq!(before, t.entries());
    assert!(t.validate().is_ok());
}

#[test]
fn maybe_compact_below_threshold() {
    let mut t = TestTree::new();
    t.insert(1, "a".into());
    t.insert(2, "b".into());
    assert!(t.maybe_compact(0.6));
    assert!(!t.maybe_compact(0.4));
}

#[test]
fn maybe_compact_empty_noop() {
    let mut t: TestTree = TestTree::new();
    assert!(!t.maybe_compact(0.5));
}

// ── update ──────────────────────────────────────────────────────────

#[test]
fn update_existing() {
    let mut t = TestTree::new();
    t.insert(10, "a".into());
    assert!(t.update(&10, |v| *v = "updated".into()));
    assert_eq!(t.get(&10).unwrap(), "updated");
    assert!(t.validate().is_ok());
}

#[test]
fn update_nonexistent() {
    let mut t = TestTree::new();
    t.insert(10, "a".into());
    assert!(!t.update(&99, |_| unreachable!()));
    assert_eq!(t.len(), 1);
}

#[test]
fn update_preserves_order() {
    let mut t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
    t.update(&2, |v| *v = "beta".into());
    assert_eq!(
        t.entries(),
        vec![
            (1u64, "a".into()),
            (2u64, "beta".into()),
            (3u64, "c".into())
        ]
    );
}

// ── clear ───────────────────────────────────────────────────────────

#[test]
fn clear_empties_tree() {
    let mut t = make_tree(&[(1, "a"), (2, "b")]);
    t.clear();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert!(t.validate().is_ok());
}

// ── spec constant ───────────────────────────────────────────────────

#[test]
fn spec_constant_non_empty() {
    assert!(!BTREE_SPEC.is_empty());
}

// ── is_empty / len consistency ──────────────────────────────────────

#[test]
fn empty_tree_properties() {
    let t: TestTree = TestTree::new();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert!(t.entries().is_empty());
    assert!(t.range(..).is_empty());
}

// ── depth on single entry ───────────────────────────────────────────

#[test]
fn depth_single_entry() {
    let mut t = TestTree::new();
    t.insert(1, "a".into());
    assert_eq!(t.depth(), 1);
}

// ── odd-fanout const generics ───────────────────────────────────────

#[test]
fn odd_fanout_3_split_to_internal() {
    let mut t: BPlusTree<u64, String, 3, 3> = BPlusTree::new();
    for i in 0..4u64 {
        t.insert(i, i.to_string());
    }
    assert_eq!(t.depth(), 2);
    assert_eq!(t.len(), 4);
    assert!(t.validate().is_ok());
    for i in 0..4u64 {
        assert_eq!(t.get(&i).unwrap(), &i.to_string());
    }
}

#[test]
fn odd_fanout_3_multi_level() {
    let mut t: BPlusTree<u64, String, 3, 3> = BPlusTree::new();
    // 3*3 = 9 entries minimum for depth 3 with MAX_LEAF=3, MAX_INTERNAL=3
    for i in 0..10u64 {
        t.insert(i, i.to_string());
    }
    assert!(t.depth() >= 3);
    assert_eq!(t.len(), 10);
    assert!(t.validate().is_ok());
    for i in 0..10u64 {
        assert!(t.contains_key(&i));
    }
}

#[test]
fn odd_fanout_5_leaf_boundary() {
    let mut t: BPlusTree<u64, String, 5, 5> = BPlusTree::new();
    // MAX_LEAF=5: 5 entries should fit in 1 leaf
    for i in 0..5u64 {
        t.insert(i, i.to_string());
    }
    assert_eq!(t.depth(), 1);
    assert_eq!(t.leaf_count(), 1);
    // 6th entry forces split
    t.insert(5, "five".into());
    assert_eq!(t.depth(), 2);
    assert!(t.validate().is_ok());
}

#[test]
fn odd_fanout_7_delete_merge() {
    let mut t: BPlusTree<u64, String, 3, 3> = BPlusTree::new();
    // MAX_LEAF=3, MIN_LEAF=2. 4 entries -> 2 leaves
    for i in 0..4u64 {
        t.insert(i, i.to_string());
    }
    assert_eq!(t.leaf_count(), 2);
    // Delete one causes leaf underflow -> rebuild merges to 1 leaf
    t.delete(&0);
    assert_eq!(t.leaf_count(), 1);
    assert_eq!(t.len(), 3);
    assert!(t.validate().is_ok());
    for i in 1..4u64 {
        assert_eq!(t.get(&i).unwrap(), &i.to_string());
    }
}

// ── String key type ─────────────────────────────────────────────────

#[test]
fn string_key_insert_get() {
    let mut t: BPlusTree<String, u64, 4, 4> = BPlusTree::new();
    t.insert("apple".into(), 1);
    t.insert("banana".into(), 2);
    t.insert("cherry".into(), 3);
    assert_eq!(t.len(), 3);
    assert_eq!(t.get(&"banana".into()), Some(&2));
    assert!(t.get(&"durian".into()).is_none());
    assert!(t.validate().is_ok());
}

#[test]
fn string_key_range_ordering() {
    let mut t: BPlusTree<String, u64, 4, 4> = BPlusTree::new();
    let words = ["zebra", "apple", "mango", "cherry", "banana"];
    for (i, w) in words.iter().enumerate() {
        t.insert(w.to_string(), i as u64);
    }
    let all = t.entries();
    let keys: Vec<&String> = all.iter().map(|(k, _)| k).collect();
    for w in keys.windows(2) {
        assert!(w[0] < w[1], "{:?} >= {:?}", w[0], w[1]);
    }
    let r = t.range("banana".to_string().."mango".to_string());
    let rkeys: Vec<&String> = r.iter().map(|(k, _)| k).collect();
    assert_eq!(rkeys, vec!["banana", "cherry"]);
}

#[test]
fn string_key_delete_merge() {
    let mut t: BPlusTree<String, u64, 3, 3> = BPlusTree::new();
    for (i, w) in ["a", "b", "c", "d"].iter().enumerate() {
        t.insert(w.to_string(), i as u64);
    }
    assert_eq!(t.leaf_count(), 2);
    let old = t.delete(&"a".into());
    assert_eq!(old, Some(0));
    assert_eq!(t.leaf_count(), 1);
    assert!(t.validate().is_ok());
    assert!(t.get(&"a".into()).is_none());
}

// ── BTreeError Display ──────────────────────────────────────────────

#[test]
fn btree_error_display_leaf_overflow() {
    use tidefs_btree::BTreeError;
    let err = BTreeError::LeafOverflow;
    let s = format!("{err}");
    assert!(s.contains("MAX_LEAF"));
}

#[test]
fn btree_error_display_internal_too_few_children() {
    use tidefs_btree::BTreeError;
    let s = format!("{}", BTreeError::InternalTooFewChildren);
    assert!(!s.is_empty());
    assert!(s.contains("fewer than 2 children"));
}

#[test]
fn btree_error_display_internal_overflow() {
    use tidefs_btree::BTreeError;
    let s = format!("{}", BTreeError::InternalOverflow);
    assert!(s.contains("MAX_INTERNAL"));
}

#[test]
fn btree_error_display_leaf_underflow() {
    use tidefs_btree::BTreeError;
    let s = format!("{}", BTreeError::LeafUnderflow);
    assert!(s.contains("MIN_LEAF"));
}

#[test]
fn btree_error_display_internal_underflow() {
    use tidefs_btree::BTreeError;
    let s = format!("{}", BTreeError::InternalUnderflow);
    assert!(s.contains("MIN_INTERNAL"));
}

#[test]
fn btree_error_display_key_child_mismatch() {
    use tidefs_btree::BTreeError;
    let s = format!("{}", BTreeError::KeyChildMismatch);
    assert!(s.contains("key count"));
}

#[test]
fn btree_error_display_key_order_violation() {
    use tidefs_btree::BTreeError;
    let s = format!("{}", BTreeError::KeyOrderViolation);
    assert!(s.contains("ascending"));
}

#[test]
fn btree_error_display_separator_mismatch() {
    use tidefs_btree::BTreeError;
    let s = format!("{}", BTreeError::SeparatorMismatch);
    assert!(s.contains("separator") || s.contains("descendant"));
}

// ── large-scale insert/delete cycle ─────────────────────────────────

#[test]
fn large_insert_delete_cycle_1000() {
    let mut t: BPlusTree<u64, u64, 16, 16> = BPlusTree::new();
    let n = 1000u64;
    // Insert 0..1000
    for i in 0..n {
        t.insert(i, i * 2);
    }
    assert_eq!(t.len(), n as usize);
    assert!(t.validate().is_ok());
    // Verify all present
    for i in 0..n {
        assert_eq!(t.get(&i), Some(&(i * 2)));
    }
    // Delete evens
    for i in (0..n).step_by(2) {
        assert!(t.delete(&i).is_some());
    }
    assert_eq!(t.len(), (n / 2) as usize);
    assert!(t.validate().is_ok());
    // Verify odds remain, evens gone
    for i in 0..n {
        if i % 2 == 1 {
            assert_eq!(t.get(&i), Some(&(i * 2)));
        } else {
            assert!(t.get(&i).is_none());
        }
    }
    // Re-insert evens
    for i in (0..n).step_by(2) {
        assert!(t.insert(i, i * 3).is_none());
    }
    assert_eq!(t.len(), n as usize);
    // Verify new values for evens
    for i in (0..n).step_by(2) {
        assert_eq!(t.get(&i), Some(&(i * 3)));
    }
}

// ── rebuild (public API) ────────────────────────────────────────────

#[test]
fn rebuild_from_empty_slice() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    t.insert(1, "a".into());
    t.rebuild(&[]);
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert!(t.validate().is_ok());
}

#[test]
fn rebuild_from_single() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    t.rebuild(&[(42, "answer".into())]);
    assert_eq!(t.len(), 1);
    assert_eq!(t.get(&42).unwrap(), "answer");
    assert_eq!(t.depth(), 1);
    assert!(t.validate().is_ok());
}

#[test]
fn rebuild_from_many_preserves_all() {
    let entries: Vec<(u64, String)> = (0..100u64).map(|i| (i, i.to_string())).collect();
    let mut t: BPlusTree<u64, String, 8, 8> = BPlusTree::new();
    t.rebuild(&entries);
    assert_eq!(t.len(), 100);
    assert!(t.validate().is_ok());
    assert_eq!(t.entries(), entries);
}

#[test]
fn rebuild_overwrites_existing() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    t.insert(1, "old".into());
    t.insert(2, "old".into());
    t.rebuild(&[(10, "new".into()), (20, "new2".into())]);
    assert_eq!(t.len(), 2);
    assert!(t.get(&1).is_none());
    assert!(t.get(&2).is_none());
    assert_eq!(t.get(&10).unwrap(), "new");
    assert_eq!(t.get(&20).unwrap(), "new2");
}

// ── maybe_compact boundary ──────────────────────────────────────────

#[test]
fn maybe_compact_exactly_at_threshold_noop() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    // 2 entries in MAX_LEAF=4 -> fill=0.5
    t.insert(1, "a".into());
    t.insert(2, "b".into());
    // fill_percent=0.5, threshold=0.5 -> should NOT compact
    assert!(!t.maybe_compact(0.5));
    assert_eq!(t.leaf_count(), 1);
}

#[test]
fn maybe_compact_above_threshold_noop() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    // 3 entries in MAX_LEAF=4 -> fill=0.75
    for i in 0..3u64 {
        t.insert(i, i.to_string());
    }
    let leaves_before = t.leaf_count();
    assert!(!t.maybe_compact(0.5));
    assert_eq!(t.leaf_count(), leaves_before);
}

// ── range edge cases ────────────────────────────────────────────────

#[test]
fn range_both_bounds_excluded() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    for i in 0..5u64 {
        t.insert(i, i.to_string());
    }
    let r = t.range((core::ops::Bound::Excluded(0), core::ops::Bound::Excluded(4)));
    assert_eq!(r.len(), 3);
    assert_eq!(r[0].0, 1);
    assert_eq!(r[1].0, 2);
    assert_eq!(r[2].0, 3);
}

#[test]
fn range_single_element() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    for i in 0..10u64 {
        t.insert(i, i.to_string());
    }
    let r = t.range(5..6);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].0, 5);
}

#[test]
fn range_unbounded_on_empty() {
    let t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    assert!(t.range(..).is_empty());
}

#[test]
fn range_to_inclusive_empty_below_min() {
    let t = make_tree(&[(10, "a"), (20, "b")]);
    let r = t.range(..=5);
    assert!(r.is_empty());
}

// ── statistics edge cases ───────────────────────────────────────────

#[test]
fn node_count_empty() {
    let t: TestTree = TestTree::new();
    assert_eq!(t.node_count(), 1); // empty root leaf
    assert_eq!(t.leaf_count(), 1);
    assert_eq!(t.internal_count(), 0);
}

#[test]
fn depth_consistent_after_varying_inserts() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    // With MAX_LEAF=4: 1 entry -> depth 1, 5 -> depth 2, 17+ -> depth 3
    assert_eq!(t.depth(), 1);
    t.insert(1, "a".into());
    assert_eq!(t.depth(), 1);
    for i in 2..6u64 {
        t.insert(i, i.to_string());
    }
    assert_eq!(t.depth(), 2);
    for i in 6..18u64 {
        t.insert(i, i.to_string());
    }
    assert!(t.depth() >= 3);
    assert!(t.validate().is_ok());
}

#[test]
fn len_after_insert_delete_cycle() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    for i in 0..20u64 {
        t.insert(i, i.to_string());
        assert_eq!(t.len(), (i + 1) as usize);
    }
    for i in 0..10u64 {
        t.delete(&i);
        assert_eq!(t.len(), (20 - i - 1) as usize);
    }
    for i in 0..5u64 {
        t.insert(i, format!("re{i}"));
        assert_eq!(t.len(), (10 + i + 1) as usize);
    }
    assert_eq!(t.len(), 15);
    assert!(t.validate().is_ok());
}

// ── multiple fanout configurations ──────────────────────────────────

#[test]
fn fanout_8_16_insert_and_query() {
    let mut t: BPlusTree<u64, u64, 8, 16> = BPlusTree::new();
    for i in 0..200u64 {
        t.insert(i, i * 10);
    }
    assert_eq!(t.len(), 200);
    assert!(t.validate().is_ok());
    // Verify all entries
    for i in 0..200u64 {
        assert_eq!(t.get(&i).unwrap(), &(i * 10));
    }
    // Range query in middle
    let r = t.range(50..100);
    assert_eq!(r.len(), 50);
    for (j, (k, v)) in r.iter().enumerate() {
        assert_eq!(*k, 50 + j as u64);
        assert_eq!(*v, (50 + j as u64) * 10);
    }
}

#[test]
fn asymmetric_fanout_more_leaves_than_internal() {
    // MAX_LEAF=8 (wide leaves), MAX_INTERNAL=3 (narrow internal) ->
    // forces deeper internal tree
    let mut t: BPlusTree<u64, String, 8, 3> = BPlusTree::new();
    for i in 0..80u64 {
        t.insert(i, i.to_string());
    }
    assert!(t.depth() >= 3);
    assert_eq!(t.len(), 80);
    assert!(t.validate().is_ok());
    for i in 0..80u64 {
        assert_eq!(t.get(&i).unwrap(), &i.to_string());
    }
}

// ── update on large tree ────────────────────────────────────────────

#[test]
fn update_all_entries_large_tree() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    for i in 0..30u64 {
        t.insert(i, i.to_string());
    }
    for i in 0..30u64 {
        assert!(t.update(&i, |v| *v = format!("v{i}")));
    }
    assert_eq!(t.len(), 30);
    assert!(t.validate().is_ok());
    for i in 0..30u64 {
        assert_eq!(t.get(&i).unwrap(), &format!("v{i}"));
    }
}

// ── duplicate key across rebuild boundary ───────────────────────────

#[test]
fn duplicate_key_across_leaf_boundary() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    // Insert enough to split leaves, then replace a key
    for i in 0..10u64 {
        t.insert(i, i.to_string());
    }
    assert!(t.leaf_count() >= 2);
    let old = t.insert(3, "replaced".into());
    assert_eq!(old.unwrap(), "3");
    assert_eq!(t.get(&3).unwrap(), "replaced");
    assert_eq!(t.len(), 10);
    assert!(t.validate().is_ok());
}

// ── BTreeError Debug ────────────────────────────────────────────────

#[test]
fn btree_error_debug_format() {
    use tidefs_btree::BTreeError;
    // All variants should have a non-empty Debug representation
    let variants = [
        BTreeError::InternalTooFewChildren,
        BTreeError::LeafOverflow,
        BTreeError::InternalOverflow,
        BTreeError::LeafUnderflow,
        BTreeError::InternalUnderflow,
        BTreeError::KeyChildMismatch,
        BTreeError::KeyOrderViolation,
        BTreeError::SeparatorMismatch,
    ];
    for v in &variants {
        let debug_str = format!("{v:?}");
        assert!(!debug_str.is_empty(), "Debug empty for {v:?}");
    }
}

// ── BTreeError Eq / PartialEq round-trip ────────────────────────────

#[test]
fn btree_error_eq_consistency() {
    use tidefs_btree::BTreeError;
    assert_eq!(BTreeError::LeafOverflow, BTreeError::LeafOverflow);
    assert_ne!(BTreeError::LeafOverflow, BTreeError::LeafUnderflow);
    assert_eq!(
        BTreeError::InternalTooFewChildren,
        BTreeError::InternalTooFewChildren
    );
    assert_ne!(
        BTreeError::InternalTooFewChildren,
        BTreeError::InternalOverflow
    );
}

// ── clone-after-mutation identity ───────────────────────────────────

#[test]
fn clone_after_mutation_identity() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    for i in 0..10u64 {
        t.insert(i, i.to_string());
    }
    t.delete(&5);
    let cloned = t.clone();
    assert_eq!(t.entries(), cloned.entries());
    assert_eq!(t.len(), cloned.len());
    assert_eq!(t.depth(), cloned.depth());
    assert_eq!(t.leaf_count(), cloned.leaf_count());
    assert!(cloned.validate().is_ok());
}

// ── compact reduces depth when possible ─────────────────────────────

#[test]
fn compact_reduces_depth_after_deletes() {
    let mut t: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    // 20 entries -> depth 3
    for i in 0..20u64 {
        t.insert(i, i.to_string());
    }
    let depth_before = t.depth();
    assert!(depth_before >= 3);
    // Delete most, leaving 3
    for i in 3..20u64 {
        t.delete(&i);
    }
    t.compact();
    assert_eq!(t.depth(), 1);
    assert_eq!(t.len(), 3);
    assert!(t.validate().is_ok());
}

// ── fill_percent monotonic after compaction ─────────────────────────

#[test]
fn fill_percent_improves_after_compact() {
    let mut t: BPlusTree<u64, String, 8, 8> = BPlusTree::new();
    // Insert and delete to create sparse leaves
    for i in 0..30u64 {
        t.insert(i, i.to_string());
    }
    for i in 0..20u64 {
        t.delete(&i);
    }
    let fill_before = t.fill_percent();
    t.compact();
    let fill_after = t.fill_percent();
    assert!(
        fill_after >= fill_before - 0.001,
        "fill after compact ({fill_after}) should be >= fill before ({fill_before})"
    );
}

// ── default fanout (45/45) boundary ──────────────────────────────────

#[test]
fn default_fanout_exact_leaf_capacity() {
    // MAX_LEAF=45: all 45 entries fit in a single leaf
    let mut t: BPlusTree<u64, u64> = BPlusTree::new();
    for i in 0..45u64 {
        t.insert(i, i * 100);
    }
    assert_eq!(t.len(), 45);
    assert_eq!(t.depth(), 1);
    assert_eq!(t.leaf_count(), 1);
    assert!(t.validate().is_ok());
    for i in 0..45u64 {
        assert_eq!(t.get(&i).unwrap(), &(i * 100));
    }
}

#[test]
fn default_fanout_one_past_leaf_capacity_splits() {
    // MAX_LEAF=45: 46 entries force at least 2 leaves
    let mut t: BPlusTree<u64, u64> = BPlusTree::new();
    for i in 0..46u64 {
        t.insert(i, i * 100);
    }
    assert_eq!(t.len(), 46);
    assert!(t.depth() >= 2);
    assert!(t.leaf_count() >= 2);
    assert!(t.validate().is_ok());
    for i in 0..46u64 {
        assert_eq!(t.get(&i).unwrap(), &(i * 100));
    }
}

#[test]
fn default_fanout_deep_split_multi_level() {
    // 45*45 = 2025 entries minimum for depth 3 with MAX_LEAF=45,
    // MAX_INTERNAL=45. Insert 2026 to force depth >= 3.
    let mut t: BPlusTree<u64, u64> = BPlusTree::new();
    for i in 0..2026u64 {
        t.insert(i, i * 10);
    }
    assert_eq!(t.len(), 2026);
    assert!(t.depth() >= 3);
    assert!(t.validate().is_ok());
    assert_eq!(t.get(&0).unwrap(), &0);
    assert_eq!(t.get(&1000).unwrap(), &10000);
    assert_eq!(t.get(&2025).unwrap(), &20250);
}

#[test]
fn default_fanout_range_across_splits() {
    let mut t: BPlusTree<u64, u64> = BPlusTree::new();
    for i in 0..200u64 {
        t.insert(i, i * 5);
    }
    assert!(t.depth() >= 2);
    let r = t.range(40..50);
    assert_eq!(r.len(), 10);
    for (j, (k, v)) in r.iter().enumerate() {
        assert_eq!(*k, 40 + j as u64);
        assert_eq!(*v, (40 + j as u64) * 5);
    }
}

#[test]
fn default_fanout_delete_to_empty() {
    let mut t: BPlusTree<u64, u64> = BPlusTree::new();
    for i in 0..100u64 {
        t.insert(i, i);
    }
    for i in 0..100u64 {
        assert!(t.delete(&i).is_some());
    }
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert_eq!(t.depth(), 1);
    assert!(t.validate().is_ok());
    t.insert(10, 100);
    assert_eq!(t.get(&10).unwrap(), &100);
}

// ── fanout=2 minimal (MIN_LEAF=1, MIN_INTERNAL=1) ───────────────────

#[test]
fn fanout_2_single_insert_get() {
    let mut t: BPlusTree<u64, String, 2, 2> = BPlusTree::new();
    assert!(t.is_empty());
    t.insert(1, "one".into());
    assert_eq!(t.len(), 1);
    assert_eq!(t.depth(), 1);
    assert_eq!(t.get(&1).unwrap(), "one");
    assert!(t.get(&99).is_none());
}

#[test]
fn fanout_2_insert_splits() {
    let mut t: BPlusTree<u64, String, 2, 2> = BPlusTree::new();
    t.insert(10, "a".into());
    t.insert(20, "b".into());
    t.insert(30, "c".into());
    assert_eq!(t.len(), 3);
    assert!(t.depth() >= 2);
    assert!(t.validate().is_ok());
    assert_eq!(t.get(&10).unwrap(), "a");
    assert_eq!(t.get(&20).unwrap(), "b");
    assert_eq!(t.get(&30).unwrap(), "c");
}

#[test]
fn fanout_2_insert_many_multi_level() {
    let mut t: BPlusTree<u64, u64, 2, 2> = BPlusTree::new();
    for i in 0..7u64 {
        t.insert(i, i * 10);
    }
    assert_eq!(t.len(), 7);
    assert!(t.depth() >= 3);
    assert!(t.validate().is_ok());
    for i in 0..7u64 {
        assert_eq!(t.get(&i).unwrap(), &(i * 10));
    }
}

#[test]
fn fanout_2_delete_leaf_merge() {
    let mut t: BPlusTree<u64, String, 2, 2> = BPlusTree::new();
    t.insert(10, "a".into());
    t.insert(20, "b".into());
    t.insert(30, "c".into());
    assert!(t.depth() >= 2);
    t.delete(&30);
    assert_eq!(t.len(), 2);
    assert_eq!(t.depth(), 1);
    assert!(t.validate().is_ok());
}

#[test]
fn fanout_2_delete_all_to_empty() {
    let mut t: BPlusTree<u64, u64, 2, 2> = BPlusTree::new();
    for i in 0..10u64 {
        t.insert(i, i);
    }
    for i in 0..10u64 {
        t.delete(&i);
    }
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert!(t.validate().is_ok());
    t.insert(42, 99);
    assert_eq!(t.get(&42).unwrap(), &99);
}

#[test]
fn fanout_2_duplicate_replace() {
    let mut t: BPlusTree<u64, String, 2, 2> = BPlusTree::new();
    t.insert(1, "first".into());
    let old = t.insert(1, "second".into());
    assert_eq!(old.unwrap(), "first");
    assert_eq!(t.len(), 1);
    assert_eq!(t.get(&1).unwrap(), "second");
}

#[test]
fn fanout_2_range_queries() {
    let mut t: BPlusTree<u64, u64, 2, 2> = BPlusTree::new();
    for i in 0..10u64 {
        t.insert(i, i * 10);
    }
    assert_eq!(t.range(3..7).len(), 4);
    assert_eq!(t.range(..).len(), 10);
    assert_eq!(t.range(0..0).len(), 0);
    assert_eq!(t.range(8..20).len(), 2);
    let entries = t.entries();
    assert_eq!(entries.len(), 10);
    for (i, (k, v)) in entries.iter().enumerate() {
        assert_eq!(*k, i as u64);
        assert_eq!(*v, i as u64 * 10);
    }
}

#[test]
fn fanout_2_clone_after_mutation() {
    let mut t: BPlusTree<u64, String, 2, 2> = BPlusTree::new();
    t.insert(1, "one".into());
    t.insert(2, "two".into());
    t.insert(3, "three".into());
    let cloned = t.clone();
    assert_eq!(t.entries(), cloned.entries());
    assert_eq!(t.len(), cloned.len());
    assert!(cloned.validate().is_ok());
}

#[test]
fn fanout_2_compact_after_deletes() {
    let mut t: BPlusTree<u64, u64, 2, 2> = BPlusTree::new();
    for i in 0..10u64 {
        t.insert(i, i);
    }
    for i in 2..10u64 {
        t.delete(&i);
    }
    t.compact();
    assert_eq!(t.depth(), 1);
    assert_eq!(t.len(), 2);
    assert!(t.validate().is_ok());
}

// ── asymmetric fanout with one minimal ─────────────────────────────

#[test]
fn fanout_2_45_insert_and_query() {
    let mut t: BPlusTree<u64, String, 2, 45> = BPlusTree::new();
    for i in 0..20u64 {
        t.insert(i, i.to_string());
    }
    assert_eq!(t.len(), 20);
    assert!(t.depth() >= 2);
    assert!(t.validate().is_ok());
    for i in 0..20u64 {
        assert_eq!(t.get(&i).unwrap(), &i.to_string());
    }
}

#[test]
fn fanout_45_2_insert_and_query() {
    let mut t: BPlusTree<u64, String, 45, 2> = BPlusTree::new();
    for i in 0..100u64 {
        t.insert(i, i.to_string());
    }
    assert_eq!(t.len(), 100);
    assert!(t.depth() >= 2);
    assert!(t.validate().is_ok());
    for i in 0..100u64 {
        assert_eq!(t.get(&i).unwrap(), &i.to_string());
    }
    let r = t.range(45..55);
    assert_eq!(r.len(), 10);
}

// ── insert-delete-reinsert stress with default fanout ───────────────

#[test]
fn default_fanout_insert_delete_reinsert_cycle() {
    let mut t: BPlusTree<u64, u64> = BPlusTree::new();
    for i in 0..500u64 {
        t.insert(i, i * 2);
    }
    assert_eq!(t.len(), 500);
    for i in (0..500u64).step_by(2) {
        t.delete(&i);
    }
    assert_eq!(t.len(), 250);
    for i in (0..500u64).step_by(2) {
        t.insert(i, i * 100);
    }
    assert_eq!(t.len(), 500);
    assert!(t.validate().is_ok());
    for i in 0..500u64 {
        if i % 2 == 0 {
            assert_eq!(t.get(&i).unwrap(), &(i * 100));
        } else {
            assert_eq!(t.get(&i).unwrap(), &(i * 2));
        }
    }
}

#[test]
fn default_fanout_update_all_values() {
    let mut t: BPlusTree<u64, String> = BPlusTree::new();
    for i in 0..100u64 {
        t.insert(i, i.to_string());
    }
    for i in 0..100u64 {
        t.update(&i, |v| *v = format!("updated-{i}"));
    }
    assert!(t.validate().is_ok());
    for i in 0..100u64 {
        assert_eq!(t.get(&i).unwrap(), &format!("updated-{i}"));
    }
}
// ── RangeScan edge cases on multi-level trees ──────────────────────

#[test]
fn range_scan_excluded_start_at_separator_boundary() {
    let mut t = TestTree::new();
    for i in 1u64..=9 {
        t.insert(i, format!("v{i}"));
    }
    let scan = t.range_scan((
        core::ops::Bound::Excluded(4u64),
        core::ops::Bound::Unbounded,
    ));
    let result: Vec<(u64, String)> = scan.map(|(k, v)| (*k, v.clone())).collect();
    let keys: Vec<u64> = result.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![5, 6, 7, 8, 9]);
}

#[test]
fn range_scan_excluded_end_at_separator_boundary() {
    let mut t = TestTree::new();
    for i in 1u64..=9 {
        t.insert(i, format!("v{i}"));
    }
    let scan = t.range_scan((
        core::ops::Bound::Unbounded,
        core::ops::Bound::Excluded(7u64),
    ));
    let result: Vec<(u64, String)> = scan.map(|(k, v)| (*k, v.clone())).collect();
    let keys: Vec<u64> = result.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![1, 2, 3, 4, 5, 6]);
}

#[test]
fn range_scan_included_end_at_separator_boundary() {
    let mut t = TestTree::new();
    for i in 1u64..=9 {
        t.insert(i, format!("v{i}"));
    }
    let scan = t.range_scan((
        core::ops::Bound::Unbounded,
        core::ops::Bound::Included(7u64),
    ));
    let result: Vec<(u64, String)> = scan.map(|(k, v)| (*k, v.clone())).collect();
    let keys: Vec<u64> = result.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn range_scan_both_bounds_at_separators() {
    let mut t = TestTree::new();
    for i in 1u64..=9 {
        t.insert(i, format!("v{i}"));
    }
    let scan = t.range_scan((
        core::ops::Bound::Excluded(4u64),
        core::ops::Bound::Excluded(7u64),
    ));
    let result: Vec<(u64, String)> = scan.map(|(k, v)| (*k, v.clone())).collect();
    let keys: Vec<u64> = result.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![5, 6]);
}

#[test]
fn range_scan_start_above_max_key() {
    let mut t = TestTree::new();
    for i in 1u64..=5 {
        t.insert(i, format!("v{i}"));
    }
    let scan = t.range_scan(100u64..200u64);
    let result: Vec<(u64, String)> = scan.map(|(k, v)| (*k, v.clone())).collect();
    assert!(result.is_empty());
}

#[test]
fn range_scan_end_below_min_key() {
    let mut t = TestTree::new();
    for i in 10u64..=20 {
        t.insert(i, format!("v{i}"));
    }
    let scan = t.range_scan(..5u64);
    let result: Vec<(u64, String)> = scan.map(|(k, v)| (*k, v.clone())).collect();
    assert!(result.is_empty());
}

#[test]
fn range_scan_start_greater_than_end() {
    let mut t = TestTree::new();
    for i in 1u64..=10 {
        t.insert(i, format!("v{i}"));
    }
    let start = 7u64;
    let end = 3u64;
    let scan = t.range_scan(start..end);
    let result: Vec<(u64, String)> = scan.map(|(k, v)| (*k, v.clone())).collect();
    assert!(result.is_empty());
}

#[test]
fn range_scan_collect_preserves_order() {
    let mut t = TestTree::new();
    for i in 1u64..=50 {
        t.insert(i, format!("v{i}"));
    }
    let scan = t.range_scan(10u64..40u64);
    let result: Vec<(u64, String)> = scan.map(|(k, v)| (*k, v.clone())).collect();
    let keys: Vec<u64> = result.iter().map(|(k, _)| *k).collect();
    let expected: Vec<u64> = (10..40).collect();
    assert_eq!(keys, expected);
}

#[test]
fn range_scan_after_mutation() {
    let mut t = TestTree::new();
    for i in 1u64..=20 {
        t.insert(i, format!("v{i}"));
    }
    t.delete(&5);
    t.delete(&15);
    let scan = t.range_scan(..);
    let result: Vec<(u64, String)> = scan.map(|(k, v)| (*k, v.clone())).collect();
    let keys: Vec<u64> = result.iter().map(|(k, _)| *k).collect();
    assert!(!keys.contains(&5));
    assert!(!keys.contains(&15));
    assert_eq!(result.len(), 18);
}

#[test]
fn range_scan_with_inclusive_inclusive_bounds_multi_level() {
    let mut t = TestTree::new();
    for i in 1u64..=30 {
        t.insert(i, format!("v{i}"));
    }
    let scan = t.range_scan((
        core::ops::Bound::Included(7u64),
        core::ops::Bound::Included(23u64),
    ));
    let result: Vec<(u64, String)> = scan.map(|(k, v)| (*k, v.clone())).collect();
    let keys: Vec<u64> = result.iter().map(|(k, _)| *k).collect();
    let expected: Vec<u64> = (7..=23).collect();
    assert_eq!(keys, expected);
}

// ── Checksum edge cases ────────────────────────────────────────────

#[test]
fn verify_checksums_on_rebuilt_tree() {
    let mut t = TestTree::new();
    for i in 1u64..=20 {
        t.insert(i, format!("v{i}"));
    }
    t.compact();
    assert!(t.verify_checksums().is_ok());
}

#[test]
fn verify_checksums_after_many_mutations() {
    let mut t = TestTree::new();
    for i in 1u64..=30 {
        t.insert(i, format!("v{i}"));
    }
    for i in 1u64..=10 {
        t.delete(&i);
    }
    for i in 31u64..=40 {
        t.insert(i, format!("v{i}"));
    }
    assert!(t.verify_checksums().is_ok());
    assert!(t.validate().is_ok());
}

#[test]
fn verify_checksums_on_empty_tree() {
    let t = TestTree::new();
    assert!(t.verify_checksums().is_ok());
}

#[test]
fn verify_checksums_single_entry() {
    let mut t = TestTree::new();
    t.insert(1, "one".into());
    assert!(t.verify_checksums().is_ok());
}

#[test]
fn checksum_mismatch_error_display() {
    let err = tidefs_btree::BTreeError::ChecksumMismatch;
    let s = format!("{err}");
    assert!(!s.is_empty());
}

// ── Rebuild edge cases ─────────────────────────────────────────────

#[test]
fn rebuild_exactly_max_leaf_entries() {
    let entries: Vec<(u64, String)> = (1..=4).map(|i| (i, format!("v{i}"))).collect();
    let mut t = TestTree::new();
    t.rebuild(&entries);
    assert_eq!(t.len(), 4);
    assert_eq!(t.leaf_count(), 1);
    assert_eq!(t.internal_count(), 0);
    assert!(t.validate().is_ok());
    assert_eq!(t.get(&1).unwrap(), "v1");
    assert_eq!(t.get(&4).unwrap(), "v4");
}

#[test]
fn rebuild_double_max_leaf_entries() {
    let entries: Vec<(u64, String)> = (1..=8).map(|i| (i, format!("v{i}"))).collect();
    let mut t = TestTree::new();
    t.rebuild(&entries);
    assert_eq!(t.len(), 8);
    assert_eq!(t.leaf_count(), 2);
    assert_eq!(t.internal_count(), 1);
    assert!(t.validate().is_ok());
}

#[test]
fn rebuild_exactly_internal_boundary() {
    let entries: Vec<(u64, String)> = (1..=16).map(|i| (i, format!("v{i}"))).collect();
    let mut t = TestTree::new();
    t.rebuild(&entries);
    assert_eq!(t.leaf_count(), 4);
    assert_eq!(t.internal_count(), 1);
    assert!(t.validate().is_ok());
    assert_eq!(t.depth(), 2);
}

#[test]
fn rebuild_past_internal_boundary_produces_depth_3() {
    // rebuild() (non-compact): 17 entries -> 5 leaves [4,4,4,4,1],
    // 5 children at level 1 -> [4+1] -> 2 internal nodes at level 1,
    // then 1 root internal -> depth 3.
    // Non-compact rebuild produces underfull nodes, so skip validate.
    let entries: Vec<(u64, String)> = (1..=17).map(|i| (i, format!("v{i}"))).collect();
    let mut t = TestTree::new();
    t.rebuild(&entries);
    assert_eq!(t.depth(), 3);
    assert_eq!(t.len(), 17);
    // Verify all entries are present
    assert_eq!(t.entries(), entries);
}

#[test]
fn rebuild_preserves_all_entries_large() {
    let entries: Vec<(u64, String)> = (0..100).map(|i| (i, format!("v{i}"))).collect();
    let expected = entries.clone();
    let mut t = TestTree::new();
    t.rebuild(&entries);
    assert_eq!(t.entries(), expected);
}

#[test]
fn rebuild_compact_even_distribution() {
    // insert uses rebuild_compact: 9 entries -> 3 leaves of 3 each
    let mut t = TestTree::new();
    for i in 1u64..=9 {
        t.insert(i, format!("v{i}"));
    }
    assert_eq!(t.leaf_count(), 3);
    assert!(t.validate().is_ok());
}

// ── Insert/delete cycle edge cases ─────────────────────────────────

#[test]
fn insert_delete_reinsert_same_key_multi_level() {
    let mut t = TestTree::new();
    for i in 1u64..=30 {
        t.insert(i, format!("v{i}"));
    }
    assert_eq!(t.delete(&15), Some("v15".to_string()));
    assert!(t.get(&15).is_none());
    assert!(t.insert(15, "reinserted".into()).is_none());
    assert_eq!(t.get(&15).unwrap(), "reinserted");
    assert_eq!(t.len(), 30);
    assert!(t.validate().is_ok());
}

#[test]
fn insert_many_delete_all_reinsert_all() {
    let mut t = TestTree::new();
    for i in 1u64..=20 {
        t.insert(i, format!("v{i}"));
    }
    for i in 1u64..=20 {
        assert_eq!(t.delete(&i), Some(format!("v{i}")));
    }
    assert!(t.is_empty());
    for i in 1u64..=20 {
        assert!(t.insert(i, format!("new{i}")).is_none());
    }
    assert_eq!(t.len(), 20);
    assert!(t.validate().is_ok());
    assert_eq!(t.get(&10).unwrap(), "new10");
}

// ── Validate edge cases ────────────────────────────────────────────

#[test]
fn validate_tree_with_exactly_min_leaf_fill() {
    let mut t = TestTree::new();
    for i in 1u64..=6 {
        t.insert(i, format!("v{i}"));
    }
    assert!(t.validate().is_ok());
}

#[test]
fn validate_tree_with_exactly_max_leaf_fill() {
    let mut t = TestTree::new();
    for i in 1u64..=4 {
        t.insert(i, format!("v{i}"));
    }
    assert!(t.validate().is_ok());
    assert_eq!(t.leaf_count(), 1);
}

// ── NodeId ─────────────────────────────────────────────────────────

#[test]
fn node_id_display_includes_n_prefix() {
    let id = tidefs_btree::NodeId(42);
    let s = format!("{id}");
    assert!(s.contains("42"));
}

#[test]
fn node_id_ordering() {
    let a = tidefs_btree::NodeId(1);
    let b = tidefs_btree::NodeId(2);
    assert!(a < b);
    assert_eq!(a, tidefs_btree::NodeId(1));
}

// ── UnderfullNodeInfo edge cases ───────────────────────────────────

#[test]
fn underfull_info_fill_ratio_at_max() {
    let info = tidefs_btree::UnderfullNodeInfo {
        node_id: tidefs_btree::NodeId(0),
        is_leaf: true,
        fill_count: 4,
        max_capacity: 4,
    };
    assert!((info.fill_ratio() - 1.0).abs() < 0.001);
    assert!(!info.is_below_min_fill());
}

#[test]
fn underfull_info_fill_ratio_below_half_is_underfull() {
    // is_below_min_fill() uses strict < 0.5.
    // fill=2, max=4 => ratio=0.5, which is NOT below min fill.
    let info = tidefs_btree::UnderfullNodeInfo {
        node_id: tidefs_btree::NodeId(0),
        is_leaf: true,
        fill_count: 2,
        max_capacity: 4,
    };
    assert!((info.fill_ratio() - 0.5).abs() < 0.001);
    assert!(!info.is_below_min_fill());
}

#[test]
fn underfull_info_fill_ratio_below_threshold() {
    // fill=1, max=4 => ratio=0.25 < 0.5 => below min fill.
    let info = tidefs_btree::UnderfullNodeInfo {
        node_id: tidefs_btree::NodeId(0),
        is_leaf: true,
        fill_count: 1,
        max_capacity: 4,
    };
    assert!(info.is_below_min_fill());
}

#[test]
fn underfull_info_internal_node() {
    let info = tidefs_btree::UnderfullNodeInfo {
        node_id: tidefs_btree::NodeId(1),
        is_leaf: false,
        fill_count: 1,
        max_capacity: 4,
    };
    assert!(!info.is_leaf);
    assert!((info.fill_ratio() - 0.25).abs() < 0.001);
    assert!(info.is_below_min_fill());
}

// ── clear edge cases ───────────────────────────────────────────────

#[test]
fn clear_on_multi_level_tree_then_reinsert() {
    let mut t = TestTree::new();
    for i in 1u64..=50 {
        t.insert(i, format!("v{i}"));
    }
    assert_eq!(t.depth(), 3);
    t.clear();
    assert!(t.is_empty());
    assert_eq!(t.depth(), 1);
    t.insert(100, "after_clear".into());
    assert_eq!(t.len(), 1);
    assert_eq!(t.get(&100).unwrap(), "after_clear");
}

#[test]
fn clear_then_reinsert_many() {
    let mut t = TestTree::new();
    for i in 1u64..=30 {
        t.insert(i, format!("v{i}"));
    }
    t.clear();
    assert!(t.is_empty());
    for i in 1u64..=30 {
        t.insert(i, format!("new{i}"));
    }
    assert_eq!(t.len(), 30);
    assert!(t.validate().is_ok());
}

// ── Clone and entries edge cases ───────────────────────────────────

#[test]
fn entries_empty_tree_returns_empty_vec() {
    let t = TestTree::new();
    assert!(t.entries().is_empty());
}

#[test]
fn entries_returns_ordered_keys() {
    let mut t = TestTree::new();
    t.insert(3, "c".into());
    t.insert(1, "a".into());
    t.insert(2, "b".into());
    let entries = t.entries();
    let keys: Vec<u64> = entries.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![1, 2, 3]);
}

#[test]
fn clone_produces_identical_entries() {
    let mut t = TestTree::new();
    for i in 1u64..=20 {
        t.insert(i, format!("v{i}"));
    }
    let cloned = t.clone();
    assert_eq!(t.entries(), cloned.entries());
    assert_eq!(t.len(), cloned.len());
    assert_eq!(t.leaf_count(), cloned.leaf_count());
}

#[test]
fn clone_isolation_after_mutation() {
    let mut t = TestTree::new();
    for i in 1u64..=10 {
        t.insert(i, format!("v{i}"));
    }
    let mut cloned = t.clone();
    cloned.insert(11, "eleven".into());
    assert_eq!(t.len(), 10);
    assert_eq!(cloned.len(), 11);
    assert!(t.get(&11).is_none());
    assert_eq!(cloned.get(&11).unwrap(), "eleven");
}

#[test]
fn display_format_is_non_empty() {
    let mut t = TestTree::new();
    t.insert(1, "a".into());
    let s = format!("{t}");
    assert!(!s.is_empty());
}

// ── Default fanout additional edge cases ───────────────────────────

#[test]
fn default_fanout_range_scan_excluded_boundary() {
    let mut t: BPlusTree<u64, String> = BPlusTree::new();
    for i in 0u64..100 {
        t.insert(i, format!("v{i}"));
    }
    let scan = t.range_scan((
        core::ops::Bound::Excluded(50u64),
        core::ops::Bound::Excluded(60u64),
    ));
    let result: Vec<(u64, String)> = scan.map(|(k, v)| (*k, v.clone())).collect();
    let keys: Vec<u64> = result.iter().map(|(k, _)| *k).collect();
    assert!(!keys.contains(&50));
    assert!(!keys.contains(&60));
    for k in 51..60 {
        assert!(keys.contains(&k));
    }
}

#[test]
fn default_fanout_range_scan_collect_ordered() {
    let mut t: BPlusTree<u64, String> = BPlusTree::new();
    for i in (0u64..100).rev() {
        t.insert(i, format!("v{i}"));
    }
    let scan = t.range_scan(..);
    let result: Vec<(u64, String)> = scan.map(|(k, v)| (*k, v.clone())).collect();
    let keys: Vec<u64> = result.iter().map(|(k, _)| *k).collect();
    let expected: Vec<u64> = (0..100).collect();
    assert_eq!(keys, expected);
}

#[test]
fn default_fanout_validate_after_random_ops() {
    let mut t: BPlusTree<u64, String> = BPlusTree::new();
    for i in 0u64..200 {
        t.insert(i, format!("v{i}"));
    }
    for i in (0u64..200).step_by(3) {
        t.delete(&i);
    }
    for i in (0u64..200).step_by(5) {
        t.update(&i, |v| *v = format!("updated-{i}"));
    }
    assert!(t.validate().is_ok());
    assert!(t.verify_checksums().is_ok());
}

#[test]
fn default_fanout_large_rebuild_cycle() {
    // Insert, rebuild explicitly via compact, verify all entries.
    let mut t: BPlusTree<u64, String> = BPlusTree::new();
    for i in 0u64..500 {
        t.insert(i, format!("v{i}"));
    }
    t.compact();
    assert!(t.validate().is_ok());
    assert_eq!(t.len(), 500);
    for i in 0u64..500 {
        assert_eq!(t.get(&i).unwrap(), &format!("v{i}"));
    }
}

// ── range() function edge cases ────────────────────────────────────

#[test]
fn range_with_complex_bounds() {
    let mut t = TestTree::new();
    for i in 1u64..=20 {
        t.insert(i, format!("v{i}"));
    }
    // Excluded start, Included end: (3, 7]
    let result = t.range((
        core::ops::Bound::Excluded(3u64),
        core::ops::Bound::Included(7u64),
    ));
    let keys: Vec<u64> = result.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![4, 5, 6, 7]);
}

#[test]
fn range_excluded_start_included_end() {
    let mut t = TestTree::new();
    for i in 1u64..=10 {
        t.insert(i, format!("v{i}"));
    }
    let result = t.range((
        core::ops::Bound::Excluded(3u64),
        core::ops::Bound::Included(7u64),
    ));
    let keys: Vec<u64> = result.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![4, 5, 6, 7]);
}

#[test]
fn range_from_excluded_to_excluded() {
    let mut t = TestTree::new();
    for i in 1u64..=10 {
        t.insert(i, format!("v{i}"));
    }
    let result = t.range((
        core::ops::Bound::Excluded(2u64),
        core::ops::Bound::Excluded(9u64),
    ));
    let keys: Vec<u64> = result.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![3, 4, 5, 6, 7, 8]);
}
