// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// proptest_roundtrip.rs — Property-based round-trip and invariant tests for
// tidefs-dir-index insert, lookup, delete, and iteration.
//
// These tests complement the deterministic suite with randomized inputs and
// operation sequences. They verify the same invariants at the proptest level.

use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use tidefs_dir_index::{DatasetDirPolicy, DirIndex, DirIndexError, DirIterator};

/// Test policy with small thresholds so promotion/demotion occurs during
/// property tests without needing huge entry counts.
fn test_policy() -> DatasetDirPolicy {
    DatasetDirPolicy {
        dir_micro_max_entries: 6,
        dir_micro_max_name_bytes: 512,
        dir_btree_downshift_entries: 3,
        dir_btree_downshift_name_bytes: 128,
    }
}

/// Strategy generating a random non-empty name (1..32 ASCII alphanumeric bytes).
fn arb_name() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(proptest::char::range('a', 'z'), 1..32)
        .prop_map(|v| v.into_iter().map(|c| c as u8).collect::<Vec<u8>>())
}

/// Strategy generating a small set of unique names (1..max entries).
fn arb_name_set(max: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
    proptest::collection::btree_set(arb_name(), 1..=max)
        .prop_map(|s| s.into_iter().collect::<Vec<Vec<u8>>>())
}

// ---------------------------------------------------------------------------
// Round-trip: insert then lookup
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn insert_lookup_round_trip(
        name in arb_name(),
        inode_id in any::<u64>(),
        generation in any::<u64>(),
        kind in any::<u32>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(&name, inode_id, generation, kind).unwrap();

        let entry = idx.lookup(&name).expect("lookup must succeed after insert");
        assert_eq!(entry.inode_id, inode_id);
        assert_eq!(entry.generation, generation);
        assert_eq!(entry.kind, kind);
        assert_eq!(entry.name, name);
        assert_eq!(entry.name_len as usize, name.len());
        assert_eq!(idx.len(), 1);
        assert!(idx.contains(&name));
    }

    #[test]
    fn insert_many_lookup_all(
        names in arb_name_set(12),
        base_inode in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        let mut expected: HashMap<Vec<u8>, (u64, u64, u32)> = HashMap::new();

        for (i, name) in names.iter().enumerate() {
            let inode_id = base_inode.wrapping_add(i as u64);
            let gen = (i as u64).wrapping_mul(3);
            let kind = (i % 5) as u32;
            idx.insert(name, inode_id, gen, kind).unwrap();
            expected.insert(name.clone(), (inode_id, gen, kind));
        }

        assert_eq!(idx.len(), names.len());

        for (name, &(inode_id, gen, kind)) in &expected {
            let entry = idx.lookup(name).expect("lookup must find inserted entry");
            assert_eq!(entry.inode_id, inode_id, "inode_id mismatch for {name:?}");
            assert_eq!(entry.generation, gen);
            assert_eq!(entry.kind, kind);
            assert_eq!(&entry.name, name);
        }
    }

    #[test]
    fn insert_duplicate_is_error(
        name in arb_name(),
        inode_id_a in any::<u64>(),
        inode_id_b in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(&name, inode_id_a, 0, 1).unwrap();
        let result = idx.insert(&name, inode_id_b, 0, 1);
        assert_eq!(result, Err(DirIndexError::EntryAlreadyExists));

        // Original entry unchanged
        let entry = idx.lookup(&name).unwrap();
        assert_eq!(entry.inode_id, inode_id_a);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn lookup_nonexistent_is_none(
        present in arb_name(),
        absent in arb_name(),
        inode_id in any::<u64>(),
    ) {
        prop_assume!(present != absent);
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(&present, inode_id, 0, 1).unwrap();
        assert!(idx.lookup(&absent).is_none());
        assert!(!idx.contains(&absent));
    }

    #[test]
    fn delete_existing_succeeds(
        name in arb_name(),
        inode_id in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(&name, inode_id, 0, 1).unwrap();
        idx.delete(&name).unwrap();
        assert!(idx.lookup(&name).is_none());
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn delete_nonexistent_is_error(
        name in arb_name(),
        inode_id in any::<u64>(),
        ghost in arb_name(),
    ) {
        prop_assume!(name != ghost);
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(&name, inode_id, 0, 1).unwrap();
        let result = idx.delete(&ghost);
        assert_eq!(result, Err(DirIndexError::EntryNotFound));
        assert_eq!(idx.len(), 1);
        assert!(idx.contains(&name));
    }

    #[test]
    fn remove_returns_entry(
        name in arb_name(),
        inode_id in any::<u64>(),
        generation in any::<u64>(),
        kind in any::<u32>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(&name, inode_id, generation, kind).unwrap();
        let removed = idx.remove(&name).expect("remove must return entry");
        assert_eq!(removed.inode_id, inode_id);
        assert_eq!(removed.generation, generation);
        assert_eq!(removed.kind, kind);
        assert_eq!(removed.name, name);
        assert!(idx.lookup(&name).is_none());
    }

    #[test]
    fn insert_delete_reinsert_round_trip(
        name in arb_name(),
        inode_id_a in any::<u64>(),
        inode_id_b in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(&name, inode_id_a, 0, 1).unwrap();
        idx.delete(&name).unwrap();
        idx.insert(&name, inode_id_b, 1, 2).unwrap();
        let entry = idx.lookup(&name).unwrap();
        assert_eq!(entry.inode_id, inode_id_b);
        assert_eq!(entry.generation, 1);
        assert_eq!(entry.kind, 2);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn iteration_count_matches_len(
        names in arb_name_set(12),
        base_inode in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        for (i, name) in names.iter().enumerate() {
            idx.insert(name, base_inode.wrapping_add(i as u64), 0, 1).unwrap();
        }
        assert_eq!(idx.len(), names.len());

        let mut count = 0;
        idx.reset_cursor();
        while idx.next_entry().is_some() {
            count += 1;
        }
        assert_eq!(count, names.len());
    }

    #[test]
    fn iteration_no_duplicate_names(
        names in arb_name_set(12),
        base_inode in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        for (i, name) in names.iter().enumerate() {
            idx.insert(name, base_inode.wrapping_add(i as u64), 0, 1).unwrap();
        }

        let mut seen = HashSet::new();
        idx.reset_cursor();
        while let Some(entry) = idx.next_entry() {
            assert!(seen.insert(entry.name.clone()), "duplicate name in iteration: {:?}", entry.name);
        }
        assert_eq!(seen.len(), names.len());
    }

    #[test]
    fn iteration_sorted_order(
        names in arb_name_set(10),
        base_inode in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        for (i, name) in names.iter().enumerate() {
            idx.insert(name, base_inode.wrapping_add(i as u64), 0, 1).unwrap();
        }

        let mut yielded: Vec<Vec<u8>> = Vec::new();
        idx.reset_cursor();
        while let Some(entry) = idx.next_entry() {
            yielded.push(entry.name);
        }
        // Verify sorted order
        for w in yielded.windows(2) {
            assert!(w[0] <= w[1], "iteration not sorted: {:?} > {:?}", w[0], w[1]);
        }
    }

    #[test]
    fn list_matches_iteration(
        names in arb_name_set(10),
        base_inode in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        for (i, name) in names.iter().enumerate() {
            idx.insert(name, base_inode.wrapping_add(i as u64), 0, 1).unwrap();
        }

        let listed = idx.list();
        let mut iterated: Vec<tidefs_dir_index::DirEntry> = Vec::new();
        idx.reset_cursor();
        while let Some(entry) = idx.next_entry() {
            iterated.push(entry);
        }

        assert_eq!(listed.len(), iterated.len());
        for (l, i) in listed.iter().zip(iterated.iter()) {
            assert_eq!(l.name, i.name);
            assert_eq!(l.inode_id, i.inode_id);
        }
    }

    #[test]
    fn replace_existing_updates(
        name in arb_name(),
        inode_id_old in any::<u64>(),
        inode_id_new in any::<u64>(),
        kind_new in any::<u32>(),
        gen_new in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(&name, inode_id_old, 0, 1).unwrap();
        idx.replace(&name, inode_id_new, gen_new, kind_new);
        let entry = idx.lookup(&name).unwrap();
        assert_eq!(entry.inode_id, inode_id_new);
        assert_eq!(entry.generation, gen_new);
        assert_eq!(entry.kind, kind_new);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn replace_inserts_new_name(
        name in arb_name(),
        inode_id in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(b"existing", 1, 0, 1).unwrap();
        idx.replace(&name, inode_id, 0, 1);
        assert!(idx.contains(&name));
        assert_eq!(idx.lookup(&name).unwrap().inode_id, inode_id);
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn rename_moves_entry(
        old in arb_name(),
        new in arb_name(),
        inode_id in any::<u64>(),
    ) {
        prop_assume!(old != new);
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(&old, inode_id, 5, 2).unwrap();
        idx.rename(&old, &new).unwrap();
        assert!(idx.lookup(&old).is_none());
        let entry = idx.lookup(&new).unwrap();
        assert_eq!(entry.inode_id, inode_id);
        assert_eq!(entry.generation, 5);
        assert_eq!(entry.kind, 2);
    }

    #[test]
    fn rename_overwrite_replaces_target(
        src in arb_name(),
        dst in arb_name(),
        src_ino in any::<u64>(),
        dst_ino in any::<u64>(),
    ) {
        prop_assume!(src != dst);
        let mut idx = DirIndex::new(1, test_policy());
        idx.insert(&src, src_ino, 0, 1).unwrap();
        idx.insert(&dst, dst_ino, 0, 1).unwrap();
        let overwritten = idx.rename_overwrite(&src, &dst).unwrap().unwrap();
        assert_eq!(overwritten.inode_id, dst_ino);
        assert!(idx.lookup(&src).is_none());
        assert_eq!(idx.lookup(&dst).unwrap().inode_id, src_ino);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn len_consistent_across_inserts(
        names in arb_name_set(10),
        base_inode in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        for (i, name) in names.iter().enumerate() {
            idx.insert(name, base_inode.wrapping_add(i as u64), 0, 1).unwrap();
            assert_eq!(idx.len(), i + 1);
        }
    }

    #[test]
    fn len_consistent_across_insert_delete(
        names in arb_name_set(8),
        base_inode in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        for (i, name) in names.iter().enumerate() {
            idx.insert(name, base_inode.wrapping_add(i as u64), 0, 1).unwrap();
        }

        let total = names.len();
        for (i, name) in names.iter().enumerate() {
            idx.delete(name).unwrap();
            assert_eq!(idx.len(), total - i - 1);
        }
        assert!(idx.is_empty());
    }

    #[test]
    fn to_bytes_from_bytes_roundtrip_with_random_entries(
        names in arb_name_set(6),
        base_inode in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(42, test_policy());
        for (i, name) in names.iter().enumerate() {
            idx.insert(name, base_inode.wrapping_add(i as u64), i as u64, (i % 3) as u32).unwrap();
        }

        let bytes = idx.to_bytes();
        let restored = DirIndex::from_bytes(&bytes, test_policy())
            .expect("from_bytes must succeed on valid serialized data");

        assert_eq!(restored.len(), idx.len());
        for name in &names {
            let orig = idx.lookup(name).unwrap();
            let rest = restored.lookup(name).unwrap();
            assert_eq!(orig.inode_id, rest.inode_id);
            assert_eq!(orig.generation, rest.generation);
            assert_eq!(orig.kind, rest.kind);
            assert_eq!(orig.name_len, rest.name_len);
        }
    }

    #[test]
    fn version_monotonic_on_insert(
        names in arb_name_set(5),
        base_inode in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        let mut prev_version = idx.directory_version();
        for (i, name) in names.iter().enumerate() {
            idx.insert(name, base_inode.wrapping_add(i as u64), 0, 1).unwrap();
            let curr = idx.directory_version();
            assert!(curr > prev_version, "version must increase on insert");
            prev_version = curr;
        }
    }

    #[test]
    fn list_returns_only_inserted_names(
        names in arb_name_set(10),
        base_inode in any::<u64>(),
    ) {
        let mut idx = DirIndex::new(1, test_policy());
        for (i, name) in names.iter().enumerate() {
            idx.insert(name, base_inode.wrapping_add(i as u64), 0, 1).unwrap();
        }

        let listed_names: HashSet<Vec<u8>> =
            idx.list().into_iter().map(|e| e.name).collect();
        let expected: HashSet<Vec<u8>> =
            names.iter().cloned().collect();
        assert_eq!(listed_names, expected);
    }
}
