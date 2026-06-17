// dir_index_basic.rs — Integration tests for DirIndex entry CRUD, lookup, and
// empty-directory behavior.
//
// These tests exercise the public API of tidefs-dir-index and do not depend on
// any crate-internal helpers.

use tidefs_dir_index::{
    DatasetDirPolicy, DirCookie, DirIndex, DirIndexError, DirIterator, DirStorageKind,
};

/// A policy with thresholds low enough to trigger promotion/demotion in small
/// tests without needing hundreds of entries. Mirrors the policy used in the
/// crate's own unit-test module.
fn test_policy() -> DatasetDirPolicy {
    DatasetDirPolicy {
        dir_micro_max_entries: 6,
        dir_micro_max_name_bytes: 512,
        dir_btree_downshift_entries: 3,
        dir_btree_downshift_name_bytes: 128,
    }
}

/// Convenience: extract sorted names from a list of entries.
fn names(entries: &[tidefs_dir_index::DirEntry]) -> Vec<Vec<u8>> {
    entries.iter().map(|e| e.name.clone()).collect()
}

// ---------------------------------------------------------------------------
// Empty directory behaviour
// ---------------------------------------------------------------------------

#[test]
fn empty_dir_is_empty() {
    let idx = DirIndex::new(1, test_policy());
    assert!(idx.is_empty());
    assert_eq!(idx.len(), 0);
    assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);
}

#[test]
fn empty_dir_lookup_returns_none() {
    let idx = DirIndex::new(42, test_policy());
    assert!(idx.lookup(b"anything").is_none());
    assert!(!idx.contains(b"anything"));
}

#[test]
fn empty_dir_list_is_empty() {
    let idx = DirIndex::new(99, test_policy());
    assert!(idx.list().is_empty());
}

#[test]
fn empty_dir_range_scan_returns_empty() {
    let idx = DirIndex::new(1, test_policy());
    assert!(idx.range_scan(b"", 10).is_empty());
    assert!(idx.range_scan(b"foo", 10).is_empty());
}

#[test]
fn empty_dir_list_from_returns_empty() {
    let idx = DirIndex::new(1, test_policy());
    let (entries, cookie) = idx.list_from(DirCookie::START).unwrap();
    assert!(entries.is_empty());
    assert!(cookie.0 & tidefs_dir_index::format::DIR_COOKIE_VERSIONED_MASK != 0);
    assert_eq!(tidefs_dir_index::format::dir_cookie_skip(cookie.0), 0);
}

#[test]
fn empty_dir_delete_returns_not_found() {
    let mut idx = DirIndex::new(1, test_policy());
    assert_eq!(idx.delete(b"nope"), Err(DirIndexError::EntryNotFound));
    assert!(idx.remove(b"nope").is_none());
}

#[test]
fn empty_dir_diriterator_yields_none() {
    let mut idx = DirIndex::new(1, test_policy());
    assert!(idx.next_entry().is_none());
    assert_eq!(idx.current_cursor(), DirCookie::START);
}

#[test]
fn empty_dir_version_is_zero() {
    let idx = DirIndex::new(1, test_policy());
    assert_eq!(idx.directory_version(), 0);
}

#[test]
fn empty_dir_is_dirty() {
    let idx = DirIndex::new(1, test_policy());
    // A freshly-created empty index is dirty because it has never been
    // persisted.
    assert!(idx.is_dirty());
}

// ---------------------------------------------------------------------------
// Insertion
// ---------------------------------------------------------------------------

#[test]
fn insert_single_entry_and_lookup() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"hello", 100, 5, 1).unwrap();

    assert!(!idx.is_empty());
    assert_eq!(idx.len(), 1);
    assert!(idx.contains(b"hello"));

    let entry = idx.lookup(b"hello").unwrap();
    assert_eq!(entry.inode_id, 100);
    assert_eq!(entry.generation, 5);
    assert_eq!(entry.kind, 1);
    assert_eq!(entry.name, b"hello");
    assert_eq!(entry.name_len, 5);
}

#[test]
fn insert_multiple_entries_and_lookup_all() {
    let mut idx = DirIndex::new(1, test_policy());
    let entries: Vec<(&[u8], u64, u64, u32)> = vec![
        (b"alpha", 10, 1, 1),
        (b"beta", 20, 2, 2),
        (b"gamma", 30, 3, 1),
        (b"delta", 40, 4, 2),
    ];
    for (name, inode, gen, kind) in &entries {
        idx.insert(name, *inode, *gen, *kind).unwrap();
    }
    assert_eq!(idx.len(), 4);

    for (name, inode, gen, kind) in &entries {
        let e = idx.lookup(name).unwrap();
        assert_eq!(e.inode_id, *inode, "inode mismatch for {name:?}");
        assert_eq!(e.generation, *gen, "gen mismatch for {name:?}");
        assert_eq!(e.kind, *kind, "kind mismatch for {name:?}");
    }
}

#[test]
fn insert_entries_with_various_kind_values() {
    let mut idx = DirIndex::new(1, test_policy());
    // kind: 0=Dir, 1=File, 2=Symlink — exercise the full range
    idx.insert(b"a_dir", 1, 0, 0).unwrap();
    idx.insert(b"a_file", 2, 0, 1).unwrap();
    idx.insert(b"a_symlink", 3, 0, 2).unwrap();
    idx.insert(b"a_device", 4, 0, 99).unwrap(); // arbitrary kind

    assert_eq!(idx.lookup(b"a_dir").unwrap().kind, 0);
    assert_eq!(idx.lookup(b"a_file").unwrap().kind, 1);
    assert_eq!(idx.lookup(b"a_symlink").unwrap().kind, 2);
    assert_eq!(idx.lookup(b"a_device").unwrap().kind, 99);
}

#[test]
fn insert_with_high_generation() {
    let mut idx = DirIndex::new(1, test_policy());
    let high_gen: u64 = u64::MAX;
    idx.insert(b"gen_test", 1, high_gen, 1).unwrap();
    assert_eq!(idx.lookup(b"gen_test").unwrap().generation, high_gen);
}

#[test]
fn insert_with_high_inode_id() {
    let mut idx = DirIndex::new(1, test_policy());
    let high_inode: u64 = u64::MAX;
    idx.insert(b"big_inode", high_inode, 0, 1).unwrap();
    assert_eq!(idx.lookup(b"big_inode").unwrap().inode_id, high_inode);
}

#[test]
fn insert_bumps_version() {
    let mut idx = DirIndex::new(1, test_policy());
    let v0 = idx.directory_version();
    idx.insert(b"first", 1, 0, 1).unwrap();
    let v1 = idx.directory_version();
    assert!(v1 > v0, "version should bump after insert");

    idx.insert(b"second", 2, 0, 1).unwrap();
    let v2 = idx.directory_version();
    assert!(v2 > v1, "version should bump after second insert");
}

#[test]
fn insert_sets_dirty() {
    let mut idx = DirIndex::new(1, test_policy());
    // Fresh index is dirty; inserting keeps it dirty.
    idx.insert(b"x", 1, 0, 1).unwrap();
    assert!(idx.is_dirty());
}

// ---------------------------------------------------------------------------
// Duplicate-insert rejection
// ---------------------------------------------------------------------------

#[test]
fn insert_duplicate_name_rejected() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"dup", 1, 0, 1).unwrap();
    let result = idx.insert(b"dup", 2, 0, 1);
    assert_eq!(result, Err(DirIndexError::EntryAlreadyExists));

    // Original entry must be unchanged
    let e = idx.lookup(b"dup").unwrap();
    assert_eq!(e.inode_id, 1);
    assert_eq!(idx.len(), 1);
}

#[test]
fn insert_duplicate_after_delete_succeeds() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"dupe", 10, 0, 1).unwrap();
    idx.delete(b"dupe").unwrap();
    // Re-insert with same name, different inode
    idx.insert(b"dupe", 20, 1, 2).unwrap();
    let e = idx.lookup(b"dupe").unwrap();
    assert_eq!(e.inode_id, 20);
    assert_eq!(e.generation, 1);
    assert_eq!(e.kind, 2);
}

#[test]
fn insert_duplicate_name_micro_list() {
    let mut idx = DirIndex::new(1, test_policy());
    // Stay within micro-list thresholds
    for i in 0..5u64 {
        let name = format!("entry_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);

    // Duplicate insert should still be rejected in micro-list mode
    let result = idx.insert(b"entry_02", 999, 0, 1);
    assert_eq!(result, Err(DirIndexError::EntryAlreadyExists));
    assert_eq!(idx.lookup(b"entry_02").unwrap().inode_id, 2);
}

#[test]
fn insert_duplicate_name_btree() {
    let mut idx = DirIndex::new(1, test_policy());
    // Push into BTree representation
    for i in 0..7u64 {
        let name = format!("filler_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Duplicate insert should be rejected in BTree mode too
    let result = idx.insert(b"filler_03", 999, 0, 1);
    assert_eq!(result, Err(DirIndexError::EntryAlreadyExists));
    assert_eq!(idx.lookup(b"filler_03").unwrap().inode_id, 3);
}

// ---------------------------------------------------------------------------
// Deletion
// ---------------------------------------------------------------------------

#[test]
fn delete_existing_entry() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"remove_me", 10, 0, 1).unwrap();
    assert_eq!(idx.len(), 1);

    idx.delete(b"remove_me").unwrap();
    assert!(idx.is_empty());
    assert!(!idx.contains(b"remove_me"));
    assert!(idx.lookup(b"remove_me").is_none());
}

#[test]
fn delete_nonexistent_entry() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"keep", 1, 0, 1).unwrap();

    let result = idx.delete(b"ghost");
    assert_eq!(result, Err(DirIndexError::EntryNotFound));
    assert_eq!(idx.len(), 1);
}

#[test]
fn delete_bumps_version() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"v_test", 1, 0, 1).unwrap();
    let v_before = idx.directory_version();
    idx.delete(b"v_test").unwrap();
    let v_after = idx.directory_version();
    assert!(v_after > v_before);
}

#[test]
fn remove_returns_entry() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"pop", 42, 7, 3).unwrap();
    let removed = idx.remove(b"pop").unwrap();
    assert_eq!(removed.inode_id, 42);
    assert_eq!(removed.generation, 7);
    assert_eq!(removed.kind, 3);
    assert_eq!(removed.name, b"pop");
    assert!(idx.is_empty());
}

#[test]
fn delete_all_entries_empty_dir() {
    let mut idx = DirIndex::new(1, test_policy());
    let names_in: Vec<Vec<u8>> = (0..5u64)
        .map(|i| format!("d_{i:02}").into_bytes())
        .collect();

    for name in &names_in {
        idx.insert(name, 1, 0, 1).unwrap();
    }
    assert_eq!(idx.len(), 5);

    for name in &names_in {
        idx.delete(name).unwrap();
    }

    assert!(idx.is_empty());
    assert_eq!(idx.len(), 0);
    assert!(idx.list().is_empty());
}

// ---------------------------------------------------------------------------
// Lookup correctness under various conditions
// ---------------------------------------------------------------------------

#[test]
fn lookup_nonexistent_in_populated_dir() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"alpha", 1, 0, 1).unwrap();
    idx.insert(b"beta", 2, 0, 1).unwrap();

    assert!(idx.lookup(b"gamma").is_none());
    assert!(idx.lookup(b"ALPHA").is_none()); // case-sensitive
    assert!(idx.lookup(b"").is_none());
}

#[test]
fn lookup_case_sensitive() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"File", 1, 0, 1).unwrap();
    idx.insert(b"file", 2, 0, 1).unwrap();
    idx.insert(b"FILE", 3, 0, 1).unwrap();

    assert_eq!(idx.lookup(b"File").unwrap().inode_id, 1);
    assert_eq!(idx.lookup(b"file").unwrap().inode_id, 2);
    assert_eq!(idx.lookup(b"FILE").unwrap().inode_id, 3);
}

#[test]
fn lookup_binary_names() {
    let mut idx = DirIndex::new(1, test_policy());
    let name_a = vec![0x00, 0x01, 0xFF, 0xFE];
    let name_b = vec![0x00, 0x01, 0xFF, 0xFF];
    idx.insert(&name_a, 10, 0, 1).unwrap();
    idx.insert(&name_b, 20, 0, 1).unwrap();

    assert_eq!(idx.lookup(&name_a).unwrap().inode_id, 10);
    assert_eq!(idx.lookup(&name_b).unwrap().inode_id, 20);
}

#[test]
fn lookup_exact_match_no_prefix_confusion() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"abc", 1, 0, 1).unwrap();
    idx.insert(b"abcd", 2, 0, 1).unwrap();
    idx.insert(b"abcde", 3, 0, 1).unwrap();

    assert_eq!(idx.lookup(b"abc").unwrap().inode_id, 1);
    assert_eq!(idx.lookup(b"abcd").unwrap().inode_id, 2);
    assert_eq!(idx.lookup(b"abcde").unwrap().inode_id, 3);

    // b"ab" is not a prefix match for any entry
    assert!(idx.lookup(b"ab").is_none());
    assert!(idx.lookup(b"abcdef").is_none());
}

#[test]
fn contains_matches_lookup() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"present", 1, 0, 1).unwrap();

    assert!(idx.contains(b"present"));
    assert!(!idx.contains(b"absent"));
    assert!(idx.contains(b"present") == idx.lookup(b"present").is_some());
}

// ---------------------------------------------------------------------------
// List (sorted readdir) correctness
// ---------------------------------------------------------------------------

#[test]
fn list_returns_sorted_entries() {
    let mut idx = DirIndex::new(1, test_policy());
    // Insert in random order
    idx.insert(b"zulu", 26, 0, 1).unwrap();
    idx.insert(b"alpha", 1, 0, 1).unwrap();
    idx.insert(b"mike", 13, 0, 1).unwrap();
    idx.insert(b"delta", 4, 0, 1).unwrap();

    let entries = idx.list();
    let sorted_names: Vec<Vec<u8>> = entries.iter().map(|e| e.name.clone()).collect();
    assert_eq!(
        sorted_names,
        vec![
            b"alpha".to_vec(),
            b"delta".to_vec(),
            b"mike".to_vec(),
            b"zulu".to_vec()
        ]
    );
}

#[test]
fn list_reflects_deletions() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();

    idx.delete(b"b").unwrap();
    let entries = idx.list();
    assert_eq!(names(&entries), vec![b"a".to_vec(), b"c".to_vec()]);
}

#[test]
fn list_reflects_inserts() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"a", 1, 0, 1).unwrap();

    let entries = idx.list();
    assert_eq!(names(&entries), vec![b"a".to_vec(), b"b".to_vec()]);

    idx.insert(b"c", 3, 0, 1).unwrap();
    let entries = idx.list();
    assert_eq!(
        names(&entries),
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
    );
}

// ---------------------------------------------------------------------------
// Range scan
// ---------------------------------------------------------------------------

#[test]
fn range_scan_from_empty_prefix() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..5u64 {
        let name = format!("item_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    let results = idx.range_scan(b"", 3);
    assert_eq!(results.len(), 3);
    assert_eq!(
        names(&results),
        vec![
            b"item_00".to_vec(),
            b"item_01".to_vec(),
            b"item_02".to_vec(),
        ]
    );
}

#[test]
fn range_scan_from_midpoint() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..5u64 {
        let name = format!("item_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    let results = idx.range_scan(b"item_02", 10);
    assert_eq!(results.len(), 2);
    assert_eq!(
        names(&results),
        vec![b"item_03".to_vec(), b"item_04".to_vec()]
    );
}

#[test]
fn range_scan_past_end() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();

    let results = idx.range_scan(b"b", 10);
    assert!(results.is_empty());
}

#[test]
fn range_scan_empty_dir() {
    let idx = DirIndex::new(1, test_policy());
    assert!(idx.range_scan(b"", 10).is_empty());
    assert!(idx.range_scan(b"anything", 10).is_empty());
}

#[test]
fn range_scan_nonexistent_start_name() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"alpha", 1, 0, 1).unwrap();
    idx.insert(b"gamma", 3, 0, 1).unwrap();

    // "beta" doesn't exist — should start after its insertion point
    let results = idx.range_scan(b"beta", 10);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, b"gamma");
}

// ---------------------------------------------------------------------------
// list_from with DirCookie
// ---------------------------------------------------------------------------

#[test]
fn list_from_start_returns_all() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();

    let (entries, _) = idx.list_from(DirCookie::START).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(
        names(&entries),
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
    );
}

#[test]
fn list_from_empty_dir_cookie() {
    let idx = DirIndex::new(1, test_policy());
    let (entries, cookie) = idx.list_from(DirCookie::START).unwrap();
    assert!(entries.is_empty());
    assert!(cookie.0 & tidefs_dir_index::format::DIR_COOKIE_VERSIONED_MASK != 0);
    assert_eq!(tidefs_dir_index::format::dir_cookie_skip(cookie.0), 0);
}

// ---------------------------------------------------------------------------
// Representation and promotion
// ---------------------------------------------------------------------------

#[test]
fn starts_as_micro_list() {
    let idx = DirIndex::new(1, test_policy());
    assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);
}

#[test]
fn stays_micro_below_threshold() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..6u64 {
        let name = format!("n_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);
}

#[test]
fn promotes_to_btree_above_threshold() {
    let mut idx = DirIndex::new(1, test_policy());
    // test_policy has dir_micro_max_entries = 6, so 7 entries triggers
    // promotion.
    for i in 0..7u64 {
        let name = format!("p_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);
}

#[test]
fn btree_lookup_works_after_promotion() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..7u64 {
        let name = format!("btree_{i:02}");
        idx.insert(name.as_bytes(), 100 + i, 0, 1).unwrap();
    }
    for i in 0..7u64 {
        let name = format!("btree_{i:02}");
        let e = idx.lookup(name.as_bytes()).unwrap();
        assert_eq!(e.inode_id, 100 + i);
    }
}

#[test]
fn btree_delete_works_after_promotion() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..7u64 {
        let name = format!("deltree_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    idx.delete(b"deltree_03").unwrap();
    assert_eq!(idx.len(), 6);
    assert!(!idx.contains(b"deltree_03"));
    assert!(idx.contains(b"deltree_00"));
}

#[test]
fn btree_list_sorted_after_promotion() {
    let mut idx = DirIndex::new(1, test_policy());
    // Insert in reverse order
    for i in (0..7u64).rev() {
        let name = format!("rev_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    let entries = idx.list();
    let expected: Vec<Vec<u8>> = (0..7u64)
        .map(|i| format!("rev_{i:02}").into_bytes())
        .collect();
    assert_eq!(names(&entries), expected);
}

// ---------------------------------------------------------------------------
// DirIterator on DirIndex (integration with cursor semantics)
// ---------------------------------------------------------------------------

#[test]
fn diriterator_full_iteration_and_reset() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"c", 3, 0, 1).unwrap();
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();

    // First pass
    let e1 = idx.next_entry().unwrap();
    assert_eq!(e1.name, b"a");
    let e2 = idx.next_entry().unwrap();
    assert_eq!(e2.name, b"b");
    let e3 = idx.next_entry().unwrap();
    assert_eq!(e3.name, b"c");
    assert!(idx.next_entry().is_none());

    // Reset and re-iterate
    idx.reset_cursor();
    let e1b = idx.next_entry().unwrap();
    assert_eq!(e1b.name, b"a");
    let e2b = idx.next_entry().unwrap();
    assert_eq!(e2b.name, b"b");
}

#[test]
fn diriterator_seek_to_cursor_and_resume() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..5u64 {
        let name = format!("s_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }

    // Iterate two entries, save cursor
    let _ = idx.next_entry().unwrap(); // s_00
    let _ = idx.next_entry().unwrap(); // s_01
    let saved = idx.current_cursor();

    // Continue iterating
    let e3 = idx.next_entry().unwrap();
    assert_eq!(e3.name, b"s_02");

    // Seek back to saved cursor
    idx.seek_to_cursor(saved);
    let resumed = idx.next_entry().unwrap();
    assert_eq!(resumed.name, b"s_02");
}

#[test]
fn diriterator_current_cursor_after_next_entry() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"x", 1, 0, 1).unwrap();

    assert_eq!(idx.current_cursor(), DirCookie::START);
    let _ = idx.next_entry().unwrap();
    // After yielding the only entry, cursor should be non-START
    assert!(idx.current_cursor() != DirCookie::START);
}

#[test]
fn diriterator_seek_to_start() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();

    let _ = idx.next_entry().unwrap();
    let _ = idx.next_entry().unwrap();
    assert!(idx.next_entry().is_none());

    // Seek back to START
    idx.seek_to_cursor(DirCookie::START);
    let fresh = idx.next_entry().unwrap();
    assert_eq!(fresh.name, b"a");
}

#[test]
fn diriterator_on_btree_works() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..7u64 {
        let name = format!("iter_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    let mut count = 0;
    idx.reset_cursor();
    while idx.next_entry().is_some() {
        count += 1;
    }
    assert_eq!(count, 7);
}

// ---------------------------------------------------------------------------
// Version tracking across operations
// ---------------------------------------------------------------------------

#[test]
fn version_monotonic_across_mixed_operations() {
    let mut idx = DirIndex::new(1, test_policy());
    let v0 = idx.directory_version();

    idx.insert(b"one", 1, 0, 1).unwrap();
    let v1 = idx.directory_version();
    assert!(v1 > v0);

    idx.insert(b"two", 2, 0, 1).unwrap();
    let v2 = idx.directory_version();
    assert!(v2 > v1);

    idx.delete(b"one").unwrap();
    let v3 = idx.directory_version();
    assert!(v3 > v2);

    idx.replace(b"two", 99, 0, 99);
    let v4 = idx.directory_version();
    assert!(v4 > v3);
}

// ---------------------------------------------------------------------------
// Replace (upsert) semantics
// ---------------------------------------------------------------------------

#[test]
fn replace_updates_existing_entry() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"target", 10, 1, 1).unwrap();
    idx.replace(b"target", 20, 2, 2);

    let e = idx.lookup(b"target").unwrap();
    assert_eq!(e.inode_id, 20);
    assert_eq!(e.generation, 2);
    assert_eq!(e.kind, 2);
    assert_eq!(idx.len(), 1);
}

#[test]
fn replace_inserts_new_entry() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"existing", 1, 0, 1).unwrap();

    // replace on a name that doesn't exist → insert
    idx.replace(b"new_one", 42, 7, 3);
    assert_eq!(idx.len(), 2);
    let e = idx.lookup(b"new_one").unwrap();
    assert_eq!(e.inode_id, 42);
    assert_eq!(e.generation, 7);
    assert_eq!(e.kind, 3);
}

// ---------------------------------------------------------------------------
// Rename within same directory
// ---------------------------------------------------------------------------

#[test]
fn rename_moves_entry() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"old", 10, 1, 1).unwrap();
    idx.rename(b"old", b"new").unwrap();

    assert!(idx.lookup(b"old").is_none());
    let e = idx.lookup(b"new").unwrap();
    assert_eq!(e.inode_id, 10);
    assert_eq!(idx.len(), 1);
}

#[test]
fn rename_same_name_is_noop() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"same", 10, 1, 1).unwrap();
    let v_before = idx.directory_version();

    idx.rename(b"same", b"same").unwrap();
    // No version bump for no-op
    assert_eq!(idx.directory_version(), v_before);
    assert_eq!(idx.lookup(b"same").unwrap().inode_id, 10);
}

#[test]
fn rename_nonexistent_source_fails() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"real", 1, 0, 1).unwrap();

    assert_eq!(
        idx.rename(b"ghost", b"target"),
        Err(DirIndexError::EntryNotFound)
    );
}

#[test]
fn rename_to_existing_target_fails() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"src", 1, 0, 1).unwrap();
    idx.insert(b"dst", 2, 0, 1).unwrap();

    assert_eq!(
        idx.rename(b"src", b"dst"),
        Err(DirIndexError::EntryAlreadyExists)
    );
    // Both entries should remain unchanged
    assert_eq!(idx.lookup(b"src").unwrap().inode_id, 1);
    assert_eq!(idx.lookup(b"dst").unwrap().inode_id, 2);
}

#[test]
fn rename_overwrite_replaces_target() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"src", 1, 0, 1).unwrap();
    idx.insert(b"dst", 2, 0, 1).unwrap();

    let overwritten = idx.rename_overwrite(b"src", b"dst").unwrap().unwrap();
    assert_eq!(overwritten.inode_id, 2);
    assert_eq!(overwritten.name, b"dst");

    assert!(idx.lookup(b"src").is_none());
    assert_eq!(idx.lookup(b"dst").unwrap().inode_id, 1);
    assert_eq!(idx.len(), 1);
}

#[test]
fn rename_overwrite_same_name_is_noop() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"only", 1, 0, 1).unwrap();

    let overwritten = idx.rename_overwrite(b"only", b"only").unwrap();
    assert!(overwritten.is_none());
    assert_eq!(idx.len(), 1);
    assert_eq!(idx.lookup(b"only").unwrap().inode_id, 1);
}

// ---------------------------------------------------------------------------
// move_entry_to across directories
// ---------------------------------------------------------------------------

#[test]
fn move_entry_between_dirs() {
    let mut src = DirIndex::new(1, test_policy());
    let mut dst = DirIndex::new(2, test_policy());

    src.insert(b"migrant", 100, 1, 1).unwrap();
    assert_eq!(src.len(), 1);
    assert!(dst.is_empty());

    let overwritten = src.move_entry_to(b"migrant", &mut dst, b"arrived").unwrap();
    assert!(overwritten.is_none());

    assert!(src.is_empty());
    assert!(!src.contains(b"migrant"));

    assert_eq!(dst.len(), 1);
    let e = dst.lookup(b"arrived").unwrap();
    assert_eq!(e.inode_id, 100);
    assert_eq!(e.generation, 1);
    assert_eq!(e.kind, 1);
}

#[test]
fn move_entry_overwrites_dst() {
    let mut src = DirIndex::new(1, test_policy());
    let mut dst = DirIndex::new(2, test_policy());

    src.insert(b"src_e", 10, 0, 1).unwrap();
    dst.insert(b"dst_e", 20, 0, 1).unwrap();

    let overwritten = src
        .move_entry_to(b"src_e", &mut dst, b"dst_e")
        .unwrap()
        .unwrap();
    assert_eq!(overwritten.inode_id, 20);

    assert!(src.is_empty());
    assert_eq!(dst.len(), 1);
    assert_eq!(dst.lookup(b"dst_e").unwrap().inode_id, 10);
}

#[test]
fn move_entry_nonexistent_source_fails() {
    let mut src = DirIndex::new(1, test_policy());
    let mut dst = DirIndex::new(2, test_policy());

    assert_eq!(
        src.move_entry_to(b"nope", &mut dst, b"dest"),
        Err(DirIndexError::EntryNotFound)
    );
}

// ---------------------------------------------------------------------------
// Policy and storage accessors
// ---------------------------------------------------------------------------

#[test]
fn policy_returns_configured_policy() {
    let p = test_policy();
    let idx = DirIndex::new(1, p);
    assert_eq!(idx.policy(), p);
}

#[test]
fn storage_returns_current_storage() {
    let mut idx = DirIndex::new(1, test_policy());
    let storage = idx.storage();
    assert_eq!(storage.kind(), DirStorageKind::MICRO_LIST);

    // Promote to btree
    for i in 0..7u64 {
        let name = format!("stor_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    let storage = idx.storage();
    assert_eq!(storage.kind(), DirStorageKind::BTREE);
}

// ---------------------------------------------------------------------------
// to_bytes / from_bytes round-trip (micro-list only from public API)
// ---------------------------------------------------------------------------

#[test]
fn to_bytes_from_bytes_roundtrip_empty() {
    let idx = DirIndex::new(42, test_policy());
    let bytes = idx.to_bytes();
    assert!(!bytes.is_empty());

    let restored = DirIndex::from_bytes(&bytes, test_policy()).unwrap();
    assert_eq!(restored.len(), 0);
    assert!(restored.is_empty());
    assert_eq!(restored.directory_version(), 0);
}

#[test]
fn to_bytes_from_bytes_roundtrip_with_entries() {
    let mut idx = DirIndex::new(99, test_policy());
    idx.insert(b"alpha", 1, 10, 1).unwrap();
    idx.insert(b"beta", 2, 20, 2).unwrap();
    idx.insert(b"gamma", 3, 30, 1).unwrap();

    let bytes = idx.to_bytes();
    let restored = DirIndex::from_bytes(&bytes, test_policy()).unwrap();

    assert_eq!(restored.len(), 3);
    assert_eq!(restored.lookup(b"alpha").unwrap().inode_id, 1);
    assert_eq!(restored.lookup(b"alpha").unwrap().generation, 10);
    assert_eq!(restored.lookup(b"beta").unwrap().inode_id, 2);
    assert_eq!(restored.lookup(b"gamma").unwrap().inode_id, 3);
    assert_eq!(restored.list().len(), 3);
}

#[test]
fn from_bytes_invalid_data_returns_none() {
    let bad: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    assert!(DirIndex::from_bytes(bad, test_policy()).is_none());
}

// ---------------------------------------------------------------------------
// has_subdirs accessor
// ---------------------------------------------------------------------------

#[test]
fn has_subdirs_defaults_false() {
    let idx = DirIndex::new(1, test_policy());
    assert!(!idx.has_subdirs());
}

#[test]
fn set_has_subdirs_persists() {
    let mut idx = DirIndex::new(1, test_policy());
    assert!(!idx.has_subdirs());
    idx.set_has_subdirs(true);
    assert!(idx.has_subdirs());
    idx.set_has_subdirs(false);
    assert!(!idx.has_subdirs());
}

// ---------------------------------------------------------------------------
// Edge cases: single entry, large volumes, zero-length names
// ---------------------------------------------------------------------------

#[test]
fn single_entry_all_operations() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"only", 42, 5, 1).unwrap();
    assert_eq!(idx.len(), 1);
    assert!(!idx.is_empty());

    // List
    assert_eq!(idx.list().len(), 1);
    assert_eq!(idx.list()[0].name, b"only");

    // Range scan
    let results = idx.range_scan(b"", 1);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, b"only");

    // DirIterator
    idx.reset_cursor();
    let e = idx.next_entry().unwrap();
    assert_eq!(e.name, b"only");
    assert!(idx.next_entry().is_none());

    // Delete
    idx.delete(b"only").unwrap();
    assert!(idx.is_empty());
}

#[test]
fn insert_many_entries() {
    let mut idx = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
    let count: u64 = 200;
    for i in 0..count {
        let name = format!("entry_{i:05}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.len(), count as usize);
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Verify spot checks
    assert_eq!(idx.lookup(b"entry_00042").unwrap().inode_id, 42);
    assert_eq!(idx.lookup(b"entry_00199").unwrap().inode_id, 199);

    // Full iteration returns all entries in sorted order
    let entries = idx.list();
    assert_eq!(entries.len(), count as usize);
    for (i, e) in entries.iter().enumerate() {
        let expected = format!("entry_{i:05}");
        assert_eq!(e.name.as_slice(), expected.as_bytes());
    }
}

#[test]
fn long_name_entries() {
    let mut idx = DirIndex::new(1, test_policy());
    let long_name: Vec<u8> = (b'a'..=b'z').cycle().take(255).collect();
    idx.insert(&long_name, 1, 0, 1).unwrap();
    assert_eq!(idx.lookup(&long_name).unwrap().inode_id, 1);
}

#[test]
fn single_byte_name() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"x", 1, 0, 1).unwrap();
    assert_eq!(idx.lookup(b"x").unwrap().inode_id, 1);
    assert_eq!(idx.len(), 1);
}
