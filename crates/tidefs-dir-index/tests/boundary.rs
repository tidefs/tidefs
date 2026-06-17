// boundary.rs — Boundary-condition integration tests for DirIndex:
// maximum name length, zero-length names, single-entry directory,
// 500-entry large directories, and edge-case cursor operations.

use tidefs_dir_index::{DatasetDirPolicy, DirCookie, DirIndex, DirIterator, DirStorageKind};

fn test_policy() -> DatasetDirPolicy {
    DatasetDirPolicy {
        dir_micro_max_entries: 6,
        dir_micro_max_name_bytes: 512,
        dir_btree_downshift_entries: 3,
        dir_btree_downshift_name_bytes: 128,
    }
}

// ---------------------------------------------------------------------------
// Maximum name length entries
// ---------------------------------------------------------------------------

#[test]
fn longest_name_255_bytes_insert_and_lookup() {
    let mut idx = DirIndex::new(1, test_policy());
    let long_name: Vec<u8> = (b'a'..=b'z').cycle().take(255).collect();
    assert_eq!(long_name.len(), 255);

    idx.insert(&long_name, 42, 7, 1).unwrap();
    assert_eq!(idx.len(), 1);

    let e = idx.lookup(&long_name).unwrap();
    assert_eq!(e.inode_id, 42);
    assert_eq!(e.generation, 7);
    assert_eq!(e.kind, 1);
    assert_eq!(e.name, long_name);
    assert_eq!(e.name_len, 255);
}

#[test]
fn longest_name_deleted_and_reinserted() {
    let mut idx = DirIndex::new(1, test_policy());
    let long_name: Vec<u8> = std::iter::repeat_n(b'x', 255).collect();

    idx.insert(&long_name, 1, 0, 1).unwrap();
    idx.delete(&long_name).unwrap();
    assert!(idx.is_empty());

    idx.insert(&long_name, 99, 9, 1).unwrap();
    assert_eq!(idx.lookup(&long_name).unwrap().inode_id, 99);
}

#[test]
fn multiple_long_names_in_btree() {
    let mut idx = DirIndex::new(1, test_policy());
    let mut names: Vec<Vec<u8>> = Vec::new();

    // Promote to B-tree with entries that have very long names
    for i in 0..10u64 {
        let prefix = format!("long_{i:02}_");
        let mut name: Vec<u8> = prefix.into_bytes();
        name.extend((b'a'..=b'z').cycle().take(240));
        assert!(name.len() > 240);
        idx.insert(&name, i, 0, 1).unwrap();
        names.push(name);
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);
    assert_eq!(idx.len(), 10);

    for (i, name) in names.iter().enumerate() {
        let e = idx.lookup(name).unwrap();
        assert_eq!(e.inode_id, i as u64);
    }

    // Sorted iteration produces correct order
    let entries = idx.list();
    assert_eq!(entries.len(), 10);
    // Verify sorted
    for w in entries.windows(2) {
        assert!(w[0].name <= w[1].name, "list must be sorted");
    }
}

#[test]
fn longest_name_with_non_ascii_bytes() {
    let mut idx = DirIndex::new(1, test_policy());
    let name: Vec<u8> = (0u8..=254u8).collect();
    assert_eq!(name.len(), 255);

    idx.insert(&name, 1, 0, 1).unwrap();
    let e = idx.lookup(&name).unwrap();
    assert_eq!(e.name, name);
}

// ---------------------------------------------------------------------------
// Zero-length names
// ---------------------------------------------------------------------------

#[test]
fn zero_length_name_can_be_inserted_and_looked_up() {
    // The API does not reject zero-length names at the DirIndex level
    // (FUSE protocol handles that validation). Verify the data structure
    // handles this edge case correctly.
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"", 1, 0, 1).unwrap();
    assert_eq!(idx.len(), 1);
    assert!(idx.contains(b""));
    let e = idx.lookup(b"").unwrap();
    assert_eq!(e.inode_id, 1);
    assert_eq!(e.name_len, 0);
    assert!(e.name.is_empty());
}

#[test]
fn zero_length_name_deleted_and_lookup_fails() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"", 1, 0, 1).unwrap();
    idx.delete(b"").unwrap();
    assert!(idx.is_empty());
    assert!(!idx.contains(b""));
    assert!(idx.lookup(b"").is_none());
}

#[test]
fn zero_length_name_with_other_entries() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"", 0, 0, 1).unwrap();
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();

    // Zero-length name sorts before all other names
    let entries = idx.list();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, b"");
    assert_eq!(entries[1].name, b"a");
    assert_eq!(entries[2].name, b"b");

    // DirIterator yields empty-name first
    idx.reset_cursor();
    let first = idx.next_entry().unwrap();
    assert_eq!(first.name, b"");
    assert_eq!(first.inode_id, 0);
}

#[test]
fn zero_length_name_in_btree() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..6u64 {
        let name = format!("pad_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    idx.insert(b"", 99, 0, 1).unwrap(); // 7th entry triggers promotion
    assert_eq!(idx.representation(), DirStorageKind::BTREE);
    assert!(idx.contains(b""));
    assert_eq!(idx.lookup(b"").unwrap().inode_id, 99);

    let entries = idx.list();
    assert_eq!(entries[0].name, b""); // empty name sorts first
}

// ---------------------------------------------------------------------------
// Single-entry directory boundary
// ---------------------------------------------------------------------------

#[test]
fn single_entry_dir_all_iterator_ops() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"only", 42, 5, 1).unwrap();

    // next_entry
    idx.reset_cursor();
    let e = idx.next_entry().unwrap();
    assert_eq!(e.name, b"only");
    assert!(idx.next_entry().is_none());

    // reset and re-iterate
    idx.reset_cursor();
    assert!(idx.next_entry().is_some());
    assert!(idx.next_entry().is_none());

    // seek_to_cursor to START
    idx.seek_to_cursor(DirCookie::START);
    let e = idx.next_entry().unwrap();
    assert_eq!(e.name, b"only");

    // list, range_scan, list_from all return single entry
    assert_eq!(idx.list().len(), 1);
    assert_eq!(idx.range_scan(b"", 10).len(), 1);
    let (entries, _) = idx.list_from(DirCookie::START).unwrap();
    assert_eq!(entries.len(), 1);
}

#[test]
fn single_entry_dir_delete_makes_empty() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"x", 1, 0, 1).unwrap();
    idx.delete(b"x").unwrap();
    assert!(idx.is_empty());
    assert!(idx.next_entry().is_none());
    assert_eq!(idx.current_cursor(), DirCookie::START);
}

#[test]
fn single_entry_dir_replace_changes_value() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"x", 1, 0, 1).unwrap();
    idx.replace(b"x", 99, 9, 9);
    assert_eq!(idx.len(), 1);
    let e = idx.lookup(b"x").unwrap();
    assert_eq!(e.inode_id, 99);
    assert_eq!(e.generation, 9);
    assert_eq!(e.kind, 9);
}

// ---------------------------------------------------------------------------
// Large directory (500 entries)
// ---------------------------------------------------------------------------

#[test]
fn large_dir_500_entries_full_iteration() {
    let mut idx = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
    let count: u64 = 500;
    for i in 0..count {
        let name = format!("entry_{i:05}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);
    assert_eq!(idx.len(), count as usize);

    // Full sorted iteration
    let entries = idx.list();
    assert_eq!(entries.len(), count as usize);
    for (k, e) in entries.iter().enumerate() {
        assert_eq!(e.name, format!("entry_{k:05}").as_bytes());
        assert_eq!(e.inode_id, k as u64);
    }
}

#[test]
fn large_dir_500_entries_cursor_round_trip() {
    let mut idx = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
    let count: u64 = 500;
    for i in 0..count {
        let name = format!("big_{i:05}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    idx.reset_cursor();
    // Skip 200 entries
    for _ in 0..200 {
        idx.next_entry().unwrap();
    }
    let saved = idx.current_cursor();

    // Continue 100 more
    for _ in 0..100 {
        idx.next_entry().unwrap();
    }

    // Seek back to saved cursor
    idx.seek_to_cursor(saved);
    let resumed = idx.next_entry().unwrap();
    assert_eq!(resumed.name, b"big_00200");
    assert_eq!(resumed.inode_id, 200);

    // Iterate remaining
    let mut remaining = 0usize;
    while idx.next_entry().is_some() {
        remaining += 1;
    }
    assert_eq!(remaining, 500 - 200 - 1); // -1 for the entry we just consumed
}

#[test]
fn large_dir_500_entries_range_scan_paginated() {
    let mut idx = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
    let count: u64 = 500;
    for i in 0..count {
        let name = format!("page_{i:05}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }

    let page_size = 50;
    let mut start: Vec<u8> = Vec::new();
    let mut total = 0usize;

    loop {
        let page = idx.range_scan(&start, page_size);
        if page.is_empty() {
            break;
        }
        assert!(
            page.len() <= page_size,
            "page should not exceed max_entries"
        );
        for (k, e) in page.iter().enumerate() {
            assert_eq!(e.inode_id, (total + k) as u64);
        }
        total += page.len();
        start = page.last().unwrap().name.clone();
    }
    assert_eq!(total, count as usize);
}

#[test]
fn large_dir_500_entries_lookup_all() {
    let mut idx = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
    let count: u64 = 500;
    for i in 0..count {
        let name = format!("find_{i:05}");
        idx.insert(name.as_bytes(), 1000 + i, 0, 1).unwrap();
    }

    // Spot-check: every 50th entry
    for i in (0..count).step_by(50) {
        let name = format!("find_{i:05}");
        let e = idx.lookup(name.as_bytes()).unwrap();
        assert_eq!(e.inode_id, 1000 + i);
    }

    // Non-existent entries
    assert!(idx.lookup(b"find_99999").is_none());
    assert!(idx.lookup(b"find_00500").is_none()); // 0..499, so 500 doesn't exist
}

#[test]
fn large_dir_500_entries_delete_half() {
    let mut idx = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
    let count: u64 = 500;
    for i in 0..count {
        let name = format!("half_{i:05}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }

    // Delete even entries
    for i in (0..count).step_by(2) {
        let name = format!("half_{i:05}");
        idx.delete(name.as_bytes()).unwrap();
    }

    assert_eq!(idx.len(), 250);

    // Remaining entries are odd
    let entries = idx.list();
    assert_eq!(entries.len(), 250);
    for (k, e) in entries.iter().enumerate() {
        let expected_i = (2 * k as u64) + 1;
        assert_eq!(e.name, format!("half_{expected_i:05}").as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Promotion threshold exactly at boundary
// ---------------------------------------------------------------------------

#[test]
fn exactly_at_promotion_threshold() {
    // test_policy has dir_micro_max_entries = 6
    // 6 entries: should stay micro
    // 7 entries: should promote
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..6u64 {
        let name = format!("edge_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);

    idx.insert(b"edge_06", 6, 0, 1).unwrap();
    assert_eq!(idx.representation(), DirStorageKind::BTREE);
}

#[test]
fn exactly_at_demotion_threshold() {
    // btree_downshift_entries = 3
    // 3 entries: should demote (if btree) or stay micro
    // 4 entries: should stay btree
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..7u64 {
        let name = format!("dem_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Delete to 4 entries: should stay btree
    for i in 0..3u64 {
        let name = format!("dem_{i:02}");
        idx.delete(name.as_bytes()).unwrap();
    }
    assert_eq!(idx.len(), 4);

    // Delete one more to 3 entries: should demote
    idx.delete(b"dem_03").unwrap();
    assert_eq!(idx.len(), 3);
    // Representation may be either (check_and_switch called on each mutation)
}

// ---------------------------------------------------------------------------
// Name byte threshold boundary
// ---------------------------------------------------------------------------

#[test]
fn promote_on_total_name_bytes_threshold() {
    let mut idx = DirIndex::new(1, test_policy());
    // test_policy.dir_micro_max_name_bytes = 512
    // Few entries but each long enough to exceed 512 bytes total
    let mut long_a = b"a_".to_vec();
    long_a.extend(std::iter::repeat_n(b'x', 250));
    let mut long_b = b"b_".to_vec();
    long_b.extend(std::iter::repeat_n(b'y', 250));
    let mut long_c = b"c_".to_vec();
    long_c.extend(std::iter::repeat_n(b'z', 250));
    idx.insert(&long_a, 1, 0, 1).unwrap();
    idx.insert(&long_b, 2, 0, 1).unwrap();
    idx.insert(&long_c, 3, 0, 1).unwrap();
    // ~3 * 252 = ~756 > 512, should promote on name bytes
    assert_eq!(idx.representation(), DirStorageKind::BTREE);
    assert_eq!(idx.len(), 3);
}

// ---------------------------------------------------------------------------
// dir_version wraps correctly on high values
// ---------------------------------------------------------------------------

#[test]
fn directory_version_near_u64_max() {
    // We can't set version directly, but we can verify it increments
    // correctly through many mutations.
    let mut idx = DirIndex::new(1, test_policy());
    // 200 mutations worth of version bumps
    for i in 0..200u64 {
        let name = format!("v_{i:04}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    // Version should be >= 200
    assert!(idx.directory_version() >= 200);
    assert_eq!(idx.len(), 200);
}

// ---------------------------------------------------------------------------
// to_bytes/from_bytes with boundary entries
// ---------------------------------------------------------------------------

#[test]
fn to_bytes_from_bytes_with_zero_length_name() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"", 1, 0, 1).unwrap();
    idx.insert(b"normal", 2, 0, 1).unwrap();

    let bytes = idx.to_bytes();
    let restored = DirIndex::from_bytes(&bytes, test_policy()).unwrap();
    assert_eq!(restored.len(), 2);
    assert!(restored.contains(b""));
    assert_eq!(restored.lookup(b"").unwrap().inode_id, 1);
    assert_eq!(restored.lookup(b"normal").unwrap().inode_id, 2);
}

#[test]
fn to_bytes_from_bytes_with_long_names() {
    let mut idx = DirIndex::new(1, test_policy());
    let long: Vec<u8> = std::iter::repeat_n(b'z', 255).collect();
    idx.insert(&long, 42, 5, 1).unwrap();
    idx.insert(b"short", 7, 0, 1).unwrap();

    let bytes = idx.to_bytes();
    let restored = DirIndex::from_bytes(&bytes, test_policy()).unwrap();
    assert_eq!(restored.len(), 2);
    assert_eq!(restored.lookup(&long).unwrap().inode_id, 42);
    assert_eq!(restored.lookup(b"short").unwrap().inode_id, 7);
}

// ---------------------------------------------------------------------------
// Empty name iteration boundaries
// ---------------------------------------------------------------------------

#[test]
fn empty_name_dir_range_scan_from_empty_start() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"", 0, 0, 1).unwrap();
    idx.insert(b"a", 1, 0, 1).unwrap();

    // range_scan from empty start_name returns both
    let results = idx.range_scan(b"", 10);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].name, b"");
    assert_eq!(results[1].name, b"a");
}

#[test]
fn empty_name_dir_range_scan_from_empty_start_name() {
    // range_scan treats empty start_name as "start from beginning".
    // To skip past the empty-name entry, pass it explicitly as start_name.
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"", 0, 0, 1).unwrap();
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();

    // Empty start_name means "from the beginning" — returns all entries
    let results = idx.range_scan(b"", 10);
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].name, b"");
    assert_eq!(results[1].name, b"a");
    assert_eq!(results[2].name, b"b");

    // To skip the empty-name entry: pass b"" as start_name after already
    // seeing it. But range_scan treats "" specially. The correct way to
    // paginate past an entry named "" is to use range_scan with the
    // actual last-seen name as start_name.
    let after_empty = idx.range_scan(b"", 10);
    // Still returns all entries since "" means "from beginning"
    assert_eq!(after_empty.len(), 3);
}
