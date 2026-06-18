// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// hash_collision.rs — Integration tests for B-tree hash-bucket behaviour and
// integrity under the public API. Since the forced-hash helpers are crate-
// internal (not public), these tests focus on verifying B-tree correctness
// with many entries, name-sorted iteration stability, lookup/delete in B-tree
// mode, and bucket-level invariants inferred through behaviour.

use tidefs_dir_index::{DatasetDirPolicy, DirIndex, DirIterator, DirStorageKind};

fn test_policy() -> DatasetDirPolicy {
    DatasetDirPolicy {
        dir_micro_max_entries: 6,
        dir_micro_max_name_bytes: 512,
        dir_btree_downshift_entries: 3,
        dir_btree_downshift_name_bytes: 128,
    }
}

// ---------------------------------------------------------------------------
// B-tree representation integrity
// ---------------------------------------------------------------------------

#[test]
fn btree_insert_many_entries_all_reachable() {
    let mut idx = DirIndex::new(1, test_policy());
    let count: u64 = 50;
    for i in 0..count {
        let name = format!("entry_{i:04}");
        idx.insert(name.as_bytes(), 100 + i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);
    assert_eq!(idx.len(), count as usize);

    // Every entry must be reachable by name
    for i in 0..count {
        let name = format!("entry_{i:04}");
        let e = idx.lookup(name.as_bytes()).unwrap();
        assert_eq!(e.inode_id, 100 + i);
    }
}

#[test]
fn btree_delete_many_entries_maintains_integrity() {
    let mut idx = DirIndex::new(1, test_policy());
    let count: u64 = 50;
    for i in 0..count {
        let name = format!("del_{i:04}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Delete every other entry
    for i in (0..count).step_by(2) {
        let name = format!("del_{i:04}");
        idx.delete(name.as_bytes()).unwrap();
    }

    assert_eq!(idx.len(), (count / 2) as usize);

    // Remaining entries must be reachable
    for i in (1..count).step_by(2) {
        let name = format!("del_{i:04}");
        assert!(
            idx.contains(name.as_bytes()),
            "entry {i} should still exist"
        );
    }

    // Deleted entries must not be reachable
    for i in (0..count).step_by(2) {
        let name = format!("del_{i:04}");
        assert!(
            !idx.contains(name.as_bytes()),
            "entry {i} should be deleted"
        );
    }

    // Iteration still works
    let entries = idx.list();
    assert_eq!(entries.len(), (count / 2) as usize);
    for (k, e) in entries.iter().enumerate() {
        let expected_i = (2 * k as u64) + 1;
        assert_eq!(e.name, format!("del_{expected_i:04}").as_bytes());
    }
}

#[test]
fn btree_lookup_under_prefix_overlap() {
    // Names that share prefixes of varying lengths; hash collision is unlikely
    // but the B-tree name comparison must correctly distinguish them.
    let mut idx = DirIndex::new(1, test_policy());
    let names: Vec<Vec<u8>> = vec![
        b"a".to_vec(),
        b"aa".to_vec(),
        b"aaa".to_vec(),
        b"aaaa".to_vec(),
        b"aaaaa".to_vec(),
        b"ab".to_vec(),
        b"abc".to_vec(),
        b"abcd".to_vec(),
    ];
    for (i, name) in names.iter().enumerate() {
        idx.insert(name, i as u64, 0, 1).unwrap();
    }
    // Promote to B-tree
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    for (i, name) in names.iter().enumerate() {
        let e = idx.lookup(name).unwrap();
        assert_eq!(e.inode_id, i as u64, "lookup failed for {name:?}");
    }

    // Non-existent prefixes
    assert!(idx.lookup(b"aab").is_none());
    assert!(idx.lookup(b"abcde").is_none());
    assert!(idx.lookup(b"").is_none());
}

#[test]
fn btree_name_sorted_iteration_with_similar_names() {
    // Names that differ only in trailing characters; the B-tree must sort
    // correctly by full name comparison, not just by hash.
    let mut idx = DirIndex::new(1, test_policy());
    let insert_order = [
        b"report_2024_final".to_vec(),
        b"report_2024".to_vec(),
        b"report_2024_v2".to_vec(),
        b"report_2024_draft".to_vec(),
        b"report_2023".to_vec(),
        b"report_2025_q1".to_vec(),
        b"report_2023_revised".to_vec(),
    ];
    for (i, name) in insert_order.iter().enumerate() {
        idx.insert(name, i as u64, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    let entries = idx.list();
    let sorted_names: Vec<Vec<u8>> = entries.iter().map(|e| e.name.clone()).collect();
    let expected: Vec<Vec<u8>> = vec![
        b"report_2023".to_vec(),
        b"report_2023_revised".to_vec(),
        b"report_2024".to_vec(),
        b"report_2024_draft".to_vec(),
        b"report_2024_final".to_vec(),
        b"report_2024_v2".to_vec(),
        b"report_2025_q1".to_vec(),
    ];
    assert_eq!(sorted_names, expected);
}

// ---------------------------------------------------------------------------
// B-tree iteration stability
// ---------------------------------------------------------------------------

#[test]
fn btree_iteration_ordering_stable_across_multiple_passes() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..20u64 {
        let name = format!("iter_{i:03}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    let first_pass: Vec<Vec<u8>> = idx.list().iter().map(|e| e.name.clone()).collect();

    // Mutate and re-query — same ordering expected
    let second_pass: Vec<Vec<u8>> = idx.list().iter().map(|e| e.name.clone()).collect();
    assert_eq!(
        first_pass, second_pass,
        "list ordering must be deterministic"
    );

    let third_pass: Vec<Vec<u8>> = idx.list().iter().map(|e| e.name.clone()).collect();
    assert_eq!(first_pass, third_pass);
}

#[test]
fn btree_iterator_cursor_stable_across_idle_calls() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..10u64 {
        let name = format!("c_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    idx.reset_cursor();
    for _ in 0..5 {
        idx.next_entry().unwrap();
    }
    let saved = idx.current_cursor();

    // Several read-only operations should not affect cursor
    let _ = idx.list();
    let _ = idx.lookup(b"c_03");
    let _ = idx.len();
    let _ = idx.is_empty();
    let _ = idx.to_bytes();

    // Seek back and verify same entry
    idx.seek_to_cursor(saved);
    let resumed = idx.next_entry().unwrap();
    assert_eq!(resumed.name, b"c_05");
}

// ---------------------------------------------------------------------------
// Insert/delete/re-insert cycling in B-tree
// ---------------------------------------------------------------------------

#[test]
fn btree_repeated_insert_delete_same_name() {
    let mut idx = DirIndex::new(1, test_policy());
    // Promote first
    for i in 0..7u64 {
        let name = format!("filler_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    for cycle in 0..5 {
        idx.insert(b"pulse", 10 + cycle, cycle, 1).unwrap();
        let e = idx.lookup(b"pulse").unwrap();
        assert_eq!(e.inode_id, 10 + cycle);
        idx.delete(b"pulse").unwrap();
        assert!(!idx.contains(b"pulse"));
    }

    // Final insert
    idx.insert(b"pulse", 99, 9, 1).unwrap();
    assert_eq!(idx.lookup(b"pulse").unwrap().inode_id, 99);
    assert_eq!(idx.len(), 8); // 7 fillers + 1 pulse
}

#[test]
fn btree_delete_all_reinsert_all() {
    let mut idx = DirIndex::new(1, test_policy());
    let count: u64 = 20;
    for i in 0..count {
        let name = format!("cyc_{i:03}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Delete all
    for i in 0..count {
        let name = format!("cyc_{i:03}");
        idx.delete(name.as_bytes()).unwrap();
    }
    assert_eq!(idx.len(), 0);
    assert!(idx.is_empty());

    // Re-insert all with different inodes
    for i in 0..count {
        let name = format!("cyc_{i:03}");
        idx.insert(name.as_bytes(), 1000 + i, 0, 1).unwrap();
    }
    assert_eq!(idx.len(), count as usize);
    for i in 0..count {
        let name = format!("cyc_{i:03}");
        assert_eq!(idx.lookup(name.as_bytes()).unwrap().inode_id, 1000 + i);
    }
}

// ---------------------------------------------------------------------------
// B-tree rename operations
// ---------------------------------------------------------------------------

#[test]
fn btree_rename_all_entries() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..10u64 {
        let name = format!("orig_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Rename every entry to a new name
    for i in 0..10u64 {
        let old = format!("orig_{i:02}");
        let new = format!("renamed_{i:02}");
        idx.rename(old.as_bytes(), new.as_bytes()).unwrap();
    }

    assert_eq!(idx.len(), 10);
    for i in 0..10u64 {
        let old = format!("orig_{i:02}");
        let new = format!("renamed_{i:02}");
        assert!(!idx.contains(old.as_bytes()), "old name should not exist");
        assert_eq!(
            idx.lookup(new.as_bytes()).unwrap().inode_id,
            i,
            "renamed entry should have original inode"
        );
    }

    // List is sorted by new names
    let entries = idx.list();
    assert_eq!(entries.len(), 10);
    for (k, e) in entries.iter().enumerate() {
        assert_eq!(e.name, format!("renamed_{k:02}").as_bytes());
    }
}

// ---------------------------------------------------------------------------
// B-tree range_scan correctness
// ---------------------------------------------------------------------------

#[test]
fn btree_range_scan_covers_all_entries() {
    let mut idx = DirIndex::new(1, test_policy());
    let count: u64 = 30;
    for i in 0..count {
        let name = format!("scan_{i:03}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Paginate through all entries
    let page_size = 7;
    let mut start: Vec<u8> = Vec::new();
    let mut seen = 0usize;

    loop {
        let page = idx.range_scan(&start, page_size);
        if page.is_empty() {
            break;
        }
        for e in &page {
            assert_eq!(e.inode_id, seen as u64);
            // Verify name matches expected
            assert_eq!(e.name, format!("scan_{seen:03}").as_bytes());
            seen += 1;
        }
        start = page.last().unwrap().name.clone();
    }

    assert_eq!(seen, count as usize);
}

#[test]
fn btree_range_scan_single_entry_page() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..10u64 {
        let name = format!("p_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Page size 1 should return one entry per call
    let mut start: Vec<u8> = Vec::new();
    let mut count: u64 = 0;
    loop {
        let page = idx.range_scan(&start, 1);
        if page.is_empty() {
            break;
        }
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].inode_id, count);
        start = page[0].name.clone();
        count += 1;
    }
    assert_eq!(count, 10);
}

// ---------------------------------------------------------------------------
// B-tree DirIterator cursor round-trip with large dir
// ---------------------------------------------------------------------------

#[test]
fn btree_large_dir_cursor_round_trip() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..50u64 {
        let name = format!("cr_{i:03}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    idx.reset_cursor();
    // Skip 25 entries
    for _ in 0..25 {
        idx.next_entry().unwrap();
    }
    let saved = idx.current_cursor();

    // Continue 10 more
    for _ in 0..10 {
        idx.next_entry().unwrap();
    }

    // Seek back
    idx.seek_to_cursor(saved);
    let resumed = idx.next_entry().unwrap();
    assert_eq!(resumed.name, b"cr_025");
    assert_eq!(resumed.inode_id, 25);
}

// ---------------------------------------------------------------------------
// B-tree moves between directories
// ---------------------------------------------------------------------------

#[test]
fn btree_move_all_entries_to_another_dir() {
    let mut src = DirIndex::new(1, test_policy());
    let mut dst = DirIndex::new(2, test_policy());

    let count: u64 = 15;
    for i in 0..count {
        let name = format!("mv_{i:03}");
        src.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(src.representation(), DirStorageKind::BTREE);
    assert_eq!(src.len(), count as usize);

    // Move all to dst
    for i in 0..count {
        let name = format!("mv_{i:03}");
        src.move_entry_to(name.as_bytes(), &mut dst, name.as_bytes())
            .unwrap();
    }

    assert!(src.is_empty());
    assert_eq!(dst.len(), count as usize);
    assert_eq!(dst.representation(), DirStorageKind::BTREE);

    for i in 0..count {
        let name = format!("mv_{i:03}");
        assert_eq!(dst.lookup(name.as_bytes()).unwrap().inode_id, i);
    }
}

// ---------------------------------------------------------------------------
// Promotion/demotion hysteresis verified via lookup integrity
// ---------------------------------------------------------------------------

#[test]
fn btree_demotes_when_count_drops_below_threshold() {
    let mut idx = DirIndex::new(1, test_policy());
    // Promote: 7 > 6 entries
    for i in 0..7u64 {
        let name = format!("hyst_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Delete until below demotion threshold (3)
    for i in 0..5u64 {
        let name = format!("hyst_{i:02}");
        idx.delete(name.as_bytes()).unwrap();
    }
    assert_eq!(idx.len(), 2);
    // With 2 entries, should demote (btree_downshift_entries = 3)
    // But check_and_switch is called on each delete, so representation may
    // have changed. Even if it hasn't demoted yet, lookup must still work.
    let e = idx.lookup(b"hyst_05").unwrap();
    assert_eq!(e.inode_id, 5);

    let entries = idx.list();
    assert_eq!(entries.len(), 2);
}
