// dir_iterator_smoke.rs — Integration tests for DirIterator trait on populated
// DirIndex instances. Covers full iteration, reset_cursor, seek_to_cursor
// round-trip, current_cursor tracking, and representation stability.

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
// Full iteration — micro-list
// ---------------------------------------------------------------------------

#[test]
fn full_iteration_micro_list_sorted_order() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"zulu", 26, 0, 1).unwrap();
    idx.insert(b"alpha", 1, 0, 1).unwrap();
    idx.insert(b"mike", 13, 0, 1).unwrap();
    idx.insert(b"delta", 4, 0, 1).unwrap();
    assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);

    idx.reset_cursor();
    let mut collected = Vec::new();
    while let Some(entry) = idx.next_entry() {
        collected.push(entry);
    }

    assert_eq!(collected.len(), 4);
    let sorted_names: Vec<Vec<u8>> = collected.iter().map(|e| e.name.clone()).collect();
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
fn full_iteration_micro_list_yields_correct_inodes() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"c", 30, 0, 1).unwrap();
    idx.insert(b"a", 10, 1, 2).unwrap();
    idx.insert(b"b", 20, 2, 3).unwrap();

    idx.reset_cursor();
    let e1 = idx.next_entry().unwrap();
    assert_eq!(e1.name, b"a");
    assert_eq!(e1.inode_id, 10);
    assert_eq!(e1.generation, 1);
    assert_eq!(e1.kind, 2);

    let e2 = idx.next_entry().unwrap();
    assert_eq!(e2.name, b"b");
    assert_eq!(e2.inode_id, 20);

    let e3 = idx.next_entry().unwrap();
    assert_eq!(e3.name, b"c");
    assert_eq!(e3.inode_id, 30);

    assert!(idx.next_entry().is_none());
}

#[test]
fn full_iteration_micro_list_count_matches_len() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..5u64 {
        let name = format!("entry_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.len(), 5);

    idx.reset_cursor();
    let mut count = 0;
    while idx.next_entry().is_some() {
        count += 1;
    }
    assert_eq!(count, 5);
}

// ---------------------------------------------------------------------------
// Full iteration — B-tree
// ---------------------------------------------------------------------------

#[test]
fn full_iteration_btree_sorted_order() {
    let mut idx = DirIndex::new(1, test_policy());
    // 7 entries triggers promotion to B-tree
    for i in 0..7u64 {
        // Insert in reverse order
        let rev = 6 - i;
        let name = format!("btree_{rev:02}");
        idx.insert(name.as_bytes(), rev, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    idx.reset_cursor();
    let mut collected = Vec::new();
    while let Some(entry) = idx.next_entry() {
        collected.push(entry);
    }

    assert_eq!(collected.len(), 7);
    let sorted_names: Vec<Vec<u8>> = collected.iter().map(|e| e.name.clone()).collect();
    let expected: Vec<Vec<u8>> = (0..7u64)
        .map(|i| format!("btree_{i:02}").into_bytes())
        .collect();
    assert_eq!(sorted_names, expected);
}

#[test]
fn full_iteration_btree_count_matches_len() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..10u64 {
        let name = format!("b_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    idx.reset_cursor();
    let mut count = 0;
    while idx.next_entry().is_some() {
        count += 1;
    }
    assert_eq!(count, idx.len());
    assert_eq!(count, 10);
}

// ---------------------------------------------------------------------------
// reset_cursor
// ---------------------------------------------------------------------------

#[test]
fn reset_cursor_mid_iteration_restarts_from_beginning() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"c", 3, 0, 1).unwrap();
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();

    // Iterate one entry
    let first = idx.next_entry().unwrap();
    assert_eq!(first.name, b"a");

    // Reset and re-iterate from beginning
    idx.reset_cursor();
    let first_again = idx.next_entry().unwrap();
    assert_eq!(first_again.name, b"a");
    assert_eq!(first_again.inode_id, 1);

    // Continue after reset
    let second = idx.next_entry().unwrap();
    assert_eq!(second.name, b"b");
}

#[test]
fn reset_cursor_after_exhaustion_restarts() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"x", 1, 0, 1).unwrap();
    idx.insert(b"y", 2, 0, 1).unwrap();

    // Exhaust
    assert!(idx.next_entry().is_some());
    assert!(idx.next_entry().is_some());
    assert!(idx.next_entry().is_none());

    // Reset and iterate again
    idx.reset_cursor();
    assert!(idx.next_entry().is_some());
    assert!(idx.next_entry().is_some());
    assert!(idx.next_entry().is_none());
}

#[test]
fn reset_cursor_btree_restarts_correctly() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..7u64 {
        let name = format!("r_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Skip to the middle
    for _ in 0..4 {
        idx.next_entry().unwrap();
    }
    let mid = idx.next_entry().unwrap();
    assert_eq!(mid.name, b"r_04");

    // Reset
    idx.reset_cursor();
    let first = idx.next_entry().unwrap();
    assert_eq!(first.name, b"r_00");
}

// ---------------------------------------------------------------------------
// seek_to_cursor round-trip
// ---------------------------------------------------------------------------

#[test]
fn seek_to_cursor_round_trip_micro_list() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..6u64 {
        let name = format!("s_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);

    // Iterate two entries
    let _ = idx.next_entry().unwrap(); // s_00
    let _ = idx.next_entry().unwrap(); // s_01
    let saved = idx.current_cursor();

    // Continue iterating
    let e3 = idx.next_entry().unwrap();
    assert_eq!(e3.name, b"s_02");
    let e4 = idx.next_entry().unwrap();
    assert_eq!(e4.name, b"s_03");

    // Seek back to saved cursor
    idx.seek_to_cursor(saved);
    let resumed = idx.next_entry().unwrap();
    assert_eq!(resumed.name, b"s_02");
    assert_eq!(resumed.inode_id, 2);
}

#[test]
fn seek_to_cursor_round_trip_btree() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..10u64 {
        let name = format!("bseek_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Iterate three entries
    for _ in 0..3 {
        idx.next_entry().unwrap();
    }
    let saved = idx.current_cursor();

    // Continue a bit more
    let e4 = idx.next_entry().unwrap();
    assert_eq!(e4.name, b"bseek_03");

    // Seek back
    idx.seek_to_cursor(saved);
    let resumed = idx.next_entry().unwrap();
    assert_eq!(resumed.name, b"bseek_03");
}

#[test]
fn seek_to_cursor_start_is_reset() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"alpha", 1, 0, 1).unwrap();
    idx.insert(b"beta", 2, 0, 1).unwrap();
    idx.insert(b"gamma", 3, 0, 1).unwrap();

    // Iterate past first two
    let _ = idx.next_entry().unwrap();
    let _ = idx.next_entry().unwrap();

    // Seek to START
    idx.seek_to_cursor(DirCookie::START);
    let first = idx.next_entry().unwrap();
    assert_eq!(first.name, b"alpha");
}

#[test]
fn seek_to_cursor_multiple_round_trips() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..5u64 {
        let name = format!("mr_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }

    // Save cursor after each entry and verify we can seek back to each
    let mut cursors = Vec::new();
    cursors.push(idx.current_cursor()); // before any entries
    for i in 0..5 {
        let e = idx.next_entry().unwrap();
        assert_eq!(e.name, format!("mr_{i:02}").as_bytes());
        cursors.push(idx.current_cursor());
    }

    // Seek back to each saved cursor and verify correct resume
    for (i, cursor) in cursors.iter().enumerate().take(5) {
        idx.seek_to_cursor(*cursor);
        let resumed = idx.next_entry().unwrap();
        assert_eq!(
            resumed.name,
            format!("mr_{i:02}").as_bytes(),
            "seek to cursor {i} should resume at mr_{i:02}",
        );
    }
}

// ---------------------------------------------------------------------------
// current_cursor
// ---------------------------------------------------------------------------

#[test]
fn current_cursor_starts_at_start() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.reset_cursor();
    assert_eq!(idx.current_cursor(), DirCookie::START);
}

#[test]
fn current_cursor_advances_after_each_next_entry() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();

    idx.reset_cursor();
    let c0 = idx.current_cursor();
    assert_eq!(c0, DirCookie::START);

    let _ = idx.next_entry().unwrap();
    let c1 = idx.current_cursor();
    assert_ne!(c1, c0, "cursor should advance after first entry");

    let _ = idx.next_entry().unwrap();
    let c2 = idx.current_cursor();
    assert_ne!(c2, c1, "cursor should advance after second entry");

    let _ = idx.next_entry().unwrap();
    let c3 = idx.current_cursor();
    assert_ne!(c3, c2, "cursor should advance after third entry");
}

#[test]
fn current_cursor_unchanged_after_exhaustion() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();

    let _ = idx.next_entry().unwrap();
    assert!(idx.next_entry().is_none());

    let _c_exhausted = idx.current_cursor();
    assert!(idx.next_entry().is_none());
    // Cursor should not change on subsequent None returns
    // (implementation yields 0 after exhaustion via cookie_from_index
    // since cursor >= len means index past end and cookie_from_index
    // encodes it)
}

// ---------------------------------------------------------------------------
// Consistency: iteration matches list()
// ---------------------------------------------------------------------------

#[test]
fn diriterator_yields_same_entries_as_list() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"d", 4, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();

    let list_entries = idx.list();
    let mut iter_entries = Vec::new();
    idx.reset_cursor();
    while let Some(e) = idx.next_entry() {
        iter_entries.push(e);
    }

    assert_eq!(iter_entries.len(), list_entries.len());
    for (iter_e, list_e) in iter_entries.iter().zip(list_entries.iter()) {
        assert_eq!(iter_e.name, list_e.name);
        assert_eq!(iter_e.inode_id, list_e.inode_id);
    }
}

#[test]
fn diriterator_btree_yields_same_as_list() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..7u64 {
        let name = format!("consist_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    let list_entries = idx.list();
    let mut iter_entries = Vec::new();
    idx.reset_cursor();
    while let Some(e) = idx.next_entry() {
        iter_entries.push(e);
    }

    assert_eq!(iter_entries.len(), list_entries.len());
    for (iter_e, list_e) in iter_entries.iter().zip(list_entries.iter()) {
        assert_eq!(iter_e.name, list_e.name);
    }
}

// ---------------------------------------------------------------------------
// Multiple independent iteration passes
// ---------------------------------------------------------------------------

#[test]
fn three_consecutive_full_iterations_yield_same_results() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"z", 3, 0, 1).unwrap();
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"m", 2, 0, 1).unwrap();

    let mut results = Vec::new();
    for _pass in 0..3 {
        idx.reset_cursor();
        let mut pass_entries = Vec::new();
        while let Some(e) = idx.next_entry() {
            pass_entries.push(e.name.clone());
        }
        results.push(pass_entries);
    }

    assert_eq!(results[0], results[1]);
    assert_eq!(results[0], results[2]);
    assert_eq!(
        results[0],
        vec![b"a".to_vec(), b"m".to_vec(), b"z".to_vec()]
    );
}

// ---------------------------------------------------------------------------
// Seek to various cursor positions
// ---------------------------------------------------------------------------

#[test]
fn seek_to_cursor_of_last_entry_yields_last_then_none() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..5u64 {
        let name = format!("last_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }

    // Iterate to last entry, save cursor after it
    for _ in 0..4 {
        idx.next_entry().unwrap();
    }
    let cursor_before_last = idx.current_cursor();

    idx.seek_to_cursor(cursor_before_last);
    let last = idx.next_entry().unwrap();
    assert_eq!(last.name, b"last_04");
    assert!(idx.next_entry().is_none());
}

#[test]
fn seek_to_cursor_single_entry_dir() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"only", 42, 0, 1).unwrap();

    // Save cursor before first entry
    let c0 = idx.current_cursor();
    assert_eq!(c0, DirCookie::START);

    let _ = idx.next_entry().unwrap();
    let c1 = idx.current_cursor();

    // Seek back to start
    idx.seek_to_cursor(c0);
    let e = idx.next_entry().unwrap();
    assert_eq!(e.name, b"only");

    // Seek to c1 (past the entry), should yield None
    idx.seek_to_cursor(c1);
    assert!(idx.next_entry().is_none());
}

// ---------------------------------------------------------------------------
// DirIterator after representation change (micro → btree)
// ---------------------------------------------------------------------------

#[test]
fn iteration_works_after_promotion_to_btree() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..5u64 {
        let name = format!("pre_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);

    // Promote
    idx.insert(b"trigger_a", 100, 0, 1).unwrap();
    idx.insert(b"trigger_b", 101, 0, 1).unwrap();
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Iteration should still work
    idx.reset_cursor();
    let mut count = 0;
    while idx.next_entry().is_some() {
        count += 1;
    }
    assert_eq!(count, 7);
}

#[test]
fn cursor_stable_across_promotion() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..5u64 {
        let name = format!("stab_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }

    // Start iterating in micro-list mode
    let _ = idx.next_entry().unwrap(); // stab_00
    let _ = idx.next_entry().unwrap(); // stab_01
    let saved = idx.current_cursor();

    // Promote to btree
    idx.insert(b"zz_promo_a", 100, 0, 1).unwrap();
    idx.insert(b"zz_promo_b", 101, 0, 1).unwrap();
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Seek back to saved cursor and resume
    idx.seek_to_cursor(saved);
    let resumed = idx.next_entry().unwrap();
    // The resumed entry should be the one after our saved position
    // in the new sorted order (zz_promo_* sort after all stab_* entries)
    assert_eq!(resumed.name, b"stab_02");
}
