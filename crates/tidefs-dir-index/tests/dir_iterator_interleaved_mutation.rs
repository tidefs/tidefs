// dir_iterator_interleaved_mutation.rs — Integration tests for DirIterator
// behaviour when DirIndex entries are inserted, deleted, replaced, or renamed
// between next_entry() calls.
//
// Since DirIterator for DirIndex re-reads the live entry list on each
// next_entry() call, mutations are reflected in subsequent iteration results.

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
// Insertion between next_entry calls
// ---------------------------------------------------------------------------

#[test]
fn insert_after_cursor_appears_in_remaining_iteration() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();
    idx.insert(b"e", 5, 0, 1).unwrap();

    idx.reset_cursor();
    let first = idx.next_entry().unwrap();
    assert_eq!(first.name, b"a");

    // Insert an entry that sorts after the current cursor ("a" < "b" < "c")
    idx.insert(b"b", 2, 0, 1).unwrap();

    // Continue iteration — "b" should appear
    let second = idx.next_entry().unwrap();
    assert_eq!(second.name, b"b", "inserted entry should appear in order");
    assert_eq!(second.inode_id, 2);

    let third = idx.next_entry().unwrap();
    assert_eq!(third.name, b"c");

    let fourth = idx.next_entry().unwrap();
    assert_eq!(fourth.name, b"e");

    assert!(idx.next_entry().is_none());
}

#[test]
fn insert_before_cursor_re_yields_shifted_entry() {
    // Inserting before the cursor shifts all entries right by one.
    // The entry that was at cursor position moves to cursor+1 and
    // will be yielded again on the next call.
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();
    idx.insert(b"d", 4, 0, 1).unwrap();

    idx.reset_cursor();
    let first = idx.next_entry().unwrap();
    assert_eq!(first.name, b"b");

    // Insert "a" before cursor: list goes [a,b,c,d], cursor=1 is now "b" again
    idx.insert(b"a", 1, 0, 1).unwrap();

    // Cursor index 1 in [a,b,c,d] is still "b" — it gets yielded twice
    let second = idx.next_entry().unwrap();
    assert_eq!(second.name, b"b");

    let third = idx.next_entry().unwrap();
    assert_eq!(third.name, b"c");

    let fourth = idx.next_entry().unwrap();
    assert_eq!(fourth.name, b"d");

    assert!(idx.next_entry().is_none());
}

#[test]
fn insert_multiple_entries_between_calls() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"z", 2, 0, 1).unwrap();

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // "a"

    // Insert several entries that sort between "a" and "z"
    idx.insert(b"m", 10, 0, 1).unwrap();
    idx.insert(b"c", 11, 0, 1).unwrap();
    idx.insert(b"x", 12, 0, 1).unwrap();

    let mut remaining = Vec::new();
    while let Some(e) = idx.next_entry() {
        remaining.push(e.name);
    }

    assert_eq!(
        remaining,
        vec![b"c".to_vec(), b"m".to_vec(), b"x".to_vec(), b"z".to_vec()]
    );
}

#[test]
fn insert_after_cursor_in_btree() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..7u64 {
        let name = format!("bt_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // bt_00
    let _ = idx.next_entry().unwrap(); // bt_01

    // Insert entry that sorts after bt_01
    idx.insert(b"bt_01a", 99, 0, 1).unwrap();

    let mut names = Vec::new();
    while let Some(e) = idx.next_entry() {
        names.push(e.name);
    }

    assert!(names.contains(&b"bt_01a".to_vec()));
}

// ---------------------------------------------------------------------------
// Deletion between next_entry calls
// ---------------------------------------------------------------------------

#[test]
fn delete_entry_ahead_of_cursor_removes_it_from_iteration() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();
    idx.insert(b"d", 4, 0, 1).unwrap();

    idx.reset_cursor();
    let first = idx.next_entry().unwrap();
    assert_eq!(first.name, b"a");

    // Delete "c" which is ahead of the cursor
    idx.delete(b"c").unwrap();

    // Continue — should see "b", then "d" (skipping "c")
    let second = idx.next_entry().unwrap();
    assert_eq!(second.name, b"b");

    let third = idx.next_entry().unwrap();
    assert_eq!(third.name, b"d");

    assert!(idx.next_entry().is_none());
}

#[test]
fn delete_already_yielded_entry_no_effect_on_remaining() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();
    idx.insert(b"d", 4, 0, 1).unwrap();

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // "a"
    let _ = idx.next_entry().unwrap(); // "b"

    // Delete "a" which was already yielded.
    // List shifts from [a,b,c,d] → [b,c,d]; cursor=2 now points to "d"
    idx.delete(b"a").unwrap();

    // Cursor at index 2 of [b,c,d] yields "d"
    let third = idx.next_entry().unwrap();
    assert_eq!(third.name, b"d");
    assert!(idx.next_entry().is_none());
}

#[test]
fn delete_currently_yielded_entry() {
    // After yielding an entry, deleting it does not affect the cursor.
    // The entry is gone from the index but the cursor index refers to
    // the next position in the (now shorter) list. The entry at that
    // index is the one that was after the deleted entry.
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // "a"
    let _ = idx.next_entry().unwrap(); // "b"

    // Delete "b" — it was just yielded
    idx.delete(b"b").unwrap();

    // Cursor is at index 2, but list is now ["a", "c"] (length 2)
    // So cursor >= len, next_entry() returns None
    assert!(idx.next_entry().is_none());
}

#[test]
fn delete_all_ahead_entries_yields_none_early() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // "a"

    // Delete everything after cursor
    idx.delete(b"b").unwrap();
    idx.delete(b"c").unwrap();

    assert!(idx.next_entry().is_none());
}

#[test]
fn delete_and_reinsert_same_name() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // "a"

    // Delete "b", then re-insert with different inode
    idx.delete(b"b").unwrap();
    idx.insert(b"b", 99, 9, 9).unwrap();

    let mut remaining = Vec::new();
    while let Some(e) = idx.next_entry() {
        remaining.push((e.name, e.inode_id));
    }

    assert_eq!(remaining.len(), 2);
    assert_eq!(remaining[0], (b"b".to_vec(), 99));
    assert_eq!(remaining[1], (b"c".to_vec(), 3));
}

// ---------------------------------------------------------------------------
// Replace between next_entry calls
// ---------------------------------------------------------------------------

#[test]
fn replace_entry_ahead_of_cursor_shows_new_values() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 2).unwrap();
    idx.insert(b"c", 3, 0, 3).unwrap();

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // "a"

    // Replace "c" before we reach it
    idx.replace(b"c", 99, 9, 9);

    let second = idx.next_entry().unwrap();
    assert_eq!(second.name, b"b");

    let third = idx.next_entry().unwrap();
    assert_eq!(third.name, b"c");
    assert_eq!(third.inode_id, 99);
    assert_eq!(third.generation, 9);
    assert_eq!(third.kind, 9);

    assert!(idx.next_entry().is_none());
}

#[test]
fn replace_already_yielded_entry_no_effect_on_remaining() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // "a"

    // Replace "a" (already yielded)
    idx.replace(b"a", 99, 9, 9);

    let second = idx.next_entry().unwrap();
    assert_eq!(second.name, b"b");
    assert!(idx.next_entry().is_none());
}

// ---------------------------------------------------------------------------
// Rename between next_entry calls
// ---------------------------------------------------------------------------

#[test]
fn rename_entry_ahead_of_cursor_to_later_name() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // "a"

    // Rename "b" → "z" — moves it to end of sorted order
    idx.rename(b"b", b"z").unwrap();

    // Should see "c" next (since "b" was renamed to "z" which comes after)
    // But careful: cursor is at index 1, list is ["a","c","z"], so next is "c"
    let second = idx.next_entry().unwrap();
    assert_eq!(second.name, b"c");

    let third = idx.next_entry().unwrap();
    assert_eq!(third.name, b"z");

    assert!(idx.next_entry().is_none());
}

#[test]
fn rename_entry_before_cursor() {
    // Renaming an already-yielded entry should not affect remaining iteration
    // because the cursor has moved past it.
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();
    idx.insert(b"d", 4, 0, 1).unwrap();

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // "b"
    let _ = idx.next_entry().unwrap(); // "c"

    // Rename "b" → "a" (already yielded entry)
    idx.rename(b"b", b"a").unwrap();

    // Cursor is at index 2, list after rename is ["a","c","d"]
    // So next should be "d" (index 2)
    let third = idx.next_entry().unwrap();
    assert_eq!(third.name, b"d");
    assert!(idx.next_entry().is_none());
}

#[test]
fn rename_entry_ahead_to_before_cursor_shifts_entries() {
    // Renaming "d" → "a" shifts all entries: [b,c,d] → [a,b,c].
    // Cursor was at 1 (pointing to "c"), now cursor=1 is "b" (a duplicate).
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();
    idx.insert(b"d", 4, 0, 1).unwrap();

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // "b"

    // Rename "d" → "a": list becomes [a,b,c], cursor=1 now points to "b"
    idx.rename(b"d", b"a").unwrap();

    // Cursor 1 is "b" (already yielded), then "c"
    let second = idx.next_entry().unwrap();
    assert_eq!(second.name, b"b");

    let third = idx.next_entry().unwrap();
    assert_eq!(third.name, b"c");

    assert!(idx.next_entry().is_none());
}

// ---------------------------------------------------------------------------
// Mixed mutation scenarios
// ---------------------------------------------------------------------------

#[test]
fn insert_and_delete_between_calls() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"d", 4, 0, 1).unwrap();
    idx.insert(b"e", 5, 0, 1).unwrap();

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // "a"

    // Insert "b" and "c", then delete "d"
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();
    idx.delete(b"d").unwrap();

    let mut remaining = Vec::new();
    while let Some(e) = idx.next_entry() {
        remaining.push(e.name);
    }

    assert_eq!(remaining, vec![b"b".to_vec(), b"c".to_vec(), b"e".to_vec()]);
}

#[test]
fn mutation_frenzy() {
    let mut idx = DirIndex::new(1, test_policy());
    // Start with entries a,b,c,d,e,f,g (7 → btree)
    for (i, name) in [b"a", b"b", b"c", b"d", b"e", b"f", b"g"]
        .iter()
        .enumerate()
    {
        idx.insert(*name, i as u64, 0, 1).unwrap();
    }

    idx.reset_cursor();
    let e1 = idx.next_entry().unwrap();
    assert_eq!(e1.name, b"a");

    // Mutate: delete b, rename c→cc, insert a1, replace e
    idx.delete(b"b").unwrap();
    idx.rename(b"c", b"cc").unwrap();
    idx.insert(b"a1", 99, 0, 1).unwrap();
    idx.replace(b"e", 88, 8, 8);

    let e2 = idx.next_entry().unwrap();
    assert_eq!(e2.name, b"a1", "a1 sorts after a, should be next");

    let e3 = idx.next_entry().unwrap();
    assert_eq!(e3.name, b"cc");

    let e4 = idx.next_entry().unwrap();
    assert_eq!(e4.name, b"d");

    let e5 = idx.next_entry().unwrap();
    assert_eq!(e5.name, b"e");
    assert_eq!(e5.inode_id, 88);

    let e6 = idx.next_entry().unwrap();
    assert_eq!(e6.name, b"f");

    let e7 = idx.next_entry().unwrap();
    assert_eq!(e7.name, b"g");

    assert!(idx.next_entry().is_none());
}

// ---------------------------------------------------------------------------
// DirIterator cursor saved before mutation, seek back after mutation
// ---------------------------------------------------------------------------

#[test]
fn save_cursor_before_mutation_seek_back_after() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();

    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // "a"
    let saved = idx.current_cursor();
    let _ = idx.next_entry().unwrap(); // "b"

    // Mutate
    idx.insert(b"aa", 99, 0, 1).unwrap(); // sorts between a and b
    idx.delete(b"c").unwrap();

    // Seek back to saved cursor (should resume after "a")
    idx.seek_to_cursor(saved);
    let resumed = idx.next_entry().unwrap();
    // After mutation: list is [a, aa, b], saved cursor was at index 1
    // which now points to "aa" instead of "b"
    assert_eq!(resumed.name, b"aa");

    let next = idx.next_entry().unwrap();
    assert_eq!(next.name, b"b");

    assert!(idx.next_entry().is_none());
}

// ---------------------------------------------------------------------------
// Mutation during btree iteration
// ---------------------------------------------------------------------------

#[test]
fn insert_after_cursor_in_btree_preserves_iteration() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..10u64 {
        let name = format!("m_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    idx.reset_cursor();
    for _ in 0..5 {
        idx.next_entry().unwrap(); // m_00 through m_04
    }

    // Insert entries that sort after m_04
    idx.insert(b"m_04a", 100, 0, 1).unwrap();
    idx.insert(b"m_04b", 101, 0, 1).unwrap();

    // Delete m_07 and m_08 ahead of cursor
    idx.delete(b"m_07").unwrap();
    idx.delete(b"m_08").unwrap();

    let mut remaining_names = Vec::new();
    while let Some(e) = idx.next_entry() {
        remaining_names.push(e.name);
    }

    assert!(remaining_names.contains(&b"m_04a".to_vec()));
    assert!(remaining_names.contains(&b"m_04b".to_vec()));
    assert!(!remaining_names.contains(&b"m_07".to_vec()));
    assert!(!remaining_names.contains(&b"m_08".to_vec()));
}

// ---------------------------------------------------------------------------
// move_entry_to between directories during iteration
// ---------------------------------------------------------------------------

#[test]
fn move_entry_to_during_iteration() {
    let mut src = DirIndex::new(1, test_policy());
    let mut dst = DirIndex::new(2, test_policy());

    src.insert(b"a", 1, 0, 1).unwrap();
    src.insert(b"b", 2, 0, 1).unwrap();
    src.insert(b"c", 3, 0, 1).unwrap();

    dst.insert(b"x", 99, 0, 1).unwrap();

    src.reset_cursor();
    let _ = src.next_entry().unwrap(); // "a"

    // Move "c" to dst
    src.move_entry_to(b"c", &mut dst, b"c_moved").unwrap();

    // Src should now yield only "b"
    let remaining: Vec<Vec<u8>> = (0..)
        .map(|_| src.next_entry())
        .take_while(|e| e.is_some())
        .map(|e| e.unwrap().name)
        .collect();

    assert_eq!(remaining, vec![b"b".to_vec()]);
    assert_eq!(src.len(), 2); // a, b remain

    // Dst should have both entries
    assert_eq!(dst.len(), 2);
    assert!(dst.contains(b"x"));
    assert!(dst.contains(b"c_moved"));
}
