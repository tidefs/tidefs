// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// dir_iterator_empty.rs — Integration tests for DirIterator trait on empty
// DirIndex instances. Verifies that next_entry returns None immediately,
// reset_cursor/seek_to_cursor are no-ops, and current_cursor reports START.

use tidefs_dir_index::{DatasetDirPolicy, DirCookie, DirIndex, DirIterator};

fn test_policy() -> DatasetDirPolicy {
    DatasetDirPolicy {
        dir_micro_max_entries: 6,
        dir_micro_max_name_bytes: 512,
        dir_btree_downshift_entries: 3,
        dir_btree_downshift_name_bytes: 128,
    }
}

// ---------------------------------------------------------------------------
// next_entry on empty directory
// ---------------------------------------------------------------------------

#[test]
fn empty_dir_next_entry_returns_none_immediately() {
    let mut idx = DirIndex::new(1, test_policy());
    assert!(idx.is_empty());
    assert!(idx.next_entry().is_none());
}

#[test]
fn empty_dir_next_entry_always_none_on_repeated_calls() {
    let mut idx = DirIndex::new(1, test_policy());
    for _ in 0..5 {
        assert!(idx.next_entry().is_none());
    }
}

// ---------------------------------------------------------------------------
// reset_cursor on empty directory
// ---------------------------------------------------------------------------

#[test]
fn empty_dir_reset_cursor_does_not_panic() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.reset_cursor(); // should not panic
    assert!(idx.next_entry().is_none());
}

#[test]
fn empty_dir_reset_cursor_idempotent() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.reset_cursor();
    idx.reset_cursor();
    idx.reset_cursor();
    assert!(idx.next_entry().is_none());
}

#[test]
fn empty_dir_reset_then_next_still_none() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.reset_cursor();
    assert!(idx.next_entry().is_none());
    // Even after a second reset
    idx.reset_cursor();
    assert!(idx.next_entry().is_none());
}

// ---------------------------------------------------------------------------
// seek_to_cursor on empty directory
// ---------------------------------------------------------------------------

#[test]
fn empty_dir_seek_to_start_does_not_panic() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.seek_to_cursor(DirCookie::START);
    assert!(idx.next_entry().is_none());
}

#[test]
fn empty_dir_seek_to_arbitrary_cookie_does_not_panic() {
    let mut idx = DirIndex::new(1, test_policy());
    // Create a cookie pointing to entry index 5 (DirCookie encodes micro index)
    let arbitrary = DirCookie(DirCookie::encode_micro(5));
    idx.seek_to_cursor(arbitrary);
    // Should clamp to 0 since total=0, so next_entry yields None
    assert!(idx.next_entry().is_none());
}

#[test]
fn empty_dir_seek_to_btree_cookie_does_not_panic() {
    let mut idx = DirIndex::new(1, test_policy());
    let btree_cookie = DirCookie(DirCookie::encode_btree(3, 7));
    idx.seek_to_cursor(btree_cookie);
    assert!(idx.next_entry().is_none());
}

#[test]
fn empty_dir_seek_to_cursor_then_next_still_none() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.seek_to_cursor(DirCookie::START);
    assert!(idx.next_entry().is_none());

    idx.seek_to_cursor(DirCookie(DirCookie::encode_micro(42)));
    assert!(idx.next_entry().is_none());

    idx.seek_to_cursor(DirCookie(DirCookie::encode_btree(0, 0)));
    assert!(idx.next_entry().is_none());
}

// ---------------------------------------------------------------------------
// current_cursor on empty directory
// ---------------------------------------------------------------------------

#[test]
fn empty_dir_current_cursor_is_start() {
    let idx = DirIndex::new(1, test_policy());
    assert_eq!(idx.current_cursor(), DirCookie::START);
}

#[test]
fn empty_dir_current_cursor_stays_start_after_none_yields() {
    let mut idx = DirIndex::new(1, test_policy());
    assert_eq!(idx.current_cursor(), DirCookie::START);
    let _ = idx.next_entry(); // None
                              // After yielding None on empty, cursor should still be START
                              // because cursor=0, total=0, cookie_from_index(0) = DirCookie::START
    assert_eq!(idx.current_cursor(), DirCookie::START);
}

#[test]
fn empty_dir_current_cursor_stays_start_after_reset() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.reset_cursor();
    assert_eq!(idx.current_cursor(), DirCookie::START);
}

#[test]
fn empty_dir_current_cursor_unchanged_after_seek_to_start() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.seek_to_cursor(DirCookie::START);
    assert_eq!(idx.current_cursor(), DirCookie::START);
}

#[test]
fn empty_dir_current_cursor_after_seek_to_arbitrary_cookie() {
    let mut idx = DirIndex::new(1, test_policy());
    let arbitrary = DirCookie(DirCookie::encode_micro(5));
    idx.seek_to_cursor(arbitrary);
    // After seek with total=0, index_from_cookie clamps to 0,
    // so current_cursor should be cookie_from_index(0) = START
    assert_eq!(idx.current_cursor(), DirCookie::START);
}

// ---------------------------------------------------------------------------
// Full cycle: insert, delete all, iterate empty
// ---------------------------------------------------------------------------

#[test]
fn insert_then_delete_all_yields_empty_iterator() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"temp", 1, 0, 1).unwrap();
    assert!(idx.next_entry().is_some());

    // Delete the only entry
    idx.delete(b"temp").unwrap();
    assert!(idx.is_empty());
    assert!(idx.next_entry().is_none());
}

#[test]
fn insert_then_delete_all_iterator_reset_works() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..5u64 {
        let name = format!("del_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    for i in 0..5u64 {
        let name = format!("del_{i:02}");
        idx.delete(name.as_bytes()).unwrap();
    }
    assert!(idx.is_empty());

    // Iterator on now-empty directory
    idx.reset_cursor();
    assert!(idx.next_entry().is_none());
    assert_eq!(idx.current_cursor(), DirCookie::START);
}

// ---------------------------------------------------------------------------
// Representation transitions don't break empty iterator
// ---------------------------------------------------------------------------

#[test]
fn promote_then_demote_to_empty_iterator() {
    let mut idx = DirIndex::new(1, test_policy());
    // Promote to B-tree
    for i in 0..7u64 {
        let name = format!("pde_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(
        idx.representation(),
        tidefs_dir_index::DirStorageKind::BTREE
    );

    // Delete all to demote
    for i in 0..7u64 {
        let name = format!("pde_{i:02}");
        idx.delete(name.as_bytes()).unwrap();
    }
    assert!(idx.is_empty());
    // After deleting all, representation may be micro (demoted) or still btree
    // depending on hysteresis — but iterator must work in both cases
    assert!(idx.next_entry().is_none());
    assert_eq!(idx.current_cursor(), DirCookie::START);
}

// ---------------------------------------------------------------------------
// Empty dir created from to_bytes/from_bytes
// ---------------------------------------------------------------------------

#[test]
fn from_bytes_roundtrip_empty_preserves_empty_iterator() {
    let idx = DirIndex::new(99, test_policy());
    let bytes = idx.to_bytes();
    let mut restored = DirIndex::from_bytes(&bytes, test_policy()).unwrap();

    assert!(restored.is_empty());
    assert!(restored.next_entry().is_none());
    assert_eq!(restored.current_cursor(), DirCookie::START);
}
