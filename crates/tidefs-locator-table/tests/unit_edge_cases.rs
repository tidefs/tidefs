//! Edge-case unit tests for tidefs-locator-table covering gaps not
//! exercised by the existing inline and integration test suites:
//! zero-length entries, maximum valid offset, delete-all verification,
//! double-delete idempotency, and interleaved operations on an empty
//! table.

use std::path::Path;
use tidefs_local_object_store::{LocalObjectStore, StoreOptions};
use tidefs_locator_table::{ExtentId, LocatorEntry, LocatorError, LocatorTable};

fn make_store(dir: &Path) -> LocalObjectStore {
    let mut opts = StoreOptions::test_fast();
    opts.max_segment_bytes = 8192;
    LocalObjectStore::open_with_options(dir, opts).expect("open store")
}

fn make_table(dir: &Path) -> LocatorTable {
    LocatorTable::new(make_store(dir), 1)
}

// ── Zero-length entry ──────────────────────────────────────────

#[test]
fn insert_zero_length_entry_lookup_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let entry = LocatorEntry::new(0, ExtentId(1), 0, 4096, 0, 0);
    table.insert(1, entry).unwrap();

    let found = table.lookup(1, 0).unwrap();
    assert_eq!(found, Some(entry));
    assert_eq!(found.unwrap().length, 0);
}

#[test]
fn zero_length_entry_persists_across_reopen() {
    let dir = tempfile::tempdir().unwrap();

    let entry = LocatorEntry::new(4096, ExtentId(42), 0, 8192, 0, 0x01);
    {
        let table = make_table(dir.path());
        table.insert(1, entry).unwrap();
    }
    {
        let store = make_store(dir.path());
        let table = LocatorTable::new(store, 1);
        let found = table.lookup(1, 4096).unwrap();
        assert_eq!(found, Some(entry));
        assert_eq!(found.unwrap().length, 0);
    }
}

#[test]
fn zero_length_entry_lookup_extent_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let entry = LocatorEntry::new(0, ExtentId(99), 0, 0, 0, 0);
    table.insert(1, entry).unwrap();

    let found = table.lookup_extent(1, ExtentId(99)).unwrap();
    assert_eq!(found, Some(entry));
}

#[test]
fn zero_length_entry_can_be_removed() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let entry = LocatorEntry::new(0, ExtentId(1), 0, 4096, 0, 0);
    table.insert(1, entry).unwrap();
    assert_eq!(table.len(1), 1);

    table.remove(1, 0).unwrap();
    assert_eq!(table.len(1), 0);
    assert_eq!(table.lookup(1, 0).unwrap(), None);
}

#[test]
fn zero_length_entry_can_be_relocated() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let entry = LocatorEntry::new(0, ExtentId(1), 0, 0, 0, 0);
    table.insert(1, entry).unwrap();

    table.relocate_extent(1, ExtentId(1), 0, 16384).unwrap();

    let found = table.lookup(1, 0).unwrap().unwrap();
    assert_eq!(found.physical_offset, 16384);
    assert_eq!(found.length, 0);
}

// ── Maximum valid offset ───────────────────────────────────────

#[test]
fn insert_max_valid_offset_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    // u64::MAX-2 is the highest valid logical_offset (below the two sentinels).
    let max_off = u64::MAX - 2;
    let entry = LocatorEntry::new(max_off, ExtentId(7), 0, 1024, 4096, 0);
    table.insert(1, entry).unwrap();

    let found = table.lookup(1, max_off).unwrap();
    assert_eq!(found, Some(entry));
}

#[test]
fn max_valid_offset_lookup_extent_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let max_off = u64::MAX - 2;
    let entry = LocatorEntry::new(max_off, ExtentId(77), 0, 2048, 512, 0);
    table.insert(1, entry).unwrap();

    let found = table.lookup_extent(1, ExtentId(77)).unwrap();
    assert_eq!(found, Some(entry));
}

#[test]
fn max_valid_offset_can_be_removed_and_reinserted() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let max_off = u64::MAX - 2;
    let e1 = LocatorEntry::new(max_off, ExtentId(10), 0, 0, 64, 0);
    table.insert(1, e1).unwrap();
    table.remove(1, max_off).unwrap();

    let e2 = LocatorEntry::new(max_off, ExtentId(20), 0, 128, 128, 0);
    table.insert(1, e2).unwrap();

    assert_eq!(table.lookup(1, max_off).unwrap(), Some(e2));
}

#[test]
fn max_valid_offset_mixed_with_small_offsets() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let small = LocatorEntry::new(0, ExtentId(1), 0, 0, 64, 0);
    let max_off = u64::MAX - 2;
    let large = LocatorEntry::new(max_off, ExtentId(2), 0, 64, 4096, 0);
    let mid = LocatorEntry::new(4096, ExtentId(3), 0, 4160, 128, 0);

    table.insert(1, small).unwrap();
    table.insert(1, large).unwrap();
    table.insert(1, mid).unwrap();

    assert_eq!(table.lookup(1, 0).unwrap(), Some(small));
    assert_eq!(table.lookup(1, max_off).unwrap(), Some(large));
    assert_eq!(table.lookup(1, 4096).unwrap(), Some(mid));
    assert_eq!(table.len(1), 3);
}

// ── Delete-all verification ────────────────────────────────────

#[test]
fn delete_all_entries_verify_empty() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let mut offsets: Vec<u64> = Vec::new();
    for i in 0..11 {
        let off = i * 64;
        table
            .insert(
                1,
                LocatorEntry::new(off, ExtentId(i + 1), 0, off * 2, 64, (i % 256) as u8),
            )
            .unwrap();
        offsets.push(off);
    }
    assert_eq!(table.len(1), 11);

    // Remove every one.
    for off in &offsets {
        table.remove(1, *off).unwrap();
    }

    assert_eq!(table.len(1), 0);

    // Verify no phantom entries.
    for off in &offsets {
        assert_eq!(table.lookup(1, *off).unwrap(), None);
    }

    // Verify iterate yields nothing.
    let entries: Vec<LocatorEntry> = table.iterate(1).unwrap().collect();
    assert!(entries.is_empty());
}

#[test]
fn delete_all_then_reinsert_works() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    for i in 0..10 {
        table
            .insert(
                1,
                LocatorEntry::new(i * 64, ExtentId(100 + i), 0, i * 128, 64, 0),
            )
            .unwrap();
    }
    for i in 0..10 {
        table.remove(1, i * 64).unwrap();
    }
    assert_eq!(table.len(1), 0);

    // Reinsert a different entry at offset 0.
    let new_entry = LocatorEntry::new(0, ExtentId(999), 0, 4096, 256, 0);
    table.insert(1, new_entry).unwrap();

    assert_eq!(table.lookup(1, 0).unwrap(), Some(new_entry));
    assert_eq!(table.len(1), 1);
}

// ── Double-delete idempotency ───────────────────────────────────

#[test]
fn double_delete_returns_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    table
        .insert(1, LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0))
        .unwrap();
    table.remove(1, 0).unwrap();

    let result = table.remove(1, 0);
    assert_eq!(result, Err(LocatorError::NotFound));
    assert_eq!(table.len(1), 0);
}

#[test]
fn double_delete_after_reinsert_is_not_idempotent() {
    // After delete-then-reinsert, a second delete on same offset
    // removes the reinserted entry — it is not idempotent.
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    table
        .insert(1, LocatorEntry::new(0, ExtentId(1), 0, 0, 64, 0))
        .unwrap();
    table.remove(1, 0).unwrap();

    table
        .insert(1, LocatorEntry::new(0, ExtentId(2), 0, 128, 64, 0))
        .unwrap();

    // Second delete actually removes the reinserted entry.
    table.remove(1, 0).unwrap();
    assert_eq!(table.lookup(1, 0).unwrap(), None);
    assert_eq!(table.len(1), 0);
}

#[test]
fn double_delete_on_absent_offset_always_returns_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    assert_eq!(table.remove(1, 4096), Err(LocatorError::NotFound));
    assert_eq!(table.remove(1, 4096), Err(LocatorError::NotFound));
}

// ── Interleaved sequence on empty table ─────────────────────────

#[test]
fn interleaved_insert_lookup_delete_on_empty_table() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    // Start with empty table verification.
    assert_eq!(table.len(1), 0);
    assert_eq!(table.lookup(1, 0).unwrap(), None);
    assert_eq!(table.lookup_extent(1, ExtentId(1)).unwrap(), None);

    // Insert.
    let e = LocatorEntry::new(0, ExtentId(1), 0, 4096, 8192, 0x03);
    table.insert(1, e).unwrap();
    assert_eq!(table.len(1), 1);
    assert_eq!(table.lookup(1, 0).unwrap(), Some(e));
    assert_eq!(table.lookup_extent(1, ExtentId(1)).unwrap(), Some(e));

    // Overwrite (same offset, different extent_id).
    let e2 = LocatorEntry::new(0, ExtentId(2), 0, 16384, 4096, 0x01);
    table.insert(1, e2).unwrap();
    assert_eq!(table.len(1), 1);
    assert_eq!(table.lookup(1, 0).unwrap(), Some(e2));
    assert_eq!(table.lookup_extent(1, ExtentId(1)).unwrap(), None);

    // Insert second entry.
    let e3 = LocatorEntry::new(64, ExtentId(3), 0, 20480, 2048, 0);
    table.insert(1, e3).unwrap();
    assert_eq!(table.len(1), 2);

    // Iterate.
    let entries: Vec<LocatorEntry> = table.iterate(1).unwrap().collect();
    assert_eq!(entries.len(), 2);
    assert!(entries.contains(&e2));
    assert!(entries.contains(&e3));

    // Remove and re-verify.
    table.remove(1, 0).unwrap();
    table.remove(1, 64).unwrap();
    assert_eq!(table.len(1), 0);
    assert_eq!(table.lookup(1, 0).unwrap(), None);
    assert_eq!(table.lookup(1, 64).unwrap(), None);
}

// ── Large offset with grow ─────────────────────────────────────

fn make_large_store(dir: &Path) -> LocalObjectStore {
    let mut opts = StoreOptions::test_fast();
    opts.max_segment_bytes = 1_048_576;
    LocalObjectStore::open_with_options(dir, opts).expect("open store")
}

#[test]
fn max_offset_entries_survive_grow() {
    let dir = tempfile::tempdir().unwrap();
    let table = LocatorTable::new(make_large_store(dir.path()), 1);

    let max_off = u64::MAX - 2;
    let e = LocatorEntry::new(max_off, ExtentId(42), 0, 8192, 2048, 0x02);
    table.insert(1, e).unwrap();

    table.grow(1, 63).unwrap();

    assert_eq!(table.lookup(1, max_off).unwrap(), Some(e));
    assert_eq!(table.lookup_extent(1, ExtentId(42)).unwrap(), Some(e));
}

// ── Table capacity boundary (16 → WouldGrow) ───────────────────

#[test]
fn fill_to_wouldgrow_boundary_then_remove_all() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    // Capacity 16, max load 7/10 = 11 live entries before WouldGrow.
    // Insert exactly 11 entries.
    for i in 0..11 {
        table
            .insert(
                1,
                LocatorEntry::new(i * 64, ExtentId(i + 1), 0, i * 128, 64, (i % 256) as u8),
            )
            .unwrap();
    }
    assert_eq!(table.len(1), 11);

    // The 12th insert should trigger WouldGrow.
    let result = table.insert(
        1,
        LocatorEntry::new(11 * 64, ExtentId(12), 0, 11 * 128, 64, 0),
    );
    assert!(matches!(result, Err(LocatorError::WouldGrow { .. })));

    // Remove all and verify the table is fully drained.
    for i in 0..11 {
        table.remove(1, i * 64).unwrap();
    }
    assert_eq!(table.len(1), 0);

    // After draining, inserts should succeed again.
    table
        .insert(1, LocatorEntry::new(0, ExtentId(99), 0, 0, 128, 0))
        .unwrap();
    assert_eq!(table.len(1), 1);
}

// ── Toggle between insert/remove on same offset ─────────────────

#[test]
fn insert_remove_insert_remove_same_offset() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    for cycle in 0..5 {
        let e = LocatorEntry::new(0, ExtentId(cycle + 1), 0, cycle * 4096, 64, 0);
        table.insert(1, e).unwrap();
        assert_eq!(table.lookup(1, 0).unwrap(), Some(e));
        assert_eq!(table.len(1), 1);

        table.remove(1, 0).unwrap();
        assert_eq!(table.lookup(1, 0).unwrap(), None);
        assert_eq!(table.len(1), 0);
    }
}
