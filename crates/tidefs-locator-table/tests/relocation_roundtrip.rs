// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests covering the full allocate->relocate->lookup->free
//! cycle through the locator table, exercising compact(), swap_commit(),
//! and relocate_extent() end to end.

use std::path::Path;
use tidefs_local_object_store::{LocalObjectStore, StoreOptions};
use tidefs_locator_table::{ExtentId, LocatorEntry, LocatorTable};

fn make_store(dir: &Path) -> LocalObjectStore {
    let mut opts = StoreOptions::test_fast();
    opts.max_segment_bytes = 8192;
    LocalObjectStore::open_with_options(dir, opts).expect("open store")
}

fn make_table(dir: &Path) -> LocatorTable {
    LocatorTable::new(make_store(dir), 1)
}

fn entry(offset: u64, eid: u64, phys: u64, len: u32) -> LocatorEntry {
    LocatorEntry::new(offset, ExtentId(eid), 0, phys, len, 0)
}

// ── Round-trip: allocate, relocate, verify ───────────────────

#[test]
fn single_extent_allocate_relocate_free_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let e = entry(0, 42, 4096, 8192);
    table.insert(1, e).unwrap();

    assert_eq!(table.lookup(1, 0).unwrap(), Some(e));

    table.relocate_extent(1, ExtentId(42), 0, 16384).unwrap();

    let found = table.lookup(1, 0).unwrap().unwrap();
    assert_eq!(found.physical_offset, 16384);
    assert_eq!(found.extent_id, ExtentId(42));

    table.remove(1, 0).unwrap();
    assert_eq!(table.lookup(1, 0).unwrap(), None);
    assert_eq!(table.len(1), 0);
}

#[test]
fn multi_extent_allocate_relocate_some_lookup_all() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let e0 = entry(0, 1, 0, 4096);
    let e1 = entry(4096, 2, 4096, 4096);
    let e2 = entry(8192, 3, 8192, 4096);
    let e3 = entry(12288, 4, 12288, 4096);

    for e in &[e0, e1, e2, e3] {
        table.insert(1, *e).unwrap();
    }

    table.relocate_extent(1, ExtentId(1), 0, 100000).unwrap();
    table.relocate_extent(1, ExtentId(3), 0, 200000).unwrap();

    assert_eq!(table.lookup(1, 0).unwrap().unwrap().physical_offset, 100000);
    assert_eq!(
        table.lookup(1, 4096).unwrap().unwrap().physical_offset,
        4096
    );
    assert_eq!(
        table.lookup(1, 8192).unwrap().unwrap().physical_offset,
        200000
    );
    assert_eq!(
        table.lookup(1, 12288).unwrap().unwrap().physical_offset,
        12288
    );
}

// ── Compact + relocate interaction ────────────────────────────

#[test]
fn compact_then_relocate_all_extents() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    for i in 0..10 {
        table
            .insert(1, entry(i * 64, 100 + i, i * 128, 64))
            .unwrap();
    }
    for i in (1..10).step_by(2) {
        table.remove(1, i * 64).unwrap();
    }

    let plan = table.compact(1).unwrap();
    table.swap_commit(plan).unwrap();

    let expected_ids: [u64; 5] = [100, 102, 104, 106, 108];
    let expected_offsets: [u64; 5] = [0, 128, 256, 384, 512];

    for (i, eid) in expected_ids.iter().enumerate() {
        table
            .relocate_extent(1, ExtentId(*eid), 0, 1000 + i as u64 * 1000)
            .unwrap();
    }

    for (i, off) in expected_offsets.iter().enumerate() {
        let found = table.lookup(1, *off).unwrap().unwrap();
        assert_eq!(found.physical_offset, 1000 + i as u64 * 1000);
        assert_eq!(found.extent_id, ExtentId(expected_ids[i]));
    }
}

#[test]
fn relocate_then_compact_preserves_all_changes() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    for i in 0..5 {
        table
            .insert(1, entry(i * 64, 200 + i, i * 128, 64))
            .unwrap();
    }

    table.relocate_extent(1, ExtentId(200), 0, 1).unwrap();
    table.relocate_extent(1, ExtentId(202), 0, 2).unwrap();
    table.relocate_extent(1, ExtentId(204), 0, 3).unwrap();

    let plan = table.compact(1).unwrap();
    table.swap_commit(plan).unwrap();

    assert_eq!(table.lookup(1, 0).unwrap().unwrap().physical_offset, 1);
    assert_eq!(table.lookup(1, 128).unwrap().unwrap().physical_offset, 2);
    assert_eq!(table.lookup(1, 256).unwrap().unwrap().physical_offset, 3);
}

// ── Full cycle ────────────────────────────────────────────────

#[test]
fn full_allocate_free_compact_relocate_lookup_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    // Grow first so all 20 entries fit.
    table.grow(1, 31).unwrap();
    table.grow(1, 31).unwrap();
    for i in 0..20 {
        table
            .insert(1, entry(i * 64, 1000 + i, i * 256, 64))
            .unwrap();
    }
    assert_eq!(table.len(1), 20);

    for i in (0..20).step_by(3) {
        table.remove(1, i * 64).unwrap();
    }

    let plan = table.compact(1).unwrap();
    table.swap_commit(plan).unwrap();

    let remaining_offsets: Vec<u64> = (0..20).filter(|i| i % 3 != 0).map(|i| i * 64).collect();
    for (j, off) in remaining_offsets.iter().enumerate() {
        let eid = 1000 + (*off / 64);
        table
            .relocate_extent(1, ExtentId(eid), 0, 10000 + j as u64 * 256)
            .unwrap();
    }

    for (j, off) in remaining_offsets.iter().enumerate() {
        let eid = 1000 + (*off / 64);
        let phys = 10000 + j as u64 * 256;

        let found = table.lookup(1, *off).unwrap().unwrap();
        assert_eq!(found.physical_offset, phys, "lookup offset {off}");
        assert_eq!(found.extent_id, ExtentId(eid));

        let found2 = table.lookup_extent(1, ExtentId(eid)).unwrap().unwrap();
        assert_eq!(found2.physical_offset, phys, "lookup_extent eid {eid}");
    }

    for i in (0..20).step_by(3) {
        assert_eq!(table.lookup(1, i * 64).unwrap(), None);
    }

    assert_eq!(table.len(1), 13);
}

// ── Persistence across reopen ─────────────────────────────────

#[test]
fn relocate_persists_across_reopen() {
    let dir = tempfile::tempdir().unwrap();

    {
        let table = make_table(dir.path());
        table.insert(1, entry(0, 1, 0, 4096)).unwrap();
        table.relocate_extent(1, ExtentId(1), 0, 99999).unwrap();
        table.insert(1, entry(4096, 2, 4096, 4096)).unwrap();
    }

    {
        let store = make_store(dir.path());
        let table = LocatorTable::new(store, 1);

        let found = table.lookup(1, 0).unwrap().unwrap();
        assert_eq!(found.physical_offset, 99999);
        assert_eq!(found.extent_id, ExtentId(1));

        let found2 = table.lookup(1, 4096).unwrap().unwrap();
        assert_eq!(found2.physical_offset, 4096);
    }
}

// ── Error handling ────────────────────────────────────────────

#[test]
fn relocate_nonexistent_returns_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    assert!(table.relocate_extent(1, ExtentId(999), 0, 0).is_err());
}

#[test]
fn relocate_removed_extent_returns_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    table.insert(1, entry(0, 10, 0, 4096)).unwrap();
    table.remove(1, 0).unwrap();

    assert!(table.relocate_extent(1, ExtentId(10), 0, 12345).is_err());
}

// ── Multi-inode isolation ─────────────────────────────────────

#[test]
fn relocate_one_inode_does_not_affect_others() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    table.insert(10, entry(0, 100, 0, 4096)).unwrap();
    table.insert(20, entry(0, 200, 0, 4096)).unwrap();
    table.insert(30, entry(0, 300, 0, 4096)).unwrap();

    table.relocate_extent(20, ExtentId(200), 0, 88888).unwrap();

    assert_eq!(table.lookup(10, 0).unwrap().unwrap().physical_offset, 0);
    assert_eq!(table.lookup(20, 0).unwrap().unwrap().physical_offset, 88888);
    assert_eq!(table.lookup(30, 0).unwrap().unwrap().physical_offset, 0);
}

// ── Staggered relocation ──────────────────────────────────────

#[test]
fn stagger_relocate_with_interleaved_lookups() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let mut entries = Vec::new();
    for i in 0..8 {
        let e = entry(i * 64, 500 + i, i * 128, 64);
        table.insert(1, e).unwrap();
        entries.push(e);
    }

    for i in 0..8 {
        let eid = 500 + i;
        let new_phys = 1000 + i * 500;
        table
            .relocate_extent(1, ExtentId(eid), 0, new_phys)
            .unwrap();

        for j in 0..=i {
            let found = table.lookup(1, j * 64).unwrap().unwrap();
            let expected_phys = 1000 + j * 500;
            assert_eq!(
                found.physical_offset, expected_phys,
                "stagger step {i}: entry {j} has wrong offset"
            );
        }
    }
}

// ── Empty table edge cases ────────────────────────────────────

#[test]
fn compact_empty_then_relocate_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let plan = table.compact(1).unwrap();
    table.swap_commit(plan).unwrap();

    assert!(table.relocate_extent(1, ExtentId(1), 0, 0).is_err());
}
