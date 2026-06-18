// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
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

// ── Core insert / lookup ────────────────────────────────────────

#[test]
fn insert_and_lookup_single_entry() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let entry = LocatorEntry::new(0, ExtentId(42), 0, 4096, 8192, 0);
    table.insert(1, entry).unwrap();

    let found = table.lookup(1, 0).unwrap();
    assert_eq!(found, Some(entry));
}

#[test]
fn lookup_empty_table_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let found = table.lookup(1, 1024).unwrap();
    assert_eq!(found, None);
}

#[test]
fn insert_duplicate_offset_overwrites_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let entry1 = LocatorEntry::new(4096, ExtentId(10), 0, 0, 4096, 0);
    table.insert(1, entry1).unwrap();

    // Overwrite with different extent_id and physical_offset.
    let entry2 = LocatorEntry::new(4096, ExtentId(20), 0, 8192, 4096, 0);
    table.insert(1, entry2).unwrap();

    let found = table.lookup(1, 4096).unwrap();
    assert_eq!(found, Some(entry2));
    assert_eq!(table.len(1), 1);
}

// ── Remove ──────────────────────────────────────────────────────

#[test]
fn remove_existing_entry_then_lookup_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    table
        .insert(1, LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0))
        .unwrap();
    table.remove(1, 0).unwrap();

    assert_eq!(table.lookup(1, 0).unwrap(), None);
    assert_eq!(table.len(1), 0);
}

#[test]
fn remove_nonexistent_offset_returns_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let result = table.remove(1, 4096);
    assert!(result.is_err());
}

#[test]
fn insert_past_tombstone_finds_correct_entry() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    // With capacity 16, offsets 0 and 16 both hash to slot 0.
    // Insert at 0, remove it (tombstone), then insert at 16.
    // The insert at 16 should reuse the tombstone slot.
    table
        .insert(1, LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0))
        .unwrap();
    table.remove(1, 0).unwrap();

    let entry16 = LocatorEntry::new(16, ExtentId(2), 0, 8192, 4096, 0);
    table.insert(1, entry16).unwrap();

    assert_eq!(table.lookup(1, 0).unwrap(), None);
    assert_eq!(table.lookup(1, 16).unwrap(), Some(entry16));
}

// ── WouldGrow / capacity ────────────────────────────────────────

#[test]
fn insert_triggers_would_grow_at_load_factor() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    // Default capacity is 16. Max load is 7/10, so max live = 11.
    for i in 0..11 {
        let offset = i * 64;
        table
            .insert(
                1,
                LocatorEntry::new(offset, ExtentId(i + 1), 0, offset * 2, 64, 0),
            )
            .unwrap();
    }

    let result = table.insert(
        1,
        LocatorEntry::new(11 * 64, ExtentId(12), 0, 11 * 64 * 2, 64, 0),
    );
    assert!(result.is_err());
}

#[test]
fn grow_preserves_all_entries() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let mut entries = Vec::new();
    for i in 0..8 {
        let e = LocatorEntry::new(i * 64, ExtentId(i + 1), 0, i * 128, 64, 0);
        table.insert(1, e).unwrap();
        entries.push(e);
    }

    table.grow(1, 31).unwrap();

    for e in &entries {
        let found = table.lookup(1, e.logical_offset).unwrap();
        assert_eq!(found, Some(*e));
    }
}

#[test]
fn after_grow_can_insert_more_entries() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    // Fill to 11 entries (WouldGrow threshold).
    for i in 0..11 {
        table
            .insert(
                1,
                LocatorEntry::new(i * 64, ExtentId(i + 1), 0, i * 128, 64, 0),
            )
            .unwrap();
    }

    // Grow to 64.
    table.grow(1, 31).unwrap();

    // Now we should be able to insert more.
    for i in 11..20 {
        table
            .insert(
                1,
                LocatorEntry::new(i * 64, ExtentId(i + 1), 0, i * 128, 64, 0),
            )
            .unwrap();
    }

    assert_eq!(table.len(1), 20);
}

// ── Multiple inodes ─────────────────────────────────────────────

#[test]
fn multiple_inodes_independent() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let e1 = LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0);
    let e2 = LocatorEntry::new(0, ExtentId(2), 0, 8192, 4096, 0);

    table.insert(100, e1).unwrap();
    table.insert(200, e2).unwrap();

    assert_eq!(table.lookup(100, 0).unwrap(), Some(e1));
    assert_eq!(table.lookup(200, 0).unwrap(), Some(e2));

    table.remove(100, 0).unwrap();
    assert_eq!(table.lookup(100, 0).unwrap(), None);
    assert_eq!(table.lookup(200, 0).unwrap(), Some(e2));
}

// ── Persistence ─────────────────────────────────────────────────

#[test]
fn persistence_round_trip_across_reopen() {
    let dir = tempfile::tempdir().unwrap();

    let e1 = LocatorEntry::new(0, ExtentId(42), 0, 4096, 8192, 0x01);
    let e2 = LocatorEntry::new(4096, ExtentId(43), 0, 12288, 4096, 0x02);

    {
        let table = make_table(dir.path());
        table.insert(1, e1).unwrap();
        table.insert(1, e2).unwrap();
    }

    // Open a fresh LocatorTable on the same store directory.
    {
        let store = make_store(dir.path());
        let table = LocatorTable::new(store, 1);
        assert_eq!(table.lookup(1, 0).unwrap(), Some(e1));
        assert_eq!(table.lookup(1, 4096).unwrap(), Some(e2));
        assert_eq!(table.len(1), 2);
    }
}

// ── Linear probing edge cases ───────────────────────────────────

#[test]
fn lookup_probes_past_collisions() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    // Offsets 0, 16, 32 all hash to the same slot (capacity 16).
    // Insert them in order; they should probe to slots 0, 1, 2.
    table
        .insert(1, LocatorEntry::new(0, ExtentId(1), 0, 0, 64, 0))
        .unwrap();
    table
        .insert(1, LocatorEntry::new(16, ExtentId(2), 0, 64, 64, 0))
        .unwrap();
    table
        .insert(1, LocatorEntry::new(32, ExtentId(3), 0, 128, 64, 0))
        .unwrap();

    assert_eq!(table.lookup(1, 0).unwrap().unwrap().extent_id, ExtentId(1));
    assert_eq!(table.lookup(1, 16).unwrap().unwrap().extent_id, ExtentId(2));
    assert_eq!(table.lookup(1, 32).unwrap().unwrap().extent_id, ExtentId(3));
}

#[test]
fn remove_hole_does_not_break_probe_chain() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    // Insert 0, 16, 32 (all collide at slot 0). Remove the middle one.
    table
        .insert(1, LocatorEntry::new(0, ExtentId(1), 0, 0, 64, 0))
        .unwrap();
    table
        .insert(1, LocatorEntry::new(16, ExtentId(2), 0, 64, 64, 0))
        .unwrap();
    table
        .insert(1, LocatorEntry::new(32, ExtentId(3), 0, 128, 64, 0))
        .unwrap();

    table.remove(1, 16).unwrap();

    // 0 and 32 should still be reachable.
    assert_eq!(table.lookup(1, 0).unwrap().unwrap().extent_id, ExtentId(1));
    assert_eq!(table.lookup(1, 32).unwrap().unwrap().extent_id, ExtentId(3));
    assert_eq!(table.lookup(1, 16).unwrap(), None);
}

// ── Flags ───────────────────────────────────────────────────────

#[test]
fn flags_preserved_in_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let entry = LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0x05);
    table.insert(1, entry).unwrap();

    let found = table.lookup(1, 0).unwrap().unwrap();
    assert_eq!(found.flags, 0x05);
}

#[test]
fn different_pool_ids_use_different_keys() {
    let dir = tempfile::tempdir().unwrap();
    let store = make_store(dir.path());

    let table_a = LocatorTable::new(make_store(dir.path()), 1);
    let table_b = LocatorTable::new(make_store(dir.path()), 2);

    let ea = LocatorEntry::new(0, ExtentId(10), 0, 0, 4096, 0);
    let eb = LocatorEntry::new(0, ExtentId(20), 0, 0, 4096, 0);

    table_a.insert(1, ea).unwrap();
    table_b.insert(1, eb).unwrap();

    // Table A sees its own entry.
    assert_eq!(
        table_a.lookup(1, 0).unwrap().unwrap().extent_id,
        ExtentId(10)
    );
    // Table B sees its own entry.
    assert_eq!(
        table_b.lookup(1, 0).unwrap().unwrap().extent_id,
        ExtentId(20)
    );

    drop(table_a);
    drop(table_b);
    drop(store);
}

// ── lookup_extent ───────────────────────────────────────────────

#[test]
fn lookup_extent_finds_entry_by_id() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let e1 = LocatorEntry::new(0, ExtentId(42), 0, 0, 4096, 0);
    let e2 = LocatorEntry::new(4096, ExtentId(99), 0, 8192, 2048, 0);
    table.insert(1, e1).unwrap();
    table.insert(1, e2).unwrap();

    assert_eq!(table.lookup_extent(1, ExtentId(42)).unwrap(), Some(e1));
    assert_eq!(table.lookup_extent(1, ExtentId(99)).unwrap(), Some(e2));
}

#[test]
fn lookup_extent_returns_none_for_unknown_id() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    table
        .insert(1, LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0))
        .unwrap();

    assert_eq!(table.lookup_extent(1, ExtentId(999)).unwrap(), None);
}

// ── iterate ─────────────────────────────────────────────────────

#[test]
fn iterate_yields_all_live_entries_in_slot_order() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let e1 = LocatorEntry::new(0, ExtentId(1), 0, 0, 64, 0);
    let e2 = LocatorEntry::new(64, ExtentId(2), 0, 64, 64, 0);
    let e3 = LocatorEntry::new(128, ExtentId(3), 0, 128, 64, 0);
    table.insert(1, e1).unwrap();
    table.insert(1, e2).unwrap();
    table.insert(1, e3).unwrap();

    let entries: Vec<LocatorEntry> = table.iterate(1).unwrap().collect();
    assert_eq!(entries.len(), 3);
    assert!(entries.contains(&e1));
    assert!(entries.contains(&e2));
    assert!(entries.contains(&e3));
}

#[test]
fn iterate_empty_table_yields_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let entries: Vec<LocatorEntry> = table.iterate(1).unwrap().collect();
    assert!(entries.is_empty());
}

// ── notifier (integration) ──────────────────────────────────────

use std::sync::{Arc, Mutex};

struct TestNotifier {
    inserts: Mutex<Vec<(u64, LocatorEntry)>>,
    removes: Mutex<Vec<(u64, ExtentId)>>,
}

impl TestNotifier {
    fn new() -> Self {
        Self {
            inserts: Mutex::new(Vec::new()),
            removes: Mutex::new(Vec::new()),
        }
    }
}

impl tidefs_locator_table::ExtentMapNotifier for TestNotifier {
    fn on_insert(&self, ino: u64, entry: &LocatorEntry) {
        self.inserts.lock().unwrap().push((ino, *entry));
    }

    fn on_remove(&self, ino: u64, extent_id: ExtentId) {
        self.removes.lock().unwrap().push((ino, extent_id));
    }
}

fn make_table_with_notifier(dir: &Path) -> (LocatorTable, Arc<TestNotifier>) {
    let mut table = make_table(dir);
    let spy = Arc::new(TestNotifier::new());
    table.set_notifier(spy.clone());
    (table, spy)
}

#[test]
fn notifier_on_insert_called_integration() {
    let dir = tempfile::tempdir().unwrap();
    let (table, spy) = make_table_with_notifier(dir.path());

    let entry = LocatorEntry::new(0, ExtentId(42), 0, 4096, 8192, 0);
    table.insert(1, entry).unwrap();

    let calls = spy.inserts.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0], (1, entry));
}

#[test]
fn notifier_on_remove_called_integration() {
    let dir = tempfile::tempdir().unwrap();
    let (table, spy) = make_table_with_notifier(dir.path());

    table
        .insert(1, LocatorEntry::new(0, ExtentId(42), 0, 4096, 8192, 0))
        .unwrap();
    table.remove(1, 0).unwrap();

    let calls = spy.removes.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0], (1, ExtentId(42)));
}

// ── Secondary index integrity (integration) ─────────────────────

#[test]
fn secondary_index_consistent_after_insert_remove_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let e1 = LocatorEntry::new(0, ExtentId(101), 0, 0, 4096, 0);
    let e2 = LocatorEntry::new(64, ExtentId(202), 0, 64, 4096, 0);
    let e3 = LocatorEntry::new(128, ExtentId(303), 0, 128, 4096, 0);

    table.insert(1, e1).unwrap();
    table.insert(1, e2).unwrap();
    table.insert(1, e3).unwrap();

    // All three findable via secondary.
    assert_eq!(table.lookup_extent(1, ExtentId(101)).unwrap(), Some(e1));
    assert_eq!(table.lookup_extent(1, ExtentId(202)).unwrap(), Some(e2));
    assert_eq!(table.lookup_extent(1, ExtentId(303)).unwrap(), Some(e3));

    // Remove middle.
    table.remove(1, 64).unwrap();
    assert_eq!(table.lookup_extent(1, ExtentId(202)).unwrap(), None);

    // Others still findable.
    assert_eq!(table.lookup_extent(1, ExtentId(101)).unwrap(), Some(e1));
    assert_eq!(table.lookup_extent(1, ExtentId(303)).unwrap(), Some(e3));
}

#[test]
fn secondary_index_persists_across_reopen() {
    let dir = tempfile::tempdir().unwrap();

    let e = LocatorEntry::new(0, ExtentId(77), 0, 4096, 8192, 0x03);
    {
        let table = make_table(dir.path());
        table.insert(1, e).unwrap();
    }

    {
        let store = make_store(dir.path());
        let table = LocatorTable::new(store, 1);
        assert_eq!(table.lookup_extent(1, ExtentId(77)).unwrap(), Some(e));
        assert_eq!(table.lookup(1, 0).unwrap(), Some(e));
    }
}

// ── ABA safety via generation counter ───────────────────────────

#[test]
fn aba_safety_different_generations_dont_collide() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    // Allocate extent at offset 0 with generation 0.
    let e1 = LocatorEntry::new(0, ExtentId::with_generation(42, 0), 0, 0, 4096, 0);
    table.insert(1, e1).unwrap();

    assert_eq!(table.lookup(1, 0).unwrap(), Some(e1));

    // Remove it.
    table.remove(1, 0).unwrap();
    assert_eq!(table.lookup(1, 0).unwrap(), None);

    // Stale lookup with old generation should return none.
    assert_eq!(
        table
            .lookup_extent(1, ExtentId::with_generation(42, 0))
            .unwrap(),
        None
    );

    // Allocate a new extent at the same offset with generation 1.
    let e2 = LocatorEntry::new(0, ExtentId::with_generation(42, 1), 0, 0, 8192, 0);
    table.insert(1, e2).unwrap();

    // New lookup should find the new entry.
    assert_eq!(table.lookup(1, 0).unwrap(), Some(e2));

    // Old generation lookup should still miss.
    assert_eq!(
        table
            .lookup_extent(1, ExtentId::with_generation(42, 0))
            .unwrap(),
        None
    );

    // New generation lookup should succeed.
    assert_eq!(
        table
            .lookup_extent(1, ExtentId::with_generation(42, 1))
            .unwrap(),
        Some(e2)
    );
}

// ── Stress tests ─────────────────────────────────────────────────

fn make_large_store(dir: &Path) -> LocalObjectStore {
    let mut opts = StoreOptions::test_fast();
    opts.max_segment_bytes = 1_048_576;
    LocalObjectStore::open_with_options(dir, opts).expect("open store")
}

fn make_large_table(dir: &Path) -> LocatorTable {
    LocatorTable::new(make_large_store(dir), 1)
}

#[test]
fn insert_1000_entries_all_lookups_succeed() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_large_table(dir.path());

    // Grow to fit all entries.
    table.grow(1, 2048).unwrap();

    let mut entries = Vec::with_capacity(1000);
    for i in 0..1000 {
        let e = LocatorEntry::new(i * 64, ExtentId(i + 1), 0, i * 128, 64, (i % 256) as u8);
        table.insert(1, e).unwrap();
        entries.push(e);
    }
    assert_eq!(table.len(1), 1000);

    // All lookups succeed.
    for i in 0..1000 {
        let found = table.lookup(1, i * 64).unwrap();
        assert_eq!(found, Some(entries[i as usize]));
    }

    // All lookup_extent calls succeed.
    for i in 0..1000 {
        let found = table.lookup_extent(1, ExtentId(i + 1)).unwrap();
        assert_eq!(found, Some(entries[i as usize]));
    }
}

#[test]
fn insert_1000_then_remove_500_then_reinsert() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_large_table(dir.path());

    table.grow(1, 2048).unwrap();

    // Insert 1000.
    for i in 0..1000 {
        table
            .insert(
                1,
                LocatorEntry::new(i * 64, ExtentId(i + 1), 0, i * 128, 64, 0),
            )
            .unwrap();
    }
    assert_eq!(table.len(1), 1000);

    // Remove every other one (500 removals).
    for i in (0..1000).step_by(2) {
        table.remove(1, i * 64).unwrap();
    }
    assert_eq!(table.len(1), 500);

    // Removed entries must be absent.
    for i in (0..1000).step_by(2) {
        assert_eq!(table.lookup(1, i * 64).unwrap(), None);
    }

    // Remaining entries must be present.
    for i in (1..1000).step_by(2) {
        let found = table.lookup(1, i * 64).unwrap();
        assert!(found.is_some());
    }

    // Reinsert at freed offsets.
    for i in (0..1000).step_by(2) {
        table
            .insert(
                1,
                LocatorEntry::new(i * 64, ExtentId(2000 + i), 0, i * 128, 64, 0),
            )
            .unwrap();
    }
    assert_eq!(table.len(1), 1000);

    // All 1000 lookups succeed again.
    for i in 0..1000 {
        assert!(table.lookup(1, i * 64).unwrap().is_some());
    }
}

// ── Checksum field ───────────────────────────────────────────────

#[test]
fn checksum_preserved_in_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let hash: [u8; 32] = [0xAA; 32];
    let entry = LocatorEntry::with_checksum(0, ExtentId(1), 0, 0, 4096, 0x03, hash);
    table.insert(1, entry).unwrap();

    let found = table.lookup(1, 0).unwrap().unwrap();
    assert_eq!(found.checksum, hash);
    assert_eq!(found.flags, 0x03);
}

#[test]
fn checksum_zero_for_v1_constructor() {
    let dir = tempfile::tempdir().unwrap();
    let table = make_table(dir.path());

    let entry = LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0);
    table.insert(1, entry).unwrap();

    let found = table.lookup(1, 0).unwrap().unwrap();
    assert_eq!(found.checksum, [0u8; 32]);
}

#[test]
fn checksum_round_trip_across_reopen() {
    let dir = tempfile::tempdir().unwrap();

    let hash: [u8; 32] = [0x42; 32];
    let entry = LocatorEntry::with_checksum(0, ExtentId(77), 0, 4096, 8192, 0, hash);

    {
        let table = make_table(dir.path());
        table.insert(1, entry).unwrap();
    }

    {
        let store = make_store(dir.path());
        let table = LocatorTable::new(store, 1);
        let found = table.lookup(1, 0).unwrap().unwrap();
        assert_eq!(found.checksum, hash);
        assert_eq!(found.extent_id, ExtentId(77));
    }
}
