//! Refcount lifecycle and snapshot-semantics validation tests.
//!
//! NOTE: ExtentMapEntryV2 does not yet carry an explicit refcount field.
//! The planned snapshot-hold via refcount (#3469) will add per-extent
//! refcount tracking. These tests exercise the existing clone/independent-
//! map lifecycle (the closest extant snapshot analog), hole-based free
//! patterns, and FreedExtent metadata correctness as foundational
//! coverage that refcount semantics will extend.
//!
//! Tests cover:
//! - Cloned maps are independent (modifications don't cross-propagate)
//! - hole lifecycle: alloc, punch, re-alloc, reclaim (refcount-proxy pattern)
//! - FreedExtent metadata fidelity on punch_hole and truncate
//! - Reserved/sentinel field zero-initialization on new entries

use tidefs_extent_map::InlineExtentMap;
use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapOps, ExtentType, LocatorId};

// --- helpers ---

fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
    let cs = [0xFE; 32];
    ExtentMapEntryV2::new_data(off, len, LocatorId(loc), cs, 0)
}

fn collect_all(map: &InlineExtentMap) -> Vec<ExtentMapEntryV2> {
    map.lookup_range(0, u64::MAX).unwrap_or_default()
}

// =====================================================================
// 1. Cloned maps are independent (snapshot-semantics foundation)
// =====================================================================

#[test]
fn cloned_map_is_independent_of_original() {
    let mut original = InlineExtentMap::new();
    original
        .insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
        .unwrap();

    let snapshot = original.clone();
    assert_eq!(original.entries, snapshot.entries);

    // Modify original: free the first extent.
    original.punch_hole(0, 4096).unwrap();

    // Snapshot still has both extents.
    assert_eq!(snapshot.entries.len(), 2);
    assert_eq!(snapshot.entries[0].logical_offset, 0);
    assert_eq!(snapshot.entries[1].logical_offset, 8192);

    // Original has only the second extent.
    let entries = collect_all(&original);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].logical_offset, 8192);

    // Snapshot remains valid.
    assert!(snapshot.validate().is_ok());
    assert!(original.validate().is_ok());
}

#[test]
fn cloned_map_can_diverge_with_different_free_patterns() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(4096, 4096, 2), data(8192, 4096, 3)])
        .unwrap();

    let mut clone_a = map.clone();
    let mut clone_b = map.clone();

    // Clone A: free middle extent.
    clone_a.punch_hole(4096, 4096).unwrap();
    assert_eq!(clone_a.entries.len(), 2);
    assert_eq!(clone_a.entries[0].locator_id, LocatorId(1));
    assert_eq!(clone_a.entries[1].locator_id, LocatorId(3));

    // Clone B: free first extent, reallocate last.
    clone_b.punch_hole(0, 4096).unwrap();
    clone_b.insert_extent(&[data(0, 4096, 99)]).unwrap();
    assert_eq!(clone_b.entries.len(), 3);
    assert_eq!(clone_b.entries[0].locator_id, LocatorId(99));

    // Both clones are valid.
    assert!(clone_a.validate().is_ok());
    assert!(clone_b.validate().is_ok());
}

// =====================================================================
// 2. Hole lifecycle: proxy for refcount-goes-to-zero free
// =====================================================================

#[test]
fn hole_lifecycle_alloc_free_realloc_with_different_locator() {
    let mut map = InlineExtentMap::new();

    // "Acquire reference": allocate.
    map.insert_extent(&[data(0, 4096, 42)]).unwrap();
    assert_eq!(map.header.entry_count, 1);
    let entries = collect_all(&map);
    assert_eq!(entries[0].locator_id, LocatorId(42));

    // "Release reference": free the extent.
    let freed = map.punch_hole(0, 4096).unwrap();
    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].locator_id, LocatorId(42));
    assert!(collect_all(&map).is_empty());

    // "Re-acquire with new reference": reallocate at same offset.
    map.insert_extent(&[data(0, 4096, 43)]).unwrap();
    assert_eq!(map.header.entry_count, 1);
    let entries = collect_all(&map);
    assert_eq!(entries[0].locator_id, LocatorId(43));

    assert!(map.validate().is_ok());
}

#[test]
fn freed_extent_metadata_is_preserved_in_freed_extent() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(2048, 8192, 7)]).unwrap();

    let freed = map.punch_hole(4096, 4096).unwrap();
    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, 4096);
    assert_eq!(freed[0].length, 4096);
    assert_eq!(freed[0].locator_id, LocatorId(7));
    assert_eq!(freed[0].extent_type, ExtentType::Data);

    // The surrounding fragments should still be intact with locator 7.
    let entries = collect_all(&map);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].locator_id, LocatorId(7));
    assert_eq!(entries[0].logical_offset, 2048);
    assert_eq!(entries[0].length, 2048);
    assert_eq!(entries[1].locator_id, LocatorId(7));
    assert_eq!(entries[1].logical_offset, 8192);
    assert_eq!(entries[1].length, 2048);

    assert!(map.validate().is_ok());
}

// =====================================================================
// 3. Truncate as bulk free: multiple extents released at once
// =====================================================================

#[test]
fn truncate_frees_multiple_extents_correctly() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)])
        .unwrap();

    // Truncate to 4096: drops extents 2 and 3.
    let freed = map.truncate(4096).unwrap();

    assert_eq!(freed.len(), 2);
    assert_eq!(freed[0].logical_offset, 8192);
    assert_eq!(freed[0].length, 4096);
    assert_eq!(freed[0].locator_id, LocatorId(2));
    assert_eq!(freed[0].extent_type, ExtentType::Data);
    assert_eq!(freed[1].logical_offset, 16384);
    assert_eq!(freed[1].length, 4096);
    assert_eq!(freed[1].locator_id, LocatorId(3));
    assert_eq!(freed[1].extent_type, ExtentType::Data);

    // Only extent 1 remains.
    assert_eq!(map.header.entry_count, 1);
    let entries = collect_all(&map);
    assert_eq!(entries[0].locator_id, LocatorId(1));

    assert!(map.validate().is_ok());
}

#[test]
fn truncate_mid_extent_frees_partial_extent_and_reports_survivor() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 12288, 5)]).unwrap();

    // Truncate at 4096: splits [0..12288) into [0..4096) survivor and
    // [4096..12288) freed.
    let freed = map.truncate(4096).unwrap();

    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, 4096);
    assert_eq!(freed[0].length, 8192);
    assert_eq!(freed[0].locator_id, LocatorId(5));
    assert_eq!(freed[0].extent_type, ExtentType::Data);

    let entries = collect_all(&map);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].logical_offset, 0);
    assert_eq!(entries[0].length, 4096);
    assert_eq!(entries[0].locator_id, LocatorId(5));

    assert!(map.validate().is_ok());
}

// =====================================================================
// 4. Double-punch idempotence (equivalent to double-free no-op)
// =====================================================================

#[test]
fn double_punch_hole_is_idempotent() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();

    // First free.
    let freed = map.punch_hole(0, 4096).unwrap();
    assert_eq!(freed.len(), 1);

    // Second free on same range: should return empty (idempotent).
    let freed2 = map.punch_hole(0, 4096).unwrap();
    assert!(freed2.is_empty());

    assert!(collect_all(&map).is_empty());
    assert!(map.validate().is_ok());
}

#[test]
fn punch_hole_of_never_allocated_range_returns_empty() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(4096, 4096, 1)]).unwrap();

    // Punch at offset 0 where nothing was allocated.
    let freed = map.punch_hole(0, 4096).unwrap();
    assert!(freed.is_empty());

    // Existing extent still intact.
    let entries = collect_all(&map);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].logical_offset, 4096);

    assert!(map.validate().is_ok());
}

// =====================================================================
// 5. Reserved fields are zero-initialized
// =====================================================================

#[test]
fn new_entry_reserved_field_is_zero() {
    let e = data(0, 4096, 1);
    assert_eq!(e.reserved, [0u8; 15]);

    let u = ExtentMapEntryV2::new_unwritten(0, 4096, 1);
    assert_eq!(u.reserved, [0u8; 15]);
}

#[test]
fn new_entry_flags_field_is_zero() {
    let e = data(0, 4096, 1);
    assert_eq!(e.flags, 0);

    let u = ExtentMapEntryV2::new_unwritten(0, 4096, 1);
    assert_eq!(u.flags, 0);
}
