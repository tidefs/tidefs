//! Allocation/deallocation/lookup round-trip validation tests.
//!
//! Exercises the core alloc-free-lookup cycle through InlineExtentMap,
//! complementing the existing validation tests with focused round-trip
//! scenarios: single-extent lifecycle, contiguous merge, non-contiguous
//! multi-extent, free-middle-split, free-and-reallocate, and alloc after
//! truncate.

use tidefs_extent_map::InlineExtentMap;
use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapOps, ExtentType, LocatorId};

// --- helpers ---

fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
    let cs = [0xAB; 32];
    ExtentMapEntryV2::new_data(off, len, LocatorId(loc), cs, 0)
}

/// Collect all entries via a full-range lookup.
fn collect_all(map: &InlineExtentMap) -> Vec<ExtentMapEntryV2> {
    map.lookup_range(0, u64::MAX).unwrap_or_default()
}

// =====================================================================
// 1. Single-extent allocate, lookup, free round-trip
// =====================================================================

#[test]
fn single_extent_alloc_lookup_free_roundtrip() {
    let mut map = InlineExtentMap::new();

    // Allocate one extent at offset 0, length 4096, locator 1.
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    assert_eq!(map.header.entry_count, 1);
    assert_eq!(map.header.file_size, 4096);
    assert_eq!(map.header.alloc_bytes, 4096);

    // Lookup: should find it.
    let entries = map.lookup_range(0, 4096).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].logical_offset, 0);
    assert_eq!(entries[0].length, 4096);
    assert_eq!(entries[0].locator_id, LocatorId(1));

    // Free via punch_hole: remove the extent.
    let freed = map.punch_hole(0, 4096).unwrap();
    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, 0);
    assert_eq!(freed[0].length, 4096);
    assert_eq!(freed[0].locator_id, LocatorId(1));
    assert_eq!(freed[0].extent_type, ExtentType::Data);

    // After free: map is empty.
    assert_eq!(map.header.entry_count, 0);
    assert_eq!(map.header.alloc_bytes, 0);
    assert!(collect_all(&map).is_empty());
    assert!(map.validate().is_ok());
}

#[test]
fn single_extent_lookup_beyond_boundaries_is_empty() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(4096, 4096, 1)]).unwrap();

    // Lookup before the extent: empty.
    let r = map.lookup_range(0, 4096).unwrap();
    assert!(r.is_empty());

    // Exact lookup: found.
    let r = map.lookup_range(4096, 4096).unwrap();
    assert_eq!(r.len(), 1);

    // Lookup after the extent: empty.
    let r = map.lookup_range(8192, 4096).unwrap();
    assert!(r.is_empty());

    // Lookup spanning before and into extent: returns clipped entry.
    let r = map.lookup_range(0, 8192).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, 4096);
    assert_eq!(r[0].length, 4096);

    // Lookup partially covering extent tail.
    let r = map.lookup_range(6144, 4096).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, 6144);
    assert_eq!(r[0].length, 2048);

    assert!(map.validate().is_ok());
}

// =====================================================================
// 2. Multi-extent contiguous allocate with merge
// =====================================================================

#[test]
fn contiguous_alloc_same_locator_merges() {
    let mut map = InlineExtentMap::new();

    // Allocate three adjacent extents, same locator.
    map.insert_extent(&[data(0, 4096, 7), data(4096, 4096, 7), data(8192, 4096, 7)])
        .unwrap();

    // All three should merge into a single entry.
    assert_eq!(map.header.entry_count, 1);
    let all = collect_all(&map);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].logical_offset, 0);
    assert_eq!(all[0].length, 12288);
    assert_eq!(all[0].locator_id, LocatorId(7));
    assert_eq!(map.header.file_size, 12288);
    assert_eq!(map.header.alloc_bytes, 12288);
    assert!(map.validate().is_ok());
}

#[test]
fn contiguous_alloc_different_locator_stays_separate() {
    let mut map = InlineExtentMap::new();

    map.insert_extent(&[data(0, 4096, 1), data(4096, 4096, 2), data(8192, 4096, 3)])
        .unwrap();

    // Different locators: three separate entries.
    assert_eq!(map.header.entry_count, 3);
    let all = collect_all(&map);
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].locator_id, LocatorId(1));
    assert_eq!(all[1].locator_id, LocatorId(2));
    assert_eq!(all[2].locator_id, LocatorId(3));
    assert_eq!(map.header.file_size, 12288);
    assert_eq!(map.header.alloc_bytes, 12288);
    assert!(map.validate().is_ok());
}

// =====================================================================
// 3. Multi-extent non-contiguous allocate
// =====================================================================

#[test]
fn non_contiguous_alloc_preserves_gaps() {
    let mut map = InlineExtentMap::new();

    // Allocate extents with intentional gaps.
    map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2), data(20480, 4096, 3)])
        .unwrap();

    assert_eq!(map.header.entry_count, 3);
    assert_eq!(map.header.file_size, 24576);
    // alloc_bytes: only the three data extents (no hole wasted).
    assert_eq!(map.header.alloc_bytes, 12288);

    // Gaps should return empty on lookup.
    assert!(map.lookup_range(4096, 4096).unwrap().is_empty());
    assert!(map.lookup_range(12288, 8192).unwrap().is_empty());

    // Full scan returns all three.
    let all = map.lookup_range(0, 24576).unwrap();
    assert_eq!(all.len(), 3);
    assert!(map.validate().is_ok());
}

#[test]
fn sparse_alloc_with_seek_behaviour() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(16384, 4096, 2)])
        .unwrap();

    // seek_data at 0 returns first extent.
    assert_eq!(map.seek_data(0), Some((0, 4096)));

    // seek_data in the gap: skips to second extent.
    assert_eq!(map.seek_data(4096), Some((16384, 4096)));
    assert_eq!(map.seek_data(8192), Some((16384, 4096)));

    // seek_hole at 0 after first extent finds the gap.
    assert_eq!(map.seek_hole(0), Some((4096, 12288)));

    // seek_data beyond last extent returns None.
    assert_eq!(map.seek_data(20480), None);

    assert!(map.validate().is_ok());
}

// =====================================================================
// 4. Free middle extent and verify hole
// =====================================================================

#[test]
fn free_middle_extent_splits_into_two() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 12288, 1)]).unwrap();
    assert_eq!(map.header.entry_count, 1);

    // Free the middle 4 KiB: offset 4096, length 4096.
    let freed = map.punch_hole(4096, 4096).unwrap();
    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, 4096);
    assert_eq!(freed[0].length, 4096);

    // Should now have two entries.
    assert_eq!(map.header.entry_count, 2);
    let all = collect_all(&map);
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].logical_offset, 0);
    assert_eq!(all[0].length, 4096);
    assert_eq!(all[1].logical_offset, 8192);
    assert_eq!(all[1].length, 4096);

    // The hole range [4096, 8192) should be empty.
    assert!(map.lookup_range(4096, 4096).unwrap().is_empty());
    assert_eq!(map.header.file_size, 12288);
    assert_eq!(map.header.alloc_bytes, 8192);
    assert!(map.validate().is_ok());
}

#[test]
fn free_middle_of_three_extents_splits_properly() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(4096, 4096, 2), data(8192, 4096, 3)])
        .unwrap();
    assert_eq!(map.header.entry_count, 3);

    // Free the middle extent entirely.
    let freed = map.punch_hole(4096, 4096).unwrap();
    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, 4096);
    assert_eq!(freed[0].length, 4096);
    assert_eq!(freed[0].locator_id, LocatorId(2));

    // Two entries remain in gaps: [0,4096) and [8192,12288).
    assert_eq!(map.header.entry_count, 2);
    let all = collect_all(&map);
    assert_eq!(all[0].logical_offset, 0);
    assert_eq!(all[0].locator_id, LocatorId(1));
    assert_eq!(all[1].logical_offset, 8192);
    assert_eq!(all[1].locator_id, LocatorId(3));

    // Hole at [4096, 8192).
    assert!(map.lookup_range(4096, 4096).unwrap().is_empty());
    assert_eq!(map.header.file_size, 12288);
    assert_eq!(map.header.alloc_bytes, 8192);
    assert!(map.validate().is_ok());
}

// =====================================================================
// 5. Free-and-reallocate same range
// =====================================================================

#[test]
fn free_and_reallocate_same_range_different_locator() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();

    // Free it.
    map.punch_hole(0, 4096).unwrap();
    assert!(collect_all(&map).is_empty());

    // Reallocate at same offset, different locator.
    map.insert_extent(&[data(0, 4096, 99)]).unwrap();

    assert_eq!(map.header.entry_count, 1);
    let all = collect_all(&map);
    assert_eq!(all[0].logical_offset, 0);
    assert_eq!(all[0].length, 4096);
    assert_eq!(all[0].locator_id, LocatorId(99));
    assert_eq!(map.header.file_size, 4096);
    assert_eq!(map.header.alloc_bytes, 4096);
    assert!(map.validate().is_ok());
}

#[test]
fn free_and_reallocate_overlapping_existing() {
    let mut map = InlineExtentMap::new();
    // Two data extents with a gap in between.
    map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
        .unwrap();

    // Free the first extent.
    map.punch_hole(0, 4096).unwrap();

    // Reallocate a larger extent covering the freed gap and part of the hole.
    map.insert_extent(&[data(0, 8192, 3)]).unwrap();

    // Should merge with the second if same locator... but locator differs (3 vs 2).
    let all = collect_all(&map);
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].logical_offset, 0);
    assert_eq!(all[0].length, 8192);
    assert_eq!(all[0].locator_id, LocatorId(3));
    assert_eq!(all[1].logical_offset, 8192);
    assert_eq!(all[1].length, 4096);
    assert_eq!(all[1].locator_id, LocatorId(2));
    assert_eq!(map.header.file_size, 12288);
    assert_eq!(map.header.alloc_bytes, 12288);
    assert!(map.validate().is_ok());
}

#[test]
fn free_and_reallocate_merge_with_adjacent_same_locator() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 7), data(4096, 4096, 7), data(8192, 4096, 7)])
        .unwrap();
    // Contiguous, same locator -> merged to one [0, 12288).
    assert_eq!(map.header.entry_count, 1);

    // Free the middle portion.
    map.punch_hole(4096, 4096).unwrap();
    assert_eq!(map.header.entry_count, 2);

    // Reallocate the freed portion, same locator.
    map.insert_extent(&[data(4096, 4096, 7)]).unwrap();

    // Should re-merge into one entry.
    assert_eq!(map.header.entry_count, 1);
    let all = collect_all(&map);
    assert_eq!(all[0].logical_offset, 0);
    assert_eq!(all[0].length, 12288);
    assert_eq!(all[0].locator_id, LocatorId(7));
    assert!(map.validate().is_ok());
}

// =====================================================================
// 6. Allocate at file offset zero after truncate
// =====================================================================

#[test]
fn alloc_at_zero_after_truncate_to_zero() {
    let mut map = InlineExtentMap::new();
    // Allocate three extents spanning large range.
    map.insert_extent(&[data(0, 4096, 1), data(4096, 4096, 2), data(16384, 8192, 3)])
        .unwrap();

    // Truncate to zero: all extents freed.
    let freed = map.truncate(0).unwrap();
    assert_eq!(freed.len(), 3);
    assert!(collect_all(&map).is_empty());
    assert_eq!(map.header.file_size, 0);

    // Allocate new extent at offset 0.
    map.insert_extent(&[data(0, 4096, 42)]).unwrap();

    assert_eq!(map.header.entry_count, 1);
    assert_eq!(map.header.file_size, 4096);
    let all = collect_all(&map);
    assert_eq!(all[0].logical_offset, 0);
    assert_eq!(all[0].length, 4096);
    assert_eq!(all[0].locator_id, LocatorId(42));
    assert!(map.validate().is_ok());
}

#[test]
fn alloc_at_zero_after_truncate_to_mid_extent() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 12288, 1)]).unwrap();

    // Truncate to 4096: the extent [0, 12288) is trimmed to [0, 4096).
    let freed = map.truncate(4096).unwrap();
    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, 4096);
    assert_eq!(freed[0].length, 8192);

    assert_eq!(map.header.entry_count, 1);
    assert_eq!(map.header.file_size, 4096);
    let all = collect_all(&map);
    assert_eq!(all[0].logical_offset, 0);
    assert_eq!(all[0].length, 4096);

    // Now allocate a new extent at offset 0 that overlaps the remaining entry.
    // This replaces the old [0,4096) with new [0,4096) at locator 99.
    map.insert_extent(&[data(0, 4096, 99)]).unwrap();
    assert_eq!(map.header.entry_count, 1);
    let all = collect_all(&map);
    assert_eq!(all[0].locator_id, LocatorId(99));
    assert_eq!(map.header.file_size, 4096);
    assert!(map.validate().is_ok());
}

#[test]
fn alloc_at_zero_after_truncate_then_allocate_beyond() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 8192, 1)]).unwrap();

    // Truncate to 4096.
    map.truncate(4096).unwrap();

    // Allocate at offset 0 (replaces existing).
    map.insert_extent(&[data(0, 4096, 2)]).unwrap();

    // Allocate a new extent at offset 8192 (beyond file_size).
    map.insert_extent(&[data(8192, 4096, 3)]).unwrap();

    assert_eq!(map.header.entry_count, 2);
    assert_eq!(map.header.file_size, 12288);
    let all = collect_all(&map);
    assert_eq!(all[0].logical_offset, 0);
    assert_eq!(all[0].locator_id, LocatorId(2));
    assert_eq!(all[1].logical_offset, 8192);
    assert_eq!(all[1].locator_id, LocatorId(3));

    // Gap between them.
    assert!(map.lookup_range(4096, 4096).unwrap().is_empty());
    assert!(map.validate().is_ok());
}
