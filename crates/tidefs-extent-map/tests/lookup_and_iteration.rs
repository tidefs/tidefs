// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Lookup and iteration validation tests.
//!
//! Exercises boundary-condition lookup and ordered iteration through
//! InlineExtentMap. Verifies that `lookup_range` behaves correctly at
//! extent start, middle, and end boundaries; returns empty for holes;
//! and that full-range iteration yields extents in sorted offset order.
//! Covers empty-map and post-free iteration edge cases.

use tidefs_extent_map::InlineExtentMap;
use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapOps, LocatorId};

// --- helpers ---

fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
    let cs = [0xCD; 32];
    ExtentMapEntryV2::new_data(off, len, LocatorId(loc), cs, 0)
}

/// Collect all entries via a full-range lookup.
fn collect_all(map: &InlineExtentMap) -> Vec<ExtentMapEntryV2> {
    map.lookup_range(0, u64::MAX).unwrap_or_default()
}

/// Assert entries are in strictly ascending logical_offset order.
fn assert_sorted(entries: &[ExtentMapEntryV2]) {
    for w in entries.windows(2) {
        assert!(
            w[0].logical_offset < w[1].logical_offset,
            "entries not sorted: {} followed by {}",
            w[0].logical_offset,
            w[1].logical_offset,
        );
    }
}

// =====================================================================
// 1. Lookup at extent boundaries
// =====================================================================

#[test]
fn lookup_at_extent_start_returns_full_extent() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(4096, 4096, 1)]).unwrap();

    // Lookup starting exactly at extent start.
    let r = map.lookup_range(4096, 4096).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, 4096);
    assert_eq!(r[0].length, 4096);
    assert_eq!(r[0].locator_id, LocatorId(1));
}

#[test]
fn lookup_at_extent_end_exclusive_is_empty() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();

    // Lookup starting exactly at extent end (8192). Should be empty.
    let r = map.lookup_range(4096, 4096).unwrap();
    // Wait: extent is [0, 4096), so lookup_range(4096, 4096) is [4096, 8192) -- after extent.
    assert!(r.is_empty());

    // Lookup covering the exact end boundary: [0, 4096) finds the extent,
    // [4096, 8192) does not.
    let r = map.lookup_range(4096, 4096).unwrap();
    assert!(r.is_empty());

    // A lookup that starts before and ends at extent end: [2048, 4096).
    let r = map.lookup_range(0, 4096).unwrap();
    assert_eq!(r.len(), 1);
}

#[test]
fn lookup_at_mid_extent_returns_clipped_entry() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 12288, 1)]).unwrap();

    // Lookup the middle portion: [4096, 8192).
    let r = map.lookup_range(4096, 4096).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, 4096);
    assert_eq!(r[0].length, 4096);
    assert_eq!(r[0].locator_id, LocatorId(1));

    // Lookup a narrow window: [5120, 6144).
    let r = map.lookup_range(5120, 1024).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, 5120);
    assert_eq!(r[0].length, 1024);
}

#[test]
fn lookup_at_extent_end_minus_one_still_within() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();

    // Extent covers [0, 4096). offset 4095 is the last byte.
    // lookup_range(4095, 1) -> [4095, 4096) should return the extent.
    let r = map.lookup_range(4095, 1).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, 4095);
    assert_eq!(r[0].length, 1);
}

// =====================================================================
// 2. Lookup in holes
// =====================================================================

#[test]
fn lookup_in_gap_between_extents_is_empty() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
        .unwrap();

    // The range [4096, 8192) is a gap between extents.
    assert!(map.lookup_range(4096, 4096).unwrap().is_empty());
    assert!(map.lookup_range(6144, 512).unwrap().is_empty());

    // A lookup that spans the gap: [2048, 8192).
    let r = map.lookup_range(2048, 8192).unwrap();
    // Should get two entries: tail of first extent + head of second.
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].logical_offset, 2048);
    assert_eq!(r[0].length, 2048);
    assert_eq!(r[1].logical_offset, 8192);
    assert_eq!(r[1].length, 2048);

    assert!(map.validate().is_ok());
}

#[test]
fn lookup_entirely_in_hole_before_first_extent_is_empty() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(4096, 4096, 1)]).unwrap();

    // Range [0, 4096) is before the first extent.
    assert!(map.lookup_range(0, 4096).unwrap().is_empty());
    assert!(map.lookup_range(0, 2048).unwrap().is_empty());

    // Range that starts before but includes the extent: [2048, 4096).
    let r = map.lookup_range(2048, 4096).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, 4096);
    assert_eq!(r[0].length, 2048);
}

#[test]
fn lookup_beyond_last_extent_is_empty() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    // file_size is 4096.

    // Range entirely beyond the file.
    assert!(map.lookup_range(4096, 4096).unwrap().is_empty());
    assert!(map.lookup_range(8192, 4096).unwrap().is_empty());
}

// =====================================================================
// 3. Iteration yields extents in offset order
// =====================================================================

#[test]
fn iteration_yields_sorted_order_after_out_of_order_insert() {
    let mut map = InlineExtentMap::new();
    // Insert in non-sorted order.
    map.insert_extent(&[data(16384, 4096, 3), data(0, 4096, 1), data(8192, 4096, 2)])
        .unwrap();

    let entries = collect_all(&map);
    assert_eq!(entries.len(), 3);
    assert_sorted(&entries);
    assert_eq!(entries[0].logical_offset, 0);
    assert_eq!(entries[1].logical_offset, 8192);
    assert_eq!(entries[2].logical_offset, 16384);
    assert!(map.validate().is_ok());
}

#[test]
fn iteration_yields_sorted_order_after_overwrite() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 12288, 1)]).unwrap();

    // Overwrite a middle chunk with a different locator.
    map.insert_extent(&[data(4096, 4096, 2)]).unwrap();

    let entries = collect_all(&map);
    assert_eq!(entries.len(), 3);
    assert_sorted(&entries);
    assert_eq!(entries[0].logical_offset, 0);
    assert_eq!(entries[0].locator_id, LocatorId(1));
    assert_eq!(entries[1].logical_offset, 4096);
    assert_eq!(entries[1].locator_id, LocatorId(2));
    assert_eq!(entries[2].logical_offset, 8192);
    assert_eq!(entries[2].locator_id, LocatorId(1));
    assert!(map.validate().is_ok());
}

#[test]
fn iteration_yields_sorted_order_after_free_middle() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(4096, 4096, 2), data(8192, 4096, 3)])
        .unwrap();

    // Free the middle extent.
    map.punch_hole(4096, 4096).unwrap();

    let entries = collect_all(&map);
    assert_eq!(entries.len(), 2);
    assert_sorted(&entries);
    assert_eq!(entries[0].logical_offset, 0);
    assert_eq!(entries[1].logical_offset, 8192);
    assert!(map.validate().is_ok());
}

#[test]
fn iteration_yields_sorted_order_after_truncate() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[
        data(0, 4096, 1),
        data(8192, 4096, 2),
        data(16384, 4096, 3),
        data(24576, 4096, 4),
    ])
    .unwrap();

    map.truncate(14336).unwrap();

    let entries = collect_all(&map);
    assert_sorted(&entries);
    // Truncate at 14336: drops [16384,20480) and [24576,28672),
    // keeps [0,4096) and [8192,12288). Third entry (16384) is fully
    // beyond new_size; second entry (8192) is fully before 14336.
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].logical_offset, 0);
    assert_eq!(entries[1].logical_offset, 8192);
    assert_eq!(map.header.file_size, 14336);
    assert!(map.validate().is_ok());
}

// =====================================================================
// 4. Iteration on empty map
// =====================================================================

#[test]
fn iteration_empty_map_yields_no_extents() {
    let map = InlineExtentMap::new();
    let entries = collect_all(&map);
    assert!(entries.is_empty());
    assert_eq!(map.header.entry_count, 0);

    // Also verify non-full-range lookup returns empty.
    assert!(map.lookup_range(0, 4096).unwrap().is_empty());
    assert!(map.lookup_range(8192, 16384).unwrap().is_empty());
    assert!(map.validate().is_ok());
}

#[test]
fn iteration_empty_map_after_insert_then_free_all() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)])
        .unwrap();

    // Free all three extents.
    map.punch_hole(0, 4096).unwrap();
    map.punch_hole(8192, 4096).unwrap();
    map.punch_hole(16384, 4096).unwrap();

    let entries = collect_all(&map);
    assert!(entries.is_empty());
    assert_eq!(map.header.entry_count, 0);
    assert_eq!(map.header.alloc_bytes, 0);
    // file_size preserved: last punch_hole extends file_size to 20480.
    assert!(map.validate().is_ok());
}

#[test]
fn iteration_empty_map_after_truncate_to_zero() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(4096, 4096, 2), data(16384, 8192, 3)])
        .unwrap();

    map.truncate(0).unwrap();

    let entries = collect_all(&map);
    assert!(entries.is_empty());
    assert_eq!(map.header.entry_count, 0);
    assert_eq!(map.header.alloc_bytes, 0);
    assert_eq!(map.header.file_size, 0);
    assert!(map.validate().is_ok());
}

// =====================================================================
// 5. Entry count matches iteration count
// =====================================================================

#[test]
fn entry_count_matches_collected_count_after_insert() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2), data(20480, 8192, 3)])
        .unwrap();

    let entries = collect_all(&map);
    assert_eq!(entries.len() as u64, map.header.entry_count);
    assert_eq!(map.header.entry_count, 3);
}

#[test]
fn entry_count_matches_collected_count_after_free() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[
        data(0, 4096, 1),
        data(4096, 4096, 2),
        data(8192, 4096, 3),
        data(12288, 4096, 4),
    ])
    .unwrap();

    // Free the second extent.
    map.punch_hole(4096, 4096).unwrap();

    let entries = collect_all(&map);
    assert_eq!(entries.len() as u64, map.header.entry_count);
    assert_eq!(map.header.entry_count, 3);
}

#[test]
fn entry_count_matches_collected_count_after_truncate() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(4096, 4096, 2), data(8192, 4096, 3)])
        .unwrap();

    // Truncate mid-second-extent.
    map.truncate(6144).unwrap();

    let entries = collect_all(&map);
    assert_eq!(entries.len() as u64, map.header.entry_count);
    // First extent [0,4096) intact, second extent [4096,8192) trimmed to [4096,6144).
    assert_eq!(map.header.entry_count, 2);
}

// =====================================================================
// 6. Iteration with partial-range lookup
// =====================================================================

#[test]
fn partial_range_iteration_respects_bounds() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)])
        .unwrap();

    // Range [2048, 12288): covers tail of first, all of second, gap before third.
    let r = map.lookup_range(2048, 12288).unwrap();
    assert_sorted(&r);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].logical_offset, 2048);
    assert_eq!(r[0].length, 2048);
    assert_eq!(r[0].locator_id, LocatorId(1));
    assert_eq!(r[1].logical_offset, 8192);
    assert_eq!(r[1].length, 4096);
    assert_eq!(r[1].locator_id, LocatorId(2));
}
