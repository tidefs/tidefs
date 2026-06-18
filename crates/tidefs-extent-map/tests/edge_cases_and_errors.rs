// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Edge case and error-path validation tests.
//!
//! Exercises error returns, boundary rejection, and idempotent no-ops
//! through the InlineExtentMap public API. Focuses on InvalidRange,
//! MapFull, NotFound, and Corrupt error variants without duplicating
//! coverage already present in extent_map_validation.rs.

use tidefs_extent_map::InlineExtentMap;
use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapError, ExtentMapOps, LocatorId};

// --- helpers ---

fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
    let cs = [0x11; 32];
    ExtentMapEntryV2::new_data(off, len, LocatorId(loc), cs, 0)
}

// =====================================================================
// 1. Zero-length rejection
// =====================================================================

#[test]
fn zero_length_insert_rejected() {
    let mut map = InlineExtentMap::new();
    let err = map.insert_extent(&[data(0, 0, 1)]).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
    assert!(map.entries.is_empty());
}

#[test]
fn zero_length_punch_hole_rejected() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    let err = map.punch_hole(0, 0).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
    // Existing extent untouched.
    assert_eq!(map.header.entry_count, 1);
}

#[test]
fn zero_length_lookup_rejected() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    let err = map.lookup_range(0, 0).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
}

#[test]
fn zero_length_fallocate_rejected() {
    let mut map = InlineExtentMap::new();
    let err = map.fallocate(0, 0, false).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
    assert!(map.entries.is_empty());
}

#[test]
fn zero_length_fiemap_rejected() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    let err = map.fiemap(0, 0).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
}

// =====================================================================
// 2. Offset overflow rejection
// =====================================================================

#[test]
fn lookup_overflow_u64_max_plus_length_rejected() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    let err = map.lookup_range(u64::MAX, 1).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
}

#[test]
fn punch_hole_overflow_u64_max_plus_length_rejected() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    let err = map.punch_hole(u64::MAX, 1).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
}

#[test]
fn fallocate_overflow_rejected() {
    let mut map = InlineExtentMap::new();
    let err = map.fallocate(u64::MAX, 1, false).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
    assert_eq!(map.header.file_size, 0);
}

#[test]
fn collapse_range_overflow_rejected() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    let err = map.collapse_range(u64::MAX, 1).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
}

// =====================================================================
// 3. MapFull: insert after limit reached preserves state
// =====================================================================

#[test]
fn map_full_leaves_existing_state_intact() {
    let mut map = InlineExtentMap::new();

    // Fill exactly 6 entries.
    for i in 0..6u64 {
        map.insert_extent(&[data(i * 8192, 4096, i + 1)]).unwrap();
    }
    assert_eq!(map.header.entry_count, 6);

    // Snapshot before failed insert.
    let snapshot = map.clone();

    // 7th insert should fail with MapFull.
    let err = map.insert_extent(&[data(6 * 8192, 4096, 7)]).unwrap_err();
    assert_eq!(err, ExtentMapError::MapFull);

    // Map state must be identical to snapshot.
    assert_eq!(map.entries, snapshot.entries);
    assert_eq!(map.header, snapshot.header);
    assert_eq!(map.header.entry_count, 6);
    assert!(map.validate().is_ok());
}

#[test]
fn map_full_preserves_alloc_bytes() {
    let mut map = InlineExtentMap::new();

    for i in 0..6u64 {
        map.insert_extent(&[data(i * 8192, 4096, i + 1)]).unwrap();
    }
    let expected_alloc = map.header.alloc_bytes;

    let _ = map.insert_extent(&[data(49152, 4096, 7)]);

    assert_eq!(map.header.alloc_bytes, expected_alloc);
    assert_eq!(map.header.entry_count, 6);
}

// =====================================================================
// 4. Lookup beyond file size
// =====================================================================

#[test]
fn lookup_entirely_beyond_file_size_is_empty() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    // file_size is 4096.

    assert!(map.lookup_range(4096, 4096).unwrap().is_empty());
    assert!(map.lookup_range(8192, 4096).unwrap().is_empty());
    assert!(map
        .lookup_range(12288, u64::MAX - 12288)
        .unwrap()
        .is_empty());
}

#[test]
fn lookup_spanning_past_file_size_clips_to_file() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();

    // Lookup spanning [0..8192): should only return the [0..4096) entry.
    let r = map.lookup_range(0, 8192).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, 0);
    assert_eq!(r[0].length, 4096);
}

// =====================================================================
// 5. Punch and free: no-op on empty/unallocated ranges
// =====================================================================

#[test]
fn punch_hole_on_empty_map_extends_file_size() {
    let mut map = InlineExtentMap::new();
    let freed = map.punch_hole(4096, 4096).unwrap();
    assert!(freed.is_empty());
    assert_eq!(map.header.file_size, 8192);
    assert!(map.entries.is_empty());
    assert!(map.validate().is_ok());
}

#[test]
fn punch_hole_on_existing_gap_no_freed() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
        .unwrap();

    // Punch exactly the gap: [4096..8192).
    let freed = map.punch_hole(4096, 4096).unwrap();
    assert!(freed.is_empty());

    // Both extents preserved.
    assert_eq!(map.header.entry_count, 2);
    assert_eq!(map.header.alloc_bytes, 8192);
    assert!(map.validate().is_ok());
}

// =====================================================================
// 6. Collapse range error paths
// =====================================================================

#[test]
fn collapse_range_zero_length_is_noop() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();

    let freed = map.collapse_range(0, 0).unwrap();
    assert!(freed.is_empty());
    assert_eq!(map.header.entry_count, 1);
    assert_eq!(map.header.file_size, 4096);
}

#[test]
fn collapse_range_beyond_file_size_rejected() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    // file_size is 4096. Collapse at offset 4096+ would exceed it.
    let err = map.collapse_range(8192, 4096).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);

    // Collapse that ends exactly at file_size: [4096..8192) -> end=8192 > file_size=4096.
    let err = map.collapse_range(4096, 4096).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);

    assert_eq!(map.header.entry_count, 1);
}

// =====================================================================
// 7. Convert unwritten_to_data error paths
// =====================================================================

#[test]
fn convert_unwritten_to_data_zero_length_rejected() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[ExtentMapEntryV2::new_unwritten(0, 4096, 0)])
        .unwrap();

    let err = map
        .convert_unwritten_to_data(0, 0, LocatorId(1), [0u8; 32], 0)
        .unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
}

#[test]
fn convert_unwritten_to_data_on_data_entry_returns_not_found() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();

    let err = map
        .convert_unwritten_to_data(0, 2048, LocatorId(1), [0u8; 32], 0)
        .unwrap_err();
    assert_eq!(err, ExtentMapError::NotFound);
}

#[test]
fn convert_unwritten_to_data_partial_overlap_rejected() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[ExtentMapEntryV2::new_unwritten(0, 4096, 0)])
        .unwrap();

    // Range extends beyond the UNWRITTEN entry: [2048..6144), but
    // UNWRITTEN only covers [0..4096).
    let err = map
        .convert_unwritten_to_data(2048, 4096, LocatorId(1), [0u8; 32], 0)
        .unwrap_err();
    assert_eq!(err, ExtentMapError::NotFound);
}

// =====================================================================
// 8. Seek data/hole past file size
// =====================================================================

#[test]
fn seek_data_past_file_size_returns_none() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();

    assert_eq!(map.seek_data(4096), None);
    assert_eq!(map.seek_data(8192), None);
    assert_eq!(map.seek_data(u64::MAX), None);
}

#[test]
fn seek_hole_past_file_size_returns_none() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();

    // file_size is 4096; past that there's nothing.
    assert_eq!(map.seek_hole(4096), None);
    assert_eq!(map.seek_hole(8192), None);
}

// =====================================================================
// 9. Validate error variants
// =====================================================================

#[test]
fn validate_detects_overlapping_entries() {
    let mut map = InlineExtentMap::new();
    // Construct overlapping entries by direct manipulation.
    map.entries = vec![data(0, 8192, 1), data(4096, 4096, 2)];
    map.header.file_size = 12288;
    map.header.entry_count = 2;
    map.header.alloc_bytes = 12288;

    let err = map.validate().unwrap_err();
    assert_eq!(err, ExtentMapError::OverlappingExtent);
}

#[test]
fn validate_detects_entry_count_mismatch() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    map.header.entry_count = 99;

    let err = map.validate().unwrap_err();
    assert_eq!(err, ExtentMapError::Corrupt);
}

#[test]
fn validate_detects_alloc_bytes_mismatch() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    map.header.alloc_bytes = 9999;

    let err = map.validate().unwrap_err();
    assert_eq!(err, ExtentMapError::Corrupt);
}

#[test]
fn validate_passes_on_well_formed_map() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
        .unwrap();
    assert!(map.validate().is_ok());
}

// =====================================================================
// 10. fiemap on empty map and error paths
// =====================================================================

#[test]
fn fiemap_on_empty_map_returns_single_hole() {
    let map = InlineExtentMap::new();
    let r = map.fiemap(0, 4096).unwrap();
    assert_eq!(r.len(), 1);
    // Empty map: the entire [0..4096) range is a single hole.
    assert_eq!(r[0].fe_logical, 0);
    assert_eq!(r[0].fe_length, 4096);
}

#[test]
fn fiemap_on_empty_map_zero_length_rejected() {
    let map = InlineExtentMap::new();
    let err = map.fiemap(0, 0).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
}

#[test]
fn fiemap_overflow_rejected() {
    let mut map = InlineExtentMap::new();
    map.insert_extent(&[data(0, 4096, 1)]).unwrap();
    let err = map.fiemap(u64::MAX, 1).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
}
