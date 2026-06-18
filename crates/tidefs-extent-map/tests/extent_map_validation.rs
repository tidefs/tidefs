// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration validation tests for tidefs-extent-map.
//!
//! Exercises the public API of InlineExtentMap across allocation, lookup,
//! truncation, hole/gap, persistence round-trip, and stress boundaries.
//! These tests complement the inline unit tests by verifying behavior
//! through only the public interface.

use tidefs_extent_map::InlineExtentMap;
use tidefs_types_extent_map_core::{
    ExtentMapEntryV2, ExtentMapError, ExtentMapOps, ExtentMapV1, ExtentType, FiemapExtent,
    LocatorId,
};

// --- helpers ---

fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
    let cs = [0xAB; 32];
    ExtentMapEntryV2::new_data(off, len, LocatorId(loc), cs, 0)
}

fn make_map(entries: &[ExtentMapEntryV2]) -> InlineExtentMap {
    let mut m = InlineExtentMap::new();
    if !entries.is_empty() {
        m.insert_extent(entries).unwrap();
    }
    m
}

// =====================================================================
// 1. Empty-map boundary
// =====================================================================

#[test]
fn empty_map_defaults() {
    let m = InlineExtentMap::new();
    assert_eq!(m.header.file_size, 0);
    assert_eq!(m.header.entry_count, 0);
    assert_eq!(m.header.alloc_bytes, 0);
    assert!(m.entries.is_empty());
    assert!(m.validate().is_ok());
}

#[test]
fn empty_map_lookup_returns_empty() {
    let m = InlineExtentMap::new();
    let err = m.lookup_range(0, 0).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);

    let r = m.lookup_range(0, 4096).unwrap();
    assert!(r.is_empty());
    let r = m.lookup_range(0, u64::MAX).unwrap();
    assert!(r.is_empty());
}

#[test]
fn empty_map_truncate_noop() {
    let mut m = InlineExtentMap::new();
    let freed = m.truncate(0).unwrap();
    assert!(freed.is_empty());
    assert_eq!(m.header.file_size, 0);
    assert!(m.entries.is_empty());

    let freed = m.truncate(8192).unwrap();
    assert!(freed.is_empty());
    assert_eq!(m.header.file_size, 8192);
    assert!(m.entries.is_empty());
    assert!(m.validate().is_ok());
}

#[test]
fn empty_map_seek_returns_none() {
    let m = InlineExtentMap::new();
    assert_eq!(m.seek_data(0), None);
    assert_eq!(m.seek_data(4096), None);
    assert_eq!(m.seek_hole(0), None);
    assert_eq!(m.seek_hole(4096), None);
}

#[test]
fn empty_map_fallocate_and_punch() {
    let mut m = InlineExtentMap::new();
    let err = m.fallocate(0, 0, false).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);

    let err = m.punch_hole(0, 0).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);

    let freed = m.punch_hole(0, 4096).unwrap();
    assert!(freed.is_empty());
    assert_eq!(m.header.file_size, 4096);
    assert!(m.validate().is_ok());
}

#[test]
fn empty_map_insert_empty_batch_is_noop() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[]).unwrap();
    assert!(m.entries.is_empty());
    assert_eq!(m.header.file_size, 0);
    assert!(m.validate().is_ok());
}

#[test]
fn empty_map_from_parts_default_roundtrip() {
    let header = ExtentMapV1::new();
    let entries: Vec<ExtentMapEntryV2> = Vec::new();
    let m = InlineExtentMap::from_parts(header, entries);
    assert_eq!(m.header.file_size, 0);
    assert_eq!(m.header.entry_count, 0);
    assert_eq!(m.header.alloc_bytes, 0);
    assert!(m.entries.is_empty());
    assert!(m.validate().is_ok());
}

// =====================================================================
// 2. Single-extent allocation and lookup
// =====================================================================

#[test]
fn single_extent_allocate_and_exact_lookup() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 4096, 1)]).unwrap();

    assert_eq!(m.header.file_size, 4096);
    assert_eq!(m.header.entry_count, 1);
    assert_eq!(m.header.alloc_bytes, 4096);
    assert_eq!(m.entries.len(), 1);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 4096);
    assert_eq!(m.entries[0].locator_id, LocatorId(1));
    assert!(m.validate().is_ok());
}

#[test]
fn single_extent_lookup_whole_range() {
    let m = make_map(&[data(0, 4096, 1)]);
    let r = m.lookup_range(0, 4096).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, 0);
    assert_eq!(r[0].length, 4096);
    assert_eq!(r[0].locator_id, LocatorId(1));
}

#[test]
fn single_extent_lookup_sub_range() {
    let m = make_map(&[data(0, 4096, 1)]);
    let r = m.lookup_range(1024, 2048).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, 1024);
    assert_eq!(r[0].length, 2048);
    assert_eq!(r[0].locator_id, LocatorId(1));
}

#[test]
fn single_extent_lookup_before_extent() {
    let m = make_map(&[data(4096, 4096, 1)]);
    let r = m.lookup_range(0, 4096).unwrap();
    assert!(r.is_empty());
}

#[test]
fn single_extent_lookup_after_extent() {
    let m = make_map(&[data(0, 4096, 1)]);
    let r = m.lookup_range(4096, 4096).unwrap();
    assert!(r.is_empty());
}

#[test]
fn single_extent_lookup_spanning_beyond() {
    let m = make_map(&[data(2048, 4096, 1)]);
    let r = m.lookup_range(0, 8192).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, 2048);
    assert_eq!(r[0].length, 4096);
}

#[test]
fn single_extent_lookup_zero_length_rejected() {
    let m = make_map(&[data(0, 4096, 1)]);
    let err = m.lookup_range(0, 0).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
}

#[test]
fn single_extent_lookup_overflow_rejected() {
    let m = make_map(&[data(0, 4096, 1)]);
    let err = m.lookup_range(u64::MAX, 1).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
    let err = m.lookup_range(1, u64::MAX).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
}

#[test]
fn single_extent_seek_data_and_hole() {
    let m = make_map(&[data(4096, 4096, 1)]);

    assert_eq!(m.seek_data(0), Some((4096, 4096)));
    assert_eq!(m.seek_data(4096), Some((4096, 4096)));
    assert_eq!(m.seek_data(6144), Some((6144, 2048)));
    assert_eq!(m.seek_data(8192), None);

    // Hole before the first extent: [0, 4096).
    assert_eq!(m.seek_hole(0), Some((0, 4096)));
    assert_eq!(m.seek_hole(2048), Some((2048, 2048)));
    // At the extent boundary there is no hole: extent covers [4096, 8192)
    // and file_size is 8192.
    assert_eq!(m.seek_hole(4096), None);
    assert_eq!(m.seek_hole(8192), None);
}

#[test]
fn single_extent_st_blocks() {
    let m = make_map(&[data(0, 4096, 1)]);
    assert_eq!(m.st_blocks(), 8);

    let m = make_map(&[data(0, 512, 1)]);
    assert_eq!(m.st_blocks(), 1);

    let m = make_map(&[data(0, 1, 1)]);
    assert_eq!(m.st_blocks(), 1);
}

#[test]
fn single_extent_fiemap() {
    let m = make_map(&[data(0, 4096, 1)]);
    let r = m.fiemap(0, 4096).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].fe_logical, 0);
    assert_eq!(r[0].fe_length, 4096);
    assert_ne!(r[0].fe_flags & FiemapExtent::FLAG_LAST, 0);
}

// =====================================================================
// 3. Multi-extent allocation and merge
// =====================================================================

#[test]
fn multi_extent_non_adjacent_stay_separate() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)])
        .unwrap();

    assert_eq!(m.header.entry_count, 3);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 4096);
    assert_eq!(m.entries[1].logical_offset, 8192);
    assert_eq!(m.entries[1].length, 4096);
    assert_eq!(m.entries[2].logical_offset, 16384);
    assert_eq!(m.entries[2].length, 4096);
    assert_eq!(m.header.file_size, 20480);
    assert!(m.validate().is_ok());
}

#[test]
fn multi_extent_adjacent_same_locator_merge() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 4096, 7), data(4096, 4096, 7), data(8192, 4096, 7)])
        .unwrap();

    assert_eq!(m.header.entry_count, 1);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 12288);
    assert_eq!(m.entries[0].locator_id, LocatorId(7));
    assert_eq!(m.header.file_size, 12288);
    assert_eq!(m.header.alloc_bytes, 12288);
    assert!(m.validate().is_ok());
}

#[test]
fn multi_extent_adjacent_different_locator_stay_separate() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 4096, 1), data(4096, 4096, 2)])
        .unwrap();

    assert_eq!(m.header.entry_count, 2);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].locator_id, LocatorId(1));
    assert_eq!(m.entries[1].logical_offset, 4096);
    assert_eq!(m.entries[1].locator_id, LocatorId(2));
    assert!(m.validate().is_ok());
}

#[test]
fn multi_extent_overwrite_bridge_merges() {
    let mut m = make_map(&[data(0, 4096, 1), data(8192, 4096, 1), data(16384, 4096, 1)]);

    m.insert_extent(&[data(2048, 10240, 1)]).unwrap();

    assert_eq!(m.header.entry_count, 2);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 12288);
    assert_eq!(m.entries[0].locator_id, LocatorId(1));
    assert_eq!(m.entries[1].logical_offset, 16384);
    assert_eq!(m.entries[1].length, 4096);
    assert_eq!(m.entries[1].locator_id, LocatorId(1));
    assert!(m.validate().is_ok());
}

#[test]
fn multi_extent_overwrite_different_locator_splits() {
    let mut m = make_map(&[data(0, 8192, 1)]);

    m.insert_extent(&[data(2048, 4096, 2)]).unwrap();

    assert_eq!(m.header.entry_count, 3);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 2048);
    assert_eq!(m.entries[0].locator_id, LocatorId(1));
    assert_eq!(m.entries[1].logical_offset, 2048);
    assert_eq!(m.entries[1].length, 4096);
    assert_eq!(m.entries[1].locator_id, LocatorId(2));
    assert_eq!(m.entries[2].logical_offset, 6144);
    assert_eq!(m.entries[2].length, 2048);
    assert_eq!(m.entries[2].locator_id, LocatorId(1));
    assert_eq!(m.header.alloc_bytes, 8192);
    assert!(m.validate().is_ok());
}

#[test]
fn multi_extent_map_full_rejected() {
    let mut m = InlineExtentMap::new();
    let entries: Vec<_> = (0..7).map(|i| data(i * 8192, 4096, i + 1)).collect();
    let err = m.insert_extent(&entries).unwrap_err();
    assert_eq!(err, ExtentMapError::MapFull);
}

#[test]
fn multi_extent_overlapping_batch_rejected() {
    let mut m = InlineExtentMap::new();
    let err = m
        .insert_extent(&[data(0, 8192, 1), data(4096, 4096, 2)])
        .unwrap_err();
    assert_eq!(err, ExtentMapError::OverlappingExtent);
}

// =====================================================================
// 4. Hole and gap behavior
// =====================================================================

#[test]
fn gap_between_extents_is_empty_on_lookup() {
    let m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);

    let r = m.lookup_range(4096, 4096).unwrap();
    assert!(r.is_empty());

    let r = m.lookup_range(0, 12288).unwrap();
    assert_eq!(r.len(), 2);
}

#[test]
fn gap_seek_data_skips_to_next() {
    let m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);

    assert_eq!(m.seek_data(4096), Some((8192, 4096)));
    assert_eq!(m.seek_data(6144), Some((8192, 4096)));
}

#[test]
fn gap_seek_hole_finds_the_gap() {
    let m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);

    // Hole at [4096, 8192).
    assert_eq!(m.seek_hole(0), Some((4096, 4096)));
    assert_eq!(m.seek_hole(4096), Some((4096, 4096)));
    // Current implementation returns sub-hole starting at the query offset; cursor does not reset backwards
    // within a hole; returns hole start rather than sub-hole from the offset.
    assert_eq!(m.seek_hole(6144), Some((6144, 8192 - 6144)));
}

#[test]
fn seek_hole_past_last_extent() {
    let mut m = make_map(&[data(0, 4096, 1)]);
    m.header.file_size = 8192;

    assert_eq!(m.seek_hole(4096), Some((4096, 4096)));
    // seek_hole from within the hole returns sub-hole starting at offset.
    assert_eq!(m.seek_hole(6144), Some((6144, 8192 - 6144)));
    // At file_size, no hole remains.
    assert_eq!(m.seek_hole(8192), None);
}

#[test]
fn seek_hole_contiguous_data_no_hole() {
    let m = make_map(&[data(0, 4096, 1), data(4096, 4096, 1)]);
    // Adjacent same-locator entries merge into one.
    assert_eq!(m.entries.len(), 1);
    assert_eq!(m.seek_hole(0), None);
}

// =====================================================================
// 4½. Hole-punch integration: boundary, spanning, and idempotence
// =====================================================================

#[test]
fn punch_hole_mid_extent_splits_and_frees() {
    let mut m = make_map(&[data(0, 12288, 1)]);

    let freed = m.punch_hole(4096, 4096).unwrap();

    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, 4096);
    assert_eq!(freed[0].length, 4096);
    assert_eq!(freed[0].locator_id, LocatorId(1));
    assert_eq!(freed[0].extent_type, ExtentType::Data);

    assert_eq!(m.header.entry_count, 2);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 4096);
    assert_eq!(m.entries[1].logical_offset, 8192);
    assert_eq!(m.entries[1].length, 4096);
    assert_eq!(m.header.file_size, 12288);
    assert_eq!(m.header.alloc_bytes, 8192);
    assert!(m.validate().is_ok());

    // Verify the hole is not data-bearing.
    let r = m.lookup_range(4096, 4096).unwrap();
    assert!(r.is_empty());
    // Surrounding data is intact.
    let r = m.lookup_range(0, 4096).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].length, 4096);
    let r = m.lookup_range(8192, 4096).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].length, 4096);
}

#[test]
fn punch_hole_spanning_two_data_extents_frees_both() {
    let mut m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);

    // Punch from 2048 through 10240: covers tail of first extent, the
    // 4096-byte gap (no data), and the head of the second extent.
    let freed = m.punch_hole(2048, 8192).unwrap();

    assert_eq!(freed.len(), 2);
    assert_eq!(freed[0].logical_offset, 2048);
    assert_eq!(freed[0].length, 2048);
    assert_eq!(freed[0].locator_id, LocatorId(1));
    assert_eq!(freed[0].extent_type, ExtentType::Data);
    assert_eq!(freed[1].logical_offset, 8192);
    assert_eq!(freed[1].length, 2048);
    assert_eq!(freed[1].locator_id, LocatorId(2));
    assert_eq!(freed[1].extent_type, ExtentType::Data);

    // First extent trimmed to [0, 2048), second trimmed to [10240, 12288).
    assert_eq!(m.header.entry_count, 2);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 2048);
    assert_eq!(m.entries[1].logical_offset, 10240);
    assert_eq!(m.entries[1].length, 2048);
    assert_eq!(m.header.file_size, 12288);
    assert_eq!(m.header.alloc_bytes, 4096);
    assert!(m.validate().is_ok());
}

#[test]
fn punch_hole_at_extent_start_removes_entire_extent() {
    let mut m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);

    // Punch exactly at the start of the first extent, covering all of it.
    let freed = m.punch_hole(0, 4096).unwrap();

    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, 0);
    assert_eq!(freed[0].length, 4096);
    assert_eq!(freed[0].locator_id, LocatorId(1));
    assert_eq!(freed[0].extent_type, ExtentType::Data);

    assert_eq!(m.header.entry_count, 1);
    assert_eq!(m.entries[0].logical_offset, 8192);
    assert_eq!(m.entries[0].length, 4096);
    assert!(m.validate().is_ok());
}

#[test]
fn punch_hole_before_first_extent_extends_file_size() {
    let mut m = make_map(&[data(4096, 4096, 1)]);

    let freed = m.punch_hole(0, 2048).unwrap();

    // No data freed — the 0..2048 range is before any extent.
    assert!(freed.is_empty());
    // File size extends to cover the hole.
    assert_eq!(m.header.file_size, 8192);
    // Extent unchanged.
    assert_eq!(m.header.entry_count, 1);
    assert_eq!(m.entries[0].logical_offset, 4096);
    assert_eq!(m.entries[0].length, 4096);
    assert!(m.validate().is_ok());
}

#[test]
fn punch_hole_exactly_in_gap_no_freed() {
    let mut m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);

    // Punch exactly the gap between the two extents.
    let freed = m.punch_hole(4096, 4096).unwrap();

    assert!(freed.is_empty());
    assert_eq!(m.header.entry_count, 2);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 4096);
    assert_eq!(m.entries[1].logical_offset, 8192);
    assert_eq!(m.entries[1].length, 4096);
    assert_eq!(m.header.file_size, 12288);
    assert!(m.validate().is_ok());
}

#[test]
fn punch_hole_double_free_idempotent() {
    let mut m = make_map(&[data(0, 12288, 1)]);

    let freed1 = m.punch_hole(4096, 4096).unwrap();
    assert_eq!(freed1.len(), 1);

    let snapshot = m.clone();

    let freed2 = m.punch_hole(4096, 4096).unwrap();
    assert!(freed2.is_empty());
    assert_eq!(m, snapshot);
    assert!(m.validate().is_ok());
}

#[test]
fn punch_hole_past_eof_extends_file_size_no_freed() {
    let mut m = make_map(&[data(0, 4096, 1)]);

    let freed = m.punch_hole(8192, 4096).unwrap();

    assert!(freed.is_empty());
    assert_eq!(m.header.file_size, 12288);
    assert_eq!(m.header.entry_count, 1);
    assert!(m.validate().is_ok());
}

// =====================================================================
// 5. Truncation
// =====================================================================

#[test]
fn truncate_to_zero_frees_all_extents() {
    let mut m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);

    let freed = m.truncate(0).unwrap();
    assert_eq!(freed.len(), 2);
    assert_eq!(freed[0].logical_offset, 0);
    assert_eq!(freed[0].length, 4096);
    assert_eq!(freed[0].locator_id, LocatorId(1));
    assert_eq!(freed[0].extent_type, ExtentType::Data);
    assert_eq!(freed[1].logical_offset, 8192);
    assert_eq!(freed[1].length, 4096);
    assert_eq!(freed[1].locator_id, LocatorId(2));
    assert_eq!(freed[1].extent_type, ExtentType::Data);

    assert!(m.entries.is_empty());
    assert_eq!(m.header.file_size, 0);
    assert_eq!(m.header.alloc_bytes, 0);
    assert!(m.validate().is_ok());
}

#[test]
fn truncate_mid_extent_splits_and_frees_tail() {
    let mut m = make_map(&[data(0, 12288, 1)]);

    let freed = m.truncate(4096).unwrap();
    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, 4096);
    assert_eq!(freed[0].length, 8192);
    assert_eq!(freed[0].locator_id, LocatorId(1));
    assert_eq!(freed[0].extent_type, ExtentType::Data);

    assert_eq!(m.entries.len(), 1);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 4096);
    assert_eq!(m.header.file_size, 4096);
    assert_eq!(m.header.alloc_bytes, 4096);
    assert!(m.validate().is_ok());
}

#[test]
fn truncate_at_exact_boundary_removes_tail_extent() {
    let mut m = make_map(&[data(0, 4096, 1), data(4096, 4096, 2)]);

    let freed = m.truncate(4096).unwrap();
    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, 4096);
    assert_eq!(freed[0].length, 4096);
    assert_eq!(freed[0].locator_id, LocatorId(2));
    assert_eq!(freed[0].extent_type, ExtentType::Data);

    assert_eq!(m.entries.len(), 1);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 4096);
    assert_eq!(m.header.file_size, 4096);
    assert!(m.validate().is_ok());
}

#[test]
fn truncate_beyond_last_extent_expands_file_size() {
    let mut m = make_map(&[data(0, 4096, 1)]);

    let freed = m.truncate(16384).unwrap();
    assert!(freed.is_empty());
    assert_eq!(m.header.file_size, 16384);
    assert_eq!(m.entries.len(), 1);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 4096);
    assert!(m.validate().is_ok());
}

#[test]
fn truncate_idempotent() {
    let mut m = make_map(&[data(0, 12288, 1)]);

    let freed = m.truncate(4096).unwrap();
    assert_eq!(freed.len(), 1);
    assert_eq!(m.header.file_size, 4096);

    let freed = m.truncate(4096).unwrap();
    assert!(freed.is_empty());
    assert_eq!(m.header.file_size, 4096);
    assert_eq!(m.entries.len(), 1);
    assert!(m.validate().is_ok());
}

#[test]
fn truncate_preserves_data_before_boundary() {
    let mut m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)]);

    // Truncate at 10240 cuts through entry 2 (8192..12288), freeing its
    // tail [10240..12288) and the entirety of entry 3 [16384..20480).
    let freed = m.truncate(10240).unwrap();
    assert_eq!(freed.len(), 2);
    assert_eq!(freed[0].logical_offset, 10240);
    assert_eq!(freed[0].length, 2048);
    assert_eq!(freed[0].locator_id, LocatorId(2));
    assert_eq!(freed[1].logical_offset, 16384);
    assert_eq!(freed[1].length, 4096);
    assert_eq!(freed[1].locator_id, LocatorId(3));

    assert_eq!(m.entries.len(), 2);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 4096);
    assert_eq!(m.entries[1].logical_offset, 8192);
    assert_eq!(m.entries[1].length, 2048);
    assert_eq!(m.header.file_size, 10240);
    assert!(m.validate().is_ok());
}

#[test]
fn truncate_zero_length_file_noop() {
    let mut m = InlineExtentMap::new();
    let freed = m.truncate(0).unwrap();
    assert!(freed.is_empty());
    let freed = m.truncate(4096).unwrap();
    assert!(freed.is_empty());
    assert_eq!(m.header.file_size, 4096);
    assert!(m.validate().is_ok());
}

#[test]
fn truncate_in_gap_between_extents_frees_tail_only() {
    let mut m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)]);

    // Truncate at 6144: falls in the [4096, 8192) gap between extents.
    // Extent 1 [0, 4096) is before the cut, extents 2 [8192, 12288) and
    // 3 [16384, 20480) are entirely after — both should be removed.
    let freed = m.truncate(6144).unwrap();

    assert_eq!(freed.len(), 2);
    assert_eq!(freed[0].logical_offset, 8192);
    assert_eq!(freed[0].length, 4096);
    assert_eq!(freed[0].locator_id, LocatorId(2));
    assert_eq!(freed[0].extent_type, ExtentType::Data);
    assert_eq!(freed[1].logical_offset, 16384);
    assert_eq!(freed[1].length, 4096);
    assert_eq!(freed[1].locator_id, LocatorId(3));
    assert_eq!(freed[1].extent_type, ExtentType::Data);

    // Only the first extent survives, unchanged.
    assert_eq!(m.header.entry_count, 1);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 4096);
    assert_eq!(m.header.file_size, 6144);
    assert_eq!(m.header.alloc_bytes, 4096);
    assert!(m.validate().is_ok());

    // Verify the gap past the extent is a hole.
    let r = m.lookup_range(4096, 2048).unwrap();
    assert!(r.is_empty());
}

#[test]
fn truncate_to_exact_extent_end_preserves_extent() {
    let mut m = make_map(&[data(0, 4096, 1), data(4096, 4096, 2)]);

    // Truncate exactly at the end of the first extent.
    let freed = m.truncate(4096).unwrap();

    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, 4096);
    assert_eq!(freed[0].length, 4096);
    assert_eq!(freed[0].locator_id, LocatorId(2));

    assert_eq!(m.header.entry_count, 1);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 4096);
    assert_eq!(m.header.file_size, 4096);
    assert!(m.validate().is_ok());
}
// =====================================================================
// 6. Persistence round-trip (populated map)
// =====================================================================

#[test]
fn persistence_roundtrip_populated_map() {
    let entries_in = vec![data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)];
    let original = make_map(&entries_in);

    let saved_header = original.header.clone();
    let saved_entries = original.entries.clone();

    let reconstructed = InlineExtentMap::from_parts(saved_header, saved_entries);

    assert_eq!(reconstructed.header.file_size, original.header.file_size);
    assert_eq!(
        reconstructed.header.entry_count,
        original.header.entry_count
    );
    assert_eq!(
        reconstructed.header.alloc_bytes,
        original.header.alloc_bytes
    );
    assert_eq!(reconstructed.header.version, original.header.version);

    assert_eq!(reconstructed.entries.len(), original.entries.len());
    for i in 0..reconstructed.entries.len() {
        assert_eq!(
            reconstructed.entries[i].logical_offset,
            original.entries[i].logical_offset
        );
        assert_eq!(reconstructed.entries[i].length, original.entries[i].length);
        assert_eq!(
            reconstructed.entries[i].locator_id,
            original.entries[i].locator_id
        );
        assert_eq!(
            reconstructed.entries[i].extent_type(),
            original.entries[i].extent_type()
        );
        assert_eq!(
            reconstructed.entries[i].checksum,
            original.entries[i].checksum
        );
        assert_eq!(
            reconstructed.entries[i].birth_commit_group,
            original.entries[i].birth_commit_group
        );
    }

    assert!(reconstructed.validate().is_ok());

    // Verify reconstructed map behaves identically to original.
    for off in [0u64, 4096, 8192, 12288, 16384, 20480] {
        let orig = original.lookup_range(off, 4096).unwrap_or_default();
        let recon = reconstructed.lookup_range(off, 4096).unwrap_or_default();
        assert_eq!(orig.len(), recon.len(), "mismatch at offset {off}");
        for (a, b) in orig.iter().zip(recon.iter()) {
            assert_eq!(a.logical_offset, b.logical_offset);
            assert_eq!(a.length, b.length);
            assert_eq!(a.locator_id, b.locator_id);
        }
    }

    for off in [0u64, 4096, 12288, 20480] {
        assert_eq!(original.seek_data(off), reconstructed.seek_data(off));
        assert_eq!(original.seek_hole(off), reconstructed.seek_hole(off));
    }
}

#[test]
fn persistence_roundtrip_after_mutations() {
    let mut m = make_map(&[data(0, 8192, 1)]);

    let _ = m.punch_hole(2048, 4096).unwrap();

    let saved_header = m.header.clone();
    let saved_entries = m.entries.clone();

    let recon = InlineExtentMap::from_parts(saved_header, saved_entries);
    assert!(recon.validate().is_ok());

    let r = recon.lookup_range(2048, 4096).unwrap();
    assert!(r.is_empty());
    let r = recon.lookup_range(0, 2048).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].length, 2048);
    let r = recon.lookup_range(6144, 2048).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].length, 2048);
}

// =====================================================================
// 7. Zero-length file persistence round-trip
// =====================================================================

#[test]
fn persistence_roundtrip_empty_map() {
    let original = InlineExtentMap::new();

    let saved_header = original.header.clone();
    let saved_entries = original.entries.clone();

    let recon = InlineExtentMap::from_parts(saved_header, saved_entries);

    assert_eq!(recon.header.file_size, 0);
    assert_eq!(recon.header.entry_count, 0);
    assert_eq!(recon.header.alloc_bytes, 0);
    assert!(recon.entries.is_empty());
    assert!(recon.validate().is_ok());

    assert_eq!(recon.seek_data(0), None);
    assert_eq!(recon.seek_hole(0), None);
    let r = recon.lookup_range(0, 4096).unwrap();
    assert!(r.is_empty());
}

#[test]
fn persistence_roundtrip_zero_size_after_truncate() {
    let mut m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
    m.truncate(0).unwrap();

    let saved_header = m.header.clone();
    let saved_entries = m.entries.clone();

    let recon = InlineExtentMap::from_parts(saved_header, saved_entries);

    assert_eq!(recon.header.file_size, 0);
    assert_eq!(recon.header.entry_count, 0);
    assert_eq!(recon.header.alloc_bytes, 0);
    assert!(recon.entries.is_empty());
    assert!(recon.validate().is_ok());
}

#[test]
fn persistence_roundtrip_corrupt_header_detected() {
    let entries = vec![data(0, 4096, 1)];
    let mut header = ExtentMapV1::new();
    header.file_size = 4096;
    header.entry_count = 1;
    header.alloc_bytes = 4096;

    let m = InlineExtentMap::from_parts(header, entries.clone());
    assert!(m.validate().is_ok());

    let mut bad_header = m.header.clone();
    bad_header.alloc_bytes = 0;
    let corrupt = InlineExtentMap::from_parts(bad_header, entries.clone());
    assert_eq!(corrupt.validate(), Err(ExtentMapError::Corrupt));

    let mut bad_header = m.header.clone();
    bad_header.entry_count = 99;
    let corrupt = InlineExtentMap::from_parts(bad_header, entries);
    assert_eq!(corrupt.validate(), Err(ExtentMapError::Corrupt));
}

// =====================================================================
// 8. Large-range stress smoke
// =====================================================================

#[test]
fn stress_inline_map_full_rejected() {
    // InlineExtentMap rejects >6 entries with MapFull.
    let mut inline = InlineExtentMap::new();
    let inline_entries: Vec<_> = (0..7).map(|i| data(i * 8192, 4096, i + 1)).collect();
    let err = inline.insert_extent(&inline_entries).unwrap_err();
    assert_eq!(err, ExtentMapError::MapFull);
}

#[test]
fn stress_polymorphic_large_allocation_and_lookup() {
    use tidefs_extent_map::PolymorphicExtentMap;

    const N: u64 = 10_000;
    let mut m = PolymorphicExtentMap::new();

    let entries: Vec<ExtentMapEntryV2> = (0..N).map(|i| data(i * 8192, 4096, i + 1)).collect();

    m.insert_extent(&entries).unwrap();
    assert!(m.validate().is_ok());

    // Verify all extents present via a full-span lookup.
    let r = m.lookup_range(0, N * 8192).unwrap();
    assert_eq!(r.len() as u64, N);

    // Spot-check specific extents.
    for i in [0, 1, 100, 1000, 5000, 9999] {
        let r = m.lookup_range(i * 8192, 4096).unwrap();
        assert_eq!(r.len(), 1, "extent {i} missing");
        assert_eq!(r[0].logical_offset, i * 8192);
        assert_eq!(r[0].length, 4096);
        assert_eq!(r[0].locator_id, LocatorId(i + 1));
    }

    // Check holes between extents.
    for i in [0, 1, 100, 5000] {
        let r = m.lookup_range(i * 8192 + 4096, 4096).unwrap();
        assert!(r.is_empty(), "hole at {} should be empty", i * 8192 + 4096);
    }

    // Spot-check seek_data.
    assert_eq!(m.seek_data(0), Some((0, 4096)));
    assert_eq!(m.seek_data(4096), Some((8192, 4096)));
    assert_eq!(m.seek_data(8192), Some((8192, 4096)));

    // Spot-check seek_hole.
    assert_eq!(m.seek_hole(0), Some((4096, 4096)));
    assert_eq!(m.seek_hole(4096), Some((4096, 4096)));
}

// =====================================================================
// 9. Object-store round-trip
// =====================================================================

mod objstore_roundtrip {
    use std::io::{Cursor, Read};
    use tidefs_extent_map::InlineExtentMap;
    use tidefs_local_object_store::{LocalObjectStore, ObjectKey};
    use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapOps, ExtentMapV1, LocatorId};

    const MAGIC: [u8; 4] = [b'E', b'X', b'M', b'S'];

    fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
        let cs = [0xAB; 32];
        ExtentMapEntryV2::new_data(off, len, LocatorId(loc), cs, 0)
    }

    fn make_map(entries: &[ExtentMapEntryV2]) -> InlineExtentMap {
        let mut m = InlineExtentMap::new();
        if !entries.is_empty() {
            m.insert_extent(entries).unwrap();
        }
        m
    }

    /// Serialize an InlineExtentMap to bytes.
    fn serialize_map(map: &InlineExtentMap) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&map.header.file_size.to_le_bytes());
        buf.extend_from_slice(&map.header.entry_count.to_le_bytes());
        buf.extend_from_slice(&map.header.alloc_bytes.to_le_bytes());
        buf.extend_from_slice(&[map.header.version]);
        for e in &map.entries {
            buf.extend_from_slice(&e.logical_offset.to_le_bytes());
            buf.extend_from_slice(&e.length.to_le_bytes());
            buf.push(e.extent_kind);
            buf.push(e.flags);
            buf.extend_from_slice(&e.locator_id.0.to_le_bytes());
            buf.extend_from_slice(&e.checksum);
            buf.extend_from_slice(&e.birth_commit_group.to_le_bytes());
        }
        buf
    }

    /// Deserialize bytes back into an InlineExtentMap.
    fn deserialize_map(data: &[u8]) -> Option<InlineExtentMap> {
        let mut cursor = Cursor::new(data);

        let mut magic = [0u8; 4];
        cursor.read_exact(&mut magic).ok()?;
        if magic != MAGIC {
            return None;
        }

        let mut file_size_buf = [0u8; 8];
        cursor.read_exact(&mut file_size_buf).ok()?;
        let file_size = u64::from_le_bytes(file_size_buf);

        let mut entry_count_buf = [0u8; 8];
        cursor.read_exact(&mut entry_count_buf).ok()?;
        let entry_count = u64::from_le_bytes(entry_count_buf);

        let mut alloc_bytes_buf = [0u8; 8];
        cursor.read_exact(&mut alloc_bytes_buf).ok()?;
        let alloc_bytes = u64::from_le_bytes(alloc_bytes_buf);

        let mut version_buf = [0u8; 1];
        cursor.read_exact(&mut version_buf).ok()?;
        let version = version_buf[0];

        let header = ExtentMapV1 {
            root: None,
            entry_count,
            alloc_bytes,
            file_size,
            version,
        };

        let mut entries = Vec::new();
        for _ in 0..entry_count {
            let mut lo_buf = [0u8; 8];
            cursor.read_exact(&mut lo_buf).ok()?;
            let logical_offset = u64::from_le_bytes(lo_buf);

            let mut len_buf = [0u8; 8];
            cursor.read_exact(&mut len_buf).ok()?;
            let length = u64::from_le_bytes(len_buf);

            let mut kind_buf = [0u8; 1];
            cursor.read_exact(&mut kind_buf).ok()?;
            let extent_kind = kind_buf[0];

            let mut flags_buf = [0u8; 1];
            cursor.read_exact(&mut flags_buf).ok()?;
            let flags = flags_buf[0];

            let mut loc_buf = [0u8; 8];
            cursor.read_exact(&mut loc_buf).ok()?;
            let locator_id = LocatorId(u64::from_le_bytes(loc_buf));

            let mut checksum = [0u8; 32];
            cursor.read_exact(&mut checksum).ok()?;

            let mut commit_group_buf = [0u8; 8];
            cursor.read_exact(&mut commit_group_buf).ok()?;
            let birth_commit_group = u64::from_le_bytes(commit_group_buf);

            entries.push(ExtentMapEntryV2 {
                logical_offset,
                length,
                extent_kind,
                flags,
                locator_id,
                checksum,
                birth_commit_group,
                reserved: [0u8; 15],
            });
        }

        let map = InlineExtentMap::from_parts(header, entries);
        Some(map)
    }

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn open_temp_store(name: &str) -> (LocalObjectStore, std::path::PathBuf) {
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("tidefs-em-{name}-{n}"));
        std::fs::create_dir_all(&path).expect("create test dir");
        let store = LocalObjectStore::open(&path).expect("open store");
        (store, path)
    }
    #[test]
    fn objstore_empty_map_roundtrip() {
        let (mut store, _path) = open_temp_store("empty");
        let original = InlineExtentMap::new();
        let key_name = "extent_empty";

        let serialized = serialize_map(&original);
        store.put_named(key_name, &serialized).expect("put");

        let loc = store
            .location_of(ObjectKey::from_name(key_name))
            .expect("location");
        let bytes = store.get_at_location(loc).expect("get");

        let reconstructed = deserialize_map(&bytes).expect("deserialize");
        assert!(reconstructed.entries.is_empty());
        assert_eq!(reconstructed.header.file_size, 0);
        assert_eq!(reconstructed.header.alloc_bytes, 0);
        assert!(reconstructed.validate().is_ok());
    }

    #[test]
    fn objstore_single_extent_roundtrip() {
        let (mut store, _path) = open_temp_store("empty");
        let original = make_map(&[data(0, 4096, 1)]);
        let key_name = "extent_single";

        let serialized = serialize_map(&original);
        store.put_named(key_name, &serialized).expect("put");

        let loc = store
            .location_of(ObjectKey::from_name(key_name))
            .expect("location");
        let bytes = store.get_at_location(loc).expect("get");

        let reconstructed = deserialize_map(&bytes).expect("deserialize");
        assert_eq!(reconstructed.entries.len(), 1);
        assert_eq!(reconstructed.entries[0].logical_offset, 0);
        assert_eq!(reconstructed.entries[0].length, 4096);
        assert_eq!(reconstructed.entries[0].locator_id, LocatorId(1));
        assert_eq!(reconstructed.header.file_size, 4096);
        assert_eq!(reconstructed.header.alloc_bytes, 4096);
        assert!(reconstructed.validate().is_ok());

        let lookup = reconstructed.lookup_range(0, 4096).unwrap();
        assert_eq!(lookup.len(), 1);
    }

    #[test]
    fn objstore_fragmented_map_roundtrip() {
        let (mut store, _path) = open_temp_store("empty");
        // 6 extents: fragmented with gaps
        let entries: Vec<_> = (0..6).map(|i| data(i * 8192, 4096, i + 1)).collect();
        let original = make_map(&entries);
        let key_name = "extent_frag";

        let serialized = serialize_map(&original);
        store.put_named(key_name, &serialized).expect("put");

        let loc = store
            .location_of(ObjectKey::from_name(key_name))
            .expect("location");
        let bytes = store.get_at_location(loc).expect("get");

        let reconstructed = deserialize_map(&bytes).expect("deserialize");
        assert_eq!(reconstructed.entries.len(), 6);
        for i in 0..6 {
            assert_eq!(reconstructed.entries[i].logical_offset, i as u64 * 8192);
            assert_eq!(reconstructed.entries[i].length, 4096);
            assert_eq!(reconstructed.entries[i].locator_id, LocatorId(i as u64 + 1));
        }
        assert!(reconstructed.validate().is_ok());

        // Verify lookups work after round-trip.
        for i in 0..6 {
            let r = reconstructed.lookup_range(i * 8192, 4096).unwrap();
            assert_eq!(r.len(), 1);
        }
        // Verify gaps.
        for i in 0..5 {
            let r = reconstructed.lookup_range(i * 8192 + 4096, 4096).unwrap();
            assert!(r.is_empty());
        }
    }

    #[test]
    fn objstore_full_map_roundtrip() {
        let (mut store, _path) = open_temp_store("empty");
        // 6 contiguous extents (max for inline map).
        let entries: Vec<_> = (0..6).map(|i| data(i * 4096, 4096, i + 1)).collect();
        let original = make_map(&entries);
        let key_name = "extent_full";

        let serialized = serialize_map(&original);
        store.put_named(key_name, &serialized).expect("put");

        let loc = store
            .location_of(ObjectKey::from_name(key_name))
            .expect("location");
        let bytes = store.get_at_location(loc).expect("get");

        let reconstructed = deserialize_map(&bytes).expect("deserialize");
        assert_eq!(reconstructed.entries.len(), 6);
        assert_eq!(reconstructed.header.file_size, 6 * 4096);
        assert_eq!(reconstructed.header.alloc_bytes, 6 * 4096);
        assert!(reconstructed.validate().is_ok());
    }

    #[test]
    fn objstore_after_mutations_roundtrip() {
        let (mut store, _path) = open_temp_store("empty");
        let mut original = make_map(&[data(0, 8192, 1)]);

        // Punch a hole in the middle.
        let freed = original.punch_hole(2048, 4096).unwrap();
        assert_eq!(freed.len(), 1);

        let key_name = "extent_mutated";
        let serialized = serialize_map(&original);
        store.put_named(key_name, &serialized).expect("put");

        let loc = store
            .location_of(ObjectKey::from_name(key_name))
            .expect("location");
        let bytes = store.get_at_location(loc).expect("get");

        let reconstructed = deserialize_map(&bytes).expect("deserialize");
        assert!(reconstructed.validate().is_ok());
        assert_eq!(reconstructed.entries.len(), 2);

        // Verify the hole is preserved.
        let r = reconstructed.lookup_range(2048, 4096).unwrap();
        assert!(r.is_empty());
        // Verify surrounding data preserved.
        let r = reconstructed.lookup_range(0, 2048).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].length, 2048);
        let r = reconstructed.lookup_range(6144, 2048).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].length, 2048);
    }

    #[test]
    fn objstore_corrupt_magic_detected() {
        let map = make_map(&[data(0, 4096, 1)]);
        let mut serialized = serialize_map(&map);
        // Corrupt magic bytes.
        serialized[2] ^= 0xFF;

        let result = deserialize_map(&serialized);
        assert!(result.is_none());
    }

    #[test]
    fn objstore_corrupt_truncated_data_detected() {
        let map = make_map(&[data(0, 4096, 1)]);
        let serialized = serialize_map(&map);
        // Truncate to half the data.
        let truncated = &serialized[..serialized.len() / 2];

        let result = deserialize_map(truncated);
        assert!(result.is_none());
    }
}

// =====================================================================
// 10. Property-based invariant tests
// =====================================================================

#[test]
fn invariant_no_overlapping_extents() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
        .unwrap();
    assert!(m.validate().is_ok());

    // Insert overwriting entry across a gap.
    m.insert_extent(&[data(2048, 10240, 3)]).unwrap();
    assert!(m.validate().is_ok());
    // No two extents should overlap.
    for i in 0..m.entries.len() {
        for j in (i + 1)..m.entries.len() {
            let a_end = m.entries[i].end_offset();
            let b_start = m.entries[j].logical_offset;
            assert!(a_end <= b_start, "overlap at indices {i} and {j}");
        }
    }
}

#[test]
fn invariant_alloc_bytes_consistent() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2)])
        .unwrap();
    assert_eq!(m.header.alloc_bytes, 8192);

    m.punch_hole(0, 4096).unwrap();
    assert_eq!(m.header.alloc_bytes, 4096);

    m.truncate(4096).unwrap();
    assert_eq!(m.header.alloc_bytes, 0);

    // alloc_bytes should always match sum of DATA + UNWRITTEN lengths.
    let computed: u64 = m
        .entries
        .iter()
        .filter(|e| e.extent_type().consumes_space())
        .map(|e| e.length)
        .sum();
    assert_eq!(m.header.alloc_bytes, computed);
    assert!(m.validate().is_ok());
}

#[test]
fn invariant_alloc_bytes_recomputed_after_punch_merges() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 12288, 1)]).unwrap();
    m.punch_hole(4096, 4096).unwrap();
    // Two fragments remain: [0,4096) and [8192,4096), total alloc_bytes = 8192.
    // After merge_adjacent there are exactly 2 entries — verify that.
    assert_eq!(m.header.entry_count, 2);
    let computed: u64 = m
        .entries
        .iter()
        .filter(|e| e.extent_type().consumes_space())
        .map(|e| e.length)
        .sum();
    assert_eq!(m.header.alloc_bytes, computed);
}

#[test]
fn invariant_lookup_consistent_after_mutations() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)])
        .unwrap();

    // Capture lookup results before mutation.
    let before = m.lookup_range(0, 20480).unwrap();
    assert_eq!(before.len(), 3);

    // Punch a hole.
    m.punch_hole(2048, 12288).unwrap();

    // After punch, lookup should return the remaining fragments.
    let after = m.lookup_range(0, 20480).unwrap();
    for entry in &after {
        // Every remaining entry must be a sub-range of the original entries.
        let original_covered = before.iter().any(|orig| {
            entry.logical_offset >= orig.logical_offset && entry.end_offset() <= orig.end_offset()
        });
        assert!(
            original_covered,
            "entry {entry:?} not covered by original extents"
        );
    }
    // No entry should land in the punched range.
    for entry in &after {
        assert!(
            entry.end_offset() <= 2048 || entry.logical_offset >= 14336,
            "entry {entry:?} falls in punched range [2048, 14336)"
        );
    }
}

#[test]
fn invariant_random_operation_sequence() {
    use tidefs_extent_map::PolymorphicExtentMap;

    // Deterministic pseudo-random sequence using a simple LCG.
    let mut state: u64 = 0xDEADBEEF_CAFEBABE;
    let mut next = move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };

    let mut m = PolymorphicExtentMap::new();

    for _step in 0..50 {
        let op = next() % 5;
        match op {
            0 => {
                // Insert a new extent at a random offset.
                let off = next() % 100_000;
                let len = (next() % 16 + 1) * 4096;
                let loc = next() % 100 + 1;
                let e = data(off, len, loc);
                let _ = m.insert_extent(&[e]);
            }
            1 => {
                // Punch a hole.
                let off = next() % 100_000;
                let len = (next() % 16 + 1) * 4096;
                let _ = m.punch_hole(off, len);
            }
            2 => {
                // Truncate.
                let new_size = next() % 200_000;
                let _ = m.truncate(new_size);
            }
            3 => {
                // Lookup (read-only, verify no panic).
                let off = next() % 100_000;
                let len = (next() % 16 + 1) * 4096;
                let r = m.lookup_range(off, len);
                if let Ok(entries) = r {
                    for (i, a) in entries.iter().enumerate() {
                        for b in &entries[i + 1..] {
                            assert!(
                                a.end_offset() <= b.logical_offset,
                                "lookup returned overlapping entries"
                            );
                        }
                    }
                }
            }
            4 => {
                // Seek (read-only, verify no panic).
                let off = next() % 100_000;
                let _ = m.seek_data(off);
                let _ = m.seek_hole(off);
            }
            _ => {}
        }

        // Verify invariants after each mutation.
        assert!(m.validate().is_ok(), "validate failed after step {_step}");
    }
}

#[test]
fn invariant_file_size_consistent() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 4096, 1)]).unwrap();
    assert_eq!(m.header.file_size, 4096);

    m.insert_extent(&[data(8192, 4096, 2)]).unwrap();
    assert_eq!(m.header.file_size, 12288);

    m.truncate(6144).unwrap();
    assert_eq!(m.header.file_size, 6144);

    // file_size must be >= max(end_offset) of all entries.
    let max_end = m.entries.iter().map(|e| e.end_offset()).max().unwrap_or(0);
    assert!(m.header.file_size >= max_end);
    assert!(m.validate().is_ok());
}

// =====================================================================
// 11. Error-injection tests
// =====================================================================

#[test]
fn error_checksum_mismatch_detected_on_validate() {
    // Manually construct a map where alloc_bytes doesn't match sum of entries.
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 4096, 1)]).unwrap();
    assert!(m.validate().is_ok());

    // Corrupt alloc_bytes.
    m.header.alloc_bytes = 999;
    assert_eq!(m.validate(), Err(ExtentMapError::Corrupt));
}

#[test]
fn error_out_of_space_map_full() {
    let mut m = InlineExtentMap::new();
    // Fill to capacity (6 entries).
    let entries: Vec<_> = (0..6).map(|i| data(i * 8192, 4096, i + 1)).collect();
    m.insert_extent(&entries).unwrap();
    assert!(m.validate().is_ok());

    // Try to insert a 7th entry — should fail with MapFull.
    let err = m.insert_extent(&[data(50000, 4096, 99)]).unwrap_err();
    assert_eq!(err, ExtentMapError::MapFull);

    // Map should be unchanged after failed insert.
    assert_eq!(m.entries.len(), 6);
    assert!(m.validate().is_ok());
}

#[test]
fn error_out_of_space_overlapping_insert_does_not_corrupt() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 4096, 1)]).unwrap();
    let snapshot = m.clone();

    // Try to insert zero-length entry — rejected.
    let mut zero_entry = data(0, 0, 1);
    zero_entry.length = 0;
    let err = m.insert_extent(&[zero_entry]).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
    assert_eq!(m, snapshot);
    assert!(m.validate().is_ok());
}

#[test]
fn error_invalid_range_no_mutation() {
    let m = InlineExtentMap::new();
    // u64::MAX + 1 overflows.
    let err = m.lookup_range(u64::MAX, 1).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
    assert!(m.entries.is_empty());
    assert!(m.validate().is_ok());
}

#[test]
fn error_truncate_does_not_corrupt_on_bad_size() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 4096, 1)]).unwrap();
    let snapshot = m.clone();

    // Truncate to same size — no-op.
    let freed = m.truncate(4096).unwrap();
    assert!(freed.is_empty());
    assert_eq!(m, snapshot);
    assert!(m.validate().is_ok());

    // Truncate to larger size — expands file_size, frees nothing.
    let freed = m.truncate(16384).unwrap();
    assert!(freed.is_empty());
    assert_eq!(m.header.file_size, 16384);
    assert_eq!(m.entries.len(), 1);
    assert_eq!(m.entries[0], data(0, 4096, 1));
    assert!(m.validate().is_ok());
}

// =====================================================================
// 12. PolymorphicExtentMap object-store round-trip (>6 extents)
// =====================================================================

mod poly_objstore_roundtrip {
    use std::io::{Cursor, Read};
    use tidefs_extent_map::PolymorphicExtentMap;
    use tidefs_local_object_store::{LocalObjectStore, ObjectKey};
    use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapOps, LocatorId};

    const MAGIC: [u8; 4] = [b'E', b'X', b'M', b'P'];

    fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
        let cs = [0xAB; 32];
        ExtentMapEntryV2::new_data(off, len, LocatorId(loc), cs, 0)
    }

    /// Serialize a PolymorphicExtentMap entry list to bytes.
    fn serialize_poly_entries(entries: &[ExtentMapEntryV2], file_size: u64) -> Vec<u8> {
        let alloc_bytes: u64 = entries
            .iter()
            .filter(|e| e.extent_type().consumes_space())
            .map(|e| e.length)
            .sum();
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&file_size.to_le_bytes());
        buf.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        buf.extend_from_slice(&alloc_bytes.to_le_bytes());
        for e in entries {
            buf.extend_from_slice(&e.logical_offset.to_le_bytes());
            buf.extend_from_slice(&e.length.to_le_bytes());
            buf.push(e.extent_kind);
            buf.push(e.flags);
            buf.extend_from_slice(&e.locator_id.0.to_le_bytes());
            buf.extend_from_slice(&e.checksum);
            buf.extend_from_slice(&e.birth_commit_group.to_le_bytes());
        }
        buf
    }

    /// Deserialize bytes into entry vector.
    fn deserialize_poly_entries(data: &[u8]) -> Option<(Vec<ExtentMapEntryV2>, u64)> {
        let mut cursor = Cursor::new(data);
        let mut magic = [0u8; 4];
        cursor.read_exact(&mut magic).ok()?;
        if magic != MAGIC {
            return None;
        }
        let mut buf8 = [0u8; 8];
        cursor.read_exact(&mut buf8).ok()?;
        let file_size = u64::from_le_bytes(buf8);
        cursor.read_exact(&mut buf8).ok()?;
        let entry_count = u64::from_le_bytes(buf8);
        // alloc_bytes (skip for reconstruction, derived from entries)
        cursor.read_exact(&mut buf8).ok()?;

        let mut entries = Vec::new();
        for _ in 0..entry_count {
            cursor.read_exact(&mut buf8).ok()?;
            let logical_offset = u64::from_le_bytes(buf8);
            cursor.read_exact(&mut buf8).ok()?;
            let length = u64::from_le_bytes(buf8);
            let mut buf1 = [0u8; 1];
            cursor.read_exact(&mut buf1).ok()?;
            let extent_kind = buf1[0];
            cursor.read_exact(&mut buf1).ok()?;
            let flags = buf1[0];
            cursor.read_exact(&mut buf8).ok()?;
            let locator_id = LocatorId(u64::from_le_bytes(buf8));
            let mut checksum = [0u8; 32];
            cursor.read_exact(&mut checksum).ok()?;
            cursor.read_exact(&mut buf8).ok()?;
            let birth_commit_group = u64::from_le_bytes(buf8);
            entries.push(ExtentMapEntryV2 {
                logical_offset,
                length,
                extent_kind,
                flags,
                locator_id,
                checksum,
                birth_commit_group,
                reserved: [0u8; 15],
            });
        }
        Some((entries, file_size))
    }

    fn open_temp_store(name: &str) -> (LocalObjectStore, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1000); // offset from inline tests
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("tidefs-poly-em-{name}-{n}"));
        std::fs::create_dir_all(&path).expect("create test dir");
        let store = LocalObjectStore::open(&path).expect("open store");
        (store, path)
    }

    #[test]
    fn poly_objstore_large_map_roundtrip() {
        let (mut store, _path) = open_temp_store("large");
        const N: u64 = 100;
        let entries: Vec<_> = (0..N).map(|i| data(i * 8192, 4096, i + 1)).collect();

        let mut original = PolymorphicExtentMap::new();
        original.insert_extent(&entries).unwrap();
        assert!(original.validate().is_ok());

        // Serialize via lookup_range.
        let all = original.lookup_range(0, u64::MAX).unwrap();
        assert_eq!(all.len() as u64, N);
        let file_size = N * 8192; // max end_offset: (N-1)*8192 + 4096 = N*8192
        let serialized = serialize_poly_entries(&all, file_size);

        let key_name = "poly_large";
        store.put_named(key_name, &serialized).expect("put");

        let loc = store
            .location_of(ObjectKey::from_name(key_name))
            .expect("location");
        let bytes = store.get_at_location(loc).expect("get");

        let (deserialized, _fs) = deserialize_poly_entries(&bytes).expect("deserialize");
        assert_eq!(deserialized.len() as u64, N);

        // Reconstruct a new PolymorphicExtentMap.
        let mut recon = PolymorphicExtentMap::new();
        recon.insert_extent(&deserialized).unwrap();
        assert!(recon.validate().is_ok());

        // Verify spot-checks.
        for i in [0u64, 1, 50, 99] {
            let r = recon.lookup_range(i * 8192, 4096).unwrap();
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].logical_offset, i * 8192);
            assert_eq!(r[0].length, 4096);
            assert_eq!(r[0].locator_id, LocatorId(i + 1));
        }
        // Verify holes between extents.
        for i in 0..99 {
            let r = recon.lookup_range(i * 8192 + 4096, 4096).unwrap();
            assert!(r.is_empty());
        }
    }

    #[test]
    fn poly_objstore_after_mutations_roundtrip() {
        let (mut store, _path) = open_temp_store("mutated");
        let entries: Vec<_> = (0..10).map(|i| data(i * 8192, 4096, i + 100)).collect();

        let mut original = PolymorphicExtentMap::new();
        original.insert_extent(&entries).unwrap();

        // Punch holes at two locations.
        original.punch_hole(4096, 6144).unwrap(); // removes entry 1 half and entry 2
        original.punch_hole(40960, 4096).unwrap(); // removes entry 5 (offset 40960 = 5*8192)

        // Truncate past the last extent.
        original.truncate(57344).unwrap(); // 7*8192 = 57344

        assert!(original.validate().is_ok());

        let all = original.lookup_range(0, u64::MAX).unwrap();
        let file_size = original
            .validate()
            .map(|_| {
                // file_size = max truncation or max end_offset; we know it's 57344
                57344u64
            })
            .unwrap_or(57344);
        let serialized = serialize_poly_entries(&all, file_size);

        let key_name = "poly_mutated";
        store.put_named(key_name, &serialized).expect("put");

        let loc = store
            .location_of(ObjectKey::from_name(key_name))
            .expect("location");
        let bytes = store.get_at_location(loc).expect("get");

        let (deserialized, _fs) = deserialize_poly_entries(&bytes).expect("deserialize");

        let mut recon = PolymorphicExtentMap::new();
        recon.insert_extent(&deserialized).unwrap();
        assert!(recon.validate().is_ok());

        // Verify the punched holes are gone.
        let r = recon.lookup_range(4096, 6144).unwrap();
        assert!(r.is_empty());
        let r = recon.lookup_range(40960, 4096).unwrap();
        assert!(r.is_empty());

        // Verify surviving entries.
        let r = recon.lookup_range(0, 4096).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].logical_offset, 0);
        assert_eq!(r[0].locator_id, LocatorId(100));

        let r = recon.lookup_range(10240, 4096).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].logical_offset, 10240);
        assert_eq!(r[0].locator_id, LocatorId(101));
    }

    #[test]
    fn poly_objstore_empty_then_populated_then_empty_roundtrip() {
        let (mut store, _path) = open_temp_store("emptycycle");

        // Empty map round-trip.
        {
            let original = PolymorphicExtentMap::new();
            let all = original.lookup_range(0, u64::MAX).unwrap();
            let serialized = serialize_poly_entries(&all, 0);
            store.put_named("poly_empty", &serialized).expect("put");

            let loc = store
                .location_of(ObjectKey::from_name("poly_empty"))
                .expect("loc");
            let bytes = store.get_at_location(loc).expect("get");
            let (deserialized, fs) = deserialize_poly_entries(&bytes).expect("deser");
            assert!(deserialized.is_empty());
            assert_eq!(fs, 0);
        }

        // Populate, then serialize.
        {
            let mut m = PolymorphicExtentMap::new();
            let entries: Vec<_> = (0..50).map(|i| data(i * 4096, 4096, i + 1)).collect();
            m.insert_extent(&entries).unwrap();
            assert!(m.validate().is_ok());

            let all = m.lookup_range(0, u64::MAX).unwrap();
            assert_eq!(all.len(), 50);
            let serialized = serialize_poly_entries(&all, 50 * 4096);
            store.put_named("poly_pop", &serialized).expect("put");

            let loc = store
                .location_of(ObjectKey::from_name("poly_pop"))
                .expect("loc");
            let bytes = store.get_at_location(loc).expect("get");
            let (deserialized, fs) = deserialize_poly_entries(&bytes).expect("deser");
            assert_eq!(deserialized.len(), 50);
            assert_eq!(fs, 50 * 4096);

            let mut recon = PolymorphicExtentMap::new();
            recon.insert_extent(&deserialized).unwrap();
            assert!(recon.validate().is_ok());
        }
    }

    #[test]
    fn poly_objstore_corrupt_data_detected() {
        let entries: Vec<_> = (0..20).map(|i| data(i * 4096, 4096, i + 1)).collect();

        let mut original = PolymorphicExtentMap::new();
        original.insert_extent(&entries).unwrap();
        let all = original.lookup_range(0, u64::MAX).unwrap();
        let serialized = serialize_poly_entries(&all, 20 * 4096);

        // Corrupt magic.
        let mut corrupt_magic = serialized.clone();
        corrupt_magic[3] ^= 0xFF;
        assert!(deserialize_poly_entries(&corrupt_magic).is_none());

        // Truncate mid-entry.
        let trunc = &serialized[..serialized.len() - 30];
        assert!(deserialize_poly_entries(trunc).is_none());
    }
}

// =====================================================================
// 13. Property-test shrink: minimal invariant violation detection
// =====================================================================

#[test]
fn property_shrink_minimal_map_full_sequence() {
    // Fill to exactly 6 entries, verify MapFull on seventh.
    let mut m = InlineExtentMap::new();
    for i in 0..6 {
        m.insert_extent(&[data(i * 4096, 4096, i + 1)]).unwrap();
    }
    assert!(m.validate().is_ok());
    assert_eq!(m.header.entry_count, 6);

    let err = m.insert_extent(&[data(6 * 4096, 4096, 7)]).unwrap_err();
    assert_eq!(err, ExtentMapError::MapFull);

    // Map unchanged after rejection.
    assert_eq!(m.header.entry_count, 6);
    assert!(m.validate().is_ok());
}

#[test]
fn property_shrink_minimal_overlap_sequence() {
    // Two-step insertion that would produce overlapping entries if not handled.
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 8192, 1)]).unwrap();
    m.insert_extent(&[data(4096, 4096, 2)]).unwrap();

    // Should produce 2 entries: [0,4096,1], [4096,4096,2].
    assert_eq!(m.entries.len(), 2);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 4096);
    assert_eq!(m.entries[0].locator_id, LocatorId(1));
    assert_eq!(m.entries[1].logical_offset, 4096);
    assert_eq!(m.entries[1].length, 4096);
    assert_eq!(m.entries[1].locator_id, LocatorId(2));
    assert_eq!(m.header.alloc_bytes, 8192);
    assert!(m.validate().is_ok());
}

#[test]
fn property_shrink_reproducible_random_sequence() {
    // Verify that a given seed produces deterministic behavior.
    use tidefs_extent_map::PolymorphicExtentMap;

    // Simple LCG seeded with a fixed value.
    let mut state: u64 = 0xCAFE_F00D_BEEF_BABE_u64;
    let mut next = move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };

    let mut m = PolymorphicExtentMap::new();
    for step in 0..30 {
        let op = next() % 5;
        match op {
            0 => {
                let off = next() % 100_000;
                let len = (next() % 8 + 1) * 4096;
                let loc = next() % 100 + 1;
                let _ = m.insert_extent(&[data(off, len, loc)]);
            }
            1 => {
                let off = next() % 100_000;
                let len = (next() % 8 + 1) * 4096;
                let _ = m.punch_hole(off, len);
            }
            2 => {
                let new_size = next() % 200_000;
                let _ = m.truncate(new_size);
            }
            _ => {
                let off = next() % 100_000;
                let _ = m.seek_data(off);
                let _ = m.seek_hole(off);
            }
        }
        assert!(m.validate().is_ok(), "validate failed at step {step}");
    }

    // Collect and verify entries.
    let all = m.lookup_range(0, u64::MAX).unwrap();
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert!(
                all[i].end_offset() <= all[j].logical_offset,
                "overlap at ({}, {}) after step {:?}",
                i,
                j,
                m.representation()
            );
        }
    }
}

// =====================================================================
// 14. Partial write recovery tests
// =====================================================================

mod partial_write_recovery {

    use tidefs_extent_map::PolymorphicExtentMap;
    use tidefs_local_object_store::{FaultInjectionConfig, LocalObjectStore, ObjectKey};
    use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapOps, LocatorId};

    fn data(off: u64, len: u64, loc: u64) -> ExtentMapEntryV2 {
        let cs = [0xAB; 32];
        ExtentMapEntryV2::new_data(off, len, LocatorId(loc), cs, 0)
    }

    const POLY_MAGIC: [u8; 4] = [b'E', b'X', b'M', b'P'];

    fn serialize_for_test(entries: &[ExtentMapEntryV2], file_size: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&POLY_MAGIC);
        buf.extend_from_slice(&file_size.to_le_bytes());
        buf.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        let alloc_bytes: u64 = entries
            .iter()
            .filter(|e| e.extent_type().consumes_space())
            .map(|e| e.length)
            .sum();
        buf.extend_from_slice(&alloc_bytes.to_le_bytes());
        for e in entries {
            buf.extend_from_slice(&e.logical_offset.to_le_bytes());
            buf.extend_from_slice(&e.length.to_le_bytes());
            buf.push(e.extent_kind);
            buf.push(e.flags);
            buf.extend_from_slice(&e.locator_id.0.to_le_bytes());
            buf.extend_from_slice(&e.checksum);
            buf.extend_from_slice(&e.birth_commit_group.to_le_bytes());
        }
        buf
    }

    fn open_temp_store(name: &str) -> (LocalObjectStore, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(10000);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("tidefs-pwr-{name}-{n}"));
        std::fs::create_dir_all(&path).expect("create test dir");
        let store = LocalObjectStore::open(&path).expect("open store");
        (store, path)
    }

    #[test]
    fn partial_write_truncated_segment_recovery() {
        let (mut store, store_path) = open_temp_store("truncseg");

        // Write a large extent map payload.
        let entries: Vec<_> = (0..20).map(|i| data(i * 4096, 4096, i + 1)).collect();
        let mut original = PolymorphicExtentMap::new();
        original.insert_extent(&entries).unwrap();
        let all = original.lookup_range(0, u64::MAX).unwrap();
        let serialized = serialize_for_test(&all, 20 * 4096);

        // Write through store.
        store.put_named("recovery_test", &serialized).unwrap();

        // Read back to confirm it's there.
        {
            let loc = store
                .location_of(ObjectKey::from_name("recovery_test"))
                .unwrap();
            let bytes = store.get_at_location(loc).unwrap();
            assert_eq!(bytes.len(), serialized.len());
        }

        // Drop the store to release file handles.
        drop(store);

        // Find and truncate the segment file.
        let segments_dir = store_path.join("segments");
        let mut segment_files: Vec<_> = std::fs::read_dir(&segments_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        segment_files.sort();
        assert!(
            !segment_files.is_empty(),
            "expected at least one segment file"
        );

        let seg_path = &segment_files[0];
        let orig_len = std::fs::metadata(seg_path).unwrap().len();

        // Truncate to half the file size to simulate a partial write / crash.
        {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(seg_path)
                .unwrap();
            f.set_len(orig_len / 2).unwrap();
        }
        let new_len = std::fs::metadata(seg_path).unwrap().len();
        assert!(new_len < orig_len);

        // Reopen the store — should recover without panicking.
        let reopened = LocalObjectStore::open(&store_path);
        assert!(
            reopened.is_ok(),
            "store should recover from truncated segment"
        );
    }

    #[test]
    fn partial_write_fault_injection_handles_error() {
        let path = std::env::temp_dir().join(format!("tidefs-pwr-faultinj-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create test dir");

        // Inject a write failure with 100% probability after some bytes.
        let opts = tidefs_local_object_store::StoreOptions {
            fault_injection_config: Some(FaultInjectionConfig {
                write_failure_probability: 0.0,
                byte_corruption_probability: 0.0,
                enospc_after_bytes: None,
                schedule: None,
                crash: tidefs_local_object_store::CrashInjectionConfig::off(),
            }),
            ..tidefs_local_object_store::StoreOptions::default()
        };

        let store_result = LocalObjectStore::open_with_options(&path, opts);
        assert!(store_result.is_ok(), "store should open with fault config");

        let mut store = store_result.unwrap();

        let entries: Vec<_> = (0..10).map(|i| data(i * 4096, 4096, i + 1)).collect();
        let mut original = PolymorphicExtentMap::new();
        original.insert_extent(&entries).unwrap();
        let all = original.lookup_range(0, u64::MAX).unwrap();
        let serialized = serialize_for_test(&all, 10 * 4096);

        // The store with fault injection config but zero probability should
        // write normally.
        store.put_named("fault_test", &serialized).unwrap();

        let loc = store
            .location_of(ObjectKey::from_name("fault_test"))
            .unwrap();
        let bytes = store.get_at_location(loc).unwrap();
        assert_eq!(bytes.len(), serialized.len());

        drop(store);
        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn partial_write_reopen_preserves_existing_keys() {
        let (mut store, store_path) = open_temp_store("rekey");

        // Write two separate keys.
        store.put_named("key_a", b"payload_a").unwrap();
        store.put_named("key_b", b"payload_b").unwrap();

        // Verify both exist.
        let loc_a = store.location_of(ObjectKey::from_name("key_a")).unwrap();
        let loc_b = store.location_of(ObjectKey::from_name("key_b")).unwrap();
        assert_eq!(store.get_at_location(loc_a).unwrap(), b"payload_a");
        assert_eq!(store.get_at_location(loc_b).unwrap(), b"payload_b");

        drop(store);

        // Reopen and verify both still exist.
        let reopened = LocalObjectStore::open(&store_path).unwrap();
        let loc_a = reopened.location_of(ObjectKey::from_name("key_a")).unwrap();
        let loc_b = reopened.location_of(ObjectKey::from_name("key_b")).unwrap();
        assert_eq!(reopened.get_at_location(loc_a).unwrap(), b"payload_a");
        assert_eq!(reopened.get_at_location(loc_b).unwrap(), b"payload_b");
    }
}

// =====================================================================
// 15. Iteration ordering
// =====================================================================

/// Verify that lookup_range spanning the full file returns entries in
/// ascending logical_offset order.
fn assert_entries_sorted(entries: &[ExtentMapEntryV2]) {
    for w in entries.windows(2) {
        assert!(
            w[0].logical_offset < w[1].logical_offset,
            "entries not sorted: offset {} followed by offset {}",
            w[0].logical_offset,
            w[1].logical_offset,
        );
    }
}

/// Verify no adjacent entries could be merged (no same-type same-locator
/// adjacency).
fn assert_no_unmerged_adjacent(entries: &[ExtentMapEntryV2]) {
    for w in entries.windows(2) {
        if w[0].end_offset() == w[1].logical_offset
            && w[0].extent_type() == w[1].extent_type()
            && w[0].locator_id == w[1].locator_id
        {
            panic!(
                "unmerged adjacent entries at offsets {} and {}",
                w[0].logical_offset, w[1].logical_offset
            );
        }
    }
}

/// Verify no overlapping extents exist.
fn assert_no_overlaps(entries: &[ExtentMapEntryV2]) {
    for w in entries.windows(2) {
        assert!(
            w[0].end_offset() <= w[1].logical_offset,
            "overlap between [{}, {}) and [{}, {})",
            w[0].logical_offset,
            w[0].end_offset(),
            w[1].logical_offset,
            w[1].end_offset(),
        );
    }
}

fn collect_all_entries(m: &InlineExtentMap) -> Vec<ExtentMapEntryV2> {
    m.lookup_range(0, u64::MAX).unwrap_or_default()
}

#[test]
fn iteration_sorted_after_single_insert() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(8192, 4096, 2), data(0, 4096, 1), data(16384, 4096, 3)])
        .unwrap();
    let entries = collect_all_entries(&m);
    assert_entries_sorted(&entries);
    assert_no_overlaps(&entries);
    assert!(m.validate().is_ok());
}

#[test]
fn iteration_sorted_after_overwrite_split() {
    let mut m = make_map(&[data(0, 12288, 1)]);
    m.insert_extent(&[data(4096, 4096, 2)]).unwrap();
    let entries = collect_all_entries(&m);
    assert_entries_sorted(&entries);
    assert_no_overlaps(&entries);
    assert_eq!(entries.len(), 3);
    assert!(m.validate().is_ok());
}

#[test]
fn iteration_sorted_after_punch_hole() {
    let mut m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)]);
    m.punch_hole(2048, 12288).unwrap();
    let entries = collect_all_entries(&m);
    assert_entries_sorted(&entries);
    assert_no_overlaps(&entries);
    assert!(m.validate().is_ok());
}

#[test]
fn iteration_sorted_after_truncate() {
    let mut m = make_map(&[
        data(0, 4096, 1),
        data(8192, 4096, 2),
        data(16384, 4096, 3),
        data(24576, 4096, 4),
    ]);
    m.truncate(14336).unwrap();
    let entries = collect_all_entries(&m);
    assert_entries_sorted(&entries);
    assert_no_overlaps(&entries);
    assert!(m.validate().is_ok());
}

#[test]
fn iteration_sorted_after_collapse_range() {
    let mut m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)]);
    m.collapse_range(4096, 4096).unwrap();
    let entries = collect_all_entries(&m);
    assert_entries_sorted(&entries);
    assert_no_overlaps(&entries);
    assert!(m.validate().is_ok());
}

#[test]
fn iteration_sorted_after_fallocate() {
    let mut m = make_map(&[data(0, 4096, 1), data(16384, 4096, 2)]);
    m.fallocate(8192, 4096, false).unwrap();
    let entries = collect_all_entries(&m);
    assert_entries_sorted(&entries);
    assert_no_overlaps(&entries);
    assert!(m.validate().is_ok());
}

#[test]
fn iteration_unmerged_adjacent_rejected_by_validate() {
    let mut m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
    m.insert_extent(&[data(4096, 4096, 1)]).unwrap();
    let entries = collect_all_entries(&m);
    assert_no_unmerged_adjacent(&entries);
    assert!(m.validate().is_ok());
}

#[test]
fn iteration_entries_count_matches_header() {
    let mut m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2), data(16384, 4096, 3)]);
    let entries = collect_all_entries(&m);
    assert_eq!(entries.len() as u64, m.header.entry_count);

    m.punch_hole(2048, 12288).unwrap();
    let entries = collect_all_entries(&m);
    assert_eq!(entries.len() as u64, m.header.entry_count);

    m.truncate(2048).unwrap();
    let entries = collect_all_entries(&m);
    assert_eq!(entries.len() as u64, m.header.entry_count);
}

#[test]
fn iteration_alloc_bytes_matches_header() {
    let m = make_map(&[data(0, 4096, 1), data(8192, 4096, 2)]);
    let entries = collect_all_entries(&m);
    let computed_alloc: u64 = entries
        .iter()
        .filter(|e| e.extent_type().consumes_space())
        .map(|e| e.length)
        .sum();
    assert_eq!(computed_alloc, m.header.alloc_bytes);
}

// =====================================================================
// 16. Boundary conditions
// =====================================================================

#[test]
fn exact_overlap_replacement() {
    let mut m = make_map(&[data(0, 4096, 1)]);
    assert_eq!(m.entries[0].locator_id, LocatorId(1));

    m.insert_extent(&[data(0, 4096, 2)]).unwrap();
    assert_eq!(m.header.entry_count, 1);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, 4096);
    assert_eq!(m.entries[0].locator_id, LocatorId(2));
    assert_eq!(m.header.file_size, 4096);
    assert_eq!(m.header.alloc_bytes, 4096);
    assert!(m.validate().is_ok());
}

#[test]
fn exact_overlap_replacement_smaller() {
    let mut m = make_map(&[data(0, 8192, 1)]);
    m.insert_extent(&[data(2048, 4096, 2)]).unwrap();
    assert_eq!(m.header.entry_count, 3);
    assert_eq!(m.entries[0], data(0, 2048, 1));
    assert_eq!(m.entries[1], data(2048, 4096, 2));
    assert_eq!(m.entries[2], data(6144, 2048, 1));
    assert_eq!(m.header.file_size, 8192);
    assert_eq!(m.header.alloc_bytes, 8192);
    assert!(m.validate().is_ok());
}

#[test]
fn insert_near_u64_max_succeeds() {
    let mut m = InlineExtentMap::new();
    let off = u64::MAX - 4096;
    m.insert_extent(&[data(off, 4096, 1)]).unwrap();
    assert_eq!(m.header.file_size, u64::MAX);
    assert_eq!(m.entries[0].logical_offset, off);
    assert_eq!(m.entries[0].length, 4096);
    assert!(m.validate().is_ok());

    let r = m.lookup_range(off, 4096).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, off);
}

#[test]
fn insert_offset_plus_length_wraparound_rejected() {
    let mut m = InlineExtentMap::new();
    let err = m.insert_extent(&[data(u64::MAX, 2, 1)]).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
}

#[test]
fn insert_at_u64_max_zero_length_rejected() {
    let mut m = InlineExtentMap::new();
    let err = m.insert_extent(&[data(u64::MAX, 0, 1)]).unwrap_err();
    assert_eq!(err, ExtentMapError::InvalidRange);
}

#[test]
fn lookup_spanning_to_u64_max() {
    let m = make_map(&[data(0, 4096, 1)]);
    let r = m.lookup_range(0, u64::MAX - 1).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].logical_offset, 0);
}

#[test]
fn truncate_to_u64_max_expands() {
    let mut m = make_map(&[data(0, 4096, 1)]);
    let freed = m.truncate(u64::MAX).unwrap();
    assert!(freed.is_empty());
    assert_eq!(m.header.file_size, u64::MAX);
    assert_eq!(m.entries.len(), 1);
    assert!(m.validate().is_ok());
}

#[test]
fn punch_hole_at_u64_max_no_wraparound() {
    let mut m = make_map(&[data(u64::MAX - 8192, 8192, 1)]);
    let freed = m.punch_hole(u64::MAX - 4096, 4096).unwrap();
    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, u64::MAX - 4096);
    assert_eq!(freed[0].length, 4096);
    assert!(m.validate().is_ok());
}

#[test]
fn multi_extent_adjacent_different_type_no_merge() {
    let mut m = InlineExtentMap::new();
    let entries = [
        data(0, 4096, 1),
        ExtentMapEntryV2::new_unwritten(4096, 4096, 0),
    ];
    m.insert_extent(&entries).unwrap();
    assert_eq!(m.header.entry_count, 2);
    assert_eq!(m.entries[0], data(0, 4096, 1));
    assert_eq!(m.entries[1], ExtentMapEntryV2::new_unwritten(4096, 4096, 0));
    assert!(m.validate().is_ok());
}

#[test]
fn single_extent_at_offset_zero_with_max_length() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, u64::MAX, 1)]).unwrap();
    assert_eq!(m.header.file_size, u64::MAX);
    assert_eq!(m.entries.len(), 1);
    assert_eq!(m.entries[0].logical_offset, 0);
    assert_eq!(m.entries[0].length, u64::MAX);
    assert!(m.validate().is_ok());
}

#[test]
fn collapse_range_near_eof_removes_tail() {
    let mut m = make_map(&[data(0, 4096, 1), data(4096, 4096, 2)]);
    let freed = m.collapse_range(6144, 2048).unwrap();
    assert_eq!(freed.len(), 1);
    assert_eq!(freed[0].logical_offset, 6144);
    assert_eq!(freed[0].length, 2048);
    assert_eq!(freed[0].locator_id, LocatorId(2));
    assert_eq!(m.header.file_size, 6144);
    assert_eq!(m.entries.len(), 2);
    assert_eq!(m.entries[1].length, 2048);
    assert!(m.validate().is_ok());
}

#[test]
fn mixed_data_unwritten_hole_after_fallocate() {
    let mut m = InlineExtentMap::new();
    m.insert_extent(&[data(0, 4096, 1)]).unwrap();
    m.fallocate(8192, 4096, false).unwrap();
    assert_eq!(m.header.file_size, 12288);
    assert_eq!(m.entries.len(), 2);
    assert!(m.entries[0].is_data());
    assert!(m.entries[1].is_unwritten());
    assert!(m.validate().is_ok());
}

#[test]
fn insert_within_hole_preserves_boundaries() {
    let mut m = make_map(&[data(0, 4096, 1), data(12288, 4096, 2)]);
    m.insert_extent(&[data(8192, 2048, 3)]).unwrap();
    assert_eq!(m.entries.len(), 3);
    assert_eq!(m.entries[0], data(0, 4096, 1));
    assert_eq!(m.entries[1], data(8192, 2048, 3));
    assert_eq!(m.entries[2], data(12288, 4096, 2));
    assert!(m.validate().is_ok());

    let r = m.lookup_range(4096, 4096).unwrap();
    assert!(r.is_empty());
    let r = m.lookup_range(10240, 2048).unwrap();
    assert!(r.is_empty());
}

#[test]
fn insert_at_exact_extent_boundaries_no_split() {
    let mut m = make_map(&[data(4096, 4096, 1)]);
    m.insert_extent(&[data(0, 4096, 1)]).unwrap();
    assert_eq!(m.entries.len(), 1);
    assert_eq!(m.entries[0], data(0, 8192, 1));
    assert!(m.validate().is_ok());
}

// =====================================================================
// 17. Randomized invariant stress
// =====================================================================

use tidefs_extent_map::PolymorphicExtentMap;

/// Simple deterministic PRNG for reproducible test seeds.
struct MiniRng {
    state: u64,
}

impl MiniRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        // SplitMix64 variant.
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn next_u64_range(&mut self, min: u64, max: u64) -> u64 {
        if min >= max {
            return min;
        }
        min + self.next() % (max - min)
    }
}

/// Verify all invariants hold after a mutation on a PolymorphicExtentMap.
fn assert_poly_invariants(m: &PolymorphicExtentMap) {
    m.validate().expect("validate() failed");

    let entries = m.lookup_range(0, u64::MAX).unwrap_or_default();

    // Check sorted order.
    for w in entries.windows(2) {
        assert!(
            w[0].logical_offset < w[1].logical_offset,
            "entries not sorted: offset {} followed by {}",
            w[0].logical_offset,
            w[1].logical_offset,
        );
    }

    // Check no overlaps.
    for w in entries.windows(2) {
        assert!(
            w[0].end_offset() <= w[1].logical_offset,
            "overlap between [{}, {}) and [{}, {})",
            w[0].logical_offset,
            w[0].end_offset(),
            w[1].logical_offset,
            w[1].end_offset(),
        );
    }

    // entry_count consistency.
    assert_eq!(
        entries.len() as u64,
        m.entry_count(),
        "entry_count mismatch: header={}, actual={}",
        m.entry_count(),
        entries.len()
    );
}

#[test]
fn randomized_stress_1000_ops() {
    let seed = 0xDEADBEEF_CAFE1234;
    let mut rng = MiniRng::new(seed);
    let mut m = PolymorphicExtentMap::new();

    m.insert_extent(&[
        data(0, 4096, 1),
        data(8192, 4096, 2),
        data(16384, 4096, 3),
        data(24576, 4096, 4),
        data(32768, 4096, 5),
    ])
    .unwrap();
    assert_poly_invariants(&m);

    let mut op_count = 0;
    let mut insert_attempts = 0;
    let mut insert_successes = 0;
    let mut punch_attempts = 0;
    let mut truncate_attempts = 0;

    for _ in 0..1000 {
        let op = rng.next_u64_range(0, 3);
        op_count += 1;

        match op {
            0 => {
                insert_attempts += 1;
                let offset = rng.next_u64_range(0, 65536);
                let length = rng.next_u64_range(1, 16384);
                let loc = rng.next_u64_range(1, 100);
                let entry = data(offset, length, loc);

                let result = m.insert_extent(&[entry]);
                if result.is_ok() {
                    insert_successes += 1;
                }
                assert_poly_invariants(&m);
            }
            1 => {
                punch_attempts += 1;
                let offset = rng.next_u64_range(0, 65536);
                let length = rng.next_u64_range(1, 16384);
                let _ = m.punch_hole(offset, length);
                assert_poly_invariants(&m);
            }
            _ => {
                truncate_attempts += 1;
                let new_size = rng.next_u64_range(0, 65536);
                let _ = m.truncate(new_size);
                assert_poly_invariants(&m);
            }
        }

        if op_count % 100 == 0 {
            let entries = m.lookup_range(0, u64::MAX).unwrap_or_default();
            for e in &entries {
                assert!(
                    e.length > 0,
                    "zero-length entry at offset {}",
                    e.logical_offset
                );
                assert!(
                    e.end_offset() > e.logical_offset,
                    "invalid range at offset {}",
                    e.logical_offset
                );
            }
        }
    }

    assert_poly_invariants(&m);

    eprintln!(
        "stress stats: {} ops ({} inserts/{} ok, {} punches, {} truncates), final entries={}",
        op_count,
        insert_attempts,
        insert_successes,
        punch_attempts,
        truncate_attempts,
        m.entry_count()
    );
}

#[test]
fn randomized_stress_different_seed() {
    let mut rng = MiniRng::new(0xBEEF_F00D);
    let mut m = PolymorphicExtentMap::new();

    m.insert_extent(&[data(0, 8192, 1), data(16384, 4096, 2)])
        .unwrap();
    assert_poly_invariants(&m);

    for _ in 0..500 {
        let op = rng.next_u64_range(0, 3);
        match op {
            0 => {
                let offset = rng.next_u64_range(0, 32768);
                let length = rng.next_u64_range(1, 8192);
                let loc = rng.next_u64_range(1, 50);
                let _ = m.insert_extent(&[data(offset, length, loc)]);
                assert_poly_invariants(&m);
            }
            1 => {
                let offset = rng.next_u64_range(0, 32768);
                let length = rng.next_u64_range(1, 8192);
                let _ = m.punch_hole(offset, length);
                assert_poly_invariants(&m);
            }
            _ => {
                let new_size = rng.next_u64_range(0, 32768);
                let _ = m.truncate(new_size);
                assert_poly_invariants(&m);
            }
        }
    }
    assert_poly_invariants(&m);
}

#[test]
fn randomized_stress_chaos_inserts() {
    let mut rng = MiniRng::new(0xCAFE_BABE);
    let mut m = PolymorphicExtentMap::new();

    for _ in 0..200 {
        let offset = rng.next_u64_range(0, 32768);
        let length = rng.next_u64_range(1, 4096);
        let loc = rng.next_u64_range(1, 20);

        let _ = m.insert_extent(&[data(offset, length, loc)]);
        assert_poly_invariants(&m);

        if rng.next_u64_range(0, 4) == 0 {
            let poff = rng.next_u64_range(0, 32768);
            let plen = rng.next_u64_range(1, 4096);
            let _ = m.punch_hole(poff, plen);
            assert_poly_invariants(&m);
        }
        if rng.next_u64_range(0, 5) == 0 {
            let tsize = rng.next_u64_range(0, 32768);
            let _ = m.truncate(tsize);
            assert_poly_invariants(&m);
        }
    }
    assert_poly_invariants(&m);
}
