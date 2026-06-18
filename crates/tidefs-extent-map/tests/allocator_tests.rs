// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration validation tests for ExtentAllocator lifecycle.
//!
//! Exercises allocate, lookup, free, resize, edge cases, and capacity
//! stress through the public API. Complements the inline unit tests in
//! `allocator.rs`.

use tidefs_extent_map::allocator::ExtentAllocError;
use tidefs_extent_map::ExtentAllocator;
use tidefs_types_extent_map_core::{ExtentId, LocatorId};

// =====================================================================
// 1. Allocate/free round-trip
// =====================================================================

#[test]
fn allocate_then_free_then_lookup_empty() {
    let mut alloc = ExtentAllocator::new();

    let _results = alloc.allocate_extent(1, 0, 4096, None).unwrap();

    let eid = _results[0].0;

    let lid = _results[0].1;
    assert_eq!(eid, ExtentId(0));
    assert_eq!(lid, LocatorId(0));

    let entries = alloc.lookup_extents(1, 0, 4096);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].logical_offset, 0);
    assert_eq!(entries[0].length, 4096);

    alloc.free_extent(1, 0, 4096).unwrap();
    assert!(alloc.lookup_extents(1, 0, 4096).is_empty());
    assert!(!alloc.has_extents(1));
    assert_eq!(alloc.total_extents(), 0);
}

// =====================================================================
// 2. Multiple non-overlapping allocations
// =====================================================================

#[test]
fn multiple_non_overlapping_allocations() {
    let mut alloc = ExtentAllocator::new();

    alloc.allocate_extent(1, 0, 4096, None).unwrap();
    alloc.allocate_extent(1, 8192, 4096, None).unwrap();
    alloc.allocate_extent(1, 16384, 8192, None).unwrap();

    assert_eq!(alloc.total_extents(), 3);
    assert!(alloc.has_extents(1));

    // Verify each range independently.
    assert_eq!(alloc.lookup_extents(1, 0, 4096).len(), 1);
    assert_eq!(alloc.lookup_extents(1, 8192, 4096).len(), 1);
    assert_eq!(alloc.lookup_extents(1, 16384, 8192).len(), 1);

    // No overlap: the range [4096, 8192) should be empty.
    assert!(alloc.lookup_extents(1, 4096, 4096).is_empty());

    // Full scan.
    assert_eq!(alloc.lookup_extents(1, 0, 24576).len(), 3);
}

// =====================================================================
// 3. Lookup by extent ID and LocatorId
// =====================================================================

#[test]
fn extent_ids_are_monotonic() {
    let mut alloc = ExtentAllocator::new();

    let _results = alloc.allocate_extent(42, 0, 4096, None).unwrap();

    let e0 = _results[0].0;
    let _results = alloc.allocate_extent(42, 8192, 4096, None).unwrap();
    let e1 = _results[0].0;
    let _results = alloc.allocate_extent(42, 16384, 4096, None).unwrap();
    let e2 = _results[0].0;

    assert!(e0.0 < e1.0);
    assert!(e1.0 < e2.0);
}

#[test]
fn lookup_by_returned_extent_id_via_range() {
    let mut alloc = ExtentAllocator::new();

    let _results = alloc.allocate_extent(99, 0, 4096, None).unwrap();

    let eid0 = _results[0].0;

    let lid0 = _results[0].1;
    let _results = alloc.allocate_extent(99, 8192, 4096, None).unwrap();
    let eid1 = _results[0].0;
    let lid1 = _results[0].1;

    // ExtentId is a counter, not a direct lookup key. Verify the
    // corresponding ranges exist with the returned LocatorIds.
    assert_eq!(eid0, ExtentId(0));
    assert_eq!(eid1, ExtentId(1));
    assert_eq!(lid0, LocatorId(0));
    assert_eq!(lid1, LocatorId(4096));

    let r0 = alloc.lookup_extents(99, 0, 4096);
    assert_eq!(r0[0].locator_id, lid0);
    assert_eq!(r0[0].length, 4096);

    let r1 = alloc.lookup_extents(99, 8192, 4096);
    assert_eq!(r1[0].locator_id, lid1);
    assert_eq!(r1[0].length, 4096);
}

// =====================================================================
// 4. Resize: grow, shrink, and error paths
// =====================================================================

#[test]
fn resize_grow_extent() {
    let mut alloc = ExtentAllocator::new();
    alloc.allocate_extent(1, 0, 4096, None).unwrap();

    let results = alloc.resize_extent(1, 0, 4096, 12288).unwrap();
    let (_, lid) = results[0];

    let entries = alloc.lookup_extents(1, 0, 12288);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].length, 12288);
    // Old alloc at loc 0; resize frees it, reallocates at 4096.
    assert_eq!(lid, LocatorId(4096));
}

#[test]
fn resize_shrink_extent() {
    let mut alloc = ExtentAllocator::new();
    alloc.allocate_extent(1, 0, 12288, None).unwrap();

    let results = alloc.resize_extent(1, 0, 12288, 4096).unwrap();
    let (_, lid) = results[0];

    let entries = alloc.lookup_extents(1, 0, 4096);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].length, 4096);
    // Old alloc at loc 0 (len 12288). Free, then realloc: next_locator
    // was 12288, so new loc = 12288.
    assert_eq!(lid, LocatorId(12288));
}

#[test]
fn resize_to_zero_rejected() {
    let mut alloc = ExtentAllocator::new();
    alloc.allocate_extent(1, 0, 4096, None).unwrap();

    let err = alloc.resize_extent(1, 0, 4096, 0).unwrap_err();
    assert_eq!(err, ExtentAllocError::InvalidOffset);

    // Original extent intact.
    assert_eq!(alloc.lookup_extents(1, 0, 4096).len(), 1);
    assert_eq!(alloc.total_extents(), 1);
}

#[test]
fn resize_nonexistent_inode_errors() {
    let mut alloc = ExtentAllocator::new();
    let err = alloc.resize_extent(1, 0, 4096, 8192).unwrap_err();
    assert_eq!(err, ExtentAllocError::ExtentNotFound);
}

#[test]
fn resize_non_overlapping_range_errors() {
    let mut alloc = ExtentAllocator::new();
    alloc.allocate_extent(1, 0, 4096, None).unwrap();

    // Range [16384, 20480) does not overlap the existing extent at [0,4096).
    let err = alloc.resize_extent(1, 16384, 4096, 8192).unwrap_err();
    assert_eq!(err, ExtentAllocError::ExtentNotFound);

    // Original extent intact.
    assert_eq!(alloc.total_extents(), 1);
}

// =====================================================================
// 5. Free and reallocate
// =====================================================================

#[test]
fn free_then_reallocate_same_offset() {
    let mut alloc = ExtentAllocator::new();

    alloc.allocate_extent(1, 0, 4096, None).unwrap();
    alloc.free_extent(1, 0, 4096).unwrap();

    // Reallocate at the same logical offset.
    let _results = alloc.allocate_extent(1, 0, 4096, None).unwrap();
    let eid = _results[0].0;
    let lid = _results[0].1;
    assert_eq!(eid, ExtentId(1)); // second ext id
    assert_eq!(lid, LocatorId(4096)); // locator advanced past first alloc

    assert_eq!(alloc.lookup_extents(1, 0, 4096).len(), 1);
    assert_eq!(alloc.total_extents(), 1);
}

#[test]
fn free_one_then_reallocate_another_offset() {
    let mut alloc = ExtentAllocator::new();

    alloc.allocate_extent(1, 0, 4096, None).unwrap();
    alloc.allocate_extent(1, 8192, 4096, None).unwrap();
    alloc.free_extent(1, 0, 4096).unwrap();

    // Allocate a new extent at a different logical offset.
    alloc.allocate_extent(1, 16384, 4096, None).unwrap();

    assert_eq!(alloc.total_extents(), 2);
    // The free'd range [0,4096) is gone, [8192,12288) and [16384,20480)
    // exist.
    let entries = alloc.lookup_extents(1, 0, 24576);
    assert_eq!(entries.len(), 2);
}

// =====================================================================
// 6. Edge cases: double-free, partial free, nonexistent resources
// =====================================================================

#[test]
fn double_free_errors() {
    let mut alloc = ExtentAllocator::new();
    alloc.allocate_extent(1, 0, 4096, None).unwrap();
    alloc.free_extent(1, 0, 4096).unwrap();

    let err = alloc.free_extent(1, 0, 4096).unwrap_err();
    assert_eq!(err, ExtentAllocError::ExtentNotFound);
}

#[test]
fn free_nonexistent_inode_errors() {
    let mut alloc = ExtentAllocator::new();
    let err = alloc.free_extent(999, 0, 4096).unwrap_err();
    assert_eq!(err, ExtentAllocError::ExtentNotFound);
}

#[test]
fn free_nonexistent_offset_errors() {
    let mut alloc = ExtentAllocator::new();
    alloc.allocate_extent(1, 0, 4096, None).unwrap();

    // Range [8192, 12288) has no extent data.
    let err = alloc.free_extent(1, 8192, 4096).unwrap_err();
    assert_eq!(err, ExtentAllocError::ExtentNotFound);
    assert_eq!(alloc.total_extents(), 1);
}

#[test]
fn free_partial_range_splits_extent() {
    let mut alloc = ExtentAllocator::new();
    alloc.allocate_extent(1, 0, 4096, None).unwrap();

    // Free a middle portion: [1024, 3072).
    alloc.free_extent(1, 1024, 2048).unwrap();

    let entries = alloc.lookup_extents(1, 0, 4096);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].logical_offset, 0);
    assert_eq!(entries[0].length, 1024);
    assert_eq!(entries[1].logical_offset, 3072);
    assert_eq!(entries[1].length, 1024);
    assert_eq!(alloc.total_extents(), 2);
}

#[test]
fn free_at_extent_start_removes_entire_extent() {
    let mut alloc = ExtentAllocator::new();
    alloc.allocate_extent(1, 0, 4096, None).unwrap();
    alloc.allocate_extent(1, 8192, 4096, None).unwrap();

    alloc.free_extent(1, 0, 4096).unwrap();

    assert_eq!(alloc.total_extents(), 1);
    let entries = alloc.lookup_extents(1, 0, 12288);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].logical_offset, 8192);
}

#[test]
fn has_extents_and_total_extents_edge_cases() {
    let alloc = ExtentAllocator::new();
    assert!(!alloc.has_extents(0));
    assert!(!alloc.has_extents(1));
    assert!(!alloc.has_extents(u64::MAX));
    assert_eq!(alloc.total_extents(), 0);
}

#[test]
fn lookup_on_nonexistent_inode_returns_empty() {
    let alloc = ExtentAllocator::new();
    let entries = alloc.lookup_extents(999, 0, 4096);
    assert!(entries.is_empty());
}

// =====================================================================
// 7. Capacity stress
// =====================================================================

#[test]
fn stress_allocate_1000_extents_across_inodes_then_free_all() {
    // InlineExtentMap is capped at 6 entries per inode, so capacity
    // testing uses many distinct inodes.
    let mut alloc = ExtentAllocator::new();
    const N: u64 = 1000;

    for inode in 0..N {
        alloc.allocate_extent(inode, 0, 4096, None).unwrap();
    }
    assert_eq!(alloc.total_extents(), N as usize);

    // Spot-check.
    for inode in [0, 1, 100, 500, 999] {
        assert!(alloc.has_extents(inode));
        let entries = alloc.lookup_extents(inode, 0, 4096);
        assert_eq!(entries.len(), 1, "extent for inode {inode} missing");
        assert_eq!(entries[0].logical_offset, 0);
        assert_eq!(entries[0].length, 4096);
    }

    // Free all.
    for inode in 0..N {
        alloc.free_extent(inode, 0, 4096).unwrap();
    }

    assert_eq!(alloc.total_extents(), 0);
    assert!(!alloc.has_extents(500));
}

#[test]
fn stress_many_extents_per_inode_up_to_map_limit() {
    // Test all 6 slots per inode for several inodes.
    let mut alloc = ExtentAllocator::new();

    for inode in 1..=10u64 {
        for j in 0..6u64 {
            alloc.allocate_extent(inode, j * 8192, 4096, None).unwrap();
        }
    }
    assert_eq!(alloc.total_extents(), 60);

    // The 7th entry for any inode fails with MapFull.
    let err = alloc.allocate_extent(1, 6 * 8192, 4096, None).unwrap_err();
    assert_eq!(
        err,
        ExtentAllocError::MapError(tidefs_types_extent_map_core::ExtentMapError::MapFull)
    );
}

// =====================================================================
// 8. Inode isolation
// =====================================================================

#[test]
fn inode_isolation_free_preserves_other_inodes() {
    let mut alloc = ExtentAllocator::new();

    alloc.allocate_extent(1, 0, 4096, None).unwrap();
    alloc.allocate_extent(2, 0, 8192, None).unwrap();
    alloc.allocate_extent(3, 16384, 4096, None).unwrap();

    // Free inode 2.
    alloc.free_extent(2, 0, 8192).unwrap();

    assert!(!alloc.has_extents(2));
    assert!(alloc.has_extents(1));
    assert!(alloc.has_extents(3));

    assert_eq!(alloc.lookup_extents(1, 0, 4096).len(), 1);
    assert_eq!(alloc.lookup_extents(3, 16384, 4096).len(), 1);
}

// =====================================================================
// 9. LocatorId and ExtentId sequencing
// =====================================================================

#[test]
fn locator_advances_by_length_on_each_alloc() {
    let mut alloc = ExtentAllocator::new();

    let _results = alloc.allocate_extent(1, 0, 4096, None).unwrap();

    let l0 = _results[0].1;
    let _results = alloc.allocate_extent(1, 8192, 8192, None).unwrap();
    let l1 = _results[0].1;
    let _results = alloc.allocate_extent(1, 20480, 512, None).unwrap();
    let l2 = _results[0].1;

    assert_eq!(l0, LocatorId(0));
    assert_eq!(l1, LocatorId(4096));
    assert_eq!(l2, LocatorId(4096 + 8192));
}

#[test]
fn locator_wraps_at_u64_boundary() {
    let mut alloc = ExtentAllocator::with_initial_locator(u64::MAX - 100);

    let _results = alloc.allocate_extent(1, 0, 4096, None).unwrap();

    let l0 = _results[0].1;
    assert_eq!(l0, LocatorId(u64::MAX - 100));

    let _results = alloc.allocate_extent(1, 8192, 4096, None).unwrap();

    let l1 = _results[0].1;
    // wrapping_add(4096) on (u64::MAX - 100) wraps to 3995.
    assert!(l1.0 < 10000, "locator should wrap around u64::MAX");

    let entries = alloc.lookup_extents(1, 0, 12288);
    assert_eq!(entries.len(), 2);
}

#[test]
fn with_initial_locator_accepts_zero() {
    let mut alloc = ExtentAllocator::with_initial_locator(0);
    let _results = alloc.allocate_extent(1, 0, 4096, None).unwrap();
    let lid = _results[0].1;
    assert_eq!(lid, LocatorId(0));
}

#[test]
fn extent_id_continues_across_inodes() {
    let mut alloc = ExtentAllocator::new();

    let _results = alloc.allocate_extent(1, 0, 4096, None).unwrap();

    let e0 = _results[0].0;
    let _results = alloc.allocate_extent(2, 0, 4096, None).unwrap();
    let e1 = _results[0].0;
    let _results = alloc.allocate_extent(1, 8192, 4096, None).unwrap();
    let e2 = _results[0].0;

    // ExtentId is global, continues across inodes.
    assert_eq!(e0, ExtentId(0));
    assert_eq!(e1, ExtentId(1));
    assert_eq!(e2, ExtentId(2));
}

// =====================================================================
// 10. MapFull boundary
// =====================================================================

#[test]
fn inline_map_full_at_seventh_entry() {
    // The allocator uses per-inode InlineExtentMap (V1, <=6 entries).
    let mut alloc = ExtentAllocator::new();

    for i in 0..6u64 {
        alloc.allocate_extent(1, i * 8192, 4096, None).unwrap();
    }
    assert_eq!(alloc.total_extents(), 6);

    let err = alloc.allocate_extent(1, 6 * 8192, 4096, None).unwrap_err();
    assert_eq!(
        err,
        ExtentAllocError::MapError(tidefs_types_extent_map_core::ExtentMapError::MapFull)
    );
}

#[test]
fn map_full_does_not_corrupt_previous_extents() {
    let mut alloc = ExtentAllocator::new();

    for i in 0..6u64 {
        alloc.allocate_extent(1, i * 8192, 4096, None).unwrap();
    }

    let err = alloc.allocate_extent(1, 6 * 8192, 4096, None).unwrap_err();
    assert_eq!(
        err,
        ExtentAllocError::MapError(tidefs_types_extent_map_core::ExtentMapError::MapFull)
    );

    // The 6 existing extents should still be intact.
    assert_eq!(alloc.total_extents(), 6);
    for i in 0..6u64 {
        let entries = alloc.lookup_extents(1, i * 8192, 4096);
        assert_eq!(entries.len(), 1, "extent {i} lost after MapFull");
    }
}
