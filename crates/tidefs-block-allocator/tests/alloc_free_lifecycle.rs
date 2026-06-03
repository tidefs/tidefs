//! Alloc/free lifecycle tests for tidefs-block-allocator.
//!
//! Tests the full lifecycle: allocate blocks, verify they are consumed,
//! free them, verify they return to the free pool, re-allocate and confirm
//! reuse, double-free idempotence, free-of-never-allocated noop, and
//! pool exhaustion behavior.

use tidefs_block_allocator::{AllocError, BlockAllocator, Region};

fn region(block_count: u64) -> Region {
    Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
}

// ─── Basic lifecycle: alloc → verify used → free → verify free ────────

#[test]
fn alloc_consumes_blocks_from_pool() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let free_before = ba.free_count();

    let a = ba.alloc(3).unwrap();
    assert_eq!(a.len(), 3);
    assert_eq!(ba.free_count(), free_before - 3);

    // Allocated blocks must not be re-allocated while held.
    // Try alloc_contiguous — it should skip the held blocks.
    let b = ba.alloc_contiguous(10).unwrap();
    for &bid in &b {
        assert!(!a.contains(&bid), "allocated block {bid} in both a and b");
    }

    ba.free(&a);
    ba.free(&b);
    assert_eq!(ba.free_count(), 64);
}

#[test]
fn free_returns_blocks_to_pool() {
    let ba = BlockAllocator::new(128, 4096, region(128));

    let a = ba.alloc_any(40).unwrap();
    assert_eq!(ba.free_count(), 88);

    ba.free(&a);
    assert_eq!(ba.free_count(), 128);

    // Can allocate those same blocks again.
    let b = ba.alloc(40).unwrap();
    assert_eq!(b.len(), 40);
    assert_eq!(ba.free_count(), 88);

    ba.free(&b);
    assert_eq!(ba.free_count(), 128);
}

#[test]
fn free_partial_batch_single_block() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let a = ba.alloc(10).unwrap();
    assert_eq!(ba.free_count(), 54);

    // Free a subset.
    ba.free(&a[..3]);
    assert_eq!(ba.free_count(), 57);

    // The remaining 7 are still allocated.
    let b = ba.alloc(5).unwrap();
    // Should not overlap with held blocks (a[3..]).
    for &bid in &b {
        assert!(!a[3..].contains(&bid));
    }
    assert_eq!(b.len(), 5);

    ba.free(&a[3..]);
    ba.free(&b);
    assert_eq!(ba.free_count(), 64);
}

// ─── Reuse after free ─────────────────────────────────────────────────

#[test]
fn reuse_same_blocks_after_free_when_hint_reset() {
    // After freeing blocks, re-allocating with contiguous allocator
    // should eventually reuse the same range when the hint wraps.
    let ba = BlockAllocator::new(128, 4096, region(128));

    let a = ba.alloc_contiguous(5).unwrap(); // blocks 0..4
    ba.free(&a);

    // alloc_any should find these blocks first (hint is past them though).
    // Because the hint advanced past 4, alloc_contiguous scans from hint.
    // But alloc_any does two-pass and will pick them up on wrap.
    let b = ba.alloc_any(5).unwrap();
    let mut sorted_b = b.clone();
    sorted_b.sort();
    // alloc_any may pick from different positions; we just verify 5 blocks.
    assert_eq!(sorted_b.len(), 5);
    ba.free(&b);
    assert_eq!(ba.free_count(), 128);
}

#[test]
fn reuse_same_positions_after_free_with_contiguous() {
    // Free then alloc_contiguous with hint wrap-back picks the freed hole.
    let ba = BlockAllocator::new(128, 4096, region(128));

    let a = ba.alloc_contiguous(3).unwrap(); // 0..2, hint=3
    let b = ba.alloc_contiguous(10).unwrap(); // 3..12, hint=13
    ba.free(&a); // 0..2 free, hint still at 13

    // Allocate all blocks past hint, forcing wrap.
    let rest = ba.alloc_contiguous(128 - 13).unwrap(); // 13..127
    ba.free(&rest);

    // Now hint wrapped back to 0. alloc_contiguous should reuse 0..2.
    let c = ba.alloc_contiguous(3).unwrap();
    assert_eq!(&c, &[0, 1, 2]);

    ba.free(&b);
    ba.free(&c);
    assert_eq!(ba.free_count(), 128);
}

// ─── Pool exhaustion ──────────────────────────────────────────────────

#[test]
fn alloc_exhausted_pool_all_paths_report_nospace() {
    let ba = BlockAllocator::new(16, 4096, region(16));
    let all = ba.alloc_any(16).unwrap();
    assert_eq!(all.len(), 16);
    assert_eq!(ba.free_count(), 0);

    // All three alloc paths must return NoSpace.
    assert_eq!(ba.alloc(1), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_contiguous(1), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_any(1), Err(AllocError::NoSpace));

    // alloc_bytes also fails.
    match ba.alloc_bytes(4096) {
        Err(AllocError::NoSpace) => {}
        other => panic!("expected NoSpace, got {other:?}"),
    }

    ba.free(&all);
    assert_eq!(ba.free_count(), 16);
}

#[test]
fn alloc_just_beyond_pool_fails_immediately() {
    // Request more blocks than the pool has — must fail without allocation.
    let ba = BlockAllocator::new(32, 4096, region(32));
    assert_eq!(ba.alloc(33), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_contiguous(33), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_any(33), Err(AllocError::NoSpace));
    assert_eq!(ba.free_count(), 32);
}

#[test]
fn alloc_zero_blocks_all_paths_rejected() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    assert_eq!(ba.alloc(0), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_contiguous(0), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_any(0), Err(AllocError::NoSpace));
    assert_eq!(ba.free_count(), 64);
}

// ─── Double-free idempotence ─────────────────────────────────────────

#[test]
fn double_free_idempotent_no_double_count() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let a = ba.alloc_any(10).unwrap();

    let fc_after_alloc = ba.free_count();

    ba.free(&a);
    assert_eq!(ba.free_count(), fc_after_alloc + 10);

    // Second free must not change free_count.
    ba.free(&a);
    assert_eq!(ba.free_count(), fc_after_alloc + 10);

    // Third free.
    ba.free(&a);
    assert_eq!(ba.free_count(), fc_after_alloc + 10);
}

#[test]
fn double_free_subset_idempotent() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let a = ba.alloc_any(10).unwrap();

    ba.free(&a[..5]);
    let fc_partial = ba.free_count();

    // Re-free the same subset.
    ba.free(&a[..5]);
    assert_eq!(ba.free_count(), fc_partial);

    // Free the remainder.
    ba.free(&a[5..]);
    assert_eq!(ba.free_count(), 128);
}

// ─── Free of never-allocated blocks is no-op ─────────────────────────

#[test]
fn free_never_allocated_is_noop() {
    let ba = BlockAllocator::new(64, 4096, region(64));

    // Blocks 50, 51, 52 were never allocated.
    ba.free(&[50, 51, 52]);
    assert_eq!(ba.free_count(), 64);

    // Even after some allocations.
    let a = ba.alloc(5).unwrap(); // 0..4
    ba.free(&[50, 51, 52]);
    assert_eq!(ba.free_count(), 59);

    // Free the real allocation.
    ba.free(&a);
    assert_eq!(ba.free_count(), 64);
}

#[test]
fn free_out_of_range_blocks_is_noop() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    // Block IDs beyond block_count are silently ignored.
    ba.free(&[100, 200, 300]);
    assert_eq!(ba.free_count(), 64);

    // Mixed: some out-of-range, some in-range (not allocated).
    ba.free(&[10, 100, 20]);
    assert_eq!(ba.free_count(), 64);

    // With allocated blocks present.
    let a = ba.alloc(5).unwrap();
    ba.free(&[a[0], 999, a[1]]);
    // a[0] and a[1] freed, 999 ignored.
    assert_eq!(ba.free_count(), 61); // 64-5+2 = 61

    ba.free(&a[2..]);
    assert_eq!(ba.free_count(), 64);
}

// ─── Free empty slice is no-op ──────────────────────────────────────

#[test]
fn free_empty_slice_is_noop() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    ba.free(&[]);
    assert_eq!(ba.free_count(), 64);

    let a = ba.alloc(3).unwrap();
    ba.free(&[]);
    assert_eq!(ba.free_count(), 61);

    ba.free(&a);
    assert_eq!(ba.free_count(), 64);
}

// ─── Many-cycle alloc/free convergence ────────────────────────────────

#[test]
fn one_thousand_alloc_free_cycles() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    let total = ba.block_count();

    for _ in 0..1000 {
        let b = ba.alloc(1).unwrap();
        assert_eq!(ba.free_count(), total - 1);
        ba.free(&b);
        assert_eq!(ba.free_count(), total);
    }
}

#[test]
fn multi_block_alloc_free_convergence_over_cycles() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let total = ba.block_count();

    for i in 0..200 {
        let n = ((i % 4) + 3) as u32; // 3, 4, 5, 6 blocks per cycle
        let b = ba.alloc(n).unwrap();
        assert_eq!(b.len(), n as usize);
        assert_eq!(ba.free_count(), total - n as u64);
        ba.free(&b);
        assert_eq!(ba.free_count(), total);
    }
}

// ─── Concurrent-owner lifecycle ───────────────────────────────────────

#[test]
fn multiple_independent_allocations_lifecycle() {
    let ba = BlockAllocator::new(256, 4096, region(256));

    let owner_a = ba.alloc_any(30).unwrap();
    let owner_b = ba.alloc_contiguous(40).unwrap();
    let owner_c = ba.alloc_any(20).unwrap();

    assert_eq!(ba.free_count(), 166); // 256 - 90

    // Free them in different order than allocation.
    ba.free(&owner_b);
    assert_eq!(ba.free_count(), 206);

    ba.free(&owner_c);
    assert_eq!(ba.free_count(), 226);

    // Re-allocate in the freed space.
    let owner_d = ba.alloc(35).unwrap();
    assert_eq!(owner_d.len(), 35);
    assert_eq!(ba.free_count(), 191);

    ba.free(&owner_a);
    ba.free(&owner_d);
    assert_eq!(ba.free_count(), 256);
}

// ─── Alloc/Free with persist interruptions ────────────────────────────

#[test]
fn lifecycle_across_persist_roundtrip() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    let a = ba.alloc_contiguous(10).unwrap();
    let b = ba.alloc_any(20).unwrap();
    assert_eq!(ba.free_count(), 226);

    let words = ba.flush_words();
    let ba2 = BlockAllocator::from_persisted(256, 4096, region(256), words);

    // Allocated blocks still unavailable in restored allocator.
    assert_eq!(ba2.free_count(), 226);

    // Free via original.
    ba.free(&a);
    ba.free(&b);
    assert_eq!(ba.free_count(), 256);
}

#[test]
fn lifecycle_after_partial_free_and_persist() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let a = ba.alloc_any(30).unwrap();
    let b = ba.alloc_any(20).unwrap();

    ba.free(&a[..10]); // 10 freed, 40 still held
    assert_eq!(ba.free_count(), 88);

    let words = ba.flush_words();
    let ba2 = BlockAllocator::from_persisted(128, 4096, region(128), words);
    assert_eq!(ba2.free_count(), 88);

    // Free via ba2 (fresh handle) — remaining 20 of a and 20 of b.
    ba2.free(&a[10..]);
    assert_eq!(ba2.free_count(), 108);
    ba2.free(&b);
    assert_eq!(ba2.free_count(), 128);

    // Cleanup original.
    ba.free(&a[10..]);
    ba.free(&b);
}
