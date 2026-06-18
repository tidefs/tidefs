// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests: allocate → free → reallocate with free-space convergence.
//!
//! These tests treat `BlockAllocator` as a black box and verify that
//! observed allocation/free outcomes are consistent and stable across
//! multiple cycles.

use tidefs_block_allocator::{BlockAllocator, Region};

fn region(block_count: u64) -> Region {
    Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
}

#[test]
fn single_block_alloc_free_realloc_converges() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    for _cycle in 0..5 {
        let blocks = ba.alloc(1).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(ba.free_count(), 255);
        ba.free(&blocks);
        assert_eq!(ba.free_count(), 256);
    }
}

#[test]
fn multi_cycle_borrow_return() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let a = ba.alloc(10).unwrap();
    assert_eq!(ba.free_count(), 118);
    ba.free(&a[..5]);
    assert_eq!(ba.free_count(), 123);
    let b = ba.alloc(3).unwrap();
    assert_eq!(ba.free_count(), 120);
    ba.free(&a[5..]);
    ba.free(&b);
    assert_eq!(ba.free_count(), 128);
}

#[test]
fn concurrent_owner_allocation_converges() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let owner_a = ba.alloc_any(8).unwrap();
    let owner_b = ba.alloc_any(12).unwrap();
    assert_eq!(ba.free_count(), 44);
    assert_eq!(ba.block_count(), 64);

    ba.free(&owner_a);
    assert_eq!(ba.free_count(), 52);
    ba.free(&owner_b);
    assert_eq!(ba.free_count(), 64);
}

#[test]
fn alloc_free_alternating_many_cycles() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    let total = ba.block_count();
    for _ in 0..100 {
        let b = ba.alloc(1).unwrap();
        assert_eq!(ba.free_count(), total - 1);
        ba.free(&b);
        assert_eq!(ba.free_count(), total);
    }
}

#[test]
fn free_empty_slice_is_noop() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    ba.free(&[]);
    assert_eq!(ba.free_count(), 64);
    let blocks = ba.alloc(3).unwrap();
    ba.free(&[]);
    assert_eq!(ba.free_count(), 61);
    ba.free(&blocks);
    assert_eq!(ba.free_count(), 64);
}

#[test]
fn mixed_contiguous_and_any_allocation_free_count() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    let c = ba.alloc_contiguous(10).unwrap();
    assert_eq!(c.len(), 10);
    assert!(c.windows(2).all(|w| w[1] == w[0] + 1));
    assert_eq!(ba.free_count(), 246);

    let s = ba.alloc_any(15).unwrap();
    assert_eq!(s.len(), 15);
    assert_eq!(ba.free_count(), 231);

    ba.free(&c);
    ba.free(&s);
    assert_eq!(ba.free_count(), 256);
}
