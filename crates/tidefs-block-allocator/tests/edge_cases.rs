// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests: edge cases.
//!
//! Zero-length rejection, ENOSPC, free of unallocated blocks,
//! double-free idempotence at the BlockAllocator level, root-reserve
//! boundary, and large-allocation edge cases.

use tidefs_block_allocator::{AllocError, BlockAllocator, Region};

fn region(block_count: u64) -> Region {
    Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
}

#[test]
fn zero_length_alloc_rejected() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    assert_eq!(ba.alloc(0), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_contiguous(0), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_any(0), Err(AllocError::NoSpace));
    assert_eq!(ba.free_count(), 64);
}

#[test]
fn alloc_exceeding_pool_size() {
    let ba = BlockAllocator::new(16, 4096, region(16));
    assert_eq!(ba.alloc(17), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_contiguous(17), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_any(17), Err(AllocError::NoSpace));
}

#[test]
fn alloc_all_blocks_then_one_more_through_admission() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let blocks = ba.alloc_any(64).unwrap();
    assert_eq!(blocks.len(), 64);
    assert_eq!(ba.free_count(), 0);
    // All three alloc paths must return NoSpace.
    assert_eq!(ba.alloc(1), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_contiguous(1), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_any(1), Err(AllocError::NoSpace));
    ba.free(&blocks[..1]);
    assert_eq!(ba.free_count(), 1);
    let recovered = ba.alloc(1).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(ba.free_count(), 0);
    ba.free(&blocks[1..]);
    ba.free(&recovered);
    assert_eq!(ba.free_count(), 64);
}

#[test]
fn free_unallocated_blocks_is_noop() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    ba.free(&[10, 20, 30]);
    assert_eq!(ba.free_count(), 64);

    let blocks = ba.alloc_any(5).unwrap();
    ba.free(&[100, 200]);
    ba.free(&[blocks[0], 999]);
    assert_eq!(ba.free_count(), 60); // one real block freed
    ba.free(&blocks[1..]);
    assert_eq!(ba.free_count(), 64);
}

#[test]
fn double_free_idempotent_at_allocator_level() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let blocks = ba.alloc_any(10).unwrap();
    let free_before = ba.free_count();

    ba.free(&blocks);
    assert_eq!(ba.free_count(), free_before + 10);
    ba.free(&blocks);
    assert_eq!(ba.free_count(), free_before + 10);
}

#[test]
fn root_reserve_blocks_withheld_from_public_allocation() {
    let ba = BlockAllocator::with_root_reserve(8, 4096, region(8), 4);
    assert!(ba.alloc_any(4).is_ok());
    assert_eq!(ba.alloc(1), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_contiguous(1), Err(AllocError::NoSpace));
    assert_eq!(ba.alloc_any(1), Err(AllocError::NoSpace));
    let s = ba.allocator_statfs();
    assert_eq!(s.f_bfree, 4);
    assert_eq!(s.f_bavail, 0);
}

#[test]
fn root_reserve_can_be_zero() {
    let ba = BlockAllocator::with_root_reserve(16, 4096, region(16), 0);
    ba.alloc_any(16).unwrap();
    assert_eq!(ba.free_count(), 0);
    let s = ba.allocator_statfs();
    assert_eq!(s.f_bavail, 0);
}

#[test]
fn large_allocation_near_pool_size_succeeds() {
    let ba = BlockAllocator::new(1024, 4096, region(1024));
    let blocks = ba.alloc_contiguous(1024).unwrap();
    assert_eq!(blocks.len(), 1024);
    assert_eq!(ba.free_count(), 0);
    ba.free(&blocks);
    assert_eq!(ba.free_count(), 1024);
}

#[test]
fn alloc_within_pool_but_beyond_available_fails() {
    let ba = BlockAllocator::new(32, 4096, region(32));
    let _held = ba.alloc(20).unwrap();
    assert_eq!(ba.alloc(13), Err(AllocError::NoSpace));
    let rest = ba.alloc_any(12).unwrap();
    assert_eq!(rest.len(), 12);
}
