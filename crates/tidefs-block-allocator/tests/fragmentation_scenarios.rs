//! Integration tests: fragmentation scenarios.
//!
//! Interleaved allocate/free patterns that produce non-trivial
//! fragmentation. Verify the allocator can still satisfy requests
//! when sufficient total space exists.

use tidefs_block_allocator::{AllocError, BlockAllocator, BlockId, Region};

fn region(block_count: u64) -> Region {
    Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
}

#[test]
fn checkerboard_fragmentation_alloc_any_still_works() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let a = ba.alloc_contiguous(32).unwrap(); // blocks 0..31
    let odds: Vec<BlockId> = a.iter().copied().filter(|b| b % 2 == 1).collect();
    ba.free(&odds);
    let evens_first: Vec<BlockId> = a.iter().copied().filter(|b| b % 2 == 0).collect();
    ba.free(&evens_first);
    // Hint advanced past 31. alloc_contiguous should pick from 32+.
    let b = ba.alloc_contiguous(16).unwrap();
    assert_eq!(b.len(), 16);
    assert!(b[0] >= 32);
    // Cleanup.
    ba.free(&odds);
    ba.free(&evens_first);
    ba.free(&b);
    assert_eq!(ba.free_count(), 64);
}

#[test]
fn alloc_contiguous_fails_when_no_large_enough_run_but_any_succeeds() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    // Allocate every block individually (scattered), then free all
    // except every 4th. This leaves 16 used blocks at intervals of
    // (at most) 4, creating max 3 contiguous free between any two.
    let mut all: Vec<Vec<BlockId>> = Vec::new();
    for _ in 0..64 {
        all.push(ba.alloc_any(1).unwrap());
    }
    for (i, blocks) in all.iter().enumerate().take(64) {
        if i % 4 != 0 {
            ba.free(blocks);
        }
    }
    // Max contiguous free run is at most 3; alloc_contiguous(4) must fail.
    assert!(ba.alloc_contiguous(4).is_err());
    // alloc_any(4) should still work (scattered).
    let s = ba.alloc_any(4).unwrap();
    assert_eq!(s.len(), 4);
    assert!(
        s.windows(2).any(|w| w[1] != w[0] + 1),
        "expected non-contiguous allocation"
    );
}

#[test]
fn interleaved_alloc_free_produces_non_trivial_free_runs() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    let mut held: Vec<Vec<BlockId>> = Vec::new();
    for _ in 0..64 {
        held.push(ba.alloc(1).unwrap());
    }
    for i in (0..64).step_by(2) {
        ba.free(&held[i]);
    }
    let b = ba.alloc_contiguous(8).unwrap();
    assert_eq!(b.len(), 8);
    assert!(b.windows(2).all(|w| w[1] == w[0] + 1));
    ba.free(&b);
    for i in (1..64).step_by(2) {
        ba.free(&held[i]);
    }
    assert_eq!(ba.free_count(), 256);
}

#[test]
fn fragmentation_stress_many_small_allocs_and_frees() {
    let ba = BlockAllocator::new(512, 4096, region(512));
    let total = ba.block_count();
    let mut held: Vec<Vec<BlockId>> = Vec::new();
    for i in 0..200 {
        let n = if i % 5 == 0 { 3 } else { 2 };
        match ba.alloc(n) {
            Ok(blocks) => {
                held.push(blocks);
            }
            Err(AllocError::NoSpace) => {
                for batch in held.drain(..) {
                    ba.free(&batch);
                }
            }
            Err(_) => panic!("unexpected error"),
        }
        if held.len() > 20 {
            let old = held.remove(0);
            ba.free(&old);
        }
    }
    for batch in held.drain(..) {
        ba.free(&batch);
    }
    assert_eq!(ba.free_count(), total);
}
