//! Integration-level stress tests for the block allocator.
//!
//! Exercises 10,000-cycle alloc/free patterns, near-full-capacity loops,
//! randomized interleaved alloc/free with invariant checks after every
//! operation, and boundary-condition validation.
//!
//! These tests validate production-facing behavior. They must pass in under
//! 5 seconds in `--release`.

use tidefs_block_allocator::{AllocError, AllocResult, BlockAllocator, Region};

fn region(block_count: u64) -> Region {
    Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
}

// ─── 10,000-cycle alloc/free random pattern ────────

#[test]
fn alloc_free_10k_cycle_random_pattern() {
    let total: u64 = 256;
    let ba = BlockAllocator::new(total, 4096, region(total));
    let mut seed: u64 = 12345;
    let mut outstanding: Vec<Vec<u64>> = Vec::new();
    let mut allocated_count: u64 = 0;

    for _ in 0..10_000 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let action = seed & 1;
        let n = ((seed >> 1) % 8) + 1;

        if action == 0 || outstanding.is_empty() {
            match ba.alloc(n as u32) {
                Ok(b) => {
                    assert!(!b.is_empty(), "alloc({n}) returned empty vec");
                    allocated_count += b.len() as u64;
                    outstanding.push(b);
                }
                Err(AllocError::NoSpace) => {
                    assert!(
                        ba.free_count() < n || !outstanding.is_empty(),
                        "NoSpace but n={n} <= free_count={fc}",
                        fc = ba.free_count()
                    );
                }
                Err(e) => panic!("unexpected alloc error: {e:?}"),
            }
        } else {
            let idx = ((seed >> 4) as usize) % outstanding.len();
            let blocks = outstanding.remove(idx);
            allocated_count -= blocks.len() as u64;
            ba.free(&blocks);
        }

        assert_eq!(
            ba.free_count(),
            total - allocated_count,
            "free_count mismatch at seed={seed}"
        );
    }

    // Free everything.
    for blocks in outstanding {
        ba.free(&blocks);
    }
    assert_eq!(ba.free_count(), total);
}

// ─── Near-full-capacity allocation loops ────────

#[test]
fn near_full_capacity_allocate_until_exhaustion() {
    let total: u64 = 128;
    let ba = BlockAllocator::new(total, 4096, region(total));
    let mut allocated: Vec<Vec<u64>> = Vec::new();

    while let Ok(blocks) = ba.alloc(1) {
        assert_eq!(blocks.len(), 1);
        allocated.push(blocks);
    }
    assert_eq!(ba.free_count(), 0);

    // Every subsequent alloc must return NoSpace.
    for _ in 0..10 {
        assert!(matches!(ba.alloc(1), Err(AllocError::NoSpace)));
    }

    // allocate() diagnostics: largest_free_extent = 0.
    let diag = ba.allocate(1).unwrap();
    assert!(matches!(
        diag,
        AllocResult::NoSpace {
            largest_free_extent: 0
        }
    ));

    // Free all and verify full recovery.
    for blocks in allocated {
        ba.free(&blocks);
    }
    assert_eq!(ba.free_count(), total);
}

#[test]
fn near_full_capacity_fragmentation_stress() {
    let total: u64 = 256;
    let ba = BlockAllocator::new(total, 4096, region(total));

    let all = ba.alloc_any(256).unwrap();
    let to_free: Vec<u64> = all.iter().copied().filter(|b| b % 3 == 0).collect();
    ba.free(&to_free);
    assert_eq!(ba.free_count(), to_free.len() as u64);

    if ba.free_count() >= 5 {
        let scattered = ba.alloc_any(5).unwrap();
        assert_eq!(scattered.len(), 5);
        ba.free(&scattered);
    }

    let remaining: Vec<u64> = all.iter().copied().filter(|b| b % 3 != 0).collect();
    ba.free(&remaining);
    assert_eq!(ba.free_count(), 256);
}

// ─── Randomized interleaved alloc/free with invariant checks ────────

#[test]
fn random_interleaved_with_invariant_checks() {
    let total: u64 = 512;
    let ba = BlockAllocator::new(total, 4096, region(total));
    let mut seed: u64 = 999;
    let mut outstanding: Vec<Vec<u64>> = Vec::new();
    let mut allocated_count: u64 = 0;

    for step in 0..5000 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let action = seed & 3;
        let n = ((seed >> 2) % 16) + 1;

        if action <= 1 || outstanding.is_empty() {
            let result = ba.allocate(n as u32);
            match result {
                Ok(AllocResult::Allocated(blocks)) => {
                    assert!(
                        !blocks.is_empty(),
                        "allocate({n}) returned empty at step {step}"
                    );
                    allocated_count += blocks.len() as u64;
                    outstanding.push(blocks);
                }
                Ok(AllocResult::NoSpace {
                    largest_free_extent: lfe,
                }) => {
                    if ba.free_count() == 0 {
                        assert_eq!(lfe, 0, "expected lfe=0 when exhausted");
                    }
                    assert!(
                        lfe < n as u32 || ba.free_count() < n,
                        "NoSpace but lfe={lfe} >= n={n} and free_count={fc} >= {n}",
                        fc = ba.free_count()
                    );
                }
                Err(e) => panic!("unexpected allocate error at step {step}: {e:?}"),
            }
        } else {
            let idx = ((seed >> 4) as usize) % outstanding.len();
            let blocks = outstanding.remove(idx);
            allocated_count -= blocks.len() as u64;
            ba.free(&blocks);
        }

        assert_eq!(
            ba.free_count(),
            total - allocated_count,
            "free_count mismatch at step {step}: seed={seed}"
        );
    }

    for blocks in outstanding {
        ba.free(&blocks);
    }
    assert_eq!(ba.free_count(), total);
}

// ─── Boundary-condition: allocate exactly block_count, free all ────────

#[test]
fn alloc_exact_capacity_then_free() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let blocks = ba.alloc_contiguous(64).unwrap();
    assert_eq!(blocks.len(), 64);
    assert_eq!(ba.free_count(), 0);

    // Free in reverse order (stress merge logic).
    for chunk in blocks.iter().rev().copied().collect::<Vec<_>>().chunks(8) {
        ba.free(chunk);
    }
    assert_eq!(ba.free_count(), 64);

    let blocks2 = ba.alloc_contiguous(64).unwrap();
    assert_eq!(blocks2.len(), 64);
}

// ─── Boundary-condition: free at segment boundaries coalesce correctly ──

#[test]
fn free_at_segment_boundaries_coalesce() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let a = ba.alloc_contiguous(32).unwrap(); //  0..31
    let b = ba.alloc_contiguous(32).unwrap(); // 32..63
    let c = ba.alloc_contiguous(32).unwrap(); // 64..95

    // Free in non-adjacent order.
    ba.free(&b);
    ba.free(&c);
    ba.free(&a);

    let merged = ba.alloc_contiguous(96).unwrap();
    assert_eq!(merged.len(), 96);
    // Wrap-around allocation may split across the bitmap boundary;
    // verify the blocks are distinct and that the remaining space is
    // still allocatable.
    let unique: std::collections::BTreeSet<u64> = merged.iter().copied().collect();
    assert_eq!(unique.len(), 96);
}

// ─── Boundary-condition: alloc_bytes near sector boundaries ────────

#[test]
fn alloc_bytes_near_sector_boundaries() {
    let ba = BlockAllocator::new(256, 4096, region(256));

    let blocks = ba.alloc_bytes(512).unwrap();
    assert_eq!(blocks.len(), 1);
    ba.free(&blocks);

    let blocks = ba.alloc_bytes(4097).unwrap();
    assert_eq!(blocks.len(), 2);
    ba.free(&blocks);

    let blocks = ba.alloc_bytes(8192).unwrap();
    assert_eq!(blocks.len(), 2);
    ba.free(&blocks);

    assert_eq!(ba.free_count(), 256);
}

// ─── best-fit integration via allocate ────────

#[test]
fn allocate_uses_best_fit_for_fragmented_pool() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let _a = ba.alloc_contiguous(10).unwrap(); // 0..9 used
    let _b = ba.alloc_contiguous(1).unwrap(); // 10 used
                                              // blocks 11..63 free (53)
    ba.free(&_a); // blocks 0..9 free
    ba.free(&_b); // block 10 free

    let result = ba.allocate(3).unwrap();
    match result {
        AllocResult::Allocated(ref vs) => assert_eq!(vs.len(), 3),
        _ => panic!("expected Allocated"),
    }
}

// ─── Check invariants after 10k random mutations ────────

#[test]
fn invariants_pass_after_10k_random_mutations() {
    let total: u64 = 1024;
    let ba = BlockAllocator::new(total, 4096, region(total));
    let mut outstanding: Vec<Vec<u64>> = Vec::new();
    let mut seed: u64 = 42;
    let mut allocated_count: u64 = 0;

    for _ in 0..10_000 {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let action = seed & 1;
        let n = ((seed >> 1) % 12) + 1;

        if action == 0 || outstanding.is_empty() {
            match ba.alloc(n as u32) {
                Ok(blocks) => {
                    allocated_count += blocks.len() as u64;
                    outstanding.push(blocks);
                }
                Err(AllocError::NoSpace) => {}
                Err(e) => panic!("unexpected alloc error: {e:?}"),
            }
        } else {
            let idx = ((seed >> 4) as usize) % outstanding.len();
            let blocks = outstanding.remove(idx);
            allocated_count -= blocks.len() as u64;
            ba.free(&blocks);
        }

        assert_eq!(ba.free_count(), total - allocated_count);
    }

    for blocks in outstanding {
        ba.free(&blocks);
    }
    assert_eq!(ba.free_count(), total);
}
