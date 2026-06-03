//! Fragmentation tests for tidefs-block-allocator.
//!
//! Executes randomized alloc/free workloads with a seeded RNG, measures
//! fragmentation ratio at checkpoints, and verifies the allocator can
//! satisfy requests under moderate fragmentation.

use tidefs_block_allocator::{AllocError, BlockAllocator, BlockId, Region};

fn region(block_count: u64) -> Region {
    Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
}

/// A simple seeded PRNG (xorshift64) for deterministic randomness.
struct SeededRng {
    state: u64,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        // Seed must be non-zero.
        Self { state: seed | 1 }
    }

    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Return u32 in [0, max).
    fn next_u32(&mut self, max: u32) -> u32 {
        if max == 0 {
            return 0;
        }
        (self.next() as u32) % max
    }

    /// Return usize in [0, max).
    fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        (self.next() as usize) % max
    }
}

/// Compute fragmentation ratio by scanning bitmap words.
///
/// Returns a value in [0.0, 1.0] where:
/// - 0.0 = all free blocks are in one contiguous run (no fragmentation)
/// - 1.0 = every free block is isolated (maximum fragmentation)
///
/// Formula: 1.0 - (longest_contiguous_free_run / total_free_blocks)
fn fragmentation_ratio(ba: &BlockAllocator) -> f64 {
    let words = ba.flush_words();
    let total = ba.block_count();
    let free = ba.free_count();

    if free == 0 {
        return 0.0;
    }

    let mut longest = 0u64;
    let mut current = 0u64;

    for blk in 0..total {
        let word_idx = (blk / 64) as usize;
        let bit_in_word = (blk % 64) as u32;
        let is_free = word_idx < words.len() && (words[word_idx] >> bit_in_word) & 1 == 0;

        if is_free {
            current += 1;
        } else {
            longest = longest.max(current);
            current = 0;
        }
    }
    longest = longest.max(current);

    1.0 - (longest as f64 / free as f64)
}

/// Return (largest_contiguous_free, fragmentation_ratio).
fn fragmentation_stats(ba: &BlockAllocator) -> (u64, f64) {
    let words = ba.flush_words();
    let total = ba.block_count();
    let free = ba.free_count();

    if free == 0 {
        return (0, 0.0);
    }

    let mut longest = 0u64;
    let mut current = 0u64;

    for blk in 0..total {
        let word_idx = (blk / 64) as usize;
        let bit_in_word = (blk % 64) as u32;
        let is_free = word_idx < words.len() && (words[word_idx] >> bit_in_word) & 1 == 0;

        if is_free {
            current += 1;
        } else {
            longest = longest.max(current);
            current = 0;
        }
    }
    longest = longest.max(current);

    let ratio = 1.0 - (longest as f64 / free as f64);
    (longest, ratio)
}

// ─── 1000+ alloc/free with seeded RNG ─────────────────────────────────

#[test]
fn fragmentation_churn_1000_ops_with_seeded_rng() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    let mut rng = SeededRng::new(0xdead_beef_cafe_babe);
    let mut held: Vec<Vec<BlockId>> = Vec::new();
    let mut frag_samples: Vec<f64> = Vec::new();

    for _step in 0..1200 {
        // Decide: alloc (70%) or free (30%).
        if rng.next_u32(100) < 70 || held.is_empty() {
            // Alloc: 1..12 blocks, use a mix of contiguous and any.
            let nblocks = rng.next_u32(12) + 1;
            let use_contiguous = rng.next_u32(2) == 0;

            let result = if use_contiguous {
                ba.alloc_contiguous(nblocks)
            } else {
                ba.alloc_any(nblocks)
            };

            match result {
                Ok(blocks) => held.push(blocks),
                Err(AllocError::NoSpace) => {
                    // Drain all and continue.
                    for batch in held.drain(..) {
                        ba.free(&batch);
                    }
                    // Try alloc again after drain.
                    if let Ok(blocks) = ba.alloc(nblocks) {
                        held.push(blocks);
                    }
                }
                Err(_) => panic!("unexpected error"),
            }
        } else {
            // Free a random held batch.
            let idx = rng.next_usize(held.len());
            let batch = held.remove(idx);
            ba.free(&batch);
        }

        // Sample fragmentation every 100 steps when there are free blocks.
        if _step % 100 == 0 && ba.free_count() > 0 {
            let ratio = fragmentation_ratio(&ba);
            frag_samples.push(ratio);
        }
    }

    // Clean up.
    for batch in held.drain(..) {
        ba.free(&batch);
    }
    assert_eq!(ba.free_count(), 256);

    // Report fragmentation stats.
    if !frag_samples.is_empty() {
        let min_frag = frag_samples.iter().cloned().fold(f64::MAX, f64::min);
        let max_frag = frag_samples.iter().cloned().fold(f64::MIN, f64::max);
        let mean_frag = frag_samples.iter().sum::<f64>() / frag_samples.len() as f64;

        eprintln!(
            "fragmentation ({} samples): min={:.4}, mean={:.4}, max={:.4}",
            frag_samples.len(),
            min_frag,
            mean_frag,
            max_frag
        );

        // Sanity checks: all values must be in [0.0, 1.0].
        assert!((0.0..=1.0).contains(&min_frag));
        assert!((0.0..=1.0).contains(&mean_frag));
        assert!((0.0..=1.0).contains(&max_frag));
    }
}

// ─── Fragmentation under targeted patterns ────────────────────────────

#[test]
fn fragmentation_under_checkerboard_pattern() {
    let ba = BlockAllocator::new(64, 4096, region(64));

    // Allocate even blocks, free odd blocks → checkerboard.
    let all = ba.alloc_contiguous(64).unwrap();
    let evens: Vec<BlockId> = all.iter().copied().filter(|b| b % 2 == 0).collect();
    let odds: Vec<BlockId> = all.iter().copied().filter(|b| b % 2 == 1).collect();
    ba.free(&evens);
    // Now: odd blocks used, evens free.

    // Every free block is isolated → fragmentation close to 1.0.
    let (longest, ratio) = fragmentation_stats(&ba);
    assert_eq!(longest, 1); // Every free block is isolated.
    assert!(ratio > 0.9, "expected high fragmentation, got {ratio:.4}");

    // alloc_contiguous(1) must succeed for every free block.
    for _ in 0..32 {
        let b = ba.alloc_contiguous(1).unwrap();
        // hold temporarily, then free.
        ba.free(&b);
    }

    ba.free(&odds);
    assert_eq!(ba.free_count(), 64);
}

#[test]
fn fragmentation_after_interleaved_free() {
    let ba = BlockAllocator::new(128, 4096, region(128));

    // Allocate all 128 blocks, then free every 5th in the first 100.
    // This creates a 100-block region with known fragmentation (runs of 4 free),
    // while keeping the tail 28 blocks allocated so they don't inflate
    // the longest-contiguous-free-run measurement.
    let a = ba.alloc_contiguous(100).unwrap(); // 0..99, first 100 blocks
    let tail = ba.alloc_contiguous(28).unwrap(); // 100..127, keep allocated
    for i in (0..100).step_by(5) {
        ba.free(&[a[i]]);
    }

    let (longest, ratio) = fragmentation_stats(&ba);
    // Within the first 100 blocks, freed every 5th → runs of max 4.
    assert!(longest <= 4, "longest free run {longest} > 4");
    assert!(ratio > 0.0);

    // alloc_any(20) should still succeed (scattered across holes).
    let b = ba.alloc_any(20).unwrap();
    assert_eq!(b.len(), 20);

    ba.free(&a);
    ba.free(&tail);
    ba.free(&b);
    assert_eq!(ba.free_count(), 128);
}

#[test]
fn fragmentation_satisfies_requests_under_moderate_churn() {
    let ba = BlockAllocator::new(256, 4096, region(256));
    let mut rng = SeededRng::new(0x1234_5678_9abc_def0);
    let mut held: Vec<Vec<BlockId>> = Vec::new();

    // Phase 1: Build up fragmentation with many small allocs/frees.
    for _ in 0..500 {
        if rng.next_u32(100) < 60 {
            let n = rng.next_u32(4) + 1; // 1..4 blocks
            if let Ok(blocks) = ba.alloc(n) {
                held.push(blocks);
            }
        } else if !held.is_empty() {
            let idx = rng.next_usize(held.len());
            let batch = held.remove(idx);
            ba.free(&batch);
        }
        if held.len() > 40 {
            let idx = rng.next_usize(held.len());
            let batch = held.remove(idx);
            ba.free(&batch);
        }
    }

    // Phase 2: Under existing fragmentation, verify alloc_any still works.
    let free = ba.free_count();
    assert!(free > 0, "pool must have free blocks");

    let request = free.min(30);
    let b = ba.alloc_any(request as u32).unwrap();
    assert_eq!(b.len() as u64, request);
    ba.free(&b);

    // Cleanup.
    for batch in held.drain(..) {
        ba.free(&batch);
    }
    assert_eq!(ba.free_count(), 256);
}

#[test]
fn fragmentation_never_blocks_single_block_when_free_exists() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let mut rng = SeededRng::new(0xaaaa_bbbb_cccc_dddd);
    let mut held: Vec<Vec<BlockId>> = Vec::new();

    for _ in 0..800 {
        match rng.next_u32(100) {
            0..=59 => {
                let n = rng.next_u32(5) + 1;
                if let Ok(blocks) = ba.alloc(n) {
                    held.push(blocks);
                }
            }
            _ => {
                if !held.is_empty() {
                    let idx = rng.next_usize(held.len());
                    let batch = held.remove(idx);
                    ba.free(&batch);
                }
            }
        }

        // Invariant: alloc_contiguous(1) must succeed when free blocks exist.
        let fc = ba.free_count();
        if fc > 0 {
            let b = ba.alloc_contiguous(1);
            assert!(
                b.is_ok(),
                "alloc_contiguous(1) failed with {fc} free blocks after {} ops",
                held.len() + (800 - held.len())
            );
            if let Ok(block) = b {
                ba.free(&block);
            }
        }
    }

    for batch in held.drain(..) {
        ba.free(&batch);
    }
    assert_eq!(ba.free_count(), 128);
}

// ─── Fragmentation ratio sanity ───────────────────────────────────────

#[test]
fn fragmentation_ratio_zero_on_clean_pool() {
    let ba = BlockAllocator::new(64, 4096, region(64));
    let ratio = fragmentation_ratio(&ba);
    assert_eq!(ratio, 0.0);
}

#[test]
fn fragmentation_ratio_zero_when_all_blocks_free() {
    let ba = BlockAllocator::new(128, 4096, region(128));
    let a = ba.alloc_contiguous(50).unwrap();
    ba.free(&a);
    let ratio = fragmentation_ratio(&ba);
    assert_eq!(ratio, 0.0);
}

#[test]
fn fragmentation_ratio_zero_on_empty_pool() {
    let ba = BlockAllocator::new(16, 4096, region(16));
    ba.alloc_contiguous(16).unwrap();
    let ratio = fragmentation_ratio(&ba);
    assert_eq!(ratio, 0.0);
}
