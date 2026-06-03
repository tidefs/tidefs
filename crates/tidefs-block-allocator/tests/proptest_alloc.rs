//! Property-based tests (proptest) for tidefs-block-allocator.
//!
//! Verifies allocation invariants under randomized workloads:
//!  - Alloc/free round-trip with double-alloc detection
//!  - Capacity monotonicity under interleaved alloc/free
//!  - Fragmentation bound: contiguous-free lower-bound invariant
//!  - Strategy commutativity between alloc/alloc_any/alloc_contiguous
//!
//! Worker slot: s8

use std::collections::HashSet;

use proptest::prelude::*;
use tidefs_block_allocator::{BlockAllocator, BlockId, Region};

// ── helpers ───────────────────────────────────────────────────────────

fn region(block_count: u64) -> Region {
    Region::new(0, BlockAllocator::required_bitmap_bytes(block_count))
}

/// Small pool (64 blocks, 4K block size) for most tests.
fn small_pool() -> BlockAllocator {
    BlockAllocator::new(64, 4096, region(64))
}

/// Larger pool for fragmentation stress tests.
fn medium_pool() -> BlockAllocator {
    BlockAllocator::new(256, 4096, region(256))
}

// ── Alloc/Free round-trip + no-double-alloc ────────────────────────────

proptest! {
    /// Sequential alloc then bulk-free: free_count must return to total.
    /// Each returned block ID must be unique within the same allocation
    /// batch and across batches (no double-alloc).
    #[test]
    fn alloc_free_roundtrip_no_double_alloc(
        batches in prop::collection::vec(1u32..8u32, 1..150)
    ) {
        let ba = small_pool();
        let total = ba.block_count();
        let mut held: Vec<Vec<BlockId>> = Vec::new();
        let mut ever_allocated: HashSet<BlockId> = HashSet::new();

        for &n in &batches {
            match ba.alloc(n) {
                Ok(blocks) => {
                    // No block allocated twice without intervening free.
                    for &b in &blocks {
                        prop_assert!(
                            !ever_allocated.contains(&b),
                            "double-alloc: block {b} already allocated"
                        );
                        ever_allocated.insert(b);
                    }
                    held.push(blocks);
                }
                Err(_) => {
                    // ENOSPC: drain and restart so the test doesn't stall.
                    for batch in held.drain(..) {
                        for &b in &batch {
                            ever_allocated.remove(&b);
                        }
                        ba.free(&batch);
                    }
                }
            }
            // Invariant: free_count never exceeds total.
            let fc = ba.free_count();
            prop_assert!(fc <= total, "free_count {fc} > total {total}");
        }

        // Drain remaining.
        for batch in &held {
            ba.free(batch);
        }

        prop_assert!(
            ba.free_count() == total,
            "free_count should be {} after full drain, got {}",
            total, ba.free_count());
    }
}

// ── Capacity monotonicity under interleaved alloc/free ─────────────────

/// A single operation in the interleaved workload.
#[derive(Debug, Clone)]
enum Op {
    /// Allocate `count` blocks (1..6).
    Alloc(u32),
    /// Free the allocation at the given index (wraps modulo held count).
    Free(usize),
}

fn op_strategy() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(
        prop_oneof![
            (1u32..6u32).prop_map(Op::Alloc),
            (0usize..50usize).prop_map(Op::Free),
        ],
        1..400,
    )
}

proptest! {
    /// Under arbitrary interleaved alloc/free, the free count never exceeds
    /// the total block count, and allocated bytes never exceed capacity.
    #[test]
    fn capacity_monotonicity_under_interleaved_ops(
        ops in op_strategy()
    ) {
        let ba = medium_pool();
        let total = ba.block_count();
        let block_size = ba.block_size() as u64;
        let mut held: Vec<Vec<BlockId>> = Vec::new();

        for op in &ops {
            match op {
                Op::Alloc(n) => {
                    if let Ok(blocks) = ba.alloc(*n) {
                        held.push(blocks);
                    }
                    // ENOSPC is fine.
                }
                Op::Free(idx) => {
                    if !held.is_empty() {
                        let i = idx % held.len();
                        let batch = held.remove(i);
                        ba.free(&batch);
                    }
                }
            }

            let fc = ba.free_count();
            let allocated = total - fc;
            prop_assert!(fc <= total,
                "free_count {fc} > total {total}");
            prop_assert!(
                allocated.saturating_mul(block_size) <= total.saturating_mul(block_size),
                "allocated bytes overflow"
            );

            // allocated_bytes <= total_capacity
            let allocated_bytes = allocated * block_size;
            let capacity = total * block_size;
            prop_assert!(allocated_bytes <= capacity,
                "allocated_bytes {allocated_bytes} > capacity {capacity}");
        }

        // Cleanup.
        for batch in held {
            ba.free(&batch);
        }
        prop_assert_eq!(ba.free_count(), total);
    }
}

// ── Fragmentation bound ─────────────────────────────────────────────────

proptest! {
    /// After many random alloc/free operations, alloc_contiguous can
    /// still find a single block when any blocks remain free.
    /// This is the weakest fragmentation invariant: no pathological
    /// bitmap state where free blocks exist but alloc_contiguous(1)
    /// fails.
    #[test]
    fn fragmentation_never_blocks_single_block_when_free_exists(
        ops in op_strategy()
    ) {
        let ba = medium_pool();
        let mut held: Vec<Vec<BlockId>> = Vec::new();

        for op in &ops {
            match op {
                Op::Alloc(n) => {
                    if let Ok(blocks) = ba.alloc(*n) {
                        held.push(blocks);
                    }
                }
                Op::Free(idx) => {
                    if !held.is_empty() {
                        let i = idx % held.len();
                        let batch = held.remove(i);
                        ba.free(&batch);
                    }
                }
            }

            // Whenever free blocks exist, alloc_contiguous(1) must succeed.
            let fc = ba.free_count();
            if fc > 0 {
                let block = ba.alloc_contiguous(1);
                prop_assert!(block.is_ok(),
                    "alloc_contiguous(1) failed with {fc} free blocks");
                if let Ok(b) = block {
                    held.push(b);
                }
            }
        }

        for batch in held {
            ba.free(&batch);
        }
    }
}

// ── Strategy commutativity ──────────────────────────────────────────────

proptest! {
    /// For any two allocation methods among alloc/alloc_any/alloc_contiguous,
    /// free(alloc_via_s1(n)) followed by alloc_via_s2(n) succeeds when
    /// free space suffices.
    #[test]
    fn strategy_commutativity(
        n in 1u32..16u32,
        use_any_first in any::<bool>(),
        use_any_second in any::<bool>(),
    ) {
        let ba = medium_pool();
        let total = ba.block_count();

        // First allocation via strategy 1.
        let first = if use_any_first {
            ba.alloc_any(n)
        } else {
            ba.alloc_contiguous(n)
        };

        prop_assert!(first.is_ok(),
            "first alloc({n}) failed with free_count={}",
            ba.free_count());
        let first_blocks = first.unwrap();
        let fc_after_alloc = ba.free_count();

        // Free then re-allocate via strategy 2.
        ba.free(&first_blocks);
        let fc_after_free = ba.free_count();
        prop_assert_eq!(fc_after_free, fc_after_alloc + n as u64,
            "free didn't restore {} blocks", n);

        let second = if use_any_second {
            ba.alloc_any(n)
        } else {
            ba.alloc_contiguous(n)
        };
        prop_assert!(second.is_ok(),
            "second alloc({n}) failed after free, free_count={}",
            ba.free_count());

        ba.free(&second.unwrap());
        prop_assert_eq!(ba.free_count(), total);
    }
}

// ── Large-pool stress: alloc/free sequence with drain ───────────────────

proptest! {
    /// On a larger pool, allocate varying-sized batches then free
    /// in reverse order. After drain, the pool must be fully free.
    #[test]
    fn large_pool_alloc_free_drain(
        batches in prop::collection::vec(1u32..20u32, 1..100)
    ) {
        let ba = BlockAllocator::new(512, 4096, region(512));
        let total = ba.block_count();
        let mut held: Vec<Vec<BlockId>> = Vec::new();

        for &n in &batches {
            match ba.alloc(n) {
                Ok(blocks) => held.push(blocks),
                Err(_) => {
                    // Drain and continue.
                    while let Some(batch) = held.pop() {
                        ba.free(&batch);
                    }
                }
            }
            prop_assert!(ba.free_count() <= total);
        }

        // Free in LIFO order (reverse).
        while let Some(batch) = held.pop() {
            ba.free(&batch);
        }

        prop_assert_eq!(ba.free_count(), total,
            "pool not fully free after drain");
    }
}

// ── Idempotent free safety ──────────────────────────────────────────────

proptest! {
    /// Freeing the same blocks multiple times must never corrupt free_count
    /// (idempotent free — already covered by the code, but verify
    /// under random workloads).
    #[test]
    fn random_double_free_idempotent(
        batches in prop::collection::vec(1u32..5u32, 1..100)
    ) {
        let ba = small_pool();
        let total = ba.block_count();
        let mut held: Vec<Vec<BlockId>> = Vec::new();

        for &n in &batches {
            if let Ok(blocks) = ba.alloc(n) {
                held.push(blocks);
            }
        }

        let _fc_before = ba.free_count();

        // Free all batches once.
        for batch in &held {
            ba.free(batch);
        }
        let after_first = ba.free_count();
        prop_assert!(
            after_first == total,
            "first free didn't restore to {}",
            total);

        // Free all batches again — must be idempotent.
        for batch in &held {
            ba.free(batch);
        }
        prop_assert_eq!(ba.free_count(), total,
            "double-free changed free_count");
    }
}

// ── Exhaustion-recovery ────────────────────────────────────────────────

proptest! {
    /// Exhaust the pool, free a random subset, then verify that exactly
    /// that many blocks can be re-allocated. Repeat multiple exhaustion/
    /// recovery cycles to exercise different exhaustion patterns.
    #[test]
    fn exhaustion_recovery_after_free(
        cycles in 1u32..8u32,
        pool_size in prop_oneof![Just(16u64), Just(32u64), Just(64u64), Just(128u64)],
    ) {
        let ba = BlockAllocator::new(pool_size, 4096, region(pool_size));
        let total = ba.block_count();

        for _ in 0..cycles {
            // Exhaust the pool with alloc_any.
            let mut held: Vec<BlockId> = Vec::new();
            while (held.len() as u64) < total {
                let remaining = (total - held.len() as u64).min(8);
                match ba.alloc_any(remaining as u32) {
                    Ok(blocks) => held.extend(blocks),
                    Err(_) => break,
                }
            }
            prop_assert_eq!(
                ba.free_count(), 0,
                "pool should be exhausted, free_count={}", ba.free_count()
            );

            // Free a subset of held blocks.
            let free_count = (held.len() as u64).max(2) / 2;
            let to_free: Vec<BlockId> = held[..free_count as usize].to_vec();
            ba.free(&to_free);

            prop_assert_eq!(
                ba.free_count(), free_count,
                "after freeing {} blocks, got free_count={}",
                free_count, ba.free_count()
            );

            // Re-allocate exactly the freed count via alloc_any. Must succeed.
            let recovered = ba.alloc_any(free_count as u32);
            prop_assert!(
                recovered.is_ok(),
                "alloc_any({}) failed after freeing {} blocks (exhaustion recovery)",
                free_count, free_count
            );
            let rec = recovered.unwrap();
            prop_assert_eq!(
                rec.len() as u64, free_count,
                "recovered {} blocks, expected {}",
                rec.len(), free_count
            );

            // Drain the remaining held blocks plus recovered for the next cycle.
            held = held[free_count as usize..].to_vec();
            held.extend(rec);
            ba.free(&held);
            prop_assert_eq!(
                ba.free_count(), total,
                "after drain, free_count={}, expected={}",
                ba.free_count(), total
            );
        }
    }
}

// ── Coalescing ─────────────────────────────────────────────────────────

proptest! {
    /// Allocate small batches, free them all, then verify that
    /// alloc_contiguous(total) succeeds — proof that adjacent
    /// freed extents coalesce.
    #[test]
    fn coalescing_after_batch_free_returns_full_pool(
        batches in prop::collection::vec(1u32..4u32, 5..30),
        pool_size in prop_oneof![Just(16u64), Just(32u64), Just(64u64)],
    ) {
        let ba = BlockAllocator::new(pool_size, 4096, region(pool_size));
        let total = ba.block_count();
        let mut held: Vec<Vec<BlockId>> = Vec::new();
        let mut allocated: u64 = 0;

        for &n in &batches {
            let need = n as u64;
            if allocated + need > total {
                // Drain and restart.
                for batch in held.drain(..) {
                    ba.free(&batch);
                }
                allocated = 0;
            }
            match ba.alloc(n) {
                Ok(blocks) => {
                    allocated += blocks.len() as u64;
                    held.push(blocks);
                }
                Err(_) => {
                    // Drain and retry.
                    for batch in held.drain(..) {
                        ba.free(&batch);
                    }
                    allocated = 0;
                    if let Ok(blocks) = ba.alloc(n) {
                        allocated += blocks.len() as u64;
                        held.push(blocks);
                    }
                }
            }
        }

        // Free everything.
        for batch in held.drain(..) {
            ba.free(&batch);
        }
        prop_assert_eq!(
            ba.free_count(), total,
            "free_count should be {} after freeing all, got {}",
            total, ba.free_count()
        );

        // Allocate the entire pool as a single contiguous run.
        // Coalescing must merge all freed extents into one.
        let big = ba.alloc_contiguous(total as u32);
        prop_assert!(
            big.is_ok(),
            "alloc_contiguous({}) should succeed after coalescing (free_count={})",
            total, ba.free_count()
        );
        let big_blocks = big.unwrap();
        prop_assert_eq!(
            big_blocks.len() as u64, total,
            "alloc_contiguous({}) returned {} blocks",
            total, big_blocks.len()
        );

        ba.free(&big_blocks);
        prop_assert_eq!(ba.free_count(), total);
    }
}

// ── Model-based test ───────────────────────────────────────────────────

/// A trivial `Vec<bool>` model of the block allocator, tracking which
/// blocks are allocated (true) or free (false). Runs the same operation
/// sequence alongside the real `BlockAllocator` and asserts equivalent
/// outcomes.
struct VecModel {
    blocks: Vec<bool>,
    free_count: u64,
}

impl VecModel {
    fn new(block_count: u64) -> Self {
        Self {
            blocks: vec![false; block_count as usize],
            free_count: block_count,
        }
    }

    /// Try to allocate `n` free blocks (preferring a contiguous run,
    /// falling back to scattered). Returns block IDs or None if
    /// insufficient free blocks exist.
    fn alloc(&mut self, n: u32) -> Option<Vec<u64>> {
        let need = n as u64;
        if need == 0 || need > self.free_count {
            return None;
        }
        let total = self.blocks.len() as u64;
        // Try contiguous first (linear scan from 0).
        let mut run_start: Option<u64> = None;
        let mut run_len: u64 = 0;
        for i in 0..total {
            if !self.blocks[i as usize] {
                if run_start.is_none() {
                    run_start = Some(i);
                }
                run_len += 1;
                if run_len >= need {
                    let start = run_start.unwrap();
                    let ids: Vec<u64> = (start..start + need).collect();
                    for &id in &ids {
                        self.blocks[id as usize] = true;
                    }
                    self.free_count -= need;
                    return Some(ids);
                }
            } else {
                run_start = None;
                run_len = 0;
            }
        }
        // Wrap-around check: contiguous run may span end->start boundary.
        let suffix_free = (0..total)
            .rev()
            .take_while(|&i| !self.blocks[i as usize])
            .count() as u64;
        let prefix_free = (0..total).take_while(|&i| !self.blocks[i as usize]).count() as u64;
        if suffix_free + prefix_free >= need {
            let first = total.saturating_sub(need.min(suffix_free));
            if suffix_free >= need {
                let ids: Vec<u64> = (first..first + need).collect();
                for &id in &ids {
                    self.blocks[id as usize] = true;
                }
                self.free_count -= need;
                return Some(ids);
            } else {
                let mut ids = Vec::with_capacity(need as usize);
                for i in first..total {
                    ids.push(i);
                }
                for i in 0..(need - suffix_free) {
                    ids.push(i);
                }
                for &id in &ids {
                    self.blocks[id as usize] = true;
                }
                self.free_count -= need;
                return Some(ids);
            }
        }
        // Fall back to scattered (alloc_any).
        let mut ids = Vec::with_capacity(need as usize);
        for (i, used) in self.blocks.iter_mut().enumerate() {
            if !*used {
                *used = true;
                ids.push(i as u64);
                if ids.len() as u64 >= need {
                    self.free_count -= need;
                    return Some(ids);
                }
            }
        }
        None
    }

    /// Free a set of blocks. Idempotent for already-free blocks.
    fn free(&mut self, blocks: &[u64]) {
        for &id in blocks {
            if (id as usize) < self.blocks.len() && self.blocks[id as usize] {
                self.blocks[id as usize] = false;
                self.free_count += 1;
            }
        }
    }
}

proptest! {
    /// Run identical operation sequences against a `Vec<bool>` model
    /// and the real `BlockAllocator`, asserting that both agree on
    /// allocation success/failure and free_count at every step.
    #[test]
    fn model_agreement_across_random_ops(
        ops in op_strategy(),
        pool_size in prop_oneof![Just(16u64), Just(32u64), Just(64u64), Just(128u64)],
    ) {
        let ba = BlockAllocator::new(pool_size, 4096, region(pool_size));
        let mut model = VecModel::new(pool_size);
        let mut held: Vec<Vec<BlockId>> = Vec::new();
        let mut model_held: Vec<Vec<u64>> = Vec::new();

        for op in &ops {
            match op {
                Op::Alloc(n) => {
                    let real_result = ba.alloc(*n);
                    let model_result = model.alloc(*n);

                    // Both should agree on success/failure.
                    prop_assert_eq!(
                        real_result.is_ok(),
                        model_result.is_some(),
                        "model disagreement at alloc({}): real={:?}, model={:?}",
                        n,
                        real_result.as_ref().map(|v| v.len()),
                        model_result.as_ref().map(|v| v.len()),
                    );

                    if let Ok(blocks) = real_result {
                        held.push(blocks);
                    }
                    if let Some(blocks) = model_result {
                        model_held.push(blocks);
                    }

                    prop_assert_eq!(
                        ba.free_count(), model.free_count,
                        "free_count mismatch after alloc({})", n
                    );
                }
                Op::Free(idx) => {
                    if !held.is_empty() {
                        let i = idx % held.len();
                        let batch = held.remove(i);
                        let model_batch = model_held.remove(i);
                        ba.free(&batch);
                        model.free(&model_batch);
                    }
                    prop_assert_eq!(
                        ba.free_count(), model.free_count,
                        "free_count mismatch after free"
                    );
                }
            }
        }

        // Drain remaining.
        for batch in held.drain(..) {
            ba.free(&batch);
        }
        for batch in model_held.drain(..) {
            model.free(&batch);
        }
        prop_assert_eq!(
            ba.free_count(), model.free_count,
            "final free_count mismatch: real={}, model={}",
            ba.free_count(), model.free_count
        );
    }
}

// ── Statfs consistency under random workloads ─────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]
    /// After arbitrary interleaved alloc/free sequences, the `Statfs`
    /// output must be internally consistent and match the allocator's
    /// own counters: `f_blocks == block_count`, `f_bfree == free_count`,
    /// `f_bavail` accounts for root reserve, and `f_bsize` matches
    /// the configured block size. This verifies that statfs remains
    /// correct across at least 1,000 randomized scenarios.
    #[test]
    fn statfs_consistency_under_random_workload(
        ops in op_strategy(),
        pool_size in prop_oneof![Just(16u64), Just(64u64), Just(256u64)],
        with_root_reserve in any::<bool>(),
    ) {
        let root_reserve = if with_root_reserve { pool_size / 8 } else { 0 };
        let ba = BlockAllocator::with_topology(
            pool_size, 4096, region(pool_size),
            Default::default(), root_reserve,
        );
        let total = ba.block_count();
        let block_size = ba.block_size() as u64;
        let mut held: Vec<Vec<BlockId>> = Vec::new();

        for op in &ops {
            match op {
                Op::Alloc(n) => {
                    if let Ok(blocks) = ba.alloc(*n) {
                        held.push(blocks);
                    }
                }
                Op::Free(idx) => {
                    if !held.is_empty() {
                        let i = idx % held.len();
                        let batch = held.remove(i);
                        ba.free(&batch);
                    }
                }
            }

            let s = ba.allocator_statfs();
            prop_assert_eq!(s.f_blocks, total,
                "statfs.f_blocks mismatch: {} != {}", s.f_blocks, total);
            prop_assert_eq!(s.f_bfree, ba.free_count(),
                "statfs.f_bfree {} != free_count {}", s.f_bfree, ba.free_count());
            prop_assert_eq!(s.f_bsize, block_size,
                "statfs.f_bsize mismatch");
            prop_assert_eq!(s.f_frsize, block_size,
                "statfs.f_frsize != f_bsize");

            // f_bavail: free blocks minus root reserve (floor at 0).
            let expected_bavail = ba.free_count().saturating_sub(root_reserve);
            prop_assert_eq!(s.f_bavail, expected_bavail,
                "statfs.f_bavail {} != free_count({}) - root_reserve({})",
                s.f_bavail, ba.free_count(), root_reserve);

            // f_bfree + used <= f_blocks (integer invariant).
            let used = total - ba.free_count();
            prop_assert!(ba.free_count() + used == total,
                "free + used != total");

            // f_bavail <= f_bfree.
            prop_assert!(s.f_bavail <= s.f_bfree,
                "f_bavail {} > f_bfree {}", s.f_bavail, s.f_bfree);
        }

        // Cleanup.
        for batch in held {
            ba.free(&batch);
        }
        let s = ba.allocator_statfs();
        prop_assert_eq!(s.f_bfree, total, "final f_bfree not total");
        prop_assert_eq!(s.f_bavail, total.saturating_sub(root_reserve),
            "final f_bavail incorrect");
    }
}
