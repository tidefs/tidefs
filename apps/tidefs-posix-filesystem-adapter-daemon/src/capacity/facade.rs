//! Capacity facade wrapping a shared tidefs_block_allocator::BlockAllocator.

use super::statfs_reply::StatfsReply;
use std::sync::{Arc, Mutex};
use tidefs_block_allocator::BlockAllocator;

#[derive(Clone, Debug)]
pub struct CapacityFacade {
    allocator: BlockAllocator,
    lifecycle: Arc<Mutex<CapacityLifecycle>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CapacityLifecycle {
    reserved_blocks: u64,
    committed_blocks: u64,
}

impl CapacityFacade {
    #[must_use]
    pub fn new(allocator: BlockAllocator) -> Self {
        Self {
            allocator,
            lifecycle: Arc::new(Mutex::new(CapacityLifecycle::default())),
        }
    }

    /// Create a facade seeded with lower-layer committed blocks.
    ///
    /// This is used when a mounted lower layer already contains allocated
    /// storage at adapter startup. Subsequent lower-layer free events can then
    /// release those committed blocks through [`Self::release_committed_blocks`].
    #[must_use]
    pub fn with_committed_blocks(allocator: BlockAllocator, committed_blocks: u64) -> Self {
        assert!(
            committed_blocks <= allocator.block_count(),
            "capacity committed baseline exceeds allocator blocks: committed={committed_blocks}, blocks={}",
            allocator.block_count()
        );
        Self {
            allocator,
            lifecycle: Arc::new(Mutex::new(CapacityLifecycle {
                reserved_blocks: 0,
                committed_blocks,
            })),
        }
    }

    #[must_use]
    pub fn statfs(&self) -> StatfsReply {
        let s = self.allocator.allocator_statfs();
        let lifecycle = self.lifecycle.lock().unwrap();
        let adapter_held = lifecycle
            .reserved_blocks
            .saturating_add(lifecycle.committed_blocks);
        StatfsReply {
            blocks: s.f_blocks,
            bfree: s.f_bfree.saturating_sub(adapter_held),
            bavail: s.f_bavail.saturating_sub(adapter_held),
            bsize: s.f_bsize,
            frsize: s.f_frsize,
            files: s.f_files,
            ffree: s.f_ffree,
            favail: s.f_favail,
            namemax: s.f_namemax,
        }
        .normalized()
    }

    #[must_use]
    pub fn block_size(&self) -> u32 {
        self.allocator.block_size()
    }
    #[must_use]
    pub fn block_count(&self) -> u64 {
        self.allocator.block_count()
    }
    #[must_use]
    pub fn free_count(&self) -> u64 {
        self.allocator.free_count()
    }
    #[must_use]
    pub fn allocator(&self) -> &BlockAllocator {
        &self.allocator
    }

    pub(crate) fn hold_reserved_blocks(&self, blocks: u64) {
        if blocks == 0 {
            return;
        }
        let mut lifecycle = self.lifecycle.lock().unwrap();
        lifecycle.reserved_blocks = lifecycle.reserved_blocks.saturating_add(blocks);
    }

    pub(crate) fn release_reserved_blocks(&self, blocks: u64) {
        if blocks == 0 {
            return;
        }
        let mut lifecycle = self.lifecycle.lock().unwrap();
        if lifecycle.reserved_blocks < blocks {
            let reserved_blocks = lifecycle.reserved_blocks;
            drop(lifecycle);
            panic!(
                "capacity reservation release underflow: reserved={reserved_blocks}, blocks={blocks}"
            );
        }
        lifecycle.reserved_blocks -= blocks;
    }

    pub(crate) fn commit_reserved_blocks(&self, blocks: u64) {
        if blocks == 0 {
            return;
        }
        let mut lifecycle = self.lifecycle.lock().unwrap();
        if lifecycle.reserved_blocks < blocks {
            let reserved_blocks = lifecycle.reserved_blocks;
            drop(lifecycle);
            panic!(
                "capacity reservation commit underflow: reserved={reserved_blocks}, blocks={blocks}"
            );
        }
        lifecycle.reserved_blocks -= blocks;
        lifecycle.committed_blocks = lifecycle.committed_blocks.saturating_add(blocks);
    }

    /// Release committed adapter-local blocks after lower layers free storage.
    ///
    /// Panics on underflow so callers do not silently mask a broken
    /// allocation/free event stream.
    pub fn release_committed_blocks(&self, blocks: u64) {
        if blocks == 0 {
            return;
        }
        let mut lifecycle = self.lifecycle.lock().unwrap();
        if lifecycle.committed_blocks < blocks {
            let committed_blocks = lifecycle.committed_blocks;
            drop(lifecycle);
            panic!(
                "capacity committed release underflow: committed={committed_blocks}, blocks={blocks}"
            );
        }
        lifecycle.committed_blocks -= blocks;
    }

    #[must_use]
    pub fn reserved_blocks(&self) -> u64 {
        self.lifecycle.lock().unwrap().reserved_blocks
    }

    #[must_use]
    pub fn committed_blocks(&self) -> u64 {
        self.lifecycle.lock().unwrap().committed_blocks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_block_allocator::Region;

    fn test_alloc() -> BlockAllocator {
        BlockAllocator::with_root_reserve(
            1000,
            4096,
            Region::new(0, BlockAllocator::required_bitmap_bytes(1000)),
            50,
        )
    }

    #[test]
    fn statfs_reflects_allocator() {
        let f = CapacityFacade::new(test_alloc());
        let r = f.statfs();
        assert_eq!(r.blocks, 1000);
        assert_eq!(r.bfree, 1000);
        assert_eq!(r.bavail, 950);
        assert_eq!(r.bsize, 4096);
    }

    #[test]
    fn statfs_reflects_committed_baseline() {
        let f = CapacityFacade::with_committed_blocks(test_alloc(), 12);
        let r = f.statfs();
        assert_eq!(r.blocks, 1000);
        assert_eq!(r.bfree, 988);
        assert_eq!(r.bavail, 938);
        assert_eq!(f.reserved_blocks(), 0);
        assert_eq!(f.committed_blocks(), 12);
    }

    #[test]
    #[should_panic(expected = "capacity committed baseline exceeds allocator blocks")]
    fn committed_baseline_rejects_overflow() {
        let _ = CapacityFacade::with_committed_blocks(test_alloc(), 1001);
    }

    #[test]
    fn statfs_after_alloc() {
        let a = test_alloc();
        a.alloc(30).unwrap();
        let f = CapacityFacade::new(a);
        let r = f.statfs();
        assert_eq!(r.bfree, 970);
        assert_eq!(r.bavail, 920);
    }

    #[test]
    fn properties() {
        let f = CapacityFacade::new(test_alloc());
        assert_eq!(f.block_size(), 4096);
        assert_eq!(f.block_count(), 1000);
        assert_eq!(f.free_count(), 1000);
    }

    #[test]
    fn statfs_subtracts_adapter_lifecycle_blocks() {
        let f = CapacityFacade::new(test_alloc());
        f.hold_reserved_blocks(10);
        let reserved = f.statfs();
        assert_eq!(reserved.bfree, 990);
        assert_eq!(reserved.bavail, 940);

        f.commit_reserved_blocks(4);
        let committed = f.statfs();
        assert_eq!(committed.bfree, 990);
        assert_eq!(committed.bavail, 940);
        assert_eq!(f.reserved_blocks(), 6);
        assert_eq!(f.committed_blocks(), 4);

        f.release_reserved_blocks(6);
        let released = f.statfs();
        assert_eq!(released.bfree, 996);
        assert_eq!(released.bavail, 946);
    }

    #[test]
    fn release_committed_blocks_restores_capacity_after_free() {
        let f = CapacityFacade::new(test_alloc());
        f.hold_reserved_blocks(10);
        f.commit_reserved_blocks(8);

        let committed = f.statfs();
        assert_eq!(committed.bfree, 990);
        assert_eq!(committed.bavail, 940);
        assert_eq!(f.reserved_blocks(), 2);
        assert_eq!(f.committed_blocks(), 8);

        f.release_committed_blocks(3);
        let partially_released = f.statfs();
        assert_eq!(partially_released.bfree, 993);
        assert_eq!(partially_released.bavail, 943);
        assert_eq!(f.reserved_blocks(), 2);
        assert_eq!(f.committed_blocks(), 5);

        f.release_committed_blocks(5);
        let fully_released = f.statfs();
        assert_eq!(fully_released.bfree, 998);
        assert_eq!(fully_released.bavail, 948);
        assert_eq!(f.reserved_blocks(), 2);
        assert_eq!(f.committed_blocks(), 0);
    }

    #[test]
    fn statfs_clamps_lifecycle_hold_beyond_allocator_free() {
        let f = CapacityFacade::new(test_alloc());
        f.hold_reserved_blocks(1500);

        let statfs = f.statfs();
        assert_eq!(statfs.blocks, 1000);
        assert_eq!(statfs.bfree, 0);
        assert_eq!(statfs.bavail, 0);
    }

    #[test]
    #[should_panic(expected = "capacity committed release underflow")]
    fn release_committed_blocks_rejects_underflow() {
        let f = CapacityFacade::new(test_alloc());
        f.hold_reserved_blocks(1);
        f.commit_reserved_blocks(1);

        f.release_committed_blocks(2);
    }

    // ── Zero-op lifecycle methods ─────────────────────────────────────

    #[test]
    fn hold_zero_blocks_is_noop() {
        let f = CapacityFacade::new(test_alloc());
        let before = f.statfs();
        f.hold_reserved_blocks(0);
        assert_eq!(f.statfs(), before);
        assert_eq!(f.reserved_blocks(), 0);
    }

    #[test]
    fn release_zero_reserved_blocks_is_noop() {
        let f = CapacityFacade::new(test_alloc());
        f.hold_reserved_blocks(5);
        let statfs_after_hold = f.statfs();
        f.release_reserved_blocks(0);
        assert_eq!(f.statfs(), statfs_after_hold);
        assert_eq!(f.reserved_blocks(), 5);
    }

    #[test]
    fn commit_zero_reserved_blocks_is_noop() {
        let f = CapacityFacade::new(test_alloc());
        f.hold_reserved_blocks(3);
        let statfs_before = f.statfs();
        let reserved_before = f.reserved_blocks();
        f.commit_reserved_blocks(0);
        assert_eq!(f.statfs(), statfs_before);
        assert_eq!(f.reserved_blocks(), reserved_before);
        assert_eq!(f.committed_blocks(), 0);
    }

    #[test]
    fn release_zero_committed_blocks_is_noop() {
        let f = CapacityFacade::new(test_alloc());
        f.hold_reserved_blocks(2);
        f.commit_reserved_blocks(2);
        let committed_before = f.committed_blocks();
        f.release_committed_blocks(0);
        assert_eq!(f.committed_blocks(), committed_before);
    }

    // ── Saturating overflow ───────────────────────────────────────────

    #[test]
    fn hold_reserved_blocks_saturates_at_u64_max() {
        let f = CapacityFacade::new(test_alloc());
        f.hold_reserved_blocks(u64::MAX);
        // Second hold should saturate, not panic or wrap
        f.hold_reserved_blocks(1);
        assert_eq!(f.reserved_blocks(), u64::MAX);
    }

    #[test]
    fn commit_reserved_blocks_saturates_committed_at_u64_max() {
        let f = CapacityFacade::new(test_alloc());
        // Manually set up a large reservation: hold-reserve then commit repeatedly
        f.hold_reserved_blocks(u64::MAX);
        f.commit_reserved_blocks(u64::MAX);
        f.hold_reserved_blocks(1);
        f.commit_reserved_blocks(1);
        assert_eq!(f.committed_blocks(), u64::MAX);
    }

    // ── Boundary: with_committed_blocks at exact block_count ──────────

    #[test]
    fn with_committed_blocks_at_exact_block_count() {
        let f = CapacityFacade::with_committed_blocks(test_alloc(), 1000);
        assert_eq!(f.committed_blocks(), 1000);
        let statfs = f.statfs();
        assert_eq!(statfs.blocks, 1000);
        assert_eq!(statfs.bfree, 0);
        assert_eq!(statfs.bavail, 0);
    }

    // ── allocator() returns a reference to the same allocator ─────────

    #[test]
    fn allocator_accessor_returns_same_backing_store() {
        let a = test_alloc();
        let f = CapacityFacade::new(a);
        let alloc_ref = f.allocator();
        assert_eq!(alloc_ref.block_count(), 1000);
        assert_eq!(alloc_ref.block_size(), 4096);
        assert_eq!(f.block_count(), alloc_ref.block_count());
    }

    // ── Clone produces independently usable facade ────────────────────

    #[test]
    fn clone_produces_sharing_facade() {
        let f = CapacityFacade::new(test_alloc());
        let f2 = f.clone();
        f.hold_reserved_blocks(3);
        // Both facades share the same lifecycle; reservation visible through either
        assert_eq!(f.reserved_blocks(), 3);
        assert_eq!(f2.reserved_blocks(), 3);
        assert_eq!(f.statfs(), f2.statfs());
    }

    // ── Debug output ──────────────────────────────────────────────────

    #[test]
    fn debug_output_is_nonempty() {
        let f = CapacityFacade::new(test_alloc());
        let debug = format!("{f:?}");
        assert!(!debug.is_empty());
        // Format again after lifecycle changes
        f.hold_reserved_blocks(7);
        let debug2 = format!("{f:?}");
        assert!(!debug2.is_empty());
    }

    // ── reserved_blocks / committed_blocks accessors ──────────────────

    #[test]
    fn reserved_and_committed_reflect_initial_state() {
        let f = CapacityFacade::new(test_alloc());
        assert_eq!(f.reserved_blocks(), 0);
        assert_eq!(f.committed_blocks(), 0);
    }

    #[test]
    fn reserved_and_committed_after_lifecycle_transitions() {
        let f = CapacityFacade::new(test_alloc());

        f.hold_reserved_blocks(10);
        assert_eq!(f.reserved_blocks(), 10);
        assert_eq!(f.committed_blocks(), 0);

        f.commit_reserved_blocks(6);
        assert_eq!(f.reserved_blocks(), 4);
        assert_eq!(f.committed_blocks(), 6);

        f.commit_reserved_blocks(4);
        assert_eq!(f.reserved_blocks(), 0);
        assert_eq!(f.committed_blocks(), 10);

        f.release_committed_blocks(10);
        assert_eq!(f.committed_blocks(), 0);
    }

    // ── statfs propagates block counts from allocator ─────────────────

    #[test]
    fn statfs_propagates_block_counts_from_allocator() {
        let a = test_alloc();
        let f = CapacityFacade::new(a);
        let statfs = f.statfs();
        assert_eq!(statfs.blocks, 1000);
        assert_eq!(statfs.bfree, 1000);
        assert_eq!(statfs.bavail, 950);
    }

    // ── Cumulative hold: multiple hold_reserved_blocks calls stack ────

    #[test]
    fn multiple_hold_calls_stack_reservation() {
        let f = CapacityFacade::new(test_alloc());
        f.hold_reserved_blocks(3);
        f.hold_reserved_blocks(5);
        assert_eq!(f.reserved_blocks(), 8);
        assert_eq!(f.statfs().bavail, 950 - 8);
    }

    // ── Partial commit: commit less than reserved ─────────────────────

    #[test]
    fn partial_commit_leaves_remainder_reserved() {
        let f = CapacityFacade::new(test_alloc());
        f.hold_reserved_blocks(10);
        f.commit_reserved_blocks(4);
        assert_eq!(f.reserved_blocks(), 6);
        assert_eq!(f.committed_blocks(), 4);
        assert_eq!(f.statfs().bavail, 950 - 10);
    }
}
