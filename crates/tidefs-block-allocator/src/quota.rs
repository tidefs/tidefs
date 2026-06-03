//! Per-inode quota tracking table.
//!
//! Tracks reserved-but-not-yet-committed block counts per inode
//! and committed (actually allocated) block counts, enforcing
//! per-inode hard limits. The table participates in the allocation
//! state machine: `reserve` checks and increments the reserved count,
//! `commit` transfers from reserved to committed, `release` rolls
//! back a reservation, and `uncommit` decreases committed after
//! lower-layer deallocation. Entries are lazily created on first access
//! and pruned when both counts reach zero.
//!
//! This module is called only from `BlockAllocator`'s write-locked
//! methods; it is not safe for direct concurrent use.

use crate::error::AllocError;
use tidefs_types_vfs_core::InodeId;

/// Default per-inode block quota when none is set explicitly.
pub const DEFAULT_QUOTA_BLOCKS: u64 = 0; // 0 = no limit

/// Tracked state for one inode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct InodeQuotaSlot {
    /// Blocks reserved but not yet committed.
    reserved: u64,
    /// Blocks actually committed (counted against the limit).
    committed: u64,
    /// Hard limit on total committed blocks (0 = unlimited).
    limit: u64,
}

/// Per-inode quota table.
///
/// Small table: entries are created on first reserve/commit and
/// lazily pruned when both reserved and committed reach zero.
/// For now a simple Vec<(InodeId, InodeQuotaSlot)> suffices;
/// large-scale deployments can replace with a hash map later.
#[derive(Clone, Debug, Default)]
pub struct QuotaTable {
    entries: Vec<(InodeId, InodeQuotaSlot)>,
}

impl QuotaTable {
    /// Create an empty quota table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Set a hard block limit for an inode. 0 = unlimited.
    pub fn set_limit(&mut self, inode: InodeId, limit: u64) {
        let slot = self.slot_mut(inode);
        slot.limit = limit;
    }

    /// Try to reserve `nblocks` for an inode without committing.
    ///
    /// Returns `Err(AllocError::QuotaExceeded)` if `committed + reserved + nblocks > limit`
    /// (when limit != 0).
    #[must_use = "reservation result must be consumed to detect QuotaExceeded"]
    pub fn reserve(&mut self, inode: InodeId, nblocks: u64) -> Result<(), AllocError> {
        if nblocks == 0 {
            return Ok(());
        }
        let slot = self.slot_mut(inode);
        let total = slot
            .committed
            .saturating_add(slot.reserved)
            .saturating_add(nblocks);
        if slot.limit != 0 && total > slot.limit {
            return Err(AllocError::QuotaExceeded);
        }
        slot.reserved = slot.reserved.saturating_add(nblocks);
        Ok(())
    }

    /// Commit a prior reserve: move `nblocks` from reserved to committed.
    ///
    /// Panics if `nblocks > reserved`; this is a programmer error.
    pub fn commit(&mut self, inode: InodeId, nblocks: u64) {
        if nblocks == 0 {
            return;
        }
        let slot = self.slot_mut(inode);
        assert!(
            slot.reserved >= nblocks,
            "commit underflow: reserved={}, nblocks={nblocks}",
            slot.reserved
        );
        slot.reserved -= nblocks;
        slot.committed = slot.committed.saturating_add(nblocks);
    }

    /// Release a prior reserve without allocating.
    ///
    /// Panics if `nblocks > reserved`.
    pub fn release(&mut self, inode: InodeId, nblocks: u64) {
        if nblocks == 0 {
            return;
        }
        let slot = self.slot_mut(inode);
        assert!(
            slot.reserved >= nblocks,
            "release underflow: reserved={}, nblocks={nblocks}",
            slot.reserved
        );
        slot.reserved -= nblocks;
    }

    /// Decrease committed count (blocks freed).
    pub fn uncommit(&mut self, inode: InodeId, nblocks: u64) {
        if nblocks == 0 {
            return;
        }
        let slot = self.slot_mut(inode);
        slot.committed = slot.committed.saturating_sub(nblocks);
    }

    /// Return (reserved, committed) for an inode.
    #[must_use]
    pub fn counts(&self, inode: InodeId) -> (u64, u64) {
        if let Some(slot) = self.find(inode) {
            (slot.reserved, slot.committed)
        } else {
            (0, 0)
        }
    }

    /// Sum of committed blocks across all inodes.
    #[must_use]
    pub fn total_committed(&self) -> u64 {
        self.entries.iter().map(|(_, s)| s.committed).sum()
    }

    /// Number of tracked inodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if no inodes are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find an entry by inode.
    fn find(&self, inode: InodeId) -> Option<&InodeQuotaSlot> {
        self.entries
            .iter()
            .find(|(id, _)| *id == inode)
            .map(|(_, s)| s)
    }

    /// Find or create a slot for an inode.
    fn slot_mut(&mut self, inode: InodeId) -> &mut InodeQuotaSlot {
        let pos = self.entries.iter().position(|(id, _)| *id == inode);
        if let Some(idx) = pos {
            &mut self.entries[idx].1
        } else {
            self.entries.push((inode, InodeQuotaSlot::default()));
            &mut self.entries.last_mut().unwrap().1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_within_unlimited() {
        let mut qt = QuotaTable::new();
        let ino = InodeId::new(1);
        assert!(qt.reserve(ino, 100).is_ok());
        let (r, c) = qt.counts(ino);
        assert_eq!(r, 100);
        assert_eq!(c, 0);
    }

    #[test]
    fn reserve_exceeds_limit() {
        let mut qt = QuotaTable::new();
        let ino = InodeId::new(1);
        qt.set_limit(ino, 50);
        assert!(qt.reserve(ino, 100).is_err());
        assert_eq!(qt.counts(ino), (0, 0));
    }

    #[test]
    fn commit_and_release_flow() {
        let mut qt = QuotaTable::new();
        let ino = InodeId::new(2);
        qt.reserve(ino, 30).unwrap();
        qt.commit(ino, 10);
        let (r, c) = qt.counts(ino);
        assert_eq!(r, 20);
        assert_eq!(c, 10);

        qt.release(ino, 20);
        let (r, c) = qt.counts(ino);
        assert_eq!(r, 0);
        assert_eq!(c, 10);
    }

    #[test]
    fn limit_checks_committed_plus_reserved() {
        let mut qt = QuotaTable::new();
        let ino = InodeId::new(3);
        qt.set_limit(ino, 100);
        qt.reserve(ino, 60).unwrap();
        qt.commit(ino, 60);
        // Now committed=60, reserved=0. We can reserve 40 more.
        assert!(qt.reserve(ino, 40).is_ok());
        // But not 41.
        assert!(qt.reserve(ino, 1).is_err());
    }

    #[test]
    fn uncommit_reduces_count() {
        let mut qt = QuotaTable::new();
        let ino = InodeId::new(4);
        qt.reserve(ino, 50).unwrap();
        qt.commit(ino, 50);
        qt.uncommit(ino, 20);
        let (_r, c) = qt.counts(ino);
        assert_eq!(c, 30);
    }

    #[test]
    fn total_committed_across_inodes() {
        let mut qt = QuotaTable::new();
        qt.reserve(InodeId::new(1), 10).unwrap();
        qt.commit(InodeId::new(1), 10);
        qt.reserve(InodeId::new(2), 20).unwrap();
        qt.commit(InodeId::new(2), 20);
        assert_eq!(qt.total_committed(), 30);
    }
}
