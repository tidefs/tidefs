// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Epoch-gated deterministic slot allocator keyed on (epoch, node_id, write_txg).
//!
//! Produces collision-free slot assignments within an epoch. The slot index
//! for a given (node_id, write_txg) is deterministic via a fixed
//! multiply-rotate-xor hash. No two distinct (node_id, write_txg) pairs
//! can share the same slot index.

use std::collections::{HashMap, HashSet};

use tidefs_membership_epoch::EpochId;

/// Errors from slot-allocation operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SlotAllocError {
    /// The request epoch does not match the allocator's current epoch.
    #[error("epoch mismatch: allocator at {current:?}, request at {request:?}")]
    EpochMismatch { current: EpochId, request: EpochId },

    /// The (node_id, write_txg) key already has an allocated slot.
    #[error("slot collision: (node={node}, txg={txg}) already allocated in epoch {epoch:?}")]
    SlotCollision { epoch: EpochId, node: u64, txg: u64 },

    /// The allocator has no remaining slots for this epoch.
    #[error("slot table full: max {max_slots} slots in epoch {epoch:?}")]
    TableFull { max_slots: usize, epoch: EpochId },
}

/// A deterministic slot-assignment descriptor produced by [`SlotAllocator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotAssignment {
    /// The epoch this slot belongs to.
    pub epoch: EpochId,
    /// The node that owns this slot.
    pub node_id: u64,
    /// Write transaction-group identifier.
    pub write_txg: u64,
    /// Deterministic slot index within the epoch (0-based).
    pub slot_index: u64,
}

// ---------------------------------------------------------------------------
// SlotAllocator
// ---------------------------------------------------------------------------

/// Epoch-gated deterministic slot allocator.
///
/// Each call to [`allocate`](Self::allocate) hashes the triple
/// `(epoch.0, node_id, write_txg)` with a deterministic mix to
/// produce a starting slot index in `[0, max_slots)`. Linear probing
/// finds the next free slot index. No two distinct `(node_id,
/// write_txg)` pairs are assigned the same slot index.
///
/// # Epoch gating
///
/// The allocator is constructed with an epoch. All allocations must match
/// that epoch; stale-epoch requests are rejected with
/// [`SlotAllocError::EpochMismatch`].
pub struct SlotAllocator {
    /// The epoch this allocator is bound to.
    epoch: EpochId,
    /// Maximum number of slots in this epoch.
    max_slots: usize,
    /// Mapping from (node_id, write_txg) key to assigned slot_index.
    assigned: HashMap<(u64, u64), u64>,
    /// Set of occupied slot indices in this epoch.
    occupied: HashSet<u64>,
}

impl SlotAllocator {
    /// Create a new epoch-gated slot allocator.
    ///
    /// Returns `None` if `max_slots` is zero.
    pub fn new(epoch: EpochId, max_slots: usize) -> Option<Self> {
        if max_slots == 0 {
            return None;
        }
        Some(Self {
            epoch,
            max_slots,
            assigned: HashMap::new(),
            occupied: HashSet::new(),
        })
    }

    /// The epoch this allocator is bound to.
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// Maximum slots in this epoch.
    pub fn max_slots(&self) -> usize {
        self.max_slots
    }

    /// Number of slots already allocated.
    pub fn allocated_count(&self) -> usize {
        self.assigned.len()
    }

    /// Number of slots still available.
    pub fn remaining(&self) -> usize {
        self.max_slots.saturating_sub(self.assigned.len())
    }

    /// True when no remaining slots are available.
    pub fn is_full(&self) -> bool {
        self.assigned.len() >= self.max_slots
    }

    // ------------------------------------------------------------------
    // Allocation
    // ------------------------------------------------------------------

    /// Allocate a deterministic, collision-free slot for
    /// (epoch, node_id, write_txg).
    ///
    /// The starting slot index is computed by mixing the triple with a
    /// fixed multiply-rotate-xor function, then reducing modulo
    /// `max_slots`. If the slot is already occupied by a different
    /// `(node_id, write_txg)` pair, linear probing finds the next free
    /// slot. Duplicate allocation of the same key returns
    /// [`SlotAllocError::SlotCollision`].
    pub fn allocate(
        &mut self,
        request_epoch: EpochId,
        node_id: u64,
        write_txg: u64,
    ) -> Result<SlotAssignment, SlotAllocError> {
        if request_epoch != self.epoch {
            return Err(SlotAllocError::EpochMismatch {
                current: self.epoch,
                request: request_epoch,
            });
        }

        let key = (node_id, write_txg);
        if self.assigned.contains_key(&key) {
            return Err(SlotAllocError::SlotCollision {
                epoch: self.epoch,
                node: node_id,
                txg: write_txg,
            });
        }

        if self.is_full() {
            return Err(SlotAllocError::TableFull {
                max_slots: self.max_slots,
                epoch: self.epoch,
            });
        }

        let base = hash_triple(self.epoch, node_id, write_txg) % self.max_slots as u64;

        for offset in 0..self.max_slots as u64 {
            let idx = (base + offset) % self.max_slots as u64;
            if !self.occupied.contains(&idx) {
                self.occupied.insert(idx);
                self.assigned.insert(key, idx);
                return Ok(SlotAssignment {
                    epoch: self.epoch,
                    node_id,
                    write_txg,
                    slot_index: idx,
                });
            }
        }

        Err(SlotAllocError::TableFull {
            max_slots: self.max_slots,
            epoch: self.epoch,
        })
    }

    /// Check whether a specific slot index is occupied.
    pub fn is_occupied(&self, slot_index: u64) -> bool {
        self.occupied.contains(&slot_index)
    }

    /// Check whether a specific (node_id, write_txg, slot_index)
    /// triple is the currently assigned entry.
    pub fn is_allocated(&self, node_id: u64, write_txg: u64, slot_index: u64) -> bool {
        self.assigned.get(&(node_id, write_txg)).copied() == Some(slot_index)
    }

    /// Look up a previously allocated slot by (node_id, write_txg) key.
    ///
    /// Returns `None` if no slot with that key is currently allocated.
    pub fn lookup(&self, node_id: u64, write_txg: u64) -> Option<SlotAssignment> {
        let idx = self.assigned.get(&(node_id, write_txg))?;
        Some(SlotAssignment {
            epoch: self.epoch,
            node_id,
            write_txg,
            slot_index: *idx,
        })
    }

    /// Release a slot back to the free pool.
    ///
    /// Returns `true` if the entry was present and removed.
    pub fn release(&mut self, node_id: u64, write_txg: u64) -> bool {
        let key = (node_id, write_txg);
        if let Some(idx) = self.assigned.remove(&key) {
            self.occupied.remove(&idx);
            true
        } else {
            false
        }
    }

    /// Iterate over all assigned slot indices (in arbitrary order).
    pub fn assigned_slots(&self) -> impl Iterator<Item = &u64> {
        self.occupied.iter()
    }
}

// ---------------------------------------------------------------------------
// TdmaSchedule impl
// ---------------------------------------------------------------------------

use crate::TdmaSchedule;

impl TdmaSchedule for SlotAllocator {
    type Slot = SlotAssignment;
    type Error = SlotAllocError;

    fn allocate_slot(
        &mut self,
        epoch: EpochId,
        node_id: u64,
        write_txg: u64,
    ) -> Result<Self::Slot, Self::Error> {
        self.allocate(epoch, node_id, write_txg)
    }

    fn lookup_slot(&self, node_id: u64, write_txg: u64) -> Option<Self::Slot> {
        self.lookup(node_id, write_txg)
    }

    fn release_slot(&mut self, node_id: u64, write_txg: u64) -> bool {
        self.release(node_id, write_txg)
    }

    fn max_slots(&self) -> usize {
        self.max_slots()
    }

    fn allocated_count(&self) -> usize {
        self.allocated_count()
    }
}

// ---------------------------------------------------------------------------
// Deterministic triple hash
// ---------------------------------------------------------------------------

/// Mix (epoch, node_id, write_txg) into a single u64.
///
/// Uses multiply-rotate-xor: deterministic and fast, with no per-process
/// random seed.
fn hash_triple(epoch: EpochId, node_id: u64, write_txg: u64) -> u64 {
    let mut h: u64 = epoch.0.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h = h.rotate_left(31).wrapping_add(node_id);
    h = h.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h = h.rotate_left(27).wrapping_add(write_txg);
    h = h.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^= h >> 33;
    h
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> EpochId {
        EpochId(7)
    }

    fn test_allocator() -> SlotAllocator {
        SlotAllocator::new(test_epoch(), 64).unwrap()
    }

    #[test]
    fn rejects_zero_max_slots() {
        assert!(SlotAllocator::new(EpochId(1), 0).is_none());
    }

    #[test]
    fn returns_epoch_and_capacity() {
        let a = test_allocator();
        assert_eq!(a.epoch(), test_epoch());
        assert_eq!(a.max_slots(), 64);
        assert_eq!(a.remaining(), 64);
        assert_eq!(a.allocated_count(), 0);
        assert!(!a.is_full());
    }

    #[test]
    fn allocate_single_slot() {
        let mut a = test_allocator();
        let slot = a.allocate(test_epoch(), 10, 1).unwrap();
        assert_eq!(slot.epoch, test_epoch());
        assert_eq!(slot.node_id, 10);
        assert_eq!(slot.write_txg, 1);
        assert!(slot.slot_index < 64);
        assert_eq!(a.allocated_count(), 1);
        assert!(a.is_occupied(slot.slot_index));
    }

    #[test]
    fn allocate_is_deterministic() {
        let mut a1 = test_allocator();
        let mut a2 = test_allocator();
        let s1 = a1.allocate(test_epoch(), 42, 3).unwrap();
        let s2 = a2.allocate(test_epoch(), 42, 3).unwrap();
        assert_eq!(s1.slot_index, s2.slot_index);
    }

    #[test]
    fn different_triples_different_slots() {
        let mut a = test_allocator();
        let s1 = a.allocate(test_epoch(), 10, 1).unwrap();
        let s2 = a.allocate(test_epoch(), 20, 1).unwrap();
        assert_ne!(s1.slot_index, s2.slot_index);
    }

    #[test]
    fn same_node_different_txg_different_slots() {
        let mut a = test_allocator();
        let s1 = a.allocate(test_epoch(), 10, 1).unwrap();
        let s2 = a.allocate(test_epoch(), 10, 2).unwrap();
        assert_ne!(s1.slot_index, s2.slot_index);
    }

    #[test]
    fn wrong_epoch_rejected() {
        let mut a = test_allocator();
        let err = a.allocate(EpochId(99), 10, 1).unwrap_err();
        assert!(matches!(err, SlotAllocError::EpochMismatch { .. }));
    }

    #[test]
    fn duplicate_key_rejected() {
        let mut a = test_allocator();
        a.allocate(test_epoch(), 10, 1).unwrap();
        let err = a.allocate(test_epoch(), 10, 1).unwrap_err();
        assert!(matches!(
            err,
            SlotAllocError::SlotCollision {
                node: 10,
                txg: 1,
                ..
            }
        ));
    }

    #[test]
    fn allocate_until_full_then_error() {
        let mut a = SlotAllocator::new(EpochId(1), 4).unwrap();
        for i in 1..=4u64 {
            a.allocate(EpochId(1), i, 0).unwrap();
        }
        assert!(a.is_full());
        let err = a.allocate(EpochId(1), 999, 0).unwrap_err();
        assert!(matches!(err, SlotAllocError::TableFull { .. }));
    }

    #[test]
    fn release_frees_and_allows_reuse() {
        let mut a = SlotAllocator::new(EpochId(1), 4).unwrap();
        let s1 = a.allocate(EpochId(1), 10, 1).unwrap();
        assert_eq!(a.allocated_count(), 1);

        assert!(a.release(10, 1));
        assert_eq!(a.allocated_count(), 0);
        assert!(!a.is_occupied(s1.slot_index));

        let s2 = a.allocate(EpochId(1), 10, 1).unwrap();
        assert_eq!(s1.slot_index, s2.slot_index);
    }

    #[test]
    fn release_unknown_is_noop() {
        let mut a = test_allocator();
        assert!(!a.release(99, 99));
    }

    #[test]
    fn separate_epochs_independent() {
        let mut a1 = SlotAllocator::new(EpochId(1), 64).unwrap();
        let mut a2 = SlotAllocator::new(EpochId(2), 64).unwrap();
        let s1 = a1.allocate(EpochId(1), 10, 5).unwrap();
        let s2 = a2.allocate(EpochId(2), 10, 5).unwrap();
        assert_ne!(s1.slot_index, s2.slot_index);
        assert_ne!(s1.epoch, s2.epoch);
    }

    #[test]
    fn stress_allocate_full_table() {
        let mut a = SlotAllocator::new(EpochId(1), 1024).unwrap();
        for i in 1..=1024u64 {
            a.allocate(EpochId(1), i, 0).unwrap();
        }
        assert!(a.is_full());
        assert_eq!(a.allocated_count(), 1024);
    }

    #[test]
    fn deterministic_across_instances() {
        for epoch in [1u64, 2, 3] {
            for node_id in [10u64, 20, 30] {
                for txg in [0u64, 1, 2] {
                    let mut a1 = SlotAllocator::new(EpochId(epoch), 256).unwrap();
                    let mut a2 = SlotAllocator::new(EpochId(epoch), 256).unwrap();
                    let s1 = a1.allocate(EpochId(epoch), node_id, txg).unwrap();
                    let s2 = a2.allocate(EpochId(epoch), node_id, txg).unwrap();
                    assert_eq!(
                        s1.slot_index, s2.slot_index,
                        "mismatch epoch={epoch} node={node_id} txg={txg}"
                    );
                }
            }
        }
    }

    #[test]
    fn no_collision_across_different_nodes() {
        // Fill the entire table: every (node_id, txg) pair must get a
        // distinct slot index.
        let mut a = SlotAllocator::new(EpochId(1), 1024).unwrap();
        let mut seen = HashSet::new();
        for i in 1..=1024u64 {
            let slot = a.allocate(EpochId(1), i, 0).unwrap();
            assert!(
                seen.insert(slot.slot_index),
                "duplicate slot_index={} for node={i}",
                slot.slot_index
            );
        }
        assert!(a.is_full());
    }

    #[test]
    fn lookup_returns_correct_slot() {
        let mut a = test_allocator();
        let assigned = a.allocate(test_epoch(), 42, 3).unwrap();
        let found = a.lookup(42, 3).unwrap();
        assert_eq!(assigned.slot_index, found.slot_index);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let a = test_allocator();
        assert!(a.lookup(99, 99).is_none());
    }

    #[test]
    fn is_allocated_triple_check() {
        let mut a = test_allocator();
        let s = a.allocate(test_epoch(), 10, 1).unwrap();
        assert!(a.is_allocated(10, 1, s.slot_index));
        assert!(!a.is_allocated(10, 2, s.slot_index));
        assert!(!a.is_allocated(20, 1, s.slot_index));
        assert!(!a.is_allocated(10, 1, s.slot_index + 1));
    }
}
