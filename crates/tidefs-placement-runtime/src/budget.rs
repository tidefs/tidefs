// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Placement budget tracker.
//!
//! Per-node capacity tracking with lease-protected reservations.
//! Tracks available capacity per member, holds reservations during
//! placement cycles, and releases budget when reservations are committed
//! or retired.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_replication_model::ReplicatedSubjectId;

use crate::types::{BudgetReservation, BudgetReservationId, CycleId};

// ── Capacity tracking ─────────────────────────────────────────────────

/// Per-member capacity budget tracker.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MemberBudget {
    pub member_id: MemberId,
    /// Total capacity in bytes.
    pub total_bytes: u64,
    /// Currently used bytes (committed placements).
    pub used_bytes: u64,
    /// Reserved bytes (pending placements).
    pub reserved_bytes: u64,
    /// Soft high-water mark (fraction of capacity).
    pub high_water_mark_bytes: u64,
    /// Epoch this budget reflects.
    pub epoch: EpochId,
    /// Whether this member is accepting new placements.
    pub accepting: bool,
}

impl MemberBudget {
    #[must_use]
    pub fn new(member_id: MemberId, total_bytes: u64, epoch: EpochId) -> Self {
        let high_water = total_bytes.saturating_mul(85) / 100;
        Self {
            member_id,
            total_bytes,
            used_bytes: 0,
            reserved_bytes: 0,
            high_water_mark_bytes: high_water,
            epoch,
            accepting: true,
        }
    }

    /// Available capacity after accounting for used and reserved.
    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        let committed = self.used_bytes.saturating_add(self.reserved_bytes);
        self.total_bytes.saturating_sub(committed)
    }

    /// Whether this member can accept a placement of `size` bytes.
    #[must_use]
    pub fn can_accept(&self, size: u64) -> bool {
        self.accepting && self.available_bytes() >= size
    }

    /// Whether this member is above the high-water mark.
    #[must_use]
    pub fn is_above_high_water(&self) -> bool {
        let committed = self.used_bytes.saturating_add(self.reserved_bytes);
        committed > self.high_water_mark_bytes
    }

    /// Reserve capacity for a pending placement.
    pub fn reserve(&mut self, bytes: u64) -> Result<(), BudgetError> {
        if !self.can_accept(bytes) {
            return Err(BudgetError::InsufficientCapacity {
                member_id: self.member_id,
                available: self.available_bytes(),
                required: bytes,
            });
        }
        self.reserved_bytes = self.reserved_bytes.saturating_add(bytes);
        Ok(())
    }

    /// Commit a reservation (moves reserved → used).
    pub fn commit(&mut self, bytes: u64) {
        self.reserved_bytes = self.reserved_bytes.saturating_sub(bytes);
        self.used_bytes = self.used_bytes.saturating_add(bytes);
    }

    /// Release a reservation without committing.
    /// Retire used capacity (excess retirement, drain cleanup).
    pub fn retire_capacity(&mut self, bytes: u64) {
        self.used_bytes = self.used_bytes.saturating_sub(bytes);
    }

    pub fn release(&mut self, bytes: u64) {
        self.reserved_bytes = self.reserved_bytes.saturating_sub(bytes);
    }
}

// ── Budget errors ─────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("member {member_id:?} has insufficient capacity: available={available}, required={required}")]
    InsufficientCapacity {
        member_id: MemberId,
        available: u64,
        required: u64,
    },
    #[error("reservation {0:?} not found")]
    ReservationNotFound(BudgetReservationId),
    #[error("reservation {0:?} already committed")]
    ReservationAlreadyCommitted(BudgetReservationId),
    #[error("reservation {0:?} already released")]
    ReservationAlreadyReleased(BudgetReservationId),
    #[error("member {0:?} not found")]
    MemberNotFound(MemberId),
}

// ── Budget tracker ────────────────────────────────────────────────────

/// Placement budget tracker manages per-node capacity reservations.
///
/// Each placement cycle trades budget reservations against member capacity.
/// Reservations are held until the placement is committed (verified receipt)
/// or retired (excess removal).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PlacementBudgetTracker {
    /// Per-member budgets.
    pub budgets: BTreeMap<MemberId, MemberBudget>,
    /// Active budget reservations.
    pub reservations: BTreeMap<BudgetReservationId, BudgetReservation>,
    /// Monotonic reservation id counter.
    next_reservation_id: u64,
    /// Current epoch for time-binding.
    pub current_epoch: EpochId,
}

impl PlacementBudgetTracker {
    #[must_use]
    pub fn new(epoch: EpochId) -> Self {
        Self {
            budgets: BTreeMap::new(),
            reservations: BTreeMap::new(),
            next_reservation_id: 1,
            current_epoch: epoch,
        }
    }

    /// Register a member's capacity budget.
    pub fn register_member(&mut self, member_id: MemberId, total_bytes: u64) {
        self.budgets.insert(
            member_id,
            MemberBudget::new(member_id, total_bytes, self.current_epoch),
        );
    }

    /// Update a member's total capacity.
    pub fn update_capacity(&mut self, member_id: MemberId, total_bytes: u64) {
        if let Some(budget) = self.budgets.get_mut(&member_id) {
            budget.total_bytes = total_bytes;
            budget.high_water_mark_bytes = total_bytes.saturating_mul(85) / 100;
            budget.epoch = self.current_epoch;
        }
    }

    /// Get budget for a member.
    #[must_use]
    pub fn get_budget(&self, member_id: MemberId) -> Option<&MemberBudget> {
        self.budgets.get(&member_id)
    }

    /// Reserve budget for a placement decision.
    ///
    /// Returns the reservation record on success.
    pub fn reserve(
        &mut self,
        target_node: MemberId,
        subject_refs: Vec<ReplicatedSubjectId>,
        byte_cost: u64,
        cycle_ref: CycleId,
        lease_ref: Option<u64>,
    ) -> Result<BudgetReservation, BudgetError> {
        let budget = self
            .budgets
            .get_mut(&target_node)
            .ok_or(BudgetError::MemberNotFound(target_node))?;

        budget.reserve(byte_cost)?;

        let reservation_id = BudgetReservationId::new(self.next_reservation_id);
        self.next_reservation_id += 1;

        let reservation = BudgetReservation {
            reservation_id,
            target_node,
            subject_refs,
            byte_cost,
            epoch: self.current_epoch,
            lease_ref,
            cycle_ref,
            committed: false,
            released: false,
        };

        self.reservations
            .insert(reservation_id, reservation.clone());
        Ok(reservation)
    }

    /// Commit a budget reservation (placement receipt confirmed).
    ///
    /// Moves reserved capacity to used capacity on the target node.
    pub fn commit_reservation(
        &mut self,
        reservation_id: BudgetReservationId,
    ) -> Result<(), BudgetError> {
        let reservation = self
            .reservations
            .get_mut(&reservation_id)
            .ok_or(BudgetError::ReservationNotFound(reservation_id))?;

        if reservation.committed {
            return Err(BudgetError::ReservationAlreadyCommitted(reservation_id));
        }
        if reservation.released {
            return Err(BudgetError::ReservationAlreadyReleased(reservation_id));
        }

        let budget = self
            .budgets
            .get_mut(&reservation.target_node)
            .ok_or(BudgetError::MemberNotFound(reservation.target_node))?;

        budget.commit(reservation.byte_cost);
        reservation.committed = true;
        Ok(())
    }

    /// Release a budget reservation (placement cycle abandoned or retired excess).
    ///
    /// Returns reserved capacity to available on the target node.
    pub fn release_reservation(
        &mut self,
        reservation_id: BudgetReservationId,
    ) -> Result<(), BudgetError> {
        let reservation = self
            .reservations
            .get_mut(&reservation_id)
            .ok_or(BudgetError::ReservationNotFound(reservation_id))?;

        if reservation.released {
            return Err(BudgetError::ReservationAlreadyReleased(reservation_id));
        }
        if reservation.committed {
            return Err(BudgetError::ReservationAlreadyCommitted(reservation_id));
        }

        let budget = self
            .budgets
            .get_mut(&reservation.target_node)
            .ok_or(BudgetError::MemberNotFound(reservation.target_node))?;

        budget.release(reservation.byte_cost);
        reservation.released = true;
        Ok(())
    }

    /// Get all members with available capacity for a given byte cost.
    #[must_use]
    pub fn candidate_nodes(&self, byte_cost: u64) -> Vec<MemberId> {
        let mut candidates: Vec<MemberId> = self
            .budgets
            .iter()
            .filter(|(_, b)| b.can_accept(byte_cost) && !b.is_above_high_water())
            .map(|(id, _)| *id)
            .collect();
        candidates.sort();
        candidates
    }

    /// Advance epoch.
    pub fn advance_epoch(&mut self, new_epoch: EpochId) {
        self.current_epoch = new_epoch;
        // Expire reservations tied to stale epochs.
        let stale: Vec<BudgetReservationId> = self
            .reservations
            .iter()
            .filter(|(_, r)| r.epoch != new_epoch && !r.committed && !r.released)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            let _ = self.release_reservation(id);
        }
        for budget in self.budgets.values_mut() {
            budget.epoch = new_epoch;
        }
    }
}

impl Default for PlacementBudgetTracker {
    fn default() -> Self {
        Self::new(EpochId::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- MemberBudget tests ---

    #[test]
    fn test_member_budget_creation_defaults() {
        let mb = MemberBudget::new(MemberId::new(1), 1_000_000, EpochId::new(1));
        assert_eq!(mb.member_id, MemberId::new(1));
        assert_eq!(mb.total_bytes, 1_000_000);
        assert_eq!(mb.used_bytes, 0);
        assert_eq!(mb.reserved_bytes, 0);
        assert!(mb.accepting);
        assert_eq!(mb.epoch, EpochId::new(1));
        assert_eq!(mb.high_water_mark_bytes, 850_000); // 85% of 1_000_000
    }

    #[test]
    fn test_member_budget_high_water_at_85_percent() {
        let mb = MemberBudget::new(MemberId::new(1), 100, EpochId::new(1));
        assert_eq!(mb.high_water_mark_bytes, 85);
    }

    #[test]
    fn test_available_bytes_returns_correct_remaining() {
        let mut mb = MemberBudget::new(MemberId::new(1), 10_000, EpochId::new(1));
        assert_eq!(mb.available_bytes(), 10_000);
        mb.reserved_bytes = 2_000;
        mb.used_bytes = 1_000;
        assert_eq!(mb.available_bytes(), 7_000);
    }

    #[test]
    fn test_can_accept_respects_accepting_flag_and_available() {
        let mut mb = MemberBudget::new(MemberId::new(1), 10_000, EpochId::new(1));
        assert!(mb.can_accept(5_000));
        assert!(!mb.can_accept(15_000));

        mb.accepting = false;
        assert!(!mb.can_accept(100));
    }

    #[test]
    fn test_is_above_high_water() {
        let mut mb = MemberBudget::new(MemberId::new(1), 10_000, EpochId::new(1));
        // high water = 8_500
        assert!(!mb.is_above_high_water());
        mb.used_bytes = 8_000;
        assert!(!mb.is_above_high_water());
        mb.used_bytes = 8_501;
        assert!(mb.is_above_high_water());
        mb.reserved_bytes = 500;
        // committed = 8_501 + 500 = 9_001 > 8_500
        assert!(mb.is_above_high_water());
    }

    #[test]
    fn test_reserve_commits_capacity() {
        let mut mb = MemberBudget::new(MemberId::new(1), 10_000, EpochId::new(1));
        mb.reserve(1_000).unwrap();
        assert_eq!(mb.reserved_bytes, 1_000);
        assert_eq!(mb.available_bytes(), 9_000);
    }

    #[test]
    fn test_reserve_fails_when_cannot_accept() {
        let mut mb = MemberBudget::new(MemberId::new(1), 100, EpochId::new(1));
        let result = mb.reserve(1_000);
        assert!(result.is_err());
        match result.unwrap_err() {
            BudgetError::InsufficientCapacity {
                member_id,
                available,
                required,
            } => {
                assert_eq!(member_id, MemberId::new(1));
                assert_eq!(available, 100);
                assert_eq!(required, 1_000);
            }
            _ => panic!("wrong error variant"),
        }
    }

    #[test]
    fn test_commit_moves_reserved_to_used() {
        let mut mb = MemberBudget::new(MemberId::new(1), 10_000, EpochId::new(1));
        mb.reserve(1_000).unwrap();
        mb.commit(1_000);
        assert_eq!(mb.reserved_bytes, 0);
        assert_eq!(mb.used_bytes, 1_000);
    }

    #[test]
    fn test_release_frees_reserved() {
        let mut mb = MemberBudget::new(MemberId::new(1), 10_000, EpochId::new(1));
        mb.reserve(1_000).unwrap();
        mb.release(1_000);
        assert_eq!(mb.reserved_bytes, 0);
        assert_eq!(mb.used_bytes, 0);
        assert_eq!(mb.available_bytes(), 10_000);
    }

    #[test]
    fn test_retire_capacity_reduces_used() {
        let mut mb = MemberBudget::new(MemberId::new(1), 10_000, EpochId::new(1));
        mb.used_bytes = 3_000;
        mb.retire_capacity(1_000);
        assert_eq!(mb.used_bytes, 2_000);
    }

    // --- PlacementBudgetTracker tests ---

    #[test]
    fn test_tracker_creation() {
        let bt = PlacementBudgetTracker::new(EpochId::new(1));
        assert_eq!(bt.current_epoch, EpochId::new(1));
        assert!(bt.budgets.is_empty());
        assert!(bt.reservations.is_empty());
    }

    #[test]
    fn test_register_and_get_budget() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        bt.register_member(MemberId::new(1), 1_000_000);
        let b = bt.get_budget(MemberId::new(1)).unwrap();
        assert_eq!(b.total_bytes, 1_000_000);
        assert!(bt.get_budget(MemberId::new(99)).is_none());
    }

    #[test]
    fn test_update_capacity() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        bt.register_member(MemberId::new(1), 1_000_000);
        bt.update_capacity(MemberId::new(1), 2_000_000);
        let b = bt.get_budget(MemberId::new(1)).unwrap();
        assert_eq!(b.total_bytes, 2_000_000);
        assert_eq!(b.high_water_mark_bytes, 1_700_000);
    }

    #[test]
    fn test_reserve_and_commit_reservation() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        bt.register_member(MemberId::new(2), 1_000_000);

        let reservation = bt
            .reserve(
                MemberId::new(2),
                vec![ReplicatedSubjectId::new(42)],
                4096,
                CycleId::new(1),
                Some(7),
            )
            .expect("reserve should succeed");

        assert_eq!(reservation.target_node, MemberId::new(2));
        assert_eq!(reservation.byte_cost, 4096);
        assert_eq!(reservation.lease_ref, Some(7));
        assert!(!reservation.committed);

        bt.commit_reservation(reservation.reservation_id).unwrap();
        let r = bt.reservations.get(&reservation.reservation_id).unwrap();
        assert!(r.committed);
        let b = bt.get_budget(MemberId::new(2)).unwrap();
        assert_eq!(b.used_bytes, 4096);
        assert_eq!(b.reserved_bytes, 0);
    }

    #[test]
    fn test_release_reservation_frees_capacity() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        bt.register_member(MemberId::new(2), 1_000_000);

        let reservation = bt
            .reserve(
                MemberId::new(2),
                vec![ReplicatedSubjectId::new(42)],
                4096,
                CycleId::new(1),
                None,
            )
            .unwrap();

        bt.release_reservation(reservation.reservation_id).unwrap();
        let r = bt.reservations.get(&reservation.reservation_id).unwrap();
        assert!(r.released);
        let b = bt.get_budget(MemberId::new(2)).unwrap();
        assert_eq!(b.used_bytes, 0);
        assert_eq!(b.reserved_bytes, 0);
    }

    #[test]
    fn test_reserve_fails_for_unknown_member() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        let result = bt.reserve(
            MemberId::new(99),
            vec![ReplicatedSubjectId::new(42)],
            4096,
            CycleId::new(1),
            None,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BudgetError::MemberNotFound(_)
        ));
    }

    #[test]
    fn test_commit_fails_for_already_committed() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        bt.register_member(MemberId::new(1), 1_000_000);
        let r = bt
            .reserve(
                MemberId::new(1),
                vec![ReplicatedSubjectId::new(1)],
                4096,
                CycleId::new(1),
                None,
            )
            .unwrap();
        bt.commit_reservation(r.reservation_id).unwrap();
        let result = bt.commit_reservation(r.reservation_id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BudgetError::ReservationAlreadyCommitted(_)
        ));
    }

    #[test]
    fn test_release_fails_for_already_released() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        bt.register_member(MemberId::new(1), 1_000_000);
        let r = bt
            .reserve(
                MemberId::new(1),
                vec![ReplicatedSubjectId::new(1)],
                4096,
                CycleId::new(1),
                None,
            )
            .unwrap();
        bt.release_reservation(r.reservation_id).unwrap();
        let result = bt.release_reservation(r.reservation_id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BudgetError::ReservationAlreadyReleased(_)
        ));
    }

    #[test]
    fn test_candidate_nodes_filters_by_capacity_and_high_water() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        bt.register_member(MemberId::new(1), 1_000_000);
        bt.register_member(MemberId::new(2), 1_000);
        bt.register_member(MemberId::new(3), 1_000_000);

        // Fill node 3 past high-water
        bt.budgets.get_mut(&MemberId::new(3)).unwrap().used_bytes = 900_000;

        let candidates = bt.candidate_nodes(5_000);
        // Node 1: 1M available, ok
        // Node 2: 1K available, not enough for 5K
        // Node 3: above high-water, excluded
        assert_eq!(candidates, vec![MemberId::new(1)]);

        let all_candidates = bt.candidate_nodes(100);
        assert_eq!(all_candidates.len(), 2);
        assert!(all_candidates.contains(&MemberId::new(1)));
        assert!(all_candidates.contains(&MemberId::new(2)));
    }

    #[test]
    fn test_advance_epoch_expires_stale_reservations() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        bt.register_member(MemberId::new(1), 1_000_000);

        let r = bt
            .reserve(
                MemberId::new(1),
                vec![ReplicatedSubjectId::new(1)],
                4096,
                CycleId::new(1),
                None,
            )
            .unwrap();

        assert!(!bt.reservations.get(&r.reservation_id).unwrap().released);

        bt.advance_epoch(EpochId::new(2));
        assert_eq!(bt.current_epoch, EpochId::new(2));
        // Stale reservation from epoch 1 should be released.
        assert!(bt.reservations.get(&r.reservation_id).unwrap().released);
        // Budget epoch should be updated.
        assert_eq!(
            bt.get_budget(MemberId::new(1)).unwrap().epoch,
            EpochId::new(2)
        );
    }

    #[test]
    fn test_advance_epoch_does_not_touch_committed_reservations() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        bt.register_member(MemberId::new(1), 1_000_000);

        let r = bt
            .reserve(
                MemberId::new(1),
                vec![ReplicatedSubjectId::new(1)],
                4096,
                CycleId::new(1),
                None,
            )
            .unwrap();
        bt.commit_reservation(r.reservation_id).unwrap();

        bt.advance_epoch(EpochId::new(2));
        // Committed reservation should still be committed, not released.
        let r = bt.reservations.get(&r.reservation_id).unwrap();
        assert!(r.committed);
        assert!(!r.released);
    }

    #[test]
    fn test_tracker_default_uses_zero_epoch() {
        let bt = PlacementBudgetTracker::default();
        assert_eq!(bt.current_epoch, EpochId::ZERO);
    }
}
