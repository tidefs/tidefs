//! Placement plan registry.
//!
//! Distributed conflict detection and resolution for placement decisions.
//! When multiple nodes independently compute placement plans, the registry
//! detects conflicts (e.g., two nodes trying to place the same chunk on
//! different targets) and resolves them deterministically.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_replication_model::{ReplicaPlacementReceipt, ReplicatedSubjectId};

use crate::types::{CycleId, PlacementDecision, PlacementPhase};

// ── Plan entry ────────────────────────────────────────────────────────

/// A placement plan registered in the registry.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PlanEntry {
    /// Unique plan id.
    pub plan_id: u64,
    /// The node that proposed this plan.
    pub proposer: MemberId,
    /// The epoch this plan was computed in.
    pub epoch: EpochId,
    /// The cycle this plan belongs to.
    pub cycle_ref: CycleId,
    /// Subjects covered by this plan.
    pub subject_refs: BTreeSet<ReplicatedSubjectId>,
    /// Placement decisions in this plan.
    pub decisions: Vec<PlacementDecision>,
    /// Current phase of the plan.
    pub phase: PlacementPhase,
    /// Whether the plan has been accepted (no conflicts).
    pub accepted: bool,
    /// Whether the plan is complete.
    pub complete: bool,
    /// Timestamp when the plan was registered (millis since Unix epoch).
    pub registered_at_millis: u64,
}

// ── Conflict detection ────────────────────────────────────────────────

/// A conflict between two placement plans.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PlanConflict {
    /// The subject that has conflicting placements.
    pub subject_ref: ReplicatedSubjectId,
    /// Plan A's target for this subject.
    pub target_a: MemberId,
    /// Plan B's target for this subject.
    pub target_b: MemberId,
    /// Plan A id.
    pub plan_a_id: u64,
    /// Plan B id.
    pub plan_b_id: u64,
    /// The proposer of plan A.
    pub proposer_a: MemberId,
    /// The proposer of plan B.
    pub proposer_b: MemberId,
}

// ── Plan registry ────────────────────────────────────────────────────

/// The placement plan registry provides distributed conflict detection
/// and resolution for concurrent placement decisions.
///
/// Every node registers its placement plans before executing them.
/// The registry detects when two nodes plan to place the same subject
/// on different targets and resolves conflicts deterministically
/// (lower proposer id wins for the same epoch, lower epoch wins
/// across epochs).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PlacementPlanRegistry {
    /// Registered plans, keyed by plan id.
    pub plans: BTreeMap<u64, PlanEntry>,
    /// Detected conflicts.
    pub conflicts: Vec<PlanConflict>,
    /// Placed receipts (for cross-plan deduplication).
    pub placed_receipts: Vec<ReplicaPlacementReceipt>,
    /// Monotonic plan id counter.
    next_plan_id: u64,
    /// Current epoch.
    pub current_epoch: EpochId,
}

impl PlacementPlanRegistry {
    #[must_use]
    pub fn new(epoch: EpochId) -> Self {
        Self {
            plans: BTreeMap::new(),
            conflicts: Vec::new(),
            placed_receipts: Vec::new(),
            next_plan_id: 1,
            current_epoch: epoch,
        }
    }

    /// Register a new placement plan.
    ///
    /// Returns conflicts if any exist with other active plans.
    pub fn register_plan(
        &mut self,
        proposer: MemberId,
        cycle_ref: CycleId,
        subject_refs: BTreeSet<ReplicatedSubjectId>,
        decisions: Vec<PlacementDecision>,
        now_millis: u64,
    ) -> (u64, Vec<PlanConflict>) {
        let plan_id = self.next_plan_id;
        self.next_plan_id += 1;

        let entry = PlanEntry {
            plan_id,
            proposer,
            epoch: self.current_epoch,
            cycle_ref,
            subject_refs: subject_refs.clone(),
            decisions: decisions.clone(),
            phase: PlacementPhase::Planning,
            accepted: false,
            complete: false,
            registered_at_millis: now_millis,
        };

        let conflicts = self.detect_conflicts(&entry);
        self.plans.insert(plan_id, entry);
        (plan_id, conflicts)
    }

    /// Detect conflicts between a proposed plan and existing active plans.
    fn detect_conflicts(&self, proposed: &PlanEntry) -> Vec<PlanConflict> {
        let mut conflicts = Vec::new();

        for existing in self.plans.values() {
            // Skip completed or stale-epoch plans.
            if existing.complete || existing.epoch != self.current_epoch {
                continue;
            }
            // Skip plans from the same proposer.
            if existing.proposer == proposed.proposer {
                continue;
            }

            // Check for overlapping subjects.
            let overlap: BTreeSet<_> = existing
                .subject_refs
                .intersection(&proposed.subject_refs)
                .cloned()
                .collect();

            for subject_ref in &overlap {
                // Find the target each plan assigns to this subject.
                let target_a = existing
                    .decisions
                    .iter()
                    .find(|d| d.subject_ref == *subject_ref)
                    .map(|d| d.target_ref);
                let target_b = proposed
                    .decisions
                    .iter()
                    .find(|d| d.subject_ref == *subject_ref)
                    .map(|d| d.target_ref);

                if let (Some(ta), Some(tb)) = (target_a, target_b) {
                    if ta != tb {
                        conflicts.push(PlanConflict {
                            subject_ref: *subject_ref,
                            target_a: ta,
                            target_b: tb,
                            plan_a_id: existing.plan_id,
                            plan_b_id: proposed.plan_id,
                            proposer_a: existing.proposer,
                            proposer_b: proposed.proposer,
                        });
                    }
                }
            }
        }

        conflicts
    }

    /// Resolve a conflict deterministically.
    ///
    /// Lower proposer id wins for same epoch; lower epoch wins across epochs.
    /// Returns the winning plan id and the losing plan id.
    #[must_use]
    pub fn resolve_conflict(&self, conflict: &PlanConflict) -> Option<(u64, u64)> {
        let plan_a = self.plans.get(&conflict.plan_a_id)?;
        let plan_b = self.plans.get(&conflict.plan_b_id)?;

        if plan_a.epoch != plan_b.epoch {
            // Lower epoch wins (stale decisions are superseded).
            if plan_a.epoch.0 < plan_b.epoch.0 {
                Some((conflict.plan_a_id, conflict.plan_b_id))
            } else {
                Some((conflict.plan_b_id, conflict.plan_a_id))
            }
        } else {
            // Same epoch: lower proposer id wins.
            if conflict.proposer_a.0 < conflict.proposer_b.0 {
                Some((conflict.plan_a_id, conflict.plan_b_id))
            } else {
                Some((conflict.plan_b_id, conflict.plan_a_id))
            }
        }
    }

    /// Accept a plan (no conflicts remain).
    pub fn accept_plan(&mut self, plan_id: u64) -> Result<(), PlanRegistryError> {
        let plan = self
            .plans
            .get_mut(&plan_id)
            .ok_or(PlanRegistryError::PlanNotFound(plan_id))?;
        plan.accepted = true;
        Ok(())
    }

    /// Mark a plan as complete and clean up.
    pub fn complete_plan(&mut self, plan_id: u64) -> Result<(), PlanRegistryError> {
        let plan = self
            .plans
            .get_mut(&plan_id)
            .ok_or(PlanRegistryError::PlanNotFound(plan_id))?;
        plan.complete = true;
        plan.phase = PlacementPhase::Complete;
        Ok(())
    }

    /// Record a placement receipt (for cross-plan deduplication).
    pub fn record_placement(&mut self, receipt: ReplicaPlacementReceipt) {
        self.placed_receipts.push(receipt);
    }

    /// Check if a subject is already placed (according to receipts).
    #[must_use]
    pub fn is_already_placed(&self, subject_ref: ReplicatedSubjectId, member_id: MemberId) -> bool {
        self.placed_receipts
            .iter()
            .any(|r| r.subject_refs.contains(&subject_ref) && r.placed_on == member_id)
    }

    /// Advance epoch.
    pub fn advance_epoch(&mut self, new_epoch: EpochId) {
        self.current_epoch = new_epoch;
        // Mark all non-complete plans from old epochs as stale.
        for plan in self.plans.values_mut() {
            if plan.epoch != new_epoch && !plan.complete {
                plan.phase = PlacementPhase::Complete;
                plan.complete = true;
            }
        }
    }
}

impl Default for PlacementPlanRegistry {
    fn default() -> Self {
        Self::new(EpochId::ZERO)
    }
}

// ── Registry errors ───────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PlanRegistryError {
    #[error("plan {0} not found")]
    PlanNotFound(u64),
    #[error("plan {0} already complete")]
    PlanAlreadyComplete(u64),
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::BudgetReservationId;
    use crate::CycleId;
    use tidefs_membership_epoch::PlacementIntentClass;
    use tidefs_replication_model::ReplicatedReceiptId;

    fn make_decision(decision_id: u64, subject_id: u64, target_id: u64) -> PlacementDecision {
        PlacementDecision {
            decision_id,
            subject_ref: ReplicatedSubjectId::new(subject_id),
            source_ref: MemberId::new(1),
            target_ref: MemberId::new(target_id),
            placement_class: PlacementIntentClass::ReplicaTarget,
            receipt_ref: ReplicatedReceiptId(0),
            epoch: EpochId::new(1),
            reservation_ref: BudgetReservationId::new(1),
        }
    }

    #[test]
    fn test_registry_creation_defaults() {
        let reg = PlacementPlanRegistry::new(EpochId::new(1));
        assert_eq!(reg.current_epoch, EpochId::new(1));
        assert!(reg.plans.is_empty());
        assert!(reg.conflicts.is_empty());
        assert!(reg.placed_receipts.is_empty());
    }

    #[test]
    fn test_register_single_plan_no_conflicts() {
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let subjects: BTreeSet<_> = [ReplicatedSubjectId::new(10)].iter().copied().collect();
        let decisions = vec![make_decision(1, 10, 2)];
        let (plan_id, conflicts) =
            reg.register_plan(MemberId::new(1), CycleId::new(1), subjects, decisions, 0);
        assert_eq!(plan_id, 1);
        assert!(conflicts.is_empty());
        assert!(reg.plans.contains_key(&1));
    }

    #[test]
    fn test_register_two_non_overlapping_plans_no_conflicts() {
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let s1: BTreeSet<_> = [ReplicatedSubjectId::new(10)].iter().copied().collect();
        let s2: BTreeSet<_> = [ReplicatedSubjectId::new(20)].iter().copied().collect();

        let (_, c1) = reg.register_plan(
            MemberId::new(1),
            CycleId::new(1),
            s1,
            vec![make_decision(1, 10, 2)],
            0,
        );
        assert!(c1.is_empty());

        let (_, c2) = reg.register_plan(
            MemberId::new(2),
            CycleId::new(1),
            s2,
            vec![make_decision(2, 20, 3)],
            0,
        );
        assert!(c2.is_empty());
    }

    #[test]
    fn test_register_plans_with_subject_overlap_different_targets_detects_conflict() {
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let subjects: BTreeSet<_> = [ReplicatedSubjectId::new(100)].iter().copied().collect();

        let _ = reg.register_plan(
            MemberId::new(1),
            CycleId::new(1),
            subjects.clone(),
            vec![make_decision(1, 100, 2)],
            0,
        );

        let (_, conflicts) = reg.register_plan(
            MemberId::new(3),
            CycleId::new(1),
            subjects,
            vec![make_decision(2, 100, 5)],
            0,
        );

        assert_eq!(conflicts.len(), 1);
        let c = &conflicts[0];
        assert_eq!(c.subject_ref, ReplicatedSubjectId::new(100));
        assert_eq!(c.target_a, MemberId::new(2));
        assert_eq!(c.target_b, MemberId::new(5));
        assert_eq!(c.proposer_a, MemberId::new(1));
        assert_eq!(c.proposer_b, MemberId::new(3));
    }

    #[test]
    fn test_same_target_no_conflict_even_with_subject_overlap() {
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let subjects: BTreeSet<_> = [ReplicatedSubjectId::new(100)].iter().copied().collect();

        let _ = reg.register_plan(
            MemberId::new(1),
            CycleId::new(1),
            subjects.clone(),
            vec![make_decision(1, 100, 7)],
            0,
        );

        let (_, conflicts) = reg.register_plan(
            MemberId::new(3),
            CycleId::new(1),
            subjects,
            vec![make_decision(2, 100, 7)],
            0,
        );

        assert!(conflicts.is_empty(), "same target should not conflict");
    }

    #[test]
    fn test_same_proposer_no_conflict_even_with_subject_overlap() {
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let subjects: BTreeSet<_> = [ReplicatedSubjectId::new(100)].iter().copied().collect();

        let _ = reg.register_plan(
            MemberId::new(1),
            CycleId::new(1),
            subjects.clone(),
            vec![make_decision(1, 100, 2)],
            0,
        );

        let (_, conflicts) = reg.register_plan(
            MemberId::new(1),
            CycleId::new(1),
            subjects,
            vec![make_decision(2, 100, 5)],
            0,
        );

        assert!(
            conflicts.is_empty(),
            "same proposer should not conflict with self"
        );
    }

    #[test]
    fn test_completed_plans_skipped_in_conflict_detection() {
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let subjects: BTreeSet<_> = [ReplicatedSubjectId::new(100)].iter().copied().collect();

        let (plan1_id, _) = reg.register_plan(
            MemberId::new(1),
            CycleId::new(1),
            subjects.clone(),
            vec![make_decision(1, 100, 2)],
            0,
        );
        reg.complete_plan(plan1_id).unwrap();

        let (_, conflicts) = reg.register_plan(
            MemberId::new(3),
            CycleId::new(1),
            subjects,
            vec![make_decision(2, 100, 5)],
            0,
        );

        assert!(conflicts.is_empty(), "completed plans should be skipped");
    }

    #[test]
    fn test_resolve_conflict_same_epoch_lower_proposer_wins() {
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let subjects: BTreeSet<_> = [ReplicatedSubjectId::new(100)].iter().copied().collect();

        let (plan_a_id, _) = reg.register_plan(
            MemberId::new(1),
            CycleId::new(1),
            subjects.clone(),
            vec![make_decision(1, 100, 2)],
            0,
        );
        let (plan_b_id, conflicts) = reg.register_plan(
            MemberId::new(3),
            CycleId::new(1),
            subjects,
            vec![make_decision(2, 100, 5)],
            0,
        );

        let winner_loser = reg.resolve_conflict(&conflicts[0]);
        assert_eq!(winner_loser, Some((plan_a_id, plan_b_id)));
    }

    #[test]
    fn test_resolve_conflict_lower_epoch_wins_direct() {
        // Test epoch-based resolution by directly constructing plans with
        // different epochs. This exercises the path where plan_a.epoch !=
        // plan_b.epoch (lower epoch wins).
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let subjects: BTreeSet<_> = [ReplicatedSubjectId::new(100)].iter().copied().collect();

        let (plan_a_id, _) = reg.register_plan(
            MemberId::new(5),
            CycleId::new(1),
            subjects.clone(),
            vec![make_decision(1, 100, 2)],
            0,
        );
        // Manually re-set plan_a to epoch 1 (before advance_epoch marks it complete).
        // Then register plan_b in epoch 2 to test cross-epoch conflict resolution.
        reg.plans.get_mut(&plan_a_id).unwrap().epoch = EpochId::new(1);
        reg.current_epoch = EpochId::new(2);
        let (plan_b_id, _) = reg.register_plan(
            MemberId::new(1),
            CycleId::new(1),
            subjects,
            vec![make_decision(2, 100, 5)],
            0,
        );

        // Build the conflict manually — plan_a (epoch 1) vs plan_b (epoch 2).
        let conflict = PlanConflict {
            subject_ref: ReplicatedSubjectId::new(100),
            target_a: MemberId::new(2),
            target_b: MemberId::new(5),
            plan_a_id,
            plan_b_id,
            proposer_a: MemberId::new(5),
            proposer_b: MemberId::new(1),
        };
        // plan_a is older epoch → wins despite higher proposer id.
        let winner_loser = reg.resolve_conflict(&conflict);
        assert_eq!(winner_loser, Some((plan_a_id, plan_b_id)));
    }

    #[test]
    fn test_accept_plan_success() {
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let subjects: BTreeSet<_> = [ReplicatedSubjectId::new(10)].iter().copied().collect();
        let (plan_id, _) = reg.register_plan(
            MemberId::new(1),
            CycleId::new(1),
            subjects,
            vec![make_decision(1, 10, 2)],
            0,
        );
        reg.accept_plan(plan_id).unwrap();
        assert!(reg.plans.get(&plan_id).unwrap().accepted);
    }

    #[test]
    fn test_accept_plan_not_found_error() {
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let result = reg.accept_plan(99);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PlanRegistryError::PlanNotFound(99)
        ));
    }

    #[test]
    fn test_complete_plan_sets_phase_and_flag() {
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let subjects: BTreeSet<_> = [ReplicatedSubjectId::new(10)].iter().copied().collect();
        let (plan_id, _) = reg.register_plan(
            MemberId::new(1),
            CycleId::new(1),
            subjects,
            vec![make_decision(1, 10, 2)],
            0,
        );
        reg.complete_plan(plan_id).unwrap();
        let plan = reg.plans.get(&plan_id).unwrap();
        assert!(plan.complete);
        assert_eq!(plan.phase, PlacementPhase::Complete);
    }

    #[test]
    fn test_record_and_check_placement() {
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let subject = ReplicatedSubjectId::new(42);
        let member = MemberId::new(7);

        assert!(!reg.is_already_placed(subject, member));

        let receipt = ReplicaPlacementReceipt {
            receipt_id: ReplicatedReceiptId(1),
            verification_ref: ReplicatedReceiptId(0),
            transfer_ref: ReplicatedReceiptId(0),
            subject_refs: vec![subject],
            placed_on: member,
            placement_epoch: EpochId::new(1),
            subjects_placed: 1,
            placement_receipt_refs: Vec::new(),
        };
        reg.record_placement(receipt);

        assert!(reg.is_already_placed(subject, member));
        assert!(!reg.is_already_placed(subject, MemberId::new(99)));
    }

    #[test]
    fn test_advance_epoch_marks_stale_plans_complete() {
        let mut reg = PlacementPlanRegistry::new(EpochId::new(1));
        let subjects: BTreeSet<_> = [ReplicatedSubjectId::new(10)].iter().copied().collect();
        let (plan_id, _) = reg.register_plan(
            MemberId::new(1),
            CycleId::new(1),
            subjects,
            vec![make_decision(1, 10, 2)],
            0,
        );
        reg.accept_plan(plan_id).unwrap();

        reg.advance_epoch(EpochId::new(2));
        assert_eq!(reg.current_epoch, EpochId::new(2));
        let plan = reg.plans.get(&plan_id).unwrap();
        assert!(
            plan.complete,
            "non-complete old-epoch plan should be marked complete"
        );
        assert_eq!(plan.phase, PlacementPhase::Complete);
    }

    #[test]
    fn test_registry_default_uses_zero_epoch() {
        let reg = PlacementPlanRegistry::default();
        assert_eq!(reg.current_epoch, EpochId::ZERO);
    }
}
