//! Core types for the placement runtime.
//!
//! Defines the placement lifecycle, gaps, decisions, transfer tickets,
//! and budget reservations used by the placement runtime engine.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tidefs_membership_epoch::{
    EpochId, MemberId, MembershipPlacementVerdictRecord, PlacementIntentClass, VerdictClass,
};
use tidefs_replication_model::{ReplicaCopyRecord, ReplicatedReceiptId, ReplicatedSubjectId};

// ── Cycle identifiers ─────────────────────────────────────────────────

/// Monotonically increasing placement cycle id.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct CycleId(pub u64);

impl CycleId {
    pub const ZERO: Self = Self(0);
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// Monotonically increasing budget reservation id.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct BudgetReservationId(pub u64);

impl BudgetReservationId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

// ── Placement lifecycle phases ────────────────────────────────────────

/// The 5-phase placement lifecycle.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementPhase {
    /// Phase 1: Evaluate — compare desired vs actual, find gaps.
    Evaluating = 0,
    /// Phase 2: Plan — allocate targets, reserve budget.
    Planning = 1,
    /// Phase 3: Execute — submit transfer tickets.
    Executing = 2,
    /// Phase 4: Verify — wait for placement receipts.
    Verifying = 3,
    /// Phase 5: Complete — update placement state, release reservations.
    Complete = 4,
}

impl PlacementPhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evaluating => "evaluating",
            Self::Planning => "planning",
            Self::Executing => "executing",
            Self::Verifying => "verifying",
            Self::Complete => "complete",
        }
    }

    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Evaluating => Some(Self::Planning),
            Self::Planning => Some(Self::Executing),
            Self::Executing => Some(Self::Verifying),
            Self::Verifying => Some(Self::Complete),
            Self::Complete => None,
        }
    }
}

// ── Placement gap classification ──────────────────────────────────────

/// Priority-ordered gap classes for scheduling.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum PlacementGapClass {
    /// Quorum loss: fewer replicas than quorum requires.
    QuorumLoss = 0,
    /// Anti-affinity violation: replicas exist but violate failure-domain separation.
    AntiAffinityViolation = 1,
    /// Normal under-replication: replicas missing but above quorum floor.
    Normal = 2,
    /// Relocation: moving replicas for drain/rebuild/rebalance.
    Relocation = 3,
}

// ── Placement gap ─────────────────────────────────────────────────────

/// A detected gap between desired and actual placement.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PlacementGap {
    /// The chunk (subject) with a placement gap.
    pub chunk_id: u64,
    pub subject_ref: ReplicatedSubjectId,
    /// Which nodes should have this chunk.
    pub desired: BTreeSet<MemberId>,
    /// Which nodes actually have this chunk.
    pub actual: BTreeSet<MemberId>,
    /// Which nodes are missing (desired - actual).
    pub missing: BTreeSet<MemberId>,
    /// Positive = under-replicated, negative = over-replicated.
    pub replica_count_gap: i32,
    /// Priority class for scheduling.
    pub gap_class: PlacementGapClass,
    /// Verdict class from the placement model.
    pub verdict_class: VerdictClass,
}

/// A detected excess placement (over-replicated chunk).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PlacementExcess {
    pub chunk_id: u64,
    pub subject_ref: ReplicatedSubjectId,
    /// Which nodes should have this chunk.
    pub desired: BTreeSet<MemberId>,
    /// Which nodes actually have this chunk.
    pub actual: BTreeSet<MemberId>,
    /// Which nodes have excess copies (actual - desired).
    pub excess: BTreeSet<MemberId>,
}

// ── Placement decision ────────────────────────────────────────────────

/// A single placement decision: put chunk X on node Y.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PlacementDecision {
    pub decision_id: u64,
    pub subject_ref: ReplicatedSubjectId,
    pub source_ref: MemberId,
    pub target_ref: MemberId,
    pub placement_class: PlacementIntentClass,
    pub receipt_ref: ReplicatedReceiptId,
    pub epoch: EpochId,
    pub reservation_ref: BudgetReservationId,
}

// ── Transfer ticket ───────────────────────────────────────────────────

/// A transfer ticket submitted to the transfer orchestrator.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransferTicket {
    pub ticket_id: u64,
    pub subject_ref: ReplicatedSubjectId,
    pub source_ref: MemberId,
    pub target_ref: MemberId,
    pub decision_ref: u64,
    pub flow_class: tidefs_replication_model::FlowCommitClass,
    pub epoch: EpochId,
    pub priority: u8,
}

// ── Budget reservation ────────────────────────────────────────────────

/// A capacity reservation on a target node.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct BudgetReservation {
    pub reservation_id: BudgetReservationId,
    pub target_node: MemberId,
    pub subject_refs: Vec<ReplicatedSubjectId>,
    pub byte_cost: u64,
    pub epoch: EpochId,
    pub lease_ref: Option<u64>,
    pub cycle_ref: CycleId,
    pub committed: bool,
    pub released: bool,
}

// ── Placement cycle ───────────────────────────────────────────────────

/// A single placement cycle through the 5-phase lifecycle.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PlacementCycle {
    pub cycle_id: CycleId,
    pub phase: PlacementPhase,
    pub started_at_millis: u64,
    pub epoch: EpochId,
    /// Chunks that need new placement (under-replicated).
    pub under_replicated: Vec<PlacementGap>,
    /// Chunks that have excess placement (over-replicated).
    pub over_replicated: Vec<PlacementExcess>,
    /// Placement decisions made this cycle.
    pub decisions: Vec<PlacementDecision>,
    /// Transfer tickets submitted.
    pub tickets: Vec<TransferTicket>,
    /// Budgets reserved.
    pub reservations: Vec<BudgetReservation>,
    /// Verdicts emitted this cycle.
    pub verdicts: Vec<MembershipPlacementVerdictRecord>,
    /// Rebalance intents generated this cycle.
    pub rebalance_intents: Vec<tidefs_rebalance_planner::RebalanceIntent>,
    /// Whether the cycle is complete.
    pub complete: bool,
}

impl PlacementCycle {
    #[must_use]
    pub fn new(cycle_id: CycleId, epoch: EpochId, started_at_millis: u64) -> Self {
        Self {
            cycle_id,
            phase: PlacementPhase::Evaluating,
            started_at_millis,
            epoch,
            under_replicated: Vec::new(),
            over_replicated: Vec::new(),
            decisions: Vec::new(),
            tickets: Vec::new(),
            reservations: Vec::new(),
            verdicts: Vec::new(),
            rebalance_intents: Vec::new(),
            complete: false,
        }
    }

    #[must_use]
    pub fn pending_gap_count(&self) -> usize {
        self.under_replicated.len()
    }

    #[must_use]
    pub fn has_gaps(&self) -> bool {
        !self.under_replicated.is_empty() || !self.over_replicated.is_empty()
    }
}

// ── Placement state ───────────────────────────────────────────────────

/// Current placement state: what's placed where.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PlacementState {
    /// Which members hold which subjects.
    pub placement_map: std::collections::BTreeMap<ReplicatedSubjectId, BTreeSet<MemberId>>,
    /// Copy records by subject + member.
    pub copy_records: std::collections::BTreeMap<u64, ReplicaCopyRecord>,
    /// Verified placement receipts.
    pub placement_receipts: Vec<tidefs_replication_model::ReplicaPlacementReceipt>,
    /// Current epoch this state reflects.
    pub epoch: EpochId,
    /// Last cycle id completed.
    pub last_cycle_id: CycleId,
}

impl PlacementState {
    #[must_use]
    pub fn new(epoch: EpochId) -> Self {
        Self {
            placement_map: std::collections::BTreeMap::new(),
            copy_records: std::collections::BTreeMap::new(),
            placement_receipts: Vec::new(),
            epoch,
            last_cycle_id: CycleId::ZERO,
        }
    }

    /// Record a subject placed on a member.
    pub fn record_placement(&mut self, subject_ref: ReplicatedSubjectId, member_id: MemberId) {
        self.placement_map
            .entry(subject_ref)
            .or_default()
            .insert(member_id);
    }

    /// Remove a subject from a member (retirement).
    pub fn retire_placement(&mut self, subject_ref: ReplicatedSubjectId, member_id: MemberId) {
        if let Some(members) = self.placement_map.get_mut(&subject_ref) {
            members.remove(&member_id);
            if members.is_empty() {
                self.placement_map.remove(&subject_ref);
            }
        }
    }

    /// Get the members that hold a subject.
    #[must_use]
    pub fn placed_on(&self, subject_ref: ReplicatedSubjectId) -> BTreeSet<MemberId> {
        self.placement_map
            .get(&subject_ref)
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::{EpochId, MemberId, PlacementIntentClass, VerdictClass};
    use tidefs_replication_model::{ReplicatedReceiptId, ReplicatedSubjectId};

    #[test]
    fn test_cycle_id_creation_and_ordering() {
        let a = CycleId::new(5);
        let b = CycleId::new(10);
        assert_eq!(a.0, 5);
        assert_eq!(b.0, 10);
        assert!(a < b);
        assert_eq!(CycleId::ZERO, CycleId::new(0));
    }

    #[test]
    fn test_cycle_id_next() {
        let a = CycleId::new(7);
        assert_eq!(a.next(), CycleId::new(8));
    }

    #[test]
    fn test_budget_reservation_id_creation() {
        let id = BudgetReservationId::new(42);
        assert_eq!(id.0, 42);
    }

    #[test]
    fn test_placement_phase_as_str() {
        assert_eq!(PlacementPhase::Evaluating.as_str(), "evaluating");
        assert_eq!(PlacementPhase::Planning.as_str(), "planning");
        assert_eq!(PlacementPhase::Executing.as_str(), "executing");
        assert_eq!(PlacementPhase::Verifying.as_str(), "verifying");
        assert_eq!(PlacementPhase::Complete.as_str(), "complete");
    }

    #[test]
    fn test_placement_phase_next_all_transitions() {
        assert_eq!(
            PlacementPhase::Evaluating.next(),
            Some(PlacementPhase::Planning)
        );
        assert_eq!(
            PlacementPhase::Planning.next(),
            Some(PlacementPhase::Executing)
        );
        assert_eq!(
            PlacementPhase::Executing.next(),
            Some(PlacementPhase::Verifying)
        );
        assert_eq!(
            PlacementPhase::Verifying.next(),
            Some(PlacementPhase::Complete)
        );
        assert_eq!(PlacementPhase::Complete.next(), None);
    }

    #[test]
    fn test_gap_class_priority_ordering() {
        assert!(PlacementGapClass::QuorumLoss < PlacementGapClass::AntiAffinityViolation);
        assert!(PlacementGapClass::AntiAffinityViolation < PlacementGapClass::Normal);
        assert!(PlacementGapClass::Normal < PlacementGapClass::Relocation);
    }

    #[test]
    fn test_placement_gap_creation() {
        let gap = PlacementGap {
            chunk_id: 100,
            subject_ref: ReplicatedSubjectId::new(100),
            desired: [MemberId::new(1), MemberId::new(2)]
                .iter()
                .copied()
                .collect(),
            actual: [MemberId::new(1)].iter().copied().collect(),
            missing: [MemberId::new(2)].iter().copied().collect(),
            replica_count_gap: 1,
            gap_class: PlacementGapClass::Normal,
            verdict_class: VerdictClass::Admit,
        };
        assert_eq!(gap.chunk_id, 100);
        assert_eq!(gap.replica_count_gap, 1);
        assert_eq!(gap.missing.len(), 1);
    }

    #[test]
    fn test_placement_excess_creation() {
        let excess = PlacementExcess {
            chunk_id: 200,
            subject_ref: ReplicatedSubjectId::new(200),
            desired: [MemberId::new(1)].iter().copied().collect(),
            actual: [MemberId::new(1), MemberId::new(2)]
                .iter()
                .copied()
                .collect(),
            excess: [MemberId::new(2)].iter().copied().collect(),
        };
        assert_eq!(excess.excess.len(), 1);
        assert!(excess.excess.contains(&MemberId::new(2)));
    }

    #[test]
    fn test_placement_decision_creation() {
        let decision = PlacementDecision {
            decision_id: 1,
            subject_ref: ReplicatedSubjectId::new(42),
            source_ref: MemberId::new(1),
            target_ref: MemberId::new(2),
            placement_class: PlacementIntentClass::ReplicaTarget,
            receipt_ref: ReplicatedReceiptId(10),
            epoch: EpochId::new(1),
            reservation_ref: BudgetReservationId::new(3),
        };
        assert_eq!(decision.decision_id, 1);
        assert_eq!(decision.source_ref, MemberId::new(1));
        assert_eq!(decision.target_ref, MemberId::new(2));
    }

    #[test]
    fn test_transfer_ticket_creation() {
        let ticket = TransferTicket {
            ticket_id: 5,
            subject_ref: ReplicatedSubjectId::new(99),
            source_ref: MemberId::new(1),
            target_ref: MemberId::new(2),
            decision_ref: 1,
            flow_class: tidefs_replication_model::FlowCommitClass::SteadyReplication,
            epoch: EpochId::new(1),
            priority: 3,
        };
        assert_eq!(ticket.ticket_id, 5);
        assert_eq!(ticket.priority, 3);
    }

    #[test]
    fn test_budget_reservation_lifecycle() {
        let reservation = BudgetReservation {
            reservation_id: BudgetReservationId::new(1),
            target_node: MemberId::new(3),
            subject_refs: vec![ReplicatedSubjectId::new(42)],
            byte_cost: 4096,
            epoch: EpochId::new(1),
            lease_ref: Some(7),
            cycle_ref: CycleId::new(1),
            committed: false,
            released: false,
        };
        assert!(!reservation.committed);
        assert!(!reservation.released);
        assert_eq!(reservation.byte_cost, 4096);
    }

    #[test]
    fn test_placement_cycle_new() {
        let cycle = PlacementCycle::new(CycleId::new(1), EpochId::new(7), 1_000_000);
        assert_eq!(cycle.cycle_id, CycleId::new(1));
        assert_eq!(cycle.epoch, EpochId::new(7));
        assert_eq!(cycle.phase, PlacementPhase::Evaluating);
        assert!(!cycle.complete);
        assert!(cycle.under_replicated.is_empty());
        assert!(cycle.over_replicated.is_empty());
        assert!(cycle.decisions.is_empty());
    }

    #[test]
    fn test_placement_cycle_pending_gap_count() {
        let mut cycle = PlacementCycle::new(CycleId::new(1), EpochId::new(1), 0);
        assert_eq!(cycle.pending_gap_count(), 0);
        cycle.under_replicated.push(PlacementGap {
            chunk_id: 1,
            subject_ref: ReplicatedSubjectId::new(1),
            desired: Default::default(),
            actual: Default::default(),
            missing: Default::default(),
            replica_count_gap: 1,
            gap_class: PlacementGapClass::Normal,
            verdict_class: VerdictClass::Admit,
        });
        assert_eq!(cycle.pending_gap_count(), 1);
    }

    #[test]
    fn test_placement_cycle_has_gaps() {
        let mut cycle = PlacementCycle::new(CycleId::new(1), EpochId::new(1), 0);
        assert!(!cycle.has_gaps());
        cycle.under_replicated.push(PlacementGap {
            chunk_id: 1,
            subject_ref: ReplicatedSubjectId::new(1),
            desired: Default::default(),
            actual: Default::default(),
            missing: Default::default(),
            replica_count_gap: 1,
            gap_class: PlacementGapClass::Normal,
            verdict_class: VerdictClass::Admit,
        });
        assert!(cycle.has_gaps());
    }

    #[test]
    fn test_placement_state_record_and_retire() {
        let mut state = PlacementState::new(EpochId::new(1));
        let subj = ReplicatedSubjectId::new(100);
        assert!(state.placed_on(subj).is_empty());
        state.record_placement(subj, MemberId::new(1));
        state.record_placement(subj, MemberId::new(2));
        assert_eq!(state.placed_on(subj).len(), 2);
        state.retire_placement(subj, MemberId::new(1));
        assert_eq!(state.placed_on(subj).len(), 1);
        assert!(state.placed_on(subj).contains(&MemberId::new(2)));
        state.retire_placement(subj, MemberId::new(2));
        assert!(state.placed_on(subj).is_empty());
    }

    #[test]
    fn test_placement_state_new_defaults() {
        let state = PlacementState::new(EpochId::new(5));
        assert_eq!(state.epoch, EpochId::new(5));
        assert_eq!(state.last_cycle_id, CycleId::ZERO);
        assert!(state.placement_map.is_empty());
        assert!(state.copy_records.is_empty());
        assert!(state.placement_receipts.is_empty());
    }

    #[test]
    fn test_placement_state_retire_nonexistent_no_panic() {
        let mut state = PlacementState::new(EpochId::new(1));
        let subj = ReplicatedSubjectId::new(99);
        state.retire_placement(subj, MemberId::new(1));
        assert!(state.placed_on(subj).is_empty());
    }

    #[test]
    fn test_placement_state_retire_unknown_member_no_panic() {
        let mut state = PlacementState::new(EpochId::new(1));
        let subj = ReplicatedSubjectId::new(42);
        state.record_placement(subj, MemberId::new(1));
        state.retire_placement(subj, MemberId::new(99));
        assert_eq!(state.placed_on(subj).len(), 1);
    }

    #[test]
    fn test_placement_cycle_over_replicated_has_gaps() {
        let mut cycle = PlacementCycle::new(CycleId::new(1), EpochId::new(1), 0);
        cycle.over_replicated.push(PlacementExcess {
            chunk_id: 1,
            subject_ref: ReplicatedSubjectId::new(1),
            desired: Default::default(),
            actual: Default::default(),
            excess: Default::default(),
        });
        assert!(cycle.has_gaps());
    }

    #[test]
    fn test_placement_gaps_sort_by_priority() {
        let mut gaps = vec![
            PlacementGap {
                chunk_id: 1,
                subject_ref: ReplicatedSubjectId::new(1),
                desired: Default::default(),
                actual: Default::default(),
                missing: Default::default(),
                replica_count_gap: 1,
                gap_class: PlacementGapClass::Normal,
                verdict_class: VerdictClass::Admit,
            },
            PlacementGap {
                chunk_id: 2,
                subject_ref: ReplicatedSubjectId::new(2),
                desired: Default::default(),
                actual: Default::default(),
                missing: Default::default(),
                replica_count_gap: 1,
                gap_class: PlacementGapClass::QuorumLoss,
                verdict_class: VerdictClass::Admit,
            },
            PlacementGap {
                chunk_id: 3,
                subject_ref: ReplicatedSubjectId::new(3),
                desired: Default::default(),
                actual: Default::default(),
                missing: Default::default(),
                replica_count_gap: 1,
                gap_class: PlacementGapClass::AntiAffinityViolation,
                verdict_class: VerdictClass::AdmitDegraded,
            },
        ];
        gaps.sort_by_key(|g| g.gap_class);
        assert_eq!(gaps[0].gap_class, PlacementGapClass::QuorumLoss);
        assert_eq!(gaps[1].gap_class, PlacementGapClass::AntiAffinityViolation);
        assert_eq!(gaps[2].gap_class, PlacementGapClass::Normal);
    }
}
