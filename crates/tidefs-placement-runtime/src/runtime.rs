//! Placement runtime: the execution engine.

use std::collections::{BTreeMap, BTreeSet};

use tidefs_membership_epoch::{
    ClusterMemberRecord, EpochId, FailureDomainClass, FailureDomainPlacementPolicy, MemberId,
    MembershipConfigRecord, VerdictClass,
};
use tidefs_rebalance_planner::RebalanceIntent;
use tidefs_replication_model::{
    FlowCommitClass, ReplicaPlacementReceipt, ReplicatedReceiptId, ReplicatedSubjectId,
};

use crate::budget::{BudgetError, PlacementBudgetTracker};
use crate::health::PlacementHealthTracker;
use crate::plan_registry::{PlacementPlanRegistry, PlanRegistryError};
use crate::planner::PlacementPlanner;
use crate::rebalance::RebalanceIntegration;
use crate::types::*;
use tidefs_durability_layout::{
    DurabilityLayoutV1, DurabilityPolicy, FailureDomainLevel, FailureDomainV1,
};
use tidefs_placement_planner::constraint;
use tidefs_placement_planner::DeviceHealthCapacity;

#[derive(Debug)]
pub struct PlacementRuntime {
    pub placement_state: PlacementState,
    pub budget_tracker: PlacementBudgetTracker,
    pub plan_registry: PlacementPlanRegistry,
    pub current_cycle: Option<PlacementCycle>,
    pub completed_cycles: Vec<PlacementCycle>,
    pub current_epoch: EpochId,
    pub local_member_id: MemberId,
    pub active_leases: BTreeMap<u64, tidefs_lease::LeaseGrant>,
    next_decision_id: u64,
    next_ticket_id: u64,
    pub planner: PlacementPlanner,
    pub health_tracker: PlacementHealthTracker,
    /// Rebalance integration (PC-010.4): capacity skew detection, movement budget, epoch gating.
    pub rebalance: RebalanceIntegration,
}

impl PlacementRuntime {
    #[must_use]
    pub fn new(local_member_id: MemberId, epoch: EpochId) -> Self {
        Self {
            placement_state: PlacementState::new(epoch),
            budget_tracker: PlacementBudgetTracker::new(epoch),
            plan_registry: PlacementPlanRegistry::new(epoch),
            current_cycle: None,
            completed_cycles: Vec::new(),
            current_epoch: epoch,
            local_member_id,
            active_leases: BTreeMap::new(),
            next_decision_id: 1,
            planner: PlacementPlanner::new(epoch),
            health_tracker: PlacementHealthTracker::new(epoch),
            rebalance: RebalanceIntegration::new(epoch),
            next_ticket_id: 1,
        }
    }

    pub fn register_lease(&mut self, lease: tidefs_lease::LeaseGrant) {
        self.active_leases.insert(lease.lease_id, lease);
    }

    pub fn release_lease(&mut self, lease_id: u64) -> Option<tidefs_lease::LeaseGrant> {
        self.active_leases.remove(&lease_id)
    }

    pub fn seed_budgets(&mut self, member_capacities: BTreeMap<MemberId, u64>) {
        for (member_id, total_bytes) in member_capacities {
            self.budget_tracker.register_member(member_id, total_bytes);
        }
    }

    /// Refresh the planner's failure domain inventory from member list.
    pub fn refresh_domains(&mut self, members: &[ClusterMemberRecord]) {
        self.planner.refresh_domains(members);
        self.rebalance.refresh_members(members);
    }

    /// Handle an epoch transition: abort inflight rebalance plans and advance epoch.
    ///
    /// Epoch transitions abort all inflight rebalancing and trigger re-planning
    /// at the new epoch. Placement state is preserved; only rebalancing is reset.
    pub fn on_epoch_transition(&mut self, new_epoch: EpochId, at_ns: u64) {
        self.rebalance.on_epoch_transition(new_epoch, at_ns);
        self.planner.advance_epoch(new_epoch);
        self.budget_tracker.advance_epoch(new_epoch);
        self.health_tracker.advance_epoch(new_epoch);
        self.current_epoch = new_epoch;
    }

    /// Filter members to those that can accept replicas (healthy + at p5 or beyond).
    ///
    /// New nodes must be at `JoinPhase::ReplicaTarget` or beyond before receiving
    /// replica placements. Nodes being drained or below p5 are excluded.
    #[must_use]
    pub fn replica_eligible_members<'a>(
        &self,
        members: &'a [ClusterMemberRecord],
        _join_phases: &std::collections::BTreeMap<
            tidefs_membership_epoch::MemberId,
            tidefs_node_join::JoinPhase,
        >,
    ) -> Vec<&'a ClusterMemberRecord> {
        members
            .iter()
            .filter(|m| m.member_class.can_hold_replicas() && m.health.admits_new_work())
            .collect()
    }

    pub fn evaluate(
        &mut self,
        config: &MembershipConfigRecord,
        members: &[ClusterMemberRecord],
        policy: FailureDomainPlacementPolicy,
        subjects: &[ReplicatedSubjectId],
        _receipt_registry: &[ReplicaPlacementReceipt],
    ) -> PlacementCycle {
        let now = now_millis();
        let cycle_id = if let Some(ref current) = self.current_cycle {
            if !current.complete {
                return current.clone();
            }
            current.cycle_id.next()
        } else {
            CycleId::new(1)
        };

        let mut cycle = PlacementCycle::new(cycle_id, self.current_epoch, now);

        // Compute per-subject placement plans for balanced distribution.
        let subject_plans = self
            .planner
            .compute_subject_plans(config, members, &policy, subjects);

        // Collect unique verdicts (dedup by placement_class + verdict_class).
        let mut seen = BTreeSet::new();
        for plan in subject_plans.values() {
            let key = (
                plan.verdict.placement_class as u8,
                plan.verdict.verdict_class as u8,
            );
            if seen.insert(key) {
                cycle.verdicts.push(plan.verdict.clone());
            }
        }

        // Incorporate authority-home placement verdicts.
        for subject_ref in subjects {
            if let Some((_leader, verdict)) =
                self.planner
                    .compute_authority_home(config, members, *subject_ref)
            {
                let key = (verdict.placement_class as u8, verdict.verdict_class as u8);
                if seen.insert(key) {
                    cycle.verdicts.push(verdict);
                }
            }
        }

        for subject_ref in subjects {
            let plan = subject_plans.get(subject_ref).cloned();
            let desired: BTreeSet<MemberId> = plan
                .as_ref()
                .map(|p| p.selected_members.iter().copied().collect())
                .unwrap_or_default();

            let raw_actual = self.placement_state.placed_on(*subject_ref);
            let actual: BTreeSet<MemberId> = raw_actual
                .into_iter()
                .filter(|&m| self.health_tracker.is_healthy(*subject_ref, m))
                .collect();
            let missing: BTreeSet<MemberId> = desired.difference(&actual).copied().collect();
            let replica_count_gap = desired.len() as i32 - actual.len() as i32;

            if replica_count_gap == 0 && missing.is_empty() {
                continue;
            }

            let verdict_class = plan
                .as_ref()
                .map(|p| p.verdict.verdict_class)
                .unwrap_or(VerdictClass::Admit);

            let gap_class = if replica_count_gap > 0 || !missing.is_empty() {
                let quorum = (desired.len().max(1) / 2) + 1;
                if actual.len() < quorum {
                    PlacementGapClass::QuorumLoss
                } else if verdict_class == VerdictClass::AdmitDegraded {
                    PlacementGapClass::AntiAffinityViolation
                } else {
                    PlacementGapClass::Normal
                }
            } else {
                PlacementGapClass::Relocation
            };

            // Under-replicated or replacement needed (wrong nodes holding replicas)
            if replica_count_gap > 0 || !missing.is_empty() {
                cycle.under_replicated.push(PlacementGap {
                    chunk_id: subject_ref.0,
                    subject_ref: *subject_ref,
                    desired: desired.clone(),
                    actual: actual.clone(),
                    missing: missing.clone(),
                    replica_count_gap,
                    gap_class,
                    verdict_class,
                });
            }

            // Over-replicated: excess replicas or wrong nodes that need retirement
            let excess: BTreeSet<MemberId> = actual.difference(&desired).copied().collect();
            if replica_count_gap < 0 || !excess.is_empty() {
                cycle.over_replicated.push(PlacementExcess {
                    chunk_id: subject_ref.0,
                    subject_ref: *subject_ref,
                    desired: desired.clone(),
                    actual,
                    excess,
                });
            }
        }

        cycle.under_replicated.sort_by_key(|g| g.gap_class);
        // ── Rebalance check (PC-010.4) ──────────────────────────────
        // If we have a fresh cycle and capacity skew is detected, produce rebalance intents.
        if !cycle.has_gaps() || cycle.under_replicated.len() <= subjects.len() {
            // Collect per-member utilization for skew detection.
            let mut member_used: std::collections::BTreeMap<
                tidefs_membership_epoch::MemberId,
                u64,
            > = std::collections::BTreeMap::new();
            for m in members {
                let placed = self.placement_state.placed_on(
                    tidefs_replication_model::ReplicatedSubjectId::new(m.member_id.0),
                );
                member_used.insert(m.member_id, placed.len() as u64 * 4096);
            }
            let util_snapshot =
                crate::rebalance::member_utilization_snapshot(members, &member_used);
            let total_capacity: u64 = members.iter().map(|_m| 1_000_000_000u64).sum();
            if let Some(skew) = self
                .rebalance
                .detect_skew(&util_snapshot, total_capacity, now)
            {
                // Convert failure domains for the rebalance planner
                if self
                    .rebalance
                    .plan(
                        &skew,
                        self.current_epoch,
                        &self.planner.failure_domains,
                        &policy,
                        now,
                    )
                    .is_ok()
                {
                    // Extract active intents into the cycle
                    let intents: Vec<RebalanceIntent> = self
                        .rebalance
                        .active_intents()
                        .into_iter()
                        .cloned()
                        .collect();
                    cycle.rebalance_intents = intents;
                }
            }
        }

        self.current_cycle = Some(cycle.clone());
        cycle
    }

    pub fn plan(
        &mut self,
        gaps: &[PlacementGap],
        members: &[ClusterMemberRecord],
        policy: &FailureDomainPlacementPolicy,
        byte_cost: u64,
    ) -> Result<Vec<PlacementDecision>, PlacementRuntimeError> {
        let cycle = self
            .current_cycle
            .as_ref()
            .ok_or(PlacementRuntimeError::NoActiveCycle)?;
        let cycle_id = cycle.cycle_id;

        let mut decisions = Vec::new();
        let mut reservations: Vec<BudgetReservation> = Vec::new();

        // Pre-flight constraint satisfaction check.
        // Skip when no device capacities exist (empty cluster / no budget).
        let device_capacities = self.build_device_capacities(members);
        if !device_capacities.is_empty() {
            let layout = policy_to_layout(policy);
            let fd = policy_to_failure_domain(policy);
            let c = constraint::PlacementConstraint::new(&layout, &fd);
            let sat = constraint::check_satisfaction(&c, &device_capacities);
            if !sat.satisfiable {
                return Err(PlacementRuntimeError::PlannerError(format!(
                    "constraint check failed: {:?}",
                    sat.failure_reason
                )));
            }
        }

        let candidate_nodes = self.budget_tracker.candidate_nodes(byte_cost);

        let healthy: BTreeSet<MemberId> = members
            .iter()
            .filter(|m| {
                m.current_membership_epoch_ref == cycle.epoch
                    && m.health.admits_new_work()
                    && m.member_class.can_hold_replicas()
            })
            .map(|m| m.member_id)
            .collect();

        for gap in gaps {
            // Process ALL missing targets per gap.
            for &target_ref in &gap.missing {
                if !candidate_nodes.contains(&target_ref) || !healthy.contains(&target_ref) {
                    continue;
                }

                // Source must be a known healthy member that holds the subject.
                let source_ref = if let Some(&src) = gap.actual.iter().next() {
                    src
                } else {
                    // No known healthy source; skip this target.
                    continue;
                };

                let reservation = self.budget_tracker.reserve(
                    target_ref,
                    vec![gap.subject_ref],
                    byte_cost,
                    cycle_id,
                    None,
                )?;

                let decision = PlacementDecision {
                    decision_id: self.next_decision_id,
                    subject_ref: gap.subject_ref,
                    source_ref,
                    target_ref,
                    placement_class: policy.placement_class,
                    receipt_ref: ReplicatedReceiptId(reservation.reservation_id.0),
                    epoch: self.current_epoch,
                    reservation_ref: reservation.reservation_id,
                };

                self.next_decision_id += 1;
                decisions.push(decision);
                reservations.push(reservation);
            }
        }

        let subject_refs: BTreeSet<ReplicatedSubjectId> =
            decisions.iter().map(|d| d.subject_ref).collect();

        let (registry_plan_id, conflicts) = self.plan_registry.register_plan(
            self.local_member_id,
            cycle.cycle_id,
            subject_refs,
            decisions.clone(),
            now_millis(),
        );

        for conflict in &conflicts {
            if let Some((_winner, loser)) = self.plan_registry.resolve_conflict(conflict) {
                if loser == registry_plan_id {
                    for decision in &decisions {
                        let _ = self
                            .budget_tracker
                            .release_reservation(decision.reservation_ref);
                    }
                    self.plan_registry.complete_plan(registry_plan_id).ok();
                    return Err(PlacementRuntimeError::PlanConflictResolved {
                        plan_id: registry_plan_id,
                        conflict: conflict.clone(),
                    });
                }
                self.plan_registry.complete_plan(loser).ok();
            }
        }

        self.plan_registry.accept_plan(registry_plan_id)?;

        if let Some(ref mut cycle) = self.current_cycle {
            cycle.phase = PlacementPhase::Planning;
            cycle.decisions = decisions.clone();
            cycle.reservations = reservations;
        }

        Ok(decisions)
    }

    pub fn execute(
        &mut self,
        decisions: &[PlacementDecision],
    ) -> Result<Vec<TransferTicket>, PlacementRuntimeError> {
        let _cycle = self
            .current_cycle
            .as_ref()
            .ok_or(PlacementRuntimeError::NoActiveCycle)?;

        let mut tickets = Vec::new();

        for decision in decisions {
            let ticket = TransferTicket {
                ticket_id: self.next_ticket_id,
                subject_ref: decision.subject_ref,
                source_ref: decision.source_ref,
                target_ref: decision.target_ref,
                decision_ref: decision.decision_id,
                flow_class: flow_class_for_intent(decision.placement_class),
                epoch: self.current_epoch,
                priority: 0,
            };

            self.next_ticket_id += 1;
            tickets.push(ticket);
        }

        if let Some(ref mut cycle) = self.current_cycle {
            cycle.phase = PlacementPhase::Executing;
            cycle.tickets = tickets.clone();
        }

        Ok(tickets)
    }

    /// Verify placement receipts using precise decision-based matching.
    pub fn verify(
        &mut self,
        receipts: &[ReplicaPlacementReceipt],
        decisions: &[PlacementDecision],
    ) -> Result<Vec<BudgetReservationId>, PlacementRuntimeError> {
        let decision_lookup: BTreeMap<(ReplicatedSubjectId, MemberId), &PlacementDecision> =
            decisions
                .iter()
                .map(|d| ((d.subject_ref, d.target_ref), d))
                .collect();

        let mut committed = Vec::new();

        for receipt in receipts {
            for subject_ref in &receipt.subject_refs {
                self.placement_state
                    .record_placement(*subject_ref, receipt.placed_on);

                if let Some(decision) = decision_lookup.get(&(*subject_ref, receipt.placed_on)) {
                    let reservation_id = decision.reservation_ref;
                    let should_commit = self
                        .budget_tracker
                        .reservations
                        .get(&reservation_id)
                        .map(|r| !r.committed && !r.released && r.target_node == receipt.placed_on)
                        .unwrap_or(false);

                    if should_commit {
                        self.budget_tracker.commit_reservation(reservation_id)?;
                        committed.push(reservation_id);
                    }
                }
            }

            self.plan_registry.record_placement(receipt.clone());
            self.placement_state
                .placement_receipts
                .push(receipt.clone());
        }

        if let Some(ref mut cycle) = self.current_cycle {
            cycle.phase = PlacementPhase::Verifying;
        }

        Ok(committed)
    }

    pub fn complete(&mut self) -> Result<(), PlacementRuntimeError> {
        let cycle = self
            .current_cycle
            .as_mut()
            .ok_or(PlacementRuntimeError::NoActiveCycle)?;

        for reservation in &cycle.reservations {
            if !reservation.committed && !reservation.released {
                self.budget_tracker
                    .release_reservation(reservation.reservation_id)
                    .ok();
            }
        }

        cycle.phase = PlacementPhase::Complete;
        cycle.complete = true;
        self.placement_state.last_cycle_id = cycle.cycle_id;

        let completed = cycle.clone();
        self.completed_cycles.push(completed);
        self.current_cycle = None;

        Ok(())
    }

    pub fn retire_excess(
        &mut self,
        excess: &[PlacementExcess],
        byte_cost_per_subject: u64,
    ) -> Vec<PlacementExcess> {
        let mut retired = Vec::new();

        for ex in excess {
            for &member_ref in &ex.excess {
                self.placement_state
                    .retire_placement(ex.subject_ref, member_ref);

                if let Some(budget) = self.budget_tracker.budgets.get_mut(&member_ref) {
                    budget.retire_capacity(byte_cost_per_subject);
                }
            }
            retired.push(ex.clone());
        }

        if let Some(ref mut cycle) = self.current_cycle {
            cycle.over_replicated.clear();
        }

        retired
    }

    /// Build DeviceHealthCapacity records from cluster members for
    /// constraint-based pre-flight validation.
    #[must_use]
    pub fn build_device_capacities(
        &self,
        members: &[ClusterMemberRecord],
    ) -> Vec<DeviceHealthCapacity> {
        members
            .iter()
            .filter(|m| m.member_class.can_hold_replicas() && m.health.admits_new_work())
            .map(|m| {
                let node_id = m.failure_domain_vector.node.0;
                let rack_id = m.failure_domain_vector.rack.0;
                let total_bytes = self
                    .budget_tracker
                    .get_budget(m.member_id)
                    .map(|b| b.total_bytes)
                    .unwrap_or(1_000_000_000);
                let used_bytes = self
                    .budget_tracker
                    .get_budget(m.member_id)
                    .map(|b| b.used_bytes)
                    .unwrap_or(0);
                DeviceHealthCapacity {
                    device_id: m.member_id.0,
                    node_id,
                    rack_id,
                    total_bytes,
                    used_bytes,
                    healthy: m.health.admits_new_work(),
                }
            })
            .collect()
    }

    /// BLAKE3-seal a set of placement decisions using the constraint module.
    #[must_use]
    pub fn seal_plan_decisions(
        constraint: &constraint::PlacementConstraint,
        decisions: &[PlacementDecision],
    ) -> BTreeMap<u64, [u8; 32]> {
        decisions
            .iter()
            .map(|d| {
                let seal = constraint::seal_assignment(
                    constraint,
                    d.subject_ref.0,
                    0,
                    d.epoch.0,
                    &[d.target_ref.0],
                );
                (d.decision_id, seal)
            })
            .collect()
    }

    pub fn run_cycle(
        &mut self,
        config: &MembershipConfigRecord,
        members: &[ClusterMemberRecord],
        policy: FailureDomainPlacementPolicy,
        subjects: &[ReplicatedSubjectId],
        byte_cost: u64,
        receipts: &[ReplicaPlacementReceipt],
    ) -> Result<PlacementCycle, PlacementRuntimeError> {
        let _ = self.evaluate(config, members, policy, subjects, &[]);

        let gaps = {
            let cycle = self
                .current_cycle
                .as_ref()
                .ok_or(PlacementRuntimeError::NoActiveCycle)?;
            cycle.under_replicated.clone()
        };
        let decisions = self.plan(&gaps, members, &policy, byte_cost)?;

        let _tickets = self.execute(&decisions)?;

        let decisions_for_verify = decisions.clone();
        let _committed = self.verify(receipts, &decisions_for_verify)?;

        self.complete()?;

        let cycle = self
            .completed_cycles
            .last()
            .cloned()
            .ok_or(PlacementRuntimeError::NoActiveCycle)?;

        Ok(cycle)
    }

    /// Evaluate placement gaps with the per-subject planner.
    pub fn evaluate_with_planner(
        &mut self,
        config: &MembershipConfigRecord,
        members: &[ClusterMemberRecord],
        policy: FailureDomainPlacementPolicy,
        subjects: &[ReplicatedSubjectId],
    ) -> PlacementCycle {
        self.refresh_domains(members);
        self.evaluate(config, members, policy, subjects, &[])
    }

    pub fn advance_epoch(&mut self, new_epoch: EpochId) {
        self.current_epoch = new_epoch;
        self.placement_state.epoch = new_epoch;
        self.budget_tracker.advance_epoch(new_epoch);
        self.plan_registry.advance_epoch(new_epoch);
        self.planner.advance_epoch(new_epoch);
        self.health_tracker.advance_epoch(new_epoch);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PlacementRuntimeError {
    #[error("no active placement cycle")]
    NoActiveCycle,
    #[error("budget error: {0}")]
    Budget(#[from] BudgetError),
    #[error("plan registry error: {0}")]
    PlanRegistry(#[from] PlanRegistryError),
    #[error("plan {plan_id} conflicted with another plan")]
    PlanConflictResolved {
        plan_id: u64,
        conflict: crate::plan_registry::PlanConflict,
    },
    #[error("no healthy members available for placement")]
    NoHealthyMembers,
    #[error("not enough capacity for placement: need {required}, have {available}")]
    InsufficientCapacity { required: u64, available: u64 },
    #[error("epoch mismatch")]
    EpochMismatch {
        cycle_epoch: EpochId,
        runtime_epoch: EpochId,
    },
    #[error("placement planner error: {0}")]
    PlannerError(String),
}

fn flow_class_for_intent(class: tidefs_membership_epoch::PlacementIntentClass) -> FlowCommitClass {
    match class {
        tidefs_membership_epoch::PlacementIntentClass::AuthorityHome => FlowCommitClass::Failover,
        tidefs_membership_epoch::PlacementIntentClass::FailoverSuccessor => {
            FlowCommitClass::Failover
        }
        tidefs_membership_epoch::PlacementIntentClass::VoterSpread => {
            FlowCommitClass::SteadyReplication
        }
        tidefs_membership_epoch::PlacementIntentClass::LearnerStaging => {
            FlowCommitClass::CatchupReplication
        }
        tidefs_membership_epoch::PlacementIntentClass::WitnessSpread => {
            FlowCommitClass::SteadyReplication
        }
        tidefs_membership_epoch::PlacementIntentClass::ReplicaTarget => {
            FlowCommitClass::SteadyReplication
        }
        tidefs_membership_epoch::PlacementIntentClass::RebuildRelocateTarget => {
            FlowCommitClass::Rebuild
        }
        tidefs_membership_epoch::PlacementIntentClass::ShadowValidationOnly => {
            FlowCommitClass::SteadyReplication
        }
    }
}
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn policy_to_layout(policy: &FailureDomainPlacementPolicy) -> DurabilityLayoutV1 {
    DurabilityLayoutV1 {
        policy: DurabilityPolicy::Mirror {
            copies: policy.required_replica_count as u8,
        },
    }
}

fn policy_to_failure_domain(policy: &FailureDomainPlacementPolicy) -> FailureDomainV1 {
    let level = match policy.required_failure_domain_class_ref {
        FailureDomainClass::Device => FailureDomainLevel::Device,
        FailureDomainClass::Node => FailureDomainLevel::Node,
        FailureDomainClass::Rack => FailureDomainLevel::Rack,
        FailureDomainClass::Region => FailureDomainLevel::Datacenter,
        _ => FailureDomainLevel::Node,
    };
    FailureDomainV1::new(level, 64).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::DomainId;
    use tidefs_membership_epoch::{
        ConfigClass, EpochId, FailureDomainClass, FailureDomainPlacementPolicy,
        FailureDomainVector, HealthClass, MemberClass, MemberId, PlacementIntentClass, ReceiptId,
    };

    #[test]
    fn test_placement_runtime_creation() {
        let rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        assert_eq!(rt.current_epoch, EpochId::new(1));
        assert_eq!(rt.local_member_id, MemberId::new(1));
        assert!(rt.current_cycle.is_none());
        assert!(rt.completed_cycles.is_empty());
    }

    #[test]
    fn test_budget_tracker_reserve_and_commit() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        bt.register_member(MemberId::new(1), 1_000_000);

        let reservation = bt
            .reserve(
                MemberId::new(1),
                vec![ReplicatedSubjectId::new(42)],
                4096,
                CycleId::new(1),
                None,
            )
            .expect("reservation");

        assert!(!reservation.committed);
        assert!(!reservation.released);

        bt.commit_reservation(reservation.reservation_id)
            .expect("commit");
        assert!(
            bt.reservations
                .get(&reservation.reservation_id)
                .unwrap()
                .committed
        );

        let budget = bt.get_budget(MemberId::new(1)).unwrap();
        assert_eq!(budget.used_bytes, 4096);
        assert_eq!(budget.reserved_bytes, 0);
    }

    #[test]
    fn test_budget_tracker_release_reservation() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        bt.register_member(MemberId::new(1), 1_000_000);

        let reservation = bt
            .reserve(
                MemberId::new(1),
                vec![ReplicatedSubjectId::new(42)],
                4096,
                CycleId::new(1),
                None,
            )
            .expect("reservation");

        bt.release_reservation(reservation.reservation_id)
            .expect("release");
        assert!(
            bt.reservations
                .get(&reservation.reservation_id)
                .unwrap()
                .released
        );

        let budget = bt.get_budget(MemberId::new(1)).unwrap();
        assert_eq!(budget.used_bytes, 0);
        assert_eq!(budget.reserved_bytes, 0);
    }

    #[test]
    fn test_budget_tracker_insufficient_capacity() {
        let mut bt = PlacementBudgetTracker::new(EpochId::new(1));
        bt.register_member(MemberId::new(1), 100);

        let result = bt.reserve(
            MemberId::new(1),
            vec![ReplicatedSubjectId::new(42)],
            4096,
            CycleId::new(1),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_gap_priority_ordering() {
        assert!(PlacementGapClass::QuorumLoss < PlacementGapClass::AntiAffinityViolation);
        assert!(PlacementGapClass::AntiAffinityViolation < PlacementGapClass::Normal);
        assert!(PlacementGapClass::Normal < PlacementGapClass::Relocation);
    }

    #[test]
    fn test_plan_reserves_all_missing_targets() {
        let mut rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        rt.seed_budgets(BTreeMap::from([
            (MemberId::new(1), 1_000_000),
            (MemberId::new(2), 1_000_000),
            (MemberId::new(3), 1_000_000),
        ]));

        let s1 = ReplicatedSubjectId::new(100);
        rt.placement_state.record_placement(s1, MemberId::new(1));

        let gap = PlacementGap {
            chunk_id: s1.0,
            subject_ref: s1,
            desired: [MemberId::new(1), MemberId::new(2), MemberId::new(3)]
                .iter()
                .copied()
                .collect(),
            actual: [MemberId::new(1)].iter().copied().collect(),
            missing: [MemberId::new(2), MemberId::new(3)]
                .iter()
                .copied()
                .collect(),
            replica_count_gap: 2,
            gap_class: PlacementGapClass::Normal,
            verdict_class: VerdictClass::Admit,
        };

        let members = vec![
            make_member(1, EpochId::new(1)),
            make_member(2, EpochId::new(1)),
            make_member(3, EpochId::new(1)),
        ];

        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Node);

        rt.current_cycle = Some(PlacementCycle::new(CycleId::new(1), EpochId::new(1), 0));

        let decisions = rt
            .plan(&[gap], &members, &policy, 4096)
            .expect("plan succeeded");

        assert_eq!(
            decisions.len(),
            2,
            "should create decisions for both missing targets"
        );
        assert_eq!(
            rt.current_cycle.as_ref().unwrap().reservations.len(),
            2,
            "cycle should track both reservations"
        );
    }

    #[test]
    fn test_verify_uses_precise_matching() {
        let mut rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        rt.seed_budgets(BTreeMap::from([(MemberId::new(2), 1_000_000)]));
        let s1 = ReplicatedSubjectId::new(100);
        rt.placement_state.record_placement(s1, MemberId::new(1));

        rt.current_cycle = Some(PlacementCycle::new(CycleId::new(1), EpochId::new(1), 0));
        let reservation = rt
            .budget_tracker
            .reserve(MemberId::new(2), vec![s1], 4096, CycleId::new(1), None)
            .expect("reservation");

        let decision = PlacementDecision {
            decision_id: 1,
            subject_ref: s1,
            source_ref: MemberId::new(1),
            target_ref: MemberId::new(2),
            placement_class: PlacementIntentClass::ReplicaTarget,
            receipt_ref: ReplicatedReceiptId(reservation.reservation_id.0),
            epoch: EpochId::new(1),
            reservation_ref: reservation.reservation_id,
        };
        rt.current_cycle
            .as_mut()
            .unwrap()
            .reservations
            .push(reservation);

        let receipt = ReplicaPlacementReceipt {
            receipt_id: ReplicatedReceiptId(1),
            verification_ref: ReplicatedReceiptId(0),
            transfer_ref: ReplicatedReceiptId(0),
            subject_refs: vec![s1],
            placed_on: MemberId::new(2),
            placement_epoch: EpochId::new(1),
            subjects_placed: 1,
            placement_receipt_refs: Vec::new(),
        };

        let committed = rt.verify(&[receipt], &[decision]).expect("verify");
        assert_eq!(committed.len(), 1, "should commit one reservation");
    }

    #[test]
    fn test_complete_releases_uncommitted_reservations() {
        let mut rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        rt.seed_budgets(BTreeMap::from([(MemberId::new(2), 1_000_000)]));
        let s1 = ReplicatedSubjectId::new(100);

        let reservation = rt
            .budget_tracker
            .reserve(MemberId::new(2), vec![s1], 4096, CycleId::new(1), None)
            .expect("reservation");

        let mut cycle = PlacementCycle::new(CycleId::new(1), EpochId::new(1), 0);
        cycle.reservations.push(reservation.clone());
        rt.current_cycle = Some(cycle);

        rt.complete().expect("complete");
        assert!(rt.current_cycle.is_none());
        assert_eq!(rt.completed_cycles.len(), 1);

        let r = rt
            .budget_tracker
            .reservations
            .get(&reservation.reservation_id)
            .unwrap();
        assert!(r.released, "uncommitted reservations should be released");
    }

    #[test]
    fn test_retire_excess_frees_budget() {
        let mut rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        rt.seed_budgets(BTreeMap::from([(MemberId::new(2), 1_000_000)]));
        let s1 = ReplicatedSubjectId::new(100);

        rt.budget_tracker
            .budgets
            .get_mut(&MemberId::new(2))
            .unwrap()
            .used_bytes = 8192;
        rt.placement_state.record_placement(s1, MemberId::new(2));

        let excess = PlacementExcess {
            chunk_id: s1.0,
            subject_ref: s1,
            desired: BTreeSet::new(),
            actual: [MemberId::new(2)].iter().copied().collect(),
            excess: [MemberId::new(2)].iter().copied().collect(),
        };

        let retired = rt.retire_excess(&[excess], 4096);
        assert_eq!(retired.len(), 1);
        let budget = rt.budget_tracker.get_budget(MemberId::new(2)).unwrap();
        assert_eq!(
            budget.used_bytes, 4096,
            "excess retirement should reduce used_bytes"
        );
    }

    #[test]
    fn test_evaluate_empty_cluster_yields_no_gaps() {
        let mut rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        let config = MembershipConfigRecord {
            membership_epoch_id: EpochId::new(1),
            config_class: ConfigClass::Normal,
            version_index: 1,
            voter_set_refs: Vec::new(),
            learner_set_refs: Vec::new(),
            observer_set_refs: Vec::new(),
            joint_old_set_refs: Vec::new(),
            joint_new_set_refs: Vec::new(),
            issuance_receipt_ref: ReceiptId::ZERO,
            digest: 1,
        };
        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Node);
        let cycle = rt.evaluate(&config, &[], policy, &[], &[]);
        assert!(cycle.under_replicated.is_empty());
        assert!(cycle.over_replicated.is_empty());
        assert!(cycle.verdicts.is_empty());
    }

    #[test]
    fn test_evaluate_idempotent_during_active_cycle() {
        let mut rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        let member = make_member(1, EpochId::new(1));
        let config = MembershipConfigRecord {
            membership_epoch_id: EpochId::new(1),
            config_class: ConfigClass::Normal,
            version_index: 1,
            voter_set_refs: vec![MemberId::new(1)],
            learner_set_refs: Vec::new(),
            observer_set_refs: Vec::new(),
            joint_old_set_refs: Vec::new(),
            joint_new_set_refs: Vec::new(),
            issuance_receipt_ref: ReceiptId::ZERO,
            digest: 1,
        };
        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Node);
        let subjects = vec![ReplicatedSubjectId::new(1)];
        let c1 = rt.evaluate(&config, &[member], policy, &subjects, &[]);
        let c2 = rt.evaluate(&config, &[member], policy, &subjects, &[]);
        assert_eq!(
            c1.cycle_id, c2.cycle_id,
            "second evaluate should return same cycle"
        );
    }

    #[test]
    fn test_epoch_transition_updates_all_components() {
        let mut rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        rt.seed_budgets(BTreeMap::from([(MemberId::new(2), 1_000_000)]));
        rt.advance_epoch(EpochId::new(3));
        assert_eq!(rt.current_epoch, EpochId::new(3));
        assert_eq!(rt.budget_tracker.current_epoch, EpochId::new(3));
        assert_eq!(rt.plan_registry.current_epoch, EpochId::new(3));
        assert_eq!(rt.planner.epoch, EpochId::new(3));
        assert_eq!(rt.health_tracker.epoch, EpochId::new(3));
    }

    #[test]
    fn test_plan_with_all_empty_members_produces_empty_decisions() {
        let mut rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        rt.current_cycle = Some(PlacementCycle::new(CycleId::new(1), EpochId::new(1), 0));
        let gap = PlacementGap {
            chunk_id: 1,
            subject_ref: ReplicatedSubjectId::new(1),
            desired: [MemberId::new(2)].iter().copied().collect(),
            actual: BTreeSet::new(),
            missing: [MemberId::new(2)].iter().copied().collect(),
            replica_count_gap: 1,
            gap_class: PlacementGapClass::Normal,
            verdict_class: VerdictClass::Admit,
        };
        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Node);
        let result = rt.plan(&[gap], &[], &policy, 4096);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    fn make_member(id: u64, epoch: EpochId) -> ClusterMemberRecord {
        ClusterMemberRecord {
            member_id: MemberId::new(id),
            member_class: MemberClass::Voter,
            health: HealthClass::Healthy,
            current_membership_epoch_ref: epoch,
            failure_domain_vector: FailureDomainVector {
                device: DomainId::new(id),
                node: DomainId::new(id),
                chassis: DomainId::ZERO,
                rack: DomainId::ZERO,
                zone: DomainId::ZERO,
                region: DomainId::ZERO,
            },
            log_frontier: 0,
            digest: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Constraint-wired placement runtime tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_device_capacities_from_members() {
        let rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        let members = vec![
            make_member(1, EpochId::new(1)),
            make_member(2, EpochId::new(1)),
        ];
        let caps = rt.build_device_capacities(&members);
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].device_id, 1);
        assert_eq!(caps[1].device_id, 2);
        assert!(caps[0].healthy);
        assert!(caps[1].healthy);
    }

    #[test]
    fn test_build_device_capacities_excludes_unhealthy() {
        let rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        let mut m = make_member(1, EpochId::new(1));
        m.health = HealthClass::Down;
        let caps = rt.build_device_capacities(&[m]);
        assert!(caps.is_empty());
    }

    #[test]
    fn test_constraint_preflight_rejects_insufficient_devices() {
        let mut rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        rt.current_cycle = Some(PlacementCycle::new(CycleId::new(1), EpochId::new(1), 0));
        let gap = PlacementGap {
            chunk_id: 1,
            subject_ref: ReplicatedSubjectId::new(1),
            desired: [MemberId::new(2), MemberId::new(3)]
                .iter()
                .copied()
                .collect(),
            actual: BTreeSet::new(),
            missing: [MemberId::new(2), MemberId::new(3)]
                .iter()
                .copied()
                .collect(),
            replica_count_gap: 2,
            gap_class: PlacementGapClass::Normal,
            verdict_class: VerdictClass::Admit,
        };
        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(3, FailureDomainClass::Node);
        // Only 2 members — constraint check should fail.
        let members = vec![
            make_member(2, EpochId::new(1)),
            make_member(3, EpochId::new(1)),
        ];
        let err = rt.plan(&[gap], &members, &policy, 4096).unwrap_err();
        assert!(
            matches!(err, PlacementRuntimeError::PlannerError(_)),
            "should return PlannerError for unsatisfiable constraint"
        );
    }

    #[test]
    fn test_constraint_preflight_passes_with_sufficient_devices() {
        let mut rt = PlacementRuntime::new(MemberId::new(1), EpochId::new(1));
        rt.seed_budgets(BTreeMap::from([
            (MemberId::new(2), 1_000_000),
            (MemberId::new(3), 1_000_000),
        ]));
        rt.current_cycle = Some(PlacementCycle::new(CycleId::new(1), EpochId::new(1), 0));
        let gap = PlacementGap {
            chunk_id: 1,
            subject_ref: ReplicatedSubjectId::new(1),
            desired: [MemberId::new(2)].iter().copied().collect(),
            actual: BTreeSet::new(),
            missing: [MemberId::new(2)].iter().copied().collect(),
            replica_count_gap: 1,
            gap_class: PlacementGapClass::Normal,
            verdict_class: VerdictClass::Admit,
        };
        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Node);
        let members = vec![make_member(2, EpochId::new(1))];
        let result = rt.plan(&[gap], &members, &policy, 4096);
        assert!(result.is_ok());
    }

    #[test]
    fn test_seal_plan_decisions_produces_stable_output() {
        let c = constraint::PlacementConstraint::new(
            &DurabilityLayoutV1::mirror(1).unwrap(),
            &FailureDomainV1::new(FailureDomainLevel::Node, 64).unwrap(),
        );
        let decisions = vec![PlacementDecision {
            decision_id: 1,
            subject_ref: ReplicatedSubjectId::new(42),
            source_ref: MemberId::new(1),
            target_ref: MemberId::new(2),
            placement_class: PlacementIntentClass::ReplicaTarget,
            receipt_ref: ReplicatedReceiptId(0),
            epoch: EpochId::new(1),
            reservation_ref: BudgetReservationId::new(1),
        }];

        let seals1 = PlacementRuntime::seal_plan_decisions(&c, &decisions);
        let seals2 = PlacementRuntime::seal_plan_decisions(&c, &decisions);
        assert_eq!(seals1, seals2);
        assert_eq!(seals1.len(), 1);
        assert!(seals1.contains_key(&1));
    }

    #[test]
    fn test_seal_plan_decisions_differs_per_decision() {
        let c = constraint::PlacementConstraint::new(
            &DurabilityLayoutV1::mirror(1).unwrap(),
            &FailureDomainV1::new(FailureDomainLevel::Node, 64).unwrap(),
        );
        let d1 = PlacementDecision {
            decision_id: 1,
            subject_ref: ReplicatedSubjectId::new(42),
            source_ref: MemberId::new(1),
            target_ref: MemberId::new(2),
            placement_class: PlacementIntentClass::ReplicaTarget,
            receipt_ref: ReplicatedReceiptId(0),
            epoch: EpochId::new(1),
            reservation_ref: BudgetReservationId::new(1),
        };
        let d2 = PlacementDecision {
            decision_id: 2,
            subject_ref: ReplicatedSubjectId::new(99),
            source_ref: MemberId::new(1),
            target_ref: MemberId::new(3),
            placement_class: PlacementIntentClass::ReplicaTarget,
            receipt_ref: ReplicatedReceiptId(0),
            epoch: EpochId::new(1),
            reservation_ref: BudgetReservationId::new(2),
        };

        let seals = PlacementRuntime::seal_plan_decisions(&c, &[d1, d2]);
        assert_eq!(seals.len(), 2);
        assert_ne!(seals[&1], seals[&2]);
    }

    #[test]
    fn test_seal_verify_roundtrip() {
        let c = constraint::PlacementConstraint::new(
            &DurabilityLayoutV1::mirror(1).unwrap(),
            &FailureDomainV1::new(FailureDomainLevel::Node, 64).unwrap(),
        );
        let decision = PlacementDecision {
            decision_id: 1,
            subject_ref: ReplicatedSubjectId::new(42),
            source_ref: MemberId::new(1),
            target_ref: MemberId::new(2),
            placement_class: PlacementIntentClass::ReplicaTarget,
            receipt_ref: ReplicatedReceiptId(0),
            epoch: EpochId::new(1),
            reservation_ref: BudgetReservationId::new(1),
        };
        let seal = constraint::seal_assignment(
            &c,
            decision.subject_ref.0,
            0,
            decision.epoch.0,
            &[decision.target_ref.0],
        );
        assert!(constraint::verify_assignment(
            &c,
            decision.subject_ref.0,
            0,
            decision.epoch.0,
            &[decision.target_ref.0],
            &seal,
        ));
    }
}
