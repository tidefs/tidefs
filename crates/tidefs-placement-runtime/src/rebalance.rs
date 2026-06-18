// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Rebalance integration: wires the capacity rebalance planner into the
//! placement runtime so that epoch transitions, capacity skew detection,
//! and rebalance plan execution flow through the standard placement
//! lifecycle (PC-010.4).

use std::collections::BTreeMap;

use tidefs_membership_epoch::{
    ClusterMemberRecord, EpochId, FailureDomainPlacementPolicy, FailureDomainRecord, MemberId,
};
use tidefs_rebalance_planner::{MovementBudget, RebalanceError, RebalanceIntent, RebalancePlanner};
use tidefs_rebuild_planner::CapacityRebalanceSkew;
use tidefs_replica_health::NodeId;

/// Integration wrapper that ties the rebalance planner into placement-runtime.
///
/// Provides capacity skew detection, rebalance planning, and
/// epoch-transition abort that feeds into the placement lifecycle.
#[derive(Debug)]
pub struct RebalanceIntegration {
    /// The underlying rebalance planner.
    pub planner: RebalancePlanner,
    /// Map from placement-runtime MemberId to NodeId for the rebalance planner.
    pub member_node_map: BTreeMap<MemberId, u64>,
    /// Current epoch.
    pub epoch: EpochId,
}

impl RebalanceIntegration {
    #[must_use]
    pub fn new(epoch: EpochId) -> Self {
        Self {
            planner: RebalancePlanner::default_for_epoch(epoch),
            member_node_map: BTreeMap::new(),
            epoch,
        }
    }

    /// Rebuild the member→node mapping from the current member list.
    pub fn refresh_members(&mut self, members: &[ClusterMemberRecord]) {
        self.member_node_map.clear();
        for m in members {
            self.member_node_map.insert(m.member_id, m.member_id.0);
        }
    }

    /// Detect capacity skew from per-member utilization data.
    ///
    /// Returns `None` if the variance is below the rebalance threshold.
    pub fn detect_skew(
        &self,
        node_utilization: &BTreeMap<u64, u64>,
        total_capacity: u64,
        now_ms: u64,
    ) -> Option<CapacityRebalanceSkew> {
        // Convert BTreeMap<u64, u64> to BTreeMap<NodeId, u64> for the planner
        let node_util: BTreeMap<NodeId, u64> = node_utilization
            .iter()
            .map(|(k, v)| (NodeId(*k), *v))
            .collect();
        self.planner.detect_skew(&node_util, total_capacity, now_ms)
    }

    /// Plan rebalancing given a detected capacity skew.
    ///
    /// Produces a rebalance plan that can be converted into transfer tickets.
    pub fn plan(
        &mut self,
        skew: &CapacityRebalanceSkew,
        epoch: EpochId,
        failure_domains: &[FailureDomainRecord],
        policy: &FailureDomainPlacementPolicy,
        now_ms: u64,
        evidence_commit_group_id: u64,
        committed_free_bytes_by_member: &BTreeMap<MemberId, u64>,
    ) -> Result<&Vec<RebalanceIntent>, RebalanceError> {
        self.planner.plan_rebalance(
            skew,
            epoch,
            failure_domains,
            policy,
            now_ms,
            evidence_commit_group_id,
            committed_free_bytes_by_member,
        )?;
        // Return the intents from the newly-created plan
        Ok(&self.planner.plans.last().unwrap().intents)
    }

    /// Handle an epoch transition: abort inflight plans, advance the epoch.
    pub fn on_epoch_transition(&mut self, new_epoch: EpochId, at_ns: u64) {
        self.planner.on_epoch_transition(new_epoch, at_ns);
        self.epoch = new_epoch;
    }

    /// Check if there are active rebalance plans.
    #[must_use]
    pub fn has_active_work(&self) -> bool {
        self.planner.has_active_work()
    }

    /// Get all active (non-aborted) rebalance intents.
    #[must_use]
    pub fn active_intents(&self) -> Vec<&RebalanceIntent> {
        self.planner
            .plans
            .iter()
            .filter(|p| !p.is_aborted)
            .flat_map(|p| p.intents.iter())
            .collect()
    }

    /// Get the movement budget reference.
    #[must_use]
    pub fn budget(&self) -> Option<&MovementBudget> {
        self.planner.movement_budget.as_ref()
    }

    /// Get the movement budget mutably.
    pub fn budget_mut(&mut self) -> Option<&mut MovementBudget> {
        self.planner.movement_budget.as_mut()
    }

    /// Check if the movement budget is entirely exhausted.
    #[must_use]
    pub fn budget_exhausted(&self) -> bool {
        self.planner
            .movement_budget
            .as_ref()
            .is_some_and(|b| b.is_exhausted)
    }
}

/// Build a per-member utilization snapshot for capacity skew detection.
#[must_use]
pub fn member_utilization_snapshot(
    members: &[ClusterMemberRecord],
    member_used_bytes: &BTreeMap<MemberId, u64>,
) -> BTreeMap<u64, u64> {
    let mut util = BTreeMap::new();
    for m in members {
        if m.member_class.can_hold_replicas() && m.health.admits_new_work() {
            let used = member_used_bytes.get(&m.member_id).copied().unwrap_or(0);
            util.insert(m.member_id.0, used);
        }
    }
    util
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::{
        AntiAffinityClass, DomainId, FailureDomainClass, FailureDomainRecord, FailureDomainVector,
        HealthClass, MemberClass, ReceiptId,
    };

    fn make_member(id: u64, class: MemberClass, health: HealthClass) -> ClusterMemberRecord {
        ClusterMemberRecord {
            member_id: MemberId::new(id),
            member_class: class,
            health,
            current_membership_epoch_ref: EpochId::new(1),
            failure_domain_vector: FailureDomainVector {
                device: DomainId::new(id),
                node: DomainId::new(id),
                chassis: DomainId::ZERO,
                rack: DomainId::new(id % 3 + 1),
                zone: DomainId::ZERO,
                region: DomainId::ZERO,
            },
            log_frontier: 0,
            digest: 0,
        }
    }

    fn make_failure_domain(id: u64, member_id: u64) -> FailureDomainRecord {
        FailureDomainRecord {
            failure_domain_id: DomainId::new(id),
            failure_domain_class_ref: FailureDomainClass::Rack,
            member_refs: vec![MemberId::new(member_id)],
            health_class: HealthClass::Healthy,
            separation_policy_ref: AntiAffinityClass::Strict,
            parent_domain_ref: DomainId::ZERO,
            availability_receipt_ref: ReceiptId::ZERO,
            storage_tier: None,
            digest: 0,
        }
    }

    #[test]
    fn integration_creates_with_epoch() {
        let ri = RebalanceIntegration::new(EpochId::new(1));
        assert_eq!(ri.epoch, EpochId::new(1));
        assert!(!ri.has_active_work());
    }

    #[test]
    fn refresh_members_builds_map() {
        let mut ri = RebalanceIntegration::new(EpochId::new(1));
        let m1 = make_member(1, MemberClass::Voter, HealthClass::Healthy);
        let m2 = make_member(2, MemberClass::Voter, HealthClass::Healthy);
        ri.refresh_members(&[m1, m2]);
        assert_eq!(ri.member_node_map.len(), 2);
        assert!(ri.member_node_map.contains_key(&MemberId::new(1)));
        assert!(ri.member_node_map.contains_key(&MemberId::new(2)));
    }

    #[test]
    fn on_epoch_transition_updates_epoch() {
        let mut ri = RebalanceIntegration::new(EpochId::new(1));
        ri.on_epoch_transition(EpochId::new(2), 1000);
        assert_eq!(ri.epoch, EpochId::new(2));
    }

    #[test]
    fn plan_records_committed_evidence_commit_group() {
        let mut ri = RebalanceIntegration::new(EpochId::new(1));
        let skew =
            CapacityRebalanceSkew::new(vec![NodeId(1)], vec![NodeId(2)], 50, 20, 100_000, 10, 1000);
        let domains = vec![make_failure_domain(1, 1), make_failure_domain(2, 2)];
        let policy =
            FailureDomainPlacementPolicy::strict_replica_targets(1, FailureDomainClass::Rack);
        let committed_free = BTreeMap::from([(MemberId::new(2), 1_000_000)]);

        let intents = ri
            .plan(
                &skew,
                EpochId::new(1),
                &domains,
                &policy,
                2000,
                42,
                &committed_free,
            )
            .expect("rebalance plan");

        assert!(!intents.is_empty());
        assert_eq!(ri.planner.plans[0].evidence_commit_group_id, 42);
    }

    #[test]
    fn member_utilization_snapshot_filters_non_replica_members() {
        let m1 = make_member(1, MemberClass::Voter, HealthClass::Healthy);
        let m2 = make_member(2, MemberClass::WitnessOnly, HealthClass::Healthy);
        let m3 = make_member(3, MemberClass::Voter, HealthClass::Down);

        let mut used = BTreeMap::new();
        used.insert(MemberId::new(1), 4096);
        used.insert(MemberId::new(2), 1024);
        used.insert(MemberId::new(3), 2048);

        let snap = member_utilization_snapshot(&[m1, m2, m3], &used);
        // Only member 1 is replica-capable and healthy.
        assert_eq!(snap.len(), 1);
        assert_eq!(snap.get(&1), Some(&4096));
    }
}
