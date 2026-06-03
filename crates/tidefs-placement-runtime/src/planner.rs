//! Placement planner: computes per-chunk replica target sets.
//!
//! Wraps the deterministic placement model (OW-303) to compute target
//! replica sets per subject, respecting failure domains, tier goals,
//! and placement policy.

use std::collections::BTreeMap;

use tidefs_membership_epoch::{
    AntiAffinityClass, ClusterMemberRecord, DomainId, EpochId, FailureDomainClass,
    FailureDomainPlacementPolicy, FailureDomainRecord, MemberId, MembershipConfigRecord,
    MembershipPlacementVerdictRecord, PlacementIntentClass, ReceiptId, StorageTierPolicy,
    VerdictClass,
};
use tidefs_placement_planner::{self, TierGoal};
use tidefs_replication_model::ReplicatedSubjectId;

/// PlacementPlanner computes per-subject replica target sets.
#[derive(Debug, Clone)]
pub struct PlacementPlanner {
    pub failure_domains: Vec<FailureDomainRecord>,
    pub epoch: EpochId,
}

impl PlacementPlanner {
    #[must_use]
    pub fn new(epoch: EpochId) -> Self {
        Self {
            failure_domains: Vec::new(),
            epoch,
        }
    }

    pub fn refresh_domains(&mut self, members: &[ClusterMemberRecord]) {
        let mut domain_map: BTreeMap<(FailureDomainClass, DomainId), FailureDomainRecord> =
            BTreeMap::new();
        for member in members {
            for class in &[
                FailureDomainClass::Device,
                FailureDomainClass::Node,
                FailureDomainClass::Rack,
                FailureDomainClass::Region,
            ] {
                let domain_id = member.failure_domain_vector.domain(*class);
                domain_map
                    .entry((*class, domain_id))
                    .or_insert_with(|| FailureDomainRecord {
                        failure_domain_id: domain_id,
                        failure_domain_class_ref: *class,
                        parent_domain_ref: DomainId::ZERO,
                        member_refs: Vec::new(),
                        separation_policy_ref: AntiAffinityClass::Strict,
                        health_class: member.health,
                        availability_receipt_ref: ReceiptId::ZERO,
                        digest: 0,
                        storage_tier: None,
                    })
                    .member_refs
                    .push(member.member_id);
            }
        }
        self.failure_domains = domain_map.into_values().collect();
    }

    /// Apply a [`StorageTierPolicy`] to the current failure domains,
    /// populating `storage_tier` on device-level domain records.
    ///
    /// Call this after [`refresh_domains`] and before computing placement plans
    /// when tier-aware placement is needed.
    pub fn apply_tier_policy(&mut self, policy: &StorageTierPolicy) {
        policy.apply_to_domains(&mut self.failure_domains);
    }

    /// Returns a reference to the current failure domains (for inspection).
    #[must_use]
    pub fn domains(&self) -> &[FailureDomainRecord] {
        &self.failure_domains
    }
    pub fn compute_subject_plan(
        &self,
        _config: &MembershipConfigRecord,
        members: &[ClusterMemberRecord],
        policy: &FailureDomainPlacementPolicy,
        subject_ref: ReplicatedSubjectId,
    ) -> SubjectPlacementPlan {
        let base_plan = tidefs_placement_planner::compute_keyed_replica_target_set(
            policy,
            &self.failure_domains,
            tier_goal_for_placement_class(policy.placement_class),
            self.epoch,
            subject_ref.0,
            &[],
        );

        match base_plan {
            Ok(plan) => {
                let verdict = plan.verdict;
                let degraded = verdict.verdict_class != VerdictClass::Admit;
                SubjectPlacementPlan {
                    subject_ref,
                    selected_members: plan.selected_member_refs,
                    selected_domains: plan.selected_domain_refs,
                    verdict,
                    degraded,
                }
            }
            Err(_) => {
                let eligible = eligible_members_for_policy(members);
                SubjectPlacementPlan {
                    subject_ref,
                    selected_members: eligible
                        .into_iter()
                        .take(policy.required_replica_count)
                        .collect(),
                    selected_domains: Vec::new(),
                    verdict: MembershipPlacementVerdictRecord {
                        verdict_id: 0,
                        membership_epoch_ref: self.epoch,
                        placement_class: policy.placement_class,
                        selected_member_refs: Vec::new(),
                        selected_domain_refs: Vec::new(),
                        verdict_class: VerdictClass::HoldDomainGap,
                        degraded_reason_refs: vec!["insufficient eligible members"],
                        issuance_receipt_ref: ReceiptId::ZERO,
                        digest: 0,
                    },
                    degraded: true,
                }
            }
        }
    }

    #[must_use]
    pub fn compute_subject_plans(
        &self,
        config: &MembershipConfigRecord,
        members: &[ClusterMemberRecord],
        policy: &FailureDomainPlacementPolicy,
        subjects: &[ReplicatedSubjectId],
    ) -> BTreeMap<ReplicatedSubjectId, SubjectPlacementPlan> {
        subjects
            .iter()
            .map(|s| (*s, self.compute_subject_plan(config, members, policy, *s)))
            .collect()
    }

    #[must_use]
    pub fn compute_authority_home(
        &self,
        config: &MembershipConfigRecord,
        members: &[ClusterMemberRecord],
        subject_ref: ReplicatedSubjectId,
    ) -> Option<(MemberId, MembershipPlacementVerdictRecord)> {
        let voters: Vec<&ClusterMemberRecord> = members
            .iter()
            .filter(|m| {
                m.current_membership_epoch_ref == config.membership_epoch_id
                    && m.member_class.can_vote()
                    && m.health.admits_new_work()
            })
            .collect();
        if voters.is_empty() {
            return None;
        }
        let leader_idx = (subject_ref.0 as usize) % voters.len();
        let leader = voters[leader_idx].member_id;
        let verdict = MembershipPlacementVerdictRecord {
            verdict_id: 0,
            membership_epoch_ref: self.epoch,
            placement_class: PlacementIntentClass::AuthorityHome,
            selected_member_refs: vec![leader],
            selected_domain_refs: Vec::new(),
            verdict_class: VerdictClass::Admit,
            degraded_reason_refs: Vec::new(),
            issuance_receipt_ref: ReceiptId::ZERO,
            digest: 0,
        };
        Some((leader, verdict))
    }

    pub fn advance_epoch(&mut self, new_epoch: EpochId) {
        self.epoch = new_epoch;
    }
}

#[derive(Debug, Clone)]
pub struct SubjectPlacementPlan {
    pub subject_ref: ReplicatedSubjectId,
    pub selected_members: Vec<MemberId>,
    pub selected_domains: Vec<DomainId>,
    pub verdict: MembershipPlacementVerdictRecord,
    pub degraded: bool,
}

#[must_use]
pub fn tier_goal_for_placement_class(class: PlacementIntentClass) -> TierGoal {
    match class {
        PlacementIntentClass::AuthorityHome
        | PlacementIntentClass::FailoverSuccessor
        | PlacementIntentClass::VoterSpread
        | PlacementIntentClass::ReplicaTarget => TierGoal::Primary,
        PlacementIntentClass::WitnessSpread | PlacementIntentClass::LearnerStaging => {
            TierGoal::Secondary
        }
        PlacementIntentClass::RebuildRelocateTarget => TierGoal::Primary,
        PlacementIntentClass::ShadowValidationOnly => TierGoal::Archive,
    }
}

#[must_use]
fn eligible_members_for_policy(members: &[ClusterMemberRecord]) -> Vec<MemberId> {
    let mut eligible: Vec<MemberId> = members
        .iter()
        .filter(|m| m.member_class.can_hold_replicas() && m.health.admits_new_work())
        .map(|m| m.member_id)
        .collect();
    eligible.sort();
    eligible
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_goal_mapping() {
        assert_eq!(
            tier_goal_for_placement_class(PlacementIntentClass::ReplicaTarget),
            TierGoal::Primary
        );
        assert_eq!(
            tier_goal_for_placement_class(PlacementIntentClass::WitnessSpread),
            TierGoal::Secondary
        );
        assert_eq!(
            tier_goal_for_placement_class(PlacementIntentClass::ShadowValidationOnly),
            TierGoal::Archive
        );
    }

    #[test]
    fn test_planner_creation() {
        let planner = PlacementPlanner::new(EpochId::new(1));
        assert_eq!(planner.epoch, EpochId::new(1));
        assert!(planner.failure_domains.is_empty());
    }

    #[test]
    fn subject_plans_use_subject_keyed_target_order() {
        let members: Vec<ClusterMemberRecord> = (1..=6)
            .map(|id| ClusterMemberRecord {
                member_id: MemberId::new(id),
                member_class: tidefs_membership_epoch::MemberClass::Voter,
                current_membership_epoch_ref: EpochId::new(7),
                log_frontier: 100,
                health: tidefs_membership_epoch::HealthClass::Healthy,
                failure_domain_vector: tidefs_membership_epoch::FailureDomainVector::new(
                    tidefs_membership_epoch::DomainId::new(id),
                    tidefs_membership_epoch::DomainId::new(id),
                    tidefs_membership_epoch::DomainId::new(id),
                    tidefs_membership_epoch::DomainId::new(id),
                    tidefs_membership_epoch::DomainId::new(1),
                    tidefs_membership_epoch::DomainId::new(1),
                ),
                digest: id,
            })
            .collect();
        let config = MembershipConfigRecord {
            membership_epoch_id: EpochId::new(7),
            config_class: tidefs_membership_epoch::ConfigClass::Normal,
            version_index: 1,
            voter_set_refs: members.iter().map(|m| m.member_id).collect(),
            learner_set_refs: Vec::new(),
            observer_set_refs: Vec::new(),
            joint_old_set_refs: Vec::new(),
            joint_new_set_refs: Vec::new(),
            issuance_receipt_ref: ReceiptId::ZERO,
            digest: 7,
        };
        let policy = FailureDomainPlacementPolicy::strict_replica_targets(
            3,
            tidefs_membership_epoch::FailureDomainClass::Node,
        );

        let mut planner = PlacementPlanner::new(EpochId::new(7));
        planner.refresh_domains(&members);
        let mut seen = std::collections::BTreeSet::new();
        for subject in 0..24 {
            let plan = planner.compute_subject_plan(
                &config,
                &members,
                &policy,
                ReplicatedSubjectId::new(subject),
            );
            seen.insert(plan.selected_members);
        }

        assert!(
            seen.len() > 1,
            "subject-keyed placement should spread target order across subjects"
        );
    }
}
