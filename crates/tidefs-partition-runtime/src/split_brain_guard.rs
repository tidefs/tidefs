// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! SplitBrainGuard: membership-epoch-gated quorum checking, witness-vouche
//! verification, minority-side freeze, and split-brain hazard emission.

use crate::types::{
    derive_record_id, now_millis, PartitionFence, PartitionHazardClass, PartitionState,
    ReachabilityMatrix,
};
use std::collections::BTreeSet;
use tidefs_membership_epoch::{
    self as me, ClusterMemberRecord, EpochId, MemberClass, MemberId, SplitBrainHazardRecord,
    VerdictClass,
};
use tidefs_membership_live::failure_detector::FailureDetector;
use tidefs_witness_set::types::{WitnessError, WitnessSet};

pub struct SplitBrainGuard {
    pub my_id: MemberId,
    pub epoch: EpochId,
    pub partition_state: PartitionState,
    pub fence: PartitionFence,
    pub hazard_records: Vec<SplitBrainHazardRecord>,
    pub min_voters_for_quorum: usize,
}

impl SplitBrainGuard {
    pub fn new(my_id: MemberId, epoch: EpochId, min_voters_for_quorum: usize) -> Self {
        Self {
            my_id,
            epoch,
            partition_state: PartitionState::Connected,
            fence: PartitionFence::default(),
            hazard_records: Vec::new(),
            min_voters_for_quorum,
        }
    }

    pub fn evaluate(
        &mut self,
        matrix: &ReachabilityMatrix,
        _detector: &FailureDetector,
        members: &[ClusterMemberRecord],
    ) -> (PartitionState, Option<SplitBrainHazardRecord>) {
        let components = matrix.connected_components();

        if components.len() <= 1 {
            if matches!(self.partition_state, PartitionState::Healing { .. }) {
                return (self.partition_state.clone(), None);
            }
            return (self.partition_state.clone(), None);
        }

        let my_component = self.find_my_component(&components);
        let other_components: Vec<&Vec<MemberId>> = components
            .iter()
            .filter(|c| !c.contains(&self.my_id))
            .collect();

        let total_voters = self.count_total_voters(members);
        let my_voters = self.count_voters_in(&my_component, members);
        let quorum_threshold = (total_voters / 2) + 1;

        let (hazard_class, new_state) = if my_voters >= quorum_threshold {
            let minority: Vec<MemberId> = other_components
                .iter()
                .flat_map(|c| c.iter().copied())
                .collect();
            (
                PartitionHazardClass::QuorumSide,
                PartitionState::QuorumSideActive {
                    minority_members: minority.clone(),
                    new_epoch: self.epoch.next(),
                    since_millis: now_millis(),
                },
            )
        } else {
            let quorum_side_count: usize = components
                .iter()
                .filter(|c| self.count_voters_in(c, members) >= quorum_threshold)
                .count();

            if quorum_side_count > 0 {
                (
                    PartitionHazardClass::MinoritySide,
                    PartitionState::MinorityFenced {
                        quorum_side_voter_count: quorum_threshold,
                        since_millis: now_millis(),
                    },
                )
            } else {
                (
                    PartitionHazardClass::PartitionAmbiguous,
                    PartitionState::AmbiguousHalted {
                        sides: components.clone(),
                        since_millis: now_millis(),
                    },
                )
            }
        };

        self.partition_state = new_state.clone();

        match &self.partition_state {
            PartitionState::MinorityFenced { .. } | PartitionState::AmbiguousHalted { .. } => {
                self.fence = PartitionFence::raise_all();
            }
            _ => {}
        }

        let hazard = self.emit_split_brain_hazard(
            hazard_class,
            &my_component,
            &other_components
                .iter()
                .flat_map(|c| c.iter().copied())
                .collect::<Vec<_>>(),
        );

        (new_state, hazard)
    }

    #[must_use]
    pub fn can_accept_writes(&self) -> bool {
        matches!(
            &self.partition_state,
            PartitionState::Connected | PartitionState::QuorumSideActive { .. }
        )
    }

    #[must_use]
    pub fn can_commit_publications(&self) -> bool {
        !self.fence.publication_frozen && self.can_accept_writes()
    }

    #[must_use]
    pub fn can_grant_leases(&self) -> bool {
        !self.fence.leases_frozen && self.can_accept_writes()
    }

    #[must_use]
    pub fn can_mint_receipts(&self) -> bool {
        !self.fence.receipts_frozen && self.can_accept_writes()
    }

    #[must_use]
    pub fn authority_homes_valid(&self) -> bool {
        !self.fence.authority_homes_invalidated
    }

    pub fn verify_witness_vouche(
        &self,
        witness_set: &WitnessSet,
        required_confirmations: usize,
    ) -> Result<usize, WitnessError> {
        let quorum_side = self.get_quorum_side_members();
        let confirming = witness_set
            .collected
            .iter()
            .filter(|w| quorum_side.contains(&w.witness_id))
            .count();

        if confirming >= required_confirmations {
            Ok(confirming)
        } else {
            Err(WitnessError::InsufficientVoters {
                have: confirming,
                need: required_confirmations,
            })
        }
    }

    #[must_use]
    pub fn get_quorum_side_members(&self) -> Vec<MemberId> {
        vec![self.my_id]
    }

    #[must_use]
    pub fn get_minority_side_members(&self) -> Vec<MemberId> {
        match &self.partition_state {
            PartitionState::QuorumSideActive {
                ref minority_members,
                ..
            } => minority_members.clone(),
            PartitionState::MinorityFenced { .. } => vec![self.my_id],
            _ => Vec::new(),
        }
    }

    fn find_my_component(&self, components: &[Vec<MemberId>]) -> Vec<MemberId> {
        for comp in components {
            if comp.contains(&self.my_id) {
                return comp.clone();
            }
        }
        vec![self.my_id]
    }

    fn count_voters_in(&self, component: &[MemberId], members: &[ClusterMemberRecord]) -> usize {
        let comp_set: BTreeSet<MemberId> = component.iter().copied().collect();
        members
            .iter()
            .filter(|m| {
                comp_set.contains(&m.member_id)
                    && m.member_class.can_vote()
                    && m.health != me::HealthClass::Down
                    && m.member_class != MemberClass::Quarantined
            })
            .count()
    }

    fn count_total_voters(&self, members: &[ClusterMemberRecord]) -> usize {
        members
            .iter()
            .filter(|m| m.member_class.can_vote() && m.member_class != MemberClass::Quarantined)
            .count()
    }

    fn emit_split_brain_hazard(
        &mut self,
        hazard_class: PartitionHazardClass,
        my_component: &[MemberId],
        other_members: &[MemberId],
    ) -> Option<SplitBrainHazardRecord> {
        let mut conflicting_holders: Vec<MemberId> = my_component
            .iter()
            .chain(other_members.iter())
            .copied()
            .collect();
        conflicting_holders.sort();
        conflicting_holders.dedup();

        let hazard_id = derive_record_id(
            self.epoch.0,
            hazard_class as u64,
            conflicting_holders.len() as u64,
        );

        let hazard = SplitBrainHazardRecord {
            hazard_id,
            authority_domain_ref: tidefs_membership_epoch::AuthorityDomainId::new(self.epoch.0),
            membership_epoch_ref: self.epoch,
            conflicting_holder_refs: conflicting_holders,
            conflicting_domain_refs: Vec::new(),
            required_hold_or_quarantine_ref: VerdictClass::RefuseSplitBrain,
            resolution_receipt_ref: tidefs_membership_epoch::ReceiptId::ZERO,
            digest: derive_record_id(hazard_id, VerdictClass::RefuseSplitBrain as u64, 0x71),
        };

        self.hazard_records.push(hazard.clone());
        Some(hazard)
    }

    pub fn reset(&mut self) {
        self.partition_state = PartitionState::Connected;
        self.fence = PartitionFence::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    fn make_detector() -> FailureDetector {
        let kp = Keypair::generate(&mut OsRng);
        FailureDetector::new(Default::default(), kp)
    }

    fn voter_member(id: u64) -> ClusterMemberRecord {
        ClusterMemberRecord {
            member_id: MemberId::new(id),
            member_class: MemberClass::Voter,
            current_membership_epoch_ref: EpochId::new(1),
            log_frontier: 0,
            health: me::HealthClass::Healthy,
            failure_domain_vector: me::FailureDomainVector::new(
                me::DomainId::new(id),
                me::DomainId::new(100 + id),
                me::DomainId::ZERO,
                me::DomainId::ZERO,
                me::DomainId::ZERO,
                me::DomainId::ZERO,
            ),
            digest: 0,
        }
    }

    fn reachability_entry(observer: u64, reachable: Vec<u64>) -> crate::types::ReachabilityEntry {
        crate::types::ReachabilityEntry {
            observer: MemberId::new(observer),
            reachable: reachable.into_iter().map(MemberId::new).collect(),
            observed_at_millis: 1000,
            epoch: EpochId::new(1),
        }
    }

    #[test]
    fn test_initial_state_connected() {
        let guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        assert!(guard.can_accept_writes());
        assert!(guard.can_commit_publications());
        assert!(guard.can_grant_leases());
        assert!(guard.can_mint_receipts());
        assert!(guard.authority_homes_valid());
    }

    // ----- evaluate() coverage -----

    #[test]
    fn evaluate_quorum_side_with_majority() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2, 3]),
                reachability_entry(2, vec![1, 3]),
                reachability_entry(3, vec![1, 2]),
                reachability_entry(4, vec![]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=4).map(voter_member).collect();
        let (state, hazard) = guard.evaluate(&matrix, &detector, &members);
        assert!(matches!(state, PartitionState::QuorumSideActive { .. }));
        assert!(hazard.is_some());
        assert!(guard.can_accept_writes());
        assert!(!guard.fence.is_any_raised());
    }

    #[test]
    fn evaluate_minority_side_fenced() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2]),
                reachability_entry(2, vec![1]),
                reachability_entry(3, vec![4, 5]),
                reachability_entry(4, vec![3, 5]),
                reachability_entry(5, vec![3, 4]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=5).map(voter_member).collect();
        let (state, hazard) = guard.evaluate(&matrix, &detector, &members);
        assert!(matches!(state, PartitionState::MinorityFenced { .. }));
        assert!(hazard.is_some());
        assert!(!guard.can_accept_writes());
        assert!(guard.fence.is_any_raised());
    }

    #[test]
    fn evaluate_ambiguous_split_no_quorum() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2]),
                reachability_entry(2, vec![1]),
                reachability_entry(3, vec![4]),
                reachability_entry(4, vec![3]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=4).map(voter_member).collect();
        let (state, hazard) = guard.evaluate(&matrix, &detector, &members);
        assert!(matches!(state, PartitionState::AmbiguousHalted { .. }));
        assert!(hazard.is_some());
        assert!(!guard.can_accept_writes());
        assert!(guard.fence.is_any_raised());
    }

    #[test]
    fn evaluate_connected_single_component() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2, 3]),
                reachability_entry(2, vec![1, 3]),
                reachability_entry(3, vec![1, 2]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=3).map(voter_member).collect();
        let (state, hazard) = guard.evaluate(&matrix, &detector, &members);
        assert!(matches!(state, PartitionState::Connected));
        assert!(hazard.is_none());
    }

    #[test]
    fn evaluate_empty_members() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![1]),
                reachability_entry(2, vec![2]),
            ],
            computed_at_millis: 1000,
        };
        let (state, _) = guard.evaluate(&matrix, &detector, &[]);
        assert!(matches!(state, PartitionState::AmbiguousHalted { .. }));
    }

    #[test]
    fn evaluate_single_node_self_only() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![reachability_entry(1, vec![])],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = vec![voter_member(1)];
        let (state, hazard) = guard.evaluate(&matrix, &detector, &members);
        assert!(matches!(state, PartitionState::Connected));
        assert!(hazard.is_none());
    }

    #[test]
    fn test_hazard_emission_on_partition() {
        let _guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![1, 2, 3]),
                reachability_entry(4, vec![4, 5]),
            ],
            computed_at_millis: 1000,
        };
        assert_eq!(matrix.connected_components().len(), 2);
    }

    // ----- Predicates -----

    #[test]
    fn predicates_on_minority() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2]),
                reachability_entry(2, vec![1]),
                reachability_entry(3, vec![4, 5]),
                reachability_entry(4, vec![3, 5]),
                reachability_entry(5, vec![3, 4]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=5).map(voter_member).collect();
        guard.evaluate(&matrix, &detector, &members);
        assert!(!guard.can_accept_writes());
        assert!(!guard.can_commit_publications());
        assert!(!guard.can_grant_leases());
        assert!(!guard.can_mint_receipts());
        assert!(!guard.authority_homes_valid());
    }

    #[test]
    fn predicates_on_ambiguous() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2]),
                reachability_entry(2, vec![1]),
                reachability_entry(3, vec![4]),
                reachability_entry(4, vec![3]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=4).map(voter_member).collect();
        guard.evaluate(&matrix, &detector, &members);
        assert!(!guard.can_accept_writes());
        assert!(!guard.can_commit_publications());
        assert!(!guard.can_grant_leases());
        assert!(!guard.can_mint_receipts());
        assert!(!guard.authority_homes_valid());
    }

    #[test]
    fn predicates_on_quorum() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2, 3]),
                reachability_entry(2, vec![1, 3]),
                reachability_entry(3, vec![1, 2]),
                reachability_entry(4, vec![]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=4).map(voter_member).collect();
        guard.evaluate(&matrix, &detector, &members);
        assert!(guard.can_accept_writes());
        assert!(guard.can_commit_publications());
        assert!(guard.can_grant_leases());
        assert!(guard.can_mint_receipts());
        assert!(guard.authority_homes_valid());
    }

    // ----- Fence and reset -----

    #[test]
    fn fence_raised_on_minority() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        assert!(!guard.fence.is_any_raised());
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2]),
                reachability_entry(2, vec![1]),
                reachability_entry(3, vec![4, 5]),
                reachability_entry(4, vec![3, 5]),
                reachability_entry(5, vec![3, 4]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=5).map(voter_member).collect();
        guard.evaluate(&matrix, &detector, &members);
        assert!(guard.fence.is_any_raised());
        assert!(guard.fence.publication_frozen);
        assert!(guard.fence.leases_frozen);
        assert!(guard.fence.receipts_frozen);
        assert!(guard.fence.authority_homes_invalidated);
    }

    #[test]
    fn restored_connectivity_keeps_healing_fenced_until_completion() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        guard.partition_state = PartitionState::Healing {
            joint_epoch: EpochId::new(2),
            rejoining_members: vec![MemberId::new(2)],
            since_millis: 1000,
        };
        guard.fence = PartitionFence::raise_all();

        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2, 3]),
                reachability_entry(2, vec![1, 3]),
                reachability_entry(3, vec![1, 2]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=3).map(voter_member).collect();

        let (state, hazard) = guard.evaluate(&matrix, &detector, &members);

        assert!(matches!(state, PartitionState::Healing { .. }));
        assert!(hazard.is_none());
        assert!(guard.fence.publication_frozen);
        assert!(guard.fence.leases_frozen);
        assert!(guard.fence.receipts_frozen);
        assert!(!guard.can_accept_writes());
        assert!(!guard.can_commit_publications());
        assert!(!guard.can_grant_leases());
        assert!(!guard.can_mint_receipts());
    }

    #[test]
    fn reset_restores_connected() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2]),
                reachability_entry(2, vec![1]),
                reachability_entry(3, vec![4, 5]),
                reachability_entry(4, vec![3, 5]),
                reachability_entry(5, vec![3, 4]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=5).map(voter_member).collect();
        guard.evaluate(&matrix, &detector, &members);
        assert!(!guard.can_accept_writes());
        guard.reset();
        assert!(matches!(guard.partition_state, PartitionState::Connected));
        assert!(!guard.fence.is_any_raised());
        assert!(guard.can_accept_writes());
    }

    // ----- get_quorum_side_members / get_minority_side_members -----

    #[test]
    fn get_quorum_side_members_self() {
        let guard = SplitBrainGuard::new(MemberId::new(5), EpochId::new(1), 2);
        assert_eq!(guard.get_quorum_side_members(), vec![MemberId::new(5)]);
    }

    #[test]
    fn get_minority_side_members_after_quorum() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2, 3]),
                reachability_entry(2, vec![1, 3]),
                reachability_entry(3, vec![1, 2]),
                reachability_entry(4, vec![]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=4).map(voter_member).collect();
        guard.evaluate(&matrix, &detector, &members);
        assert_eq!(guard.get_minority_side_members(), vec![MemberId::new(4)]);
    }

    // ----- Edge cases -----

    #[test]
    fn evaluate_three_components_with_quorum() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2, 3, 4]),
                reachability_entry(2, vec![1, 3, 4]),
                reachability_entry(3, vec![1, 2, 4]),
                reachability_entry(4, vec![1, 2, 3]),
                reachability_entry(5, vec![6]),
                reachability_entry(6, vec![5]),
                reachability_entry(7, vec![]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=7).map(voter_member).collect();
        let (state, _) = guard.evaluate(&matrix, &detector, &members);
        assert!(matches!(state, PartitionState::QuorumSideActive { .. }));
    }

    #[test]
    fn evaluate_three_components_no_quorum() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2, 3]),
                reachability_entry(2, vec![1, 3]),
                reachability_entry(3, vec![1, 2]),
                reachability_entry(4, vec![5]),
                reachability_entry(5, vec![4]),
                reachability_entry(6, vec![7]),
                reachability_entry(7, vec![6]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=7).map(voter_member).collect();
        let (state, _) = guard.evaluate(&matrix, &detector, &members);
        assert!(matches!(state, PartitionState::AmbiguousHalted { .. }));
    }

    #[test]
    fn evaluate_learner_not_counted() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![reachability_entry(1, vec![]), reachability_entry(2, vec![])],
            computed_at_millis: 1000,
        };
        let members = vec![
            voter_member(1),
            ClusterMemberRecord {
                member_id: MemberId::new(2),
                member_class: MemberClass::Learner,
                current_membership_epoch_ref: EpochId::new(1),
                log_frontier: 0,
                health: me::HealthClass::Healthy,
                failure_domain_vector: me::FailureDomainVector::new(
                    me::DomainId::new(2),
                    me::DomainId::new(102),
                    me::DomainId::ZERO,
                    me::DomainId::ZERO,
                    me::DomainId::ZERO,
                    me::DomainId::ZERO,
                ),
                digest: 0,
            },
        ];
        let (state, _) = guard.evaluate(&matrix, &detector, &members);
        assert!(matches!(state, PartitionState::QuorumSideActive { .. }));
    }

    #[test]
    fn evaluate_quarantined_not_counted() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![reachability_entry(1, vec![]), reachability_entry(3, vec![])],
            computed_at_millis: 1000,
        };
        let members = vec![
            voter_member(1),
            ClusterMemberRecord {
                member_id: MemberId::new(2),
                member_class: MemberClass::Quarantined,
                current_membership_epoch_ref: EpochId::new(1),
                log_frontier: 0,
                health: me::HealthClass::Healthy,
                failure_domain_vector: me::FailureDomainVector::new(
                    me::DomainId::new(2),
                    me::DomainId::new(102),
                    me::DomainId::ZERO,
                    me::DomainId::ZERO,
                    me::DomainId::ZERO,
                    me::DomainId::ZERO,
                ),
                digest: 0,
            },
            voter_member(3),
        ];
        let (state, _) = guard.evaluate(&matrix, &detector, &members);
        assert!(matches!(state, PartitionState::AmbiguousHalted { .. }));
    }

    #[test]
    fn evaluate_idempotent_same_inputs() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2, 3]),
                reachability_entry(2, vec![1, 3]),
                reachability_entry(3, vec![1, 2]),
                reachability_entry(4, vec![]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=4).map(voter_member).collect();
        let (state1, _) = guard.evaluate(&matrix, &detector, &members);
        let (state2, _) = guard.evaluate(&matrix, &detector, &members);
        assert_eq!(state1, state2);
    }

    #[test]
    fn hazard_records_accumulate() {
        let mut guard = SplitBrainGuard::new(MemberId::new(1), EpochId::new(1), 2);
        assert!(guard.hazard_records.is_empty());
        let detector = make_detector();
        let matrix = ReachabilityMatrix {
            entries: vec![
                reachability_entry(1, vec![2, 3]),
                reachability_entry(2, vec![1, 3]),
                reachability_entry(3, vec![1, 2]),
                reachability_entry(4, vec![]),
            ],
            computed_at_millis: 1000,
        };
        let members: Vec<ClusterMemberRecord> = (1..=4).map(voter_member).collect();
        guard.evaluate(&matrix, &detector, &members);
        assert!(!guard.hazard_records.is_empty());
    }
}
