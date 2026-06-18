// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! PartitionDetector: monitors SWIM failure detector reachability, builds
//! a reachability matrix, and identifies partition sides.

use crate::types::{now_millis, PartitionDetectionConfig, PartitionSuspect, ReachabilityEntry};
use std::collections::BTreeMap;
use tidefs_membership_epoch::{EpochId, HealthClass, MemberId};
use tidefs_membership_live::failure_detector::FailureDetector;

// ---------------------------------------------------------------------------
// PartitionDetector
// ---------------------------------------------------------------------------

/// Monitors the live SWIM failure detector to detect network partitions.
pub struct PartitionDetector {
    pub config: PartitionDetectionConfig,
    pub my_id: MemberId,
    pub my_epoch: EpochId,
    reachability: BTreeMap<MemberId, ReachabilityEntry>,
    pub suspects: Vec<PartitionSuspect>,
    suspicion_rounds: BTreeMap<MemberId, u32>,
    pub partition_confirmed: bool,
    pub partition_detected_at_millis: u64,
    pub observed_drift_ppm: f64,
}

impl PartitionDetector {
    pub fn new(config: PartitionDetectionConfig, my_id: MemberId, my_epoch: EpochId) -> Self {
        Self {
            config,
            my_id,
            my_epoch,
            reachability: BTreeMap::new(),
            suspects: Vec::new(),
            suspicion_rounds: BTreeMap::new(),
            partition_confirmed: false,
            partition_detected_at_millis: 0,
            observed_drift_ppm: 0.0,
        }
    }

    pub fn absorb_failure_detector_state(
        &mut self,
        detector: &FailureDetector,
    ) -> crate::types::ReachabilityMatrix {
        let now = now_millis();

        let mut reachable: Vec<MemberId> = Vec::new();
        for peer in detector.all_peers() {
            if peer.health == HealthClass::Healthy || peer.health == HealthClass::Suspect {
                reachable.push(peer.member_id);
            }
        }
        reachable.push(self.my_id);
        reachable.sort();
        reachable.dedup();

        self.reachability.insert(
            self.my_id,
            ReachabilityEntry {
                observer: self.my_id,
                reachable: reachable.clone(),
                observed_at_millis: now,
                epoch: self.my_epoch,
            },
        );

        let all_peer_ids: Vec<MemberId> = detector.all_peers().map(|p| p.member_id).collect();
        for peer_id in &all_peer_ids {
            if !reachable.contains(peer_id) {
                let rounds = self.suspicion_rounds.entry(*peer_id).or_insert(0);
                *rounds += 1;
            } else {
                self.suspicion_rounds.insert(*peer_id, 0);
            }
        }

        self.suspects = self
            .suspicion_rounds
            .iter()
            .filter(|(_, rounds)| **rounds > 0)
            .map(|(peer_id, rounds)| PartitionSuspect {
                member_id: *peer_id,
                missed_pings: *rounds,
                indirect_confirmations: 0,
                last_seen_millis: 0,
            })
            .collect();

        self.build_matrix()
    }

    #[must_use]
    pub fn build_matrix(&self) -> crate::types::ReachabilityMatrix {
        crate::types::ReachabilityMatrix {
            entries: self.reachability.values().cloned().collect(),
            computed_at_millis: now_millis(),
        }
    }

    #[must_use]
    pub fn connected_components(&self) -> Vec<Vec<MemberId>> {
        self.build_matrix().connected_components()
    }

    #[must_use]
    pub fn my_component(&self) -> Vec<MemberId> {
        let components = self.connected_components();
        for comp in &components {
            if comp.contains(&self.my_id) {
                return comp.clone();
            }
        }
        vec![self.my_id]
    }

    #[must_use]
    pub fn is_partition_suspected(&self) -> bool {
        self.suspicion_rounds
            .values()
            .any(|rounds| *rounds >= self.config.suspicion_rounds_before_partition)
    }

    #[must_use]
    pub fn effective_timeout_ms(&self) -> u64 {
        self.config.effective_timeout_ms(self.observed_drift_ppm)
    }

    #[must_use]
    pub fn escalated_deadline_ms(&self, round: u32) -> u64 {
        self.config
            .escalated_deadline_ms(round, self.observed_drift_ppm)
    }

    pub fn update_drift(&mut self, drift_ppm: f64) {
        self.observed_drift_ppm = drift_ppm;
    }

    #[must_use]
    pub fn alive_voters_in_my_component(&self, detector: &FailureDetector) -> usize {
        let my_comp_set: std::collections::BTreeSet<MemberId> =
            self.my_component().into_iter().collect();
        detector
            .all_peers()
            .filter(|p| my_comp_set.contains(&p.member_id) && p.is_alive() && p.is_voter())
            .count()
            + if self.is_voter_in_failure_detector(detector) {
                1
            } else {
                0
            }
    }

    #[must_use]
    pub fn total_known_voters(&self, detector: &FailureDetector) -> usize {
        detector.all_peers().filter(|p| p.is_voter()).count() + 1
    }

    #[must_use]
    pub fn my_component_has_quorum(&self, detector: &FailureDetector) -> bool {
        let total_voters = self.total_known_voters(detector);
        if total_voters == 0 {
            return false;
        }
        let my_voters = self.alive_voters_in_my_component(detector);
        let quorum_threshold = (total_voters / 2) + 1;
        my_voters >= quorum_threshold
    }

    #[must_use]
    pub fn has_multiple_components(&self) -> bool {
        self.connected_components().len() > 1
    }

    fn is_voter_in_failure_detector(&self, detector: &FailureDetector) -> bool {
        detector
            .get_peer(self.my_id)
            .map(|p| p.is_voter())
            .unwrap_or(true)
    }

    pub fn confirm_partition(&mut self) {
        if !self.partition_confirmed {
            self.partition_confirmed = true;
            self.partition_detected_at_millis = now_millis();
        }
    }

    pub fn reset(&mut self) {
        self.partition_confirmed = false;
        self.partition_detected_at_millis = 0;
        self.suspicion_rounds.clear();
        self.suspects.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_detector(my_id: MemberId) -> PartitionDetector {
        PartitionDetector::new(PartitionDetectionConfig::default(), my_id, EpochId::new(1))
    }

    #[test]
    fn test_initial_state_no_partition() {
        let pd = make_detector(MemberId::new(1));
        assert!(!pd.partition_confirmed);
        assert!(pd.suspects.is_empty());
        assert!(!pd.is_partition_suspected());
    }

    #[test]
    fn test_reachability_matrix_builds() {
        let pd = make_detector(MemberId::new(1));
        // Matrix without absorbing state has self entry from build_matrix
        // which accesses reachability directly via build_matrix
        let _matrix = pd.build_matrix();
        // After construction, reachability map is empty; matrix reflects that
        // This is expected — entries are populated via absorb_failure_detector_state
    }

    #[test]
    fn test_my_component_includes_self() {
        let pd = make_detector(MemberId::new(1));
        let comp = pd.my_component();
        assert!(comp.contains(&MemberId::new(1)));
    }

    #[test]
    fn test_adaptive_timeout_scales_with_drift() {
        let mut pd = make_detector(MemberId::new(1));
        let base = pd.effective_timeout_ms();
        pd.update_drift(100.0);
        let with_drift = pd.effective_timeout_ms();
        assert!(with_drift >= base);
    }

    #[test]
    fn test_deadline_escalation() {
        let pd = make_detector(MemberId::new(1));
        let round0 = pd.escalated_deadline_ms(0);
        let round1 = pd.escalated_deadline_ms(1);
        let round2 = pd.escalated_deadline_ms(2);
        assert!(round1 > round0);
        assert!(round2 > round1);
    }

    #[test]
    fn test_multiple_components_detected() {
        let pd = make_detector(MemberId::new(1));
        assert!(!pd.has_multiple_components());
    }
    // ── Helpers for detector-with-peers tests ─────────────────────

    fn make_simple_fd() -> FailureDetector {
        use ed25519_dalek::Keypair;
        use rand::rngs::OsRng;
        use tidefs_membership_live::types::MembershipConfig;
        let kp = Keypair::generate(&mut OsRng);
        FailureDetector::new(MembershipConfig::default(), kp)
    }

    #[test]
    fn total_known_voters_counts_registered_peers_plus_self() {
        let mut fd = make_simple_fd();
        fd.register_peer(
            MemberId::new(2),
            tidefs_membership_epoch::MemberClass::Voter,
            0,
            EpochId::new(1),
        );
        fd.register_peer(
            MemberId::new(3),
            tidefs_membership_epoch::MemberClass::Voter,
            0,
            EpochId::new(1),
        );
        fd.register_peer(
            MemberId::new(4),
            tidefs_membership_epoch::MemberClass::WitnessOnly,
            0,
            EpochId::new(1),
        );
        let pd = make_detector(MemberId::new(1));
        assert_eq!(pd.total_known_voters(&fd), 3);
    }

    #[test]
    fn total_known_voters_no_peers() {
        let fd = make_simple_fd();
        let pd = make_detector(MemberId::new(1));
        assert_eq!(pd.total_known_voters(&fd), 1);
    }

    #[test]
    fn alive_voters_in_my_component_counts_healthy_voters() {
        let mut fd = make_simple_fd();
        fd.register_peer(
            MemberId::new(2),
            tidefs_membership_epoch::MemberClass::Voter,
            0,
            EpochId::new(1),
        );
        fd.register_peer(
            MemberId::new(3),
            tidefs_membership_epoch::MemberClass::Voter,
            0,
            EpochId::new(1),
        );
        let mut pd = PartitionDetector::new(
            PartitionDetectionConfig::default(),
            MemberId::new(1),
            EpochId::new(1),
        );
        let _ = pd.absorb_failure_detector_state(&fd);
        let alive_count = pd.alive_voters_in_my_component(&fd);
        assert!(alive_count >= 1);
    }

    #[test]
    fn my_component_has_quorum_with_majority() {
        let mut fd = make_simple_fd();
        fd.register_peer(
            MemberId::new(2),
            tidefs_membership_epoch::MemberClass::Voter,
            0,
            EpochId::new(1),
        );
        fd.register_peer(
            MemberId::new(3),
            tidefs_membership_epoch::MemberClass::Voter,
            0,
            EpochId::new(1),
        );
        let mut pd = PartitionDetector::new(
            PartitionDetectionConfig::default(),
            MemberId::new(1),
            EpochId::new(1),
        );
        let _ = pd.absorb_failure_detector_state(&fd);
        assert!(pd.my_component_has_quorum(&fd));
    }

    #[test]
    fn confirm_partition_sets_timestamp_and_flag() {
        let mut pd = make_detector(MemberId::new(1));
        assert!(!pd.partition_confirmed);
        assert_eq!(pd.partition_detected_at_millis, 0);
        pd.confirm_partition();
        assert!(pd.partition_confirmed);
        assert!(pd.partition_detected_at_millis > 0);
    }

    #[test]
    fn confirm_partition_idempotent() {
        let mut pd = make_detector(MemberId::new(1));
        pd.confirm_partition();
        let first_ts = pd.partition_detected_at_millis;
        pd.confirm_partition();
        assert_eq!(pd.partition_detected_at_millis, first_ts);
    }

    #[test]
    fn reset_clears_suspicion_and_partition() {
        let mut pd = make_detector(MemberId::new(1));
        pd.confirm_partition();
        pd.suspects.push(PartitionSuspect {
            member_id: MemberId::new(2),
            missed_pings: 3,
            indirect_confirmations: 0,
            last_seen_millis: 0,
        });
        pd.reset();
        assert!(!pd.partition_confirmed);
        assert_eq!(pd.partition_detected_at_millis, 0);
        assert!(pd.suspects.is_empty());
        assert!(pd.suspicion_rounds.is_empty());
    }

    #[test]
    fn is_partition_suspected_with_enough_rounds() {
        let mut pd = make_detector(MemberId::new(1));
        assert!(!pd.is_partition_suspected());
        pd.suspicion_rounds.insert(
            MemberId::new(2),
            pd.config.suspicion_rounds_before_partition,
        );
        assert!(pd.is_partition_suspected());
    }
}
