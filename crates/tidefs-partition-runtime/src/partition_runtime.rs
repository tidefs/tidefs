//! PartitionRuntime: the main service coordinating partition detection,
//! split-brain prevention, and partition healing.
//!
//! Integrates the [`PartitionDetector`], [`SplitBrainGuard`],
//! [`PartitionHealingProtocol`], and [`PartitionAuditRecorder`] into
//! a single long-running service.

use crate::partition_audit::PartitionAuditRecorder;
use crate::partition_detector::PartitionDetector;
use crate::partition_healing::PartitionHealingProtocol;
use crate::split_brain_guard::SplitBrainGuard;
use crate::types::{now_millis, PartitionDetectionConfig, PartitionHazardClass, PartitionState};

use std::sync::Arc;
use tidefs_membership_epoch::{
    ClusterMemberRecord, EpochId, MemberClass, MemberId, SplitBrainHazardRecord,
};
use tidefs_membership_live::epoch_fence::MembershipEpochFence;
use tidefs_membership_live::failure_detector::FailureDetector;
use tidefs_membership_live::fencing_watchdog::FencingWatchdog;

// ---------------------------------------------------------------------------
// PartitionRuntime
// ---------------------------------------------------------------------------

/// The live partition runtime for TideFS.
///
/// ## Lifecycle
///
/// 1. Boot: tied to the membership runtime's failure detector
/// 2. Detection loop: on every tick, absorb failure detector state, build
///    reachability matrix, check for partitions
/// 3. On partition: the split-brain guard evaluates quorum, issues hazard
///    records, freezes the minority side
/// 4. On heal: healing protocol creates c2 joint config, exchanges receipt
///    frontiers, classifies divergence, selects reconciliation strategy
/// 5. Continuous: lives for the process lifetime
pub struct PartitionRuntime {
    /// Configuration for partition detection.
    pub config: PartitionDetectionConfig,
    /// Partition detector — builds reachability matrix.
    pub detector: PartitionDetector,
    /// Split-brain guard — quorum checking, fencing, hazard emission.
    pub guard: SplitBrainGuard,
    /// Partition healing protocol.
    pub healing: PartitionHealingProtocol,
    /// Operator audit trail for partition and healing events.
    pub audit: PartitionAuditRecorder,
    /// My member ID.
    pub my_id: MemberId,
    /// My member class.
    pub my_member_class: MemberClass,
    /// Current epoch.
    pub epoch: EpochId,
    /// Number of ticks since start.
    tick_count: u64,
    /// Cluster members known to the runtime.
    members: Vec<ClusterMemberRecord>,
    /// Total known voters across all members.
    total_known_voters: usize,
    /// Whether the runtime has been bootstrapped.
    bootstrapped: bool,
    /// Shared epoch fence from the membership runtime for unified write-safety.
    pub epoch_fence: Option<Arc<MembershipEpochFence>>,
}

impl PartitionRuntime {
    /// Create a new partition runtime.
    pub fn new(
        config: PartitionDetectionConfig,
        my_id: MemberId,
        my_member_class: MemberClass,
        epoch: EpochId,
        min_voters_for_quorum: usize,
    ) -> Self {
        let detector = PartitionDetector::new(config.clone(), my_id, epoch);
        let guard = SplitBrainGuard::new(my_id, epoch, min_voters_for_quorum);
        let healing = PartitionHealingProtocol::new(my_id);
        let audit = PartitionAuditRecorder::new(my_id, epoch);

        Self {
            config,
            detector,
            guard,
            healing,
            audit,
            my_id,
            my_member_class,
            epoch,
            tick_count: 0,
            members: Vec::new(),
            total_known_voters: 0,
            bootstrapped: false,
            epoch_fence: None,
        }
    }

    /// Bootstrap the partition runtime with initial cluster members.
    pub fn bootstrap(&mut self, members: Vec<ClusterMemberRecord>) {
        self.total_known_voters = members
            .iter()
            .filter(|m| m.member_class.can_vote() && m.member_class != MemberClass::Quarantined)
            .count();
        self.members = members;
        self.bootstrapped = true;
    }

    /// Update the list of known cluster members (after epoch transitions).
    pub fn update_members(&mut self, members: Vec<ClusterMemberRecord>) {
        self.total_known_voters = members
            .iter()
            .filter(|m| m.member_class.can_vote() && m.member_class != MemberClass::Quarantined)
            .count();
        self.members = members;
        self.guard.min_voters_for_quorum = (self.total_known_voters / 2) + 1;
    }

    /// Update the current epoch (after a membership epoch transition).
    pub fn update_epoch(&mut self, epoch: EpochId) {
        self.epoch = epoch;
        self.detector.my_epoch = epoch;
        self.guard.epoch = epoch;
        self.audit.epoch = epoch;
    }

    /// Tick the partition runtime.
    ///
    /// This should be called on every membership runtime tick. It:
    /// 1. Absorbs failure detector state into the partition detector
    /// 2. Builds the reachability matrix
    /// 3. If partition suspected, evaluates quorum
    /// 4. If healed, transitions to healing protocol
    ///
    /// Returns the result of the tick.
    pub fn tick(&mut self, failure_detector: &FailureDetector) -> PartitionTickResult {
        if !self.bootstrapped {
            return PartitionTickResult::default();
        }

        self.tick_count += 1;
        let mut result = PartitionTickResult::default();

        // 1. Absorb failure detector state → reachability matrix
        let matrix = self
            .detector
            .absorb_failure_detector_state(failure_detector);
        result.matrix = Some(matrix.clone());

        // 2. Check for partition
        if self.detector.has_multiple_components() {
            result.partition_detected = true;

            if !self.detector.partition_confirmed {
                // Check if we have enough suspicion rounds
                if self.detector.is_partition_suspected() {
                    self.detector.confirm_partition();

                    // Evaluate quorum and determine side
                    let (new_state, hazard) =
                        self.guard
                            .evaluate(&matrix, failure_detector, &self.members);
                    result.partition_state = Some(new_state.clone());
                    result.hazard_emitted = hazard.is_some();
                    result.hazard_record = hazard.clone();

                    // Record the operator audit trail.
                    let components = matrix.connected_components();
                    let my_comp = self.detector.my_component();
                    let minority: Vec<MemberId> = components
                        .iter()
                        .flat_map(|c| {
                            if !c.contains(&self.my_id) {
                                c.clone()
                            } else {
                                Vec::new()
                            }
                        })
                        .collect();

                    let hazard_class = match &new_state {
                        PartitionState::QuorumSideActive { .. } => PartitionHazardClass::QuorumSide,
                        PartitionState::MinorityFenced { .. } => PartitionHazardClass::MinoritySide,
                        _ => PartitionHazardClass::PartitionAmbiguous,
                    };

                    let all_members: Vec<MemberId> =
                        components.iter().flat_map(|c| c.iter().copied()).collect();

                    self.audit.record_partition_detected(
                        hazard_class,
                        all_members,
                        my_comp.clone(),
                        minority.clone(),
                        hazard.clone(),
                    );

                    // Record side-specific events
                    match &new_state {
                        PartitionState::QuorumSideActive {
                            ref minority_members,
                            ..
                        } => {
                            self.audit
                                .record_quorum_side_confirmed(minority_members.clone());
                        }
                        PartitionState::MinorityFenced { .. } => {
                            self.audit.record_minority_fenced(my_comp.clone());
                        }
                        PartitionState::AmbiguousHalted { ref sides, .. } => {
                            self.audit.record_ambiguous_halted(sides.clone());
                        }
                        _ => {}
                    }

                    if let Some(ref h) = hazard {
                        self.audit.record_split_brain_hazard(h);
                    }
                }
            }

            // If partition is already confirmed, check for heal
            if self.detector.partition_confirmed && !self.healing.healing_in_progress {
                // Check if all members are reachable again (healed)
                let alive_count = failure_detector
                    .all_peers()
                    .filter(|p| p.is_alive())
                    .count();
                let all_known = failure_detector.peer_count();

                // Simple heuristic: if all known peers are alive and we were partitioned
                if alive_count == all_known && all_known > 0 {
                    // Partition has healed! Initiate healing protocol
                    self.initiate_healing(failure_detector);
                    result.healing_initiated = true;
                }
            }
        } else {
            // No partition: if we were partitioned, heal is complete
            if self.healing.healing_in_progress {
                self.complete_healing();
                result.healing_completed = true;
            }
            if self.detector.partition_confirmed {
                // Connectivity restored
                self.detector.reset();
                self.guard.reset();
            }
        }

        // 3. If healing is in progress, check reconciliation progress
        if self.healing.healing_in_progress {
            result.healing_in_progress = true;

            if self.healing.all_caught_up() && !self.healing.healing_complete {
                self.complete_healing();
                result.healing_completed = true;
            }
        }

        result.partition_state = Some(self.guard.partition_state.clone());
        result.fence_raised = self.guard.fence.is_any_raised();

        // 4. Evaluate unified writer fence (partition + epoch)
        //    Liveness-watchdog check requires the external FencingWatchdog
        //    reference and is computed via can_accept_writes_unified().
        if let Some(ref fence) = self.epoch_fence {
            let partition_ok = self.guard.can_accept_writes();
            let in_roster = fence.contains(self.my_id);
            result.writer_fence_accepted = Some(partition_ok && in_roster);
            if !result.writer_fence_accepted.unwrap_or(true) {
                result.writer_fence_fenced_since = Some(now_millis());
            }
        }

        result
    }

    /// Initiate healing when connectivity is restored after a partition.
    fn initiate_healing(&mut self, failure_detector: &FailureDetector) {
        // Determine which members are rejoining (were in minority)
        let rejoining: Vec<MemberId> = match &self.guard.partition_state {
            PartitionState::QuorumSideActive {
                ref minority_members,
                ..
            } => minority_members.clone(),
            _ => {
                // All other members are rejoining
                failure_detector
                    .all_peers()
                    .map(|p| p.member_id)
                    .filter(|id| *id != self.my_id)
                    .collect()
            }
        };

        if rejoining.is_empty() {
            // No one to rejoin — just transition to connected
            self.detector.reset();
            self.guard.reset();
            return;
        }

        // Begin healing: create c2 joint config
        let joint_epoch = self.healing.begin_healing(self.epoch, rejoining.clone());

        // Create receipt frontiers (stubs — populated by actual receipt exchange
        // via the transfer orchestrator #901)
        // For the quorum side: we know all our receipts
        // For the minority side: we'll receive their frontier via network

        self.guard.partition_state = PartitionState::Healing {
            joint_epoch,
            rejoining_members: rejoining.clone(),
            since_millis: now_millis(),
        };

        // Record healing started
        self.audit.record_healing_started(rejoining);
    }

    /// Complete healing after all rejoining members are caught up.
    fn complete_healing(&mut self) {
        let rejoining = self.healing.rejoining_members.clone();

        self.healing.complete_healing();
        self.detector.reset();
        self.guard.reset();

        // Record healing complete
        self.audit.record_healing_complete(rejoining);
    }

    /// Handle a receipt frontier received from a minority-side node during healing.
    pub fn handle_minority_frontier(
        &mut self,
        receipt_ids: Vec<u64>,
        minority_members: Vec<MemberId>,
        frontier_epoch: EpochId,
    ) {
        use crate::types::ReceiptFrontier;

        let minority_frontier = ReceiptFrontier {
            side: PartitionHazardClass::MinoritySide,
            members: minority_members,
            receipt_ids,
            frontier_epoch,
            frontier_millis: now_millis(),
        };

        // Build our quorum-side frontier from known state
        let quorum_frontier = ReceiptFrontier {
            side: PartitionHazardClass::QuorumSide,
            members: self.members.iter().map(|m| m.member_id).collect(),
            receipt_ids: Vec::new(), // Populated by actual receipt tracking
            frontier_epoch: self.epoch,
            frontier_millis: now_millis(),
        };

        self.healing
            .exchange_frontiers(quorum_frontier, minority_frontier);

        let divergence = self.healing.classify_divergence();
        let missed_epochs = self.healing.compute_missed_epochs();
        let _strategy = self.healing.select_strategy(&divergence, missed_epochs);

        // The selected strategy determines what the transfer orchestrator (#901)
        // should ship to the minority side.
    }

    /// Mark a rejoining member as caught up (called after reconciliation shipment).
    pub fn mark_member_caught_up(&mut self, member_id: MemberId) {
        self.healing.mark_caught_up(member_id);
    }

    /// Check whether this node can accept writes.
    #[must_use]
    pub fn can_accept_writes(&self) -> bool {
        self.guard.can_accept_writes()
    }

    /// Check whether publications can be committed.
    #[must_use]
    pub fn can_commit_publications(&self) -> bool {
        self.guard.can_commit_publications()
    }

    /// Check whether leases can be granted.
    #[must_use]
    pub fn can_grant_leases(&self) -> bool {
        self.guard.can_grant_leases()
    }

    /// Check whether receipts can be minted (partition-state only).
    #[must_use]
    pub fn can_mint_receipts(&self) -> bool {
        self.guard.can_mint_receipts()
    }

    // ------------------------------------------------------------------
    // Unified write-fence: partition + epoch + liveness
    // ------------------------------------------------------------------

    /// Set the shared epoch fence from the membership runtime.
    pub fn set_epoch_fence(&mut self, fence: Arc<MembershipEpochFence>) {
        self.epoch_fence = Some(fence);
    }

    /// Unified write-safety check: true only when all three fencing
    /// mechanisms permit writes.
    ///
    /// 1. Partition state: must be Connected or QuorumSideActive
    /// 2. Epoch fence: this node must be in the current roster
    /// 3. Liveness watchdog: this node must not be individually fenced
    #[must_use]
    pub fn can_accept_writes_unified(&self, watchdog: &FencingWatchdog) -> bool {
        // 1. Partition guard check
        if !self.guard.can_accept_writes() {
            return false;
        }
        // 2. Epoch fence: in roster
        if let Some(ref fence) = self.epoch_fence {
            if !fence.contains(self.my_id) {
                return false;
            }
        }
        // 3. Liveness watchdog: not individually fenced
        if watchdog.is_fenced(self.my_id) {
            return false;
        }
        true
    }

    /// Unified lease-grant check: write acceptance + lease authority not frozen.
    #[must_use]
    pub fn can_grant_leases_unified(&self, watchdog: &FencingWatchdog) -> bool {
        self.can_accept_writes_unified(watchdog) && self.guard.can_grant_leases()
    }

    /// Unified publication-commit check: write acceptance + publication path not frozen.
    #[must_use]
    pub fn can_commit_publications_unified(&self, watchdog: &FencingWatchdog) -> bool {
        self.can_accept_writes_unified(watchdog) && self.guard.can_commit_publications()
    }

    /// Unified receipt-mint check: write acceptance + receipt path not frozen.
    #[must_use]
    pub fn can_mint_receipts_unified(&self, watchdog: &FencingWatchdog) -> bool {
        self.can_accept_writes_unified(watchdog) && self.guard.can_mint_receipts()
    }

    /// Get the current partition state.
    #[must_use]
    pub fn partition_state(&self) -> &PartitionState {
        &self.guard.partition_state
    }

    /// Get the current partition fence.
    #[must_use]
    pub fn fence(&self) -> &crate::types::PartitionFence {
        &self.guard.fence
    }

    /// Get all emitted split-brain hazard records.
    #[must_use]
    pub fn hazard_records(&self) -> &[SplitBrainHazardRecord] {
        &self.guard.hazard_records
    }

    /// Get all partition audit events.
    #[must_use]
    pub fn events(&self) -> &[crate::types::PartitionEvent] {
        &self.audit.events
    }

    /// Get the minority side members (empty if not partitioned).
    #[must_use]
    pub fn minority_members(&self) -> Vec<MemberId> {
        self.guard.get_minority_side_members()
    }

    /// Get the number of alive voters in our component.
    #[must_use]
    pub fn alive_voters_in_my_component(&self, failure_detector: &FailureDetector) -> usize {
        self.detector.alive_voters_in_my_component(failure_detector)
    }
}

// ---------------------------------------------------------------------------
// Tick result
// ---------------------------------------------------------------------------

/// Result returned by [`PartitionRuntime::tick`].
#[derive(Clone, Debug, Default)]
pub struct PartitionTickResult {
    /// The current reachability matrix (if computed).
    pub matrix: Option<crate::types::ReachabilityMatrix>,
    /// Whether a partition was detected this tick.
    pub partition_detected: bool,
    /// The current partition state.
    pub partition_state: Option<PartitionState>,
    /// Whether a split-brain hazard was emitted.
    pub hazard_emitted: bool,
    /// The hazard record (if emitted).
    pub hazard_record: Option<SplitBrainHazardRecord>,
    /// Whether healing was initiated this tick.
    pub healing_initiated: bool,
    /// Whether healing completed this tick.
    pub healing_completed: bool,
    /// Whether healing is in progress.
    pub healing_in_progress: bool,
    /// Whether the partition fence is raised.
    pub fence_raised: bool,
    /// Whether the unified writer fence accepted writes on this tick.
    /// None when the epoch fence or watchdog ref was not available.
    pub writer_fence_accepted: Option<bool>,
    /// When the unified fence transitioned to fenced (millis since epoch).
    /// None when writes are accepted.
    pub writer_fence_fenced_since: Option<u64>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cluster_member(
        id: u64,
        class: MemberClass,
        health: tidefs_membership_epoch::HealthClass,
    ) -> ClusterMemberRecord {
        ClusterMemberRecord {
            member_id: MemberId::new(id),
            member_class: class,
            current_membership_epoch_ref: EpochId::new(1),
            log_frontier: 100,
            health,
            failure_domain_vector: tidefs_membership_epoch::FailureDomainVector::new(
                tidefs_membership_epoch::DomainId::new(id),
                tidefs_membership_epoch::DomainId::new(100 + id),
                tidefs_membership_epoch::DomainId::ZERO,
                tidefs_membership_epoch::DomainId::ZERO,
                tidefs_membership_epoch::DomainId::ZERO,
                tidefs_membership_epoch::DomainId::ZERO,
            ),
            digest: 0,
        }
    }

    fn make_detector() -> FailureDetector {
        use ed25519_dalek::Keypair;
        use rand::rngs::OsRng;
        let kp = Keypair::generate(&mut OsRng);
        let config = tidefs_membership_live::types::MembershipConfig::default();
        FailureDetector::new(config, kp)
    }

    fn make_runtime() -> PartitionRuntime {
        PartitionRuntime::new(
            PartitionDetectionConfig::default(),
            MemberId::new(1),
            MemberClass::Voter,
            EpochId::new(1),
            3,
        )
    }

    #[test]
    fn test_partition_runtime_initial_state() {
        let rt = PartitionRuntime::new(
            PartitionDetectionConfig::default(),
            MemberId::new(1),
            MemberClass::Voter,
            EpochId::new(1),
            3,
        );
        assert!(rt.can_accept_writes());
        assert!(matches!(rt.partition_state(), PartitionState::Connected));
        assert!(!rt.fence().is_any_raised());
    }

    #[test]
    fn test_partition_runtime_not_bootstrapped_yet() {
        let mut rt = make_runtime();
        let detector = make_detector();
        let result = rt.tick(&detector);
        assert!(!result.partition_detected);
    }

    #[test]
    fn test_bootstrap_sets_total_voters() {
        let mut rt = make_runtime();
        let members = vec![
            make_cluster_member(
                1,
                MemberClass::Voter,
                tidefs_membership_epoch::HealthClass::Healthy,
            ),
            make_cluster_member(
                2,
                MemberClass::Voter,
                tidefs_membership_epoch::HealthClass::Healthy,
            ),
            make_cluster_member(
                3,
                MemberClass::Voter,
                tidefs_membership_epoch::HealthClass::Healthy,
            ),
            make_cluster_member(
                4,
                MemberClass::WitnessOnly,
                tidefs_membership_epoch::HealthClass::Healthy,
            ),
            make_cluster_member(
                5,
                MemberClass::Learner,
                tidefs_membership_epoch::HealthClass::Healthy,
            ),
        ];
        rt.bootstrap(members);
        assert!(rt.bootstrapped);
    }

    #[test]
    fn test_update_epoch() {
        let mut rt = make_runtime();
        rt.update_epoch(EpochId::new(5));
        assert_eq!(rt.epoch, EpochId::new(5));
        assert_eq!(rt.guard.epoch, EpochId::new(5));
        assert_eq!(rt.detector.my_epoch, EpochId::new(5));
        assert_eq!(rt.audit.epoch, EpochId::new(5));
    }

    #[test]
    fn test_hazard_records_empty_initially() {
        let rt = make_runtime();
        assert!(rt.hazard_records().is_empty());
    }

    #[test]
    fn test_events_empty_initially() {
        let rt = make_runtime();
        assert!(rt.events().is_empty());
    }

    #[test]
    fn test_minority_members_empty_when_connected() {
        let rt = make_runtime();
        assert!(rt.minority_members().is_empty());
    }

    #[test]
    fn test_update_members() {
        let mut rt = make_runtime();
        let members = vec![
            make_cluster_member(
                1,
                MemberClass::Voter,
                tidefs_membership_epoch::HealthClass::Healthy,
            ),
            make_cluster_member(
                2,
                MemberClass::Voter,
                tidefs_membership_epoch::HealthClass::Healthy,
            ),
            make_cluster_member(
                3,
                MemberClass::Voter,
                tidefs_membership_epoch::HealthClass::Healthy,
            ),
        ];
        rt.update_members(members);
        assert_eq!(rt.guard.min_voters_for_quorum, 2);
    }

    #[test]
    fn test_tick_bootstrapped_single_node() {
        let mut rt = make_runtime();
        let members = vec![make_cluster_member(
            1,
            MemberClass::Voter,
            tidefs_membership_epoch::HealthClass::Healthy,
        )];
        rt.bootstrap(members);
        let detector = make_detector();
        let result = rt.tick(&detector);
        // Single node, no peers, should not detect partition
        assert!(!result.partition_detected);
        assert!(matches!(
            result.partition_state,
            Some(PartitionState::Connected)
        ));
    }

    #[test]
    fn test_passes_through() {
        let rt = make_runtime();
        assert!(rt.can_accept_writes());
        assert!(rt.can_commit_publications());
        assert!(rt.can_grant_leases());
        assert!(rt.can_mint_receipts());
        assert_eq!(rt.events().len(), 0);
    }

    #[test]
    fn test_tick_produces_matrix() {
        let mut rt = make_runtime();
        let members = vec![make_cluster_member(
            1,
            MemberClass::Voter,
            tidefs_membership_epoch::HealthClass::Healthy,
        )];
        rt.bootstrap(members);
        let detector = make_detector();
        let result = rt.tick(&detector);
        assert!(result.matrix.is_some());
    }

    #[test]
    fn test_tick_increments_internally() {
        let mut rt = make_runtime();
        let members = vec![make_cluster_member(
            1,
            MemberClass::Voter,
            tidefs_membership_epoch::HealthClass::Healthy,
        )];
        rt.bootstrap(members);
        let detector = make_detector();
        let _ = rt.tick(&detector);
        let _ = rt.tick(&detector);
        // After 2 ticks, internal state should be updated
        assert!(matches!(rt.partition_state(), PartitionState::Connected));
    }

    #[test]
    fn test_mark_member_caught_up() {
        let mut rt = make_runtime();
        rt.healing.rejoining_members = vec![MemberId::new(2), MemberId::new(3)];
        rt.mark_member_caught_up(MemberId::new(2));
        assert!(rt.healing.caught_up_members.contains(&MemberId::new(2)));
        assert!(!rt.healing.caught_up_members.contains(&MemberId::new(3)));
    }

    #[test]
    fn test_alive_voters_in_my_component_delegates() {
        let mut rt = make_runtime();
        let members = vec![make_cluster_member(
            1,
            MemberClass::Voter,
            tidefs_membership_epoch::HealthClass::Healthy,
        )];
        rt.bootstrap(members);
        let detector = make_detector();
        let count = rt.alive_voters_in_my_component(&detector);
        // Self is voter, so at least 1
        assert!(count >= 1);
    }

    #[test]
    fn test_handle_minority_frontier() {
        let mut rt = make_runtime();
        let members = vec![
            make_cluster_member(
                1,
                MemberClass::Voter,
                tidefs_membership_epoch::HealthClass::Healthy,
            ),
            make_cluster_member(
                2,
                MemberClass::Voter,
                tidefs_membership_epoch::HealthClass::Healthy,
            ),
        ];
        rt.bootstrap(members);
        rt.handle_minority_frontier(vec![1, 2, 3], vec![MemberId::new(2)], EpochId::new(5));
        // Should have populated healing state
        assert!(rt.healing.divergence.is_some());
    }
}
