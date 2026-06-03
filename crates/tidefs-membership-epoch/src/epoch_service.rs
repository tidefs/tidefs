//! Membership-gated epoch service for authoritative epoch transitions.
//!
//! [`EpochService`] wraps the deterministic [`EpochStateMachine`] with
//! membership-gated transition validation, BLAKE3-verified transition
//! hashing, and persistence hooks. It is the canonical epoch authority
//! that node-join, node-drain, lease-grant, and quorum-write protocols
//! consume.

use std::collections::BTreeSet;

use crate::departure_coordinator::DepartureCoordinator;
use crate::epoch_error::EpochTransitionError;
use crate::leave_coordinator::LeaveCoordinator;
use crate::membership_quorum_tracker::QuorumOutcome;
use crate::{
    EpochEvent, EpochId, EpochMemberSet, EpochStateMachine, EpochTransition, LeaveReason, MemberId,
    MembershipEpoch,
};

/// Service result for epoch operations.
pub type EpochResult<T> = Result<T, EpochTransitionError>;

/// Transition reason tag for audit trails.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TransitionReason {
    Join,
    Leave,
    Heartbeat,
    Admin,
    Quorum,
}

impl TransitionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Join => "join",
            Self::Leave => "leave",
            Self::Heartbeat => "heartbeat",
            Self::Admin => "admin",
            Self::Quorum => "quorum",
        }
    }
}

/// A BLAKE3-verified epoch transition with hash validation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct VerifiedEpochTransition {
    pub transition: EpochTransition,
    pub blake3_hash: [u8; 32],
    pub proposed_by: u64,
    pub reason: TransitionReason,
}

impl VerifiedEpochTransition {
    /// Compute the BLAKE3 hash of an [`EpochTransition`] using
    /// domain-separated hashing covering from_epoch_id, to_epoch_id,
    /// event discriminant, and member_set_delta.
    pub fn compute_hash(transition: &EpochTransition) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"MembershipEpoch.transition.v1");
        hasher.update(&transition.from_epoch_id.to_le_bytes());
        hasher.update(&transition.to_epoch_id.to_le_bytes());
        let event_tag: u8 = match transition.event {
            EpochEvent::Join(_) => 0x01,
            EpochEvent::Leave(_) => 0x02,
            EpochEvent::Increment => 0x03,
            EpochEvent::CoordinatorChanged { .. } => 0x04,
        };
        hasher.update(&[event_tag]);
        for id in &transition.member_set_delta.added {
            hasher.update(&id.node_id.to_le_bytes());
        }
        hasher.update(b"|");
        for id in &transition.member_set_delta.removed {
            hasher.update(&id.node_id.to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// Verify that the stored hash matches the computed hash.
    pub fn verify(&self) -> bool {
        Self::compute_hash(&self.transition) == self.blake3_hash
    }
}

/// The authoritative epoch service.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EpochService {
    state_machine: EpochStateMachine,
    transition_history: Vec<VerifiedEpochTransition>,
    member_set: BTreeSet<u64>,
    transition_in_progress: bool,
    max_history: usize,
    /// Optional quorum-based departure coordinator for distributed operation.
    #[serde(default, skip)]
    departure_coordinator: Option<DepartureCoordinator>,
}

impl EpochService {
    pub fn bootstrap(initial_members: EpochMemberSet) -> Self {
        let member_set: BTreeSet<u64> = initial_members
            .members()
            .iter()
            .map(|ni| ni.node_id)
            .collect();
        let state_machine = EpochStateMachine::bootstrap(initial_members);

        Self {
            state_machine,
            transition_history: Vec::new(),
            member_set,
            transition_in_progress: false,
            max_history: 1024,
            departure_coordinator: None,
        }
    }

    /// Attach a departure coordinator for quorum-based peer removal.
    ///
    /// The coordinator's LeaveCoordinator is initialized from the current
    /// epoch service state so the two stay consistent.
    pub fn with_departure_coordinator(mut self) -> Self {
        let member_ids: Vec<MemberId> = self
            .member_set
            .iter()
            .map(|&id| MemberId::new(id))
            .collect();
        let lc = LeaveCoordinator::new(EpochId::new(self.current_epoch().epoch_id), member_ids);
        self.departure_coordinator = Some(DepartureCoordinator::new(lc));
        self
    }

    /// Handle a departure request through the quorum-based coordinator.
    ///
    /// Delegates to [`DepartureCoordinator::handle_departure_request`] when
    /// a coordinator is attached. Returns the response to send to the peer
    /// and an optional proposal id for vote tracking.
    #[allow(clippy::type_complexity)]
    pub fn handle_departure_request(
        &mut self,
        peer_id: u64,
        reason: LeaveReason,
        now_millis: u64,
    ) -> Option<(
        tidefs_membership_types::departure::DepartureResponse,
        Option<u64>,
    )> {
        self.departure_coordinator
            .as_mut()
            .map(|dc| dc.handle_departure_request(peer_id, reason, now_millis))
    }

    /// Receive a quorum vote for a pending departure proposal.
    pub fn receive_departure_vote(
        &mut self,
        proposal_id: u64,
        voter_id: u64,
        accepted: bool,
        now_millis: u64,
    ) -> Option<Result<QuorumOutcome, crate::membership_quorum_tracker::QuorumTrackerError>> {
        self.departure_coordinator
            .as_mut()
            .map(|dc| dc.receive_vote(proposal_id, voter_id, accepted, now_millis))
    }

    /// Check for timeout on all pending departure proposals.
    pub fn check_departure_timeouts(&mut self, now_millis: u64) -> Vec<(u64, QuorumOutcome)> {
        self.departure_coordinator
            .as_mut()
            .map(|dc| dc.check_timeouts(now_millis))
            .unwrap_or_default()
    }

    /// Set the epoch counter to match a snapshot epoch during crash recovery.
    ///
    /// Only valid when called immediately after bootstrap (epoch 0).
    /// Delegates to [`EpochStateMachine::set_snapshot_epoch`].
    pub(crate) fn set_snapshot_epoch(&mut self, epoch: u64) {
        // Only safe when called before any transitions are recorded
        debug_assert!(self.transition_history.is_empty());
        self.state_machine.set_snapshot_epoch(epoch);
    }

    pub fn current_epoch(&self) -> &MembershipEpoch {
        self.state_machine.current_epoch()
    }

    pub fn is_member(&self, node_id: u64) -> bool {
        self.member_set.contains(&node_id)
    }

    pub fn member_node_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.member_set.iter().copied().collect();
        ids.sort_unstable();
        ids
    }

    pub fn propose_transition(
        &mut self,
        member_id: u64,
        event: EpochEvent,
        reason: TransitionReason,
    ) -> EpochResult<VerifiedEpochTransition> {
        if !self.member_set.contains(&member_id) {
            return Err(EpochTransitionError::NotMember {
                member_id,
                current_epoch: self.state_machine.current_epoch().epoch_id,
            });
        }

        if self.transition_in_progress {
            return Err(EpochTransitionError::TransitionInProgress);
        }

        self.transition_in_progress = true;
        let result = self.commit_transition(event, member_id, reason);
        self.transition_in_progress = false;
        result
    }

    pub fn validate_epoch(&self, epoch: u64) -> bool {
        if self.state_machine.current_epoch().epoch_id == epoch {
            return true;
        }
        self.transition_history
            .iter()
            .any(|vt| vt.transition.to_epoch_id == epoch || vt.transition.from_epoch_id == epoch)
    }

    pub fn epoch_since(&self, since_epoch: u64) -> Vec<&VerifiedEpochTransition> {
        self.transition_history
            .iter()
            .filter(|vt| vt.transition.to_epoch_id >= since_epoch)
            .collect()
    }

    pub fn transition_history(&self) -> &[VerifiedEpochTransition] {
        &self.transition_history
    }

    pub fn transition_count(&self) -> usize {
        self.transition_history.len()
    }

    pub fn is_transition_in_progress(&self) -> bool {
        self.transition_in_progress
    }

    // ── Internal ──

    pub(crate) fn commit_transition(
        &mut self,
        event: EpochEvent,
        proposed_by: u64,
        reason: TransitionReason,
    ) -> EpochResult<VerifiedEpochTransition> {
        let transition = match event {
            EpochEvent::Join(node) => self.state_machine.join(node),
            EpochEvent::Leave(node) => self.state_machine.leave(node),
            EpochEvent::Increment => self.state_machine.increment(),
            EpochEvent::CoordinatorChanged { .. } => self.state_machine.increment(),
        };

        match &transition.event {
            EpochEvent::Join(node) => {
                self.member_set.insert(node.node_id);
            }
            EpochEvent::Leave(node) => {
                self.member_set.remove(&node.node_id);
            }
            EpochEvent::Increment => {}
            EpochEvent::CoordinatorChanged { .. } => {}
        }

        let blake3_hash = VerifiedEpochTransition::compute_hash(&transition);
        let verified = VerifiedEpochTransition {
            transition,
            blake3_hash,
            proposed_by,
            reason,
        };

        if self.transition_history.len() >= self.max_history {
            self.transition_history.truncate(self.max_history - 1);
        }
        self.transition_history.insert(0, verified.clone());

        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeIdentity;

    fn bootstrap_service(member_ids: &[u64]) -> EpochService {
        let members = EpochMemberSet::new(member_ids.iter().map(|&id| NodeIdentity::new(id)));
        EpochService::bootstrap(members)
    }

    #[test]
    fn bootstrap_sets_epoch_zero() {
        let svc = bootstrap_service(&[1, 2, 3]);
        assert_eq!(svc.current_epoch().epoch_id, 0);
        assert_eq!(svc.member_node_ids(), vec![1, 2, 3]);
    }

    #[test]
    fn propose_join_by_member_succeeds() {
        let mut svc = bootstrap_service(&[1, 2]);
        let result = svc.propose_transition(
            1,
            EpochEvent::Join(NodeIdentity::new(3)),
            TransitionReason::Join,
        );
        assert!(result.is_ok());
        let vt = result.unwrap();
        assert_eq!(vt.transition.to_epoch_id, 1);
        assert!(vt.verify());
        assert!(svc.is_member(3));
        assert_eq!(svc.member_node_ids(), vec![1, 2, 3]);
    }

    #[test]
    fn propose_by_non_member_fails() {
        let mut svc = bootstrap_service(&[1, 2]);
        let result = svc.propose_transition(99, EpochEvent::Increment, TransitionReason::Heartbeat);
        match result {
            Err(EpochTransitionError::NotMember { member_id, .. }) => {
                assert_eq!(member_id, 99);
            }
            other => panic!("expected NotMember, got {other:?}"),
        }
    }

    #[test]
    fn propose_leave_removes_member() {
        let mut svc = bootstrap_service(&[1, 2, 3]);
        let result = svc.propose_transition(
            1,
            EpochEvent::Leave(NodeIdentity::new(2)),
            TransitionReason::Leave,
        );
        assert!(result.is_ok());
        assert!(!svc.is_member(2));
        assert_eq!(svc.member_node_ids(), vec![1, 3]);
        assert_eq!(svc.current_epoch().epoch_id, 1);
    }

    #[test]
    fn propose_increment_bumps_epoch() {
        let mut svc = bootstrap_service(&[1]);
        let result = svc.propose_transition(1, EpochEvent::Increment, TransitionReason::Heartbeat);
        assert!(result.is_ok());
        assert_eq!(svc.current_epoch().epoch_id, 1);
        assert_eq!(svc.member_node_ids(), vec![1]);
    }

    #[test]
    fn validate_epoch_accepts_current_and_past() {
        let mut svc = bootstrap_service(&[1]);
        assert!(svc.validate_epoch(0));
        svc.propose_transition(1, EpochEvent::Increment, TransitionReason::Heartbeat)
            .unwrap();
        assert!(svc.validate_epoch(0));
        assert!(svc.validate_epoch(1));
    }

    #[test]
    fn validate_epoch_rejects_unknown() {
        let svc = bootstrap_service(&[1]);
        assert!(!svc.validate_epoch(999));
    }

    #[test]
    fn epoch_since_filters_correctly() {
        let mut svc = bootstrap_service(&[1]);
        svc.propose_transition(1, EpochEvent::Increment, TransitionReason::Heartbeat)
            .unwrap();
        svc.propose_transition(1, EpochEvent::Increment, TransitionReason::Heartbeat)
            .unwrap();
        svc.propose_transition(1, EpochEvent::Increment, TransitionReason::Heartbeat)
            .unwrap();

        let since_2 = svc.epoch_since(2);
        assert_eq!(since_2.len(), 2);
    }

    #[test]
    fn verified_transition_hash_is_deterministic() {
        let mut svc1 = bootstrap_service(&[1]);
        let mut svc2 = bootstrap_service(&[1]);

        let vt1 = svc1
            .propose_transition(1, EpochEvent::Increment, TransitionReason::Heartbeat)
            .unwrap();
        let vt2 = svc2
            .propose_transition(1, EpochEvent::Increment, TransitionReason::Heartbeat)
            .unwrap();

        assert_eq!(vt1.blake3_hash, vt2.blake3_hash);
        assert!(vt1.verify());
        assert!(vt2.verify());
    }

    #[test]
    fn verified_transition_hash_differs_by_event() {
        let mut svc = bootstrap_service(&[1, 2]);
        let vt_inc = svc
            .propose_transition(1, EpochEvent::Increment, TransitionReason::Heartbeat)
            .unwrap();

        let mut svc2 = bootstrap_service(&[1, 2]);
        let vt_join = svc2
            .propose_transition(
                1,
                EpochEvent::Join(NodeIdentity::new(3)),
                TransitionReason::Join,
            )
            .unwrap();

        assert_ne!(vt_inc.blake3_hash, vt_join.blake3_hash);
    }

    #[test]
    fn transition_history_capped() {
        let mut svc = bootstrap_service(&[1]);
        for _i in 0..1100 {
            svc.propose_transition(1, EpochEvent::Increment, TransitionReason::Heartbeat)
                .unwrap();
        }
        assert!(svc.transition_count() <= 1024);
    }

    #[test]
    fn serde_roundtrip_epoch_service() {
        let mut svc = bootstrap_service(&[1, 2, 3]);
        svc.propose_transition(
            1,
            EpochEvent::Join(NodeIdentity::new(4)),
            TransitionReason::Join,
        )
        .unwrap();

        let json = serde_json::to_string(&svc).unwrap();
        let restored: EpochService = serde_json::from_str(&json).unwrap();

        assert_eq!(
            restored.current_epoch().epoch_id,
            svc.current_epoch().epoch_id
        );
        assert_eq!(restored.member_node_ids(), svc.member_node_ids());
        assert_eq!(restored.transition_count(), svc.transition_count());
    }

    #[test]
    fn verified_epoch_transition_serde_roundtrip() {
        let mut svc = bootstrap_service(&[1]);
        let vt = svc
            .propose_transition(1, EpochEvent::Increment, TransitionReason::Heartbeat)
            .unwrap();

        let json = serde_json::to_string(&vt).unwrap();
        let restored: VerifiedEpochTransition = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.blake3_hash, vt.blake3_hash);
        assert!(restored.verify());
    }

    #[test]
    fn full_lifecycle_join_leave_join() {
        let mut svc = bootstrap_service(&[1]);
        svc.propose_transition(
            1,
            EpochEvent::Join(NodeIdentity::new(2)),
            TransitionReason::Join,
        )
        .unwrap();
        assert!(svc.is_member(2));
        assert_eq!(svc.current_epoch().epoch_id, 1);

        svc.propose_transition(
            1,
            EpochEvent::Leave(NodeIdentity::new(2)),
            TransitionReason::Leave,
        )
        .unwrap();
        assert!(!svc.is_member(2));
        assert_eq!(svc.current_epoch().epoch_id, 2);

        svc.propose_transition(
            1,
            EpochEvent::Join(NodeIdentity::new(2)),
            TransitionReason::Join,
        )
        .unwrap();
        assert!(svc.is_member(2));
        assert_eq!(svc.current_epoch().epoch_id, 3);

        assert_eq!(svc.transition_count(), 3);
    }

    // ── Departure coordinator integration tests ─────────────────────

    #[test]
    fn with_departure_coordinator_enables_departure_handling() {
        let svc = bootstrap_service(&[1, 2, 3]).with_departure_coordinator();
        assert!(svc.departure_coordinator.is_some());
        assert_eq!(svc.current_epoch().epoch_id, 0);
        assert_eq!(svc.member_node_ids(), vec![1, 2, 3]);
    }

    #[test]
    fn handle_departure_request_accepts_when_coordinator_present() {
        let mut svc = bootstrap_service(&[1, 2, 3, 4]).with_departure_coordinator();
        let (resp, proposal_id) = svc
            .handle_departure_request(2, LeaveReason::Voluntary, 1000)
            .unwrap();

        assert!(resp.accepted);
        assert_eq!(resp.peer_id, 2);
        assert!(proposal_id.is_some());
    }

    #[test]
    fn handle_departure_request_returns_none_without_coordinator() {
        let mut svc = bootstrap_service(&[1, 2, 3]);
        assert!(svc
            .handle_departure_request(2, LeaveReason::Voluntary, 1000)
            .is_none());
    }

    #[test]
    fn departure_vote_commits_through_epoch_service() {
        let mut svc = bootstrap_service(&[1, 2, 3]).with_departure_coordinator();
        let (_, proposal_id) = svc
            .handle_departure_request(2, LeaveReason::Voluntary, 1000)
            .unwrap();
        let pid = proposal_id.unwrap();

        let r1 = svc
            .receive_departure_vote(pid, 1, true, 2000)
            .unwrap()
            .unwrap();
        assert!(matches!(r1, QuorumOutcome::Pending));

        let r2 = svc
            .receive_departure_vote(pid, 3, true, 3000)
            .unwrap()
            .unwrap();
        assert!(matches!(r2, QuorumOutcome::Committed { .. }));
    }

    #[test]
    fn departure_timeout_detected_through_epoch_service() {
        let mut svc = bootstrap_service(&[1, 2, 3]).with_departure_coordinator();
        let (_, proposal_id) = svc
            .handle_departure_request(2, LeaveReason::Voluntary, 1000)
            .unwrap();
        let pid = proposal_id.unwrap();

        // Reject votes make quorum unreachable; timeout will abort.
        svc.receive_departure_vote(pid, 1, false, 2000);
        svc.receive_departure_vote(pid, 3, false, 2000);

        let terminal = svc.check_departure_timeouts(1000 + 50_000);
        assert!(!terminal.is_empty());
        assert!(matches!(terminal[0].1, QuorumOutcome::Rejected { .. }));
    }

    #[test]
    fn check_departure_timeouts_empty_without_coordinator() {
        let mut svc = bootstrap_service(&[1, 2, 3]);
        let terminal = svc.check_departure_timeouts(5000);
        assert!(terminal.is_empty());
    }
}
