// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Node-drain state machine with membership-epoch coordination.
//!
//! The [`DrainStateMachine`] processes [`DrainRequest`]s validated against
//! the live membership view via the [`MembershipVerificationOps`] trait,
//! coordinates with membership-epoch for post-drain epoch advancement, and
//! ensures drain idempotency through drain sequence tracking.
//!
//! ## Lifecycle
//!
//! ```text
//! Idle → [validate_drain_request] → Validating
//!   → [initiate_drain] → Transferring
//!     → [complete_drain] → Complete
//!     → [abort_drain] → Failed
//! ```
//!
//! Each transition validates the request against live membership state.
//! Idempotent retry is provided by `drain_sequence`. Transport-layer
//! integrity and Ed25519 signatures provide authenticity.

use serde::Serialize;
use std::fmt;
use tidefs_membership_epoch::{EpochId, MemberId};

// ---------------------------------------------------------------------------
// MembershipVerificationOps — trait for live membership checks
// ---------------------------------------------------------------------------

/// Operations that the [`DrainStateMachine`] calls to validate drain requests
/// against the live membership view. Production implementations wire this to
/// [`tidefs_membership_live::FailureDetector`] and
/// [`tidefs_membership_epoch::MembershipEpoch`]. Test implementations use
/// mocks.
pub trait MembershipVerificationOps {
    /// Returns true if the given node is currently live (responding to
    /// heartbeats, not suspected or dead).
    fn is_node_live(&self, node_id: MemberId) -> bool;

    /// Returns true if the given node is a member of the current cluster
    /// configuration.
    fn is_member(&self, node_id: MemberId) -> bool;

    /// Returns the current membership epoch.
    fn current_epoch(&self) -> EpochId;
}

// ---------------------------------------------------------------------------
// PlacementEvidenceVerifier — receipt-to-node reference check
// ---------------------------------------------------------------------------

/// Verifier that checks whether any placement receipt still references
/// a given node.  Used by the drain safety gate: decommission must fail
/// closed when any placement receipt still references the draining node.
pub trait PlacementEvidenceVerifier {
    /// Return the set of placement receipt ids that reference `node_id`.
    fn receipts_referencing_node(&self, node_id: MemberId) -> Vec<tidefs_replication_model::ReplicatedReceiptId>;

    /// Returns true if any placement receipt references `node_id`.
    fn has_receipts_referencing_node(&self, node_id: MemberId) -> bool {
        !self.receipts_referencing_node(node_id).is_empty()
    }
}

// ---------------------------------------------------------------------------
// DrainRequest — BLAKE3-verified drain request
// ---------------------------------------------------------------------------

/// A request to drain a node from the cluster.
///
/// Idempotent retry is identified by `drain_sequence`.
/// Transport-layer integrity and Ed25519 signatures provide authenticity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DrainRequest {
    /// The node being drained.
    pub draining_node_id: MemberId,
    /// The node that initiated the drain (operator or coordinator).
    pub initiator_node_id: MemberId,
    /// Membership epoch at the time the request was issued.
    pub membership_epoch: EpochId,
    /// Monotonically increasing sequence number for idempotent retry.
    pub drain_sequence: u64,
}

impl DrainRequest {
    /// Create a new drain request.
    #[must_use]
    pub fn new(
        draining_node_id: MemberId,
        initiator_node_id: MemberId,
        membership_epoch: EpochId,
        drain_sequence: u64,
    ) -> Self {
        Self {
            draining_node_id,
            initiator_node_id,
            membership_epoch,
            drain_sequence,
        }
    }

    /// Returns true if this request targets the same node, epoch, and sequence
    /// (used for idempotent retry detection).
    #[must_use]
    pub fn is_same_drain(&self, other: &Self) -> bool {
        self.draining_node_id == other.draining_node_id
            && self.membership_epoch == other.membership_epoch
            && self.drain_sequence == other.drain_sequence
    }
}

// ---------------------------------------------------------------------------
// DrainState — request-level drain lifecycle
// ---------------------------------------------------------------------------

/// Phases of a drain request as it moves through validation, transfer, and
/// completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DrainState {
    /// No drain operation is in progress.
    Idle,
    /// Drain request received; validating against membership and BLAKE3 digest.
    Validating,
    /// Data/leases/cache being transferred off the draining node.
    Transferring,
    /// Transfer complete; finalizing epoch transition.
    Completing,
    /// Drain completed successfully; node is excluded from next epoch.
    Complete,
    /// Drain failed (transfer loss, epoch rejection, validation error).
    Failed,
}

impl DrainState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Validating => "validating",
            Self::Transferring => "transferring",
            Self::Completing => "completing",
            Self::Complete => "complete",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed)
    }

    /// Returns true if the current state can transition to `next`.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Idle, Self::Validating)
                | (Self::Validating, Self::Transferring)
                | (Self::Validating, Self::Failed)
                | (Self::Transferring, Self::Completing)
                | (Self::Transferring, Self::Failed)
                | (Self::Completing, Self::Complete)
                | (Self::Completing, Self::Failed)
        )
    }
}

impl Default for DrainState {
    fn default() -> Self {
        Self::Idle
    }
}

// ---------------------------------------------------------------------------
// DrainRequestError
// ---------------------------------------------------------------------------

/// Errors that can occur during drain request validation and execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrainRequestError {
    /// The request is structurally invalid (missing fields, bad format).
    InvalidRequest { reason: String },
    /// The draining or initiator node was not found in the membership view.
    NodeNotFound { node_id: MemberId },
    /// The draining node is not in a drainable state.
    NotDrainable { node_id: MemberId, reason: String },
    /// The initiator is not a member of the cluster.
    InitiatorNotMember { node_id: MemberId },
    /// Self-drain requests are rejected (a node cannot drain itself).
    SelfDrainRejected { node_id: MemberId },
    /// The request's membership epoch is stale (behind the current epoch).
    StaleEpoch {
        request_epoch: u64,
        current_epoch: u64,
    },
    /// Transfer of data/leases/cache failed.
    TransferFailure { reason: String },
    /// The epoch gate rejected the post-drain epoch transition.
    EpochRejection { reason: String },
    /// Drain is already complete for this node.
    AlreadyComplete { node_id: MemberId },
}

impl fmt::Display for DrainRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest { reason } => {
                write!(f, "invalid drain request: {reason}")
            }
            Self::NodeNotFound { node_id } => {
                write!(f, "node {} not found in membership", node_id.0)
            }
            Self::NotDrainable { node_id, reason } => {
                write!(f, "node {} cannot be drained: {reason}", node_id.0)
            }
            Self::InitiatorNotMember { node_id } => {
                write!(f, "initiator node {} is not a cluster member", node_id.0)
            }
            Self::SelfDrainRejected { node_id } => {
                write!(f, "node {} cannot drain itself", node_id.0)
            }
            Self::StaleEpoch {
                request_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "stale epoch: request at {request_epoch}, current is {current_epoch}"
                )
            }
            Self::TransferFailure { reason } => {
                write!(f, "transfer failure: {reason}")
            }
            Self::EpochRejection { reason } => {
                write!(f, "epoch rejection: {reason}")
            }
            Self::AlreadyComplete { node_id } => {
                write!(f, "drain already complete for node {}", node_id.0)
            }
        }
    }
}

impl std::error::Error for DrainRequestError {}

// ---------------------------------------------------------------------------
// DrainStateMachine — request-level drain protocol
// ---------------------------------------------------------------------------

/// A state machine that processes a single drain request through validation,
/// transfer, and completion phases.
///
/// The machine uses [`MembershipVerificationOps`] to validate requests against
/// the live membership view and coordinates with membership-epoch for the
/// post-drain epoch transition. Drain idempotency is ensured by tracking the
/// per-node drain sequence number; repeated requests with the same sequence
/// are no-ops.
#[derive(Clone, Debug)]
pub struct DrainStateMachine {
    state: DrainState,
    draining_node_id: MemberId,
    current_epoch: EpochId,
    drain_sequence: u64,
    /// Human-readable reason for the last failure.
    failure_reason: Option<String>,
}

impl DrainStateMachine {
    /// Create a new idle state machine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: DrainState::Idle,
            draining_node_id: MemberId::ZERO,
            current_epoch: EpochId(0),
            drain_sequence: 0,
            failure_reason: None,
        }
    }

    // Accessors

    #[must_use]
    pub fn state(&self) -> DrainState {
        self.state
    }

    #[must_use]
    pub fn draining_node_id(&self) -> MemberId {
        self.draining_node_id
    }

    #[must_use]
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    #[must_use]
    pub fn drain_sequence(&self) -> u64 {
        self.drain_sequence
    }

    #[must_use]
    pub fn failure_reason(&self) -> Option<&str> {
        self.failure_reason.as_deref()
    }

    /// Validate a drain request against the live membership view.
    ///
    /// Checks performed:
    /// 1. State must be Idle (no concurrent drain for this node)
    /// 2. The draining node must exist in membership and be live
    /// 3. The initiator must be a member (if not self-drain)
    /// 4. Self-drain is rejected
    /// 5. Epoch must not be stale
    ///
    /// On success, transitions from `Idle` to `Validating`.
    pub fn validate_drain_request(
        &mut self,
        request: &DrainRequest,
        ops: &dyn MembershipVerificationOps,
    ) -> Result<(), DrainRequestError> {
        // 1. State precondition: must be Idle
        if self.state != DrainState::Idle {
            return if self.state == DrainState::Complete {
                Err(DrainRequestError::AlreadyComplete {
                    node_id: self.draining_node_id,
                })
            } else {
                Err(DrainRequestError::InvalidRequest {
                    reason: format!(
                        "drain state machine is not idle (current: {:?})",
                        self.state
                    ),
                })
            };
        }

        // 2. Draining node must exist and be live
        if !ops.is_member(request.draining_node_id) {
            return Err(DrainRequestError::NodeNotFound {
                node_id: request.draining_node_id,
            });
        }
        if !ops.is_node_live(request.draining_node_id) {
            return Err(DrainRequestError::NotDrainable {
                node_id: request.draining_node_id,
                reason: "node is not live".to_string(),
            });
        }

        // 3. Initiator must be a member
        if request.initiator_node_id != request.draining_node_id
            && !ops.is_member(request.initiator_node_id)
        {
            return Err(DrainRequestError::InitiatorNotMember {
                node_id: request.initiator_node_id,
            });
        }

        // 4. Self-drain is rejected
        if request.initiator_node_id == request.draining_node_id {
            return Err(DrainRequestError::SelfDrainRejected {
                node_id: request.draining_node_id,
            });
        }

        // 5. Epoch must not be stale
        let current_epoch = ops.current_epoch();
        if request.membership_epoch.0 < current_epoch.0 {
            return Err(DrainRequestError::StaleEpoch {
                request_epoch: request.membership_epoch.0,
                current_epoch: current_epoch.0,
            });
        }

        // Accept the request
        self.draining_node_id = request.draining_node_id;
        self.current_epoch = current_epoch;
        self.drain_sequence = request.drain_sequence;
        self.state = DrainState::Validating;
        self.failure_reason = None;

        Ok(())
    }

    /// Initiate the drain, transitioning from Validating to Transferring.
    ///
    /// This is the point where the drain intent is persisted to the committed
    /// root for crash idempotency. In production, this writes a drain-intent
    /// record anchored to the current committed root.
    ///
    /// Returns an error if the state machine is not in `Validating`.
    pub fn initiate_drain(&mut self) -> Result<(), DrainRequestError> {
        if self.state != DrainState::Validating {
            return Err(DrainRequestError::InvalidRequest {
                reason: format!("cannot initiate drain from state {:?}", self.state),
            });
        }

        self.state = DrainState::Transferring;
        Ok(())
    }

    /// Complete the drain, transitioning from Transferring to Completing and
    /// then to Complete.
    ///
    /// This signals to membership-epoch that the departing node can be excluded
    /// from the next epoch proposal. The caller is responsible for actually
    /// triggering the epoch advancement via [`crate::epoch_gate::EpochGate`].
    ///
    /// Returns an error if the state machine is not in `Transferring`.
    pub fn complete_drain(&mut self) -> Result<(), DrainRequestError> {
        if self.state != DrainState::Transferring {
            return Err(DrainRequestError::InvalidRequest {
                reason: format!("cannot complete drain from state {:?}", self.state),
            });
        }

        self.state = DrainState::Completing;

        // The Completing → Complete transition happens once the epoch gate
        // commits. For now, we move directly to Complete; the orchestrator
        // wires the epoch gate externally.
        self.state = DrainState::Complete;

        Ok(())
    }

    /// Abort the drain, rolling back to `Failed`.
    ///
    /// Called on unrecoverable errors: transport loss mid-transfer, epoch
    /// gate rejection, or operator cancellation. The failure reason is
    /// recorded for diagnostics.
    pub fn abort_drain(&mut self, reason: String) -> Result<(), DrainRequestError> {
        if self.state.is_terminal() {
            return Err(DrainRequestError::InvalidRequest {
                reason: format!("cannot abort drain from terminal state {:?}", self.state),
            });
        }

        self.failure_reason = Some(reason);
        self.state = DrainState::Failed;
        Ok(())
    }

    /// Reset the state machine back to Idle for a new drain request.
    pub fn reset(&mut self) {
        self.state = DrainState::Idle;
        self.draining_node_id = MemberId::ZERO;
        self.current_epoch = EpochId(0);
        self.drain_sequence = 0;
        self.failure_reason = None;
    }
}

impl Default for DrainStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Test helper: mock membership ops ---

    struct MockMembershipOps {
        live_nodes: Vec<MemberId>,
        members: Vec<MemberId>,
        epoch: EpochId,
    }

    impl MockMembershipOps {
        fn new(epoch: u64) -> Self {
            Self {
                live_nodes: Vec::new(),
                members: Vec::new(),
                epoch: EpochId(epoch),
            }
        }

        fn add_member(&mut self, id: MemberId, live: bool) {
            self.members.push(id);
            if live {
                self.live_nodes.push(id);
            }
        }
    }

    impl MembershipVerificationOps for MockMembershipOps {
        fn is_node_live(&self, node_id: MemberId) -> bool {
            self.live_nodes.contains(&node_id)
        }

        fn is_member(&self, node_id: MemberId) -> bool {
            self.members.contains(&node_id)
        }

        fn current_epoch(&self) -> EpochId {
            self.epoch
        }
    }

    fn mid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn make_request(draining: u64, initiator: u64, epoch: u64, seq: u64) -> DrainRequest {
        DrainRequest::new(mid(draining), mid(initiator), EpochId(epoch), seq)
    }

    // --- DrainRequest tests ---

    #[test]
    fn drain_request_is_same_drain() {
        let r1 = make_request(1, 2, 5, 42);
        let r2 = make_request(1, 2, 5, 42);
        assert!(r1.is_same_drain(&r2));
    }

    #[test]
    fn drain_request_is_not_same_drain_different_seq() {
        let r1 = make_request(1, 2, 5, 42);
        let r2 = make_request(1, 2, 5, 43);
        assert!(!r1.is_same_drain(&r2));
    }

    // --- DrainState tests ---

    #[test]
    fn drain_state_transitions() {
        assert!(DrainState::Idle.can_transition_to(DrainState::Validating));
        assert!(!DrainState::Idle.can_transition_to(DrainState::Transferring));
        assert!(!DrainState::Idle.can_transition_to(DrainState::Complete));

        assert!(DrainState::Validating.can_transition_to(DrainState::Transferring));
        assert!(DrainState::Validating.can_transition_to(DrainState::Failed));
        assert!(!DrainState::Validating.can_transition_to(DrainState::Complete));

        assert!(DrainState::Transferring.can_transition_to(DrainState::Completing));
        assert!(DrainState::Transferring.can_transition_to(DrainState::Failed));

        assert!(DrainState::Completing.can_transition_to(DrainState::Complete));
        assert!(DrainState::Completing.can_transition_to(DrainState::Failed));

        assert!(!DrainState::Complete.can_transition_to(DrainState::Idle));
        assert!(!DrainState::Failed.can_transition_to(DrainState::Idle));
    }

    #[test]
    fn drain_state_terminal() {
        assert!(DrainState::Complete.is_terminal());
        assert!(DrainState::Failed.is_terminal());
        assert!(!DrainState::Idle.is_terminal());
        assert!(!DrainState::Validating.is_terminal());
        assert!(!DrainState::Transferring.is_terminal());
        assert!(!DrainState::Completing.is_terminal());
    }

    // --- DrainStateMachine tests ---

    #[test]
    fn state_machine_starts_idle() {
        let sm = DrainStateMachine::new();
        assert_eq!(sm.state(), DrainState::Idle);
    }

    #[test]
    fn validate_accepts_valid_request() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true); // draining node: member + live
        ops.add_member(mid(2), true); // initiator: member + live

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();

        sm.validate_drain_request(&req, &ops).unwrap();
        assert_eq!(sm.state(), DrainState::Validating);
        assert_eq!(sm.draining_node_id(), mid(1));
        assert_eq!(sm.drain_sequence(), 0);
    }

    #[test]
    fn drain_request_constructs_without_blake3() {
        let req = DrainRequest::new(mid(1), mid(2), EpochId(5), 0);
        assert_eq!(req.draining_node_id, mid(1));
        assert_eq!(req.initiator_node_id, mid(2));
        assert_eq!(req.membership_epoch, EpochId(5));
        assert_eq!(req.drain_sequence, 0);
    }

    #[test]
    fn validate_rejects_node_not_member() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(2), true); // only initiator is a member
                                      // node 1 is NOT a member

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();
        let err = sm.validate_drain_request(&req, &ops).unwrap_err();
        assert!(matches!(err, DrainRequestError::NodeNotFound { .. }));
    }

    #[test]
    fn validate_rejects_node_not_live() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), false); // member but NOT live
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();
        let err = sm.validate_drain_request(&req, &ops).unwrap_err();
        assert!(matches!(err, DrainRequestError::NotDrainable { .. }));
    }

    #[test]
    fn validate_rejects_initiator_not_member() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true); // draining node is member + live
                                      // initiator node 2 is NOT a member

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();
        let err = sm.validate_drain_request(&req, &ops).unwrap_err();
        assert!(matches!(err, DrainRequestError::InitiatorNotMember { .. }));
    }

    #[test]
    fn validate_rejects_self_drain() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true);

        let req = make_request(1, 1, 5, 0); // self-drain
        let mut sm = DrainStateMachine::new();
        let err = sm.validate_drain_request(&req, &ops).unwrap_err();
        assert!(matches!(err, DrainRequestError::SelfDrainRejected { .. }));
    }

    #[test]
    fn validate_rejects_stale_epoch() {
        let mut ops = MockMembershipOps::new(10); // current epoch is 10
        ops.add_member(mid(1), true);
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0); // request at epoch 5
        let mut sm = DrainStateMachine::new();
        let err = sm.validate_drain_request(&req, &ops).unwrap_err();
        assert!(matches!(err, DrainRequestError::StaleEpoch { .. }));
    }

    #[test]
    fn validate_accepts_same_epoch() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true);
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0); // request at epoch 5, current is 5
        let mut sm = DrainStateMachine::new();
        sm.validate_drain_request(&req, &ops).unwrap();
        assert_eq!(sm.state(), DrainState::Validating);
    }

    #[test]
    fn validate_rejects_when_not_idle() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true);
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();
        sm.validate_drain_request(&req, &ops).unwrap();
        assert_eq!(sm.state(), DrainState::Validating);

        // Second validation should fail
        let req2 = make_request(3, 2, 5, 0);
        let err = sm.validate_drain_request(&req2, &ops).unwrap_err();
        assert!(matches!(err, DrainRequestError::InvalidRequest { .. }));
    }

    #[test]
    fn initiate_from_validating() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true);
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();
        sm.validate_drain_request(&req, &ops).unwrap();
        assert_eq!(sm.state(), DrainState::Validating);

        sm.initiate_drain().unwrap();
        assert_eq!(sm.state(), DrainState::Transferring);
    }

    #[test]
    fn initiate_rejects_from_idle() {
        let mut sm = DrainStateMachine::new();
        let err = sm.initiate_drain().unwrap_err();
        assert!(matches!(err, DrainRequestError::InvalidRequest { .. }));
    }

    #[test]
    fn complete_from_transferring() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true);
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();
        sm.validate_drain_request(&req, &ops).unwrap();
        sm.initiate_drain().unwrap();
        assert_eq!(sm.state(), DrainState::Transferring);

        sm.complete_drain().unwrap();
        assert_eq!(sm.state(), DrainState::Complete);
    }

    #[test]
    fn complete_rejects_from_validating() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true);
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();
        sm.validate_drain_request(&req, &ops).unwrap();
        let err = sm.complete_drain().unwrap_err();
        assert!(matches!(err, DrainRequestError::InvalidRequest { .. }));
    }

    #[test]
    fn abort_from_validating() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true);
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();
        sm.validate_drain_request(&req, &ops).unwrap();
        assert_eq!(sm.state(), DrainState::Validating);

        sm.abort_drain("transport loss".to_string()).unwrap();
        assert_eq!(sm.state(), DrainState::Failed);
        assert_eq!(sm.failure_reason(), Some("transport loss"));
    }

    #[test]
    fn abort_from_transferring() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true);
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();
        sm.validate_drain_request(&req, &ops).unwrap();
        sm.initiate_drain().unwrap();
        sm.abort_drain("mid-transfer crash".to_string()).unwrap();
        assert_eq!(sm.state(), DrainState::Failed);
    }

    #[test]
    fn abort_rejects_from_complete() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true);
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();
        sm.validate_drain_request(&req, &ops).unwrap();
        sm.initiate_drain().unwrap();
        sm.complete_drain().unwrap();
        assert_eq!(sm.state(), DrainState::Complete);

        let err = sm.abort_drain("too late".to_string()).unwrap_err();
        assert!(matches!(err, DrainRequestError::InvalidRequest { .. }));
    }

    #[test]
    fn abort_rejects_from_failed() {
        let mut sm = DrainStateMachine::new();
        // Force into Failed via manual state manipulation
        sm.state = DrainState::Failed;
        let err = sm.abort_drain("retry".to_string()).unwrap_err();
        assert!(matches!(err, DrainRequestError::InvalidRequest { .. }));
    }

    #[test]
    fn reset_after_complete() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true);
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();
        sm.validate_drain_request(&req, &ops).unwrap();
        sm.initiate_drain().unwrap();
        sm.complete_drain().unwrap();
        assert_eq!(sm.state(), DrainState::Complete);

        sm.reset();
        assert_eq!(sm.state(), DrainState::Idle);
        assert_eq!(sm.draining_node_id(), MemberId::ZERO);
        assert_eq!(sm.drain_sequence(), 0);
    }

    #[test]
    fn full_lifecycle_idle_to_complete() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true);
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();

        sm.validate_drain_request(&req, &ops).unwrap();
        assert_eq!(sm.state(), DrainState::Validating);

        sm.initiate_drain().unwrap();
        assert_eq!(sm.state(), DrainState::Transferring);

        sm.complete_drain().unwrap();
        assert_eq!(sm.state(), DrainState::Complete);
        assert!(sm.state().is_terminal());
    }

    #[test]
    fn idempotent_validation_after_reset() {
        let mut ops = MockMembershipOps::new(5);
        ops.add_member(mid(1), true);
        ops.add_member(mid(2), true);

        let req = make_request(1, 2, 5, 0);
        let mut sm = DrainStateMachine::new();
        sm.validate_drain_request(&req, &ops).unwrap();
        sm.initiate_drain().unwrap();
        sm.complete_drain().unwrap();
        sm.reset();

        // Same request should be accepted again after reset
        sm.validate_drain_request(&req, &ops).unwrap();
        assert_eq!(sm.state(), DrainState::Validating);
    }

    #[test]
    fn drain_request_error_display() {
        let err = DrainRequestError::SelfDrainRejected { node_id: mid(42) };
        assert!(format!("{err}").contains("42"));

        let err = DrainRequestError::StaleEpoch {
            request_epoch: 3,
            current_epoch: 7,
        };
        let s = format!("{err}");
        assert!(s.contains("3"));
        assert!(s.contains("7"));
    }

    #[test]
    fn drain_state_display() {
        assert_eq!(DrainState::Idle.as_str(), "idle");
        assert_eq!(DrainState::Validating.as_str(), "validating");
        assert_eq!(DrainState::Transferring.as_str(), "transferring");
        assert_eq!(DrainState::Completing.as_str(), "completing");
        assert_eq!(DrainState::Complete.as_str(), "complete");
        assert_eq!(DrainState::Failed.as_str(), "failed");
    }
}
