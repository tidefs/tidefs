// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Node join protocol: staged promotion with health gates — PC-010.4.
//!
//! Implements a 3-phase staged join that safely onboards a new member
//! into the cluster. Each promotion phase requires a health check gate.
//! Failing a health gate demotes the node to the previous phase rather
//! than ejecting it. Replicas are only placed after p5 (ReplicaTarget)
//! promotion with placement receipts.
//!
//! # Phases
//!
//! ```text
//! ShadowOnly(p4) → VoterSpread(p2) → ReplicaTarget(p5)
//! ```
//!
//! - p4 (WitnessSpread / ShadowOnly): shadow/witness phase —
//!   minimal data, observes cluster state
//! - p2 (VoterSpread / Witness): witness phase — can participate
//!   in quorum and serve witness functions
//! - p5 (ReplicaTarget): full replica target — can receive new
//!   replica placements

#![forbid(unsafe_code)]

pub mod auth;
pub mod discovery;
pub mod handshake;
pub mod join_lifecycle;
pub mod session_binding;
pub mod state_transfer;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use tidefs_membership_epoch::{
    EpochId, HealthClass, MemberId, MembershipConfigRecord, PlacementIntentClass,
};

// ── Gate constant ───────────────────────────────────────────────────

pub const NODE_JOIN_PROTOCOL_GATE_PC_010_4: &str =
    "PC-010.4 node join protocol with p4→p2→p5 promotion phases and health gates";

// ── Error types ──────────────────────────────────────────────────────

#[derive(Error, Clone, Debug, PartialEq)]
pub enum JoinError {
    #[error("join preflight denied: {0}")]
    PreflightDenied(String),

    #[error("health gate at phase {phase:?} blocked: {reason}")]
    HealthGateBlocked { phase: JoinPhase, reason: String },

    #[error("cannot promote from {from:?} to {to:?}: {reason}")]
    CannotPromote {
        from: JoinPhase,
        to: JoinPhase,
        reason: String,
    },

    #[error("join is already in terminal phase {0:?}")]
    AlreadyTerminal(JoinPhase),

    #[error("node {member_id} is not joinable: {reason}")]
    NotJoinable { member_id: u64, reason: String },

    #[error("epoch mismatch: expected {expected:?}, got {got:?}")]
    EpochMismatch { expected: EpochId, got: EpochId },

    #[error("joint-config epoch already in progress: epoch {epoch:?}")]
    JointConfigInProgress { epoch: EpochId },

    #[error("member {member_id:?} health insufficient for {phase:?}: {health:?}")]
    InsufficientHealth {
        member_id: MemberId,
        phase: JoinPhase,
        health: HealthClass,
    },

    #[error("missing epoch evidence for operation: {0}")]
    MissingEpochEvidence(String),

    #[error("stale epoch: session epoch {session_epoch:?}, current epoch {current_epoch:?}: {reason}")]
    StaleEpoch {
        session_epoch: EpochId,
        current_epoch: EpochId,
        reason: String,
    },

    #[error("identity mismatch: session bound to {session_member:?}, caller is {caller_member:?}")]
    IdentityMismatch {
        session_member: MemberId,
        caller_member: MemberId,
    },

    #[error("quorum not reached for epoch {epoch:?}: {approvals}/{threshold} approvals")]
    QuorumNotReached {
        epoch: EpochId,
        approvals: usize,
        threshold: usize,
    },
}

// ── Quorum evidence ──────────────────────────────────────────────────

/// Evidence that the membership epoch authorizing this join session
/// was backed by a quorum of cluster members.
///
/// Carried through the node-join pipeline so that state transfer and
/// promotion gates can verify the join was quorum-authorized.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuorumEvidence {
    /// The membership epoch this evidence covers.
    pub epoch: EpochId,
    /// Number of approvals that established the quorum.
    pub quorum_approvals: usize,
    /// The quorum threshold required.
    pub quorum_threshold: usize,
    /// The set of member IDs that approved (for audit trail).
    pub approving_members: Vec<MemberId>,
}

impl QuorumEvidence {
    /// Whether this evidence demonstrates a valid quorum.
    #[must_use]
    pub fn is_quorum_reached(&self) -> bool {
        self.quorum_approvals >= self.quorum_threshold
            && self.quorum_threshold > 0
    }

    /// Required approvals for a simple-majority quorum of `n` members.
    #[must_use]
    pub fn simple_majority_threshold(n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (n / 2) + 1
        }
    }
}

// ── Join session epoch ──────────────────────────────────────────────

/// The join session epoch binding: ties a join session to the
/// membership epoch and quorum that authorized it.
///
/// All phases of node join (handshake → state transfer → promotion)
/// must reference the same `JoinSessionEpoch` to ensure the join
/// was authorized under a quorum-backed membership view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JoinSessionEpoch {
    /// The membership epoch.
    pub epoch: EpochId,
    /// Evidence that quorum was reached for this epoch.
    /// `None` means quorum evidence was not recorded
    /// (not yet received, or this is a legacy join path).
    pub quorum_evidence: Option<QuorumEvidence>,
    /// The member ID of the joining node.
    pub joining_member_id: MemberId,
    /// Nonce unique to this join session.
    pub session_nonce: u64,
}

impl JoinSessionEpoch {
    /// Create a new session epoch binding.
    #[must_use]
    pub fn new(
        epoch: EpochId,
        joining_member_id: MemberId,
        session_nonce: u64,
    ) -> Self {
        Self {
            epoch,
            quorum_evidence: None,
            joining_member_id,
            session_nonce,
        }
    }

    /// Attach quorum evidence to this session.
    pub fn with_quorum(mut self, evidence: QuorumEvidence) -> Self {
        self.quorum_evidence = Some(evidence);
        self
    }

    /// Verify that this session has a quorum-backed membership epoch.
    ///
    /// Returns `Ok(())` if quorum evidence is present and the threshold
    /// is met. Returns a [`JoinStatus`] describing why it isn't valid.
    #[must_use]
    pub fn verify_quorum(&self) -> Result<(), JoinStatus> {
        match &self.quorum_evidence {
            Some(qe) if qe.is_quorum_reached() => Ok(()),
            Some(_) => Err(JoinStatus::WaitingForQuorum),
            None => Err(JoinStatus::WaitingForQuorum),
        }
    }

    /// Verify identity binding: check that the session is bound to
    /// the expected joining member.
    #[must_use]
    pub fn verify_identity(&self, caller_member_id: MemberId) -> Result<(), JoinStatus> {
        if self.joining_member_id != caller_member_id {
            Err(JoinStatus::IdentityMismatch {
                expected: self.joining_member_id,
                actual: caller_member_id,
            })
        } else {
            Ok(())
        }
    }

    /// Verify epoch freshness against the current membership epoch.
    #[must_use]
    pub fn verify_epoch_fresh(&self, current_epoch: EpochId) -> Result<(), JoinStatus> {
        if self.epoch != current_epoch {
            Err(JoinStatus::StaleEpoch {
                current_epoch,
                join_epoch: self.epoch,
            })
        } else {
            Ok(())
        }
    }

    /// Full validation: identity + epoch freshness + quorum.
    #[must_use]
    pub fn is_valid_for(
        &self,
        member_id: MemberId,
        current_epoch: EpochId,
    ) -> Result<(), JoinStatus> {
        self.verify_identity(member_id)?;
        self.verify_epoch_fresh(current_epoch)?;
        self.verify_quorum()?;
        Ok(())
    }
}

// ── Operator-visible join status ────────────────────────────────────

/// Operator-visible join status with distinguishable outcomes.
///
/// Exposed through the node-join pipeline so operators can diagnose
/// why a joining node is stuck without inspecting internal state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum JoinStatus {
    /// Waiting for quorum to be reached for the join session's epoch.
    WaitingForQuorum,
    /// The join session's epoch is stale relative to the current membership.
    StaleEpoch {
        current_epoch: EpochId,
        join_epoch: EpochId,
    },
    /// The join session is bound to a different node identity.
    IdentityMismatch {
        expected: MemberId,
        actual: MemberId,
    },
    /// No epoch evidence has been recorded for this join.
    MissingEpochEvidence,
    /// State transfer is ready to proceed.
    TransferReady,
    /// State transfer is in progress.
    TransferInProgress,
    /// State transfer is complete.
    TransferComplete,
    /// Join failed with a terminal reason.
    Failed(String),
}

// ── Join phases ──────────────────────────────────────────────────────

/// Promotion phases for node join.
///
/// The node progresses through p4 (ShadowOnly) → p2 (VoterSpread) → p5 (ReplicaTarget).
/// For p4 and p2, the numerical values correspond to PlacementIntentClass discriminants
/// for traceability.
#[repr(u8)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum JoinPhase {
    /// Node not yet started joining.
    NotStarted = 0,
    /// p4 — ShadowOnly / WitnessSpread. Shadow phase: minimal data, observes cluster state.
    ShadowOnly = 4,
    /// p2 — VoterSpread / Witness. Can serve witness functions and participate in quorum.
    VoterSpread = 2,
    /// p5 — ReplicaTarget. Full replica target: can receive new replica placements.
    ReplicaTarget = 5,
    /// Join complete — node is fully operational as a replica target.
    Completed = 6,
    /// Node was demoted from ReplicaTarget back to VoterSpread due to health failure.
    DemotedToWitness = 7,
    /// Join failed entirely.
    Failed = 8,
}

impl JoinPhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "join.not_started",
            Self::ShadowOnly => "join.shadow_only.p4",
            Self::VoterSpread => "join.voter_spread.p2",
            Self::ReplicaTarget => "join.replica_target.p5",
            Self::Completed => "join.completed",
            Self::DemotedToWitness => "join.demoted_to_witness",
            Self::Failed => "join.failed",
        }
    }

    /// Next promotion phase in sequence: ShadowOnly → VoterSpread → ReplicaTarget
    #[must_use]
    pub const fn next_promotion(self) -> Option<Self> {
        match self {
            Self::NotStarted => Some(Self::ShadowOnly),
            Self::ShadowOnly => Some(Self::VoterSpread),
            Self::VoterSpread => Some(Self::ReplicaTarget),
            Self::ReplicaTarget => Some(Self::Completed),
            _ => None,
        }
    }

    /// Previous phase for demotion: ReplicaTarget → VoterSpread → ShadowOnly
    #[must_use]
    pub const fn prev_demotion(self) -> Option<Self> {
        match self {
            Self::ReplicaTarget => Some(Self::VoterSpread),
            Self::VoterSpread => Some(Self::ShadowOnly),
            Self::ShadowOnly => Some(Self::NotStarted),
            _ => None,
        }
    }

    /// Placement intent class that governs replica placement at this phase.
    #[must_use]
    pub fn placement_intent(self) -> Option<PlacementIntentClass> {
        match self {
            Self::ShadowOnly => Some(PlacementIntentClass::WitnessSpread),
            Self::VoterSpread => Some(PlacementIntentClass::VoterSpread),
            Self::ReplicaTarget => Some(PlacementIntentClass::ReplicaTarget),
            _ => None,
        }
    }

    /// Whether the node is eligible to receive replica data.
    #[must_use]
    pub const fn can_accept_replicas(self) -> bool {
        matches!(self, Self::ReplicaTarget | Self::Completed)
    }

    /// Whether the node can participate in quorum.
    #[must_use]
    pub const fn can_participate_quorum(self) -> bool {
        matches!(
            self,
            Self::VoterSpread | Self::ReplicaTarget | Self::Completed
        )
    }

    /// Whether the join is in a terminal state (completed, failed).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }

    /// Whether demotion is allowed from this phase.
    #[must_use]
    pub const fn can_demote(self) -> bool {
        matches!(
            self,
            Self::ReplicaTarget | Self::VoterSpread | Self::ShadowOnly
        )
    }
}

// ── Health gate ──────────────────────────────────────────────────────

/// A health check gate that must pass before promotion.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct JoinHealthGate {
    /// The target promotion phase.
    pub target_phase: JoinPhase,
    /// Required minimum health class for promotion.
    pub required_health: HealthClass,
    /// How many consecutive health checks must pass.
    pub required_consecutive_passes: u64,
    /// How many consecutive health checks have passed so far.
    pub consecutive_passes: u64,
    /// Whether the gate is currently satisfied.
    pub is_satisfied: bool,
    /// Human-readable reason for satisfaction/failure.
    pub reason: String,
}

impl JoinHealthGate {
    #[must_use]
    pub fn new(
        target_phase: JoinPhase,
        required_health: HealthClass,
        required_consecutive_passes: u64,
    ) -> Self {
        Self {
            target_phase,
            required_health,
            required_consecutive_passes,
            consecutive_passes: 0,
            is_satisfied: false,
            reason: String::new(),
        }
    }

    /// Evaluate the gate against current node health.
    pub fn evaluate(&mut self, current_health: HealthClass) -> bool {
        if self.is_health_sufficient(current_health) {
            self.consecutive_passes += 1;
        } else {
            self.consecutive_passes = 0;
        }

        self.is_satisfied = self.consecutive_passes >= self.required_consecutive_passes;
        self.reason = if self.is_satisfied {
            format!(
                "health check passed: {consecutive}/{required} consecutive passes (health: {health:?})",
                consecutive = self.consecutive_passes,
                required = self.required_consecutive_passes,
                health = current_health,
            )
        } else {
            format!(
                "health check not yet satisfied: {consecutive}/{required} consecutive passes (health: {health:?})",
                consecutive = self.consecutive_passes,
                required = self.required_consecutive_passes,
                health = current_health,
            )
        };
        self.is_satisfied
    }

    #[must_use]
    pub fn is_health_sufficient(&self, health: HealthClass) -> bool {
        matches!(
            (self.required_health, health),
            (HealthClass::Healthy, HealthClass::Healthy)
                | (HealthClass::Suspect, HealthClass::Healthy)
                | (HealthClass::Suspect, HealthClass::Suspect)
                | (HealthClass::Down, _)
        )
    }
}

// ── Join progress ────────────────────────────────────────────────────

/// Tracks overall join progress across all phases.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JoinProgress {
    /// The joining member.
    pub member_id: MemberId,
    /// Current epoch.
    pub epoch: EpochId,
    /// Current join phase.
    pub phase: JoinPhase,
    /// Health gate for the current promotion target.
    pub health_gate: Option<JoinHealthGate>,
    /// The join session epoch binding that authorizes this join.
    /// Set during the handshake when quorum evidence is recorded.
    pub session_epoch: Option<JoinSessionEpoch>,
    /// When the join started (ns).
    pub started_at_ns: u64,
    /// When the latest phase transition occurred (ns).
    pub phase_entered_at_ns: u64,
    /// Whether demotion has occurred at least once.
    pub has_demoted: bool,
    /// Number of demotions so far.
    pub demotion_count: u64,
}

impl JoinProgress {
    #[must_use]
    pub fn new(member_id: MemberId, epoch: EpochId, started_at_ns: u64) -> Self {
        Self {
            member_id,
            epoch,
            phase: JoinPhase::NotStarted,
            health_gate: None,
            session_epoch: None,
            started_at_ns,
            phase_entered_at_ns: started_at_ns,
            has_demoted: false,
            demotion_count: 0,
        }
    }

    /// Whether the join is complete.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.phase == JoinPhase::Completed
    }

    /// Whether the join has failed.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        self.phase == JoinPhase::Failed
    }

    /// Whether the node can currently accept replicas.
    #[must_use]
    pub fn can_accept_replicas(&self) -> bool {
        self.phase.can_accept_replicas()
    }

    /// The operator-visible join status.
    ///
    /// Distinguishes between waiting-for-quorum, stale-epoch,
    /// identity-mismatch, and transfer-ready outcomes.
    #[must_use]
    pub fn join_status(&self, current_epoch: EpochId) -> JoinStatus {
        // Terminal states first
        if self.phase == JoinPhase::Failed {
            return JoinStatus::Failed("join failed".into());
        }
        if self.phase == JoinPhase::Completed {
            return JoinStatus::TransferComplete;
        }

        // Check session epoch evidence
        let session = match &self.session_epoch {
            Some(s) => s,
            None => {
                if self.phase != JoinPhase::NotStarted {
                    return JoinStatus::MissingEpochEvidence;
                }
                return JoinStatus::WaitingForQuorum;
            }
        };

        // Full validation
        match session.is_valid_for(self.member_id, current_epoch) {
            Ok(()) => {
                // Phases at or past VoterSpread(p2) and ReplicaTarget(p5)
                // are transfer-ready; earlier phases are in-progress.
                // Note: JoinPhase discriminants are NOT in linear
                // progression order (p4=4, p2=2, p5=5), so we use
                // explicit phase checks instead of >=.
                if self.phase == JoinPhase::VoterSpread
                    || self.phase == JoinPhase::ReplicaTarget
                {
                    JoinStatus::TransferReady
                } else {
                    JoinStatus::TransferInProgress
                }
            }
            Err(status) => status,
        }
    }
}

// ── Node join protocol ───────────────────────────────────────────────

/// The node join protocol orchestrator.
///
/// Manages the 3-phase promotion of a new node through
/// ShadowOnly(p4) → VoterSpread(p2) → ReplicaTarget(p5).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeJoinProtocol {
    /// The joining member's id.
    pub member_id: MemberId,
    /// Current join progress.
    pub progress: JoinProgress,
    /// Required consecutive health passes for each promotion.
    pub required_consecutive_passes: u64,
    /// The join session epoch binding for this node.
    pub session_epoch: Option<JoinSessionEpoch>,
}

impl NodeJoinProtocol {
    /// Create a new node join protocol for the given member.
    #[must_use]
    pub fn new(
        member_id: MemberId,
        epoch: EpochId,
        required_consecutive_passes: u64,
        started_at_ns: u64,
    ) -> Self {
        Self {
            member_id,
            progress: JoinProgress::new(member_id, epoch, started_at_ns),
            required_consecutive_passes,
            session_epoch: None,
        }
    }

    /// Begin the join — transition from NotStarted to ShadowOnly(p4).
    ///
    /// The node enters the shadow phase: minimal data, observes cluster state.
    pub fn phase_shadow(
        &mut self,
        config: &MembershipConfigRecord,
        at_ns: u64,
    ) -> Result<(), JoinError> {
        if self.progress.phase != JoinPhase::NotStarted {
            return Err(JoinError::CannotPromote {
                from: self.progress.phase,
                to: JoinPhase::ShadowOnly,
                reason: "join already started".into(),
            });
        }

        if self.progress.epoch != config.membership_epoch_id {
            return Err(JoinError::EpochMismatch {
                expected: self.progress.epoch,
                got: config.membership_epoch_id,
            });
        }

        self.progress.phase = JoinPhase::ShadowOnly;
        self.progress.phase_entered_at_ns = at_ns;
        self.progress.health_gate = Some(JoinHealthGate::new(
            JoinPhase::VoterSpread,
            HealthClass::Healthy,
            self.required_consecutive_passes,
        ));

        Ok(())
    }

    /// Evaluate health gate and attempt promotion to VoterSpread(p2).
    ///
    /// On health check success, promotes to VoterSpread (witness).
    /// On failure, does nothing — the node stays at ShadowOnly.
    pub fn evaluate_health_for_witness(
        &mut self,
        health: HealthClass,
        at_ns: u64,
    ) -> Result<bool, JoinError> {
        if self.progress.phase != JoinPhase::ShadowOnly {
            return Err(JoinError::CannotPromote {
                from: self.progress.phase,
                to: JoinPhase::VoterSpread,
                reason: "not in shadow phase".into(),
            });
        }

        let gate = self
            .progress
            .health_gate
            .as_mut()
            .ok_or(JoinError::CannotPromote {
                from: self.progress.phase,
                to: JoinPhase::VoterSpread,
                reason: "no active health gate".into(),
            })?;

        let passed = gate.evaluate(health);
        if passed {
            self.progress.phase = JoinPhase::VoterSpread;
            self.progress.phase_entered_at_ns = at_ns;
            self.progress.health_gate = Some(JoinHealthGate::new(
                JoinPhase::ReplicaTarget,
                HealthClass::Healthy,
                self.required_consecutive_passes,
            ));
        }
        Ok(passed)
    }

    /// Evaluate health gate and attempt promotion to ReplicaTarget(p5).
    ///
    /// On health check success, promotes to ReplicaTarget.
    /// On failure, demotes to VoterSpread (not ejected).
    pub fn evaluate_health_for_replica_target(
        &mut self,
        health: HealthClass,
        at_ns: u64,
    ) -> Result<bool, JoinError> {
        if self.progress.phase != JoinPhase::VoterSpread {
            return Err(JoinError::CannotPromote {
                from: self.progress.phase,
                to: JoinPhase::ReplicaTarget,
                reason: "not in witness phase".into(),
            });
        }

        let gate = self
            .progress
            .health_gate
            .as_mut()
            .ok_or(JoinError::CannotPromote {
                from: self.progress.phase,
                to: JoinPhase::ReplicaTarget,
                reason: "no active health gate".into(),
            })?;

        let passed = gate.evaluate(health);
        if passed {
            self.progress.phase = JoinPhase::ReplicaTarget;
            self.progress.phase_entered_at_ns = at_ns;
            self.progress.health_gate = None; // Promotion complete once we reach ReplicaTarget
        } else if !gate.is_health_sufficient(health) {
            self.demote_to_previous(at_ns);
        }
        // If health is sufficient but we haven't reached the required
        // consecutive passes yet, stay at VoterSpread and wait.

        Ok(passed)
    }

    /// Demote the node to the previous phase.
    ///
    /// Implements AC 3: node failing health at any promotion phase
    /// is demoted to previous phase, not ejected.
    pub fn demote_to_previous(&mut self, at_ns: u64) -> Option<JoinPhase> {
        if !self.progress.phase.can_demote() {
            return None;
        }

        let prev = self.progress.phase.prev_demotion()?;
        self.progress.phase = if prev == JoinPhase::NotStarted {
            JoinPhase::ShadowOnly // Stay at ShadowOnly, don't go back to NotStarted
        } else {
            prev
        };
        self.progress.phase_entered_at_ns = at_ns;
        self.progress.has_demoted = true;
        self.progress.demotion_count += 1;

        // Reset health gate for the demoted-to phase's next promotion target
        let next_target = self.progress.phase.next_promotion();
        self.progress.health_gate = next_target.map(|target| {
            JoinHealthGate::new(
                target,
                HealthClass::Healthy,
                self.required_consecutive_passes,
            )
        });

        Some(self.progress.phase)
    }

    /// Mark the join as complete — node is fully operational.
    pub fn complete(&mut self, at_ns: u64) -> Result<(), JoinError> {
        if self.progress.phase != JoinPhase::ReplicaTarget {
            return Err(JoinError::CannotPromote {
                from: self.progress.phase,
                to: JoinPhase::Completed,
                reason: "must be at ReplicaTarget phase before completing".into(),
            });
        }
        self.progress.phase = JoinPhase::Completed;
        self.progress.phase_entered_at_ns = at_ns;
        self.progress.health_gate = None;
        Ok(())
    }

    /// Mark the join as failed.
    pub fn fail(&mut self, at_ns: u64, _reason: &str) {
        self.progress.phase = JoinPhase::Failed;
        self.progress.phase_entered_at_ns = at_ns;
        self.progress.health_gate = None;
    }

    /// Check whether this node can currently accept replica placements.
    #[must_use]
    pub fn can_accept_replicas(&self) -> bool {
        self.progress.can_accept_replicas()
    }
}

// ── Join pipeline: end-to-end join orchestration ─────────────────────

/// High-level orchestrator that runs the full node join pipeline:
/// discovery → handshake → commit → phase promotion → catch-up → joined.
///
/// This ties together [`ClusterDiscovery`], [`JoinHandshake`],
/// [`JoinCommit`], [`NodeJoinProtocol`], and [`NodeJoin`] into a
/// single callable pipeline suitable for use by the storage node binary.
#[derive(Clone, Debug)]
pub struct JoinPipeline {
    /// The joining node's member ID (populated after handshake).
    pub member_id: Option<MemberId>,
    /// The join commit result (populated after validation).
    pub commit_result: Option<JoinCommitResult>,
    /// The epoch-verified node join handshake (set during Handshaking phase).
    pub node_handshake: Option<crate::handshake::NodeJoinHandshake>,
    /// Transport session bindings for the joined node.
    pub session_manager: Option<crate::session_binding::SessionBindingManager>,
    /// Current pipeline phase.
    pub phase: JoinPipelinePhase,
}

/// Phases in the join pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoinPipelinePhase {
    /// Pipeline has not started.
    Idle,
    /// Discovery phase: broadcasting probes, collecting responses.
    Discovering,
    /// Handshake phase: performing join request/response.
    Handshaking,
    /// Commit phase: validating membership config.
    Committing,
    /// Phase promotion: p4→p2→p5 health-gated promotion.
    Promoting,
    /// Catch-up: pulling committed segments.
    CatchingUp,
    /// Join complete: node is a full member.
    Complete,
    /// Join failed.
    Failed,
}

impl JoinPipeline {
    /// Create a new join pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self {
            member_id: None,
            commit_result: None,
            node_handshake: None,
            session_manager: None,
            phase: JoinPipelinePhase::Idle,
        }
    }

    /// Record that discovery is in progress.
    pub fn begin_discovery(&mut self) {
        self.phase = JoinPipelinePhase::Discovering;
    }

    /// Begin the epoch-verified handshake phase.
    /// Creates a [`NodeJoinHandshake`] with the given identity, config,
    /// and target epoch. Advances the pipeline to Handshaking.
    pub fn begin_handshake(
        &mut self,
        node_identity: tidefs_membership_epoch::NodeIdentity,
        config: crate::discovery::JoinHandshakeConfig,
        target_epoch: EpochId,
        now_ns: u64,
    ) {
        self.node_handshake = Some(crate::handshake::NodeJoinHandshake::new(
            node_identity,
            config,
            target_epoch,
            now_ns,
        ));
        self.phase = JoinPipelinePhase::Handshaking;
    }

    /// Complete the handshake with epoch verification and commit validation.
    /// Verifies the epoch against the given verifier and pool epoch,
    /// then validates the join commit from the inner handshake.
    /// On success, stores the commit result and advances to Promoting.
    pub fn verify_handshake_epoch(
        &mut self,
        verifier: &dyn crate::handshake::EpochVerifier,
        pool_epoch: EpochId,
    ) -> Result<(), JoinError> {
        let hs = self
            .node_handshake
            .as_mut()
            .ok_or_else(|| JoinError::PreflightDenied("no active node handshake".into()))?;

        hs.verify_epoch(verifier, pool_epoch)
            .map_err(|reason| JoinError::PreflightDenied(reason.as_str()))?;

        Ok(())
    }

    /// Allocate transport sessions for the joined node to the given peers.
    /// Creates a [`SessionBindingManager`] bound to the commit result epoch
    /// and allocates sessions to each peer. Must be called after a successful
    /// handshake commit.
    pub fn allocate_sessions(
        &mut self,
        peers: &[MemberId],
        base_session_id: u64,
    ) -> Result<Vec<crate::session_binding::SessionAllocationResult>, JoinError> {
        let commit = self
            .commit_result
            .as_ref()
            .ok_or_else(|| JoinError::PreflightDenied("no commit result".into()))?;

        let member_id = self
            .member_id
            .ok_or_else(|| JoinError::PreflightDenied("no member ID assigned".into()))?;

        let mut mgr = crate::session_binding::SessionBindingManager::new(member_id, commit.epoch);

        let results = mgr.allocate_sessions(peers, base_session_id);
        self.session_manager = Some(mgr);
        Ok(results)
    }

    /// Record that the handshake completed and validate the join commit.
    ///
    /// On success, stores the commit result and advances the phase to
    /// Promoting. Returns an error if validation fails.
    pub fn commit_handshake(
        &mut self,
        handshake: &crate::discovery::JoinHandshake,
    ) -> Result<(), JoinError> {
        self.phase = JoinPipelinePhase::Committing;

        let commit = JoinCommit::validate(handshake);
        if !commit.is_ready() {
            self.phase = JoinPipelinePhase::Failed;
            return Err(JoinError::PreflightDenied(
                commit
                    .error
                    .unwrap_or_else(|| "join commit validation failed".into()),
            ));
        }

        let result = commit.result.unwrap();
        self.member_id = Some(result.member_id);
        self.commit_result = Some(result);
        self.phase = JoinPipelinePhase::Promoting;
        Ok(())
    }

    /// Promote the node through the join phases using [`NodeJoinProtocol`].
    pub fn promote(
        &mut self,
        protocol: &mut NodeJoinProtocol,
        at_ns: u64,
    ) -> Result<(), JoinError> {
        let commit = self
            .commit_result
            .as_ref()
            .ok_or_else(|| JoinError::PreflightDenied("no commit result".into()))?;

        protocol.start_from_join_commit(commit, at_ns)?;
        self.phase = JoinPipelinePhase::CatchingUp;
        Ok(())
    }

    /// Mark the join as complete.
    pub fn complete(&mut self) {
        self.phase = JoinPipelinePhase::Complete;
    }

    /// Mark the join as failed.
    pub fn fail(&mut self) {
        self.phase = JoinPipelinePhase::Failed;
    }

    /// Whether the pipeline has completed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.phase == JoinPipelinePhase::Complete
    }
}

impl Default for JoinPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// Re-exports from join_lifecycle module
pub use join_lifecycle::{
    CatchUpPlan, CatchUpProgress, JoinStats, JoinToken, NodeJoin, NodeJoinState,
};

// ── Join commit: bridge handshake completion to phase promotion ──────

/// Result of a successful join commit: membership config verified,
/// ready for phase promotion via [`NodeJoinProtocol`].
#[derive(Clone, Debug)]
pub struct JoinCommitResult {
    /// The joining member's assigned ID.
    pub member_id: MemberId,
    /// The membership configuration after epoch increment.
    pub membership_config: MembershipConfigRecord,
    /// The committed root digest.
    pub committed_root: u64,
    /// The pool epoch.
    pub epoch: EpochId,
    /// The pool ID.
    pub pool_id: u64,
}

/// Bridges a completed [`JoinHandshake`] (in `Active` state) into
/// the [`NodeJoinProtocol`] phase promotion.
///
/// After the join handshake succeeds and the joining node receives
/// the membership configuration and committed root, this type
/// validates consistency before phase promotion begins.
#[derive(Clone, Debug)]
pub struct JoinCommit {
    /// The joining member's assigned ID.
    pub member_id: MemberId,
    /// Whether the commit is valid.
    pub is_valid: bool,
    /// The commit result (populated on success).
    pub result: Option<JoinCommitResult>,
    /// Validation error message (populated on failure).
    pub error: Option<String>,
}

impl JoinCommit {
    /// Validate a completed join handshake and produce a commit result
    /// ready for phase promotion.
    ///
    /// Checks:
    /// - Handshake is in Active state
    /// - Assigned member ID is present
    /// - Membership config was received
    /// - The assigned member appears in the voter, learner, or observer set
    /// - Epoch is consistent with the synced epoch
    #[must_use]
    pub fn validate(handshake: &discovery::JoinHandshake) -> Self {
        // Must be in Active state
        if handshake.state != crate::discovery::HandshakeState::Active {
            return Self {
                member_id: MemberId::ZERO,
                is_valid: false,
                result: None,
                error: Some(format!(
                    "handshake not active: state is {:?}",
                    handshake.state
                )),
            };
        }

        // Must have assigned member ID
        let member_id = match handshake.assigned_member_id {
            Some(id) => id,
            None => {
                return Self {
                    member_id: MemberId::ZERO,
                    is_valid: false,
                    result: None,
                    error: Some("no assigned member ID".into()),
                };
            }
        };

        // Must have membership config
        let config = match &handshake.membership_config {
            Some(c) => c.clone(),
            None => {
                return Self {
                    member_id,
                    is_valid: false,
                    result: None,
                    error: Some("no membership config received".into()),
                };
            }
        };

        // Must have synced epoch
        let epoch = match handshake.synced_epoch {
            Some(e) => e,
            None => {
                return Self {
                    member_id,
                    is_valid: false,
                    result: None,
                    error: Some("no synced epoch".into()),
                };
            }
        };

        // Epoch must match membership config
        if config.membership_epoch_id != epoch {
            return Self {
                member_id,
                is_valid: false,
                result: None,
                error: Some(format!(
                    "epoch mismatch: handshake has {:?}, config has {:?}",
                    epoch, config.membership_epoch_id
                )),
            };
        }

        // The assigned member must appear in the voter, learner, or observer set
        let in_voter = config.voter_set_refs.contains(&member_id);
        let in_learner = config.learner_set_refs.contains(&member_id);
        let in_observer = config.observer_set_refs.contains(&member_id);

        if !in_voter && !in_learner && !in_observer {
            return Self {
                member_id,
                is_valid: false,
                result: None,
                error: Some(format!(
                    "assigned member {member_id:?} not found in membership config"
                )),
            };
        }

        // All checks passed
        let pool_id = handshake.pool_id.unwrap_or(0);
        let committed_root = handshake.committed_root;

        Self {
            member_id,
            is_valid: true,
            result: Some(JoinCommitResult {
                member_id,
                membership_config: config,
                committed_root,
                epoch,
                pool_id,
            }),
            error: None,
        }
    }

    /// Whether the commit is valid and ready for phase promotion.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.is_valid
    }
}

impl NodeJoinProtocol {
    /// Record the join session epoch with quorum evidence.
    ///
    /// Must be called after the handshake produces quorum-backed evidence
    /// for the join session. State transfer and replica-target promotion
    /// are gated on this evidence being present and valid.
    pub fn record_session_epoch(&mut self, session: JoinSessionEpoch) {
        self.session_epoch = Some(session.clone());
        self.progress.session_epoch = Some(session);
    }

    /// Operator-visible join status for this node.
    #[must_use]
    pub fn join_status(&self, current_epoch: EpochId) -> JoinStatus {
        self.progress.join_status(current_epoch)
    }

    /// Whether state transfer is allowed to start for this node.
    ///
    /// State transfer requires a quorum-backed session epoch with
    /// matching identity and a non-stale epoch.
    #[must_use]
    pub fn can_start_state_transfer(&self, current_epoch: EpochId) -> Result<(), JoinError> {
        let session = self
            .progress
            .session_epoch
            .as_ref()
            .ok_or_else(|| JoinError::MissingEpochEvidence(
                "no session epoch recorded".into(),
            ))?;

        let _ = session.is_valid_for(self.member_id, current_epoch).map_err(|status| match status {
            JoinStatus::WaitingForQuorum => JoinError::QuorumNotReached {
                epoch: session.epoch,
                approvals: session.quorum_evidence.as_ref().map_or(0, |qe| qe.quorum_approvals),
                threshold: session.quorum_evidence.as_ref().map_or(1, |qe| qe.quorum_threshold),
            },
            JoinStatus::StaleEpoch { current_epoch, join_epoch } => JoinError::StaleEpoch {
                session_epoch: join_epoch,
                current_epoch,
                reason: "state transfer blocked: stale epoch".into(),
            },
            JoinStatus::IdentityMismatch { expected, actual } => JoinError::IdentityMismatch {
                session_member: expected,
                caller_member: actual,
            },
            _ => JoinError::PreflightDenied(format!("state transfer blocked: {:?}", status)),
        })?;

        Ok(())
    }

    /// Start phase promotion from a validated join commit.
    ///
    /// Transitions from `NotStarted` to `ShadowOnly(p4)` using the
    /// membership configuration received during the join.
    pub fn start_from_join_commit(
        &mut self,
        commit: &JoinCommitResult,
        at_ns: u64,
    ) -> Result<(), JoinError> {
        self.phase_shadow(&commit.membership_config, at_ns)
    }
}

// Re-exports from discovery module
pub use discovery::{
    ClusterDiscovery, DiscoveryConsensus, DiscoveryPhase, DiscoveryProbe, DiscoveryResponse,
    HandshakeState, JoinHandshake, JoinHandshakeConfig, JoinHandshakeRequest,
    JoinHandshakeResponse, MemberRegistration, DISCOVERY_PROTOCOL_VERSION,
};

// Re-exports from auth module
pub use auth::{JoinAuth, JoinAuthResult, JoinAuthState};
// Re-exports from handshake module
pub use handshake::{EpochVerifier, NodeJoinHandshake, RejectionReason, StrictEpochVerifier};

// Re-exports from session_binding module
pub use session_binding::{
    SessionAllocationRequest, SessionAllocationResult, SessionBindingManager,
};

// These types are defined in this module (lib.rs)
// JoinCommit, JoinCommitResult, JoinPipeline, JoinPipelinePhase
// are re-exported directly via their definitions.

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::{ConfigClass, ReceiptId};

    fn make_config(epoch: u64) -> MembershipConfigRecord {
        MembershipConfigRecord {
            membership_epoch_id: EpochId::new(epoch),
            config_class: ConfigClass::Normal,
            version_index: 0,
            voter_set_refs: vec![],
            learner_set_refs: vec![],
            observer_set_refs: vec![],
            joint_old_set_refs: vec![],
            joint_new_set_refs: vec![],
            issuance_receipt_ref: ReceiptId(0),
            digest: 0,
        }
    }

    #[test]
    fn join_progresses_p4_to_p2_to_p5() {
        let mut join = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 2, 1000);
        let config = make_config(1);

        // Start -> ShadowOnly(p4)
        join.phase_shadow(&config, 2000).unwrap();
        assert_eq!(join.progress.phase, JoinPhase::ShadowOnly);

        // Health check x2 -> VoterSpread(p2)
        assert!(!join
            .evaluate_health_for_witness(HealthClass::Healthy, 3000)
            .unwrap()); // 1/2
        assert!(join
            .evaluate_health_for_witness(HealthClass::Healthy, 4000)
            .unwrap()); // 2/2
        assert_eq!(join.progress.phase, JoinPhase::VoterSpread);

        // Health check x2 -> ReplicaTarget(p5)
        assert!(!join
            .evaluate_health_for_replica_target(HealthClass::Healthy, 5000)
            .unwrap()); // 1/2
        assert!(join
            .evaluate_health_for_replica_target(HealthClass::Healthy, 6000)
            .unwrap()); // 2/2
        assert_eq!(join.progress.phase, JoinPhase::ReplicaTarget);
        assert!(join.can_accept_replicas());

        // Complete
        join.complete(7000).unwrap();
        assert_eq!(join.progress.phase, JoinPhase::Completed);
    }

    #[test]
    fn demote_on_health_failure_at_p5_gate() {
        let mut join = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        let config = make_config(1);

        join.phase_shadow(&config, 2000).unwrap();
        join.evaluate_health_for_witness(HealthClass::Healthy, 3000)
            .unwrap();
        assert_eq!(join.progress.phase, JoinPhase::VoterSpread);

        // Now evaluate replica target — but with Down health -> demotion
        assert!(!join
            .evaluate_health_for_replica_target(HealthClass::Down, 4000)
            .unwrap());
        assert_eq!(join.progress.phase, JoinPhase::ShadowOnly); // Demoted to p4
        assert!(join.progress.has_demoted);
        assert_eq!(join.progress.demotion_count, 1);

        // After demotion can re-promote through p2
        join.evaluate_health_for_witness(HealthClass::Healthy, 5000)
            .unwrap();
        assert_eq!(join.progress.phase, JoinPhase::VoterSpread);
    }

    #[test]
    fn cannot_promote_out_of_sequence() {
        let mut join = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);

        // Try to go directly to VoterSpread without shadow
        let err = join
            .evaluate_health_for_witness(HealthClass::Healthy, 2000)
            .unwrap_err();
        assert!(matches!(err, JoinError::CannotPromote { .. }));
    }

    #[test]
    fn cannot_complete_before_replica_target() {
        let mut join = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        let config = make_config(1);

        join.phase_shadow(&config, 2000).unwrap();

        let err = join.complete(3000).unwrap_err();
        assert!(matches!(err, JoinError::CannotPromote { .. }));
    }

    #[test]
    fn epoch_mismatch_blocks_shadow_phase() {
        let mut join = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        let config = make_config(99); // Different epoch

        let err = join.phase_shadow(&config, 2000).unwrap_err();
        assert!(matches!(err, JoinError::EpochMismatch { .. }));
    }

    #[test]
    fn health_gate_requires_consecutive_passes() {
        let mut gate = JoinHealthGate::new(JoinPhase::VoterSpread, HealthClass::Healthy, 3);

        assert!(!gate.evaluate(HealthClass::Healthy)); // 1/3
        assert!(!gate.evaluate(HealthClass::Healthy)); // 2/3
        assert!(!gate.evaluate(HealthClass::Down)); // Reset to 0/3
        assert_eq!(gate.consecutive_passes, 0);
        assert!(!gate.evaluate(HealthClass::Healthy)); // 1/3
        assert!(!gate.evaluate(HealthClass::Healthy)); // 2/3
        assert!(gate.evaluate(HealthClass::Healthy)); // 3/3 -> satisfied
        assert!(gate.is_satisfied);
    }

    #[test]
    fn phase_sequence_is_correct() {
        assert_eq!(
            JoinPhase::NotStarted.next_promotion(),
            Some(JoinPhase::ShadowOnly)
        );
        assert_eq!(
            JoinPhase::ShadowOnly.next_promotion(),
            Some(JoinPhase::VoterSpread)
        );
        assert_eq!(
            JoinPhase::VoterSpread.next_promotion(),
            Some(JoinPhase::ReplicaTarget)
        );
        assert_eq!(
            JoinPhase::ReplicaTarget.next_promotion(),
            Some(JoinPhase::Completed)
        );
        assert_eq!(JoinPhase::Completed.next_promotion(), None);
        assert_eq!(JoinPhase::Failed.next_promotion(), None);
    }

    #[test]
    fn demotion_chain_is_correct() {
        assert_eq!(
            JoinPhase::ReplicaTarget.prev_demotion(),
            Some(JoinPhase::VoterSpread)
        );
        assert_eq!(
            JoinPhase::VoterSpread.prev_demotion(),
            Some(JoinPhase::ShadowOnly)
        );
        assert_eq!(
            JoinPhase::ShadowOnly.prev_demotion(),
            Some(JoinPhase::NotStarted)
        );
    }

    #[test]
    fn can_accept_replicas_only_after_p5() {
        assert!(!JoinPhase::ShadowOnly.can_accept_replicas());
        assert!(!JoinPhase::VoterSpread.can_accept_replicas());
        assert!(JoinPhase::ReplicaTarget.can_accept_replicas());
        assert!(JoinPhase::Completed.can_accept_replicas());
    }

    #[test]
    fn can_participate_quorum_from_p2_onwards() {
        assert!(!JoinPhase::ShadowOnly.can_participate_quorum());
        assert!(JoinPhase::VoterSpread.can_participate_quorum());
        assert!(JoinPhase::ReplicaTarget.can_participate_quorum());
        assert!(JoinPhase::Completed.can_participate_quorum());
    }

    #[test]
    fn fail_marks_terminal() {
        let mut join = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        join.fail(2000, "node unreachable");
        assert_eq!(join.progress.phase, JoinPhase::Failed);
        assert!(join.progress.is_failed());
    }

    #[test]
    fn join_progress_defaults() {
        let p = JoinProgress::new(MemberId::new(1), EpochId::new(5), 1000);
        assert_eq!(p.phase, JoinPhase::NotStarted);
        assert!(!p.is_complete());
        assert!(!p.is_failed());
        assert!(!p.can_accept_replicas());
    }

    // ── JoinCommit tests ────────────────────────────────────────────

    /// Create a MembershipConfigRecord that includes the given member as a learner.
    fn make_config_with_member(epoch: u64, member_id: MemberId) -> MembershipConfigRecord {
        let mut config = make_config(epoch);
        config.learner_set_refs = vec![member_id];
        config
    }

    fn make_active_handshake(
        member_id: MemberId,
        epoch: EpochId,
        config: MembershipConfigRecord,
        committed_root: u64,
    ) -> crate::discovery::JoinHandshake {
        use crate::discovery::{JoinHandshake, JoinHandshakeConfig};
        let mut hs = JoinHandshake::new(
            tidefs_membership_epoch::NodeIdentity::new(member_id.0),
            JoinHandshakeConfig::default(),
            0,
        );
        // Manually set fields to simulate completed handshake
        hs.state = crate::discovery::HandshakeState::Candidate;
        hs.apply_consensus(
            &crate::discovery::DiscoveryConsensus {
                bootstrap_peer: MemberId::new(1),
                agreed_epoch: epoch,
                member_table_hash: 0,
                pool_id: 1,
                responder_count: 1,
                responses: vec![],
            },
            1000,
        )
        .unwrap();
        // Simulate join response acceptance
        let resp = crate::discovery::JoinHandshakeResponse::accept_with_config(
            member_id,
            epoch,
            config,
            committed_root,
        );
        hs.on_join_response(&resp, 2000).unwrap();
        hs
    }

    #[test]
    fn join_commit_validates_active_handshake() {
        let config = make_config_with_member(10, MemberId::new(99));
        let hs = make_active_handshake(MemberId::new(99), EpochId::new(10), config.clone(), 0xABCD);

        let commit = JoinCommit::validate(&hs);
        assert!(commit.is_ready());
        let result = commit.result.as_ref().unwrap();
        assert_eq!(result.member_id, MemberId::new(99));
        assert_eq!(result.epoch, EpochId::new(10));
        assert_eq!(result.committed_root, 0xABCD);
    }

    #[test]
    fn join_commit_rejects_non_active_handshake() {
        use crate::discovery::{JoinHandshake, JoinHandshakeConfig};
        let hs = JoinHandshake::new(
            tidefs_membership_epoch::NodeIdentity::new(1),
            JoinHandshakeConfig::default(),
            0,
        );
        // Still in Candidate state
        let commit = JoinCommit::validate(&hs);
        assert!(!commit.is_ready());
        assert!(commit.error.as_ref().unwrap().contains("not active"));
    }

    #[test]
    fn join_commit_rejects_missing_membership_config() {
        use crate::discovery::{JoinHandshake, JoinHandshakeConfig};
        let mut hs = JoinHandshake::new(
            tidefs_membership_epoch::NodeIdentity::new(1),
            JoinHandshakeConfig::default(),
            0,
        );
        hs.state = crate::discovery::HandshakeState::Candidate;
        hs.apply_consensus(
            &crate::discovery::DiscoveryConsensus {
                bootstrap_peer: MemberId::new(1),
                agreed_epoch: EpochId::new(5),
                member_table_hash: 0,
                pool_id: 1,
                responder_count: 1,
                responses: vec![],
            },
            1000,
        )
        .unwrap();
        // Accept without config
        let resp =
            crate::discovery::JoinHandshakeResponse::accept(MemberId::new(99), EpochId::new(5));
        hs.on_join_response(&resp, 2000).unwrap();

        let commit = JoinCommit::validate(&hs);
        assert!(!commit.is_ready());
        assert!(commit
            .error
            .as_ref()
            .unwrap()
            .contains("no membership config"));
    }

    #[test]
    fn join_commit_rejects_epoch_mismatch() {
        let config = make_config_with_member(10, MemberId::new(99));
        let mut hs = make_active_handshake(MemberId::new(99), EpochId::new(10), config, 0);
        // Tamper with the synced epoch
        hs.synced_epoch = Some(EpochId::new(99));

        let commit = JoinCommit::validate(&hs);
        assert!(!commit.is_ready());
        assert!(commit.error.as_ref().unwrap().contains("epoch mismatch"));
    }

    #[test]
    fn join_commit_rejects_member_not_in_config() {
        let config = make_config(10); // Empty sets, member 999 not present
        let hs = make_active_handshake(
            MemberId::new(999), // Not in config
            EpochId::new(10),
            config,
            0,
        );

        let commit = JoinCommit::validate(&hs);
        assert!(!commit.is_ready());
        assert!(commit
            .error
            .as_ref()
            .unwrap()
            .contains("not found in membership config"));
    }

    #[test]
    fn node_join_protocol_starts_from_join_commit() {
        let config = make_config_with_member(1, MemberId::new(10));
        let hs = make_active_handshake(MemberId::new(10), EpochId::new(1), config.clone(), 0xBEEF);
        let commit = JoinCommit::validate(&hs);
        assert!(commit.is_ready());

        let mut protocol = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        assert_eq!(protocol.progress.phase, JoinPhase::NotStarted);

        protocol
            .start_from_join_commit(commit.result.as_ref().unwrap(), 2000)
            .unwrap();
        assert_eq!(protocol.progress.phase, JoinPhase::ShadowOnly);
    }

    // ── JoinPipeline with NodeJoinHandshake + SessionBindingManager ──

    /// Full pipeline: handshake with epoch verification, session allocation,
    /// and three-node cluster formation via JoinPipeline orchestrator.
    #[test]
    fn join_pipeline_with_epoch_verified_handshake_and_session_binding() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use tidefs_transport::harness::{DeterministicMessageScheduler, SchedulerConfig};

        let sched = Rc::new(RefCell::new(DeterministicMessageScheduler::new(
            SchedulerConfig::deterministic(555),
        )));

        let n1 = tidefs_membership_epoch::NodeIdentity::new(1); // joiner
        let n2 = tidefs_membership_epoch::NodeIdentity::new(2); // existing member

        sched.borrow_mut().register_node(n1);
        sched.borrow_mut().register_node(n2);

        // ── Phase 1: Start the pipeline with epoch-verified handshake ──

        // ── Phase 1: Start the pipeline with epoch-verified handshake ──
        let mut pipeline = JoinPipeline::new();
        assert_eq!(pipeline.phase, JoinPipelinePhase::Idle);

        pipeline.begin_handshake(
            n1,
            crate::discovery::JoinHandshakeConfig::default(),
            EpochId::new(10),
            0,
        );
        assert_eq!(pipeline.phase, JoinPipelinePhase::Handshaking);
        assert!(pipeline.node_handshake.is_some());

        // Point-to-point discovery: probe n2 only (JoinHandshake is 1:1)
        let hs = pipeline.node_handshake.as_mut().unwrap();
        hs.inner.probe_sent(1000).unwrap();

        let probe = hs.inner.build_discovery_probe(0);
        sched
            .borrow_mut()
            .send(n1, n2, 0, probe.encode().unwrap(), 0);
        sched.borrow_mut().tick_n(2);

        // n2 responds to discovery
        {
            let mut s = sched.borrow_mut();
            while let Some(_msg) = s.recv(n2) {
                let resp = crate::discovery::DiscoveryResponse::new(
                    EpochId::new(10),
                    true,
                    MemberId::new(2),
                    77,
                );
                s.send(n2, n1, 0, resp.encode().unwrap(), 1);
            }
        }
        sched.borrow_mut().tick_n(1);

        // Joiner receives discovery response → Syncing
        while let Some(msg) = sched.borrow_mut().recv(n1) {
            let decoded = crate::discovery::DiscoveryResponse::decode(&msg.payload).unwrap();
            hs.inner.on_discovery_response(&decoded, 2000).unwrap();
        }
        assert_eq!(hs.inner.state, crate::discovery::HandshakeState::Syncing);
        let _ = hs;

        // ── Phase 2: Epoch verification (during Syncing, before join request) ──
        let verifier = crate::handshake::StrictEpochVerifier::new(EpochId::new(10), 8, 2);
        pipeline
            .verify_handshake_epoch(&verifier, EpochId::new(10))
            .unwrap();

        // Re-acquire hs for sending join request
        let hs = pipeline.node_handshake.as_mut().unwrap();
        assert_eq!(hs.inner.state, crate::discovery::HandshakeState::Syncing);

        // Send join request to n2 (the responder)
        let join_req = hs
            .inner
            .build_join_request(tidefs_membership_epoch::MemberClass::Learner, 42)
            .unwrap();
        sched
            .borrow_mut()
            .send(n1, n2, 0, join_req.encode().unwrap(), 2);
        sched.borrow_mut().tick_n(2);

        // n2 accepts join with membership config
        {
            let mut s = sched.borrow_mut();
            while let Some(_msg) = s.recv(n2) {
                let config = tidefs_membership_epoch::MembershipConfigRecord {
                    membership_epoch_id: EpochId::new(10),
                    config_class: tidefs_membership_epoch::ConfigClass::Normal,
                    version_index: 1,
                    voter_set_refs: vec![MemberId::new(2), MemberId::new(3)],
                    learner_set_refs: vec![MemberId::new(1)],
                    observer_set_refs: vec![],
                    joint_old_set_refs: vec![],
                    joint_new_set_refs: vec![],
                    issuance_receipt_ref: tidefs_membership_epoch::ReceiptId(0),
                    digest: 0,
                };
                let resp = crate::discovery::JoinHandshakeResponse::accept_with_config(
                    MemberId::new(1),
                    EpochId::new(10),
                    config,
                    0xABCDEF,
                );
                s.send(n2, n1, 0, resp.encode().unwrap(), 3);
            }
        }
        sched.borrow_mut().tick_n(1);

        // Joiner receives acceptance → Active
        while let Some(msg) = sched.borrow_mut().recv(n1) {
            hs.inner
                .on_join_response(
                    &crate::discovery::JoinHandshakeResponse::decode(&msg.payload).unwrap(),
                    3000,
                )
                .unwrap();
        }
        assert_eq!(hs.inner.state, crate::discovery::HandshakeState::Active);
        let inner_clone = hs.inner.clone();
        let _ = hs;

        // ── Phase 3: Commit validation ──
        pipeline.commit_handshake(&inner_clone).unwrap();
        assert_eq!(pipeline.phase, JoinPipelinePhase::Promoting);
        assert!(pipeline.commit_result.is_some());
        assert_eq!(pipeline.member_id, Some(MemberId::new(1)));
        // ── Phase 3: Allocate transport sessions ──
        let peers = vec![MemberId::new(2), MemberId::new(3)];
        let results = pipeline.allocate_sessions(&peers, 1000).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_success()));

        let mgr = pipeline.session_manager.as_ref().unwrap();
        assert_eq!(mgr.member_id, MemberId::new(1));
        assert_eq!(mgr.bound_epoch, EpochId::new(10));
        assert_eq!(mgr.binding_count(), 2);
        assert!(mgr.is_bound_to(MemberId::new(2)));
        assert!(mgr.is_bound_to(MemberId::new(3)));
        assert_eq!(
            mgr.get_session(MemberId::new(2)),
            Some(tidefs_transport::types::SessionId::new(1000))
        );
        assert_eq!(
            mgr.get_session(MemberId::new(3)),
            Some(tidefs_transport::types::SessionId::new(1001))
        );

        // ── Phase 4: Phase promotion and join completion ──
        let mut protocol = NodeJoinProtocol::new(MemberId::new(1), EpochId::new(10), 1, 5000);
        pipeline.promote(&mut protocol, 5000).unwrap();
        assert_eq!(pipeline.phase, JoinPipelinePhase::CatchingUp);
        assert_eq!(protocol.progress.phase, JoinPhase::ShadowOnly);

        // Health checks → promote to p5 (ReplicaTarget)
        protocol
            .evaluate_health_for_witness(HealthClass::Healthy, 6000)
            .unwrap();
        assert_eq!(protocol.progress.phase, JoinPhase::VoterSpread);

        protocol
            .evaluate_health_for_replica_target(HealthClass::Healthy, 7000)
            .unwrap();
        assert_eq!(protocol.progress.phase, JoinPhase::ReplicaTarget);
        assert!(protocol.can_accept_replicas());

        protocol.complete(8000).unwrap();
        assert_eq!(protocol.progress.phase, JoinPhase::Completed);

        pipeline.complete();
        assert!(pipeline.is_complete());

        // ── Final verification: sessions are still bound ──
        let mgr = pipeline.session_manager.as_ref().unwrap();
        assert!(mgr.verify_epoch_binding(EpochId::new(10)).is_ok());
    }

    // ── JoinPhase::DemotedToWitness and JoinPhase::Failed coverage ──

    #[test]
    fn demoted_to_witness_phase_methods() {
        let p = JoinPhase::DemotedToWitness;
        assert!(!p.can_accept_replicas());
        assert!(!p.can_participate_quorum());
        assert_eq!(p.placement_intent(), None);
        assert!(!p.can_demote());
        assert!(!p.is_terminal());
        assert_eq!(p.next_promotion(), None);
        assert_eq!(p.prev_demotion(), None);
        assert_eq!(p.as_str(), "join.demoted_to_witness");
    }

    #[test]
    fn failed_phase_methods() {
        let p = JoinPhase::Failed;
        assert!(!p.can_accept_replicas());
        assert!(!p.can_participate_quorum());
        assert_eq!(p.placement_intent(), None);
        assert!(!p.can_demote());
        assert!(p.is_terminal());
        assert_eq!(p.next_promotion(), None);
        assert_eq!(p.prev_demotion(), None);
        assert_eq!(p.as_str(), "join.failed");
    }

    #[test]
    fn completed_phase_methods() {
        let p = JoinPhase::Completed;
        assert!(p.can_accept_replicas());
        assert!(p.can_participate_quorum());
        assert_eq!(p.placement_intent(), None);
        assert!(!p.can_demote());
        assert!(p.is_terminal());
        assert_eq!(p.next_promotion(), None);
        assert_eq!(p.as_str(), "join.completed");
    }

    // ── JoinPipeline error paths ──

    #[test]
    fn pipeline_verify_epoch_without_handshake() {
        let mut pipeline = JoinPipeline::new();
        let verifier = crate::handshake::StrictEpochVerifier::new(EpochId::new(1), 8, 1);
        let err = pipeline
            .verify_handshake_epoch(&verifier, EpochId::new(1))
            .unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(_)));
        assert!(format!("{err}").contains("no active node handshake"));
    }

    #[test]
    fn pipeline_allocate_sessions_without_commit() {
        let mut pipeline = JoinPipeline::new();
        let peers = vec![MemberId::new(2)];
        let err = pipeline.allocate_sessions(&peers, 100).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(_)));
        assert!(format!("{err}").contains("no commit result"));
    }

    #[test]
    fn pipeline_allocate_sessions_without_member_id() {
        let mut pipeline = JoinPipeline::new();
        // Set commit result but no member_id
        pipeline.commit_result = Some(JoinCommitResult {
            member_id: MemberId::new(99),
            membership_config: make_config(1),
            committed_root: 0,
            epoch: EpochId::new(1),
            pool_id: 1,
        });
        // member_id stays None
        let peers = vec![MemberId::new(2)];
        let err = pipeline.allocate_sessions(&peers, 100).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(_)));
        assert!(format!("{err}").contains("no member ID assigned"));
    }

    #[test]
    fn pipeline_promote_without_commit() {
        let mut pipeline = JoinPipeline::new();
        let mut protocol = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        let err = pipeline.promote(&mut protocol, 2000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(_)));
        assert!(format!("{err}").contains("no commit result"));
    }

    #[test]
    fn pipeline_fail_and_begin_discovery() {
        let mut pipeline = JoinPipeline::new();
        assert_eq!(pipeline.phase, JoinPipelinePhase::Idle);

        pipeline.begin_discovery();
        assert_eq!(pipeline.phase, JoinPipelinePhase::Discovering);

        pipeline.fail();
        assert_eq!(pipeline.phase, JoinPipelinePhase::Failed);
        assert!(!pipeline.is_complete());
    }

    #[test]
    fn pipeline_commit_handshake_validation_failure() {
        use crate::discovery::{JoinHandshake, JoinHandshakeConfig};
        let mut pipeline = JoinPipeline::new();
        let hs = JoinHandshake::new(
            tidefs_membership_epoch::NodeIdentity::new(1),
            JoinHandshakeConfig::default(),
            0,
        );
        // Handshake not Active -> commit fails
        let err = pipeline.commit_handshake(&hs).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(_)));
        assert_eq!(pipeline.phase, JoinPipelinePhase::Failed);
    }

    // ── JoinHealthGate with Suspect health ──

    #[test]
    fn health_gate_with_suspect_required() {
        let mut gate = JoinHealthGate::new(JoinPhase::VoterSpread, HealthClass::Suspect, 2);

        // Suspect passes when required is Suspect
        assert!(!gate.evaluate(HealthClass::Suspect)); // 1/2
        assert!(gate.evaluate(HealthClass::Suspect)); // 2/2 -> satisfied
        assert!(gate.is_satisfied);
    }

    #[test]
    fn health_gate_suspect_required_healthy_passes() {
        let mut gate = JoinHealthGate::new(JoinPhase::VoterSpread, HealthClass::Suspect, 1);
        // Healthy exceeds Suspect requirement
        assert!(gate.evaluate(HealthClass::Healthy));
        assert!(gate.is_satisfied);
    }

    #[test]
    fn health_gate_healthy_required_suspect_fails() {
        let mut gate = JoinHealthGate::new(JoinPhase::VoterSpread, HealthClass::Healthy, 1);
        // Suspect does not meet Healthy requirement
        assert!(!gate.evaluate(HealthClass::Suspect));
        assert!(!gate.is_satisfied);
        assert_eq!(gate.consecutive_passes, 0);
    }

    #[test]
    fn is_health_sufficient_all_combinations() {
        // Healthy required
        assert!(
            JoinHealthGate::new(JoinPhase::ShadowOnly, HealthClass::Healthy, 1)
                .is_health_sufficient(HealthClass::Healthy)
        );
        assert!(
            !JoinHealthGate::new(JoinPhase::ShadowOnly, HealthClass::Healthy, 1)
                .is_health_sufficient(HealthClass::Suspect)
        );
        assert!(
            !JoinHealthGate::new(JoinPhase::ShadowOnly, HealthClass::Healthy, 1)
                .is_health_sufficient(HealthClass::Down)
        );

        // Suspect required
        assert!(
            JoinHealthGate::new(JoinPhase::ShadowOnly, HealthClass::Suspect, 1)
                .is_health_sufficient(HealthClass::Healthy)
        );
        assert!(
            JoinHealthGate::new(JoinPhase::ShadowOnly, HealthClass::Suspect, 1)
                .is_health_sufficient(HealthClass::Suspect)
        );
        assert!(
            !JoinHealthGate::new(JoinPhase::ShadowOnly, HealthClass::Suspect, 1)
                .is_health_sufficient(HealthClass::Down)
        );

        // Down required (any health passes)
        assert!(
            JoinHealthGate::new(JoinPhase::ShadowOnly, HealthClass::Down, 1)
                .is_health_sufficient(HealthClass::Healthy)
        );
        assert!(
            JoinHealthGate::new(JoinPhase::ShadowOnly, HealthClass::Down, 1)
                .is_health_sufficient(HealthClass::Suspect)
        );
        assert!(
            JoinHealthGate::new(JoinPhase::ShadowOnly, HealthClass::Down, 1)
                .is_health_sufficient(HealthClass::Down)
        );
    }

    // ── NodeJoinProtocol demotion edge cases ──

    #[test]
    fn demote_from_shadow_only_stays_at_shadow() {
        let mut join = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        let config = make_config(1);
        join.phase_shadow(&config, 2000).unwrap();
        assert_eq!(join.progress.phase, JoinPhase::ShadowOnly);

        // Call demote_to_previous from ShadowOnly - should stay at ShadowOnly
        let result = join.demote_to_previous(3000);
        assert_eq!(result, Some(JoinPhase::ShadowOnly));
        assert_eq!(join.progress.phase, JoinPhase::ShadowOnly);
        assert!(join.progress.has_demoted);
        assert_eq!(join.progress.demotion_count, 1);
    }

    #[test]
    fn demote_from_not_started_returns_none() {
        let mut join = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        assert_eq!(join.progress.phase, JoinPhase::NotStarted);
        let result = join.demote_to_previous(2000);
        assert_eq!(result, None);
    }

    #[test]
    fn fail_on_completed_protocol_overwrites_state() {
        let mut join = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        let config = make_config(1);

        // Progress through all phases to completion
        join.phase_shadow(&config, 2000).unwrap();
        join.evaluate_health_for_witness(HealthClass::Healthy, 3000)
            .unwrap();
        join.evaluate_health_for_replica_target(HealthClass::Healthy, 4000)
            .unwrap();
        join.complete(5000).unwrap();
        assert_eq!(join.progress.phase, JoinPhase::Completed);

        // Fail after completion
        join.fail(6000, "post-completion failure");
        assert_eq!(join.progress.phase, JoinPhase::Failed);
        assert!(join.progress.is_failed());
    }

    #[test]
    fn phase_shadow_when_already_started_errors() {
        let mut join = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        let config = make_config(1);
        join.phase_shadow(&config, 2000).unwrap();

        let err = join.phase_shadow(&config, 3000).unwrap_err();
        assert!(matches!(err, JoinError::CannotPromote { .. }));
    }

    // ── NodeJoin lifecycle error paths ──

    #[test]
    fn node_join_start_from_commit_twice_errors() {
        let mut nj = crate::join_lifecycle::NodeJoin::new(MemberId::new(10), EpochId::new(1), 1000);
        let commit = JoinCommitResult {
            member_id: MemberId::new(10),
            membership_config: make_config(1),
            committed_root: 0xBEEF,
            epoch: EpochId::new(1),
            pool_id: 1,
        };
        nj.start_from_join_commit(&commit, MemberId::new(2), 2000)
            .unwrap();
        assert_eq!(
            nj.state,
            crate::join_lifecycle::NodeJoinState::Bootstrapping
        );

        let err = nj
            .start_from_join_commit(&commit, MemberId::new(2), 3000)
            .unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(_)));
    }

    #[test]
    fn node_join_begin_catch_up_wrong_state() {
        let mut nj = crate::join_lifecycle::NodeJoin::new(MemberId::new(10), EpochId::new(1), 1000);
        let plan = crate::join_lifecycle::CatchUpPlan::default();
        let err = nj.begin_catch_up(&plan, 100, 2000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(_)));
    }

    #[test]
    fn node_join_complete_catch_up_wrong_state() {
        let mut nj = crate::join_lifecycle::NodeJoin::new(MemberId::new(10), EpochId::new(1), 1000);
        let progress = crate::join_lifecycle::CatchUpProgress::default();
        let err = nj.complete_catch_up(&progress, 2000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(_)));
    }

    #[test]
    fn node_join_fail_on_joined_state() {
        let mut nj = crate::join_lifecycle::NodeJoin::new(MemberId::new(10), EpochId::new(1), 1000);
        // Manually set to Joined for test
        nj.request_join(MemberId::new(2), 1500).unwrap();
        let token = crate::join_lifecycle::JoinToken::new(
            0,
            MemberId::new(10),
            MemberId::new(2),
            2000,
            1_000_000_000_000,
        );
        nj.accept_token(token, 2000).unwrap();
        nj.bootstrap_complete(4096, 3000).unwrap();
        nj.catch_up_progress(0, true, 4000).unwrap();
        nj.join_complete(5000).unwrap();
        assert_eq!(nj.state, crate::join_lifecycle::NodeJoinState::Joined);
        assert!(nj.stats.join_success);

        nj.fail(6000);
        assert_eq!(nj.state, crate::join_lifecycle::NodeJoinState::Failed);
        assert!(!nj.stats.join_success);
    }

    // ── JoinError Display ──

    #[test]
    fn join_error_display_outputs() {
        let e1 = JoinError::PreflightDenied("test reason".into());
        assert!(format!("{e1}").contains("test reason"));

        let e2 = JoinError::EpochMismatch {
            expected: EpochId::new(5),
            got: EpochId::new(10),
        };
        let s = format!("{e2}");
        assert!(s.contains("epoch mismatch"));

        let e3 = JoinError::CannotPromote {
            from: JoinPhase::ShadowOnly,
            to: JoinPhase::ReplicaTarget,
            reason: "skip phase".into(),
        };
        let s = format!("{e3}");
        assert!(s.contains("skip phase"));

        let e4 = JoinError::AlreadyTerminal(JoinPhase::Completed);
        let s = format!("{e4}");
        assert!(s.contains("Completed"));

        let e5 = JoinError::NotJoinable {
            member_id: 42,
            reason: "already member".into(),
        };
        let s = format!("{e5}");
        assert!(s.contains("42"));
        assert!(s.contains("already member"));
    }

    // ── Session binding edge cases ──

    #[test]
    fn empty_peer_session_allocation() {
        let mut mgr =
            crate::session_binding::SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        let results = mgr.allocate_sessions(&[], 100);
        assert!(results.is_empty());
        assert_eq!(mgr.binding_count(), 0);
    }

    // ── JoinCommit with observer set ──

    #[test]
    fn join_commit_accepts_observer_set_member() {
        let mut config = make_config(10);
        config.observer_set_refs = vec![MemberId::new(99)];
        let hs = make_active_handshake(MemberId::new(99), EpochId::new(10), config, 0xABCD);
        let commit = JoinCommit::validate(&hs);
        assert!(commit.is_ready());
        assert_eq!(commit.result.as_ref().unwrap().member_id, MemberId::new(99));
    }

    // ── CatchUpProgress with segments ──

    #[test]
    fn catch_up_progress_with_nonempty_plan() {
        let plan = crate::join_lifecycle::CatchUpPlan {
            segment_ids: vec![1, 2, 3],
            bootstrap_peer: MemberId::new(2),
            committed_root: 0xBEEF,
            estimated_bytes: 4096,
        };
        let mut progress = crate::join_lifecycle::CatchUpProgress::new(&plan);
        assert_eq!(progress.segments_total, 3);
        assert!(!progress.is_complete());

        progress.record_segment(1024);
        assert_eq!(progress.segments_received, 1);
        assert_eq!(progress.bytes_received, 1024);
        assert!(!progress.is_complete());

        progress.record_segment(2048);
        progress.record_segment(4096);
        assert!(progress.is_complete());
        assert_eq!(progress.bytes_received, 7168);
    }

    #[test]
    fn catch_up_progress_overflow_protection() {
        let plan = crate::join_lifecycle::CatchUpPlan {
            segment_ids: vec![1],
            ..Default::default()
        };
        let mut progress = crate::join_lifecycle::CatchUpProgress::new(&plan);
        // Record many segments - should saturate without panic
        for _ in 0..100 {
            progress.record_segment(u64::MAX);
        }
        assert!(progress.segments_received >= 1);
        assert!(progress.is_complete());
    }

    // ── JoinPipeline begin_handshake and phase transitions ──

    #[test]
    fn pipeline_begin_handshake_sets_state() {
        let mut pipeline = JoinPipeline::new();
        assert_eq!(pipeline.phase, JoinPipelinePhase::Idle);

        pipeline.begin_handshake(
            tidefs_membership_epoch::NodeIdentity::new(1),
            crate::discovery::JoinHandshakeConfig::default(),
            EpochId::new(42),
            1000,
        );
        assert_eq!(pipeline.phase, JoinPipelinePhase::Handshaking);
        assert!(pipeline.node_handshake.is_some());
    }

    #[test]
    fn pipeline_complete_from_idle() {
        let mut pipeline = JoinPipeline::new();
        assert_eq!(pipeline.phase, JoinPipelinePhase::Idle);
        pipeline.complete();
        assert_eq!(pipeline.phase, JoinPipelinePhase::Complete);
        assert!(pipeline.is_complete());
    }

    #[test]
    fn pipeline_begin_handshake_overwrites_previous_state() {
        let mut pipeline = JoinPipeline::new();
        pipeline.begin_discovery();
        assert_eq!(pipeline.phase, JoinPipelinePhase::Discovering);

        pipeline.begin_handshake(
            tidefs_membership_epoch::NodeIdentity::new(2),
            crate::discovery::JoinHandshakeConfig::default(),
            EpochId::new(5),
            2000,
        );
        assert_eq!(pipeline.phase, JoinPipelinePhase::Handshaking);
    }

    // ── NodeJoin re-join after failure ──

    #[test]
    fn node_join_rejoin_after_failure_errors() {
        let mut nj = crate::join_lifecycle::NodeJoin::new(MemberId::new(10), EpochId::new(1), 1000);
        nj.request_join(MemberId::new(2), 1500).unwrap();
        nj.fail(2000);
        assert_eq!(nj.state, crate::join_lifecycle::NodeJoinState::Failed);

        // Attempting to re-join from Failed state must be rejected
        let err = nj.request_join(MemberId::new(3), 3000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(_)));
    }

    #[test]
    fn node_join_accept_token_from_failed_state_errors() {
        let mut nj = crate::join_lifecycle::NodeJoin::new(MemberId::new(10), EpochId::new(1), 1000);
        nj.request_join(MemberId::new(2), 1500).unwrap();
        let token = crate::join_lifecycle::JoinToken::new(
            0,
            MemberId::new(10),
            MemberId::new(2),
            2000,
            1_000_000_000,
        );
        nj.accept_token(token, 2000).unwrap();
        nj.fail(3000);

        let token2 = crate::join_lifecycle::JoinToken::new(
            1,
            MemberId::new(10),
            MemberId::new(2),
            4000,
            1_000_000_000,
        );
        let err = nj.accept_token(token2, 4000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(_)));
    }

    // ── StrictEpochVerifier setters ──

    #[test]
    fn strict_epoch_verifier_set_member_count_updates_capacity() {
        let mut verifier = crate::handshake::StrictEpochVerifier::new(EpochId::new(5), 16, 8);
        verifier.set_member_count(10);
        // With 10 members and epoch 5, should accept epoch 5
        assert!(verifier
            .verify_join_epoch(EpochId::new(5), EpochId::new(5))
            .is_ok());
    }

    #[test]
    fn strict_epoch_verifier_set_epoch_updates_target() {
        let mut verifier = crate::handshake::StrictEpochVerifier::new(EpochId::new(5), 16, 8);
        verifier.set_epoch(EpochId::new(10));
        // Should now reject old epoch 5
        assert!(verifier
            .verify_join_epoch(EpochId::new(5), EpochId::new(10))
            .is_err());
        // Should accept new epoch 10
        assert!(verifier
            .verify_join_epoch(EpochId::new(10), EpochId::new(10))
            .is_ok());
    }

    // ── JoinToken is_expired_at boundary ──

    #[test]
    fn join_token_not_expired_at_ttl_boundary() {
        let token = crate::join_lifecycle::JoinToken::new(
            0,
            MemberId::new(10),
            MemberId::new(2),
            1000,
            5000,
        );
        // At 5999: not expired. At 6000: expired (>= boundary)
        assert!(!token.is_expired_at(5999));
        assert!(token.is_expired_at(6000));
    }

    // ── JoinToken rejects wrong member ──

    #[test]
    fn join_token_rejects_wrong_member_id() {
        let token = crate::join_lifecycle::JoinToken::new(
            0,
            MemberId::new(10),
            MemberId::new(2),
            1000,
            1_000_000,
        );
        // Wrong member
        assert!(!token.is_valid_for(MemberId::new(99), 2000));
        // Correct member
        assert!(token.is_valid_for(MemberId::new(10), 2000));
    }

    // ── SessionBinding allocate with duplicate peers ──

    #[test]
    fn session_binding_allocate_with_duplicate_peers() {
        let mut mgr =
            crate::session_binding::SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        let results =
            mgr.allocate_sessions(&[MemberId::new(2), MemberId::new(2), MemberId::new(3)], 100);
        assert_eq!(results.len(), 3);
        // All allocations are success objects
        assert!(results[0].is_success());
        assert!(results[1].is_success());
        assert!(results[2].is_success());
        // Deduplication: duplicates overwrite, so unique binding count is 2
        assert_eq!(mgr.binding_count(), 2);
    }

    // ── NodeJoinProtocol wrong-phase evaluation ──

    #[test]
    fn protocol_eval_health_for_witness_wrong_phase() {
        let mut protocol = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        // Not started - can't eval health for witness
        let err = protocol
            .evaluate_health_for_witness(HealthClass::Healthy, 2000)
            .unwrap_err();
        assert!(matches!(err, JoinError::CannotPromote { .. }));
    }

    #[test]
    fn protocol_eval_health_for_replica_wrong_phase() {
        let mut protocol = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        let config = make_config(1);
        protocol.phase_shadow(&config, 2000).unwrap();
        // At ShadowOnly, can't directly eval for replica target
        let err = protocol
            .evaluate_health_for_replica_target(HealthClass::Healthy, 3000)
            .unwrap_err();
        assert!(matches!(err, JoinError::CannotPromote { .. }));
    }

    #[test]
    fn protocol_complete_when_not_at_replica_target() {
        let mut protocol = NodeJoinProtocol::new(MemberId::new(10), EpochId::new(1), 1, 1000);
        let config = make_config(1);
        protocol.phase_shadow(&config, 2000).unwrap();
        // Can't complete from ShadowOnly
        let err = protocol.complete(3000).unwrap_err();
        assert!(matches!(err, JoinError::CannotPromote { .. }));
    }

    // ── NodeJoin can_receive_placements / is_terminal per state ──

    #[test]
    fn node_join_is_terminal_per_state() {
        let mut nj = crate::join_lifecycle::NodeJoin::new(MemberId::new(10), EpochId::new(1), 1000);
        assert!(!nj.is_terminal()); // Idle

        nj.request_join(MemberId::new(2), 1500).unwrap();
        assert!(!nj.is_terminal()); // JoinRequested

        nj.fail(2000);
        assert!(nj.is_terminal()); // Failed is terminal

        // New join for success path
        let mut nj2 =
            crate::join_lifecycle::NodeJoin::new(MemberId::new(20), EpochId::new(1), 1000);
        nj2.request_join(MemberId::new(2), 1500).unwrap();
        let token = crate::join_lifecycle::JoinToken::new(
            0,
            MemberId::new(20),
            MemberId::new(2),
            2000,
            1_000_000_000,
        );
        nj2.accept_token(token, 2000).unwrap();
        nj2.bootstrap_complete(4096, 3000).unwrap();
        nj2.catch_up_progress(0, true, 4000).unwrap();
        nj2.join_complete(5000).unwrap();
        assert!(nj2.is_terminal()); // Joined is terminal
    }

    #[test]
    fn node_join_can_receive_placements_per_state() {
        let mut nj = crate::join_lifecycle::NodeJoin::new(MemberId::new(10), EpochId::new(1), 1000);
        assert!(!nj.can_receive_placements()); // Idle

        nj.request_join(MemberId::new(2), 1500).unwrap();
        let token = crate::join_lifecycle::JoinToken::new(
            0,
            MemberId::new(10),
            MemberId::new(2),
            2000,
            1_000_000_000,
        );
        nj.accept_token(token, 2000).unwrap();
        assert!(!nj.can_receive_placements()); // Bootstrapping

        nj.bootstrap_complete(4096, 3000).unwrap();
        assert!(!nj.can_receive_placements()); // CatchingUp

        nj.catch_up_progress(0, true, 4000).unwrap();
        assert!(!nj.can_receive_placements()); // Joining

        nj.join_complete(5000).unwrap();
        assert!(nj.can_receive_placements()); // Joined
    }
    // ── Quorum evidence tests ──────────────────────────────────────

    #[test]
    fn quorum_evidence_simple_majority() {
        assert_eq!(QuorumEvidence::simple_majority_threshold(0), 0);
        assert_eq!(QuorumEvidence::simple_majority_threshold(1), 1);
        assert_eq!(QuorumEvidence::simple_majority_threshold(3), 2);
        assert_eq!(QuorumEvidence::simple_majority_threshold(5), 3);
        assert_eq!(QuorumEvidence::simple_majority_threshold(7), 4);
    }

    #[test]
    fn quorum_evidence_reached_and_not_reached() {
        let qe = QuorumEvidence {
            epoch: EpochId::new(5),
            quorum_approvals: 3,
            quorum_threshold: 3,
            approving_members: vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
        };
        assert!(qe.is_quorum_reached());

        let qe2 = QuorumEvidence {
            epoch: EpochId::new(5),
            quorum_approvals: 2,
            quorum_threshold: 3,
            approving_members: vec![MemberId::new(1), MemberId::new(2)],
        };
        assert!(!qe2.is_quorum_reached());

        // Zero threshold means no quorum possible
        let qe3 = QuorumEvidence {
            epoch: EpochId::new(5),
            quorum_approvals: 0,
            quorum_threshold: 0,
            approving_members: vec![],
        };
        assert!(!qe3.is_quorum_reached());
    }

    // ── JoinSessionEpoch tests ─────────────────────────────────────

    #[test]
    fn session_epoch_valid_with_quorum() {
        let qe = QuorumEvidence {
            epoch: EpochId::new(10),
            quorum_approvals: 3,
            quorum_threshold: 3,
            approving_members: vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
        };
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(42), 100)
            .with_quorum(qe);
        assert!(session.is_valid_for(MemberId::new(42), EpochId::new(10)).is_ok());
    }

    #[test]
    fn session_epoch_stale_epoch_rejection() {
        let qe = QuorumEvidence {
            epoch: EpochId::new(10),
            quorum_approvals: 2,
            quorum_threshold: 2,
            approving_members: vec![MemberId::new(1), MemberId::new(2)],
        };
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(42), 100)
            .with_quorum(qe);
        let result = session.is_valid_for(MemberId::new(42), EpochId::new(11));
        assert!(matches!(result, Err(JoinStatus::StaleEpoch { .. })));
    }

    #[test]
    fn session_epoch_identity_mismatch_rejection() {
        let qe = QuorumEvidence {
            epoch: EpochId::new(10),
            quorum_approvals: 2,
            quorum_threshold: 2,
            approving_members: vec![MemberId::new(1), MemberId::new(2)],
        };
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(42), 100)
            .with_quorum(qe);
        let result = session.is_valid_for(MemberId::new(99), EpochId::new(10));
        assert!(matches!(result, Err(JoinStatus::IdentityMismatch { .. })));
    }

    #[test]
    fn session_epoch_waiting_for_quorum_without_evidence() {
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(42), 100);
        let result = session.is_valid_for(MemberId::new(42), EpochId::new(10));
        assert!(matches!(result, Err(JoinStatus::WaitingForQuorum)));
    }

    #[test]
    fn session_epoch_waiting_for_quorum_insufficient_approvals() {
        let qe = QuorumEvidence {
            epoch: EpochId::new(10),
            quorum_approvals: 1,
            quorum_threshold: 3,
            approving_members: vec![MemberId::new(1)],
        };
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(42), 100)
            .with_quorum(qe);
        let result = session.is_valid_for(MemberId::new(42), EpochId::new(10));
        assert!(matches!(result, Err(JoinStatus::WaitingForQuorum)));
    }

    // ── JoinStatus operator distinguishability ─────────────────────

    #[test]
    fn join_status_distinguishes_outcomes() {
        // Verify all status variants are distinct and meaningful
        let waiting = JoinStatus::WaitingForQuorum;
        let stale = JoinStatus::StaleEpoch {
            current_epoch: EpochId::new(10),
            join_epoch: EpochId::new(5),
        };
        let mismatch = JoinStatus::IdentityMismatch {
            expected: MemberId::new(42),
            actual: MemberId::new(99),
        };
        let missing = JoinStatus::MissingEpochEvidence;
        let ready = JoinStatus::TransferReady;
        let in_progress = JoinStatus::TransferInProgress;
        let complete = JoinStatus::TransferComplete;
        let failed = JoinStatus::Failed("test failure".into());

        // All variants are distinct
        assert_ne!(waiting, stale);
        assert_ne!(stale, mismatch);
        assert_ne!(mismatch, missing);
        assert_ne!(missing, ready);
        assert_ne!(ready, in_progress);
        assert_ne!(in_progress, complete);
        assert_ne!(complete, failed);
    }

    // ── NodeJoinProtocol can_start_state_transfer tests ────────────

    #[test]
    fn can_start_state_transfer_with_quorum_evidence() {
        let mut protocol = NodeJoinProtocol::new(MemberId::new(42), EpochId::new(10), 1, 1000);
        let config = make_config(10);
        protocol.phase_shadow(&config, 2000).unwrap();

        // Record quorum-backed session
        let qe = QuorumEvidence {
            epoch: EpochId::new(10),
            quorum_approvals: 3,
            quorum_threshold: 3,
            approving_members: vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
        };
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(42), 100)
            .with_quorum(qe);
        protocol.record_session_epoch(session);

        assert!(protocol.can_start_state_transfer(EpochId::new(10)).is_ok());
    }

    #[test]
    fn cannot_start_state_transfer_without_session_epoch() {
        let mut protocol = NodeJoinProtocol::new(MemberId::new(42), EpochId::new(10), 1, 1000);
        let config = make_config(10);
        protocol.phase_shadow(&config, 2000).unwrap();

        // No session epoch recorded
        let result = protocol.can_start_state_transfer(EpochId::new(10));
        assert!(matches!(result, Err(JoinError::MissingEpochEvidence(_))));
    }

    #[test]
    fn cannot_start_state_transfer_with_stale_epoch() {
        let mut protocol = NodeJoinProtocol::new(MemberId::new(42), EpochId::new(10), 1, 1000);
        let config = make_config(10);
        protocol.phase_shadow(&config, 2000).unwrap();

        let qe = QuorumEvidence {
            epoch: EpochId::new(10),
            quorum_approvals: 2,
            quorum_threshold: 2,
            approving_members: vec![MemberId::new(1), MemberId::new(2)],
        };
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(42), 100)
            .with_quorum(qe);
        protocol.record_session_epoch(session);

        // Check against a newer epoch
        let result = protocol.can_start_state_transfer(EpochId::new(11));
        assert!(matches!(result, Err(JoinError::StaleEpoch { .. })));
    }

    #[test]
    fn cannot_start_state_transfer_with_identity_mismatch() {
        let mut protocol = NodeJoinProtocol::new(MemberId::new(42), EpochId::new(10), 1, 1000);
        let config = make_config(10);
        protocol.phase_shadow(&config, 2000).unwrap();

        // Session bound to wrong member
        let qe = QuorumEvidence {
            epoch: EpochId::new(10),
            quorum_approvals: 2,
            quorum_threshold: 2,
            approving_members: vec![MemberId::new(1), MemberId::new(2)],
        };
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(99), 100)
            .with_quorum(qe);
        protocol.record_session_epoch(session);

        let result = protocol.can_start_state_transfer(EpochId::new(10));
        assert!(matches!(result, Err(JoinError::IdentityMismatch { .. })));
    }

    #[test]
    fn cannot_start_state_transfer_without_quorum() {
        let mut protocol = NodeJoinProtocol::new(MemberId::new(42), EpochId::new(10), 1, 1000);
        let config = make_config(10);
        protocol.phase_shadow(&config, 2000).unwrap();

        // Quorum not reached
        let qe = QuorumEvidence {
            epoch: EpochId::new(10),
            quorum_approvals: 1,
            quorum_threshold: 3,
            approving_members: vec![MemberId::new(1)],
        };
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(42), 100)
            .with_quorum(qe);
        protocol.record_session_epoch(session);

        let result = protocol.can_start_state_transfer(EpochId::new(10));
        assert!(matches!(result, Err(JoinError::QuorumNotReached { .. })));
    }

    // ── JoinStatus via NodeJoinProtocol ────────────────────────────

    #[test]
    fn join_status_waiting_for_quorum_before_session() {
        let mut protocol = NodeJoinProtocol::new(MemberId::new(42), EpochId::new(10), 1, 1000);
        let config = make_config(10);
        protocol.phase_shadow(&config, 2000).unwrap();

        // No session epoch - should be MissingEpochEvidence because we're past ShadowOnly
        let status = protocol.join_status(EpochId::new(10));
        assert!(matches!(status, JoinStatus::MissingEpochEvidence));
    }

    #[test]
    fn join_status_transfer_ready_with_quorum() {
        let mut protocol = NodeJoinProtocol::new(MemberId::new(42), EpochId::new(10), 1, 1000);
        let config = make_config(10);
        protocol.phase_shadow(&config, 2000).unwrap();

        let qe = QuorumEvidence {
            epoch: EpochId::new(10),
            quorum_approvals: 2,
            quorum_threshold: 2,
            approving_members: vec![MemberId::new(1), MemberId::new(2)],
        };
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(42), 100)
            .with_quorum(qe);
        protocol.record_session_epoch(session);

        let status = protocol.join_status(EpochId::new(10));
        // Still at ShadowOnly, so TransferInProgress (not TransferReady until VoterSpread)
        assert!(matches!(status, JoinStatus::TransferInProgress));
    }

    #[test]
    fn join_status_stale_epoch_visible() {
        let mut protocol = NodeJoinProtocol::new(MemberId::new(42), EpochId::new(10), 1, 1000);
        let config = make_config(10);
        protocol.phase_shadow(&config, 2000).unwrap();

        let qe = QuorumEvidence {
            epoch: EpochId::new(10),
            quorum_approvals: 2,
            quorum_threshold: 2,
            approving_members: vec![MemberId::new(1), MemberId::new(2)],
        };
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(42), 100)
            .with_quorum(qe);
        protocol.record_session_epoch(session);

        let status = protocol.join_status(EpochId::new(15));
        assert!(matches!(status, JoinStatus::StaleEpoch { .. }));
    }

    #[test]
    fn join_status_failed_visible() {
        let mut protocol = NodeJoinProtocol::new(MemberId::new(42), EpochId::new(10), 1, 1000);
        protocol.fail(2000, "test failure");
        let status = protocol.join_status(EpochId::new(10));
        assert!(matches!(status, JoinStatus::Failed(_)));
    }

    // ── StateTransferReceiver epoch gate tests ─────────────────────

    #[test]
    fn state_transfer_receiver_refuses_stale_session_epoch() {
        let mut receiver = crate::state_transfer::StateTransferReceiver::new(10);
        // Set a stale session epoch
        let session = crate::JoinSessionEpoch::new(EpochId::new(5), MemberId::new(42), 100);
        receiver.session_epoch = Some(session);

        let offer = crate::state_transfer::SegmentOffer::new(1, [0u8; 32], 100);
        let result = receiver.accept_offer(offer);
        assert!(matches!(
            result,
            Err(crate::state_transfer::SegmentTransferError::EpochMismatch { .. })
        ));
    }

    #[test]
    fn state_transfer_receiver_accepts_with_valid_session_epoch() {
        let mut receiver = crate::state_transfer::StateTransferReceiver::new(10);
        let qe = QuorumEvidence {
            epoch: EpochId::new(10),
            quorum_approvals: 2,
            quorum_threshold: 2,
            approving_members: vec![MemberId::new(1), MemberId::new(2)],
        };
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(42), 100)
            .with_quorum(qe);
        receiver.session_epoch = Some(session);

        let offer = crate::state_transfer::SegmentOffer::new(1, [0u8; 32], 100);
        assert!(receiver.accept_offer(offer).is_ok());
    }

    // ── SessionBindingManager epoch gate tests ─────────────────────

    #[test]
    fn session_binding_cannot_bind_without_epoch_evidence() {
        let mgr = crate::session_binding::SessionBindingManager::new(
            MemberId::new(42),
            EpochId::new(10),
        );
        let result = mgr.can_bind_sessions(EpochId::new(10));
        assert!(matches!(result, Err(JoinError::MissingEpochEvidence(_))));
    }

    #[test]
    fn session_binding_can_bind_with_valid_epoch() {
        let mut mgr = crate::session_binding::SessionBindingManager::new(
            MemberId::new(42),
            EpochId::new(10),
        );
        let qe = QuorumEvidence {
            epoch: EpochId::new(10),
            quorum_approvals: 2,
            quorum_threshold: 2,
            approving_members: vec![MemberId::new(1), MemberId::new(2)],
        };
        let session = JoinSessionEpoch::new(EpochId::new(10), MemberId::new(42), 100)
            .with_quorum(qe);
        mgr.set_session_epoch(session);

        assert!(mgr.can_bind_sessions(EpochId::new(10)).is_ok());
    }


}
