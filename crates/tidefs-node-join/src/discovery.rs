// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Node join discovery and handshake protocol.
//!
//! Implements the low-level discovery probe, join handshake wire protocol,
//! and epoch synchronization for a new node joining a TideFS pool.
//!
//! # State machine
//!
//! ```text
//! Candidate ──(probe sent)──▶ Discovering ──(response)──▶ Syncing ──(accept)──▶ Active
//!      │                          │                        │
//!      │                          │                        └──(reject)──▶ Rejected
//!      └──(retry)─────────────────┴──(max retries)──▶ Timeout
//! ```
//!
//! # Protocol flow
//!
//! ```text
//! Joiner (Candidate)                        Pool Member (Responder)
//!      |                                              |
//!      |──── DiscoveryProbe { id, caps } ────────────▶|
//!      |                                              |
//!      |◀─── DiscoveryResponse { epoch, accept } ─────|
//!      |                                              |
//!      |──── JoinHandshakeRequest { id, class } ─────▶|
//!      |                                              |
//!      |◀─── JoinHandshakeResponse { accept, mid } ───|
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub use tidefs_membership_epoch::NodeIdentity;
use tidefs_membership_epoch::{EpochId, MemberClass, MemberId, MembershipConfigRecord};

use crate::JoinError;
use tidefs_types_pool_label_core::PoolLabelFingerprint;

/// Wire protocol version for the discovery/handshake protocol.
pub const DISCOVERY_PROTOCOL_VERSION: u32 = 1;

// ── Wire message types ────────────────────────────────────────────────

/// Discovery probe broadcast by a candidate node to locate pool members.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryProbe {
    /// Protocol version supported by the candidate.
    pub protocol_version: u32,
    /// Identity of the candidate node.
    pub node_identity: NodeIdentity,
    /// Capabilities bitmask advertised by the candidate.
    pub capabilities: u64,
}

impl DiscoveryProbe {
    #[must_use]
    pub fn new(node_identity: NodeIdentity, capabilities: u64, protocol_version: u32) -> Self {
        Self {
            protocol_version,
            node_identity,
            capabilities,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, JoinError> {
        bincode::serialize(self).map_err(|e| JoinError::PreflightDenied(format!("encode: {e}")))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, JoinError> {
        bincode::deserialize(bytes).map_err(|e| JoinError::PreflightDenied(format!("decode: {e}")))
    }
}

/// Response from a pool member to a discovery probe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    /// Current pool epoch at the responding member.
    pub current_epoch: EpochId,
    /// Epoch vector: the responding member's view of every known member's epoch.
    /// Maps MemberId -> EpochId.
    pub epoch_vector: BTreeMap<u64, u64>,
    /// Hash of the membership table as seen by the responding member.
    /// Used to verify cluster-wide consistency during discovery.
    pub member_table_hash: u64,
    /// Whether the pool is accepting new members.
    pub accepting_members: bool,
    /// The member that responded.
    pub responder_id: MemberId,
    /// Pool identity for verification (prevents cross-pool joins).
    pub pool_id: u64,
    /// Optional redirect: candidate should contact this member instead.
    pub redirect_to: Option<MemberId>,
}

impl DiscoveryResponse {
    #[must_use]
    pub fn new(
        current_epoch: EpochId,
        accepting_members: bool,
        responder_id: MemberId,
        pool_id: u64,
    ) -> Self {
        Self {
            current_epoch,
            epoch_vector: BTreeMap::new(),
            member_table_hash: 0,
            accepting_members,
            responder_id,
            pool_id,
            redirect_to: None,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, JoinError> {
        bincode::serialize(self).map_err(|e| JoinError::PreflightDenied(format!("encode: {e}")))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, JoinError> {
        bincode::deserialize(bytes).map_err(|e| JoinError::PreflightDenied(format!("decode: {e}")))
    }
}

/// Formal join request from a candidate node to a pool member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JoinHandshakeRequest {
    /// Protocol version.
    pub protocol_version: u32,
    /// Candidate node identity.
    pub node_identity: NodeIdentity,
    /// Proposed member class (typically Learner).
    pub proposed_class: MemberClass,
    /// Epoch observed during discovery.
    pub observed_epoch: EpochId,
    /// Join nonce for replay protection.
    pub join_nonce: u64,
}

impl JoinHandshakeRequest {
    #[must_use]
    pub fn new(
        node_identity: NodeIdentity,
        proposed_class: MemberClass,
        observed_epoch: EpochId,
        join_nonce: u64,
        protocol_version: u32,
    ) -> Self {
        Self {
            protocol_version,
            node_identity,
            proposed_class,
            observed_epoch,
            join_nonce,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, JoinError> {
        bincode::serialize(self).map_err(|e| JoinError::PreflightDenied(format!("encode: {e}")))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, JoinError> {
        bincode::deserialize(bytes).map_err(|e| JoinError::PreflightDenied(format!("decode: {e}")))
    }
}

/// Response to a join request: accept or reject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JoinHandshakeResponse {
    /// Whether the join was accepted.
    pub accepted: bool,
    /// Assigned member ID (valid only if accepted).
    pub assigned_member_id: MemberId,
    /// Current pool epoch.
    pub current_epoch: EpochId,
    /// The membership configuration record after epoch increment.
    /// Populated on accepted joins to give the new node the full
    /// membership table.
    pub membership_config: Option<MembershipConfigRecord>,
    /// The committed root digest at the time of join acceptance.
    /// Used by the joining node to verify data integrity.
    pub committed_root: u64,
    /// Reason for rejection (valid only if !accepted).
    pub rejection_reason: Option<String>,
}

impl JoinHandshakeResponse {
    #[must_use]
    pub fn accept(assigned_member_id: MemberId, current_epoch: EpochId) -> Self {
        Self {
            accepted: true,
            assigned_member_id,
            current_epoch,
            membership_config: None,
            committed_root: 0,
            rejection_reason: None,
        }
    }

    /// Create an accepted response with full membership config and committed root.
    #[must_use]
    pub fn accept_with_config(
        assigned_member_id: MemberId,
        current_epoch: EpochId,
        membership_config: MembershipConfigRecord,
        committed_root: u64,
    ) -> Self {
        Self {
            accepted: true,
            assigned_member_id,
            current_epoch,
            membership_config: Some(membership_config),
            committed_root,
            rejection_reason: None,
        }
    }

    #[must_use]
    pub fn reject(reason: impl Into<String>) -> Self {
        Self {
            accepted: false,
            assigned_member_id: MemberId::ZERO,
            current_epoch: EpochId::ZERO,
            membership_config: None,
            committed_root: 0,
            rejection_reason: Some(reason.into()),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, JoinError> {
        bincode::serialize(self).map_err(|e| JoinError::PreflightDenied(format!("encode: {e}")))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, JoinError> {
        bincode::deserialize(bytes).map_err(|e| JoinError::PreflightDenied(format!("decode: {e}")))
    }
}

// ── Handshake states ──────────────────────────────────────────────────

/// States in the join handshake state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum HandshakeState {
    /// Initial state: ready to send a discovery probe.
    Candidate = 0,
    /// Discovery probe sent, awaiting response.
    Discovering = 1,
    /// Discovery succeeded; ready for join request.
    Syncing = 2,
    /// Join accepted, epoch synchronized, node is active.
    Active = 3,
    /// Join was rejected by the pool (terminal).
    Rejected = 4,
    /// Timeout exhausted all retries (terminal, but can be reset).
    Timeout = 5,
}

impl HandshakeState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Active | Self::Rejected | Self::Timeout)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "handshake.candidate",
            Self::Discovering => "handshake.discovering",
            Self::Syncing => "handshake.syncing",
            Self::Active => "handshake.active",
            Self::Rejected => "handshake.rejected",
            Self::Timeout => "handshake.timeout",
        }
    }
}

// ── Handshake config ──────────────────────────────────────────────────

/// Configuration for the join handshake.
#[derive(Clone, Debug)]
pub struct JoinHandshakeConfig {
    /// Timeout for the discovery phase (nanoseconds).
    pub discovery_timeout_ns: u64,
    /// Timeout for the handshake phase (nanoseconds).
    pub handshake_timeout_ns: u64,
    /// Maximum number of retries before giving up with Timeout.
    pub max_retries: u32,
    /// Protocol version for this node.
    pub protocol_version: u32,
}

impl Default for JoinHandshakeConfig {
    fn default() -> Self {
        Self {
            discovery_timeout_ns: 5_000_000_000,  // 5s
            handshake_timeout_ns: 10_000_000_000, // 10s
            max_retries: 3,
            protocol_version: DISCOVERY_PROTOCOL_VERSION,
        }
    }
}

// ── Member registration trait ─────────────────────────────────────────

/// Trait for registering a new member after a successful join.
///
/// This trait boundary avoids a dependency cycle between
/// `tidefs-node-join` and `tidefs-membership-live`. Consumers
/// (e.g., the membership runtime) implement this trait to receive
/// join notifications and register the new member.
pub trait MemberRegistration {
    /// Register a newly joined member with the given identity and epoch.
    ///
    /// Returns an error if the member cannot be registered (e.g.,
    /// duplicate ID, stale epoch).
    fn register_member(
        &mut self,
        member_id: MemberId,
        node_identity: NodeIdentity,
        epoch: EpochId,
        member_class: MemberClass,
    ) -> Result<(), JoinError>;

    /// Query the current epoch known to the membership system.
    fn current_epoch(&self) -> EpochId;
}

// ── Join handshake orchestrator ───────────────────────────────────────

/// Orchestrates the join handshake from Candidate through Active.
///
/// Tracks the state machine, builds wire messages, validates responses,
/// and manages timeout/retry logic. Consumers drive the handshake by:
///
/// 1. Calling `probe_sent()` when sending a discovery probe
/// 2. Calling `on_discovery_response()` when a response arrives
/// 3. Calling `build_join_request()` to construct the join request
/// 4. Calling `on_join_response()` when the join response arrives
/// 5. Periodically calling `check_timeout()` to detect stalled phases
///
/// After reaching `Active`, call `register_with()` to notify the
/// membership system via the [`MemberRegistration`] trait.
#[derive(Clone, Debug)]
pub struct JoinHandshake {
    /// Identity of the joining node.
    pub node_identity: NodeIdentity,
    /// Current handshake state.
    pub state: HandshakeState,
    /// Handshake configuration.
    pub config: JoinHandshakeConfig,
    /// The pool member responding to this join.
    pub responder: Option<MemberId>,
    /// Assigned member ID after successful join.
    pub assigned_member_id: Option<MemberId>,
    /// Pool epoch synchronized after successful join.
    pub synced_epoch: Option<EpochId>,
    /// Pool ID discovered during discovery.
    pub pool_id: Option<u64>,
    /// Membership config record received on accepted join.
    pub membership_config: Option<MembershipConfigRecord>,
    /// Committed root received on accepted join.
    pub committed_root: u64,
    /// Timestamp (ns) when current phase started.
    pub phase_started_ns: u64,
    /// Number of retries attempted so far.
    pub retry_count: u32,
    /// Rejection reason if state is Rejected.
    pub rejection_reason: Option<String>,
    /// Last epoch observed from discovery (for diagnostics).
    pub last_discovery_epoch: Option<EpochId>,
}

impl JoinHandshake {
    /// Create a new handshake in Candidate state.
    #[must_use]
    pub fn new(node_identity: NodeIdentity, config: JoinHandshakeConfig, now_ns: u64) -> Self {
        Self {
            node_identity,
            state: HandshakeState::Candidate,
            config,
            responder: None,
            assigned_member_id: None,
            synced_epoch: None,
            pool_id: None,
            membership_config: None,
            committed_root: 0,
            phase_started_ns: now_ns,
            retry_count: 0,
            rejection_reason: None,
            last_discovery_epoch: None,
        }
    }

    /// Transition from Candidate to Discovering (probe being sent).
    ///
    /// Returns an error if the handshake is not in the Candidate state.
    pub fn probe_sent(&mut self, now_ns: u64) -> Result<(), JoinError> {
        if self.state != HandshakeState::Candidate {
            return Err(JoinError::PreflightDenied(format!(
                "cannot send probe in state {:?}",
                self.state
            )));
        }
        self.state = HandshakeState::Discovering;
        self.phase_started_ns = now_ns;
        Ok(())
    }

    /// Process a discovery response from a pool member.
    ///
    /// Transitions from Discovering to Syncing if the pool is accepting
    /// members. Transitions to Rejected if `accepting_members` is false.
    pub fn on_discovery_response(
        &mut self,
        response: &DiscoveryResponse,
        now_ns: u64,
    ) -> Result<(), JoinError> {
        if self.state != HandshakeState::Discovering {
            return Err(JoinError::PreflightDenied(format!(
                "unexpected discovery response in state {:?}",
                self.state
            )));
        }

        self.last_discovery_epoch = Some(response.current_epoch);

        if !response.accepting_members {
            self.state = HandshakeState::Rejected;
            self.rejection_reason = Some("pool not accepting new members".into());
            return Ok(());
        }

        self.responder = if let Some(redirect) = response.redirect_to {
            Some(redirect)
        } else {
            Some(response.responder_id)
        };
        self.pool_id = Some(response.pool_id);
        self.state = HandshakeState::Syncing;
        self.phase_started_ns = now_ns;
        Ok(())
    }

    /// Process a join response from the pool member.
    ///
    /// Transitions to Active on acceptance, or Rejected on refusal.
    pub fn on_join_response(
        &mut self,
        response: &JoinHandshakeResponse,
        now_ns: u64,
    ) -> Result<(), JoinError> {
        if self.state != HandshakeState::Syncing {
            return Err(JoinError::PreflightDenied(format!(
                "unexpected join response in state {:?}",
                self.state
            )));
        }

        if !response.accepted {
            self.state = HandshakeState::Rejected;
            self.rejection_reason = response.rejection_reason.clone();
            return Ok(());
        }

        self.assigned_member_id = Some(response.assigned_member_id);
        self.synced_epoch = Some(response.current_epoch);
        self.membership_config = response.membership_config.clone();
        self.committed_root = response.committed_root;
        self.state = HandshakeState::Active;
        self.phase_started_ns = now_ns;
        Ok(())
    }

    /// Apply a discovery consensus to skip the point-to-point discovery
    /// phase. Transitions directly from Candidate to Syncing using the
    /// bootstrap peer selected by [`ClusterDiscovery`].
    ///
    /// This bridges broadcast discovery (which probes multiple peers and
    /// selects a bootstrap peer) into the point-to-point join handshake.
    pub fn apply_consensus(
        &mut self,
        consensus: &crate::discovery::DiscoveryConsensus,
        now_ns: u64,
    ) -> Result<(), JoinError> {
        if self.state != HandshakeState::Candidate {
            return Err(JoinError::PreflightDenied(format!(
                "cannot apply consensus in state {:?}",
                self.state
            )));
        }

        self.responder = Some(consensus.bootstrap_peer);
        self.pool_id = Some(consensus.pool_id);
        self.synced_epoch = Some(consensus.agreed_epoch);
        self.last_discovery_epoch = Some(consensus.agreed_epoch);
        self.state = HandshakeState::Syncing;
        self.phase_started_ns = now_ns;
        Ok(())
    }

    /// Check for timeout in the current phase. Returns the new state if a
    /// transition occurred, or `None` if still within the timeout window.
    ///
    /// On timeout with retries remaining: resets to Candidate for retry.
    /// On timeout with no retries remaining: transitions to Timeout.
    pub fn check_timeout(&mut self, now_ns: u64) -> Option<HandshakeState> {
        let timeout_ns = match self.state {
            HandshakeState::Discovering => self.config.discovery_timeout_ns,
            HandshakeState::Syncing => self.config.handshake_timeout_ns,
            _ => return None,
        };

        let elapsed = now_ns.saturating_sub(self.phase_started_ns);
        if elapsed < timeout_ns {
            return None;
        }

        if self.retry_count < self.config.max_retries {
            self.retry_count += 1;
            self.state = HandshakeState::Candidate;
            self.phase_started_ns = now_ns;
            self.responder = None;
            Some(HandshakeState::Candidate)
        } else {
            self.state = HandshakeState::Timeout;
            self.rejection_reason = Some(format!(
                "timeout after {} retries ({} ms elapsed)",
                self.retry_count,
                elapsed / 1_000_000
            ));
            Some(HandshakeState::Timeout)
        }
    }

    /// Reset the handshake to Candidate for a fresh attempt.
    pub fn reset(&mut self, now_ns: u64) {
        self.state = HandshakeState::Candidate;
        self.responder = None;
        self.assigned_member_id = None;
        self.synced_epoch = None;
        self.pool_id = None;
        self.membership_config = None;
        self.committed_root = 0;
        self.phase_started_ns = now_ns;
        self.retry_count = 0;
        self.rejection_reason = None;
        self.last_discovery_epoch = None;
    }

    /// Register the newly joined member with a [`MemberRegistration`] provider.
    ///
    /// Must be called after reaching the Active state. Validates that the
    /// epoch is consistent with the membership system before registering.
    pub fn register_with(
        &self,
        registrar: &mut dyn MemberRegistration,
        member_class: MemberClass,
    ) -> Result<(), JoinError> {
        if self.state != HandshakeState::Active {
            return Err(JoinError::PreflightDenied(format!(
                "cannot register member in state {:?}",
                self.state
            )));
        }

        let member_id = self
            .assigned_member_id
            .ok_or_else(|| JoinError::PreflightDenied("no assigned member ID".into()))?;

        let epoch = self
            .synced_epoch
            .ok_or_else(|| JoinError::PreflightDenied("no synced epoch".into()))?;

        // Epoch consistency check: registrar's epoch must match the synced epoch.
        let current = registrar.current_epoch();
        if current != EpochId::ZERO && current != epoch {
            return Err(JoinError::EpochMismatch {
                expected: epoch,
                got: current,
            });
        }

        registrar.register_member(member_id, self.node_identity, epoch, member_class)
    }

    /// Whether the handshake has reached a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Whether the node has successfully joined (Active).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == HandshakeState::Active
    }

    /// Build a discovery probe message with the given capabilities.
    #[must_use]
    pub fn build_discovery_probe(&self, capabilities: u64) -> DiscoveryProbe {
        DiscoveryProbe::new(
            self.node_identity,
            capabilities,
            self.config.protocol_version,
        )
    }

    /// Build a join request to send to the current responder.
    ///
    /// Returns `None` if no responder has been selected (i.e., discovery
    /// has not completed).
    #[must_use]
    pub fn build_join_request(
        &self,
        proposed_class: MemberClass,
        join_nonce: u64,
    ) -> Option<JoinHandshakeRequest> {
        self.responder?;
        Some(JoinHandshakeRequest::new(
            self.node_identity,
            proposed_class,
            self.synced_epoch.unwrap_or(EpochId::ZERO),
            join_nonce,
            self.config.protocol_version,
        ))
    }
}

// ── Cluster broadcast discovery ───────────────────────────────────────

/// Phase of the broadcast cluster discovery protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryPhase {
    /// Discovery has not started.
    Idle,
    /// Probes sent, waiting for responses.
    Broadcasting,
    /// Sufficient consistent responses received, consensus reached.
    Consensus,
    /// Inconsistent responses detected (split-brain or epoch mismatch).
    Inconsistent,
    /// Timeout exhausted without sufficient responses.
    Timeout,
}

/// Result of a successful broadcast discovery: a set of consistent
/// responses from pool members that agree on epoch vector and member
/// table hash.
#[derive(Clone, Debug)]
pub struct DiscoveryConsensus {
    /// The member selected as bootstrap peer for join handshake.
    pub bootstrap_peer: MemberId,
    /// Agreed-upon epoch as reported by consistent responders.
    pub agreed_epoch: EpochId,
    /// Agreed-upon member table hash.
    pub member_table_hash: u64,
    /// The pool ID from the consensus.
    pub pool_id: u64,
    /// Number of responders that agreed (for confidence).
    pub responder_count: usize,
    /// All consistent discovery responses received.
    pub responses: Vec<DiscoveryResponse>,
}

/// Orchestrates broadcast cluster discovery for a node joining a TideFS pool.
///
/// Sends discovery probes to all known peers, collects responses, validates
/// epoch vector and member table hash consistency, and selects a bootstrap
/// peer for the join handshake.
#[derive(Clone, Debug)]
pub struct ClusterDiscovery {
    /// List of known peer identities to probe.
    pub peers: Vec<NodeIdentity>,
    /// Current discovery phase.
    pub phase: DiscoveryPhase,
    /// Responses collected so far.
    responses: Vec<DiscoveryResponse>,
    /// When the current phase started (ns).
    phase_started_ns: u64,
    /// Discovery timeout in nanoseconds.
    pub timeout_ns: u64,
    /// Minimum number of consistent responses required for consensus.
    pub min_consensus_responses: usize,
    /// The consensus result, if reached.
    pub consensus: Option<DiscoveryConsensus>,
}

impl ClusterDiscovery {
    /// Create a new cluster discovery with the given peer list.
    #[must_use]
    pub fn new(peers: Vec<NodeIdentity>, timeout_ns: u64, min_consensus_responses: usize) -> Self {
        Self {
            peers,
            phase: DiscoveryPhase::Idle,
            responses: Vec::new(),
            phase_started_ns: 0,
            timeout_ns,
            min_consensus_responses,
            consensus: None,
        }
    }

    /// Start the discovery phase. Returns a list of `DiscoveryProbe` messages
    /// to send to each peer. Transitions to `Broadcasting`.
    pub fn start_discovery(
        &mut self,
        capabilities: u64,
        protocol_version: u32,
        node_identity: NodeIdentity,
        now_ns: u64,
    ) -> Result<Vec<(NodeIdentity, DiscoveryProbe)>, JoinError> {
        if self.phase != DiscoveryPhase::Idle {
            return Err(JoinError::PreflightDenied(format!(
                "cannot start discovery in phase {:?}",
                self.phase
            )));
        }
        self.phase = DiscoveryPhase::Broadcasting;
        self.phase_started_ns = now_ns;
        self.responses.clear();
        self.consensus = None;

        Ok(self
            .peers
            .iter()
            .map(|peer| {
                (
                    *peer,
                    DiscoveryProbe::new(node_identity, capabilities, protocol_version),
                )
            })
            .collect())
    }

    /// Process a discovery response from a peer.
    ///
    /// Returns `true` if consensus was reached after processing this response.
    pub fn on_response(
        &mut self,
        response: DiscoveryResponse,
        _now_ns: u64,
    ) -> Result<bool, JoinError> {
        if self.phase != DiscoveryPhase::Broadcasting {
            return Err(JoinError::PreflightDenied(format!(
                "unexpected response in phase {:?}",
                self.phase
            )));
        }

        if !response.accepting_members {
            self.responses.push(response);
            return Ok(false);
        }

        self.responses.push(response);

        self.try_consensus()
    }

    /// Check for timeout. Returns `true` if the discovery timed out.
    pub fn check_timeout(&mut self, now_ns: u64) -> bool {
        if self.phase != DiscoveryPhase::Broadcasting {
            return false;
        }

        let elapsed = now_ns.saturating_sub(self.phase_started_ns);
        if elapsed >= self.timeout_ns {
            self.phase = DiscoveryPhase::Timeout;
            return true;
        }
        false
    }

    /// Whether the discovery reached consensus successfully.
    #[must_use]
    pub fn is_consensus(&self) -> bool {
        self.phase == DiscoveryPhase::Consensus
    }

    /// Whether the discovery timed out.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        self.phase == DiscoveryPhase::Timeout
    }

    /// Whether the discovery detected inconsistent responses.
    #[must_use]
    pub fn is_inconsistent(&self) -> bool {
        self.phase == DiscoveryPhase::Inconsistent
    }

    /// Attempt to form consensus from collected accepting responses.
    ///
    /// Consensus requires:
    /// - At least `min_consensus_responses` accepting responses
    /// - All accepting responses agree on `member_table_hash`
    /// - No epoch vector contradictions (same member, different epoch)
    fn try_consensus(&mut self) -> Result<bool, JoinError> {
        let accepting: Vec<&DiscoveryResponse> = self
            .responses
            .iter()
            .filter(|r| r.accepting_members)
            .collect();

        if accepting.len() < self.min_consensus_responses {
            return Ok(false);
        }

        // Validate member table hash consistency across all responders.
        let expected_hash = accepting[0].member_table_hash;
        for r in &accepting[1..] {
            if r.member_table_hash != expected_hash {
                self.phase = DiscoveryPhase::Inconsistent;
                return Ok(false);
            }
        }

        // Validate epoch vector consistency: merge epoch vectors from all
        // responders and check for contradictions.
        let mut merged: BTreeMap<u64, u64> = BTreeMap::new();
        for r in &accepting {
            for (&member_id, &epoch) in &r.epoch_vector {
                if let Some(&existing) = merged.get(&member_id) {
                    if existing != epoch {
                        self.phase = DiscoveryPhase::Inconsistent;
                        return Ok(false);
                    }
                } else {
                    merged.insert(member_id, epoch);
                }
            }
        }

        // Select bootstrap peer: prefer the responder with the highest
        // current_epoch. If tied, prefer the one with the largest epoch_vector.
        // If still tied, prefer the numerically highest responder_id.
        let best = accepting
            .iter()
            .max_by_key(|r| {
                (
                    r.current_epoch.0,
                    r.epoch_vector.len() as u64,
                    r.responder_id.0,
                )
            })
            .unwrap();

        self.phase = DiscoveryPhase::Consensus;
        self.consensus = Some(DiscoveryConsensus {
            bootstrap_peer: best.responder_id,
            agreed_epoch: best.current_epoch,
            member_table_hash: expected_hash,
            pool_id: best.pool_id,
            responder_count: accepting.len(),
            responses: accepting.iter().map(|r| (*r).clone()).collect(),
        });

        Ok(true)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(id: u64) -> NodeIdentity {
        NodeIdentity::new(id)
    }

    // ── State transition tests ────────────────────────────────────────

    #[test]
    fn candidate_to_discovering_to_syncing_to_active() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 1000);
        assert_eq!(hs.state, HandshakeState::Candidate);

        // Candidate → Discovering
        hs.probe_sent(2000).unwrap();
        assert_eq!(hs.state, HandshakeState::Discovering);
        assert_eq!(hs.phase_started_ns, 2000);

        // Discovering → Syncing
        let resp = DiscoveryResponse::new(EpochId::new(5), true, MemberId::new(10), 42);
        hs.on_discovery_response(&resp, 3000).unwrap();
        assert_eq!(hs.state, HandshakeState::Syncing);
        assert_eq!(hs.responder, Some(MemberId::new(10)));
        assert_eq!(hs.pool_id, Some(42));

        // Syncing → Active
        let join_resp = JoinHandshakeResponse::accept(MemberId::new(99), EpochId::new(5));
        hs.on_join_response(&join_resp, 4000).unwrap();
        assert_eq!(hs.state, HandshakeState::Active);
        assert_eq!(hs.assigned_member_id, Some(MemberId::new(99)));
        assert_eq!(hs.synced_epoch, Some(EpochId::new(5)));
        assert!(hs.is_active());
        assert!(hs.is_terminal());
    }

    #[test]
    fn discovery_rejected_pool_not_accepting() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 1000);
        hs.probe_sent(2000).unwrap();

        let resp = DiscoveryResponse::new(EpochId::new(5), false, MemberId::new(10), 42);
        hs.on_discovery_response(&resp, 3000).unwrap();
        assert_eq!(hs.state, HandshakeState::Rejected);
        assert!(hs.rejection_reason.is_some());
        assert!(hs.is_terminal());
    }

    #[test]
    fn handshake_rejected_by_pool() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 1000);
        hs.probe_sent(2000).unwrap();
        hs.on_discovery_response(
            &DiscoveryResponse::new(EpochId::new(5), true, MemberId::new(10), 42),
            3000,
        )
        .unwrap();

        let resp = JoinHandshakeResponse::reject("pool at capacity");
        hs.on_join_response(&resp, 4000).unwrap();
        assert_eq!(hs.state, HandshakeState::Rejected);
        assert_eq!(hs.rejection_reason, Some("pool at capacity".into()));
    }

    #[test]
    fn handshake_rejected_epoch_mismatch() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 1000);
        hs.probe_sent(2000).unwrap();
        hs.on_discovery_response(
            &DiscoveryResponse::new(EpochId::new(5), true, MemberId::new(10), 42),
            3000,
        )
        .unwrap();

        let resp = JoinHandshakeResponse::reject("epoch mismatch: expected 5, node has 3");
        hs.on_join_response(&resp, 4000).unwrap();
        assert_eq!(hs.state, HandshakeState::Rejected);
    }

    #[test]
    fn discovery_redirect_followed() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 1000);
        hs.probe_sent(2000).unwrap();

        let mut resp = DiscoveryResponse::new(EpochId::new(5), true, MemberId::new(10), 42);
        resp.redirect_to = Some(MemberId::new(20));
        hs.on_discovery_response(&resp, 3000).unwrap();
        assert_eq!(hs.state, HandshakeState::Syncing);
        assert_eq!(hs.responder, Some(MemberId::new(20)));
    }

    // ── Timeout tests ─────────────────────────────────────────────────

    #[test]
    fn discovery_timeout_with_retry() {
        let config = JoinHandshakeConfig {
            discovery_timeout_ns: 5_000_000_000,
            max_retries: 2,
            ..Default::default()
        };
        let mut hs = JoinHandshake::new(test_identity(1), config, 0);
        hs.probe_sent(1000).unwrap();

        // Before timeout — no transition
        assert_eq!(hs.check_timeout(4_000_000_000), None);
        assert_eq!(hs.state, HandshakeState::Discovering);

        // After timeout — retry to Candidate
        let result = hs.check_timeout(6_000_000_000);
        assert_eq!(result, Some(HandshakeState::Candidate));
        assert_eq!(hs.state, HandshakeState::Candidate);
        assert_eq!(hs.retry_count, 1);
    }

    #[test]
    fn discovery_timeout_exhausted_retries() {
        let config = JoinHandshakeConfig {
            discovery_timeout_ns: 1_000_000_000,
            max_retries: 1,
            ..Default::default()
        };
        let mut hs = JoinHandshake::new(test_identity(1), config, 0);

        // First attempt times out → retry
        hs.probe_sent(1000).unwrap();
        hs.check_timeout(3_000_000_000);
        assert_eq!(hs.state, HandshakeState::Candidate);
        assert_eq!(hs.retry_count, 1);

        // Second attempt times out → exhausted
        hs.probe_sent(4_000_000_000).unwrap();
        hs.check_timeout(6_000_000_000);
        assert_eq!(hs.state, HandshakeState::Timeout);
    }

    #[test]
    fn handshake_timeout_with_retry() {
        let config = JoinHandshakeConfig {
            discovery_timeout_ns: 10_000_000_000,
            handshake_timeout_ns: 3_000_000_000,
            max_retries: 2,
            ..Default::default()
        };
        let mut hs = JoinHandshake::new(test_identity(1), config, 0);
        hs.probe_sent(1000).unwrap();
        hs.on_discovery_response(
            &DiscoveryResponse::new(EpochId::new(5), true, MemberId::new(10), 42),
            2000,
        )
        .unwrap();
        assert_eq!(hs.state, HandshakeState::Syncing);

        // After handshake timeout → retry to Candidate
        assert_eq!(
            hs.check_timeout(6_000_000_000),
            Some(HandshakeState::Candidate)
        );
        assert_eq!(hs.retry_count, 1);
    }

    #[test]
    fn no_timeout_on_terminal_states() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 0);
        hs.probe_sent(1000).unwrap();
        hs.on_discovery_response(
            &DiscoveryResponse::new(EpochId::new(5), true, MemberId::new(10), 42),
            2000,
        )
        .unwrap();
        hs.on_join_response(
            &JoinHandshakeResponse::accept(MemberId::new(99), EpochId::new(5)),
            3000,
        )
        .unwrap();
        assert_eq!(hs.state, HandshakeState::Active);

        // Timeout check on Active does nothing
        assert_eq!(hs.check_timeout(10_000_000_000), None);
        assert_eq!(hs.state, HandshakeState::Active);
    }

    // ── Error path tests ──────────────────────────────────────────────

    #[test]
    fn cannot_send_probe_twice() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 0);
        hs.probe_sent(1000).unwrap();
        let err = hs.probe_sent(2000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
    }

    #[test]
    fn cannot_process_discovery_response_in_wrong_state() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 0);
        // No probe sent
        let resp = DiscoveryResponse::new(EpochId::new(5), true, MemberId::new(10), 42);
        let err = hs.on_discovery_response(&resp, 1000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
    }

    #[test]
    fn cannot_process_join_response_before_discovery() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 0);
        let resp = JoinHandshakeResponse::accept(MemberId::new(99), EpochId::new(5));
        let err = hs.on_join_response(&resp, 1000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
    }

    #[test]
    fn reset_clears_all_state() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 0);
        hs.probe_sent(1000).unwrap();
        hs.on_discovery_response(
            &DiscoveryResponse::new(EpochId::new(5), true, MemberId::new(10), 42),
            2000,
        )
        .unwrap();
        hs.on_join_response(
            &JoinHandshakeResponse::accept(MemberId::new(99), EpochId::new(5)),
            3000,
        )
        .unwrap();

        hs.reset(10000);
        assert_eq!(hs.state, HandshakeState::Candidate);
        assert_eq!(hs.responder, None);
        assert_eq!(hs.assigned_member_id, None);
        assert_eq!(hs.synced_epoch, None);
        assert_eq!(hs.retry_count, 0);
        assert_eq!(hs.rejection_reason, None);
    }

    // ── Wire message round-trip tests ─────────────────────────────────

    #[test]
    fn discovery_probe_encode_decode_roundtrip() {
        let probe = DiscoveryProbe::new(test_identity(42), 0xDEAD, 1);
        let bytes = probe.encode().unwrap();
        let decoded = DiscoveryProbe::decode(&bytes).unwrap();
        assert_eq!(decoded, probe);
    }

    #[test]
    fn discovery_response_encode_decode_roundtrip() {
        let resp = DiscoveryResponse::new(EpochId::new(7), true, MemberId::new(3), 99);
        let bytes = resp.encode().unwrap();
        let decoded = DiscoveryResponse::decode(&bytes).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn discovery_response_with_redirect_encode_decode() {
        let mut resp = DiscoveryResponse::new(EpochId::new(7), true, MemberId::new(3), 99);
        resp.redirect_to = Some(MemberId::new(42));
        let bytes = resp.encode().unwrap();
        let decoded = DiscoveryResponse::decode(&bytes).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn join_request_encode_decode_roundtrip() {
        let req = JoinHandshakeRequest::new(
            test_identity(5),
            MemberClass::Learner,
            EpochId::new(3),
            12345,
            1,
        );
        let bytes = req.encode().unwrap();
        let decoded = JoinHandshakeRequest::decode(&bytes).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn join_response_accept_encode_decode_roundtrip() {
        let resp = JoinHandshakeResponse::accept(MemberId::new(42), EpochId::new(7));
        let bytes = resp.encode().unwrap();
        let decoded = JoinHandshakeResponse::decode(&bytes).unwrap();
        assert_eq!(decoded, resp);
        assert!(decoded.accepted);
        assert_eq!(decoded.assigned_member_id, MemberId::new(42));
    }

    #[test]
    fn join_response_reject_encode_decode_roundtrip() {
        let resp = JoinHandshakeResponse::reject("epoch mismatch");
        let bytes = resp.encode().unwrap();
        let decoded = JoinHandshakeResponse::decode(&bytes).unwrap();
        assert_eq!(decoded, resp);
        assert!(!decoded.accepted);
        assert_eq!(decoded.rejection_reason, Some("epoch mismatch".into()));
    }

    // ── MemberRegistration integration tests ──────────────────────────

    /// A trivial in-memory registrar for testing.
    struct TestRegistrar {
        epoch: EpochId,
        registered: Vec<(MemberId, NodeIdentity, EpochId, MemberClass)>,
    }

    impl TestRegistrar {
        fn new(epoch: EpochId) -> Self {
            Self {
                epoch,
                registered: Vec::new(),
            }
        }
    }

    impl MemberRegistration for TestRegistrar {
        fn register_member(
            &mut self,
            member_id: MemberId,
            node_identity: NodeIdentity,
            epoch: EpochId,
            member_class: MemberClass,
        ) -> Result<(), JoinError> {
            self.registered
                .push((member_id, node_identity, epoch, member_class));
            Ok(())
        }

        fn current_epoch(&self) -> EpochId {
            self.epoch
        }
    }

    #[test]
    fn register_with_success() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 1000);
        hs.probe_sent(2000).unwrap();
        hs.on_discovery_response(
            &DiscoveryResponse::new(EpochId::new(10), true, MemberId::new(2), 1),
            3000,
        )
        .unwrap();
        hs.on_join_response(
            &JoinHandshakeResponse::accept(MemberId::new(99), EpochId::new(10)),
            4000,
        )
        .unwrap();

        let mut reg = TestRegistrar::new(EpochId::new(10));
        hs.register_with(&mut reg, MemberClass::Learner).unwrap();
        assert_eq!(reg.registered.len(), 1);
        assert_eq!(reg.registered[0].0, MemberId::new(99));
        assert_eq!(reg.registered[0].2, EpochId::new(10));
        assert_eq!(reg.registered[0].3, MemberClass::Learner);
    }

    #[test]
    fn register_with_epoch_mismatch_rejected() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 1000);
        hs.probe_sent(2000).unwrap();
        hs.on_discovery_response(
            &DiscoveryResponse::new(EpochId::new(10), true, MemberId::new(2), 1),
            3000,
        )
        .unwrap();
        hs.on_join_response(
            &JoinHandshakeResponse::accept(MemberId::new(99), EpochId::new(10)),
            4000,
        )
        .unwrap();

        // Registrar has a different epoch
        let mut reg = TestRegistrar::new(EpochId::new(11));
        let err = hs
            .register_with(&mut reg, MemberClass::Learner)
            .unwrap_err();
        assert!(matches!(err, JoinError::EpochMismatch { .. }));
    }

    #[test]
    fn register_with_zero_epoch_allowed() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 1000);
        hs.probe_sent(2000).unwrap();
        hs.on_discovery_response(
            &DiscoveryResponse::new(EpochId::new(10), true, MemberId::new(2), 1),
            3000,
        )
        .unwrap();
        hs.on_join_response(
            &JoinHandshakeResponse::accept(MemberId::new(99), EpochId::new(10)),
            4000,
        )
        .unwrap();

        // Registrar with zero epoch (uninitialized) skips consistency check
        let mut reg = TestRegistrar::new(EpochId::ZERO);
        hs.register_with(&mut reg, MemberClass::Voter).unwrap();
        assert_eq!(reg.registered.len(), 1);
    }

    #[test]
    fn register_with_not_active_errors() {
        let hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 0);
        let mut reg = TestRegistrar::new(EpochId::new(1));
        let err = hs
            .register_with(&mut reg, MemberClass::Learner)
            .unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
    }

    // ── Two-node handshake integration test (transport harness) ───────

    /// Two nodes perform a complete discovery + join handshake over the
    /// deterministic transport message scheduler.
    #[test]
    fn two_node_handshake_candidate_to_active_over_transport() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use tidefs_transport::harness::{DeterministicMessageScheduler, SchedulerConfig};

        let sched = Rc::new(RefCell::new(DeterministicMessageScheduler::new(
            SchedulerConfig::deterministic(123),
        )));

        let n_cand = transport_node_identity(1);
        let n_member = transport_node_identity(2);

        sched.borrow_mut().register_node(n_cand);
        sched.borrow_mut().register_node(n_member);

        // --- Candidate side ---
        let mut candidate = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 0);

        // Phase 1: send discovery probe
        candidate.probe_sent(1000).unwrap();
        let probe = candidate.build_discovery_probe(0);
        sched
            .borrow_mut()
            .send(n_cand, n_member, 0, probe.encode().unwrap(), 0);

        sched.borrow_mut().tick_n(2);

        // Pool member receives probe — collect then respond to avoid BorrowMutError
        {
            let mut s = sched.borrow_mut();
            let mut responses: Vec<(NodeIdentity, Vec<u8>, u64)> = Vec::new();
            while let Some(msg) = s.recv(n_member) {
                let decoded = DiscoveryProbe::decode(&msg.payload).unwrap();
                assert_eq!(decoded.node_identity, test_identity(1));
                let resp = DiscoveryResponse::new(EpochId::new(10), true, MemberId::new(2), 42);
                responses.push((n_cand, resp.encode().unwrap(), 1));
            }
            for (to, payload, seq) in responses {
                s.send(n_member, to, 0, payload, seq);
            }
        }

        sched.borrow_mut().tick_n(1);

        // Candidate receives discovery response → Syncing
        while let Some(msg) = sched.borrow_mut().recv(n_cand) {
            let decoded = DiscoveryResponse::decode(&msg.payload).unwrap();
            candidate.on_discovery_response(&decoded, 2000).unwrap();
        }
        assert_eq!(candidate.state, HandshakeState::Syncing);

        // Phase 2: send join request
        let join_req = candidate
            .build_join_request(MemberClass::Learner, 999)
            .unwrap();
        sched
            .borrow_mut()
            .send(n_cand, n_member, 0, join_req.encode().unwrap(), 2);

        sched.borrow_mut().tick_n(2);

        // Pool member receives join request — collect then respond
        {
            let mut s = sched.borrow_mut();
            let mut responses: Vec<(NodeIdentity, Vec<u8>, u64)> = Vec::new();
            while let Some(msg) = s.recv(n_member) {
                let decoded = JoinHandshakeRequest::decode(&msg.payload).unwrap();
                assert_eq!(decoded.node_identity, test_identity(1));
                assert_eq!(decoded.proposed_class, MemberClass::Learner);
                let resp = JoinHandshakeResponse::accept(MemberId::new(99), EpochId::new(10));
                responses.push((n_cand, resp.encode().unwrap(), 3));
            }
            for (to, payload, seq) in responses {
                s.send(n_member, to, 0, payload, seq);
            }
        }

        sched.borrow_mut().tick_n(1);

        // Candidate receives join response → Active
        while let Some(msg) = sched.borrow_mut().recv(n_cand) {
            let decoded = JoinHandshakeResponse::decode(&msg.payload).unwrap();
            candidate.on_join_response(&decoded, 3000).unwrap();
        }
        assert_eq!(candidate.state, HandshakeState::Active);
        assert_eq!(candidate.assigned_member_id, Some(MemberId::new(99)));
        assert_eq!(candidate.synced_epoch, Some(EpochId::new(10)));
        assert!(candidate.is_active());
    }

    /// Pool member rejects the join: candidate reaches Rejected.
    #[test]
    fn two_node_handshake_rejection_over_transport() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use tidefs_transport::harness::{DeterministicMessageScheduler, SchedulerConfig};

        let sched = Rc::new(RefCell::new(DeterministicMessageScheduler::new(
            SchedulerConfig::deterministic(456),
        )));

        let n_cand = transport_node_identity(1);
        let n_member = transport_node_identity(2);

        sched.borrow_mut().register_node(n_cand);
        sched.borrow_mut().register_node(n_member);

        let mut candidate = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 0);

        // Discovery
        candidate.probe_sent(1000).unwrap();
        sched.borrow_mut().send(
            n_cand,
            n_member,
            0,
            candidate.build_discovery_probe(0).encode().unwrap(),
            0,
        );
        sched.borrow_mut().tick_n(2);

        // Pool member receives probe — collect then respond
        {
            let mut s = sched.borrow_mut();
            let mut responses: Vec<(NodeIdentity, Vec<u8>, u64)> = Vec::new();
            while let Some(_msg) = s.recv(n_member) {
                let resp = DiscoveryResponse::new(EpochId::new(10), true, MemberId::new(2), 42);
                responses.push((n_cand, resp.encode().unwrap(), 1));
            }
            for (to, payload, seq) in responses {
                s.send(n_member, to, 0, payload, seq);
            }
        }
        sched.borrow_mut().tick_n(1);

        while let Some(msg) = sched.borrow_mut().recv(n_cand) {
            candidate
                .on_discovery_response(&DiscoveryResponse::decode(&msg.payload).unwrap(), 2000)
                .unwrap();
        }

        // Join request → rejected
        let join_req = candidate
            .build_join_request(MemberClass::Learner, 1)
            .unwrap();
        sched
            .borrow_mut()
            .send(n_cand, n_member, 0, join_req.encode().unwrap(), 2);
        sched.borrow_mut().tick_n(1);

        // Pool member receives join request — collect then respond
        {
            let mut s = sched.borrow_mut();
            let mut responses: Vec<(NodeIdentity, Vec<u8>, u64)> = Vec::new();
            while let Some(_msg) = s.recv(n_member) {
                let resp = JoinHandshakeResponse::reject("pool at capacity");
                responses.push((n_cand, resp.encode().unwrap(), 3));
            }
            for (to, payload, seq) in responses {
                s.send(n_member, to, 0, payload, seq);
            }
        }
        sched.borrow_mut().tick_n(1);

        while let Some(msg) = sched.borrow_mut().recv(n_cand) {
            candidate
                .on_join_response(&JoinHandshakeResponse::decode(&msg.payload).unwrap(), 3000)
                .unwrap();
        }

        assert_eq!(candidate.state, HandshakeState::Rejected);
        assert_eq!(candidate.rejection_reason, Some("pool at capacity".into()));
        assert!(candidate.is_terminal());
    }

    // ── ClusterDiscovery tests ────────────────────────────────────────

    fn accepting_response(
        responder_id: u64,
        epoch: u64,
        pool_id: u64,
        hash: u64,
        epoch_vector: BTreeMap<u64, u64>,
    ) -> DiscoveryResponse {
        DiscoveryResponse {
            current_epoch: EpochId::new(epoch),
            epoch_vector,
            member_table_hash: hash,
            accepting_members: true,
            responder_id: MemberId::new(responder_id),
            pool_id,
            redirect_to: None,
        }
    }

    #[test]
    fn cluster_discovery_idle_to_consensus_two_responders() {
        let peers = vec![NodeIdentity::new(2), NodeIdentity::new(3)];
        let mut cd = ClusterDiscovery::new(peers, 10_000_000_000, 2);

        assert_eq!(cd.phase, DiscoveryPhase::Idle);

        // Start discovery
        let probes = cd
            .start_discovery(0, 1, NodeIdentity::new(1), 1000)
            .unwrap();
        assert_eq!(probes.len(), 2);
        assert_eq!(cd.phase, DiscoveryPhase::Broadcasting);

        // Two responders with consistent epoch vectors
        let mut ev1 = BTreeMap::new();
        ev1.insert(1, 5);
        ev1.insert(2, 5);
        ev1.insert(3, 5);

        let mut ev2 = BTreeMap::new();
        ev2.insert(1, 5);
        ev2.insert(2, 5);
        ev2.insert(3, 5);

        // First response: not enough for consensus yet
        let r1 = accepting_response(2, 5, 42, 0xCAFE, ev1.clone());
        let reached = cd.on_response(r1, 2000).unwrap();
        assert!(!reached);
        assert_eq!(cd.phase, DiscoveryPhase::Broadcasting);

        // Second response: consensus
        let r2 = accepting_response(3, 5, 42, 0xCAFE, ev2.clone());
        let reached = cd.on_response(r2, 3000).unwrap();
        assert!(reached);
        assert_eq!(cd.phase, DiscoveryPhase::Consensus);
        assert!(cd.is_consensus());

        let consensus = cd.consensus.as_ref().unwrap();
        assert_eq!(consensus.responder_count, 2);
        assert_eq!(consensus.member_table_hash, 0xCAFE);
        assert_eq!(consensus.pool_id, 42);
        assert_eq!(consensus.agreed_epoch, EpochId::new(5));
        // Bootstrap peer should be the one with highest epoch_vector.len()
        // (tied, then by responder_id: 3 > 2)
        assert_eq!(consensus.bootstrap_peer, MemberId::new(3));
    }

    #[test]
    fn cluster_discovery_consensus_min_responses() {
        let peers = vec![
            NodeIdentity::new(2),
            NodeIdentity::new(3),
            NodeIdentity::new(4),
        ];
        // Require 3 consistent responses
        let mut cd = ClusterDiscovery::new(peers, 10_000_000_000, 3);

        cd.start_discovery(0, 1, NodeIdentity::new(1), 1000)
            .unwrap();

        let ev = BTreeMap::new();

        // Two responses: not enough
        cd.on_response(accepting_response(2, 5, 42, 0xBEEF, ev.clone()), 2000)
            .unwrap();
        assert_eq!(cd.phase, DiscoveryPhase::Broadcasting);

        cd.on_response(accepting_response(3, 5, 42, 0xBEEF, ev.clone()), 3000)
            .unwrap();
        assert_eq!(cd.phase, DiscoveryPhase::Broadcasting);

        // Third response: consensus
        let reached = cd
            .on_response(accepting_response(4, 5, 42, 0xBEEF, ev.clone()), 4000)
            .unwrap();
        assert!(reached);
        assert_eq!(cd.phase, DiscoveryPhase::Consensus);
        assert_eq!(cd.consensus.as_ref().unwrap().responder_count, 3);
    }

    #[test]
    fn cluster_discovery_member_table_hash_mismatch() {
        let peers = vec![NodeIdentity::new(2), NodeIdentity::new(3)];
        let mut cd = ClusterDiscovery::new(peers, 10_000_000_000, 2);

        cd.start_discovery(0, 1, NodeIdentity::new(1), 1000)
            .unwrap();

        let ev = BTreeMap::new();
        cd.on_response(accepting_response(2, 5, 42, 0xAAAA, ev.clone()), 2000)
            .unwrap();

        // Different member table hash → inconsistent
        let reached = cd
            .on_response(accepting_response(3, 5, 42, 0xBBBB, ev.clone()), 3000)
            .unwrap();
        assert!(!reached);
        assert_eq!(cd.phase, DiscoveryPhase::Inconsistent);
        assert!(cd.is_inconsistent());
        assert!(cd.consensus.is_none());
    }

    #[test]
    fn cluster_discovery_epoch_vector_contradiction() {
        let peers = vec![NodeIdentity::new(2), NodeIdentity::new(3)];
        let mut cd = ClusterDiscovery::new(peers, 10_000_000_000, 2);

        cd.start_discovery(0, 1, NodeIdentity::new(1), 1000)
            .unwrap();

        let mut ev1 = BTreeMap::new();
        ev1.insert(1, 5);
        ev1.insert(2, 5);

        let mut ev2 = BTreeMap::new();
        ev2.insert(1, 7); // Different epoch for member 1
        ev2.insert(2, 5);

        cd.on_response(accepting_response(2, 5, 42, 0xCAFE, ev1), 2000)
            .unwrap();

        // Epoch contradiction on member 1 → inconsistent
        let reached = cd
            .on_response(accepting_response(3, 5, 42, 0xCAFE, ev2), 3000)
            .unwrap();
        assert!(!reached);
        assert_eq!(cd.phase, DiscoveryPhase::Inconsistent);
    }

    #[test]
    fn cluster_discovery_timeout() {
        let peers = vec![NodeIdentity::new(2), NodeIdentity::new(3)];
        let mut cd = ClusterDiscovery::new(peers, 5_000_000_000, 2);

        cd.start_discovery(0, 1, NodeIdentity::new(1), 1000)
            .unwrap();

        // Before timeout
        assert!(!cd.check_timeout(4_000_000_000));
        assert_eq!(cd.phase, DiscoveryPhase::Broadcasting);

        // After timeout
        assert!(cd.check_timeout(7_000_000_000));
        assert_eq!(cd.phase, DiscoveryPhase::Timeout);
        assert!(cd.is_timeout());
    }

    #[test]
    fn cluster_discovery_ignores_non_accepting_responses() {
        let peers = vec![
            NodeIdentity::new(2),
            NodeIdentity::new(3),
            NodeIdentity::new(4),
        ];
        let mut cd = ClusterDiscovery::new(peers, 10_000_000_000, 2);

        cd.start_discovery(0, 1, NodeIdentity::new(1), 1000)
            .unwrap();

        let ev = BTreeMap::new();

        // Non-accepting response
        let rejecting = DiscoveryResponse {
            current_epoch: EpochId::new(5),
            epoch_vector: ev.clone(),
            member_table_hash: 0xCAFE,
            accepting_members: false,
            responder_id: MemberId::new(2),
            pool_id: 42,
            redirect_to: None,
        };
        cd.on_response(rejecting, 2000).unwrap();
        assert_eq!(cd.phase, DiscoveryPhase::Broadcasting);

        // Two accepting responses → consensus (rejection ignored)
        cd.on_response(accepting_response(3, 5, 42, 0xCAFE, ev.clone()), 3000)
            .unwrap();
        let reached = cd
            .on_response(accepting_response(4, 5, 42, 0xCAFE, ev.clone()), 4000)
            .unwrap();
        assert!(reached);
        assert_eq!(cd.phase, DiscoveryPhase::Consensus);
        assert_eq!(cd.consensus.as_ref().unwrap().responder_count, 2);
    }

    #[test]
    fn cluster_discovery_cannot_start_twice() {
        let peers = vec![NodeIdentity::new(2)];
        let mut cd = ClusterDiscovery::new(peers, 10_000_000_000, 1);

        cd.start_discovery(0, 1, NodeIdentity::new(1), 1000)
            .unwrap();
        let err = cd
            .start_discovery(0, 1, NodeIdentity::new(1), 2000)
            .unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
    }

    #[test]
    fn cluster_discovery_rejects_response_out_of_phase() {
        let peers = vec![NodeIdentity::new(2)];
        let mut cd = ClusterDiscovery::new(peers, 10_000_000_000, 1);

        // Not in Broadcasting phase
        let ev = BTreeMap::new();
        let err = cd
            .on_response(accepting_response(2, 5, 42, 0xCAFE, ev), 2000)
            .unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
    }

    #[test]
    fn cluster_discovery_consensus_single_responder() {
        let peers = vec![NodeIdentity::new(2)];
        let mut cd = ClusterDiscovery::new(peers, 10_000_000_000, 1);

        cd.start_discovery(0, 1, NodeIdentity::new(1), 1000)
            .unwrap();

        let ev = BTreeMap::new();
        let reached = cd
            .on_response(accepting_response(2, 5, 42, 0xCAFE, ev), 2000)
            .unwrap();
        assert!(reached);
        assert_eq!(cd.phase, DiscoveryPhase::Consensus);
        assert_eq!(
            cd.consensus.as_ref().unwrap().bootstrap_peer,
            MemberId::new(2)
        );
    }

    #[test]
    fn cluster_discovery_bootstrap_peer_highest_epoch() {
        let peers = vec![
            NodeIdentity::new(2),
            NodeIdentity::new(3),
            NodeIdentity::new(4),
        ];
        let mut cd = ClusterDiscovery::new(peers, 10_000_000_000, 2);

        cd.start_discovery(0, 1, NodeIdentity::new(1), 1000)
            .unwrap();

        let ev = BTreeMap::new();

        // Responder 2 has epoch 3
        cd.on_response(accepting_response(2, 3, 42, 0xCAFE, ev.clone()), 2000)
            .unwrap();
        assert_eq!(cd.phase, DiscoveryPhase::Broadcasting);

        // Responder 3 has epoch 5 (higher) - consensus picks epoch 5
        let reached = cd
            .on_response(accepting_response(3, 5, 42, 0xCAFE, ev.clone()), 3000)
            .unwrap();
        assert!(reached);
        assert_eq!(cd.phase, DiscoveryPhase::Consensus);

        let consensus = cd.consensus.as_ref().unwrap();
        assert_eq!(consensus.agreed_epoch, EpochId::new(5));
        assert_eq!(consensus.bootstrap_peer, MemberId::new(3));
    }

    #[test]
    fn cluster_discovery_no_timeout_on_consensus_or_inconsistent() {
        let peers = vec![NodeIdentity::new(2), NodeIdentity::new(3)];
        let mut cd = ClusterDiscovery::new(peers, 1_000_000_000, 2);

        cd.start_discovery(0, 1, NodeIdentity::new(1), 1000)
            .unwrap();

        let ev = BTreeMap::new();
        cd.on_response(accepting_response(2, 5, 42, 0xCAFE, ev.clone()), 2000)
            .unwrap();
        cd.on_response(accepting_response(3, 5, 42, 0xCAFE, ev.clone()), 3000)
            .unwrap();
        assert_eq!(cd.phase, DiscoveryPhase::Consensus);

        // Timeout check should be a no-op on Consensus
        assert!(!cd.check_timeout(10_000_000_000));
        assert_eq!(cd.phase, DiscoveryPhase::Consensus);
    }

    // ── Discovery-to-handshake integration test ────────────────────

    /// Full flow: broadcast discovery (ClusterDiscovery) reaches consensus,
    /// consensus is applied to JoinHandshake (bypassing 1:1 discovery), then
    /// the join request/response completes the handshake over transport.
    #[test]
    fn discovery_consensus_to_handshake_active_over_transport() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use tidefs_transport::harness::{DeterministicMessageScheduler, SchedulerConfig};

        let sched = Rc::new(RefCell::new(DeterministicMessageScheduler::new(
            SchedulerConfig::deterministic(999),
        )));

        let n_joiner = transport_node_identity(1);
        let n_peer2 = transport_node_identity(2);
        let n_peer3 = transport_node_identity(3);

        sched.borrow_mut().register_node(n_joiner);
        sched.borrow_mut().register_node(n_peer2);
        sched.borrow_mut().register_node(n_peer3);

        // --- Phase 1: ClusterDiscovery ---
        let peers = vec![n_peer2, n_peer3];
        let mut cd = ClusterDiscovery::new(peers, 10_000_000_000, 2);

        let probes = cd.start_discovery(0, 1, n_joiner, 1000).unwrap();
        assert_eq!(probes.len(), 2);

        // Send both probes
        for (to, probe) in &probes {
            sched
                .borrow_mut()
                .send(n_joiner, *to, 0, probe.encode().unwrap(), 0);
        }
        sched.borrow_mut().tick_n(2);

        // Both peers respond
        {
            let mut s = sched.borrow_mut();
            let mut responses: Vec<(NodeIdentity, Vec<u8>, u64)> = Vec::new();
            for &peer in &[n_peer2, n_peer3] {
                while let Some(_msg) = s.recv(peer) {
                    let mut ev = BTreeMap::new();
                    ev.insert(1, 10);
                    ev.insert(2, 10);
                    ev.insert(3, 10);
                    let resp = DiscoveryResponse {
                        current_epoch: EpochId::new(10),
                        epoch_vector: ev,
                        member_table_hash: 0xBEEF,
                        accepting_members: true,
                        responder_id: MemberId::new(peer.node_id),
                        pool_id: 77,
                        redirect_to: None,
                    };
                    responses.push((n_joiner, resp.encode().unwrap(), 1));
                }
            }
            for (to, payload, seq) in responses {
                s.send(n_peer2, to, 0, payload, seq);
            }
        }
        sched.borrow_mut().tick_n(1);

        // Joiner collects responses → consensus
        while let Some(msg) = sched.borrow_mut().recv(n_joiner) {
            let decoded = DiscoveryResponse::decode(&msg.payload).unwrap();
            cd.on_response(decoded, 2000).unwrap();
        }
        assert_eq!(cd.phase, DiscoveryPhase::Consensus);
        assert!(cd.is_consensus());

        let consensus = cd.consensus.as_ref().unwrap();
        assert_eq!(consensus.pool_id, 77);
        assert_eq!(consensus.agreed_epoch, EpochId::new(10));
        assert_eq!(consensus.member_table_hash, 0xBEEF);
        assert_eq!(consensus.responder_count, 2);

        // --- Phase 2: JoinHandshake using consensus ---
        let mut handshake = JoinHandshake::new(n_joiner, JoinHandshakeConfig::default(), 0);

        // Skip 1:1 discovery — apply consensus directly
        handshake.apply_consensus(consensus, 3000).unwrap();
        assert_eq!(handshake.state, HandshakeState::Syncing);
        assert_eq!(handshake.responder, Some(consensus.bootstrap_peer));
        assert_eq!(handshake.pool_id, Some(77));
        assert_eq!(handshake.synced_epoch, Some(EpochId::new(10)));

        // Send join request to bootstrap peer
        let join_req = handshake
            .build_join_request(MemberClass::Learner, 42)
            .unwrap();
        let bootstrap_ni = NodeIdentity::new(consensus.bootstrap_peer.0);
        sched
            .borrow_mut()
            .send(n_joiner, bootstrap_ni, 0, join_req.encode().unwrap(), 2);

        sched.borrow_mut().tick_n(2);

        // Bootstrap peer accepts join
        {
            let mut s = sched.borrow_mut();
            let mut responses: Vec<(NodeIdentity, Vec<u8>, u64)> = Vec::new();
            while let Some(_msg) = s.recv(bootstrap_ni) {
                let resp = JoinHandshakeResponse::accept(MemberId::new(99), EpochId::new(10));
                responses.push((n_joiner, resp.encode().unwrap(), 3));
            }
            for (to, payload, seq) in responses {
                s.send(bootstrap_ni, to, 0, payload, seq);
            }
        }
        sched.borrow_mut().tick_n(1);

        // Joiner receives acceptance → Active
        while let Some(msg) = sched.borrow_mut().recv(n_joiner) {
            let decoded = JoinHandshakeResponse::decode(&msg.payload).unwrap();
            handshake.on_join_response(&decoded, 4000).unwrap();
        }
        assert_eq!(handshake.state, HandshakeState::Active);
        assert_eq!(handshake.assigned_member_id, Some(MemberId::new(99)));
        assert!(handshake.is_active());
    }

    /// apply_consensus is rejected when not in Candidate state.
    #[test]
    fn apply_consensus_rejected_in_wrong_state() {
        let mut hs = JoinHandshake::new(test_identity(1), JoinHandshakeConfig::default(), 0);
        hs.probe_sent(1000).unwrap();
        assert_eq!(hs.state, HandshakeState::Discovering);

        let consensus = DiscoveryConsensus {
            bootstrap_peer: MemberId::new(2),
            agreed_epoch: EpochId::new(5),
            member_table_hash: 0,
            pool_id: 1,
            responder_count: 1,
            responses: vec![],
        };
        let err = hs.apply_consensus(&consensus, 2000).unwrap_err();
        assert!(matches!(err, JoinError::PreflightDenied(..)));
    }

    // ── Three-node cluster formation integration test ──────────────

    /// Full pipeline: three nodes form a cluster with node 1 joining
    /// nodes 2 and 3. Covers discovery broadcast → consensus →
    /// handshake → commit → phase promotion → catch-up → joined.
    #[test]
    fn three_node_join_full_pipeline() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use tidefs_transport::harness::{DeterministicMessageScheduler, SchedulerConfig};

        let sched = Rc::new(RefCell::new(DeterministicMessageScheduler::new(
            SchedulerConfig::deterministic(777),
        )));

        let n1 = transport_node_identity(1); // joiner
        let n2 = transport_node_identity(2); // existing member
        let n3 = transport_node_identity(3); // existing member

        sched.borrow_mut().register_node(n1);
        sched.borrow_mut().register_node(n2);
        sched.borrow_mut().register_node(n3);

        // ── Phase 1: ClusterDiscovery (broadcast to n2, n3) ──
        let peers = vec![n2, n3];
        let mut cd = ClusterDiscovery::new(peers, 20_000_000_000, 2);

        let probes = cd.start_discovery(0, 1, n1, 1000).unwrap();
        assert_eq!(probes.len(), 2);

        // Send probes
        for (to, probe) in &probes {
            sched
                .borrow_mut()
                .send(n1, *to, 0, probe.encode().unwrap(), 0);
        }
        sched.borrow_mut().tick_n(2);

        // Both peers respond consistently
        {
            let mut s = sched.borrow_mut();
            let mut responses: Vec<(NodeIdentity, Vec<u8>, u64)> = Vec::new();
            for &peer in &[n2, n3] {
                while let Some(_msg) = s.recv(peer) {
                    let mut ev = BTreeMap::new();
                    ev.insert(1, 10);
                    ev.insert(2, 10);
                    ev.insert(3, 10);
                    let resp = DiscoveryResponse {
                        current_epoch: EpochId::new(10),
                        epoch_vector: ev,
                        member_table_hash: 0xF00D,
                        accepting_members: true,
                        responder_id: MemberId::new(peer.node_id),
                        pool_id: 99,
                        redirect_to: None,
                    };
                    responses.push((n1, resp.encode().unwrap(), 1));
                }
            }
            for (to, payload, seq) in responses {
                s.send(n2, to, 0, payload, seq);
            }
        }
        sched.borrow_mut().tick_n(1);

        // Joiner collects → consensus
        while let Some(msg) = sched.borrow_mut().recv(n1) {
            cd.on_response(DiscoveryResponse::decode(&msg.payload).unwrap(), 2000)
                .unwrap();
        }
        assert_eq!(cd.phase, DiscoveryPhase::Consensus);
        assert!(cd.is_consensus());

        let consensus = cd.consensus.as_ref().unwrap();
        assert_eq!(consensus.responder_count, 2);
        assert_eq!(consensus.pool_id, 99);
        assert_eq!(consensus.member_table_hash, 0xF00D);

        // ── Phase 2: JoinHandshake using consensus ──
        let mut handshake = JoinHandshake::new(n1, JoinHandshakeConfig::default(), 0);
        handshake.apply_consensus(consensus, 3000).unwrap();
        assert_eq!(handshake.state, HandshakeState::Syncing);

        let bootstrap_ni = NodeIdentity::new(consensus.bootstrap_peer.0);

        // Send join request
        let join_req = handshake
            .build_join_request(MemberClass::Learner, 42)
            .unwrap();
        sched
            .borrow_mut()
            .send(n1, bootstrap_ni, 0, join_req.encode().unwrap(), 2);
        sched.borrow_mut().tick_n(2);

        // Bootstrap peer accepts with membership config
        {
            let mut s = sched.borrow_mut();
            let mut responses: Vec<(NodeIdentity, Vec<u8>, u64)> = Vec::new();
            while let Some(_msg) = s.recv(bootstrap_ni) {
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
                let resp = JoinHandshakeResponse::accept_with_config(
                    MemberId::new(1),
                    EpochId::new(10),
                    config,
                    0xABCDEF,
                );
                responses.push((n1, resp.encode().unwrap(), 3));
            }
            for (to, payload, seq) in responses {
                s.send(bootstrap_ni, to, 0, payload, seq);
            }
        }
        sched.borrow_mut().tick_n(1);

        // Joiner receives acceptance → Active
        while let Some(msg) = sched.borrow_mut().recv(n1) {
            handshake
                .on_join_response(&JoinHandshakeResponse::decode(&msg.payload).unwrap(), 4000)
                .unwrap();
        }
        assert_eq!(handshake.state, HandshakeState::Active);
        assert_eq!(handshake.assigned_member_id, Some(MemberId::new(1)));
        assert!(handshake.membership_config.is_some());
        assert_eq!(handshake.committed_root, 0xABCDEF);

        // ── Phase 3: JoinCommit validation ──
        let commit = crate::JoinCommit::validate(&handshake);
        assert!(commit.is_ready());
        let commit_result = commit.result.unwrap();
        assert_eq!(commit_result.member_id, MemberId::new(1));
        assert_eq!(commit_result.epoch, EpochId::new(10));
        assert_eq!(commit_result.committed_root, 0xABCDEF);

        // ── Phase 4: NodeJoinProtocol phase promotion ──
        let mut protocol =
            crate::NodeJoinProtocol::new(MemberId::new(1), EpochId::new(10), 1, 5000);
        // Provide committed evidence so phase_shadow gates pass
        let session = crate::JoinSessionEpoch::new(commit_result.epoch, MemberId::new(1), 5000)
            .with_pool_scan_evidence(
                tidefs_membership_epoch::pool_scan_gate::PoolScanEvidence::committed(
                    commit_result.epoch.0.saturating_sub(1),
                    commit_result.epoch.0,
                    42,
                    1,
                    [
                        tidefs_membership_epoch::pool_scan_gate::EpochMemberLabelFingerprint::new(
                            1,
                            PoolLabelFingerprint::from([0xBBu8; 32]),
                        ),
                    ],
                ),
            )
            .with_label_agreement(crate::LabelAgreementFingerprint {
                fingerprint: PoolLabelFingerprint::from([0xBBu8; 32]),
                is_committed: true,
            })
            .with_placement_receipt(crate::PlacementReceiptEvidence {
                intent_class: None,
                is_committed: true,
                placement_epoch: commit_result.epoch,
                receipt_id: 1,
                receipt_hash: [0xCCu8; 32],
            });
        protocol.record_session_epoch(session);
        protocol
            .start_from_join_commit(&commit_result, 5000)
            .unwrap();
        assert_eq!(protocol.progress.phase, crate::JoinPhase::ShadowOnly);
        assert!(!protocol.can_accept_replicas());

        // ── Phase 5: NodeJoin lifecycle → catch-up → joined ──
        let mut node_join = crate::NodeJoin::new(MemberId::new(1), EpochId::new(10), 6000);
        node_join
            .start_from_join_commit(&commit_result, consensus.bootstrap_peer, 6000)
            .unwrap();
        assert_eq!(node_join.state, crate::NodeJoinState::Bootstrapping);

        // Begin catch-up with empty plan (no segments to pull in this test)
        let plan = crate::CatchUpPlan {
            segment_ids: vec![],
            bootstrap_peer: consensus.bootstrap_peer,
            committed_root: commit_result.committed_root,
            estimated_bytes: 0,
        };
        let progress = node_join.begin_catch_up(&plan, 4096, 7000).unwrap();
        assert!(progress.is_complete());

        node_join.complete_catch_up(&progress, 8000).unwrap();
        assert_eq!(node_join.state, crate::NodeJoinState::Joining);

        node_join.join_complete(9000).unwrap();
        assert_eq!(node_join.state, crate::NodeJoinState::Joined);
        assert!(node_join.can_receive_placements());

        // ── Final state verification ──
        assert!(handshake.is_active());
        assert!(protocol.progress.phase == crate::JoinPhase::ShadowOnly);
        assert!(node_join.is_terminal());
    }
    // Helper: create a transport harness NodeIdentity
    fn transport_node_identity(id: u64) -> NodeIdentity {
        NodeIdentity::new(id)
    }
}
