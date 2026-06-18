// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Membership outbound message dispatch bridge.
//!
//! Bridges subsystem-generated membership protocol messages (lease grants,
//! epoch proposals, liveness heartbeats, roster updates, gossip, drain
//! commands) to the transport per-connection send pipeline provided by
//! [`tidefs_transport::SendDispatcher`] (#5829).
//!
//! ## Architecture
//!
//! ```text
//! MembershipOutboundDispatch
//!   |
//!   +-- send_to_peer(member_id, msg)
//!   |     |
//!   |     +-- resolve member_id -> PeerId (direct mapping)
//!   |     +-- verify peer in roster snapshot
//!   |     +-- serialize msg via bincode
//!   |     +-- wrap in OutboundMessage (family=m4.PublicationProgress)
//!   |     +-- SendDispatcher::enqueue(peer_id, outbound)
//!   |
//!   +-- broadcast(msg)
//!         |
//!         +-- iterate roster snapshot (Active members only)
//!         +-- clone msg per peer
//!         +-- send_to_peer for each
//!         +-- return BroadcastResult { success_count, errors }
//! ```
//!
//! ## Integration
//!
//! The membership runtime creates a `MembershipOutboundDispatch` holding
//! references to the transport [`SendDispatcher`] and the membership
//! [`MembershipRoster`]. Subsystems call `send_to_peer` for unicast
//! protocol messages or `broadcast` for epidemic dissemination.
//!
//! Backpressure from the transport send queue is propagated to the caller
//! via [`OutboundDispatchError::Backpressure`]. Callers should inspect and
//! delay, drop, or shed accordingly.

use std::fmt;

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::epoch_catch_up::CommittedEpochView;
use tidefs_membership_epoch::epoch_proposal::MembershipDelta;
use tidefs_membership_epoch::{EpochId, Incarnation, LeaveReason, MemberId};
use tidefs_transport::circuit_breaker::PeerId;
use tidefs_transport::envelope::MessageFamily;
use tidefs_transport::send_dispatch::{OutboundMessage, SendDispatcher, SendError};
#[cfg(test)]
use tidefs_transport::ErrorClassifier;

use crate::roster::{MembershipRoster, RosterState};
// ---------------------------------------------------------------------------
// MembershipOutboundMessage -- outbound protocol message variants
// ---------------------------------------------------------------------------

/// A membership protocol message heading outbound to one or more peers.
///
/// Serialized with bincode and wrapped in a transport [`OutboundMessage`]
/// carrying [`MessageFamily::PublicationProgress`] (m4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipOutboundMessage {
    /// Grant write-authority lease to a member.
    LeaseGrant {
        member_id: MemberId,
        lease_epoch: EpochId,
        lease_expires_at_millis: u64,
        granted_at_millis: u64,
    },
    /// Renew an existing lease for a member.
    LeaseRenew {
        member_id: MemberId,
        lease_epoch: EpochId,
        new_expires_at_millis: u64,
        renewed_at_millis: u64,
    },
    /// Revoke a member's write-authority lease.
    LeaseRevoke {
        member_id: MemberId,
        lease_epoch: EpochId,
        revoked_at_millis: u64,
    },
    /// Propose a new membership epoch.
    EpochProposal {
        proposer: MemberId,
        proposed_epoch: EpochId,
        proposed_member_set: Vec<MemberId>,
        proposal_nonce: u64,
        proposed_at_millis: u64,
        /// Coordinator incarnation when this proposal was issued.
        incarnation: Incarnation,
    },
    /// Accept a proposed epoch.
    EpochAccept {
        acceptor: MemberId,
        proposal_nonce: u64,
        accepted_epoch: EpochId,
        accepted_at_millis: u64,
    },
    /// Commit an epoch after quorum accepts.
    EpochCommit {
        committed_member_set: Vec<MemberId>,
        epoch_number: EpochId,
        monotonic_epoch_counter: u64,
        committed_at_millis: u64,
    },
    /// Liveness heartbeat health report.
    HealthReport {
        member_id: MemberId,
        epoch: EpochId,
        health_class: u8,
        reported_at_millis: u64,
    },
    /// Anti-entropy digest for gossip reconciliation.
    GossipDigest {
        originator: MemberId,
        digest_epoch: EpochId,
        state_digest: [u8; 32],
        sent_at_millis: u64,
    },
    /// Incremental gossip delta carrying state changes.
    GossipDelta {
        originator: MemberId,
        delta_epoch: EpochId,
        delta_payload: Vec<u8>,
        sent_at_millis: u64,
    },
    /// Request to drain a node for graceful removal.
    DrainRequest {
        target_member_id: MemberId,
        drain_epoch: EpochId,
        requested_at_millis: u64,
    },
    /// Drain operation completed, node can be safely removed.
    DrainComplete {
        member_id: MemberId,
        drain_epoch: EpochId,
        completed_at_millis: u64,
    },
    /// Request to join the cluster.
    JoinRequest {
        member_id: MemberId,
        join_epoch: EpochId,
        created_at_millis: u64,
    },
    /// Response to a join request.
    JoinResponse {
        request_member_id: MemberId,
        accepted: bool,
        assigned_epoch: Option<EpochId>,
        reject_reason: Option<String>,
        responded_at_millis: u64,
        /// Coordinator incarnation at response time.
        incarnation: Incarnation,
    },
    /// Graceful leave notification.
    LeaveNotification {
        member_id: MemberId,
        departure_epoch: EpochId,
        announced_at_millis: u64,
        /// Reason for departure (voluntary, maintenance, draining).
        leave_reason: LeaveReason,
        /// Coordinator incarnation when this notice was issued.
        incarnation: Incarnation,
    },
    /// Push local roster state to a peer for gossip dissemination.
    PushRoster {
        originator: MemberId,
        roster_epoch: EpochId,
        roster_payload: Vec<u8>,
        sent_at_millis: u64,
    },
    /// Request a peer's current roster view.
    PullRequest {
        requester: MemberId,
        request_epoch: EpochId,
        sent_at_millis: u64,
    },
    /// Response to a pull request with the peer's roster state.
    PullResponse {
        responder: MemberId,
        roster_epoch: EpochId,
        roster_payload: Vec<u8>,
        responded_at_millis: u64,
    },
    /// Push a committed epoch view to connected peers for live roster synchronization.
    EpochPush {
        /// The epoch number being pushed.
        epoch_number: EpochId,
        /// Sorted, deduplicated member set at this epoch.
        member_set: Vec<MemberId>,
        /// Millisecond timestamp when the epoch was created.
        created_at_millis: u64,
    },
    /// Request missed epoch range from an up-to-date peer for catch-up after partition.
    EpochCatchUpRequest {
        /// Peer requesting the catch-up.
        requester: MemberId,
        /// First missing epoch (inclusive).
        from_epoch: u64,
        /// Last requested epoch (inclusive).
        to_epoch: u64,
    },
    /// Response to an EpochCatchUpRequest, carrying batched committed epoch views.
    EpochCatchUpResponse {
        /// Peer responding to the catch-up request.
        responder: MemberId,
        /// Batched committed epoch views, in ascending epoch-number order.
        epochs: Vec<CommittedEpochView>,
        /// True when the response is truncated (more epochs exist beyond the range).
        truncated: bool,
    },
    /// Submit an epoch proposal to peers for quorum collection.
    ProposalSubmission {
        /// The proposing member.
        proposer: MemberId,
        /// Current committed epoch before the transition.
        current_epoch: u64,
        /// Proposed next epoch (must equal current_epoch + 1).
        proposed_epoch: u64,
        /// The membership change driving this proposal.
        delta: MembershipDelta,
        /// Sorted, deduplicated member node IDs after applying the delta.
        resulting_members: Vec<u64>,
        /// BLAKE3-256 hash of the canonical proposal payload for ack matching.
        proposal_hash: [u8; 32],
        /// Millisecond timestamp when the proposal was submitted.
        submitted_at_millis: u64,
        /// Optional serialized [`CatalogDelta`] for a dataset catalog mutation
        /// proposed alongside or independently of the membership change.
        /// `None` when this proposal carries no catalog mutation.
        catalog_delta_bytes: Option<Vec<u8>>,
    },
    /// Acknowledge (accept or reject) a proposal from the commit coordinator.
    ProposalAck {
        /// Member sending the acknowledgment.
        responder: MemberId,
        /// BLAKE3-256 hash matching the proposal being acked.
        proposal_hash: [u8; 32],
        /// Whether the responder accepts the proposal.
        accepted: bool,
        /// Rejection reason when `accepted` is false.
        reject_reason: Option<String>,
        /// Millisecond timestamp when the ack was created.
        acked_at_millis: u64,
    },
    /// Notification broadcast when a new peer joins the cluster.
    ///
    /// Sent by the roster notifier to all existing connected members
    /// except the joining peer itself.
    PeerJoined {
        /// The peer that joined.
        member_id: MemberId,
        /// The roster epoch after the join.
        roster_epoch: EpochId,
    },
    /// Full roster state snapshot sent to a newly joined peer.
    ///
    /// Carries the complete current roster (members, classes, states,
    /// addresses, failure domains) so the joining peer can participate
    /// immediately without external bootstrap.
    RosterSnapshot {
        /// The existing member sending the snapshot.
        originator: MemberId,
        /// The epoch at which this snapshot was taken.
        roster_epoch: EpochId,
        /// Serialized roster entries.
        entries: Vec<crate::roster_sync::RosterEntryData>,
    },
    /// Coordinator heartbeat sent to each roster member for lease renewal.
    CoordinatorHeartbeat {
        /// Current membership epoch.
        epoch: EpochId,
        /// The coordinator sending the heartbeat.
        coordinator_id: MemberId,
        /// Monotonic nonce that increments on each heartbeat round.
        lease_nonce: u64,
    },
    /// Acknowledgment from a roster member to a coordinator heartbeat.
    CoordinatorHeartbeatAck {
        /// The epoch matching the heartbeat.
        epoch: EpochId,
        /// The member acknowledging the heartbeat.
        member_id: MemberId,
        /// Nonce from the heartbeat being acknowledged.
        lease_nonce: u64,
    },
    /// Batch of transition journal entries for peer synchronization.
    ///
    /// Carries a base epoch and a batch of journal entries representing
    /// roster transitions committed at or after that epoch.
    JournalSyncBatch {
        /// The local member sending this batch.
        originator: MemberId,
        /// The base epoch from which these entries start.
        base_epoch: u64,
        /// Serialized [`JournalSyncBatch`] payload.
        batch_payload: Vec<u8>,
    },
    /// A peer requests voluntary departure from the cluster.
    DepartureRequest {
        /// The peer requesting departure.
        peer_id: u64,
        /// Reason for departure (Voluntary or Evicted).
        reason: tidefs_membership_types::departure::DepartureReason,
        /// Current epoch when the request was created.
        request_epoch: u64,
        /// Monotonic nonce for request deduplication.
        nonce: u64,
    },
    /// Coordinator response to a departure request.
    DepartureResponse {
        /// The peer this response is addressed to.
        peer_id: u64,
        /// Whether the departure was accepted.
        accepted: bool,
        /// The epoch after the departure (successor epoch).
        successor_epoch: u64,
        /// Human-readable rejection reason when not accepted.
        reject_reason: Option<String>,
    },
}

impl MembershipOutboundMessage {
    /// The transport [`MessageFamily`] this outbound message carries.
    ///
    /// All membership protocol messages use `PublicationProgress` (m4),
    /// which carries proposals, commits, and progress vectors.
    #[must_use]
    pub fn message_family(&self) -> MessageFamily {
        MessageFamily::PublicationProgress
    }

    /// Human-readable variant name for logging and diagnostics.
    #[must_use]
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::LeaseGrant { .. } => "LeaseGrant",
            Self::LeaseRenew { .. } => "LeaseRenew",
            Self::LeaseRevoke { .. } => "LeaseRevoke",
            Self::EpochProposal { .. } => "EpochProposal",
            Self::EpochAccept { .. } => "EpochAccept",
            Self::EpochCommit { .. } => "EpochCommit",
            Self::HealthReport { .. } => "HealthReport",
            Self::GossipDigest { .. } => "GossipDigest",
            Self::GossipDelta { .. } => "GossipDelta",
            Self::DrainRequest { .. } => "DrainRequest",
            Self::DrainComplete { .. } => "DrainComplete",
            Self::JoinRequest { .. } => "JoinRequest",
            Self::JoinResponse { .. } => "JoinResponse",
            Self::LeaveNotification { .. } => "LeaveNotification",
            Self::PushRoster { .. } => "PushRoster",
            Self::PullRequest { .. } => "PullRequest",
            Self::PullResponse { .. } => "PullResponse",
            Self::EpochPush { .. } => "EpochPush",
            Self::EpochCatchUpRequest { .. } => "EpochCatchUpRequest",
            Self::EpochCatchUpResponse { .. } => "EpochCatchUpResponse",
            Self::ProposalSubmission { .. } => "ProposalSubmission",
            Self::ProposalAck { .. } => "ProposalAck",
            Self::PeerJoined { .. } => "PeerJoined",
            Self::RosterSnapshot { .. } => "RosterSnapshot",
            Self::CoordinatorHeartbeat { .. } => "CoordinatorHeartbeat",
            Self::CoordinatorHeartbeatAck { .. } => "CoordinatorHeartbeatAck",
            Self::JournalSyncBatch { .. } => "JournalSyncBatch",
            Self::DepartureRequest { .. } => "DepartureRequest",
            Self::DepartureResponse { .. } => "DepartureResponse",
        }
    }
}

// ---------------------------------------------------------------------------
// OutboundDispatchError
// ---------------------------------------------------------------------------

/// Errors from the membership outbound dispatch layer.
#[derive(Clone, Debug)]
pub enum OutboundDispatchError {
    /// The target member is not present in the membership roster.
    PeerNotInRoster { member_id: MemberId },
    /// Bincode serialization of the membership message failed.
    SerializationFailed(String),
    /// The transport send queue is at capacity (backpressure).
    Backpressure {
        member_id: MemberId,
        peer_id: PeerId,
        depth: usize,
        byte_depth: usize,
    },
    /// No transport send queue exists for the peer.
    NoTransportQueue {
        member_id: MemberId,
        peer_id: PeerId,
    },
    /// The transport send queue has been shut down.
    TransportShutdown {
        member_id: MemberId,
        peer_id: PeerId,
    },
}

impl fmt::Display for OutboundDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerNotInRoster { member_id } => {
                write!(f, "peer not in roster: member_id={}", member_id.0)
            }
            Self::SerializationFailed(msg) => {
                write!(f, "membership message serialization failed: {msg}")
            }
            Self::Backpressure {
                member_id,
                depth,
                byte_depth,
                ..
            } => {
                write!(
                    f,
                    "backpressure on peer {}: depth={depth} msgs, byte_depth={byte_depth}B",
                    member_id.0,
                )
            }
            Self::NoTransportQueue { member_id, .. } => {
                write!(f, "no transport queue for peer {}", member_id.0)
            }
            Self::TransportShutdown { member_id, .. } => {
                write!(f, "transport queue shut down for peer {}", member_id.0)
            }
        }
    }
}

impl std::error::Error for OutboundDispatchError {}

// ---------------------------------------------------------------------------
// BroadcastResult
// ---------------------------------------------------------------------------

/// Outcome of a broadcast operation.
///
/// A partially successful broadcast delivers to some peers and records
/// per-peer errors for the rest. Callers inspect `errors` to decide
/// whether to retry or escalate.
#[derive(Clone, Debug)]
pub struct BroadcastResult {
    /// Number of peers the message was successfully enqueued to.
    pub success_count: usize,
    /// Per-peer errors for peers where dispatch failed.
    pub errors: Vec<(MemberId, OutboundDispatchError)>,
}

impl BroadcastResult {
    /// Create a new broadcast result.
    pub fn new(success_count: usize, errors: Vec<(MemberId, OutboundDispatchError)>) -> Self {
        Self {
            success_count,
            errors,
        }
    }

    /// Whether every active peer in the roster received the broadcast.
    pub fn all_succeeded(&self) -> bool {
        self.errors.is_empty()
    }

    /// Whether no peer received the broadcast.
    pub fn all_failed(&self) -> bool {
        self.success_count == 0
    }
}

// ---------------------------------------------------------------------------
// MembershipOutboundDispatch -- the outbound bridge
// ---------------------------------------------------------------------------

/// Bridges membership outbound protocol messages to the transport
/// per-connection send pipeline.
///
/// Holds references to the transport [`SendDispatcher`] and the
/// membership [`MembershipRoster`]. Subsystems call [`send_to_peer`]
/// for unicast delivery or [`broadcast`] for epidemic fan-out.
///
/// # Example
///
/// ```ignore
/// let dispatch = MembershipOutboundDispatch::new(&send_dispatcher, &roster);
/// let msg = MembershipOutboundMessage::HealthReport { ... };
/// dispatch.send_to_peer(target_member, msg)?;
/// ```
///
/// [`send_to_peer`]: Self::send_to_peer
/// [`broadcast`]: Self::broadcast
pub struct MembershipOutboundDispatch<'a> {
    send_dispatcher: &'a SendDispatcher,
    roster: &'a MembershipRoster,
}

impl<'a> MembershipOutboundDispatch<'a> {
    /// Create a new outbound dispatch bridge.
    pub fn new(send_dispatcher: &'a SendDispatcher, roster: &'a MembershipRoster) -> Self {
        Self {
            send_dispatcher,
            roster,
        }
    }

    /// Send a membership protocol message to a single peer.
    ///
    /// 1. Looks up the target member in the roster snapshot.
    /// 2. Serializes the message with bincode.
    /// 3. Wraps it in a transport [`OutboundMessage`].
    /// 4. Enqueues through the transport [`SendDispatcher`].
    ///
    /// # Errors
    ///
    /// Returns [`OutboundDispatchError::PeerNotInRoster`] if the target
    /// member is not in the roster. Propagates transport backpressure,
    /// queue-not-found, and shutdown errors with member context.
    pub fn send_to_peer(
        &self,
        member_id: MemberId,
        message: MembershipOutboundMessage,
    ) -> Result<(), OutboundDispatchError> {
        // Verify the target is a known roster member.
        let snapshot = self.roster.snapshot();
        let _state = snapshot
            .lookup(member_id)
            .ok_or(OutboundDispatchError::PeerNotInRoster { member_id })?;

        // Serialize the membership message.
        let payload = bincode::serialize(&message)
            .map_err(|e| OutboundDispatchError::SerializationFailed(e.to_string()))?;

        // Map MemberId -> PeerId (both are u64).
        let peer_id: PeerId = member_id.0;
        let family = message.message_family();
        let outbound = OutboundMessage::new(family, payload);

        // Enqueue through the transport send pipeline.
        self.send_dispatcher
            .enqueue(peer_id, outbound)
            .map(|_| ())
            .map_err(|e| Self::map_send_error(member_id, e))
    }

    /// Broadcast a membership protocol message to all active roster peers.
    ///
    /// Iterates the roster snapshot, cloning the message for each active
    /// member, and enqueues through [`send_to_peer`]. Returns a
    /// [`BroadcastResult`] with per-peer error details.
    ///
    /// The broadcast skips peers not in the `Active` roster state.
    pub fn broadcast(&self, message: MembershipOutboundMessage) -> BroadcastResult {
        let snapshot = self.roster.snapshot();
        let mut success_count = 0usize;
        let mut errors = Vec::new();

        for (member_id, state) in snapshot.iter() {
            if *state != RosterState::Active {
                continue;
            }
            match self.send_to_peer(*member_id, message.clone()) {
                Ok(()) => success_count += 1,
                Err(e) => errors.push((*member_id, e)),
            }
        }

        BroadcastResult::new(success_count, errors)
    }

    /// Map a transport [`SendError`] to an [`OutboundDispatchError`] with
    /// member context.
    fn map_send_error(member_id: MemberId, e: SendError) -> OutboundDispatchError {
        match e {
            SendError::Backpressure {
                conn_id,
                depth,
                byte_depth,
                ..
            } => OutboundDispatchError::Backpressure {
                member_id,
                peer_id: conn_id,
                depth,
                byte_depth,
            },
            SendError::NoConnection { conn_id, .. } => OutboundDispatchError::NoTransportQueue {
                member_id,
                peer_id: conn_id,
            },
            SendError::Shutdown { conn_id, .. } => OutboundDispatchError::TransportShutdown {
                member_id,
                peer_id: conn_id,
            },
            SendError::SendConcurrencyLimitExceeded {
                conn_id, max: _, ..
            } => OutboundDispatchError::Backpressure {
                member_id,
                peer_id: conn_id,
                depth: 0,
                byte_depth: 0,
            },
            SendError::SendQueueFull {
                lane: _,
                depth,
                max_depth: _,
                ..
            } => {
                OutboundDispatchError::Backpressure {
                    member_id,
                    peer_id: member_id.0, // lane-class full; propagate as backpressure on member
                    depth,
                    byte_depth: 0,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_transport::send_dispatch::SendQueueConfig;

    fn test_queue_config() -> SendQueueConfig {
        SendQueueConfig::new(256, 1_048_576).unwrap()
    }

    // ------------------------------------------------------------------
    // MembershipOutboundMessage tests
    // ------------------------------------------------------------------

    #[test]
    fn all_variants_have_distinct_names() {
        let names: Vec<&str> = vec![
            MembershipOutboundMessage::LeaseGrant {
                member_id: MemberId::new(1),
                lease_epoch: EpochId::new(0),
                lease_expires_at_millis: 0,
                granted_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::LeaseRenew {
                member_id: MemberId::new(1),
                lease_epoch: EpochId::new(0),
                new_expires_at_millis: 0,
                renewed_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::LeaseRevoke {
                member_id: MemberId::new(1),
                lease_epoch: EpochId::new(0),
                revoked_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::EpochProposal {
                proposer: MemberId::new(1),
                proposed_epoch: EpochId::new(0),
                proposed_member_set: vec![],
                proposal_nonce: 0,
                proposed_at_millis: 0,
                incarnation: Incarnation::ZERO,
            }
            .variant_name(),
            MembershipOutboundMessage::EpochAccept {
                acceptor: MemberId::new(1),
                proposal_nonce: 0,
                accepted_epoch: EpochId::new(0),
                accepted_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::EpochCommit {
                committed_member_set: vec![],
                epoch_number: EpochId::new(0),
                monotonic_epoch_counter: 0,
                committed_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::HealthReport {
                member_id: MemberId::new(1),
                epoch: EpochId::new(0),
                health_class: 0,
                reported_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::GossipDigest {
                originator: MemberId::new(1),
                digest_epoch: EpochId::new(0),
                state_digest: [0u8; 32],
                sent_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::GossipDelta {
                originator: MemberId::new(1),
                delta_epoch: EpochId::new(0),
                delta_payload: vec![],
                sent_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::DrainRequest {
                target_member_id: MemberId::new(1),
                drain_epoch: EpochId::new(0),
                requested_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::DrainComplete {
                member_id: MemberId::new(1),
                drain_epoch: EpochId::new(0),
                completed_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::JoinRequest {
                member_id: MemberId::new(1),
                join_epoch: EpochId::new(0),
                created_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::JoinResponse {
                request_member_id: MemberId::new(1),
                accepted: true,
                assigned_epoch: None,
                reject_reason: None,
                responded_at_millis: 0,
                incarnation: Incarnation::ZERO,
            }
            .variant_name(),
            MembershipOutboundMessage::LeaveNotification {
                member_id: MemberId::new(1),
                departure_epoch: EpochId::new(0),
                announced_at_millis: 0,
                leave_reason: LeaveReason::Voluntary,
                incarnation: Incarnation::ZERO,
            }
            .variant_name(),
            MembershipOutboundMessage::EpochPush {
                epoch_number: EpochId::new(0),
                member_set: vec![],
                created_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::EpochCatchUpRequest {
                requester: MemberId::new(1),
                from_epoch: 1,
                to_epoch: 5,
            }
            .variant_name(),
            MembershipOutboundMessage::EpochCatchUpResponse {
                responder: MemberId::new(1),
                epochs: vec![],
                truncated: false,
            }
            .variant_name(),
            MembershipOutboundMessage::ProposalSubmission {
                proposer: MemberId::new(1),
                current_epoch: 0,
                proposed_epoch: 1,
                delta: MembershipDelta::NodeJoined(2),
                resulting_members: vec![1, 2],
                proposal_hash: [0u8; 32],
                submitted_at_millis: 0,
                catalog_delta_bytes: None,
            }
            .variant_name(),
            MembershipOutboundMessage::ProposalAck {
                responder: MemberId::new(2),
                proposal_hash: [0u8; 32],
                accepted: true,
                reject_reason: None,
                acked_at_millis: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::PeerJoined {
                member_id: MemberId::new(3),
                roster_epoch: EpochId::new(2),
            }
            .variant_name(),
            MembershipOutboundMessage::RosterSnapshot {
                originator: MemberId::new(1),
                roster_epoch: EpochId::new(2),
                entries: vec![],
            }
            .variant_name(),
            MembershipOutboundMessage::CoordinatorHeartbeat {
                epoch: EpochId::new(3),
                coordinator_id: MemberId::new(1),
                lease_nonce: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::CoordinatorHeartbeatAck {
                epoch: EpochId::new(3),
                member_id: MemberId::new(2),
                lease_nonce: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::JournalSyncBatch {
                originator: MemberId::new(1),
                base_epoch: 0,
                batch_payload: vec![],
            }
            .variant_name(),
            MembershipOutboundMessage::DepartureRequest {
                peer_id: 1,
                reason: tidefs_membership_types::departure::DepartureReason::Voluntary,
                request_epoch: 0,
                nonce: 0,
            }
            .variant_name(),
            MembershipOutboundMessage::DepartureResponse {
                peer_id: 1,
                accepted: true,
                successor_epoch: 1,
                reject_reason: None,
            }
            .variant_name(),
        ];

        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 26, "all 26 variants must have distinct names");
    }

    #[test]
    fn bincode_roundtrip_all_variants() {
        let messages: Vec<MembershipOutboundMessage> = vec![
            MembershipOutboundMessage::LeaseGrant {
                member_id: MemberId::new(1),
                lease_epoch: EpochId::new(5),
                lease_expires_at_millis: 1000,
                granted_at_millis: 500,
            },
            MembershipOutboundMessage::LeaseRenew {
                member_id: MemberId::new(2),
                lease_epoch: EpochId::new(5),
                new_expires_at_millis: 2000,
                renewed_at_millis: 1500,
            },
            MembershipOutboundMessage::LeaseRevoke {
                member_id: MemberId::new(3),
                lease_epoch: EpochId::new(5),
                revoked_at_millis: 2000,
            },
            MembershipOutboundMessage::EpochProposal {
                proposer: MemberId::new(1),
                proposed_epoch: EpochId::new(10),
                proposed_member_set: vec![MemberId::new(1), MemberId::new(2)],
                proposal_nonce: 42,
                proposed_at_millis: 3000,
                incarnation: Incarnation::ZERO,
            },
            MembershipOutboundMessage::EpochAccept {
                acceptor: MemberId::new(2),
                proposal_nonce: 42,
                accepted_epoch: EpochId::new(10),
                accepted_at_millis: 3100,
            },
            MembershipOutboundMessage::EpochCommit {
                committed_member_set: vec![MemberId::new(1), MemberId::new(2)],
                epoch_number: EpochId::new(10),
                monotonic_epoch_counter: 10,
                committed_at_millis: 3200,
            },
            MembershipOutboundMessage::HealthReport {
                member_id: MemberId::new(1),
                epoch: EpochId::new(10),
                health_class: 1,
                reported_at_millis: 4000,
            },
            MembershipOutboundMessage::GossipDigest {
                originator: MemberId::new(1),
                digest_epoch: EpochId::new(10),
                state_digest: [0xABu8; 32],
                sent_at_millis: 5000,
            },
            MembershipOutboundMessage::GossipDelta {
                originator: MemberId::new(1),
                delta_epoch: EpochId::new(10),
                delta_payload: vec![1, 2, 3],
                sent_at_millis: 5100,
            },
            MembershipOutboundMessage::DrainRequest {
                target_member_id: MemberId::new(3),
                drain_epoch: EpochId::new(10),
                requested_at_millis: 6000,
            },
            MembershipOutboundMessage::DrainComplete {
                member_id: MemberId::new(3),
                drain_epoch: EpochId::new(10),
                completed_at_millis: 7000,
            },
            MembershipOutboundMessage::JoinRequest {
                member_id: MemberId::new(4),
                join_epoch: EpochId::new(10),
                created_at_millis: 8000,
            },
            MembershipOutboundMessage::JoinResponse {
                request_member_id: MemberId::new(4),
                accepted: true,
                assigned_epoch: Some(EpochId::new(10)),
                reject_reason: None,
                responded_at_millis: 8100,
                incarnation: Incarnation::ZERO,
            },
            MembershipOutboundMessage::LeaveNotification {
                member_id: MemberId::new(1),
                departure_epoch: EpochId::new(10),
                announced_at_millis: 9000,
                leave_reason: LeaveReason::Voluntary,
                incarnation: Incarnation::ZERO,
            },
            MembershipOutboundMessage::EpochPush {
                epoch_number: EpochId::new(15),
                member_set: vec![MemberId::new(10), MemberId::new(20)],
                created_at_millis: 10000,
            },
            MembershipOutboundMessage::EpochCatchUpRequest {
                requester: MemberId::new(1),
                from_epoch: 3,
                to_epoch: 7,
            },
            MembershipOutboundMessage::EpochCatchUpResponse {
                responder: MemberId::new(2),
                epochs: vec![],
                truncated: true,
            },
            MembershipOutboundMessage::ProposalSubmission {
                proposer: MemberId::new(1),
                current_epoch: 5,
                proposed_epoch: 6,
                delta: MembershipDelta::NodeJoined(3),
                resulting_members: vec![1, 2, 3],
                proposal_hash: [0xAAu8; 32],
                submitted_at_millis: 11000,
                catalog_delta_bytes: None,
            },
            MembershipOutboundMessage::ProposalAck {
                responder: MemberId::new(2),
                proposal_hash: [0xAAu8; 32],
                accepted: true,
                reject_reason: None,
                acked_at_millis: 11100,
            },
            MembershipOutboundMessage::RosterSnapshot {
                originator: MemberId::new(1),
                roster_epoch: EpochId::new(2),
                entries: vec![],
            },
            MembershipOutboundMessage::CoordinatorHeartbeat {
                epoch: EpochId::new(7),
                coordinator_id: MemberId::new(1),
                lease_nonce: 42,
            },
            MembershipOutboundMessage::CoordinatorHeartbeatAck {
                epoch: EpochId::new(7),
                member_id: MemberId::new(3),
                lease_nonce: 42,
            },
            MembershipOutboundMessage::JournalSyncBatch {
                originator: MemberId::new(1),
                base_epoch: 0,
                batch_payload: vec![],
            },
            MembershipOutboundMessage::DepartureRequest {
                peer_id: 1,
                reason: tidefs_membership_types::departure::DepartureReason::Voluntary,
                request_epoch: 0,
                nonce: 0,
            },
            MembershipOutboundMessage::DepartureResponse {
                peer_id: 1,
                accepted: true,
                successor_epoch: 1,
                reject_reason: None,
            },
        ];

        assert_eq!(messages.len(), 25);

        for (i, msg) in messages.iter().enumerate() {
            let encoded = bincode::serialize(msg).expect("bincode serialize");
            let decoded: MembershipOutboundMessage =
                bincode::deserialize(&encoded).expect("bincode deserialize");
            assert_eq!(msg, &decoded, "roundtrip failed for variant at index {i}");
        }
    }

    #[test]
    fn message_family_is_publication_progress() {
        let msg = MembershipOutboundMessage::HealthReport {
            member_id: MemberId::new(1),
            epoch: EpochId::new(0),
            health_class: 0,
            reported_at_millis: 0,
        };
        assert_eq!(msg.message_family(), MessageFamily::PublicationProgress);
    }

    #[test]
    fn clone_produces_equal_message() {
        let msg = MembershipOutboundMessage::LeaseGrant {
            member_id: MemberId::new(42),
            lease_epoch: EpochId::new(7),
            lease_expires_at_millis: 1000,
            granted_at_millis: 500,
        };
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    // ------------------------------------------------------------------
    // OutboundDispatchError tests
    // ------------------------------------------------------------------

    #[test]
    fn error_display_peer_not_in_roster() {
        let e = OutboundDispatchError::PeerNotInRoster {
            member_id: MemberId::new(99),
        };
        let s = format!("{e}");
        assert!(s.contains("peer not in roster"));
        assert!(s.contains("99"));
    }

    #[test]
    fn error_display_serialization_failed() {
        let e = OutboundDispatchError::SerializationFailed("bad bytes".into());
        let s = format!("{e}");
        assert!(s.contains("serialization failed"));
        assert!(s.contains("bad bytes"));
    }

    #[test]
    fn error_display_backpressure() {
        let e = OutboundDispatchError::Backpressure {
            member_id: MemberId::new(7),
            peer_id: 7,
            depth: 5,
            byte_depth: 1024,
        };
        let s = format!("{e}");
        assert!(s.contains("backpressure"));
        assert!(s.contains("7"));
        assert!(s.contains("5"));
        assert!(s.contains("1024"));
    }

    #[test]
    fn error_display_no_transport_queue() {
        let e = OutboundDispatchError::NoTransportQueue {
            member_id: MemberId::new(3),
            peer_id: 3,
        };
        let s = format!("{e}");
        assert!(s.contains("no transport queue"));
        assert!(s.contains("3"));
    }

    #[test]
    fn error_display_transport_shutdown() {
        let e = OutboundDispatchError::TransportShutdown {
            member_id: MemberId::new(5),
            peer_id: 5,
        };
        let s = format!("{e}");
        assert!(s.contains("shut down"));
        assert!(s.contains("5"));
    }

    #[test]
    fn error_is_std_error() {
        let e = OutboundDispatchError::PeerNotInRoster {
            member_id: MemberId::new(1),
        };
        let _: &dyn std::error::Error = &e;
    }

    // ------------------------------------------------------------------
    // BroadcastResult tests
    // ------------------------------------------------------------------

    #[test]
    fn broadcast_result_all_succeeded() {
        let r = BroadcastResult::new(5, vec![]);
        assert!(r.all_succeeded());
        assert!(!r.all_failed());
    }

    #[test]
    fn broadcast_result_all_failed() {
        let r = BroadcastResult::new(
            0,
            vec![(
                MemberId::new(1),
                OutboundDispatchError::PeerNotInRoster {
                    member_id: MemberId::new(1),
                },
            )],
        );
        assert!(!r.all_succeeded());
        assert!(r.all_failed());
    }

    #[test]
    fn broadcast_result_partial() {
        let r = BroadcastResult::new(
            3,
            vec![(
                MemberId::new(4),
                OutboundDispatchError::PeerNotInRoster {
                    member_id: MemberId::new(4),
                },
            )],
        );
        assert!(!r.all_succeeded());
        assert!(!r.all_failed());
    }

    // ------------------------------------------------------------------
    // MembershipOutboundDispatch tests
    // ------------------------------------------------------------------

    #[test]
    fn send_to_peer_unknown_member_returns_error() {
        let dispatcher = SendDispatcher::new(test_queue_config(), ErrorClassifier, None);
        let roster = MembershipRoster::new();
        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);

        let msg = MembershipOutboundMessage::HealthReport {
            member_id: MemberId::new(99),
            epoch: EpochId::new(0),
            health_class: 0,
            reported_at_millis: 0,
        };

        let result = dispatch.send_to_peer(MemberId::new(99), msg);
        assert!(matches!(
            result,
            Err(OutboundDispatchError::PeerNotInRoster { .. })
        ));
    }

    #[test]
    fn send_to_peer_enqueues_successfully() {
        let dispatcher = SendDispatcher::new(test_queue_config(), ErrorClassifier, None);
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(42));

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);

        let msg = MembershipOutboundMessage::HealthReport {
            member_id: MemberId::new(42),
            epoch: EpochId::new(0),
            health_class: 0,
            reported_at_millis: 100,
        };

        let result = dispatch.send_to_peer(MemberId::new(42), msg.clone());
        assert!(result.is_ok(), "send_to_peer failed: {result:?}");

        // Verify the message landed in the transport queue.
        let q = dispatcher
            .queue(42)
            .expect("queue should exist after enqueue");
        assert_eq!(q.depth(), 1);

        let drained = q.dequeue().expect("should have one message");
        let decoded: MembershipOutboundMessage =
            bincode::deserialize(&drained.payload).expect("deserialize from transport queue");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn broadcast_to_active_peers() {
        let dispatcher = SendDispatcher::new(test_queue_config(), ErrorClassifier, None);
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1));
        roster.add_member(MemberId::new(2));
        roster.add_member(MemberId::new(3));

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);

        let msg = MembershipOutboundMessage::HealthReport {
            member_id: MemberId::new(0),
            epoch: EpochId::new(1),
            health_class: 1,
            reported_at_millis: 200,
        };

        let result = dispatch.broadcast(msg);
        assert_eq!(result.success_count, 3);
        assert!(result.all_succeeded());

        for peer_id in [1u64, 2, 3] {
            let q = dispatcher
                .queue(peer_id)
                .expect("queue should exist for peer");
            assert_eq!(q.depth(), 1, "peer {peer_id} should have one message");
        }
    }

    #[test]
    fn broadcast_skips_non_active_peers() {
        let dispatcher = SendDispatcher::new(test_queue_config(), ErrorClassifier, None);
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1));
        roster.add_member(MemberId::new(2));
        roster.add_member(MemberId::new(3));

        // Transition member 2 to Suspected.
        roster
            .transition_state(MemberId::new(2), RosterState::Suspected)
            .expect("transition should succeed");

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);

        let msg = MembershipOutboundMessage::HealthReport {
            member_id: MemberId::new(0),
            epoch: EpochId::new(1),
            health_class: 1,
            reported_at_millis: 200,
        };

        let result = dispatch.broadcast(msg);
        assert_eq!(result.success_count, 2, "should skip suspected peer");
        assert!(result.all_succeeded());

        assert_eq!(dispatcher.queue(1).unwrap().depth(), 1);
        assert_eq!(dispatcher.queue(3).unwrap().depth(), 1);
        // Peer 2 (suspected) should NOT have a queue.
        assert!(dispatcher.queue(2).is_none());
    }

    #[test]
    fn broadcast_empty_roster_returns_zero() {
        let dispatcher = SendDispatcher::new(test_queue_config(), ErrorClassifier, None);
        let roster = MembershipRoster::new();
        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);

        let msg = MembershipOutboundMessage::HealthReport {
            member_id: MemberId::new(0),
            epoch: EpochId::new(0),
            health_class: 0,
            reported_at_millis: 0,
        };

        let result = dispatch.broadcast(msg);
        assert_eq!(result.success_count, 0);
        assert!(result.all_succeeded());
        assert!(result.all_failed());
    }

    #[test]
    fn backpressure_propagates_as_error() {
        // Use a very constrained queue to trigger backpressure.
        let config = SendQueueConfig::new(1, 64).unwrap();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier, None);
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1));

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);

        // First message fits.
        let msg1 = MembershipOutboundMessage::HealthReport {
            member_id: MemberId::new(0),
            epoch: EpochId::new(0),
            health_class: 0,
            reported_at_millis: 0,
        };
        dispatch.send_to_peer(MemberId::new(1), msg1).unwrap();

        // Second message should trigger backpressure (queue cap = 1).
        let msg2 = MembershipOutboundMessage::HealthReport {
            member_id: MemberId::new(0),
            epoch: EpochId::new(0),
            health_class: 0,
            reported_at_millis: 0,
        };
        let result = dispatch.send_to_peer(MemberId::new(1), msg2);
        match result {
            Err(OutboundDispatchError::Backpressure {
                member_id, depth, ..
            }) => {
                assert_eq!(member_id.0, 1);
                assert_eq!(depth, 1);
            }
            other => panic!("expected Backpressure, got: {other:?}"),
        }
    }

    #[test]
    fn send_to_peer_serializes_through_bincode() {
        let dispatcher = SendDispatcher::new(test_queue_config(), ErrorClassifier, None);
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(10));

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);

        let original = MembershipOutboundMessage::DrainComplete {
            member_id: MemberId::new(10),
            drain_epoch: EpochId::new(3),
            completed_at_millis: 9999,
        };

        dispatch
            .send_to_peer(MemberId::new(10), original.clone())
            .unwrap();

        let q = dispatcher.queue(10).unwrap();
        let drained = q.dequeue().unwrap();
        let decoded: MembershipOutboundMessage = bincode::deserialize(&drained.payload).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn broadcast_with_failed_and_succeeded_peers() {
        // Two active peers, one non-existent — broadcast should report
        // partial success.
        let dispatcher = SendDispatcher::new(test_queue_config(), ErrorClassifier, None);
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(10));
        roster.add_member(MemberId::new(20));
        roster.add_member(MemberId::new(30));

        // Transition 30 to Failed — broadcast skips non-Active peers.
        roster
            .transition_state(MemberId::new(30), RosterState::Suspected)
            .unwrap();
        roster
            .transition_state(MemberId::new(30), RosterState::Failed)
            .unwrap();

        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);

        let msg = MembershipOutboundMessage::HealthReport {
            member_id: MemberId::new(0),
            epoch: EpochId::new(0),
            health_class: 0,
            reported_at_millis: 0,
        };

        let result = dispatch.broadcast(msg);
        assert_eq!(result.success_count, 2, "only active peers should receive");
        assert!(result.errors.is_empty());
        assert!(dispatcher.queue(10).is_some());
        assert!(dispatcher.queue(20).is_some());
        assert!(dispatcher.queue(30).is_none());
    }
}
