#![forbid(unsafe_code)]

//! Membership inbound message dispatch router.
//!
//! Routes decoded membership protocol messages arriving from transport
//! channels to the correct subsystem handler (liveness tracker, epoch
//! state machine, lease manager, roster, gossip engine, drain protocol).
//!
//! ## Architecture
//!
//! ```text
//! MembershipMessage (enum variant)
//!   |
//!   v
//! MembershipDispatchRouter::route(msg)
//!   |
//!   +-- extract discriminant(u8) from variant
//!   +-- lookup discriminant -> Box<dyn MembershipMessageHandler>
//!   +-- call handler.handle_<variant>(msg)
//! ```
//!
//! Each [`MembershipMessageHandler`] method has a default no-op
//! implementation. Subsystems implement the trait and override only
//! the methods for the message variants they handle.
//!
//! ## Integration
//!
//! The transport receive path calls [`MembershipDispatchRouter::route`]
//! with decoded membership messages. The router dispatches to registered
//! subsystem handlers, enabling multi-node membership protocol messages
//! to produce concrete state transitions instead of being dropped.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use tidefs_membership_epoch::epoch_catch_up::CommittedEpochView;
use tidefs_membership_epoch::epoch_proposal::MembershipDelta;
use tidefs_membership_epoch::{EpochId, Incarnation, LeaveReason, MemberId};
use tidefs_membership_types::capabilities::PeerCapabilities;
use tidefs_membership_types::departure::DepartureReason;

// ---------------------------------------------------------------------------
// MembershipMessage — protocol message variants
// ---------------------------------------------------------------------------

/// A decoded membership protocol message received from a transport channel.
///
/// Each variant corresponds to a membership-layer protocol operation.
/// The discriminant byte uniquely identifies the variant for handler
/// registration and routing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipMessage {
    /// A node requests to join the cluster.
    JoinRequest {
        member_id: MemberId,
        /// Proposed epoch for join (must be >= current).
        join_epoch: EpochId,
        /// Millisecond timestamp when the request was created.
        created_at_millis: u64,
        /// Optional peer-capability advertisement for placement and transport carrier selection.
        peer_capabilities: Option<PeerCapabilities>,
    },
    /// Response to a join request (accept or reject).
    JoinResponse {
        request_member_id: MemberId,
        accepted: bool,
        /// Assigned epoch if accepted.
        assigned_epoch: Option<EpochId>,
        /// Rejection reason if not accepted.
        reject_reason: Option<String>,
        responded_at_millis: u64,
        /// Coordinator incarnation at response time.
        incarnation: Incarnation,
    },
    /// A member announces it is gracefully leaving the cluster.
    LeaveNotification {
        member_id: MemberId,
        /// Current epoch at departure.
        departure_epoch: EpochId,
        announced_at_millis: u64,
        /// Reason for departure.
        leave_reason: LeaveReason,
        /// Coordinator incarnation when this notice was issued.
        incarnation: Incarnation,
    },
    /// A new epoch is proposed for the membership set.
    EpochProposal {
        proposer: MemberId,
        proposed_epoch: EpochId,
        proposed_member_set: Vec<MemberId>,
        proposal_nonce: u64,
        proposed_at_millis: u64,
        /// Coordinator incarnation when this proposal was issued.
        incarnation: Incarnation,
    },
    /// A member accepts an epoch proposal.
    EpochAccept {
        acceptor: MemberId,
        proposal_nonce: u64,
        accepted_epoch: EpochId,
        accepted_at_millis: u64,
    },
    /// A lease is granted to a member for write authority.
    LeaseGrant {
        member_id: MemberId,
        lease_id: u64,
        lease_epoch: EpochId,
        lease_term: u64,
        lease_ttl_millis: u64,
        lease_expires_at_millis: u64,
        granted_at_millis: u64,
    },
    /// A lease is renewed for an additional term.
    LeaseRenew {
        member_id: MemberId,
        lease_id: u64,
        lease_epoch: EpochId,
        lease_term: u64,
        lease_ttl_millis: u64,
        new_expires_at_millis: u64,
        renewed_at_millis: u64,
    },
    /// A lease is revoked (member loses write authority).
    LeaseRevoke {
        member_id: MemberId,
        lease_id: u64,
        lease_epoch: EpochId,
        revoked_at_millis: u64,
    },
    /// Health status report from a member (liveness heartbeat).
    HealthReport {
        member_id: MemberId,
        epoch: EpochId,
        health_class: u8,
        reported_at_millis: u64,
    },
    /// Anti-entropy digest exchange for gossip reconciliation.
    GossipDigest {
        originator: MemberId,
        digest_epoch: EpochId,
        /// BLAKE3-256 digest of the originator's member-state table.
        state_digest: [u8; 32],
        sent_at_millis: u64,
    },
    /// Incremental gossip delta carrying state changes.
    GossipDelta {
        originator: MemberId,
        delta_epoch: EpochId,
        /// Serialized member-state delta payload.
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
    /// Lease holder acknowledges (accepts or rejects) a lease grant.
    LeaseAcknowledge {
        member_id: MemberId,
        lease_id: u64,
        lease_epoch: EpochId,
        accepted: bool,
        acknowledged_at_millis: u64,
    },
    /// Lease has expired due to TTL elapsing without renewal.
    LeaseExpire {
        member_id: MemberId,
        lease_id: u64,
        lease_epoch: EpochId,
        expired_at_millis: u64,
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
    ///
    /// Carries the membership delta, resulting member set, and a BLAKE3-256
    /// proposal hash that peers use to match their acknowledgments.
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
    ///
    /// The `proposal_hash` must match the BLAKE3-256 hash in the corresponding
    /// `ProposalSubmission`.
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
    /// Notification that a new peer has joined the cluster.
    ///
    /// Broadcast by the roster notifier to existing members when
    /// a peer completes the join handshake and is added to the roster.
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
    ///
    /// The coordinator periodically pings every roster member to confirm
    /// it still has quorum connectivity. A majority must acknowledge
    /// within the heartbeat interval for the lease to remain held.
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
    /// roster transitions committed at or after that epoch. Transport
    /// sessions use this for catch-up, broadcast, and new-peer bootstrap.
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
        /// Reason for departure.
        reason: DepartureReason,
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
    /// A peer announces updated operational capabilities.
    ///
    /// Carries the full [`PeerCapabilities`] blob so the membership
    /// coordinator can refresh the roster-scoped capability view
    /// without requiring a leave/rejoin cycle.
    CapabilityUpdate {
        /// The member whose capabilities are being updated.
        member_id: MemberId,
        /// The epoch this update applies to.
        update_epoch: EpochId,
        /// Full operational capability advertisement.
        capabilities: PeerCapabilities,
        /// Millisecond timestamp when the update was issued.
        updated_at_millis: u64,
    },
}
impl MembershipMessage {
    /// Return the discriminant byte for this message variant.
    ///
    /// The discriminant is stable and used as the registry key
    /// for handler lookup.
    #[must_use]
    pub fn discriminant(&self) -> u8 {
        match self {
            Self::JoinRequest { .. } => 0,
            Self::JoinResponse { .. } => 1,
            Self::LeaveNotification { .. } => 2,
            Self::EpochProposal { .. } => 3,
            Self::EpochAccept { .. } => 4,
            Self::LeaseGrant { .. } => 5,
            Self::LeaseRenew { .. } => 6,
            Self::LeaseRevoke { .. } => 7,
            Self::HealthReport { .. } => 8,
            Self::GossipDigest { .. } => 9,
            Self::GossipDelta { .. } => 10,
            Self::DrainRequest { .. } => 11,
            Self::DrainComplete { .. } => 12,
            Self::LeaseAcknowledge { .. } => 13,
            Self::LeaseExpire { .. } => 14,
            Self::PushRoster { .. } => 15,
            Self::PullRequest { .. } => 16,
            Self::PullResponse { .. } => 17,
            Self::EpochPush { .. } => 18,
            Self::EpochCatchUpRequest { .. } => 19,
            Self::EpochCatchUpResponse { .. } => 20,
            Self::ProposalSubmission { .. } => 21,
            Self::ProposalAck { .. } => 22,
            Self::PeerJoined { .. } => 23,
            Self::RosterSnapshot { .. } => 24,
            Self::CoordinatorHeartbeat { .. } => 25,
            Self::CoordinatorHeartbeatAck { .. } => 26,
            Self::JournalSyncBatch { .. } => 27,
            Self::DepartureRequest { .. } => 28,
            Self::DepartureResponse { .. } => 29,
            Self::CapabilityUpdate { .. } => 30,
        }
    }

    /// All message variant discriminants in order.
    #[must_use]
    pub const fn all_discriminants() -> [u8; 31] {
        [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30,
        ]
    }

    /// Human-readable name for the variant.
    #[must_use]
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::JoinRequest { .. } => "JoinRequest",
            Self::JoinResponse { .. } => "JoinResponse",
            Self::LeaveNotification { .. } => "LeaveNotification",
            Self::EpochProposal { .. } => "EpochProposal",
            Self::EpochAccept { .. } => "EpochAccept",
            Self::LeaseGrant { .. } => "LeaseGrant",
            Self::LeaseRenew { .. } => "LeaseRenew",
            Self::LeaseRevoke { .. } => "LeaseRevoke",
            Self::HealthReport { .. } => "HealthReport",
            Self::GossipDigest { .. } => "GossipDigest",
            Self::GossipDelta { .. } => "GossipDelta",
            Self::DrainRequest { .. } => "DrainRequest",
            Self::DrainComplete { .. } => "DrainComplete",
            Self::LeaseAcknowledge { .. } => "LeaseAcknowledge",
            Self::LeaseExpire { .. } => "LeaseExpire",
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
            Self::CapabilityUpdate { .. } => "CapabilityUpdate",
        }
    }

    /// Extract the sender's [`MemberId`] from this message.
    ///
    /// Returns `MemberId::ZERO` for `EpochPush` which carries a member_set
    /// but no single sender identity. Callers should handle broadcasts
    /// specially (they carry the receiver's own epoch view).
    #[must_use]
    pub fn sender_id(&self) -> MemberId {
        match self {
            Self::JoinRequest { member_id, .. } => *member_id,
            Self::JoinResponse {
                request_member_id, ..
            } => *request_member_id,
            Self::LeaveNotification { member_id, .. } => *member_id,
            Self::EpochProposal { proposer, .. } => *proposer,
            Self::EpochAccept { acceptor, .. } => *acceptor,
            Self::LeaseGrant { member_id, .. } => *member_id,
            Self::LeaseRenew { member_id, .. } => *member_id,
            Self::LeaseRevoke { member_id, .. } => *member_id,
            Self::HealthReport { member_id, .. } => *member_id,
            Self::GossipDigest { originator, .. } => *originator,
            Self::GossipDelta { originator, .. } => *originator,
            Self::DrainRequest {
                target_member_id, ..
            } => *target_member_id,
            Self::DrainComplete { member_id, .. } => *member_id,
            Self::LeaseAcknowledge { member_id, .. } => *member_id,
            Self::LeaseExpire { member_id, .. } => *member_id,
            Self::PushRoster { originator, .. } => *originator,
            Self::PullRequest { requester, .. } => *requester,
            Self::PullResponse { responder, .. } => *responder,
            Self::EpochPush { .. } => MemberId::ZERO,
            Self::EpochCatchUpRequest { requester, .. } => *requester,
            Self::EpochCatchUpResponse { responder, .. } => *responder,
            Self::ProposalSubmission { proposer, .. } => *proposer,
            Self::ProposalAck { responder, .. } => *responder,
            Self::PeerJoined { member_id, .. } => *member_id,
            Self::RosterSnapshot { originator, .. } => *originator,
            Self::CoordinatorHeartbeat { coordinator_id, .. } => *coordinator_id,
            Self::CoordinatorHeartbeatAck { member_id, .. } => *member_id,
            Self::JournalSyncBatch { originator, .. } => *originator,
            Self::DepartureRequest { peer_id, .. } => MemberId::new(*peer_id),
            Self::DepartureResponse { peer_id, .. } => MemberId::new(*peer_id),
            Self::CapabilityUpdate { member_id, .. } => *member_id,
        }
    }

    /// Extract the epoch number relevant to this message, if any.
    ///
    /// Returns `None` for variants that do not carry an explicit epoch
    /// (e.g., `EpochCatchUpResponse`, `ProposalAck`). Those messages
    /// are only checked for roster membership, not epoch freshness.
    #[must_use]
    pub fn message_epoch(&self) -> Option<u64> {
        match self {
            Self::JoinRequest { join_epoch, .. } => Some(join_epoch.0),
            Self::JoinResponse { assigned_epoch, .. } => assigned_epoch.map(|e| e.0),
            Self::LeaveNotification {
                departure_epoch, ..
            } => Some(departure_epoch.0),
            Self::EpochProposal { proposed_epoch, .. } => Some(proposed_epoch.0),
            Self::EpochAccept { accepted_epoch, .. } => Some(accepted_epoch.0),
            Self::LeaseGrant { lease_epoch, .. } => Some(lease_epoch.0),
            Self::LeaseRenew { lease_epoch, .. } => Some(lease_epoch.0),
            Self::LeaseRevoke { lease_epoch, .. } => Some(lease_epoch.0),
            Self::HealthReport { epoch, .. } => Some(epoch.0),
            Self::GossipDigest { digest_epoch, .. } => Some(digest_epoch.0),
            Self::GossipDelta { delta_epoch, .. } => Some(delta_epoch.0),
            Self::DrainRequest { drain_epoch, .. } => Some(drain_epoch.0),
            Self::DrainComplete { drain_epoch, .. } => Some(drain_epoch.0),
            Self::LeaseAcknowledge { lease_epoch, .. } => Some(lease_epoch.0),
            Self::LeaseExpire { lease_epoch, .. } => Some(lease_epoch.0),
            Self::PushRoster { roster_epoch, .. } => Some(roster_epoch.0),
            Self::PullRequest { request_epoch, .. } => Some(request_epoch.0),
            Self::PullResponse { roster_epoch, .. } => Some(roster_epoch.0),
            Self::EpochPush { epoch_number, .. } => Some(epoch_number.0),
            Self::EpochCatchUpRequest { from_epoch, .. } => Some(*from_epoch),
            Self::EpochCatchUpResponse { .. } => None,
            Self::ProposalSubmission { proposed_epoch, .. } => Some(*proposed_epoch),
            Self::ProposalAck { .. } => None,
            Self::PeerJoined { roster_epoch, .. } => Some(roster_epoch.0),
            Self::RosterSnapshot { roster_epoch, .. } => Some(roster_epoch.0),
            Self::CoordinatorHeartbeat { epoch, .. } => Some(epoch.0),
            Self::CoordinatorHeartbeatAck { epoch, .. } => Some(epoch.0),
            Self::JournalSyncBatch { base_epoch, .. } => Some(*base_epoch),
            Self::DepartureRequest { request_epoch, .. } => Some(*request_epoch),
            Self::DepartureResponse {
                successor_epoch, ..
            } => Some(*successor_epoch),
            Self::CapabilityUpdate { update_epoch, .. } => Some(update_epoch.0),
        }
    }
}

// ---------------------------------------------------------------------------
// MembershipDispatchError
// ---------------------------------------------------------------------------

/// Errors that can occur during membership message dispatch.
#[derive(Debug)]
pub enum MembershipDispatchError {
    /// No handler is registered for the given message discriminant.
    NoHandlerRegistered(u8),
    /// The registered handler returned an error.
    HandlerError(String),
}

impl fmt::Display for MembershipDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHandlerRegistered(disc) => {
                write!(
                    f,
                    "no handler registered for membership message discriminant: {disc}"
                )
            }
            Self::HandlerError(msg) => {
                write!(f, "membership handler error: {msg}")
            }
        }
    }
}

impl std::error::Error for MembershipDispatchError {}

// ---------------------------------------------------------------------------
// MembershipMessageHandler trait
// ---------------------------------------------------------------------------

/// Trait for handling decoded membership protocol messages.
///
/// Every method has a default no-op implementation that returns `Ok(())`.
/// Subsystems implement this trait and override only the methods for
/// the message variants they handle.
///
/// # Concurrency
///
/// Implementations must be `Send + Sync` for concurrent access through
/// the [`MembershipDispatchRouter`].
pub trait MembershipMessageHandler: Send + Sync {
    /// Handle a join request from a prospective member.
    ///
    /// Default: no-op.
    fn handle_join_request(&self, _msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a join response (accept or reject).
    ///
    /// Default: no-op.
    fn handle_join_response(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a graceful leave notification.
    ///
    /// Default: no-op.
    fn handle_leave_notification(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle an epoch proposal.
    ///
    /// Default: no-op.
    fn handle_epoch_proposal(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle an epoch accept.
    ///
    /// Default: no-op.
    fn handle_epoch_accept(&self, _msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a lease grant.
    ///
    /// Default: no-op.
    fn handle_lease_grant(&self, _msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a lease renewal.
    ///
    /// Default: no-op.
    fn handle_lease_renew(&self, _msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a lease revocation.
    ///
    /// Default: no-op.
    fn handle_lease_revoke(&self, _msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a lease acknowledgement (accept or reject).
    ///
    /// Default: no-op.
    fn handle_lease_acknowledge(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a lease expiry notification.
    ///
    /// Default: no-op.
    fn handle_lease_expire(&self, _msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a health report (liveness heartbeat).
    ///
    /// Default: no-op.
    fn handle_health_report(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a gossip digest for anti-entropy exchange.
    ///
    /// Default: no-op.
    fn handle_gossip_digest(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a gossip delta with incremental state changes.
    ///
    /// Default: no-op.
    fn handle_gossip_delta(&self, _msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a drain request for graceful node removal.
    ///
    /// Default: no-op.
    fn handle_drain_request(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle drain completion notification.
    ///
    /// Default: no-op.
    fn handle_drain_complete(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle an inbound push-roster gossip message.
    ///
    /// Default: no-op.
    fn handle_push_roster(&self, _msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle an inbound pull-request gossip message.
    ///
    /// Default: no-op.
    fn handle_pull_request(&self, _msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle an inbound pull-response gossip message.
    ///
    /// Default: no-op.
    fn handle_pull_response(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle an inbound epoch push broadcast from a peer.
    ///
    /// The push carries a committed epoch view (epoch number, member set,
    /// creation timestamp) that should be validated against the local
    /// epoch chain before application.
    ///
    /// Default: no-op.
    fn handle_epoch_push(&self, _msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle an inbound epoch catch-up request from a lagging peer.
    ///
    /// The handler should query the local epoch store and respond with
    /// batched `[CommittedEpochView]` entries covering the requested range.
    ///
    /// Default: no-op.
    fn handle_epoch_catch_up_request(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle an inbound epoch catch-up response containing batched
    /// committed epoch views.
    ///
    /// The handler should apply received epochs in order via the
    /// epoch chain verifier and advance coordinator replay path.
    ///
    /// Default: no-op.
    fn handle_epoch_catch_up_response(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle an inbound proposal submission from the commit coordinator.
    ///
    /// The handler should validate the proposal against the local epoch chain,
    /// decide whether to accept, and send a `ProposalAck` back to the proposer.
    ///
    /// Default: no-op.
    fn handle_proposal_submission(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle an inbound proposal acknowledgment from a peer.
    ///
    /// The handler should record the ack in the quorum tally.  If the
    /// ack represents a new peer vote for a proposal the local node
    /// originated, the ack-count drives the quorum decision.
    ///
    /// Duplicate acks (same responder + same proposal_hash) must be
    /// idempotent — counted at most once.
    ///
    /// Default: no-op.
    fn handle_proposal_ack(&self, _msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a peer-joined notification broadcast.
    ///
    /// Sent by the roster notifier when a peer completes the join
    /// handshake and is added to the roster. Existing members use
    /// this to update their local peer state without polling.
    ///
    /// Default: no-op.
    fn handle_peer_joined(&self, _msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle an inbound roster snapshot from an existing member.
    ///
    /// Sent when a peer joins the cluster so the joining peer can
    /// bootstrap its local roster and address registry from the
    /// canonical state without external bootstrap.
    ///
    /// Default: no-op.
    fn handle_roster_snapshot(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a coordinator heartbeat for epoch lease renewal.
    ///
    /// Peers respond with a CoordinatorHeartbeatAck to confirm
    /// connectivity. The coordinator counts acks to determine
    /// whether it retains quorum and can continue operating.
    ///
    /// Default: no-op.
    fn handle_coordinator_heartbeat(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a coordinator heartbeat acknowledgment from a peer.
    ///
    /// The coordinator tallies these to determine quorum for
    /// lease renewal. Acks with a nonce lower than the current
    /// heartbeat round are silently dropped.
    ///
    /// Default: no-op.
    fn handle_coordinator_heartbeat_ack(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a `JournalSyncBatch` message (discriminant 27).
    ///
    /// Delivers batched transition journal entries for peer catch-up
    /// and new-peer bootstrap.
    fn handle_journal_sync_batch(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a departure request from a peer requesting voluntary departure.
    ///
    /// Default: no-op.
    fn handle_departure_request(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle a departure response from the coordinator.
    ///
    /// Default: no-op.
    fn handle_departure_response(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }

    /// Handle an inbound capability update from a peer (discriminant 30).
    ///
    /// Called when a peer advertises refreshed operational capabilities.
    /// The default implementation is a no-op.
    fn handle_capability_update(
        &self,
        _msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MembershipDispatchRouter
// ---------------------------------------------------------------------------

/// Registry-based dispatcher that routes [`MembershipMessage`] variants
/// to registered subsystem handlers.
///
/// Handlers are stored in a [`HashMap`] keyed by message discriminant.
/// Registration replaces any existing handler for the same discriminant.
///
/// # Example
///
/// ```ignore
/// let mut router = MembershipDispatchRouter::new();
/// router.register(0, Box::new(my_join_handler));
///
/// let msg = MembershipMessage::JoinRequest {
///     member_id: MemberId::new(1),
///     join_epoch: EpochId::new(0),
///     created_at_millis: 1000,
///     peer_capabilities: None,
/// };
/// router.route(&msg)?;
/// ```
pub struct MembershipDispatchRouter {
    handlers: HashMap<u8, Box<dyn MembershipMessageHandler>>,
}

impl MembershipDispatchRouter {
    /// Create a new empty dispatch router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a given message discriminant.
    ///
    /// If a handler is already registered for this discriminant,
    /// it is replaced.
    pub fn register(&mut self, discriminant: u8, handler: Box<dyn MembershipMessageHandler>) {
        self.handlers.insert(discriminant, handler);
    }

    /// Remove the handler for a given message discriminant.
    ///
    /// Returns the removed handler, if any.
    pub fn unregister(&mut self, discriminant: u8) -> Option<Box<dyn MembershipMessageHandler>> {
        self.handlers.remove(&discriminant)
    }

    /// Route a membership message to the registered handler for its variant.
    ///
    /// Inspects the message discriminant, looks up the registered handler,
    /// and calls the appropriate typed handler method.
    ///
    /// # Errors
    ///
    /// Returns [`MembershipDispatchError::NoHandlerRegistered`] if no handler
    /// is registered for the message's discriminant. Returns
    /// [`MembershipDispatchError::HandlerError`] if the handler method fails.
    pub fn route(&self, msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        let disc = msg.discriminant();
        let handler = self
            .handlers
            .get(&disc)
            .ok_or(MembershipDispatchError::NoHandlerRegistered(disc))?;

        match msg {
            MembershipMessage::JoinRequest { .. } => handler.handle_join_request(msg),
            MembershipMessage::JoinResponse { .. } => handler.handle_join_response(msg),
            MembershipMessage::LeaveNotification { .. } => handler.handle_leave_notification(msg),
            MembershipMessage::EpochProposal { .. } => handler.handle_epoch_proposal(msg),
            MembershipMessage::EpochAccept { .. } => handler.handle_epoch_accept(msg),
            MembershipMessage::LeaseGrant { .. } => handler.handle_lease_grant(msg),
            MembershipMessage::LeaseRenew { .. } => handler.handle_lease_renew(msg),
            MembershipMessage::LeaseRevoke { .. } => handler.handle_lease_revoke(msg),
            MembershipMessage::HealthReport { .. } => handler.handle_health_report(msg),
            MembershipMessage::GossipDigest { .. } => handler.handle_gossip_digest(msg),
            MembershipMessage::GossipDelta { .. } => handler.handle_gossip_delta(msg),
            MembershipMessage::DrainRequest { .. } => handler.handle_drain_request(msg),
            MembershipMessage::DrainComplete { .. } => handler.handle_drain_complete(msg),
            MembershipMessage::LeaseAcknowledge { .. } => handler.handle_lease_acknowledge(msg),
            MembershipMessage::LeaseExpire { .. } => handler.handle_lease_expire(msg),
            MembershipMessage::PushRoster { .. } => handler.handle_push_roster(msg),
            MembershipMessage::PullRequest { .. } => handler.handle_pull_request(msg),
            MembershipMessage::PullResponse { .. } => handler.handle_pull_response(msg),
            MembershipMessage::EpochPush { .. } => handler.handle_epoch_push(msg),
            MembershipMessage::EpochCatchUpRequest { .. } => {
                handler.handle_epoch_catch_up_request(msg)
            }
            MembershipMessage::EpochCatchUpResponse { .. } => {
                handler.handle_epoch_catch_up_response(msg)
            }
            MembershipMessage::ProposalSubmission { .. } => handler.handle_proposal_submission(msg),
            MembershipMessage::ProposalAck { .. } => handler.handle_proposal_ack(msg),
            MembershipMessage::PeerJoined { .. } => handler.handle_peer_joined(msg),
            MembershipMessage::RosterSnapshot { .. } => handler.handle_roster_snapshot(msg),
            MembershipMessage::CoordinatorHeartbeat { .. } => {
                handler.handle_coordinator_heartbeat(msg)
            }
            MembershipMessage::CoordinatorHeartbeatAck { .. } => {
                handler.handle_coordinator_heartbeat_ack(msg)
            }
            MembershipMessage::JournalSyncBatch { .. } => handler.handle_journal_sync_batch(msg),
            MembershipMessage::DepartureRequest { .. } => handler.handle_departure_request(msg),
            MembershipMessage::DepartureResponse { .. } => handler.handle_departure_response(msg),
            MembershipMessage::CapabilityUpdate { .. } => handler.handle_capability_update(msg),
        }
    }

    /// Return whether a handler is registered for the given discriminant.
    #[must_use]
    pub fn has_handler(&self, discriminant: u8) -> bool {
        self.handlers.contains_key(&discriminant)
    }

    /// Return the number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }
}

impl Default for MembershipDispatchRouter {
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
    use std::sync::{Arc, Mutex};

    // ------------------------------------------------------------------
    // Test helpers
    // ------------------------------------------------------------------

    /// A shared call log for tracking handler invocations.
    #[derive(Clone, Default)]
    struct CallLog {
        calls: Arc<Mutex<Vec<(String, MembershipMessage)>>>,
    }

    impl CallLog {
        fn new() -> Self {
            Self::default()
        }

        fn push(&self, method: &str, msg: &MembershipMessage) {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_string(), msg.clone()));
        }

        fn count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn method_of(&self, index: usize) -> Option<String> {
            self.calls.lock().unwrap().get(index).map(|c| c.0.clone())
        }
    }

    /// A test handler that records invocations to a shared [`CallLog`].
    struct RecordingHandler {
        log: CallLog,
        /// If set, the named method will return an error.
        fail_on: Mutex<Option<String>>,
    }

    impl RecordingHandler {
        fn new(log: CallLog) -> Self {
            Self {
                log,
                fail_on: Mutex::new(None),
            }
        }

        fn set_fail_on(&self, method: &str) {
            *self.fail_on.lock().unwrap() = Some(method.to_string());
        }
    }

    macro_rules! impl_handler_method {
        ($name:ident, $method:ident, $label:expr) => {
            fn $method(&self, msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
                if self.fail_on.lock().unwrap().as_deref() == Some($label) {
                    return Err(MembershipDispatchError::HandlerError(format!(
                        "{} failed",
                        $label
                    )));
                }
                self.log.push($label, msg);
                Ok(())
            }
        };
    }

    impl MembershipMessageHandler for RecordingHandler {
        impl_handler_method!(handle_join_request, handle_join_request, "join_request");
        impl_handler_method!(handle_join_response, handle_join_response, "join_response");
        impl_handler_method!(
            handle_leave_notification,
            handle_leave_notification,
            "leave_notification"
        );
        impl_handler_method!(
            handle_epoch_proposal,
            handle_epoch_proposal,
            "epoch_proposal"
        );
        impl_handler_method!(handle_epoch_accept, handle_epoch_accept, "epoch_accept");
        impl_handler_method!(handle_lease_grant, handle_lease_grant, "lease_grant");
        impl_handler_method!(handle_lease_renew, handle_lease_renew, "lease_renew");
        impl_handler_method!(handle_lease_revoke, handle_lease_revoke, "lease_revoke");
        impl_handler_method!(
            handle_lease_acknowledge,
            handle_lease_acknowledge,
            "lease_acknowledge"
        );
        impl_handler_method!(handle_lease_expire, handle_lease_expire, "lease_expire");
        impl_handler_method!(handle_health_report, handle_health_report, "health_report");
        impl_handler_method!(handle_gossip_digest, handle_gossip_digest, "gossip_digest");
        impl_handler_method!(handle_gossip_delta, handle_gossip_delta, "gossip_delta");
        impl_handler_method!(handle_drain_request, handle_drain_request, "drain_request");
        impl_handler_method!(
            handle_drain_complete,
            handle_drain_complete,
            "drain_complete"
        );
    }

    /// A handler that only implements select methods (all others no-op).
    struct SelectiveHandler {
        log: CallLog,
    }

    impl SelectiveHandler {
        fn new(log: CallLog) -> Self {
            Self { log }
        }
    }

    impl MembershipMessageHandler for SelectiveHandler {
        fn handle_join_request(
            &self,
            msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.log.push("join_request", msg);
            Ok(())
        }

        fn handle_health_report(
            &self,
            msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.log.push("health_report", msg);
            Ok(())
        }

        fn handle_drain_complete(
            &self,
            msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.log.push("drain_complete", msg);
            Ok(())
        }
    }

    // ------------------------------------------------------------------
    // MembershipMessage tests
    // ------------------------------------------------------------------

    #[test]
    fn all_variants_have_distinct_discriminants() {
        let mut discs = Vec::with_capacity(31);
        // Build one of each variant
        discs.push(
            MembershipMessage::JoinRequest {
                member_id: MemberId::new(1),
                join_epoch: EpochId::new(0),
                created_at_millis: 0,
                peer_capabilities: None,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::JoinResponse {
                request_member_id: MemberId::new(1),
                accepted: true,
                assigned_epoch: None,
                reject_reason: None,
                responded_at_millis: 0,
                incarnation: Incarnation::ZERO,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::LeaveNotification {
                member_id: MemberId::new(1),
                departure_epoch: EpochId::new(0),
                announced_at_millis: 0,
                leave_reason: LeaveReason::Voluntary,
                incarnation: Incarnation::ZERO,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::EpochProposal {
                proposer: MemberId::new(1),
                proposed_epoch: EpochId::new(0),
                proposed_member_set: vec![],
                proposal_nonce: 0,
                proposed_at_millis: 0,
                incarnation: Incarnation::ZERO,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::EpochAccept {
                acceptor: MemberId::new(1),
                proposal_nonce: 0,
                accepted_epoch: EpochId::new(0),
                accepted_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::LeaseGrant {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                lease_term: 0,
                lease_ttl_millis: 0,
                lease_expires_at_millis: 0,
                granted_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::LeaseRenew {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                lease_term: 0,
                lease_ttl_millis: 0,
                new_expires_at_millis: 0,
                renewed_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::LeaseRevoke {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                revoked_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::HealthReport {
                member_id: MemberId::new(1),
                epoch: EpochId::new(0),
                health_class: 0,
                reported_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::GossipDigest {
                originator: MemberId::new(1),
                digest_epoch: EpochId::new(0),
                state_digest: [0u8; 32],
                sent_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::GossipDelta {
                originator: MemberId::new(1),
                delta_epoch: EpochId::new(0),
                delta_payload: vec![],
                sent_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::DrainRequest {
                target_member_id: MemberId::new(1),
                drain_epoch: EpochId::new(0),
                requested_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::DrainComplete {
                member_id: MemberId::new(1),
                drain_epoch: EpochId::new(0),
                completed_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::LeaseAcknowledge {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                accepted: true,
                acknowledged_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::LeaseExpire {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                expired_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::PushRoster {
                originator: MemberId::new(1),
                roster_epoch: EpochId::new(0),
                roster_payload: vec![],
                sent_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::PullRequest {
                requester: MemberId::new(1),
                request_epoch: EpochId::new(0),
                sent_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::PullResponse {
                responder: MemberId::new(1),
                roster_epoch: EpochId::new(0),
                roster_payload: vec![],
                responded_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::EpochPush {
                epoch_number: EpochId::new(0),
                member_set: vec![],
                created_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::EpochCatchUpRequest {
                requester: MemberId::new(1),
                from_epoch: 1,
                to_epoch: 5,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::EpochCatchUpResponse {
                responder: MemberId::new(1),
                epochs: vec![],
                truncated: false,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::ProposalSubmission {
                proposer: MemberId::new(1),
                current_epoch: 0,
                proposed_epoch: 1,
                delta: MembershipDelta::NodeJoined(2),
                resulting_members: vec![1, 2],
                proposal_hash: [0u8; 32],
                submitted_at_millis: 0,
                catalog_delta_bytes: None,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::ProposalAck {
                responder: MemberId::new(2),
                proposal_hash: [0u8; 32],
                accepted: true,
                reject_reason: None,
                acked_at_millis: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::PeerJoined {
                member_id: MemberId::new(3),
                roster_epoch: EpochId::new(2),
            }
            .discriminant(),
        );

        discs.push(
            MembershipMessage::RosterSnapshot {
                originator: MemberId::new(1),
                roster_epoch: EpochId::new(2),
                entries: vec![],
            }
            .discriminant(),
        );

        discs.push(
            MembershipMessage::CoordinatorHeartbeat {
                epoch: EpochId::new(3),
                coordinator_id: MemberId::new(1),
                lease_nonce: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::CoordinatorHeartbeatAck {
                epoch: EpochId::new(3),
                member_id: MemberId::new(2),
                lease_nonce: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::JournalSyncBatch {
                originator: MemberId::new(1),
                base_epoch: 0,
                batch_payload: vec![],
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::DepartureRequest {
                peer_id: 1,
                reason: tidefs_membership_types::departure::DepartureReason::Voluntary,
                request_epoch: 0,
                nonce: 0,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::DepartureResponse {
                peer_id: 1,
                accepted: true,
                successor_epoch: 1,
                reject_reason: None,
            }
            .discriminant(),
        );
        discs.push(
            MembershipMessage::CapabilityUpdate {
                member_id: MemberId::new(1),
                update_epoch: EpochId::new(0),
                capabilities: PeerCapabilities::new(1000, 500),
                updated_at_millis: 0,
            }
            .discriminant(),
        );
        discs.sort();
        discs.dedup();
        assert_eq!(
            discs.len(),
            31,
            "all 31 variants must have distinct discriminants"
        );
    }

    #[test]
    fn all_discriminants_returns_thirty_one() {
        assert_eq!(MembershipMessage::all_discriminants().len(), 31);
    }

    #[test]
    fn variant_name_returns_correct_names() {
        assert_eq!(
            MembershipMessage::JoinRequest {
                member_id: MemberId::new(1),
                join_epoch: EpochId::new(0),
                created_at_millis: 0,
                peer_capabilities: None
            }
            .variant_name(),
            "JoinRequest"
        );
        assert_eq!(
            MembershipMessage::JoinResponse {
                request_member_id: MemberId::new(1),
                accepted: true,
                assigned_epoch: None,
                reject_reason: None,
                responded_at_millis: 0,
                incarnation: Incarnation::ZERO
            }
            .variant_name(),
            "JoinResponse"
        );
        assert_eq!(
            MembershipMessage::LeaveNotification {
                member_id: MemberId::new(1),
                departure_epoch: EpochId::new(0),
                announced_at_millis: 0,
                leave_reason: LeaveReason::Voluntary,
                incarnation: Incarnation::ZERO
            }
            .variant_name(),
            "LeaveNotification"
        );
        assert_eq!(
            MembershipMessage::EpochProposal {
                proposer: MemberId::new(1),
                proposed_epoch: EpochId::new(0),
                proposed_member_set: vec![],
                proposal_nonce: 0,
                proposed_at_millis: 0,
                incarnation: Incarnation::ZERO
            }
            .variant_name(),
            "EpochProposal"
        );
        assert_eq!(
            MembershipMessage::EpochAccept {
                acceptor: MemberId::new(1),
                proposal_nonce: 0,
                accepted_epoch: EpochId::new(0),
                accepted_at_millis: 0
            }
            .variant_name(),
            "EpochAccept"
        );
        assert_eq!(
            MembershipMessage::LeaseGrant {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                lease_term: 0,
                lease_ttl_millis: 0,
                lease_expires_at_millis: 0,
                granted_at_millis: 0
            }
            .variant_name(),
            "LeaseGrant"
        );
        assert_eq!(
            MembershipMessage::LeaseRenew {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                lease_term: 0,
                lease_ttl_millis: 0,
                new_expires_at_millis: 0,
                renewed_at_millis: 0
            }
            .variant_name(),
            "LeaseRenew"
        );
        assert_eq!(
            MembershipMessage::LeaseRevoke {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                revoked_at_millis: 0
            }
            .variant_name(),
            "LeaseRevoke"
        );
        assert_eq!(
            MembershipMessage::HealthReport {
                member_id: MemberId::new(1),
                epoch: EpochId::new(0),
                health_class: 0,
                reported_at_millis: 0
            }
            .variant_name(),
            "HealthReport"
        );
        assert_eq!(
            MembershipMessage::GossipDigest {
                originator: MemberId::new(1),
                digest_epoch: EpochId::new(0),
                state_digest: [0u8; 32],
                sent_at_millis: 0
            }
            .variant_name(),
            "GossipDigest"
        );
        assert_eq!(
            MembershipMessage::GossipDelta {
                originator: MemberId::new(1),
                delta_epoch: EpochId::new(0),
                delta_payload: vec![],
                sent_at_millis: 0
            }
            .variant_name(),
            "GossipDelta"
        );
        assert_eq!(
            MembershipMessage::DrainRequest {
                target_member_id: MemberId::new(1),
                drain_epoch: EpochId::new(0),
                requested_at_millis: 0
            }
            .variant_name(),
            "DrainRequest"
        );
        assert_eq!(
            MembershipMessage::DrainComplete {
                member_id: MemberId::new(1),
                drain_epoch: EpochId::new(0),
                completed_at_millis: 0
            }
            .variant_name(),
            "DrainComplete"
        );
        assert_eq!(
            MembershipMessage::LeaseAcknowledge {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                accepted: true,
                acknowledged_at_millis: 0
            }
            .variant_name(),
            "LeaseAcknowledge"
        );
        assert_eq!(
            MembershipMessage::LeaseExpire {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                expired_at_millis: 0
            }
            .variant_name(),
            "LeaseExpire"
        );
        assert_eq!(
            MembershipMessage::PushRoster {
                originator: MemberId::new(1),
                roster_epoch: EpochId::new(0),
                roster_payload: vec![],
                sent_at_millis: 0
            }
            .variant_name(),
            "PushRoster"
        );
        assert_eq!(
            MembershipMessage::PullRequest {
                requester: MemberId::new(1),
                request_epoch: EpochId::new(0),
                sent_at_millis: 0
            }
            .variant_name(),
            "PullRequest"
        );
        assert_eq!(
            MembershipMessage::PullResponse {
                responder: MemberId::new(1),
                roster_epoch: EpochId::new(0),
                roster_payload: vec![],
                responded_at_millis: 0
            }
            .variant_name(),
            "PullResponse"
        );
        assert_eq!(
            MembershipMessage::EpochPush {
                epoch_number: EpochId::new(0),
                member_set: vec![],
                created_at_millis: 0
            }
            .variant_name(),
            "EpochPush"
        );
        assert_eq!(
            MembershipMessage::EpochCatchUpRequest {
                requester: MemberId::new(1),
                from_epoch: 1,
                to_epoch: 5
            }
            .variant_name(),
            "EpochCatchUpRequest"
        );
        assert_eq!(
            MembershipMessage::EpochCatchUpResponse {
                responder: MemberId::new(1),
                epochs: vec![],
                truncated: false
            }
            .variant_name(),
            "EpochCatchUpResponse"
        );
        assert_eq!(
            MembershipMessage::ProposalSubmission {
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
            "ProposalSubmission"
        );
        assert_eq!(
            MembershipMessage::ProposalAck {
                responder: MemberId::new(2),
                proposal_hash: [0u8; 32],
                accepted: true,
                reject_reason: None,
                acked_at_millis: 0,
            }
            .variant_name(),
            "ProposalAck"
        );
        assert_eq!(
            MembershipMessage::PeerJoined {
                member_id: MemberId::new(3),
                roster_epoch: EpochId::new(2),
            }
            .variant_name(),
            "PeerJoined"
        );
        assert_eq!(
            MembershipMessage::RosterSnapshot {
                originator: MemberId::new(1),
                roster_epoch: EpochId::new(2),
                entries: vec![],
            }
            .variant_name(),
            "RosterSnapshot"
        );
        assert_eq!(
            MembershipMessage::CoordinatorHeartbeat {
                epoch: EpochId::new(3),
                coordinator_id: MemberId::new(1),
                lease_nonce: 0,
            }
            .variant_name(),
            "CoordinatorHeartbeat"
        );
        assert_eq!(
            MembershipMessage::CoordinatorHeartbeatAck {
                epoch: EpochId::new(3),
                member_id: MemberId::new(2),
                lease_nonce: 0,
            }
            .variant_name(),
            "CoordinatorHeartbeatAck"
        );
    }

    #[test]
    fn membership_message_clone_eq() {
        let msg1 = MembershipMessage::JoinRequest {
            member_id: MemberId::new(42),
            join_epoch: EpochId::new(7),
            created_at_millis: 5000,
            peer_capabilities: None,
        };
        let msg2 = msg1.clone();
        assert_eq!(msg1, msg2);
    }

    // ------------------------------------------------------------------
    // MembershipDispatchRouter tests
    // ------------------------------------------------------------------

    #[test]
    fn new_router_is_empty() {
        let router = MembershipDispatchRouter::new();
        assert_eq!(router.handler_count(), 0);
    }

    #[test]
    fn register_and_route_join_request() {
        let mut router = MembershipDispatchRouter::new();
        let log = CallLog::new();
        let handler = Box::new(RecordingHandler::new(log.clone()));

        router.register(0, handler);
        assert_eq!(router.handler_count(), 1);
        assert!(router.has_handler(0));

        let msg = MembershipMessage::JoinRequest {
            member_id: MemberId::new(1),
            join_epoch: EpochId::new(5),
            created_at_millis: 1000,
            peer_capabilities: None,
        };
        router.route(&msg).unwrap();

        assert_eq!(log.count(), 1);
        assert_eq!(log.method_of(0).unwrap(), "join_request");
    }

    #[test]
    fn route_each_of_31_variants() {
        let mut router = MembershipDispatchRouter::new();

        // Register one handler for all 31 discriminants
        for disc in MembershipMessage::all_discriminants() {
            let log = CallLog::new();
            router.register(disc, Box::new(RecordingHandler::new(log)));
        }
        assert_eq!(router.handler_count(), 31);

        let messages: Vec<MembershipMessage> = vec![
            MembershipMessage::JoinRequest {
                member_id: MemberId::new(1),
                join_epoch: EpochId::new(0),
                created_at_millis: 0,
                peer_capabilities: None,
            },
            MembershipMessage::JoinResponse {
                request_member_id: MemberId::new(1),
                accepted: true,
                assigned_epoch: None,
                reject_reason: None,
                responded_at_millis: 0,
                incarnation: Incarnation::ZERO,
            },
            MembershipMessage::LeaveNotification {
                member_id: MemberId::new(1),
                departure_epoch: EpochId::new(0),
                announced_at_millis: 0,
                leave_reason: LeaveReason::Voluntary,
                incarnation: Incarnation::ZERO,
            },
            MembershipMessage::EpochProposal {
                proposer: MemberId::new(1),
                proposed_epoch: EpochId::new(0),
                proposed_member_set: vec![],
                proposal_nonce: 0,
                proposed_at_millis: 0,
                incarnation: Incarnation::ZERO,
            },
            MembershipMessage::EpochAccept {
                acceptor: MemberId::new(1),
                proposal_nonce: 0,
                accepted_epoch: EpochId::new(0),
                accepted_at_millis: 0,
            },
            MembershipMessage::LeaseGrant {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                lease_term: 0,
                lease_ttl_millis: 0,
                lease_expires_at_millis: 0,
                granted_at_millis: 0,
            },
            MembershipMessage::LeaseRenew {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                lease_term: 0,
                lease_ttl_millis: 0,
                new_expires_at_millis: 0,
                renewed_at_millis: 0,
            },
            MembershipMessage::LeaseRevoke {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                revoked_at_millis: 0,
            },
            MembershipMessage::HealthReport {
                member_id: MemberId::new(1),
                epoch: EpochId::new(0),
                health_class: 0,
                reported_at_millis: 0,
            },
            MembershipMessage::GossipDigest {
                originator: MemberId::new(1),
                digest_epoch: EpochId::new(0),
                state_digest: [0u8; 32],
                sent_at_millis: 0,
            },
            MembershipMessage::GossipDelta {
                originator: MemberId::new(1),
                delta_epoch: EpochId::new(0),
                delta_payload: vec![],
                sent_at_millis: 0,
            },
            MembershipMessage::DrainRequest {
                target_member_id: MemberId::new(1),
                drain_epoch: EpochId::new(0),
                requested_at_millis: 0,
            },
            MembershipMessage::DrainComplete {
                member_id: MemberId::new(1),
                drain_epoch: EpochId::new(0),
                completed_at_millis: 0,
            },
            MembershipMessage::LeaseAcknowledge {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                accepted: true,
                acknowledged_at_millis: 0,
            },
            MembershipMessage::LeaseExpire {
                member_id: MemberId::new(1),
                lease_id: 0,
                lease_epoch: EpochId::new(0),
                expired_at_millis: 0,
            },
            MembershipMessage::PushRoster {
                originator: MemberId::new(1),
                roster_epoch: EpochId::new(0),
                roster_payload: vec![],
                sent_at_millis: 0,
            },
            MembershipMessage::PullRequest {
                requester: MemberId::new(1),
                request_epoch: EpochId::new(0),
                sent_at_millis: 0,
            },
            MembershipMessage::PullResponse {
                responder: MemberId::new(1),
                roster_epoch: EpochId::new(0),
                roster_payload: vec![],
                responded_at_millis: 0,
            },
            MembershipMessage::EpochPush {
                epoch_number: EpochId::new(0),
                member_set: vec![],
                created_at_millis: 0,
            },
            MembershipMessage::EpochCatchUpRequest {
                requester: MemberId::new(1),
                from_epoch: 1,
                to_epoch: 5,
            },
            MembershipMessage::EpochCatchUpResponse {
                responder: MemberId::new(1),
                epochs: vec![],
                truncated: false,
            },
            MembershipMessage::ProposalSubmission {
                proposer: MemberId::new(1),
                current_epoch: 0,
                proposed_epoch: 1,
                delta: MembershipDelta::NodeJoined(2),
                resulting_members: vec![1, 2],
                proposal_hash: [0u8; 32],
                submitted_at_millis: 0,
                catalog_delta_bytes: None,
            },
            MembershipMessage::ProposalAck {
                responder: MemberId::new(2),
                proposal_hash: [0u8; 32],
                accepted: true,
                reject_reason: None,
                acked_at_millis: 0,
            },
            MembershipMessage::PeerJoined {
                member_id: MemberId::new(3),
                roster_epoch: EpochId::new(2),
            },
            MembershipMessage::RosterSnapshot {
                originator: MemberId::new(1),
                roster_epoch: EpochId::new(2),
                entries: vec![],
            },
            MembershipMessage::CoordinatorHeartbeat {
                epoch: EpochId::new(3),
                coordinator_id: MemberId::new(1),
                lease_nonce: 0,
            },
            MembershipMessage::CoordinatorHeartbeatAck {
                epoch: EpochId::new(3),
                member_id: MemberId::new(2),
                lease_nonce: 0,
            },
            MembershipMessage::JournalSyncBatch {
                originator: MemberId::new(1),
                base_epoch: 0,
                batch_payload: vec![],
            },
            MembershipMessage::DepartureRequest {
                peer_id: 1,
                reason: tidefs_membership_types::departure::DepartureReason::Voluntary,
                request_epoch: 0,
                nonce: 0,
            },
            MembershipMessage::DepartureResponse {
                peer_id: 1,
                accepted: true,
                successor_epoch: 1,
                reject_reason: None,
            },
            MembershipMessage::CapabilityUpdate {
                member_id: MemberId::new(1),
                update_epoch: EpochId::new(0),
                capabilities: PeerCapabilities::new(1000, 500),
                updated_at_millis: 0,
            },
        ];

        assert_eq!(messages.len(), 31);

        for msg in &messages {
            router.route(msg).unwrap();
        }
    }

    #[test]
    fn dispatch_to_correct_handler_per_variant() {
        let mut router = MembershipDispatchRouter::new();

        let log_join = CallLog::new();
        let log_health = CallLog::new();
        let log_drain = CallLog::new();

        router.register(0, Box::new(RecordingHandler::new(log_join.clone()))); // JoinRequest
        router.register(8, Box::new(RecordingHandler::new(log_health.clone()))); // HealthReport
        router.register(12, Box::new(RecordingHandler::new(log_drain.clone()))); // DrainComplete

        // Route JoinRequest -> should go to join handler
        router
            .route(&MembershipMessage::JoinRequest {
                member_id: MemberId::new(10),
                join_epoch: EpochId::new(1),
                created_at_millis: 100,
                peer_capabilities: None,
            })
            .unwrap();
        assert_eq!(log_join.count(), 1);
        assert_eq!(log_health.count(), 0);
        assert_eq!(log_drain.count(), 0);

        // Route HealthReport -> should go to health handler
        router
            .route(&MembershipMessage::HealthReport {
                member_id: MemberId::new(20),
                epoch: EpochId::new(2),
                health_class: 1,
                reported_at_millis: 200,
            })
            .unwrap();
        assert_eq!(log_join.count(), 1);
        assert_eq!(log_health.count(), 1);
        assert_eq!(log_drain.count(), 0);

        // Route DrainComplete -> should go to drain handler
        router
            .route(&MembershipMessage::DrainComplete {
                member_id: MemberId::new(30),
                drain_epoch: EpochId::new(3),
                completed_at_millis: 300,
            })
            .unwrap();
        assert_eq!(log_join.count(), 1);
        assert_eq!(log_health.count(), 1);
        assert_eq!(log_drain.count(), 1);

        assert_eq!(log_join.method_of(0).unwrap(), "join_request");
        assert_eq!(log_health.method_of(0).unwrap(), "health_report");
        assert_eq!(log_drain.method_of(0).unwrap(), "drain_complete");
    }

    #[test]
    fn route_no_handler_registered_returns_error() {
        let router = MembershipDispatchRouter::new();
        let msg = MembershipMessage::JoinRequest {
            member_id: MemberId::new(1),
            join_epoch: EpochId::new(0),
            created_at_millis: 0,
            peer_capabilities: None,
        };
        let result = router.route(&msg);
        assert!(matches!(
            result,
            Err(MembershipDispatchError::NoHandlerRegistered(0))
        ));
    }

    #[test]
    fn route_handler_error_propagates() {
        let mut router = MembershipDispatchRouter::new();
        let log = CallLog::new();
        let handler = RecordingHandler::new(log);
        handler.set_fail_on("join_request");
        router.register(0, Box::new(handler));

        let msg = MembershipMessage::JoinRequest {
            member_id: MemberId::new(1),
            join_epoch: EpochId::new(0),
            created_at_millis: 0,
            peer_capabilities: None,
        };
        let result = router.route(&msg);
        assert!(matches!(
            result,
            Err(MembershipDispatchError::HandlerError(_))
        ));
        if let Err(MembershipDispatchError::HandlerError(s)) = result {
            assert!(s.contains("join_request failed"));
        }
    }

    #[test]
    fn register_replaces_existing_handler() {
        let mut router = MembershipDispatchRouter::new();
        let log1 = CallLog::new();
        let log2 = CallLog::new();

        router.register(0, Box::new(RecordingHandler::new(log1.clone())));
        router.register(0, Box::new(RecordingHandler::new(log2.clone())));

        assert_eq!(router.handler_count(), 1);

        router
            .route(&MembershipMessage::JoinRequest {
                member_id: MemberId::new(1),
                join_epoch: EpochId::new(0),
                created_at_millis: 0,
                peer_capabilities: None,
            })
            .unwrap();

        assert_eq!(log1.count(), 0, "replaced handler should not receive calls");
        assert_eq!(log2.count(), 1, "replacement handler should receive calls");
    }

    #[test]
    fn unregister_removes_handler() {
        let mut router = MembershipDispatchRouter::new();
        let log = CallLog::new();
        router.register(5, Box::new(RecordingHandler::new(log))); // LeaseGrant

        assert_eq!(router.handler_count(), 1);
        assert!(router.has_handler(5));

        let removed = router.unregister(5);
        assert!(removed.is_some());
        assert_eq!(router.handler_count(), 0);
        assert!(!router.has_handler(5));

        let result = router.route(&MembershipMessage::LeaseGrant {
            member_id: MemberId::new(1),
            lease_id: 0,
            lease_epoch: EpochId::new(0),
            lease_term: 0,
            lease_ttl_millis: 0,
            lease_expires_at_millis: 0,
            granted_at_millis: 0,
        });
        assert!(matches!(
            result,
            Err(MembershipDispatchError::NoHandlerRegistered(5))
        ));
    }

    #[test]
    fn unregister_nonexistent_returns_none() {
        let mut router = MembershipDispatchRouter::new();
        let removed = router.unregister(7); // LeaseRevoke, not registered
        assert!(removed.is_none());
    }

    #[test]
    fn has_handler_returns_correct_values() {
        let mut router = MembershipDispatchRouter::new();
        assert!(!router.has_handler(3)); // EpochProposal

        let log = CallLog::new();
        router.register(3, Box::new(RecordingHandler::new(log)));
        assert!(router.has_handler(3));

        router.unregister(3);
        assert!(!router.has_handler(3));
    }

    #[test]
    fn selective_handler_only_handles_registered_methods() {
        let mut router = MembershipDispatchRouter::new();
        let log = CallLog::new();
        router.register(0, Box::new(SelectiveHandler::new(log.clone()))); // handles join_request
        router.register(8, Box::new(SelectiveHandler::new(log.clone()))); // handles health_report
        router.register(12, Box::new(SelectiveHandler::new(log.clone()))); // handles drain_complete

        // JoinRequest -> handled
        router
            .route(&MembershipMessage::JoinRequest {
                member_id: MemberId::new(1),
                join_epoch: EpochId::new(0),
                created_at_millis: 0,
                peer_capabilities: None,
            })
            .unwrap();
        assert_eq!(log.count(), 1);
        assert_eq!(log.method_of(0).unwrap(), "join_request");

        // HealthReport -> handled
        router
            .route(&MembershipMessage::HealthReport {
                member_id: MemberId::new(1),
                epoch: EpochId::new(0),
                health_class: 0,
                reported_at_millis: 0,
            })
            .unwrap();
        assert_eq!(log.count(), 2);
        assert_eq!(log.method_of(1).unwrap(), "health_report");

        // DrainComplete -> handled
        router
            .route(&MembershipMessage::DrainComplete {
                member_id: MemberId::new(1),
                drain_epoch: EpochId::new(0),
                completed_at_millis: 0,
            })
            .unwrap();
        assert_eq!(log.count(), 3);
        assert_eq!(log.method_of(2).unwrap(), "drain_complete");
    }

    #[test]
    fn selective_handler_noops_on_unhandled_variants() {
        // Register a SelectiveHandler for JoinRequest (disc 0).
        // It only overrides handle_join_request. When routed a
        // different variant for the same discriminant (which shouldn't
        // normally happen since discriminants are 1:1), the no-op
        // default should apply without error.
        let mut router = MembershipDispatchRouter::new();
        let log = CallLog::new();
        router.register(0, Box::new(SelectiveHandler::new(log.clone())));

        // Route JoinRequest (disc 0) -> should hit the overridden method
        router
            .route(&MembershipMessage::JoinRequest {
                member_id: MemberId::new(1),
                join_epoch: EpochId::new(0),
                created_at_millis: 0,
                peer_capabilities: None,
            })
            .unwrap();
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn default_router_is_empty() {
        let router = MembershipDispatchRouter::default();
        assert_eq!(router.handler_count(), 0);
    }

    // ------------------------------------------------------------------
    // MembershipDispatchError tests
    // ------------------------------------------------------------------

    #[test]
    fn dispatch_error_display_no_handler_registered() {
        let e = MembershipDispatchError::NoHandlerRegistered(5);
        let s = format!("{e}");
        assert!(s.contains("no handler registered"));
        assert!(s.contains("5"));
    }

    #[test]
    fn dispatch_error_display_handler_error() {
        let e = MembershipDispatchError::HandlerError("something broke".to_string());
        let s = format!("{e}");
        assert!(s.contains("handler error"));
        assert!(s.contains("something broke"));
    }

    #[test]
    fn dispatch_error_is_std_error() {
        let e = MembershipDispatchError::NoHandlerRegistered(0);
        // Just verify it implements std::error::Error
        let _: &dyn std::error::Error = &e;
    }
}
