//! Coordinator-side join-request validation and admission lifecycle management.
//!
//! When a peer sends a [`MembershipMessage::JoinRequest`] over transport, the
//! coordinator evaluates admission constraints, creates a tracked
//! [`PendingJoin`], initiates a quorum proposal through the configured
//! proposal initiator callback, and manages the admission lifecycle through
//! to a final outcome.
//!
//! ## Admission lifecycle
//!
//! ```text
//! JoinRequest received
//!   |
//!   v
//! validate_admission()  ──► Rejected (validation failure)
//!   |                       outcome dispatched to joining peer
//!   v
//! Pending (created)
//!   |
//!   v
//! Proposed (proposal initiator called)
//!   |
//!   +──► Accepted (quorum accepts)
//!   |      |
//!   |      v
//!   |    Committed (epoch advances)
//!   |
//!   +──► Rejected (quorum rejects or timeout)
//!          outcome dispatched to joining peer
//! ```
//!
//! ## Integration points
//!
//! - [`MembershipMessage::JoinRequest`]: inbound message variant handled by
//!   this handler via the `handle_join_request` trait method.
//! - **Proposal initiation**: the `on_propose` callback bridges to the quorum
//!   proposal system (#6176), typically wired to broadcast a
//!   [`MembershipOutboundMessage::ProposalSubmission`].
//! - **Outcome dispatch**: the `on_outcome` callback bridges to the
//!   join-response dispatcher (#6147), delivering acceptance or rejection
//!   to the joining peer over transport.
//! - **Timeout**: stale pending joins that never reach a terminal state are
//!   reaped by [`JoinRequestHandler::reap_expired`], which the runtime calls
//!   periodically.

use std::collections::HashMap;

use tidefs_membership_epoch::{EpochId, MemberId};

use crate::capability_view::MembershipCapabilityView;
use crate::dispatch_router::{
    MembershipDispatchError, MembershipMessage, MembershipMessageHandler,
};
use crate::roster::MembershipRoster;
use std::sync::{Arc, Mutex, RwLock};
use tidefs_membership_types::capabilities::PeerCapabilities;

type JoinProposalCallback = Box<dyn Fn(&PendingJoin) + Send + Sync>;
type JoinOutcomeCallback = Box<dyn Fn(PendingJoin) + Send + Sync>;

// ---------------------------------------------------------------------------
// AdmissionState — lifecycle states for a join request
// ---------------------------------------------------------------------------

/// The state of a join request as it moves through the admission lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionState {
    /// Join request received and validated; awaiting proposal initiation.
    Pending,
    /// A quorum proposal has been initiated for this join.
    Proposed,
    /// The quorum has accepted the join.
    Accepted,
    /// The join was rejected (validation failure, quorum rejection, or timeout).
    Rejected,
    /// The join has been committed to the epoch and the peer is now a member.
    Committed,
}

// ---------------------------------------------------------------------------
// PendingJoin — a single join tracked through admission
// ---------------------------------------------------------------------------

/// A tracked in-flight join request moving through the admission lifecycle.
#[derive(Clone, Debug)]
pub struct PendingJoin {
    /// The joining peer's member identity.
    pub member_id: MemberId,
    /// The proposed join epoch (must be >= current committed epoch).
    pub join_epoch: EpochId,
    /// Millisecond timestamp when the join request was created.
    pub created_at_millis: u64,
    /// Current admission state.
    pub state: AdmissionState,
    /// Reason for rejection, set when state becomes Rejected.
    pub rejection_reason: Option<String>,
    /// Operational capabilities advertised by the joining peer, if any.
    pub peer_capabilities: Option<PeerCapabilities>,
    /// Millisecond timestamp when the proposal was initiated.
    pub proposed_at_millis: Option<u64>,
    /// Millisecond timestamp when the final outcome was reached.
    pub resolved_at_millis: Option<u64>,
}

impl PendingJoin {
    /// Create a new pending join in the `Pending` state.
    pub fn new(
        member_id: MemberId,
        join_epoch: EpochId,
        created_at_millis: u64,
        peer_capabilities: Option<PeerCapabilities>,
    ) -> Self {
        Self {
            member_id,
            join_epoch,
            created_at_millis,
            state: AdmissionState::Pending,
            rejection_reason: None,
            peer_capabilities,
            proposed_at_millis: None,
            resolved_at_millis: None,
        }
    }

    /// Transition to `Proposed`, recording the proposal timestamp.
    pub fn mark_proposed(&mut self, now_millis: u64) {
        self.state = AdmissionState::Proposed;
        self.proposed_at_millis = Some(now_millis);
    }

    /// Transition to `Accepted`, recording the resolution timestamp.
    pub fn mark_accepted(&mut self, now_millis: u64) {
        self.state = AdmissionState::Accepted;
        self.resolved_at_millis = Some(now_millis);
    }

    /// Transition to `Rejected` with a reason, recording the resolution timestamp.
    pub fn mark_rejected(&mut self, reason: String, now_millis: u64) {
        self.state = AdmissionState::Rejected;
        self.rejection_reason = Some(reason);
        self.resolved_at_millis = Some(now_millis);
    }

    /// Transition to `Committed`, recording the resolution timestamp.
    pub fn mark_committed(&mut self, now_millis: u64) {
        self.state = AdmissionState::Committed;
        self.resolved_at_millis = Some(now_millis);
    }

    /// Whether this join has reached a terminal state (Rejected or Committed).
    /// Once terminal, the handler may remove it from the active set.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            AdmissionState::Rejected | AdmissionState::Committed
        )
    }

    /// Whether this join is stale: has been in `Pending` or `Proposed` state
    /// for longer than `timeout_ms`.
    pub fn is_expired(&self, timeout_ms: u64, now_millis: u64) -> bool {
        if self.is_terminal() {
            return false;
        }
        let age_ms = now_millis.saturating_sub(self.created_at_millis);
        age_ms > timeout_ms
    }
}

// ---------------------------------------------------------------------------
// JoinRequestHandler — coordinator-side admission lifecycle manager
// ---------------------------------------------------------------------------

/// Handles inbound [`MembershipMessage::JoinRequest`] messages: validates
/// admission constraints, creates a [`PendingJoin`], initiates a quorum
/// proposal via the configured callback, and manages the join through to
/// a final outcome delivered via the outcome callback.
///
/// Implements [`MembershipMessageHandler`] so the handler can be registered
/// with [`crate::membership_inbound_dispatch::MembershipInboundDispatch`]
/// via [`crate::membership_inbound_dispatch::HandlerSet::with_join_request_handler`].
pub struct JoinRequestHandler {
    /// Active pending joins, keyed by joining peer's [`MemberId`].
    pending: RwLock<HashMap<MemberId, PendingJoin>>,
    /// Maximum number of members allowed in the cluster.
    max_members: usize,
    /// Milliseconds before a pending join is considered expired.
    join_timeout_ms: u64,
    /// Shared capability view populated on join commit and capability update.
    capability_view: Arc<Mutex<MembershipCapabilityView>>,
    /// Reference to the authoritative membership roster for duplicate-member
    /// checks.
    roster: RwLock<Option<Box<MembershipRoster>>>,
    /// Callback invoked when a validated join should be proposed.
    /// Receives the [`PendingJoin`] and should initiate a quorum proposal
    /// (e.g., broadcast [`MembershipOutboundMessage::ProposalSubmission`]).
    on_propose: RwLock<Option<JoinProposalCallback>>,
    /// Callback invoked when a join reaches a final outcome (Accepted or
    /// Rejected).  The runtime wires this to the [`JoinResponseDispatcher`]
    /// to deliver the outcome to the joining peer.
    on_outcome: RwLock<Option<JoinOutcomeCallback>>,
}

impl JoinRequestHandler {
    /// Create a new join-request handler.
    ///
    /// `max_members` is the maximum cluster size (including existing members).
    /// `join_timeout_ms` is the timeout for stale pending joins.
    pub fn new(
        max_members: usize,
        join_timeout_ms: u64,
        capability_view: Arc<Mutex<MembershipCapabilityView>>,
    ) -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            max_members,
            join_timeout_ms,
            capability_view,
            roster: RwLock::new(None),
            on_propose: RwLock::new(None),
            on_outcome: RwLock::new(None),
        }
    }

    /// Set the membership roster reference for duplicate-member checks.
    pub fn set_roster(&self, roster: MembershipRoster) {
        *self.roster.write().expect("lock poisoned") = Some(Box::new(roster));
    }

    /// Set the proposal initiation callback.
    ///
    /// Called when a validated join should be proposed via the quorum system.
    /// The callback receives the [`PendingJoin`] and should broadcast a
    /// [`MembershipOutboundMessage::ProposalSubmission`].
    pub fn set_on_propose<F: Fn(&PendingJoin) + Send + Sync + 'static>(&self, cb: F) {
        *self.on_propose.write().expect("lock poisoned") = Some(Box::new(cb));
    }

    /// Set the outcome delivery callback.
    ///
    /// Called when a join reaches a final outcome (accepted or rejected).
    /// The runtime wires this to the [`JoinResponseDispatcher`] to deliver
    /// the result to the joining peer.
    pub fn set_on_outcome<F: Fn(PendingJoin) + Send + Sync + 'static>(&self, cb: F) {
        *self.on_outcome.write().expect("lock poisoned") = Some(Box::new(cb));
    }

    /// Number of active (non-terminal) pending joins.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.pending
            .read()
            .expect("lock poisoned")
            .values()
            .filter(|p| !p.is_terminal())
            .count()
    }

    /// Total number of tracked joins (including terminal).
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.pending.read().expect("lock poisoned").len()
    }

    /// Look up a pending join by member id.
    #[must_use]
    pub fn get(&self, member_id: &MemberId) -> Option<PendingJoin> {
        self.pending
            .read()
            .expect("lock poisoned")
            .get(member_id)
            .cloned()
    }

    /// Transition a pending join to `Accepted`.
    ///
    /// Called by the runtime when quorum acceptance is confirmed.
    /// Returns `true` if the transition was applied, `false` if no matching
    /// pending join exists or it is already terminal.
    pub fn accept(&self, member_id: &MemberId, now_millis: u64) -> bool {
        let mut pending = self.pending.write().expect("lock poisoned");
        if let Some(pj) = pending.get_mut(member_id) {
            if pj.is_terminal() {
                return false;
            }
            pj.mark_accepted(now_millis);
            let pj_clone = pj.clone();
            drop(pending); // release lock before callback
            if let Some(cb) = self.on_outcome.read().expect("lock poisoned").as_ref() {
                cb(pj_clone);
            }
            return true;
        }
        false
    }

    /// Transition a pending join to `Rejected`.
    ///
    /// Called by the runtime when quorum rejection occurs or validation fails
    /// externally.  Returns `true` if the transition was applied.
    pub fn reject(&self, member_id: &MemberId, reason: String, now_millis: u64) -> bool {
        let mut pending = self.pending.write().expect("lock poisoned");
        if let Some(pj) = pending.get_mut(member_id) {
            if pj.is_terminal() {
                return false;
            }
            pj.mark_rejected(reason, now_millis);
            let pj_clone = pj.clone();
            drop(pending);
            if let Some(cb) = self.on_outcome.read().expect("lock poisoned").as_ref() {
                cb(pj_clone);
            }
            return true;
        }
        false
    }

    /// Transition a pending join to `Committed`.
    ///
    /// Called by the runtime when the epoch advances and the join is committed.
    /// Returns `true` if the transition was applied. When the join carries
    /// peer capabilities, they are inserted into the shared capability view.
    pub fn commit(&self, member_id: &MemberId, now_millis: u64) -> bool {
        let mut pending = self.pending.write().expect("lock poisoned");
        if let Some(pj) = pending.get_mut(member_id) {
            if matches!(pj.state, AdmissionState::Rejected) {
                return false;
            }
            pj.mark_committed(now_millis);
            // Insert peer capabilities into the shared view, if advertised.
            if let Some(ref caps) = pj.peer_capabilities {
                let mut view = self
                    .capability_view
                    .lock()
                    .expect("capability view lock poisoned");
                view.insert(*member_id, caps.clone());
            }
            return true;
        }
        false
    }

    /// Remove a pending join entirely (e.g., after it has been committed or
    /// the outcome has been delivered).  Returns the removed [`PendingJoin`]
    /// if one existed.
    pub fn remove(&self, member_id: &MemberId) -> Option<PendingJoin> {
        self.pending
            .write()
            .expect("lock poisoned")
            .remove(member_id)
    }

    /// Reap expired pending joins: any join in `Pending` or `Proposed` state
    /// older than `join_timeout_ms` is transitioned to `Rejected` with an
    /// expiry reason and the outcome callback is invoked.
    ///
    /// Returns the number of joins reaped.
    pub fn reap_expired(&self, now_millis: u64) -> usize {
        let mut reaped = 0usize;
        let expired_ids: Vec<MemberId> = {
            let pending = self.pending.read().expect("lock poisoned");
            pending
                .iter()
                .filter(|(_, pj)| pj.is_expired(self.join_timeout_ms, now_millis))
                .map(|(id, _)| *id)
                .collect()
        };

        for id in expired_ids {
            self.reject(&id, "join request timed out".into(), now_millis);
            reaped += 1;
        }
        reaped
    }

    /// Clear all terminal joins from the active set.
    ///
    /// Returns the number removed.
    pub fn purge_terminal(&self) -> usize {
        let mut pending = self.pending.write().expect("lock poisoned");
        let before = pending.len();
        pending.retain(|_, pj| !pj.is_terminal());
        before - pending.len()
    }

    // -- internal validation helpers --

    /// Validate admission constraints for a join request.
    ///
    /// Returns `Ok(())` if the join should proceed, or an `Err` with a
    /// human-readable rejection reason.
    fn validate_admission(&self, member_id: MemberId, _join_epoch: EpochId) -> Result<(), String> {
        // Check if already a member.
        if let Some(ref roster) = *self.roster.read().expect("lock poisoned") {
            if roster.lookup(member_id).is_some() {
                return Err("peer is already a cluster member".into());
            }
            if roster.len() >= self.max_members {
                return Err(format!("cluster at member limit ({})", self.max_members));
            }
        }

        // Check for duplicate pending join.
        let pending = self.pending.read().expect("lock poisoned");
        if let Some(pj) = pending.get(&member_id) {
            if !pj.is_terminal() {
                return Err(format!(
                    "join request already in progress (state: {:?})",
                    pj.state
                ));
            }
        }

        Ok(())
    }
}

impl Default for JoinRequestHandler {
    fn default() -> Self {
        Self::new(
            64,
            30_000,
            Arc::new(Mutex::new(MembershipCapabilityView::new())),
        )
    }
}

impl MembershipMessageHandler for JoinRequestHandler {
    fn handle_join_request(&self, msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        let (member_id, join_epoch, created_at_millis, peer_capabilities) = match msg {
            MembershipMessage::JoinRequest {
                member_id,
                join_epoch,
                created_at_millis,
                peer_capabilities,
            } => (
                *member_id,
                *join_epoch,
                *created_at_millis,
                peer_capabilities.clone(),
            ),
            _ => {
                return Err(MembershipDispatchError::HandlerError(
                    "JoinRequestHandler received non-JoinRequest message".into(),
                ));
            }
        };

        // 1. Validate admission constraints.
        if let Err(reason) = self.validate_admission(member_id, join_epoch) {
            // Create rejected PendingJoin for callback delivery, but do not
            // overwrite an existing active join in the map — insert only if
            // no entry exists, so the original Proposed join survives for
            // the duplicate-pending rejection case.
            let mut pj = PendingJoin::new(
                member_id,
                join_epoch,
                created_at_millis,
                peer_capabilities.clone(),
            );
            pj.mark_rejected(reason.clone(), created_at_millis);

            {
                let mut pending = self.pending.write().expect("lock poisoned");
                pending.entry(member_id).or_insert_with(|| pj.clone());
            }

            if let Some(cb) = self.on_outcome.read().expect("lock poisoned").as_ref() {
                cb(pj);
            }
            return Ok(());
        }

        // 2. Create PendingJoin in Pending state.
        let pj = PendingJoin::new(member_id, join_epoch, created_at_millis, peer_capabilities);
        {
            let mut pending = self.pending.write().expect("lock poisoned");
            pending.insert(member_id, pj.clone());
        }

        // 3. Transition to Proposed and invoke proposal initiator.
        {
            let mut pending = self.pending.write().expect("lock poisoned");
            if let Some(pj_ref) = pending.get_mut(&member_id) {
                pj_ref.mark_proposed(created_at_millis);
            }
        }

        let proposed_pj = self
            .pending
            .read()
            .expect("lock poisoned")
            .get(&member_id)
            .cloned()
            .unwrap_or(pj.clone());

        if let Some(cb) = self.on_propose.read().expect("lock poisoned").as_ref() {
            cb(&proposed_pj);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_view::CapabilityUpdateHandler;
    use crate::dispatch_router::MembershipDispatchRouter;
    use std::sync::{Arc, Mutex};
    use tidefs_membership_epoch::EpochId;
    use tidefs_membership_types::capabilities::TransportCarrier;

    fn make_handler(max_members: usize, timeout_ms: u64) -> JoinRequestHandler {
        JoinRequestHandler::new(
            max_members,
            timeout_ms,
            Arc::new(Mutex::new(MembershipCapabilityView::new())),
        )
    }

    fn make_join_msg(member_id: u64, join_epoch: u64, created_at_millis: u64) -> MembershipMessage {
        MembershipMessage::JoinRequest {
            member_id: MemberId::new(member_id),
            join_epoch: EpochId::new(join_epoch),
            created_at_millis,
            peer_capabilities: None,
        }
    }

    fn make_join_msg_with_caps(
        member_id: u64,
        join_epoch: u64,
        created_at_millis: u64,
        caps: PeerCapabilities,
    ) -> MembershipMessage {
        MembershipMessage::JoinRequest {
            member_id: MemberId::new(member_id),
            join_epoch: EpochId::new(join_epoch),
            created_at_millis,
            peer_capabilities: Some(caps),
        }
    }

    // --- AdmissionState ---

    #[test]
    fn admission_state_terminal_semantics() {
        assert!(
            !matches!(AdmissionState::Pending, s if matches!(s, AdmissionState::Rejected | AdmissionState::Committed))
        );
        assert!(
            !matches!(AdmissionState::Proposed, s if matches!(s, AdmissionState::Rejected | AdmissionState::Committed))
        );
        assert!(
            !matches!(AdmissionState::Accepted, s if matches!(s, AdmissionState::Rejected | AdmissionState::Committed))
        );
        assert!(matches!(
            AdmissionState::Rejected,
            AdmissionState::Rejected | AdmissionState::Committed
        ));
        assert!(matches!(
            AdmissionState::Committed,
            AdmissionState::Rejected | AdmissionState::Committed
        ));
    }

    // --- PendingJoin ---

    #[test]
    fn pending_join_initial_state() {
        let pj = PendingJoin::new(MemberId::new(42), EpochId::new(3), 1000, None);
        assert_eq!(pj.member_id, MemberId::new(42));
        assert_eq!(pj.join_epoch, EpochId::new(3));
        assert_eq!(pj.created_at_millis, 1000);
        assert_eq!(pj.state, AdmissionState::Pending);
        assert!(pj.rejection_reason.is_none());
        assert!(!pj.is_terminal());
    }

    #[test]
    fn pending_join_state_transitions() {
        let mut pj = PendingJoin::new(MemberId::new(1), EpochId::new(0), 0, None);

        pj.mark_proposed(500);
        assert_eq!(pj.state, AdmissionState::Proposed);
        assert_eq!(pj.proposed_at_millis, Some(500));
        assert!(!pj.is_terminal());

        pj.mark_accepted(1000);
        assert_eq!(pj.state, AdmissionState::Accepted);
        assert_eq!(pj.resolved_at_millis, Some(1000));
        assert!(!pj.is_terminal());

        pj.mark_committed(1500);
        assert_eq!(pj.state, AdmissionState::Committed);
        assert!(pj.is_terminal());
    }

    #[test]
    fn pending_join_rejection_lifecycle() {
        let mut pj = PendingJoin::new(MemberId::new(2), EpochId::new(1), 0, None);
        pj.mark_rejected("cluster full".into(), 300);
        assert_eq!(pj.state, AdmissionState::Rejected);
        assert_eq!(pj.rejection_reason.as_deref(), Some("cluster full"));
        assert_eq!(pj.resolved_at_millis, Some(300));
        assert!(pj.is_terminal());
    }

    #[test]
    fn pending_join_is_expired() {
        let pj = PendingJoin::new(MemberId::new(1), EpochId::new(0), 1000, None);
        assert!(!pj.is_expired(5000, 5000)); // age = 4000 < 5000
        assert!(pj.is_expired(5000, 6001)); // age = 5001 > 5000
        assert!(!pj.is_expired(5000, 6000)); // age = 5000 = timeout (not expired)
    }

    #[test]
    fn pending_join_terminal_never_expired() {
        let mut pj = PendingJoin::new(MemberId::new(1), EpochId::new(0), 1000, None);
        pj.mark_rejected("test".into(), 2000);
        assert!(!pj.is_expired(500, 10000)); // terminal, not expired regardless
    }

    #[test]
    fn pending_join_clone_and_debug() {
        let pj = PendingJoin::new(MemberId::new(99), EpochId::new(5), 1234, None);
        let cloned = pj.clone();
        assert_eq!(cloned.member_id, pj.member_id);
        assert_eq!(cloned.state, pj.state);
        let s = format!("{pj:?}");
        assert!(s.contains("99") || s.contains("Pending"));
    }

    // --- JoinRequestHandler ---

    #[test]
    fn handler_valid_join_creates_pending_and_calls_propose() {
        let handler = make_handler(10, 30_000);
        let proposed: Arc<Mutex<Vec<PendingJoin>>> = Arc::new(Mutex::new(Vec::new()));
        let p_clone = Arc::clone(&proposed);
        handler.set_on_propose(move |pj| {
            p_clone.lock().unwrap().push(pj.clone());
        });

        let msg = make_join_msg(42, 5, 1000);
        let result = handler.handle_join_request(&msg);
        assert!(result.is_ok());

        // Should have one active pending join
        assert_eq!(handler.active_count(), 1);

        // Proposal callback should have been called
        let props = proposed.lock().unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].member_id, MemberId::new(42));
        assert_eq!(props[0].state, AdmissionState::Proposed);

        // Pending join should be in Proposed state
        let pj = handler.get(&MemberId::new(42)).unwrap();
        assert_eq!(pj.state, AdmissionState::Proposed);
    }

    #[test]
    fn handler_rejects_duplicate_pending_join() {
        let handler = make_handler(10, 30_000);
        let outcomes: Arc<Mutex<Vec<PendingJoin>>> = Arc::new(Mutex::new(Vec::new()));
        let o_clone = Arc::clone(&outcomes);
        handler.set_on_outcome(move |pj| {
            o_clone.lock().unwrap().push(pj);
        });

        let msg1 = make_join_msg(42, 5, 1000);
        handler.handle_join_request(&msg1).unwrap();
        assert_eq!(handler.active_count(), 1);

        // Duplicate join request from same peer — should be rejected
        // but not overwrite the active Proposed entry in the map.
        let msg2 = make_join_msg(42, 6, 2000);
        handler.handle_join_request(&msg2).unwrap();

        // The original entry is still Proposed (not replaced).
        let pj = handler.get(&MemberId::new(42)).unwrap();
        assert_eq!(pj.state, AdmissionState::Proposed);

        // Only the original entry remains in the map; the duplicate
        // was rejected and delivered via the outcome callback.
        assert_eq!(handler.total_count(), 1);
        assert_eq!(handler.active_count(), 1);

        // Outcome callback should have fired with the rejected join.
        let results = outcomes.lock().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, AdmissionState::Rejected);
        assert!(results[0]
            .rejection_reason
            .as_deref()
            .unwrap()
            .contains("already in progress"));
    }

    #[test]
    fn handler_rejects_already_member() {
        let handler = make_handler(10, 30_000);
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(42));
        handler.set_roster(roster);

        let outcomes: Arc<Mutex<Vec<PendingJoin>>> = Arc::new(Mutex::new(Vec::new()));
        let o_clone = Arc::clone(&outcomes);
        handler.set_on_outcome(move |pj| {
            o_clone.lock().unwrap().push(pj);
        });

        let msg = make_join_msg(42, 5, 1000);
        handler.handle_join_request(&msg).unwrap();

        // Should have been rejected immediately
        let results = outcomes.lock().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, AdmissionState::Rejected);
        assert!(results[0]
            .rejection_reason
            .as_deref()
            .unwrap()
            .contains("already a cluster member"));

        assert_eq!(handler.active_count(), 0);
    }

    #[test]
    fn handler_rejects_cluster_full() {
        let handler = make_handler(2, 30_000); // max 2 members
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1));
        roster.add_member(MemberId::new(2));
        handler.set_roster(roster);

        let outcomes: Arc<Mutex<Vec<PendingJoin>>> = Arc::new(Mutex::new(Vec::new()));
        let o_clone = Arc::clone(&outcomes);
        handler.set_on_outcome(move |pj| {
            o_clone.lock().unwrap().push(pj);
        });

        let msg = make_join_msg(3, 5, 1000);
        handler.handle_join_request(&msg).unwrap();

        let results = outcomes.lock().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, AdmissionState::Rejected);
        assert!(results[0]
            .rejection_reason
            .as_deref()
            .unwrap()
            .contains("member limit"));
    }

    #[test]
    fn handler_accept_transitions_state() {
        let handler = make_handler(10, 30_000);
        let msg = make_join_msg(42, 5, 1000);
        handler.handle_join_request(&msg).unwrap();

        let accepted = handler.accept(&MemberId::new(42), 2000);
        assert!(accepted);

        let pj = handler.get(&MemberId::new(42)).unwrap();
        assert_eq!(pj.state, AdmissionState::Accepted);
        assert_eq!(pj.resolved_at_millis, Some(2000));
    }

    #[test]
    fn handler_reject_transitions_state() {
        let handler = make_handler(10, 30_000);
        let msg = make_join_msg(42, 5, 1000);
        handler.handle_join_request(&msg).unwrap();

        let rejected = handler.reject(&MemberId::new(42), "quorum denied".into(), 2000);
        assert!(rejected);

        let pj = handler.get(&MemberId::new(42)).unwrap();
        assert_eq!(pj.state, AdmissionState::Rejected);
        assert_eq!(pj.rejection_reason.as_deref(), Some("quorum denied"));
    }

    #[test]
    fn handler_commit_transitions_state() {
        let handler = make_handler(10, 30_000);
        let msg = make_join_msg(42, 5, 1000);
        handler.handle_join_request(&msg).unwrap();
        handler.accept(&MemberId::new(42), 1500);

        let committed = handler.commit(&MemberId::new(42), 2000);
        assert!(committed);

        let pj = handler.get(&MemberId::new(42)).unwrap();
        assert_eq!(pj.state, AdmissionState::Committed);
        assert!(pj.is_terminal());
    }

    #[test]
    fn handler_commit_refuses_rejected() {
        let handler = make_handler(10, 30_000);
        let msg = make_join_msg(42, 5, 1000);
        handler.handle_join_request(&msg).unwrap();
        handler.reject(&MemberId::new(42), "no".into(), 1500);

        let committed = handler.commit(&MemberId::new(42), 2000);
        assert!(!committed);

        let pj = handler.get(&MemberId::new(42)).unwrap();
        assert_eq!(pj.state, AdmissionState::Rejected);
    }

    #[test]
    fn handler_accept_nonexistent_returns_false() {
        let handler = make_handler(10, 30_000);
        assert!(!handler.accept(&MemberId::new(999), 1000));
    }

    #[test]
    fn handler_reject_nonexistent_returns_false() {
        let handler = make_handler(10, 30_000);
        assert!(!handler.reject(&MemberId::new(999), "no".into(), 1000));
    }

    #[test]
    fn handler_commit_nonexistent_returns_false() {
        let handler = make_handler(10, 30_000);
        assert!(!handler.commit(&MemberId::new(999), 1000));
    }

    #[test]
    fn handler_reap_expired_transitions_to_rejected() {
        let handler = make_handler(10, 1000); // 1 second timeout
        let outcomes: Arc<Mutex<Vec<PendingJoin>>> = Arc::new(Mutex::new(Vec::new()));
        let o_clone = Arc::clone(&outcomes);
        handler.set_on_outcome(move |pj| {
            o_clone.lock().unwrap().push(pj);
        });

        let msg = make_join_msg(42, 5, 1000);
        handler.handle_join_request(&msg).unwrap();

        // At time 2500, age = 1500 > 1000 timeout -> expired
        let reaped = handler.reap_expired(2500);
        assert_eq!(reaped, 1);

        // Check the pending join was rejected
        let pj = handler.get(&MemberId::new(42)).unwrap();
        assert_eq!(pj.state, AdmissionState::Rejected);
        assert!(pj
            .rejection_reason
            .as_deref()
            .unwrap()
            .contains("timed out"));

        // Outcome callback should have fired
        let results = outcomes.lock().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, AdmissionState::Rejected);
    }

    #[test]
    fn handler_reap_expired_ignores_non_expired() {
        let handler = make_handler(10, 5000);
        let msg = make_join_msg(42, 5, 1000);
        handler.handle_join_request(&msg).unwrap();

        let reaped = handler.reap_expired(2500);
        assert_eq!(reaped, 0);
        assert_eq!(handler.active_count(), 1);

        let pj = handler.get(&MemberId::new(42)).unwrap();
        assert_eq!(pj.state, AdmissionState::Proposed);
    }

    #[test]
    fn handler_purge_terminal_removes_completed() {
        let handler = make_handler(10, 30_000);

        // Create and reject one join
        let msg1 = make_join_msg(1, 5, 1000);
        handler.handle_join_request(&msg1).unwrap();
        handler.reject(&MemberId::new(1), "no".into(), 2000);

        // Create and commit another
        let msg2 = make_join_msg(2, 5, 1000);
        handler.handle_join_request(&msg2).unwrap();
        handler.accept(&MemberId::new(2), 1500);
        handler.commit(&MemberId::new(2), 2000);

        // Create an active one
        let msg3 = make_join_msg(3, 5, 1000);
        handler.handle_join_request(&msg3).unwrap();

        assert_eq!(handler.total_count(), 3);
        assert_eq!(handler.active_count(), 1);

        let purged = handler.purge_terminal();
        assert_eq!(purged, 2);
        assert_eq!(handler.total_count(), 1);
        assert_eq!(handler.active_count(), 1);
        assert!(handler.get(&MemberId::new(3)).is_some());
    }

    #[test]
    fn handler_remove_nonexistent_returns_none() {
        let handler = make_handler(10, 30_000);
        assert!(handler.remove(&MemberId::new(999)).is_none());
    }

    #[test]
    fn handler_outcome_callback_on_accept() {
        let handler = make_handler(10, 30_000);
        let outcomes: Arc<Mutex<Vec<PendingJoin>>> = Arc::new(Mutex::new(Vec::new()));
        let o_clone = Arc::clone(&outcomes);
        handler.set_on_outcome(move |pj| {
            o_clone.lock().unwrap().push(pj);
        });

        let msg = make_join_msg(42, 5, 1000);
        handler.handle_join_request(&msg).unwrap();
        handler.accept(&MemberId::new(42), 2000);

        let results = outcomes.lock().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, AdmissionState::Accepted);
    }

    #[test]
    fn handler_outcome_callback_on_reject() {
        let handler = make_handler(10, 30_000);
        let outcomes: Arc<Mutex<Vec<PendingJoin>>> = Arc::new(Mutex::new(Vec::new()));
        let o_clone = Arc::clone(&outcomes);
        handler.set_on_outcome(move |pj| {
            o_clone.lock().unwrap().push(pj);
        });

        let msg = make_join_msg(42, 5, 1000);
        handler.handle_join_request(&msg).unwrap();
        handler.reject(&MemberId::new(42), "denied".into(), 2000);

        let results = outcomes.lock().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, AdmissionState::Rejected);
    }

    #[test]
    fn handler_no_propose_callback_is_noop() {
        let handler = make_handler(10, 30_000);
        let msg = make_join_msg(42, 5, 1000);
        let result = handler.handle_join_request(&msg);
        assert!(result.is_ok());
        assert_eq!(handler.active_count(), 1);

        let pj = handler.get(&MemberId::new(42)).unwrap();
        assert_eq!(pj.state, AdmissionState::Proposed);
    }

    #[test]
    fn handler_default_creates_with_sensible_defaults() {
        let handler = JoinRequestHandler::default();
        assert_eq!(handler.max_members, 64);
        assert_eq!(handler.join_timeout_ms, 30_000);
        assert_eq!(handler.active_count(), 0);
    }

    #[test]
    fn handler_is_membership_message_handler() {
        fn _assert_handler<T: MembershipMessageHandler + Send + Sync>(_: &T) {}
        let handler = JoinRequestHandler::new(
            10,
            30_000,
            Arc::new(Mutex::new(MembershipCapabilityView::new())),
        );
        _assert_handler(&handler);
    }

    #[test]
    fn handler_non_join_request_message_returns_error() {
        let handler = make_handler(10, 30_000);
        let msg = MembershipMessage::HealthReport {
            member_id: MemberId::new(1),
            epoch: EpochId::new(0),
            health_class: 0,
            reported_at_millis: 0,
        };
        let result = handler.handle_join_request(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn handler_active_count_excludes_terminal() {
        let handler = make_handler(10, 30_000);
        let msg = make_join_msg(42, 5, 1000);
        handler.handle_join_request(&msg).unwrap();
        assert_eq!(handler.active_count(), 1);

        handler.reject(&MemberId::new(42), "no".into(), 2000);
        assert_eq!(handler.active_count(), 0);
    }

    // ── Capability view integration tests ──────────────────────────

    #[test]
    fn join_capabilities_flow_to_capability_view_on_commit() {
        let view = Arc::new(Mutex::new(MembershipCapabilityView::new()));
        let handler = JoinRequestHandler::new(10, 30_000, Arc::clone(&view));

        let caps = PeerCapabilities {
            storage_capacity_bytes: 10_000_000_000,
            available_bytes: 5_000_000_000,
            transport_carriers: TransportCarrier::TCP.union(TransportCarrier::RDMA),
            failure_domain_datacenter: "dc-east".to_string(),
            failure_domain_rack: "rack-42".to_string(),
            coordinator_eligible: true,
            attributes: vec![("zone".to_string(), "us-east-1a".to_string())],
        };

        let msg = make_join_msg_with_caps(42, 5, 1000, caps.clone());
        handler.handle_join_request(&msg).unwrap();

        // Before commit: capability view should still be empty.
        {
            let v = view.lock().unwrap();
            assert!(v.is_empty());
            assert!(v.lookup(MemberId::new(42)).is_none());
        }

        // Accept and commit the join.
        handler.accept(&MemberId::new(42), 1500);
        let committed = handler.commit(&MemberId::new(42), 2000);
        assert!(committed);

        // After commit: capability view should be populated.
        {
            let v = view.lock().unwrap();
            assert_eq!(v.len(), 1);
            let stored = v
                .lookup(MemberId::new(42))
                .expect("capabilities should be stored");
            assert_eq!(stored.storage_capacity_bytes, 10_000_000_000);
            assert_eq!(stored.available_bytes, 5_000_000_000);
            assert!(stored.transport_carriers.contains(TransportCarrier::TCP));
            assert!(stored.transport_carriers.contains(TransportCarrier::RDMA));
            assert_eq!(stored.failure_domain_datacenter, "dc-east");
            assert_eq!(stored.failure_domain_rack, "rack-42");
            assert!(stored.coordinator_eligible);
            assert_eq!(stored.attributes.len(), 1);
            assert_eq!(
                stored.attributes[0],
                ("zone".to_string(), "us-east-1a".to_string())
            );
        }
    }

    #[test]
    fn join_without_capabilities_does_not_populate_view() {
        let view = Arc::new(Mutex::new(MembershipCapabilityView::new()));
        let handler = JoinRequestHandler::new(10, 30_000, Arc::clone(&view));

        let msg = make_join_msg(42, 5, 1000); // no capabilities
        handler.handle_join_request(&msg).unwrap();
        handler.accept(&MemberId::new(42), 1500);
        let committed = handler.commit(&MemberId::new(42), 2000);
        assert!(committed);

        let v = view.lock().unwrap();
        assert!(
            v.is_empty(),
            "view should be empty when join had no capabilities"
        );
    }

    #[test]
    fn capability_update_handler_dispatches_through_router() {
        let view = Arc::new(Mutex::new(MembershipCapabilityView::new()));

        // Create the capability update handler.
        let capability_handler = CapabilityUpdateHandler::new(Arc::clone(&view));

        // Register it in a dispatch router at discriminant 28.
        let mut router = MembershipDispatchRouter::new();
        router.register(30, Box::new(capability_handler));
        assert!(router.has_handler(30));

        // Create a CapabilityUpdate message with concrete capabilities.
        let caps = PeerCapabilities {
            storage_capacity_bytes: 5000,
            available_bytes: 3000,
            transport_carriers: TransportCarrier::TCP,
            failure_domain_datacenter: "dc-west".to_string(),
            failure_domain_rack: "rack-7".to_string(),
            coordinator_eligible: false,
            attributes: vec![],
        };
        let msg = MembershipMessage::CapabilityUpdate {
            member_id: MemberId::new(99),
            update_epoch: EpochId::new(1),
            capabilities: caps.clone(),
            updated_at_millis: 1000,
        };

        // Route the message through the dispatch router.
        router
            .route(&msg)
            .expect("routing CapabilityUpdate should succeed");

        // Verify the capability view was populated.
        let v = view.lock().unwrap();
        assert_eq!(v.len(), 1);
        let stored = v
            .lookup(MemberId::new(99))
            .expect("capabilities should be stored");
        assert_eq!(stored.storage_capacity_bytes, 5000);
        assert_eq!(stored.available_bytes, 3000);
        assert!(stored.transport_carriers.contains(TransportCarrier::TCP));
        assert_eq!(stored.failure_domain_datacenter, "dc-west");
    }

    #[test]
    fn capability_update_handler_overwrites_existing_entry() {
        let view = Arc::new(Mutex::new(MembershipCapabilityView::new()));

        let capability_handler = CapabilityUpdateHandler::new(Arc::clone(&view));
        let mut router = MembershipDispatchRouter::new();
        router.register(30, Box::new(capability_handler));

        // First update: set initial capabilities.
        let caps1 = PeerCapabilities {
            storage_capacity_bytes: 1000,
            available_bytes: 500,
            transport_carriers: TransportCarrier::TCP,
            failure_domain_datacenter: "dc-1".to_string(),
            failure_domain_rack: "r1".to_string(),
            coordinator_eligible: true,
            attributes: vec![],
        };
        router
            .route(&MembershipMessage::CapabilityUpdate {
                member_id: MemberId::new(1),
                update_epoch: EpochId::new(1),
                capabilities: caps1,
                updated_at_millis: 100,
            })
            .unwrap();

        // Second update: overwrite with new values.
        let caps2 = PeerCapabilities {
            storage_capacity_bytes: 2000,
            available_bytes: 1500,
            transport_carriers: TransportCarrier::RDMA,
            failure_domain_datacenter: "dc-2".to_string(),
            failure_domain_rack: "r2".to_string(),
            coordinator_eligible: false,
            attributes: vec![("status".to_string(), "degraded".to_string())],
        };
        router
            .route(&MembershipMessage::CapabilityUpdate {
                member_id: MemberId::new(1),
                update_epoch: EpochId::new(2),
                capabilities: caps2,
                updated_at_millis: 200,
            })
            .unwrap();

        // Verify the view reflects the latest update.
        let v = view.lock().unwrap();
        assert_eq!(v.len(), 1);
        let stored = v.lookup(MemberId::new(1)).unwrap();
        assert_eq!(stored.storage_capacity_bytes, 2000);
        assert_eq!(stored.available_bytes, 1500);
        assert!(stored.transport_carriers.contains(TransportCarrier::RDMA));
        assert!(!stored.transport_carriers.contains(TransportCarrier::TCP));
        assert_eq!(stored.failure_domain_datacenter, "dc-2");
        assert!(!stored.coordinator_eligible);
        assert_eq!(stored.attributes.len(), 1);
    }
}
