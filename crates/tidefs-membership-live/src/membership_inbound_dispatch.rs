// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Membership inbound message dispatch: a single transport receive hook that
//! routes all inbound membership protocol messages to the correct subsystem
//! handler via the centralized [`MembershipDispatchRouter`].
//!
//! ## Problem
//!
//! Before this module, each membership protocol component (epoch push
//! receiver, catch-up handler, etc.) would need to independently register
//! a transport receive callback for [`MessageFamily::PublicationProgress`],
//! deserialize the payload, and match on the message discriminant. This
//! caused dispatch fragmentation, duplicated discriminant-matching code,
//! and potential ordering issues.
//!
//! ## Solution
//!
//! [`MembershipInboundDispatch`] implements [`MessageHandler`] so it can
//! be registered as a single transport receive hook. On each inbound
//! message it:
//!
//! 1. Verifies the message family is [`MessageFamily::PublicationProgress`].
//! 2. Deserializes the payload into a [`MembershipMessage`].
//! 3. Routes through the internal [`MembershipDispatchRouter`] to the
//!    correct subsystem handler by discriminant.
//!
//! ## Architecture
//!
//! ```text
//! Transport receive loop
//!   |
//!   v
//! MessageDispatch::dispatch(DecodedMessage { family: PublicationProgress, payload })
//!   |
//!   v
//! MembershipInboundDispatch::handle(msg)
//!   |
//!   +-- bincode::deserialize<MembershipMessage>(payload)
//!   +-- MembershipDispatchRouter::route(&membership_msg)
//!         |
//!         +-- disc 18: EpochPushReceiveHandler::handle_epoch_push()
//!         +-- disc 19: EpochCatchUpResponder::handle_epoch_catch_up_request()
//!         +-- disc 20: EpochCatchUpResponseHandler::handle_epoch_catch_up_response()
//! ```
//!
//! ## Handler registration
//!
//! Handlers are registered by discriminant. Unknown discriminants
//! (no handler registered) are logged and dropped without error.
//! This allows incremental protocol deployment: new message variants
//! can be added to [`MembershipMessage`] before their handlers are
//! implemented.
//!
//! ## Security model
//!
//! This module is pure event-driven dispatch operating within the
//! existing transport/session security boundary. No new wire types,
//! framing, crypto, or protocol layers are introduced.

use std::sync::Arc;

use crate::dispatch_router::{
    MembershipDispatchError, MembershipDispatchRouter, MembershipMessage, MembershipMessageHandler,
};
use crate::epoch_fence::MembershipEpochFence;
use crate::incarnation_validator::IncarnationValidator;
use tidefs_membership_epoch::incarnation::IncarnationTracker;
use tidefs_transport::dispatch::{DecodedMessage, DispatchError, MessageHandler};
use tidefs_transport::envelope::MessageFamily;

// ---------------------------------------------------------------------------
// HandlerSet — typed collection of subsystem handlers
// ---------------------------------------------------------------------------

/// A typed collection of subsystem protocol handlers for registration
/// with the inbound dispatch router.
///
/// Each field is optional: setting a field to `None` means messages of
/// that discriminant will be logged and dropped. This allows incremental
/// handler deployment without requiring all subsystems to be wired at
/// once.
///
/// # Handler-to-discriminant mapping
///
/// | Field                            | Discriminant | Message variant           |
/// |----------------------------------|-------------|---------------------------|
/// | `epoch_push_handler`             | 18          | `EpochPush`               |
/// | `epoch_catch_up_request_handler` | 19          | `EpochCatchUpRequest`     |
/// | `epoch_catch_up_response_handler`| 20          | `EpochCatchUpResponse`    |
pub struct HandlerSet {
    /// Handler for inbound join requests (discriminant 0).
    pub join_request_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound join responses (discriminant 1).
    pub join_response_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound leave notifications (discriminant 2).
    pub leave_notification_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound health reports / liveness heartbeats (discriminant 8).
    pub health_report_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound roster push messages (discriminant 15).
    pub push_roster_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound roster pull requests (discriminant 16).
    pub pull_request_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound roster pull responses (discriminant 17).
    pub pull_response_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound epoch push broadcasts (discriminant 18).
    pub epoch_push_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound epoch catch-up requests (discriminant 19).
    pub epoch_catch_up_request_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound epoch catch-up responses (discriminant 20).
    pub epoch_catch_up_response_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound proposal submissions (discriminant 21).
    ///
    /// Delivers `ProposalSubmission` messages from the commit coordinator
    /// so peers can validate and vote on proposed membership changes.
    pub proposal_submission_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound proposal acknowledgments (discriminant 22).
    ///
    /// Delivers `ProposalAck` messages to the commit coordinator bridge
    /// so quorum votes from peers advance the proposal state machine.
    pub proposal_ack_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound peer-joined notifications (discriminant 23).
    ///
    /// Delivers `PeerJoined` notifications broadcast by the roster
    /// notifier when a new peer completes the join handshake.
    pub peer_joined_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound roster-snapshot messages (discriminant 24).
    ///
    /// Delivers `RosterSnapshot` messages containing the complete current
    /// roster (members, classes, states, addresses, failure domains) so
    /// newly joined peers can participate without external bootstrap.
    pub roster_snapshot_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound coordinator heartbeat messages (discriminant 25).
    pub coordinator_heartbeat_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound coordinator heartbeat ack messages (discriminant 26).
    pub coordinator_heartbeat_ack_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound journal sync batch messages (discriminant 27).
    ///
    /// Delivers `JournalSyncBatch` messages containing batched transition
    /// journal entries for peer catch-up and new-peer bootstrap.
    pub journal_sync_batch_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound departure request messages (discriminant 28).
    ///
    /// Delivers `DepartureRequest` messages from peers requesting
    /// voluntary departure from the cluster.
    pub departure_request_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound departure response messages (discriminant 29).
    ///
    /// Delivers `DepartureResponse` messages from the coordinator
    /// responding to a departure request.
    pub departure_response_handler: Option<Box<dyn MembershipMessageHandler>>,
    /// Handler for inbound capability update messages (discriminant 30).
    ///
    /// Delivers `CapabilityUpdate` messages from peers advertising
    /// refreshed operational capabilities for placement and transport selection.
    pub capability_update_handler: Option<Box<dyn MembershipMessageHandler>>,
}

impl HandlerSet {
    /// Create an empty handler set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            join_request_handler: None,
            join_response_handler: None,
            leave_notification_handler: None,
            health_report_handler: None,
            push_roster_handler: None,
            pull_request_handler: None,
            pull_response_handler: None,
            epoch_push_handler: None,
            epoch_catch_up_request_handler: None,
            epoch_catch_up_response_handler: None,
            proposal_submission_handler: None,
            proposal_ack_handler: None,
            peer_joined_handler: None,
            roster_snapshot_handler: None,
            coordinator_heartbeat_handler: None,
            coordinator_heartbeat_ack_handler: None,
            journal_sync_batch_handler: None,
            departure_request_handler: None,
            departure_response_handler: None,
            capability_update_handler: None,
        }
    }

    /// Set the join request handler.
    #[must_use]
    pub fn with_join_request_handler(mut self, handler: Box<dyn MembershipMessageHandler>) -> Self {
        self.join_request_handler = Some(handler);
        self
    }

    /// Set the join response handler.
    #[must_use]
    pub fn with_join_response_handler(
        mut self,
        handler: Box<dyn MembershipMessageHandler>,
    ) -> Self {
        self.join_response_handler = Some(handler);
        self
    }

    /// Set the leave notification handler.
    #[must_use]
    pub fn with_leave_notification_handler(
        mut self,
        handler: Box<dyn MembershipMessageHandler>,
    ) -> Self {
        self.leave_notification_handler = Some(handler);
        self
    }

    /// Set the health report / liveness handler.
    #[must_use]
    pub fn with_health_report_handler(
        mut self,
        handler: Box<dyn MembershipMessageHandler>,
    ) -> Self {
        self.health_report_handler = Some(handler);
        self
    }

    /// Set the push roster handler.
    #[must_use]
    pub fn with_push_roster_handler(mut self, handler: Box<dyn MembershipMessageHandler>) -> Self {
        self.push_roster_handler = Some(handler);
        self
    }

    /// Set the pull request handler.
    #[must_use]
    pub fn with_pull_request_handler(mut self, handler: Box<dyn MembershipMessageHandler>) -> Self {
        self.pull_request_handler = Some(handler);
        self
    }

    /// Set the pull response handler.
    #[must_use]
    pub fn with_pull_response_handler(
        mut self,
        handler: Box<dyn MembershipMessageHandler>,
    ) -> Self {
        self.pull_response_handler = Some(handler);
        self
    }

    /// Set the epoch push receive handler.
    #[must_use]
    pub fn with_epoch_push_handler(mut self, handler: Box<dyn MembershipMessageHandler>) -> Self {
        self.epoch_push_handler = Some(handler);
        self
    }

    /// Set the epoch catch-up request handler.
    #[must_use]
    pub fn with_epoch_catch_up_request_handler(
        mut self,
        handler: Box<dyn MembershipMessageHandler>,
    ) -> Self {
        self.epoch_catch_up_request_handler = Some(handler);
        self
    }

    /// Set the epoch catch-up response handler.
    #[must_use]
    pub fn with_epoch_catch_up_response_handler(
        mut self,
        handler: Box<dyn MembershipMessageHandler>,
    ) -> Self {
        self.epoch_catch_up_response_handler = Some(handler);
        self
    }

    /// Set the proposal submission handler.
    #[must_use]
    pub fn with_proposal_submission_handler(
        mut self,
        handler: Box<dyn MembershipMessageHandler>,
    ) -> Self {
        self.proposal_submission_handler = Some(handler);
        self
    }

    /// Set the proposal ack handler.
    #[must_use]
    pub fn with_proposal_ack_handler(mut self, handler: Box<dyn MembershipMessageHandler>) -> Self {
        self.proposal_ack_handler = Some(handler);
        self
    }

    /// Set the peer-joined notification handler.
    #[must_use]
    pub fn with_peer_joined_handler(mut self, handler: Box<dyn MembershipMessageHandler>) -> Self {
        self.peer_joined_handler = Some(handler);
        self
    }

    /// Set the roster-snapshot handler.
    #[must_use]
    pub fn with_roster_snapshot_handler(
        mut self,
        handler: Box<dyn MembershipMessageHandler>,
    ) -> Self {
        self.roster_snapshot_handler = Some(handler);
        self
    }

    /// Set the departure request handler.
    #[must_use]
    pub fn with_departure_request_handler(
        mut self,
        handler: Box<dyn MembershipMessageHandler>,
    ) -> Self {
        self.departure_request_handler = Some(handler);
        self
    }

    /// Set the departure response handler.
    #[must_use]
    pub fn with_departure_response_handler(
        mut self,
        handler: Box<dyn MembershipMessageHandler>,
    ) -> Self {
        self.departure_response_handler = Some(handler);
        self
    }

    /// Set the journal sync batch handler.
    #[must_use]
    pub fn with_journal_sync_batch_handler(
        mut self,
        handler: Box<dyn MembershipMessageHandler>,
    ) -> Self {
        self.journal_sync_batch_handler = Some(handler);
        self
    }

    /// Set the capability update handler.
    #[must_use]
    pub fn with_capability_update_handler(
        mut self,
        handler: Box<dyn MembershipMessageHandler>,
    ) -> Self {
        self.capability_update_handler = Some(handler);
        self
    }

    /// Number of non-None handlers in this set.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        let mut count = 0usize;
        if self.join_request_handler.is_some() {
            count += 1;
        }
        if self.join_response_handler.is_some() {
            count += 1;
        }
        if self.leave_notification_handler.is_some() {
            count += 1;
        }
        if self.health_report_handler.is_some() {
            count += 1;
        }
        if self.push_roster_handler.is_some() {
            count += 1;
        }
        if self.pull_request_handler.is_some() {
            count += 1;
        }
        if self.pull_response_handler.is_some() {
            count += 1;
        }
        if self.epoch_push_handler.is_some() {
            count += 1;
        }
        if self.epoch_catch_up_request_handler.is_some() {
            count += 1;
        }
        if self.epoch_catch_up_response_handler.is_some() {
            count += 1;
        }
        if self.proposal_submission_handler.is_some() {
            count += 1;
        }
        if self.proposal_ack_handler.is_some() {
            count += 1;
        }
        if self.peer_joined_handler.is_some() {
            count += 1;
        }
        if self.roster_snapshot_handler.is_some() {
            count += 1;
        }
        if self.coordinator_heartbeat_handler.is_some() {
            count += 1;
        }
        if self.coordinator_heartbeat_ack_handler.is_some() {
            count += 1;
        }
        if self.journal_sync_batch_handler.is_some() {
            count += 1;
        }
        if self.departure_request_handler.is_some() {
            count += 1;
        }
        if self.departure_response_handler.is_some() {
            count += 1;
        }
        if self.capability_update_handler.is_some() {
            count += 1;
        }
        count
    }
}

impl Default for HandlerSet {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MembershipInboundDispatch
// ---------------------------------------------------------------------------

/// Centralized inbound dispatch for all membership protocol messages.
///
/// Implements [`MessageHandler`] so it can be registered as a single
/// transport receive hook for [`MessageFamily::PublicationProgress`].
///
/// On each inbound message, deserializes the payload into a
/// [`MembershipMessage`] and routes it through the internal
/// [`MembershipDispatchRouter`] to the correct subsystem handler.
///
/// # Registration
///
/// ```ignore
/// use tidefs_membership_live::membership_inbound_dispatch::{
///     MembershipInboundDispatch, HandlerSet,
/// };
/// use tidefs_transport::dispatch::MessageDispatch;
/// use tidefs_transport::envelope::MessageFamily;
///
/// let handlers = HandlerSet::new()
///     .with_epoch_push_handler(Box::new(my_push_handler))
///     .with_epoch_catch_up_response_handler(Box::new(my_catch_up_handler));
///
/// let dispatch = MembershipInboundDispatch::new(handlers);
/// transport_dispatch.register(
///     MessageFamily::PublicationProgress,
///     Box::new(dispatch),
/// );
/// ```
///
/// # Unregistered discriminants
///
/// Messages with discriminants that have no registered handler are
/// silently dropped after logging at `tracing::warn!` level. This
/// avoids noisy error propagation while preserving observability.
pub struct MembershipInboundDispatch {
    router: MembershipDispatchRouter,
    /// Optional epoch fence for rejecting messages from departed peers.
    fence: Option<Arc<MembershipEpochFence>>,
    /// Optional incarnation tracker for rejecting stale-command messages
    /// from deposed coordinators.
    incarnation_tracker: Option<IncarnationTracker>,
}

impl MembershipInboundDispatch {
    /// Create a new dispatch pre-configured with the given handlers.
    ///
    /// Only non-`None` entries in `HandlerSet` are registered.
    /// Create a new dispatch pre-configured with the given handlers
    /// and an optional epoch fence.
    ///
    /// When a fence is provided, inbound messages are checked against
    /// the current roster and epoch before handler dispatch.  Messages
    /// from departed peers or carrying stale epochs are rejected with
    /// a [`DispatchError::HandlerError`] wrapping a [`FenceError`].
    #[must_use]
    pub fn new_with_fence(
        handlers: HandlerSet,
        fence: Option<Arc<MembershipEpochFence>>,
        incarnation_tracker: Option<IncarnationTracker>,
    ) -> Self {
        let mut router = MembershipDispatchRouter::new();

        if let Some(h) = handlers.join_request_handler {
            router.register(0, h);
        }
        if let Some(h) = handlers.join_response_handler {
            router.register(1, h);
        }
        if let Some(h) = handlers.leave_notification_handler {
            router.register(2, h);
        }
        if let Some(h) = handlers.health_report_handler {
            router.register(8, h);
        }
        if let Some(h) = handlers.push_roster_handler {
            router.register(15, h);
        }
        if let Some(h) = handlers.pull_request_handler {
            router.register(16, h);
        }
        if let Some(h) = handlers.pull_response_handler {
            router.register(17, h);
        }
        if let Some(h) = handlers.epoch_push_handler {
            router.register(18, h);
        }
        if let Some(h) = handlers.epoch_catch_up_request_handler {
            router.register(19, h);
        }
        if let Some(h) = handlers.epoch_catch_up_response_handler {
            router.register(20, h);
        }
        if let Some(h) = handlers.proposal_submission_handler {
            router.register(21, h);
        }
        if let Some(h) = handlers.proposal_ack_handler {
            router.register(22, h);
        }
        if let Some(h) = handlers.peer_joined_handler {
            router.register(23, h);
        }
        if let Some(h) = handlers.roster_snapshot_handler {
            router.register(24, h);
        }
        if let Some(h) = handlers.coordinator_heartbeat_handler {
            router.register(25, h);
        }
        if let Some(h) = handlers.coordinator_heartbeat_ack_handler {
            router.register(26, h);
        }
        if let Some(h) = handlers.journal_sync_batch_handler {
            router.register(27, h);
        }
        if let Some(h) = handlers.departure_request_handler {
            router.register(28, h);
        }
        if let Some(h) = handlers.departure_response_handler {
            router.register(29, h);
        }
        if let Some(h) = handlers.capability_update_handler {
            router.register(30, h);
        }

        Self {
            router,
            fence,
            incarnation_tracker,
        }
    }

    /// Create a new dispatch without an epoch fence.
    ///
    /// This preserves the pre-fence constructor for callers that do not
    /// (yet) wire an epoch fence.
    #[must_use]
    pub fn new(handlers: HandlerSet) -> Self {
        Self::new_with_fence(handlers, None, None)
    }

    /// Register a handler for a given message discriminant.
    ///
    /// Replaces any existing handler for the same discriminant.
    /// Useful for adding handlers after construction without
    /// rebuilding the `HandlerSet`.
    pub fn register(&mut self, discriminant: u8, handler: Box<dyn MembershipMessageHandler>) {
        self.router.register(discriminant, handler);
    }

    /// Remove the handler for a given discriminant.
    pub fn unregister(&mut self, discriminant: u8) -> Option<Box<dyn MembershipMessageHandler>> {
        self.router.unregister(discriminant)
    }

    /// Number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.router.handler_count()
    }
}

impl MessageHandler for MembershipInboundDispatch {
    fn handle(&self, msg: DecodedMessage) -> Result<(), DispatchError> {
        // Only handle PublicationProgress messages.  Other families
        // are silently skipped (they belong to different subsystems).
        if msg.family != MessageFamily::PublicationProgress {
            return Ok(());
        }

        // Deserialize the payload into a MembershipMessage.
        let membership_msg: MembershipMessage =
            bincode::deserialize(&msg.payload).map_err(|e| {
                DispatchError::HandlerError(
                    format!("membership message bincode deserialize failed: {e}").into(),
                )
            })?;

        // Epoch-fence check: reject messages from departed peers or
        // carrying stale epochs before handler dispatch.
        if let Some(ref fence) = self.fence {
            let sender = membership_msg.sender_id();
            let msg_epoch = membership_msg.message_epoch();

            // EpochPush messages carry the receiver's own epoch view
            // (member_set broadcast); skip sender-id check for them.
            // The epoch push handler validates the content independently.
            let sender_for_check = match &membership_msg {
                MembershipMessage::EpochPush { .. } => None,
                _ => Some(sender),
            };

            if let Some(sid) = sender_for_check {
                if let Err(fence_err) = fence.check(sid, msg_epoch) {
                    return Err(DispatchError::HandlerError(
                        format!("epoch fence rejected message: {fence_err}").into(),
                    ));
                }
            }
        }

        // Incarnation validation: reject messages from deposed coordinators
        // carrying stale incarnation values (msg.incarnation < current).
        if let Some(ref tracker) = self.incarnation_tracker {
            IncarnationValidator::validate(tracker, &membership_msg).map_err(|e| {
                DispatchError::HandlerError(format!("incarnation validation failed: {e}").into())
            })?;
        }

        // Route through the dispatch router.
        match self.router.route(&membership_msg) {
            Ok(()) => Ok(()),
            Err(MembershipDispatchError::NoHandlerRegistered(_disc)) => {
                // Unregistered discriminant: silently drop.
                // Not an error — expected during incremental protocol
                // deployment when message variants exist before handlers.
                Ok(())
            }
            Err(e) => Err(DispatchError::HandlerError(
                format!("membership dispatch: {e}").into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch_router::MembershipDispatchError;
    use std::sync::{Arc, Mutex};
    use tidefs_membership_epoch::epoch_proposal::MembershipDelta;
    use tidefs_membership_epoch::{EpochId, Incarnation, LeaveReason, MemberId};
    use tidefs_transport::envelope::MessageFamily;

    // ------------------------------------------------------------------
    // Test helpers
    // ------------------------------------------------------------------

    /// A test handler that records which method was called.
    struct TestHandler {
        name: String,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl TestHandler {
        fn new(name: &str) -> (Self, Arc<Mutex<Vec<String>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let handler = Self {
                name: name.to_string(),
                calls: Arc::clone(&calls),
            };
            (handler, calls)
        }

        fn record(&self, method: &str) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{}:{}", self.name, method));
        }
    }

    impl MembershipMessageHandler for TestHandler {
        fn handle_join_request(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("join_request");
            Ok(())
        }
        fn handle_join_response(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("join_response");
            Ok(())
        }
        fn handle_leave_notification(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("leave_notification");
            Ok(())
        }
        fn handle_health_report(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("health_report");
            Ok(())
        }
        fn handle_push_roster(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("push_roster");
            Ok(())
        }
        fn handle_pull_request(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("pull_request");
            Ok(())
        }
        fn handle_pull_response(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("pull_response");
            Ok(())
        }
        fn handle_epoch_push(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("epoch_push");
            Ok(())
        }
        fn handle_epoch_catch_up_request(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("epoch_catch_up_request");
            Ok(())
        }
        fn handle_epoch_catch_up_response(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("epoch_catch_up_response");
            Ok(())
        }
        fn handle_proposal_submission(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("proposal_submission");
            Ok(())
        }
        fn handle_proposal_ack(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("proposal_ack");
            Ok(())
        }
        fn handle_peer_joined(
            &self,
            _msg: &MembershipMessage,
        ) -> Result<(), MembershipDispatchError> {
            self.record("peer_joined");
            Ok(())
        }
    }

    /// Build a bincode-encoded payload for a MembershipMessage variant.
    fn encode_msg(msg: &MembershipMessage) -> Vec<u8> {
        bincode::serialize(msg).expect("bincode serialize")
    }

    fn make_decoded(payload: Vec<u8>) -> DecodedMessage {
        DecodedMessage::new(MessageFamily::PublicationProgress, payload)
    }

    // ------------------------------------------------------------------
    // HandlerSet tests
    // ------------------------------------------------------------------

    #[test]
    fn handler_set_empty() {
        let hs = HandlerSet::new();
        assert_eq!(hs.handler_count(), 0);
    }

    #[test]
    fn handler_set_with_all_three() {
        let (h1, _) = TestHandler::new("push");
        let (h2, _) = TestHandler::new("req");
        let (h3, _) = TestHandler::new("resp");

        let hs = HandlerSet::new()
            .with_epoch_push_handler(Box::new(h1))
            .with_epoch_catch_up_request_handler(Box::new(h2))
            .with_epoch_catch_up_response_handler(Box::new(h3));

        assert_eq!(hs.handler_count(), 3);
    }

    #[test]
    fn handler_set_partial() {
        let (h1, _) = TestHandler::new("push");
        let hs = HandlerSet::new().with_epoch_push_handler(Box::new(h1));
        assert_eq!(hs.handler_count(), 1);
    }

    #[test]
    fn handler_set_with_all_thirteen() {
        // Register all 13 handler slots
        let (h0, _) = TestHandler::new("join_req");
        let (h1, _) = TestHandler::new("join_resp");
        let (h2, _) = TestHandler::new("leave");
        let (h3, _) = TestHandler::new("health");
        let (h4, _) = TestHandler::new("push_roster");
        let (h5, _) = TestHandler::new("pull_req");
        let (h6, _) = TestHandler::new("pull_resp");
        let (h7, _) = TestHandler::new("epoch_push");
        let (h8, _) = TestHandler::new("catch_req");
        let (h9, _) = TestHandler::new("catch_resp");
        let (h10, _) = TestHandler::new("prop_sub");
        let (h11, _) = TestHandler::new("prop_ack");
        let (h12, _) = TestHandler::new("peer_joined");

        let hs = HandlerSet::new()
            .with_join_request_handler(Box::new(h0))
            .with_join_response_handler(Box::new(h1))
            .with_leave_notification_handler(Box::new(h2))
            .with_health_report_handler(Box::new(h3))
            .with_push_roster_handler(Box::new(h4))
            .with_pull_request_handler(Box::new(h5))
            .with_pull_response_handler(Box::new(h6))
            .with_epoch_push_handler(Box::new(h7))
            .with_epoch_catch_up_request_handler(Box::new(h8))
            .with_epoch_catch_up_response_handler(Box::new(h9))
            .with_proposal_submission_handler(Box::new(h10))
            .with_proposal_ack_handler(Box::new(h11))
            .with_peer_joined_handler(Box::new(h12));

        assert_eq!(hs.handler_count(), 13);
    }

    #[test]
    fn handler_set_live_membership_handlers_registered_correctly() {
        // join_request (0), join_response (1), leave_notification (2),
        // push_roster (15), pull_request (16), pull_response (17)
        let (h0, _) = TestHandler::new("join_req");
        let (h2, _) = TestHandler::new("leave");
        let (h5, _) = TestHandler::new("pull_req");

        let hs = HandlerSet::new()
            .with_join_request_handler(Box::new(h0))
            .with_leave_notification_handler(Box::new(h2))
            .with_pull_request_handler(Box::new(h5));

        assert_eq!(hs.handler_count(), 3);
    }

    #[test]
    fn handler_set_default_is_empty() {
        let hs = HandlerSet::default();
        assert_eq!(hs.handler_count(), 0);
    }

    // ------------------------------------------------------------------
    // MembershipInboundDispatch tests
    // ------------------------------------------------------------------

    #[test]
    fn dispatch_routes_epoch_push_to_correct_handler() {
        let (push_h, push_calls) = TestHandler::new("push");
        let (req_h, req_calls) = TestHandler::new("req");
        let (resp_h, resp_calls) = TestHandler::new("resp");

        let handlers = HandlerSet::new()
            .with_epoch_push_handler(Box::new(push_h))
            .with_epoch_catch_up_request_handler(Box::new(req_h))
            .with_epoch_catch_up_response_handler(Box::new(resp_h));

        let dispatch = MembershipInboundDispatch::new(handlers);
        assert_eq!(dispatch.handler_count(), 3);

        let msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(5),
            member_set: vec![MemberId::new(1), MemberId::new(2)],
            created_at_millis: 1000,
        };
        let decoded = make_decoded(encode_msg(&msg));

        let result = dispatch.handle(decoded);
        assert!(result.is_ok());

        let calls = push_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].contains("epoch_push"));

        // Other handlers should not have been called
        assert!(req_calls.lock().unwrap().is_empty());
        assert!(resp_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn dispatch_routes_epoch_catch_up_request_to_correct_handler() {
        let (push_h, push_calls) = TestHandler::new("push");
        let (req_h, req_calls) = TestHandler::new("req");
        let (resp_h, resp_calls) = TestHandler::new("resp");

        let handlers = HandlerSet::new()
            .with_epoch_push_handler(Box::new(push_h))
            .with_epoch_catch_up_request_handler(Box::new(req_h))
            .with_epoch_catch_up_response_handler(Box::new(resp_h));

        let dispatch = MembershipInboundDispatch::new(handlers);

        let msg = MembershipMessage::EpochCatchUpRequest {
            requester: MemberId::new(1),
            from_epoch: 1,
            to_epoch: 5,
        };
        let decoded = make_decoded(encode_msg(&msg));

        let result = dispatch.handle(decoded);
        assert!(result.is_ok());

        assert!(push_calls.lock().unwrap().is_empty());
        let req = req_calls.lock().unwrap();
        assert_eq!(req.len(), 1);
        assert!(req[0].contains("epoch_catch_up_request"));
        assert!(resp_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn dispatch_routes_epoch_catch_up_response_to_correct_handler() {
        let (push_h, push_calls) = TestHandler::new("push");
        let (req_h, req_calls) = TestHandler::new("req");
        let (resp_h, resp_calls) = TestHandler::new("resp");

        let handlers = HandlerSet::new()
            .with_epoch_push_handler(Box::new(push_h))
            .with_epoch_catch_up_request_handler(Box::new(req_h))
            .with_epoch_catch_up_response_handler(Box::new(resp_h));

        let dispatch = MembershipInboundDispatch::new(handlers);

        let msg = MembershipMessage::EpochCatchUpResponse {
            responder: MemberId::new(2),
            epochs: vec![],
            truncated: false,
        };
        let decoded = make_decoded(encode_msg(&msg));

        let result = dispatch.handle(decoded);
        assert!(result.is_ok());

        assert!(push_calls.lock().unwrap().is_empty());
        assert!(req_calls.lock().unwrap().is_empty());
        let resp = resp_calls.lock().unwrap();
        assert_eq!(resp.len(), 1);
        assert!(resp[0].contains("epoch_catch_up_response"));
    }

    #[test]
    fn unregistered_discriminant_is_dropped_without_error() {
        let handlers = HandlerSet::new(); // empty — no handlers
        let dispatch = MembershipInboundDispatch::new(handlers);
        assert_eq!(dispatch.handler_count(), 0);

        let msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![],
            created_at_millis: 0,
        };
        let decoded = make_decoded(encode_msg(&msg));

        // Should return Ok(()) even though no handler is registered
        let result = dispatch.handle(decoded);
        assert!(result.is_ok());
    }

    #[test]
    fn non_publication_progress_family_is_silently_skipped() {
        let (push_h, push_calls) = TestHandler::new("push");
        let handlers = HandlerSet::new().with_epoch_push_handler(Box::new(push_h));
        let dispatch = MembershipInboundDispatch::new(handlers);

        let msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![],
            created_at_millis: 0,
        };
        let payload = encode_msg(&msg);
        let decoded = DecodedMessage::new(MessageFamily::HelloClose, payload);

        let result = dispatch.handle(decoded);
        assert!(result.is_ok());
        assert!(push_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn deserialize_failure_returns_error() {
        let handlers = HandlerSet::new();
        let dispatch = MembershipInboundDispatch::new(handlers);

        // Garbage bytes that won't deserialize as MembershipMessage
        let decoded = DecodedMessage::new(
            MessageFamily::PublicationProgress,
            vec![0xFF, 0xFF, 0xFF, 0xFF],
        );

        let result = dispatch.handle(decoded);
        assert!(result.is_err());
        match result {
            Err(DispatchError::HandlerError(s)) => {
                let err_msg = s.to_string();
                assert!(
                    err_msg.contains("deserialize"),
                    "error should mention deserialize: {err_msg}"
                );
            }
            other => panic!("expected HandlerError, got {other:?}"),
        }
    }

    #[test]
    fn register_and_unregister_after_construction() {
        let (push_h, push_calls) = TestHandler::new("push");
        let handlers = HandlerSet::new().with_epoch_push_handler(Box::new(push_h));
        let mut dispatch = MembershipInboundDispatch::new(handlers);
        assert_eq!(dispatch.handler_count(), 1);

        // Unregister the push handler
        let removed = dispatch.unregister(18);
        assert!(removed.is_some());
        assert_eq!(dispatch.handler_count(), 0);

        // Now push messages should be dropped silently
        let msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![],
            created_at_millis: 0,
        };
        let decoded = make_decoded(encode_msg(&msg));
        let result = dispatch.handle(decoded);
        assert!(result.is_ok());
        assert!(push_calls.lock().unwrap().is_empty());

        // Re-register
        let (new_h, new_calls) = TestHandler::new("new_push");
        dispatch.register(18, Box::new(new_h));
        assert_eq!(dispatch.handler_count(), 1);

        let msg2 = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(2),
            member_set: vec![],
            created_at_millis: 0,
        };
        let decoded2 = make_decoded(encode_msg(&msg2));
        dispatch.handle(decoded2).unwrap();
        assert_eq!(new_calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn multiple_variants_routed_to_different_handlers_in_sequence() {
        let (push_h, push_calls) = TestHandler::new("push");
        let (req_h, req_calls) = TestHandler::new("req");
        let (resp_h, resp_calls) = TestHandler::new("resp");

        let handlers = HandlerSet::new()
            .with_epoch_push_handler(Box::new(push_h))
            .with_epoch_catch_up_request_handler(Box::new(req_h))
            .with_epoch_catch_up_response_handler(Box::new(resp_h));

        let dispatch = MembershipInboundDispatch::new(handlers);

        // Push
        let msg1 = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![MemberId::new(1)],
            created_at_millis: 100,
        };
        dispatch.handle(make_decoded(encode_msg(&msg1))).unwrap();
        assert_eq!(push_calls.lock().unwrap().len(), 1);

        // Catch-up request
        let msg2 = MembershipMessage::EpochCatchUpRequest {
            requester: MemberId::new(10),
            from_epoch: 1,
            to_epoch: 3,
        };
        dispatch.handle(make_decoded(encode_msg(&msg2))).unwrap();
        assert_eq!(req_calls.lock().unwrap().len(), 1);

        // Catch-up response
        let msg3 = MembershipMessage::EpochCatchUpResponse {
            responder: MemberId::new(20),
            epochs: vec![],
            truncated: true,
        };
        dispatch.handle(make_decoded(encode_msg(&msg3))).unwrap();
        assert_eq!(resp_calls.lock().unwrap().len(), 1);

        // Push count still 1, req count still 1
        assert_eq!(push_calls.lock().unwrap().len(), 1);
        assert_eq!(req_calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn dispatch_routes_join_request_to_correct_handler() {
        let (h, calls) = TestHandler::new("join");
        let handlers = HandlerSet::new().with_join_request_handler(Box::new(h));
        let dispatch = MembershipInboundDispatch::new(handlers);
        assert_eq!(dispatch.handler_count(), 1);

        let msg = MembershipMessage::JoinRequest {
            member_id: MemberId::new(42),
            join_epoch: EpochId::new(1),
            created_at_millis: 500,
            peer_capabilities: None,
        };
        dispatch.handle(make_decoded(encode_msg(&msg))).unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(calls.lock().unwrap()[0].contains("join_request"));
    }

    #[test]
    fn dispatch_routes_health_report_to_correct_handler() {
        let (h, calls) = TestHandler::new("health");
        let handlers = HandlerSet::new().with_health_report_handler(Box::new(h));
        let dispatch = MembershipInboundDispatch::new(handlers);
        assert_eq!(dispatch.handler_count(), 1);

        let msg = MembershipMessage::HealthReport {
            member_id: MemberId::new(7),
            epoch: EpochId::new(3),
            health_class: 1,
            reported_at_millis: 999,
        };
        dispatch.handle(make_decoded(encode_msg(&msg))).unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(calls.lock().unwrap()[0].contains("health_report"));
    }

    #[test]
    fn dispatch_routes_leave_notification_to_correct_handler() {
        let (h, calls) = TestHandler::new("leave");
        let handlers = HandlerSet::new().with_leave_notification_handler(Box::new(h));
        let dispatch = MembershipInboundDispatch::new(handlers);
        assert_eq!(dispatch.handler_count(), 1);

        let msg = MembershipMessage::LeaveNotification {
            member_id: MemberId::new(99),
            departure_epoch: EpochId::new(5),
            announced_at_millis: 1000,
            leave_reason: LeaveReason::Voluntary,
            incarnation: Incarnation::ZERO,
        };
        dispatch.handle(make_decoded(encode_msg(&msg))).unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(calls.lock().unwrap()[0].contains("leave_notification"));
    }

    #[test]
    fn dispatch_routes_push_roster_to_correct_handler() {
        let (h, calls) = TestHandler::new("push_roster");
        let handlers = HandlerSet::new().with_push_roster_handler(Box::new(h));
        let dispatch = MembershipInboundDispatch::new(handlers);
        assert_eq!(dispatch.handler_count(), 1);

        let msg = MembershipMessage::PushRoster {
            originator: MemberId::new(10),
            roster_epoch: EpochId::new(2),
            roster_payload: vec![1, 2, 3],
            sent_at_millis: 2000,
        };
        dispatch.handle(make_decoded(encode_msg(&msg))).unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(calls.lock().unwrap()[0].contains("push_roster"));
    }

    #[test]
    fn dispatch_routes_proposal_submission_to_correct_handler() {
        let (h, calls) = TestHandler::new("prop_sub");
        let handlers = HandlerSet::new().with_proposal_submission_handler(Box::new(h));
        let dispatch = MembershipInboundDispatch::new(handlers);
        assert_eq!(dispatch.handler_count(), 1);

        let msg = MembershipMessage::ProposalSubmission {
            proposer: MemberId::new(1),
            current_epoch: 5,
            proposed_epoch: 6,
            delta: MembershipDelta::NodeJoined(3),
            resulting_members: vec![1, 2, 3],
            proposal_hash: [0xAAu8; 32],
            submitted_at_millis: 3000,
            catalog_delta_bytes: None,
        };
        dispatch.handle(make_decoded(encode_msg(&msg))).unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(calls.lock().unwrap()[0].contains("proposal_submission"));
    }

    #[test]
    fn handler_count_reflects_registered_handlers() {
        let (h1, _) = TestHandler::new("a");
        let (h2, _) = TestHandler::new("b");

        let handlers = HandlerSet::new()
            .with_epoch_push_handler(Box::new(h1))
            .with_epoch_catch_up_response_handler(Box::new(h2));

        let dispatch = MembershipInboundDispatch::new(handlers);
        assert_eq!(dispatch.handler_count(), 2);
    }

    #[test]
    fn handler_error_propagates_as_dispatch_error() {
        /// A handler that always errors on epoch_push.
        struct ErrorHandler;
        impl MembershipMessageHandler for ErrorHandler {
            fn handle_epoch_push(
                &self,
                _msg: &MembershipMessage,
            ) -> Result<(), MembershipDispatchError> {
                Err(MembershipDispatchError::HandlerError(
                    "test handler failure".to_string(),
                ))
            }
        }

        let handlers = HandlerSet::new().with_epoch_push_handler(Box::new(ErrorHandler));
        let dispatch = MembershipInboundDispatch::new(handlers);

        let msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(1),
            member_set: vec![],
            created_at_millis: 0,
        };
        let decoded = make_decoded(encode_msg(&msg));

        let result = dispatch.handle(decoded);
        assert!(result.is_err());
        match result {
            Err(DispatchError::HandlerError(s)) => {
                let err_msg = s.to_string();
                assert!(err_msg.contains("test handler failure"), "error: {err_msg}");
            }
            other => panic!("expected HandlerError, got {other:?}"),
        }
    }

    #[test]
    fn membership_inbound_dispatch_is_message_handler() {
        // Compile-time verification that trait bound is satisfied.
        fn _assert_handler<T: MessageHandler>(_: &T) {}

        let handlers = HandlerSet::new();
        let dispatch = MembershipInboundDispatch::new(handlers);
        _assert_handler(&dispatch);
    }

    // ------------------------------------------------------------------
    // Epoch fence integration tests
    // ------------------------------------------------------------------

    #[test]
    fn fence_rejects_message_from_departed_peer() {
        let fence = Arc::new(MembershipEpochFence::new());
        let v = crate::epoch_coordinator::EpochView::new(
            EpochId::new(5),
            vec![MemberId::new(2), MemberId::new(3)], // member 1 is NOT in the roster
            1000,
        );
        fence.update_from_view(&v);

        let (h, calls) = TestHandler::new("join");
        let handlers = HandlerSet::new().with_join_request_handler(Box::new(h));
        let dispatch = MembershipInboundDispatch::new_with_fence(handlers, Some(fence), None);

        // Message from departed member 1 (not in current roster {2,3})
        let msg = MembershipMessage::JoinRequest {
            member_id: MemberId::new(1),
            join_epoch: EpochId::new(1),
            created_at_millis: 500,
            peer_capabilities: None,
        };
        let result = dispatch.handle(make_decoded(encode_msg(&msg)));
        assert!(result.is_err(), "departed peer message should be fenced");
        match result {
            Err(DispatchError::HandlerError(s)) => {
                assert!(s.to_string().contains("epoch fence"), "error: {s}");
            }
            other => panic!("expected HandlerError, got {other:?}"),
        }
        // Handler should not have been called
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn fence_accepts_message_from_current_member() {
        let fence = Arc::new(MembershipEpochFence::new());
        let v = crate::epoch_coordinator::EpochView::new(
            EpochId::new(3),
            vec![MemberId::new(1), MemberId::new(2)],
            1000,
        );
        fence.update_from_view(&v);

        let (h, calls) = TestHandler::new("join");
        let handlers = HandlerSet::new().with_join_request_handler(Box::new(h));
        let dispatch = MembershipInboundDispatch::new_with_fence(handlers, Some(fence), None);

        // Message from current member 1
        let msg = MembershipMessage::JoinRequest {
            member_id: MemberId::new(1),
            join_epoch: EpochId::new(3),
            created_at_millis: 500,
            peer_capabilities: None,
        };
        let result = dispatch.handle(make_decoded(encode_msg(&msg)));
        assert!(result.is_ok(), "current member message should be accepted");
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn fence_rejects_stale_epoch_from_current_member() {
        let fence = Arc::new(MembershipEpochFence::new());
        let v =
            crate::epoch_coordinator::EpochView::new(EpochId::new(7), vec![MemberId::new(1)], 1000);
        fence.update_from_view(&v);

        let (h, calls) = TestHandler::new("join");
        let handlers = HandlerSet::new().with_join_request_handler(Box::new(h));
        let dispatch = MembershipInboundDispatch::new_with_fence(handlers, Some(fence), None);

        // Message from current member but with epoch 3 (stale, current is 7)
        let msg = MembershipMessage::JoinRequest {
            member_id: MemberId::new(1),
            join_epoch: EpochId::new(3),
            created_at_millis: 500,
            peer_capabilities: None,
        };
        let result = dispatch.handle(make_decoded(encode_msg(&msg)));
        assert!(result.is_err(), "stale epoch should be fenced");
        match result {
            Err(DispatchError::HandlerError(s)) => {
                assert!(s.to_string().contains("stale"), "error: {s}");
            }
            other => panic!("expected HandlerError, got {other:?}"),
        }
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn no_fence_allows_all_messages() {
        // Without a fence, messages pass through (existing behavior).
        let (h, calls) = TestHandler::new("join");
        let handlers = HandlerSet::new().with_join_request_handler(Box::new(h));
        let dispatch = MembershipInboundDispatch::new(handlers); // no fence

        // Unknown member should still be dispatched (fence is optional)
        let msg = MembershipMessage::JoinRequest {
            member_id: MemberId::new(999),
            join_epoch: EpochId::new(0),
            created_at_millis: 500,
            peer_capabilities: None,
        };
        let result = dispatch.handle(make_decoded(encode_msg(&msg)));
        assert!(result.is_ok());
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn fence_new_with_fence_no_fence_behaves_like_new() {
        let (h, calls) = TestHandler::new("join");
        let handlers = HandlerSet::new().with_join_request_handler(Box::new(h));
        let dispatch = MembershipInboundDispatch::new_with_fence(handlers, None, None);

        let msg = MembershipMessage::JoinRequest {
            member_id: MemberId::new(99),
            join_epoch: EpochId::new(0),
            created_at_millis: 500,
            peer_capabilities: None,
        };
        let result = dispatch.handle(make_decoded(encode_msg(&msg)));
        assert!(result.is_ok());
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn fence_epoch_push_passes_through() {
        // EpochPush has no single sender; it should pass the fence.
        let fence = Arc::new(MembershipEpochFence::new());
        let v = crate::epoch_coordinator::EpochView::new(
            EpochId::new(3),
            vec![MemberId::new(2), MemberId::new(3)], // no member 1
            1000,
        );
        fence.update_from_view(&v);

        let (h, calls) = TestHandler::new("push");
        let handlers = HandlerSet::new().with_epoch_push_handler(Box::new(h));
        let dispatch = MembershipInboundDispatch::new_with_fence(handlers, Some(fence), None);

        let msg = MembershipMessage::EpochPush {
            epoch_number: EpochId::new(3),
            member_set: vec![],
            created_at_millis: 1000,
        };
        let result = dispatch.handle(make_decoded(encode_msg(&msg)));
        assert!(result.is_ok(), "EpochPush should pass through fence");
        assert_eq!(calls.lock().unwrap().len(), 1);
    }
}
