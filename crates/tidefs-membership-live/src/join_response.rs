// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Join-response dispatch and handling for membership handshake completion.
//!
//! When a peer's join request is processed by the membership epoch coordinator,
//! the outcome (acceptance or rejection) must be delivered to the joining peer
//! over transport. [`JoinResponseDispatcher`] constructs a
//! [`MembershipOutboundMessage::JoinResponse`] and dispatches it through the
//! existing outbound transport pipeline.
//!
//! On the receiving side, [`JoinResponseHandler`] implements
//! [`MembershipMessageHandler`] (registered via [`HandlerSet`] slot 1) to
//! process inbound join responses: extracting the assigned `MemberId` and
//! epoch on acceptance, recording the rejection reason on rejection, and
//! handling idempotent re-delivery.

use std::collections::HashSet;
use std::sync::RwLock;

use tidefs_membership_epoch::{EpochId, Incarnation, MemberId};

use crate::dispatch_router::{
    MembershipDispatchError, MembershipMessage, MembershipMessageHandler,
};
use crate::membership_outbound_dispatch::{
    MembershipOutboundDispatch, MembershipOutboundMessage, OutboundDispatchError,
};

type JoinAcceptedCallback = Box<dyn Fn(JoinOutcome) + Send + Sync>;
type JoinRejectedCallback = Box<dyn Fn(String) + Send + Sync>;

/// The outcome of a join-request evaluation by the membership epoch
/// coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinOutcome {
    /// Join request was accepted.
    Accepted {
        /// The `MemberId` assigned to the joining peer.
        member_id: MemberId,
        /// The cluster epoch at which the peer was accepted.
        epoch: EpochId,
        /// The roster member set after the join (sorted, deduplicated).
        roster: Vec<MemberId>,
        /// Coordinator incarnation at join time.
        incarnation: Incarnation,
    },
    /// Join request was rejected.
    Rejected {
        /// Human-readable reason for rejection.
        reason: String,
    },
}

impl JoinOutcome {
    /// Returns `true` if the join was accepted.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    /// Returns `true` if the join was rejected.
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }
}

/// Dispatches join-response messages over transport to complete the join
/// handshake.
pub struct JoinResponseDispatcher<'a> {
    dispatch: &'a MembershipOutboundDispatch<'a>,
}

impl<'a> JoinResponseDispatcher<'a> {
    /// Create a new join-response dispatcher.
    pub fn new(dispatch: &'a MembershipOutboundDispatch<'a>) -> Self {
        Self { dispatch }
    }

    /// Send an acceptance join-response to the joining peer.
    pub fn send_acceptance(
        &self,
        request_member_id: MemberId,
        assigned_epoch: EpochId,
        incarnation: Incarnation,
    ) -> Result<(), OutboundDispatchError> {
        let msg = MembershipOutboundMessage::JoinResponse {
            request_member_id,
            accepted: true,
            assigned_epoch: Some(assigned_epoch),
            reject_reason: None,
            responded_at_millis: current_time_millis(),
            incarnation,
        };
        self.dispatch.send_to_peer(request_member_id, msg)
    }

    /// Send a rejection join-response to the joining peer.
    pub fn send_rejection(
        &self,
        request_member_id: MemberId,
        reason: String,
        incarnation: Incarnation,
    ) -> Result<(), OutboundDispatchError> {
        let msg = MembershipOutboundMessage::JoinResponse {
            request_member_id,
            accepted: false,
            assigned_epoch: None,
            reject_reason: Some(reason),
            responded_at_millis: current_time_millis(),
            incarnation,
        };
        self.dispatch.send_to_peer(request_member_id, msg)
    }
}

/// Handles inbound [`MembershipMessage::JoinResponse`] messages received
/// from the cluster during the join handshake.
///
/// Implements [`MembershipMessageHandler`] so it can be registered via
/// [`HandlerSet::with_join_response_handler`] at slot 1.
pub struct JoinResponseHandler {
    /// Set of already-processed (member_id, epoch) tuples for idempotency.
    processed: RwLock<HashSet<(u64, u64)>>,
    /// Callback invoked when a join response is accepted.
    on_accepted: RwLock<Option<JoinAcceptedCallback>>,
    /// Callback invoked when a join response is rejected.
    on_rejected: RwLock<Option<JoinRejectedCallback>>,
}

impl JoinResponseHandler {
    /// Create a new join-response handler with empty idempotency set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            processed: RwLock::new(HashSet::new()),
            on_accepted: RwLock::new(None),
            on_rejected: RwLock::new(None),
        }
    }

    /// Set the callback invoked when a join is accepted.
    pub fn set_on_accepted<F: Fn(JoinOutcome) + Send + Sync + 'static>(&self, cb: F) {
        *self.on_accepted.write().expect("lock poisoned") = Some(Box::new(cb));
    }

    /// Set the callback invoked when a join is rejected.
    pub fn set_on_rejected<F: Fn(String) + Send + Sync + 'static>(&self, cb: F) {
        *self.on_rejected.write().expect("lock poisoned") = Some(Box::new(cb));
    }

    /// Clear all idempotency state.
    pub fn clear_processed(&self) {
        self.processed.write().expect("lock poisoned").clear();
    }

    /// Number of unique `(member_id, epoch)` pairs recorded as processed.
    #[must_use]
    pub fn processed_count(&self) -> usize {
        self.processed.read().expect("lock poisoned").len()
    }
}

impl Default for JoinResponseHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl MembershipMessageHandler for JoinResponseHandler {
    fn handle_join_response(&self, msg: &MembershipMessage) -> Result<(), MembershipDispatchError> {
        let (request_member_id, accepted, assigned_epoch, reject_reason, incarnation) = match msg {
            MembershipMessage::JoinResponse {
                request_member_id,
                accepted,
                assigned_epoch,
                reject_reason,
                incarnation,
                ..
            } => (
                *request_member_id,
                *accepted,
                *assigned_epoch,
                reject_reason.clone(),
                *incarnation,
            ),
            _ => {
                return Err(MembershipDispatchError::HandlerError(
                    "JoinResponseHandler received non-JoinResponse message".into(),
                ));
            }
        };

        // Idempotency check.
        let epoch_key = assigned_epoch.map(|e| e.0).unwrap_or(0);
        let id_key = (request_member_id.0, epoch_key);
        {
            let mut proc = self.processed.write().expect("lock poisoned");
            if !proc.insert(id_key) {
                return Ok(()); // already processed, idempotent no-op
            }
        }

        if accepted {
            if let Some(epoch) = assigned_epoch {
                let outcome = JoinOutcome::Accepted {
                    member_id: request_member_id,
                    epoch,
                    roster: Vec::new(),
                    incarnation,
                };
                if let Some(cb) = self.on_accepted.read().expect("lock poisoned").as_ref() {
                    cb(outcome);
                }
            }
        } else if let Some(cb) = self.on_rejected.read().expect("lock poisoned").as_ref() {
            cb(reject_reason.unwrap_or_else(|| "join rejected (no reason given)".into()));
        }

        Ok(())
    }
}

/// Return the current wall-clock time in milliseconds since the Unix epoch.
fn current_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::MembershipRoster;
    use std::sync::{Arc, Mutex};
    use tidefs_transport::send_dispatch::{SendDispatcher, SendQueueConfig};
    use tidefs_transport::ErrorClassifier;

    fn test_queue_config() -> SendQueueConfig {
        SendQueueConfig::new(256, 1_048_576).unwrap()
    }

    // --- JoinOutcome ---

    #[test]
    fn join_outcome_accepted_is_accepted() {
        let outcome = JoinOutcome::Accepted {
            member_id: MemberId::new(42),
            epoch: EpochId::new(7),
            roster: vec![MemberId::new(1), MemberId::new(2), MemberId::new(42)],
            incarnation: Incarnation::ZERO,
        };
        assert!(outcome.is_accepted());
        assert!(!outcome.is_rejected());
    }

    #[test]
    fn join_outcome_rejected_is_rejected() {
        let outcome = JoinOutcome::Rejected {
            reason: "capacity full".into(),
        };
        assert!(outcome.is_rejected());
        assert!(!outcome.is_accepted());
    }

    #[test]
    fn join_outcome_eq() {
        let a1 = JoinOutcome::Accepted {
            member_id: MemberId::new(1),
            epoch: EpochId::new(3),
            roster: vec![MemberId::new(1)],
            incarnation: Incarnation::ZERO,
        };
        let a2 = JoinOutcome::Accepted {
            member_id: MemberId::new(1),
            epoch: EpochId::new(3),
            roster: vec![MemberId::new(1)],
            incarnation: Incarnation::ZERO,
        };
        assert_eq!(a1, a2);

        let r1 = JoinOutcome::Rejected {
            reason: "no".into(),
        };
        let r2 = JoinOutcome::Rejected {
            reason: "no".into(),
        };
        assert_eq!(r1, r2);
        assert_ne!(
            a1,
            JoinOutcome::Rejected {
                reason: "no".into()
            }
        );
    }

    #[test]
    fn join_outcome_clone_and_debug() {
        let outcome = JoinOutcome::Accepted {
            member_id: MemberId::new(99),
            epoch: EpochId::new(5),
            roster: vec![],
            incarnation: Incarnation::ZERO,
        };
        let cloned = outcome.clone();
        assert_eq!(outcome, cloned);
        let s = format!("{outcome:?}");
        assert!(s.contains("99"));
        assert!(s.contains("Accepted"));
    }

    // --- JoinResponseDispatcher ---

    #[test]
    fn dispatcher_send_acceptance_enqueues_join_response() {
        let send_disp = SendDispatcher::new(test_queue_config(), ErrorClassifier, None);
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(10));

        let dispatch = MembershipOutboundDispatch::new(&send_disp, &roster);
        let dispatcher = JoinResponseDispatcher::new(&dispatch);

        let result =
            dispatcher.send_acceptance(MemberId::new(10), EpochId::new(5), Incarnation::ZERO);
        assert!(result.is_ok());

        let q = send_disp.queue(10).expect("queue for peer 10 should exist");
        assert_eq!(q.depth(), 1);

        let drained = q.dequeue().unwrap();
        let decoded: MembershipOutboundMessage = bincode::deserialize(&drained.payload).unwrap();

        match decoded {
            MembershipOutboundMessage::JoinResponse {
                request_member_id,
                accepted,
                assigned_epoch,
                reject_reason,
                ..
            } => {
                assert_eq!(request_member_id, MemberId::new(10));
                assert!(accepted);
                assert_eq!(assigned_epoch, Some(EpochId::new(5)));
                assert!(reject_reason.is_none());
            }
            other => panic!("expected JoinResponse, got {other:?}"),
        }
    }

    #[test]
    fn dispatcher_send_rejection_enqueues_reject_message() {
        let send_disp = SendDispatcher::new(test_queue_config(), ErrorClassifier, None);
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(20));

        let dispatch = MembershipOutboundDispatch::new(&send_disp, &roster);
        let dispatcher = JoinResponseDispatcher::new(&dispatch);

        let result = dispatcher.send_rejection(
            MemberId::new(20),
            "peer not allowed".into(),
            Incarnation::ZERO,
        );
        assert!(result.is_ok());

        let q = send_disp.queue(20).unwrap();
        let drained = q.dequeue().unwrap();
        let decoded: MembershipOutboundMessage = bincode::deserialize(&drained.payload).unwrap();

        match decoded {
            MembershipOutboundMessage::JoinResponse {
                request_member_id,
                accepted,
                assigned_epoch,
                reject_reason,
                ..
            } => {
                assert_eq!(request_member_id, MemberId::new(20));
                assert!(!accepted);
                assert!(assigned_epoch.is_none());
                assert_eq!(reject_reason, Some("peer not allowed".into()));
            }
            other => panic!("expected JoinResponse, got {other:?}"),
        }
    }

    #[test]
    fn dispatcher_send_to_unknown_member_returns_error() {
        let send_disp = SendDispatcher::new(test_queue_config(), ErrorClassifier, None);
        let roster = MembershipRoster::new();
        let dispatch = MembershipOutboundDispatch::new(&send_disp, &roster);
        let dispatcher = JoinResponseDispatcher::new(&dispatch);

        let result =
            dispatcher.send_acceptance(MemberId::new(999), EpochId::new(1), Incarnation::ZERO);
        assert!(result.is_err());
        match result {
            Err(OutboundDispatchError::PeerNotInRoster { member_id }) => {
                assert_eq!(member_id.0, 999);
            }
            other => panic!("expected PeerNotInRoster, got {other:?}"),
        }
    }

    // --- JoinResponseHandler ---

    #[test]
    fn handler_processes_accepted_join_response() {
        let handler = JoinResponseHandler::new();
        let outcomes: Arc<Mutex<Vec<JoinOutcome>>> = Arc::new(Mutex::new(Vec::new()));
        let o2 = Arc::clone(&outcomes);
        handler.set_on_accepted(move |outcome| {
            o2.lock().unwrap().push(outcome);
        });

        let msg = MembershipMessage::JoinResponse {
            request_member_id: MemberId::new(42),
            accepted: true,
            assigned_epoch: Some(EpochId::new(7)),
            reject_reason: None,
            responded_at_millis: 1234,
            incarnation: Incarnation::ZERO,
        };

        let result = handler.handle_join_response(&msg);
        assert!(result.is_ok());

        let recorded = outcomes.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0],
            JoinOutcome::Accepted {
                member_id: MemberId::new(42),
                epoch: EpochId::new(7),
                roster: vec![],
                incarnation: Incarnation::ZERO,
            }
        );
    }

    #[test]
    fn handler_processes_rejected_join_response() {
        let handler = JoinResponseHandler::new();
        let reasons: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let r2 = Arc::clone(&reasons);
        handler.set_on_rejected(move |reason| {
            r2.lock().unwrap().push(reason);
        });

        let msg = MembershipMessage::JoinResponse {
            request_member_id: MemberId::new(13),
            accepted: false,
            assigned_epoch: None,
            reject_reason: Some("cluster is full".into()),
            responded_at_millis: 5678,
            incarnation: Incarnation::ZERO,
        };

        let result = handler.handle_join_response(&msg);
        assert!(result.is_ok());

        let recorded = reasons.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], "cluster is full");
    }

    #[test]
    fn handler_idempotent_redelivery_silently_dropped() {
        let handler = JoinResponseHandler::new();
        let calls: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let c2 = Arc::clone(&calls);
        handler.set_on_accepted(move |_| {
            *c2.lock().unwrap() += 1;
        });

        let msg = MembershipMessage::JoinResponse {
            request_member_id: MemberId::new(1),
            accepted: true,
            assigned_epoch: Some(EpochId::new(3)),
            reject_reason: None,
            responded_at_millis: 100,
            incarnation: Incarnation::ZERO,
        };

        handler.handle_join_response(&msg).unwrap();
        assert_eq!(*calls.lock().unwrap(), 1);
        assert_eq!(handler.processed_count(), 1);

        handler.handle_join_response(&msg).unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            1,
            "callback should not fire on duplicate"
        );
        assert_eq!(handler.processed_count(), 1);
    }

    #[test]
    fn handler_different_epoch_is_not_duplicate() {
        let handler = JoinResponseHandler::new();
        let calls: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let c2 = Arc::clone(&calls);
        handler.set_on_accepted(move |_| {
            *c2.lock().unwrap() += 1;
        });

        let msg1 = MembershipMessage::JoinResponse {
            request_member_id: MemberId::new(1),
            accepted: true,
            assigned_epoch: Some(EpochId::new(3)),
            reject_reason: None,
            responded_at_millis: 100,
            incarnation: Incarnation::ZERO,
        };

        let msg2 = MembershipMessage::JoinResponse {
            request_member_id: MemberId::new(1),
            accepted: true,
            assigned_epoch: Some(EpochId::new(4)),
            reject_reason: None,
            responded_at_millis: 200,
            incarnation: Incarnation::ZERO,
        };

        handler.handle_join_response(&msg1).unwrap();
        handler.handle_join_response(&msg2).unwrap();
        assert_eq!(*calls.lock().unwrap(), 2);
        assert_eq!(handler.processed_count(), 2);
    }

    #[test]
    fn handler_no_callbacks_is_noop() {
        let handler = JoinResponseHandler::new();
        let msg = MembershipMessage::JoinResponse {
            request_member_id: MemberId::new(7),
            accepted: true,
            assigned_epoch: Some(EpochId::new(1)),
            reject_reason: None,
            responded_at_millis: 0,
            incarnation: Incarnation::ZERO,
        };
        let result = handler.handle_join_response(&msg);
        assert!(result.is_ok());
        assert_eq!(handler.processed_count(), 1);
    }

    #[test]
    fn handler_rejected_without_reason_defaults_string() {
        let handler = JoinResponseHandler::new();
        let reasons: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let r2 = Arc::clone(&reasons);
        handler.set_on_rejected(move |reason| {
            r2.lock().unwrap().push(reason);
        });

        let msg = MembershipMessage::JoinResponse {
            request_member_id: MemberId::new(99),
            accepted: false,
            assigned_epoch: None,
            reject_reason: None,
            responded_at_millis: 0,
            incarnation: Incarnation::ZERO,
        };

        handler.handle_join_response(&msg).unwrap();
        let recorded = reasons.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].contains("no reason given"));
    }

    #[test]
    fn handler_non_join_response_message_returns_error() {
        let handler = JoinResponseHandler::new();
        let msg = MembershipMessage::HealthReport {
            member_id: MemberId::new(1),
            epoch: EpochId::new(0),
            health_class: 0,
            reported_at_millis: 0,
        };
        let result = handler.handle_join_response(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn handler_clear_processed_resets_idempotency() {
        let handler = JoinResponseHandler::new();
        let calls: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let c2 = Arc::clone(&calls);
        handler.set_on_accepted(move |_| {
            *c2.lock().unwrap() += 1;
        });

        let msg = MembershipMessage::JoinResponse {
            request_member_id: MemberId::new(1),
            accepted: true,
            assigned_epoch: Some(EpochId::new(5)),
            reject_reason: None,
            responded_at_millis: 0,
            incarnation: Incarnation::ZERO,
        };

        handler.handle_join_response(&msg).unwrap();
        assert_eq!(*calls.lock().unwrap(), 1);
        assert_eq!(handler.processed_count(), 1);

        handler.clear_processed();
        assert_eq!(handler.processed_count(), 0);

        handler.handle_join_response(&msg).unwrap();
        assert_eq!(*calls.lock().unwrap(), 2);
        assert_eq!(handler.processed_count(), 1);
    }

    #[test]
    fn handler_default_creates_empty() {
        let handler = JoinResponseHandler::default();
        assert_eq!(handler.processed_count(), 0);
    }

    #[test]
    fn join_response_handler_is_membership_message_handler() {
        fn _assert_handler<T: MembershipMessageHandler + Send + Sync>(_: &T) {}
        let handler = JoinResponseHandler::new();
        _assert_handler(&handler);
    }
}
