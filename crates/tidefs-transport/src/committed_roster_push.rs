// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Committed-roster push message type for passive-peer epoch synchronization.
//!
//! After an epoch agreement round concludes, the quorum participants know
//! the new committed roster. This module provides the transport message type
//! and handler trait so the committed roster can be pushed to passive and
//! non-quorum peers over transport, closing the post-commit synchronization
//! gap.
//!
//! ## Wire format
//!
//! ```text
//! [0..8)   push_seq      u64 LE -- monotonic push sequence number
//! [8..16)  epoch         u64 LE -- epoch number
//! [16..48) roster_hash   32 bytes -- BLAKE3-256 roster hash
//! [48..52) member_count  u32 LE -- number of member IDs
//! [52..]   member_ids    member_count x u64 LE -- sorted member node IDs
//! ```
//!
//! ## Fire-and-forget semantics
//!
//! Push sends are fire-and-forget with transport-level reliability. Peers
//! that miss a push catch up via the next agreement round they participate
//! in or explicit state transfer (future work).

use std::sync::Arc;

use tidefs_membership_epoch::epoch_commit_subscriber::CommittedRoster;
use tidefs_membership_epoch::EpochId;

// ---------------------------------------------------------------------------
// CommittedRosterPushMessage -- wire-format message
// ---------------------------------------------------------------------------

/// A transport-level committed-roster push message.
///
/// Carries the serialised [`CommittedRoster`] plus a monotonic push sequence
/// number used by the receiver for deduplication and replay rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedRosterPushMessage {
    /// Monotonic push sequence number (per-sender, not global).
    pub push_seq: u64,
    /// The committed roster (epoch, member IDs, roster hash).
    pub roster: CommittedRoster,
}

impl CommittedRosterPushMessage {
    /// Create a new committed-roster push message.
    #[must_use]
    pub fn new(push_seq: u64, roster: CommittedRoster) -> Self {
        Self { push_seq, roster }
    }

    /// Encode to binary wire format.
    ///
    /// Format: push_seq(u64 LE) + epoch(u64 LE) + roster_hash(32 bytes)
    /// + member_count(u32 LE) + member_ids(u64 LE each).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let member_count = self.roster.member_ids.len() as u32;
        let mut buf = Vec::with_capacity(52 + member_count as usize * 8);

        buf.extend_from_slice(&self.push_seq.to_le_bytes());
        buf.extend_from_slice(&self.roster.epoch.0.to_le_bytes());
        buf.extend_from_slice(&self.roster.roster_hash);
        buf.extend_from_slice(&member_count.to_le_bytes());
        for id in &self.roster.member_ids {
            buf.extend_from_slice(&id.to_le_bytes());
        }

        buf
    }

    /// Decode from binary wire format.
    ///
    /// Returns `None` if the buffer is too short or member_count exceeds
    /// the available data.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 52 {
            return None;
        }

        let push_seq = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let epoch = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let mut roster_hash = [0u8; 32];
        roster_hash.copy_from_slice(&data[16..48]);
        let member_count = u32::from_le_bytes(data[48..52].try_into().unwrap()) as usize;

        let expected_len = 52 + member_count * 8;
        if data.len() < expected_len {
            return None;
        }

        let mut member_ids = Vec::with_capacity(member_count);
        for i in 0..member_count {
            let offset = 52 + i * 8;
            let id = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            member_ids.push(id);
        }

        let roster = CommittedRoster {
            epoch: EpochId(epoch),
            member_ids,
            roster_hash,
        };

        Some(Self { push_seq, roster })
    }
}

// ---------------------------------------------------------------------------
// RosterPushHandler -- trait for receiving incoming roster pushes
// ---------------------------------------------------------------------------

/// Trait for handling incoming committed-roster push messages.
///
/// Implementations register with the transport layer and are invoked
/// when a [`CommittedRosterPushMessage`] arrives from a remote peer.
///
/// Handlers must be non-blocking and fast; long-running work should be
/// spawned onto a task.
pub trait RosterPushHandler: Send + Sync {
    /// Handle an incoming committed-roster push.
    ///
    /// `push_seq` is the sender's monotonic push sequence number.
    /// `roster` is the committed roster carried in the message.
    fn on_roster_push(&self, push_seq: u64, roster: &CommittedRoster);
}

// ---------------------------------------------------------------------------
// RosterPushDispatcher -- wires transport receipt to handler
// ---------------------------------------------------------------------------

/// Bridges transport message dispatch to a registered [`RosterPushHandler`].
///
/// This type decodes incoming committed-roster push transport messages
/// and forwards the parsed roster to the handler.
pub struct RosterPushDispatcher {
    handler: Arc<dyn RosterPushHandler>,
}

impl RosterPushDispatcher {
    /// Create a new dispatcher wrapping the given handler.
    #[must_use]
    pub fn new(handler: Arc<dyn RosterPushHandler>) -> Self {
        Self { handler }
    }

    /// Handle an incoming committed-roster push from raw wire bytes.
    ///
    /// Decodes the payload and, on success, forwards to the registered
    /// [`RosterPushHandler`].
    ///
    /// Returns `Ok(())` on successful decode and handler invocation.
    /// Returns `Err` with a description if the payload cannot be decoded.
    pub fn handle_raw(&self, payload: &[u8]) -> Result<(), String> {
        let msg = CommittedRosterPushMessage::decode(payload)
            .ok_or_else(|| "committed-roster push: decode failed".to_string())?;
        self.handler.on_roster_push(msg.push_seq, &msg.roster);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use tidefs_membership_epoch::EpochId;

    fn make_roster(epoch: u64, member_ids: Vec<u64>) -> CommittedRoster {
        CommittedRoster::new(EpochId(epoch), member_ids)
    }

    // -- encode/decode round-trips --

    #[test]
    fn encode_decode_round_trip_empty_members() {
        let roster = make_roster(1, vec![]);
        let msg = CommittedRosterPushMessage::new(0, roster);
        let encoded = msg.encode();
        let decoded = CommittedRosterPushMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.push_seq, 0);
        assert_eq!(decoded.roster.epoch, EpochId(1));
        assert!(decoded.roster.member_ids.is_empty());
    }

    #[test]
    fn encode_decode_round_trip_single_member() {
        let roster = make_roster(5, vec![42]);
        let msg = CommittedRosterPushMessage::new(1, roster.clone());
        let encoded = msg.encode();
        let decoded = CommittedRosterPushMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.push_seq, 1);
        assert_eq!(decoded.roster.epoch, EpochId(5));
        assert_eq!(decoded.roster.member_ids, vec![42]);
        assert_eq!(decoded.roster.roster_hash, roster.roster_hash);
    }

    #[test]
    fn encode_decode_round_trip_multiple_members() {
        let member_ids = vec![1, 3, 5, 7, 9, 11];
        let roster = make_roster(3, member_ids.clone());
        let msg = CommittedRosterPushMessage::new(7, roster.clone());
        let encoded = msg.encode();
        let decoded = CommittedRosterPushMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.push_seq, 7);
        assert_eq!(decoded.roster.member_ids, member_ids);
        assert_eq!(decoded.roster.roster_hash, roster.roster_hash);
    }

    #[test]
    fn decode_buffer_too_short_returns_none() {
        assert!(CommittedRosterPushMessage::decode(&[]).is_none());
        assert!(CommittedRosterPushMessage::decode(&[0u8; 10]).is_none());
        assert!(CommittedRosterPushMessage::decode(&[0u8; 51]).is_none());
    }

    #[test]
    fn decode_truncated_member_list_returns_none() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&42u64.to_le_bytes());
        assert!(CommittedRosterPushMessage::decode(&buf).is_none());
    }

    #[test]
    fn encode_deterministic() {
        let roster = make_roster(2, vec![10, 20]);
        let msg = CommittedRosterPushMessage::new(0, roster);
        let enc1 = msg.encode();
        let enc2 = msg.encode();
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn different_push_seq_produce_different_encoding() {
        let roster = make_roster(1, vec![1]);
        let msg1 = CommittedRosterPushMessage::new(0, roster.clone());
        let msg2 = CommittedRosterPushMessage::new(1, roster);
        assert_ne!(msg1.encode(), msg2.encode());
    }

    // -- RosterPushDispatcher tests --

    pub(crate) struct TestHandler {
        pub(crate) calls: Mutex<Vec<(u64, CommittedRoster)>>,
    }

    impl TestHandler {
        pub(crate) fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl RosterPushHandler for TestHandler {
        fn on_roster_push(&self, push_seq: u64, roster: &CommittedRoster) {
            self.calls.lock().unwrap().push((push_seq, roster.clone()));
        }
    }

    #[test]
    fn dispatcher_forwards_to_handler() {
        let handler = Arc::new(TestHandler::new());
        let dispatcher = RosterPushDispatcher::new(handler.clone());

        let roster = make_roster(5, vec![1, 2, 3]);
        let msg = CommittedRosterPushMessage::new(3, roster.clone());
        let result = dispatcher.handle_raw(&msg.encode());
        assert!(result.is_ok());

        let calls = handler.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 3);
        assert_eq!(calls[0].1.member_ids, vec![1, 2, 3]);
    }

    #[test]
    fn dispatcher_decode_failure_returns_err() {
        let handler = Arc::new(TestHandler::new());
        let dispatcher = RosterPushDispatcher::new(handler.clone());

        let result = dispatcher.handle_raw(&[0u8; 10]);
        assert!(result.is_err());
        assert_eq!(handler.calls.lock().unwrap().len(), 0);
    }

    #[test]
    fn dispatcher_multiple_calls() {
        let handler = Arc::new(TestHandler::new());
        let dispatcher = RosterPushDispatcher::new(handler.clone());

        for i in 0..5 {
            let roster = make_roster(i, vec![i]);
            let msg = CommittedRosterPushMessage::new(i, roster);
            dispatcher.handle_raw(&msg.encode()).unwrap();
        }

        assert_eq!(handler.calls.lock().unwrap().len(), 5);
    }
}

// ===========================================================================
// Transport-side auto-push subscriber (bridges EpochCommitBus to send_push)
// ===========================================================================

use std::sync::Mutex;

use tidefs_membership_epoch::epoch_commit_subscriber::{
    EpochCommitNotification, EpochCommitSubscriber,
};
use tidefs_membership_epoch::roster_push::RosterPushService;

/// An [`EpochCommitSubscriber`] that pushes committed rosters to all
/// connected peers via the transport layer.
///
/// Wraps a [`Mutex<RosterPushService>`] so the subscriber can satisfy the
/// `Sync` bound on [`EpochCommitSubscriber`] despite `RosterPushService`
/// containing `RefCell`-based interior mutability from `EpochCommitBus`.
///
/// # Integration
///
/// 1. Create a `RosterPushService` with a configured `RosterPushSender`.
/// 2. Wrap it in `Mutex` and create this subscriber.
/// 3. Register it on the `EpochCommitBus` so every local epoch commit
///    automatically pushes the roster to all connected peers.
/// 4. For incoming pushes, use [`RosterPushDispatcher`] with a
///    [`RosterPushHandler`] that delegates to `RosterPushService::on_incoming_push`.
pub struct TransportAutoPushSubscriber {
    service: Mutex<RosterPushService>,
}

impl TransportAutoPushSubscriber {
    /// Create a new auto-push subscriber wrapping the given service.
    #[must_use]
    pub fn new(service: RosterPushService) -> Self {
        Self {
            service: Mutex::new(service),
        }
    }
}

impl EpochCommitSubscriber for TransportAutoPushSubscriber {
    fn on_epoch_committed(&self, notification: &EpochCommitNotification) {
        let svc = self.service.lock().unwrap();
        let roster = CommittedRoster {
            epoch: notification.epoch,
            member_ids: notification.member_ids.clone(),
            roster_hash: notification.roster_hash,
        };
        svc.send_push(&roster);
    }
}

// ===========================================================================
// MessageHandler adapter for RosterPushDispatcher
// ===========================================================================

use crate::message_dispatch::{DispatchError, MessageHandler};
use crate::types::SessionId;

/// A [`MessageHandler`] that decodes incoming committed-roster push messages
/// and forwards them to the registered [`RosterPushHandler`].
///
/// This adapter bridges the transport message-dispatch system (which
/// operates on raw payloads with a session ID) to the roster-push
/// subsystem (which operates on decoded [`CommittedRoster`] values).
pub struct RosterPushMessageHandler {
    dispatcher: RosterPushDispatcher,
}

impl RosterPushMessageHandler {
    /// Create a new message handler wrapping the given dispatcher.
    #[must_use]
    pub fn new(dispatcher: RosterPushDispatcher) -> Self {
        Self { dispatcher }
    }
}

impl MessageHandler for RosterPushMessageHandler {
    fn handle(&self, _session_id: SessionId, payload: &[u8]) -> Result<(), DispatchError> {
        self.dispatcher
            .handle_raw(payload)
            .map_err(|reason| DispatchError::HandlerRejected {
                message_type: crate::message_dispatch::MessageType::RosterPush,
                reason,
            })
    }
}

// ===========================================================================
// Integration tests
// ===========================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    use tidefs_membership_epoch::epoch_commit_subscriber::EpochCommitBus;
    use tidefs_membership_epoch::roster_push::RosterPushSender;
    use tidefs_membership_epoch::EpochId;

    /// A test sender that records calls.
    struct TestSender {
        calls: StdMutex<Vec<(u64, Vec<u8>)>>,
    }

    impl TestSender {
        pub(crate) fn new() -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
            }
        }
    }

    impl RosterPushSender for TestSender {
        fn send_to_all_peers(&self, push_seq: u64, payload: &[u8]) {
            self.calls
                .lock()
                .unwrap()
                .push((push_seq, payload.to_vec()));
        }
    }

    fn make_roster(epoch: u64, member_ids: Vec<u64>) -> CommittedRoster {
        CommittedRoster::new(EpochId(epoch), member_ids)
    }

    // ── TransportAutoPushSubscriber ──────────────────────────────

    #[test]
    fn auto_push_subscriber_triggers_on_commit() {
        let bus = EpochCommitBus::new();
        let sender = Arc::new(TestSender::new());
        let mut svc = RosterPushService::new(EpochCommitBus::new());
        svc.set_sender(sender.clone());

        let subscriber = TransportAutoPushSubscriber::new(svc);
        bus.register(Box::new(subscriber));

        bus.dispatch_commit(EpochId(3), vec![1, 2]);

        let calls = sender.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 1); // push_seq starts at 1
    }

    #[test]
    fn auto_push_subscriber_multiple_commits() {
        let bus = EpochCommitBus::new();
        let sender = Arc::new(TestSender::new());
        let mut svc = RosterPushService::new(EpochCommitBus::new());
        svc.set_sender(sender.clone());

        let subscriber = TransportAutoPushSubscriber::new(svc);
        bus.register(Box::new(subscriber));

        bus.dispatch_commit(EpochId(1), vec![1]);
        bus.dispatch_commit(EpochId(2), vec![1, 2]);
        bus.dispatch_commit(EpochId(3), vec![1, 2, 3]);

        let calls = sender.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, 1);
        assert_eq!(calls[1].0, 2);
        assert_eq!(calls[2].0, 3);
    }

    #[test]
    fn auto_push_subscriber_noop_when_no_sender() {
        let bus = EpochCommitBus::new();
        let svc = RosterPushService::new(EpochCommitBus::new());
        let subscriber = TransportAutoPushSubscriber::new(svc);
        bus.register(Box::new(subscriber));

        // Should not panic
        bus.dispatch_commit(EpochId(1), vec![1]);
    }

    #[test]
    fn auto_push_subscriber_payload_is_valid_wire_format() {
        let bus = EpochCommitBus::new();
        let sender = Arc::new(TestSender::new());
        let mut svc = RosterPushService::new(EpochCommitBus::new());
        svc.set_sender(sender.clone());

        let subscriber = TransportAutoPushSubscriber::new(svc);
        bus.register(Box::new(subscriber));

        let roster = make_roster(5, vec![10, 20, 30]);
        // Manually trigger via the same path dispatch_commit would use
        let notification = EpochCommitNotification {
            epoch: roster.epoch,
            roster_hash: roster.roster_hash,
            member_ids: roster.member_ids.clone(),
            commit_index: 1,
            catalog_delta_bytes: None,
        };
        // Can't easily test via the bus since push happens inside subscriber;
        // verify that subscriber works by manually calling on_epoch_committed
        // and decoding the result.
        let sender = Arc::new(TestSender::new());
        let mut svc = RosterPushService::new(EpochCommitBus::new());
        svc.set_sender(sender.clone());
        let subscriber = TransportAutoPushSubscriber::new(svc);
        subscriber.on_epoch_committed(&notification);

        let calls = sender.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (_seq, ref payload) = calls[0];

        // Verify the payload can be decoded back
        let decoded = CommittedRosterPushMessage::decode(payload);
        assert!(decoded.is_some());
        let decoded = decoded.unwrap();
        assert_eq!(decoded.roster.epoch, roster.epoch);
        assert_eq!(decoded.roster.member_ids, roster.member_ids);
    }

    // ── RosterPushMessageHandler ─────────────────────────────────

    #[test]
    fn message_handler_forwards_to_dispatcher() {
        let handler = Arc::new(crate::committed_roster_push::tests::TestHandler::new());
        let dispatcher = RosterPushDispatcher::new(handler.clone());
        let msg_handler = RosterPushMessageHandler::new(dispatcher);

        let roster = make_roster(2, vec![5, 6]);
        let msg = CommittedRosterPushMessage::new(2, roster.clone());
        let payload = msg.encode();

        let result = msg_handler.handle(SessionId::new(0), &payload);
        assert!(result.is_ok());

        let calls = handler.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 2);
        assert_eq!(calls[0].1.member_ids, vec![5, 6]);
    }

    #[test]
    fn message_handler_bad_payload_returns_error() {
        let handler = Arc::new(crate::committed_roster_push::tests::TestHandler::new());
        let dispatcher = RosterPushDispatcher::new(handler.clone());
        let msg_handler = RosterPushMessageHandler::new(dispatcher);

        let result = msg_handler.handle(SessionId::new(0), &[0u8; 10]);
        assert!(result.is_err());
        assert!(matches!(result, Err(DispatchError::HandlerRejected { .. })));
    }

    #[test]
    fn message_handler_registered_in_dispatcher() {
        #[allow(unused_imports)]
        use crate::message_dispatch::MessageDispatcher;

        let handler = Arc::new(crate::committed_roster_push::tests::TestHandler::new());
        let dispatcher = RosterPushDispatcher::new(handler.clone());
        let msg_handler = Arc::new(RosterPushMessageHandler::new(dispatcher));

        let mut msg_dispatcher = MessageDispatcher::new();
        msg_dispatcher.register(
            crate::message_dispatch::MessageType::RosterPush,
            msg_handler,
        );

        // Now encode a RosterPush message through the envelope
        let roster = make_roster(7, vec![99]);
        let msg = CommittedRosterPushMessage::new(1, roster.clone());
        let payload = msg.encode();
        let envelope = crate::message_dispatch::MessageEnvelope::encode(
            crate::message_dispatch::MessageType::RosterPush,
            &payload,
        );

        let result = msg_dispatcher.dispatch(SessionId::new(42), &envelope);
        assert!(result.is_ok());

        let calls = handler.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1.member_ids, vec![99]);
    }
}
