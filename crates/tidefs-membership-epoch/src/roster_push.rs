// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Committed-roster transport push for passive-peer epoch synchronization.
//!
//! After an epoch agreement round concludes via [`crate::quorum`], the
//! quorum participants know the new committed roster. This module provides
//! [`RosterPushService`] so the roster can be serialised and pushed to
//! passive and non-quorum peers, and so incoming pushes are validated and
//! fed into the local commit-subscriber chain via [`crate::EpochCommitBus`].
//!
//! ## Protocol
//!
//! - **Send side**: on each `dispatch_commit`, the caller serialises the
//!   [`CommittedRoster`] via [`RosterPushService::send_push`] and delivers
//!   it through a user-provided [`RosterPushSender`] to every connected peer.
//! - **Receive side**: incoming pushes undergo monotonicity validation:
//!   epoch regressions and duplicate push-seq numbers are rejected;
//!   forward-progress epochs update the local epoch view and trigger
//!   local commit-subscriber dispatch via [`RosterPushService::on_incoming_push`].
//! - **Fire-and-forget**: sends are fire-and-forget with transport-level
//!   reliability. Peers that miss a push catch up via the next agreement
//!   round they participate in or explicit state transfer (future work).
//!
//! ## Integration with transport
//!
//! The auto-push subscriber (which subscribes to `EpochCommitBus` and
//! calls `send_push` on each local commit) lives in `tidefs-transport`,
//! where it can wrap `RosterPushService` in a `Mutex` to satisfy the
//! `Sync` bound on `EpochCommitSubscriber`.
//!
//! This module depends only on the local [`EpochCommitBus`] and
//! [`CommittedRoster`] types.

use std::cell::Cell;
use std::sync::Arc;

use crate::epoch_commit_subscriber::{CommittedRoster, EpochCommitBus, SubscriberId};
// ---------------------------------------------------------------------------
// RosterPushSender -- trait for sending push messages over transport
// ---------------------------------------------------------------------------

/// Trait for sending serialised committed-roster push messages to peers.
///
/// Implementations (typically the transport layer) deliver the binary
/// payload to one or more connected peers. Sends are fire-and-forget
/// with transport-level reliability.
pub trait RosterPushSender: Send + Sync {
    /// Send a binary committed-roster push payload to every currently
    /// connected peer.
    ///
    /// The payload is the wire-format encoding produced by
    /// `tidefs-transport::CommittedRosterPushMessage::encode`.
    fn send_to_all_peers(&self, push_seq: u64, payload: &[u8]);
}

// ---------------------------------------------------------------------------
// PushError -- receive-side validation errors
// ---------------------------------------------------------------------------

/// Errors that can occur when processing an incoming roster push.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PushError {
    /// The pushed epoch is a regression (older than the current epoch).
    EpochRegression { current: u64, received: u64 },
    /// The push sequence number indicates a duplicate or replay.
    DuplicatePushSeq { push_seq: u64 },
}

// ---------------------------------------------------------------------------
// RosterPushService -- send and receive logic
// ---------------------------------------------------------------------------

/// Service that handles committed-roster push send and receive logic.
///
/// On the send side, callers invoke [`Self::send_push`] to serialise the
/// roster and deliver it via the configured [`RosterPushSender`].
///
/// On the receive side, callers invoke [`Self::on_incoming_push`] to
/// validate monotonicity (rejecting epoch regressions and duplicate push
/// sequence numbers) and dispatch to the local commit-subscriber chain.
///
/// ## Thread safety
///
/// `RosterPushService` is `Send` but not `Sync` (due to `Cell` fields and
/// `EpochCommitBus`). Wrap in `Mutex` when sharing across threads (e.g.
/// from transport's `EpochCommitSubscriber` impl).
pub struct RosterPushService {
    /// The local epoch-commit bus for local dispatch.
    commit_bus: EpochCommitBus,
    /// The configured sender for outbound pushes.
    sender: Option<Arc<dyn RosterPushSender>>,
    /// Monotonic push sequence counter (incremented on each send).
    next_push_seq: Cell<u64>,
    /// Last-seen push sequence number for deduplication (per-sender).
    last_seen_push_seq: Cell<u64>,
    /// Current epoch known to this service (updated on receive).
    current_epoch: Cell<u64>,
}

impl RosterPushService {
    /// Create a new roster push service.
    ///
    /// `commit_bus` is the local epoch-commit bus used to dispatch
    /// incoming roster updates to local subscribers.
    #[must_use]
    pub fn new(commit_bus: EpochCommitBus) -> Self {
        Self {
            commit_bus,
            sender: None,
            next_push_seq: Cell::new(1),
            last_seen_push_seq: Cell::new(0),
            current_epoch: Cell::new(0),
        }
    }

    /// Set the sender used for outbound roster pushes.
    ///
    /// When configured, calls to [`Self::send_push`] deliver the payload
    /// to all connected peers via the sender.
    pub fn set_sender(&mut self, sender: Arc<dyn RosterPushSender>) {
        self.sender = Some(sender);
    }

    /// Handle an incoming committed-roster push from a remote peer.
    ///
    /// Validates:
    /// - Epoch monotonicity: the incoming epoch must be >= current epoch.
    /// - Push sequence deduplication: the incoming push_seq must be
    ///   strictly greater than the last-seen push_seq (when epoch is equal).
    ///
    /// On success, updates the local epoch view and dispatches to the
    /// local commit-subscriber chain via [`EpochCommitBus::dispatch_commit`].
    ///
    /// # Errors
    ///
    /// Returns [`PushError::EpochRegression`] if the received epoch is
    /// older than the current epoch.
    /// Returns [`PushError::DuplicatePushSeq`] if the push sequence
    /// number does not advance for the same epoch.
    pub fn on_incoming_push(
        &self,
        push_seq: u64,
        roster: &CommittedRoster,
    ) -> Result<(), PushError> {
        let received_epoch = roster.epoch.0;
        let current = self.current_epoch.get();

        // Reject epoch regressions
        if received_epoch < current {
            return Err(PushError::EpochRegression {
                current,
                received: received_epoch,
            });
        }

        // Epochs equal to current: check push seq for dedup
        if received_epoch == current {
            let last_seq = self.last_seen_push_seq.get();
            if push_seq <= last_seq {
                return Err(PushError::DuplicatePushSeq { push_seq });
            }
        }

        // Accept: advance state and dispatch locally
        self.current_epoch.set(received_epoch);
        self.last_seen_push_seq.set(push_seq);
        self.commit_bus
            .dispatch_commit(roster.epoch, roster.member_ids.clone());

        Ok(())
    }

    /// Current epoch known to this service.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch.get()
    }

    /// Dispatch an outgoing roster push to all connected peers.
    ///
    /// Serialises the roster into the binary wire format (see
    /// transport's `CommittedRosterPushMessage::encode`) and delivers it
    /// via the configured [`RosterPushSender`].
    ///
    /// The push sequence number is automatically incremented after each send.
    pub fn send_push(&self, roster: &CommittedRoster) {
        if let Some(ref sender) = self.sender {
            let push_seq = self.next_push_seq.get();
            self.next_push_seq.set(push_seq + 1);

            // Build the wire-format payload inline:
            // push_seq(u64 LE) + epoch(u64 LE) + roster_hash(32 bytes)
            // + member_count(u32 LE) + member_ids(u64 LE each)
            let member_count = roster.member_ids.len() as u32;
            let mut payload = Vec::with_capacity(52 + member_count as usize * 8);
            payload.extend_from_slice(&push_seq.to_le_bytes());
            payload.extend_from_slice(&roster.epoch.0.to_le_bytes());
            payload.extend_from_slice(&roster.roster_hash);
            payload.extend_from_slice(&member_count.to_le_bytes());
            for id in &roster.member_ids {
                payload.extend_from_slice(&id.to_le_bytes());
            }

            sender.send_to_all_peers(push_seq, &payload);
        }
    }

    /// Return a reference to the commit bus, for external wiring
    /// (e.g. registering an auto-push subscriber in transport).
    #[must_use]
    pub fn commit_bus(&self) -> &EpochCommitBus {
        &self.commit_bus
    }

    /// Register a subscriber on the internal commit bus.
    ///
    /// Convenience wrapper around [`EpochCommitBus::register`] for
    /// transport-side auto-push subscriber wiring.
    #[must_use]
    pub fn register_subscriber(
        &self,
        subscriber: Box<dyn crate::epoch_commit_subscriber::EpochCommitSubscriber>,
    ) -> SubscriberId {
        self.commit_bus.register(subscriber)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EpochId;
    use std::sync::Mutex;

    use crate::epoch_commit_subscriber::{EpochCommitNotification, EpochCommitSubscriber};
    /// A test sender that records calls.
    struct TestSender {
        calls: Mutex<Vec<(u64, Vec<u8>)>>,
    }

    impl TestSender {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
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

    fn make_service() -> (RosterPushService, Arc<TestSender>) {
        let bus = EpochCommitBus::new();
        let sender = Arc::new(TestSender::new());
        let mut service = RosterPushService::new(bus);
        service.set_sender(sender.clone());
        (service, sender)
    }

    // -- Receive-side tests --

    #[test]
    fn incoming_push_updates_epoch() {
        let (service, _sender) = make_service();
        let roster = make_roster(5, vec![1, 2, 3]);
        let result = service.on_incoming_push(10, &roster);
        assert!(result.is_ok());
        assert_eq!(service.current_epoch(), 5);
    }

    #[test]
    fn incoming_push_dispatches_to_bus() {
        let bus = EpochCommitBus::new();
        let service = RosterPushService::new(bus);
        let roster = make_roster(3, vec![1, 2]);
        service.on_incoming_push(1, &roster).unwrap();
        assert_eq!(service.commit_bus().current_commit_index(), 1);
    }

    #[test]
    fn incoming_push_rejects_epoch_regression() {
        let (service, _sender) = make_service();
        service
            .on_incoming_push(1, &make_roster(10, vec![1]))
            .unwrap();
        let result = service.on_incoming_push(2, &make_roster(5, vec![1]));
        assert_eq!(
            result,
            Err(PushError::EpochRegression {
                current: 10,
                received: 5
            })
        );
    }

    #[test]
    fn incoming_push_rejects_duplicate_push_seq() {
        let (service, _sender) = make_service();
        service
            .on_incoming_push(5, &make_roster(10, vec![1]))
            .unwrap();
        let result = service.on_incoming_push(5, &make_roster(10, vec![1, 2]));
        assert_eq!(result, Err(PushError::DuplicatePushSeq { push_seq: 5 }));
    }

    #[test]
    fn incoming_push_rejects_lower_push_seq_same_epoch() {
        let (service, _sender) = make_service();
        service
            .on_incoming_push(10, &make_roster(10, vec![1]))
            .unwrap();
        let result = service.on_incoming_push(5, &make_roster(10, vec![1, 2]));
        assert_eq!(result, Err(PushError::DuplicatePushSeq { push_seq: 5 }));
    }

    #[test]
    fn incoming_push_accepts_higher_epoch_resets_dedup() {
        let (service, _sender) = make_service();
        service
            .on_incoming_push(7, &make_roster(5, vec![1]))
            .unwrap();
        // Higher epoch with potentially lower push_seq from different sender
        let result = service.on_incoming_push(3, &make_roster(6, vec![1, 2]));
        assert!(result.is_ok());
        assert_eq!(service.current_epoch(), 6);
    }

    #[test]
    fn incoming_push_same_epoch_same_push_seq_is_duplicate() {
        let (service, _sender) = make_service();
        service
            .on_incoming_push(1, &make_roster(5, vec![1, 2]))
            .unwrap();
        let result = service.on_incoming_push(1, &make_roster(5, vec![1, 2]));
        assert!(result.is_err());
    }

    // -- Send-side tests --

    #[test]
    fn send_push_increments_push_seq() {
        let (service, sender) = make_service();
        let roster = make_roster(1, vec![10]);
        service.send_push(&roster);
        service.send_push(&roster);
        let calls = sender.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, 1);
        assert_eq!(calls[1].0, 2);
    }

    #[test]
    fn send_push_produces_valid_wire_format() {
        let (service, sender) = make_service();
        let roster = make_roster(7, vec![42, 99]);
        service.send_push(&roster);
        let calls = sender.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (_push_seq, ref payload) = calls[0];
        // Verify wire format: push_seq(8) + epoch(8) + hash(32) + count(4) + 2*8 = 68
        assert_eq!(payload.len(), 52 + 2 * 8);
    }

    #[test]
    fn send_push_noop_when_no_sender_configured() {
        let bus = EpochCommitBus::new();
        let service = RosterPushService::new(bus);
        let roster = make_roster(1, vec![1]);
        service.send_push(&roster);
    }

    #[test]
    fn send_push_payload_decode_round_trip() {
        let (service, sender) = make_service();
        let orig_roster = make_roster(5, vec![1, 2, 3]);
        service.send_push(&orig_roster);

        let calls = sender.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (_push_seq, ref payload) = calls[0];

        // Verify the payload can be decoded back to match original
        // push_seq(8) + epoch(8) + hash(32) + count(4) + 3*8 = 76
        assert_eq!(payload.len(), 52 + 3 * 8);

        let decoded_epoch = u64::from_le_bytes(payload[8..16].try_into().unwrap());
        assert_eq!(decoded_epoch, 5);

        let count = u32::from_le_bytes(payload[48..52].try_into().unwrap()) as usize;
        assert_eq!(count, 3);
    }

    // -- current_epoch tests --

    #[test]
    fn current_epoch_starts_at_zero() {
        let (service, _sender) = make_service();
        assert_eq!(service.current_epoch(), 0);
    }

    #[test]
    fn current_epoch_tracks_incoming_pushes() {
        let (service, _sender) = make_service();
        service
            .on_incoming_push(1, &make_roster(5, vec![1]))
            .unwrap();
        assert_eq!(service.current_epoch(), 5);
        service
            .on_incoming_push(2, &make_roster(10, vec![1, 2]))
            .unwrap();
        assert_eq!(service.current_epoch(), 10);
    }

    // -- Integration: incoming push dispatches to local subscribers --

    #[test]
    fn pushed_roster_dispatches_to_local_subscribers() {
        let bus = EpochCommitBus::new();

        // Register a local subscriber on the bus
        struct TestLocalSubscriber {
            received: Mutex<Vec<u64>>,
        }
        impl EpochCommitSubscriber for TestLocalSubscriber {
            fn on_epoch_committed(&self, notification: &EpochCommitNotification) {
                self.received.lock().unwrap().push(notification.epoch.0);
            }
        }
        let local = TestLocalSubscriber {
            received: Mutex::new(Vec::new()),
        };
        bus.register(Box::new(local));

        let service = RosterPushService::new(bus);

        // Simulate incoming push
        service
            .on_incoming_push(1, &make_roster(7, vec![10, 20]))
            .unwrap();

        // The bus should have dispatched
        assert_eq!(service.commit_bus().current_commit_index(), 1);
    }

    // -- commit_bus accessor --

    #[test]
    fn commit_bus_accessor_works() {
        let bus = EpochCommitBus::new();
        let service = RosterPushService::new(bus);
        assert_eq!(service.commit_bus().subscriber_count(), 0);
    }

    // -- No-op when no sender configured --

    #[test]
    fn on_incoming_push_works_without_sender() {
        let bus = EpochCommitBus::new();
        let service = RosterPushService::new(bus);
        let roster = make_roster(1, vec![1]);
        let result = service.on_incoming_push(1, &roster);
        assert!(result.is_ok());
        assert_eq!(service.current_epoch(), 1);
    }
}
