//! Peer-add connection establishment on committed-epoch roster additions.
//!
//! [`PeerAddConnector`] bridges committed-epoch roster additions to transport
//! connection establishment.  When the
//! [`crate::epoch_coordinator::EpochAdvanceCoordinator`] commits a new
//! [`crate::epoch_coordinator::EpochView`] that adds peer members not present
//! in the prior roster, the connector triggers transport connection
//! establishment for each added peer and emits
//! [`crate::transport_event_recorder::MembershipTransportEvent::PeerConnected`]
//! events through the
//! [`crate::transport_event_recorder::TransportEventRecorder`] for
//! deterministic replay coverage.
//!
//! This is the peer-add complement to
//! [`crate::peer_eviction::EvictionExecutor`] (teardown of removed peers) and
//! [`crate::reconnect_handshake::PeerReconnectHandshake`] (re-binding of
//! previously-known peers).
//!
//! # Architecture
//!
//! The connector implements
//! [`crate::epoch_coordinator::EpochCommitSubscriber`] and is registered with
//! the [`EpochAdvanceCoordinator`] via
//! [`EpochAdvanceCoordinator::subscribe`].  On each committed epoch view:
//!
//! 1. The new member set is compared against a cached prior roster.
//! 2. Added peers are identified via set difference.
//! 3. For each added peer:
//!    - The caller-provided [`PeerAddCallback`] is invoked to initiate
//!      transport connection establishment.
//!    - On success, a
//!      [`MembershipTransportEvent::PeerConnected`]
//!      is emitted through the [`TransportEventRecorder`].
//!    - On failure, a
//!      [`MembershipTransportEvent::ConnectionError`]
//!      is emitted instead, and the connector continues to the next peer.
//! 4. The prior-roster cache is updated to include the new peers.
//!
//! # Integration
//!
//! ```ignore
//! use tidefs_membership_live::peer_add_connector::{
//!     PeerAddConnector, PeerAddCallback, PeerAddStatus,
//! };
//!
//! let connector = PeerAddConnector::new(
//!     event_recorder.clone(),
//!     Box::new(move |member_id| {
//!         // Resolve member_id -> endpoint, initiate transport connect.
//!         // Return PeerAddStatus::Connected or PeerAddStatus::Unreachable(...).
//!         PeerAddStatus::Connected
//!     }),
//!     initial_roster,
//! );
//!
//! coordinator.subscribe(Box::new(connector));
//! ```

use std::collections::BTreeSet;
use std::sync::Mutex;

use tidefs_membership_epoch::MemberId;

use crate::epoch_coordinator::{EpochCommitSubscriber, EpochView};
use crate::transport_event_recorder::{MembershipTransportEvent, TransportEventRecorder};

// ---------------------------------------------------------------------------
// PeerAddStatus
// ---------------------------------------------------------------------------

/// Outcome of an attempt to establish a transport connection to an added peer.
///
/// Returned by [`PeerAddCallback`] so the connector can emit the appropriate
/// transport event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerAddStatus {
    /// Transport connection establishment succeeded.
    Connected,
    /// Transport connection establishment failed for the given reason.
    Unreachable(String),
}

// ---------------------------------------------------------------------------
// PeerAddOutcome
// ---------------------------------------------------------------------------

/// Result of processing a single added peer during an epoch commit.
///
/// Carries the peer identity and the connection status for observability
/// and deterministic replay verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAddOutcome {
    /// The peer that was added.
    pub peer_id: MemberId,
    /// Whether the connection succeeded or was unreachable.
    pub status: PeerAddStatus,
}

// ---------------------------------------------------------------------------
// PeerAddCallback
// ---------------------------------------------------------------------------

/// Callback invoked when a peer newly added to the roster should have a
/// transport connection established.
///
/// The callback receives the peer's `MemberId`.  Implementations are
/// responsible for resolving the member ID to a network endpoint and
/// initiating the transport connect.
///
/// Returns [`PeerAddStatus::Connected`] on success or
/// [`PeerAddStatus::Unreachable`] with a diagnostic message on failure.
///
/// Implementations must be non-blocking and fast; spawn async work if the
/// underlying connect requires I/O.
pub type PeerAddCallback = Box<dyn Fn(MemberId) -> PeerAddStatus + Send + Sync>;

// ---------------------------------------------------------------------------
// PeerAddConnector
// ---------------------------------------------------------------------------

/// Bridges committed-epoch roster additions to transport connection
/// establishment.
///
/// Implements [`EpochCommitSubscriber`] to receive committed epoch views
/// from the
/// [`crate::epoch_coordinator::EpochAdvanceCoordinator`].  On each commit,
/// diffs the new member set against the prior roster, invokes the callback
/// for each added peer, and emits transport events for deterministic
/// replay coverage.
///
/// # Lifecycle
///
/// 1. Construct via [`new`](PeerAddConnector::new) with an event recorder,
///    a connect callback, and the initial roster.
/// 2. Register with the epoch advance coordinator via
///    `coordinator.subscribe(Box::new(connector))`.
/// 3. On each committed epoch, newly added peers are automatically
///    connected and recorded.
///
/// # Failure handling
///
/// Connection failure for a given peer emits a
/// [`MembershipTransportEvent::ConnectionError`] event and the connector
/// continues to the next peer.  Epoch advancement is never blocked by
/// peer connection failures.
pub struct PeerAddConnector {
    /// Transport event recorder for deterministic replay coverage.
    event_recorder: TransportEventRecorder,
    /// Callback that initiates the actual transport connect.
    connect_callback: PeerAddCallback,
    /// Cached set of peer IDs from the last committed epoch, used for
    /// diff-based peer-add detection.
    prior_roster: Mutex<BTreeSet<MemberId>>,
}

impl PeerAddConnector {
    /// Create a new connector.
    ///
    /// `event_recorder` — shared recorder for emitting transport events.
    /// `connect_callback` — callback that initiates transport connection.
    /// `initial_roster` — the set of peer IDs in the initial epoch view,
    ///   used as the baseline for diff-based peer-add detection.
    #[must_use]
    pub fn new(
        event_recorder: TransportEventRecorder,
        connect_callback: PeerAddCallback,
        initial_roster: BTreeSet<MemberId>,
    ) -> Self {
        Self {
            event_recorder,
            connect_callback,
            prior_roster: Mutex::new(initial_roster),
        }
    }

    /// Attempt to connect to a single added peer and emit the appropriate
    /// transport event.
    ///
    /// Returns a [`PeerAddOutcome`] recording the result.
    fn connect_peer(&self, peer_id: MemberId) -> PeerAddOutcome {
        let status = (self.connect_callback)(peer_id);

        match &status {
            PeerAddStatus::Connected => {
                self.event_recorder
                    .record(MembershipTransportEvent::PeerConnected {
                        peer_id,
                        label: format!("peer-add:{peer_id:?}"),
                    });
            }
            PeerAddStatus::Unreachable(reason) => {
                self.event_recorder
                    .record(MembershipTransportEvent::ConnectionError {
                        peer_id,
                        error_kind: format!("peer-add-unreachable:{reason}"),
                    });
            }
        }

        PeerAddOutcome { peer_id, status }
    }

    /// Diff the new roster against the prior roster and establish
    /// connections to added peers.
    ///
    /// Returns a [`Vec<PeerAddOutcome>`] with one entry per added peer.
    /// Peers already in the prior roster are not processed.
    ///
    /// This is the primary entry point for epoch-commit-driven peer
    /// connection establishment.
    pub fn execute_adds(&self, new_roster: &BTreeSet<MemberId>) -> Vec<PeerAddOutcome> {
        let mut prior = self.prior_roster.lock().unwrap();

        // Identify added peers: present in new roster, absent in prior.
        let added: Vec<MemberId> = new_roster.difference(&prior).copied().collect();
        let mut outcomes = Vec::with_capacity(added.len());

        for peer_id in &added {
            prior.insert(*peer_id);
            outcomes.push(self.connect_peer(*peer_id));
        }

        outcomes
    }

    /// Number of peers in the cached prior roster.
    #[must_use]
    pub fn known_peer_count(&self) -> usize {
        self.prior_roster.lock().unwrap().len()
    }

    /// Return a reference to the event recorder so callers can drain or
    /// snapshot events for deterministic replay verification.
    #[must_use]
    pub fn event_recorder(&self) -> &TransportEventRecorder {
        &self.event_recorder
    }
}

// ---------------------------------------------------------------------------
// EpochCommitSubscriber impl
// ---------------------------------------------------------------------------

impl EpochCommitSubscriber for PeerAddConnector {
    /// Called when a new epoch view is committed by the coordinator.
    ///
    /// Diffs the new member set against the prior roster, triggers
    /// transport connection establishment for each added peer, and
    /// emits the appropriate transport events.
    ///
    /// This callback is non-blocking: the actual transport I/O is
    /// delegated to the [`PeerAddCallback`], which should spawn async
    /// work if needed.
    fn on_epoch_committed(&self, view: &EpochView) {
        let new_roster: BTreeSet<MemberId> = view.member_set.iter().copied().collect();
        let _outcomes = self.execute_adds(&new_roster);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use tidefs_membership_epoch::MemberId;

    use crate::epoch_coordinator::{
        EpochAdvanceCoordinator, PeerLivenessChange, PeerLivenessStatus,
    };
    use crate::transport_event_recorder::{EventLog, MembershipTransportEvent};

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    type PeerAddCalls = Arc<Mutex<Vec<(MemberId, PeerAddStatus)>>>;

    fn make_connector(
        recorder: TransportEventRecorder,
        initial: BTreeSet<MemberId>,
    ) -> (PeerAddConnector, PeerAddCalls) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let calls_clone = Arc::clone(&calls);

        let connector = PeerAddConnector::new(
            recorder,
            Box::new(move |member_id| {
                let status = PeerAddStatus::Connected;
                calls_clone
                    .lock()
                    .unwrap()
                    .push((member_id, status.clone()));
                status
            }),
            initial,
        );

        (connector, calls)
    }

    fn make_connector_with_status(
        recorder: TransportEventRecorder,
        initial: BTreeSet<MemberId>,
        status_fn: impl Fn(MemberId) -> PeerAddStatus + Send + Sync + 'static,
    ) -> PeerAddConnector {
        PeerAddConnector::new(recorder, Box::new(status_fn), initial)
    }

    fn new_coordinator_with_connector(
        members: Vec<MemberId>,
        connector: PeerAddConnector,
    ) -> EpochAdvanceCoordinator {
        let mut coord = EpochAdvanceCoordinator::new(1);
        coord.initialize(members, 1_700_000_000_000);
        coord.subscribe(Box::new(connector));
        coord
    }

    fn drain_connected_ids(recorder: &TransportEventRecorder) -> Vec<MemberId> {
        let log: EventLog = recorder.drain_events();
        log.events
            .iter()
            .filter_map(|te| match &te.event {
                MembershipTransportEvent::PeerConnected { peer_id, .. } => Some(*peer_id),
                _ => None,
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // EpochCommitSubscriber integration: single peer add
    // ------------------------------------------------------------------

    #[test]
    fn subscriber_receives_commit_and_connects_added_peer() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s
        };

        let (connector, calls) = make_connector(recorder.clone(), initial);

        let mut coord =
            new_coordinator_with_connector(vec![MemberId::new(1), MemberId::new(2)], connector);

        // Peer 3 transitions Dead->Alive: coordinator adds it to the roster.
        let change = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Dead,
            PeerLivenessStatus::Alive,
            1_700_000_000_000,
        );
        let result = coord.on_liveness_change(change);
        assert!(result.is_some());

        // Callback was invoked for peer 3.
        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, MemberId::new(3));
        assert_eq!(recorded[0].1, PeerAddStatus::Connected);

        // PeerConnected event emitted.
        let connected = drain_connected_ids(&recorder);
        assert_eq!(connected, vec![MemberId::new(3)]);
    }

    // ------------------------------------------------------------------
    // EpochCommitSubscriber: no-op when roster unchanged
    // ------------------------------------------------------------------

    #[test]
    fn no_adds_when_roster_unchanged() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s
        };

        let (connector, calls) = make_connector(recorder.clone(), initial);

        let mut coord =
            new_coordinator_with_connector(vec![MemberId::new(1), MemberId::new(2)], connector);

        // Peer 1 Alive->Alive: no transition, no epoch commit.
        let change = PeerLivenessChange::new(
            MemberId::new(1),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Alive,
            1_700_000_000_000,
        );
        let result = coord.on_liveness_change(change);
        assert!(result.is_none());

        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(recorder.event_count(), 0);
    }

    // ------------------------------------------------------------------
    // Roster diff: added, retained, no-op
    // ------------------------------------------------------------------

    #[test]
    fn execute_adds_identifies_new_peers() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s
        };

        let (connector, calls) = make_connector(recorder.clone(), initial);

        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s
        };

        let outcomes = connector.execute_adds(&new_roster);
        assert_eq!(outcomes.len(), 2);

        let added_ids: BTreeSet<MemberId> = outcomes.iter().map(|o| o.peer_id).collect();
        assert!(added_ids.contains(&MemberId::new(2)));
        assert!(added_ids.contains(&MemberId::new(3)));
        assert!(!added_ids.contains(&MemberId::new(1)));

        for outcome in &outcomes {
            assert_eq!(outcome.status, PeerAddStatus::Connected);
        }

        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn execute_adds_empty_diff_is_noop() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s
        };

        let (connector, calls) = make_connector(recorder.clone(), initial);

        let same_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s
        };

        let outcomes = connector.execute_adds(&same_roster);
        assert!(outcomes.is_empty());
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(recorder.event_count(), 0);
    }

    #[test]
    fn execute_adds_no_adds_when_all_known() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s
        };

        let (connector, calls) = make_connector(recorder.clone(), initial);

        // Subset of initial -- no new peers.
        let subset: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s
        };

        let outcomes = connector.execute_adds(&subset);
        assert!(outcomes.is_empty());
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn execute_adds_all_new() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = BTreeSet::new();

        let (connector, calls) = make_connector(recorder.clone(), initial);

        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(10));
            s.insert(MemberId::new(20));
            s.insert(MemberId::new(30));
            s
        };

        let outcomes = connector.execute_adds(&new_roster);
        assert_eq!(outcomes.len(), 3);
        assert_eq!(calls.lock().unwrap().len(), 3);

        let connected = drain_connected_ids(&recorder);
        assert_eq!(connected.len(), 3);
    }

    // ------------------------------------------------------------------
    // Connection failure: unreachable peer
    // ------------------------------------------------------------------

    #[test]
    fn unreachable_peer_emits_connection_error() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s
        };

        let connector = make_connector_with_status(recorder.clone(), initial, move |peer_id| {
            if peer_id == MemberId::new(3) {
                PeerAddStatus::Unreachable("no route".into())
            } else {
                PeerAddStatus::Connected
            }
        });

        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s
        };

        let outcomes = connector.execute_adds(&new_roster);
        assert_eq!(outcomes.len(), 2);

        // Peer 2 connected, peer 3 unreachable.
        let outcome_2 = outcomes
            .iter()
            .find(|o| o.peer_id == MemberId::new(2))
            .unwrap();
        assert_eq!(outcome_2.status, PeerAddStatus::Connected);

        let outcome_3 = outcomes
            .iter()
            .find(|o| o.peer_id == MemberId::new(3))
            .unwrap();
        assert_eq!(
            outcome_3.status,
            PeerAddStatus::Unreachable("no route".into())
        );

        // PeerConnected for 2, ConnectionError for 3.
        let log = recorder.drain_events();
        let connected: Vec<MemberId> = log
            .events
            .iter()
            .filter_map(|te| match &te.event {
                MembershipTransportEvent::PeerConnected { peer_id, .. } => Some(*peer_id),
                _ => None,
            })
            .collect();
        let errors: Vec<MemberId> = log
            .events
            .iter()
            .filter_map(|te| match &te.event {
                MembershipTransportEvent::ConnectionError { peer_id, .. } => Some(*peer_id),
                _ => None,
            })
            .collect();
        assert_eq!(connected, vec![MemberId::new(2)]);
        assert_eq!(errors, vec![MemberId::new(3)]);
    }

    #[test]
    fn unreachable_peer_does_not_block_others() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = BTreeSet::new();

        let connector = make_connector_with_status(recorder.clone(), initial, move |peer_id| {
            if peer_id.0 % 2 == 0 {
                PeerAddStatus::Connected
            } else {
                PeerAddStatus::Unreachable("odd peer".into())
            }
        });

        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s.insert(MemberId::new(4));
            s
        };

        let outcomes = connector.execute_adds(&new_roster);
        assert_eq!(outcomes.len(), 4);

        let connected: Vec<_> = outcomes
            .iter()
            .filter(|o| o.status == PeerAddStatus::Connected)
            .map(|o| o.peer_id)
            .collect();
        let unreachable: Vec<_> = outcomes
            .iter()
            .filter(|o| matches!(o.status, PeerAddStatus::Unreachable(_)))
            .map(|o| o.peer_id)
            .collect();

        assert_eq!(connected.len(), 2);
        assert_eq!(unreachable.len(), 2);
        assert_eq!(recorder.event_count(), 4);
    }

    // ------------------------------------------------------------------
    // Transport event emission order
    // ------------------------------------------------------------------

    #[test]
    fn events_emitted_in_roster_order() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = BTreeSet::new();

        let (connector, _calls) = make_connector(recorder.clone(), initial);

        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(30));
            s.insert(MemberId::new(10));
            s.insert(MemberId::new(20));
            s
        };

        connector.execute_adds(&new_roster);

        // BTreeSet iterates in sorted (ascending) order.
        let log = recorder.drain_events();
        let ids: Vec<MemberId> = log
            .events
            .iter()
            .filter_map(|te| match &te.event {
                MembershipTransportEvent::PeerConnected { peer_id, .. } => Some(*peer_id),
                _ => None,
            })
            .collect();

        assert_eq!(
            ids,
            vec![MemberId::new(10), MemberId::new(20), MemberId::new(30)]
        );
    }

    // ------------------------------------------------------------------
    // Multiple simultaneous additions
    // ------------------------------------------------------------------

    #[test]
    fn multiple_peers_added_simultaneously() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s
        };

        let (connector, calls) = make_connector(recorder.clone(), initial);

        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s.insert(MemberId::new(4));
            s.insert(MemberId::new(5));
            s
        };

        let outcomes = connector.execute_adds(&new_roster);
        assert_eq!(outcomes.len(), 4);
        assert_eq!(calls.lock().unwrap().len(), 4);

        let connected = drain_connected_ids(&recorder);
        assert_eq!(connected.len(), 4);
    }

    // ------------------------------------------------------------------
    // Idempotency: added peer tracked in prior roster
    // ------------------------------------------------------------------

    #[test]
    fn second_epoch_does_not_retrigger_already_added_peer() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s
        };

        let (connector, calls) = make_connector(recorder.clone(), initial);

        // First epoch add.
        let first: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s
        };
        let outcomes = connector.execute_adds(&first);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(calls.lock().unwrap().len(), 1);

        // Second epoch with same members -- no new adds.
        let second: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s
        };
        let outcomes = connector.execute_adds(&second);
        assert!(outcomes.is_empty());
        assert_eq!(calls.lock().unwrap().len(), 1);

        // Third epoch adds peer 3.
        let third: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s
        };
        let outcomes = connector.execute_adds(&third);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(calls.lock().unwrap().len(), 2);

        let connected = drain_connected_ids(&recorder);
        assert_eq!(connected.len(), 2);
    }

    // ------------------------------------------------------------------
    // known_peer_count
    // ------------------------------------------------------------------

    #[test]
    fn known_peer_count_reflects_cached_roster() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s
        };

        let (connector, _calls) = make_connector(recorder.clone(), initial);

        assert_eq!(connector.known_peer_count(), 3);

        // Add peers 4 and 5.
        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s.insert(MemberId::new(4));
            s.insert(MemberId::new(5));
            s
        };
        connector.execute_adds(&new_roster);
        assert_eq!(connector.known_peer_count(), 5);
    }

    // ------------------------------------------------------------------
    // event_recorder accessor
    // ------------------------------------------------------------------

    #[test]
    fn event_recorder_accessor_returns_same_recorder() {
        let recorder = TransportEventRecorder::new();
        let initial: BTreeSet<MemberId> = BTreeSet::new();

        let (connector, _calls) = make_connector(recorder.clone(), initial);

        // Record through the accessor.
        connector
            .event_recorder()
            .record(MembershipTransportEvent::PeerConnected {
                peer_id: MemberId::new(99),
                label: "test".into(),
            });

        let connected = drain_connected_ids(connector.event_recorder());
        assert_eq!(connected, vec![MemberId::new(99)]);
    }

    // ------------------------------------------------------------------
    // EpochCommitSubscriber: peer removal does not trigger add
    // ------------------------------------------------------------------

    #[test]
    fn dead_peer_removal_does_not_trigger_add() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s
        };

        let (connector, calls) = make_connector(recorder.clone(), initial);

        let mut coord = new_coordinator_with_connector(
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            connector,
        );

        // Peer 2 goes Dead -- removed from roster.
        let change = PeerLivenessChange::new(
            MemberId::new(2),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            1_700_000_000_000,
        );
        let result = coord.on_liveness_change(change);
        assert!(result.is_some());

        // No connection attempt for removed peer.
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(recorder.event_count(), 0);
    }

    // ------------------------------------------------------------------
    // PeerAddStatus traits
    // ------------------------------------------------------------------

    #[test]
    fn peer_add_status_debug_and_eq() {
        assert_eq!(PeerAddStatus::Connected, PeerAddStatus::Connected);
        assert_ne!(
            PeerAddStatus::Connected,
            PeerAddStatus::Unreachable("no route".into())
        );
        assert_eq!(
            PeerAddStatus::Unreachable("a".into()),
            PeerAddStatus::Unreachable("a".into())
        );
        assert_ne!(
            PeerAddStatus::Unreachable("a".into()),
            PeerAddStatus::Unreachable("b".into())
        );
        assert_eq!(format!("{:?}", PeerAddStatus::Connected), "Connected");
        assert_eq!(
            format!("{:?}", PeerAddStatus::Unreachable("no route".into())),
            "Unreachable(\"no route\")"
        );
    }

    // ------------------------------------------------------------------
    // PeerAddOutcome
    // ------------------------------------------------------------------

    #[test]
    fn peer_add_outcome_carries_correct_fields() {
        let outcome = PeerAddOutcome {
            peer_id: MemberId::new(7),
            status: PeerAddStatus::Connected,
        };
        assert_eq!(outcome.peer_id, MemberId::new(7));
        assert_eq!(outcome.status, PeerAddStatus::Connected);

        let outcome_err = PeerAddOutcome {
            peer_id: MemberId::new(8),
            status: PeerAddStatus::Unreachable("timeout".into()),
        };
        assert_eq!(outcome_err.peer_id, MemberId::new(8));
        assert_eq!(
            outcome_err.status,
            PeerAddStatus::Unreachable("timeout".into())
        );
    }

    // ------------------------------------------------------------------
    // Deterministic replay: events captured for replay
    // ------------------------------------------------------------------

    #[test]
    fn deterministic_replay_events_captured_in_order() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = BTreeSet::new();

        let (connector, _calls) = make_connector(recorder.clone(), initial);

        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(100));
            s.insert(MemberId::new(200));
            s.insert(MemberId::new(300));
            s
        };

        connector.execute_adds(&new_roster);

        let log = recorder.drain_events();
        assert_eq!(log.events.len(), 3);

        // Verify each event is well-formed and carries correct peer ID.
        for (i, expected_id) in [100u64, 200u64, 300u64].iter().enumerate() {
            let te = &log.events[i];
            assert!(te.seq > 0);
            assert!(te.at_millis > 0);
            match &te.event {
                MembershipTransportEvent::PeerConnected { peer_id, label } => {
                    assert_eq!(*peer_id, MemberId::new(*expected_id));
                    assert!(label.contains("peer-add"));
                }
                other => panic!("expected PeerConnected, got {other:?}"),
            }
        }
    }

    #[test]
    fn deterministic_replay_mixed_connected_and_unreachable() {
        let recorder = TransportEventRecorder::new();

        let initial: BTreeSet<MemberId> = BTreeSet::new();

        let connector = make_connector_with_status(recorder.clone(), initial, move |peer_id| {
            if peer_id.0 == 200 {
                PeerAddStatus::Unreachable("simulated failure".into())
            } else {
                PeerAddStatus::Connected
            }
        });

        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(100));
            s.insert(MemberId::new(200));
            s.insert(MemberId::new(300));
            s
        };

        connector.execute_adds(&new_roster);

        let log = recorder.drain_events();
        assert_eq!(log.events.len(), 3);

        // Peer 100: Connected
        match &log.events[0].event {
            MembershipTransportEvent::PeerConnected { peer_id, .. } => {
                assert_eq!(*peer_id, MemberId::new(100));
            }
            other => panic!("expected PeerConnected, got {other:?}"),
        }

        // Peer 200: ConnectionError
        match &log.events[1].event {
            MembershipTransportEvent::ConnectionError {
                peer_id,
                error_kind,
            } => {
                assert_eq!(*peer_id, MemberId::new(200));
                assert!(error_kind.contains("simulated failure"));
            }
            other => panic!("expected ConnectionError, got {other:?}"),
        }

        // Peer 300: Connected
        match &log.events[2].event {
            MembershipTransportEvent::PeerConnected { peer_id, .. } => {
                assert_eq!(*peer_id, MemberId::new(300));
            }
            other => panic!("expected PeerConnected, got {other:?}"),
        }
    }
}
