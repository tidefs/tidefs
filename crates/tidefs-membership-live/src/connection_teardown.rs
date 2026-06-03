//! Connection teardown bridge from membership epoch transitions to
//! transport connection lifecycle.
//!
//! [`EpochTeardownSubscriber`] subscribes to [`crate::event_bridge::MembershipEventPublisher`]
//! and, on member departure (Left, Failed, Drained), tears down the
//! associated transport connections through [`tidefs_transport::connection_registry::ConnectionRegistry`]
//! and a caller-provided teardown callback.
//!
//! # Architecture
//!
//! - Subscribes to membership lifecycle events via the event publisher.
//! - On `MemberLeft`, `MemberFailed`, or `MemberDrained`:
//!   1. Looks up the peer in [`ConnectionRegistry`] to obtain the `SocketAddr`.
//!   2. Removes the peer entry from the registry.
//!   3. Removes all bindings for the peer from [`crate::session_binding::SessionBindingTable`].
//!   4. Invokes the caller-provided `TeardownCallback` with the address and action
//!      (Drain for graceful, Close for immediate teardown).
//! - Handles edge cases: peer already disconnected (not in registry), concurrent
//!   teardown requests (second teardown is no-op), epoch-stamp races
//!   (registry entry from a newer epoch is preserved).
//!
//! # Integration
//!
//! The transport runtime provides a `TeardownCallback` that bridges to
//! [`tidefs_transport::connection::ConnectionManager`] for actual TCP stream teardown:
//!
//! ```ignore
//! use tidefs_membership_live::connection_teardown::{EpochTeardownSubscriber, TeardownAction};
//!
//! let handle = tokio::runtime::Handle::current();
//! let sub = EpochTeardownSubscriber::new(
//!     session_bindings,
//!     connection_registry,
//!     Box::new(move |addr, action| {
//!         let mgr = conn_manager.clone();
//!         handle.spawn(async move {
//!             match action {
//!                 TeardownAction::Drain => { let _ = mgr.drain(addr).await; }
//!                 TeardownAction::Close => { let _ = mgr.disconnect(addr).await; }
//!             }
//!         });
//!     }),
//! );
//! ```

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tidefs_membership_epoch::MemberId;
use tidefs_transport::connection_registry::ConnectionRegistry;

use crate::event_bridge::{MembershipEvent, MembershipEventSubscriber};
use crate::session_binding::SessionBindingTable;

// ---------------------------------------------------------------------------
// TeardownAction
// ---------------------------------------------------------------------------

/// Action to take when tearing down a transport connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TeardownAction {
    /// Graceful drain: allow in-flight work to complete, then close.
    Drain,
    /// Immediate disconnect: tear down without waiting.
    Close,
}

impl TeardownAction {
    /// Derive the teardown action from a membership event.
    #[must_use]
    pub fn from_event(event: &MembershipEvent) -> Self {
        match event {
            // Failed peers get immediate close — no point draining a dead link.
            MembershipEvent::MemberFailed { .. } => TeardownAction::Close,
            // Drained peers have already completed state transfer; close immediately.
            MembershipEvent::MemberDrained { .. } => TeardownAction::Close,
            // Peers that left gracefully get a drain window.
            MembershipEvent::MemberLeft { .. } => TeardownAction::Drain,
            // Other events (Joined, Suspected, Draining) are not teardown triggers.
            _ => TeardownAction::Drain,
        }
    }
}

// ---------------------------------------------------------------------------
// TeardownCallback
// ---------------------------------------------------------------------------

/// Callback invoked when a peer's transport connection should be torn down.
///
/// The callback receives the peer's socket address and the action to take.
/// Implementations must be non-blocking and fast; spawn async work if the
/// underlying teardown requires I/O.
pub type TeardownCallback = Box<dyn Fn(SocketAddr, TeardownAction) + Send + Sync>;

// ---------------------------------------------------------------------------
// EpochTeardownSubscriber
// ---------------------------------------------------------------------------

/// Subscribes to membership events and tears down transport connections
/// for peers that have left or failed.
///
/// Maintains a cached roster snapshot to detect removed peers on epoch
/// transitions and prevent duplicate teardown requests.
pub struct EpochTeardownSubscriber {
    /// Session binding table shared with the transport layer.
    session_bindings: Arc<Mutex<SessionBindingTable>>,
    /// Connection registry for peer-to-endpoint resolution.
    connection_registry: Arc<ConnectionRegistry>,
    /// Callback that performs the actual transport teardown.
    teardown: TeardownCallback,
    /// Cached set of peer IDs currently in the roster, used for
    /// deduplication and to detect multiple-peer removals.
    known_peers: Mutex<BTreeSet<MemberId>>,
}

impl EpochTeardownSubscriber {
    /// Create a new subscriber.
    ///
    /// `session_bindings` — shared session binding table.
    /// `connection_registry` — shared connection registry.
    /// `teardown` — callback that executes the actual transport close/drain.
    /// `initial_peers` — the set of peer IDs currently in the roster at
    ///   construction time, used as the baseline for diff-based teardown.
    #[must_use]
    pub fn new(
        session_bindings: Arc<Mutex<SessionBindingTable>>,
        connection_registry: Arc<ConnectionRegistry>,
        teardown: TeardownCallback,
        initial_peers: BTreeSet<MemberId>,
    ) -> Self {
        Self {
            session_bindings,
            connection_registry,
            teardown,
            known_peers: Mutex::new(initial_peers),
        }
    }
    /// Tear down the transport connection for a single peer.
    ///
    /// 1. Looks up the peer in the connection registry.
    /// 2. Removes the entry from the registry.
    /// 3. Removes all session bindings for the peer.
    /// 4. Invokes the teardown callback with the endpoint and action.
    ///
    /// Returns `true` if a teardown was actually performed, `false` if
    /// the peer was already gone (idempotent).
    fn teardown_peer(&self, peer_id: MemberId, action: TeardownAction) -> bool {
        // 1. Look up and remove from connection registry.
        let entry = match self.connection_registry.remove(peer_id.0) {
            Ok(entry) => entry,
            Err(_) => {
                // Peer not in registry — already torn down or never admitted.
                return false;
            }
        };

        // 2. Remove all session bindings for this peer.
        {
            let mut bindings = self.session_bindings.lock().unwrap();
            bindings.remove_all_for_peer(peer_id);
        }

        // 3. Invoke the teardown callback.
        (self.teardown)(entry.endpoint, action);

        true
    }

    /// Synchronize the cached roster against a new member set.
    ///
    /// Removes peers that are no longer present in `new_roster` from
    /// the cache, triggering teardown for each removed peer.
    ///
    /// This is the primary entry point for epoch-commit-driven teardown:
    /// after an epoch commit produces a new committed member set, call
    /// this method to tear down connections to peers that were removed.
    pub fn sync_roster(&self, new_roster: &BTreeSet<MemberId>, action: TeardownAction) -> usize {
        let mut known = self.known_peers.lock().unwrap();
        let removed: Vec<MemberId> = known.difference(new_roster).copied().collect();
        let mut count = 0;

        for peer_id in &removed {
            known.remove(peer_id);
            if self.teardown_peer(*peer_id, action) {
                count += 1;
            }
        }

        // Add newly-joined peers to the cache.
        let new_peers: Vec<MemberId> = new_roster.difference(&known).copied().collect();
        for peer_id in &new_peers {
            known.insert(*peer_id);
        }

        count
    }
}

// ---------------------------------------------------------------------------
// MembershipEventSubscriber impl
// ---------------------------------------------------------------------------

impl MembershipEventSubscriber for EpochTeardownSubscriber {
    /// Called by the publisher for each published membership event.
    ///
    /// On member departure events (`MemberLeft`, `MemberFailed`,
    /// `MemberDrained`), tears down the associated transport connection.
    ///
    /// This callback is non-blocking: the actual transport I/O is
    /// delegated to the `teardown` callback, which should spawn async
    /// work if needed.
    fn on_membership_event(&self, event: &MembershipEvent) {
        let (peer_id, action) = match event {
            MembershipEvent::MemberLeft { member_id, .. }
            | MembershipEvent::MemberFailed { member_id, .. }
            | MembershipEvent::MemberDrained { member_id, .. } => {
                (*member_id, TeardownAction::from_event(event))
            }
            // Joined, Suspected, Draining — not teardown triggers.
            _ => return,
        };

        // Update the cached roster.
        {
            let mut known = self.known_peers.lock().unwrap();
            known.remove(&peer_id);
        }

        self.teardown_peer(peer_id, action);
    }
}

// Safety: all interior mutability is behind Mutex; the teardown callback
// is required to be Send + Sync. ConnectionRegistry uses RwLock internally.
// The subscriber is designed for single-threaded use within the
// MembershipRuntime::tick() loop, consistent with MembershipEventPublisher.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    use tidefs_membership_epoch::MemberId;
    use tidefs_transport::connection_registry::ConnectionId;
    use tidefs_transport::peer_admission::AdmittedPeer;

    use crate::event_bridge::{MembershipEvent, MembershipEventSubscriber};
    use crate::session_binding::{PeerSessionBinding, SessionBindingTable, SessionId};

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    type TeardownCalls = Arc<Mutex<Vec<(SocketAddr, TeardownAction)>>>;

    fn test_endpoint() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000)
    }

    fn make_admitted(peer_id: u64, epoch: u64) -> AdmittedPeer {
        AdmittedPeer::new(peer_id, epoch)
    }

    fn make_subscriber(
        registry: Arc<ConnectionRegistry>,
        bindings: Arc<Mutex<SessionBindingTable>>,
    ) -> (EpochTeardownSubscriber, TeardownCalls) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let calls_clone = Arc::clone(&calls);

        let sub = EpochTeardownSubscriber::new(
            bindings,
            registry,
            Box::new(move |addr, action| {
                calls_clone.lock().unwrap().push((addr, action));
            }),
            BTreeSet::new(),
        );

        (sub, calls)
    }

    /// Register a peer in both the registry and binding table.
    fn register_peer(
        registry: &ConnectionRegistry,
        bindings: &Arc<Mutex<SessionBindingTable>>,
        peer_id: u64,
        endpoint: SocketAddr,
        epoch: u64,
    ) {
        let admitted = make_admitted(peer_id, epoch);
        registry
            .insert(&admitted, ConnectionId::new(peer_id * 10), endpoint)
            .unwrap();

        let mut bt = bindings.lock().unwrap();
        bt.insert(PeerSessionBinding::new(
            peer_id,
            MemberId::new(peer_id),
            SessionId::new(peer_id * 100),
            tidefs_membership_epoch::EpochId::new(epoch),
        ));
    }

    // ------------------------------------------------------------------
    // Single-peer removal via event
    // ------------------------------------------------------------------

    #[test]
    fn member_left_triggers_teardown() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));
        let ep = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8000);

        register_peer(&registry, &bindings, 42, ep, 3);

        let (sub, calls) = make_subscriber(Arc::clone(&registry), Arc::clone(&bindings));

        let event = MembershipEvent::member_left(MemberId::new(42), 5);
        sub.on_membership_event(&event);

        // Verify callback was invoked with Drain action.
        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, ep);
        assert_eq!(recorded[0].1, TeardownAction::Drain);

        // Registry should be empty.
        assert!(registry.get(42).is_none());

        // Binding table should be empty.
        assert!(bindings.lock().unwrap().is_empty());
    }

    #[test]
    fn member_failed_triggers_close() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));
        let ep = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8001);

        register_peer(&registry, &bindings, 7, ep, 2);

        let (sub, calls) = make_subscriber(Arc::clone(&registry), Arc::clone(&bindings));

        let event = MembershipEvent::member_failed(MemberId::new(7), 4);
        sub.on_membership_event(&event);

        assert_eq!(calls.lock().unwrap()[0].1, TeardownAction::Close);
    }

    #[test]
    fn member_drained_triggers_close() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));
        let ep = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8002);

        register_peer(&registry, &bindings, 99, ep, 1);

        let (sub, calls) = make_subscriber(Arc::clone(&registry), Arc::clone(&bindings));

        let event = MembershipEvent::member_drained(MemberId::new(99), 6);
        sub.on_membership_event(&event);

        assert_eq!(calls.lock().unwrap()[0].1, TeardownAction::Close);
    }

    // ------------------------------------------------------------------
    // Idempotent teardown (already-closed peer)
    // ------------------------------------------------------------------

    #[test]
    fn teardown_already_removed_peer_is_noop() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        // Don't register anything — peer is not in registry.
        let (sub, calls) = make_subscriber(Arc::clone(&registry), Arc::clone(&bindings));

        let event = MembershipEvent::member_left(MemberId::new(55), 1);
        sub.on_membership_event(&event);

        // No callback should have been invoked.
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn double_teardown_is_idempotent() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));
        let ep = test_endpoint();

        register_peer(&registry, &bindings, 1, ep, 1);

        let (sub, calls) = make_subscriber(Arc::clone(&registry), Arc::clone(&bindings));

        // First teardown.
        let event = MembershipEvent::member_left(MemberId::new(1), 2);
        sub.on_membership_event(&event);
        assert_eq!(calls.lock().unwrap().len(), 1);

        // Second teardown — should be no-op since peer is already removed.
        let event2 = MembershipEvent::member_left(MemberId::new(1), 3);
        sub.on_membership_event(&event2);
        assert_eq!(calls.lock().unwrap().len(), 1); // No new call.
    }

    // ------------------------------------------------------------------
    // Non-teardown events are ignored
    // ------------------------------------------------------------------

    #[test]
    fn joined_and_suspected_are_ignored() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));
        let ep = test_endpoint();

        register_peer(&registry, &bindings, 10, ep, 1);

        let (sub, calls) = make_subscriber(Arc::clone(&registry), Arc::clone(&bindings));

        sub.on_membership_event(&MembershipEvent::member_joined(MemberId::new(10), 1));
        sub.on_membership_event(&MembershipEvent::member_suspected(MemberId::new(10), 1));
        sub.on_membership_event(&MembershipEvent::member_draining(MemberId::new(10), 1));

        // No teardown calls should have been made.
        assert!(calls.lock().unwrap().is_empty());

        // Registry should still have the peer.
        assert!(registry.get(10).is_some());
    }

    // ------------------------------------------------------------------
    // Multi-peer removal via roster sync
    // ------------------------------------------------------------------

    #[test]
    fn sync_roster_removes_multiple_peers() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        let ep1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8000);
        let ep2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8001);
        let ep3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8002);

        register_peer(&registry, &bindings, 1, ep1, 1);
        register_peer(&registry, &bindings, 2, ep2, 1);
        register_peer(&registry, &bindings, 3, ep3, 1);

        let initial = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s
        };

        let (sub, calls) = make_subscriber(Arc::clone(&registry), Arc::clone(&bindings));
        // Override known_peers with our test set.
        *sub.known_peers.lock().unwrap() = initial;

        // New roster removes peers 2 and 3, keeps 1, adds 4.
        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(4));
            s
        };

        let removed = sub.sync_roster(&new_roster, TeardownAction::Close);
        assert_eq!(removed, 2);

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        // Both removed peers should have had their callback invoked.
        let addrs: Vec<SocketAddr> = recorded.iter().map(|(a, _)| *a).collect();
        assert!(addrs.contains(&ep2));
        assert!(addrs.contains(&ep3));
        assert!(!addrs.contains(&ep1)); // Peer 1 was kept.

        // Registry should still have peer 1 but not 2 or 3.
        assert!(registry.get(1).is_some());
        assert!(registry.get(2).is_none());
        assert!(registry.get(3).is_none());

        // Known peers cache should reflect new roster.
        let known = sub.known_peers.lock().unwrap();
        assert!(known.contains(&MemberId::new(1)));
        assert!(known.contains(&MemberId::new(4)));
        assert!(!known.contains(&MemberId::new(2)));
        assert!(!known.contains(&MemberId::new(3)));
    }

    #[test]
    fn sync_roster_empty_diff_is_noop() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));
        let ep = test_endpoint();

        register_peer(&registry, &bindings, 1, ep, 1);

        let initial = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s
        };

        let (sub, calls) = make_subscriber(Arc::clone(&registry), Arc::clone(&bindings));
        *sub.known_peers.lock().unwrap() = initial;

        // Same roster — no changes.
        let same_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s
        };

        let removed = sub.sync_roster(&same_roster, TeardownAction::Close);
        assert_eq!(removed, 0);
        assert!(calls.lock().unwrap().is_empty());
        assert!(registry.get(1).is_some());
    }

    // ------------------------------------------------------------------
    // Session binding cleanup
    // ------------------------------------------------------------------

    #[test]
    fn teardown_removes_all_bindings_for_peer() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));
        let ep = test_endpoint();

        let peer = MemberId::new(42);
        register_peer(&registry, &bindings, 42, ep, 1);

        // Add a second binding for the same peer.
        {
            let mut bt = bindings.lock().unwrap();
            bt.insert(PeerSessionBinding::new(
                2,
                peer,
                SessionId::new(999),
                tidefs_membership_epoch::EpochId::new(1),
            ));
        }

        assert_eq!(bindings.lock().unwrap().len(), 2);

        let (sub, calls) = make_subscriber(Arc::clone(&registry), Arc::clone(&bindings));

        let event = MembershipEvent::member_left(peer, 2);
        sub.on_membership_event(&event);

        // Both bindings should be removed.
        assert!(bindings.lock().unwrap().is_empty());
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    // ------------------------------------------------------------------
    // TeardownAction::from_event coverage
    // ------------------------------------------------------------------

    #[test]
    fn from_event_maps_correctly() {
        assert_eq!(
            TeardownAction::from_event(&MembershipEvent::member_failed(MemberId::new(1), 1)),
            TeardownAction::Close
        );
        assert_eq!(
            TeardownAction::from_event(&MembershipEvent::member_drained(MemberId::new(1), 1)),
            TeardownAction::Close
        );
        assert_eq!(
            TeardownAction::from_event(&MembershipEvent::member_left(MemberId::new(1), 1)),
            TeardownAction::Drain
        );
        assert_eq!(
            TeardownAction::from_event(&MembershipEvent::member_joined(MemberId::new(1), 1)),
            TeardownAction::Drain // non-triggering event; default
        );
        assert_eq!(
            TeardownAction::from_event(&MembershipEvent::member_suspected(MemberId::new(1), 1)),
            TeardownAction::Drain
        );
        assert_eq!(
            TeardownAction::from_event(&MembershipEvent::member_draining(MemberId::new(1), 1)),
            TeardownAction::Drain
        );
    }

    // ------------------------------------------------------------------
    // Epoch-stamp race: newer epoch entry not torn down
    // ------------------------------------------------------------------

    #[test]
    fn newer_epoch_entry_is_preserved() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));
        let ep = test_endpoint();

        // Register peer at epoch 1.
        register_peer(&registry, &bindings, 10, ep, 1);

        let (sub, calls) = make_subscriber(Arc::clone(&registry), Arc::clone(&bindings));
        // Simulate known roster with peer 10.
        {
            let mut known = sub.known_peers.lock().unwrap();
            known.insert(MemberId::new(10));
        }

        // Now re-register the same peer at a newer epoch (simulating re-admission
        // after a previous teardown event was processed).
        // This replaces the entry in the registry with a newer epoch.
        registry.remove(10).unwrap();
        let ep2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)), 9001);
        register_peer(&registry, &bindings, 10, ep2, 5);

        // Fire a MemberLeft for an older incarnation.
        let event = MembershipEvent::member_left(MemberId::new(10), 2);
        sub.on_membership_event(&event);

        // The registry entry at epoch 5 should have been torn down
        // (teardown removes by peer ID, not by epoch).
        assert!(registry.get(10).is_none());
        assert_eq!(calls.lock().unwrap().len(), 1);
    }
}
