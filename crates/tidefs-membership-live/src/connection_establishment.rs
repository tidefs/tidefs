// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Connection establishment bridge from membership epoch transitions to
//! transport connection lifecycle.
//!
//! [`ConnectionEstablishmentSubscriber`] subscribes to
//! [`crate::event_bridge::MembershipEventPublisher`] and, when new peers
//! appear in the membership roster (via `MemberJoined` events or a
//! committed roster diff), triggers transport connection establishment
//! through a caller-provided callback.
//!
//! This is the symmetric counterpart to [`crate::connection_teardown`],
//! which handles peer removal.
//!
//! # Architecture
//!
//! - Subscribes to membership lifecycle events via the event publisher.
//! - On `MemberJoined`:
//!   1. Checks if the peer is already in the cached known-peer set.
//!   2. Checks the [`ConnectionRegistry`] for an existing connection
//!      (idempotency guard).
//!   3. Invokes the caller-provided `EstablishCallback` with the
//!      member ID.
//! - A `sync_roster` method diffs the cached known-peer set against a
//!   new committed roster and triggers establishment for every newly
//!   added peer.
//!
//! # Integration
//!
//! The transport runtime provides an `EstablishCallback` that bridges to
//! [`tidefs_transport::connection::ConnectionManager`]:
//!
//! ```ignore
//! use tidefs_membership_live::connection_establishment::{
//!     ConnectionEstablishmentSubscriber, ConnectionEstablishmentConfig,
//! };
//!
//! let handle = tokio::runtime::Handle::current();
//! let sub = ConnectionEstablishmentSubscriber::new(
//!     ConnectionEstablishmentConfig::default(),
//!     connection_registry,
//!     Box::new(move |member_id| {
//!         let mgr = conn_manager.clone();
//!         let addr = resolve_peer_address(member_id);
//!         handle.spawn(async move {
//!             let _ = mgr.connect(addr).await;
//!         });
//!     }),
//!     BTreeSet::new(),
//! );
//! ```

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use tidefs_membership_epoch::MemberId;
use tidefs_transport::connection_registry::ConnectionRegistry;

use crate::event_bridge::{MembershipEvent, MembershipEventSubscriber};

// ---------------------------------------------------------------------------
// ConnectionEstablishmentConfig
// ---------------------------------------------------------------------------

/// Configuration for connection establishment retry behavior.
///
/// The subscriber itself does not perform retries — it is a synchronous
/// non-blocking component. The config is exposed so the caller-provided
/// [`EstablishCallback`] can read it and implement retry logic internally
/// (e.g., spawning async connect attempts with backoff).
#[derive(Clone, Debug)]
pub struct ConnectionEstablishmentConfig {
    /// Maximum number of connect attempts before giving up.
    /// Default: 3.
    pub max_attempts: u32,
    /// Backoff duration in milliseconds between retry attempts.
    /// Default: 500ms.
    pub backoff_ms: u64,
}

impl Default for ConnectionEstablishmentConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            backoff_ms: 500,
        }
    }
}

impl ConnectionEstablishmentConfig {
    /// Create a new config with the given retry policy.
    #[must_use]
    pub fn new(max_attempts: u32, backoff_ms: u64) -> Self {
        Self {
            max_attempts,
            backoff_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// EstablishCallback
// ---------------------------------------------------------------------------

/// Callback invoked when a new peer should have a transport connection
/// established.
///
/// The callback receives the peer's `MemberId`. Implementations are
/// responsible for resolving the member ID to a network endpoint and
/// initiating the transport connect.
///
/// Implementations must be non-blocking and fast; spawn async work if
/// the underlying connect requires I/O.
pub type EstablishCallback = Box<dyn Fn(MemberId) + Send + Sync>;

// ---------------------------------------------------------------------------
// ConnectionEstablishmentSubscriber
// ---------------------------------------------------------------------------

/// Subscribes to membership events and triggers transport connection
/// establishment for newly joined peers.
///
/// Maintains a cached known-peer set to detect new peers on epoch
/// transitions (via `sync_roster`) and to prevent duplicate
/// establishment requests.
pub struct ConnectionEstablishmentSubscriber {
    /// Configuration controlling establishment behavior.
    #[allow(dead_code)]
    config: ConnectionEstablishmentConfig,
    /// Connection registry for idempotency checks.
    connection_registry: Arc<ConnectionRegistry>,
    /// Callback that triggers the actual transport connect.
    establish: EstablishCallback,
    /// Cached set of peer IDs currently known to the subscriber, used
    /// for deduplication and to detect newly-added peers on roster
    /// sync.
    known_peers: Mutex<BTreeSet<MemberId>>,
}

impl ConnectionEstablishmentSubscriber {
    /// Create a new subscriber.
    ///
    /// `config` — establishment retry behavior (used by callback).
    /// `connection_registry` — shared registry for idempotency checks.
    /// `establish` — callback that initiates the transport connect.
    /// `initial_peers` — the set of peer IDs currently in the roster at
    ///   construction time, used as the baseline for diff-based
    ///   establishment.
    #[must_use]
    pub fn new(
        config: ConnectionEstablishmentConfig,
        connection_registry: Arc<ConnectionRegistry>,
        establish: EstablishCallback,
        initial_peers: BTreeSet<MemberId>,
    ) -> Self {
        Self {
            config,
            connection_registry,
            establish,
            known_peers: Mutex::new(initial_peers),
        }
    }

    /// Return a reference to the config so callers can inspect retry
    /// policy.
    #[must_use]
    pub fn config(&self) -> &ConnectionEstablishmentConfig {
        &self.config
    }

    /// Trigger connection establishment for a single peer.
    ///
    /// 1. Checks the connection registry: if the peer already has an
    ///    active connection entry, establishment is skipped (idempotent).
    /// 2. Adds the peer to the cached known-peer set.
    /// 3. Invokes the establish callback with the member ID.
    ///
    /// Returns `true` if establishment was triggered, `false` if
    /// the peer was already connected (idempotent no-op).
    fn establish_peer(&self, peer_id: MemberId) -> bool {
        // Idempotency check: if the peer already has a connection entry,
        // skip establishment.
        if self.connection_registry.get(peer_id.0).is_some() {
            return false;
        }

        // Add to known-peers cache.
        {
            let mut known = self.known_peers.lock().unwrap();
            known.insert(peer_id);
        }

        // Invoke the callback.
        (self.establish)(peer_id);

        true
    }

    /// Synchronize the cached known-peer set against a new committed
    /// roster.
    ///
    /// Triggers connection establishment for every peer present in
    /// `new_roster` that is not already in the cached known-peer set.
    ///
    /// This is the primary entry point for epoch-commit-driven
    /// establishment: after an epoch commit produces a new committed
    /// member set, call this method to establish connections to
    /// newly added peers.
    ///
    /// Returns the number of new peers for which establishment was
    /// triggered. Peers with existing connections (already in the
    /// registry) are not counted.
    pub fn sync_roster(&self, new_roster: &BTreeSet<MemberId>) -> usize {
        let known = self.known_peers.lock().unwrap();
        let new_peers: Vec<MemberId> = new_roster.difference(&known).copied().collect();
        drop(known);

        let mut count = 0;
        for peer_id in &new_peers {
            if self.establish_peer(*peer_id) {
                count += 1;
            }
        }

        count
    }

    /// Return the number of peers currently in the cached known set.
    #[must_use]
    pub fn known_peer_count(&self) -> usize {
        self.known_peers.lock().unwrap().len()
    }
}

// ---------------------------------------------------------------------------
// MembershipEventSubscriber impl
// ---------------------------------------------------------------------------

impl MembershipEventSubscriber for ConnectionEstablishmentSubscriber {
    /// Called by the publisher for each published membership event.
    ///
    /// On `MemberJoined` events, triggers transport connection
    /// establishment for the new peer.
    ///
    /// All other events (`MemberSuspected`, `MemberFailed`,
    /// `MemberLeft`, `MemberDraining`, `MemberDrained`) are ignored —
    /// those are handled by [`crate::connection_teardown`].
    ///
    /// This callback is non-blocking: the actual transport I/O is
    /// delegated to the `establish` callback, which should spawn
    /// async work if needed.
    fn on_membership_event(&self, event: &MembershipEvent) {
        let peer_id = match event {
            MembershipEvent::MemberJoined { member_id, .. } => *member_id,
            // Other event variants are not establishment triggers.
            _ => return,
        };

        // Check if we already know about this peer.
        {
            let known = self.known_peers.lock().unwrap();
            if known.contains(&peer_id) {
                return;
            }
        }

        self.establish_peer(peer_id);
    }
}

// Safety: all interior mutability is behind Mutex; the establish callback
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use tidefs_membership_epoch::MemberId;
    use tidefs_transport::connection_registry::ConnectionId;
    use tidefs_transport::peer_admission::AdmittedPeer;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn test_endpoint() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000)
    }

    fn make_admitted(peer_id: u64, epoch: u64) -> AdmittedPeer {
        AdmittedPeer::new(peer_id, epoch)
    }

    fn make_subscriber(
        registry: Arc<ConnectionRegistry>,
    ) -> (ConnectionEstablishmentSubscriber, Arc<Mutex<Vec<MemberId>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let calls_clone = Arc::clone(&calls);

        let sub = ConnectionEstablishmentSubscriber::new(
            ConnectionEstablishmentConfig::default(),
            registry,
            Box::new(move |member_id| {
                calls_clone.lock().unwrap().push(member_id);
            }),
            BTreeSet::new(),
        );

        (sub, calls)
    }

    /// Register a peer in the connection registry, simulating an
    /// already-connected peer.
    fn register_peer(
        registry: &ConnectionRegistry,
        peer_id: u64,
        endpoint: SocketAddr,
        epoch: u64,
    ) {
        let admitted = make_admitted(peer_id, epoch);
        registry
            .insert(&admitted, ConnectionId::new(peer_id * 10), endpoint)
            .unwrap();
    }

    /// Seed the subscriber's known-peers cache.
    fn seed_known_peers(sub: &ConnectionEstablishmentSubscriber, peers: &[u64]) {
        let mut known = sub.known_peers.lock().unwrap();
        for &pid in peers {
            known.insert(MemberId::new(pid));
        }
    }

    // ------------------------------------------------------------------
    // Single-peer join via event
    // ------------------------------------------------------------------

    #[test]
    fn member_joined_triggers_establish() {
        let registry = Arc::new(ConnectionRegistry::new());
        let (sub, calls) = make_subscriber(Arc::clone(&registry));

        let event = MembershipEvent::member_joined(MemberId::new(42), 1);
        sub.on_membership_event(&event);

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], MemberId::new(42));

        let known = sub.known_peers.lock().unwrap();
        assert!(known.contains(&MemberId::new(42)));
    }

    #[test]
    fn member_joined_already_connected_is_noop() {
        let registry = Arc::new(ConnectionRegistry::new());
        let ep = test_endpoint();

        register_peer(&registry, 42, ep, 1);

        let (sub, calls) = make_subscriber(Arc::clone(&registry));

        let event = MembershipEvent::member_joined(MemberId::new(42), 1);
        sub.on_membership_event(&event);

        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn member_joined_already_known_is_noop() {
        let registry = Arc::new(ConnectionRegistry::new());
        let (sub, calls) = make_subscriber(Arc::clone(&registry));

        seed_known_peers(&sub, &[42]);

        let event = MembershipEvent::member_joined(MemberId::new(42), 1);
        sub.on_membership_event(&event);

        assert!(calls.lock().unwrap().is_empty());
    }

    // ------------------------------------------------------------------
    // Non-establishment events are ignored
    // ------------------------------------------------------------------

    #[test]
    fn non_join_events_are_ignored() {
        let registry = Arc::new(ConnectionRegistry::new());
        let (sub, calls) = make_subscriber(Arc::clone(&registry));

        sub.on_membership_event(&MembershipEvent::member_suspected(MemberId::new(10), 1));
        sub.on_membership_event(&MembershipEvent::member_failed(MemberId::new(10), 1));
        sub.on_membership_event(&MembershipEvent::member_left(MemberId::new(10), 1));
        sub.on_membership_event(&MembershipEvent::member_draining(MemberId::new(10), 1));
        sub.on_membership_event(&MembershipEvent::member_drained(MemberId::new(10), 1));

        assert!(calls.lock().unwrap().is_empty());
    }

    // ------------------------------------------------------------------
    // Multi-peer roster sync
    // ------------------------------------------------------------------

    #[test]
    fn sync_roster_establishes_new_peers() {
        let registry = Arc::new(ConnectionRegistry::new());
        let (sub, calls) = make_subscriber(Arc::clone(&registry));

        seed_known_peers(&sub, &[1, 2]);

        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(3));
            s.insert(MemberId::new(4));
            s
        };

        let count = sub.sync_roster(&new_roster);
        assert_eq!(count, 2);

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert!(recorded.contains(&MemberId::new(3)));
        assert!(recorded.contains(&MemberId::new(4)));
        assert!(!recorded.contains(&MemberId::new(1)));

        let known = sub.known_peers.lock().unwrap();
        assert!(known.contains(&MemberId::new(1)));
        assert!(known.contains(&MemberId::new(3)));
        assert!(known.contains(&MemberId::new(4)));
    }

    #[test]
    fn sync_roster_skips_already_connected() {
        let registry = Arc::new(ConnectionRegistry::new());
        let ep1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8000);

        register_peer(&registry, 3, ep1, 1);

        let (sub, calls) = make_subscriber(Arc::clone(&registry));

        seed_known_peers(&sub, &[1]);

        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(3));
            s
        };

        let count = sub.sync_roster(&new_roster);
        assert_eq!(count, 0);
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn sync_roster_empty_diff_is_noop() {
        let registry = Arc::new(ConnectionRegistry::new());
        let (sub, calls) = make_subscriber(Arc::clone(&registry));

        seed_known_peers(&sub, &[1, 2, 3]);

        let same_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s
        };

        let count = sub.sync_roster(&same_roster);
        assert_eq!(count, 0);
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn sync_roster_all_new() {
        let registry = Arc::new(ConnectionRegistry::new());
        let (sub, calls) = make_subscriber(Arc::clone(&registry));

        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(10));
            s.insert(MemberId::new(20));
            s.insert(MemberId::new(30));
            s
        };

        let count = sub.sync_roster(&new_roster);
        assert_eq!(count, 3);
        assert_eq!(calls.lock().unwrap().len(), 3);
    }

    // ------------------------------------------------------------------
    // Idempotency
    // ------------------------------------------------------------------

    #[test]
    fn double_establish_is_idempotent() {
        let registry = Arc::new(ConnectionRegistry::new());
        let (sub, calls) = make_subscriber(Arc::clone(&registry));

        let event = MembershipEvent::member_joined(MemberId::new(7), 1);
        sub.on_membership_event(&event);
        assert_eq!(calls.lock().unwrap().len(), 1);

        let event2 = MembershipEvent::member_joined(MemberId::new(7), 2);
        sub.on_membership_event(&event2);
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn re_joined_after_connection_established_is_noop() {
        let registry = Arc::new(ConnectionRegistry::new());
        let ep = test_endpoint();
        let (sub, calls) = make_subscriber(Arc::clone(&registry));

        let event = MembershipEvent::member_joined(MemberId::new(99), 1);
        sub.on_membership_event(&event);
        assert_eq!(calls.lock().unwrap().len(), 1);

        register_peer(&registry, 99, ep, 1);

        {
            let mut known = sub.known_peers.lock().unwrap();
            known.clear();
        }

        let event2 = MembershipEvent::member_joined(MemberId::new(99), 2);
        sub.on_membership_event(&event2);

        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    // ------------------------------------------------------------------
    // Config
    // ------------------------------------------------------------------

    #[test]
    fn config_defaults_are_reasonable() {
        let cfg = ConnectionEstablishmentConfig::default();
        assert_eq!(cfg.max_attempts, 3);
        assert_eq!(cfg.backoff_ms, 500);
    }

    #[test]
    fn config_custom_values() {
        let cfg = ConnectionEstablishmentConfig::new(5, 1000);
        assert_eq!(cfg.max_attempts, 5);
        assert_eq!(cfg.backoff_ms, 1000);
    }

    #[test]
    fn subscriber_exposes_config() {
        let registry = Arc::new(ConnectionRegistry::new());
        let cfg = ConnectionEstablishmentConfig::new(7, 200);
        let sub = ConnectionEstablishmentSubscriber::new(
            cfg.clone(),
            registry,
            Box::new(|_| {}),
            BTreeSet::new(),
        );
        assert_eq!(sub.config().max_attempts, 7);
        assert_eq!(sub.config().backoff_ms, 200);
    }

    // ------------------------------------------------------------------
    // known_peer_count
    // ------------------------------------------------------------------

    #[test]
    fn known_peer_count_tracks_cache() {
        let registry = Arc::new(ConnectionRegistry::new());
        let (sub, _calls) = make_subscriber(Arc::clone(&registry));

        assert_eq!(sub.known_peer_count(), 0);

        seed_known_peers(&sub, &[1, 2, 3]);
        assert_eq!(sub.known_peer_count(), 3);
    }
}
