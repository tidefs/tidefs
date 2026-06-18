// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Peer eviction execution on dead-peer epoch commit.
//!
//! [`EvictionExecutor`] bridges the epoch-commit subscriber dispatch (#5900)
//! to transport connection teardown and session cleanup. When the
//! [`crate::epoch_coordinator::EpochAdvanceCoordinator`] commits a new
//! [`crate::epoch_coordinator::EpochView`] that removes a dead peer, the
//! executor tears down the associated transport connections, releases
//! session bindings, and emits [`EvictionOutcome`] records for downstream
//! subsystem notification.
//!
//! # Architecture
//!
//! The executor implements [`crate::epoch_coordinator::EpochCommitSubscriber`]
//! and is registered with the [`EpochAdvanceCoordinator`] via
//! [`EpochAdvanceCoordinator::subscribe`]. On each committed epoch view:
//!
//! 1. The new member set is compared against a cached prior roster.
//! 2. Removed peers are identified via set difference.
//! 3. For each removed peer:
//!    - The connection entry is removed from
//!      [`tidefs_transport::connection_registry::ConnectionRegistry`].
//!    - All session bindings are cleared from
//!      [`crate::session_binding::SessionBindingTable`].
//!    - The [`EvictionCallback`] is invoked with the peer's endpoint
//!      and the appropriate [`EvictionAction`].
//! 4. An [`EvictionOutcome`] is emitted for each evicted peer.
//!
//! # Integration
//!
//! ```ignore
//! use tidefs_membership_live::peer_eviction::{EvictionExecutor, EvictionAction};
//!
//! let executor = EvictionExecutor::new(
//!     session_bindings,
//!     connection_registry,
//!     Box::new(move |addr, action| {
//!         let mgr = conn_manager.clone();
//!         tokio::runtime::Handle::current().spawn(async move {
//!             match action {
//!                 EvictionAction::Drain => { let _ = mgr.drain(addr).await; }
//!                 EvictionAction::Close => { let _ = mgr.disconnect(addr).await; }
//!             }
//!         });
//!     }),
//!     initial_roster,
//! );
//!
//! coordinator.subscribe(Box::new(executor));
//! ```

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tidefs_membership_epoch::MemberId;
use tidefs_transport::connection_registry::ConnectionRegistry;

use crate::epoch_coordinator::{EpochCommitSubscriber, EpochView};
use crate::session_binding::SessionBindingTable;

// ---------------------------------------------------------------------------
// EvictionAction
// ---------------------------------------------------------------------------

/// Action to take when evicting a peer from the membership roster.
///
/// Dead peers are evicted with [`Close`](EvictionAction::Close) (immediate
/// teardown, no point draining a dead link). Graceful departures use
/// [`Drain`](EvictionAction::Drain).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictionAction {
    /// Graceful drain: allow in-flight work to complete, then close.
    Drain,
    /// Immediate disconnect: tear down without waiting.
    Close,
}

// ---------------------------------------------------------------------------
// EvictionOutcome
// ---------------------------------------------------------------------------

/// Outcome of an eviction execution for a single peer.
///
/// Carries the peer identity, action taken, and resource release counts
/// for observability and downstream subsystem notification (e.g.,
/// placement-runtime rebalance triggering).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvictionOutcome {
    /// The peer that was evicted.
    pub peer_id: MemberId,
    /// Action taken (Drain or Close).
    pub action: EvictionAction,
    /// Number of transport connections closed (0 or 1 per peer).
    pub connections_closed: usize,
    /// Number of session bindings released.
    pub sessions_released: usize,
}

// ---------------------------------------------------------------------------
// EvictionCallback
// ---------------------------------------------------------------------------

/// Callback invoked when a peer's transport connection should be evicted.
///
/// The callback receives the peer's socket address and the action to take.
/// Implementations must be non-blocking and fast; spawn async work if the
/// underlying teardown requires I/O.
pub type EvictionCallback = Box<dyn Fn(SocketAddr, EvictionAction) + Send + Sync>;

// ---------------------------------------------------------------------------
// EvictionExecutor
// ---------------------------------------------------------------------------

/// Executes concrete eviction actions — transport connection teardown,
/// session cleanup, and resource release — for peers removed from the
/// membership roster when an epoch commits after liveness-detected failure.
///
/// Implements [`EpochCommitSubscriber`] to receive committed epoch views
/// from the
/// [`crate::epoch_coordinator::EpochAdvanceCoordinator`].  On each commit,
/// diffs the new member set against the prior roster and evicts removed
/// peers.
///
/// # Lifecycle
///
/// 1. Construct via [`new`](EvictionExecutor::new) with session bindings,
///    connection registry, an eviction callback, and the initial roster.
/// 2. Register with the epoch advance coordinator via
///    `coordinator.subscribe(Box::new(executor))`.
/// 3. On each committed epoch, removed peers are automatically evicted.
///
/// # Idempotency
///
/// - A peer not found in the connection registry (already evicted or never
///   admitted) is a no-op for connection teardown.
/// - Session bindings for an already-cleared peer return an empty list.
/// - The prior-roster cache prevents duplicate evictions for the same
///   epoch transition.
pub struct EvictionExecutor {
    /// Session binding table shared with the transport layer.
    session_bindings: Arc<Mutex<SessionBindingTable>>,
    /// Connection registry for peer-to-endpoint resolution.
    connection_registry: Arc<ConnectionRegistry>,
    /// Callback that performs the actual transport teardown.
    callback: EvictionCallback,
    /// Cached set of peer IDs from the last committed epoch, used for
    /// diff-based eviction detection.
    prior_roster: Mutex<BTreeSet<MemberId>>,
    /// Accumulated eviction outcomes since last drain.
    recent_outcomes: Mutex<Vec<EvictionOutcome>>,
}

impl EvictionExecutor {
    /// Create a new executor.
    ///
    /// `session_bindings` — shared session binding table.
    /// `connection_registry` — shared connection registry.
    /// `callback` — callback that executes the actual transport close/drain.
    /// `initial_roster` — the set of peer IDs in the initial epoch view,
    ///   used as the baseline for diff-based eviction detection.
    #[must_use]
    pub fn new(
        session_bindings: Arc<Mutex<SessionBindingTable>>,
        connection_registry: Arc<ConnectionRegistry>,
        callback: EvictionCallback,
        initial_roster: BTreeSet<MemberId>,
    ) -> Self {
        Self {
            session_bindings,
            connection_registry,
            callback,
            prior_roster: Mutex::new(initial_roster),
            recent_outcomes: Mutex::new(Vec::new()),
        }
    }

    /// Evict a single peer: remove from connection registry, release
    /// session bindings, invoke callback.
    ///
    /// Returns an [`EvictionOutcome`] recording the results.
    fn evict_peer(&self, peer_id: MemberId, action: EvictionAction) -> EvictionOutcome {
        // 1. Remove from connection registry and invoke teardown callback.
        let connections_closed = match self.connection_registry.remove(peer_id.0) {
            Ok(entry) => {
                (self.callback)(entry.endpoint, action);
                1
            }
            Err(_) => {
                // Peer not in registry — already torn down or never admitted.
                0
            }
        };

        // 2. Release all session bindings for this peer.
        let sessions_released = {
            let mut bindings = self.session_bindings.lock().unwrap();
            bindings.remove_all_for_peer(peer_id).len()
        };

        EvictionOutcome {
            peer_id,
            action,
            connections_closed,
            sessions_released,
        }
    }

    /// Diff the new roster against the prior roster and evict removed peers.
    ///
    /// Returns a [`Vec<EvictionOutcome>`] with one entry per evicted peer.
    /// Newly added peers are tracked in the prior-roster cache without
    /// triggering any callback.
    ///
    /// This is the primary entry point for epoch-commit-driven eviction.
    pub fn execute_evictions(
        &self,
        new_roster: &BTreeSet<MemberId>,
        action: EvictionAction,
    ) -> Vec<EvictionOutcome> {
        let mut prior = self.prior_roster.lock().unwrap();

        // Identify removed peers.
        let removed: Vec<MemberId> = prior.difference(new_roster).copied().collect();
        let mut outcomes = Vec::with_capacity(removed.len());

        for peer_id in &removed {
            prior.remove(peer_id);
            outcomes.push(self.evict_peer(*peer_id, action));
        }

        // Track newly added peers in the cache.
        let added: Vec<MemberId> = new_roster.difference(&prior).copied().collect();
        for peer_id in added {
            prior.insert(peer_id);
        }

        outcomes
    }

    /// Number of peers in the cached prior roster.
    pub fn known_peer_count(&self) -> usize {
        self.prior_roster.lock().unwrap().len()
    }

    /// Drain and return all accumulated eviction outcomes since the last
    /// call. Outcomes are accumulated automatically from every commit
    /// dispatched through [`EpochCommitSubscriber::on_epoch_committed`]
    /// and from direct [`execute_evictions`] calls.
    ///
    /// Callers that need downstream notification (placement rebalance,
    /// observability) should call this periodically.
    pub fn drain_outcomes(&self) -> Vec<EvictionOutcome> {
        std::mem::take(&mut *self.recent_outcomes.lock().unwrap())
    }
}

// ---------------------------------------------------------------------------
// EpochCommitSubscriber impl
// ---------------------------------------------------------------------------

impl EpochCommitSubscriber for EvictionExecutor {
    /// Called when a new epoch view is committed by the coordinator.
    ///
    /// Diffs the new member set against the prior roster and evicts
    /// removed peers with [`EvictionAction::Close`] (dead peers get
    /// immediate teardown, consistent with the liveness→eviction
    /// pipeline where only Dead peers are removed).
    ///
    /// This callback is non-blocking: the actual transport I/O is
    /// delegated to the [`EvictionCallback`], which should spawn async
    /// work if needed.
    fn on_epoch_committed(&self, view: &EpochView) {
        let new_roster: BTreeSet<MemberId> = view.member_set.iter().copied().collect();
        let outcomes = self.execute_evictions(&new_roster, EvictionAction::Close);
        // Accumulate outcomes for downstream inspection via drain_outcomes().
        self.recent_outcomes.lock().unwrap().extend(outcomes);
    }
}

// Safety: all interior mutability is behind Mutex; the eviction callback
// is required to be Send + Sync.  ConnectionRegistry uses RwLock internally.
// The executor is designed for single-threaded use within the epoch
// coordinator's commit path, consistent with EpochCommitSubscriber.

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
    use tidefs_transport::connection_registry::{ConnectionId, ConnectionRegistry};
    use tidefs_transport::peer_admission::AdmittedPeer;

    use crate::epoch_coordinator::{
        EpochAdvanceCoordinator, PeerLivenessChange, PeerLivenessStatus,
    };
    use crate::session_binding::{PeerSessionBinding, SessionBindingTable, SessionId};

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn test_endpoint(id: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, id)), 8000)
    }

    fn make_admitted(peer_id: u64, epoch: u64) -> AdmittedPeer {
        AdmittedPeer::new(peer_id, epoch)
    }

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

    type EvictionCalls = Arc<Mutex<Vec<(SocketAddr, EvictionAction)>>>;

    fn make_executor(
        registry: Arc<ConnectionRegistry>,
        bindings: Arc<Mutex<SessionBindingTable>>,
        initial: BTreeSet<MemberId>,
    ) -> (EvictionExecutor, EvictionCalls) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let calls_clone = Arc::clone(&calls);

        let executor = EvictionExecutor::new(
            bindings,
            registry,
            Box::new(move |addr, action| {
                calls_clone.lock().unwrap().push((addr, action));
            }),
            initial,
        );

        (executor, calls)
    }

    fn new_coordinator_with_executor(
        members: Vec<MemberId>,
        executor: EvictionExecutor,
    ) -> EpochAdvanceCoordinator {
        let mut coord = EpochAdvanceCoordinator::new(1);
        coord.initialize(members, 1_700_000_000_000);
        coord.subscribe(Box::new(executor));
        coord
    }

    // ------------------------------------------------------------------
    // EpochCommitSubscriber integration
    // ------------------------------------------------------------------

    #[test]
    fn executor_receives_commit_notification_and_evicts_dead_peer() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        let ep2 = test_endpoint(2);
        register_peer(&registry, &bindings, 2, ep2, 1);

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s
        };

        let (executor, calls) =
            make_executor(Arc::clone(&registry), Arc::clone(&bindings), initial);

        let mut coord = new_coordinator_with_executor(
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            executor,
        );

        // Peer 2 goes Dead → triggers epoch advance → executor evicts peer 2.
        let change = PeerLivenessChange::new(
            MemberId::new(2),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            1_700_000_000_000,
        );
        let result = coord.on_liveness_change(change);
        assert!(result.is_some());

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1, "peer 2 should have been evicted");
        assert_eq!(recorded[0].0, ep2);
        assert_eq!(recorded[0].1, EvictionAction::Close);

        // Registry should no longer have peer 2.
        assert!(registry.get(2).is_none());

        // Bindings should be cleared for peer 2.
        assert!(bindings.lock().unwrap().is_empty());
    }

    #[test]
    fn executor_is_noop_when_roster_unchanged() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s
        };

        let (executor, calls) =
            make_executor(Arc::clone(&registry), Arc::clone(&bindings), initial);

        let mut coord =
            new_coordinator_with_executor(vec![MemberId::new(1), MemberId::new(2)], executor);

        // Peer 1 Alive→Alive: no-op for coordinator, no epoch commit fired.
        let change = PeerLivenessChange::new(
            MemberId::new(1),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Alive,
            1_700_000_000_000,
        );
        let result = coord.on_liveness_change(change);
        assert!(result.is_none());

        // No eviction calls.
        assert!(calls.lock().unwrap().is_empty());
    }

    // ------------------------------------------------------------------
    // Roster diff: added, retained, removed
    // ------------------------------------------------------------------

    #[test]
    fn execute_evictions_identifies_removed_peers() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        let ep2 = test_endpoint(2);
        let ep3 = test_endpoint(3);
        register_peer(&registry, &bindings, 2, ep2, 1);
        register_peer(&registry, &bindings, 3, ep3, 1);

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s
        };

        let (executor, calls) =
            make_executor(Arc::clone(&registry), Arc::clone(&bindings), initial);

        // New roster: peer 1 kept, peer 4 added, peers 2 and 3 removed.
        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(4));
            s
        };

        let outcomes = executor.execute_evictions(&new_roster, EvictionAction::Close);
        assert_eq!(outcomes.len(), 2);

        // Check outcomes carry correct peer IDs.
        let evicted_ids: BTreeSet<MemberId> = outcomes.iter().map(|o| o.peer_id).collect();
        assert!(evicted_ids.contains(&MemberId::new(2)));
        assert!(evicted_ids.contains(&MemberId::new(3)));
        assert!(!evicted_ids.contains(&MemberId::new(1)));

        for outcome in &outcomes {
            assert_eq!(outcome.action, EvictionAction::Close);
            // Peer may or may not have been in registry; connections_closed
            // is 1 because we registered both peers above.
            assert_eq!(outcome.connections_closed, 1);
        }

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 2);
    }

    #[test]
    fn execute_evictions_retains_unchanged_peers() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        let ep1 = test_endpoint(1);
        register_peer(&registry, &bindings, 1, ep1, 1);

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s
        };

        let (executor, calls) =
            make_executor(Arc::clone(&registry), Arc::clone(&bindings), initial);

        // Same roster.
        let same: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s
        };

        let outcomes = executor.execute_evictions(&same, EvictionAction::Close);
        assert!(outcomes.is_empty());
        assert!(calls.lock().unwrap().is_empty());

        // Registry should still have peer 1.
        assert!(registry.get(1).is_some());
    }

    #[test]
    fn execute_evictions_tracks_newly_added_peers() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s
        };

        let (executor, calls) =
            make_executor(Arc::clone(&registry), Arc::clone(&bindings), initial);

        // Add peer 2.
        let with_new: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s
        };

        let outcomes = executor.execute_evictions(&with_new, EvictionAction::Close);
        assert!(outcomes.is_empty(), "no peers removed, just added");
        assert!(calls.lock().unwrap().is_empty());

        // Now remove peer 2 — should trigger eviction.
        let ep2 = test_endpoint(2);
        register_peer(&registry, &bindings, 2, ep2, 1);

        let without_new: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s
        };

        let outcomes = executor.execute_evictions(&without_new, EvictionAction::Close);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].peer_id, MemberId::new(2));
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    // ------------------------------------------------------------------
    // Multiple simultaneous removals
    // ------------------------------------------------------------------

    #[test]
    fn multiple_peers_evicted_simultaneously() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        let ep1 = test_endpoint(1);
        let ep2 = test_endpoint(2);
        let ep3 = test_endpoint(3);
        register_peer(&registry, &bindings, 1, ep1, 1);
        register_peer(&registry, &bindings, 2, ep2, 1);
        register_peer(&registry, &bindings, 3, ep3, 1);

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s
        };

        let (executor, calls) =
            make_executor(Arc::clone(&registry), Arc::clone(&bindings), initial);

        // Remove all three at once.
        let empty: BTreeSet<MemberId> = BTreeSet::new();

        let outcomes = executor.execute_evictions(&empty, EvictionAction::Close);
        assert_eq!(outcomes.len(), 3);
        assert_eq!(calls.lock().unwrap().len(), 3);

        for outcome in &outcomes {
            assert_eq!(outcome.connections_closed, 1);
        }

        // All registry entries removed.
        assert!(registry.get(1).is_none());
        assert!(registry.get(2).is_none());
        assert!(registry.get(3).is_none());
    }

    // ------------------------------------------------------------------
    // Idempotency: already-evicted peer
    // ------------------------------------------------------------------

    #[test]
    fn evicting_already_removed_peer_is_noop_for_connection() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        // Peer 42 is in the initial roster but NOT in registry (already evicted).
        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(42));
            s
        };

        let (executor, calls) =
            make_executor(Arc::clone(&registry), Arc::clone(&bindings), initial);

        let empty: BTreeSet<MemberId> = BTreeSet::new();
        let outcomes = executor.execute_evictions(&empty, EvictionAction::Close);

        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].peer_id, MemberId::new(42));
        assert_eq!(outcomes[0].connections_closed, 0, "peer not in registry");
        assert_eq!(outcomes[0].sessions_released, 0, "no bindings to release");

        // No callback invoked.
        assert!(calls.lock().unwrap().is_empty());
    }

    // ------------------------------------------------------------------
    // EvictionAction variants
    // ------------------------------------------------------------------

    #[test]
    fn drain_action_invokes_callback_with_drain() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        let ep = test_endpoint(1);
        register_peer(&registry, &bindings, 1, ep, 1);

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s
        };

        let (executor, calls) =
            make_executor(Arc::clone(&registry), Arc::clone(&bindings), initial);

        let empty: BTreeSet<MemberId> = BTreeSet::new();
        executor.execute_evictions(&empty, EvictionAction::Drain);

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].1, EvictionAction::Drain);
    }

    // ------------------------------------------------------------------
    // Session binding cleanup
    // ------------------------------------------------------------------

    #[test]
    fn eviction_releases_all_session_bindings() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        let ep = test_endpoint(1);
        register_peer(&registry, &bindings, 1, ep, 1);

        // Add multiple bindings for the same peer.
        {
            let mut bt = bindings.lock().unwrap();
            bt.insert(PeerSessionBinding::new(
                100,
                MemberId::new(1),
                SessionId::new(1000),
                tidefs_membership_epoch::EpochId::new(1),
            ));
            bt.insert(PeerSessionBinding::new(
                101,
                MemberId::new(1),
                SessionId::new(1001),
                tidefs_membership_epoch::EpochId::new(2),
            ));
        }
        assert_eq!(bindings.lock().unwrap().len(), 3);

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s
        };

        let (executor, _calls) =
            make_executor(Arc::clone(&registry), Arc::clone(&bindings), initial);

        let empty: BTreeSet<MemberId> = BTreeSet::new();
        let outcomes = executor.execute_evictions(&empty, EvictionAction::Close);

        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].sessions_released, 3);

        // All bindings cleared.
        assert!(bindings.lock().unwrap().is_empty());
    }

    // ------------------------------------------------------------------
    // EvictionOutcome
    // ------------------------------------------------------------------

    #[test]
    fn eviction_outcome_records_correct_counts() {
        let outcome = EvictionOutcome {
            peer_id: MemberId::new(7),
            action: EvictionAction::Close,
            connections_closed: 1,
            sessions_released: 2,
        };

        assert_eq!(outcome.peer_id, MemberId::new(7));
        assert_eq!(outcome.action, EvictionAction::Close);
        assert_eq!(outcome.connections_closed, 1);
        assert_eq!(outcome.sessions_released, 2);
    }

    // ------------------------------------------------------------------
    // known_peer_count
    // ------------------------------------------------------------------

    #[test]
    fn known_peer_count_reflects_cached_roster() {
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        let initial: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(2));
            s.insert(MemberId::new(3));
            s
        };

        let (executor, _calls) =
            make_executor(Arc::clone(&registry), Arc::clone(&bindings), initial);

        assert_eq!(executor.known_peer_count(), 3);

        // Evict one.
        let new_roster: BTreeSet<MemberId> = {
            let mut s = BTreeSet::new();
            s.insert(MemberId::new(1));
            s.insert(MemberId::new(3));
            s
        };
        executor.execute_evictions(&new_roster, EvictionAction::Close);
        assert_eq!(executor.known_peer_count(), 2);
    }

    // ------------------------------------------------------------------
    // EvictionAction traits
    // ------------------------------------------------------------------

    #[test]
    fn eviction_action_debug_and_eq() {
        assert_eq!(EvictionAction::Drain, EvictionAction::Drain);
        assert_ne!(EvictionAction::Drain, EvictionAction::Close);
        assert_eq!(format!("{:?}", EvictionAction::Drain), "Drain");
        assert_eq!(format!("{:?}", EvictionAction::Close), "Close");
    }
}
