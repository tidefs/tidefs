// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Membership session guard: tears down transport sessions to departed peers
//! on epoch advancement.
//!
//! When the membership roster changes (peer drained or failed), the guard
//! subscribes to epoch transition events via [`TransportEpochSubscriber`] and
//! proactively tears down transport sessions to departed peers through
//! [`ConnectionManager`], draining queued outbound messages and freeing
//! transport resources without waiting for idle-timeout expiry.
//!
//! ## Architecture
//!
//! - [`MembershipSessionGuard`] implements [`TransportEpochSubscriber`] and
//!   receives per-peer state deltas on every epoch transition. When a peer
//!   is marked `Drained` or `Failed`, the guard resolves the peer's transport
//!   addresses via [`PeerAddressRegistry`] and enqueues a teardown request.
//! - [`MembershipSessionGuardRuntime`] is a background task that receives
//!   teardown requests and calls [`ConnectionManager::drain`] or
//!   [`ConnectionManager::disconnect`] asynchronously, avoiding blocking
//!   the subscriber dispatch path.
//! - The guard also maintains a current-roster snapshot for downstream
//!   session-establishment gating.
//!
//! ## Integration
//!
//! 1. Create a [`MembershipSessionGuard`] with the connection manager and
//!    peer address registry.
//! 2. Register it with [`EpochEventBridge::register`].
//! 3. Spawn the runtime via [`MembershipSessionGuard::spawn_runtime`] (or
//!    hold the guard and runtime together).
//! 4. On each epoch transition where peers depart, sessions are torn down
//!    automatically.
//!
//! ## Relationship to EpochFence
//!
//! [`EpochFence`](crate::epoch_fence::EpochFence) gates connections at the
//! [`ConnectionRegistry`] level (marking entries `Draining`). This guard
//! complements it by driving the actual transport teardown through
//! [`ConnectionManager`], closing TCP streams and freeing OS resources.
//!
//! ## PeerDeparted error notification
//!
//! When a session is torn down due to peer departure, callers with pending
//! response futures receive [`CorrelationError::PeerDeparted`] so they can
//! retry or route around the departed peer immediately, rather than waiting
//! for a timeout.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::connection::ConnectionManager;
use crate::epoch_bridge::{PeerStateDelta, TransportEpochSubscriber};
use crate::peer_address_registry::PeerAddressRegistry;
use crate::request_response::{CorrelationError, RequestResponseHandle};
use tidefs_membership_epoch::roster_verifier::MembershipRosterVerifier;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// TeardownRequest
// ---------------------------------------------------------------------------

/// A request to tear down sessions to a departed peer.
#[derive(Clone, Debug)]
struct TeardownRequest {
    /// The departed peer's member ID.
    member_id: MemberId,
    /// Why the peer departed.
    reason: TeardownReason,
}

/// Why a peer's sessions are being torn down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TeardownReason {
    /// Peer gracefully drained and departed the cluster.
    Drained,
    /// Peer was detected as failed (unreachable or confirmed dead).
    Failed,
}

impl TeardownReason {
    /// Human-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Drained => "drained",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for TeardownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// TeardownOutcome
// ---------------------------------------------------------------------------

/// Outcome of tearing down sessions for a single departed peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TeardownOutcome {
    /// Sessions were successfully drained.
    Drained {
        member_id: MemberId,
        address_count: usize,
    },
    /// Sessions were force-disconnected (for Failed peers).
    Disconnected {
        member_id: MemberId,
        address_count: usize,
    },
    /// No addresses were registered for this peer.
    NoAddress { member_id: MemberId },
    /// The peer had no active connections to tear down.
    NoConnection { member_id: MemberId },
    /// Teardown was attempted but the connection manager reported an error.
    Error { member_id: MemberId, reason: String },
}

impl TeardownOutcome {
    /// The member ID for this outcome.
    pub fn member_id(&self) -> MemberId {
        match self {
            Self::Drained { member_id, .. }
            | Self::Disconnected { member_id, .. }
            | Self::NoAddress { member_id }
            | Self::NoConnection { member_id }
            | Self::Error { member_id, .. } => *member_id,
        }
    }

    /// Whether the teardown was successful (peer sessions are gone).
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            Self::Drained { .. }
                | Self::Disconnected { .. }
                | Self::NoAddress { .. }
                | Self::NoConnection { .. }
        )
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Drained { .. } => "drained",
            Self::Disconnected { .. } => "disconnected",
            Self::NoAddress { .. } => "no-address",
            Self::NoConnection { .. } => "no-connection",
            Self::Error { .. } => "error",
        }
    }
}

impl std::fmt::Display for TeardownOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Drained {
                member_id,
                address_count,
            } => {
                write!(
                    f,
                    "peer {} drained ({} addresses)",
                    member_id.0, address_count
                )
            }
            Self::Disconnected {
                member_id,
                address_count,
            } => {
                write!(
                    f,
                    "peer {} disconnected ({} addresses)",
                    member_id.0, address_count
                )
            }
            Self::NoAddress { member_id } => {
                write!(f, "peer {} has no registered addresses", member_id.0)
            }
            Self::NoConnection { member_id } => {
                write!(f, "peer {} has no active connections", member_id.0)
            }
            Self::Error { member_id, reason } => {
                write!(f, "peer {} teardown error: {}", member_id.0, reason)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MembershiSessionGuard
// ---------------------------------------------------------------------------

/// Transport subscriber that tears down sessions to departed peers on epoch
/// advancement.
///
/// Implements [`TransportEpochSubscriber`] to receive per-peer state deltas.
/// When a peer is marked `Drained` or `Failed`, the guard resolves the peer's
/// transport addresses and enqueues teardown requests that are processed
/// asynchronously by the spawned runtime task.
///
/// The guard also maintains a snapshot of the current roster for use by
/// session-establishment gating.
pub struct MembershipSessionGuard {
    /// Channel sender for teardown requests.
    teardown_tx: mpsc::UnboundedSender<TeardownRequest>,
    /// The current roster snapshot (sorted, deduplicated).
    current_roster: Mutex<BTreeSet<u64>>,
    /// The last applied epoch number.
    last_epoch: Mutex<u64>,
}

impl MembershipSessionGuard {
    /// Create a new guard and its associated runtime.
    ///
    /// Returns the guard (for registration with [`EpochEventBridge`]) and the
    /// runtime (which must be spawned as a tokio task via
    /// [`MembershipSessionGuardRuntime::run`]).
    pub fn new(
        connection_manager: ConnectionManager,
        address_registry: Arc<PeerAddressRegistry>,
    ) -> (Self, MembershipSessionGuardRuntime) {
        let (tx, rx) = mpsc::unbounded_channel();
        let guard = Self {
            teardown_tx: tx,
            current_roster: Mutex::new(BTreeSet::new()),
            last_epoch: Mutex::new(0),
        };
        let runtime = MembershipSessionGuardRuntime {
            teardown_rx: rx,
            connection_manager,
            address_registry,
            response_handle: None,
        };
        (guard, runtime)
    }

    /// Return a snapshot of the current roster (sorted member IDs).
    pub fn current_roster(&self) -> Vec<u64> {
        self.current_roster
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect()
    }

    /// Check whether a given member ID is in the current roster.
    pub fn is_member(&self, member_id: u64) -> bool {
        self.current_roster.lock().unwrap().contains(&member_id)
    }

    /// Return the last applied epoch number.
    pub fn last_epoch(&self) -> u64 {
        *self.last_epoch.lock().unwrap()
    }

    /// Number of members in the current roster.
    pub fn member_count(&self) -> usize {
        self.current_roster.lock().unwrap().len()
    }

    /// Return a [`MembershipRosterVerifier`] backed by this guard's
    /// current-roster snapshot.
    ///
    /// The returned verifier delegates `is_member` and `current_epoch` to
    /// the guard, enabling integration with [`SessionEstablishment`] for
    /// roster-gated connection admission.
    ///
    /// [`SessionEstablishment`]: crate::session_establishment::SessionEstablishment
    pub fn as_roster_verifier(self: &Arc<Self>) -> GuardRosterVerifier {
        GuardRosterVerifier {
            guard: Arc::clone(self),
        }
    }
}

// ---------------------------------------------------------------------------
// GuardRosterVerifier
// ---------------------------------------------------------------------------

/// A [`MembershipRosterVerifier`] backed by a [`MembershipSessionGuard`]'s
/// current-roster snapshot.
///
/// Delegates `is_member` to the guard's internal [`BTreeSet`] and
/// `current_epoch` to the guard's `last_epoch` counter.
///
/// This enables the session-establishment path to gate new connections
/// against the same roster view that drives teardown, without requiring
/// a separate membership query.
#[derive(Clone)]
pub struct GuardRosterVerifier {
    guard: Arc<MembershipSessionGuard>,
}

impl MembershipRosterVerifier for GuardRosterVerifier {
    fn is_member(&self, peer_id: MemberId) -> bool {
        self.guard.is_member(peer_id.0)
    }

    fn current_epoch(&self) -> u64 {
        self.guard.last_epoch()
    }
}

impl TransportEpochSubscriber for MembershipSessionGuard {
    fn on_epoch_transition(&self, new_epoch: u64, roster: &[u64], deltas: &[PeerStateDelta]) {
        // Update current roster and epoch.
        {
            let mut current = self.current_roster.lock().unwrap();
            current.clear();
            for id in roster {
                current.insert(*id);
            }
        }
        {
            *self.last_epoch.lock().unwrap() = new_epoch;
        }

        // Enqueue teardown for departed peers.
        for delta in deltas {
            match delta {
                PeerStateDelta::Drained { node_id } => {
                    let _ = self.teardown_tx.send(TeardownRequest {
                        member_id: MemberId::new(*node_id),
                        reason: TeardownReason::Drained,
                    });
                }
                PeerStateDelta::Failed { node_id } => {
                    let _ = self.teardown_tx.send(TeardownRequest {
                        member_id: MemberId::new(*node_id),
                        reason: TeardownReason::Failed,
                    });
                }
                // Joined and StateChanged peers don't need teardown.
                PeerStateDelta::Joined { .. } | PeerStateDelta::StateChanged { .. } => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MembershiSessionGuardRuntime
// ---------------------------------------------------------------------------

/// Background task that receives teardown requests and calls
/// [`ConnectionManager`] to drain or disconnect sessions to departed peers.
///
/// Spawn via [`MembershipSessionGuardRuntime::run`] as a tokio task.
/// The runtime reads from an unbounded mpsc channel fed by
/// [`MembershipSessionGuard`] on each epoch transition, resolving peer
/// addresses through [`PeerAddressRegistry`] and driving transport teardown.
pub struct MembershipSessionGuardRuntime<T: Clone + Send + 'static = ()> {
    teardown_rx: mpsc::UnboundedReceiver<TeardownRequest>,
    connection_manager: ConnectionManager,
    address_registry: Arc<PeerAddressRegistry>,
    /// Optional handle to fail pending response futures with
    /// [`CorrelationError::PeerDeparted`] when sessions are torn down.
    response_handle: Option<RequestResponseHandle<T>>,
}

impl<T: Clone + Send + 'static> MembershipSessionGuardRuntime<T> {
    /// Attach a [`RequestResponseHandle`] so pending response futures are
    /// completed with [`CorrelationError::PeerDeparted`] when sessions are
    /// torn down.
    ///
    /// When set, each teardown operation calls
    /// [`RequestResponseHandle::fail_all`] with a `PeerDeparted(member_id)`
    /// error before draining the connection, ensuring callers awaiting
    /// response futures receive immediate failure notification instead of
    /// waiting for a timeout.
    pub fn with_response_handle(mut self, handle: RequestResponseHandle<T>) -> Self {
        self.response_handle = Some(handle);
        self
    }

    /// Run the teardown loop.
    ///
    /// Consumes the runtime and processes teardown requests until the channel
    /// is closed (all [`MembershipSessionGuard`] handles dropped). Returns
    /// all outcomes for observability.
    ///
    /// For `Drained` peers, calls [`ConnectionManager::drain`] (graceful).
    /// For `Failed` peers, calls [`ConnectionManager::disconnect`] (force).
    pub async fn run(mut self) -> Vec<TeardownOutcome> {
        let mut outcomes = Vec::new();

        while let Some(request) = self.teardown_rx.recv().await {
            let result = self.teardown_peer(request.member_id, request.reason).await;
            outcomes.push(result);
        }

        outcomes
    }

    /// Tear down sessions for a single departed peer.
    async fn teardown_peer(&self, member_id: MemberId, reason: TeardownReason) -> TeardownOutcome {
        // Fail all pending response futures for this peer before tearing down
        // connections, so callers receive immediate PeerDeparted notification
        // rather than waiting for a timeout.
        if let Some(ref handle) = self.response_handle {
            let _failed = handle
                .fail_all(CorrelationError::PeerDeparted(member_id.0))
                .await;
        }

        // Resolve addresses from the registry.
        let addresses = match self.address_registry.lookup(member_id) {
            Some(addrs) if !addrs.is_empty() => addrs,
            Some(_) | None => {
                return TeardownOutcome::NoAddress { member_id };
            }
        };

        let mut any_action = false;
        let mut last_error: Option<String> = None;

        for addr in &addresses {
            let socket_addr = match addr.as_socket_addr() {
                Some(sa) => sa,
                None => continue, // skip non-TCP addresses (RDMA, Unix)
            };

            any_action = true;
            let result = match reason {
                TeardownReason::Drained => self.connection_manager.drain(socket_addr).await,
                TeardownReason::Failed => self.connection_manager.disconnect(socket_addr).await,
            };

            if let Err(e) = result {
                last_error = Some(e.to_string());
            }
        }

        if !any_action {
            return TeardownOutcome::NoConnection { member_id };
        }

        if let Some(err) = last_error {
            // Partial action is still useful; log the error.
            TeardownOutcome::Error {
                member_id,
                reason: err,
            }
        } else {
            match reason {
                TeardownReason::Drained => TeardownOutcome::Drained {
                    member_id,
                    address_count: addresses.len(),
                },
                TeardownReason::Failed => TeardownOutcome::Disconnected {
                    member_id,
                    address_count: addresses.len(),
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::TransportAddr;
    use crate::epoch_bridge::PeerStateDelta;

    // Helper to create a TransportAddr for testing.
    fn test_addr(port: u16) -> TransportAddr {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let sa = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        TransportAddr::Tcp(sa)
    }

    fn make_registry(entries: &[(u64, u16)]) -> Arc<PeerAddressRegistry> {
        let registry = Arc::new(PeerAddressRegistry::new());
        for (member_id, port) in entries {
            registry.register(MemberId::new(*member_id), vec![test_addr(*port)]);
        }
        registry
    }

    // --- MembershipSessionGuard: roster tracking ---

    #[test]
    fn guard_initial_state_is_empty() {
        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]);
        let (guard, _runtime) = MembershipSessionGuard::new(cm, registry);

        assert!(guard.current_roster().is_empty());
        assert_eq!(guard.member_count(), 0);
        assert_eq!(guard.last_epoch(), 0);
    }

    #[test]
    fn guard_updates_roster_on_epoch_transition() {
        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]);
        let (guard, _runtime) = MembershipSessionGuard::new(cm, registry);

        guard.on_epoch_transition(
            1,
            &[10, 20, 30],
            &[
                PeerStateDelta::Joined { node_id: 10 },
                PeerStateDelta::Joined { node_id: 20 },
                PeerStateDelta::Joined { node_id: 30 },
            ],
        );

        assert_eq!(guard.current_roster(), vec![10, 20, 30]);
        assert_eq!(guard.member_count(), 3);
        assert_eq!(guard.last_epoch(), 1);
        assert!(guard.is_member(10));
        assert!(guard.is_member(20));
        assert!(guard.is_member(30));
        assert!(!guard.is_member(99));
    }

    #[test]
    fn guard_tracks_roster_removal() {
        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]);
        let (guard, _runtime) = MembershipSessionGuard::new(cm, registry);

        // Initial roster: 10, 20, 30
        guard.on_epoch_transition(
            1,
            &[10, 20, 30],
            &[
                PeerStateDelta::Joined { node_id: 10 },
                PeerStateDelta::Joined { node_id: 20 },
                PeerStateDelta::Joined { node_id: 30 },
            ],
        );

        // Peer 20 drained
        guard.on_epoch_transition(2, &[10, 30], &[PeerStateDelta::Drained { node_id: 20 }]);

        assert_eq!(guard.current_roster(), vec![10, 30]);
        assert_eq!(guard.last_epoch(), 2);
        assert!(!guard.is_member(20));
    }

    #[test]
    fn guard_noop_on_empty_deltas() {
        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]);
        let (guard, _runtime) = MembershipSessionGuard::new(cm, registry);

        guard.on_epoch_transition(1, &[1, 2], &[]);
        assert_eq!(guard.current_roster(), vec![1, 2]);
        assert_eq!(guard.last_epoch(), 1);
    }

    #[test]
    fn guard_joined_delta_no_teardown() {
        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]);
        let (guard, _runtime) = MembershipSessionGuard::new(cm, registry);

        // Joined peers don't trigger teardown; just update roster.
        guard.on_epoch_transition(1, &[5], &[PeerStateDelta::Joined { node_id: 5 }]);
        assert!(guard.is_member(5));
    }

    // --- TeardownOutcome ---

    #[test]
    fn teardown_outcome_labels() {
        assert_eq!(
            TeardownOutcome::Drained {
                member_id: MemberId::new(1),
                address_count: 2
            }
            .label(),
            "drained"
        );
        assert_eq!(
            TeardownOutcome::Disconnected {
                member_id: MemberId::new(2),
                address_count: 1
            }
            .label(),
            "disconnected"
        );
        assert_eq!(
            TeardownOutcome::NoAddress {
                member_id: MemberId::new(3)
            }
            .label(),
            "no-address"
        );
        assert_eq!(
            TeardownOutcome::NoConnection {
                member_id: MemberId::new(4)
            }
            .label(),
            "no-connection"
        );
        assert_eq!(
            TeardownOutcome::Error {
                member_id: MemberId::new(5),
                reason: "err".into()
            }
            .label(),
            "error"
        );
    }

    #[test]
    fn teardown_outcome_is_success() {
        assert!(TeardownOutcome::Drained {
            member_id: MemberId::new(1),
            address_count: 0
        }
        .is_success());
        assert!(TeardownOutcome::Disconnected {
            member_id: MemberId::new(2),
            address_count: 0
        }
        .is_success());
        assert!(TeardownOutcome::NoAddress {
            member_id: MemberId::new(3)
        }
        .is_success());
        assert!(TeardownOutcome::NoConnection {
            member_id: MemberId::new(4)
        }
        .is_success());
        assert!(!TeardownOutcome::Error {
            member_id: MemberId::new(5),
            reason: "e".into()
        }
        .is_success());
    }

    #[test]
    fn teardown_outcome_member_id() {
        let o = TeardownOutcome::Drained {
            member_id: MemberId::new(42),
            address_count: 1,
        };
        assert_eq!(o.member_id(), MemberId::new(42));

        let o = TeardownOutcome::NoAddress {
            member_id: MemberId::new(99),
        };
        assert_eq!(o.member_id(), MemberId::new(99));
    }

    // --- TeardownReason ---

    #[test]
    fn teardown_reason_display() {
        assert_eq!(TeardownReason::Drained.as_str(), "drained");
        assert_eq!(TeardownReason::Failed.as_str(), "failed");
        assert_eq!(format!("{}", TeardownReason::Drained), "drained");
    }

    // --- MembershipSessionGuardRuntime: teardown with no addresses ---

    #[tokio::test]
    async fn runtime_teardown_no_addresses() {
        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]); // empty

        let (guard, runtime) = MembershipSessionGuard::new(cm, registry);

        // Enqueue teardown for a peer with no registered addresses.
        guard.on_epoch_transition(1, &[], &[PeerStateDelta::Drained { node_id: 99 }]);
        drop(guard); // close channel

        let outcomes = runtime.run().await;
        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0],
            TeardownOutcome::NoAddress {
                member_id: MemberId::new(99)
            }
        );
    }

    // --- MembershipSessionGuardRuntime: multiple departures ---

    #[tokio::test]
    async fn runtime_teardown_multiple_peers() {
        let cm = ConnectionManager::new(Default::default());
        // Register addresses for peers 10 and 20 (ports don't matter since
        // drain/disconnect will fail on "connection not found", which is fine
        // for unit-level testing of the dispatch logic).
        let registry = make_registry(&[(10, 9001), (20, 9002)]);

        let (guard, runtime) = MembershipSessionGuard::new(cm, registry);

        guard.on_epoch_transition(
            2,
            &[30],
            &[
                PeerStateDelta::Drained { node_id: 10 },
                PeerStateDelta::Failed { node_id: 20 },
                PeerStateDelta::Joined { node_id: 30 },
            ],
        );
        drop(guard);

        let outcomes = runtime.run().await;
        // Two teardown requests: one Drained (10), one Failed (20)
        assert_eq!(outcomes.len(), 2);

        let member_ids: Vec<u64> = outcomes.iter().map(|o| o.member_id().0).collect();
        assert!(member_ids.contains(&10));
        assert!(member_ids.contains(&20));
    }

    // --- Integration: guard + bridge ---

    #[tokio::test]
    async fn guard_registered_with_bridge_receives_events() {
        use crate::epoch_bridge::EpochEventBridge;
        use std::sync::{Arc, Mutex as StdMutex};

        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[(10, 9003)]);
        let (guard, runtime) = MembershipSessionGuard::new(cm, registry);

        // Register guard with the bridge.
        let mut bridge = EpochEventBridge::new();
        bridge.register(Box::new(guard));

        // Spawn runtime in background.
        let outcomes = Arc::new(StdMutex::new(Vec::new()));
        let outcomes_clone = Arc::clone(&outcomes);
        let rt_handle = tokio::spawn(async move {
            let results = runtime.run().await;
            *outcomes_clone.lock().unwrap() = results;
        });

        // Dispatch an epoch event through the bridge — peer 10 departs.
        bridge.on_epoch_completed(1, &[], &[PeerStateDelta::Drained { node_id: 10 }]);

        // Drop the bridge, which drops the guard (our only reference),
        // closing the teardown channel.
        drop(bridge);

        // Wait for runtime to finish.
        rt_handle.await.unwrap();

        let outcomes = outcomes.lock().unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].member_id(), MemberId::new(10));
    }

    // --- Roster gating ---

    #[test]
    fn guard_is_member_after_update() {
        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]);
        let (guard, _runtime) = MembershipSessionGuard::new(cm, registry);

        guard.on_epoch_transition(1, &[1, 2, 3], &[]);
        assert!(guard.is_member(1));
        assert!(guard.is_member(2));
        assert!(guard.is_member(3));
        assert!(!guard.is_member(4));
    }

    // --- GuardRosterVerifier ---

    #[test]
    fn roster_verifier_delegates_is_member() {
        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]);
        let (guard, _runtime) = MembershipSessionGuard::new(cm, registry);
        let guard = Arc::new(guard);

        guard.on_epoch_transition(1, &[10, 20, 30], &[]);

        let verifier = guard.as_roster_verifier();
        assert!(verifier.is_member(MemberId::new(10)));
        assert!(verifier.is_member(MemberId::new(20)));
        assert!(verifier.is_member(MemberId::new(30)));
        assert!(!verifier.is_member(MemberId::new(99)));
    }

    #[test]
    fn roster_verifier_delegates_current_epoch() {
        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]);
        let (guard, _runtime) = MembershipSessionGuard::new(cm, registry);
        let guard = Arc::new(guard);

        guard.on_epoch_transition(5, &[1], &[]);
        let verifier = guard.as_roster_verifier();
        assert_eq!(verifier.current_epoch(), 5);
    }

    #[test]
    fn roster_verifier_sees_epoch_advancement() {
        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]);
        let (guard, _runtime) = MembershipSessionGuard::new(cm, registry);
        let guard = Arc::new(guard);

        // Initial state: empty
        let v1 = guard.as_roster_verifier();
        assert_eq!(v1.current_epoch(), 0);
        assert!(!v1.is_member(MemberId::new(1)));

        // After epoch transition: peer 1 joins
        guard.on_epoch_transition(1, &[1], &[PeerStateDelta::Joined { node_id: 1 }]);
        let v2 = guard.as_roster_verifier();
        assert_eq!(v2.current_epoch(), 1);
        assert!(v2.is_member(MemberId::new(1)));

        // After another transition: peer 1 departs
        guard.on_epoch_transition(2, &[], &[PeerStateDelta::Drained { node_id: 1 }]);
        let v3 = guard.as_roster_verifier();
        assert_eq!(v3.current_epoch(), 2);
        assert!(!v3.is_member(MemberId::new(1)));
    }

    #[test]
    fn roster_verifier_clone_shares_same_guard() {
        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]);
        let (guard, _runtime) = MembershipSessionGuard::new(cm, registry);
        let guard = Arc::new(guard);

        guard.on_epoch_transition(3, &[42], &[]);

        let v1 = guard.as_roster_verifier();
        let v2 = v1.clone();

        assert_eq!(v1.current_epoch(), v2.current_epoch());
        assert_eq!(
            v1.is_member(MemberId::new(42)),
            v2.is_member(MemberId::new(42))
        );
    }

    #[test]
    fn roster_verifier_empty_roster_rejects_all() {
        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]);
        let (guard, _runtime) = MembershipSessionGuard::new(cm, registry);
        let guard = Arc::new(guard);

        let verifier = guard.as_roster_verifier();
        assert!(!verifier.is_member(MemberId::new(1)));
        assert!(!verifier.is_member(MemberId::new(0)));
        assert_eq!(verifier.current_epoch(), 0);
    }

    // --- SessionEstablishment integration (unit) ---

    #[test]
    fn session_establishment_rejects_non_member() {
        use crate::codec::MessageCodec;
        use crate::session_establishment::SessionEstablishment;

        let cm = ConnectionManager::new(Default::default());
        let registry = make_registry(&[]);
        let (guard, _runtime) = MembershipSessionGuard::new(cm, registry);
        let guard = Arc::new(guard);

        // Roster: peer 10, epoch 5
        guard.on_epoch_transition(5, &[10], &[PeerStateDelta::Joined { node_id: 10 }]);

        let codec = MessageCodec::with_max_frame_size(1024);
        let establishment = SessionEstablishment::new(Box::new(guard.as_roster_verifier()), codec);

        // Peer 10 is a member — establish_responder should proceed past
        // the roster check (it will fail on I/O since there's no real
        // connection, but the roster check passes).
        let result =
            establishment.establish_responder(10, &mut |_data| Err("no io".into()), &mut || {
                Err("no io".into())
            });
        // The roster check passed; the I/O error is expected.
        assert!(matches!(
            result,
            Err(crate::session_establishment::SessionEstablishmentError::Io(
                _
            ))
        ));

        // Peer 99 is NOT a member — should get NotAMember.
        let result =
            establishment.establish_responder(99, &mut |_data| Ok(()), &mut || Err("no io".into()));
        assert!(matches!(
            result,
            Err(
                crate::session_establishment::SessionEstablishmentError::NotAMember { peer_id: 99 }
            )
        ));
    }
}
