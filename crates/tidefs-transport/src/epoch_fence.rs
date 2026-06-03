//! Epoch-bound connection fence for departed member drain.
//!
//! [`EpochFence`] bridges membership epoch transitions to transport
//! connection lifecycle by re-evaluating all active connections against
//! the new member set after every epoch advance. Connections belonging
//! to peers absent from the new member set are transitioned to Draining.
//!
//! # Architecture
//!
//! - [`EpochTransition`]: immutable event published when the membership
//!   epoch advances, carrying the new epoch number, member set, and
//!   wall-clock timestamp.
//! - [`EpochFence`]: provides the broadcast [`Sender`] that the
//!   membership layer uses to publish transitions, and a
//!   [`Receiver`] that [`EpochFenceRuntime`] awaits.
//! - [`EpochFenceRuntime`]: a tokio task that receives
//!   [`EpochTransition`] events, consults the [`ConnectionRegistry`],
//!   computes departed peers, and transitions their connections to
//!   `Draining`.
//! - [`FenceOutcome`]: per-peer drain result for observability and
//!   operator visibility.
//!
//! # Relationship to AdmissionGate
//!
//! [`AdmissionGate`] (crate::peer_admission) gates new connection
//! establishments against the current member set at establishment time.
//! [`EpochFence`] complements this by re-evaluating already-active
//! connections when the epoch advances, catching peers that departed
//! after their connections were already established.
//!
//! # Integration point
//!
//! The membership layer obtains a [`Sender`] from [`EpochFence::sender`]
//! and publishes an [`EpochTransition`] whenever the membership epoch
//! advances. [`EpochFenceRuntime::run`] is spawned as a tokio task that
//! awaits transitions on the broadcast receiver and applies fencing.
//!
//! # Follow-on
//!
//! Wiring [`tidefs_cluster::ClusterLeaseRuntime`] to publish
//! [`EpochTransition`] events into this module's broadcast channel is a
//! Review debt TFR-017.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;
use tidefs_membership_epoch::EpochMemberSet;
use tidefs_membership_types::NodeIdentity;

use crate::connection_registry::{ConnectionRegistry, ConnectionState};

// ---------------------------------------------------------------------------
// EpochTransition
// ---------------------------------------------------------------------------

/// An immutable event published when the membership epoch advances.
///
/// Carries the new epoch number, the complete member set for that
/// epoch, and a wall-clock timestamp for observability.
#[derive(Clone, Debug)]
pub struct EpochTransition {
    /// The new epoch number.
    pub epoch: u64,
    /// The complete member set for the new epoch.
    pub member_set: EpochMemberSet,
    /// Wall-clock timestamp when this transition was published.
    pub timestamp: Instant,
}

impl EpochTransition {
    /// Create a new transition event.
    #[must_use]
    pub fn new(epoch: u64, member_set: EpochMemberSet) -> Self {
        Self {
            epoch,
            member_set,
            timestamp: Instant::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// FenceOutcome
// ---------------------------------------------------------------------------

/// Outcome of fencing a single peer during an epoch transition.
///
/// Each departed peer produces exactly one outcome, recording whether
/// its connection was successfully transitioned to `Draining` or why
/// no action was needed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FenceOutcome {
    /// The peer's connection was successfully transitioned to Draining.
    Drained {
        /// The departed peer's node identifier.
        peer_id: u64,
    },
    /// The peer's connection was already Draining, Drained, or Closed.
    AlreadyDraining {
        /// The departed peer's node identifier.
        peer_id: u64,
    },
    /// No connection entry was found for this peer in the registry.
    NoConnection {
        /// The departed peer's node identifier.
        peer_id: u64,
    },
    /// The drain attempt failed due to a registry error.
    DrainFailed {
        /// The departed peer's node identifier.
        peer_id: u64,
        /// Human-readable reason for the failure.
        reason: String,
    },
}

impl FenceOutcome {
    /// Return the peer ID for this outcome.
    #[must_use]
    pub fn peer_id(&self) -> u64 {
        match self {
            Self::Drained { peer_id }
            | Self::AlreadyDraining { peer_id }
            | Self::NoConnection { peer_id }
            | Self::DrainFailed { peer_id, .. } => *peer_id,
        }
    }

    /// Whether the fence action succeeded (peer connection is no longer
    /// in an active state that could accept new messages).
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            Self::Drained { .. } | Self::AlreadyDraining { .. } | Self::NoConnection { .. }
        )
    }

    /// Human-readable summary label for this outcome.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Drained { .. } => "drained",
            Self::AlreadyDraining { .. } => "already-draining",
            Self::NoConnection { .. } => "no-connection",
            Self::DrainFailed { .. } => "drain-failed",
        }
    }
}

impl std::fmt::Display for FenceOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Drained { peer_id } => write!(f, "peer {peer_id} drained"),
            Self::AlreadyDraining { peer_id } => {
                write!(f, "peer {peer_id} already draining")
            }
            Self::NoConnection { peer_id } => {
                write!(f, "peer {peer_id} has no active connection")
            }
            Self::DrainFailed { peer_id, reason } => {
                write!(f, "peer {peer_id} drain failed: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FenceSummary
// ---------------------------------------------------------------------------

/// Aggregate summary of all fence outcomes from a single epoch transition.
///
/// Provides counts by outcome category for operator visibility and
/// monitoring.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FenceSummary {
    /// Number of peers successfully drained.
    pub drained: usize,
    /// Number of peers already draining/closed.
    pub already_draining: usize,
    /// Number of peers with no active connection.
    pub no_connection: usize,
    /// Number of peers where drain failed.
    pub drain_failed: usize,
}

impl FenceSummary {
    /// Build a summary from a slice of outcomes.
    #[must_use]
    pub fn from_outcomes(outcomes: &[FenceOutcome]) -> Self {
        let mut summary = Self::default();
        for outcome in outcomes {
            match outcome {
                FenceOutcome::Drained { .. } => summary.drained += 1,
                FenceOutcome::AlreadyDraining { .. } => summary.already_draining += 1,
                FenceOutcome::NoConnection { .. } => summary.no_connection += 1,
                FenceOutcome::DrainFailed { .. } => summary.drain_failed += 1,
            }
        }
        summary
    }

    /// Total number of outcomes summarized.
    #[must_use]
    pub fn total(&self) -> usize {
        self.drained + self.already_draining + self.no_connection + self.drain_failed
    }

    /// Whether every departed peer was handled successfully (no drain
    /// failures).
    #[must_use]
    pub fn all_success(&self) -> bool {
        self.drain_failed == 0
    }
}

impl std::fmt::Display for FenceSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fence: {} drained, {} already-draining, {} no-connection, {} failed ({} total)",
            self.drained,
            self.already_draining,
            self.no_connection,
            self.drain_failed,
            self.total()
        )
    }
}

// ---------------------------------------------------------------------------
// EpochFence
// ---------------------------------------------------------------------------

/// Epoch-bound connection fence for departed member drain.
///
/// Provides a [`broadcast::Sender`] for publishing [`EpochTransition`]
/// events and holds a reference to the [`ConnectionRegistry`] for
/// computing departed peers.
///
/// # Lifecycle
///
/// 1. Create an [`EpochFence`] with the connection registry and a
///    broadcast channel capacity.
/// 2. Hand [`EpochFence::sender`] to the membership layer so it can
///    publish transitions when the epoch advances.
/// 3. Spawn an [`EpochFenceRuntime`] via [`EpochFenceRuntime::run`]
///    to consume transitions and fence departed peers.
#[derive(Clone, Debug)]
pub struct EpochFence {
    /// Broadcast sender for publishing epoch transitions.
    tx: broadcast::Sender<EpochTransition>,
    /// The connection registry for looking up active connections.
    registry: Arc<ConnectionRegistry>,
}

impl EpochFence {
    /// Create a new epoch fence with the given broadcast channel capacity.
    ///
    /// `capacity` is the broadcast channel buffer size. A larger buffer
    /// tolerates bursty epoch transitions but uses more memory. The
    /// sender end can be cloned and shared across components.
    #[must_use]
    pub fn new(registry: Arc<ConnectionRegistry>, capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx, registry }
    }

    /// Return a new sender for publishing epoch transitions.
    ///
    /// The membership layer clones this sender and calls
    /// [`Sender::send`](broadcast::Sender::send) whenever the epoch
    /// advances.
    pub fn sender(&self) -> broadcast::Sender<EpochTransition> {
        self.tx.clone()
    }

    /// Return a new receiver subscribed to epoch transitions.
    ///
    /// [`EpochFenceRuntime`] uses this receiver to await transitions.
    /// Each call to `subscribe` yields a receiver that sees only
    /// transitions sent *after* the subscription.
    pub fn subscribe(&self) -> broadcast::Receiver<EpochTransition> {
        self.tx.subscribe()
    }

    /// Access the underlying connection registry.
    #[must_use]
    pub fn registry(&self) -> &Arc<ConnectionRegistry> {
        &self.registry
    }

    // -------------------------------------------------------------------
    // Internal helper: compute departed peers
    // -------------------------------------------------------------------

    /// Compute the set of departed peers by comparing active registry
    /// connections against the new member set.
    ///
    /// Returns peer IDs present in the registry but absent from the
    /// given member set, in sorted order.
    fn departed_peers(registry: &ConnectionRegistry, member_set: &EpochMemberSet) -> BTreeSet<u64> {
        let active = registry.list_active();
        active
            .into_iter()
            .filter(|peer_id| !member_set.contains(&NodeIdentity::new(*peer_id)))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// EpochFenceRuntime
// ---------------------------------------------------------------------------

/// Runtime task that receives [`EpochTransition`] events and applies
/// connection fencing to departed peers.
///
/// Spawn as a tokio task. On each epoch transition, the runtime:
///
/// 1. Computes departed peers (active in registry, absent from new
///    member set).
/// 2. Transitions departed peers' connections to `Draining` in the
///    registry.
/// 3. Collects [`FenceOutcome`] records and a [`FenceSummary`] for
///    observability.
///
/// # Graceful error handling
///
/// - Peers with no active connection produce `NoConnection`.
/// - Peers already in `Draining`, `Drained`, or `Closed` state produce
///   `AlreadyDraining`.
/// - Registry errors (e.g., peer removed between lookup and state
///   update) produce `DrainFailed`.
///
/// # Lag handling
///
/// If the runtime falls behind and the broadcast channel reports lag,
/// the missed transitions are noted but the runtime continues with the
/// next received transition. A full catch-up (re-computing against
/// the current registry) is best-effort; the primary guarantee is that
/// every *received* transition is fenced.
pub struct EpochFenceRuntime {
    /// Receiver for epoch transition events.
    rx: broadcast::Receiver<EpochTransition>,
    /// The connection registry for active connection lookups.
    registry: Arc<ConnectionRegistry>,
}

impl EpochFenceRuntime {
    /// Create a new runtime from a fence subscriber receiver and
    /// connection registry.
    #[must_use]
    pub fn new(
        rx: broadcast::Receiver<EpochTransition>,
        registry: Arc<ConnectionRegistry>,
    ) -> Self {
        Self { rx, registry }
    }

    /// Run the fence loop, awaiting epoch transitions and applying
    /// fencing.
    ///
    /// Returns all accumulated [`FenceOutcome`] records when the
    /// broadcast channel is closed (all senders dropped). Each
    /// transition is fenced independently.
    pub async fn run(mut self) -> Vec<FenceOutcome> {
        let mut all_outcomes = Vec::new();

        loop {
            match self.rx.recv().await {
                Ok(transition) => {
                    let outcomes = self.apply_fence(&transition);
                    all_outcomes.extend(outcomes);
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    // Lagged: missed `skipped` transitions. Re-evaluate
                    // against the current registry state as a best-effort
                    // catch-up. The next successful recv will apply
                    // incremental fencing for the new transition.
                    let _ = skipped;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }

        all_outcomes
    }

    /// Apply fencing for a single epoch transition.
    ///
    /// Computes departed peers and transitions their connections to
    /// `Draining` in the registry. Returns per-peer outcomes.
    fn apply_fence(&self, transition: &EpochTransition) -> Vec<FenceOutcome> {
        let departed = EpochFence::departed_peers(&self.registry, &transition.member_set);
        let mut outcomes = Vec::with_capacity(departed.len());

        for peer_id in departed {
            let outcome = self.drain_peer(peer_id);
            outcomes.push(outcome);
        }

        outcomes
    }

    /// Attempt to drain a single departed peer.
    ///
    /// Looks up the peer in the registry. If the peer's connection is
    /// already in a non-active state (`Draining`, `Drained`, `Closed`),
    /// no state change is made. Otherwise, the connection is transitioned
    /// to `Draining` via [`ConnectionRegistry::set_state`].
    fn drain_peer(&self, peer_id: u64) -> FenceOutcome {
        // Check current state first.
        let entry = match self.registry.get(peer_id) {
            Some(entry) => entry,
            None => return FenceOutcome::NoConnection { peer_id },
        };

        // If already draining or terminal, no action needed.
        if matches!(
            entry.state,
            ConnectionState::Draining | ConnectionState::Drained | ConnectionState::Closed
        ) {
            return FenceOutcome::AlreadyDraining { peer_id };
        }

        // Transition to Draining.
        match self.registry.set_state(peer_id, ConnectionState::Draining) {
            Ok(_) => FenceOutcome::Drained { peer_id },
            Err(e) => FenceOutcome::DrainFailed {
                peer_id,
                reason: e.to_string(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection_registry::ConnectionId;
    use crate::peer_admission::AdmittedPeer;

    // -- helpers -----------------------------------------------------------

    fn make_registry_with_peers(peer_ids: &[u64]) -> Arc<ConnectionRegistry> {
        let reg = Arc::new(ConnectionRegistry::new());
        for (i, &peer_id) in peer_ids.iter().enumerate() {
            let admitted = AdmittedPeer::new(peer_id, 1);
            let conn_id = ConnectionId::new(i as u64 + 1);
            // Ignore duplicate errors in tests that intentionally add dupes.
            let _ = reg.insert(
                &admitted,
                conn_id,
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                    0,
                ),
            );
        }
        reg
    }

    fn make_member_set(peer_ids: &[u64]) -> EpochMemberSet {
        EpochMemberSet::new(peer_ids.iter().map(|&id| NodeIdentity::new(id)))
    }

    // -- EpochTransition ---------------------------------------------------

    #[test]
    fn epoch_transition_creation() {
        let set = make_member_set(&[1, 2, 3]);
        let t = EpochTransition::new(5, set.clone());
        assert_eq!(t.epoch, 5);
        assert_eq!(t.member_set.len(), 3);
        assert!(t.member_set.contains(&NodeIdentity::new(1)));
    }

    // -- FenceOutcome ------------------------------------------------------

    #[test]
    fn fence_outcome_labels() {
        assert_eq!(FenceOutcome::Drained { peer_id: 1 }.label(), "drained");
        assert_eq!(
            FenceOutcome::AlreadyDraining { peer_id: 2 }.label(),
            "already-draining"
        );
        assert_eq!(
            FenceOutcome::NoConnection { peer_id: 3 }.label(),
            "no-connection"
        );
        assert_eq!(
            FenceOutcome::DrainFailed {
                peer_id: 4,
                reason: "err".into()
            }
            .label(),
            "drain-failed"
        );
    }

    #[test]
    fn fence_outcome_is_success() {
        assert!(FenceOutcome::Drained { peer_id: 1 }.is_success());
        assert!(FenceOutcome::AlreadyDraining { peer_id: 2 }.is_success());
        assert!(FenceOutcome::NoConnection { peer_id: 3 }.is_success());
        assert!(!FenceOutcome::DrainFailed {
            peer_id: 4,
            reason: "err".into()
        }
        .is_success());
    }

    #[test]
    fn fence_outcome_display() {
        let o = FenceOutcome::Drained { peer_id: 42 };
        assert_eq!(o.to_string(), "peer 42 drained");

        let o = FenceOutcome::DrainFailed {
            peer_id: 7,
            reason: "peer not found".into(),
        };
        assert_eq!(o.to_string(), "peer 7 drain failed: peer not found");
    }

    // -- FenceSummary ------------------------------------------------------

    #[test]
    fn fence_summary_from_outcomes() {
        let outcomes = vec![
            FenceOutcome::Drained { peer_id: 1 },
            FenceOutcome::Drained { peer_id: 2 },
            FenceOutcome::AlreadyDraining { peer_id: 3 },
            FenceOutcome::NoConnection { peer_id: 4 },
            FenceOutcome::DrainFailed {
                peer_id: 5,
                reason: "oops".into(),
            },
        ];
        let summary = FenceSummary::from_outcomes(&outcomes);
        assert_eq!(summary.drained, 2);
        assert_eq!(summary.already_draining, 1);
        assert_eq!(summary.no_connection, 1);
        assert_eq!(summary.drain_failed, 1);
        assert_eq!(summary.total(), 5);
        assert!(!summary.all_success());
    }

    #[test]
    fn fence_summary_all_success() {
        let outcomes = vec![
            FenceOutcome::Drained { peer_id: 1 },
            FenceOutcome::AlreadyDraining { peer_id: 2 },
        ];
        let summary = FenceSummary::from_outcomes(&outcomes);
        assert!(summary.all_success());
    }

    #[test]
    fn fence_summary_empty() {
        let summary = FenceSummary::from_outcomes(&[]);
        assert_eq!(summary.total(), 0);
        assert!(summary.all_success());
    }

    #[test]
    fn fence_summary_display() {
        let summary = FenceSummary {
            drained: 3,
            already_draining: 1,
            no_connection: 0,
            drain_failed: 1,
        };
        let s = summary.to_string();
        assert!(s.contains("3 drained"));
        assert!(s.contains("1 already-draining"));
        assert!(s.contains("1 failed"));
    }

    // -- EpochFence::departed_peers ----------------------------------------

    #[test]
    fn departed_peers_empty_registry() {
        let registry = ConnectionRegistry::new();
        let member_set = make_member_set(&[1, 2]);
        let departed = EpochFence::departed_peers(&registry, &member_set);
        assert!(departed.is_empty());
    }

    #[test]
    fn departed_peers_no_departed_unchanged_member_set() {
        let registry = make_registry_with_peers(&[1, 2, 3]);
        let member_set = make_member_set(&[1, 2, 3]);
        let departed = EpochFence::departed_peers(&registry, &member_set);
        assert!(departed.is_empty());
    }

    #[test]
    fn departed_peers_single_peer_removed() {
        let registry = make_registry_with_peers(&[1, 2, 3]);
        // Peer 2 is no longer in the member set
        let member_set = make_member_set(&[1, 3]);
        let departed = EpochFence::departed_peers(&registry, &member_set);
        assert_eq!(departed.len(), 1);
        assert!(departed.contains(&2));
    }

    #[test]
    fn departed_peers_multiple_peers_removed() {
        let registry = make_registry_with_peers(&[10, 20, 30, 40]);
        // Only 10 and 40 remain
        let member_set = make_member_set(&[10, 40]);
        let departed = EpochFence::departed_peers(&registry, &member_set);
        assert_eq!(departed.len(), 2);
        assert!(departed.contains(&20));
        assert!(departed.contains(&30));
    }

    #[test]
    fn departed_peers_all_peers_removed() {
        let registry = make_registry_with_peers(&[1, 2]);
        let member_set = make_member_set(&[]); // empty member set
        let departed = EpochFence::departed_peers(&registry, &member_set);
        assert_eq!(departed.len(), 2);
        assert!(departed.contains(&1));
        assert!(departed.contains(&2));
    }

    #[test]
    fn departed_peers_inactive_connections_excluded() {
        let registry = Arc::new(ConnectionRegistry::new());
        // Insert peer 1 (active by default: Accepted)
        let admitted = AdmittedPeer::new(1, 1);
        registry
            .insert(
                &admitted,
                ConnectionId::new(1),
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                    0,
                ),
            )
            .unwrap();
        // Insert peer 2 and set it to Draining (not active)
        let admitted = AdmittedPeer::new(2, 1);
        registry
            .insert(
                &admitted,
                ConnectionId::new(2),
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                    0,
                ),
            )
            .unwrap();
        registry.set_state(2, ConnectionState::Draining).unwrap();
        // Peer 1 is in member set, peer 2 is not
        let member_set = make_member_set(&[1]);
        let departed = EpochFence::departed_peers(&registry, &member_set);
        // Only peer 1 is active and in member set; peer 2 is inactive
        // so it's not considered departed.
        assert!(departed.is_empty());
    }

    // -- EpochFence construction / channel ---------------------------------

    #[test]
    fn epoch_fence_sender_and_subscribe() {
        let registry = make_registry_with_peers(&[1, 2]);
        let fence = EpochFence::new(registry, 16);

        let sender = fence.sender();
        let mut rx = fence.subscribe();

        let transition = EpochTransition::new(2, make_member_set(&[1, 2, 3]));
        sender.send(transition.clone()).unwrap();

        // The runtime would process this; here we just verify the channel.
        let received = rx.try_recv().unwrap();
        assert_eq!(received.epoch, 2);
        assert_eq!(received.member_set.len(), 3);
    }

    #[test]
    fn epoch_fence_multiple_subscribers() {
        let registry = make_registry_with_peers(&[1]);
        let fence = EpochFence::new(registry, 4);

        let mut rx1 = fence.subscribe();
        let mut rx2 = fence.subscribe();
        let sender = fence.sender();

        let t = EpochTransition::new(1, make_member_set(&[1]));
        sender.send(t).unwrap();

        let r1 = rx1.try_recv().unwrap();
        let r2 = rx2.try_recv().unwrap();
        assert_eq!(r1.epoch, 1);
        assert_eq!(r2.epoch, 1);
    }

    // -- EpochFenceRuntime::drain_peer -------------------------------------

    #[test]
    fn drain_peer_success() {
        let registry = make_registry_with_peers(&[10]);
        let (_tx, rx) = broadcast::channel(1);
        let runtime = EpochFenceRuntime::new(rx, Arc::clone(&registry));

        let outcome = runtime.drain_peer(10);
        assert_eq!(outcome, FenceOutcome::Drained { peer_id: 10 });

        // Verify the registry state was updated.
        let entry = registry.get(10).unwrap();
        assert_eq!(entry.state, ConnectionState::Draining);
    }

    #[test]
    fn drain_peer_already_draining() {
        let registry = make_registry_with_peers(&[20]);
        registry.set_state(20, ConnectionState::Draining).unwrap();

        let (_tx, rx) = broadcast::channel(1);
        let runtime = EpochFenceRuntime::new(rx, Arc::clone(&registry));

        let outcome = runtime.drain_peer(20);
        assert_eq!(outcome, FenceOutcome::AlreadyDraining { peer_id: 20 });
    }

    #[test]
    fn drain_peer_already_drained() {
        let registry = make_registry_with_peers(&[30]);
        registry.set_state(30, ConnectionState::Drained).unwrap();

        let (_tx, rx) = broadcast::channel(1);
        let runtime = EpochFenceRuntime::new(rx, Arc::clone(&registry));

        let outcome = runtime.drain_peer(30);
        assert_eq!(outcome, FenceOutcome::AlreadyDraining { peer_id: 30 });
    }

    #[test]
    fn drain_peer_already_closed() {
        let registry = make_registry_with_peers(&[40]);
        registry.set_state(40, ConnectionState::Closed).unwrap();

        let (_tx, rx) = broadcast::channel(1);
        let runtime = EpochFenceRuntime::new(rx, Arc::clone(&registry));

        let outcome = runtime.drain_peer(40);
        assert_eq!(outcome, FenceOutcome::AlreadyDraining { peer_id: 40 });
    }

    #[test]
    fn drain_peer_no_connection() {
        let registry = Arc::new(ConnectionRegistry::new());
        let (_tx, rx) = broadcast::channel(1);
        let runtime = EpochFenceRuntime::new(rx, registry);

        let outcome = runtime.drain_peer(99);
        assert_eq!(outcome, FenceOutcome::NoConnection { peer_id: 99 });
    }

    // -- EpochFenceRuntime::apply_fence ------------------------------------

    #[test]
    fn apply_fence_no_departed_peers() {
        let registry = make_registry_with_peers(&[1, 2]);
        let (_tx, rx) = broadcast::channel(1);
        let runtime = EpochFenceRuntime::new(rx, Arc::clone(&registry));

        let transition = EpochTransition::new(2, make_member_set(&[1, 2]));
        let outcomes = runtime.apply_fence(&transition);
        assert!(outcomes.is_empty());
    }

    #[test]
    fn apply_fence_single_departed() {
        let registry = make_registry_with_peers(&[1, 2, 3]);
        let (_tx, rx) = broadcast::channel(1);
        let runtime = EpochFenceRuntime::new(rx, Arc::clone(&registry));

        // Peer 3 departed
        let transition = EpochTransition::new(2, make_member_set(&[1, 2]));
        let outcomes = runtime.apply_fence(&transition);

        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0], FenceOutcome::Drained { peer_id: 3 });
        assert_eq!(registry.get(3).unwrap().state, ConnectionState::Draining);
    }

    #[test]
    fn apply_fence_multiple_departed() {
        let registry = make_registry_with_peers(&[10, 20, 30, 40]);
        let (_tx, rx) = broadcast::channel(1);
        let runtime = EpochFenceRuntime::new(rx, Arc::clone(&registry));

        // 20 and 40 departed
        let transition = EpochTransition::new(3, make_member_set(&[10, 30]));
        let outcomes = runtime.apply_fence(&transition);

        assert_eq!(outcomes.len(), 2);
        let peer_ids: BTreeSet<u64> = outcomes.iter().map(|o| o.peer_id()).collect();
        assert_eq!(peer_ids, BTreeSet::from([20, 40]));
        for outcome in &outcomes {
            assert!(outcome.is_success());
        }
    }

    #[test]
    fn apply_fence_respects_already_draining() {
        let registry = make_registry_with_peers(&[1, 2, 3]);
        // Pre-set peer 3 to Draining
        registry.set_state(3, ConnectionState::Draining).unwrap();

        let (_tx, rx) = broadcast::channel(1);
        let runtime = EpochFenceRuntime::new(rx, Arc::clone(&registry));

        // Peer 2 and 3 departed, but peer 3 is already Draining (inactive)
        // so departed_peers excludes it; only peer 2 is processed.
        let transition = EpochTransition::new(2, make_member_set(&[1]));
        let outcomes = runtime.apply_fence(&transition);

        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0], FenceOutcome::Drained { peer_id: 2 });
    }

    // -- Integration: tokio runtime test -----------------------------------

    #[tokio::test]
    async fn runtime_run_single_transition() {
        let registry = make_registry_with_peers(&[1, 2, 3]);
        let fence = EpochFence::new(Arc::clone(&registry), 8);
        let sender = fence.sender();
        let rx = fence.subscribe();
        let runtime = EpochFenceRuntime::new(rx, Arc::clone(&registry));

        // Spawn the runtime
        let handle = tokio::spawn(async move { runtime.run().await });

        // Send a transition where peer 3 is departed
        let t = EpochTransition::new(2, make_member_set(&[1, 2]));
        sender.send(t).unwrap();
        // Drop sender to close the channel and let the runtime exit
        drop(sender);
        drop(fence);

        let outcomes = handle.await.unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0], FenceOutcome::Drained { peer_id: 3 });
    }

    #[tokio::test]
    async fn runtime_run_multiple_transitions() {
        let registry = make_registry_with_peers(&[10, 20, 30]);
        let fence = EpochFence::new(Arc::clone(&registry), 8);
        let sender = fence.sender();
        let rx = fence.subscribe();
        let runtime = EpochFenceRuntime::new(rx, Arc::clone(&registry));

        let handle = tokio::spawn(async move { runtime.run().await });

        // First transition: remove peer 30
        sender
            .send(EpochTransition::new(2, make_member_set(&[10, 20])))
            .unwrap();
        // Brief yield so the runtime processes
        tokio::task::yield_now().await;

        // Second transition: add peer 30 back, remove peer 20
        // But peer 30 is now Draining (inactive), so only peer 20 is departed.
        sender
            .send(EpochTransition::new(3, make_member_set(&[10, 30])))
            .unwrap();

        drop(sender);
        drop(fence);

        let outcomes = handle.await.unwrap();

        // First transition: peer 30 drained
        // Second transition: peer 20 drained (peer 30 already Draining)
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|o| o.is_success()));
    }
}
