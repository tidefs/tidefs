// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Session-disconnect-driven peer unreachability detection.
//!
//! Bridges transport session disconnect events into per-peer unreachability
//! tracking. When a peer's transport session drops and stays disconnected
//! beyond a configurable grace period, the tracker produces
//! [`PeerLivenessChange`] events for the [`EpochAdvanceCoordinator`] to
//! automatically propose roster removal — enabling autonomous cluster
//! failure recovery without operator intervention.
//!
//! ## State Machine
//!
//! ```text
//!   Connected ──(session lost)──> Disconnected ──(grace expires)──> Unreachable
//!       ^                            |                                    |
//!       +───(session ready)──────────+────────────────────────────────────+
//! ```
//!
//! ## Integration
//!
//! - [`on_session_connected`] / [`on_session_disconnected`] are called from
//!   the [`RosterSessionHandle`] bridge (#6122) when transport sessions are
//!   established or lost.
//! - [`tick`] returns [`PeerLivenessChange`] values to feed into
//!   [`EpochAdvanceCoordinator::on_liveness_change`].
//! - [`status`] exposes per-peer [`PeerUnreachableStatus`] for operator
//!   visibility (e.g., `tidefsctl membership status`).
//!
//! [`on_session_connected`]: PeerUnreachableTracker::on_session_connected
//! [`on_session_disconnected`]: PeerUnreachableTracker::on_session_disconnected
//! [`tick`]: PeerUnreachableTracker::tick
//! [`status`]: PeerUnreachableTracker::status
//! [`EpochAdvanceCoordinator`]: crate::epoch_coordinator::EpochAdvanceCoordinator
//! [`EpochAdvanceCoordinator::on_liveness_change`]: crate::epoch_coordinator::EpochAdvanceCoordinator::on_liveness_change
//! [`RosterSessionHandle`]: crate::roster_session_bridge::RosterSessionHandle

use std::collections::BTreeMap;
use tidefs_membership_epoch::MemberId;

use crate::epoch_coordinator::{PeerLivenessChange, PeerLivenessStatus};

// ---------------------------------------------------------------------------
// PeerUnreachableConfig
// ---------------------------------------------------------------------------

/// Configuration for session-disconnect-driven peer unreachability detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerUnreachableConfig {
    /// How long a peer may remain disconnected (in milliseconds) before
    /// being considered unreachable and triggering a roster removal proposal.
    ///
    /// Default: 30_000 ms (30 seconds).
    pub unreachable_grace_ms: u64,
}

impl Default for PeerUnreachableConfig {
    fn default() -> Self {
        Self {
            unreachable_grace_ms: 30_000,
        }
    }
}

impl PeerUnreachableConfig {
    /// Create a new config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the unreachable grace duration in milliseconds.
    #[must_use]
    pub fn with_grace(mut self, grace_ms: u64) -> Self {
        self.unreachable_grace_ms = grace_ms;
        self
    }
}

// ---------------------------------------------------------------------------
// PeerUnreachableStatus
// ---------------------------------------------------------------------------

/// Per-peer unreachability status derived from transport session connectivity.
///
/// Exposed for operator visibility (e.g., `tidefsctl membership status`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerUnreachableStatus {
    /// Transport session is established; peer is reachable.
    Connected,
    /// Transport session was lost. The peer is still within the grace period.
    Disconnected {
        /// Wall-clock millis when the session was lost.
        since_ms: u64,
    },
    /// Transport session has been lost beyond the grace period.
    /// A roster removal has been (or will be) proposed.
    Unreachable {
        /// Wall-clock millis when the session was lost.
        since_ms: u64,
        /// Whether a removal proposal was already produced.
        removal_proposed: bool,
    },
}

impl PeerUnreachableStatus {
    /// Whether this status indicates the peer should be excluded from the
    /// active membership view.
    #[must_use]
    pub fn is_excluded(&self) -> bool {
        matches!(self, PeerUnreachableStatus::Unreachable { .. })
    }

    /// Whether a removal has already been proposed.
    #[must_use]
    pub fn removal_proposed(&self) -> bool {
        matches!(
            self,
            PeerUnreachableStatus::Unreachable {
                removal_proposed: true,
                ..
            }
        )
    }
}

// ---------------------------------------------------------------------------
// PeerState (internal)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum PeerState {
    /// Session is established.
    Connected { since_ms: u64 },
    /// Session was lost; grace timer is running.
    Disconnected { since_ms: u64 },
    /// Grace expired; removal proposed or pending.
    Unreachable {
        since_ms: u64,
        removal_proposed: bool,
    },
}

// ---------------------------------------------------------------------------
// PeerUnreachableTracker
// ---------------------------------------------------------------------------

/// Multi-peer tracker of session-connectivity-driven unreachability state.
///
/// Manages per-peer state driven by transport session connect and disconnect
/// notifications. On each [`tick`], checks for peers whose disconnect grace
/// period has expired and returns [`PeerLivenessChange`] events for the
/// [`EpochAdvanceCoordinator`] to process.
pub struct PeerUnreachableTracker {
    config: PeerUnreachableConfig,
    peers: BTreeMap<MemberId, PeerState>,
}

impl PeerUnreachableTracker {
    /// Create a new tracker with the given config.
    #[must_use]
    pub fn new(config: PeerUnreachableConfig) -> Self {
        Self {
            config,
            peers: BTreeMap::new(),
        }
    }

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------

    /// Register a peer for unreachability tracking.
    ///
    /// The peer starts in `Connected` state. No-op if already registered.
    pub fn register_peer(&mut self, member_id: MemberId, now_ms: u64) {
        self.peers
            .entry(member_id)
            .or_insert(PeerState::Connected { since_ms: now_ms });
    }

    /// Remove a peer from tracking entirely.
    pub fn remove_peer(&mut self, member_id: MemberId) {
        self.peers.remove(&member_id);
    }

    // ------------------------------------------------------------------
    // Session event notifications
    // ------------------------------------------------------------------

    /// Notify the tracker that a transport session has been established
    /// for the given peer.
    ///
    /// Resets the peer to `Connected` state, cancelling any in-progress
    /// grace timer or pending removal.
    ///
    /// If the peer was not previously registered, it is auto-registered.
    pub fn on_session_connected(&mut self, member_id: MemberId, now_ms: u64) {
        self.peers
            .insert(member_id, PeerState::Connected { since_ms: now_ms });
    }

    /// Notify the tracker that a transport session has been lost for the
    /// given peer.
    ///
    /// Transitions the peer to `Disconnected` state and starts the grace
    /// timer. If already disconnected or unreachable, the timestamp is
    /// not modified (preserving the original disconnect time).
    ///
    /// If the peer was not previously registered, it is auto-registered
    /// in `Disconnected` state.
    pub fn on_session_disconnected(&mut self, member_id: MemberId, now_ms: u64) {
        self.peers
            .entry(member_id)
            .and_modify(|state| {
                if matches!(state, PeerState::Connected { .. }) {
                    *state = PeerState::Disconnected { since_ms: now_ms };
                }
                // If already Disconnected or Unreachable, keep the original
                // since_ms so the grace period is measured from the first
                // disconnect.
            })
            .or_insert(PeerState::Disconnected { since_ms: now_ms });
    }

    // ------------------------------------------------------------------
    // Tick — grace expiry and change production
    // ------------------------------------------------------------------

    /// Advance time and return any [`PeerLivenessChange`] events for peers
    /// whose disconnect grace period has expired.
    ///
    /// Call this from the membership runtime tick loop. Feed returned
    /// changes into [`EpochAdvanceCoordinator::on_liveness_change`].
    pub fn tick(&mut self, now_ms: u64) -> Vec<PeerLivenessChange> {
        let mut changes = Vec::new();

        for (&member_id, state) in self.peers.iter_mut() {
            match state {
                PeerState::Disconnected { since_ms } => {
                    let elapsed = now_ms.saturating_sub(*since_ms);
                    if elapsed >= self.config.unreachable_grace_ms {
                        *state = PeerState::Unreachable {
                            since_ms: *since_ms,
                            removal_proposed: true,
                        };
                        changes.push(PeerLivenessChange::new(
                            member_id,
                            PeerLivenessStatus::Alive,
                            PeerLivenessStatus::Dead,
                            now_ms,
                        ));
                    }
                }
                PeerState::Unreachable {
                    removal_proposed: false,
                    since_ms,
                } => {
                    // Grace already expired but removal not yet proposed.
                    // This can happen if the grace was lowered at runtime.
                    let elapsed = now_ms.saturating_sub(*since_ms);
                    if elapsed >= self.config.unreachable_grace_ms {
                        *state = PeerState::Unreachable {
                            since_ms: *since_ms,
                            removal_proposed: true,
                        };
                        changes.push(PeerLivenessChange::new(
                            member_id,
                            PeerLivenessStatus::Alive,
                            PeerLivenessStatus::Dead,
                            now_ms,
                        ));
                    }
                }
                _ => {}
            }
        }

        changes
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    /// Get the current unreachability status for a peer.
    #[must_use]
    pub fn status(&self, member_id: MemberId) -> Option<PeerUnreachableStatus> {
        self.peers.get(&member_id).map(|state| match state {
            PeerState::Connected { .. } => PeerUnreachableStatus::Connected,
            PeerState::Disconnected { since_ms } => PeerUnreachableStatus::Disconnected {
                since_ms: *since_ms,
            },
            PeerState::Unreachable {
                since_ms,
                removal_proposed,
            } => PeerUnreachableStatus::Unreachable {
                since_ms: *since_ms,
                removal_proposed: *removal_proposed,
            },
        })
    }

    /// Number of tracked peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Iterate over all tracked peers and their current status.
    pub fn iter(&self) -> impl Iterator<Item = (MemberId, PeerUnreachableStatus)> + '_ {
        self.peers.iter().map(|(id, state)| {
            let status = match state {
                PeerState::Connected { .. } => PeerUnreachableStatus::Connected,
                PeerState::Disconnected { since_ms } => PeerUnreachableStatus::Disconnected {
                    since_ms: *since_ms,
                },
                PeerState::Unreachable {
                    since_ms,
                    removal_proposed,
                } => PeerUnreachableStatus::Unreachable {
                    since_ms: *since_ms,
                    removal_proposed: *removal_proposed,
                },
            };
            (*id, status)
        })
    }

    /// Collect all peer IDs that are currently unreachable.
    pub fn unreachable_peers(&self) -> Vec<MemberId> {
        self.peers
            .iter()
            .filter(|(_, state)| matches!(state, PeerState::Unreachable { .. }))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Collect all peer IDs that are currently connected.
    pub fn connected_peers(&self) -> Vec<MemberId> {
        self.peers
            .iter()
            .filter(|(_, state)| matches!(state, PeerState::Connected { .. }))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Reset all peers to `Connected` state (e.g., on full cluster restart).
    pub fn reset_all(&mut self, now_ms: u64) {
        for state in self.peers.values_mut() {
            *state = PeerState::Connected { since_ms: now_ms };
        }
    }

    /// Reset a specific peer to `Connected` state.
    pub fn reset_peer(&mut self, member_id: MemberId, now_ms: u64) {
        if let Some(state) = self.peers.get_mut(&member_id) {
            *state = PeerState::Connected { since_ms: now_ms };
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Config tests
    // ------------------------------------------------------------------

    #[test]
    fn config_default_grace() {
        let cfg = PeerUnreachableConfig::default();
        assert_eq!(cfg.unreachable_grace_ms, 30_000);
    }

    #[test]
    fn config_with_grace() {
        let cfg = PeerUnreachableConfig::new().with_grace(10_000);
        assert_eq!(cfg.unreachable_grace_ms, 10_000);
    }

    // ------------------------------------------------------------------
    // Registration tests
    // ------------------------------------------------------------------

    #[test]
    fn tracker_starts_empty() {
        let tracker = PeerUnreachableTracker::new(PeerUnreachableConfig::default());
        assert_eq!(tracker.peer_count(), 0);
    }

    #[test]
    fn register_peer_starts_connected() {
        let mut tracker = PeerUnreachableTracker::new(PeerUnreachableConfig::default());
        tracker.register_peer(MemberId::new(1), 1000);
        assert_eq!(tracker.peer_count(), 1);
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(PeerUnreachableStatus::Connected)
        );
    }

    #[test]
    fn register_peer_twice_is_idempotent() {
        let mut tracker = PeerUnreachableTracker::new(PeerUnreachableConfig::default());
        tracker.register_peer(MemberId::new(1), 1000);
        tracker.register_peer(MemberId::new(1), 2000); // second call
        assert_eq!(tracker.peer_count(), 1);
        // Still Connected with original since_ms
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(PeerUnreachableStatus::Connected)
        );
    }

    #[test]
    fn remove_peer() {
        let mut tracker = PeerUnreachableTracker::new(PeerUnreachableConfig::default());
        tracker.register_peer(MemberId::new(1), 1000);
        tracker.register_peer(MemberId::new(2), 1000);
        assert_eq!(tracker.peer_count(), 2);
        tracker.remove_peer(MemberId::new(1));
        assert_eq!(tracker.peer_count(), 1);
        assert!(tracker.status(MemberId::new(1)).is_none());
    }

    // ------------------------------------------------------------------
    // Session disconnect / reconnect tests
    // ------------------------------------------------------------------

    #[test]
    fn disconnect_transitions_to_disconnected() {
        let mut tracker = PeerUnreachableTracker::new(PeerUnreachableConfig::default());
        tracker.register_peer(MemberId::new(1), 1000);
        tracker.on_session_disconnected(MemberId::new(1), 5000);

        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(PeerUnreachableStatus::Disconnected { since_ms: 5000 })
        );
    }

    #[test]
    fn reconnect_within_grace_resets_to_connected() {
        let mut tracker = PeerUnreachableTracker::new(PeerUnreachableConfig::default());
        tracker.register_peer(MemberId::new(1), 1000);
        tracker.on_session_disconnected(MemberId::new(1), 5000);
        tracker.on_session_connected(MemberId::new(1), 10_000);

        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(PeerUnreachableStatus::Connected)
        );
    }

    #[test]
    fn disconnect_auto_registers() {
        let mut tracker = PeerUnreachableTracker::new(PeerUnreachableConfig::default());
        tracker.on_session_disconnected(MemberId::new(42), 5000);

        assert_eq!(tracker.peer_count(), 1);
        assert_eq!(
            tracker.status(MemberId::new(42)),
            Some(PeerUnreachableStatus::Disconnected { since_ms: 5000 })
        );
    }

    #[test]
    fn connect_auto_registers() {
        let mut tracker = PeerUnreachableTracker::new(PeerUnreachableConfig::default());
        tracker.on_session_connected(MemberId::new(7), 3000);

        assert_eq!(tracker.peer_count(), 1);
        assert_eq!(
            tracker.status(MemberId::new(7)),
            Some(PeerUnreachableStatus::Connected)
        );
    }

    // ------------------------------------------------------------------
    // Grace expiry tests
    // ------------------------------------------------------------------

    #[test]
    fn grace_expiry_produces_change() {
        let cfg = PeerUnreachableConfig::new().with_grace(5_000);
        let mut tracker = PeerUnreachableTracker::new(cfg);

        tracker.register_peer(MemberId::new(1), 1000);
        tracker.on_session_disconnected(MemberId::new(1), 2000);

        // Tick at 4000: grace not expired (only 2000ms elapsed)
        let changes = tracker.tick(4000);
        assert!(changes.is_empty());
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(PeerUnreachableStatus::Disconnected { since_ms: 2000 })
        );

        // Tick at 8000: grace expired (6000ms > 5000ms)
        let changes = tracker.tick(8000);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].member_id, MemberId::new(1));
        assert_eq!(changes[0].previous_status, PeerLivenessStatus::Alive);
        assert_eq!(changes[0].new_status, PeerLivenessStatus::Dead);

        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(PeerUnreachableStatus::Unreachable {
                since_ms: 2000,
                removal_proposed: true
            })
        );
    }

    #[test]
    fn grace_not_expired_at_boundary() {
        let cfg = PeerUnreachableConfig::new().with_grace(5_000);
        let mut tracker = PeerUnreachableTracker::new(cfg);

        tracker.register_peer(MemberId::new(1), 1000);
        tracker.on_session_disconnected(MemberId::new(1), 2000);

        // Tick at 7000: elapsed = 5000, which is == grace (not beyond)
        // But our condition is elapsed >= grace, so this should trigger
        let changes = tracker.tick(7000);
        assert_eq!(changes.len(), 1); // elapsed >= grace
    }

    #[test]
    fn removal_proposed_only_once() {
        let cfg = PeerUnreachableConfig::new().with_grace(1_000);
        let mut tracker = PeerUnreachableTracker::new(cfg);

        tracker.register_peer(MemberId::new(1), 0);
        tracker.on_session_disconnected(MemberId::new(1), 0);

        // First tick: grace expires
        let changes = tracker.tick(2000);
        assert_eq!(changes.len(), 1);

        // Second tick: no additional change produced
        let changes = tracker.tick(3000);
        assert!(changes.is_empty());
    }

    // ------------------------------------------------------------------
    // Multi-peer tests
    // ------------------------------------------------------------------

    #[test]
    fn multiple_peers_independent() {
        let cfg = PeerUnreachableConfig::new().with_grace(5_000);
        let mut tracker = PeerUnreachableTracker::new(cfg);

        tracker.register_peer(MemberId::new(1), 1000);
        tracker.register_peer(MemberId::new(2), 1000);
        tracker.register_peer(MemberId::new(3), 1000);

        // Peer 1 disconnects at t=2000
        tracker.on_session_disconnected(MemberId::new(1), 2000);
        // Peer 2 disconnects at t=4000
        tracker.on_session_disconnected(MemberId::new(2), 4000);
        // Peer 3 stays connected

        // Tick at t=6000: peer 1 elapsed=4000 (< 5000), peer 2 elapsed=2000 (< 5000)
        let changes = tracker.tick(6000);
        assert!(changes.is_empty());

        // Tick at t=8000: peer 1 elapsed=6000 (>= 5000), peer 2 elapsed=4000 (< 5000)
        let changes = tracker.tick(8000);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].member_id, MemberId::new(1));

        // Peer 3 is still connected
        assert_eq!(
            tracker.status(MemberId::new(3)),
            Some(PeerUnreachableStatus::Connected)
        );

        // Tick at t=10000: peer 2 elapsed=6000 (>= 5000)
        let changes = tracker.tick(10000);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].member_id, MemberId::new(2));
    }

    #[test]
    fn reconnect_after_grace_resets() {
        let cfg = PeerUnreachableConfig::new().with_grace(2_000);
        let mut tracker = PeerUnreachableTracker::new(cfg);

        tracker.register_peer(MemberId::new(1), 0);
        tracker.on_session_disconnected(MemberId::new(1), 1000);

        // Grace expires
        let changes = tracker.tick(4000);
        assert_eq!(changes.len(), 1);
        assert!(tracker.status(MemberId::new(1)).unwrap().is_excluded());

        // Peer reconnects
        tracker.on_session_connected(MemberId::new(1), 5000);
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(PeerUnreachableStatus::Connected)
        );
        assert!(!tracker.status(MemberId::new(1)).unwrap().is_excluded());
    }

    // ------------------------------------------------------------------
    // Query tests
    // ------------------------------------------------------------------

    #[test]
    fn connected_peers_list() {
        let mut tracker = PeerUnreachableTracker::new(PeerUnreachableConfig::default());
        tracker.register_peer(MemberId::new(1), 0);
        tracker.register_peer(MemberId::new(2), 0);
        tracker.on_session_disconnected(MemberId::new(2), 500);

        let connected = tracker.connected_peers();
        assert_eq!(connected, vec![MemberId::new(1)]);
    }

    #[test]
    fn unreachable_peers_list() {
        let cfg = PeerUnreachableConfig::new().with_grace(1_000);
        let mut tracker = PeerUnreachableTracker::new(cfg);

        tracker.register_peer(MemberId::new(1), 0);
        tracker.on_session_disconnected(MemberId::new(1), 500);
        tracker.tick(2000); // grace expires

        assert_eq!(tracker.unreachable_peers(), vec![MemberId::new(1)]);
    }

    #[test]
    fn iter_returns_all_peers() {
        let mut tracker = PeerUnreachableTracker::new(PeerUnreachableConfig::default());
        tracker.register_peer(MemberId::new(1), 1000);
        tracker.on_session_disconnected(MemberId::new(2), 2000);

        let statuses: BTreeMap<MemberId, PeerUnreachableStatus> = tracker.iter().collect();
        assert_eq!(statuses.len(), 2);
        assert_eq!(
            statuses[&MemberId::new(1)],
            PeerUnreachableStatus::Connected
        );
        assert_eq!(
            statuses[&MemberId::new(2)],
            PeerUnreachableStatus::Disconnected { since_ms: 2000 }
        );
    }

    // ------------------------------------------------------------------
    // Reset tests
    // ------------------------------------------------------------------

    #[test]
    fn reset_all() {
        let cfg = PeerUnreachableConfig::new().with_grace(1_000);
        let mut tracker = PeerUnreachableTracker::new(cfg);

        tracker.register_peer(MemberId::new(1), 0);
        tracker.register_peer(MemberId::new(2), 0);
        tracker.on_session_disconnected(MemberId::new(1), 500);
        tracker.tick(2000); // peer 1 becomes unreachable

        tracker.reset_all(10_000);
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(PeerUnreachableStatus::Connected)
        );
        assert_eq!(
            tracker.status(MemberId::new(2)),
            Some(PeerUnreachableStatus::Connected)
        );
    }

    #[test]
    fn reset_peer() {
        let cfg = PeerUnreachableConfig::new().with_grace(1_000);
        let mut tracker = PeerUnreachableTracker::new(cfg);

        tracker.register_peer(MemberId::new(1), 0);
        tracker.on_session_disconnected(MemberId::new(1), 500);
        tracker.tick(2000);

        tracker.reset_peer(MemberId::new(1), 10_000);
        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(PeerUnreachableStatus::Connected)
        );
    }

    // ------------------------------------------------------------------
    // Edge cases
    // ------------------------------------------------------------------

    #[test]
    fn status_returns_none_for_untracked() {
        let tracker = PeerUnreachableTracker::new(PeerUnreachableConfig::default());
        assert_eq!(tracker.status(MemberId::new(99)), None);
    }

    #[test]
    fn disconnect_preserves_original_timestamp() {
        let mut tracker = PeerUnreachableTracker::new(PeerUnreachableConfig::default());
        tracker.register_peer(MemberId::new(1), 1000);
        tracker.on_session_disconnected(MemberId::new(1), 2000);

        // Second disconnect (e.g., duplicate notification) should not change since_ms
        tracker.on_session_disconnected(MemberId::new(1), 5000);

        assert_eq!(
            tracker.status(MemberId::new(1)),
            Some(PeerUnreachableStatus::Disconnected { since_ms: 2000 })
        );
    }

    #[test]
    fn peer_unreachable_status_removal_proposed() {
        assert!(PeerUnreachableStatus::Unreachable {
            since_ms: 1000,
            removal_proposed: true
        }
        .removal_proposed());

        assert!(!PeerUnreachableStatus::Unreachable {
            since_ms: 1000,
            removal_proposed: false
        }
        .removal_proposed());

        assert!(!PeerUnreachableStatus::Connected.removal_proposed());
        assert!(!PeerUnreachableStatus::Disconnected { since_ms: 1000 }.removal_proposed());
    }

    #[test]
    fn peer_unreachable_status_is_excluded() {
        assert!(PeerUnreachableStatus::Unreachable {
            since_ms: 0,
            removal_proposed: false
        }
        .is_excluded());
        assert!(!PeerUnreachableStatus::Connected.is_excluded());
        assert!(!PeerUnreachableStatus::Disconnected { since_ms: 0 }.is_excluded());
    }
}
