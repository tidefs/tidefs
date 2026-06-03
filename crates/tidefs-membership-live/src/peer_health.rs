//! Heartbeat-miss-based peer health tracking with automated eviction.
//!
//! [`PeerHealthTracker`] monitors per-peer heartbeat response liveness and
//! drives automated roster removal when a peer stops responding. It bridges
//! the gap between raw heartbeat misses and eviction proposals: the tracker
//! counts consecutive missed heartbeats, enforces a configurable
//! Healthy→Suspect→Failed state machine, and on Failed transition produces
//! eviction proposals gated by quorum availability and a coordinator
//! self-eviction guard.
//!
//! # State Machine
//!
//! ```text
//!                   missed > max_missed_heartbeats
//!     HEALTHY  -----------------------------------> SUSPECT
//!        ^                                             |
//!        |            elapsed > failure_window_ms      |
//!        |            without heartbeat response       |
//!        |                                             v
//!        +---------------------------------------- FAILED
//!              heartbeat response received           (eviction proposed)
//!              before failure_window_ms expires
//! ```
//!
//! Any state transitions to `Failed` immediately when the
//! [`UnreachablePeerCallback`] fires (transport-level hard failure).
//!
//! # Integration
//!
//! - [`PeerHealthTracker::tick`] is called from the membership runtime tick
//!   loop. It returns failed peer IDs for the runtime to feed into epoch
//!   transition initiation.
//! - [`PeerHealthTracker::on_heartbeat_response`] resets a peer's missed
//!   counter when a heartbeat ack arrives.
//! - [`PeerHealthTracker::on_heartbeat_miss`] increments the counter for
//!   each peer that failed to respond in a tick.
//! - [`PeerHealthTracker::on_peer_unreachable`] is wired to the transport
//!   unreachability callback for immediate failure.

use std::collections::BTreeMap;

use tidefs_membership_epoch::MemberId;
use tidefs_membership_types::{PeerHealthConfig, PeerHealthState, UnreachablePeerCallback};

// ---------------------------------------------------------------------------
// TrackedPeer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct TrackedPeer {
    state: PeerHealthState,
    consecutive_misses: usize,
    suspect_since_ms: u64,
    eviction_proposed: bool,
}

impl TrackedPeer {
    fn new() -> Self {
        Self {
            state: PeerHealthState::Healthy,
            consecutive_misses: 0,
            suspect_since_ms: 0,
            eviction_proposed: false,
        }
    }
}

// ---------------------------------------------------------------------------
// PeerHealthTracker
// ---------------------------------------------------------------------------

/// Heartbeat-miss-based peer health tracker with automated eviction
/// proposal generation.
///
/// Tracks per-peer heartbeat liveness, enforces a Healthy→Suspect→Failed
/// state machine, and emits eviction proposals on Failed transitions
/// subject to quorum and coordinator self-eviction guards.
pub struct PeerHealthTracker {
    config: PeerHealthConfig,
    peers: BTreeMap<MemberId, TrackedPeer>,
}

impl PeerHealthTracker {
    /// Create a new tracker with the given configuration.
    #[must_use]
    pub fn new(config: PeerHealthConfig) -> Self {
        Self {
            config,
            peers: BTreeMap::new(),
        }
    }

    // ------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------

    /// Return a reference to the tracker's configuration.
    #[must_use]
    pub fn config(&self) -> &PeerHealthConfig {
        &self.config
    }

    /// Return the number of currently tracked peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------

    /// Register a peer for health tracking. Starts in Healthy state.
    /// No-op if the peer is already tracked.
    pub fn register_peer(&mut self, member_id: MemberId) {
        self.peers.entry(member_id).or_insert_with(TrackedPeer::new);
    }

    /// Remove a peer from tracking entirely (e.g., after successful
    /// eviction or graceful departure).
    pub fn remove_peer(&mut self, member_id: MemberId) {
        self.peers.remove(&member_id);
    }

    /// Synchronise tracked peers with the current roster: register new
    /// peers, remove departed ones. The local peer (self_id) is never
    /// removed — the coordinator self-eviction guard relies on the
    /// tracker knowing about the coordinator for quorum checks.
    pub fn sync_roster(&mut self, active_members: &[MemberId], self_id: MemberId) {
        let member_set: std::collections::BTreeSet<MemberId> =
            active_members.iter().copied().collect();

        // Remove peers no longer in the roster (except self).
        self.peers
            .retain(|id, _| member_set.contains(id) || *id == self_id);

        // Register new peers.
        for &id in active_members {
            self.peers.entry(id).or_insert_with(TrackedPeer::new);
        }

        // Ensure self is always tracked (for coordinator guard).
        self.peers.entry(self_id).or_insert_with(TrackedPeer::new);
    }

    // ------------------------------------------------------------------
    // Heartbeat events
    // ------------------------------------------------------------------

    /// Record that a heartbeat response was received from a peer.
    /// Resets the missed counter and returns the peer to Healthy if
    /// it was in Suspect state.
    ///
    /// If the peer is not tracked, it is auto-registered.
    pub fn on_heartbeat_response(&mut self, member_id: MemberId) {
        let peer = self.peers.entry(member_id).or_insert_with(TrackedPeer::new);
        peer.consecutive_misses = 0;
        if peer.state == PeerHealthState::Suspect {
            peer.state = PeerHealthState::Healthy;
        }
        peer.suspect_since_ms = 0;
        peer.eviction_proposed = false;
    }

    /// Record that a heartbeat was missed for a peer. Increments the
    /// consecutive miss counter.
    ///
    /// If the peer is not tracked, it is auto-registered.
    pub fn on_heartbeat_miss(&mut self, member_id: MemberId) {
        let peer = self.peers.entry(member_id).or_insert_with(TrackedPeer::new);
        if peer.state != PeerHealthState::Failed {
            peer.consecutive_misses += 1;
        }
    }

    // ------------------------------------------------------------------
    // Unreachability callback integration
    // ------------------------------------------------------------------

    /// Immediately transition a peer to Failed, bypassing the Healthy→
    /// Suspect→Failed state machine. Called when transport declares a
    /// peer permanently unreachable after exhausting reconnection.
    ///
    /// Returns `true` if this is a new failure (transition from non-Failed
    /// state), `false` if the peer was already Failed.
    pub fn on_peer_unreachable(&mut self, member_id: MemberId) -> bool {
        let peer = self.peers.entry(member_id).or_insert_with(TrackedPeer::new);
        let was_already_failed = peer.state == PeerHealthState::Failed;
        peer.state = PeerHealthState::Failed;
        peer.consecutive_misses = self.config.max_missed_heartbeats.max(1);
        if !was_already_failed {
            peer.eviction_proposed = false;
        }
        !was_already_failed
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    /// Get the current health state of a peer.
    #[must_use]
    pub fn state(&self, member_id: MemberId) -> Option<PeerHealthState> {
        self.peers.get(&member_id).map(|p| p.state)
    }

    /// Get the number of consecutive missed heartbeats for a peer.
    #[must_use]
    pub fn consecutive_misses(&self, member_id: MemberId) -> Option<usize> {
        self.peers.get(&member_id).map(|p| p.consecutive_misses)
    }

    /// Return all peer IDs currently in Failed state.
    #[must_use]
    pub fn failed_peers(&self) -> Vec<MemberId> {
        self.peers
            .iter()
            .filter(|(_, p)| p.state == PeerHealthState::Failed)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Return all peer IDs currently in Suspect state.
    #[must_use]
    pub fn suspect_peers(&self) -> Vec<MemberId> {
        self.peers
            .iter()
            .filter(|(_, p)| p.state == PeerHealthState::Suspect)
            .map(|(id, _)| *id)
            .collect()
    }

    // ------------------------------------------------------------------
    // Tick — state machine advancement and eviction proposal generation
    // ------------------------------------------------------------------

    /// Advance time and return the set of peer IDs that should be
    /// evicted (newly transitioned to Failed and not yet proposed).
    ///
    /// `now_ms` is the current wall-clock time in milliseconds.
    /// `coordinator_id` is the current coordinator (used for the
    /// self-eviction guard).
    ///
    /// The returned peer IDs should be fed into the epoch transition
    /// machinery. The tracker marks these peers as
    /// `eviction_proposed = true` so duplicate proposals are not generated.
    ///
    /// # Guards
    ///
    /// - **Coordinator self-eviction**: if `coordinator_id` is Some and
    ///   the coordinator itself would be evicted, the eviction is skipped
    ///   (lease health is [#6198]'s responsibility).
    /// - **Quorum gate**: eviction is skipped if the remaining roster
    ///   would fall below `min_peers_for_eviction_quorum`.
    pub fn tick(
        &mut self,
        now_ms: u64,
        coordinator_id: Option<MemberId>,
        active_member_count: usize,
    ) -> Vec<MemberId> {
        let mut evict = Vec::new();

        for (&member_id, peer) in self.peers.iter_mut() {
            // State machine: Healthy → Suspect
            if peer.state == PeerHealthState::Healthy
                && peer.consecutive_misses > self.config.max_missed_heartbeats
            {
                peer.state = PeerHealthState::Suspect;
                peer.suspect_since_ms = now_ms;
            }

            // State machine: Suspect → Failed
            if peer.state == PeerHealthState::Suspect {
                let elapsed = now_ms.saturating_sub(peer.suspect_since_ms);
                if elapsed >= self.config.failure_window_ms {
                    peer.state = PeerHealthState::Failed;
                }
            }

            // Eviction proposal: Failed + not yet proposed
            if peer.state == PeerHealthState::Failed && !peer.eviction_proposed {
                // Guard: coordinator self-eviction
                if let Some(coord_id) = coordinator_id {
                    if member_id == coord_id {
                        continue;
                    }
                }

                // Guard: quorum availability
                if active_member_count.saturating_sub(1) < self.config.min_peers_for_eviction_quorum
                {
                    continue;
                }

                peer.eviction_proposed = true;
                evict.push(member_id);
            }
        }

        evict
    }

    /// Mark a peer's eviction as resolved (e.g., the epoch transition
    /// was committed and the peer was removed from the roster). Resets
    /// the eviction_proposed flag so the peer can be proposed again if
    /// it re-enters Failed state.
    pub fn mark_eviction_resolved(&mut self, member_id: MemberId) {
        if let Some(peer) = self.peers.get_mut(&member_id) {
            peer.eviction_proposed = false;
        }
    }

    /// Reset all peers to Healthy (e.g., on cluster restart or
    /// coordinator promotion).
    pub fn reset_all(&mut self) {
        for peer in self.peers.values_mut() {
            peer.state = PeerHealthState::Healthy;
            peer.consecutive_misses = 0;
            peer.suspect_since_ms = 0;
            peer.eviction_proposed = false;
        }
    }
}

// ---------------------------------------------------------------------------
// UnreachablePeerCallback implementation
// ---------------------------------------------------------------------------

/// Shared handle to a [`PeerHealthTracker`] behind
/// `Arc<std::sync::Mutex<PeerHealthTracker>>` so it can be used
/// simultaneously by the membership runtime (tick loop) and passed to
/// transport as an `Arc<dyn UnreachablePeerCallback>`.
///
/// When transport calls `on_peer_unreachable`, this wrapper delegates
/// to [`PeerHealthTracker::on_peer_unreachable`], immediately marking
/// the peer as Failed.
pub struct PeerHealthHandle {
    inner: std::sync::Arc<PeerHealthCallbackInner>,
}

impl PeerHealthHandle {
    /// Create a new shared handle with the given configuration.
    /// The underlying tracker starts empty.
    #[must_use]
    pub fn new(config: PeerHealthConfig) -> Self {
        Self {
            inner: std::sync::Arc::new(PeerHealthCallbackInner {
                inner: std::sync::Mutex::new(PeerHealthTracker::new(config)),
            }),
        }
    }

    /// Acquire the lock and run a closure against the tracker.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn with_tracker<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut PeerHealthTracker) -> R,
    {
        let mut guard = self
            .inner
            .inner
            .lock()
            .expect("PeerHealthHandle mutex poisoned");
        f(&mut guard)
    }

    /// Return a clone of the inner `Arc` for use as an
    /// `UnreachablePeerCallback`.
    #[must_use]
    pub fn callback_arc(&self) -> std::sync::Arc<dyn UnreachablePeerCallback> {
        self.inner.clone() as std::sync::Arc<dyn UnreachablePeerCallback>
    }
}

impl Clone for PeerHealthHandle {
    fn clone(&self) -> Self {
        Self {
            inner: std::sync::Arc::clone(&self.inner),
        }
    }
}

/// Thin newtype that implements [`UnreachablePeerCallback`] by
/// delegating to the inner `Mutex<PeerHealthTracker>`.
///
/// The transport layer receives an `Arc<PeerHealthCallbackInner>` and
/// calls `on_peer_unreachable` which locks the shared mutex and
/// immediately marks the peer as Failed.
struct PeerHealthCallbackInner {
    inner: std::sync::Mutex<PeerHealthTracker>,
}

impl UnreachablePeerCallback for PeerHealthCallbackInner {
    fn on_peer_unreachable(&self, peer_id: u64) {
        let mut tracker = self.inner.lock().expect("PeerHealthTracker mutex poisoned");
        tracker.on_peer_unreachable(MemberId::new(peer_id));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(n: u64) -> MemberId {
        MemberId::new(n)
    }

    #[test]
    fn default_config_values() {
        let cfg = PeerHealthConfig::default();
        assert_eq!(cfg.max_missed_heartbeats, 5);
        assert_eq!(cfg.failure_window_ms, 30_000);
        assert_eq!(cfg.min_peers_for_eviction_quorum, 2);
    }

    #[test]
    fn config_builder_pattern() {
        let cfg = PeerHealthConfig::new()
            .with_max_missed_heartbeats(3)
            .with_failure_window_ms(10_000)
            .with_min_peers_for_eviction_quorum(1);
        assert_eq!(cfg.max_missed_heartbeats, 3);
        assert_eq!(cfg.failure_window_ms, 10_000);
        assert_eq!(cfg.min_peers_for_eviction_quorum, 1);
    }

    #[test]
    fn new_tracker_is_empty() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        assert_eq!(tracker.peer_count(), 0);
        assert_eq!(tracker.state(mid(1)), None);
    }

    #[test]
    fn register_peer_starts_healthy() {
        let mut tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        tracker.register_peer(mid(1));
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Healthy));
        assert_eq!(tracker.consecutive_misses(mid(1)), Some(0));
    }

    #[test]
    fn register_peer_twice_is_idempotent() {
        let mut tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        tracker.register_peer(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        assert_eq!(tracker.consecutive_misses(mid(1)), Some(1));
        tracker.register_peer(mid(1));
        assert_eq!(tracker.consecutive_misses(mid(1)), Some(1));
    }

    #[test]
    fn remove_peer_cleans_up() {
        let mut tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        tracker.register_peer(mid(1));
        tracker.register_peer(mid(2));
        assert_eq!(tracker.peer_count(), 2);
        tracker.remove_peer(mid(1));
        assert_eq!(tracker.peer_count(), 1);
        assert_eq!(tracker.state(mid(1)), None);
    }

    #[test]
    fn heartbeat_response_resets_misses() {
        let mut tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        tracker.register_peer(mid(1));
        for _ in 0..3 {
            tracker.on_heartbeat_miss(mid(1));
        }
        assert_eq!(tracker.consecutive_misses(mid(1)), Some(3));
        tracker.on_heartbeat_response(mid(1));
        assert_eq!(tracker.consecutive_misses(mid(1)), Some(0));
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Healthy));
    }

    #[test]
    fn heartbeat_miss_increments_counter() {
        let mut tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        tracker.register_peer(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        assert_eq!(tracker.consecutive_misses(mid(1)), Some(2));
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Healthy));
    }

    #[test]
    fn heartbeat_miss_on_failed_does_not_increment() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(1)
                .with_failure_window_ms(1),
        );
        tracker.register_peer(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.tick(1000, None, 3);
        let evicted = tracker.tick(1001, None, 3);
        assert_eq!(evicted.len(), 1);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Failed));
        tracker.on_heartbeat_miss(mid(1));
        assert_eq!(tracker.consecutive_misses(mid(1)), Some(2));
    }

    #[test]
    fn healthy_to_suspect_after_exceeding_max_misses() {
        let mut tracker =
            PeerHealthTracker::new(PeerHealthConfig::new().with_max_missed_heartbeats(3));
        tracker.register_peer(mid(1));
        for _ in 0..3 {
            tracker.on_heartbeat_miss(mid(1));
        }
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Healthy));
        tracker.on_heartbeat_miss(mid(1));
        tracker.tick(0, None, 3);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Suspect));
    }

    #[test]
    fn suspect_to_failed_after_failure_window() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(1)
                .with_failure_window_ms(5000),
        );
        tracker.register_peer(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.tick(1000, None, 3);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Suspect));
        tracker.tick(4000, None, 3);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Suspect));
        let evicted = tracker.tick(7000, None, 3);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Failed));
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0], mid(1));
    }

    #[test]
    fn suspect_heartbeat_response_reverts_to_healthy() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(1)
                .with_failure_window_ms(5000),
        );
        tracker.register_peer(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.tick(1000, None, 3);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Suspect));
        tracker.on_heartbeat_response(mid(1));
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Healthy));
        assert_eq!(tracker.consecutive_misses(mid(1)), Some(0));
    }

    #[test]
    fn unreachable_callback_immediate_failure_from_healthy() {
        let mut tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        tracker.register_peer(mid(1));
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Healthy));
        let is_new = tracker.on_peer_unreachable(mid(1));
        assert!(is_new);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Failed));
    }

    #[test]
    fn unreachable_callback_immediate_failure_from_suspect() {
        let mut tracker =
            PeerHealthTracker::new(PeerHealthConfig::new().with_max_missed_heartbeats(1));
        tracker.register_peer(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.tick(0, None, 3);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Suspect));
        let is_new = tracker.on_peer_unreachable(mid(1));
        assert!(is_new);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Failed));
    }

    #[test]
    fn unreachable_callback_idempotent_on_already_failed() {
        let mut tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        tracker.register_peer(mid(1));
        tracker.on_peer_unreachable(mid(1));
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Failed));
        let is_new = tracker.on_peer_unreachable(mid(1));
        assert!(!is_new);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Failed));
    }

    #[test]
    fn unreachable_callback_auto_registers() {
        let mut tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        let is_new = tracker.on_peer_unreachable(mid(42));
        assert!(is_new);
        assert_eq!(tracker.state(mid(42)), Some(PeerHealthState::Failed));
        assert_eq!(tracker.peer_count(), 1);
    }

    #[test]
    fn eviction_proposed_once_per_failure() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(1)
                .with_failure_window_ms(1),
        );
        tracker.register_peer(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        let evicted = tracker.tick(1000, None, 3);
        assert!(evicted.is_empty());
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Suspect));
        let evicted2 = tracker.tick(1001, None, 3);
        assert_eq!(evicted2.len(), 1);
        let evicted3 = tracker.tick(2000, None, 3);
        assert!(evicted3.is_empty());
    }

    #[test]
    fn eviction_resolved_allows_re_proposal() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(1)
                .with_failure_window_ms(1),
        );
        tracker.register_peer(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.tick(1000, None, 3);
        let evicted = tracker.tick(1001, None, 3);
        assert_eq!(evicted.len(), 1);
        tracker.mark_eviction_resolved(mid(1));
        tracker.on_peer_unreachable(mid(1));
        let evicted2 = tracker.tick(2000, None, 3);
        assert_eq!(evicted2.len(), 1);
    }

    #[test]
    fn coordinator_self_eviction_is_skipped() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(1)
                .with_failure_window_ms(1),
        );
        tracker.register_peer(mid(1));
        tracker.register_peer(mid(2));
        tracker.register_peer(mid(3));
        tracker.on_peer_unreachable(mid(1));
        let evicted = tracker.tick(1000, Some(mid(1)), 3);
        assert!(!evicted.contains(&mid(1)));
        tracker.on_peer_unreachable(mid(2));
        let evicted2 = tracker.tick(2000, Some(mid(1)), 3);
        assert!(evicted2.contains(&mid(2)));
    }

    #[test]
    fn self_eviction_allowed_when_no_coordinator() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(1)
                .with_failure_window_ms(1),
        );
        tracker.register_peer(mid(1));
        tracker.on_peer_unreachable(mid(1));
        let evicted = tracker.tick(1000, None, 3);
        assert_eq!(evicted, vec![mid(1)]);
    }

    #[test]
    fn eviction_skipped_when_below_quorum() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(1)
                .with_failure_window_ms(1)
                .with_min_peers_for_eviction_quorum(3),
        );
        tracker.register_peer(mid(1));
        tracker.register_peer(mid(2));
        tracker.register_peer(mid(3));
        tracker.on_peer_unreachable(mid(2));
        let evicted = tracker.tick(1000, Some(mid(1)), 3);
        assert!(evicted.is_empty());
    }

    #[test]
    fn eviction_allowed_when_above_quorum() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(1)
                .with_failure_window_ms(1)
                .with_min_peers_for_eviction_quorum(2),
        );
        tracker.register_peer(mid(1));
        tracker.register_peer(mid(2));
        tracker.register_peer(mid(3));
        tracker.on_peer_unreachable(mid(3));
        let evicted = tracker.tick(1000, Some(mid(1)), 3);
        assert_eq!(evicted, vec![mid(3)]);
    }

    #[test]
    fn eviction_at_quorum_boundary_is_allowed() {
        let cfg = PeerHealthConfig::new()
            .with_max_missed_heartbeats(1)
            .with_failure_window_ms(1)
            .with_min_peers_for_eviction_quorum(1);
        let mut tracker = PeerHealthTracker::new(cfg);
        tracker.register_peer(mid(1));
        tracker.register_peer(mid(2));
        tracker.on_peer_unreachable(mid(2));
        let evicted = tracker.tick(1000, Some(mid(1)), 2);
        assert_eq!(evicted, vec![mid(2)]);
    }

    #[test]
    fn sync_roster_registers_new_peers() {
        let mut tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        tracker.sync_roster(&[mid(1), mid(2), mid(3)], mid(1));
        assert_eq!(tracker.peer_count(), 3);
        assert_eq!(tracker.state(mid(2)), Some(PeerHealthState::Healthy));
    }

    #[test]
    fn sync_roster_removes_departed_peers() {
        let mut tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        tracker.sync_roster(&[mid(1), mid(2), mid(3)], mid(1));
        assert_eq!(tracker.peer_count(), 3);
        tracker.sync_roster(&[mid(1), mid(3)], mid(1));
        assert_eq!(tracker.peer_count(), 2);
        assert_eq!(tracker.state(mid(2)), None);
    }

    #[test]
    fn sync_roster_preserves_self_even_when_not_in_roster() {
        let mut tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        tracker.sync_roster(&[mid(2), mid(3)], mid(1));
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Healthy));
        assert_eq!(tracker.peer_count(), 3);
    }

    #[test]
    fn reset_all_returns_all_to_healthy() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(1)
                .with_failure_window_ms(1),
        );
        tracker.register_peer(mid(1));
        tracker.register_peer(mid(2));
        tracker.on_peer_unreachable(mid(1));
        tracker.on_heartbeat_miss(mid(2));
        tracker.on_heartbeat_miss(mid(2));
        tracker.tick(0, None, 3);
        tracker.reset_all();
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Healthy));
        assert_eq!(tracker.state(mid(2)), Some(PeerHealthState::Healthy));
        assert_eq!(tracker.consecutive_misses(mid(1)), Some(0));
        assert_eq!(tracker.consecutive_misses(mid(2)), Some(0));
    }

    #[test]
    fn failed_peers_returns_only_failed() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(1)
                .with_failure_window_ms(1),
        );
        tracker.register_peer(mid(1));
        tracker.register_peer(mid(2));
        tracker.register_peer(mid(3));
        tracker.on_peer_unreachable(mid(1));
        tracker.on_peer_unreachable(mid(3));
        let failed = tracker.failed_peers();
        assert_eq!(failed.len(), 2);
        assert!(failed.contains(&mid(1)));
        assert!(failed.contains(&mid(3)));
        assert!(!failed.contains(&mid(2)));
    }

    #[test]
    fn suspect_peers_returns_only_suspect() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(2)
                .with_failure_window_ms(60_000),
        );
        tracker.register_peer(mid(1));
        tracker.register_peer(mid(2));
        for _ in 0..3 {
            tracker.on_heartbeat_miss(mid(1));
        }
        tracker.tick(1000, None, 3);
        let suspect = tracker.suspect_peers();
        assert_eq!(suspect, vec![mid(1)]);
    }

    #[test]
    fn peer_health_handle_delegates_to_tracker() {
        let handle = PeerHealthHandle::new(PeerHealthConfig::default());
        let callback = handle.callback_arc();
        callback.on_peer_unreachable(7);
        handle.with_tracker(|t| {
            assert_eq!(t.state(mid(7)), Some(PeerHealthState::Failed));
        });
    }

    #[test]
    fn peer_health_handle_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PeerHealthHandle>();
    }

    #[test]
    fn peer_health_handle_clone_shares_tracker() {
        let handle = PeerHealthHandle::new(PeerHealthConfig::default());
        let clone = handle.clone();
        handle.with_tracker(|t| {
            t.register_peer(mid(1));
            t.on_heartbeat_miss(mid(1));
        });
        clone.with_tracker(|t| {
            assert_eq!(t.consecutive_misses(mid(1)), Some(1));
        });
    }

    #[test]
    fn multiple_peers_independent() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(2)
                .with_failure_window_ms(1),
        );
        tracker.register_peer(mid(1));
        tracker.register_peer(mid(2));
        tracker.register_peer(mid(3));
        tracker.on_heartbeat_miss(mid(1));
        tracker.on_heartbeat_miss(mid(2));
        tracker.on_heartbeat_miss(mid(2));
        tracker.on_heartbeat_miss(mid(2));
        tracker.on_peer_unreachable(mid(3));
        let evicted1 = tracker.tick(1000, Some(mid(1)), 4);
        assert_eq!(tracker.state(mid(2)), Some(PeerHealthState::Suspect));
        assert!(evicted1.contains(&mid(3)));
        assert!(!evicted1.contains(&mid(1)));
        assert!(!evicted1.contains(&mid(2)));
        let evicted2 = tracker.tick(1001, Some(mid(1)), 4);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Healthy));
        assert_eq!(tracker.state(mid(2)), Some(PeerHealthState::Failed));
        assert_eq!(tracker.state(mid(3)), Some(PeerHealthState::Failed));
        assert!(evicted2.contains(&mid(2)));
        assert!(!evicted2.contains(&mid(3)));
        assert!(!evicted2.contains(&mid(1)));
    }

    #[test]
    fn consecutive_misses_never_decrease_on_miss() {
        let mut tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        tracker.register_peer(mid(1));
        for _ in 0..10 {
            tracker.on_heartbeat_miss(mid(1));
        }
        assert_eq!(tracker.consecutive_misses(mid(1)), Some(10));
        tracker.tick(1000, None, 3);
        assert_eq!(tracker.consecutive_misses(mid(1)), Some(10));
    }

    #[test]
    fn state_returns_none_for_untracked() {
        let tracker = PeerHealthTracker::new(PeerHealthConfig::default());
        assert_eq!(tracker.state(mid(99)), None);
        assert_eq!(tracker.consecutive_misses(mid(99)), None);
    }

    #[test]
    fn zero_missed_heartbeats_threshold_triggers_immediately() {
        let mut tracker = PeerHealthTracker::new(
            PeerHealthConfig::new()
                .with_max_missed_heartbeats(0)
                .with_failure_window_ms(1),
        );
        tracker.register_peer(mid(1));
        tracker.on_heartbeat_miss(mid(1));
        tracker.tick(1000, None, 3);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Suspect));
        let evicted = tracker.tick(2000, None, 3);
        assert_eq!(tracker.state(mid(1)), Some(PeerHealthState::Failed));
        assert_eq!(evicted, vec![mid(1)]);
    }

    #[test]
    fn massive_miss_count_does_not_overflow() {
        let mut tracker =
            PeerHealthTracker::new(PeerHealthConfig::new().with_max_missed_heartbeats(usize::MAX));
        tracker.register_peer(mid(1));
        for _ in 0..1000 {
            tracker.on_heartbeat_miss(mid(1));
        }
        assert!(tracker.consecutive_misses(mid(1)).unwrap() > 0);
    }

    #[test]
    fn peer_health_state_debug_format() {
        assert_eq!(format!("{:?}", PeerHealthState::Healthy), "Healthy");
        assert_eq!(format!("{:?}", PeerHealthState::Suspect), "Suspect");
        assert_eq!(format!("{:?}", PeerHealthState::Failed), "Failed");
    }
}
