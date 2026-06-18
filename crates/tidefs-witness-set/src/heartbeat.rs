// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Heartbeat protocol for witness-set node failure detection.
//
// Tracks per-node heartbeat liveness with configurable intervals and
// failure thresholds. Drives WitnessHealth state transitions and emits
// NodeFailureEvent for consumption by membership-live.
//
// Key design decisions:
// - Epoch monotonicity guards against stale, duplicate, and reordered
//   heartbeat messages.
// - Consecutive-miss counting avoids transient network blips triggering
//   false Suspect/Dead transitions.
// - Flap detection prevents a node that rapidly cycles through Online/Offline
//   from destabilizing quorum decisions.

use crate::health::WitnessHealth;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// HeartbeatConfig
// ---------------------------------------------------------------------------

/// Configuration for the witness-set heartbeat protocol.
#[derive(Clone, Debug, PartialEq)]
pub struct HeartbeatConfig {
    /// Expected interval between successive heartbeats from each node.
    pub heartbeat_interval: Duration,
    /// Number of consecutive missed heartbeat checks before transitioning
    /// a node from Online to Suspect.
    pub suspect_threshold: u32,
    /// Number of additional consecutive missed heartbeat checks (after
    /// entering Suspect) before transitioning to Dead (Offline).
    pub dead_threshold: u32,
    /// Minimum time a node must remain Online before flap detection
    /// considers the transition stable. If a node rejoins and then goes
    /// dead again within this window, it is considered to be flapping.
    pub min_stable_duration: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(1),
            suspect_threshold: 3,
            dead_threshold: 5,
            min_stable_duration: Duration::from_secs(30),
        }
    }
}

// ---------------------------------------------------------------------------
// HeartbeatEpoch
// ---------------------------------------------------------------------------

/// Monotonically increasing heartbeat epoch counter.
///
/// Each heartbeat carries the sender's current epoch. Receipt validates
/// that the epoch is strictly greater than the last seen epoch, rejecting
/// stale (epoch <= last_seen) heartbeats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeartbeatEpoch(pub u64);

impl HeartbeatEpoch {
    /// The initial, never-valid epoch. All real heartbeats must carry
    /// an epoch strictly greater than zero.
    pub const ZERO: Self = Self(0);

    /// Create a new epoch from a raw u64.
    pub const fn new(epoch: u64) -> Self {
        Self(epoch)
    }

    /// Return the next epoch in the sequence.
    pub fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    /// Return the raw epoch value.
    pub fn value(self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// NodeHeartbeatState
// ---------------------------------------------------------------------------

/// Per-node heartbeat tracking state maintained by the protocol.
#[derive(Clone, Debug)]
pub struct NodeHeartbeatState {
    /// Highest validated epoch received from this node.
    pub last_epoch: HeartbeatEpoch,
    /// Instant when the last valid heartbeat was received.
    pub last_heartbeat_at: Instant,
    /// Number of consecutive check_heartbeats() calls where this node
    /// has failed to deliver a heartbeat within the configured interval.
    pub consecutive_misses: u32,
    /// Current health state.
    pub health: WitnessHealth,
    /// Instant when this node entered its current health state.
    pub health_since: Instant,
    /// Number of flap events detected (rapid Online->Offline->Online
    /// cycling within min_stable_duration).
    pub flap_count: u32,
}

impl NodeHeartbeatState {
    fn new(now: Instant) -> Self {
        Self {
            last_epoch: HeartbeatEpoch::ZERO,
            last_heartbeat_at: now,
            consecutive_misses: 0,
            health: WitnessHealth::Online,
            health_since: now,
            flap_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// NodeFailureEvent
// ---------------------------------------------------------------------------

/// Events emitted by [`HeartbeatProtocol`] for consumption by
/// membership-live, quorum-write runtime, and other cluster subsystems.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeFailureEvent {
    /// A node has been declared Suspect after missing at least
    /// `suspect_threshold` consecutive heartbeats.
    NodeSuspect { node_id: u64 },
    /// A node has been declared Dead (Offline) after missing at least
    /// `dead_threshold` consecutive heartbeats while Suspect.
    NodeDead { node_id: u64 },
    /// A node that was previously Suspect or Dead has delivered a fresh
    /// heartbeat and is now Online again.
    NodeRejoined { node_id: u64 },
    /// A node is flapping — rapidly cycling between Online and Offline
    /// within `min_stable_duration`.
    NodeFlapping { node_id: u64, flap_count: u32 },
}

// ---------------------------------------------------------------------------
// HeartbeatProtocol
// ---------------------------------------------------------------------------

/// Heartbeat protocol engine for witness-set failure detection.
///
/// Tracks per-node heartbeat liveness, drives [`WitnessHealth`] state
/// transitions, and emits [`NodeFailureEvent`] for cluster-wide
/// notification.
///
/// # Usage
///
/// 1. Register every witness-set member via [`register_node`].
/// 2. Call [`receive_heartbeat`] whenever a heartbeat message arrives.
/// 3. Call [`check_heartbeats`] on a periodic timer (at least every
///    `heartbeat_interval`).
/// 4. Consume returned [`NodeFailureEvent`]s and feed them into
///    membership-live for automatic member removal or rebuild triggering.
///
/// [`register_node`]: HeartbeatProtocol::register_node
/// [`receive_heartbeat`]: HeartbeatProtocol::receive_heartbeat
/// [`check_heartbeats`]: HeartbeatProtocol::check_heartbeats
#[derive(Clone, Debug)]
pub struct HeartbeatProtocol {
    config: HeartbeatConfig,
    states: HashMap<u64, NodeHeartbeatState>,
}

impl HeartbeatProtocol {
    /// Create a new heartbeat protocol with the given configuration.
    pub fn new(config: HeartbeatConfig) -> Self {
        Self {
            config,
            states: HashMap::new(),
        }
    }

    /// Return a reference to the current configuration.
    pub fn config(&self) -> &HeartbeatConfig {
        &self.config
    }

    /// Register a node for heartbeat tracking.
    ///
    /// If the node is already registered, this is a no-op.
    pub fn register_node(&mut self, node_id: u64) {
        let now = Instant::now();
        self.states
            .entry(node_id)
            .or_insert_with(|| NodeHeartbeatState::new(now));
    }

    /// Unregister a node from heartbeat tracking.
    ///
    /// Returns the final state of the node, if it was registered.
    pub fn unregister_node(&mut self, node_id: u64) -> Option<NodeHeartbeatState> {
        self.states.remove(&node_id)
    }

    /// Return true if the node is currently registered.
    pub fn is_registered(&self, node_id: u64) -> bool {
        self.states.contains_key(&node_id)
    }

    /// Number of registered nodes.
    pub fn node_count(&self) -> usize {
        self.states.len()
    }

    /// Return a reference to a node's heartbeat state, if registered.
    pub fn node_state(&self, node_id: u64) -> Option<&NodeHeartbeatState> {
        self.states.get(&node_id)
    }

    // ------------------------------------------------------------------
    // Heartbeat receipt
    // ------------------------------------------------------------------

    /// Process a heartbeat received from a node.
    ///
    /// Validates epoch monotonicity (epoch must be strictly greater than
    /// the last seen epoch for this node). Resets the consecutive-miss
    /// counter and, if the node was Suspect or Offline, transitions it
    /// back to Online.
    ///
    /// Returns any [`NodeFailureEvent`]s triggered by the receipt (e.g.,
    /// rejoining, flap detection).
    pub fn receive_heartbeat(
        &mut self,
        node_id: u64,
        epoch: HeartbeatEpoch,
    ) -> Vec<NodeFailureEvent> {
        let state = match self.states.get_mut(&node_id) {
            Some(s) => s,
            None => return Vec::new(),
        };

        let now = Instant::now();

        // Monotonic epoch validation: reject stale, duplicate, or reordered
        // heartbeats. This protects against network duplication and replay.
        if epoch <= state.last_epoch {
            return Vec::new();
        }

        state.last_epoch = epoch;
        state.last_heartbeat_at = now;
        state.consecutive_misses = 0;

        let mut events = Vec::new();

        match state.health {
            // Already Online: no transition needed.
            WitnessHealth::Online => {}
            // Suspect or Offline that receives a valid heartbeat rejoins.
            WitnessHealth::Suspect | WitnessHealth::Offline => {
                // Flap detection: if this node was Offline and returned
                // within min_stable_duration, increment the flap counter.
                if state.health == WitnessHealth::Offline {
                    let offlined_for = now.duration_since(state.health_since);
                    if offlined_for < self.config.min_stable_duration {
                        state.flap_count += 1;
                        events.push(NodeFailureEvent::NodeFlapping {
                            node_id,
                            flap_count: state.flap_count,
                        });
                    }
                }
                state.health = WitnessHealth::Online;
                state.health_since = now;
                events.push(NodeFailureEvent::NodeRejoined { node_id });
            }
        }

        events
    }

    // ------------------------------------------------------------------
    // Periodic health check
    // ------------------------------------------------------------------

    /// Check all registered nodes for missed heartbeats.
    ///
    /// For each node, if at least one `heartbeat_interval` has elapsed
    /// since the last heartbeat, the consecutive-miss counter is
    /// incremented. When the counter crosses the configured thresholds,
    /// the node transitions to Suspect or Dead.
    ///
    /// This method should be called on a periodic timer at least as
    /// frequently as `heartbeat_interval` to avoid threshold aliasing.
    ///
    /// Returns all [`NodeFailureEvent`]s triggered during this check.
    pub fn check_heartbeats(&mut self) -> Vec<NodeFailureEvent> {
        let now = Instant::now();
        let mut events = Vec::new();

        for (&node_id, state) in self.states.iter_mut() {
            let elapsed = now.duration_since(state.last_heartbeat_at);

            // Count how many full heartbeat intervals have elapsed.
            let missed_intervals =
                (elapsed.as_nanos() / self.config.heartbeat_interval.as_nanos()) as u64;

            if missed_intervals == 0 {
                // Within one interval — no missed heartbeat yet.
                continue;
            }

            // Advance the miss counter by 1 per check cycle (not by
            // missed_intervals), so that the threshold is measured in
            // consecutive check cycles, not raw elapsed intervals.
            // This makes behavior independent of the check timer's
            // absolute jitter.
            state.consecutive_misses += 1;

            match state.health {
                WitnessHealth::Online => {
                    if state.consecutive_misses >= self.config.suspect_threshold {
                        state.health = WitnessHealth::Suspect;
                        state.health_since = now;
                        events.push(NodeFailureEvent::NodeSuspect { node_id });
                    }
                }
                WitnessHealth::Suspect => {
                    if state.consecutive_misses >= self.config.dead_threshold {
                        state.health = WitnessHealth::Offline;
                        state.health_since = now;
                        events.push(NodeFailureEvent::NodeDead { node_id });
                    }
                }
                // Dead: no further transition possible via heartbeats alone.
                WitnessHealth::Offline => {}
            }
        }

        events
    }

    // ------------------------------------------------------------------
    // Bulk operations
    // ------------------------------------------------------------------

    /// Register multiple nodes at once.
    pub fn register_nodes(&mut self, node_ids: &[u64]) {
        for &id in node_ids {
            self.register_node(id);
        }
    }

    /// Return a snapshot of all per-node health states suitable for
    /// feeding into quorum-availability calculations.
    pub fn health_map(&self) -> HashMap<u64, WitnessHealth> {
        self.states.iter().map(|(&id, s)| (id, s.health)).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_config() -> HeartbeatConfig {
        HeartbeatConfig {
            heartbeat_interval: Duration::from_millis(10),
            suspect_threshold: 3,
            dead_threshold: 5,
            min_stable_duration: Duration::from_millis(100),
        }
    }

    fn new_protocol() -> HeartbeatProtocol {
        HeartbeatProtocol::new(fast_config())
    }

    // -- Construction --------------------------------------------------------

    #[test]
    fn test_new_protocol_is_empty() {
        let p = new_protocol();
        assert_eq!(p.node_count(), 0);
    }

    #[test]
    fn test_register_node() {
        let mut p = new_protocol();
        p.register_node(1);
        assert_eq!(p.node_count(), 1);
        assert!(p.is_registered(1));
        assert!(!p.is_registered(2));
    }

    #[test]
    fn test_register_duplicate_is_noop() {
        let mut p = new_protocol();
        p.register_node(1);
        p.register_node(1);
        assert_eq!(p.node_count(), 1);
    }

    #[test]
    fn test_register_nodes_bulk() {
        let mut p = new_protocol();
        p.register_nodes(&[1, 2, 3, 4, 5]);
        assert_eq!(p.node_count(), 5);
        for id in 1..=5 {
            assert!(p.is_registered(id));
        }
    }

    #[test]
    fn test_unregister_node() {
        let mut p = new_protocol();
        p.register_node(42);
        let state = p.unregister_node(42);
        assert!(state.is_some());
        assert!(!p.is_registered(42));
    }

    #[test]
    fn test_unregister_unknown_node() {
        let mut p = new_protocol();
        assert!(p.unregister_node(99).is_none());
    }

    #[test]
    fn test_node_state_accessor() {
        let mut p = new_protocol();
        p.register_node(7);
        let s = p.node_state(7).unwrap();
        assert_eq!(s.health, WitnessHealth::Online);
        assert_eq!(s.consecutive_misses, 0);
        assert_eq!(s.last_epoch, HeartbeatEpoch::ZERO);
    }

    // -- Heartbeat receipt (normal cycle) -----------------------------------

    #[test]
    fn test_receive_heartbeat_updates_epoch() {
        let mut p = new_protocol();
        p.register_node(1);
        let events = p.receive_heartbeat(1, HeartbeatEpoch(5));
        assert!(events.is_empty());
        assert_eq!(p.node_state(1).unwrap().last_epoch, HeartbeatEpoch(5));
    }

    #[test]
    fn test_receive_heartbeat_no_events_when_staying_online() {
        let mut p = new_protocol();
        p.register_node(1);
        let events = p.receive_heartbeat(1, HeartbeatEpoch(1));
        assert!(events.is_empty());
        let events = p.receive_heartbeat(1, HeartbeatEpoch(2));
        assert!(events.is_empty());
    }

    #[test]
    fn test_receive_heartbeat_resets_misses() {
        let mut p = new_protocol();
        p.register_node(1);
        // Artificially set high miss count.
        p.states.get_mut(&1).unwrap().consecutive_misses = 5;
        p.receive_heartbeat(1, HeartbeatEpoch(1));
        assert_eq!(p.node_state(1).unwrap().consecutive_misses, 0);
    }

    // -- Epoch monotonicity ------------------------------------------------

    #[test]
    fn test_reject_duplicate_epoch() {
        let mut p = new_protocol();
        p.register_node(1);
        p.receive_heartbeat(1, HeartbeatEpoch(5));
        // Duplicate epoch should be silently rejected.
        let events = p.receive_heartbeat(1, HeartbeatEpoch(5));
        assert!(events.is_empty());
        assert_eq!(p.node_state(1).unwrap().last_epoch, HeartbeatEpoch(5));
    }

    #[test]
    fn test_reject_stale_epoch() {
        let mut p = new_protocol();
        p.register_node(1);
        p.receive_heartbeat(1, HeartbeatEpoch(10));
        // Stale epoch should be silently rejected.
        let events = p.receive_heartbeat(1, HeartbeatEpoch(5));
        assert!(events.is_empty());
        assert_eq!(p.node_state(1).unwrap().last_epoch, HeartbeatEpoch(10));
    }

    #[test]
    fn test_reject_zero_epoch_after_nonzero() {
        let mut p = new_protocol();
        p.register_node(1);
        // First heartbeat: epoch 0 from a fresh node is accepted
        // (last_epoch starts at ZERO(0); epoch 0 is NOT strictly greater).
        // So initial epoch must be >=1.
        p.receive_heartbeat(1, HeartbeatEpoch(1));
        // Now try epoch 0 — stale.
        let events = p.receive_heartbeat(1, HeartbeatEpoch(0));
        assert!(events.is_empty());
        assert_eq!(p.node_state(1).unwrap().last_epoch, HeartbeatEpoch(1));
    }

    #[test]
    fn test_epoch_monotonicity_across_gaps() {
        let mut p = new_protocol();
        p.register_node(1);
        p.receive_heartbeat(1, HeartbeatEpoch(1));
        p.receive_heartbeat(1, HeartbeatEpoch(100));
        assert_eq!(p.node_state(1).unwrap().last_epoch, HeartbeatEpoch(100));
        // Gap is fine as long as sequential numbers increase.
    }

    // -- Missed heartbeat detection ---------------------------------------

    #[test]
    fn test_check_heartbeats_within_interval_no_miss() {
        let mut p = new_protocol();
        p.register_node(1);
        // Heartbeat just received; check_heartbeats immediately should
        // find no missed intervals.
        p.receive_heartbeat(1, HeartbeatEpoch(1));
        let events = p.check_heartbeats();
        assert!(events.is_empty());
        assert_eq!(p.node_state(1).unwrap().consecutive_misses, 0);
    }

    #[test]
    fn test_check_heartbeats_after_interval_increments_misses() {
        let mut p = new_protocol();
        p.register_node(1);

        // Rewind last_heartbeat_at to simulate elapsed time.
        {
            let state = p.states.get_mut(&1).unwrap();
            state.last_heartbeat_at = Instant::now() - Duration::from_millis(20);
            // 2 intervals
        }

        let events = p.check_heartbeats();
        assert!(events.is_empty()); // hasn't reached threshold yet
        assert_eq!(p.node_state(1).unwrap().consecutive_misses, 1);
    }

    #[test]
    fn test_online_to_suspect_on_threshold_crossing() {
        let mut p = new_protocol();
        p.register_node(1);

        // Simulate elapsed time for each check.
        for _ in 0..3 {
            {
                let state = p.states.get_mut(&1).unwrap();
                state.last_heartbeat_at = Instant::now() - Duration::from_millis(20);
            }
            let events = p.check_heartbeats();
            // On the 3rd check, suspect_threshold=3 is reached.
            if events.is_empty() {
                continue;
            }
            assert_eq!(events.len(), 1);
            assert_eq!(events[0], NodeFailureEvent::NodeSuspect { node_id: 1 });
            assert_eq!(p.node_state(1).unwrap().health, WitnessHealth::Suspect);
            break;
        }
    }

    #[test]
    fn test_suspect_to_dead_on_threshold_crossing() {
        let mut p = new_protocol();
        p.register_node(1);

        // First cross the suspect threshold.
        for _ in 0..3 {
            {
                let state = p.states.get_mut(&1).unwrap();
                state.last_heartbeat_at = Instant::now() - Duration::from_millis(20);
                // Keep health as Online for first checks so we can drive
                // it through Suspect.
            }
            p.check_heartbeats();
        }
        assert_eq!(p.node_state(1).unwrap().health, WitnessHealth::Suspect);

        // Now drive through dead_threshold (5 more checks needed, but
        // already at 3 misses, so 2 more to reach 5).
        let mut dead_event_seen = false;
        for _ in 0..5 {
            {
                let state = p.states.get_mut(&1).unwrap();
                state.last_heartbeat_at = Instant::now() - Duration::from_millis(20);
            }
            let events = p.check_heartbeats();
            for ev in events {
                if ev == (NodeFailureEvent::NodeDead { node_id: 1 }) {
                    dead_event_seen = true;
                }
            }
        }
        assert!(dead_event_seen);
        assert_eq!(p.node_state(1).unwrap().health, WitnessHealth::Offline);
    }

    #[test]
    fn test_dead_stays_dead_on_further_checks() {
        let mut p = new_protocol();
        p.register_node(1);

        // Fast-track to dead.
        p.states.get_mut(&1).unwrap().consecutive_misses = 10;
        p.states.get_mut(&1).unwrap().health = WitnessHealth::Offline;
        p.states.get_mut(&1).unwrap().last_heartbeat_at =
            Instant::now() - Duration::from_millis(20);

        let events = p.check_heartbeats();
        // No further Dead event should fire — already dead.
        assert!(!events
            .iter()
            .any(|e| matches!(e, NodeFailureEvent::NodeDead { .. })));
    }

    // -- Rejoin path --------------------------------------------------------

    #[test]
    fn test_suspect_rejoins_on_heartbeat() {
        let mut p = new_protocol();
        p.register_node(1);

        // Push into Suspect.
        {
            let state = p.states.get_mut(&1).unwrap();
            state.consecutive_misses = 3;
            state.health = WitnessHealth::Suspect;
        }

        let events = p.receive_heartbeat(1, HeartbeatEpoch(7));
        assert!(events
            .iter()
            .any(|e| matches!(e, NodeFailureEvent::NodeRejoined { node_id: 1 })));
        assert_eq!(p.node_state(1).unwrap().health, WitnessHealth::Online);
        assert_eq!(p.node_state(1).unwrap().consecutive_misses, 0);
    }

    #[test]
    fn test_offline_rejoins_on_heartbeat() {
        let mut p = new_protocol();
        p.register_node(1);

        // Push into Offline.
        {
            let state = p.states.get_mut(&1).unwrap();
            state.consecutive_misses = 10;
            state.health = WitnessHealth::Offline;
            state.health_since = Instant::now() - Duration::from_secs(60); // outside flap window
        }

        let events = p.receive_heartbeat(1, HeartbeatEpoch(42));
        assert!(events
            .iter()
            .any(|e| matches!(e, NodeFailureEvent::NodeRejoined { node_id: 1 })));
        assert_eq!(p.node_state(1).unwrap().health, WitnessHealth::Online);
        assert_eq!(p.node_state(1).unwrap().consecutive_misses, 0);
    }

    // -- Flap detection -----------------------------------------------------

    #[test]
    fn test_flap_detection_on_rapid_rejoin() {
        let mut p = new_protocol();
        p.register_node(1);

        // Push into Offline very recently (within min_stable_duration).
        {
            let state = p.states.get_mut(&1).unwrap();
            state.consecutive_misses = 10;
            state.health = WitnessHealth::Offline;
            state.health_since = Instant::now() - Duration::from_millis(5); // 5ms ago, flap window is 100ms
        }

        let events = p.receive_heartbeat(1, HeartbeatEpoch(1));
        assert!(events
            .iter()
            .any(|e| matches!(e, NodeFailureEvent::NodeFlapping { node_id: 1, .. })));
        assert_eq!(p.node_state(1).unwrap().flap_count, 1);
    }

    #[test]
    fn test_no_flap_when_offline_for_long_time() {
        let mut p = new_protocol();
        p.register_node(1);

        // Push into Offline long ago (outside flap window).
        {
            let state = p.states.get_mut(&1).unwrap();
            state.consecutive_misses = 10;
            state.health = WitnessHealth::Offline;
            state.health_since = Instant::now() - Duration::from_secs(5); // 5s ago >> 100ms flap window
        }

        let events = p.receive_heartbeat(1, HeartbeatEpoch(1));
        assert!(!events
            .iter()
            .any(|e| matches!(e, NodeFailureEvent::NodeFlapping { .. })));
    }

    #[test]
    fn test_flap_count_accumulates() {
        let mut p = new_protocol();
        p.register_node(1);

        for i in 0..3u64 {
            // Offline briefly.
            {
                let state = p.states.get_mut(&1).unwrap();
                state.health = WitnessHealth::Offline;
                state.health_since = Instant::now() - Duration::from_millis(1);
            }
            p.receive_heartbeat(1, HeartbeatEpoch(i + 1));
            // Push back to Offline for next iteration.
            {
                let state = p.states.get_mut(&1).unwrap();
                state.consecutive_misses = 10;
                state.health = WitnessHealth::Offline;
                state.health_since = Instant::now() - Duration::from_millis(1);
            }
        }

        assert_eq!(p.node_state(1).unwrap().flap_count, 3);
    }

    // -- Health map for quorum integration ---------------------------------

    #[test]
    fn test_health_map_reflects_current_state() {
        let mut p = new_protocol();
        p.register_node(1);
        p.register_node(2);
        p.register_node(3);

        // Node 2 goes Suspect.
        {
            let state = p.states.get_mut(&2).unwrap();
            state.health = WitnessHealth::Suspect;
        }
        // Node 3 goes Offline.
        {
            let state = p.states.get_mut(&3).unwrap();
            state.health = WitnessHealth::Offline;
        }

        let map = p.health_map();
        assert_eq!(map.get(&1), Some(&WitnessHealth::Online));
        assert_eq!(map.get(&2), Some(&WitnessHealth::Suspect));
        assert_eq!(map.get(&3), Some(&WitnessHealth::Offline));
    }

    // -- Integration: full lifecycle ---------------------------------------

    #[test]
    fn test_full_lifecycle_online_suspect_dead_rejoin() {
        let mut p = new_protocol();
        p.register_node(1);

        // 1. Normal operation: heartbeats arrive.
        assert!(p.receive_heartbeat(1, HeartbeatEpoch(1)).is_empty());
        assert_eq!(p.node_state(1).unwrap().health, WitnessHealth::Online);
        assert_eq!(p.node_state(1).unwrap().consecutive_misses, 0);

        // 2. Simulate missed heartbeats -> Suspect.
        for _ in 0..3 {
            {
                let state = p.states.get_mut(&1).unwrap();
                state.last_heartbeat_at = Instant::now() - Duration::from_millis(20);
            }
            p.check_heartbeats();
        }
        assert_eq!(p.node_state(1).unwrap().health, WitnessHealth::Suspect);

        // 3. More misses -> Dead.
        for _ in 0..5 {
            {
                let state = p.states.get_mut(&1).unwrap();
                state.last_heartbeat_at = Instant::now() - Duration::from_millis(20);
            }
            p.check_heartbeats();
        }
        assert_eq!(p.node_state(1).unwrap().health, WitnessHealth::Offline);

        // 4. Rejoin -> Online.
        let events = p.receive_heartbeat(1, HeartbeatEpoch(100));
        assert!(events
            .iter()
            .any(|e| matches!(e, NodeFailureEvent::NodeRejoined { .. })));
        assert_eq!(p.node_state(1).unwrap().health, WitnessHealth::Online);
        assert_eq!(p.node_state(1).unwrap().consecutive_misses, 0);
    }

    // -- Config ------------------------------------------------------------

    #[test]
    fn test_default_config() {
        let cfg = HeartbeatConfig::default();
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(1));
        assert_eq!(cfg.suspect_threshold, 3);
        assert_eq!(cfg.dead_threshold, 5);
        assert_eq!(cfg.min_stable_duration, Duration::from_secs(30));
    }

    // -- Epoch arithmetic --------------------------------------------------

    #[test]
    fn test_epoch_next() {
        assert_eq!(HeartbeatEpoch(0).next(), HeartbeatEpoch(1));
        assert_eq!(HeartbeatEpoch(42).next(), HeartbeatEpoch(43));
        assert_eq!(HeartbeatEpoch(u64::MAX).next(), HeartbeatEpoch(0)); // wraps
    }

    #[test]
    fn test_epoch_ordering() {
        assert!(HeartbeatEpoch(1) > HeartbeatEpoch(0));
        assert!(HeartbeatEpoch(100) > HeartbeatEpoch(99));
        assert!((HeartbeatEpoch(5) <= HeartbeatEpoch(5)));
    }

    #[test]
    fn test_epoch_zero() {
        assert_eq!(HeartbeatEpoch::ZERO, HeartbeatEpoch(0));
        assert_eq!(HeartbeatEpoch::ZERO.value(), 0);
    }
}
