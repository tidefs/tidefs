// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;
use tidefs_membership_epoch::{EpochId, HealthClass, MemberId};
use tidefs_node_drain::{
    FenceToken, FenceTrigger, FencingError, FencingStats, ForcedFencing, ForcedFencingConfig,
    NodeDrain, NodeState,
};

// ---------------------------------------------------------------------------
// FencingWatchdog — monitors liveness and triggers forced fencing
// ---------------------------------------------------------------------------

/// The fencing watchdog monitors peer liveness through the failure detector
/// and triggers forced fencing when nodes are unresponsive beyond the
/// configured fence timeout.
///
/// ## Lifecycle
///
/// 1. On each tick, the watchdog inspects peer states for unresponsive nodes.
/// 2. Nodes that have been Down (no ack) for longer than `fence_timeout_ms`
///    are candidates for forced fencing.
/// 3. The watchdog creates (or reuses) a [`NodeDrain`], fences it via
///    [`ForcedFencing::fence`], and returns a [`FencingAction`] telling
///    the runtime to initiate an epoch transition excluding the node.
/// 4. Fenced nodes are recorded; rejoin attempts with stale tokens are
///    validated via [`ForcedFencing::validate_fence_token`].
pub struct FencingWatchdog {
    fencing: ForcedFencing,
    /// Active drain instances for nodes being drained.
    drains: BTreeMap<u64, NodeDrain>,
    /// When each peer was last seen healthy (last_ack_millis from detection).
    last_healthy: BTreeMap<u64, u64>,
}

/// An action the watchdog wants the runtime to take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FencingAction {
    /// No action needed.
    None,
    /// A node has been fenced; the runtime should initiate an epoch
    /// transition to exclude it.
    FenceNode {
        node_id: MemberId,
        fence_token: FenceToken,
        trigger: FenceTrigger,
    },
}

impl FencingWatchdog {
    /// Create a new fencing watchdog with default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fencing: ForcedFencing::new(),
            drains: BTreeMap::new(),
            last_healthy: BTreeMap::new(),
        }
    }

    /// Create a new fencing watchdog with custom config.
    #[must_use]
    pub fn with_config(config: ForcedFencingConfig) -> Self {
        Self {
            fencing: ForcedFencing::with_config(config),
            drains: BTreeMap::new(),
            last_healthy: BTreeMap::new(),
        }
    }

    // Accessors

    #[must_use]
    pub fn stats(&self) -> FencingStats {
        self.fencing.stats()
    }

    #[must_use]
    pub fn token_for(&self, node_id: MemberId) -> FenceToken {
        self.fencing.token_for(node_id)
    }

    #[must_use]
    pub fn is_fenced(&self, node_id: MemberId) -> bool {
        self.fencing.is_fenced(node_id)
    }

    #[must_use]
    pub fn fenced_node_ids(&self) -> Vec<u64> {
        self.fencing.fenced_node_ids()
    }

    /// Returns true while forced fencing holds the epoch-transition barrier.
    #[must_use]
    pub fn forced_fence_barrier_blocked(&self) -> bool {
        self.fencing.lease_acquisition_blocked()
    }

    /// Return the pending epoch guarded by the forced-fence barrier, if any.
    #[must_use]
    pub fn pending_epoch(&self) -> Option<EpochId> {
        self.fencing.pending_epoch()
    }

    /// Update the fence timeout for testing or runtime reconfiguration.
    pub fn set_fence_timeout_ms(&mut self, ms: u64) {
        self.fencing.set_fence_timeout_ms(ms);
    }

    /// Register that a peer is healthy at the given timestamp.
    /// Called when the failure detector records a successful ack.
    pub fn record_healthy(&mut self, node_id: MemberId, now_millis: u64) {
        self.last_healthy.insert(node_id.0, now_millis);
    }

    /// Drop tracking for a removed or decommissioned peer.
    pub fn remove_peer(&mut self, node_id: MemberId) {
        self.last_healthy.remove(&node_id.0);
        self.drains.remove(&node_id.0);
    }

    /// Begin tracking a drain for a node (called when graceful drain starts).
    pub fn start_drain(&mut self, node_id: MemberId) {
        let (drain, _handle) = NodeDrain::drain(node_id);
        self.drains.insert(node_id.0, drain);
    }

    /// Get the drain state for a node, if being drained.
    #[must_use]
    pub fn drain_state(&self, node_id: MemberId) -> Option<NodeState> {
        self.drains.get(&node_id.0).map(|d| d.state())
    }

    // -----------------------------------------------------------------------
    // Tick: inspect peers and trigger fencing if needed
    // -----------------------------------------------------------------------

    /// Inspect peer health and trigger forced fencing for unresponsive nodes.
    ///
    /// `peers` is an iterator of `(node_id, health, last_ack_millis)` tuples
    /// from the failure detector. The watchdog compares `last_ack_millis`
    /// against `now_millis` and fences nodes that have been unresponsive
    /// beyond `fence_timeout_ms`.
    ///
    /// Returns a [`FencingAction`] to tell the runtime what to do.
    pub fn tick(
        &mut self,
        peers: &[(MemberId, HealthClass, u64)], // (node_id, health, last_ack_millis)
        now_millis: u64,
        current_epoch: u64,
    ) -> FencingAction {
        let fence_timeout = self.fencing.fence_timeout_ms();

        for &(node_id, health, last_ack_millis) in peers {
            let nid = node_id.0;

            // Skip self (node 0 or any node that's not the right target).
            // Actually we can't distinguish self here; the runtime should
            // filter out self before calling us. We'll trust the caller.

            // Record the last time we saw this peer healthy
            if health == HealthClass::Healthy {
                self.record_healthy(node_id, now_millis);
                continue;
            }

            // Already fenced — nothing to do
            if self.fencing.is_fenced(node_id) {
                continue;
            }

            // Check how long the node has been unresponsive
            let last_seen = self
                .last_healthy
                .get(&nid)
                .copied()
                .unwrap_or(last_ack_millis);
            let unresponsive_duration = now_millis.saturating_sub(last_seen);

            if unresponsive_duration < fence_timeout {
                continue;
            }

            // Node is unresponsive beyond fence timeout — attempt forced fence
            let trigger = FenceTrigger::Timeout;

            // Get or create a drain for this node
            let drain = self.drains.entry(nid).or_insert_with(|| {
                let (d, _) = NodeDrain::drain(node_id);
                d
            });

            match self.fencing.fence(node_id, trigger, drain, current_epoch) {
                Ok(token) => {
                    return FencingAction::FenceNode {
                        node_id,
                        fence_token: token,
                        trigger,
                    };
                }
                Err(FencingError::AlreadyFenced { .. }) => {
                    // Already handled above, but safety net
                    continue;
                }
                Err(FencingError::NotEligible { .. }) => {
                    // Node is decommissioned or in an ineligible state
                    continue;
                }
                Err(FencingError::MaxFencesExceeded { .. }) => {
                    // Operator intervention required; stop trying
                    continue;
                }
                Err(_) => {
                    continue;
                }
            }
        }

        FencingAction::None
    }

    // -----------------------------------------------------------------------
    // Fence token validation for rejoin
    // -----------------------------------------------------------------------

    /// Validate a fence token presented by a node attempting to rejoin.
    pub fn validate_fence_token(
        &self,
        node_id: MemberId,
        presented: FenceToken,
    ) -> Result<(), FencingError> {
        self.fencing.validate_fence_token(node_id, presented)
    }

    /// Clear a node's fenced status after successful catch-up rejoin.
    pub fn clear_fence(
        &mut self,
        node_id: MemberId,
        presented: FenceToken,
    ) -> Result<(), FencingError> {
        self.fencing.clear_fence(node_id, presented)
    }

    /// Release the forced-fence epoch barrier when the membership runtime
    /// reaches the matching terminal transition.
    ///
    /// The barrier is released only if the active forced-fence transition
    /// matches both the fenced node and target epoch, leaving unrelated
    /// membership transitions and other active fences untouched.
    pub fn release_epoch_barrier_for_transition(
        &mut self,
        node_id: MemberId,
        to_epoch: EpochId,
    ) -> bool {
        if self
            .fencing
            .active_epoch_transition()
            .is_some_and(|transition| {
                transition.node_id() == node_id && transition.to_epoch() == to_epoch
            })
        {
            self.fencing.release_epoch_barrier();
            return true;
        }

        false
    }

    /// Manual fence by operator command.
    pub fn manual_fence(
        &mut self,
        node_id: MemberId,
        current_epoch: u64,
    ) -> Result<FenceToken, FencingError> {
        let drain = self.drains.entry(node_id.0).or_insert_with(|| {
            let (d, _) = NodeDrain::drain(node_id);
            d
        });
        self.fencing
            .fence(node_id, FenceTrigger::Operator, drain, current_epoch)
    }

    /// Build an exclusion proposal for epoch transition.
    #[must_use]
    pub fn build_exclusion_proposal(
        &self,
        node_id: MemberId,
        from_epoch: EpochId,
        to_epoch: EpochId,
    ) -> tidefs_node_drain::FenceExclusionProposal {
        self.fencing
            .build_exclusion_proposal(node_id, from_epoch, to_epoch)
    }
}

impl Default for FencingWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u64) -> MemberId {
        MemberId::new(id)
    }

    #[test]
    fn test_watchdog_creation() {
        let wd = FencingWatchdog::new();
        assert_eq!(wd.stats().nodes_fenced, 0);
        assert!(!wd.is_fenced(node(1)));
        let ids: Vec<u64> = wd.fenced_node_ids();
        assert!(ids.is_empty());
    }

    #[test]
    fn test_watchdog_fences_unresponsive_node() {
        let mut wd = FencingWatchdog::with_config(ForcedFencingConfig {
            fence_timeout_ms: 1000,
            max_consecutive_fences: 5,
        });

        // Node 1 was healthy at t=0
        wd.record_healthy(node(1), 0);

        // At t=2000, node 1 is still Down (unresponsive for 2000ms > 1000ms)
        let peers = vec![(node(1), HealthClass::Down, 0)];
        let action = wd.tick(&peers, 2000, 1);

        match action {
            FencingAction::FenceNode {
                node_id,
                fence_token,
                trigger,
            } => {
                assert_eq!(node_id, node(1));
                assert_eq!(fence_token.value(), 1);
                assert_eq!(trigger, FenceTrigger::Timeout);
            }
            _ => panic!("expected FenceNode action"),
        }

        assert!(wd.is_fenced(node(1)));
        assert_eq!(wd.stats().nodes_fenced, 1);
        assert_eq!(wd.stats().fence_triggers_timeout, 1);
    }

    #[test]
    fn test_watchdog_ignores_healthy_node() {
        let mut wd = FencingWatchdog::with_config(ForcedFencingConfig {
            fence_timeout_ms: 1000,
            max_consecutive_fences: 5,
        });

        // Node 1 is healthy
        let peers = vec![(node(1), HealthClass::Healthy, 1000)];
        let action = wd.tick(&peers, 2000, 1);
        assert_eq!(action, FencingAction::None);
        assert!(!wd.is_fenced(node(1)));
    }

    #[test]
    fn test_watchdog_ignores_recently_unresponsive() {
        let mut wd = FencingWatchdog::with_config(ForcedFencingConfig {
            fence_timeout_ms: 5000,
            max_consecutive_fences: 5,
        });

        wd.record_healthy(node(1), 0);

        // Node 1 unresponsive for only 3000ms, under 5000ms timeout
        let peers = vec![(node(1), HealthClass::Down, 0)];
        let action = wd.tick(&peers, 3000, 1);
        assert_eq!(action, FencingAction::None);
    }

    #[test]
    fn test_watchdog_single_fence_per_node() {
        let mut wd = FencingWatchdog::with_config(ForcedFencingConfig {
            fence_timeout_ms: 1000,
            max_consecutive_fences: 5,
        });

        wd.record_healthy(node(1), 0);
        let peers = vec![(node(1), HealthClass::Down, 0)];

        // First tick: fence
        let _ = wd.tick(&peers, 2000, 1);
        assert!(wd.is_fenced(node(1)));

        // Second tick: no action (already fenced)
        let action = wd.tick(&peers, 3000, 1);
        assert_eq!(action, FencingAction::None);
        assert_eq!(wd.stats().nodes_fenced, 1); // still only 1
    }

    #[test]
    fn test_watchdog_clear_fence_and_refence() {
        let mut wd = FencingWatchdog::with_config(ForcedFencingConfig {
            fence_timeout_ms: 1000,
            max_consecutive_fences: 5,
        });

        wd.record_healthy(node(1), 0);
        let peers = vec![(node(1), HealthClass::Down, 0)];
        let action = wd.tick(&peers, 2000, 1);
        let token = match action {
            FencingAction::FenceNode { fence_token, .. } => fence_token,
            _ => panic!("expected fence"),
        };

        // Clear the fence (node catches up and rejoins)
        wd.clear_fence(node(1), token).unwrap();
        assert!(!wd.is_fenced(node(1)));

        // Node goes unresponsive again — refence with higher token
        wd.record_healthy(node(1), 3000);
        let peers2 = vec![(node(1), HealthClass::Down, 3000)];
        let action2 = wd.tick(&peers2, 5000, 2);

        match action2 {
            FencingAction::FenceNode {
                node_id,
                fence_token,
                ..
            } => {
                assert_eq!(node_id, node(1));
                assert_eq!(fence_token.value(), 2);
            }
            _ => panic!("expected refence"),
        }

        assert_eq!(wd.stats().nodes_fenced, 2);
    }

    #[test]
    fn test_watchdog_terminal_release_matches_active_transition() {
        let mut wd = FencingWatchdog::with_config(ForcedFencingConfig {
            fence_timeout_ms: 1000,
            max_consecutive_fences: 5,
        });

        wd.record_healthy(node(1), 0);
        let peers = vec![(node(1), HealthClass::Down, 0)];
        let action = wd.tick(&peers, 2000, 1);
        assert!(matches!(action, FencingAction::FenceNode { .. }));
        assert!(wd.forced_fence_barrier_blocked());
        assert_eq!(wd.pending_epoch(), Some(EpochId::new(2)));

        assert!(!wd.release_epoch_barrier_for_transition(node(2), EpochId::new(2)));
        assert!(wd.forced_fence_barrier_blocked());

        assert!(!wd.release_epoch_barrier_for_transition(node(1), EpochId::new(3)));
        assert!(wd.forced_fence_barrier_blocked());

        assert!(wd.release_epoch_barrier_for_transition(node(1), EpochId::new(2)));
        assert!(!wd.forced_fence_barrier_blocked());
        assert_eq!(wd.pending_epoch(), None);
        assert!(wd.is_fenced(node(1)));
    }

    #[test]
    fn test_watchdog_validate_token_reject_old() {
        let mut wd = FencingWatchdog::with_config(ForcedFencingConfig {
            fence_timeout_ms: 1000,
            max_consecutive_fences: 5,
        });

        wd.record_healthy(node(1), 0);
        let peers = vec![(node(1), HealthClass::Down, 0)];
        let _ = wd.tick(&peers, 2000, 1);

        // Reject old token
        let result = wd.validate_fence_token(node(1), FenceToken::new(0));
        assert!(result.is_err());

        // Accept current token
        let result = wd.validate_fence_token(node(1), FenceToken::new(1));
        assert!(result.is_ok());
    }

    #[test]
    fn test_watchdog_manual_fence() {
        let mut wd = FencingWatchdog::new();

        let token = wd.manual_fence(node(2), 1).unwrap();
        assert_eq!(token.value(), 1);
        assert!(wd.is_fenced(node(2)));
        assert_eq!(wd.stats().fence_triggers_manual, 1);
    }

    #[test]
    fn test_watchdog_remove_peer() {
        let mut wd = FencingWatchdog::with_config(ForcedFencingConfig {
            fence_timeout_ms: 1000,
            max_consecutive_fences: 5,
        });

        wd.record_healthy(node(1), 0);
        wd.start_drain(node(1));

        wd.remove_peer(node(1));
        // After removal, the node shouldn't be tracked
        // (fenced status in ForcedFencing is separate from last_healthy/drains)
        assert!(!wd.drains.contains_key(&1));
    }

    #[test]
    fn test_watchdog_drain_state_tracking() {
        let mut wd = FencingWatchdog::new();

        // Before starting drain
        assert_eq!(wd.drain_state(node(3)), None);

        wd.start_drain(node(3));
        assert_eq!(wd.drain_state(node(3)), Some(NodeState::Draining));

        // After fencing
        wd.record_healthy(node(3), 0);
        let peers = vec![(node(3), HealthClass::Down, 0)];
        let _ = wd.tick(&peers, 100000, 1);

        assert_eq!(wd.drain_state(node(3)), Some(NodeState::Fenced));
    }

    #[test]
    fn test_watchdog_max_consecutive_fences() {
        let mut wd = FencingWatchdog::with_config(ForcedFencingConfig {
            fence_timeout_ms: 100,
            max_consecutive_fences: 2,
        });

        // First fence
        wd.record_healthy(node(1), 0);
        let peers = vec![(node(1), HealthClass::Down, 0)];
        let _ = wd.tick(&peers, 1000, 1);
        assert!(wd.is_fenced(node(1)));

        // Clear and re-fence
        wd.clear_fence(node(1), FenceToken::new(1)).unwrap();

        // Second fence
        wd.record_healthy(node(1), 2000);
        let peers2 = vec![(node(1), HealthClass::Down, 2000)];
        let _ = wd.tick(&peers2, 3000, 2);
        assert!(wd.is_fenced(node(1)));

        // Clear and try third fence — should be blocked
        wd.clear_fence(node(1), FenceToken::new(2)).unwrap();

        wd.record_healthy(node(1), 4000);
        let peers3 = vec![(node(1), HealthClass::Down, 4000)];
        let action = wd.tick(&peers3, 5000, 3);
        assert_eq!(action, FencingAction::None); // blocked by max_consecutive_fences
    }
}
