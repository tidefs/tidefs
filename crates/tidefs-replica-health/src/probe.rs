//! Replica liveness probing with configurable probe loop.
//!
//! Drives periodic liveness checks through transport sessions to determine
//! whether replicas are reachable. Uses a dedicated probe state machine
//! (Unknown -> Healthy -> Degraded -> Failed) with configurable thresholds,
//! feeding results into the degradation tracker and notifying listeners
//! on state transitions.

use crate::health_state::{HealthTransitionClass, HealthTransitionRecord, ReplicaHealthState};
use crate::NodeId;

/// Configuration for the replica liveness probe loop.
#[derive(Clone, Debug)]
pub struct ProbeConfig {
    /// Interval between consecutive probes to each replica (nanoseconds).
    pub probe_interval_ns: u64,
    /// Number of consecutive probe failures to transition Healthy -> Degraded.
    pub degradation_threshold: u32,
    /// Number of consecutive probe failures in Degraded to transition to Failed.
    pub failure_threshold: u32,
    /// Number of consecutive successful probes in Degraded to return to Healthy.
    pub recovery_threshold: u32,
    /// Per-probe timeout — if no response within this window, count as failure.
    pub probe_timeout_ns: u64,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        ProbeConfig {
            probe_interval_ns: 500_000_000,
            degradation_threshold: 3,
            failure_threshold: 5,
            recovery_threshold: 2,
            probe_timeout_ns: 1_000_000_000,
        }
    }
}

/// Simplified replica health state for liveness probing.
///
/// Four states with well-defined transitions driven by probe outcomes:
/// - Unknown: initial state, no probe has completed yet
/// - Healthy: replica is reachable and responding
/// - Degraded: replica is intermittently unreachable; still usable but flagged
/// - Failed: replica is persistently unreachable; excluded from placement
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ReplicaLivenessState {
    Unknown,
    Healthy,
    Degraded,
    Failed,
}

impl ReplicaLivenessState {
    pub fn is_placeable(&self) -> bool {
        matches!(
            self,
            ReplicaLivenessState::Healthy
                | ReplicaLivenessState::Degraded
                | ReplicaLivenessState::Unknown
        )
    }

    pub fn is_excluded(&self) -> bool {
        matches!(self, ReplicaLivenessState::Failed)
    }

    pub fn label(&self) -> &'static str {
        match self {
            ReplicaLivenessState::Unknown => "unknown",
            ReplicaLivenessState::Healthy => "healthy",
            ReplicaLivenessState::Degraded => "degraded",
            ReplicaLivenessState::Failed => "failed",
        }
    }
}

impl std::fmt::Display for ReplicaLivenessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Result of a single liveness probe attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeResult {
    pub replica_id: NodeId,
    pub success: bool,
    pub latency_ns: Option<u64>,
    pub probe_at_ns: u64,
    pub state_changed: bool,
    pub new_state: ReplicaLivenessState,
    pub previous_state: ReplicaLivenessState,
}

/// Per-replica liveness tracker driven by probe outcomes.
#[derive(Clone, Debug)]
pub struct ReplicaLivenessTracker {
    config: ProbeConfig,
    states: std::collections::BTreeMap<NodeId, ReplicaLivenessState>,
    failures: std::collections::BTreeMap<NodeId, u32>,
    successes: std::collections::BTreeMap<NodeId, u32>,
    last_transition: std::collections::BTreeMap<NodeId, u64>,
    transition_history: Vec<HealthTransitionRecord>,
}

impl ReplicaLivenessTracker {
    pub fn new(config: ProbeConfig) -> Self {
        ReplicaLivenessTracker {
            config,
            states: std::collections::BTreeMap::new(),
            failures: std::collections::BTreeMap::new(),
            successes: std::collections::BTreeMap::new(),
            last_transition: std::collections::BTreeMap::new(),
            transition_history: Vec::new(),
        }
    }

    pub fn record_probe_success(
        &mut self,
        replica_id: NodeId,
        latency_ns: u64,
        now_ns: u64,
    ) -> ProbeResult {
        let old_state = self.ensure_replica(replica_id);
        self.increment_success(replica_id);
        self.reset_failures(replica_id);

        let new_state = match old_state {
            ReplicaLivenessState::Unknown => ReplicaLivenessState::Healthy,
            ReplicaLivenessState::Degraded => {
                let cons_success = self.successes.get(&replica_id).copied().unwrap_or(0);
                if cons_success >= self.config.recovery_threshold {
                    ReplicaLivenessState::Healthy
                } else {
                    ReplicaLivenessState::Degraded
                }
            }
            ReplicaLivenessState::Failed => {
                let cons_success = self.successes.get(&replica_id).copied().unwrap_or(0);
                if cons_success >= self.config.recovery_threshold {
                    ReplicaLivenessState::Healthy
                } else {
                    ReplicaLivenessState::Failed
                }
            }
            other => other,
        };

        let changed = old_state != new_state;
        if changed {
            self.states.insert(replica_id, new_state);
            self.last_transition.insert(replica_id, now_ns);
            if new_state == ReplicaLivenessState::Healthy {
                self.reset_successes(replica_id);
            }
            self.transition_history.push(HealthTransitionRecord {
                from_state: liveness_to_health_state(old_state, replica_id),
                to_state: liveness_to_health_state(new_state, replica_id),
                transition_class: HealthTransitionClass::Recovery,
                epoch: 0,
                reason: format!("probe success from {}", old_state.label()),
            });
        }

        ProbeResult {
            replica_id,
            success: true,
            latency_ns: Some(latency_ns),
            probe_at_ns: now_ns,
            state_changed: changed,
            new_state,
            previous_state: old_state,
        }
    }

    pub fn record_probe_failure(&mut self, replica_id: NodeId, now_ns: u64) -> ProbeResult {
        let old_state = self.ensure_replica(replica_id);
        self.reset_successes(replica_id);
        self.increment_failure(replica_id);
        let cons_failures = self.failures.get(&replica_id).copied().unwrap_or(0);

        let new_state = match old_state {
            ReplicaLivenessState::Unknown => {
                if cons_failures >= self.config.degradation_threshold {
                    ReplicaLivenessState::Degraded
                } else {
                    ReplicaLivenessState::Unknown
                }
            }
            ReplicaLivenessState::Healthy => {
                if cons_failures >= self.config.degradation_threshold {
                    ReplicaLivenessState::Degraded
                } else {
                    ReplicaLivenessState::Healthy
                }
            }
            ReplicaLivenessState::Degraded => {
                if cons_failures >= self.config.failure_threshold {
                    ReplicaLivenessState::Failed
                } else {
                    ReplicaLivenessState::Degraded
                }
            }
            other => other,
        };

        let changed = old_state != new_state;
        if changed {
            self.states.insert(replica_id, new_state);
            self.last_transition.insert(replica_id, now_ns);
            if new_state == ReplicaLivenessState::Degraded
                || new_state == ReplicaLivenessState::Failed
            {
                self.reset_failures(replica_id);
            }
            self.transition_history.push(HealthTransitionRecord {
                from_state: liveness_to_health_state(old_state, replica_id),
                to_state: liveness_to_health_state(new_state, replica_id),
                transition_class: HealthTransitionClass::Degradation,
                epoch: 0,
                reason: format!(
                    "probe failure from {} ({} consecutive)",
                    old_state.label(),
                    cons_failures
                ),
            });
        }

        ProbeResult {
            replica_id,
            success: false,
            latency_ns: None,
            probe_at_ns: now_ns,
            state_changed: changed,
            new_state,
            previous_state: old_state,
        }
    }

    pub fn mark_rebuild_initiated(&mut self, replica_id: NodeId, now_ns: u64) -> ProbeResult {
        let old_state = self.current_state(replica_id);
        if old_state != ReplicaLivenessState::Failed && old_state != ReplicaLivenessState::Degraded
        {
            return ProbeResult {
                replica_id,
                success: false,
                latency_ns: None,
                probe_at_ns: now_ns,
                state_changed: false,
                new_state: old_state,
                previous_state: old_state,
            };
        }

        self.states
            .insert(replica_id, ReplicaLivenessState::Healthy);
        self.reset_failures(replica_id);
        self.reset_successes(replica_id);
        self.last_transition.insert(replica_id, now_ns);
        self.transition_history.push(HealthTransitionRecord {
            from_state: liveness_to_health_state(old_state, replica_id),
            to_state: liveness_to_health_state(ReplicaLivenessState::Healthy, replica_id),
            transition_class: HealthTransitionClass::Recovery,
            epoch: 0,
            reason: "rebuild initiated externally".into(),
        });

        ProbeResult {
            replica_id,
            success: true,
            latency_ns: None,
            probe_at_ns: now_ns,
            state_changed: true,
            new_state: ReplicaLivenessState::Healthy,
            previous_state: old_state,
        }
    }

    pub fn current_state(&mut self, replica_id: NodeId) -> ReplicaLivenessState {
        self.ensure_replica(replica_id)
    }

    pub fn count_in_state(&self, state: ReplicaLivenessState) -> usize {
        self.states.values().filter(|s| **s == state).count()
    }

    pub fn tracked_count(&self) -> usize {
        self.states.len()
    }

    pub fn consecutive_failures(&self, replica_id: NodeId) -> u32 {
        self.failures.get(&replica_id).copied().unwrap_or(0)
    }

    pub fn consecutive_successes(&self, replica_id: NodeId) -> u32 {
        self.successes.get(&replica_id).copied().unwrap_or(0)
    }

    pub fn snapshot(&self) -> ReplicaLivenessSnapshot {
        let mut healthy = 0u64;
        let mut degraded = 0u64;
        let mut failed = 0u64;
        let mut unknown = 0u64;

        for state in self.states.values() {
            match state {
                ReplicaLivenessState::Healthy => healthy += 1,
                ReplicaLivenessState::Degraded => degraded += 1,
                ReplicaLivenessState::Failed => failed += 1,
                ReplicaLivenessState::Unknown => unknown += 1,
            }
        }

        let total = healthy + degraded + failed + unknown;

        ReplicaLivenessSnapshot {
            healthy_count: healthy,
            degraded_count: degraded,
            failed_count: failed,
            unknown_count: unknown,
            rebuilding_count: 0,
            total_count: total,
        }
    }

    pub fn drain_history(&mut self) -> Vec<HealthTransitionRecord> {
        std::mem::take(&mut self.transition_history)
    }

    fn ensure_replica(&mut self, replica_id: NodeId) -> ReplicaLivenessState {
        self.states.get(&replica_id).copied().unwrap_or_else(|| {
            self.states
                .insert(replica_id, ReplicaLivenessState::Unknown);
            ReplicaLivenessState::Unknown
        })
    }

    fn increment_failure(&mut self, replica_id: NodeId) {
        let entry = self.failures.entry(replica_id).or_insert(0);
        *entry += 1;
    }

    fn increment_success(&mut self, replica_id: NodeId) {
        let entry = self.successes.entry(replica_id).or_insert(0);
        *entry += 1;
    }

    fn reset_failures(&mut self, replica_id: NodeId) {
        self.failures.insert(replica_id, 0);
    }

    fn reset_successes(&mut self, replica_id: NodeId) {
        self.successes.insert(replica_id, 0);
    }
}

fn liveness_to_health_state(state: ReplicaLivenessState, replica_id: NodeId) -> ReplicaHealthState {
    match state {
        ReplicaLivenessState::Unknown => ReplicaHealthState::Absent,
        ReplicaLivenessState::Healthy => ReplicaHealthState::Healthy {
            receipt_id: replica_id.0,
            last_verified_ns: 0,
        },
        ReplicaLivenessState::Degraded => ReplicaHealthState::Degraded {
            degraded_since_ns: 0,
            missing_chunks: 0,
            corrupt_chunks: 0,
        },
        ReplicaLivenessState::Failed => ReplicaHealthState::Degraded {
            degraded_since_ns: 0,
            missing_chunks: 1,
            corrupt_chunks: 0,
        },
    }
}

/// Snapshot of replica liveness counts for batch health queries.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReplicaLivenessSnapshot {
    pub healthy_count: u64,
    pub degraded_count: u64,
    pub failed_count: u64,
    pub unknown_count: u64,
    pub rebuilding_count: u64,
    pub total_count: u64,
}

impl ReplicaLivenessSnapshot {
    pub fn all_healthy(&self) -> bool {
        self.degraded_count == 0
            && self.failed_count == 0
            && self.unknown_count == 0
            && self.rebuilding_count == 0
    }

    pub fn can_quorum_write(&self, required_acks: u64) -> bool {
        self.healthy_count + self.degraded_count >= required_acks
    }

    pub fn placeable_count(&self) -> u64 {
        self.healthy_count + self.degraded_count + self.unknown_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> ReplicaLivenessTracker {
        ReplicaLivenessTracker::new(ProbeConfig::default())
    }

    #[test]
    fn unknown_to_healthy_on_first_success() {
        let mut t = tracker();
        let node = NodeId::new(1);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Unknown);

        let result = t.record_probe_success(node, 1_000_000, 1000);
        assert!(result.state_changed);
        assert_eq!(result.new_state, ReplicaLivenessState::Healthy);
        assert_eq!(result.previous_state, ReplicaLivenessState::Unknown);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);
    }

    #[test]
    fn healthy_stays_healthy_on_successes() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_probe_success(node, 1_000_000, 1000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);
        for _ in 0..10 {
            let result = t.record_probe_success(node, 1_000_000, 2000);
            assert!(!result.state_changed);
            assert_eq!(result.new_state, ReplicaLivenessState::Healthy);
        }
    }

    #[test]
    fn healthy_to_degraded_on_consecutive_failures() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_probe_success(node, 1_000_000, 1000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);

        t.record_probe_failure(node, 2000);
        t.record_probe_failure(node, 3000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);
        assert_eq!(t.consecutive_failures(node), 2);

        let result = t.record_probe_failure(node, 4000);
        assert!(result.state_changed);
        assert_eq!(result.new_state, ReplicaLivenessState::Degraded);
        assert_eq!(result.previous_state, ReplicaLivenessState::Healthy);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Degraded);
    }

    #[test]
    fn degraded_to_failed_on_consecutive_failures() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_probe_success(node, 1_000_000, 1000);
        t.record_probe_failure(node, 2000);
        t.record_probe_failure(node, 3000);
        t.record_probe_failure(node, 4000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Degraded);

        for i in 0..4 {
            t.record_probe_failure(node, 5000 + i * 1000);
            assert_eq!(t.current_state(node), ReplicaLivenessState::Degraded);
        }

        let result = t.record_probe_failure(node, 10000);
        assert!(result.state_changed);
        assert_eq!(result.new_state, ReplicaLivenessState::Failed);
        assert_eq!(result.previous_state, ReplicaLivenessState::Degraded);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Failed);
    }

    #[test]
    fn failed_stays_failed_on_more_failures() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_probe_success(node, 1_000_000, 1000);
        for _ in 0..3 {
            t.record_probe_failure(node, 2000);
        }
        for _ in 0..5 {
            t.record_probe_failure(node, 3000);
        }
        assert_eq!(t.current_state(node), ReplicaLivenessState::Failed);

        for _ in 0..10 {
            let result = t.record_probe_failure(node, 4000);
            assert!(!result.state_changed);
            assert_eq!(result.new_state, ReplicaLivenessState::Failed);
        }
    }

    #[test]
    fn degraded_to_healthy_on_recovery_successes() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_probe_success(node, 1_000_000, 1000);
        t.record_probe_failure(node, 2000);
        t.record_probe_failure(node, 3000);
        t.record_probe_failure(node, 4000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Degraded);

        t.record_probe_success(node, 1_000_000, 5000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Degraded);
        let result = t.record_probe_success(node, 1_000_000, 6000);
        assert!(result.state_changed);
        assert_eq!(result.new_state, ReplicaLivenessState::Healthy);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);
    }

    #[test]
    fn failed_to_healthy_on_recovery_successes() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_probe_success(node, 1_000_000, 1000);
        for _ in 0..3 {
            t.record_probe_failure(node, 2000);
        }
        for _ in 0..5 {
            t.record_probe_failure(node, 3000);
        }
        assert_eq!(t.current_state(node), ReplicaLivenessState::Failed);

        t.record_probe_success(node, 1_000_000, 10000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Failed);
        let result = t.record_probe_success(node, 1_000_000, 11000);
        assert!(result.state_changed);
        assert_eq!(result.new_state, ReplicaLivenessState::Healthy);
    }

    #[test]
    fn success_resets_failure_counter() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_probe_success(node, 1_000_000, 1000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);

        t.record_probe_failure(node, 2000);
        t.record_probe_failure(node, 3000);
        assert_eq!(t.consecutive_failures(node), 2);

        t.record_probe_success(node, 1_000_000, 4000);
        assert_eq!(t.consecutive_failures(node), 0);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);

        t.record_probe_failure(node, 5000);
        t.record_probe_failure(node, 6000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);
        t.record_probe_failure(node, 7000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Degraded);
    }

    #[test]
    fn rebuild_initiated_from_failed() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_probe_success(node, 1_000_000, 1000);
        for _ in 0..3 {
            t.record_probe_failure(node, 2000);
        }
        for _ in 0..5 {
            t.record_probe_failure(node, 3000);
        }
        assert_eq!(t.current_state(node), ReplicaLivenessState::Failed);

        let result = t.mark_rebuild_initiated(node, 10000);
        assert!(result.state_changed);
        assert_eq!(result.new_state, ReplicaLivenessState::Healthy);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);
        assert_eq!(t.consecutive_failures(node), 0);
        assert_eq!(t.consecutive_successes(node), 0);
    }

    #[test]
    fn rebuild_initiated_from_healthy_is_noop() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_probe_success(node, 1_000_000, 1000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);

        let result = t.mark_rebuild_initiated(node, 2000);
        assert!(!result.state_changed);
        assert_eq!(result.new_state, ReplicaLivenessState::Healthy);
    }

    #[test]
    fn snapshot_counts_by_state() {
        let mut t = tracker();
        t.record_probe_success(NodeId::new(1), 1_000_000, 1000);
        t.record_probe_success(NodeId::new(2), 1_000_000, 1000);
        t.record_probe_failure(NodeId::new(2), 2000);
        t.record_probe_failure(NodeId::new(2), 3000);
        t.record_probe_failure(NodeId::new(2), 4000);
        t.record_probe_success(NodeId::new(4), 1_000_000, 1000);
        for _ in 0..3 {
            t.record_probe_failure(NodeId::new(4), 2000);
        }
        for _ in 0..5 {
            t.record_probe_failure(NodeId::new(4), 3000);
        }
        let _ = t.current_state(NodeId::new(3));

        let snap = t.snapshot();
        assert_eq!(snap.healthy_count, 1);
        assert_eq!(snap.degraded_count, 1);
        assert_eq!(snap.failed_count, 1);
        assert_eq!(snap.unknown_count, 1);
        assert_eq!(snap.total_count, 4);
        assert!(!snap.all_healthy());
    }

    #[test]
    fn snapshot_all_healthy() {
        let mut t = tracker();
        t.record_probe_success(NodeId::new(1), 1_000_000, 1000);
        t.record_probe_success(NodeId::new(2), 1_000_000, 1000);
        let snap = t.snapshot();
        assert_eq!(snap.healthy_count, 2);
        assert_eq!(snap.total_count, 2);
        assert!(snap.all_healthy());
    }

    #[test]
    fn can_quorum_write_with_enough_healthy() {
        let mut t = tracker();
        for id in 1..=5 {
            t.record_probe_success(NodeId::new(id), 1_000_000, 1000);
        }
        let snap = t.snapshot();
        assert!(snap.can_quorum_write(3));
        assert!(snap.can_quorum_write(5));
        assert!(!snap.can_quorum_write(6));
    }

    #[test]
    fn can_quorum_write_with_degraded() {
        let mut t = tracker();
        for id in 1..=2 {
            t.record_probe_success(NodeId::new(id), 1_000_000, 1000);
        }
        t.record_probe_success(NodeId::new(3), 1_000_000, 1000);
        for _ in 0..3 {
            t.record_probe_failure(NodeId::new(3), 2000);
        }
        assert_eq!(
            t.current_state(NodeId::new(3)),
            ReplicaLivenessState::Degraded
        );

        let snap = t.snapshot();
        assert!(snap.can_quorum_write(2));
        assert!(snap.can_quorum_write(3));
        assert!(!snap.can_quorum_write(4));
    }

    #[test]
    fn placeable_count_includes_healthy_degraded_unknown() {
        let mut t = tracker();
        t.record_probe_success(NodeId::new(1), 1_000_000, 1000);
        t.record_probe_success(NodeId::new(2), 1_000_000, 1000);
        for _ in 0..3 {
            t.record_probe_failure(NodeId::new(2), 2000);
        }
        let _ = t.current_state(NodeId::new(3));
        t.record_probe_success(NodeId::new(4), 1_000_000, 1000);
        for _ in 0..3 {
            t.record_probe_failure(NodeId::new(4), 2000);
        }
        for _ in 0..5 {
            t.record_probe_failure(NodeId::new(4), 3000);
        }

        let snap = t.snapshot();
        assert_eq!(snap.placeable_count(), 3);
    }

    #[test]
    fn unknown_to_degraded_on_consecutive_failures_alt() {
        let mut t = tracker();
        let node = NodeId::new(1);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Unknown);

        t.record_probe_failure(node, 1000);
        t.record_probe_failure(node, 2000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Unknown);

        let result = t.record_probe_failure(node, 3000);
        assert!(result.state_changed);
        assert_eq!(result.new_state, ReplicaLivenessState::Degraded);
    }

    #[test]
    fn degraded_with_intermittent_successes_does_not_recover() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_probe_success(node, 1_000_000, 1000);
        t.record_probe_failure(node, 2000);
        t.record_probe_failure(node, 3000);
        t.record_probe_failure(node, 4000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Degraded);

        t.record_probe_success(node, 1_000_000, 5000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Degraded);
        t.record_probe_failure(node, 6000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Degraded);
        assert_eq!(t.consecutive_successes(node), 0);
    }

    #[test]
    fn drain_history_captures_transitions() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_probe_success(node, 1_000_000, 1000);
        t.record_probe_failure(node, 2000);
        t.record_probe_failure(node, 3000);
        t.record_probe_failure(node, 4000);
        t.record_probe_failure(node, 5000);
        t.record_probe_failure(node, 6000);
        t.record_probe_failure(node, 7000);
        t.record_probe_failure(node, 8000);
        t.record_probe_failure(node, 9000);

        let history = t.drain_history();
        assert!(!history.is_empty());
        assert!(history.len() >= 3);
        assert!(t.drain_history().is_empty());
    }

    #[test]
    fn custom_thresholds() {
        let config = ProbeConfig {
            degradation_threshold: 2,
            failure_threshold: 2,
            recovery_threshold: 1,
            ..ProbeConfig::default()
        };
        let mut t = ReplicaLivenessTracker::new(config);
        let node = NodeId::new(1);

        t.record_probe_success(node, 1_000_000, 1000);
        t.record_probe_failure(node, 2000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);
        t.record_probe_failure(node, 3000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Degraded);

        t.record_probe_failure(node, 4000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Degraded);
        t.record_probe_failure(node, 5000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Failed);

        let result = t.record_probe_success(node, 1_000_000, 6000);
        assert!(result.state_changed);
        assert_eq!(result.new_state, ReplicaLivenessState::Healthy);
    }

    #[test]
    fn probe_result_contains_latency_on_success() {
        let mut t = tracker();
        let node = NodeId::new(1);
        let result = t.record_probe_success(node, 5_000_000, 1000);
        assert!(result.success);
        assert_eq!(result.latency_ns, Some(5_000_000));
        assert_eq!(result.probe_at_ns, 1000);
        assert!(result.state_changed);
        assert_eq!(result.replica_id, node);
    }

    #[test]
    fn probe_result_no_latency_on_failure() {
        let mut t = tracker();
        let node = NodeId::new(1);
        let result = t.record_probe_failure(node, 1000);
        assert!(!result.success);
        assert_eq!(result.latency_ns, None);
        assert_eq!(result.probe_at_ns, 1000);
    }

    #[test]
    fn liveness_state_predicates() {
        assert!(ReplicaLivenessState::Unknown.is_placeable());
        assert!(ReplicaLivenessState::Healthy.is_placeable());
        assert!(ReplicaLivenessState::Degraded.is_placeable());
        assert!(!ReplicaLivenessState::Failed.is_placeable());

        assert!(!ReplicaLivenessState::Unknown.is_excluded());
        assert!(!ReplicaLivenessState::Healthy.is_excluded());
        assert!(!ReplicaLivenessState::Degraded.is_excluded());
        assert!(ReplicaLivenessState::Failed.is_excluded());
    }

    #[test]
    fn liveness_state_display() {
        assert_eq!(ReplicaLivenessState::Unknown.to_string(), "unknown");
        assert_eq!(ReplicaLivenessState::Healthy.to_string(), "healthy");
        assert_eq!(ReplicaLivenessState::Degraded.to_string(), "degraded");
        assert_eq!(ReplicaLivenessState::Failed.to_string(), "failed");
    }

    #[test]
    fn count_in_state_aggregates_by_state() {
        let mut t = tracker();
        t.record_probe_success(NodeId::new(1), 1_000_000, 1000);
        t.record_probe_success(NodeId::new(2), 1_000_000, 1000);
        t.record_probe_success(NodeId::new(3), 1_000_000, 1000);
        assert_eq!(t.count_in_state(ReplicaLivenessState::Healthy), 3);
        assert_eq!(t.count_in_state(ReplicaLivenessState::Degraded), 0);
        assert_eq!(t.count_in_state(ReplicaLivenessState::Failed), 0);
    }

    #[test]
    fn snapshot_reflects_current_distribution() {
        let mut t = tracker();
        t.record_probe_success(NodeId::new(1), 1_000_000, 1000);
        t.record_probe_success(NodeId::new(2), 1_000_000, 1000);
        // Degrade NodeId::new(3)
        for _ in 0..3 {
            t.record_probe_failure(NodeId::new(3), 2000);
        }
        // Fail NodeId::new(4)
        for _ in 0..3 {
            t.record_probe_failure(NodeId::new(4), 2000);
        }
        for _ in 0..5 {
            t.record_probe_failure(NodeId::new(4), 3000);
        }

        let snap = t.snapshot();
        assert_eq!(snap.healthy_count, 2);
        assert_eq!(snap.degraded_count, 1);
        assert_eq!(snap.failed_count, 1);
        assert_eq!(snap.unknown_count, 0);
        assert_eq!(snap.total_count, 4);
    }

    #[test]
    fn snapshot_all_healthy_when_no_failures() {
        let mut t = tracker();
        t.record_probe_success(NodeId::new(1), 1_000_000, 1000);
        t.record_probe_success(NodeId::new(2), 1_000_000, 1000);
        let snap = t.snapshot();
        assert!(snap.all_healthy());
    }

    #[test]
    fn snapshot_not_all_healthy_when_degraded_present() {
        let mut t = tracker();
        t.record_probe_success(NodeId::new(1), 1_000_000, 1000);
        for _ in 0..3 {
            t.record_probe_failure(NodeId::new(2), 2000);
        }
        let snap = t.snapshot();
        assert!(!snap.all_healthy());
    }

    #[test]
    fn drain_history_clears_and_returns_transitions() {
        let mut t = tracker();
        t.record_probe_success(NodeId::new(1), 1_000_000, 1000);
        for _ in 0..3 {
            t.record_probe_failure(NodeId::new(1), 2000);
        }
        // Should have at least: Unknown->Healthy (success), Healthy->Degraded (3 failures)
        let history = t.drain_history();
        assert!(history.len() >= 2);
        // Second drain returns empty
        let empty = t.drain_history();
        assert!(empty.is_empty());
    }

    #[test]
    fn tracked_count_reflects_unique_replicas() {
        let mut t = tracker();
        assert_eq!(t.tracked_count(), 0);
        t.record_probe_success(NodeId::new(1), 1_000_000, 1000);
        assert_eq!(t.tracked_count(), 1);
        t.record_probe_success(NodeId::new(2), 1_000_000, 1000);
        assert_eq!(t.tracked_count(), 2);
        // Same replica doesn't double-count
        t.record_probe_success(NodeId::new(1), 1_000_000, 2000);
        assert_eq!(t.tracked_count(), 2);
    }

    #[test]
    fn unknown_to_degraded_on_three_failures() {
        let mut t = tracker();
        let node = NodeId::new(1);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Unknown);

        t.record_probe_failure(node, 1000);
        t.record_probe_failure(node, 2000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Unknown);
        assert_eq!(t.consecutive_failures(node), 2);

        let result = t.record_probe_failure(node, 3000);
        assert!(result.state_changed);
        assert_eq!(result.new_state, ReplicaLivenessState::Degraded);
        assert_eq!(result.previous_state, ReplicaLivenessState::Unknown);
    }

    #[test]
    fn snapshot_can_quorum_write() {
        let mut t = tracker();
        t.record_probe_success(NodeId::new(1), 1_000_000, 1000);
        t.record_probe_success(NodeId::new(2), 1_000_000, 1000);
        t.record_probe_success(NodeId::new(3), 1_000_000, 1000);
        // Degrade NodeId::new(4)
        for _ in 0..3 {
            t.record_probe_failure(NodeId::new(4), 2000);
        }
        // Fail NodeId::new(5)
        for _ in 0..3 {
            t.record_probe_failure(NodeId::new(5), 2000);
        }
        for _ in 0..5 {
            t.record_probe_failure(NodeId::new(5), 3000);
        }

        let snap = t.snapshot();
        // healthy=3, degraded=1, failed=1; placeable=healthy+degraded+unknown=4
        assert!(snap.can_quorum_write(3));
        assert!(snap.can_quorum_write(4));
        assert!(!snap.can_quorum_write(5));
        assert_eq!(snap.placeable_count(), 4); // healthy+degraded+unknown (failed excluded)
    }

    #[test]
    fn rebuild_initiated_from_healthy_is_no_op() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_probe_success(node, 1_000_000, 1000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);

        let result = t.mark_rebuild_initiated(node, 2000);
        assert!(!result.state_changed);
        assert_eq!(result.new_state, ReplicaLivenessState::Healthy);
    }

    #[test]
    fn probe_failure_accumulates_to_failed_then_success_brings_back() {
        let mut t = tracker();
        let node = NodeId::new(1);
        // Unknown -> Healthy via success
        t.record_probe_success(node, 1_000_000, 1000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);

        // Healthy -> Degraded: 3 consecutive failures
        t.record_probe_failure(node, 2000);
        t.record_probe_failure(node, 3000);
        t.record_probe_failure(node, 4000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Degraded);

        // Degraded -> Failed: 5 consecutive failures
        for _ in 0..5 {
            t.record_probe_failure(node, 5000);
        }
        assert_eq!(t.current_state(node), ReplicaLivenessState::Failed);

        // Failed -> Healthy: 2 consecutive successes
        t.record_probe_success(node, 1_000_000, 10000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Failed);
        t.record_probe_success(node, 1_000_000, 11000);
        assert_eq!(t.current_state(node), ReplicaLivenessState::Healthy);
    }
}
