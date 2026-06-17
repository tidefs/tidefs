#![forbid(unsafe_code)]

//! Replica health: per-chunk degradation tracking, BLAKE3-authenticated
//! health probes, epoch-gated quorum aggregation, adaptive failure
//! detection, and lag computation — P8-03 data_copy_3.
//!
//! # Design
//!
//! TideFS replica health is:
//! - **per-chunk**, not per-PG (unlike Ceph)
//! - **receipt-backed**, not heartbeat-only (unlike Cassandra)
//! - **dual-source**: receipt chains for optimistic frontier;
//!   anti-entropy for ground-truth verification
//! - **adaptive**: timeout windows widen during network instability
//! - **flap-suppressed**: flapping nodes get exponential backoff,
//!   preventing cascading data movement (unlike Ceph OSD flap amplification)

pub mod adaptive_timeout;
pub mod background;
pub mod flap_detector;
pub mod health_probe;
pub mod health_quorum;
pub mod health_state;
pub mod health_tracker;
pub mod lag;
pub mod notifier;
pub mod probe;
pub mod propagation;
pub mod scoring;
pub mod state_machine;
pub mod suspicion;
pub mod tracker;

// Re-exports from health_probe and health_quorum modules.
pub use health_probe::{
    AuthTag, HealthAttestation, HealthProbe, HealthSample, Nonce,
    ProbeEvidenceClass, SharedSecret,
};
pub use health_quorum::{HealthQuorum, QuorumHealthResult, QuorumHealthStatus};

/// A chunk identifier — opaque key used to track per-chunk health.
#[derive(
    Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub struct ChunkId(pub u64);

impl ChunkId {
    pub fn new(id: u64) -> Self {
        ChunkId(id)
    }
}

/// A node identifier for tracking replica placement across cluster members.
#[derive(
    Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub struct NodeId(pub u64);

impl NodeId {
    pub fn new(id: u64) -> Self {
        NodeId(id)
    }
}

/// Bytes-behind measurement for lag computation.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct BytesBehind(pub u64);

impl BytesBehind {
    pub fn new(bytes: u64) -> Self {
        BytesBehind(bytes)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl std::ops::Sub for BytesBehind {
    type Output = BytesBehind;
    fn sub(self, rhs: Self) -> Self::Output {
        BytesBehind(self.0.saturating_sub(rhs.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_id_roundtrip() {
        let id = ChunkId::new(42);
        assert_eq!(id.0, 42);
    }

    #[test]
    fn node_id_roundtrip() {
        let id = NodeId::new(7);
        assert_eq!(id.0, 7);
    }

    #[test]
    fn bytes_behind_arithmetic() {
        let a = BytesBehind::new(100);
        let b = BytesBehind::new(30);
        assert_eq!((a - b).0, 70);
        assert_eq!((b - a).0, 0); // saturating
    }
}

// ── Per-replica degradation tracking ───────────────────────────────
// Issue #5165: Replica-level degradation state machine driven by I/O
// success/failure, latency, and BLAKE3 checksum mismatches.

use std::collections::BTreeMap;

/// Per-replica degradation tracker that couples the state machine
/// with rolling I/O scoring to produce health metrics for the
/// placement planner (#5157) and rebuild planner (#5153).
#[derive(Debug)]
pub struct ReplicaDegradationTracker {
    scorer_config: scoring::ScoreConfig,
    degradation_config: state_machine::DegradationConfig,
    /// Timeout (ns) after which a replica with no I/O is considered stale.
    stale_timeout_ns: u64,
    /// Per-replica transition engines.
    engines: BTreeMap<NodeId, state_machine::DegradationTransitionEngine>,
    /// Per-replica I/O scorers.
    scorers: BTreeMap<NodeId, scoring::ReplicaHealthScorer>,
    /// Timestamp (ns) of last I/O for each replica.
    last_io_ns: BTreeMap<NodeId, u64>,
}

impl ReplicaDegradationTracker {
    pub fn new(
        scorer_config: scoring::ScoreConfig,
        degradation_config: state_machine::DegradationConfig,
    ) -> Self {
        ReplicaDegradationTracker {
            scorer_config,
            degradation_config,
            stale_timeout_ns: 30_000_000_000, // 30s default
            engines: BTreeMap::new(),
            scorers: BTreeMap::new(),
            last_io_ns: BTreeMap::new(),
        }
    }

    /// Create a tracker with a custom stale timeout.
    pub fn with_stale_timeout(
        scorer_config: scoring::ScoreConfig,
        degradation_config: state_machine::DegradationConfig,
        stale_timeout_ns: u64,
    ) -> Self {
        ReplicaDegradationTracker {
            scorer_config,
            degradation_config,
            stale_timeout_ns,
            engines: BTreeMap::new(),
            scorers: BTreeMap::new(),
            last_io_ns: BTreeMap::new(),
        }
    }

    /// Record a successful I/O operation for a replica.
    /// Returns the transition result from the state machine.
    pub fn record_success(
        &mut self,
        replica_id: NodeId,
        now_ns: u64,
        latency_us: u64,
    ) -> state_machine::TransitionResult {
        self.last_io_ns.insert(replica_id, now_ns);
        let (engine, scorer) = self.ensure_replica(replica_id);
        scorer.record_success(latency_us);
        let result = engine.record_success(now_ns, latency_us);
        scorer.set_degradation_state(result.new_state);
        result
    }

    /// Record a failed I/O operation for a replica.
    pub fn record_failure(
        &mut self,
        replica_id: NodeId,
        now_ns: u64,
        latency_us: u64,
        unrecoverable: bool,
    ) -> state_machine::TransitionResult {
        self.last_io_ns.insert(replica_id, now_ns);
        let (engine, scorer) = self.ensure_replica(replica_id);
        scorer.record_failure(latency_us, unrecoverable);
        let result = engine.record_failure(now_ns, unrecoverable);
        scorer.set_degradation_state(result.new_state);
        result
    }

    /// Record a BLAKE3 checksum mismatch for a replica.
    pub fn record_checksum_mismatch(
        &mut self,
        replica_id: NodeId,
        now_ns: u64,
        latency_us: u64,
    ) -> state_machine::TransitionResult {
        self.last_io_ns.insert(replica_id, now_ns);
        let (engine, scorer) = self.ensure_replica(replica_id);
        scorer.record_checksum_mismatch(latency_us);
        let result = engine.record_checksum_mismatch(now_ns);
        scorer.set_degradation_state(result.new_state);
        result
    }

    /// Force a state transition (e.g., admin action or external detector).
    pub fn force_state(
        &mut self,
        replica_id: NodeId,
        new_state: state_machine::DegradationState,
        now_ns: u64,
    ) -> state_machine::TransitionResult {
        self.last_io_ns.insert(replica_id, now_ns);
        let (engine, scorer) = self.ensure_replica(replica_id);
        let result = engine.force_state(new_state, now_ns);
        scorer.set_degradation_state(result.new_state);
        result
    }

    /// Get the current degradation state for a replica.
    pub fn degradation_state(&self, replica_id: NodeId) -> state_machine::DegradationState {
        self.engines
            .get(&replica_id)
            .map(|e| e.state())
            .unwrap_or(state_machine::DegradationState::Healthy)
    }

    /// Compute the current health score for a replica.
    pub fn compute_score(
        &self,
        replica_id: NodeId,
        now_ns: u64,
    ) -> Option<scoring::ReplicaHealthScore> {
        self.scorers
            .get(&replica_id)
            .map(|s| s.compute_score(now_ns))
    }

    /// Export health metrics for a replica.
    pub fn export_metrics(
        &self,
        replica_id: NodeId,
        now_ns: u64,
    ) -> Option<scoring::ReplicaHealthMetrics> {
        let scorer = self.scorers.get(&replica_id)?;
        let score = scorer.compute_score(now_ns);
        Some(scoring::ReplicaHealthMetrics::from_score(
            replica_id.0,
            &score,
            scorer.lifetime_ops(),
        ))
    }

    /// Export health metrics for all tracked replicas.
    pub fn export_all_metrics(&self, now_ns: u64) -> Vec<scoring::ReplicaHealthMetrics> {
        self.scorers
            .iter()
            .map(|(node_id, scorer)| {
                let score = scorer.compute_score(now_ns);
                scoring::ReplicaHealthMetrics::from_score(node_id.0, &score, scorer.lifetime_ops())
            })
            .collect()
    }

    /// Count of tracked replicas.
    pub fn tracked_count(&self) -> usize {
        self.engines.len()
    }

    /// Whether a specific replica is eligible for new placement.
    pub fn is_placeable(&self, replica_id: NodeId) -> bool {
        self.degradation_state(replica_id).is_placeable()
    }

    /// Whether a specific replica is excluded from all I/O.
    pub fn is_excluded(&self, replica_id: NodeId) -> bool {
        self.degradation_state(replica_id).is_excluded()
    }

    /// Timestamp (ns) of the last I/O recorded for a replica.
    /// Returns None if the replica has never been seen.
    pub fn last_seen(&self, replica_id: NodeId) -> Option<u64> {
        self.last_io_ns.get(&replica_id).copied()
    }

    /// Check all tracked replicas for staleness and transition
    /// silent replicas past their timeout to Dead.
    ///
    /// Returns a list of replicas that were transitioned to Dead
    /// due to staleness, with their previous state and reason.
    pub fn check_stale(
        &mut self,
        now_ns: u64,
    ) -> Vec<(
        NodeId,
        state_machine::DegradationState,
        state_machine::TransitionResult,
    )> {
        let mut stale = Vec::new();
        let replica_ids: Vec<NodeId> = self.engines.keys().copied().collect();
        let timeout = self.stale_timeout_ns;

        for replica_id in replica_ids {
            let last = self.last_io_ns.get(&replica_id).copied().unwrap_or(0);
            if now_ns.saturating_sub(last) > timeout {
                let current_state = self.degradation_state(replica_id);
                // Only transition if not already Dead or Recovering
                if current_state != state_machine::DegradationState::Dead {
                    let result =
                        self.force_state(replica_id, state_machine::DegradationState::Dead, now_ns);
                    stale.push((replica_id, current_state, result));
                }
            }
        }
        stale
    }

    /// Set the stale timeout (ns). After this duration without I/O,
    /// a replica is transitioned to Dead by check_stale().
    pub fn set_stale_timeout(&mut self, timeout_ns: u64) {
        self.stale_timeout_ns = timeout_ns;
    }

    /// Get the current stale timeout (ns).
    pub fn stale_timeout(&self) -> u64 {
        self.stale_timeout_ns
    }

    /// Remove a replica from tracking entirely.
    pub fn remove_replica(&mut self, replica_id: NodeId) -> bool {
        let removed = self.engines.remove(&replica_id).is_some();
        self.scorers.remove(&replica_id);
        self.last_io_ns.remove(&replica_id);
        removed
    }

    // ── Internal ────────────────────────────────────────────────

    fn ensure_replica(
        &mut self,
        replica_id: NodeId,
    ) -> (
        &mut state_machine::DegradationTransitionEngine,
        &mut scoring::ReplicaHealthScorer,
    ) {
        if !self.engines.contains_key(&replica_id) {
            self.engines.insert(
                replica_id,
                state_machine::DegradationTransitionEngine::new(self.degradation_config.clone()),
            );
            self.scorers.insert(
                replica_id,
                scoring::ReplicaHealthScorer::new(self.scorer_config.clone()),
            );
        }
        (
            self.engines.get_mut(&replica_id).unwrap(),
            self.scorers.get_mut(&replica_id).unwrap(),
        )
    }
}

#[cfg(test)]
mod degradation_tests {
    use super::*;

    fn tracker() -> ReplicaDegradationTracker {
        ReplicaDegradationTracker::new(
            scoring::ScoreConfig::default(),
            state_machine::DegradationConfig::default(),
        )
    }

    #[test]
    fn healthy_replica_is_placeable() {
        let t = tracker();
        assert!(t.is_placeable(NodeId::new(1)));
        assert!(!t.is_excluded(NodeId::new(1)));
    }

    #[test]
    fn failure_cascade_to_dead() {
        let mut t = tracker();
        let node = NodeId::new(1);

        // 5 failures to Degraded
        for _ in 0..5 {
            t.record_failure(node, 1000, 5000, false);
        }
        assert_eq!(
            t.degradation_state(node),
            state_machine::DegradationState::Degraded
        );

        // 3 more failures to Dead
        for _ in 0..3 {
            t.record_failure(node, 2000, 5000, false);
        }
        assert_eq!(
            t.degradation_state(node),
            state_machine::DegradationState::Dead
        );
        assert!(t.is_excluded(node));
    }

    #[test]
    fn dead_to_recovering_to_healthy() {
        let mut t = tracker();
        let node = NodeId::new(1);

        // Force to Dead, then recover
        t.force_state(node, state_machine::DegradationState::Dead, 1000);
        assert_eq!(
            t.degradation_state(node),
            state_machine::DegradationState::Dead
        );

        // First success → Recovering
        t.record_success(node, 2000, 100);
        assert_eq!(
            t.degradation_state(node),
            state_machine::DegradationState::Recovering
        );

        // 10 successes → Healthy
        for _ in 0..10 {
            t.record_success(node, 3000, 100);
        }
        assert_eq!(
            t.degradation_state(node),
            state_machine::DegradationState::Healthy
        );
    }

    #[test]
    fn immediate_dead_on_unrecoverable() {
        let mut t = tracker();
        let node = NodeId::new(1);

        let result = t.record_failure(node, 1000, 5000, true);
        assert!(result.changed);
        assert_eq!(result.new_state, state_machine::DegradationState::Dead);
    }

    #[test]
    fn checksum_mismatch_causes_dead() {
        let mut t = tracker();
        let node = NodeId::new(1);

        // First mismatch: counted
        t.record_checksum_mismatch(node, 1000, 200);
        assert_eq!(
            t.degradation_state(node),
            state_machine::DegradationState::Healthy
        );

        // Second mismatch: > threshold → Dead
        let result = t.record_checksum_mismatch(node, 2000, 200);
        assert!(result.changed);
        assert_eq!(result.new_state, state_machine::DegradationState::Dead);
    }

    #[test]
    fn metrics_export_includes_all_replicas() {
        let mut t = tracker();
        t.record_success(NodeId::new(1), 1000, 50);
        t.record_success(NodeId::new(2), 1000, 100);
        t.record_failure(NodeId::new(3), 2000, 5000, false);

        let metrics = t.export_all_metrics(5000);
        assert_eq!(metrics.len(), 3);
        assert!(metrics.iter().any(|m| m.replica_id == 1));
        assert!(metrics.iter().any(|m| m.replica_id == 2));
        assert!(metrics.iter().any(|m| m.replica_id == 3));
    }

    #[test]
    fn untracked_replica_returns_healthy() {
        let t = tracker();
        assert_eq!(
            t.degradation_state(NodeId::new(99)),
            state_machine::DegradationState::Healthy
        );
        assert!(t.compute_score(NodeId::new(99), 1000).is_none());
        assert!(t.export_metrics(NodeId::new(99), 1000).is_none());
    }

    #[test]
    fn forced_state_propagates_to_scorer() {
        let mut t = tracker();
        let node = NodeId::new(1);
        t.record_success(node, 1000, 100);

        t.force_state(node, state_machine::DegradationState::Degraded, 2000);
        let score = t.compute_score(node, 3000).unwrap();
        assert_eq!(
            score.degradation_state,
            state_machine::DegradationState::Degraded
        );
    }

    #[test]
    fn last_seen_tracks_io_timestamps() {
        let mut t = tracker();
        let node = NodeId::new(1);

        // Never seen => None
        assert!(t.last_seen(node).is_none());

        // After first record => Some
        t.record_success(node, 1000, 100);
        assert_eq!(t.last_seen(node), Some(1000));

        // Updated on subsequent records
        t.record_failure(node, 5000, 1000, false);
        assert_eq!(t.last_seen(node), Some(5000));

        t.record_checksum_mismatch(node, 8000, 200);
        assert_eq!(t.last_seen(node), Some(8000));
    }

    #[test]
    fn check_stale_transitions_silent_replica_to_dead() {
        let mut t = ReplicaDegradationTracker::with_stale_timeout(
            scoring::ScoreConfig::default(),
            state_machine::DegradationConfig::default(),
            10_000_000_000, // 10s stale timeout
        );
        let node = NodeId::new(1);

        // Record some I/O at t=1000
        t.record_success(node, 1_000_000_000, 100);
        assert_eq!(
            t.degradation_state(node),
            state_machine::DegradationState::Healthy
        );

        // Check at t=5s (within timeout) => no change
        let stale = t.check_stale(5_000_000_000);
        assert!(stale.is_empty());
        assert_eq!(
            t.degradation_state(node),
            state_machine::DegradationState::Healthy
        );

        // Check at t=12s (past 10s timeout) => Dead
        let stale = t.check_stale(12_000_000_000);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].1, state_machine::DegradationState::Healthy);
        assert_eq!(stale[0].2.new_state, state_machine::DegradationState::Dead);
        assert!(t.is_excluded(node));
    }

    #[test]
    fn check_stale_skips_already_dead_replicas() {
        let mut t = ReplicaDegradationTracker::with_stale_timeout(
            scoring::ScoreConfig::default(),
            state_machine::DegradationConfig::default(),
            10_000_000_000,
        );
        let node = NodeId::new(1);

        // Already dead via unrecoverable
        t.record_failure(node, 1_000_000_000, 0, true);
        assert_eq!(
            t.degradation_state(node),
            state_machine::DegradationState::Dead
        );

        // check_stale skips it (already Dead)
        let stale = t.check_stale(20_000_000_000);
        assert!(stale.is_empty());
    }

    #[test]
    fn check_stale_with_no_io_ever_uses_zero_baseline() {
        let mut t = ReplicaDegradationTracker::with_stale_timeout(
            scoring::ScoreConfig::default(),
            state_machine::DegradationConfig::default(),
            5_000_000_000,
        );
        let node = NodeId::new(99);

        // Force track a replica without any I/O (simulate pre-registration)
        t.force_state(node, state_machine::DegradationState::Healthy, 0);

        // At t=6s, past 5s timeout with last_seen = 0 => stale
        let stale = t.check_stale(6_000_000_000);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].2.new_state, state_machine::DegradationState::Dead);
    }

    #[test]
    fn fresh_io_resets_stale_clock() {
        let mut t = ReplicaDegradationTracker::with_stale_timeout(
            scoring::ScoreConfig::default(),
            state_machine::DegradationConfig::default(),
            10_000_000_000,
        );
        let node = NodeId::new(1);

        t.record_success(node, 1_000_000_000, 100);
        // 9s later, fresh I/O resets clock
        t.record_success(node, 10_000_000_000, 100);
        // 12s later from the first I/O, but only 2s from the last => still alive
        let stale = t.check_stale(12_000_000_000);
        assert!(stale.is_empty());

        // 22s later from the last I/O => stale
        let stale = t.check_stale(32_000_000_000);
        assert_eq!(stale.len(), 1);
    }

    #[test]
    fn stale_timeout_getter_setter() {
        let mut t = tracker();
        assert_eq!(t.stale_timeout(), 30_000_000_000); // default

        t.set_stale_timeout(60_000_000_000);
        assert_eq!(t.stale_timeout(), 60_000_000_000);
    }

    #[test]
    fn remove_replica_cleans_all_state() {
        let mut t = tracker();
        let node = NodeId::new(1);

        t.record_success(node, 1000, 100);
        assert_eq!(t.tracked_count(), 1);
        assert!(t.last_seen(node).is_some());
        assert!(t.compute_score(node, 2000).is_some());

        let removed = t.remove_replica(node);
        assert!(removed);
        assert_eq!(t.tracked_count(), 0);
        assert!(t.last_seen(node).is_none());
        assert!(t.compute_score(node, 3000).is_none());
    }

    #[test]
    fn remove_nonexistent_replica_returns_false() {
        let mut t = tracker();
        assert!(!t.remove_replica(NodeId::new(99)));
    }

    #[test]
    fn multiple_replicas_independent_state_machines() {
        let mut t = tracker();
        let n1 = NodeId::new(1);
        let n2 = NodeId::new(2);

        // n1: degrade to Dead
        for _ in 0..5 {
            t.record_failure(n1, 1000, 5000, false);
        }
        for _ in 0..3 {
            t.record_failure(n1, 2000, 5000, false);
        }
        assert_eq!(
            t.degradation_state(n1),
            state_machine::DegradationState::Dead
        );

        // n2: stay Healthy (no failures)
        t.record_success(n2, 1000, 50);
        assert_eq!(
            t.degradation_state(n2),
            state_machine::DegradationState::Healthy
        );
    }

    #[test]
    fn stale_detection_multiple_replicas() {
        let mut t = ReplicaDegradationTracker::with_stale_timeout(
            scoring::ScoreConfig::default(),
            state_machine::DegradationConfig::default(),
            5_000_000_000, // 5s stale timeout
        );
        let n1 = NodeId::new(1);
        let n2 = NodeId::new(2);
        let n3 = NodeId::new(3);

        // All three have I/O at t=1s
        t.record_success(n1, 1_000_000_000, 100);
        t.record_success(n2, 1_000_000_000, 100);
        t.record_success(n3, 1_000_000_000, 100);

        // n2 gets a fresh I/O at t=3s (still alive)
        t.record_success(n2, 3_000_000_000, 100);

        // At t=7s: n1 and n3 are stale (past 5s), n2 is fresh (4s ago)
        let stale = t.check_stale(7_000_000_000);
        assert_eq!(stale.len(), 2);
        assert!(stale.iter().any(|(id, _, _)| *id == n1));
        assert!(stale.iter().any(|(id, _, _)| *id == n3));
        assert!(!stale.iter().any(|(id, _, _)| *id == n2));
    }

    #[test]
    fn last_seen_is_none_for_untracked_replicas() {
        let t = tracker();
        assert!(t.last_seen(NodeId::new(99)).is_none());
    }

    #[test]
    fn compute_score_returns_none_for_untracked() {
        let t = tracker();
        assert!(t.compute_score(NodeId::new(99), 1000).is_none());
    }

    #[test]
    fn remove_all_scores_does_not_lose_other_replicas() {
        let mut t = tracker();
        let n1 = NodeId::new(1);
        let n2 = NodeId::new(2);

        t.record_success(n1, 1000, 100);
        t.record_success(n2, 1000, 100);
        assert_eq!(t.tracked_count(), 2);

        t.remove_replica(n1);
        assert_eq!(t.tracked_count(), 1);
        assert!(t.compute_score(n2, 2000).is_some());
        assert!(t.compute_score(n1, 2000).is_none());
    }

    #[test]
    fn export_all_metrics_includes_placeable_flags() {
        let mut t = tracker();
        t.record_success(NodeId::new(1), 1000, 50);
        // Degrade and kill NodeId::new(2)
        for _ in 0..5 {
            t.record_failure(NodeId::new(2), 1000, 5000, false);
        }
        for _ in 0..3 {
            t.record_failure(NodeId::new(2), 2000, 5000, false);
        }

        let metrics = t.export_all_metrics(5000);
        assert_eq!(metrics.len(), 2);

        let m1 = metrics.iter().find(|m| m.replica_id == 1).unwrap();
        assert!(m1.is_placeable);
        assert!(!m1.is_excluded);

        let m2 = metrics.iter().find(|m| m.replica_id == 2).unwrap();
        assert!(!m2.is_placeable);
        assert!(m2.is_excluded);
    }

    #[test]
    fn stale_check_preserves_fresh_replicas() {
        let mut t = ReplicaDegradationTracker::with_stale_timeout(
            scoring::ScoreConfig::default(),
            state_machine::DegradationConfig::default(),
            10_000_000_000,
        );
        let node = NodeId::new(1);

        t.record_success(node, 1_000_000_000, 100);
        let stale = t.check_stale(5_000_000_000); // only 4s elapsed
        assert!(stale.is_empty());
        assert_eq!(
            t.degradation_state(node),
            state_machine::DegradationState::Healthy
        );
    }
}

// ── Read-path replica selection ────────────────────────────────────

/// Select the healthiest replica for a read operation.
///
/// Queries current health scores from the tracker for each candidate
/// replica and returns the highest-scoring one. If no candidate meets
/// `min_score`, the best available is still returned as a graceful
/// fallback (the caller may still reject it). Returns `None` only
/// when the candidate set is empty.
///
/// This is the core dispatch-agnostic selection function — it does not
/// depend on transport sessions, object stores, or read-protocol details.
/// Callers in `tidefs-replicated-object-store` and `tidefs-object-io`
/// wire it into their replica-iteration loops.
pub fn select_read_replica(
    tracker: &ReplicaDegradationTracker,
    candidates: &[NodeId],
    min_score: u32,
    now_ns: u64,
) -> Option<NodeId> {
    if candidates.is_empty() {
        return None;
    }

    let mut best: Option<(NodeId, u32)> = None;
    let mut best_above_threshold: Option<(NodeId, u32)> = None;

    for &candidate in candidates {
        let score = tracker
            .compute_score(candidate, now_ns)
            .map(|s| s.score)
            .unwrap_or(100); // no data = assume perfect health

        // Track overall best (for graceful fallback)
        match best {
            None => best = Some((candidate, score)),
            Some((_, current_best)) if score > current_best => {
                best = Some((candidate, score));
            }
            _ => {}
        }

        // Track best above threshold
        if score >= min_score {
            match best_above_threshold {
                None => best_above_threshold = Some((candidate, score)),
                Some((_, current)) if score > current => {
                    best_above_threshold = Some((candidate, score));
                }
                _ => {}
            }
        }
    }

    // Prefer a candidate above threshold; if none, fall back to the
    // best available (graceful fallback when all replicas are degraded).
    best_above_threshold.or(best).map(|(id, _score)| id)
}

/// Sort candidate replicas by health score, descending.
///
/// Returns a new `Vec<NodeId>` ordered from highest to lowest score.
/// Replicas with no score data are treated as score 100 and placed first.
/// This can be fed directly into a replica-iteration loop.
pub fn sort_replicas_by_health(
    tracker: &ReplicaDegradationTracker,
    candidates: &[NodeId],
    now_ns: u64,
) -> Vec<NodeId> {
    let mut scored: Vec<(NodeId, u32)> = candidates
        .iter()
        .map(|&id| {
            let score = tracker
                .compute_score(id, now_ns)
                .map(|s| s.score)
                .unwrap_or(100);
            (id, score)
        })
        .collect();

    scored.sort_by(|a, b| b.1.cmp(&a.1)); // descending by score
    scored.into_iter().map(|(id, _)| id).collect()
}

// ── select_read_replica unit tests ──────────────────────────────────

#[cfg(test)]
mod read_selection_tests {
    use super::*;
    use crate::scoring::ScoreConfig;
    use crate::state_machine::DegradationConfig;

    fn tracker_with_scores(
        scores: &[(u64, u32)], // (node_id, desired_score)
    ) -> ReplicaDegradationTracker {
        let mut tracker = ReplicaDegradationTracker::new(
            ScoreConfig {
                window_size: 20,
                ..ScoreConfig::default()
            },
            DegradationConfig {
                failure_threshold: 50, // high enough to avoid state transitions
                ..DegradationConfig::default()
            },
        );

        for &(node_id, target_score) in scores {
            let node = NodeId::new(node_id);
            // Fill window with successes first, then add failures to hit
            // the target score. Score ≈ 100 * (1 - failure_rate*weight).
            // With window_size=20, each failure reduces score by ~2.5 pts.
            let failures = ((100 - target_score) as usize * 20 / 100).max(0);
            let successes = 20usize.saturating_sub(failures);

            for _ in 0..successes {
                tracker.record_success(node, 1000, 50);
            }
            for _ in 0..failures {
                tracker.record_failure(node, 1000, 5000, false);
            }
        }

        tracker
    }

    #[test]
    fn select_read_replica_empty_candidates_returns_none() {
        let tracker =
            ReplicaDegradationTracker::new(ScoreConfig::default(), DegradationConfig::default());
        assert!(select_read_replica(&tracker, &[], 0, 1000).is_none());
    }

    #[test]
    fn select_read_replica_single_candidate_always_wins() {
        let tracker = tracker_with_scores(&[(1, 100)]);
        let result = select_read_replica(&tracker, &[NodeId::new(1)], 70, 2000);
        assert_eq!(result, Some(NodeId::new(1)));
    }

    #[test]
    fn select_read_replica_picks_highest_score() {
        let tracker = tracker_with_scores(&[(1, 60), (2, 95), (3, 80)]);

        let result = select_read_replica(
            &tracker,
            &[NodeId::new(1), NodeId::new(2), NodeId::new(3)],
            0,
            2000,
        );
        assert_eq!(result, Some(NodeId::new(2)));
    }

    #[test]
    fn select_read_replica_graceful_fallback_below_threshold() {
        let tracker = tracker_with_scores(&[(1, 20), (2, 35), (3, 10)]);

        let result = select_read_replica(
            &tracker,
            &[NodeId::new(1), NodeId::new(2), NodeId::new(3)],
            70,
            2000,
        );
        assert_eq!(result, Some(NodeId::new(2)));
    }

    #[test]
    fn select_read_replica_untracked_replicas_treated_as_perfect() {
        let tracker =
            ReplicaDegradationTracker::new(ScoreConfig::default(), DegradationConfig::default());

        let result = select_read_replica(&tracker, &[NodeId::new(99)], 0, 2000);
        assert_eq!(result, Some(NodeId::new(99)));
    }

    #[test]
    fn sort_replicas_by_health_descending_order() {
        let tracker = tracker_with_scores(&[(1, 40), (2, 90), (3, 70), (4, 100)]);

        let sorted = sort_replicas_by_health(
            &tracker,
            &[
                NodeId::new(1),
                NodeId::new(2),
                NodeId::new(3),
                NodeId::new(4),
            ],
            2000,
        );

        assert_eq!(
            sorted,
            vec![
                NodeId::new(4),
                NodeId::new(2),
                NodeId::new(3),
                NodeId::new(1),
            ]
        );
    }

    #[test]
    fn sort_replicas_by_health_empty_candidates() {
        let tracker =
            ReplicaDegradationTracker::new(ScoreConfig::default(), DegradationConfig::default());
        let sorted = sort_replicas_by_health(&tracker, &[], 1000);
        assert!(sorted.is_empty());
    }
}

// ── Integration with tidefs-replication-model ──
// P8-03 §5: ReplicaLagStateRecord schema family and
// advance_replica_health_and_lag_frontiers() algorithm

use tidefs_replication_model::{
    DegradedVisibilityClass, ReplicaCopyRecord, ReplicaLagClass, ReplicaTransferReceipt,
    ReplicaVerificationReceipt, ReplicatedReceiptId, ReplicatedSubjectId, VerificationStatus,
};

/// Authoritative lag / degraded visibility state (P8-03 §5).
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReplicaLagStateRecord {
    pub subject_ref: ReplicatedSubjectId,
    pub target_ref: u64,
    pub freshness_fence_frontier: u64,
    pub lag_class: ReplicaLagClass,
    pub bytes_behind: u64,
    pub oldest_missing_receipt_ref: ReplicatedReceiptId,
    pub degraded_visibility_class: DegradedVisibilityClass,
}

impl ReplicaLagStateRecord {
    #[must_use]
    pub fn new(
        subject_ref: ReplicatedSubjectId,
        target_ref: u64,
        freshness_fence_frontier: u64,
        lag_class: ReplicaLagClass,
        bytes_behind: u64,
    ) -> Self {
        ReplicaLagStateRecord {
            subject_ref,
            target_ref,
            freshness_fence_frontier,
            lag_class,
            bytes_behind,
            oldest_missing_receipt_ref: ReplicatedReceiptId(0),
            degraded_visibility_class: DegradedVisibilityClass::None,
        }
    }

    #[must_use]
    pub fn is_current(&self) -> bool {
        matches!(self.lag_class, ReplicaLagClass::Current)
    }

    #[must_use]
    pub fn is_stale(&self) -> bool {
        matches!(self.lag_class, ReplicaLagClass::Stale)
    }
}

/// Advance replica health and lag frontiers from receipts (P8-03 §6).
#[must_use]
pub fn advance_replica_health_and_lag_frontiers(
    current_frontier: u64,
    copy_records: &[ReplicaCopyRecord],
    verification_receipts: &[ReplicaVerificationReceipt],
    transfer_receipts: &[ReplicaTransferReceipt],
) -> Vec<ReplicaLagStateRecord> {
    let mut lag_records: Vec<ReplicaLagStateRecord> = Vec::new();

    for copy in copy_records {
        let replica_frontier = copy.freshness_frontier;
        let bytes_behind = current_frontier.saturating_sub(replica_frontier);
        let lag_class = classify_lag(bytes_behind);

        let vreceipt = verification_receipts
            .iter()
            .find(|r| r.subject_refs.contains(&copy.subject_ref));

        let degraded_visibility = match vreceipt {
            Some(r) if r.status == VerificationStatus::Verified => DegradedVisibilityClass::None,
            Some(r) if r.status == VerificationStatus::DegradedVerified => {
                DegradedVisibilityClass::DegradedReadPossible
            }
            Some(r) if r.status == VerificationStatus::WitnessInsufficient => {
                DegradedVisibilityClass::StaleDataServed
            }
            _ => DegradedVisibilityClass::ReadUnavailable,
        };

        let oldest_missing = transfer_receipts
            .iter()
            .filter(|r| r.ticket_ref == copy.verification_receipt_ref)
            .map(|r| r.receipt_id)
            .min()
            .unwrap_or(ReplicatedReceiptId(0));

        lag_records.push(ReplicaLagStateRecord {
            subject_ref: copy.subject_ref,
            target_ref: copy.member_ref.0,
            freshness_fence_frontier: replica_frontier,
            lag_class,
            bytes_behind,
            oldest_missing_receipt_ref: oldest_missing,
            degraded_visibility_class: degraded_visibility,
        });
    }

    lag_records
}

fn classify_lag(bytes_behind: u64) -> ReplicaLagClass {
    if bytes_behind == 0 {
        ReplicaLagClass::Current
    } else if bytes_behind < 1024 {
        ReplicaLagClass::SlightlyBehind
    } else if bytes_behind < 1024 * 1024 {
        ReplicaLagClass::ModeratelyBehind
    } else if bytes_behind < 100 * 1024 * 1024 {
        ReplicaLagClass::SeverelyBehind
    } else {
        ReplicaLagClass::Stale
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use tidefs_membership_epoch::{DomainId, EpochId, MemberId};
    use tidefs_replication_model::{
        ObjectDigest, ReplicaCopyClass, ReplicaCopyRecord, ReplicaLagClass,
        ReplicaVerificationReceipt, ReplicatedReceiptId, ReplicatedSubjectId, VerificationStatus,
    };

    #[test]
    fn advance_lag_frontiers_verified_copies() {
        let subject = ReplicatedSubjectId::new(1);
        let member = MemberId(1);
        let domain = DomainId(1);
        let digest = ObjectDigest::new(42);

        let copies = vec![
            ReplicaCopyRecord::verified(subject, member, domain, digest, 1000),
            ReplicaCopyRecord::verified(subject, MemberId(2), domain, digest, 900),
        ];

        let vreceipt = ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(1),
            subject_refs: vec![subject],
            digest_results: vec![digest],
            witness_refs: vec![member],
            quorum_class: 1,
            verification_epoch: EpochId(1),
            status: VerificationStatus::Verified,
        };

        let records = advance_replica_health_and_lag_frontiers(1000, &copies, &[vreceipt], &[]);

        assert_eq!(records.len(), 2);
        // First copy is at frontier, should be Current
        assert_eq!(records[0].lag_class, ReplicaLagClass::Current);
        assert_eq!(records[0].bytes_behind, 0);
        assert_eq!(
            records[0].degraded_visibility_class,
            DegradedVisibilityClass::None
        );
        // Second copy is behind by 100, should be SlightlyBehind
        assert_eq!(records[1].lag_class, ReplicaLagClass::SlightlyBehind);
        assert_eq!(records[1].bytes_behind, 100);
    }

    #[test]
    fn advance_lag_frontiers_unverified_copies() {
        let subject = ReplicatedSubjectId::new(1);
        let copies = vec![ReplicaCopyRecord::unavailable(
            subject,
            MemberId(1),
            DomainId(1),
            ReplicaCopyClass::Missing,
            ObjectDigest::new(0),
        )];

        let records = advance_replica_health_and_lag_frontiers(5000, &copies, &[], &[]);

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].degraded_visibility_class,
            DegradedVisibilityClass::ReadUnavailable
        );
    }

    #[test]
    fn advance_lag_frontiers_degraded_verified() {
        let subject = ReplicatedSubjectId::new(1);
        let member = MemberId(1);
        let domain = DomainId(1);
        let digest = ObjectDigest::new(42);

        let copies = vec![ReplicaCopyRecord::verified(
            subject, member, domain, digest, 800,
        )];

        let vreceipt = ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(1),
            subject_refs: vec![subject],
            digest_results: vec![digest],
            witness_refs: vec![member],
            quorum_class: 1,
            verification_epoch: EpochId(1),
            status: VerificationStatus::DegradedVerified,
        };

        let records = advance_replica_health_and_lag_frontiers(1000, &copies, &[vreceipt], &[]);

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].degraded_visibility_class,
            DegradedVisibilityClass::DegradedReadPossible
        );
        assert_eq!(records[0].bytes_behind, 200);
    }

    #[test]
    fn lag_class_boundaries() {
        // Exactly 0 = Current
        assert_eq!(classify_lag(0), ReplicaLagClass::Current);
        // 1 - 1023 = SlightlyBehind
        assert_eq!(classify_lag(1), ReplicaLagClass::SlightlyBehind);
        assert_eq!(classify_lag(1023), ReplicaLagClass::SlightlyBehind);
        // 1024 - 1048575 = ModeratelyBehind
        assert_eq!(classify_lag(1024), ReplicaLagClass::ModeratelyBehind);
        assert_eq!(
            classify_lag(1024 * 1024 - 1),
            ReplicaLagClass::ModeratelyBehind
        );
        // 1MB - 99MB = SeverelyBehind
        assert_eq!(classify_lag(1024 * 1024), ReplicaLagClass::SeverelyBehind);
        assert_eq!(
            classify_lag(99 * 1024 * 1024),
            ReplicaLagClass::SeverelyBehind
        );
        // 100MB+ = Stale
        assert_eq!(classify_lag(100 * 1024 * 1024), ReplicaLagClass::Stale);
        assert_eq!(classify_lag(u64::MAX), ReplicaLagClass::Stale);
    }

    #[test]
    fn lag_state_record_accessors() {
        let rec = super::ReplicaLagStateRecord::new(
            ReplicatedSubjectId::new(1),
            2,
            100,
            ReplicaLagClass::Current,
            0,
        );
        assert!(rec.is_current());
        assert!(!rec.is_stale());

        let rec = super::ReplicaLagStateRecord::new(
            ReplicatedSubjectId::new(1),
            2,
            100,
            ReplicaLagClass::Stale,
            1024 * 1024 * 1024,
        );
        assert!(!rec.is_current());
        assert!(rec.is_stale());
    }
}
