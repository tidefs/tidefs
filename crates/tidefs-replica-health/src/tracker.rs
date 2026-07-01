// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Replica health tracker — source-owned data_copy_3 core runtime component.
//!
//! Tracks per-chunk health across all replicas, updates health state
//! on placement receipts, anti-entropy results, and node failure events.
//! Provides visibility queries for charter adapters (FUSE, block volume).

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::adaptive_timeout::AdaptiveTimeout;
use crate::flap_detector::{FlapDetector, FlapEvent};
use crate::health_state::{ReplicaHealthState, RetireReason};
use crate::lag::ReplicaLagTracker;
use crate::propagation::{
    HealthSummary, ReplicaHealthAlert, ReplicaHealthEntry, ReplicaLagSummary, SuspectEventSummary,
};
use crate::suspicion::{PeerHealthObservation, SuspicionLevel, VisibilityClass};
use crate::{ChunkId, NodeId};

/// Tracks per-chunk replica health with adaptive failure detection.
///
/// # Design
///
/// - **per-chunk**, not per-PG — no Ceph PG state combinatorics
/// - **receipt-backed** — lag is computed from receipt frontiers,
///   not just heartbeats
/// - **dual-source** — receipt chains for optimistic frontier,
///   anti-entropy for ground truth
/// - **adaptive timeouts** — window widens during network instability
/// - **flap-suppressed** — exponential backoff prevents cascade
#[derive(Debug)]
pub struct ReplicaHealthTracker {
    /// Per-chunk, per-replica health state.
    chunk_health: BTreeMap<(ChunkId, NodeId), ReplicaHealthState>,
    /// Per-node suspicion level (aggregated from chunk health).
    node_suspicion: BTreeMap<NodeId, SuspicionLevel>,
    /// Peer observations for consensus.
    peer_observations: BTreeMap<NodeId, Vec<PeerHealthObservation>>,
    /// Lag tracker — computes lag from receipt frontiers.
    lag_tracker: ReplicaLagTracker,
    /// Adaptive timeout — widens during instability.
    adaptive_timeout: AdaptiveTimeout,
    /// Flap detector — exponential backoff for flapping nodes.
    flap_detector: FlapDetector,
    /// Alerts emitted on state transitions to degraded/repair.
    alerts: Vec<ReplicaHealthAlert>,
    /// Monotonic transition counter.
    transition_count: u64,
}

impl ReplicaHealthTracker {
    pub fn new(bounded_lag_threshold: u64, repair_threshold: u64) -> Self {
        ReplicaHealthTracker {
            chunk_health: BTreeMap::new(),
            node_suspicion: BTreeMap::new(),
            peer_observations: BTreeMap::new(),
            lag_tracker: ReplicaLagTracker::new(bounded_lag_threshold, repair_threshold),
            adaptive_timeout: AdaptiveTimeout::new(std::time::Duration::from_millis(500)),
            flap_detector: FlapDetector::new(std::time::Duration::from_secs(60)),
            alerts: Vec::new(),
            transition_count: 0,
        }
    }

    // ── Chunk health ─────────────────────────────────────────────────

    /// Get the health state for a specific chunk on a specific node.
    pub fn chunk_health(&self, chunk_id: ChunkId, node_id: NodeId) -> Option<&ReplicaHealthState> {
        self.chunk_health.get(&(chunk_id, node_id))
    }

    /// Mark a chunk as placed on a node (initial registration).
    pub fn register_chunk(
        &mut self,
        chunk_id: ChunkId,
        node_id: NodeId,
        receipt_id: u64,
        at_ns: u64,
    ) {
        self.chunk_health.insert(
            (chunk_id, node_id),
            ReplicaHealthState::Placed {
                receipt_id,
                placed_at_ns: at_ns,
            },
        );
    }

    /// Mark a chunk as healthy (receipt verified).
    pub fn mark_healthy(
        &mut self,
        chunk_id: ChunkId,
        node_id: NodeId,
        receipt_id: u64,
        verified_at_ns: u64,
    ) {
        self.chunk_health.insert(
            (chunk_id, node_id),
            ReplicaHealthState::Healthy {
                receipt_id,
                last_verified_ns: verified_at_ns,
            },
        );
    }

    /// Transition a chunk to lagged state.
    pub fn mark_lagged(
        &mut self,
        chunk_id: ChunkId,
        node_id: NodeId,
        bytes_behind: u64,
        last_receipt_ns: u64,
        detected_at_ns: u64,
    ) -> Option<ReplicaHealthAlert> {
        self.transition(
            chunk_id,
            node_id,
            ReplicaHealthState::Lagged {
                bytes_behind,
                last_receipt_ns,
                detected_at_ns,
            },
            detected_at_ns,
            format!("lag detected: {bytes_behind} bytes behind"),
        )
    }

    /// Transition a chunk to suspect state.
    pub fn mark_suspect(
        &mut self,
        chunk_id: ChunkId,
        node_id: NodeId,
        bytes_behind: u64,
        suspect_since_ns: u64,
        consecutive_checks: u32,
    ) -> Option<ReplicaHealthAlert> {
        self.transition(
            chunk_id,
            node_id,
            ReplicaHealthState::Suspect {
                bytes_behind,
                suspect_since_ns,
                consecutive_checks,
            },
            suspect_since_ns,
            format!("suspect after {consecutive_checks} checks"),
        )
    }

    /// Transition a chunk to degraded state (anti-entropy or checksum mismatch).
    pub fn mark_degraded(
        &mut self,
        chunk_id: ChunkId,
        node_id: NodeId,
        degraded_since_ns: u64,
        missing_chunks: u64,
        corrupt_chunks: u64,
    ) -> Option<ReplicaHealthAlert> {
        self.transition(
            chunk_id,
            node_id,
            ReplicaHealthState::Degraded {
                degraded_since_ns,
                missing_chunks,
                corrupt_chunks,
            },
            degraded_since_ns,
            format!("degraded: {missing_chunks} missing, {corrupt_chunks} corrupt chunks"),
        )
    }

    /// Mark that rebuild has started for a degraded chunk.
    pub fn mark_rebuilding(
        &mut self,
        chunk_id: ChunkId,
        node_id: NodeId,
        rebuild_started_ns: u64,
        bytes_total: u64,
    ) -> Option<ReplicaHealthAlert> {
        self.transition(
            chunk_id,
            node_id,
            ReplicaHealthState::Rebuilding {
                rebuild_started_ns,
                bytes_rebuilt: 0,
                bytes_total,
            },
            rebuild_started_ns,
            format!("rebuild started: {bytes_total} bytes total"),
        )
    }

    /// Mark rebuild as complete.
    pub fn mark_recovered(
        &mut self,
        chunk_id: ChunkId,
        node_id: NodeId,
        recovered_at_ns: u64,
        rebuild_receipt_id: u64,
    ) -> Option<ReplicaHealthAlert> {
        self.transition(
            chunk_id,
            node_id,
            ReplicaHealthState::Recovered {
                recovered_at_ns,
                rebuild_receipt_id,
            },
            recovered_at_ns,
            format!("recovered with receipt {rebuild_receipt_id}"),
        )
    }

    /// Retire a chunk from tracking (node decommissioned, placement changed).
    pub fn retire_chunk(
        &mut self,
        chunk_id: ChunkId,
        node_id: NodeId,
        retired_at_ns: u64,
        reason: RetireReason,
    ) {
        self.chunk_health.insert(
            (chunk_id, node_id),
            ReplicaHealthState::Retired {
                retired_at_ns,
                reason,
            },
        );
    }

    // ── Node suspicion ───────────────────────────────────────────────

    /// Update a node's suspicion level.
    pub fn set_node_suspicion(&mut self, node_id: NodeId, level: SuspicionLevel, at_ns: u64) {
        let old = self
            .node_suspicion
            .get(&node_id)
            .copied()
            .unwrap_or(SuspicionLevel::Healthy);

        // Feed flap detector
        let _is_flap = self.flap_detector.record_transition(
            node_id,
            FlapEvent {
                previous_state: old,
                new_state: level,
                at_ns,
            },
        );

        self.node_suspicion.insert(node_id, level);
    }

    /// Get a node's current suspicion level.
    pub fn node_suspicion(&self, node_id: NodeId) -> SuspicionLevel {
        self.node_suspicion
            .get(&node_id)
            .copied()
            .unwrap_or(SuspicionLevel::Healthy)
    }

    /// Whether a node is currently in flap backoff.
    pub fn is_in_backoff(&self, node_id: NodeId, now_ns: u64) -> bool {
        self.flap_detector.is_in_backoff(node_id, now_ns)
    }

    /// Check and clear expired flap backoffs.
    /// Returns the set of nodes whose backoff just expired.
    pub fn check_backoff_expiry(&mut self, now_ns: u64) -> Vec<NodeId> {
        self.flap_detector.check_backoff_expiry(now_ns)
    }

    /// Get the current flap backoff state for a node, if any.
    pub fn flap_backoff_state(&self, node_id: NodeId, now_ns: u64) -> Option<bool> {
        let backoff = self.flap_detector.get_backoff(node_id)?;
        Some(backoff.in_backoff && now_ns < backoff.backoff_until)
    }

    // ── Peer consensus ───────────────────────────────────────────────

    /// Record a peer observation of a node's health.
    pub fn record_peer_observation(&mut self, node_id: NodeId, observation: PeerHealthObservation) {
        self.peer_observations
            .entry(node_id)
            .or_default()
            .push(observation);
    }

    /// Compute consensus suspicion from peer observations.
    /// Returns (agreeing_peers, total_peers).
    pub fn peer_consensus(&self, node_id: NodeId) -> (usize, usize) {
        let observations = self.peer_observations.get(&node_id);
        let total = observations.map(|o| o.len()).unwrap_or(0);
        let agreeing = observations
            .map(|obs| {
                obs.iter()
                    .filter(|r| r.suspicion.is_at_least(SuspicionLevel::Suspect))
                    .count()
            })
            .unwrap_or(0);
        (agreeing, total)
    }

    // ── Visibility queries ───────────────────────────────────────────

    /// Check visibility for a chunk on a specific node.
    /// Returns the visibility class for charter adapters.
    pub fn check_visibility(&self, chunk_id: ChunkId, node_id: NodeId) -> VisibilityClass {
        match self.chunk_health.get(&(chunk_id, node_id)) {
            Some(ReplicaHealthState::Healthy { .. }) | Some(ReplicaHealthState::Placed { .. }) => {
                // Check lag tracker for freshness
                if let Some(lag) = self.lag_tracker.get_lag(chunk_id, node_id) {
                    if !lag.bytes_behind.is_zero() {
                        return lag.lag_class;
                    }
                }
                VisibilityClass::Exact
            }
            Some(ReplicaHealthState::Lagged { .. }) => VisibilityClass::BoundedLag,
            Some(ReplicaHealthState::Suspect { .. }) => VisibilityClass::DegradedButValid,
            Some(ReplicaHealthState::Degraded { .. }) => VisibilityClass::RepairRequired,
            Some(ReplicaHealthState::Rebuilding { .. }) => VisibilityClass::RepairRequired,
            Some(ReplicaHealthState::Recovered { .. }) => VisibilityClass::BoundedLag,
            Some(ReplicaHealthState::FlapSuppressed { .. }) => VisibilityClass::DegradedButValid,
            _ => VisibilityClass::RepairRequired,
        }
    }

    // ── Lag tracking delegation ──────────────────────────────────────

    pub fn update_primary_frontier(&mut self, chunk_id: ChunkId, bytes_placed: u64) {
        self.lag_tracker
            .update_primary_frontier(chunk_id, bytes_placed);
    }

    pub fn update_replica_frontier(
        &mut self,
        chunk_id: ChunkId,
        node_id: NodeId,
        bytes_placed: u64,
        receipt_id: u64,
    ) {
        self.lag_tracker
            .update_replica_frontier(chunk_id, node_id, bytes_placed, receipt_id);
    }

    // ── Adaptive timeout delegation ──────────────────────────────────

    pub fn observe_heartbeat(&mut self, inter_arrival: std::time::Duration) {
        self.adaptive_timeout.observe(inter_arrival);
    }

    pub fn current_timeout_window(&self) -> std::time::Duration {
        self.adaptive_timeout.current_window()
    }

    // ── Health summary generation ────────────────────────────────────

    /// Generate a health summary for this node to piggyback on heartbeats.
    pub fn generate_summary(
        &self,
        reporting_node: NodeId,
        epoch: u64,
        now_ns: u64,
    ) -> HealthSummary {
        let mut summary = HealthSummary::empty(reporting_node, epoch, now_ns);

        for ((chunk_id, node_id), state) in &self.chunk_health {
            match state {
                ReplicaHealthState::Degraded { .. } | ReplicaHealthState::Suspect { .. } => {
                    summary.degraded_replicas.push(ReplicaHealthEntry {
                        chunk_id: *chunk_id,
                        target_node: *node_id,
                        state: state.clone(),
                        updated_at_ns: now_ns,
                    });
                }
                ReplicaHealthState::Lagged { .. } => {
                    if let Some(lag) = self.lag_tracker.get_lag(*chunk_id, *node_id) {
                        summary.lagging_replicas.push(ReplicaLagSummary {
                            chunk_id: *chunk_id,
                            replica_node: *node_id,
                            bytes_behind: lag.bytes_behind.0,
                        });
                    }
                }
                _ => {}
            }
        }

        summary
    }

    /// Generate suspect event summaries for a full sync.
    pub fn suspect_events(&self) -> Vec<SuspectEventSummary> {
        self.chunk_health
            .iter()
            .filter_map(|((chunk_id, node_id), state)| {
                if let ReplicaHealthState::Suspect {
                    suspect_since_ns, ..
                } = state
                {
                    Some(SuspectEventSummary {
                        chunk_id: *chunk_id,
                        target_node: *node_id,
                        suspicion: SuspicionLevel::Suspect,
                        observed_by: NodeId::new(0), // caller should fill
                        observed_at_ns: *suspect_since_ns,
                        reason: Some("suspect state present".into()),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    // ── Statistics ───────────────────────────────────────────────────

    /// Count of chunks in each health state.
    pub fn health_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for state in self.chunk_health.values() {
            let key = match state {
                ReplicaHealthState::Absent => "absent",
                ReplicaHealthState::Ticketed { .. } => "ticketed",
                ReplicaHealthState::Inflight { .. } => "inflight",
                ReplicaHealthState::Received { .. } => "received",
                ReplicaHealthState::Verified { .. } => "verified",
                ReplicaHealthState::Placed { .. } => "placed",
                ReplicaHealthState::Healthy { .. } => "healthy",
                ReplicaHealthState::Lagged { .. } => "lagged",
                ReplicaHealthState::Suspect { .. } => "suspect",
                ReplicaHealthState::Degraded { .. } => "degraded",
                ReplicaHealthState::Rebuilding { .. } => "rebuilding",
                ReplicaHealthState::Recovered { .. } => "recovered",
                ReplicaHealthState::FlapSuppressed { .. } => "flap_suppressed",
                ReplicaHealthState::Retired { .. } => "retired",
            };
            *counts.entry(key.to_string()).or_default() += 1;
        }
        counts
    }

    /// Total number of tracked chunk-replica pairs.
    pub fn tracked_count(&self) -> usize {
        self.chunk_health.len()
    }

    /// Alerts emitted since last drain.
    pub fn drain_alerts(&mut self) -> Vec<ReplicaHealthAlert> {
        std::mem::take(&mut self.alerts)
    }

    /// Return unique chunk IDs that have at least one replica in a degraded,
    /// suspect, lagged, or rebuilding state — these are recovery loop candidates.
    pub fn degraded_chunk_ids(&self) -> Vec<ChunkId> {
        let mut ids: BTreeSet<ChunkId> = BTreeSet::new();
        for ((chunk_id, _), state) in &self.chunk_health {
            if state.is_degraded() || state.is_rebuilding() {
                ids.insert(*chunk_id);
            }
        }
        ids.into_iter().collect()
    }

    /// Return all replica health states for a given chunk across all nodes.
    pub fn replica_states_for_chunk(&self, chunk_id: ChunkId) -> Vec<(NodeId, ReplicaHealthState)> {
        self.chunk_health
            .iter()
            .filter_map(|((cid, node_id), state)| {
                if *cid == chunk_id {
                    Some((*node_id, state.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    // ── Internal: state transition ──────────────────────────────────

    fn transition(
        &mut self,
        chunk_id: ChunkId,
        node_id: NodeId,
        new_state: ReplicaHealthState,
        at_ns: u64,
        reason: String,
    ) -> Option<ReplicaHealthAlert> {
        let key = (chunk_id, node_id);
        let previous = self.chunk_health.get(&key).cloned();

        // Don't transition if already in same state
        if let Some(ref prev) = previous {
            if std::mem::discriminant(prev) == std::mem::discriminant(&new_state) {
                return None;
            }
        }

        self.transition_count += 1;
        self.chunk_health.insert(key, new_state.clone());

        let alert = ReplicaHealthAlert::new(
            chunk_id,
            node_id,
            previous.unwrap_or(ReplicaHealthState::Absent),
            new_state,
            at_ns,
            reason,
            NodeId::new(0), // local node — caller can override
        );

        self.alerts.push(alert.clone());
        Some(alert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> ReplicaHealthTracker {
        ReplicaHealthTracker::new(1024, 1024 * 1024)
    }

    #[test]
    fn register_and_check_health() {
        let mut t = tracker();
        let chunk = ChunkId::new(1);
        let node = NodeId::new(1);

        t.register_chunk(chunk, node, 1, 1000);
        let state = t.chunk_health(chunk, node).unwrap();
        assert!(matches!(state, ReplicaHealthState::Placed { .. }));
    }

    #[test]
    fn healthy_visibility_is_exact() {
        let mut t = tracker();
        let chunk = ChunkId::new(1);
        let node = NodeId::new(1);

        t.mark_healthy(chunk, node, 1, 1000);
        assert_eq!(t.check_visibility(chunk, node), VisibilityClass::Exact);
    }

    #[test]
    fn degraded_visibility_is_repair_required() {
        let mut t = tracker();
        let chunk = ChunkId::new(1);
        let node = NodeId::new(1);

        t.register_chunk(chunk, node, 1, 1000);
        t.mark_degraded(chunk, node, 2000, 3, 1);
        assert_eq!(
            t.check_visibility(chunk, node),
            VisibilityClass::RepairRequired
        );
    }

    #[test]
    fn health_state_machine_transitions() {
        let mut t = tracker();
        let chunk = ChunkId::new(1);
        let node = NodeId::new(1);

        t.register_chunk(chunk, node, 1, 1000);
        assert!(t.chunk_health(chunk, node).unwrap().is_healthy());

        let alert = t.mark_lagged(chunk, node, 500, 2000, 2000);
        assert!(alert.is_some());
        assert!(matches!(
            t.chunk_health(chunk, node).unwrap(),
            ReplicaHealthState::Lagged { .. }
        ));

        let alert = t.mark_suspect(chunk, node, 5000, 3000, 3);
        assert!(alert.is_some());
        assert!(t.chunk_health(chunk, node).unwrap().is_degraded());

        let alert = t.mark_degraded(chunk, node, 4000, 1, 0);
        assert!(alert.is_some());
        assert!(matches!(
            t.chunk_health(chunk, node).unwrap(),
            ReplicaHealthState::Degraded { .. }
        ));
    }

    #[test]
    fn rebuild_cycle() {
        let mut t = tracker();
        let chunk = ChunkId::new(1);
        let node = NodeId::new(1);

        t.register_chunk(chunk, node, 1, 1000);
        t.mark_degraded(chunk, node, 2000, 1, 0);
        t.mark_rebuilding(chunk, node, 3000, 1024);
        assert!(t.chunk_health(chunk, node).unwrap().is_rebuilding());

        t.mark_recovered(chunk, node, 4000, 2);
        // Recovered -> mark as healthy
        t.mark_healthy(chunk, node, 2, 5000);
        assert!(t.chunk_health(chunk, node).unwrap().is_healthy());
    }

    #[test]
    fn node_suspicion_escalates() {
        let mut t = tracker();
        let node = NodeId::new(1);

        assert_eq!(t.node_suspicion(node), SuspicionLevel::Healthy);
        t.set_node_suspicion(node, SuspicionLevel::Sluggish, 1000);
        assert_eq!(t.node_suspicion(node), SuspicionLevel::Sluggish);
        t.set_node_suspicion(node, SuspicionLevel::Suspect, 2000);
        assert_eq!(t.node_suspicion(node), SuspicionLevel::Suspect);
    }

    #[test]
    fn peer_consensus_aggregates_observations() {
        let mut t = tracker();
        let node = NodeId::new(1);

        t.record_peer_observation(
            node,
            PeerHealthObservation::new(2, SuspicionLevel::Suspect, 1000),
        );
        t.record_peer_observation(
            node,
            PeerHealthObservation::new(3, SuspicionLevel::Degraded, 2000),
        );

        let (agreeing, total) = t.peer_consensus(node);
        assert_eq!(total, 2);
        assert_eq!(agreeing, 2); // both are >= Suspect
    }

    #[test]
    fn generate_summary_includes_only_unhealthy() {
        let mut t = tracker();
        let c1 = ChunkId::new(1);
        let c2 = ChunkId::new(2);
        let n1 = NodeId::new(1);
        let n2 = NodeId::new(2);

        t.mark_healthy(c1, n1, 1, 1000);
        t.mark_degraded(c2, n2, 2000, 1, 0);

        let summary = t.generate_summary(NodeId::new(0), 1, 3000);
        assert!(!summary.all_healthy());
        assert_eq!(summary.degraded_replicas.len(), 1);
    }

    #[test]
    fn same_state_transition_is_idempotent() {
        let mut t = tracker();
        let chunk = ChunkId::new(1);
        let node = NodeId::new(1);

        t.register_chunk(chunk, node, 1, 1000);
        let alert1 = t.mark_lagged(chunk, node, 500, 2000, 2000);
        assert!(alert1.is_some());

        // Same transition again should be a no-op
        let alert2 = t.mark_lagged(chunk, node, 600, 2001, 2001);
        assert!(alert2.is_none());
    }

    #[test]
    fn retire_chunk_stops_tracking_health() {
        let mut t = tracker();
        let chunk = ChunkId::new(1);
        let node = NodeId::new(1);

        t.register_chunk(chunk, node, 1, 1000);
        t.retire_chunk(chunk, node, 2000, RetireReason::OperatorRetired);
        assert!(t.chunk_health(chunk, node).unwrap().is_retired());
    }

    #[test]
    fn health_counts_aggregates_by_state() {
        let mut t = tracker();
        t.mark_healthy(ChunkId::new(1), NodeId::new(1), 1, 1000);
        t.mark_healthy(ChunkId::new(2), NodeId::new(1), 2, 1000);
        t.mark_degraded(ChunkId::new(3), NodeId::new(2), 2000, 1, 0);

        let counts = t.health_counts();
        assert_eq!(counts.get("healthy").copied().unwrap_or(0), 2);
        assert_eq!(counts.get("degraded").copied().unwrap_or(0), 1);
    }

    // ── degraded_chunk_ids ──────────────────────────────────────────

    #[test]
    fn degraded_chunk_ids_returns_only_unhealthy_chunks() {
        let mut t = tracker();
        let c1 = ChunkId::new(1);
        let c2 = ChunkId::new(2);
        let c3 = ChunkId::new(3);
        let n1 = NodeId::new(1);

        t.mark_healthy(c1, n1, 1, 1000);
        t.mark_degraded(c2, n1, 2000, 1, 0);
        t.mark_suspect(c3, n1, 500, 2000, 3);

        let ids = t.degraded_chunk_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&c2));
        assert!(ids.contains(&c3));
        assert!(!ids.contains(&c1));
    }

    #[test]
    fn degraded_chunk_ids_includes_rebuilding() {
        let mut t = tracker();
        let c1 = ChunkId::new(1);
        let n1 = NodeId::new(1);

        t.register_chunk(c1, n1, 1, 1000);
        t.mark_rebuilding(c1, n1, 2000, 1024);

        let ids = t.degraded_chunk_ids();
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(&c1));
    }

    // ── replica_states_for_chunk ────────────────────────────────────

    #[test]
    fn replica_states_for_chunk_returns_all_nodes() {
        let mut t = tracker();
        let c1 = ChunkId::new(1);
        let n1 = NodeId::new(1);
        let n2 = NodeId::new(2);
        let n3 = NodeId::new(3);

        t.mark_healthy(c1, n1, 1, 1000);
        t.mark_healthy(c1, n2, 2, 1000);
        t.mark_degraded(c1, n3, 2000, 1, 0);

        let states = t.replica_states_for_chunk(c1);
        assert_eq!(states.len(), 3);
    }

    #[test]
    fn replica_states_for_unknown_chunk_is_empty() {
        let t = tracker();
        let states = t.replica_states_for_chunk(ChunkId::new(99));
        assert!(states.is_empty());
    }

    // ── suspect_events ─────────────────────────────────────────────

    #[test]
    fn suspect_events_returns_only_suspect_states() {
        let mut t = tracker();
        let c1 = ChunkId::new(1);
        let c2 = ChunkId::new(2);
        let n1 = NodeId::new(1);
        let n2 = NodeId::new(2);

        t.mark_healthy(c1, n1, 1, 1000);
        t.mark_suspect(c2, n2, 500, 2000, 3);

        let events = t.suspect_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].chunk_id, c2);
        assert_eq!(events[0].target_node, n2);
    }

    // ── drain_alerts ────────────────────────────────────────────────

    #[test]
    fn drain_alerts_clears_after_retrieval() {
        let mut t = tracker();
        let chunk = ChunkId::new(1);
        let node = NodeId::new(1);

        t.register_chunk(chunk, node, 1, 1000);
        let alert = t.mark_lagged(chunk, node, 500, 2000, 2000);
        assert!(alert.is_some());

        let alerts = t.drain_alerts();
        assert_eq!(alerts.len(), 1);

        // Second drain: empty
        let alerts2 = t.drain_alerts();
        assert!(alerts2.is_empty());
    }

    // ── flap backoff integration ────────────────────────────────────

    #[test]
    fn flap_backoff_state_integration() {
        let mut t = tracker();
        let node = NodeId::new(1);

        // Initially not in backoff
        assert!(t.flap_backoff_state(node, 1000).is_none());

        // Trigger flap by rapidly changing suspicion
        t.set_node_suspicion(node, SuspicionLevel::Down, 1000);
        t.set_node_suspicion(node, SuspicionLevel::Healthy, 2000);
        t.set_node_suspicion(node, SuspicionLevel::Down, 3000);
        t.set_node_suspicion(node, SuspicionLevel::Healthy, 4000);

        // Should be in backoff now (two rapid Down<->Healthy transitions)
        let backoff = t.flap_backoff_state(node, 5000);
        assert!(backoff.is_some());
    }
    // ── check_backoff_expiry ────────────────────────────────────────

    #[test]
    fn check_backoff_expiry_returns_expired() {
        let mut t = tracker();
        let node = NodeId::new(1);

        t.set_node_suspicion(node, SuspicionLevel::Down, 1_000_000_000);
        t.set_node_suspicion(node, SuspicionLevel::Healthy, 2_000_000_000);
        t.set_node_suspicion(node, SuspicionLevel::Down, 3_000_000_000);
        t.set_node_suspicion(node, SuspicionLevel::Healthy, 4_000_000_000);

        // Backoff extends to 120s after 3 flap episodes; at 5s still in backoff
        assert!(t.is_in_backoff(node, 5_000_000_000));

        // At 130s, past the 120s backoff (which started at 4e9)
        let expired = t.check_backoff_expiry(130_000_000_000);
        assert!(expired.contains(&node));
        assert!(!t.is_in_backoff(node, 130_000_000_000));
    }

    #[test]
    fn tracked_count_reflects_chunk_replica_pairs() {
        let mut t = tracker();
        assert_eq!(t.tracked_count(), 0);

        t.register_chunk(ChunkId::new(1), NodeId::new(1), 1, 1000);
        assert_eq!(t.tracked_count(), 1);

        t.register_chunk(ChunkId::new(2), NodeId::new(1), 2, 1000);
        assert_eq!(t.tracked_count(), 2);

        t.register_chunk(ChunkId::new(1), NodeId::new(2), 3, 1000);
        assert_eq!(t.tracked_count(), 3);
    }
}
