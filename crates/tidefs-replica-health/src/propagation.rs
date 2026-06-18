// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Health state propagation structures.
//!
//! Health state propagates via piggyback on heartbeat messages and
//! periodic full-state syncs. This module defines the wire formats.
//!
//! Key differences from centralized pgmap (Ceph bottleneck):
//! - Each node computes health for replicas it touches
//! - Cluster-wide health is a scatter-gather query, not centralized
//! - Piggybacked summaries carry only unhealthy replicas (normally near-zero)

use crate::health_state::ReplicaHealthState;
use crate::suspicion::SuspicionLevel;
use crate::{ChunkId, NodeId};

/// Health summary piggybacked on heartbeat messages.
///
/// Normally near-empty — only carries degraded or lagging replicas.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HealthSummary {
    /// Which node generated this summary.
    pub reporting_node: NodeId,
    /// Membership epoch this summary covers.
    pub epoch: u64,
    /// Replicas this node sees as degraded.
    pub degraded_replicas: Vec<ReplicaHealthEntry>,
    /// Replicas this node sees as lagging.
    pub lagging_replicas: Vec<ReplicaLagSummary>,
    /// When the summary was generated (ns).
    pub generated_at_ns: u64,
}

/// A single replica's health entry in a summary.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReplicaHealthEntry {
    pub chunk_id: ChunkId,
    pub target_node: NodeId,
    pub state: ReplicaHealthState,
    pub updated_at_ns: u64,
}

/// A lag summary entry in a health summary.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReplicaLagSummary {
    pub chunk_id: ChunkId,
    pub replica_node: NodeId,
    pub bytes_behind: u64,
}

impl HealthSummary {
    /// Create an empty health summary for a node.
    pub fn empty(reporting_node: NodeId, epoch: u64, now_ns: u64) -> Self {
        HealthSummary {
            reporting_node,
            epoch,
            degraded_replicas: Vec::new(),
            lagging_replicas: Vec::new(),
            generated_at_ns: now_ns,
        }
    }

    /// Whether this summary indicates all replicas are healthy.
    pub fn all_healthy(&self) -> bool {
        self.degraded_replicas.is_empty() && self.lagging_replicas.is_empty()
    }

    /// Total number of unhealthy replicas in this summary.
    pub fn unhealthy_count(&self) -> usize {
        self.degraded_replicas.len() + self.lagging_replicas.len()
    }
}

/// Full health state sync sent on epoch transitions and periodic intervals.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HealthStateSync {
    /// Membership epoch.
    pub epoch: u64,
    /// Health state for all replicas this node knows about.
    pub replica_health: Vec<ReplicaHealthEntry>,
    /// Lag state for replicas.
    pub replica_lag: Vec<ReplicaLagSummary>,
    /// Suspect events observed.
    pub suspect_events: Vec<SuspectEventSummary>,
    /// Monotonic sync sequence number.
    pub sync_sequence: u64,
}

/// A summary of a suspect event.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SuspectEventSummary {
    pub chunk_id: ChunkId,
    pub target_node: NodeId,
    pub suspicion: SuspicionLevel,
    pub observed_by: NodeId,
    pub observed_at_ns: u64,
    pub reason: Option<String>,
}

/// A health alert pushed on state transition to Degraded or RepairRequired.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReplicaHealthAlert {
    pub chunk_id: ChunkId,
    pub target_node: NodeId,
    pub previous_state: ReplicaHealthState,
    pub new_state: ReplicaHealthState,
    pub transition_at_ns: u64,
    pub alert_reason: String,
    /// Which node detected the transition.
    pub detected_by: NodeId,
}

impl ReplicaHealthAlert {
    pub fn new(
        chunk_id: ChunkId,
        target_node: NodeId,
        previous_state: ReplicaHealthState,
        new_state: ReplicaHealthState,
        transition_at_ns: u64,
        alert_reason: impl Into<String>,
        detected_by: NodeId,
    ) -> Self {
        ReplicaHealthAlert {
            chunk_id,
            target_node,
            previous_state,
            new_state,
            transition_at_ns,
            alert_reason: alert_reason.into(),
            detected_by,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_summary_is_healthy() {
        let summary = HealthSummary::empty(NodeId::new(1), 1, 1000);
        assert!(summary.all_healthy());
        assert_eq!(summary.unhealthy_count(), 0);
    }

    #[test]
    fn summary_with_degraded_is_not_healthy() {
        let mut summary = HealthSummary::empty(NodeId::new(1), 1, 1000);
        summary.degraded_replicas.push(ReplicaHealthEntry {
            chunk_id: ChunkId::new(1),
            target_node: NodeId::new(2),
            state: ReplicaHealthState::Degraded {
                degraded_since_ns: 1000,
                missing_chunks: 1,
                corrupt_chunks: 0,
            },
            updated_at_ns: 1000,
        });
        assert!(!summary.all_healthy());
        assert_eq!(summary.unhealthy_count(), 1);
    }
}
