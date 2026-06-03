//! Replica lag tracking from receipt frontiers.
//!
//! Lag is computed as the difference between the primary's known-placed
//! byte count and each replica's known-placed byte count. Lag class
//! assignment uses configurable thresholds for bounded-lag and
//! degraded-but-valid boundaries.

use std::collections::BTreeMap;

use crate::suspicion::VisibilityClass;
use crate::{BytesBehind, ChunkId, NodeId};

/// Lag state for a single chunk on a specific replica node.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReplicaLagEntry {
    pub chunk_id: ChunkId,
    pub replica_node: NodeId,
    pub bytes_behind: BytesBehind,
    pub primary_receipt_id: u64,
    pub replica_receipt_id: u64,
    pub lag_class: VisibilityClass,
}

impl ReplicaLagEntry {
    pub fn new(
        chunk_id: ChunkId,
        replica_node: NodeId,
        bytes_behind: BytesBehind,
        primary_receipt_id: u64,
        replica_receipt_id: u64,
    ) -> Self {
        ReplicaLagEntry {
            chunk_id,
            replica_node,
            bytes_behind,
            primary_receipt_id,
            replica_receipt_id,
            lag_class: VisibilityClass::Exact,
        }
    }

    /// Classify lag based on thresholds.
    ///
    /// - `Exact`: zero bytes behind
    /// - `BoundedLag`: within the bounded-lag threshold
    /// - `DegradedButValid`: beyond bounded-lag but replica has verified copies
    /// - `RepairRequired`: missing chunks (not just lagging)
    pub fn classify(&mut self, bounded_lag_threshold: u64, repair_threshold: u64) {
        self.lag_class = if self.bytes_behind.is_zero() {
            VisibilityClass::Exact
        } else if self.bytes_behind.0 <= bounded_lag_threshold {
            VisibilityClass::BoundedLag
        } else if self.bytes_behind.0 <= repair_threshold {
            VisibilityClass::DegradedButValid
        } else {
            VisibilityClass::RepairRequired
        };
    }
}

/// Tracks lag across all replicas for all chunks.
#[derive(Clone, Debug)]
pub struct ReplicaLagTracker {
    /// Per-chunk, per-replica lag entries.
    entries: BTreeMap<(ChunkId, NodeId), ReplicaLagEntry>,
    /// Threshold for bounded lag classification (bytes).
    bounded_lag_threshold: u64,
    /// Threshold beyond which repair is required (bytes).
    repair_threshold: u64,
    /// Primary's known-placed byte count per chunk.
    primary_frontiers: BTreeMap<ChunkId, u64>,
}

impl ReplicaLagTracker {
    pub fn new(bounded_lag_threshold: u64, repair_threshold: u64) -> Self {
        ReplicaLagTracker {
            entries: BTreeMap::new(),
            bounded_lag_threshold,
            repair_threshold,
            primary_frontiers: BTreeMap::new(),
        }
    }

    /// Update the primary's known-placed byte count for a chunk.
    /// This advances the frontier against which replicas are compared.
    pub fn update_primary_frontier(&mut self, chunk_id: ChunkId, bytes_placed: u64) {
        self.primary_frontiers.insert(chunk_id, bytes_placed);
    }

    /// Update a replica's known-placed byte count for a chunk.
    /// Lag is computed as primary.bytes_placed - replica.bytes_placed.
    pub fn update_replica_frontier(
        &mut self,
        chunk_id: ChunkId,
        replica_node: NodeId,
        bytes_placed: u64,
        receipt_id: u64,
    ) {
        let primary_bytes = self.primary_frontiers.get(&chunk_id).copied().unwrap_or(0);
        let lag_bytes = primary_bytes.saturating_sub(bytes_placed);

        let mut entry = ReplicaLagEntry::new(
            chunk_id,
            replica_node,
            BytesBehind::new(lag_bytes),
            0, // primary receipt — set separately
            receipt_id,
        );
        entry.classify(self.bounded_lag_threshold, self.repair_threshold);
        self.entries.insert((chunk_id, replica_node), entry);
    }

    /// Get lag for a specific chunk on a specific replica.
    pub fn get_lag(&self, chunk_id: ChunkId, replica_node: NodeId) -> Option<&ReplicaLagEntry> {
        self.entries.get(&(chunk_id, replica_node))
    }

    /// Get all lagging replicas (> 0 bytes behind).
    pub fn lagging_replicas(&self) -> Vec<&ReplicaLagEntry> {
        self.entries
            .values()
            .filter(|e| !e.bytes_behind.is_zero())
            .collect()
    }

    /// Get replicas requiring repair (exceeded repair threshold).
    pub fn repair_required(&self) -> Vec<&ReplicaLagEntry> {
        self.entries
            .values()
            .filter(|e| e.lag_class == VisibilityClass::RepairRequired)
            .collect()
    }

    /// Total number of tracked entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Remove all entries for a specific chunk (e.g., after deletion).
    pub fn remove_chunk(&mut self, chunk_id: ChunkId) {
        self.entries.retain(|(c, _), _| *c != chunk_id);
        self.primary_frontiers.remove(&chunk_id);
    }

    /// Remove all entries for a specific replica (e.g., after decommission).
    pub fn remove_replica(&mut self, replica_node: NodeId) {
        self.entries.retain(|(_, n), _| *n != replica_node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_lag_when_frontiers_match() {
        let mut tracker = ReplicaLagTracker::new(1024, 1024 * 1024);
        let chunk = ChunkId::new(1);
        let node = NodeId::new(1);

        tracker.update_primary_frontier(chunk, 4096);
        tracker.update_replica_frontier(chunk, node, 4096, 1);

        let lag = tracker.get_lag(chunk, node).unwrap();
        assert!(lag.bytes_behind.is_zero());
        assert_eq!(lag.lag_class, VisibilityClass::Exact);
    }

    #[test]
    fn bounded_lag_when_within_threshold() {
        let mut tracker = ReplicaLagTracker::new(1024, 1024 * 1024);
        let chunk = ChunkId::new(1);
        let node = NodeId::new(1);

        tracker.update_primary_frontier(chunk, 5000);
        tracker.update_replica_frontier(chunk, node, 4000, 1);

        let lag = tracker.get_lag(chunk, node).unwrap();
        assert_eq!(lag.bytes_behind.0, 1000);
        assert_eq!(lag.lag_class, VisibilityClass::BoundedLag);
    }

    #[test]
    fn repair_required_when_past_threshold() {
        let mut tracker = ReplicaLagTracker::new(100, 500);
        let chunk = ChunkId::new(1);
        let node = NodeId::new(1);

        tracker.update_primary_frontier(chunk, 10000);
        tracker.update_replica_frontier(chunk, node, 500, 1);

        let lag = tracker.get_lag(chunk, node).unwrap();
        assert_eq!(lag.lag_class, VisibilityClass::RepairRequired);
    }

    #[test]
    fn remove_chunk_cleans_up() {
        let mut tracker = ReplicaLagTracker::new(1024, 1024 * 1024);
        let chunk = ChunkId::new(1);
        tracker.update_primary_frontier(chunk, 4096);
        tracker.update_replica_frontier(chunk, NodeId::new(1), 4096, 1);
        assert_eq!(tracker.entry_count(), 1);
        tracker.remove_chunk(chunk);
        assert_eq!(tracker.entry_count(), 0);
    }

    #[test]
    fn lagging_replicas_lists_non_zero_entries() {
        let mut tracker = ReplicaLagTracker::new(1024, 1024 * 1024);
        let chunk = ChunkId::new(1);
        tracker.update_primary_frontier(chunk, 10000);
        tracker.update_replica_frontier(chunk, NodeId::new(1), 10000, 1);
        tracker.update_replica_frontier(chunk, NodeId::new(2), 9000, 2);
        tracker.update_replica_frontier(chunk, NodeId::new(3), 5000, 3);

        let lagging = tracker.lagging_replicas();
        // Node 1 is at frontier (0 behind), Nodes 2 and 3 are behind
        assert_eq!(lagging.len(), 2);
        assert!(lagging.iter().any(|e| e.replica_node == NodeId::new(2)));
        assert!(lagging.iter().any(|e| e.replica_node == NodeId::new(3)));
    }

    #[test]
    fn repair_required_lists_only_past_repair_threshold() {
        let mut tracker = ReplicaLagTracker::new(100, 500);
        let chunk = ChunkId::new(1);
        tracker.update_primary_frontier(chunk, 10000);
        tracker.update_replica_frontier(chunk, NodeId::new(1), 9900, 1); // 100 behind = bounded
        tracker.update_replica_frontier(chunk, NodeId::new(2), 5000, 2); // 5000 behind = repair
        tracker.update_replica_frontier(chunk, NodeId::new(3), 600, 3); // past 500 = repair

        let repair = tracker.repair_required();
        assert_eq!(repair.len(), 2);
    }

    #[test]
    fn remove_replica_cleans_all_entries_for_node() {
        let mut tracker = ReplicaLagTracker::new(1024, 1024 * 1024);
        let c1 = ChunkId::new(1);
        let c2 = ChunkId::new(2);
        let node = NodeId::new(1);
        tracker.update_primary_frontier(c1, 4096);
        tracker.update_primary_frontier(c2, 4096);
        tracker.update_replica_frontier(c1, node, 4096, 1);
        tracker.update_replica_frontier(c2, node, 4096, 2);
        assert_eq!(tracker.entry_count(), 2);

        tracker.remove_replica(node);
        assert_eq!(tracker.entry_count(), 0);
    }

    #[test]
    fn replicated_lag_entries_are_independent() {
        let mut tracker = ReplicaLagTracker::new(1024, 1024 * 1024);
        let chunk = ChunkId::new(1);
        tracker.update_primary_frontier(chunk, 5000);
        tracker.update_replica_frontier(chunk, NodeId::new(1), 5000, 1);
        tracker.update_replica_frontier(chunk, NodeId::new(2), 4000, 2);

        let lag1 = tracker.get_lag(chunk, NodeId::new(1)).unwrap();
        let lag2 = tracker.get_lag(chunk, NodeId::new(2)).unwrap();
        assert_eq!(lag1.bytes_behind.0, 0);
        assert_eq!(lag2.bytes_behind.0, 1000);
        assert_eq!(lag1.lag_class, VisibilityClass::Exact);
        assert_eq!(lag2.lag_class, VisibilityClass::BoundedLag);
    }
}
