// Quorum acknowledgment tracker: maps (txg_id, object_id) to a bitset of
// acknowledging replica indices. Used by quorum-write runtime for majority-quorum
// decisions across replica groups.
//
// Supports up to 64 replicas per group via u64 bitset.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Tracks which replicas in a replica group have acknowledged each
/// transaction-group operation. Uses a u64 bitset supporting up to 64 replicas.
#[derive(Clone, Debug, Default)]
pub struct AckTracker {
    acks: HashMap<(u64, u64), u64>,
}

impl AckTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            acks: HashMap::new(),
        }
    }

    /// Record that `replica_index` has acknowledged the operation identified
    /// by `(txg_id, object_id)`.  Panics if replica_index >= 64.
    pub fn record_ack(&mut self, txg_id: u64, object_id: u64, replica_index: u32) {
        assert!(
            replica_index < 64,
            "replica_index {replica_index} exceeds bitset capacity of 64"
        );
        let entry = self.acks.entry((txg_id, object_id)).or_insert(0);
        *entry |= 1u64 << replica_index;
    }

    /// Return the number of replicas that have acknowledged this operation.
    pub fn witness_count(&self, txg_id: u64, object_id: u64) -> usize {
        self.acks
            .get(&(txg_id, object_id))
            .map(|bits| bits.count_ones() as usize)
            .unwrap_or(0)
    }

    /// Return true when at least `quorum_size` replicas have acknowledged.
    pub fn has_quorum(&self, txg_id: u64, object_id: u64, quorum_size: usize) -> bool {
        self.witness_count(txg_id, object_id) >= quorum_size
    }

    /// Drop all acknowledgment records whose txg_id is strictly below
    /// `horizon_commit_group`, preventing unbounded memory growth.
    pub fn prune_epoch(&mut self, horizon_commit_group: u64) {
        self.acks
            .retain(|&(commit_group, _), _| commit_group >= horizon_commit_group);
    }

    /// Number of distinct (commit_group, object) entries currently tracked.
    pub fn entry_count(&self) -> usize {
        self.acks.len()
    }

    /// Return a snapshot suitable for serialization and crash recovery.
    pub fn snapshot(&self) -> WitnessSetSnapshot {
        let entries = self
            .acks
            .iter()
            .map(|(&(txg_id, object_id), &bitset)| SnapshotEntry {
                txg_id,
                object_id,
                ack_bitset: bitset,
            })
            .collect();
        WitnessSetSnapshot { entries }
    }

    /// Restore tracker state from a previously saved snapshot.
    pub fn restore(&mut self, snapshot: &WitnessSetSnapshot) {
        self.acks.clear();
        for entry in &snapshot.entries {
            self.acks
                .insert((entry.txg_id, entry.object_id), entry.ack_bitset);
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot types for serialization and crash recovery
// ---------------------------------------------------------------------------

/// Serializable checkpoint of witness acknowledgment state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessSetSnapshot {
    pub entries: Vec<SnapshotEntry>,
}

/// A single (commit_group, object) entry in a snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub txg_id: u64,
    pub object_id: u64,
    pub ack_bitset: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_tracker_is_empty() {
        let t = AckTracker::new();
        assert_eq!(t.entry_count(), 0);
        assert_eq!(t.witness_count(1, 100), 0);
    }

    #[test]
    fn test_record_and_count_single_ack() {
        let mut t = AckTracker::new();
        t.record_ack(1, 100, 0);
        assert_eq!(t.witness_count(1, 100), 1);
    }

    #[test]
    fn test_record_multiple_replicas() {
        let mut t = AckTracker::new();
        t.record_ack(2, 200, 0);
        t.record_ack(2, 200, 1);
        t.record_ack(2, 200, 3);
        assert_eq!(t.witness_count(2, 200), 3);
    }

    #[test]
    fn test_duplicate_ack_is_idempotent() {
        let mut t = AckTracker::new();
        t.record_ack(3, 300, 2);
        t.record_ack(3, 300, 2);
        t.record_ack(3, 300, 2);
        assert_eq!(t.witness_count(3, 300), 1);
    }

    #[test]
    fn test_distinct_objects_independent() {
        let mut t = AckTracker::new();
        t.record_ack(1, 10, 0);
        t.record_ack(1, 20, 1);
        t.record_ack(2, 10, 2);
        assert_eq!(t.witness_count(1, 10), 1);
        assert_eq!(t.witness_count(1, 20), 1);
        assert_eq!(t.witness_count(2, 10), 1);
    }

    #[test]
    fn test_has_quorum_exact_majority() {
        let mut t = AckTracker::new();
        // 3 of 5 replicas
        t.record_ack(1, 100, 0);
        t.record_ack(1, 100, 1);
        t.record_ack(1, 100, 2);
        assert!(t.has_quorum(1, 100, 3));
    }

    #[test]
    fn test_has_quorum_below_majority() {
        let mut t = AckTracker::new();
        t.record_ack(1, 100, 0);
        t.record_ack(1, 100, 1);
        // Need 3, have 2
        assert!(!t.has_quorum(1, 100, 3));
    }

    #[test]
    fn test_has_quorum_unanimous() {
        let mut t = AckTracker::new();
        for i in 0..5 {
            t.record_ack(1, 100, i);
        }
        assert!(t.has_quorum(1, 100, 5));
        assert!(t.has_quorum(1, 100, 3));
    }

    #[test]
    fn test_has_quorum_empty_set() {
        let t = AckTracker::new();
        assert!(!t.has_quorum(99, 999, 1));
    }

    #[test]
    fn test_prune_epoch_removes_old_entries() {
        let mut t = AckTracker::new();
        t.record_ack(10, 100, 0);
        t.record_ack(20, 200, 1);
        t.record_ack(30, 300, 2);

        t.prune_epoch(20);
        assert_eq!(t.witness_count(10, 100), 0); // pruned
        assert_eq!(t.witness_count(20, 200), 1); // at horizon, kept
        assert_eq!(t.witness_count(30, 300), 1); // above horizon, kept
        assert_eq!(t.entry_count(), 2);
    }

    #[test]
    fn test_prune_epoch_horizon_zero_keeps_all() {
        let mut t = AckTracker::new();
        t.record_ack(5, 50, 0);
        t.prune_epoch(0);
        assert_eq!(t.entry_count(), 1);
    }

    #[test]
    fn test_prune_epoch_horizon_future_clears_all() {
        let mut t = AckTracker::new();
        t.record_ack(5, 50, 0);
        t.record_ack(7, 70, 1);
        t.prune_epoch(100);
        assert_eq!(t.entry_count(), 0);
    }

    #[test]
    fn test_snapshot_round_trip_empty() {
        let t = AckTracker::new();
        let snap = t.snapshot();
        assert!(snap.entries.is_empty());

        let mut t2 = AckTracker::new();
        t2.restore(&snap);
        assert_eq!(t2.entry_count(), 0);
    }

    #[test]
    fn test_snapshot_round_trip_full() {
        let mut t = AckTracker::new();
        t.record_ack(1, 100, 0);
        t.record_ack(1, 100, 2);
        t.record_ack(2, 200, 1);
        t.record_ack(2, 200, 3);
        t.record_ack(2, 200, 5);

        let snap = t.snapshot();

        let mut t2 = AckTracker::new();
        t2.restore(&snap);

        assert_eq!(t2.witness_count(1, 100), 2);
        assert_eq!(t2.witness_count(2, 200), 3);
        assert_eq!(t2.entry_count(), 2);
    }

    #[test]
    fn test_snapshot_serialize_deserialize() {
        let mut t = AckTracker::new();
        t.record_ack(7, 77, 0);
        t.record_ack(7, 77, 3);
        t.record_ack(8, 88, 1);

        let snap = t.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let snap2: WitnessSetSnapshot = serde_json::from_str(&json).unwrap();

        let mut t2 = AckTracker::new();
        t2.restore(&snap2);

        assert_eq!(t2.witness_count(7, 77), 2);
        assert_eq!(t2.witness_count(8, 88), 1);
        assert!(t2.has_quorum(7, 77, 2));
        assert!(!t2.has_quorum(7, 77, 3));
    }

    #[test]
    fn test_integration_3_of_5_quorum() {
        let mut t = AckTracker::new();
        // Simulate 3 of 5 replica acks
        t.record_ack(42, 1, 0);
        t.record_ack(42, 1, 1);
        t.record_ack(42, 1, 4);

        assert!(t.has_quorum(42, 1, 3));
        assert!(!t.has_quorum(42, 1, 4));
    }

    #[test]
    #[should_panic(expected = "replica_index")]
    fn test_replica_index_out_of_bounds() {
        let mut t = AckTracker::new();
        t.record_ack(1, 1, 64);
    }

    #[test]
    fn test_high_replica_index_boundary() {
        let mut t = AckTracker::new();
        t.record_ack(1, 1, 63);
        assert_eq!(t.witness_count(1, 1), 1);
    }
}
