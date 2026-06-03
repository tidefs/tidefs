//! Membership epoch checkpoint management for bounded-replay crash recovery.
//!
//! The [`CheckpointManager`] wraps the underlying [`EpochSnapshotStore`]
//! and provides high-level checkpoint creation and retrieval on top of
//! [`MembershipEpochSnapshot`]. It tracks a monotonic checkpoint sequence
//! number so each checkpoint supersedes the previous one.
//!
//! ## Integration
//!
//! - Call [`create_checkpoint`](CheckpointManager::create_checkpoint) after
//!   quorum-confirmed epoch advancement to bound future journal replay.
//! - Call [`latest_checkpoint`](CheckpointManager::latest_checkpoint) on
//!   restart to reconstruct pre-crash state before replaying only the
//!   post-checkpoint transition journal entries.

use super::snapshot::{
    load_latest_snapshot, write_epoch_snapshot, EpochSnapshotError, EpochSnapshotStore,
    MembershipEpochSnapshot, TransportAddress,
};
use super::{EpochId, MemberId};
use tidefs_membership_types::Incarnation;

// ---------------------------------------------------------------------------
// CheckpointManager
// ---------------------------------------------------------------------------

/// High-level checkpoint manager wrapping a pluggable snapshot store.
///
/// Tracks a monotonic sequence number so each checkpoint automatically
/// supersedes any previous one. Delegates persistence to the underlying
/// [`EpochSnapshotStore`].
pub struct CheckpointManager {
    store: Box<dyn EpochSnapshotStore>,
    next_sequence: u64,
}

impl CheckpointManager {
    /// Create a new checkpoint manager backed by the given store.
    ///
    /// On construction, the manager scans for the latest persisted
    /// checkpoint and initializes `next_sequence` to one past that.
    pub fn new(store: Box<dyn EpochSnapshotStore>) -> Self {
        let latest_seq = load_latest_snapshot(store.as_ref())
            .ok()
            .flatten()
            .map(|s| s.sequence_number)
            .unwrap_or(0);
        Self {
            store,
            next_sequence: latest_seq + 1,
        }
    }

    /// Create a new checkpoint from the current membership state.
    ///
    /// The roster is encoded as `(MemberId, TransportAddress)` pairs.
    ///
    /// # Errors
    ///
    /// Returns `EpochSnapshotError` if serialization or storage fails.
    pub fn create_checkpoint(
        &mut self,
        epoch: EpochId,
        coordinator: MemberId,
        incarnation: Incarnation,
        roster: impl IntoIterator<Item = (MemberId, TransportAddress)>,
    ) -> Result<MembershipEpochSnapshot, EpochSnapshotError> {
        let seq = self.next_sequence;
        self.next_sequence += 1;

        let snapshot = MembershipEpochSnapshot::new(seq, epoch, coordinator, incarnation, roster);

        write_epoch_snapshot(self.store.as_ref(), &snapshot)?;
        Ok(snapshot)
    }

    /// Load the latest (highest sequence number) checkpoint from the store.
    ///
    /// Returns `None` when no checkpoint has been persisted yet.
    pub fn latest_checkpoint(&self) -> Result<Option<MembershipEpochSnapshot>, EpochSnapshotError> {
        load_latest_snapshot(self.store.as_ref())
    }

    /// The next sequence number that will be assigned.
    #[must_use]
    pub fn next_sequence_number(&self) -> u64 {
        self.next_sequence
    }

    /// Access the underlying store.
    #[must_use]
    pub fn store(&self) -> &dyn EpochSnapshotStore {
        self.store.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::snapshot::InMemorySnapshotStore;
    use super::super::MemberId;
    use super::*;

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn epoch(id: u64) -> EpochId {
        EpochId::new(id)
    }

    fn addr_for(id: u64) -> TransportAddress {
        TransportAddress::new(format!("10.0.0.{id}:8000"))
    }

    fn roster_items(ids: &[u64]) -> Vec<(MemberId, TransportAddress)> {
        ids.iter().map(|&id| (member(id), addr_for(id))).collect()
    }

    #[test]
    fn create_and_retrieve_checkpoint() {
        let store = Box::new(InMemorySnapshotStore::new());
        let mut mgr = CheckpointManager::new(store);

        let snapshot = mgr
            .create_checkpoint(
                epoch(5),
                member(1),
                Incarnation::ZERO,
                roster_items(&[1, 2, 3]),
            )
            .unwrap();

        assert_eq!(snapshot.sequence_number, 1);
        assert_eq!(snapshot.epoch, epoch(5));
        assert_eq!(snapshot.coordinator, member(1));

        let loaded = mgr.latest_checkpoint().unwrap().unwrap();
        assert_eq!(loaded, snapshot);
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        let store = Box::new(InMemorySnapshotStore::new());
        let mut mgr = CheckpointManager::new(store);

        let s1 = mgr
            .create_checkpoint(epoch(1), member(1), Incarnation::ZERO, roster_items(&[1]))
            .unwrap();
        let s2 = mgr
            .create_checkpoint(epoch(2), member(1), Incarnation(1), roster_items(&[1, 2]))
            .unwrap();
        let s3 = mgr
            .create_checkpoint(
                epoch(3),
                member(2),
                Incarnation(1),
                roster_items(&[1, 2, 3]),
            )
            .unwrap();

        assert_eq!(s1.sequence_number, 1);
        assert_eq!(s2.sequence_number, 2);
        assert_eq!(s3.sequence_number, 3);

        let latest = mgr.latest_checkpoint().unwrap().unwrap();
        assert_eq!(latest.sequence_number, 3);
        assert_eq!(latest.epoch, epoch(3));
    }

    #[test]
    fn latest_checkpoint_empty_store_returns_none() {
        let store = Box::new(InMemorySnapshotStore::new());
        let mgr = CheckpointManager::new(store);

        let result = mgr.latest_checkpoint().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn manager_initializes_next_sequence_from_existing_store() {
        let store = Box::new(InMemorySnapshotStore::new());
        {
            let snap = MembershipEpochSnapshot::new(
                4,
                epoch(2),
                member(1),
                Incarnation::ZERO,
                roster_items(&[1, 2]),
            );
            write_epoch_snapshot(store.as_ref(), &snap).unwrap();
        }

        let mut mgr = CheckpointManager::new(store);
        assert_eq!(mgr.next_sequence_number(), 5);

        let s5 = mgr
            .create_checkpoint(
                epoch(3),
                member(1),
                Incarnation::ZERO,
                roster_items(&[1, 2, 3]),
            )
            .unwrap();
        assert_eq!(s5.sequence_number, 5);
    }

    #[test]
    fn checkpoint_round_trip_full_state() {
        let store = Box::new(InMemorySnapshotStore::new());
        let mut mgr = CheckpointManager::new(store);

        let roster = vec![
            (member(10), addr_for(10)),
            (member(20), addr_for(20)),
            (member(30), addr_for(30)),
        ];

        let _created = mgr
            .create_checkpoint(epoch(7), member(10), Incarnation(3), roster)
            .unwrap();

        let loaded = mgr.latest_checkpoint().unwrap().unwrap();
        assert_eq!(loaded.epoch, epoch(7));
        assert_eq!(loaded.coordinator, member(10));
        assert_eq!(loaded.incarnation, Incarnation(3));
        assert_eq!(loaded.member_ids().len(), 3);

        let ids: Vec<u64> = loaded.roster.iter().map(|(id, _)| id.0).collect();
        assert_eq!(ids, vec![10, 20, 30]);
    }
}
