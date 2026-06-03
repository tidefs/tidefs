//! Checkpoint persistence backed by [`tidefs_local_object_store::LocalObjectStore`].
//!
//! Implements the [`tidefs_membership_epoch::snapshot::EpochSnapshotStore`] trait
//! using the local object store's `put_named` / `get_named` API.  Checkpoints
//! are stored as `__membership_checkpoint_{seq:020}` objects, and the latest
//! sequence number is tracked via a `__membership_checkpoint_head` sentinel.
//!
//! ## Design
//!
//! 1. Each checkpoint is a named object with a zero-padded sequence number.
//! 2. The head object stores the latest sequence number as a little-endian u64.
//! 3. On write, the head is updated atomically after the checkpoint object.
//! 4. On read, the head is consulted first, then the checkpoint object is fetched.

use std::path::Path;
use std::sync::{Arc, Mutex};

use tidefs_local_object_store::LocalObjectStore;
#[cfg(test)]
use tidefs_membership_epoch::checkpoint::CheckpointManager;
use tidefs_membership_epoch::snapshot::{EpochSnapshotError, EpochSnapshotStore};

#[cfg(test)]
use tidefs_membership_epoch::snapshot::{MembershipEpochSnapshot, TransportAddress};
#[cfg(test)]
use tidefs_membership_epoch::{EpochId, MemberId};
#[cfg(test)]
use tidefs_membership_types::Incarnation;

// ---------------------------------------------------------------------------
// Object names
// ---------------------------------------------------------------------------

/// Prefix for checkpoint named objects.
const CHECKPOINT_PREFIX: &str = "__membership_checkpoint_";

/// Named object for the latest-sequence-number sentinel.
const CHECKPOINT_HEAD_NAME: &str = "__membership_checkpoint_head";

// ---------------------------------------------------------------------------
// CheckpointPersistence
// ---------------------------------------------------------------------------

/// A [`EpochSnapshotStore`] backed by a [`LocalObjectStore`].
///
/// Each checkpoint is stored as a named object with key
/// `__membership_checkpoint_{seq:020}`. The head sentinel tracks
/// the latest sequence number.
pub struct CheckpointPersistence {
    store: Arc<Mutex<LocalObjectStore>>,
}

impl CheckpointPersistence {
    /// Open (or create) a checkpoint persistence store under `root`.
    ///
    /// The store creates a `LocalObjectStore` in the given directory.
    /// Existing checkpoints are discovered during construction.
    ///
    /// # Errors
    ///
    /// Returns `EpochSnapshotError::StorageError` if the underlying
    /// `LocalObjectStore` cannot be opened.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, EpochSnapshotError> {
        let store = LocalObjectStore::open(root.as_ref()).map_err(|e| {
            EpochSnapshotError::StorageError(format!(
                "cannot open checkpoint store at {}: {e}",
                root.as_ref().display()
            ))
        })?;
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
        })
    }

    /// Return the inner `LocalObjectStore` (guarded by a mutex).
    #[must_use]
    pub fn inner_store(&self) -> &Arc<Mutex<LocalObjectStore>> {
        &self.store
    }
}

impl EpochSnapshotStore for CheckpointPersistence {
    fn write_snapshot(
        &self,
        encoded: &[u8],
        sequence_number: u64,
    ) -> Result<(), EpochSnapshotError> {
        let mut guard = self
            .store
            .lock()
            .map_err(|e| EpochSnapshotError::StorageError(format!("lock poisoned: {e}")))?;

        let name = checkpoint_name(sequence_number);
        guard
            .put_named(name.as_bytes(), encoded)
            .map_err(|e| EpochSnapshotError::StorageError(format!("put_named({name}): {e}")))?;

        // Update head sentinel.
        let head_bytes = sequence_number.to_le_bytes();
        guard
            .put_named(CHECKPOINT_HEAD_NAME.as_bytes(), &head_bytes)
            .map_err(|e| {
                EpochSnapshotError::StorageError(format!("put_named({CHECKPOINT_HEAD_NAME}): {e}"))
            })?;

        Ok(())
    }

    fn read_snapshot(&self, sequence_number: u64) -> Result<Option<Vec<u8>>, EpochSnapshotError> {
        let guard = self
            .store
            .lock()
            .map_err(|e| EpochSnapshotError::StorageError(format!("lock poisoned: {e}")))?;

        let name = checkpoint_name(sequence_number);
        guard
            .get_named(name.as_bytes())
            .map_err(|e| EpochSnapshotError::StorageError(format!("get_named({name}): {e}")))
    }

    fn list_snapshots(&self) -> Result<Vec<u64>, EpochSnapshotError> {
        // We only track the latest via the head sentinel.
        // Return at most one entry: the head sequence, if it exists.
        let guard = self
            .store
            .lock()
            .map_err(|e| EpochSnapshotError::StorageError(format!("lock poisoned: {e}")))?;

        match guard.get_named(CHECKPOINT_HEAD_NAME.as_bytes()) {
            Ok(Some(bytes)) if bytes.len() >= 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes[..8]);
                let seq = u64::from_le_bytes(arr);
                Ok(vec![seq])
            }
            Ok(_) => Ok(Vec::new()),
            Err(e) => Err(EpochSnapshotError::StorageError(format!(
                "get_named({CHECKPOINT_HEAD_NAME}): {e}"
            ))),
        }
    }

    fn clear(&self) -> Result<(), EpochSnapshotError> {
        let mut guard = self
            .store
            .lock()
            .map_err(|e| EpochSnapshotError::StorageError(format!("lock poisoned: {e}")))?;
        // Write a zero-length head to signal "no checkpoints".
        let _ = guard.put_named(CHECKPOINT_HEAD_NAME.as_bytes(), &[]);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the named-object key for a given sequence number.
fn checkpoint_name(seq: u64) -> String {
    format!("{CHECKPOINT_PREFIX}{seq:020}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_root(test_name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("tidefs-checkpoint-persistence-tests")
            .join(test_name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_snapshot(seq: u64, epoch_id: u64) -> MembershipEpochSnapshot {
        MembershipEpochSnapshot::new(
            seq,
            EpochId::new(epoch_id),
            MemberId::new(1),
            Incarnation::ZERO,
            vec![
                (MemberId::new(1), TransportAddress::new("10.0.0.1:8000")),
                (MemberId::new(2), TransportAddress::new("10.0.0.2:8000")),
            ],
        )
    }

    #[test]
    fn write_and_read_snapshot() {
        let root = tmp_root("write_and_read_snapshot");
        let cp = CheckpointPersistence::open(&root).unwrap();

        let snap = sample_snapshot(1, 5);
        let encoded = snap.encode().unwrap();
        cp.write_snapshot(&encoded, 1).unwrap();

        let read = cp.read_snapshot(1).unwrap().unwrap();
        let decoded = MembershipEpochSnapshot::decode(&read).unwrap();
        assert_eq!(decoded, snap);
    }

    #[test]
    fn missing_snapshot_returns_none() {
        let root = tmp_root("missing_snapshot_returns_none");
        let cp = CheckpointPersistence::open(&root).unwrap();
        let result = cp.read_snapshot(99).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn list_snapshots_returns_head() {
        let root = tmp_root("list_snapshots_returns_head");
        let cp = CheckpointPersistence::open(&root).unwrap();

        let snap = sample_snapshot(7, 10);
        let encoded = snap.encode().unwrap();
        cp.write_snapshot(&encoded, 7).unwrap();

        let seqs = cp.list_snapshots().unwrap();
        assert_eq!(seqs, vec![7]);
    }

    #[test]
    fn list_snapshots_empty_on_fresh_store() {
        let root = tmp_root("list_snapshots_empty");
        let cp = CheckpointPersistence::open(&root).unwrap();
        let seqs = cp.list_snapshots().unwrap();
        assert!(seqs.is_empty());
    }

    #[test]
    fn clear_resets_head() {
        let root = tmp_root("clear_resets_head");
        let cp = CheckpointPersistence::open(&root).unwrap();

        let snap = sample_snapshot(3, 1);
        let encoded = snap.encode().unwrap();
        cp.write_snapshot(&encoded, 3).unwrap();
        assert_eq!(cp.list_snapshots().unwrap(), vec![3]);

        cp.clear().unwrap();
        assert!(cp.list_snapshots().unwrap().is_empty());
    }

    #[test]
    fn overwrite_same_sequence_number() {
        let root = tmp_root("overwrite_same_sequence");
        let cp = CheckpointPersistence::open(&root).unwrap();

        let snap1 = sample_snapshot(1, 1);
        cp.write_snapshot(&snap1.encode().unwrap(), 1).unwrap();

        let snap2 = MembershipEpochSnapshot::new(
            1,
            EpochId::new(2),
            MemberId::new(2),
            Incarnation(1),
            vec![(MemberId::new(3), TransportAddress::new("10.0.0.3:8000"))],
        );
        cp.write_snapshot(&snap2.encode().unwrap(), 1).unwrap();

        let read = cp.read_snapshot(1).unwrap().unwrap();
        let decoded = MembershipEpochSnapshot::decode(&read).unwrap();
        assert_eq!(decoded, snap2);
    }

    #[test]
    fn checkpoint_manager_integration_with_local_store() {
        let root = tmp_root("checkpoint_manager_integration");
        let cp = CheckpointPersistence::open(&root).unwrap();
        let store: Box<dyn EpochSnapshotStore> = Box::new(cp);
        let mut mgr = CheckpointManager::new(store);

        let roster = vec![
            (MemberId::new(1), TransportAddress::new("10.0.0.1:8000")),
            (MemberId::new(2), TransportAddress::new("10.0.0.2:8000")),
        ];

        let created = mgr
            .create_checkpoint(EpochId::new(5), MemberId::new(1), Incarnation::ZERO, roster)
            .unwrap();
        assert_eq!(created.sequence_number, 1);

        let loaded = mgr.latest_checkpoint().unwrap().unwrap();
        assert_eq!(loaded.epoch, EpochId::new(5));
        assert_eq!(loaded.roster.len(), 2);
    }

    #[test]
    fn multiple_checkpoints() {
        let root = tmp_root("multiple_checkpoints");
        let cp = CheckpointPersistence::open(&root).unwrap();
        let store: Box<dyn EpochSnapshotStore> = Box::new(cp);
        let mut mgr = CheckpointManager::new(store);

        mgr.create_checkpoint(
            EpochId::new(1),
            MemberId::new(1),
            Incarnation::ZERO,
            vec![(MemberId::new(1), TransportAddress::new("10.0.0.1:8000"))],
        )
        .unwrap();

        mgr.create_checkpoint(
            EpochId::new(2),
            MemberId::new(1),
            Incarnation(1),
            vec![
                (MemberId::new(1), TransportAddress::new("10.0.0.1:8000")),
                (MemberId::new(2), TransportAddress::new("10.0.0.2:8000")),
            ],
        )
        .unwrap();

        let latest = mgr.latest_checkpoint().unwrap().unwrap();
        assert_eq!(latest.sequence_number, 2);
        assert_eq!(latest.epoch, EpochId::new(2));
        assert_eq!(latest.roster.len(), 2);
    }

    #[test]
    fn restart_simulation_loads_latest_checkpoint() {
        let roster = vec![
            (MemberId::new(1), TransportAddress::new("10.0.0.1:8000")),
            (MemberId::new(2), TransportAddress::new("10.0.0.2:8000")),
            (MemberId::new(3), TransportAddress::new("10.0.0.3:8000")),
        ];

        let root = tmp_root("restart_simulation");

        // Phase 1: running runtime creates a checkpoint, then crashes.
        {
            let cp = CheckpointPersistence::open(&root).unwrap();
            let store: Box<dyn EpochSnapshotStore> = Box::new(cp);
            let mut mgr = CheckpointManager::new(store);
            mgr.create_checkpoint(
                EpochId::new(5),
                MemberId::new(1),
                Incarnation::ZERO,
                roster.clone(),
            )
            .unwrap();
        }

        // Phase 2: restart — fresh CheckpointManager re-opens the same dir,
        // loads the latest checkpoint, and verifies the recovered state.
        {
            let cp = CheckpointPersistence::open(&root).unwrap();
            let store: Box<dyn EpochSnapshotStore> = Box::new(cp);
            let mgr = CheckpointManager::new(store);
            let loaded = mgr.latest_checkpoint().unwrap().unwrap();
            assert_eq!(loaded.epoch, EpochId::new(5));
            assert_eq!(loaded.coordinator, MemberId::new(1));
            assert_eq!(loaded.incarnation, Incarnation::ZERO);
            assert_eq!(loaded.roster.len(), 3);
            assert_eq!(loaded.sequence_number, 1);
        }
    }

    #[test]
    fn checkpoint_bounds_journal_replay() {
        use tidefs_membership_epoch::snapshot::{recover_roster, MembershipEpochSnapshot};
        use tidefs_membership_epoch::transition_journal::MembershipTransitionJournal;

        let root = tmp_root("checkpoint_bounds_journal_replay");
        let cp = CheckpointPersistence::open(&root).unwrap();
        let store: Box<dyn EpochSnapshotStore> = Box::new(cp);

        // Write a checkpoint at epoch 5 with members 1,2.
        let snap = MembershipEpochSnapshot::new(
            1,
            EpochId::new(5),
            MemberId::new(1),
            Incarnation::ZERO,
            vec![
                (MemberId::new(1), TransportAddress::new("10.0.0.1:8000")),
                (MemberId::new(2), TransportAddress::new("10.0.0.2:8000")),
            ],
        );
        tidefs_membership_epoch::snapshot::write_epoch_snapshot(store.as_ref(), &snap).unwrap();

        // Build a journal with entries at epochs 4, 5, 6, 7.
        // Epochs <= 5 should be skipped during replay.
        use tidefs_membership_epoch::transition_journal::TransitionKind;
        use tidefs_membership_epoch::LeaveReason;

        let mut journal = MembershipTransitionJournal::new();
        // Epoch 4 join (should be skipped — before checkpoint)
        let id4 = journal.record_prepare(
            TransitionKind::Join {
                peer_id: MemberId::new(10),
                epoch: EpochId::new(4),
            },
            1000,
        );
        let _ = journal.record_commit(id4, 1001);
        // Epoch 5 join (should be skipped — equal to checkpoint)
        let id5 = journal.record_prepare(
            TransitionKind::Join {
                peer_id: MemberId::new(11),
                epoch: EpochId::new(5),
            },
            1002,
        );
        let _ = journal.record_commit(id5, 1003);
        // Epoch 6 join (should be replayed)
        let id6 = journal.record_prepare(
            TransitionKind::Join {
                peer_id: MemberId::new(3),
                epoch: EpochId::new(6),
            },
            1004,
        );
        let _ = journal.record_commit(id6, 1005);
        // Epoch 7 leave (should be replayed — removes member 2)
        let id7 = journal.record_prepare(
            TransitionKind::Leave {
                peer_id: MemberId::new(2),
                epoch: EpochId::new(7),
                reason: LeaveReason::Voluntary,
            },
            1006,
        );
        let _ = journal.record_commit(id7, 1007);

        let recovered = recover_roster(store.as_ref(), &journal).unwrap();
        // Post-replay members: 1 (from snapshot), 3 (join at epoch 6).
        // Member 2 was removed at epoch 7.
        assert_eq!(
            recovered.member_ids,
            vec![MemberId::new(1), MemberId::new(3)]
        );
        assert_eq!(recovered.epoch, EpochId::new(7));
        assert_eq!(recovered.coordinator, MemberId::new(1));
    }
}
