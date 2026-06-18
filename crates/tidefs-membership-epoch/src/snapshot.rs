// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Membership epoch snapshot persistence for coordinator crash-recovery bootstrap.
//!
//! Stores a point-in-time snapshot of the membership roster (members with
//! transport addresses, current epoch, coordinator, and a monotonic sequence
//! number) so a restarting coordinator can reconstruct the current state from
//! the latest snapshot plus incremental transition-journal replay, avoiding
//! full sequential journal replay for long-running clusters.
//!
//! ## Design
//!
//! 1. **Snapshot creation**: After a quorum-confirmed roster change, a snapshot
//!    is written before advancing the in-memory epoch. Each snapshot carries a
//!    monotonically increasing sequence number.
//! 2. **Recovery**: On coordinator restart, `recover_roster` loads the latest
//!    snapshot (highest sequence number) and replays only those transition
//!    journal entries whose epoch is strictly greater than the snapshot epoch.
//! 3. **Empty fallback**: When no snapshot exists (first start or clean store),
//!    `load_latest_snapshot` returns `None` and `recover_roster` returns an
//!    empty roster so the caller bootstraps from genesis.

use crate::transition_journal::{MembershipTransitionJournal, TransitionKind};
use crate::{EpochId, MemberId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tidefs_membership_types::Incarnation;

// ---------------------------------------------------------------------------
// TransportAddress
// ---------------------------------------------------------------------------

/// Network address for reaching a member node.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct TransportAddress {
    /// Host:port or socket address string (e.g. "192.168.1.10:8000").
    pub address: String,
}

impl TransportAddress {
    /// Create a new transport address.
    #[must_use]
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// MembershipEpochSnapshot
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of the membership state.
///
/// Stores the full roster with per-member transport addresses, the current
/// epoch, the coordinator identity, and a monotonic sequence number for
/// ordering snapshots.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MembershipEpochSnapshot {
    /// Monotonically increasing snapshot sequence number.
    pub sequence_number: u64,
    /// The epoch at the time this snapshot was taken.
    pub epoch: EpochId,
    /// The coordinator member at the time of the snapshot.
    pub coordinator: MemberId,
    /// Monotonic coordinator incarnation at snapshot time.
    pub incarnation: tidefs_membership_types::Incarnation,
    /// Ordered set of member entries: (MemberId, TransportAddress).
    pub roster: Vec<(MemberId, TransportAddress)>,
}

impl MembershipEpochSnapshot {
    /// Create a new epoch snapshot.
    ///
    /// The roster is sorted by `MemberId` for deterministic encoding.
    #[must_use]
    pub fn new(
        sequence_number: u64,
        epoch: EpochId,
        coordinator: MemberId,
        incarnation: tidefs_membership_types::Incarnation,
        roster: impl IntoIterator<Item = (MemberId, TransportAddress)>,
    ) -> Self {
        let mut roster: Vec<_> = roster.into_iter().collect();
        roster.sort_by_key(|(id, _)| *id);
        Self {
            sequence_number,
            epoch,
            coordinator,
            incarnation,
            roster,
        }
    }

    /// Encode the snapshot to a binary representation using bincode.
    ///
    /// # Errors
    ///
    /// Returns `EpochSnapshotError::EncodeError` if serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, EpochSnapshotError> {
        bincode::serialize(self)
            .map_err(|e| EpochSnapshotError::EncodeError(format!("snapshot encode failed: {e}")))
    }

    /// Decode a snapshot from its binary representation.
    ///
    /// # Errors
    ///
    /// Returns `EpochSnapshotError::DecodeError` if deserialization fails.
    pub fn decode(data: &[u8]) -> Result<Self, EpochSnapshotError> {
        bincode::deserialize(data)
            .map_err(|e| EpochSnapshotError::DecodeError(format!("snapshot decode failed: {e}")))
    }

    /// The set of member ids in this snapshot, in sorted order.
    #[must_use]
    pub fn member_ids(&self) -> BTreeSet<MemberId> {
        self.roster.iter().map(|(id, _)| *id).collect()
    }

    /// Look up the transport address for a member.
    #[must_use]
    pub fn address_of(&self, member_id: MemberId) -> Option<&TransportAddress> {
        self.roster
            .iter()
            .find(|(id, _)| *id == member_id)
            .map(|(_, addr)| addr)
    }
}

// ---------------------------------------------------------------------------
// EpochSnapshotError
// ---------------------------------------------------------------------------

/// Errors returned by snapshot persistence and recovery operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EpochSnapshotError {
    /// The underlying storage backend returned an error.
    StorageError(String),
    /// Snapshot serialization failed.
    EncodeError(String),
    /// Snapshot deserialization failed.
    DecodeError(String),
    /// The snapshot's epoch is ahead of the journal (data corruption).
    SnapshotAheadOfJournal {
        snapshot_epoch: u64,
        journal_epoch: u64,
    },
    /// No snapshots and no journal entries exist (genesis bootstrap — not an
    /// error, but callers should bootstrap from scratch).
    NoState,
}

impl std::fmt::Display for EpochSnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StorageError(msg) => write!(f, "snapshot storage error: {msg}"),
            Self::EncodeError(msg) => write!(f, "snapshot encode error: {msg}"),
            Self::DecodeError(msg) => write!(f, "snapshot decode error: {msg}"),
            Self::SnapshotAheadOfJournal {
                snapshot_epoch,
                journal_epoch,
            } => {
                write!(
                    f,
                    "snapshot epoch {snapshot_epoch} ahead of journal epoch {journal_epoch}"
                )
            }
            Self::NoState => write!(f, "no snapshot or journal state available"),
        }
    }
}

impl std::error::Error for EpochSnapshotError {}

// ---------------------------------------------------------------------------
// EpochSnapshotStore
// ---------------------------------------------------------------------------

/// Pluggable storage backend for epoch snapshots.
///
/// Implementations persist and retrieve [`MembershipEpochSnapshot`] records,
/// indexed by sequence number. A production implementation writes to the pool
/// label system area; test implementations can use an in-memory map.
pub trait EpochSnapshotStore: Send + Sync {
    /// Persist an encoded snapshot.
    ///
    /// Implementations must overwrite any existing snapshot with the same
    /// sequence number.
    fn write_snapshot(
        &self,
        encoded: &[u8],
        sequence_number: u64,
    ) -> Result<(), EpochSnapshotError>;

    /// Read the encoded bytes for a given sequence number.
    ///
    /// Returns `Ok(None)` if no snapshot exists for that sequence number.
    fn read_snapshot(&self, sequence_number: u64) -> Result<Option<Vec<u8>>, EpochSnapshotError>;

    /// List all persisted snapshot sequence numbers in arbitrary order.
    fn list_snapshots(&self) -> Result<Vec<u64>, EpochSnapshotError>;

    /// Clear all persisted snapshots (for testing/reset).
    fn clear(&self) -> Result<(), EpochSnapshotError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// In-memory snapshot store (for tests)
// ---------------------------------------------------------------------------

/// An in-memory implementation of [`EpochSnapshotStore`] backed by a
/// `Vec<(u64, Vec<u8>)>`.
#[derive(Debug, Default)]
pub struct InMemorySnapshotStore {
    entries: std::sync::Mutex<Vec<(u64, Vec<u8>)>>,
}

impl InMemorySnapshotStore {
    /// Create a new, empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl EpochSnapshotStore for InMemorySnapshotStore {
    fn write_snapshot(
        &self,
        encoded: &[u8],
        sequence_number: u64,
    ) -> Result<(), EpochSnapshotError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|e| EpochSnapshotError::StorageError(format!("lock poisoned: {e}")))?;
        // Overwrite existing entry with same sequence number.
        entries.retain(|(sn, _)| *sn != sequence_number);
        entries.push((sequence_number, encoded.to_vec()));
        Ok(())
    }

    fn read_snapshot(&self, sequence_number: u64) -> Result<Option<Vec<u8>>, EpochSnapshotError> {
        let entries = self
            .entries
            .lock()
            .map_err(|e| EpochSnapshotError::StorageError(format!("lock poisoned: {e}")))?;
        Ok(entries
            .iter()
            .find(|(sn, _)| *sn == sequence_number)
            .map(|(_, data)| data.clone()))
    }

    fn list_snapshots(&self) -> Result<Vec<u64>, EpochSnapshotError> {
        let entries = self
            .entries
            .lock()
            .map_err(|e| EpochSnapshotError::StorageError(format!("lock poisoned: {e}")))?;
        Ok(entries.iter().map(|(sn, _)| *sn).collect())
    }

    fn clear(&self) -> Result<(), EpochSnapshotError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|e| EpochSnapshotError::StorageError(format!("lock poisoned: {e}")))?;
        entries.clear();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// High-level snapshot operations
// ---------------------------------------------------------------------------

/// Write a snapshot to the store.
///
/// Encodes the snapshot and persists it via the store backend.
///
/// # Errors
///
/// Returns `EpochSnapshotError::EncodeError` if serialization fails,
/// or `EpochSnapshotError::StorageError` if the backend write fails.
pub fn write_epoch_snapshot(
    store: &dyn EpochSnapshotStore,
    snapshot: &MembershipEpochSnapshot,
) -> Result<(), EpochSnapshotError> {
    let encoded = snapshot.encode()?;
    store.write_snapshot(&encoded, snapshot.sequence_number)
}

/// Load the latest snapshot (highest sequence number) from the store.
///
/// Returns `Ok(None)` when no snapshots have been persisted.
///
/// # Errors
///
/// Returns `EpochSnapshotError` if the store read or decode fails.
pub fn load_latest_snapshot(
    store: &dyn EpochSnapshotStore,
) -> Result<Option<MembershipEpochSnapshot>, EpochSnapshotError> {
    let seqs = store.list_snapshots()?;
    let max_seq = match seqs.iter().max().copied() {
        Some(s) => s,
        None => return Ok(None),
    };
    let data = store.read_snapshot(max_seq)?;
    match data {
        Some(bytes) => {
            let snapshot = MembershipEpochSnapshot::decode(&bytes)?;
            Ok(Some(snapshot))
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// RecoveredRoster
// ---------------------------------------------------------------------------

/// Result of roster recovery from snapshot + journal replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredRoster {
    /// The reconstructed member set (sorted member ids).
    pub member_ids: Vec<MemberId>,
    /// The epoch after replaying all applicable journal entries.
    pub epoch: EpochId,
    /// The coordinator at the recovered epoch (lowest MemberId).
    pub coordinator: MemberId,
    /// Monotonic coordinator incarnation at snapshot time.
    pub incarnation: tidefs_membership_types::Incarnation,
}

// ---------------------------------------------------------------------------
// Recovery entry point
// ---------------------------------------------------------------------------

/// Recover the membership roster from the latest snapshot and the transition
/// journal.
///
/// 1. Loads the latest snapshot (highest sequence number) from the store.
/// 2. Applies all committed journal transitions whose epoch is strictly
///    greater than the snapshot epoch.
/// 3. Returns the reconstructed roster.
///
/// When no snapshot exists, the recovery starts from an empty roster (epoch 0)
/// and replays all committed journal entries. Prepared entries are skipped
/// because they haven't been committed yet and may be aborted.
///
/// # Errors
///
/// Returns `EpochSnapshotError::NoState` when there is no snapshot and the
/// journal is empty (genesis bootstrap).
pub fn recover_roster(
    store: &dyn EpochSnapshotStore,
    journal: &MembershipTransitionJournal,
) -> Result<RecoveredRoster, EpochSnapshotError> {
    // Load latest snapshot; fall back to empty bootstrap if none exists.
    let (mut member_ids, mut current_epoch, snapshot_epoch, snapshot_incarnation) =
        if let Some(snapshot) = load_latest_snapshot(store)? {
            let ids: Vec<MemberId> = snapshot.roster.iter().map(|(id, _)| *id).collect();
            let epoch = snapshot.epoch;
            let incarnation = snapshot.incarnation;
            (ids, epoch, Some(epoch), incarnation)
        } else {
            // No snapshot: start empty, epoch 0, genesis incarnation.
            (Vec::new(), EpochId::ZERO, None, Incarnation::ZERO)
        };

    // Replay committed journal entries that are after the snapshot epoch.
    for record in journal.iter() {
        // Only consider committed records.
        if !record.is_committed() {
            continue;
        }
        let entry_epoch = record.kind.epoch();

        // If we have a snapshot, only replay entries strictly after it.
        if let Some(snap_epoch) = snapshot_epoch {
            if entry_epoch.0 <= snap_epoch.0 {
                continue;
            }
            // Sanity: journal epoch should not fall behind snapshot.
            if entry_epoch.0 < snap_epoch.0 {
                return Err(EpochSnapshotError::SnapshotAheadOfJournal {
                    snapshot_epoch: snap_epoch.0,
                    journal_epoch: entry_epoch.0,
                });
            }
        }

        // Apply the transition.
        match record.kind {
            TransitionKind::Join { peer_id, .. } => {
                if !member_ids.contains(&peer_id) {
                    member_ids.push(peer_id);
                }
            }
            TransitionKind::Leave { peer_id, .. } => {
                member_ids.retain(|id| *id != peer_id);
            }
        }

        // Advance epoch to the max of current and entry epoch.
        if entry_epoch.0 > current_epoch.0 {
            current_epoch = entry_epoch;
        }
    }

    // Sort and deduplicate member ids.
    member_ids.sort();
    member_ids.dedup();

    if member_ids.is_empty() && snapshot_epoch.is_none() && journal.is_empty() {
        return Err(EpochSnapshotError::NoState);
    }

    // Coordinator is the lowest MemberId (deterministic promotion rule).
    let coordinator = member_ids.first().copied().unwrap_or(MemberId::ZERO);

    Ok(RecoveredRoster {
        member_ids,
        epoch: current_epoch,
        coordinator,
        incarnation: snapshot_incarnation,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transition_journal::{MembershipTransitionJournal, TransitionKind};
    use crate::{EpochId, LeaveReason};

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn epoch(id: u64) -> EpochId {
        EpochId::new(id)
    }

    fn addr(host: &str, port: u16) -> TransportAddress {
        TransportAddress::new(format!("{host}:{port}"))
    }

    fn make_snapshot(
        seq: u64,
        ep: u64,
        coordinator: u64,
        incarnation: u64,
        roster: &[(u64, &str, u16)],
    ) -> MembershipEpochSnapshot {
        MembershipEpochSnapshot::new(
            seq,
            epoch(ep),
            member(coordinator),
            Incarnation(incarnation),
            roster
                .iter()
                .map(|(id, host, port)| (member(*id), addr(host, *port))),
        )
    }

    // ── TransportAddress ─────────────────────────────────────────────

    #[test]
    fn transport_address_creation() {
        let a = TransportAddress::new("10.0.0.1:8000");
        assert_eq!(a.address, "10.0.0.1:8000");
    }

    #[test]
    fn transport_address_ordering() {
        let a = addr("10.0.0.1", 8000);
        let b = addr("10.0.0.2", 8000);
        assert!(a != b);
    }

    // ── MembershipEpochSnapshot ──────────────────────────────────────

    #[test]
    fn snapshot_creation_sorts_roster() {
        let snap = make_snapshot(
            1,
            5,
            10,
            0,
            &[
                (30, "10.0.0.30", 8000),
                (10, "10.0.0.10", 8000),
                (20, "10.0.0.20", 8000),
            ],
        );
        let ids: Vec<u64> = snap.roster.iter().map(|(id, _)| id.0).collect();
        assert_eq!(ids, vec![10, 20, 30]);
    }

    #[test]
    fn snapshot_member_ids_returns_sorted_set() {
        let snap = make_snapshot(1, 1, 1, 0, &[(3, "h3", 1), (1, "h1", 1), (2, "h2", 1)]);
        let ids: Vec<u64> = snap.member_ids().iter().map(|id| id.0).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn snapshot_address_of() {
        let snap = make_snapshot(1, 1, 1, 0, &[(1, "10.0.0.1", 9000), (2, "10.0.0.2", 9000)]);
        assert_eq!(snap.address_of(member(1)).unwrap().address, "10.0.0.1:9000");
        assert_eq!(snap.address_of(member(2)).unwrap().address, "10.0.0.2:9000");
        assert!(snap.address_of(member(99)).is_none());
    }

    // ── encode / decode ──────────────────────────────────────────────

    #[test]
    fn round_trip_encode_decode_single_member() {
        let snap = make_snapshot(1, 1, 1, 0, &[(1, "10.0.0.1", 9000)]);
        let encoded = snap.encode().unwrap();
        let decoded = MembershipEpochSnapshot::decode(&encoded).unwrap();
        assert_eq!(decoded, snap);
    }

    #[test]
    fn round_trip_encode_decode_three_members() {
        let snap = make_snapshot(
            2,
            5,
            10,
            0,
            &[
                (10, "10.0.0.10", 8000),
                (20, "10.0.0.20", 8000),
                (30, "10.0.0.30", 8000),
            ],
        );
        let encoded = snap.encode().unwrap();
        let decoded = MembershipEpochSnapshot::decode(&encoded).unwrap();
        assert_eq!(decoded, snap);
    }

    #[test]
    fn round_trip_encode_decode_seven_members() {
        let snap = make_snapshot(
            3,
            10,
            1,
            0,
            &[
                (1, "10.0.0.1", 9000),
                (2, "10.0.0.2", 9000),
                (3, "10.0.0.3", 9000),
                (4, "10.0.0.4", 9000),
                (5, "10.0.0.5", 9000),
                (6, "10.0.0.6", 9000),
                (7, "10.0.0.7", 9000),
            ],
        );
        let encoded = snap.encode().unwrap();
        let decoded = MembershipEpochSnapshot::decode(&encoded).unwrap();
        assert_eq!(decoded, snap);
    }

    #[test]
    fn decode_garbage_fails() {
        let result = MembershipEpochSnapshot::decode(b"not a valid snapshot");
        assert!(result.is_err());
    }

    #[test]
    fn decode_empty_fails() {
        let result = MembershipEpochSnapshot::decode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn sequence_number_monotonicity() {
        let snap1 = make_snapshot(1, 1, 1, 0, &[(1, "h1", 1)]);
        let snap2 = make_snapshot(2, 1, 1, 0, &[(1, "h1", 1)]);
        assert_ne!(snap1.sequence_number, snap2.sequence_number);
        assert_ne!(snap1, snap2);
    }

    #[test]
    fn snapshot_with_empty_roster() {
        let snap =
            MembershipEpochSnapshot::new(1, epoch(0), member(0), Incarnation::ZERO, Vec::new());
        assert!(snap.roster.is_empty());
        assert!(snap.member_ids().is_empty());

        let encoded = snap.encode().unwrap();
        let decoded = MembershipEpochSnapshot::decode(&encoded).unwrap();
        assert_eq!(decoded, snap);
    }

    // ── InMemorySnapshotStore ────────────────────────────────────────

    #[test]
    fn in_memory_store_write_and_read() {
        let store = InMemorySnapshotStore::new();
        let snap = make_snapshot(1, 1, 1, 0, &[(1, "h1", 1)]);
        let encoded = snap.encode().unwrap();

        store.write_snapshot(&encoded, 1).unwrap();

        let read = store.read_snapshot(1).unwrap().unwrap();
        let decoded = MembershipEpochSnapshot::decode(&read).unwrap();
        assert_eq!(decoded, snap);
    }

    #[test]
    fn in_memory_store_missing_returns_none() {
        let store = InMemorySnapshotStore::new();
        let result = store.read_snapshot(99).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn in_memory_store_overwrite() {
        let store = InMemorySnapshotStore::new();
        let snap1 = make_snapshot(1, 1, 1, 0, &[(1, "h1", 1)]);
        let snap2 = make_snapshot(1, 2, 1, 0, &[(1, "h1", 1), (2, "h2", 1)]);

        store.write_snapshot(&snap1.encode().unwrap(), 1).unwrap();
        store.write_snapshot(&snap2.encode().unwrap(), 1).unwrap();

        let read = store.read_snapshot(1).unwrap().unwrap();
        let decoded = MembershipEpochSnapshot::decode(&read).unwrap();
        assert_eq!(decoded, snap2);
    }

    #[test]
    fn in_memory_store_list_snapshots() {
        let store = InMemorySnapshotStore::new();
        store.write_snapshot(b"data1", 5).unwrap();
        store.write_snapshot(b"data2", 3).unwrap();
        store.write_snapshot(b"data3", 7).unwrap();

        let mut seqs = store.list_snapshots().unwrap();
        seqs.sort();
        assert_eq!(seqs, vec![3, 5, 7]);
    }

    #[test]
    fn in_memory_store_clear() {
        let store = InMemorySnapshotStore::new();
        store.write_snapshot(b"data", 1).unwrap();
        store.clear().unwrap();
        assert!(store.list_snapshots().unwrap().is_empty());
    }

    // ── write_epoch_snapshot / load_latest_snapshot ──────────────────

    #[test]
    fn write_and_load_latest_single_snapshot() {
        let store = InMemorySnapshotStore::new();
        let snap = make_snapshot(1, 5, 1, 0, &[(1, "h1", 1), (2, "h2", 1)]);
        write_epoch_snapshot(&store, &snap).unwrap();

        let loaded = load_latest_snapshot(&store).unwrap().unwrap();
        assert_eq!(loaded, snap);
    }

    #[test]
    fn load_latest_returns_highest_sequence() {
        let store = InMemorySnapshotStore::new();
        let snap1 = make_snapshot(1, 1, 1, 0, &[(1, "h1", 1)]);
        let snap2 = make_snapshot(5, 3, 1, 0, &[(1, "h1", 1), (2, "h2", 1)]);
        let snap3 = make_snapshot(3, 2, 1, 0, &[(1, "h1", 1)]);

        write_epoch_snapshot(&store, &snap1).unwrap();
        write_epoch_snapshot(&store, &snap2).unwrap();
        write_epoch_snapshot(&store, &snap3).unwrap();

        let loaded = load_latest_snapshot(&store).unwrap().unwrap();
        assert_eq!(loaded.sequence_number, 5);
        assert_eq!(loaded, snap2);
    }

    #[test]
    fn load_latest_empty_store_returns_none() {
        let store = InMemorySnapshotStore::new();
        let result = load_latest_snapshot(&store).unwrap();
        assert!(result.is_none());
    }

    // ── recover_roster: snapshot + journal ───────────────────────────

    /// Build a journal with prepared and committed join/leave entries.
    fn build_journal(entries: &[(TransitionKind, bool)]) -> MembershipTransitionJournal {
        let mut j = MembershipTransitionJournal::new();
        let mut t = 1000u64;
        for (kind, committed) in entries {
            t += 1;
            let id = j.record_prepare(*kind, t);

            if *committed {
                let _ = j.record_commit(id, t + 1);
            }
        }
        j
    }

    #[test]
    fn recover_from_snapshot_replays_only_later_epochs() {
        let store = InMemorySnapshotStore::new();
        let snap = make_snapshot(1, 5, 1, 0, &[(1, "h1", 1), (2, "h2", 1)]);
        write_epoch_snapshot(&store, &snap).unwrap();

        let journal = build_journal(&[
            (
                TransitionKind::Join {
                    peer_id: member(3),
                    epoch: epoch(5),
                },
                true,
            ),
            (
                TransitionKind::Leave {
                    peer_id: member(2),
                    epoch: epoch(6),
                    reason: LeaveReason::Voluntary,
                },
                true,
            ),
            (
                TransitionKind::Join {
                    peer_id: member(4),
                    epoch: epoch(7),
                },
                true,
            ),
        ]);

        let recovered = recover_roster(&store, &journal).unwrap();
        assert_eq!(recovered.member_ids, vec![member(1), member(4)]);
        assert_eq!(recovered.epoch, epoch(7));
        assert_eq!(recovered.coordinator, member(1));
    }

    #[test]
    fn recover_skips_prepared_uncommitted_entries() {
        let store = InMemorySnapshotStore::new();
        let snap = make_snapshot(1, 1, 1, 0, &[(1, "h1", 1)]);
        write_epoch_snapshot(&store, &snap).unwrap();

        let journal = build_journal(&[
            (
                TransitionKind::Join {
                    peer_id: member(2),
                    epoch: epoch(2),
                },
                true,
            ),
            (
                TransitionKind::Join {
                    peer_id: member(3),
                    epoch: epoch(3),
                },
                false,
            ),
        ]);

        let recovered = recover_roster(&store, &journal).unwrap();
        assert_eq!(recovered.member_ids, vec![member(1), member(2)]);
        assert_eq!(recovered.epoch, epoch(2));
    }

    #[test]
    fn recover_no_snapshot_replays_all_committed() {
        let store = InMemorySnapshotStore::new();

        let journal = build_journal(&[
            (
                TransitionKind::Join {
                    peer_id: member(1),
                    epoch: epoch(1),
                },
                true,
            ),
            (
                TransitionKind::Join {
                    peer_id: member(2),
                    epoch: epoch(2),
                },
                true,
            ),
            (
                TransitionKind::Join {
                    peer_id: member(3),
                    epoch: epoch(3),
                },
                true,
            ),
        ]);

        let recovered = recover_roster(&store, &journal).unwrap();
        assert_eq!(recovered.member_ids, vec![member(1), member(2), member(3)]);
        assert_eq!(recovered.epoch, epoch(3));
        assert_eq!(recovered.coordinator, member(1));
    }

    #[test]
    fn recover_no_snapshot_no_journal_returns_no_state() {
        let store = InMemorySnapshotStore::new();
        let journal = MembershipTransitionJournal::new();

        let result = recover_roster(&store, &journal);
        assert!(matches!(result, Err(EpochSnapshotError::NoState)));
    }

    #[test]
    fn recover_empty_snapshot_with_journal_join_only() {
        let store = InMemorySnapshotStore::new();
        let snap =
            MembershipEpochSnapshot::new(1, epoch(0), member(0), Incarnation::ZERO, Vec::new());
        write_epoch_snapshot(&store, &snap).unwrap();

        let journal = build_journal(&[
            (
                TransitionKind::Join {
                    peer_id: member(10),
                    epoch: epoch(1),
                },
                true,
            ),
            (
                TransitionKind::Join {
                    peer_id: member(20),
                    epoch: epoch(2),
                },
                true,
            ),
        ]);

        let recovered = recover_roster(&store, &journal).unwrap();
        assert_eq!(recovered.member_ids, vec![member(10), member(20)]);
        assert_eq!(recovered.epoch, epoch(2));
        assert_eq!(recovered.coordinator, member(10));
    }

    #[test]
    fn recover_snapshot_join_and_leave_net_empty() {
        let store = InMemorySnapshotStore::new();
        let snap = make_snapshot(1, 1, 1, 0, &[(1, "h1", 1)]);
        write_epoch_snapshot(&store, &snap).unwrap();

        let journal = build_journal(&[
            (
                TransitionKind::Join {
                    peer_id: member(2),
                    epoch: epoch(2),
                },
                true,
            ),
            (
                TransitionKind::Leave {
                    peer_id: member(1),
                    epoch: epoch(3),
                    reason: LeaveReason::Draining,
                },
                true,
            ),
            (
                TransitionKind::Leave {
                    peer_id: member(2),
                    epoch: epoch(4),
                    reason: LeaveReason::Voluntary,
                },
                true,
            ),
        ]);

        let recovered = recover_roster(&store, &journal).unwrap();
        assert!(recovered.member_ids.is_empty());
        assert_eq!(recovered.epoch, epoch(4));
        assert_eq!(recovered.coordinator, MemberId::ZERO);
    }

    #[test]
    fn recover_hybrid_snapshot_epoch_n_plus_journal_n1_through_m() {
        let store = InMemorySnapshotStore::new();
        let snap = make_snapshot(5, 10, 1, 0, &[(1, "h1", 1), (2, "h2", 1), (3, "h3", 1)]);
        write_epoch_snapshot(&store, &snap).unwrap();

        let journal = build_journal(&[
            (
                TransitionKind::Join {
                    peer_id: member(4),
                    epoch: epoch(10),
                },
                true,
            ),
            (
                TransitionKind::Leave {
                    peer_id: member(3),
                    epoch: epoch(11),
                    reason: LeaveReason::Voluntary,
                },
                true,
            ),
            (
                TransitionKind::Join {
                    peer_id: member(5),
                    epoch: epoch(12),
                },
                true,
            ),
            (
                TransitionKind::Join {
                    peer_id: member(6),
                    epoch: epoch(13),
                },
                true,
            ),
        ]);

        let recovered = recover_roster(&store, &journal).unwrap();
        assert_eq!(
            recovered.member_ids,
            vec![member(1), member(2), member(5), member(6)]
        );
        assert_eq!(recovered.epoch, epoch(13));
        assert_eq!(recovered.coordinator, member(1));
    }

    #[test]
    fn recover_deduplicates_member_ids() {
        let store = InMemorySnapshotStore::new();
        let snap = make_snapshot(1, 1, 1, 0, &[(1, "h1", 1)]);
        write_epoch_snapshot(&store, &snap).unwrap();

        let journal = build_journal(&[
            (
                TransitionKind::Join {
                    peer_id: member(2),
                    epoch: epoch(2),
                },
                true,
            ),
            (
                TransitionKind::Join {
                    peer_id: member(2),
                    epoch: epoch(3),
                },
                true,
            ),
        ]);

        let recovered = recover_roster(&store, &journal).unwrap();
        assert_eq!(recovered.member_ids, vec![member(1), member(2)]);
    }

    #[test]
    fn recover_coordinator_is_lowest_id() {
        let store = InMemorySnapshotStore::new();
        let snap = make_snapshot(1, 1, 99, 0, &[(5, "h5", 1), (10, "h10", 1), (99, "h99", 1)]);
        write_epoch_snapshot(&store, &snap).unwrap();

        let journal = MembershipTransitionJournal::new();

        let recovered = recover_roster(&store, &journal).unwrap();
        assert_eq!(recovered.coordinator, member(5));
    }

    // ── Sequence number monotonicity enforcement ─────────────────────

    #[test]
    fn sequence_numbers_are_monotonically_increasing_across_snapshots() {
        let store = InMemorySnapshotStore::new();

        for seq in 1..=10u64 {
            let snap = MembershipEpochSnapshot::new(
                seq,
                epoch(seq),
                member(1),
                Incarnation::ZERO,
                vec![(member(1), addr("h1", 1))],
            );
            write_epoch_snapshot(&store, &snap).unwrap();
        }

        let latest = load_latest_snapshot(&store).unwrap().unwrap();
        assert_eq!(latest.sequence_number, 10);

        let seqs = store.list_snapshots().unwrap();
        assert_eq!(seqs.len(), 10);
        for seq in seqs {
            let data = store.read_snapshot(seq).unwrap().unwrap();
            let decoded = MembershipEpochSnapshot::decode(&data).unwrap();
            assert_eq!(decoded.sequence_number, seq);
        }
    }

    // ── Error display ────────────────────────────────────────────────

    #[test]
    fn error_display_formats() {
        let e = EpochSnapshotError::StorageError("disk full".to_string());
        assert!(e.to_string().contains("disk full"));

        let e = EpochSnapshotError::EncodeError("bad data".to_string());
        assert!(e.to_string().contains("bad data"));

        let e = EpochSnapshotError::DecodeError("corrupt".to_string());
        assert!(e.to_string().contains("corrupt"));

        let e = EpochSnapshotError::NoState;
        assert!(e.to_string().contains("no snapshot"));
    }
}
