// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Durable epoch-state persistence with restart recovery and chain integrity.
//!
//! [`EpochStateStore`] persists committed roster views to a pluggable
//! [`DurableEpochStore`] backend, keyed by monotonic epoch number.
//! [`EpochChainLoader`] reloads the full chain on restart and validates
//! each transition through the existing [`EpochChainVerifier`].
//! [`EpochPersistenceHandle`] bridges [`EpochCommitBus`] commit events
//! to automatic persistence by implementing [`EpochCommitSubscriber`].
//!
//! # Bootstrap
//!
//! When no persisted chain exists (first start or blank store),
//! [`EpochStateStore::load_chain`] returns an empty vector so
//! genesis-bootstrap consumers can initialise from scratch.

use std::sync::Arc;

use crate::epoch_chain::{ChainError, EpochChainVerifier};
use crate::epoch_commit_subscriber::{
    CommittedRoster, EpochCommitNotification, EpochCommitSubscriber,
};

// ── EpochPersistenceError ──────────────────────────────────────────

/// Errors returned by epoch persistence operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EpochPersistenceError {
    /// The underlying storage backend returned an error.
    StorageError(String),
    /// A stored epoch record could not be deserialized.
    DeserializationError { epoch_number: u64, reason: String },
    /// The loaded epoch chain failed integrity verification.
    ChainVerificationError(ChainError),
    /// The loaded chain has a gap or non-monotonic sequence.
    ChainIntegrityError(String),
}

impl std::fmt::Display for EpochPersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StorageError(msg) => write!(f, "storage error: {msg}"),
            Self::DeserializationError {
                epoch_number,
                reason,
            } => {
                write!(
                    f,
                    "deserialization error for epoch {epoch_number}: {reason}"
                )
            }
            Self::ChainVerificationError(e) => {
                write!(f, "chain verification error: {e}")
            }
            Self::ChainIntegrityError(msg) => {
                write!(f, "chain integrity error: {msg}")
            }
        }
    }
}

impl std::error::Error for EpochPersistenceError {}

impl From<ChainError> for EpochPersistenceError {
    fn from(e: ChainError) -> Self {
        Self::ChainVerificationError(e)
    }
}

// ── DurableEpochStore ──────────────────────────────────────────────

/// Pluggable durable storage backend for epoch persistence.
///
/// Implementations provide the raw read/write/list primitives that
/// [`EpochStateStore`] builds upon. A production implementation might
/// use a local object store or intent-log; test implementations can
/// use an in-memory map.
///
/// All methods are synchronous (no async) to match the existing
/// single-threaded commit-path design.
pub trait DurableEpochStore: Send + Sync {
    /// Persist the serialized roster bytes for a given epoch number.
    ///
    /// Implementations must overwrite any existing record for the
    /// same epoch number.
    fn write_epoch(&self, epoch_number: u64, data: &[u8]) -> Result<(), EpochPersistenceError>;

    /// Read the serialized roster bytes for a given epoch number.
    ///
    /// Returns `Ok(None)` if no record exists for that epoch.
    fn read_epoch(&self, epoch_number: u64) -> Result<Option<Vec<u8>>, EpochPersistenceError>;

    /// List all persisted epoch numbers in arbitrary order.
    fn list_epochs(&self) -> Result<Vec<u64>, EpochPersistenceError>;

    /// Clear all persisted epoch records (for testing/reset).
    fn clear(&self) -> Result<(), EpochPersistenceError> {
        // Default: no-op; override for real backends.
        Ok(())
    }
}

// ── EpochStateStore ────────────────────────────────────────────────

/// Persists committed [`CommittedRoster`] views to durable storage,
/// keyed by monotonic epoch number.
///
/// # Storage layout
///
/// Each epoch's roster is serialized as a canonical JSON record
/// (via serde) keyed by its epoch number. The store does not impose
/// a file or object naming scheme — that is the responsibility of
/// the [`DurableEpochStore`] implementation.
pub struct EpochStateStore<S: DurableEpochStore> {
    store: Arc<S>,
}

impl<S: DurableEpochStore> EpochStateStore<S> {
    /// Create a new state store backed by the given storage backend.
    pub fn new(store: S) -> Self {
        Self {
            store: Arc::new(store),
        }
    }

    /// Create a new state store from an already-shared backend.
    pub fn from_arc(store: Arc<S>) -> Self {
        Self { store }
    }

    /// Persist a committed roster view.
    ///
    /// The roster's epoch number is used as the storage key.
    /// An existing record for the same epoch is overwritten.
    pub fn persist_epoch(&self, roster: &CommittedRoster) -> Result<(), EpochPersistenceError> {
        let data = serde_json::to_vec(roster).map_err(|e| {
            EpochPersistenceError::StorageError(format!("serialization failed: {e}"))
        })?;
        self.store.write_epoch(roster.epoch.0, &data)
    }

    /// Load all persisted rosters, returning them in monotonic
    /// epoch order.
    ///
    /// Returns an empty vector when no rosters have been persisted
    /// (first start or blank store).
    pub fn load_chain(&self) -> Result<Vec<CommittedRoster>, EpochPersistenceError> {
        let mut epoch_numbers = self.store.list_epochs()?;
        epoch_numbers.sort();

        let mut rosters = Vec::with_capacity(epoch_numbers.len());
        for epoch_num in &epoch_numbers {
            let data = self.store.read_epoch(*epoch_num)?.ok_or_else(|| {
                EpochPersistenceError::ChainIntegrityError(format!(
                    "epoch {epoch_num} listed but not readable"
                ))
            })?;

            let roster: CommittedRoster = serde_json::from_slice(&data).map_err(|e| {
                EpochPersistenceError::DeserializationError {
                    epoch_number: *epoch_num,
                    reason: format!("{e}"),
                }
            })?;

            rosters.push(roster);
        }
        Ok(rosters)
    }

    /// Delete all persisted epoch records.
    pub fn clear(&self) -> Result<(), EpochPersistenceError> {
        self.store.clear()
    }
}

// ── EpochChainLoader ───────────────────────────────────────────────

/// Loads the complete epoch chain on restart, validates each
/// transition via [`EpochChainVerifier`], and rejects truncated
/// or corrupt chains.
///
/// # Integrity checks
///
/// - The chain must be in monotonic epoch order (validated by
///   [`EpochStateStore::load_chain`]).
/// - Each consecutive pair of rosters must satisfy the
///   `EpochChainVerifier` transition rules (monotonic, no gaps).
/// - Roster-internal hash verification is performed on each loaded
///   roster via [`CommittedRoster::verify`].
pub struct EpochChainLoader {
    verifier: EpochChainVerifier,
}

impl EpochChainLoader {
    /// Create a new chain loader.
    pub fn new() -> Self {
        Self {
            verifier: EpochChainVerifier::new(),
        }
    }

    /// Load and verify the epoch chain from the given store.
    ///
    /// Returns the verified roster chain in monotonic order, or
    /// an error if any integrity check fails.
    ///
    /// An empty store produces an empty chain (bootstrap case).
    pub fn load_and_verify<S: DurableEpochStore>(
        &mut self,
        state_store: &EpochStateStore<S>,
    ) -> Result<Vec<CommittedRoster>, EpochPersistenceError> {
        let rosters = state_store.load_chain()?;

        if rosters.is_empty() {
            return Ok(Vec::new());
        }

        // Verify each roster's internal hash.
        for roster in &rosters {
            if !roster.verify() {
                return Err(EpochPersistenceError::ChainIntegrityError(format!(
                    "roster hash verification failed for epoch {}",
                    roster.epoch.0
                )));
            }
        }

        // Verify consecutive transitions via EpochChainVerifier.
        // Use proposer_id = 0 as a sentinel for restart-reload
        // verification (fork detection is not relevant on reload).
        self.verifier.reset();
        for window in rosters.windows(2) {
            let prev = &window[0];
            let next = &window[1];
            self.verifier.verify_proposal(
                0, // sentinel proposer for reload verification
                next.epoch.0,
                &next.member_ids,
                prev.epoch.0,
            )?;
        }

        Ok(rosters)
    }
}

impl Default for EpochChainLoader {
    fn default() -> Self {
        Self::new()
    }
}

// ── EpochPersistenceHandle ─────────────────────────────────────────

/// Bridges [`EpochCommitBus`] commit events to automatic durable
/// persistence.
///
/// Implements [`EpochCommitSubscriber`] so it can be registered with
/// an [`EpochCommitBus`]. On each commit notification, the handle
/// converts the notification into a [`CommittedRoster`] and persists
/// it via the wrapped [`EpochStateStore`].
///
/// Persistence failures are logged (via tracing or println in test
/// contexts) but do not block the commit path — the epoch has already
/// been committed in memory; persistence is best-effort durable
/// recording.
pub struct EpochPersistenceHandle<S: DurableEpochStore> {
    state_store: Arc<EpochStateStore<S>>,
}

impl<S: DurableEpochStore> EpochPersistenceHandle<S> {
    /// Create a new persistence handle that writes to the given store.
    pub fn new(state_store: Arc<EpochStateStore<S>>) -> Self {
        Self { state_store }
    }

    /// Return a reference to the underlying state store.
    pub fn state_store(&self) -> &EpochStateStore<S> {
        &self.state_store
    }
}

impl<S: DurableEpochStore> EpochCommitSubscriber for EpochPersistenceHandle<S> {
    fn on_epoch_committed(&self, notification: &EpochCommitNotification) {
        let roster = CommittedRoster {
            epoch: notification.epoch,
            member_ids: notification.member_ids.clone(),
            roster_hash: notification.roster_hash,
        };

        if let Err(e) = self.state_store.persist_epoch(&roster) {
            // Best-effort: log and continue. The epoch is already committed
            // in memory; persistence errors should not abort the commit path.
            eprintln!(
                "EpochPersistenceHandle: failed to persist epoch {}: {e}",
                roster.epoch.0
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// In-memory store for testing
// ═══════════════════════════════════════════════════════════════════

/// An in-memory [`DurableEpochStore`] for unit testing.
///
/// Not intended for production use.
#[derive(Clone, Debug, Default)]
pub struct InMemoryDurableStore {
    data: Arc<std::sync::Mutex<std::collections::BTreeMap<u64, Vec<u8>>>>,
}

impl InMemoryDurableStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl DurableEpochStore for InMemoryDurableStore {
    fn write_epoch(&self, epoch_number: u64, data: &[u8]) -> Result<(), EpochPersistenceError> {
        let mut map = self.data.lock().unwrap();
        map.insert(epoch_number, data.to_vec());
        Ok(())
    }

    fn read_epoch(&self, epoch_number: u64) -> Result<Option<Vec<u8>>, EpochPersistenceError> {
        let map = self.data.lock().unwrap();
        Ok(map.get(&epoch_number).cloned())
    }

    fn list_epochs(&self) -> Result<Vec<u64>, EpochPersistenceError> {
        let map = self.data.lock().unwrap();
        Ok(map.keys().copied().collect())
    }

    fn clear(&self) -> Result<(), EpochPersistenceError> {
        let mut map = self.data.lock().unwrap();
        map.clear();
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_commit_subscriber::{CommittedRoster, EpochCommitBus, EpochCommitSubscriber};
    use crate::EpochId;

    // ── helpers ───────────────────────────────────────────────────

    fn make_roster(epoch: u64, members: &[u64]) -> CommittedRoster {
        CommittedRoster::new(EpochId::new(epoch), members.to_vec())
    }

    fn make_notification(epoch: u64, members: &[u64]) -> EpochCommitNotification {
        let roster = CommittedRoster::new(EpochId::new(epoch), members.to_vec());
        EpochCommitNotification {
            epoch: roster.epoch,
            roster_hash: roster.roster_hash,
            member_ids: roster.member_ids.clone(),
            commit_index: epoch, // simplified
            catalog_delta_bytes: None,
        }
    }

    #[test]
    fn in_memory_store_write_and_read() {
        let store = InMemoryDurableStore::new();
        store.write_epoch(1, b"hello").unwrap();
        let val = store.read_epoch(1).unwrap();
        assert_eq!(val, Some(b"hello".to_vec()));
    }

    #[test]
    fn in_memory_store_read_missing_returns_none() {
        let store = InMemoryDurableStore::new();
        let val = store.read_epoch(99).unwrap();
        assert_eq!(val, None);
    }

    #[test]
    fn in_memory_store_list_epochs() {
        let store = InMemoryDurableStore::new();
        store.write_epoch(3, b"c").unwrap();
        store.write_epoch(1, b"a").unwrap();
        store.write_epoch(2, b"b").unwrap();
        let mut epochs = store.list_epochs().unwrap();
        epochs.sort();
        assert_eq!(epochs, vec![1, 2, 3]);
    }

    #[test]
    fn in_memory_store_clear() {
        let store = InMemoryDurableStore::new();
        store.write_epoch(1, b"x").unwrap();
        store.clear().unwrap();
        assert!(store.list_epochs().unwrap().is_empty());
        assert_eq!(store.read_epoch(1).unwrap(), None);
    }

    // ── EpochStateStore ───────────────────────────────────────────

    #[test]
    fn persist_single_epoch_round_trip() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);
        let roster = make_roster(1, &[10, 20]);

        state.persist_epoch(&roster).unwrap();
        let loaded = state.load_chain().unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], roster);
        assert!(loaded[0].verify());
    }

    #[test]
    fn persist_and_reload_multi_epoch_chain() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);

        let r1 = make_roster(1, &[1, 2]);
        let r2 = make_roster(2, &[1, 2, 3]);
        let r3 = make_roster(3, &[1, 2, 3, 4]);

        state.persist_epoch(&r1).unwrap();
        state.persist_epoch(&r2).unwrap();
        state.persist_epoch(&r3).unwrap();

        let loaded = state.load_chain().unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0], r1);
        assert_eq!(loaded[1], r2);
        assert_eq!(loaded[2], r3);
    }

    #[test]
    fn empty_store_returns_empty_chain() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);
        let loaded = state.load_chain().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn load_chain_returns_monotonic_order() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);

        // Persist out of order
        let r3 = make_roster(3, &[1, 2, 3, 4]);
        let r1 = make_roster(1, &[1, 2]);
        let r2 = make_roster(2, &[1, 2, 3]);

        state.persist_epoch(&r3).unwrap();
        state.persist_epoch(&r1).unwrap();
        state.persist_epoch(&r2).unwrap();

        let loaded = state.load_chain().unwrap();
        assert_eq!(loaded[0], r1);
        assert_eq!(loaded[1], r2);
        assert_eq!(loaded[2], r3);
    }

    #[test]
    fn overwrite_existing_epoch() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);

        let r1a = make_roster(1, &[1, 2]);
        let r1b = make_roster(1, &[1, 2, 3]);

        state.persist_epoch(&r1a).unwrap();
        state.persist_epoch(&r1b).unwrap();

        let loaded = state.load_chain().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], r1b);
    }

    // ── EpochChainLoader ──────────────────────────────────────────

    #[test]
    fn chain_loader_accepts_valid_chain() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);

        state.persist_epoch(&make_roster(1, &[1, 2])).unwrap();
        state.persist_epoch(&make_roster(2, &[1, 2, 3])).unwrap();
        state.persist_epoch(&make_roster(3, &[1, 2, 3, 4])).unwrap();

        let mut loader = EpochChainLoader::new();
        let result = loader.load_and_verify(&state).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn chain_loader_empty_store_returns_empty() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);

        let mut loader = EpochChainLoader::new();
        let result = loader.load_and_verify(&state).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn chain_loader_single_epoch_is_valid() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);

        state.persist_epoch(&make_roster(1, &[1, 2, 3])).unwrap();

        let mut loader = EpochChainLoader::new();
        let result = loader.load_and_verify(&state).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].epoch.0, 1);
    }

    #[test]
    fn chain_loader_rejects_non_monotonic_chain() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);

        // Epoch 3 follows epoch 1 (gap at epoch 2)
        state.persist_epoch(&make_roster(1, &[1, 2])).unwrap();
        state.persist_epoch(&make_roster(3, &[1, 2, 3])).unwrap();

        let mut loader = EpochChainLoader::new();
        let result = loader.load_and_verify(&state);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                EpochPersistenceError::ChainVerificationError(ChainError::InvalidTransition { .. })
            ),
            "expected InvalidTransition, got {err:?}"
        );
    }

    #[test]
    fn chain_loader_rejects_corrupt_roster_hash() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);

        // Create a roster with a deliberately wrong hash
        let mut corrupt = CommittedRoster::new(EpochId::new(1), vec![1, 2]);
        corrupt.roster_hash = [0u8; 32]; // tampered hash

        state.persist_epoch(&corrupt).unwrap();

        let mut loader = EpochChainLoader::new();
        let result = loader.load_and_verify(&state);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, EpochPersistenceError::ChainIntegrityError(_)),
            "expected ChainIntegrityError, got {err:?}"
        );
    }

    #[test]
    fn chain_loader_rejects_epoch_gap() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);

        state.persist_epoch(&make_roster(1, &[1, 2])).unwrap();
        state.persist_epoch(&make_roster(5, &[1, 2, 3])).unwrap(); // gap: 1->5, not 1->2

        let mut loader = EpochChainLoader::new();
        let result = loader.load_and_verify(&state);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                EpochPersistenceError::ChainVerificationError(ChainError::InvalidTransition { .. })
            ),
            "expected InvalidTransition, got {err:?}"
        );
    }

    // ── EpochPersistenceHandle ────────────────────────────────────

    #[test]
    fn persistence_handle_persists_on_commit() {
        let store = InMemoryDurableStore::new();
        let state = Arc::new(EpochStateStore::new(store));
        let handle = EpochPersistenceHandle::new(state.clone());

        let notification = make_notification(1, &[10, 20]);
        handle.on_epoch_committed(&notification);

        let loaded = state.load_chain().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].epoch.0, 1);
        assert_eq!(loaded[0].member_ids, vec![10, 20]);
    }

    #[test]
    fn persistence_handle_registers_with_bus() {
        let store = InMemoryDurableStore::new();
        let state = Arc::new(EpochStateStore::new(store));
        let _handle = Arc::new(EpochPersistenceHandle::new(state.clone()));

        let bus = EpochCommitBus::new();
        bus.register(Box::new(EpochPersistenceHandle::new(state.clone())));

        bus.dispatch_commit(EpochId::new(1), vec![1, 2, 3]);

        let loaded = state.load_chain().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].member_ids, vec![1, 2, 3]);
    }

    #[test]
    fn persistence_handle_multiple_commits() {
        let store = InMemoryDurableStore::new();
        let state = Arc::new(EpochStateStore::new(store));
        let handle = EpochPersistenceHandle::new(state.clone());

        handle.on_epoch_committed(&make_notification(1, &[1]));
        handle.on_epoch_committed(&make_notification(2, &[1, 2]));
        handle.on_epoch_committed(&make_notification(3, &[1, 2, 3]));

        let loaded = state.load_chain().unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].member_ids, vec![1]);
        assert_eq!(loaded[1].member_ids, vec![1, 2]);
        assert_eq!(loaded[2].member_ids, vec![1, 2, 3]);
    }

    #[test]
    fn persistence_handle_failure_is_non_blocking() {
        // Even if the store fails (simulated by a failing store),
        // on_epoch_committed must not panic.
        struct FailingStore;
        impl DurableEpochStore for FailingStore {
            fn write_epoch(&self, _epoch: u64, _data: &[u8]) -> Result<(), EpochPersistenceError> {
                Err(EpochPersistenceError::StorageError(
                    "simulated failure".into(),
                ))
            }
            fn read_epoch(&self, _epoch: u64) -> Result<Option<Vec<u8>>, EpochPersistenceError> {
                Ok(None)
            }
            fn list_epochs(&self) -> Result<Vec<u64>, EpochPersistenceError> {
                Ok(Vec::new())
            }
        }

        let state = Arc::new(EpochStateStore::new(FailingStore));
        let handle = EpochPersistenceHandle::new(state);
        let notification = make_notification(1, &[1, 2]);
        // Must not panic
        handle.on_epoch_committed(&notification);
    }

    #[test]
    fn state_store_clear() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);

        state.persist_epoch(&make_roster(1, &[1])).unwrap();
        state.persist_epoch(&make_roster(2, &[1, 2])).unwrap();
        assert_eq!(state.load_chain().unwrap().len(), 2);

        state.clear().unwrap();
        assert!(state.load_chain().unwrap().is_empty());
    }

    // ── End-to-end: commit bus -> persistence -> reload ───────────

    #[test]
    fn end_to_end_bus_persist_reload_verify() {
        let store = InMemoryDurableStore::new();
        let state = Arc::new(EpochStateStore::new(store));
        let _handle = Arc::new(EpochPersistenceHandle::new(state.clone()));

        let bus = EpochCommitBus::new();
        bus.register(Box::new(EpochPersistenceHandle::new(state.clone())));

        // Simulate three consecutive epoch commits
        bus.dispatch_commit(EpochId::new(1), vec![10, 20]);
        bus.dispatch_commit(EpochId::new(2), vec![10, 20, 30]);
        bus.dispatch_commit(EpochId::new(3), vec![10, 20, 30, 40]);

        // Reload and verify
        let mut loader = EpochChainLoader::new();
        let chain = loader.load_and_verify(&state).unwrap();

        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].epoch.0, 1);
        assert_eq!(chain[0].member_ids, vec![10, 20]);
        assert_eq!(chain[1].epoch.0, 2);
        assert_eq!(chain[1].member_ids, vec![10, 20, 30]);
        assert_eq!(chain[2].epoch.0, 3);
        assert_eq!(chain[2].member_ids, vec![10, 20, 30, 40]);
    }

    // ── Concurrent persist isolation ──────────────────────────────

    #[test]
    fn concurrent_persist_isolation() {
        use std::thread;

        let store = InMemoryDurableStore::new();
        let state = Arc::new(EpochStateStore::new(store));

        let s1 = state.clone();
        let t1 = thread::spawn(move || {
            for i in 0..50 {
                let roster = make_roster(i * 2 + 1, &[1]);
                s1.persist_epoch(&roster).unwrap();
            }
        });

        let s2 = state.clone();
        let t2 = thread::spawn(move || {
            for i in 0..50 {
                let roster = make_roster(i * 2 + 2, &[1, 2]);
                s2.persist_epoch(&roster).unwrap();
            }
        });

        t1.join().unwrap();
        t2.join().unwrap();

        let loaded = state.load_chain().unwrap();
        assert_eq!(loaded.len(), 100);

        // Verify all epochs are present and sorted
        for (i, roster) in loaded.iter().enumerate() {
            assert_eq!(roster.epoch.0, (i + 1) as u64);
            assert!(roster.verify());
        }
    }

    // ── Restart with partial chain recovery ───────────────────────

    #[test]
    fn restart_with_partial_chain() {
        let store = InMemoryDurableStore::new();
        let state = EpochStateStore::new(store);

        // Persist a full chain: epochs 1, 2, 3
        state.persist_epoch(&make_roster(1, &[1])).unwrap();
        state.persist_epoch(&make_roster(2, &[1, 2])).unwrap();
        state.persist_epoch(&make_roster(3, &[1, 2, 3])).unwrap();

        // Simulate restart: reload and verify
        let mut loader = EpochChainLoader::new();
        let chain = loader.load_and_verify(&state).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.last().unwrap().epoch.0, 3);

        // Add more epochs after "restart"
        state.persist_epoch(&make_roster(4, &[1, 2, 3, 4])).unwrap();
        state
            .persist_epoch(&make_roster(5, &[1, 2, 3, 4, 5]))
            .unwrap();

        let chain2 = loader.load_and_verify(&state).unwrap();
        assert_eq!(chain2.len(), 5);
        assert_eq!(chain2.last().unwrap().epoch.0, 5);
    }
}
