//! Persistent cleanup-queue ledger bridging reclaim-queue output
//! (FreedExtents) to block-allocator free-space reconciliation.
//!
//! The ledger is a FIFO queue of [`CleanupEntry`] values, each driving
//! through a three-stage pipeline:
//!
//! 1. **Enqueue** — a [`FreedExtent`] arrives from the reclaim queue.
//! 2. **Verify dead** — BLAKE3 comparison confirms the extent data has
//!    been overwritten (hash mismatch), proving it is truly dead.
//! 3. **Reconcile** — the entry is marked reconciled; the caller wires
//!    the allocator free call.
//!
//! Every state transition produces an [`IntentLogRecord::CleanupQueue`]
//! so that crash replay can resume the pipeline without double-freeing
//! or leaking extents.

use std::collections::VecDeque;
use std::fmt;

use tidefs_intent_log::IntentLogRecord;
use tidefs_reclaim_queue_core::FreedExtent;

// ── CleanupStatus ───────────────────────────────────────────────────

/// Status of a cleanup-queue entry in the verification and
/// reconciliation pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupStatus {
    /// Entry is queued for dead-verification.
    Pending = 0,
    /// BLAKE3 verification confirmed the extent is dead (data
    /// overwritten).
    Verified = 1,
    /// Space has been returned to the block allocator.
    Reconciled = 2,
    /// Verification or reconciliation failed (max retries exceeded
    /// or extent still has live data at time of verification).
    Failed = 3,
}

impl CleanupStatus {
    /// Deserialize from the on-wire byte representation.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Pending),
            1 => Some(Self::Verified),
            2 => Some(Self::Reconciled),
            3 => Some(Self::Failed),
            _ => None,
        }
    }
}

impl fmt::Display for CleanupStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Verified => write!(f, "Verified"),
            Self::Reconciled => write!(f, "Reconciled"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

// ── CleanupQueueConfig ──────────────────────────────────────────────

/// Configuration for the cleanup-queue ledger.
#[derive(Clone, Debug, PartialEq)]
pub struct CleanupQueueConfig {
    /// Maximum entries to process in one batch.
    pub batch_size: usize,
    /// Whether to perform BLAKE3 dead-verification.
    pub verify_dead: bool,
    /// Maximum reconciliation retries per entry before marking
    /// [`CleanupStatus::Failed`].
    pub max_retries: u8,
}

impl Default for CleanupQueueConfig {
    fn default() -> Self {
        Self {
            batch_size: 128,
            verify_dead: true,
            max_retries: 3,
        }
    }
}

// ── CleanupQueueError ───────────────────────────────────────────────

/// Errors produced by cleanup-queue ledger operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CleanupQueueError {
    /// No entry with the given ID exists in the ledger.
    EntryNotFound {
        /// The entry ID that was looked up.
        entry_id: u64,
    },
    /// The entry was already reconciled.
    AlreadyReconciled {
        /// The entry ID.
        entry_id: u64,
    },
    /// The entry was already marked failed.
    AlreadyFailed {
        /// The entry ID.
        entry_id: u64,
    },
    /// BLAKE3 dead-verification failed (extent still has live data).
    VerificationFailed {
        /// The entry ID.
        entry_id: u64,
    },
    /// Max retry count exceeded, entry moved to Failed.
    MaxRetriesExceeded {
        /// The entry ID.
        entry_id: u64,
        /// Number of retries attempted.
        retries: u8,
    },
    /// Invalid status transition requested.
    InvalidStatusTransition {
        /// The entry ID.
        entry_id: u64,
        /// Current status.
        from: CleanupStatus,
        /// Requested status.
        to: CleanupStatus,
    },
}

impl fmt::Display for CleanupQueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntryNotFound { entry_id } => {
                write!(f, "cleanup-queue entry {entry_id} not found")
            }
            Self::AlreadyReconciled { entry_id } => {
                write!(f, "cleanup-queue entry {entry_id} already reconciled")
            }
            Self::AlreadyFailed { entry_id } => {
                write!(f, "cleanup-queue entry {entry_id} already failed")
            }
            Self::VerificationFailed { entry_id } => {
                write!(
                    f,
                    "dead-verification failed for entry {entry_id}: \
                     extent still has live data"
                )
            }
            Self::MaxRetriesExceeded { entry_id, retries } => {
                write!(f, "max retries ({retries}) exceeded for entry {entry_id}")
            }
            Self::InvalidStatusTransition { entry_id, from, to } => {
                write!(
                    f,
                    "invalid status transition for entry {entry_id}: \
                     {from} -> {to}"
                )
            }
        }
    }
}

// ── CleanupEntry ────────────────────────────────────────────────────

/// An entry in the cleanup-queue ledger, wrapping a [`FreedExtent`]
/// with state-machine tracking through the verification and
/// reconciliation pipeline.
#[derive(Clone, Debug, PartialEq)]
pub struct CleanupEntry {
    /// Unique entry ID within this ledger instance.
    pub entry_id: u64,
    /// The freed extent from the reclaim queue.
    pub extent: FreedExtent,
    /// Current cleanup status.
    pub status: CleanupStatus,
    /// Number of verification or reconciliation attempts.
    pub retry_count: u8,
}

impl CleanupEntry {
    /// Create a new pending cleanup entry from a freed extent.
    #[must_use]
    pub fn from_freed_extent(entry_id: u64, extent: FreedExtent) -> Self {
        Self {
            entry_id,
            extent,
            status: CleanupStatus::Pending,
            retry_count: 0,
        }
    }

    /// Convert this entry to an [`IntentLogRecord::CleanupQueue`] for
    /// crash-safe persistence.
    #[must_use]
    pub fn to_intent_log_record(&self) -> IntentLogRecord {
        IntentLogRecord::CleanupQueue {
            entry_id: self.entry_id,
            device_id: self.extent.device_id,
            physical_offset: self.extent.physical_offset,
            length: self.extent.length,
            blake3_hash: self.extent.blake3_hash,
            freed_at_txg: self.extent.freed_at_txg,
            cleanup_status: self.status as u8,
            retry_count: self.retry_count,
        }
    }

    /// Restore a cleanup entry from an [`IntentLogRecord::CleanupQueue`]
    /// variant.  Returns `None` if the record is not a `CleanupQueue`
    /// variant or has an invalid status byte.
    #[must_use]
    pub fn from_intent_log_record(record: &IntentLogRecord) -> Option<Self> {
        match record {
            IntentLogRecord::CleanupQueue {
                entry_id,
                device_id,
                physical_offset,
                length,
                blake3_hash,
                freed_at_txg,
                cleanup_status,
                retry_count,
            } => {
                let status = CleanupStatus::from_u8(*cleanup_status)?;
                Some(Self {
                    entry_id: *entry_id,
                    extent: FreedExtent::new(
                        *device_id,
                        *physical_offset,
                        *length,
                        *blake3_hash,
                        *freed_at_txg,
                    ),
                    status,
                    retry_count: *retry_count,
                })
            }
            _ => None,
        }
    }
}

// ── CleanupFreeTarget ──────────────────────────────────────────────

/// Trait for wiring the actual block-allocator free call during
/// [`CleanupQueueLedger::reconcile_with`].
///
/// A mock implementation for integration testing should track freed
/// byte counts and return `Ok(())` when the extent is valid.
pub trait CleanupFreeTarget {
    /// Free the blocks backing `extent` back to the allocator.
    ///
    /// Implementations must be idempotent: freeing an already-freed
    /// extent must succeed silently.
    fn free_extent(&mut self, extent: &FreedExtent) -> Result<(), CleanupQueueError>;
}

// ── CleanupQueueLedger ──────────────────────────────────────────────

/// Persistent cleanup-queue ledger bridging reclaim-queue output to
/// block-allocator free-space reconciliation.
///
/// The ledger holds a FIFO queue of [`CleanupEntry`] values and drives
/// each through enqueue → verify-dead → reconcile.  The caller is
/// responsible for wiring the actual [`FreedExtent`] dequeue from
/// `ReclaimQueueLedger` and the `BlockAllocator::free` call during
/// reconciliation — the ledger tracks only the state transitions and
/// produces intent-log records for crash safety.
///
/// # Crash recovery
///
/// After a crash, call [`replay_records`](Self::replay_records) with
/// the intent-log records produced by
/// [`all_records`](Self::all_records) (or
/// [`dirty_records`](Self::dirty_records)).  Replay is idempotent:
/// replaying the same records twice produces the same final state.
/// Entries in [`CleanupStatus::Reconciled`] must not be re-freed by
/// the allocator caller (the intent-log record serves as the
/// already-reconciled marker).
pub struct CleanupQueueLedger {
    config: CleanupQueueConfig,
    entries: VecDeque<CleanupEntry>,
    next_entry_id: u64,
    dirty: bool,
}

impl CleanupQueueLedger {
    /// Create a new empty cleanup-queue ledger.
    #[must_use]
    pub fn new(config: CleanupQueueConfig) -> Self {
        Self {
            config,
            entries: VecDeque::new(),
            next_entry_id: 1,
            dirty: false,
        }
    }

    /// Create a ledger with a specific starting entry ID (used during
    /// crash recovery replay to resume from the last known ID).
    #[must_use]
    pub fn with_starting_id(config: CleanupQueueConfig, next_entry_id: u64) -> Self {
        Self {
            config,
            entries: VecDeque::new(),
            next_entry_id,
            dirty: false,
        }
    }

    // ── Enqueue ──────────────────────────────────────────────────

    /// Enqueue a freed extent from the reclaim queue.
    ///
    /// Returns the assigned entry ID.
    pub fn enqueue(&mut self, extent: FreedExtent) -> u64 {
        let entry_id = self.next_entry_id;
        self.next_entry_id += 1;
        let entry = CleanupEntry::from_freed_extent(entry_id, extent);
        self.entries.push_back(entry);
        self.dirty = true;
        entry_id
    }

    /// Enqueue a batch of freed extents.  Returns the assigned entry
    /// IDs in FIFO order.
    pub fn enqueue_batch(&mut self, extents: Vec<FreedExtent>) -> Vec<u64> {
        extents.into_iter().map(|e| self.enqueue(e)).collect()
    }

    // ── Verify dead ──────────────────────────────────────────────

    /// Verify that an extent is truly dead by comparing the stored
    /// BLAKE3 hash against the current object-store hash.
    ///
    /// If the hashes differ, the extent data has been overwritten and
    /// the entry transitions to [`CleanupStatus::Verified`].  If the
    /// hashes match, the verification fails: the retry counter is
    /// incremented and the entry stays [`CleanupStatus::Pending`] until
    /// `max_retries` is exceeded, at which point it moves to
    /// [`CleanupStatus::Failed`].
    ///
    /// Already-verified entries are silently accepted (idempotent).
    /// Reconciled or failed entries return an error.
    pub fn verify_dead(
        &mut self,
        entry_id: u64,
        current_object_hash: &[u8; 32],
    ) -> Result<(), CleanupQueueError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.entry_id == entry_id)
            .ok_or(CleanupQueueError::EntryNotFound { entry_id })?;

        match entry.status {
            CleanupStatus::Pending => {}
            CleanupStatus::Verified => {
                // Idempotent: already verified.
                return Ok(());
            }
            CleanupStatus::Reconciled => {
                return Err(CleanupQueueError::AlreadyReconciled { entry_id });
            }
            CleanupStatus::Failed => {
                return Err(CleanupQueueError::AlreadyFailed { entry_id });
            }
        }

        if entry.extent.blake3_hash != *current_object_hash {
            // Data has been overwritten — extent is truly dead.
            entry.status = CleanupStatus::Verified;
            entry.retry_count = 0;
            self.dirty = true;
            Ok(())
        } else {
            // Data still matches — extent might still be live.
            entry.retry_count += 1;
            if entry.retry_count >= self.config.max_retries {
                entry.status = CleanupStatus::Failed;
                self.dirty = true;
                return Err(CleanupQueueError::MaxRetriesExceeded {
                    entry_id,
                    retries: entry.retry_count,
                });
            }
            Err(CleanupQueueError::VerificationFailed { entry_id })
        }
    }

    // ── Reconcile ────────────────────────────────────────────────

    /// Mark a verified entry as reconciled.
    ///
    /// The caller is responsible for calling `BlockAllocator::free`
    /// before or after this transition.  The ledger tracks only the
    /// state; crash-recovery replay uses the intent-log record to
    /// prevent double-reconciliation.
    ///
    /// Returns a reference to the reconciled entry.
    /// Idempotent: already-reconciled entries succeed without error.
    pub fn reconcile(&mut self, entry_id: u64) -> Result<&CleanupEntry, CleanupQueueError> {
        let entry_idx = self
            .entries
            .iter()
            .position(|e| e.entry_id == entry_id)
            .ok_or(CleanupQueueError::EntryNotFound { entry_id })?;

        match self.entries[entry_idx].status {
            CleanupStatus::Verified => {
                self.entries[entry_idx].status = CleanupStatus::Reconciled;
                self.dirty = true;
            }
            CleanupStatus::Reconciled => {
                // Idempotent: already reconciled.
            }
            CleanupStatus::Pending => {
                return Err(CleanupQueueError::InvalidStatusTransition {
                    entry_id,
                    from: CleanupStatus::Pending,
                    to: CleanupStatus::Reconciled,
                });
            }
            CleanupStatus::Failed => {
                return Err(CleanupQueueError::AlreadyFailed { entry_id });
            }
        }

        Ok(&self.entries[entry_idx])
    }

    /// Mark a verified entry as reconciled AND call the allocator free
    /// path through `target`.
    ///
    /// This is the production codepath: the state transition is recorded
    /// in the ledger (for crash safety), and `target.free_extent()` is
    /// called to return the freed blocks to the block allocator.
    ///
    /// Idempotent: already-reconciled entries succeed without error,
    /// and `free_extent` is called again (allocator implementations
    /// must be idempotent).
    pub fn reconcile_with<T: CleanupFreeTarget>(
        &mut self,
        entry_id: u64,
        target: &mut T,
    ) -> Result<(), CleanupQueueError> {
        let entry_idx = self
            .entries
            .iter()
            .position(|e| e.entry_id == entry_id)
            .ok_or(CleanupQueueError::EntryNotFound { entry_id })?;

        match self.entries[entry_idx].status {
            CleanupStatus::Verified => {
                self.entries[entry_idx].status = CleanupStatus::Reconciled;
                self.dirty = true;
            }
            CleanupStatus::Reconciled => {
                // Already reconciled; call free again for idempotency.
            }
            CleanupStatus::Pending => {
                return Err(CleanupQueueError::InvalidStatusTransition {
                    entry_id,
                    from: CleanupStatus::Pending,
                    to: CleanupStatus::Reconciled,
                });
            }
            CleanupStatus::Failed => {
                return Err(CleanupQueueError::AlreadyFailed { entry_id });
            }
        }

        target.free_extent(&self.entries[entry_idx].extent)
    }

    // ── Query ────────────────────────────────────────────────────

    /// Return the number of entries in the ledger.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the ledger is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return `true` if the ledger has uncommitted changes.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Clear the dirty flag (call after persisting intent-log records).
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Return the next entry ID that will be assigned.
    #[must_use]
    pub fn next_entry_id(&self) -> u64 {
        self.next_entry_id
    }

    /// Look up an entry by ID.
    #[must_use]
    pub fn get(&self, entry_id: u64) -> Option<&CleanupEntry> {
        self.entries.iter().find(|e| e.entry_id == entry_id)
    }

    /// Count entries with a given status.
    #[must_use]
    pub fn count_by_status(&self, status: CleanupStatus) -> usize {
        self.entries.iter().filter(|e| e.status == status).count()
    }

    /// Return all pending entries up to `max_count` (FIFO order).
    #[must_use]
    pub fn pending_batch(&self, max_count: usize) -> Vec<&CleanupEntry> {
        self.entries
            .iter()
            .filter(|e| e.status == CleanupStatus::Pending)
            .take(max_count)
            .collect()
    }

    /// Return all verified entries up to `max_count` (FIFO order).
    #[must_use]
    pub fn verified_batch(&self, max_count: usize) -> Vec<&CleanupEntry> {
        self.entries
            .iter()
            .filter(|e| e.status == CleanupStatus::Verified)
            .take(max_count)
            .collect()
    }

    /// Iterate over all entries in FIFO order.
    pub fn iter(&self) -> impl Iterator<Item = &CleanupEntry> {
        self.entries.iter()
    }

    /// Drain entries in a terminal state
    /// ([`CleanupStatus::Reconciled`] or [`CleanupStatus::Failed`]).
    /// Returns the number of entries removed.
    pub fn purge_terminal(&mut self) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|e| !matches!(e.status, CleanupStatus::Reconciled | CleanupStatus::Failed));
        let removed = before - self.entries.len();
        if removed > 0 {
            self.dirty = true;
        }
        removed
    }

    // ── Crash recovery ───────────────────────────────────────────

    /// Replay a batch of intent-log records to restore ledger state
    /// after a crash.
    ///
    /// Entries that already exist are updated (higher status wins);
    /// new entries are appended in FIFO order.  This is idempotent:
    /// replaying the same records twice produces the same final state.
    ///
    /// Returns the number of entries replayed (new or updated).
    pub fn replay_records(
        &mut self,
        records: &[IntentLogRecord],
    ) -> Result<usize, CleanupQueueError> {
        let mut replayed = 0;
        for record in records {
            if let Some(recovered) = CleanupEntry::from_intent_log_record(record) {
                let eid = recovered.entry_id;
                if let Some(existing) = self.entries.iter_mut().find(|e| e.entry_id == eid) {
                    // Update if the recovered status is further along.
                    if (recovered.status as u8) > (existing.status as u8) {
                        existing.status = recovered.status;
                        existing.retry_count = recovered.retry_count;
                        self.dirty = true;
                        replayed += 1;
                    }
                } else {
                    // New entry from replay — append in FIFO order.
                    self.next_entry_id = self.next_entry_id.max(recovered.entry_id + 1);
                    self.entries.push_back(recovered);
                    self.dirty = true;
                    replayed += 1;
                }
            }
        }
        Ok(replayed)
    }

    /// Produce intent-log records for all entries not yet in a
    /// terminal state (Pending and Verified).  These are the entries
    /// that must survive a crash so that the pipeline can resume.
    #[must_use]
    pub fn dirty_records(&self) -> Vec<IntentLogRecord> {
        self.entries
            .iter()
            .filter(|e| e.status == CleanupStatus::Pending || e.status == CleanupStatus::Verified)
            .map(|e| e.to_intent_log_record())
            .collect()
    }

    /// Produce intent-log records for every entry in the ledger.
    #[must_use]
    pub fn all_records(&self) -> Vec<IntentLogRecord> {
        self.entries
            .iter()
            .map(|e| e.to_intent_log_record())
            .collect()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test `FreedExtent` with deterministic fields derived
    /// from a seed byte, making test assertions easy to read.
    fn fe(seed: u8) -> FreedExtent {
        FreedExtent::new(
            u64::from(seed) * 100,  // device_id
            u64::from(seed) * 4096, // physical_offset
            8192,                   // length
            [seed; 32],             // blake3_hash
            u64::from(seed),        // freed_at_txg
        )
    }

    // ── Enqueue ──────────────────────────────────────────────────

    #[test]
    fn enqueue_single_assigns_entry_id() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let id = ledger.enqueue(fe(1));
        assert_eq!(id, 1);
        assert_eq!(ledger.len(), 1);
        assert!(ledger.is_dirty());
    }

    #[test]
    fn enqueue_multiple_increments_ids() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let ids = ledger.enqueue_batch(vec![fe(1), fe(2), fe(3)]);
        assert_eq!(ids, vec![1, 2, 3]);
        assert_eq!(ledger.len(), 3);
    }

    #[test]
    fn enqueue_preserves_fifo_order() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        ledger.enqueue(fe(1));
        ledger.enqueue(fe(2));
        let ids: Vec<u64> = ledger.iter().map(|e| e.entry_id).collect();
        assert_eq!(ids, vec![1, 2]);
    }

    // ── Verify dead ──────────────────────────────────────────────

    #[test]
    fn verify_dead_hash_mismatch_transitions_to_verified() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let id = ledger.enqueue(fe(1));
        // fe(1) produces blake3_hash = [1; 32]; a different hash
        // means the data has been overwritten → truly dead.
        ledger.verify_dead(id, &[0xFF; 32]).unwrap();
        let entry = ledger.get(id).unwrap();
        assert_eq!(entry.status, CleanupStatus::Verified);
        assert_eq!(entry.retry_count, 0);
    }

    #[test]
    fn verify_dead_hash_match_stays_pending_and_increments_retry() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let id = ledger.enqueue(fe(1));
        // fe(1) produces blake3_hash = [1; 32]; same hash means
        // data still matches → extent may still be live.
        let result = ledger.verify_dead(id, &[1; 32]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            CleanupQueueError::VerificationFailed { entry_id: id }
        );
        let entry = ledger.get(id).unwrap();
        assert_eq!(entry.status, CleanupStatus::Pending);
        assert_eq!(entry.retry_count, 1);
    }

    #[test]
    fn verify_dead_max_retries_transitions_to_failed() {
        let config = CleanupQueueConfig {
            max_retries: 2,
            ..CleanupQueueConfig::default()
        };
        let mut ledger = CleanupQueueLedger::new(config);
        let id = ledger.enqueue(fe(1));
        let same_hash = &[1; 32];

        // Retry 1: still pending.
        let r1 = ledger.verify_dead(id, same_hash);
        assert_eq!(
            r1,
            Err(CleanupQueueError::VerificationFailed { entry_id: id })
        );
        assert_eq!(ledger.get(id).unwrap().status, CleanupStatus::Pending);

        // Retry 2: exceeds max_retries=2 → Failed.
        let r2 = ledger.verify_dead(id, same_hash);
        assert_eq!(
            r2,
            Err(CleanupQueueError::MaxRetriesExceeded {
                entry_id: id,
                retries: 2
            })
        );
        assert_eq!(ledger.get(id).unwrap().status, CleanupStatus::Failed);
    }

    #[test]
    fn verify_dead_on_nonexistent_entry() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let result = ledger.verify_dead(999, &[0; 32]);
        assert_eq!(
            result,
            Err(CleanupQueueError::EntryNotFound { entry_id: 999 })
        );
    }

    #[test]
    fn verify_dead_already_reconciled_is_error() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let id = ledger.enqueue(fe(1));
        ledger.verify_dead(id, &[0xFF; 32]).unwrap();
        ledger.reconcile(id).unwrap();
        let result = ledger.verify_dead(id, &[0xFF; 32]);
        assert_eq!(
            result,
            Err(CleanupQueueError::AlreadyReconciled { entry_id: id })
        );
    }

    #[test]
    fn verify_dead_already_failed_is_error() {
        let config = CleanupQueueConfig {
            max_retries: 0,
            ..CleanupQueueConfig::default()
        };
        let mut ledger = CleanupQueueLedger::new(config);
        let id = ledger.enqueue(fe(1));
        // First attempt with max_retries=0 immediately fails.
        let _ = ledger.verify_dead(id, &[1; 32]);
        assert_eq!(ledger.get(id).unwrap().status, CleanupStatus::Failed);
        let result = ledger.verify_dead(id, &[1; 32]);
        assert_eq!(
            result,
            Err(CleanupQueueError::AlreadyFailed { entry_id: id })
        );
    }

    #[test]
    fn verify_dead_already_verified_is_idempotent() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let id = ledger.enqueue(fe(1));
        ledger.verify_dead(id, &[0xFF; 32]).unwrap();
        // Second call is idempotent.
        ledger.verify_dead(id, &[0xFF; 32]).unwrap();
        assert_eq!(ledger.get(id).unwrap().status, CleanupStatus::Verified);
    }

    // ── Reconcile ────────────────────────────────────────────────

    #[test]
    fn reconcile_verified_transitions_to_reconciled() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let id = ledger.enqueue(fe(1));
        ledger.verify_dead(id, &[0xFF; 32]).unwrap();
        let entry = ledger.reconcile(id).unwrap();
        assert_eq!(entry.status, CleanupStatus::Reconciled);
    }

    #[test]
    fn reconcile_double_is_idempotent() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let id = ledger.enqueue(fe(1));
        ledger.verify_dead(id, &[0xFF; 32]).unwrap();
        ledger.reconcile(id).unwrap();
        // Second reconcile is a no-op.
        ledger.reconcile(id).unwrap();
        assert_eq!(ledger.get(id).unwrap().status, CleanupStatus::Reconciled);
    }

    #[test]
    fn reconcile_pending_is_error() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let id = ledger.enqueue(fe(1));
        let result = ledger.reconcile(id);
        assert_eq!(
            result,
            Err(CleanupQueueError::InvalidStatusTransition {
                entry_id: id,
                from: CleanupStatus::Pending,
                to: CleanupStatus::Reconciled,
            })
        );
    }

    #[test]
    fn reconcile_failed_is_error() {
        let config = CleanupQueueConfig {
            max_retries: 0,
            ..CleanupQueueConfig::default()
        };
        let mut ledger = CleanupQueueLedger::new(config);
        let id = ledger.enqueue(fe(1));
        let _ = ledger.verify_dead(id, &[1; 32]);
        let result = ledger.reconcile(id);
        assert_eq!(
            result,
            Err(CleanupQueueError::AlreadyFailed { entry_id: id })
        );
    }

    #[test]
    fn reconcile_nonexistent_entry() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let result = ledger.reconcile(999);
        assert_eq!(
            result,
            Err(CleanupQueueError::EntryNotFound { entry_id: 999 })
        );
    }

    // ── Batch operations ─────────────────────────────────────────

    #[test]
    fn pending_batch_respects_max_count() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        ledger.enqueue_batch(vec![fe(1), fe(2), fe(3)]);
        let batch = ledger.pending_batch(2);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].entry_id, 1);
        assert_eq!(batch[1].entry_id, 2);
    }

    #[test]
    fn verified_batch_only_returns_verified() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let id1 = ledger.enqueue(fe(1));
        let _id2 = ledger.enqueue(fe(2));
        let id3 = ledger.enqueue(fe(3));
        ledger.verify_dead(id1, &[0xFF; 32]).unwrap();
        ledger.verify_dead(id3, &[0xAA; 32]).unwrap();
        let batch = ledger.verified_batch(10);
        assert_eq!(batch.len(), 2);
        let ids: Vec<u64> = batch.iter().map(|e| e.entry_id).collect();
        assert_eq!(ids, vec![1, 3]);
    }

    // ── Purge terminal ───────────────────────────────────────────

    #[test]
    fn purge_terminal_removes_reconciled_and_failed() {
        let config = CleanupQueueConfig {
            max_retries: 0,
            ..CleanupQueueConfig::default()
        };
        let mut ledger = CleanupQueueLedger::new(config);
        ledger.enqueue(fe(1)); // will be verified then reconciled
        ledger.enqueue(fe(2)); // will fail
        ledger.enqueue(fe(3)); // stays pending

        ledger.verify_dead(1, &[0xFF; 32]).unwrap();
        ledger.reconcile(1).unwrap();
        let _ = ledger.verify_dead(2, &[2; 32]);

        assert_eq!(ledger.len(), 3);
        let purged = ledger.purge_terminal();
        assert_eq!(purged, 2);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.get(3).unwrap().status, CleanupStatus::Pending);
    }

    // ── Intent-log roundtrip ─────────────────────────────────────

    #[test]
    fn cleanup_entry_to_from_intent_log_roundtrip() {
        let entry = CleanupEntry::from_freed_extent(42, fe(5));
        let record = entry.to_intent_log_record();
        let recovered = CleanupEntry::from_intent_log_record(&record).unwrap();
        assert_eq!(recovered.entry_id, entry.entry_id);
        assert_eq!(recovered.extent.device_id, entry.extent.device_id);
        assert_eq!(
            recovered.extent.physical_offset,
            entry.extent.physical_offset
        );
        assert_eq!(recovered.extent.length, entry.extent.length);
        assert_eq!(recovered.extent.blake3_hash, entry.extent.blake3_hash);
        assert_eq!(recovered.extent.freed_at_txg, entry.extent.freed_at_txg);
        assert_eq!(recovered.status, entry.status);
        assert_eq!(recovered.retry_count, entry.retry_count);
    }

    #[test]
    fn cleanup_entry_from_non_cleanup_record_returns_none() {
        let record = IntentLogRecord::Create {
            parent: 1,
            name: b"test".to_vec(),
            mode: 0o644,
            ino: 42,
        };
        assert!(CleanupEntry::from_intent_log_record(&record).is_none());
    }

    #[test]
    fn intent_log_encode_decode_roundtrip() {
        let entry = CleanupEntry::from_freed_extent(7, fe(3));
        let record = entry.to_intent_log_record();
        let encoded = record.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        let recovered = CleanupEntry::from_intent_log_record(&decoded).unwrap();
        assert_eq!(recovered.entry_id, 7);
        assert_eq!(recovered.status, CleanupStatus::Pending);
    }

    // ── Crash recovery replay ────────────────────────────────────

    #[test]
    fn replay_records_restores_entries() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());

        let e1 = CleanupEntry::from_freed_extent(1, fe(1));
        let mut e2 = CleanupEntry::from_freed_extent(2, fe(2));
        e2.status = CleanupStatus::Verified;
        let records = vec![e1.to_intent_log_record(), e2.to_intent_log_record()];

        let replayed = ledger.replay_records(&records).unwrap();
        assert_eq!(replayed, 2);
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.get(1).unwrap().status, CleanupStatus::Pending);
        assert_eq!(ledger.get(2).unwrap().status, CleanupStatus::Verified);
    }

    #[test]
    fn replay_idempotent_does_not_double_insert() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let e1 = CleanupEntry::from_freed_extent(1, fe(1));
        let records = vec![e1.to_intent_log_record()];

        ledger.replay_records(&records).unwrap();
        assert_eq!(ledger.len(), 1);

        // Replay same records — still 1 entry.
        ledger.replay_records(&records).unwrap();
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn replay_updates_status_to_higher_value() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let e1 = CleanupEntry::from_freed_extent(1, fe(1));
        ledger.replay_records(&[e1.to_intent_log_record()]).unwrap();
        assert_eq!(ledger.get(1).unwrap().status, CleanupStatus::Pending);

        // Replay with Verified status.
        let mut e1_verified = e1.clone();
        e1_verified.status = CleanupStatus::Verified;
        ledger
            .replay_records(&[e1_verified.to_intent_log_record()])
            .unwrap();
        assert_eq!(ledger.get(1).unwrap().status, CleanupStatus::Verified);

        // Replay with Reconciled status.
        e1_verified.status = CleanupStatus::Reconciled;
        ledger
            .replay_records(&[e1_verified.to_intent_log_record()])
            .unwrap();
        assert_eq!(ledger.get(1).unwrap().status, CleanupStatus::Reconciled);
    }

    #[test]
    fn replay_advances_next_entry_id() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        let e1 = CleanupEntry::from_freed_extent(5, fe(1));
        ledger.replay_records(&[e1.to_intent_log_record()]).unwrap();
        // next_entry_id should be max(existing) + 1 = 6
        assert_eq!(ledger.next_entry_id(), 6);
    }

    // ── Count by status ──────────────────────────────────────────

    #[test]
    fn count_by_status_tracks_state_correctly() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        ledger.enqueue(fe(1));
        ledger.enqueue(fe(2));
        ledger.enqueue(fe(3));

        ledger.verify_dead(1, &[0xFF; 32]).unwrap();
        ledger.verify_dead(2, &[0xAA; 32]).unwrap();
        // 3 stays Pending

        assert_eq!(ledger.count_by_status(CleanupStatus::Pending), 1);
        assert_eq!(ledger.count_by_status(CleanupStatus::Verified), 2);
        assert_eq!(ledger.count_by_status(CleanupStatus::Reconciled), 0);
        assert_eq!(ledger.count_by_status(CleanupStatus::Failed), 0);

        ledger.reconcile(1).unwrap();
        assert_eq!(ledger.count_by_status(CleanupStatus::Reconciled), 1);
    }

    // ── Dirty tracking ───────────────────────────────────────────

    #[test]
    fn dirty_flag_tracks_modifications() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        assert!(!ledger.is_dirty());

        ledger.enqueue(fe(1));
        assert!(ledger.is_dirty());

        ledger.mark_clean();
        assert!(!ledger.is_dirty());

        ledger.verify_dead(1, &[0xFF; 32]).unwrap();
        assert!(ledger.is_dirty());
    }

    // ── All/dirty records ────────────────────────────────────────

    #[test]
    fn all_records_returns_every_entry() {
        let mut ledger = CleanupQueueLedger::new(CleanupQueueConfig::default());
        ledger.enqueue(fe(1));
        ledger.enqueue(fe(2));
        let records = ledger.all_records();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn dirty_records_only_returns_pending_and_verified() {
        let config = CleanupQueueConfig {
            max_retries: 0,
            ..CleanupQueueConfig::default()
        };
        let mut ledger = CleanupQueueLedger::new(config);

        ledger.enqueue(fe(1)); // pending
        ledger.enqueue(fe(2)); // will be verified
        ledger.enqueue(fe(3)); // will be failed
        ledger.enqueue(fe(4)); // will be verified then reconciled

        ledger.verify_dead(2, &[0xFF; 32]).unwrap();
        let _ = ledger.verify_dead(3, &[3; 32]);
        ledger.verify_dead(4, &[0xAA; 32]).unwrap();
        ledger.reconcile(4).unwrap();

        let records = ledger.dirty_records();
        // Entries 1 (Pending) and 2 (Verified) only.
        assert_eq!(records.len(), 2);
    }

    // ── With starting ID ─────────────────────────────────────────

    #[test]
    fn with_starting_id_resumes_from_given_id() {
        let mut ledger = CleanupQueueLedger::with_starting_id(CleanupQueueConfig::default(), 100);
        let id = ledger.enqueue(fe(1));
        assert_eq!(id, 100);
        assert_eq!(ledger.next_entry_id(), 101);
    }
}
