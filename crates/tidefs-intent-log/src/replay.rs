//! Intent-log replay engine for mount-time crash recovery.
//!
//! [`IntentReplayEngine`] iterates unapplied intent records from segment
//! data, dispatches each record type through an [`IntentReplayHandler`],
//! and marks records as applied after successful replay. The engine
//! skips already-applied records (idempotent) and handles truncated
//! partial records at log tail.
//!
//! # Architecture
//!
//! ```text
//! Mount recovery ──► IntentReplayEngine::replay_segment()
//!                         │
//!                         ├─ read_segment() via IntentLogReader
//!                         ├─ filter: lsn > applied_txg
//!                         ├─ filter: lsn not in applied_lsns (dedup)
//!                         ├─ dispatch: handler.handle_record()
//!                         ├─ update: ReplayState counters + covered LSNs
//!                         └─ checkpoint: BLAKE3 domain-separated digest
//! ```
//!
//! # Idempotency
//!
//! Replay must be idempotent: applying the same committed log records
//! multiple times must produce the same persistent state as a single
//! application. Crash during replay itself must not produce a state
//! that a subsequent replay cannot recover.
//!
//! Replay idempotency is split across three responsibilities:
//!
//! 1. **applied_txg watermark**: Records with LSN ≤ `applied_txg` are
//!    skipped because the persistent checkpoint already reflects them.
//!    This covers the common case of a clean restart after a completed
//!    replay.
//!
//! 2. **handler idempotency**: For records above the checkpoint
//!    watermark, handlers must treat an already-applied durable mutation
//!    as success. This is the crash-during-replay contract: after a real
//!    restart, in-memory replay state is gone, so durable state may see
//!    the same committed record again.
//!
//! 3. **applied_lsns dedup**: Records whose LSN appears in the in-memory
//!    `applied_lsns` set are skipped even when `applied_txg` has not
//!    yet advanced. This prevents duplicate dispatch inside one replay
//!    engine instance, for example when segments overlap or a caller
//!    retries a segment in the same process. Replay-safe no-op records
//!    are also marked here so checkpoint gating can prove the LSN range
//!    is covered without dispatching a durable mutation. It is not
//!    persistent crash state.
//!
//! ## Per-Record-Kind Idempotency Contract
//!
//! Handlers implement per-record-type idempotency by treating
//! already-applied operations as success:
//!
//! | Record Kind     | Idempotency Behaviour                                          |
//! |-----------------|----------------------------------------------------------------|
//! | Create          | EEXIST → success (entry already present)                       |
//! | Unlink          | ENOENT  → success (entry already removed)                     |
//! | Rename          | ENOENT on src → success; target already correct → success     |
//! | Write           | Same data at same offset → no-op                              |
//! | Truncate        | Already at target size → no-op                                |
//! | Setattr         | Attributes already match → no-op                              |
//! | Symlink         | EEXIST → success                                              |
//! | HardLink        | EEXIST → success                                              |
//! | Mkdir           | EEXIST → success                                              |
//! | Rmdir           | ENOENT → success                                              |
//! | Mknod           | EEXIST → success                                              |
//! | XattrSet        | Key+value already match → no-op                               |
//! | XattrRemove     | ENODATA → success                                             |
//! | Fallocate       | Extents already allocated → no-op                             |
//! | BufferedWrite   | Same data at same offset → no-op                              |
//! | Tmpfile         | EEXIST for allocated temp inode → success                     |
//! | CopyFileRange   | Destination range already matches source → no-op              |
//! | TxBegin         | Already in expected state → no-op                             |
//! | TxCommit        | Already committed → no-op                                     |
//! | TxAbort         | Already aborted → no-op                                       |
//! | ExportTerminal  | Terminal already exported → no-op                             |
//!
//! Record types that are never replayable (Flush, Fsync, WriteIntentAck,
//! Lseek, CleanupQueue) are skipped unconditionally; cleanup-queue reclaim
//! state remains under the cleanup ledger authority, not replay dispatch.
//!
//! # Checkpoint
//!
//! After replay completes, [`IntentReplayEngine::compute_checkpoint`]
//! computes a BLAKE3-256 domain-separated digest over the replay state
//! including the set of applied LSNs. The domain tag
//! `tidefs-intent-replay-v1` prevents cross-purpose hash collisions.
//!
//! The checkpoint must only advance after all records up to the target
//! LSN have been applied and verified. Use
//! [`IntentReplayEngine::is_checkpointable_up_to`] to check readiness
//! before advancing the watermark.

use crate::{IntentLogReader, IntentLogRecord, SegmentReadResult};

// ── Domain tag for BLAKE3 replay checkpoint ──────────────────────────

/// Domain separation prefix for intent-replay checkpoint digests.
const REPLAY_CHECKPOINT_DOMAIN: &[u8] = b"tidefs-intent-replay-v1";

// ── IntentReplayHandler ──────────────────────────────────────────────

/// Trait for replay handlers that process intent-log records.
///
/// Implementations bridge intent-log records back to filesystem
/// operations. Each record type is dispatched through the single
/// [`handle_record`] method; implementors pattern-match on the
/// record variant and apply the corresponding mutation.
///
/// # Idempotency
///
/// Handlers must treat already-applied operations as success
/// (e.g. `EEXIST` for namespace creates means the entry is already
/// present — no work needed). See the module-level documentation
/// for the per-record-kind idempotency contract. This handler contract
/// is what makes crash-before-checkpoint re-replay safe after process
/// state is lost.
pub trait IntentReplayHandler {
    /// The error type returned when replay of a record fails.
    type Error: std::fmt::Display;

    /// Handle a single intent-log record during replay.
    ///
    /// Returns `Ok(())` if the record was applied successfully or
    /// was already applied (idempotent). Returns `Err` if replay
    /// of this specific record failed and should abort the replay run.
    fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), Self::Error>;
}

// ── ReplayState ──────────────────────────────────────────────────────

/// Tracks replay progress across the replay run.
///
/// The `applied_lsns` field records every LSN that has been safely covered
/// during the current replay run, either by successful replay dispatch or by
/// recognizing a replay-safe no-op record. This enables within-run
/// deduplication and checkpoint verification, but it is not durable post-crash
/// replay state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayState {
    /// Last fully-applied transaction group ID.
    /// Records with LSN <= this watermark are skipped.
    pub applied_txg: u64,

    /// Number of intent-log entries successfully replayed.
    pub entries_replayed: u64,

    /// Number of entries skipped (LSN <= applied_txg or non-mutating record types).
    pub entries_skipped: u64,

    /// Number of entries that encountered a dispatch error.
    pub entries_errored: u64,

    /// Highest LSN encountered across all replayed segments.
    pub highest_lsn_seen: u64,

    /// LSNs that have been safely covered during this replay run. Stored in
    /// monotonic order; used for within-run dedup and checkpoint verification.
    pub applied_lsns: Vec<u64>,
}

impl ReplayState {
    /// Create a new replay state with an initial applied-txg watermark.
    #[must_use]
    pub fn new(applied_txg: u64) -> Self {
        Self {
            applied_txg,
            entries_replayed: 0,
            entries_skipped: 0,
            entries_errored: 0,
            highest_lsn_seen: 0,
            applied_lsns: Vec::new(),
        }
    }

    /// Total entries processed (replayed + skipped + errored).
    #[must_use]
    pub fn total_processed(&self) -> u64 {
        self.entries_replayed + self.entries_skipped + self.entries_errored
    }

    /// Check whether a given LSN has already been applied in this run.
    #[must_use]
    pub fn is_lsn_applied(&self, lsn: u64) -> bool {
        self.applied_lsns.binary_search(&lsn).is_ok()
    }

    /// Record that an LSN has been safely covered by replay.
    ///
    /// # Panics
    ///
    /// Panics if the LSN is already present (duplicate application).
    pub fn mark_lsn_applied(&mut self, lsn: u64) {
        match self.applied_lsns.binary_search(&lsn) {
            Ok(_) => panic!("LSN {lsn} already marked applied"),
            Err(pos) => self.applied_lsns.insert(pos, lsn),
        }
    }

    /// Check whether all LSNs in [0, target] have been applied.
    ///
    /// This verifies contiguous coverage from zero through the target,
    /// which is required before advancing the checkpoint watermark.
    /// LSNs at or below `applied_txg` are considered implicitly applied.
    #[must_use]
    pub fn applied_contiguous_up_to(&self, target: u64) -> bool {
        if target <= self.applied_txg {
            return true;
        }
        let start = self.applied_txg + 1;
        let expected_count = (target - self.applied_txg) as usize;
        if self.applied_lsns.len() < expected_count {
            return false;
        }
        // applied_lsns is sorted. Check that entries from
        // [start, target] match the expected sequence contiguously.
        let idx = self.applied_lsns.binary_search(&start);
        match idx {
            Ok(pos) => {
                if pos + expected_count > self.applied_lsns.len() {
                    return false;
                }
                for (i, expected_lsn) in (start..=target).enumerate() {
                    if self.applied_lsns[pos + i] != expected_lsn {
                        return false;
                    }
                }
                true
            }
            Err(_) => false,
        }
    }

    /// Returns the highest LSN that has been applied contiguously from zero.
    #[must_use]
    pub fn contiguous_applied_high(&self) -> u64 {
        let mut next = self.applied_txg + 1;
        for &lsn in &self.applied_lsns {
            if lsn == next {
                next += 1;
            } else if lsn > next {
                break;
            }
        }
        next.saturating_sub(1)
    }

    /// Compute a deterministic BLAKE3 hash of the applied LSNs for
    /// inclusion in the replay checkpoint.
    fn applied_lsns_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"applied-lsns-v1");
        hasher.update(&(self.applied_lsns.len() as u64).to_le_bytes());
        for &lsn in &self.applied_lsns {
            hasher.update(&lsn.to_le_bytes());
        }
        hasher.finalize().into()
    }
}

// ── ReplayCheckpoint ─────────────────────────────────────────────────

/// BLAKE3-verified replay checkpoint.
///
/// Computed after replay completes via [`IntentReplayEngine::compute_checkpoint`].
/// The digest covers the checkpoint watermark, highest observed LSN,
/// and the applied-LSNs hash under the domain tag
/// `tidefs-intent-replay-v1` for cross-purpose collision resistance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayCheckpoint {
    /// BLAKE3-256 digest of the replay state.
    pub digest: [u8; 32],
}

impl ReplayCheckpoint {
    /// Verify that this checkpoint matches an expected digest.
    #[must_use]
    pub fn verify(&self, expected: &[u8; 32]) -> bool {
        self.digest == *expected
    }
}

// ── ReplayError ──────────────────────────────────────────────────────

/// Errors that can occur during intent-log replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayError {
    /// A BLAKE3 checksum mismatch was detected in a segment frame.
    IntegrityFailure {
        /// The LSN of the corrupted record.
        lsn: u64,
        /// Description of the failure.
        reason: String,
    },
    /// The replay handler returned an error for a record.
    HandlerError {
        /// The LSN of the failing record.
        lsn: u64,
        /// Description of the failure.
        reason: String,
    },
    /// The segment data is corrupt and cannot be read.
    SegmentCorrupt {
        /// Description of the failure.
        reason: String,
    },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntegrityFailure { lsn, reason } => {
                write!(f, "replay integrity failure at LSN {lsn}: {reason}")
            }
            Self::HandlerError { lsn, reason } => {
                write!(f, "replay handler error at LSN {lsn}: {reason}")
            }
            Self::SegmentCorrupt { reason } => {
                write!(f, "segment corrupt: {reason}")
            }
        }
    }
}

impl std::error::Error for ReplayError {}

// ── SegmentReplayOutcome ─────────────────────────────────────────────

/// Outcome of replaying a single segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SegmentReplayOutcome {
    /// All records in the segment were replayed or skipped.
    Replayed {
        /// Number of records replayed in this segment.
        replayed: u64,
        /// Number of records skipped in this segment.
        skipped: u64,
    },
    /// The segment was skipped (no unapplied records, or corrupt).
    Skipped {
        /// Reason for skipping.
        reason: SkippedReason,
    },
}

/// Why a segment was skipped during replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkippedReason {
    /// All records in the segment were already applied.
    AllApplied,
    /// The segment has no replayable records.
    NoReplayableRecords,
    /// The segment is corrupt.
    Corrupt,
}

// ── IntentReplayEngine ───────────────────────────────────────────────

/// Engine for replaying BLAKE3-verified intent-log records during
/// mount-time crash recovery.
///
/// # Idempotency guarantees
///
/// Three independent mechanisms prevent double-application:
///
/// 1. The persistent `applied_txg` watermark skips records with
///    LSN ≤ the checkpointed value.
/// 2. Handler implementations make re-dispatch safe after a crash by
///    treating already-applied durable mutations as success.
/// 3. The in-memory `applied_lsns` set skips records already dispatched
///    in the current run.
///
/// # Checkpoint gating
///
/// Use [`is_checkpointable_up_to`] to verify that all records up to a
/// target LSN have been applied before advancing the checkpoint. The
/// checkpoint digest covers the watermark, highest observed LSN, and
/// applied-LSN set, so two replays that produce the same digest have
/// applied the same records.
///
/// # Example
///
/// ```ignore
/// use tidefs_intent_log::replay::{IntentReplayEngine, IntentReplayHandler};
///
/// struct MyHandler;
/// impl IntentReplayHandler for MyHandler {
///     type Error = String;
///     fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), String> {
///         match record {
///             IntentLogRecord::Create { parent, name, mode, ino } => {
///                 Ok(())
///             }
///             _ => Ok(()),
///         }
///     }
/// }
///
/// let mut engine = IntentReplayEngine::new(42);
/// let segment_data = std::fs::read("intent_log/segment-001.viflodev").unwrap();
/// engine.replay_segment(&segment_data, &mut MyHandler).unwrap();
///
/// // Only checkpoint after verifying contiguous application.
/// if engine.is_checkpointable_up_to(engine.state.highest_lsn_seen) {
///     let checkpoint = engine.compute_checkpoint();
///     // Persist checkpoint...
/// }
/// ```
#[derive(Clone, Debug)]
pub struct IntentReplayEngine {
    /// Replay progress and statistics.
    pub state: ReplayState,
}

impl IntentReplayEngine {
    /// Create a new replay engine with the given applied-txg watermark.
    #[must_use]
    pub fn new(applied_txg: u64) -> Self {
        Self {
            state: ReplayState::new(applied_txg),
        }
    }

    /// Replay a single intent-log segment through the given handler.
    ///
    /// Reads the segment via [`IntentLogReader::read_segment`], filters
    /// records whose LSN is strictly greater than `applied_txg` and not
    /// yet in `applied_lsns`, and dispatches each unapplied record
    /// through the handler.
    ///
    /// Already-applied records (lsn <= applied_txg), already-dispatched
    /// records (lsn in applied_lsns), and non-replayable record types
    /// (Flush, Fsync, WriteIntentAck, Lseek, CleanupQueue) are counted
    /// as skipped.
    ///
    /// Successfully dispatched records are recorded in `applied_lsns`
    /// for within-run deduplication.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::SegmentCorrupt`] if the segment cannot
    /// be read. Returns [`ReplayError::HandlerError`] if the handler
    /// fails on a record.
    pub fn replay_segment<H: IntentReplayHandler>(
        &mut self,
        segment_data: &[u8],
        handler: &mut H,
    ) -> Result<SegmentReplayOutcome, ReplayError> {
        let result = IntentLogReader::read_segment(segment_data);

        let records = match result {
            SegmentReadResult::Complete { records, .. } => records,
            SegmentReadResult::Truncated { valid_records, .. } => valid_records,
            SegmentReadResult::Corrupt => {
                return Ok(SegmentReplayOutcome::Skipped {
                    reason: SkippedReason::Corrupt,
                });
            }
        };

        if records.is_empty() {
            return Ok(SegmentReplayOutcome::Skipped {
                reason: SkippedReason::NoReplayableRecords,
            });
        }

        let mut segment_replayed: u64 = 0;
        let mut segment_skipped: u64 = 0;
        let mut any_unapplied = false;

        for seg_rec in &records {
            // Track highest LSN seen across all segments.
            self.state.highest_lsn_seen = self.state.highest_lsn_seen.max(seg_rec.lsn);

            // Idempotency gate: skip already-applied entries (persistent watermark).
            if seg_rec.lsn <= self.state.applied_txg {
                self.state.entries_skipped += 1;
                segment_skipped += 1;
                continue;
            }

            // Idempotency gate: skip entries already dispatched in this run.
            if self.state.is_lsn_applied(seg_rec.lsn) {
                self.state.entries_skipped += 1;
                segment_skipped += 1;
                continue;
            }

            // Replay-safe no-op records still cover their LSN for checkpoint
            // gating, even though they do not dispatch a durable mutation.
            if !is_replayable_record_type(&seg_rec.record) {
                self.state.mark_lsn_applied(seg_rec.lsn);
                self.state.entries_skipped += 1;
                segment_skipped += 1;
                continue;
            }

            any_unapplied = true;

            match handler.handle_record(&seg_rec.record) {
                Ok(()) => {
                    self.state.mark_lsn_applied(seg_rec.lsn);
                    self.state.entries_replayed += 1;
                    segment_replayed += 1;
                }
                Err(e) => {
                    self.state.entries_errored += 1;
                    return Err(ReplayError::HandlerError {
                        lsn: seg_rec.lsn,
                        reason: format!("{e}"),
                    });
                }
            }
        }

        if !any_unapplied {
            return Ok(SegmentReplayOutcome::Skipped {
                reason: SkippedReason::AllApplied,
            });
        }

        Ok(SegmentReplayOutcome::Replayed {
            replayed: segment_replayed,
            skipped: segment_skipped,
        })
    }

    /// Check whether all records up to `target_lsn` have been applied
    /// contiguously, making it safe to advance the checkpoint watermark
    /// to `target_lsn`.
    ///
    /// Returns `true` if every LSN in [0, target_lsn] is either covered
    /// by `applied_txg` or present in `applied_lsns`.
    #[must_use]
    pub fn is_checkpointable_up_to(&self, target_lsn: u64) -> bool {
        self.state.applied_contiguous_up_to(target_lsn)
    }

    /// Advance the applied_txg watermark to `new_watermark`.
    ///
    /// # Panics
    ///
    /// Panics if `new_watermark` is less than the current `applied_txg`,
    /// or if not all records up to `new_watermark` have been applied
    /// contiguously.
    pub fn advance_watermark(&mut self, new_watermark: u64) {
        assert!(
            new_watermark >= self.state.applied_txg,
            "watermark must advance: {new_watermark} < {}",
            self.state.applied_txg
        );
        assert!(
            self.is_checkpointable_up_to(new_watermark),
            "cannot advance watermark to {new_watermark}: applied LSNs not contiguous"
        );
        self.state.applied_txg = new_watermark;
    }

    /// Compute a BLAKE3-256 domain-separated checkpoint digest over the
    /// current replay state.
    ///
    /// The digest covers `applied_txg`, `highest_lsn_seen`, and the
    /// hash of `applied_lsns` under the domain tag
    /// `tidefs-intent-replay-v1`.
    #[must_use]
    pub fn compute_checkpoint(&self) -> ReplayCheckpoint {
        let mut hasher = blake3::Hasher::new_keyed(&blake3::hash(REPLAY_CHECKPOINT_DOMAIN).into());

        hasher.update(&self.state.applied_txg.to_le_bytes());
        hasher.update(&self.state.highest_lsn_seen.to_le_bytes());
        hasher.update(&self.state.applied_lsns_hash());

        let digest: [u8; 32] = hasher.finalize().into();
        ReplayCheckpoint { digest }
    }

    /// Verify that the current replay state matches an expected checkpoint.
    #[must_use]
    pub fn verify_checkpoint(&self, expected: &ReplayCheckpoint) -> bool {
        self.compute_checkpoint().verify(&expected.digest)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Returns `true` if the record type requires mutation dispatch during replay.
///
/// Records like `Flush`, `Fsync`, `WriteIntentAck`, `Lseek`, and
/// `CleanupQueue` are acknowledgment markers or metadata-only entries
/// that do not represent a durable filesystem mutation.
pub fn is_replayable_record_type(record: &IntentLogRecord) -> bool {
    !matches!(
        record,
        IntentLogRecord::Flush { .. }
            | IntentLogRecord::Fsync { .. }
            | IntentLogRecord::WriteIntentAck { .. }
            | IntentLogRecord::Lseek { .. }
            | IntentLogRecord::CleanupQueue { .. }
    )
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IntentLogFrame, IntentLogWriter, XattrNamespace, RECORD_DISCRIMINANT_WRITE};
    use std::collections::{BTreeMap, BTreeSet, HashSet};

    /// A test handler that records every record it sees.
    #[derive(Debug, Default)]
    struct RecordingHandler {
        records: Vec<IntentLogRecord>,
    }

    impl IntentReplayHandler for RecordingHandler {
        type Error = String;

        fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), String> {
            self.records.push(record.clone());
            Ok(())
        }
    }

    /// A handler that fails on a specific discriminant.
    #[derive(Debug)]
    struct FailingHandler {
        fail_on: u8,
        seen: u64,
    }

    impl IntentReplayHandler for FailingHandler {
        type Error = String;

        fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), String> {
            self.seen += 1;
            let disc = record.encode().first().copied().unwrap_or(0);
            if disc == self.fail_on {
                return Err(format!("intentional failure on discriminant {disc}"));
            }
            Ok(())
        }
    }

    /// A handler that tracks whether it's already seen an inode,
    /// simulating idempotent namespace operations.
    #[derive(Debug, Default)]
    struct IdempotentNamespaceHandler {
        created_inodes: HashSet<u64>,
        unlinked_inodes: HashSet<u64>,
        records: Vec<IntentLogRecord>,
    }

    impl IntentReplayHandler for IdempotentNamespaceHandler {
        type Error = String;

        fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), String> {
            self.records.push(record.clone());
            match record {
                IntentLogRecord::Create { ino, .. } | IntentLogRecord::Mkdir { ino, .. } => {
                    self.created_inodes.insert(*ino);
                }
                IntentLogRecord::Unlink { ino, .. } | IntentLogRecord::Rmdir { ino, .. } => {
                    self.unlinked_inodes.insert(*ino);
                }
                _ => {}
            }
            Ok(())
        }
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct DurableReplayModel {
        dirents: BTreeMap<(u64, Vec<u8>), u64>,
        removed_dirents: BTreeSet<(u64, Vec<u8>, u64)>,
        tmpfiles: BTreeSet<u64>,
        symlinks: BTreeMap<u64, Vec<u8>>,
        writes: BTreeMap<(u64, u64, u64), [u8; 32]>,
        buffered_writes: BTreeMap<(u64, u64, u64), Vec<u8>>,
        sizes: BTreeMap<u64, u64>,
        attrs: BTreeMap<u64, (u64, [u8; 64])>,
        xattrs: BTreeMap<(u64, u8, [u8; 32]), [u8; 32]>,
        removed_xattrs: BTreeSet<(u64, u8, [u8; 32])>,
        allocations: BTreeMap<(u64, u64, u64), i32>,
        copies: BTreeSet<(u64, u64, u64, u64, u64, u64, u64)>,
        tx_states: BTreeMap<u64, u8>,
        export_terminal: Option<u64>,
    }

    #[derive(Debug, Default)]
    struct DurableReplayHandler {
        state: DurableReplayModel,
        dispatches: u64,
    }

    impl IntentReplayHandler for DurableReplayHandler {
        type Error = String;

        fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), String> {
            self.dispatches += 1;
            match record {
                IntentLogRecord::Write {
                    ino,
                    offset,
                    length,
                    data_hash,
                } => {
                    self.state
                        .writes
                        .insert((*ino, *offset, *length), *data_hash);
                }
                IntentLogRecord::Truncate { ino, new_size } => {
                    self.state.sizes.insert(*ino, *new_size);
                }
                IntentLogRecord::Setattr {
                    ino,
                    attr_mask,
                    attrs,
                } => {
                    self.state.attrs.insert(*ino, (*attr_mask, *attrs));
                }
                IntentLogRecord::Create {
                    parent, name, ino, ..
                }
                | IntentLogRecord::Mkdir {
                    parent, name, ino, ..
                }
                | IntentLogRecord::Mknod {
                    parent, name, ino, ..
                } => {
                    self.state.dirents.insert((*parent, name.clone()), *ino);
                }
                IntentLogRecord::Unlink { parent, name, ino }
                | IntentLogRecord::Rmdir { parent, name, ino } => {
                    self.state.dirents.remove(&(*parent, name.clone()));
                    self.state
                        .removed_dirents
                        .insert((*parent, name.clone(), *ino));
                }
                IntentLogRecord::Rename {
                    src_parent,
                    src_name,
                    dst_parent,
                    dst_name,
                    ino,
                    overwrite_target_ino,
                    ..
                } => {
                    self.state.dirents.remove(&(*src_parent, src_name.clone()));
                    if let Some(target_ino) = overwrite_target_ino {
                        self.state.removed_dirents.insert((
                            *dst_parent,
                            dst_name.clone(),
                            *target_ino,
                        ));
                    }
                    self.state
                        .dirents
                        .insert((*dst_parent, dst_name.clone()), *ino);
                }
                IntentLogRecord::Symlink {
                    parent,
                    name,
                    target,
                    ino,
                } => {
                    self.state.dirents.insert((*parent, name.clone()), *ino);
                    self.state.symlinks.insert(*ino, target.clone());
                }
                IntentLogRecord::HardLink {
                    ino,
                    new_parent,
                    new_name,
                } => {
                    self.state
                        .dirents
                        .insert((*new_parent, new_name.clone()), *ino);
                }
                IntentLogRecord::XattrSet {
                    ino,
                    namespace,
                    key_hash,
                    value_hash,
                } => {
                    self.state
                        .xattrs
                        .insert((*ino, namespace.to_byte(), *key_hash), *value_hash);
                }
                IntentLogRecord::XattrRemove {
                    ino,
                    namespace,
                    key_hash,
                } => {
                    self.state
                        .xattrs
                        .remove(&(*ino, namespace.to_byte(), *key_hash));
                    self.state
                        .removed_xattrs
                        .insert((*ino, namespace.to_byte(), *key_hash));
                }
                IntentLogRecord::Fallocate {
                    ino,
                    offset,
                    length,
                    mode,
                } => {
                    self.state
                        .allocations
                        .insert((*ino, *offset, *length), *mode);
                }
                IntentLogRecord::BufferedWrite {
                    ino,
                    offset,
                    length,
                    data,
                } => {
                    self.state
                        .buffered_writes
                        .insert((*ino, *offset, *length), data.clone());
                }
                IntentLogRecord::Tmpfile { ino, .. } => {
                    self.state.tmpfiles.insert(*ino);
                }
                IntentLogRecord::CopyFileRange {
                    src_ino,
                    src_fh,
                    dst_ino,
                    dst_fh,
                    src_offset,
                    dst_offset,
                    len,
                } => {
                    self.state.copies.insert((
                        *src_ino,
                        *src_fh,
                        *dst_ino,
                        *dst_fh,
                        *src_offset,
                        *dst_offset,
                        *len,
                    ));
                }
                IntentLogRecord::TxBegin { cg_id } => {
                    self.state.tx_states.insert(*cg_id, 1);
                }
                IntentLogRecord::TxCommit { cg_id } => {
                    self.state.tx_states.insert(*cg_id, 2);
                }
                IntentLogRecord::TxAbort { cg_id } => {
                    self.state.tx_states.insert(*cg_id, 3);
                }
                IntentLogRecord::ExportTerminal { cg_id } => {
                    self.state.export_terminal = Some(*cg_id);
                }
                IntentLogRecord::Flush { .. }
                | IntentLogRecord::Fsync { .. }
                | IntentLogRecord::WriteIntentAck { .. }
                | IntentLogRecord::Lseek { .. }
                | IntentLogRecord::CleanupQueue { .. } => {}
            }
            Ok(())
        }
    }

    fn make_write_frame(seq: u64, ino: u64) -> IntentLogFrame {
        let rec = IntentLogRecord::Write {
            ino,
            offset: seq * 4096,
            length: 4096,
            data_hash: [0xAA; 32],
        };
        IntentLogFrame::new(rec, 1, seq)
    }

    fn make_test_segment(frames: &[IntentLogFrame]) -> Vec<u8> {
        let mut writer = IntentLogWriter::new(64 * 1024 * 1024);
        for f in frames {
            writer.append_frame(f).unwrap();
        }
        writer.finish().unwrap().unwrap()
    }

    fn make_record_segment(records: &[IntentLogRecord], first_lsn: u64) -> Vec<u8> {
        let frames: Vec<_> = records
            .iter()
            .enumerate()
            .map(|(i, record)| IntentLogFrame::new(record.clone(), 1, first_lsn + i as u64))
            .collect();
        make_test_segment(&frames)
    }

    fn replayable_record_suite() -> Vec<IntentLogRecord> {
        vec![
            IntentLogRecord::Write {
                ino: 10,
                offset: 0,
                length: 4096,
                data_hash: [0x11; 32],
            },
            IntentLogRecord::Truncate {
                ino: 10,
                new_size: 8192,
            },
            IntentLogRecord::Setattr {
                ino: 10,
                attr_mask: 0x7,
                attrs: [0x22; 64],
            },
            IntentLogRecord::Create {
                parent: 1,
                name: b"created".to_vec(),
                mode: 0o644,
                ino: 20,
            },
            IntentLogRecord::Unlink {
                parent: 1,
                name: b"removed".to_vec(),
                ino: 21,
            },
            IntentLogRecord::Rename {
                src_parent: 1,
                src_name: b"old".to_vec(),
                dst_parent: 2,
                dst_name: b"new".to_vec(),
                ino: 22,
                overwrite_target_ino: Some(23),
                rename_flags: 0,
            },
            IntentLogRecord::Symlink {
                parent: 1,
                name: b"link".to_vec(),
                target: b"target".to_vec(),
                ino: 24,
            },
            IntentLogRecord::HardLink {
                ino: 20,
                new_parent: 2,
                new_name: b"hard".to_vec(),
            },
            IntentLogRecord::Mkdir {
                parent: 1,
                name: b"dir".to_vec(),
                mode: 0o755,
                ino: 25,
            },
            IntentLogRecord::Rmdir {
                parent: 1,
                name: b"empty".to_vec(),
                ino: 26,
            },
            IntentLogRecord::Mknod {
                parent: 1,
                name: b"node".to_vec(),
                mode: 0o600,
                rdev: 0x1234,
                ino: 27,
            },
            IntentLogRecord::XattrSet {
                ino: 10,
                namespace: XattrNamespace::User,
                key_hash: [0x33; 32],
                value_hash: [0x44; 32],
            },
            IntentLogRecord::XattrRemove {
                ino: 10,
                namespace: XattrNamespace::User,
                key_hash: [0x55; 32],
            },
            IntentLogRecord::Fallocate {
                ino: 10,
                offset: 4096,
                length: 4096,
                mode: 0,
            },
            IntentLogRecord::BufferedWrite {
                ino: 10,
                offset: 8192,
                length: 4,
                data: b"data".to_vec(),
            },
            IntentLogRecord::Tmpfile {
                parent: 1,
                mode: 0o600,
                ino: 28,
            },
            IntentLogRecord::CopyFileRange {
                src_ino: 10,
                src_fh: 1,
                dst_ino: 11,
                dst_fh: 2,
                src_offset: 0,
                dst_offset: 4096,
                len: 512,
            },
            IntentLogRecord::TxBegin { cg_id: 100 },
            IntentLogRecord::TxCommit { cg_id: 100 },
            IntentLogRecord::TxAbort { cg_id: 101 },
            IntentLogRecord::ExportTerminal { cg_id: 102 },
        ]
    }

    // ── Engine construction ───────────────────────────────────────

    #[test]
    fn engine_new_stores_applied_txg() {
        let engine = IntentReplayEngine::new(42);
        assert_eq!(engine.state.applied_txg, 42);
        assert_eq!(engine.state.entries_replayed, 0);
        assert_eq!(engine.state.entries_skipped, 0);
        assert_eq!(engine.state.entries_errored, 0);
        assert_eq!(engine.state.highest_lsn_seen, 0);
        assert!(engine.state.applied_lsns.is_empty());
    }

    // ── ReplayState ──────────────────────────────────────────────

    #[test]
    fn replay_state_total_processed() {
        let mut state = ReplayState::new(0);
        state.entries_replayed = 10;
        state.entries_skipped = 5;
        state.entries_errored = 2;
        assert_eq!(state.total_processed(), 17);
    }

    #[test]
    fn replay_state_mark_and_check_lsn() {
        let mut state = ReplayState::new(0);
        assert!(!state.is_lsn_applied(0));

        state.mark_lsn_applied(0);
        assert!(state.is_lsn_applied(0));
        assert!(!state.is_lsn_applied(1));

        state.mark_lsn_applied(1);
        assert!(state.is_lsn_applied(0));
        assert!(state.is_lsn_applied(1));
    }

    #[test]
    #[should_panic(expected = "already marked applied")]
    fn replay_state_double_mark_panics() {
        let mut state = ReplayState::new(0);
        state.mark_lsn_applied(0);
        state.mark_lsn_applied(0);
    }

    #[test]
    fn applied_lsns_maintains_monotonic_order() {
        let mut state = ReplayState::new(0);
        state.mark_lsn_applied(3);
        state.mark_lsn_applied(1);
        state.mark_lsn_applied(5);
        state.mark_lsn_applied(0);
        assert_eq!(state.applied_lsns, vec![0, 1, 3, 5]);
    }

    #[test]
    fn applied_contiguous_up_to_empty() {
        let state = ReplayState::new(0);
        assert!(state.applied_contiguous_up_to(0));
    }

    #[test]
    fn applied_contiguous_up_to_full() {
        let mut state = ReplayState::new(0);
        for i in 0..=5 {
            state.mark_lsn_applied(i);
        }
        assert!(state.applied_contiguous_up_to(5));
        assert!(state.applied_contiguous_up_to(3));
        assert!(!state.applied_contiguous_up_to(6));
    }

    #[test]
    fn applied_contiguous_up_to_gap() {
        let mut state = ReplayState::new(0);
        state.mark_lsn_applied(0);
        state.mark_lsn_applied(1);
        // gap at 2
        state.mark_lsn_applied(3);
        assert!(state.applied_contiguous_up_to(1));
        assert!(!state.applied_contiguous_up_to(2));
        assert!(!state.applied_contiguous_up_to(3));
    }

    #[test]
    fn applied_contiguous_respects_applied_txg() {
        let mut state = ReplayState::new(5);
        // LSNs 0-5 are covered by applied_txg
        state.mark_lsn_applied(6);
        state.mark_lsn_applied(7);
        assert!(state.applied_contiguous_up_to(7));
        assert!(state.applied_contiguous_up_to(6));
        assert!(!state.applied_contiguous_up_to(8));
    }

    #[test]
    fn contiguous_applied_high_empty() {
        let state = ReplayState::new(0);
        // When nothing is applied beyond applied_txg, contiguous high is applied_txg (0).
        assert_eq!(state.contiguous_applied_high(), 0);
    }

    #[test]
    fn contiguous_applied_high_gap() {
        let mut state = ReplayState::new(0);
        state.mark_lsn_applied(0);
        state.mark_lsn_applied(1);
        state.mark_lsn_applied(3);
        assert_eq!(state.contiguous_applied_high(), 1);
    }

    // ── Replay full segment ──────────────────────────────────────

    #[test]
    fn replay_full_segment() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 100 + i)).collect();
        let segment = make_test_segment(&frames);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = RecordingHandler::default();

        let outcome = engine.replay_segment(&segment, &mut handler).unwrap();
        assert!(matches!(outcome, SegmentReplayOutcome::Replayed { .. }));
        // LSN 0 is NOT > 0, so it's skipped. 4 records (1-4) replayed.
        assert_eq!(engine.state.entries_replayed, 4);
        assert_eq!(engine.state.entries_skipped, 1);
        assert_eq!(handler.records.len(), 4);
        assert_eq!(engine.state.highest_lsn_seen, 4);
        assert_eq!(engine.state.applied_lsns, vec![1, 2, 3, 4]);
    }

    #[test]
    fn replay_with_applied_txg_filters() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 200 + i)).collect();
        let segment = make_test_segment(&frames);

        // Set applied_txg to 2 — records with lsn <= 2 are skipped.
        let mut engine = IntentReplayEngine::new(2);
        let mut handler = RecordingHandler::default();

        engine.replay_segment(&segment, &mut handler).unwrap();
        assert_eq!(engine.state.entries_replayed, 2); // LSNs 3, 4
        assert_eq!(engine.state.entries_skipped, 3); // LSNs 0, 1, 2
        assert_eq!(handler.records.len(), 2);
        assert_eq!(engine.state.applied_lsns, vec![3, 4]);
    }

    // ── Corrupt segment ──────────────────────────────────────────

    #[test]
    fn replay_corrupt_segment() {
        let corrupt_data = vec![0xFFu8; 256];
        let mut engine = IntentReplayEngine::new(0);
        let mut handler = RecordingHandler::default();

        let outcome = engine.replay_segment(&corrupt_data, &mut handler).unwrap();
        assert!(matches!(
            outcome,
            SegmentReplayOutcome::Skipped {
                reason: SkippedReason::Corrupt
            }
        ));
        assert_eq!(engine.state.entries_replayed, 0);
    }

    // ── Handler error ────────────────────────────────────────────

    #[test]
    fn replay_handler_error() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 300 + i)).collect();
        let segment = make_test_segment(&frames);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = FailingHandler {
            fail_on: RECORD_DISCRIMINANT_WRITE,
            seen: 0,
        };

        let result = engine.replay_segment(&segment, &mut handler);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ReplayError::HandlerError { .. }));
        assert_eq!(handler.seen, 1);
        assert_eq!(engine.state.entries_errored, 1);
        // LSN 1 was not successfully applied
        assert!(!engine.state.is_lsn_applied(1));
    }

    // ── ReplayCheckpoint ─────────────────────────────────────────

    #[test]
    fn checkpoint_digest_is_32_bytes() {
        let engine = IntentReplayEngine::new(0);
        let cp = engine.compute_checkpoint();
        assert_eq!(cp.digest.len(), 32);
    }

    #[test]
    fn verify_checkpoint_matches() {
        let mut engine = IntentReplayEngine::new(7);
        engine.state.highest_lsn_seen = 10;
        engine.state.mark_lsn_applied(8);
        engine.state.mark_lsn_applied(9);
        engine.state.mark_lsn_applied(10);

        let cp = engine.compute_checkpoint();
        assert!(engine.verify_checkpoint(&cp));

        // Tamper with state (change applied_lsns)
        engine.state.mark_lsn_applied(11);
        assert!(!engine.verify_checkpoint(&cp));
    }

    #[test]
    fn checkpoint_changes_with_applied_lsns() {
        let mut engine = IntentReplayEngine::new(0);
        let cp_empty = engine.compute_checkpoint();

        engine.state.mark_lsn_applied(0);
        engine.state.mark_lsn_applied(1);
        let cp_with_lsns = engine.compute_checkpoint();

        assert_ne!(cp_empty.digest, cp_with_lsns.digest);
    }

    // ── Non-replayable record types are skipped ──────────────────

    #[test]
    fn flush_is_not_replayable() {
        let rec = IntentLogRecord::Flush {
            ino: 1,
            fh: 42,
            lock_owner: 0,
        };
        assert!(!is_replayable_record_type(&rec));
    }

    #[test]
    fn fsync_is_not_replayable() {
        let rec = IntentLogRecord::Fsync {
            ino: 1,
            fh: 42,
            mode: 0,
        };
        assert!(!is_replayable_record_type(&rec));
    }

    #[test]
    fn create_is_replayable() {
        let rec = IntentLogRecord::Create {
            parent: 1,
            name: b"f".to_vec(),
            mode: 0o644,
            ino: 10,
        };
        assert!(is_replayable_record_type(&rec));
    }

    #[test]
    fn unlink_is_replayable() {
        let rec = IntentLogRecord::Unlink {
            parent: 1,
            name: b"f".to_vec(),
            ino: 10,
        };
        assert!(is_replayable_record_type(&rec));
    }

    #[test]
    fn buffered_write_is_replayable() {
        let rec = IntentLogRecord::BufferedWrite {
            ino: 1,
            offset: 0,
            length: 4,
            data: b"test".to_vec(),
        };
        assert!(is_replayable_record_type(&rec));
    }

    // ── Truncated segment replay ─────────────────────────────────

    #[test]
    fn replay_truncated_segment() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 400 + i)).collect();
        let mut segment = make_test_segment(&frames);

        // Truncate before the footer (simulate crash)
        let trailer_start = segment.len() - 64;
        segment.truncate(trailer_start);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = RecordingHandler::default();

        let outcome = engine.replay_segment(&segment, &mut handler).unwrap();
        // Should replay valid records from truncated segment
        assert!(matches!(outcome, SegmentReplayOutcome::Replayed { .. }));
        assert!(engine.state.entries_replayed > 0);
    }

    // ── ReplayError Display ──────────────────────────────────────

    #[test]
    fn replay_error_display_is_readable() {
        let err = ReplayError::IntegrityFailure {
            lsn: 42,
            reason: "bad checksum".into(),
        };
        let s = format!("{err}");
        assert!(s.contains("42"));
        assert!(s.contains("bad checksum"));

        let err = ReplayError::HandlerError {
            lsn: 7,
            reason: "dispatch failed".into(),
        };
        let s = format!("{err}");
        assert!(s.contains("7"));
        assert!(s.contains("dispatch failed"));

        let err = ReplayError::SegmentCorrupt {
            reason: "io error".into(),
        };
        assert!(format!("{err}").contains("io error"));
    }

    // ── All-applied segment is skipped ───────────────────────────

    #[test]
    fn segment_all_applied_is_skipped() {
        let frames: Vec<_> = (0..3).map(|i| make_write_frame(i, 500 + i)).collect();
        let segment = make_test_segment(&frames);

        // applied_txg higher than any record LSN → all skipped
        let mut engine = IntentReplayEngine::new(100);
        let mut handler = RecordingHandler::default();

        let outcome = engine.replay_segment(&segment, &mut handler).unwrap();
        assert!(matches!(
            outcome,
            SegmentReplayOutcome::Skipped {
                reason: SkippedReason::AllApplied
            }
        ));
        assert_eq!(engine.state.entries_replayed, 0);
        assert_eq!(engine.state.entries_skipped, 3);
    }

    // ── ReplayCheckpoint verify ──────────────────────────────────

    #[test]
    fn replay_checkpoint_verify_against_expected() {
        let cp = ReplayCheckpoint { digest: [0xAB; 32] };
        assert!(cp.verify(&[0xAB; 32]));
        assert!(!cp.verify(&[0xCD; 32]));
    }

    // ── Idempotency: double-apply of the same segment ────────────

    #[test]
    fn double_replay_same_segment_is_idempotent() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 600 + i)).collect();
        let segment = make_test_segment(&frames);

        // First replay
        let mut engine = IntentReplayEngine::new(0);
        let mut handler = RecordingHandler::default();
        engine.replay_segment(&segment, &mut handler).unwrap();
        let first_replayed = engine.state.entries_replayed;
        let first_applied = engine.state.applied_lsns.clone();

        // Same-process retry of the same segment.
        let mut handler2 = RecordingHandler::default();
        engine.replay_segment(&segment, &mut handler2).unwrap();

        // No additional records should be dispatched (all in applied_lsns)
        assert_eq!(engine.state.entries_replayed, first_replayed);
        assert_eq!(engine.state.applied_lsns, first_applied);
        // Handler should not receive any new records
        assert!(handler2.records.is_empty());
    }

    #[test]
    fn double_replay_after_watermark_advance_skips_all() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 700 + i)).collect();
        let segment = make_test_segment(&frames);

        // First replay
        let mut engine = IntentReplayEngine::new(0);
        let mut handler = RecordingHandler::default();
        engine.replay_segment(&segment, &mut handler).unwrap();

        // Advance watermark past all LSNs
        engine.advance_watermark(4);

        // Second replay — all records should be skipped by applied_txg
        let mut handler2 = RecordingHandler::default();
        let outcome = engine.replay_segment(&segment, &mut handler2).unwrap();
        assert!(matches!(
            outcome,
            SegmentReplayOutcome::Skipped {
                reason: SkippedReason::AllApplied
            }
        ));
        assert!(handler2.records.is_empty());
    }

    // ── Idempotency: crash during replay ─────────────────────────

    #[test]
    fn fresh_engine_rereplay_after_mid_replay_crash_converges() {
        let records = replayable_record_suite();
        let segment = make_record_segment(&records, 1);

        let mut crashed = DurableReplayHandler::default();
        let mut partial_engine = IntentReplayEngine::new(0);
        let segment_records = match IntentLogReader::read_segment(&segment) {
            SegmentReadResult::Complete { records, .. } => records,
            _ => panic!("expected complete segment"),
        };
        for seg_rec in segment_records.iter().take(records.len() / 2) {
            crashed.handle_record(&seg_rec.record).unwrap();
            partial_engine.state.mark_lsn_applied(seg_rec.lsn);
            partial_engine.state.entries_replayed += 1;
            partial_engine.state.highest_lsn_seen =
                partial_engine.state.highest_lsn_seen.max(seg_rec.lsn);
        }
        let state_after_partial_crash = crashed.state.clone();
        assert_ne!(state_after_partial_crash, DurableReplayModel::default());

        // A real crash loses applied_lsns. Durable state remains and must make
        // replaying the same committed records idempotent.
        let mut rereplay_engine = IntentReplayEngine::new(0);
        rereplay_engine
            .replay_segment(&segment, &mut crashed)
            .unwrap();

        let mut clean = DurableReplayHandler::default();
        let mut clean_engine = IntentReplayEngine::new(0);
        clean_engine.replay_segment(&segment, &mut clean).unwrap();

        assert_eq!(crashed.state, clean.state);
        assert!(crashed.dispatches > clean.dispatches);
        assert_eq!(
            rereplay_engine.compute_checkpoint().digest,
            clean_engine.compute_checkpoint().digest
        );
    }

    #[test]
    fn crash_at_start_of_replay_all_records_replayed() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 900 + i)).collect();
        let segment = make_test_segment(&frames);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = RecordingHandler::default();
        engine.replay_segment(&segment, &mut handler).unwrap();
        assert_eq!(engine.state.entries_replayed, 4);
        let checkpoint_full = engine.compute_checkpoint();

        // Replay again (simulating crash-at-start with no checkpoint)
        let mut engine2 = IntentReplayEngine::new(0);
        let mut handler2 = RecordingHandler::default();
        engine2.replay_segment(&segment, &mut handler2).unwrap();

        // Should produce same checkpoint (same applied records)
        assert_eq!(engine2.compute_checkpoint().digest, checkpoint_full.digest);
    }

    #[test]
    fn crash_at_end_of_replay_before_checkpoint() {
        let records = replayable_record_suite();
        let segment = make_record_segment(&records, 1);

        // Full replay, then simulate crash before checkpoint write
        let mut engine = IntentReplayEngine::new(0);
        let mut handler = DurableReplayHandler::default();
        engine.replay_segment(&segment, &mut handler).unwrap();
        let state_after_first_replay = handler.state.clone();
        let first_dispatches = handler.dispatches;

        // applied_txg is still 0 and applied_lsns is lost after restart.
        let mut engine_rereplay = IntentReplayEngine::new(0);
        engine_rereplay
            .replay_segment(&segment, &mut handler)
            .unwrap();

        assert_eq!(handler.state, state_after_first_replay);
        assert_eq!(handler.dispatches, first_dispatches + records.len() as u64);
    }

    // ── Idempotency: crash during checkpoint write ───────────────

    #[test]
    fn crash_during_checkpoint_write_watermark_not_advanced() {
        // After a full replay, if the checkpoint write crashes,
        // the watermark stays at old value. Next mount replays the segment
        // with a fresh engine; handler idempotency prevents double-apply.
        let records = replayable_record_suite();
        let segment = make_record_segment(&records, 1);

        // Full replay
        let mut engine = IntentReplayEngine::new(0);
        let mut handler = DurableReplayHandler::default();
        engine.replay_segment(&segment, &mut handler).unwrap();
        let full_checkpoint = engine.compute_checkpoint();
        let state_after_first_replay = handler.state.clone();

        // Simulate: checkpoint write crashes, then a new process starts
        // with only the old durable watermark.
        let mut engine_rereplay = IntentReplayEngine::new(0);
        engine_rereplay
            .replay_segment(&segment, &mut handler)
            .unwrap();

        assert_eq!(handler.state, state_after_first_replay);
        assert_eq!(
            engine_rereplay.compute_checkpoint().digest,
            full_checkpoint.digest
        );
    }

    // ── Checkpoint gating ────────────────────────────────────────

    #[test]
    fn is_checkpointable_up_to_after_full_replay() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 1200 + i)).collect();
        let segment = make_test_segment(&frames);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = RecordingHandler::default();
        engine.replay_segment(&segment, &mut handler).unwrap();

        // LSNs 1,2,3,4 applied. LSN 0 covered by applied_txg=0.
        assert!(engine.is_checkpointable_up_to(4));
    }

    #[test]
    fn skipped_noop_records_cover_lsns_for_checkpoint_gating() {
        let records = vec![
            IntentLogRecord::Write {
                ino: 10,
                offset: 0,
                length: 4096,
                data_hash: [0x11; 32],
            },
            IntentLogRecord::Flush {
                ino: 10,
                fh: 1,
                lock_owner: 0,
            },
            IntentLogRecord::Write {
                ino: 10,
                offset: 4096,
                length: 4096,
                data_hash: [0x22; 32],
            },
            IntentLogRecord::Fsync {
                ino: 10,
                fh: 1,
                mode: 0,
            },
            IntentLogRecord::Write {
                ino: 10,
                offset: 8192,
                length: 4096,
                data_hash: [0x33; 32],
            },
        ];
        let segment = make_record_segment(&records, 1);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = RecordingHandler::default();
        engine.replay_segment(&segment, &mut handler).unwrap();

        assert_eq!(handler.records.len(), 3);
        assert_eq!(engine.state.entries_replayed, 3);
        assert_eq!(engine.state.entries_skipped, 2);
        assert_eq!(engine.state.applied_lsns, vec![1, 2, 3, 4, 5]);
        assert!(engine.is_checkpointable_up_to(engine.state.highest_lsn_seen));
    }

    #[test]
    fn advance_watermark_after_replay() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 1300 + i)).collect();
        let segment = make_test_segment(&frames);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = RecordingHandler::default();
        engine.replay_segment(&segment, &mut handler).unwrap();

        engine.advance_watermark(4);
        assert_eq!(engine.state.applied_txg, 4);
    }

    #[test]
    #[should_panic(expected = "watermark must advance")]
    fn advance_watermark_backwards_panics() {
        let mut engine = IntentReplayEngine::new(10);
        engine.advance_watermark(5);
    }

    #[test]
    #[should_panic(expected = "cannot advance watermark")]
    fn advance_watermark_without_contiguous_coverage_panics() {
        let mut engine = IntentReplayEngine::new(0);
        engine.state.mark_lsn_applied(3);
        engine.advance_watermark(3);
    }

    // ── Idempotency: partial final record ────────────────────────

    #[test]
    fn replay_with_partial_final_record() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 1400 + i)).collect();
        let mut segment = make_test_segment(&frames);

        // Truncate mid-record: remove last few bytes to simulate
        // a partially-written final record
        let truncate_at = segment.len() - 16;
        segment.truncate(truncate_at);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = RecordingHandler::default();

        let outcome = engine.replay_segment(&segment, &mut handler).unwrap();
        // Should replay valid records and skip the partial one
        assert!(matches!(outcome, SegmentReplayOutcome::Replayed { .. }));
        assert!(engine.state.entries_replayed > 0);
    }

    // ── Idempotency: log truncation after checkpoint ─────────────

    #[test]
    fn log_truncation_after_checkpoint() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 1500 + i)).collect();
        let segment = make_test_segment(&frames);

        // Full replay, then advance watermark
        let mut engine = IntentReplayEngine::new(0);
        {
            let mut handler = RecordingHandler::default();
            engine.replay_segment(&segment, &mut handler).unwrap();
        }
        engine.advance_watermark(4);
        let post_checkpoint = engine.compute_checkpoint();

        // Simulate log truncation: new segment with LSNs 5-9
        let frames2: Vec<_> = (5..10).map(|i| make_write_frame(i, 1600 + i)).collect();
        let segment2 = make_test_segment(&frames2);

        let mut handler2 = RecordingHandler::default();
        engine.replay_segment(&segment2, &mut handler2).unwrap();

        // Records 5-9 were replayed (LSN > applied_txg=4)
        assert_eq!(engine.state.entries_replayed, 9);
        assert_eq!(handler2.records.len(), 5);

        // Checkpoint has changed
        assert_ne!(engine.compute_checkpoint().digest, post_checkpoint.digest);
    }

    // ── Idempotency: per-record-kind double-apply ────────────────

    #[test]
    fn double_apply_create_record_idempotent() {
        let mut handler = IdempotentNamespaceHandler::default();
        let rec = IntentLogRecord::Create {
            parent: 1,
            name: b"file.txt".to_vec(),
            mode: 0o644,
            ino: 100,
        };
        handler.handle_record(&rec).unwrap();
        handler.handle_record(&rec).unwrap();
        assert_eq!(handler.created_inodes.len(), 1);
        assert_eq!(handler.records.len(), 2);
    }

    #[test]
    fn double_apply_unlink_record_idempotent() {
        let mut handler = IdempotentNamespaceHandler::default();
        let rec = IntentLogRecord::Unlink {
            parent: 1,
            name: b"stale.log".to_vec(),
            ino: 200,
        };
        handler.handle_record(&rec).unwrap();
        handler.handle_record(&rec).unwrap();
        assert_eq!(handler.unlinked_inodes.len(), 1);
    }

    #[test]
    fn double_apply_mkdir_record_idempotent() {
        let mut handler = IdempotentNamespaceHandler::default();
        let rec = IntentLogRecord::Mkdir {
            parent: 1,
            name: b"newdir".to_vec(),
            mode: 0o755,
            ino: 300,
        };
        handler.handle_record(&rec).unwrap();
        handler.handle_record(&rec).unwrap();
        assert_eq!(handler.created_inodes.len(), 1);
    }

    #[test]
    fn double_apply_rmdir_record_idempotent() {
        let mut handler = IdempotentNamespaceHandler::default();
        let rec = IntentLogRecord::Rmdir {
            parent: 1,
            name: b"olddir".to_vec(),
            ino: 400,
        };
        handler.handle_record(&rec).unwrap();
        handler.handle_record(&rec).unwrap();
        assert_eq!(handler.unlinked_inodes.len(), 1);
    }

    // ── Checkpoint: same state produces same digest ──────────────

    #[test]
    fn identical_replay_runs_produce_same_checkpoint() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 1700 + i)).collect();
        let segment = make_test_segment(&frames);

        let mut engine1 = IntentReplayEngine::new(0);
        let mut handler1 = RecordingHandler::default();
        engine1.replay_segment(&segment, &mut handler1).unwrap();
        let cp1 = engine1.compute_checkpoint();

        let mut engine2 = IntentReplayEngine::new(0);
        let mut handler2 = RecordingHandler::default();
        engine2.replay_segment(&segment, &mut handler2).unwrap();
        let cp2 = engine2.compute_checkpoint();

        assert_eq!(cp1.digest, cp2.digest);
    }

    #[test]
    fn different_replay_runs_produce_different_checkpoint() {
        let frames1: Vec<_> = (0..3).map(|i| make_write_frame(i, 100)).collect();
        let segment1 = make_test_segment(&frames1);

        let frames2: Vec<_> = (0..5).map(|i| make_write_frame(i, 200)).collect();
        let segment2 = make_test_segment(&frames2);

        let mut engine1 = IntentReplayEngine::new(0);
        let mut handler1 = RecordingHandler::default();
        engine1.replay_segment(&segment1, &mut handler1).unwrap();
        let cp1 = engine1.compute_checkpoint();

        let mut engine2 = IntentReplayEngine::new(0);
        let mut handler2 = RecordingHandler::default();
        engine2.replay_segment(&segment2, &mut handler2).unwrap();
        let cp2 = engine2.compute_checkpoint();

        assert_ne!(cp1.digest, cp2.digest);
    }
}
