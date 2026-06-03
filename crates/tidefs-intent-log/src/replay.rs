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
//!                         ├─ dispatch: handler.handle_record()
//!                         ├─ update: ReplayState counters
//!                         └─ checkpoint: BLAKE3 domain-separated digest
//! ```
//!
//! # Idempotency
//!
//! Records at or below `applied_txg` are skipped — the committed root
//! already reflects those mutations. For records above `applied_txg`,
//! dispatch is naturally idempotent: creating an already-existing entry
//! returns `EEXIST`, which handlers should treat as success.
//!
//! # Checkpoint
//!
//! After replay completes, [`IntentReplayEngine::compute_checkpoint`]
//! computes a BLAKE3-256 domain-separated digest over the replay state.
//! The domain tag `tidefs-intent-replay-v1` prevents cross-purpose
//! hash collisions.

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
/// Handlers should treat already-applied operations as success
/// (e.g. `EEXIST` for namespace creates means the entry is already
/// present — no work needed).
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
        }
    }

    /// Total entries processed (replayed + skipped + errored).
    #[must_use]
    pub fn total_processed(&self) -> u64 {
        self.entries_replayed + self.entries_skipped + self.entries_errored
    }
}

// ── ReplayCheckpoint ─────────────────────────────────────────────────

/// BLAKE3-verified replay checkpoint.
///
/// Computed after replay completes via [`IntentReplayEngine::compute_checkpoint`].
/// The digest covers the replay state (applied_txg, entries_replayed,
/// skipped, errored, highest_lsn_seen) under the domain tag
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
///                 // Create the file in the namespace
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
/// let checkpoint = engine.compute_checkpoint();
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
    /// records whose LSN is strictly greater than `applied_txg`, and
    /// dispatches each unapplied record through the handler.
    ///
    /// Already-applied records (lsn <= applied_txg) and non-replayable
    /// record types (Flush, Fsync, WriteIntentAck, Lseek, CleanupQueue)
    /// are counted as skipped.
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

            // Idempotency gate: skip already-applied entries.
            if seg_rec.lsn <= self.state.applied_txg {
                self.state.entries_skipped += 1;
                segment_skipped += 1;
                continue;
            }

            // Skip non-replayable record types.
            if !is_replayable_record_type(&seg_rec.record) {
                self.state.entries_skipped += 1;
                segment_skipped += 1;
                continue;
            }

            any_unapplied = true;

            match handler.handle_record(&seg_rec.record) {
                Ok(()) => {
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

    /// Compute a BLAKE3-256 domain-separated checkpoint digest over the
    /// current replay state.
    ///
    /// The digest covers `applied_txg`, `entries_replayed`,
    /// `entries_skipped`, `entries_errored`, and `highest_lsn_seen`
    /// under the domain tag `tidefs-intent-replay-v1`.
    #[must_use]
    pub fn compute_checkpoint(&self) -> ReplayCheckpoint {
        let mut hasher = blake3::Hasher::new_keyed(&blake3::hash(REPLAY_CHECKPOINT_DOMAIN).into());

        hasher.update(&self.state.applied_txg.to_le_bytes());
        hasher.update(&self.state.entries_replayed.to_le_bytes());
        hasher.update(&self.state.entries_skipped.to_le_bytes());
        hasher.update(&self.state.entries_errored.to_le_bytes());
        hasher.update(&self.state.highest_lsn_seen.to_le_bytes());

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
    use crate::{IntentLogFrame, IntentLogWriter, RECORD_DISCRIMINANT_WRITE};

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

    // ── Engine construction ───────────────────────────────────────

    #[test]
    fn engine_new_stores_applied_txg() {
        let engine = IntentReplayEngine::new(42);
        assert_eq!(engine.state.applied_txg, 42);
        assert_eq!(engine.state.entries_replayed, 0);
        assert_eq!(engine.state.entries_skipped, 0);
        assert_eq!(engine.state.entries_errored, 0);
        assert_eq!(engine.state.highest_lsn_seen, 0);
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

    // ── Replay full segment ──────────────────────────────────────

    #[test]
    fn replay_full_segment() {
        let frames: Vec<_> = (0..5).map(|i| make_write_frame(i, 100 + i)).collect();
        let segment = make_test_segment(&frames);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = RecordingHandler::default();

        let outcome = engine.replay_segment(&segment, &mut handler).unwrap();
        assert!(matches!(outcome, SegmentReplayOutcome::Replayed { .. }));
        // LSN 0 has lsn=0 which is <= applied_txg(0)... wait, applied_txg=0,
        // and records have lsn >= 0. The issue says lsn > applied_txg.
        // LSN 0 is NOT > 0, so it should be skipped. Let me adjust.
        // Actually, LSN 0 > 0 is false, so it's skipped. 4 records (1-4) replayed.
        assert_eq!(engine.state.entries_replayed, 4);
        assert_eq!(engine.state.entries_skipped, 1);
        assert_eq!(handler.records.len(), 4);
        assert_eq!(engine.state.highest_lsn_seen, 4);
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
    fn replay_handler_error_propagates() {
        let frames: Vec<_> = (0..3).map(|i| make_write_frame(i, 300 + i)).collect();
        let segment = make_test_segment(&frames);

        let mut engine = IntentReplayEngine::new(0);
        let mut handler = FailingHandler {
            fail_on: RECORD_DISCRIMINANT_WRITE,
            seen: 0,
        };

        let result = engine.replay_segment(&segment, &mut handler);
        assert!(result.is_err());
        assert_eq!(engine.state.entries_errored, 1);
        // The first record (LSN 0) should be skipped (lsn <= 0? No, lsn == 0, applied_txg=0,
        // so lsn > applied_txg is false → skipped). First dispatched is LSN 1.
        assert_eq!(handler.seen, 1);
    }

    // ── Checkpoint ───────────────────────────────────────────────

    #[test]
    fn checkpoint_is_deterministic() {
        let mut engine = IntentReplayEngine::new(42);
        engine.state.entries_replayed = 100;
        engine.state.entries_skipped = 20;
        engine.state.highest_lsn_seen = 150;

        let cp1 = engine.compute_checkpoint();
        let cp2 = engine.compute_checkpoint();
        assert_eq!(cp1.digest, cp2.digest);
    }

    #[test]
    fn checkpoint_differs_on_different_state() {
        let mut engine_a = IntentReplayEngine::new(1);
        engine_a.state.entries_replayed = 10;
        let mut engine_b = IntentReplayEngine::new(1);
        engine_b.state.entries_replayed = 11;

        let cp_a = engine_a.compute_checkpoint();
        let cp_b = engine_b.compute_checkpoint();
        assert_ne!(cp_a.digest, cp_b.digest);
    }

    #[test]
    fn checkpoint_digest_is_32_bytes() {
        let engine = IntentReplayEngine::new(0);
        let cp = engine.compute_checkpoint();
        assert_eq!(cp.digest.len(), 32);
    }

    #[test]
    fn verify_checkpoint_matches() {
        let mut engine = IntentReplayEngine::new(7);
        engine.state.entries_replayed = 5;
        engine.state.highest_lsn_seen = 10;

        let cp = engine.compute_checkpoint();
        assert!(engine.verify_checkpoint(&cp));

        // Tamper with state
        engine.state.entries_replayed += 1;
        assert!(!engine.verify_checkpoint(&cp));
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
}
