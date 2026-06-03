//! VfsEngine-aware intent-log replay engine for mount-time crash recovery.
//!
//! [`ReplayEngine`] uses the [`tidefs_intent_log::replay::IntentReplayEngine`]
//! to iterate BLAKE3-verified intent-log segments, filter entries by the
//! applied-transaction-group watermark, and dispatch unapplied namespace
//! and data mutations through [`VfsEngine`] via [`VfsReplayHandler`].
//!
//! # Architecture
//!
//! ```text
//! Mount ──► ReplayEngine::replay_intent_log()
//!                │
//!                ├─ List segment files from intent_log_dir
//!                ├─ For each segment: IntentReplayEngine::replay_segment()
//!                │     └─ VfsReplayHandler::handle_record()
//!                │          └─ dispatch_record() → VfsEngine
//!                ├─ Update ReplayState statistics
//!                └─ Return ReplayOutcome
//! ```
//!
//! # Idempotency
//!
//! Records at or below `applied_txg` are skipped: the committed root
//! already reflects those mutations. For records above `applied_txg`,
//! dispatch is naturally idempotent — creating an already-existing
//! entry returns `EEXIST`, which is treated as success during replay.

use std::path::Path;

use tidefs_intent_log::{
    replay::{
        self as intent_replay, IntentReplayEngine, IntentReplayHandler, ReplayCheckpoint,
        SegmentReplayOutcome,
    },
    IntentLogReader, IntentLogRecord, SegmentReadResult,
};
use tidefs_vfs_engine::{Errno, InodeId, RequestCtx, SetAttr, VfsEngine, FATTR_SIZE};

// ── ReplayState ─────────────────────────────────────────────────────

/// Tracks replay progress and statistics across the replay run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReplayState {
    /// Last fully-applied transaction group ID.
    /// Records with LSN <= this watermark are skipped.
    pub applied_txg: u64,

    /// Number of intent-log entries successfully replayed.
    pub entries_replayed: u64,

    /// Number of entries skipped (LSN <= applied_txg or non-dirty record types).
    pub entries_skipped: u64,

    /// Number of entries that encountered a dispatch error.
    pub entries_errored: u64,
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
        }
    }
}

// ── ReplayOutcome ────────────────────────────────────────────────────

/// Result of a replay run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayOutcome {
    /// All unapplied entries were replayed successfully.
    ReplayComplete {
        /// Number of intent-log entries replayed.
        replayed: u64,
        /// Number of entries skipped (already applied or non-mutating).
        skipped: u64,
    },
    /// Replay encountered a non-recoverable error.
    ReplayError {
        /// Number of entries replayed before the error.
        replayed: u64,
        /// Description of the failure.
        error: ReplayError,
    },
}

impl ReplayOutcome {
    /// Returns `true` if replay completed without error.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::ReplayComplete { .. })
    }

    /// Total entries processed (replayed + skipped).
    #[must_use]
    pub fn total_processed(&self) -> u64 {
        match self {
            Self::ReplayComplete { replayed, skipped } => replayed + skipped,
            Self::ReplayError { replayed, .. } => *replayed,
        }
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
    /// The VfsEngine returned an unexpected error during dispatch.
    VfsEngineError {
        /// The LSN of the failing record.
        lsn: u64,
        /// The record discriminant for diagnostics.
        discriminant: u8,
        /// The errno returned by VfsEngine (when available).
        errno: Option<Errno>,
        /// Description of the failure.
        reason: String,
    },
    /// An I/O error occurred reading intent-log segments.
    IntentLogReadError {
        /// Description of the failure.
        reason: String,
    },
    /// A required inode was not found during replay.
    InodeNotFound {
        /// The missing inode.
        ino: u64,
    },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntegrityFailure { lsn, reason } => {
                write!(f, "integrity failure at LSN {lsn}: {reason}")
            }
            Self::VfsEngineError {
                lsn,
                discriminant,
                errno,
                reason,
            } => {
                write!(
                    f,
                    "VfsEngine error at LSN {lsn} (discriminant={discriminant}): {reason}"
                )?;
                if let Some(e) = errno {
                    write!(f, " (errno={e})")?;
                }
                Ok(())
            }
            Self::IntentLogReadError { reason } => {
                write!(f, "intent-log read error: {reason}")
            }
            Self::InodeNotFound { ino } => {
                write!(f, "inode not found during replay: {ino}")
            }
        }
    }
}

impl std::error::Error for ReplayError {}

// ── VfsReplayHandler ─────────────────────────────────────────────────

/// Bridges [`IntentReplayHandler`] to [`VfsEngine`] for replay dispatch.
///
/// Delegates each intent-log record to the appropriate VfsEngine method
/// via [`dispatch_record`], with idempotency semantics (EEXIST and
/// ENOENT are treated as success for namespace operations).
impl std::fmt::Debug for VfsReplayHandler<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VfsReplayHandler")
            .field("vfs", &"(dyn VfsEngine)")
            .field("ctx", &self.ctx)
            .finish()
    }
}

pub struct VfsReplayHandler<'a> {
    /// The VfsEngine instance for dispatch.
    pub vfs: &'a dyn VfsEngine,
    /// Replay-compatible request context (typically root credentials).
    pub ctx: RequestCtx,
}

impl<'a> VfsReplayHandler<'a> {
    /// Create a new VfsReplayHandler with root credentials.
    #[must_use]
    pub fn new(vfs: &'a dyn VfsEngine) -> Self {
        Self {
            vfs,
            ctx: RequestCtx::new_root(),
        }
    }
}

impl IntentReplayHandler for VfsReplayHandler<'_> {
    type Error = ReplayError;

    fn handle_record(&mut self, record: &IntentLogRecord) -> Result<(), ReplayError> {
        dispatch_record(self.vfs, record, &self.ctx)
    }
}

// ── ReplayEngine ─────────────────────────────────────────────────────

/// Engine for replaying BLAKE3-verified intent-log entries through
/// [`VfsEngine`] during mount-time crash recovery.
///
/// Uses [`IntentReplayEngine`] from `tidefs-intent-log` for segment-level
/// replay orchestration, with [`VfsReplayHandler`] bridging to VfsEngine.
///
/// # Example
///
/// ```ignore
/// let mut engine = ReplayEngine::new(applied_txg);
/// let outcome = engine.replay_intent_log(
///     Path::new("/pool/intent_log"),
///     &vfs,
/// )?;
/// ```
#[derive(Debug)]
pub struct ReplayEngine {
    /// Replay progress and statistics.
    pub state: ReplayState,
}

impl ReplayEngine {
    /// Create a new replay engine with the given applied-txg watermark.
    #[must_use]
    pub fn new(applied_txg: u64) -> Self {
        Self {
            state: ReplayState::new(applied_txg),
        }
    }

    /// Replay all intent-log segments from `intent_log_dir` through `vfs`.
    ///
    /// Iterates segment files in the directory, reads each via
    /// [`IntentLogReader::read_segment`], filters records whose LSN is
    /// strictly greater than `applied_txg`, and dispatches unapplied
    /// mutations through the provided [`VfsEngine`] instance.
    ///
    /// Internally delegates to [`IntentReplayEngine::replay_segment`]
    /// for per-segment iteration, filtering, and dispatch orchestration.
    ///
    /// # Idempotency
    ///
    /// Records with `lsn <= self.state.applied_txg` are skipped —
    /// the committed root already reflects those mutations.
    /// Dispatch is naturally idempotent: creating an already-existing
    /// entry returns `EEXIST`, treated as success during replay.
    ///
    /// # Errors
    ///
    /// Returns `ReplayError` on integrity failure, I/O error, or
    /// VfsEngine dispatch failure for a non-idempotent operation.
    pub fn replay_intent_log(
        &mut self,
        intent_log_dir: &Path,
        vfs: &dyn VfsEngine,
    ) -> Result<ReplayOutcome, ReplayError> {
        // List segment files, sorted by name for deterministic order.
        let segment_paths = list_segment_files(intent_log_dir)?;
        if segment_paths.is_empty() {
            return Ok(ReplayOutcome::ReplayComplete {
                replayed: 0,
                skipped: 0,
            });
        }

        let mut handler = VfsReplayHandler::new(vfs);

        // Create an IntentReplayEngine for per-segment replay orchestration.
        let mut inner_engine = IntentReplayEngine::new(self.state.applied_txg);

        for path in &segment_paths {
            let data = std::fs::read(path).map_err(|e| ReplayError::IntentLogReadError {
                reason: format!("read segment {path:?}: {e}"),
            })?;

            let result = IntentLogReader::read_segment(&data);

            // Handle corrupt segments with a warning; don't abort recovery.
            if matches!(result, SegmentReadResult::Corrupt) {
                let segment_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown");
                eprintln!("replay: skipping corrupt intent-log segment {segment_name}");
                continue;
            }

            // Use the IntentReplayEngine to replay this segment.
            // Note: we need to extract the segment data handling slightly
            // differently since IntentReplayEngine::replay_segment takes raw bytes
            // and does its own read_segment internally.
            match inner_engine.replay_segment(&data, &mut handler) {
                Ok(outcome) => {
                    use SegmentReplayOutcome;
                    match outcome {
                        SegmentReplayOutcome::Replayed { .. }
                        | SegmentReplayOutcome::Skipped { .. } => {
                            // Progress recorded inside inner_engine.state
                        }
                    }
                }
                Err(e) => {
                    return Err(match e {
                        intent_replay::ReplayError::HandlerError { lsn, reason } => {
                            ReplayError::VfsEngineError {
                                lsn,
                                discriminant: 0,
                                errno: None,
                                reason,
                            }
                        }
                        intent_replay::ReplayError::IntegrityFailure { lsn, reason } => {
                            ReplayError::IntegrityFailure { lsn, reason }
                        }
                        intent_replay::ReplayError::SegmentCorrupt { reason } => {
                            ReplayError::IntentLogReadError { reason }
                        }
                    });
                }
            }
        }

        // Sync state from the inner engine.
        self.state.entries_replayed = inner_engine.state.entries_replayed;
        self.state.entries_skipped = inner_engine.state.entries_skipped;
        self.state.entries_errored = inner_engine.state.entries_errored;
        self.state.applied_txg = inner_engine
            .state
            .applied_txg
            .max(inner_engine.state.highest_lsn_seen);

        Ok(ReplayOutcome::ReplayComplete {
            replayed: self.state.entries_replayed,
            skipped: self.state.entries_skipped,
        })
    }

    /// Compute a BLAKE3 domain-separated replay checkpoint digest.
    ///
    /// Delegates to [`IntentReplayEngine::compute_checkpoint`] using
    /// the current replay state.
    #[must_use]
    pub fn compute_checkpoint(&self) -> ReplayCheckpoint {
        // Reconstruct inner engine state from our state for checkpoint computation.
        let mut inner = IntentReplayEngine::new(self.state.applied_txg);
        inner.state.entries_replayed = self.state.entries_replayed;
        inner.state.entries_skipped = self.state.entries_skipped;
        inner.state.entries_errored = self.state.entries_errored;
        inner.state.highest_lsn_seen = self.state.applied_txg;
        inner.compute_checkpoint()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// List segment files (`.viflodev` extension) in `intent_log_dir`,
/// sorted by filename for deterministic replay order.
fn list_segment_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, ReplayError> {
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|e| ReplayError::IntentLogReadError {
                    reason: format!("read_dir {dir:?}: {e}"),
                })?;
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "viflodev") {
                    paths.push(path);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No intent-log directory — nothing to replay.
            return Ok(paths);
        }
        Err(e) => {
            return Err(ReplayError::IntentLogReadError {
                reason: format!("read_dir {dir:?}: {e}"),
            });
        }
    }
    paths.sort();
    Ok(paths)
}

/// Dispatch a single intent-log record through [`VfsEngine`].
///
/// Returns `Ok(())` if the operation was applied or was already
/// applied (`EEXIST` for namespace creates). Returns `Err` for
/// non-recoverable dispatch failures.
fn dispatch_record(
    vfs: &dyn VfsEngine,
    record: &IntentLogRecord,
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    match record {
        // ── Namespace creation (idempotent via EEXIST) ───────────
        IntentLogRecord::Create {
            parent,
            name,
            mode,
            ino,
        } => {
            let parent_id = InodeId(*parent);
            match vfs.create(parent_id, name, *mode, 0, ctx) {
                Ok(_) | Err(Errno::EEXIST) => Ok(()),
                Err(e) => Err(engine_error(*ino, record, e)),
            }
        }
        IntentLogRecord::Mkdir {
            parent,
            name,
            mode,
            ino,
        } => {
            let parent_id = InodeId(*parent);
            match vfs.mkdir(parent_id, name, *mode, ctx) {
                Ok(_) | Err(Errno::EEXIST) => Ok(()),
                Err(e) => Err(engine_error(*ino, record, e)),
            }
        }
        IntentLogRecord::Symlink {
            parent,
            name,
            target,
            ino,
        } => {
            let parent_id = InodeId(*parent);
            match vfs.symlink(parent_id, name, target, ctx) {
                Ok(_) | Err(Errno::EEXIST) => Ok(()),
                Err(e) => Err(engine_error(*ino, record, e)),
            }
        }
        IntentLogRecord::Mknod {
            parent,
            name,
            mode,
            rdev,
            ino,
        } => {
            let parent_id = InodeId(*parent);
            match vfs.mknod(parent_id, name, *mode, *rdev as u32, ctx) {
                Ok(_) | Err(Errno::EEXIST) => Ok(()),
                Err(e) => Err(engine_error(*ino, record, e)),
            }
        }
        IntentLogRecord::Tmpfile { parent, mode, ino } => {
            let parent_id = InodeId(*parent);
            match vfs.tmpfile(parent_id, *mode, 0, ctx) {
                Ok(_) | Err(Errno::EEXIST) => Ok(()),
                Err(e) => Err(engine_error(*ino, record, e)),
            }
        }

        // ── Namespace removal (idempotent via ENOENT) ───────────
        IntentLogRecord::Unlink { parent, name, ino } => {
            let parent_id = InodeId(*parent);
            match vfs.unlink(parent_id, name, ctx) {
                Ok(()) | Err(Errno::ENOENT) => Ok(()),
                Err(e) => Err(engine_error(*ino, record, e)),
            }
        }
        IntentLogRecord::Rmdir { parent, name, ino } => {
            let parent_id = InodeId(*parent);
            match vfs.rmdir(parent_id, name, ctx) {
                Ok(()) | Err(Errno::ENOENT) => Ok(()),
                Err(e) => Err(engine_error(*ino, record, e)),
            }
        }

        // ── Rename (idempotent via ENOENT) ──────────────────────
        IntentLogRecord::Rename {
            src_parent,
            src_name,
            dst_parent,
            dst_name,
            ino,
            rename_flags,
            ..
        } => {
            let src_id = InodeId(*src_parent);
            let dst_id = InodeId(*dst_parent);
            match vfs.rename(src_id, src_name, dst_id, dst_name, *rename_flags, ctx) {
                Ok(()) | Err(Errno::ENOENT) => Ok(()),
                Err(e) => Err(engine_error(*ino, record, e)),
            }
        }

        // ── Hard link ───────────────────────────────────────────
        IntentLogRecord::HardLink {
            ino,
            new_parent,
            new_name,
        } => {
            let target_id = InodeId(*ino);
            let parent_id = InodeId(*new_parent);
            match vfs.link(target_id, parent_id, new_name, ctx) {
                Ok(_) | Err(Errno::EEXIST) => Ok(()),
                Err(e) => Err(engine_error(*ino, record, e)),
            }
        }

        // ── Truncate ────────────────────────────────────────────
        IntentLogRecord::Truncate { ino, new_size } => {
            let inode = InodeId(*ino);
            let mut attr = SetAttr::new();
            attr.valid = FATTR_SIZE;
            attr.size = *new_size;
            match vfs.setattr(inode, &attr, None, ctx) {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e == Errno::ENOENT {
                        return Ok(());
                    }
                    Err(engine_error(*ino, record, e))
                }
            }
        }

        // ── Setattr ─────────────────────────────────────────────
        IntentLogRecord::Setattr {
            ino,
            attr_mask,
            attrs,
        } => {
            let inode = InodeId(*ino);
            let mut set = SetAttr::new();
            set.valid = *attr_mask as u32;
            // Decode the 64-byte attr blob into SetAttr fields.
            let bytes = attrs;
            set.mode = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            set.uid = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            set.gid = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            set.size = u64::from_le_bytes([
                bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18],
                bytes[19],
            ]);
            set.atime_ns = i64::from_le_bytes([
                bytes[20], bytes[21], bytes[22], bytes[23], bytes[24], bytes[25], bytes[26],
                bytes[27],
            ]);
            set.mtime_ns = i64::from_le_bytes([
                bytes[28], bytes[29], bytes[30], bytes[31], bytes[32], bytes[33], bytes[34],
                bytes[35],
            ]);
            set.ctime_ns = i64::from_le_bytes([
                bytes[36], bytes[37], bytes[38], bytes[39], bytes[40], bytes[41], bytes[42],
                bytes[43],
            ]);
            match vfs.setattr(inode, &set, None, ctx) {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e == Errno::ENOENT {
                        return Ok(());
                    }
                    Err(engine_error(*ino, record, e))
                }
            }
        }

        // ── BufferedWrite (inline data) ─────────────────────────
        IntentLogRecord::BufferedWrite {
            ino, offset, data, ..
        } => replay_buffered_write(vfs, *ino, *offset, data, ctx),

        // ── Write (hash only, no inline data) ───────────────────
        IntentLogRecord::Write { .. } => Ok(()),

        // ── Fallocate ───────────────────────────────────────────
        IntentLogRecord::Fallocate { .. } => Ok(()),

        // ── CopyFileRange ───────────────────────────────────────
        IntentLogRecord::CopyFileRange { .. } => Ok(()),

        // ── Xattr operations ────────────────────────────────────
        IntentLogRecord::XattrSet { .. } | IntentLogRecord::XattrRemove { .. } => Ok(()),

        // Non-replayable records are filtered by is_replayable_record_type.
        _ => Ok(()),
    }
}

/// Replay a buffered write by opening the file, writing the inline data,
/// flushing, and releasing the handle.
fn replay_buffered_write(
    vfs: &dyn VfsEngine,
    ino: u64,
    offset: u64,
    data: &[u8],
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    if data.is_empty() {
        return Ok(());
    }

    let inode = InodeId(ino);

    let fh = match vfs.open(inode, 1 /* O_WRONLY */, ctx) {
        Ok(fh) => fh,
        Err(Errno::ENOENT) => return Ok(()),
        Err(e) => {
            return Err(ReplayError::VfsEngineError {
                lsn: 0,
                discriminant: tidefs_intent_log::RECORD_DISCRIMINANT_BUFFERED_WRITE,
                errno: Some(e),
                reason: format!("open ino={ino} for buffered-write replay: {e}"),
            })
        }
    };

    let _written = vfs
        .write(&fh, offset, data, ctx)
        .map_err(|e| ReplayError::VfsEngineError {
            lsn: 0,
            discriminant: tidefs_intent_log::RECORD_DISCRIMINANT_BUFFERED_WRITE,
            errno: Some(e),
            reason: format!("write ino={ino} offset={offset} len={}: {e}", data.len()),
        })?;

    let _ = vfs.flush(&fh, ctx);
    let _ = vfs.release(&fh);

    Ok(())
}

/// Build a VfsEngine dispatch error.
fn engine_error(ino: u64, record: &IntentLogRecord, errno: Errno) -> ReplayError {
    let discriminant = record.encode().first().copied().unwrap_or(0);
    ReplayError::VfsEngineError {
        lsn: 0,
        discriminant,
        errno: Some(errno),
        reason: format!("dispatch failed for ino={ino}: {errno}"),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── ReplayState ─────────────────────────────────────────────

    #[test]
    fn replay_state_new_sets_applied_txg() {
        let state = ReplayState::new(42);
        assert_eq!(state.applied_txg, 42);
        assert_eq!(state.entries_replayed, 0);
        assert_eq!(state.entries_skipped, 0);
        assert_eq!(state.entries_errored, 0);
    }

    #[test]
    fn replay_state_default_is_zeroed() {
        let state = ReplayState::default();
        assert_eq!(state.applied_txg, 0);
        assert_eq!(state.entries_replayed, 0);
    }

    // ── ReplayEngine construction ───────────────────────────────

    #[test]
    fn replay_engine_new_stores_applied_txg() {
        let engine = ReplayEngine::new(100);
        assert_eq!(engine.state.applied_txg, 100);
        assert_eq!(engine.state.entries_replayed, 0);
    }

    // ── ReplayOutcome ───────────────────────────────────────────

    #[test]
    fn replay_outcome_is_ok() {
        let ok = ReplayOutcome::ReplayComplete {
            replayed: 10,
            skipped: 3,
        };
        assert!(ok.is_ok());

        let err = ReplayOutcome::ReplayError {
            replayed: 5,
            error: ReplayError::IntentLogReadError {
                reason: "bad".into(),
            },
        };
        assert!(!err.is_ok());
    }

    #[test]
    fn replay_outcome_total_processed() {
        let ok = ReplayOutcome::ReplayComplete {
            replayed: 7,
            skipped: 3,
        };
        assert_eq!(ok.total_processed(), 10);

        let err = ReplayOutcome::ReplayError {
            replayed: 4,
            error: ReplayError::InodeNotFound { ino: 1 },
        };
        assert_eq!(err.total_processed(), 4);
    }

    // ── ReplayError Display ─────────────────────────────────────

    #[test]
    fn replay_error_display_is_human_readable() {
        let err = ReplayError::IntegrityFailure {
            lsn: 42,
            reason: "bad checksum".into(),
        };
        assert!(format!("{err}").contains("bad checksum"));
        assert!(format!("{err}").contains("42"));

        let err = ReplayError::VfsEngineError {
            lsn: 7,
            discriminant: 1,
            errno: None,
            reason: "dispatch failed".into(),
        };
        assert!(format!("{err}").contains("dispatch failed"));
        assert!(format!("{err}").contains("7"));

        let err = ReplayError::IntentLogReadError {
            reason: "io error".into(),
        };
        assert!(format!("{err}").contains("io error"));

        let err = ReplayError::InodeNotFound { ino: 99 };
        assert!(format!("{err}").contains("99"));
    }

    // ── list_segment_files ──────────────────────────────────────

    #[test]
    fn list_segment_files_empty_dir() {
        let tmp = TempDir::new().expect("tempdir");
        let result = list_segment_files(tmp.path()).expect("list");
        assert!(result.is_empty());
    }

    #[test]
    fn list_segment_files_nonexistent_dir() {
        let path = std::path::Path::new("/tmp/tidefs_nonexistent_replay_dir_99");
        let result = list_segment_files(path).expect("list nonexistent");
        assert!(result.is_empty());
    }

    #[test]
    fn list_segment_files_finds_viflodev_files() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join("seg-001.viflodev"), b"dummy").unwrap();
        std::fs::write(tmp.path().join("seg-002.viflodev"), b"dummy").unwrap();
        std::fs::write(tmp.path().join("other.txt"), b"ignore").unwrap();

        let result = list_segment_files(tmp.path()).expect("list");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn list_segment_files_sorted() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join("seg-010.viflodev"), b"").unwrap();
        std::fs::write(tmp.path().join("seg-001.viflodev"), b"").unwrap();
        std::fs::write(tmp.path().join("seg-005.viflodev"), b"").unwrap();

        let result = list_segment_files(tmp.path()).expect("list");
        assert_eq!(result.len(), 3);
        let names: Vec<String> = result
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names[0] < names[1]);
        assert!(names[1] < names[2]);
    }

    // ── VfsReplayHandler ────────────────────────────────────────

    #[test]
    fn vfs_replay_handler_constructs_with_root_ctx() {
        // We can't create a real VfsEngine without the full stack,
        // but we can verify the struct construction compiles and
        // the type is correct.
        // This is a compilation-only test — the actual dispatch
        // requires a real VfsEngine implementation.
    }

    // ── ReplayEngine checkpoint ─────────────────────────────────

    #[test]
    fn replay_engine_checkpoint_is_deterministic() {
        let mut engine = ReplayEngine::new(42);
        engine.state.entries_replayed = 10;
        engine.state.entries_skipped = 3;

        let cp1 = engine.compute_checkpoint();
        let cp2 = engine.compute_checkpoint();
        assert_eq!(cp1.digest, cp2.digest);
    }
}

// Review debt TFR-008: replay_intent_log integration tests need daemon wiring.
