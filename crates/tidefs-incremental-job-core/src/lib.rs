#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Control-plane [`IncrementalJob`] trait and checkpoint serialization
//! contract for the universal incremental cursor framework.
//!
//! Implements Phase 2 of the background service framework.
//! Canonical design spec:
//! [`docs/design/background-service-framework-design.md`]
//! (issues #1592, #1673, #1674, #1780). Wire-up tracking: #1877.
//! Phase 1 (data-plane types: [`WorkBudget`], [`Checkpoint`], [`StepResult`],
//! [`JobId`], [`JobKind`], [`JobProgress`], [`JobError`]) lives in
//! [`tidefs_types_incremental_job_core`].
//!
//! # The IncrementalJob contract
//!
//! Every cursor-driven, bounded, crash-resumable background job in tidefs
//! must implement the [`IncrementalJob`] trait. This includes at least:
//!
//! - Deferred cleanup (extent freeing after unlink/truncate)
//! - Snapshot destroy (deadlist processing)
//! - GC mark (metadata reachability)
//! - B+tree compaction (node merging and rebalancing)
//! - Rebake (ingest journal to base shard conversion)
//! - Journal cleaning (data journal segment reclamation)
//! - Dataset destroy (admin-initiated teardown)
//! - Scrub / deep scrub (integrity verification)
//! - Resilver (device replacement data rebuild)
//! - Admin jobs (generic long-running operations)
//!
//! ## What implementors MUST guarantee
//!
//! 1. **Budget respect**: `step()` MUST NOT exceed the supplied [`WorkBudget`]
//!    in any dimension (items, bytes, time). The framework trusts the
//!    implementation; validation gates test compliance.
//! 2. **Crash safety**: `resume(Some(cp))` after a crash MUST produce the
//!    same final outcome as if the crash never happened (idempotent resumption).
//! 3. **Idempotency**: Calling `step()` twice with the same cursor position
//!    MUST NOT produce duplicate side effects. The checkpoint is the
//!    linearization point.
//! 4. **Checkpoint persistence**: After every `step()` that returns
//!    `Ok(result)`, the caller persists `result.checkpoint` before the next
//!    `step()`. This is the implementor's responsibility via
//!    `persist_checkpoint`.
//! 5. **Completion**: When `StepResult::is_complete` is true, the caller
//!    invokes `complete()` exactly once and never calls `step()` again.
//!
//! # Checkpoint serialization
//!
//! The [`CheckpointCodec`] trait provides a binary encoding contract for
//! persisting [`Checkpoint`] values to stable storage. The default
//! implementation uses a length-delimited binary format with magic bytes
//! and version number for forward compatibility.
//!
//! # Comparison to ZFS / Ceph
//!
//! - **ZFS**: Background operations (scrub, resilver, dataset destroy,
//!   send/receive) each use ad-hoc progress tracking (`dsl_scan_phys_t`,
//!   `device_rebuild` bitmaps, `bpobj` deferred-free lists) with no shared
//!   contract, non-resumable checkpoints, and fragmented admin visibility.
//! - **Ceph**: PG scrub/recovery/backfill use per-PG state machines with
//!   no cluster-wide budget model, no unified cursor contract, and
//!   duplicated crash-recovery logic across subsystems.
//!
//! TideFS eliminates this duplication with a single [`IncrementalJob`] trait
//! that all subsystems implement, providing uniform budget enforcement,
//! crash-resumable checkpoints, and consistent admin visibility.
//!
//! [`WorkBudget`]: tidefs_types_incremental_job_core::WorkBudget
//! [`Checkpoint`]: tidefs_types_incremental_job_core::Checkpoint
//! [`StepResult`]: tidefs_types_incremental_job_core::StepResult
//! [`JobId`]: tidefs_types_incremental_job_core::JobId
//! [`JobKind`]: tidefs_types_incremental_job_core::JobKind
//! [`JobProgress`]: tidefs_types_incremental_job_core::JobProgress
//! [`JobError`]: tidefs_types_incremental_job_core::JobError
//! [`docs/design/background-service-framework-design.md`]:
//!     docs/design/background-service-framework-design.md

#[cfg(feature = "alloc")]
extern crate alloc;

use tidefs_types_incremental_job_core::{
    Checkpoint, JobError, JobId, JobKind, StepResult, WorkBudget,
};

// ---------------------------------------------------------------------------
// IncrementalJob — the universal contract
// ---------------------------------------------------------------------------

/// The universal contract for bounded, cursor-driven, crash-resumable
/// background work.
///
/// # Lifecycle
///
/// ```text
///   resume(None) ──→ step(budget) ──→ persist_checkpoint ──→ step(budget) ──→ … ──→ complete()
///                      │                                                           │
///                      └── crash ──→ resume(Some(cp)) ──→ step(budget) ──→ … ──────┘
/// ```
///
/// Every implementation MUST:
/// - Accept and respect a [`WorkBudget`] on every `step()` call
/// - Return an accurate [`StepResult`] with the updated [`Checkpoint`]
/// - Support `resume(None)` for first-run and `resume(Some(cp))` for crash
///   recovery
/// - Guarantee idempotency: `step()` with the same cursor position produces
///   no duplicate side effects
///
/// # Object safety
///
/// This trait is object-safe and can be used as `&dyn IncrementalJob` for
/// scheduler dispatch. The `resume` constructor is called on the concrete
/// type; only `step`, `persist_checkpoint`, `complete`, `job_id`, and
/// `job_kind` are dispatched dynamically.
///
/// Requires the `alloc` feature (enabled by default) because [`Checkpoint`],
/// [`StepResult`], and [`JobError::Other`] require allocation.
#[cfg(feature = "alloc")]
pub trait IncrementalJob: Send {
    /// Resume from a previous checkpoint, or start fresh.
    ///
    /// `state`: `None` for first run; `Some(cp)` after crash or restart.
    /// Implementations load the cursor position from the persisted checkpoint
    /// and reposition their internal iterator accordingly.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::CheckpointCorrupt`] if the checkpoint is
    /// unreadable, [`JobError::CursorStateInvalid`] if the cursor blob
    /// cannot be parsed, or [`JobError::IoError`] on storage failures.
    fn resume(state: Option<Checkpoint>) -> Result<Self, JobError>
    where
        Self: Sized;

    /// Execute one bounded batch of work.
    ///
    /// MUST NOT exceed the supplied `budget`. On return,
    /// `StepResult.checkpoint` reflects the exact position after the batch.
    /// The caller persists this checkpoint before the next `step()`.
    ///
    /// If `StepResult.is_complete` is true, the job has finished and the
    /// caller should invoke `complete()` instead of calling `step()` again.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::BudgetExceeded`] if budget limits are violated,
    /// [`JobError::IoError`] on storage failures, or
    /// [`JobError::JobAlreadyComplete`] if `step()` is called after
    /// completion.
    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError>;

    /// Persist the checkpoint to stable storage.
    ///
    /// Called after every `step()` that produced a new checkpoint.
    /// Implementations write to the dataset-scoped checkpoint area.
    /// The write must be atomic within the current commit_group.
    ///
    /// Implementations may delegate to [`CheckpointCodec`] for the binary
    /// encoding, then handle the actual I/O.
    fn persist_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), JobError>;

    /// Finalize the completed job.
    ///
    /// Cleans up the job's persistent checkpoint, releases resources,
    /// and optionally emits a completion event.
    /// Called exactly once when [`StepResult::is_complete`] is true.
    ///
    /// After `complete()` returns, the job must not be used again.
    fn complete(self) -> Result<(), JobError>;

    /// Unique identifier for this job instance.
    ///
    /// Remains stable across daemon restarts and crash recovery.
    fn job_id(&self) -> JobId;

    /// Human-readable kind for admin display.
    ///
    /// Used by the background service framework for scheduling priority
    /// and admin-facing progress reporting.
    fn job_kind(&self) -> JobKind;
}

// ---------------------------------------------------------------------------
// CheckpointCodec — binary checkpoint serialization
// ---------------------------------------------------------------------------

/// Binary encoding/decoding contract for [`Checkpoint`] persistence.
///
/// Implementations provide a deterministic, byte-reproducible encoding
/// that enables golden-trace validation of checkpoint behavior across
/// runs. The default implementation uses a length-delimited binary
/// format.
///
/// Requires the `alloc` feature (enabled by default).
#[cfg(feature = "alloc")]
pub trait CheckpointCodec {
    /// Encode a [`Checkpoint`] to a byte vector.
    ///
    /// The encoding MUST be deterministic — the same checkpoint
    /// produces the same bytes every time.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::Other`] on encoding failure (e.g., cursor
    /// state too large).
    fn encode(checkpoint: &Checkpoint) -> Result<alloc::vec::Vec<u8>, JobError>;

    /// Decode a [`Checkpoint`] from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::CheckpointCorrupt`] if the magic bytes are
    /// wrong, the version is unsupported, or the payload is truncated.
    fn decode(data: &[u8]) -> Result<Checkpoint, JobError>;
}

// ---------------------------------------------------------------------------
// Binary checkpoint format
// ---------------------------------------------------------------------------

/// Magic bytes for the checkpoint binary format: `INCJCHKP`.
pub const CHECKPOINT_MAGIC: &[u8; 8] = b"INCJCHKP";

/// Current checkpoint binary format version.
pub const CHECKPOINT_VERSION: u32 = 1;

/// Header size in bytes: 8 (magic) + 4 (version) + 4 (payload_length) = 16.
pub const CHECKPOINT_HEADER_SIZE: usize = 16;

/// Maximum checkpoint payload size (1 MiB). Prevents runaway allocation
/// from corrupt data.
pub const CHECKPOINT_MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Parsed checkpoint binary header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointHeader {
    /// Monotonically increasing format version.
    pub version: u32,
    /// Length of the payload following the 16-byte header.
    pub payload_length: u32,
}

impl CheckpointHeader {
    /// Parse a header from the first 16 bytes of a checkpoint blob.
    ///
    /// Returns `None` if the magic bytes do not match.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < CHECKPOINT_HEADER_SIZE {
            return None;
        }
        if &data[..8] != CHECKPOINT_MAGIC {
            return None;
        }
        let version = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let payload_length = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        Some(CheckpointHeader {
            version,
            payload_length,
        })
    }

    /// Write this header into the first 16 bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() < 16`.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(buf.len() >= CHECKPOINT_HEADER_SIZE);
        buf[..8].copy_from_slice(CHECKPOINT_MAGIC);
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.payload_length.to_le_bytes());
    }

    /// Validate this header.
    ///
    /// Returns `Ok(())` if the version is supported and the payload
    /// length does not exceed the maximum.
    pub fn validate(&self) -> Result<(), CheckpointHeaderError> {
        if self.version != CHECKPOINT_VERSION {
            return Err(CheckpointHeaderError::UnsupportedVersion {
                found: self.version,
                expected: CHECKPOINT_VERSION,
            });
        }
        if self.payload_length as usize > CHECKPOINT_MAX_PAYLOAD_SIZE {
            return Err(CheckpointHeaderError::PayloadTooLarge {
                found: self.payload_length as usize,
                max: CHECKPOINT_MAX_PAYLOAD_SIZE,
            });
        }
        Ok(())
    }
}

/// Errors from checkpoint header validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointHeaderError {
    /// The version in the header is not supported by this codec.
    UnsupportedVersion { found: u32, expected: u32 },
    /// The payload length exceeds the maximum allowed size.
    PayloadTooLarge { found: usize, max: usize },
}

impl core::fmt::Display for CheckpointHeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CheckpointHeaderError::UnsupportedVersion { found, expected } => {
                write!(
                    f,
                    "unsupported checkpoint version {found} (expected {expected})"
                )
            }
            CheckpointHeaderError::PayloadTooLarge { found, max } => {
                write!(f, "checkpoint payload too large: {found} bytes (max {max})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JobKind discriminant helpers (used by DefaultCheckpointCodec)
// ---------------------------------------------------------------------------

/// Convert a [`JobKind`] to its u8 discriminant for binary serialization.
///
/// Known variants use discriminants 0–19. [`JobKind::Other(n)`] uses `n`
/// directly (caller must ensure `n` does not collide with 0–10).
fn job_kind_discriminant(kind: JobKind) -> u8 {
    match kind {
        JobKind::DeferredCleanup => 0,
        JobKind::SnapshotDestroy => 1,
        JobKind::GCMark => 2,
        JobKind::BtreeCompaction => 3,
        JobKind::Rebake => 4,
        JobKind::JournalCleaning => 5,
        JobKind::DatasetDestroy => 6,
        JobKind::Scrub => 7,
        JobKind::DeepScrub => 8,
        JobKind::Resilver => 9,
        JobKind::AdminJob => 10,
        JobKind::Reclaim => 11,
        JobKind::OrphanRecovery => 12,
        JobKind::DerivedCatalog => 13,
        JobKind::DataCleaner => 14,
        JobKind::Defrag => 15,
        JobKind::SegmentCleaner => 16,
        JobKind::SnapshotPruner => 17,
        JobKind::Recovery => 18,
        JobKind::Dedup => 19,
        JobKind::GeometryConvert => 20,
        JobKind::Rebuild => 21,
        JobKind::Backfill => 22,
        JobKind::Rebalance => 23,
        JobKind::Other(n) => n,
    }
}

/// Convert a u8 discriminant back to a [`JobKind`].
///
/// Returns `None` if the discriminant is not recognized. Discriminants
/// 0–10 map to known variants; values ≥ 128 are reserved for future use
/// and return `None`. Values 11–19 map to known variants; 20–127 map to [`JobKind::Other`].
fn job_kind_from_discriminant(disc: u8) -> Option<JobKind> {
    match disc {
        0 => Some(JobKind::DeferredCleanup),
        1 => Some(JobKind::SnapshotDestroy),
        2 => Some(JobKind::GCMark),
        3 => Some(JobKind::BtreeCompaction),
        4 => Some(JobKind::Rebake),
        5 => Some(JobKind::JournalCleaning),
        6 => Some(JobKind::DatasetDestroy),
        7 => Some(JobKind::Scrub),
        8 => Some(JobKind::DeepScrub),
        9 => Some(JobKind::Resilver),
        10 => Some(JobKind::AdminJob),
        11 => Some(JobKind::Reclaim),
        12 => Some(JobKind::OrphanRecovery),
        13 => Some(JobKind::DerivedCatalog),
        14 => Some(JobKind::DataCleaner),
        15 => Some(JobKind::Defrag),
        16 => Some(JobKind::SegmentCleaner),
        17 => Some(JobKind::SnapshotPruner),
        18 => Some(JobKind::Recovery),
        19 => Some(JobKind::Dedup),
        20 => Some(JobKind::GeometryConvert),
        21 => Some(JobKind::Rebuild),
        22 => Some(JobKind::Backfill),
        23 => Some(JobKind::Rebalance),
        24..=127 => Some(JobKind::Other(disc)),
        128..=255 => None, // reserved
    }
}

// ---------------------------------------------------------------------------
// JobKind discriminant helpers (used by DefaultCheckpointCodec)
// ---------------------------------------------------------------------------
/// # Wire format
///
/// ```text
///  0               8              12              16
/// ├───────────────┼──────────────┼──────────────┼─────────────────┐
/// │ magic (8B)    │ version (u32)│ payload_len   │ payload (N B)   │
/// │ INCJCHKP      │ LE           │ (u32 LE)      │                 │
/// └───────────────┴──────────────┴──────────────┴─────────────────┘
/// ```
///
/// The payload is a simple length-delimited encoding:
/// - `job_id` as u64 LE (8 bytes)
/// - `job_kind` discriminant as u8 (1 byte)
/// - `epoch` as u64 LE (8 bytes)
/// - `items_processed` as u64 LE (8 bytes)
/// - `items_total_estimate` as u64 LE (8 bytes)
/// - `bytes_processed` as u64 LE (8 bytes)
/// - `bytes_total_estimate` as u64 LE (8 bytes)
/// - `elapsed_ms` as u64 LE (8 bytes)
/// - `cursor_state_len` as u32 LE (4 bytes)
/// - `cursor_state` bytes (cursor_state_len bytes)
///
/// Total fixed overhead: 61 bytes + cursor state length.
#[cfg(feature = "alloc")]
pub struct DefaultCheckpointCodec;

#[cfg(feature = "alloc")]
impl CheckpointCodec for DefaultCheckpointCodec {
    fn encode(checkpoint: &Checkpoint) -> Result<alloc::vec::Vec<u8>, JobError> {
        let cursor_bytes = checkpoint.cursor_state.as_bytes();
        let cursor_len: u32 = cursor_bytes
            .len()
            .try_into()
            .map_err(|_| JobError::Other("cursor state too large for u32".into()))?;

        let payload_len: usize = 61usize
            .checked_add(cursor_bytes.len())
            .ok_or_else(|| JobError::Other("payload length overflow".into()))?;

        if payload_len > CHECKPOINT_MAX_PAYLOAD_SIZE {
            return Err(JobError::Other(
                "checkpoint payload exceeds max size".into(),
            ));
        }

        let total_len = CHECKPOINT_HEADER_SIZE + payload_len;
        let mut buf = alloc::vec::Vec::with_capacity(total_len);

        // Reserve header space
        buf.resize(CHECKPOINT_HEADER_SIZE, 0);

        // Payload: job_id (u64 LE)
        buf.extend_from_slice(&checkpoint.job_id.0.to_le_bytes());

        // job_kind discriminant (u8)
        buf.push(job_kind_discriminant(checkpoint.job_kind));

        // epoch (u64 LE)
        buf.extend_from_slice(&checkpoint.epoch.to_le_bytes());

        // progress counters
        buf.extend_from_slice(&checkpoint.progress.items_processed.to_le_bytes());
        buf.extend_from_slice(&checkpoint.progress.items_total_estimate.to_le_bytes());
        buf.extend_from_slice(&checkpoint.progress.bytes_processed.to_le_bytes());
        buf.extend_from_slice(&checkpoint.progress.bytes_total_estimate.to_le_bytes());
        buf.extend_from_slice(&checkpoint.progress.elapsed_ms.to_le_bytes());

        // cursor state
        buf.extend_from_slice(&cursor_len.to_le_bytes());
        buf.extend_from_slice(cursor_bytes);

        // Write header
        let header = CheckpointHeader {
            version: CHECKPOINT_VERSION,
            payload_length: payload_len as u32,
        };
        header.write_to(&mut buf[..CHECKPOINT_HEADER_SIZE]);

        Ok(buf)
    }

    fn decode(data: &[u8]) -> Result<Checkpoint, JobError> {
        let header = CheckpointHeader::parse(data).ok_or(JobError::CheckpointCorrupt {
            job_id: JobId::NONE,
            reason: "bad magic or truncated header",
        })?;

        header
            .validate()
            .map_err(|_e| JobError::CheckpointCorrupt {
                job_id: JobId::NONE,
                reason: "header validation failed",
            })?;

        let payload = data
            .get(CHECKPOINT_HEADER_SIZE..CHECKPOINT_HEADER_SIZE + header.payload_length as usize)
            .ok_or(JobError::CheckpointCorrupt {
                job_id: JobId::NONE,
                reason: "truncated payload",
            })?;

        if payload.len() < 61 {
            return Err(JobError::CheckpointCorrupt {
                job_id: JobId::NONE,
                reason: "payload too short",
            });
        }

        // job_id: u64 LE
        let job_id_raw = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        let job_id = JobId(job_id_raw);

        // job_kind discriminant
        let kind_disc = payload[8];
        let job_kind = job_kind_from_discriminant(kind_disc).ok_or({
            JobError::CheckpointCorrupt {
                job_id,
                reason: "unknown job_kind discriminant",
            }
        })?;

        // epoch: u64 LE
        let epoch = u64::from_le_bytes([
            payload[9],
            payload[10],
            payload[11],
            payload[12],
            payload[13],
            payload[14],
            payload[15],
            payload[16],
        ]);

        // progress counters
        let items_processed = u64::from_le_bytes([
            payload[17],
            payload[18],
            payload[19],
            payload[20],
            payload[21],
            payload[22],
            payload[23],
            payload[24],
        ]);
        let items_total_estimate = u64::from_le_bytes([
            payload[25],
            payload[26],
            payload[27],
            payload[28],
            payload[29],
            payload[30],
            payload[31],
            payload[32],
        ]);
        let bytes_processed = u64::from_le_bytes([
            payload[33],
            payload[34],
            payload[35],
            payload[36],
            payload[37],
            payload[38],
            payload[39],
            payload[40],
        ]);
        let bytes_total_estimate = u64::from_le_bytes([
            payload[41],
            payload[42],
            payload[43],
            payload[44],
            payload[45],
            payload[46],
            payload[47],
            payload[48],
        ]);
        let elapsed_ms = u64::from_le_bytes([
            payload[49],
            payload[50],
            payload[51],
            payload[52],
            payload[53],
            payload[54],
            payload[55],
            payload[56],
        ]);

        let progress = tidefs_types_incremental_job_core::JobProgress {
            items_processed,
            items_total_estimate,
            bytes_processed,
            bytes_total_estimate,
            elapsed_ms,
        };

        // cursor state length
        let cursor_len =
            u32::from_le_bytes([payload[57], payload[58], payload[59], payload[60]]) as usize;

        if payload.len() < 61 + cursor_len {
            return Err(JobError::CheckpointCorrupt {
                job_id,
                reason: "truncated cursor state",
            });
        }

        let cursor_bytes = payload[61..61 + cursor_len].to_vec();
        #[cfg(feature = "alloc")]
        {
            let cursor_state = tidefs_types_incremental_job_core::CursorState(cursor_bytes);
            Ok(Checkpoint {
                job_id,
                job_kind,
                epoch,
                cursor_state,
                progress,
            })
        }
        #[cfg(not(feature = "alloc"))]
        {
            let _ = cursor_bytes;
            unreachable!("decode requires alloc");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_incremental_job_core::{CursorState, JobProgress, StepResult};

    // ── CheckpointHeader ───────────────────────────────────────────────

    #[test]
    fn header_parse_valid() {
        let mut buf = [0u8; 16];
        let h = CheckpointHeader {
            version: 1,
            payload_length: 64,
        };
        h.write_to(&mut buf);
        let parsed = CheckpointHeader::parse(&buf).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.payload_length, 64);
    }

    #[test]
    fn header_parse_wrong_magic() {
        let mut buf = [0u8; 16];
        buf[0] = 0xFF;
        assert!(CheckpointHeader::parse(&buf).is_none());
    }

    #[test]
    fn header_parse_too_short() {
        let buf = [0u8; 8];
        assert!(CheckpointHeader::parse(&buf).is_none());
    }

    #[test]
    fn header_validate_ok() {
        let h = CheckpointHeader {
            version: 1,
            payload_length: 1024,
        };
        assert!(h.validate().is_ok());
    }

    #[test]
    fn header_validate_wrong_version() {
        let h = CheckpointHeader {
            version: 99,
            payload_length: 64,
        };
        let err = h.validate().unwrap_err();
        assert!(matches!(
            err,
            CheckpointHeaderError::UnsupportedVersion {
                found: 99,
                expected: 1
            }
        ));
    }

    #[test]
    fn header_validate_payload_too_large() {
        let h = CheckpointHeader {
            version: 1,
            payload_length: (CHECKPOINT_MAX_PAYLOAD_SIZE + 1) as u32,
        };
        let err = h.validate().unwrap_err();
        assert!(matches!(err, CheckpointHeaderError::PayloadTooLarge { .. }));
    }

    #[test]
    fn header_error_display() {
        let e = CheckpointHeaderError::UnsupportedVersion {
            found: 2,
            expected: 1,
        };
        let s = format!("{e}");
        assert!(s.contains("unsupported"));
        assert!(s.contains("2"));
        assert!(s.contains("1"));
    }

    // ── DefaultCheckpointCodec ─────────────────────────────────────────

    fn make_test_checkpoint(job_id: u64, kind: JobKind) -> Checkpoint {
        Checkpoint {
            job_id: JobId(job_id),
            job_kind: kind,
            epoch: 3,
            cursor_state: CursorState(vec![0xAB, 0xCD, 0xEF]),
            progress: JobProgress {
                items_processed: 500,
                items_total_estimate: 10000,
                bytes_processed: 2 * 1024 * 1024,
                bytes_total_estimate: 40 * 1024 * 1024,
                elapsed_ms: 1200,
            },
        }
    }

    #[test]
    fn codec_roundtrip_basic() {
        let ck = make_test_checkpoint(42, JobKind::Scrub);
        let encoded = DefaultCheckpointCodec::encode(&ck).unwrap();
        let decoded = DefaultCheckpointCodec::decode(&encoded).unwrap();
        assert_eq!(decoded.job_id, ck.job_id);
        assert_eq!(decoded.job_kind, ck.job_kind);
        assert_eq!(decoded.epoch, ck.epoch);
        assert_eq!(decoded.progress, ck.progress);
        assert_eq!(decoded.cursor_state, ck.cursor_state);
    }

    #[test]
    fn codec_roundtrip_empty_cursor() {
        let mut ck = make_test_checkpoint(1, JobKind::DeferredCleanup);
        ck.cursor_state = CursorState::empty();
        let encoded = DefaultCheckpointCodec::encode(&ck).unwrap();
        let decoded = DefaultCheckpointCodec::decode(&encoded).unwrap();
        assert_eq!(decoded.cursor_state, CursorState::empty());
        assert_eq!(decoded.job_id, ck.job_id);
    }

    #[test]
    fn codec_roundtrip_all_kinds() {
        let kinds = [
            JobKind::DeferredCleanup,
            JobKind::SnapshotDestroy,
            JobKind::GCMark,
            JobKind::BtreeCompaction,
            JobKind::Rebake,
            JobKind::JournalCleaning,
            JobKind::DatasetDestroy,
            JobKind::Scrub,
            JobKind::DeepScrub,
            JobKind::Resilver,
            JobKind::AdminJob,
            JobKind::Reclaim,
            JobKind::OrphanRecovery,
            JobKind::DerivedCatalog,
            JobKind::Other(42),
        ];
        for (i, &kind) in kinds.iter().enumerate() {
            let ck = make_test_checkpoint(i as u64, kind);
            let encoded = DefaultCheckpointCodec::encode(&ck).unwrap();
            let decoded = DefaultCheckpointCodec::decode(&encoded).unwrap();
            assert_eq!(decoded.job_kind, kind, "roundtrip failed for {kind:?}");
        }
    }

    #[test]
    fn codec_decode_bad_magic() {
        let buf = vec![0u8; 32];
        let err = DefaultCheckpointCodec::decode(&buf).unwrap_err();
        assert!(matches!(err, JobError::CheckpointCorrupt { .. }));
    }

    #[test]
    fn codec_decode_truncated() {
        let mut buf = [0u8; 16];
        let h = CheckpointHeader {
            version: 1,
            payload_length: 1024,
        };
        h.write_to(&mut buf);
        let err = DefaultCheckpointCodec::decode(&buf).unwrap_err();
        assert!(matches!(err, JobError::CheckpointCorrupt { .. }));
    }

    #[test]
    fn codec_encode_deterministic() {
        let ck = make_test_checkpoint(7, JobKind::BtreeCompaction);
        let e1 = DefaultCheckpointCodec::encode(&ck).unwrap();
        let e2 = DefaultCheckpointCodec::encode(&ck).unwrap();
        assert_eq!(e1, e2, "encoding must be deterministic");
    }

    #[test]
    fn codec_large_cursor_state() {
        let mut ck = make_test_checkpoint(1, JobKind::GCMark);
        ck.cursor_state = CursorState(vec![0x42u8; 65536]);
        let encoded = DefaultCheckpointCodec::encode(&ck).unwrap();
        let decoded = DefaultCheckpointCodec::decode(&encoded).unwrap();
        assert_eq!(decoded.cursor_state.len(), 65536);
    }

    // ── Mock IncrementalJob implementation for testing ────────────────

    /// A simple counting job that increments an internal counter each step.
    /// Used to verify trait object safety and lifecycle correctness.
    struct CountingJob {
        job_id: JobId,
        job_kind: JobKind,
        counter: u64,
        target: u64,
        items_per_step: u64,
    }

    impl CountingJob {
        fn new_resume(
            state: Option<Checkpoint>,
            target: u64,
            items_per_step: u64,
        ) -> Result<Self, JobError> {
            let (job_id, job_kind, counter) = if let Some(cp) = state {
                // Resume from checkpoint: extract counter from cursor state
                if cp.cursor_state.len() >= 8 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&cp.cursor_state.as_bytes()[..8]);
                    (cp.job_id, cp.job_kind, u64::from_le_bytes(bytes))
                } else {
                    (cp.job_id, cp.job_kind, 0)
                }
            } else {
                // Fresh start
                (JobId(1), JobKind::AdminJob, 0)
            };
            Ok(CountingJob {
                job_id,
                job_kind,
                counter,
                target,
                items_per_step,
            })
        }
    }

    #[cfg(feature = "alloc")]
    impl IncrementalJob for CountingJob {
        fn resume(state: Option<Checkpoint>) -> Result<Self, JobError>
        where
            Self: Sized,
        {
            Self::new_resume(state, 100, 10)
        }

        fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
            if self.counter >= self.target {
                return Err(JobError::JobAlreadyComplete {
                    job_id: self.job_id,
                });
            }

            let max_items = if budget.max_items > 0 {
                budget.max_items.min(self.items_per_step)
            } else {
                self.items_per_step
            };

            let remaining = self.target - self.counter;
            let processed = max_items.min(remaining);
            self.counter += processed;

            let is_complete = self.counter >= self.target;

            // Encode counter into cursor state
            let cursor_bytes = self.counter.to_le_bytes().to_vec();
            let cursor_state = CursorState(cursor_bytes);

            let progress = JobProgress {
                items_processed: self.counter,
                items_total_estimate: self.target,
                ..Default::default()
            };

            let checkpoint = Checkpoint {
                job_id: self.job_id,
                job_kind: self.job_kind,
                epoch: 1,
                cursor_state,
                progress,
            };

            if is_complete {
                Ok(StepResult::complete(checkpoint))
            } else {
                Ok(StepResult::in_progress(checkpoint))
            }
        }

        fn persist_checkpoint(&self, _checkpoint: &Checkpoint) -> Result<(), JobError> {
            // No-op for the mock: just acknowledge persistence
            Ok(())
        }

        fn complete(self) -> Result<(), JobError> {
            assert!(
                self.counter >= self.target,
                "complete called before job finished"
            );
            Ok(())
        }

        fn job_id(&self) -> JobId {
            self.job_id
        }

        fn job_kind(&self) -> JobKind {
            self.job_kind
        }
    }

    #[test]
    fn counting_job_full_lifecycle() {
        let mut job = CountingJob::resume(None).unwrap();
        assert_eq!(job.job_id(), JobId(1));
        assert_eq!(job.job_kind(), JobKind::AdminJob);

        // Run steps until complete
        let mut steps = 0u32;
        loop {
            let result = job.step(WorkBudget::DEFAULT_TICK).unwrap();
            job.persist_checkpoint(&result.checkpoint).unwrap();
            steps += 1;
            if result.is_complete {
                job.complete().unwrap();
                break;
            }
        }

        // 100 items at 10 per step = 10 steps
        assert_eq!(steps, 10);
    }

    #[test]
    fn counting_job_resume_from_checkpoint() {
        // First run: do 5 steps then capture checkpoint
        let mut job = CountingJob::resume(None).unwrap();
        let mut last_checkpoint = None;
        for _ in 0..5 {
            let result = job.step(WorkBudget::DEFAULT_TICK).unwrap();
            last_checkpoint = Some(result.checkpoint.clone());
            if result.is_complete {
                break;
            }
        }

        // Resume from checkpoint
        let mut resumed = CountingJob::resume(last_checkpoint).unwrap();
        assert_eq!(resumed.job_id(), JobId(1));
        assert_eq!(resumed.job_kind(), JobKind::AdminJob);

        // Complete remaining steps
        loop {
            let result = resumed.step(WorkBudget::DEFAULT_TICK).unwrap();
            if result.is_complete {
                resumed.complete().unwrap();
                break;
            }
        }
    }

    #[test]
    fn counting_job_budget_respected() {
        let mut job = CountingJob::resume(None).unwrap();
        let tight_budget = WorkBudget {
            max_items: 3,
            ..WorkBudget::default()
        };
        let result = job.step(tight_budget).unwrap();
        // Should process at most 3 items
        let counter = u64::from_le_bytes(
            result.checkpoint.cursor_state.as_bytes()[..8]
                .try_into()
                .unwrap(),
        );
        assert!(counter <= 3);
    }

    #[test]
    fn counting_job_step_after_complete_errors() {
        let mut job = CountingJob::resume(None).unwrap();
        // Run to completion
        loop {
            let result = job.step(WorkBudget::DEFAULT_TICK).unwrap();
            if result.is_complete {
                break;
            }
        }
        // Step after complete should error
        let err = job.step(WorkBudget::DEFAULT_TICK).unwrap_err();
        assert!(matches!(err, JobError::JobAlreadyComplete { .. }));
    }

    // ── Thread safety compilation check ────────────────────────────────

    /// Compile-time verification that `IncrementalJob` is `Send`.
    #[test]
    fn trait_is_send() {
        fn assert_send<T: Send>() {}
        // CountingJob implements IncrementalJob (Send bound)
        // If it compiles, the trait enforces Send.
        assert_send::<CountingJob>();
    }

    // ── Trait object compilation check ─────────────────────────────────

    /// Verify the trait can be used as a trait object.
    #[test]
    fn trait_object_dispatch() {
        let mut job = CountingJob::resume(None).unwrap();
        let dyn_job: &mut dyn IncrementalJob = &mut job;
        assert_eq!(dyn_job.job_id(), JobId(1));
        assert_eq!(dyn_job.job_kind(), JobKind::AdminJob);
        let result = dyn_job.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert!(!result.is_complete);
    }

    // ── Push constants ─────────────────────────────────────────────────

    #[test]
    fn checkpoint_magic_is_eight_bytes() {
        assert_eq!(CHECKPOINT_MAGIC.len(), 8);
    }

    #[test]
    fn checkpoint_header_size_is_sixteen() {
        assert_eq!(CHECKPOINT_HEADER_SIZE, 16);
    }
}
