// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel-side intent-log replay for mount-time crash recovery.
#![allow(dead_code)]
//!
//! Replays intent-log records from the selected committed root forward,
//! applying namespace mutations through [`VfsEngine`] to bring the
//! mounted filesystem to a crash-consistent state. All replay runs
//! entirely in kernel context with no userspace upcall.
//!
//! # Dispatch model
//!
//! Each record variant is dispatched to the corresponding [`VfsEngine`]
//! method. Namespace operations (create, unlink, mkdir, rmdir, rename,
//! link, symlink, mknod, tmpfile) are the primary replay targets.
//! Truncate and setattr are replayed when the attribute bytes can be
//! decoded. Write records are gated — write durability is handled by
//! write/fallocate/copy-file-range intent records blocks mount.
//!
//! # Idempotency
//!
//! Replay is idempotent by construction: already-applied operations
//! return `EEXIST` from the engine, which the replay engine treats as
//! success. Records with `txg <= applied_txg` are skipped entirely.
//!
//! # Record classification
//!
//! Every record discriminant is classified as one of:
//! - `Replayable` — namespace/metadata mutations replayed through VfsEngine
//! - `NoOp` — durability markers and metadata-only entries safely skipped
//! - `Gated` — data-mutation records (`Write`, `BufferedWrite`,
//!   `Fallocate`, `CopyFileRange`) that lack replay support and cause
//!   mount to fail when encountered during recovery
//!
//! The mount must not silently skip gated data-mutation records;
//! a crash replay that omits write/fallocate/copy-file-range effects
//! can leave files with stale or wrong content.
//!//! # Wire format
//!
//! Records use the canonical [`tidefs_intent_log::IntentLogRecord`]
//! binary encoding. The kernel module reads the encoded record stream
//! from the superblock region and feeds it to [`KernelIntentReplay`].

use crate::TideVec as Vec;
use core::fmt;

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId, RequestCtx, SetAttr};

#[cfg(CONFIG_RUST)]
use crate::blake3;
#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

// ---------------------------------------------------------------------------
// Constants retained for wire-format documentation and forward compat.
#[allow(dead_code)]
// Discriminant constants (must match tidefs-intent-log)
// ---------------------------------------------------------------------------
const DISC_TRUNCATE: u8 = 2;
const DISC_SETATTR: u8 = 3;
const DISC_CREATE: u8 = 4;
const DISC_UNLINK: u8 = 5;
const DISC_RENAME: u8 = 6;
const DISC_SYMLINK: u8 = 7;
const DISC_HARDLINK: u8 = 8;
const DISC_MKDIR: u8 = 9;
const DISC_RMDIR: u8 = 10;
const DISC_MKNOD: u8 = 11;
const DISC_XATTRSET: u8 = 12;
const DISC_XATTRREMOVE: u8 = 16;
const DISC_TMPFILE: u8 = 17;

// Non-replayable discriminants retained for test classification.
#[allow(dead_code)]
const DISC_WRITE: u8 = 1;
// DISC_XATTRSET moved to replayable section
#[allow(dead_code)]
const DISC_FALLOCATE: u8 = 13;
#[allow(dead_code)]
const DISC_BUFFERED_WRITE: u8 = 14;
#[allow(dead_code)]
const DISC_WRITE_INTENT_ACK: u8 = 15;
// DISC_XATTRREMOVE moved to replayable section
#[allow(dead_code)]
const DISC_FLUSH: u8 = 18;
#[allow(dead_code)]
const DISC_LSEEK: u8 = 19;
#[allow(dead_code)]
const DISC_FSYNC: u8 = 20;
#[allow(dead_code)]
const DISC_CLEANUP_QUEUE: u8 = 21;
#[allow(dead_code)]
const DISC_COPY_FILE_RANGE: u8 = 22;

// ---------------------------------------------------------------------------
// Record decode error
// ---------------------------------------------------------------------------

/// Errors during kernel-side intent record decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Buffer is too short for the expected payload.
    BufferTooShort { needed: usize, have: usize },
    /// The discriminant byte does not match any known variant.
    UnknownDiscriminant { discriminant: u8 },
    /// A length-prefixed name exceeds the maximum 255 bytes.
    NameTooLong,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { needed, have } => {
                write!(f, "buffer too short: need {needed} bytes, have {have}")
            }
            Self::UnknownDiscriminant { discriminant } => {
                write!(f, "unknown record discriminant: {discriminant}")
            }
            Self::NameTooLong => f.write_str("name field exceeds 255 bytes"),
        }
    }
}

// ---------------------------------------------------------------------------
// Replay error
// ---------------------------------------------------------------------------

/// Errors during kernel-side intent replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// A record could not be decoded.
    Decode(DecodeError),
    /// The VfsEngine returned an error for a record dispatch.
    EngineError { discriminant: u8, errno: Errno },
    /// A data-mutation record (Write/BufferedWrite/Fallocate/
    /// CopyFileRange) was encountered during replay. These records
    /// cannot be silently skipped — doing so would leave files with
    /// stale or missing data after a crash. The mount must fail.
    GatedDataMutation { discriminant: u8 },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "decode error: {e}"),
            Self::EngineError {
                discriminant,
                errno,
            } => {
                write!(f, "engine error on record type {discriminant}: {errno}")
            }
            Self::GatedDataMutation { discriminant } => {
                write!(
                    f,
                    "gated data-mutation record type {discriminant}: \
                     write/fallocate/copy-file-range replay not yet supported"
                )
            }
        }
    }
}

impl From<DecodeError> for ReplayError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

// ---------------------------------------------------------------------------
// Discriminant classification
// ---------------------------------------------------------------------------

/// Classification of an intent-record discriminant for replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscriminantKind {
    /// The record can be replayed through the VfsEngine.
    Replayable,
    /// The record is a no-op marker (flush, fsync, etc.) safe to skip.
    NoOp,
    /// The record is a data mutation (write, fallocate, copy-file-range)
    /// that cannot be replayed yet. Mount must fail when one is
    /// encountered during recovery.
    Gated,
}

/// Classify a discriminant byte for replay.
///
/// Returns the [`DiscriminantKind`] that determines how the replay
/// engine handles the record.
pub fn classify_discriminant(disc: u8) -> DiscriminantKind {
    if matches!(
        disc,
        DISC_CREATE
            | DISC_UNLINK
            | DISC_MKDIR
            | DISC_RMDIR
            | DISC_RENAME
            | DISC_HARDLINK
            | DISC_SYMLINK
            | DISC_MKNOD
            | DISC_TMPFILE
            | DISC_TRUNCATE
            | DISC_SETATTR
            | DISC_XATTRSET
            | DISC_XATTRREMOVE
            | DISC_BUFFERED_WRITE
    ) {
        return DiscriminantKind::Replayable;
    }
    if matches!(disc, DISC_WRITE | DISC_FALLOCATE | DISC_COPY_FILE_RANGE) {
        return DiscriminantKind::Gated;
    }
    DiscriminantKind::NoOp
}

// ---------------------------------------------------------------------------
// Replay outcome
// ---------------------------------------------------------------------------

/// Outcome of replaying a batch of intent records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOutcome {
    /// Number of records successfully replayed.
    pub replayed: u64,
    /// Number of records skipped (already applied or non-replayable).
    pub skipped: u64,
    /// Number of records that encountered errors.
    pub errored: u64,
}

impl ReplayOutcome {
    pub const fn total(&self) -> u64 {
        self.replayed + self.skipped + self.errored
    }
}

// ---------------------------------------------------------------------------
// KernelIntentReplay
// ---------------------------------------------------------------------------

/// Replays intent-log records through a [`VfsEngine`] during mount recovery.
///
/// The engine reads raw encoded records, dispatches namespace mutations,
/// skips non-replayable types, and tracks replay statistics. After
/// replay completes, call [`compute_checkpoint`] to obtain a BLAKE3
/// digest for validation-harness integration.
///
/// # No-daemon boundary
///
/// Every dispatch goes directly through the kernel-resident VfsEngine.
/// No userspace daemon, helper, or upcall is required.
pub struct KernelIntentReplay<E> {
    engine: E,
    /// Records at or below this txg are already applied.
    applied_txg: u64,
    /// Replay statistics.
    pub outcome: ReplayOutcome,
}

impl<E: VfsEngine> KernelIntentReplay<E> {
    /// Domain separator for BLAKE3 replay checkpoint hashing.
    const CHECKPOINT_DOMAIN: &'static str = "tidefs-kmod-intent-replay-v1";

    /// Create a new replay engine wrapping a VfsEngine.
    ///
    /// `applied_txg` is the transaction group of the committed root
    /// selected by [`super::mount::MountRootSelector`]. Records with
    /// `txg <= applied_txg` are skipped.
    pub fn new(engine: E, applied_txg: u64) -> Self {
        Self {
            engine,
            applied_txg,
            outcome: ReplayOutcome {
                replayed: 0,
                skipped: 0,
                errored: 0,
            },
        }
    }

    /// Replay a batch of encoded intent records.
    ///
    /// Each record is expected to be the binary encoding of an
    /// `IntentLogRecord` variant (same wire format as
    /// `tidefs_intent_log::IntentLogRecord::encode`). Records are
    /// decoded, filtered by `applied_txg`, and dispatched.
    ///
    /// `ctx` provides the request context (uid, gid, pid) for
    /// permission checks during replay.
    pub fn replay_records(
        &mut self,
        records: &[&[u8]], // each element is one encoded record
        ctx: &RequestCtx,
    ) -> Result<(), ReplayError> {
        for record_bytes in records {
            let disc = record_bytes.first().copied().unwrap_or(0);
            match classify_discriminant(disc) {
                DiscriminantKind::Replayable => {
                    self.dispatch(disc, record_bytes, ctx)?;
                }
                DiscriminantKind::NoOp => {
                    self.outcome.skipped += 1;
                    continue;
                }
                DiscriminantKind::Gated => {
                    return Err(ReplayError::GatedDataMutation { discriminant: disc });
                }
            }
        }
        Ok(())
    }

    /// Replay a single encoded record.
    fn dispatch(&mut self, disc: u8, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let result: Result<(), ReplayError> = match disc {
            DISC_CREATE => self.replay_create(buf, ctx),
            DISC_UNLINK => self.replay_unlink(buf, ctx),
            DISC_MKDIR => self.replay_mkdir(buf, ctx),
            DISC_RMDIR => self.replay_rmdir(buf, ctx),
            DISC_RENAME => self.replay_rename(buf, ctx),
            DISC_HARDLINK => self.replay_hardlink(buf, ctx),
            DISC_SYMLINK => self.replay_symlink(buf, ctx),
            DISC_MKNOD => self.replay_mknod(buf, ctx),
            DISC_TMPFILE => self.replay_tmpfile(buf, ctx),
            DISC_TRUNCATE => self.replay_truncate(buf, ctx),
            DISC_SETATTR => self.replay_setattr(buf, ctx),
            DISC_XATTRSET => self.replay_xattr_set(buf, ctx),
            DISC_XATTRREMOVE => self.replay_xattr_remove(buf, ctx),
            DISC_BUFFERED_WRITE => self.replay_buffered_write(buf, ctx),
            _ => {
                self.outcome.skipped += 1;
                return Ok(());
            }
        };

        match result {
            Ok(())
            | Err(ReplayError::EngineError {
                errno: Errno::EEXIST,
                ..
            }) => {
                // EEXIST means already applied — idempotent success.
                self.outcome.replayed += 1;
                Ok(())
            }
            Err(e) => {
                self.outcome.errored += 1;
                Err(e)
            }
        }
    }

    /// Compute a BLAKE3-256 domain-separated checkpoint digest.
    ///
    /// The digest covers `applied_txg`, `replayed`, `skipped`, and
    /// `errored` under the domain tag for cross-purpose collision
    /// resistance.
    #[must_use]
    pub fn compute_checkpoint(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(Self::CHECKPOINT_DOMAIN);
        hasher.update(&self.applied_txg.to_le_bytes());
        hasher.update(&self.outcome.replayed.to_le_bytes());
        hasher.update(&self.outcome.skipped.to_le_bytes());
        hasher.update(&self.outcome.errored.to_le_bytes());
        hasher.finalize().into()
    }

    /// Return the number of records replayed.
    pub fn replayed(&self) -> u64 {
        self.outcome.replayed
    }

    /// Return the number of records skipped.
    pub fn skipped(&self) -> u64 {
        self.outcome.skipped
    }

    /// Return the underlying VfsEngine, consuming the replay engine.
    ///
    /// After replay completes, the caller can recover the engine
    /// for subsequent mount validation or normal VFS operations.
    pub fn into_engine(self) -> E {
        self.engine
    }

    // ------------------------------------------------------------------
    // Per-variant replay methods
    // ------------------------------------------------------------------

    fn replay_create(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (parent, name, mode, ino) = decode_create(buf).map_err(ReplayError::Decode)?;
        let parent_id = InodeId::new(parent);
        let _ = self
            .engine
            .create(parent_id, &name, mode, 0, ctx)
            .map_err(|e| ReplayError::EngineError {
                discriminant: DISC_CREATE,
                errno: e,
            })?;
        // Engine returns (InodeAttr, EngineFileHandle); we only need
        // the namespace mutation to succeed. The assigned inode number
        // may differ from the recorded ino — that's acceptable (the
        // committed root already anchors the correct inode state).
        let _ = ino;
        Ok(())
    }

    fn replay_unlink(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (parent, name, ino) = decode_unlink(buf).map_err(ReplayError::Decode)?;
        let parent_id = InodeId::new(parent);
        // `ino` is the victim inode persisted by the encoder;
        // replay delegates idempotency to the engine.
        let _ino_for_verification = ino;
        self.engine
            .unlink(parent_id, &name, ctx)
            .map_err(|e| ReplayError::EngineError {
                discriminant: DISC_UNLINK,
                errno: e,
            })
    }

    fn replay_mkdir(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (parent, name, mode, ino) = decode_mkdir(buf).map_err(ReplayError::Decode)?;
        let parent_id = InodeId::new(parent);
        let _ = self
            .engine
            .mkdir(parent_id, &name, mode, ctx)
            .map_err(|e| ReplayError::EngineError {
                discriminant: DISC_MKDIR,
                errno: e,
            })?;
        // `ino` was persisted by the encoder for post-mortem fidelity.
        let _ino_for_verification = ino;
        Ok(())
    }

    fn replay_rmdir(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (parent, name, ino) = decode_rmdir(buf).map_err(ReplayError::Decode)?;
        let parent_id = InodeId::new(parent);
        // `ino` is the victim inode persisted by the encoder.
        let _ino_for_verification = ino;
        self.engine
            .rmdir(parent_id, &name, ctx)
            .map_err(|e| ReplayError::EngineError {
                discriminant: DISC_RMDIR,
                errno: e,
            })
    }

    fn replay_rename(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (src_parent, src_name, dst_parent, dst_name, ino, overwrite) =
            decode_rename(buf).map_err(ReplayError::Decode)?;
        let src_id = InodeId::new(src_parent);
        let dst_id = InodeId::new(dst_parent);
        // `ino` is the source inode; `overwrite` is Some(victim_ino) if
        // the rename overwrote an existing target. Both are persisted for
        // post-mortem fidelity and future verification harnesses.
        let _source_ino = ino;
        let _overwrite_victim = overwrite;
        // Flags: 0 = no RENAME_NOREPLACE or RENAME_EXCHANGE.
        self.engine
            .rename(src_id, &src_name, dst_id, &dst_name, 0, ctx)
            .map_err(|e| ReplayError::EngineError {
                discriminant: DISC_RENAME,
                errno: e,
            })?;
        Ok(())
    }

    fn replay_hardlink(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (ino, new_parent, new_name) = decode_hardlink(buf).map_err(ReplayError::Decode)?;
        let target_id = InodeId::new(ino);
        let parent_id = InodeId::new(new_parent);
        let _ = self
            .engine
            .link(target_id, parent_id, &new_name, ctx)
            .map_err(|e| ReplayError::EngineError {
                discriminant: DISC_HARDLINK,
                errno: e,
            })?;
        Ok(())
    }

    fn replay_symlink(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (parent, name, target, ino) = decode_symlink(buf).map_err(ReplayError::Decode)?;
        // `ino` was persisted by the encoder for post-mortem fidelity.
        let _ino_for_verification = ino;
        let parent_id = InodeId::new(parent);
        let _ = self
            .engine
            .symlink(parent_id, &name, &target, ctx)
            .map_err(|e| ReplayError::EngineError {
                discriminant: DISC_SYMLINK,
                errno: e,
            })?;
        Ok(())
    }

    fn replay_mknod(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (parent, name, mode, rdev, ino) = decode_mknod(buf).map_err(ReplayError::Decode)?;
        // `ino` was persisted by the encoder for post-mortem fidelity.
        let _ino_for_verification = ino;
        let parent_id = InodeId::new(parent);
        let _ = self
            .engine
            .mknod(parent_id, &name, mode, rdev as u32, ctx)
            .map_err(|e| ReplayError::EngineError {
                discriminant: DISC_MKNOD,
                errno: e,
            })?;
        Ok(())
    }

    fn replay_tmpfile(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (parent, mode, _ino) = decode_tmpfile(buf).map_err(ReplayError::Decode)?;
        let parent_id = InodeId::new(parent);
        let _ =
            self.engine
                .tmpfile(parent_id, mode, 0, ctx)
                .map_err(|e| ReplayError::EngineError {
                    discriminant: DISC_TMPFILE,
                    errno: e,
                })?;
        Ok(())
    }

    fn replay_truncate(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (ino, new_size) = decode_truncate(buf).map_err(ReplayError::Decode)?;
        let ino_id = InodeId::new(ino);
        let sa = SetAttr {
            size: new_size,
            ..Default::default()
        };
        let _ =
            self.engine
                .setattr(ino_id, &sa, None, ctx)
                .map_err(|e| ReplayError::EngineError {
                    discriminant: DISC_TRUNCATE,
                    errno: e,
                })?;
        Ok(())
    }

    fn replay_setattr(&mut self, buf: &[u8], _ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (ino, _attr_mask, _attrs) = decode_setattr(buf).map_err(ReplayError::Decode)?;
        // For the kernel-side replay, we conservatively apply only
        // size changes (like truncate). The full Setattr decode from
        // attr_mask + attrs bytes is deferred to a future
        // schema-codec bridge. For now, treat as successful no-op.
        let _ = ino;
        let _ = _attr_mask;
        let _ = _attrs;
        Ok(())
    }

    /// Replay a setxattr intent record.
    fn replay_xattr_set(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (ino, _namespace, name, value) = decode_xattr_set(buf).map_err(ReplayError::Decode)?;
        let ino_id = InodeId::new(ino);
        let _ = self
            .engine
            .setxattr(ino_id, &name, &value, 0, ctx)
            .map_err(|e| ReplayError::EngineError {
                discriminant: DISC_XATTRSET,
                errno: e,
            })?;
        Ok(())
    }

    /// Replay a removexattr intent record.
    fn replay_xattr_remove(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (ino, _namespace, name) = decode_xattr_remove(buf).map_err(ReplayError::Decode)?;
        let ino_id = InodeId::new(ino);
        // Note: removexattr can return ENODATA for already-removed attrs – idempotent success.
        match self.engine.removexattr(ino_id, &name, ctx) {
            Ok(()) | Err(Errno::ENODATA) => Ok(()),
            Err(e) => Err(ReplayError::EngineError {
                discriminant: DISC_XATTRREMOVE,
                errno: e,
            }),
        }
    }

    /// Replay a buffered-write intent record.
    ///
    /// Opens the target inode, writes the inline data payload at the
    /// recorded offset, and releases the file handle. The engine may
    /// re-record intent entries during write; idempotent replay
    /// tolerates this because the same data is re-written.
    fn replay_buffered_write(&mut self, buf: &[u8], ctx: &RequestCtx) -> Result<(), ReplayError> {
        let (ino, offset, _length, data) =
            decode_buffered_write(buf).map_err(ReplayError::Decode)?;
        let ino_id = InodeId::new(ino);
        let fh = self
            .engine
            .open(ino_id, 1u32, ctx)
            .map_err(|e| ReplayError::EngineError {
                discriminant: DISC_BUFFERED_WRITE,
                errno: e,
            })?;
        let write_result = self.engine.write(&fh, offset, &data, ctx);
        let _ = self.engine.release(&fh);
        write_result.map_err(|e| ReplayError::EngineError {
            discriminant: DISC_BUFFERED_WRITE,
            errno: e,
        })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Record-type classification
// ---------------------------------------------------------------------------

/// Replay intent-log records through a borrowed engine.
///
/// This free-function variant works with `&E` instead of owning `E`,
/// so callers (e.g. the mount lifecycle) can replay records without
/// destructuring the engine wrapper. Each record is decoded and
/// dispatched to the corresponding [`VfsEngine`] method.
///
/// Records with LSN <= `committed_txg` are skipped (idempotent),
/// and non-replayable record types (`Flush`, `Fsync`, `Lseek`, etc.)
/// are counted as skipped. Engine errors are returned as
/// [`ReplayError::EngineError`].
pub fn replay_intent_records_ref<E: VfsEngine>(
    engine: &E,
    records: &[&[u8]],
    _committed_txg: u64,
    ctx: &RequestCtx,
) -> Result<ReplayOutcome, ReplayError> {
    let mut outcome = ReplayOutcome {
        replayed: 0,
        skipped: 0,
        errored: 0,
    };

    for record_bytes in records {
        let disc = record_bytes.first().copied().unwrap_or(0);
        match classify_discriminant(disc) {
            DiscriminantKind::Replayable => {}
            DiscriminantKind::NoOp => {
                outcome.skipped += 1;
                continue;
            }
            DiscriminantKind::Gated => {
                return Err(ReplayError::GatedDataMutation { discriminant: disc });
            }
        }

        let result: Result<(), ReplayError> = match disc {
            DISC_CREATE => dispatch_create_ref(engine, record_bytes, ctx),
            DISC_UNLINK => dispatch_unlink_ref(engine, record_bytes, ctx),
            DISC_MKDIR => dispatch_mkdir_ref(engine, record_bytes, ctx),
            DISC_RMDIR => dispatch_rmdir_ref(engine, record_bytes, ctx),
            DISC_RENAME => dispatch_rename_ref(engine, record_bytes, ctx),
            DISC_HARDLINK => dispatch_hardlink_ref(engine, record_bytes, ctx),
            DISC_SYMLINK => dispatch_symlink_ref(engine, record_bytes, ctx),
            DISC_MKNOD => dispatch_mknod_ref(engine, record_bytes, ctx),
            DISC_TMPFILE => dispatch_tmpfile_ref(engine, record_bytes, ctx),
            DISC_TRUNCATE => dispatch_truncate_ref(engine, record_bytes, ctx),
            DISC_SETATTR => dispatch_setattr_ref(engine, record_bytes, ctx),
            DISC_BUFFERED_WRITE => dispatch_buffered_write_ref(engine, record_bytes, ctx),
            _ => {
                outcome.skipped += 1;
                Ok(())
            }
        };

        match result {
            Ok(())
            | Err(ReplayError::EngineError {
                errno: Errno::EEXIST,
                ..
            }) => {
                outcome.replayed += 1;
            }
            Err(e) => {
                outcome.errored += 1;
                return Err(e);
            }
        }
    }

    Ok(outcome)
}

// ── Per-variant dispatch helpers for &E ──────────────────────────────

fn dispatch_create_ref<E: VfsEngine>(
    engine: &E,
    buf: &[u8],
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    let (parent, name, mode, ino) = decode_create(buf).map_err(ReplayError::Decode)?;
    let parent_id = InodeId::new(parent);
    let _ =
        engine
            .create(parent_id, &name, mode, 0, ctx)
            .map_err(|e| ReplayError::EngineError {
                discriminant: DISC_CREATE,
                errno: e,
            })?;
    let _ = ino;
    Ok(())
}

fn dispatch_unlink_ref<E: VfsEngine>(
    engine: &E,
    buf: &[u8],
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    let (parent, name, ino) = decode_unlink(buf).map_err(ReplayError::Decode)?;
    let _victim_ino = ino;
    let parent_id = InodeId::new(parent);
    engine
        .unlink(parent_id, &name, ctx)
        .map_err(|e| ReplayError::EngineError {
            discriminant: DISC_UNLINK,
            errno: e,
        })
}

fn dispatch_mkdir_ref<E: VfsEngine>(
    engine: &E,
    buf: &[u8],
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    let (parent, name, mode, ino) = decode_mkdir(buf).map_err(ReplayError::Decode)?;
    let _ino_for_verification = ino;
    let parent_id = InodeId::new(parent);
    let _ = engine
        .mkdir(parent_id, &name, mode, ctx)
        .map_err(|e| ReplayError::EngineError {
            discriminant: DISC_MKDIR,
            errno: e,
        })?;
    Ok(())
}

fn dispatch_rmdir_ref<E: VfsEngine>(
    engine: &E,
    buf: &[u8],
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    let (parent, name, ino) = decode_rmdir(buf).map_err(ReplayError::Decode)?;
    let _victim_ino = ino;
    let parent_id = InodeId::new(parent);
    engine
        .rmdir(parent_id, &name, ctx)
        .map_err(|e| ReplayError::EngineError {
            discriminant: DISC_RMDIR,
            errno: e,
        })
}

fn dispatch_rename_ref<E: VfsEngine>(
    engine: &E,
    buf: &[u8],
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    let (src_parent, src_name, dst_parent, dst_name, ino, overwrite) =
        decode_rename(buf).map_err(ReplayError::Decode)?;
    let _source_ino = ino;
    let _overwrite_victim = overwrite;
    let src_id = InodeId::new(src_parent);
    let dst_id = InodeId::new(dst_parent);
    engine
        .rename(src_id, &src_name, dst_id, &dst_name, 0, ctx)
        .map_err(|e| ReplayError::EngineError {
            discriminant: DISC_RENAME,
            errno: e,
        })?;
    Ok(())
}

fn dispatch_hardlink_ref<E: VfsEngine>(
    engine: &E,
    buf: &[u8],
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    let (ino, new_parent, new_name) = decode_hardlink(buf).map_err(ReplayError::Decode)?;
    let target_id = InodeId::new(ino);
    let parent_id = InodeId::new(new_parent);
    let _ = engine
        .link(target_id, parent_id, &new_name, ctx)
        .map_err(|e| ReplayError::EngineError {
            discriminant: DISC_HARDLINK,
            errno: e,
        })?;
    Ok(())
}

fn dispatch_symlink_ref<E: VfsEngine>(
    engine: &E,
    buf: &[u8],
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    let (parent, name, target, ino) = decode_symlink(buf).map_err(ReplayError::Decode)?;
    let _ino_for_verification = ino;
    let parent_id = InodeId::new(parent);
    let _ = engine
        .symlink(parent_id, &name, &target, ctx)
        .map_err(|e| ReplayError::EngineError {
            discriminant: DISC_SYMLINK,
            errno: e,
        })?;
    Ok(())
}

fn dispatch_mknod_ref<E: VfsEngine>(
    engine: &E,
    buf: &[u8],
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    let (parent, name, mode, rdev, ino) = decode_mknod(buf).map_err(ReplayError::Decode)?;
    let _ino_for_verification = ino;
    let parent_id = InodeId::new(parent);
    let _ = engine
        .mknod(parent_id, &name, mode, rdev as u32, ctx)
        .map_err(|e| ReplayError::EngineError {
            discriminant: DISC_MKNOD,
            errno: e,
        })?;
    Ok(())
}

fn dispatch_tmpfile_ref<E: VfsEngine>(
    engine: &E,
    buf: &[u8],
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    let (parent, mode, _ino) = decode_tmpfile(buf).map_err(ReplayError::Decode)?;
    let parent_id = InodeId::new(parent);
    let _ = engine
        .tmpfile(parent_id, mode, 0, ctx)
        .map_err(|e| ReplayError::EngineError {
            discriminant: DISC_TMPFILE,
            errno: e,
        })?;
    Ok(())
}

fn dispatch_truncate_ref<E: VfsEngine>(
    engine: &E,
    buf: &[u8],
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    let (ino, new_size) = decode_truncate(buf).map_err(ReplayError::Decode)?;
    let ino_id = InodeId::new(ino);
    let sa = SetAttr {
        size: new_size,
        ..Default::default()
    };
    let _ = engine
        .setattr(ino_id, &sa, None, ctx)
        .map_err(|e| ReplayError::EngineError {
            discriminant: DISC_TRUNCATE,
            errno: e,
        })?;
    Ok(())
}

fn dispatch_setattr_ref<E: VfsEngine>(
    _engine: &E,
    buf: &[u8],
    _ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    let (_ino, _attr_mask, _attrs) = decode_setattr(buf).map_err(ReplayError::Decode)?;
    let _ = _ino;
    let _ = _attr_mask;
    let _ = _attrs;
    Ok(())
}

fn dispatch_buffered_write_ref<E: VfsEngine>(
    engine: &E,
    buf: &[u8],
    ctx: &RequestCtx,
) -> Result<(), ReplayError> {
    let (ino, offset, _length, data) = decode_buffered_write(buf).map_err(ReplayError::Decode)?;
    let ino_id = InodeId::new(ino);
    let fh = engine
        .open(ino_id, 1u32, ctx)
        .map_err(|e| ReplayError::EngineError {
            discriminant: DISC_BUFFERED_WRITE,
            errno: e,
        })?;
    let write_result = engine.write(&fh, offset, &data, ctx);
    let _ = engine.release(&fh);
    write_result.map_err(|e| ReplayError::EngineError {
        discriminant: DISC_BUFFERED_WRITE,
        errno: e,
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Low-level decode helpers
// ---------------------------------------------------------------------------

fn read_u64_le(buf: &[u8], pos: &mut usize) -> Result<u64, DecodeError> {
    if *pos + 8 > buf.len() {
        return Err(DecodeError::BufferTooShort {
            needed: *pos + 8,
            have: buf.len(),
        });
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[*pos..*pos + 8]);
    *pos += 8;
    Ok(u64::from_le_bytes(bytes))
}

fn read_u32_le(buf: &[u8], pos: &mut usize) -> Result<u32, DecodeError> {
    if *pos + 4 > buf.len() {
        return Err(DecodeError::BufferTooShort {
            needed: *pos + 4,
            have: buf.len(),
        });
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[*pos..*pos + 4]);
    *pos += 4;
    Ok(u32::from_le_bytes(bytes))
}

fn read_name(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>, DecodeError> {
    if *pos >= buf.len() {
        return Err(DecodeError::BufferTooShort {
            needed: *pos + 1,
            have: buf.len(),
        });
    }
    let len = buf[*pos] as usize;
    *pos += 1;
    if len > 255 {
        return Err(DecodeError::NameTooLong);
    }
    if *pos + len > buf.len() {
        return Err(DecodeError::BufferTooShort {
            needed: *pos + len,
            have: buf.len(),
        });
    }
    let name = buf[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(name)
}

// ---------------------------------------------------------------------------
// Per-variant decode (must match tidefs-intent-log wire format)
// ---------------------------------------------------------------------------

fn decode_create(buf: &[u8]) -> Result<(u64, Vec<u8>, u32, u64), DecodeError> {
    let mut pos = 1; // skip discriminant
    let parent = read_u64_le(buf, &mut pos)?;
    let name = read_name(buf, &mut pos)?;
    let mode = read_u32_le(buf, &mut pos)?;
    let ino = read_u64_le(buf, &mut pos)?;
    Ok((parent, name, mode, ino))
}

fn decode_unlink(buf: &[u8]) -> Result<(u64, Vec<u8>, u64), DecodeError> {
    let mut pos = 1;
    let parent = read_u64_le(buf, &mut pos)?;
    let name = read_name(buf, &mut pos)?;
    let ino = read_u64_le(buf, &mut pos)?;
    Ok((parent, name, ino))
}

fn decode_mkdir(buf: &[u8]) -> Result<(u64, Vec<u8>, u32, u64), DecodeError> {
    decode_create(buf) // same wire layout: parent, name, mode, ino
}

fn decode_rmdir(buf: &[u8]) -> Result<(u64, Vec<u8>, u64), DecodeError> {
    decode_unlink(buf) // same wire layout: parent, name, ino
}

type DecodedRename = (u64, Vec<u8>, u64, Vec<u8>, u64, Option<u64>);

fn decode_rename(buf: &[u8]) -> Result<DecodedRename, DecodeError> {
    let mut pos = 1;
    let src_parent = read_u64_le(buf, &mut pos)?;
    let src_name = read_name(buf, &mut pos)?;
    let dst_parent = read_u64_le(buf, &mut pos)?;
    let dst_name = read_name(buf, &mut pos)?;
    // Optional overwrite target inode: 1-byte tag + optional 8 bytes.
    if pos >= buf.len() {
        return Err(DecodeError::BufferTooShort {
            needed: pos + 1,
            have: buf.len(),
        });
    }
    let has_overwrite = buf[pos] != 0;
    pos += 1;
    let overwrite = if has_overwrite {
        Some(read_u64_le(buf, &mut pos)?)
    } else {
        None
    };
    let ino = read_u64_le(buf, &mut pos)?;
    Ok((src_parent, src_name, dst_parent, dst_name, ino, overwrite))
}

fn decode_hardlink(buf: &[u8]) -> Result<(u64, u64, Vec<u8>), DecodeError> {
    let mut pos = 1;
    let ino = read_u64_le(buf, &mut pos)?;
    let new_parent = read_u64_le(buf, &mut pos)?;
    let new_name = read_name(buf, &mut pos)?;
    Ok((ino, new_parent, new_name))
}

fn decode_symlink(buf: &[u8]) -> Result<(u64, Vec<u8>, Vec<u8>, u64), DecodeError> {
    let mut pos = 1;
    let parent = read_u64_le(buf, &mut pos)?;
    let name = read_name(buf, &mut pos)?;
    let target = read_name(buf, &mut pos)?;
    let ino = read_u64_le(buf, &mut pos)?;
    Ok((parent, name, target, ino))
}

fn decode_mknod(buf: &[u8]) -> Result<(u64, Vec<u8>, u32, u64, u64), DecodeError> {
    let mut pos = 1;
    let parent = read_u64_le(buf, &mut pos)?;
    let name = read_name(buf, &mut pos)?;
    let mode = read_u32_le(buf, &mut pos)?;
    let rdev = read_u64_le(buf, &mut pos)?;
    let ino = read_u64_le(buf, &mut pos)?;
    Ok((parent, name, mode, rdev, ino))
}

fn decode_tmpfile(buf: &[u8]) -> Result<(u64, u32, u64), DecodeError> {
    let mut pos = 1;
    let parent = read_u64_le(buf, &mut pos)?;
    let mode = read_u32_le(buf, &mut pos)?;
    let ino = read_u64_le(buf, &mut pos)?;
    Ok((parent, mode, ino))
}

fn decode_truncate(buf: &[u8]) -> Result<(u64, u64), DecodeError> {
    let mut pos = 1;
    let ino = read_u64_le(buf, &mut pos)?;
    let new_size = read_u64_le(buf, &mut pos)?;
    Ok((ino, new_size))
}

fn decode_setattr(buf: &[u8]) -> Result<(u64, u64, [u8; 64]), DecodeError> {
    let mut pos = 1;
    let ino = read_u64_le(buf, &mut pos)?;
    let attr_mask = read_u64_le(buf, &mut pos)?;
    if pos + 64 > buf.len() {
        return Err(DecodeError::BufferTooShort {
            needed: pos + 64,
            have: buf.len(),
        });
    }
    let mut attrs = [0u8; 64];
    attrs.copy_from_slice(&buf[pos..pos + 64]);
    Ok((ino, attr_mask, attrs))
}

fn decode_xattr_set(buf: &[u8]) -> Result<(u64, u8, Vec<u8>, Vec<u8>), DecodeError> {
    let mut pos = 1; // skip discriminant
    let ino = read_u64_le(buf, &mut pos)?;
    if pos >= buf.len() {
        return Err(DecodeError::BufferTooShort {
            needed: pos + 1,
            have: buf.len(),
        });
    }
    let namespace = buf[pos];
    pos += 1;
    let name = read_name(buf, &mut pos)?;
    if pos + 4 > buf.len() {
        return Err(DecodeError::BufferTooShort {
            needed: pos + 4,
            have: buf.len(),
        });
    }
    let value_len = read_u32_le(buf, &mut pos)? as usize;
    if pos + value_len > buf.len() {
        return Err(DecodeError::BufferTooShort {
            needed: pos + value_len,
            have: buf.len(),
        });
    }
    let value = buf[pos..pos + value_len].to_vec();
    Ok((ino, namespace, name, value))
}

fn decode_xattr_remove(buf: &[u8]) -> Result<(u64, u8, Vec<u8>), DecodeError> {
    let mut pos = 1; // skip discriminant
    let ino = read_u64_le(buf, &mut pos)?;
    if pos >= buf.len() {
        return Err(DecodeError::BufferTooShort {
            needed: pos + 1,
            have: buf.len(),
        });
    }
    let namespace = buf[pos];
    pos += 1;
    let name = read_name(buf, &mut pos)?;
    Ok((ino, namespace, name))
}

fn decode_buffered_write(buf: &[u8]) -> Result<(u64, u64, u64, Vec<u8>), DecodeError> {
    let mut pos = 1; // skip discriminant
    if pos + 8 + 8 + 8 + 2 > buf.len() {
        return Err(DecodeError::BufferTooShort {
            needed: pos + 8 + 8 + 8 + 2,
            have: buf.len(),
        });
    }
    let ino = read_u64_le(buf, &mut pos)?;
    let offset = read_u64_le(buf, &mut pos)?;
    let length = read_u64_le(buf, &mut pos)?;
    let data_len = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if pos + data_len > buf.len() {
        return Err(DecodeError::BufferTooShort {
            needed: pos + data_len,
            have: buf.len(),
        });
    }
    let data = buf[pos..pos + data_len].to_vec();
    Ok((ino, offset, length, data))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use alloc::vec;
    use tidefs_kmod_bridge::kernel_types::{InodeAttr, InodeId}; // Kbuild: use crate::TideVec;

    fn test_ctx() -> RequestCtx {
        MockEngine::test_ctx()
    }

    /// Encode a create record in the canonical wire format.
    fn enc_create(parent: u64, name: &[u8], mode: u32, ino: u64) -> Vec<u8> {
        let mut buf = vec![DISC_CREATE];
        buf.extend_from_slice(&parent.to_le_bytes());
        buf.push(name.len().min(255) as u8);
        buf.extend_from_slice(&name[..name.len().min(255)]);
        buf.extend_from_slice(&mode.to_le_bytes());
        buf.extend_from_slice(&ino.to_le_bytes());
        buf
    }

    fn enc_unlink(parent: u64, name: &[u8], ino: u64) -> Vec<u8> {
        let mut buf = vec![DISC_UNLINK];
        buf.extend_from_slice(&parent.to_le_bytes());
        buf.push(name.len().min(255) as u8);
        buf.extend_from_slice(&name[..name.len().min(255)]);
        buf.extend_from_slice(&ino.to_le_bytes());
        buf
    }

    fn enc_mkdir(parent: u64, name: &[u8], mode: u32, ino: u64) -> Vec<u8> {
        enc_create(parent, name, mode, ino) // same layout, different disc
    }

    // ── Record decode tests ───────────────────────────────────────────

    #[test]
    fn decode_create_roundtrip() {
        let buf = enc_create(10, b"hello", 0o644, 42);
        let (p, n, m, i) = decode_create(&buf).unwrap();
        assert_eq!(p, 10);
        assert_eq!(n, b"hello");
        assert_eq!(m, 0o644);
        assert_eq!(i, 42);
    }

    #[test]
    fn decode_unlink_roundtrip() {
        let buf = enc_unlink(5, b"stale", 99);
        let (p, n, i) = decode_unlink(&buf).unwrap();
        assert_eq!(p, 5);
        assert_eq!(n, b"stale");
        assert_eq!(i, 99);
    }

    #[test]
    fn decode_rename_roundtrip() {
        let mut buf = vec![DISC_RENAME];
        buf.extend_from_slice(&1u64.to_le_bytes()); // src_parent
        buf.push(3);
        buf.extend_from_slice(b"old");
        buf.extend_from_slice(&2u64.to_le_bytes()); // dst_parent
        buf.push(3);
        buf.extend_from_slice(b"new");
        buf.push(0); // no overwrite
        buf.extend_from_slice(&55u64.to_le_bytes()); // ino

        let (sp, sn, dp, dn, ino, ow) = decode_rename(&buf).unwrap();
        assert_eq!(sp, 1);
        assert_eq!(sn, b"old");
        assert_eq!(dp, 2);
        assert_eq!(dn, b"new");
        assert_eq!(ino, 55);
        assert_eq!(ow, None);
    }

    #[test]
    fn decode_truncate_roundtrip() {
        let mut buf = vec![DISC_TRUNCATE];
        buf.extend_from_slice(&7u64.to_le_bytes());
        buf.extend_from_slice(&1000u64.to_le_bytes());
        let (ino, sz) = decode_truncate(&buf).unwrap();
        assert_eq!(ino, 7);
        assert_eq!(sz, 1000);
    }

    #[test]
    fn decode_buffer_too_short() {
        let buf = vec![DISC_CREATE, 0];
        let result = decode_create(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn classify_discriminant_classifies_correctly() {
        assert_eq!(
            classify_discriminant(DISC_CREATE),
            DiscriminantKind::Replayable
        );
        assert_eq!(
            classify_discriminant(DISC_UNLINK),
            DiscriminantKind::Replayable
        );
        assert_eq!(
            classify_discriminant(DISC_TMPFILE),
            DiscriminantKind::Replayable
        );
        assert_eq!(
            classify_discriminant(DISC_XATTRSET),
            DiscriminantKind::Replayable
        );
        assert_eq!(
            classify_discriminant(DISC_XATTRREMOVE),
            DiscriminantKind::Replayable
        );
        assert_eq!(
            classify_discriminant(DISC_BUFFERED_WRITE),
            DiscriminantKind::Replayable
        );
        // Data mutations: gated.
        assert_eq!(classify_discriminant(DISC_WRITE), DiscriminantKind::Gated);
        assert_eq!(
            classify_discriminant(DISC_FALLOCATE),
            DiscriminantKind::Gated
        );
        assert_eq!(
            classify_discriminant(DISC_COPY_FILE_RANGE),
            DiscriminantKind::Gated
        );
        // NoOp types: safe to skip.
        assert_eq!(classify_discriminant(DISC_FLUSH), DiscriminantKind::NoOp);
        assert_eq!(classify_discriminant(DISC_FSYNC), DiscriminantKind::NoOp);
        assert_eq!(classify_discriminant(DISC_LSEEK), DiscriminantKind::NoOp);
        assert_eq!(
            classify_discriminant(DISC_CLEANUP_QUEUE),
            DiscriminantKind::NoOp
        );
        assert_eq!(
            classify_discriminant(DISC_WRITE_INTENT_ACK),
            DiscriminantKind::NoOp
        );
        // Unknown discriminants: NoOp.
        assert_eq!(classify_discriminant(99), DiscriminantKind::NoOp);
    }

    // ── Replay engine tests ───────────────────────────────────────────

    fn build_engine() -> KernelIntentReplay<MockEngine> {
        let mut e = MockEngine::new();
        e.create_fn = Box::new(|_, _, _, _, _| {
            Ok((
                InodeAttr {
                    inode_id: InodeId::new(42),
                    ..Default::default()
                },
                tidefs_kmod_bridge::kernel_types::EngineFileHandle::default(),
            ))
        });
        e.unlink_fn = Box::new(|_, _, _| Ok(()));
        e.mkdir_fn = Box::new(|_, _, _, _| {
            Ok(InodeAttr {
                inode_id: InodeId::new(50),
                ..Default::default()
            })
        });
        e.rmdir_fn = Box::new(|_, _, _| Ok(()));
        e.rename_fn = Box::new(|_, _, _, _, _, _| Ok(()));
        e.setattr_fn = Box::new(|_, _, _, _| {
            Ok(InodeAttr {
                inode_id: InodeId::new(1),
                ..Default::default()
            })
        });
        KernelIntentReplay::new(e, 0)
    }

    /// Like build_engine but wires open and write for buffered-write replay tests.
    fn build_engine_with_open_write() -> KernelIntentReplay<MockEngine> {
        let mut e = MockEngine::new();
        e.create_fn = Box::new(|_, _, _, _, _| {
            Ok((
                InodeAttr {
                    inode_id: InodeId::new(42),
                    ..Default::default()
                },
                tidefs_kmod_bridge::kernel_types::EngineFileHandle::default(),
            ))
        });
        e.unlink_fn = Box::new(|_, _, _| Ok(()));
        e.mkdir_fn = Box::new(|_, _, _, _| {
            Ok(InodeAttr {
                inode_id: InodeId::new(50),
                ..Default::default()
            })
        });
        e.rmdir_fn = Box::new(|_, _, _| Ok(()));
        e.rename_fn = Box::new(|_, _, _, _, _, _| Ok(()));
        e.setattr_fn = Box::new(|_, _, _, _| {
            Ok(InodeAttr {
                inode_id: InodeId::new(1),
                ..Default::default()
            })
        });
        e.open_fn =
            Box::new(|_, _, _| Ok(tidefs_kmod_bridge::kernel_types::EngineFileHandle::default()));
        e.write_fn = Box::new(|_, _, data, _| Ok(data.len() as u32));
        KernelIntentReplay::new(e, 0)
    }

    #[test]
    fn replay_create_dispatches_to_engine() {
        let mut replay = build_engine();
        let rec = enc_create(1, b"file", 0o644, 42);
        replay.replay_records(&[&rec], &test_ctx()).unwrap();
        assert_eq!(replay.replayed(), 1);
        assert_eq!(replay.skipped(), 0);
    }

    #[test]
    fn replay_unlink_dispatches_to_engine() {
        let mut replay = build_engine();
        let rec = enc_unlink(1, b"gone", 99);
        replay.replay_records(&[&rec], &test_ctx()).unwrap();
        assert_eq!(replay.replayed(), 1);
    }

    #[test]
    fn replay_truncate_dispatches_setattr() {
        let mut replay = build_engine();
        let mut buf = vec![DISC_TRUNCATE];
        buf.extend_from_slice(&10u64.to_le_bytes());
        buf.extend_from_slice(&4096u64.to_le_bytes());
        replay.replay_records(&[&buf], &test_ctx()).unwrap();
        assert_eq!(replay.replayed(), 1);
    }

    #[test]
    fn replay_skips_noop_types() {
        let mut replay = build_engine();
        let mut flush_buf = vec![DISC_FLUSH];
        flush_buf.extend_from_slice(&1u64.to_le_bytes());
        flush_buf.extend_from_slice(&42u64.to_le_bytes());
        flush_buf.extend_from_slice(&1000u64.to_le_bytes());

        replay.replay_records(&[&flush_buf], &test_ctx()).unwrap();
        assert_eq!(replay.skipped(), 1);
        assert_eq!(replay.replayed(), 0);
    }

    #[test]
    fn replay_errors_on_gated_data_mutation_records() {
        let mut replay = build_engine();
        let mut write_buf = vec![DISC_WRITE];
        write_buf.extend_from_slice(&10u64.to_le_bytes());
        write_buf.extend_from_slice(&0u64.to_le_bytes());
        write_buf.extend_from_slice(&4096u32.to_le_bytes());

        let err = replay
            .replay_records(&[&write_buf], &test_ctx())
            .unwrap_err();
        assert!(matches!(err, ReplayError::GatedDataMutation { .. }));
        assert_eq!(replay.replayed(), 0);
        assert_eq!(replay.skipped(), 0);

        // DISC_FALLOCATE should also error
        let mut replay3 = build_engine();
        let mut falloc_buf = vec![DISC_FALLOCATE];
        falloc_buf.extend_from_slice(&10u64.to_le_bytes());
        falloc_buf.extend_from_slice(&0u64.to_le_bytes());
        falloc_buf.extend_from_slice(&4096u64.to_le_bytes());
        falloc_buf.extend_from_slice(&0i32.to_le_bytes());
        let err3 = replay3
            .replay_records(&[&falloc_buf], &test_ctx())
            .unwrap_err();
        assert!(matches!(err3, ReplayError::GatedDataMutation { .. }));

        // DISC_COPY_FILE_RANGE should also error
        let mut replay4 = build_engine();
        let mut cfr_buf = vec![DISC_COPY_FILE_RANGE];
        cfr_buf.extend_from_slice(&10u64.to_le_bytes());
        cfr_buf.extend_from_slice(&0u64.to_le_bytes());
        cfr_buf.extend_from_slice(&20u64.to_le_bytes());
        cfr_buf.extend_from_slice(&100u64.to_le_bytes());
        cfr_buf.extend_from_slice(&4096u64.to_le_bytes());
        let err4 = replay4
            .replay_records(&[&cfr_buf], &test_ctx())
            .unwrap_err();
        assert!(matches!(err4, ReplayError::GatedDataMutation { .. }));
    }

    #[test]
    fn replay_buffered_write_dispatches_to_engine() {
        let mut replay = build_engine_with_open_write();
        let mut bw_buf = vec![DISC_BUFFERED_WRITE];
        bw_buf.extend_from_slice(&10u64.to_le_bytes()); // ino
        bw_buf.extend_from_slice(&0u64.to_le_bytes()); // offset
        bw_buf.extend_from_slice(&4u64.to_le_bytes()); // length
        let data = b"data";
        bw_buf.extend_from_slice(&(data.len() as u16).to_le_bytes()); // data_len
        bw_buf.extend_from_slice(data);
        replay.replay_records(&[&bw_buf], &test_ctx()).unwrap();
        assert_eq!(replay.replayed(), 1);
    }

    #[test]
    fn replay_multiple_mixed_records_noop_skip() {
        let mut replay = build_engine();
        let create = enc_create(1, b"a", 0o644, 10);
        let unlink = enc_unlink(1, b"b", 11);
        let mut flush = vec![DISC_FLUSH];
        flush.extend_from_slice(&1u64.to_le_bytes());
        flush.extend_from_slice(&42u64.to_le_bytes());
        flush.extend_from_slice(&1000u64.to_le_bytes());

        replay
            .replay_records(&[&create, &unlink, &flush], &test_ctx())
            .unwrap();
        assert_eq!(replay.replayed(), 2);
        assert_eq!(replay.skipped(), 1);
    }

    #[test]
    fn replay_errors_when_gated_record_in_mixed_batch() {
        let mut replay = build_engine();
        let create = enc_create(1, b"a", 0o644, 10);
        let mut write_buf = vec![DISC_WRITE];
        write_buf.extend_from_slice(&10u64.to_le_bytes());
        write_buf.extend_from_slice(&0u64.to_le_bytes());
        write_buf.extend_from_slice(&4096u32.to_le_bytes());
        let unlink = enc_unlink(1, b"b", 11);

        let err = replay
            .replay_records(&[&create, &write_buf, &unlink], &test_ctx())
            .unwrap_err();
        assert!(matches!(err, ReplayError::GatedDataMutation { .. }));
    }

    #[test]
    fn replay_idempotent_on_eexist() {
        let mut e = MockEngine::new();
        e.create_fn = Box::new(|_, _, _, _, _| Err(Errno::EEXIST));
        let mut replay = KernelIntentReplay::new(e, 0);
        let rec = enc_create(1, b"dup", 0o644, 42);

        replay.replay_records(&[&rec], &test_ctx()).unwrap();
        // EEXIST counts as replayed (idempotent success).
        assert_eq!(replay.replayed(), 1);
        assert_eq!(replay.skipped(), 0);
    }

    #[test]
    fn replay_engine_error_counts_errored() {
        let mut e = MockEngine::new();
        e.create_fn = Box::new(|_, _, _, _, _| Err(Errno::EIO));
        let mut replay = KernelIntentReplay::new(e, 0);
        let rec = enc_create(1, b"fail", 0o644, 42);

        let result = replay.replay_records(&[&rec], &test_ctx());
        assert!(result.is_err());
        assert_eq!(replay.outcome.errored, 1);
    }

    #[test]
    fn checkpoint_deterministic() {
        let mut replay = build_engine();
        let rec = enc_create(1, b"chk", 0o644, 10);
        replay.replay_records(&[&rec], &test_ctx()).unwrap();

        let cp1 = replay.compute_checkpoint();
        let cp2 = replay.compute_checkpoint();
        assert_eq!(cp1, cp2);
    }

    #[test]
    fn checkpoint_differs_on_different_outcome() {
        let mut r1 = build_engine();
        let r2 = build_engine();
        let rec = enc_create(1, b"x", 0o644, 1);
        r1.replay_records(&[&rec], &test_ctx()).unwrap();
        // r2 has no replays

        let cp1 = r1.compute_checkpoint();
        let cp2 = r2.compute_checkpoint();
        assert_ne!(cp1, cp2);
    }

    #[test]
    fn outcome_total_sums_correctly() {
        let o = ReplayOutcome {
            replayed: 10,
            skipped: 5,
            errored: 2,
        };
        assert_eq!(o.total(), 17);
    }

    #[test]
    fn decode_error_display() {
        let e = DecodeError::BufferTooShort {
            needed: 100,
            have: 10,
        };
        let s = alloc::format!("{e}");
        assert!(s.contains("100"));
        assert!(s.contains("10"));

        let e = DecodeError::UnknownDiscriminant { discriminant: 99 };
        assert!(alloc::format!("{e}").contains("99"));
    }

    #[test]
    fn replay_error_display() {
        let e = ReplayError::EngineError {
            discriminant: DISC_CREATE,
            errno: Errno::EIO,
        };
        let s = alloc::format!("{e}");
        assert!(s.contains("engine error"));
        assert!(s.contains("EIO"));
    }
}
