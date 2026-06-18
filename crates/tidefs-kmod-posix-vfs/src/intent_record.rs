// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel-side intent-log record construction and recording dispatch.
#![allow(dead_code)]
//!
//! Builds binary-encoded intent-log records for storage mutation operations
//! and dispatches them through [`VfsEngine::record_intent_entry`] so the
//! kernel-mode path records crash-safety intent entries without userspace
//! daemon mediation. The recording half pairs with mount-time replay
//! ([`crate::intent_replay`]).
//!
//! # Recording contract
//!
//! 1. An intent entry must be recorded before the corresponding storage
//!    mutation completes.  This ensures crash recovery via
//!    [`VfsEngine::replay_intent_log`] can observe and replay any
//!    committed records.
//!
//! 2. Operations that produce intent entries:
//!    - Writeback (writepage/writepages): write-intent before dirty-page flush
//!    - Truncate (setattr with size change): truncate-intent before size change
//!    - Fallocate (space preallocation): allocate-intent before block alloc
//!    - Namespace mutations (create, unlink, rename, mkdir, rmdir, symlink,
//!      link, mknod): namespace-intent before directory update
//!
//! 3. The entry wire format mirrors [`tidefs_intent_log::IntentLogRecord`]
//!    binary encoding: one-byte discriminant followed by variant-specific
//!    little-endian fields with length-prefixed names (max 255 bytes).
//!
//! # No-daemon boundary
//!
//! Every recording dispatch goes directly to the kernel-resident
//! [`VfsEngine`]. No userspace daemon, helper, or upcall is required.

#[cfg(test)]
use crate::test_util::MockEngine;
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;
#[cfg(not(CONFIG_RUST))]
#[path = "kernel_intent_writer.rs"]
pub mod kernel_intent_writer;

use crate::TideVec as Vec;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId, VfsEngine};

// ---------------------------------------------------------------------------
// KernelIntentRecorder -- bridges intent_record encoding to KernelIntentWriter
// ---------------------------------------------------------------------------

/// Middleware that ties intent-record encoding to the sector-aligned
/// [`KernelIntentWriter`] with txg tracking.
///
/// The recorder does NOT own the storage backend; it borrows it through
/// the [`KernelIntentWriter`]. Txg advancement is explicit: callers
/// must call [`advance_txg`](Self::advance_txg) to seal the current
/// transaction group and begin a new one.
#[cfg(not(CONFIG_RUST))]
#[derive(Debug)]
pub struct KernelIntentRecorder {
    writer: kernel_intent_writer::KernelIntentWriter,
    /// Currently open transaction group for record appends.
    current_txg: u64,
    /// Number of records appended in the current txg.
    records_in_txg: u64,
}

#[cfg(not(CONFIG_RUST))]
impl KernelIntentRecorder {
    #[must_use]
    pub const fn new(writer: kernel_intent_writer::KernelIntentWriter, starting_txg: u64) -> Self {
        Self {
            writer,
            current_txg: starting_txg,
            records_in_txg: 0,
        }
    }

    #[must_use]
    pub fn current_txg(&self) -> u64 {
        self.current_txg
    }
    #[must_use]
    pub fn records_in_txg(&self) -> u64 {
        self.records_in_txg
    }
    #[must_use]
    pub fn next_sector(&self) -> u64 {
        self.writer.next_sector()
    }
    #[must_use]
    pub fn next_record_seq(&self) -> u64 {
        self.writer.next_record_seq()
    }

    pub fn record(
        &mut self,
        entry: &IntentLogEntry,
        flush: kernel_intent_writer::KernelIntentFlush,
    ) -> Result<kernel_intent_writer::KernelIntentAppend, Errno> {
        if entry.bytes.len() > MAX_INTENT_ENTRY_SIZE {
            return Err(Errno::EINVAL);
        }
        let result = self
            .writer
            .append_record(self.current_txg, &entry.bytes, flush)?;
        self.records_in_txg = self.records_in_txg.saturating_add(1);
        Ok(result)
    }

    pub fn advance_txg(&mut self, next_txg: u64) -> Result<(), Errno> {
        if next_txg <= self.current_txg {
            return Err(Errno::EINVAL);
        }
        self.current_txg = next_txg;
        self.records_in_txg = 0;
        Ok(())
    }

    pub fn flush_backend(&self) -> Result<(), Errno> {
        self.writer.flush_backend()
    }

    #[must_use]
    pub fn writer(&self) -> &kernel_intent_writer::KernelIntentWriter {
        &self.writer
    }
    #[must_use]
    pub fn writer_mut(&mut self) -> &mut kernel_intent_writer::KernelIntentWriter {
        &mut self.writer
    }
}

/// Convenience: record an entry with flush held until the txg commit barrier.
#[cfg(not(CONFIG_RUST))]
pub fn record_intent_deferred(
    recorder: &mut KernelIntentRecorder,
    entry: &IntentLogEntry,
) -> Result<kernel_intent_writer::KernelIntentAppend, Errno> {
    recorder.record(entry, kernel_intent_writer::KernelIntentFlush::Deferred)
}

// ---------------------------------------------------------------------------
// Record discriminants (must match tidefs-intent-log)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// KmodPosixVfs::record_mutation_intent -- dispatches to recorder or engine
// ---------------------------------------------------------------------------

#[cfg(not(CONFIG_RUST))]
impl<E: tidefs_kmod_bridge::kernel_types::VfsEngine> crate::KmodPosixVfs<E> {
    pub fn record_mutation_intent(&self, entry: &IntentLogEntry) -> Result<(), Errno> {
        if let Some(ref mut recorder) = *self.intent_recorder.borrow_mut() {
            recorder
                .record(entry, kernel_intent_writer::KernelIntentFlush::Deferred)
                .map(|_| ())
        } else {
            record_intent(&self.engine, entry).map_err(|_| Errno::EIO)
        }
    }

    pub fn commit_fs_barrier(&self) -> Result<(), Errno> {
        if let Some(ref mut recorder) = *self.intent_recorder.borrow_mut() {
            recorder.flush_backend()?;
            let next_txg = recorder.current_txg().saturating_add(1);
            recorder.advance_txg(next_txg)?;
        }
        self.engine.txg_commit_barrier()?;
        Ok(())
    }
}

#[cfg(CONFIG_RUST)]
impl<E: tidefs_kmod_bridge::kernel_types::VfsEngine> crate::KmodPosixVfs<E> {
    /// Kbuild path: dispatch through the engine trait (no recorder available).
    pub fn record_mutation_intent(&self, entry: &IntentLogEntry) -> Result<(), Errno> {
        record_intent(&self.engine, entry).map_err(|_| Errno::EIO)
    }

    /// Kbuild path: dispatch txg commit barrier through the engine trait.
    pub fn commit_fs_barrier(&self) -> Result<(), Errno> {
        self.engine.txg_commit_barrier()
    }
}

pub const DISC_WRITE: u8 = 1;
/// Discriminant for .
pub const DISC_TRUNCATE: u8 = 2;
/// Discriminant for .
pub const DISC_SETATTR: u8 = 3;
/// Discriminant for .
pub const DISC_CREATE: u8 = 4;
/// Discriminant for .
pub const DISC_UNLINK: u8 = 5;
/// Discriminant for .
pub const DISC_RENAME: u8 = 6;
/// Discriminant for .
pub const DISC_SYMLINK: u8 = 7;
/// Discriminant for .
pub const DISC_HARDLINK: u8 = 8;
/// Discriminant for .
pub const DISC_MKDIR: u8 = 9;
/// Discriminant for .
pub const DISC_RMDIR: u8 = 10;
/// Discriminant for .
pub const DISC_MKNOD: u8 = 11;
/// Discriminant for xattr-set intent (replayable).
pub const DISC_XATTRSET: u8 = 12;
/// Discriminant for xattr-remove intent (replayable).
pub const DISC_XATTRREMOVE: u8 = 16;
/// Discriminant for .
pub const DISC_FALLOCATE: u8 = 13;
/// Discriminant for tmpfile intent (replayable).
pub const DISC_TMPFILE: u8 = 17;
/// Discriminant for flush barrier (non-replayable).
pub const DISC_FLUSH: u8 = 18;
/// Discriminant for fsync intent (non-replayable).
pub const DISC_FSYNC: u8 = 20;

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Minimum encoded size for a write-intent record (discriminant + ino + offset + length).
pub const WRITE_INTENT_SIZE: usize = 25;

/// Encode a write-intent record for crash-safety recording.
///
/// Wire format:
/// - 1 byte:
/// - 8 bytes:  (little-endian u64)
/// - 8 bytes:  (little-endian u64)
/// - 8 bytes:  (little-endian u64)
///
/// The caller must call [] with this entry before completing
/// the corresponding storage mutation.
pub fn encode_write_intent(inode: InodeId, offset: u64, length: u32) -> IntentLogEntry {
    let mut buf = crate::TideVec::with_capacity(WRITE_INTENT_SIZE);
    buf.push(DISC_WRITE);
    buf.extend_from_slice(&inode.get().to_le_bytes());
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(&(length as u64).to_le_bytes());
    IntentLogEntry::from(buf)
}
/// Minimum encoded size for a namespace-intent record (discriminant + parent + name_len + name).
pub const NS_INTENT_MIN_SIZE: usize = 4;

/// Encode a create-intent record.
///
/// Wire format: DISC_CREATE + parent(u64 LE) + name_len(u8) + name(bytes) + mode(u32 LE) + ino(u64 LE, zero placeholder).
pub fn encode_create_intent(
    parent: InodeId,
    name: &[u8],
    mode: u32,
    ino: InodeId,
) -> IntentLogEntry {
    let name_len = name.len().min(255) as u8;
    let mut buf = crate::TideVec::with_capacity(25 + name.len());
    buf.push(DISC_CREATE);
    buf.extend_from_slice(&parent.get().to_le_bytes());
    buf.push(name_len);
    buf.extend_from_slice(&name[..name.len().min(255)]);
    buf.extend_from_slice(&mode.to_le_bytes());
    buf.extend_from_slice(&ino.get().to_le_bytes());
    IntentLogEntry::from(buf)
}

/// Encode an unlink-intent record.
///
/// Wire format: DISC_UNLINK + parent(u64 LE) + name_len(u8) + name(bytes) + ino(u64 LE, zero placeholder).
pub fn encode_unlink_intent(parent: InodeId, name: &[u8], ino: InodeId) -> IntentLogEntry {
    let name_len = name.len().min(255) as u8;
    let mut buf = crate::TideVec::with_capacity(11 + name.len());
    buf.push(DISC_UNLINK);
    buf.extend_from_slice(&parent.get().to_le_bytes());
    buf.push(name_len);
    buf.extend_from_slice(&name[..name.len().min(255)]);
    buf.extend_from_slice(&ino.get().to_le_bytes());
    IntentLogEntry::from(buf)
}

/// Encode a mkdir-intent record (same wire format as create).
///
/// Wire format: DISC_MKDIR + parent(u64 LE) + name_len(u8) + name(bytes) + mode(u32 LE) + ino(u64 LE, zero placeholder).
pub fn encode_mkdir_intent(
    parent: InodeId,
    name: &[u8],
    mode: u32,
    ino: InodeId,
) -> IntentLogEntry {
    let name_len = name.len().min(255) as u8;
    let mut buf = crate::TideVec::with_capacity(25 + name.len());
    buf.push(DISC_MKDIR);
    buf.extend_from_slice(&parent.get().to_le_bytes());
    buf.push(name_len);
    buf.extend_from_slice(&name[..name.len().min(255)]);
    buf.extend_from_slice(&mode.to_le_bytes());
    buf.extend_from_slice(&ino.get().to_le_bytes());
    IntentLogEntry::from(buf)
}

/// Encode a rmdir-intent record.
///
/// Wire format: DISC_RMDIR + parent(u64 LE) + name_len(u8) + name(bytes) + ino(u64 LE).
pub fn encode_rmdir_intent(parent: InodeId, name: &[u8], ino: InodeId) -> IntentLogEntry {
    let name_len = name.len().min(255) as u8;
    let mut buf = crate::TideVec::with_capacity(19 + name.len());
    buf.push(DISC_RMDIR);
    buf.extend_from_slice(&parent.get().to_le_bytes());
    buf.push(name_len);
    buf.extend_from_slice(&name[..name.len().min(255)]);
    buf.extend_from_slice(&ino.get().to_le_bytes());
    IntentLogEntry::from(buf)
}

/// Encode a rename-intent record.
///
/// Wire format: DISC_RENAME + src_parent(u64 LE) + src_name_len(u8) + src_name(bytes)
///              + dst_parent(u64 LE) + dst_name_len(u8) + dst_name(bytes)
///              + overwrite_flag(u8) [+ overwrite_ino(u64 LE) if flag=1] + ino(u64 LE).
pub fn encode_rename_intent(
    old_parent: InodeId,
    old_name: &[u8],
    new_parent: InodeId,
    new_name: &[u8],
    source_ino: InodeId,
    overwrite_ino: Option<InodeId>,
) -> IntentLogEntry {
    let old_len = old_name.len().min(255) as u8;
    let new_len = new_name.len().min(255) as u8;
    let extra = if overwrite_ino.is_some() { 8 } else { 0 };
    let mut buf = crate::TideVec::with_capacity(21 + old_name.len() + new_name.len() + extra);
    buf.push(DISC_RENAME);
    buf.extend_from_slice(&old_parent.get().to_le_bytes());
    buf.push(old_len);
    buf.extend_from_slice(&old_name[..old_name.len().min(255)]);
    buf.extend_from_slice(&new_parent.get().to_le_bytes());
    buf.push(new_len);
    buf.extend_from_slice(&new_name[..new_name.len().min(255)]);
    if let Some(ov_ino) = overwrite_ino {
        buf.push(1u8); // overwrite
        buf.extend_from_slice(&ov_ino.get().to_le_bytes());
    } else {
        buf.push(0u8); // no overwrite
    }
    buf.extend_from_slice(&source_ino.get().to_le_bytes());
    IntentLogEntry::from(buf)
}

/// Encode a symlink-intent record.
///
/// Wire format: DISC_SYMLINK + parent(u64 LE) + name_len(u8) + name(bytes) + target_len(u8) + target(bytes) + ino(u64 LE).
pub fn encode_symlink_intent(
    parent: InodeId,
    name: &[u8],
    target: &[u8],
    ino: InodeId,
) -> IntentLogEntry {
    let name_len = name.len().min(255) as u8;
    let target_len = target.len().min(255) as u8;
    let mut buf = crate::TideVec::with_capacity(20 + name.len() + target.len());
    buf.push(DISC_SYMLINK);
    buf.extend_from_slice(&parent.get().to_le_bytes());
    buf.push(name_len);
    buf.extend_from_slice(&name[..name.len().min(255)]);
    buf.push(target_len);
    buf.extend_from_slice(&target[..target.len().min(255)]);
    buf.extend_from_slice(&ino.get().to_le_bytes());
    IntentLogEntry::from(buf)
}

/// Encode a hardlink-intent record.
///
/// Wire format: DISC_HARDLINK + target_ino(u64 LE) + new_parent(u64 LE) + new_name_len(u8) + new_name(bytes).
pub fn encode_link_intent(target: InodeId, new_parent: InodeId, new_name: &[u8]) -> IntentLogEntry {
    let name_len = new_name.len().min(255) as u8;
    let mut buf = crate::TideVec::with_capacity(18 + new_name.len());
    buf.push(DISC_HARDLINK);
    buf.extend_from_slice(&target.get().to_le_bytes());
    buf.extend_from_slice(&new_parent.get().to_le_bytes());
    buf.push(name_len);
    buf.extend_from_slice(&new_name[..new_name.len().min(255)]);
    IntentLogEntry::from(buf)
}

/// Encode a mknod-intent record.
///
/// Wire format: DISC_MKNOD + parent(u64 LE) + name_len(u8) + name(bytes) + mode(u32 LE) + rdev(u32 LE) + ino(u64 LE).
pub fn encode_mknod_intent(
    parent: InodeId,
    name: &[u8],
    mode: u32,
    rdev: u32,
    ino: InodeId,
) -> IntentLogEntry {
    let name_len = name.len().min(255) as u8;
    let mut buf = crate::TideVec::with_capacity(27 + name.len());
    buf.push(DISC_MKNOD);
    buf.extend_from_slice(&parent.get().to_le_bytes());
    buf.push(name_len);
    buf.extend_from_slice(&name[..name.len().min(255)]);
    buf.extend_from_slice(&mode.to_le_bytes());
    buf.extend_from_slice(&rdev.to_le_bytes());
    buf.extend_from_slice(&ino.get().to_le_bytes());
    IntentLogEntry::from(buf)
}
/// Encode a truncate-intent record for crash-safety recording.
///
/// Wire format: DISC_TRUNCATE + ino(u64 LE) + new_size(u64 LE).
pub fn encode_truncate_intent(inode: InodeId, new_size: u64) -> IntentLogEntry {
    let mut buf = crate::TideVec::with_capacity(17);
    buf.push(DISC_TRUNCATE);
    buf.extend_from_slice(&inode.get().to_le_bytes());
    buf.extend_from_slice(&new_size.to_le_bytes());
    IntentLogEntry::from(buf)
}

/// Encode a fallocate-intent record for crash-safety recording.
///
/// Wire format: DISC_FALLOCATE + ino(u64 LE) + mode(u32 LE) + offset(u64 LE) + length(u64 LE).
pub fn encode_fallocate_intent(
    inode: InodeId,
    mode: u32,
    offset: u64,
    length: u64,
) -> IntentLogEntry {
    let mut buf = crate::TideVec::with_capacity(29);
    buf.push(DISC_FALLOCATE);
    buf.extend_from_slice(&inode.get().to_le_bytes());
    buf.extend_from_slice(&mode.to_le_bytes());
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(&length.to_le_bytes());
    IntentLogEntry::from(buf)
}

// ---------------------------------------------------------------------------
// Record discriminants (must match tidefs-intent-log)

/// Encode a setxattr-intent record for crash-safety recording.
///
/// Wire format: DISC_XATTRSET + ino(u64 LE) + namespace(u8) + name_len(u8) + name(bytes) + value_len(u32 LE) + value(bytes).
pub fn encode_setxattr_intent(
    inode: InodeId,
    namespace: u8,
    name: &[u8],
    value: &[u8],
) -> IntentLogEntry {
    let cap = 1 + 8 + 1 + 1 + name.len() + 4 + value.len();
    let mut buf = crate::TideVec::with_capacity(cap);
    buf.push(DISC_XATTRSET);
    buf.extend_from_slice(&inode.get().to_le_bytes());
    buf.push(namespace);
    buf.push(name.len() as u8);
    buf.extend_from_slice(name);
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value);
    IntentLogEntry::from(buf)
}

/// Encode a removexattr-intent record for crash-safety recording.
///
/// Wire format: DISC_XATTRREMOVE + ino(u64 LE) + namespace(u8) + name_len(u8) + name(bytes).
pub fn encode_removexattr_intent(inode: InodeId, namespace: u8, name: &[u8]) -> IntentLogEntry {
    let cap = 1 + 8 + 1 + 1 + name.len();
    let mut buf = crate::TideVec::with_capacity(cap);
    buf.push(DISC_XATTRREMOVE);
    buf.extend_from_slice(&inode.get().to_le_bytes());
    buf.push(namespace);
    buf.push(name.len() as u8);
    buf.extend_from_slice(name);
    IntentLogEntry::from(buf)
}
// ---------------------------------------------------------------------------

/// A binary-encoded intent-log record ready for dispatch to
/// [`VfsEngine::record_intent_entry`].
///
/// The encoding follows the `tidefs_intent_log::IntentLogRecord` wire format:
/// one-byte discriminant followed by variant-specific little-endian fields.
/// Name fields are length-prefixed with a single byte (max 255 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentLogEntry {
    /// The binary-encoded record bytes.
    pub bytes: Vec<u8>,
}

impl IntentLogEntry {
    /// Wrap an already-encoded record buffer.
    pub fn from_encoded(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Return the record discriminant (first byte).
    pub fn discriminant(&self) -> u8 {
        self.bytes.first().copied().unwrap_or(0)
    }

    /// View the entry as a byte slice for dispatch.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for IntentLogEntry {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl AsRef<[u8]> for IntentLogEntry {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// ---------------------------------------------------------------------------
// IntentLogError
// ---------------------------------------------------------------------------

/// Errors from kernel-side intent-log recording.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntentLogError {
    /// The record payload exceeds the maximum frame size.
    EntryTooLarge { size: usize, max: usize },
    /// The record discriminant is not valid for a mutable storage operation.
    InvalidDiscriminant { discriminant: u8 },
    /// The VfsEngine returned an error when recording.
    EngineError(Errno),
}

impl core::fmt::Display for IntentLogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EntryTooLarge { size, max } => {
                write!(f, "intent entry {size} bytes exceeds maximum {max}")
            }
            Self::InvalidDiscriminant { discriminant } => {
                write!(f, "invalid intent record discriminant: {discriminant}")
            }
            Self::EngineError(e) => write!(f, "engine error recording intent: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Maximum size of an intent-log entry in bytes.
pub const MAX_INTENT_ENTRY_SIZE: usize = 4096;

/// Record an intent entry through the engine, translating errors.
///
/// Returns `Ok(())` when the entry was accepted. Returns
/// [`IntentLogError::EntryTooLarge`] when `entry.as_bytes().len()` exceeds
/// [`MAX_INTENT_ENTRY_SIZE`]. Returns [`IntentLogError::EngineError`] when
/// the engine rejects the entry.
pub fn record_intent(
    engine: &impl VfsEngine,
    entry: &IntentLogEntry,
) -> Result<(), IntentLogError> {
    if entry.bytes.len() > MAX_INTENT_ENTRY_SIZE {
        return Err(IntentLogError::EntryTooLarge {
            size: entry.bytes.len(),
            max: MAX_INTENT_ENTRY_SIZE,
        });
    }
    engine
        .record_intent_entry(entry.as_bytes())
        .map_err(IntentLogError::EngineError)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec; // Kbuild: use crate::TideVec;

    fn make_entry() -> IntentLogEntry {
        let mut buf = vec![1u8]; // DISC_WRITE
        buf.extend_from_slice(&42u64.to_le_bytes()); // inode
        buf.extend_from_slice(&0u64.to_le_bytes()); // offset
        buf.extend_from_slice(&[8, 0, 0, 0]); // len
        buf.extend_from_slice(b"testdata"); // data
        IntentLogEntry::from(buf)
    }

    #[test]
    fn entry_discriminant() {
        let e = make_entry();
        assert_eq!(e.discriminant(), 1);
    }

    #[test]
    fn entry_as_bytes() {
        let e = make_entry();
        assert!(!e.as_bytes().is_empty());
    }

    #[test]
    fn entry_as_ref() {
        let e = make_entry();
        let s: &[u8] = e.as_ref();
        assert_eq!(s[0], 1);
    }

    #[test]
    fn entry_from_encoded() {
        let e = IntentLogEntry::from_encoded(vec![4, 0, 0]);
        assert_eq!(e.discriminant(), 4);
    }

    #[test]
    fn entry_clone_eq() {
        let e1 = make_entry();
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn entry_debug_contains_discriminant() {
        let e = make_entry();
        let s = alloc::format!("{e:?}");
        assert!(s.contains('1'));
    }

    #[test]
    fn record_intent_dispatches_to_engine() {
        let engine = MockEngine::new();
        let entry = make_entry();
        record_intent(&engine, &entry).unwrap();
        // MockEngine records succeed silently (default no-op).
    }

    #[test]
    fn record_intent_rejects_oversized_entry() {
        let engine = MockEngine::new();
        let big = IntentLogEntry::from(vec![0u8; MAX_INTENT_ENTRY_SIZE + 1]);
        let err = record_intent(&engine, &big).unwrap_err();
        assert!(matches!(err, IntentLogError::EntryTooLarge { .. }));
    }

    #[test]
    fn intent_log_error_display() {
        let e = IntentLogError::InvalidDiscriminant { discriminant: 99 };
        let s = alloc::format!("{e}");
        assert!(s.contains("99"));

        let e = IntentLogError::EntryTooLarge {
            size: 5000,
            max: 4096,
        };
        let s = alloc::format!("{e}");
        assert!(s.contains("5000"));
    }
}

#[test]
fn encode_write_intent_discriminant() {
    let entry = encode_write_intent(InodeId::new(42), 1024, 4096);
    assert_eq!(entry.discriminant(), DISC_WRITE);
}

#[test]
fn encode_write_intent_size() {
    let entry = encode_write_intent(InodeId::new(1), 0, 8192);
    assert_eq!(entry.bytes.len(), WRITE_INTENT_SIZE);
}

#[test]
fn encode_write_intent_roundtrip() {
    let ino = InodeId::new(99);
    let offset = 65536u64;
    let length = 16384u32;
    let entry = encode_write_intent(ino, offset, length);

    // Verify discriminant
    assert_eq!(entry.bytes[0], DISC_WRITE);

    // Verify inode (bytes 1-8, little-endian u64)
    let mut ino_bytes = [0u8; 8];
    ino_bytes.copy_from_slice(&entry.bytes[1..9]);
    assert_eq!(u64::from_le_bytes(ino_bytes), 99);

    // Verify offset (bytes 9-16, little-endian u64)
    let mut off_bytes = [0u8; 8];
    off_bytes.copy_from_slice(&entry.bytes[9..17]);
    assert_eq!(u64::from_le_bytes(off_bytes), 65536);

    // Verify length (bytes 17-25, little-endian u64)
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&entry.bytes[17..25]);
    assert_eq!(u64::from_le_bytes(len_bytes), 16384);
}

#[test]
fn encode_write_intent_via_record_intent() {
    let engine = MockEngine::new();
    let entry = encode_write_intent(InodeId::new(7), 0, 4096);
    let result = record_intent(&engine, &entry);
    assert!(result.is_ok());
}

#[test]
fn encode_write_intent_zero_length() {
    let entry = encode_write_intent(InodeId::new(3), 0, 0);
    assert_eq!(entry.discriminant(), DISC_WRITE);
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&entry.bytes[17..25]);
    assert_eq!(u64::from_le_bytes(len_bytes), 0);
}

#[test]
fn encode_write_intent_max_u64_offset() {
    let entry = encode_write_intent(InodeId::new(1), u64::MAX, 1);
    let mut off_bytes = [0u8; 8];
    off_bytes.copy_from_slice(&entry.bytes[9..17]);
    assert_eq!(u64::from_le_bytes(off_bytes), u64::MAX);
}
