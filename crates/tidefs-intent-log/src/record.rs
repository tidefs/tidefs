// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Intent-log record type enum and binary encoding/decoding.
//!
//! Every mutating filesystem operation has a corresponding variant in
//! [`IntentLogRecord`]. The binary encoding uses a one-byte discriminant
//! followed by variant-specific fields in little-endian order. Name fields
//! are length-prefixed with a single byte (max 255 bytes).

#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

use crate::{
    IntentLogError, RECORD_DISCRIMINANT_BUFFERED_WRITE, RECORD_DISCRIMINANT_CLEANUP_QUEUE,
    RECORD_DISCRIMINANT_COPY_FILE_RANGE, RECORD_DISCRIMINANT_CREATE,
    RECORD_DISCRIMINANT_EXPORT_TERMINAL, RECORD_DISCRIMINANT_FALLOCATE, RECORD_DISCRIMINANT_FLUSH,
    RECORD_DISCRIMINANT_FSYNC, RECORD_DISCRIMINANT_HARDLINK, RECORD_DISCRIMINANT_LSEEK,
    RECORD_DISCRIMINANT_MKDIR, RECORD_DISCRIMINANT_MKNOD, RECORD_DISCRIMINANT_RENAME,
    RECORD_DISCRIMINANT_RMDIR, RECORD_DISCRIMINANT_SETATTR, RECORD_DISCRIMINANT_SYMLINK,
    RECORD_DISCRIMINANT_TMPFILE, RECORD_DISCRIMINANT_TRUNCATE, RECORD_DISCRIMINANT_TX_ABORT,
    RECORD_DISCRIMINANT_TX_BEGIN, RECORD_DISCRIMINANT_TX_COMMIT, RECORD_DISCRIMINANT_UNLINK,
    RECORD_DISCRIMINANT_WRITE, RECORD_DISCRIMINANT_WRITE_INTENT_ACK,
    RECORD_DISCRIMINANT_XATTRREMOVE, RECORD_DISCRIMINANT_XATTRSET,
};

// ---------------------------------------------------------------------------
// XattrNamespace
// ---------------------------------------------------------------------------

/// The xattr namespace for an extended-attribute operation.
///
/// Corresponds to the Linux xattr namespace prefixes (`security.`, `system.`,
/// `trusted.`, `user.`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum XattrNamespace {
    /// `security.*` — SELinux, SMACK, AppArmor.
    Security = 1,
    /// `system.*` — ACLs, capabilities.
    System = 2,
    /// `trusted.*` — restricted to CAP_SYS_ADMIN.
    Trusted = 3,
    /// `user.*` — unrestricted per-file attributes.
    User = 4,
}

impl XattrNamespace {
    /// Serialize the namespace as a single byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Deserialize a namespace from a single byte.
    pub fn from_byte(b: u8) -> Result<Self, IntentLogError> {
        match b {
            1 => Ok(Self::Security),
            2 => Ok(Self::System),
            3 => Ok(Self::Trusted),
            4 => Ok(Self::User),
            _ => Err(IntentLogError::UnknownDiscriminant { discriminant: b }),
        }
    }
}

// ---------------------------------------------------------------------------
// IntentLogRecord
// ---------------------------------------------------------------------------

/// A single mutating filesystem operation recorded in the intent log.
///
/// Covers all 14 operation classes that modify filesystem state. Each variant
/// carries enough information to replay the operation during crash recovery
/// or to undo it during transaction abort.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntentLogRecord {
    /// Write data to a file at a specific offset.
    Write {
        /// Inode number.
        ino: u64,
        /// Byte offset within the file.
        offset: u64,
        /// Number of bytes written.
        length: u64,
        /// BLAKE3-256 hash of the written data.
        data_hash: [u8; 32],
    },
    /// Truncate a file to a new size.
    Truncate {
        /// Inode number.
        ino: u64,
        /// New file size in bytes.
        new_size: u64,
    },
    /// Set file attributes (mode, uid, gid, size, atime, mtime).
    Setattr {
        /// Inode number.
        ino: u64,
        /// Bitmask of attributes being set (see `SETATTR_*` constants in
        /// the FUSE protocol).
        attr_mask: u64,
        /// Serialized attribute values (layout defined by attr_mask).
        attrs: [u8; 64],
    },
    /// Create a regular file.
    Create {
        /// Parent directory inode.
        parent: u64,
        /// File name (max 255 bytes).
        name: Vec<u8>,
        /// File mode (permissions + type).
        mode: u32,
        /// Newly allocated inode number.
        ino: u64,
    },
    /// Unlink (remove) a file.
    Unlink {
        /// Parent directory inode.
        parent: u64,
        /// File name.
        name: Vec<u8>,
        /// Inode being removed.
        ino: u64,
    },
    /// Rename a file or directory.
    Rename {
        /// Source parent directory inode.
        src_parent: u64,
        /// Source name.
        src_name: Vec<u8>,
        /// Destination parent directory inode.
        dst_parent: u64,
        /// Destination name.
        dst_name: Vec<u8>,
        /// Inode being renamed.
        ino: u64,
        /// Inode overwritten at the target (if any), for idempotent replay.
        overwrite_target_ino: Option<u64>,
        /// renameat2 flags (0 = plain, 1 = RENAME_NOREPLACE, 2 = RENAME_EXCHANGE).
        rename_flags: u32,
    },
    /// Create a symbolic link.
    Symlink {
        /// Parent directory inode.
        parent: u64,
        /// Link name.
        name: Vec<u8>,
        /// Symlink target path.
        target: Vec<u8>,
        /// Newly allocated inode number.
        ino: u64,
    },
    /// Create a hard link.
    HardLink {
        /// Existing inode to link to.
        ino: u64,
        /// New parent directory inode.
        new_parent: u64,
        /// New link name.
        new_name: Vec<u8>,
    },
    /// Create a directory.
    Mkdir {
        /// Parent directory inode.
        parent: u64,
        /// Directory name.
        name: Vec<u8>,
        /// Directory mode.
        mode: u32,
        /// Newly allocated inode number.
        ino: u64,
    },
    /// Remove an empty directory.
    Rmdir {
        /// Parent directory inode.
        parent: u64,
        /// Directory name.
        name: Vec<u8>,
        /// Inode being removed.
        ino: u64,
    },
    /// Create a device node (FIFO, socket, block, char).
    Mknod {
        /// Parent directory inode.
        parent: u64,
        /// Node name.
        name: Vec<u8>,
        /// File mode (permissions + type).
        mode: u32,
        /// Device number (for block/char devices).
        rdev: u64,
        /// Newly allocated inode number.
        ino: u64,
    },
    /// Set an extended attribute.
    XattrSet {
        /// Inode number.
        ino: u64,
        /// Xattr namespace.
        namespace: XattrNamespace,
        /// BLAKE3-256 hash of the attribute key.
        key_hash: [u8; 32],
        /// BLAKE3-256 hash of the attribute value.
        value_hash: [u8; 32],
    },
    /// Remove an extended attribute.
    XattrRemove {
        /// Inode number.
        ino: u64,
        /// Xattr namespace.
        namespace: XattrNamespace,
        /// BLAKE3-256 hash of the attribute key.
        key_hash: [u8; 32],
    },
    /// Close-path flush record for per-fd writeback-buffer drain.
    ///
    /// Recorded on every `close(2)` when the file handle has dirty
    /// writeback buffers. Unlike [`Write`] or [`BufferedWrite`], this
    /// record carries no data payload — it serves as a crash-safety
    /// marker so that replay can confirm the close-flush completed.
    Flush {
        /// Inode number.
        ino: u64,
        /// File handle identifier.
        fh: u64,
        /// Lock owner identifier (pid or thread-group leader).
        lock_owner: u64,
    },
    /// Allocate or deallocate space in a file.
    Fallocate {
        /// Inode number.
        ino: u64,
        /// Starting byte offset.
        offset: u64,
        /// Length of the region.
        length: u64,
        /// Allocation mode (FALLOC_FL_* constants).
        mode: i32,
    },
    /// Buffered write with inline data payload for crash-safe intent recording.
    ///
    /// Small writes (up to 65535 bytes) embed their data directly in the
    /// record so that crash replay can restore the written bytes without a
    /// separate data-store lookup. Larger writes use [`Write`] with a
    /// `data_hash` reference instead.
    BufferedWrite {
        /// Inode number.
        ino: u64,
        /// Byte offset within the file.
        offset: u64,
        /// Number of bytes written.
        length: u64,
        /// Inline data payload (max 65535 bytes).
        data: Vec<u8>,
    },
    /// Acknowledgment sentinel recording that a buffered-write intent

    /// has been durably committed.

    ///

    /// The TxgCoordinator inserts this record after the write data

    /// reaches stable storage. Crash replay uses it to confirm that

    /// the corresponding [`Write`] or [`BufferedWrite`] record

    /// is durable and does not need redo.
    WriteIntentAck {
        /// Inode number.
        ino: u64,

        /// Byte offset of the acknowledged write.
        offset: u64,

        /// Number of bytes durably committed.
        length: u64,
    },
    /// Create an unnamed temporary file (O_TMPFILE).
    Tmpfile {
        /// Parent directory inode.
        parent: u64,
        /// File mode (permissions + type).
        mode: u32,
        /// Newly allocated inode number.
        ino: u64,
    },

    /// Lseek operation recording for future crash-safe
    /// hole-punch/zero-range interaction tracing.
    ///
    /// The lseek read path is read-only; this record type is reserved
    /// for future write-path operations that depend on lseek extent
    /// information for correct hole-aware mutation replay.
    Lseek {
        /// Inode number.
        ino: u64,
        /// SEEK_DATA (3) or SEEK_HOLE (4) whence.
        whence: u8,
        /// Starting byte offset for the search.
        offset: u64,
        /// Resulting byte offset returned by the seek operation.
        result: u64,
    },

    /// Fsync/fdatasync durability barrier record.
    ///
    /// Recorded when the FUSE fsync or fdatasync handler commits
    /// dirty writeback buffers to stable storage. The `mode` field
    /// distinguishes full metadata+data sync (`Fsync`, mode=0) from
    /// data-only sync (`Fdatasync`, mode=1).
    Fsync {
        /// Inode number.
        ino: u64,
        /// File handle identifier.
        fh: u64,
        /// Sync mode: 0=Fsync (metadata+data), 1=Fdatasync (data-only).
        mode: u8,
    },

    /// GC cleanup-queue ledger state transition for crash recovery.
    ///
    /// Records each state transition (Pending→Verified→Reconciled→Failed)
    /// so that crash replay can resume the cleanup pipeline without
    /// double-freeing or leaking extents.
    CleanupQueue {
        /// Unique entry ID in the cleanup-queue ledger.
        entry_id: u64,
        /// Device identifier for the freed extent.
        device_id: u64,
        /// Physical byte offset on the device.
        physical_offset: u64,
        /// Length of the freed extent in bytes.
        length: u64,
        /// BLAKE3 hash of the extent data at the time of freeing.
        blake3_hash: [u8; 32],
        /// Transaction group at which this free became durable.
        freed_at_txg: u64,
        /// Cleanup status: 0=Pending, 1=Verified, 2=Reconciled, 3=Failed.
        cleanup_status: u8,
        /// Number of reconcile attempts for this entry.
        retry_count: u8,
    },
    /// Copy a byte range from one file to another.
    ///
    /// Used by copy_file_range(2) to provide crash-safe copies between
    /// open file handles. The record carries source/dest inode and
    /// handle IDs plus the offset/length parameters so replay can
    /// verify the copy completed or redo it.
    CopyFileRange {
        /// Source file inode number.
        src_ino: u64,
        /// Source file handle identifier.
        src_fh: u64,
        /// Destination file inode number.
        dst_ino: u64,
        /// Destination file handle identifier.
        dst_fh: u64,
        /// Starting byte offset in source.
        src_offset: u64,
        /// Starting byte offset in destination.
        dst_offset: u64,
        /// Number of bytes to copy.
        len: u64,
    },
    /// Begin a transaction group boundary.
    ///
    /// Marks the start of an atomic group of intent-log records
    /// that should be committed or rolled back together.
    TxBegin {
        /// Monotonically increasing transaction group identifier.
        cg_id: u64,
    },
    /// Commit a transaction group.
    ///
    /// Confirms that all records since the matching [`TxBegin`](Self::TxBegin)
    /// have been durably persisted and can be applied atomically.
    TxCommit {
        /// Transaction group identifier matching a prior `TxBegin`.
        cg_id: u64,
    },
    /// Abort (roll back) a transaction group.
    ///
    /// Marks that the records since the matching [`TxBegin`](Self::TxBegin)
    /// should be discarded and their effects rolled back.
    TxAbort {
        /// Transaction group identifier matching a prior `TxBegin`.
        cg_id: u64,
    },
    /// Export terminal: clean shutdown marker written at pool export time.
    ///
    /// Written as the final record before a clean pool export, this marker
    /// allows the next mount to detect that the pool was shut down cleanly
    /// without requiring a full intent-log replay.
    ExportTerminal {
        /// Transaction group identifier of the final committed commit_group.
        cg_id: u64,
    },
}

impl IntentLogRecord {
    // ── Encoding ───────────────────────────────────────────────────

    /// Serialize this record into a byte vector.
    ///
    /// Format: `[discriminant: u8] [variant-specific fields...]`
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf);
        buf
    }

    /// Serialize this record into an existing buffer.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Write {
                ino,
                offset,
                length,
                data_hash,
            } => {
                buf.push(RECORD_DISCRIMINANT_WRITE);
                buf.extend_from_slice(&ino.to_le_bytes());
                buf.extend_from_slice(&offset.to_le_bytes());
                buf.extend_from_slice(&length.to_le_bytes());
                buf.extend_from_slice(data_hash);
            }
            Self::Truncate { ino, new_size } => {
                buf.push(RECORD_DISCRIMINANT_TRUNCATE);
                buf.extend_from_slice(&ino.to_le_bytes());
                buf.extend_from_slice(&new_size.to_le_bytes());
            }
            Self::Setattr {
                ino,
                attr_mask,
                attrs,
            } => {
                buf.push(RECORD_DISCRIMINANT_SETATTR);
                buf.extend_from_slice(&ino.to_le_bytes());
                buf.extend_from_slice(&attr_mask.to_le_bytes());
                buf.extend_from_slice(attrs);
            }
            Self::Create {
                parent,
                name,
                mode,
                ino,
            } => {
                buf.push(RECORD_DISCRIMINANT_CREATE);
                buf.extend_from_slice(&parent.to_le_bytes());
                encode_name(name, buf);
                buf.extend_from_slice(&mode.to_le_bytes());
                buf.extend_from_slice(&ino.to_le_bytes());
            }
            Self::Unlink { parent, name, ino } => {
                buf.push(RECORD_DISCRIMINANT_UNLINK);
                buf.extend_from_slice(&parent.to_le_bytes());
                encode_name(name, buf);
                buf.extend_from_slice(&ino.to_le_bytes());
            }
            Self::Rename {
                src_parent,
                src_name,
                dst_parent,
                dst_name,
                overwrite_target_ino,
                ino,
                rename_flags,
            } => {
                buf.push(RECORD_DISCRIMINANT_RENAME);
                buf.extend_from_slice(&src_parent.to_le_bytes());
                encode_name(src_name, buf);
                buf.extend_from_slice(&dst_parent.to_le_bytes());
                encode_name(dst_name, buf);
                // Encode optional overwrite target inode: 1-byte tag + optional 8 bytes
                if let Some(ow_ino) = overwrite_target_ino {
                    buf.push(1);
                    buf.extend_from_slice(&ow_ino.to_le_bytes());
                } else {
                    buf.push(0);
                }
                buf.extend_from_slice(&ino.to_le_bytes());
                // Append rename flags as 4-byte LE after ino
                buf.extend_from_slice(&rename_flags.to_le_bytes());
            }
            Self::Symlink {
                parent,
                name,
                target,
                ino,
            } => {
                buf.push(RECORD_DISCRIMINANT_SYMLINK);
                buf.extend_from_slice(&parent.to_le_bytes());
                encode_name(name, buf);
                encode_name(target, buf);
                buf.extend_from_slice(&ino.to_le_bytes());
            }
            Self::HardLink {
                ino,
                new_parent,
                new_name,
            } => {
                buf.push(RECORD_DISCRIMINANT_HARDLINK);
                buf.extend_from_slice(&ino.to_le_bytes());
                buf.extend_from_slice(&new_parent.to_le_bytes());
                encode_name(new_name, buf);
            }
            Self::Mkdir {
                parent,
                name,
                mode,
                ino,
            } => {
                buf.push(RECORD_DISCRIMINANT_MKDIR);
                buf.extend_from_slice(&parent.to_le_bytes());
                encode_name(name, buf);
                buf.extend_from_slice(&mode.to_le_bytes());
                buf.extend_from_slice(&ino.to_le_bytes());
            }
            Self::Rmdir { parent, name, ino } => {
                buf.push(RECORD_DISCRIMINANT_RMDIR);
                buf.extend_from_slice(&parent.to_le_bytes());
                encode_name(name, buf);
                buf.extend_from_slice(&ino.to_le_bytes());
            }
            Self::Mknod {
                parent,
                name,
                mode,
                rdev,
                ino,
            } => {
                buf.push(RECORD_DISCRIMINANT_MKNOD);
                buf.extend_from_slice(&parent.to_le_bytes());
                encode_name(name, buf);
                buf.extend_from_slice(&mode.to_le_bytes());
                buf.extend_from_slice(&rdev.to_le_bytes());
                buf.extend_from_slice(&ino.to_le_bytes());
            }
            Self::XattrSet {
                ino,
                namespace,
                key_hash,
                value_hash,
            } => {
                buf.push(RECORD_DISCRIMINANT_XATTRSET);
                buf.extend_from_slice(&ino.to_le_bytes());
                buf.push(namespace.to_byte());
                buf.extend_from_slice(key_hash);
                buf.extend_from_slice(value_hash);
            }
            Self::XattrRemove {
                ino,
                namespace,
                key_hash,
            } => {
                buf.push(RECORD_DISCRIMINANT_XATTRREMOVE);
                buf.extend_from_slice(&ino.to_le_bytes());
                buf.push(namespace.to_byte());
                buf.extend_from_slice(key_hash);
            }
            Self::Flush {
                ino,
                fh,
                lock_owner,
            } => {
                buf.push(RECORD_DISCRIMINANT_FLUSH);
                buf.extend_from_slice(&ino.to_le_bytes());
                buf.extend_from_slice(&fh.to_le_bytes());
                buf.extend_from_slice(&lock_owner.to_le_bytes());
            }
            Self::Fallocate {
                ino,
                offset,
                length,
                mode,
            } => {
                buf.push(RECORD_DISCRIMINANT_FALLOCATE);
                buf.extend_from_slice(&ino.to_le_bytes());
                buf.extend_from_slice(&offset.to_le_bytes());
                buf.extend_from_slice(&length.to_le_bytes());
                buf.extend_from_slice(&mode.to_le_bytes());
            }
            Self::BufferedWrite {
                ino,
                offset,
                length,
                data,
            } => {
                buf.push(RECORD_DISCRIMINANT_BUFFERED_WRITE);
                buf.extend_from_slice(&ino.to_le_bytes());
                buf.extend_from_slice(&offset.to_le_bytes());
                buf.extend_from_slice(&length.to_le_bytes());
                let data_len = data.len().min(65535) as u16;
                buf.extend_from_slice(&data_len.to_le_bytes());
                buf.extend_from_slice(data);
            }

            Self::WriteIntentAck {
                ino,

                offset,

                length,
            } => {
                buf.push(RECORD_DISCRIMINANT_WRITE_INTENT_ACK);

                buf.extend_from_slice(&ino.to_le_bytes());

                buf.extend_from_slice(&offset.to_le_bytes());

                buf.extend_from_slice(&length.to_le_bytes());
            }
            Self::Tmpfile { parent, mode, ino } => {
                buf.push(RECORD_DISCRIMINANT_TMPFILE);
                buf.extend_from_slice(&parent.to_le_bytes());
                buf.extend_from_slice(&mode.to_le_bytes());
                buf.extend_from_slice(&ino.to_le_bytes());
            }

            Self::Lseek {
                ino,
                whence,
                offset,
                result,
            } => {
                buf.push(RECORD_DISCRIMINANT_LSEEK);
                buf.extend_from_slice(&ino.to_le_bytes());
                buf.push(*whence);
                buf.extend_from_slice(&offset.to_le_bytes());
                buf.extend_from_slice(&result.to_le_bytes());
            }
            Self::Fsync { ino, fh, mode } => {
                buf.push(RECORD_DISCRIMINANT_FSYNC);
                buf.extend_from_slice(&ino.to_le_bytes());
                buf.extend_from_slice(&fh.to_le_bytes());
                buf.push(*mode);
            }

            Self::CleanupQueue {
                entry_id,
                device_id,
                physical_offset,
                length,
                blake3_hash,
                freed_at_txg,
                cleanup_status,
                retry_count,
            } => {
                buf.push(RECORD_DISCRIMINANT_CLEANUP_QUEUE);
                buf.extend_from_slice(&entry_id.to_le_bytes());
                buf.extend_from_slice(&device_id.to_le_bytes());
                buf.extend_from_slice(&physical_offset.to_le_bytes());
                buf.extend_from_slice(&length.to_le_bytes());
                buf.extend_from_slice(blake3_hash);
                buf.extend_from_slice(&freed_at_txg.to_le_bytes());
                buf.push(*cleanup_status);
                buf.push(*retry_count);
            }
            Self::CopyFileRange {
                src_ino,
                src_fh,
                dst_ino,
                dst_fh,
                src_offset,
                dst_offset,
                len,
            } => {
                buf.push(RECORD_DISCRIMINANT_COPY_FILE_RANGE);
                buf.extend_from_slice(&src_ino.to_le_bytes());
                buf.extend_from_slice(&src_fh.to_le_bytes());
                buf.extend_from_slice(&dst_ino.to_le_bytes());
                buf.extend_from_slice(&dst_fh.to_le_bytes());
                buf.extend_from_slice(&src_offset.to_le_bytes());
                buf.extend_from_slice(&dst_offset.to_le_bytes());
                buf.extend_from_slice(&len.to_le_bytes());
            }
            Self::TxBegin { cg_id } => {
                buf.push(RECORD_DISCRIMINANT_TX_BEGIN);
                buf.extend_from_slice(&cg_id.to_le_bytes());
            }
            Self::TxCommit { cg_id } => {
                buf.push(RECORD_DISCRIMINANT_TX_COMMIT);
                buf.extend_from_slice(&cg_id.to_le_bytes());
            }
            Self::TxAbort { cg_id } => {
                buf.push(RECORD_DISCRIMINANT_TX_ABORT);
                buf.extend_from_slice(&cg_id.to_le_bytes());
            }
            Self::ExportTerminal { cg_id } => {
                buf.push(RECORD_DISCRIMINANT_EXPORT_TERMINAL);
                buf.extend_from_slice(&cg_id.to_le_bytes());
            }
        }
    }

    // ── Decoding ───────────────────────────────────────────────────

    /// Deserialize a record from bytes.
    ///
    /// Returns `IntentLogError::BufferTooShort` if the buffer is too small
    /// or `IntentLogError::UnknownDiscriminant` if the first byte is invalid.
    pub fn decode(buf: &[u8]) -> Result<Self, IntentLogError> {
        if buf.is_empty() {
            return Err(IntentLogError::BufferTooShort);
        }
        let mut pos = 1; // skip discriminant
        match buf[0] {
            RECORD_DISCRIMINANT_WRITE => {
                ensure_len(buf, pos + 8 + 8 + 8 + 32)?;
                let ino = read_u64_le(buf, &mut pos);
                let offset = read_u64_le(buf, &mut pos);
                let length = read_u64_le(buf, &mut pos);
                let mut data_hash = [0u8; 32];
                data_hash.copy_from_slice(&buf[pos..pos + 32]);
                Ok(Self::Write {
                    ino,
                    offset,
                    length,
                    data_hash,
                })
            }
            RECORD_DISCRIMINANT_TRUNCATE => {
                ensure_len(buf, pos + 8 + 8)?;
                let ino = read_u64_le(buf, &mut pos);
                let new_size = read_u64_le(buf, &mut pos);
                Ok(Self::Truncate { ino, new_size })
            }
            RECORD_DISCRIMINANT_SETATTR => {
                ensure_len(buf, pos + 8 + 8 + 64)?;
                let ino = read_u64_le(buf, &mut pos);
                let attr_mask = read_u64_le(buf, &mut pos);
                let mut attrs = [0u8; 64];
                attrs.copy_from_slice(&buf[pos..pos + 64]);
                Ok(Self::Setattr {
                    ino,
                    attr_mask,
                    attrs,
                })
            }
            RECORD_DISCRIMINANT_CREATE => {
                let parent = read_u64_le(buf, &mut pos);
                let name = decode_name(buf, &mut pos)?;
                ensure_len(buf, pos + 4 + 8)?;
                let mode = read_u32_le(buf, &mut pos);
                let ino = read_u64_le(buf, &mut pos);
                Ok(Self::Create {
                    parent,
                    name,
                    mode,
                    ino,
                })
            }
            RECORD_DISCRIMINANT_UNLINK => {
                let parent = read_u64_le(buf, &mut pos);
                let name = decode_name(buf, &mut pos)?;
                ensure_len(buf, pos + 8)?;
                let ino = read_u64_le(buf, &mut pos);
                Ok(Self::Unlink { parent, name, ino })
            }
            RECORD_DISCRIMINANT_RENAME => {
                let src_parent = read_u64_le(buf, &mut pos);
                let src_name = decode_name(buf, &mut pos)?;
                let dst_parent = read_u64_le(buf, &mut pos);
                let dst_name = decode_name(buf, &mut pos)?;
                // Optional overwrite target inode: 1-byte tag + optional 8 bytes
                ensure_len(buf, pos + 1)?;
                let has_overwrite = buf[pos] != 0;
                pos += 1;
                let overwrite_target_ino = if has_overwrite {
                    ensure_len(buf, pos + 8)?;
                    Some(read_u64_le(buf, &mut pos))
                } else {
                    None
                };
                ensure_len(buf, pos + 8)?;
                let ino = read_u64_le(buf, &mut pos);
                ensure_len(buf, pos + 4)?;
                let rename_flags = read_u32_le(buf, &mut pos);
                Ok(Self::Rename {
                    src_parent,
                    src_name,
                    dst_parent,
                    dst_name,
                    overwrite_target_ino,
                    ino,
                    rename_flags,
                })
            }
            RECORD_DISCRIMINANT_SYMLINK => {
                let parent = read_u64_le(buf, &mut pos);
                let name = decode_name(buf, &mut pos)?;
                let target = decode_name(buf, &mut pos)?;
                ensure_len(buf, pos + 8)?;
                let ino = read_u64_le(buf, &mut pos);
                Ok(Self::Symlink {
                    parent,
                    name,
                    target,
                    ino,
                })
            }
            RECORD_DISCRIMINANT_HARDLINK => {
                let ino = read_u64_le(buf, &mut pos);
                let new_parent = read_u64_le(buf, &mut pos);
                let new_name = decode_name(buf, &mut pos)?;
                Ok(Self::HardLink {
                    ino,
                    new_parent,
                    new_name,
                })
            }
            RECORD_DISCRIMINANT_MKDIR => {
                let parent = read_u64_le(buf, &mut pos);
                let name = decode_name(buf, &mut pos)?;
                ensure_len(buf, pos + 4 + 8)?;
                let mode = read_u32_le(buf, &mut pos);
                let ino = read_u64_le(buf, &mut pos);
                Ok(Self::Mkdir {
                    parent,
                    name,
                    mode,
                    ino,
                })
            }
            RECORD_DISCRIMINANT_RMDIR => {
                let parent = read_u64_le(buf, &mut pos);
                let name = decode_name(buf, &mut pos)?;
                ensure_len(buf, pos + 8)?;
                let ino = read_u64_le(buf, &mut pos);
                Ok(Self::Rmdir { parent, name, ino })
            }
            RECORD_DISCRIMINANT_MKNOD => {
                let parent = read_u64_le(buf, &mut pos);
                let name = decode_name(buf, &mut pos)?;
                ensure_len(buf, pos + 4 + 8 + 8)?;
                let mode = read_u32_le(buf, &mut pos);
                let rdev = read_u64_le(buf, &mut pos);
                let ino = read_u64_le(buf, &mut pos);
                Ok(Self::Mknod {
                    parent,
                    name,
                    mode,
                    rdev,
                    ino,
                })
            }
            RECORD_DISCRIMINANT_XATTRSET => {
                ensure_len(buf, pos + 8 + 1 + 32 + 32)?;
                let ino = read_u64_le(buf, &mut pos);
                let namespace = XattrNamespace::from_byte(buf[pos])?;
                pos += 1;
                let mut key_hash = [0u8; 32];
                key_hash.copy_from_slice(&buf[pos..pos + 32]);
                pos += 32;
                let mut value_hash = [0u8; 32];
                value_hash.copy_from_slice(&buf[pos..pos + 32]);
                Ok(Self::XattrSet {
                    ino,
                    namespace,
                    key_hash,
                    value_hash,
                })
            }
            RECORD_DISCRIMINANT_XATTRREMOVE => {
                ensure_len(buf, pos + 8 + 1 + 32)?;
                let ino = read_u64_le(buf, &mut pos);
                let namespace = XattrNamespace::from_byte(buf[pos])?;
                pos += 1;
                let mut key_hash = [0u8; 32];
                key_hash.copy_from_slice(&buf[pos..pos + 32]);
                Ok(Self::XattrRemove {
                    ino,
                    namespace,
                    key_hash,
                })
            }
            RECORD_DISCRIMINANT_FLUSH => {
                ensure_len(buf, pos + 8 + 8 + 8)?;
                let ino = read_u64_le(buf, &mut pos);
                let fh = read_u64_le(buf, &mut pos);
                let lock_owner = read_u64_le(buf, &mut pos);
                Ok(Self::Flush {
                    ino,
                    fh,
                    lock_owner,
                })
            }
            RECORD_DISCRIMINANT_FALLOCATE => {
                ensure_len(buf, pos + 8 + 8 + 8 + 4)?;
                let ino = read_u64_le(buf, &mut pos);
                let offset = read_u64_le(buf, &mut pos);
                let length = read_u64_le(buf, &mut pos);
                let mode = read_i32_le(buf, &mut pos);
                Ok(Self::Fallocate {
                    ino,
                    offset,
                    length,
                    mode,
                })
            }
            RECORD_DISCRIMINANT_BUFFERED_WRITE => {
                ensure_len(buf, pos + 8 + 8 + 8 + 2)?;
                let ino = read_u64_le(buf, &mut pos);
                let offset = read_u64_le(buf, &mut pos);
                let length = read_u64_le(buf, &mut pos);
                let data_len = read_u16_le(buf, &mut pos) as usize;
                ensure_len(buf, pos + data_len)?;
                let data = buf[pos..pos + data_len].to_vec();
                Ok(Self::BufferedWrite {
                    ino,
                    offset,
                    length,
                    data,
                })
            }
            RECORD_DISCRIMINANT_WRITE_INTENT_ACK => {
                ensure_len(buf, pos + 8 + 8 + 8)?;

                let ino = read_u64_le(buf, &mut pos);

                let offset = read_u64_le(buf, &mut pos);

                let length = read_u64_le(buf, &mut pos);

                Ok(Self::WriteIntentAck {
                    ino,

                    offset,

                    length,
                })
            }
            RECORD_DISCRIMINANT_TMPFILE => {
                ensure_len(buf, pos + 8 + 4 + 8)?;
                let parent = read_u64_le(buf, &mut pos);
                let mode = read_u32_le(buf, &mut pos);
                let ino = read_u64_le(buf, &mut pos);
                Ok(Self::Tmpfile { parent, mode, ino })
            }
            RECORD_DISCRIMINANT_LSEEK => {
                ensure_len(buf, pos + 8 + 1 + 8 + 8)?;
                let ino = read_u64_le(buf, &mut pos);
                let whence = buf[pos];
                pos += 1;
                let offset = read_u64_le(buf, &mut pos);
                let result = read_u64_le(buf, &mut pos);
                Ok(Self::Lseek {
                    ino,
                    whence,
                    offset,
                    result,
                })
            }
            RECORD_DISCRIMINANT_FSYNC => {
                ensure_len(buf, pos + 8 + 8 + 1)?;
                let ino = read_u64_le(buf, &mut pos);
                let fh = read_u64_le(buf, &mut pos);
                let mode = buf[pos];
                Ok(Self::Fsync { ino, fh, mode })
            }

            RECORD_DISCRIMINANT_CLEANUP_QUEUE => {
                ensure_len(buf, pos + 8 + 8 + 8 + 8 + 32 + 8 + 1 + 1)?;
                let entry_id = read_u64_le(buf, &mut pos);
                let device_id = read_u64_le(buf, &mut pos);
                let physical_offset = read_u64_le(buf, &mut pos);
                let length = read_u64_le(buf, &mut pos);
                let mut blake3_hash = [0u8; 32];
                blake3_hash.copy_from_slice(&buf[pos..pos + 32]);
                pos += 32;
                let freed_at_txg = read_u64_le(buf, &mut pos);
                let cleanup_status = buf[pos];
                pos += 1;
                let retry_count = buf[pos];
                Ok(Self::CleanupQueue {
                    entry_id,
                    device_id,
                    physical_offset,
                    length,
                    blake3_hash,
                    freed_at_txg,
                    cleanup_status,
                    retry_count,
                })
            }
            RECORD_DISCRIMINANT_COPY_FILE_RANGE => {
                ensure_len(buf, pos + 8 + 8 + 8 + 8 + 8 + 8 + 8)?;
                let src_ino = read_u64_le(buf, &mut pos);
                let src_fh = read_u64_le(buf, &mut pos);
                let dst_ino = read_u64_le(buf, &mut pos);
                let dst_fh = read_u64_le(buf, &mut pos);
                let src_offset = read_u64_le(buf, &mut pos);
                let dst_offset = read_u64_le(buf, &mut pos);
                let len = read_u64_le(buf, &mut pos);
                Ok(Self::CopyFileRange {
                    src_ino,
                    src_fh,
                    dst_ino,
                    dst_fh,
                    src_offset,
                    dst_offset,
                    len,
                })
            }
            RECORD_DISCRIMINANT_TX_BEGIN => {
                ensure_len(buf, pos + 8)?;
                let cg_id = read_u64_le(buf, &mut pos);
                Ok(Self::TxBegin { cg_id })
            }
            RECORD_DISCRIMINANT_TX_COMMIT => {
                ensure_len(buf, pos + 8)?;
                let cg_id = read_u64_le(buf, &mut pos);
                Ok(Self::TxCommit { cg_id })
            }
            RECORD_DISCRIMINANT_TX_ABORT => {
                ensure_len(buf, pos + 8)?;
                let cg_id = read_u64_le(buf, &mut pos);
                Ok(Self::TxAbort { cg_id })
            }
            RECORD_DISCRIMINANT_EXPORT_TERMINAL => {
                ensure_len(buf, pos + 8)?;
                let cg_id = read_u64_le(buf, &mut pos);
                Ok(Self::ExportTerminal { cg_id })
            }
            d => Err(IntentLogError::UnknownDiscriminant { discriminant: d }),
        }
    }
}

// ── Helper functions ──────────────────────────────────────────────────

/// Encode a name as length-prefixed bytes (1-byte length, then data).
fn encode_name(name: &[u8], buf: &mut Vec<u8>) {
    let len = name.len().min(255);
    buf.push(len as u8);
    buf.extend_from_slice(&name[..len]);
}

/// Decode a length-prefixed name from the buffer, advancing `pos`.
fn decode_name(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>, IntentLogError> {
    if *pos >= buf.len() {
        return Err(IntentLogError::BufferTooShort);
    }
    let len = buf[*pos] as usize;
    *pos += 1;
    if *pos + len > buf.len() {
        return Err(IntentLogError::BufferTooShort);
    }
    let name = buf[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(name)
}

/// Ensure the buffer has at least `required` bytes available at `buf.len()`.
fn ensure_len(buf: &[u8], required: usize) -> Result<(), IntentLogError> {
    if buf.len() < required {
        Err(IntentLogError::BufferTooShort)
    } else {
        Ok(())
    }
}

fn read_u64_le(buf: &[u8], pos: &mut usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[*pos..*pos + 8]);
    *pos += 8;
    u64::from_le_bytes(bytes)
}

fn read_u16_le(buf: &[u8], pos: &mut usize) -> u16 {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&buf[*pos..*pos + 2]);
    *pos += 2;
    u16::from_le_bytes(bytes)
}

fn read_u32_le(buf: &[u8], pos: &mut usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[*pos..*pos + 4]);
    *pos += 4;
    u32::from_le_bytes(bytes)
}

fn read_i32_le(buf: &[u8], pos: &mut usize) -> i32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[*pos..*pos + 4]);
    *pos += 4;
    i32::from_le_bytes(bytes)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xattr_namespace_roundtrip() {
        for ns in &[
            XattrNamespace::Security,
            XattrNamespace::System,
            XattrNamespace::Trusted,
            XattrNamespace::User,
        ] {
            let b = ns.to_byte();
            let decoded = XattrNamespace::from_byte(b).unwrap();
            assert_eq!(*ns, decoded);
        }
    }
    #[test]
    fn xattr_remove_encode_decode_roundtrip() {
        let rec = IntentLogRecord::XattrRemove {
            ino: 42,
            namespace: XattrNamespace::Security,
            key_hash: [0x11; 32],
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn xattr_namespace_invalid_byte() {
        assert!(XattrNamespace::from_byte(0).is_err());
        assert!(XattrNamespace::from_byte(5).is_err());
        assert!(XattrNamespace::from_byte(255).is_err());
    }

    #[test]
    fn all_variants_have_unique_discriminants() {
        let records = vec![
            IntentLogRecord::Write {
                ino: 1,
                offset: 0,
                length: 0,
                data_hash: [0; 32],
            },
            IntentLogRecord::Truncate {
                ino: 1,
                new_size: 0,
            },
            IntentLogRecord::Setattr {
                ino: 1,
                attr_mask: 0,
                attrs: [0; 64],
            },
            IntentLogRecord::Create {
                parent: 1,
                name: b"f".to_vec(),
                mode: 0,
                ino: 2,
            },
            IntentLogRecord::Unlink {
                parent: 1,
                name: b"f".to_vec(),
                ino: 2,
            },
            IntentLogRecord::Rename {
                src_parent: 1,
                src_name: b"a".to_vec(),
                dst_parent: 2,
                dst_name: b"b".to_vec(),
                overwrite_target_ino: None,
                ino: 3,
                rename_flags: 0,
            },
            IntentLogRecord::Symlink {
                parent: 1,
                name: b"l".to_vec(),
                target: b"t".to_vec(),
                ino: 4,
            },
            IntentLogRecord::HardLink {
                ino: 1,
                new_parent: 2,
                new_name: b"h".to_vec(),
            },
            IntentLogRecord::Mkdir {
                parent: 1,
                name: b"d".to_vec(),
                mode: 0o755,
                ino: 5,
            },
            IntentLogRecord::Rmdir {
                parent: 1,
                name: b"d".to_vec(),
                ino: 5,
            },
            IntentLogRecord::Mknod {
                parent: 1,
                name: b"n".to_vec(),
                mode: 0o660,
                rdev: 0,
                ino: 6,
            },
            IntentLogRecord::XattrSet {
                ino: 1,
                namespace: XattrNamespace::User,
                key_hash: [0; 32],
                value_hash: [0; 32],
            },
            IntentLogRecord::XattrRemove {
                ino: 1,
                namespace: XattrNamespace::User,
                key_hash: [0; 32],
            },
            IntentLogRecord::Tmpfile {
                parent: 1,
                mode: 0o644,
                ino: 7,
            },
            IntentLogRecord::Flush {
                ino: 1,
                fh: 42,
                lock_owner: 1000,
            },
            IntentLogRecord::Fallocate {
                ino: 1,
                offset: 0,
                length: 4096,
                mode: 0,
            },
            IntentLogRecord::BufferedWrite {
                ino: 1,
                offset: 0,
                length: 4,
                data: b"test".to_vec(),
            },
            IntentLogRecord::Fsync {
                ino: 1,
                fh: 42,
                mode: 0,
            },
            IntentLogRecord::CleanupQueue {
                entry_id: 1,
                device_id: 100,
                physical_offset: 4096,
                length: 8192,
                blake3_hash: [0xAA; 32],
                freed_at_txg: 5,
                cleanup_status: 1,
                retry_count: 0,
            },
            IntentLogRecord::WriteIntentAck {
                ino: 1,

                offset: 0,

                length: 4,
            },
            IntentLogRecord::CopyFileRange {
                src_ino: 10,
                src_fh: 42,
                dst_ino: 20,
                dst_fh: 43,
                src_offset: 0,
                dst_offset: 100,
                len: 4096,
            },
            IntentLogRecord::TxBegin { cg_id: 1 },
            IntentLogRecord::TxCommit { cg_id: 1 },
            IntentLogRecord::TxAbort { cg_id: 1 },
            IntentLogRecord::ExportTerminal { cg_id: 99 },
        ];

        let mut seen = std::collections::HashSet::new();
        for rec in &records {
            let encoded = rec.encode();
            let disc = encoded[0];
            assert!(seen.insert(disc), "duplicate discriminant: {disc}");
        }
        assert_eq!(seen.len(), 25);
    }

    #[test]
    fn roundtrip_cleanup_queue() {
        let rec = IntentLogRecord::CleanupQueue {
            entry_id: 42,
            device_id: 7,
            physical_offset: 65536,
            length: 131072,
            blake3_hash: [0xBB; 32],
            freed_at_txg: 99,
            cleanup_status: 1,
            retry_count: 2,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_copy_file_range() {
        let rec = IntentLogRecord::CopyFileRange {
            src_ino: 100,
            src_fh: 42,
            dst_ino: 200,
            dst_fh: 43,
            src_offset: 1024,
            dst_offset: 2048,
            len: 65536,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_tx_begin() {
        let rec = IntentLogRecord::TxBegin { cg_id: 42 };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_tx_commit() {
        let rec = IntentLogRecord::TxCommit { cg_id: 7 };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_tx_abort() {
        let rec = IntentLogRecord::TxAbort { cg_id: 3 };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_export_terminal() {
        let rec = IntentLogRecord::ExportTerminal { cg_id: 99 };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn tx_begin_frame_verifies() {
        let rec = IntentLogRecord::TxBegin { cg_id: 1 };
        let frame = crate::IntentLogFrame::new(rec, 1, 0);
        assert!(frame.verify().is_ok());
    }

    #[test]
    fn decode_truncated_buffer() {
        // Write needs 1 + 8 + 8 + 8 + 32 = 57 bytes
        let buf = vec![RECORD_DISCRIMINANT_WRITE, 0, 0, 0]; // too short
        assert_eq!(
            IntentLogRecord::decode(&buf).unwrap_err(),
            IntentLogError::BufferTooShort
        );
    }

    #[test]
    fn decode_truncated_name() {
        // Create: 1 + 8 + (1 + 5) + 4 + 8 = 27 bytes for a 5-byte name
        // Construct a buffer that claims 5-byte name but only has 2 bytes
        let mut buf = vec![RECORD_DISCRIMINANT_CREATE];
        buf.extend_from_slice(&1u64.to_le_bytes()); // parent
        buf.push(5); // name length = 5
        buf.extend_from_slice(b"ab"); // only 2 bytes
        assert_eq!(
            IntentLogRecord::decode(&buf).unwrap_err(),
            IntentLogError::BufferTooShort
        );
    }
}
