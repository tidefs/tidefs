// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg_attr(all(feature = "kernel-io", not(feature = "std")), no_std)]
#![forbid(unsafe_code)]

//! TideFS intent-log record types, BLAKE3-authenticated framing, and
//! lock-free in-memory append buffer.
//!
//! # Overview
//!
//! The intent log captures every mutating filesystem operation before it
//! commits. During two-phase commit, the [`CommitGroupCoordinator`] drains the
//! [`IntentLogBuffer`], anchors the frames into the commit group, and
//! writes them to stable storage via [`IntentLogWriter`]. On crash
//! recovery, [`IntentLogReader`] reads the segments back and replays
//! uncommitted operations.
//!
//! # Architecture
//!
//! ```text
//! FUSE write/setattr/create/unlink/... → IntentLogBuffer::append()
//!                                              │
//!                                              ▼
//!                                    IntentLogFrame { record, txg_id,
//!                                                      record_seq, checksum }
//!                                              │
//!                           CommitGroupCoordinator::prepare() drains frames
//!                                              │
//!                                              ▼
//!                           IntentLogWriter → on-disk segment (BLAKE3)
//!                                              │
//!                           Crash? → IntentLogReader → replay records
//! ```
//!
//! # Record Types
//!
//! [`IntentLogRecord`] covers all 15 mutating filesystem operations:
//! write, truncate, setattr, create, unlink, rename, symlink, hard-link,
//! mkdir, rmdir, mknod, xattr-set, and fallocate.
//!
//! # Integrity
//!
//! Every [`IntentLogFrame`] carries a BLAKE3-256 checksum computed over the
//! serialized record, `txg_id`, and `record_seq`. Domain separation prevents
//! cross-type collisions.
//!
//! # On-Disk Format
//!
//! The [`segment`] module defines the durable segment layout with
//! BLAKE3-authenticated headers, per-record checksums, and a footer with a
//! record index for fast replay. [`IntentLogWriter`] appends frames to
//! segments with automatic rotation at the configured maximum size.
//! [`IntentLogReader`] reads segments and handles crash recovery: fully
//! committed segments replay all records; truncated segments replay up to
//! the last valid record checksum.
//!
//! # Segment Lifecycle
//!
//! Segments are identified by their LSN range (see [`SegmentHeader`]).
//! After a TXG commits, segments whose entire LSN range falls below the
//! committed LSN can be trimmed (see [`trimming`]).

extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(feature = "std")]
mod buffer;
#[cfg(feature = "std")]
pub mod compaction;
mod frame;
#[cfg(feature = "kernel-io")]
pub mod kernel_reader;
#[cfg(feature = "kernel-io")]
pub mod kernel_writer;
#[cfg(feature = "std")]
mod log;
#[cfg(feature = "std")]
pub mod reader;
mod record;
#[cfg(feature = "std")]
pub mod replay;
#[cfg(feature = "std")]
pub mod segment;
#[cfg(feature = "std")]
pub mod trimming;
#[cfg(feature = "std")]
pub mod writer;

#[cfg(all(feature = "replication", feature = "std"))]
pub mod replication_bridge;

#[cfg(feature = "std")]
pub use buffer::IntentLogBuffer;
#[cfg(feature = "std")]
pub use compaction::{compact_on_disk, CompactionResult, CompactionStats, IntentLogCompactor};
pub use frame::IntentLogFrame;
#[cfg(feature = "kernel-io")]
pub use kernel_reader::{
    IntentLogKernelScanner, KernelScanError, KernelScannedRecord, RedoCallback,
    DEFAULT_KERNEL_SCAN_MAX_FRAME_BYTES,
};
#[cfg(feature = "kernel-io")]
pub use kernel_writer::{
    decode_sector_aligned_frame, sector_aligned_frame_len, IntentLogKernelAppend,
    IntentLogKernelWriter, KernelIntentFlush,
};
#[cfg(feature = "std")]
pub use log::{IntentLog, IntentLogStats};
#[cfg(feature = "std")]
pub use reader::{FilteredReadResult, IntentLogReader, SegmentReadResult, SegmentRecord};
pub use record::{IntentLogRecord, XattrNamespace};
#[cfg(feature = "std")]
pub use record_verification::RecordRoundtrip;
#[cfg(feature = "std")]
pub use replay::{
    IntentReplayEngine, IntentReplayHandler, ReplayCheckpoint, ReplayError, ReplayState,
    SegmentReplayOutcome, SkippedReason,
};
#[cfg(feature = "std")]
pub use segment::{
    RecordIndexEntry, SegmentFooter, SegmentHeader, SEGMENT_HEADER_SIZE, SEGMENT_MAGIC,
    SEGMENT_VERSION,
};
#[cfg(feature = "std")]
pub use trimming::{earliest_retained_lsn, is_sealed, segments_to_trim};
#[cfg(feature = "std")]
pub use writer::IntentLogWriter;

// ── Canonical discriminant values (stable, do not reorder) ────────────

/// Discriminant for [`IntentLogRecord::Write`].
pub const RECORD_DISCRIMINANT_WRITE: u8 = 1;
/// Discriminant for [`IntentLogRecord::Truncate`].
pub const RECORD_DISCRIMINANT_TRUNCATE: u8 = 2;
/// Discriminant for [`IntentLogRecord::Setattr`].
pub const RECORD_DISCRIMINANT_SETATTR: u8 = 3;
/// Discriminant for [`IntentLogRecord::Create`].
pub const RECORD_DISCRIMINANT_CREATE: u8 = 4;
/// Discriminant for [`IntentLogRecord::Unlink`].
pub const RECORD_DISCRIMINANT_UNLINK: u8 = 5;
/// Discriminant for [`IntentLogRecord::Rename`].
pub const RECORD_DISCRIMINANT_RENAME: u8 = 6;
/// Discriminant for [`IntentLogRecord::Symlink`].
pub const RECORD_DISCRIMINANT_SYMLINK: u8 = 7;
/// Discriminant for [`IntentLogRecord::HardLink`].
pub const RECORD_DISCRIMINANT_HARDLINK: u8 = 8;
/// Discriminant for [`IntentLogRecord::Mkdir`].
pub const RECORD_DISCRIMINANT_MKDIR: u8 = 9;
/// Discriminant for [`IntentLogRecord::Rmdir`].
pub const RECORD_DISCRIMINANT_RMDIR: u8 = 10;
/// Discriminant for [`IntentLogRecord::Mknod`].
pub const RECORD_DISCRIMINANT_MKNOD: u8 = 11;
/// Discriminant for [`IntentLogRecord::XattrSet`].
pub const RECORD_DISCRIMINANT_XATTRSET: u8 = 12;
/// Discriminant for [`IntentLogRecord::Fallocate`].
pub const RECORD_DISCRIMINANT_FALLOCATE: u8 = 13;
/// Discriminant for [`IntentLogRecord::BufferedWrite`].
pub const RECORD_DISCRIMINANT_BUFFERED_WRITE: u8 = 14;
/// Discriminant for [`IntentLogRecord::WriteIntentAck`].
pub const RECORD_DISCRIMINANT_WRITE_INTENT_ACK: u8 = 15;
/// Discriminant for [`IntentLogRecord::XattrRemove`].
pub const RECORD_DISCRIMINANT_XATTRREMOVE: u8 = 16;
/// IntentLogRecord::Fsync discriminant.
pub const RECORD_DISCRIMINANT_FSYNC: u8 = 20;

/// O_TMPFILE unnamed temporary file creation.
pub const RECORD_DISCRIMINANT_TMPFILE: u8 = 17;

/// Discriminant for [`IntentLogRecord::Flush`].
pub const RECORD_DISCRIMINANT_FLUSH: u8 = 18;

/// Discriminant for [`IntentLogRecord::Lseek`].
///
/// Reserved for future crash-safe hole-punch/zero-range interaction tracing.
pub const RECORD_DISCRIMINANT_LSEEK: u8 = 19;

/// Discriminant for [`IntentLogRecord::CleanupQueue`].
pub const RECORD_DISCRIMINANT_CLEANUP_QUEUE: u8 = 21;

/// Discriminant for [`IntentLogRecord::CopyFileRange`].
///
/// Records copy_file_range operations for crash-recovery replay.
pub const RECORD_DISCRIMINANT_COPY_FILE_RANGE: u8 = 22;

/// Discriminant for [`IntentLogRecord::TxBegin`].
///
/// Marks the start of a transaction group boundary in the intent log.
pub const RECORD_DISCRIMINANT_TX_BEGIN: u8 = 23;

/// Discriminant for [`IntentLogRecord::TxCommit`].
///
/// Marks the successful commit of a transaction group.
pub const RECORD_DISCRIMINANT_TX_COMMIT: u8 = 24;

/// Discriminant for [`IntentLogRecord::TxAbort`].
///
/// Marks the rollback/abort of a transaction group.
pub const RECORD_DISCRIMINANT_TX_ABORT: u8 = 25;

/// Discriminant for [`IntentLogRecord::ExportTerminal`].
///
/// Clean shutdown marker written at pool export time.
pub const RECORD_DISCRIMINANT_EXPORT_TERMINAL: u8 = 26;
// ── Error type ────────────────────────────────────────────────────────

/// Errors produced by intent-log operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentLogError {
    /// The encoded record buffer is too short to contain valid data.
    BufferTooShort,
    /// The record discriminant byte does not match any known variant.
    UnknownDiscriminant { discriminant: u8 },
    /// A BLAKE3 checksum mismatch was detected during verification.
    ChecksumMismatch,
    /// A string field exceeds the maximum allowed length (255 bytes).
    StringTooLong,
}

impl core::fmt::Display for IntentLogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooShort => write!(f, "buffer too short for intent-log record"),
            Self::UnknownDiscriminant { discriminant } => {
                write!(f, "unknown intent-log record discriminant: {discriminant}")
            }
            Self::ChecksumMismatch => write!(f, "intent-log frame checksum mismatch"),
            Self::StringTooLong => write!(f, "intent-log string field exceeds 255 bytes"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IntentLogError {}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
pub mod record_verification;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // ── Round-trip encode/decode for every record variant ─────────

    #[test]
    fn roundtrip_write() {
        let rec = IntentLogRecord::Write {
            ino: 42,
            offset: 4096,
            length: 1024,
            data_hash: [0xAA; 32],
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_truncate() {
        let rec = IntentLogRecord::Truncate {
            ino: 7,
            new_size: 1048576,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_setattr() {
        let rec = IntentLogRecord::Setattr {
            ino: 100,
            attr_mask: 0xFFFF,
            attrs: [0x42; 64],
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_create() {
        let rec = IntentLogRecord::Create {
            parent: 1,
            name: b"hello.txt".to_vec(),
            mode: 0o644,
            ino: 42,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_unlink() {
        let rec = IntentLogRecord::Unlink {
            parent: 1,
            name: b"stale.log".to_vec(),
            ino: 99,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_rename() {
        let rec = IntentLogRecord::Rename {
            src_parent: 1,
            src_name: b"old.txt".to_vec(),
            dst_parent: 2,
            dst_name: b"new.txt".to_vec(),
            overwrite_target_ino: None,
            ino: 55,
            rename_flags: 0,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_rename_with_overwrite() {
        let rec = IntentLogRecord::Rename {
            src_parent: 1,
            src_name: b"old.txt".to_vec(),
            dst_parent: 2,
            dst_name: b"new.txt".to_vec(),
            overwrite_target_ino: Some(99),
            ino: 55,
            rename_flags: 0,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_rename_exchange() {
        let rec = IntentLogRecord::Rename {
            src_parent: 3,
            src_name: b"a.txt".to_vec(),
            dst_parent: 4,
            dst_name: b"b.txt".to_vec(),
            overwrite_target_ino: Some(77),
            ino: 55,
            rename_flags: 2,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
        // Verify flags roundtrip correctly
        match &decoded {
            IntentLogRecord::Rename { rename_flags, .. } => {
                assert_eq!(
                    *rename_flags, 2,
                    "RENAME_EXCHANGE flags must survive roundtrip"
                );
            }
            _ => panic!("expected Rename variant"),
        }
    }

    #[test]
    fn roundtrip_symlink() {
        let rec = IntentLogRecord::Symlink {
            parent: 1,
            name: b"link".to_vec(),
            target: b"/some/path".to_vec(),
            ino: 77,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_hardlink() {
        let rec = IntentLogRecord::HardLink {
            ino: 42,
            new_parent: 2,
            new_name: b"hardlink".to_vec(),
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_mkdir() {
        let rec = IntentLogRecord::Mkdir {
            parent: 1,
            name: b"subdir".to_vec(),
            mode: 0o755,
            ino: 50,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_rmdir() {
        let rec = IntentLogRecord::Rmdir {
            parent: 1,
            name: b"emptydir".to_vec(),
            ino: 50,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_mknod() {
        let rec = IntentLogRecord::Mknod {
            parent: 1,
            name: b"device".to_vec(),
            mode: 0o660,
            rdev: 0x0801,
            ino: 88,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_xattr_set() {
        let rec = IntentLogRecord::XattrSet {
            ino: 42,
            namespace: XattrNamespace::Security,
            key_hash: [0x11; 32],
            value_hash: [0x22; 32],
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_xattr_remove() {
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
    fn roundtrip_fallocate() {
        let rec = IntentLogRecord::Fallocate {
            ino: 33,
            offset: 0,
            length: 1_048_576,
            mode: 0,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_buffered_write() {
        let rec = IntentLogRecord::BufferedWrite {
            ino: 42,
            offset: 4096,
            length: 12,
            data: b"hello world!".to_vec(),
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_buffered_write_empty() {
        let rec = IntentLogRecord::BufferedWrite {
            ino: 1,
            offset: 0,
            length: 0,
            data: vec![],
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn buffered_write_frame_verifies() {
        let rec = IntentLogRecord::BufferedWrite {
            ino: 7,
            offset: 0,
            length: 6,
            data: b"foobar".to_vec(),
        };
        let frame = IntentLogFrame::new(rec, 1, 0);
        assert!(frame.verify().is_ok());
    }

    #[test]

    fn roundtrip_write_intent_ack() {
        let rec = IntentLogRecord::WriteIntentAck {
            ino: 42,

            offset: 4096,

            length: 1024,
        };

        let encoded = rec.encode();

        let decoded = IntentLogRecord::decode(&encoded).unwrap();

        assert_eq!(rec, decoded);
    }

    #[test]

    fn write_intent_ack_frame_verifies() {
        let rec = IntentLogRecord::WriteIntentAck {
            ino: 99,

            offset: 0,

            length: 65536,
        };

        let frame = IntentLogFrame::new(rec, 1, 0);

        assert!(frame.verify().is_ok());
    }
    // ── Decode error paths ────────────────────────────────────────

    #[test]
    fn decode_buffer_too_short() {
        let buf = [0u8; 0];
        assert_eq!(
            IntentLogRecord::decode(&buf).unwrap_err(),
            IntentLogError::BufferTooShort
        );
    }

    #[test]
    fn decode_unknown_discriminant() {
        let buf = [255u8];
        assert_eq!(
            IntentLogRecord::decode(&buf).unwrap_err(),
            IntentLogError::UnknownDiscriminant { discriminant: 255 }
        );
    }

    // ── Frame checksum verification ───────────────────────────────

    #[test]
    fn frame_checksum_verifies() {
        let rec = IntentLogRecord::Write {
            ino: 1,
            offset: 0,
            length: 256,
            data_hash: [0xAB; 32],
        };
        let frame = IntentLogFrame::new(rec, 1, 0);
        assert!(frame.verify().is_ok());
    }

    #[test]
    fn frame_tampered_record_detected() {
        let rec = IntentLogRecord::Write {
            ino: 1,
            offset: 0,
            length: 256,
            data_hash: [0xAB; 32],
        };
        let mut frame = IntentLogFrame::new(rec, 1, 0);
        // Tamper with txg_id via the record field
        let bad_rec = IntentLogRecord::Write {
            ino: 999,
            offset: 0,
            length: 256,
            data_hash: [0xAB; 32],
        };
        frame.record = bad_rec;
        assert_eq!(
            frame.verify().unwrap_err(),
            IntentLogError::ChecksumMismatch
        );
    }

    #[test]
    fn frame_tampered_txg_id_detected() {
        let rec = IntentLogRecord::Truncate {
            ino: 1,
            new_size: 100,
        };
        let mut frame = IntentLogFrame::new(rec, 1, 0);
        frame.txg_id = 999;
        assert_eq!(
            frame.verify().unwrap_err(),
            IntentLogError::ChecksumMismatch
        );
    }

    #[test]
    fn frame_tampered_seq_detected() {
        let rec = IntentLogRecord::Truncate {
            ino: 1,
            new_size: 100,
        };
        let mut frame = IntentLogFrame::new(rec, 1, 0);
        frame.record_seq = 999;
        assert_eq!(
            frame.verify().unwrap_err(),
            IntentLogError::ChecksumMismatch
        );
    }

    // ── IntentLogBuffer append/drain ordering ─────────────────────

    #[test]
    fn buffer_append_returns_frame_with_checksum() {
        let buf = IntentLogBuffer::new();
        let rec = IntentLogRecord::Mkdir {
            parent: 1,
            name: b"d".to_vec(),
            mode: 0o755,
            ino: 10,
        };
        let frame = buf.append(rec.clone(), 1);
        assert_eq!(frame.record, rec);
        assert_eq!(frame.txg_id, 1);
        assert_eq!(frame.record_seq, 0);
        assert!(frame.verify().is_ok());
    }

    #[test]
    fn buffer_drain_returns_appended_frames() {
        let buf = IntentLogBuffer::new();
        let r1 = IntentLogRecord::Create {
            parent: 1,
            name: b"a".to_vec(),
            mode: 0o644,
            ino: 10,
        };
        let r2 = IntentLogRecord::Create {
            parent: 1,
            name: b"b".to_vec(),
            mode: 0o644,
            ino: 11,
        };
        buf.append(r1.clone(), 1);
        buf.append(r2.clone(), 1);

        let frames = buf.drain_since(0);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].record_seq, 0);
        assert_eq!(frames[1].record_seq, 1);
    }

    #[test]
    fn buffer_drain_since_respects_seq() {
        let buf = IntentLogBuffer::new();
        for i in 0..5 {
            let rec = IntentLogRecord::Truncate {
                ino: i,
                new_size: 100,
            };
            buf.append(rec, 1);
        }
        // drain from seq 2 (inclusive) returns frames with seq >= 2
        let frames = buf.drain_since(2);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].record_seq, 2);
        assert_eq!(frames[1].record_seq, 3);
        assert_eq!(frames[2].record_seq, 4);
    }

    #[test]
    fn buffer_current_seq_increments() {
        let buf = IntentLogBuffer::new();
        assert_eq!(buf.current_seq(), 0);
        buf.append(
            IntentLogRecord::Truncate {
                ino: 1,
                new_size: 0,
            },
            1,
        );
        assert_eq!(buf.current_seq(), 1);
    }

    // ── Concurrent append stress ──────────────────────────────────

    #[test]
    fn concurrent_append_stress() {
        use std::sync::Arc;
        use std::thread;

        let buf = Arc::new(IntentLogBuffer::new());
        let n_threads = 4;
        let n_records = 1000;

        let mut handles = Vec::new();
        for t in 0..n_threads {
            let buf = Arc::clone(&buf);
            handles.push(thread::spawn(move || {
                for i in 0..n_records {
                    let rec = IntentLogRecord::Truncate {
                        ino: (t * 10000 + i) as u64,
                        new_size: i as u64,
                    };
                    buf.append(rec, 1);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let total = n_threads * n_records;
        assert_eq!(buf.current_seq() as usize, total);

        let frames = buf.drain_since(0);
        assert_eq!(frames.len(), total);

        // Verify every frame checksum is valid
        for frame in &frames {
            assert!(frame.verify().is_ok());
        }

        // Verify no duplicate seq numbers (seqs should be contiguous)
        let mut seqs: Vec<u64> = frames.iter().map(|f| f.record_seq).collect();
        seqs.sort();
        for (i, &s) in seqs.iter().enumerate() {
            assert_eq!(s, i as u64, "missing seq at position {i}");
        }
    }

    // ── String encoding round-trips ───────────────────────────────

    #[test]
    fn roundtrip_empty_name() {
        let rec = IntentLogRecord::Unlink {
            parent: 1,
            name: vec![],
            ino: 5,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_max_length_name() {
        let name = vec![b'x'; 255];
        let rec = IntentLogRecord::Create {
            parent: 1,
            name,
            mode: 0o644,
            ino: 10,
        };
        let encoded = rec.encode();
        let decoded = IntentLogRecord::decode(&encoded).unwrap();
        assert_eq!(rec, decoded);
    }
}
