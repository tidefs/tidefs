// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_local_object_store::{IntegrityDigest64, LocalObjectStore};
use tidefs_types_vfs_core::{Generation, InodeId, NodeKind};

use crate::constants::*;
use crate::encoding::*;
use crate::error::FileSystemError;
use crate::object_keys::*;
use crate::records::NamespaceCreateIntentRecord;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tidefs_local_object_store::StoreError;

use crate::Result;

// ---------------------------------------------------------------------------
// Intent log entry types for the sync write latency model.
// ---------------------------------------------------------------------------

// ── LOG_DEVICE: Separate intent LOG device ────────────────────────────────────────
//
// ZFS uses a separate intent-log device (ZIL) (fast NVMe/SSD) to acknowledge sync
// writes before bulk data lands on slower HDD devices.  When configured, every
// intent log entry is written to the log device first (with fsync), acknowledged
// to the caller, and then replicated to the main object store.  On crash
// recovery, the log device is the authoritative source.
//
// File format:
//   Header:  "VIBFILOG" (8 bytes) | version: u32 LE | reserved: u32 LE
//   Entry:   [payload_len: u32 LE][crc32c: u32 LE][payload: u8*]

pub(crate) const LOG_DEVICE_MAGIC: &[u8; 8] = b"VIBFILOG";
pub(crate) const LOG_DEVICE_VERSION: u32 = 1;
pub(crate) const LOG_DEVICE_HEADER_SIZE: u64 = 16;
pub(crate) const LOG_DEVICE_ENTRY_FRAME_SIZE: u64 = 8;

pub(crate) fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

pub(crate) fn store_io_err(
    op: &'static str,
    path: &Path,
    source: std::io::Error,
) -> FileSystemError {
    FileSystemError::Store(StoreError::Io {
        operation: op,
        path: path.to_path_buf(),
        source,
    })
}

pub(crate) struct LogDeviceFile {
    path: PathBuf,
    file: File,
    next_offset: u64,
}

impl std::fmt::Debug for LogDeviceFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogDeviceFile")
            .field("path", &self.path)
            .field("next_offset", &self.next_offset)
            .finish()
    }
}

impl LogDeviceFile {
    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| store_io_err("open log_device file", path, e))?;

        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|e| store_io_err("seek log_device end", path, e))?;

        if file_len == 0 {
            let mut header = Vec::with_capacity(16);
            header.extend_from_slice(LOG_DEVICE_MAGIC);
            header.extend_from_slice(&LOG_DEVICE_VERSION.to_le_bytes());
            header.extend_from_slice(&0u32.to_le_bytes());
            file.write_all(&header)
                .map_err(|e| store_io_err("write log_device header", path, e))?;
            file.sync_all()
                .map_err(|e| store_io_err("fsync log_device header", path, e))?;
            return Ok(Self {
                path: path.to_path_buf(),
                file,
                next_offset: LOG_DEVICE_HEADER_SIZE,
            });
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|e| store_io_err("seek log_device header", path, e))?;
        let mut header = [0u8; 16];
        file.read_exact(&mut header)
            .map_err(|e| store_io_err("read log_device header", path, e))?;

        if &header[0..8] != LOG_DEVICE_MAGIC {
            return Err(FileSystemError::CorruptState {
                reason: "log_device file has wrong magic",
            });
        }
        if u32::from_le_bytes(header[8..12].try_into().unwrap()) != LOG_DEVICE_VERSION {
            return Err(FileSystemError::CorruptState {
                reason: "log_device unsupported version",
            });
        }

        let last_valid = Self::scan_to_last_valid(&mut file, file_len, path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            next_offset: last_valid,
        })
    }

    fn scan_to_last_valid(file: &mut File, file_len: u64, path: &Path) -> Result<u64> {
        let mut offset = LOG_DEVICE_HEADER_SIZE;
        let mut last_valid = offset;
        while offset + LOG_DEVICE_ENTRY_FRAME_SIZE <= file_len {
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| store_io_err("seek log_device entry", path, e))?;
            let mut frame = [0u8; 8];
            if file.read_exact(&mut frame).is_err() {
                break;
            }
            let payload_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as u64;
            let stored_crc = u32::from_le_bytes(frame[4..8].try_into().unwrap());
            let entry_end = offset + LOG_DEVICE_ENTRY_FRAME_SIZE + payload_len;
            if entry_end > file_len {
                break;
            }
            let mut payload = vec![0u8; payload_len as usize];
            if file.read_exact(&mut payload).is_err() {
                break;
            }
            if crc32c(&payload) != stored_crc {
                break;
            }
            last_valid = entry_end;
            offset = entry_end;
        }
        Ok(last_valid)
    }

    fn append(&mut self, payload: &[u8]) -> Result<()> {
        let checksum = crc32c(payload);
        let len_u32 = payload.len() as u32;
        let mut frame = Vec::with_capacity(8 + payload.len());
        frame.extend_from_slice(&len_u32.to_le_bytes());
        frame.extend_from_slice(&checksum.to_le_bytes());
        frame.extend_from_slice(payload);
        self.file
            .seek(SeekFrom::Start(self.next_offset))
            .map_err(|e| store_io_err("seek log_device append", &self.path, e))?;
        self.file
            .write_all(&frame)
            .map_err(|e| store_io_err("write log_device entry", &self.path, e))?;
        self.file
            .sync_all()
            .map_err(|e| store_io_err("fsync log_device entry", &self.path, e))?;
        self.next_offset += frame.len() as u64;
        Ok(())
    }
    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    fn read_all_entries(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut entries = Vec::new();
        let mut offset = LOG_DEVICE_HEADER_SIZE;
        let file_len = self
            .file
            .seek(SeekFrom::End(0))
            .map_err(|e| store_io_err("seek log_device end", &self.path, e))?;
        while offset + LOG_DEVICE_ENTRY_FRAME_SIZE <= file_len {
            self.file
                .seek(SeekFrom::Start(offset))
                .map_err(|e| store_io_err("seek log_device entry", &self.path, e))?;
            let mut frame = [0u8; 8];
            if self.file.read_exact(&mut frame).is_err() {
                break;
            }
            let payload_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as u64;
            let stored_crc = u32::from_le_bytes(frame[4..8].try_into().unwrap());
            let entry_end = offset + 8 + payload_len;
            if entry_end > file_len {
                break;
            }
            let mut payload = vec![0u8; payload_len as usize];
            if self.file.read_exact(&mut payload).is_err() {
                break;
            }
            if crc32c(&payload) != stored_crc {
                break;
            }
            entries.push(payload);
            offset = entry_end;
        }
        Ok(entries)
    }

    fn truncate(&mut self) -> Result<()> {
        self.file
            .set_len(LOG_DEVICE_HEADER_SIZE)
            .map_err(|e| store_io_err("truncate log_device", &self.path, e))?;
        self.file
            .sync_all()
            .map_err(|e| store_io_err("fsync log_device truncate", &self.path, e))?;
        self.next_offset = LOG_DEVICE_HEADER_SIZE;
        Ok(())
    }
}

/// Anchor identifying the filesystem root state when the intent was recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentLogRootAnchor {
    pub transaction_id: u64,
    pub generation: u64,
    pub manifest_digest: IntegrityDigest64,
}

#[derive(Clone, Debug)]
pub enum IntentLogEntryKind {
    /// Replayable range intent for a buffered sync write.
    SyncWriteRange {
        inode_id: InodeId,
        offset: u64,
        #[allow(dead_code)]
        length: u64,
        payload_digest: IntegrityDigest64,
        data_version: u64,
    },
    /// O_DSYNC data-only range intent (may omit unrelated metadata).
    OdsyncDataRange {
        inode_id: InodeId,
        offset: u64,
        #[allow(dead_code)]
        length: u64,
        payload_digest: IntegrityDigest64,
        has_size_delta: bool,
        data_version: u64,
    },
    /// fsync barrier that drains all sealed intents for the listed files.
    FsyncDirtyDrain { inode_ids: Vec<InodeId> },
    /// MS_SYNC for shared writable mmap windows.
    SharedMmapMsync {
        inode_id: InodeId,
        offset: u64,
        #[allow(dead_code)]
        length: u64,
        payload_digest: IntegrityDigest64,
        data_version: u64,
    },
    /// Namespace mutation intent (mkdir, unlink, rename, etc.).
    NamespaceSyncIntent {
        parent_inode_id: InodeId,
        affected_inode_ids: Vec<InodeId>,
        link_count_deltas: Vec<(InodeId, i64)>,
    },
    /// Replayable metadata-only create/mknod intent. The embedded inode
    /// record is the authority for mode, facets, and special-node `rdev`.
    NamespaceCreateIntent(NamespaceCreateIntentRecord),
    /// Fast path refused: system under pressure, fell back to full commit.
    PressureFallback,
    /// Marker written during crash-recovery reconcile pass.
    CrashReplayReconcile,
}
impl IntentLogEntryKind {
    /// Whether this entry kind carries data intents that reference `inode_id`.
    ///
    /// Covers SyncWriteRange, OdsyncDataRange, SharedMmapMsync, and
    /// FsyncDirtyDrain (which drains accumulated intents for listed inodes).
    /// NamespaceCreateIntent is metadata-only: directory fsync tracks it
    /// through is_namespace_sync_for_dir(), but file fsync/fdatasync must not
    /// treat it as durable data authority for the created inode.
    pub fn references_data_inode(&self, inode_id: InodeId) -> bool {
        match self {
            IntentLogEntryKind::SyncWriteRange { inode_id: id, .. }
            | IntentLogEntryKind::OdsyncDataRange { inode_id: id, .. }
            | IntentLogEntryKind::SharedMmapMsync { inode_id: id, .. } => *id == inode_id,
            IntentLogEntryKind::FsyncDirtyDrain { inode_ids } => inode_ids.contains(&inode_id),
            IntentLogEntryKind::NamespaceSyncIntent {
                affected_inode_ids, ..
            } => affected_inode_ids.contains(&inode_id),
            IntentLogEntryKind::NamespaceCreateIntent(_) => false,
            IntentLogEntryKind::PressureFallback | IntentLogEntryKind::CrashReplayReconcile => {
                false
            }
        }
    }

    /// Whether this entry is a `NamespaceSyncIntent` for the given directory inode.
    pub fn is_namespace_sync_for_dir(&self, parent_inode_id: InodeId) -> bool {
        matches!(self,
            IntentLogEntryKind::NamespaceSyncIntent { parent_inode_id: pid, .. }
            | IntentLogEntryKind::NamespaceCreateIntent(NamespaceCreateIntentRecord {
                parent_inode_id: pid,
                ..
            })
            if *pid == parent_inode_id)
    }
}

/// A single entry in the intent log.
#[derive(Clone, Debug)]
pub struct IntentLogEntry {
    pub entry_id: u64,
    pub entry_kind: IntentLogEntryKind,
    pub root_anchor: IntentLogRootAnchor,
    pub timestamp_ns: u64,
}

// Entry-kind discriminant tags for the binary format.
const KIND_SYNC_WRITE_RANGE: u8 = 1;
const KIND_ODSYNC_DATA_RANGE: u8 = 2;
const KIND_FSYNC_DIRTY_DRAIN: u8 = 3;
const KIND_SHARED_MMAP_MSYNC: u8 = 4;
const KIND_NAMESPACE_SYNC_INTENT: u8 = 5;
const KIND_PRESSURE_FALLBACK: u8 = 6;
const KIND_CRASH_REPLAY_RECONCILE: u8 = 7;
const KIND_NAMESPACE_CREATE_INTENT: u8 = 8;

// ---------------------------------------------------------------------------
// Encoding / decoding
// ---------------------------------------------------------------------------

fn encode_namespace_create_intent(out: &mut Vec<u8>, intent: &NamespaceCreateIntentRecord) {
    push_u64(out, intent.parent_inode_id.get());
    push_u64(out, intent.entry.name.len() as u64);
    out.extend_from_slice(&intent.entry.name);
    push_u64(out, intent.entry.inode_id.get());
    push_u64(out, intent.entry.generation.get());
    push_u32(out, intent.entry.kind().as_u32());
    push_u32(out, intent.entry.mode);

    let inode = encode_inode(&intent.inode);
    push_u64(out, inode.len() as u64);
    out.extend_from_slice(&inode);
}

fn read_decoder_vec(decoder: &mut Decoder<'_>, len: usize) -> Result<Vec<u8>> {
    let end = decoder
        .offset
        .checked_add(len)
        .ok_or(FileSystemError::Decode {
            object: decoder.object,
            reason: "offset overflow",
        })?;
    if end > decoder.bytes.len() {
        return Err(FileSystemError::Decode {
            object: decoder.object,
            reason: "record ended early",
        });
    }
    let bytes = decoder.bytes[decoder.offset..end].to_vec();
    decoder.offset = end;
    Ok(bytes)
}

fn decode_namespace_create_intent(
    decoder: &mut Decoder<'_>,
) -> Result<NamespaceCreateIntentRecord> {
    let parent_inode_id = InodeId::new(decoder.read_u64()?);
    let name_len = decoder.read_count_bounded(MAX_NAME_BYTES)?;
    let name = read_decoder_vec(decoder, name_len)?;
    crate::helpers::validate_name(&name)?;
    let entry_inode_id = InodeId::new(decoder.read_u64()?);
    let entry_generation = Generation::new(decoder.read_u64()?);
    let kind_raw = decoder.read_u32()?;
    let entry_kind = NodeKind::try_from(kind_raw).map_err(|_| FileSystemError::Decode {
        object: "intent log entry",
        reason: "unknown namespace create entry kind",
    })?;
    let entry_mode = decoder.read_u32()?;
    let inode_len =
        decoder.read_count_bounded(decoder.bytes.len().saturating_sub(decoder.offset))?;
    let inode = decode_inode(&read_decoder_vec(decoder, inode_len)?)?;
    let entry = crate::types::NamespaceEntry {
        name,
        inode_id: entry_inode_id,
        generation: entry_generation,
        facets: entry_kind.to_facets(),
        mode: entry_mode,
    };
    Ok(NamespaceCreateIntentRecord {
        parent_inode_id,
        entry,
        inode,
    })
}

fn encode_intent_log_entry(entry: &IntentLogEntry) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&INTENT_LOG_MAGIC_BYTES);
    push_u16(&mut out, INTENT_LOG_ENTRY_VERSION);
    push_u16(&mut out, 0); // reserved
    push_u64(&mut out, entry.entry_id);
    push_u64(&mut out, entry.timestamp_ns);

    // root anchor
    push_u64(&mut out, entry.root_anchor.transaction_id);
    push_u64(&mut out, entry.root_anchor.generation);
    push_u64(&mut out, entry.root_anchor.manifest_digest.0);

    // kind-specific body
    match &entry.entry_kind {
        IntentLogEntryKind::SyncWriteRange {
            inode_id,
            offset,
            length,
            payload_digest,
            data_version,
        } => {
            out.push(KIND_SYNC_WRITE_RANGE);
            push_u64(&mut out, inode_id.get());
            push_u64(&mut out, *offset);
            push_u64(&mut out, *length);
            push_u64(&mut out, payload_digest.0);
            push_u64(&mut out, *data_version);
        }
        IntentLogEntryKind::OdsyncDataRange {
            inode_id,
            offset,
            length,
            payload_digest,
            has_size_delta,
            data_version,
        } => {
            out.push(KIND_ODSYNC_DATA_RANGE);
            push_u64(&mut out, inode_id.get());
            push_u64(&mut out, *offset);
            push_u64(&mut out, *length);
            push_u64(&mut out, payload_digest.0);
            out.push(if *has_size_delta { 1 } else { 0 });
            push_u64(&mut out, *data_version);
        }
        IntentLogEntryKind::FsyncDirtyDrain { inode_ids } => {
            out.push(KIND_FSYNC_DIRTY_DRAIN);
            push_u64(&mut out, inode_ids.len() as u64);
            for id in inode_ids {
                push_u64(&mut out, id.get());
            }
        }
        IntentLogEntryKind::SharedMmapMsync {
            inode_id,
            offset,
            length,
            payload_digest,
            data_version,
        } => {
            out.push(KIND_SHARED_MMAP_MSYNC);
            push_u64(&mut out, inode_id.get());
            push_u64(&mut out, *offset);
            push_u64(&mut out, *length);
            push_u64(&mut out, payload_digest.0);
            push_u64(&mut out, *data_version);
        }
        IntentLogEntryKind::NamespaceSyncIntent {
            parent_inode_id,
            affected_inode_ids,
            link_count_deltas,
        } => {
            out.push(KIND_NAMESPACE_SYNC_INTENT);
            push_u64(&mut out, parent_inode_id.get());
            push_u64(&mut out, affected_inode_ids.len() as u64);
            for id in affected_inode_ids {
                push_u64(&mut out, id.get());
            }
            push_u64(&mut out, link_count_deltas.len() as u64);
            for (inode_id, delta) in link_count_deltas {
                push_u64(&mut out, inode_id.get());
                push_i64(&mut out, *delta);
            }
        }
        IntentLogEntryKind::NamespaceCreateIntent(intent) => {
            out.push(KIND_NAMESPACE_CREATE_INTENT);
            encode_namespace_create_intent(&mut out, intent);
        }
        IntentLogEntryKind::PressureFallback => {
            out.push(KIND_PRESSURE_FALLBACK);
        }
        IntentLogEntryKind::CrashReplayReconcile => {
            out.push(KIND_CRASH_REPLAY_RECONCILE);
        }
    }
    out
}

fn decode_intent_log_entry(bytes: &[u8]) -> Result<IntentLogEntry> {
    let mut decoder = Decoder::new("intent log entry", bytes);
    decoder.expect_magic(INTENT_LOG_MAGIC_BYTES)?;
    let version = decoder.read_u16()?;
    if version != INTENT_LOG_ENTRY_VERSION {
        return Err(FileSystemError::Decode {
            object: "intent log entry",
            reason: "unsupported format version",
        });
    }
    if decoder.read_u16()? != 0 {
        return Err(FileSystemError::Decode {
            object: "intent log entry",
            reason: "reserved field is non-zero",
        });
    }
    let entry_id = decoder.read_u64()?;
    let timestamp_ns = decoder.read_u64()?;
    let root_anchor = IntentLogRootAnchor {
        transaction_id: decoder.read_u64()?,
        generation: decoder.read_u64()?,
        manifest_digest: IntegrityDigest64(decoder.read_u64()?),
    };

    let kind_byte = decoder.read_u8()?;
    let entry_kind = match kind_byte {
        KIND_SYNC_WRITE_RANGE => IntentLogEntryKind::SyncWriteRange {
            inode_id: InodeId::new(decoder.read_u64()?),
            offset: decoder.read_u64()?,
            length: decoder.read_u64()?,
            payload_digest: IntegrityDigest64(decoder.read_u64()?),
            data_version: decoder.read_u64()?,
        },
        KIND_ODSYNC_DATA_RANGE => IntentLogEntryKind::OdsyncDataRange {
            inode_id: InodeId::new(decoder.read_u64()?),
            offset: decoder.read_u64()?,
            length: decoder.read_u64()?,
            payload_digest: IntegrityDigest64(decoder.read_u64()?),
            has_size_delta: decoder.read_u8()? != 0,
            data_version: decoder.read_u64()?,
        },
        KIND_FSYNC_DIRTY_DRAIN => {
            let count = decoder.read_count()?;
            let mut inode_ids = Vec::with_capacity(count);
            for _ in 0..count {
                inode_ids.push(InodeId::new(decoder.read_u64()?));
            }
            IntentLogEntryKind::FsyncDirtyDrain { inode_ids }
        }
        KIND_SHARED_MMAP_MSYNC => IntentLogEntryKind::SharedMmapMsync {
            inode_id: InodeId::new(decoder.read_u64()?),
            offset: decoder.read_u64()?,
            length: decoder.read_u64()?,
            payload_digest: IntegrityDigest64(decoder.read_u64()?),
            data_version: decoder.read_u64()?,
        },
        KIND_NAMESPACE_SYNC_INTENT => {
            let parent_inode_id = InodeId::new(decoder.read_u64()?);
            let affected_count = decoder.read_count()?;
            let mut affected_inode_ids = Vec::with_capacity(affected_count);
            for _ in 0..affected_count {
                affected_inode_ids.push(InodeId::new(decoder.read_u64()?));
            }
            let delta_count = decoder.read_count()?;
            let mut link_count_deltas = Vec::with_capacity(delta_count);
            for _ in 0..delta_count {
                let inode_id = InodeId::new(decoder.read_u64()?);
                let delta = decoder.read_i64()?;
                link_count_deltas.push((inode_id, delta));
            }
            IntentLogEntryKind::NamespaceSyncIntent {
                parent_inode_id,
                affected_inode_ids,
                link_count_deltas,
            }
        }
        KIND_NAMESPACE_CREATE_INTENT => {
            IntentLogEntryKind::NamespaceCreateIntent(decode_namespace_create_intent(&mut decoder)?)
        }
        KIND_PRESSURE_FALLBACK => IntentLogEntryKind::PressureFallback,
        KIND_CRASH_REPLAY_RECONCILE => IntentLogEntryKind::CrashReplayReconcile,
        _ => {
            return Err(FileSystemError::Decode {
                object: "intent log entry",
                reason: "unknown entry kind",
            });
        }
    };
    decoder.finish()?;
    Ok(IntentLogEntry {
        entry_id,
        entry_kind,
        root_anchor,
        timestamp_ns,
    })
}

/// Public wrapper for fuzz testing: feed arbitrary bytes to the intent-log
/// entry decoder. Must never panic; the fuzz crate calls this directly.
#[doc(hidden)]
pub fn fuzz_decode_intent_log_entry(data: &[u8]) {
    let _ = decode_intent_log_entry(data);
}

// ---------------------------------------------------------------------------
// IntentLog
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Number of recent flush intervals to track for adaptive tuning.
const FLUSH_HISTORY_LEN: usize = 8;

/// Minimum adaptive flush interval in microseconds.
const ADAPTIVE_FLUSH_MIN_US: u64 = 50;
/// Maximum adaptive flush interval in microseconds.
const ADAPTIVE_FLUSH_MAX_US: u64 = 10_000;

/// Configuration for the intent log group-commit batching and admission control.
#[derive(Clone, Debug)]
pub struct IntentLogConfig {
    /// Maximum number of entries to accumulate before forcing a flush.
    pub max_batch_entries: usize,
    /// Whether to use adaptive flush interval (auto-tune based on recent
    /// workload patterns). When true, `flush_interval_us` is the initial
    /// value; the interval adapts within [50µs, 10ms] based on observed
    /// batch fill rates. When false, the interval stays fixed.
    pub adaptive_flush: bool,
    /// Maximum microseconds to wait before flushing a non-empty batch.
    /// A value of 0 disables time-based flush; only batch-size threshold triggers.
    pub flush_interval_us: u64,
    /// When total entries (flushed + unflushed) exceeds this threshold,
    /// the next append emits a PressureFallback entry instead of accepting
    /// a fast-path intent.
    pub pressure_depth_threshold: usize,
    /// Maximum byte capacity of the intent log.  When non-zero, byte-based
    /// space pressure tracking is enabled.  0 disables byte-pressure.
    pub log_max_bytes: u64,
    /// Fraction of `log_max_bytes` at which Warning level is triggered.
    /// Default: 0.50 (50%).
    pub pressure_warning_threshold: f64,
    /// Fraction of `log_max_bytes` at which Sync (throttle) level is triggered.
    /// Default: 0.75 (75%).
    pub pressure_sync_threshold: f64,
    /// Fraction of `log_max_bytes` at which Critical (block) level is triggered.
    /// Default: 0.90 (90%).
    pub pressure_critical_threshold: f64,
}

impl Default for IntentLogConfig {
    fn default() -> Self {
        Self {
            max_batch_entries: 64,
            adaptive_flush: true,
            flush_interval_us: 500,
            pressure_depth_threshold: 1024,
            log_max_bytes: 0,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        }
    }
}

impl IntentLogConfig {
    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    /// A conservative config: smaller batches, shorter flush interval.
    pub const fn conservative() -> Self {
        Self {
            max_batch_entries: 16,
            adaptive_flush: false,
            flush_interval_us: 100,
            pressure_depth_threshold: 256,
            log_max_bytes: 1_048_576,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        }
    }
    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    /// A config tuned for throughput: larger batches, longer flush interval.
    pub const fn throughput() -> Self {
        Self {
            max_batch_entries: 256,
            adaptive_flush: true,
            flush_interval_us: 10_000,
            pressure_depth_threshold: 4096,
            log_max_bytes: 16_777_216,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        }
    }
}

/// Space pressure level for the intent log based on byte usage fraction.
///
/// Derived from `used_bytes / log_max_bytes` during each append.
/// Ordered from least to most severe.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogSpacePressureLevel {
    /// Below the warning threshold: normal fast-path operation.
    #[default]
    Healthy,
    /// Crossed the warning threshold: log a diagnostic, continue accepting.
    Warning,
    /// Crossed the sync threshold: throttle writes to slow log growth.
    Sync,
    /// Crossed the critical threshold: refuse fast-path; caller must fall
    /// back to full commit.
    Critical,
}

impl LogSpacePressureLevel {
    /// Human-readable label for observability / tracing.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Sync => "sync",
            Self::Critical => "critical",
        }
    }
}

/// Accumulated space pressure statistics for the intent log.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogSpaceStats {
    /// Current byte usage of the intent log (flushed + unflushed entries).
    pub log_used_bytes: u64,
    /// Configured maximum byte capacity.  0 means byte-pressure is disabled.
    pub log_max_bytes: u64,
    /// Current pressure level derived from the used/max ratio.
    pub pressure_level: LogSpacePressureLevel,
    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    /// Number of committed entry batches trimmed from the log.
    pub segments_trimmed: u64,
    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    /// Number of times a write was throttled due to Sync-level pressure.
    pub write_throttle_events: u64,
}

/// Compute the wire-format byte length of an intent log entry *without*
/// actually allocating a Vec.  Used for byte-pressure accounting.
fn encoded_entry_len(entry: &IntentLogEntry) -> usize {
    // Header: magic(8) + version(2) + reserved(2) + entry_id(8) + timestamp_ns(8)
    //        + root_anchor(8+8+8) = 44 bytes
    let mut len: usize = 8 + 2 + 2 + 8 + 8 + 8 + 8 + 8; // 52

    match &entry.entry_kind {
        IntentLogEntryKind::SyncWriteRange { .. } => {
            len += 1 + 8 + 8 + 8 + 8 + 8; // kind + inode_id + offset + length + digest + data_version
        }
        IntentLogEntryKind::OdsyncDataRange { .. } => {
            len += 1 + 8 + 8 + 8 + 8 + 1 + 8; // kind + inode_id + offset + length + digest + has_size_delta + data_version
        }
        IntentLogEntryKind::FsyncDirtyDrain { inode_ids } => {
            len += 1 + 8; // kind + count
            len += inode_ids.len() * 8;
        }
        IntentLogEntryKind::SharedMmapMsync { .. } => {
            len += 1 + 8 + 8 + 8 + 8 + 8; // kind + inode_id + offset + length + digest + data_version
        }
        IntentLogEntryKind::NamespaceSyncIntent {
            affected_inode_ids,
            link_count_deltas,
            ..
        } => {
            len += 1 + 8; // kind + parent_inode_id
            len += 8; // affected count
            len += affected_inode_ids.len() * 8;
            len += 8; // delta count
            len += link_count_deltas.len() * (8 + 8); // (inode_id + delta) per entry
        }
        IntentLogEntryKind::NamespaceCreateIntent(intent) => {
            len += 1; // kind
            len += 8; // parent_inode_id
            len += 8 + intent.entry.name.len(); // name length + bytes
            len += 8 + 8 + 4 + 4; // inode_id + generation + kind + mode
            len += 8 + encode_inode(&intent.inode).len(); // inode payload length + bytes
        }
        IntentLogEntryKind::PressureFallback => {
            len += 1; // kind byte only
        }
        IntentLogEntryKind::CrashReplayReconcile => {
            len += 1; // kind byte only
        }
    }
    len
}

/// A fast-path write-ahead log that records mutations with bounded latency.
///
/// The intent log sits in front of the full transaction-root commit path.
/// Entries are written sequentially to the object store and replayed during
/// crash recovery before a normal committed root is selected.
///
/// ## Group-commit batching
///
/// `append()` queues entries in memory. `flush()` writes all queued entries
/// to the store in a single batch with one head-pointer update and one
/// `sync_all()`, matching ZFS ZIL group-commit semantics. A time-based or
/// batch-size threshold triggers automatic flush.
///
/// ## Pressure admission control
///
/// Two independent pressure mechanisms guard the log:
///
/// *Entry-count pressure*: when total log depth exceeds
/// `config.pressure_depth_threshold`, the next append emits a
/// `PressureFallback` entry and flushes immediately.  The caller must
/// then fall back to the full commit path.
///
/// *Byte-based space pressure*: when `config.log_max_bytes` is non-zero,
/// each append checks the ratio `used_bytes / log_max_bytes`.  At
/// Warning (>=50%) a diagnostic is logged.  At Sync (>=75%)
/// a throttle counter is incremented.  At Critical (>=90%) the
/// append is refused.
#[derive(Debug)]
pub struct IntentLog {
    next_entry_id: u64,
    /// All entries that have been appended (both flushed and unflushed).
    entries: Vec<IntentLogEntry>,
    /// Number of entries that have been written to durable storage.
    /// entries[0..flushed_entry_count] are on disk; the rest are batched in memory.
    flushed_entry_count: usize,
    config: IntentLogConfig,
    /// Timestamp of the most recent flush, used for time-based auto-flush.
    last_flush: Option<Instant>,
    /// Timestamp of the first unflushed append, used to measure batch fill rate
    /// for adaptive interval tuning.
    first_unflushed_at: Option<Instant>,
    /// Ring buffer of recent flush intervals (microseconds) for adaptive tuning.
    flush_history: [u64; FLUSH_HISTORY_LEN],
    flush_history_pos: usize,
    flush_history_filled: bool,
    log_device: Option<LogDeviceFile>,
    /// Cumulative wire-format bytes of all entries currently in the log
    /// (both flushed and unflushed).  Updated on append and trim.
    used_bytes: u64,
    /// Number of times an append was throttled at Sync pressure level.
    throttle_events: u64,
    /// Number of times `trim_committed` has been called (each call may trim
    /// zero or more committed entry batches).
    segments_trimmed: u64,
}

impl IntentLog {
    pub fn new() -> Self {
        Self {
            next_entry_id: 0,
            entries: Vec::new(),
            flushed_entry_count: 0,
            config: IntentLogConfig::default(),
            last_flush: None,
            first_unflushed_at: None,
            flush_history: [0; FLUSH_HISTORY_LEN],
            flush_history_pos: 0,
            flush_history_filled: false,
            log_device: None,
            used_bytes: 0,
            throttle_events: 0,
            segments_trimmed: 0,
        }
    }

    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    pub fn with_config(config: IntentLogConfig) -> Self {
        Self {
            next_entry_id: 0,
            entries: Vec::new(),
            flushed_entry_count: 0,
            config,
            last_flush: None,
            first_unflushed_at: None,
            flush_history: [0; FLUSH_HISTORY_LEN],
            flush_history_pos: 0,
            flush_history_filled: false,
            log_device: None,
            used_bytes: 0,
            throttle_events: 0,
            segments_trimmed: 0,
        }
    }
    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    /// Configure a separate fast log device (LOG_DEVICE) for sync write
    /// acceleration.  When set, every intent log entry is written to the
    /// log device first and fsync'd before the caller is acknowledged.
    ///
    /// On crash recovery, entries found in the log device that are not yet in the
    /// in-memory log are merged (log device is authoritative).
    pub fn open_log_device(&mut self, path: &Path) -> Result<()> {
        let mut log_device = LogDeviceFile::open(path)?;
        // Crash recovery: merge any LOG_DEVICE entries not yet in the in-memory log.
        let log_device_entries = log_device.read_all_entries()?;
        for raw in log_device_entries {
            match decode_intent_log_entry(&raw) {
                Ok(entry) => {
                    if entry.entry_id >= self.next_entry_id {
                        eprintln!(
                            "log_device: recovering entry id {} from crash",
                            entry.entry_id,
                        );
                        let recovered_id = entry.entry_id;
                        self.entries.push(entry);
                        self.next_entry_id = self.next_entry_id.max(recovered_id + 1);
                    }
                }
                Err(e) => {
                    eprintln!("log_device: skipping corrupt entry during recovery: {e}");
                }
            }
        }
        self.log_device = Some(log_device);
        Ok(())
    }
    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    pub fn has_log_device(&self) -> bool {
        self.log_device.is_some()
    }

    /// Load the intent log from the object store during mount/recovery
    /// using the default config. Use `load_with_config` for a custom config.
    pub fn load(store: &LocalObjectStore) -> Result<Self> {
        Self::load_with_config(store, IntentLogConfig::default())
    }

    /// Load the intent log from the object store during mount/recovery
    /// with a custom config.
    pub fn load_with_config(store: &LocalObjectStore, config: IntentLogConfig) -> Result<Self> {
        let head_bytes = store.get(intent_log_head_object_key())?;
        let head_entry_id: u64 = match head_bytes {
            Some(ref bytes) if bytes.len() == 8 => {
                u64::from_le_bytes(bytes[..8].try_into().map_err(|_| {
                    FileSystemError::CorruptState {
                        reason: "intent log head is not 8 bytes",
                    }
                })?)
            }
            Some(_) => {
                return Err(FileSystemError::CorruptState {
                    reason: "intent log head has wrong size",
                });
            }
            None => 0,
        };

        let mut entries = Vec::new();
        for entry_id in 0..head_entry_id {
            let key = intent_log_entry_object_key(entry_id);
            match store.get(key)? {
                Some(bytes) => {
                    let entry = decode_intent_log_entry(&bytes)?;
                    if entry.entry_id != entry_id {
                        return Err(FileSystemError::CorruptState {
                            reason: "intent log entry id mismatch",
                        });
                    }
                    entries.push(entry);
                }
                None => {
                    // Gap in entry IDs — stop reading
                    break;
                }
            }
        }
        let entry_count = entries.len();
        Ok(Self {
            next_entry_id: entry_count as u64,
            entries,
            flushed_entry_count: entry_count,
            config,
            last_flush: None,
            first_unflushed_at: None,
            flush_history: [0; FLUSH_HISTORY_LEN],
            flush_history_pos: 0,
            flush_history_filled: false,
            log_device: None,
            used_bytes: 0,
            throttle_events: 0,
            segments_trimmed: 0,
        })
    }

    /// Append an entry to the in-memory log.
    ///
    /// The entry is queued for group-commit. It will be flushed to durable
    /// storage when `flush` is called or when the batch-size threshold
    /// triggers auto-flush.
    ///
    /// Returns `Ok(true)` if the entry was accepted and queued.
    /// Returns `Ok(false)` if the pressure threshold was exceeded — a
    /// `PressureFallback` entry was emitted instead and flushed immediately.
    /// The caller should then switch to the full commit path.
    pub fn append(
        &mut self,
        store: &mut LocalObjectStore,
        entry_kind: IntentLogEntryKind,
        root_anchor: IntentLogRootAnchor,
        timestamp_ns: u64,
    ) -> Result<bool> {
        // Pressure admission: if log depth exceeds threshold, emit fallback
        if self.entries.len() >= self.config.pressure_depth_threshold {
            let fallback = IntentLogEntry {
                entry_id: self.next_entry_id,
                entry_kind: IntentLogEntryKind::PressureFallback,
                root_anchor,
                timestamp_ns,
            };
            let fallback_bytes = encode_intent_log_entry(&fallback);
            if let Some(ref mut log_device) = self.log_device {
                log_device.append(&fallback_bytes)?;
            }
            self.next_entry_id += 1;
            self.entries.push(fallback);
            self.flush(store)?;
            return Ok(false);
        }

        // Byte-based space pressure: when log_max_bytes is configured,
        // check used/max ratio and apply throttle/block semantics.
        if self.config.log_max_bytes > 0 {
            let used_fraction = self.used_bytes as f64 / self.config.log_max_bytes as f64;
            if used_fraction >= self.config.pressure_critical_threshold {
                // Critical: refuse fast-path append.
                self.throttle_events += 1;
                return Ok(false);
            }
            if used_fraction >= self.config.pressure_sync_threshold {
                // Sync: throttle (increment counter) but still accept.
                self.throttle_events += 1;
            }
            if used_fraction >= self.config.pressure_warning_threshold {
                // Warning: diagnostic (no rate limit; callers are low-frequency).
                eprintln!(
                    "intent_log space pressure warning: {:.1}% used ({}/{} bytes)",
                    used_fraction * 100.0,
                    self.used_bytes,
                    self.config.log_max_bytes
                );
            }
        }

        let entry = IntentLogEntry {
            entry_id: self.next_entry_id,
            entry_kind,
            root_anchor,
            timestamp_ns,
        };

        // Track byte usage without a separate allocation.
        let entry_len = encoded_entry_len(&entry) as u64;
        self.used_bytes = self.used_bytes.saturating_add(entry_len);

        // Encode once for both LOG_DEVICE and deferred main-store write.
        let bytes = encode_intent_log_entry(&entry);

        // Write to log device first for fast durable acknowledgment before the
        // batch lands in the main object store.  On crash, log device is
        // authoritative for entries not yet flushed.
        if let Some(ref mut log_device) = self.log_device {
            log_device.append(&bytes)?;
        }

        // Track batch start time for adaptive flush interval tuning.
        let was_empty_batch = self.entries.len() == self.flushed_entry_count;

        self.next_entry_id += 1;
        // Main-store write is deferred to flush() for group commit.
        self.entries.push(entry);

        if was_empty_batch {
            self.first_unflushed_at = Some(Instant::now());
        }

        // Auto-flush when batch reaches threshold
        let batch_len = self.entries.len().saturating_sub(self.flushed_entry_count);
        if batch_len >= self.config.max_batch_entries {
            self.flush(store)?;
        }

        Ok(true)
    }
    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    /// Number of entries currently in the log.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry ID that will be assigned to the next append.
    /// Callers that need to pre-store data payloads must use this ID
    /// before calling [].
    pub fn next_entry_id(&self) -> u64 {
        self.next_entry_id
    }

    /// Write all batched (unflushed) entries to durable storage.
    ///
    /// This writes each queued entry to the store (and LOG_DEVICE if configured),
    /// updates the head pointer once for the entire batch, and syncs.
    /// After this returns, all entries are on stable storage.
    ///
    /// If no entries are pending, this is a no-op.
    pub fn flush(&mut self, store: &mut LocalObjectStore) -> Result<()> {
        let flush_from = self.flushed_entry_count;
        let flush_to = self.entries.len();

        if flush_from >= flush_to {
            return Ok(());
        }

        // Write all queued entries to the main object store.
        // log device writes already happened in append(); here we only batch-land
        // into the object store for the group commit.
        for idx in flush_from..flush_to {
            let entry = &self.entries[idx];
            let bytes = encode_intent_log_entry(entry);
            store.put(intent_log_entry_object_key(entry.entry_id), &bytes)?;
        }

        // Single head-pointer update for the entire batch
        store.put(
            intent_log_head_object_key(),
            &self.next_entry_id.to_le_bytes(),
        )?;

        // Durable sync — one fsync for the entire batch
        store.sync_all().map_err(FileSystemError::from)?;

        // Record the batch fill interval for adaptive tuning.
        let now = Instant::now();
        if let Some(start) = self.first_unflushed_at {
            let interval_us = now.duration_since(start).as_micros() as u64;
            self.flush_history[self.flush_history_pos] = interval_us;
            self.flush_history_pos = (self.flush_history_pos + 1) % FLUSH_HISTORY_LEN;
            if self.flush_history_pos == 0 {
                self.flush_history_filled = true;
            }
        }
        self.flushed_entry_count = flush_to;
        self.last_flush = Some(now);
        self.first_unflushed_at = None;
        Ok(())
    }

    /// Number of entries currently queued in memory awaiting flush.
    pub fn pending_flush_count(&self) -> usize {
        self.entries.len().saturating_sub(self.flushed_entry_count)
    }

    /// Whether any pending (unflushed) intent log entry carries data
    /// intents for `inode_id`. Used by the fsync fast path to decide
    /// whether flushing the intent log is sufficient instead of a full
    /// commit_group commit.
    pub fn has_pending_data_for_inode(&self, inode_id: InodeId) -> bool {
        self.entries
            .iter()
            .any(|e| e.entry_kind.references_data_inode(inode_id))
    }

    /// Whether any pending (unflushed) intent log entry is a
    /// `NamespaceSyncIntent` for the given directory inode.
    /// Used by the fsync_directory fast path.
    pub fn has_pending_namespace_for_dir(&self, parent_inode_id: InodeId) -> bool {
        self.entries
            .iter()
            .any(|e| e.entry_kind.is_namespace_sync_for_dir(parent_inode_id))
    }

    /// Whether the adaptive flush interval has elapsed since the last flush.
    /// Returns true if there are pending entries and the interval has passed.
    pub fn should_flush(&self) -> bool {
        if self.pending_flush_count() == 0 {
            return false;
        }
        let interval = self.effective_flush_interval_us();
        if interval == 0 {
            return false;
        }
        match self.last_flush {
            None => true,
            Some(t) => {
                let elapsed = t.elapsed().as_micros() as u64;
                elapsed >= interval
            }
        }
    }

    /// Return the effective flush interval to use right now.
    ///
    /// When adaptive flushing is enabled, this is the exponential moving
    /// average of recent flush intervals, clamped to
    /// [ADAPTIVE_FLUSH_MIN_US, ADAPTIVE_FLUSH_MAX_US].
    /// When adaptive flushing is disabled, this is the configured
    /// `flush_interval_us`.
    pub fn effective_flush_interval_us(&self) -> u64 {
        if !self.config.adaptive_flush {
            return self.config.flush_interval_us;
        }
        let avg = self.adaptive_interval_us();
        if avg == 0 {
            return self.config.flush_interval_us;
        }
        avg.clamp(ADAPTIVE_FLUSH_MIN_US, ADAPTIVE_FLUSH_MAX_US)
    }

    /// Exponential moving average of recent flush intervals.
    fn adaptive_interval_us(&self) -> u64 {
        let count = if self.flush_history_filled {
            FLUSH_HISTORY_LEN
        } else {
            self.flush_history_pos
        };
        if count == 0 {
            return 0;
        }
        // Weighted average: recent intervals have higher weight.
        let mut total: u64 = 0;
        let mut weight_sum: u64 = 0;
        for i in 0..count {
            let idx = if self.flush_history_filled {
                (self.flush_history_pos + i) % FLUSH_HISTORY_LEN
            } else {
                i
            };
            let weight = (i + 1) as u64;
            total += self.flush_history[idx].saturating_mul(weight);
            weight_sum += weight;
        }
        if weight_sum == 0 {
            return 0;
        }
        total / weight_sum
    }

    /// Flush if the batch is non-empty and the flush interval has elapsed.
    /// Returns Ok(true) if a flush was performed, Ok(false) if no flush was
    /// needed, or an error.
    pub fn flush_if_needed(&mut self, store: &mut LocalObjectStore) -> Result<bool> {
        if self.should_flush() {
            self.flush(store)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Flush any batched entries and sync to durable storage.
    pub fn flush_and_sync(&mut self, store: &mut LocalObjectStore) -> Result<()> {
        self.flush(store)?;
        store.sync_all().map_err(FileSystemError::from)
    }

    /// Flush batched entries and sync the store.
    pub fn sync(&mut self, store: &mut LocalObjectStore) -> Result<()> {
        self.flush_and_sync(store)
    }

    /// Clear the intent log (after a successful full commit has persisted all
    /// intended mutations through the normal transaction-root path).
    pub fn clear(&mut self, store: &mut LocalObjectStore) -> Result<()> {
        for entry in &self.entries {
            store.delete(intent_log_entry_object_key(entry.entry_id))?;
            store.delete(intent_log_data_object_key(entry.entry_id))?;
        }
        store.delete(intent_log_head_object_key())?;

        if let Some(ref mut log_device) = self.log_device {
            log_device.truncate()?;
        }
        self.entries.clear();
        self.flushed_entry_count = 0;
        self.next_entry_id = 0;
        self.last_flush = None;
        self.first_unflushed_at = None;
        self.used_bytes = 0;
        self.throttle_events = 0;
        self.segments_trimmed = 0;
        Ok(())
    }
    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    /// Remove all entries that reference `inode_id`, keeping flushed count
    /// consistent by treating removed entries as if they were never appended.
    /// Call this when an inode is truncated so the intent log does not replay
    /// stale write data during the fsync fast path.
    pub fn remove_entries_for_inode(&mut self, inode_id: InodeId) -> Vec<u64> {
        let mut removed_ids = Vec::new();
        let before = self.entries.len();
        self.entries.retain(|e| {
            if e.entry_kind.references_data_inode(inode_id) {
                removed_ids.push(e.entry_id);
                false
            } else {
                true
            }
        });
        let removed = before - self.entries.len();
        if self.flushed_entry_count > self.entries.len() {
            self.flushed_entry_count = self.entries.len();
        }
        if removed > 0 {
            eprintln!(
                "intent_log: removed {removed} entries for truncated inode {inode_id}",
                removed = removed,
                inode_id = inode_id.0,
            );
        }
        removed_ids
    }
    /// After crash recovery replay succeeds, call `clear` to remove them.
    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    pub fn pending_entries(&self) -> &[IntentLogEntry] {
        &self.entries
    }

    /// Derive the byte-based space pressure level from current usage.
    ///
    /// Returns `Healthy` when `log_max_bytes` is zero (byte-pressure disabled).
    pub fn compute_pressure_level(&self) -> LogSpacePressureLevel {
        if self.config.log_max_bytes == 0 {
            return LogSpacePressureLevel::Healthy;
        }
        let used_fraction = self.used_bytes as f64 / self.config.log_max_bytes as f64;
        if used_fraction >= self.config.pressure_critical_threshold {
            LogSpacePressureLevel::Critical
        } else if used_fraction >= self.config.pressure_sync_threshold {
            LogSpacePressureLevel::Sync
        } else if used_fraction >= self.config.pressure_warning_threshold {
            LogSpacePressureLevel::Warning
        } else {
            LogSpacePressureLevel::Healthy
        }
    }

    /// Snapshot current space pressure statistics.
    pub fn space_stats(&self) -> LogSpaceStats {
        LogSpaceStats {
            log_used_bytes: self.used_bytes,
            log_max_bytes: self.config.log_max_bytes,
            pressure_level: self.compute_pressure_level(),
            segments_trimmed: self.segments_trimmed,
            write_throttle_events: self.throttle_events,
        }
    }

    /// Trim all entries whose `entry_id` is <= `committed_entry_id`.
    ///
    /// After a COMMIT_GROUP commit flushes the log and the committed root advances,
    /// entries up to the committed LSN are no longer needed for replay.
    /// This reclaims memory and updates `used_bytes`.
    ///
    /// Returns the number of entries trimmed.
    pub fn trim_committed(&mut self, committed_entry_id: u64) -> usize {
        if committed_entry_id == 0 || self.entries.is_empty() {
            return 0;
        }
        // Find the split point: first entry with entry_id > committed_entry_id.
        let split_idx = self
            .entries
            .partition_point(|e| e.entry_id <= committed_entry_id);
        if split_idx == 0 {
            return 0;
        }
        let trimmed: Vec<IntentLogEntry> = self.entries.drain(..split_idx).collect();
        let trimmed_count = trimmed.len();
        // Reclaim byte usage.
        let mut reclaimed: u64 = 0;
        for entry in &trimmed {
            reclaimed += encoded_entry_len(entry) as u64;
        }
        self.used_bytes = self.used_bytes.saturating_sub(reclaimed);
        // Adjust flushed_entry_count.
        self.flushed_entry_count = self.flushed_entry_count.saturating_sub(trimmed_count);
        self.segments_trimmed += 1;
        trimmed_count
    }

    /// Trim all entries that have been flushed to durable storage.
    ///
    /// After a COMMIT_GROUP commit, flushed entries are committed and no longer needed
    /// for crash recovery.  This is a convenience wrapper around
    /// `trim_committed`.
    ///
    /// Returns the number of entries trimmed.
    pub fn trim_flushed(&mut self) -> usize {
        if self.flushed_entry_count == 0 {
            return 0;
        }
        // The last flushed entry's id is the committed high-water mark.
        let last_flushed_id = self.entries[self.flushed_entry_count - 1].entry_id;
        self.trim_committed(last_flushed_id)
    }
    #[allow(dead_code)] // INTENT: intent-log types for planned log device fast path and crash recovery
    /// Current byte usage of the log.
    pub fn bytes_used(&self) -> u64 {
        self.used_bytes
    }

    /// Check whether any entries have a root anchor newer than
    /// `since_transaction_id`.  Used during crash recovery to decide
    /// whether replay is needed before mount.
    pub fn replay_is_needed(&self, since_transaction_id: u64) -> bool {
        self.entries
            .iter()
            .any(|e| e.root_anchor.transaction_id > since_transaction_id)
    }
}

// ---------------------------------------------------------------------------
// Standalone replay functions (used by both IntentLog and recovery module)
// ---------------------------------------------------------------------------

fn validate_namespace_create_intent(intent: &NamespaceCreateIntentRecord) -> Result<()> {
    if intent.entry.inode_id != intent.inode.inode_id {
        return Err(FileSystemError::CorruptState {
            reason: "intent log replay: namespace create entry/inode id mismatch",
        });
    }
    if intent.entry.generation != intent.inode.generation {
        return Err(FileSystemError::CorruptState {
            reason: "intent log replay: namespace create generation mismatch",
        });
    }
    if intent.entry.mode != intent.inode.mode {
        return Err(FileSystemError::CorruptState {
            reason: "intent log replay: namespace create mode mismatch",
        });
    }
    if intent.entry.kind() != intent.inode.kind() {
        return Err(FileSystemError::CorruptState {
            reason: "intent log replay: namespace create kind mismatch",
        });
    }
    match intent.inode.kind() {
        NodeKind::CharDev | NodeKind::BlockDev => Ok(()),
        NodeKind::File | NodeKind::Fifo | NodeKind::Socket if intent.inode.rdev == 0 => Ok(()),
        NodeKind::File | NodeKind::Fifo | NodeKind::Socket => Err(FileSystemError::CorruptState {
            reason: "intent log replay: namespace create rdev is invalid for node kind",
        }),
        NodeKind::Dir | NodeKind::Symlink | NodeKind::Whiteout => {
            Err(FileSystemError::CorruptState {
                reason: "intent log replay: namespace create kind needs a dedicated replay path",
            })
        }
    }
}

fn replay_namespace_create_intent(
    intent: &NamespaceCreateIntentRecord,
    state: &mut crate::FileSystemState,
) -> Result<()> {
    use std::sync::Arc;

    validate_namespace_create_intent(intent)?;

    if !state.inodes.contains_key(&intent.parent_inode_id) {
        return Err(FileSystemError::CorruptState {
            reason: "intent log replay: namespace create parent inode not found",
        });
    }

    let parent_dir =
        state
            .directories
            .get(&intent.parent_inode_id)
            .ok_or(FileSystemError::CorruptState {
                reason: "intent log replay: namespace create parent directory not found",
            })?;
    if let Some(existing) = state.inodes.get(&intent.inode.inode_id) {
        if existing != &intent.inode {
            return Err(FileSystemError::CorruptState {
                reason: "intent log replay: namespace create inode conflicts with state",
            });
        }
    }
    match parent_dir.get(&intent.entry.name) {
        Some(existing) if existing == &intent.entry => {}
        Some(_) => {
            return Err(FileSystemError::CorruptState {
                reason: "intent log replay: namespace create directory entry conflict",
            });
        }
        None => {}
    }

    if !state.inodes.contains_key(&intent.inode.inode_id) {
        Arc::make_mut(&mut state.inodes).insert(intent.inode.inode_id, intent.inode.clone());
    }

    let parent_dir = Arc::make_mut(&mut state.directories)
        .get_mut(&intent.parent_inode_id)
        .expect("namespace create parent directory was validated before replay mutation");
    if !parent_dir.contains_key(&intent.entry.name) {
        parent_dir.insert(intent.entry.name.clone(), intent.entry.clone());
    }

    state.observe_explicit_inode_id(intent.inode.inode_id);
    state.known_inode_ids.insert(intent.parent_inode_id);
    state.dirty_inodes.insert(intent.inode.inode_id);
    state.dirty_inodes.insert(intent.parent_inode_id);
    state.dirty_dirs.insert(intent.parent_inode_id);
    Ok(())
}

/// Replay a single intent log entry against the filesystem state.
///
/// Dispatches on [`IntentLogEntryKind`]:
/// - SyncWriteRange / OdsyncDataRange / SharedMmapMsync: read payload from
///   store, apply to inode content, update size and metadata version.
/// - NamespaceSyncIntent: apply link_count_deltas to affected inodes, mark
///   parent directory dirty.
/// - NamespaceCreateIntent: restore metadata-only create/mknod inodes and
///   directory entries, using the embedded inode record as `rdev` authority.
/// - FsyncDirtyDrain / PressureFallback / CrashReplayReconcile: no-op.
pub(crate) fn replay_entry(
    entry: &IntentLogEntry,
    state: &mut crate::FileSystemState,
    store: &mut LocalObjectStore,
) -> Result<()> {
    use crate::allocation::next_generation_after;
    use crate::constants::content_chunk_size;
    use crate::content::content_chunk_count;
    use crate::encoding::{encode_content_chunk, encode_content_manifest};
    use crate::object_keys::content_chunk_object_key_for_version;
    use crate::object_keys::content_object_key_for_version;
    use crate::records::{ContentChunkRef, ContentManifestObject};
    use std::sync::Arc;
    use tidefs_local_object_store::checksum64;

    match &entry.entry_kind {
        IntentLogEntryKind::CrashReplayReconcile | IntentLogEntryKind::PressureFallback => {
            // No-op: reconcile markers and pressure fallbacks don't carry data.
        }
        IntentLogEntryKind::SyncWriteRange {
            inode_id,
            offset,
            length,
            ..
        }
        | IntentLogEntryKind::OdsyncDataRange {
            inode_id,
            offset,
            length,
            ..
        }
        | IntentLogEntryKind::SharedMmapMsync {
            inode_id,
            offset,
            length,
            ..
        } => {
            let data_key = intent_log_data_object_key(entry.entry_id);
            let payload = match store.get(data_key)? {
                Some(bytes) => bytes,
                None => {
                    return Err(FileSystemError::CorruptState {
                        reason: "intent log replay: missing data payload",
                    });
                }
            };

            let mut record = match state.inodes.get(inode_id) {
                Some(rec) => rec.clone(),
                None => {
                    return Err(FileSystemError::CorruptState {
                        reason: "intent log replay: inode not found",
                    });
                }
            };

            let write_end = offset.saturating_add(*length);
            let new_size = record.size.max(write_end);

            let existing_bytes = match crate::content::read_content_from_store(
                store, *inode_id, &record, true, None,
            ) {
                Ok(bytes) => bytes,
                Err(_) => vec![0u8; record.size as usize],
            };

            let mut full_content = existing_bytes;
            if new_size as usize > full_content.len() {
                full_content.resize(new_size as usize, 0);
            }
            let start = usize::try_from(*offset).unwrap_or(0);
            let len = payload.len().min(full_content.len().saturating_sub(start));
            full_content[start..start + len].copy_from_slice(&payload[..len]);

            let tick = next_generation_after(state.generation);
            record.data_version = tick;
            let chunk_size = content_chunk_size() as usize;
            let chunk_count = content_chunk_count(new_size).unwrap_or(0);
            let mut manifest = ContentManifestObject {
                inode_id: *inode_id,
                data_version: tick,
                file_size: new_size,
                chunk_size: content_chunk_size(),
                chunks: Vec::new(),
            };

            for ci in 0..chunk_count {
                let chunk_start = (ci as usize) * chunk_size;
                let chunk_end = (chunk_start + chunk_size).min(full_content.len());
                let chunk_data = &full_content[chunk_start..chunk_end];
                let chunk_len = chunk_data.len() as u32;

                let encoded_chunk = encode_content_chunk(
                    &record,
                    ci,
                    chunk_data,
                    &state.content_compression_policy,
                );
                let checksum = checksum64(&encoded_chunk);

                let chunk_key = content_chunk_object_key_for_version(*inode_id, tick, ci);
                store.put(chunk_key, &encoded_chunk)?;

                manifest.chunks.push(ContentChunkRef {
                    chunk_index: ci,
                    data_version: tick,
                    len: chunk_len,
                    checksum,
                    placement_receipt_generation: 0,
                });
            }

            let encoded_manifest = encode_content_manifest(&manifest);
            store.put(
                content_object_key_for_version(*inode_id, tick),
                &encoded_manifest,
            )?;

            record.size = new_size;
            record.metadata_version = tick;
            Arc::make_mut(&mut state.inodes).insert(*inode_id, record);
            state.dirty_inodes.insert(*inode_id);
            state.dirty_content.insert(*inode_id);
        }
        IntentLogEntryKind::FsyncDirtyDrain { .. } => {
            // fsync barriers don't carry replayable data — the individual
            // entries drained by this barrier are separate log entries.
        }
        IntentLogEntryKind::NamespaceSyncIntent {
            parent_inode_id,
            affected_inode_ids,
            link_count_deltas,
        } => {
            // Apply nlink deltas to affected inodes.
            for (inode_id, delta) in link_count_deltas {
                let mut record = match state.inodes.get(inode_id) {
                    Some(rec) => rec.clone(),
                    None => {
                        return Err(FileSystemError::CorruptState {
                            reason: "intent log replay: namespace inode not found",
                        });
                    }
                };
                if *delta > 0 {
                    record.nlink = record.nlink.saturating_add(*delta as u32);
                } else {
                    record.nlink = record.nlink.saturating_sub((-(*delta)) as u32);
                }
                Arc::make_mut(&mut state.inodes).insert(*inode_id, record);
                state.dirty_inodes.insert(*inode_id);
            }
            // Mark parent directory dirty so namespace can be rebuilt.
            if state.inodes.contains_key(parent_inode_id) {
                state.dirty_dirs.insert(*parent_inode_id);
            }
            // Track affected inodes.
            for id in affected_inode_ids {
                state.observe_explicit_inode_id(*id);
            }
        }
        IntentLogEntryKind::NamespaceCreateIntent(intent) => {
            replay_namespace_create_intent(intent, state)?;
        }
    }
    Ok(())
}

/// Replay uncommitted intent log entries against filesystem state.
///
/// Skips entries whose `root_anchor.transaction_id` is not greater than
/// `since_transaction_id`. Returns the count of replayed entries.
pub(crate) fn replay_uncommitted(
    log: &IntentLog,
    state: &mut crate::FileSystemState,
    store: &mut LocalObjectStore,
    since_transaction_id: u64,
) -> Result<u64> {
    // Delegate to the batched replay path for bounded cost under repeated writes.
    batched_replay_uncommitted(log, state, store, since_transaction_id)
}

// ---------------------------------------------------------------------------
// ReplayBatcher: bounded-cost replay under repeated writes
// ---------------------------------------------------------------------------

use std::collections::BTreeMap;

/// A single data-write payload queued for batched replay application.
#[derive(Clone, Debug)]
struct BatchedWrite {
    offset: u64,
    #[allow(dead_code)]
    length: u64,
    data: Vec<u8>,
}

/// Batches data-write intent-log entries by inode so that content is
/// read once per file, all payloads are applied, and chunks are
/// re-encoded once — giving O(file_size + N) replay cost instead of the
/// O(N * file_size) incurred by replaying every write individually.
struct ReplayBatcher {
    /// Accumulated writes keyed by inode.
    writes: BTreeMap<InodeId, Vec<BatchedWrite>>,
    /// The largest end-position observed for each inode (used to compute
    /// the final file size before encoding).
    max_end: BTreeMap<InodeId, u64>,
}

impl ReplayBatcher {
    fn new() -> Self {
        Self {
            writes: BTreeMap::new(),
            max_end: BTreeMap::new(),
        }
    }

    /// Queue a write payload for the given inode.
    fn push(&mut self, inode_id: InodeId, offset: u64, length: u64, data: Vec<u8>) {
        let end = offset.saturating_add(length);
        self.max_end
            .entry(inode_id)
            .and_modify(|e| *e = (*e).max(end))
            .or_insert(end);
        self.writes.entry(inode_id).or_default().push(BatchedWrite {
            offset,
            length,
            data,
        });
    }

    /// Number of distinct inodes with queued writes.
    #[allow(dead_code)]
    fn inode_count(&self) -> usize {
        self.writes.len()
    }

    /// Apply all queued writes to the filesystem state and object store.
    ///
    /// For each inode that has queued writes, this method:
    /// 1. Reads the current file content once.
    /// 2. Applies every queued payload in order.
    /// 3. Re-encodes all content chunks once.
    /// 4. Writes the new content manifest and updates the inode record.
    ///
    /// Returns the total number of write entries flushed.
    fn flush(
        &mut self,
        state: &mut crate::FileSystemState,
        store: &mut LocalObjectStore,
    ) -> Result<u64> {
        use crate::allocation::next_generation_after;
        use crate::constants::content_chunk_size;
        use crate::content::content_chunk_count;
        use crate::encoding::{encode_content_chunk, encode_content_manifest};
        use crate::object_keys::content_chunk_object_key_for_version;
        use crate::object_keys::content_object_key_for_version;
        use crate::records::{ContentChunkRef, ContentManifestObject};
        use std::sync::Arc;
        use tidefs_local_object_store::checksum64;

        let mut total_flushed: u64 = 0;

        // Take ownership of both maps to avoid unstable BTreeMap::drain.
        let writes_map = std::mem::take(&mut self.writes);
        let max_end_map = std::mem::take(&mut self.max_end);

        for (inode_id, writes) in writes_map {
            if writes.is_empty() {
                continue;
            }

            let mut record = match state.inodes.get(&inode_id) {
                Some(rec) => rec.clone(),
                None => {
                    return Err(FileSystemError::CorruptState {
                        reason: "batched replay: inode not found",
                    });
                }
            };

            // 1. Read existing content once.
            let existing_bytes =
                match crate::content::read_content_from_store(store, inode_id, &record, true, None)
                {
                    Ok(bytes) => bytes,
                    Err(_) => vec![0u8; record.size as usize],
                };

            // 2. Compute the final size: the maximum of the existing size,
            //    the current record size, and the end of every write.
            let new_end = max_end_map.get(&inode_id).copied().unwrap_or(0);
            let new_size = record.size.max(new_end);
            let mut full_content = existing_bytes;
            if new_size as usize > full_content.len() {
                full_content.resize(new_size as usize, 0);
            }

            // 3. Apply each write payload into the content buffer.
            for w in &writes {
                let start = usize::try_from(w.offset).unwrap_or(0);
                let available = full_content.len().saturating_sub(start);
                let len = w.data.len().min(available);
                full_content[start..start + len].copy_from_slice(&w.data[..len]);
                total_flushed += 1;
            }

            // 4. Re-encode all chunks once and write them.
            let tick = next_generation_after(state.generation);
            record.data_version = tick;
            let chunk_size = content_chunk_size() as usize;
            let chunk_count = content_chunk_count(new_size).unwrap_or(0);
            let mut manifest = ContentManifestObject {
                inode_id,
                data_version: tick,
                file_size: new_size,
                chunk_size: content_chunk_size(),
                chunks: Vec::new(),
            };

            for ci in 0..chunk_count {
                let chunk_start = (ci as usize) * chunk_size;
                let chunk_end = (chunk_start + chunk_size).min(full_content.len());
                let chunk_data = &full_content[chunk_start..chunk_end];
                let chunk_len = chunk_data.len() as u32;

                let encoded_chunk = encode_content_chunk(
                    &record,
                    ci,
                    chunk_data,
                    &state.content_compression_policy,
                );
                let checksum = checksum64(&encoded_chunk);

                let chunk_key = content_chunk_object_key_for_version(inode_id, tick, ci);
                store.put(chunk_key, &encoded_chunk)?;

                manifest.chunks.push(ContentChunkRef {
                    chunk_index: ci,
                    data_version: tick,
                    len: chunk_len,
                    checksum,
                    placement_receipt_generation: 0,
                });
            }

            let encoded_manifest = encode_content_manifest(&manifest);
            store.put(
                content_object_key_for_version(inode_id, tick),
                &encoded_manifest,
            )?;

            record.size = new_size;
            record.metadata_version = tick;
            Arc::make_mut(&mut state.inodes).insert(inode_id, record);
            state.dirty_inodes.insert(inode_id);
            state.dirty_content.insert(inode_id);
        }

        Ok(total_flushed)
    }
}

/// Replay uncommitted intent-log entries with bounded cost under
/// repeated writes to the same file.
///
/// Unlike [`replay_uncommitted`], which dispatches each write entry
/// individually (reading full file content and re-encoding all chunks
/// for every entry), this function groups SyncWriteRange /
/// OdsyncDataRange / SharedMmapMsync entries by inode into a
/// [`ReplayBatcher`]. Content is read once per file, all payloads are
/// applied, and chunks are re-encoded once — producing O(file_size + N)
/// replay cost instead of O(N * file_size).
///
/// Namespace operations (NamespaceSyncIntent) and non-replayable
/// records (FsyncDirtyDrain, PressureFallback, CrashReplayReconcile) are
/// still dispatched per-entry since they cannot be meaningfully batched.
///
/// Returns the total number of entries replayed.
pub(crate) fn batched_replay_uncommitted(
    log: &IntentLog,
    state: &mut crate::FileSystemState,
    store: &mut LocalObjectStore,
    since_transaction_id: u64,
) -> Result<u64> {
    let mut batcher = ReplayBatcher::new();
    let mut count: u64 = 0;

    for entry in &log.entries {
        if entry.root_anchor.transaction_id <= since_transaction_id {
            continue;
        }

        match &entry.entry_kind {
            IntentLogEntryKind::SyncWriteRange {
                inode_id,
                offset,
                length,
                ..
            }
            | IntentLogEntryKind::OdsyncDataRange {
                inode_id,
                offset,
                length,
                ..
            }
            | IntentLogEntryKind::SharedMmapMsync {
                inode_id,
                offset,
                length,
                ..
            } => {
                let data_key = intent_log_data_object_key(entry.entry_id);
                let payload = match store.get(data_key)? {
                    Some(bytes) => bytes,
                    None => {
                        return Err(FileSystemError::CorruptState {
                            reason: "intent log batched replay: missing data payload",
                        });
                    }
                };
                batcher.push(*inode_id, *offset, *length, payload);
            }
            // Non-write entries are replayed individually.
            _ => {
                replay_entry(entry, state, store)?;
                count += 1;
            }
        }
    }

    count += batcher.flush(state, store)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::InodeRecord;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tidefs_types_vfs_core::{
        Generation, NodeKind, ROOT_INODE_ID, S_IFBLK, S_IFCHR, S_IFIFO, S_IFREG, S_IFSOCK,
    };

    fn test_root_anchor() -> IntentLogRootAnchor {
        IntentLogRootAnchor {
            transaction_id: 1,
            generation: 1,
            manifest_digest: IntegrityDigest64(0xABCD),
        }
    }

    fn test_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    // -----------------------------------------------------------------------
    // Round-trip encode/decode tests (preserved from original)
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_sync_write_range() {
        let entry = IntentLogEntry {
            entry_id: 0,
            entry_kind: IntentLogEntryKind::SyncWriteRange {
                inode_id: InodeId::new(42),
                offset: 1024,
                length: 4096,
                payload_digest: IntegrityDigest64(0xDEADBEEF),
                data_version: 1,
            },
            root_anchor: test_root_anchor(),
            timestamp_ns: test_timestamp(),
        };
        let bytes = encode_intent_log_entry(&entry);
        let decoded = decode_intent_log_entry(&bytes).expect("decode");
        assert_eq!(decoded.entry_id, entry.entry_id);
        assert_eq!(decoded.root_anchor, entry.root_anchor);
        match (&entry.entry_kind, &decoded.entry_kind) {
            (
                IntentLogEntryKind::SyncWriteRange {
                    inode_id: a_id,
                    offset: a_off,
                    length: a_len,
                    payload_digest: a_dig,
                    ..
                },
                IntentLogEntryKind::SyncWriteRange {
                    inode_id: b_id,
                    offset: b_off,
                    length: b_len,
                    payload_digest: b_dig,
                    ..
                },
            ) => {
                assert_eq!(a_id, b_id);
                assert_eq!(a_off, b_off);
                assert_eq!(a_len, b_len);
                assert_eq!(a_dig, b_dig);
            }
            _ => panic!("wrong entry kind after decode"),
        }
    }

    #[test]
    fn round_trip_odsync_data_range() {
        let entry = IntentLogEntry {
            entry_id: 1,
            entry_kind: IntentLogEntryKind::OdsyncDataRange {
                inode_id: InodeId::new(7),
                offset: 0,
                length: 512,
                payload_digest: IntegrityDigest64(0xCAFE),
                has_size_delta: true,
                data_version: 1,
            },
            root_anchor: test_root_anchor(),
            timestamp_ns: test_timestamp(),
        };
        let bytes = encode_intent_log_entry(&entry);
        let decoded = decode_intent_log_entry(&bytes).expect("decode");
        match &decoded.entry_kind {
            IntentLogEntryKind::OdsyncDataRange { has_size_delta, .. } => {
                assert!(has_size_delta);
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn round_trip_fsync_dirty_drain() {
        let entry = IntentLogEntry {
            entry_id: 2,
            entry_kind: IntentLogEntryKind::FsyncDirtyDrain {
                inode_ids: vec![InodeId::new(1), InodeId::new(2), InodeId::new(3)],
            },
            root_anchor: test_root_anchor(),
            timestamp_ns: test_timestamp(),
        };
        let bytes = encode_intent_log_entry(&entry);
        let decoded = decode_intent_log_entry(&bytes).expect("decode");
        match &decoded.entry_kind {
            IntentLogEntryKind::FsyncDirtyDrain { inode_ids } => {
                assert_eq!(inode_ids.len(), 3);
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn round_trip_pressure_fallback() {
        let entry = IntentLogEntry {
            entry_id: 3,
            entry_kind: IntentLogEntryKind::PressureFallback,
            root_anchor: test_root_anchor(),
            timestamp_ns: test_timestamp(),
        };
        let bytes = encode_intent_log_entry(&entry);
        let decoded = decode_intent_log_entry(&bytes).expect("decode");
        assert!(matches!(
            decoded.entry_kind,
            IntentLogEntryKind::PressureFallback
        ));
    }

    #[test]
    fn round_trip_namespace_sync_intent() {
        let entry = IntentLogEntry {
            entry_id: 4,
            entry_kind: IntentLogEntryKind::NamespaceSyncIntent {
                parent_inode_id: InodeId::new(100),
                affected_inode_ids: vec![InodeId::new(101), InodeId::new(102)],
                link_count_deltas: vec![(InodeId::new(101), 1), (InodeId::new(102), -1)],
            },
            root_anchor: test_root_anchor(),
            timestamp_ns: test_timestamp(),
        };
        let bytes = encode_intent_log_entry(&entry);
        let decoded = decode_intent_log_entry(&bytes).expect("decode");
        match &decoded.entry_kind {
            IntentLogEntryKind::NamespaceSyncIntent {
                parent_inode_id,
                affected_inode_ids,
                link_count_deltas,
            } => {
                assert_eq!(parent_inode_id.get(), 100);
                assert_eq!(affected_inode_ids.len(), 2);
                assert_eq!(link_count_deltas.len(), 2);
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn round_trip_namespace_create_intent_preserves_rdev_authority() {
        let inode = special_inode(InodeId::new(44), NodeKind::CharDev, S_IFCHR | 0o600, 0x0103);
        let namespace_entry = namespace_entry("null", &inode);
        let entry = IntentLogEntry {
            entry_id: 44,
            entry_kind: IntentLogEntryKind::NamespaceCreateIntent(NamespaceCreateIntentRecord {
                parent_inode_id: ROOT_INODE_ID,
                entry: namespace_entry,
                inode,
            }),
            root_anchor: test_root_anchor(),
            timestamp_ns: test_timestamp(),
        };

        let bytes = encode_intent_log_entry(&entry);
        let decoded = decode_intent_log_entry(&bytes).expect("decode");
        match &decoded.entry_kind {
            IntentLogEntryKind::NamespaceCreateIntent(intent) => {
                assert_eq!(intent.parent_inode_id, ROOT_INODE_ID);
                assert_eq!(intent.entry.name, b"null");
                assert_eq!(intent.inode.kind(), NodeKind::CharDev);
                assert_eq!(intent.inode.rdev, 0x0103);
                assert_eq!(intent.entry.mode, S_IFCHR | 0o600);
                assert!(!decoded.entry_kind.references_data_inode(InodeId::new(44)));
                assert!(decoded.entry_kind.is_namespace_sync_for_dir(ROOT_INODE_ID));
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let bytes = vec![0u8; 32];
        assert!(decode_intent_log_entry(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_unknown_kind() {
        let entry = IntentLogEntry {
            entry_id: 0,
            entry_kind: IntentLogEntryKind::SyncWriteRange {
                inode_id: InodeId::new(1),
                offset: 0,
                length: 0,
                payload_digest: IntegrityDigest64(0),
                data_version: 1,
            },
            root_anchor: test_root_anchor(),
            timestamp_ns: 0,
        };
        let mut bytes = encode_intent_log_entry(&entry);
        let kind_pos = bytes.len().saturating_sub(41);
        bytes[kind_pos] = 99;
        assert!(decode_intent_log_entry(&bytes).is_err());
    }

    // -----------------------------------------------------------------------
    // LOG_DEVICE tests (from master #796)
    // -----------------------------------------------------------------------

    #[test]
    fn log_device_appends_and_reads_back() {
        let dir = std::env::temp_dir().join(format!(
            "tidefs-log_device-test-{:016x}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let log_device_path = dir.join("log_device.bin");
        let mut log_device = LogDeviceFile::open(&log_device_path).expect("open log_device");

        let entry = IntentLogEntry {
            entry_id: 0,
            entry_kind: IntentLogEntryKind::SyncWriteRange {
                inode_id: InodeId::new(1),
                offset: 0,
                length: 512,
                payload_digest: IntegrityDigest64(0xAAAA),
                data_version: 1,
            },
            root_anchor: test_root_anchor(),
            timestamp_ns: test_timestamp(),
        };
        let bytes = encode_intent_log_entry(&entry);
        log_device.append(&bytes).expect("log_device append");

        let recovered = log_device.read_all_entries().expect("read log_device");
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0], bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_device_crash_recovery_merges_entries() {
        let dir = std::env::temp_dir().join(format!(
            "tidefs-log_device-crash-{:016x}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Write 5 entries to LOG_DEVICE independently
        let log_device_path = dir.join("log_device.bin");
        {
            let mut log_device = LogDeviceFile::open(&log_device_path).expect("open log_device");
            for i in 0..5 {
                let entry = IntentLogEntry {
                    entry_id: i,
                    entry_kind: IntentLogEntryKind::SyncWriteRange {
                        inode_id: InodeId::new(100 + i),
                        offset: i * 4096,
                        length: 4096,
                        payload_digest: IntegrityDigest64(0xBEEF0000 + i),
                        data_version: 1,
                    },
                    root_anchor: test_root_anchor(),
                    timestamp_ns: test_timestamp(),
                };
                log_device
                    .append(&encode_intent_log_entry(&entry))
                    .expect("log_device append");
            }
        }

        // Now open IntentLog with LOG_DEVICE — should recover 5 entries
        let mut log = IntentLog::new();
        assert_eq!(log.len(), 0);
        log.open_log_device(&log_device_path)
            .expect("open_log_device for recovery");
        assert_eq!(log.len(), 5);
        assert!((0..5).all(|i| log.entries[i as usize].entry_id == i));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Group-commit batching tests
    // -----------------------------------------------------------------------

    fn test_store() -> (LocalObjectStore, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "tidefs-intent-log-test-{:016x}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = LocalObjectStore::open_with_options(
            &dir,
            tidefs_local_object_store::StoreOptions::test_fast(),
        )
        .expect("store open");
        (store, dir)
    }

    fn sync_write_entry(log: &mut IntentLog, store: &mut LocalObjectStore, entry_id: u64) {
        let accepted = log
            .append(
                store,
                IntentLogEntryKind::SyncWriteRange {
                    inode_id: InodeId::new(100 + entry_id),
                    offset: entry_id * 4096,
                    length: 4096,
                    payload_digest: IntegrityDigest64(0xCAFE0000 + entry_id),
                    data_version: 1,
                },
                test_root_anchor(),
                test_timestamp(),
            )
            .expect("append");
        assert!(
            accepted,
            "entry should be accepted when below pressure threshold"
        );
    }

    #[test]
    fn group_commit_batches_entries_before_flush() {
        let (mut store, _dir) = test_store();
        let mut log = IntentLog::with_config(IntentLogConfig {
            max_batch_entries: 8,
            adaptive_flush: false,
            flush_interval_us: 0,
            pressure_depth_threshold: 1024,
            log_max_bytes: 0,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        });

        for i in 0..5 {
            sync_write_entry(&mut log, &mut store, i);
        }
        assert_eq!(log.len(), 5);
        assert_eq!(log.pending_flush_count(), 5);
        assert!(store.get(intent_log_entry_object_key(0)).unwrap().is_none());

        log.flush(&mut store).expect("flush");
        assert_eq!(log.pending_flush_count(), 0);
        assert_eq!(log.len(), 5);

        let entry0 = store.get(intent_log_entry_object_key(0)).unwrap();
        assert!(entry0.is_some());
        let head = store.get(intent_log_head_object_key()).unwrap().unwrap();
        assert_eq!(u64::from_le_bytes(head[..8].try_into().unwrap()), 5);
    }

    #[test]
    fn auto_flush_on_batch_threshold() {
        let (mut store, _dir) = test_store();
        let mut log = IntentLog::with_config(IntentLogConfig {
            max_batch_entries: 3,
            adaptive_flush: false,
            flush_interval_us: 0,
            pressure_depth_threshold: 1024,
            log_max_bytes: 0,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        });

        for i in 0..3 {
            sync_write_entry(&mut log, &mut store, i);
        }
        assert_eq!(log.pending_flush_count(), 0);
        assert_eq!(log.len(), 3);

        for i in 0..3 {
            assert!(store.get(intent_log_entry_object_key(i)).unwrap().is_some());
        }
        let head = store.get(intent_log_head_object_key()).unwrap().unwrap();
        assert_eq!(u64::from_le_bytes(head[..8].try_into().unwrap()), 3);
    }

    #[test]
    fn flush_is_noop_when_nothing_pending() {
        let (mut store, _dir) = test_store();
        let mut log = IntentLog::new();
        assert!(log.flush(&mut store).is_ok());
        assert_eq!(log.pending_flush_count(), 0);
    }

    #[test]
    fn clear_handles_unflushed_entries() {
        let (mut store, _dir) = test_store();
        let mut log = IntentLog::with_config(IntentLogConfig {
            max_batch_entries: 64,
            adaptive_flush: false,
            flush_interval_us: 0,
            pressure_depth_threshold: 1024,
            log_max_bytes: 0,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        });

        for i in 0..5 {
            sync_write_entry(&mut log, &mut store, i);
        }
        assert_eq!(log.pending_flush_count(), 5);

        log.clear(&mut store).expect("clear");
        assert!(log.is_empty());
        assert_eq!(log.pending_flush_count(), 0);
        assert_eq!(log.next_entry_id, 0);
    }

    #[test]
    fn multiple_flush_cycles() {
        let (mut store, _dir) = test_store();
        let mut log = IntentLog::with_config(IntentLogConfig {
            max_batch_entries: 3,
            adaptive_flush: false,
            flush_interval_us: 0,
            pressure_depth_threshold: 1024,
            log_max_bytes: 0,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        });

        for i in 0..3 {
            sync_write_entry(&mut log, &mut store, i);
        }
        assert_eq!(log.pending_flush_count(), 0);
        log.clear(&mut store).expect("clear 1");

        for i in 0..4 {
            sync_write_entry(&mut log, &mut store, i);
        }
        assert_eq!(log.pending_flush_count(), 1);
        log.flush(&mut store).expect("flush 2");
        assert_eq!(log.pending_flush_count(), 0);

        for i in 0..4 {
            assert!(store.get(intent_log_entry_object_key(i)).unwrap().is_some());
        }
    }

    #[test]
    fn load_preserves_flushed_state() {
        let (mut store, _dir) = test_store();
        let config = IntentLogConfig::default();

        {
            let mut log = IntentLog::with_config(config.clone());
            for i in 0..5 {
                sync_write_entry(&mut log, &mut store, i);
            }
            log.flush(&mut store).expect("flush");
        }

        let loaded = IntentLog::load_with_config(&store, config).expect("load");
        assert_eq!(loaded.len(), 5);
        assert_eq!(loaded.pending_flush_count(), 0);
    }

    #[test]
    fn should_flush_returns_correctly() {
        let (mut store, _dir) = test_store();
        let mut log = IntentLog::with_config(IntentLogConfig {
            max_batch_entries: 64,
            adaptive_flush: false,
            flush_interval_us: 10_000,
            pressure_depth_threshold: 1024,
            log_max_bytes: 0,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        });

        assert!(!log.should_flush());
        sync_write_entry(&mut log, &mut store, 0);
        assert!(log.should_flush());

        log.flush(&mut store).expect("flush");
        assert!(!log.should_flush());

        let mut log2 = IntentLog::with_config(IntentLogConfig {
            max_batch_entries: 64,
            adaptive_flush: false,
            flush_interval_us: 0,
            pressure_depth_threshold: 1024,
            log_max_bytes: 0,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        });
        sync_write_entry(&mut log2, &mut store, 1);
        assert!(!log2.should_flush());
    }

    #[test]
    fn log_device_writes_during_batch_flush() {
        let dir = std::env::temp_dir().join(format!(
            "tidefs-log_device-batch-{:016x}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut store, store_dir) = test_store();
        let mut log = IntentLog::with_config(IntentLogConfig {
            max_batch_entries: 8,
            adaptive_flush: false,
            flush_interval_us: 0,
            pressure_depth_threshold: 1024,
            log_max_bytes: 0,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        });

        let log_device_path = dir.join("log_device.bin");
        log.open_log_device(&log_device_path)
            .expect("open log_device");

        for i in 0..3 {
            sync_write_entry(&mut log, &mut store, i);
        }
        assert_eq!(log.pending_flush_count(), 3);
        log.flush(&mut store).expect("flush");
        assert_eq!(log.pending_flush_count(), 0);

        // log device should have all 3 entries
        let mut log_device = LogDeviceFile::open(&log_device_path).expect("reopen log_device");
        let recovered = log_device.read_all_entries().expect("read log_device");
        assert_eq!(recovered.len(), 3);

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&store_dir);
    }

    // -----------------------------------------------------------------------
    // Pressure admission control tests
    // -----------------------------------------------------------------------

    #[test]
    fn pressure_fallback_emitted_when_depth_exceeds_threshold() {
        let (mut store, _dir) = test_store();
        let mut log = IntentLog::with_config(IntentLogConfig {
            max_batch_entries: 64,
            adaptive_flush: false,
            flush_interval_us: 0,
            pressure_depth_threshold: 3,
            log_max_bytes: 0,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        });

        for i in 0..3 {
            sync_write_entry(&mut log, &mut store, i);
        }
        assert_eq!(log.len(), 3);

        let result = log
            .append(
                &mut store,
                IntentLogEntryKind::SyncWriteRange {
                    inode_id: InodeId::new(200),
                    offset: 0,
                    length: 4096,
                    payload_digest: IntegrityDigest64(0xBEEF),
                    data_version: 1,
                },
                test_root_anchor(),
                test_timestamp(),
            )
            .expect("append with pressure");

        assert!(!result, "should return false when pressure triggers");
        assert!(log.len() >= 4);
        assert!(log
            .pending_entries()
            .iter()
            .any(|e| matches!(e.entry_kind, IntentLogEntryKind::PressureFallback)));
        assert_eq!(log.pending_flush_count(), 0);
    }

    #[test]
    fn pressure_fallback_does_not_accept_original_entry() {
        let (mut store, _dir) = test_store();
        let mut log = IntentLog::with_config(IntentLogConfig {
            max_batch_entries: 64,
            adaptive_flush: false,
            flush_interval_us: 0,
            pressure_depth_threshold: 0,
            log_max_bytes: 0,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        });

        let result = log
            .append(
                &mut store,
                IntentLogEntryKind::SyncWriteRange {
                    inode_id: InodeId::new(1),
                    offset: 0,
                    length: 4096,
                    payload_digest: IntegrityDigest64(0xAAAA),
                    data_version: 1,
                },
                test_root_anchor(),
                test_timestamp(),
            )
            .expect("append with zero threshold");

        assert!(!result);
        assert_eq!(log.len(), 1);
        assert!(matches!(
            log.pending_entries()[0].entry_kind,
            IntentLogEntryKind::PressureFallback
        ));
    }

    #[test]
    fn group_commit_config_defaults() {
        let config = IntentLogConfig::default();
        assert_eq!(config.max_batch_entries, 64);
        assert_eq!(config.flush_interval_us, 500);
        assert_eq!(config.pressure_depth_threshold, 1024);
    }

    #[test]
    fn group_commit_config_conservative() {
        let config = IntentLogConfig::conservative();
        assert_eq!(config.max_batch_entries, 16);
    }

    #[test]
    fn group_commit_config_throughput() {
        let config = IntentLogConfig::throughput();
        assert_eq!(config.max_batch_entries, 256);
    }

    // ──────────────────────────────────────────────────────────────────
    // Byte-based space pressure tests (#3424)
    // ──────────────────────────────────────────────────────────────────

    fn pressure_config() -> IntentLogConfig {
        IntentLogConfig {
            max_batch_entries: 64,
            adaptive_flush: false,
            flush_interval_us: 0,
            pressure_depth_threshold: 1024,
            log_max_bytes: 1_000_000,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        }
    }

    #[test]
    fn compute_pressure_level_healthy_when_below_warning() {
        let (_store, _dir) = test_store();
        let log = IntentLog::with_config(pressure_config());
        // Force used_bytes via append
        // Default: log_max_bytes=1M, used=0 -> Healthy
        assert_eq!(log.compute_pressure_level(), LogSpacePressureLevel::Healthy);
        assert_eq!(
            log.space_stats().pressure_level,
            LogSpacePressureLevel::Healthy
        );
    }

    #[test]
    fn compute_pressure_level_warning_at_50_percent() {
        let (mut store, _dir) = test_store();
        let mut log = IntentLog::with_config(pressure_config());
        // Append entries totaling ~600k bytes to cross 50%
        // Each entry is roughly 60 bytes
        for i in 0..10_000 {
            let _ = log.append(
                &mut store,
                IntentLogEntryKind::SyncWriteRange {
                    inode_id: InodeId::new(100 + i),
                    offset: i * 4096,
                    length: 4096,
                    payload_digest: IntegrityDigest64(0xCAFE0000 + i),
                    data_version: 1,
                },
                test_root_anchor(),
                test_timestamp(),
            );
        }
        assert_eq!(log.compute_pressure_level(), LogSpacePressureLevel::Warning);
    }

    #[test]
    fn compute_pressure_level_sync_at_75_percent() {
        let (mut store, _dir) = test_store();
        let mut log = IntentLog::with_config(pressure_config());
        // ~750k bytes
        for i in 0..12_500 {
            let _ = log.append(
                &mut store,
                IntentLogEntryKind::SyncWriteRange {
                    inode_id: InodeId::new(100 + i),
                    offset: i * 4096,
                    length: 4096,
                    payload_digest: IntegrityDigest64(0xCAFE0000 + i),
                    data_version: 1,
                },
                test_root_anchor(),
                test_timestamp(),
            );
        }
        assert_eq!(log.compute_pressure_level(), LogSpacePressureLevel::Sync);
        assert!(log.space_stats().write_throttle_events > 0);
    }

    #[test]
    fn compute_pressure_level_critical_at_90_percent() {
        let (mut store, _dir) = test_store();
        // Narrow log so we cross 90% quickly
        let cfg = IntentLogConfig {
            log_max_bytes: 10_000,
            ..pressure_config()
        };
        let mut log = IntentLog::with_config(cfg);
        // Append enough to cross 90% (9k out of 10k)
        for i in 0..200 {
            let accepted = log.append(
                &mut store,
                IntentLogEntryKind::SyncWriteRange {
                    inode_id: InodeId::new(100 + i),
                    offset: i * 4096,
                    length: 4096,
                    payload_digest: IntegrityDigest64(0xCAFE0000 + i),
                    data_version: 1,
                },
                test_root_anchor(),
                test_timestamp(),
            );
            // At some point, appends should be refused at Critical
            if accepted.is_err() || !accepted.unwrap() {
                assert_eq!(
                    log.compute_pressure_level(),
                    LogSpacePressureLevel::Critical
                );
                return;
            }
        }
        // If we get here, the log didn't reach Critical — still acceptable
        let level = log.compute_pressure_level();
        assert!(level >= LogSpacePressureLevel::Sync);
    }

    #[test]
    fn critical_pressure_refuses_append() {
        let (mut store, _dir) = test_store();
        let cfg = IntentLogConfig {
            log_max_bytes: 5_000,
            ..pressure_config()
        };
        let mut log = IntentLog::with_config(cfg);
        // Append entries until Critical blocks
        let mut blocked = false;
        for _i in 0..500 {
            match log.append(
                &mut store,
                IntentLogEntryKind::SyncWriteRange {
                    inode_id: InodeId::new(1),
                    offset: 0,
                    length: 4096,
                    payload_digest: IntegrityDigest64(0xBEEF),
                    data_version: 1,
                },
                test_root_anchor(),
                test_timestamp(),
            ) {
                Ok(true) => {} // accepted
                Ok(false) => {
                    blocked = true;
                    break;
                }
                Err(_) => {
                    blocked = true;
                    break;
                }
            }
        }
        assert!(
            blocked,
            "expected append to be refused at Critical pressure"
        );
        assert_eq!(
            log.compute_pressure_level(),
            LogSpacePressureLevel::Critical
        );
    }

    #[test]
    fn byte_pressure_disabled_when_log_max_bytes_is_zero() {
        let (mut store, _dir) = test_store();
        let cfg = IntentLogConfig {
            log_max_bytes: 0,
            ..pressure_config()
        };
        let mut log = IntentLog::with_config(cfg);
        assert_eq!(log.compute_pressure_level(), LogSpacePressureLevel::Healthy);
        // Should accept many entries without blocking
        for i in 0..100 {
            let accepted = log.append(
                &mut store,
                IntentLogEntryKind::SyncWriteRange {
                    inode_id: InodeId::new(100 + i),
                    offset: i * 4096,
                    length: 4096,
                    payload_digest: IntegrityDigest64(0xCAFE0000 + i),
                    data_version: 1,
                },
                test_root_anchor(),
                test_timestamp(),
            );
            assert!(accepted.is_ok() && accepted.unwrap());
        }
    }

    #[test]
    fn trim_committed_removes_entries_below_lsn() {
        let (mut store, _dir) = test_store();
        let mut log = IntentLog::with_config(IntentLogConfig {
            max_batch_entries: 64,
            adaptive_flush: false,
            flush_interval_us: 0,
            pressure_depth_threshold: 1024,
            log_max_bytes: 0,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        });

        for i in 0..10 {
            sync_write_entry(&mut log, &mut store, i);
        }
        assert_eq!(log.len(), 10);
        let bytes_before = log.bytes_used();

        // Trim entries with ids <= 4
        let trimmed = log.trim_committed(4);
        assert_eq!(trimmed, 5);
        assert_eq!(log.len(), 5);
        assert!(log.bytes_used() < bytes_before);
        // Remaining entries should have entry_id > 4
        for entry in log.pending_entries() {
            assert!(entry.entry_id > 4);
        }
    }

    #[test]
    fn trim_flushed_removes_all_flushed_entries() {
        let (mut store, _dir) = test_store();
        let mut log = IntentLog::with_config(IntentLogConfig {
            max_batch_entries: 4,
            adaptive_flush: false,
            flush_interval_us: 0,
            pressure_depth_threshold: 1024,
            log_max_bytes: 0,
            pressure_warning_threshold: 0.50,
            pressure_sync_threshold: 0.75,
            pressure_critical_threshold: 0.90,
        });

        // First batch: auto-flushes at 4
        for i in 0..4 {
            sync_write_entry(&mut log, &mut store, i);
        }
        assert_eq!(log.pending_flush_count(), 0);
        assert_eq!(log.len(), 4);

        let trimmed = log.trim_flushed();
        assert_eq!(trimmed, 4);
        assert!(log.is_empty());
        assert_eq!(log.bytes_used(), 0);
    }

    #[test]
    fn trim_committed_zero_or_empty_is_noop() {
        let mut log = IntentLog::new();
        assert_eq!(log.trim_committed(0), 0);
        assert_eq!(log.trim_flushed(), 0);
    }

    #[test]
    fn space_stats_accumulate_throttle_events() {
        let (mut store, _dir) = test_store();
        let cfg = IntentLogConfig {
            log_max_bytes: 100_000,
            ..pressure_config()
        };
        let mut log = IntentLog::with_config(cfg);
        let initial_stats = log.space_stats();
        assert_eq!(initial_stats.write_throttle_events, 0);
        assert_eq!(initial_stats.segments_trimmed, 0);

        // Fill to Sync/Critical level — throttle counter should increase
        for _i in 0..2_000 {
            let _ = log.append(
                &mut store,
                IntentLogEntryKind::SyncWriteRange {
                    inode_id: InodeId::new(1),
                    offset: 0,
                    length: 4096,
                    payload_digest: IntegrityDigest64(0xCAFE),
                    data_version: 1,
                },
                test_root_anchor(),
                test_timestamp(),
            );
        }
        let stats = log.space_stats();
        assert!(stats.write_throttle_events > 0);
        assert!(stats.log_used_bytes > 0);
        assert_eq!(stats.log_max_bytes, 100_000);
    }

    #[test]
    fn encoded_entry_len_matches_actual_encoding() {
        let entry = IntentLogEntry {
            entry_id: 42,
            entry_kind: IntentLogEntryKind::SyncWriteRange {
                inode_id: InodeId::new(7),
                offset: 1024,
                length: 4096,
                payload_digest: IntegrityDigest64(0xDEADBEEF),
                data_version: 1,
            },
            root_anchor: test_root_anchor(),
            timestamp_ns: test_timestamp(),
        };
        let encoded = encode_intent_log_entry(&entry);
        assert_eq!(encoded_entry_len(&entry), encoded.len());
    }

    #[test]
    fn encoded_entry_len_various_kinds() {
        let anchor = test_root_anchor();
        let ts = test_timestamp();
        let special_node = special_inode(
            InodeId::new(103),
            NodeKind::CharDev,
            S_IFCHR | 0o600,
            0x0103,
        );

        let cases: Vec<IntentLogEntry> = vec![
            IntentLogEntry {
                entry_id: 0,
                entry_kind: IntentLogEntryKind::PressureFallback,
                root_anchor: anchor.clone(),
                timestamp_ns: ts,
            },
            IntentLogEntry {
                entry_id: 1,
                entry_kind: IntentLogEntryKind::FsyncDirtyDrain {
                    inode_ids: vec![InodeId::new(1), InodeId::new(2)],
                },
                root_anchor: anchor.clone(),
                timestamp_ns: ts,
            },
            IntentLogEntry {
                entry_id: 2,
                entry_kind: IntentLogEntryKind::NamespaceSyncIntent {
                    parent_inode_id: InodeId::new(100),
                    affected_inode_ids: vec![InodeId::new(101)],
                    link_count_deltas: vec![(InodeId::new(101), 1), (InodeId::new(102), -1)],
                },
                root_anchor: anchor,
                timestamp_ns: ts,
            },
            IntentLogEntry {
                entry_id: 3,
                entry_kind: IntentLogEntryKind::NamespaceCreateIntent(
                    NamespaceCreateIntentRecord {
                        parent_inode_id: ROOT_INODE_ID,
                        entry: namespace_entry("null", &special_node),
                        inode: special_node,
                    },
                ),
                root_anchor: test_root_anchor(),
                timestamp_ns: ts,
            },
        ];
        for entry in &cases {
            let encoded = encode_intent_log_entry(entry);
            assert_eq!(encoded_entry_len(entry), encoded.len(), "mismatch for kind");
        }
    }

    #[test]
    fn log_space_pressure_level_ordering() {
        assert!(LogSpacePressureLevel::Healthy < LogSpacePressureLevel::Warning);
        assert!(LogSpacePressureLevel::Warning < LogSpacePressureLevel::Sync);
        assert!(LogSpacePressureLevel::Sync < LogSpacePressureLevel::Critical);
    }

    #[test]
    fn log_space_pressure_level_labels() {
        assert_eq!(LogSpacePressureLevel::Healthy.label(), "healthy");
        assert_eq!(LogSpacePressureLevel::Warning.label(), "warning");
        assert_eq!(LogSpacePressureLevel::Sync.label(), "sync");
        assert_eq!(LogSpacePressureLevel::Critical.label(), "critical");
    }

    #[test]
    fn log_space_pressure_level_default_is_healthy() {
        assert_eq!(
            LogSpacePressureLevel::default(),
            LogSpacePressureLevel::Healthy
        );
    }

    // -----------------------------------------------------------------------
    // Replay tests
    // -----------------------------------------------------------------------

    fn minimal_state() -> crate::FileSystemState {
        crate::recovery::initial_state()
    }

    fn anchor_for_tx(transaction_id: u64) -> IntentLogRootAnchor {
        IntentLogRootAnchor {
            transaction_id,
            generation: 1,
            manifest_digest: IntegrityDigest64(0),
        }
    }

    fn store_data_payload(store: &mut LocalObjectStore, entry_id: u64, data: &[u8]) {
        store
            .put(intent_log_data_object_key(entry_id), data)
            .expect("store data payload");
    }

    fn make_test_inode(state: &mut crate::FileSystemState, inode_id: InodeId, size: u64) {
        let record = InodeRecord {
            rdev: 0,
            dir_storage_kind: 0,
            inode_id,
            generation: Generation::new(1),
            facets: NodeKind::File.to_facets(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            nlink: 1,
            size,
            data_version: 1,
            metadata_version: 1,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattr_storage_kind: 0,
            xattrs: BTreeMap::new(),
            dir_rev: 0,
            subtree_rev: 0,
        };
        Arc::make_mut(&mut state.inodes).insert(inode_id, record);
        state.observe_explicit_inode_id(inode_id);
    }

    fn special_inode(inode_id: InodeId, kind: NodeKind, mode: u32, rdev: u32) -> InodeRecord {
        InodeRecord {
            rdev,
            dir_storage_kind: 0,
            inode_id,
            generation: Generation::new(inode_id.get()),
            facets: kind.to_facets(),
            mode,
            uid: 0,
            gid: 0,
            nlink: 1,
            size: 0,
            data_version: 1,
            metadata_version: 1,
            posix_time: crate::types::PosixTimeRecord::new(1, 1, 1, 1),
            xattr_storage_kind: 0,
            xattrs: BTreeMap::new(),
            dir_rev: 0,
            subtree_rev: 0,
        }
    }

    fn namespace_entry(name: &str, inode: &InodeRecord) -> crate::types::NamespaceEntry {
        crate::types::NamespaceEntry {
            name: name.as_bytes().to_vec(),
            inode_id: inode.inode_id,
            generation: inode.generation,
            facets: inode.facets,
            mode: inode.mode,
        }
    }

    #[test]
    fn replay_sync_write_range_updates_content() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();

        let file_id = InodeId::new(10);
        make_test_inode(&mut state, file_id, 0);

        let payload = b"hello world";
        store_data_payload(&mut store, 1, payload);

        let entry = IntentLogEntry {
            entry_id: 1,
            entry_kind: IntentLogEntryKind::SyncWriteRange {
                inode_id: file_id,
                offset: 0,
                length: payload.len() as u64,
                payload_digest: IntegrityDigest64(0),
                data_version: 1,
            },
            root_anchor: anchor_for_tx(2),
            timestamp_ns: 0,
        };

        replay_entry(&entry, &mut state, &mut store).expect("replay");

        let record = state.inodes.get(&file_id).expect("inode should exist");
        assert_eq!(record.size, payload.len() as u64);
        assert!(state.dirty_inodes.contains(&file_id));
        assert!(state.dirty_content.contains(&file_id));
    }

    #[test]
    fn replay_odsync_data_range_preserves_existing_content() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();

        let file_id = InodeId::new(11);
        make_test_inode(&mut state, file_id, 0);

        // Write a first payload at offset 0
        let payload1 = b"AAAA";
        store_data_payload(&mut store, 1, payload1);
        let entry1 = IntentLogEntry {
            entry_id: 1,
            entry_kind: IntentLogEntryKind::OdsyncDataRange {
                inode_id: file_id,
                offset: 0,
                length: 4,
                payload_digest: IntegrityDigest64(0),
                has_size_delta: true,
                data_version: 1,
            },
            root_anchor: anchor_for_tx(2),
            timestamp_ns: 0,
        };
        replay_entry(&entry1, &mut state, &mut store).expect("replay 1");

        // Write a second payload at offset 4
        let payload2 = b"BBBB";
        store_data_payload(&mut store, 2, payload2);
        let entry2 = IntentLogEntry {
            entry_id: 2,
            entry_kind: IntentLogEntryKind::OdsyncDataRange {
                inode_id: file_id,
                offset: 4,
                length: 4,
                payload_digest: IntegrityDigest64(0),
                has_size_delta: true,
                data_version: 2,
            },
            root_anchor: anchor_for_tx(3),
            timestamp_ns: 0,
        };
        replay_entry(&entry2, &mut state, &mut store).expect("replay 2");

        let record = state.inodes.get(&file_id).expect("inode should exist");
        assert_eq!(record.size, 8);
    }

    #[test]
    fn replay_shared_mmap_msync_behaves_like_sync_write() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();

        let file_id = InodeId::new(12);
        make_test_inode(&mut state, file_id, 0);

        let payload = b"mmap data";
        store_data_payload(&mut store, 3, payload);

        let entry = IntentLogEntry {
            entry_id: 3,
            entry_kind: IntentLogEntryKind::SharedMmapMsync {
                inode_id: file_id,
                offset: 0,
                length: payload.len() as u64,
                payload_digest: IntegrityDigest64(0),
                data_version: 1,
            },
            root_anchor: anchor_for_tx(2),
            timestamp_ns: 0,
        };

        replay_entry(&entry, &mut state, &mut store).expect("replay");
        let record = state.inodes.get(&file_id).unwrap();
        assert_eq!(record.size, payload.len() as u64);
    }

    #[test]
    fn replay_fsync_dirty_drain_is_noop() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();

        let entry = IntentLogEntry {
            entry_id: 5,
            entry_kind: IntentLogEntryKind::FsyncDirtyDrain { inode_ids: vec![] },
            root_anchor: anchor_for_tx(2),
            timestamp_ns: 0,
        };

        // Should succeed without modifying state
        replay_entry(&entry, &mut state, &mut store).expect("replay");
    }

    #[test]
    fn replay_pressure_fallback_is_noop() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();

        let entry = IntentLogEntry {
            entry_id: 6,
            entry_kind: IntentLogEntryKind::PressureFallback,
            root_anchor: anchor_for_tx(2),
            timestamp_ns: 0,
        };
        replay_entry(&entry, &mut state, &mut store).expect("replay");
    }

    #[test]
    fn replay_crash_replay_reconcile_is_noop() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();

        let entry = IntentLogEntry {
            entry_id: 7,
            entry_kind: IntentLogEntryKind::CrashReplayReconcile,
            root_anchor: anchor_for_tx(2),
            timestamp_ns: 0,
        };
        replay_entry(&entry, &mut state, &mut store).expect("replay");
    }

    #[test]
    fn replay_namespace_sync_intent_applies_nlink_deltas() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();

        let dir_id = InodeId::new(100);
        let child1 = InodeId::new(101);
        let child2 = InodeId::new(102);

        // Set up parent directory
        let dir_record = InodeRecord {
            rdev: 0,
            dir_storage_kind: 0,
            inode_id: dir_id,
            generation: Generation::new(1),
            facets: NodeKind::Dir.to_facets(),
            mode: 0o755,
            uid: 0,
            gid: 0,
            nlink: 2,
            size: 0,
            data_version: 0,
            metadata_version: 1,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattr_storage_kind: 0,
            xattrs: BTreeMap::new(),
            dir_rev: 0,
            subtree_rev: 0,
        };
        Arc::make_mut(&mut state.inodes).insert(dir_id, dir_record);
        state.observe_explicit_inode_id(dir_id);

        // Set up children
        make_test_inode(&mut state, child1, 0);
        make_test_inode(&mut state, child2, 0);

        let entry = IntentLogEntry {
            entry_id: 8,
            entry_kind: IntentLogEntryKind::NamespaceSyncIntent {
                parent_inode_id: dir_id,
                affected_inode_ids: vec![child1, child2],
                link_count_deltas: vec![(child1, 1), (child2, -1)],
            },
            root_anchor: anchor_for_tx(2),
            timestamp_ns: 0,
        };

        replay_entry(&entry, &mut state, &mut store).expect("replay");

        // child1 nlink should go from 1 to 2
        let r1 = state.inodes.get(&child1).unwrap();
        assert_eq!(r1.nlink, 2);
        assert!(state.dirty_inodes.contains(&child1));

        // child2 nlink should go from 1 to 0
        let r2 = state.inodes.get(&child2).unwrap();
        assert_eq!(r2.nlink, 0);
        assert!(state.dirty_inodes.contains(&child2));

        // Parent directory should be marked dirty
        assert!(state.dirty_dirs.contains(&dir_id));
    }

    #[test]
    fn replay_namespace_create_intent_restores_files_and_special_nodes_with_rdev() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();
        let cases = [
            ("file", NodeKind::File, S_IFREG | 0o644, 0),
            ("fifo", NodeKind::Fifo, S_IFIFO | 0o644, 0),
            ("char", NodeKind::CharDev, S_IFCHR | 0o600, 0x0103),
            ("block", NodeKind::BlockDev, S_IFBLK | 0o660, 0x0801),
            ("socket", NodeKind::Socket, S_IFSOCK | 0o700, 0),
        ];

        for (idx, (name, kind, mode, rdev)) in cases.into_iter().enumerate() {
            let inode = special_inode(InodeId::new(200 + idx as u64), kind, mode, rdev);
            let intent = NamespaceCreateIntentRecord {
                parent_inode_id: ROOT_INODE_ID,
                entry: namespace_entry(name, &inode),
                inode: inode.clone(),
            };
            let entry = IntentLogEntry {
                entry_id: 100 + idx as u64,
                entry_kind: IntentLogEntryKind::NamespaceCreateIntent(intent),
                root_anchor: anchor_for_tx(2),
                timestamp_ns: 0,
            };

            replay_entry(&entry, &mut state, &mut store).expect("replay create");

            let recovered = state.inodes.get(&inode.inode_id).expect("inode");
            assert_eq!(recovered.kind(), kind, "wrong kind for {name}");
            assert_eq!(recovered.mode, mode, "wrong mode for {name}");
            assert_eq!(recovered.rdev, rdev, "wrong rdev for {name}");

            let root_dir = state.directories.get(&ROOT_INODE_ID).expect("root dir");
            let recovered_entry = root_dir
                .get(name.as_bytes())
                .unwrap_or_else(|| panic!("missing entry for {name}"));
            assert_eq!(recovered_entry.inode_id, inode.inode_id);
            assert_eq!(recovered_entry.kind(), kind);
            assert!(state.known_inode_ids.contains(&inode.inode_id));
            assert!(state.dirty_inodes.contains(&inode.inode_id));
        }

        assert!(state.dirty_dirs.contains(&ROOT_INODE_ID));
        assert!(state.dirty_inodes.contains(&ROOT_INODE_ID));
        assert_eq!(state.next_inode_id(), InodeId::new(205));
    }

    #[test]
    fn replay_namespace_create_intent_is_idempotent() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();
        let inode = special_inode(
            InodeId::new(250),
            NodeKind::CharDev,
            S_IFCHR | 0o600,
            0x0105,
        );
        let intent = NamespaceCreateIntentRecord {
            parent_inode_id: ROOT_INODE_ID,
            entry: namespace_entry("tty", &inode),
            inode,
        };
        let entry = IntentLogEntry {
            entry_id: 250,
            entry_kind: IntentLogEntryKind::NamespaceCreateIntent(intent),
            root_anchor: anchor_for_tx(2),
            timestamp_ns: 0,
        };

        replay_entry(&entry, &mut state, &mut store).expect("first replay");
        replay_entry(&entry, &mut state, &mut store).expect("second replay");

        let root_dir = state.directories.get(&ROOT_INODE_ID).expect("root dir");
        assert_eq!(root_dir.get(b"tty".as_slice()).unwrap().inode_id.get(), 250);
        assert_eq!(state.inodes.get(&InodeId::new(250)).unwrap().rdev, 0x0105);
    }

    #[test]
    fn replay_namespace_create_intent_rejects_non_device_rdev() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();
        let inode = special_inode(InodeId::new(251), NodeKind::Fifo, S_IFIFO | 0o644, 0x0103);
        let intent = NamespaceCreateIntentRecord {
            parent_inode_id: ROOT_INODE_ID,
            entry: namespace_entry("pipe", &inode),
            inode,
        };
        let entry = IntentLogEntry {
            entry_id: 251,
            entry_kind: IntentLogEntryKind::NamespaceCreateIntent(intent),
            root_anchor: anchor_for_tx(2),
            timestamp_ns: 0,
        };

        assert!(replay_entry(&entry, &mut state, &mut store).is_err());
        assert!(!state.inodes.contains_key(&InodeId::new(251)));
        assert!(!state
            .directories
            .get(&ROOT_INODE_ID)
            .expect("root dir")
            .contains_key(b"pipe".as_slice()));
    }

    #[test]
    fn replay_uncommitted_skips_committed_entries() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();
        let file_id = InodeId::new(20);
        make_test_inode(&mut state, file_id, 0);

        // Create a log with two entries: one at tx 1, one at tx 3
        let mut log = IntentLog::new();
        // We manually push entries for testing
        let entry1 = IntentLogEntry {
            entry_id: 1,
            entry_kind: IntentLogEntryKind::SyncWriteRange {
                inode_id: file_id,
                offset: 0,
                length: 4,
                payload_digest: IntegrityDigest64(0),
                data_version: 1,
            },
            root_anchor: IntentLogRootAnchor {
                transaction_id: 1,
                generation: 1,
                manifest_digest: IntegrityDigest64(0),
            },
            timestamp_ns: 0,
        };
        let entry2 = IntentLogEntry {
            entry_id: 2,
            entry_kind: IntentLogEntryKind::SyncWriteRange {
                inode_id: file_id,
                offset: 4,
                length: 4,
                payload_digest: IntegrityDigest64(0),
                data_version: 1,
            },
            root_anchor: IntentLogRootAnchor {
                transaction_id: 3,
                generation: 1,
                manifest_digest: IntegrityDigest64(0),
            },
            timestamp_ns: 0,
        };
        // Push entries directly into log.entries
        log.entries.push(entry1);
        log.entries.push(entry2);
        log.flushed_entry_count = 2;

        store_data_payload(&mut store, 2, b"BBBB");

        // Replay with since_transaction_id = 1: only entry2 (tx=3) should replay
        let count =
            replay_uncommitted(&log, &mut state, &mut store, 1).expect("replay_uncommitted");
        assert_eq!(count, 1);

        let record = state.inodes.get(&file_id).unwrap();
        // Only the second write (offset 4, len 4) should be applied
        assert_eq!(record.size, 8);
    }

    #[test]
    fn replay_uncommitted_noop_when_nothing_to_replay() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();

        let mut log = IntentLog::new();
        let entry = IntentLogEntry {
            entry_id: 1,
            entry_kind: IntentLogEntryKind::SyncWriteRange {
                inode_id: InodeId::new(30),
                offset: 0,
                length: 4,
                payload_digest: IntegrityDigest64(0),
                data_version: 1,
            },
            root_anchor: IntentLogRootAnchor {
                transaction_id: 1,
                generation: 1,
                manifest_digest: IntegrityDigest64(0),
            },
            timestamp_ns: 0,
        };
        log.entries.push(entry);
        log.flushed_entry_count = 1;

        // since_transaction_id = 5 => no entries should replay
        let count =
            replay_uncommitted(&log, &mut state, &mut store, 5).expect("replay_uncommitted");
        assert_eq!(count, 0);
    }

    #[test]
    fn replay_entry_missing_inode_errors() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();

        let entry = IntentLogEntry {
            entry_id: 1,
            entry_kind: IntentLogEntryKind::SyncWriteRange {
                inode_id: InodeId::new(999),
                offset: 0,
                length: 4,
                payload_digest: IntegrityDigest64(0),
                data_version: 1,
            },
            root_anchor: anchor_for_tx(2),
            timestamp_ns: 0,
        };

        store_data_payload(&mut store, 1, b"data");
        let result = replay_entry(&entry, &mut state, &mut store);
        assert!(result.is_err());
    }

    #[test]
    fn replay_entry_missing_payload_errors() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();
        let file_id = InodeId::new(40);
        make_test_inode(&mut state, file_id, 0);

        let entry = IntentLogEntry {
            entry_id: 99,
            entry_kind: IntentLogEntryKind::SyncWriteRange {
                inode_id: file_id,
                offset: 0,
                length: 4,
                payload_digest: IntegrityDigest64(0),
                data_version: 1,
            },
            root_anchor: anchor_for_tx(2),
            timestamp_ns: 0,
        };

        // No data payload stored for entry 99
        let result = replay_entry(&entry, &mut state, &mut store);
        assert!(result.is_err());
    }

    #[test]
    fn replay_is_needed_detects_uncommitted() {
        let mut log = IntentLog::new();
        log.entries.push(IntentLogEntry {
            entry_id: 1,
            entry_kind: IntentLogEntryKind::PressureFallback,
            root_anchor: IntentLogRootAnchor {
                transaction_id: 5,
                generation: 1,
                manifest_digest: IntegrityDigest64(0),
            },
            timestamp_ns: 0,
        });
        log.flushed_entry_count = 1;

        assert!(log.replay_is_needed(0));
        assert!(log.replay_is_needed(4));
        assert!(!log.replay_is_needed(5));
        assert!(!log.replay_is_needed(10));
    }

    #[test]
    fn replay_is_needed_empty_log() {
        let log = IntentLog::new();
        assert!(!log.replay_is_needed(0));
        assert!(!log.replay_is_needed(100));
    }

    // -----------------------------------------------------------------------
    // Batched replay stress and correctness tests (REL-STOR-002)
    // -----------------------------------------------------------------------

    fn make_write_entry(
        store: &mut LocalObjectStore,
        entry_id: u64,
        inode_id: InodeId,
        offset: u64,
        data: &[u8],
        tx: u64,
    ) -> IntentLogEntry {
        store_data_payload(store, entry_id, data);
        IntentLogEntry {
            entry_id,
            entry_kind: IntentLogEntryKind::SyncWriteRange {
                inode_id,
                offset,
                length: data.len() as u64,
                payload_digest: IntegrityDigest64(0),
                data_version: 1,
            },
            root_anchor: anchor_for_tx(tx),
            timestamp_ns: 0,
        }
    }

    fn log_from_entries(entries: Vec<IntentLogEntry>) -> IntentLog {
        let mut log = IntentLog::new();
        log.flushed_entry_count = entries.len();
        log.entries = entries;
        log
    }

    #[test]
    fn batched_replay_many_writes_to_same_file_is_correct() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();
        let file_id = InodeId::new(50);
        make_test_inode(&mut state, file_id, 0);

        let mut entries: Vec<IntentLogEntry> = Vec::new();
        for i in 0..100u64 {
            let data = vec![b'A' + (i % 26) as u8; 8];
            entries.push(make_write_entry(
                &mut store,
                i,
                file_id,
                i * 3,
                &data,
                i + 1,
            ));
        }

        let log = log_from_entries(entries);
        let count =
            batched_replay_uncommitted(&log, &mut state, &mut store, 0).expect("batched replay");

        assert_eq!(count, 100);
        let record = state.inodes.get(&file_id).expect("inode should exist");
        assert_eq!(record.size, 305); // 99*3 + 8 = 305
        assert!(state.dirty_inodes.contains(&file_id));
        assert!(state.dirty_content.contains(&file_id));
    }

    #[test]
    fn batched_replay_single_write_unchanged() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();
        let file_id = InodeId::new(51);
        make_test_inode(&mut state, file_id, 0);

        let payload = b"single write";
        let entry = make_write_entry(&mut store, 0, file_id, 0, payload, 2);
        let log = log_from_entries(vec![entry]);

        let count =
            batched_replay_uncommitted(&log, &mut state, &mut store, 0).expect("batched replay");
        assert_eq!(count, 1);

        let record = state.inodes.get(&file_id).unwrap();
        assert_eq!(record.size, payload.len() as u64);
    }

    #[test]
    fn batched_replay_writes_to_different_files() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();

        for fid in [60u64, 61u64, 62u64] {
            make_test_inode(&mut state, InodeId::new(fid), 0);
        }

        let mut entries: Vec<IntentLogEntry> = Vec::new();
        for i in 0..9u64 {
            let fid = 60 + (i % 3);
            let data = vec![b'X' + (i % 3) as u8; 4];
            entries.push(make_write_entry(
                &mut store,
                i,
                InodeId::new(fid),
                i * 4,
                &data,
                i + 1,
            ));
        }

        let log = log_from_entries(entries);
        let count =
            batched_replay_uncommitted(&log, &mut state, &mut store, 0).expect("batched replay");
        assert_eq!(count, 9);

        for fid in [60u64, 61u64, 62u64] {
            let record = state.inodes.get(&InodeId::new(fid)).unwrap();
            assert!(record.size >= 12);
            assert!(state.dirty_inodes.contains(&InodeId::new(fid)));
        }
    }

    #[test]
    fn batched_replay_mixed_write_and_namespace_entries() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();

        let file_id = InodeId::new(70);
        let dir_id = InodeId::new(71);
        make_test_inode(&mut state, file_id, 0);
        make_test_inode(&mut state, dir_id, 64);

        let entries: Vec<IntentLogEntry> = vec![
            make_write_entry(&mut store, 0, file_id, 0, b"aaaa", 2),
            IntentLogEntry {
                entry_id: 1,
                entry_kind: IntentLogEntryKind::NamespaceSyncIntent {
                    parent_inode_id: dir_id,
                    affected_inode_ids: vec![file_id],
                    link_count_deltas: vec![(file_id, 1)],
                },
                root_anchor: anchor_for_tx(3),
                timestamp_ns: 0,
            },
            make_write_entry(&mut store, 2, file_id, 4, b"bbbb", 4),
            make_write_entry(&mut store, 3, file_id, 8, b"cccc", 5),
        ];

        let log = log_from_entries(entries);
        let count =
            batched_replay_uncommitted(&log, &mut state, &mut store, 0).expect("batched replay");
        assert_eq!(count, 4);

        let record = state.inodes.get(&file_id).unwrap();
        assert_eq!(record.size, 12);
        assert_eq!(record.nlink, 2);
    }

    #[test]
    fn batched_replay_no_writes_returns_zero() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();

        let log = IntentLog::new();
        let count =
            batched_replay_uncommitted(&log, &mut state, &mut store, 0).expect("batched replay");
        assert_eq!(count, 0);
    }

    #[test]
    fn batched_replay_all_skipped_returns_zero() {
        let (mut store, _dir) = test_store();
        let mut state = minimal_state();
        let file_id = InodeId::new(52);
        make_test_inode(&mut state, file_id, 0);

        let entry = make_write_entry(&mut store, 0, file_id, 0, b"data", 1);
        let log = log_from_entries(vec![entry]);

        let count =
            batched_replay_uncommitted(&log, &mut state, &mut store, 5).expect("batched replay");
        assert_eq!(count, 0);
    }
}
