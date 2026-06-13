//! Kernel-mode intent-log scan and replay through [`KernelStorageIo`].
//!
//! This module is the no_std read side for frames written by
//! [`IntentLogKernelWriter`](crate::IntentLogKernelWriter). It scans a
//! sector-aligned region, validates each `IntentLogFrame`, and either yields
//! records to the caller or replays them through an idempotent callback.
//!
//! Corrupt frame paths always advance the scan cursor before returning. This is
//! the mount-time recovery invariant: a bad frame can be reported or skipped,
//! but it must never wedge replay at the same sector.

use alloc::vec;
use core::fmt;

use tidefs_kernel_storage_io::{KernelStorageIo, KernelStorageIoCapabilities};
use tidefs_types_vfs_core::Errno;

use crate::kernel_writer::{decode_sector_aligned_frame, FRAME_PREFIX_LEN};
use crate::IntentLogRecord;

/// Default maximum sector-padded frame allocation accepted by the scanner.
///
/// Intent records should stay small enough for kernel recovery to allocate
/// predictably. A larger on-disk length is treated as corruption before any
/// large allocation is attempted.
pub const DEFAULT_KERNEL_SCAN_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Errors produced during kernel-mode intent-log scanning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelScanError {
    /// A frame at `sector` is not decodable as a valid intent-log frame.
    CorruptedRecord {
        /// Sector where the corrupt frame or garbage starts.
        sector: u64,
        /// Static reason suitable for logs and validation output.
        reason: &'static str,
    },
    /// Fatal storage backend or callback error.
    Io(Errno),
    /// No valid records were found before the written region ended.
    EmptyRegion,
}

impl fmt::Display for KernelScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorruptedRecord { sector, reason } => {
                write!(f, "corrupt intent-log frame at sector {sector}: {reason}")
            }
            Self::Io(errno) => write!(f, "intent-log scan I/O error: {}", errno.name()),
            Self::EmptyRegion => write!(f, "intent-log region is empty"),
        }
    }
}

/// A validated intent-log record plus its sector metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelScannedRecord {
    /// Decoded intent-log record.
    pub record: IntentLogRecord,
    /// Transaction group carried by the frame.
    pub txg_id: u64,
    /// Monotonic record sequence carried by the frame.
    pub record_seq: u64,
    /// First sector occupied by this frame.
    pub start_sector: u64,
    /// Number of sectors occupied by this frame, including padding.
    pub sector_count: u64,
}

/// Callback used by [`IntentLogKernelScanner::scan_and_replay`].
///
/// Implementations must be idempotent. Mount recovery may replay a record that
/// was already applied before a crash during replay.
pub trait RedoCallback {
    /// Replay one validated intent-log record.
    fn replay(
        &mut self,
        record: &IntentLogRecord,
        txg_id: u64,
        record_seq: u64,
    ) -> Result<(), Errno>;
}
// ---------------------------------------------------------------------------
// Record classification for kernel replay
// ---------------------------------------------------------------------------

/// Classification of an intent-log record for kernel replay overlay.
///
/// During mounted import, each record must be classified before the
/// overlay dispatches or blocks on it. The three categories guarantee
/// that the kernel replay layer cannot silently skip a data-changing
/// operation that it does not understand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentReplayKind {
    /// The record type is supported for kernel replay dispatch.
    /// Namespace mutations (create, unlink, mkdir, rmdir, rename,
    /// hardlink, symlink, mknod, tmpfile), metadata updates, xattrs,
    /// and inline buffered writes.
    Supported,
    /// The record type carries no durable filesystem mutation.
    /// Flush, fsync, write-intent-ack, lseek, and cleanup-queue
    /// records are acknowledgment or metadata-only markers.
    NoOp,
    /// The record type requires replay logic that the kernel overlay
    /// does not implement. Mount must fail closed rather than
    /// silently skipping the operation.
    Unsupported,
}

/// Classify a single [`IntentLogRecord`] for kernel replay.
///
/// This is the canonical classification shared between the
/// kernel-mode scanner and the kmod replay dispatcher.
/// Unsupported record types must block mount; they must not be
/// silently counted as skipped.
pub fn classify_for_replay(record: &IntentLogRecord) -> IntentReplayKind {
    match record {
        // Supported: namespace, metadata, xattr, and inline-data mutations.
        IntentLogRecord::Create { .. }
        | IntentLogRecord::Unlink { .. }
        | IntentLogRecord::Mkdir { .. }
        | IntentLogRecord::Rmdir { .. }
        | IntentLogRecord::Rename { .. }
        | IntentLogRecord::Symlink { .. }
        | IntentLogRecord::HardLink { .. }
        | IntentLogRecord::Mknod { .. }
        | IntentLogRecord::Tmpfile { .. }
        | IntentLogRecord::Truncate { .. }
        | IntentLogRecord::Setattr { .. }
        | IntentLogRecord::XattrSet { .. }
        | IntentLogRecord::XattrRemove { .. }
        | IntentLogRecord::BufferedWrite { .. } => IntentReplayKind::Supported,

        // NoOp: non-mutating control markers
        IntentLogRecord::Flush { .. }
        | IntentLogRecord::Fsync { .. }
        | IntentLogRecord::WriteIntentAck { .. }
        | IntentLogRecord::Lseek { .. }
        | IntentLogRecord::CleanupQueue { .. } => IntentReplayKind::NoOp,

        // Unsupported: hash-only Write records, complex range operations,
        // and transaction-group markers.
        _ => IntentReplayKind::Unsupported,
    }
}

// ---------------------------------------------------------------------------
// Kernel replay overlay
// ---------------------------------------------------------------------------

/// Outcome of a kernel replay overlay run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelReplayOutcome {
    /// Number of records replayed through the callback.
    pub replayed: u64,
    /// Number of records skipped (txg <= committed_root_txg or NoOp kind).
    pub skipped: u64,
    /// Number of unsupported records that blocked replay.
    pub blocked: u64,
    /// Highest txg encountered across all records examined.
    pub highest_txg: Option<u64>,
}

impl KernelReplayOutcome {
    /// Total records examined (replayed + skipped + blocked).
    pub const fn total(&self) -> u64 {
        self.replayed + self.skipped + self.blocked
    }
}

/// Kernel-mode intent replay overlay.
///
/// Wraps an [`IntentLogKernelScanner`] with committed-root boundary
/// semantics: only records with `txg > committed_root_txg` are replayed
/// through the [`RedoCallback`]. Records at or below the committed-root
/// txg are already durable in the object store and are skipped.
///
/// Unsupported record types (see [`classify_for_replay`]) cause early
/// termination with a [`KernelScanError::CorruptedRecord`]. The caller
/// must not silently skip data-changing operations.
///
/// # Mount contract
///
/// The parent issue #6252 uses this overlay as the mount-time replay
/// hook: scan intent-log records from the committed-root pointer,
/// replay supported namespace mutations through a [`RedoCallback`],
/// and block on unsupported record types.
pub struct KernelReplayOverlay<'a, 'b> {
    scanner: IntentLogKernelScanner<'a>,
    callback: &'b mut dyn RedoCallback,
    committed_root_txg: u64,
    outcome: KernelReplayOutcome,
}

impl<'a, 'b> KernelReplayOverlay<'a, 'b> {
    /// Create a new replay overlay from an existing scanner and a
    /// committed-root transaction group.
    ///
    /// `committed_root_txg` is the transaction group of the committed
    /// root selected during mount. Records with `txg <= committed_root_txg`
    /// are already reflected in the object store and are skipped.
    pub fn new(
        scanner: IntentLogKernelScanner<'a>,
        callback: &'b mut dyn RedoCallback,
        committed_root_txg: u64,
    ) -> Self {
        Self {
            scanner,
            callback,
            committed_root_txg,
            outcome: KernelReplayOutcome {
                replayed: 0,
                skipped: 0,
                blocked: 0,
                highest_txg: None,
            },
        }
    }

    /// Replay the next eligible record from the scanner.
    ///
    /// Returns:
    /// - `Ok(true)` if a record was replayed
    /// - `Ok(false)` if the region is exhausted (no more records)
    /// - `Err(KernelScanError::CorruptedRecord)` for corrupt frames or
    ///   unsupported record types (scan already advanced cursor)
    /// - `Err(KernelScanError::Io)` for fatal I/O or callback errors
    ///
    /// NoOp records and records at or below `committed_root_txg` are
    /// counted as skipped and the method continues to the next record.
    pub fn replay_next(&mut self) -> Result<bool, KernelScanError> {
        loop {
            match self.scanner.next_record() {
                Ok(Some(record)) => {
                    // Track highest txg seen.
                    self.outcome.highest_txg = Some(
                        self.outcome
                            .highest_txg
                            .map_or(record.txg_id, |h| h.max(record.txg_id)),
                    );

                    // Skip records already reflected in the committed root.
                    if record.txg_id <= self.committed_root_txg {
                        self.outcome.skipped += 1;
                        continue;
                    }

                    // Classify the record.
                    match classify_for_replay(&record.record) {
                        IntentReplayKind::Supported => {
                            self.callback
                                .replay(&record.record, record.txg_id, record.record_seq)
                                .map_err(KernelScanError::Io)?;
                            self.outcome.replayed += 1;
                            return Ok(true);
                        }
                        IntentReplayKind::NoOp => {
                            self.outcome.skipped += 1;
                            // Continue to next record.
                        }
                        IntentReplayKind::Unsupported => {
                            self.outcome.blocked += 1;
                            return Err(KernelScanError::CorruptedRecord {
                                sector: record.start_sector,
                                reason: "unsupported intent record type for kernel replay overlay",
                            });
                        }
                    }
                }
                Ok(None) => return Ok(false),
                Err(KernelScanError::CorruptedRecord { .. }) => {
                    // Corrupt frames: scanner already advanced cursor, count as skipped.
                    self.outcome.skipped += 1;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Replay all eligible records until the region is exhausted.
    ///
    /// Stops on the first fatal error or unsupported record type.
    /// Returns `Ok(())` if at least one record was replayed; returns
    /// `Err(KernelScanError::EmptyRegion)` if no records were found.
    pub fn replay_all(&mut self) -> Result<(), KernelScanError> {
        let mut replayed_any = false;
        loop {
            match self.replay_next() {
                Ok(true) => replayed_any = true,
                Ok(false) => break,
                Err(e) => return Err(e),
            }
        }
        if replayed_any {
            Ok(())
        } else {
            // Distinguish empty region from no-replay-due-to-filter.
            if self.outcome.skipped > 0 {
                Ok(())
            } else {
                Err(KernelScanError::EmptyRegion)
            }
        }
    }

    /// Read-only view of the replay outcome.
    pub fn outcome(&self) -> &KernelReplayOutcome {
        &self.outcome
    }

    /// Return the underlying scanner, consuming the overlay.
    ///
    /// The caller can continue scanning past the replayed region for
    /// post-replay verification.
    pub fn into_scanner(self) -> IntentLogKernelScanner<'a> {
        self.scanner
    }
}

/// Sector-aligned no_std intent-log scanner.
pub struct IntentLogKernelScanner<'a> {
    io: &'a dyn KernelStorageIo,
    current_sector: u64,
    capacity_sectors: u64,
    sector_size: usize,
    max_frame_bytes: usize,
}

impl<'a> IntentLogKernelScanner<'a> {
    /// Create a scanner at `start_sector` with the default frame-size limit.
    pub fn new(io: &'a dyn KernelStorageIo, start_sector: u64) -> Result<Self, KernelScanError> {
        Self::with_max_frame_bytes(io, start_sector, DEFAULT_KERNEL_SCAN_MAX_FRAME_BYTES)
    }

    /// Create a scanner with an explicit maximum sector-padded frame size.
    pub fn with_max_frame_bytes(
        io: &'a dyn KernelStorageIo,
        start_sector: u64,
        max_frame_bytes: usize,
    ) -> Result<Self, KernelScanError> {
        let sector_size = io.sector_size() as usize;
        let capacity_sectors = io.capacity_sectors();
        if sector_size == 0 || start_sector > capacity_sectors {
            return Err(KernelScanError::Io(Errno::EINVAL));
        }
        if max_frame_bytes < FRAME_PREFIX_LEN {
            return Err(KernelScanError::Io(Errno::EINVAL));
        }
        Ok(Self {
            io,
            current_sector: start_sector,
            capacity_sectors,
            sector_size,
            max_frame_bytes,
        })
    }

    /// Return the sector where the next scan will start.
    #[inline]
    pub fn position(&self) -> u64 {
        self.current_sector
    }

    /// Seek to an absolute sector.
    ///
    /// The caller must seek only to a known frame boundary.
    pub fn seek(&mut self, sector: u64) -> Result<(), KernelScanError> {
        if sector > self.capacity_sectors {
            return Err(KernelScanError::Io(Errno::EINVAL));
        }
        self.current_sector = sector;
        Ok(())
    }

    /// Return the next validated record.
    ///
    /// If a corrupt frame is detected, the cursor has already advanced before
    /// `CorruptedRecord` is returned. Calling `next_record` again will inspect
    /// the next candidate sector.
    pub fn next_record(&mut self) -> Result<Option<KernelScannedRecord>, KernelScanError> {
        self.read_one_record()
    }

    /// Replay all valid records from the current cursor until the region ends.
    ///
    /// Corrupt frames are skipped after advancing the cursor. Fatal I/O errors
    /// and callback errors abort the scan.
    pub fn scan_and_replay(
        &mut self,
        callback: &mut dyn RedoCallback,
    ) -> Result<(), KernelScanError> {
        let mut replayed_any = false;
        loop {
            match self.read_one_record() {
                Ok(Some(scanned)) => {
                    callback
                        .replay(&scanned.record, scanned.txg_id, scanned.record_seq)
                        .map_err(KernelScanError::Io)?;
                    replayed_any = true;
                }
                Ok(None) => break,
                Err(KernelScanError::CorruptedRecord { .. }) => continue,
                Err(err) => return Err(err),
            }
        }
        if replayed_any {
            Ok(())
        } else {
            Err(KernelScanError::EmptyRegion)
        }
    }

    fn read_one_record(&mut self) -> Result<Option<KernelScannedRecord>, KernelScanError> {
        let start_sector = self.current_sector;
        if start_sector >= self.capacity_sectors {
            return Ok(None);
        }

        let mut first_sector = vec![0u8; self.sector_size];
        let read = self
            .io
            .read_sectors(start_sector, &mut first_sector)
            .map_err(KernelScanError::Io)?;
        if read != 1 {
            return Err(KernelScanError::Io(Errno::EIO));
        }
        if first_sector.iter().all(|byte| *byte == 0) {
            return Ok(None);
        }
        if self.sector_size < FRAME_PREFIX_LEN {
            return self.corrupt_and_advance(
                start_sector,
                1,
                "sector is too small for an intent-log frame prefix",
            );
        }

        let record_len = read_record_len(&first_sector);
        let encoded_len = match FRAME_PREFIX_LEN.checked_add(record_len) {
            Some(len) => len,
            None => {
                return self.corrupt_and_advance(
                    start_sector,
                    1,
                    "record length overflows frame length",
                )
            }
        };
        if encoded_len > self.max_frame_bytes {
            return self.corrupt_and_advance(
                start_sector,
                1,
                "record length exceeds kernel scanner frame limit",
            );
        }

        let sector_count = match sectors_for_len(encoded_len, self.sector_size) {
            Ok(sectors) if sectors > 0 => sectors,
            _ => return self.corrupt_and_advance(start_sector, 1, "frame sector count overflows"),
        };
        let end_sector = match start_sector.checked_add(sector_count) {
            Some(end) => end,
            None => {
                return self.corrupt_and_advance(start_sector, 1, "frame sector range overflows")
            }
        };
        if end_sector > self.capacity_sectors {
            return self.corrupt_and_advance(
                start_sector,
                1,
                "frame extends beyond storage capacity",
            );
        }

        let frame_buf = if sector_count == 1 {
            first_sector
        } else {
            let padded_len = match padded_len_for_sectors(sector_count, self.sector_size) {
                Ok(len) => len,
                Err(()) => {
                    return self.corrupt_and_advance(
                        start_sector,
                        1,
                        "frame padded length overflows",
                    )
                }
            };
            let mut buf = vec![0u8; padded_len];
            let read = self
                .io
                .read_sectors(start_sector, &mut buf)
                .map_err(KernelScanError::Io)?;
            if u64::from(read) != sector_count {
                return self.corrupt_and_advance(
                    start_sector,
                    sector_count,
                    "short read for multi-sector intent-log frame",
                );
            }
            buf
        };

        let frame = match decode_sector_aligned_frame(&frame_buf) {
            Ok(frame) => frame,
            Err(_) => {
                return self.corrupt_and_advance(
                    start_sector,
                    sector_count,
                    "frame decode or checksum verification failed",
                )
            }
        };

        self.advance_by(sector_count);
        Ok(Some(KernelScannedRecord {
            record: frame.record,
            txg_id: frame.txg_id,
            record_seq: frame.record_seq,
            start_sector,
            sector_count,
        }))
    }

    fn corrupt_and_advance(
        &mut self,
        sector: u64,
        sector_count: u64,
        reason: &'static str,
    ) -> Result<Option<KernelScannedRecord>, KernelScanError> {
        self.advance_by(sector_count.max(1));
        Err(KernelScanError::CorruptedRecord { sector, reason })
    }

    fn advance_by(&mut self, sector_count: u64) {
        self.current_sector = self
            .current_sector
            .saturating_add(sector_count.max(1))
            .min(self.capacity_sectors);
    }
}

fn read_record_len(buf: &[u8]) -> usize {
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&buf[8 + 8 + 32..FRAME_PREFIX_LEN]);
    u32::from_le_bytes(len_bytes) as usize
}

fn sectors_for_len(encoded_len: usize, sector_size: usize) -> Result<u64, ()> {
    let sectors = encoded_len.checked_add(sector_size - 1).ok_or(())? / sector_size;
    u64::try_from(sectors).map_err(|_| ())
}

fn padded_len_for_sectors(sector_count: u64, sector_size: usize) -> Result<usize, ()> {
    let sector_count = usize::try_from(sector_count).map_err(|_| ())?;
    sector_count.checked_mul(sector_size).ok_or(())
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};
    use std::sync::Mutex;

    use super::*;
    use crate::{IntentLogKernelWriter, KernelIntentFlush};

    struct MemoryIo {
        data: Mutex<Vec<u8>>,
        sector_size: u32,
        fail_read_sector: Mutex<Option<(u64, Errno)>>,
        short_read: Mutex<Option<(u64, u32)>>,
    }

    impl MemoryIo {
        fn new(sectors: u64, sector_size: u32) -> Self {
            let len = usize::try_from(sectors * u64::from(sector_size)).unwrap();
            Self {
                data: Mutex::new(vec![0u8; len]),
                sector_size,
                fail_read_sector: Mutex::new(None),
                short_read: Mutex::new(None),
            }
        }

        fn set_fail_read(&self, sector: u64, errno: Errno) {
            *self.fail_read_sector.lock().unwrap() = Some((sector, errno));
        }

        fn set_short_read(&self, sector: u64, sectors_returned: u32) {
            *self.short_read.lock().unwrap() = Some((sector, sectors_returned));
        }
    }

    impl KernelStorageIo for MemoryIo {
        fn capabilities(&self) -> KernelStorageIoCapabilities {
            KernelStorageIoCapabilities {
                read: true,
                write: true,
                flush: true,
                discard: false,
                write_zeroes: false,
                zero_range: false,
                teardown: true,
                sector_size: self.sector_size,
                capacity_sectors: self.capacity_sectors(),
            }
        }

        fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno> {
            let sector_size = self.sector_size as usize;
            if sector_size == 0 || buf.len() % sector_size != 0 {
                return Err(Errno::EINVAL);
            }
            if let Some((sector, errno)) = *self.fail_read_sector.lock().unwrap() {
                if start_sector == sector {
                    return Err(errno);
                }
            }

            let requested = (buf.len() / sector_size) as u32;
            let returned =
                if let Some((sector, sectors_returned)) = *self.short_read.lock().unwrap() {
                    if start_sector == sector && requested > sectors_returned {
                        sectors_returned
                    } else {
                        requested
                    }
                } else {
                    requested
                };

            let start = usize::try_from(start_sector * u64::from(self.sector_size)).unwrap();
            let bytes_to_copy =
                usize::try_from(u64::from(returned) * u64::from(self.sector_size)).unwrap();
            let data = self.data.lock().unwrap();
            if start + bytes_to_copy > data.len() {
                return Err(Errno::EINVAL);
            }
            if bytes_to_copy > 0 {
                buf[..bytes_to_copy].copy_from_slice(&data[start..start + bytes_to_copy]);
            }
            Ok(returned)
        }

        fn write_sectors(&self, start_sector: u64, data: &[u8]) -> Result<u32, Errno> {
            let sector_size = self.sector_size as usize;
            if sector_size == 0 || data.len() % sector_size != 0 {
                return Err(Errno::EINVAL);
            }
            let start = usize::try_from(start_sector * u64::from(self.sector_size)).unwrap();
            let mut target = self.data.lock().unwrap();
            if start + data.len() > target.len() {
                return Err(Errno::ENOSPC);
            }
            target[start..start + data.len()].copy_from_slice(data);
            Ok((data.len() / sector_size) as u32)
        }

        fn flush(&self) -> Result<(), Errno> {
            Ok(())
        }

        fn sector_size(&self) -> u32 {
            self.sector_size
        }

        fn capacity_sectors(&self) -> u64 {
            self.data.lock().unwrap().len() as u64 / u64::from(self.sector_size)
        }

        fn teardown(&self) -> Result<(), Errno> {
            Ok(())
        }
    }

    fn tx_record(cg_id: u64) -> IntentLogRecord {
        IntentLogRecord::TxBegin { cg_id }
    }

    fn mkdir_record(parent: u64, name: &[u8], ino: u64) -> IntentLogRecord {
        IntentLogRecord::Mkdir {
            parent,
            name: name.to_vec(),
            mode: 0o755,
            ino,
        }
    }

    fn write_records(io: &MemoryIo, start_sector: u64, records: &[(u64, IntentLogRecord)]) -> u64 {
        let mut writer = IntentLogKernelWriter::new(io, start_sector, 0).unwrap();
        for (txg_id, record) in records {
            writer
                .append_record(*txg_id, record.clone(), KernelIntentFlush::Deferred)
                .unwrap();
        }
        writer.next_sector()
    }

    struct CollectingRedo {
        records: Vec<(IntentLogRecord, u64, u64)>,
    }

    impl CollectingRedo {
        fn new() -> Self {
            Self {
                records: Vec::new(),
            }
        }
    }

    impl RedoCallback for CollectingRedo {
        fn replay(
            &mut self,
            record: &IntentLogRecord,
            txg_id: u64,
            record_seq: u64,
        ) -> Result<(), Errno> {
            self.records.push((record.clone(), txg_id, record_seq));
            Ok(())
        }
    }

    #[test]
    fn empty_region_reports_empty_for_replay_and_none_for_next() {
        let io = MemoryIo::new(8, 512);
        let mut replay_scanner = IntentLogKernelScanner::new(&io, 2).unwrap();
        assert_eq!(
            replay_scanner.scan_and_replay(&mut CollectingRedo::new()),
            Err(KernelScanError::EmptyRegion)
        );

        let mut next_scanner = IntentLogKernelScanner::new(&io, 2).unwrap();
        assert_eq!(next_scanner.next_record().unwrap(), None);
    }

    #[test]
    fn scans_records_written_by_kernel_writer() {
        let io = MemoryIo::new(16, 512);
        let expected = vec![
            (7, tx_record(7)),
            (8, mkdir_record(1, b"dir", 42)),
            (
                9,
                IntentLogRecord::Truncate {
                    ino: 42,
                    new_size: 4096,
                },
            ),
        ];
        write_records(&io, 3, &expected);

        let mut scanner = IntentLogKernelScanner::new(&io, 3).unwrap();
        let mut replay = CollectingRedo::new();
        scanner.scan_and_replay(&mut replay).unwrap();

        assert_eq!(replay.records.len(), expected.len());
        for (idx, (txg_id, record)) in expected.iter().enumerate() {
            assert_eq!(&replay.records[idx].0, record);
            assert_eq!(replay.records[idx].1, *txg_id);
            assert_eq!(replay.records[idx].2, idx as u64);
        }
    }

    #[test]
    fn next_record_returns_sector_metadata_and_seek_resumes() {
        let io = MemoryIo::new(16, 512);
        write_records(
            &io,
            0,
            &[(1, tx_record(1)), (2, tx_record(2)), (3, tx_record(3))],
        );

        let mut scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let first = scanner.next_record().unwrap().unwrap();
        assert_eq!(first.record, tx_record(1));
        assert_eq!(first.start_sector, 0);
        assert_eq!(first.sector_count, 1);
        assert_eq!(scanner.position(), 1);

        scanner
            .seek(first.start_sector + first.sector_count)
            .unwrap();
        let second = scanner.next_record().unwrap().unwrap();
        assert_eq!(second.record, tx_record(2));
        assert_eq!(scanner.next_record().unwrap().unwrap().record, tx_record(3));
    }

    #[test]
    fn multi_sector_record_is_read_and_replayed() {
        let io = MemoryIo::new(8, 512);
        let big = IntentLogRecord::BufferedWrite {
            ino: 9,
            offset: 0,
            length: 900,
            data: vec![0x5a; 900],
        };
        write_records(&io, 0, &[(4, big.clone())]);

        let mut scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let scanned = scanner.next_record().unwrap().unwrap();
        assert_eq!(scanned.record, big);
        assert!(scanned.sector_count > 1);
        assert_eq!(scanner.position(), scanned.sector_count);
    }

    #[test]
    fn corrupt_checksum_advances_and_allows_next_record() {
        let io = MemoryIo::new(8, 512);
        let frame = crate::IntentLogFrame::new(tx_record(1), 1, 0);
        let mut bytes = frame.encode();
        bytes[16] ^= 0xff;
        let mut sector = vec![0u8; 512];
        sector[..bytes.len()].copy_from_slice(&bytes);
        io.write_sectors(0, &sector).unwrap();
        write_records(&io, 1, &[(2, tx_record(2))]);

        let mut scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        assert!(matches!(
            scanner.next_record(),
            Err(KernelScanError::CorruptedRecord { sector: 0, .. })
        ));
        assert_eq!(scanner.position(), 1);
        assert_eq!(scanner.next_record().unwrap().unwrap().record, tx_record(2));
    }

    #[test]
    fn scan_and_replay_skips_corrupt_frames_without_wedging() {
        let io = MemoryIo::new(8, 512);
        write_records(&io, 0, &[(1, tx_record(1))]);
        let garbage = vec![0xffu8; 512];
        io.write_sectors(1, &garbage).unwrap();
        write_records(&io, 2, &[(2, tx_record(2))]);

        let mut scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let mut replay = CollectingRedo::new();
        scanner.scan_and_replay(&mut replay).unwrap();

        assert_eq!(replay.records.len(), 2);
        assert_eq!(replay.records[0].0, tx_record(1));
        assert_eq!(replay.records[1].0, tx_record(2));
        assert_eq!(scanner.position(), 3);
    }

    #[test]
    fn oversized_frame_length_advances_one_sector_before_reporting_corruption() {
        let io = MemoryIo::new(8, 512);
        let mut garbage = vec![0x11u8; 512];
        garbage[8 + 8 + 32..FRAME_PREFIX_LEN].copy_from_slice(&u32::MAX.to_le_bytes());
        io.write_sectors(0, &garbage).unwrap();
        write_records(&io, 1, &[(2, tx_record(2))]);

        let mut scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        assert!(matches!(
            scanner.next_record(),
            Err(KernelScanError::CorruptedRecord { sector: 0, .. })
        ));
        assert_eq!(scanner.position(), 1);
        assert_eq!(scanner.next_record().unwrap().unwrap().record, tx_record(2));
    }

    #[test]
    fn short_multi_sector_read_advances_past_the_claimed_frame() {
        let io = MemoryIo::new(8, 512);
        let big = IntentLogRecord::BufferedWrite {
            ino: 2,
            offset: 0,
            length: 900,
            data: vec![0x7b; 900],
        };
        let end_sector = write_records(&io, 0, &[(1, big)]);
        io.set_short_read(0, 1);

        let mut scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        assert!(matches!(
            scanner.next_record(),
            Err(KernelScanError::CorruptedRecord { sector: 0, .. })
        ));
        assert_eq!(scanner.position(), end_sector);
    }

    #[test]
    fn fatal_read_error_after_valid_record_aborts_replay() {
        let io = MemoryIo::new(8, 512);
        write_records(&io, 0, &[(1, tx_record(1)), (2, tx_record(2))]);
        io.set_fail_read(1, Errno::EIO);

        let mut scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let mut replay = CollectingRedo::new();
        assert_eq!(
            scanner.scan_and_replay(&mut replay),
            Err(KernelScanError::Io(Errno::EIO))
        );
        assert_eq!(replay.records.len(), 1);
    }

    #[test]
    fn callback_error_aborts_replay() {
        let io = MemoryIo::new(8, 512);
        write_records(&io, 0, &[(1, tx_record(1)), (2, tx_record(2))]);

        struct FailsOnSecond {
            calls: u32,
        }
        impl RedoCallback for FailsOnSecond {
            fn replay(
                &mut self,
                _record: &IntentLogRecord,
                _txg_id: u64,
                _record_seq: u64,
            ) -> Result<(), Errno> {
                self.calls += 1;
                if self.calls == 2 {
                    Err(Errno::EIO)
                } else {
                    Ok(())
                }
            }
        }

        let mut scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let mut replay = FailsOnSecond { calls: 0 };
        assert_eq!(
            scanner.scan_and_replay(&mut replay),
            Err(KernelScanError::Io(Errno::EIO))
        );
        assert_eq!(replay.calls, 2);
    }

    #[test]
    fn validates_constructor_and_seek_bounds() {
        let io = MemoryIo::new(8, 512);
        assert_eq!(
            IntentLogKernelScanner::new(&io, 9).err().unwrap(),
            KernelScanError::Io(Errno::EINVAL)
        );
        assert_eq!(
            IntentLogKernelScanner::with_max_frame_bytes(&io, 0, FRAME_PREFIX_LEN - 1)
                .err()
                .unwrap(),
            KernelScanError::Io(Errno::EINVAL)
        );

        let mut scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        assert_eq!(
            scanner.seek(9).unwrap_err(),
            KernelScanError::Io(Errno::EINVAL)
        );
    }

    #[test]
    fn rejects_zero_sector_size_backend() {
        struct ZeroSectorIo;
        impl KernelStorageIo for ZeroSectorIo {
            fn capabilities(&self) -> KernelStorageIoCapabilities {
                KernelStorageIoCapabilities {
                    read: true,
                    write: true,
                    flush: true,
                    discard: false,
                    write_zeroes: false,
                    zero_range: false,
                    teardown: true,
                    sector_size: 0,
                    capacity_sectors: 8,
                }
            }

            fn read_sectors(&self, _start_sector: u64, _buf: &mut [u8]) -> Result<u32, Errno> {
                Ok(0)
            }

            fn write_sectors(&self, _start_sector: u64, _data: &[u8]) -> Result<u32, Errno> {
                Ok(0)
            }

            fn flush(&self) -> Result<(), Errno> {
                Ok(())
            }

            fn sector_size(&self) -> u32 {
                0
            }

            fn capacity_sectors(&self) -> u64 {
                8
            }

            fn teardown(&self) -> Result<(), Errno> {
                Ok(())
            }
        }

        assert_eq!(
            IntentLogKernelScanner::new(&ZeroSectorIo, 0).err().unwrap(),
            KernelScanError::Io(Errno::EINVAL)
        );
    }

    // ── Record classification tests ─────────────────────────────────

    #[test]
    fn classify_supported_types() {
        use IntentReplayKind::*;
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Create {
                parent: 1,
                name: vec![],
                mode: 0,
                ino: 2
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Unlink {
                parent: 1,
                name: vec![],
                ino: 2
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Mkdir {
                parent: 1,
                name: vec![],
                mode: 0o755,
                ino: 2
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Rmdir {
                parent: 1,
                name: vec![],
                ino: 2
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Rename {
                src_parent: 1,
                src_name: vec![],
                dst_parent: 2,
                dst_name: vec![],
                ino: 3,
                overwrite_target_ino: None,
                rename_flags: 0
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Symlink {
                parent: 1,
                name: vec![],
                target: vec![],
                ino: 2
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::HardLink {
                ino: 1,
                new_parent: 2,
                new_name: vec![]
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Mknod {
                parent: 1,
                name: vec![],
                mode: 0,
                rdev: 0,
                ino: 2
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Tmpfile {
                parent: 1,
                mode: 0,
                ino: 2
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Truncate {
                ino: 1,
                new_size: 0
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Setattr {
                ino: 1,
                attr_mask: 0,
                attrs: [0u8; 64]
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::BufferedWrite {
                ino: 1,
                offset: 0,
                length: 0,
                data: vec![],
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::XattrSet {
                ino: 1,
                namespace: crate::XattrNamespace::User,
                key_hash: [0u8; 32],
                value_hash: [0u8; 32]
            }),
            Supported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::XattrRemove {
                ino: 1,
                namespace: crate::XattrNamespace::User,
                key_hash: [0u8; 32]
            }),
            Supported
        );
    }

    #[test]
    fn classify_noop_types() {
        use IntentReplayKind::*;
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Flush {
                ino: 1,
                fh: 0,
                lock_owner: 0
            }),
            NoOp
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Fsync {
                ino: 1,
                fh: 0,
                mode: 0
            }),
            NoOp
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::WriteIntentAck {
                ino: 0,
                offset: 0,
                length: 0
            }),
            NoOp
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Lseek {
                ino: 1,
                whence: 0,
                offset: 0,
                result: 0
            }),
            NoOp
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::CleanupQueue {
                entry_id: 0,
                device_id: 0,
                physical_offset: 0,
                length: 0,
                blake3_hash: [0u8; 32],
                freed_at_txg: 0,
                cleanup_status: 0,
                retry_count: 0
            }),
            NoOp
        );
    }

    #[test]
    fn classify_unsupported_types() {
        use IntentReplayKind::*;
        // Data-path Write: hash-based, not replayable.
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Write {
                ino: 1,
                offset: 0,
                length: 0,
                data_hash: [0u8; 32]
            }),
            Unsupported
        );
        // Complex ops
        assert_eq!(
            classify_for_replay(&IntentLogRecord::Fallocate {
                ino: 1,
                offset: 0,
                length: 0,
                mode: 0
            }),
            Unsupported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::CopyFileRange {
                src_ino: 1,
                src_fh: 0,
                dst_ino: 2,
                dst_fh: 0,
                src_offset: 0,
                dst_offset: 0,
                len: 0
            }),
            Unsupported
        );
        // Tx markers
        assert_eq!(
            classify_for_replay(&IntentLogRecord::TxBegin { cg_id: 1 }),
            Unsupported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::TxCommit { cg_id: 1 }),
            Unsupported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::TxAbort { cg_id: 1 }),
            Unsupported
        );
        assert_eq!(
            classify_for_replay(&IntentLogRecord::ExportTerminal { cg_id: 1 }),
            Unsupported
        );
    }

    // ── Kernel replay overlay tests ─────────────────────────────────

    #[test]
    fn overlay_replays_records_above_committed_root() {
        let io = MemoryIo::new(16, 512);
        let records = vec![
            (1, tx_record(1)),
            (2, mkdir_record(1, b"dir_a", 10)),
            (3, mkdir_record(1, b"dir_b", 11)),
        ];
        write_records(&io, 0, &records);

        let scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let mut callback = CollectingRedo::new();
        let committed_root_txg = 1;
        {
            let mut overlay = KernelReplayOverlay::new(scanner, &mut callback, committed_root_txg);
            overlay.replay_all().unwrap();
            assert_eq!(overlay.outcome().replayed, 2);
            assert_eq!(overlay.outcome().skipped, 1);
            assert_eq!(overlay.outcome().blocked, 0);
            assert_eq!(overlay.outcome().highest_txg, Some(3));
        }
        // callback accessible after overlay dropped
        assert_eq!(callback.records.len(), 2);
        assert_eq!(callback.records[0].1, 2);
        assert_eq!(callback.records[1].1, 3);
    }

    #[test]
    fn overlay_skips_all_records_below_committed_root() {
        let io = MemoryIo::new(16, 512);
        write_records(
            &io,
            0,
            &[(1, tx_record(1)), (2, tx_record(2)), (3, tx_record(3))],
        );

        let scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let mut callback = CollectingRedo::new();
        {
            let mut overlay = KernelReplayOverlay::new(scanner, &mut callback, 5);
            // All skipped because txg <= committed_root. Records exist but none
            // were eligible for replay. This is not an empty region.
            overlay.replay_all().unwrap();
            assert_eq!(overlay.outcome().replayed, 0);
            assert_eq!(overlay.outcome().skipped, 3);
        }
        assert_eq!(callback.records.len(), 0);
    }

    #[test]
    fn overlay_blocks_on_unsupported_record() {
        let io = MemoryIo::new(16, 512);
        write_records(
            &io,
            0,
            &[
                (1, mkdir_record(1, b"ok", 10)),
                (
                    2,
                    IntentLogRecord::Write {
                        ino: 1,
                        offset: 0,
                        length: 0,
                        data_hash: [0u8; 32],
                    },
                ),
                (3, mkdir_record(1, b"never", 11)),
            ],
        );

        let scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let mut callback = CollectingRedo::new();
        {
            let mut overlay = KernelReplayOverlay::new(scanner, &mut callback, 0);
            let result = overlay.replay_all();
            assert!(matches!(
                result,
                Err(KernelScanError::CorruptedRecord { .. })
            ));
            assert_eq!(overlay.outcome().replayed, 1);
            assert_eq!(overlay.outcome().blocked, 1);
        }
        assert_eq!(callback.records.len(), 1);
    }

    #[test]
    fn overlay_skips_noop_records() {
        let io = MemoryIo::new(16, 512);
        write_records(
            &io,
            0,
            &[
                (
                    1,
                    IntentLogRecord::Flush {
                        ino: 1,
                        fh: 0,
                        lock_owner: 0,
                    },
                ),
                (2, mkdir_record(1, b"after_flush", 10)),
                (
                    3,
                    IntentLogRecord::Fsync {
                        ino: 1,
                        fh: 0,
                        mode: 0,
                    },
                ),
                (4, mkdir_record(1, b"after_fsync", 11)),
            ],
        );

        let scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let mut callback = CollectingRedo::new();
        {
            let mut overlay = KernelReplayOverlay::new(scanner, &mut callback, 0);
            overlay.replay_all().unwrap();
            assert_eq!(overlay.outcome().replayed, 2);
            assert_eq!(overlay.outcome().skipped, 2);
            assert_eq!(overlay.outcome().blocked, 0);
        }
        assert_eq!(callback.records.len(), 2);
    }

    #[test]
    fn overlay_corrupt_frame_skipped_and_continues() {
        let io = MemoryIo::new(16, 512);
        write_records(&io, 0, &[(1, mkdir_record(1, b"first", 10))]);
        let garbage = vec![0xffu8; 512];
        io.write_sectors(1, &garbage).unwrap();
        write_records(&io, 2, &[(2, mkdir_record(1, b"second", 11))]);

        let scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let mut callback = CollectingRedo::new();
        {
            let mut overlay = KernelReplayOverlay::new(scanner, &mut callback, 0);
            overlay.replay_all().unwrap();
            assert_eq!(overlay.outcome().replayed, 2);
            assert_eq!(overlay.outcome().skipped, 1);
            assert_eq!(overlay.outcome().blocked, 0);
        }
        assert_eq!(callback.records.len(), 2);
    }

    #[test]
    fn overlay_replay_next_step_by_step() {
        let io = MemoryIo::new(16, 512);
        write_records(
            &io,
            0,
            &[
                (1, mkdir_record(1, b"a", 10)),
                (2, mkdir_record(1, b"b", 11)),
                (3, mkdir_record(1, b"c", 12)),
            ],
        );

        let scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let mut callback = CollectingRedo::new();
        let mut overlay = KernelReplayOverlay::new(scanner, &mut callback, 0);

        assert!(overlay.replay_next().unwrap());
        assert_eq!(overlay.outcome().replayed, 1);
        assert!(overlay.replay_next().unwrap());
        assert_eq!(overlay.outcome().replayed, 2);
        assert!(overlay.replay_next().unwrap());
        assert_eq!(overlay.outcome().replayed, 3);
        assert!(!overlay.replay_next().unwrap());
    }

    #[test]
    fn overlay_empty_region_returns_false_on_replay_next() {
        let io = MemoryIo::new(8, 512);
        let scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let mut callback = CollectingRedo::new();
        let mut overlay = KernelReplayOverlay::new(scanner, &mut callback, 0);

        assert!(!overlay.replay_next().unwrap());
    }

    #[test]
    fn overlay_into_scanner_returns_scanner_at_correct_position() {
        let io = MemoryIo::new(16, 512);
        write_records(
            &io,
            0,
            &[
                (1, mkdir_record(1, b"x", 10)),
                (2, mkdir_record(1, b"y", 11)),
            ],
        );

        let scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let mut callback = CollectingRedo::new();
        let mut overlay = KernelReplayOverlay::new(scanner, &mut callback, 0);
        overlay.replay_all().unwrap();

        let scanner = overlay.into_scanner();
        assert!(scanner.position() > 0);
    }

    #[test]
    fn overlay_outcome_total() {
        let o = KernelReplayOutcome {
            replayed: 10,
            skipped: 5,
            blocked: 2,
            highest_txg: Some(42),
        };
        assert_eq!(o.total(), 17);
    }

    #[test]
    fn overlay_stops_on_callback_error() {
        let io = MemoryIo::new(16, 512);
        write_records(
            &io,
            0,
            &[
                (1, mkdir_record(1, b"x", 10)),
                (2, mkdir_record(1, b"y", 11)),
            ],
        );

        struct FailOnSecond {
            calls: u32,
        }
        impl RedoCallback for FailOnSecond {
            fn replay(&mut self, _r: &IntentLogRecord, _txg: u64, _seq: u64) -> Result<(), Errno> {
                self.calls += 1;
                if self.calls == 2 {
                    Err(Errno::EIO)
                } else {
                    Ok(())
                }
            }
        }

        let scanner = IntentLogKernelScanner::new(&io, 0).unwrap();
        let mut cb = FailOnSecond { calls: 0 };
        {
            let mut overlay = KernelReplayOverlay::new(scanner, &mut cb, 0);
            assert_eq!(overlay.replay_all(), Err(KernelScanError::Io(Errno::EIO)));
        }
        assert_eq!(cb.calls, 2);
    }
}
