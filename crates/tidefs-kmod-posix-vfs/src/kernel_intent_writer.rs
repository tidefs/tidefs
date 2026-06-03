// SPDX-License-Identifier: GPL-2.0
//! Kernel-mode intent-log frame writer (inline, no child-crate dependency).
//!
//! Provides sector-aligned BLAKE3-integrity intent-log frame encoding and
//! writing through [`KernelStorageIo`].  This is the Kbuild-only companion to
//! [`crate::intent_record`]: encoding functions produce binary entries, and
//! this module wraps them in frames and writes them to storage.
//!
//! The on-disk frame layout matches [`tidefs_intent_log::IntentLogFrame`]:
//! ```text
//!   txg_id (u64 LE) || record_seq (u64 LE) || checksum ([u8; 32])
//!   || record_len (u32 LE) || record_bytes
//! ```
//! The BLAKE3-256 checksum covers `record_bytes || txg_id || record_seq`.

use crate::errno::KernelErrno;
#[cfg(not(CONFIG_RUST))]
use core::fmt;
use tidefs_kmod_bridge::kernel_types::Errno;

use crate::TideVec as Vec;
#[cfg(not(CONFIG_RUST))]
use tidefs_kernel_storage_io::KernelStorageIo;

// ---------------------------------------------------------------------------
// Frame constants
// ---------------------------------------------------------------------------

/// Frame prefix length: txg_id (8) + record_seq (8) + checksum (32) + record_len (4).
pub const FRAME_PREFIX_LEN: usize = 8 + 8 + 32 + 4;

/// Flush policy for a kernel intent-log append.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelIntentFlush {
    /// Write the sector-aligned record and leave the flush to a later barrier.
    Deferred,
    /// Write the record and immediately call [`KernelStorageIo::flush`].
    Flush,
}

impl KernelIntentFlush {
    #[inline]
    fn should_flush(self) -> bool {
        matches!(self, Self::Flush)
    }
}

// ---------------------------------------------------------------------------
// KernelIntentFrame
// ---------------------------------------------------------------------------

/// A BLAKE3-integrity intent-log frame wrapping an encoded record.
///
/// The checksum binds the record to a specific transaction group and
/// monotonic sequence position, preventing reordering or corruption.
/// The on-disk layout is compatible with
/// [`tidefs_intent_log::IntentLogFrame::encode`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelIntentFrame {
    /// Binary-encoded record payload (from [`crate::intent_record::IntentLogEntry`]).
    pub record_bytes: Vec<u8>,
    /// Transaction group this frame belongs to.
    pub txg_id: u64,
    /// Monotonic sequence number within the intent-log stream.
    pub record_seq: u64,
    /// BLAKE3-256 checksum of `record_bytes || txg_id || record_seq`.
    pub checksum: [u8; 32],
}

impl KernelIntentFrame {
    /// Create and checksum a new frame.
    ///
    /// Checksum covers `record_bytes || txg_id (LE) || record_seq (LE)` so
    /// the frame is bound to its exact position in the commit pipeline.
    pub fn new(record_bytes: Vec<u8>, txg_id: u64, record_seq: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&record_bytes);
        hasher.update(&txg_id.to_le_bytes());
        hasher.update(&record_seq.to_le_bytes());
        let checksum: [u8; 32] = hasher.finalize().into();
        Self {
            record_bytes,
            txg_id,
            record_seq,
            checksum,
        }
    }

    /// Verify the stored checksum against a fresh computation.
    ///
    /// Returns [`KernelErrno::STORAGE_IO`] on mismatch (tampering or corruption).
    pub fn verify(&self) -> Result<(), Errno> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.record_bytes);
        hasher.update(&self.txg_id.to_le_bytes());
        hasher.update(&self.record_seq.to_le_bytes());
        let computed: [u8; 32] = hasher.finalize().into();
        if computed == self.checksum {
            Ok(())
        } else {
            Err(KernelErrno::STORAGE_IO)
        }
    }

    /// Serialize the frame to on-disk wire format.
    pub fn encode(&self) -> Vec<u8> {
        let record_len = self.record_bytes.len();
        let mut buf = Vec::with_capacity(FRAME_PREFIX_LEN + record_len);
        buf.extend_from_slice(&self.txg_id.to_le_bytes());
        buf.extend_from_slice(&self.record_seq.to_le_bytes());
        buf.extend_from_slice(&self.checksum);
        buf.extend_from_slice(&(record_len as u32).to_le_bytes());
        buf.extend_from_slice(&self.record_bytes);
        buf
    }

    /// Deserialize a frame from on-disk wire format.
    ///
    /// Returns [`KernelErrno::INVALID_ARGUMENT`] for truncated or malformed data.
    /// Returns [`KernelErrno::STORAGE_IO`] on checksum mismatch.
    pub fn decode(buf: &[u8]) -> Result<Self, Errno> {
        if buf.len() < FRAME_PREFIX_LEN {
            return Err(KernelErrno::INVALID_ARGUMENT);
        }
        let txg_id = u64::from_le_bytes(
            buf[0..8]
                .try_into()
                .map_err(|_| KernelErrno::INVALID_ARGUMENT)?,
        );
        let record_seq = u64::from_le_bytes(
            buf[8..16]
                .try_into()
                .map_err(|_| KernelErrno::INVALID_ARGUMENT)?,
        );
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&buf[16..48]);
        let record_len = u32::from_le_bytes(
            buf[48..52]
                .try_into()
                .map_err(|_| KernelErrno::INVALID_ARGUMENT)?,
        ) as usize;
        if 52 + record_len > buf.len() {
            return Err(KernelErrno::INVALID_ARGUMENT);
        }
        let record_bytes = buf[52..52 + record_len].to_vec();
        let frame = Self {
            record_bytes,
            txg_id,
            record_seq,
            checksum,
        };
        frame.verify()?;
        Ok(frame)
    }

    /// Total encoded frame length including prefix and record.
    pub fn encoded_len(&self) -> usize {
        FRAME_PREFIX_LEN + self.record_bytes.len()
    }
}

// ---------------------------------------------------------------------------
// KernelIntentAppend (result metadata)
// ---------------------------------------------------------------------------

/// Result metadata for a successful intent-log append.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelIntentAppend {
    /// First sector written.
    pub start_sector: u64,
    /// Number of sectors written (including zero-padding).
    pub sector_count: u64,
    /// Meaningful encoded frame bytes before sector padding.
    pub encoded_len: usize,
    /// Transaction group attached to the frame.
    pub txg_id: u64,
    /// Sequence assigned to the frame.
    pub record_seq: u64,
    /// Whether a storage flush completed for this append.
    pub flushed: bool,
}

// ---------------------------------------------------------------------------
// KernelIntentWriter
// ---------------------------------------------------------------------------

/// Sector-aligned no_std intent-log writer.
///
/// Owns cursor state only; the block-device implementation sits behind
/// [`KernelStorageIo`].  Compatible with the canonical
/// [`tidefs_intent_log::IntentLogKernelWriter`] on-disk layout.
pub struct KernelIntentWriter {
    io: alloc::boxed::Box<dyn KernelStorageIo + Send + Sync>,
    next_sector: u64,
    next_record_seq: u64,
}

impl KernelIntentWriter {
    /// Create a writer starting at `start_sector` with `next_record_seq`.
    ///
    /// Returns [`KernelErrno::INVALID_ARGUMENT`] for zero sector size or out-of-range cursor.
    pub fn new(
        io: alloc::boxed::Box<dyn KernelStorageIo + Send + Sync>,
        start_sector: u64,
        next_record_seq: u64,
    ) -> Result<Self, Errno> {
        if io.sector_size() == 0 || start_sector > io.capacity_sectors() {
            return Err(KernelErrno::INVALID_ARGUMENT);
        }
        Ok(Self {
            io,
            next_sector: start_sector,
            next_record_seq,
        })
    }

    /// Next sector to be written on success.
    pub fn next_sector(&self) -> u64 {
        self.next_sector
    }

    /// Next sequence number to be assigned on success.
    pub fn next_record_seq(&self) -> u64 {
        self.next_record_seq
    }

    /// Append one encoded intent record as a framed sector-aligned write.
    ///
    /// The writer assigns a monotonic record sequence, creates a
    /// [`KernelIntentFrame`] with BLAKE3 integrity, pads the encoded frame
    /// to a whole number of sectors, writes it through [`KernelStorageIo`],
    /// and optionally flushes the backend.
    ///
    /// Cursor advances only on success; partial writes and flush failures
    /// return errors without moving the cursor.
    pub fn append_record(
        &mut self,
        txg_id: u64,
        record_bytes: &[u8],
        flush: KernelIntentFlush,
    ) -> Result<KernelIntentAppend, Errno> {
        if record_bytes.is_empty() || record_bytes.len() > u32::MAX as usize {
            return Err(KernelErrno::INVALID_ARGUMENT);
        }

        let record_seq = self.next_record_seq;
        let frame = KernelIntentFrame::new(record_bytes.to_vec(), txg_id, record_seq);
        let frame_bytes = frame.encode();
        let encoded_len = frame_bytes.len();

        let sector_size =
            usize::try_from(self.io.sector_size()).map_err(|_| KernelErrno::INVALID_ARGUMENT)?;
        if sector_size == 0 {
            return Err(KernelErrno::INVALID_ARGUMENT);
        }

        let sector_count = sectors_for_len(encoded_len, sector_size)?;
        let end_sector = self
            .next_sector
            .checked_add(sector_count)
            .ok_or(KernelErrno::VALUE_OVERFLOW)?;
        if end_sector > self.io.capacity_sectors() {
            return Err(KernelErrno::SPACE_EXHAUSTED);
        }

        let padded_len = padded_len_for_sectors(sector_count, sector_size)?;
        let mut sector_buf = Vec::with_capacity(padded_len);
        sector_buf.extend_from_slice(&frame_bytes);
        sector_buf.resize(padded_len, 0);

        let written = self.io.write_sectors(self.next_sector, &sector_buf)?;
        if u64::from(written) != sector_count {
            return Err(KernelErrno::STORAGE_IO);
        }

        if flush.should_flush() {
            self.io.flush()?;
        }

        let start_sector = self.next_sector;
        self.next_sector = end_sector;
        self.next_record_seq = self
            .next_record_seq
            .checked_add(1)
            .ok_or(KernelErrno::VALUE_OVERFLOW)?;

        Ok(KernelIntentAppend {
            start_sector,
            sector_count,
            encoded_len,
            txg_id,
            record_seq,
            flushed: flush.should_flush(),
        })
    }

    /// Flush the storage backend without appending a record.
    pub fn flush_backend(&self) -> Result<(), Errno> {
        self.io.flush()
    }

    /// Return a reference to the storage I/O backend.
    pub fn io(&self) -> &dyn KernelStorageIo {
        &*self.io
    }
}

impl fmt::Debug for KernelIntentWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelIntentWriter")
            .field("next_sector", &self.next_sector)
            .field("next_record_seq", &self.next_record_seq)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Sector-math helpers
// ---------------------------------------------------------------------------

fn sectors_for_len(encoded_len: usize, sector_size: usize) -> Result<u64, Errno> {
    let sectors = encoded_len
        .checked_add(sector_size - 1)
        .ok_or(KernelErrno::VALUE_OVERFLOW)?
        / sector_size;
    u64::try_from(sectors).map_err(|_| KernelErrno::VALUE_OVERFLOW)
}

fn padded_len_for_sectors(sector_count: u64, sector_size: usize) -> Result<usize, Errno> {
    let sector_count = usize::try_from(sector_count).map_err(|_| KernelErrno::VALUE_OVERFLOW)?;
    sector_count
        .checked_mul(sector_size)
        .ok_or(KernelErrno::VALUE_OVERFLOW)
}

// ---------------------------------------------------------------------------
// Kbuild stub — provides no-op types when kernel-intent-log is not available
// ---------------------------------------------------------------------------

#[cfg(CONFIG_RUST)]
pub enum KernelIntentFlush {
    Deferred,
    Flush,
}

#[cfg(CONFIG_RUST)]
impl KernelIntentFlush {
    pub(crate) fn should_flush(self) -> bool {
        matches!(self, Self::Flush)
    }
}

#[cfg(CONFIG_RUST)]
pub struct KernelIntentAppend {
    pub start_sector: u64,
    pub sector_count: u64,
    pub encoded_len: usize,
    pub txg_id: u64,
    pub record_seq: u64,
    pub flushed: bool,
}

#[cfg(CONFIG_RUST)]
pub struct KernelIntentWriter {
    _private: (),
}

#[cfg(CONFIG_RUST)]
impl KernelIntentWriter {
    pub fn new(_io: (), _start_sector: u64, _next_record_seq: u64) -> Result<Self, Errno> {
        Ok(Self { _private: () })
    }
    pub fn next_sector(&self) -> u64 {
        0
    }
    pub fn next_record_seq(&self) -> u64 {
        0
    }
    pub fn append_record(
        &mut self,
        _txg_id: u64,
        _record_bytes: &[u8],
        _flush: KernelIntentFlush,
    ) -> Result<KernelIntentAppend, Errno> {
        Err(Errno::ENOSYS)
    }
    pub fn flush_backend(&self) -> Result<(), Errno> {
        Ok(())
    }
}
