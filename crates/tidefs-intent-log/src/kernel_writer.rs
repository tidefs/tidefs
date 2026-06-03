//! Kernel-mode intent-log append through [`KernelStorageIo`].
//!
//! This module is the no_std append primitive used by mounted kernel code. It
//! writes the existing BLAKE3-verified [`IntentLogFrame`] encoding directly to
//! sector-aligned storage and pads only the physical sector tail.

use alloc::vec::Vec;

use tidefs_kernel_storage_io::KernelStorageIo;
use tidefs_types_vfs_core::Errno;

use crate::{IntentLogError, IntentLogFrame, IntentLogRecord};

/// Encoded frame prefix length:
/// `txg_id u64 || record_seq u64 || checksum [u8; 32] || record_len u32`.
pub(crate) const FRAME_PREFIX_LEN: usize = 8 + 8 + 32 + 4;

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

/// Successful append result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntentLogKernelAppend {
    /// First sector written.
    pub start_sector: u64,
    /// Number of sectors written, including physical padding.
    pub sector_count: u64,
    /// Number of meaningful encoded-frame bytes before sector padding.
    pub encoded_len: usize,
    /// Transaction group attached to the frame.
    pub txg_id: u64,
    /// Sequence assigned by [`IntentLogKernelWriter`].
    pub record_seq: u64,
    /// Whether a storage flush completed for this append.
    pub flushed: bool,
}

/// Sector-aligned no_std intent-log writer.
///
/// The writer owns only cursor state. The block-device implementation remains
/// behind [`KernelStorageIo`], so mounted kernel code can use the same append
/// primitive with C-shim or Rust block-device adapters.
pub struct IntentLogKernelWriter<'a> {
    io: &'a dyn KernelStorageIo,
    next_sector: u64,
    next_record_seq: u64,
}

impl<'a> IntentLogKernelWriter<'a> {
    /// Create a writer at an existing sector and sequence cursor.
    pub fn new(
        io: &'a dyn KernelStorageIo,
        start_sector: u64,
        next_record_seq: u64,
    ) -> Result<Self, Errno> {
        if io.sector_size() == 0 || start_sector > io.capacity_sectors() {
            return Err(Errno::EINVAL);
        }
        Ok(Self {
            io,
            next_sector: start_sector,
            next_record_seq,
        })
    }

    /// Return the next sector that will be written on success.
    #[inline]
    pub fn next_sector(&self) -> u64 {
        self.next_sector
    }

    /// Return the next sequence number that will be assigned on success.
    #[inline]
    pub fn next_record_seq(&self) -> u64 {
        self.next_record_seq
    }

    /// Append one intent-log record.
    ///
    /// The writer assigns a monotonic record sequence, creates a real
    /// [`IntentLogFrame`] with BLAKE3 integrity, pads the encoded frame to a
    /// whole number of sectors, writes it through [`KernelStorageIo`], and
    /// optionally flushes the backend.
    pub fn append_record(
        &mut self,
        txg_id: u64,
        record: IntentLogRecord,
        flush: KernelIntentFlush,
    ) -> Result<IntentLogKernelAppend, Errno> {
        let record_seq = self.next_record_seq;
        let frame = IntentLogFrame::new(record, txg_id, record_seq);
        let frame_bytes = frame.encode();
        let encoded_len = frame_bytes.len();
        if encoded_len < FRAME_PREFIX_LEN || encoded_len > u32::MAX as usize {
            return Err(Errno::EOVERFLOW);
        }

        let sector_size = usize::try_from(self.io.sector_size()).map_err(|_| Errno::EINVAL)?;
        if sector_size == 0 {
            return Err(Errno::EINVAL);
        }
        let sector_count = sectors_for_len(encoded_len, sector_size)?;
        let end_sector = self
            .next_sector
            .checked_add(sector_count)
            .ok_or(Errno::EOVERFLOW)?;
        if end_sector > self.io.capacity_sectors() {
            return Err(Errno::ENOSPC);
        }

        let padded_len = padded_len_for_sectors(sector_count, sector_size)?;
        let mut sector_buf = Vec::with_capacity(padded_len);
        sector_buf.extend_from_slice(&frame_bytes);
        sector_buf.resize(padded_len, 0);

        let written = self.io.write_sectors(self.next_sector, &sector_buf)?;
        if u64::from(written) != sector_count {
            return Err(Errno::EIO);
        }
        if flush.should_flush() {
            self.io.flush()?;
        }

        let start_sector = self.next_sector;
        self.next_sector = end_sector;
        self.next_record_seq = self
            .next_record_seq
            .checked_add(1)
            .ok_or(Errno::EOVERFLOW)?;

        Ok(IntentLogKernelAppend {
            start_sector,
            sector_count,
            encoded_len,
            txg_id,
            record_seq,
            flushed: flush.should_flush(),
        })
    }
}

/// Return the meaningful encoded frame length within a sector-padded buffer.
pub fn sector_aligned_frame_len(buf: &[u8]) -> Result<usize, IntentLogError> {
    if buf.len() < FRAME_PREFIX_LEN {
        return Err(IntentLogError::BufferTooShort);
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[8 + 8 + 32..FRAME_PREFIX_LEN]);
    let record_len = u32::from_le_bytes(bytes) as usize;
    FRAME_PREFIX_LEN
        .checked_add(record_len)
        .filter(|len| *len <= buf.len())
        .ok_or(IntentLogError::BufferTooShort)
}

/// Decode an [`IntentLogFrame`] from a sector-padded buffer.
pub fn decode_sector_aligned_frame(buf: &[u8]) -> Result<IntentLogFrame, IntentLogError> {
    let encoded_len = sector_aligned_frame_len(buf)?;
    IntentLogFrame::decode(&buf[..encoded_len])
}

fn sectors_for_len(encoded_len: usize, sector_size: usize) -> Result<u64, Errno> {
    let sectors = encoded_len
        .checked_add(sector_size - 1)
        .ok_or(Errno::EOVERFLOW)?
        / sector_size;
    u64::try_from(sectors).map_err(|_| Errno::EOVERFLOW)
}

fn padded_len_for_sectors(sector_count: u64, sector_size: usize) -> Result<usize, Errno> {
    let sector_count = usize::try_from(sector_count).map_err(|_| Errno::EOVERFLOW)?;
    sector_count
        .checked_mul(sector_size)
        .ok_or(Errno::EOVERFLOW)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    use super::*;

    struct MemoryIo {
        data: Mutex<Vec<u8>>,
        sector_size: u32,
        flush_count: Mutex<u32>,
        short_write: Mutex<bool>,
        fail_flush: Mutex<bool>,
    }

    impl MemoryIo {
        fn new(sectors: u64, sector_size: u32) -> Self {
            let len = usize::try_from(sectors * u64::from(sector_size)).unwrap();
            Self {
                data: Mutex::new(vec![0; len]),
                sector_size,
                flush_count: Mutex::new(0),
                short_write: Mutex::new(false),
                fail_flush: Mutex::new(false),
            }
        }

        fn read_sector_bytes(&self, start_sector: u64, sector_count: u64) -> Vec<u8> {
            let start = usize::try_from(start_sector * u64::from(self.sector_size)).unwrap();
            let len = usize::try_from(sector_count * u64::from(self.sector_size)).unwrap();
            self.data.lock().unwrap()[start..start + len].to_vec()
        }

        fn flush_count(&self) -> u32 {
            *self.flush_count.lock().unwrap()
        }

        fn set_short_write(&self, value: bool) {
            *self.short_write.lock().unwrap() = value;
        }

        fn set_fail_flush(&self, value: bool) {
            *self.fail_flush.lock().unwrap() = value;
        }
    }

    impl KernelStorageIo for MemoryIo {
        fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno> {
            let sector_size = usize::try_from(self.sector_size).unwrap();
            if buf.len() % sector_size != 0 {
                return Err(Errno::EINVAL);
            }
            let start = usize::try_from(start_sector * u64::from(self.sector_size)).unwrap();
            let data = self.data.lock().unwrap();
            if start + buf.len() > data.len() {
                return Err(Errno::EINVAL);
            }
            buf.copy_from_slice(&data[start..start + buf.len()]);
            Ok((buf.len() / sector_size) as u32)
        }

        fn write_sectors(&self, start_sector: u64, data: &[u8]) -> Result<u32, Errno> {
            let sector_size = usize::try_from(self.sector_size).unwrap();
            if data.len() % sector_size != 0 {
                return Err(Errno::EINVAL);
            }
            let sectors = (data.len() / sector_size) as u32;
            if *self.short_write.lock().unwrap() {
                return Ok(sectors.saturating_sub(1));
            }
            let start = usize::try_from(start_sector * u64::from(self.sector_size)).unwrap();
            let mut target = self.data.lock().unwrap();
            if start + data.len() > target.len() {
                return Err(Errno::ENOSPC);
            }
            target[start..start + data.len()].copy_from_slice(data);
            Ok(sectors)
        }

        fn flush(&self) -> Result<(), Errno> {
            if *self.fail_flush.lock().unwrap() {
                return Err(Errno::EIO);
            }
            *self.flush_count.lock().unwrap() += 1;
            Ok(())
        }

        fn sector_size(&self) -> u32 {
            self.sector_size
        }

        fn capacity_sectors(&self) -> u64 {
            self.data.lock().unwrap().len() as u64 / u64::from(self.sector_size)
        }
    }

    fn tx_record(cg_id: u64) -> IntentLogRecord {
        IntentLogRecord::TxBegin { cg_id }
    }

    #[test]
    fn append_record_writes_sector_aligned_frame_and_flushes() {
        let io = MemoryIo::new(16, 512);
        let mut writer = IntentLogKernelWriter::new(&io, 2, 42).unwrap();

        let append = writer
            .append_record(7, tx_record(7), KernelIntentFlush::Flush)
            .unwrap();

        assert_eq!(append.start_sector, 2);
        assert_eq!(append.sector_count, 1);
        assert_eq!(append.record_seq, 42);
        assert!(append.flushed);
        assert_eq!(writer.next_sector(), 3);
        assert_eq!(writer.next_record_seq(), 43);
        assert_eq!(io.flush_count(), 1);

        let bytes = io.read_sector_bytes(append.start_sector, append.sector_count);
        let decoded = decode_sector_aligned_frame(&bytes).unwrap();
        assert_eq!(decoded.txg_id, 7);
        assert_eq!(decoded.record_seq, 42);
        assert_eq!(decoded.record, tx_record(7));
        decoded.verify().unwrap();
    }

    #[test]
    fn append_record_zero_pads_only_the_sector_tail() {
        let io = MemoryIo::new(4, 512);
        let mut writer = IntentLogKernelWriter::new(&io, 0, 0).unwrap();
        let append = writer
            .append_record(1, tx_record(1), KernelIntentFlush::Deferred)
            .unwrap();
        let bytes = io.read_sector_bytes(0, append.sector_count);
        assert_eq!(
            sector_aligned_frame_len(&bytes).unwrap(),
            append.encoded_len
        );
        assert!(bytes[append.encoded_len..].iter().all(|b| *b == 0));
        assert_eq!(io.flush_count(), 0);
    }

    #[test]
    fn append_large_record_advances_multiple_sectors() {
        let io = MemoryIo::new(16, 512);
        let mut writer = IntentLogKernelWriter::new(&io, 0, 9).unwrap();
        let record = IntentLogRecord::BufferedWrite {
            ino: 5,
            offset: 4096,
            length: 900,
            data: vec![0x5a; 900],
        };

        let append = writer
            .append_record(3, record.clone(), KernelIntentFlush::Deferred)
            .unwrap();

        assert!(append.sector_count >= 2);
        assert_eq!(writer.next_sector(), append.sector_count);
        assert_eq!(writer.next_record_seq(), 10);
        let bytes = io.read_sector_bytes(append.start_sector, append.sector_count);
        let decoded = decode_sector_aligned_frame(&bytes).unwrap();
        assert_eq!(decoded.record_seq, 9);
        assert_eq!(decoded.record, record);
    }

    #[test]
    fn short_write_returns_eio_and_does_not_advance() {
        let io = MemoryIo::new(4, 512);
        io.set_short_write(true);
        let mut writer = IntentLogKernelWriter::new(&io, 1, 11).unwrap();

        let err = writer
            .append_record(1, tx_record(1), KernelIntentFlush::Flush)
            .unwrap_err();

        assert_eq!(err, Errno::EIO);
        assert_eq!(writer.next_sector(), 1);
        assert_eq!(writer.next_record_seq(), 11);
        assert_eq!(io.flush_count(), 0);
    }

    #[test]
    fn flush_error_returns_eio_and_does_not_advance() {
        let io = MemoryIo::new(4, 512);
        io.set_fail_flush(true);
        let mut writer = IntentLogKernelWriter::new(&io, 1, 11).unwrap();

        let err = writer
            .append_record(1, tx_record(1), KernelIntentFlush::Flush)
            .unwrap_err();

        assert_eq!(err, Errno::EIO);
        assert_eq!(writer.next_sector(), 1);
        assert_eq!(writer.next_record_seq(), 11);
    }

    #[test]
    fn capacity_exhaustion_returns_enospc() {
        let io = MemoryIo::new(1, 512);
        let mut writer = IntentLogKernelWriter::new(&io, 1, 0).unwrap();

        let err = writer
            .append_record(1, tx_record(1), KernelIntentFlush::Deferred)
            .unwrap_err();

        assert_eq!(err, Errno::ENOSPC);
    }
}
