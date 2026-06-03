//! KernelStorageIo committed-root persistence helpers.
//!
//! This module keeps the kernel path on the existing committed-root authority:
//! the `VRBT` [`CommittedRootBlock`] from [`crate::writer`].  The small pointer
//! record here only names the sector where that block lives and carries the
//! block hash for recovery validation; it is not a second committed-root body.

use alloc::vec;

use crate::txg_sequence::TxgSequenceCounter;
use crate::types::CommitGroupId;
use crate::writer::{CommitGroupWriter, CommittedRootBlock};
use tidefs_kernel_storage_io::KernelStorageIo;
use tidefs_types_vfs_core::Errno;

const POINTER_MAGIC: &[u8; 4] = b"VCRP";
const POINTER_VERSION: u32 = 1;
const POINTER_HEADER_SIZE: usize = 64;
const POINTER_RECORD_SIZE: usize = 96;
const POINTER_HASH_OFFSET: usize = 64;

/// Durability policy for kernel committed-root writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelCommittedRootFlush {
    /// Leave the backend dirty; caller will issue a later barrier.
    Deferred,
    /// Flush after the write sequence completes.
    Flush,
}

impl KernelCommittedRootFlush {
    fn should_flush(self) -> bool {
        matches!(self, Self::Flush)
    }
}

/// Result metadata for a written `VRBT` committed-root block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelCommittedRootWrite {
    /// First sector containing the padded `VRBT` block.
    pub start_sector: u64,
    /// Number of physical sectors written.
    pub sector_count: u32,
    /// Unpadded encoded `VRBT` byte length.
    pub encoded_len: usize,
    /// Transaction group encoded in the sealed block.
    pub commit_group_id: CommitGroupId,
    /// BLAKE3 root-block hash copied from the sealed block.
    pub root_hash: [u8; 32],
    /// Whether this helper issued a flush after writing.
    pub flushed: bool,
}

/// Pointer to the currently selected committed-root block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedRootPointer {
    /// Monotonic pointer update sequence; recovery chooses the highest valid one.
    pub sequence: u64,
    /// Sector where the `VRBT` committed-root block begins.
    pub root_sector: u64,
    /// Transaction group encoded in the referenced block.
    pub commit_group_id: CommitGroupId,
    /// BLAKE3 hash of the referenced `VRBT` block.
    pub root_hash: [u8; 32],
}

/// Result metadata for writing both the root block and pointer slots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedRootCommit {
    /// Written `VRBT` root-block metadata.
    pub root_write: KernelCommittedRootWrite,
    /// Pointer record selected by future recovery.
    pub pointer: CommittedRootPointer,
    /// Number of sectors written for each pointer copy.
    pub pointer_sectors: u32,
}

/// Seal and write a committed-root block through sector-aligned kernel I/O.
///
/// The existing `VRBT` committed-root block is written first, padded only to
/// the device sector size.  Short writes are treated as `EIO`.
pub fn seal_and_write_committed_root_block<I: KernelStorageIo + ?Sized>(
    io: &I,
    start_sector: u64,
    block: CommittedRootBlock,
    flush: KernelCommittedRootFlush,
) -> Result<(CommittedRootBlock, KernelCommittedRootWrite), Errno> {
    let sealed = CommitGroupWriter::seal_root_block(block);
    let sector_size = checked_sector_size(io)?;
    let sector_count = sector_count_for_len(CommittedRootBlock::WIRE_SIZE, sector_size)?;
    ensure_range(io, start_sector, sector_count)?;

    let padded_len = sectors_to_len(sector_count, sector_size)?;
    let mut data = vec![0u8; padded_len];
    data[..CommittedRootBlock::WIRE_SIZE].copy_from_slice(&sealed.to_bytes());

    let written = io.write_sectors(start_sector, &data)?;
    let expected = u32::try_from(sector_count).map_err(|_| Errno::EOVERFLOW)?;
    if written != expected {
        return Err(Errno::EIO);
    }

    if flush.should_flush() {
        io.flush()?;
    }

    let result = KernelCommittedRootWrite {
        start_sector,
        sector_count: expected,
        encoded_len: CommittedRootBlock::WIRE_SIZE,
        commit_group_id: sealed.commit_group_id,
        root_hash: sealed.block_hash,
        flushed: flush.should_flush(),
    };
    Ok((sealed, result))
}

/// Read and verify a sector-aligned `VRBT` committed-root block.
pub fn read_committed_root_block<I: KernelStorageIo + ?Sized>(
    io: &I,
    start_sector: u64,
) -> Result<CommittedRootBlock, Errno> {
    let sector_size = checked_sector_size(io)?;
    let sector_count = sector_count_for_len(CommittedRootBlock::WIRE_SIZE, sector_size)?;
    ensure_range(io, start_sector, sector_count)?;

    let padded_len = sectors_to_len(sector_count, sector_size)?;
    let mut data = vec![0u8; padded_len];
    let read = io.read_sectors(start_sector, &mut data)?;
    let expected = u32::try_from(sector_count).map_err(|_| Errno::EOVERFLOW)?;
    if read != expected {
        return Err(Errno::EIO);
    }

    let block =
        CommittedRootBlock::from_bytes(&data[..CommittedRootBlock::WIRE_SIZE]).ok_or(Errno::EIO)?;
    if !CommitGroupWriter::verify_root_block(&block) {
        return Err(Errno::EIO);
    }
    Ok(block)
}

/// Write the double-buffered committed-root pointer slots.
///
/// The pointer slots contain only a sector location plus hash of the existing
/// `VRBT` block.  Recovery validates both copies and selects the highest valid
/// sequence number.
pub fn write_committed_root_pointer<I: KernelStorageIo + ?Sized>(
    io: &I,
    pointer_sector: u64,
    sequence: u64,
    root_sector: u64,
    sealed_block: &CommittedRootBlock,
    flush: KernelCommittedRootFlush,
) -> Result<(CommittedRootPointer, u32), Errno> {
    if !CommitGroupWriter::verify_root_block(sealed_block) {
        return Err(Errno::EINVAL);
    }

    let sector_size = checked_sector_size(io)?;
    let pointer_sector_count = sector_count_for_len(POINTER_RECORD_SIZE, sector_size)?;
    ensure_range(io, pointer_sector, pointer_sector_count.saturating_mul(2))?;

    let pointer = CommittedRootPointer {
        sequence,
        root_sector,
        commit_group_id: sealed_block.commit_group_id,
        root_hash: sealed_block.block_hash,
    };

    let padded_len = sectors_to_len(pointer_sector_count, sector_size)?;
    let mut data = vec![0u8; padded_len];
    data[..POINTER_RECORD_SIZE].copy_from_slice(&encode_pointer_record(&pointer));

    let expected = u32::try_from(pointer_sector_count).map_err(|_| Errno::EOVERFLOW)?;
    let first = io.write_sectors(pointer_sector, &data)?;
    if first != expected {
        return Err(Errno::EIO);
    }
    let second_sector = pointer_sector
        .checked_add(pointer_sector_count)
        .ok_or(Errno::EINVAL)?;
    let second = io.write_sectors(second_sector, &data)?;
    if second != expected {
        return Err(Errno::EIO);
    }

    if flush.should_flush() {
        io.flush()?;
    }

    Ok((pointer, expected))
}

/// Read the double-buffered committed-root pointer slots.
///
/// Returns `Ok(None)` only when both slots are still zero-filled.  If at least
/// one slot is nonzero and no valid pointer can be decoded, recovery reports
/// `EIO` rather than silently selecting an unknown root.
pub fn read_committed_root_pointer<I: KernelStorageIo + ?Sized>(
    io: &I,
    pointer_sector: u64,
) -> Result<Option<CommittedRootPointer>, Errno> {
    let sector_size = checked_sector_size(io)?;
    let pointer_sector_count = sector_count_for_len(POINTER_RECORD_SIZE, sector_size)?;
    ensure_range(io, pointer_sector, pointer_sector_count.saturating_mul(2))?;

    let first = read_pointer_copy(io, pointer_sector, pointer_sector_count, sector_size)?;
    let second_sector = pointer_sector
        .checked_add(pointer_sector_count)
        .ok_or(Errno::EINVAL)?;
    let second = read_pointer_copy(io, second_sector, pointer_sector_count, sector_size)?;

    match (first, second) {
        (PointerCopy::Valid(a), PointerCopy::Valid(b)) => {
            Ok(Some(if a.sequence >= b.sequence { a } else { b }))
        }
        (PointerCopy::Valid(pointer), _) | (_, PointerCopy::Valid(pointer)) => Ok(Some(pointer)),
        (PointerCopy::Zero, PointerCopy::Zero) => Ok(None),
        _ => Err(Errno::EIO),
    }
}

/// Write the root block, then publish the double-buffered current-root pointer.
pub fn write_current_committed_root<I: KernelStorageIo + ?Sized>(
    io: &I,
    pointer_sector: u64,
    root_sector: u64,
    sequence: u64,
    block: CommittedRootBlock,
    flush: KernelCommittedRootFlush,
) -> Result<CommittedRootCommit, Errno> {
    let root_flush = if flush.should_flush() {
        KernelCommittedRootFlush::Flush
    } else {
        KernelCommittedRootFlush::Deferred
    };
    let (sealed, root_write) =
        seal_and_write_committed_root_block(io, root_sector, block, root_flush)?;
    let (pointer, pointer_sectors) =
        write_committed_root_pointer(io, pointer_sector, sequence, root_sector, &sealed, flush)?;

    Ok(CommittedRootCommit {
        root_write,
        pointer,
        pointer_sectors,
    })
}

/// Read the current-root pointer, then read and verify the referenced `VRBT`.
pub fn read_current_committed_root<I: KernelStorageIo + ?Sized>(
    io: &I,
    pointer_sector: u64,
) -> Result<Option<(CommittedRootPointer, CommittedRootBlock)>, Errno> {
    let Some(pointer) = read_committed_root_pointer(io, pointer_sector)? else {
        return Ok(None);
    };

    let block = read_committed_root_block(io, pointer.root_sector)?;
    if block.commit_group_id != pointer.commit_group_id || block.block_hash != pointer.root_hash {
        return Err(Errno::EIO);
    }
    Ok(Some((pointer, block)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PointerCopy {
    Zero,
    Invalid,
    Valid(CommittedRootPointer),
}

fn read_pointer_copy<I: KernelStorageIo + ?Sized>(
    io: &I,
    sector: u64,
    sector_count: u64,
    sector_size: usize,
) -> Result<PointerCopy, Errno> {
    let padded_len = sectors_to_len(sector_count, sector_size)?;
    let mut data = vec![0u8; padded_len];
    let read = io.read_sectors(sector, &mut data)?;
    let expected = u32::try_from(sector_count).map_err(|_| Errno::EOVERFLOW)?;
    if read != expected {
        return Err(Errno::EIO);
    }

    let record = &data[..POINTER_RECORD_SIZE];
    if record.iter().all(|byte| *byte == 0) {
        return Ok(PointerCopy::Zero);
    }

    Ok(decode_pointer_record(record)
        .map(PointerCopy::Valid)
        .unwrap_or(PointerCopy::Invalid))
}

fn encode_pointer_record(pointer: &CommittedRootPointer) -> [u8; POINTER_RECORD_SIZE] {
    let mut bytes = [0u8; POINTER_RECORD_SIZE];
    bytes[0..4].copy_from_slice(POINTER_MAGIC);
    bytes[4..8].copy_from_slice(&POINTER_VERSION.to_le_bytes());
    bytes[8..16].copy_from_slice(&pointer.sequence.to_le_bytes());
    bytes[16..24].copy_from_slice(&pointer.root_sector.to_le_bytes());
    bytes[24..32].copy_from_slice(&pointer.commit_group_id.0.to_le_bytes());
    bytes[32..64].copy_from_slice(&pointer.root_hash);
    let checksum: [u8; 32] = blake3::hash(&bytes[..POINTER_HEADER_SIZE]).into();
    bytes[POINTER_HASH_OFFSET..POINTER_RECORD_SIZE].copy_from_slice(&checksum);
    bytes
}

fn decode_pointer_record(bytes: &[u8]) -> Option<CommittedRootPointer> {
    if bytes.len() < POINTER_RECORD_SIZE {
        return None;
    }
    if &bytes[0..4] != POINTER_MAGIC {
        return None;
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    if version != POINTER_VERSION {
        return None;
    }

    let checksum: [u8; 32] = blake3::hash(&bytes[..POINTER_HEADER_SIZE]).into();
    if bytes[POINTER_HASH_OFFSET..POINTER_RECORD_SIZE] != checksum {
        return None;
    }

    let sequence = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let root_sector = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
    let commit_group_id = CommitGroupId(u64::from_le_bytes(bytes[24..32].try_into().ok()?));
    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&bytes[32..64]);

    Some(CommittedRootPointer {
        sequence,
        root_sector,
        commit_group_id,
        root_hash,
    })
}

fn checked_sector_size<I: KernelStorageIo + ?Sized>(io: &I) -> Result<usize, Errno> {
    let sector_size = io.sector_size() as usize;
    if sector_size == 0 {
        return Err(Errno::EINVAL);
    }
    Ok(sector_size)
}

fn sector_count_for_len(len: usize, sector_size: usize) -> Result<u64, Errno> {
    let sectors = len
        .checked_add(sector_size.checked_sub(1).ok_or(Errno::EINVAL)?)
        .ok_or(Errno::EOVERFLOW)?
        / sector_size;
    u64::try_from(sectors).map_err(|_| Errno::EOVERFLOW)
}

fn sectors_to_len(sector_count: u64, sector_size: usize) -> Result<usize, Errno> {
    let sector_count = usize::try_from(sector_count).map_err(|_| Errno::EOVERFLOW)?;
    sector_count
        .checked_mul(sector_size)
        .ok_or(Errno::EOVERFLOW)
}

fn ensure_range<I: KernelStorageIo + ?Sized>(
    io: &I,
    start_sector: u64,
    sector_count: u64,
) -> Result<(), Errno> {
    let end = start_sector
        .checked_add(sector_count)
        .ok_or(Errno::EINVAL)?;
    if end > io.capacity_sectors() {
        return Err(Errno::ENOSPC);
    }
    Ok(())
}

/// Commit the open txg and persist the committed-root state in one barrier.
///
/// This is the kernel-side mount-point for fsync, syncfs, and clean unmount:
/// it seals the current transaction group, writes the committed-root block
/// and pointer through [`KernelStorageIo`], and advances the sequence counter.
///
/// Returns the committed-root commit metadata on success.
///
/// # Panics
///
/// Panics if `counter.commit_txg(id)` returns an error (txg id mismatch or
/// no open txg). Callers must ensure the counter state matches the given id.
pub fn commit_txg_barrier<I: KernelStorageIo + ?Sized>(
    io: &I,
    counter: &mut TxgSequenceCounter,
    txg_id: tidefs_vfs_engine::TxgId,
    pointer_sector: u64,
    root_sector: u64,
    block: CommittedRootBlock,
    flush: KernelCommittedRootFlush,
) -> Result<CommittedRootCommit, Errno> {
    counter
        .commit_txg(txg_id)
        .expect("commit_txg_barrier: TxgId mismatch or no open txg");
    write_current_committed_root(io, pointer_sector, root_sector, txg_id.0, block, flush)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::vec::Vec;

    struct MemoryKernelStorage {
        sector_size: u32,
        sectors: u64,
        data: Mutex<Vec<u8>>,
        short_write: Mutex<Option<u32>>,
        flush_error: Mutex<Option<Errno>>,
        flushes: AtomicUsize,
    }

    impl MemoryKernelStorage {
        fn new(sector_size: u32, sectors: u64) -> Self {
            let len = usize::try_from(u64::from(sector_size) * sectors).unwrap();
            Self {
                sector_size,
                sectors,
                data: Mutex::new(vec![0u8; len]),
                short_write: Mutex::new(None),
                flush_error: Mutex::new(None),
                flushes: AtomicUsize::new(0),
            }
        }

        fn set_short_write(&self, sectors: u32) {
            *self.short_write.lock().unwrap() = Some(sectors);
        }

        fn set_flush_error(&self, err: Errno) {
            *self.flush_error.lock().unwrap() = Some(err);
        }

        fn corrupt_byte(&self, sector: u64, offset: usize) {
            let byte_offset =
                usize::try_from(sector * u64::from(self.sector_size)).unwrap() + offset;
            self.data.lock().unwrap()[byte_offset] ^= 0x55;
        }

        fn read_byte(&self, sector: u64, offset: usize) -> u8 {
            let byte_offset =
                usize::try_from(sector * u64::from(self.sector_size)).unwrap() + offset;
            self.data.lock().unwrap()[byte_offset]
        }
    }

    impl KernelStorageIo for MemoryKernelStorage {
        fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno> {
            let sector_size = self.sector_size as usize;
            if sector_size == 0 || buf.len() % sector_size != 0 {
                return Err(Errno::EINVAL);
            }
            let sector_count = u64::try_from(buf.len() / sector_size).unwrap();
            if start_sector
                .checked_add(sector_count)
                .ok_or(Errno::EINVAL)?
                > self.sectors
            {
                return Err(Errno::EINVAL);
            }
            let start = usize::try_from(start_sector * u64::from(self.sector_size)).unwrap();
            let end = start + buf.len();
            buf.copy_from_slice(&self.data.lock().unwrap()[start..end]);
            Ok(u32::try_from(sector_count).unwrap())
        }

        fn write_sectors(&self, start_sector: u64, data: &[u8]) -> Result<u32, Errno> {
            let sector_size = self.sector_size as usize;
            if sector_size == 0 || data.len() % sector_size != 0 {
                return Err(Errno::EINVAL);
            }
            let requested = u64::try_from(data.len() / sector_size).unwrap();
            if start_sector.checked_add(requested).ok_or(Errno::EINVAL)? > self.sectors {
                return Err(Errno::ENOSPC);
            }

            let actual = self
                .short_write
                .lock()
                .unwrap()
                .take()
                .map(u64::from)
                .unwrap_or(requested)
                .min(requested);
            let bytes = usize::try_from(actual).unwrap() * sector_size;
            let start = usize::try_from(start_sector * u64::from(self.sector_size)).unwrap();
            let end = start + bytes;
            self.data.lock().unwrap()[start..end].copy_from_slice(&data[..bytes]);
            Ok(u32::try_from(actual).unwrap())
        }

        fn flush(&self) -> Result<(), Errno> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            if let Some(err) = self.flush_error.lock().unwrap().take() {
                return Err(err);
            }
            Ok(())
        }

        fn sector_size(&self) -> u32 {
            self.sector_size
        }

        fn capacity_sectors(&self) -> u64 {
            self.sectors
        }
    }

    fn root_block(txg: u64) -> CommittedRootBlock {
        CommittedRootBlock::new(CommitGroupId(txg), 10 + txg, 20 + txg, 30 + txg, 40 + txg)
    }

    #[test]
    fn root_block_write_read_roundtrip() {
        let io = MemoryKernelStorage::new(512, 16);
        let (sealed, write) = seal_and_write_committed_root_block(
            &io,
            2,
            root_block(7),
            KernelCommittedRootFlush::Flush,
        )
        .unwrap();

        assert_eq!(write.start_sector, 2);
        assert_eq!(write.sector_count, 1);
        assert_eq!(write.encoded_len, CommittedRootBlock::WIRE_SIZE);
        assert_eq!(write.commit_group_id, CommitGroupId(7));
        assert_eq!(write.root_hash, sealed.block_hash);
        assert_eq!(io.flushes.load(Ordering::SeqCst), 1);

        let read_back = read_committed_root_block(&io, 2).unwrap();
        assert_eq!(read_back, sealed);
    }

    #[test]
    fn root_block_sector_tail_is_zero_padded() {
        let io = MemoryKernelStorage::new(512, 16);
        seal_and_write_committed_root_block(
            &io,
            2,
            root_block(1),
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap();

        for offset in CommittedRootBlock::WIRE_SIZE..512 {
            assert_eq!(io.read_byte(2, offset), 0);
        }
    }

    #[test]
    fn root_block_short_write_is_eio() {
        let io = MemoryKernelStorage::new(512, 16);
        io.set_short_write(0);
        let err = seal_and_write_committed_root_block(
            &io,
            2,
            root_block(1),
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap_err();
        assert_eq!(err, Errno::EIO);
    }

    #[test]
    fn root_block_capacity_is_enospc() {
        let io = MemoryKernelStorage::new(512, 2);
        let err = seal_and_write_committed_root_block(
            &io,
            2,
            root_block(1),
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap_err();
        assert_eq!(err, Errno::ENOSPC);
    }

    #[test]
    fn root_block_checksum_mismatch_is_rejected() {
        let io = MemoryKernelStorage::new(512, 16);
        seal_and_write_committed_root_block(
            &io,
            2,
            root_block(1),
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap();
        io.corrupt_byte(2, 16);

        let err = read_committed_root_block(&io, 2).unwrap_err();
        assert_eq!(err, Errno::EIO);
    }

    #[test]
    fn flush_error_is_returned() {
        let io = MemoryKernelStorage::new(512, 16);
        io.set_flush_error(Errno::EIO);

        let err = seal_and_write_committed_root_block(
            &io,
            2,
            root_block(1),
            KernelCommittedRootFlush::Flush,
        )
        .unwrap_err();
        assert_eq!(err, Errno::EIO);
    }

    #[test]
    fn pointer_write_read_roundtrip() {
        let io = MemoryKernelStorage::new(512, 16);
        let (sealed, _) = seal_and_write_committed_root_block(
            &io,
            4,
            root_block(3),
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap();
        let (pointer, sectors) =
            write_committed_root_pointer(&io, 0, 9, 4, &sealed, KernelCommittedRootFlush::Flush)
                .unwrap();

        assert_eq!(sectors, 1);
        assert_eq!(io.flushes.load(Ordering::SeqCst), 1);
        assert_eq!(read_committed_root_pointer(&io, 0).unwrap(), Some(pointer));
    }

    #[test]
    fn pointer_read_falls_back_from_corrupt_first_copy() {
        let io = MemoryKernelStorage::new(512, 16);
        let (sealed, _) = seal_and_write_committed_root_block(
            &io,
            4,
            root_block(3),
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap();
        let (pointer, _) = write_committed_root_pointer(
            &io,
            0,
            11,
            4,
            &sealed,
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap();
        io.corrupt_byte(0, 8);

        assert_eq!(read_committed_root_pointer(&io, 0).unwrap(), Some(pointer));
    }

    #[test]
    fn pointer_read_zero_slots_returns_none() {
        let io = MemoryKernelStorage::new(512, 16);
        assert_eq!(read_committed_root_pointer(&io, 0).unwrap(), None);
    }

    #[test]
    fn pointer_rejects_unsealed_block() {
        let io = MemoryKernelStorage::new(512, 16);
        let err = write_committed_root_pointer(
            &io,
            0,
            1,
            4,
            &root_block(3),
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap_err();
        assert_eq!(err, Errno::EINVAL);
    }

    #[test]
    fn current_root_write_read_roundtrip() {
        let io = MemoryKernelStorage::new(512, 32);
        let commit = write_current_committed_root(
            &io,
            0,
            4,
            12,
            root_block(5),
            KernelCommittedRootFlush::Flush,
        )
        .unwrap();

        assert_eq!(commit.pointer.sequence, 12);
        assert_eq!(commit.pointer.root_sector, 4);
        assert_eq!(commit.pointer.commit_group_id, CommitGroupId(5));
        assert_eq!(io.flushes.load(Ordering::SeqCst), 2);

        let (pointer, block) = read_current_committed_root(&io, 0).unwrap().unwrap();
        assert_eq!(pointer, commit.pointer);
        assert_eq!(block.commit_group_id, CommitGroupId(5));
    }

    #[test]
    fn current_root_rejects_pointer_root_hash_mismatch() {
        let io = MemoryKernelStorage::new(512, 32);
        write_current_committed_root(
            &io,
            0,
            4,
            12,
            root_block(5),
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap();
        io.corrupt_byte(4, 16);

        let err = read_current_committed_root(&io, 0).unwrap_err();
        assert_eq!(err, Errno::EIO);
    }

    #[test]
    fn pointer_read_both_copies_corrupt_returns_eio() {
        let io = MemoryKernelStorage::new(512, 16);
        let (sealed, _) = seal_and_write_committed_root_block(
            &io,
            4,
            root_block(3),
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap();
        write_committed_root_pointer(&io, 0, 11, 4, &sealed, KernelCommittedRootFlush::Deferred)
            .unwrap();

        // Corrupt both copies. Both will fail checksum verification.
        io.corrupt_byte(0, 8);
        io.corrupt_byte(1, 16);

        let err = read_committed_root_pointer(&io, 0).unwrap_err();
        assert_eq!(err, Errno::EIO);
    }

    #[test]
    fn pointer_read_bad_magic_returns_eio() {
        let io = MemoryKernelStorage::new(512, 16);
        let (sealed, _) = seal_and_write_committed_root_block(
            &io,
            4,
            root_block(3),
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap();
        write_committed_root_pointer(&io, 0, 11, 4, &sealed, KernelCommittedRootFlush::Deferred)
            .unwrap();

        // Corrupt the magic bytes of the first copy, zero the second.
        io.corrupt_byte(0, 0);
        let data = vec![0u8; 512];
        io.write_sectors(1, &data).unwrap();

        // First copy has bad magic (Invalid), second copy is zero (Zero).
        // (Invalid, Zero) must return EIO, not None.
        let err = read_committed_root_pointer(&io, 0).unwrap_err();
        assert_eq!(err, Errno::EIO);
    }

    #[test]
    fn pointer_read_single_copy_fallback() {
        // Verify that when one copy is corrupt but the other is valid,
        // the valid copy is returned.  Already tested above; this adds
        // an explicit second-copy-fallback variant.
        let io = MemoryKernelStorage::new(512, 16);
        let (sealed, _) = seal_and_write_committed_root_block(
            &io,
            4,
            root_block(3),
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap();
        let (pointer, _) = write_committed_root_pointer(
            &io,
            0,
            11,
            4,
            &sealed,
            KernelCommittedRootFlush::Deferred,
        )
        .unwrap();

        // Corrupt second copy; first copy should be returned.
        io.corrupt_byte(1, 8);
        let result = read_committed_root_pointer(&io, 0).unwrap();
        assert_eq!(result, Some(pointer));
    }

    #[test]
    fn pointer_read_truncated_device_no_panic() {
        // A device too small to hold both pointer copies must return
        // an error, not panic.
        let io = MemoryKernelStorage::new(512, 1); // only one sector
        let err = read_committed_root_pointer(&io, 0).unwrap_err();
        assert_eq!(err, Errno::ENOSPC);
    }

    #[test]
    fn current_root_returns_none_on_empty_pool() {
        // A fresh pool with zero-filled pointer slots must return Ok(None),
        // not an error, so the kmod can distinguish "no committed root yet"
        // from "corrupt committed root".
        let io = MemoryKernelStorage::new(512, 16);
        let result = read_current_committed_root(&io, 0).unwrap();
        assert!(result.is_none());
    }
}
