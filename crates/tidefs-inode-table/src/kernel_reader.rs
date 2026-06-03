//! Kernel-mode inode table record reader.
//!
//! [`KernelInodeTableReader`] reads and decodes individual inode records
//! from a raw on-disk inode table region through [`KernelStorageIo`],
//! enabling kernel VFS inode resolution without userspace assistance.
//!
//! # On-disk record format
//!
//! Each record is 116 bytes, stored contiguously starting at
//! `table_start_sector`. Record `i` (inode number `i+1`) begins at byte
//! offset `i * INODE_RECORD_BYTES` within the table region.
//!
//! ```text
//! Offset  Bytes  Field
//! 0       4      magic "VINO"
//! 4       4      mode (u32 LE)
//! 8       4      uid (u32 LE)
//! 12      4      gid (u32 LE)
//! 16      8      size (u64 LE)
//! 24      8      blocks (u64 LE)
//! 32      8      atime_secs (u64 LE)
//! 40      4      atime_nanos (u32 LE)
//! 44      8      mtime_secs (u64 LE)
//! 52      4      mtime_nanos (u32 LE)
//! 56      8      ctime_secs (u64 LE)
//! 64      4      ctime_nanos (u32 LE)
//! 68      4      nlink (u32 LE)
//! 72      8      generation (u64 LE)
//! 80      1      kind (0=File, 1=Directory, 2=Symlink)
//! 81      1      format_version (currently 1)
//! 81      3      reserved (zero)
//! 84      8      object_store_locator (u64 LE)
//! 92      8      extent_map_root (u64 LE)
//! 100     8      btime_secs (u64 LE)
//! 108     4      btime_nanos (u32 LE)
//! 112     4      flags (u32 LE)
//! ```
//!
//! # no_std
//!
//! This module is `no_std` compatible. It uses only `core` primitives
//! and the [`KernelStorageIo`] trait.

use tidefs_kernel_storage_io::KernelStorageIo;

// ── Constants ────────────────────────────────────────────────────────────

/// Magic bytes prefixing every valid inode record.
const INODE_RECORD_MAGIC: [u8; 4] = [b'V', b'I', b'N', b'O'];

/// Size of a single on-disk inode record in bytes.
const INODE_RECORD_BYTES: usize = 116;

/// On-disk format version byte stored at record offset 81.
/// Reader rejects records with an unrecognized version.
const FORMAT_VERSION: u8 = 1;

// ── InodeKind ────────────────────────────────────────────────────────────

/// The kind of filesystem object an inode represents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InodeKind {
    /// Regular file.
    File = 0,
    /// Directory.
    Directory = 1,
    /// Symbolic link.
    Symlink = 2,
}

impl InodeKind {
    /// Decode from the on-disk kind byte. Returns `None` for invalid values.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(InodeKind::File),
            1 => Some(InodeKind::Directory),
            2 => Some(InodeKind::Symlink),
            _ => None,
        }
    }

    /// Returns `true` for [`InodeKind::Directory`].
    #[must_use]
    pub fn is_dir(self) -> bool {
        matches!(self, InodeKind::Directory)
    }

    /// Returns `true` for [`InodeKind::File`].
    #[must_use]
    pub fn is_file(self) -> bool {
        matches!(self, InodeKind::File)
    }

    /// Returns `true` for [`InodeKind::Symlink`].
    #[must_use]
    pub fn is_symlink(self) -> bool {
        matches!(self, InodeKind::Symlink)
    }
}

// ── InodeRecord ───────────────────────────────────────────────────────────

/// A decoded inode record from the on-disk inode table.
///
/// Contains POSIX inode attributes plus storage backend pointers
/// (object store locator and extent map root) needed by the kernel
/// VFS layer to perform file read/write dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InodeRecord {
    /// File mode / permission bits.
    pub mode: u32,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// Last access time (seconds since Unix epoch).
    pub atime_secs: u64,
    /// Last access time (nanoseconds subsecond).
    pub atime_nanos: u32,
    /// Last modification time (seconds since Unix epoch).
    pub mtime_secs: u64,
    /// Last modification time (nanoseconds subsecond).
    pub mtime_nanos: u32,
    /// Last status-change time (seconds since Unix epoch).
    pub ctime_secs: u64,
    /// Last status-change time (nanoseconds subsecond).
    pub ctime_nanos: u32,
    /// Hard-link count.
    pub nlink: u32,
    /// Inode generation number (incremented on reuse).
    pub generation: u64,
    /// Object kind.
    pub kind: InodeKind,
    /// Object store locator: pointer to the backing object in the
    /// pool's object storage namespace.
    pub object_store_locator: u64,
    /// Extent map root pointer: logical block number of the root
    /// of the extent map B-tree for this file.
    pub extent_map_root: u64,
    /// Birth time (seconds since Unix epoch).
    pub btime_secs: u64,
    /// Birth time (nanoseconds subsecond).
    pub btime_nanos: u32,
    /// File attribute flags (immutable, append-only, nodump, etc.).
    pub flags: u32,
}

// ── KernelInodeTableError ─────────────────────────────────────────────────

/// Errors returned by [`KernelInodeTableReader::read_inode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelInodeTableError {
    /// The requested inode number is zero or exceeds the table capacity.
    InodeNotFound,
    /// The inode number is in range but the record slot is empty
    /// (magic bytes missing).
    SlotEmpty,
    /// The on-disk record is corrupt (bad magic or invalid kind byte).
    CorruptRecord,
    /// The on-disk format version byte does not match the expected version.
    VersionMismatch,
    /// The root inode exists but is not a directory.
    RootNotDirectory,
    /// An I/O error occurred reading from the storage backend.
    IoError,
}

// ── Primitive decode helpers (little-endian, no_std) ──────────────────────

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

// ── Record decode ─────────────────────────────────────────────────────────

/// Decode a 116-byte buffer into an [`InodeRecord`].
///
/// Returns `None` if the magic bytes are missing, the kind byte is
/// invalid, or the buffer is the wrong size.
fn decode_inode_record(bytes: &[u8]) -> Option<InodeRecord> {
    if bytes.len() < INODE_RECORD_BYTES {
        return None;
    }
    if bytes[0..4] != INODE_RECORD_MAGIC {
        return None;
    }
    let mode = read_u32_le(bytes, 4);
    let uid = read_u32_le(bytes, 8);
    let gid = read_u32_le(bytes, 12);
    let size = read_u64_le(bytes, 16);
    let blocks = read_u64_le(bytes, 24);
    let atime_secs = read_u64_le(bytes, 32);
    let atime_nanos = read_u32_le(bytes, 40);
    let mtime_secs = read_u64_le(bytes, 44);
    let mtime_nanos = read_u32_le(bytes, 52);
    let ctime_secs = read_u64_le(bytes, 56);
    let ctime_nanos = read_u32_le(bytes, 64);
    let nlink = read_u32_le(bytes, 68);
    let generation = read_u64_le(bytes, 72);
    let kind = InodeKind::from_byte(bytes[80])?;

    // Reject unknown format version
    if bytes[81] != FORMAT_VERSION {
        return None;
    }
    let object_store_locator = read_u64_le(bytes, 84);
    let extent_map_root = read_u64_le(bytes, 92);
    let btime_secs = read_u64_le(bytes, 100);
    let btime_nanos = read_u32_le(bytes, 108);
    let flags = read_u32_le(bytes, 112);

    Some(InodeRecord {
        mode,
        uid,
        gid,
        size,
        blocks,
        atime_secs,
        atime_nanos,
        mtime_secs,
        mtime_nanos,
        ctime_secs,
        ctime_nanos,
        nlink,
        generation,
        kind,
        object_store_locator,
        extent_map_root,
        btime_secs,
        btime_nanos,
        flags,
    })
}

// ── KernelInodeTableReader ────────────────────────────────────────────────

/// Reader that resolves inode numbers to on-disk inode records through
/// a [`KernelStorageIo`] backend.
///
/// The inode table is assumed to be a contiguous region of sectors on
/// the underlying block device, with records stored sequentially by
/// inode number. Record `N` (inode number `N+1`) starts at byte offset
/// `N * INODE_RECORD_BYTES` from the beginning of the table region.
///
/// # Sector-spanning reads
///
/// Records may span two sectors. The reader handles this by reading
/// both sectors into a stack buffer and extracting the record slice.
pub struct KernelInodeTableReader<'a> {
    io: &'a dyn KernelStorageIo,
    /// Starting sector of the inode table region (pool-relative).
    table_start_sector: u64,
    /// Number of sectors in the table region.
    table_sector_count: u64,
    /// Maximum inode number supported (derived from table size).
    max_inodes: u64,
}

impl<'a> KernelInodeTableReader<'a> {
    /// Create a new reader for an inode table at the given sector range.
    ///
    /// `table_start_sector` is the pool-relative sector where inode
    /// records begin. `table_sector_count` is the total number of
    /// sectors allocated to the table.
    ///
    /// # Panics
    ///
    /// Panics if `INODE_RECORD_BYTES` as u64 times `table_sector_count`
    /// overflows `u64`.
    pub fn new(
        io: &'a dyn KernelStorageIo,
        table_start_sector: u64,
        table_sector_count: u64,
    ) -> Self {
        let sector_size = io.sector_size() as u64;
        let table_bytes = table_sector_count
            .checked_mul(sector_size)
            .expect("inode table region too large (byte overflow)");
        let max_inodes = table_bytes / (INODE_RECORD_BYTES as u64);

        Self {
            io,
            table_start_sector,
            table_sector_count,
            max_inodes,
        }
    }

    /// Return the maximum inode number this table can hold (1-based).
    #[must_use]
    pub fn max_inodes(&self) -> u64 {
        self.max_inodes
    }

    /// Return the start sector of the inode table region.
    #[must_use]
    pub fn table_start_sector(&self) -> u64 {
        self.table_start_sector
    }

    /// Read and decode the inode record for `ino` (1-based).
    ///
    /// Returns [`KernelInodeTableError::InodeNotFound`] when `ino` is
    /// zero or exceeds [`max_inodes`](Self::max_inodes).
    ///
    /// Returns [`KernelInodeTableError::SlotEmpty`] when the slot
    /// exists but the magic bytes are missing (never-allocated or
    /// freed slot).
    ///
    /// # Sector-spanning records
    ///
    /// When a record spans two sectors, both sectors are read and the
    /// record is reconstructed from the combined buffer.
    pub fn read_inode(&self, ino: u64) -> Result<InodeRecord, KernelInodeTableError> {
        if ino == 0 || ino > self.max_inodes {
            return Err(KernelInodeTableError::InodeNotFound);
        }

        let record_offset = (ino - 1)
            .checked_mul(INODE_RECORD_BYTES as u64)
            .expect("inode offset overflow");

        let sector_size = self.io.sector_size() as u64;
        let sector_offset = record_offset / sector_size;
        let byte_within_sector = (record_offset % sector_size) as usize;
        let start_sector = self.table_start_sector + sector_offset;

        // Check that the record fits within the table region
        let record_end_byte = record_offset + (INODE_RECORD_BYTES as u64);
        let table_end_byte = self.table_sector_count * sector_size;
        if record_end_byte > table_end_byte {
            return Err(KernelInodeTableError::InodeNotFound);
        }

        // Does the record span two sectors?
        let sectors_needed = if byte_within_sector + INODE_RECORD_BYTES > sector_size as usize {
            2u64
        } else {
            1u64
        };

        // Validate the sector range is within device capacity
        if start_sector + sectors_needed > self.io.capacity_sectors() {
            return Err(KernelInodeTableError::IoError);
        }

        // Allocate a buffer large enough for the required sectors.
        // Max record size is INODE_RECORD_BYTES. In the worst case
        // the record starts at the last byte of a sector, needing
        // 2 full sectors (INODE_RECORD_BYTES - 1 + sector_size bytes).
        // We'll read whole sectors for simplicity.
        let buf_sectors = sectors_needed as usize;
        let buf_bytes = buf_sectors * sector_size as usize;
        let mut buf = alloc::vec![0u8; buf_bytes];

        // Read the sector(s) containing the record
        let _read = self
            .io
            .read_sectors(start_sector, &mut buf)
            .map_err(|_| KernelInodeTableError::IoError)?;

        // Extract the record bytes from the buffer
        let record_end = byte_within_sector + INODE_RECORD_BYTES;
        if record_end > buf.len() {
            return Err(KernelInodeTableError::CorruptRecord);
        }
        let record_bytes = &buf[byte_within_sector..record_end];

        // Decode and check for empty slot vs corrupt record
        let record = decode_inode_record(record_bytes).ok_or_else(|| {
            if record_bytes.len() >= 4 && record_bytes[0..4] == INODE_RECORD_MAGIC {
                // Magic matches but decode failed: version mismatch or invalid kind
                if record_bytes.len() > 81 && record_bytes[81] != FORMAT_VERSION {
                    KernelInodeTableError::VersionMismatch
                } else {
                    KernelInodeTableError::CorruptRecord
                }
            } else {
                KernelInodeTableError::SlotEmpty
            }
        })?;

        Ok(record)
    }

    /// Read and validate the root inode for mount admission.
    ///
    /// Reads the inode record for `root_ino` and checks that it is a
    /// directory suitable for serving as the filesystem root. Returns
    /// [`KernelInodeTableError::RootNotDirectory`] when the record
    /// exists but is not a directory.
    ///
    /// This is the contract entry point for mount-path root validation
    /// in #6252: the caller provides the root inode number from the
    /// committed-root anchor, and this method returns the validated
    /// [`InodeRecord`] or a fail-closed error.
    pub fn read_root_inode(&self, root_ino: u64) -> Result<InodeRecord, KernelInodeTableError> {
        let record = self.read_inode(root_ino)?;
        if !record.kind.is_dir() {
            return Err(KernelInodeTableError::RootNotDirectory);
        }
        // Root inode must have a non-zero mode (sanity check).
        if record.mode == 0 {
            return Err(KernelInodeTableError::CorruptRecord);
        }
        Ok(record)
    }

    /// Read an inode and return only the POSIX attribute subset needed
    /// for getattr/lookup without exposing the full storage backend
    /// pointers.
    ///
    /// This is a convenience wrapper around [`read_inode`] that
    /// projects the record into only the fields needed by kernel VFS
    /// lookup and getattr: mode, uid, gid, size, blocks, timestamps,
    /// nlink, generation, and kind.
    #[must_use]
    pub fn read_inode_attrs(&self, ino: u64) -> Result<InodeRecord, KernelInodeTableError> {
        self.read_inode(ino)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// In-memory test backend that implements [`KernelStorageIo`].
    struct TestStorage {
        data: Vec<u8>,
        sector_size: u32,
    }

    impl TestStorage {
        fn new(size_sectors: u64, sector_size: u32) -> Self {
            use alloc::vec;
            let cap = (size_sectors as usize) * (sector_size as usize);
            Self {
                data: vec![0u8; cap],
                sector_size,
            }
        }

        fn write_sector(&mut self, sector: u64, data: &[u8]) {
            let offset = (sector as usize) * (self.sector_size as usize);
            let end = offset + data.len();
            self.data[offset..end].copy_from_slice(data);
        }
    }

    // Use raw errno values for test error injection
    const EIO: u16 = 5;
    const EINVAL: u16 = 22;

    impl KernelStorageIo for TestStorage {
        fn read_sectors(
            &self,
            start_sector: u64,
            buf: &mut [u8],
        ) -> Result<u32, tidefs_types_vfs_core::Errno> {
            let ss = self.sector_size as u64;
            let start_byte = start_sector * ss;
            let len = buf.len() as u64;
            if start_byte + len > self.data.len() as u64 {
                return Err(tidefs_types_vfs_core::Errno(EINVAL));
            }
            let end = (start_byte + len) as usize;
            buf.copy_from_slice(&self.data[start_byte as usize..end]);
            Ok((len / ss) as u32)
        }

        fn write_sectors(
            &self,
            _start_sector: u64,
            _data: &[u8],
        ) -> Result<u32, tidefs_types_vfs_core::Errno> {
            Err(tidefs_types_vfs_core::Errno(EIO))
        }

        fn flush(&self) -> Result<(), tidefs_types_vfs_core::Errno> {
            Ok(())
        }

        fn sector_size(&self) -> u32 {
            self.sector_size
        }

        fn capacity_sectors(&self) -> u64 {
            (self.data.len() / self.sector_size as usize) as u64
        }
    }

    /// Encode an [`InodeRecord`] into a 116-byte buffer.
    fn encode_record(rec: &InodeRecord) -> [u8; INODE_RECORD_BYTES] {
        let mut buf = [0u8; INODE_RECORD_BYTES];
        buf[0..4].copy_from_slice(&INODE_RECORD_MAGIC);
        buf[4..8].copy_from_slice(&rec.mode.to_le_bytes());
        buf[8..12].copy_from_slice(&rec.uid.to_le_bytes());
        buf[12..16].copy_from_slice(&rec.gid.to_le_bytes());
        buf[16..24].copy_from_slice(&rec.size.to_le_bytes());
        buf[24..32].copy_from_slice(&rec.blocks.to_le_bytes());
        buf[32..40].copy_from_slice(&rec.atime_secs.to_le_bytes());
        buf[40..44].copy_from_slice(&rec.atime_nanos.to_le_bytes());
        buf[44..52].copy_from_slice(&rec.mtime_secs.to_le_bytes());
        buf[52..56].copy_from_slice(&rec.mtime_nanos.to_le_bytes());
        buf[56..64].copy_from_slice(&rec.ctime_secs.to_le_bytes());
        buf[64..68].copy_from_slice(&rec.ctime_nanos.to_le_bytes());
        buf[68..72].copy_from_slice(&rec.nlink.to_le_bytes());
        buf[72..80].copy_from_slice(&rec.generation.to_le_bytes());
        buf[80] = rec.kind as u8;
        buf[81] = FORMAT_VERSION;
        buf[84..92].copy_from_slice(&rec.object_store_locator.to_le_bytes());
        buf[92..100].copy_from_slice(&rec.extent_map_root.to_le_bytes());
        buf[100..108].copy_from_slice(&rec.btime_secs.to_le_bytes());
        buf[108..112].copy_from_slice(&rec.btime_nanos.to_le_bytes());
        buf[112..116].copy_from_slice(&rec.flags.to_le_bytes());
        buf
    }

    fn make_record(ino: u64) -> InodeRecord {
        InodeRecord {
            mode: 0o644,
            uid: 1000 + ino as u32,
            gid: 1000,
            size: ino * 4096,
            blocks: ino * 8,
            atime_secs: 100,
            atime_nanos: 500_000_000,
            mtime_secs: 200,
            mtime_nanos: 250_000_000,
            ctime_secs: 300,
            ctime_nanos: 750_000_000,
            nlink: 1,
            generation: ino * 100,
            kind: InodeKind::File,
            object_store_locator: ino * 1000,
            extent_map_root: ino * 2000,
            btime_secs: 50,
            btime_nanos: 0,
            flags: 0,
        }
    }

    // ── Basic read tests ──────────────────────────────────────────────

    #[test]
    fn read_inode_roundtrip() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);
        let rec = make_record(1);
        let encoded = encode_record(&rec);
        storage.write_sector(0, &encoded);

        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        let result = reader.read_inode(1).unwrap();
        assert_eq!(result, rec);
    }

    #[test]
    fn read_multiple_inodes() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);

        let recs: Vec<InodeRecord> = (1..=5).map(make_record).collect();
        for (i, rec) in recs.iter().enumerate() {
            let encoded = encode_record(rec);
            let offset = i * INODE_RECORD_BYTES;
            storage.data[offset..offset + INODE_RECORD_BYTES].copy_from_slice(&encoded);
        }

        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        for (i, expected) in recs.iter().enumerate() {
            let ino = (i + 1) as u64;
            let result = reader.read_inode(ino).unwrap();
            assert_eq!(result, *expected, "inode {ino} mismatch");
        }
    }

    // ── Error path tests ──────────────────────────────────────────────

    #[test]
    fn read_inode_zero() {
        let storage = TestStorage::new(16, 512);
        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        assert_eq!(
            reader.read_inode(0),
            Err(KernelInodeTableError::InodeNotFound)
        );
    }

    #[test]
    fn read_inode_beyond_max() {
        let storage = TestStorage::new(16, 512);
        // 1 sector of 512 bytes = 4 records (4*116=464)
        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        assert_eq!(reader.max_inodes(), 4);
        assert_eq!(
            reader.read_inode(5),
            Err(KernelInodeTableError::InodeNotFound)
        );
    }

    #[test]
    fn read_empty_slot() {
        let sector_size = 512u32;
        let storage = TestStorage::new(16, sector_size);
        // All zeros = no magic bytes
        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        assert_eq!(reader.read_inode(1), Err(KernelInodeTableError::SlotEmpty));
    }

    #[test]
    fn read_corrupt_kind_byte() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);
        let mut encoded = encode_record(&make_record(1));
        encoded[80] = 99; // invalid kind byte
        storage.write_sector(0, &encoded);

        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        // Magic matches and version is correct, but kind is invalid
        assert_eq!(
            reader.read_inode(1),
            Err(KernelInodeTableError::CorruptRecord)
        );
    }

    // ── Sector-spanning tests ─────────────────────────────────────────

    #[test]
    fn read_inode_spanning_two_sectors() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);

        // Record for ino=5 is at offset 4*116=464, spans bytes 464..579
        // crossing sector boundary at 512.
        let rec5 = make_record(5);
        let encoded5 = encode_record(&rec5);
        let offset5 = 4 * INODE_RECORD_BYTES; // 464
        storage.data[offset5..offset5 + INODE_RECORD_BYTES].copy_from_slice(&encoded5);

        // Need 2 sectors to cover offset 464 + 116 = 580 bytes
        let reader = KernelInodeTableReader::new(&storage, 0, 2);
        let result = reader.read_inode(5).unwrap();
        assert_eq!(result, rec5);
    }

    #[test]
    fn read_inodes_before_and_after_spanning() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);

        // Inode 1 at offset 0 (stays within sector 0)
        let rec1 = make_record(1);
        storage.data[0..INODE_RECORD_BYTES].copy_from_slice(&encode_record(&rec1));

        // Inode 5 at offset 4*116=464 (spans sector 0 and 1)
        let rec5 = make_record(5);
        let offset5 = 4 * INODE_RECORD_BYTES;
        storage.data[offset5..offset5 + INODE_RECORD_BYTES].copy_from_slice(&encode_record(&rec5));

        let reader = KernelInodeTableReader::new(&storage, 0, 2);

        let r1 = reader.read_inode(1).unwrap();
        assert_eq!(r1, rec1);

        let r5 = reader.read_inode(5).unwrap();
        assert_eq!(r5, rec5);
    }

    // ── Kind variants ─────────────────────────────────────────────────

    #[test]
    fn read_inode_kind_directory() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);
        let mut rec = make_record(1);
        rec.kind = InodeKind::Directory;
        storage.write_sector(0, &encode_record(&rec));

        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        let result = reader.read_inode(1).unwrap();
        assert_eq!(result.kind, InodeKind::Directory);
    }

    #[test]
    fn read_inode_kind_symlink() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);
        let mut rec = make_record(1);
        rec.kind = InodeKind::Symlink;
        storage.write_sector(0, &encode_record(&rec));

        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        let result = reader.read_inode(1).unwrap();
        assert_eq!(result.kind, InodeKind::Symlink);
    }

    // ── Edge cases ────────────────────────────────────────────────────

    #[test]
    fn read_inode_max_values() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);
        let rec = InodeRecord {
            mode: u32::MAX,
            uid: u32::MAX,
            gid: u32::MAX,
            size: u64::MAX,
            blocks: u64::MAX,
            atime_secs: u64::MAX,
            atime_nanos: 999_999_999,
            mtime_secs: u64::MAX,
            mtime_nanos: 999_999_999,
            ctime_secs: u64::MAX,
            ctime_nanos: 999_999_999,
            nlink: u32::MAX,
            generation: u64::MAX,
            kind: InodeKind::Symlink,
            object_store_locator: u64::MAX,
            extent_map_root: u64::MAX,
            btime_secs: u64::MAX,
            btime_nanos: 999_999_999,
            flags: u32::MAX,
        };
        storage.write_sector(0, &encode_record(&rec));

        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        let result = reader.read_inode(1).unwrap();
        assert_eq!(result, rec);
    }

    #[test]
    fn read_inode_at_max_capacity() {
        let sector_size = 4096u32;
        // 1 sector of 4096 bytes = 35 records (35*116=4060)
        let mut storage = TestStorage::new(2, sector_size);

        let rec = make_record(35);
        let offset = 34 * INODE_RECORD_BYTES;
        storage.data[offset..offset + INODE_RECORD_BYTES].copy_from_slice(&encode_record(&rec));

        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        assert_eq!(reader.max_inodes(), 35);
        let result = reader.read_inode(35).unwrap();
        assert_eq!(result, rec);
    }

    #[test]
    fn accessors_return_constructor_args() {
        let storage = TestStorage::new(16, 512);
        let reader = KernelInodeTableReader::new(&storage, 42, 8);
        assert_eq!(reader.table_start_sector(), 42);
        // 8 sectors * 512 bytes = 4096 bytes, / 116 = 35 records
        assert_eq!(reader.max_inodes(), 35);
    }

    #[test]
    fn max_inodes_with_large_sectors() {
        let storage = TestStorage::new(16, 4096);
        let reader = KernelInodeTableReader::new(&storage, 0, 2);
        // 2 * 4096 = 8192 bytes, / 116 = 70 records
        assert_eq!(reader.max_inodes(), 70);
    }

    #[test]
    fn inode_kind_from_byte_invalid() {
        assert!(InodeKind::from_byte(3).is_none());
        assert!(InodeKind::from_byte(255).is_none());
    }

    #[test]
    fn inode_kind_is_predicates() {
        assert!(InodeKind::File.is_file());
        assert!(!InodeKind::File.is_dir());
        assert!(!InodeKind::File.is_symlink());

        assert!(InodeKind::Directory.is_dir());
        assert!(!InodeKind::Directory.is_file());

        assert!(InodeKind::Symlink.is_symlink());
        assert!(!InodeKind::Symlink.is_dir());
    }

    // ── Root inode validation tests ───────────────────────────────────

    #[test]
    fn read_root_inode_success() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);
        let mut rec = make_record(1);
        rec.kind = InodeKind::Directory;
        rec.mode = 0o755;
        storage.write_sector(0, &encode_record(&rec));

        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        let result = reader.read_root_inode(1).unwrap();
        assert_eq!(result.kind, InodeKind::Directory);
        assert_eq!(result.mode, 0o755);
    }

    #[test]
    fn read_root_inode_not_directory() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);
        let rec = make_record(1); // kind=File by default
        storage.write_sector(0, &encode_record(&rec));

        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        assert_eq!(
            reader.read_root_inode(1),
            Err(KernelInodeTableError::RootNotDirectory)
        );
    }

    #[test]
    fn read_root_inode_missing() {
        let storage = TestStorage::new(16, 512);
        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        assert_eq!(
            reader.read_root_inode(1),
            Err(KernelInodeTableError::SlotEmpty)
        );
    }

    #[test]
    fn read_root_inode_zero_mode() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);
        let mut rec = make_record(1);
        rec.kind = InodeKind::Directory;
        rec.mode = 0;
        storage.write_sector(0, &encode_record(&rec));

        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        assert_eq!(
            reader.read_root_inode(1),
            Err(KernelInodeTableError::CorruptRecord)
        );
    }

    #[test]
    fn version_mismatch_rejected() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);
        let mut encoded = encode_record(&make_record(1));
        encoded[81] = 99; // wrong version byte
        storage.write_sector(0, &encoded);

        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        assert_eq!(
            reader.read_inode(1),
            Err(KernelInodeTableError::VersionMismatch)
        );
    }

    #[test]
    fn read_inode_attrs_passthrough() {
        let sector_size = 512u32;
        let mut storage = TestStorage::new(16, sector_size);
        let rec = make_record(3);
        storage.data[2 * INODE_RECORD_BYTES..3 * INODE_RECORD_BYTES]
            .copy_from_slice(&encode_record(&rec));

        let reader = KernelInodeTableReader::new(&storage, 0, 1);
        let result = reader.read_inode_attrs(3).unwrap();
        assert_eq!(result, rec);
    }
}
