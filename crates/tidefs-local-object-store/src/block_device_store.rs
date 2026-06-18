// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Block-device-backed object store.
//!
//! `BlockDeviceStore` stores objects directly on a byte-addressable block
//! device or development regular file using a sequential-write log structure.
//! On open, the object data region is scanned to rebuild the in-memory index.
//! Objects are immutable once written; deletes are logical (index removal
//! only). Space reclamation happens through compaction/rewrite of live objects.
//!
//! This is the production block-device backend for TideFS pools.
//! It provides the object-store/segment allocation backend consumed by
//! `LocalFileSystem` and FUSE when the pool is backed by block devices or
//! hidden regular-file development devices.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::{ObjectKey, Result as StoreResult, StoreError, StoreOptions, StoredObject};

type BlockDataIndex = std::collections::BTreeMap<ObjectKey, (u64, u64)>;
type BlockScanResult = (BlockDataIndex, u64, u64);

// ---------------------------------------------------------------------------
// On-disk format constants
// ---------------------------------------------------------------------------

/// Magic bytes at the start of the block-device object-store region.
const BLOCK_STORE_MAGIC: &[u8; 4] = b"VBFS";

/// Current data-region format version.
const BLOCK_STORE_FORMAT_VERSION: u32 = 1;

/// Size of each pool label copy reserved at fixed byte-media locations.
const BLOCK_STORE_POOL_LABEL_BYTES: u64 = tidefs_types_pool_label_core::POOL_LABEL_SIZE as u64;

/// Pool create/import bootstrap bytes reserved after the primary pool label.
const BLOCK_STORE_BOOTSTRAP_REGION_BYTES: u64 = 8 * 1024;

/// Offset where TideFS object-store records may begin using byte-addressable
/// block devices or explicit regular-file development devices.
const BLOCK_STORE_DATA_REGION_OFFSET: u64 =
    BLOCK_STORE_POOL_LABEL_BYTES + BLOCK_STORE_BOOTSTRAP_REGION_BYTES;

/// Bytes reserved at the end of the backing for the secondary pool label copy.
const BLOCK_STORE_TRAILING_LABEL_BYTES: u64 = BLOCK_STORE_POOL_LABEL_BYTES;

/// The standalone block-store superblock is the first object-store record in
/// the data region, after pool-label and bootstrap bytes.
const BLOCK_STORE_SUPERBLOCK_OFFSET: u64 = BLOCK_STORE_DATA_REGION_OFFSET;

/// Size of the superblock header (before object data).
const BLOCK_STORE_SUPERBLOCK_SIZE: u64 = 4096;

/// Absolute offset of the first append-only object/tombstone record.
const BLOCK_STORE_OBJECT_LOG_OFFSET: u64 =
    BLOCK_STORE_SUPERBLOCK_OFFSET + BLOCK_STORE_SUPERBLOCK_SIZE;

/// Minimum object-log room required for this standalone backend.
const BLOCK_STORE_MIN_OBJECT_LOG_BYTES: u64 = 65536;

/// Minimum device size: front reserved regions + block-store superblock + room
/// for at least one object + trailing pool label copy.
const BLOCK_STORE_MIN_DEVICE_BYTES: u64 = BLOCK_STORE_OBJECT_LOG_OFFSET
    + BLOCK_STORE_MIN_OBJECT_LOG_BYTES
    + BLOCK_STORE_TRAILING_LABEL_BYTES;

/// Alignment for object records (512-byte sector alignment).
const BLOCK_STORE_RECORD_ALIGN: u64 = 512;

// ---------------------------------------------------------------------------
// On-disk record header
// ---------------------------------------------------------------------------

/// Per-object record header written before the payload.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct RecordHeader {
    /// Magic sentinel: 0xBF01_0001
    magic: u32,
    /// Record format version.
    format_version: u16,
    /// Flags (bit 0 = tombstone/deleted).
    flags: u16,
    /// Object key.
    key: [u8; 32],
    /// Payload length in bytes.
    payload_len: u64,
    /// CRC-32C of the payload (0 if not computed).
    payload_crc32c: u32,
    /// Padding to 64 bytes.
    _pad: [u8; 6],
}

// RecordHeader must be exactly 64 bytes.
const RECORD_HEADER_SIZE: u64 = 64;

impl RecordHeader {
    const MAGIC: u32 = 0xBF01_0001;
    const FLAG_TOMBSTONE: u16 = 0x0001;

    fn new(key: ObjectKey, payload_len: u64) -> Self {
        Self {
            magic: Self::MAGIC,
            format_version: 1,
            flags: 0,
            key: key.as_bytes32(),
            payload_len,
            payload_crc32c: 0,
            _pad: [0u8; 6],
        }
    }

    fn encode(&self) -> [u8; RECORD_HEADER_SIZE as usize] {
        let mut buf = [0u8; RECORD_HEADER_SIZE as usize];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.format_version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.flags.to_le_bytes());
        buf[8..40].copy_from_slice(&self.key);
        buf[40..48].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[48..52].copy_from_slice(&self.payload_crc32c.to_le_bytes());
        buf
    }

    fn decode(buf: &[u8; RECORD_HEADER_SIZE as usize]) -> Option<Self> {
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != Self::MAGIC {
            return None;
        }
        let format_version = u16::from_le_bytes([buf[4], buf[5]]);
        let flags = u16::from_le_bytes([buf[6], buf[7]]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&buf[8..40]);
        let payload_len = u64::from_le_bytes([
            buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
        ]);
        let payload_crc32c = u32::from_le_bytes([buf[48], buf[49], buf[50], buf[51]]);
        Some(Self {
            magic,
            format_version,
            flags,
            key,
            payload_len,
            payload_crc32c,
            _pad: [0u8; 6],
        })
    }

    fn is_tombstone(&self) -> bool {
        self.flags & Self::FLAG_TOMBSTONE != 0
    }

    /// Total on-disk size of this record (header + aligned payload).
    fn record_size(&self) -> u64 {
        let data_size = RECORD_HEADER_SIZE + self.payload_len;
        align_up(data_size, BLOCK_STORE_RECORD_ALIGN)
    }
}

fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

// ---------------------------------------------------------------------------
// BlockDeviceStore
// ---------------------------------------------------------------------------

/// A block-device-backed object store.
///
/// Objects are written sequentially to the block device with a 64-byte
/// record header.  On open, the entire data region is scanned to rebuild
/// the in-memory index.  Deletes write a tombstone record.
pub struct BlockDeviceStore {
    /// Path to the block device.
    device_path: PathBuf,
    /// Opened file handle.
    file: File,
    /// Current write offset in the data region.
    write_offset: u64,
    /// Total device capacity in bytes.
    capacity_bytes: u64,
    /// Exclusive upper bound for object-store writes, before the trailing label.
    data_end_offset: u64,
    /// In-memory index: maps ObjectKey to (offset, payload_len).
    index: std::collections::BTreeMap<ObjectKey, (u64, u64)>,
    /// Read-only flag.
    read_only: bool,
    /// Store options.
    #[allow(dead_code)]
    options: StoreOptions,
    /// Object count.
    object_count: u64,
    /// Total bytes stored (payload only).
    total_payload_bytes: u64,
}

impl BlockDeviceStore {
    /// Open a block device for reading and writing, creating the
    /// superblock if the device is empty.
    pub fn open(device_path: impl AsRef<Path>) -> StoreResult<Self> {
        Self::open_with_options(device_path, StoreOptions::default())
    }

    /// Open a block device with explicit store options.
    pub fn open_with_options(
        device_path: impl AsRef<Path>,
        options: StoreOptions,
    ) -> StoreResult<Self> {
        let device_path = device_path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&device_path)
            .map_err(|e| StoreError::Io {
                operation: "block_store_open",
                path: device_path.clone(),
                source: e,
            })?;

        let capacity_bytes = file.seek(SeekFrom::End(0)).map_err(|e| StoreError::Io {
            operation: "block_store_seek_end",
            path: device_path.clone(),
            source: e,
        })?;

        if capacity_bytes < BLOCK_STORE_MIN_DEVICE_BYTES {
            return Err(StoreError::InvalidOptions {
                reason: "block device too small for TideFS block store",
            });
        }

        let data_end_offset = Self::data_end_offset(capacity_bytes)?;

        // Check if the data region has a valid block-store superblock.
        let mut superblock_buf = [0u8; 8];
        file.seek(SeekFrom::Start(BLOCK_STORE_SUPERBLOCK_OFFSET))
            .map_err(|e| StoreError::Io {
                operation: "block_store_seek_start",
                path: device_path.clone(),
                source: e,
            })?;
        file.read_exact(&mut superblock_buf)
            .map_err(|e| StoreError::Io {
                operation: "block_store_read_superblock",
                path: device_path.clone(),
                source: e,
            })?;

        let initialized = &superblock_buf[0..4] == BLOCK_STORE_MAGIC;

        if !initialized {
            // Initialize the superblock.
            Self::initialize_superblock(&mut file, capacity_bytes)?;
        }

        // Read format version from superblock.
        file.seek(SeekFrom::Start(BLOCK_STORE_SUPERBLOCK_OFFSET + 4))
            .map_err(|e| StoreError::Io {
                operation: "block_store_seek_version",
                path: device_path.clone(),
                source: e,
            })?;
        let mut version_buf = [0u8; 4];
        file.read_exact(&mut version_buf)
            .map_err(|e| StoreError::Io {
                operation: "block_store_read_version",
                path: device_path.clone(),
                source: e,
            })?;
        let _format_version = u32::from_le_bytes(version_buf);

        // Read write_offset from superblock.
        file.seek(SeekFrom::Start(BLOCK_STORE_SUPERBLOCK_OFFSET + 8))
            .map_err(|e| StoreError::Io {
                operation: "block_store_seek_offset",
                path: device_path.clone(),
                source: e,
            })?;
        let mut offset_buf = [0u8; 8];
        file.read_exact(&mut offset_buf)
            .map_err(|e| StoreError::Io {
                operation: "block_store_read_offset",
                path: device_path.clone(),
                source: e,
            })?;
        let write_offset = u64::from_le_bytes(offset_buf);
        if !(BLOCK_STORE_OBJECT_LOG_OFFSET..=data_end_offset).contains(&write_offset) {
            return Err(StoreError::InvalidOptions {
                reason: "block device store superblock has invalid write offset",
            });
        }

        // Scan from the object log start to write_offset to rebuild the index.
        let (index, object_count, total_payload_bytes) =
            Self::scan_data_region(&mut file, BLOCK_STORE_OBJECT_LOG_OFFSET, write_offset)?;

        Ok(Self {
            device_path,
            file,
            write_offset,
            capacity_bytes,
            data_end_offset,
            index,
            read_only: false,
            options,
            object_count,
            total_payload_bytes,
        })
    }

    /// Initialize the superblock on a fresh device.
    fn initialize_superblock(file: &mut File, capacity_bytes: u64) -> StoreResult<()> {
        let mut superblock = vec![0u8; BLOCK_STORE_SUPERBLOCK_SIZE as usize];
        superblock[0..4].copy_from_slice(BLOCK_STORE_MAGIC);
        superblock[4..8].copy_from_slice(&BLOCK_STORE_FORMAT_VERSION.to_le_bytes());
        superblock[8..16].copy_from_slice(&BLOCK_STORE_OBJECT_LOG_OFFSET.to_le_bytes());
        superblock[16..24].copy_from_slice(&capacity_bytes.to_le_bytes());

        file.seek(SeekFrom::Start(BLOCK_STORE_SUPERBLOCK_OFFSET))
            .map_err(|e| StoreError::Io {
                operation: "block_store_init_seek",
                path: PathBuf::from("<block-device>"),
                source: e,
            })?;
        file.write_all(&superblock).map_err(|e| StoreError::Io {
            operation: "block_store_init_write",
            path: PathBuf::from("<block-device>"),
            source: e,
        })?;
        file.flush().map_err(|e| StoreError::Io {
            operation: "block_store_init_flush",
            path: PathBuf::from("<block-device>"),
            source: e,
        })?;
        Ok(())
    }

    fn data_end_offset(capacity_bytes: u64) -> StoreResult<u64> {
        capacity_bytes
            .checked_sub(BLOCK_STORE_TRAILING_LABEL_BYTES)
            .filter(|end| *end >= BLOCK_STORE_OBJECT_LOG_OFFSET)
            .ok_or(StoreError::InvalidOptions {
                reason: "block device too small for TideFS block store layout",
            })
    }

    /// Scan the data region from `start_offset` to `end_offset`,
    /// rebuilding the in-memory index.
    fn scan_data_region(
        file: &mut File,
        start_offset: u64,
        end_offset: u64,
    ) -> StoreResult<BlockScanResult> {
        let mut index = std::collections::BTreeMap::new();
        let mut cursor = start_offset;

        file.seek(SeekFrom::Start(cursor))
            .map_err(|e| StoreError::Io {
                operation: "block_store_scan_seek",
                path: PathBuf::from("<block-device>"),
                source: e,
            })?;

        while cursor + RECORD_HEADER_SIZE <= end_offset {
            let mut header_buf = [0u8; RECORD_HEADER_SIZE as usize];
            match file.read_exact(&mut header_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => {
                    return Err(StoreError::Io {
                        operation: "block_store_scan_read_header",
                        path: PathBuf::from("<block-device>"),
                        source: e,
                    });
                }
            }

            let header = match RecordHeader::decode(&header_buf) {
                Some(h) => h,
                None => {
                    // Invalid header — stop scanning (unwritten tail).
                    break;
                }
            };

            cursor += RECORD_HEADER_SIZE;

            if cursor + header.payload_len > end_offset {
                // Truncated record at end of written region.
                break;
            }

            let key = ObjectKey::from_bytes(header.key);

            if header.is_tombstone() {
                index.remove(&key);
            } else {
                index.insert(key, (cursor, header.payload_len));
            }

            cursor = align_up(cursor + header.payload_len, BLOCK_STORE_RECORD_ALIGN);
            if cursor > end_offset {
                break;
            }

            if let Err(e) = file.seek(SeekFrom::Start(cursor)) {
                return Err(StoreError::Io {
                    operation: "block_store_scan_seek_next",
                    path: PathBuf::from("<block-device>"),
                    source: e,
                });
            }
        }

        let object_count = index.len() as u64;
        let total_payload_bytes = index.values().map(|(_, payload_len)| *payload_len).sum();

        Ok((index, object_count, total_payload_bytes))
    }

    /// Store an object on the block device.
    pub fn put(&mut self, key: ObjectKey, payload: &[u8]) -> StoreResult<StoredObject> {
        if self.read_only {
            return Err(StoreError::InvalidOptions {
                reason: "block device store is read-only",
            });
        }

        let header = RecordHeader::new(key, payload.len() as u64);
        let record_size = header.record_size();

        let next_offset = self
            .write_offset
            .checked_add(record_size)
            .ok_or(StoreError::NoSpace)?;

        if next_offset > self.data_end_offset {
            return Err(StoreError::NoSpace);
        }

        let offset = self.write_offset;

        // Write header.
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| StoreError::Io {
                operation: "block_store_put_seek",
                path: self.device_path.clone(),
                source: e,
            })?;
        self.file
            .write_all(&header.encode())
            .map_err(|e| StoreError::Io {
                operation: "block_store_put_header",
                path: self.device_path.clone(),
                source: e,
            })?;

        // Write payload.
        self.file.write_all(payload).map_err(|e| StoreError::Io {
            operation: "block_store_put_payload",
            path: self.device_path.clone(),
            source: e,
        })?;

        // Update write_offset.
        self.write_offset = next_offset;

        // Update superblock with new write_offset.
        self.file
            .seek(SeekFrom::Start(BLOCK_STORE_SUPERBLOCK_OFFSET + 8))
            .map_err(|e| StoreError::Io {
                operation: "block_store_put_update_offset_seek",
                path: self.device_path.clone(),
                source: e,
            })?;
        self.file
            .write_all(&self.write_offset.to_le_bytes())
            .map_err(|e| StoreError::Io {
                operation: "block_store_put_update_offset",
                path: self.device_path.clone(),
                source: e,
            })?;

        // Update in-memory live-object accounting.
        let payload_len = payload.len() as u64;
        if let Some((_, old_len)) = self
            .index
            .insert(key, (offset + RECORD_HEADER_SIZE, payload_len))
        {
            self.total_payload_bytes = self
                .total_payload_bytes
                .saturating_sub(old_len)
                .saturating_add(payload_len);
        } else {
            self.object_count += 1;
            self.total_payload_bytes = self.total_payload_bytes.saturating_add(payload_len);
        }

        Ok(StoredObject {
            key,
            sequence: offset,
            len: payload.len() as u64,
            checksum: crate::IntegrityDigest64::default(),
        })
    }

    /// Retrieve an object from the block device.
    pub fn get(&self, key: ObjectKey) -> StoreResult<Option<Vec<u8>>> {
        let (offset, length) = match self.index.get(&key) {
            Some(&loc) => loc,
            None => return Ok(None),
        };

        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.device_path)
            .map_err(|e| StoreError::Io {
                operation: "block_store_get_open",
                path: self.device_path.clone(),
                source: e,
            })?;

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| StoreError::Io {
                operation: "block_store_get_seek",
                path: self.device_path.clone(),
                source: e,
            })?;

        let mut payload = vec![0u8; length as usize];
        file.read_exact(&mut payload).map_err(|e| StoreError::Io {
            operation: "block_store_get_read",
            path: self.device_path.clone(),
            source: e,
        })?;

        Ok(Some(payload))
    }

    /// Delete an object by writing a tombstone record.
    pub fn delete(&mut self, key: ObjectKey) -> StoreResult<bool> {
        if self.read_only {
            return Err(StoreError::InvalidOptions {
                reason: "block device store is read-only",
            });
        }

        let old_payload_len = match self.index.get(&key) {
            Some((_, payload_len)) => *payload_len,
            None => return Ok(false),
        };

        {
            let mut header = RecordHeader::new(key, 0);
            header.flags |= RecordHeader::FLAG_TOMBSTONE;
            let record_size = header.record_size();
            let next_offset = self
                .write_offset
                .checked_add(record_size)
                .ok_or(StoreError::NoSpace)?;
            if next_offset > self.data_end_offset {
                return Err(StoreError::NoSpace);
            }

            let offset = self.write_offset;
            self.file
                .seek(SeekFrom::Start(offset))
                .map_err(|e| StoreError::Io {
                    operation: "block_store_delete_seek",
                    path: self.device_path.clone(),
                    source: e,
                })?;
            self.file
                .write_all(&header.encode())
                .map_err(|e| StoreError::Io {
                    operation: "block_store_delete_header",
                    path: self.device_path.clone(),
                    source: e,
                })?;

            self.write_offset = next_offset;
            self.index.remove(&key);
            self.object_count = self.object_count.saturating_sub(1);
            self.total_payload_bytes = self.total_payload_bytes.saturating_sub(old_payload_len);

            // Update superblock offset.
            self.file
                .seek(SeekFrom::Start(BLOCK_STORE_SUPERBLOCK_OFFSET + 8))
                .map_err(|e| StoreError::Io {
                    operation: "block_store_delete_update_seek",
                    path: self.device_path.clone(),
                    source: e,
                })?;
            self.file
                .write_all(&self.write_offset.to_le_bytes())
                .map_err(|e| StoreError::Io {
                    operation: "block_store_delete_update",
                    path: self.device_path.clone(),
                    source: e,
                })?;
        }

        Ok(true)
    }

    /// Flush all pending writes to durable storage.
    pub fn sync_all(&mut self) -> StoreResult<()> {
        self.file.flush().map_err(|e| StoreError::Io {
            operation: "block_store_sync",
            path: self.device_path.clone(),
            source: e,
        })
    }

    /// Return the device path.
    pub fn device_path(&self) -> &Path {
        &self.device_path
    }

    /// Return the capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    /// Return the number of live objects.
    pub fn object_count(&self) -> u64 {
        self.object_count
    }

    /// Return the total payload bytes stored.
    pub fn total_payload_bytes(&self) -> u64 {
        self.total_payload_bytes
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::TempDir;

    fn temp_device(dir: &TempDir, name: &str, size: u64) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = File::create(&path).unwrap();
        f.set_len(size).unwrap();
        f.flush().unwrap();
        path
    }

    fn write_bytes(path: &Path, offset: u64, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(bytes).unwrap();
        file.flush().unwrap();
    }

    fn write_region(path: &Path, offset: u64, len: usize, byte: u8) {
        write_bytes(path, offset, &vec![byte; len]);
    }

    fn read_region(path: &Path, offset: u64, len: usize) -> Vec<u8> {
        let mut file = OpenOptions::new().read(true).open(path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut buf = vec![0u8; len];
        file.read_exact(&mut buf).unwrap();
        buf
    }

    #[test]
    fn open_initializes_superblock() {
        let dir = tempfile::tempdir().unwrap();
        let dev = temp_device(&dir, "dev0", BLOCK_STORE_MIN_DEVICE_BYTES);
        let store = BlockDeviceStore::open(&dev).unwrap();
        assert_eq!(store.capacity_bytes, BLOCK_STORE_MIN_DEVICE_BYTES);
        assert_eq!(store.write_offset, BLOCK_STORE_OBJECT_LOG_OFFSET);
        assert_eq!(
            store.data_end_offset,
            BLOCK_STORE_MIN_DEVICE_BYTES - BLOCK_STORE_TRAILING_LABEL_BYTES
        );
        assert_eq!(store.object_count, 0);
    }

    #[test]
    fn put_and_get_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let dev = temp_device(&dir, "dev0", BLOCK_STORE_MIN_DEVICE_BYTES);
        let mut store = BlockDeviceStore::open(&dev).unwrap();

        let key = ObjectKey::from_name(b"test-object");
        let payload = b"Hello, TideFS block store!";
        let stored = store.put(key, payload).unwrap();
        assert_eq!(stored.key, key);

        let retrieved = store.get(key).unwrap().expect("object should exist");
        assert_eq!(retrieved, payload);
    }

    #[test]
    fn delete_removes_object() {
        let dir = tempfile::tempdir().unwrap();
        let dev = temp_device(&dir, "dev0", BLOCK_STORE_MIN_DEVICE_BYTES);
        let mut store = BlockDeviceStore::open(&dev).unwrap();

        let key = ObjectKey::from_name(b"delete-me");
        store.put(key, b"payload").unwrap();
        assert!(store.get(key).unwrap().is_some());

        let existed = store.delete(key).unwrap();
        assert!(existed);
        assert!(store.get(key).unwrap().is_none());
    }

    #[test]
    fn survival_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let dev = temp_device(&dir, "dev0", BLOCK_STORE_MIN_DEVICE_BYTES);

        let key = ObjectKey::from_name(b"persistent");
        let payload = b"data that survives reopen";

        {
            let mut store = BlockDeviceStore::open(&dev).unwrap();
            store.put(key, payload).unwrap();
            store.sync_all().unwrap();
        }

        {
            let store = BlockDeviceStore::open(&dev).unwrap();
            let retrieved = store.get(key).unwrap().expect("should survive reopen");
            assert_eq!(retrieved, payload);
        }
    }

    #[test]
    fn reserved_pool_regions_survive_open_put_sync_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let dev_size = BLOCK_STORE_MIN_DEVICE_BYTES + 128 * 1024;
        let dev = temp_device(&dir, "dev0", dev_size);
        let tail_offset = dev_size - BLOCK_STORE_TRAILING_LABEL_BYTES;

        write_region(&dev, 0, BLOCK_STORE_SUPERBLOCK_OFFSET as usize, 0xA5);
        write_bytes(&dev, 0, BLOCK_STORE_MAGIC);
        write_region(
            &dev,
            tail_offset,
            BLOCK_STORE_TRAILING_LABEL_BYTES as usize,
            0x5A,
        );
        let front_before = read_region(&dev, 0, BLOCK_STORE_SUPERBLOCK_OFFSET as usize);
        let tail_before = read_region(&dev, tail_offset, BLOCK_STORE_TRAILING_LABEL_BYTES as usize);

        let key = ObjectKey::from_name(b"reserved-region-payload");
        let payload = vec![0xC3; 16 * 1024];
        {
            let mut store = BlockDeviceStore::open(&dev).unwrap();
            store.put(key, &payload).unwrap();
            store.sync_all().unwrap();
        }

        {
            let store = BlockDeviceStore::open(&dev).unwrap();
            assert_eq!(
                store
                    .get(key)
                    .unwrap()
                    .expect("payload should survive reopen"),
                payload
            );
        }

        assert_eq!(
            read_region(&dev, 0, BLOCK_STORE_SUPERBLOCK_OFFSET as usize),
            front_before
        );
        assert_eq!(
            read_region(&dev, tail_offset, BLOCK_STORE_TRAILING_LABEL_BYTES as usize),
            tail_before
        );
    }

    #[test]
    fn put_refuses_to_enter_trailing_label_region() {
        let dir = tempfile::tempdir().unwrap();
        let dev = temp_device(&dir, "dev0", BLOCK_STORE_MIN_DEVICE_BYTES);
        let tail_offset = BLOCK_STORE_MIN_DEVICE_BYTES - BLOCK_STORE_TRAILING_LABEL_BYTES;
        write_region(
            &dev,
            tail_offset,
            BLOCK_STORE_TRAILING_LABEL_BYTES as usize,
            0xD4,
        );
        let tail_before = read_region(&dev, tail_offset, BLOCK_STORE_TRAILING_LABEL_BYTES as usize);

        let mut store = BlockDeviceStore::open(&dev).unwrap();
        let available = (store.data_end_offset - store.write_offset) as usize;
        let payload = vec![0xEE; available];
        let result = store.put(ObjectKey::from_name(b"too-large-for-data-region"), &payload);
        assert!(matches!(result, Err(StoreError::NoSpace)));

        assert_eq!(
            read_region(&dev, tail_offset, BLOCK_STORE_TRAILING_LABEL_BYTES as usize),
            tail_before
        );
    }

    #[test]
    fn delete_then_put_survives_reopen_after_tombstone_alignment() {
        let dir = tempfile::tempdir().unwrap();
        let dev = temp_device(&dir, "dev0", BLOCK_STORE_MIN_DEVICE_BYTES);
        let deleted = ObjectKey::from_name(b"deleted-before-next-put");
        let survivor = ObjectKey::from_name(b"survives-after-tombstone");
        let survivor_payload = b"record after aligned tombstone";

        {
            let mut store = BlockDeviceStore::open(&dev).unwrap();
            store.put(deleted, b"will be tombstoned").unwrap();
            assert!(store.delete(deleted).unwrap());
            store.put(survivor, survivor_payload).unwrap();
            store.sync_all().unwrap();
        }

        {
            let store = BlockDeviceStore::open(&dev).unwrap();
            assert!(store.get(deleted).unwrap().is_none());
            assert_eq!(
                store
                    .get(survivor)
                    .unwrap()
                    .expect("post-tombstone record should survive reopen"),
                survivor_payload
            );
            assert_eq!(store.object_count(), 1);
            assert_eq!(store.total_payload_bytes(), survivor_payload.len() as u64);
        }
    }

    #[test]
    fn multiple_objects() {
        let dir = tempfile::tempdir().unwrap();
        let dev = temp_device(&dir, "dev0", BLOCK_STORE_MIN_DEVICE_BYTES + 1024 * 1024);
        let mut store = BlockDeviceStore::open(&dev).unwrap();

        for i in 0..10 {
            let key = ObjectKey::from_name(format!("obj-{i}").as_bytes());
            let payload = format!("payload-{i}").into_bytes();
            store.put(key, &payload).unwrap();
        }

        assert_eq!(store.object_count(), 10);

        for i in 0..10 {
            let key = ObjectKey::from_name(format!("obj-{i}").as_bytes());
            let retrieved = store.get(key).unwrap().expect("should exist");
            assert_eq!(retrieved, format!("payload-{i}").as_bytes());
        }
    }

    #[test]
    fn reopen_rebuilds_index() {
        let dir = tempfile::tempdir().unwrap();
        let dev = temp_device(&dir, "dev0", BLOCK_STORE_MIN_DEVICE_BYTES + 1024 * 1024);

        {
            let mut store = BlockDeviceStore::open(&dev).unwrap();
            for i in 0..5 {
                let key = ObjectKey::from_name(format!("idx-{i}").as_bytes());
                store.put(key, format!("val-{i}").as_bytes()).unwrap();
            }
            store.sync_all().unwrap();
        }

        {
            let store = BlockDeviceStore::open(&dev).unwrap();
            assert_eq!(store.object_count(), 5);
            for i in 0..5 {
                let key = ObjectKey::from_name(format!("idx-{i}").as_bytes());
                assert!(store.get(key).unwrap().is_some());
            }
        }
    }

    #[test]
    fn device_too_small_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let dev = temp_device(&dir, "tiny", 1024);
        let result = BlockDeviceStore::open(&dev);
        assert!(result.is_err());
    }

    #[test]
    fn record_header_encode_decode_roundtrip() {
        let key = ObjectKey::from_name(b"header-test");
        let header = RecordHeader::new(key, 42);
        let encoded = header.encode();
        let decoded = RecordHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.key, header.key);
        assert_eq!(decoded.payload_len, 42);
        assert!(!decoded.is_tombstone());
    }

    #[test]
    fn record_header_tombstone_flag() {
        let key = ObjectKey::from_name(b"tombstone-test");
        let mut header = RecordHeader::new(key, 0);
        header.flags |= RecordHeader::FLAG_TOMBSTONE;
        let encoded = header.encode();
        let decoded = RecordHeader::decode(&encoded).unwrap();
        assert!(decoded.is_tombstone());
    }

    #[test]
    fn align_up_correct() {
        assert_eq!(align_up(0, 512), 0);
        assert_eq!(align_up(1, 512), 512);
        assert_eq!(align_up(512, 512), 512);
        assert_eq!(align_up(513, 512), 1024);
        assert_eq!(align_up(1024, 512), 1024);
    }
}
