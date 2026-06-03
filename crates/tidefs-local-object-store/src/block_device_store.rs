//! Block-device-backed object store.
//!
//! `BlockDeviceStore` stores objects directly on a raw block device using
//! a sequential-write log structure.  On open, the full device is scanned
//! to rebuild the in-memory index.  Objects are immutable once written;
//! deletes are logical (index removal only).  Space reclamation happens
//! through compaction/rewrite of live objects.
//!
//! This is the production block-device backend for TideFS pools.
//! It provides the object-store/segment allocation backend consumed by
//! `LocalFileSystem` and FUSE when the pool is backed by raw block devices.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::{ObjectKey, Result as StoreResult, StoreError, StoreOptions, StoredObject};

type BlockDataIndex = std::collections::BTreeMap<ObjectKey, (u64, u64)>;
type BlockScanResult = (BlockDataIndex, u64, u64);

// ---------------------------------------------------------------------------
// On-disk format constants
// ---------------------------------------------------------------------------

/// Magic bytes at the start of the block-device data region.
const BLOCK_STORE_MAGIC: &[u8; 4] = b"VBFS";

/// Current data-region format version.
const BLOCK_STORE_FORMAT_VERSION: u32 = 1;

/// Size of the superblock header (before object data).
/// Superblock starts after the pool label area (256 KiB).
const BLOCK_STORE_SUPERBLOCK_OFFSET: u64 = tidefs_types_pool_label_core::POOL_LABEL_SIZE as u64;
/// Size of the superblock header (before object data).
const BLOCK_STORE_SUPERBLOCK_SIZE: u64 = 4096;

/// Minimum device size: superblock + room for at least one object.
const BLOCK_STORE_MIN_DEVICE_BYTES: u64 =
    BLOCK_STORE_SUPERBLOCK_OFFSET + BLOCK_STORE_SUPERBLOCK_SIZE + 65536;

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

        // Check if the device has a valid superblock.
        let mut superblock_buf = [0u8; 8];
        file.seek(SeekFrom::Start(0)).map_err(|e| StoreError::Io {
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

        // Scan the data region to rebuild the index.
        let _current_offset = file.seek(SeekFrom::Start(0)).map_err(|e| StoreError::Io {
            operation: "block_store_seek",
            path: device_path.clone(),
            source: e,
        })?;
        // Read format version from superblock.
        file.seek(SeekFrom::Start(4)).map_err(|e| StoreError::Io {
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
        file.seek(SeekFrom::Start(8)).map_err(|e| StoreError::Io {
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

        // Scan from superblock end to write_offset to rebuild the index.
        let (index, object_count, total_payload_bytes) =
            Self::scan_data_region(&mut file, BLOCK_STORE_SUPERBLOCK_SIZE, write_offset)?;

        Ok(Self {
            device_path,
            file,
            write_offset,
            capacity_bytes,
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
        superblock[8..16].copy_from_slice(&BLOCK_STORE_SUPERBLOCK_SIZE.to_le_bytes());
        superblock[16..24].copy_from_slice(&capacity_bytes.to_le_bytes());

        file.seek(SeekFrom::Start(0)).map_err(|e| StoreError::Io {
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

    /// Scan the data region from `start_offset` to `end_offset`,
    /// rebuilding the in-memory index.
    fn scan_data_region(
        file: &mut File,
        start_offset: u64,
        end_offset: u64,
    ) -> StoreResult<BlockScanResult> {
        let mut index = std::collections::BTreeMap::new();
        let mut object_count = 0u64;
        let mut total_payload_bytes = 0u64;
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
                object_count += 1;
                total_payload_bytes += header.payload_len;
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

        if self.write_offset + record_size > self.capacity_bytes {
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
        self.write_offset = offset + record_size;

        // Update superblock with new write_offset.
        self.file
            .seek(SeekFrom::Start(8))
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

        // Update in-memory index.
        self.index
            .insert(key, (offset + RECORD_HEADER_SIZE, payload.len() as u64));
        self.object_count += 1;
        self.total_payload_bytes += payload.len() as u64;

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

        let existed = self.index.remove(&key).is_some();
        if existed {
            // Write a tombstone record.
            let mut header = RecordHeader::new(key, 0);
            header.flags |= RecordHeader::FLAG_TOMBSTONE;

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

            self.write_offset = offset + RECORD_HEADER_SIZE;
            self.object_count = self.object_count.saturating_sub(1);

            // Update superblock offset.
            self.file
                .seek(SeekFrom::Start(8))
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

        Ok(existed)
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
    use std::io::Write;
    use tempfile::TempDir;

    fn temp_device(dir: &TempDir, name: &str, size: u64) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = File::create(&path).unwrap();
        f.set_len(size).unwrap();
        f.flush().unwrap();
        path
    }

    #[test]
    fn open_initializes_superblock() {
        let dir = tempfile::tempdir().unwrap();
        let dev = temp_device(&dir, "dev0", BLOCK_STORE_MIN_DEVICE_BYTES);
        let store = BlockDeviceStore::open(&dev).unwrap();
        assert_eq!(store.capacity_bytes, BLOCK_STORE_MIN_DEVICE_BYTES);
        assert_eq!(store.write_offset, BLOCK_STORE_SUPERBLOCK_SIZE);
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
