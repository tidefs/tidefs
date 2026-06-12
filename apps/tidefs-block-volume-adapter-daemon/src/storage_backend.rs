use std::{collections::BTreeSet, fmt};

use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeCompletionClass, BlockVolumeFileImage, BlockVolumeFileImageError,
    BlockVolumeGeometryRecord,
};

/// Result of a backend read operation.
#[derive(Debug)]
pub struct BackendReadResult {
    pub completion_class: BlockVolumeCompletionClass,
    pub payload: Option<Vec<u8>>,
}

/// Result of a backend write operation.
#[derive(Debug)]
pub struct BackendWriteResult {
    pub completion_class: BlockVolumeCompletionClass,
}

/// Errors that a block-volume storage backend can return.
#[derive(Debug)]
#[allow(dead_code)]
pub enum BackendError {
    Io(std::io::Error),
    OutOfBounds,
    MisalignedRange,
    BackingStoreUnavailable,
    PayloadTooShort,
    NoSpace,
    Other(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::OutOfBounds => write!(f, "out of bounds"),
            Self::MisalignedRange => write!(f, "misaligned range"),
            Self::BackingStoreUnavailable => write!(f, "backing store unavailable"),
            Self::PayloadTooShort => write!(f, "payload too short"),
            Self::NoSpace => write!(f, "no space left on device"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<std::io::Error> for BackendError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Abstraction over a block-volume storage backend.
///
/// The backend translates block-number ranges into reads and writes against
/// the concrete storage layer (file image, object store, or future backends).
pub trait BlockVolumeStorageBackend {
    /// Read one or more blocks starting at `start_block`.
    fn read_blocks(
        &self,
        start_block: usize,
        block_count: usize,
        block_size_bytes: usize,
    ) -> Result<BackendReadResult, BackendError>;

    /// Write `payload` to contiguous blocks starting at `start_block`.
    fn write_blocks(
        &mut self,
        start_block: usize,
        payload: &[u8],
        block_size_bytes: usize,
    ) -> Result<BackendWriteResult, BackendError>;

    /// Flush all pending writes to durable storage.
    fn flush(&mut self) -> Result<(), BackendError>;

    /// Discard a range of blocks (may be a no-op for some backends).
    fn discard_blocks(
        &mut self,
        start_block: usize,
        block_count: usize,
        block_size_bytes: usize,
    ) -> Result<(), BackendError>;

    /// Zero a range of blocks.
    fn write_zeroes(
        &mut self,
        start_block: usize,
        block_count: usize,
        block_size_bytes: usize,
    ) -> Result<(), BackendError>;

    /// Return the block volume geometry.
    fn geometry(&self) -> tidefs_block_volume_adapter_core::BlockVolumeGeometryRecord;

    /// Whether this backend is read-only (default: false).
    /// When true, write/flush/discard/write-zeroes are rejected with EROFS.
    fn is_read_only(&self) -> bool {
        false
    }

    /// Resize the backing storage to a new block count.
    ///
    /// After this call succeeds, the caller must issue ublk UPDATE_SIZE to
    /// notify the kernel block layer of the capacity change.
    ///
    /// Default implementation returns `Err(BackendError::Other(...))` —
    /// backends that support online resize must override.
    fn resize_to(&mut self, _new_block_count: usize) -> Result<(), BackendError> {
        Err(BackendError::Other(
            "resize not supported by this backend".into(),
        ))
    }

    /// Return the raw file descriptor for io_uring, if applicable.
    #[allow(dead_code)]
    fn as_raw_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }

    /// Return the txg committed-root pointer from the last barrier flush,
    /// if the backend tracks it (object-store backends).
    ///
    /// Returns `None` for file-image backends or before any flush.
    fn last_committed_root(&self) -> Option<u64> {
        None
    }
}

// ── BlockVolumeFileImage backend ────────────────────────────────────────

impl BlockVolumeStorageBackend for BlockVolumeFileImage {
    fn read_blocks(
        &self,
        start_block: usize,
        block_count: usize,
        _block_size_bytes: usize,
    ) -> Result<BackendReadResult, BackendError> {
        let range = BlockRangeRecord::new(start_block, block_count);
        match self.read_blocks(range) {
            Ok((_plan, payload)) => Ok(BackendReadResult {
                completion_class: BlockVolumeCompletionClass::Completed,
                payload,
            }),
            Err(BlockVolumeFileImageError::Io(e)) => Err(BackendError::Io(e)),
            Err(_) => Err(BackendError::OutOfBounds),
        }
    }

    fn write_blocks(
        &mut self,
        start_block: usize,
        payload: &[u8],
        _block_size_bytes: usize,
    ) -> Result<BackendWriteResult, BackendError> {
        match self.write_blocks(start_block, payload) {
            Ok(plan) => Ok(BackendWriteResult {
                completion_class: plan.completion_class,
            }),
            Err(BlockVolumeFileImageError::Io(e)) => Err(BackendError::Io(e)),
            Err(_) => Err(BackendError::OutOfBounds),
        }
    }

    fn flush(&mut self) -> Result<(), BackendError> {
        self.flush().map_err(|e| match e {
            BlockVolumeFileImageError::Io(io) => BackendError::Io(io),
            _ => BackendError::Other("flush failed".into()),
        })?;
        Ok(())
    }

    fn discard_blocks(
        &mut self,
        start_block: usize,
        block_count: usize,
        _block_size_bytes: usize,
    ) -> Result<(), BackendError> {
        let range = BlockRangeRecord::new(start_block, block_count);
        self.discard_blocks(range).map_err(|e| match e {
            BlockVolumeFileImageError::Io(io) => BackendError::Io(io),
            _ => BackendError::Other("discard failed".into()),
        })?;
        Ok(())
    }

    fn write_zeroes(
        &mut self,
        start_block: usize,
        block_count: usize,
        block_size_bytes: usize,
    ) -> Result<(), BackendError> {
        let _ = block_size_bytes;
        let payload = vec![0u8; block_count * self.geometry.block_size_bytes];
        // Use the concrete write_blocks which takes (start_block, payload) only.
        self.write_blocks(start_block, &payload)
            .map_err(|e| match e {
                BlockVolumeFileImageError::Io(io) => BackendError::Io(io),
                _ => BackendError::Other("write_zeroes failed".into()),
            })?;
        Ok(())
    }

    fn geometry(&self) -> tidefs_block_volume_adapter_core::BlockVolumeGeometryRecord {
        self.geometry
    }

    fn as_raw_fd(&self) -> Option<std::os::fd::RawFd> {
        Some(BlockVolumeFileImage::as_raw_fd(self))
    }

    fn resize_to(&mut self, new_block_count: usize) -> Result<(), BackendError> {
        let new_geometry = BlockVolumeGeometryRecord::new(
            self.geometry.volume_id,
            self.geometry.block_size_bytes,
            new_block_count,
            self.geometry.discard_granularity_blocks,
        );
        self.resize_to(new_geometry)
            .map_err(|e| BackendError::Other(format!("resize file image: {e}")))?;
        Ok(())
    }
}

// ── LocalObjectStore backend ──────────────────────────────────────────

use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreError};

/// A block-volume storage backend backed by a `LocalObjectStore`.
///
/// Each block range is stored as a named object with a key derived
/// from the block offset, e.g. `b:0000000000000042` for block 42.
pub struct BlockVolumeObjectStoreBackend {
    store: LocalObjectStore,
    geometry: tidefs_block_volume_adapter_core::BlockVolumeGeometryRecord,
    written_blocks: BTreeSet<usize>,
    written_index_dirty: bool,
    /// Committed root of the snapshot backing this read-only export,
    /// set when opened via `open_snapshot_read_only`.
    pub snapshot_committed_root: Option<tidefs_commit_group::RootPointer>,
}

impl BlockVolumeObjectStoreBackend {
    const WRITTEN_BLOCK_INDEX_NAME: &'static [u8] = b"__tidefs_block_volume_written_blocks_v1";
    const WRITTEN_BLOCK_INDEX_MAGIC: &'static [u8; 8] = b"VBBI0001";

    /// Open a `LocalObjectStore` at `root` and wrap it as a block backend.
    pub fn open(
        root: impl AsRef<std::path::Path>,
        geometry: tidefs_block_volume_adapter_core::BlockVolumeGeometryRecord,
    ) -> Result<Self, BackendError> {
        let store = LocalObjectStore::open(root)
            .map_err(|e| BackendError::Other(format!("open object store: {e}")))?;
        let (written_blocks, written_index_dirty) =
            Self::load_written_block_index(&store, geometry)?;
        Ok(Self {
            store,
            geometry,
            written_blocks,
            written_index_dirty,
            snapshot_committed_root: None,
        })
    }

    /// Open a read-only `LocalObjectStore` at `root` for snapshot-backed ublk export.
    pub fn open_read_only(
        root: impl AsRef<std::path::Path>,
        geometry: tidefs_block_volume_adapter_core::BlockVolumeGeometryRecord,
    ) -> Result<Self, BackendError> {
        let store = LocalObjectStore::open_read_only_with_options(
            root,
            tidefs_local_object_store::StoreOptions::default(),
        )
        .map_err(|e| BackendError::Other(format!("open object store read-only: {e}")))?
        .ok_or_else(|| BackendError::Other("object store does not exist".into()))?;
        let (written_blocks, _written_index_dirty) =
            Self::load_written_block_index(&store, geometry)?;
        Ok(Self {
            store,
            geometry,
            written_blocks,
            written_index_dirty: false,
            snapshot_committed_root: None,
        })
    }

    /// Open a read-only object store anchored to a named snapshot.
    ///
    /// Validates that `snapshot_name` exists in the store's snapshot catalog
    /// and captures its committed root for traceability. Reads are served from
    /// the store's in-memory index (stable because the store is read-only).
    /// True per-object anchored reading requires per-object commit_group
    /// tracking in the LocalObjectStore index (future work).
    pub fn open_snapshot_read_only(
        root: impl AsRef<std::path::Path>,
        geometry: tidefs_block_volume_adapter_core::BlockVolumeGeometryRecord,
        snapshot_name: &str,
    ) -> Result<Self, BackendError> {
        let store = LocalObjectStore::open_read_only_with_options(
            root.as_ref(),
            tidefs_local_object_store::StoreOptions::default(),
        )
        .map_err(|e| BackendError::Other(format!("open object store read-only: {e}")))?
        .ok_or_else(|| BackendError::Other("object store does not exist".into()))?;

        // Validate snapshot exists and capture its committed root
        let snapshots = store.list_snapshots("default");
        let snapshot = snapshots
            .iter()
            .find(|s| s.name == snapshot_name)
            .ok_or_else(|| {
                BackendError::Other(format!(
                    "snapshot '{}' not found in store catalog ({} snapshots available)",
                    snapshot_name,
                    snapshots.len()
                ))
            })?;

        let committed_root = snapshot.committed_root;
        let (written_blocks, _written_index_dirty) =
            Self::load_written_block_index(&store, geometry)?;
        Ok(Self {
            store,
            geometry,
            written_blocks,
            written_index_dirty: false,
            snapshot_committed_root: Some(committed_root),
        })
    }

    /// Return the block key name for a given block number.
    fn block_key(block: usize) -> [u8; 18] {
        let mut key = [0u8; 18];
        key[0] = b'b';
        key[1] = b':';
        // 16 hex digits for the block number
        let hex = format!("{block:016x}");
        key[2..].copy_from_slice(hex.as_bytes());
        key
    }

    fn load_written_block_index(
        store: &LocalObjectStore,
        geometry: tidefs_block_volume_adapter_core::BlockVolumeGeometryRecord,
    ) -> Result<(BTreeSet<usize>, bool), BackendError> {
        match store
            .get_named(Self::WRITTEN_BLOCK_INDEX_NAME)
            .map_err(|e| BackendError::Other(format!("read block-volume written index: {e}")))?
        {
            Some(payload) => {
                Self::decode_written_block_index(&payload, geometry).map(|blocks| (blocks, false))
            }
            None => {
                let block_payloads = Self::scan_block_payload_keys(store, geometry);
                if !block_payloads.is_empty() {
                    return Err(BackendError::Other(format!(
                        "block-volume object store is missing current written index but contains {} block payload object(s); refusing pre-index block data",
                        block_payloads.len()
                    )));
                }
                Ok((BTreeSet::new(), !store.is_read_only()))
            }
        }
    }

    fn scan_block_payload_keys(
        store: &LocalObjectStore,
        geometry: tidefs_block_volume_adapter_core::BlockVolumeGeometryRecord,
    ) -> BTreeSet<usize> {
        let live_keys: BTreeSet<ObjectKey> = store.list_keys().into_iter().collect();
        let mut written_blocks = BTreeSet::new();
        for block in 0..geometry.block_count {
            if live_keys.contains(&ObjectKey::from_name(Self::block_key(block))) {
                written_blocks.insert(block);
            }
        }
        written_blocks
    }

    fn decode_written_block_index(
        payload: &[u8],
        geometry: tidefs_block_volume_adapter_core::BlockVolumeGeometryRecord,
    ) -> Result<BTreeSet<usize>, BackendError> {
        let header_len = Self::WRITTEN_BLOCK_INDEX_MAGIC.len() + 8 + 8 + 8;
        if payload.len() < header_len {
            return Err(BackendError::Other(
                "block-volume written index is truncated".into(),
            ));
        }
        if &payload[..Self::WRITTEN_BLOCK_INDEX_MAGIC.len()] != Self::WRITTEN_BLOCK_INDEX_MAGIC {
            return Err(BackendError::Other(
                "block-volume written index has bad magic".into(),
            ));
        }

        let mut cursor = Self::WRITTEN_BLOCK_INDEX_MAGIC.len();
        let stored_block_size = read_le_u64(payload, &mut cursor)?;
        let stored_block_count = read_le_u64(payload, &mut cursor)?;
        let entry_count = read_le_u64(payload, &mut cursor)? as usize;
        let expected_len = header_len
            .checked_add(entry_count.checked_mul(8).ok_or_else(|| {
                BackendError::Other("block-volume written index entry count overflows".into())
            })?)
            .ok_or_else(|| {
                BackendError::Other("block-volume written index length overflows".into())
            })?;
        if payload.len() != expected_len {
            return Err(BackendError::Other(
                "block-volume written index length does not match entry count".into(),
            ));
        }
        if stored_block_size != geometry.block_size_bytes as u64 {
            return Err(BackendError::Other(format!(
                "block-volume written index block size mismatch: stored {stored_block_size}, geometry {}",
                geometry.block_size_bytes
            )));
        }
        if stored_block_count != geometry.block_count as u64 {
            return Err(BackendError::Other(format!(
                "block-volume written index block count mismatch: stored {stored_block_count}, geometry {}",
                geometry.block_count
            )));
        }

        let mut written_blocks = BTreeSet::new();
        for _ in 0..entry_count {
            let block = read_le_u64(payload, &mut cursor)?;
            if block >= geometry.block_count as u64 {
                return Err(BackendError::Other(format!(
                    "block-volume written index contains out-of-range block {block}"
                )));
            }
            let block = usize::try_from(block).map_err(|_| {
                BackendError::Other("block-volume written index block does not fit usize".into())
            })?;
            written_blocks.insert(block);
        }
        Ok(written_blocks)
    }

    fn encode_written_block_index(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(
            Self::WRITTEN_BLOCK_INDEX_MAGIC.len() + 24 + self.written_blocks.len() * 8,
        );
        payload.extend_from_slice(Self::WRITTEN_BLOCK_INDEX_MAGIC);
        payload.extend_from_slice(&(self.geometry.block_size_bytes as u64).to_le_bytes());
        payload.extend_from_slice(&(self.geometry.block_count as u64).to_le_bytes());
        payload.extend_from_slice(&(self.written_blocks.len() as u64).to_le_bytes());
        for block in &self.written_blocks {
            payload.extend_from_slice(&(*block as u64).to_le_bytes());
        }
        payload
    }

    fn persist_written_block_index_if_dirty(&mut self) -> Result<(), BackendError> {
        if !self.written_index_dirty {
            return Ok(());
        }
        let payload = self.encode_written_block_index();
        self.store
            .put_named(Self::WRITTEN_BLOCK_INDEX_NAME, &payload)
            .map_err(|e| match e {
                StoreError::NoSpace => BackendError::NoSpace,
                other => {
                    BackendError::Other(format!("persist block-volume written index: {other}"))
                }
            })?;
        self.written_index_dirty = false;
        Ok(())
    }

    fn written_blocks_in_range(
        &self,
        start_block: usize,
        block_count: usize,
    ) -> Result<Vec<usize>, BackendError> {
        let end_block = start_block
            .checked_add(block_count)
            .ok_or(BackendError::OutOfBounds)?;
        Ok(self
            .written_blocks
            .range(start_block..end_block)
            .copied()
            .collect())
    }

    fn delete_written_blocks_in_range(
        &mut self,
        start_block: usize,
        block_count: usize,
    ) -> Result<(), BackendError> {
        let blocks = self.written_blocks_in_range(start_block, block_count)?;
        for block in &blocks {
            let key = Self::block_key(*block);
            self.store.delete_named(key).map_err(|e| {
                BackendError::Other(format!("delete zero-visible block {block}: {e}"))
            })?;
            self.written_blocks.remove(block);
        }
        if !blocks.is_empty() {
            self.written_index_dirty = true;
        }
        Ok(())
    }
}

fn read_le_u64(payload: &[u8], cursor: &mut usize) -> Result<u64, BackendError> {
    let end = cursor
        .checked_add(8)
        .ok_or_else(|| BackendError::Other("block-volume index cursor overflow".into()))?;
    let bytes = payload
        .get(*cursor..end)
        .ok_or_else(|| BackendError::Other("block-volume written index is truncated".into()))?;
    *cursor = end;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("u64 slice length"),
    ))
}

impl BlockVolumeStorageBackend for BlockVolumeObjectStoreBackend {
    fn geometry(&self) -> tidefs_block_volume_adapter_core::BlockVolumeGeometryRecord {
        self.geometry
    }

    fn is_read_only(&self) -> bool {
        self.store.is_read_only()
    }

    fn read_blocks(
        &self,
        start_block: usize,
        block_count: usize,
        block_size_bytes: usize,
    ) -> Result<BackendReadResult, BackendError> {
        if block_count == 0 {
            return Ok(BackendReadResult {
                completion_class: BlockVolumeCompletionClass::Completed,
                payload: Some(Vec::new()),
            });
        }
        let mut payload = Vec::with_capacity(block_count * block_size_bytes);
        for i in 0..block_count {
            let key = Self::block_key(start_block + i);
            let read_result = if let Some(root) = self.snapshot_committed_root {
                self.store
                    .get_at_commit_group(tidefs_local_object_store::ObjectKey::from_name(key), root)
                    .map_err(|e| {
                        BackendError::Other(format!("read block at root {start_block}+{i}: {e}"))
                    })?
            } else {
                self.store.get_named(key).map_err(|e| {
                    BackendError::Other(format!("read block {start_block}+{i}: {e}"))
                })?
            };
            match read_result {
                Some(data) => {
                    if data.len() != block_size_bytes {
                        return Ok(BackendReadResult {
                            completion_class: BlockVolumeCompletionClass::RefusedMisalignedRange,
                            payload: None,
                        });
                    }
                    payload.extend_from_slice(&data);
                }
                None => {
                    // Unwritten blocks read as zeroes
                    payload.extend(std::iter::repeat_n(0u8, block_size_bytes));
                }
            }
        }
        Ok(BackendReadResult {
            completion_class: BlockVolumeCompletionClass::Completed,
            payload: Some(payload),
        })
    }

    fn write_blocks(
        &mut self,
        start_block: usize,
        payload: &[u8],
        block_size_bytes: usize,
    ) -> Result<BackendWriteResult, BackendError> {
        if payload.len() % block_size_bytes != 0 {
            return Ok(BackendWriteResult {
                completion_class: BlockVolumeCompletionClass::RefusedMisalignedRange,
            });
        }
        let block_count = payload.len() / block_size_bytes;
        for i in 0..block_count {
            let key = Self::block_key(start_block + i);
            let chunk = &payload[i * block_size_bytes..(i + 1) * block_size_bytes];
            self.store.put_named(key, chunk).map_err(|e| match e {
                StoreError::NoSpace => BackendError::NoSpace,
                other => BackendError::Other(format!("write block {start_block}+{i}: {other}")),
            })?;
            if self.written_blocks.insert(start_block + i) {
                self.written_index_dirty = true;
            }
        }
        Ok(BackendWriteResult {
            completion_class: BlockVolumeCompletionClass::Completed,
        })
    }

    fn flush(&mut self) -> Result<(), BackendError> {
        // Issue a durability barrier through the local-object-store's
        // sync path, which flushes the segment file, writes a spacemap
        // checkpoint, drains the intent-log to durable storage, commits
        // the current commit_group, and persists the committed root.
        self.persist_written_block_index_if_dirty()?;
        self.store
            .sync()
            .map_err(|e| BackendError::Other(format!("object store sync failed: {e}")))
    }

    fn last_committed_root(&self) -> Option<u64> {
        self.store.committed_root_u64()
    }

    fn discard_blocks(
        &mut self,
        start_block: usize,
        block_count: usize,
        _block_size_bytes: usize,
    ) -> Result<(), BackendError> {
        self.delete_written_blocks_in_range(start_block, block_count)
    }

    fn write_zeroes(
        &mut self,
        start_block: usize,
        block_count: usize,
        _block_size_bytes: usize,
    ) -> Result<(), BackendError> {
        self.delete_written_blocks_in_range(start_block, block_count)
    }

    fn resize_to(&mut self, new_block_count: usize) -> Result<(), BackendError> {
        // Only grow is supported; refuse shrink
        if new_block_count <= self.geometry.block_count {
            return Err(BackendError::Other("online shrink is not supported".into()));
        }
        self.geometry.block_count = new_block_count;
        self.written_index_dirty = true;
        Ok(())
    }
}

// ── UblkIoBackend bridge adapter ─────────────────────────────────────

use tidefs_block_volume_adapter_ublk_control_runtime::ublk_io::UblkIoBackend;

/// Newtype wrapper around [] that bridges the
/// crate-level [] trait, enabling the ublk IO ring handler
/// to dispatch reads, writes, flushes, discards, and write-zeroes
/// through the block-volume adapter core.
pub struct UblkIoFileImageBackend {
    pub image: BlockVolumeFileImage,
}

impl UblkIoFileImageBackend {
    #[must_use]
    pub fn new(image: BlockVolumeFileImage) -> Self {
        Self { image }
    }

    fn block_size(&self) -> u64 {
        self.image.geometry.block_size_bytes as u64
    }

    fn align_check(&self, byte_offset: u64, byte_len: u64) -> std::io::Result<()> {
        let bs = self.block_size();
        if byte_offset % bs != 0 || byte_len % bs != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "byte_offset and length must be block-aligned",
            ));
        }
        Ok(())
    }
}

impl UblkIoBackend for UblkIoFileImageBackend {
    fn read(&mut self, byte_offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.align_check(byte_offset, buf.len() as u64)?;
        let bs = self.block_size();
        let start_block = (byte_offset / bs) as usize;
        let block_count = buf.len() / bs as usize;
        if block_count == 0 {
            return Ok(0);
        }
        let range = BlockRangeRecord::new(start_block, block_count);
        match self.image.read_blocks(range) {
            Ok((_plan, Some(payload))) => {
                let n = payload.len().min(buf.len());
                buf[..n].copy_from_slice(&payload[..n]);
                Ok(n)
            }
            Ok((_plan, None)) => {
                buf.fill(0u8);
                Ok(buf.len())
            }
            Err(BlockVolumeFileImageError::Io(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "read out of bounds",
            )),
        }
    }

    fn write(&mut self, byte_offset: u64, data: &[u8]) -> std::io::Result<usize> {
        self.align_check(byte_offset, data.len() as u64)?;
        if data.is_empty() {
            return Ok(0);
        }
        let start_block = (byte_offset / self.block_size()) as usize;
        match self.image.write_blocks(start_block, data) {
            Ok(plan) => {
                if plan.completion_class == BlockVolumeCompletionClass::Completed {
                    Ok(data.len())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "write refused",
                    ))
                }
            }
            Err(BlockVolumeFileImageError::Io(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "write out of bounds",
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.image.flush() {
            Ok(_plan) => Ok(()),
            Err(BlockVolumeFileImageError::Io(io)) => Err(io),
            Err(_) => Err(std::io::Error::other("flush failed")),
        }
    }

    fn discard(&mut self, byte_offset: u64, byte_len: u64) -> std::io::Result<()> {
        self.align_check(byte_offset, byte_len)?;
        if byte_len == 0 {
            return Ok(());
        }
        let bs = self.block_size();
        let start_block = (byte_offset / bs) as usize;
        let block_count = (byte_len / bs) as usize;
        let range = BlockRangeRecord::new(start_block, block_count);
        match self.image.discard_blocks(range) {
            Ok(_plan) => Ok(()),
            Err(BlockVolumeFileImageError::Io(io)) => Err(io),
            Err(_) => Err(std::io::Error::other("discard failed")),
        }
    }

    fn write_zeroes(&mut self, byte_offset: u64, byte_len: u64) -> std::io::Result<()> {
        self.align_check(byte_offset, byte_len)?;
        if byte_len == 0 {
            return Ok(());
        }
        let bs = self.block_size();
        let start_block = (byte_offset / bs) as usize;
        let block_count = (byte_len / bs) as usize;
        let zeroes = vec![0u8; block_count * bs as usize];
        match self.image.write_blocks(start_block, &zeroes) {
            Ok(plan) => {
                if plan.completion_class == BlockVolumeCompletionClass::Completed {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "write_zeroes refused",
                    ))
                }
            }
            Err(BlockVolumeFileImageError::Io(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "write_zeroes out of bounds",
            )),
        }
    }
}

#[cfg(test)]
mod ublk_io_backend_tests {
    use super::*;
    use tidefs_block_volume_adapter_core::{BlockVolumeGeometryRecord, BlockVolumeId};
    use tidefs_block_volume_adapter_ublk_control_runtime::ublk_io::{
        dispatch_io, UblkIoDescriptor,
    };
    use tidefs_ublk_abi::{
        UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ, UBLK_IO_OP_WRITE,
        UBLK_IO_OP_WRITE_ZEROES,
    };

    fn test_backend() -> (tempfile::TempDir, UblkIoFileImageBackend) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ublk-backend-test.img");
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(401_100), 4096, 64, 1);
        let image =
            BlockVolumeFileImage::create_zeroed(&path, geometry).expect("create test image");
        (dir, UblkIoFileImageBackend::new(image))
    }

    fn object_store_backend(
        block_count: usize,
    ) -> (tempfile::TempDir, BlockVolumeObjectStoreBackend) {
        let dir = tempfile::tempdir().expect("tempdir");
        let geometry =
            BlockVolumeGeometryRecord::new(BlockVolumeId::new(401_200), 4096, block_count, 1);
        let backend =
            BlockVolumeObjectStoreBackend::open(dir.path(), geometry).expect("open object backend");
        (dir, backend)
    }

    #[test]
    fn object_store_full_range_discard_only_touches_written_blocks() {
        let (_dir, mut backend) = object_store_backend(1_000_000);
        backend
            .write_blocks(2, &[0xAAu8; 4096], 4096)
            .expect("write low block");
        backend
            .write_blocks(900_000, &[0xBBu8; 4096], 4096)
            .expect("write high block");
        assert_eq!(backend.written_blocks.len(), 2);

        backend
            .discard_blocks(0, 1_000_000, 4096)
            .expect("full range discard");

        assert!(backend.written_blocks.is_empty());
        let read = backend
            .read_blocks(900_000, 1, 4096)
            .expect("read discarded block");
        assert_eq!(read.payload.expect("payload"), vec![0u8; 4096]);
    }

    #[test]
    fn object_store_write_zeroes_sparse_deletes_live_blocks() {
        let (_dir, mut backend) = object_store_backend(128);
        backend
            .write_blocks(5, &[0xE5u8; 4096], 4096)
            .expect("write block");
        backend
            .write_zeroes(0, 128, 4096)
            .expect("write zeroes full range");

        assert!(backend.written_blocks.is_empty());
        let read = backend.read_blocks(5, 1, 4096).expect("read zeroed block");
        assert_eq!(read.payload.expect("payload"), vec![0u8; 4096]);
    }

    #[test]
    fn object_store_written_index_persists_across_reopen() {
        let (dir, mut backend) = object_store_backend(256);
        backend
            .write_blocks(42, &[0x42u8; 4096], 4096)
            .expect("write block");
        backend.flush().expect("flush written index");
        drop(backend);

        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(401_200), 4096, 256, 1);
        let mut reopened =
            BlockVolumeObjectStoreBackend::open(dir.path(), geometry).expect("reopen backend");
        assert!(reopened.written_blocks.contains(&42));

        reopened
            .discard_blocks(0, 256, 4096)
            .expect("discard after reopen");
        let read = reopened
            .read_blocks(42, 1, 4096)
            .expect("read discarded after reopen");
        assert_eq!(read.payload.expect("payload"), vec![0u8; 4096]);
    }

    #[test]
    fn object_store_missing_written_index_with_block_payloads_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(401_201), 4096, 128, 1);
        {
            let mut store = LocalObjectStore::open(dir.path()).expect("open raw store");
            store
                .put_named(
                    BlockVolumeObjectStoreBackend::block_key(77),
                    &[0x77u8; 4096],
                )
                .expect("pre-index block payload write");
            store.sync().expect("sync raw store");
        }

        let err = match BlockVolumeObjectStoreBackend::open(dir.path(), geometry) {
            Ok(_) => panic!("accepted pre-index block payloads without written index"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(message.contains("missing current written index"));
        assert!(message.contains("refusing pre-index block data"));
    }

    fn make_io_desc(op: u8, start_sector: u64, sector_count: u32) -> UblkIoDescriptor {
        use tidefs_ublk_abi::UblkSrvIoDesc;
        let raw = UblkSrvIoDesc {
            op_flags: op as u32,
            count_or_zones: sector_count,
            start_sector,
            addr: 0x1000_0000,
        };
        UblkIoDescriptor::from_desc(0, 0, &raw)
    }

    #[test]
    fn ublk_io_backend_read_roundtrip_through_dispatch_io() {
        let (_dir, mut backend) = test_backend();
        // Write some data first through the wrapped image
        let write_data = [0x42u8; 4096];
        backend
            .image
            .write_blocks(1, &write_data)
            .expect("write block 1");

        // Read through dispatch_io using the UblkIoBackend impl
        let mut buf = [0u8; 4096];
        let desc = make_io_desc(UBLK_IO_OP_READ, 8, 8); // sector 8 = block 1 (4096/512=8)
        let result =
            dispatch_io(&mut backend, &desc, Some(&mut buf), None).expect("dispatch_io read");
        assert!(matches!(result, tidefs_block_volume_adapter_ublk_control_runtime::ublk_io::UblkIoDispatchResult::Completed { byte_count: 4096 }));
        assert_eq!(&buf[..], &write_data[..]);
    }

    #[test]
    fn ublk_io_backend_write_through_dispatch_io() {
        let (_dir, mut backend) = test_backend();
        let data = [0xABu8; 4096];
        let desc = make_io_desc(UBLK_IO_OP_WRITE, 16, 8); // sector 16 = block 2
        let result =
            dispatch_io(&mut backend, &desc, None, Some(&data)).expect("dispatch_io write");
        assert!(matches!(result, tidefs_block_volume_adapter_ublk_control_runtime::ublk_io::UblkIoDispatchResult::Completed { byte_count: 4096 }));

        // Verify with direct read on wrapped image
        let (_, payload) = backend
            .image
            .read_blocks(BlockRangeRecord::new(2, 1))
            .expect("read back");
        assert_eq!(payload.unwrap(), data.to_vec());
    }

    #[test]
    fn ublk_io_backend_flush_through_dispatch_io() {
        let (_dir, mut backend) = test_backend();
        let desc = make_io_desc(UBLK_IO_OP_FLUSH, 0, 0);
        let result = dispatch_io(&mut backend, &desc, None, None).expect("dispatch_io flush");
        assert!(matches!(result, tidefs_block_volume_adapter_ublk_control_runtime::ublk_io::UblkIoDispatchResult::Completed { byte_count: 0 }));
    }

    #[test]
    fn ublk_io_backend_discard_through_dispatch_io() {
        let (_dir, mut backend) = test_backend();
        let desc = make_io_desc(UBLK_IO_OP_DISCARD, 32, 8); // sector 32 = block 4
        let result = dispatch_io(&mut backend, &desc, None, None).expect("dispatch_io discard");
        assert!(matches!(result, tidefs_block_volume_adapter_ublk_control_runtime::ublk_io::UblkIoDispatchResult::Completed { byte_count: 0 }));
    }

    #[test]
    fn ublk_io_backend_write_zeroes_through_dispatch_io() {
        let (_dir, mut backend) = test_backend();
        // Pre-fill with non-zero data through the wrapped image
        backend
            .image
            .write_blocks(5, &[0xFFu8; 4096])
            .expect("write block 5");

        let desc = make_io_desc(UBLK_IO_OP_WRITE_ZEROES, 40, 8); // sector 40 = block 5
        let result =
            dispatch_io(&mut backend, &desc, None, None).expect("dispatch_io write_zeroes");
        assert!(matches!(result, tidefs_block_volume_adapter_ublk_control_runtime::ublk_io::UblkIoDispatchResult::Completed { byte_count: 0 }));

        // Verify zeroed through the wrapped image
        let (_, payload) = backend
            .image
            .read_blocks(BlockRangeRecord::new(5, 1))
            .expect("read back");
        assert_eq!(payload.unwrap(), vec![0u8; 4096]);
    }

    #[test]
    fn ublk_io_backend_misaligned_read_refused() {
        let (_dir, mut backend) = test_backend();
        let mut buf = [0u8; 511]; // not block-aligned
        let result = backend.read(0, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn ublk_io_backend_misaligned_write_refused() {
        let (_dir, mut backend) = test_backend();
        let data = [0u8; 511]; // not block-aligned
        let result = backend.write(1, &data);
        assert!(result.is_err());
    }
}
