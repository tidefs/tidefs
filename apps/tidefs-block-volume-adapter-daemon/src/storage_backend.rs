// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeCompletionClass, BlockVolumeFileImage, BlockVolumeFileImageError,
    BlockVolumeGeometryRecord,
};
use tidefs_cluster::PoolLeaseToken;
use tidefs_pool_runtime::ExternalMutationDeadline;

/// Geometry consumed by the Linux block carrier.
///
/// Dataset identity deliberately does not cross this boundary. The durable
/// Pool engine owns the canonical 128-bit `DatasetId`; ublk needs only the
/// exact committed capacity and topology used to project a block device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockDeviceGeometry {
    pub block_size_bytes: usize,
    pub block_count: usize,
    pub discard_granularity_blocks: usize,
    pub logical_sector_size: u64,
    pub physical_sector_size: u64,
    pub optimal_io_size: u64,
    pub alignment_offset: u64,
    pub min_io_size: u64,
}

impl BlockDeviceGeometry {
    #[must_use]
    pub const fn capacity_bytes(self) -> Option<usize> {
        self.block_size_bytes.checked_mul(self.block_count)
    }

    #[must_use]
    pub const fn admits_discard(self) -> bool {
        self.discard_granularity_blocks > 0
    }

    pub fn from_pool(geometry: tidefs_pool_runtime::VolumeGeometry) -> Result<Self, BackendError> {
        let block_size_bytes = usize::try_from(geometry.block_size_bytes)
            .map_err(|_| BackendError::Other("volume block size exceeds host usize".into()))?;
        let block_count = usize::try_from(geometry.block_count())
            .map_err(|_| BackendError::Other("volume block count exceeds host usize".into()))?;
        let discard_granularity_blocks =
            usize::try_from(geometry.discard_granularity_bytes / geometry.block_size_bytes)
                .map_err(|_| {
                    BackendError::Other("discard granularity exceeds host usize".into())
                })?;
        Ok(Self {
            block_size_bytes,
            block_count,
            discard_granularity_blocks,
            logical_sector_size: u64::from(geometry.logical_sector_size),
            physical_sector_size: u64::from(geometry.physical_sector_size),
            optimal_io_size: u64::from(geometry.optimal_io_size),
            alignment_offset: 0,
            min_io_size: u64::from(geometry.block_size_bytes),
        })
    }
}

impl From<BlockVolumeGeometryRecord> for BlockDeviceGeometry {
    fn from(geometry: BlockVolumeGeometryRecord) -> Self {
        Self {
            block_size_bytes: geometry.block_size_bytes,
            block_count: geometry.block_count,
            discard_granularity_blocks: geometry.discard_granularity_blocks,
            logical_sector_size: geometry.logical_sector_size,
            physical_sector_size: geometry.physical_sector_size,
            optimal_io_size: geometry.optimal_io_size,
            alignment_offset: geometry.alignment_offset,
            min_io_size: geometry.min_io_size,
        }
    }
}

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
    ReadOnly,
    InvalidClusterAuthority(&'static str),
    ClusterAuthorityExpired,
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
            Self::ReadOnly => write!(f, "read-only block volume"),
            Self::InvalidClusterAuthority(reason) => {
                write!(f, "invalid clustered block authority: {reason}")
            }
            Self::ClusterAuthorityExpired => {
                write!(
                    f,
                    "clustered block writer authority expired; reopen required"
                )
            }
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
    fn geometry(&self) -> BlockDeviceGeometry;

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
    /// if the backend tracks it.
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

    fn geometry(&self) -> BlockDeviceGeometry {
        self.geometry.into()
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

/// Shared neutral Pool owner used by a standalone block export and its
/// live-owner control endpoint.
pub type PoolRuntime = tidefs_pool_runtime::PoolRuntime;
pub type SharedPoolRuntime = Arc<Mutex<PoolRuntime>>;
pub type PoolVolumeSnapshotSummary = tidefs_pool_runtime::VolumeSnapshotSummary;

enum PoolVolumeOwner {
    Standalone(SharedPoolRuntime),
    Mounted(tidefs_local_filesystem::vfs_engine_impl::SharedLocalFileSystem),
}

#[derive(Clone, Debug)]
struct ClusteredPoolVolumeAuthority {
    lease: PoolLeaseToken,
    deadline: ExternalMutationDeadline,
}

/// Real named-volume backend over the canonical Pool runtime.
///
/// Standalone exports own the runtime directly. A mounted export shares the
/// already-open filesystem/Pool owner and locks it only for one backend call;
/// the ublk service loop never holds the FUSE engine mutex for its lifetime.
pub struct PoolVolumeBackend {
    owner: PoolVolumeOwner,
    volume: tidefs_pool_runtime::PoolVolume,
    geometry: BlockDeviceGeometry,
    read_only: bool,
    clustered_authority: Option<ClusteredPoolVolumeAuthority>,
}

impl PoolVolumeBackend {
    pub fn open_standalone(
        runtime: tidefs_pool_runtime::PoolRuntime,
        path: &str,
        read_only: bool,
    ) -> Result<Self, BackendError> {
        Self::open_shared(Arc::new(Mutex::new(runtime)), path, read_only)
    }

    /// Open a named Pool volume under one authenticated clustered writer
    /// lease. The caller derives `valid_until` immediately from the remaining
    /// lifetime reported with the committed grant, so later validation and
    /// Pool reopen work cannot restart that already-elapsing window.
    pub fn open_clustered(
        mut runtime: tidefs_pool_runtime::PoolRuntime,
        path: &str,
        read_only: bool,
        lease: PoolLeaseToken,
        valid_until: Instant,
    ) -> Result<Self, BackendError> {
        validate_clustered_lease(&runtime, &lease, valid_until)?;
        let deadline = ExternalMutationDeadline::new_until(valid_until);
        runtime
            .install_external_mutation_deadline(deadline.clone())
            .map_err(map_pool_runtime_error)?;
        let mut backend = Self::open_standalone(runtime, path, read_only)?;
        backend.clustered_authority = Some(ClusteredPoolVolumeAuthority { lease, deadline });
        Ok(backend)
    }

    /// Open a named volume through a shared neutral Pool owner.
    ///
    /// The ublk data path locks this owner only for one backend operation, so
    /// the same runtime can serialize live-owner administration without a
    /// second Pool open or authority path.
    pub fn open_shared(
        runtime: SharedPoolRuntime,
        path: &str,
        read_only: bool,
    ) -> Result<Self, BackendError> {
        let volume = lock_pool_runtime(&runtime)?
            .open_volume(path)
            .map_err(map_pool_runtime_error)?;
        let geometry = BlockDeviceGeometry::from_pool(volume.geometry())?;
        Ok(Self {
            owner: PoolVolumeOwner::Standalone(runtime),
            volume,
            geometry,
            read_only,
            clustered_authority: None,
        })
    }

    pub fn open_mounted(
        owner: tidefs_local_filesystem::vfs_engine_impl::SharedLocalFileSystem,
        path: &str,
        read_only: bool,
    ) -> Result<Self, BackendError> {
        let volume = owner
            .borrow()
            .open_volume_dataset(path)
            .map_err(map_filesystem_error)?;
        let geometry = BlockDeviceGeometry::from_pool(volume.geometry())?;
        Ok(Self {
            owner: PoolVolumeOwner::Mounted(owner),
            volume,
            geometry,
            read_only,
            clustered_authority: None,
        })
    }

    /// Renew the process-local gate only with the same committed writer,
    /// lease, epoch, and fence. Ownership transfer requires a full Pool reopen
    /// so a stale backend can never be retargeted to a successor lease.
    pub fn renew_clustered_authority(
        &mut self,
        lease: PoolLeaseToken,
        valid_until: Instant,
    ) -> Result<(), BackendError> {
        let authority =
            self.clustered_authority
                .as_mut()
                .ok_or(BackendError::InvalidClusterAuthority(
                    "backend is not a clustered export",
                ))?;
        if !authority.deadline.is_live() {
            return Err(BackendError::ClusterAuthorityExpired);
        }
        if !lease.is_valid()
            || lease.pool_guid != authority.lease.pool_guid
            || lease.node_id != authority.lease.node_id
            || lease.epoch != authority.lease.epoch
            || lease.lease_id != authority.lease.lease_id
            || lease.slot != authority.lease.slot
            || lease.write_fence != authority.lease.write_fence
            || lease.expiration_deadline_ms <= authority.lease.expiration_deadline_ms
        {
            return Err(BackendError::InvalidClusterAuthority(
                "renewal does not extend the same writer lease and fence",
            ));
        }
        if authority
            .deadline
            .valid_until()
            .is_none_or(|current| valid_until <= current)
        {
            return Err(BackendError::InvalidClusterAuthority(
                "renewal does not advance the process-local deadline",
            ));
        }
        if !authority.deadline.renew_until(valid_until) {
            return Err(BackendError::ClusterAuthorityExpired);
        }
        authority.lease = lease;
        Ok(())
    }

    /// Quarantine this backend immediately after release or authority loss.
    pub fn fence_clustered_authority(&self) -> Result<(), BackendError> {
        let authority =
            self.clustered_authority
                .as_ref()
                .ok_or(BackendError::InvalidClusterAuthority(
                    "backend is not a clustered export",
                ))?;
        authority.deadline.fence();
        Ok(())
    }

    fn ensure_clustered_authority(&self) -> Result<(), BackendError> {
        if self
            .clustered_authority
            .as_ref()
            .is_some_and(|authority| !authority.deadline.is_live())
        {
            Err(BackendError::ClusterAuthorityExpired)
        } else {
            Ok(())
        }
    }

    fn zero_blocks(
        &mut self,
        start_block: usize,
        block_count: usize,
        block_size_bytes: usize,
    ) -> Result<(), BackendError> {
        self.ensure_clustered_authority()?;
        if self.read_only {
            return Err(BackendError::ReadOnly);
        }
        if block_size_bytes != self.geometry.block_size_bytes {
            return Err(BackendError::MisalignedRange);
        }
        let start_block = u64::try_from(start_block).map_err(|_| BackendError::OutOfBounds)?;
        let block_count = u64::try_from(block_count).map_err(|_| BackendError::OutOfBounds)?;
        match (&mut self.owner, &mut self.volume) {
            (PoolVolumeOwner::Standalone(runtime), volume) => {
                let runtime = lock_pool_runtime(runtime)?;
                volume
                    .zero_blocks(&runtime, start_block, block_count)
                    .map_err(map_pool_runtime_error)
            }
            (PoolVolumeOwner::Mounted(owner), volume) => owner
                .borrow()
                .zero_volume_blocks(volume, start_block, block_count)
                .map_err(map_filesystem_error),
        }
    }
}

impl BlockVolumeStorageBackend for PoolVolumeBackend {
    fn read_blocks(
        &self,
        start_block: usize,
        block_count: usize,
        block_size_bytes: usize,
    ) -> Result<BackendReadResult, BackendError> {
        self.ensure_clustered_authority()?;
        if block_size_bytes != self.geometry.block_size_bytes {
            return Err(BackendError::MisalignedRange);
        }
        let start_block = u64::try_from(start_block).map_err(|_| BackendError::OutOfBounds)?;
        let block_count = u64::try_from(block_count).map_err(|_| BackendError::OutOfBounds)?;
        let payload = match &self.owner {
            PoolVolumeOwner::Standalone(runtime) => {
                let runtime = lock_pool_runtime(runtime)?;
                self.volume
                    .read_blocks(&runtime, start_block, block_count)
                    .map_err(map_pool_runtime_error)?
            }
            PoolVolumeOwner::Mounted(owner) => owner
                .borrow()
                .read_volume_blocks(&self.volume, start_block, block_count)
                .map_err(map_filesystem_error)?,
        };
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
        self.ensure_clustered_authority()?;
        if self.read_only {
            return Err(BackendError::ReadOnly);
        }
        if block_size_bytes != self.geometry.block_size_bytes
            || payload.len() % block_size_bytes != 0
        {
            return Err(BackendError::MisalignedRange);
        }
        let start_block = u64::try_from(start_block).map_err(|_| BackendError::OutOfBounds)?;
        match (&mut self.owner, &mut self.volume) {
            (PoolVolumeOwner::Standalone(runtime), volume) => {
                let runtime = lock_pool_runtime(runtime)?;
                volume
                    .write_blocks(&runtime, start_block, payload)
                    .map_err(map_pool_runtime_error)?
            }
            (PoolVolumeOwner::Mounted(owner), volume) => owner
                .borrow()
                .write_volume_blocks(volume, start_block, payload)
                .map_err(map_filesystem_error)?,
        }
        Ok(BackendWriteResult {
            completion_class: BlockVolumeCompletionClass::Completed,
        })
    }

    fn flush(&mut self) -> Result<(), BackendError> {
        self.ensure_clustered_authority()?;
        if self.read_only {
            return Err(BackendError::ReadOnly);
        }
        match (&mut self.owner, &mut self.volume) {
            (PoolVolumeOwner::Standalone(runtime), volume) => {
                let mut runtime = lock_pool_runtime(runtime)?;
                volume.flush(&mut runtime).map_err(map_pool_runtime_error)
            }
            (PoolVolumeOwner::Mounted(owner), volume) => owner
                .borrow_mut()
                .flush_volume(volume)
                .map_err(map_filesystem_error),
        }
    }

    fn discard_blocks(
        &mut self,
        start_block: usize,
        block_count: usize,
        block_size_bytes: usize,
    ) -> Result<(), BackendError> {
        self.zero_blocks(start_block, block_count, block_size_bytes)
    }

    fn write_zeroes(
        &mut self,
        start_block: usize,
        block_count: usize,
        block_size_bytes: usize,
    ) -> Result<(), BackendError> {
        self.zero_blocks(start_block, block_count, block_size_bytes)
    }

    fn geometry(&self) -> BlockDeviceGeometry {
        self.geometry
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }
}

fn lock_pool_runtime(
    runtime: &SharedPoolRuntime,
) -> Result<MutexGuard<'_, tidefs_pool_runtime::PoolRuntime>, BackendError> {
    runtime
        .lock()
        .map_err(|_| BackendError::Other("shared Pool runtime lock poisoned".into()))
}

fn validate_clustered_lease(
    runtime: &tidefs_pool_runtime::PoolRuntime,
    lease: &PoolLeaseToken,
    valid_until: Instant,
) -> Result<(), BackendError> {
    if !lease.is_valid() {
        return Err(BackendError::InvalidClusterAuthority(
            "lease identity is incomplete",
        ));
    }
    if lease.write_fence.epoch != lease.epoch || lease.write_fence.generation == 0 {
        return Err(BackendError::InvalidClusterAuthority(
            "write fence does not match the lease epoch",
        ));
    }
    if !lease.authorizes_pool(&runtime.pool().pool_guid()) {
        return Err(BackendError::InvalidClusterAuthority(
            "lease Pool GUID does not match the opened Pool",
        ));
    }
    if valid_until <= Instant::now() {
        return Err(BackendError::ClusterAuthorityExpired);
    }
    Ok(())
}

fn map_pool_runtime_error(error: tidefs_pool_runtime::PoolRuntimeError) -> BackendError {
    match error {
        tidefs_pool_runtime::PoolRuntimeError::Bounds => BackendError::OutOfBounds,
        tidefs_pool_runtime::PoolRuntimeError::Store(
            tidefs_local_object_store::StoreError::NoSpace,
        ) => BackendError::NoSpace,
        tidefs_pool_runtime::PoolRuntimeError::ExternalMutationAuthorityExpired { .. } => {
            BackendError::ClusterAuthorityExpired
        }
        other => BackendError::Other(other.to_string()),
    }
}

fn map_filesystem_error(error: tidefs_local_filesystem::FileSystemError) -> BackendError {
    match error {
        tidefs_local_filesystem::FileSystemError::NoSpace { .. } => BackendError::NoSpace,
        tidefs_local_filesystem::FileSystemError::PoolRuntime(error) => {
            map_pool_runtime_error(error)
        }
        other => BackendError::Other(other.to_string()),
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
