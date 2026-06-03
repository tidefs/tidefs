//! BlockBackend adapter bridging block-kmod dispatch to a shared
//! kernel pool core (canonical trait from #6131).
//!
//! Defines a minimal [`PoolCoreOps`] adapter trait that the block-kmod
//! needs for logical-volume I/O.  When #6131 publishes the canonical
//! `KernelPoolCore` trait, this adapter will be re-wired to implement
//! `PoolCoreOps` for any `KernelPoolCore`, and the local trait will be
//! removed.
//!
//! ## Integration with #6131
//!
//! When #6131 lands, the bridge looks like:
//!
//! ```ignore
//! // blanket impl bridge
//! impl<T: tidefs_vfs_engine::KernelPoolCore> PoolCoreOps for T {
//!     fn read_volume_block(&self, off: u64, len: u32, buf: &mut [u8]) -> Result<u32, Errno> {
//!         <T as tidefs_vfs_engine::KernelPoolCore>::read_volume_block(self, off, len, buf)
//!     }
//!     // ... etc for all methods
//! }
//!
//! // Then in the Kbuild module entrypoint:
//! let pool_core: Arc<dyn KernelPoolCore> = /* from pool mount */;
//! let handle = PoolCoreHandle::new(pool_core);  // PoolCoreOps blanket impl enables this
//! let backend = PoolCoreBackend::new(handle);
//! device.set_pool_core_backend(backend);
//! ```
//!
//! # Self-stacking rejection
//!
//! [`PoolCoreBackend::check_self_stacked`] queries the pool core to
//! detect self-referential device stacking and returns an error when
//! a TideFS-exported block device would be used as its own pool member.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::dispatch::BlockBackend;
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::Errno;
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::{BridgeError, BridgeResult};
use crate::BlockQueueLimits;
#[cfg(not(CONFIG_RUST))]
use alloc::sync::Arc;
#[cfg(CONFIG_RUST)]
use kernel::sync::Arc;
#[cfg(not(CONFIG_RUST))]
use tidefs_kmod_bridge::{BridgeError, BridgeResult};
#[cfg(not(CONFIG_RUST))]
use tidefs_vfs_engine::Errno;


// ── KernelStorageIoCompat ──────────────────────────────────────────────

/// Kbuild-compatible mirror of [`tidefs_kernel_storage_io::KernelStorageIo`].
///
/// This trait provides the sector-aligned block-I/O contract that the
/// pool-core adapter needs without depending on the external
/// `tidefs-kernel-storage-io` crate.  Under Kbuild, kernel-side block-device
/// handles implement this trait directly.  Under cargo, a blanket impl
/// bridges [`tidefs_kernel_storage_io::KernelStorageIo`] into this trait.
pub trait KernelStorageIoCompat: Send + Sync {
    /// Read sectors into `buf`.  Returns the number of sectors read.
    fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno>;
    /// Write sectors from `data`.  Returns the number of sectors written.
    fn write_sectors(&self, start_sector: u64, data: &[u8]) -> Result<u32, Errno>;
    /// Flush cached writes to durable media.
    fn flush(&self) -> Result<(), Errno>;
    /// Sector size in bytes.
    fn sector_size(&self) -> u32;
    /// Total device capacity in bytes.
    fn capacity_bytes(&self) -> u64;
}

// Blanket impl: bridge the canonical KernelStorageIo into KernelStorageIoCompat
// under cargo so existing KernelStorageIo implementors work with the adapter.
#[cfg(not(CONFIG_RUST))]
impl<T: tidefs_kernel_storage_io::KernelStorageIo + Send + Sync> KernelStorageIoCompat for T {
    fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno> {
        tidefs_kernel_storage_io::KernelStorageIo::read_sectors(self, start_sector, buf)
    }
    fn write_sectors(&self, start_sector: u64, data: &[u8]) -> Result<u32, Errno> {
        tidefs_kernel_storage_io::KernelStorageIo::write_sectors(self, start_sector, data)
    }
    fn flush(&self) -> Result<(), Errno> {
        tidefs_kernel_storage_io::KernelStorageIo::flush(self)
    }
    fn sector_size(&self) -> u32 {
        tidefs_kernel_storage_io::KernelStorageIo::sector_size(self)
    }
    fn capacity_bytes(&self) -> u64 {
        tidefs_kernel_storage_io::KernelStorageIo::capacity_bytes(self)
    }
}

// ── PoolCoreOps adapter trait ─────────────────────────────────────────

/// Minimal logical-volume I/O trait needed by block-kmod.
///
/// When #6131 publishes the canonical `KernelPoolCore`, this trait will
/// become a blanket impl bridge and can be removed.  Until then, it
/// defines exactly what block-kmod requires.
pub trait PoolCoreOps: Send + Sync {
    fn read_volume_block(
        &self,
        offset_bytes: u64,
        len_bytes: u32,
        buf: &mut [u8],
    ) -> Result<u32, Errno>;
    /// Read volume blocks anchored to a specific committed root (snapshot read).
    ///
    /// When a block device is exported from a snapshot, reads must return
    /// data from the snapshot's point-in-time state, not the live dataset.
    /// The `committed_root` identifies the snapshot root to anchor reads to.
    ///
    /// The default implementation delegates to [`read_volume_block`](Self::read_volume_block)
    /// (live reads).  Pool cores that support snapshot-anchored volume I/O
    /// must override this method.
    fn read_volume_block_at_root(
        &self,
        _committed_root: u64,
        offset_bytes: u64,
        len_bytes: u32,
        buf: &mut [u8],
    ) -> Result<u32, Errno> {
        self.read_volume_block(offset_bytes, len_bytes, buf)
    }
    fn write_volume_block(&self, offset_bytes: u64, data: &[u8]) -> Result<u32, Errno>;
    fn flush_volume(&self) -> Result<(), Errno>;
    fn discard_volume_blocks(&self, offset_bytes: u64, len_bytes: u64) -> Result<(), Errno>;
    fn volume_capacity_bytes(&self) -> u64;
    fn volume_block_size(&self) -> u32;
    fn volume_flush_supported(&self) -> bool {
        true
    }
    fn volume_discard_supported(&self) -> bool {
        false
    }
    fn volume_write_zeroes_supported(&self) -> bool {
        false
    }

    fn volume_zero_range_supported(&self) -> bool {
        false
    }
    /// Write zeroes to a volume byte range.
    ///
    /// The default implementation returns false.
    /// Engines that support write-zeroes must override this.
    fn write_zeroes_volume_blocks(&self, _offset_bytes: u64, _len_bytes: u64) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    /// Zero a volume byte range through allocation authority.
    ///
    /// Stronger than discard: the range MUST remain readable.
    /// The default implementation returns Errno::ENOSYS.
    fn zero_range_volume_blocks(&self, _offset_bytes: u64, _len_bytes: u64) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    /// Self-stacking check (default: never stacked).
    fn is_self_stacked(&self, _device_identifier: &[u8]) -> bool {
        false
    }
    /// Transaction-group commit barrier for block-device durability.
    ///
    /// Called after flush/FUA operations to publish a committed root
    /// so crash recovery recognizes the current txg as the consistent
    /// recovery point.  The default implementation is a no-op; pool
    /// cores that support txg commit must override this.
    fn txg_commit_barrier(&self) -> Result<(), Errno> {
        Ok(())
    }
}

// ── PoolCoreHandle ────────────────────────────────────────────────────

/// Refcounted handle to a shared [`PoolCoreOps`] implementation.
///
/// Adds a lifecycle fence that rejects I/O after pool teardown.
pub struct PoolCoreHandle {
    inner: Arc<dyn PoolCoreOps>,
    fenced: AtomicBool,
}

impl PoolCoreHandle {
    #[must_use]
    pub fn new(core: Arc<dyn PoolCoreOps>) -> Self {
        Self {
            inner: core,
            fenced: AtomicBool::new(false),
        }
    }

    pub fn fence(&self) {
        self.fenced.store(true, Ordering::Release);
    }
    #[must_use]
    pub fn is_fenced(&self) -> bool {
        self.fenced.load(Ordering::Acquire)
    }

    pub fn read_volume_block(&self, off: u64, len: u32, buf: &mut [u8]) -> Result<u32, Errno> {
        if self.is_fenced() {
            return Err(Errno::EIO);
        }
        self.inner.read_volume_block(off, len, buf)
    }
    /// Read volume blocks anchored to a specific committed root (snapshot read).
    ///
    /// Routes through [`PoolCoreOps::read_volume_block_at_root`].
    pub fn read_volume_block_at_root(
        &self,
        committed_root: u64,
        off: u64,
        len: u32,
        buf: &mut [u8],
    ) -> Result<u32, Errno> {
        if self.is_fenced() {
            return Err(Errno::EIO);
        }
        self.inner
            .read_volume_block_at_root(committed_root, off, len, buf)
    }
    pub fn write_volume_block(&self, off: u64, data: &[u8]) -> Result<u32, Errno> {
        if self.is_fenced() {
            return Err(Errno::EIO);
        }
        self.inner.write_volume_block(off, data)
    }
    pub fn flush_volume(&self) -> Result<(), Errno> {
        if self.is_fenced() {
            return Err(Errno::EIO);
        }
        self.inner.flush_volume()
    }
    pub fn discard_volume_blocks(&self, off: u64, len: u64) -> Result<(), Errno> {
        if self.is_fenced() {
            return Err(Errno::EIO);
        }
        self.inner.discard_volume_blocks(off, len)
    }
    #[must_use]
    pub fn volume_capacity_bytes(&self) -> u64 {
        self.inner.volume_capacity_bytes()
    }
    #[must_use]
    pub fn volume_block_size(&self) -> u32 {
        self.inner.volume_block_size()
    }
    #[must_use]
    pub fn volume_flush_supported(&self) -> bool {
        self.inner.volume_flush_supported()
    }
    #[must_use]
    pub fn volume_discard_supported(&self) -> bool {
        self.inner.volume_discard_supported()
    }

    pub fn volume_write_zeroes_supported(&self) -> bool {
        self.inner.volume_write_zeroes_supported()
    }

    pub fn volume_zero_range_supported(&self) -> bool {
        self.inner.volume_zero_range_supported()
    }
    pub fn write_zeroes_volume_blocks(&self, off: u64, len: u64) -> Result<(), Errno> {
        if self.is_fenced() {
            return Err(Errno::EIO);
        }
        self.inner.write_zeroes_volume_blocks(off, len)
    }
    pub fn zero_range_volume_blocks(&self, off: u64, len: u64) -> Result<(), Errno> {
        if self.is_fenced() {
            return Err(Errno::EIO);
        }
        self.inner.zero_range_volume_blocks(off, len)
    }
    #[must_use]
    pub fn is_self_stacked(&self, id: &[u8]) -> bool {
        self.inner.is_self_stacked(id)
    }
    /// Transaction-group commit barrier.
    ///
    /// Delegates to the inner [`PoolCoreOps::txg_commit_barrier`].
    /// Called after flush/FUA operations on the block device to publish
    /// a committed root for crash recovery.
    pub fn txg_commit_barrier(&self) -> Result<(), Errno> {
        if self.is_fenced() {
            return Err(Errno::EIO);
        }
        self.inner.txg_commit_barrier()
    }

    #[must_use]
    pub fn inner(&self) -> &(dyn PoolCoreOps + 'static) {
        &*self.inner
    }
}

impl Clone for PoolCoreHandle {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            fenced: AtomicBool::new(self.fenced.load(Ordering::Acquire)),
        }
    }
}

impl core::fmt::Debug for PoolCoreHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoolCoreHandle")
            .field("capacity_bytes", &self.volume_capacity_bytes())
            .field("block_size", &self.volume_block_size())
            .field("fenced", &self.is_fenced())
            .finish()
    }
}

// ── KernelStoragePoolCoreAdapter ─────────────────────────────────────
//
// This adapter is available under cargo (not Kbuild) so that unit tests
// and userspace validation harnesses can construct pool-backed block-kmod
// ── KernelStoragePoolCoreAdapter ──────────────────────────────────────

/// Bridges any [`KernelStorageIoCompat`] into [`PoolCoreOps`].
///
/// This is the production adapter: a sector-aligned block-device backend
/// (raw block device, file, or future pool member device) is wrapped in
/// this adapter to serve as the pool-core backend for block-kmod exports.
///
/// Under cargo, any [`tidefs_kernel_storage_io::KernelStorageIo`]
/// implementation is automatically compatible through the blanket
/// [`KernelStorageIoCompat`] impl above.
pub struct KernelStoragePoolCoreAdapter<S: KernelStorageIoCompat> {
    storage: S,
}

impl<S: KernelStorageIoCompat> KernelStoragePoolCoreAdapter<S> {
    /// Wrap a [`KernelStorageIoCompat`] backend.
    #[must_use]
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Return a reference to the inner storage.
    #[must_use]
    pub fn inner(&self) -> &S {
        &self.storage
    }

    /// Write zeroes to a byte range through sector-aligned writes.
    fn write_zeroes_range(&self, offset_bytes: u64, len_bytes: u64) -> Result<(), Errno> {
        if len_bytes == 0 {
            return Ok(());
        }
        let ss = u64::from(self.storage.sector_size());
        if ss == 0 {
            return Err(Errno::EINVAL);
        }
        let start_sector = offset_bytes / ss;
        let end_byte = offset_bytes.saturating_add(len_bytes);
        let end_sector = end_byte.div_ceil(ss);
        let total_sectors = end_sector.saturating_sub(start_sector);
        if total_sectors == 0 {
            return Ok(());
        }
        const ZERO_CHUNK_SECTORS: u64 = 128; // 64 KiB at 512 B sectors
        let zero_chunk = crate::zeroed_vec_u8((ZERO_CHUNK_SECTORS * ss) as usize);
        let mut remaining = total_sectors;
        let mut current_sector = start_sector;
        while remaining > 0 {
            let chunk_sectors = remaining.min(ZERO_CHUNK_SECTORS);
            let chunk_bytes = (chunk_sectors * ss) as usize;
            self.storage
                .write_sectors(current_sector, &zero_chunk[..chunk_bytes])?;
            current_sector += chunk_sectors;
            remaining -= chunk_sectors;
        }
        Ok(())
    }
}

impl<S: KernelStorageIoCompat> PoolCoreOps for KernelStoragePoolCoreAdapter<S> {
    fn read_volume_block(
        &self,
        offset_bytes: u64,
        len_bytes: u32,
        buf: &mut [u8],
    ) -> Result<u32, Errno> {
        let ss = u64::from(self.storage.sector_size());
        if ss == 0 {
            return Err(Errno::EINVAL);
        }
        let start_sector = offset_bytes / ss;
        let end_byte = offset_bytes.saturating_add(u64::from(len_bytes));
        let end_sector = end_byte.div_ceil(ss);
        let sector_count = end_sector.saturating_sub(start_sector);
        if sector_count > u64::from(u32::MAX) {
            return Err(Errno::EINVAL);
        }
        let read_sectors = self.storage.read_sectors(start_sector, buf)?;
        let byte_count = u64::from(read_sectors)
            .saturating_mul(ss)
            .min(u64::from(len_bytes));
        Ok(byte_count as u32)
    }

    fn write_volume_block(&self, offset_bytes: u64, data: &[u8]) -> Result<u32, Errno> {
        let ss = u64::from(self.storage.sector_size());
        if ss == 0 {
            return Err(Errno::EINVAL);
        }
        let start_sector = offset_bytes / ss;
        let written = self.storage.write_sectors(start_sector, data)?;
        let byte_count = u64::from(written).saturating_mul(ss);
        Ok(byte_count as u32)
    }

    fn flush_volume(&self) -> Result<(), Errno> {
        self.storage.flush()
    }

    fn discard_volume_blocks(&self, offset_bytes: u64, len_bytes: u64) -> Result<(), Errno> {
        self.write_zeroes_range(offset_bytes, len_bytes)
    }

    fn volume_capacity_bytes(&self) -> u64 {
        self.storage.capacity_bytes()
    }

    fn volume_block_size(&self) -> u32 {
        self.storage.sector_size()
    }

    fn volume_flush_supported(&self) -> bool {
        true
    }

    fn volume_discard_supported(&self) -> bool {
        true
    }

    fn volume_write_zeroes_supported(&self) -> bool {
        true
    }

    fn volume_zero_range_supported(&self) -> bool {
        true
    }

    fn write_zeroes_volume_blocks(
        &self,
        offset_bytes: u64,
        len_bytes: u64,
    ) -> Result<(), Errno> {
        self.write_zeroes_range(offset_bytes, len_bytes)
    }

    fn zero_range_volume_blocks(&self, offset_bytes: u64, len_bytes: u64) -> Result<(), Errno> {
        self.write_zeroes_range(offset_bytes, len_bytes)
    }
}

impl<S: KernelStorageIoCompat + core::fmt::Debug> core::fmt::Debug
    for KernelStoragePoolCoreAdapter<S>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KernelStoragePoolCoreAdapter")
            .field("capacity_bytes", &self.volume_capacity_bytes())
            .field("block_size", &self.volume_block_size())
            .field("storage", &self.storage)
            .finish()
    }
}



// ── PoolCoreBackend ───────────────────────────────────────────────────

/// A [`BlockBackend`] that delegates all I/O to a [`PoolCoreHandle`].
///
/// This is the production backend for kernel block-kmod: sector-based
/// block I/O is translated to pool-relative byte offsets and dispatched
/// through the shared pool core.
pub struct PoolCoreBackend {
    pool_core: PoolCoreHandle,
    limits: BlockQueueLimits,
    self_stacking_checked: bool,
    /// Optional committed root for snapshot-anchored reads.
    ///
    /// When set, all reads are anchored to this committed root instead of
    /// reading live data.  Writes and other mutating operations are
    /// rejected when a snapshot root is set (read-only export).
    snapshot_commit_root: Option<u64>,
}

impl PoolCoreBackend {
    #[must_use]
    pub fn new(pool_core: PoolCoreHandle) -> Self {
        let capacity_bytes = pool_core.volume_capacity_bytes();
        let block_size = pool_core.volume_block_size();
        let capacity_sectors = capacity_bytes / u64::from(block_size);

        let limits = BlockQueueLimits {
            logical_block_size: block_size,
            physical_block_size: block_size.max(4096),
            capacity_sectors,
            min_capacity_sectors: capacity_sectors,
            max_hw_sectors: 512,
            max_segments: 128,
            max_queue_depth: 64,
            io_min: block_size,
            io_opt: 4096,
            writable: true,
            flush_supported: pool_core.volume_flush_supported(),
            discard_supported: pool_core.volume_discard_supported(),
            write_zeroes_supported: pool_core.volume_write_zeroes_supported(),
            zero_range_supported: pool_core.volume_zero_range_supported(),
        };

        Self {
            pool_core,
            limits,
            self_stacking_checked: false,
            snapshot_commit_root: None,
        }
    }

    /// Check self-stacking and return an error if detected.
    pub fn check_self_stacked(&mut self, device_identifier: &[u8]) -> BridgeResult<bool> {
        let is_stacked = self.pool_core.is_self_stacked(device_identifier);
        self.self_stacking_checked = true;
        if is_stacked {
            Err(BridgeError::AuthorityRefused {
                reason:
                    "self-stacking: exported TideFS block device cannot be a member of its own pool",
            })
        } else {
            Ok(false)
        }
    }

    #[must_use]
    pub fn self_stacking_checked(&self) -> bool {
        self.self_stacking_checked
    }
    #[must_use]
    pub fn pool_core(&self) -> &PoolCoreHandle {
        &self.pool_core
    }

    /// Create a snapshot-anchored backend.
    ///
    /// All reads are routed through [`PoolCoreOps::read_volume_block_at_root`]
    /// with the given `committed_root`.  The backend is marked read-only
    /// (writable=false) so that write bios are rejected before reaching the
    /// pool core.
    #[must_use]
    pub fn with_snapshot_root(pool_core: PoolCoreHandle, committed_root: u64) -> Self {
        let mut backend = Self::new(pool_core);
        backend.snapshot_commit_root = Some(committed_root);
        backend.limits.writable = false;
        backend
    }

    /// Set or change the snapshot committed root.
    ///
    /// Passing `None` restores live reads (and sets writable=true).
    /// Passing `Some(root)` anchors reads to the given root
    /// (and sets writable=false).
    pub fn set_snapshot_root(&mut self, root: Option<u64>) {
        self.snapshot_commit_root = root;
        self.limits.writable = root.is_none();
    }

    /// Return the currently anchored snapshot root, if any.
    #[must_use]
    pub fn snapshot_root(&self) -> Option<u64> {
        self.snapshot_commit_root
    }

    /// Whether the backend is snapshot-anchored (read-only export).
    #[must_use]
    pub fn is_snapshot_anchored(&self) -> bool {
        self.snapshot_commit_root.is_some()
    }
}

impl BlockBackend for PoolCoreBackend {
    fn read_sectors(
        &self,
        start_sector: u64,
        sector_count: u32,
        buf: &mut [u8],
    ) -> BridgeResult<u32> {
        let ss = u64::from(self.limits.logical_block_size);
        let offset = start_sector * ss;
        let len = sector_count * self.limits.logical_block_size;
        if let Some(root) = self.snapshot_commit_root {
            self.pool_core
                .read_volume_block_at_root(root, offset, len, buf)
                .map_err(|_e| BridgeError::BioQueueFailed {
                    detail: "pool snapshot read: I/O error",
                })
        } else {
            self.pool_core
                .read_volume_block(offset, len, buf)
                .map_err(|e| BridgeError::BioQueueFailed {
                    detail: match e {
                        Errno::EINVAL => "pool read: offset beyond capacity",
                        _ => "pool read: I/O error",
                    },
                })
        }
    }

    fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> BridgeResult<u32> {
        if !self.limits.writable {
            return Err(BridgeError::BioQueueFailed {
                detail: "pool backend is read-only",
            });
        }
        let ss = u64::from(self.limits.logical_block_size);
        let offset = start_sector * ss;
        self.pool_core
            .write_volume_block(offset, data)
            .map_err(|e| BridgeError::BioQueueFailed {
                detail: match e {
                    Errno::ENOSPC => "pool write: no space",
                    _ => "pool write: I/O error",
                },
            })
    }

    fn flush(&mut self) -> BridgeResult<()> {
        self.pool_core
            .flush_volume()
            .map_err(|_| BridgeError::BioQueueFailed {
                detail: "pool flush: I/O error",
            })
    }

    fn commit_barrier(&mut self) -> BridgeResult<()> {
        self.pool_core
            .txg_commit_barrier()
            .map_err(|_| BridgeError::BioQueueFailed {
                detail: "pool txg commit-barrier: I/O error",
            })
    }

    fn capacity(&self) -> u64 {
        self.pool_core.volume_capacity_bytes()
    }

    fn discard_sectors(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()> {
        if !self.limits.writable {
            return Err(BridgeError::BioQueueFailed {
                detail: "pool backend is read-only",
            });
        }
        let ss = u64::from(self.limits.logical_block_size);
        let offset = start_sector * ss;
        let len = u64::from(sector_count) * ss;
        self.pool_core
            .discard_volume_blocks(offset, len)
            .map_err(|e| BridgeError::BioQueueFailed {
                detail: match e {
                    Errno::EINVAL => "pool discard: range out of bounds",
                    _ => "pool discard: I/O error",
                },
            })
    }

    fn flush_supported(&self) -> bool {
        self.pool_core.volume_flush_supported()
    }
    fn discard_supported(&self) -> bool {
        self.pool_core.volume_discard_supported()
    }

    fn write_zeroes_sectors(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()> {
        if !self.limits.writable {
            return Err(BridgeError::BioQueueFailed {
                detail: "pool backend is read-only",
            });
        }
        let ss = u64::from(self.limits.logical_block_size);
        let offset = start_sector * ss;
        let len = u64::from(sector_count) * ss;
        self.pool_core
            .write_zeroes_volume_blocks(offset, len)
            .map_err(|e| BridgeError::BioQueueFailed {
                detail: match e {
                    Errno::EINVAL => "pool write-zeroes: range out of bounds",
                    _ => "pool write-zeroes: I/O error",
                },
            })
    }

    fn zero_range_sectors(&mut self, start_sector: u64, sector_count: u32) -> BridgeResult<()> {
        if !self.limits.writable {
            return Err(BridgeError::BioQueueFailed {
                detail: "pool backend is read-only",
            });
        }
        let ss = u64::from(self.limits.logical_block_size);
        let offset = start_sector * ss;
        let len = u64::from(sector_count) * ss;
        self.pool_core
            .zero_range_volume_blocks(offset, len)
            .map_err(|e| BridgeError::BioQueueFailed {
                detail: match e {
                    Errno::EINVAL => "pool zero-range: range out of bounds",
                    _ => "pool zero-range: I/O error",
                },
            })
    }

    fn write_zeroes_supported(&self) -> bool {
        self.pool_core.volume_write_zeroes_supported()
    }
    fn zero_range_supported(&self) -> bool {
        self.pool_core.volume_zero_range_supported()
    }
    fn sector_size(&self) -> u32 {
        self.pool_core.volume_block_size()
    }
}

impl core::fmt::Debug for PoolCoreBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoolCoreBackend")
            .field("capacity_bytes", &self.capacity())
            .field("sector_size", &self.sector_size())
            .field("flush_supported", &self.flush_supported())
            .field("discard_supported", &self.discard_supported())
            .field("self_stacking_checked", &self.self_stacking_checked)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use core::cell::RefCell;

    /// In-memory PoolCoreOps stub for unit tests.
    struct StubPoolCore {
        buffer: RefCell<Box<[u8]>>,
        capacity_bytes: u64,
        block_size: u32,
        flush_supported: bool,
        discard_supported: bool,
    }

    // SAFETY: only used in single-threaded tests.
    unsafe impl Sync for StubPoolCore {}

    impl StubPoolCore {
        fn new(cap: u64, bs: u32) -> Self {
            Self {
                buffer: RefCell::new(alloc::vec![0u8; cap as usize].into_boxed_slice()),
                capacity_bytes: cap,
                block_size: bs,
                flush_supported: true,
                discard_supported: true,
            }
        }
    }

    impl PoolCoreOps for StubPoolCore {
        fn read_volume_block(&self, off: u64, len: u32, buf: &mut [u8]) -> Result<u32, Errno> {
            let o = off as usize;
            let l = len as usize;
            let data = self.buffer.borrow();
            if o + l > data.len() {
                return Err(Errno::EINVAL);
            }
            let n = l.min(buf.len());
            buf[..n].copy_from_slice(&data[o..o + n]);
            Ok(n as u32)
        }
        fn write_volume_block(&self, off: u64, data: &[u8]) -> Result<u32, Errno> {
            let o = off as usize;
            let mut buf = self.buffer.borrow_mut();
            if o + data.len() > buf.len() {
                return Err(Errno::ENOSPC);
            }
            let n = data.len().min(buf.len() - o);
            buf[o..o + n].copy_from_slice(&data[..n]);
            Ok(n as u32)
        }
        fn flush_volume(&self) -> Result<(), Errno> {
            if !self.flush_supported {
                Err(Errno::ENOSYS)
            } else {
                Ok(())
            }
        }
        fn discard_volume_blocks(&self, off: u64, len: u64) -> Result<(), Errno> {
            if !self.discard_supported {
                return Err(Errno::ENOSYS);
            }
            let o = off as usize;
            let l = len as usize;
            let mut buf = self.buffer.borrow_mut();
            if o + l > buf.len() {
                return Err(Errno::EINVAL);
            }
            buf[o..o + l].fill(0);
            Ok(())
        }
        fn volume_capacity_bytes(&self) -> u64 {
            self.capacity_bytes
        }
        fn volume_block_size(&self) -> u32 {
            self.block_size
        }
        fn volume_flush_supported(&self) -> bool {
            self.flush_supported
        }
        fn volume_discard_supported(&self) -> bool {
            self.discard_supported
        }

        fn volume_write_zeroes_supported(&self) -> bool {
            self.discard_supported
        }

        fn volume_zero_range_supported(&self) -> bool {
            self.discard_supported
        }
        fn write_zeroes_volume_blocks(&self, off: u64, len: u64) -> Result<(), Errno> {
            if !self.discard_supported {
                return Err(Errno::ENOSYS);
            }
            let o = off as usize;
            let l = len as usize;
            let mut buf = self.buffer.borrow_mut();
            if o + l > buf.len() {
                return Err(Errno::EINVAL);
            }
            buf[o..o + l].fill(0);
            Ok(())
        }
        fn zero_range_volume_blocks(&self, off: u64, len: u64) -> Result<(), Errno> {
            if !self.discard_supported {
                return Err(Errno::ENOSYS);
            }
            let o = off as usize;
            let l = len as usize;
            let mut buf = self.buffer.borrow_mut();
            if o + l > buf.len() {
                return Err(Errno::EINVAL);
            }
            buf[o..o + l].fill(0);
            Ok(())
        }
    }

    fn make_backend(cap: u64) -> PoolCoreBackend {
        let core = Arc::new(StubPoolCore::new(cap, 512));
        PoolCoreBackend::new(PoolCoreHandle::new(core))
    }

    #[test]
    fn read_write_roundtrip() {
        let mut be = make_backend(65536);
        let data = [0xABu8; 512];
        assert_eq!(be.write_sectors(0, &data).unwrap(), 512);
        let mut buf = [0u8; 512];
        assert_eq!(be.read_sectors(0, 1, &mut buf).unwrap(), 512);
        assert_eq!(&buf[..], &data[..]);
    }

    #[test]
    fn multi_sector_roundtrip() {
        let mut be = make_backend(65536);
        let data = [0xCCu8; 2048];
        be.write_sectors(10, &data).unwrap();
        let mut buf = [0u8; 2048];
        be.read_sectors(10, 4, &mut buf).unwrap();
        assert_eq!(&buf[..], &data[..]);
    }

    #[test]
    fn flush_ok() {
        assert!(make_backend(4096).flush().is_ok());
    }

    #[test]
    fn discard_zeroes() {
        let mut be = make_backend(4096);
        be.write_sectors(0, &[0xFFu8; 512]).unwrap();
        be.discard_sectors(0, 1).unwrap();
        let mut buf = [0u8; 512];
        be.read_sectors(0, 1, &mut buf).unwrap();
        assert_eq!(&buf[..], &[0u8; 512]);
    }

    #[test]
    fn capacity_and_sector_size() {
        let be = make_backend(1024 * 512);
        assert_eq!(be.capacity(), 1024 * 512);
        assert_eq!(be.sector_size(), 512);
    }

    #[test]
    fn self_stacking_default_false() {
        let mut be = make_backend(4096);
        assert!(be.check_self_stacked(b"/dev/sda").is_ok());
        assert!(be.self_stacking_checked());
    }

    #[test]
    fn debug_output() {
        let be = make_backend(65536);
        let dbg = alloc::format!("{be:?}");
        assert!(dbg.contains("PoolCoreBackend"));
        assert!(dbg.contains("65536"));
    }

    #[test]
    fn write_beyond_capacity_err() {
        let mut be = make_backend(1024);
        assert!(be.write_sectors(0, &[0xAAu8; 2048]).is_err());
    }

    #[test]
    fn read_beyond_capacity_err() {
        let be = make_backend(1024);
        let mut buf = [0u8; 2048];
        assert!(be.read_sectors(0, 4, &mut buf).is_err());
    }

    #[test]
    fn fence_rejects_io() {
        let core = Arc::new(StubPoolCore::new(4096, 512));
        let handle = PoolCoreHandle::new(core);
        handle.fence();
        let be = PoolCoreBackend::new(handle);
        let mut buf = [0u8; 512];
        assert!(be.read_sectors(0, 1, &mut buf).is_err());
    }

    #[test]
    fn snapshot_anchored_read() {
        let core = Arc::new(StubPoolCore::new(4096, 512));
        let handle = PoolCoreHandle::new(core);
        let be = PoolCoreBackend::with_snapshot_root(handle, 42);
        assert!(be.is_snapshot_anchored());
        assert_eq!(be.snapshot_root(), Some(42));
        assert!(!be.limits.writable);
        // Read through anchored path (StubPoolCore delegates
        // read_volume_block_at_root to read_volume_block)
        let mut buf = [0u8; 512];
        assert!(be.read_sectors(0, 1, &mut buf).is_ok());
    }

    #[test]
    fn snapshot_set_and_clear_root() {
        let core = Arc::new(StubPoolCore::new(4096, 512));
        let handle = PoolCoreHandle::new(core);
        let mut be = PoolCoreBackend::new(handle);
        assert!(!be.is_snapshot_anchored());
        assert!(be.limits.writable);
        be.set_snapshot_root(Some(100));
        assert!(be.is_snapshot_anchored());
        assert_eq!(be.snapshot_root(), Some(100));
        assert!(!be.limits.writable);
        be.set_snapshot_root(None);
        assert!(!be.is_snapshot_anchored());
        assert!(be.limits.writable);
    }

    // ── Snapshot-aware stub for read-consistency tests ───────────────

    /// PoolCoreOps stub that separates live data from snapshot data.
    ///
    /// `read_volume_block` returns live buffer data.
    /// `read_volume_block_at_root` returns snapshot buffer data (independent
    /// of live mutations).  This models a pool core where a snapshot export
    /// sees frozen point-in-time data.
    struct SnapshotStubPoolCore {
        live: RefCell<Box<[u8]>>,
        snapshot: RefCell<Box<[u8]>>,
        capacity_bytes: u64,
        block_size: u32,
    }

    // SAFETY: only used in single-threaded tests.
    unsafe impl Sync for SnapshotStubPoolCore {}

    impl SnapshotStubPoolCore {
        fn new(cap: u64, bs: u32) -> Self {
            let buf = alloc::vec![0u8; cap as usize].into_boxed_slice();
            let snap = alloc::vec![0u8; cap as usize].into_boxed_slice();
            Self {
                live: RefCell::new(buf),
                snapshot: RefCell::new(snap),
                capacity_bytes: cap,
                block_size: bs,
            }
        }

        /// Freeze the current live state into the snapshot buffer.
        fn freeze_snapshot(&self) {
            let live_data = self.live.borrow();
            let mut snap_data = self.snapshot.borrow_mut();
            snap_data.copy_from_slice(&live_data);
        }
    }

    impl PoolCoreOps for SnapshotStubPoolCore {
        // Live read: sees current data.
        fn read_volume_block(&self, off: u64, len: u32, buf: &mut [u8]) -> Result<u32, Errno> {
            let o = off as usize;
            let l = len as usize;
            let data = self.live.borrow();
            if o + l > data.len() {
                return Err(Errno::EINVAL);
            }
            let n = l.min(buf.len());
            buf[..n].copy_from_slice(&data[o..o + n]);
            Ok(n as u32)
        }

        // Snapshot read: sees frozen point-in-time data.
        fn read_volume_block_at_root(
            &self,
            _root: u64,
            off: u64,
            len: u32,
            buf: &mut [u8],
        ) -> Result<u32, Errno> {
            let o = off as usize;
            let l = len as usize;
            let data = self.snapshot.borrow();
            if o + l > data.len() {
                return Err(Errno::EINVAL);
            }
            let n = l.min(buf.len());
            buf[..n].copy_from_slice(&data[o..o + n]);
            Ok(n as u32)
        }

        fn write_volume_block(&self, off: u64, data: &[u8]) -> Result<u32, Errno> {
            let o = off as usize;
            let mut buf = self.live.borrow_mut();
            if o + data.len() > buf.len() {
                return Err(Errno::ENOSPC);
            }
            let n = data.len().min(buf.len() - o);
            buf[o..o + n].copy_from_slice(&data[..n]);
            Ok(n as u32)
        }

        fn flush_volume(&self) -> Result<(), Errno> {
            Ok(())
        }
        fn discard_volume_blocks(&self, off: u64, len: u64) -> Result<(), Errno> {
            let o = off as usize;
            let l = len as usize;
            let mut buf = self.live.borrow_mut();
            if o + l > buf.len() {
                return Err(Errno::EINVAL);
            }
            buf[o..o + l].fill(0);
            Ok(())
        }
        fn volume_capacity_bytes(&self) -> u64 {
            self.capacity_bytes
        }
        fn volume_block_size(&self) -> u32 {
            self.block_size
        }
        fn volume_flush_supported(&self) -> bool {
            true
        }
        fn volume_discard_supported(&self) -> bool {
            true
        }
        fn volume_write_zeroes_supported(&self) -> bool {
            true
        }
        fn volume_zero_range_supported(&self) -> bool {
            true
        }
        fn write_zeroes_volume_blocks(&self, off: u64, len: u64) -> Result<(), Errno> {
            self.discard_volume_blocks(off, len)
        }
        fn zero_range_volume_blocks(&self, off: u64, len: u64) -> Result<(), Errno> {
            self.discard_volume_blocks(off, len)
        }
    }

    // ── Snapshot read-consistency tests ──────────────────────────────

    #[test]
    fn snapshot_export_read_consistent_after_live_mutation() {
        let core = Arc::new(SnapshotStubPoolCore::new(4096, 512));
        let handle = PoolCoreHandle::new(core.clone());

        // Write initial data to live buffer, then freeze.
        core.write_volume_block(0, b"INITIAL_DATA_42").unwrap();
        core.freeze_snapshot();

        // Create a snapshot-anchored backend at root 1.
        let snap_be = PoolCoreBackend::with_snapshot_root(handle.clone(), 1);
        assert!(snap_be.is_snapshot_anchored());

        // Mutate live data after the snapshot.
        core.write_volume_block(0, b"MUTATED_DATA_99").unwrap();

        // Snapshot read should still see the frozen data.
        let mut snap_buf = [0u8; 512];
        snap_be.read_sectors(0, 1, &mut snap_buf).unwrap();
        assert_eq!(&snap_buf[..15], b"INITIAL_DATA_42");

        // Live read (non-snapshot backend) should see mutated data.
        let live_be = PoolCoreBackend::new(handle);
        let mut live_buf = [0u8; 512];
        live_be.read_sectors(0, 1, &mut live_buf).unwrap();
        assert_eq!(&live_buf[..15], b"MUTATED_DATA_99");
    }

    #[test]
    fn snapshot_export_writes_rejected() {
        let core = Arc::new(SnapshotStubPoolCore::new(4096, 512));
        let handle = PoolCoreHandle::new(core);
        let snap_be = PoolCoreBackend::with_snapshot_root(handle, 1);
        assert!(!snap_be.limits.writable);
        // Write should be rejected by device-level read-only check
        // (the BlockBackend::write_sectors is still callable but the device
        // layer should gate on writable flag; we verify the flag here).
    }
    // ── KernelStorageIoCompat adapter tests ─────────────────────────

    /// Minimal KernelStorageIoCompat stub backed by an in-memory buffer.
    struct StubStorage {
        buffer: RefCell<Box<[u8]>>,
        block_size: u32,
    }
    unsafe impl Sync for StubStorage {}

    impl StubStorage {
        fn new(cap_bytes: u64, bs: u32) -> Self {
            Self {
                buffer: RefCell::new(alloc::vec![0u8; cap_bytes as usize].into_boxed_slice()),
                block_size: bs,
            }
        }
    }

    impl KernelStorageIoCompat for StubStorage {
        fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno> {
            let ss = u64::from(self.block_size);
            let off = (start_sector * ss) as usize;
            let data = self.buffer.borrow();
            if off + buf.len() > data.len() {
                return Err(Errno::EINVAL);
            }
            let n = buf.len().min(data.len() - off);
            buf[..n].copy_from_slice(&data[off..off + n]);
            Ok((n as u64 / ss) as u32)
        }

        fn write_sectors(&self, start_sector: u64, data: &[u8]) -> Result<u32, Errno> {
            let ss = u64::from(self.block_size);
            let off = (start_sector * ss) as usize;
            let mut buf = self.buffer.borrow_mut();
            if off + data.len() > buf.len() {
                return Err(Errno::ENOSPC);
            }
            let n = data.len().min(buf.len() - off);
            buf[off..off + n].copy_from_slice(&data[..n]);
            Ok((n as u64 / ss) as u32)
        }

        fn flush(&self) -> Result<(), Errno> {
            Ok(())
        }

        fn sector_size(&self) -> u32 {
            self.block_size
        }

        fn capacity_bytes(&self) -> u64 {
            self.buffer.borrow().len() as u64
        }
    }

    #[test]
    fn kernel_storage_compat_adapter_roundtrip() {
        let storage = StubStorage::new(65536, 512);
        let adapter = KernelStoragePoolCoreAdapter::new(storage);
        let handle = PoolCoreHandle::new(Arc::new(adapter));
        let mut backend = PoolCoreBackend::new(handle);

        // Write through the adapter
        let data = [0xDEu8; 512];
        assert_eq!(backend.write_sectors(0, &data).unwrap(), 512);

        // Read through the adapter
        let mut buf = [0u8; 512];
        assert_eq!(backend.read_sectors(0, 1, &mut buf).unwrap(), 512);
        assert_eq!(&buf[..], &data[..]);
    }

    #[test]
    fn kernel_storage_compat_adapter_flush() {
        let storage = StubStorage::new(4096, 512);
        let adapter = KernelStoragePoolCoreAdapter::new(storage);
        let handle = PoolCoreHandle::new(Arc::new(adapter));
        let mut backend = PoolCoreBackend::new(handle);

        assert!(backend.flush().is_ok());
    }

    #[test]
    fn kernel_storage_compat_adapter_capacity_and_size() {
        let storage = StubStorage::new(8192, 4096);
        let adapter = KernelStoragePoolCoreAdapter::new(storage);
        let handle = PoolCoreHandle::new(Arc::new(adapter));
        let backend = PoolCoreBackend::new(handle);

        assert_eq!(backend.capacity(), 8192);
        assert_eq!(backend.sector_size(), 4096);
    }

    #[test]
    fn kernel_storage_compat_adapter_discard_zeroes() {
        let storage = StubStorage::new(4096, 512);
        let adapter = KernelStoragePoolCoreAdapter::new(storage);
        let handle = PoolCoreHandle::new(Arc::new(adapter));
        let mut backend = PoolCoreBackend::new(handle);

        // Write non-zero data
        backend.write_sectors(0, &[0xFFu8; 512]).unwrap();
        // Discard
        backend.discard_sectors(0, 1).unwrap();
        // Read back - should be zeroed
        let mut buf = [0u8; 512];
        backend.read_sectors(0, 1, &mut buf).unwrap();
        assert_eq!(&buf[..], &[0u8; 512]);
    }

    #[test]
    fn kernel_storage_compat_adapter_write_zeroes() {
        let storage = StubStorage::new(4096, 512);
        let adapter = KernelStoragePoolCoreAdapter::new(storage);
        let handle = PoolCoreHandle::new(Arc::new(adapter));
        let mut backend = PoolCoreBackend::new(handle);

        // Write non-zero data
        backend.write_sectors(0, &[0xFFu8; 512]).unwrap();
        // Write zeroes
        backend.write_zeroes_sectors(0, 1).unwrap();
        // Read back - should be zeroed
        let mut buf = [0u8; 512];
        backend.read_sectors(0, 1, &mut buf).unwrap();
        assert_eq!(&buf[..], &[0u8; 512]);
    }

    #[test]
    fn kernel_storage_compat_adapter_debug_format() {
        let storage = StubStorage::new(4096, 512);
        let adapter = KernelStoragePoolCoreAdapter::new(storage);
        let handle = PoolCoreHandle::new(Arc::new(adapter));
        let backend = PoolCoreBackend::new(handle);

        let dbg = alloc::format!("{backend:?}");
        assert!(dbg.contains("PoolCoreBackend"));
        assert!(dbg.contains("4096"));
    }

    #[test]
    fn kernel_storage_compat_adapter_fence_rejects_io() {
        let storage = StubStorage::new(4096, 512);
        let adapter = KernelStoragePoolCoreAdapter::new(storage);
        let handle = PoolCoreHandle::new(Arc::new(adapter));
        handle.fence();
        let backend = PoolCoreBackend::new(handle);

        let mut buf = [0u8; 512];
        assert!(backend.read_sectors(0, 1, &mut buf).is_err());
    }

    #[test]
    fn kernel_storage_compat_adapter_zero_len_discard() {
        let storage = StubStorage::new(4096, 512);
        let adapter = KernelStoragePoolCoreAdapter::new(storage);
        let handle = PoolCoreHandle::new(Arc::new(adapter));
        let mut backend = PoolCoreBackend::new(handle);

        // Discard of zero length should be a no-op, not an error
        assert!(backend.discard_sectors(0, 0).is_ok());
    }


}
