//! Core storage I/O traits for kernel-mode block-device access.
//!
//! [`KernelStorageIo`] is the canonical portable trait consumed by TideFS
//! durability subsystems (intent-log append, txg commit-barrier). It
//! presents sector-aligned read/write/flush primitives with kernel-errno
//! error translation.
//!
//! [`RawBlockIo`] is a lower-level byte-offset trait that adapters bridge
//! into [`KernelStorageIo`].

use tidefs_types_vfs_core::Errno;

/// Explicit capability report for a kernel pool I/O authority.
///
/// Mount and durability paths use this before accepting a lower device as
/// authoritative. Unsupported optional operations must be visible here instead
/// of being discovered only through inherited `ENOSYS` defaults.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelStorageIoCapabilities {
    pub read: bool,
    pub write: bool,
    pub flush: bool,
    pub discard: bool,
    pub write_zeroes: bool,
    pub zero_range: bool,
    pub teardown: bool,
    pub sector_size: u32,
    pub capacity_sectors: u64,
}

impl KernelStorageIoCapabilities {
    #[inline]
    pub const fn unsupported() -> Self {
        Self {
            read: false,
            write: false,
            flush: false,
            discard: false,
            write_zeroes: false,
            zero_range: false,
            teardown: false,
            sector_size: 0,
            capacity_sectors: 0,
        }
    }

    #[inline]
    pub const fn read_write_flush(sector_size: u32, capacity_sectors: u64, teardown: bool) -> Self {
        Self {
            read: true,
            write: true,
            flush: true,
            discard: false,
            write_zeroes: false,
            zero_range: false,
            teardown,
            sector_size,
            capacity_sectors,
        }
    }

    #[inline]
    pub fn capacity_bytes(self) -> u64 {
        self.capacity_sectors
            .saturating_mul(u64::from(self.sector_size))
    }

    #[inline]
    pub const fn has_mounted_authority(self) -> bool {
        self.read
            && self.write
            && self.flush
            && self.teardown
            && self.sector_size != 0
            && self.capacity_sectors != 0
    }
}

// ── KernelStorageIo ────────────────────────────────────────────────────

/// Portable sector-aligned block-I/O trait for kernel-mode storage.
///
/// Every method uses sector addressing (not byte offsets) and returns
/// Linux `Errno` values. The sector size is queried via [`sector_size`].
///
/// # Contract
///
/// - `buf.len()` and `data.len()` must be integer multiples of
///   [`sector_size`](Self::sector_size).
/// - `start_sector + sector_count` must not exceed
///   [`capacity_sectors`](Self::capacity_sectors).
/// - A caller that needs durability must call [`flush`](Self::flush) after
///   a series of writes and wait for `Ok(())`.
///
/// Implementations must be `Send + Sync` so they can be held behind an
/// `Arc` in multi-threaded kernel dispatch.
pub trait KernelStorageIo: Send + Sync {
    /// Report the lower-device operations this authority deliberately supports.
    fn capabilities(&self) -> KernelStorageIoCapabilities;

    /// Read `buf.len() / sector_size()` sectors starting at `start_sector`.
    ///
    /// Returns the number of **sectors** successfully read.
    ///
    /// # Errors
    ///
    /// - `EINVAL` when `start_sector` is out of range or the buffer
    ///   length is not a multiple of the sector size.
    /// - `EIO` on uncorrectable read error.
    fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno>;

    /// Write `data` to the device starting at `start_sector`.
    ///
    /// Returns the number of **sectors** successfully written.
    ///
    /// # Errors
    ///
    /// - `EINVAL` when `start_sector` is out of range or the data length
    ///   is not a multiple of the sector size.
    /// - `ENOSPC` when the write would exceed device capacity.
    /// - `EIO` on uncorrectable write error.
    fn write_sectors(&self, start_sector: u64, data: &[u8]) -> Result<u32, Errno>;

    /// Flush any cached writes to durable media (write barrier / FUA).
    ///
    /// After `Ok(())` returns, all preceding writes are stable.
    ///
    /// # Errors
    ///
    /// - `EIO` when the flush fails.
    /// - `ENOSYS` when the backend does not support flush semantics.
    fn flush(&self) -> Result<(), Errno>;

    /// Discard a range of sectors.
    fn discard_sectors(&self, _start_sector: u64, _sector_count: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Write zeroes to a range of sectors; subsequent reads must return zeroes.
    fn write_zeroes(&self, _start_sector: u64, _sector_count: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Zero a range without making it unreadable or exposing stale data.
    fn zero_range(&self, _start_sector: u64, _sector_count: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Tear down lower-device authority after the final sync path.
    fn teardown(&self) -> Result<(), Errno>;

    /// Size of a single sector in bytes (typically 512 or 4096).
    fn sector_size(&self) -> u32;

    /// Total device capacity in sectors.
    fn capacity_sectors(&self) -> u64;

    // ── Derived helpers ──────────────────────────────────────────────

    /// Total device capacity in bytes.
    #[inline]
    fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors()
            .saturating_mul(u64::from(self.sector_size()))
    }

    /// Check whether `start_sector` and `len` (sector count) are in range.
    #[inline]
    fn validate_range(&self, start_sector: u64, sector_count: u64) -> Result<(), Errno> {
        let end = start_sector
            .checked_add(sector_count)
            .ok_or(Errno::EINVAL)?;
        if end > self.capacity_sectors() {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }
}

// ── RawBlockIo ─────────────────────────────────────────────────────────

/// Low-level byte-offset block I/O trait used by [`KernelStorageAdapter`].
///
/// This is the interface that concrete block-device backends implement.
/// The adapter translates sector-aligned [`KernelStorageIo`] calls into
/// these byte-offset operations.
pub trait RawBlockIo: Send + Sync {
    /// Report the lower-device operations this backend deliberately supports.
    fn capabilities(&self) -> KernelStorageIoCapabilities;

    /// Read bytes from the given byte offset.
    ///
    /// Returns the number of bytes successfully read.
    ///
    /// # Errors
    ///
    /// - `EINVAL` when the offset + length exceeds capacity.
    /// - `EIO` on uncorrectable read error.
    fn read_bytes(&self, offset_bytes: u64, buf: &mut [u8]) -> Result<u32, Errno>;

    /// Write bytes at the given byte offset.
    ///
    /// Returns the number of bytes successfully written.
    ///
    /// # Errors
    ///
    /// - `EINVAL` when the offset + length exceeds capacity.
    /// - `ENOSPC` when out of space.
    /// - `EIO` on uncorrectable write error.
    fn write_bytes(&self, offset_bytes: u64, data: &[u8]) -> Result<u32, Errno>;

    /// Flush any cached writes to durable media.
    ///
    /// # Errors
    ///
    /// - `EIO` when the flush fails.
    /// - `ENOSYS` when the backend does not support flush semantics.
    fn flush_bytes(&self) -> Result<(), Errno>;

    /// Discard a byte range.
    fn discard_bytes(&self, _offset_bytes: u64, _len_bytes: u64) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Write zeroes to a byte range.
    fn write_zeroes_bytes(&self, _offset_bytes: u64, _len_bytes: u64) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Zero a byte range without exposing stale data.
    fn zero_range_bytes(&self, _offset_bytes: u64, _len_bytes: u64) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Tear down the lower-device handle.
    fn teardown_bytes(&self) -> Result<(), Errno>;

    /// Sector size of the underlying device in bytes.
    fn block_size(&self) -> u32;

    /// Total device capacity in bytes.
    fn total_capacity_bytes(&self) -> u64;
}
