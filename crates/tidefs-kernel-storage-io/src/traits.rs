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

    /// Sector size of the underlying device in bytes.
    fn block_size(&self) -> u32;

    /// Total device capacity in bytes.
    fn total_capacity_bytes(&self) -> u64;
}
