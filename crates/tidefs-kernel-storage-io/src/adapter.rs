//! [`KernelStorageAdapter`] bridges a byte-offset [`RawBlockIo`] backend
//! into the sector-aligned [`KernelStorageIo`] trait.
//!
//! # Offset normalization
//!
//! The adapter converts sector numbers to byte offsets and validates
//! sector alignment on every call.
//!
//! # Example
//!
//! ```ignore
//! use tidefs_kernel_storage_io::{KernelStorageAdapter, KernelStorageIo, RawBlockIo};
//!
//! struct MyBackend { /* … */ }
//! impl RawBlockIo for MyBackend { /* … */ }
//!
//! let backend = MyBackend::new();
//! let adapter = KernelStorageAdapter::new(backend);
//! let mut buf = [0u8; 4096];
//! adapter.read_sectors(0, &mut buf)?;
//! ```

use core::fmt;

use tidefs_types_vfs_core::Errno;

use crate::traits::{KernelStorageIo, RawBlockIo};

// ── KernelStorageAdapter ───────────────────────────────────────────────

/// Generic adapter that wraps any [`RawBlockIo`] backend and presents a
/// sector-aligned [`KernelStorageIo`] interface.
///
/// The adapter is zero-overhead: all methods inline through to the
/// backend after sector-to-byte translation.
pub struct KernelStorageAdapter<B: RawBlockIo> {
    backend: B,
}

impl<B: RawBlockIo> KernelStorageAdapter<B> {
    /// Wrap a [`RawBlockIo`] backend.
    #[inline]
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Return a reference to the inner backend.
    #[inline]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Return a mutable reference to the inner backend.
    #[inline]
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
}

impl<B: RawBlockIo> KernelStorageIo for KernelStorageAdapter<B> {
    #[inline]
    fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno> {
        let ss = u64::from(self.sector_size());
        let offset = start_sector.checked_mul(ss).ok_or(Errno::EINVAL)?;
        let len = buf.len() as u64;
        if len % ss != 0 {
            return Err(Errno::EINVAL);
        }
        let byte_count = self.backend.read_bytes(offset, buf)?;
        Ok(byte_count / self.sector_size())
    }

    #[inline]
    fn write_sectors(&self, start_sector: u64, data: &[u8]) -> Result<u32, Errno> {
        let ss = u64::from(self.sector_size());
        let offset = start_sector.checked_mul(ss).ok_or(Errno::EINVAL)?;
        let len = data.len() as u64;
        if len % ss != 0 {
            return Err(Errno::EINVAL);
        }
        let byte_count = self.backend.write_bytes(offset, data)?;
        Ok(byte_count / self.sector_size())
    }

    #[inline]
    fn flush(&self) -> Result<(), Errno> {
        self.backend.flush_bytes()
    }

    #[inline]
    fn sector_size(&self) -> u32 {
        self.backend.block_size()
    }

    #[inline]
    fn capacity_sectors(&self) -> u64 {
        let bs = u64::from(self.backend.block_size());
        if bs == 0 {
            return 0;
        }
        self.backend.total_capacity_bytes() / bs
    }
}

impl<B: RawBlockIo + fmt::Debug> fmt::Debug for KernelStorageAdapter<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelStorageAdapter")
            .field("sector_size", &self.sector_size())
            .field("capacity_sectors", &self.capacity_sectors())
            .field("backend", &self.backend)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::boxed::Box;
    use std::sync::Mutex;

    // ── In-memory test backend ───────────────────────────────────────

    /// Simple in-memory `RawBlockIo` for unit testing.
    #[derive(Debug)]
    struct MemoryBackend {
        buffer: Mutex<Box<[u8]>>,
        block_size: u32,
        flush_supported: bool,
        flush_count: Mutex<u64>,
    }

    impl MemoryBackend {
        fn new(capacity_bytes: u64, block_size: u32) -> Self {
            Self {
                buffer: Mutex::new(alloc::vec![0u8; capacity_bytes as usize].into_boxed_slice()),
                block_size,
                flush_supported: true,
                flush_count: Mutex::new(0),
            }
        }

        fn flush_count(&self) -> u64 {
            *self.flush_count.lock().unwrap()
        }
    }

    impl RawBlockIo for MemoryBackend {
        fn read_bytes(&self, offset_bytes: u64, buf: &mut [u8]) -> Result<u32, Errno> {
            let off = offset_bytes as usize;
            let data = self.buffer.lock().unwrap();
            if off + buf.len() > data.len() {
                return Err(Errno::EINVAL);
            }
            let n = buf.len().min(data.len() - off);
            buf[..n].copy_from_slice(&data[off..off + n]);
            Ok(n as u32)
        }

        fn write_bytes(&self, offset_bytes: u64, data: &[u8]) -> Result<u32, Errno> {
            let off = offset_bytes as usize;
            let mut buf = self.buffer.lock().unwrap();
            if off + data.len() > buf.len() {
                return Err(Errno::ENOSPC);
            }
            let n = data.len().min(buf.len() - off);
            buf[off..off + n].copy_from_slice(&data[..n]);
            Ok(n as u32)
        }

        fn flush_bytes(&self) -> Result<(), Errno> {
            if !self.flush_supported {
                return Err(Errno::ENOSYS);
            }
            *self.flush_count.lock().unwrap() += 1;
            Ok(())
        }

        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn total_capacity_bytes(&self) -> u64 {
            self.buffer.lock().unwrap().len() as u64
        }
    }

    fn make_adapter(cap: u64, bs: u32) -> KernelStorageAdapter<MemoryBackend> {
        KernelStorageAdapter::new(MemoryBackend::new(cap, bs))
    }

    // ── Sector-aligned read/write roundtrip ─────────────────────────

    #[test]
    fn single_sector_roundtrip_512() {
        let adapter = make_adapter(1024 * 512, 512);
        let data = [0xABu8; 512];
        assert_eq!(adapter.write_sectors(0, &data).unwrap(), 1);
        let mut buf = [0u8; 512];
        assert_eq!(adapter.read_sectors(0, &mut buf).unwrap(), 1);
        assert_eq!(&buf[..], &data[..]);
    }

    #[test]
    fn multi_sector_roundtrip_4096() {
        let adapter = make_adapter(16 * 4096, 4096);
        let data = [0xCCu8; 8192]; // 2 sectors
        assert_eq!(adapter.write_sectors(3, &data).unwrap(), 2);
        let mut buf = [0u8; 8192];
        assert_eq!(adapter.read_sectors(3, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..], &data[..]);
    }

    #[test]
    fn sector_boundary_crossing() {
        let adapter = make_adapter(4 * 512, 512);
        let data = [0xDDu8; 1024];
        adapter.write_sectors(1, &data).unwrap();
        // Read individual sectors back
        let mut buf0 = [0u8; 512];
        let mut buf1 = [0u8; 512];
        adapter.read_sectors(1, &mut buf0).unwrap();
        adapter.read_sectors(2, &mut buf1).unwrap();
        assert_eq!(&buf0[..], &data[..512]);
        assert_eq!(&buf1[..], &data[512..]);
    }

    // ── Sector alignment validation ─────────────────────────────────

    #[test]
    fn read_rejects_unaligned_buffer() {
        let adapter = make_adapter(2048, 512);
        let mut buf = [0u8; 513]; // not a multiple of 512
        let err = adapter.read_sectors(0, &mut buf).unwrap_err();
        assert_eq!(err, Errno::EINVAL);
    }

    #[test]
    fn write_rejects_unaligned_buffer() {
        let adapter = make_adapter(2048, 512);
        let data = [0u8; 513];
        let err = adapter.write_sectors(0, &data).unwrap_err();
        assert_eq!(err, Errno::EINVAL);
    }

    #[test]
    fn read_beyond_capacity() {
        let adapter = make_adapter(1024, 512);
        let mut buf = [0u8; 512];
        let err = adapter.read_sectors(3, &mut buf).unwrap_err();
        assert_eq!(err, Errno::EINVAL);
    }

    #[test]
    fn write_beyond_capacity() {
        let adapter = make_adapter(1024, 512);
        let data = [0u8; 512];
        let err = adapter.write_sectors(3, &data).unwrap_err();
        assert_eq!(err, Errno::ENOSPC);
    }

    #[test]
    fn write_overflow_start_sector() {
        let adapter = make_adapter(8 * 512, 512);
        let data = [0u8; 512];
        // u64::MAX * 512 overflows in checked_mul -> EINVAL
        let err = adapter.write_sectors(u64::MAX, &data).unwrap_err();
        assert_eq!(err, Errno::EINVAL);
    }

    #[test]
    fn read_overflow_start_sector() {
        let adapter = make_adapter(8 * 512, 512);
        let mut buf = [0u8; 512];
        let err = adapter.read_sectors(u64::MAX, &mut buf).unwrap_err();
        assert_eq!(err, Errno::EINVAL);
    }

    // ── Flush barrier ───────────────────────────────────────────────

    #[test]
    fn flush_increments_counter() {
        let backend = MemoryBackend::new(4096, 512);
        let adapter = KernelStorageAdapter::new(backend);
        adapter.flush().unwrap();
        adapter.flush().unwrap();
        adapter.flush().unwrap();
        assert_eq!(adapter.backend().flush_count(), 3);
    }

    #[test]
    fn flush_unsupported_returns_enosys() {
        let mut backend = MemoryBackend::new(4096, 512);
        backend.flush_supported = false;
        let adapter = KernelStorageAdapter::new(backend);
        let err = adapter.flush().unwrap_err();
        assert_eq!(err, Errno::ENOSYS);
    }

    // ── Capacity and sector size ────────────────────────────────────

    #[test]
    fn sector_size_propagates() {
        let adapter = make_adapter(65536, 4096);
        assert_eq!(adapter.sector_size(), 4096);
    }

    #[test]
    fn capacity_sectors_512() {
        let adapter = make_adapter(1024 * 512, 512);
        assert_eq!(adapter.capacity_sectors(), 1024);
    }

    #[test]
    fn capacity_sectors_4096() {
        let adapter = make_adapter(16 * 4096, 4096);
        assert_eq!(adapter.capacity_sectors(), 16);
    }

    #[test]
    fn capacity_bytes_derived() {
        let adapter = make_adapter(8 * 512, 512);
        assert_eq!(adapter.capacity_bytes(), 4096);
    }

    #[test]
    fn capacity_sectors_zero_block_size() {
        let mut backend = MemoryBackend::new(4096, 0);
        backend.block_size = 0;
        let adapter = KernelStorageAdapter::new(backend);
        assert_eq!(adapter.capacity_sectors(), 0);
    }

    // ── validate_range ──────────────────────────────────────────────

    #[test]
    fn validate_range_in_bounds() {
        let adapter = make_adapter(1024 * 512, 512);
        assert!(adapter.validate_range(0, 1024).is_ok());
        assert!(adapter.validate_range(500, 100).is_ok());
        assert!(adapter.validate_range(1023, 1).is_ok());
    }

    #[test]
    fn validate_range_out_of_bounds() {
        let adapter = make_adapter(1024 * 512, 512);
        assert_eq!(adapter.validate_range(1024, 1).unwrap_err(), Errno::EINVAL);
        assert_eq!(adapter.validate_range(0, 1025).unwrap_err(), Errno::EINVAL);
        assert_eq!(adapter.validate_range(1023, 2).unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn validate_range_overflow() {
        let adapter = make_adapter(100, 512);
        assert_eq!(
            adapter.validate_range(u64::MAX, 1).unwrap_err(),
            Errno::EINVAL
        );
    }

    // ── Debug output ────────────────────────────────────────────────

    #[test]
    fn debug_format() {
        let adapter = make_adapter(4096, 512);
        let dbg = alloc::format!("{adapter:?}");
        assert!(dbg.contains("KernelStorageAdapter"));
        assert!(dbg.contains("sector_size"));
        assert!(dbg.contains("capacity_sectors"));
    }

    // ── Object safety check ─────────────────────────────────────────

    #[test]
    fn kernel_storage_io_is_object_safe() {
        let adapter = make_adapter(4096, 512);
        let _dyn: &dyn KernelStorageIo = &adapter;
    }

    #[test]
    fn raw_block_io_is_object_safe() {
        let backend = MemoryBackend::new(4096, 512);
        let _dyn: &dyn RawBlockIo = &backend;
    }
}
