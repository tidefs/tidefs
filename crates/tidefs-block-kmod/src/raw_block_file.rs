// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Persistent file-backed [`PoolCoreOps`] adapter for kernel block kmod.
//!
//! [`RawBlockFile`] opens a regular file (or block device node) and
//! exposes the [`super::pool_core_backend::PoolCoreOps`] trait for
//! read/write/flush/discard/zero operations. When configured as the
//! backing store for a block-kmod device, writes survive QEMU guest
//! reboots as long as the backing file lives on persistent storage
//! (e.g., a virtio-blk-backed filesystem).
//!
//! # Architecture
//!
//! Directly implements [`PoolCoreOps`] so no external crate dependency
//! is required -- this module compiles under both cargo (`std::fs::File`)
//! and Kbuild (kernel VFS: `filp_open`/`kernel_read`/`kernel_write`/
//! `vfs_fsync`).
//!
//! # Cargo path
//!
//! Under `#[cfg(not(CONFIG_RUST))]`, uses `std::fs::File` with
//! `read_exact_at`/`write_all_at` and `sync_all`.
//!
//! # Kbuild path
//!
//! Under `#[cfg(CONFIG_RUST)]`, uses kernel VFS primitives:
//!   - `filp_open` / `filp_close` for lifecycle
//!   - `kernel_read` / `kernel_write` for I/O
//!   - `vfs_fsync` for flush barriers
//!   - `vfs_llseek` for size queries
//!
//! ## Safety
//!
//! Kbuild path uses raw kernel pointers and unsafe C FFI. All unsafe
//! blocks are documented with `// SAFETY:` justifications. The device
//! mutex in `tidefs_block_kmod.rs` serializes all I/O.

#[cfg(not(CONFIG_RUST))]
extern crate std;

use crate::pool_core_backend::PoolCoreOps;

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::Errno;
#[cfg(not(CONFIG_RUST))]
use tidefs_vfs_engine::Errno;

// ── RawBlockFile ────────────────────────────────────────────────────────

pub struct RawBlockFile {
    #[cfg(not(CONFIG_RUST))]
    file: std::fs::File,
    #[cfg(CONFIG_RUST)]
    filp: *mut core::ffi::c_void,
    block_size: u32,
    capacity_bytes: u64,
}

#[cfg(CONFIG_RUST)]
// SAFETY: RawBlockFile owns a single live struct file pointer; runtime I/O is
// serialized by the block device mutex before reaching this adapter.
unsafe impl Send for RawBlockFile {}
#[cfg(CONFIG_RUST)]
// SAFETY: shared references call kernel_read/kernel_write/vfs_fsync through the
// serialized device path; Drop closes the owned filp exactly once.
unsafe impl Sync for RawBlockFile {}

impl RawBlockFile {
    #[cfg(not(CONFIG_RUST))]
    pub fn open(path: &std::path::Path, block_size: u32) -> Result<Self, Errno> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| Errno::EIO)?;
        let metadata = file.metadata().map_err(|_| Errno::EIO)?;
        Ok(Self {
            file,
            block_size,
            capacity_bytes: metadata.len(),
        })
    }

    #[cfg(CONFIG_RUST)]
    pub fn open(path: &[u8], block_size: u32) -> Result<Self, Errno> {
        const O_FLAGS: i32 = 0x2 | 0x8000; // O_RDWR | O_LARGEFILE
        // SAFETY: path is the NUL-terminated module parameter buffer supplied
        // by the Kbuild entrypoint; filp_open returns either a live filp or an
        // ERR_PTR/null sentinel checked below.
        let filp = unsafe { filp_open(path.as_ptr() as *const i8, O_FLAGS, 0u16) };
        if filp.is_null() || is_err_ptr(filp) {
            return Err(Errno::EIO);
        }
        // SAFETY: filp was returned live by filp_open; vfs_llseek only updates
        // kernel file position state for this owned file pointer.
        let sz = unsafe { vfs_llseek(filp, 0, 2) };
        if sz < 0 {
            // SAFETY: filp is the owned file pointer from filp_open and has
            // not been stored in RawBlockFile because open is failing.
            unsafe { filp_close(filp, core::ptr::null_mut()) };
            return Err(Errno::EIO);
        }
        Ok(Self {
            filp,
            block_size,
            capacity_bytes: sz as u64,
        })
    }

    /// Return the raw filp pointer for geometry extraction.
    ///
    /// Only available under Kbuild. The caller (typically the Kbuild
    /// module entrypoint) can cast this to `*mut bindings::file` and
    /// read `f_inode->i_rdev` for the backing block device's major/minor,
    /// plus `i_size` for the actual device capacity.
    #[cfg(CONFIG_RUST)]
    pub fn filp_ptr(&self) -> *mut core::ffi::c_void {
        self.filp
    }

    /// Return the raw capacity in bytes queried at open time.
    ///
    /// Unlike [`PoolCoreOps::volume_capacity_bytes`], this inherent
    /// method does not require the trait to be in scope.
    #[cfg(CONFIG_RUST)]
    pub fn raw_capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    /// Return the raw block size set at open time.
    #[cfg(CONFIG_RUST)]
    pub fn raw_block_size(&self) -> u32 {
        self.block_size
    }
}

impl PoolCoreOps for RawBlockFile {
    #[cfg(not(CONFIG_RUST))]
    fn read_volume_block(&self, off: u64, len: u32, buf: &mut [u8]) -> Result<u32, Errno> {
        use std::os::unix::fs::FileExt;
        if off.saturating_add(u64::from(len)) > self.capacity_bytes {
            return Err(Errno::EINVAL);
        }
        self.file
            .read_at(buf, off)
            .map(|n| n as u32)
            .map_err(|_| Errno::EIO)
    }

    #[cfg(CONFIG_RUST)]
    fn read_volume_block(&self, off: u64, len: u32, buf: &mut [u8]) -> Result<u32, Errno> {
        if off.saturating_add(u64::from(len)) > self.capacity_bytes {
            return Err(Errno::EINVAL);
        }
        let mut pos: i64 = off as i64;
        // SAFETY: self.filp is the live owned struct file; buf is a valid
        // writable slice and the byte range was bounds checked above.
        let ret = unsafe {
            kernel_read(
                self.filp,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                buf.len().min(len as usize),
                &mut pos as *mut i64,
            )
        };
        if ret < 0 {
            Err(Errno::EIO)
        } else {
            Ok(ret as u32)
        }
    }

    #[cfg(not(CONFIG_RUST))]
    fn write_volume_block(&self, off: u64, data: &[u8]) -> Result<u32, Errno> {
        use std::os::unix::fs::FileExt;
        if off.saturating_add(data.len() as u64) > self.capacity_bytes {
            return Err(Errno::ENOSPC);
        }
        self.file
            .write_at(data, off)
            .map(|n| n as u32)
            .map_err(|_| Errno::EIO)
    }

    #[cfg(CONFIG_RUST)]
    fn write_volume_block(&self, off: u64, data: &[u8]) -> Result<u32, Errno> {
        if off.saturating_add(data.len() as u64) > self.capacity_bytes {
            return Err(Errno::ENOSPC);
        }
        let mut pos: i64 = off as i64;
        // SAFETY: self.filp is the live owned struct file; data is a valid
        // initialized slice and the byte range was bounds checked above.
        let ret = unsafe {
            kernel_write(
                self.filp,
                data.as_ptr() as *const core::ffi::c_void,
                data.len(),
                &mut pos as *mut i64,
            )
        };
        if ret < 0 {
            Err(Errno::EIO)
        } else {
            Ok(ret as u32)
        }
    }

    fn flush_volume(&self) -> Result<(), Errno> {
        #[cfg(not(CONFIG_RUST))]
        {
            self.file.sync_all().map_err(|_| Errno::EIO)
        }
        #[cfg(CONFIG_RUST)]
        {
            // SAFETY: self.filp is the live owned struct file; vfs_fsync does
            // not access Rust memory and provides the kernel flush barrier.
            let ret = unsafe { vfs_fsync(self.filp, 0) };
            if ret < 0 {
                Err(Errno((-ret) as u16))
            } else {
                Ok(())
            }
        }
    }

    fn discard_volume_blocks(&self, offset_bytes: u64, len_bytes: u64) -> Result<(), Errno> {
        let end = offset_bytes.saturating_add(len_bytes);
        if end > self.capacity_bytes {
            return Err(Errno::EINVAL);
        }
        const ZB: usize = 8192;
        let zeroes = [0u8; ZB];
        let mut off = offset_bytes;
        let mut remaining = len_bytes;
        while remaining > 0 {
            let chunk = remaining.min(ZB as u64);
            let _ = self.write_volume_block(off, &zeroes[..chunk as usize])?;
            off += chunk;
            remaining -= chunk;
        }
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

// ── KernelStorageIoCompat impl ──────────────────────────────────────

impl crate::pool_core_backend::KernelStorageIoCompat for RawBlockFile {
    #[cfg(not(CONFIG_RUST))]
    fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno> {
        use std::os::unix::fs::FileExt;
        let ss = u64::from(self.block_size);
        let off = start_sector * ss;
        let len = buf.len() as u64;
        if off.saturating_add(len) > self.capacity_bytes {
            return Err(Errno::EINVAL);
        }
        let bytes = self.file.read_at(buf, off).map_err(|_| Errno::EIO)?;
        Ok((bytes as u64 / ss) as u32)
    }

    #[cfg(CONFIG_RUST)]
    fn read_sectors(&self, start_sector: u64, buf: &mut [u8]) -> Result<u32, Errno> {
        let ss = u64::from(self.block_size);
        let off = start_sector * ss;
        let len = buf.len() as u64;
        if off.saturating_add(len) > self.capacity_bytes {
            return Err(Errno::EINVAL);
        }
        let mut pos: i64 = off as i64;
        // SAFETY: self.filp is the live owned struct file; buf is a valid
        // writable slice and the sector range was bounds checked above.
        let ret = unsafe {
            kernel_read(
                self.filp,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                buf.len(),
                &mut pos as *mut i64,
            )
        };
        if ret < 0 {
            Err(Errno::EIO)
        } else {
            Ok((ret as u64 / ss) as u32)
        }
    }

    #[cfg(not(CONFIG_RUST))]
    fn write_sectors(&self, start_sector: u64, data: &[u8]) -> Result<u32, Errno> {
        use std::os::unix::fs::FileExt;
        let ss = u64::from(self.block_size);
        let off = start_sector * ss;
        let len = data.len() as u64;
        if off.saturating_add(len) > self.capacity_bytes {
            return Err(Errno::ENOSPC);
        }
        let bytes = self.file.write_at(data, off).map_err(|_| Errno::EIO)?;
        Ok((bytes as u64 / ss) as u32)
    }

    #[cfg(CONFIG_RUST)]
    fn write_sectors(&self, start_sector: u64, data: &[u8]) -> Result<u32, Errno> {
        let ss = u64::from(self.block_size);
        let off = start_sector * ss;
        let len = data.len() as u64;
        if off.saturating_add(len) > self.capacity_bytes {
            return Err(Errno::ENOSPC);
        }
        let mut pos: i64 = off as i64;
        // SAFETY: self.filp is the live owned struct file; data is a valid
        // initialized slice and the sector range was bounds checked above.
        let ret = unsafe {
            kernel_write(
                self.filp,
                data.as_ptr() as *const core::ffi::c_void,
                data.len(),
                &mut pos as *mut i64,
            )
        };
        if ret < 0 {
            Err(Errno::EIO)
        } else {
            Ok((ret as u64 / ss) as u32)
        }
    }

    fn flush(&self) -> Result<(), Errno> {
        self.flush_volume()
    }

    fn sector_size(&self) -> u32 {
        self.block_size
    }

    fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }
}

#[cfg(CONFIG_RUST)]
impl Drop for RawBlockFile {
    fn drop(&mut self) {
        if !self.filp.is_null() && !is_err_ptr(self.filp) {
            // SAFETY: self.filp is the owned file pointer from filp_open and
            // Drop is the single close point for RawBlockFile.
            unsafe { filp_close(self.filp, core::ptr::null_mut()) };
        }
    }
}

/// Inline replacement for kernel IS_ERR macro (not an exported symbol).
/// Returns true when ptr is an error pointer (value in [-MAX_ERRNO, 0)).
#[cfg(CONFIG_RUST)]
fn is_err_ptr(ptr: *mut core::ffi::c_void) -> bool {
    (ptr as usize) >= (usize::MAX - 4095)
}

#[cfg(CONFIG_RUST)]
extern "C" {
    fn filp_open(path: *const i8, flags: i32, mode: u16) -> *mut core::ffi::c_void;
    fn filp_close(filp: *mut core::ffi::c_void, id: *mut core::ffi::c_void) -> i32;
    fn kernel_read(
        filp: *mut core::ffi::c_void,
        buf: *mut core::ffi::c_void,
        count: usize,
        pos: *mut i64,
    ) -> isize;
    fn kernel_write(
        filp: *mut core::ffi::c_void,
        buf: *const core::ffi::c_void,
        count: usize,
        pos: *mut i64,
    ) -> isize;
    fn vfs_fsync(filp: *mut core::ffi::c_void, datasync: i32) -> i32;
    fn vfs_llseek(filp: *mut core::ffi::c_void, offset: i64, whence: i32) -> i64;
}

#[cfg(all(test, not(CONFIG_RUST)))]
mod tests {
    use super::*;

    #[test]
    fn rw_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backing.bin");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&alloc::vec![0u8; 8192]).unwrap();
        }
        let rbf = RawBlockFile::open(&path, 512).unwrap();
        assert_eq!(rbf.volume_capacity_bytes(), 8192);
        let data = [0xABu8; 512];
        rbf.write_volume_block(0, &data).unwrap();
        let mut buf = [0u8; 512];
        assert_eq!(rbf.read_volume_block(0, 512, &mut buf).unwrap(), 512);
        assert_eq!(&buf[..], &data[..]);
    }

    #[test]
    fn flush_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backing.bin");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&alloc::vec![0u8; 4096]).unwrap();
        }
        RawBlockFile::open(&path, 512)
            .unwrap()
            .flush_volume()
            .unwrap();
    }

    #[test]
    fn discard_zeroes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backing.bin");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&alloc::vec![0xFFu8; 4096]).unwrap();
        }
        let rbf = RawBlockFile::open(&path, 512).unwrap();
        rbf.discard_volume_blocks(0, 1024).unwrap();
        let mut buf = [0xFFu8; 1024];
        assert_eq!(rbf.read_volume_block(0, 1024, &mut buf).unwrap(), 1024);
        assert_eq!(&buf[..], &[0u8; 1024]);
    }
}
