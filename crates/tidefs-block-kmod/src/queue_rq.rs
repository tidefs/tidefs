//! blk-mq queue_rq dispatch bridging the Linux block layer to VfsEngine.
//!
//! This module implements the blk_mq `queue_rq` / `submit_bio` request-processing
//! callback that translates Linux block I/O requests into VfsEngine block-level
//! read/write/flush/discard operations with blk-mq status codes and byte-transferred
//! accounting.
//!
//! # Architecture
//!
//! ```text
//! Linux block layer (queue_rq / submit_bio)
//!   ↓
//! BlockKmodQueueRq::dispatch(request)
//!   ├─ classify: BioOp::Read/Write/Flush/Discard
//!   ├─ validate: sector range, capacity bounds
//!   ├─ execute: VfsEngine::block_read / block_write / block_flush / block_discard
//!   └─ complete: blk_status_t + bytes_transferred
//! ```
//!
//! # Intent-log crash safety
//!
//! Before a block write is dispatched, the caller records the write intent
//! in the intent log. After the VfsEngine write completes, the intent is
//! committed. On crash recovery, uncommitted intents are replayed to ensure
//! the write is durable.
//!
//! # Status codes
//!
//! Maps VfsEngine errors to Linux blk-mq status codes:
//! - `ENOSPC` → `BLK_STS_RESOURCE` (space exhausted)
//! - `EIO` → `BLK_STS_IOERR` (storage I/O failure)
//! - `ENOSYS` → `BLK_STS_IOERR` (operation not supported by backend)
//! - All others → `BLK_STS_IOERR`

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::kernel_types::{Errno, KernelStorageIoCapabilities, VfsEngine};
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::BridgeError;
#[cfg(not(CONFIG_RUST))]
use tidefs_kmod_bridge::BridgeError;
#[cfg(not(CONFIG_RUST))]
use tidefs_vfs_engine::{Errno, KernelStorageIoCapabilities, VfsEngine};

// ── BlkMqStatus ─────────────────────────────────────────────────────────

/// Linux blk-mq request completion status codes.
///
/// These correspond to `blk_status_t` values returned by the `queue_rq`
/// callback. They signal the block layer whether the request succeeded
/// and whether it should be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkMqStatus {
    /// Request completed successfully (`BLK_STS_OK` = 0).
    Ok,
    /// Non-retriable I/O error (`BLK_STS_IOERR` = 1).
    IoError,
    /// Temporary resource shortage; the request may be retried (`BLK_STS_RESOURCE` = 2).
    Resource,
    /// Critical space exhausted -- allocation impossible (`BLK_STS_NOSPC` = 4).
    ///
    /// The block layer treats this as a terminal space error; the I/O
    /// scheduler will not retry.
    NoSpace,
    /// Medium error -- the underlying storage medium reported a fault
    /// (`BLK_STS_MEDIUM` = 5). The block layer may attempt recovery
    /// but the I/O is not retried on the same medium.
    Medium,
}

impl BlkMqStatus {
    /// Convert to the integer representation expected by the Linux kernel
    /// (`BLK_STS_OK = 0`, `BLK_STS_IOERR = 1`, `BLK_STS_RESOURCE = 2`).
    #[must_use]
    pub const fn to_kernel_code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::IoError => 1,
            Self::Resource => 2,
            Self::NoSpace => 4,
            Self::Medium => 5,
        }
    }

    /// Whether the status indicates success.
    #[must_use]
    pub fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl From<Errno> for BlkMqStatus {
    fn from(err: Errno) -> Self {
        match err {
            Errno::ENOSPC => BlkMqStatus::NoSpace,
            Errno::EIO => BlkMqStatus::IoError,
            Errno::ENXIO => BlkMqStatus::Medium,
            _ => BlkMqStatus::IoError,
        }
    }
}

// ── From<BridgeError> ──────────────────────────────────────────────────

impl From<&BridgeError> for BlkMqStatus {
    /// Convert a `BridgeError` from the kmod bridge into a `BlkMqStatus`
    /// suitable for `blk_mq_end_request`.
    ///
    /// # Mapping
    ///
    /// | BridgeError | BlkMqStatus | Rationale |
    /// |---|---|---|
    /// | `BioQueueFailed { .. }` | `IoError` | storage I/O failure |
    /// | `InvalidState { .. }` | `IoError` | device in invalid state |
    /// | `Unimplemented { .. }` | `IoError` | ENOSYS semantics |
    /// | `DecodeFailed { .. }` | `IoError` | protocol/data corruption |
    /// | `PinDrainFailed { .. }` | `Resource` | temporary resource shortage |
    /// | Others | `IoError` | conservative error mapping |
    fn from(err: &BridgeError) -> Self {
        match err {
            BridgeError::BioQueueFailed { .. }
            | BridgeError::InvalidState { .. }
            | BridgeError::Unimplemented { .. }
            | BridgeError::DecodeFailed { .. }
            | BridgeError::AnchorStale { .. }
            | BridgeError::MirrorLiftFailed { .. }
            | BridgeError::AuthorityRefused { .. }
            | BridgeError::RenderRejected { .. }
            | BridgeError::ValidationEmitFailed { .. }
            | BridgeError::SecretLeaseExpired { .. }
            | BridgeError::PageWindowFailed { .. } => BlkMqStatus::IoError,
            BridgeError::PinDrainFailed { .. } => BlkMqStatus::Resource,
        }
    }
}

impl From<BridgeError> for BlkMqStatus {
    /// Convert an owned `BridgeError` into a `BlkMqStatus`.
    #[inline]
    fn from(err: BridgeError) -> Self {
        Self::from(&err)
    }
}

// ── QueueRqOutcome ──────────────────────────────────────────────────────

/// Outcome of a single `queue_rq` dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueRqOutcome {
    /// blk-mq status code for request completion.
    pub status: BlkMqStatus,
    /// Number of bytes transferred (for `blk_mq_end_request`).
    pub bytes_transferred: u32,
}

impl QueueRqOutcome {
    /// Success outcome with byte count.
    #[must_use]
    pub const fn ok(bytes: u32) -> Self {
        Self {
            status: BlkMqStatus::Ok,
            bytes_transferred: bytes,
        }
    }

    /// Error outcome with a status code.
    #[must_use]
    pub const fn err(status: BlkMqStatus) -> Self {
        Self {
            status,
            bytes_transferred: 0,
        }
    }
}

// ── QueueRqOp ───────────────────────────────────────────────────────────

/// Block I/O operation kind dispatched through `queue_rq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueRqOp {
    /// REQ_OP_READ: read sectors.
    Read,
    /// REQ_OP_WRITE: write sectors.
    Write,
    /// REQ_OP_FLUSH: flush volatile write caches.
    Flush,
    /// REQ_OP_DISCARD: discard (trim/unmap) sector range.
    Discard,
    /// REQ_OP_WRITE_ZEROES: write zeroes to sector range.
    WriteZeroes,
    /// Zero-range through allocation authority.
    ZeroRange,
}

// ── BlockKmodQueueRq ────────────────────────────────────────────────────

/// blk-mq request dispatcher bridging the Linux block layer to VfsEngine.
///
/// Accepts block I/O requests classified by [`QueueRqOp`], validates sector
/// ranges against the engine's capacity, dispatches to
/// [`VfsEngine::block_read`], [`VfsEngine::block_write`],
/// [`VfsEngine::block_flush`], or [`VfsEngine::block_discard`], and returns
/// a [`QueueRqOutcome`] with blk-mq status and byte-transferred accounting.
///
/// # Intent-log contract
///
/// Callers must record a write intent before calling `dispatch_write` and
/// commit it after the outcome reports `BlkMqStatus::Ok`. The dispatcher
/// itself does not manage the intent log — that is the caller's
/// responsibility.
///
/// # Lifecycle
///
/// The dispatcher is created active. Call [`fence`] to reject all further
/// I/O (maps to `blk_mq_quiesce_queue`), and [`unfence`] to resume.
pub struct BlockKmodQueueRq<E: VfsEngine> {
    /// The VfsEngine backend providing block-level storage.
    engine: E,
    /// Whether the queue is fenced (rejecting all I/O).
    fenced: bool,
}

impl<E: VfsEngine> BlockKmodQueueRq<E> {
    /// Create a new queue_rq dispatcher wrapping a VfsEngine backend.
    pub fn new(engine: E) -> Self
    where
        E: Sized,
    {
        Self {
            engine,
            fenced: false,
        }
    }

    /// Fence the queue: reject all future I/O.
    pub fn fence(&mut self) {
        self.fenced = true;
    }

    /// Unfence the queue: resume accepting I/O.
    pub fn unfence(&mut self) {
        self.fenced = false;
    }

    /// Whether the queue is currently fenced.
    #[must_use]
    pub fn is_fenced(&self) -> bool {
        self.fenced
    }

    /// Return a reference to the VfsEngine backend.
    #[must_use]
    pub fn engine(&self) -> &E {
        &self.engine
    }

    /// Return the engine's block device capacity in sectors.
    #[must_use]
    pub fn capacity_sectors(&self) -> u64 {
        self.engine.block_capacity_sectors()
    }

    /// Return the engine's logical block (sector) size in bytes.
    #[must_use]
    pub fn sector_size(&self) -> u32 {
        self.engine.block_sector_size()
    }

    // ── Validation ──────────────────────────────────────────────────────

    /// Validate that a sector range is within the engine's capacity bounds.
    fn validate_range(&self, start_sector: u64, sector_count: u32) -> Result<(), QueueRqOutcome> {
        let capacity = self.capacity_sectors();
        if sector_count == 0 {
            return Err(QueueRqOutcome::err(BlkMqStatus::IoError));
        }
        let end = start_sector.saturating_add(u64::from(sector_count));
        if end > capacity {
            return Err(QueueRqOutcome::err(BlkMqStatus::IoError));
        }
        Ok(())
    }

    // ── Dispatch ────────────────────────────────────────────────────────

    /// Dispatch a block I/O operation to the VfsEngine backend.
    ///
    /// * `op` — operation kind (Read/Write/Flush/Discard).
    /// * `start_sector` — logical block address of the first sector.
    /// * `sector_count` — number of sectors (ignored for Flush).
    /// * `buf` — data buffer: for reads, receives data; for writes,
    ///   provides data. Ignored for Flush/Discard.
    ///
    /// # Returns
    ///
    /// A [`QueueRqOutcome`] with blk-mq status and byte count suitable
    /// for `blk_mq_end_request`.
    pub fn dispatch(
        &self,
        op: QueueRqOp,
        start_sector: u64,
        sector_count: u32,
        buf: &mut [u8],
    ) -> QueueRqOutcome {
        if self.fenced {
            return QueueRqOutcome::err(BlkMqStatus::IoError);
        }

        match op {
            QueueRqOp::Read => self.dispatch_read(start_sector, sector_count, buf),
            QueueRqOp::Write => self.dispatch_write(start_sector, sector_count, buf),
            QueueRqOp::Flush => self.dispatch_flush(),
            QueueRqOp::Discard => self.dispatch_discard(start_sector, sector_count),
            QueueRqOp::WriteZeroes => self.dispatch_write_zeroes(start_sector, sector_count),
            QueueRqOp::ZeroRange => self.dispatch_zero_range(start_sector, sector_count),
        }
    }

    fn dispatch_read(
        &self,
        start_sector: u64,
        sector_count: u32,
        buf: &mut [u8],
    ) -> QueueRqOutcome {
        if let Err(outcome) = self.validate_range(start_sector, sector_count) {
            return outcome;
        }
        let expected = sector_count as usize * self.sector_size() as usize;
        if buf.len() < expected {
            return QueueRqOutcome::err(BlkMqStatus::IoError);
        }
        match self.engine.block_read(start_sector, sector_count, buf) {
            Ok(bytes) => QueueRqOutcome::ok(bytes),
            Err(e) => QueueRqOutcome::err(BlkMqStatus::from(e)),
        }
    }

    fn dispatch_write(&self, start_sector: u64, sector_count: u32, buf: &[u8]) -> QueueRqOutcome {
        if let Err(outcome) = self.validate_range(start_sector, sector_count) {
            return outcome;
        }
        let expected = sector_count as usize * self.sector_size() as usize;
        let data = if buf.len() >= expected {
            &buf[..expected]
        } else {
            return QueueRqOutcome::err(BlkMqStatus::IoError);
        };
        match self.engine.block_write(start_sector, data) {
            Ok(bytes) => QueueRqOutcome::ok(bytes),
            Err(e) => QueueRqOutcome::err(BlkMqStatus::from(e)),
        }
    }

    fn dispatch_flush(&self) -> QueueRqOutcome {
        match self.engine.block_flush() {
            Ok(()) => QueueRqOutcome::ok(0),
            Err(e) => QueueRqOutcome::err(BlkMqStatus::from(e)),
        }
    }

    fn dispatch_discard(&self, start_sector: u64, sector_count: u32) -> QueueRqOutcome {
        if let Err(outcome) = self.validate_range(start_sector, sector_count) {
            return outcome;
        }
        match self.engine.block_discard(start_sector, sector_count) {
            Ok(()) => QueueRqOutcome::ok(0),
            Err(e) => QueueRqOutcome::err(BlkMqStatus::from(e)),
        }
    }
    fn dispatch_write_zeroes(&self, start_sector: u64, sector_count: u32) -> QueueRqOutcome {
        if let Err(outcome) = self.validate_range(start_sector, sector_count) {
            return outcome;
        }
        match self.engine.block_write_zeroes(start_sector, sector_count) {
            Ok(()) => QueueRqOutcome::ok(0),
            Err(e) => QueueRqOutcome::err(BlkMqStatus::from(e)),
        }
    }

    fn dispatch_zero_range(&self, start_sector: u64, sector_count: u32) -> QueueRqOutcome {
        if let Err(outcome) = self.validate_range(start_sector, sector_count) {
            return outcome;
        }
        match self.engine.block_zero_range(start_sector, sector_count) {
            Ok(()) => QueueRqOutcome::ok(0),
            Err(e) => QueueRqOutcome::err(BlkMqStatus::from(e)),
        }
    }
}

impl<E: VfsEngine> core::fmt::Debug for BlockKmodQueueRq<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlockKmodQueueRq")
            .field("capacity_sectors", &self.capacity_sectors())
            .field("sector_size", &self.sector_size())
            .field("fenced", &self.fenced)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(CONFIG_RUST)]
    use crate::tidefs_kmod_bridge::kernel_types::KmodVec as Vec;
    use alloc::boxed::Box;
    use core::cell::RefCell;
    #[cfg(not(CONFIG_RUST))]
    use tidefs_kmod_bridge::kernel_types::KmodVec as Vec;
    use tidefs_vfs_engine::{
        DirEntry, EngineDirHandle, EngineFileHandle, InodeAttr, InodeId, LockSpec, RequestCtx,
        SetAttr,
    };

    // ── In-memory block engine stub ────────────────────────────────────

    /// In-memory VfsEngine stub for block device dispatch testing.
    ///
    /// Provides a fixed-capacity byte buffer backing the block methods.
    /// All other VfsEngine methods return ENOSYS.
    struct BlockEngineStub {
        buffer: RefCell<Box<[u8]>>,
        sector_size: u32,
        capacity_sectors: u64,
        flush_supported: bool,
        discard_supported: bool,
    }

    impl BlockEngineStub {
        fn new(capacity_sectors: u64, sector_size: u32) -> Self {
            let cap_bytes = capacity_sectors as usize * sector_size as usize;
            Self {
                buffer: RefCell::new(alloc::vec![0u8; cap_bytes].into_boxed_slice()),
                sector_size,
                capacity_sectors,
                flush_supported: true,
                discard_supported: true,
            }
        }

        fn without_discard(mut self) -> Self {
            self.discard_supported = false;
            self
        }

        fn without_flush(mut self) -> Self {
            self.flush_supported = false;
            self
        }
    }

    // Stub VfsEngine impl: all non-block methods return ENOSYS.
    #[allow(unused_variables)]
    impl VfsEngine for BlockEngineStub {
        fn block_io_capabilities(&self) -> KernelStorageIoCapabilities {
            KernelStorageIoCapabilities {
                read: true,
                write: true,
                flush: self.flush_supported,
                discard: self.discard_supported,
                write_zeroes: false,
                zero_range: false,
                teardown: true,
                sector_size: self.sector_size,
                capacity_sectors: self.capacity_sectors,
            }
        }

        fn get_root_inode(&self, ctx: &RequestCtx) -> Result<InodeId, Errno> {
            Err(Errno::ENOSYS)
        }
        fn lookup(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn getattr(
            &self,
            i: InodeId,
            h: Option<&EngineFileHandle>,
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn setattr(
            &self,
            i: InodeId,
            a: &SetAttr,
            h: Option<&EngineFileHandle>,
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn mkdir(&self, p: InodeId, n: &[u8], m: u32, c: &RequestCtx) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn create(
            &self,
            p: InodeId,
            n: &[u8],
            m: u32,
            f: u32,
            c: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn tmpfile(
            &self,
            p: InodeId,
            m: u32,
            f: u32,
            c: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn unlink(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn rmdir(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn rename(
            &self,
            op: InodeId,
            on: &[u8],
            np: InodeId,
            nn: &[u8],
            f: u32,
            c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn link(
            &self,
            t: InodeId,
            np: InodeId,
            nn: &[u8],
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn symlink(
            &self,
            p: InodeId,
            n: &[u8],
            t: &[u8],
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn readlink(&self, i: InodeId, c: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn mknod(
            &self,
            p: InodeId,
            n: &[u8],
            m: u32,
            r: u32,
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn open(&self, i: InodeId, f: u32, c: &RequestCtx) -> Result<EngineFileHandle, Errno> {
            Err(Errno::ENOSYS)
        }
        fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn read(
            &self,
            fh: &EngineFileHandle,
            o: u64,
            s: u32,
            c: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn write(
            &self,
            fh: &EngineFileHandle,
            o: u64,
            d: &[u8],
            c: &RequestCtx,
        ) -> Result<u32, Errno> {
            Err(Errno::ENOSYS)
        }
        fn flush(&self, fh: &EngineFileHandle, c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fsync(&self, fh: &EngineFileHandle, d: bool, c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fallocate(
            &self,
            fh: &EngineFileHandle,
            m: u32,
            o: u64,
            l: u64,
            c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn opendir(&self, i: InodeId, c: &RequestCtx) -> Result<EngineDirHandle, Errno> {
            Err(Errno::ENOSYS)
        }
        fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn readdir(
            &self,
            dh: &EngineDirHandle,
            o: u64,
            c: &RequestCtx,
        ) -> Result<(Vec<DirEntry>, bool), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fsyncdir(&self, dh: &EngineDirHandle, d: bool, c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn getxattr(&self, i: InodeId, n: &[u8], c: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn setxattr(
            &self,
            i: InodeId,
            n: &[u8],
            v: &[u8],
            f: u32,
            c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn listxattr(&self, i: InodeId, c: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn removexattr(&self, i: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn getlk(
            &self,
            i: InodeId,
            l: &LockSpec,
            c: &RequestCtx,
        ) -> Result<Option<LockSpec>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn setlk(&self, i: InodeId, l: &LockSpec, c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }

        // ── Block methods ─────────────────────────────────────────
        fn block_read(&self, start: u64, count: u32, buf: &mut [u8]) -> Result<u32, Errno> {
            let ss = self.sector_size as usize;
            let offset = start as usize * ss;
            let len = count as usize * ss;
            let data = self.buffer.borrow();
            if offset + len > data.len() || buf.len() < len {
                return Err(Errno::EIO);
            }
            let n = len.min(buf.len());
            buf[..n].copy_from_slice(&data[offset..offset + n]);
            Ok(n as u32)
        }

        fn block_write(&self, start: u64, data: &[u8]) -> Result<u32, Errno> {
            let ss = self.sector_size as usize;
            let offset = start as usize * ss;
            let padded = data.len().div_ceil(ss) * ss;
            let mut buf = self.buffer.borrow_mut();
            if offset + data.len() > buf.len() {
                return Err(Errno::ENOSPC);
            }
            let n = data.len().min(buf.len() - offset);
            buf[offset..offset + n].copy_from_slice(&data[..n]);
            Ok(n as u32)
        }

        fn block_flush(&self) -> Result<(), Errno> {
            if !self.flush_supported {
                return Err(Errno::ENOSYS);
            }
            Ok(())
        }

        fn block_discard(&self, start: u64, count: u32) -> Result<(), Errno> {
            if !self.discard_supported {
                return Err(Errno::ENOSYS);
            }
            let ss = self.sector_size as usize;
            let offset = start as usize * ss;
            let len = count as usize * ss;
            let mut buf = self.buffer.borrow_mut();
            if offset + len > buf.len() {
                return Err(Errno::EIO);
            }
            buf[offset..offset + len].fill(0);
            Ok(())
        }

        fn block_capacity_sectors(&self) -> u64 {
            self.capacity_sectors
        }
        fn block_sector_size(&self) -> u32 {
            self.sector_size
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────

    fn make_dispatcher(capacity_sectors: u64) -> BlockKmodQueueRq<BlockEngineStub> {
        BlockKmodQueueRq::new(BlockEngineStub::new(capacity_sectors, 512))
    }

    // ── BlkMqStatus tests ─────────────────────────────────────────────

    #[test]
    fn blkmq_status_kernel_codes() {
        assert_eq!(BlkMqStatus::Ok.to_kernel_code(), 0);
        assert_eq!(BlkMqStatus::IoError.to_kernel_code(), 1);
        assert_eq!(BlkMqStatus::Resource.to_kernel_code(), 2);
    }

    #[test]
    fn blkmq_status_is_ok() {
        assert!(BlkMqStatus::Ok.is_ok());
        assert!(!BlkMqStatus::IoError.is_ok());
        assert!(!BlkMqStatus::Resource.is_ok());
    }

    #[test]
    fn blkmq_status_from_enospc_is_nospace() {
        assert_eq!(BlkMqStatus::from(Errno::ENOSPC), BlkMqStatus::NoSpace);
    }

    #[test]
    fn blkmq_status_from_eio_is_ioerror() {
        assert_eq!(BlkMqStatus::from(Errno::EIO), BlkMqStatus::IoError);
    }

    #[test]
    fn blkmq_status_from_other_is_ioerror() {
        assert_eq!(BlkMqStatus::from(Errno::EINVAL), BlkMqStatus::IoError);
    }

    // ── QueueRqOutcome tests ──────────────────────────────────────────

    #[test]
    fn outcome_ok_with_bytes() {
        let o = QueueRqOutcome::ok(4096);
        assert_eq!(o.status, BlkMqStatus::Ok);
        assert_eq!(o.bytes_transferred, 4096);
    }

    #[test]
    fn outcome_err_zero_bytes() {
        let o = QueueRqOutcome::err(BlkMqStatus::IoError);
        assert_eq!(o.bytes_transferred, 0);
    }

    // ── Dispatch: single-sector read ──────────────────────────────────

    #[test]
    fn single_sector_read_returns_zeroes() {
        let d = make_dispatcher(100);
        let mut buf = [0u8; 512];
        let outcome = d.dispatch(QueueRqOp::Read, 0, 1, &mut buf);
        assert_eq!(outcome.status, BlkMqStatus::Ok);
        assert_eq!(outcome.bytes_transferred, 512);
        assert_eq!(&buf[..], &[0u8; 512]);
    }

    #[test]
    fn single_sector_write_then_read() {
        let d = make_dispatcher(100);
        let data = [0xABu8; 512];
        let mut buf = data;

        let w_outcome = d.dispatch(QueueRqOp::Write, 5, 1, &mut buf);
        assert!(w_outcome.status.is_ok());
        assert_eq!(w_outcome.bytes_transferred, 512);

        let mut rbuf = [0u8; 512];
        let r_outcome = d.dispatch(QueueRqOp::Read, 5, 1, &mut rbuf);
        assert!(r_outcome.status.is_ok());
        assert_eq!(&rbuf[..], &data[..]);
    }

    // ── Dispatch: multi-sector ────────────────────────────────────────

    #[test]
    fn multi_sector_write_read_roundtrip() {
        let d = make_dispatcher(200);
        let data = alloc::vec![0xCCu8; 4 * 512]; // 4 sectors
        let mut buf = data.clone();

        let w = d.dispatch(QueueRqOp::Write, 10, 4, &mut buf);
        assert!(w.status.is_ok());
        assert_eq!(w.bytes_transferred, 2048);

        let mut rbuf = alloc::vec![0u8; 4 * 512];
        let r = d.dispatch(QueueRqOp::Read, 10, 4, &mut rbuf);
        assert!(r.status.is_ok());
        assert_eq!(&rbuf[..], &data[..]);
    }

    #[test]
    fn partial_sector_read() {
        let d = make_dispatcher(200);
        let data = alloc::vec![0xDDu8; 8 * 512];
        let mut buf = data.clone();
        d.dispatch(QueueRqOp::Write, 20, 8, &mut buf);

        let mut rbuf = alloc::vec![0u8; 4 * 512];
        let r = d.dispatch(QueueRqOp::Read, 22, 4, &mut rbuf);
        assert!(r.status.is_ok());
        assert_eq!(&rbuf[..], &data[2 * 512..6 * 512]);
    }

    // ── Dispatch: flush ───────────────────────────────────────────────

    #[test]
    fn flush_succeeds() {
        let d = make_dispatcher(100);
        let outcome = d.dispatch(QueueRqOp::Flush, 0, 0, &mut []);
        assert_eq!(outcome.status, BlkMqStatus::Ok);
        assert_eq!(outcome.bytes_transferred, 0);
    }

    #[test]
    fn flush_fails_when_not_supported() {
        let engine = BlockEngineStub::new(100, 512).without_flush();
        let d = BlockKmodQueueRq::new(engine);
        let outcome = d.dispatch(QueueRqOp::Flush, 0, 0, &mut []);
        assert_eq!(outcome.status, BlkMqStatus::IoError);
    }

    // ── Dispatch: discard ─────────────────────────────────────────────

    #[test]
    fn discard_zeroes_data() {
        let d = make_dispatcher(100);
        let data = [0xFFu8; 512];
        let mut buf = data;
        d.dispatch(QueueRqOp::Write, 5, 1, &mut buf);

        let disc = d.dispatch(QueueRqOp::Discard, 5, 1, &mut []);
        assert!(disc.status.is_ok());

        let mut rbuf = [0u8; 512];
        d.dispatch(QueueRqOp::Read, 5, 1, &mut rbuf);
        assert_eq!(&rbuf[..], &[0u8; 512]);
    }

    #[test]
    fn discard_unsupported_is_ioerror() {
        let engine = BlockEngineStub::new(100, 512).without_discard();
        let d = BlockKmodQueueRq::new(engine);
        let outcome = d.dispatch(QueueRqOp::Discard, 0, 1, &mut []);
        assert_eq!(outcome.status, BlkMqStatus::IoError);
    }

    // ── Dispatch: out-of-bounds ───────────────────────────────────────

    #[test]
    fn read_beyond_capacity_rejected() {
        let d = make_dispatcher(50);
        let mut buf = [0u8; 512];
        let outcome = d.dispatch(QueueRqOp::Read, 60, 1, &mut buf);
        assert_eq!(outcome.status, BlkMqStatus::IoError);
        assert_eq!(outcome.bytes_transferred, 0);
    }

    #[test]
    fn write_beyond_capacity_rejected() {
        let d = make_dispatcher(50);
        let mut buf = [0x11u8; 512];
        let outcome = d.dispatch(QueueRqOp::Write, 60, 1, &mut buf);
        assert_eq!(outcome.status, BlkMqStatus::IoError);
    }

    #[test]
    fn discard_beyond_capacity_rejected() {
        let d = make_dispatcher(50);
        let outcome = d.dispatch(QueueRqOp::Discard, 60, 1, &mut []);
        assert_eq!(outcome.status, BlkMqStatus::IoError);
    }

    #[test]
    fn zero_sector_count_rejected() {
        let d = make_dispatcher(50);
        let mut buf = [0u8; 512];
        let outcome = d.dispatch(QueueRqOp::Read, 0, 0, &mut buf);
        assert_eq!(outcome.status, BlkMqStatus::IoError);
    }

    #[test]
    fn buffer_too_short_rejected() {
        let d = make_dispatcher(100);
        let mut buf = [0u8; 100]; // too short for 1 sector (512 bytes)
        let outcome = d.dispatch(QueueRqOp::Read, 0, 1, &mut buf);
        assert_eq!(outcome.status, BlkMqStatus::IoError);
    }

    // ── Fence / unfence ───────────────────────────────────────────────

    #[test]
    fn fence_rejects_all_io() {
        let mut d = make_dispatcher(100);
        let data = [0xAAu8; 512];
        let mut buf = data;
        d.dispatch(QueueRqOp::Write, 0, 1, &mut buf);

        d.fence();
        assert!(d.is_fenced());

        let mut rbuf = [0u8; 512];
        let outcome = d.dispatch(QueueRqOp::Read, 0, 1, &mut rbuf);
        assert_eq!(outcome.status, BlkMqStatus::IoError);

        let w_outcome = d.dispatch(QueueRqOp::Write, 1, 1, &mut [0u8; 512]);
        assert_eq!(w_outcome.status, BlkMqStatus::IoError);
    }

    #[test]
    fn unfence_restores_io() {
        let mut d = make_dispatcher(100);
        d.fence();
        d.unfence();
        assert!(!d.is_fenced());

        let mut buf = [0u8; 512];
        let outcome = d.dispatch(QueueRqOp::Read, 0, 1, &mut buf);
        assert_eq!(outcome.status, BlkMqStatus::Ok);
    }

    // ── Accessor tests ────────────────────────────────────────────────

    #[test]
    fn capacity_sectors_matches_engine() {
        let d = make_dispatcher(1024);
        assert_eq!(d.capacity_sectors(), 1024);
    }

    #[test]
    fn sector_size_matches_engine() {
        let d = make_dispatcher(100);
        assert_eq!(d.sector_size(), 512);
    }

    // ── Concurrent non-overlapping writes ─────────────────────────────

    #[test]
    fn concurrent_writes_non_overlapping() {
        let d = make_dispatcher(200);
        let d1 = [0x11u8; 512];
        let d2 = [0x22u8; 512];
        let d3 = [0x33u8; 512];

        let mut buf1 = d1;
        let mut buf2 = d2;
        let mut buf3 = d3;
        assert!(d.dispatch(QueueRqOp::Write, 0, 1, &mut buf1).status.is_ok());
        assert!(d
            .dispatch(QueueRqOp::Write, 10, 1, &mut buf2)
            .status
            .is_ok());
        assert!(d
            .dispatch(QueueRqOp::Write, 20, 1, &mut buf3)
            .status
            .is_ok());

        let mut r1 = [0u8; 512];
        let mut r2 = [0u8; 512];
        let mut r3 = [0u8; 512];
        d.dispatch(QueueRqOp::Read, 0, 1, &mut r1);
        d.dispatch(QueueRqOp::Read, 10, 1, &mut r2);
        d.dispatch(QueueRqOp::Read, 20, 1, &mut r3);

        assert_eq!(&r1[..], &d1[..]);
        assert_eq!(&r2[..], &d2[..]);
        assert_eq!(&r3[..], &d3[..]);
    }

    // ── Full device fill/verify ────────────────────────────────────────

    #[test]
    fn full_device_fill_and_verify() {
        let sectors = 64u64;
        let d = make_dispatcher(sectors);
        let pattern = [0x5Au8; 512];

        for sector in 0..sectors {
            let mut buf = pattern;
            let outcome = d.dispatch(QueueRqOp::Write, sector, 1, &mut buf);
            assert!(outcome.status.is_ok(), "write sector {sector} failed");
        }

        for sector in 0..sectors {
            let mut buf = [0u8; 512];
            let outcome = d.dispatch(QueueRqOp::Read, sector, 1, &mut buf);
            assert!(outcome.status.is_ok(), "read sector {sector} failed");
            assert_eq!(&buf[..], &pattern[..], "sector {sector} mismatch");
        }
    }

    // ── Debug output ──────────────────────────────────────────────────

    #[test]
    fn dispatcher_debug_output() {
        let d = make_dispatcher(100);
        let dbg = alloc::format!("{d:?}");
        assert!(dbg.contains("BlockKmodQueueRq"));
        assert!(dbg.contains("100")); // capacity_sectors
    }

    #[test]
    fn blkmq_status_debug() {
        let dbg = alloc::format!("{:?}", BlkMqStatus::Resource);
        assert!(dbg.contains("Resource"));
    }

    #[test]
    fn queue_rq_op_debug_and_eq() {
        assert_eq!(QueueRqOp::Read, QueueRqOp::Read);
        assert_ne!(QueueRqOp::Read, QueueRqOp::Write);
        let dbg = alloc::format!("{:?}", QueueRqOp::Flush);
        assert!(dbg.contains("Flush"));
    }

    // ── From<BridgeError> tests ────────────────────────────────────────

    #[test]
    fn bridgeerror_bioqueuefailed_maps_to_ioerror() {
        let err = BridgeError::BioQueueFailed {
            detail: "write out of bounds",
        };
        assert_eq!(BlkMqStatus::from(&err), BlkMqStatus::IoError);
        assert_eq!(BlkMqStatus::from(err), BlkMqStatus::IoError);
    }

    #[test]
    fn bridgeerror_invalidstate_maps_to_ioerror() {
        let err = BridgeError::InvalidState {
            detail: "device not registered",
        };
        assert_eq!(BlkMqStatus::from(&err), BlkMqStatus::IoError);
    }

    #[test]
    fn bridgeerror_unimplemented_maps_to_ioerror() {
        let err = BridgeError::Unimplemented { feature: "flush" };
        assert_eq!(BlkMqStatus::from(&err), BlkMqStatus::IoError);
    }

    #[test]
    fn bridgeerror_pindrainfailed_maps_to_resource() {
        let err = BridgeError::PinDrainFailed { detail: "timeout" };
        assert_eq!(BlkMqStatus::from(&err), BlkMqStatus::Resource);
        assert_eq!(BlkMqStatus::from(err), BlkMqStatus::Resource);
    }

    #[test]
    fn bridgeerror_decodefailed_maps_to_ioerror() {
        let err = BridgeError::DecodeFailed { detail: "corrupt" };
        assert_eq!(BlkMqStatus::from(&err), BlkMqStatus::IoError);
    }

    #[test]
    fn bridgeerror_other_variants_map_to_ioerror() {
        // Conservative mapping for all other variants
        for err in &[
            BridgeError::AnchorStale {
                generation: 1,
                expected: 2,
            },
            BridgeError::MirrorLiftFailed { detail: "mirror" },
            BridgeError::AuthorityRefused { reason: "denied" },
            BridgeError::RenderRejected { field: "field" },
            BridgeError::ValidationEmitFailed { detail: "full" },
            BridgeError::SecretLeaseExpired { handle_id: 42 },
            BridgeError::PageWindowFailed { detail: "window" },
        ] {
            assert_eq!(
                BlkMqStatus::from(err),
                BlkMqStatus::IoError,
                "unexpected status for {err:?}"
            );
        }
    }

    #[test]
    fn bridgeerror_status_codes_match_blk_sts() {
        assert_eq!(BlkMqStatus::IoError.to_kernel_code(), 1);
        assert_eq!(BlkMqStatus::Resource.to_kernel_code(), 2);
    }
}
