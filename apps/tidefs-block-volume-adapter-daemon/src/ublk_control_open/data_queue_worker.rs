// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_block_volume_adapter_core::{
    BlockRangeRecord, BlockVolumeCompletionClass, BlockVolumeFileImage, BlockVolumeGeometryRecord,
    BlockVolumeRequestClass,
};

use crate::storage_backend::{BackendError, BlockVolumeStorageBackend};
use tidefs_ublk_abi::{
    UblkSrvIoCmd, UblkSrvIoDesc, UBLK_IO_F_FAILFAST_DEV, UBLK_IO_F_FAILFAST_DRIVER,
    UBLK_IO_F_FAILFAST_TRANSPORT, UBLK_IO_F_FUA, UBLK_IO_F_META, UBLK_IO_F_NEED_REG_BUF,
    UBLK_IO_F_NOUNMAP, UBLK_IO_F_SWAP, UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH, UBLK_IO_OP_READ,
    UBLK_IO_OP_WRITE, UBLK_IO_OP_WRITE_SAME, UBLK_IO_OP_WRITE_ZEROES, UBLK_IO_RES_ABORT,
    UBLK_IO_RES_OK,
};

use crate::ublk_io_uring::UblkIoUringDispatcher;
use crate::LINUX_SECTOR_SIZE_BYTES;
use crate::{BarrierAuditLog, BarrierResult, BarrierType};

pub const BLOCK_VOLUME_UBLK_DATA_QUEUE_WORKER_GATE_OW_301Z: &str =
    "OW-301Z block-volume adapter ublk data-queue worker dispatches read/write/flush descriptors to the backing image and returns kernel-visible completion status";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataQueueWorkerError {
    UnsupportedOperation,
    UnsupportedWriteSame,
    UnsupportedZonedOperation,
    UnsupportedFlags,
    OutOfRange,
    SectorRangeNotBlockAligned,
    BlockSizeBelowLinuxSector,
    RangeOverflow,
    ZeroLengthDataOperation,
    MissingBufferAddress,
    RangeOnFlush,
    UnexpectedBufferAddress,
    PayloadBufferTooShort,
    BackingStoreError(i32),
    /// Write/flush/discard/write-zeroes refused on a read-only volume.
    ReadOnlyVolume,
}

impl DataQueueWorkerError {
    #[must_use]
    pub const fn linux_errno(self) -> i32 {
        match self {
            Self::UnsupportedOperation
            | Self::UnsupportedWriteSame
            | Self::UnsupportedZonedOperation => -95,
            Self::UnsupportedFlags => -22,
            Self::OutOfRange
            | Self::SectorRangeNotBlockAligned
            | Self::BlockSizeBelowLinuxSector
            | Self::RangeOverflow
            | Self::ZeroLengthDataOperation
            | Self::MissingBufferAddress
            | Self::RangeOnFlush
            | Self::UnexpectedBufferAddress
            | Self::PayloadBufferTooShort => -22,
            Self::BackingStoreError(errno) => errno,
            Self::ReadOnlyVolume => -30,
        }
    }
}

#[derive(Debug)]
pub struct DataQueueWorker {
    pub queue_id: u16,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub flush_ops: u64,
    pub discard_ops: u64,
    pub write_zeroes_ops: u64,
    pub completed_ops: u64,
    pub error_ops: u64,
    pub unsupported_ops: u64,
    pub barrier_audit: BarrierAuditLog,
    geometry: BlockVolumeGeometryRecord,
    max_queue_depth: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct DataQueueWorkerReport {
    pub queue_id: u16,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub flush_ops: u64,
    pub discard_ops: u64,
    pub write_zeroes_ops: u64,
    pub completed_ops: u64,
    pub error_ops: u64,
    pub unsupported_ops: u64,
    pub results: Vec<DataQueueWorkerResultEntry>,
}

#[derive(Clone, Debug)]
pub struct DataQueueWorkerResultEntry {
    pub tag: u16,
    pub request_class: BlockVolumeRequestClass,
    pub completion_class: BlockVolumeCompletionClass,
    pub io_cmd: UblkSrvIoCmd,
    pub byte_count: usize,
}

impl DataQueueWorker {
    /// Legitimate pass-through flags from the kernel block layer that ublk
    /// may set on I/O descriptors. All of these are acceptable and must
    /// not cause EINVAL rejection at the worker dispatch boundary.
    const ACCEPTABLE_RAW_FLAGS: u32 = UBLK_IO_F_FAILFAST_DEV
        | UBLK_IO_F_FAILFAST_TRANSPORT
        | UBLK_IO_F_FAILFAST_DRIVER
        | UBLK_IO_F_META
        | UBLK_IO_F_NEED_REG_BUF
        | UBLK_IO_F_NOUNMAP
        | UBLK_IO_F_SWAP;

    #[must_use]
    pub fn new(queue_id: u16, geometry: BlockVolumeGeometryRecord) -> Self {
        Self {
            queue_id,
            bytes_read: 0,
            bytes_written: 0,
            read_ops: 0,
            write_ops: 0,
            flush_ops: 0,
            discard_ops: 0,
            write_zeroes_ops: 0,
            completed_ops: 0,
            error_ops: 0,
            unsupported_ops: 0,
            barrier_audit: BarrierAuditLog::new(),
            geometry,
            max_queue_depth: None,
        }
    }

    #[allow(dead_code)]
    pub fn set_max_queue_depth(&mut self, max: Option<usize>) {
        self.max_queue_depth = max;
    }

    pub fn process_one(
        &mut self,
        backend: &mut dyn BlockVolumeStorageBackend,
        tag: u16,
        desc: &UblkSrvIoDesc,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        self.process_one_with_buffers(backend, tag, desc, None, None)
    }

    pub fn process_one_with_buffers(
        &mut self,
        backend: &mut dyn BlockVolumeStorageBackend,
        tag: u16,
        desc: &UblkSrvIoDesc,
        read_buffer: Option<&mut [u8]>,
        write_payload: Option<&[u8]>,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        let op = desc.op();
        let raw_flags = desc.op_flags & !0xff;

        // Reject mutating operations on read-only backends (EROFS).
        if backend.is_read_only() && op != UBLK_IO_OP_READ {
            self.error_ops += 1;
            return Err(DataQueueWorkerError::ReadOnlyVolume);
        }

        match op {
            UBLK_IO_OP_READ => self.dispatch_read(backend, tag, desc, raw_flags, read_buffer),
            UBLK_IO_OP_WRITE => self.dispatch_write(backend, tag, desc, raw_flags, write_payload),
            UBLK_IO_OP_FLUSH => self.dispatch_flush(backend, tag, desc, raw_flags),
            UBLK_IO_OP_DISCARD => self.dispatch_discard(backend, tag, desc, raw_flags),
            UBLK_IO_OP_WRITE_ZEROES => self.dispatch_write_zeroes(backend, tag, desc, raw_flags),
            UBLK_IO_OP_WRITE_SAME => {
                self.unsupported_ops += 1;
                self.error_ops += 1;
                Err(DataQueueWorkerError::UnsupportedWriteSame)
            }
            _ if (10..=18).contains(&op) => {
                self.unsupported_ops += 1;
                self.error_ops += 1;
                Err(DataQueueWorkerError::UnsupportedZonedOperation)
            }
            _ => {
                self.unsupported_ops += 1;
                self.error_ops += 1;
                Err(DataQueueWorkerError::UnsupportedOperation)
            }
        }
    }

    pub fn process_one_io_uring(
        &mut self,
        dispatcher: &mut UblkIoUringDispatcher,
        tag: u16,
        desc: &UblkSrvIoDesc,
        read_buffer: Option<&mut [u8]>,
        write_payload: Option<&[u8]>,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        let op = desc.op();
        let raw_flags = desc.op_flags & !0xff;

        match op {
            UBLK_IO_OP_READ => {
                self.dispatch_read_io_uring(dispatcher, tag, desc, raw_flags, read_buffer)
            }
            UBLK_IO_OP_WRITE => {
                self.dispatch_write_io_uring(dispatcher, tag, desc, raw_flags, write_payload)
            }
            UBLK_IO_OP_FLUSH => self.dispatch_flush_io_uring(dispatcher, tag, desc, raw_flags),
            UBLK_IO_OP_DISCARD => self.dispatch_discard_io_uring(dispatcher, tag, desc, raw_flags),
            UBLK_IO_OP_WRITE_ZEROES => {
                self.dispatch_write_zeroes_io_uring(dispatcher, tag, desc, raw_flags)
            }
            _ => {
                self.unsupported_ops += 1;
                self.error_ops += 1;
                Err(DataQueueWorkerError::UnsupportedOperation)
            }
        }
    }

    fn dispatch_read_io_uring(
        &mut self,
        dispatcher: &mut UblkIoUringDispatcher,
        tag: u16,
        desc: &UblkSrvIoDesc,
        raw_flags: u32,
        read_buffer: Option<&mut [u8]>,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        // Accept all kernel raw flags; flags are advisory hints.
        let _ = raw_flags;
        let range = match self.project_range(desc) {
            Ok(range) => range,
            Err(DataQueueWorkerError::OutOfRange) => {
                return Ok(self.refused_entry(
                    tag,
                    BlockVolumeRequestClass::Read,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                ));
            }
            Err(err) => return Err(err),
        };
        let offset = (range.start_block * self.geometry.block_size_bytes) as u64;
        let byte_count = range.block_count * self.geometry.block_size_bytes;

        let buffer = read_buffer.ok_or(DataQueueWorkerError::MissingBufferAddress)?;
        if buffer.len() < byte_count {
            self.error_ops += 1;
            return Err(DataQueueWorkerError::PayloadBufferTooShort);
        }

        match dispatcher.read_at(offset, &mut buffer[..byte_count]) {
            Ok(n) => {
                if n < byte_count {
                    self.error_ops += 1;
                    return Err(DataQueueWorkerError::BackingStoreError(-libc::EIO));
                }
                self.bytes_read += n as u64;
                self.read_ops += 1;
                self.completed_ops += 1;
                Ok(DataQueueWorkerResultEntry {
                    tag,
                    request_class: BlockVolumeRequestClass::Read,
                    completion_class: BlockVolumeCompletionClass::Completed,
                    io_cmd: UblkSrvIoCmd {
                        q_id: self.queue_id,
                        tag,
                        result: UBLK_IO_RES_OK,
                        addr_or_zone_append_lba: 0,
                    },
                    byte_count: n,
                })
            }
            Err(err) => {
                self.error_ops += 1;
                let errno = err.linux_errno();
                Err(DataQueueWorkerError::BackingStoreError(errno))
            }
        }
    }

    fn dispatch_write_io_uring(
        &mut self,
        dispatcher: &mut UblkIoUringDispatcher,
        tag: u16,
        desc: &UblkSrvIoDesc,
        raw_flags: u32,
        write_payload: Option<&[u8]>,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        // Accept all kernel raw flags; FUA handled below for write durability.
        let _ = raw_flags;
        let range = match self.project_range(desc) {
            Ok(range) => range,
            Err(DataQueueWorkerError::OutOfRange) => {
                return Ok(self.refused_entry(
                    tag,
                    BlockVolumeRequestClass::Write,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                ));
            }
            Err(err) => return Err(err),
        };
        let offset = (range.start_block * self.geometry.block_size_bytes) as u64;
        let byte_count = range.block_count * self.geometry.block_size_bytes;

        let payload = write_payload.ok_or(DataQueueWorkerError::MissingBufferAddress)?;
        if payload.len() < byte_count {
            self.error_ops += 1;
            return Err(DataQueueWorkerError::PayloadBufferTooShort);
        }

        match dispatcher.write_at(offset, &payload[..byte_count]) {
            Ok(n) => {
                if raw_flags & UBLK_IO_F_FUA != 0 {
                    if let Err(e) = dispatcher.flush() {
                        self.error_ops += 1;
                        self.barrier_audit
                            .record(BarrierType::FuaWrite, BarrierResult::Failed);
                        return Err(DataQueueWorkerError::BackingStoreError(e.linux_errno()));
                    }
                    self.barrier_audit
                        .record(BarrierType::FuaWrite, BarrierResult::Completed);
                }
                self.bytes_written += n as u64;
                self.write_ops += 1;
                self.completed_ops += 1;
                Ok(DataQueueWorkerResultEntry {
                    tag,
                    request_class: BlockVolumeRequestClass::Write,
                    completion_class: BlockVolumeCompletionClass::Completed,
                    io_cmd: UblkSrvIoCmd {
                        q_id: self.queue_id,
                        tag,
                        result: UBLK_IO_RES_OK,
                        addr_or_zone_append_lba: 0,
                    },
                    byte_count: n,
                })
            }
            Err(err) => {
                self.error_ops += 1;
                let errno = err.linux_errno();
                Err(DataQueueWorkerError::BackingStoreError(errno))
            }
        }
    }

    fn dispatch_flush_io_uring(
        &mut self,
        dispatcher: &mut UblkIoUringDispatcher,
        tag: u16,
        _desc: &UblkSrvIoDesc,
        raw_flags: u32,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        // Accept all kernel raw flags; flags are advisory hints.
        let _ = raw_flags;
        match dispatcher.flush() {
            Ok(()) => {
                self.flush_ops += 1;
                self.completed_ops += 1;
                self.barrier_audit
                    .record(BarrierType::Flush, BarrierResult::Completed);
                Ok(DataQueueWorkerResultEntry {
                    tag,
                    request_class: BlockVolumeRequestClass::Flush,
                    completion_class: BlockVolumeCompletionClass::Completed,
                    io_cmd: UblkSrvIoCmd {
                        q_id: self.queue_id,
                        tag,
                        result: UBLK_IO_RES_OK,
                        addr_or_zone_append_lba: 0,
                    },
                    byte_count: 0,
                })
            }
            Err(err) => {
                self.error_ops += 1;
                self.barrier_audit
                    .record(BarrierType::Flush, BarrierResult::Failed);
                let errno = err.linux_errno();
                Err(DataQueueWorkerError::BackingStoreError(errno))
            }
        }
    }

    fn dispatch_discard_io_uring(
        &mut self,
        dispatcher: &mut UblkIoUringDispatcher,
        tag: u16,
        desc: &UblkSrvIoDesc,
        raw_flags: u32,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        // Accept all kernel raw flags; flags are advisory hints.
        let _ = raw_flags;
        let range = match self.project_range(desc) {
            Ok(range) => range,
            Err(DataQueueWorkerError::OutOfRange) => {
                return Ok(self.refused_entry(
                    tag,
                    BlockVolumeRequestClass::Discard,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                ));
            }
            Err(err) => return Err(err),
        };
        let offset = (range.start_block * self.geometry.block_size_bytes) as u64;
        let byte_count = (range.block_count * self.geometry.block_size_bytes) as u64;

        match dispatcher.discard_at(offset, byte_count) {
            Ok(()) => {
                self.discard_ops += 1;
                self.completed_ops += 1;
                Ok(DataQueueWorkerResultEntry {
                    tag,
                    request_class: BlockVolumeRequestClass::Discard,
                    completion_class: BlockVolumeCompletionClass::Completed,
                    io_cmd: UblkSrvIoCmd {
                        q_id: self.queue_id,
                        tag,
                        result: UBLK_IO_RES_OK,
                        addr_or_zone_append_lba: 0,
                    },
                    byte_count: 0,
                })
            }
            Err(err) => {
                self.error_ops += 1;
                let errno = err.linux_errno();
                Err(DataQueueWorkerError::BackingStoreError(errno))
            }
        }
    }

    fn dispatch_write_zeroes_io_uring(
        &mut self,
        dispatcher: &mut UblkIoUringDispatcher,
        tag: u16,
        desc: &UblkSrvIoDesc,
        raw_flags: u32,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        // Accept all kernel raw flags; flags are advisory hints.
        let _ = raw_flags;
        let range = match self.project_range(desc) {
            Ok(range) => range,
            Err(DataQueueWorkerError::OutOfRange) => {
                return Ok(self.refused_entry(
                    tag,
                    BlockVolumeRequestClass::WriteZeroes,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                ));
            }
            Err(err) => return Err(err),
        };
        let offset = (range.start_block * self.geometry.block_size_bytes) as u64;
        let byte_count = (range.block_count * self.geometry.block_size_bytes) as u64;

        match dispatcher.write_zeroes_at(offset, byte_count) {
            Ok(()) => {
                self.write_zeroes_ops += 1;
                self.completed_ops += 1;
                Ok(DataQueueWorkerResultEntry {
                    tag,
                    request_class: BlockVolumeRequestClass::WriteZeroes,
                    completion_class: BlockVolumeCompletionClass::Completed,
                    io_cmd: UblkSrvIoCmd {
                        q_id: self.queue_id,
                        tag,
                        result: UBLK_IO_RES_OK,
                        addr_or_zone_append_lba: 0,
                    },
                    byte_count: 0,
                })
            }
            Err(err) => {
                self.error_ops += 1;
                let errno = err.linux_errno();
                Err(DataQueueWorkerError::BackingStoreError(errno))
            }
        }
    }

    fn dispatch_read(
        &mut self,
        backend: &mut dyn BlockVolumeStorageBackend,
        tag: u16,
        desc: &UblkSrvIoDesc,
        raw_flags: u32,
        read_buffer: Option<&mut [u8]>,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        // Accept all kernel raw flags; flags are advisory hints.
        let _ = raw_flags;
        let range = match self.project_range(desc) {
            Ok(range) => range,
            Err(DataQueueWorkerError::OutOfRange) => {
                return Ok(self.refused_entry(
                    tag,
                    BlockVolumeRequestClass::Read,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                ));
            }
            Err(err) => return Err(err),
        };
        let (byte_offset, requested_bytes) = self.sector_byte_range(desc);
        match backend.read_blocks(
            range.start_block,
            range.block_count,
            self.geometry.block_size_bytes,
        ) {
            Ok(result) => {
                if result.completion_class != BlockVolumeCompletionClass::Completed {
                    self.error_ops += 1;
                    return Ok(DataQueueWorkerResultEntry {
                        tag,
                        request_class: BlockVolumeRequestClass::Read,
                        completion_class: result.completion_class,
                        io_cmd: self.refusal_io_cmd(tag, &result.completion_class),
                        byte_count: 0,
                    });
                }
                if let Some(payload) = result.payload {
                    // Trim to the originally requested byte range
                    let trimmed = &payload[byte_offset..byte_offset + requested_bytes];
                    let byte_count = trimmed.len();
                    if let Some(buffer) = read_buffer {
                        if buffer.len() < byte_count {
                            self.error_ops += 1;
                            return Err(DataQueueWorkerError::PayloadBufferTooShort);
                        }
                        buffer[..byte_count].copy_from_slice(trimmed);
                    }
                    self.bytes_read += byte_count as u64;
                    self.read_ops += 1;
                    self.completed_ops += 1;
                    Ok(DataQueueWorkerResultEntry {
                        tag,
                        request_class: BlockVolumeRequestClass::Read,
                        completion_class: BlockVolumeCompletionClass::Completed,
                        io_cmd: UblkSrvIoCmd {
                            q_id: self.queue_id,
                            tag,
                            result: UBLK_IO_RES_OK,
                            addr_or_zone_append_lba: 0,
                        },
                        byte_count,
                    })
                } else {
                    self.error_ops += 1;
                    Err(DataQueueWorkerError::BackingStoreError(-libc::EIO))
                }
            }
            Err(BackendError::Io(e)) => {
                self.error_ops += 1;
                let errno = -e.raw_os_error().unwrap_or(libc::EIO);
                Err(DataQueueWorkerError::BackingStoreError(errno))
            }
            Err(BackendError::NoSpace) => {
                self.error_ops += 1;
                Err(DataQueueWorkerError::BackingStoreError(-libc::ENOSPC))
            }
            Err(_) => {
                self.error_ops += 1;
                Err(DataQueueWorkerError::OutOfRange)
            }
        }
    }

    fn dispatch_write(
        &mut self,
        backend: &mut dyn BlockVolumeStorageBackend,
        tag: u16,
        desc: &UblkSrvIoDesc,
        raw_flags: u32,
        write_payload: Option<&[u8]>,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        // Accept all kernel raw flags; FUA handled below for write durability.
        let _ = raw_flags;
        let range = match self.project_range(desc) {
            Ok(range) => range,
            Err(DataQueueWorkerError::OutOfRange) => {
                return Ok(self.refused_entry(
                    tag,
                    BlockVolumeRequestClass::Write,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                ));
            }
            Err(err) => return Err(err),
        };
        let byte_count = range.block_count * self.geometry.block_size_bytes;
        let payload = match write_payload {
            Some(payload) => {
                if payload.len() < byte_count {
                    self.error_ops += 1;
                    return Err(DataQueueWorkerError::PayloadBufferTooShort);
                }
                &payload[..byte_count]
            }
            None => {
                self.error_ops += 1;
                return Err(DataQueueWorkerError::MissingBufferAddress);
            }
        };
        match backend.write_blocks(range.start_block, payload, self.geometry.block_size_bytes) {
            Ok(result) => {
                if result.completion_class != BlockVolumeCompletionClass::Completed {
                    self.error_ops += 1;
                    return Ok(DataQueueWorkerResultEntry {
                        tag,
                        request_class: BlockVolumeRequestClass::Write,
                        completion_class: result.completion_class,
                        io_cmd: self.refusal_io_cmd(tag, &result.completion_class),
                        byte_count: 0,
                    });
                }
                if raw_flags & UBLK_IO_F_FUA != 0 {
                    if let Err(e) = backend.flush() {
                        self.error_ops += 1;
                        self.barrier_audit
                            .record(BarrierType::FuaWrite, BarrierResult::Failed);
                        let errno = match e {
                            BackendError::Io(io) => -io.raw_os_error().unwrap_or(libc::EIO),
                            _ => -libc::EIO,
                        };
                        return Err(DataQueueWorkerError::BackingStoreError(errno));
                    }
                    let cr = backend.last_committed_root();
                    self.barrier_audit.record_with_root(
                        BarrierType::FuaWrite,
                        BarrierResult::Completed,
                        cr,
                    );
                }
                self.bytes_written += byte_count as u64;
                self.write_ops += 1;
                self.completed_ops += 1;
                Ok(DataQueueWorkerResultEntry {
                    tag,
                    request_class: BlockVolumeRequestClass::Write,
                    completion_class: BlockVolumeCompletionClass::Completed,
                    io_cmd: UblkSrvIoCmd {
                        q_id: self.queue_id,
                        tag,
                        result: UBLK_IO_RES_OK,
                        addr_or_zone_append_lba: 0,
                    },
                    byte_count,
                })
            }
            Err(BackendError::Io(e)) => {
                self.error_ops += 1;
                let errno = -e.raw_os_error().unwrap_or(libc::EIO);
                Err(DataQueueWorkerError::BackingStoreError(errno))
            }
            Err(BackendError::NoSpace) => {
                self.error_ops += 1;
                Err(DataQueueWorkerError::BackingStoreError(-libc::ENOSPC))
            }
            Err(_) => {
                self.error_ops += 1;
                Err(DataQueueWorkerError::OutOfRange)
            }
        }
    }

    fn dispatch_flush(
        &mut self,
        backend: &mut dyn BlockVolumeStorageBackend,
        tag: u16,
        desc: &UblkSrvIoDesc,
        raw_flags: u32,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        // Accept all kernel raw flags; flags are advisory hints.
        let _ = raw_flags;
        if desc.start_sector != 0 || desc.count_or_zones != 0 {
            self.error_ops += 1;
            return Err(DataQueueWorkerError::RangeOnFlush);
        }
        if desc.addr != 0 {
            self.error_ops += 1;
            return Err(DataQueueWorkerError::UnexpectedBufferAddress);
        }
        match backend.flush() {
            Ok(()) => {
                self.flush_ops += 1;
                self.completed_ops += 1;
                let cr = backend.last_committed_root();
                self.barrier_audit.record_with_root(
                    BarrierType::Flush,
                    BarrierResult::Completed,
                    cr,
                );
                Ok(DataQueueWorkerResultEntry {
                    tag,
                    request_class: BlockVolumeRequestClass::Flush,
                    completion_class: BlockVolumeCompletionClass::Completed,
                    io_cmd: UblkSrvIoCmd {
                        q_id: self.queue_id,
                        tag,
                        result: UBLK_IO_RES_OK,
                        addr_or_zone_append_lba: 0,
                    },
                    byte_count: 0,
                })
            }
            Err(BackendError::Io(e)) => {
                self.error_ops += 1;
                self.barrier_audit
                    .record(BarrierType::Flush, BarrierResult::Failed);
                let errno = e.raw_os_error().unwrap_or(-libc::EIO);
                Err(DataQueueWorkerError::BackingStoreError(errno))
            }
            Err(BackendError::NoSpace) => {
                self.error_ops += 1;
                self.barrier_audit
                    .record(BarrierType::Flush, BarrierResult::Failed);
                Err(DataQueueWorkerError::BackingStoreError(-libc::ENOSPC))
            }
            Err(_) => {
                self.error_ops += 1;
                self.barrier_audit
                    .record(BarrierType::Flush, BarrierResult::Failed);
                Err(DataQueueWorkerError::BackingStoreError(-libc::EIO))
            }
        }
    }

    fn dispatch_discard(
        &mut self,
        backend: &mut dyn BlockVolumeStorageBackend,
        tag: u16,
        desc: &UblkSrvIoDesc,
        raw_flags: u32,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        // Accept all kernel raw flags; flags are advisory hints.
        let _ = raw_flags;
        let range = match self.project_range(desc) {
            Ok(range) => range,
            Err(DataQueueWorkerError::OutOfRange) => {
                return Ok(self.refused_entry(
                    tag,
                    BlockVolumeRequestClass::Discard,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                ));
            }
            Err(err) => return Err(err),
        };
        match backend.discard_blocks(
            range.start_block,
            range.block_count,
            self.geometry.block_size_bytes,
        ) {
            Ok(()) => {
                self.discard_ops += 1;
                self.completed_ops += 1;
                Ok(DataQueueWorkerResultEntry {
                    tag,
                    request_class: BlockVolumeRequestClass::Discard,
                    completion_class: BlockVolumeCompletionClass::Completed,
                    io_cmd: UblkSrvIoCmd {
                        q_id: self.queue_id,
                        tag,
                        result: UBLK_IO_RES_OK,
                        addr_or_zone_append_lba: 0,
                    },
                    byte_count: 0,
                })
            }
            Err(BackendError::Io(e)) => {
                self.error_ops += 1;
                let errno = -e.raw_os_error().unwrap_or(libc::EIO);
                Err(DataQueueWorkerError::BackingStoreError(errno))
            }
            Err(BackendError::NoSpace) => {
                self.error_ops += 1;
                Err(DataQueueWorkerError::BackingStoreError(-libc::ENOSPC))
            }
            Err(_) => {
                self.error_ops += 1;
                Err(DataQueueWorkerError::OutOfRange)
            }
        }
    }

    fn dispatch_write_zeroes(
        &mut self,
        backend: &mut dyn BlockVolumeStorageBackend,
        tag: u16,
        desc: &UblkSrvIoDesc,
        raw_flags: u32,
    ) -> Result<DataQueueWorkerResultEntry, DataQueueWorkerError> {
        // Accept all kernel raw flags; flags are advisory hints.
        let _ = raw_flags;
        let range = match self.project_range(desc) {
            Ok(range) => range,
            Err(DataQueueWorkerError::OutOfRange) => {
                return Ok(self.refused_entry(
                    tag,
                    BlockVolumeRequestClass::WriteZeroes,
                    BlockVolumeCompletionClass::RefusedOutOfBounds,
                ));
            }
            Err(err) => return Err(err),
        };
        match backend.write_zeroes(
            range.start_block,
            range.block_count,
            self.geometry.block_size_bytes,
        ) {
            Ok(()) => {
                self.write_zeroes_ops += 1;
                self.completed_ops += 1;
                Ok(DataQueueWorkerResultEntry {
                    tag,
                    request_class: BlockVolumeRequestClass::WriteZeroes,
                    completion_class: BlockVolumeCompletionClass::Completed,
                    io_cmd: UblkSrvIoCmd {
                        q_id: self.queue_id,
                        tag,
                        result: UBLK_IO_RES_OK,
                        addr_or_zone_append_lba: 0,
                    },
                    byte_count: 0,
                })
            }
            Err(BackendError::Io(e)) => {
                self.error_ops += 1;
                let errno = -e.raw_os_error().unwrap_or(libc::EIO);
                Err(DataQueueWorkerError::BackingStoreError(errno))
            }
            Err(BackendError::NoSpace) => {
                self.error_ops += 1;
                Err(DataQueueWorkerError::BackingStoreError(-libc::ENOSPC))
            }
            Err(_) => {
                self.error_ops += 1;
                Err(DataQueueWorkerError::OutOfRange)
            }
        }
    }

    fn project_range(
        &self,
        desc: &UblkSrvIoDesc,
    ) -> Result<BlockRangeRecord, DataQueueWorkerError> {
        // Round to block-aligned range, accepting unaligned sector requests.
        let sectors_per_block = self.geometry.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
        if sectors_per_block == 0 {
            return Err(DataQueueWorkerError::BlockSizeBelowLinuxSector);
        }
        let start_sector =
            usize::try_from(desc.start_sector).map_err(|_| DataQueueWorkerError::RangeOverflow)?;
        let sector_count = usize::try_from(desc.count_or_zones)
            .map_err(|_| DataQueueWorkerError::RangeOverflow)?;
        if sector_count == 0 {
            return Err(DataQueueWorkerError::ZeroLengthDataOperation);
        }
        let start_block = start_sector / sectors_per_block;
        let end_sector = start_sector + sector_count;
        let end_block = end_sector.div_ceil(sectors_per_block);
        let block_count = end_block
            .checked_sub(start_block)
            .ok_or(DataQueueWorkerError::RangeOverflow)?;
        if end_block > self.geometry.block_count {
            return Err(DataQueueWorkerError::OutOfRange);
        }
        Ok(BlockRangeRecord::new(start_block, block_count))
    }

    /// Returns the exact byte range requested by the IO descriptor:
    /// (byte_offset_in_first_block, total_requested_bytes)
    fn sector_byte_range(&self, desc: &UblkSrvIoDesc) -> (usize, usize) {
        let sectors_per_block = self.geometry.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
        let start_sector = desc.start_sector as usize;
        let sector_count = desc.count_or_zones as usize;
        let byte_offset = (start_sector % sectors_per_block) * LINUX_SECTOR_SIZE_BYTES;
        let requested_bytes = sector_count * LINUX_SECTOR_SIZE_BYTES;
        (byte_offset, requested_bytes)
    }

    /// Compute the read buffer size needed for the IO descriptor,
    /// rounding up to cover the full expanded block range.
    pub(crate) fn read_buffer_size(&self, desc: &UblkSrvIoDesc) -> usize {
        let sectors_per_block = self.geometry.block_size_bytes / LINUX_SECTOR_SIZE_BYTES;
        let sector_count = desc.count_or_zones as usize;
        let block_count = sector_count.div_ceil(sectors_per_block);
        block_count * self.geometry.block_size_bytes
    }
    fn refusal_io_cmd(
        &self,
        tag: u16,
        completion_class: &BlockVolumeCompletionClass,
    ) -> UblkSrvIoCmd {
        let result = match completion_class {
            BlockVolumeCompletionClass::RefusedOutOfBounds => -22,
            BlockVolumeCompletionClass::RefusedMisalignedRange => -22,
            BlockVolumeCompletionClass::RefusedDiscardUnsupported => -95,
            BlockVolumeCompletionClass::RefusedBackpressure => -11,
            BlockVolumeCompletionClass::RefusedExportFenced => UBLK_IO_RES_ABORT,
            BlockVolumeCompletionClass::RefusedUnadmittedContext => -2,
            BlockVolumeCompletionClass::RefusedPayloadMismatch => -22,
            BlockVolumeCompletionClass::Completed => UBLK_IO_RES_OK,
        };
        UblkSrvIoCmd {
            q_id: self.queue_id,
            tag,
            result,
            addr_or_zone_append_lba: 0,
        }
    }

    fn refused_entry(
        &mut self,
        tag: u16,
        request_class: BlockVolumeRequestClass,
        completion_class: BlockVolumeCompletionClass,
    ) -> DataQueueWorkerResultEntry {
        self.error_ops += 1;
        DataQueueWorkerResultEntry {
            tag,
            request_class,
            completion_class,
            io_cmd: self.refusal_io_cmd(tag, &completion_class),
            byte_count: 0,
        }
    }

    pub fn run_bounded(
        &mut self,
        backend: &mut dyn BlockVolumeStorageBackend,
        descriptors: &[(u16, UblkSrvIoDesc)],
    ) -> DataQueueWorkerReport {
        let limit = self.max_queue_depth.unwrap_or(descriptors.len());
        let mut results = Vec::with_capacity(descriptors.len());
        for &(tag, ref desc) in descriptors.iter().take(limit) {
            match self.process_one(backend, tag, desc) {
                Ok(entry) => results.push(entry),
                Err(err) => {
                    let request_class = match desc.op() {
                        UBLK_IO_OP_WRITE => BlockVolumeRequestClass::Write,
                        UBLK_IO_OP_FLUSH => BlockVolumeRequestClass::Flush,
                        UBLK_IO_OP_DISCARD => BlockVolumeRequestClass::Discard,
                        UBLK_IO_OP_WRITE_ZEROES => BlockVolumeRequestClass::WriteZeroes,
                        _ => BlockVolumeRequestClass::Read,
                    };
                    results.push(DataQueueWorkerResultEntry {
                        tag,
                        request_class,
                        completion_class: BlockVolumeCompletionClass::RefusedUnadmittedContext,
                        io_cmd: UblkSrvIoCmd {
                            q_id: self.queue_id,
                            tag,
                            result: err.linux_errno(),
                            addr_or_zone_append_lba: 0,
                        },
                        byte_count: 0,
                    });
                }
            }
        }
        // Refuse descriptors beyond the configured queue depth with backpressure
        for &(tag, _) in descriptors.iter().skip(limit) {
            self.error_ops += 1;
            results.push(DataQueueWorkerResultEntry {
                tag,
                request_class: BlockVolumeRequestClass::Read,
                completion_class: BlockVolumeCompletionClass::RefusedBackpressure,
                io_cmd: UblkSrvIoCmd {
                    q_id: self.queue_id,
                    tag,
                    result: -(libc::ENOSPC),
                    addr_or_zone_append_lba: 0,
                },
                byte_count: 0,
            });
        }
        self.report(results)
    }

    fn report(&self, results: Vec<DataQueueWorkerResultEntry>) -> DataQueueWorkerReport {
        DataQueueWorkerReport {
            queue_id: self.queue_id,
            bytes_read: self.bytes_read,
            bytes_written: self.bytes_written,
            read_ops: self.read_ops,
            write_ops: self.write_ops,
            flush_ops: self.flush_ops,
            discard_ops: self.discard_ops,
            write_zeroes_ops: self.write_zeroes_ops,
            completed_ops: self.completed_ops,
            error_ops: self.error_ops,
            unsupported_ops: self.unsupported_ops,
            results,
        }
    }
}

fn data_queue_worker_smoke_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| (idx as u8).wrapping_mul(37).wrapping_add(11))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tidefs_block_volume_adapter_core::{
        BlockVolumeCompletionClass, BlockVolumeGeometryRecord, BlockVolumeId,
    };
    use tidefs_ublk_abi::UBLK_IO_F_FUA;

    fn test_geometry() -> BlockVolumeGeometryRecord {
        BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_100), 4096, 1024, 1)
    }

    fn test_image() -> (tempfile::TempDir, BlockVolumeFileImage) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.img");
        let image =
            BlockVolumeFileImage::create_zeroed(&path, test_geometry()).expect("create image");
        (dir, image)
    }

    struct RawErrBackend {
        geometry: BlockVolumeGeometryRecord,
        errno: i32,
    }

    impl RawErrBackend {
        fn new(errno: i32) -> Self {
            Self {
                geometry: test_geometry(),
                errno,
            }
        }

        fn raw_error(&self) -> io::Error {
            io::Error::from_raw_os_error(self.errno)
        }
    }

    impl BlockVolumeStorageBackend for RawErrBackend {
        fn read_blocks(
            &self,
            _start_block: usize,
            _block_count: usize,
            _block_size_bytes: usize,
        ) -> Result<crate::storage_backend::BackendReadResult, crate::storage_backend::BackendError>
        {
            Err(crate::storage_backend::BackendError::Io(self.raw_error()))
        }

        fn write_blocks(
            &mut self,
            _start_block: usize,
            _payload: &[u8],
            _block_size_bytes: usize,
        ) -> Result<crate::storage_backend::BackendWriteResult, crate::storage_backend::BackendError>
        {
            Err(crate::storage_backend::BackendError::Io(self.raw_error()))
        }

        fn flush(&mut self) -> Result<(), crate::storage_backend::BackendError> {
            Err(crate::storage_backend::BackendError::Io(self.raw_error()))
        }

        fn discard_blocks(
            &mut self,
            _start_block: usize,
            _block_count: usize,
            _block_size_bytes: usize,
        ) -> Result<(), crate::storage_backend::BackendError> {
            Err(crate::storage_backend::BackendError::Io(self.raw_error()))
        }

        fn write_zeroes(
            &mut self,
            _start_block: usize,
            _block_count: usize,
            _block_size_bytes: usize,
        ) -> Result<(), crate::storage_backend::BackendError> {
            Err(crate::storage_backend::BackendError::Io(self.raw_error()))
        }

        fn geometry(&self) -> BlockVolumeGeometryRecord {
            self.geometry
        }
    }

    fn io_desc(
        op: u8,
        raw_flags: u32,
        start_sector: u64,
        count_or_zones: u32,
        addr: u64,
    ) -> UblkSrvIoDesc {
        UblkSrvIoDesc {
            op_flags: u32::from(op) | raw_flags,
            count_or_zones,
            start_sector,
            addr,
        }
    }

    const DEMO_BUFFER_ADDR: u64 = 0x1000_0000;

    #[test]
    fn worker_new_has_zero_counters() {
        let worker = DataQueueWorker::new(0, test_geometry());
        assert_eq!(worker.queue_id, 0);
        assert_eq!(worker.bytes_read, 0);
        assert_eq!(worker.bytes_written, 0);
        assert_eq!(worker.read_ops, 0);
        assert_eq!(worker.write_ops, 0);
        assert_eq!(worker.flush_ops, 0);
        assert_eq!(worker.completed_ops, 0);
        assert_eq!(worker.error_ops, 0);
    }

    #[test]
    fn worker_gate_constant_is_stable() {
        assert_eq!(
            BLOCK_VOLUME_UBLK_DATA_QUEUE_WORKER_GATE_OW_301Z,
            "OW-301Z block-volume adapter ublk data-queue worker dispatches read/write/flush descriptors to the backing image and returns kernel-visible completion status"
        );
    }

    #[test]
    fn worker_rejects_unsupported_operation_codes() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        let result = worker.process_one(&mut image, 0, &io_desc(0xff, 0, 0, 8, DEMO_BUFFER_ADDR));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            DataQueueWorkerError::UnsupportedOperation
        );
        assert_eq!(worker.unsupported_ops, 1);
        assert_eq!(worker.error_ops, 1);
    }

    #[test]
    fn worker_rejects_write_same() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        let result = worker.process_one(
            &mut image,
            0,
            &io_desc(UBLK_IO_OP_WRITE_SAME, 0, 0, 8, DEMO_BUFFER_ADDR),
        );
        assert_eq!(
            result.unwrap_err(),
            DataQueueWorkerError::UnsupportedWriteSame
        );
    }

    #[test]
    fn worker_rejects_zoned_operations() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        for op in &[10u8, 11, 12, 13, 14, 15, 18] {
            let result =
                worker.process_one(&mut image, 0, &io_desc(*op, 0, 0, 8, DEMO_BUFFER_ADDR));
            assert_eq!(
                result.unwrap_err(),
                DataQueueWorkerError::UnsupportedZonedOperation
            );
        }
    }

    #[test]
    fn worker_read_returns_completed_with_zeroes_from_new_image() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        let result = worker
            .process_one(
                &mut image,
                1,
                &io_desc(UBLK_IO_OP_READ, 0, 0, 8, DEMO_BUFFER_ADDR),
            )
            .expect("read should succeed");
        assert_eq!(result.request_class, BlockVolumeRequestClass::Read);
        assert_eq!(
            result.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(result.io_cmd.result, UBLK_IO_RES_OK);
        assert_eq!(result.io_cmd.tag, 1);
        assert_eq!(result.byte_count, 4096);
        assert_eq!(worker.bytes_read, 4096);
        assert_eq!(worker.read_ops, 1);
        assert_eq!(worker.completed_ops, 1);
        assert_eq!(worker.error_ops, 0);
    }

    #[test]
    fn worker_read_accepts_zero_addr_for_user_copy() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        // addr=0 is legitimate with USER_COPY data-path mode.
        // The legacy EINVAL at sector 0 was caused by rejecting
        // addr==0 descriptors that are valid in the fd-backed
        // data queue direction (#6369).
        let result = worker.process_one(&mut image, 0, &io_desc(UBLK_IO_OP_READ, 0, 0, 8, 0));
        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_eq!(
            entry.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(entry.byte_count, 4096);
    }

    #[test]
    fn worker_read_rejects_out_of_range() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        let result = worker.process_one(
            &mut image,
            0,
            &io_desc(UBLK_IO_OP_READ, 0, 8192, 8, DEMO_BUFFER_ADDR),
        );
        // out of range => refusal via image, not our error
        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_eq!(
            entry.completion_class,
            BlockVolumeCompletionClass::RefusedOutOfBounds
        );
        assert_eq!(entry.io_cmd.result, -22);
        assert_eq!(worker.error_ops, 1);
    }

    #[test]
    fn worker_read_rounds_misaligned_range_to_block_boundary() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        // Sector 1 count 8 (crosses block boundary): now rounds to block-aligned range.
        let result = worker.process_one(
            &mut image,
            0,
            &io_desc(UBLK_IO_OP_READ, 0, 1, 8, DEMO_BUFFER_ADDR),
        );
        assert!(
            result.is_ok(),
            "misaligned range rounded to block boundary, got {:?}",
            result.err()
        );
        let entry = result.unwrap();
        assert_eq!(
            entry.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(entry.byte_count > 0);
    }

    #[test]
    fn worker_read_accepts_any_raw_flags_as_advisory() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        // All raw flags are now accepted as advisory hints; no rejection.
        let result = worker.process_one(
            &mut image,
            0,
            &io_desc(UBLK_IO_OP_READ, 1 << 17, 0, 8, DEMO_BUFFER_ADDR),
        );
        assert!(
            result.is_ok(),
            "raw flags now accepted, got {:?}",
            result.err()
        );
        let entry = result.unwrap();
        assert_eq!(
            entry.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert!(entry.byte_count > 0);
    }

    #[test]
    fn worker_write_succeeds_and_updates_counters() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        let write_payload = vec![0xAB; 4096];
        let result = worker
            .process_one_with_buffers(
                &mut image,
                3,
                &io_desc(UBLK_IO_OP_WRITE, 0, 0, 8, DEMO_BUFFER_ADDR),
                None,
                Some(&write_payload),
            )
            .expect("write should succeed");
        assert_eq!(result.request_class, BlockVolumeRequestClass::Write);
        assert_eq!(
            result.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(result.io_cmd.result, UBLK_IO_RES_OK);
        assert_eq!(result.byte_count, 4096);
        assert_eq!(worker.bytes_written, 4096);
        assert_eq!(worker.write_ops, 1);
        assert_eq!(worker.completed_ops, 1);
    }

    #[test]
    fn worker_write_with_fua_succeeds() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        let fua_write_payload = vec![0xEF; 4096];
        let result = worker
            .process_one_with_buffers(
                &mut image,
                4,
                &io_desc(UBLK_IO_OP_WRITE, UBLK_IO_F_FUA, 0, 8, DEMO_BUFFER_ADDR),
                None,
                Some(&fua_write_payload),
            )
            .expect("FUA write should succeed");
        assert_eq!(result.request_class, BlockVolumeRequestClass::Write);
        assert_eq!(
            result.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(result.io_cmd.result, UBLK_IO_RES_OK);
        assert_eq!(worker.bytes_written, 4096);
    }

    #[test]
    fn worker_flush_succeeds() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        let desc = io_desc(UBLK_IO_OP_FLUSH, 0, 0, 0, 0);
        let result = worker
            .process_one(&mut image, 5, &desc)
            .expect("flush should succeed");
        assert_eq!(desc.start_sector, 0);
        assert_eq!(desc.count_or_zones, 0);
        assert_eq!(desc.addr, 0);
        assert_eq!(result.request_class, BlockVolumeRequestClass::Flush);
        assert_eq!(
            result.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(result.io_cmd.result, UBLK_IO_RES_OK);
        assert_eq!(result.byte_count, 0);
        assert_eq!(worker.flush_ops, 1);
        assert_eq!(worker.completed_ops, 1);
    }

    #[test]
    fn worker_flush_rejects_range_and_buffer_shape() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);

        let start_sector =
            worker.process_one(&mut image, 5, &io_desc(UBLK_IO_OP_FLUSH, 0, 8, 0, 0));
        assert_eq!(
            start_sector.unwrap_err(),
            DataQueueWorkerError::RangeOnFlush
        );

        let count = worker.process_one(&mut image, 6, &io_desc(UBLK_IO_OP_FLUSH, 0, 0, 8, 0));
        assert_eq!(count.unwrap_err(), DataQueueWorkerError::RangeOnFlush);

        let buffer = worker.process_one(
            &mut image,
            7,
            &io_desc(UBLK_IO_OP_FLUSH, 0, 0, 0, DEMO_BUFFER_ADDR),
        );
        assert_eq!(
            buffer.unwrap_err(),
            DataQueueWorkerError::UnexpectedBufferAddress
        );

        assert_eq!(worker.flush_ops, 0);
        assert_eq!(worker.completed_ops, 0);
        assert_eq!(worker.error_ops, 3);
    }

    #[test]
    fn worker_discard_succeeds() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        let result = worker
            .process_one(&mut image, 6, &io_desc(UBLK_IO_OP_DISCARD, 0, 0, 8, 0))
            .expect("discard should succeed");
        assert_eq!(result.request_class, BlockVolumeRequestClass::Discard);
        assert_eq!(result.io_cmd.result, UBLK_IO_RES_OK);
        assert_eq!(worker.discard_ops, 1);
        assert_eq!(worker.completed_ops, 1);
    }

    #[test]
    fn worker_write_zeroes_succeeds() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        let result = worker
            .process_one(&mut image, 7, &io_desc(UBLK_IO_OP_WRITE_ZEROES, 0, 0, 8, 0))
            .expect("write_zeroes should succeed");
        assert_eq!(result.request_class, BlockVolumeRequestClass::WriteZeroes);
        assert_eq!(result.io_cmd.result, UBLK_IO_RES_OK);
        assert_eq!(worker.write_zeroes_ops, 1);
        assert_eq!(worker.completed_ops, 1);
    }

    #[test]
    fn worker_run_bounded_processes_multiple_descriptors_in_order() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(1, geometry);

        let descriptors: Vec<(u16, UblkSrvIoDesc)> = vec![
            (10, io_desc(UBLK_IO_OP_WRITE, 0, 0, 8, DEMO_BUFFER_ADDR)),
            (
                11,
                io_desc(UBLK_IO_OP_READ, 0, 0, 8, DEMO_BUFFER_ADDR + 4096),
            ),
            (12, io_desc(UBLK_IO_OP_FLUSH, 0, 0, 0, 0)),
        ];

        let report = worker.run_bounded(&mut image, &descriptors);
        assert_eq!(report.queue_id, 1);
        assert_eq!(report.results.len(), 3);
        assert_eq!(report.write_ops, 0);
        assert_eq!(report.read_ops, 1);
        assert_eq!(report.flush_ops, 1);
        assert_eq!(report.completed_ops, 2);
        assert_eq!(report.error_ops, 1);
        assert_eq!(report.bytes_written, 0);
        assert_eq!(report.bytes_read, 4096);

        // Write without buffer now correctly errors
        assert_eq!(report.results[0].tag, 10);
        assert_eq!(
            report.results[0].request_class,
            BlockVolumeRequestClass::Write
        );
        assert!(
            report.results[0].io_cmd.result < 0,
            "write without buffer must error"
        );
        assert_eq!(report.results[1].tag, 11);
        assert_eq!(
            report.results[1].request_class,
            BlockVolumeRequestClass::Read
        );
        assert_eq!(
            report.results[1].completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(report.results[1].io_cmd.result, UBLK_IO_RES_OK);
        assert_eq!(report.results[2].tag, 12);
        assert_eq!(
            report.results[2].request_class,
            BlockVolumeRequestClass::Flush
        );
        assert_eq!(
            report.results[2].completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(report.results[2].io_cmd.result, UBLK_IO_RES_OK);
    }

    #[test]
    fn worker_run_bounded_handles_errors_without_stopping() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(2, geometry);

        let descriptors: Vec<(u16, UblkSrvIoDesc)> = vec![
            (20, io_desc(UBLK_IO_OP_READ, 0, 0, 8, DEMO_BUFFER_ADDR)),
            (21, io_desc(0xff, 0, 0, 0, 0)),
            (
                22,
                io_desc(UBLK_IO_OP_WRITE, 0, 0, 8, DEMO_BUFFER_ADDR + 4096),
            ),
            (23, io_desc(UBLK_IO_OP_FLUSH, 0, 0, 0, 0)),
        ];

        let report = worker.run_bounded(&mut image, &descriptors);
        assert_eq!(report.results.len(), 4);
        assert_eq!(report.completed_ops, 2);
        assert_eq!(report.error_ops, 2);
        assert_eq!(report.unsupported_ops, 1);

        assert_eq!(
            report.results[0].completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(report.results[1].io_cmd.result, -95);
        // Write without buffer now correctly errors
        assert!(
            report.results[2].io_cmd.result < 0,
            "write without buffer must error, got {}",
            report.results[2].io_cmd.result
        );
        assert_eq!(
            report.results[3].completion_class,
            BlockVolumeCompletionClass::Completed
        );
    }

    #[test]
    fn worker_run_bounded_empty_descriptors_is_noop() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(3, geometry);
        let report = worker.run_bounded(&mut image, &[]);
        assert_eq!(report.results.len(), 0);
        assert_eq!(report.completed_ops, 0);
        assert_eq!(report.error_ops, 0);
    }

    #[test]
    fn worker_write_then_read_round_trip_through_worker() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(4, geometry);
        let write_payload = vec![0xA5; 4096];

        let write_result = worker
            .process_one_with_buffers(
                &mut image,
                30,
                &io_desc(UBLK_IO_OP_WRITE, 0, 0, 8, DEMO_BUFFER_ADDR),
                None,
                Some(&write_payload),
            )
            .expect("write");
        assert_eq!(
            write_result.completion_class,
            BlockVolumeCompletionClass::Completed
        );

        let flush_result = worker
            .process_one(&mut image, 31, &io_desc(UBLK_IO_OP_FLUSH, 0, 0, 0, 0))
            .expect("flush");
        assert_eq!(
            flush_result.completion_class,
            BlockVolumeCompletionClass::Completed
        );

        let mut read_buffer = vec![0; 4096];
        let read_result = worker
            .process_one_with_buffers(
                &mut image,
                32,
                &io_desc(UBLK_IO_OP_READ, 0, 0, 8, DEMO_BUFFER_ADDR + 8192),
                Some(&mut read_buffer),
                None,
            )
            .expect("read");
        assert_eq!(
            read_result.completion_class,
            BlockVolumeCompletionClass::Completed
        );
        assert_eq!(read_result.byte_count, 4096);
        assert_eq!(read_buffer, write_payload);

        assert_eq!(worker.write_ops, 1);
        assert_eq!(worker.flush_ops, 1);
        assert_eq!(worker.read_ops, 1);
        assert_eq!(worker.completed_ops, 3);
    }

    #[test]
    fn worker_write_rejects_zero_length() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        let result = worker.process_one(
            &mut image,
            0,
            &io_desc(UBLK_IO_OP_WRITE, 0, 0, 0, DEMO_BUFFER_ADDR),
        );
        assert_eq!(
            result.unwrap_err(),
            DataQueueWorkerError::ZeroLengthDataOperation
        );
    }

    #[test]
    fn worker_write_rejects_unsupported_raw_flags() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);

        // UBLK_IO_F_NEED_REG_BUF (1 << 17) is now accepted; write proceeds.
        let result = worker.process_one(
            &mut image,
            0,
            &io_desc(UBLK_IO_OP_WRITE, 1 << 17, 0, 8, DEMO_BUFFER_ADDR),
        );
        assert_eq!(
            result.unwrap_err(),
            DataQueueWorkerError::MissingBufferAddress
        );
    }

    #[test]
    fn worker_rejects_short_data_buffers() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker = DataQueueWorker::new(0, geometry);
        let short_write = vec![0xA5; 2048];
        let write = worker.process_one_with_buffers(
            &mut image,
            0,
            &io_desc(UBLK_IO_OP_WRITE, 0, 0, 8, DEMO_BUFFER_ADDR),
            None,
            Some(&short_write),
        );
        assert_eq!(
            write.unwrap_err(),
            DataQueueWorkerError::PayloadBufferTooShort
        );

        let mut short_read = vec![0; 2048];
        let read = worker.process_one_with_buffers(
            &mut image,
            1,
            &io_desc(UBLK_IO_OP_READ, 0, 0, 8, DEMO_BUFFER_ADDR),
            Some(&mut short_read),
            None,
        );
        assert_eq!(
            read.unwrap_err(),
            DataQueueWorkerError::PayloadBufferTooShort
        );
    }

    #[test]
    fn worker_error_linux_errno_mapping() {
        assert_eq!(
            DataQueueWorkerError::UnsupportedOperation.linux_errno(),
            -95
        );
        assert_eq!(
            DataQueueWorkerError::UnsupportedWriteSame.linux_errno(),
            -95
        );
        assert_eq!(
            DataQueueWorkerError::UnsupportedZonedOperation.linux_errno(),
            -95
        );
        assert_eq!(DataQueueWorkerError::UnsupportedFlags.linux_errno(), -22);
        assert_eq!(DataQueueWorkerError::OutOfRange.linux_errno(), -22);
        assert_eq!(
            DataQueueWorkerError::ZeroLengthDataOperation.linux_errno(),
            -22
        );
        assert_eq!(
            DataQueueWorkerError::MissingBufferAddress.linux_errno(),
            -22
        );
        assert_eq!(DataQueueWorkerError::RangeOnFlush.linux_errno(), -22);
        assert_eq!(
            DataQueueWorkerError::UnexpectedBufferAddress.linux_errno(),
            -22
        );
        assert_eq!(
            DataQueueWorkerError::PayloadBufferTooShort.linux_errno(),
            -22
        );
        assert_eq!(
            DataQueueWorkerError::BackingStoreError(-5).linux_errno(),
            -5
        );
    }

    #[test]
    fn worker_propagates_raw_enospc_from_backend_io_error() {
        let geometry = test_geometry();
        let mut backend = RawErrBackend::new(libc::ENOSPC);
        let mut worker = DataQueueWorker::new(0, geometry);
        let payload = vec![0x5a; 4096];

        let err = worker
            .process_one_with_buffers(
                &mut backend,
                7,
                &io_desc(UBLK_IO_OP_WRITE, 0, 0, 8, DEMO_BUFFER_ADDR),
                None,
                Some(&payload),
            )
            .unwrap_err();

        assert_eq!(err, DataQueueWorkerError::BackingStoreError(-libc::ENOSPC));
        assert_eq!(err.linux_errno(), -libc::ENOSPC);
    }

    #[test]
    fn worker_multiple_queue_ids_are_independent() {
        let geometry = test_geometry();
        let (_dir, mut image) = test_image();
        let mut worker_q0 = DataQueueWorker::new(0, geometry);
        let mut worker_q1 = DataQueueWorker::new(1, geometry);

        let r0 = worker_q0
            .process_one(
                &mut image,
                0,
                &io_desc(UBLK_IO_OP_READ, 0, 0, 8, DEMO_BUFFER_ADDR),
            )
            .expect("q0 read");
        let q1_write_payload = vec![0x33; 4096];
        let r1 = worker_q1
            .process_one_with_buffers(
                &mut image,
                0,
                &io_desc(UBLK_IO_OP_WRITE, 0, 0, 8, DEMO_BUFFER_ADDR + 4096),
                None,
                Some(&q1_write_payload),
            )
            .expect("q1 write");

        assert_eq!(r0.io_cmd.q_id, 0);
        assert_eq!(r1.io_cmd.q_id, 1);
        assert_eq!(worker_q0.read_ops, 1);
        assert_eq!(worker_q0.write_ops, 0);
        assert_eq!(worker_q1.read_ops, 0);
        assert_eq!(worker_q1.write_ops, 1);
    }

    #[test]
    fn worker_smoke_payload_is_deterministic_and_non_zero() {
        let payload = data_queue_worker_smoke_payload(4096);
        assert_eq!(payload, data_queue_worker_smoke_payload(4096));
        assert_eq!(payload.len(), 4096);
        assert!(payload.iter().any(|byte| *byte != 0));
        assert!(payload.windows(2).any(|pair| pair[0] != pair[1]));
    }
}
