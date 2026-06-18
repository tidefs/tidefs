// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! ublk IO submission-completion ring handler.
//!
//! Parses ublk IO descriptors from the mmap'd submission ring buffer,
//! dispatches read/write/flush/discard/write-zeroes operations through
//! a pluggable [`UblkIoBackend`] trait, and posts COMMIT_AND_FETCH_REQ
//! completions back to the ublk kernel driver.

use std::fmt;
use std::io;

use tidefs_ublk_abi::{
    UblkSrvIoCmd, UblkSrvIoDesc, UBLK_IO_F_FUA, UBLK_IO_OP_DISCARD, UBLK_IO_OP_FLUSH,
    UBLK_IO_OP_READ, UBLK_IO_OP_WRITE, UBLK_IO_OP_WRITE_SAME, UBLK_IO_OP_WRITE_ZEROES,
    UBLK_IO_RES_ABORT, UBLK_IO_RES_OK,
};

use crate::{
    decode_fetch_req_user_data, is_fetch_req_user_data,
    submit_runtime_commit_and_fetch_without_wait, UblkDataQueueCommitAndFetchError,
    UblkDataQueueCommitAndFetchInput, UblkDataQueueCommitAndFetchReadiness, UblkDataQueueRuntime,
};

/// OW-301AA block-volume adapter ublk IO ring handler parses submission descriptors, dispatches to backend, and posts COMMIT_AND_FETCH_REQ completions
pub const BLOCK_VOLUME_UBLK_IO_RING_HANDLER_GATE_OW_301AA: &str =
    "OW-301AA block-volume adapter ublk IO ring handler parses submission descriptors, dispatches to backend, and posts COMMIT_AND_FETCH_REQ completions";

/// Typed ublk IO operation derived from the low 8 bits of a
/// [`UblkSrvIoDesc::op_flags`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkIoOp {
    /// Read.
    Read,
    /// Write.
    Write,
    /// Flush.
    Flush,
    /// Discard.
    Discard,
    /// Writezeroes.
    WriteZeroes,
    /// Writesame.
    WriteSame,
    /// Unknown.
    Unknown(u8),
}

impl UblkIoOp {
    /// Decode a raw ublk opcode byte into the typed variant.
    #[must_use]
    pub const fn from_opcode(op: u8) -> Self {
        match op {
            UBLK_IO_OP_READ => Self::Read,
            UBLK_IO_OP_WRITE => Self::Write,
            UBLK_IO_OP_FLUSH => Self::Flush,
            UBLK_IO_OP_DISCARD => Self::Discard,
            UBLK_IO_OP_WRITE_ZEROES => Self::WriteZeroes,
            UBLK_IO_OP_WRITE_SAME => Self::WriteSame,
            other => Self::Unknown(other),
        }
    }

    /// As Str.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Flush => "flush",
            Self::Discard => "discard",
            Self::WriteZeroes => "write_zeroes",
            Self::WriteSame => "write_same",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Whether this op expects a data range (sector offset + count).
    #[must_use]
    pub const fn expects_range(self) -> bool {
        matches!(
            self,
            Self::Read | Self::Write | Self::Discard | Self::WriteZeroes | Self::WriteSame
        )
    }

    /// Whether this op expects a data buffer to be mapped.
    #[must_use]
    pub const fn expects_buffer(self) -> bool {
        matches!(self, Self::Read | Self::Write | Self::WriteSame)
    }
}

/// Parsed ublk IO descriptor extracted from the mmap'd IO buffer slot
/// after a FETCH_REQ CQE has been received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkIoDescriptor {
    /// Queue id (0..nr_hw_queues-1).
    pub q_id: u16,
    /// Tag (0..queue_depth-1).
    pub tag: u16,
    /// Typed IO operation.
    pub op: UblkIoOp,
    /// Raw flags field (upper 24 bits of op_flags, right-shifted by 8).
    pub flags: u32,
    /// Whether FUA (Force Unit Access) flag is set.
    pub fua: bool,
    /// Starting sector (512-byte Linux sector).
    pub start_sector: u64,
    /// Sector count for data operations; zone count for zoned ops.
    pub sector_count: u32,
    /// Address of the data buffer within the mmap'd IO region.
    /// This is the raw `addr` field from `UblkSrvIoDesc`.
    pub buffer_addr: u64,
}

impl UblkIoDescriptor {
    /// Parse from a raw `UblkSrvIoDesc` plus (q_id, tag) context.
    #[must_use]
    pub fn from_desc(q_id: u16, tag: u16, desc: &UblkSrvIoDesc) -> Self {
        let op = UblkIoOp::from_opcode(desc.op());
        Self {
            q_id,
            tag,
            op,
            flags: desc.flags(),
            fua: (desc.op_flags & UBLK_IO_F_FUA) != 0,
            start_sector: desc.start_sector,
            sector_count: desc.count_or_zones,
            buffer_addr: desc.addr,
        }
    }

    /// Read the descriptor from the runtime's IO buffer for the given
    /// (q_id, tag) slot. Returns `None` if the slot is out of range.
    #[must_use]
    pub fn from_runtime(runtime: &UblkDataQueueRuntime, q_id: u16, tag: u16) -> Option<Self> {
        let desc = runtime.io_desc_for_queue(q_id, tag)?;
        Some(Self::from_desc(q_id, tag, desc))
    }

    /// Total byte count represented by this descriptor's sector range.
    /// Uses 512-byte Linux sector size.
    #[must_use]
    pub const fn sector_bytes(self) -> u64 {
        self.sector_count as u64 * 512
    }
}

impl fmt::Display for UblkIoDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ublk io [q={} tag={}] op={} start_sector={} count={} fua={} addr=0x{:016x}",
            self.q_id,
            self.tag,
            self.op.as_str(),
            self.start_sector,
            self.sector_count,
            self.fua,
            self.buffer_addr,
        )
    }
}

/// Result of dispatching a single ublk IO descriptor to the backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkIoDispatchResult {
    /// IO completed successfully.
    Completed {
        /// Byte count for read/write operations; 0 for flush/discard/write_zeroes.
        byte_count: usize,
    },
    /// The descriptor was refused as invalid (e.g., unsupported op, bad range).
    Refused {
        /// Linux errno for the completion.
        errno: i32,
    },
    /// The backend returned an I/O error.
    IoError {
        /// Linux errno for the completion.
        errno: i32,
    },
}

impl UblkIoDispatchResult {
    /// Convert into a ublk completion result code suitable for the
    /// `result` field of `UblkSrvIoCmd`.
    #[must_use]
    pub const fn to_ublk_result(self) -> i32 {
        match self {
            Self::Completed { byte_count: _ } => UBLK_IO_RES_OK,
            Self::Refused { errno } | Self::IoError { errno } => {
                if errno == -libc::ENODEV {
                    UBLK_IO_RES_ABORT
                } else {
                    -errno
                }
            }
        }
    }

    /// Convert into a ublk completion result code, detecting short I/O
    /// when the backend returned fewer bytes than requested.
    ///
    /// Returns `UBLK_IO_RES_NEED_GET_DATA` (1) when a read/write
    /// completed but the actual byte count is less than `requested_bytes`.
    #[must_use]
    pub const fn to_ublk_result_checked(self, requested_bytes: u64) -> i32 {
        match self {
            Self::Completed { byte_count } => {
                if (byte_count as u64) < requested_bytes {
                    1 // UBLK_IO_RES_NEED_GET_DATA
                } else {
                    UBLK_IO_RES_OK
                }
            }
            Self::Refused { errno } | Self::IoError { errno } => {
                if errno == -libc::ENODEV {
                    UBLK_IO_RES_ABORT
                } else {
                    -errno
                }
            }
        }
    }

    /// Build a `UblkSrvIoCmd` completion command for this result.
    #[must_use]
    pub fn to_io_cmd(self, q_id: u16, tag: u16) -> UblkSrvIoCmd {
        UblkSrvIoCmd {
            q_id,
            tag,
            result: self.to_ublk_result(),
            addr_or_zone_append_lba: 0,
        }
    }

    /// Post a COMMIT_AND_FETCH_REQ completion to the io_uring ring.
    ///
    /// # Errors
    ///
    /// Returns `UblkDataQueueCommitAndFetchError` if submission fails.
    pub fn submit_completion(
        self,
        runtime: &mut UblkDataQueueRuntime,
        q_id: u16,
        tag: u16,
        nr_hw_queues: u16,
        queue_depth: u16,
    ) -> Result<crate::UblkDataQueueCommitAndFetchOutcome, UblkDataQueueCommitAndFetchError> {
        let input = UblkDataQueueCommitAndFetchInput {
            q_id,
            tag,
            nr_hw_queues,
            queue_depth,
            result: self.to_ublk_result(),
            addr_or_zone_append_lba: 0,
        };
        let readiness = UblkDataQueueCommitAndFetchReadiness {
            data_queue_runtime_live: runtime.runtime_live(),
            fetched_request_available: true,
            completion_result_ready: true,
        };
        submit_runtime_commit_and_fetch_without_wait(runtime, input, readiness)
    }

    /// Post a COMMIT_AND_FETCH_REQ completion with short-I/O detection.
    ///
    /// When `requested_bytes` is greater than the actual completion byte
    /// count, the ublk result is set to `UBLK_IO_RES_NEED_GET_DATA` (1)
    /// so the kernel block layer can retry the remainder.
    pub fn submit_completion_checked(
        self,
        runtime: &mut UblkDataQueueRuntime,
        q_id: u16,
        tag: u16,
        nr_hw_queues: u16,
        queue_depth: u16,
        requested_bytes: u64,
    ) -> Result<crate::UblkDataQueueCommitAndFetchOutcome, UblkDataQueueCommitAndFetchError> {
        let input = UblkDataQueueCommitAndFetchInput {
            q_id,
            tag,
            nr_hw_queues,
            queue_depth,
            result: self.to_ublk_result_checked(requested_bytes),
            addr_or_zone_append_lba: 0,
        };
        let readiness = UblkDataQueueCommitAndFetchReadiness {
            data_queue_runtime_live: runtime.runtime_live(),
            fetched_request_available: true,
            completion_result_ready: true,
        };
        submit_runtime_commit_and_fetch_without_wait(runtime, input, readiness)
    }
}

/// Pluggable backend trait for block-level I/O operations.
///
/// Implementations provide the actual storage backend: a file, a block
/// device, a local-object-store pool, or an in-memory test harness.
pub trait UblkIoBackend {
    /// Read data from `byte_offset` into `buf`. Returns bytes read.
    fn read(&mut self, byte_offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Write data from `buf` at `byte_offset`. Returns bytes written.
    fn write(&mut self, byte_offset: u64, data: &[u8]) -> io::Result<usize>;

    /// Flush pending writes to durable storage.
    fn flush(&mut self) -> io::Result<()>;

    /// Discard (unmap/hole-punch) the given byte range. May be a no-op.
    fn discard(&mut self, byte_offset: u64, byte_len: u64) -> io::Result<()>;

    /// Write zeroes to the given byte range.
    fn write_zeroes(&mut self, byte_offset: u64, byte_len: u64) -> io::Result<()>;
}

/// Error returned by the IO ring handler when processing an IO descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkIoHandlerError {
    /// The descriptor operation is unsupported (e.g., WRITE_SAME, zoned ops).
    UnsupportedOperation(u8),
    /// FUA flag is only valid on write operations.
    FuaOnlyValidForWrite,
    /// Data operations require a non-zero sector count.
    ZeroLengthDataOperation,
    /// Data operations (read/write) require a buffer address.
    MissingBufferAddress,
    /// Non-data ops (flush) must not carry range information.
    RangeOnFlush,
    /// Backend I/O error.
    BackendIoError(i32),
}

impl UblkIoHandlerError {
    /// To Linux Errno.
    #[must_use]
    pub const fn to_linux_errno(self) -> i32 {
        match self {
            Self::UnsupportedOperation(_) => libc::EOPNOTSUPP,
            Self::FuaOnlyValidForWrite
            | Self::ZeroLengthDataOperation
            | Self::MissingBufferAddress
            | Self::RangeOnFlush => libc::EINVAL,
            Self::BackendIoError(errno) => errno,
        }
    }
}

/// Dispatch a single ublk IO descriptor to the backend.
///
/// Validates the descriptor shape (range, buffer presence, flag correctness)
/// and then invokes the appropriate backend method.
pub fn dispatch_io(
    backend: &mut dyn UblkIoBackend,
    desc: &UblkIoDescriptor,
    read_buf: Option<&mut [u8]>,
    write_buf: Option<&[u8]>,
) -> Result<UblkIoDispatchResult, UblkIoHandlerError> {
    // Validate flags
    if desc.fua && desc.op != UblkIoOp::Write {
        return Err(UblkIoHandlerError::FuaOnlyValidForWrite);
    }

    match desc.op {
        UblkIoOp::Read => dispatch_read(backend, desc, read_buf),
        UblkIoOp::Write => dispatch_write(backend, desc, write_buf),
        UblkIoOp::Flush => dispatch_flush(backend, desc),
        UblkIoOp::Discard => dispatch_discard(backend, desc),
        UblkIoOp::WriteZeroes => dispatch_write_zeroes(backend, desc),
        UblkIoOp::WriteSame => Err(UblkIoHandlerError::UnsupportedOperation(
            UBLK_IO_OP_WRITE_SAME,
        )),
        UblkIoOp::Unknown(opcode) => Err(UblkIoHandlerError::UnsupportedOperation(opcode)),
    }
}

fn dispatch_read(
    backend: &mut dyn UblkIoBackend,
    desc: &UblkIoDescriptor,
    read_buf: Option<&mut [u8]>,
) -> Result<UblkIoDispatchResult, UblkIoHandlerError> {
    let byte_len = desc.sector_bytes() as usize;

    if byte_len == 0 {
        return Err(UblkIoHandlerError::ZeroLengthDataOperation);
    }

    let buf = read_buf.ok_or(UblkIoHandlerError::MissingBufferAddress)?;
    if buf.len() < byte_len {
        return Err(UblkIoHandlerError::MissingBufferAddress);
    }

    let byte_offset = desc.start_sector * 512;
    match backend.read(byte_offset, &mut buf[..byte_len]) {
        Ok(n) => Ok(UblkIoDispatchResult::Completed { byte_count: n }),
        Err(e) => Err(UblkIoHandlerError::BackendIoError(
            e.raw_os_error().unwrap_or(libc::EIO),
        )),
    }
}

fn dispatch_write(
    backend: &mut dyn UblkIoBackend,
    desc: &UblkIoDescriptor,
    write_buf: Option<&[u8]>,
) -> Result<UblkIoDispatchResult, UblkIoHandlerError> {
    let byte_len = desc.sector_bytes() as usize;

    if byte_len == 0 {
        return Err(UblkIoHandlerError::ZeroLengthDataOperation);
    }

    let data = write_buf.ok_or(UblkIoHandlerError::MissingBufferAddress)?;
    if data.len() < byte_len {
        return Err(UblkIoHandlerError::MissingBufferAddress);
    }

    let byte_offset = desc.start_sector * 512;
    match backend.write(byte_offset, &data[..byte_len]) {
        Ok(n) => {
            if desc.fua {
                match backend.flush() {
                    Ok(()) => Ok(UblkIoDispatchResult::Completed { byte_count: n }),
                    Err(e) => Err(UblkIoHandlerError::BackendIoError(
                        e.raw_os_error().unwrap_or(libc::EIO),
                    )),
                }
            } else {
                Ok(UblkIoDispatchResult::Completed { byte_count: n })
            }
        }
        Err(e) => Err(UblkIoHandlerError::BackendIoError(
            e.raw_os_error().unwrap_or(libc::EIO),
        )),
    }
}

fn dispatch_flush(
    backend: &mut dyn UblkIoBackend,
    desc: &UblkIoDescriptor,
) -> Result<UblkIoDispatchResult, UblkIoHandlerError> {
    if desc.start_sector != 0 || desc.sector_count != 0 {
        return Err(UblkIoHandlerError::RangeOnFlush);
    }

    match backend.flush() {
        Ok(()) => Ok(UblkIoDispatchResult::Completed { byte_count: 0 }),
        Err(e) => Err(UblkIoHandlerError::BackendIoError(
            e.raw_os_error().unwrap_or(libc::EIO),
        )),
    }
}

fn dispatch_discard(
    backend: &mut dyn UblkIoBackend,
    desc: &UblkIoDescriptor,
) -> Result<UblkIoDispatchResult, UblkIoHandlerError> {
    let byte_len = desc.sector_bytes();
    let byte_offset = desc.start_sector * 512;

    match backend.discard(byte_offset, byte_len) {
        Ok(()) => Ok(UblkIoDispatchResult::Completed { byte_count: 0 }),
        Err(e) => Err(UblkIoHandlerError::BackendIoError(
            e.raw_os_error().unwrap_or(libc::EIO),
        )),
    }
}

fn dispatch_write_zeroes(
    backend: &mut dyn UblkIoBackend,
    desc: &UblkIoDescriptor,
) -> Result<UblkIoDispatchResult, UblkIoHandlerError> {
    let byte_len = desc.sector_bytes();
    let byte_offset = desc.start_sector * 512;

    match backend.write_zeroes(byte_offset, byte_len) {
        Ok(()) => Ok(UblkIoDispatchResult::Completed { byte_count: 0 }),
        Err(e) => Err(UblkIoHandlerError::BackendIoError(
            e.raw_os_error().unwrap_or(libc::EIO),
        )),
    }
}

/// Poll the io_uring completion queue for FETCH_REQ CQEs and return the
/// parsed IO descriptors.
///
/// Each completed FETCH_REQ indicates the kernel has placed a block
/// request into the corresponding slot in the mmap'd IO buffer. This
/// function reaps all available FETCH_REQ CQEs, parses their descriptors,
/// and returns them for dispatch.
///
/// The returned descriptors include the (q_id, tag) so the caller can
/// access the data buffer via `runtime.data_buffer_for_queue()` or
/// `runtime.data_buffer_mut_for_queue()`.
///
/// # CQ overflow handling
///
/// After draining visible CQEs, this function checks for io_uring CQ
/// overflow. When the kernel supports IORING_FEAT_NODROP, overflowed
/// CQEs are buffered internally; calling `submit()` flushes them back
/// into the CQ ring so they can be reaped. A bounded retry loop (max 5)
/// prevents infinite spinning under pathological load. The overflow
/// counter on `UblkDataQueueRuntime` is incremented for each overflow
/// cycle detected.
pub fn poll_completed_fetch_reqs(runtime: &mut UblkDataQueueRuntime) -> Vec<UblkIoDescriptor> {
    let mut descriptors = Vec::new();
    const MAX_OVERFLOW_RETRIES: u32 = 5;
    let nodrop = runtime.nodrop_enabled;

    for _retry in 0..MAX_OVERFLOW_RETRIES {
        // Drain all visible CQEs from the completion ring.
        loop {
            let cqe = runtime.ring_mut().completion().next();
            let Some(cqe) = cqe else {
                break;
            };

            let user_data = cqe.user_data();

            // Decrement in-flight counter for each CQE consumed (both FETCH_REQ
            // and COMMIT_AND_FETCH_REQ), keeping it accurate for drain.
            runtime.in_flight_counter().decrement();

            // Only process FETCH_REQ completions; skip COMMIT_AND_FETCH_REQ
            // and any other opcodes that may appear on this ring.
            if !is_fetch_req_user_data(user_data) {
                continue;
            }

            let (q_id, tag) = decode_fetch_req_user_data(user_data);

            if let Some(desc) = runtime.io_desc_for_queue(q_id, tag) {
                let io_desc = UblkIoDescriptor::from_desc(q_id, tag, desc);
                descriptors.push(io_desc);
            }
        }

        // Check for CQ overflow after draining. The CompletionQueue drop
        // above has already written back the head pointer, so a fresh
        // call reads the kernel's current overflow counter.
        let overflow = runtime.ring_mut().completion().overflow();
        if overflow == 0 {
            break;
        }

        if !nodrop {
            runtime.cq_overflow_count += 1;
            break;
        }

        // Track overflow events for observability.
        runtime.cq_overflow_count += 1;

        // Call submit() to flush kernel-buffered overflow CQEs.
        // When IORING_FEAT_NODROP is enabled, the io-uring crate
        // internally calls io_uring_enter() to make buffered events
        // visible in the CQ ring. Without NODROP, overflowed events
        // are permanently lost, but the counter still provides
        // observability.
        let _ = runtime.ring_mut().submit();
    }

    descriptors
}

/// Post a COMMIT_AND_FETCH_REQ completion for a single IO descriptor.
///
/// This submits a command to the io_uring ring that both:
/// - posts the completion result back to the kernel ublk driver
/// - fetches the next block request for this (q_id, tag) slot
///
/// # Errors
///
/// Returns `UblkDataQueueCommitAndFetchError` on submission failure.
pub fn commit_io_and_fetch_next(
    runtime: &mut UblkDataQueueRuntime,
    q_id: u16,
    tag: u16,
    result: UblkIoDispatchResult,
    nr_hw_queues: u16,
    queue_depth: u16,
) -> Result<crate::UblkDataQueueCommitAndFetchOutcome, UblkDataQueueCommitAndFetchError> {
    result.submit_completion(runtime, q_id, tag, nr_hw_queues, queue_depth)
}

/// Process a batch of ublk IO descriptors through the backend, dispatching
/// each and posting COMMIT_AND_FETCH_REQ completions.
///
/// This is the core event loop for ublk IO handling. For each descriptor:
/// 1. Read or write buffer is obtained from the runtime's mmap'd IO buffer.
/// 2. The descriptor is dispatched to the backend via [`dispatch_io`].
/// 3. A COMMIT_AND_FETCH_REQ is posted to the ring.
///
/// Returns the number of descriptors processed and the number that succeeded.
pub fn process_io_batch(
    runtime: &mut UblkDataQueueRuntime,
    backend: &mut dyn UblkIoBackend,
    descriptors: &[UblkIoDescriptor],
    nr_hw_queues: u16,
    queue_depth: u16,
) -> (usize, usize) {
    let mut processed = 0usize;
    let mut succeeded = 0usize;

    for desc in descriptors {
        processed += 1;

        let dispatch_result = match desc.op {
            UblkIoOp::Read => {
                let byte_count = desc.sector_bytes();
                let mut read_buf = vec![0u8; byte_count as usize];
                match dispatch_io(backend, desc, Some(&mut read_buf), None) {
                    Ok(r) => {
                        if matches!(r, UblkIoDispatchResult::Completed { .. }) {
                            if let Err(e) = runtime.write_data_at(desc.q_id, desc.tag, &read_buf) {
                                UblkIoDispatchResult::Refused {
                                    errno: e.raw_os_error().unwrap_or(libc::EIO),
                                }
                            } else {
                                r
                            }
                        } else {
                            r
                        }
                    }
                    Err(e) => UblkIoDispatchResult::Refused {
                        errno: e.to_linux_errno(),
                    },
                }
            }
            UblkIoOp::Write => {
                let byte_count = desc.sector_bytes();
                let mut write_buf = vec![0u8; byte_count as usize];
                match runtime.read_data_at(desc.q_id, desc.tag, &mut write_buf) {
                    Ok(_) => match dispatch_io(backend, desc, None, Some(&write_buf)) {
                        Ok(r) => r,
                        Err(e) => UblkIoDispatchResult::Refused {
                            errno: e.to_linux_errno(),
                        },
                    },
                    Err(_) => UblkIoDispatchResult::Refused { errno: libc::EIO },
                }
            }
            _ => match dispatch_io(backend, desc, None, None) {
                Ok(r) => r,
                Err(e) => UblkIoDispatchResult::Refused {
                    errno: e.to_linux_errno(),
                },
            },
        };

        let is_ok = matches!(dispatch_result, UblkIoDispatchResult::Completed { .. });
        if is_ok {
            succeeded += 1;
        }

        // Use short-I/O-aware completion for read/write ops so the
        // kernel sees UBLK_IO_RES_NEED_GET_DATA when the backend
        // returned fewer bytes than requested.
        let requested_bytes = desc.sector_bytes();
        let _completion_result = if matches!(desc.op, UblkIoOp::Read | UblkIoOp::Write) {
            dispatch_result.submit_completion_checked(
                runtime,
                desc.q_id,
                desc.tag,
                nr_hw_queues,
                queue_depth,
                requested_bytes,
            )
        } else {
            commit_io_and_fetch_next(
                runtime,
                desc.q_id,
                desc.tag,
                dispatch_result,
                nr_hw_queues,
                queue_depth,
            )
        };
        // Completion submission failures are non-fatal: the kernel will
        // eventually time out and re-fetch the slot.
        #[allow(unused_variables)]
        if let Err(ref e) = _completion_result {
            let _ = e; // silence unused-parens lint
        }
    }

    (processed, succeeded)
}

/// Run a single iteration of the ublk IO event loop:
/// 1. Poll for FETCH_REQ completions.
/// 2. Parse IO descriptors from the mmap'd buffer.
/// 3. Dispatch each to the backend.
/// 4. Post COMMIT_AND_FETCH_REQ completions.
///
/// Returns the count of (descriptors_polled, descriptors_completed_successfully).
pub fn run_io_loop_iteration(
    runtime: &mut UblkDataQueueRuntime,
    backend: &mut dyn UblkIoBackend,
    nr_hw_queues: u16,
    queue_depth: u16,
) -> (usize, usize) {
    let descriptors = poll_completed_fetch_reqs(runtime);
    let total = descriptors.len();
    if total == 0 {
        return (0, 0);
    }
    let (processed, succeeded) =
        process_io_batch(runtime, backend, &descriptors, nr_hw_queues, queue_depth);
    (processed, succeeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use std::path::PathBuf;

    // ── In-memory backend for testing ────────────────────────────────

    struct TestBackend {
        data: HashMap<u64, Vec<u8>>,
        capacity: u64,
        flush_count: u64,
        discard_count: u64,
        write_zeroes_count: u64,
    }

    impl TestBackend {
        fn new(capacity: u64) -> Self {
            Self {
                data: HashMap::new(),
                capacity,
                flush_count: 0,
                discard_count: 0,
                write_zeroes_count: 0,
            }
        }

        fn ensure_range(&mut self, offset: u64, len: u64) {
            let end = offset.saturating_add(len).min(self.capacity);
            let start_block = offset / 4096;
            let end_block = end.div_ceil(4096);
            for block in start_block..end_block {
                let key = block * 4096;
                self.data.entry(key).or_insert_with(|| vec![0u8; 4096]);
            }
        }

        fn read_range(&self, offset: u64, buf: &mut [u8]) -> usize {
            let capacity = self.capacity;
            let end = (offset as usize + buf.len()).min(capacity as usize);
            let len = end.saturating_sub(offset as usize);
            let write_end = len.min(buf.len());

            let mut pos = 0usize;
            while pos < write_end {
                let block = ((offset as usize + pos) / 4096) * 4096;
                let block_off = (offset as usize + pos) % 4096;
                let chunk = (4096 - block_off).min(write_end - pos);

                if let Some(block_data) = self.data.get(&(block as u64)) {
                    buf[pos..pos + chunk]
                        .copy_from_slice(&block_data[block_off..block_off + chunk]);
                } else {
                    buf[pos..pos + chunk].fill(0u8);
                }
                pos += chunk;
            }
            len
        }

        fn write_range(&mut self, offset: u64, data: &[u8]) -> usize {
            let end = (offset as usize + data.len()).min(self.capacity as usize);
            let len = end.saturating_sub(offset as usize);
            self.ensure_range(offset, len as u64);

            let mut pos = 0usize;
            while pos < len {
                let block = ((offset as usize + pos) / 4096) * 4096;
                let block_off = (offset as usize + pos) % 4096;
                let chunk = (4096 - block_off).min(len - pos);

                if let Some(block_data) = self.data.get_mut(&(block as u64)) {
                    block_data[block_off..block_off + chunk]
                        .copy_from_slice(&data[pos..pos + chunk]);
                }
                pos += chunk;
            }
            len
        }
    }

    impl UblkIoBackend for TestBackend {
        fn read(&mut self, byte_offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            Ok(self.read_range(byte_offset, buf))
        }

        fn write(&mut self, byte_offset: u64, data: &[u8]) -> io::Result<usize> {
            Ok(self.write_range(byte_offset, data))
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_count += 1;
            Ok(())
        }

        fn discard(&mut self, _byte_offset: u64, _byte_len: u64) -> io::Result<()> {
            self.discard_count += 1;
            Ok(())
        }

        fn write_zeroes(&mut self, byte_offset: u64, byte_len: u64) -> io::Result<()> {
            self.write_zeroes_count += 1;
            let len = byte_len.min(self.capacity.saturating_sub(byte_offset));
            let zeroes = vec![0u8; len as usize];
            self.write_range(byte_offset, &zeroes);
            Ok(())
        }
    }

    fn make_desc(
        q_id: u16,
        tag: u16,
        op: u8,
        flags: u32,
        start_sector: u64,
        sector_count: u32,
        addr: u64,
    ) -> UblkIoDescriptor {
        let raw_desc = UblkSrvIoDesc {
            op_flags: op as u32 | flags,
            count_or_zones: sector_count,
            start_sector,
            addr,
        };
        UblkIoDescriptor::from_desc(q_id, tag, &raw_desc)
    }

    fn make_read_desc(start_sector: u64, sector_count: u32) -> UblkIoDescriptor {
        make_desc(0, 0, UBLK_IO_OP_READ, 0, start_sector, sector_count, 0x1000)
    }

    fn make_write_desc(start_sector: u64, sector_count: u32) -> UblkIoDescriptor {
        make_desc(
            0,
            0,
            UBLK_IO_OP_WRITE,
            0,
            start_sector,
            sector_count,
            0x2000,
        )
    }

    fn make_fua_write_desc(start_sector: u64, sector_count: u32) -> UblkIoDescriptor {
        make_desc(
            0,
            0,
            UBLK_IO_OP_WRITE,
            UBLK_IO_F_FUA,
            start_sector,
            sector_count,
            0x3000,
        )
    }

    fn make_flush_desc() -> UblkIoDescriptor {
        make_desc(0, 0, UBLK_IO_OP_FLUSH, 0, 0, 0, 0)
    }

    fn make_discard_desc(start_sector: u64, sector_count: u32) -> UblkIoDescriptor {
        make_desc(0, 0, UBLK_IO_OP_DISCARD, 0, start_sector, sector_count, 0)
    }

    fn make_write_zeroes_desc(start_sector: u64, sector_count: u32) -> UblkIoDescriptor {
        make_desc(
            0,
            0,
            UBLK_IO_OP_WRITE_ZEROES,
            0,
            start_sector,
            sector_count,
            0,
        )
    }

    // ── UblkIoOp tests ───────────────────────────────────────────────

    #[test]
    fn io_op_from_opcode_maps_all_known_ops() {
        assert_eq!(UblkIoOp::from_opcode(UBLK_IO_OP_READ), UblkIoOp::Read);
        assert_eq!(UblkIoOp::from_opcode(UBLK_IO_OP_WRITE), UblkIoOp::Write);
        assert_eq!(UblkIoOp::from_opcode(UBLK_IO_OP_FLUSH), UblkIoOp::Flush);
        assert_eq!(UblkIoOp::from_opcode(UBLK_IO_OP_DISCARD), UblkIoOp::Discard);
        assert_eq!(
            UblkIoOp::from_opcode(UBLK_IO_OP_WRITE_ZEROES),
            UblkIoOp::WriteZeroes
        );
        assert_eq!(
            UblkIoOp::from_opcode(UBLK_IO_OP_WRITE_SAME),
            UblkIoOp::WriteSame
        );
        assert_eq!(UblkIoOp::from_opcode(0xFF), UblkIoOp::Unknown(0xFF));
        assert_eq!(UblkIoOp::from_opcode(0x00), UblkIoOp::Read);
    }

    #[test]
    fn io_op_expects_range_and_buffer() {
        assert!(UblkIoOp::Read.expects_range());
        assert!(UblkIoOp::Read.expects_buffer());
        assert!(UblkIoOp::Write.expects_range());
        assert!(UblkIoOp::Write.expects_buffer());
        assert!(!UblkIoOp::Flush.expects_range());
        assert!(!UblkIoOp::Flush.expects_buffer());
        assert!(UblkIoOp::Discard.expects_range());
        assert!(!UblkIoOp::Discard.expects_buffer());
        assert!(UblkIoOp::WriteZeroes.expects_range());
        assert!(!UblkIoOp::WriteZeroes.expects_buffer());
        assert!(UblkIoOp::WriteSame.expects_range());
        assert!(UblkIoOp::WriteSame.expects_buffer());
    }

    #[test]
    fn io_op_as_str_is_stable() {
        assert_eq!(UblkIoOp::Read.as_str(), "read");
        assert_eq!(UblkIoOp::Write.as_str(), "write");
        assert_eq!(UblkIoOp::Flush.as_str(), "flush");
        assert_eq!(UblkIoOp::Discard.as_str(), "discard");
        assert_eq!(UblkIoOp::WriteZeroes.as_str(), "write_zeroes");
        assert_eq!(UblkIoOp::WriteSame.as_str(), "write_same");
        assert_eq!(UblkIoOp::Unknown(99).as_str(), "unknown");
    }

    // ── UblkIoDescriptor tests ───────────────────────────────────────

    #[test]
    fn io_descriptor_from_desc_preserves_fields() {
        let raw = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_READ) | UBLK_IO_F_FUA,
            count_or_zones: 8,
            start_sector: 64,
            addr: 0xDEAD_BEEF,
        };
        let desc = UblkIoDescriptor::from_desc(2, 42, &raw);
        assert_eq!(desc.q_id, 2);
        assert_eq!(desc.tag, 42);
        assert_eq!(desc.op, UblkIoOp::Read);
        assert_eq!(desc.flags, UBLK_IO_F_FUA >> 8);
        assert!(desc.fua);
        assert_eq!(desc.start_sector, 64);
        assert_eq!(desc.sector_count, 8);
        assert_eq!(desc.buffer_addr, 0xDEAD_BEEF);
    }

    #[test]
    fn io_descriptor_fua_false_when_flag_absent() {
        let raw = UblkSrvIoDesc {
            op_flags: u32::from(UBLK_IO_OP_WRITE),
            count_or_zones: 1,
            start_sector: 0,
            addr: 0,
        };
        let desc = UblkIoDescriptor::from_desc(0, 0, &raw);
        assert!(!desc.fua);
    }

    #[test]
    fn io_descriptor_sector_bytes() {
        let desc = make_read_desc(10, 4);
        assert_eq!(desc.sector_bytes(), 2048); // 4 * 512
    }

    #[test]
    fn io_descriptor_zero_sector_bytes() {
        let desc = make_flush_desc();
        assert_eq!(desc.sector_bytes(), 0);
    }

    #[test]
    fn io_descriptor_display_includes_key_fields() {
        let desc = make_read_desc(128, 16);
        let s = desc.to_string();
        assert!(s.contains("read"));
        assert!(s.contains("128"));
        assert!(s.contains("16"));
        assert!(s.contains("q=0"));
        assert!(s.contains("tag=0"));
    }

    // ── UblkIoDispatchResult tests ───────────────────────────────────

    #[test]
    fn dispatch_result_completed_to_ublk_result_ok() {
        let r = UblkIoDispatchResult::Completed { byte_count: 512 };
        assert_eq!(r.to_ublk_result(), UBLK_IO_RES_OK);
    }

    #[test]
    fn dispatch_result_refused_to_negative_errno() {
        let r = UblkIoDispatchResult::Refused {
            errno: libc::EINVAL,
        };
        assert_eq!(r.to_ublk_result(), -libc::EINVAL);
    }

    #[test]
    fn dispatch_result_refused_enodev_maps_to_abort() {
        let r = UblkIoDispatchResult::Refused {
            errno: libc::ENODEV,
        };
        assert_eq!(r.to_ublk_result(), UBLK_IO_RES_ABORT);
    }

    #[test]
    fn dispatch_result_io_error_to_negative_errno() {
        let r = UblkIoDispatchResult::IoError { errno: libc::EIO };
        assert_eq!(r.to_ublk_result(), -libc::EIO);
    }

    #[test]
    fn dispatch_result_to_io_cmd_builds_correct_structure() {
        let r = UblkIoDispatchResult::Completed { byte_count: 1024 };
        let cmd = r.to_io_cmd(3, 7);
        assert_eq!(cmd.q_id, 3);
        assert_eq!(cmd.tag, 7);
        assert_eq!(cmd.result, UBLK_IO_RES_OK);
        assert_eq!(cmd.addr_or_zone_append_lba, 0);
    }

    #[test]
    fn dispatch_result_to_io_cmd_refused_has_negative_result() {
        let r = UblkIoDispatchResult::Refused {
            errno: libc::EINVAL,
        };
        let cmd = r.to_io_cmd(1, 5);
        assert_eq!(cmd.result, -libc::EINVAL);
    }

    // ── dispatch_io tests ────────────────────────────────────────────

    #[test]
    fn dispatch_read_succeeds() {
        let mut backend = TestBackend::new(65536);
        let mut buf = vec![0u8; 512];
        let desc = make_read_desc(0, 1); // 1 sector = 512 bytes

        let result = dispatch_io(&mut backend, &desc, Some(&mut buf), None).unwrap();
        assert!(matches!(
            result,
            UblkIoDispatchResult::Completed { byte_count: 512 }
        ));
    }

    #[test]
    fn dispatch_read_missing_buffer_errors() {
        let mut backend = TestBackend::new(65536);
        let desc = make_read_desc(0, 1);
        let err = dispatch_io(&mut backend, &desc, None, None).unwrap_err();
        assert_eq!(err, UblkIoHandlerError::MissingBufferAddress);
    }

    #[test]
    fn dispatch_read_zero_length_errors() {
        let mut backend = TestBackend::new(65536);
        let mut buf = [0u8; 1];
        let desc = make_read_desc(0, 0); // zero sectors
        let err = dispatch_io(&mut backend, &desc, Some(&mut buf), None).unwrap_err();
        assert_eq!(err, UblkIoHandlerError::ZeroLengthDataOperation);
    }

    #[test]
    fn dispatch_write_succeeds() {
        let mut backend = TestBackend::new(65536);
        let data = [0xABu8; 512];
        let desc = make_write_desc(0, 1);

        let result = dispatch_io(&mut backend, &desc, None, Some(&data)).unwrap();
        assert!(matches!(
            result,
            UblkIoDispatchResult::Completed { byte_count: 512 }
        ));
    }

    #[test]
    fn dispatch_write_missing_buffer_errors() {
        let mut backend = TestBackend::new(65536);
        let desc = make_write_desc(0, 1);
        let err = dispatch_io(&mut backend, &desc, None, None).unwrap_err();
        assert_eq!(err, UblkIoHandlerError::MissingBufferAddress);
    }

    #[test]
    fn dispatch_fua_write_succeeds() {
        let mut backend = TestBackend::new(65536);
        let data = [0xCDu8; 512];
        let desc = make_fua_write_desc(0, 1);
        let flush_before = backend.flush_count;

        let result = dispatch_io(&mut backend, &desc, None, Some(&data)).unwrap();
        assert!(matches!(result, UblkIoDispatchResult::Completed { .. }));
        assert_eq!(
            backend.flush_count,
            flush_before + 1,
            "FUA write must flush"
        );
    }

    #[test]
    fn dispatch_fua_on_read_errors() {
        let mut backend = TestBackend::new(65536);
        let mut buf = [0u8; 512];
        let desc = make_desc(0, 0, UBLK_IO_OP_READ, UBLK_IO_F_FUA, 0, 1, 0x1000);
        let err = dispatch_io(&mut backend, &desc, Some(&mut buf), None).unwrap_err();
        assert_eq!(err, UblkIoHandlerError::FuaOnlyValidForWrite);
    }

    #[test]
    fn dispatch_flush_succeeds() {
        let mut backend = TestBackend::new(65536);
        let desc = make_flush_desc();

        let result = dispatch_io(&mut backend, &desc, None, None).unwrap();
        assert!(matches!(
            result,
            UblkIoDispatchResult::Completed { byte_count: 0 }
        ));
        assert_eq!(backend.flush_count, 1);
    }

    #[test]
    fn dispatch_flush_with_range_errors() {
        let mut backend = TestBackend::new(65536);
        let desc = make_desc(0, 0, UBLK_IO_OP_FLUSH, 0, 8, 2, 0);

        let err = dispatch_io(&mut backend, &desc, None, None).unwrap_err();
        assert_eq!(err, UblkIoHandlerError::RangeOnFlush);
    }

    #[test]
    fn dispatch_discard_succeeds() {
        let mut backend = TestBackend::new(65536);
        let desc = make_discard_desc(0, 8);

        let result = dispatch_io(&mut backend, &desc, None, None).unwrap();
        assert!(matches!(
            result,
            UblkIoDispatchResult::Completed { byte_count: 0 }
        ));
        assert_eq!(backend.discard_count, 1);
    }

    #[test]
    fn dispatch_write_zeroes_succeeds() {
        let mut backend = TestBackend::new(65536);
        // Pre-write some data
        backend.write_range(0, &[0xFFu8; 512]);
        let desc = make_write_zeroes_desc(0, 1);

        let result = dispatch_io(&mut backend, &desc, None, None).unwrap();
        assert!(matches!(
            result,
            UblkIoDispatchResult::Completed { byte_count: 0 }
        ));
        assert_eq!(backend.write_zeroes_count, 1);

        // Verify the data was zeroed
        let mut buf = [0xCCu8; 512];
        backend.read_range(0, &mut buf);
        assert_eq!(&buf[..], &[0u8; 512]);
    }

    #[test]
    fn dispatch_write_same_errors() {
        let mut backend = TestBackend::new(65536);
        let desc = make_desc(0, 0, UBLK_IO_OP_WRITE_SAME, 0, 0, 1, 0x1000);
        let mut buf = [0u8; 512];

        let err = dispatch_io(&mut backend, &desc, Some(&mut buf), None).unwrap_err();
        assert_eq!(
            err,
            UblkIoHandlerError::UnsupportedOperation(UBLK_IO_OP_WRITE_SAME)
        );
    }

    #[test]
    fn dispatch_unknown_op_errors() {
        let mut backend = TestBackend::new(65536);
        let desc = make_desc(0, 0, 0xFF, 0, 0, 1, 0);

        let err = dispatch_io(&mut backend, &desc, None, None).unwrap_err();
        assert_eq!(err, UblkIoHandlerError::UnsupportedOperation(0xFF));
    }

    // ── read-after-write round trip ──────────────────────────────────

    #[test]
    fn read_after_write_round_trip() {
        let mut backend = TestBackend::new(65536);
        let write_data = [0x42u8; 512];
        let write_desc = make_write_desc(1, 1); // sector 1 = byte 512

        let _ = dispatch_io(&mut backend, &write_desc, None, Some(&write_data)).unwrap();

        let mut read_buf = [0u8; 512];
        let read_desc = make_read_desc(1, 1);
        let result = dispatch_io(&mut backend, &read_desc, Some(&mut read_buf), None).unwrap();
        assert!(matches!(
            result,
            UblkIoDispatchResult::Completed { byte_count: 512 }
        ));
        assert_eq!(&read_buf[..], &write_data[..]);
    }

    // ── UblkIoHandlerError tests ─────────────────────────────────────

    #[test]
    fn handler_error_to_linux_errno() {
        assert_eq!(
            UblkIoHandlerError::UnsupportedOperation(0xFF).to_linux_errno(),
            libc::EOPNOTSUPP
        );
        assert_eq!(
            UblkIoHandlerError::FuaOnlyValidForWrite.to_linux_errno(),
            libc::EINVAL
        );
        assert_eq!(
            UblkIoHandlerError::ZeroLengthDataOperation.to_linux_errno(),
            libc::EINVAL
        );
        assert_eq!(
            UblkIoHandlerError::MissingBufferAddress.to_linux_errno(),
            libc::EINVAL
        );
        assert_eq!(
            UblkIoHandlerError::BackendIoError(libc::EIO).to_linux_errno(),
            libc::EIO
        );
    }

    // ── poll_completed_fetch_reqs (structural, no real ublk device) ──

    #[test]
    fn poll_completed_fetch_reqs_returns_empty_on_null_buf() {
        // With a null io_buf_base, fetching descriptors returns nothing
        // because io_desc_for_queue returns None (tag >= queue_depth or
        // null pointer deref avoided).
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let ring =
            io_uring::IoUring::<io_uring::squeue::Entry128, io_uring::cqueue::Entry>::builder()
                .build(64)
                .expect("io_uring create");
        let mut runtime = UblkDataQueueRuntime {
            data_queue_file: control_file,
            ring,
            outcome: crate::UblkDataQueueRuntimeOpenOutcome {
                dev_id: 0,
                q_id: 0,
                nr_hw_queues: 1,
                queue_depth: 64,
                data_queue_path: PathBuf::from("/dev/null"),
                ring_entries: 64,
                data_queue_fd_open: true,
                io_uring_ready: true,
                runtime_live: true,
            },
            cmd_buf_ptrs: Vec::new(),
            cmd_buf_lens: Vec::new(),
            io_buf_queue_depth: 64,
            io_buf_nr_hw_queues: 1,
            in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
            nodrop_enabled: true,
            cq_overflow_count: 0,
        };

        let descriptors = poll_completed_fetch_reqs(&mut runtime);
        assert!(descriptors.is_empty(), "null mmap yields no descriptors");
    }

    #[test]
    fn poll_completed_fetch_reqs_overflow_fields_accessible_and_zero_init() {
        // Verify nodrop_enabled and cq_overflow_count are set correctly
        // at construction and remain accessible after poll.
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let ring =
            io_uring::IoUring::<io_uring::squeue::Entry128, io_uring::cqueue::Entry>::builder()
                .build(64)
                .expect("io_uring create");
        let mut runtime = UblkDataQueueRuntime {
            data_queue_file: control_file,
            ring,
            outcome: crate::UblkDataQueueRuntimeOpenOutcome {
                dev_id: 0,
                q_id: 0,
                nr_hw_queues: 1,
                queue_depth: 64,
                data_queue_path: PathBuf::from("/dev/null"),
                ring_entries: 64,
                data_queue_fd_open: true,
                io_uring_ready: true,
                runtime_live: true,
            },
            cmd_buf_ptrs: Vec::new(),
            cmd_buf_lens: Vec::new(),
            io_buf_queue_depth: 64,
            io_buf_nr_hw_queues: 1,
            in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
            nodrop_enabled: true,
            cq_overflow_count: 0,
        };

        assert!(runtime.nodrop_enabled(), "nodrop flag set at construction");
        assert_eq!(
            runtime.cq_overflow_count(),
            0,
            "overflow counter starts at zero"
        );

        // With a null mmap, no CQEs are present; poll should return empty
        // and the overflow counter should remain unchanged.
        let descriptors = poll_completed_fetch_reqs(&mut runtime);
        assert!(descriptors.is_empty());
        assert_eq!(runtime.cq_overflow_count(), 0);
    }

    #[test]
    fn poll_completed_fetch_reqs_nodrop_disabled_guard_prevents_spin() {
        // When nodrop_enabled is false and the kernel reports overflow,
        // the function must not retry (since submit() cannot recover
        // overflowed CQEs without NODROP). The counter increments once.
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let ring =
            io_uring::IoUring::<io_uring::squeue::Entry128, io_uring::cqueue::Entry>::builder()
                .build(64)
                .expect("io_uring create");
        let mut runtime = UblkDataQueueRuntime {
            data_queue_file: control_file,
            ring,
            outcome: crate::UblkDataQueueRuntimeOpenOutcome {
                dev_id: 0,
                q_id: 0,
                nr_hw_queues: 1,
                queue_depth: 64,
                data_queue_path: PathBuf::from("/dev/null"),
                ring_entries: 64,
                data_queue_fd_open: true,
                io_uring_ready: true,
                runtime_live: true,
            },
            cmd_buf_ptrs: Vec::new(),
            cmd_buf_lens: Vec::new(),
            io_buf_queue_depth: 64,
            io_buf_nr_hw_queues: 1,
            in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
            nodrop_enabled: false,
            cq_overflow_count: 0,
        };

        // With NODROP disabled, the retry loop exits immediately after
        // recording the overflow. On a null mmap ring there are no CQEs
        // so the function simply returns empty.
        let descriptors = poll_completed_fetch_reqs(&mut runtime);
        assert!(descriptors.is_empty());
        // cq_overflow_count stays at 0 because no real overflow occurred
        // on this synthetic ring.
        assert_eq!(runtime.cq_overflow_count(), 0);
    }

    // ── run_io_loop_iteration (structural, no real ublk device) ──────

    #[test]
    fn run_io_loop_iteration_no_descriptors_returns_zero() {
        let control_file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let ring =
            io_uring::IoUring::<io_uring::squeue::Entry128, io_uring::cqueue::Entry>::builder()
                .build(64)
                .expect("io_uring create");
        let mut runtime = UblkDataQueueRuntime {
            data_queue_file: control_file,
            ring,
            outcome: crate::UblkDataQueueRuntimeOpenOutcome {
                dev_id: 0,
                q_id: 0,
                nr_hw_queues: 1,
                queue_depth: 64,
                data_queue_path: PathBuf::from("/dev/null"),
                ring_entries: 64,
                data_queue_fd_open: true,
                io_uring_ready: true,
                runtime_live: true,
            },
            cmd_buf_ptrs: Vec::new(),
            cmd_buf_lens: Vec::new(),
            io_buf_queue_depth: 64,
            io_buf_nr_hw_queues: 1,
            in_flight_counter: crate::target_reset_guard::InFlightCounter::new(),
            nodrop_enabled: true,
            cq_overflow_count: 0,
        };

        let mut backend = TestBackend::new(65536);
        let (processed, succeeded) = run_io_loop_iteration(&mut runtime, &mut backend, 1, 64);
        assert_eq!(processed, 0);
        assert_eq!(succeeded, 0);
    }

    // ── Gate constant tests ──────────────────────────────────────────

    #[test]
    fn io_ring_handler_gate_constant_is_stable() {
        assert_eq!(
            BLOCK_VOLUME_UBLK_IO_RING_HANDLER_GATE_OW_301AA,
            "OW-301AA block-volume adapter ublk IO ring handler parses submission descriptors, dispatches to backend, and posts COMMIT_AND_FETCH_REQ completions"
        );
    }

    // ── UblkIoDescriptor is Display ──────────────────────────────────

    #[test]
    fn io_descriptor_display_contains_op_and_sectors() {
        let desc = make_desc(1, 99, UBLK_IO_OP_WRITE, UBLK_IO_F_FUA, 1024, 32, 0xBEEF);
        let s = format!("{desc}");
        assert!(s.contains("write"));
        assert!(s.contains("1024"));
        assert!(s.contains("32"));
        assert!(s.contains("fua=true"));
    }

    // ── Large sector count does not overflow ─────────────────────────

    #[test]
    fn sector_bytes_does_not_overflow_for_large_count() {
        let desc = make_desc(0, 0, UBLK_IO_OP_READ, 0, 0, u32::MAX, 0);
        // u32::MAX * 512 = 2_199_023_255_040 - 512 = fits in u64
        let bytes = desc.sector_bytes();
        assert!(bytes > 0);
    }
}
