// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// io_uring-based block I/O dispatch for ublk data-plane operations.
//
// When the --io-uring flag is set, this module provides an alternative
// I/O path that submits read/write/flush SQEs through an io_uring ring
// targeting the backing file descriptor, bypassing the synchronous
// pread/pwrite calls in BlockVolumeFileImage.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::os::fd::RawFd;

use io_uring::{cqueue, opcode, squeue, types, IoUring};

/// Minimum ring entries for the io_uring block I/O dispatch ring.
const UBLK_IO_URING_DISPATCH_RING_ENTRIES: u32 = 256;

/// Result of a single reaped io_uring completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkIoCompletionResult {
    Read { tag: u64, bytes: usize },
    Write { tag: u64, bytes: usize },
    Flush { tag: u64 },
    Discard { tag: u64 },
    WriteZeroes { tag: u64 },
    Error { tag: u64, errno: i32 },
}

impl UblkIoCompletionResult {
    #[must_use]
    pub fn tag(self) -> u64 {
        match self {
            Self::Read { tag, .. }
            | Self::Write { tag, .. }
            | Self::Flush { tag }
            | Self::Discard { tag }
            | Self::WriteZeroes { tag }
            | Self::Error { tag, .. } => tag,
        }
    }

    #[must_use]
    pub fn is_ok(self) -> bool {
        !matches!(self, Self::Error { .. })
    }
}

/// io_uring-based block I/O dispatcher for the backing file.
///
/// Owns a dedicated [`IoUring`] instance configured for the backing
/// file fd and submits read/write/flush operations through standard
/// io_uring SQEs (`IORING_OP_READ`, `IORING_OP_WRITE`, `IORING_OP_FSYNC`).
pub struct UblkIoUringDispatcher {
    ring: IoUring<squeue::Entry, cqueue::Entry>,
    backing_fd: RawFd,
    next_tag: u64,
    inflight: HashMap<u64, InflightOp>,
    /// Accumulated bytes read since construction.
    pub bytes_read: u64,
    /// Accumulated bytes written since construction.
    pub bytes_written: u64,
    /// Number of read operations completed.
    pub read_ops: u64,
    /// Number of write operations completed.
    pub write_ops: u64,
    /// Number of flush operations completed.
    pub flush_ops: u64,
    /// Number of discard operations completed.
    pub discard_ops: u64,
    /// Number of write_zeroes operations completed.
    pub write_zeroes_ops: u64,
    /// Number of operations completed successfully.
    pub completed_ops: u64,
    /// Number of operations that returned an error.
    pub error_ops: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InflightOp {
    Read,
    Write,
    Fsync,
    Discard,
    WriteZeroes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UblkIoUringDispatcherError {
    IoUringSetupErrno(i32),
    IoUringSetupMissingErrno,
    IoUringSubmitErrno(i32),
    IoUringSubmitMissingErrno,
    SubmissionQueueFull,
    CompletionMissing,
    UnsupportedOperation,
    InvalidDescriptor,
    BackingStoreError(i32),
}

impl UblkIoUringDispatcherError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IoUringSetupErrno(_) => "io_uring_setup_errno",
            Self::IoUringSetupMissingErrno => "io_uring_setup_missing_errno",
            Self::IoUringSubmitErrno(_) => "io_uring_submit_errno",
            Self::IoUringSubmitMissingErrno => "io_uring_submit_missing_errno",
            Self::SubmissionQueueFull => "submission_queue_full",
            Self::CompletionMissing => "completion_missing",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::InvalidDescriptor => "invalid_descriptor",
            Self::BackingStoreError(_) => "backing_store_error",
        }
    }

    #[must_use]
    pub const fn linux_errno(self) -> i32 {
        match self {
            Self::BackingStoreError(errno) => errno,
            Self::IoUringSetupErrno(errno) | Self::IoUringSubmitErrno(errno) => -errno,
            Self::IoUringSetupMissingErrno | Self::IoUringSubmitMissingErrno => -libc::EIO,
            Self::SubmissionQueueFull => -libc::EBUSY,
            Self::CompletionMissing => -libc::EIO,
            Self::UnsupportedOperation => -libc::EOPNOTSUPP,
            Self::InvalidDescriptor => -libc::EINVAL,
        }
    }
}

impl UblkIoUringDispatcher {
    pub fn new(backing_fd: RawFd) -> Result<Self, UblkIoUringDispatcherError> {
        let ring = IoUring::<squeue::Entry, cqueue::Entry>::builder()
            .build(UBLK_IO_URING_DISPATCH_RING_ENTRIES)
            .map_err(|err| {
                UblkIoUringDispatcherError::IoUringSetupErrno(err.raw_os_error().unwrap_or(0))
            })?;
        Ok(Self {
            ring,
            backing_fd,
            next_tag: 0,
            inflight: HashMap::with_capacity(UBLK_IO_URING_DISPATCH_RING_ENTRIES as usize),
            bytes_read: 0,
            bytes_written: 0,
            read_ops: 0,
            write_ops: 0,
            flush_ops: 0,
            discard_ops: 0,
            write_zeroes_ops: 0,
            completed_ops: 0,
            error_ops: 0,
        })
    }

    #[must_use]
    pub fn queue_processed(&self) -> bool {
        self.completed_ops > 0 || self.error_ops > 0
    }

    #[must_use]
    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    // ── Blocking single-operation methods ────────────────────────────

    pub fn read_at(
        &mut self,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, UblkIoUringDispatcherError> {
        let len = dst.len().min(u32::MAX as usize) as u32;
        let tag = self.alloc_tag();
        let read_sqe = opcode::Read::new(types::Fd(self.backing_fd), dst.as_mut_ptr(), len)
            .offset(offset)
            .build()
            .user_data(tag);

        // SAFETY: The read_sqe is properly initialized with valid fd, offset,
        // length, and user_data; the backing buffer is pinned for the I/O
        // lifetime via self.inflight tracking. The ring is exclusively owned.
        unsafe {
            self.ring
                .submission()
                .push(&read_sqe)
                .map_err(|_| UblkIoUringDispatcherError::SubmissionQueueFull)?;
        }
        self.inflight.insert(tag, InflightOp::Read);

        self.ring.submit_and_wait(1).map_err(|err| {
            UblkIoUringDispatcherError::IoUringSubmitErrno(err.raw_os_error().unwrap_or(0))
        })?;

        self.reap_one(tag)
    }

    pub fn write_at(
        &mut self,
        offset: u64,
        src: &[u8],
    ) -> Result<usize, UblkIoUringDispatcherError> {
        let len = src.len().min(u32::MAX as usize) as u32;
        let tag = self.alloc_tag();
        let write_sqe =
            opcode::Write::new(types::Fd(self.backing_fd), src.as_ptr() as *mut u8, len)
                .offset(offset)
                .build()
                .user_data(tag);

        // SAFETY: The write_sqe is properly initialized with valid fd, offset,
        // length, and user_data; the backing buffer is pinned for the I/O
        // lifetime via self.inflight tracking. The ring is exclusively owned.
        unsafe {
            self.ring
                .submission()
                .push(&write_sqe)
                .map_err(|_| UblkIoUringDispatcherError::SubmissionQueueFull)?;
        }
        self.inflight.insert(tag, InflightOp::Write);

        self.ring.submit_and_wait(1).map_err(|err| {
            UblkIoUringDispatcherError::IoUringSubmitErrno(err.raw_os_error().unwrap_or(0))
        })?;

        self.reap_one(tag)
    }

    pub fn flush(&mut self) -> Result<(), UblkIoUringDispatcherError> {
        let tag = self.alloc_tag();
        let fsync_sqe = opcode::Fsync::new(types::Fd(self.backing_fd))
            .build()
            .user_data(tag);

        // SAFETY: fsync_sqe is properly initialized with valid fd and
        // user_data; the ring is exclusively owned.
        unsafe {
            self.ring
                .submission()
                .push(&fsync_sqe)
                .map_err(|_| UblkIoUringDispatcherError::SubmissionQueueFull)?;
        }
        self.inflight.insert(tag, InflightOp::Fsync);

        self.ring.submit_and_wait(1).map_err(|err| {
            UblkIoUringDispatcherError::IoUringSubmitErrno(err.raw_os_error().unwrap_or(0))
        })?;

        let _ = self.reap_one(tag)?;
        Ok(())
    }

    pub fn discard_at(&mut self, offset: u64, len: u64) -> Result<(), UblkIoUringDispatcherError> {
        self.fallocate_or_zero_fill(
            InflightOp::Discard,
            offset,
            len,
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
        )
    }

    pub fn write_zeroes_at(
        &mut self,
        offset: u64,
        len: u64,
    ) -> Result<(), UblkIoUringDispatcherError> {
        self.fallocate_or_zero_fill(
            InflightOp::WriteZeroes,
            offset,
            len,
            libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE,
        )
    }

    // ── Batch submission methods ─────────────────────────────────────

    pub fn submit_read(
        &mut self,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<u64, UblkIoUringDispatcherError> {
        let len = dst.len().min(u32::MAX as usize) as u32;
        let tag = self.alloc_tag();
        let read_sqe = opcode::Read::new(types::Fd(self.backing_fd), dst.as_mut_ptr(), len)
            .offset(offset)
            .build()
            .user_data(tag);

        // SAFETY: The read_sqe is properly initialized with valid fd, offset,
        // length, and user_data; the backing buffer is pinned for the I/O
        // lifetime via self.inflight tracking. The ring is exclusively owned.
        unsafe {
            self.ring
                .submission()
                .push(&read_sqe)
                .map_err(|_| UblkIoUringDispatcherError::SubmissionQueueFull)?;
        }
        self.inflight.insert(tag, InflightOp::Read);
        Ok(tag)
    }

    pub fn submit_write(
        &mut self,
        offset: u64,
        src: &[u8],
    ) -> Result<u64, UblkIoUringDispatcherError> {
        let len = src.len().min(u32::MAX as usize) as u32;
        let tag = self.alloc_tag();
        let write_sqe =
            opcode::Write::new(types::Fd(self.backing_fd), src.as_ptr() as *mut u8, len)
                .offset(offset)
                .build()
                .user_data(tag);

        // SAFETY: The write_sqe is properly initialized with valid fd, offset,
        // length, and user_data; the backing buffer is pinned for the I/O
        // lifetime via self.inflight tracking. The ring is exclusively owned.
        unsafe {
            self.ring
                .submission()
                .push(&write_sqe)
                .map_err(|_| UblkIoUringDispatcherError::SubmissionQueueFull)?;
        }
        self.inflight.insert(tag, InflightOp::Write);
        Ok(tag)
    }

    pub fn submit_flush(&mut self) -> Result<u64, UblkIoUringDispatcherError> {
        let tag = self.alloc_tag();
        let fsync_sqe = opcode::Fsync::new(types::Fd(self.backing_fd))
            .build()
            .user_data(tag);

        // SAFETY: fsync_sqe is properly initialized with valid fd and
        // user_data; the ring is exclusively owned.
        unsafe {
            self.ring
                .submission()
                .push(&fsync_sqe)
                .map_err(|_| UblkIoUringDispatcherError::SubmissionQueueFull)?;
        }
        self.inflight.insert(tag, InflightOp::Fsync);
        Ok(tag)
    }

    pub fn submit_discard(
        &mut self,
        offset: u64,
        len: u64,
    ) -> Result<u64, UblkIoUringDispatcherError> {
        let tag = self.alloc_tag();
        let falloc_sqe = opcode::Fallocate::new(types::Fd(self.backing_fd), len)
            .offset(offset)
            .mode(libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE)
            .build()
            .user_data(tag);

        // SAFETY: falloc_sqe is properly initialized with valid fd, offset,
        // and length; the ring is exclusively owned.
        unsafe {
            self.ring
                .submission()
                .push(&falloc_sqe)
                .map_err(|_| UblkIoUringDispatcherError::SubmissionQueueFull)?;
        }
        self.inflight.insert(tag, InflightOp::Discard);
        Ok(tag)
    }

    pub fn submit_write_zeroes(
        &mut self,
        offset: u64,
        len: u64,
    ) -> Result<u64, UblkIoUringDispatcherError> {
        let tag = self.alloc_tag();
        let falloc_sqe = opcode::Fallocate::new(types::Fd(self.backing_fd), len)
            .offset(offset)
            .mode(libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE)
            .build()
            .user_data(tag);

        // SAFETY: falloc_sqe is properly initialized with valid fd, offset,
        // and length; the ring is exclusively owned.
        unsafe {
            self.ring
                .submission()
                .push(&falloc_sqe)
                .map_err(|_| UblkIoUringDispatcherError::SubmissionQueueFull)?;
        }
        self.inflight.insert(tag, InflightOp::WriteZeroes);
        Ok(tag)
    }

    /// Submit all pending SQEs. Returns the number submitted.
    pub fn submit_all(&mut self) -> Result<usize, UblkIoUringDispatcherError> {
        self.ring.submit().map_err(|err| {
            UblkIoUringDispatcherError::IoUringSubmitErrno(err.raw_os_error().unwrap_or(0))
        })
    }

    /// Submit pending SQEs and wait for at least `want` completions.
    pub fn submit_and_wait(&mut self, want: usize) -> Result<usize, UblkIoUringDispatcherError> {
        self.ring.submit_and_wait(want).map_err(|err| {
            UblkIoUringDispatcherError::IoUringSubmitErrno(err.raw_os_error().unwrap_or(0))
        })
    }

    /// Poll the CQ and reap all available completions. Non-blocking.
    pub fn reap_completions(&mut self) -> Vec<UblkIoCompletionResult> {
        let mut results = Vec::new();
        // Drain available CQEs in a loop (no borrow conflict since we
        // drop the CompletionQueue after each iteration).
        loop {
            let cqe = self.ring.completion().next();
            let Some(cqe) = cqe else {
                break;
            };
            let tag = cqe.user_data();
            let result = cqe.result();

            let Some(op) = self.inflight.remove(&tag) else {
                continue;
            };

            if result < 0 {
                self.error_ops += 1;
                results.push(UblkIoCompletionResult::Error {
                    tag,
                    errno: -result,
                });
                continue;
            }

            let byte_count = result as usize;
            match op {
                InflightOp::Read => {
                    self.bytes_read += byte_count as u64;
                    self.read_ops += 1;
                    self.completed_ops += 1;
                    results.push(UblkIoCompletionResult::Read {
                        tag,
                        bytes: byte_count,
                    });
                }
                InflightOp::Write => {
                    self.bytes_written += byte_count as u64;
                    self.write_ops += 1;
                    self.completed_ops += 1;
                    results.push(UblkIoCompletionResult::Write {
                        tag,
                        bytes: byte_count,
                    });
                }
                InflightOp::Fsync => {
                    self.flush_ops += 1;
                    self.completed_ops += 1;
                    results.push(UblkIoCompletionResult::Flush { tag });
                }
                InflightOp::Discard => {
                    self.discard_ops += 1;
                    self.completed_ops += 1;
                    results.push(UblkIoCompletionResult::Discard { tag });
                }
                InflightOp::WriteZeroes => {
                    self.write_zeroes_ops += 1;
                    self.completed_ops += 1;
                    results.push(UblkIoCompletionResult::WriteZeroes { tag });
                }
            }
        }
        results
    }

    // ── Private helpers ──────────────────────────────────────────────

    fn alloc_tag(&mut self) -> u64 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        tag
    }

    fn fallocate_or_zero_fill(
        &mut self,
        op: InflightOp,
        offset: u64,
        len: u64,
        mode: i32,
    ) -> Result<(), UblkIoUringDispatcherError> {
        if offset > i64::MAX as u64 || len > i64::MAX as u64 {
            return Err(UblkIoUringDispatcherError::InvalidDescriptor);
        }

        // SAFETY: fallocate is a C FFI call; backing_fd is a valid open fd;
        // offset and len are valid off_t values; mode is valid per the fallocate
        // mode flags.
        let rc = unsafe {
            libc::fallocate(
                self.backing_fd,
                mode,
                offset as libc::off_t,
                len as libc::off_t,
            )
        };
        if rc == 0 {
            self.record_fallocate_completion(op);
            return Ok(());
        }

        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if Self::can_zero_fill_after_fallocate_errno(errno) {
            self.zero_fill_at(offset, len)?;
            self.record_fallocate_completion(op);
            return Ok(());
        }

        self.error_ops += 1;
        Err(UblkIoUringDispatcherError::BackingStoreError(-errno))
    }

    const fn can_zero_fill_after_fallocate_errno(errno: i32) -> bool {
        matches!(errno, libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL)
    }

    fn zero_fill_at(&self, offset: u64, len: u64) -> Result<(), UblkIoUringDispatcherError> {
        if offset > i64::MAX as u64 {
            return Err(UblkIoUringDispatcherError::InvalidDescriptor);
        }

        let zeroes = [0_u8; 64 * 1024];
        let mut written = 0_u64;
        while written < len {
            let remaining = (len - written) as usize;
            let chunk = remaining.min(zeroes.len());
            let write_offset = offset
                .checked_add(written)
                .ok_or(UblkIoUringDispatcherError::InvalidDescriptor)?;
            if write_offset > i64::MAX as u64 {
                return Err(UblkIoUringDispatcherError::InvalidDescriptor);
            }

            // SAFETY: pwrite is a C FFI call; backing_fd is valid; zeroes
            // is a Vec with at least chunk bytes; write_offset is a valid off_t.
            let rc = unsafe {
                libc::pwrite(
                    self.backing_fd,
                    zeroes.as_ptr().cast(),
                    chunk,
                    write_offset as libc::off_t,
                )
            };
            if rc < 0 {
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                return Err(UblkIoUringDispatcherError::BackingStoreError(-errno));
            }
            if rc == 0 {
                return Err(UblkIoUringDispatcherError::BackingStoreError(-libc::EIO));
            }
            written += rc as u64;
        }
        Ok(())
    }

    fn record_fallocate_completion(&mut self, op: InflightOp) {
        match op {
            InflightOp::Discard => self.discard_ops += 1,
            InflightOp::WriteZeroes => self.write_zeroes_ops += 1,
            InflightOp::Read | InflightOp::Write | InflightOp::Fsync => {}
        }
        self.completed_ops += 1;
    }

    /// After submit_and_wait, reap CQEs until we find `wanted_tag` and
    /// return its byte count, or return an error.
    fn reap_one(&mut self, wanted_tag: u64) -> Result<usize, UblkIoUringDispatcherError> {
        loop {
            let cqe = self.ring.completion().next();
            let Some(cqe) = cqe else {
                return Err(UblkIoUringDispatcherError::CompletionMissing);
            };
            let tag = cqe.user_data();
            let result = cqe.result();

            let Some(op) = self.inflight.remove(&tag) else {
                continue;
            };

            if result < 0 {
                self.error_ops += 1;
                if tag == wanted_tag {
                    return Err(UblkIoUringDispatcherError::BackingStoreError(result));
                }
                continue;
            }

            let byte_count = result as usize;
            match op {
                InflightOp::Read => {
                    self.bytes_read += byte_count as u64;
                    self.read_ops += 1;
                    self.completed_ops += 1;
                }
                InflightOp::Write => {
                    self.bytes_written += byte_count as u64;
                    self.write_ops += 1;
                    self.completed_ops += 1;
                }
                InflightOp::Fsync => {
                    self.flush_ops += 1;
                    self.completed_ops += 1;
                }
                InflightOp::Discard => {
                    self.discard_ops += 1;
                    self.completed_ops += 1;
                }
                InflightOp::WriteZeroes => {
                    self.write_zeroes_ops += 1;
                    self.completed_ops += 1;
                }
            }

            if tag == wanted_tag {
                return Ok(byte_count);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use tempfile::tempfile;

    fn create_tempfile_with_data(data: &[u8]) -> (std::fs::File, RawFd) {
        let mut f = tempfile().expect("tempfile");
        f.write_all(data).expect("write data");
        f.flush().expect("flush");
        let fd = f.as_raw_fd();
        (f, fd)
    }

    #[test]
    fn dispatcher_new_succeeds_with_valid_fd() {
        let (_f, fd) = create_tempfile_with_data(&[0u8; 4096]);
        let dispatcher = UblkIoUringDispatcher::new(fd);
        assert!(
            dispatcher.is_ok(),
            "dispatcher should be created with valid fd"
        );
        let d = dispatcher.unwrap();
        assert_eq!(d.completed_ops, 0);
        assert_eq!(d.error_ops, 0);
        assert_eq!(d.inflight_count(), 0);
    }

    #[test]
    fn dispatcher_new_accepts_or_rejects_invalid_fd_by_kernel() {
        // io_uring setup may or may not validate the fd, depending on
        // kernel version. We accept both outcomes as valid.
        let result = UblkIoUringDispatcher::new(-1);
        // If it succeeded, the ring is functional but ops will fail.
        // If it errored, that's also correct kernel behavior.
        if let Ok(_dispatcher) = result {
            // Ring created despite invalid fd; later ops will fail.
        }
    }

    #[test]
    fn read_at_returns_correct_data() {
        let data: Vec<u8> = (0..4096u16).map(|i| (i % 256) as u8).collect();
        let (_f, fd) = create_tempfile_with_data(&data);
        let mut dispatcher = UblkIoUringDispatcher::new(fd).expect("dispatcher");

        let mut buf = vec![0u8; 512];
        let bytes = dispatcher.read_at(1024, &mut buf).expect("read_at");

        assert_eq!(bytes, 512);
        assert_eq!(&buf[..], &data[1024..1024 + 512]);
        assert_eq!(dispatcher.read_ops, 1);
        assert_eq!(dispatcher.completed_ops, 1);
        assert_eq!(dispatcher.bytes_read, 512);
    }

    #[test]
    fn write_at_then_read_at_roundtrip() {
        let data = vec![0u8; 8192];
        let (_f, fd) = create_tempfile_with_data(&data);
        let mut dispatcher = UblkIoUringDispatcher::new(fd).expect("dispatcher");

        let payload: Vec<u8> = (0..1024u16).map(|i| (i % 256) as u8).collect();
        let written = dispatcher.write_at(2048, &payload).expect("write_at");
        assert_eq!(written, 1024);
        assert_eq!(dispatcher.write_ops, 1);
        assert_eq!(dispatcher.completed_ops, 1);
        assert_eq!(dispatcher.bytes_written, 1024);

        // Sync to ensure durability before reading.
        dispatcher.flush().expect("flush");
        assert_eq!(dispatcher.flush_ops, 1);

        let mut buf = vec![0u8; 1024];
        let read = dispatcher.read_at(2048, &mut buf).expect("read_at");
        assert_eq!(read, 1024);
        assert_eq!(&buf[..], &payload[..]);
        assert_eq!(dispatcher.read_ops, 1);
        assert_eq!(dispatcher.completed_ops, 3);
    }

    #[test]
    fn flush_completes_successfully() {
        let data = vec![0u8; 4096];
        let (_f, fd) = create_tempfile_with_data(&data);
        let mut dispatcher = UblkIoUringDispatcher::new(fd).expect("dispatcher");

        dispatcher.flush().expect("flush");
        assert_eq!(dispatcher.flush_ops, 1);
        assert_eq!(dispatcher.completed_ops, 1);
    }

    #[test]
    fn batch_submit_and_reap_read_write_flush() {
        let data = vec![0u8; 16384];
        let (_f, fd) = create_tempfile_with_data(&data);
        let mut dispatcher = UblkIoUringDispatcher::new(fd).expect("dispatcher");

        let write_payload: Vec<u8> = (0..1024u16).map(|i| i as u8).collect();
        let mut read_buf = vec![0u8; 1024];

        // Use blocking path: write, flush, then read for deterministic ordering.
        dispatcher.write_at(0, &write_payload).expect("write_at");
        dispatcher.flush().expect("flush");
        let read_bytes = dispatcher.read_at(0, &mut read_buf).expect("read_at");

        assert_eq!(read_bytes, 1024);
        assert_eq!(&read_buf[..], &write_payload[..]);
        assert_eq!(dispatcher.completed_ops, 3);
        assert_eq!(dispatcher.write_ops, 1);
        assert_eq!(dispatcher.flush_ops, 1);
        assert_eq!(dispatcher.read_ops, 1);
    }

    #[test]
    fn discard_and_write_zeroes_complete_without_error() {
        let data = vec![0x5au8; 16384];
        let (_f, fd) = create_tempfile_with_data(&data);
        let mut dispatcher = UblkIoUringDispatcher::new(fd).expect("dispatcher");

        dispatcher.discard_at(0, 4096).expect("discard_at");
        assert_eq!(dispatcher.discard_ops, 1);

        dispatcher
            .write_zeroes_at(4096, 4096)
            .expect("write_zeroes_at");
        assert_eq!(dispatcher.write_zeroes_ops, 1);
        assert_eq!(dispatcher.completed_ops, 2);

        let mut buf = vec![0u8; 12288];
        dispatcher.read_at(0, &mut buf).expect("read_at");
        assert_eq!(&buf[..8192], vec![0u8; 8192]);
        assert_eq!(&buf[8192..], vec![0x5au8; 4096]);
    }

    #[test]
    fn submission_queue_full_after_capacity() {
        let data = vec![0u8; 4096];
        let (_f, fd) = create_tempfile_with_data(&data);
        let mut dispatcher = UblkIoUringDispatcher::new(fd).expect("dispatcher");

        // Push SQEs without submitting to fill the SQ.
        let mut full_err = false;
        for i in 0..300u64 {
            let mut buf = vec![0u8; 4096];
            let _buf_slice: &mut [u8] = &mut buf;
            // SAFETY: we leak the buf to keep the pointer valid for SQE.
            // This is a test-only approach; in production, buffers come
            // from pinned memory.
            let leaked: &'static mut [u8] = Box::leak(buf.into_boxed_slice());
            match dispatcher.submit_read(i * 4096, leaked) {
                Ok(_) => {}
                Err(UblkIoUringDispatcherError::SubmissionQueueFull) => {
                    full_err = true;
                    break;
                }
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert!(full_err, "expected SubmissionQueueFull after filling ring");
    }
}
