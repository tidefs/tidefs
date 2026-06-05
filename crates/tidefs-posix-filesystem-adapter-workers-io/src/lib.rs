#![no_std]
#![forbid(unsafe_code)]

//! Sparse I/O types and write-buffer staging for the POSIX filesystem adapter.
//!
//! This crate provides write payload staging, content hashing, read caching,
//! and copy_file_range request/plan types used by the FUSE daemon dispatch path.

extern crate alloc;

use alloc::vec::Vec;

use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterWriteStagingOutcome, PosixFilesystemAdapterWriteStagingRequest,
    SPARSE_IO_BLOCK_SIZE,
};

/// Re-export all request-queue types and runtime functions for this seam family.
pub const SEAM_FAMILY_DOC: &str = concat!("seam.", env!("CARGO_PKG_NAME"), ".    P5-02.v0");

// ── Write staging ──────────────────────────────────────────────────────────

/// Errors returned while copying FUSE write payloads into staging buffers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteStagingError {
    InvalidRange,
    Misaligned,
    LengthMismatch,
    OutOfBufferHandles,
}

impl WriteStagingError {
    #[must_use]
    pub const fn to_errno(self) -> i32 {
        match self {
            Self::InvalidRange | Self::Misaligned | Self::LengthMismatch => io_errno::EINVAL,
            Self::OutOfBufferHandles => io_errno::EIO,
        }
    }
}

/// Owned staged write payload ready for scheduler submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedWrite {
    pub outcome: PosixFilesystemAdapterWriteStagingOutcome,
    pub data: Vec<u8>,
}

/// Copies classified FUSE write payloads into extent-aligned staging buffers.
#[derive(Clone, Debug)]
pub struct WriteBuffer {
    next_buffer_handle: u64,
}

impl WriteBuffer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_buffer_handle: 1,
        }
    }

    pub fn stage(
        &mut self,
        request: PosixFilesystemAdapterWriteStagingRequest,
        data: &[u8],
    ) -> Result<StagedWrite, WriteStagingError> {
        if request.length as usize != data.len() {
            return Err(WriteStagingError::LengthMismatch);
        }

        if request.end_offset().is_none() {
            return Err(WriteStagingError::InvalidRange);
        }

        if !request.is_empty()
            && (request.offset % SPARSE_IO_BLOCK_SIZE != 0
                || request.length as u64 % SPARSE_IO_BLOCK_SIZE != 0)
        {
            return Err(WriteStagingError::Misaligned);
        }

        let buffer_handle = self.next_buffer_handle;
        self.next_buffer_handle = self
            .next_buffer_handle
            .checked_add(1)
            .ok_or(WriteStagingError::OutOfBufferHandles)?;

        let copied = Vec::from(data);
        let outcome = PosixFilesystemAdapterWriteStagingOutcome {
            unique: request.unique,
            inode: request.inode,
            offset: request.offset,
            length: request.length,
            buffer_handle,
            content_hash64: staged_write_hash64(&copied),
            write_flags: request.write_flags,
            _reserved: [0_u32; 1],
        };

        Ok(StagedWrite {
            outcome,
            data: copied,
        })
    }
}

impl Default for WriteBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Content hashing ────────────────────────────────────────────────────────

#[must_use]
pub fn staged_write_hash64(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for byte in data {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ── I/O errno constants ────────────────────────────────────────────────────

pub mod io_errno {
    /// Input/output error.
    pub const EIO: i32 = 5;
    /// Invalid argument.
    pub const EINVAL: i32 = 22;
}

// ── Copy file range ────────────────────────────────────────────────────────

/// Maximum chunk size for a copy_file_range loop iteration.
pub const COPY_FILE_RANGE_MAX_CHUNK: u64 = SPARSE_IO_BLOCK_SIZE;

/// Validated copy_file_range request ready for IO-worker dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuseCopyFileRangePlan {
    /// FUSE unique request identifier.
    pub unique: u64,
    /// Source inode number.
    pub ino_in: u64,
    /// Source file handle.
    pub fh_in: u64,
    /// Source file offset.
    pub offset_in: u64,
    /// Destination inode number.
    pub ino_out: u64,
    /// Destination file handle.
    pub fh_out: u64,
    /// Destination file offset.
    pub offset_out: u64,
    /// Requested copy length.
    pub len: u64,
}

/// Validation errors for copy_file_range request planning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyFileRangePlanError {
    /// Source or destination offset was negative.
    NegativeOffset,
    /// FUSE flags are currently unsupported and must be zero.
    UnsupportedFlags,
    /// Range arithmetic overflowed.
    InvalidRange,
}

impl CopyFileRangePlanError {
    /// Map the planning error to POSIX errno for FUSE replies.
    #[must_use]
    pub const fn to_errno(self) -> i32 {
        match self {
            Self::NegativeOffset | Self::UnsupportedFlags | Self::InvalidRange => io_errno::EINVAL,
        }
    }
}

fn checked_add(left: u64, right: u64) -> Result<u64, CopyFileRangePlanError> {
    left.checked_add(right)
        .ok_or(CopyFileRangePlanError::InvalidRange)
}

/// Raw copy_file_range request from the FUSE wire, before validation.
pub struct FuseCopyFileRangeRequest {
    /// FUSE unique request identifier.
    pub unique: u64,
    /// Source inode number.
    pub ino_in: u64,
    /// Source file handle.
    pub fh_in: u64,
    /// Source offset from fuser, still signed for pre-cast validation.
    pub offset_in: i64,
    /// Destination inode number.
    pub ino_out: u64,
    /// Destination file handle.
    pub fh_out: u64,
    /// Destination offset from fuser, still signed for pre-cast validation.
    pub offset_out: i64,
    /// Requested copy length.
    pub len: u64,
    /// FUSE copy_file_range flags.
    pub flags: u32,
}

impl FuseCopyFileRangeRequest {
    /// Construct a copy_file_range request with explicit FUSE fields.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        unique: u64,
        ino_in: u64,
        fh_in: u64,
        offset_in: i64,
        ino_out: u64,
        fh_out: u64,
        offset_out: i64,
        len: u64,
        flags: u32,
    ) -> Self {
        Self {
            unique,
            ino_in,
            fh_in,
            offset_in,
            ino_out,
            fh_out,
            offset_out,
            len,
            flags,
        }
    }

    /// Validate signed offsets and flags before converting to a copy plan.
    pub fn plan(&self) -> Result<FuseCopyFileRangePlan, CopyFileRangePlanError> {
        if self.offset_in < 0 || self.offset_out < 0 {
            return Err(CopyFileRangePlanError::NegativeOffset);
        }
        if self.flags != 0 {
            return Err(CopyFileRangePlanError::UnsupportedFlags);
        }
        let offset_in =
            u64::try_from(self.offset_in).map_err(|_| CopyFileRangePlanError::NegativeOffset)?;
        let offset_out =
            u64::try_from(self.offset_out).map_err(|_| CopyFileRangePlanError::NegativeOffset)?;
        let end_in = checked_add(offset_in, self.len)?;
        let end_out = checked_add(offset_out, self.len)?;
        let max_signed_offset = i64::MAX as u64;
        if end_in > max_signed_offset || end_out > max_signed_offset {
            return Err(CopyFileRangePlanError::InvalidRange);
        }
        Ok(FuseCopyFileRangePlan {
            unique: self.unique,
            ino_in: self.ino_in,
            fh_in: self.fh_in,
            offset_in,
            ino_out: self.ino_out,
            fh_out: self.fh_out,
            offset_out,
            len: self.len,
        })
    }
}

// ── Read cache trait ───────────────────────────────────────────────────────

/// Read cache contract needed by file-read workers.
///
/// Implementations may defer to an external page cache or provide a no-op
/// fallback for testing and direct-I/O paths.
pub trait ReadCache {
    /// Look up cached data spanning `[offset, offset + length)` for `ino`.
    ///
    /// Returns `None` when no cached data covers the requested range.
    fn lookup(&self, ino: u64, offset: u64, length: u64) -> Option<Vec<u8>>;

    /// Insert data into the cache for `ino` at `offset`.
    fn insert(&mut self, ino: u64, offset: u64, data: &[u8]);
}

/// A [`ReadCache`] that never caches data — every lookup is a miss.
///
/// Use this when page-cache acceleration is unavailable (e.g. direct-I/O
/// mode or testing without a cache layer).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopReadCache;

impl ReadCache for NoopReadCache {
    fn lookup(&self, _ino: u64, _offset: u64, _length: u64) -> Option<Vec<u8>> {
        None
    }

    fn insert(&mut self, _ino: u64, _offset: u64, _data: &[u8]) {
        // no-op: discard all cached data
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn write_buffer_rejects_length_mismatch() {
        let mut buf = WriteBuffer::new();
        let req = PosixFilesystemAdapterWriteStagingRequest {
            unique: 1,
            inode: 100,
            fh: 0,
            lock_owner: 0,
            offset: 0,
            length: 8,
            write_flags: 0,
            _reserved: [0_u32; 2],
        };
        let err = buf.stage(req, b"short").unwrap_err();
        assert_eq!(err, WriteStagingError::LengthMismatch);
    }

    #[test]
    fn write_buffer_accepts_zero_length_payload() {
        let mut buf = WriteBuffer::new();
        let req = PosixFilesystemAdapterWriteStagingRequest {
            unique: 1,
            inode: 100,
            fh: 0,
            lock_owner: 0,
            offset: SPARSE_IO_BLOCK_SIZE,
            length: 0,
            write_flags: 0,
            _reserved: [0_u32; 2],
        };
        let staged = buf.stage(req, &[]).expect("zero-length write");
        assert_eq!(staged.outcome.unique, 1);
        assert_eq!(staged.outcome.length, 0);
        assert!(staged.data.is_empty());
    }

    #[test]
    fn staged_write_hash64_is_deterministic() {
        let h1 = staged_write_hash64(b"hello");
        let h2 = staged_write_hash64(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn staged_write_hash64_differs_on_input() {
        let h1 = staged_write_hash64(b"hello");
        let h2 = staged_write_hash64(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn copy_file_range_request_rejects_negative_offsets_and_flags() {
        let req = FuseCopyFileRangeRequest::new(1, 2, 3, -1, 4, 5, 0, 4096, 0);
        assert_eq!(
            req.plan().unwrap_err(),
            CopyFileRangePlanError::NegativeOffset
        );

        let req = FuseCopyFileRangeRequest::new(1, 2, 3, 0, 4, 5, -1, 4096, 0);
        assert_eq!(
            req.plan().unwrap_err(),
            CopyFileRangePlanError::NegativeOffset
        );

        let req = FuseCopyFileRangeRequest::new(1, 2, 3, 0, 4, 5, 0, 4096, 1);
        assert_eq!(
            req.plan().unwrap_err(),
            CopyFileRangePlanError::UnsupportedFlags
        );
    }

    #[test]
    fn copy_file_range_request_rejects_overflowing_ranges() {
        let req = FuseCopyFileRangeRequest::new(1, 2, 3, 0, 4, 5, 0, u64::MAX, 0);
        assert_eq!(
            req.plan().unwrap_err(),
            CopyFileRangePlanError::InvalidRange
        );
    }

    #[test]
    fn copy_file_range_request_plan_succeeds_for_valid_input() {
        let req = FuseCopyFileRangeRequest::new(100, 10, 20, 0, 30, 40, 1024, 4096, 0);
        let plan = req.plan().expect("valid request");
        assert_eq!(plan.unique, 100);
        assert_eq!(plan.ino_in, 10);
        assert_eq!(plan.fh_in, 20);
        assert_eq!(plan.offset_in, 0);
        assert_eq!(plan.ino_out, 30);
        assert_eq!(plan.fh_out, 40);
        assert_eq!(plan.offset_out, 1024);
        assert_eq!(plan.len, 4096);
    }

    #[test]
    fn noop_read_cache_always_misses() {
        let cache = NoopReadCache;
        assert!(cache.lookup(1, 0, 256).is_none());
    }

    #[test]
    fn noop_read_cache_insert_is_noop() {
        let mut cache = NoopReadCache;
        cache.insert(1, 0, b"data");
        assert!(cache.lookup(1, 0, 4).is_none());
    }
}
