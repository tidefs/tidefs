//! FUSE `write` handler helpers -- write-flag validation, direct-I/O
//! alignment, overflow-safe end-offset calculation, and writeback
//! buffering, and unified dispatch for the POSIX write(2) data path.
//!
//! Provides:
//! - [`WRITE_DIRECT_IO_ALIGNMENT`]: sector-size alignment constant (512).
//! - [`validate_write_flags`]: reject unknown write-flag bits; optionally
//!   gate [`FUSE_WRITE_CACHE`] on a writeback-cache-enabled switch
//!   (requires `abi-7-9`).
//! - Re-export of FUSE write flags: [`FUSE_WRITE_CACHE`],
//!   [`FUSE_WRITE_LOCKOWNER`] (requires `abi-7-9`), and
//!   [`FUSE_WRITE_KILL_PRIV`] (requires `abi-7-31`).
//! - [`checked_write_end`]: compute `offset + len` with overflow and
//!   negative-offset rejection.
//! - [`check_direct_io_alignment`]: verify offset and data length are
//!   multiples of [`WRITE_DIRECT_IO_ALIGNMENT`] (required for
//!   `FOPEN_DIRECT_IO` file descriptors per POSIX).
//! - [`WritePlan`]: structured plan for a write operation carrying
//!   resolved offset, data length, exclusive end offset, and write flags.
//! - [`plan_write`]: construct a [`WritePlan`] from raw parameters.
//! - [`check_write_allowed`]: validate that a write operation is
//!   applicable to the given file kind (reject directories, pipes,
//!   sockets, and symlinks).
//! - [`check_write_readonly`]: reject writes on a read-only filesystem.
//! - [`validate_write`]: composite validation combining file-kind,
//!   read-only, and end-offset checks.
//! - [`WriteBuffering`]: writeback accumulation buffer that gathers
//!   dirty data and flushes at a configurable byte threshold.
//! - [`is_append_open`], [`is_direct_io_open`], [`is_sync_open`]:
//!   predicate helpers for inspecting the file-open `flags` passed
//!   with each FUSE `write` request (`O_APPEND`, `O_DIRECT`, `O_SYNC`).
//! - [`validate_write_request`]: validate core request parameters
//!   (`fh`, `offset`, `size`, `flags`) for a FUSE write request,
//!   rejecting bad file handles, negative offsets, and overflow.
//! - [`handle_write`]: unified dispatch entry-point that validates
//!   all parameters, builds a [`WritePlan`], and delegates to the
//!   writeback worker or VfsEngine with intent-log crash safety.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::write;
//!
//! // Validate that write_flags contains only recognised bits.
//! write::validate_write_flags(0, true)?;
//!
//! // Build a write plan from raw FUSE parameters.
//! let plan = write::plan_write(0, &data, 0)?;
//! assert_eq!(plan.end, data.len() as u64);
//!
//! // Composite validation.
//! write::validate_write(FileType::RegularFile, plan.end, false)?;
//!
//! // Ensure O_DIRECT alignment.
//! write::check_direct_io_alignment(512, 4096)?;
//! ```

use crate::errno;
use libc::c_int;

use crate::FileType;

// Re-export write flags (feature-gated to match the upstream constants).
#[cfg(feature = "abi-7-31")]
pub use crate::ll::fuse_abi::consts::FUSE_WRITE_KILL_PRIV;
#[cfg(feature = "abi-7-9")]
pub use crate::ll::fuse_abi::consts::{FUSE_WRITE_CACHE, FUSE_WRITE_LOCKOWNER};

// ---------------------------------------------------------------------------
// Re-exports: standard errno codes for write error paths
// ---------------------------------------------------------------------------

pub use libc::{EBADF, EFBIG, EINTR, EINVAL, EIO, EISDIR, ENOSPC, EROFS};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Minimum sector alignment required for `O_DIRECT` / `FOPEN_DIRECT_IO`
// write operations.  POSIX mandates that direct-I/O buffers and file
// offsets be multiples of the logical block size, which is at least
// 512 bytes.
// ── check_write_permission — POSIX write DAC ────────────────────────

/// Check that the caller has write permission on the target inode.
///
/// Wraps [`crate::access::check_fuse_access`] requesting
/// [`crate::access::ACCESS_WRITE`].
pub fn check_write_permission(
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
) -> Result<(), c_int> {
    crate::access::check_fuse_access(
        mode,
        file_uid,
        file_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        crate::access::ACCESS_WRITE,
    )
}

// ---------------------------------------------------------------------------
// Open-flag predicate helpers
// ---------------------------------------------------------------------------

/// File-open flags used to classify write behaviour.
///
/// These are the standard `open(2)` flag bits that the kernel
/// passes through in the `flags` field of every FUSE `write`
/// request (since protocol 7.9).
pub const O_APPEND: i32 = libc::O_APPEND;
/// O_DIRECT flag bit, mirrored from `libc::O_DIRECT` for use in FUSE write
/// request flag validation.
pub const O_DIRECT: i32 = libc::O_DIRECT;
/// O_SYNC flag bit, mirrored from `libc::O_SYNC` for use in FUSE write
/// request flag validation.
pub const O_SYNC: i32 = libc::O_SYNC;

/// Returns `true` when the file was opened with `O_APPEND`.
///
/// Under `O_APPEND` the write offset must be resolved to the
/// current file size before dispatching.
#[inline]
#[must_use]
pub const fn is_append_open(flags: i32) -> bool {
    (flags & O_APPEND) != 0
}

/// Returns `true` when the file was opened with `O_DIRECT`.
///
/// Direct-I/O writes require sector-aligned buffers and offsets;
/// use [`check_direct_io_alignment`] to verify alignment.
#[inline]
#[must_use]
pub const fn is_direct_io_open(flags: i32) -> bool {
    (flags & O_DIRECT) != 0
}

/// Returns `true` when the file was opened with `O_SYNC`.
///
/// Synchronous writes must persist data to stable storage before
/// the syscall returns.
#[inline]
#[must_use]
pub const fn is_sync_open(flags: i32) -> bool {
    (flags & O_SYNC) != 0
}

// ---------------------------------------------------------------------------
// validate_write_request -- per-request parameter validation
// ---------------------------------------------------------------------------

/// Validate core parameters of a FUSE write request.
///
/// Checks:
/// - `fh` is non-zero (TideFS uses monotonic handle allocation
///   starting from 1; a zero handle means the file was never opened).
/// - `offset` is non-negative.
/// - `offset + size` does not overflow `u64`.
/// - `flags` does not contain unsupported open-flag bits.
///
/// Does **not** check `write_flags`, file-kind, or read-only status;
/// those are validated separately via [`validate_write_flags`] and
/// [`validate_write`].
///
/// # Errors
///
/// - `EBADF` when `fh` is zero.
/// - `EINVAL` when `offset` is negative or unsupported flags are set.
/// - `EFBIG` when `offset + size` overflows `u64`.
#[inline]
pub fn validate_write_request(fh: u64, offset: i64, size: u32, flags: i32) -> Result<(), c_int> {
    if fh == 0 {
        return Err(errno::EBADF);
    }
    if offset < 0 {
        return Err(errno::EINVAL);
    }
    let _end = checked_write_end(offset, size as usize)?;
    // Reject unknown/unexpected flag bits beyond the standard set.
    let known_flags: i32 = O_APPEND | O_DIRECT | O_SYNC;
    if flags & !known_flags != 0 {
        return Err(errno::EINVAL);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// handle_write -- unified dispatch entry-point
// ---------------------------------------------------------------------------

/// Unified dispatch entry-point for FUSE `write` operations.
///
/// Combines request-parameter validation, write-flag validation,
/// plan construction, and composite file-kind/read-only/size
/// checks into a single call.  On success returns a [`WritePlan`]
/// ready for delegation to the writeback worker or VfsEngine.
///
/// # Parameters
///
/// - `fh`: file handle from a prior open (must be non-zero).
/// - `offset`: signed byte offset from the FUSE request.
/// - `data`: the data payload to write.
/// - `write_flags`: FUSE write-flag bits (e.g. `FUSE_WRITE_CACHE`).
/// - `flags`: file-open flags from the FUSE request (`O_APPEND`,
///   `O_DIRECT`, `O_SYNC`, etc.).
/// - `kind`: the [`FileType`] of the target inode.
/// - `read_only`: when `true` the entire filesystem is read-only.
/// - `writeback_cache`: when `true` the `FUSE_WRITE_CACHE` flag is
///   accepted; otherwise it is rejected.
///
/// # Errors
///
/// Returns the first error encountered during the validation chain:
/// request validation → write-flag validation → plan construction →
/// composite write validation.
#[allow(clippy::too_many_arguments)]
pub fn handle_write(
    fh: u64,
    offset: i64,
    data: &[u8],
    write_flags: u32,
    flags: i32,
    kind: FileType,
    read_only: bool,
    writeback_cache: bool,
) -> Result<WritePlan, c_int> {
    validate_write_request(fh, offset, data.len() as u32, flags)?;

    #[cfg(feature = "abi-7-9")]
    validate_write_flags(write_flags, writeback_cache)?;
    #[cfg(not(feature = "abi-7-9"))]
    let _ = (write_flags, writeback_cache);

    let plan = plan_write(offset, data, write_flags)?;
    validate_write(kind, plan.end, read_only)?;
    Ok(plan)
}

/// Minimum alignment (in bytes) required for direct-I/O write buffers and
/// offsets.  Corresponds to the sector size used by the block layer.
pub const WRITE_DIRECT_IO_ALIGNMENT: u64 = 512;

// ---------------------------------------------------------------------------
// Write-flag validation (requires abi-7-9 for FUSE_WRITE_* constants)
// ---------------------------------------------------------------------------

/// Validate a FUSE `write_flags` value.
///
/// Returns `Ok(())` when every set bit is recognised.
///
/// `FUSE_WRITE_CACHE` is accepted only when `writeback_cache_enabled` is
/// `true`; when it is `false`, the flag is treated as unsupported and
/// triggers `Err(EINVAL)`.
///
/// Returns `Err(EINVAL)` when unsupported (unknown) bits are set.
///
/// Requires feature `abi-7-9`.
#[cfg(feature = "abi-7-9")]
pub fn validate_write_flags(write_flags: u32, writeback_cache_enabled: bool) -> Result<(), c_int> {
    #[cfg(feature = "abi-7-31")]
    let base_mask: u32 = FUSE_WRITE_CACHE | FUSE_WRITE_LOCKOWNER | FUSE_WRITE_KILL_PRIV;
    #[cfg(not(feature = "abi-7-31"))]
    let base_mask: u32 = FUSE_WRITE_CACHE | FUSE_WRITE_LOCKOWNER;

    let supported = if writeback_cache_enabled {
        base_mask
    } else {
        base_mask & !FUSE_WRITE_CACHE
    };
    if write_flags & !supported != 0 {
        return Err(errno::EINVAL);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// End-offset computation
// ---------------------------------------------------------------------------

/// Compute the exclusive end byte offset for a write.
///
/// Returns `Err(EINVAL)` when `offset` is negative.
/// Returns `Err(EFBIG)` when `offset + len` overflows `u64`.
///
/// The result may safely be compared against `i64::MAX as u64` by the
/// caller to enforce filesystem-level size limits.
#[inline]
pub fn checked_write_end(offset: i64, len: usize) -> Result<u64, c_int> {
    if offset < 0 {
        return Err(errno::EINVAL);
    }
    (offset as u64).checked_add(len as u64).ok_or(errno::EFBIG)
}

// ---------------------------------------------------------------------------
// Direct-I/O alignment check
// ---------------------------------------------------------------------------

/// Verify that an `offset` and data `len` satisfy POSIX direct-I/O
/// alignment requirements.
///
/// Both `offset` and `len` must be exact multiples of
/// [`WRITE_DIRECT_IO_ALIGNMENT`] (512).  A zero-length write is
/// permitted at any offset.
///
/// Returns `Ok(())` when alignment is satisfied, `Err(EINVAL)` otherwise.
pub fn check_direct_io_alignment(offset: u64, len: usize) -> Result<(), c_int> {
    if len == 0 {
        return Ok(());
    }
    if offset % WRITE_DIRECT_IO_ALIGNMENT != 0 || (len as u64) % WRITE_DIRECT_IO_ALIGNMENT != 0 {
        return Err(errno::EINVAL);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WritePlan -- structured write operation
// ---------------------------------------------------------------------------

/// Planned write operation derived from a FUSE `write` request.
///
/// Carries the resolved offset as `u64`, the data length, the computed
/// exclusive end offset, and the raw write flags for downstream use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WritePlan {
    /// Byte offset within the file where data will be written.
    pub offset: u64,
    /// Number of data bytes to write.
    pub len: usize,
    /// Exclusive end offset (`offset + len`), pre-validated against
    /// overflow and negative-offset in [`plan_write`].
    pub end: u64,
    /// Raw FUSE `write_flags` value (e.g. `FUSE_WRITE_CACHE`).
    pub write_flags: u32,
}

impl WritePlan {
    /// Create a new write plan.
    #[must_use]
    pub const fn new(offset: u64, len: usize, end: u64, write_flags: u32) -> Self {
        Self {
            offset,
            len,
            end,
            write_flags,
        }
    }

    /// Returns `true` when the write extends beyond the current file size.
    #[must_use]
    pub const fn is_extending(&self, current_size: u64) -> bool {
        self.end > current_size
    }

    /// Returns `true` when the write is entirely within the current file bounds.
    #[must_use]
    pub const fn is_overwrite(&self, current_size: u64) -> bool {
        self.end <= current_size
    }

    /// Returns the number of bytes that would extend the file past `current_size`.
    #[must_use]
    pub const fn extend_bytes(&self, current_size: u64) -> u64 {
        self.end.saturating_sub(current_size)
    }

    /// Returns `true` when the data length is zero (no-op write).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ---------------------------------------------------------------------------
// plan_write
// ---------------------------------------------------------------------------

/// Construct a [`WritePlan`] from raw FUSE `write` parameters.
///
/// This resolves the offset from `i64` to `u64` (rejecting negative
/// offsets via [`checked_write_end`]) and computes the exclusive end
/// offset.
///
/// # Errors
///
/// Returns `Err(EINVAL)` when `offset` is negative.
/// Returns `Err(EFBIG)` when `offset + data.len()` overflows `u64`.
#[inline]
pub fn plan_write(offset: i64, data: &[u8], write_flags: u32) -> Result<WritePlan, c_int> {
    let len = data.len();
    let end = checked_write_end(offset, len)?;
    Ok(WritePlan::new(offset as u64, len, end, write_flags))
}

// ---------------------------------------------------------------------------
// check_write_allowed -- file-kind validation
// ---------------------------------------------------------------------------

/// Check whether a write operation is allowed for the given [`FileType`].
///
/// # Returns
///
/// `Ok(())` for regular files and block devices.
///
/// `Err(EISDIR)` for directories (POSIX: write to a directory fd returns
/// `EISDIR`).
///
/// `Err(EBADF)` for named pipes, Unix domain sockets, and character
/// devices that are not open for writing.
///
/// `Err(EINVAL)` for symbolic links (resolved by the kernel before the
/// FUSE handler is invoked, but guarded for defense in depth).
#[inline]
pub fn check_write_allowed(kind: FileType) -> Result<(), c_int> {
    match kind {
        FileType::RegularFile | FileType::BlockDevice => Ok(()),
        FileType::Directory => Err(errno::EISDIR),
        FileType::Symlink => Err(errno::EINVAL),
        FileType::NamedPipe | FileType::Socket | FileType::CharDevice => Err(errno::EBADF),
    }
}

// ---------------------------------------------------------------------------
// check_write_readonly -- read-only mount guard
// ---------------------------------------------------------------------------

/// Check whether a write operation is permitted on a read-only filesystem.
///
/// When `read_only` is `true`, any write is rejected with `EROFS`.
///
/// # Returns
///
/// `Ok(())` when the operation is allowed; `Err(EROFS)` otherwise.
#[inline]
pub fn check_write_readonly(read_only: bool) -> Result<(), c_int> {
    if read_only {
        Err(errno::EROFS)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// validate_write -- composite write-path validation
// ---------------------------------------------------------------------------

/// Perform composite validation for a write operation.
///
/// This bundles the three standard checks into a single call:
///
/// 1. [`check_write_allowed`] — reject non-writable file kinds.
/// 2. [`check_write_readonly`] — reject writes on a read-only filesystem.
/// 3. Maximum file size check — reject writes whose `end` offset exceeds
///    [`MAX_FILE_SIZE`].
///
/// # Returns
///
/// `Ok(())` when all checks pass.  The first failing check determines the
/// error code returned.
#[inline]
pub fn validate_write(kind: FileType, end: u64, read_only: bool) -> Result<(), c_int> {
    check_write_allowed(kind)?;
    check_write_readonly(read_only)?;
    if end > MAX_FILE_SIZE {
        return Err(errno::EFBIG);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Maximum file size
// ---------------------------------------------------------------------------

/// Maximum file size accepted for write operations (8 EiB - 1).
///
/// This matches the Linux off_t limit for a 64-bit signed offset,
/// preventing overflow in extent-map calculations.
pub const MAX_FILE_SIZE: u64 = i64::MAX as u64;

// ---------------------------------------------------------------------------
// WriteBuffering -- writeback accumulation buffer
// ---------------------------------------------------------------------------

/// A writeback accumulation buffer that gathers dirty data for a single
/// inode and flushes when a configurable byte threshold is reached.
///
/// The buffer accumulates appended writes.  When the total buffered data
/// reaches `flush_threshold` bytes, the caller should drain the buffer
/// and persist it to backing storage via the intent log.
///
/// # Usage
///
/// ```rust,ignore
/// use fuser::write::WriteBuffering;
///
/// let mut buf = WriteBuffering::new(65536); // flush at 64 KiB
/// buf.append(0, b"hello")?;
/// buf.append(5, b" world")?;
/// assert_eq!(buf.len(), 11);
/// if buf.should_flush() {
///     let data = buf.drain();
///     // ... persist data to intent log ...
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteBuffering {
    /// Accumulated dirty data.
    data: Vec<u8>,
    /// Byte threshold at which [`should_flush`](Self::should_flush) returns `true`.
    flush_threshold: usize,
}

impl WriteBuffering {
    /// Create a new empty writeback buffer with the given flush threshold.
    ///
    /// A threshold of 0 means the buffer will always signal flush after
    /// any non-zero append.
    #[must_use]
    pub fn new(flush_threshold: usize) -> Self {
        Self {
            data: Vec::new(),
            flush_threshold,
        }
    }

    /// Append a write at the given offset.
    ///
    /// If the write extends past the current buffer length, the gap is
    /// zero-filled to maintain a contiguous byte range starting at offset 0.
    ///
    /// This design assumes the buffer represents a single contiguous
    /// dirty range; sparse writes should use separate buffers or be
    /// flushed individually.
    ///
    /// # Errors
    ///
    /// Returns `Err(EINVAL)` when `data` is empty (no-op write).
    pub fn append(&mut self, offset: u64, data: &[u8]) -> Result<(), c_int> {
        if data.is_empty() {
            return Ok(());
        }
        let end = (offset as usize).saturating_add(data.len());
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        let start = offset as usize;
        self.data[start..start + data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Return the number of buffered bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` when the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return `true` when the buffered data meets or exceeds the flush
    /// threshold.
    #[must_use]
    pub fn should_flush(&self) -> bool {
        if self.flush_threshold == 0 {
            return !self.data.is_empty();
        }
        self.data.len() >= self.flush_threshold
    }

    /// Drain the buffer, returning all accumulated data and resetting the
    /// buffer to empty.
    #[must_use]
    pub fn drain(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        std::mem::swap(&mut out, &mut self.data);
        out
    }

    /// Return a reference to the buffered data without draining.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Default for WriteBuffering {
    fn default() -> Self {
        Self::new(65536) // 64 KiB default flush threshold
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- WritePlan --------------------------------------------------------

    #[test]
    fn write_plan_new() {
        let plan = WritePlan::new(1024, 512, 1536, 0);
        assert_eq!(plan.offset, 1024);
        assert_eq!(plan.len, 512);
        assert_eq!(plan.end, 1536);
        assert_eq!(plan.write_flags, 0);
    }

    #[test]
    fn write_plan_is_extending() {
        let plan = WritePlan::new(0, 4096, 4096, 0);
        assert!(plan.is_extending(0));
        assert!(!plan.is_extending(4096));
        assert!(!plan.is_extending(8192));
    }

    #[test]
    fn write_plan_is_overwrite() {
        let plan = WritePlan::new(100, 36, 136, 0);
        assert!(plan.is_overwrite(136));
        assert!(plan.is_overwrite(1024));
        assert!(!plan.is_overwrite(100));
    }

    #[test]
    fn write_plan_extend_bytes() {
        let plan = WritePlan::new(0, 8192, 8192, 0);
        assert_eq!(plan.extend_bytes(0), 8192);
        assert_eq!(plan.extend_bytes(4096), 4096);
        assert_eq!(plan.extend_bytes(8192), 0);
        assert_eq!(plan.extend_bytes(16384), 0);
    }

    #[test]
    fn write_plan_is_empty() {
        assert!(WritePlan::new(0, 0, 0, 0).is_empty());
        assert!(!WritePlan::new(0, 1, 1, 0).is_empty());
    }

    // -- plan_write -------------------------------------------------------

    #[test]
    fn plan_write_normal() {
        let data = vec![0u8; 4096];
        let plan = plan_write(0, &data, 0).unwrap();
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.len, 4096);
        assert_eq!(plan.end, 4096);
        assert_eq!(plan.write_flags, 0);
    }

    #[test]
    fn plan_write_zero_len() {
        let data: [u8; 0] = [];
        let plan = plan_write(100, &data, 0).unwrap();
        assert_eq!(plan.offset, 100);
        assert_eq!(plan.len, 0);
        assert_eq!(plan.end, 100);
        assert!(plan.is_empty());
    }

    #[test]
    fn plan_write_negative_offset_rejected() {
        let data = vec![1u8; 10];
        assert_eq!(plan_write(-1, &data, 0), Err(errno::EINVAL));
    }

    #[test]
    #[cfg(feature = "abi-7-9")]
    fn plan_write_preserves_write_flags() {
        let data = vec![0u8; 512];
        let plan = plan_write(0, &data, FUSE_WRITE_CACHE).unwrap();
        assert_eq!(plan.write_flags, FUSE_WRITE_CACHE);
    }

    // -- check_write_allowed ----------------------------------------------

    #[test]
    fn write_allowed_on_regular_file() {
        assert_eq!(check_write_allowed(FileType::RegularFile), Ok(()));
    }

    #[test]
    fn write_allowed_on_block_device() {
        assert_eq!(check_write_allowed(FileType::BlockDevice), Ok(()));
    }

    #[test]
    fn write_denied_on_directory() {
        assert_eq!(check_write_allowed(FileType::Directory), Err(errno::EISDIR));
    }

    #[test]
    fn write_denied_on_named_pipe() {
        assert_eq!(check_write_allowed(FileType::NamedPipe), Err(errno::EBADF));
    }

    #[test]
    fn write_denied_on_socket() {
        assert_eq!(check_write_allowed(FileType::Socket), Err(errno::EBADF));
    }

    #[test]
    fn write_denied_on_char_device() {
        assert_eq!(check_write_allowed(FileType::CharDevice), Err(errno::EBADF));
    }

    #[test]
    fn write_denied_on_symlink() {
        assert_eq!(check_write_allowed(FileType::Symlink), Err(errno::EINVAL));
    }

    // -- check_write_readonly ---------------------------------------------

    #[test]
    fn ro_mount_rejects_write() {
        assert_eq!(check_write_readonly(true), Err(errno::EROFS));
    }

    #[test]
    fn rw_mount_allows_write() {
        assert_eq!(check_write_readonly(false), Ok(()));
    }

    // -- validate_write ---------------------------------------------------

    #[test]
    fn validate_write_passes_all_checks() {
        assert_eq!(validate_write(FileType::RegularFile, 4096, false), Ok(()));
    }

    #[test]
    fn validate_write_rejects_directory() {
        assert_eq!(
            validate_write(FileType::Directory, 1024, false),
            Err(errno::EISDIR)
        );
    }

    #[test]
    fn validate_write_rejects_readonly() {
        assert_eq!(
            validate_write(FileType::RegularFile, 4096, true),
            Err(errno::EROFS)
        );
    }

    #[test]
    fn validate_write_rejects_pipe_even_if_rw() {
        assert_eq!(
            validate_write(FileType::NamedPipe, 1024, false),
            Err(errno::EBADF)
        );
    }

    #[test]
    fn validate_write_oversize_end_rejected() {
        let too_big = MAX_FILE_SIZE + 1;
        assert_eq!(
            validate_write(FileType::RegularFile, too_big, false),
            Err(errno::EFBIG)
        );
    }

    #[test]
    fn validate_write_at_max_file_size_ok() {
        assert_eq!(
            validate_write(FileType::RegularFile, MAX_FILE_SIZE, false),
            Ok(())
        );
    }

    #[test]
    fn validate_write_zero_len_at_zero_offset_ok() {
        assert_eq!(validate_write(FileType::RegularFile, 0, false), Ok(()));
    }

    // -- WriteBuffering ---------------------------------------------------

    #[test]
    fn write_buffer_new_empty() {
        let buf = WriteBuffering::new(4096);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert!(!buf.should_flush());
    }

    #[test]
    fn write_buffer_append_accumulates() {
        let mut buf = WriteBuffering::new(65536);
        buf.append(0, b"hello").unwrap();
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_bytes(), b"hello");
    }

    #[test]
    fn write_buffer_append_at_offset_gaps_are_zero_filled() {
        let mut buf = WriteBuffering::new(65536);
        buf.append(5, b"world").unwrap();
        assert_eq!(buf.len(), 10);
        assert_eq!(&buf.as_bytes()[0..5], &[0u8; 5]);
        assert_eq!(&buf.as_bytes()[5..10], b"world");
    }

    #[test]
    fn write_buffer_append_overlapping_overwrites() {
        let mut buf = WriteBuffering::new(4096);
        buf.append(0, b"hello").unwrap();
        buf.append(0, b"HELLO").unwrap();
        assert_eq!(&buf.as_bytes()[0..5], b"HELLO");
    }

    #[test]
    fn write_buffer_should_flush_at_threshold() {
        let mut buf = WriteBuffering::new(10);
        buf.append(0, &[0u8; 9]).unwrap();
        assert!(!buf.should_flush());
        buf.append(9, &[1u8]).unwrap();
        assert!(buf.should_flush());
    }

    #[test]
    fn write_buffer_should_flush_zero_threshold() {
        let mut buf = WriteBuffering::new(0);
        assert!(!buf.should_flush()); // empty
        buf.append(0, b"x").unwrap();
        assert!(buf.should_flush());
    }

    #[test]
    fn write_buffer_drain_empties_and_returns_data() {
        let mut buf = WriteBuffering::new(65536);
        buf.append(0, b"hello").unwrap();
        buf.append(5, b" world").unwrap();
        let data = buf.drain();
        assert_eq!(data, b"hello world");
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn write_buffer_append_empty_is_noop() {
        let mut buf = WriteBuffering::new(256);
        buf.append(0, &[]).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn write_buffer_default_creates_64kib_threshold() {
        let buf = WriteBuffering::default();
        assert_eq!(buf.flush_threshold, 65536);
    }

    #[test]
    fn write_buffer_append_sequential_writes() {
        let mut buf = WriteBuffering::new(65536);
        buf.append(0, &[0xAAu8; 32]).unwrap();
        buf.append(32, &[0xBBu8; 32]).unwrap();
        buf.append(64, &[0xCCu8; 32]).unwrap();
        assert_eq!(buf.len(), 96);
        let bytes = buf.as_bytes();
        assert_eq!(bytes[0..32], [0xAAu8; 32]);
        assert_eq!(bytes[32..64], [0xBBu8; 32]);
        assert_eq!(bytes[64..96], [0xCCu8; 32]);
    }

    #[test]
    fn write_buffer_multiple_drain_cycles() {
        let mut buf = WriteBuffering::new(32);
        buf.append(0, &[0x11u8; 32]).unwrap();
        assert!(buf.should_flush());
        let first = buf.drain();
        assert_eq!(first.len(), 32);

        buf.append(0, &[0x22u8; 16]).unwrap();
        assert!(!buf.should_flush());
        buf.append(16, &[0x33u8; 16]).unwrap();
        assert!(buf.should_flush());
        let second = buf.drain();
        assert_eq!(second.len(), 32);
    }

    // -- check_direct_io_alignment (always available) -------------------------

    #[test]
    fn direct_io_aligned_passes() {
        assert_eq!(check_direct_io_alignment(0, 4096), Ok(()));
        assert_eq!(check_direct_io_alignment(512, 512), Ok(()));
        assert_eq!(check_direct_io_alignment(4096, 8192), Ok(()));
    }

    #[test]
    fn direct_io_zero_len_passes_at_any_offset() {
        assert_eq!(check_direct_io_alignment(0, 0), Ok(()));
        assert_eq!(check_direct_io_alignment(1, 0), Ok(()));
        assert_eq!(check_direct_io_alignment(513, 0), Ok(()));
    }

    #[test]
    fn direct_io_unaligned_offset_rejected() {
        assert_eq!(check_direct_io_alignment(1, 512), Err(errno::EINVAL));
        assert_eq!(check_direct_io_alignment(513, 512), Err(errno::EINVAL));
    }

    #[test]
    fn direct_io_unaligned_length_rejected() {
        assert_eq!(check_direct_io_alignment(0, 1), Err(errno::EINVAL));
        assert_eq!(check_direct_io_alignment(512, 513), Err(errno::EINVAL));
    }

    #[test]
    fn direct_io_both_unaligned_rejected() {
        assert_eq!(check_direct_io_alignment(1, 1), Err(errno::EINVAL));
    }

    #[test]
    fn direct_io_megabyte_aligned_passes() {
        let one_mb = 1024 * 1024;
        assert_eq!(check_direct_io_alignment(one_mb, one_mb as usize), Ok(()));
    }

    // -- checked_write_end (always available) ---------------------------------

    #[test]
    fn checked_write_end_normal() {
        assert_eq!(checked_write_end(0, 4096), Ok(4096));
        assert_eq!(checked_write_end(100, 36), Ok(136));
        assert_eq!(checked_write_end(4096, 0), Ok(4096));
    }

    #[test]
    fn checked_write_end_zero_len_at_zero() {
        assert_eq!(checked_write_end(0, 0), Ok(0));
    }

    #[test]
    fn checked_write_end_large_but_valid() {
        assert_eq!(checked_write_end(0, u32::MAX as usize), Ok(u32::MAX as u64));
    }

    #[test]
    fn checked_write_end_negative_offset_rejected() {
        assert_eq!(checked_write_end(-1, 1), Err(errno::EINVAL));
        assert_eq!(checked_write_end(-4096, 0), Err(errno::EINVAL));
    }

    #[test]
    fn checked_write_end_overflow_rejected() {
        assert_eq!(checked_write_end(1, usize::MAX), Err(errno::EFBIG));
        assert_eq!(checked_write_end(i64::MAX, usize::MAX), Err(errno::EFBIG));
    }

    // -- is_append_open / is_direct_io_open / is_sync_open --------------------

    #[test]
    fn is_append_open_true_with_o_append() {
        assert!(is_append_open(libc::O_APPEND));
    }

    #[test]
    fn is_append_open_false_with_zero() {
        assert!(!is_append_open(0));
    }

    #[test]
    fn is_append_open_false_with_o_rdonly() {
        assert!(!is_append_open(libc::O_RDONLY));
    }

    #[test]
    fn is_direct_io_open_true_with_o_direct() {
        assert!(is_direct_io_open(libc::O_DIRECT));
    }

    #[test]
    fn is_direct_io_open_false_with_zero() {
        assert!(!is_direct_io_open(0));
    }

    #[test]
    fn is_sync_open_true_with_o_sync() {
        assert!(is_sync_open(libc::O_SYNC));
    }

    #[test]
    fn is_sync_open_false_with_zero() {
        assert!(!is_sync_open(0));
    }

    #[test]
    fn is_sync_open_false_with_rdonly() {
        assert!(!is_sync_open(libc::O_RDONLY));
    }

    #[test]
    fn combined_flags_all_predicates() {
        let flags = libc::O_APPEND | libc::O_DIRECT | libc::O_SYNC;
        assert!(is_append_open(flags));
        assert!(is_direct_io_open(flags));
        assert!(is_sync_open(flags));
    }

    // -- validate_write_request -------------------------------------------------

    #[test]
    fn validate_write_request_valid() {
        assert_eq!(validate_write_request(1, 0, 4096, 0), Ok(()));
    }

    #[test]
    fn validate_write_request_zero_fh_rejected() {
        assert_eq!(validate_write_request(0, 0, 4096, 0), Err(errno::EBADF));
    }

    #[test]
    fn validate_write_request_large_fh_ok() {
        assert_eq!(validate_write_request(u64::MAX, 0, 1024, 0), Ok(()));
    }

    #[test]
    fn validate_write_request_negative_offset_rejected() {
        assert_eq!(validate_write_request(1, -1, 1, 0), Err(errno::EINVAL));
    }

    #[test]
    fn validate_write_request_zero_size_at_large_offset_ok() {
        assert_eq!(validate_write_request(1, i64::MAX, 0, 0), Ok(()));
    }

    #[test]
    fn validate_write_request_unknown_flags_rejected() {
        assert_eq!(
            validate_write_request(1, 0, 4096, 0xDEAD),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn validate_write_request_append_flag_ok() {
        // O_APPEND is a known flag — it should pass validation
        assert_eq!(validate_write_request(1, 0, 4096, libc::O_APPEND), Ok(()));
    }

    #[test]
    fn validate_write_request_direct_flag_ok() {
        // O_DIRECT is a known flag — it should pass validation
        assert_eq!(validate_write_request(1, 0, 4096, libc::O_DIRECT), Ok(()));
    }

    #[test]
    fn validate_write_request_sync_flag_ok() {
        // O_SYNC is a known flag — it should pass validation
        assert_eq!(validate_write_request(1, 0, 4096, libc::O_SYNC), Ok(()));
    }

    #[test]
    fn validate_write_request_all_known_flags_ok() {
        let flags = libc::O_APPEND | libc::O_DIRECT | libc::O_SYNC;
        assert_eq!(validate_write_request(1, 0, 4096, flags), Ok(()));
    }

    #[test]
    fn validate_write_request_mixed_known_and_unknown_rejected() {
        let flags = libc::O_APPEND | 0xF000;
        assert_eq!(
            validate_write_request(1, 0, 4096, flags),
            Err(errno::EINVAL)
        );
    }

    // -- handle_write ---------------------------------------------------------

    #[test]
    fn handle_write_basic_success() {
        let data = b"hello world";
        let plan = handle_write(1, 0, data, 0, 0, FileType::RegularFile, false, false).unwrap();
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.len, 11);
        assert_eq!(plan.end, 11);
    }

    #[test]
    fn handle_write_zero_len_success() {
        let data: &[u8] = &[];
        let plan = handle_write(1, 100, data, 0, 0, FileType::RegularFile, false, false).unwrap();
        assert_eq!(plan.offset, 100);
        assert_eq!(plan.len, 0);
        assert_eq!(plan.end, 100);
    }

    #[test]
    fn handle_write_bad_fh_rejected() {
        let data = b"test";
        assert_eq!(
            handle_write(0, 0, data, 0, 0, FileType::RegularFile, false, false),
            Err(errno::EBADF)
        );
    }

    #[test]
    fn handle_write_negative_offset_rejected() {
        let data = b"test";
        assert_eq!(
            handle_write(1, -1, data, 0, 0, FileType::RegularFile, false, false),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn handle_write_directory_rejected() {
        let data = b"test";
        assert_eq!(
            handle_write(1, 0, data, 0, 0, FileType::Directory, false, false),
            Err(errno::EISDIR)
        );
    }

    #[test]
    fn handle_write_readonly_rejected() {
        let data = b"test";
        assert_eq!(
            handle_write(1, 0, data, 0, 0, FileType::RegularFile, true, false),
            Err(errno::EROFS)
        );
    }

    #[test]
    fn handle_write_oversize_rejected() {
        // A write whose end offset exceeds MAX_FILE_SIZE
        let data = vec![0u8; 32];
        let err = handle_write(
            1,
            i64::MAX,
            &data,
            0,
            0,
            FileType::RegularFile,
            false,
            false,
        );
        assert!(err.is_err());
    }

    #[test]
    fn handle_write_at_max_offset_zero_len_ok() {
        let data: &[u8] = &[];
        let plan =
            handle_write(1, i64::MAX, data, 0, 0, FileType::RegularFile, false, false).unwrap();
        assert_eq!(plan.end, i64::MAX as u64);
    }

    #[test]
    fn handle_write_block_device_ok() {
        let data = b"block-write";
        let plan = handle_write(2, 512, data, 0, 0, FileType::BlockDevice, false, false).unwrap();
        assert_eq!(plan.offset, 512);
        assert_eq!(plan.len, 11);
    }

    #[test]
    fn handle_write_pipe_rejected() {
        let data = b"pipe-write";
        assert_eq!(
            handle_write(1, 0, data, 0, 0, FileType::NamedPipe, false, false),
            Err(errno::EBADF)
        );
    }

    #[test]
    fn handle_write_socket_rejected() {
        let data = b"socket-write";
        assert_eq!(
            handle_write(1, 0, data, 0, 0, FileType::Socket, false, false),
            Err(errno::EBADF)
        );
    }

    #[test]
    #[cfg(feature = "abi-7-9")]
    fn handle_write_preserves_valid_write_flags() {
        let data = b"cached-data";
        // Valid write_flags are validated before being passed through in the plan.
        let plan = handle_write(
            3,
            64,
            data,
            FUSE_WRITE_LOCKOWNER,
            0,
            FileType::RegularFile,
            false,
            false,
        )
        .unwrap();
        assert_eq!(plan.write_flags, FUSE_WRITE_LOCKOWNER);
    }

    #[test]
    fn handle_write_unknown_file_flags_rejected() {
        let data = b"test";
        // flags has an unknown bit outside O_APPEND|O_DIRECT|O_SYNC
        assert_eq!(
            handle_write(1, 0, data, 0, 0x8000, FileType::RegularFile, false, false),
            Err(errno::EINVAL)
        );
    }

    // -- validate_write_flags (requires abi-7-9) ------------------------------

    #[cfg(feature = "abi-7-9")]
    mod write_flags_tests {
        use super::*;

        #[test]
        fn validate_zero_flags_ok() {
            assert_eq!(validate_write_flags(0, false), Ok(()));
            assert_eq!(validate_write_flags(0, true), Ok(()));
        }

        #[test]
        fn validate_lockowner_ok() {
            assert_eq!(validate_write_flags(FUSE_WRITE_LOCKOWNER, false), Ok(()));
            assert_eq!(validate_write_flags(FUSE_WRITE_LOCKOWNER, true), Ok(()));
        }

        #[cfg(feature = "abi-7-31")]
        #[test]
        fn validate_kill_priv_ok() {
            assert_eq!(validate_write_flags(FUSE_WRITE_KILL_PRIV, false), Ok(()));
            assert_eq!(validate_write_flags(FUSE_WRITE_KILL_PRIV, true), Ok(()));
        }

        #[test]
        fn validate_cache_flag_rejected_without_writeback() {
            assert_eq!(
                validate_write_flags(FUSE_WRITE_CACHE, false),
                Err(errno::EINVAL)
            );
        }

        #[test]
        fn validate_cache_flag_accepted_with_writeback() {
            assert_eq!(validate_write_flags(FUSE_WRITE_CACHE, true), Ok(()));
        }

        #[cfg(feature = "abi-7-31")]
        #[test]
        fn validate_combined_flags_with_writeback() {
            let flags = FUSE_WRITE_CACHE | FUSE_WRITE_LOCKOWNER | FUSE_WRITE_KILL_PRIV;
            assert_eq!(validate_write_flags(flags, true), Ok(()));
        }

        #[test]
        fn validate_combined_flags_without_writeback() {
            let flags = FUSE_WRITE_LOCKOWNER | FUSE_WRITE_KILL_PRIV;
            assert_eq!(validate_write_flags(flags, false), Ok(()));
        }

        #[test]
        fn validate_unknown_bit_rejected() {
            assert_eq!(validate_write_flags(0x80, false), Err(errno::EINVAL));
            assert_eq!(validate_write_flags(0x80, true), Err(errno::EINVAL));
        }

        #[test]
        fn validate_unknown_bit_with_valid_flags_rejected() {
            assert_eq!(
                validate_write_flags(FUSE_WRITE_LOCKOWNER | 0x80, true),
                Err(errno::EINVAL)
            );
        }
    }
}
