//! FUSE `read` handler helpers -- offset validation, size clamping,
//! direct-I/O alignment, and error translation for the POSIX read(2)
//! data path.
//!
//! Provides:
//! - [`ReadPlan`]: structured plan for a read operation.
//! - [`plan_read`]: construct a [`ReadPlan`] from FUSE parameters with
//!   offset validation and size clamping.
//! - [`validate_read_request`]: validate core FUSE read request parameters
//!   (file handle, offset, size, flags, file-size bounds).
//! - [`handle_read`]: unified dispatch entry-point combining request
//!   validation and plan construction.
//! - [`validate_read_offset`]: reject negative offsets.
//! - [`clamp_read_size`]: clamp the requested read size to
//!   [`MAX_READ_SIZE`].
//! - [`check_direct_io_alignment`]: verify offset and buffer length
//!   satisfy O_DIRECT sector alignment.
//! - [`ReadError`]: error type mapping TideFS object-I/O failures to
//!   POSIX errno values suitable for FUSE reply.
//! - [`fuse_read`]: convenience entry point that executes a read
//!   through [`tidefs_object_io::ObjectReader`], maps errors, and
//!   assembles the response.
//! - [`check_read_permission`]: verify caller read access on a target
//!   inode via [`crate::access::check_fuse_access`].
//! - Re-exported POSIX errno codes relevant to the read path.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::read;
//!
//! let plan = read::plan_read(ino, fh, offset, size)?;
//! let mut buf = vec![0u8; plan.size];
//! let n = read::fuse_read(&plan, extent_map, store, reader, &mut buf, file_size)?;
//! reply.data(&buf[..n]);
//! ```

use libc::{c_int, O_APPEND, O_DIRECT, O_SYNC};
use std::fmt;

// Re-export standard errno codes for read error paths.
pub use libc::{EBADF, EINVAL, EIO};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum read size for a single FUSE read request (16 MiB).
/// Matches the session-level [`crate::session::MAX_WRITE_SIZE`] since
/// FUSE typically uses the same buffer size for reads and writes.
pub const MAX_READ_SIZE: usize = 16 * 1024 * 1024;

/// Minimum sector alignment required for `O_DIRECT` / `FOPEN_DIRECT_IO`
/// read operations.  POSIX mandates that direct-I/O buffers and file
/// offsets be multiples of the logical block size, which is at least
/// 512 bytes.
pub const READ_DIRECT_IO_ALIGNMENT: u64 = 512;

// ---------------------------------------------------------------------------
// ReadPlan -- structured read request
// ---------------------------------------------------------------------------

/// Check that the caller has read permission on the target inode.
///
/// Wraps [`crate::access::check_fuse_access`] requesting
/// [`crate::access::ACCESS_READ`].
pub fn check_read_permission(
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    mount_identity: &tidefs_permission::MountIdentity,
) -> Result<(), ReadError> {
    crate::access::check_fuse_access(
        mode,
        file_uid,
        file_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        crate::access::ACCESS_READ,
        mount_identity,
    )
    .map_err(|_e| ReadError::PermissionDenied)
}

/// Planned read operation derived from a FUSE `read` request.
///
/// The plan captures the validated inode, file handle, logical offset,
/// and clamped byte count before the data path is entered.
/// Callers should validate permissions and file-handle validity before
/// constructing a [`ReadPlan`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadPlan {
    /// Inode number.
    pub ino: u64,
    /// File handle (opaque value set by `open`).
    pub fh: u64,
    /// Logical byte offset within the file.
    pub offset: u64,
    /// Number of bytes requested (clamped to [`MAX_READ_SIZE`]).
    pub size: usize,
}

impl ReadPlan {
    /// Create a new read plan with explicit fields.
    #[must_use]
    pub const fn new(ino: u64, fh: u64, offset: u64, size: usize) -> Self {
        Self {
            ino,
            fh,
            offset,
            size,
        }
    }

    /// Returns `true` when the requested size is zero (empty read).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that a read offset is non-negative.
///
/// Returns `Err(EINVAL)` when `offset` is negative.
#[inline]
pub fn validate_read_offset(offset: i64) -> Result<u64, c_int> {
    if offset < 0 {
        return Err(libc::EINVAL);
    }
    Ok(offset as u64)
}

/// Clamp a requested read `size` to [`MAX_READ_SIZE`].
///
/// Returns the clamped size. A zero size is preserved as zero.
#[inline]
#[must_use]
pub fn clamp_read_size(size: u32) -> usize {
    let s = size as usize;
    if s == 0 {
        0
    } else {
        s.min(MAX_READ_SIZE)
    }
}

/// Verify that an `offset` and buffer `len` satisfy POSIX direct-I/O
/// alignment requirements.
///
/// Both `offset` and `len` must be exact multiples of
/// [`READ_DIRECT_IO_ALIGNMENT`] (512).  A zero-length read is permitted
/// at any offset.
///
/// Returns `Ok(())` when alignment is satisfied, `Err(EINVAL)` otherwise.
pub fn check_direct_io_alignment(offset: u64, len: usize) -> Result<(), c_int> {
    if len == 0 {
        return Ok(());
    }
    if offset % READ_DIRECT_IO_ALIGNMENT != 0 || (len as u64) % READ_DIRECT_IO_ALIGNMENT != 0 {
        return Err(libc::EINVAL);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// validate_read_request -- per-request parameter validation
// ---------------------------------------------------------------------------

/// Validate core parameters of a FUSE read request.
///
/// Checks:
/// - `fh` is non-zero (TideFS uses monotonic handle allocation
///   starting from 1; a zero handle means the file was never opened).
/// - `offset` is non-negative and within the current file size
///   (at-EOF is handled at data-dispatch time; past-EOF is rejected
///   with EINVAL).
/// - `size` is non-zero (size clamping to [`MAX_READ_SIZE`] is
///   handled by [`plan_read`]).
/// - `flags` does not contain unsupported open-flag bits.
///
/// # Errors
///
/// - `EBADF` when `fh` is zero.
/// - `EINVAL` when `offset` is negative, `offset > file_size`,
///   `size` is zero, or unsupported flags are set.
#[inline]
pub fn validate_read_request(
    fh: u64,
    offset: i64,
    size: u32,
    flags: i32,
    file_size: u64,
) -> Result<(), c_int> {
    if fh == 0 {
        return Err(EBADF);
    }
    if offset < 0 {
        return Err(EINVAL);
    }
    let off = offset as u64;
    if off > file_size {
        return Err(EINVAL);
    }
    if size == 0 {
        return Err(EINVAL);
    }
    let known_flags: i32 = O_APPEND | O_DIRECT | O_SYNC;
    if flags & !known_flags != 0 {
        return Err(EINVAL);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// plan_read -- construct a ReadPlan from FUSE parameters
// ---------------------------------------------------------------------------

/// Construct a [`ReadPlan`] from the raw FUSE `read` parameters.
///
/// Validates the offset and clamps the size. Returns `Err(EINVAL)` for
/// negative offsets.
///
/// # Arguments
///
/// * `ino` - Inode number.
/// * `fh` - File handle.
/// * `offset` - Signed byte offset (may be negative for error).
/// * `size` - Requested number of bytes (u32 from FUSE protocol).
pub fn plan_read(ino: u64, fh: u64, offset: i64, size: u32) -> Result<ReadPlan, c_int> {
    let abs_offset = validate_read_offset(offset)?;
    let clamped = clamp_read_size(size);
    Ok(ReadPlan::new(ino, fh, abs_offset, clamped))
}

// ---------------------------------------------------------------------------
// handle_read -- unified dispatch entry-point
// ---------------------------------------------------------------------------

/// Unified dispatch entry-point for FUSE `read` operations.
///
/// Combines request-parameter validation and plan construction into a
/// single call.  On success returns a [`ReadPlan`] ready for delegation
/// to the data path ([fuse_read]) or the adapter dispatch layer.
///
/// # Parameters
///
/// - `ino`: inode number.
/// - `fh`: file handle from a prior open (must be non-zero).
/// - `offset`: signed byte offset from the FUSE request.
/// - `size`: requested number of bytes (u32 from FUSE protocol).
/// - `flags`: file-open flags from the FUSE request (`O_APPEND`,
///   `O_DIRECT`, `O_SYNC`, etc.).
/// - `file_size`: current logical file size; used to reject
///   past-EOF reads.
///
/// # Errors
///
/// Returns the first error encountered during the validation chain:
/// request validation -> plan construction.
pub fn handle_read(
    ino: u64,
    fh: u64,
    offset: i64,
    size: u32,
    flags: i32,
    file_size: u64,
) -> Result<ReadPlan, c_int> {
    validate_read_request(fh, offset, size, flags, file_size)?;
    let plan = plan_read(ino, fh, offset, size)?;
    Ok(plan)
}

// ---------------------------------------------------------------------------
// ReadError -- error type for read operations
// ---------------------------------------------------------------------------

/// Errors produced by the FUSE read path.
///
/// Maps TideFS object-I/O errors and validation failures to POSIX errno
/// values suitable for FUSE `reply.error()`.
#[derive(Debug)]
pub enum ReadError {
    /// The requested byte range was invalid (negative offset, overflow).
    InvalidRange,
    /// The read encountered an I/O error in the object store.
    IoError(String),
    /// A data extent referenced a missing object (integrity failure).
    MissingObject,
    /// A data extent failed durable receipt/header validation.
    CorruptExtent(String),
    /// The read range lies entirely in a hole past EOF.
    HoleBeyondEof,
    /// An internal error occurred (should map to EIO).
    Internal(String),
    /// Caller lacks read permission on the target inode.
    PermissionDenied,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRange => f.write_str("invalid byte range for read"),
            Self::IoError(msg) => write!(f, "object store I/O error: {msg}"),
            Self::MissingObject => f.write_str("extent references missing object"),
            Self::CorruptExtent(msg) => write!(f, "corrupt extent: {msg}"),
            Self::HoleBeyondEof => f.write_str("read entirely in hole past EOF"),
            Self::Internal(msg) => write!(f, "internal read error: {msg}"),
            Self::PermissionDenied => write!(f, "permission denied for read"),
        }
    }
}

impl std::error::Error for ReadError {}

impl ReadError {
    /// Convert this error to a POSIX errno suitable for FUSE reply.
    #[must_use]
    pub fn to_errno(&self) -> c_int {
        match self {
            Self::InvalidRange => libc::EINVAL,
            Self::IoError(_) => libc::EIO,
            Self::MissingObject => libc::EIO,
            Self::CorruptExtent(_) => libc::EIO,
            Self::HoleBeyondEof => libc::EINVAL,
            Self::Internal(_) => libc::EIO,
            Self::PermissionDenied => libc::EACCES,
        }
    }
}

impl From<tidefs_object_io::ObjectIoError> for ReadError {
    fn from(err: tidefs_object_io::ObjectIoError) -> Self {
        match err {
            tidefs_object_io::ObjectIoError::InvalidRange => Self::InvalidRange,
            tidefs_object_io::ObjectIoError::StoreError(e) => Self::IoError(e.to_string()),
            tidefs_object_io::ObjectIoError::ExtentError(e) => Self::Internal(e.to_string()),
            tidefs_object_io::ObjectIoError::InvalidChunkSize => {
                Self::Internal("invalid chunk size".into())
            }
            tidefs_object_io::ObjectIoError::MissingObject(_) => Self::MissingObject,
            tidefs_object_io::ObjectIoError::TransformMismatch {
                field,
                expected,
                observed,
            } => Self::CorruptExtent(format!(
                "transform mismatch: {field} expected {expected}, observed {observed}"
            )),
            tidefs_object_io::ObjectIoError::HoleBeyondEof => Self::HoleBeyondEof,
        }
    }
}

impl From<ReadError> for c_int {
    fn from(err: ReadError) -> Self {
        err.to_errno()
    }
}

impl From<&ReadError> for c_int {
    fn from(err: &ReadError) -> Self {
        err.to_errno()
    }
}

// ---------------------------------------------------------------------------
// fuse_read -- execute a read through ObjectReader
// ---------------------------------------------------------------------------
/// Execute a read through [`tidefs_object_io::ObjectReader`] and return
/// the number of bytes read.
///
/// `file_size` is the logical file size; reads starting at or beyond it
/// return zero bytes. Reads that cross EOF are short-read (the returned
/// count is clamped to the remaining file bytes).
///
/// The provided `buf` *must* be at least [`plan.size`](ReadPlan::size)
/// bytes long. The buffer is zeroed before the read and the returned
/// byte count may be less than the requested size when reading past EOF.
///
/// # Errors
///
/// Returns [`ReadError`] on I/O failures, checksum mismatches, or
/// missing objects.
pub fn fuse_read<M, S>(
    plan: &ReadPlan,
    extent_map: &M,
    store: &S,
    reader: &tidefs_object_io::ObjectReader,
    buf: &mut [u8],
    file_size: u64,
) -> Result<usize, ReadError>
where
    M: tidefs_object_io::ExtentMapOps,
    S: tidefs_object_io::ObjectStore,
{
    // Zero the output region so the reply buffer is always initialized.
    buf[..plan.size].fill(0);

    if plan.is_empty() {
        return Ok(0);
    }

    // Offset past EOF: POSIX read returns 0.
    if plan.offset >= file_size {
        return Ok(0);
    }

    // Clamp to remaining file bytes.
    let remaining = (file_size - plan.offset) as usize;
    let readable = plan.size.min(remaining);
    if readable == 0 {
        return Ok(0);
    }

    reader
        .read(extent_map, store, plan.offset, &mut buf[..readable])
        .map_err(ReadError::from)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_MOUNT: tidefs_permission::MountIdentity =
        tidefs_permission::MountIdentity::new([0x41; 16], 1);
    use std::collections::HashMap;
    use std::convert::TryInto;
    use tidefs_object_io::{
        ExtentMapEntryV2, ExtentMapError, FreedExtent, LocatorId, ObjectKey, ObjectStore,
    };
    use tidefs_types_extent_map_core::FiemapExtent;

    // -----------------------------------------------------------------------
    // In-memory test store and extent map
    // -----------------------------------------------------------------------

    #[derive(Debug, Default)]
    struct MemStore {
        objects: HashMap<ObjectKey, Vec<u8>>,
    }

    impl ObjectStore for MemStore {
        type Error = std::convert::Infallible;

        fn put(&mut self, key: ObjectKey, data: &[u8]) -> std::result::Result<(), Self::Error> {
            self.objects.insert(key, data.to_vec());
            Ok(())
        }

        fn get(&self, key: &ObjectKey) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.objects.get(key).cloned())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct StaticExtentMap {
        entries: Vec<ExtentMapEntryV2>,
    }

    impl tidefs_object_io::ExtentMapOps for StaticExtentMap {
        fn lookup_range(
            &self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<ExtentMapEntryV2>, ExtentMapError> {
            Ok(self.entries.clone())
        }

        fn insert_extent(
            &mut self,
            _entries: &[ExtentMapEntryV2],
        ) -> std::result::Result<(), ExtentMapError> {
            Ok(())
        }

        fn truncate(
            &mut self,
            _new_size: u64,
        ) -> std::result::Result<Vec<FreedExtent>, ExtentMapError> {
            Ok(Vec::new())
        }

        fn punch_hole(
            &mut self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<FreedExtent>, ExtentMapError> {
            Ok(Vec::new())
        }

        fn collapse_range(
            &mut self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<FreedExtent>, ExtentMapError> {
            Ok(Vec::new())
        }

        fn convert_unwritten_to_data(
            &mut self,
            _offset: u64,
            _length: u64,
            _locator_id: LocatorId,
            _checksum: [u8; 32],
            _birth_commit_group: u64,
        ) -> std::result::Result<(), ExtentMapError> {
            Ok(())
        }

        fn seek_data(&self, _offset: u64) -> Option<(u64, u64)> {
            for e in &self.entries {
                if e.logical_offset >= _offset && e.extent_type().is_data() {
                    return Some((e.logical_offset, e.length));
                }
            }
            None
        }

        fn seek_hole(&self, _offset: u64) -> Option<(u64, u64)> {
            let max_end = self
                .entries
                .iter()
                .map(|e| e.logical_offset + e.length)
                .max()
                .unwrap_or(0);
            if _offset >= max_end {
                return Some((_offset, u64::MAX - _offset));
            }
            let mut cursor = 0u64;
            for e in &self.entries {
                if e.logical_offset > cursor && cursor >= _offset {
                    return Some((cursor, e.logical_offset - cursor));
                }
                cursor = e.logical_offset + e.length;
            }
            None
        }

        fn fallocate(
            &mut self,
            _offset: u64,
            _length: u64,
            _keep_size: bool,
        ) -> std::result::Result<(), ExtentMapError> {
            Ok(())
        }

        fn zero_range(
            &mut self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<FreedExtent>, ExtentMapError> {
            Ok(Vec::new())
        }

        fn fiemap(
            &self,
            _offset: u64,
            _length: u64,
        ) -> std::result::Result<Vec<FiemapExtent>, ExtentMapError> {
            Ok(Vec::new())
        }

        fn validate(&self) -> std::result::Result<(), ExtentMapError> {
            Ok(())
        }
    }

    /// Build a deterministic ObjectKey from seed bytes by repeating into 32 bytes.
    fn make_test_key(seed: &[u8]) -> ObjectKey {
        let mut bytes = [0u8; 32];
        for (i, b) in seed.iter().cycle().take(32).enumerate() {
            bytes[i] = *b;
        }
        ObjectKey::from_bytes32(bytes)
    }

    fn make_data_entry(offset: u64, data: &[u8], store: &mut MemStore) -> ExtentMapEntryV2 {
        let key = make_test_key(data);
        store.put(key, data).unwrap();
        let locator_bytes: [u8; 8] = key.as_bytes()[..8].try_into().unwrap();
        let locator = LocatorId(u64::from_le_bytes(locator_bytes).max(1));
        ExtentMapEntryV2::new_data(offset, data.len() as u64, locator, key.as_bytes32(), 0)
    }

    // -- validate_read_offset -----------------------------------------------

    #[test]
    fn validate_nonnegative_offset_ok() {
        assert_eq!(validate_read_offset(0), Ok(0));
        assert_eq!(validate_read_offset(4096), Ok(4096));
        assert_eq!(validate_read_offset(i64::MAX), Ok(i64::MAX as u64));
    }

    #[test]
    fn validate_negative_offset_rejected() {
        assert_eq!(validate_read_offset(-1), Err(libc::EINVAL));
        assert_eq!(validate_read_offset(-4096), Err(libc::EINVAL));
    }

    // -- clamp_read_size ----------------------------------------------------

    #[test]
    fn clamp_zero_returns_zero() {
        assert_eq!(clamp_read_size(0), 0);
    }

    #[test]
    fn clamp_small_size_passthrough() {
        assert_eq!(clamp_read_size(1), 1);
        assert_eq!(clamp_read_size(4096), 4096);
        assert_eq!(clamp_read_size(65536), 65536);
    }

    #[test]
    fn clamp_at_max_read_size() {
        assert_eq!(clamp_read_size(MAX_READ_SIZE as u32), MAX_READ_SIZE);
    }

    #[test]
    fn clamp_exceeds_max_read_size() {
        assert_eq!(clamp_read_size(MAX_READ_SIZE as u32 + 1), MAX_READ_SIZE);
        assert_eq!(clamp_read_size(u32::MAX), MAX_READ_SIZE);
    }

    // -- check_direct_io_alignment ------------------------------------------

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
        assert_eq!(check_direct_io_alignment(1, 512), Err(libc::EINVAL));
        assert_eq!(check_direct_io_alignment(513, 512), Err(libc::EINVAL));
    }

    #[test]
    fn direct_io_unaligned_length_rejected() {
        assert_eq!(check_direct_io_alignment(0, 1), Err(libc::EINVAL));
        assert_eq!(check_direct_io_alignment(512, 513), Err(libc::EINVAL));
    }

    // -- validate_read_request -----------------------------------------------

    #[test]
    fn validate_read_request_valid() {
        assert_eq!(validate_read_request(1, 0, 4096, 0, 8192), Ok(()));
    }

    #[test]
    fn validate_read_request_zero_fh_rejected() {
        assert_eq!(validate_read_request(0, 0, 4096, 0, 8192), Err(EBADF));
    }

    #[test]
    fn validate_read_request_negative_offset_rejected() {
        assert_eq!(validate_read_request(1, -1, 4096, 0, 8192), Err(EINVAL));
    }

    #[test]
    fn validate_read_request_past_eof_offset_rejected() {
        // offset=8192, file_size=4096: past-EOF is rejected
        assert_eq!(validate_read_request(1, 8192, 4096, 0, 4096), Err(EINVAL));
    }

    #[test]
    fn validate_read_request_at_eof_offset_allowed() {
        // offset=4096, file_size=4096: at-EOF is allowed (returns empty)
        assert_eq!(validate_read_request(1, 4096, 4096, 0, 4096), Ok(()));
    }

    #[test]
    fn validate_read_request_zero_size_rejected() {
        assert_eq!(validate_read_request(1, 0, 0, 0, 8192), Err(EINVAL));
    }

    #[test]
    fn validate_read_request_size_exceeds_max_allowed() {
        // validate_read_request does not enforce MAX_READ_SIZE;
        // size clamping is handled by plan_read / clamp_read_size.
        let big = MAX_READ_SIZE as u32 + 1;
        assert_eq!(validate_read_request(1, 0, big, 0, u64::MAX), Ok(()));
    }

    #[test]
    fn validate_read_request_max_size_allowed() {
        assert_eq!(
            validate_read_request(1, 0, MAX_READ_SIZE as u32, 0, u64::MAX),
            Ok(())
        );
    }

    #[test]
    fn validate_read_request_unknown_flags_rejected() {
        assert_eq!(validate_read_request(1, 0, 4096, 0xDEAD, 8192), Err(EINVAL));
    }

    #[test]
    fn validate_read_request_append_flag_allowed() {
        assert_eq!(validate_read_request(1, 0, 4096, O_APPEND, 8192), Ok(()));
    }

    #[test]
    fn validate_read_request_direct_flag_allowed() {
        assert_eq!(validate_read_request(1, 0, 4096, O_DIRECT, 8192), Ok(()));
    }

    #[test]
    fn validate_read_request_sync_flag_allowed() {
        assert_eq!(validate_read_request(1, 0, 4096, O_SYNC, 8192), Ok(()));
    }

    #[test]
    fn validate_read_request_all_known_flags_allowed() {
        let flags = O_APPEND | O_DIRECT | O_SYNC;
        assert_eq!(validate_read_request(1, 0, 4096, flags, 8192), Ok(()));
    }

    #[test]
    fn validate_read_request_large_fh_ok() {
        assert_eq!(validate_read_request(u64::MAX, 0, 1024, 0, 2048), Ok(()));
    }

    #[test]
    fn validate_read_request_file_size_zero_at_eof_ok() {
        // offset == file_size == 0: at-EOF allowed
        assert_eq!(validate_read_request(1, 0, 1, 0, 0), Ok(()));
    }

    #[test]
    fn validate_read_request_file_size_zero_past_eof_rejected() {
        // offset=1 > file_size=0: past-EOF
        assert_eq!(validate_read_request(1, 1, 1, 0, 0), Err(EINVAL));
    }

    // -- plan_read ----------------------------------------------------------

    #[test]
    fn plan_read_normal() {
        let plan = plan_read(42, 7, 0, 4096).unwrap();
        assert_eq!(plan.ino, 42);
        assert_eq!(plan.fh, 7);
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.size, 4096);
    }

    #[test]
    fn plan_read_zero_size() {
        let plan = plan_read(1, 2, 100, 0).unwrap();
        assert_eq!(plan.offset, 100);
        assert_eq!(plan.size, 0);
        assert!(plan.is_empty());
    }

    #[test]
    fn plan_read_negative_offset_rejected() {
        assert_eq!(plan_read(1, 2, -1, 4096), Err(libc::EINVAL));
    }

    #[test]
    fn plan_read_size_clamped() {
        let plan = plan_read(1, 2, 0, MAX_READ_SIZE as u32 + 1024).unwrap();
        assert_eq!(plan.size, MAX_READ_SIZE);
    }

    // -- handle_read ----------------------------------------------------------

    #[test]
    fn handle_read_valid_returns_plan() {
        let plan = handle_read(42, 7, 0, 4096, 0, 8192).unwrap();
        assert_eq!(plan.ino, 42);
        assert_eq!(plan.fh, 7);
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.size, 4096);
    }

    #[test]
    fn handle_read_zero_fh_rejected() {
        assert_eq!(handle_read(42, 0, 0, 4096, 0, 8192), Err(EBADF));
    }

    #[test]
    fn handle_read_negative_offset_rejected() {
        assert_eq!(handle_read(42, 1, -1, 4096, 0, 8192), Err(EINVAL));
    }

    #[test]
    fn handle_read_size_clamped_to_max() {
        let plan = handle_read(1, 2, 0, u32::MAX, 0, u64::MAX).unwrap();
        assert_eq!(plan.size, MAX_READ_SIZE);
    }

    #[test]
    fn handle_read_past_eof_rejected() {
        assert_eq!(handle_read(42, 1, 8192, 4096, 0, 4096), Err(EINVAL));
    }

    #[test]
    fn handle_read_at_eof_zero_size_rejected() {
        // offset == file_size but size is zero -> EINVAL (zero-size reads rejected)
        assert_eq!(handle_read(42, 1, 4096, 0, 0, 4096), Err(EINVAL));
    }

    #[test]
    fn handle_read_unknown_flags_rejected() {
        assert_eq!(handle_read(42, 1, 0, 4096, 0xDEAD, 8192), Err(EINVAL));
    }

    // -- ReadPlan -----------------------------------------------------------

    #[test]
    fn read_plan_is_empty() {
        assert!(ReadPlan::new(1, 2, 0, 0).is_empty());
        assert!(!ReadPlan::new(1, 2, 0, 4096).is_empty());
    }

    // -- ReadError ----------------------------------------------------------

    #[test]
    fn read_error_display() {
        assert!(ReadError::InvalidRange
            .to_string()
            .contains("invalid byte range"));
        assert!(ReadError::IoError("disk full".into())
            .to_string()
            .contains("disk full"));
        assert!(ReadError::MissingObject
            .to_string()
            .contains("missing object"));
        assert!(ReadError::CorruptExtent("transform mismatch".into())
            .to_string()
            .contains("corrupt extent"));
        assert!(ReadError::HoleBeyondEof
            .to_string()
            .contains("hole past EOF"));
        assert!(ReadError::Internal("boom".into())
            .to_string()
            .contains("boom"));
    }

    #[test]
    fn read_error_to_errno() {
        assert_eq!(ReadError::InvalidRange.to_errno(), libc::EINVAL);
        assert_eq!(ReadError::IoError("".into()).to_errno(), libc::EIO);
        assert_eq!(ReadError::MissingObject.to_errno(), libc::EIO);
        assert_eq!(ReadError::CorruptExtent("".into()).to_errno(), libc::EIO);
        assert_eq!(ReadError::HoleBeyondEof.to_errno(), libc::EINVAL);
        assert_eq!(ReadError::Internal("".into()).to_errno(), libc::EIO);
    }

    #[test]
    fn read_error_into_c_int() {
        let e: c_int = ReadError::InvalidRange.into();
        assert_eq!(e, libc::EINVAL);
    }

    #[test]
    fn read_error_ref_into_c_int() {
        let e: c_int = (&ReadError::MissingObject).into();
        assert_eq!(e, libc::EIO);
    }

    // -- fuse_read: zero-length ---------------------------------------------

    #[test]
    fn fuse_read_zero_size_returns_zero() {
        let plan = ReadPlan::new(1, 2, 0, 0);
        let map = StaticExtentMap::default();
        let store = MemStore::default();
        let reader = tidefs_object_io::ObjectReader::new();
        let mut buf = vec![0u8; 16];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 0).unwrap();
        assert_eq!(n, 0);
    }

    // -- fuse_read: single extent -------------------------------------------

    #[test]
    fn fuse_read_single_extent_returns_correct_data() {
        let mut store = MemStore::default();
        let data = b"Hello, TideFS read path!";
        let entry = make_data_entry(0, data, &mut store);
        let map = StaticExtentMap {
            entries: vec![entry],
        };
        let reader = tidefs_object_io::ObjectReader::new();

        let plan = ReadPlan::new(1, 2, 0, data.len());
        let mut buf = vec![0u8; data.len()];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 24).unwrap();
        assert_eq!(n, data.len());
        assert_eq!(&buf[..n], data);
    }

    // -- fuse_read: read within extent at non-zero offset -------------------

    #[test]
    fn fuse_read_within_extent_at_offset() {
        let mut store = MemStore::default();
        let data = b"0123456789";
        let entry = make_data_entry(0, data, &mut store);
        let map = StaticExtentMap {
            entries: vec![entry],
        };
        let reader = tidefs_object_io::ObjectReader::new();

        let plan = ReadPlan::new(1, 2, 6, 4);
        let mut buf = vec![0u8; 4];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 10).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"6789");
    }

    // -- fuse_read: multiple extents ----------------------------------------

    #[test]
    fn fuse_read_multiple_extents_assembles_correctly() {
        let mut store = MemStore::default();
        let head = make_data_entry(0, b"HEAD", &mut store);
        let tail = make_data_entry(8, b"TAIL", &mut store);
        let map = StaticExtentMap {
            entries: vec![head, tail],
        };
        let reader = tidefs_object_io::ObjectReader::new();

        let plan = ReadPlan::new(1, 2, 0, 12);
        let mut buf = vec![0u8; 12];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 12).unwrap();
        assert_eq!(n, 12);
        assert_eq!(&buf[0..4], b"HEAD");
        // bytes 4-7 should be zero-filled hole
        assert_eq!(&buf[4..8], &[0u8; 4]);
        assert_eq!(&buf[8..12], b"TAIL");
    }

    // -- fuse_read: entirely within a hole ----------------------------------

    #[test]
    fn fuse_read_entirely_in_hole_returns_zeroes() {
        let map = StaticExtentMap::default(); // no extents
        let store = MemStore::default();
        let reader = tidefs_object_io::ObjectReader::new();

        let plan = ReadPlan::new(1, 2, 0, 16);
        let mut buf = vec![0xffu8; 16];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 0).unwrap();
        assert_eq!(n, 0); // empty extent map, reader returns 0
        assert_eq!(&buf, &[0u8; 16]); // buffer zeroed by reader
    }

    // -- fuse_read: spanning hole + extent ----------------------------------

    #[test]
    fn fuse_read_spanning_hole_and_extent_returns_zeroes_then_data() {
        let mut store = MemStore::default();
        let data = make_data_entry(8, b"DATA", &mut store);
        let map = StaticExtentMap {
            entries: vec![data],
        };
        let reader = tidefs_object_io::ObjectReader::new();

        let plan = ReadPlan::new(1, 2, 0, 12);
        let mut buf = vec![0xffu8; 12];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 12).unwrap();
        assert_eq!(n, 12);
        assert_eq!(&buf[0..8], &[0u8; 8]);
        assert_eq!(&buf[8..12], b"DATA");
    }

    // -- fuse_read: short read past EOF -------------------------------------

    #[test]
    fn fuse_read_short_read_past_eof() {
        let mut store = MemStore::default();
        let data = make_data_entry(0, b"abc", &mut store);
        let map = StaticExtentMap {
            entries: vec![data],
        };
        let reader = tidefs_object_io::ObjectReader::new();

        let plan = ReadPlan::new(1, 2, 0, 16);
        let mut buf = vec![0xffu8; 16];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 3).unwrap();
        assert_eq!(n, 3); // only 3 bytes of data
        assert_eq!(&buf[..3], b"abc");
    }

    // -- fuse_read: offset beyond EOF ---------------------------------------

    #[test]
    fn fuse_read_offset_beyond_eof_returns_empty() {
        let mut store = MemStore::default();
        let data = make_data_entry(0, b"abc", &mut store);
        let map = StaticExtentMap {
            entries: vec![data],
        };
        let reader = tidefs_object_io::ObjectReader::new();

        let plan = ReadPlan::new(1, 2, 100, 16);
        let mut buf = vec![0xffu8; 16];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 3).unwrap();
        assert_eq!(n, 0);
    }

    // -- fuse_read: error mapping from ObjectIoError ------------------------

    #[test]
    fn fuse_read_missing_object_returns_read_error() {
        // Create an extent that references a non-existent object
        let mut store = MemStore::default();
        let data = b"will-be-lost";
        let key = make_test_key(data);
        store.put(key, data).unwrap();
        let locator_bytes: [u8; 8] = key.as_bytes()[..8].try_into().unwrap();
        let locator = LocatorId(u64::from_le_bytes(locator_bytes).max(1));
        let entry = ExtentMapEntryV2::new_data(0, data.len() as u64, locator, key.as_bytes32(), 0);
        let map = StaticExtentMap {
            entries: vec![entry],
        };
        // Use an empty store so the object is missing
        let empty_store = MemStore::default();
        let reader = tidefs_object_io::ObjectReader::new();

        let plan = ReadPlan::new(1, 2, 0, data.len());
        let mut buf = vec![0u8; data.len()];
        let err = fuse_read(&plan, &map, &empty_store, &reader, &mut buf, 12).unwrap_err();
        assert!(matches!(err, ReadError::MissingObject));
        assert_eq!(err.to_errno(), libc::EIO);
    }

    #[test]
    fn fuse_read_invalid_chunk_size_maps_to_internal_eio() {
        let io_err = tidefs_object_io::ObjectIoError::InvalidChunkSize;
        let read_err = ReadError::from(io_err);
        assert_eq!(read_err.to_errno(), libc::EIO);
    }

    #[test]
    fn fuse_read_invalid_range_maps_to_einval() {
        let io_err = tidefs_object_io::ObjectIoError::InvalidRange;
        let read_err = ReadError::from(io_err);
        assert_eq!(read_err.to_errno(), libc::EINVAL);
    }

    #[test]
    fn fuse_read_hole_beyond_eof_maps_to_einval() {
        let io_err = tidefs_object_io::ObjectIoError::HoleBeyondEof;
        let read_err = ReadError::from(io_err);
        assert_eq!(read_err.to_errno(), libc::EINVAL);
    }

    #[test]
    fn fuse_read_transform_mismatch_maps_to_corrupt_extent_eio() {
        let io_err = tidefs_object_io::ObjectIoError::TransformMismatch {
            field: "algorithm",
            expected: 1,
            observed: 2,
        };
        let read_err = ReadError::from(io_err);
        assert!(matches!(read_err, ReadError::CorruptExtent(_)));
        assert_eq!(read_err.to_errno(), libc::EIO);
        assert!(read_err.to_string().contains("transform mismatch"));
    }

    #[test]
    fn fuse_read_store_error_maps_to_eio() {
        let store_err = std::io::Error::other("disk full");
        let io_err = tidefs_object_io::ObjectIoError::StoreError(Box::new(store_err));
        let read_err = ReadError::from(io_err);
        assert_eq!(read_err.to_errno(), libc::EIO);
        assert!(read_err.to_string().contains("disk full"));
    }

    #[test]
    fn fuse_read_extent_error_maps_to_internal_eio() {
        let io_err = tidefs_object_io::ObjectIoError::ExtentError(
            tidefs_object_io::ExtentMapError::NotFound,
        );
        let read_err = ReadError::from(io_err);
        assert_eq!(read_err.to_errno(), libc::EIO);
    }

    // -- Integration: plan + fuse_read pattern -------------------------------

    #[test]
    fn plan_and_read_roundtrip() {
        let mut store = MemStore::default();
        let data = b"roundtrip test data";
        let entry = make_data_entry(0, data, &mut store);
        let map = StaticExtentMap {
            entries: vec![entry],
        };
        let reader = tidefs_object_io::ObjectReader::new();

        let plan = plan_read(42, 7, 0, data.len() as u32).unwrap();
        assert_eq!(plan.ino, 42);
        assert_eq!(plan.fh, 7);

        let mut buf = vec![0u8; plan.size];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 19).unwrap();
        assert_eq!(n, data.len());
        assert_eq!(&buf[..n], data);
    }

    #[test]
    fn plan_clamped_and_read_truncated() {
        let mut store = MemStore::default();
        let data = b"small";
        let entry = make_data_entry(0, data, &mut store);
        let map = StaticExtentMap {
            entries: vec![entry],
        };
        let reader = tidefs_object_io::ObjectReader::new();

        // Request more than available
        let plan = plan_read(1, 2, 0, 4096).unwrap();
        assert_eq!(plan.size, 4096);

        let mut buf = vec![0u8; plan.size];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 5).unwrap();
        assert_eq!(n, data.len());
        assert_eq!(&buf[..n], data);
    }

    // -- Unwritten extent reads as zeros ------------------------------------

    #[test]
    fn unwritten_extent_reads_as_zeroes() {
        let map = StaticExtentMap {
            entries: vec![ExtentMapEntryV2::new_unwritten(0, 8, 0)],
        };
        let store = MemStore::default();
        let reader = tidefs_object_io::ObjectReader::new();

        let plan = ReadPlan::new(1, 2, 0, 8);
        let mut buf = vec![0xffu8; 8];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 8).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&buf, &[0u8; 8]);
    }

    // -- Concurrent reads (no interference) ----------------------------------

    #[test]
    fn concurrent_reads_from_same_inode_no_interference() {
        let mut store = MemStore::default();
        let data = b"concurrent test data for reads";
        let entry = make_data_entry(0, data, &mut store);
        let map = StaticExtentMap {
            entries: vec![entry],
        };
        let reader = tidefs_object_io::ObjectReader::new();

        // Read 1: first half
        let plan1 = ReadPlan::new(1, 2, 0, 10);
        let mut buf1 = vec![0u8; 10];
        let n1 = fuse_read(&plan1, &map, &store, &reader, &mut buf1, 30).unwrap();

        // Read 2: second half
        let plan2 = ReadPlan::new(1, 2, 10, 20);
        let mut buf2 = vec![0u8; 20];
        let n2 = fuse_read(&plan2, &map, &store, &reader, &mut buf2, 30).unwrap();

        assert_eq!(n1, 10);
        assert_eq!(n2, data.len() - 10);
        assert_eq!(&buf1[..10], &data[..10]);
        assert_eq!(&buf2[..n2], &data[10..]);
    }

    // -- check_read_permission -----------------------------------------------

    #[test]
    fn check_read_permission_root_bypass() {
        // Root (uid=0) always passes permission check regardless of mode bits.
        let result = check_read_permission(0o000, 1000, 100, 0, 0, &[], &VALID_MOUNT);
        assert!(result.is_ok());
    }

    #[test]
    fn check_read_permission_owner_with_read_bit() {
        // Owner with read bit set passes.
        let result = check_read_permission(0o400, 1000, 100, 1000, 100, &[], &VALID_MOUNT);
        assert!(result.is_ok());
    }

    // -- Large multi-page read ------------------------------------------------

    #[test]
    fn large_multi_page_read_returns_full_extent_data() {
        let mut store = MemStore::default();
        let large_data = vec![0xABu8; MAX_READ_SIZE];
        let entry = make_data_entry(0, &large_data, &mut store);
        let map = StaticExtentMap {
            entries: vec![entry],
        };
        let reader = tidefs_object_io::ObjectReader::new();

        let plan = ReadPlan::new(1, 2, 0, MAX_READ_SIZE);
        let mut buf = vec![0u8; MAX_READ_SIZE];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, MAX_READ_SIZE as u64).unwrap();
        assert_eq!(n, MAX_READ_SIZE);
        assert_eq!(&buf[..n], &large_data[..]);
    }

    // -- Read from zero-length (empty) file -----------------------------------

    #[test]
    fn read_from_empty_file_returns_zero_bytes() {
        let map = StaticExtentMap::default();
        let store = MemStore::default();
        let reader = tidefs_object_io::ObjectReader::new();

        // file_size=0, any read returns 0
        let plan = ReadPlan::new(1, 2, 0, 16);
        let mut buf = vec![0xffu8; 16];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 0).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_from_empty_file_at_nonzero_offset_returns_zero() {
        let map = StaticExtentMap::default();
        let store = MemStore::default();
        let reader = tidefs_object_io::ObjectReader::new();

        // file_size=0, offset >= 0 returns 0 (POSIX: offset == EOF)
        let plan = ReadPlan::new(1, 2, 100, 16);
        let mut buf = vec![0xffu8; 16];
        let n = fuse_read(&plan, &map, &store, &reader, &mut buf, 0).unwrap();
        assert_eq!(n, 0);
    }

    // -- Permission denied maps correctly --------------------------------------

    #[test]
    fn read_error_permission_denied_to_errno() {
        assert_eq!(ReadError::PermissionDenied.to_errno(), libc::EACCES);
        assert!(ReadError::PermissionDenied
            .to_string()
            .contains("permission denied"));
    }
}
