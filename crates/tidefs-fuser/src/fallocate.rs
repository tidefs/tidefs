//! FUSE `fallocate` handler helpers.
//!
//! Provides:
//! - [`FallocateMode`]: operation mode (Allocate, PunchHole, ZeroRange,
//!   CollapseRange, InsertRange).
//! - [`FallocatePlan`]: structured plan for a fallocate operation with
//!   mode, offset, length, and optional file handle.
//! - [`validate_fallocate`]: check read-only FS, file type (regular only),
//!   offset/length bounds, and mode support flags.
//! - [`plan_fallocate`]: construct a [`FallocatePlan`] from mode, offset,
//!   and length parameters.
//! - [`classify_fallocate_mode`]: derive a [`FallocateMode`] from raw FUSE
//!   fallocate mode flags.
//! - Re-exported POSIX errno codes and FALLOC_FL_* constants relevant to
//!   the fallocate path.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::fallocate;
//!
//! let mode = fallocate::classify_fallocate_mode(0)?;
//! let plan = fallocate::plan_fallocate(mode, 0, 4096, 42);
//! fallocate::validate_fallocate(plan.mode, plan.offset, plan.length,
//!     false, FileType::RegularFile)?;
//! // ... perform back-end fallocate via engine ...
//! ```

use libc::c_int;

use crate::FileType;

// ---------------------------------------------------------------------------
// FALLOC_FL_* constants (Linux kernel uapi)
// ---------------------------------------------------------------------------

/// Keep file size unchanged (i.e., do not extend past EOF when
/// allocating beyond current file size).
pub const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
/// Deallocate space in the middle of a file (hole punch).
pub const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;
/// Remove a range and shift later data left (collapse range).
pub const FALLOC_FL_COLLAPSE_RANGE: i32 = 0x08;
/// Zero a range without deallocating extents (zero range).
pub const FALLOC_FL_ZERO_RANGE: i32 = 0x10;
/// Insert a zero-filled range, shifting later data right (insert range).
pub const FALLOC_FL_INSERT_RANGE: i32 = 0x20;

/// All recognised FUSE fallocate mode flags.
pub const FALLOC_FL_ALL_SUPPORTED: i32 = FALLOC_FL_KEEP_SIZE
    | FALLOC_FL_PUNCH_HOLE
    | FALLOC_FL_COLLAPSE_RANGE
    | FALLOC_FL_ZERO_RANGE
    | FALLOC_FL_INSERT_RANGE;

// ---------------------------------------------------------------------------
// Re-exports: standard errno codes for fallocate error paths
// ---------------------------------------------------------------------------

pub use libc::{
    EBADF, EFBIG, EINVAL, EIO, EISDIR, ENODEV, ENOSPC, ENOTSUP, EOPNOTSUPP, EPERM, EROFS, ESPIPE,
};

// ---------------------------------------------------------------------------
// FallocateMode
// ---------------------------------------------------------------------------

/// The semantic operation implied by a FUSE fallocate mode.
///
/// - [`FallocateMode::Allocate`]: plain preallocation (`mode == 0` or
///   `FALLOC_FL_KEEP_SIZE`). Guarantees that subsequent writes into the
///   allocated range will not fail with ENOSPC.
/// - [`FallocateMode::PunchHole`]: deallocate a range in the middle of a
///   file, creating a hole (`FALLOC_FL_PUNCH_HOLE`).
/// - [`FallocateMode::ZeroRange`]: zero a range without deallocating
///   the underlying extents (`FALLOC_FL_ZERO_RANGE`).
/// - [`FallocateMode::CollapseRange`]: remove a range and shift
///   subsequent data left, reducing file size
///   (`FALLOC_FL_COLLAPSE_RANGE`).
/// - [`FallocateMode::InsertRange`]: insert a zero-filled range,
///   shifting subsequent data right, increasing file size
///   (`FALLOC_FL_INSERT_RANGE`).
///
/// `FALLOC_FL_KEEP_SIZE` is not a standalone mode; it modifies
/// `Allocate` to avoid extending the file size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallocateMode {
    /// Plain space allocation (posix_fallocate(3)).
    Allocate {
        /// When true, do not extend the file size beyond EOF even if the
        /// allocated range extends past the current file size.
        keep_size: bool,
    },
    /// Deallocate space (hole punch).
    PunchHole,
    /// Zero a range without deallocating.
    ZeroRange,
    /// Remove a range and shift left.
    CollapseRange,
    /// Insert a zero-filled range and shift right.
    InsertRange,
}

impl FallocateMode {
    /// Returns `true` when this mode modifies the file size
    /// (CollapseRange shrinks, InsertRange extends).
    #[must_use]
    pub const fn changes_file_size(self) -> bool {
        matches!(self, Self::CollapseRange | Self::InsertRange)
    }

    /// Returns `true` when this mode deallocates space (PunchHole).
    #[must_use]
    pub const fn deallocates_space(self) -> bool {
        matches!(self, Self::PunchHole)
    }

    /// Returns `true` when this mode requires block allocation.
    #[must_use]
    pub const fn requires_allocation(self) -> bool {
        matches!(
            self,
            Self::Allocate { .. } | Self::ZeroRange | Self::InsertRange
        )
    }
}

// ---------------------------------------------------------------------------
// FallocatePlan
// ---------------------------------------------------------------------------

/// Planned fallocate operation derived from FUSE fallocate parameters.
///
/// Carries the mode, the byte range (`offset`..`offset+length`), and the
/// optional file handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FallocatePlan {
    /// The fallocate operation mode.
    pub mode: FallocateMode,
    /// Starting byte offset (inclusive).
    pub offset: u64,
    /// Length of the range in bytes.
    pub length: u64,
    /// Optional file handle.
    pub fh: Option<u64>,
}

impl FallocatePlan {
    /// Create a new fallocate plan.
    #[must_use]
    pub const fn new(mode: FallocateMode, offset: u64, length: u64, fh: Option<u64>) -> Self {
        Self {
            mode,
            offset,
            length,
            fh,
        }
    }

    /// Returns the exclusive end byte offset (`offset + length`), saturating
    /// at `u64::MAX`.
    #[must_use]
    pub const fn end_offset(&self) -> u64 {
        match self.offset.checked_add(self.length) {
            Some(end) => end,
            None => u64::MAX,
        }
    }

    /// Returns `true` when the plan is a no-op (zero-length range).
    #[must_use]
    pub const fn is_noop(&self) -> bool {
        self.length == 0
    }
}

// ---------------------------------------------------------------------------
// Maximum reasonable range extents
// ---------------------------------------------------------------------------

/// Maximum byte offset accepted for fallocate operations (8 EiB - 1).
///
/// This matches the Linux off_t limit for a 64-bit signed offset,
/// preventing overflow in extent-map calculations.
pub const MAX_FALLOCATE_OFFSET: u64 = i64::MAX as u64;

/// Maximum length accepted for a single fallocate operation (8 EiB).
///
/// Larger lengths must be split by the caller.
pub const MAX_FALLOCATE_LENGTH: u64 = i64::MAX as u64;

// ---------------------------------------------------------------------------
// classify_fallocate_mode
// ---------------------------------------------------------------------------

/// Classify a FUSE fallocate mode flags value into a [`FallocateMode`].
///
/// Returns `Err(EOPNOTSUPP)` when the mode contains unsupported flags.
/// Returns `Err(EINVAL)` when the mode is 0 with mutually exclusive
/// flag combinations.
///
/// Valid combinations:
/// - `0` or `FALLOC_FL_KEEP_SIZE` -> `Allocate`
/// - `FALLOC_FL_PUNCH_HOLE` (optionally with `KEEP_SIZE`) -> `PunchHole`
/// - `FALLOC_FL_ZERO_RANGE` (optionally with `KEEP_SIZE`) -> `ZeroRange`
/// - `FALLOC_FL_COLLAPSE_RANGE` -> `CollapseRange`
/// - `FALLOC_FL_INSERT_RANGE` -> `InsertRange`
pub fn classify_fallocate_mode(mode: i32) -> Result<FallocateMode, c_int> {
    // Reject unknown flags.
    let unknown = mode & !FALLOC_FL_ALL_SUPPORTED;
    if unknown != 0 {
        return Err(libc::EOPNOTSUPP);
    }

    // Strip KEEP_SIZE -- it's a modifier, not a standalone mode.
    let base = mode & !FALLOC_FL_KEEP_SIZE;
    let keep_size = (mode & FALLOC_FL_KEEP_SIZE) != 0;

    match base {
        0 => Ok(FallocateMode::Allocate { keep_size }),
        FALLOC_FL_PUNCH_HOLE => {
            if mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE | FALLOC_FL_INSERT_RANGE)
                != 0
            {
                return Err(libc::EINVAL);
            }
            Ok(FallocateMode::PunchHole)
        }
        FALLOC_FL_ZERO_RANGE => {
            if mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_PUNCH_HOLE | FALLOC_FL_INSERT_RANGE)
                != 0
            {
                return Err(libc::EINVAL);
            }
            Ok(FallocateMode::ZeroRange)
        }
        FALLOC_FL_COLLAPSE_RANGE => {
            if mode & (FALLOC_FL_ZERO_RANGE | FALLOC_FL_PUNCH_HOLE | FALLOC_FL_INSERT_RANGE) != 0 {
                return Err(libc::EINVAL);
            }
            Ok(FallocateMode::CollapseRange)
        }
        FALLOC_FL_INSERT_RANGE => {
            if mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE | FALLOC_FL_PUNCH_HOLE) != 0
            {
                return Err(libc::EINVAL);
            }
            Ok(FallocateMode::InsertRange)
        }
        _ => {
            // Multiple non-KEEP_SIZE flags set: invalid combination.
            Err(libc::EINVAL)
        }
    }
}

// ---------------------------------------------------------------------------
// validate_fallocate_bounds
// ---------------------------------------------------------------------------

/// Validate offset and length for a fallocate operation against filesystem
/// limits.
///
/// # Returns
///
/// `Ok(())` when offset and length are within acceptable bounds.
///
/// `Err(EINVAL)` when offset or length is negative, or the range would
/// overflow `u64`.
///
/// `Err(EFBIG)` when offset exceeds [`MAX_FALLOCATE_OFFSET`] or length
/// exceeds [`MAX_FALLOCATE_LENGTH`].
#[inline]
pub fn validate_fallocate_bounds(offset: i64, length: i64) -> Result<(u64, u64), c_int> {
    if offset < 0 || length < 0 {
        return Err(libc::EINVAL);
    }
    let off = offset as u64;
    let len = length as u64;
    if off > MAX_FALLOCATE_OFFSET {
        return Err(libc::EFBIG);
    }
    if len > MAX_FALLOCATE_LENGTH {
        return Err(libc::EFBIG);
    }
    // Check for u64 overflow: offset + length
    off.checked_add(len).ok_or(libc::EFBIG)?;
    Ok((off, len))
}

// ---------------------------------------------------------------------------
// validate_fallocate_mode_requirements
// ---------------------------------------------------------------------------

/// Validate mode-specific constraints on offset and length.
///
/// - `CollapseRange` and `InsertRange`: offset must be a multiple of the
///   filesystem block size, and length must be a multiple of the block size
///   and greater than zero.
/// - `PunchHole`: offset and length may be any value; zero-length is a no-op.
/// - `ZeroRange`: offset must be block-aligned, length must be block-aligned
///   and greater than zero.
/// - `Allocate`: any non-negative offset and length.
///
/// `block_size` is the filesystem logical block size (typically 4096).
#[inline]
pub fn validate_fallocate_mode_requirements(
    mode: FallocateMode,
    offset: u64,
    length: u64,
    block_size: u64,
) -> Result<(), c_int> {
    match mode {
        FallocateMode::CollapseRange | FallocateMode::InsertRange => {
            if length == 0 {
                return Err(libc::EINVAL);
            }
            if offset % block_size != 0 || length % block_size != 0 {
                return Err(libc::EINVAL);
            }
            Ok(())
        }
        FallocateMode::ZeroRange => {
            if length == 0 {
                return Err(libc::EINVAL);
            }
            if offset % block_size != 0 || length % block_size != 0 {
                return Err(libc::EINVAL);
            }
            Ok(())
        }
        FallocateMode::PunchHole => {
            // Zero-length punch is a no-op (allowed).
            Ok(())
        }
        FallocateMode::Allocate { .. } => {
            // Any offset and length are acceptable for plain allocation.
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// validate_fallocate -- combined validation
// ---------------------------------------------------------------------------

/// Combined validation for a fallocate operation.
///
/// Checks:
/// 1. Read-only filesystem -> `EROFS`.
/// 2. File type must be regular file -> `EISDIR` for directories,
///    `EINVAL` for other non-regular types.
/// 3. Offset/length bounds (`validate_fallocate_bounds`).
/// 4. Mode-specific alignment and length constraints
///    (`validate_fallocate_mode_requirements`).
///
/// Returns the validated `(offset, length)` pair on success.
#[inline]
pub fn validate_fallocate(
    mode: FallocateMode,
    offset: i64,
    length: i64,
    read_only: bool,
    kind: FileType,
    block_size: u64,
) -> Result<(u64, u64), c_int> {
    if read_only {
        return Err(libc::EROFS);
    }
    // Only regular files support fallocate.
    match kind {
        FileType::RegularFile => {}
        FileType::Directory => return Err(libc::EISDIR),
        _ => return Err(libc::EINVAL),
    }
    let (off, len) = validate_fallocate_bounds(offset, length)?;
    validate_fallocate_mode_requirements(mode, off, len, block_size)?;
    Ok((off, len))
}

// ---------------------------------------------------------------------------
// plan_fallocate
// ---------------------------------------------------------------------------

/// Construct a [`FallocatePlan`] from mode, offset, length, and an optional
/// file handle.
///
/// When `fh` is `Some(0)`, it is treated as `None` (no valid handle).
#[must_use]
pub fn plan_fallocate(mode: FallocateMode, offset: u64, length: u64, fh: u64) -> FallocatePlan {
    let fh_opt = if fh == 0 { None } else { Some(fh) };
    FallocatePlan::new(mode, offset, length, fh_opt)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handle_fallocate -- unified entry point for FUSE fallocate dispatch
// ---------------------------------------------------------------------------

/// Compose [`classify_fallocate_mode`], [`validate_fallocate`], and
/// [`plan_fallocate`] into a single entry point for daemon dispatch.
///
/// This is the preferred entry point for a FUSE daemon that receives a
/// raw `FUSE_FALLOCATE` request: it classifies the mode flags, validates
/// offset, length, file type, and read-only status, then returns a
/// validated [`FallocatePlan`] ready for back-end execution.
///
/// # Parameters
///
/// - `mode`: raw FUSE fallocate mode flags (0, `FALLOC_FL_KEEP_SIZE`,
///   `FALLOC_FL_PUNCH_HOLE`, `FALLOC_FL_ZERO_RANGE`,
///   `FALLOC_FL_COLLAPSE_RANGE`, `FALLOC_FL_INSERT_RANGE`).
/// - `offset`: signed byte offset from the FUSE request.
/// - `length`: signed byte length from the FUSE request.
/// - `fh`: file handle from the FUSE request (0 means no handle).
/// - `read_only`: when true, the filesystem is mounted read-only.
/// - `kind`: [`FileType`] of the target inode.
/// - `block_size`: filesystem logical block size (typically 4096).
///
/// # Errors
///
/// Returns `Err(c_int)` with a POSIX errno when any validation step fails:
/// - `EOPNOTSUPP`: unknown or unsupported mode flags.
/// - `EINVAL`: invalid flag combination, bad offset/length, or non-regular
///   file type.
/// - `EROFS`: read-only filesystem.
/// - `EISDIR`: target is a directory.
/// - `EFBIG`: offset or length exceeds filesystem limits.
///
/// # Examples
///
/// ```rust,ignore
/// let plan = fallocate::handle_fallocate(
///     0, 0, 4096, 42,
///     false, FileType::RegularFile, 4096,
/// )?;
/// ```
pub fn handle_fallocate(
    mode: i32,
    offset: i64,
    length: i64,
    fh: u64,
    read_only: bool,
    kind: FileType,
    block_size: u64,
) -> Result<FallocatePlan, c_int> {
    let fmode = classify_fallocate_mode(mode)?;
    let (off, len) = validate_fallocate(fmode, offset, length, read_only, kind, block_size)?;
    Ok(plan_fallocate(fmode, off, len, fh))
}
#[cfg(test)]
mod tests {
    use super::*;

    // -- FallocateMode ---------------------------------------------------

    #[test]
    fn mode_allocate_changes_file_size() {
        let m = FallocateMode::Allocate { keep_size: false };
        assert!(!m.changes_file_size());
        assert!(!m.deallocates_space());
        assert!(m.requires_allocation());
    }

    #[test]
    fn mode_allocate_keep_size() {
        let m = FallocateMode::Allocate { keep_size: true };
        assert!(!m.changes_file_size());
        assert!(!m.deallocates_space());
        assert!(m.requires_allocation());
    }

    #[test]
    fn mode_punch_hole_properties() {
        let m = FallocateMode::PunchHole;
        assert!(!m.changes_file_size());
        assert!(m.deallocates_space());
        assert!(!m.requires_allocation());
    }

    #[test]
    fn mode_zero_range_properties() {
        let m = FallocateMode::ZeroRange;
        assert!(!m.changes_file_size());
        assert!(!m.deallocates_space());
        assert!(m.requires_allocation());
    }

    #[test]
    fn mode_collapse_range_properties() {
        let m = FallocateMode::CollapseRange;
        assert!(m.changes_file_size());
        assert!(!m.deallocates_space());
        assert!(!m.requires_allocation());
    }

    #[test]
    fn mode_insert_range_properties() {
        let m = FallocateMode::InsertRange;
        assert!(m.changes_file_size());
        assert!(!m.deallocates_space());
        assert!(m.requires_allocation());
    }

    // -- FallocatePlan ---------------------------------------------------

    #[test]
    fn plan_new() {
        let plan = FallocatePlan::new(
            FallocateMode::Allocate { keep_size: false },
            0,
            4096,
            Some(42),
        );
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.length, 4096);
        assert_eq!(plan.fh, Some(42));
        assert_eq!(plan.end_offset(), 4096);
    }

    #[test]
    fn plan_end_offset_saturating() {
        let plan = FallocatePlan::new(FallocateMode::PunchHole, u64::MAX, 1, None);
        assert_eq!(plan.end_offset(), u64::MAX);
    }

    #[test]
    fn plan_is_noop_zero_length() {
        let plan = FallocatePlan::new(FallocateMode::Allocate { keep_size: false }, 1024, 0, None);
        assert!(plan.is_noop());
    }

    #[test]
    fn plan_is_not_noop() {
        let plan = FallocatePlan::new(FallocateMode::PunchHole, 0, 4096, None);
        assert!(!plan.is_noop());
    }

    // -- classify_fallocate_mode -----------------------------------------

    #[test]
    fn classify_plain_allocate() {
        assert_eq!(
            classify_fallocate_mode(0),
            Ok(FallocateMode::Allocate { keep_size: false })
        );
    }

    #[test]
    fn classify_allocate_keep_size() {
        assert_eq!(
            classify_fallocate_mode(FALLOC_FL_KEEP_SIZE),
            Ok(FallocateMode::Allocate { keep_size: true })
        );
    }

    #[test]
    fn classify_punch_hole() {
        assert_eq!(
            classify_fallocate_mode(FALLOC_FL_PUNCH_HOLE),
            Ok(FallocateMode::PunchHole)
        );
    }

    #[test]
    fn classify_punch_hole_with_keep_size() {
        assert_eq!(
            classify_fallocate_mode(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE),
            Ok(FallocateMode::PunchHole)
        );
    }

    #[test]
    fn classify_zero_range() {
        assert_eq!(
            classify_fallocate_mode(FALLOC_FL_ZERO_RANGE),
            Ok(FallocateMode::ZeroRange)
        );
    }

    #[test]
    fn classify_collapse_range() {
        assert_eq!(
            classify_fallocate_mode(FALLOC_FL_COLLAPSE_RANGE),
            Ok(FallocateMode::CollapseRange)
        );
    }

    #[test]
    fn classify_insert_range() {
        assert_eq!(
            classify_fallocate_mode(FALLOC_FL_INSERT_RANGE),
            Ok(FallocateMode::InsertRange)
        );
    }

    #[test]
    fn classify_unknown_flag_rejected() {
        assert_eq!(classify_fallocate_mode(0x80), Err(libc::EOPNOTSUPP));
    }

    #[test]
    fn classify_multi_flag_rejected() {
        assert_eq!(
            classify_fallocate_mode(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn classify_punch_plus_collapse_rejected() {
        assert_eq!(
            classify_fallocate_mode(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_COLLAPSE_RANGE),
            Err(libc::EINVAL)
        );
    }

    // -- validate_fallocate_bounds ---------------------------------------

    #[test]
    fn bounds_negative_offset() {
        assert_eq!(validate_fallocate_bounds(-1, 4096), Err(libc::EINVAL));
    }

    #[test]
    fn bounds_negative_length() {
        assert_eq!(validate_fallocate_bounds(0, -1), Err(libc::EINVAL));
    }

    #[test]
    fn bounds_zero_length_ok() {
        assert_eq!(validate_fallocate_bounds(0, 0), Ok((0, 0)));
    }

    #[test]
    fn bounds_normal() {
        assert_eq!(validate_fallocate_bounds(0, 4096), Ok((0, 4096)));
    }

    #[test]
    fn bounds_large_but_valid() {
        let off: i64 = 1 << 40; // 1 TiB
        let len: i64 = 1 << 30; // 1 GiB
        assert!(validate_fallocate_bounds(off, len).is_ok());
    }

    // -- validate_fallocate_mode_requirements ----------------------------

    #[test]
    fn requirements_allocate_any_offset() {
        assert_eq!(
            validate_fallocate_mode_requirements(
                FallocateMode::Allocate { keep_size: false },
                1,
                1,
                4096
            ),
            Ok(())
        );
    }

    #[test]
    fn requirements_collapse_zero_length_rejected() {
        assert_eq!(
            validate_fallocate_mode_requirements(FallocateMode::CollapseRange, 0, 0, 4096),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn requirements_collapse_unaligned_rejected() {
        assert_eq!(
            validate_fallocate_mode_requirements(FallocateMode::CollapseRange, 1, 4096, 4096),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn requirements_collapse_aligned_ok() {
        assert_eq!(
            validate_fallocate_mode_requirements(FallocateMode::CollapseRange, 0, 4096, 4096),
            Ok(())
        );
    }

    #[test]
    fn requirements_insert_aligned_ok() {
        assert_eq!(
            validate_fallocate_mode_requirements(FallocateMode::InsertRange, 4096, 8192, 4096),
            Ok(())
        );
    }

    #[test]
    fn requirements_zero_range_unaligned_rejected() {
        assert_eq!(
            validate_fallocate_mode_requirements(FallocateMode::ZeroRange, 0, 1, 4096),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn requirements_zero_range_aligned_ok() {
        assert_eq!(
            validate_fallocate_mode_requirements(FallocateMode::ZeroRange, 4096, 4096, 4096),
            Ok(())
        );
    }

    #[test]
    fn requirements_punch_hole_any_offset_ok() {
        assert_eq!(
            validate_fallocate_mode_requirements(FallocateMode::PunchHole, 1, 1, 4096),
            Ok(())
        );
    }

    // -- validate_fallocate ----------------------------------------------

    #[test]
    fn validate_read_only_rejected() {
        assert_eq!(
            validate_fallocate(
                FallocateMode::Allocate { keep_size: false },
                0,
                4096,
                true,
                FileType::RegularFile,
                4096
            ),
            Err(libc::EROFS)
        );
    }

    #[test]
    fn validate_directory_rejected() {
        assert_eq!(
            validate_fallocate(
                FallocateMode::Allocate { keep_size: false },
                0,
                4096,
                false,
                FileType::Directory,
                4096
            ),
            Err(libc::EISDIR)
        );
    }

    #[test]
    fn validate_symlink_rejected() {
        assert_eq!(
            validate_fallocate(
                FallocateMode::Allocate { keep_size: false },
                0,
                4096,
                false,
                FileType::Symlink,
                4096
            ),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn validate_named_pipe_rejected() {
        assert_eq!(
            validate_fallocate(
                FallocateMode::Allocate { keep_size: false },
                0,
                4096,
                false,
                FileType::NamedPipe,
                4096
            ),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn validate_socket_rejected() {
        assert_eq!(
            validate_fallocate(
                FallocateMode::Allocate { keep_size: false },
                0,
                4096,
                false,
                FileType::Socket,
                4096
            ),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn validate_regular_file_ok() {
        assert_eq!(
            validate_fallocate(
                FallocateMode::Allocate { keep_size: false },
                0,
                4096,
                false,
                FileType::RegularFile,
                4096
            ),
            Ok((0, 4096))
        );
    }

    #[test]
    fn validate_punch_hole_regular_file_ok() {
        assert_eq!(
            validate_fallocate(
                FallocateMode::PunchHole,
                0,
                4096,
                false,
                FileType::RegularFile,
                4096
            ),
            Ok((0, 4096))
        );
    }

    #[test]
    fn validate_collapse_range_regular_file_ok() {
        assert_eq!(
            validate_fallocate(
                FallocateMode::CollapseRange,
                0,
                4096,
                false,
                FileType::RegularFile,
                4096
            ),
            Ok((0, 4096))
        );
    }

    #[test]
    fn validate_zero_range_regular_file_ok() {
        assert_eq!(
            validate_fallocate(
                FallocateMode::ZeroRange,
                0,
                4096,
                false,
                FileType::RegularFile,
                4096
            ),
            Ok((0, 4096))
        );
    }

    #[test]
    fn validate_insert_range_regular_file_ok() {
        assert_eq!(
            validate_fallocate(
                FallocateMode::InsertRange,
                4096,
                4096,
                false,
                FileType::RegularFile,
                4096
            ),
            Ok((4096, 4096))
        );
    }

    // -- plan_fallocate --------------------------------------------------

    #[test]
    fn plan_with_valid_fh() {
        let plan = plan_fallocate(FallocateMode::PunchHole, 1024, 2048, 7);
        assert_eq!(plan.mode, FallocateMode::PunchHole);
        assert_eq!(plan.offset, 1024);
        assert_eq!(plan.length, 2048);
        assert_eq!(plan.fh, Some(7));
    }

    #[test]
    fn plan_with_zero_fh_treated_as_none() {
        let plan = plan_fallocate(FallocateMode::Allocate { keep_size: false }, 0, 4096, 0);
        assert_eq!(plan.fh, None);
    }

    // -- Integration: classify + validate + plan -------------------------

    #[test]
    fn full_allocate_flow() {
        let mode = classify_fallocate_mode(0).unwrap();
        let (off, len) =
            validate_fallocate(mode, 0, 4096, false, FileType::RegularFile, 4096).unwrap();
        let plan = plan_fallocate(mode, off, len, 42);
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.length, 4096);
        assert_eq!(plan.fh, Some(42));
        assert_eq!(plan.mode, FallocateMode::Allocate { keep_size: false });
    }

    #[test]
    fn full_punch_hole_flow() {
        let mode = classify_fallocate_mode(FALLOC_FL_PUNCH_HOLE).unwrap();
        let (off, len) =
            validate_fallocate(mode, 4096, 8192, false, FileType::RegularFile, 4096).unwrap();
        let plan = plan_fallocate(mode, off, len, 3);
        assert_eq!(plan.mode, FallocateMode::PunchHole);
        assert_eq!(plan.offset, 4096);
        assert_eq!(plan.length, 8192);
    }

    #[test]
    fn full_collapse_range_flow() {
        let mode = classify_fallocate_mode(FALLOC_FL_COLLAPSE_RANGE).unwrap();
        assert_eq!(mode, FallocateMode::CollapseRange);
        let (off, len) =
            validate_fallocate(mode, 0, 4096, false, FileType::RegularFile, 4096).unwrap();
        let plan = plan_fallocate(mode, off, len, 0);
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.length, 4096);
        assert!(mode.changes_file_size());
    }

    #[test]
    fn handle_fallocate_success_path() {
        let plan = handle_fallocate(0, 0, 4096, 42, false, FileType::RegularFile, 4096).unwrap();
        assert_eq!(plan.mode, FallocateMode::Allocate { keep_size: false });
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.length, 4096);
        assert_eq!(plan.fh, Some(42));
    }

    #[test]
    fn handle_fallocate_read_only_rejected() {
        let err = handle_fallocate(0, 0, 4096, 0, true, FileType::RegularFile, 4096).unwrap_err();
        assert_eq!(err, libc::EROFS);
    }

    #[test]
    fn handle_fallocate_directory_rejected() {
        let err = handle_fallocate(0, 0, 4096, 0, false, FileType::Directory, 4096).unwrap_err();
        assert_eq!(err, libc::EISDIR);
    }

    #[test]
    fn handle_fallocate_unknown_mode_rejected() {
        let err =
            handle_fallocate(0x80, 0, 4096, 0, false, FileType::RegularFile, 4096).unwrap_err();
        assert_eq!(err, libc::EOPNOTSUPP);
    }

    #[test]
    fn handle_fallocate_punch_hole_via_handle() {
        let plan = handle_fallocate(
            FALLOC_FL_PUNCH_HOLE,
            4096,
            8192,
            3,
            false,
            FileType::RegularFile,
            4096,
        )
        .unwrap();
        assert_eq!(plan.mode, FallocateMode::PunchHole);
        assert_eq!(plan.offset, 4096);
        assert_eq!(plan.length, 8192);
    }

    #[test]
    fn handle_fallocate_zero_fh_treated_as_none() {
        let plan = handle_fallocate(
            FALLOC_FL_KEEP_SIZE,
            0,
            4096,
            0,
            false,
            FileType::RegularFile,
            4096,
        )
        .unwrap();
        assert_eq!(plan.mode, FallocateMode::Allocate { keep_size: true });
        assert_eq!(plan.fh, None);
    }
}
