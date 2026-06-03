//! FUSE `lseek` handler helpers.
//!
//! Provides:
//! - [`LseekMode`]: enum distinguishing between SEEK_DATA and SEEK_HOLE
//!   operations.
//! - [`LseekPlan`]: structured plan for an lseek operation with mode,
//!   offset, and optional file handle.
//! - [`validate_lseek_whence`]: validate that `whence` is
//!   `SEEK_DATA` or `SEEK_HOLE` (SEEK_SET/CUR/END are handled by the
//!   kernel VFS layer without reaching FUSE).
//! - [`plan_lseek`]: construct an [`LseekPlan`] from mode and offset.
//! - [`check_lseek_allowed`]: validate that an lseek operation is
//!   applicable to the given file kind.
//! - [`check_lseek_readonly`]: Lseek is a read-only operation and
//!   always permitted (exists for API consistency with other handlers).
//! - [`seek_data`]: find the next data extent at or after an offset
//!   given a sorted, non-overlapping extent list.
//! - [`seek_hole`]: find the next hole at or after an offset.
//! - Re-exported POSIX errno codes and SEEK_* constants relevant to
//!   the lseek path.
//!
//! - [`LseekError`]: domain error type for lseek request validation.
//! - [`handle_lseek`]: canonical dispatch entry-point combining whence
//!   validation, file-kind checking, and read-only guard.
//! # Backend
//!
//! SEEK_DATA/SEEK_HOLE resolution is backed by the inode's
//! `InlineExtentMap` (via `tidefs-extent-map`), which maintains a
//! sorted, non-overlapping list of allocated and hole extents per
//! file. The extent map already supports `seek_data(offset)` and
//! `seek_hole(offset)` queries with POSIX-correct semantics.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::lseek;
//!
//! let plan = lseek::plan_lseek(
//!     lseek::LseekMode::Data,
//!     0,
//!     42,
//! );
//! lseek::validate_lseek_whence(lseek::SEEK_DATA)?;
//! lseek::check_lseek_allowed(FileType::RegularFile)?;
//! // ... perform back-end seek via engine ...
//! ```

use libc::c_int;

use crate::FileType;

// ---------------------------------------------------------------------------
// SEEK_* constants -- only the FUSE-relevant modes
// ---------------------------------------------------------------------------

/// Seek to the next data region at or after the given offset.
pub const SEEK_DATA: i32 = 3;
/// Seek to the next hole region at or after the given offset.
pub const SEEK_HOLE: i32 = 4;
/// All recognised SEEK_* values for the FUSE lseek handler.
pub const SEEK_ALL_HANDLED: i32 = SEEK_DATA | SEEK_HOLE;

// ---------------------------------------------------------------------------
// Re-exports: standard errno codes for lseek error paths
// ---------------------------------------------------------------------------

pub use libc::{EBADF, EINVAL, ENXIO, EOVERFLOW};

// ---------------------------------------------------------------------------
// LseekMode
// ---------------------------------------------------------------------------

/// The semantic operation implied by a FUSE lseek `whence` argument.
///
/// - [`LseekMode::Data`]: `SEEK_DATA` -- find the next byte offset in
///   the file that contains data (i.e., is within an allocated extent).
/// - [`LseekMode::Hole`]: `SEEK_HOLE` -- find the next byte offset in
///   the file that is a hole (i.e., is not within an allocated extent).
///
/// SEEK_SET (0), SEEK_CUR (1), and SEEK_END (2) are handled by the
/// kernel VFS layer without reaching FUSE, so they are not represented
/// here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LseekMode {
    /// SEEK_DATA -- find next data region.
    Data,
    /// SEEK_HOLE -- find next hole region.
    Hole,
}

impl LseekMode {
    /// Returns `true` when the operation is SEEK_DATA.
    #[must_use]
    pub const fn is_data(self) -> bool {
        matches!(self, Self::Data)
    }

    /// Returns `true` when the operation is SEEK_HOLE.
    #[must_use]
    pub const fn is_hole(self) -> bool {
        matches!(self, Self::Hole)
    }

    /// Convert from the raw FUSE `whence` value.
    ///
    /// Returns `None` when `whence` is not SEEK_DATA or SEEK_HOLE.
    #[must_use]
    pub const fn from_whence(whence: i32) -> Option<Self> {
        match whence {
            SEEK_DATA => Some(Self::Data),
            SEEK_HOLE => Some(Self::Hole),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// LseekPlan -- structured lseek request
// ---------------------------------------------------------------------------

/// Planned lseek operation derived from FUSE lseek dispatch.
///
/// The plan carries the operation mode, the starting byte offset,
/// and the file handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LseekPlan {
    /// Whether this is SEEK_DATA or SEEK_HOLE.
    pub mode: LseekMode,
    /// Starting byte offset for the search.
    pub offset: u64,
    /// File handle (always present for FUSE lseek).
    pub fh: u64,
}

impl LseekPlan {
    /// Create a new lseek plan.
    #[must_use]
    pub const fn new(mode: LseekMode, offset: u64, fh: u64) -> Self {
        Self { mode, offset, fh }
    }
}

// ---------------------------------------------------------------------------
// validate_lseek_whence
// ---------------------------------------------------------------------------

/// Validate that a FUSE lseek `whence` value is one we handle.
///
/// The kernel VFS handles SEEK_SET (0), SEEK_CUR (1), and SEEK_END (2)
/// without dispatching to FUSE. Only SEEK_DATA (3) and SEEK_HOLE (4)
/// reach the FUSE layer. Any other `whence` value is invalid.
///
/// # Returns
///
/// `Ok(())` when `whence` is `SEEK_DATA` or `SEEK_HOLE`.
///
/// `Err(EINVAL)` when `whence` is anything else.
#[inline]
pub fn validate_lseek_whence(whence: i32) -> Result<(), c_int> {
    if whence == SEEK_DATA || whence == SEEK_HOLE {
        Ok(())
    } else {
        Err(EINVAL)
    }
}

// ---------------------------------------------------------------------------
// plan_lseek
// ---------------------------------------------------------------------------

/// Construct an [`LseekPlan`] from the operation mode and starting offset.
///
/// The `fh` is the file handle from the FUSE request. It should be
/// non-zero for a valid open file.
#[must_use]
pub fn plan_lseek(mode: LseekMode, offset: u64, fh: u64) -> LseekPlan {
    LseekPlan::new(mode, offset, fh)
}

// ---------------------------------------------------------------------------
// check_lseek_allowed -- file-kind validation
// ---------------------------------------------------------------------------

/// Check whether an lseek operation is allowed for the given [`FileType`].
///
/// Per POSIX, SEEK_DATA/SEEK_HOLE are only meaningful for regular files
/// and block devices.
///
/// # Returns
///
/// `Ok(())` for regular files and block devices.
///
/// `Err(EINVAL)` for directories, named pipes, sockets, character
/// devices, and symbolic links.
#[inline]
pub fn check_lseek_allowed(kind: FileType) -> Result<(), c_int> {
    match kind {
        FileType::RegularFile | FileType::BlockDevice => Ok(()),
        _ => Err(EINVAL),
    }
}

// ---------------------------------------------------------------------------
// check_lseek_readonly -- read-only mount guard (always passes for lseek)
// ---------------------------------------------------------------------------

/// Check whether an lseek operation is permitted on a read-only filesystem.
///
/// Lseek is always a read-only operation and does not mutate filesystem
/// state. This function exists for API consistency with other handlers
/// and always returns `Ok(())`.
///
/// # Returns
///
/// `Ok(())` in all cases.
#[inline]
pub const fn check_lseek_readonly(_read_only: bool) -> Result<(), c_int> {
    Ok(())
}

// ---------------------------------------------------------------------------
// LseekError
// ---------------------------------------------------------------------------

/// Errors that can occur during lseek request validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LseekError {
    /// The `whence` value is not SEEK_DATA or SEEK_HOLE.
    BadWhence,
    /// The file kind does not support SEEK_DATA/SEEK_HOLE
    /// (e.g., directory, pipe, socket).
    NotSeekable,
    /// The filesystem is mounted read-only (lseek is a read-only
    /// operation and this variant is provided for API consistency;
    /// it should not be returned in practice).
    ReadOnlyFilesystem,
}

impl LseekError {
    /// Convert this error to the matching POSIX errno value.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            Self::BadWhence => libc::EINVAL,
            Self::NotSeekable => libc::EINVAL,
            Self::ReadOnlyFilesystem => libc::EROFS,
        }
    }
}

impl std::fmt::Display for LseekError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadWhence => write!(f, "invalid lseek whence value"),
            Self::NotSeekable => write!(f, "lseek not supported for this file kind"),
            Self::ReadOnlyFilesystem => write!(f, "read-only filesystem"),
        }
    }
}

impl std::error::Error for LseekError {}

// ---------------------------------------------------------------------------
// handle_lseek -- canonical dispatch entry-point
// ---------------------------------------------------------------------------

/// Validate an lseek request and return a [`LseekPlan`] ready for backend
/// dispatch.
///
/// This is the preferred single-call entry point for FUSE daemon dispatch:
/// it validates the whence value, checks the file kind, and returns a
/// structured plan.  The read-only guard is always a no-op for lseek
/// (seek is a pure read operation) but is included for API consistency
/// with other `handle_*` wrappers.
///
/// # Errors
///
/// Returns [`LseekError::BadWhence`] when `whence` is not `SEEK_DATA` or
/// `SEEK_HOLE`.
///
/// Returns [`LseekError::NotSeekable`] when `kind` is a directory, pipe,
/// socket, character device, or symlink.
#[must_use = "validates the request and returns a LseekPlan ready for dispatch"]
pub fn handle_lseek(
    whence: i32,
    kind: FileType,
    read_only: bool,
    offset: u64,
    fh: u64,
) -> Result<LseekPlan, LseekError> {
    validate_lseek_whence(whence).map_err(|_| LseekError::BadWhence)?;
    check_lseek_allowed(kind).map_err(|_| LseekError::NotSeekable)?;
    let _ = check_lseek_readonly(read_only);
    let mode = LseekMode::from_whence(whence).unwrap_or(LseekMode::Data);
    Ok(plan_lseek(mode, offset, fh))
}

// ---------------------------------------------------------------------------
// SEEK_DATA / SEEK_HOLE extent-query logic
// ---------------------------------------------------------------------------

/// A lightweight extent representation for seek operations.
///
/// Each extent covers `[offset, offset + length)` and is either data
/// (`true`) or a hole / unwritten (`false`).  Extents must be sorted
/// by offset and non-overlapping.
pub type Extent = (u64, u64, bool);

/// Find the next data extent at or after `start_offset`.
///
/// Extents must be sorted by offset (ascending) and non-overlapping.
///
/// # Errors
///
/// Returns `ENXIO` when no data extent exists at or after `start_offset`.
pub fn seek_data(extents: &[Extent], start_offset: u64, file_size: u64) -> Result<u64, c_int> {
    if start_offset >= file_size {
        return Err(ENXIO);
    }

    for &(off, len, is_data) in extents {
        let end = off.saturating_add(len);
        if is_data && off <= start_offset && start_offset < end {
            return Ok(start_offset);
        }
        if off > start_offset && is_data {
            return Ok(off);
        }
    }

    Err(ENXIO)
}

/// Find the next hole at or after `start_offset`.
///
/// Extents must be sorted by offset (ascending) and non-overlapping.
/// Always succeeds: if no hole is found, returns `file_size`.
#[must_use]
pub fn seek_hole(extents: &[Extent], start_offset: u64, file_size: u64) -> u64 {
    if start_offset >= file_size {
        return start_offset;
    }

    let mut cursor = start_offset;

    for &(off, len, is_data) in extents {
        let end = off.saturating_add(len);

        if end <= cursor {
            continue;
        }

        if is_data {
            if off <= cursor && cursor < end {
                cursor = end;
                continue;
            }
            if off > cursor {
                return cursor;
            }
        } else if cursor < end {
            return cursor.max(off);
        }
    }

    cursor
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- LseekMode -------------------------------------------------------

    #[test]
    fn lseek_mode_is_data() {
        assert!(LseekMode::Data.is_data());
        assert!(!LseekMode::Data.is_hole());
    }

    #[test]
    fn lseek_mode_is_hole() {
        assert!(LseekMode::Hole.is_hole());
        assert!(!LseekMode::Hole.is_data());
    }

    #[test]
    fn lseek_mode_from_whence_data() {
        assert_eq!(LseekMode::from_whence(SEEK_DATA), Some(LseekMode::Data));
    }

    #[test]
    fn lseek_mode_from_whence_hole() {
        assert_eq!(LseekMode::from_whence(SEEK_HOLE), Some(LseekMode::Hole));
    }

    #[test]
    fn lseek_mode_from_whence_invalid() {
        assert_eq!(LseekMode::from_whence(0), None); // SEEK_SET
        assert_eq!(LseekMode::from_whence(1), None); // SEEK_CUR
        assert_eq!(LseekMode::from_whence(2), None); // SEEK_END
        assert_eq!(LseekMode::from_whence(-1), None);
        assert_eq!(LseekMode::from_whence(99), None);
    }

    // -- LseekPlan -------------------------------------------------------

    #[test]
    fn lseek_plan_new() {
        let plan = LseekPlan::new(LseekMode::Data, 4096, 42);
        assert_eq!(plan.mode, LseekMode::Data);
        assert_eq!(plan.offset, 4096);
        assert_eq!(plan.fh, 42);
    }

    #[test]
    fn lseek_plan_zero_offset() {
        let plan = LseekPlan::new(LseekMode::Hole, 0, 1);
        assert_eq!(plan.mode, LseekMode::Hole);
        assert_eq!(plan.offset, 0);
    }

    // -- validate_lseek_whence -------------------------------------------

    #[test]
    fn validate_whence_data_ok() {
        assert_eq!(validate_lseek_whence(SEEK_DATA), Ok(()));
    }

    #[test]
    fn validate_whence_hole_ok() {
        assert_eq!(validate_lseek_whence(SEEK_HOLE), Ok(()));
    }

    #[test]
    fn validate_whence_invalid() {
        assert_eq!(validate_lseek_whence(0), Err(EINVAL));
        assert_eq!(validate_lseek_whence(1), Err(EINVAL));
        assert_eq!(validate_lseek_whence(2), Err(EINVAL));
        assert_eq!(validate_lseek_whence(5), Err(EINVAL));
        assert_eq!(validate_lseek_whence(-1), Err(EINVAL));
    }

    // -- plan_lseek ------------------------------------------------------

    #[test]
    fn plan_lseek_data() {
        let plan = plan_lseek(LseekMode::Data, 1024, 7);
        assert_eq!(plan.mode, LseekMode::Data);
        assert_eq!(plan.offset, 1024);
        assert_eq!(plan.fh, 7);
    }

    #[test]
    fn plan_lseek_hole() {
        let plan = plan_lseek(LseekMode::Hole, 0, 3);
        assert_eq!(plan.mode, LseekMode::Hole);
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.fh, 3);
    }

    // -- check_lseek_allowed --------------------------------------------

    #[test]
    fn lseek_allowed_on_regular_file() {
        assert_eq!(check_lseek_allowed(FileType::RegularFile), Ok(()));
    }

    #[test]
    fn lseek_allowed_on_block_device() {
        assert_eq!(check_lseek_allowed(FileType::BlockDevice), Ok(()));
    }

    #[test]
    fn lseek_denied_on_directory() {
        assert_eq!(check_lseek_allowed(FileType::Directory), Err(EINVAL));
    }

    #[test]
    fn lseek_denied_on_named_pipe() {
        assert_eq!(check_lseek_allowed(FileType::NamedPipe), Err(EINVAL));
    }

    #[test]
    fn lseek_denied_on_socket() {
        assert_eq!(check_lseek_allowed(FileType::Socket), Err(EINVAL));
    }

    #[test]
    fn lseek_denied_on_char_device() {
        assert_eq!(check_lseek_allowed(FileType::CharDevice), Err(EINVAL));
    }

    #[test]
    fn lseek_denied_on_symlink() {
        assert_eq!(check_lseek_allowed(FileType::Symlink), Err(EINVAL));
    }

    // -- check_lseek_readonly -------------------------------------------

    #[test]
    fn ro_mount_allows_lseek() {
        assert_eq!(check_lseek_readonly(true), Ok(()));
    }

    #[test]
    fn rw_mount_allows_lseek() {
        assert_eq!(check_lseek_readonly(false), Ok(()));
    }

    // -- integration: plan + validate + check pattern -------------------

    #[test]
    fn valid_lseek_passes_all_checks() {
        let plan = plan_lseek(LseekMode::Data, 0, 5);
        assert!(validate_lseek_whence(SEEK_DATA).is_ok());
        assert!(check_lseek_allowed(FileType::RegularFile).is_ok());
        assert!(check_lseek_readonly(true).is_ok());
        assert_eq!(plan.offset, 0);
    }

    #[test]
    fn valid_lseek_hole_passes_all_checks() {
        let plan = plan_lseek(LseekMode::Hole, 8192, 9);
        assert!(validate_lseek_whence(SEEK_HOLE).is_ok());
        assert!(check_lseek_allowed(FileType::BlockDevice).is_ok());
        assert!(check_lseek_readonly(false).is_ok());
        assert_eq!(plan.offset, 8192);
    }

    // -- LseekError ----------------------------------------------------

    #[test]
    fn lseek_error_to_errno() {
        assert_eq!(LseekError::BadWhence.to_errno(), libc::EINVAL);
        assert_eq!(LseekError::NotSeekable.to_errno(), libc::EINVAL);
        assert_eq!(LseekError::ReadOnlyFilesystem.to_errno(), libc::EROFS);
    }

    #[test]
    fn lseek_error_display() {
        assert_eq!(
            format!("{}", LseekError::BadWhence),
            "invalid lseek whence value"
        );
        assert_eq!(
            format!("{}", LseekError::NotSeekable),
            "lseek not supported for this file kind"
        );
    }

    // -- handle_lseek --------------------------------------------------

    #[test]
    fn handle_lseek_valid_seek_data() {
        let plan = handle_lseek(SEEK_DATA, FileType::RegularFile, false, 0, 42);
        assert!(plan.is_ok());
        let plan = plan.unwrap();
        assert_eq!(plan.mode, LseekMode::Data);
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.fh, 42);
    }

    #[test]
    fn handle_lseek_valid_seek_hole() {
        let plan = handle_lseek(SEEK_HOLE, FileType::BlockDevice, true, 8192, 7);
        assert!(plan.is_ok());
        let plan = plan.unwrap();
        assert_eq!(plan.mode, LseekMode::Hole);
        assert_eq!(plan.offset, 8192);
        assert_eq!(plan.fh, 7);
    }

    #[test]
    fn handle_lseek_bad_whence() {
        let result = handle_lseek(0, FileType::RegularFile, false, 0, 1);
        assert_eq!(result, Err(LseekError::BadWhence));
    }

    #[test]
    fn handle_lseek_not_seekable_dir() {
        let result = handle_lseek(SEEK_DATA, FileType::Directory, false, 0, 1);
        assert_eq!(result, Err(LseekError::NotSeekable));
    }

    #[test]
    fn handle_lseek_not_seekable_pipe() {
        let result = handle_lseek(SEEK_HOLE, FileType::NamedPipe, true, 0, 1);
        assert_eq!(result, Err(LseekError::NotSeekable));
    }

    #[test]
    fn handle_lseek_not_seekable_socket() {
        let result = handle_lseek(SEEK_DATA, FileType::Socket, false, 0, 1);
        assert_eq!(result, Err(LseekError::NotSeekable));
    }

    #[test]
    fn handle_lseek_read_only_noop() {
        // Read-only mount still allows lseek (pure read operation)
        let plan = handle_lseek(SEEK_DATA, FileType::RegularFile, true, 1024, 5);
        assert!(plan.is_ok());
        assert_eq!(plan.unwrap().offset, 1024);
    }

    // -- seek_data / seek_hole extent-query tests -----------------

    fn d(offset: u64, length: u64) -> Extent {
        (offset, length, true)
    }

    fn h(offset: u64, length: u64) -> Extent {
        (offset, length, false)
    }

    #[test]
    fn seek_data_offset_inside_data_extent() {
        let extents = &[d(0, 4096), d(8192, 8192)];
        assert_eq!(seek_data(extents, 2048, 16384), Ok(2048));
    }

    #[test]
    fn seek_data_offset_in_hole_finds_next_data() {
        let extents = &[h(0, 4096), d(4096, 4096)];
        assert_eq!(seek_data(extents, 0, 8192), Ok(4096));
    }

    #[test]
    fn seek_data_no_data_beyond_offset() {
        let extents = &[d(0, 4096)];
        assert_eq!(seek_data(extents, 4096, 4096), Err(ENXIO));
    }

    #[test]
    fn seek_data_empty_extent_list() {
        let extents: &[Extent] = &[];
        assert_eq!(seek_data(extents, 0, 4096), Err(ENXIO));
    }

    #[test]
    fn seek_data_at_or_past_eof() {
        let extents = &[d(0, 4096)];
        assert_eq!(seek_data(extents, 4096, 4096), Err(ENXIO));
        assert_eq!(seek_data(extents, 8192, 4096), Err(ENXIO));
    }

    #[test]
    fn seek_data_alternating_data_hole() {
        let extents = &[d(0, 4096), h(4096, 4096), d(8192, 4096), h(12288, 4096)];
        assert_eq!(seek_data(extents, 5000, 16384), Ok(8192));
        assert_eq!(seek_data(extents, 13000, 16384), Err(ENXIO));
    }

    #[test]
    fn seek_hole_inside_data_returns_end() {
        let extents = &[d(0, 4096), d(8192, 4096)];
        assert_eq!(seek_hole(extents, 0, 16384), 4096);
    }

    #[test]
    fn seek_hole_no_hole_returns_file_size() {
        let extents = &[d(0, 4096)];
        assert_eq!(seek_hole(extents, 0, 4096), 4096);
    }

    #[test]
    fn seek_hole_past_eof_returns_offset() {
        let extents = &[d(0, 4096)];
        assert_eq!(seek_hole(extents, 8192, 4096), 8192);
    }

    #[test]
    fn seek_hole_empty_file_is_all_hole() {
        let extents: &[Extent] = &[];
        assert_eq!(seek_hole(extents, 0, 8192), 0);
    }

    #[test]
    fn seek_hole_alternating_data_hole() {
        let extents = &[d(0, 4096), h(4096, 4096), d(8192, 4096)];
        assert_eq!(seek_hole(extents, 0, 16384), 4096);
        assert_eq!(seek_hole(extents, 5000, 16384), 5000);
        assert_eq!(seek_hole(extents, 9000, 16384), 12288);
    }

    #[test]
    fn seek_data_zero_length_file() {
        assert_eq!(seek_data(&[], 0, 0), Err(ENXIO));
    }

    #[test]
    fn seek_hole_zero_length_file() {
        assert_eq!(seek_hole(&[], 0, 0), 0);
    }
}
