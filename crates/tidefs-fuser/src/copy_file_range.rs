//! FUSE `copy_file_range` handler helpers -- source/destination offset
//! validation, range-overlap detection, and convenience entry-points for
//! server-side copy offload.
//!
//! The kernel routes `copy_file_range(2)` into the FUSE `copy_file_range`
//! handler when two open file handles on the same mounted filesystem are
//! the source and destination.  This module provides the foundational
//! validation helpers that the upper-level filesystem adapter calls before
//! delegating to the VFS engine's byte-range copy primitive.
//!
//! Provides:
//! - [`validate_copy_file_range_offsets`]: reject negative offsets and zero
//!   length.
//! - [`check_copy_file_range_ranges_overlap`]: detect same-inode
//!   overlapping source/destination regions.
//! - [`plan_copy_file_range`]: combined validation producing a
//!   [`CopyFileRangePlan`].
//! - [`handle_copy_file_range`]: canonical dispatch entry-point with
//!   read-only filesystem guard.

use libc::c_int;

/// Maximum length for a copy_file_range operation.
///
/// Linux allows up to `i64::MAX` bytes since `loff_t` is signed
/// 64-bit.  Values above this cannot be represented in the kernel's
/// signed offset type.
pub const COPY_FILE_RANGE_MAX_LEN: u64 = i64::MAX as u64;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by copy_file_range validation helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyFileRangeError {
    /// A source or destination offset was negative (i64 < 0).
    NegativeOffset {
        /// Which offset was negative: `"src"` or `"dest"`.
        side: &'static str,
    },
    /// The copy length is zero.  POSIX: zero-length copy_file_range is
    /// a no-op and the kernel may choose not to issue the FUSE
    /// request; if it does, it is invalid.
    ZeroLength,
    /// The copy length exceeds [`COPY_FILE_RANGE_MAX_LEN`].
    LengthExceedsMaximum,
    /// Source and destination ranges overlap on the same inode.
    /// POSIX: overlapping ranges within the same file produce
    /// undefined results; reject with EINVAL to prevent corruption.
    RangesOverlap,
    /// The filesystem is mounted read-only.
    ReadOnlyFilesystem,
}

impl CopyFileRangeError {
    /// Return a stable snake_case string for logging / tracing.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NegativeOffset { .. } => "negative_offset",
            Self::ZeroLength => "zero_length",
            Self::LengthExceedsMaximum => "length_exceeds_maximum",
            Self::RangesOverlap => "ranges_overlap",
            Self::ReadOnlyFilesystem => "read_only_filesystem",
        }
    }

    /// Convert to a POSIX errno value suitable for FUSE replies.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            Self::ReadOnlyFilesystem => libc::EROFS,
            _ => libc::EINVAL,
        }
    }
}

impl std::fmt::Display for CopyFileRangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NegativeOffset { side } => {
                write!(f, "negative {side} offset in copy_file_range")
            }
            Self::ZeroLength => {
                write!(f, "copy_file_range with zero length")
            }
            Self::LengthExceedsMaximum => {
                write!(
                    f,
                    "copy_file_range length exceeds maximum ({COPY_FILE_RANGE_MAX_LEN})"
                )
            }
            Self::RangesOverlap => {
                write!(
                    f,
                    "copy_file_range source and destination ranges overlap on the same inode"
                )
            }
            Self::ReadOnlyFilesystem => {
                write!(f, "read-only filesystem")
            }
        }
    }
}

impl std::error::Error for CopyFileRangeError {}

// ---------------------------------------------------------------------------
// Plan type
// ---------------------------------------------------------------------------

/// Validated plan for a copy_file_range operation.
///
/// All fields have passed basic sanity checks (offsets non-negative,
/// length > 0, no same-inode overlap).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyFileRangePlan {
    /// Source inode number.
    pub ino_in: u64,
    /// Source file handle.
    pub fh_in: u64,
    /// Source byte offset.
    pub offset_in: u64,
    /// Destination inode number.
    pub ino_out: u64,
    /// Destination file handle.
    pub fh_out: u64,
    /// Destination byte offset.
    pub offset_out: u64,
    /// Number of bytes to copy.
    pub len: u64,
    /// Raw flags from the FUSE request (currently reserved; must be 0
    /// per the kernel UAPI).
    pub flags: u32,
}

/// Inputs for FUSE `copy_file_range` dispatch validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyFileRangeRequest {
    /// Source inode number.
    pub ino_in: u64,
    /// Source file handle.
    pub fh_in: u64,
    /// Source byte offset.
    pub offset_in: i64,
    /// Destination inode number.
    pub ino_out: u64,
    /// Destination file handle.
    pub fh_out: u64,
    /// Destination byte offset.
    pub offset_out: i64,
    /// Number of bytes to copy.
    pub len: u64,
    /// Raw flags from the FUSE request.
    pub flags: u32,
    /// Whether the filesystem is mounted read-only.
    pub read_only: bool,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate source and destination offsets for copy_file_range.
///
/// The kernel passes offsets as `i64` (signed) in the FUSE wire protocol.
/// Negative offsets are rejected with [`CopyFileRangeError::NegativeOffset`].
/// Zero length is rejected with [`CopyFileRangeError::ZeroLength`].
/// Lengths exceeding [`COPY_FILE_RANGE_MAX_LEN`] are rejected with
/// [`CopyFileRangeError::LengthExceedsMaximum`].
pub fn validate_copy_file_range_offsets(
    offset_in: i64,
    offset_out: i64,
    len: u64,
) -> Result<(u64, u64), CopyFileRangeError> {
    if offset_in < 0 {
        return Err(CopyFileRangeError::NegativeOffset { side: "src" });
    }
    if offset_out < 0 {
        return Err(CopyFileRangeError::NegativeOffset { side: "dest" });
    }
    if len == 0 {
        return Err(CopyFileRangeError::ZeroLength);
    }
    if len > COPY_FILE_RANGE_MAX_LEN {
        return Err(CopyFileRangeError::LengthExceedsMaximum);
    }
    Ok((offset_in as u64, offset_out as u64))
}

/// Check whether two byte ranges on the same inode overlap.
///
/// Returns `true` if the intervals `[start_a, start_a + len)` and
/// `[start_b, start_b + len)` share at least one byte.
/// Returns `false` if the ranges are disjoint or if `len == 0`.
///
/// Overflow-safe via `checked_add` on the interval endpoints.
#[must_use]
pub fn check_copy_file_range_ranges_overlap(start_a: u64, start_b: u64, len: u64) -> bool {
    if len == 0 {
        return false;
    }
    let Some(end_a) = start_a.checked_add(len) else {
        return true;
    };
    let Some(end_b) = start_b.checked_add(len) else {
        return true;
    };
    start_a < end_b && start_b < end_a
}

// ---------------------------------------------------------------------------
// Combined planning
// ---------------------------------------------------------------------------

/// Validate and produce a [`CopyFileRangePlan`].
///
/// # Errors
///
/// Returns [`CopyFileRangeError`] when any validation check fails.
#[allow(clippy::too_many_arguments)]
pub fn plan_copy_file_range(
    ino_in: u64,
    fh_in: u64,
    offset_in: i64,
    ino_out: u64,
    fh_out: u64,
    offset_out: i64,
    len: u64,
    flags: u32,
) -> Result<CopyFileRangePlan, CopyFileRangeError> {
    let (uoff_in, uoff_out) = validate_copy_file_range_offsets(offset_in, offset_out, len)?;

    if ino_in == ino_out && check_copy_file_range_ranges_overlap(uoff_in, uoff_out, len) {
        return Err(CopyFileRangeError::RangesOverlap);
    }

    Ok(CopyFileRangePlan {
        ino_in,
        fh_in,
        offset_in: uoff_in,
        ino_out,
        fh_out,
        offset_out: uoff_out,
        len,
        flags,
    })
}

// ---------------------------------------------------------------------------
// Canonical dispatch entry-point
// ---------------------------------------------------------------------------

/// Canonical dispatch entry-point for FUSE `copy_file_range`.
///
/// Combines a read-only filesystem guard with the full validation
/// pipeline of [`plan_copy_file_range`].  Returns a [`CopyFileRangePlan`]
/// ready for delegation to the VFS engine byte-range copy primitive.
///
/// # Errors
///
/// Returns [`CopyFileRangeError::ReadOnlyFilesystem`] when `read_only`
/// is `true`.
/// Returns other [`CopyFileRangeError`] variants when validation fails.
pub fn handle_copy_file_range(
    request: CopyFileRangeRequest,
) -> Result<CopyFileRangePlan, CopyFileRangeError> {
    if request.read_only {
        return Err(CopyFileRangeError::ReadOnlyFilesystem);
    }
    plan_copy_file_range(
        request.ino_in,
        request.fh_in,
        request.offset_in,
        request.ino_out,
        request.fh_out,
        request.offset_out,
        request.len,
        request.flags,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- CopyFileRangeError -----------------------------------------------

    #[test]
    fn error_as_str_is_stable() {
        assert_eq!(
            CopyFileRangeError::NegativeOffset { side: "src" }.as_str(),
            "negative_offset"
        );
        assert_eq!(CopyFileRangeError::ZeroLength.as_str(), "zero_length");
        assert_eq!(
            CopyFileRangeError::LengthExceedsMaximum.as_str(),
            "length_exceeds_maximum"
        );
        assert_eq!(CopyFileRangeError::RangesOverlap.as_str(), "ranges_overlap");
        assert_eq!(
            CopyFileRangeError::ReadOnlyFilesystem.as_str(),
            "read_only_filesystem"
        );
    }

    #[test]
    fn error_errno_always_einval() {
        for err in &[
            CopyFileRangeError::NegativeOffset { side: "src" },
            CopyFileRangeError::NegativeOffset { side: "dest" },
            CopyFileRangeError::ZeroLength,
            CopyFileRangeError::LengthExceedsMaximum,
            CopyFileRangeError::RangesOverlap,
        ] {
            assert_eq!(err.to_errno(), libc::EINVAL);
        }
    }

    #[test]
    fn error_read_only_filesystem_maps_to_erofs() {
        assert_eq!(
            CopyFileRangeError::ReadOnlyFilesystem.to_errno(),
            libc::EROFS
        );
    }

    #[test]
    fn error_display_contains_context() {
        let s = CopyFileRangeError::NegativeOffset { side: "src" }.to_string();
        assert!(s.contains("src"));
        assert!(s.contains("negative"));

        let s = CopyFileRangeError::ZeroLength.to_string();
        assert!(s.contains("zero"));

        let s = CopyFileRangeError::LengthExceedsMaximum.to_string();
        assert!(s.contains("exceeds"));

        let s = CopyFileRangeError::RangesOverlap.to_string();
        assert!(s.contains("overlap"));

        let s = CopyFileRangeError::ReadOnlyFilesystem.to_string();
        assert!(s.contains("read-only"));
    }

    #[test]
    fn error_implements_std_error() {
        let e: &dyn std::error::Error = &CopyFileRangeError::ZeroLength;
        let _ = e.to_string();
    }

    // -- validate_copy_file_range_offsets ---------------------------------

    #[test]
    fn valid_offsets_pass() {
        let result = validate_copy_file_range_offsets(0, 0, 4096);
        assert_eq!(result, Ok((0, 0)));

        let result = validate_copy_file_range_offsets(1024, 2048, 65536);
        assert_eq!(result, Ok((1024, 2048)));
    }

    #[test]
    fn zero_length_rejected() {
        let result = validate_copy_file_range_offsets(0, 0, 0);
        assert_eq!(result, Err(CopyFileRangeError::ZeroLength));
    }

    #[test]
    fn negative_src_offset_rejected() {
        let result = validate_copy_file_range_offsets(-1, 0, 4096);
        assert_eq!(
            result,
            Err(CopyFileRangeError::NegativeOffset { side: "src" })
        );
    }

    #[test]
    fn negative_dest_offset_rejected() {
        let result = validate_copy_file_range_offsets(0, -1, 4096);
        assert_eq!(
            result,
            Err(CopyFileRangeError::NegativeOffset { side: "dest" })
        );
    }

    #[test]
    fn both_negative_reports_src_first() {
        let result = validate_copy_file_range_offsets(-5, -3, 4096);
        assert_eq!(
            result,
            Err(CopyFileRangeError::NegativeOffset { side: "src" })
        );
    }

    #[test]
    fn large_offset_at_i64_max_passes() {
        let big: i64 = i64::MAX;
        let result = validate_copy_file_range_offsets(big, big, 1);
        assert_eq!(result, Ok((big as u64, big as u64)));
    }

    #[test]
    fn length_exceeds_maximum_rejected() {
        let result = validate_copy_file_range_offsets(0, 0, COPY_FILE_RANGE_MAX_LEN + 1);
        assert_eq!(result, Err(CopyFileRangeError::LengthExceedsMaximum));
    }

    #[test]
    fn length_at_maximum_passes() {
        let result = validate_copy_file_range_offsets(0, 0, COPY_FILE_RANGE_MAX_LEN);
        assert!(result.is_ok());
    }

    #[test]
    fn length_one_passes() {
        let result = validate_copy_file_range_offsets(0, 0, 1);
        assert_eq!(result, Ok((0, 0)));
    }

    // -- check_copy_file_range_ranges_overlap -----------------------------

    #[test]
    fn zero_len_never_overlaps() {
        assert!(!check_copy_file_range_ranges_overlap(0, 0, 0));
        assert!(!check_copy_file_range_ranges_overlap(10, 10, 0));
        assert!(!check_copy_file_range_ranges_overlap(u64::MAX, u64::MAX, 0));
    }

    #[test]
    fn identical_ranges_overlap() {
        assert!(check_copy_file_range_ranges_overlap(0, 0, 4096));
        assert!(check_copy_file_range_ranges_overlap(100, 100, 50));
    }

    #[test]
    fn partial_overlap_touching_start() {
        // src: [0, 100), dst: [50, 150) => overlap [50, 100)
        assert!(check_copy_file_range_ranges_overlap(0, 50, 100));
    }

    #[test]
    fn partial_overlap_touching_end() {
        // src: [50, 150), dst: [0, 100) => overlap [50, 100)
        assert!(check_copy_file_range_ranges_overlap(50, 0, 100));
    }

    #[test]
    fn src_before_dst_no_overlap() {
        // src: [0, 100), dst: [100, 200) => no overlap
        assert!(!check_copy_file_range_ranges_overlap(0, 100, 100));
    }

    #[test]
    fn dst_before_src_no_overlap() {
        // src: [100, 200), dst: [0, 100) => no overlap
        assert!(!check_copy_file_range_ranges_overlap(100, 0, 100));
    }

    #[test]
    fn far_apart_no_overlap() {
        assert!(!check_copy_file_range_ranges_overlap(0, 1000000, 4096));
    }

    #[test]
    fn src_contains_dst() {
        // src: [0, 200), dst: [50, 100) => overlap
        assert!(check_copy_file_range_ranges_overlap(0, 50, 200));
    }

    #[test]
    fn dst_contains_src() {
        // src: [50, 100), dst: [0, 200) => overlap
        assert!(check_copy_file_range_ranges_overlap(50, 0, 200));
    }

    #[test]
    fn adjacent_non_overlapping() {
        // src: [0, 50), dst: [50, 50) => [0, 50) and [50, 100) -- no overlap
        assert!(!check_copy_file_range_ranges_overlap(0, 50, 50));
    }

    #[test]
    fn overflow_end_a_returns_true() {
        // start_a + len overflows u64 => treat as overlap
        assert!(check_copy_file_range_ranges_overlap(u64::MAX, 0, 2));
    }

    #[test]
    fn overflow_end_b_returns_true() {
        assert!(check_copy_file_range_ranges_overlap(0, u64::MAX, 2));
    }

    // -- plan_copy_file_range ---------------------------------------------

    #[test]
    fn plan_valid_non_overlapping() {
        let plan = plan_copy_file_range(1, 10, 0, 2, 20, 0, 4096, 0).unwrap();
        assert_eq!(plan.ino_in, 1);
        assert_eq!(plan.fh_in, 10);
        assert_eq!(plan.offset_in, 0);
        assert_eq!(plan.ino_out, 2);
        assert_eq!(plan.fh_out, 20);
        assert_eq!(plan.offset_out, 0);
        assert_eq!(plan.len, 4096);
        assert_eq!(plan.flags, 0);
    }

    #[test]
    fn plan_rejects_overlapping_same_inode() {
        let result = plan_copy_file_range(1, 10, 0, 1, 20, 50, 100, 0);
        assert_eq!(result, Err(CopyFileRangeError::RangesOverlap));
    }

    #[test]
    fn plan_allows_same_inode_non_overlapping() {
        // src: [0, 100), dst: [100, 200) -- no overlap
        let plan = plan_copy_file_range(1, 10, 0, 1, 20, 100, 100, 0);
        assert!(plan.is_ok());
    }

    #[test]
    fn plan_rejects_zero_length() {
        let result = plan_copy_file_range(1, 10, 0, 2, 20, 0, 0, 0);
        assert_eq!(result, Err(CopyFileRangeError::ZeroLength));
    }

    #[test]
    fn plan_rejects_negative_src() {
        let result = plan_copy_file_range(1, 10, -1, 2, 20, 0, 4096, 0);
        assert_eq!(
            result,
            Err(CopyFileRangeError::NegativeOffset { side: "src" })
        );
    }

    #[test]
    fn plan_rejects_negative_dst() {
        let result = plan_copy_file_range(1, 10, 0, 2, 20, -1, 4096, 0);
        assert_eq!(
            result,
            Err(CopyFileRangeError::NegativeOffset { side: "dest" })
        );
    }

    #[test]
    fn plan_respects_flags_field() {
        let plan = plan_copy_file_range(1, 10, 0, 2, 20, 100, 4096, 0xDEAD).unwrap();
        assert_eq!(plan.flags, 0xDEAD);
    }

    #[test]
    fn plan_rejects_length_exceeds_max() {
        let result = plan_copy_file_range(1, 10, 0, 2, 20, 0, COPY_FILE_RANGE_MAX_LEN + 1, 0);
        assert_eq!(result, Err(CopyFileRangeError::LengthExceedsMaximum));
    }

    // -- CopyFileRangePlan structural -------------------------------------

    #[test]
    fn plan_is_clone_and_debug() {
        let plan = CopyFileRangePlan {
            ino_in: 1,
            fh_in: 2,
            offset_in: 3,
            ino_out: 4,
            fh_out: 5,
            offset_out: 6,
            len: 7,
            flags: 8,
        };
        let plan2 = plan;
        assert_eq!(plan, plan2);
        let _ = format!("{plan:?}");
    }

    #[test]
    fn plan_offsets_are_non_negative() {
        // plan_copy_file_range guarantees unsigned offsets
        let plan = plan_copy_file_range(10, 100, 0, 20, 200, 0, 4096, 0).unwrap();
        assert!(plan.offset_in < u64::MAX);
        assert!(plan.offset_out < u64::MAX);
    }

    // -- handle_copy_file_range -------------------------------------------

    #[test]
    fn handle_success_non_overlapping() {
        let plan = handle_copy_file_range(CopyFileRangeRequest {
            ino_in: 1,
            fh_in: 10,
            offset_in: 0,
            ino_out: 2,
            fh_out: 20,
            offset_out: 0,
            len: 4096,
            flags: 0,
            read_only: false,
        })
        .unwrap();
        assert_eq!(plan.ino_in, 1);
        assert_eq!(plan.fh_in, 10);
        assert_eq!(plan.offset_in, 0);
        assert_eq!(plan.ino_out, 2);
        assert_eq!(plan.fh_out, 20);
        assert_eq!(plan.offset_out, 0);
        assert_eq!(plan.len, 4096);
        assert_eq!(plan.flags, 0);
    }

    #[test]
    fn handle_rejects_read_only() {
        let result = handle_copy_file_range(CopyFileRangeRequest {
            ino_in: 1,
            fh_in: 10,
            offset_in: 0,
            ino_out: 2,
            fh_out: 20,
            offset_out: 0,
            len: 4096,
            flags: 0,
            read_only: true,
        });
        assert_eq!(result, Err(CopyFileRangeError::ReadOnlyFilesystem));
    }

    #[test]
    fn handle_read_only_priority_over_other_errors() {
        // read-only is checked before offset validation
        let result = handle_copy_file_range(CopyFileRangeRequest {
            ino_in: 1,
            fh_in: 10,
            offset_in: -1,
            ino_out: 2,
            fh_out: 20,
            offset_out: 0,
            len: 4096,
            flags: 0,
            read_only: true,
        });
        assert_eq!(result, Err(CopyFileRangeError::ReadOnlyFilesystem));
    }

    #[test]
    fn handle_propagates_validation_error() {
        let result = handle_copy_file_range(CopyFileRangeRequest {
            ino_in: 1,
            fh_in: 10,
            offset_in: -1,
            ino_out: 2,
            fh_out: 20,
            offset_out: 0,
            len: 4096,
            flags: 0,
            read_only: false,
        });
        assert_eq!(
            result,
            Err(CopyFileRangeError::NegativeOffset { side: "src" })
        );
    }

    #[test]
    fn handle_preserves_flags() {
        let plan = handle_copy_file_range(CopyFileRangeRequest {
            ino_in: 1,
            fh_in: 10,
            offset_in: 0,
            ino_out: 2,
            fh_out: 20,
            offset_out: 100,
            len: 4096,
            flags: 0xDEAD,
            read_only: false,
        })
        .unwrap();
        assert_eq!(plan.flags, 0xDEAD);
    }
}
