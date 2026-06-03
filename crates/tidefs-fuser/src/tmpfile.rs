//! FUSE `tmpfile` (O_TMPFILE) handler helpers — anonymous temporary file
//! creation, parent-directory validation, and mode processing.
//!
//! O_TMPFILE creates an unnamed regular file in a directory that can later
//! be linked into the namespace via `linkat(AT_FCHDIR, ..., AT_EMPTY_PATH)`.
//! This is the atomic-create primitive used by systemd, databases, and
//! container runtimes.
//!
//! # Validation checks
//!
//! 1. Parent must be a directory — non-directory kinds rejected with
//!    `ENOTDIR`.
//! 2. Parent must not be on a read-only mount — returns `EROFS`.
//! 3. Mode is stripped of file-type bits (`S_IFMT`) and high bits, then
//!    gated through umask.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::tmpfile;
//!
//! let plan = tmpfile::plan_tmpfile(true, false, 0o644, 0o022)?;
//! // plan.mode contains the masked mode
//! ```

use crate::errno;
use libc::c_int;
use std::fmt;

// ---------------------------------------------------------------------------
// TmpfileError — domain error type for O_TMPFILE operations
// ---------------------------------------------------------------------------

/// Errors that can occur during O_TMPFILE parent-directory validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TmpfileError {
    /// The parent inode is not a directory.
    NotADirectory,
    /// The parent directory is on a read-only filesystem.
    ReadOnlyFilesystem,
}

impl TmpfileError {
    /// Convert this error to the matching POSIX errno value.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            TmpfileError::NotADirectory => errno::ENOTDIR,
            TmpfileError::ReadOnlyFilesystem => errno::EROFS,
        }
    }
}

impl fmt::Display for TmpfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TmpfileError::NotADirectory => {
                write!(f, "parent is not a directory")
            }
            TmpfileError::ReadOnlyFilesystem => {
                write!(f, "read-only filesystem")
            }
        }
    }
}

impl std::error::Error for TmpfileError {}

impl From<TmpfileError> for c_int {
    fn from(e: TmpfileError) -> c_int {
        e.to_errno()
    }
}

// ---------------------------------------------------------------------------
// TmpfilePlan — validated planning result
// ---------------------------------------------------------------------------

/// Result of planning an O_TMPFILE creation after all validation passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TmpfilePlan {
    /// Mode with file-type bits and high bits stripped, filtered through
    /// umask.
    pub mode: u32,
}

impl TmpfilePlan {
    /// Create a plan from a pre-validated mode.
    #[must_use]
    pub fn new(mode: u32) -> Self {
        Self { mode }
    }
}

// ---------------------------------------------------------------------------
// Validation functions
// ---------------------------------------------------------------------------

/// Reject parent inode kinds that are not directories.
///
/// Returns `Err(`[`TmpfileError::NotADirectory`]`)` when `is_dir` is false.
/// Returns `Ok(())` when the parent is a directory.
pub fn check_tmpfile_allowed(is_dir: bool) -> Result<(), TmpfileError> {
    if !is_dir {
        return Err(TmpfileError::NotADirectory);
    }
    Ok(())
}

/// Reject read-only mounts.
///
/// Returns `Err(`[`TmpfileError::ReadOnlyFilesystem`]`)` when `readonly` is
/// true.  Returns `Ok(())` for read-write mounts.
pub fn check_tmpfile_readonly(readonly: bool) -> Result<(), TmpfileError> {
    if readonly {
        return Err(TmpfileError::ReadOnlyFilesystem);
    }
    Ok(())
}

/// Strip file-type and high bits from `mode` and apply `umask`.
///
/// POSIX requires that only the low 12 permission bits (`0o7777`) survive
/// after masking with `!umask`.  The file-type field (`S_IFMT`) is never
/// accepted from userspace.
#[must_use]
pub fn mask_tmpfile_mode(mode: u32, umask: u32) -> u32 {
    (mode & 0o7777) & !umask
}

// ---------------------------------------------------------------------------
// Combined validation
// ---------------------------------------------------------------------------

/// Plan an O_TMPFILE creation with full validation.
///
/// Checks:
/// 1. Parent is a directory — else [`TmpfileError::NotADirectory`].
/// 2. Parent is not read-only — else [`TmpfileError::ReadOnlyFilesystem`].
/// 3. Mode is stripped of file-type and high bits, then masked through umask.
///
/// Returns a [`TmpfilePlan`] with the computed mode on success.
pub fn plan_tmpfile(
    parent_is_dir: bool,
    parent_readonly: bool,
    mode: u32,
    umask: u32,
) -> Result<TmpfilePlan, TmpfileError> {
    check_tmpfile_allowed(parent_is_dir)?;
    check_tmpfile_readonly(parent_readonly)?;
    let masked = mask_tmpfile_mode(mode, umask);
    Ok(TmpfilePlan::new(masked))
}

// ---------------------------------------------------------------------------
// Canonical dispatch entry point
// ---------------------------------------------------------------------------

/// Canonical O_TMPFILE dispatch combining read-only guard and full validation.
///
/// Checks (in order, EROFS has priority):
/// 1. Parent is not on a read-only filesystem — else [`TmpfileError::ReadOnlyFilesystem`].
/// 2. Parent is a directory — else [`TmpfileError::NotADirectory`].
/// 3. Mode is stripped of file-type and high bits, then masked through umask.
///
/// Returns a [`TmpfilePlan`] with the computed mode on success.
pub fn handle_tmpfile(
    parent_is_dir: bool,
    parent_readonly: bool,
    mode: u32,
    umask: u32,
) -> Result<TmpfilePlan, TmpfileError> {
    check_tmpfile_readonly(parent_readonly)?;
    check_tmpfile_allowed(parent_is_dir)?;
    let masked = mask_tmpfile_mode(mode, umask);
    Ok(TmpfilePlan::new(masked))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    // -- check_tmpfile_allowed ----------------------------------------------

    #[test]
    fn allowed_when_parent_is_directory() {
        assert_eq!(check_tmpfile_allowed(true), Ok(()));
    }

    #[test]
    fn not_allowed_when_parent_is_not_directory() {
        assert_eq!(
            check_tmpfile_allowed(false),
            Err(TmpfileError::NotADirectory)
        );
    }

    // -- check_tmpfile_readonly ---------------------------------------------

    #[test]
    fn readonly_rejected() {
        assert_eq!(
            check_tmpfile_readonly(true),
            Err(TmpfileError::ReadOnlyFilesystem)
        );
    }

    #[test]
    fn readwrite_accepted() {
        assert_eq!(check_tmpfile_readonly(false), Ok(()));
    }

    // -- mask_tmpfile_mode --------------------------------------------------

    #[test]
    fn mask_strips_high_bits() {
        assert_eq!(mask_tmpfile_mode(0o644 | 0xFFFF0000, 0), 0o644);
    }

    #[test]
    fn mask_applies_umask() {
        // mode 0o666, umask 0o022 -> 0o644
        assert_eq!(mask_tmpfile_mode(0o666, 0o022), 0o644);
    }

    #[test]
    fn mask_umask_all_bits_off() {
        // umask 0o777 clears all permission bits
        assert_eq!(mask_tmpfile_mode(0o777, 0o777), 0);
    }

    #[test]
    fn mask_preserves_special_bits() {
        // S_ISUID|S_ISGID|S_ISVTX are in 0o7777, preserved if umask allows
        assert_eq!(mask_tmpfile_mode(0o6755, 0), 0o6755);
        // mode with umask: 0o6755 & ~0o022 = 0o6755 & 0o7755 = 0o6755? No:
        // ~0o022 = 0o7755 in the low 12 bits
        // 0o6755 = 0o6000 | 0o755
        // 0o755 & ~0o022 = 0o755 & 0o755 = 0o755, plus 0o6000 = 0o6755
        assert_eq!(mask_tmpfile_mode(0o6755, 0o022), 0o6755 & !0o022);
    }

    // -- plan_tmpfile -------------------------------------------------------

    #[test]
    fn plan_tmpfile_success() {
        let plan = plan_tmpfile(true, false, 0o644, 0o022);
        assert_eq!(plan, Ok(TmpfilePlan { mode: 0o644 }));
    }

    #[test]
    fn plan_tmpfile_not_directory() {
        assert_eq!(
            plan_tmpfile(false, false, 0o644, 0o022),
            Err(TmpfileError::NotADirectory)
        );
    }

    #[test]
    fn plan_tmpfile_readonly() {
        assert_eq!(
            plan_tmpfile(true, true, 0o644, 0o022),
            Err(TmpfileError::ReadOnlyFilesystem)
        );
    }

    #[test]
    fn plan_tmpfile_not_dir_takes_priority_over_readonly() {
        assert_eq!(
            plan_tmpfile(false, true, 0o644, 0o022),
            Err(TmpfileError::NotADirectory)
        );
    }

    #[test]
    fn plan_tmpfile_mode_with_umask() {
        let plan = plan_tmpfile(true, false, 0o666, 0o022);
        assert_eq!(plan, Ok(TmpfilePlan { mode: 0o644 }));
    }

    #[test]
    fn plan_tmpfile_mode_strips_file_type() {
        // S_IFREG | 0o644 = 0x8000 | 0o644 -> strips to 0o644
        let plan = plan_tmpfile(true, false, 0x8000 | 0o644, 0);
        assert_eq!(plan, Ok(TmpfilePlan { mode: 0o644 }));
    }

    // -- TmpfileError ------------------------------------------------------

    #[test]
    fn tmpfile_error_display_produces_human_message() {
        let msg = format!("{}", TmpfileError::NotADirectory);
        assert!(!msg.is_empty());
        assert!(msg.contains("not a directory"));

        let msg = format!("{}", TmpfileError::ReadOnlyFilesystem);
        assert!(!msg.is_empty());
        assert!(msg.contains("read-only"));
    }

    #[test]
    fn tmpfile_error_is_std_error() {
        let e: &dyn Error = &TmpfileError::NotADirectory;
        let _ = e.to_string();
    }

    #[test]
    fn tmpfile_error_to_errno_maps_correctly() {
        assert_eq!(TmpfileError::NotADirectory.to_errno(), errno::ENOTDIR);
        assert_eq!(TmpfileError::ReadOnlyFilesystem.to_errno(), errno::EROFS);
    }

    #[test]
    fn tmpfile_error_into_c_int() {
        let e: c_int = TmpfileError::ReadOnlyFilesystem.into();
        assert_eq!(e, errno::EROFS);
    }

    #[test]
    fn tmpfile_error_debug_includes_variant() {
        let dbg = format!("{:?}", TmpfileError::NotADirectory);
        assert!(dbg.contains("NotADirectory"));
    }

    #[test]
    fn tmpfile_error_clone_and_eq() {
        let e1 = TmpfileError::NotADirectory;
        let e2 = e1;
        assert_eq!(e1, e2);
        assert_ne!(e1, TmpfileError::ReadOnlyFilesystem);
    }

    // -- TmpfilePlan --------------------------------------------------------

    #[test]
    fn tmpfile_plan_new_stores_mode() {
        let plan = TmpfilePlan::new(0o644);
        assert_eq!(plan.mode, 0o644);
    }

    #[test]
    fn tmpfile_plan_zero_mode() {
        let plan = TmpfilePlan::new(0);
        assert_eq!(plan.mode, 0);
    }

    #[test]
    fn tmpfile_plan_debug_includes_mode() {
        let dbg = format!("{:?}", TmpfilePlan::new(0o644));
        assert!(dbg.contains("420"));
    }

    // -- edge cases ---------------------------------------------------------

    #[test]
    fn plan_tmpfile_umask_all_bits_blocked() {
        let plan = plan_tmpfile(true, false, 0o777, 0o777);
        assert_eq!(plan, Ok(TmpfilePlan { mode: 0 }));
    }

    // -- handle_tmpfile -----------------------------------------------------

    #[test]
    fn handle_tmpfile_success() {
        let plan = handle_tmpfile(true, false, 0o644, 0o022);
        assert_eq!(plan, Ok(TmpfilePlan { mode: 0o644 }));
    }

    #[test]
    fn handle_tmpfile_readonly_rejected() {
        assert_eq!(
            handle_tmpfile(true, true, 0o644, 0o022),
            Err(TmpfileError::ReadOnlyFilesystem)
        );
    }

    #[test]
    fn handle_tmpfile_readonly_priority_over_not_dir() {
        assert_eq!(
            handle_tmpfile(false, true, 0o644, 0o022),
            Err(TmpfileError::ReadOnlyFilesystem)
        );
    }

    #[test]
    fn handle_tmpfile_not_directory() {
        assert_eq!(
            handle_tmpfile(false, false, 0o644, 0o022),
            Err(TmpfileError::NotADirectory)
        );
    }

    #[test]
    fn handle_tmpfile_mode_with_umask() {
        let plan = handle_tmpfile(true, false, 0o666, 0o022);
        assert_eq!(plan, Ok(TmpfilePlan { mode: 0o644 }));
    }
}
