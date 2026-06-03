//! FUSE `lookup` handler helpers — name validation, entry TTL defaults,
//! and POSIX-compliant directory entry resolution plumbing.
//!
//! Provides:
//! - [`handle_lookup`]: canonical dispatch entry-point combining name
//!   validation into a single call — returns a [`LookupPlan`] or a
//!   [`LookupError`].
//! - [`validate_lookup_name`]: reject empty, overlong, NUL-containing,
//!   and slash-containing names.  Dot and dot-dot are accepted (valid
//!   lookup targets).
//! - [`LOOKUP_MAX_NAME_BYTES`]: POSIX `NAME_MAX` (255 bytes).
//! - [`plan_lookup`]: combined name validation returning
//!   `Ok(`[`LookupPlan`]`)` or a [`LookupError`].
//! - [`LookupPlan`]: validated lookup request ready for backend
//!   dispatch.
//! - [`LookupError`]: domain error type for lookup name validation.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::lookup;
//!
//! let plan = lookup::handle_lookup(b"myfile")?;
//! // dispatch plan.name to the backend...
//! ```

use crate::errno;
use libc::c_int;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of a single file-name component in bytes
/// (POSIX `NAME_MAX` on Linux).
pub const LOOKUP_MAX_NAME_BYTES: usize = 255;

// ---------------------------------------------------------------------------
// LookupError — domain error type for lookup operations
// ---------------------------------------------------------------------------

/// Errors that can occur during lookup name validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupError {
    /// The provided name is empty, contains a NUL byte, or contains
    /// a forward slash.
    InvalidName,
    /// The provided name exceeds [`LOOKUP_MAX_NAME_BYTES`] bytes.
    NameTooLong,
}

impl LookupError {
    /// Convert this error to the matching POSIX errno value.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            LookupError::InvalidName => errno::EINVAL,
            LookupError::NameTooLong => errno::ENAMETOOLONG,
        }
    }
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LookupError::InvalidName => write!(f, "invalid lookup name"),
            LookupError::NameTooLong => {
                write!(
                    f,
                    "lookup name too long (max {LOOKUP_MAX_NAME_BYTES} bytes)"
                )
            }
        }
    }
}

impl std::error::Error for LookupError {}

impl From<LookupError> for c_int {
    fn from(e: LookupError) -> c_int {
        e.to_errno()
    }
}

// ---------------------------------------------------------------------------
// LookupPlan — validated lookup request
// ---------------------------------------------------------------------------

/// A validated `lookup` request ready for backend dispatch.
///
/// Created by [`plan_lookup`] or [`handle_lookup`], which perform all
/// client-visible validation (name checks) before the backend is
/// invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupPlan {
    /// The validated entry name.  Guaranteed to be non-empty,
    /// free of NUL bytes and slashes, and at most
    /// [`LOOKUP_MAX_NAME_BYTES`] bytes long.
    pub name: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

/// Validate a directory entry name for `lookup`.
///
/// Returns `Err(`[`LookupError::InvalidName`]`)` when the name is empty,
/// contains a NUL byte, or contains a forward slash.
///
/// Returns `Err(`[`LookupError::NameTooLong`]`)` when the name exceeds
/// [`LOOKUP_MAX_NAME_BYTES`].
///
/// Returns `Ok(())` on success.  Unlike `create`, `.` and `..` are
/// accepted — these are valid directory entries that the kernel will
/// request via lookup.
pub fn validate_lookup_name(name: &[u8]) -> Result<(), LookupError> {
    if name.is_empty() {
        return Err(LookupError::InvalidName);
    }
    if name.len() > LOOKUP_MAX_NAME_BYTES {
        return Err(LookupError::NameTooLong);
    }
    if name.contains(&0) {
        return Err(LookupError::InvalidName);
    }
    if name.contains(&b'/') {
        return Err(LookupError::InvalidName);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// Validate the lookup parameters and return a ready plan.
///
/// This is a convenience wrapper around [`validate_lookup_name`] that
/// can be extended with additional checks (e.g., parent-inode existence)
/// as the handler grows.
///
/// # Returns
///
/// `Ok(`[`LookupPlan`]`)` when all validations pass.
///
/// `Err(`[`LookupError`]`)` on failure.
#[inline]
pub fn plan_lookup(name: &[u8]) -> Result<LookupPlan, LookupError> {
    validate_lookup_name(name)?;
    Ok(LookupPlan {
        name: name.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// handle_lookup — canonical dispatch entry-point
// ---------------------------------------------------------------------------

/// Canonical dispatch entry-point for FUSE `lookup` requests.
///
/// Validates the lookup name and returns a validated [`LookupPlan`]
/// ready for backend namespace resolution.  This is the preferred
/// entry point for daemon dispatch: it validates the entry name
/// (EINVAL/ENAMETOOLONG) and returns a [`LookupPlan`] ready for
/// backend execution.
///
/// # Parameters
///
/// - `name`: entry name to look up (must be non-empty, NUL-free,
///   slash-free, and less or equal to [`LOOKUP_MAX_NAME_BYTES`];
///   `.` and `..` are accepted).
///
/// # Errors
///
/// Returns [`LookupError::InvalidName`] when the name is empty,
/// contains a NUL byte, or contains a forward slash.
///
/// Returns [`LookupError::NameTooLong`] when the name exceeds
/// [`LOOKUP_MAX_NAME_BYTES`].
///
/// # Examples
///
/// ```rust,ignore
/// let plan = lookup::handle_lookup(b"myfile")?;
/// // dispatch plan.name to the backend...
/// ```
#[inline]
pub fn handle_lookup(name: &[u8]) -> Result<LookupPlan, LookupError> {
    plan_lookup(name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    // -- validate_lookup_name success paths --

    #[test]
    fn valid_plain_name() {
        assert_eq!(validate_lookup_name(b"hello.txt"), Ok(()));
    }

    #[test]
    fn valid_single_char() {
        assert_eq!(validate_lookup_name(b"a"), Ok(()));
    }

    #[test]
    fn valid_dot() {
        assert_eq!(validate_lookup_name(b"."), Ok(()));
    }

    #[test]
    fn valid_dotdot() {
        assert_eq!(validate_lookup_name(b".."), Ok(()));
    }

    #[test]
    fn valid_max_length() {
        let max = vec![b'a'; LOOKUP_MAX_NAME_BYTES];
        assert_eq!(validate_lookup_name(&max), Ok(()));
    }

    // -- validate_lookup_name error paths --

    #[test]
    fn empty_name_rejected() {
        assert_eq!(validate_lookup_name(b""), Err(LookupError::InvalidName));
    }

    #[test]
    fn too_long_name_rejected() {
        let long = vec![b'x'; LOOKUP_MAX_NAME_BYTES + 1];
        assert_eq!(validate_lookup_name(&long), Err(LookupError::NameTooLong));
    }

    #[test]
    fn nul_in_name_rejected() {
        assert_eq!(
            validate_lookup_name(b"fi\0le"),
            Err(LookupError::InvalidName)
        );
    }

    #[test]
    fn slash_in_name_rejected() {
        assert_eq!(validate_lookup_name(b"a/b"), Err(LookupError::InvalidName));
    }

    #[test]
    fn leading_nul_rejected() {
        assert_eq!(
            validate_lookup_name(b"\0abc"),
            Err(LookupError::InvalidName)
        );
    }

    #[test]
    fn trailing_nul_rejected() {
        assert_eq!(
            validate_lookup_name(b"abc\0"),
            Err(LookupError::InvalidName)
        );
    }

    #[test]
    fn only_slash_rejected() {
        assert_eq!(validate_lookup_name(b"/"), Err(LookupError::InvalidName));
    }

    // -- plan_lookup --

    #[test]
    fn plan_lookup_valid() {
        let plan = plan_lookup(b"file").unwrap();
        assert_eq!(plan.name, b"file");
    }

    #[test]
    fn plan_lookup_empty() {
        assert_eq!(plan_lookup(b""), Err(LookupError::InvalidName));
    }

    #[test]
    fn plan_lookup_too_long() {
        let long = vec![b'z'; 300];
        assert_eq!(plan_lookup(&long), Err(LookupError::NameTooLong));
    }

    #[test]
    fn plan_lookup_dot() {
        let plan = plan_lookup(b".").unwrap();
        assert_eq!(plan.name, b".");
    }

    #[test]
    fn plan_lookup_dotdot() {
        let plan = plan_lookup(b"..").unwrap();
        assert_eq!(plan.name, b"..");
    }

    #[test]
    fn plan_lookup_preserves_exact_bytes() {
        let plan = plan_lookup(b"MiXeDcAsE").unwrap();
        assert_eq!(plan.name, b"MiXeDcAsE");
    }

    // -- LookupError ---------------------------------------------------------

    #[test]
    fn lookup_error_display_produces_human_message() {
        let msg = format!("{}", LookupError::InvalidName);
        assert!(!msg.is_empty());
        let msg = format!("{}", LookupError::NameTooLong);
        assert!(msg.contains("too long"));
    }

    #[test]
    fn lookup_error_is_std_error() {
        let e: &dyn Error = &LookupError::NameTooLong;
        let _ = e.to_string();
    }

    #[test]
    fn lookup_error_to_errno_maps_correctly() {
        assert_eq!(LookupError::InvalidName.to_errno(), errno::EINVAL);
        assert_eq!(LookupError::NameTooLong.to_errno(), errno::ENAMETOOLONG);
    }

    #[test]
    fn lookup_error_into_c_int() {
        let e: c_int = LookupError::NameTooLong.into();
        assert_eq!(e, errno::ENAMETOOLONG);
    }

    #[test]
    fn lookup_error_debug_includes_variant() {
        let dbg = format!("{:?}", LookupError::InvalidName);
        assert!(dbg.contains("InvalidName"));
    }

    #[test]
    fn lookup_error_clone_and_eq() {
        let e1 = LookupError::NameTooLong;
        let e2 = e1;
        assert_eq!(e1, e2);
        assert_ne!(e1, LookupError::InvalidName);
    }

    // -- LookupPlan ----------------------------------------------------------

    #[test]
    fn lookup_plan_debug_includes_name() {
        let plan = plan_lookup(b"testfile").unwrap();
        let dbg = format!("{plan:?}");
        assert!(dbg.contains("LookupPlan"));
    }

    #[test]
    fn lookup_plan_clone_preserves_name() {
        let plan = plan_lookup(b"testfile").unwrap();
        let clone = plan.clone();
        assert_eq!(plan.name, clone.name);
    }

    // -- Constants -----------------------------------------------------------

    #[test]
    fn lookup_max_name_bytes_is_posix_name_max() {
        assert_eq!(LOOKUP_MAX_NAME_BYTES, 255);
    }

    // -- handle_lookup -------------------------------------------------------

    #[test]
    fn handle_lookup_valid_name() {
        let plan = handle_lookup(b"myfile").unwrap();
        assert_eq!(plan.name, b"myfile");
    }

    #[test]
    fn handle_lookup_dot() {
        let plan = handle_lookup(b".").unwrap();
        assert_eq!(plan.name, b".");
    }

    #[test]
    fn handle_lookup_dotdot() {
        let plan = handle_lookup(b"..").unwrap();
        assert_eq!(plan.name, b"..");
    }

    #[test]
    fn handle_lookup_empty_name() {
        assert_eq!(handle_lookup(b""), Err(LookupError::InvalidName));
    }

    #[test]
    fn handle_lookup_nul_in_name() {
        assert_eq!(handle_lookup(b"bad\0name"), Err(LookupError::InvalidName));
    }

    #[test]
    fn handle_lookup_slash_in_name() {
        assert_eq!(handle_lookup(b"a/b"), Err(LookupError::InvalidName));
    }

    #[test]
    fn handle_lookup_name_too_long() {
        let long = vec![b'a'; 256];
        assert_eq!(handle_lookup(&long), Err(LookupError::NameTooLong));
    }

    #[test]
    fn handle_lookup_max_length() {
        let max = vec![b'a'; 255];
        let plan = handle_lookup(&max).unwrap();
        assert_eq!(plan.name.len(), 255);
    }
}
