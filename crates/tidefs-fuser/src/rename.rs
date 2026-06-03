//! FUSE `rename` / `rename2` handler helpers — name validation, flag
//! parsing, and convenience entry-points for POSIX-compliant atomic
//! cross-directory rename.
//!
//! Provides:
//! - [`RENAME_NOREPLACE`], [`RENAME_EXCHANGE`], [`RENAME_WHITEOUT`]:
//!   flag constants matching the Linux `renameat2` interface.
//! - [`RenameFlags`]: safe, typed representation of rename flags with
//!   support queries (`is_noreplace`, `is_exchange`, etc.).
//! - [`validate_rename_name`]: reject empty, overlong, dot/dotdot, NUL,
//!   and slash-containing names; `Ok(())` or a FUSE errno.
//! - [`validate_rename_flags`]: reject unsupported flag combinations
//!   (`WHITEOUT` → `EINVAL`; `NOREPLACE | EXCHANGE` → `EINVAL`).
//! - [`plan_rename`]: combined name + flags validation returning the
//!   canonical [`RenameFlags`] on success.
//! - Re-exported POSIX errno codes relevant to the rename path.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::rename;
//!
//! let flags = rename::plan_rename(b"old.txt", b"new.txt", 0)?;
//! assert!(flags.is_plain());
//! ```

use libc::c_int;

// ---------------------------------------------------------------------------
// Flag constants
// ---------------------------------------------------------------------------

/// Do not overwrite an existing destination (`renameat2` `RENAME_NOREPLACE`).
pub const RENAME_NOREPLACE: u32 = 1;

/// Atomically exchange source and destination (`renameat2` `RENAME_EXCHANGE`).
pub const RENAME_EXCHANGE: u32 = 2;

/// Create a whiteout at the source (`renameat2` `RENAME_WHITEOUT`).
/// Not yet supported; `EINVAL`.
pub const RENAME_WHITEOUT: u32 = 4;

/// Mask of all flags that this module can accept without `EINVAL`.
const SUPPORTED_FLAGS_MASK: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;

/// Maximum length of a single directory-name component in bytes
/// (POSIX `NAME_MAX` on Linux).
pub const RENAME_MAX_NAME_BYTES: usize = 255;

// ---------------------------------------------------------------------------
// RenameFlags — typed flag representation
// ---------------------------------------------------------------------------

/// Typed representation of `renameat2` flags.
///
/// Provides a safe, readable alternative to raw `u32` flag values with
/// convenience predicates for dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenameFlags {
    raw: u32,
}

impl RenameFlags {
    /// Plain rename (no flags). Overwrites an existing destination.
    pub const EMPTY: Self = Self { raw: 0 };

    /// Returns `true` when no flags are set (plain rename).
    #[must_use]
    pub const fn is_plain(self) -> bool {
        self.raw == 0
    }

    /// Returns `true` when [`RENAME_NOREPLACE`] is set.
    #[must_use]
    pub const fn is_noreplace(self) -> bool {
        (self.raw & RENAME_NOREPLACE) != 0
    }

    /// Returns `true` when [`RENAME_EXCHANGE`] is set.
    #[must_use]
    pub const fn is_exchange(self) -> bool {
        (self.raw & RENAME_EXCHANGE) != 0
    }

    /// Returns the raw `u32` value suitable for passing to the VFS engine
    /// or FUSE adapter dispatch.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.raw
    }
}

// ---------------------------------------------------------------------------
// Re-exports: standard errno codes for rename error paths
// ---------------------------------------------------------------------------

pub use libc::{
    EACCES, EBUSY, EEXIST, EINVAL, EIO, EISDIR, ENAMETOOLONG, ENOENT, ENOSPC, ENOTDIR, ENOTEMPTY,
    EPERM, EROFS, EXDEV,
};

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

/// Validate a single rename path component name.
///
/// Returns `Err(EINVAL)` when the name is empty, exceeds
/// [`RENAME_MAX_NAME_BYTES`], is `"."` or `".."`, contains a NUL byte,
/// or contains a forward slash.
///
/// Returns `Ok(())` on success.
pub fn validate_rename_name(name: &[u8]) -> Result<(), c_int> {
    if name.is_empty() {
        return Err(libc::EINVAL);
    }
    if name.len() > RENAME_MAX_NAME_BYTES {
        return Err(libc::ENAMETOOLONG);
    }
    if name == b"." || name == b".." {
        return Err(libc::EINVAL);
    }
    if name.contains(&0) {
        return Err(libc::EINVAL);
    }
    if name.contains(&b'/') {
        return Err(libc::EINVAL);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Flag validation
// ---------------------------------------------------------------------------

/// Validate `renameat2` flags for the FUSE rename handler.
///
/// # Accepted combinations
///
/// - `0` (plain rename — overwrite destination if it exists).
/// - [`RENAME_NOREPLACE`] (fail if destination exists).
/// - [`RENAME_EXCHANGE`] (atomically swap source and destination).
///
/// # Rejected
///
/// - [`RENAME_WHITEOUT`]: `EINVAL` (not yet implemented).
/// - `RENAME_NOREPLACE | RENAME_EXCHANGE`: `EINVAL` (mutually
///   exclusive per POSIX).
/// - Any other unknown bit: `EINVAL`.
///
/// On success the canonical [`RenameFlags`].
pub fn validate_rename_flags(flags: u32) -> Result<RenameFlags, c_int> {
    if flags & RENAME_WHITEOUT != 0 {
        return Err(libc::EINVAL);
    }
    if flags & !SUPPORTED_FLAGS_MASK != 0 {
        return Err(libc::EINVAL);
    }
    // NOREPLACE and EXCHANGE are mutually exclusive
    if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
        return Err(libc::EINVAL);
    }
    Ok(RenameFlags { raw: flags })
}

// ---------------------------------------------------------------------------
// Combined validation (convenience)
// ---------------------------------------------------------------------------

/// Validate both the old and new names and the rename flags in one call.
///
/// On success the canonical [`RenameFlags`].  Callers can use
/// `flags.is_plain()`, `flags.is_noreplace()`, etc. for dispatch.
///
/// # Errors
///
/// - `EINVAL` / `ENAMETOOLONG`: name validation failure for either name.
/// - `EINVAL`: `RENAME_WHITEOUT` flag requested.
/// - `EINVAL`: invalid or conflicting flag combination.
pub fn plan_rename(old_name: &[u8], new_name: &[u8], flags: u32) -> Result<RenameFlags, c_int> {
    validate_rename_name(old_name)?;
    validate_rename_name(new_name)?;
    validate_rename_flags(flags)
}

// ---------------------------------------------------------------------------
// handle_rename -- canonical entry-point for FUSE rename dispatch
// ---------------------------------------------------------------------------

/// Canonical FUSE dispatch entry-point for `rename` / `rename2`.
///
/// Validates both path-component names, checks rename flags, and rejects
/// rename on a read-only filesystem.  Returns the canonical [`RenameFlags`]
/// on success for the caller to pass to `VfsEngine::rename` or the kernel
/// adapter.
#[inline]
pub fn handle_rename(
    old_name: &[u8],
    new_name: &[u8],
    flags: u32,
    read_only: bool,
) -> Result<RenameFlags, c_int> {
    if read_only {
        return Err(libc::EROFS);
    }
    plan_rename(old_name, new_name, flags)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- validate_rename_name -----------------------------------------------

    #[test]
    fn name_empty_rejected() {
        assert_eq!(validate_rename_name(b""), Err(libc::EINVAL));
    }

    #[test]
    fn name_too_long_rejected() {
        let long = vec![b'a'; 256];
        assert_eq!(validate_rename_name(&long), Err(libc::ENAMETOOLONG));
    }

    #[test]
    fn name_max_length_accepted() {
        let max = vec![b'a'; 255];
        assert_eq!(validate_rename_name(&max), Ok(()));
    }

    #[test]
    fn dot_rejected() {
        assert_eq!(validate_rename_name(b"."), Err(libc::EINVAL));
    }

    #[test]
    fn dotdot_rejected() {
        assert_eq!(validate_rename_name(b".."), Err(libc::EINVAL));
    }

    #[test]
    fn nul_byte_rejected() {
        assert_eq!(validate_rename_name(b"foo\0bar"), Err(libc::EINVAL));
    }

    #[test]
    fn slash_rejected() {
        assert_eq!(validate_rename_name(b"a/b"), Err(libc::EINVAL));
    }

    #[test]
    fn normal_name_accepted() {
        assert_eq!(validate_rename_name(b"myfile.txt"), Ok(()));
        assert_eq!(validate_rename_name(b"file with spaces"), Ok(()));
        assert_eq!(validate_rename_name(b"file-with-dashes"), Ok(()));
        assert_eq!(validate_rename_name(b"file_with_underscores"), Ok(()));
    }

    // -- validate_rename_flags ----------------------------------------------

    #[test]
    fn flags_zero_is_plain() {
        let flags = validate_rename_flags(0).unwrap();
        assert!(flags.is_plain());
        assert!(!flags.is_noreplace());
        assert!(!flags.is_exchange());
        assert_eq!(flags.as_raw(), 0);
    }

    #[test]
    fn flags_noreplace_accepted() {
        let flags = validate_rename_flags(RENAME_NOREPLACE).unwrap();
        assert!(!flags.is_plain());
        assert!(flags.is_noreplace());
        assert!(!flags.is_exchange());
    }

    #[test]
    fn flags_exchange_accepted() {
        let flags = validate_rename_flags(RENAME_EXCHANGE).unwrap();
        assert!(!flags.is_plain());
        assert!(!flags.is_noreplace());
        assert!(flags.is_exchange());
    }

    #[test]
    fn flags_whiteout_rejected() {
        assert_eq!(validate_rename_flags(RENAME_WHITEOUT), Err(libc::EINVAL));
    }

    #[test]
    fn flags_whiteout_combined_rejected() {
        assert_eq!(
            validate_rename_flags(RENAME_NOREPLACE | RENAME_WHITEOUT),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn flags_noreplace_and_exchange_rejected() {
        assert_eq!(
            validate_rename_flags(RENAME_NOREPLACE | RENAME_EXCHANGE),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn flags_unknown_bit_rejected() {
        assert_eq!(validate_rename_flags(0x100), Err(libc::EINVAL));
    }

    // -- plan_rename --------------------------------------------------------

    #[test]
    fn plan_rename_plain_succeeds() {
        let flags = plan_rename(b"old.txt", b"new.txt", 0).unwrap();
        assert!(flags.is_plain());
    }

    #[test]
    fn plan_rename_noreplace_succeeds() {
        let flags = plan_rename(b"old.txt", b"new.txt", RENAME_NOREPLACE).unwrap();
        assert!(flags.is_noreplace());
    }

    #[test]
    fn plan_rename_exchange_succeeds() {
        let flags = plan_rename(b"a.txt", b"b.txt", RENAME_EXCHANGE).unwrap();
        assert!(flags.is_exchange());
    }

    #[test]
    fn plan_rename_invalid_old_name_rejected() {
        assert_eq!(plan_rename(b"", b"new.txt", 0), Err(libc::EINVAL));
    }

    #[test]
    fn plan_rename_invalid_new_name_rejected() {
        assert_eq!(plan_rename(b"old.txt", b"", 0), Err(libc::EINVAL));
    }

    #[test]
    fn plan_rename_whiteout_rejected() {
        assert_eq!(
            plan_rename(b"old.txt", b"new.txt", RENAME_WHITEOUT),
            Err(libc::EINVAL)
        );
    }

    // -- RenameFlags predicates ---------------------------------------------

    #[test]
    fn rename_flags_empty_is_plain() {
        assert!(RenameFlags::EMPTY.is_plain());
        assert!(!RenameFlags::EMPTY.is_noreplace());
        assert!(!RenameFlags::EMPTY.is_exchange());
    }

    #[test]
    fn rename_flags_noreplace_predicates() {
        let f = RenameFlags {
            raw: RENAME_NOREPLACE,
        };
        assert!(!f.is_plain());
        assert!(f.is_noreplace());
        assert!(!f.is_exchange());
    }

    #[test]
    fn rename_flags_exchange_predicates() {
        let f = RenameFlags {
            raw: RENAME_EXCHANGE,
        };
        assert!(!f.is_plain());
        assert!(!f.is_noreplace());
        assert!(f.is_exchange());
    }

    #[test]
    fn rename_flags_as_raw() {
        assert_eq!(RenameFlags::EMPTY.as_raw(), 0);
        assert_eq!(
            RenameFlags {
                raw: RENAME_NOREPLACE
            }
            .as_raw(),
            1
        );
        assert_eq!(
            RenameFlags {
                raw: RENAME_EXCHANGE
            }
            .as_raw(),
            2
        );
    }
    // -- handle_rename ------------------------------------------------------

    #[test]
    fn handle_rename_plain_succeeds() {
        let flags = handle_rename(b"old.txt", b"new.txt", 0, false).unwrap();
        assert!(flags.is_plain());
    }

    #[test]
    fn handle_rename_noreplace_succeeds() {
        let flags = handle_rename(b"old.txt", b"new.txt", RENAME_NOREPLACE, false).unwrap();
        assert!(flags.is_noreplace());
    }

    #[test]
    fn handle_rename_exchange_succeeds() {
        let flags = handle_rename(b"a.txt", b"b.txt", RENAME_EXCHANGE, false).unwrap();
        assert!(flags.is_exchange());
    }

    #[test]
    fn handle_rename_read_only_rejected() {
        assert_eq!(
            handle_rename(b"old.txt", b"new.txt", 0, true),
            Err(libc::EROFS)
        );
    }

    #[test]
    fn handle_rename_read_only_noreplace_rejected() {
        assert_eq!(
            handle_rename(b"old.txt", b"new.txt", RENAME_NOREPLACE, true),
            Err(libc::EROFS)
        );
    }

    #[test]
    fn handle_rename_invalid_old_name_rejected() {
        assert_eq!(handle_rename(b"", b"new.txt", 0, false), Err(libc::EINVAL));
    }

    #[test]
    fn handle_rename_invalid_new_name_rejected() {
        assert_eq!(handle_rename(b"old.txt", b"", 0, false), Err(libc::EINVAL));
    }

    #[test]
    fn handle_rename_whiteout_rejected() {
        assert_eq!(
            handle_rename(b"old.txt", b"new.txt", RENAME_WHITEOUT, false),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn handle_rename_noreplace_and_exchange_rejected() {
        assert_eq!(
            handle_rename(
                b"old.txt",
                b"new.txt",
                RENAME_NOREPLACE | RENAME_EXCHANGE,
                false,
            ),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn handle_rename_overlong_name_rejected() {
        let long = vec![b'a'; 256];
        assert_eq!(
            handle_rename(&long, b"new.txt", 0, false),
            Err(libc::ENAMETOOLONG)
        );
    }

    #[test]
    fn handle_rename_max_length_accepted() {
        let max = vec![b'a'; 255];
        let flags = handle_rename(&max, b"new.txt", 0, false).unwrap();
        assert!(flags.is_plain());
    }

    #[test]
    fn handle_rename_slash_in_name_rejected() {
        assert_eq!(
            handle_rename(b"a/b", b"new.txt", 0, false),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn handle_rename_nul_in_name_rejected() {
        assert_eq!(
            handle_rename(b"fi\0le", b"new.txt", 0, false),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn handle_rename_dot_name_rejected() {
        assert_eq!(handle_rename(b".", b"new.txt", 0, false), Err(libc::EINVAL));
    }

    #[test]
    fn handle_rename_dotdot_name_rejected() {
        assert_eq!(
            handle_rename(b"..", b"new.txt", 0, false),
            Err(libc::EINVAL)
        );
    }
}
