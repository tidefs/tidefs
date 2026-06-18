// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Extended attribute bridge types for the VFS Engine xattr surface.
//!
//! This module defines [`XattrSetFlags`] (semantic wrapper around Linux
//! `XATTR_CREATE` / `XATTR_REPLACE`) and [`XattrError`] (typed xattr
//! error, convertible to the engine [`Errno`] domain).
//!
//! The VFS Engine trait methods (`getxattr`, `setxattr`, `listxattr`,
//! `removexattr`) use raw [`Errno`] for errors and `u32` for flags.
//! These helpers exist so future callers can operate with semantic
//! types and forward errors through typed conversion.

use tidefs_types_vfs_core::{Errno, XATTR_CREATE, XATTR_REPLACE};

/// Flags controlling creation semantics for `setxattr`.
///
/// Maps directly to the Linux extended attribute flags:
///
/// | Variant             | Linux constant    | Semantics                              |
/// |---------------------|-------------------|----------------------------------------|
/// | `CreateOrReplace`   | `0`               | Create or replace (default).           |
/// | `Create`            | `XATTR_CREATE`    | Fail with `EEXIST` if already present. |
/// | `Replace`           | `XATTR_REPLACE`   | Fail with `ENODATA` if not present.    |
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrSetFlags {
    /// Create or replace the attribute (default, flags=0).
    CreateOrReplace,
    /// Create only: fail if the attribute already exists.
    Create,
    /// Replace only: fail if the attribute does not exist.
    Replace,
}

impl XattrSetFlags {
    /// Convert to the raw `u32` flag value used by the VFS engine trait.
    #[must_use]
    pub const fn raw(self) -> u32 {
        match self {
            Self::CreateOrReplace => 0,
            Self::Create => XATTR_CREATE,
            Self::Replace => XATTR_REPLACE,
        }
    }

    /// Interpret a raw `u32` flag value from the engine boundary.
    ///
    /// Unknown bits beyond `XATTR_CREATE | XATTR_REPLACE` are ignored;
    /// only the two defined flag bits are inspected.
    #[must_use]
    pub fn from_raw(raw: u32) -> Self {
        if raw & XATTR_REPLACE != 0 {
            Self::Replace
        } else if raw & XATTR_CREATE != 0 {
            Self::Create
        } else {
            Self::CreateOrReplace
        }
    }

    /// `true` when the caller requires `Create` semantics.
    #[must_use]
    pub const fn is_create(self) -> bool {
        matches!(self, Self::Create)
    }

    /// `true` when the caller requires `Replace` semantics.
    #[must_use]
    pub const fn is_replace(self) -> bool {
        matches!(self, Self::Replace)
    }
}

/// Typed errors specific to extended attribute operations.
///
/// Every variant maps to a well-known Linux errno value so callers can
/// convert to [`Errno`] trivially.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrError {
    /// The requested attribute does not exist (`ENODATA` / `ENOATTR`).
    NotFound,
    /// The attribute already exists and `XATTR_CREATE` was requested
    /// (`EEXIST`).
    AlreadyExists,
    /// The operation is not supported by this engine (`ENOSYS` / `EOPNOTSUPP`).
    NotSupported,
    /// An internal error occurred; the caller may retry or fail (`EIO`).
    Internal,
}

impl From<XattrError> for Errno {
    fn from(err: XattrError) -> Self {
        match err {
            XattrError::NotFound => Errno::ENODATA,
            XattrError::AlreadyExists => Errno::EEXIST,
            XattrError::NotSupported => Errno::ENOSYS,
            XattrError::Internal => Errno::EIO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── XattrSetFlags tests ──────────────────────────────────────────

    #[test]
    fn set_flags_create_or_replace_raw_is_zero() {
        let f = XattrSetFlags::CreateOrReplace;
        assert_eq!(f.raw(), 0);
        assert!(!f.is_create());
        assert!(!f.is_replace());
    }

    #[test]
    fn set_flags_create_raw_is_xattr_create() {
        let f = XattrSetFlags::Create;
        assert_eq!(f.raw(), XATTR_CREATE);
        assert!(f.is_create());
        assert!(!f.is_replace());
    }

    #[test]
    fn set_flags_replace_raw_is_xattr_replace() {
        let f = XattrSetFlags::Replace;
        assert_eq!(f.raw(), XATTR_REPLACE);
        assert!(!f.is_create());
        assert!(f.is_replace());
    }

    #[test]
    fn set_flags_from_raw_create_is_round_trip() {
        assert_eq!(XattrSetFlags::from_raw(XATTR_CREATE), XattrSetFlags::Create);
    }

    #[test]
    fn set_flags_from_raw_replace_is_round_trip() {
        assert_eq!(
            XattrSetFlags::from_raw(XATTR_REPLACE),
            XattrSetFlags::Replace
        );
    }

    #[test]
    fn set_flags_from_raw_zero_is_create_or_replace() {
        assert_eq!(XattrSetFlags::from_raw(0), XattrSetFlags::CreateOrReplace);
    }

    #[test]
    fn set_flags_from_raw_unknown_is_create_or_replace() {
        assert_eq!(XattrSetFlags::from_raw(0x4), XattrSetFlags::CreateOrReplace);
    }

    #[test]
    fn set_flags_from_raw_both_set_prefers_replace() {
        // Replace takes priority per the bit-test order.
        assert_eq!(
            XattrSetFlags::from_raw(XATTR_CREATE | XATTR_REPLACE),
            XattrSetFlags::Replace
        );
    }

    // ── XattrError → Errno conversion tests ──────────────────────────

    #[test]
    fn xattr_error_not_found_maps_to_enodata() {
        let e: Errno = XattrError::NotFound.into();
        assert_eq!(e, Errno::ENODATA);
    }

    #[test]
    fn xattr_error_already_exists_maps_to_eexist() {
        let e: Errno = XattrError::AlreadyExists.into();
        assert_eq!(e, Errno::EEXIST);
    }

    #[test]
    fn xattr_error_not_supported_maps_to_enosys() {
        let e: Errno = XattrError::NotSupported.into();
        assert_eq!(e, Errno::ENOSYS);
    }

    #[test]
    fn xattr_error_internal_maps_to_eio() {
        let e: Errno = XattrError::Internal.into();
        assert_eq!(e, Errno::EIO);
    }
}
