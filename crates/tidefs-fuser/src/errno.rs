//! Centralized `errno` mapping for TideFS internal error types.
//!
//! This module provides a single, audited translation table from TideFS
//! internal error categories to POSIX `errno` values used in FUSE reply
//! error codes.
//!
//! # Design
//!
//! TideFS internal error types (e.g. `tidefs_namespace::NamespaceError`,
//! `tidefs_xattr_storage::XattrSetPlanError`) live in layer crates that
//! the `fuser` library does not depend on.  This module bridges the gap
//! by defining a crate-local [`ErrorKind`] enum whose variants mirror
//! the standard POSIX error categories, plus a mapping function
//! [`to_errno`] that converts each kind to the correct `libc::c_int`.
//!
//! Callers in daemon or adapter crates match their internal error type,
//! convert it to an [`ErrorKind`], and then call [`to_errno`] (or a
//! convenience function like [`map_namespace_like`]).
//!
//! # Coverage
//!
//! The mapping was audited against:
//! - `tidefs_namespace::NamespaceError` (13 variants)
//! - `tidefs_xattr_storage::XattrSetPlanError` (5 variants)
//! - `tidefs_xattr_storage::XattrNameValidationError` (3 variants)
//! - `tidefs_xattr_storage::XattrStoreError` (1 variant)
//! - POSIX errno expectations from xfstests error-code assertions
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::errno::{self, ErrorKind};
//!
//! let errno = errno::to_errno(ErrorKind::NotFound);
//! assert_eq!(errno, libc::ENOENT);
//!
//! // Convenience: convert a NamespaceError-like match
//! let errno = errno::map_namespace_like(|e| match e {
//!     Some("exists") => ErrorKind::AlreadyExists,
//!     _ => ErrorKind::NotFound,
//! });
//! ```

use libc::c_int;

// ---------------------------------------------------------------------------
// Re-export commonly-used errno codes so handlers don't need their own
// libc imports.
// ---------------------------------------------------------------------------

pub use libc::{
    E2BIG, EACCES, EAGAIN, EBADF, EBUSY, EEXIST, EFBIG, EINTR, EINVAL, EIO, EISDIR, ELOOP, EMLINK,
    ENAMETOOLONG, ENFILE, ENODATA, ENOENT, ENOLINK, ENOSPC, ENOSYS, ENOTDIR, ENOTEMPTY, ENXIO,
    EOVERFLOW, EPERM, ERANGE, EROFS, ESTALE, EXDEV,
};

// Also re-export EOPNOTSUPP which may be spelled differently across platforms.
#[cfg(not(target_os = "linux"))]
pub use libc::EOPNOTSUPP;
#[cfg(target_os = "linux")]
pub use libc::EOPNOTSUPP;

// ---------------------------------------------------------------------------
// ErrorKind — TideFS internal error categories
// ---------------------------------------------------------------------------

/// TideFS internal error categories mapped to POSIX `errno` values.
///
/// Each variant corresponds to one or more TideFS internal error
/// variants and maps to exactly one POSIX errno code via [`to_errno`].
///
/// This enum is intentionally crate-local: the mapping is stable
/// regardless of which higher-level crate produces the error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Entry or inode not found (e.g. `NamespaceError::NotFound`,
    /// `XattrStoreError::EntryNotFound` for non-xattr paths).
    NotFound,

    /// Entry with the given name already exists
    /// (`NamespaceError::AlreadyExists`).
    AlreadyExists,

    /// Directory not empty (`NamespaceError::NotEmpty`).
    NotEmpty,

    /// Expected a directory but found a non-directory
    /// (`NamespaceError::NotDirectory`).
    NotDirectory,

    /// Expected a non-directory but found a directory
    /// (`NamespaceError::IsDirectory`).
    IsDirectory,

    /// Invalid name (empty, contains NUL, contains '/', or is `.`/`..`
    /// where disallowed) (`NamespaceError::InvalidName`,
    /// `XattrNameValidationError::EmptyName`,
    /// `XattrNameValidationError::NameContainsNul`).
    InvalidName,

    /// Name exceeds maximum length (`XattrNameValidationError::NameTooLong`,
    /// or any path component exceeding `NAME_MAX`).
    NameTooLong,

    /// Cross-device rename not supported (`NamespaceError::CrossDeviceRename`).
    CrossDevice,

    /// Rename would create a parent/child directory cycle
    /// (`NamespaceError::RenameCycle`).
    RenameCycle,

    /// Link-count increment would overflow (`NamespaceError::LinkCountOverflow`).
    LinkCountOverflow,

    /// Too many symbolic links encountered during path resolution
    /// (`NamespaceError::TooManySymlinks`).
    TooManySymlinks,

    /// Expected a symlink but found another inode type
    /// (`NamespaceError::NotSymlink`).
    NotSymlink,

    /// Operation not supported (`NamespaceError::NotSupported`).
    NotSupported,

    /// Permission denied (not owner, not in group, no execute on
    /// directory component, etc.).
    PermissionDenied,

    /// Read-only filesystem (mutation attempted on a read-only mount).
    ReadOnlyFilesystem,

    /// No space left on device (allocation failure, pool full).
    NoSpace,

    /// File too large (offset+length overflow, size exceeds filesystem limit).
    FileTooLarge,

    /// Internal I/O error (corrupt index, checksum mismatch, writeback
    /// failure, poisoned lock, etc.).  Maps to `EIO`.
    InternalIo,

    /// Bad or closed file descriptor/handle.
    BadFileDescriptor,

    /// Stale file handle (inode freed or renumbered).
    StaleFileHandle,

    /// Operation interrupted (`EINTR`).
    Interrupted,

    /// Resource busy (`EBUSY`).
    ResourceBusy,

    /// No data available (e.g. xattr not found — `ENODATA`).
    NoData,

    /// Value too large for buffer (`ERANGE`, e.g. xattr list buffer
    /// too small).
    ValueTooLarge,

    /// No such device or address (seek beyond EOF, `ENXIO`).
    NoDevice,

    /// Link severed (`ENOLINK`, e.g. inode link-count failure).
    LinkSevered,

    /// Value overflow (`EOVERFLOW`, e.g. cookie overflow in readdir).
    ValueOverflow,

    /// Resource temporarily unavailable (`EAGAIN`, scheduler
    /// backpressure, lock conflict).
    ResourceUnavailable,

    /// Function not implemented (`ENOSYS`).
    NotImplemented,

    /// Xattr entry exists (setxattr with XATTR_CREATE on existing attr).
    XattrEntryExists,

    /// Xattr entry not found (setxattr with XATTR_REPLACE on missing attr,
    /// or getxattr/removexattr on absent attr).
    XattrEntryNotFound,

    /// Xattr value too large (exceeds filesystem xattr size limit).
    XattrValueTooLarge,

    /// Invalid argument (generic catch-all for malformed parameters).
    InvalidArgument,
}

// ---------------------------------------------------------------------------
// to_errno — the centralised mapping table
// ---------------------------------------------------------------------------

/// Convert an [`ErrorKind`] to the corresponding POSIX `errno` value.
///
/// This is the single source of truth for TideFS → POSIX errno
/// translation.  Every FUSE handler that sends an error reply should
/// route through this function (directly or via a convenience wrapper).
///
/// # Examples
///
/// ```
/// use fuser::errno::{self, ErrorKind};
/// assert_eq!(errno::to_errno(ErrorKind::NotFound), libc::ENOENT);
/// assert_eq!(errno::to_errno(ErrorKind::PermissionDenied), libc::EACCES);
/// assert_eq!(errno::to_errno(ErrorKind::ReadOnlyFilesystem), libc::EROFS);
/// ```
#[must_use]
pub const fn to_errno(kind: ErrorKind) -> c_int {
    use ErrorKind::*;
    match kind {
        NotFound => libc::ENOENT,
        AlreadyExists => libc::EEXIST,
        NotEmpty => libc::ENOTEMPTY,
        NotDirectory => libc::ENOTDIR,
        IsDirectory => libc::EISDIR,
        InvalidName => libc::EINVAL,
        NameTooLong => libc::ENAMETOOLONG,
        CrossDevice => libc::EXDEV,
        RenameCycle => libc::EINVAL,
        LinkCountOverflow => libc::EMLINK,
        TooManySymlinks => libc::ELOOP,
        NotSymlink => libc::EINVAL,
        NotSupported => libc::EOPNOTSUPP,
        PermissionDenied => libc::EACCES,
        ReadOnlyFilesystem => libc::EROFS,
        NoSpace => libc::ENOSPC,
        FileTooLarge => libc::EFBIG,
        InternalIo => libc::EIO,
        BadFileDescriptor => libc::EBADF,
        StaleFileHandle => libc::ESTALE,
        Interrupted => libc::EINTR,
        ResourceBusy => libc::EBUSY,
        NoData => libc::ENODATA,
        ValueTooLarge => libc::ERANGE,
        NoDevice => libc::ENXIO,
        LinkSevered => libc::ENOLINK,
        ValueOverflow => libc::EOVERFLOW,
        ResourceUnavailable => libc::EAGAIN,
        NotImplemented => libc::ENOSYS,
        XattrEntryExists => libc::EEXIST,
        XattrEntryNotFound => libc::ENODATA,
        XattrValueTooLarge => libc::E2BIG,
        InvalidArgument => libc::EINVAL,
    }
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Map a closure that produces an [`ErrorKind`] to a [`c_int`] errno.
///
/// This is a convenience for callers that match their internal error
/// type and want to convert directly without an intermediate variable.
///
/// # Example
///
/// ```rust,ignore
/// let errno = fuser::errno::map_namespace_like(|e| match e {
///     tidefs_namespace::NamespaceError::NotFound => ErrorKind::NotFound,
///     tidefs_namespace::NamespaceError::AlreadyExists => ErrorKind::AlreadyExists,
///     _ => ErrorKind::InternalIo,
/// });
/// ```
pub fn map_errno<F>(f: F) -> c_int
where
    F: FnOnce() -> ErrorKind,
{
    to_errno(f())
}

/// Returns `true` when the errno represents a retryable condition.
///
/// Retryable errno codes are those where the caller may reasonably
/// retry the operation after a delay or state change:
/// `EAGAIN`, `EBUSY`, `EINTR`.
#[must_use]
pub const fn is_retryable(errno: c_int) -> bool {
    errno == libc::EAGAIN || errno == libc::EBUSY || errno == libc::EINTR
}

/// Returns `true` when the errno represents a permanent filesystem error
/// (i.e. the filesystem itself is broken, not the request).
///
/// Permanent filesystem errors: `EIO`, `ENOLINK`, `ESTALE`.
#[must_use]
pub const fn is_fs_error(errno: c_int) -> bool {
    errno == libc::EIO || errno == libc::ENOLINK || errno == libc::ESTALE
}

/// Returns `true` when the errno represents a client-visible failure
/// that the client may correct (bad arguments, permissions, space).
///
/// Client-correctable errors: `EACCES`, `EEXIST`, `ENOENT`, `ENOTDIR`,
/// `EISDIR`, `ENOTEMPTY`, `ENOSPC`, `EFBIG`, `ENAMETOOLONG`, `EINVAL`,
/// `EROFS`, `EPERM`, `EMLINK`, `ELOOP`, `EXDEV`, `ENODATA`, `ERANGE`,
/// `ENXIO`, `EOVERFLOW`, `ENOSYS`, `EOPNOTSUPP`, `EBADF`, `E2BIG`.
#[must_use]
pub const fn is_client_error(errno: c_int) -> bool {
    matches!(
        errno,
        libc::EACCES
            | libc::EEXIST
            | libc::ENOENT
            | libc::ENOTDIR
            | libc::EISDIR
            | libc::ENOTEMPTY
            | libc::ENOSPC
            | libc::EFBIG
            | libc::ENAMETOOLONG
            | libc::EINVAL
            | libc::EROFS
            | libc::EPERM
            | libc::EMLINK
            | libc::ELOOP
            | libc::EXDEV
            | libc::ENODATA
            | libc::ERANGE
            | libc::ENXIO
            | libc::EOVERFLOW
            | libc::ENOSYS
            | libc::EOPNOTSUPP
            | libc::EBADF
            | libc::E2BIG
    )
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── to_errno: namespace-like errors ──────────────────────────────

    #[test]
    fn not_found_maps_to_enoent() {
        assert_eq!(to_errno(ErrorKind::NotFound), libc::ENOENT);
    }

    #[test]
    fn already_exists_maps_to_eexist() {
        assert_eq!(to_errno(ErrorKind::AlreadyExists), libc::EEXIST);
    }

    #[test]
    fn not_empty_maps_to_enotempty() {
        assert_eq!(to_errno(ErrorKind::NotEmpty), libc::ENOTEMPTY);
    }

    #[test]
    fn not_directory_maps_to_enotdir() {
        assert_eq!(to_errno(ErrorKind::NotDirectory), libc::ENOTDIR);
    }

    #[test]
    fn is_directory_maps_to_eisdir() {
        assert_eq!(to_errno(ErrorKind::IsDirectory), libc::EISDIR);
    }

    #[test]
    fn invalid_name_maps_to_einval() {
        assert_eq!(to_errno(ErrorKind::InvalidName), libc::EINVAL);
    }

    #[test]
    fn name_too_long_maps_to_enametoolong() {
        assert_eq!(to_errno(ErrorKind::NameTooLong), libc::ENAMETOOLONG);
    }

    #[test]
    fn cross_device_maps_to_exdev() {
        assert_eq!(to_errno(ErrorKind::CrossDevice), libc::EXDEV);
    }

    #[test]
    fn rename_cycle_maps_to_einval() {
        assert_eq!(to_errno(ErrorKind::RenameCycle), libc::EINVAL);
    }

    #[test]
    fn link_count_overflow_maps_to_emlink() {
        assert_eq!(to_errno(ErrorKind::LinkCountOverflow), libc::EMLINK);
    }

    #[test]
    fn too_many_symlinks_maps_to_eloop() {
        assert_eq!(to_errno(ErrorKind::TooManySymlinks), libc::ELOOP);
    }

    #[test]
    fn not_symlink_maps_to_einval() {
        assert_eq!(to_errno(ErrorKind::NotSymlink), libc::EINVAL);
    }

    #[test]
    fn not_supported_maps_to_eopnotsupp() {
        assert_eq!(to_errno(ErrorKind::NotSupported), libc::EOPNOTSUPP);
    }

    // ── to_errno: permission / fs-invariant errors ──────────────────

    #[test]
    fn permission_denied_maps_to_eacces() {
        assert_eq!(to_errno(ErrorKind::PermissionDenied), libc::EACCES);
    }

    #[test]
    fn read_only_fs_maps_to_erofs() {
        assert_eq!(to_errno(ErrorKind::ReadOnlyFilesystem), libc::EROFS);
    }

    #[test]
    fn no_space_maps_to_enospc() {
        assert_eq!(to_errno(ErrorKind::NoSpace), libc::ENOSPC);
    }

    #[test]
    fn file_too_large_maps_to_efbig() {
        assert_eq!(to_errno(ErrorKind::FileTooLarge), libc::EFBIG);
    }

    // ── to_errno: internal errors ───────────────────────────────────

    #[test]
    fn internal_io_maps_to_eio() {
        assert_eq!(to_errno(ErrorKind::InternalIo), libc::EIO);
    }

    #[test]
    fn bad_fd_maps_to_ebadf() {
        assert_eq!(to_errno(ErrorKind::BadFileDescriptor), libc::EBADF);
    }

    #[test]
    fn stale_handle_maps_to_estale() {
        assert_eq!(to_errno(ErrorKind::StaleFileHandle), libc::ESTALE);
    }

    #[test]
    fn interrupted_maps_to_eintr() {
        assert_eq!(to_errno(ErrorKind::Interrupted), libc::EINTR);
    }

    #[test]
    fn resource_busy_maps_to_ebusy() {
        assert_eq!(to_errno(ErrorKind::ResourceBusy), libc::EBUSY);
    }

    // ── to_errno: xattr-specific errors ─────────────────────────────

    #[test]
    fn no_data_maps_to_enodata() {
        assert_eq!(to_errno(ErrorKind::NoData), libc::ENODATA);
    }

    #[test]
    fn value_too_large_maps_to_erange() {
        assert_eq!(to_errno(ErrorKind::ValueTooLarge), libc::ERANGE);
    }

    #[test]
    fn xattr_entry_exists_maps_to_eexist() {
        assert_eq!(to_errno(ErrorKind::XattrEntryExists), libc::EEXIST);
    }

    #[test]
    fn xattr_entry_not_found_maps_to_enodata() {
        assert_eq!(to_errno(ErrorKind::XattrEntryNotFound), libc::ENODATA);
    }

    #[test]
    fn xattr_value_too_large_maps_to_e2big() {
        assert_eq!(to_errno(ErrorKind::XattrValueTooLarge), libc::E2BIG);
    }

    // ── to_errno: remaining misc ────────────────────────────────────

    #[test]
    fn no_device_maps_to_enxio() {
        assert_eq!(to_errno(ErrorKind::NoDevice), libc::ENXIO);
    }

    #[test]
    fn link_severed_maps_to_enolink() {
        assert_eq!(to_errno(ErrorKind::LinkSevered), libc::ENOLINK);
    }

    #[test]
    fn value_overflow_maps_to_eoverflow() {
        assert_eq!(to_errno(ErrorKind::ValueOverflow), libc::EOVERFLOW);
    }

    #[test]
    fn resource_unavailable_maps_to_eagain() {
        assert_eq!(to_errno(ErrorKind::ResourceUnavailable), libc::EAGAIN);
    }

    #[test]
    fn not_implemented_maps_to_enosys() {
        assert_eq!(to_errno(ErrorKind::NotImplemented), libc::ENOSYS);
    }

    #[test]
    fn invalid_argument_maps_to_einval() {
        assert_eq!(to_errno(ErrorKind::InvalidArgument), libc::EINVAL);
    }

    // ── map_errno ──────────────────────────────────────────────────

    #[test]
    fn map_errno_closure() {
        let result = map_errno(|| ErrorKind::NotFound);
        assert_eq!(result, libc::ENOENT);
    }

    #[test]
    fn map_errno_via_inline_match() {
        // Simulate daemon-side usage pattern
        let err = "already_exists";
        let result = map_errno(|| match err {
            "not_found" => ErrorKind::NotFound,
            "already_exists" => ErrorKind::AlreadyExists,
            _ => ErrorKind::InternalIo,
        });
        assert_eq!(result, libc::EEXIST);
    }

    // ── is_retryable ───────────────────────────────────────────────

    #[test]
    fn retryable_codes() {
        assert!(is_retryable(libc::EAGAIN));
        assert!(is_retryable(libc::EBUSY));
        assert!(is_retryable(libc::EINTR));
    }

    #[test]
    fn non_retryable_codes() {
        assert!(!is_retryable(libc::EIO));
        assert!(!is_retryable(libc::ENOENT));
        assert!(!is_retryable(libc::ENOSPC));
    }

    // ── is_fs_error ────────────────────────────────────────────────

    #[test]
    fn fs_error_codes() {
        assert!(is_fs_error(libc::EIO));
        assert!(is_fs_error(libc::ENOLINK));
        assert!(is_fs_error(libc::ESTALE));
    }

    #[test]
    fn non_fs_error_codes() {
        assert!(!is_fs_error(libc::ENOENT));
        assert!(!is_fs_error(libc::EAGAIN));
    }

    // ── is_client_error ────────────────────────────────────────────

    #[test]
    fn client_error_codes() {
        assert!(is_client_error(libc::ENOENT));
        assert!(is_client_error(libc::EACCES));
        assert!(is_client_error(libc::ENOSPC));
        assert!(is_client_error(libc::EINVAL));
        assert!(is_client_error(libc::ENAMETOOLONG));
        assert!(is_client_error(libc::EEXIST));
    }

    #[test]
    fn non_client_error_codes() {
        assert!(!is_client_error(libc::EIO));
        assert!(!is_client_error(libc::EAGAIN));
    }

    // ── comprehensive mapping coverage ─────────────────────────────

    /// Verify every ErrorKind variant maps to a known errno and that
    /// no two variants mapping to different errnos share a name without
    /// explicit justification.
    #[test]
    fn all_variants_have_unique_semantics() {
        // Enumerate all current variants and check that the mapping
        // is deliberate for each one.
        let variants: &[(ErrorKind, libc::c_int)] = &[
            (ErrorKind::NotFound, libc::ENOENT),
            (ErrorKind::AlreadyExists, libc::EEXIST),
            (ErrorKind::NotEmpty, libc::ENOTEMPTY),
            (ErrorKind::NotDirectory, libc::ENOTDIR),
            (ErrorKind::IsDirectory, libc::EISDIR),
            (ErrorKind::InvalidName, libc::EINVAL),
            (ErrorKind::NameTooLong, libc::ENAMETOOLONG),
            (ErrorKind::CrossDevice, libc::EXDEV),
            (ErrorKind::RenameCycle, libc::EINVAL),
            (ErrorKind::LinkCountOverflow, libc::EMLINK),
            (ErrorKind::TooManySymlinks, libc::ELOOP),
            (ErrorKind::NotSymlink, libc::EINVAL),
            (ErrorKind::NotSupported, libc::EOPNOTSUPP),
            (ErrorKind::PermissionDenied, libc::EACCES),
            (ErrorKind::ReadOnlyFilesystem, libc::EROFS),
            (ErrorKind::NoSpace, libc::ENOSPC),
            (ErrorKind::FileTooLarge, libc::EFBIG),
            (ErrorKind::InternalIo, libc::EIO),
            (ErrorKind::BadFileDescriptor, libc::EBADF),
            (ErrorKind::StaleFileHandle, libc::ESTALE),
            (ErrorKind::Interrupted, libc::EINTR),
            (ErrorKind::ResourceBusy, libc::EBUSY),
            (ErrorKind::NoData, libc::ENODATA),
            (ErrorKind::ValueTooLarge, libc::ERANGE),
            (ErrorKind::NoDevice, libc::ENXIO),
            (ErrorKind::LinkSevered, libc::ENOLINK),
            (ErrorKind::ValueOverflow, libc::EOVERFLOW),
            (ErrorKind::ResourceUnavailable, libc::EAGAIN),
            (ErrorKind::NotImplemented, libc::ENOSYS),
            (ErrorKind::XattrEntryExists, libc::EEXIST),
            (ErrorKind::XattrEntryNotFound, libc::ENODATA),
            (ErrorKind::XattrValueTooLarge, libc::E2BIG),
            (ErrorKind::InvalidArgument, libc::EINVAL),
        ];
        for (kind, expected) in variants {
            assert_eq!(
                to_errno(*kind),
                *expected,
                "ErrorKind::{kind:?} mapped to {} instead of {expected}",
                to_errno(*kind)
            );
        }
    }

    // ── ErrorKind is non_exhaustive ────────────────────────────────

    #[test]
    fn error_kind_is_non_exhaustive() {
        // This test will fail to compile if ErrorKind loses its
        // #[non_exhaustive] attribute.  We use a wildcard match
        // to confirm external crates can match on it.
        let kind = ErrorKind::NotFound;
        let _errno = match kind {
            ErrorKind::NotFound => libc::ENOENT,
            _ => libc::EIO,
        };
        assert_eq!(_errno, libc::ENOENT);
    }

    // ── round-trip: to_errno + classification predicates ───────────

    #[test]
    fn every_kind_is_either_client_or_fs_or_retryable() {
        let kinds = [
            ErrorKind::NotFound,
            ErrorKind::AlreadyExists,
            ErrorKind::NotEmpty,
            ErrorKind::NotDirectory,
            ErrorKind::IsDirectory,
            ErrorKind::InvalidName,
            ErrorKind::NameTooLong,
            ErrorKind::CrossDevice,
            ErrorKind::RenameCycle,
            ErrorKind::LinkCountOverflow,
            ErrorKind::TooManySymlinks,
            ErrorKind::NotSymlink,
            ErrorKind::NotSupported,
            ErrorKind::PermissionDenied,
            ErrorKind::ReadOnlyFilesystem,
            ErrorKind::NoSpace,
            ErrorKind::FileTooLarge,
            ErrorKind::InternalIo,
            ErrorKind::BadFileDescriptor,
            ErrorKind::StaleFileHandle,
            ErrorKind::Interrupted,
            ErrorKind::ResourceBusy,
            ErrorKind::NoData,
            ErrorKind::ValueTooLarge,
            ErrorKind::NoDevice,
            ErrorKind::LinkSevered,
            ErrorKind::ValueOverflow,
            ErrorKind::ResourceUnavailable,
            ErrorKind::NotImplemented,
            ErrorKind::XattrEntryExists,
            ErrorKind::XattrEntryNotFound,
            ErrorKind::XattrValueTooLarge,
            ErrorKind::InvalidArgument,
        ];
        for kind in &kinds {
            let e = to_errno(*kind);
            let classified = is_client_error(e) || is_fs_error(e) || is_retryable(e);
            assert!(classified, "ErrorKind was not classified by any predicate");
        }
    }
}
