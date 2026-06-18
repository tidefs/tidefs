// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Centralized Linux errno mapping contract for the kernel VFS adapter.
//!
//! This module defines the error categories that TideFS kernel operations
//! produce and maps them to canonical Linux [`Errno`] values. Every
//! operation in this crate must use the category-to-errno mappings below
//! rather than returning ad-hoc errno values, so that the kernel VFS layer
//! and userspace observe consistent POSIX error codes.
//!
//! # Categories and canonical errno
//!
//! | Category          | Primary errno  | Meaning |
//! |-------------------|----------------|---------|
//! | `Storage`         | `EIO`          | Unrecoverable I/O failure at or below the storage layer. |
//! | `Namespace`       | `ENOENT`       | Lookup/name-resolution failure; variant-specific errno for type mismatches. |
//! | `Permission`      | `EACCES`       | Caller lacks required access rights; `EPERM` for restricted operations. |
//! | `SpaceExhausted`  | `ENOSPC`       | Pool or device has no free capacity. |
//! | `Corruption`      | `EUCLEAN`      | On-disk structure integrity failure; `EIO` when the corruption prevents any I/O. |
//! | `Stale`           | `ESTALE`       | Cached state no longer matches stable storage (e.g., generation mismatch). |
//! | `Unsupported`     | `EOPNOTSUPP`   | Operation not implemented or not applicable to this node type. |
//! | `Busy`            | `EBUSY`        | Resource is temporarily unavailable due to an in-progress operation. |

// Import Errno through the Kbuild/cargo bridge pattern.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::Errno;

#[cfg(not(CONFIG_RUST))]
use tidefs_kmod_bridge::kernel_types::Errno;

// ---------------------------------------------------------------------------
// ErrorCategory — the error taxonomy
// ---------------------------------------------------------------------------

/// Classifies a kernel-level error into one of the canonical TideFS
/// error categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    /// Unrecoverable failure in the storage backend, object store,
    /// or data-path I/O. Maps to `EIO`.
    Storage,
    /// Name-resolution failure: entry not found, wrong node type,
    /// directory not empty, name too long, cross-device link, etc.
    Namespace,
    /// Caller lacks required access rights.
    Permission,
    /// Pool or device has no free capacity.
    SpaceExhausted,
    /// On-disk structural integrity failure detected via checksum
    /// mismatch, magic mismatch, or record-level corruption.
    /// Maps to `EUCLEAN` (structure needs cleaning).
    Corruption,
    /// Cached in-memory state is stale relative to stable storage.
    Stale,
    /// Operation not implemented or not applicable.
    Unsupported,
    /// Resource is temporarily unavailable.
    Busy,
}

impl ErrorCategory {
    #[must_use]
    pub const fn to_errno(self) -> Errno {
        match self {
            Self::Storage => Errno::EIO,
            Self::Namespace => Errno::ENOENT,
            Self::Permission => Errno::EACCES,
            Self::SpaceExhausted => Errno::ENOSPC,
            Self::Corruption => Errno::EUCLEAN,
            Self::Stale => Errno::ESTALE,
            Self::Unsupported => Errno::EOPNOTSUPP,
            Self::Busy => Errno::EBUSY,
        }
    }
}

// ---------------------------------------------------------------------------
// KernelErrno — centralised errno factory
// ---------------------------------------------------------------------------

/// Centralized errno mapping for TideFS kernel operations.
///
/// Each constant returns the canonical [`Errno`] for a specific
/// error situation within an [`ErrorCategory`].
pub struct KernelErrno;

impl KernelErrno {
    // ── Storage errors ──────────────────────────────────────────────

    pub const STORAGE_IO: Errno = ErrorCategory::Storage.to_errno();
    pub const STORAGE_OBJECT_READ: Errno = ErrorCategory::Storage.to_errno();
    pub const STORAGE_OBJECT_WRITE: Errno = ErrorCategory::Storage.to_errno();
    pub const STORAGE_EXTENT_FAILURE: Errno = ErrorCategory::Corruption.to_errno();
    pub const STORAGE_SUPERBLOCK_READ: Errno = ErrorCategory::Corruption.to_errno();

    /// Storage device not present or not configured (ENODEV).
    pub const STORAGE_NO_DEVICE: Errno = Errno::ENODEV;
    /// Storage device not available or unaddressable (ENXIO).
    pub const STORAGE_DEVICE_UNAVAILABLE: Errno = Errno::ENXIO;
    /// Memory allocation failure at the kernel level (ENOMEM).
    pub const RESOURCE_MEMORY: Errno = Errno::ENOMEM;
    /// Numeric overflow in offset, size, or counter computation (EOVERFLOW).
    pub const VALUE_OVERFLOW: Errno = Errno::EOVERFLOW;

    // ── Namespace errors ────────────────────────────────────────────

    pub const NS_NOT_FOUND: Errno = Errno::ENOENT;
    pub const NS_NAME_TOO_LONG: Errno = Errno::ENAMETOOLONG;
    pub const NS_NOT_DIRECTORY: Errno = Errno::ENOTDIR;
    pub const NS_IS_DIRECTORY: Errno = Errno::EISDIR;
    pub const NS_DIR_NOT_EMPTY: Errno = Errno::ENOTEMPTY;
    pub const NS_ALREADY_EXISTS: Errno = Errno::EEXIST;
    pub const NS_CROSS_DEVICE: Errno = Errno::EXDEV;
    pub const NS_TOO_MANY_LINKS: Errno = Errno::EMLINK;
    pub const NS_SYMLINK_LOOP: Errno = Errno::ELOOP;

    // ── Permission errors ───────────────────────────────────────────

    pub const PERM_DENIED: Errno = Errno::EACCES;
    pub const PERM_NOT_PERMITTED: Errno = Errno::EPERM;
    pub const PERM_READ_ONLY_FS: Errno = Errno::EROFS;

    // ── Extended attribute errors ───────────────────────────────────

    /// Requested extended attribute does not exist (ENODATA / ENOATTR).
    /// POSIX getxattr semantics require ENODATA, not ENOENT, for a
    /// missing attribute on an existing inode. The FUSE userspace
    /// adapter uses ENODATA for this case; the kernel bridge must match.
    pub const XATTR_NOT_FOUND: Errno = Errno::ENODATA;

    // ── Space errors ────────────────────────────────────────────────

    pub const SPACE_EXHAUSTED: Errno = Errno::ENOSPC;
    pub const SPACE_FILE_TOO_LARGE: Errno = Errno::EFBIG;

    // ── Corruption errors ───────────────────────────────────────────

    pub const CORRUPTION_STRUCTURE: Errno = ErrorCategory::Corruption.to_errno();
    pub const CORRUPTION_COMMITTED_ROOT: Errno = ErrorCategory::Corruption.to_errno();
    pub const CORRUPTION_INTENT_LOG: Errno = ErrorCategory::Corruption.to_errno();
    pub const CORRUPTION_LABEL: Errno = ErrorCategory::Corruption.to_errno();

    // ── Stale errors ────────────────────────────────────────────────

    pub const STALE_GENERATION: Errno = Errno::ESTALE;
    pub const STALE_FILE_HANDLE: Errno = Errno::ESTALE;

    // ── Unsupported / invalid ───────────────────────────────────────

    pub const UNSUPPORTED_OP: Errno = Errno::EOPNOTSUPP;
    pub const INVALID_ARGUMENT: Errno = Errno::EINVAL;
    pub const INVALID_FILE_DESCRIPTOR: Errno = Errno::EBADF;
    /// Result too large for supplied buffer (ERANGE).
    /// Used when readdir results overflow the caller buffer or when
    /// a value cannot be represented in the available output space.
    /// The FUSE adapter uses ERANGE for readdir buffer-too-small.
    pub const RESULT_TOO_LARGE: Errno = Errno::ERANGE;
    /// Operation interrupted by a signal (EINTR).
    /// Used when a blocking operation is interrupted before completion,
    /// matching POSIX/EINTR semantics shared with the FUSE adapter.
    pub const INTERRUPTED: Errno = Errno::EINTR;

    /// System call or operation not implemented (ENOSYS).
    pub const UNIMPLEMENTED_SYSCALL: Errno = Errno::ENOSYS;
    /// Inappropriate ioctl for device (ENOTTY).
    pub const INAPPROPRIATE_IOCTL: Errno = Errno::ENOTTY;

    // ── Busy ────────────────────────────────────────────────────────

    pub const RESOURCE_BUSY: Errno = Errno::EBUSY;

    /// File locking deadlock detected (EDEADLK).
    pub const LOCK_DEADLOCK: Errno = Errno::EDEADLK;

    // ── Page authority ──────────────────────────────────────────────

    pub const PAGE_AUTHORITY_CONFLICT: Errno = Errno::EIO;
    pub const PAGE_AUTHORITY_RETRY: Errno = Errno::EAGAIN;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::KernelErrno;

    #[test]
    fn category_storage_is_eio() {
        assert_eq!(ErrorCategory::Storage.to_errno(), Errno::EIO);
    }

    #[test]
    fn category_namespace_is_enoent() {
        assert_eq!(ErrorCategory::Namespace.to_errno(), Errno::ENOENT);
    }

    #[test]
    fn category_permission_is_eacces() {
        assert_eq!(ErrorCategory::Permission.to_errno(), Errno::EACCES);
    }

    #[test]
    fn category_space_exhausted_is_enospc() {
        assert_eq!(ErrorCategory::SpaceExhausted.to_errno(), Errno::ENOSPC);
    }

    #[test]
    fn category_corruption_is_euclean() {
        assert_eq!(ErrorCategory::Corruption.to_errno(), Errno::EUCLEAN);
    }

    #[test]
    fn category_stale_is_estale() {
        assert_eq!(ErrorCategory::Stale.to_errno(), Errno::ESTALE);
    }

    #[test]
    fn category_unsupported_is_eopnotsupp() {
        assert_eq!(ErrorCategory::Unsupported.to_errno(), Errno::EOPNOTSUPP);
    }

    #[test]
    fn category_busy_is_ebusy() {
        assert_eq!(ErrorCategory::Busy.to_errno(), Errno::EBUSY);
    }

    #[test]
    fn storage_constants_match() {
        assert_eq!(KernelErrno::STORAGE_IO, Errno::EIO);
        assert_eq!(KernelErrno::STORAGE_OBJECT_READ, Errno::EIO);
        assert_eq!(KernelErrno::STORAGE_OBJECT_WRITE, Errno::EIO);
    }

    #[test]
    fn storage_device_constants_match() {
        assert_eq!(KernelErrno::STORAGE_NO_DEVICE, Errno::ENODEV);
        assert_eq!(KernelErrno::STORAGE_DEVICE_UNAVAILABLE, Errno::ENXIO);
    }

    #[test]
    fn storage_corruption_constants_match() {
        assert_eq!(KernelErrno::STORAGE_EXTENT_FAILURE, Errno::EUCLEAN);
        assert_eq!(KernelErrno::STORAGE_SUPERBLOCK_READ, Errno::EUCLEAN);
    }

    #[test]
    fn namespace_constants_have_correct_values() {
        assert_eq!(KernelErrno::NS_NOT_FOUND, Errno::ENOENT);
        assert_eq!(KernelErrno::NS_NAME_TOO_LONG, Errno::ENAMETOOLONG);
        assert_eq!(KernelErrno::NS_NOT_DIRECTORY, Errno::ENOTDIR);
        assert_eq!(KernelErrno::NS_IS_DIRECTORY, Errno::EISDIR);
        assert_eq!(KernelErrno::NS_DIR_NOT_EMPTY, Errno::ENOTEMPTY);
        assert_eq!(KernelErrno::NS_ALREADY_EXISTS, Errno::EEXIST);
        assert_eq!(KernelErrno::NS_CROSS_DEVICE, Errno::EXDEV);
        assert_eq!(KernelErrno::NS_TOO_MANY_LINKS, Errno::EMLINK);
        assert_eq!(KernelErrno::NS_SYMLINK_LOOP, Errno::ELOOP);
    }

    #[test]
    fn permission_constants_have_correct_values() {
        assert_eq!(KernelErrno::PERM_DENIED, Errno::EACCES);
        assert_eq!(KernelErrno::PERM_NOT_PERMITTED, Errno::EPERM);
        assert_eq!(KernelErrno::PERM_READ_ONLY_FS, Errno::EROFS);
    }

    #[test]
    fn space_constants_have_correct_values() {
        assert_eq!(KernelErrno::SPACE_EXHAUSTED, Errno::ENOSPC);
        assert_eq!(KernelErrno::SPACE_FILE_TOO_LARGE, Errno::EFBIG);
    }

    #[test]
    fn corruption_constants_are_euclean() {
        assert_eq!(KernelErrno::CORRUPTION_STRUCTURE, Errno::EUCLEAN);
        assert_eq!(KernelErrno::CORRUPTION_COMMITTED_ROOT, Errno::EUCLEAN);
        assert_eq!(KernelErrno::CORRUPTION_INTENT_LOG, Errno::EUCLEAN);
        assert_eq!(KernelErrno::CORRUPTION_LABEL, Errno::EUCLEAN);
    }

    #[test]
    fn stale_constants_are_estale() {
        assert_eq!(KernelErrno::STALE_GENERATION, Errno::ESTALE);
        assert_eq!(KernelErrno::STALE_FILE_HANDLE, Errno::ESTALE);
    }

    #[test]
    fn other_constants_have_correct_values() {
        assert_eq!(KernelErrno::UNSUPPORTED_OP, Errno::EOPNOTSUPP);
        assert_eq!(KernelErrno::INVALID_ARGUMENT, Errno::EINVAL);
        assert_eq!(KernelErrno::INVALID_FILE_DESCRIPTOR, Errno::EBADF);
        assert_eq!(KernelErrno::RESOURCE_BUSY, Errno::EBUSY);
        assert_eq!(KernelErrno::UNIMPLEMENTED_SYSCALL, Errno::ENOSYS);
        assert_eq!(KernelErrno::LOCK_DEADLOCK, Errno::EDEADLK);
        assert_eq!(KernelErrno::VALUE_OVERFLOW, Errno::EOVERFLOW);
        assert_eq!(KernelErrno::RESOURCE_MEMORY, Errno::ENOMEM);
        assert_eq!(KernelErrno::RESULT_TOO_LARGE, Errno::ERANGE);
        assert_eq!(KernelErrno::INTERRUPTED, Errno::EINTR);
    }

    #[test]
    fn xattr_constants_have_correct_values() {
        assert_eq!(KernelErrno::XATTR_NOT_FOUND, Errno::ENODATA);
    }

    #[test]
    fn page_authority_constants_have_correct_values() {
        assert_eq!(KernelErrno::PAGE_AUTHORITY_CONFLICT, Errno::EIO);
        assert_eq!(KernelErrno::PAGE_AUTHORITY_RETRY, Errno::EAGAIN);
    }

    #[test]
    fn euclean_value_is_117() {
        assert_eq!(Errno::EUCLEAN.raw(), 117);
    }

    #[test]
    fn all_categories_have_distinct_defaults() {
        use alloc::collections::BTreeSet;
        let defaults: BTreeSet<u16> = [
            ErrorCategory::Storage,
            ErrorCategory::Namespace,
            ErrorCategory::Permission,
            ErrorCategory::SpaceExhausted,
            ErrorCategory::Corruption,
            ErrorCategory::Stale,
            ErrorCategory::Unsupported,
            ErrorCategory::Busy,
        ]
        .iter()
        .map(|c| c.to_errno().raw())
        .collect();
        assert_eq!(defaults.len(), 8);
    }
}
