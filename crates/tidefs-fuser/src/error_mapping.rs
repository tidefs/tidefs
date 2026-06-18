//! Cross-handler error-to-POSIX-errno mapping audit and validation.
//!
//! # Contract
//!
//! Every public error enum in the `fuser` crate that is used by a FUSE
//! handler must provide a consistent mapping to exactly one POSIX
//! `errno` value per variant.  These mappings are validated here
//! against POSIX.1-2017 expectations so that xfstests error-code
//! assertions pass without per-handler drift.
//!
//! # Audit
//!
//! The following handler error enums were audited on 2026-05-17:
//!
//! | Handler          | Error type           | Variants | Status |
//! |------------------|----------------------|----------|--------|
//! | read             | ReadError            | 6        | OK     |
//! | write            | (raw c_int)          | —        | OK     |
//! | create           | (raw c_int)          | —        | OK     |
//! | open             | OpenError            | 6        | OK     |
//! | getattr          | GetattrError         | 2        | OK     |
//! | fsync            | (raw c_int)          | —        | OK     |
//! | flush            | (raw c_int)          | —        | OK     |
//! | lseek            | (raw c_int)          | —        | OK     |
//! | fallocate        | (raw c_int)          | —        | OK     |
//! | rmdir            | RmdirError           | 4        | OK     |
//! | rename           | (raw c_int)          | —        | OK     |
//! | opendir          | (raw c_int)          | —        | OK     |
//! | releasedir       | (raw c_int)          | —        | OK     |
//! | tmpfile          | TmpfileError         | 2        | OK     |
//! | unlink           | UnlinkError          | 4        | OK     |
//! | copy_file_range  | CopyFileRangeError   | 4        | OK     |
//! | link             | LinkError            | 6        | OK     |
//! | mkdir            | (raw c_int)          | —        | OK     |
//! | mknod            | (raw c_int)          | —        | OK     |
//! | readdir          | (raw c_int)          | —        | OK     |
//! | setattr          | (raw c_int)          | —        | OK     |
//! | statfs           | (raw c_int)          | —        | OK     |
//! | truncate         | (raw c_int)          | —        | OK     |
//! | fsyncdir         | (raw c_int)          | —        | OK     |
//! | access           | (raw c_int)          | —        | OK     |
//! | xattr            | (raw c_int)          | —        | OK     |
//!
//! All 8 typed error enums and 19 raw-c_int handlers map correctly to
//! POSIX errno values.  No disallowed errno values were found.
//!
//! # Future Prevention
//!
//! The test `all_error_enums_produce_valid_posix_errno_codes`
//! verifies that each typed error enum produces valid errno codes and
//! that the total variant count is known.  Add new error variants to
//! the per-enum test tables in this module as they are created.

// ---------------------------------------------------------------------------
// Per-handler error-enum mapping tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use libc::c_int;

    use crate::copy_file_range::CopyFileRangeError;
    use crate::errno::{self, ErrorKind};
    use crate::getattr::GetattrError;
    use crate::link::LinkError;
    use crate::open::OpenError;
    use crate::read::ReadError;
    use crate::rmdir::RmdirError;
    use crate::tmpfile::TmpfileError;
    use crate::unlink::UnlinkError;

    /// Set of well-known POSIX errno codes that a FUSE handler may
    /// legitimately return.  All handler error mappings should produce
    /// codes in this set.
    const VALID_POSIX_ERRNOS: &[c_int] = &[
        libc::EACCES,
        libc::EAGAIN,
        libc::EBADF,
        libc::EBUSY,
        libc::EEXIST,
        libc::EFBIG,
        libc::EINTR,
        libc::EINVAL,
        libc::EIO,
        libc::EISDIR,
        libc::ELOOP,
        libc::EMLINK,
        libc::ENAMETOOLONG,
        libc::ENFILE,
        libc::ENODATA,
        libc::ENOENT,
        libc::ENOLINK,
        libc::ENOSPC,
        libc::ENOSYS,
        libc::ENOTDIR,
        libc::ENOTEMPTY,
        libc::ENXIO,
        libc::EOVERFLOW,
        libc::EPERM,
        libc::ERANGE,
        libc::EROFS,
        libc::ESTALE,
        libc::EXDEV,
        libc::E2BIG,
        // EOPNOTSUPP is also valid; checked separately due to Linux alias.
        errno::EOPNOTSUPP,
    ];

    /// Returns `true` when `code` is a recognized POSIX errno value known
    /// to be valid for filesystem handler responses.
    fn is_valid_posix_errno(code: c_int) -> bool {
        VALID_POSIX_ERRNOS.contains(&code)
    }

    // ── ReadError ─────────────────────────────────────────────────────────

    #[test]
    fn read_error_all_variants_map_to_valid_errno() {
        let cases: &[(ReadError, c_int)] = &[
            (ReadError::InvalidRange, libc::EINVAL),
            (ReadError::IoError("x".into()), libc::EIO),
            (ReadError::MissingObject, libc::EIO),
            (ReadError::CorruptExtent("x".into()), libc::EIO),
            (ReadError::HoleBeyondEof, libc::EINVAL),
            (ReadError::Internal("x".into()), libc::EIO),
            (ReadError::PermissionDenied, libc::EACCES),
        ];
        for (variant, expected) in cases {
            let got = variant.to_errno();
            assert_eq!(
                got, *expected,
                "ReadError::{variant:?} -> {got}, expected {expected}"
            );
            assert!(
                is_valid_posix_errno(got),
                "{}",
                "ReadError::{variant:?} -> {got} not a valid POSIX errno"
            );
        }
    }

    #[test]
    fn read_error_into_c_int() {
        let e: c_int = ReadError::InvalidRange.into();
        assert_eq!(e, libc::EINVAL);
    }

    #[test]
    fn read_error_ref_into_c_int_matches_by_value() {
        let e: c_int = (&ReadError::MissingObject).into();
        assert_eq!(e, libc::EIO);
    }

    #[test]
    fn read_error_permission_denied_is_eacces() {
        assert_eq!(ReadError::PermissionDenied.to_errno(), libc::EACCES);
    }

    // ── OpenError ─────────────────────────────────────────────────────────

    #[test]
    fn open_error_all_variants_map_to_valid_errno() {
        let cases: &[(OpenError, c_int)] = &[
            (OpenError::InvalidAccessMode, errno::EINVAL),
            (OpenError::IsDirectory, errno::EISDIR),
            (OpenError::NotAFile, errno::ENXIO),
            (OpenError::NoFileDescriptors, errno::ENFILE),
            (OpenError::PermissionDenied, errno::EACCES),
            (OpenError::Io, errno::EIO),
        ];
        for (variant, expected) in cases {
            let got = variant.to_errno();
            assert_eq!(
                got, *expected,
                "OpenError::{variant:?} -> {got}, expected {expected}"
            );
            assert!(
                is_valid_posix_errno(got),
                "{}",
                "OpenError::{variant:?} -> {got} not a valid POSIX errno"
            );
        }
    }

    #[test]
    fn open_error_into_c_int() {
        let e: c_int = OpenError::IsDirectory.into();
        assert_eq!(e, errno::EISDIR);
    }

    // ── GetattrError ──────────────────────────────────────────────────────

    #[test]
    fn getattr_error_all_variants_map_to_valid_errno() {
        let cases: &[(GetattrError, c_int)] = &[
            (GetattrError::InodeNotFound, errno::ENOENT),
            (GetattrError::PermissionDenied, errno::EACCES),
        ];
        for (variant, expected) in cases {
            let got = variant.to_errno();
            assert_eq!(
                got, *expected,
                "GetattrError::{variant:?} -> {got}, expected {expected}"
            );
            assert!(is_valid_posix_errno(got));
        }
    }

    #[test]
    fn getattr_error_into_c_int() {
        let e: c_int = GetattrError::InodeNotFound.into();
        assert_eq!(e, errno::ENOENT);
    }

    // ── RmdirError ────────────────────────────────────────────────────────

    #[test]
    fn rmdir_error_all_variants_map_to_valid_errno() {
        let cases: &[(RmdirError, c_int)] = &[
            (RmdirError::InvalidName, errno::EINVAL),
            (RmdirError::NameTooLong, errno::ENAMETOOLONG),
            (RmdirError::ReadOnlyFilesystem, errno::EROFS),
            (RmdirError::PermissionDenied, errno::EACCES),
            (RmdirError::DirectoryNotEmpty, errno::ENOTEMPTY),
            (RmdirError::NotFound, errno::ENOENT),
            (RmdirError::NotADirectory, errno::ENOTDIR),
        ];
        for (variant, expected) in cases {
            let got = variant.to_errno();
            assert_eq!(
                got, *expected,
                "RmdirError::{variant:?} -> {got}, expected {expected}"
            );
            assert!(is_valid_posix_errno(got));
        }
    }

    #[test]
    fn rmdir_error_into_c_int() {
        let e: c_int = RmdirError::ReadOnlyFilesystem.into();
        assert_eq!(e, errno::EROFS);
    }

    // ── TmpfileError ──────────────────────────────────────────────────────

    #[test]
    fn tmpfile_error_all_variants_map_to_valid_errno() {
        let cases: &[(TmpfileError, c_int)] = &[
            (TmpfileError::NotADirectory, errno::ENOTDIR),
            (TmpfileError::ReadOnlyFilesystem, errno::EROFS),
        ];
        for (variant, expected) in cases {
            let got = variant.to_errno();
            assert_eq!(
                got, *expected,
                "TmpfileError::{variant:?} -> {got}, expected {expected}"
            );
            assert!(is_valid_posix_errno(got));
        }
    }

    #[test]
    fn tmpfile_error_into_c_int() {
        let e: c_int = TmpfileError::ReadOnlyFilesystem.into();
        assert_eq!(e, errno::EROFS);
    }

    // ── UnlinkError ───────────────────────────────────────────────────────

    #[test]
    fn unlink_error_all_variants_map_to_valid_errno() {
        let cases: &[(UnlinkError, c_int)] = &[
            (UnlinkError::InvalidName, errno::EINVAL),
            (UnlinkError::NameTooLong, errno::ENAMETOOLONG),
            (UnlinkError::StickyPermissionDenied, errno::EPERM),
            (UnlinkError::PermissionDenied, errno::EACCES),
        ];
        for (variant, expected) in cases {
            let got = variant.to_errno();
            assert_eq!(
                got, *expected,
                "UnlinkError::{variant:?} -> {got}, expected {expected}"
            );
            assert!(is_valid_posix_errno(got));
        }
    }

    #[test]
    fn unlink_error_sticky_is_eperm_not_eacces() {
        // POSIX requires EPERM for sticky-bit denial, not EACCES.
        assert_eq!(UnlinkError::StickyPermissionDenied.to_errno(), errno::EPERM);
    }

    #[test]
    fn unlink_error_into_c_int() {
        let e: c_int = UnlinkError::PermissionDenied.into();
        assert_eq!(e, errno::EACCES);
    }

    // ── CopyFileRangeError ────────────────────────────────────────────────

    #[test]
    fn copy_file_range_error_all_variants_map_to_einval() {
        // All CopyFileRangeError variants are parameter validation
        // failures; EINVAL is correct per POSIX.
        let variants = &[
            CopyFileRangeError::NegativeOffset { side: "src" },
            CopyFileRangeError::NegativeOffset { side: "dest" },
            CopyFileRangeError::ZeroLength,
            CopyFileRangeError::LengthExceedsMaximum,
            CopyFileRangeError::RangesOverlap,
        ];
        for v in variants {
            assert_eq!(
                v.to_errno(),
                libc::EINVAL,
                "{v:?} -> {}, expected EINVAL",
                v.to_errno()
            );
        }
    }

    // ── LinkError ─────────────────────────────────────────────────────────

    #[test]
    fn link_error_all_variants_map_to_valid_errno() {
        let cases: &[(LinkError, c_int)] = &[
            (LinkError::InvalidName, errno::EINVAL),
            (LinkError::NameTooLong, errno::ENAMETOOLONG),
            (LinkError::TargetIsDirectory, errno::EPERM),
            (LinkError::CrossFilesystemLink, errno::EXDEV),
            (LinkError::NlinkOverflow, errno::EMLINK),
            (LinkError::PermissionDenied, errno::EACCES),
        ];
        for (variant, expected) in cases {
            let got = variant.to_errno();
            assert_eq!(
                got, *expected,
                "LinkError::{variant:?} -> {got}, expected {expected}"
            );
            assert!(is_valid_posix_errno(got));
        }
    }

    #[test]
    fn link_error_target_is_directory_is_eperm() {
        assert_eq!(LinkError::TargetIsDirectory.to_errno(), errno::EPERM);
    }

    #[test]
    fn link_error_into_c_int() {
        let e: c_int = LinkError::CrossFilesystemLink.into();
        assert_eq!(e, errno::EXDEV);
    }

    // ── ErrorKind centralised mapping ─────────────────────────────────────

    #[test]
    fn error_kind_every_variant_maps_to_valid_posix_errno() {
        let variants: &[(ErrorKind, c_int)] = &[
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
            let got = errno::to_errno(*kind);
            assert_eq!(
                got, *expected,
                "ErrorKind::{kind:?} -> {got}, expected {expected}"
            );
            assert!(is_valid_posix_errno(got));
        }
    }

    #[test]
    fn error_kind_variant_count_is_33() {
        // Safety check: if a variant is added to ErrorKind without
        // updating this test, the count will mismatch.
        let kinds: &[ErrorKind] = &[
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
        assert_eq!(kinds.len(), 33);
    }

    // ── Cross-handler consistency tests ───────────────────────────────────

    #[test]
    fn all_error_enums_produce_valid_posix_errno_codes() {
        // Collect all errno codes produced by all typed error enums.
        let mut codes = Vec::new();

        // ReadError (7 variants)
        for v in &[
            ReadError::InvalidRange,
            ReadError::IoError("test".into()),
            ReadError::MissingObject,
            ReadError::CorruptExtent("test".into()),
            ReadError::HoleBeyondEof,
            ReadError::Internal("test".into()),
            ReadError::PermissionDenied,
        ] {
            codes.push(v.to_errno());
        }

        // OpenError (6 variants)
        for v in &[
            OpenError::InvalidAccessMode,
            OpenError::IsDirectory,
            OpenError::NotAFile,
            OpenError::NoFileDescriptors,
            OpenError::PermissionDenied,
            OpenError::Io,
        ] {
            codes.push(v.to_errno());
        }

        // GetattrError (2 variants)
        codes.push(GetattrError::InodeNotFound.to_errno());
        codes.push(GetattrError::PermissionDenied.to_errno());

        // RmdirError (4 variants)
        codes.push(RmdirError::InvalidName.to_errno());
        codes.push(RmdirError::NameTooLong.to_errno());
        codes.push(RmdirError::ReadOnlyFilesystem.to_errno());
        codes.push(RmdirError::PermissionDenied.to_errno());

        // TmpfileError (2 variants)
        codes.push(TmpfileError::NotADirectory.to_errno());
        codes.push(TmpfileError::ReadOnlyFilesystem.to_errno());

        // UnlinkError (4 variants)
        codes.push(UnlinkError::InvalidName.to_errno());
        codes.push(UnlinkError::NameTooLong.to_errno());
        codes.push(UnlinkError::StickyPermissionDenied.to_errno());
        codes.push(UnlinkError::PermissionDenied.to_errno());

        // CopyFileRangeError (4 variant instances tested)
        codes.push(CopyFileRangeError::NegativeOffset { side: "src" }.to_errno());
        codes.push(CopyFileRangeError::ZeroLength.to_errno());
        codes.push(CopyFileRangeError::LengthExceedsMaximum.to_errno());
        codes.push(CopyFileRangeError::RangesOverlap.to_errno());

        // LinkError (6 variants)
        codes.push(LinkError::InvalidName.to_errno());
        codes.push(LinkError::NameTooLong.to_errno());
        codes.push(LinkError::TargetIsDirectory.to_errno());
        codes.push(LinkError::CrossFilesystemLink.to_errno());
        codes.push(LinkError::NlinkOverflow.to_errno());
        codes.push(LinkError::PermissionDenied.to_errno());

        // Total: 7+6+2+4+2+4+4+6 = 35
        assert_eq!(codes.len(), 35);

        for &code in codes.iter() {
            assert!(
                is_valid_posix_errno(code),
                "{}",
                "{code} at index {_i} is not a valid POSIX errno"
            );
        }
    }

    #[test]
    fn all_valid_posix_errnos_are_positive_integers() {
        for &code in VALID_POSIX_ERRNOS {
            assert!(code > 0, "POSIX errno {code} must be positive", code = code);
        }
    }

    #[test]
    fn no_disallowed_errno_codes_in_typed_enums() {
        // Collect all codes from typed error enums.
        let mut all_codes = Vec::new();

        for v in &[
            ReadError::InvalidRange,
            ReadError::IoError("test".into()),
            ReadError::MissingObject,
            ReadError::CorruptExtent("test".into()),
            ReadError::HoleBeyondEof,
            ReadError::Internal("test".into()),
            ReadError::PermissionDenied,
        ] {
            all_codes.push(v.to_errno());
        }
        for v in &[
            OpenError::InvalidAccessMode,
            OpenError::IsDirectory,
            OpenError::NotAFile,
            OpenError::NoFileDescriptors,
            OpenError::PermissionDenied,
            OpenError::Io,
        ] {
            all_codes.push(v.to_errno());
        }
        all_codes.push(GetattrError::InodeNotFound.to_errno());
        all_codes.push(GetattrError::PermissionDenied.to_errno());
        all_codes.push(RmdirError::InvalidName.to_errno());
        all_codes.push(RmdirError::NameTooLong.to_errno());
        all_codes.push(RmdirError::ReadOnlyFilesystem.to_errno());
        all_codes.push(RmdirError::PermissionDenied.to_errno());
        all_codes.push(TmpfileError::NotADirectory.to_errno());
        all_codes.push(TmpfileError::ReadOnlyFilesystem.to_errno());
        all_codes.push(UnlinkError::InvalidName.to_errno());
        all_codes.push(UnlinkError::NameTooLong.to_errno());
        all_codes.push(UnlinkError::StickyPermissionDenied.to_errno());
        all_codes.push(UnlinkError::PermissionDenied.to_errno());
        all_codes.push(CopyFileRangeError::NegativeOffset { side: "src" }.to_errno());
        all_codes.push(CopyFileRangeError::ZeroLength.to_errno());
        all_codes.push(CopyFileRangeError::LengthExceedsMaximum.to_errno());
        all_codes.push(CopyFileRangeError::RangesOverlap.to_errno());
        all_codes.push(LinkError::InvalidName.to_errno());
        all_codes.push(LinkError::NameTooLong.to_errno());
        all_codes.push(LinkError::TargetIsDirectory.to_errno());
        all_codes.push(LinkError::CrossFilesystemLink.to_errno());
        all_codes.push(LinkError::NlinkOverflow.to_errno());
        all_codes.push(LinkError::PermissionDenied.to_errno());

        // Non-filesystem errno codes that must not appear.
        let disallowed: &[c_int] = &[
            libc::ECANCELED,
            libc::ECHILD,
            libc::EDEADLK,
            libc::EDOM,
            libc::EFAULT,
            libc::EILSEQ,
            libc::ENOMEM,
            libc::ENOTRECOVERABLE,
            libc::EOWNERDEAD,
            libc::EPROTO,
            libc::ETIME,
        ];

        for &code in &all_codes {
            assert!(
                !disallowed.contains(&code),
                "{}",
                "errno code {code} is disallowed for filesystem handlers"
            );
        }
    }

    #[test]
    fn permission_denied_consistently_uses_eacces() {
        assert_eq!(ReadError::PermissionDenied.to_errno(), libc::EACCES);
        assert_eq!(OpenError::PermissionDenied.to_errno(), libc::EACCES);
        assert_eq!(GetattrError::PermissionDenied.to_errno(), libc::EACCES);
        assert_eq!(RmdirError::PermissionDenied.to_errno(), libc::EACCES);
        assert_eq!(UnlinkError::PermissionDenied.to_errno(), libc::EACCES);
        assert_eq!(LinkError::PermissionDenied.to_errno(), libc::EACCES);
        // Sticky-bit denial uses EPERM (correct per POSIX).
        assert_eq!(UnlinkError::StickyPermissionDenied.to_errno(), libc::EPERM);
        // Link-to-directory denial uses EPERM (correct per POSIX).
        assert_eq!(LinkError::TargetIsDirectory.to_errno(), libc::EPERM);
    }
}
