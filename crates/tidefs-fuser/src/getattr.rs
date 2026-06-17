//! FUSE `getattr` handler helpers — permission checking, attribute
//! construction (delegated to `tidefs-posix-filesystem-adapter-reply`),
//! POSIX mode-to-file-type mapping, and timestamp translation.
//!
//! Provides:
//! - [`GetattrError`]: domain error type for getattr operations.
//! - [`GetattrPlan`]: validated inode for a getattr operation.
//! - [`file_type_from_mode`]: map a POSIX `st_mode` value to [`FileType`].
//! - [`build_file_attr`]: construct a [`FileAttr`] from raw attribute fields
//!   with [`Duration`]-from-epoch timestamps.
//! - [`check_getattr_permission`]: verify the caller may read the inode's
//!   attributes via [`tidefs_permission`].
//! - [`validate_getattr_request`]: validate that the requested inode exists.
//! - [`plan_getattr`]: plan a getattr operation after inode validation.
//! - [`format_getattr_reply`]: build a [`FileAttr`] reply from raw inode
//!   fields using [`build_file_attr`] with POSIX mode decoding.
//! - [`handle_getattr`]: unified dispatch combining inode validation,
//!   permission checking, and plan construction.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::getattr;
//!
//! let plan = getattr::handle_getattr(
//!     42, true, &my_attrs, 1000, 100, &[]
//! )?;
//! ```

use libc::c_int;

use std::fmt;
use std::time::{Duration, UNIX_EPOCH};

use tidefs_posix_filesystem_adapter_reply::LookupEntryAttr;

use crate::errno;
use crate::{FileAttr, FileType};

// ---------------------------------------------------------------------------
// POSIX mode constants (S_IFMT and friends)
// ---------------------------------------------------------------------------

/// Mask for the file-type bits in `st_mode`.
const S_IFMT: u32 = 0o170000;
/// Regular file.
const S_IFREG: u32 = 0o100000;
/// Directory.
const S_IFDIR: u32 = 0o040000;
/// Symbolic link.
const S_IFLNK: u32 = 0o120000;
/// Block device.
const S_IFBLK: u32 = 0o060000;
/// Character device.
const S_IFCHR: u32 = 0o020000;
/// FIFO / named pipe.
const S_IFIFO: u32 = 0o010000;
/// Unix domain socket.
const S_IFSOCK: u32 = 0o140000;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default filesystem block size reported via [`FileAttr::blksize`].
pub const DEFAULT_BLKSIZE: u32 = 4096;

// ---------------------------------------------------------------------------
// GetattrError
// ---------------------------------------------------------------------------

/// Errors that can occur during getattr processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetattrError {
    /// The requested inode does not exist in the inode table.
    InodeNotFound,
    /// The caller lacks read permission on the inode.
    PermissionDenied,
}

impl GetattrError {
    /// Convert this error to the matching POSIX errno value.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            GetattrError::InodeNotFound => errno::ENOENT,
            GetattrError::PermissionDenied => errno::EACCES,
        }
    }
}

impl fmt::Display for GetattrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GetattrError::InodeNotFound => write!(f, "inode not found"),
            GetattrError::PermissionDenied => write!(f, "permission denied for getattr"),
        }
    }
}

impl std::error::Error for GetattrError {}

impl From<GetattrError> for c_int {
    fn from(e: GetattrError) -> c_int {
        e.to_errno()
    }
}

// ---------------------------------------------------------------------------
// file_type_from_mode
// ---------------------------------------------------------------------------

/// Map a POSIX `st_mode` value (type + permission bits) to the fuser
/// [`FileType`] enum.
///
/// Only the file-type bits (`S_IFMT`) are inspected; permission bits
/// and special mode flags (`S_ISUID`, `S_ISGID`, `S_ISVTX`) are ignored.
///
/// Unknown file-type values fall back to [`FileType::RegularFile`].
#[must_use]
pub fn file_type_from_mode(mode: u32) -> FileType {
    match mode & S_IFMT {
        S_IFDIR => FileType::Directory,
        S_IFREG => FileType::RegularFile,
        S_IFLNK => FileType::Symlink,
        S_IFBLK => FileType::BlockDevice,
        S_IFCHR => FileType::CharDevice,
        S_IFIFO => FileType::NamedPipe,
        S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

/// Return the POSIX permission bits from `st_mode` (lower 12 bits).
#[must_use]
pub fn perm_from_mode(mode: u32) -> u16 {
    (mode & 0o7777) as u16
}

// ---------------------------------------------------------------------------
// build_file_attr
// ---------------------------------------------------------------------------

/// Build a [`FileAttr`] from raw attribute fields.
///
/// Timestamps (`atime`, `mtime`, `ctime`) are accepted as [`Duration`]
/// from the Unix epoch (1970-01-01T00:00:00Z), matching the
/// representation used by `tidefs_inode_table::InodeAttributes`.
///
/// `crtime` (creation time) is always set to the Unix epoch.
/// `flags` is always set to 0.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_file_attr(
    ino: u64,
    size: u64,
    blocks: u64,
    atime: Duration,
    mtime: Duration,
    ctime: Duration,
    kind: FileType,
    perm: u16,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
) -> FileAttr {
    // Convert Duration timestamps to sec/nsec for adapter-reply.
    let atime_secs = atime.as_secs();
    let atime_nsecs = atime.subsec_nanos();
    let mtime_secs = mtime.as_secs();
    let mtime_nsecs = mtime.subsec_nanos();
    let ctime_secs = ctime.as_secs();
    let ctime_nsecs = ctime.subsec_nanos();
    let mode = kind_to_mode(kind) | (perm as u32);

    // Canonical attribute assembly delegated to adapter-reply.
    let a = LookupEntryAttr::new(
        ino,
        size,
        blocks,
        atime_secs,
        mtime_secs,
        ctime_secs,
        atime_nsecs,
        mtime_nsecs,
        ctime_nsecs,
        mode,
        nlink,
        uid,
        gid,
        rdev,
        blksize,
    );

    FileAttr {
        ino: a.ino,
        size: a.size,
        blocks: a.blocks,
        atime: UNIX_EPOCH + Duration::new(a.atime, a.atimensec),
        mtime: UNIX_EPOCH + Duration::new(a.mtime, a.mtimensec),
        ctime: UNIX_EPOCH + Duration::new(a.ctime, a.ctimensec),
        crtime: UNIX_EPOCH,
        kind: file_type_from_mode(a.mode),
        perm: perm_from_mode(a.mode),
        nlink: a.nlink,
        uid: a.uid,
        gid: a.gid,
        rdev: a.rdev,
        blksize: a.blksize,
        flags: 0,
    }
}

/// Combine a [`FileType`] with permission bits into a POSIX `st_mode` value.
///
/// This is the inverse of [`file_type_from_mode`] plus [`perm_from_mode`].
#[must_use]
pub(crate) fn kind_to_mode(kind: FileType) -> u32 {
    match kind {
        FileType::NamedPipe => S_IFIFO,
        FileType::CharDevice => S_IFCHR,
        FileType::BlockDevice => S_IFBLK,
        FileType::Directory => S_IFDIR,
        FileType::RegularFile => S_IFREG,
        FileType::Symlink => S_IFLNK,
        FileType::Socket => S_IFSOCK,
    }
}

// ---------------------------------------------------------------------------
// check_getattr_permission
// ---------------------------------------------------------------------------

/// Check whether the caller has read permission on the inode.
///
/// Uses [`tidefs_permission::check_mode_access`] to evaluate the classic
/// Unix owner/group/other permission bits against
/// [`tidefs_permission::ACCESS_READ`].
///
/// Returns `Ok(())` when access is granted, or
/// `Err(`[`GetattrError::PermissionDenied`]`)` when the caller may not
/// read the inode's attributes.
///
/// # Root bypass
///
/// When `uid == 0`, permission is always granted (standard Unix
/// superuser semantics).
pub fn check_getattr_permission(
    attrs: &dyn tidefs_permission::InodeAttr,
    uid: u32,
    gid: u32,
    groups: &[u32],
    mount_identity: &tidefs_permission::MountIdentity,
) -> Result<(), GetattrError> {
    if tidefs_permission::check_mode_access(
        attrs,
        uid,
        gid,
        groups,
        tidefs_permission::ACCESS_READ,
        mount_identity,
    ) {
        Ok(())
    } else {
        Err(GetattrError::PermissionDenied)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// GetattrPlan
// ---------------------------------------------------------------------------

/// Captures the validated inode for a getattr operation.
///
/// Returned by [`plan_getattr`] and [`handle_getattr`] on success.
/// The caller may use `plan.ino` to fetch full attributes from the
/// inode table or VfsEngine, then pass them to [`format_getattr_reply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetattrPlan {
    /// The validated inode number.
    pub ino: u64,
}

// ---------------------------------------------------------------------------
// validate_getattr_request
// ---------------------------------------------------------------------------

/// Validate that the requested inode exists in the inode table.
///
/// Takes the result of an inode-table lookup (or equivalent) and returns
/// `Ok(())` when the inode is known, or `Err(`[`GetattrError::InodeNotFound`]`)`
/// when it does not exist.
///
/// This is a thin wrapper that the adapter daemon calls after its own
/// inode-table probe.
pub fn validate_getattr_request(ino_exists: bool) -> Result<(), GetattrError> {
    if ino_exists {
        Ok(())
    } else {
        Err(GetattrError::InodeNotFound)
    }
}

// ---------------------------------------------------------------------------
// plan_getattr
// ---------------------------------------------------------------------------

/// Plan a getattr operation by validating inode existence.
///
/// On success returns a [`GetattrPlan`] containing the validated inode.
/// The caller should then fetch the full attribute set and construct the
/// reply via [`format_getattr_reply`].
pub fn plan_getattr(ino: u64, ino_exists: bool) -> Result<GetattrPlan, GetattrError> {
    validate_getattr_request(ino_exists)?;
    Ok(GetattrPlan { ino })
}

// ---------------------------------------------------------------------------
// format_getattr_reply
// ---------------------------------------------------------------------------

/// Build a [`FileAttr`] reply from raw inode fields.
///
/// This is a convenience wrapper around [`build_file_attr`] that accepts a
/// POSIX `mode` value (type + permission bits) instead of pre-decoded
/// [`FileType`] and `perm` fields.  The file type is derived via
/// [`file_type_from_mode`] and the permission bits via [`perm_from_mode`].
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn format_getattr_reply(
    ino: u64,
    size: u64,
    blocks: u64,
    atime: Duration,
    mtime: Duration,
    ctime: Duration,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
) -> FileAttr {
    let kind = file_type_from_mode(mode);
    let perm = perm_from_mode(mode);
    build_file_attr(
        ino, size, blocks, atime, mtime, ctime, kind, perm, nlink, uid, gid, rdev, blksize,
    )
}

// ---------------------------------------------------------------------------
// handle_getattr -- unified dispatch
// ---------------------------------------------------------------------------

/// Unified getattr dispatch entry point.
///
/// Validates inode existence via [`plan_getattr`] and caller permissions
/// via [`check_getattr_permission`].  Returns a [`GetattrPlan`] on success.
/// The caller uses the plan to fetch full attributes and produce the FUSE
/// reply via [`format_getattr_reply`].
pub fn handle_getattr(
    ino: u64,
    ino_exists: bool,
    attrs: &dyn tidefs_permission::InodeAttr,
    caller_uid: u32,
    caller_gid: u32,
    groups: &[u32],
    mount_identity: &tidefs_permission::MountIdentity,
) -> Result<GetattrPlan, GetattrError> {
    let plan = plan_getattr(ino, ino_exists)?;
    check_getattr_permission(attrs, caller_uid, caller_gid, groups, mount_identity)?;
    Ok(plan)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const VALID_MOUNT: tidefs_permission::MountIdentity =
        tidefs_permission::MountIdentity::new([0x41; 16], 1);

    // -- file_type_from_mode ------------------------------------------

    #[test]
    fn regular_file_mode_maps_to_regular_file() {
        assert_eq!(file_type_from_mode(0o100644), FileType::RegularFile);
        assert_eq!(file_type_from_mode(0o100755), FileType::RegularFile);
        assert_eq!(file_type_from_mode(0o100000), FileType::RegularFile);
    }

    #[test]
    fn directory_mode_maps_to_directory() {
        assert_eq!(file_type_from_mode(0o040755), FileType::Directory);
        assert_eq!(file_type_from_mode(0o040700), FileType::Directory);
        assert_eq!(file_type_from_mode(0o040000), FileType::Directory);
    }

    #[test]
    fn symlink_mode_maps_to_symlink() {
        assert_eq!(file_type_from_mode(0o120777), FileType::Symlink);
        assert_eq!(file_type_from_mode(0o120000), FileType::Symlink);
    }

    #[test]
    fn block_device_mode_maps_to_block_device() {
        assert_eq!(file_type_from_mode(0o060644), FileType::BlockDevice);
        assert_eq!(file_type_from_mode(0o060000), FileType::BlockDevice);
    }

    #[test]
    fn char_device_mode_maps_to_char_device() {
        assert_eq!(file_type_from_mode(0o020644), FileType::CharDevice);
        assert_eq!(file_type_from_mode(0o020000), FileType::CharDevice);
    }

    #[test]
    fn fifo_mode_maps_to_named_pipe() {
        assert_eq!(file_type_from_mode(0o010644), FileType::NamedPipe);
        assert_eq!(file_type_from_mode(0o010000), FileType::NamedPipe);
    }

    #[test]
    fn socket_mode_maps_to_socket() {
        assert_eq!(file_type_from_mode(0o140644), FileType::Socket);
        assert_eq!(file_type_from_mode(0o140000), FileType::Socket);
    }

    #[test]
    fn unknown_type_falls_back_to_regular_file() {
        // File type 0 (no type bits set) is not a valid POSIX type
        assert_eq!(file_type_from_mode(0o000644), FileType::RegularFile);
        // Unused type bits
        assert_eq!(file_type_from_mode(0o160644), FileType::RegularFile);
        assert_eq!(file_type_from_mode(0o030644), FileType::RegularFile);
    }

    #[test]
    fn permission_bits_do_not_affect_type() {
        assert_eq!(file_type_from_mode(0o100777), FileType::RegularFile);
        assert_eq!(file_type_from_mode(0o100000), FileType::RegularFile);
    }

    #[test]
    fn suid_sgid_svtx_do_not_affect_type() {
        assert_eq!(
            file_type_from_mode(0o100777 | 0o4000 | 0o2000 | 0o1000),
            FileType::RegularFile
        );
    }

    // -- perm_from_mode ----------------------------------------------

    #[test]
    fn perm_from_mode_extracts_lower_12_bits() {
        assert_eq!(perm_from_mode(0o100644), 0o644);
        assert_eq!(perm_from_mode(0o040755), 0o755);
        assert_eq!(perm_from_mode(0o100000), 0o000);
    }

    #[test]
    fn perm_from_mode_includes_suid_sgid_svtx() {
        assert_eq!(perm_from_mode(0o100644 | 0o4000), 0o4644);
        assert_eq!(perm_from_mode(0o100644 | 0o2000), 0o2644);
        assert_eq!(perm_from_mode(0o100644 | 0o1000), 0o1644);
    }

    // -- build_file_attr field preservation --------------------------

    #[test]
    fn build_ino_preserved() {
        let attr = build_file_attr(
            42,
            0,
            0,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            FileType::RegularFile,
            0o644,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.ino, 42);
    }

    #[test]
    fn build_size_preserved() {
        let attr = build_file_attr(
            1,
            8192,
            16,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            FileType::RegularFile,
            0o644,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.size, 8192);
    }

    #[test]
    fn build_blocks_preserved() {
        let attr = build_file_attr(
            1,
            0,
            32,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            FileType::RegularFile,
            0o644,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.blocks, 32);
    }

    #[test]
    fn build_atime_preserved() {
        let d = Duration::from_secs(1_000_000);
        let attr = build_file_attr(
            1,
            0,
            0,
            d,
            Duration::ZERO,
            Duration::ZERO,
            FileType::RegularFile,
            0o644,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.atime, UNIX_EPOCH + d);
    }

    #[test]
    fn build_mtime_preserved() {
        let d = Duration::from_secs(2_000_000);
        let attr = build_file_attr(
            1,
            0,
            0,
            Duration::ZERO,
            d,
            Duration::ZERO,
            FileType::RegularFile,
            0o644,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.mtime, UNIX_EPOCH + d);
    }

    #[test]
    fn build_ctime_preserved() {
        let d = Duration::from_secs(3_000_000);
        let attr = build_file_attr(
            1,
            0,
            0,
            Duration::ZERO,
            Duration::ZERO,
            d,
            FileType::RegularFile,
            0o644,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.ctime, UNIX_EPOCH + d);
    }

    #[test]
    fn build_crtime_is_epoch() {
        let attr = build_file_attr(
            1,
            0,
            0,
            Duration::from_secs(100),
            Duration::from_secs(200),
            Duration::from_secs(300),
            FileType::RegularFile,
            0o644,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.crtime, UNIX_EPOCH);
    }

    #[test]
    fn build_kind_preserved() {
        for kind in &[
            FileType::Directory,
            FileType::RegularFile,
            FileType::Symlink,
            FileType::BlockDevice,
            FileType::CharDevice,
            FileType::NamedPipe,
            FileType::Socket,
        ] {
            let attr = build_file_attr(
                1,
                0,
                0,
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                *kind,
                0o644,
                1,
                1000,
                100,
                0,
                4096,
            );
            assert_eq!(attr.kind, *kind);
        }
    }

    #[test]
    fn build_perm_preserved() {
        let attr = build_file_attr(
            1,
            0,
            0,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            FileType::RegularFile,
            0o755,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.perm, 0o755);
    }

    #[test]
    fn build_nlink_preserved() {
        let attr = build_file_attr(
            1,
            0,
            0,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            FileType::RegularFile,
            0o644,
            5,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.nlink, 5);
    }

    #[test]
    fn build_uid_gid_preserved() {
        let attr = build_file_attr(
            1,
            0,
            0,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            FileType::RegularFile,
            0o644,
            1,
            1000,
            200,
            0,
            4096,
        );
        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 200);
    }

    #[test]
    fn build_rdev_preserved() {
        let attr = build_file_attr(
            1,
            0,
            0,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            FileType::BlockDevice,
            0o644,
            1,
            0,
            0,
            0x0801,
            4096,
        );
        assert_eq!(attr.rdev, 0x0801);
    }

    #[test]
    fn build_blksize_preserved() {
        let attr = build_file_attr(
            1,
            0,
            0,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            FileType::RegularFile,
            0o644,
            1,
            1000,
            100,
            0,
            512,
        );
        assert_eq!(attr.blksize, 512);
    }

    #[test]
    fn build_flags_is_zero() {
        let attr = build_file_attr(
            1,
            0,
            0,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            FileType::RegularFile,
            0o644,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.flags, 0);
    }

    #[test]
    fn build_zero_timestamps() {
        let attr = build_file_attr(
            1,
            0,
            0,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            FileType::RegularFile,
            0o644,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.atime, UNIX_EPOCH);
        assert_eq!(attr.mtime, UNIX_EPOCH);
        assert_eq!(attr.ctime, UNIX_EPOCH);
    }

    #[test]
    fn build_max_ino() {
        let attr = build_file_attr(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Duration::from_secs(1_000_000),
            Duration::from_secs(2_000_000),
            Duration::from_secs(3_000_000),
            FileType::RegularFile,
            0o777,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
        );
        assert_eq!(attr.ino, u64::MAX);
        assert_eq!(attr.size, u64::MAX);
        assert_eq!(attr.blocks, u64::MAX);
    }

    #[test]
    fn build_subsecond_timestamps() {
        let d = Duration::from_nanos(1_500_000_001);
        let attr = build_file_attr(
            1,
            0,
            0,
            d,
            d,
            d,
            FileType::RegularFile,
            0o644,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.atime, UNIX_EPOCH + d);
        assert_eq!(attr.mtime, UNIX_EPOCH + d);
        assert_eq!(attr.ctime, UNIX_EPOCH + d);
    }

    // -- GetattrError ------------------------------------------------

    #[test]
    fn getattr_error_inode_not_found_to_errno() {
        assert_eq!(GetattrError::InodeNotFound.to_errno(), libc::ENOENT);
    }

    #[test]
    fn getattr_error_permission_denied_to_errno() {
        assert_eq!(GetattrError::PermissionDenied.to_errno(), libc::EACCES);
    }

    #[test]
    fn getattr_error_display() {
        assert_eq!(
            format!("{}", GetattrError::InodeNotFound),
            "inode not found"
        );
        assert_eq!(
            format!("{}", GetattrError::PermissionDenied),
            "permission denied for getattr"
        );
    }

    #[test]
    fn getattr_error_debug() {
        assert_eq!(
            format!("{:?}", GetattrError::InodeNotFound),
            "InodeNotFound"
        );
        assert_eq!(
            format!("{:?}", GetattrError::PermissionDenied),
            "PermissionDenied"
        );
    }

    #[test]
    fn getattr_error_into_c_int() {
        let e: c_int = GetattrError::InodeNotFound.into();
        assert_eq!(e, libc::ENOENT);
        let e: c_int = GetattrError::PermissionDenied.into();
        assert_eq!(e, libc::EACCES);
    }

    #[test]
    fn getattr_error_is_error_trait() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<GetattrError>();
    }

    // -- check_getattr_permission ------------------------------------

    struct TestInode {
        uid: u32,
        gid: u32,
        mode: u32,
    }

    impl tidefs_permission::InodeAttr for TestInode {
        fn uid(&self) -> u32 {
            self.uid
        }
        fn gid(&self) -> u32 {
            self.gid
        }
        fn mode(&self) -> u32 {
            self.mode
        }
    }

    #[test]
    fn permission_owner_can_read() {
        let ino = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o400,
        };
        assert_eq!(
            check_getattr_permission(&ino, 1000, 100, &[], &VALID_MOUNT),
            Ok(())
        );
    }

    #[test]
    fn permission_owner_cannot_read_with_mode_000() {
        let ino = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o000,
        };
        assert_eq!(
            check_getattr_permission(&ino, 1000, 100, &[], &VALID_MOUNT),
            Err(GetattrError::PermissionDenied)
        );
    }

    #[test]
    fn permission_group_can_read() {
        let ino = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o040,
        };
        assert_eq!(
            check_getattr_permission(&ino, 2000, 100, &[], &VALID_MOUNT),
            Ok(())
        );
    }

    #[test]
    fn permission_group_denied_with_wrong_gid() {
        let ino = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o040,
        };
        assert_eq!(
            check_getattr_permission(&ino, 2000, 200, &[], &VALID_MOUNT),
            Err(GetattrError::PermissionDenied)
        );
    }

    #[test]
    fn permission_other_can_read() {
        let ino = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o004,
        };
        assert_eq!(
            check_getattr_permission(&ino, 2000, 200, &[], &VALID_MOUNT),
            Ok(())
        );
    }

    #[test]
    fn permission_other_denied_with_mode_000() {
        let ino = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o000,
        };
        assert_eq!(
            check_getattr_permission(&ino, 2000, 200, &[], &VALID_MOUNT),
            Err(GetattrError::PermissionDenied)
        );
    }

    #[test]
    fn permission_root_bypasses_all_checks() {
        let ino = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o000,
        };
        assert_eq!(
            check_getattr_permission(&ino, 0, 0, &[], &VALID_MOUNT),
            Ok(())
        );
    }

    #[test]
    fn permission_supplementary_group_grants_access() {
        let ino = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o040,
        };
        // caller gid=200, but supp groups contain 100
        assert_eq!(
            check_getattr_permission(&ino, 2000, 200, &[100], &VALID_MOUNT),
            Ok(())
        );
    }

    #[test]
    fn permission_supplementary_group_no_match_denied() {
        let ino = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o040,
        };
        assert_eq!(
            check_getattr_permission(&ino, 2000, 200, &[300, 400], &VALID_MOUNT),
            Err(GetattrError::PermissionDenied)
        );
    }

    // -- DEFAULT_BLKSIZE ---------------------------------------------

    #[test]
    fn default_blksize_is_4096() {
        assert_eq!(DEFAULT_BLKSIZE, 4096);
    }

    // -- GetattrPlan -------------------------------------------------

    #[test]
    fn getattr_plan_holds_ino() {
        let plan = GetattrPlan { ino: 42 };
        assert_eq!(plan.ino, 42);
    }

    // -- validate_getattr_request ------------------------------------

    #[test]
    fn validate_inode_exists() {
        assert_eq!(validate_getattr_request(true), Ok(()));
    }

    #[test]
    fn validate_inode_not_found() {
        assert_eq!(
            validate_getattr_request(false),
            Err(GetattrError::InodeNotFound)
        );
    }

    // -- plan_getattr ------------------------------------------------

    #[test]
    fn plan_getattr_existing_inode() {
        let plan = plan_getattr(100, true).unwrap();
        assert_eq!(plan.ino, 100);
    }

    #[test]
    fn plan_getattr_stale_inode() {
        assert_eq!(plan_getattr(0, false), Err(GetattrError::InodeNotFound));
    }

    // -- format_getattr_reply ----------------------------------------

    #[test]
    fn format_reply_regular_file() {
        let attr = format_getattr_reply(
            42,
            8192,
            16,
            Duration::from_secs(1000),
            Duration::from_secs(2000),
            Duration::from_secs(3000),
            0o100644,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.ino, 42);
        assert_eq!(attr.size, 8192);
        assert_eq!(attr.blocks, 16);
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.perm, 0o644);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 100);
        assert_eq!(attr.rdev, 0);
        assert_eq!(attr.blksize, 4096);
    }

    #[test]
    fn format_reply_directory() {
        let attr = format_getattr_reply(
            1,
            0,
            0,
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(3),
            0o040755,
            2,
            0,
            0,
            0,
            4096,
        );
        assert_eq!(attr.ino, 1);
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
        assert_eq!(attr.nlink, 2);
    }

    #[test]
    fn format_reply_symlink() {
        let attr = format_getattr_reply(
            99,
            10,
            0,
            Duration::from_secs(5000),
            Duration::from_secs(5001),
            Duration::from_secs(5002),
            0o120777,
            1,
            1000,
            100,
            0,
            4096,
        );
        assert_eq!(attr.kind, FileType::Symlink);
        assert_eq!(attr.perm, 0o777);
        assert_eq!(attr.size, 10);
    }

    #[test]
    fn format_reply_block_device() {
        let attr = format_getattr_reply(
            5,
            0,
            0,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            0o060640,
            1,
            0,
            6,
            0x0801,
            512,
        );
        assert_eq!(attr.kind, FileType::BlockDevice);
        assert_eq!(attr.rdev, 0x0801);
        assert_eq!(attr.blksize, 512);
    }

    #[test]
    fn format_reply_timestamps_preserved() {
        let atime = Duration::from_secs(1_600_000_000);
        let mtime = Duration::from_secs(1_600_000_100);
        let ctime = Duration::from_secs(1_600_000_200);
        let attr = format_getattr_reply(
            1, 0, 0, atime, mtime, ctime, 0o100644, 1, 1000, 100, 0, 4096,
        );
        assert_eq!(attr.atime, UNIX_EPOCH + atime);
        assert_eq!(attr.mtime, UNIX_EPOCH + mtime);
        assert_eq!(attr.ctime, UNIX_EPOCH + ctime);
    }

    // -- handle_getattr ----------------------------------------------

    #[test]
    fn handle_getattr_succeeds() {
        let attrs = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o100644,
        };
        let plan = handle_getattr(42, true, &attrs, 1000, 100, &[], &VALID_MOUNT).unwrap();
        assert_eq!(plan.ino, 42);
    }

    #[test]
    fn handle_getattr_inode_not_found() {
        let attrs = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o100644,
        };
        assert_eq!(
            handle_getattr(42, false, &attrs, 1000, 100, &[], &VALID_MOUNT),
            Err(GetattrError::InodeNotFound)
        );
    }

    #[test]
    fn handle_getattr_permission_denied() {
        let attrs = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o000,
        };
        assert_eq!(
            handle_getattr(42, true, &attrs, 2000, 200, &[], &VALID_MOUNT),
            Err(GetattrError::PermissionDenied)
        );
    }

    #[test]
    fn handle_getattr_root_bypass() {
        let attrs = TestInode {
            uid: 1000,
            gid: 100,
            mode: 0o000,
        };
        let plan = handle_getattr(42, true, &attrs, 0, 0, &[], &VALID_MOUNT).unwrap();
        assert_eq!(plan.ino, 42);
    }
}
