//! FUSE `mknod` handler helpers — mode-type validation, name
//! validation, rdev sanity checks, and convenience entry-points for
//! POSIX-compliant special-file creation.
//!
//! The kernel `mknod(2)` syscall creates block devices, character
//! devices, FIFOs, and Unix-domain sockets.  Regular files, directories,
//! and symlinks use their own dedicated FUSE handlers (`create`, `mkdir`,
//! `symlink`).
//!
//! Provides:
//! - [`validate_mknod_name`]: reject empty, overlong, dot/dotdot, NUL,
//!   and slash-containing names; returns `Ok(())` or a FUSE errno.
//! - [`validate_mknod_mode`]: ensure the file-type field in `mode` is one
//!   of the four allowed special types (`S_IFCHR`, `S_IFBLK`, `S_IFIFO`,
//!   `S_IFSOCK`); returns the cleaned-up permission bits and the
//!   identified [`FileType`] on success.
//! - [`validate_mknod_rdev`]: sanity-check `rdev` — must be zero for
//!   FIFO/socket; non-zero is allowed (but not required) for dev nodes.
//! - [`plan_mknod`]: combined name + mode + rdev validation.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::mknod;
//!
//! let (perm, kind) = mknod::validate_mknod_mode(mode)?;
//! mknod::validate_mknod_rdev(rdev, kind)?;
//! mknod::validate_mknod_name(name)?;
//! ```

use crate::errno;
use libc::c_int;

/// Maximum length of a single name component in bytes
/// (POSIX `NAME_MAX` on Linux).
pub const MKNOD_MAX_NAME_BYTES: usize = 255;

/// POSIX permission-bit mask (0o7777).  The file-type field
/// (`S_IFMT` = 0o170000) is extracted and validated separately.
pub const MKNOD_PERM_MASK: u32 = 0o7777;

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

/// Validate a file name for `mknod`.
///
/// Returns `Err(EINVAL)` when the name is empty, exceeds
/// [`MKNOD_MAX_NAME_BYTES`], is `"."` or `".."`, contains a NUL byte,
/// or contains a forward slash.
///
/// Returns `Ok(())` on success.
/// Check that the caller has write and execute (search) permission
/// on the parent directory for an mknod operation.
pub fn check_mknod_parent_permission(
    parent_mode: u32,
    parent_uid: u32,
    parent_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    mount_identity: &tidefs_permission::MountIdentity,
) -> Result<(), c_int> {
    crate::access::check_fuse_access(
        parent_mode,
        parent_uid,
        parent_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        crate::access::ACCESS_WRITE | crate::access::ACCESS_EXECUTE,
        mount_identity,
    )
}

/// Validate a file name for `mknod(2)`.
///
/// Returns `Err(EINVAL)` for empty, `"."`, `".."`, NUL-containing, or
/// slash-containing names.  Returns `Err(ENAMETOOLONG)` for names
/// longer than [`MKNOD_MAX_NAME_BYTES`].
pub fn validate_mknod_name(name: &[u8]) -> Result<(), c_int> {
    if name.is_empty() {
        return Err(errno::EINVAL);
    }
    if name.len() > MKNOD_MAX_NAME_BYTES {
        return Err(errno::ENAMETOOLONG);
    }
    if name == b"." || name == b".." {
        return Err(errno::EEXIST);
    }
    if name.contains(&0) {
        return Err(errno::EINVAL);
    }
    if name.contains(&b'/') {
        return Err(errno::EINVAL);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mode validation
// ---------------------------------------------------------------------------

/// The set of file types that `mknod(2)` is allowed to create.
/// Regular files, directories, and symlinks are routed through their
/// own dedicated FUSE handlers and are rejected here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MknodFileType {
    /// Character device (`S_IFCHR`)
    CharDevice,
    /// Block device (`S_IFBLK`)
    BlockDevice,
    /// FIFO / named pipe (`S_IFIFO`)
    Fifo,
    /// Unix-domain socket (`S_IFSOCK`)
    Socket,
}

/// Validate the `mode` for `mknod`.
///
/// Extracts the file-type field (`S_IFMT` bits) and checks that it is
/// one of the four types allowed by `mknod(2)`: `S_IFCHR`, `S_IFBLK`,
/// `S_IFIFO`, or `S_IFSOCK`.  Regular file, directory, and symlink
/// types are rejected with `EINVAL`.
///
/// Returns `Ok((perm, kind))` where `perm` is the masked permission
/// bits (0o000 – 0o7777) and `kind` is the identified [`MknodFileType`].
pub fn validate_mknod_mode(mode: u32) -> Result<(u32, MknodFileType), c_int> {
    let file_type = mode & libc::S_IFMT;
    let perm = mode & MKNOD_PERM_MASK;

    let kind = match file_type {
        x if x == libc::S_IFCHR => MknodFileType::CharDevice,
        x if x == libc::S_IFBLK => MknodFileType::BlockDevice,
        x if x == libc::S_IFIFO => MknodFileType::Fifo,
        x if x == libc::S_IFSOCK => MknodFileType::Socket,
        // Regular files use create(), directories use mkdir(),
        // symlinks use symlink().
        _ => return Err(errno::EINVAL),
    };

    Ok((perm, kind))
}

// ---------------------------------------------------------------------------
// rdev validation
// ---------------------------------------------------------------------------

/// Validate the `rdev` value for `mknod`.
///
/// For FIFOs and sockets, `rdev` must be zero (POSIX requires it be
/// ignored, but we reject non-zero to catch application bugs).
/// For device nodes (`S_IFCHR`, `S_IFBLK`), any `rdev` value is
/// accepted (zero is legal for devices that haven't been assigned a
/// major/minor yet).
///
/// Returns `Ok(())` on success, `Err(EINVAL)` on non-zero rdev for
/// a FIFO or socket.
pub fn validate_mknod_rdev(rdev: u32, kind: MknodFileType) -> Result<(), c_int> {
    match kind {
        MknodFileType::Fifo | MknodFileType::Socket => {
            if rdev != 0 {
                return Err(errno::EINVAL);
            }
            Ok(())
        }
        MknodFileType::CharDevice | MknodFileType::BlockDevice => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Combined validation (convenience)
// ---------------------------------------------------------------------------

/// Validate name, mode, and rdev for `mknod` in one call.
///
/// Returns `Ok((perm, kind))` on success where `perm` is the masked
/// permission bits and `kind` identifies the special file type.
/// On failure returns a FUSE errno (`EINVAL`, `ENAMETOOLONG`,
/// or `EEXIST`).
pub fn plan_mknod(name: &[u8], mode: u32, rdev: u32) -> Result<(u32, MknodFileType), c_int> {
    validate_mknod_name(name)?;
    let (perm, kind) = validate_mknod_mode(mode)?;
    validate_mknod_rdev(rdev, kind)?;
    Ok((perm, kind))
}

// ---------------------------------------------------------------------------
// handle_mknod -- canonical FUSE dispatch entry point for mknod(2)
// ---------------------------------------------------------------------------

/// Canonical FUSE dispatch entry point for `mknod` (opcode 8).
///
/// Wraps [`plan_mknod`] with a read-only filesystem guard (`EROFS`),
/// providing a single entry point for the FUSE dispatch path.
/// All name, mode, and rdev validation is delegated to `plan_mknod`.
///
/// Returns `Ok((perm, kind))` on success where `perm` is the masked
/// permission bits and `kind` identifies the special file type
/// ([`MknodFileType`]).  On failure returns a FUSE errno.
///
/// # Examples
///
/// ```rust,ignore
/// use fuser::mknod;
///
/// let (perm, kind) = mknod::handle_mknod(b"pipe", libc::S_IFIFO | 0o666, 0, false)?;
/// ```
#[inline]
pub fn handle_mknod(
    name: &[u8],
    mode: u32,
    rdev: u32,
    read_only: bool,
) -> Result<(u32, MknodFileType), c_int> {
    if read_only {
        return Err(libc::EROFS);
    }
    plan_mknod(name, mode, rdev)
}
// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- validate_mknod_name -------------------------------------------------

    #[test]
    fn name_empty_rejected() {
        assert_eq!(validate_mknod_name(b""), Err(errno::EINVAL));
    }

    #[test]
    fn name_too_long_rejected() {
        let long = vec![b'a'; 256];
        assert_eq!(validate_mknod_name(&long), Err(errno::ENAMETOOLONG));
    }

    #[test]
    fn name_max_length_accepted() {
        let max = vec![b'a'; 255];
        assert_eq!(validate_mknod_name(&max), Ok(()));
    }

    #[test]
    fn dot_rejected() {
        assert_eq!(validate_mknod_name(b"."), Err(errno::EEXIST));
    }

    #[test]
    fn dotdot_rejected() {
        assert_eq!(validate_mknod_name(b".."), Err(errno::EEXIST));
    }

    #[test]
    fn nul_byte_rejected() {
        assert_eq!(validate_mknod_name(b"foo\0bar"), Err(errno::EINVAL));
    }

    #[test]
    fn slash_rejected() {
        assert_eq!(validate_mknod_name(b"a/b"), Err(errno::EINVAL));
    }

    #[test]
    fn normal_name_accepted() {
        assert_eq!(validate_mknod_name(b"pipe"), Ok(()));
        assert_eq!(validate_mknod_name(b"dev node"), Ok(()));
        assert_eq!(validate_mknod_name(b"fifo-with-dashes"), Ok(()));
        assert_eq!(validate_mknod_name(b"sock_with_underscores"), Ok(()));
    }

    // -- validate_mknod_mode -------------------------------------------------

    #[test]
    fn fifo_mode_accepted() {
        let result = validate_mknod_mode(libc::S_IFIFO | 0o666);
        assert_eq!(result, Ok((0o666, MknodFileType::Fifo)));
    }

    #[test]
    fn char_device_mode_accepted() {
        let result = validate_mknod_mode(libc::S_IFCHR | 0o600);
        assert_eq!(result, Ok((0o600, MknodFileType::CharDevice)));
    }

    #[test]
    fn block_device_mode_accepted() {
        let result = validate_mknod_mode(libc::S_IFBLK | 0o640);
        assert_eq!(result, Ok((0o640, MknodFileType::BlockDevice)));
    }

    #[test]
    fn socket_mode_accepted() {
        let result = validate_mknod_mode(libc::S_IFSOCK | 0o755);
        assert_eq!(result, Ok((0o755, MknodFileType::Socket)));
    }

    #[test]
    fn regular_file_mode_rejected() {
        assert_eq!(
            validate_mknod_mode(libc::S_IFREG | 0o644),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn directory_mode_rejected() {
        assert_eq!(
            validate_mknod_mode(libc::S_IFDIR | 0o755),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn symlink_mode_rejected() {
        assert_eq!(
            validate_mknod_mode(libc::S_IFLNK | 0o777),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn mode_zero_rejected() {
        assert_eq!(validate_mknod_mode(0), Err(errno::EINVAL));
    }

    #[test]
    fn mode_with_setuid_setgid_sticky_accepted() {
        let result = validate_mknod_mode(libc::S_IFIFO | 0o4755);
        assert_eq!(result, Ok((0o4755, MknodFileType::Fifo)));
    }

    #[test]
    fn mode_permission_only_accepted() {
        let result = validate_mknod_mode(libc::S_IFCHR);
        assert_eq!(result, Ok((0o000, MknodFileType::CharDevice)));
    }

    // -- validate_mknod_rdev -------------------------------------------------

    #[test]
    fn fifo_nonzero_rdev_rejected() {
        assert_eq!(
            validate_mknod_rdev(0x0100, MknodFileType::Fifo),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn fifo_zero_rdev_accepted() {
        assert_eq!(validate_mknod_rdev(0, MknodFileType::Fifo), Ok(()));
    }

    #[test]
    fn socket_nonzero_rdev_rejected() {
        assert_eq!(
            validate_mknod_rdev(1, MknodFileType::Socket),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn socket_zero_rdev_accepted() {
        assert_eq!(validate_mknod_rdev(0, MknodFileType::Socket), Ok(()));
    }

    #[test]
    fn char_device_zero_rdev_accepted() {
        assert_eq!(validate_mknod_rdev(0, MknodFileType::CharDevice), Ok(()));
    }

    #[test]
    fn char_device_nonzero_rdev_accepted() {
        // major 1 (mem), minor 3 (null) => 0x0103
        assert_eq!(
            validate_mknod_rdev(0x0103, MknodFileType::CharDevice),
            Ok(())
        );
    }

    #[test]
    fn block_device_zero_rdev_accepted() {
        assert_eq!(validate_mknod_rdev(0, MknodFileType::BlockDevice), Ok(()));
    }

    #[test]
    fn block_device_nonzero_rdev_accepted() {
        // major 8, minor 0 (sda) => 0x0800
        assert_eq!(
            validate_mknod_rdev(0x0800, MknodFileType::BlockDevice),
            Ok(())
        );
    }

    // -- plan_mknod ----------------------------------------------------------

    #[test]
    fn plan_mknod_fifo_valid() {
        assert_eq!(
            plan_mknod(b"pipe", libc::S_IFIFO | 0o666, 0),
            Ok((0o666, MknodFileType::Fifo))
        );
    }

    #[test]
    fn plan_mknod_char_dev_valid() {
        assert_eq!(
            plan_mknod(b"null", libc::S_IFCHR | 0o666, 0x0103),
            Ok((0o666, MknodFileType::CharDevice))
        );
    }

    #[test]
    fn plan_mknod_empty_name() {
        assert_eq!(
            plan_mknod(b"", libc::S_IFIFO | 0o644, 0),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn plan_mknod_regular_file_rejected() {
        assert_eq!(
            plan_mknod(b"somefile", libc::S_IFREG | 0o644, 0),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn plan_mknod_directory_rejected() {
        assert_eq!(
            plan_mknod(b"somedir", libc::S_IFDIR | 0o755, 0),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn plan_mknod_dot_name() {
        assert_eq!(
            plan_mknod(b".", libc::S_IFIFO | 0o644, 0),
            Err(errno::EEXIST)
        );
    }

    #[test]
    fn plan_mknod_fifo_nonzero_rdev() {
        assert_eq!(
            plan_mknod(b"pipe", libc::S_IFIFO | 0o644, 1),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn plan_mknod_socket_zero_rdev() {
        assert_eq!(
            plan_mknod(b"mysock", libc::S_IFSOCK | 0o700, 0),
            Ok((0o700, MknodFileType::Socket))
        );
    }

    #[test]
    fn plan_mknod_block_device_valid() {
        assert_eq!(
            plan_mknod(b"sda", libc::S_IFBLK | 0o660, 0x0800),
            Ok((0o660, MknodFileType::BlockDevice))
        );
    }

    // -- handle_mknod --------------------------------------------------------

    #[test]
    fn handle_mknod_fifo_ok() {
        assert_eq!(
            handle_mknod(b"pipe", libc::S_IFIFO | 0o666, 0, false),
            Ok((0o666, MknodFileType::Fifo))
        );
    }

    #[test]
    fn handle_mknod_char_dev_ok() {
        assert_eq!(
            handle_mknod(b"null", libc::S_IFCHR | 0o666, 0x0103, false),
            Ok((0o666, MknodFileType::CharDevice))
        );
    }

    #[test]
    fn handle_mknod_block_dev_ok() {
        assert_eq!(
            handle_mknod(b"sda", libc::S_IFBLK | 0o660, 0x0800, false),
            Ok((0o660, MknodFileType::BlockDevice))
        );
    }

    #[test]
    fn handle_mknod_socket_ok() {
        assert_eq!(
            handle_mknod(b"mysock", libc::S_IFSOCK | 0o700, 0, false),
            Ok((0o700, MknodFileType::Socket))
        );
    }

    #[test]
    fn handle_mknod_read_only_rejected() {
        assert_eq!(
            handle_mknod(b"pipe", libc::S_IFIFO | 0o666, 0, true),
            Err(libc::EROFS)
        );
    }

    #[test]
    fn handle_mknod_read_only_takes_priority() {
        // Read-only check happens before name/mode/rdev validation
        assert_eq!(
            handle_mknod(b"", libc::S_IFREG | 0o644, 1, true),
            Err(libc::EROFS)
        );
    }

    #[test]
    fn handle_mknod_bad_name_propagated() {
        assert_eq!(
            handle_mknod(b"", libc::S_IFIFO | 0o644, 0, false),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn handle_mknod_bad_mode_propagated() {
        assert_eq!(
            handle_mknod(b"file", libc::S_IFREG | 0o644, 0, false),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn handle_mknod_bad_rdev_propagated() {
        assert_eq!(
            handle_mknod(b"pipe", libc::S_IFIFO | 0o644, 1, false),
            Err(libc::EINVAL)
        );
    }
}
