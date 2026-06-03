//! FUSE `create` handler helpers — file-name validation, mode-bit
//! sanity checks, umask application, and convenience entry-points for
//! POSIX-compliant regular-file creation.
//!
//! The kernel routes `open(O_CREAT)` and `creat(2)` into the FUSE
//! `create` handler (not `mknod`).  This module provides the
//! foundational validation helpers that the upper-level filesystem
//! adapter calls before allocating inodes, inserting directory
//! entries, and recording intent-log records.
//!
//! Provides:
//! - [`validate_create_name`]: reject empty, overlong, dot/dotdot, NUL,
//!   and slash-containing names; returns `Ok(())` or a FUSE errno.
//! - [`validate_create_mode`]: ensure the file-type field in `mode` is
//!   `S_IFREG` and return the cleaned-up permission bits.
//! - [`apply_umask`]: apply the process umask to permission bits.
//! - [`plan_create`]: combined name + mode + umask validation returning
//!   the final permission bits on success.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::create;
//!
//! let perm = create::plan_create(b"myfile", 0o644, 0o022)?;
//! assert_eq!(perm, 0o644);
//! ```

use libc::c_int;

/// Maximum length of a single file-name component in bytes
/// (POSIX `NAME_MAX` on Linux).
pub const CREATE_MAX_NAME_BYTES: usize = 255;

/// POSIX permission-bit mask (0o7777).  The file-type field
/// (`S_IFMT` = 0o170000) is validated to be `S_IFREG` by
/// [`validate_create_mode`].
pub const CREATE_PERM_MASK: u32 = 0o7777;

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

/// Validate a file name for `create`.
///
/// Returns `Err(EINVAL)` when the name is empty, exceeds
/// [`CREATE_MAX_NAME_BYTES`], is `"."` or `".."`, contains a NUL byte,
/// or contains a forward slash.
///
/// Returns `Ok(())` on success.
pub fn validate_create_name(name: &[u8]) -> Result<(), c_int> {
    if name.is_empty() {
        return Err(libc::EINVAL);
    }
    if name.len() > CREATE_MAX_NAME_BYTES {
        return Err(libc::ENAMETOOLONG);
    }
    if name == b"." || name == b".." {
        return Err(libc::EEXIST);
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
// Mode validation
// ---------------------------------------------------------------------------

/// Validate the `mode` for `create`.
///
/// Extracts the file-type field (`S_IFMT` bits) and ensures it is
/// `S_IFREG`.  Non-regular file types (directories, symlinks, device
/// nodes, FIFOs, sockets) are rejected with `EINVAL` — those types
/// use their own dedicated FUSE handlers (`mkdir`, `symlink`, `mknod`).
///
/// Returns the masked permission bits (0o000 – 0o7777) on success.
/// Stray bits outside the permission range (e.g. extra `S_IFMT` bits
/// from `S_IFREG`) are silently stripped.
pub fn validate_create_mode(mode: u32) -> Result<u32, c_int> {
    let file_type = mode & libc::S_IFMT;
    let perm = mode & CREATE_PERM_MASK;

    if file_type != libc::S_IFREG && file_type != 0 {
        // Non-regular file type specified — reject.  Mode 0 (no
        // explicit S_IFMT bits) is allowed because the kernel
        // supplies the type implicitly for create.
        return Err(libc::EINVAL);
    }

    Ok(perm)
}

// ---------------------------------------------------------------------------
// Umask application
// ---------------------------------------------------------------------------

/// Apply the process umask to a set of permission bits.
///
/// POSIX semantics: `final_perm = mode & ~umask`.  Only the low 12
/// permission bits (0o7777) are affected; setuid/setgid/sticky bits
/// are also cleared by umask when mode includes them, matching
/// standard POSIX behaviour.
///
/// Returns the resulting permission bits.
pub fn apply_umask(mode: u32, umask: u32) -> u32 {
    mode & !umask
}

// ---------------------------------------------------------------------------
// Combined validation (convenience)
// ---------------------------------------------------------------------------

/// Validate name, mode, and apply umask for `create` in one call.
///
/// Returns the final permission bits (after mode validation and umask
/// stripping) on success.
/// On failure returns a FUSE errno (`EINVAL`, `ENAMETOOLONG`,
/// or `EEXIST`).
pub fn plan_create(name: &[u8], mode: u32, umask: u32) -> Result<u32, c_int> {
    validate_create_name(name)?;
    let perm = validate_create_mode(mode)?;
    Ok(apply_umask(perm, umask))
}

// ---------------------------------------------------------------------------
// Read-only filesystem guard
// ---------------------------------------------------------------------------

/// Reject create on a read-only filesystem.
///
/// Returns `Err(EROFS)` when the filesystem is mounted read-only.
/// Returns `Ok(())` otherwise.
#[inline]
pub fn check_create_readonly(read_only: bool) -> Result<(), c_int> {
    if read_only {
        Err(libc::EROFS)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// handle_create -- combined entry-point for FUSE create dispatch
// ---------------------------------------------------------------------------

/// Perform full create validation and return the final permission bits.
///
/// This is the canonical FUSE dispatch entry point for `create` (opcode 35).
/// It validates:
/// 1. The filesystem is not mounted read-only.
/// 2. The file name is valid (non-empty, within [`CREATE_MAX_NAME_BYTES`],
///    not `"."` / `".."`, no NUL, no slash).
/// 3. The mode encodes a regular file (or no file type at all; S_IFREG
///    is implied).
/// 4. The umask is applied to strip forbidden permission bits.
///
/// Returns the final permission bits (0o000 -- 0o7777) on success.
///
/// # Errors
///
/// Returns `EROFS` for read-only mounts, `EINVAL` for invalid name/mode,
/// `ENAMETOOLONG` for overlong names, and `EEXIST` for `"."` / `".."` names.
///
/// # Examples
///
/// ```rust,ignore
/// use fuser::create;
///
/// let perm = create::handle_create(b"myfile", 0o644, 0o022, false)?;
/// assert_eq!(perm, 0o644);
/// ```
#[inline]
pub fn handle_create(name: &[u8], mode: u32, umask: u32, read_only: bool) -> Result<u32, c_int> {
    check_create_readonly(read_only)?;
    plan_create(name, mode, umask)
}

// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- validate_create_name ------------------------------------------------

    #[test]
    fn name_empty_rejected() {
        assert_eq!(validate_create_name(b""), Err(libc::EINVAL));
    }

    #[test]
    fn name_too_long_rejected() {
        let long = vec![b'a'; 256];
        assert_eq!(validate_create_name(&long), Err(libc::ENAMETOOLONG));
    }

    #[test]
    fn name_max_length_accepted() {
        let max = vec![b'a'; 255];
        assert_eq!(validate_create_name(&max), Ok(()));
    }

    #[test]
    fn dot_rejected() {
        assert_eq!(validate_create_name(b"."), Err(libc::EEXIST));
    }

    #[test]
    fn dotdot_rejected() {
        assert_eq!(validate_create_name(b".."), Err(libc::EEXIST));
    }

    #[test]
    fn nul_byte_rejected() {
        assert_eq!(validate_create_name(b"foo\0bar"), Err(libc::EINVAL));
    }

    #[test]
    fn slash_rejected() {
        assert_eq!(validate_create_name(b"a/b"), Err(libc::EINVAL));
    }

    #[test]
    fn normal_name_accepted() {
        assert_eq!(validate_create_name(b"file"), Ok(()));
        assert_eq!(validate_create_name(b"file with spaces"), Ok(()));
        assert_eq!(validate_create_name(b"file-with-dashes"), Ok(()));
        assert_eq!(validate_create_name(b"file_with_underscores"), Ok(()));
    }

    #[test]
    fn unicode_name_accepted() {
        // POSIX allows arbitrary bytes except NUL and '/'.
        let name = "resume.txt".as_bytes();
        assert_eq!(validate_create_name(name), Ok(()));
    }

    // -- validate_create_mode ------------------------------------------------

    #[test]
    fn regular_file_mode_accepted() {
        let result = validate_create_mode(libc::S_IFREG | 0o644);
        assert_eq!(result, Ok(0o644));
    }

    #[test]
    fn mode_zero_accepted() {
        // Mode 0 is allowed — kernel may omit S_IFMT for create.
        assert_eq!(validate_create_mode(0), Ok(0));
    }

    #[test]
    fn permission_only_mode_accepted() {
        assert_eq!(validate_create_mode(0o600), Ok(0o600));
    }

    #[test]
    fn mode_with_setuid_setgid_sticky_accepted() {
        let result = validate_create_mode(libc::S_IFREG | 0o4755);
        assert_eq!(result, Ok(0o4755));
    }

    #[test]
    fn directory_mode_rejected() {
        assert_eq!(
            validate_create_mode(libc::S_IFDIR | 0o755),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn symlink_mode_rejected() {
        assert_eq!(
            validate_create_mode(libc::S_IFLNK | 0o777),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn fifo_mode_rejected() {
        assert_eq!(
            validate_create_mode(libc::S_IFIFO | 0o666),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn char_device_mode_rejected() {
        assert_eq!(
            validate_create_mode(libc::S_IFCHR | 0o600),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn block_device_mode_rejected() {
        assert_eq!(
            validate_create_mode(libc::S_IFBLK | 0o640),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn socket_mode_rejected() {
        assert_eq!(
            validate_create_mode(libc::S_IFSOCK | 0o755),
            Err(libc::EINVAL)
        );
    }

    // -- apply_umask ---------------------------------------------------------

    #[test]
    fn umask_clears_write_bits() {
        assert_eq!(apply_umask(0o666, 0o022), 0o644);
    }

    #[test]
    fn umask_zero_preserves_all_bits() {
        assert_eq!(apply_umask(0o777, 0o000), 0o777);
    }

    #[test]
    fn umask_all_clears_everything() {
        assert_eq!(apply_umask(0o777, 0o777), 0o000);
    }

    #[test]
    fn umask_preserves_unrelated_bits() {
        assert_eq!(apply_umask(0o755, 0o002), 0o755);
    }

    #[test]
    fn umask_clears_setuid_setgid_sticky() {
        assert_eq!(apply_umask(0o4777, 0o077), 0o4700);
    }

    // -- plan_create ---------------------------------------------------------

    #[test]
    fn plan_create_valid_file() {
        assert_eq!(
            plan_create(b"myfile", libc::S_IFREG | 0o644, 0o022),
            Ok(0o644)
        );
    }

    #[test]
    fn plan_create_with_umask() {
        assert_eq!(plan_create(b"myfile", 0o666, 0o022), Ok(0o644));
    }

    #[test]
    fn plan_create_mode_zero() {
        assert_eq!(plan_create(b"myfile", 0o000, 0o000), Ok(0o000));
    }

    #[test]
    fn plan_create_setuid_preserved_under_zero_umask() {
        assert_eq!(
            plan_create(b"myfile", libc::S_IFREG | 0o4755, 0o000),
            Ok(0o4755)
        );
    }

    #[test]
    fn plan_create_setuid_cleared_by_umask() {
        assert_eq!(
            plan_create(b"myfile", libc::S_IFREG | 0o4755, 0o077),
            Ok(0o4700)
        );
    }

    #[test]
    fn plan_create_empty_name() {
        assert_eq!(
            plan_create(b"", libc::S_IFREG | 0o644, 0o022),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn plan_create_directory_mode_rejected() {
        assert_eq!(
            plan_create(b"file", libc::S_IFDIR | 0o755, 0o022),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn plan_create_dot_name() {
        assert_eq!(
            plan_create(b".", libc::S_IFREG | 0o644, 0o022),
            Err(libc::EEXIST)
        );
    }

    #[test]
    fn plan_create_nul_in_name() {
        assert_eq!(
            plan_create(b"fi\0le", libc::S_IFREG | 0o644, 0o022),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn plan_create_slash_in_name() {
        assert_eq!(
            plan_create(b"a/b", libc::S_IFREG | 0o644, 0o022),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn plan_create_long_name() {
        let long = vec![b'a'; 256];
        assert_eq!(
            plan_create(&long, libc::S_IFREG | 0o644, 0o022),
            Err(libc::ENAMETOOLONG)
        );
    }

    #[test]
    fn plan_create_max_length_name() {
        let max = vec![b'a'; 255];
        assert_eq!(plan_create(&max, libc::S_IFREG | 0o644, 0o022), Ok(0o644));
    }

    // -- check_create_readonly -----------------------------------------------

    #[test]
    fn readonly_rejected() {
        assert_eq!(check_create_readonly(true), Err(libc::EROFS));
    }

    #[test]
    fn writable_accepted() {
        assert_eq!(check_create_readonly(false), Ok(()));
    }

    // -- handle_create -------------------------------------------------------

    #[test]
    fn handle_create_valid_file() {
        let result = handle_create(b"myfile", libc::S_IFREG | 0o644, 0o022, false);
        assert_eq!(result, Ok(0o644));
    }

    #[test]
    fn handle_create_mode_zero() {
        assert_eq!(handle_create(b"myfile", 0o000, 0o000, false), Ok(0o000));
    }

    #[test]
    fn handle_create_with_umask() {
        assert_eq!(handle_create(b"myfile", 0o666, 0o022, false), Ok(0o644));
    }

    #[test]
    fn handle_create_setuid_preserved_under_zero_umask() {
        assert_eq!(
            handle_create(b"myfile", libc::S_IFREG | 0o4755, 0o000, false),
            Ok(0o4755)
        );
    }

    #[test]
    fn handle_create_setuid_cleared_by_umask() {
        assert_eq!(
            handle_create(b"myfile", libc::S_IFREG | 0o4755, 0o077, false),
            Ok(0o4700)
        );
    }

    #[test]
    fn handle_create_read_only_rejected() {
        assert_eq!(
            handle_create(b"myfile", 0o644, 0o022, true),
            Err(libc::EROFS)
        );
    }

    #[test]
    fn handle_create_empty_name() {
        assert_eq!(
            handle_create(b"", libc::S_IFREG | 0o644, 0o022, false),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn handle_create_directory_mode_rejected() {
        assert_eq!(
            handle_create(b"file", libc::S_IFDIR | 0o755, 0o022, false),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn handle_create_dot_name() {
        assert_eq!(
            handle_create(b".", libc::S_IFREG | 0o644, 0o022, false),
            Err(libc::EEXIST)
        );
    }

    #[test]
    fn handle_create_slash_in_name() {
        assert_eq!(
            handle_create(b"a/b", libc::S_IFREG | 0o644, 0o022, false),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn handle_create_long_name() {
        let long = vec![b'a'; 256];
        assert_eq!(
            handle_create(&long, libc::S_IFREG | 0o644, 0o022, false),
            Err(libc::ENAMETOOLONG)
        );
    }

    #[test]
    fn handle_create_max_length_name() {
        let max = vec![b'a'; 255];
        assert_eq!(
            handle_create(&max, libc::S_IFREG | 0o644, 0o022, false),
            Ok(0o644)
        );
    }

    #[test]
    fn handle_create_nul_in_name() {
        assert_eq!(
            handle_create(b"fi\0le", libc::S_IFREG | 0o644, 0o022, false),
            Err(libc::EINVAL)
        );
    }
}
