//! FUSE `mkdir` handler helpers — directory name validation, mode-bit
//! sanity checks, and convenience entry-points for POSIX-compliant
//! directory creation.
//!
//! Provides:
//! - [`validate_mkdir_name`]: reject empty, overlong, dot/dotdot, NUL,
//!   and slash-containing names; returns `Ok(())` or a FUSE errno.
//! - [`validate_mkdir_mode`]: ensure the mode fits within the POSIX
//!   permission-bit range (0o000–0o7777) and strip the file-type field.
//! - [`plan_mkdir`]: combined name + mode validation returning the
//!   cleaned-up mode on success.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::mkdir;
//!
//! let clean_mode = mkdir::plan_mkdir(b"newdir", 0o755)?;
//! assert_eq!(clean_mode, 0o755);
//! ```

use crate::errno;
use libc::c_int;

/// Maximum length of a single directory-name component in bytes
/// (POSIX `NAME_MAX` on Linux).
pub const MKDIR_MAX_NAME_BYTES: usize = 255;

/// POSIX permission-bit mask (0o7777).  The file-type field
/// (`S_IFMT` = 0o170000) is stripped by [`validate_mkdir_mode`].
pub const MKDIR_PERM_MASK: u32 = 0o7777;

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

/// Validate a directory name for `mkdir`.
///
/// Returns `Err(EINVAL)` when the name is empty, exceeds
/// [`MKDIR_MAX_NAME_BYTES`], is `"."` or `".."`, contains a NUL byte,
/// or contains a forward slash.
///
/// Returns `Ok(())` on success.
/// Check that the caller has write and execute (search) permission
/// on the parent directory for a mkdir operation.
///
/// POSIX requires directory write permission (to create the entry) and
/// execute/search permission (to traverse to the directory).
pub fn check_mkdir_parent_permission(
    parent_mode: u32,
    parent_uid: u32,
    parent_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
) -> Result<(), c_int> {
    crate::access::check_fuse_access(
        parent_mode,
        parent_uid,
        parent_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        crate::access::ACCESS_WRITE | crate::access::ACCESS_EXECUTE,
    )
}

/// Validate a directory name for `mkdir`.
///
/// Rejects empty names, names exceeding [`MKDIR_MAX_NAME_BYTES`], the
/// reserved names `"."` and `".."`, names containing NUL bytes, and
/// names containing forward slashes.
pub fn validate_mkdir_name(name: &[u8]) -> Result<(), c_int> {
    if name.is_empty() {
        return Err(errno::EINVAL);
    }
    if name.len() > MKDIR_MAX_NAME_BYTES {
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

/// Validate a `mkdir` mode value.
///
/// The mode is masked with [`MKDIR_PERM_MASK`] (0o7777).  Any bits
/// outside the permission range (e.g. stray `S_IFMT` bits) are
/// silently stripped.
///
/// Returns the cleaned-up mode (permission bits only) on success.
/// Mode 0 (no permission bits) is accepted, though unusual —
/// POSIX allows it; the caller (mkdir syscall) uses umask to
/// derive the final mode.
pub fn validate_mkdir_mode(mode: u32) -> Result<u32, c_int> {
    Ok(mode & MKDIR_PERM_MASK)
}

// ---------------------------------------------------------------------------
// Combined validation (convenience)
// ---------------------------------------------------------------------------

/// Validate both the directory name and the mode for `mkdir` in one
/// call.
///
/// Returns the permission-bit portion of `mode` on success.
/// On failure returns a FUSE errno (`EINVAL`, `ENAMETOOLONG`,
/// `EEXIST`, or `EACCES`).
pub fn plan_mkdir(name: &[u8], mode: u32) -> Result<u32, c_int> {
    validate_mkdir_name(name)?;
    validate_mkdir_mode(mode)
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
#[inline]
pub fn apply_mkdir_umask(mode: u32, umask: u32) -> u32 {
    mode & !umask
}

// ---------------------------------------------------------------------------
// Read-only filesystem guard
// ---------------------------------------------------------------------------

/// Reject mkdir on a read-only filesystem.
///
/// Returns `Err(EROFS)` when the filesystem is mounted read-only.
/// Returns `Ok(())` otherwise.
#[inline]
pub fn check_mkdir_readonly(read_only: bool) -> Result<(), c_int> {
    if read_only {
        Err(errno::EROFS)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// handle_mkdir -- combined entry-point for FUSE mkdir dispatch
// ---------------------------------------------------------------------------

/// Perform full mkdir validation and return the final permission bits.
///
/// This is the canonical FUSE dispatch entry point for `mkdir` (opcode 9).
/// It validates:
/// 1. The filesystem is not mounted read-only.
/// 2. The directory name is valid (non-empty, within
///    [`MKDIR_MAX_NAME_BYTES`], not `"."` / `".."`, no NUL, no slash).
/// 3. The mode fits within the POSIX permission-bit range
///    (0o000 -- 0o7777).
/// 4. The umask is applied to strip forbidden permission bits.
///
/// Returns the final permission bits (0o000 -- 0o7777) on success.
///
/// # Errors
///
/// Returns `EROFS` for read-only mounts, `EINVAL` for invalid name,
/// `ENAMETOOLONG` for overlong names, and `EEXIST` for `"."` / `".."` names.
#[inline]
pub fn handle_mkdir(name: &[u8], mode: u32, umask: u32, read_only: bool) -> Result<u32, c_int> {
    check_mkdir_readonly(read_only)?;
    let perm = plan_mkdir(name, mode)?;
    Ok(apply_mkdir_umask(perm, umask))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- validate_mkdir_name -------------------------------------------------

    #[test]
    fn name_empty_rejected() {
        assert_eq!(validate_mkdir_name(b""), Err(errno::EINVAL));
    }

    #[test]
    fn name_too_long_rejected() {
        let long = vec![b'a'; 256];
        assert_eq!(validate_mkdir_name(&long), Err(errno::ENAMETOOLONG));
    }

    #[test]
    fn name_max_length_accepted() {
        let max = vec![b'a'; 255];
        assert_eq!(validate_mkdir_name(&max), Ok(()));
    }

    #[test]
    fn dot_rejected() {
        assert_eq!(validate_mkdir_name(b"."), Err(errno::EEXIST));
    }

    #[test]
    fn dotdot_rejected() {
        assert_eq!(validate_mkdir_name(b".."), Err(errno::EEXIST));
    }

    #[test]
    fn nul_byte_rejected() {
        assert_eq!(validate_mkdir_name(b"foo\0bar"), Err(errno::EINVAL));
    }

    #[test]
    fn slash_rejected() {
        assert_eq!(validate_mkdir_name(b"a/b"), Err(errno::EINVAL));
    }

    #[test]
    fn normal_name_accepted() {
        assert_eq!(validate_mkdir_name(b"mydir"), Ok(()));
        assert_eq!(validate_mkdir_name(b"dir with spaces"), Ok(()));
        assert_eq!(validate_mkdir_name(b"dir-with-dashes"), Ok(()));
        assert_eq!(validate_mkdir_name(b"dir_with_underscores"), Ok(()));
    }

    // -- validate_mkdir_mode -------------------------------------------------

    #[test]
    fn mode_zero_accepted() {
        assert_eq!(validate_mkdir_mode(0), Ok(0));
        assert_eq!(validate_mkdir_mode(0o170000), Ok(0));
    }

    #[test]
    fn mode_permission_bits_accepted() {
        assert_eq!(validate_mkdir_mode(0o755), Ok(0o755));
        assert_eq!(validate_mkdir_mode(0o700), Ok(0o700));
        assert_eq!(validate_mkdir_mode(0o777), Ok(0o777));
        assert_eq!(validate_mkdir_mode(0o001), Ok(0o001));
    }

    #[test]
    fn mode_with_s_ifmt_stripped() {
        // S_IFDIR = 0o040000, mode 0o755 → 0o040755
        assert_eq!(validate_mkdir_mode(0o040755), Ok(0o755));
    }

    #[test]
    fn mode_with_setuid_setgid_sticky_accepted() {
        assert_eq!(validate_mkdir_mode(0o4755), Ok(0o4755));
        assert_eq!(validate_mkdir_mode(0o2755), Ok(0o2755));
        assert_eq!(validate_mkdir_mode(0o1755), Ok(0o1755));
    }

    #[test]
    fn mode_bits_outside_permission_range_stripped() {
        assert_eq!(validate_mkdir_mode(0o100000), Ok(0));
        assert_eq!(validate_mkdir_mode(0o200000), Ok(0));
    }

    // -- plan_mkdir ----------------------------------------------------------

    #[test]
    fn plan_mkdir_valid() {
        assert_eq!(plan_mkdir(b"subdir", 0o755), Ok(0o755));
    }

    #[test]
    fn plan_mkdir_empty_name() {
        assert_eq!(plan_mkdir(b"", 0o755), Err(errno::EINVAL));
    }

    #[test]
    fn plan_mkdir_zero_mode() {
        assert_eq!(plan_mkdir(b"subdir", 0), Ok(0));
    }

    #[test]
    fn plan_mkdir_dot_name() {
        assert_eq!(plan_mkdir(b".", 0o755), Err(errno::EEXIST));
    }

    #[test]
    fn plan_mkdir_too_long_name() {
        let long = vec![b'a'; 256];
        assert_eq!(plan_mkdir(&long, 0o755), Err(errno::ENAMETOOLONG));
    }

    #[test]
    fn plan_mkdir_nul_byte() {
        assert_eq!(plan_mkdir(b"bad\0name", 0o755), Err(errno::EINVAL));
    }

    #[test]
    fn plan_mkdir_slash() {
        assert_eq!(plan_mkdir(b"a/b", 0o755), Err(errno::EINVAL));
    }

    #[test]
    fn plan_mkdir_dotdot() {
        assert_eq!(plan_mkdir(b"..", 0o755), Err(errno::EEXIST));
    }

    // Additional name-validation edge cases

    #[test]
    fn name_single_char_accepted() {
        assert_eq!(validate_mkdir_name(b"a"), Ok(()));
    }

    #[test]
    fn name_with_leading_dot_accepted() {
        // ".hidden" is a valid directory name (POSIX allows it)
        assert_eq!(validate_mkdir_name(b".hidden"), Ok(()));
    }

    #[test]
    fn name_with_trailing_dot_accepted() {
        assert_eq!(validate_mkdir_name(b"dir."), Ok(()));
    }

    #[test]
    fn name_dot_dot_characters_accepted() {
        // "..a" and "a.." are not "." or "..", so they must be accepted
        assert_eq!(validate_mkdir_name(b"..a"), Ok(()));
        assert_eq!(validate_mkdir_name(b"a.."), Ok(()));
    }

    #[test]
    fn name_256_bytes_rejected() {
        let name = vec![b'x'; 256];
        assert_eq!(validate_mkdir_name(&name), Err(errno::ENAMETOOLONG));
    }

    #[test]
    fn name_255_bytes_accepted() {
        let name = vec![b'x'; 255];
        assert_eq!(validate_mkdir_name(&name), Ok(()));
    }

    // Additional mode-validation edge cases

    #[test]
    fn mode_all_permission_bits() {
        assert_eq!(validate_mkdir_mode(0o7777), Ok(0o7777));
    }

    #[test]
    fn mode_setuid_setgid_sticky_all() {
        // 0o7777: all permission bits + setuid + setgid + sticky
        assert_eq!(validate_mkdir_mode(0o7777), Ok(0o7777));
    }

    // plan_mkdir with mode stripping

    #[test]
    fn plan_mkdir_strips_s_ifmt() {
        assert_eq!(plan_mkdir(b"subdir", 0o040755), Ok(0o755));
    }

    #[test]
    fn plan_mkdir_strips_high_bits() {
        assert_eq!(plan_mkdir(b"subdir", 0o100755), Ok(0o755));
    }

    // -- apply_mkdir_umask ---------------------------------------------------

    #[test]
    fn umask_clears_write_bits() {
        assert_eq!(apply_mkdir_umask(0o777, 0o022), 0o755);
    }

    #[test]
    fn umask_zero_preserves_all_bits() {
        assert_eq!(apply_mkdir_umask(0o777, 0o000), 0o777);
    }

    #[test]
    fn umask_all_clears_everything() {
        assert_eq!(apply_mkdir_umask(0o777, 0o777), 0o000);
    }

    #[test]
    fn umask_preserves_unrelated_bits() {
        assert_eq!(apply_mkdir_umask(0o755, 0o002), 0o755);
    }

    #[test]
    fn umask_clears_setuid_setgid_sticky() {
        assert_eq!(apply_mkdir_umask(0o4777, 0o077), 0o4700);
    }

    // -- check_mkdir_readonly -------------------------------------------------

    #[test]
    fn readonly_rejected() {
        assert_eq!(check_mkdir_readonly(true), Err(errno::EROFS));
    }

    #[test]
    fn writable_accepted() {
        assert_eq!(check_mkdir_readonly(false), Ok(()));
    }

    // -- handle_mkdir ---------------------------------------------------------

    #[test]
    fn handle_mkdir_valid_directory() {
        let result = handle_mkdir(b"newdir", 0o755, 0o022, false);
        assert_eq!(result, Ok(0o755));
    }

    #[test]
    fn handle_mkdir_mode_zero() {
        assert_eq!(handle_mkdir(b"newdir", 0o000, 0o000, false), Ok(0o000));
    }

    #[test]
    fn handle_mkdir_with_umask() {
        assert_eq!(handle_mkdir(b"newdir", 0o777, 0o022, false), Ok(0o755));
    }

    #[test]
    fn handle_mkdir_setuid_preserved_under_zero_umask() {
        assert_eq!(handle_mkdir(b"newdir", 0o4755, 0o000, false), Ok(0o4755));
    }

    #[test]
    fn handle_mkdir_setuid_cleared_by_umask() {
        assert_eq!(handle_mkdir(b"newdir", 0o4755, 0o077, false), Ok(0o4700));
    }

    #[test]
    fn handle_mkdir_read_only_rejected() {
        assert_eq!(
            handle_mkdir(b"newdir", 0o755, 0o022, true),
            Err(errno::EROFS)
        );
    }

    #[test]
    fn handle_mkdir_empty_name() {
        assert_eq!(handle_mkdir(b"", 0o755, 0o022, false), Err(errno::EINVAL));
    }

    #[test]
    fn handle_mkdir_s_ifmt_stripped() {
        // S_IFDIR = 0o040000, mode = 0o040755
        assert_eq!(handle_mkdir(b"newdir", 0o040755, 0o022, false), Ok(0o755));
    }

    #[test]
    fn handle_mkdir_dot_name() {
        assert_eq!(handle_mkdir(b".", 0o755, 0o022, false), Err(errno::EEXIST));
    }

    #[test]
    fn handle_mkdir_dotdot_name() {
        assert_eq!(handle_mkdir(b"..", 0o755, 0o022, false), Err(errno::EEXIST));
    }

    #[test]
    fn handle_mkdir_slash_in_name() {
        assert_eq!(
            handle_mkdir(b"a/b", 0o755, 0o022, false),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn handle_mkdir_long_name() {
        let long = vec![b'a'; 256];
        assert_eq!(
            handle_mkdir(&long, 0o755, 0o022, false),
            Err(errno::ENAMETOOLONG)
        );
    }

    #[test]
    fn handle_mkdir_max_length_name() {
        let max = vec![b'a'; 255];
        assert_eq!(handle_mkdir(&max, 0o755, 0o022, false), Ok(0o755));
    }

    #[test]
    fn handle_mkdir_nul_in_name() {
        assert_eq!(
            handle_mkdir(b"dir\0name", 0o755, 0o022, false),
            Err(errno::EINVAL)
        );
    }

    // -- check_mkdir_parent_permission smoke ----------------------------------
    // Full permission checks are tested in the access module; smoke tests
    // here validate that the mkdir-specific ACCESS_WRITE|ACCESS_EXECUTE
    // combination is wired correctly.

    #[test]
    fn parent_permission_owner_write_exec_ok() {
        // Owner matches: mode 0o300 (write+execute), caller is owner.
        let result = check_mkdir_parent_permission(
            0o300,
            1000,
            100, // mode, uid, gid
            1000,
            100,
            &[], // caller uid, gid, groups
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn parent_permission_missing_write_rejected() {
        // Owner matches but mode 0o100 (execute only, no write).
        let result = check_mkdir_parent_permission(0o100, 1000, 100, 1000, 100, &[]);
        assert_eq!(result, Err(errno::EACCES));
    }

    #[test]
    fn parent_permission_missing_execute_rejected() {
        // Owner matches but mode 0o200 (write only, no execute).
        let result = check_mkdir_parent_permission(0o200, 1000, 100, 1000, 100, &[]);
        assert_eq!(result, Err(errno::EACCES));
    }

    #[test]
    fn parent_permission_root_bypass() {
        // Root (uid 0) bypasses permission checks.
        let result = check_mkdir_parent_permission(0o000, 1000, 100, 0, 0, &[]);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn parent_permission_other_no_access_rejected() {
        // Caller is neither owner, group, nor root, mode 0o000.
        let result = check_mkdir_parent_permission(0o000, 1000, 100, 2000, 200, &[]);
        assert_eq!(result, Err(errno::EACCES));
    }
}
