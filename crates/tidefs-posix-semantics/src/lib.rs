#![no_std]
#![forbid(unsafe_code)]

//! Deterministic POSIX semantics helpers.
//!
//! Ported from the v0.262 Python reference (`posix_semantics.py`, 292 lines).
//! All functions are pure, deterministic, and have no OS I/O or internal
//! allocation.
//!
//! Covers:
//! - Directory entry name validation
//! - Create-mode umask application
//! - Open flag access-mode classification
//! - Permission evaluation (owner/group/other + supplementary groups)
//! - `chmod` sanitization (S_ISGID clearing for non-root)
//! - `setgid` inheritance on file/directory creation
//! - Sticky-bit unlink/rename gate
//! - `killpriv` on write/truncate and chown
//! - `relatime` update policy
//! - Inode flags (immutable, append-only, noatime)

use tidefs_types_vfs_core::Errno;

// ---------------------------------------------------------------------------
// Mode / permission constants
// ---------------------------------------------------------------------------

/// Owner read.
pub const S_IRUSR: u32 = 0o400;
/// Owner write.
pub const S_IWUSR: u32 = 0o200;
/// Owner execute.
pub const S_IXUSR: u32 = 0o100;
/// Group read.
pub const S_IRGRP: u32 = 0o040;
/// Group write.
pub const S_IWGRP: u32 = 0o020;
/// Group execute.
pub const S_IXGRP: u32 = 0o010;
/// Other read.
pub const S_IROTH: u32 = 0o004;
/// Other write.
pub const S_IWOTH: u32 = 0o002;
/// Other execute.
pub const S_IXOTH: u32 = 0o001;

/// Set-user-ID.
pub const S_ISUID: u32 = 0o4000;
/// Set-group-ID.
pub const S_ISGID: u32 = 0o2000;
/// Sticky bit.
pub const S_ISVTX: u32 = 0o1000;

/// Access modes (R_OK / W_OK / X_OK style).
pub const R_OK: u8 = 4;
pub const W_OK: u8 = 2;
pub const X_OK: u8 = 1;
pub const F_OK: u8 = 0;

/// File type bits mask (upper nibble of 32-bit mode).
pub const S_IFMT: u32 = 0o170000;
/// Regular file.
pub const S_IFREG: u32 = 0o100000;
/// Directory.
pub const S_IFDIR: u32 = 0o040000;

/// Ordinary permission bits affected by umask.
pub const S_PERM_BITS: u32 = 0o0777;
/// Permission and special bits replaced by chmod-style mode updates.
pub const S_CHMOD_BITS: u32 = S_ISUID | S_ISGID | S_ISVTX | S_PERM_BITS;

// ---------------------------------------------------------------------------
// Open flag constants and helpers
// ---------------------------------------------------------------------------

/// Access-mode mask for Linux `open(2)` flags.
pub const O_ACCMODE: u32 = 0o00000003;
/// Open for reading only.
pub const O_RDONLY: u32 = 0o00000000;
/// Open for writing only.
pub const O_WRONLY: u32 = 0o00000001;
/// Open for reading and writing.
pub const O_RDWR: u32 = 0o00000002;
/// Create the file if it does not exist.
pub const O_CREAT: u32 = 0o00000100;
/// Fail create if the file already exists.
pub const O_EXCL: u32 = 0o00000200;
/// Truncate the file on open.
pub const O_TRUNC: u32 = 0o00001000;
/// Append writes to end-of-file.
pub const O_APPEND: u32 = 0o00002000;
/// Require the target to be a directory.
pub const O_DIRECTORY: u32 = 0o00200000;
/// Do not follow the final symlink component.
pub const O_NOFOLLOW: u32 = 0o00400000;
/// Write I/O completes only after data and metadata are on stable storage.
pub const O_SYNC: u32 = 0o4010000;
/// Write I/O completes only after data reaches stable storage.
///
/// On Linux, `O_SYNC` includes the `O_DSYNC` bit.
pub const O_DSYNC: u32 = 0o10000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OpenAccessMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OpenFlagError {
    ReservedAccessMode(u32),
}

/// Classify the access-mode bits in Linux `open(2)` flags.
pub fn open_access_mode(flags: u32) -> Result<OpenAccessMode, OpenFlagError> {
    match flags & O_ACCMODE {
        O_RDONLY => Ok(OpenAccessMode::ReadOnly),
        O_WRONLY => Ok(OpenAccessMode::WriteOnly),
        O_RDWR => Ok(OpenAccessMode::ReadWrite),
        reserved => Err(OpenFlagError::ReservedAccessMode(reserved)),
    }
}

/// Return whether an open flag set permits reads.
pub fn open_flags_allow_read(flags: u32) -> Result<bool, OpenFlagError> {
    match open_access_mode(flags)? {
        OpenAccessMode::ReadOnly | OpenAccessMode::ReadWrite => Ok(true),
        OpenAccessMode::WriteOnly => Ok(false),
    }
}

/// Return whether an open flag set permits writes.
pub fn open_flags_allow_write(flags: u32) -> Result<bool, OpenFlagError> {
    match open_access_mode(flags)? {
        OpenAccessMode::WriteOnly | OpenAccessMode::ReadWrite => Ok(true),
        OpenAccessMode::ReadOnly => Ok(false),
    }
}

/// Return whether `O_CREAT` is present.
pub fn open_flags_require_creation(flags: u32) -> bool {
    (flags & O_CREAT) != 0
}

/// Return whether `O_CREAT | O_EXCL` requests exclusive creation.
pub fn open_flags_require_exclusive_creation(flags: u32) -> bool {
    (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)
}

/// Return whether open flags require synchronous write durability.
///
/// Checking the `O_DSYNC` bit covers both `O_DSYNC` and Linux `O_SYNC`.
pub fn open_flags_require_sync(flags: u32) -> bool {
    (flags & O_DSYNC) != 0
}

// ---------------------------------------------------------------------------
// Directory entry name validation and create mode helpers
// ---------------------------------------------------------------------------

/// Linux component-name limit for a single directory entry.
pub const POSIX_NAME_MAX: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DirEntryNameError {
    Empty,
    Dot,
    DotDot,
    ContainsSlash,
    ContainsNul,
    TooLong { len: usize },
}

/// Validate a single directory-entry name, not a slash-separated path.
pub fn validate_dir_entry_name(name: &[u8]) -> Result<(), DirEntryNameError> {
    if name.is_empty() {
        return Err(DirEntryNameError::Empty);
    }
    if name == b"." {
        return Err(DirEntryNameError::Dot);
    }
    if name == b".." {
        return Err(DirEntryNameError::DotDot);
    }
    if name.len() > POSIX_NAME_MAX {
        return Err(DirEntryNameError::TooLong { len: name.len() });
    }
    if name.contains(&b'/') {
        return Err(DirEntryNameError::ContainsSlash);
    }
    if name.contains(&b'\0') {
        return Err(DirEntryNameError::ContainsNul);
    }
    Ok(())
}

/// Apply the caller umask to ordinary permission bits during create.
pub fn apply_umask_for_create(mode: u32, umask: u32) -> u32 {
    (mode & !S_PERM_BITS) | ((mode & S_PERM_BITS) & !(umask & S_PERM_BITS))
}

// ---------------------------------------------------------------------------
// POSIX inode flags (FS_IOC_GETFLAGS / FS_IOC_SETFLAGS)
// ---------------------------------------------------------------------------

/// Immutable file (FS_IMMUTABLE_FL).
pub const FS_IMMUTABLE_FL: u32 = 0x00000010;
/// Append-only file (FS_APPEND_FL).
pub const FS_APPEND_FL: u32 = 0x00000020;
/// No atime updates (FS_NOATIME_FL).
pub const FS_NOATIME_FL: u32 = 0x00000080;

// ---------------------------------------------------------------------------
// Permission evaluation (§4.1 in issue)
// ---------------------------------------------------------------------------

/// Compute the 3-bit rwx mask the caller holds for a file.
///
/// Returns `0..7` where bit 2 = read, bit 1 = write, bit 0 = execute.
///
/// `caller_groups` is the list of supplementary group IDs for the caller.
/// If `caller_uid == 0` (root), all permissions are granted unconditionally.
pub fn posix_perm_bits_for_caller(
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
) -> u8 {
    // Root can always read/write, and can execute if any execute bit is set.
    if caller_uid == 0 {
        if (mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0 || (mode & S_IFMT) == S_IFDIR {
            return 7;
        }
        return R_OK | W_OK; // read+write but not execute
    }

    // Owner check.
    if caller_uid == owner_uid {
        return ((mode >> 6) & 0x7) as u8;
    }

    // Group check: caller's gid matches file gid, OR any supplementary group
    // matches file gid.
    let is_group_member = caller_gid == owner_gid || caller_groups.contains(&owner_gid);

    if is_group_member {
        return ((mode >> 3) & 0x7) as u8;
    }

    // Other fallback.
    (mode & 0x7) as u8
}

/// Check whether the caller has a specific permission for the file.
///
/// `want_mask` uses `R_OK`, `W_OK`, `X_OK` constants.  Returns `true` if
/// the caller has all the requested bits.
pub fn posix_has_perm(
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    want_mask: u8,
) -> bool {
    if want_mask == 0 {
        return true; // F_OK: mere existence check
    }
    let bits = posix_perm_bits_for_caller(
        mode,
        owner_uid,
        owner_gid,
        caller_uid,
        caller_gid,
        caller_groups,
    );
    (bits & want_mask) == want_mask
}

// ---------------------------------------------------------------------------
// chmod sanitization (§4.2)
// ---------------------------------------------------------------------------

/// Apply Linux S_ISGID clearing rules for non-root callers on regular files.
///
/// Return value: `(sanitized_mode, ok)`.
///
/// - If the caller is not root and the file is a regular file, S_ISGID is
///   cleared when the file is not group-executable (Linux convention).
/// - The requested mode bits replace the lower 12 bits of the old mode;
///   file type bits are preserved.
/// - Returns `false` (permission denied) if a non-owner caller tries to
///   chmod.
pub fn chmod_sanitize_mode_unprivileged(
    old_mode: u32,
    requested_mode: u32,
    owner_uid: u32,
    caller_uid: u32,
) -> (u32, bool) {
    // Only the owner or root can chmod.
    if caller_uid != 0 && caller_uid != owner_uid {
        return (old_mode, false);
    }

    let file_type = old_mode & S_IFMT;
    let is_reg = file_type == S_IFREG;

    // Merge: preserve file type, replace lower 12 bits with requested.
    let mut new_mode = (old_mode & S_IFMT) | (requested_mode & S_CHMOD_BITS);

    // Linux rule: non-root chmod on a regular file clears S_ISGID unless the
    // file is group-executable.
    if caller_uid != 0 && is_reg && (new_mode & S_IXGRP) == 0 {
        new_mode &= !S_ISGID;
    }

    (new_mode, true)
}

// ---------------------------------------------------------------------------
// setgid inheritance (§4.3)
// ---------------------------------------------------------------------------

/// Apply setgid inheritance on file/directory creation.
///
/// Returns `(child_mode, child_gid)` updated for setgid inheritance.
///
/// Rules (Linux):
/// - If parent directory has S_ISGID:
///   - `child_gid` ← `parent_gid`
///   - If the child is a directory, propagate S_ISGID to the child mode.
pub fn apply_setgid_inheritance_for_create(
    parent_mode: u32,
    parent_gid: u32,
    child_mode: u32,
    child_gid: u32,
) -> (u32, u32) {
    if (parent_mode & S_ISGID) == 0 {
        return (child_mode, child_gid);
    }

    let new_gid = parent_gid;
    let file_type = child_mode & S_IFMT;
    let is_dir = file_type == S_IFDIR;

    let new_mode = if is_dir {
        child_mode | S_ISGID
    } else {
        child_mode
    };

    (new_mode, new_gid)
}

// ---------------------------------------------------------------------------
// Sticky-bit gate (§4.4)
// ---------------------------------------------------------------------------

/// Check whether a caller may unlink or rename an entry from a directory
/// with the sticky bit set.
///
/// Returns `true` if the operation is permitted.
///
/// Rules (Linux):
/// - Root (uid 0) can always unlink/rename.
/// - Caller who owns the parent directory can unlink/rename.
/// - Caller who owns the target entry can unlink/rename.
/// - Otherwise, denied if the sticky bit is set.
///
/// If the sticky bit is NOT set, this function returns `true` unconditionally
/// (the caller's write permission on the directory is checked separately).
pub fn sticky_dir_allows_unlink_or_rename(
    parent_mode: u32,
    parent_uid: u32,
    entry_uid: u32,
    caller_uid: u32,
) -> bool {
    if (parent_mode & S_ISVTX) == 0 {
        return true;
    }

    caller_uid == 0 || caller_uid == parent_uid || caller_uid == entry_uid
}

// ---------------------------------------------------------------------------
// killpriv (§4.5)
// ---------------------------------------------------------------------------

/// Apply Linux killpriv rules on write or truncate.
///
/// Called when a non-privileged caller writes to or truncates a file.
/// Returns the updated mode with privilege bits cleared as needed.
///
/// Rules:
/// - Always clear S_ISUID for non-root callers.
/// - Clear S_ISGID if the file is group-executable (or always, per Linux).
pub fn killpriv_mode_on_write_or_truncate(mode: u32, caller_uid: u32) -> u32 {
    if caller_uid == 0 {
        return mode;
    }
    // Linux clears S_ISUID unconditionally on write/truncate for non-root.
    // S_ISGID is cleared if group-exec is set (executable, so the bit
    // controls effective gid rather than mandatory locking).
    let mut new_mode = mode & !S_ISUID;
    if (mode & S_IXGRP) != 0 {
        new_mode &= !S_ISGID;
    }
    new_mode
}

/// Apply Linux killpriv rules on chown/chgrp.
///
/// Called when a non-privileged caller changes file ownership.
/// Returns the updated mode with both S_ISUID and S_ISGID cleared.
pub fn killpriv_mode_on_chown(mode: u32, caller_uid: u32) -> u32 {
    if caller_uid == 0 {
        return mode;
    }
    mode & !(S_ISUID | S_ISGID)
}

// ---------------------------------------------------------------------------
// relatime policy (§4.6)
// ---------------------------------------------------------------------------

/// Number of nanoseconds in 24 hours.
pub const RELATIME_24H_NS: i64 = 24 * 3600 * 1_000_000_000;

/// Determine whether atime should be updated under Linux relatime policy.
///
/// Returns `true` if atime should be bumped to `now_ns`.
///
/// Rules (Linux `relatime`):
/// - Update if atime < mtime.
/// - Update if atime < ctime.
/// - Update if atime is older than 24 hours from now.
pub fn should_update_atime_relatime(
    atime_ns: i64,
    mtime_ns: i64,
    ctime_ns: i64,
    now_ns: i64,
) -> bool {
    atime_ns < mtime_ns || atime_ns < ctime_ns || (now_ns - atime_ns) >= RELATIME_24H_NS
}

// ---------------------------------------------------------------------------
// Inode flags (§4.7)
// ---------------------------------------------------------------------------

/// Return `true` if the immutable flag is set.
pub fn inode_is_immutable(posix_iflags: u32) -> bool {
    (posix_iflags & FS_IMMUTABLE_FL) != 0
}

/// Return `true` if the append-only flag is set.
pub fn inode_is_append_only(posix_iflags: u32) -> bool {
    (posix_iflags & FS_APPEND_FL) != 0
}

/// Return `true` if the noatime flag is set.
pub fn inode_is_noatime(posix_iflags: u32) -> bool {
    (posix_iflags & FS_NOATIME_FL) != 0
}

// ---------------------------------------------------------------------------
// Immutable and append-only enforcement guards (§4.8)
// ---------------------------------------------------------------------------

/// Reject operations on an immutable inode.
///
/// POSIX FS_IMMUTABLE_FL prevents write, truncate, chmod, chown, unlink,
/// rmdir, and rename operations. Root (uid 0) is NOT exempt under POSIX:
/// immutable is immutable for everyone.
pub fn enforce_immutable_guard(posix_iflags: u32) -> Result<(), Errno> {
    if inode_is_immutable(posix_iflags) {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// Reject non-append writes on an append-only inode.
///
/// When `write_at_eof` is true the write lands at end-of-file and is
/// permitted even on an append-only file.  Non-EOF writes (including
/// arbitrary-offset writes) are rejected with EPERM.
pub fn enforce_append_only_write_guard(posix_iflags: u32, write_at_eof: bool) -> Result<(), Errno> {
    if inode_is_append_only(posix_iflags) && !write_at_eof {
        return Err(Errno::EPERM);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- open flag helpers -------------------------------------------------

    #[test]
    fn open_access_mode_classifies_linux_access_bits() {
        assert_eq!(open_access_mode(O_RDONLY), Ok(OpenAccessMode::ReadOnly));
        assert_eq!(open_access_mode(O_WRONLY), Ok(OpenAccessMode::WriteOnly));
        assert_eq!(open_access_mode(O_RDWR), Ok(OpenAccessMode::ReadWrite));
    }

    #[test]
    fn open_access_mode_rejects_reserved_value() {
        assert_eq!(
            open_access_mode(O_ACCMODE),
            Err(OpenFlagError::ReservedAccessMode(O_ACCMODE))
        );
    }

    #[test]
    fn open_access_mode_ignores_non_access_bits() {
        assert_eq!(
            open_access_mode(O_CREAT | O_EXCL | O_TRUNC | O_RDWR),
            Ok(OpenAccessMode::ReadWrite)
        );
    }

    #[test]
    fn open_flag_helpers_report_read_write_capability() {
        assert_eq!(open_flags_allow_read(O_RDONLY), Ok(true));
        assert_eq!(open_flags_allow_write(O_RDONLY), Ok(false));
        assert_eq!(open_flags_allow_read(O_WRONLY), Ok(false));
        assert_eq!(open_flags_allow_write(O_WRONLY), Ok(true));
        assert_eq!(open_flags_allow_read(O_RDWR), Ok(true));
        assert_eq!(open_flags_allow_write(O_RDWR), Ok(true));
    }

    #[test]
    fn open_flag_helpers_propagate_reserved_access_mode() {
        assert_eq!(
            open_flags_allow_read(O_ACCMODE | O_CREAT),
            Err(OpenFlagError::ReservedAccessMode(O_ACCMODE))
        );
        assert_eq!(
            open_flags_allow_write(O_ACCMODE | O_TRUNC),
            Err(OpenFlagError::ReservedAccessMode(O_ACCMODE))
        );
    }

    #[test]
    fn create_flag_helpers_require_expected_bits() {
        assert!(open_flags_require_creation(O_CREAT));
        assert!(open_flags_require_creation(O_CREAT | O_EXCL));
        assert!(!open_flags_require_creation(O_EXCL));

        assert!(open_flags_require_exclusive_creation(O_CREAT | O_EXCL));
        assert!(!open_flags_require_exclusive_creation(O_CREAT));
        assert!(!open_flags_require_exclusive_creation(O_EXCL));
    }

    #[test]
    fn sync_flag_helper_detects_odsync_and_osync() {
        assert!(open_flags_require_sync(O_DSYNC));
        assert!(open_flags_require_sync(O_SYNC));
        assert!(open_flags_require_sync(O_WRONLY | O_DSYNC));
        assert!(open_flags_require_sync(O_RDWR | O_SYNC));
        assert!(!open_flags_require_sync(O_WRONLY));
        assert!(!open_flags_require_sync(O_WRONLY | O_CREAT | O_TRUNC));
    }

    // -- directory entry name helpers -------------------------------------

    #[test]
    fn validate_dir_entry_name_accepts_plain_component() {
        assert_eq!(validate_dir_entry_name(b"readme.txt"), Ok(()));
        assert_eq!(validate_dir_entry_name(&[0xff, b'a']), Ok(()));
    }

    #[test]
    fn validate_dir_entry_name_rejects_reserved_components() {
        assert_eq!(validate_dir_entry_name(b""), Err(DirEntryNameError::Empty));
        assert_eq!(validate_dir_entry_name(b"."), Err(DirEntryNameError::Dot));
        assert_eq!(
            validate_dir_entry_name(b".."),
            Err(DirEntryNameError::DotDot)
        );
    }

    #[test]
    fn validate_dir_entry_name_rejects_path_separators_and_nul() {
        assert_eq!(
            validate_dir_entry_name(b"nested/name"),
            Err(DirEntryNameError::ContainsSlash)
        );
        assert_eq!(
            validate_dir_entry_name(b"name\0suffix"),
            Err(DirEntryNameError::ContainsNul)
        );
    }

    #[test]
    fn validate_dir_entry_name_enforces_name_max() {
        let max = [b'a'; POSIX_NAME_MAX];
        let too_long = [b'a'; POSIX_NAME_MAX + 1];

        assert_eq!(validate_dir_entry_name(&max), Ok(()));
        assert_eq!(
            validate_dir_entry_name(&too_long),
            Err(DirEntryNameError::TooLong {
                len: POSIX_NAME_MAX + 1
            })
        );
    }

    #[test]
    fn apply_umask_for_create_masks_only_permission_bits() {
        let mode = S_IFREG | S_ISUID | S_ISGID | S_ISVTX | 0o777;
        let result = apply_umask_for_create(mode, 0o027);

        assert_eq!(result & S_IFMT, S_IFREG);
        assert_eq!(
            result & (S_ISUID | S_ISGID | S_ISVTX),
            S_ISUID | S_ISGID | S_ISVTX
        );
        assert_eq!(result & S_PERM_BITS, 0o750);
    }

    #[test]
    fn apply_umask_for_create_ignores_non_permission_umask_bits() {
        let mode = S_IFDIR | 0o775;
        let result = apply_umask_for_create(mode, S_IFREG | S_ISUID | 0o002);

        assert_eq!(result & S_IFMT, S_IFDIR);
        assert_eq!(result & S_PERM_BITS, 0o775 & !0o002);
    }

    // -- posix_perm_bits_for_caller ----------------------------------------

    #[test]
    fn owner_gets_owner_bits() {
        // mode 0o750: owner=rwx, group=rx, other=---
        let mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP;
        let bits = posix_perm_bits_for_caller(mode, 1000, 100, 1000, 200, &[]);
        assert_eq!(bits, 7); // rwx
    }

    #[test]
    fn group_member_gets_group_bits_by_gid() {
        let mode = 0o750;
        let bits = posix_perm_bits_for_caller(mode, 1000, 100, 2000, 100, &[]);
        assert_eq!(bits, 5); // r-x
    }

    #[test]
    fn group_member_gets_group_bits_by_supplementary() {
        let mode = 0o750;
        let bits = posix_perm_bits_for_caller(mode, 1000, 100, 2000, 300, &[400, 100]);
        assert_eq!(bits, 5); // r-x
    }

    #[test]
    fn other_gets_other_bits() {
        let mode = 0o754; // owner=rwx, group=rx, other=r
        let bits = posix_perm_bits_for_caller(mode, 1000, 100, 2000, 300, &[400]);
        assert_eq!(bits, 4); // r--
    }

    #[test]
    fn root_gets_all_perms() {
        let mode = 0o700; // owner=rwx, group=---, other=---
        let bits = posix_perm_bits_for_caller(mode, 1000, 100, 0, 200, &[]);
        assert_eq!(bits, 7); // rwx
    }

    #[test]
    fn root_gets_rw_on_no_exec_file() {
        let mode = 0o600; // no execute bits at all
        let bits = posix_perm_bits_for_caller(mode, 1000, 100, 0, 200, &[]);
        assert_eq!(bits, R_OK | W_OK); // rw-
    }

    #[test]
    fn root_gets_rwx_on_directory() {
        let mode = S_IFDIR; // directory, no perm bits
        let bits = posix_perm_bits_for_caller(mode, 1000, 100, 0, 200, &[]);
        assert_eq!(bits, 7);
    }

    // -- posix_has_perm ----------------------------------------------------

    #[test]
    fn has_perm_checks_want_mask() {
        let mode = 0o755;
        assert!(posix_has_perm(mode, 1000, 100, 1000, 200, &[], R_OK));
        assert!(posix_has_perm(mode, 1000, 100, 1000, 200, &[], W_OK));
        assert!(posix_has_perm(mode, 1000, 100, 1000, 200, &[], X_OK));
        assert!(posix_has_perm(mode, 1000, 100, 1000, 200, &[], R_OK | W_OK));
    }

    #[test]
    fn has_perm_fails_for_missing_bit() {
        let mode = 0o500; // owner=r-x only
        assert!(!posix_has_perm(mode, 1000, 100, 1000, 200, &[], W_OK));
    }

    #[test]
    fn has_perm_f_ok_always_true() {
        assert!(posix_has_perm(0o000, 1000, 100, 2000, 300, &[], F_OK));
    }

    #[test]
    fn non_owner_restricted() {
        let mode = 0o700; // owner=rwx, others nothing
        assert!(!posix_has_perm(mode, 1000, 100, 2000, 300, &[], R_OK));
    }

    // -- chmod_sanitize_mode_unprivileged ----------------------------------

    #[test]
    fn owner_can_chmod() {
        let old = 0o100644; // regular file, rw-r--r--
        let (new, ok) = chmod_sanitize_mode_unprivileged(old, 0o600, 1000, 1000);
        assert!(ok);
        assert_eq!(new & 0o0777, 0o600);
        assert_eq!(new & S_IFMT, S_IFREG); // file type preserved
    }

    #[test]
    fn non_owner_chmod_denied() {
        let old = 0o100644;
        let (new, ok) = chmod_sanitize_mode_unprivileged(old, 0o777, 1000, 2000);
        assert!(!ok);
        assert_eq!(new, old); // unchanged
    }

    #[test]
    fn root_can_chmod_any_file() {
        let old = 0o100644;
        let (new, ok) = chmod_sanitize_mode_unprivileged(old, 0o700, 1000, 0);
        assert!(ok);
        assert_eq!(new & 0o0777, 0o700);
    }

    #[test]
    fn chmod_non_root_clears_sgid_on_reg_without_group_exec() {
        // Regular file with S_ISGID set, no group exec
        let old = S_IFREG | S_ISGID | 0o755;
        let (new, ok) = chmod_sanitize_mode_unprivileged(old, 0o644, 1000, 1000);
        assert!(ok);
        assert_eq!(new & S_ISGID, 0); // S_ISGID cleared
    }

    #[test]
    fn chmod_non_root_clears_requested_sgid_on_reg_without_group_exec() {
        let old = S_IFREG | 0o755;
        let requested = S_ISGID | 0o644;
        let (new, ok) = chmod_sanitize_mode_unprivileged(old, requested, 1000, 1000);
        assert!(ok);
        assert_eq!(new & S_IFMT, S_IFREG);
        assert_eq!(new & S_PERM_BITS, 0o644);
        assert_eq!(new & S_ISGID, 0);
    }

    #[test]
    fn chmod_non_root_keeps_requested_sgid_on_reg_with_group_exec() {
        // Regular file with requested S_ISGID and group exec.
        let old = S_IFREG | 0o640;
        let requested = S_ISGID | 0o750;
        let (new, ok) = chmod_sanitize_mode_unprivileged(old, requested, 1000, 1000);
        assert!(ok);
        assert_eq!(new & S_CHMOD_BITS, requested);
    }

    #[test]
    fn chmod_root_replaces_special_bits_from_requested_mode() {
        let old = S_IFREG | S_ISUID | S_ISGID | S_ISVTX | 0o777;
        let requested = S_ISVTX | 0o640;
        let (new, ok) = chmod_sanitize_mode_unprivileged(old, requested, 1000, 0);
        assert!(ok);
        assert_eq!(new & S_IFMT, S_IFREG);
        assert_eq!(new & S_CHMOD_BITS, requested);
    }

    #[test]
    fn chmod_directory_replaces_requested_special_bits() {
        let old = S_IFDIR | S_ISUID | 0o755;
        let requested = S_ISGID | S_ISVTX | 0o700;
        let (new, ok) = chmod_sanitize_mode_unprivileged(old, requested, 1000, 1000);
        assert!(ok);
        assert_eq!(new & S_IFMT, S_IFDIR);
        assert_eq!(new & S_CHMOD_BITS, requested);
    }

    // -- apply_setgid_inheritance_for_create -------------------------------

    #[test]
    fn no_setgid_parent_no_change() {
        let (cm, cg) = apply_setgid_inheritance_for_create(0o755, 100, 0o644, 200);
        assert_eq!(cg, 200);
        assert_eq!(cm, 0o644);
    }

    #[test]
    fn setgid_parent_inherits_gid() {
        let (cm, cg) = apply_setgid_inheritance_for_create(0o2755, 100, S_IFREG | 0o644, 200);
        assert_eq!(cg, 100); // child gid matches parent
        assert_eq!(cm & S_IFMT, S_IFREG);
        assert_eq!(cm & S_ISGID, 0); // regular file doesn't propagate S_ISGID
    }

    #[test]
    fn setgid_parent_dir_inherits_sgid() {
        let (cm, cg) = apply_setgid_inheritance_for_create(0o2755, 100, S_IFDIR | 0o755, 200);
        assert_eq!(cg, 100);
        assert_ne!(cm & S_ISGID, 0); // directory propagates S_ISGID
    }

    #[test]
    fn setgid_parent_mode_0_still_inherits() {
        // S_ISGID alone (no permission bits): gid still inherited
        let (cm, cg) = apply_setgid_inheritance_for_create(S_ISGID, 100, S_IFREG | 0o644, 200);
        assert_eq!(cg, 100);
        assert_eq!(cm & S_ISGID, 0); // file does not get S_ISGID
        assert_eq!(cm, S_IFREG | 0o644);
    }

    #[test]
    fn setgid_caller_uid_0_still_inherits() {
        // uid 0 (root) caller still inherits gid from setgid parent
        let (cm, cg) = apply_setgid_inheritance_for_create(0o2755, 100, S_IFREG | 0o644, 0);
        assert_eq!(cg, 100);
        assert_eq!(cm, S_IFREG | 0o644);
    }

    // -- sticky_dir_allows_unlink_or_rename --------------------------------

    #[test]
    fn no_sticky_always_allowed() {
        assert!(sticky_dir_allows_unlink_or_rename(0o755, 1000, 2000, 3000));
    }

    #[test]
    fn sticky_root_allowed() {
        assert!(sticky_dir_allows_unlink_or_rename(
            S_ISVTX | 0o777,
            1000,
            2000,
            0
        ));
    }

    #[test]
    fn sticky_dir_owner_allowed() {
        assert!(sticky_dir_allows_unlink_or_rename(
            S_ISVTX | 0o777,
            1000,
            2000,
            1000,
        ));
    }

    #[test]
    fn sticky_entry_owner_allowed() {
        assert!(sticky_dir_allows_unlink_or_rename(
            S_ISVTX | 0o777,
            1000,
            2000,
            2000,
        ));
    }

    #[test]
    fn sticky_stranger_denied() {
        assert!(!sticky_dir_allows_unlink_or_rename(
            S_ISVTX | 0o777,
            1000,
            2000,
            3000,
        ));
    }

    #[test]
    fn sticky_combined_setgid_and_sticky() {
        // Parent has both S_ISGID and S_ISVTX; sticky gate still enforced
        assert!(!sticky_dir_allows_unlink_or_rename(
            S_IFDIR | S_ISVTX | S_ISGID | 0o777,
            1000,
            2000,
            3000,
        ));
    }

    // -- killpriv ----------------------------------------------------------

    #[test]
    fn killpriv_write_clears_suid() {
        let mode = S_ISUID | S_ISGID | 0o755;
        let result = killpriv_mode_on_write_or_truncate(mode, 1000);
        assert_eq!(result & S_ISUID, 0); // S_ISUID cleared
    }

    #[test]
    fn killpriv_write_clears_sgid_with_group_exec() {
        let mode = S_ISUID | S_ISGID | 0o750; // group-exec set
        let result = killpriv_mode_on_write_or_truncate(mode, 1000);
        assert_eq!(result & S_ISGID, 0); // S_ISGID cleared
    }

    #[test]
    fn killpriv_write_preserves_sgid_without_group_exec() {
        let mode = S_ISUID | S_ISGID | 0o644; // no group-exec
        let result = killpriv_mode_on_write_or_truncate(mode, 1000);
        assert_ne!(result & S_ISGID, 0); // S_ISGID preserved (mandatory locking)
    }

    #[test]
    fn killpriv_write_root_no_change() {
        let mode = S_ISUID | S_ISGID | 0o755;
        let result = killpriv_mode_on_write_or_truncate(mode, 0);
        assert_eq!(result, mode);
    }

    #[test]
    fn killpriv_chown_clears_both() {
        let mode = S_ISUID | S_ISGID | 0o755;
        let result = killpriv_mode_on_chown(mode, 1000);
        assert_eq!(result & (S_ISUID | S_ISGID), 0);
    }

    #[test]
    fn killpriv_chown_root_no_change() {
        let mode = S_ISUID | S_ISGID | 0o755;
        let result = killpriv_mode_on_chown(mode, 0);
        assert_eq!(result, mode);
    }

    // -- relatime ----------------------------------------------------------

    #[test]
    fn relatime_updates_if_atime_before_mtime() {
        // atime=100, mtime=200, ctime=200, now=300
        assert!(should_update_atime_relatime(100, 200, 200, 300));
    }

    #[test]
    fn relatime_updates_if_atime_before_ctime() {
        // atime=100, mtime=100, ctime=200, now=300
        assert!(should_update_atime_relatime(100, 100, 200, 300));
    }

    #[test]
    fn relatime_updates_if_24h_old() {
        let now = 1_000_000_000_000;
        let atime = now - RELATIME_24H_NS - 1;
        assert!(should_update_atime_relatime(atime, 0, 0, now));
    }

    #[test]
    fn relatime_skips_if_recent() {
        let now = 1_000_000_000_000;
        let atime = now - 1_000_000_000; // 1 second ago
        let mtime = atime - 1; // older than atime
        let ctime = atime - 1;
        assert!(!should_update_atime_relatime(atime, mtime, ctime, now));
    }

    #[test]
    fn relatime_exact_24h_is_update() {
        let now = RELATIME_24H_NS;
        assert!(should_update_atime_relatime(0, 0, 0, now));
    }

    // -- inode flags -------------------------------------------------------

    #[test]
    fn detects_immutable() {
        assert!(inode_is_immutable(FS_IMMUTABLE_FL));
        assert!(!inode_is_immutable(0));
        assert!(!inode_is_immutable(FS_APPEND_FL));
    }

    #[test]
    fn detects_append_only() {
        assert!(inode_is_append_only(FS_APPEND_FL));
        assert!(!inode_is_append_only(0));
    }

    #[test]
    fn detects_noatime() {
        assert!(inode_is_noatime(FS_NOATIME_FL));
        assert!(!inode_is_noatime(0));
    }

    #[test]
    fn flags_combine() {
        let flags = FS_IMMUTABLE_FL | FS_NOATIME_FL;
        assert!(inode_is_immutable(flags));
        assert!(!inode_is_append_only(flags));
        assert!(inode_is_noatime(flags));
    }

    // -- determinism -------------------------------------------------------

    #[test]
    fn permission_evaluation_is_deterministic() {
        let mode = 0o750;
        let a = posix_perm_bits_for_caller(mode, 1000, 100, 2000, 100, &[300]);
        let b = posix_perm_bits_for_caller(mode, 1000, 100, 2000, 100, &[300]);
        assert_eq!(a, b);
    }

    #[test]
    fn chmod_sanitize_is_deterministic() {
        let old = S_IFREG | 0o644;
        let (a, _) = chmod_sanitize_mode_unprivileged(old, 0o600, 1000, 1000);
        let (b, _) = chmod_sanitize_mode_unprivileged(old, 0o600, 1000, 1000);
        assert_eq!(a, b);
    }

    // -- enforcement guards ------------------------------------------------

    #[test]
    fn immutable_guard_rejects_immutable_file() {
        assert_eq!(enforce_immutable_guard(FS_IMMUTABLE_FL), Err(Errno::EPERM));
    }

    #[test]
    fn immutable_guard_allows_normal_file() {
        assert_eq!(enforce_immutable_guard(0), Ok(()));
    }

    #[test]
    fn immutable_guard_allows_append_only_not_immutable() {
        assert_eq!(enforce_immutable_guard(FS_APPEND_FL), Ok(()));
    }

    #[test]
    fn immutable_guard_allows_noatime_only() {
        assert_eq!(enforce_immutable_guard(FS_NOATIME_FL), Ok(()));
    }

    #[test]
    fn immutable_guard_rejects_combined_flags_with_immutable() {
        assert_eq!(
            enforce_immutable_guard(FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NOATIME_FL),
            Err(Errno::EPERM)
        );
    }

    #[test]
    fn append_only_guard_rejects_non_eof_write() {
        assert_eq!(
            enforce_append_only_write_guard(FS_APPEND_FL, false),
            Err(Errno::EPERM)
        );
    }

    #[test]
    fn append_only_guard_allows_eof_write() {
        assert_eq!(enforce_append_only_write_guard(FS_APPEND_FL, true), Ok(()));
    }

    #[test]
    fn append_only_guard_allows_normal_file_at_any_offset() {
        assert_eq!(enforce_append_only_write_guard(0, false), Ok(()));
        assert_eq!(enforce_append_only_write_guard(0, true), Ok(()));
    }

    #[test]
    fn append_only_guard_allows_noatime_only_write() {
        assert_eq!(
            enforce_append_only_write_guard(FS_NOATIME_FL, false),
            Ok(())
        );
    }

    #[test]
    fn append_only_guard_immutable_but_not_append_only_allows_write() {
        // Immutable is a separate check; append-only guard only cares about FS_APPEND_FL
        assert_eq!(
            enforce_append_only_write_guard(FS_IMMUTABLE_FL, false),
            Ok(())
        );
    }

    #[test]
    fn enforcement_guard_composition_immutable_then_append_only() {
        // Typical call order: immutable first, then append-only for writes
        let flags = FS_IMMUTABLE_FL | FS_APPEND_FL;
        assert_eq!(enforce_immutable_guard(flags), Err(Errno::EPERM));
        // If immutable check passed, append-only check works
        let flags = FS_APPEND_FL;
        assert_eq!(enforce_immutable_guard(flags), Ok(()));
        assert_eq!(
            enforce_append_only_write_guard(flags, false),
            Err(Errno::EPERM)
        );
    }
}
