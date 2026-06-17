//! FUSE `open` handler helpers — open-flag validation, file-handle
//! lifecycle planning, and convenience entry-points for POSIX-compliant
//! file open.
//!
//! Provides:
//! - [`OpenError`]: typed error with errno translation for open(2)
//!   rejection paths.
//! - [`validate_open_flags`]: reject invalid access-mode bit patterns
//!   and unsupported flag combinations in the FUSE open flags word.
//! - [`plan_open`]: validated classification of open intent —
//!   access mode, truncation, append, direct-I/O — returning a
//!   structured [`OpenPlan`] plus FUSE reply flags.
//! - [`check_open_file_type`]: reject directories and special files
//!   that should not be opened with a regular file open.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::open;
//!
//! let plan = open::plan_open(open_flags)?;
//! // plan.access_mode, plan.truncate, plan.append, plan.direct_io
//! // plan.reply_flags contains kernel cache flags.
//! ```

use crate::errno;
use libc::c_int;
use std::fmt;

// ── FUSE open-flag and reply-flag constants ──────────────────────────────

/// Mask for access-mode bits in Linux open flags.
pub const O_ACCMODE: u32 = 0o3;
/// Read-only access.
pub const O_RDONLY: u32 = 0;
/// Write-only access.
pub const O_WRONLY: u32 = 1;
/// Read-write access.
pub const O_RDWR: u32 = 2;
/// Append on every write.
pub const O_APPEND: u32 = 0o2000;
/// Truncate to zero length.
pub const O_TRUNC: u32 = 0o1000;
/// Direct I/O (bypass kernel page cache).
pub const O_DIRECT: u32 = 0o40000;

/// FUSE reply flag: bypass kernel page cache (direct I/O).
pub const FOPEN_DIRECT_IO: u32 = 1 << 0;
/// FUSE reply flag: keep file cache on close.
pub const FOPEN_KEEP_CACHE: u32 = 1 << 1;
/// FUSE reply flag: file is not seekable.
pub const FOPEN_NONSEEKABLE: u32 = 1 << 2;

// ── OpenPlan — validated open-intent ─────────────────────────────────────

/// Result of validating and classifying an open request.
///
/// The caller uses these fields to decide what engine operations to
/// perform (truncate before open, enforce append, etc.) and what FUSE
/// reply flags to return to the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenPlan {
    /// Cleaned-up access mode: one of [`O_RDONLY`], [`O_WRONLY`], [`O_RDWR`].
    pub access_mode: u32,
    /// `true` when `O_TRUNC` was set and the open is writable.
    pub truncate: bool,
    /// `true` when `O_APPEND` was set and the file is not truncated.
    pub append: bool,
    /// `true` when `O_DIRECT` was requested.
    pub direct_io: bool,
    /// FUSE reply flags for kernel cache coherence.
    pub reply_flags: u32,
}

// ── OpenError — domain error type for open(2) operations ─────────────────

/// Errors that can occur during open-flag validation or file-type checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// The access-mode bits in `open_flags` are invalid (e.g., value 3
    /// which is not a valid O_RDONLY/O_WRONLY/O_RDWR combination).
    InvalidAccessMode,
    /// The target inode is a directory; use opendir instead.
    IsDirectory,
    /// The target inode is a non-file type (symlink, socket, FIFO, etc.)
    /// that should not be opened as a regular file.
    NotAFile,
    /// The file-handle table is exhausted.
    NoFileDescriptors,
    /// Caller lacks permission to open the file with the requested
    /// access mode (read/write).
    PermissionDenied,
    /// Internal I/O error.
    Io,
}

impl OpenError {
    /// Convert this error to the matching POSIX errno value.
    #[must_use]
    pub fn to_errno(self) -> c_int {
        match self {
            OpenError::InvalidAccessMode => errno::EINVAL,
            OpenError::IsDirectory => errno::EISDIR,
            OpenError::NotAFile => errno::ENXIO,
            OpenError::NoFileDescriptors => errno::ENFILE,
            OpenError::PermissionDenied => errno::EACCES,
            OpenError::Io => errno::EIO,
        }
    }
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::InvalidAccessMode => write!(f, "invalid open access mode"),
            OpenError::IsDirectory => {
                write!(f, "cannot open a directory with open(2); use opendir")
            }
            OpenError::NotAFile => {
                write!(f, "cannot open this file type as a regular file")
            }
            OpenError::NoFileDescriptors => write!(f, "file-handle table exhausted"),
            OpenError::PermissionDenied => write!(f, "permission denied for open"),
            OpenError::Io => write!(f, "I/O error during open"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<OpenError> for c_int {
    fn from(e: OpenError) -> c_int {
        e.to_errno()
    }
}

// ── Open-flag validation ─────────────────────────────────────────────────

/// Validate the access-mode bits of FUSE open flags.
///
/// Returns `Err(`[`OpenError::InvalidAccessMode`]`)` when the low 2 bits
/// are 3 (an invalid O_ACCMODE combination on Linux).
///
/// Access-mode values 0 (O_RDONLY), 1 (O_WRONLY), and 2 (O_RDWR) are all
/// valid.  Other flag bits (O_TRUNC, O_APPEND, O_DIRECT, etc.) are not
/// checked here and are instead classified by [`plan_open`].
pub fn validate_open_flags(flags: u32) -> Result<(), OpenError> {
    match flags & O_ACCMODE {
        0..=2 => Ok(()),
        _ => Err(OpenError::InvalidAccessMode),
    }
}

/// Check that the target inode is a regular file (not a directory or
/// special file).
///
/// `is_dir` should be `true` for directories, `is_file` should be `true`
/// for regular files.  All other combinations return an error.
///
/// Returns `Err(`[`OpenError::IsDirectory`]`)` for directories and
/// `Err(`[`OpenError::NotAFile`]`)` for other non-file node kinds.
pub fn check_open_file_type(is_dir: bool, is_file: bool) -> Result<(), OpenError> {
    if is_dir {
        return Err(OpenError::IsDirectory);
    }
    if !is_file {
        return Err(OpenError::NotAFile);
    }
    Ok(())
}

/// Compute FUSE reply flags from Linux open flags.
///
/// - `O_DIRECT` → [`FOPEN_DIRECT_IO`]
/// - Otherwise → 0 (default kernel caching)
pub fn open_reply_flags(open_flags: u32) -> u32 {
    if (open_flags & O_DIRECT) != 0 {
        FOPEN_DIRECT_IO
    } else {
        0
    }
}

/// Check that the caller has permission to open the target file with
/// the requested access mode.
///
/// Wraps [`crate::access::check_fuse_access`] with [`OpenError`] mapping.
pub fn check_open_permission(
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    access_mode: u32,
    mount_identity: &tidefs_permission::MountIdentity,
) -> Result<(), OpenError> {
    let requested = crate::access::fuse_access_requested_from_mask(match access_mode as i32 {
        libc::O_RDONLY => libc::R_OK,
        libc::O_WRONLY => libc::W_OK,
        libc::O_RDWR => libc::R_OK | libc::W_OK,
        _ => return Err(OpenError::InvalidAccessMode),
    })
    .map_err(|_e| OpenError::InvalidAccessMode)?;

    crate::access::check_fuse_access(
        mode,
        file_uid,
        file_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        requested,
        mount_identity,
    )
    .map_err(|_e| OpenError::PermissionDenied)
}

// ── plan_open — validated open-intent ────────────────────────────────────

/// Validate open flags and classify the open intent.
///
/// On success returns [`OpenPlan`] with the classified intent and FUSE
/// reply flags.
///
/// # Rules enforced
///
/// - Access-mode must be valid (O_RDONLY/O_WRONLY/O_RDWR).
/// - `O_TRUNC` is only meaningful for writable opens (O_RDONLY|O_TRUNC
///   is ignored, not rejected — per POSIX).
/// - `O_APPEND` is only meaningful for writable opens without O_TRUNC.
/// - `O_DIRECT` produces FOPEN_DIRECT_IO reply flags.
pub fn plan_open(flags: u32) -> Result<OpenPlan, OpenError> {
    validate_open_flags(flags)?;

    let access_mode = flags & O_ACCMODE;
    let writable = access_mode == O_WRONLY || access_mode == O_RDWR;

    // O_TRUNC without write access is silently ignored (POSIX allows this).
    let truncate = writable && (flags & O_TRUNC) != 0;
    // O_APPEND is only meaningful when writing and not truncating.
    let append = writable && !truncate && (flags & O_APPEND) != 0;
    let direct_io = (flags & O_DIRECT) != 0;
    let reply_flags = open_reply_flags(flags);

    Ok(OpenPlan {
        access_mode,
        truncate,
        append,
        direct_io,
        reply_flags,
    })
}

// ── File-handle allocation and reply formatting ─────────────────────────

/// Allocate a file handle ID using a caller-provided counter.
///
/// Increments `next_handle_id` (a mutable u64 reference) and returns
/// the allocated handle.  If the counter overflows or wraps to 0,
/// returns [`OpenError::NoFileDescriptors`].
///
/// Handle 0 is reserved and will never be returned.
///
/// # Example
///
/// ```rust,ignore
/// let mut next_id = 1u64;
/// let fh = open::allocate_file_handle(&mut next_id)?;
/// ```
pub fn allocate_file_handle(next_handle_id: &mut u64) -> Result<u64, OpenError> {
    let id = *next_handle_id;
    if id == 0 {
        // 0 was already wrapped; refuse further allocations.
        return Err(OpenError::NoFileDescriptors);
    }
    *next_handle_id = next_handle_id.wrapping_add(1);
    if *next_handle_id == 0 {
        // Wrapped; next call will get NoFileDescriptors.
        *next_handle_id = 0;
    }
    Ok(id)
}

/// Format a FUSE open reply with an allocated file handle.
///
/// `fh` is the allocated file handle ID (must be non-zero).
/// `open_flags` are the FUSE open reply flags (e.g., [`FOPEN_DIRECT_IO`]).
///
/// Returns `Err(`[`OpenError::InvalidAccessMode`]`)` if `fh` is 0
/// (reserved).
pub fn format_open_reply(
    reply: crate::ReplyOpen,
    fh: u64,
    open_flags: u32,
) -> Result<(), OpenError> {
    if fh == 0 {
        return Err(OpenError::InvalidAccessMode);
    }
    reply.opened(fh, open_flags);
    Ok(())
}

// ── handle_open -- unified entry point ──────────────────────────────────

/// Unified entry point for FUSE open dispatch.
///
/// Validates open flags via [`plan_open`], checks the target file type
/// via [`check_open_file_type`], and verifies caller permissions via
/// [`check_open_permission`].  On success returns an [`OpenPlan`]
/// describing the validated open intent and FUSE reply flags.
///
/// The caller is responsible for allocating a file handle (via
/// [`allocate_file_handle`]) and formatting the FUSE reply (via
/// [`format_open_reply`]).
///
/// # Errors
///
/// Returns [`OpenError`] when flag validation, file-type checking,
/// or permission checks fail.
#[allow(clippy::too_many_arguments)]
pub fn handle_open(
    flags: u32,
    is_dir: bool,
    is_file: bool,
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
    mount_identity: &tidefs_permission::MountIdentity,
) -> Result<OpenPlan, OpenError> {
    let plan = plan_open(flags)?;
    check_open_file_type(is_dir, is_file)?;
    check_open_permission(
        mode,
        file_uid,
        file_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        plan.access_mode,
        mount_identity,
    )?;
    Ok(plan)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_MOUNT: tidefs_permission::MountIdentity =
        tidefs_permission::MountIdentity::new([0x41; 16], 1);

    // ── validate_open_flags ──────────────────────────────────────────────

    #[test]
    fn validate_rdonly_is_ok() {
        assert!(validate_open_flags(O_RDONLY).is_ok());
    }

    #[test]
    fn validate_wronly_is_ok() {
        assert!(validate_open_flags(O_WRONLY).is_ok());
    }

    #[test]
    fn validate_rdwr_is_ok() {
        assert!(validate_open_flags(O_RDWR).is_ok());
    }

    #[test]
    fn validate_access_mode_3_is_invalid() {
        assert_eq!(validate_open_flags(3), Err(OpenError::InvalidAccessMode));
    }

    #[test]
    fn validate_access_mode_7_is_invalid() {
        // Upper bits present but accmode = 7 & 3 = 3, invalid.
        assert_eq!(validate_open_flags(7), Err(OpenError::InvalidAccessMode));
    }

    #[test]
    fn validate_with_extra_flags_passes() {
        // O_RDWR | O_TRUNC | O_CREAT
        assert!(validate_open_flags(O_RDWR | O_TRUNC | 0o100).is_ok());
    }

    #[test]
    fn validate_with_append_passes() {
        assert!(validate_open_flags(O_RDWR | O_APPEND).is_ok());
    }

    #[test]
    fn validate_with_direct_passes() {
        assert!(validate_open_flags(O_RDONLY | O_DIRECT).is_ok());
    }

    #[test]
    fn validate_zero_is_rdonly() {
        // O_RDONLY is 0 on Linux
        assert!(validate_open_flags(0).is_ok());
    }

    // ── check_open_file_type ─────────────────────────────────────────────

    #[test]
    fn check_regular_file_passes() {
        assert!(check_open_file_type(false, true).is_ok());
    }

    #[test]
    fn check_dir_returns_is_directory() {
        assert_eq!(
            check_open_file_type(true, false),
            Err(OpenError::IsDirectory)
        );
    }

    #[test]
    fn check_non_file_returns_not_a_file() {
        // Neither dir nor file (e.g. symlink, socket, FIFO).
        assert_eq!(check_open_file_type(false, false), Err(OpenError::NotAFile));
    }

    #[test]
    fn check_dir_takes_priority_over_not_file() {
        // If somehow both flags are set, dir has priority.
        assert_eq!(
            check_open_file_type(true, true),
            Err(OpenError::IsDirectory)
        );
    }

    // ── plan_open ────────────────────────────────────────────────────────

    #[test]
    fn plan_rdonly_no_special_flags() {
        let plan = plan_open(O_RDONLY).unwrap();
        assert_eq!(plan.access_mode, O_RDONLY);
        assert!(!plan.truncate);
        assert!(!plan.append);
        assert!(!plan.direct_io);
        assert_eq!(plan.reply_flags, 0);
    }

    #[test]
    fn plan_wronly_basic() {
        let plan = plan_open(O_WRONLY).unwrap();
        assert_eq!(plan.access_mode, O_WRONLY);
        assert!(!plan.truncate);
        assert!(!plan.append);
        assert!(!plan.direct_io);
        assert_eq!(plan.reply_flags, 0);
    }

    #[test]
    fn plan_rdwr_basic() {
        let plan = plan_open(O_RDWR).unwrap();
        assert_eq!(plan.access_mode, O_RDWR);
        assert!(!plan.truncate);
        assert!(!plan.append);
    }

    #[test]
    fn plan_truncate_on_writable() {
        let plan = plan_open(O_WRONLY | O_TRUNC).unwrap();
        assert_eq!(plan.access_mode, O_WRONLY);
        assert!(plan.truncate);
        assert!(!plan.append);
    }

    #[test]
    fn plan_truncate_on_rdwr() {
        let plan = plan_open(O_RDWR | O_TRUNC).unwrap();
        assert!(plan.truncate);
    }

    #[test]
    fn plan_truncate_ignored_on_rdonly() {
        // POSIX: O_RDONLY|O_TRUNC is silently accepted but truncation
        // does not happen (access mode check catches it at engine level).
        let plan = plan_open(O_RDONLY | O_TRUNC).unwrap();
        assert_eq!(plan.access_mode, O_RDONLY);
        assert!(!plan.truncate);
    }

    #[test]
    fn plan_append_on_writable() {
        let plan = plan_open(O_WRONLY | O_APPEND).unwrap();
        assert_eq!(plan.access_mode, O_WRONLY);
        assert!(!plan.truncate);
        assert!(plan.append);
    }

    #[test]
    fn plan_append_on_rdwr() {
        let plan = plan_open(O_RDWR | O_APPEND).unwrap();
        assert!(plan.append);
    }

    #[test]
    fn plan_append_ignored_on_rdonly() {
        let plan = plan_open(O_RDONLY | O_APPEND).unwrap();
        assert!(!plan.append);
    }

    #[test]
    fn plan_truncate_overrides_append() {
        // O_TRUNC|O_APPEND on writable: truncate wins.
        let plan = plan_open(O_WRONLY | O_TRUNC | O_APPEND).unwrap();
        assert!(plan.truncate);
        assert!(!plan.append);
    }

    #[test]
    fn plan_direct_io() {
        let plan = plan_open(O_RDWR | O_DIRECT).unwrap();
        assert!(plan.direct_io);
        assert_eq!(plan.reply_flags, FOPEN_DIRECT_IO);
    }

    #[test]
    fn plan_direct_io_rdonly() {
        let plan = plan_open(O_RDONLY | O_DIRECT).unwrap();
        assert!(plan.direct_io);
        assert_eq!(plan.reply_flags, FOPEN_DIRECT_IO);
    }

    #[test]
    fn plan_all_flags_combined() {
        let plan = plan_open(O_RDWR | O_TRUNC | O_DIRECT).unwrap();
        assert_eq!(plan.access_mode, O_RDWR);
        assert!(plan.truncate);
        assert!(!plan.append);
        assert!(plan.direct_io);
        assert_eq!(plan.reply_flags, FOPEN_DIRECT_IO);
    }

    #[test]
    fn plan_invalid_access_mode_fails() {
        assert!(plan_open(3).is_err());
    }

    // ── OpenError errno mapping ─────────────────────────────────────────

    #[test]
    fn open_error_is_dir_maps_to_eisdir() {
        assert_eq!(OpenError::IsDirectory.to_errno(), errno::EISDIR);
    }

    #[test]
    fn open_error_invalid_access_mode_maps_to_einval() {
        assert_eq!(OpenError::InvalidAccessMode.to_errno(), errno::EINVAL);
    }

    #[test]
    fn open_error_not_a_file_maps_to_enxio() {
        assert_eq!(OpenError::NotAFile.to_errno(), errno::ENXIO);
    }

    #[test]
    fn open_error_no_file_descriptors_maps_to_enfile() {
        assert_eq!(OpenError::NoFileDescriptors.to_errno(), errno::ENFILE);
    }

    #[test]
    fn open_error_permission_denied_maps_to_eacces() {
        assert_eq!(OpenError::PermissionDenied.to_errno(), errno::EACCES);
    }

    #[test]
    fn open_error_io_maps_to_eio() {
        assert_eq!(OpenError::Io.to_errno(), errno::EIO);
    }

    // ── OpenError Display ────────────────────────────────────────────────

    #[test]
    fn open_error_display_is_not_empty() {
        let errors = [
            OpenError::InvalidAccessMode,
            OpenError::IsDirectory,
            OpenError::NotAFile,
            OpenError::NoFileDescriptors,
            OpenError::PermissionDenied,
            OpenError::Io,
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(!s.is_empty(), "{}", "Display empty for {e:?}");
        }
    }

    // ── OpenError From<OpenError> for c_int ──────────────────────────────

    #[test]
    fn from_open_error_for_c_int() {
        let e: c_int = OpenError::IsDirectory.into();
        assert_eq!(e, errno::EISDIR);
    }

    // ── OpenPlan Copy + Eq ───────────────────────────────────────────────

    #[test]
    fn open_plan_is_copy_and_eq() {
        let a = plan_open(O_RDWR | O_TRUNC).unwrap();
        let b = a;
        assert_eq!(a, b);
    }

    // ── reply flag edge cases ────────────────────────────────────────────

    #[test]
    fn reply_flags_no_direct() {
        assert_eq!(open_reply_flags(O_RDONLY), 0);
        assert_eq!(open_reply_flags(O_WRONLY | O_APPEND), 0);
    }

    #[test]
    fn reply_flags_direct() {
        assert_eq!(open_reply_flags(O_RDWR | O_DIRECT), FOPEN_DIRECT_IO);
    }

    // ── Constants are coherent ───────────────────────────────────────────

    #[test]
    fn constants_are_non_overlapping() {
        // Access mode mask only captures bits 0-1.
        assert_eq!(O_ACCMODE, 0o3);
        // FUSE reply flags are single bits.
        assert_eq!(FOPEN_DIRECT_IO & FOPEN_KEEP_CACHE, 0);
        assert_eq!(FOPEN_DIRECT_IO & FOPEN_NONSEEKABLE, 0);
        assert_eq!(FOPEN_KEEP_CACHE & FOPEN_NONSEEKABLE, 0);
    }
    // ── allocate_file_handle ─────────────────────────────────────────

    #[test]
    fn allocate_file_handle_returns_sequential_ids() {
        let mut next = 1u64;
        let fh1 = allocate_file_handle(&mut next).unwrap();
        let fh2 = allocate_file_handle(&mut next).unwrap();
        assert_eq!(fh1, 1);
        assert_eq!(fh2, 2);
        assert_eq!(next, 3);
    }

    #[test]
    fn allocate_file_handle_refuses_zero_counter() {
        let mut next = 0u64;
        assert_eq!(
            allocate_file_handle(&mut next),
            Err(OpenError::NoFileDescriptors)
        );
    }

    #[test]
    fn allocate_file_handle_wraps_to_zero_then_refuses() {
        let mut next = u64::MAX;
        let fh = allocate_file_handle(&mut next).unwrap();
        assert_eq!(fh, u64::MAX);
        // next now wraps to 0
        assert_eq!(next, 0);
        assert_eq!(
            allocate_file_handle(&mut next),
            Err(OpenError::NoFileDescriptors)
        );
    }

    // ── format_open_reply ────────────────────────────────────────────

    #[test]
    fn format_open_reply_rejects_fh_zero() {
        // We can't easily test the success path without a real session,
        // but we test the fh==0 guard.
        // SAFETY: ReplyOpen is a repr(C) struct backed by integers; zero
        // is a valid bit pattern for all fields. This is a test helper
        // constructing a deliberately zeroed reply to exercise guard paths.
        // SAFETY: ReplyOpen is a repr(C) struct of integers; zero is a valid
        // bit pattern for all fields. This is a test helper deliberately
        // zeroing the struct to exercise the fh==0 guard path below.
        let reply: crate::ReplyOpen = unsafe { std::mem::zeroed() };
        assert_eq!(
            format_open_reply(reply, 0, 0),
            Err(OpenError::InvalidAccessMode)
        );
    }

    // ── handle_open ──────────────────────────────────────────────────

    #[test]
    fn handle_open_rdonly_file_success() {
        let plan = handle_open(
            O_RDONLY,
            false,
            true,
            0o644,
            1000,
            1000,
            1000,
            1000,
            &[],
            &VALID_MOUNT,
        )
        .unwrap();
        assert_eq!(plan.access_mode, O_RDONLY);
        assert!(!plan.truncate);
    }

    #[test]
    fn handle_open_wronly_trunc_success() {
        let plan = handle_open(
            O_WRONLY | O_TRUNC,
            false,
            true,
            0o644,
            1000,
            1000,
            1000,
            1000,
            &[],
            &VALID_MOUNT,
        )
        .unwrap();
        assert_eq!(plan.access_mode, O_WRONLY);
        assert!(plan.truncate);
    }

    #[test]
    fn handle_open_rdwr_append_success() {
        let plan = handle_open(
            O_RDWR | O_APPEND,
            false,
            true,
            0o644,
            1000,
            1000,
            1000,
            1000,
            &[],
            &VALID_MOUNT,
        )
        .unwrap();
        assert_eq!(plan.access_mode, O_RDWR);
        assert!(plan.append);
    }

    #[test]
    fn handle_open_rejects_directory() {
        let err = handle_open(
            O_RDONLY,
            true,
            false,
            0o755,
            1000,
            1000,
            1000,
            1000,
            &[],
            &VALID_MOUNT,
        )
        .unwrap_err();
        assert_eq!(err, OpenError::IsDirectory);
    }

    #[test]
    fn handle_open_rejects_non_file() {
        let err = handle_open(
            O_RDONLY,
            false,
            false,
            0o644,
            1000,
            1000,
            1000,
            1000,
            &[],
            &VALID_MOUNT,
        )
        .unwrap_err();
        assert_eq!(err, OpenError::NotAFile);
    }

    #[test]
    fn handle_open_direct_io_sets_reply_flags() {
        let plan = handle_open(
            O_RDWR | O_DIRECT,
            false,
            true,
            0o644,
            1000,
            1000,
            1000,
            1000,
            &[],
            &VALID_MOUNT,
        )
        .unwrap();
        assert_eq!(plan.reply_flags, FOPEN_DIRECT_IO);
        assert!(plan.direct_io);
    }
}
