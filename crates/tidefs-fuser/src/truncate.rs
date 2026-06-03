//! FUSE `truncate` / `ftruncate` handler helpers.
//!
//! Provides:
//! - [`TruncateMode`]: enum distinguishing between path-based truncate(2)
//!   and fd-based ftruncate(2).
//! - [`TruncatePlan`]: structured plan for a truncate operation with
//!   mode, target size, and optional file handle.
//! - [`validate_truncate_size`]: bounds-check the requested size against
//!   reasonable filesystem limits.
//! - [`plan_truncate`]: construct a [`TruncatePlan`] from mode and size.
//! - [`check_truncate_allowed`]: validate that a truncate operation is
//!   applicable to the given file kind (reject directories, pipes, sockets,
//!   and symlinks).
//! - Re-exported POSIX errno codes relevant to the truncate path.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::truncate;
//!
//! let plan = truncate::plan_truncate(
//!     truncate::TruncateMode::Ftruncate,
//!     4096,
//!     0,
//! );
//! truncate::validate_truncate_size(4096)?;
//! truncate::check_truncate_allowed(file_kind)?;
//! // ... perform back-end truncate via engine or daemon ...
//! ```

use crate::errno;
use libc::c_int;

use crate::FileType;

// ---------------------------------------------------------------------------
// Re-exports: standard errno codes for truncate error paths
// ---------------------------------------------------------------------------

pub use libc::{EBADF, EFBIG, EINTR, EINVAL, EIO, EISDIR, ENOTDIR, EPERM, EROFS};

// ---------------------------------------------------------------------------
// TruncateMode -- path-based vs fd-based truncate
// ---------------------------------------------------------------------------

/// Classifies a truncate operation by its invocation mode.
///
/// - [`TruncateMode::Truncate`]: path-based truncate(2) — the kernel
///   resolves the path and sends a FUSE `setattr` with `FATTR_SIZE` and
///   no file handle. The filesystem must look up the inode by path.
/// - [`TruncateMode::Ftruncate`]: fd-based ftruncate(2) — the kernel
///   sends a FUSE `setattr` with `FATTR_SIZE` and a valid file handle.
///   The filesystem can use the handle for direct extent manipulation.
///   Check that the caller has write permission on the target inode
///   for a truncate operation.
///
/// Wraps [`crate::access::check_fuse_access`] requesting
/// [`crate::access::ACCESS_WRITE`].
pub fn check_truncate_permission(
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    caller_groups: &[u32],
) -> Result<(), c_int> {
    crate::access::check_fuse_access(
        mode,
        file_uid,
        file_gid,
        caller_uid,
        caller_gid,
        caller_groups,
        crate::access::ACCESS_WRITE,
    )
}

/// Truncation mode: path-based (`truncate(2)`) or file-descriptor-based
/// (`ftruncate(2)`).  The mode determines whether the filesystem resolves
/// the inode via a path or uses an already-open file descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TruncateMode {
    /// Path-based truncate (truncate(2)).
    Truncate,
    /// File-descriptor-based truncate (ftruncate(2)).
    Ftruncate,
}

impl TruncateMode {
    /// Returns `true` when the operation is path-based.
    #[must_use]
    pub const fn is_path_based(self) -> bool {
        matches!(self, Self::Truncate)
    }

    /// Returns `true` when the operation is fd-based.
    #[must_use]
    pub const fn is_fd_based(self) -> bool {
        matches!(self, Self::Ftruncate)
    }
}

// ---------------------------------------------------------------------------
// TruncatePlan -- structured truncate request
// ---------------------------------------------------------------------------

/// Planned truncate operation derived from FUSE `setattr` (with `FATTR_SIZE`)
/// or a standalone `ftruncate` dispatch.
///
/// The plan carries the operation mode, the target file size in bytes,
/// and the optional file handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TruncatePlan {
    /// Whether this is path-based or fd-based.
    pub mode: TruncateMode,
    /// Target file size in bytes.
    pub size: u64,
    /// Optional file handle (present for ftruncate, absent for truncate).
    pub fh: Option<u64>,
}

impl TruncatePlan {
    /// Create a new truncate plan.
    #[must_use]
    pub const fn new(mode: TruncateMode, size: u64, fh: Option<u64>) -> Self {
        Self { mode, size, fh }
    }

    /// Returns `true` when the truncate is a shrink (new size < current size).
    #[must_use]
    pub const fn is_shrink(&self, current_size: u64) -> bool {
        self.size < current_size
    }

    /// Returns `true` when the truncate is an extend (new size > current size).
    #[must_use]
    pub const fn is_extend(&self, current_size: u64) -> bool {
        self.size > current_size
    }

    /// Returns the number of bytes to deallocate when shrinking.
    #[must_use]
    pub const fn shrink_bytes(&self, current_size: u64) -> u64 {
        current_size.saturating_sub(self.size)
    }

    /// Returns the number of zero-fill bytes when extending.
    #[must_use]
    pub const fn extend_bytes(&self, current_size: u64) -> u64 {
        self.size.saturating_sub(current_size)
    }

    /// Returns `true` when the truncate is a no-op (size unchanged).
    #[must_use]
    pub const fn is_noop(&self, current_size: u64) -> bool {
        self.size == current_size
    }
}

// ---------------------------------------------------------------------------
// Maximum reasonable file size (off_t limit)
// ---------------------------------------------------------------------------

/// Maximum file size accepted for truncate operations (8 EiB - 1).
///
/// This matches the Linux off_t limit for a 64-bit signed offset,
/// preventing overflow in extent-map calculations.
pub const MAX_TRUNCATE_SIZE: u64 = i64::MAX as u64;

// ---------------------------------------------------------------------------
// validate_truncate_size
// ---------------------------------------------------------------------------

/// Validate a requested truncate size against filesystem limits.
///
/// # Returns
///
/// `Ok(())` when the size is within acceptable bounds.
///
/// `Err(EFBIG)` when the size exceeds [`MAX_TRUNCATE_SIZE`].
///
/// `Err(EINVAL)` when the size is zero but the call semantics indicate
/// an invalid request (e.g., negative size, which would already be
/// rejected by the FUSE layer).
#[inline]
pub fn validate_truncate_size(size: u64) -> Result<(), c_int> {
    if size > MAX_TRUNCATE_SIZE {
        return Err(errno::EFBIG);
    }
    // size == 0 is always valid (empty file).
    Ok(())
}

// ---------------------------------------------------------------------------
// plan_truncate
// ---------------------------------------------------------------------------

/// Construct a [`TruncatePlan`] from the operation mode and target size.
///
/// The `fh` parameter is `Some(handle)` for ftruncate and `None` for
/// path-based truncate. When `fh` is `Some(0)`, it is treated as `None`
/// (no valid handle).
#[must_use]
pub fn plan_truncate(mode: TruncateMode, size: u64, fh: u64) -> TruncatePlan {
    let fh_opt = match mode {
        TruncateMode::Truncate => None,
        TruncateMode::Ftruncate => {
            if fh == 0 {
                None
            } else {
                Some(fh)
            }
        }
    };
    TruncatePlan::new(mode, size, fh_opt)
}

// ---------------------------------------------------------------------------
// classify_truncate_mode -- derive mode from setattr parameters
// ---------------------------------------------------------------------------

/// Classify a truncate operation as path-based or fd-based from the raw
/// FUSE `setattr` parameters.
///
/// When a valid file handle (`fh != 0`) is present, the operation is
/// [`TruncateMode::Ftruncate`]; otherwise it is
/// [`TruncateMode::Truncate`].
///
/// This function is a convenience for callers that receive the full
/// `setattr` parameter set and need to route to the correct dispatch.
#[must_use]
pub fn classify_truncate_mode(fh: Option<u64>, has_size: bool) -> Option<TruncateMode> {
    if !has_size {
        return None;
    }
    match fh {
        Some(fh) if fh != 0 => Some(TruncateMode::Ftruncate),
        _ => Some(TruncateMode::Truncate),
    }
}

// ---------------------------------------------------------------------------
// check_truncate_allowed -- file-kind validation
// ---------------------------------------------------------------------------

/// Check whether a truncate operation is allowed for the given [`FileType`].
///
/// # Returns
///
/// `Ok(())` for regular files and block devices.
///
/// `Err(EISDIR)` for directories (POSIX: truncate on a directory returns
/// `EISDIR`).
///
/// `Err(EINVAL)` for named pipes, Unix domain sockets, character devices,
/// and symbolic links.
///
/// # Rationale
///
/// Per POSIX, ftruncate(2) on a directory returns `EISDIR`, and on a pipe
/// or socket returns `EINVAL`. Symbolic links are resolved by the kernel
/// before the FUSE handler is invoked, so they should not appear here in
/// practice, but the guard is included for defense in depth.
#[inline]
pub fn check_truncate_allowed(kind: FileType) -> Result<(), c_int> {
    match kind {
        FileType::RegularFile | FileType::BlockDevice => Ok(()),
        FileType::Directory => Err(errno::EISDIR),
        FileType::NamedPipe | FileType::Socket | FileType::CharDevice | FileType::Symlink => {
            Err(errno::EINVAL)
        }
    }
}

// ---------------------------------------------------------------------------
// check_truncate_readonly -- read-only mount guard
// ---------------------------------------------------------------------------

/// Check whether a truncate operation is permitted on a read-only filesystem.
///
/// When `read_only` is `true`, any truncate is rejected with `EROFS`.
///
/// # Returns
///
/// `Ok(())` when the operation is allowed; `Err(EROFS)` otherwise.
#[inline]
pub fn check_truncate_readonly(read_only: bool) -> Result<(), c_int> {
    if read_only {
        Err(errno::EROFS)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// handle_truncate -- canonical FUSE dispatch entry point
// ---------------------------------------------------------------------------

/// Canonical FUSE dispatch entry point for truncate (opcode 41 / setattr with
/// `FATTR_SIZE`).
///
/// Wraps [`check_truncate_readonly`], [`check_truncate_allowed`],
/// [`validate_truncate_size`], and [`plan_truncate`] into a single call
/// matching the established `handle_*` pattern. All validation is delegated
/// to the existing helpers.
///
/// Returns `Ok(`[`TruncatePlan`]`)` on success. On failure returns a FUSE
/// errno.
///
/// # Errors
///
/// Returns `EROFS` for read-only mounts, `EISDIR` for directories, `EINVAL`
/// for invalid file kinds (pipes, sockets, etc.), and `EFBIG` for oversized
/// requests.
#[inline]
pub fn handle_truncate(
    kind: FileType,
    mode: TruncateMode,
    size: u64,
    fh: u64,
    read_only: bool,
) -> Result<TruncatePlan, c_int> {
    check_truncate_readonly(read_only)?;
    check_truncate_allowed(kind)?;
    validate_truncate_size(size)?;
    Ok(plan_truncate(mode, size, fh))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- TruncateMode -----------------------------------------------------

    #[test]
    fn truncate_mode_is_path_based() {
        assert!(TruncateMode::Truncate.is_path_based());
        assert!(!TruncateMode::Truncate.is_fd_based());
    }

    #[test]
    fn truncate_mode_is_fd_based() {
        assert!(TruncateMode::Ftruncate.is_fd_based());
        assert!(!TruncateMode::Ftruncate.is_path_based());
    }

    // -- TruncatePlan -----------------------------------------------------

    #[test]
    fn truncate_plan_new_path_based() {
        let plan = TruncatePlan::new(TruncateMode::Truncate, 1024, None);
        assert_eq!(plan.mode, TruncateMode::Truncate);
        assert_eq!(plan.size, 1024);
        assert_eq!(plan.fh, None);
    }

    #[test]
    fn truncate_plan_new_fd_based() {
        let plan = TruncatePlan::new(TruncateMode::Ftruncate, 4096, Some(42));
        assert_eq!(plan.mode, TruncateMode::Ftruncate);
        assert_eq!(plan.size, 4096);
        assert_eq!(plan.fh, Some(42));
    }

    #[test]
    fn truncate_plan_is_shrink() {
        let plan = TruncatePlan::new(TruncateMode::Ftruncate, 100, None);
        assert!(plan.is_shrink(1024));
        assert!(!plan.is_extend(1024));
        assert!(!plan.is_noop(1024));
    }

    #[test]
    fn truncate_plan_is_extend() {
        let plan = TruncatePlan::new(TruncateMode::Ftruncate, 8192, None);
        assert!(!plan.is_shrink(1024));
        assert!(plan.is_extend(1024));
        assert!(!plan.is_noop(1024));
    }

    #[test]
    fn truncate_plan_is_noop() {
        let plan = TruncatePlan::new(TruncateMode::Ftruncate, 1024, None);
        assert!(!plan.is_shrink(1024));
        assert!(!plan.is_extend(1024));
        assert!(plan.is_noop(1024));
    }

    #[test]
    fn truncate_plan_shrink_bytes() {
        let plan = TruncatePlan::new(TruncateMode::Ftruncate, 500, None);
        assert_eq!(plan.shrink_bytes(1024), 524);
        assert_eq!(plan.shrink_bytes(500), 0);
        assert_eq!(plan.shrink_bytes(100), 0);
    }

    #[test]
    fn truncate_plan_extend_bytes() {
        let plan = TruncatePlan::new(TruncateMode::Ftruncate, 2048, None);
        assert_eq!(plan.extend_bytes(1024), 1024);
        assert_eq!(plan.extend_bytes(2048), 0);
        assert_eq!(plan.extend_bytes(4096), 0);
    }

    #[test]
    fn truncate_plan_zero_size() {
        let plan = TruncatePlan::new(TruncateMode::Ftruncate, 0, None);
        assert!(plan.is_shrink(1024));
        assert_eq!(plan.shrink_bytes(1024), 1024);
        assert_eq!(plan.extend_bytes(1024), 0);
    }

    // -- validate_truncate_size -------------------------------------------

    #[test]
    fn validate_size_zero_is_ok() {
        assert_eq!(validate_truncate_size(0), Ok(()));
    }

    #[test]
    fn validate_size_small_is_ok() {
        assert_eq!(validate_truncate_size(1), Ok(()));
        assert_eq!(validate_truncate_size(4096), Ok(()));
        assert_eq!(validate_truncate_size(1_u64 << 30), Ok(()));
    }

    #[test]
    fn validate_size_at_max_is_ok() {
        assert_eq!(validate_truncate_size(MAX_TRUNCATE_SIZE), Ok(()));
    }

    #[test]
    fn validate_size_exceeds_max_returns_efbig() {
        // MAX_TRUNCATE_SIZE + 1 overflows the u64? Actually it doesn't
        // because MAX_TRUNCATE_SIZE = i64::MAX which is 2^63-1, so +1 = 2^63.
        // Still valid u64, but exceeds our policy.
        let oversize = MAX_TRUNCATE_SIZE + 1;
        assert_eq!(validate_truncate_size(oversize), Err(errno::EFBIG));
    }

    #[test]
    fn validate_size_u64_max_returns_efbig() {
        assert_eq!(validate_truncate_size(u64::MAX), Err(errno::EFBIG));
    }

    // -- plan_truncate ----------------------------------------------------

    #[test]
    fn plan_truncate_path_based_ignores_fh() {
        let plan = plan_truncate(TruncateMode::Truncate, 1024, 42);
        assert_eq!(plan.mode, TruncateMode::Truncate);
        assert_eq!(plan.size, 1024);
        assert_eq!(plan.fh, None);
    }

    #[test]
    fn plan_truncate_fd_based_uses_fh() {
        let plan = plan_truncate(TruncateMode::Ftruncate, 2048, 7);
        assert_eq!(plan.mode, TruncateMode::Ftruncate);
        assert_eq!(plan.size, 2048);
        assert_eq!(plan.fh, Some(7));
    }

    #[test]
    fn plan_truncate_fd_based_zero_fh_treated_as_none() {
        let plan = plan_truncate(TruncateMode::Ftruncate, 2048, 0);
        assert_eq!(plan.mode, TruncateMode::Ftruncate);
        assert_eq!(plan.size, 2048);
        assert_eq!(plan.fh, None);
    }

    // -- classify_truncate_mode -------------------------------------------

    #[test]
    fn classify_no_size_returns_none() {
        assert_eq!(classify_truncate_mode(Some(5), false), None);
        assert_eq!(classify_truncate_mode(None, false), None);
    }

    #[test]
    fn classify_with_valid_fh_returns_ftruncate() {
        assert_eq!(
            classify_truncate_mode(Some(42), true),
            Some(TruncateMode::Ftruncate)
        );
    }

    #[test]
    fn classify_with_zero_fh_returns_truncate() {
        assert_eq!(
            classify_truncate_mode(Some(0), true),
            Some(TruncateMode::Truncate)
        );
    }

    #[test]
    fn classify_with_none_fh_returns_truncate() {
        assert_eq!(
            classify_truncate_mode(None, true),
            Some(TruncateMode::Truncate)
        );
    }

    // -- check_truncate_allowed -------------------------------------------

    #[test]
    fn truncate_allowed_on_regular_file() {
        assert_eq!(check_truncate_allowed(FileType::RegularFile), Ok(()));
    }

    #[test]
    fn truncate_allowed_on_block_device() {
        assert_eq!(check_truncate_allowed(FileType::BlockDevice), Ok(()));
    }

    #[test]
    fn truncate_denied_on_directory() {
        assert_eq!(
            check_truncate_allowed(FileType::Directory),
            Err(errno::EISDIR)
        );
    }

    #[test]
    fn truncate_denied_on_named_pipe() {
        assert_eq!(
            check_truncate_allowed(FileType::NamedPipe),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn truncate_denied_on_socket() {
        assert_eq!(check_truncate_allowed(FileType::Socket), Err(errno::EINVAL));
    }

    #[test]
    fn truncate_denied_on_char_device() {
        assert_eq!(
            check_truncate_allowed(FileType::CharDevice),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn truncate_denied_on_symlink() {
        assert_eq!(
            check_truncate_allowed(FileType::Symlink),
            Err(errno::EINVAL)
        );
    }

    // -- check_truncate_readonly ------------------------------------------

    #[test]
    fn ro_mount_rejects_truncate() {
        assert_eq!(check_truncate_readonly(true), Err(errno::EROFS));
    }

    #[test]
    fn rw_mount_allows_truncate() {
        assert_eq!(check_truncate_readonly(false), Ok(()));
    }

    // -- integration: plan + validate + check pattern ---------------------

    #[test]
    fn valid_truncate_passes_all_checks() {
        let plan = plan_truncate(TruncateMode::Ftruncate, 4096, 3);
        assert!(validate_truncate_size(plan.size).is_ok());
        assert!(check_truncate_allowed(FileType::RegularFile).is_ok());
        assert!(check_truncate_readonly(false).is_ok());
        assert_eq!(plan.fh, Some(3));
    }

    #[test]
    fn extend_truncate_passes_checks() {
        let plan = plan_truncate(TruncateMode::Truncate, 65536, 0);
        assert!(validate_truncate_size(plan.size).is_ok());
        assert!(check_truncate_allowed(FileType::RegularFile).is_ok());
        assert_eq!(plan.mode, TruncateMode::Truncate);
    }

    #[test]
    fn zero_truncate_passes_checks() {
        let plan = plan_truncate(TruncateMode::Ftruncate, 0, 99);
        assert!(validate_truncate_size(plan.size).is_ok());
        assert!(check_truncate_allowed(FileType::RegularFile).is_ok());
        assert_eq!(plan.size, 0);
    }

    // -- handle_truncate --------------------------------------------------

    #[test]
    fn handle_truncate_regular_file_success() {
        let plan = handle_truncate(
            FileType::RegularFile,
            TruncateMode::Ftruncate,
            4096,
            42,
            false,
        );
        assert_eq!(
            plan,
            Ok(TruncatePlan::new(TruncateMode::Ftruncate, 4096, Some(42)))
        );
    }

    #[test]
    fn handle_truncate_block_device_success() {
        let plan = handle_truncate(
            FileType::BlockDevice,
            TruncateMode::Ftruncate,
            8192,
            7,
            false,
        );
        assert_eq!(
            plan,
            Ok(TruncatePlan::new(TruncateMode::Ftruncate, 8192, Some(7)))
        );
    }

    #[test]
    fn handle_truncate_directory_rejected() {
        assert_eq!(
            handle_truncate(FileType::Directory, TruncateMode::Truncate, 0, 0, false),
            Err(errno::EISDIR)
        );
    }

    #[test]
    fn handle_truncate_pipe_rejected() {
        assert_eq!(
            handle_truncate(FileType::NamedPipe, TruncateMode::Truncate, 100, 0, false),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn handle_truncate_socket_rejected() {
        assert_eq!(
            handle_truncate(FileType::Socket, TruncateMode::Truncate, 200, 0, false),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn handle_truncate_read_only_rejected() {
        assert_eq!(
            handle_truncate(
                FileType::RegularFile,
                TruncateMode::Ftruncate,
                4096,
                1,
                true
            ),
            Err(errno::EROFS)
        );
    }

    #[test]
    fn handle_truncate_read_only_takes_priority() {
        // Read-only check happens before kind/size validation.
        assert_eq!(
            handle_truncate(FileType::Directory, TruncateMode::Truncate, 0, 0, true),
            Err(errno::EROFS)
        );
    }

    #[test]
    fn handle_truncate_zero_size_success() {
        let plan = handle_truncate(FileType::RegularFile, TruncateMode::Ftruncate, 0, 99, false);
        assert_eq!(
            plan,
            Ok(TruncatePlan::new(TruncateMode::Ftruncate, 0, Some(99)))
        );
    }

    #[test]
    fn handle_truncate_extend_success() {
        let plan = handle_truncate(
            FileType::RegularFile,
            TruncateMode::Truncate,
            65536,
            0,
            false,
        );
        assert_eq!(
            plan,
            Ok(TruncatePlan::new(TruncateMode::Truncate, 65536, None))
        );
    }

    #[test]
    fn handle_truncate_fh_propagation() {
        let plan = handle_truncate(
            FileType::RegularFile,
            TruncateMode::Ftruncate,
            1024,
            77,
            false,
        );
        assert_eq!(plan.unwrap().fh, Some(77));
    }

    #[test]
    fn handle_truncate_fh_zero_path_based() {
        let plan = handle_truncate(
            FileType::RegularFile,
            TruncateMode::Ftruncate,
            512,
            0,
            false,
        );
        assert_eq!(plan.unwrap().fh, None);
    }

    #[test]
    fn handle_truncate_oversized_rejected() {
        assert_eq!(
            handle_truncate(
                FileType::RegularFile,
                TruncateMode::Ftruncate,
                u64::MAX,
                1,
                false
            ),
            Err(errno::EFBIG)
        );
    }
}
