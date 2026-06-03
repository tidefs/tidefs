//! FUSE `release` handler helpers — file-handle cleanup,
//! open-file reference-count tracking, and last-close detection.
//!
//! Provides:
//! - [`ReleaseRequest`]: parsed representation of a FUSE release
//!   request.
//! - [`parse_release_request`]: convert raw FUSE release parameters
//!   into a structured request.
//! - [`check_release_file_type`]: validate that release is applicable
//!   to the given file kind.
//! - [`release_file_handle`]: remove a file handle from a
//!   caller-provided handle set, returning the associated inode.
//! - [`release_file_handle_idempotent`]: idempotent handle removal
//!   for duplicate release handling.
//! - [`increment_open_refcount`] / [`decrement_open_refcount`]:
//!   track per-inode open-file-descriptor counts.
//! - [`handle_release`]: orchestrate the full release lifecycle —
//!   validate, remove handle, decrement refcount, and detect the
//!   last close so the caller can trigger orphan reclamation.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::release;
//!
//! let req = release::parse_release_request(
//!     ino, fh, flags, lock_owner, flush,
//! )?;
//! release::check_release_file_type(file_type)?;
//! let was_last_close = release::handle_release(
//!     &req, file_type, &mut handle_set, &mut ref_counts,
//! )?;
//! reply.ok();
//! ```

use std::collections::BTreeMap;

use libc::c_int;

use crate::errno;
use crate::FileType;

// ---------------------------------------------------------------------------
// Re-exports: standard errno codes for release error paths
// ---------------------------------------------------------------------------

pub use libc::{EBADF, EINVAL};

// ---------------------------------------------------------------------------
// ReleaseRequest
// ---------------------------------------------------------------------------

/// Parsed FUSE release request.
///
/// Carries the inode, file handle, open flags, lock-owner identity,
/// and the kernel's flush hint that the daemon receives in the FUSE
/// `release` (opcode 18) request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseRequest {
    /// Inode number of the file being released.
    pub ino: u64,
    /// File handle previously returned by `open`.
    pub fh: u64,
    /// Open flags (same as those passed to `open`).
    pub flags: i32,
    /// Lock owner for POSIX lock ownership tracking.
    pub lock_owner: Option<u64>,
    /// When `true`, the kernel requests a flush before release.
    /// (The flush is handled separately via FUSE `flush`; the
    /// daemon may use this flag for tracing or validation.)
    pub flush: bool,
}

/// Parse a FUSE release request from raw kernel parameters.
///
/// Returns `Err(EINVAL)` if `fh` is 0 (the kernel must never send a
/// zero handle for a valid open).
pub fn parse_release_request(
    ino: u64,
    fh: u64,
    flags: i32,
    lock_owner: Option<u64>,
    flush: bool,
) -> Result<ReleaseRequest, c_int> {
    if fh == 0 {
        return Err(errno::EINVAL);
    }
    Ok(ReleaseRequest {
        ino,
        fh,
        flags,
        lock_owner,
        flush,
    })
}

// ---------------------------------------------------------------------------
// File-type guard
// ---------------------------------------------------------------------------

/// Validate that a release operation is applicable to the given file
/// kind.
///
/// Regular files, directories, and block devices are releasable.
/// Special file kinds (pipes, sockets, char devices, symlinks) should
/// not carry file handles and are rejected.
///
/// # Errors
///
/// Returns `Err(EINVAL)` for non-releasable file kinds.
pub fn check_release_file_type(kind: FileType) -> Result<(), c_int> {
    match kind {
        FileType::RegularFile | FileType::Directory | FileType::BlockDevice => Ok(()),
        FileType::NamedPipe | FileType::Socket | FileType::CharDevice | FileType::Symlink => {
            Err(errno::EINVAL)
        }
    }
}

// ---------------------------------------------------------------------------
// Handle release
// ---------------------------------------------------------------------------

/// Release a file handle by its FUSE file handle.
///
/// Removes `fh` from `handle_set` (mapping fh → inode).  Returns the
/// associated inode on success so the caller can verify consistency and
/// perform post-release cleanup.
///
/// Returns `Err(EBADF)` if the handle is not found.
pub fn release_file_handle(fh: u64, handle_set: &mut BTreeMap<u64, u64>) -> Result<u64, c_int> {
    handle_set.remove(&fh).ok_or(errno::EBADF)
}

/// Release a file handle, returning `None` when the handle is already
/// absent.
///
/// This is safe to call on duplicate release requests (kernel retry)
/// and avoids double-free errors.  Use this when the caller cannot
/// guarantee exactly-once semantics from the kernel.
#[must_use]
pub fn release_file_handle_idempotent(fh: u64, handle_set: &mut BTreeMap<u64, u64>) -> Option<u64> {
    handle_set.remove(&fh)
}

// ---------------------------------------------------------------------------
// Open-file reference counting
// ---------------------------------------------------------------------------

/// Increment the open-file reference count for an inode.
///
/// Called during `open` so the release path can detect the last
/// close (refcount → 0) and trigger orphan-index reclamation for
/// files that were unlinked while open.
pub fn increment_open_refcount(ino: u64, ref_counts: &mut BTreeMap<u64, u32>) {
    *ref_counts.entry(ino).or_insert(0) += 1;
}

/// Decrement the open-file reference count for an inode.
///
/// Returns `true` when the count reaches zero (last close), `false`
/// when there are still open file descriptors referencing this inode.
///
/// If the inode is absent from the map (inconsistency after crash
/// recovery or programming error), the count is treated as zero and
/// `true` is returned to avoid leaking orphan state.
#[must_use]
pub fn decrement_open_refcount(ino: u64, ref_counts: &mut BTreeMap<u64, u32>) -> bool {
    match ref_counts.get_mut(&ino) {
        Some(count) if *count > 0 => {
            *count -= 1;
            if *count == 0 {
                ref_counts.remove(&ino);
                true
            } else {
                false
            }
        }
        Some(_) => {
            // Count is zero — clean up the stale entry.
            ref_counts.remove(&ino);
            true
        }
        _ => {
            // Not tracked — treat as last close.
            true
        }
    }
}

/// Return the current open-file reference count for an inode.
///
/// Returns `0` when the inode is not tracked.
#[must_use]
pub fn open_refcount(ino: u64, ref_counts: &BTreeMap<u64, u32>) -> u32 {
    ref_counts.get(&ino).copied().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/// Perform the full release lifecycle for a file handle.
///
/// 1. Validates that the file type supports release.
/// 2. Removes the file handle from the handle set.
/// 3. Checks that the handle's inode matches the request inode
///    (integrity cross-check).
/// 4. Decrements the open-file reference count.
///
/// Returns `true` when this was the **last close** (open-file refcount
/// reached zero), signalling to the caller that it should trigger
/// orphan-index reclamation for files unlinked while open.
///
/// # Errors
///
/// Returns `Err(EINVAL)` for an unsupported file type.
/// Returns `Err(EBADF)` if the handle is not found in the handle set.
pub fn handle_release(
    req: &ReleaseRequest,
    kind: FileType,
    handle_set: &mut BTreeMap<u64, u64>,
    ref_counts: &mut BTreeMap<u64, u32>,
) -> Result<bool, c_int> {
    check_release_file_type(kind)?;
    let handle_ino = release_file_handle(req.fh, handle_set)?;
    // Integrity: the handle must point to the inode the kernel names.
    if handle_ino != req.ino {
        return Err(errno::EINVAL);
    }
    Ok(decrement_open_refcount(req.ino, ref_counts))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_release_request ──────────────────────────────────────────

    #[test]
    fn parse_valid_release_request() {
        let req = parse_release_request(10, 42, 0o100, Some(0), false).expect("valid request");
        assert_eq!(req.ino, 10);
        assert_eq!(req.fh, 42);
        assert_eq!(req.flags, 0o100);
        assert_eq!(req.lock_owner, Some(0));
        assert!(!req.flush);
    }

    #[test]
    fn parse_release_with_flush_hint() {
        let req = parse_release_request(1, 2, 0, None, true).expect("valid request");
        assert!(req.flush);
        assert_eq!(req.lock_owner, None);
    }

    #[test]
    fn parse_zero_fh_fails() {
        assert_eq!(
            parse_release_request(5, 0, 0, None, false).unwrap_err(),
            errno::EINVAL
        );
    }

    #[test]
    fn parse_max_fh_ok() {
        let req =
            parse_release_request(7, u64::MAX, 0o2000, Some(99), false).expect("valid request");
        assert_eq!(req.fh, u64::MAX);
        assert_eq!(req.lock_owner, Some(99));
    }

    // ── check_release_file_type ────────────────────────────────────────

    #[test]
    fn release_allowed_on_regular_file() {
        assert_eq!(check_release_file_type(FileType::RegularFile), Ok(()));
    }

    #[test]
    fn release_allowed_on_directory() {
        assert_eq!(check_release_file_type(FileType::Directory), Ok(()));
    }

    #[test]
    fn release_allowed_on_block_device() {
        assert_eq!(check_release_file_type(FileType::BlockDevice), Ok(()));
    }

    #[test]
    fn release_denied_on_named_pipe() {
        assert_eq!(
            check_release_file_type(FileType::NamedPipe),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn release_denied_on_socket() {
        assert_eq!(
            check_release_file_type(FileType::Socket),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn release_denied_on_char_device() {
        assert_eq!(
            check_release_file_type(FileType::CharDevice),
            Err(errno::EINVAL)
        );
    }

    #[test]
    fn release_denied_on_symlink() {
        assert_eq!(
            check_release_file_type(FileType::Symlink),
            Err(errno::EINVAL)
        );
    }

    // ── release_file_handle ────────────────────────────────────────────

    #[test]
    fn release_known_handle_returns_ino() {
        let mut handles = BTreeMap::new();
        handles.insert(42, 100);
        assert_eq!(release_file_handle(42, &mut handles), Ok(100));
        assert!(!handles.contains_key(&42));
    }

    #[test]
    fn release_unknown_handle_fails() {
        let mut handles = BTreeMap::new();
        assert_eq!(
            release_file_handle(999, &mut handles).unwrap_err(),
            errno::EBADF
        );
    }

    #[test]
    fn release_removes_only_requested_handle() {
        let mut handles = BTreeMap::new();
        handles.insert(1, 101);
        handles.insert(2, 102);
        handles.insert(3, 103);
        assert_eq!(release_file_handle(2, &mut handles), Ok(102));
        assert_eq!(handles.len(), 2);
        assert!(handles.contains_key(&1));
        assert!(handles.contains_key(&3));
    }

    // ── release_file_handle_idempotent ─────────────────────────────────

    #[test]
    fn idempotent_release_returns_none_on_missing() {
        let mut handles: BTreeMap<u64, u64> = BTreeMap::new();
        assert_eq!(release_file_handle_idempotent(1, &mut handles), None);
    }

    #[test]
    fn idempotent_release_returns_some_on_present() {
        let mut handles = BTreeMap::new();
        handles.insert(99, 999);
        assert_eq!(release_file_handle_idempotent(99, &mut handles), Some(999));
        assert!(handles.is_empty());
        // Second call is idempotent
        assert_eq!(release_file_handle_idempotent(99, &mut handles), None);
    }

    // ── increment / decrement refcount ─────────────────────────────────

    #[test]
    fn increment_starts_at_one() {
        let mut rc = BTreeMap::new();
        increment_open_refcount(1, &mut rc);
        assert_eq!(rc.get(&1), Some(&1));
    }

    #[test]
    fn increment_accumulates() {
        let mut rc = BTreeMap::new();
        increment_open_refcount(5, &mut rc);
        increment_open_refcount(5, &mut rc);
        increment_open_refcount(5, &mut rc);
        assert_eq!(rc.get(&5), Some(&3));
    }

    #[test]
    fn decrement_last_close_returns_true() {
        let mut rc = BTreeMap::new();
        rc.insert(10, 1);
        assert!(decrement_open_refcount(10, &mut rc));
        assert!(!rc.contains_key(&10));
    }

    #[test]
    fn decrement_not_last_returns_false() {
        let mut rc = BTreeMap::new();
        rc.insert(20, 3);
        assert!(!decrement_open_refcount(20, &mut rc));
        assert_eq!(rc.get(&20), Some(&2));
    }

    #[test]
    fn decrement_unknown_returns_true() {
        let mut rc = BTreeMap::new();
        // Not tracked — treat as last close to avoid leaking orphan state.
        assert!(decrement_open_refcount(99, &mut rc));
    }

    #[test]
    fn decrement_zero_count_returns_true() {
        let mut rc = BTreeMap::new();
        rc.insert(30, 0);
        assert!(decrement_open_refcount(30, &mut rc));
        assert!(!rc.contains_key(&30));
    }

    #[test]
    fn open_refcount_returns_current_value() {
        let mut rc = BTreeMap::new();
        assert_eq!(open_refcount(1, &rc), 0);
        increment_open_refcount(1, &mut rc);
        assert_eq!(open_refcount(1, &rc), 1);
        increment_open_refcount(1, &mut rc);
        assert_eq!(open_refcount(1, &rc), 2);
    }

    // ── handle_release orchestration ───────────────────────────────────

    #[test]
    fn handle_release_single_open_close() {
        let req = parse_release_request(100, 42, 0, None, false).unwrap();
        let mut handles = BTreeMap::new();
        handles.insert(42, 100);
        let mut rc = BTreeMap::new();
        increment_open_refcount(100, &mut rc);

        let was_last = handle_release(&req, FileType::RegularFile, &mut handles, &mut rc)
            .expect("release succeeds");
        assert!(was_last, "single close should be last close");
        assert!(!handles.contains_key(&42));
        assert_eq!(open_refcount(100, &rc), 0);
    }

    #[test]
    fn handle_release_multi_open_single_close_not_last() {
        let req = parse_release_request(200, 7, 0, None, false).unwrap();
        let mut handles = BTreeMap::new();
        handles.insert(7, 200);
        let mut rc = BTreeMap::new();
        // Three opens, one fd closing
        increment_open_refcount(200, &mut rc);
        increment_open_refcount(200, &mut rc);
        increment_open_refcount(200, &mut rc);

        let was_last = handle_release(&req, FileType::RegularFile, &mut handles, &mut rc)
            .expect("release succeeds");
        assert!(!was_last, "not last close — 2 fds remain");
        assert_eq!(open_refcount(200, &rc), 2);
    }

    #[test]
    fn handle_release_invalid_fh_returns_ebadf() {
        let req = parse_release_request(300, 99, 0, None, false).unwrap();
        let mut handles = BTreeMap::new();
        let mut rc = BTreeMap::new();

        let err = handle_release(&req, FileType::RegularFile, &mut handles, &mut rc).unwrap_err();
        assert_eq!(err, errno::EBADF);
    }

    #[test]
    fn handle_release_special_file_rejected() {
        let req = parse_release_request(400, 8, 0, None, false).unwrap();
        let mut handles = BTreeMap::new();
        handles.insert(8, 400);
        let mut rc = BTreeMap::new();

        let err = handle_release(&req, FileType::Socket, &mut handles, &mut rc).unwrap_err();
        assert_eq!(err, errno::EINVAL);
    }

    #[test]
    fn handle_release_inode_mismatch_rejected() {
        // Handle points to inode 500, but request claims inode 501.
        let req = parse_release_request(501, 10, 0, None, false).unwrap();
        let mut handles = BTreeMap::new();
        handles.insert(10, 500);
        let mut rc = BTreeMap::new();
        increment_open_refcount(500, &mut rc);

        let err = handle_release(&req, FileType::RegularFile, &mut handles, &mut rc).unwrap_err();
        assert_eq!(err, errno::EINVAL);
    }

    #[test]
    fn handle_release_idempotent_via_idempotent_fn() {
        // Demonstrates that release_file_handle_idempotent can be
        // used for kernel-retry idempotency without changing the
        // main handle_release contract.
        let mut handles = BTreeMap::new();
        handles.insert(55, 600);
        assert_eq!(release_file_handle_idempotent(55, &mut handles), Some(600));
        assert_eq!(release_file_handle_idempotent(55, &mut handles), None);
    }

    // ── full lifecycle: open → refcount → release → last close ─────────

    #[test]
    fn full_open_release_lifecycle() {
        let mut handles = BTreeMap::new();
        let mut rc = BTreeMap::new();

        // Simulate open
        handles.insert(1, 700);
        increment_open_refcount(700, &mut rc);

        // Simulate release
        let req = parse_release_request(700, 1, 0o100, None, false).unwrap();
        let was_last =
            handle_release(&req, FileType::RegularFile, &mut handles, &mut rc).expect("release");

        assert!(was_last);
        assert!(handles.is_empty());
        assert_eq!(open_refcount(700, &rc), 0);
    }

    #[test]
    fn double_open_single_close_then_last() {
        let mut handles = BTreeMap::new();
        let mut rc = BTreeMap::new();

        // Two fds on same inode
        handles.insert(10, 800);
        handles.insert(11, 800);
        increment_open_refcount(800, &mut rc);
        increment_open_refcount(800, &mut rc);

        // Close first fd
        let req1 = parse_release_request(800, 10, 0, None, false).unwrap();
        let was_last1 =
            handle_release(&req1, FileType::RegularFile, &mut handles, &mut rc).expect("release");
        assert!(!was_last1);
        assert_eq!(open_refcount(800, &rc), 1);

        // Close last fd
        let req2 = parse_release_request(800, 11, 0, None, false).unwrap();
        let was_last2 =
            handle_release(&req2, FileType::RegularFile, &mut handles, &mut rc).expect("release");
        assert!(was_last2);
        assert!(handles.is_empty());
        assert_eq!(open_refcount(800, &rc), 0);
    }

    // ── ReleaseRequest Copy + Eq ───────────────────────────────────────

    #[test]
    fn release_request_is_copy_and_eq() {
        let a = parse_release_request(1, 2, 3, Some(4), true).unwrap();
        let b = a;
        assert_eq!(a, b);
    }
}
