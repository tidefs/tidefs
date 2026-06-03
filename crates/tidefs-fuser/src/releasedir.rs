//! FUSE `releasedir` handler helpers — directory handle release
//! and cleanup.
//!
//! Provides:
//! - [`ReleasedirRequest`]: parsed representation of a FUSE releasedir
//!   request.
//! - [`parse_releasedir_request`]: convert raw FUSE releasedir
//!   parameters into a structured request.
//! - [`release_dir_handle`]: validate and release a directory handle
//!   from a caller-provided handle set.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::releasedir;
//!
//! let req = releasedir::parse_releasedir_request(ino, fh, flags)?;
//! releasedir::release_dir_handle(fh, &mut handle_set, &mut inode_set);
//! reply.ok();
//! ```

use std::collections::{BTreeMap, BTreeSet};

use libc::c_int;

// Re-export POSIX errno codes used by releasedir.
pub use libc::{EBADF, EINVAL};

// ---------------------------------------------------------------------------
// ReleasedirRequest
// ---------------------------------------------------------------------------

/// Parsed FUSE releasedir request.
#[derive(Clone, Copy, Debug)]
pub struct ReleasedirRequest {
    /// Inode number of the directory being released.
    pub ino: u64,
    /// File handle previously returned by opendir.
    pub fh: u64,
    /// Open flags (same as those passed to opendir).
    pub flags: i32,
}

/// Parse a FUSE releasedir request from raw parameters.
///
/// Returns `Err(EINVAL)` if `fh` is 0 (invalid handle).
pub fn parse_releasedir_request(ino: u64, fh: u64, flags: i32) -> Result<ReleasedirRequest, c_int> {
    if fh == 0 {
        return Err(libc::EINVAL);
    }
    Ok(ReleasedirRequest { ino, fh, flags })
}

/// Release a directory handle by its FUSE file handle.
///
/// Removes `fh` from `handle_set` (mapping fh → inode).  Returns the
/// associated inode on success so the caller can perform post-release
/// cleanup (flushing pending enumeration state, etc.).
///
/// Returns `Err(EBADF)` if the handle is not found.
pub fn release_dir_handle(fh: u64, handle_set: &mut BTreeMap<u64, u64>) -> Result<u64, c_int> {
    handle_set.remove(&fh).ok_or(libc::EBADF)
}

/// Idempotent release: remove `fh` from `handle_set` if present.
///
/// Returns `Ok(Some(ino))` if the handle was removed, `Ok(None)` if
/// the handle was not present (already released).
pub fn release_dir_handle_idempotent(fh: u64, handle_set: &mut BTreeMap<u64, u64>) -> Option<u64> {
    handle_set.remove(&fh)
}

/// Flush pending directory enumeration state for a released handle.
///
/// Cleans up any recorded cookie-offset mappings in `cookie_state`
/// (a set of (fh, cookie) pairs), removing all entries for `fh`.
/// Returns the number of cookie mappings removed.
pub fn flush_dir_handle_state(fh: u64, cookie_state: &mut BTreeSet<(u64, u64)>) -> usize {
    let before = cookie_state.len();
    cookie_state.retain(|(h, _)| *h != fh);
    before - cookie_state.len()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_releasedir_request ───────────────────────────────────────

    #[test]
    fn parse_valid_releasedir_request() {
        let req = parse_releasedir_request(100, 5, 0).expect("valid");
        assert_eq!(req.ino, 100);
        assert_eq!(req.fh, 5);
        assert_eq!(req.flags, 0);
    }

    #[test]
    fn parse_releasedir_with_flags() {
        let req = parse_releasedir_request(200, 10, 0o40000).expect("valid");
        assert_eq!(req.ino, 200);
        assert_eq!(req.fh, 10);
        assert_eq!(req.flags, 0o40000);
    }

    #[test]
    fn parse_releasedir_rejects_zero_fh() {
        assert_eq!(parse_releasedir_request(1, 0, 0).unwrap_err(), libc::EINVAL);
    }

    // ── release_dir_handle ─────────────────────────────────────────────

    #[test]
    fn release_existing_handle_returns_inode() {
        let mut handles = BTreeMap::new();
        handles.insert(42, 100);
        let ino = release_dir_handle(42, &mut handles).expect("should release");
        assert_eq!(ino, 100);
        assert!(handles.is_empty());
    }

    #[test]
    fn release_unknown_handle_returns_ebadf() {
        let mut handles: BTreeMap<u64, u64> = BTreeMap::new();
        assert_eq!(
            release_dir_handle(999, &mut handles).unwrap_err(),
            libc::EBADF
        );
    }

    #[test]
    fn double_release_idempotency() {
        let mut handles = BTreeMap::new();
        handles.insert(7, 77);
        release_dir_handle(7, &mut handles).expect("first release");
        assert_eq!(
            release_dir_handle(7, &mut handles).unwrap_err(),
            libc::EBADF
        );
    }

    // ── release_dir_handle_idempotent ──────────────────────────────────

    #[test]
    fn idempotent_release_returns_none_on_missing() {
        let mut handles: BTreeMap<u64, u64> = BTreeMap::new();
        assert_eq!(release_dir_handle_idempotent(1, &mut handles), None);
    }

    #[test]
    fn idempotent_release_returns_some_on_present() {
        let mut handles = BTreeMap::new();
        handles.insert(99, 999);
        assert_eq!(release_dir_handle_idempotent(99, &mut handles), Some(999));
        assert!(handles.is_empty());
        // Second call is idempotent
        assert_eq!(release_dir_handle_idempotent(99, &mut handles), None);
    }

    // ── flush_dir_handle_state ─────────────────────────────────────────

    #[test]
    fn flush_removes_all_cookies_for_handle() {
        let mut state = BTreeSet::new();
        state.insert((5, 10));
        state.insert((5, 20));
        state.insert((7, 30));

        let removed = flush_dir_handle_state(5, &mut state);
        assert_eq!(removed, 2);
        assert_eq!(state.len(), 1);
        assert!(state.contains(&(7, 30)));
    }

    #[test]
    fn flush_unknown_handle_removes_none() {
        let mut state = BTreeSet::new();
        state.insert((1, 100));
        let removed = flush_dir_handle_state(99, &mut state);
        assert_eq!(removed, 0);
        assert_eq!(state.len(), 1);
    }
}
