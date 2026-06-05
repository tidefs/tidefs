//! FUSE `syncfs` handler helpers.
//!
//! Provides:
//! - [`handle_syncfs`]: canonical dispatch entry-point for the FUSE syncfs
//!   operation.  Validates the request context and returns `Ok(())` on
//!   success, or a POSIX errno on failure.
//!
//! `syncfs` (Linux `syncfs(2)`) is a filesystem-wide durability barrier:
//! it flushes all dirty data and metadata to stable storage, unlike per-file
//! `fsync` which only applies to a single open file description.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::syncfs;
//!
//! syncfs::handle_syncfs()?;
//! // ... perform filesystem-wide flush and commit barrier ...
//! ```

use libc::c_int;

// ---------------------------------------------------------------------------
// Re-exports: standard errno codes for syncfs error paths
// ---------------------------------------------------------------------------

pub use libc::{EINTR, EIO, ENOSPC, EROFS};

// ---------------------------------------------------------------------------
// handle_syncfs -- unified entry point for FUSE syncfs dispatch
// ---------------------------------------------------------------------------

/// Validate and execute a FUSE `syncfs` operation.
///
/// This is the preferred entry point for a FUSE daemon dispatching
/// `FUSE_SYNCFS` (opcode 50).  It performs request-level validation
/// and returns `Ok(())` to signal that the daemon should proceed with
/// the filesystem-wide flush and commit barrier.
///
/// # Errors
///
/// Returns a POSIX errno (`c_int`) on failure:
/// - `EROFS`: the filesystem is mounted read-only.
///
/// # Examples
///
/// ```rust,ignore
/// let result = syncfs::handle_syncfs(read_only);
/// // If Ok(()), the daemon should flush all dirty state and commit.
/// ```
pub fn handle_syncfs(read_only: bool) -> Result<(), c_int> {
    if read_only {
        return Err(libc::EROFS);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_syncfs_rw_succeeds() {
        assert_eq!(handle_syncfs(false), Ok(()));
    }

    #[test]
    fn handle_syncfs_ro_rejected() {
        assert_eq!(handle_syncfs(true), Err(libc::EROFS));
    }
}
