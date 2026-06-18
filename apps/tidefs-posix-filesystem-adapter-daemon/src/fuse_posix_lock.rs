// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE POSIX advisory record-lock dispatch trait (getlk / setlk / setlkw).
//!
//! Defines the [`FusePosixLockDispatch`] trait that abstracts POSIX
//! byte-range advisory lock operations behind a single interface so the
//! fuser [`Filesystem`] trait implementation can call through it without
//! coupling to a specific lock backend.
//!
//! The trait mirrors the FUSE kernel protocol's three lock operations:
//! - `getlk`  — test for a conflicting lock (F_GETLK)
//! - `setlk`  — acquire/release a non-blocking lock (F_SETLK)
//! - `setlkw` — acquire a blocking lock (F_SETLKW)
//!
//! [`Filesystem`]: fuser::Filesystem

use tidefs_posix_filesystem_adapter_workers_locks::LockRange;

use crate::lock_dispatch::LockDispatchError;

// ── FusePosixLockDispatch trait ───────────────────────────────────────

/// Raw FUSE POSIX byte-range lock request parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FusePosixLockRequest {
    /// Target inode number.
    pub ino: u64,
    /// FUSE file handle.
    pub fh: u64,
    /// Kernel lock owner token.
    pub lock_owner: u64,
    /// Inclusive start offset.
    pub start: u64,
    /// Inclusive end offset, or `u64::MAX` for EOF.
    pub end: u64,
    /// Kernel `F_RDLCK` / `F_WRLCK` / `F_UNLCK` type value.
    pub typ: i32,
    /// Process id associated with the lock.
    pub pid: u32,
}

/// Dispatch trait for POSIX advisory record-lock FUSE operations.
///
/// Implementors translate the raw FUSE lock parameters into backend
/// lock-state mutations and return either a conflicting [`LockRange`]
/// (for `getlk`) or an error on conflict / invalid parameters.
pub trait FusePosixLockDispatch {
    /// Test for a conflicting lock (F_GETLK).
    ///
    /// Returns `Ok(None)` when no conflict exists, or `Ok(Some(range))`
    /// describing the existing lock that would block the request.
    ///
    /// # Errors
    ///
    /// Returns [`LockDispatchError`] on invalid lock type or internal
    /// consistency failure.
    fn getlk(
        &mut self,
        request: FusePosixLockRequest,
    ) -> Result<Option<LockRange>, LockDispatchError>;

    /// Acquire or release a non-blocking lock (F_SETLK).
    ///
    /// When `typ` is `F_UNLCK` the existing lock identified by
    /// `(ino, lock_owner, start, end)` is released.
    ///
    /// # Errors
    ///
    /// Returns [`LockDispatchError::Conflict`] when the request cannot be
    /// granted immediately (→ `EAGAIN` / `EWOULDBLOCK`).
    fn setlk(&mut self, request: FusePosixLockRequest) -> Result<(), LockDispatchError>;

    /// Acquire a blocking lock (F_SETLKW).
    ///
    /// On conflict this method registers a waiter with the lock dispatch
    /// and returns [`LockDispatchError::Blocked`] carrying a
    /// [`WaiterSignal`].  The caller should block on the signal; when
    /// the conflicting lock is released the signal is fired and the
    /// caller should retry acquisition.
    fn setlkw(&mut self, request: FusePosixLockRequest) -> Result<(), LockDispatchError>;

    /// Acquire or release a BSD flock (whole-file advisory lock).
    ///
    /// Unlike POSIX fcntl byte-range locks, BSD flock operates on entire
    /// open file descriptions, is advisory only, and is automatically
    /// released when any file descriptor for the open file description
    /// is closed.  `typ` uses the kernel-translated FUSE lock type values:
    /// 0 = F_RDLCK (LOCK_SH), 1 = F_WRLCK (LOCK_EX), 2 = F_UNLCK.
    ///
    /// # Errors
    ///
    /// Returns [`LockDispatchError::WouldBlock`] on non-blocking conflict
    /// (→ `EAGAIN`).
    fn flock(
        &mut self,
        ino: u64,
        _fh: u64,
        lock_owner: u64,
        typ: u32,
    ) -> Result<(), LockDispatchError>;
}
