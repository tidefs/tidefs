// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE advisory lock dispatch (getlk / setlk / setlkw / flock).
//!
//! Owns the local mount session's in-process advisory-lock table. Clustered
//! LOCK framing and lease authority live behind the daemon's `cluster` feature
//! and do not participate in this dispatch path.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::fusewire::{
    FuseGetlkRequest, FuseLockIn, FuseSetlkRequest, FUSE_LK_TYPE_RDLCK, FUSE_LK_TYPE_UNLCK,
    FUSE_LK_TYPE_WRLCK,
};
use tidefs_posix_filesystem_adapter_workers_locks::{
    FlockType, LockConflict, LockList, LockRange, LockType,
};
use tidefs_types_vfs_core::Errno;

use crate::fuse_posix_lock::{FusePosixLockDispatch, FusePosixLockRequest};

/// A cloneable, thread-safe signal used by blocking `setlkw` waiters.
///
/// The FUSE handler creates a signal, registers it with the dispatch,
/// then blocks on `wait_timeout`.  When a conflicting lock is released
/// the dispatch calls `notify_all`, waking every waiter whose range
/// overlaps with the released region.
#[derive(Clone, Debug)]
pub struct WaiterSignal {
    inner: Arc<(Mutex<bool>, Condvar)>,
}

// WaiterSignal::eq is intentionally reference-equality via Arc
// (two signals are equal iff they point to the same inner).
impl PartialEq for WaiterSignal {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}
impl Eq for WaiterSignal {}

impl Default for WaiterSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl WaiterSignal {
    pub fn new() -> Self {
        Self {
            inner: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    /// Block until signalled or `timeout` elapses.
    /// Returns `true` when woken, `false` on timeout.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let (lock, cvar) = &*self.inner;
        let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if *guard {
            return true;
        }
        let (new_guard, _result) = cvar
            .wait_timeout(guard, timeout)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *new_guard
    }

    /// Wake all threads blocked on this signal.
    pub fn notify_all(&self) {
        let (lock, cvar) = &*self.inner;
        let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = true;
        cvar.notify_all();
    }
}

/// Daemon lock dispatch state for one local mount session.
#[allow(dead_code)]
pub struct DaemonLockDispatch {
    locks_by_inode: BTreeMap<u64, LockList>,
    /// Pending blocking `setlkw` waiters.
    waiters: Vec<WaiterEntry>,
}

struct WaiterEntry {
    ino: u64,
    start: u64,
    end: u64,
    signal: WaiterSignal,
}

#[allow(dead_code)]
impl Default for DaemonLockDispatch {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonLockDispatch {
    #[must_use]
    pub fn new() -> Self {
        Self {
            locks_by_inode: BTreeMap::new(),
            waiters: Vec::new(),
        }
    }

    fn acquire_lock(
        &mut self,
        ino: u64,
        start: u64,
        len: u64,
        lock_type: LockType,
        owner: u64,
        pid: u32,
    ) -> Result<(), LockConflict> {
        let requested = LockRange::new(start, len, lock_type, owner, pid);
        self.locks_by_inode
            .entry(ino)
            .or_default()
            .acquire(requested)
    }

    fn release_lock(&mut self, ino: u64, requested: LockRange) {
        let remove_inode = if let Some(locks) = self.locks_by_inode.get_mut(&ino) {
            locks.release(requested);
            locks.is_empty()
        } else {
            false
        };
        if remove_inode {
            self.locks_by_inode.remove(&ino);
        }
    }

    fn query_lock(&self, ino: u64, requested: LockRange) -> Option<LockConflict> {
        self.locks_by_inode
            .get(&ino)
            .and_then(|locks| locks.query_conflict(requested))
    }

    /// Return the number of inodes with active locks.
    #[must_use]
    pub fn inode_count(&self) -> usize {
        self.locks_by_inode.len()
    }

    /// Return `true` when no locks are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.locks_by_inode.is_empty()
    }

    /// Return the current lock count.
    #[must_use]
    #[allow(dead_code)]
    pub fn lock_count(&self) -> usize {
        self.locks_by_inode.values().map(LockList::len).sum()
    }

    /// Drop all lock state and return to a clean initial state.
    ///
    /// This mirrors the semantics of daemon restart: the in-memory lock
    /// table is discarded and a fresh empty one is created.  Kernel-side
    /// locks are expected to have been released through fd closure on
    /// process death before this is called.
    pub fn reset(&mut self) {
        self.locks_by_inode.clear();
        // Wake and clear any pending waiters so no threads are left
        // blocking on a discarded mount session.
        self.cancel_all_waiters();
    }
    // ── Query by FuseGetlkRequest ─────────────────────────────────────

    /// Query for a conflicting lock.
    pub fn getlk(
        &self,
        ino: u64,
        request: &FuseGetlkRequest,
    ) -> Result<Option<LockRange>, LockDispatchError> {
        let lock_type = fuse_type_to_lock_type(request.lk.typ)
            .ok_or(LockDispatchError::InvalidLockType(request.lk.typ))?;

        if lock_type == LockType::Unlock {
            return Ok(None);
        }

        let requested = LockRange::new(
            request.lk.start,
            len_from_fuse(request.lk),
            lock_type,
            request.owner,
            request.lk.pid,
        );
        Ok(self
            .query_lock(ino, requested)
            .map(|conflict| conflict.existing))
    }

    /// Acquire a non-blocking lock.
    pub fn setlk(&mut self, ino: u64, request: &FuseSetlkRequest) -> Result<(), LockDispatchError> {
        let lock_type = fuse_type_to_lock_type(request.lk.typ)
            .ok_or(LockDispatchError::InvalidLockType(request.lk.typ))?;

        if lock_type == LockType::Unlock {
            let unlock_start = request.lk.start;
            let unlock_len = len_from_fuse(request.lk);
            self.release_lock(
                ino,
                LockRange::new(
                    unlock_start,
                    unlock_len,
                    LockType::Unlock,
                    request.owner,
                    request.lk.pid,
                ),
            );
            self.wake_waiters_for_range(ino, unlock_start, range_end(unlock_start, unlock_len));
            return Ok(());
        }

        let len = len_from_fuse(request.lk);
        self.acquire_lock(
            ino,
            request.lk.start,
            len,
            lock_type,
            request.owner,
            request.lk.pid,
        )
        .map_err(LockDispatchError::Conflict)
    }

    /// Acquire a blocking lock.
    pub fn setlkw(
        &mut self,
        ino: u64,
        request: &FuseSetlkRequest,
    ) -> Result<(), LockDispatchError> {
        let lock_type = fuse_type_to_lock_type(request.lk.typ)
            .ok_or(LockDispatchError::InvalidLockType(request.lk.typ))?;

        if lock_type == LockType::Unlock {
            let unlock_start = request.lk.start;
            let unlock_len = len_from_fuse(request.lk);
            self.release_lock(
                ino,
                LockRange::new(
                    unlock_start,
                    unlock_len,
                    LockType::Unlock,
                    request.owner,
                    request.lk.pid,
                ),
            );
            self.wake_waiters_for_range(ino, unlock_start, range_end(unlock_start, unlock_len));
            return Ok(());
        }

        let len = len_from_fuse(request.lk);

        // Try non-blocking acquire first; on conflict register a waiter.
        let end = range_end(request.lk.start, len);
        match self.acquire_lock(
            ino,
            request.lk.start,
            len,
            lock_type,
            request.owner,
            request.lk.pid,
        ) {
            Ok(()) => Ok(()),
            Err(_) => {
                let signal = self.register_waiter(ino, request.lk.start, end);
                Err(LockDispatchError::Blocked { signal })
            }
        }
    }

    // ── Raw-value convenience methods ─────────────────────────────────

    /// Query lock with raw FUSE values.
    pub fn getlk_by_value(
        &self,
        ino: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: u32,
        pid: u32,
    ) -> Result<Option<LockRange>, LockDispatchError> {
        let lock_type =
            fuse_type_to_lock_type(typ).ok_or(LockDispatchError::InvalidLockType(typ))?;
        let len = len_from_fuse(FuseLockIn {
            start,
            end,
            typ,
            pid,
        });
        if lock_type == LockType::Unlock {
            return Ok(None);
        }
        let requested = LockRange::new(start, len, lock_type, lock_owner, pid);
        Ok(self
            .query_lock(ino, requested)
            .map(|conflict| conflict.existing))
    }

    /// Acquire or release a lock with raw FUSE values.
    pub fn setlk_by_value(
        &mut self,
        ino: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: u32,
        pid: u32,
    ) -> Result<(), LockDispatchError> {
        let lock_type =
            fuse_type_to_lock_type(typ).ok_or(LockDispatchError::InvalidLockType(typ))?;
        let len = len_from_fuse(FuseLockIn {
            start,
            end,
            typ,
            pid,
        });

        if lock_type == LockType::Unlock {
            self.release_lock(
                ino,
                LockRange::new(start, len, LockType::Unlock, lock_owner, pid),
            );
            self.wake_waiters_for_range(ino, start, range_end(start, len));
            return Ok(());
        }

        self.acquire_lock(ino, start, len, lock_type, lock_owner, pid)
            .map_err(LockDispatchError::Conflict)
    }

    /// Release all POSIX locks held by `lock_owner` on a single `ino`.
    pub fn release_by_owner_and_inode(&mut self, lock_owner: u64, ino: u64) {
        let remove_inode = if let Some(locks) = self.locks_by_inode.get_mut(&ino) {
            locks.release_by_owner(lock_owner);
            locks.is_empty()
        } else {
            false
        };
        if remove_inode {
            self.locks_by_inode.remove(&ino);
        }
        // Broad wake: retry logic in the FUSE handler ensures
        // waiters re-check and re-register if still blocked.
        self.cancel_all_waiters();
    }

    /// Register a blocking waiter for a lock range.
    ///
    /// Returns a `WaiterSignal` that the caller can block on.  When a
    /// conflicting lock is released overlapping this range, the signal
    /// is fired and the caller should retry the acquisition.
    pub fn register_waiter(&mut self, ino: u64, start: u64, end: u64) -> WaiterSignal {
        let signal = WaiterSignal::new();
        self.waiters.push(WaiterEntry {
            ino,
            start,
            end,
            signal: signal.clone(),
        });
        signal
    }

    /// Wake all waiters whose range overlaps `[start, end]` on `ino`.
    ///
    /// Called after releasing a lock.  Each woken waiter will retry
    /// its lock acquisition; those that still conflict will re-register.
    pub fn wake_waiters_for_range(&mut self, ino: u64, start: u64, end: u64) {
        self.waiters.retain(|w| {
            if w.ino == ino && intervals_overlap(w.start, w.end, start, end) {
                w.signal.notify_all();
                false
            } else {
                true
            }
        });
    }

    /// Cancel and wake all registered waiters.
    ///
    /// Called on close/flush so that blocking `setlkw` requests for a
    /// departed owner return `EINTR` rather than hanging indefinitely.
    /// This is a broad wake; the retry loop in the FUSE handler will
    /// re-check acquisition and re-register if still blocked by other owners.
    pub fn cancel_all_waiters(&mut self) {
        let woken: Vec<WaiterSignal> = self.waiters.drain(..).map(|w| w.signal).collect();
        for signal in woken {
            signal.notify_all();
        }
    }

    /// Remove and wake one specific waiter.
    ///
    /// Interruptible FUSE requests call this before returning `EINTR` so a
    /// cancelled waiter cannot remain in the mount-session table until some
    /// unrelated lock release happens later.
    pub fn cancel_waiter(&mut self, signal: &WaiterSignal) {
        let mut cancelled = Vec::new();
        self.waiters.retain(|waiter| {
            if waiter.signal == *signal {
                cancelled.push(waiter.signal.clone());
                false
            } else {
                true
            }
        });
        for signal in cancelled {
            signal.notify_all();
        }
    }

    // ── BSD flock dispatch ───────────────────────────────────────────

    /// Acquire or release a BSD flock on `ino` (mapped to EOF byte-range).
    pub fn flock(
        &mut self,
        ino: u64,
        flock_type: FlockType,
        owner: u64,
    ) -> Result<(), LockDispatchError> {
        let lock_type = match flock_type {
            FlockType::Shared => LockType::Read,
            FlockType::Exclusive => LockType::Write,
        };
        self.acquire_lock(ino, 0, 0, lock_type, owner, 0)
            .map_err(|_| LockDispatchError::WouldBlock)
    }

    /// Release the BSD flock on `ino` held by `owner`.
    pub fn release_flock(&mut self, ino: u64, owner: u64) {
        self.release_lock(ino, LockRange::new(0, 0, LockType::Unlock, owner, 0));
        self.wake_waiters_for_range(ino, 0, u64::MAX);
    }

    /// Acquire or release a BSD flock using raw FUSE lock values.
    pub fn flock_by_value(
        &mut self,
        ino: u64,
        lock_owner: u64,
        typ: u32,
    ) -> Result<(), LockDispatchError> {
        let flock_type = match typ {
            0 /* F_RDLCK */ => FlockType::Shared,
            1 /* F_WRLCK */ => FlockType::Exclusive,
            _ => {
                self.release_flock(ino, lock_owner);
                return Ok(());
            }
        };
        self.flock(ino, flock_type, lock_owner)
    }
}

// ── FusePosixLockDispatch impl ──────────────────────────────────────

#[allow(dead_code)]
impl FusePosixLockDispatch for DaemonLockDispatch {
    fn getlk(
        &mut self,
        request: FusePosixLockRequest,
    ) -> Result<Option<LockRange>, LockDispatchError> {
        self.getlk_by_value(
            request.ino,
            request.lock_owner,
            request.start,
            request.end,
            request.typ as u32,
            request.pid,
        )
    }

    fn setlk(&mut self, request: FusePosixLockRequest) -> Result<(), LockDispatchError> {
        self.setlk_by_value(
            request.ino,
            request.lock_owner,
            request.start,
            request.end,
            request.typ as u32,
            request.pid,
        )
    }

    fn setlkw(&mut self, request: FusePosixLockRequest) -> Result<(), LockDispatchError> {
        let ino = request.ino;
        let lk = FuseLockIn {
            start: request.start,
            end: request.end,
            typ: request.typ as u32,
            pid: request.pid,
        };
        let request = FuseSetlkRequest {
            fh: request.fh,
            owner: request.lock_owner,
            lk,
            lk_flags: 0,
            sleep: true,
        };
        self.setlkw(ino, &request)
    }

    fn flock(
        &mut self,
        ino: u64,
        _fh: u64,
        lock_owner: u64,
        typ: u32,
    ) -> Result<(), LockDispatchError> {
        self.flock_by_value(ino, lock_owner, typ)
    }
}

// ── Errors ──────────────────────────────────────────────────────────────

/// Errors returned by the daemon lock dispatch layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LockDispatchError {
    /// The lock type value is not a valid `F_RDLCK` / `F_WRLCK` / `F_UNLCK`.
    InvalidLockType(u32),
    /// The requested lock conflicts with an existing lock held by another owner.
    Conflict(LockConflict),
    /// The BSD flock request would block (non-blocking conflict).
    WouldBlock,
    /// Internal lock dispatch error.
    Internal(String),
    /// The lock could not be immediately acquired; the caller should
    /// block on the contained `WaiterSignal` and retry when woken.
    Blocked { signal: WaiterSignal },
}

// Manual PartialEq for Internal(String)
impl LockDispatchError {
    /// Map to a POSIX errno for the FUSE reply.
    #[must_use]
    pub fn to_errno(&self) -> Errno {
        match self {
            Self::InvalidLockType(_) => Errno::EINVAL,
            Self::Conflict(_) => Errno::EAGAIN,
            Self::WouldBlock => Errno::EAGAIN,
            Self::Internal(_) => Errno::EIO,
            Self::Blocked { .. } => Errno::EAGAIN,
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────
fn range_end(start: u64, len: u64) -> u64 {
    if len == 0 {
        u64::MAX
    } else {
        start.saturating_add(len)
    }
}

fn intervals_overlap(a1: u64, b1: u64, a2: u64, b2: u64) -> bool {
    a1 < b2 && a2 < b1
}

fn fuse_type_to_lock_type(typ: u32) -> Option<LockType> {
    if typ == FUSE_LK_TYPE_RDLCK {
        Some(LockType::Read)
    } else if typ == FUSE_LK_TYPE_WRLCK {
        Some(LockType::Write)
    } else if typ == FUSE_LK_TYPE_UNLCK {
        Some(LockType::Unlock)
    } else {
        None
    }
}

fn len_from_fuse(lk: FuseLockIn) -> u64 {
    if lk.end == u64::MAX {
        0
    } else {
        lk.end.saturating_sub(lk.start).saturating_add(1)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn lk_in(start: u64, end: u64, typ: u32, pid: u32) -> FuseGetlkRequest {
        let lk = FuseLockIn {
            start,
            end,
            typ,
            pid,
        };
        FuseGetlkRequest {
            fh: 0,
            owner: pid as u64,
            lk,
            lk_flags: 0,
        }
    }

    fn setlk_in(start: u64, end: u64, typ: u32, pid: u32) -> FuseSetlkRequest {
        let lk = FuseLockIn {
            start,
            end,
            typ,
            pid,
        };
        FuseSetlkRequest {
            fh: 0,
            owner: pid as u64,
            lk,
            lk_flags: 0,
            sleep: false,
        }
    }

    fn setlkw_in(start: u64, end: u64, typ: u32, pid: u32) -> FuseSetlkRequest {
        let lk = FuseLockIn {
            start,
            end,
            typ,
            pid,
        };
        FuseSetlkRequest {
            fh: 0,
            owner: pid as u64,
            lk,
            lk_flags: 0,
            sleep: true,
        }
    }

    #[test]
    fn dispatch_getlk_empty_returns_none() {
        let d = DaemonLockDispatch::new();
        let req = lk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100);
        assert_eq!(d.getlk(1, &req), Ok(None));
    }

    #[test]
    fn dispatch_getlk_returns_conflicting_lock() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        let q = lk_in(50, 60, FUSE_LK_TYPE_RDLCK, 200);
        let conflict = d.getlk(1, &q).unwrap().unwrap();
        assert_eq!(conflict.lock_type, LockType::Write);
        assert_eq!(conflict.pid, 100);
        assert_eq!(conflict.start, 0);
    }

    #[test]
    fn dispatch_setlk_acquires_lock() {
        let mut d = DaemonLockDispatch::new();
        assert_eq!(
            d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100)),
            Ok(())
        );
        assert_eq!(d.inode_count(), 1);
    }

    #[test]
    fn dispatch_setlk_conflict_returns_error() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        let err = d
            .setlk(1, &setlk_in(50, 60, FUSE_LK_TYPE_RDLCK, 200))
            .unwrap_err();
        assert_eq!(err.to_errno(), Errno::EAGAIN);
        match err {
            LockDispatchError::Conflict(c) => assert_eq!(c.existing.pid, 100),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_setlk_unlock_releases_lock() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        assert_eq!(d.inode_count(), 1);
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_UNLCK, 100))
            .unwrap();
        assert!(d.is_empty());
    }

    #[test]
    fn dispatch_setlkw_behaves_like_setlk() {
        let mut d = DaemonLockDispatch::new();
        assert_eq!(
            d.setlkw(1, &setlkw_in(0, 49, FUSE_LK_TYPE_RDLCK, 100)),
            Ok(())
        );
        assert_eq!(d.inode_count(), 1);
    }

    #[test]
    fn dispatch_setlkw_conflict_returns_blocked() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        let result = d.setlkw(1, &setlkw_in(50, 60, FUSE_LK_TYPE_RDLCK, 200));
        match result {
            Err(LockDispatchError::Blocked { signal }) => {
                // Signal should exist and not be pre-woken.
                assert!(!signal.wait_timeout(Duration::from_millis(1)));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn invalid_lock_type_is_rejected() {
        let mut d = DaemonLockDispatch::new();
        let err = d.setlk(1, &setlk_in(0, 99, 99, 100)).unwrap_err();
        assert_eq!(err.to_errno(), Errno::EINVAL);
        assert!(matches!(err, LockDispatchError::InvalidLockType(99)));
    }

    #[test]
    fn eof_write_lock_covers_entire_file() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(10, u64::MAX, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        let q = lk_in(10, 20, FUSE_LK_TYPE_RDLCK, 200);
        assert!(d.getlk(1, &q).unwrap().is_some());
        let q2 = lk_in(0, 5, FUSE_LK_TYPE_RDLCK, 200);
        assert!(d.getlk(1, &q2).unwrap().is_none());
    }

    #[test]
    fn read_locks_from_different_pids_are_compatible() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_RDLCK, 100))
            .unwrap();
        d.setlk(1, &setlk_in(50, 10, FUSE_LK_TYPE_RDLCK, 200))
            .unwrap();
        assert_eq!(d.inode_count(), 1);
    }

    #[test]
    fn len_from_fuse_converts_inclusive_end_to_length() {
        assert_eq!(
            len_from_fuse(FuseLockIn {
                start: 0,
                end: 99,
                typ: 0,
                pid: 0
            }),
            100
        );
        assert_eq!(
            len_from_fuse(FuseLockIn {
                start: 10,
                end: 10,
                typ: 0,
                pid: 0
            }),
            1
        );
        assert_eq!(
            len_from_fuse(FuseLockIn {
                start: 10,
                end: u64::MAX,
                typ: 0,
                pid: 0
            }),
            0
        );
    }

    // ── Flock dispatch tests ─────────────────────────────────────────

    #[test]
    fn flock_shared_acquire_succeeds() {
        let mut d = DaemonLockDispatch::new();
        assert!(d.flock(1, FlockType::Shared, 100).is_ok());
        assert_eq!(d.inode_count(), 1);
    }

    #[test]
    fn flock_exclusive_acquire_succeeds() {
        let mut d = DaemonLockDispatch::new();
        assert!(d.flock(1, FlockType::Exclusive, 100).is_ok());
    }

    #[test]
    fn flock_shared_with_shared_is_compatible() {
        let mut d = DaemonLockDispatch::new();
        d.flock(1, FlockType::Shared, 100).unwrap();
        assert!(d.flock(1, FlockType::Shared, 200).is_ok());
    }

    #[test]
    fn flock_shared_blocks_exclusive() {
        let mut d = DaemonLockDispatch::new();
        d.flock(1, FlockType::Shared, 100).unwrap();
        let err = d.flock(1, FlockType::Exclusive, 200).unwrap_err();
        assert_eq!(err.to_errno(), Errno::EAGAIN);
    }

    #[test]
    fn flock_exclusive_blocks_shared() {
        let mut d = DaemonLockDispatch::new();
        d.flock(1, FlockType::Exclusive, 100).unwrap();
        let err = d.flock(1, FlockType::Shared, 200).unwrap_err();
        assert_eq!(err.to_errno(), Errno::EAGAIN);
    }

    #[test]
    fn flock_exclusive_blocks_exclusive() {
        let mut d = DaemonLockDispatch::new();
        d.flock(1, FlockType::Exclusive, 100).unwrap();
        let err = d.flock(1, FlockType::Exclusive, 200).unwrap_err();
        assert_eq!(err.to_errno(), Errno::EAGAIN);
    }

    #[test]
    fn flock_release_allows_reacquire() {
        let mut d = DaemonLockDispatch::new();
        d.flock(1, FlockType::Exclusive, 100).unwrap();
        d.release_flock(1, 100);
        assert!(d.flock(1, FlockType::Exclusive, 200).is_ok());
    }

    #[test]
    fn flock_release_only_affects_owner() {
        let mut d = DaemonLockDispatch::new();
        d.flock(1, FlockType::Shared, 100).unwrap();
        d.flock(1, FlockType::Shared, 200).unwrap();
        d.release_flock(1, 100);
        let err = d.flock(1, FlockType::Exclusive, 300).unwrap_err();
        assert_eq!(err.to_errno(), Errno::EAGAIN);
    }

    #[test]
    fn flock_by_value_maps_fuse_types() {
        let mut d = DaemonLockDispatch::new();
        assert!(d.flock_by_value(1, 100, 0).is_ok());
        let err = d.flock_by_value(1, 200, 1).unwrap_err();
        assert_eq!(err.to_errno(), Errno::EAGAIN);
    }

    #[test]
    fn flock_by_value_release_on_f_unlck() {
        let mut d = DaemonLockDispatch::new();
        d.flock_by_value(1, 100, 1).unwrap();
        assert_eq!(d.inode_count(), 1);
        assert!(d.flock_by_value(1, 100, 2).is_ok());
        assert!(d.is_empty());
    }

    #[test]
    fn flock_conflicts_with_posix_byte_range_lock() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(10, 20, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        let err = d.flock(1, FlockType::Exclusive, 200).unwrap_err();
        assert_eq!(err.to_errno(), Errno::EAGAIN);
    }

    #[test]
    fn flock_shared_coexists_with_posix_read_lock() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_RDLCK, 100))
            .unwrap();
        assert!(d.flock(1, FlockType::Shared, 200).is_ok());
    }

    // ── FusePosixLockDispatch trait tests ───────────────────────────

    fn lock_request(
        ino: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
    ) -> FusePosixLockRequest {
        FusePosixLockRequest {
            ino,
            fh: 0,
            lock_owner,
            start,
            end,
            typ,
            pid,
        }
    }

    #[test]
    fn trait_getlk_empty_returns_none() {
        let mut d = DaemonLockDispatch::new();
        let result =
            FusePosixLockDispatch::getlk(&mut d, lock_request(1, 0, 0, 99, libc::F_WRLCK, 100));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn trait_setlk_acquires_lock() {
        let mut d = DaemonLockDispatch::new();
        let result =
            FusePosixLockDispatch::setlk(&mut d, lock_request(1, 0, 0, 99, libc::F_WRLCK, 100));
        assert!(result.is_ok());
        assert_eq!(d.inode_count(), 1);
    }

    #[test]
    fn trait_setlk_conflict_returns_error() {
        let mut d = DaemonLockDispatch::new();
        FusePosixLockDispatch::setlk(&mut d, lock_request(1, 0, 0, 99, libc::F_WRLCK, 100))
            .unwrap();
        let result =
            FusePosixLockDispatch::setlk(&mut d, lock_request(1, 0, 20, 40, libc::F_RDLCK, 200));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_errno(), Errno::EAGAIN);
    }

    #[test]
    fn trait_setlkw_acquires_on_free_range() {
        let mut d = DaemonLockDispatch::new();
        let result =
            FusePosixLockDispatch::setlkw(&mut d, lock_request(1, 0, 0, 49, libc::F_RDLCK, 100));
        assert!(result.is_ok());
        assert_eq!(d.inode_count(), 1);
    }

    #[test]
    fn trait_setlk_unlock_releases() {
        let mut d = DaemonLockDispatch::new();
        FusePosixLockDispatch::setlk(&mut d, lock_request(1, 0, 0, 99, libc::F_WRLCK, 100))
            .unwrap();
        assert_eq!(d.inode_count(), 1);
        let result =
            FusePosixLockDispatch::setlk(&mut d, lock_request(1, 0, 0, 99, libc::F_UNLCK, 100));
        assert!(result.is_ok());
        assert!(d.is_empty());
    }

    #[test]
    fn trait_flock_shared_acquire_succeeds() {
        let mut d = DaemonLockDispatch::new();
        let result = FusePosixLockDispatch::flock(&mut d, 1, 0, 100, 0);
        assert!(result.is_ok());
        assert_eq!(d.inode_count(), 1);
    }

    #[test]
    fn trait_flock_exclusive_conflicts_with_shared() {
        let mut d = DaemonLockDispatch::new();
        FusePosixLockDispatch::flock(&mut d, 1, 0, 100, 0).unwrap();
        let result = FusePosixLockDispatch::flock(&mut d, 1, 0, 200, 1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_errno(), Errno::EAGAIN);
    }

    #[test]
    fn trait_flock_unlock_releases() {
        let mut d = DaemonLockDispatch::new();
        FusePosixLockDispatch::flock(&mut d, 1, 0, 100, 1).unwrap();
        assert_eq!(d.inode_count(), 1);
        let result = FusePosixLockDispatch::flock(&mut d, 1, 0, 100, 2);
        assert!(result.is_ok());
        assert!(d.is_empty());
    }

    #[test]
    fn trait_flock_double_unlock_idempotent() {
        let mut d = DaemonLockDispatch::new();
        FusePosixLockDispatch::flock(&mut d, 1, 0, 100, 0).unwrap();
        assert!(FusePosixLockDispatch::flock(&mut d, 1, 0, 100, 2).is_ok());
        assert!(FusePosixLockDispatch::flock(&mut d, 1, 0, 100, 2).is_ok());
    }

    #[test]
    fn trait_flock_upgrade_shared_to_exclusive_succeeds() {
        let mut d = DaemonLockDispatch::new();
        FusePosixLockDispatch::flock(&mut d, 1, 0, 100, 0).unwrap();
        let result = FusePosixLockDispatch::flock(&mut d, 1, 0, 100, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn local_lock_survives_elapsed_wait_time() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        assert!(!WaiterSignal::new().wait_timeout(Duration::from_millis(1)));
        let conflict = d.getlk(1, &lk_in(0, 99, FUSE_LK_TYPE_WRLCK, 200)).unwrap();
        assert!(conflict.is_some(), "local locks have no lease TTL");
    }

    // ── OFD lock tests (owner != pid) ─────────────────────────────────

    /// Helper: build a setlk request for an OFD lock (owner != pid).
    fn ofd_setlk_in(start: u64, end: u64, typ: u32, pid: u32, fd: u64) -> FuseSetlkRequest {
        let lk = FuseLockIn {
            start,
            end,
            typ,
            pid,
        };
        FuseSetlkRequest {
            fh: 0,
            owner: fd,
            lk,
            lk_flags: 0,
            sleep: false,
        }
    }

    /// Helper: build a getlk request for an OFD lock query (owner != pid).
    fn ofd_lk_in(start: u64, end: u64, typ: u32, pid: u32, fd: u64) -> FuseGetlkRequest {
        let lk = FuseLockIn {
            start,
            end,
            typ,
            pid,
        };
        FuseGetlkRequest {
            fh: 0,
            owner: fd,
            lk,
            lk_flags: 0,
        }
    }

    #[test]
    fn ofd_two_fds_same_pid_conflict_on_write() {
        let mut d = DaemonLockDispatch::new();
        // FD 10 holds write lock on [0, 99] from pid=100.
        d.setlk(1, &ofd_setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100, 10))
            .unwrap();
        // FD 20 (same pid) tries write lock on overlapping range — must conflict.
        let err = d
            .setlk(1, &ofd_setlk_in(50, 60, FUSE_LK_TYPE_WRLCK, 100, 20))
            .unwrap_err();
        assert_eq!(err.to_errno(), Errno::EAGAIN);
    }

    #[test]
    fn ofd_two_fds_same_pid_getlk_reports_conflict() {
        let mut d = DaemonLockDispatch::new();
        // FD 10 holds write lock on [0, 99] from pid=100.
        d.setlk(1, &ofd_setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100, 10))
            .unwrap();
        // FD 20 (same pid) queries overlapping range — must report conflict.
        let q = ofd_lk_in(50, 60, FUSE_LK_TYPE_RDLCK, 100, 20);
        let conflict = d.getlk(1, &q).unwrap().unwrap();
        assert_eq!(conflict.lock_type, LockType::Write);
        assert_eq!(conflict.pid, 100); // stored pid
        assert_eq!(conflict.start, 0);
    }

    #[test]
    fn ofd_same_fd_does_not_self_conflict() {
        let mut d = DaemonLockDispatch::new();
        // FD 10 holds write lock on [0, 99].
        d.setlk(1, &ofd_setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100, 10))
            .unwrap();
        // Same FD 10 queries — should be its own lock, no conflict.
        let q = ofd_lk_in(50, 60, FUSE_LK_TYPE_RDLCK, 100, 10);
        assert_eq!(d.getlk(1, &q), Ok(None));
    }

    #[test]
    fn ofd_lock_release_scoped_to_owner() {
        let mut d = DaemonLockDispatch::new();
        // FD 10 holds write lock, FD 20 holds write lock on non-overlapping range.
        d.setlk(1, &ofd_setlk_in(0, 49, FUSE_LK_TYPE_WRLCK, 100, 10))
            .unwrap();
        d.setlk(1, &ofd_setlk_in(100, 49, FUSE_LK_TYPE_WRLCK, 100, 20))
            .unwrap();
        assert_eq!(d.inode_count(), 1);
        assert_eq!(d.lock_count(), 2);

        // Release FD 10's lock via unlock.
        d.setlk(1, &ofd_setlk_in(0, 49, FUSE_LK_TYPE_UNLCK, 100, 10))
            .unwrap();
        // FD 20's lock should remain; FD 10's range is now free.
        assert_eq!(d.lock_count(), 1);

        // A new FD (30) can now acquire the freed range.
        assert!(d
            .setlk(1, &ofd_setlk_in(0, 49, FUSE_LK_TYPE_WRLCK, 100, 30))
            .is_ok());
        assert_eq!(d.lock_count(), 2);
    }

    #[test]
    fn ofd_posix_lock_interaction() {
        let mut d = DaemonLockDispatch::new();
        // POSIX lock from pid=100 (owner == pid == 100).
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        // OFD lock from pid=100, FD 10 (owner != pid) on overlapping range — must conflict.
        let err = d
            .setlk(1, &ofd_setlk_in(50, 60, FUSE_LK_TYPE_RDLCK, 100, 10))
            .unwrap_err();
        assert_eq!(err.to_errno(), Errno::EAGAIN);

        // POSIX getlk from pid=200 should see the POSIX lock.
        let q = lk_in(50, 60, FUSE_LK_TYPE_RDLCK, 200);
        let conflict = d.getlk(1, &q).unwrap().unwrap();
        assert_eq!(conflict.lock_type, LockType::Write);
    }

    #[test]
    fn ofd_lock_upgrade_same_fd() {
        let mut d = DaemonLockDispatch::new();
        // Two descriptions from the same process hold overlapping read locks.
        d.setlk(1, &ofd_setlk_in(0, 99, FUSE_LK_TYPE_RDLCK, 100, 10))
            .unwrap();
        d.setlk(1, &ofd_setlk_in(0, 99, FUSE_LK_TYPE_RDLCK, 100, 20))
            .unwrap();

        // FD 10 cannot upgrade while FD 20 still owns the overlapping read lock.
        let err = d
            .setlk(1, &ofd_setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100, 10))
            .unwrap_err();
        assert_eq!(err.to_errno(), Errno::EAGAIN);

        // Releasing FD 20 leaves FD 10 free to replace its own read range.
        d.setlk(1, &ofd_setlk_in(0, 99, FUSE_LK_TYPE_UNLCK, 100, 20))
            .unwrap();
        d.setlk(1, &ofd_setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100, 10))
            .unwrap();

        assert_eq!(d.lock_count(), 1);
        let conflict = d
            .getlk(1, &ofd_lk_in(0, 99, FUSE_LK_TYPE_RDLCK, 100, 30))
            .unwrap()
            .unwrap();
        assert_eq!(conflict.lock_type, LockType::Write);
        assert_eq!(conflict.owner, 10);
    }

    #[test]
    fn ofd_two_fds_same_pid_non_overlapping_succeeds() {
        let mut d = DaemonLockDispatch::new();
        // FD 10 holds write lock on [0, 49].
        d.setlk(1, &ofd_setlk_in(0, 49, FUSE_LK_TYPE_WRLCK, 100, 10))
            .unwrap();
        // FD 20 holds write lock on [50, 49] — non-overlapping, both succeed.
        assert!(d
            .setlk(1, &ofd_setlk_in(50, 49, FUSE_LK_TYPE_WRLCK, 100, 20))
            .is_ok());
        assert_eq!(d.lock_count(), 2);
    }
    // ── setlkw waiter tests ─────────────────────────────────────────

    #[test]
    fn setlkw_waiter_woken_on_release() {
        let mut d = DaemonLockDispatch::new();
        // Holder acquires write lock on [0, 99].
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        // Blocking waiter tries to acquire overlapping read lock.
        let result = d.setlkw(1, &setlkw_in(50, 60, FUSE_LK_TYPE_RDLCK, 200));
        let signal = match result {
            Err(LockDispatchError::Blocked { signal }) => signal,
            other => panic!("expected Blocked, got {other:?}"),
        };
        // Waiter should not be pre-woken.
        assert!(!signal.wait_timeout(Duration::from_millis(1)));

        // Release the holder's lock — this should wake the waiter.
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_UNLCK, 100))
            .unwrap();
        // Waiter should now be woken.
        assert!(signal.wait_timeout(Duration::from_millis(1)));
    }

    #[test]
    fn setlkw_eof_waiter_woken_on_finite_release() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();

        let result = d.setlkw(1, &setlkw_in(50, u64::MAX, FUSE_LK_TYPE_RDLCK, 200));
        let signal = match result {
            Err(LockDispatchError::Blocked { signal }) => signal,
            other => panic!("expected Blocked, got {other:?}"),
        };
        assert!(!signal.wait_timeout(Duration::from_millis(1)));

        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_UNLCK, 100))
            .unwrap();
        assert!(signal.wait_timeout(Duration::from_millis(1)));
        assert!(d
            .setlkw(1, &setlkw_in(50, u64::MAX, FUSE_LK_TYPE_RDLCK, 200))
            .is_ok());
    }

    #[test]
    fn finite_waiter_woken_on_eof_release() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(0, u64::MAX, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();

        let result = d.setlkw(1, &setlkw_in(50, 60, FUSE_LK_TYPE_RDLCK, 200));
        let signal = match result {
            Err(LockDispatchError::Blocked { signal }) => signal,
            other => panic!("expected Blocked, got {other:?}"),
        };
        assert!(!signal.wait_timeout(Duration::from_millis(1)));

        d.setlk(1, &setlk_in(0, u64::MAX, FUSE_LK_TYPE_UNLCK, 100))
            .unwrap();
        assert!(signal.wait_timeout(Duration::from_millis(1)));
        assert!(d
            .setlkw(1, &setlkw_in(50, 60, FUSE_LK_TYPE_RDLCK, 200))
            .is_ok());
    }

    #[test]
    fn setlkw_succeeds_on_non_overlapping_range() {
        let mut d = DaemonLockDispatch::new();
        // Holder acquires write lock on [0, 49].
        d.setlk(1, &setlk_in(0, 49, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        // Waiter tries to acquire on [100, 149] — non-overlapping, should succeed.
        let result = d.setlkw(1, &setlkw_in(100, 149, FUSE_LK_TYPE_WRLCK, 200));
        assert!(
            result.is_ok(),
            "non-overlapping setlkw should succeed directly"
        );
        assert_eq!(d.inode_count(), 1);
    }

    #[test]
    fn setlkw_reacquires_after_wakeup() {
        let mut d = DaemonLockDispatch::new();
        // Holder acquires write lock on [0, 99].
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        // First blocking setlkw — should return Blocked.
        let result = d.setlkw(1, &setlkw_in(50, 60, FUSE_LK_TYPE_RDLCK, 200));
        let signal = match result {
            Err(LockDispatchError::Blocked { signal }) => signal,
            other => panic!("expected Blocked, got {other:?}"),
        };
        assert!(!signal.wait_timeout(Duration::from_millis(1)));

        // Release holder.
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_UNLCK, 100))
            .unwrap();
        assert!(signal.wait_timeout(Duration::from_millis(1)));

        // Retry — should now succeed.
        let result2 = d.setlkw(1, &setlkw_in(50, 60, FUSE_LK_TYPE_RDLCK, 200));
        assert!(result2.is_ok());
        assert_eq!(d.inode_count(), 1);
    }

    #[test]
    fn setlkw_no_arbitrary_timeout() {
        let mut d = DaemonLockDispatch::new();
        // Holder acquires write lock on [0, 99].
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        // setlkw returns Blocked, not a timeout error.
        let result = d.setlkw(1, &setlkw_in(50, 60, FUSE_LK_TYPE_RDLCK, 200));
        match result {
            Err(LockDispatchError::Blocked { .. }) => {
                // Expected: no timeout, just blocked with a signal.
            }
            Ok(()) => panic!("should have been blocked"),
            other => panic!("expected Blocked, got {other:?}"),
        }
    }
}
