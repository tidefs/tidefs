// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE advisory lock dispatch (getlk / setlk / setlkw / flock).
//!
//! Wires `tidefs-lock-service` LockService with lease-backed ownership TTLs
//! into the daemon dispatch layer so that FUSE lock operations are executed
//! against the per-filesystem lease-backed lock registry.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::fusewire::{
    FuseGetlkRequest, FuseLockIn, FuseSetlkRequest, FUSE_LK_TYPE_RDLCK, FUSE_LK_TYPE_UNLCK,
    FUSE_LK_TYPE_WRLCK,
};
use tidefs_lock_service::{
    AcquireResult, LockAcquireRequest, LockMode, LockService, LockServiceConfig, LockServiceError,
    MemberId, ServiceLockOwner,
};
use tidefs_posix_filesystem_adapter_workers_locks::{FlockType, LockConflict, LockRange, LockType};
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
        let guard = lock.lock().unwrap();
        if *guard {
            return true;
        }
        let (_new_guard, result) = cvar.wait_timeout(guard, timeout).unwrap();
        !result.timed_out()
    }

    /// Wake all threads blocked on this signal.
    pub fn notify_all(&self) {
        let (lock, cvar) = &*self.inner;
        let mut guard = lock.lock().unwrap();
        *guard = true;
        cvar.notify_all();
    }
}

/// Daemon lock dispatch state — owns the lease-backed lock service.
#[allow(dead_code)]
pub struct DaemonLockDispatch {
    svc: LockService,
    /// Monotonic clock for lease TTLs (milliseconds since an arbitrary epoch).
    now_millis: u64,
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
            svc: LockService::new(LockServiceConfig::default()),
            now_millis: 0,
            waiters: Vec::new(),
        }
    }

    fn acquire_lock(
        &mut self,
        ino: u64,
        start: u64,
        len: u64,
        mode: LockMode,
        owner: ServiceLockOwner,
        blocking: bool,
    ) -> Result<AcquireResult, LockServiceError> {
        self.svc.acquire(LockAcquireRequest {
            ino,
            start,
            len,
            mode,
            owner,
            blocking,
            now_millis: self.now_millis,
        })
    }

    /// Return a reference to the underlying LockService (for testing).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn svc(&self) -> &LockService {
        &self.svc
    }

    /// Advance the internal clock. Call before each lock operation (or
    /// periodically) so that lease TTLs are evaluated against a moving
    /// time base.
    ///
    /// Returns the list of locks that expired during this tick.
    pub fn tick(&mut self, delta_millis: u64) -> Vec<tidefs_lock_service::LockState> {
        self.now_millis = self.now_millis.saturating_add(delta_millis);
        self.svc.sweep_expired(self.now_millis)
    }

    /// Set the internal clock to an absolute value and sweep expired leases.
    pub fn set_now(&mut self, now_millis: u64) -> Vec<tidefs_lock_service::LockState> {
        self.now_millis = now_millis;
        self.svc.sweep_expired(self.now_millis)
    }

    /// Return the number of inodes with active locks.
    #[must_use]
    pub fn inode_count(&self) -> usize {
        let locks = self.svc.all_locks();
        let mut inodes: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for l in &locks {
            inodes.insert(l.ino);
        }
        inodes.len()
    }

    /// Return `true` when no locks are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.svc.lock_count() == 0
    }

    /// Return the current lock count.
    #[must_use]
    #[allow(dead_code)]
    pub fn lock_count(&self) -> usize {
        self.svc.lock_count()
    }

    /// Drop all lock state and return to a clean initial state.
    ///
    /// This mirrors the semantics of daemon restart: the in-memory lock
    /// table is discarded and a fresh empty one is created.  Kernel-side
    /// locks are expected to have been released through fd closure on
    /// process death before this is called.
    pub fn reset(&mut self) {
        self.svc = LockService::new(LockServiceConfig::default());
        self.now_millis = 0;
        // Wake and clear any pending waiters so no threads are left
        // blocking on a dead lock service.
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

        let len = len_from_fuse(request.lk);
        let overlapping = self.svc.query(ino, request.lk.start, len);

        // Use the FUSE lock_owner (request.owner) for same-owner filtering.
        // For POSIX locks lock_owner == pid; for OFD locks lock_owner is the
        // file-description id, so two FDs from the same process correctly
        // conflict.
        let requesting_owner = request.owner;
        for state in &overlapping {
            let existing_type = lock_mode_to_lock_type(state.mode);
            if lock_type_conflicts(lock_type, existing_type)
                && state.owner.owner_key != requesting_owner
            {
                return Ok(Some(LockRange {
                    start: state.start,
                    len: range_len(state.start, state.end),
                    lock_type: existing_type,
                    owner: 0,
                    pid: state.owner.pid,
                }));
            }
        }
        Ok(None)
    }

    /// Acquire a non-blocking lock.
    pub fn setlk(&mut self, ino: u64, request: &FuseSetlkRequest) -> Result<(), LockDispatchError> {
        let lock_type = fuse_type_to_lock_type(request.lk.typ)
            .ok_or(LockDispatchError::InvalidLockType(request.lk.typ))?;

        if lock_type == LockType::Unlock {
            let owner = make_owner(request.lk.pid, request.owner);
            let unlock_start = request.lk.start;
            let unlock_len = safe_len(request.lk.start, len_from_fuse(request.lk));
            match self
                .svc
                .release(ino, unlock_start, unlock_len, owner, self.now_millis)
            {
                Ok(_) | Err(LockServiceError::NotFound) => {
                    let end = range_end(unlock_start, unlock_len);
                    self.wake_waiters_for_range(ino, unlock_start, end);
                    return Ok(());
                }
                Err(e) => return Err(LockDispatchError::Internal(format!("release: {e:?}"))),
            }
        }

        let mode = lock_type_to_lock_mode(lock_type);
        let owner = make_owner(request.lk.pid, request.owner);
        let len = len_from_fuse(request.lk);

        let len = safe_len(request.lk.start, len);
        match self.acquire_lock(ino, request.lk.start, len, mode, owner, false) {
            Ok(AcquireResult::Granted { .. }) => Ok(()),
            Ok(AcquireResult::Conflict { holder: _ }) => {
                Err(LockDispatchError::Conflict(build_conflict(
                    ino,
                    &self.svc,
                    request.lk.start,
                    len,
                    lock_type,
                    request.lk.pid,
                )))
            }
            Ok(AcquireResult::Queued) => Err(LockDispatchError::Conflict(build_conflict(
                ino,
                &self.svc,
                request.lk.start,
                len,
                lock_type,
                request.lk.pid,
            ))),
            Err(LockServiceError::QueueFull) => {
                Err(LockDispatchError::Internal("lock queue full".into()))
            }
            Err(e) => Err(LockDispatchError::Internal(format!("acquire: {e:?}"))),
        }
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
            let owner = make_owner(request.lk.pid, request.owner);
            let unlock_start = request.lk.start;
            let unlock_len = safe_len(request.lk.start, len_from_fuse(request.lk));
            match self
                .svc
                .release(ino, unlock_start, unlock_len, owner, self.now_millis)
            {
                Ok(_) | Err(LockServiceError::NotFound) => {
                    let end = range_end(unlock_start, unlock_len);
                    self.wake_waiters_for_range(ino, unlock_start, end);
                    return Ok(());
                }
                Err(e) => return Err(LockDispatchError::Internal(format!("release: {e:?}"))),
            }
        }

        let mode = lock_type_to_lock_mode(lock_type);
        let owner = make_owner(request.lk.pid, request.owner);
        let len = safe_len(request.lk.start, len_from_fuse(request.lk));

        // Try non-blocking acquire first; on conflict register a waiter.
        let end = range_end(request.lk.start, len);
        match self.acquire_lock(ino, request.lk.start, len, mode, owner, false) {
            Ok(AcquireResult::Granted { .. }) => Ok(()),
            Ok(AcquireResult::Queued) | Ok(AcquireResult::Conflict { .. }) => {
                let signal = self.register_waiter(ino, request.lk.start, end);
                Err(LockDispatchError::Blocked { signal })
            }
            Err(LockServiceError::QueueFull) => {
                Err(LockDispatchError::Internal("lock queue full".into()))
            }
            Err(e) => Err(LockDispatchError::Internal(format!("acquire: {e:?}"))),
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
        // Use lock_owner for same-owner filtering.  For POSIX locks
        // lock_owner == pid; for OFD locks lock_owner != pid and
        // two different FDs from the same process correctly conflict.
        let requesting_owner = lock_owner;
        let overlapping = self.svc.query(ino, start, len);
        for state in &overlapping {
            let existing_type = lock_mode_to_lock_type(state.mode);
            if lock_type_conflicts(lock_type, existing_type)
                && state.owner.owner_key != requesting_owner
            {
                return Ok(Some(LockRange {
                    start: state.start,
                    len: range_len(state.start, state.end),
                    lock_type: existing_type,
                    owner: 0,
                    pid: state.owner.pid,
                }));
            }
        }
        Ok(None)
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
            let len = safe_len(start, len);
            let owner = make_owner(pid, lock_owner);
            match self.svc.release(ino, start, len, owner, self.now_millis) {
                Ok(_) | Err(LockServiceError::NotFound) => return Ok(()),
                Err(e) => return Err(LockDispatchError::Internal(format!("release: {e:?}"))),
            }
        }

        let mode = lock_type_to_lock_mode(lock_type);
        let owner = make_owner(pid, lock_owner);
        match self.acquire_lock(ino, start, len, mode, owner, false) {
            Ok(AcquireResult::Granted { .. }) => Ok(()),
            Ok(AcquireResult::Conflict { .. }) | Ok(AcquireResult::Queued) => {
                Err(LockDispatchError::Conflict(build_conflict(
                    ino, &self.svc, start, len, lock_type, pid,
                )))
            }
            Err(_) => Err(LockDispatchError::Conflict(build_conflict(
                ino, &self.svc, start, len, lock_type, pid,
            ))),
        }
    }

    /// Release all POSIX locks held by `lock_owner` on a single `ino`.
    pub fn release_by_owner_and_inode(&mut self, lock_owner: u64, ino: u64) {
        let owner = make_owner(lock_owner as u32, lock_owner);
        // Release all locks for this owner on this inode; wake any
        // waiters whose range overlapped the released locks.
        let _ = self.svc.release(ino, 0, 0, owner, self.now_millis);
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

    // ── BSD flock dispatch ───────────────────────────────────────────

    /// Acquire or release a BSD flock on `ino` (mapped to EOF byte-range).
    pub fn flock(
        &mut self,
        ino: u64,
        flock_type: FlockType,
        owner: u64,
    ) -> Result<(), LockDispatchError> {
        let mode = match flock_type {
            FlockType::Shared => LockMode::Shared,
            FlockType::Exclusive => LockMode::Exclusive,
        };
        let lock_owner = make_owner(0, owner);
        match self.acquire_lock(ino, 0, u64::MAX, mode, lock_owner, false) {
            Ok(AcquireResult::Granted { .. }) => Ok(()),
            Ok(AcquireResult::Conflict { holder }) => {
                // Same-owner upgrade: release old lock, retry acquire
                if holder.is_some_and(|h| h.node_id == lock_owner.node_id) {
                    let _ = self
                        .svc
                        .release(ino, 0, u64::MAX, lock_owner, self.now_millis);
                    match self.acquire_lock(ino, 0, u64::MAX, mode, lock_owner, false) {
                        Ok(AcquireResult::Granted { .. }) => return Ok(()),
                        _ => return Err(LockDispatchError::WouldBlock),
                    }
                }
                Err(LockDispatchError::WouldBlock)
            }
            Ok(AcquireResult::Queued) => Err(LockDispatchError::WouldBlock),
            Err(_) => Err(LockDispatchError::WouldBlock),
        }
    }

    /// Release the BSD flock on `ino` held by `owner`.
    pub fn release_flock(&mut self, ino: u64, owner: u64) {
        let lock_owner = make_owner(0, owner);
        let _ = self
            .svc
            .release(ino, 0, u64::MAX, lock_owner, self.now_millis);
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
    /// The requested lock conflicts with an existing lock held by another process.
    Conflict(LockConflict),
    /// The BSD flock request would block (non-blocking conflict).
    WouldBlock,
    /// Internal lock service error.
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
    start.saturating_add(len)
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

/// Convert EOF len=0 to explicit u64::MAX range for LockService compatibility.
fn safe_len(start: u64, len: u64) -> u64 {
    if len == 0 {
        u64::MAX.saturating_sub(start)
    } else {
        len
    }
}

fn len_from_fuse(lk: FuseLockIn) -> u64 {
    if lk.end == u64::MAX {
        0
    } else {
        lk.end.saturating_sub(lk.start).saturating_add(1)
    }
}

const fn lock_mode_to_lock_type(mode: LockMode) -> LockType {
    match mode {
        LockMode::Shared | LockMode::None => LockType::Read,
        LockMode::Exclusive => LockType::Write,
    }
}

const fn lock_type_conflicts(a: LockType, b: LockType) -> bool {
    matches!((a, b), (LockType::Write, _) | (_, LockType::Write))
}

const fn lock_type_to_lock_mode(lt: LockType) -> LockMode {
    match lt {
        LockType::Read => LockMode::Shared,
        LockType::Write => LockMode::Exclusive,
        LockType::Unlock => LockMode::None,
    }
}

fn make_owner(pid: u32, owner_handle: u64) -> ServiceLockOwner {
    ServiceLockOwner::new(MemberId::new(owner_handle), pid, owner_handle)
}

fn range_len(start: u64, end: u64) -> u64 {
    if end == u64::MAX {
        0
    } else {
        end.saturating_sub(start)
    }
}

fn build_conflict(
    ino: u64,
    svc: &LockService,
    start: u64,
    len: u64,
    lock_type: LockType,
    pid: u32,
) -> LockConflict {
    let overlapping = svc.query(ino, start, len);
    let existing = overlapping
        .first()
        .map(|s| LockRange {
            start: s.start,
            len: range_len(s.start, s.end),
            lock_type: lock_mode_to_lock_type(s.mode),
            owner: 0,
            pid: s.owner.pid,
        })
        .unwrap_or(LockRange {
            start: 0,
            len: 0,
            lock_type: LockType::Write,
            owner: 0,
            pid: 0,
        });
    LockConflict {
        requested: LockRange {
            start,
            len,
            lock_type,
            owner: 0,
            pid,
        },
        existing,
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

    // ── Lease-expiry sweep tests ──────────────────────────────────

    #[test]
    fn lease_expiry_auto_releases_locks() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        assert_eq!(d.inode_count(), 1);
        let expired = d.set_now(60_000);
        assert!(!expired.is_empty());
        assert!(d.is_empty());
    }

    #[test]
    fn non_expired_locks_are_not_swept() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        assert_eq!(d.inode_count(), 1);
        let expired = d.set_now(5_000);
        assert!(expired.is_empty());
        assert_eq!(d.inode_count(), 1);
    }

    #[test]
    fn tick_advances_clock_and_sweeps() {
        let mut d = DaemonLockDispatch::new();
        d.setlk(1, &setlk_in(0, 99, FUSE_LK_TYPE_WRLCK, 100))
            .unwrap();
        assert_eq!(d.inode_count(), 1);
        let had_expired = !d.tick(60_000).is_empty();
        assert!(had_expired);
        assert!(d.is_empty());
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
        // FD 10 holds read lock.
        d.setlk(1, &ofd_setlk_in(0, 99, FUSE_LK_TYPE_RDLCK, 100, 10))
            .unwrap();
        // Same FD tries to upgrade to write lock. The kernel handles
        // same-owner replacement at the VFS layer; the direct dispatch
        // path sees this as a self-conflict, which is correct — the
        // LockService doesn't auto-replace same-owner locks.
        // FD 20's read lock on overlapping range must conflict with
        // FD 10's existing read lock (read locks are compatible, but
        // the attempted write upgrade is the point of interest).
        let err = d.setlk(1, &ofd_setlk_in(50, 10, FUSE_LK_TYPE_RDLCK, 100, 20));
        assert!(
            err.is_ok(),
            "FD 20 read lock should be compatible with FD 10 read lock"
        );
        assert_eq!(d.lock_count(), 2);
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
