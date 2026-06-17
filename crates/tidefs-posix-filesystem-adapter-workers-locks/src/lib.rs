#![no_std]
#![forbid(unsafe_code)]

//! P5-02 FUSE lock-wait worker pool (queue_class_6.lock_wait).
//!
//! Part of the P5-02 classified multipool topology for the userspace FUSE runtime.
//! This seam family is one of 10 explicit crate boundaries that separate ingress,
//! scheduling, workers, reply commit, and maintenance so they do not blur
//! into one daemon blob.
//!
//! Core lock types (LockType, LockRange, LockConflict, LockList, LockTracker)
//! are owned by tidefs-types-vfs-core and re-exported here for backward
//! compatibility. This crate adds FUSE-specific BSD flock extensions, the
//! LockBackend trait, and POSIX lock dispatch handlers.

extern crate alloc;

use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterRequestClass, PosixFilesystemAdapterRequestContextMirrorRecord,
};

/// Re-export all P5-02 request-queue types and runtime functions for this seam family.
pub const SEAM_FAMILY_DOC: &str = concat!("seam.", env!("CARGO_PKG_NAME"), ".    P5-02.v0");

#[must_use]
pub fn dispatch_lock_wait(
    ctx: PosixFilesystemAdapterRequestContextMirrorRecord,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    ctx
}

#[must_use]
pub fn is_lock_wait_request(ctx: &PosixFilesystemAdapterRequestContextMirrorRecord) -> bool {
    ctx.request_class == PosixFilesystemAdapterRequestClass::LockWait.as_u32()
}

#[must_use]
pub fn lock_wait_shard_key(nodeid: u64) -> u64 {
    nodeid
}

#[must_use]
pub fn is_blocking_lock(opcode: u32) -> bool {
    opcode == 33 // FUSE_SETLKW
}

// ── Core lock types re-exported from tidefs-types-vfs-core ───────────
//
// LockType, LockRange, LockConflict, LockList, and LockTracker are
// product-core types owned by tidefs-types-vfs-core.  This crate
// re-exports them for backward compatibility and adds FUSE-specific
// flock extensions, LockBackend trait, and POSIX lock dispatch handlers.
pub use tidefs_types_vfs_core::{LockConflict, LockList, LockRange, LockTracker, LockType};

// ── BSD flock() types ─────────────────────────────────────────────────

/// BSD `flock()` lock type (whole-file advisory lock, per-fd).
///
/// Unlike POSIX fcntl byte-range locks, BSD `flock()` locks the entire
/// file and is associated with the file descriptor, not the process.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FlockType {
    /// Shared lock (`LOCK_SH`).
    Shared = 0,
    /// Exclusive lock (`LOCK_EX`).
    Exclusive = 1,
}

impl FlockType {
    #[must_use]
    pub const fn from_libc(value: i32) -> Option<Self> {
        match value {
            1  /* LOCK_SH */ => Some(Self::Shared),
            2  /* LOCK_EX */ => Some(Self::Exclusive),
            _ => None,
        }
    }
}

/// Owner identity for a BSD `flock()`.
///
/// Because flock is per-fd, the owner is the FUSE `lock_owner` value
/// (derived from the fd's file pointer) rather than a process PID.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlockOwner {
    pub owner_fd: u64,
}

impl FlockOwner {
    #[must_use]
    pub const fn new(owner_fd: u64) -> Self {
        Self { owner_fd }
    }
}

/// Errors returned by BSD flock operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlockError {
    /// The requested lock conflicts with an existing flock or POSIX lock.
    WouldBlock,
}

// ── BSD flock free functions (operate on core LockTracker) ────────────

/// Acquire a BSD flock on `ino`.
///
/// Shared flocks coexist with other shared flocks but conflict with
/// exclusive flocks. Any POSIX byte-range lock on the same inode
/// conflicts with an exclusive flock (and vice versa).
///
/// Returns `Err(FlockError::WouldBlock)` on conflict.
pub fn tracker_acquire_flock(
    tracker: &mut LockTracker,
    dataset_mount_id: u64,
    ino: u64,
    flock_type: FlockType,
    owner: FlockOwner,
) -> Result<(), FlockError> {
    let lock_type = match flock_type {
        FlockType::Shared => LockType::Read,
        FlockType::Exclusive => LockType::Write,
    };
    // Whole-file lock: start=0, len=0 (EOF).
    let range = LockRange::new(0, 0, lock_type, 0, owner.owner_fd as u32);
    tracker
        .acquire(dataset_mount_id, ino, range)
        .map_err(|_| FlockError::WouldBlock)
}

/// Release the BSD flock on `ino` held by `owner`.
///
/// Does nothing when no flock is held by this owner on this inode.
pub fn tracker_release_flock(tracker: &mut LockTracker, dataset_mount_id: u64, ino: u64, owner: FlockOwner) {
    let range = LockRange::unlock(0, 0, owner.owner_fd as u32);
    tracker.release(dataset_mount_id, ino, range);
}

/// Check whether `requested` would conflict with an existing BSD
/// flock or POSIX lock on `ino`.
///
/// Returns `Some(conflict)` when a conflict exists, or `None` when
/// the lock could be acquired.
#[must_use]
pub fn tracker_query_flock_conflict(
    tracker: &LockTracker,
    dataset_mount_id: u64,
    ino: u64,
    flock_type: FlockType,
    owner: FlockOwner,
) -> Option<LockConflict> {
    let lock_type = match flock_type {
        FlockType::Shared => LockType::Read,
        FlockType::Exclusive => LockType::Write,
    };
    let requested = LockRange::new(0, 0, lock_type, 0, owner.owner_fd as u32);
    tracker.query_conflict(dataset_mount_id, ino, requested)
}

/// Dispatch a BSD flock acquire/release through `tracker`.
pub fn dispatch_flock(
    tracker: &mut LockTracker,
    dataset_mount_id: u64,
    ino: u64,
    flock_type: FlockType,
    owner: FlockOwner,
) -> Result<(), FlockError> {
    tracker_acquire_flock(tracker, dataset_mount_id, ino, flock_type, owner)
}

// ── Lock operation error type ──────────────────────────────────────────

/// Errors returned by lock dispatch handlers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockError {
    /// The requested lock conflicts with an existing lock held by another
    /// process.
    Conflict(LockConflict),
    /// The lock type value is not a valid F_RDLCK / F_WRLCK / F_UNLCK.
    InvalidLockType(u32),
}

// ── LockBackend trait ──────────────────────────────────────────────────

/// Trait for accessing the lock registry from FUSE dispatch handlers.
///
/// Implementations typically wrap a [`LockTracker`] behind interior
/// mutability or provide direct `&mut` access.
pub trait LockBackend {
    /// Return a shared reference to the lock tracker (for getlk queries).
    fn lock_tracker(&self) -> &LockTracker;

    /// Return a mutable reference to the lock tracker (for setlk acquire /
    /// release).
    fn lock_tracker_mut(&mut self) -> &mut LockTracker;
}

// ── getlk handler ──────────────────────────────────────────────────────

/// Query for a conflicting lock on `ino`.
///
/// Returns `Ok(None)` (= `F_UNLCK`) when no conflict exists, or
/// `Ok(Some(conflicting_lock))` with the existing [`LockRange`] that would
/// block the requested lock.
///
/// Per POSIX, an `F_UNLCK` request always returns no conflict.
pub fn handle_getlk<B: LockBackend>(
    backend: &B,
    dataset_mount_id: u64,
    ino: u64,
    lock_type: LockType,
    start: u64,
    len: u64,
    pid: u32,
) -> Result<Option<LockRange>, LockError> {
    if lock_type == LockType::Unlock {
        // unlock always succeeds; no conflict to report
        return Ok(None);
    }
    let requested = LockRange::new(start, len, lock_type, 0, pid);
    Ok(backend
        .lock_tracker()
        .query_conflict(dataset_mount_id, ino, requested)
        .map(|conflict| conflict.existing))
}

// ── setlk handler ──────────────────────────────────────────────────────

/// Acquire a non-blocking lock on `ino`.
///
/// Returns `Err(LockError::Conflict(conflict))` when the lock cannot be
/// acquired immediately. The caller should map this to `EAGAIN` /
/// `EWOULDBLOCK` in the FUSE reply.
///
/// When `lock_type` is [`LockType::Unlock`], the matching lock range held
/// by `pid` is released instead and no conflict is possible.
pub fn handle_setlk<B: LockBackend>(
    backend: &mut B,
    dataset_mount_id: u64,
    ino: u64,
    lock_type: LockType,
    start: u64,
    len: u64,
    pid: u32,
) -> Result<(), LockError> {
    let requested = LockRange::new(start, len, lock_type, 0, pid);
    backend
        .lock_tracker_mut()
        .acquire(dataset_mount_id, ino, requested)
        .map_err(LockError::Conflict)
}

// ── setlkw handler ─────────────────────────────────────────────────────

/// Acquire a blocking lock on `ino`.
///
/// For the initial implementation this behaves identically to
/// [`handle_setlk`]. The blocking / retry loop is managed by the dispatch
/// layer above.
pub fn handle_setlkw<B: LockBackend>(
    backend: &mut B,
    dataset_mount_id: u64,
    ino: u64,
    lock_type: LockType,
    start: u64,
    len: u64,
    pid: u32,
) -> Result<(), LockError> {
    handle_setlk(backend, dataset_mount_id, ino, lock_type, start, len, pid)
}

// ── Dispatch wrappers ──────────────────────────────────────────────────

/// Dispatch a FUSE_GETLK request through `backend`.
pub fn dispatch_getlk<B: LockBackend>(
    backend: &B,
    dataset_mount_id: u64,
    ino: u64,
    lock_type: LockType,
    start: u64,
    len: u64,
    pid: u32,
) -> Result<Option<LockRange>, LockError> {
    handle_getlk(backend, dataset_mount_id, ino, lock_type, start, len, pid)
}

/// Dispatch a FUSE_SETLK request through `backend`.
pub fn dispatch_setlk<B: LockBackend>(
    backend: &mut B,
    dataset_mount_id: u64,
    ino: u64,
    lock_type: LockType,
    start: u64,
    len: u64,
    pid: u32,
) -> Result<(), LockError> {
    handle_setlk(backend, dataset_mount_id, ino, lock_type, start, len, pid)
}

/// Dispatch a FUSE_SETLKW request through `backend`.
pub fn dispatch_setlkw<B: LockBackend>(
    backend: &mut B,
    dataset_mount_id: u64,
    ino: u64,
    lock_type: LockType,
    start: u64,
    len: u64,
    pid: u32,
) -> Result<(), LockError> {
    handle_setlkw(backend, dataset_mount_id, ino, lock_type, start, len, pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_posix_filesystem_adapter_core::PosixFilesystemAdapterShardKeyPolicy;

    #[test]
    fn is_lock_wait_detects_correct_class() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            request_class: PosixFilesystemAdapterRequestClass::LockWait.as_u32(),
            shard_key_policy: PosixFilesystemAdapterShardKeyPolicy::LockScope.as_u32(),
            nodeid: 1,
            ..Default::default()
        };
        assert!(is_lock_wait_request(&ctx));
    }

    #[test]
    fn is_lock_wait_rejects_other_class() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        assert!(!is_lock_wait_request(&ctx));
    }

    #[test]
    fn dispatch_preserves_context() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 400,
            nodeid: 1,
            request_class: PosixFilesystemAdapterRequestClass::LockWait.as_u32(),
            shard_key_policy: PosixFilesystemAdapterShardKeyPolicy::LockScope.as_u32(),
            ..Default::default()
        };
        let dispatched = dispatch_lock_wait(ctx);
        assert_eq!(dispatched.unique, 400);
    }

    #[test]
    fn setlkw_is_blocking() {
        assert!(is_blocking_lock(33)); // FUSE_SETLKW
        assert!(!is_blocking_lock(31)); // FUSE_GETLK
        assert!(!is_blocking_lock(32)); // FUSE_SETLK
    }

    #[test]
    fn shard_key_is_nodeid() {
        assert_eq!(lock_wait_shard_key(5), 5);
    }

    #[test]
    fn lock_type_matches_linux_fcntl_values() {
        assert_eq!(LockType::from_fcntl(0), Some(LockType::Read));
        assert_eq!(LockType::from_fcntl(1), Some(LockType::Write));
        assert_eq!(LockType::from_fcntl(2), Some(LockType::Unlock));
        assert_eq!(LockType::Write.as_fcntl(), LockType::F_WRLCK);
        assert_eq!(LockType::from_fcntl(9), None);
    }

    #[test]
    fn single_lock_acquire_tracks_range() {
        let mut tracker = LockTracker::new();
        tracker.acquire(1, 7, LockRange::write(10, 20, 100)).unwrap();

        let locks = tracker.locks_for_mount_inode(1, 7).unwrap().locks();
        assert_eq!(locks, &[LockRange::write(10, 20, 100)]);
    }

    #[test]
    fn read_locks_from_different_processes_are_compatible() {
        let mut tracker = LockTracker::new();
        tracker.acquire(1, 7, LockRange::read(0, 100, 100)).unwrap();
        tracker.acquire(1, 7, LockRange::read(50, 10, 200)).unwrap();

        assert_eq!(tracker.locks_for_mount_inode(1, 7).unwrap().len(), 2);
    }

    #[test]
    fn read_write_conflict_reports_existing_lock() {
        let mut tracker = LockTracker::new();
        let existing = LockRange::read(0, 100, 100);
        let requested = LockRange::write(50, 10, 200);
        tracker.acquire(1, 7, existing).unwrap();

        let conflict = tracker.acquire(1, 7, requested).unwrap_err();
        assert_eq!(
            conflict,
            LockConflict {
                requested,
                existing
            }
        );
    }

    #[test]
    fn write_write_conflict_reports_existing_lock() {
        let mut tracker = LockTracker::new();
        let existing = LockRange::write(0, 100, 100);
        let requested = LockRange::write(99, 100, 200);
        tracker.acquire(1, 7, existing).unwrap();

        let conflict = tracker.acquire(1, 7, requested).unwrap_err();
        assert_eq!(conflict.existing, existing);
        assert_eq!(conflict.requested, requested);
    }

    #[test]
    fn unlock_splits_existing_range() {
        let mut tracker = LockTracker::new();
        tracker.acquire(1, 7, LockRange::write(0, 100, 100)).unwrap();

        tracker.release(1, 7, LockRange::unlock(40, 20, 100));

        assert_eq!(
            tracker.locks_for_mount_inode(1, 7).unwrap().locks(),
            &[LockRange::write(0, 40, 100), LockRange::write(60, 40, 100)]
        );
    }

    #[test]
    fn adjacent_unlock_reacquire_merges_ranges() {
        let mut list = LockList::new();
        list.acquire(LockRange::write(0, 10, 100)).unwrap();
        list.acquire(LockRange::write(10, 10, 100)).unwrap();

        assert_eq!(list.locks(), &[LockRange::write(0, 20, 100)]);
    }

    #[test]
    fn query_returns_conflicting_lock_without_modifying_tracker() {
        let mut tracker = LockTracker::new();
        let existing = LockRange::write(0, 0, 100);
        let requested = LockRange::read(1000, 1, 200);
        tracker.acquire(1, 7, existing).unwrap();

        let conflict = tracker.query_conflict(1, 7, requested).unwrap();
        assert_eq!(
            conflict,
            LockConflict {
                requested,
                existing
            }
        );
        assert_eq!(tracker.locks_for_mount_inode(1, 7).unwrap().locks(), &[existing]);
    }

    #[test]
    fn release_by_pid_clears_all_process_locks() {
        let mut tracker = LockTracker::new();
        tracker.acquire(1, 7, LockRange::read(0, 10, 100)).unwrap();
        tracker.acquire(1, 8, LockRange::write(0, 10, 100)).unwrap();
        tracker.acquire(1, 8, LockRange::read(20, 10, 200)).unwrap();

        tracker.release_by_pid(1, 100);

        assert!(tracker.locks_for_mount_inode(1, 7).is_none());
        assert_eq!(
            tracker.locks_for_mount_inode(1, 8).unwrap().locks(),
            &[LockRange::read(20, 10, 200)]
        );
    }

    #[test]
    fn overlapping_replace_preserves_non_overlapping_segments() {
        let mut tracker = LockTracker::new();
        tracker.acquire(1, 7, LockRange::read(0, 100, 100)).unwrap();

        tracker.acquire(1, 7, LockRange::write(25, 50, 100)).unwrap();

        assert_eq!(
            tracker.locks_for_mount_inode(1, 7).unwrap().locks(),
            &[
                LockRange::read(0, 25, 100),
                LockRange::write(25, 50, 100),
                LockRange::read(75, 25, 100),
            ]
        );
    }

    #[test]
    fn eof_lock_unlock_keeps_tail_when_unlock_is_finite() {
        let mut tracker = LockTracker::new();
        tracker.acquire(1, 7, LockRange::write(10, 0, 100)).unwrap();

        tracker.release(1, 7, LockRange::unlock(20, 10, 100));

        assert_eq!(
            tracker.locks_for_mount_inode(1, 7).unwrap().locks(),
            &[LockRange::write(10, 10, 100), LockRange::write(30, 0, 100)]
        );
    }

    // ── release_by_owner / release_by_owner_inode tests ──────────────

    #[test]
    fn release_by_owner_list_clears_matching_owner_locks() {
        let mut list = LockList::new();
        list.acquire(LockRange::new(0, 10, LockType::Write, 42, 100))
            .unwrap();
        list.acquire(LockRange::new(20, 10, LockType::Read, 42, 100))
            .unwrap();
        list.acquire(LockRange::new(40, 10, LockType::Write, 99, 100))
            .unwrap();

        list.release_by_owner(42);

        assert_eq!(
            list.locks(),
            &[LockRange::new(40, 10, LockType::Write, 99, 100)]
        );
    }

    #[test]
    fn release_by_owner_inode_clears_all_owner_locks() {
        let mut tracker = LockTracker::new();
        tracker
            .acquire(1, 7, LockRange::new(0, 50, LockType::Write, 1, 100))
            .unwrap();
        tracker
            .acquire(1, 7, LockRange::new(100, 50, LockType::Read, 1, 100))
            .unwrap();

        tracker.release_by_owner_mount_inode(1, 7, 1);

        assert!(tracker.locks_for_mount_inode(1, 7).is_none());
    }

    #[test]
    fn release_by_owner_inode_preserves_other_owners() {
        let mut tracker = LockTracker::new();
        tracker
            .acquire(1, 7, LockRange::new(0, 50, LockType::Write, 1, 100))
            .unwrap();
        tracker
            .acquire(1, 7, LockRange::new(60, 40, LockType::Read, 2, 200))
            .unwrap();

        tracker.release_by_owner_mount_inode(1, 7, 1);

        let locks = tracker.locks_for_mount_inode(1, 7).unwrap();
        assert_eq!(locks.len(), 1);
        assert_eq!(
            locks.locks(),
            &[LockRange::new(60, 40, LockType::Read, 2, 200)]
        );
    }

    #[test]
    fn release_by_owner_inode_preserves_other_inodes() {
        let mut tracker = LockTracker::new();
        tracker
            .acquire(1, 7, LockRange::new(0, 50, LockType::Write, 1, 100))
            .unwrap();
        tracker
            .acquire(1, 9, LockRange::new(0, 50, LockType::Write, 1, 100))
            .unwrap();

        tracker.release_by_owner_mount_inode(1, 7, 1);

        assert!(tracker.locks_for_mount_inode(1, 7).is_none());
        assert_eq!(tracker.locks_for_mount_inode(1, 9).unwrap().len(), 1);
    }

    #[test]
    fn release_by_owner_no_owner_match_is_noop() {
        let mut tracker = LockTracker::new();
        tracker
            .acquire(1, 7, LockRange::new(0, 50, LockType::Write, 1, 100))
            .unwrap();

        tracker.release_by_owner_mount_inode(1, 7, 999);

        assert_eq!(tracker.locks_for_mount_inode(1, 7).unwrap().len(), 1);
    }

    #[test]
    fn adjacent_locks_different_owner_do_not_merge() {
        let mut list = LockList::new();
        list.acquire(LockRange::new(0, 10, LockType::Write, 1, 100))
            .unwrap();
        list.acquire(LockRange::new(10, 10, LockType::Write, 2, 100))
            .unwrap();

        assert_eq!(list.len(), 2);
        assert_eq!(
            list.locks(),
            &[
                LockRange::new(0, 10, LockType::Write, 1, 100),
                LockRange::new(10, 10, LockType::Write, 2, 100),
            ]
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Lock handler tests
    // ═══════════════════════════════════════════════════════════════════

    /// Stub backend that owns a `LockTracker` directly.
    struct StubLockBackend {
        tracker: LockTracker,
        #[allow(dead_code)]
        mount_id: u64,
    }

    impl LockBackend for StubLockBackend {
        fn lock_tracker(&self) -> &LockTracker {
            &self.tracker
        }

        fn lock_tracker_mut(&mut self) -> &mut LockTracker {
            &mut self.tracker
        }
    }

    impl StubLockBackend {
        fn new() -> Self {
            Self {
                tracker: LockTracker::new(),
                mount_id: 1,
            }
        }
    }

    // ── handle_getlk tests ─────────────────────────────────────────

    #[test]
    fn getlk_no_locks_returns_none() {
        let backend = StubLockBackend::new();
        let result = handle_getlk(&backend, 1, 1, LockType::Write, 0, 10, 100);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn getlk_unlock_always_returns_none() {
        let backend = StubLockBackend::new();
        // Even with existing locks, an unlock query returns no conflict
        let result = handle_getlk(&backend, 1, 1, LockType::Unlock, 0, 10, 100);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn getlk_returns_conflicting_lock() {
        let mut backend = StubLockBackend::new();
        // Acquire a write lock
        backend
            .tracker
            .acquire(1, 1, LockRange::write(0, 100, 200))
            .unwrap();
        // Query with a conflicting read lock
        let result = handle_getlk(&backend, 1, 1, LockType::Read, 50, 10, 300);
        let conflict = result.unwrap().unwrap();
        assert_eq!(conflict.lock_type, LockType::Write);
        assert_eq!(conflict.pid, 200);
        assert_eq!(conflict.start, 0);
        assert_eq!(conflict.len, 100);
    }

    #[test]
    fn getlk_no_conflict_for_compatible_read_locks() {
        let mut backend = StubLockBackend::new();
        backend
            .tracker
            .acquire(1, 1, LockRange::read(0, 100, 200))
            .unwrap();
        let result = handle_getlk(&backend, 1, 1, LockType::Read, 50, 10, 300);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn getlk_no_conflict_for_non_overlapping_ranges() {
        let mut backend = StubLockBackend::new();
        backend
            .tracker
            .acquire(1, 1, LockRange::write(0, 10, 100))
            .unwrap();
        let result = handle_getlk(&backend, 1, 1, LockType::Write, 20, 10, 200);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn getlk_same_pid_no_conflict() {
        let mut backend = StubLockBackend::new();
        backend
            .tracker
            .acquire(1, 1, LockRange::write(0, 100, 100))
            .unwrap();
        // Same PID requesting overlapping write — POSIX allows same-process
        // lock upgrade/replacement without conflict reporting
        let result = handle_getlk(&backend, 1, 1, LockType::Write, 50, 20, 100);
        assert_eq!(result, Ok(None));
    }

    // ── handle_setlk tests ─────────────────────────────────────────

    #[test]
    fn setlk_acquires_lock_successfully() {
        let mut backend = StubLockBackend::new();
        let result = handle_setlk(&mut backend, 1, 1, LockType::Write, 0, 100, 100);
        assert_eq!(result, Ok(()));
        assert!(!backend.tracker.is_empty());
        let locks = backend.tracker.locks_for_mount_inode(1, 1).unwrap();
        assert_eq!(locks.len(), 1);
        assert_eq!(locks.locks()[0].lock_type, LockType::Write);
    }

    #[test]
    fn setlk_returns_conflict_on_write_write() {
        let mut backend = StubLockBackend::new();
        handle_setlk(&mut backend, 1, 1, LockType::Write, 0, 100, 100).unwrap();
        let result = handle_setlk(&mut backend, 1, 1, LockType::Write, 50, 20, 200);
        match result {
            Err(LockError::Conflict(conflict)) => {
                assert_eq!(conflict.existing.pid, 100);
                assert_eq!(conflict.requested.pid, 200);
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn setlk_unlock_releases_existing_lock() {
        let mut backend = StubLockBackend::new();
        handle_setlk(&mut backend, 1, 1, LockType::Write, 0, 100, 100).unwrap();
        assert_eq!(backend.tracker.inode_count(), 1);
        let result = handle_setlk(&mut backend, 1, 1, LockType::Unlock, 0, 100, 100);
        assert_eq!(result, Ok(()));
        assert!(backend.tracker.is_empty());
    }

    #[test]
    fn setlk_same_pid_overlapping_write_replaces() {
        let mut backend = StubLockBackend::new();
        handle_setlk(&mut backend, 1, 1, LockType::Write, 0, 100, 100).unwrap();
        // Same PID, overlapping range — should replace rather than conflict
        let result = handle_setlk(&mut backend, 1, 1, LockType::Write, 50, 20, 100);
        assert_eq!(result, Ok(()));
        let locks = backend.tracker.locks_for_mount_inode(1, 1).unwrap().locks();
        assert_eq!(locks.len(), 1);
    }

    #[test]
    fn setlk_multiple_inodes_independent() {
        let mut backend = StubLockBackend::new();
        handle_setlk(&mut backend, 1, 1, LockType::Write, 0, 100, 100).unwrap();
        handle_setlk(&mut backend, 1, 2, LockType::Write, 0, 100, 200).unwrap();
        assert_eq!(backend.tracker.inode_count(), 2);
    }

    // ── handle_setlkw tests ────────────────────────────────────────

    #[test]
    fn setlkw_behaves_same_as_setlk_on_success() {
        let mut backend = StubLockBackend::new();
        let result = handle_setlkw(&mut backend, 1, 1, LockType::Read, 0, 50, 100);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn setlkw_returns_conflict_same_as_setlk() {
        let mut backend = StubLockBackend::new();
        handle_setlk(&mut backend, 1, 1, LockType::Write, 0, 100, 100).unwrap();
        let result = handle_setlkw(&mut backend, 1, 1, LockType::Read, 50, 10, 200);
        assert!(matches!(result, Err(LockError::Conflict(_))));
    }

    // ── dispatch wrappers ──────────────────────────────────────────

    #[test]
    fn dispatch_getlk_delegates_to_handle_getlk() {
        let backend = StubLockBackend::new();
        let result = dispatch_getlk(&backend, 1, 1, LockType::Write, 0, 10, 100);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn dispatch_setlk_delegates_to_handle_setlk() {
        let mut backend = StubLockBackend::new();
        let result = dispatch_setlk(&mut backend, 1, 1, LockType::Write, 0, 100, 100);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn dispatch_setlkw_delegates_to_handle_setlkw() {
        let mut backend = StubLockBackend::new();
        let result = dispatch_setlkw(&mut backend, 1, 1, LockType::Read, 0, 50, 100);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn dispatch_setlkw_preserves_conflict() {
        let mut backend = StubLockBackend::new();
        dispatch_setlk(&mut backend, 1, 1, LockType::Write, 0, 100, 100).unwrap();
        let result = dispatch_setlkw(&mut backend, 1, 1, LockType::Read, 50, 10, 200);
        assert!(matches!(result, Err(LockError::Conflict(_))));
    }
}
