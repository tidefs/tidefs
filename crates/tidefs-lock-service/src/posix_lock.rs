// SPDX-License-Identifier: Apache-2.0
//! POSIX byte-range lock manager with deadlock detection.
//!
//! Provides a local (non-clustered) per-inode lock table implementing
//! F_SETLK, F_SETLKW, and F_GETLK semantics as specified by POSIX fcntl
//! advisory record locking. Len=0 on a LockRange means "to EOF" (u64::MAX).
//!
//! ## Deadlock Detection
//!
//! Before parking a blocking (F_SETLKW) request, the lock manager builds a
//! wait-for-graph across all inodes. If placing the waiter would create a
//! directed cycle among lock-holder/waiter PIDs, the request is rejected with
//! `PosixLockError::Deadlock` (corresponding to POSIX EDEADLK).

use std::collections::{BTreeMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// LockRange — byte-range with POSIX len=0 → EOF semantics
// ---------------------------------------------------------------------------

/// A byte-range for POSIX advisory record locking.
///
/// `len == 0` carries the special POSIX meaning "lock to end of file" (EOF),
/// represented internally as `u64::MAX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockRange {
    pub start: u64,
    pub len: u64,
}

impl LockRange {
    /// Create a new range. If len is 0, the effective end is EOF (u64::MAX).
    pub const fn new(start: u64, len: u64) -> Self {
        Self { start, len }
    }

    /// The effective end of the range (exclusive).
    pub const fn end(self) -> u64 {
        if self.len == 0 {
            u64::MAX
        } else {
            self.start.saturating_add(self.len)
        }
    }

    /// True when two byte-ranges overlap.
    pub fn overlaps(&self, other: &LockRange) -> bool {
        let a1 = self.start;
        let b1 = self.end();
        let a2 = other.start;
        let b2 = other.end();
        a1 < b2 && a2 < b1
    }

    /// True when two ranges are directly adjacent (no gap between them).
    pub fn adjacent_to(&self, other: &LockRange) -> bool {
        self.end() == other.start || other.end() == self.start
    }

    /// Merge two ranges if they are adjacent or overlapping.
    /// Returns `Some(merged)` when ranges touch or overlap, `None` otherwise.
    pub fn merge_with(&self, other: &LockRange) -> Option<LockRange> {
        if !self.overlaps(other) && !self.adjacent_to(other) {
            return None;
        }
        let new_start = self.start.min(other.start);
        let new_end = self.end().max(other.end());
        let len = if new_end == u64::MAX {
            0
        } else {
            new_end.saturating_sub(new_start)
        };
        Some(LockRange {
            start: new_start,
            len,
        })
    }
}

// ---------------------------------------------------------------------------
// LockType — F_RDLCK / F_WRLCK / F_UNLCK
// ---------------------------------------------------------------------------

/// The type of a POSIX advisory record lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockType {
    /// F_RDLCK — shared read lock. Compatible with other Read locks only.
    Read,
    /// F_WRLCK — exclusive write lock. Conflicts with any lock.
    Write,
    /// F_UNLCK — release (not used for acquisition, only for unlock).
    Unlock,
}

impl LockType {
    /// Return true when two lock types are incompatible on an overlapping range.
    pub fn conflicts_with(&self, other: LockType) -> bool {
        matches!((self, other), (LockType::Write, _) | (_, LockType::Write))
    }
}

// ---------------------------------------------------------------------------
// LockEntry — a single lock record
// ---------------------------------------------------------------------------

/// Process identifier used as a lock owner.
pub type LockOwnerPid = u32;

/// A single advisory lock entry in the per-inode lock table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockEntry {
    pub range: LockRange,
    pub lock_type: LockType,
    pub owner_pid: LockOwnerPid,
}

impl LockEntry {
    pub const fn new(range: LockRange, lock_type: LockType, owner_pid: LockOwnerPid) -> Self {
        Self {
            range,
            lock_type,
            owner_pid,
        }
    }
}

// ---------------------------------------------------------------------------
// WokenWaiter — a parked blocking request that can now proceed
// ---------------------------------------------------------------------------

/// A blocked waiter that has been woken because its conflicting locks were
/// released. The caller should grant the lock and notify the FUSE request
/// identified by `opaque`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WokenWaiter {
    pub entry: LockEntry,
    pub opaque: u64,
}

// ---------------------------------------------------------------------------
// PosixLockError
// ---------------------------------------------------------------------------

/// Error returned by POSIX lock operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PosixLockError {
    /// Non-blocking request denied due to conflict (POSIX EAGAIN/EACCES).
    WouldBlock,
    /// Blocking request would create a deadlock cycle (POSIX EDEADLK).
    Deadlock,
    /// No matching lock found for release.
    NotFound,
}

// ---------------------------------------------------------------------------
// Internal waiter struct (not exposed)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Waiter {
    entry: LockEntry,
    opaque: u64,
}

// ---------------------------------------------------------------------------
// Per-inode state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct InodeState {
    /// Active locks sorted by start byte.
    locks: Vec<LockEntry>,
    /// Parked blocking waiters (FIFO order).
    waiters: VecDeque<Waiter>,
}

// ---------------------------------------------------------------------------
// PosixLockTable
// ---------------------------------------------------------------------------

/// A local (non-clustered) POSIX byte-range lock manager.
///
/// Maintains per-inode lock sets with O(n) conflict detection per inode,
/// adjacent-range merging on release, a FIFO blocking-wait queue, and
/// wait-for-graph deadlock detection.
///
/// # Examples
///
/// ```
/// use tidefs_lock_service::posix_lock::*;
///
/// let mut table = PosixLockTable::new();
///
/// // Acquire a write lock (non-blocking, succeeds)
/// let entry = LockEntry::new(LockRange::new(0, 100), LockType::Write, 1001);
/// assert!(table.acquire_lock(1, entry.clone(), false, 0).is_ok());
///
/// // F_GETLK: test for conflicting lock
/// let probe = LockRange::new(50, 10);
/// let conflict = table.test_lock(1, probe, LockType::Read);
/// assert!(conflict.is_some());
///
/// // Release and verify
/// let woken = table.release_lock(1, entry.range, 1001).unwrap();
/// assert!(woken.is_empty());
/// ```
#[derive(Clone, Debug, Default)]
pub struct PosixLockTable {
    inodes: BTreeMap<u64, InodeState>,
}

impl PosixLockTable {
    pub fn new() -> Self {
        Self {
            inodes: BTreeMap::new(),
        }
    }

    // -- Public API ----------------------------------------------------------

    /// Try to acquire a lock on `ino`.
    ///
    /// * `blocking = false` (F_SETLK): returns `Err(WouldBlock)` on conflict.
    /// * `blocking = true` (F_SETLKW): parks the request if it conflicts;
    ///   returns `Err(Deadlock)` if the wait would create a cycle.
    /// * `opaque` is returned in `WokenWaiter` for the caller to identify
    ///   the FUSE request when the waiter is later woken by `release_lock`.
    ///
    /// Returns `Ok(())` when the lock was granted immediately.
    pub fn acquire_lock(
        &mut self,
        ino: u64,
        entry: LockEntry,
        blocking: bool,
        opaque: u64,
    ) -> Result<(), PosixLockError> {
        if entry.lock_type == LockType::Unlock {
            // Unlock is handled by release_lock; silently ignore.
            return Ok(());
        }

        // Collect PIDs holding conflicting locks via an immutable lookup.
        let conflicting_pids: Vec<LockOwnerPid> = match self.inodes.get(&ino) {
            Some(state) => state
                .locks
                .iter()
                .filter(|existing| {
                    existing.range.overlaps(&entry.range)
                        && entry.lock_type.conflicts_with(existing.lock_type)
                })
                .map(|e| e.owner_pid)
                .collect(),
            None => Vec::new(),
        };

        if conflicting_pids.is_empty() {
            self.insert_lock(ino, entry);
            return Ok(());
        }

        if !blocking {
            return Err(PosixLockError::WouldBlock);
        }

        // Deadlock check before parking (uses immutable &self).
        if self.would_deadlock(ino, entry.owner_pid, &conflicting_pids) {
            return Err(PosixLockError::Deadlock);
        }

        // Re-acquire mutable access to park the waiter.
        self.inodes
            .entry(ino)
            .or_default()
            .waiters
            .push_back(Waiter { entry, opaque });
        Ok(())
    }

    /// Release a specific byte-range held by `owner_pid` on `ino`.
    ///
    /// Adjacent ranges held by the same owner with the same lock type are
    /// merged. Returns the list of waiters that can now be granted — the
    /// caller must grant them and notify the corresponding FUSE requests.
    pub fn release_lock(
        &mut self,
        ino: u64,
        range: LockRange,
        owner_pid: LockOwnerPid,
    ) -> Result<Vec<WokenWaiter>, PosixLockError> {
        let end = range.end();

        // Remove the lock from the inode state; scope the borrow.
        {
            let state = self.inodes.get_mut(&ino).ok_or(PosixLockError::NotFound)?;

            let idx = state
                .locks
                .iter()
                .position(|e| {
                    e.owner_pid == owner_pid && e.range.start == range.start && e.range.end() == end
                })
                .ok_or(PosixLockError::NotFound)?;

            state.locks.remove(idx);
        }

        // Merge adjacent ranges held by the same owner with the same type.
        self.merge_adjacent(ino, owner_pid);

        // Drain waiters whose conflicts have been resolved.
        let woken = self.drain_satisfied_waiters(ino);

        // GC empty inode state.
        if let Some(state) = self.inodes.get(&ino) {
            if state.locks.is_empty() && state.waiters.is_empty() {
                self.inodes.remove(&ino);
            }
        }

        Ok(woken)
    }

    /// F_GETLK: test whether a hypothetical lock would conflict.
    ///
    /// Returns the first conflicting `LockEntry` if the lock would be denied,
    /// or `None` if it would be granted.
    pub fn test_lock(&self, ino: u64, range: LockRange, lock_type: LockType) -> Option<LockEntry> {
        let state = self.inodes.get(&ino)?;
        state
            .locks
            .iter()
            .find(|existing| {
                existing.range.overlaps(&range) && lock_type.conflicts_with(existing.lock_type)
            })
            .cloned()
    }

    /// Release every lock held by `owner_pid` across all inodes.
    ///
    /// Returns the count of locks released.
    pub fn release_all_for_owner(&mut self, owner_pid: LockOwnerPid) -> usize {
        let mut released = 0usize;
        let inos: Vec<u64> = self.inodes.keys().copied().collect();
        for ino in inos {
            if let Some(state) = self.inodes.get_mut(&ino) {
                let before = state.locks.len();
                state.locks.retain(|e| e.owner_pid != owner_pid);
                released += before.saturating_sub(state.locks.len());

                if state.locks.is_empty() && state.waiters.is_empty() {
                    self.inodes.remove(&ino);
                }
            }
        }
        released
    }

    // -- Query helpers -------------------------------------------------------

    /// Return all active locks as `(ino, LockEntry)` pairs.
    pub fn all_locks(&self) -> Vec<(u64, LockEntry)> {
        let mut result = Vec::new();
        for (&ino, state) in &self.inodes {
            for entry in &state.locks {
                result.push((ino, entry.clone()));
            }
        }
        result.sort_by_key(|(ino, e)| (*ino, e.range.start));
        result
    }

    /// Return the number of parked (blocking) waiters across all inodes.
    pub fn waiter_count(&self) -> usize {
        self.inodes.values().map(|s| s.waiters.len()).sum()
    }

    /// Return the number of active (granted) locks across all inodes.
    pub fn lock_count(&self) -> usize {
        self.inodes.values().map(|s| s.locks.len()).sum()
    }

    /// Check whether an inode is present (has locks or waiters).
    pub fn has_inode(&self, ino: u64) -> bool {
        self.inodes.contains_key(&ino)
    }

    // -- Internal helpers ----------------------------------------------------

    fn insert_lock(&mut self, ino: u64, entry: LockEntry) {
        let state = self.inodes.entry(ino).or_default();
        state.locks.push(entry);
        state.locks.sort_by_key(|e| e.range.start);
    }

    /// Merge adjacent or overlapping ranges held by the same owner with the
    /// same lock type on `ino`.
    fn merge_adjacent(&mut self, ino: u64, owner_pid: LockOwnerPid) {
        let state = match self.inodes.get_mut(&ino) {
            Some(s) => s,
            None => return,
        };

        // Sort by start.
        state.locks.sort_by_key(|e| e.range.start);

        let mut merged: Vec<LockEntry> = Vec::with_capacity(state.locks.len());

        for entry in state.locks.drain(..) {
            if entry.owner_pid != owner_pid {
                merged.push(entry);
                continue;
            }

            if let Some(last) = merged.last_mut() {
                if last.owner_pid == owner_pid
                    && last.lock_type == entry.lock_type
                    && last.range.adjacent_to(&entry.range)
                {
                    // Merge into last.
                    if let Some(combined) = last.range.merge_with(&entry.range) {
                        last.range = combined;
                        continue;
                    }
                }
            }
            merged.push(entry);
        }

        state.locks = merged;
    }

    /// Try to grant locks to parked waiters whose conflicts are gone.
    /// Returns the list of successfully woken waiters.
    fn drain_satisfied_waiters(&mut self, ino: u64) -> Vec<WokenWaiter> {
        // Collect waiters that can now be granted and those still blocked.
        let to_grant = {
            let state = match self.inodes.get_mut(&ino) {
                Some(s) => s,
                None => return Vec::new(),
            };

            let mut grant = Vec::new();
            let mut waiting = VecDeque::new();

            while let Some(waiter) = state.waiters.pop_front() {
                let still_conflicts = state.locks.iter().any(|existing| {
                    existing.range.overlaps(&waiter.entry.range)
                        && waiter.entry.lock_type.conflicts_with(existing.lock_type)
                });

                if still_conflicts {
                    waiting.push_back(waiter);
                } else {
                    grant.push(waiter);
                }
            }

            state.waiters = waiting;
            grant
        };

        // Now insert granted locks (no borrow on self.inodes held).
        let mut woken = Vec::new();
        for waiter in to_grant {
            self.insert_lock(ino, waiter.entry.clone());
            woken.push(WokenWaiter {
                entry: waiter.entry,
                opaque: waiter.opaque,
            });
        }

        woken
    }

    // -- Deadlock detection --------------------------------------------------

    /// Build a wait-for-graph across all inodes and check whether adding
    /// an edge from `waiter_pid` to each of `holders` creates a directed
    /// cycle reachable from `waiter_pid`.
    fn would_deadlock(
        &self,
        _current_ino: u64,
        waiter_pid: LockOwnerPid,
        holders: &[LockOwnerPid],
    ) -> bool {
        // Collect all waiter → holder edges across every inode.
        let mut edges: Vec<(LockOwnerPid, LockOwnerPid)> = Vec::new();

        // Proposed edges: waiter → each current holder.
        for &holder in holders {
            if holder != waiter_pid {
                edges.push((waiter_pid, holder));
            }
        }

        // Existing edges from parked waiters.
        for (&_ino, state) in &self.inodes {
            for waiter in &state.waiters {
                for existing in &state.locks {
                    if existing.range.overlaps(&waiter.entry.range)
                        && waiter.entry.lock_type.conflicts_with(existing.lock_type)
                        && existing.owner_pid != waiter.entry.owner_pid
                    {
                        edges.push((waiter.entry.owner_pid, existing.owner_pid));
                    }
                }
            }
        }

        // DFS cycle detection from waiter_pid.
        let mut visited = HashSet::new();
        let mut stack = HashSet::new();
        Self::dfs_cycle(waiter_pid, &edges, &mut visited, &mut stack)
    }

    fn dfs_cycle(
        node: LockOwnerPid,
        edges: &[(LockOwnerPid, LockOwnerPid)],
        visited: &mut HashSet<LockOwnerPid>,
        stack: &mut HashSet<LockOwnerPid>,
    ) -> bool {
        if stack.contains(&node) {
            return true;
        }
        if visited.contains(&node) {
            return false;
        }
        visited.insert(node);
        stack.insert(node);

        for &(from, to) in edges {
            if from == node && Self::dfs_cycle(to, edges, visited, stack) {
                return true;
            }
        }

        stack.remove(&node);
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn r(start: u64, len: u64) -> LockRange {
        LockRange::new(start, len)
    }

    fn rd(start: u64, len: u64, pid: LockOwnerPid) -> LockEntry {
        LockEntry::new(r(start, len), LockType::Read, pid)
    }

    fn wr(start: u64, len: u64, pid: LockOwnerPid) -> LockEntry {
        LockEntry::new(r(start, len), LockType::Write, pid)
    }

    // -- LockRange tests ---------------------------------------------------

    #[test]
    fn lockrange_eof_len_zero() {
        assert_eq!(r(0, 0).end(), u64::MAX);
        assert_eq!(r(100, 0).end(), u64::MAX);
        assert_eq!(r(0, 50).end(), 50);
        assert_eq!(r(100, 50).end(), 150);
    }

    #[test]
    fn lockrange_overlaps() {
        assert!(r(0, 100).overlaps(&r(50, 100)));
        assert!(r(0, 100).overlaps(&r(0, 10)));
        assert!(!r(0, 100).overlaps(&r(100, 50)));
        assert!(!r(0, 100).overlaps(&r(200, 50)));
        // EOF case
        assert!(r(50, 0).overlaps(&r(100, 50)));
        assert!(r(0, 100).overlaps(&r(50, 0)));
    }

    #[test]
    fn lockrange_adjacent_merge() {
        assert!(r(0, 100).adjacent_to(&r(100, 50)));
        assert!(r(100, 50).adjacent_to(&r(0, 100)));
        assert!(!r(0, 100).adjacent_to(&r(101, 50)));

        let merged = r(0, 100).merge_with(&r(100, 50)).unwrap();
        assert_eq!(merged.start, 0);
        assert_eq!(merged.len, 150);

        let merged = r(100, 50).merge_with(&r(0, 100)).unwrap();
        assert_eq!(merged.start, 0);
        assert_eq!(merged.len, 150);

        // EOF merge
        let merged = r(0, 100).merge_with(&r(100, 0)).unwrap();
        assert_eq!(merged.start, 0);
        assert_eq!(merged.len, 0); // to EOF
    }

    // -- Single-lock acquire / release ------------------------------------

    #[test]
    fn single_write_lock_acquire_release() {
        let mut tbl = PosixLockTable::new();
        let e = wr(0, 4096, 100);
        assert_eq!(tbl.acquire_lock(1, e.clone(), false, 0), Ok(()));
        assert_eq!(tbl.lock_count(), 1);

        let woken = tbl.release_lock(1, e.range, 100).unwrap();
        assert!(woken.is_empty());
        assert_eq!(tbl.lock_count(), 0);
        assert!(!tbl.has_inode(1));
    }

    #[test]
    fn multiple_read_locks_compatible() {
        let mut tbl = PosixLockTable::new();
        assert_eq!(tbl.acquire_lock(1, rd(0, 100, 10), false, 0), Ok(()));
        assert_eq!(tbl.acquire_lock(1, rd(0, 100, 20), false, 0), Ok(()));
        assert_eq!(tbl.lock_count(), 2);
    }

    #[test]
    fn read_then_write_conflict() {
        let mut tbl = PosixLockTable::new();
        assert_eq!(tbl.acquire_lock(1, rd(0, 100, 10), false, 0), Ok(()));
        assert_eq!(
            tbl.acquire_lock(1, wr(50, 10, 20), false, 0),
            Err(PosixLockError::WouldBlock)
        );
        assert_eq!(tbl.lock_count(), 1);
    }

    #[test]
    fn write_then_read_conflict() {
        let mut tbl = PosixLockTable::new();
        assert_eq!(tbl.acquire_lock(1, wr(0, 100, 10), false, 0), Ok(()));
        assert_eq!(
            tbl.acquire_lock(1, rd(50, 10, 20), false, 0),
            Err(PosixLockError::WouldBlock)
        );
    }

    #[test]
    fn non_overlapping_write_locks_succeed() {
        let mut tbl = PosixLockTable::new();
        assert_eq!(tbl.acquire_lock(1, wr(0, 100, 10), false, 0), Ok(()));
        assert_eq!(tbl.acquire_lock(1, wr(100, 100, 20), false, 0), Ok(()));
        assert_eq!(tbl.lock_count(), 2);
    }

    // -- Adjacent-range merge on unlock ----------------------------------

    #[test]
    fn adjacent_writes_merge_on_release() {
        let mut tbl = PosixLockTable::new();
        // Acquire two adjacent write ranges for the same owner.
        tbl.acquire_lock(1, wr(0, 100, 10), false, 0).unwrap();
        tbl.acquire_lock(1, wr(100, 100, 10), false, 0).unwrap();
        assert_eq!(tbl.lock_count(), 2);

        // Release the first range — the two should merge into one.
        let woken = tbl.release_lock(1, r(0, 100), 10).unwrap();
        assert!(woken.is_empty());
        assert_eq!(tbl.lock_count(), 1);

        let locks = tbl.all_locks();
        assert_eq!(locks.len(), 1);
        // The remaining lock should cover 100..200
        assert_eq!(locks[0].1.range.start, 100);
        assert_eq!(locks[0].1.range.len, 100);

        // Release the second and the inode should be GC'd
        tbl.release_lock(1, r(100, 100), 10).unwrap();
        assert!(!tbl.has_inode(1));
    }

    #[test]
    fn merge_only_same_owner_and_type() {
        let mut tbl = PosixLockTable::new();
        tbl.acquire_lock(1, wr(0, 100, 10), false, 0).unwrap();
        tbl.acquire_lock(1, rd(100, 100, 10), false, 0).unwrap();
        assert_eq!(tbl.lock_count(), 2);

        tbl.release_lock(1, r(0, 100), 10).unwrap();
        // Should NOT merge: different lock types.
        assert_eq!(tbl.lock_count(), 1);

        let locks = tbl.all_locks();
        assert_eq!(locks[0].1.lock_type, LockType::Read);
    }

    // -- F_GETLK (test_lock) ---------------------------------------------

    #[test]
    fn getlk_returns_conflicting_lock() {
        let mut tbl = PosixLockTable::new();
        tbl.acquire_lock(1, wr(100, 200, 10), false, 0).unwrap();
        tbl.acquire_lock(1, rd(400, 100, 20), false, 0).unwrap();

        let conflict = tbl.test_lock(1, r(150, 10), LockType::Read);
        let c = conflict.unwrap();
        assert_eq!(c.owner_pid, 10);
        assert_eq!(c.lock_type, LockType::Write);

        let conflict = tbl.test_lock(1, r(450, 10), LockType::Write);
        let c = conflict.unwrap();
        assert_eq!(c.owner_pid, 20);

        let no_conflict = tbl.test_lock(1, r(300, 50), LockType::Write);
        assert!(no_conflict.is_none());
    }

    // -- Blocking wait with wake -----------------------------------------

    #[test]
    fn blocking_wait_woken_on_release() {
        let mut tbl = PosixLockTable::new();

        // Process A holds write lock.
        tbl.acquire_lock(1, wr(0, 100, 10), false, 0).unwrap();

        // Process B tries blocking write (will park).
        tbl.acquire_lock(1, wr(50, 50, 20), true, 42).unwrap();
        assert_eq!(tbl.lock_count(), 1);
        assert_eq!(tbl.waiter_count(), 1);

        // Process A releases.
        let woken = tbl.release_lock(1, r(0, 100), 10).unwrap();
        assert_eq!(woken.len(), 1);
        assert_eq!(woken[0].opaque, 42);
        assert_eq!(woken[0].entry.owner_pid, 20);
        assert_eq!(tbl.lock_count(), 1); // B's lock is now granted
        assert_eq!(tbl.waiter_count(), 0);
    }

    #[test]
    fn blocking_wait_not_woken_while_still_conflict() {
        let mut tbl = PosixLockTable::new();
        // Process A holds write on [0, 100).
        tbl.acquire_lock(1, wr(0, 100, 10), false, 0).unwrap();
        // Process B holds write on [200, 300).
        tbl.acquire_lock(1, wr(200, 100, 20), false, 0).unwrap();

        // Process C wants write on [0, 300) — conflicts with both.
        tbl.acquire_lock(1, wr(0, 300, 30), true, 1).unwrap();
        assert_eq!(tbl.waiter_count(), 1);

        // Process A releases — C still conflicts with B.
        let woken = tbl.release_lock(1, r(0, 100), 10).unwrap();
        assert!(woken.is_empty());
        assert_eq!(tbl.waiter_count(), 1);

        // Process B releases — C should now wake.
        let woken = tbl.release_lock(1, r(200, 100), 20).unwrap();
        assert_eq!(woken.len(), 1);
        assert_eq!(woken[0].entry.owner_pid, 30);
    }

    // -- Deadlock detection ----------------------------------------------

    #[test]
    fn deadlock_two_process_inversion() {
        let mut tbl = PosixLockTable::new();

        // Process A holds [0, 100).
        tbl.acquire_lock(1, wr(0, 100, 10), false, 0).unwrap();
        // Process B holds [100, 200).
        tbl.acquire_lock(1, wr(100, 100, 20), false, 0).unwrap();

        // Process A blocks wanting [100, 200).
        tbl.acquire_lock(1, wr(100, 100, 10), true, 0).unwrap();
        assert_eq!(tbl.waiter_count(), 1);

        // Process B blocks wanting [0, 100) — this would create cycle A→B→A.
        let result = tbl.acquire_lock(1, wr(0, 100, 20), true, 0);
        assert_eq!(result, Err(PosixLockError::Deadlock));
        assert_eq!(tbl.waiter_count(), 1); // B not parked
    }

    #[test]
    fn cross_inode_deadlock_detected() {
        let mut tbl = PosixLockTable::new();

        // Process A holds inode 1.
        tbl.acquire_lock(1, wr(0, 100, 10), false, 0).unwrap();
        // Process B holds inode 2.
        tbl.acquire_lock(2, wr(0, 100, 20), false, 0).unwrap();

        // Process A blocks on inode 2 (waiting for B).
        tbl.acquire_lock(2, wr(0, 100, 10), true, 0).unwrap();
        // Process B blocks on inode 1 (waiting for A) — cycle!
        let result = tbl.acquire_lock(1, wr(0, 100, 20), true, 0);
        assert_eq!(result, Err(PosixLockError::Deadlock));
    }

    #[test]
    fn no_deadlock_when_blocking_on_non_holder() {
        let mut tbl = PosixLockTable::new();

        // Process A holds [0, 100).
        tbl.acquire_lock(1, wr(0, 100, 10), false, 0).unwrap();

        // Process B blocks on [0, 100) (waiting for A).
        tbl.acquire_lock(1, wr(0, 100, 20), true, 0).unwrap();

        // Process C (new, holds nothing) also blocks on [0, 100) — no cycle.
        let result = tbl.acquire_lock(1, wr(0, 100, 30), true, 0);
        assert_eq!(result, Ok(()));
        assert_eq!(tbl.waiter_count(), 2);
    }

    // -- release_all_for_owner -------------------------------------------

    #[test]
    fn release_all_for_owner_clears_all_inodes() {
        let mut tbl = PosixLockTable::new();
        tbl.acquire_lock(1, wr(0, 100, 10), false, 0).unwrap();
        tbl.acquire_lock(1, rd(200, 100, 10), false, 0).unwrap();
        tbl.acquire_lock(2, wr(0, 50, 10), false, 0).unwrap();
        tbl.acquire_lock(2, wr(50, 50, 20), false, 0).unwrap(); // different owner, non-overlapping

        let count = tbl.release_all_for_owner(10);
        assert_eq!(count, 3);
        assert_eq!(tbl.lock_count(), 1); // only owner 20 remains
    }

    // -- Multi-owner isolation -------------------------------------------

    #[test]
    fn owners_do_not_affect_each_other_except_via_conflict() {
        let mut tbl = PosixLockTable::new();
        // Owner 10 locks [0, 100).
        tbl.acquire_lock(1, wr(0, 100, 10), false, 0).unwrap();
        // Owner 20 locks [200, 100) — no conflict.
        tbl.acquire_lock(1, wr(200, 100, 20), false, 0).unwrap();
        assert_eq!(tbl.lock_count(), 2);

        // Owner 10 releases its lock — owner 20's lock unaffected.
        tbl.release_lock(1, r(0, 100), 10).unwrap();
        assert_eq!(tbl.lock_count(), 1);
        assert_eq!(tbl.all_locks()[0].1.owner_pid, 20);
    }

    // -- Edge cases ------------------------------------------------------

    #[test]
    fn unlock_type_ignored_in_acquire() {
        let mut tbl = PosixLockTable::new();
        let entry = LockEntry::new(r(0, 100), LockType::Unlock, 10);
        assert_eq!(tbl.acquire_lock(1, entry, false, 0), Ok(()));
        assert_eq!(tbl.lock_count(), 0);
    }

    #[test]
    fn release_nonexistent_lock() {
        let mut tbl = PosixLockTable::new();
        assert_eq!(
            tbl.release_lock(1, r(0, 100), 10),
            Err(PosixLockError::NotFound)
        );
    }

    #[test]
    fn release_nonexistent_inode() {
        let mut tbl = PosixLockTable::new();
        assert_eq!(
            tbl.release_lock(42, r(0, 100), 10),
            Err(PosixLockError::NotFound)
        );
    }

    #[test]
    fn test_lock_on_empty_inode() {
        let tbl = PosixLockTable::new();
        assert_eq!(tbl.test_lock(1, r(0, 100), LockType::Write), None);
    }

    #[test]
    fn same_owner_no_self_conflict() {
        let mut tbl = PosixLockTable::new();
        // POSIX: a process replacing its own lock range is handled at a
        // higher level.  Our lock manager treats same-owner overlapping
        // ranges as conflicting (the FUSE layer should split/merge first).
        tbl.acquire_lock(1, wr(0, 100, 10), false, 0).unwrap();
        // Same owner, overlapping range — our rules say conflict.
        assert_eq!(
            tbl.acquire_lock(1, wr(0, 100, 10), false, 0),
            Err(PosixLockError::WouldBlock)
        );
    }

    #[test]
    fn eof_range_blocks_everything_after() {
        let mut tbl = PosixLockTable::new();
        // Write lock from 100 to EOF.
        tbl.acquire_lock(1, wr(100, 0, 10), false, 0).unwrap();

        // Any lock starting at or after 100 should conflict.
        assert_eq!(
            tbl.acquire_lock(1, rd(200, 50, 20), false, 0),
            Err(PosixLockError::WouldBlock)
        );
        // Before 100 should succeed.
        assert_eq!(tbl.acquire_lock(1, rd(0, 50, 20), false, 0), Ok(()));
    }
}
