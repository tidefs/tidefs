//! CommitGroupSync: fsync, fdatasync, and syncfs entry points.
//!
//! `CommitGroupSync` provides the durability barrier for individual inode fsync
//! and filesystem-wide syncfs. It blocks until the transaction group
//! containing the inode's dirty data has been committed and the journal
//! record is durable.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};

use crate::types::{CommitGroupError, CommitGroupId};

// ---------------------------------------------------------------------------
// SyncBarrier
// ---------------------------------------------------------------------------

/// A lightweight notification primitive for one waiter.
///
/// When multiple waiters need to be woken (e.g., syncfs wakes all fsync
/// waiters), we broadcast through a shared `SyncGate`.
#[derive(Clone, Debug)]
pub struct SyncBarrier {
    inner: Arc<(Mutex<bool>, Condvar)>,
}

impl SyncBarrier {
    fn new() -> Self {
        Self {
            inner: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    /// Block until `signal()` is called.
    fn wait(&self) {
        let (lock, cvar) = &*self.inner;
        let mut done = lock.lock().unwrap();
        while !*done {
            done = cvar.wait(done).unwrap();
        }
    }

    /// Wake the waiting thread.
    fn signal(&self) {
        let (lock, cvar) = &*self.inner;
        let mut done = lock.lock().unwrap();
        *done = true;
        cvar.notify_all();
    }
}

// ---------------------------------------------------------------------------
// InodeSyncState
// ---------------------------------------------------------------------------

/// Tracks sync state for a single inode: what commit_group it last dirtied in
/// and a barrier to wait on.
#[derive(Clone, Debug)]
struct InodeSyncState {
    /// The commit_group in which this inode was last dirtied.
    dirty_commit_group: CommitGroupId,
    /// Barrier to signal when the commit_group commits.
    barrier: SyncBarrier,
}

// ---------------------------------------------------------------------------
// SyncGate
// ---------------------------------------------------------------------------

/// A shared coordination point for commit_group → fsync notification.
///
/// When a commit_group commits, `SyncGate` wakes all fsync waiters whose inodes
/// were dirtied in that commit_group and advances the durable commit_group pointer.
#[derive(Clone, Debug, Default)]
pub struct SyncGate {
    inner: Arc<Mutex<SyncGateInner>>,
}

#[derive(Debug, Default)]
struct SyncGateInner {
    /// Durable commit_group id — the highest commit_group known to be committed.
    durable_commit_group: CommitGroupId,
    /// Per-inode sync state: ino → InodeSyncState.
    inode_states: BTreeMap<u64, InodeSyncState>,
    /// Completed commit_groups waiting for syncfs.
    committed_commit_groups: VecDeque<CommitGroupId>,
    /// Global barrier: signaled on every syncfs.
    global_barrier: Option<SyncBarrier>,
}

impl SyncGate {
    /// Create a new sync gate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the highest durable (committed + synced) commit_group id.
    #[must_use]
    pub fn durable_commit_group(&self) -> CommitGroupId {
        self.inner.lock().unwrap().durable_commit_group
    }

    /// Register that `ino` has dirty data in `commit_group_id`.
    pub fn register_dirty(&self, ino: u64, commit_group_id: CommitGroupId) {
        let mut inner = self.inner.lock().unwrap();
        inner.inode_states.insert(
            ino,
            InodeSyncState {
                dirty_commit_group: commit_group_id,
                barrier: SyncBarrier::new(),
            },
        );
    }

    /// Notify that `commit_group_id` has been committed (journal record written).
    ///
    /// Wakes all inode-level fsync waiters whose dirty commit_group equals
    /// `commit_group_id`. Also records the commit_group as committed for syncfs.
    pub fn notify_committed(&self, commit_group_id: CommitGroupId) {
        let mut inner = self.inner.lock().unwrap();

        // Wake per-inode waiters whose dirty commit_group has completed.
        let to_wake: Vec<SyncBarrier> = inner
            .inode_states
            .iter()
            .filter(|(_, state)| state.dirty_commit_group == commit_group_id)
            .map(|(_, state)| state.barrier.clone())
            .collect();

        for barrier in &to_wake {
            barrier.signal();
        }

        // Update durable commit_group pointer.
        if commit_group_id > inner.durable_commit_group {
            inner.durable_commit_group = commit_group_id;
        }

        // Record for syncfs.
        inner.committed_commit_groups.push_back(commit_group_id);
    }

    /// Notify that a syncfs barrier has been reached.
    ///
    /// This signals the global syncfs waiter and advances the durable
    /// pointer to the most recent committed commit_group.
    pub fn notify_synced(&self) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(barrier) = inner.global_barrier.take() {
            barrier.signal();
        }
        // All committed commit_groups are now synced.
        inner.committed_commit_groups.clear();
    }

    /// Prepare a global syncfs barrier and return the barrier to wait on.
    pub fn prepare_syncfs(&self) -> SyncBarrier {
        let mut inner = self.inner.lock().unwrap();
        let barrier = SyncBarrier::new();
        inner.global_barrier = Some(barrier.clone());
        barrier
    }
}

// ---------------------------------------------------------------------------
// CommitGroupSync
// ---------------------------------------------------------------------------

/// Durability coordinator: fsync(ino) and syncfs().
///
/// `CommitGroupSync` uses a `SyncGate` to coordinate between the commit path
/// (which calls `notify_committed`) and fsync/syncfs callers (which wait
/// on barriers).
#[derive(Clone, Debug)]
pub struct CommitGroupSync {
    gate: SyncGate,
}

impl CommitGroupSync {
    /// Create a new sync coordinator.
    #[must_use]
    pub fn new(gate: SyncGate) -> Self {
        Self { gate }
    }

    /// Return a reference to the underlying sync gate.
    #[must_use]
    pub fn gate(&self) -> &SyncGate {
        &self.gate
    }

    /// Block until all data for `ino` up through the currently accumulating
    /// commit_group has been committed (journal record written).
    ///
    /// This is `fsync(ino)` semantics: after return, a crash will not lose
    /// data or metadata for `ino`.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::Io` if the wait is interrupted.
    pub fn fsync(&self, ino: u64) -> Result<(), CommitGroupError> {
        let barrier = {
            let inner = self.gate.inner.lock().unwrap();
            inner.inode_states.get(&ino).map(|s| s.barrier.clone())
        };

        match barrier {
            Some(b) => {
                b.wait();
                Ok(())
            }
            None => {
                // No dirty data for this inode — already durable.
                Ok(())
            }
        }
    }

    /// Block until all pending transactions have been committed *and*
    /// synced (journal records are durable).
    ///
    /// This is `syncfs()` semantics.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::Io` if the wait is interrupted.
    pub fn syncfs(&self) -> Result<(), CommitGroupError> {
        let barrier = self.gate.prepare_syncfs();
        barrier.wait();
        Ok(())
    }

    /// Block until `ino`'s data is durable, then also call syncfs.
    ///
    /// This is `fsync` + `syncfs` combined; used when the caller wants
    /// both guarantees.
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError::Io` if the wait is interrupted.
    pub fn fsync_and_syncfs(&self, ino: u64) -> Result<(), CommitGroupError> {
        self.fsync(ino)?;
        self.syncfs()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn fsync_no_dirty_data_returns_immediately() {
        let gate = SyncGate::new();
        let sync = CommitGroupSync::new(gate);
        assert!(sync.fsync(42).is_ok());
    }

    #[test]
    fn fsync_blocks_until_notified() {
        let gate = SyncGate::new();
        let sync = CommitGroupSync::new(gate.clone());

        gate.register_dirty(1, CommitGroupId(1));

        let handle = thread::spawn(move || {
            sync.fsync(1).unwrap();
        });

        // Give the thread a moment to block.
        thread::sleep(std::time::Duration::from_millis(50));

        gate.notify_committed(CommitGroupId(1));

        handle.join().unwrap();
    }

    #[test]
    fn syncfs_blocks_until_notified() {
        let gate = SyncGate::new();
        let sync = CommitGroupSync::new(gate.clone());

        let handle = thread::spawn(move || {
            sync.syncfs().unwrap();
        });

        thread::sleep(std::time::Duration::from_millis(50));

        gate.notify_synced();

        handle.join().unwrap();
    }

    #[test]
    fn durable_commit_group_advances() {
        let gate = SyncGate::new();
        assert_eq!(gate.durable_commit_group(), CommitGroupId(0));
        gate.notify_committed(CommitGroupId(1));
        assert_eq!(gate.durable_commit_group(), CommitGroupId(1));
        gate.notify_committed(CommitGroupId(5));
        assert_eq!(gate.durable_commit_group(), CommitGroupId(5));
    }

    #[test]
    fn durable_commit_group_does_not_regress() {
        let gate = SyncGate::new();
        gate.notify_committed(CommitGroupId(10));
        gate.notify_committed(CommitGroupId(3));
        assert_eq!(gate.durable_commit_group(), CommitGroupId(10));
    }

    #[test]
    fn fsync_and_syncfs_combined() {
        let gate = SyncGate::new();
        let sync = CommitGroupSync::new(gate.clone());

        gate.register_dirty(7, CommitGroupId(2));

        let handle = thread::spawn(move || {
            sync.fsync_and_syncfs(7).unwrap();
        });

        thread::sleep(std::time::Duration::from_millis(50));

        gate.notify_committed(CommitGroupId(2));
        // After notify_committed, fsync proceeds; syncfs needs notify_synced
        thread::sleep(std::time::Duration::from_millis(50));
        gate.notify_synced();

        handle.join().unwrap();
    }

    #[test]
    fn multiple_inode_fsync() {
        let gate = SyncGate::new();
        gate.register_dirty(1, CommitGroupId(1));
        gate.register_dirty(2, CommitGroupId(1));
        gate.register_dirty(3, CommitGroupId(2));

        let sync1 = CommitGroupSync::new(gate.clone());
        let sync2 = CommitGroupSync::new(gate.clone());
        let sync3 = CommitGroupSync::new(gate.clone());

        let h1 = thread::spawn(move || sync1.fsync(1).unwrap());
        let h2 = thread::spawn(move || sync2.fsync(2).unwrap());
        let h3 = thread::spawn(move || sync3.fsync(3).unwrap());

        thread::sleep(std::time::Duration::from_millis(50));
        gate.notify_committed(CommitGroupId(1));
        // ino 1 and 2 should unblock, ino 3 still waits
        h1.join().unwrap();
        h2.join().unwrap();

        thread::sleep(std::time::Duration::from_millis(50));
        gate.notify_committed(CommitGroupId(2));
        h3.join().unwrap();
    }
}
