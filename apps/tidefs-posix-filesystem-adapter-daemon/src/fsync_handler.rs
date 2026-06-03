//! FsyncHandler: commit_group-integrated fsync/fdatasync dispatch.
//!
//! Wraps a [`tidefs_commit_group::CommitGroupSync`] and provides the
//! daemon-level fsync barrier: after the PageCache writeback and engine
//! fsync phases complete, the handler waits on the commit_group sync gate
//! for transaction group durability notification.
//!
//! The sync gate is signaled by the commit path (background commit thread
//! or explicit `notify_committed` call) when the transaction group
//! containing the inode's dirty data has been committed.

use tidefs_commit_group::{CommitGroupError, CommitGroupSync, SyncGate};
use tidefs_types_vfs_core::Errno;

// ---------------------------------------------------------------------------
// FsyncHandler
// ---------------------------------------------------------------------------

/// Daemon-level fsync handler backed by the commit_group durability gate.
///
/// Constructed with a [`SyncGate`] shared with the commit path.  After
/// the caller has flushed dirty pages and called `engine.fsync()`, the
/// handler blocks until the transaction group is durable.
///
/// When no sync gate is configured (e.g., during early boot or testing
/// without a background commit thread), `handle_fsync` is a no-op.
#[derive(Clone, Debug)]
pub struct FsyncHandler {
    sync: Option<CommitGroupSync>,
}

impl FsyncHandler {
    /// Create a new handler from an optional [`SyncGate`].
    ///
    /// When `gate` is [`None`], the handler treats all fsync calls as
    /// immediate no-ops (the caller is responsible for ensuring durability
    /// through other means, e.g., the engine's `sync_inode` path).
    #[must_use]
    pub fn new(gate: Option<SyncGate>) -> Self {
        Self {
            sync: gate.map(CommitGroupSync::new),
        }
    }

    /// Return a reference to the underlying [`SyncGate`], if any.
    ///
    /// The commit path uses this gate to call [`SyncGate::register_dirty`]
    /// when writes are buffered and [`SyncGate::notify_committed`] when a
    /// transaction group commits.
    #[must_use]
    #[allow(dead_code)] // gate() is used by the commit path for sync coordination
    pub fn gate(&self) -> Option<&SyncGate> {
        self.sync.as_ref().map(|s| s.gate())
    }

    /// Block until the transaction group containing `ino`'s dirty data
    /// is durable.
    ///
    /// This is the fsync durability barrier.  The caller must have already
    /// flushed dirty pages and called `engine.fsync()` before invoking
    /// this method.
    ///
    /// When no sync gate is configured, returns `Ok(())` immediately
    /// (the engine's sync path is assumed to provide durability).
    ///
    /// # Errors
    ///
    /// Returns [`Errno::EIO`] if the commit_group reports an I/O error
    /// during the wait.
    pub fn handle_fsync(&self, _ino: u64, _datasync: bool) -> Result<(), Errno> {
        match &self.sync {
            Some(sync) => {
                // Register the inode's dirty state with the sync gate,
                // then wait for the commit notification.
                // In the current implementation, the caller (dispatch_fsync_file)
                // already performed engine.fsync() which calls do_commit() +
                // store.sync_all().  The sync gate provides an additional
                // coordination point for future background-commit paths.
                sync.fsync(_ino).map_err(|e| match e {
                    CommitGroupError::Io(_) => Errno::EIO,
                    _ => Errno::EIO,
                })
            }
            None => {
                // No sync gate configured: the engine's sync path
                // (engine.fsync → LocalFileSystem::fsync_file →
                // do_commit + store.sync_all) already provides durability.
                Ok(())
            }
        }
    }

    /// Block until all pending transaction groups are committed and synced.
    ///
    /// This is `syncfs` semantics: filesystem-wide durability barrier.
    ///
    /// # Errors
    ///
    /// Returns [`Errno::EIO`] if the commit_group reports an I/O error.
    pub fn handle_syncfs(&self) -> Result<(), Errno> {
        match &self.sync {
            Some(sync) => sync.syncfs().map_err(|e| match e {
                CommitGroupError::Io(_) => Errno::EIO,
                _ => Errno::EIO,
            }),
            None => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fsync_handler_no_gate_returns_ok() {
        let handler = FsyncHandler::new(None);
        assert_eq!(handler.handle_fsync(42, false), Ok(()));
        assert_eq!(handler.handle_fsync(99, true), Ok(()));
        assert_eq!(handler.handle_syncfs(), Ok(()));
    }

    #[test]
    fn fsync_handler_no_gate_idempotent() {
        let handler = FsyncHandler::new(None);
        // Multiple calls should all succeed.
        for _ in 0..10 {
            assert_eq!(handler.handle_fsync(1, false), Ok(()));
        }
    }

    #[test]
    fn fsync_handler_gate_is_none_without_sync() {
        let handler = FsyncHandler::new(None);
        assert!(handler.gate().is_none());
    }

    #[test]
    fn fsync_handler_with_gate_returns_gate() {
        let gate = SyncGate::new();
        let handler = FsyncHandler::new(Some(gate.clone()));
        assert!(handler.gate().is_some());
    }

    #[test]
    fn fsync_handler_clone_works() {
        let gate = SyncGate::new();
        let handler = FsyncHandler::new(Some(gate));
        let _cloned = handler.clone();
        // Both should have gates.
        assert!(handler.gate().is_some());
        assert!(_cloned.gate().is_some());
    }

    #[test]
    fn fsync_handler_debug_format_nonempty() {
        let handler = FsyncHandler::new(None);
        let s = format!("{handler:?}");
        assert!(!s.is_empty());
    }

    #[test]
    fn fsync_handler_with_gate_fsync_no_dirty_data_returns_immediately() {
        let gate = SyncGate::new();
        let handler = FsyncHandler::new(Some(gate));
        // No dirty data registered: fsync returns immediately.
        assert_eq!(handler.handle_fsync(42, false), Ok(()));
    }

    #[test]
    fn fsync_handler_with_gate_fsync_blocks_until_notified() {
        use std::thread;
        let gate = SyncGate::new();
        let handler = FsyncHandler::new(Some(gate.clone()));

        gate.register_dirty(1, tidefs_commit_group::CommitGroupId(1));

        let h = {
            let handler = handler.clone();
            thread::spawn(move || {
                handler.handle_fsync(1, false).unwrap();
            })
        };

        // Give the thread a moment to block on the barrier.
        thread::sleep(std::time::Duration::from_millis(50));

        gate.notify_committed(tidefs_commit_group::CommitGroupId(1));
        h.join().unwrap();
    }

    #[test]
    fn fsync_handler_with_gate_syncfs_returns_immediately_when_empty() {
        let gate = SyncGate::new();
        let handler = FsyncHandler::new(Some(gate.clone()));

        // syncfs with no committed commit_groups: should return immediately
        // after notify_synced is called (which happens in a background thread
        // in production; here we call it directly to unblock).
        let h = {
            let handler = handler.clone();
            std::thread::spawn(move || {
                handler.handle_syncfs().unwrap();
            })
        };

        std::thread::sleep(std::time::Duration::from_millis(50));
        gate.notify_synced();
        h.join().unwrap();
    }
}
