// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// transaction.rs — explicit transaction guard with staged-root isolation
//
// §5 of the writeback/transaction/durability design spec (#1190).
// TransactionGuard provides RAII-style begin/commit/abort with
// auto-abort on drop.  This is the analogue of ZFS's object_store_tx at
// the application layer, distinct from the internal commit_group commit group.

use crate::Result;

/// An RAII guard for an explicit transaction on a LocalFileSystem.
///
/// Created by `LocalFileSystem::begin_transaction`.  Mutations
/// accumulate in the filesystem's in-memory state and are published
/// atomically when `commit` is called.
/// If the guard is dropped without committing, the transaction is
/// automatically aborted and state is rolled back.
///
/// # Examples
///
/// ```ignore
/// let mut tx = fs.begin_transaction()?;
/// tx.fs.write_file("/foo", 0, b"hello")?;
/// tx.fs.mkdir("/bar")?;
/// tx.commit()?;
/// ```
pub struct TransactionGuard<'fs> {
    fs: &'fs mut crate::LocalFileSystem,
    committed: bool,
}

impl<'fs> TransactionGuard<'fs> {
    /// Create a new guard.  Intended to be called only by
    /// `LocalFileSystem::begin_transaction`.
    pub(crate) fn new(fs: &'fs mut crate::LocalFileSystem) -> Self {
        Self {
            fs,
            committed: false,
        }
    }

    /// Commit the transaction: publish all staged mutations as a
    /// single commit_group commit.
    ///
    /// This forces an immediate commit_group sync (quiesce → sync → complete)
    /// and clears the dirty-set index.
    ///
    /// Consumes the guard — after `commit()` the transaction is
    /// closed and the borrow on the filesystem is released.
    pub fn commit(mut self) -> Result<()> {
        self.committed = true;
        self.fs.commit_transaction_inner()
    }

    /// Abort the transaction: discard all mutations made since
    /// `begin_transaction` by restoring state to the pre-transaction
    /// snapshot.
    ///
    /// Consumes the guard — after `abort()` the transaction is
    /// closed and the borrow on the filesystem is released.
    pub fn abort(mut self) -> Result<()> {
        self.committed = true; // prevent double-abort in drop
        self.fs.abort_transaction_inner()
    }
}

impl<'fs> Drop for TransactionGuard<'fs> {
    fn drop(&mut self) {
        if !self.committed {
            // Auto-abort on drop without explicit commit/abort.
            // We discard the result because drop cannot propagate
            // errors, but rollback is best-effort: on failure the
            // in-memory state may be inconsistent, which will be
            // caught at the next mount.
            let _ = self.fs.abort_transaction_inner();
        }
    }
}
