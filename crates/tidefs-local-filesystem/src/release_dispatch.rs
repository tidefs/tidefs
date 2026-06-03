//! FUSE release dispatch handler for file-handle teardown.
//!
//! Provides two layers:
//!
//! - **Engine-level** (`engine_release`): validate the handle, remove it
//!   from the [`FileHandleTable`],
//!   and return the owning inode ID for tmpfile reclamation.
//! - **FUSE-level** (`dispatch_release`): wrap engine_release with FUSE
//!   protocol semantics (flush-before-close notification, error mapping).

use std::cell::RefCell;

use tidefs_types_vfs_core::{EngineFileHandle, Errno, InodeId};

use crate::open_dispatch::FileHandleTable;

// ── Engine layer ─────────────────────────────────────────────────────────

/// Release a file handle.
///
/// Validates the handle exists in `table`, removes the entry, and returns
/// the inode ID that was associated with the handle.  The caller can use
/// this to perform tmpfile reclamation if the inode is an anonymous
/// temporary file with no remaining open handles.
///
/// Idempotent on already-released handles: returns `EBADF` if the handle
/// is not found or does not match.
pub fn engine_release(
    table: &RefCell<FileHandleTable>,
    fh: &EngineFileHandle,
) -> Result<InodeId, Errno> {
    table.borrow_mut().release(fh).map_err(|e| e.to_errno())
}

// ── FUSE layer ───────────────────────────────────────────────────────────

/// FUSE-level release dispatch.
///
/// Wraps [`engine_release`] with FUSE protocol semantics.  Currently a thin
/// wrapper; in the future this is the place to add flush-before-close
/// notification, writeback coordination, or release-lifecycle observability.
///
/// Returns `Ok(())` on successful release, or the appropriate errno.
pub fn dispatch_release(
    table: &RefCell<FileHandleTable>,
    fh: &EngineFileHandle,
) -> Result<(), Errno> {
    engine_release(table, fh)?;
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_vfs_core::InodeId;

    #[test]
    fn release_existing_handle() {
        let table = RefCell::new(FileHandleTable::new());
        let inode = InodeId::new(100);
        let fh = table.borrow_mut().register(inode, 0, false).unwrap();

        let released_inode = engine_release(&table, &fh).unwrap();
        assert_eq!(released_inode, inode);
        assert!(table.borrow().is_empty());
    }

    #[test]
    fn release_nonexistent_handle_returns_ebadf() {
        let table = RefCell::new(FileHandleTable::new());
        let fh = tidefs_types_vfs_core::EngineFileHandle {
            inode_id: InodeId::new(1),
            open_flags: 0,
            fh_id: tidefs_types_vfs_core::FileHandleId::new(999),
            lock_owner: 0,
        };
        assert_eq!(engine_release(&table, &fh), Err(Errno::EBADF));
    }

    #[test]
    fn release_twice_returns_ebadf() {
        let table = RefCell::new(FileHandleTable::new());
        let fh = table
            .borrow_mut()
            .register(InodeId::new(55), 0, false)
            .unwrap();
        engine_release(&table, &fh).unwrap();
        assert_eq!(engine_release(&table, &fh), Err(Errno::EBADF));
    }

    #[test]
    fn dispatch_release_wraps_engine() {
        let table = RefCell::new(FileHandleTable::new());
        let fh = table
            .borrow_mut()
            .register(InodeId::new(77), 1, true)
            .unwrap();
        assert!(dispatch_release(&table, &fh).is_ok());
        assert!(dispatch_release(&table, &fh).is_err());
    }
}
