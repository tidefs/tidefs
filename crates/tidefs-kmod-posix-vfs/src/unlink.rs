// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Directory entry removal mutation for the kernel VFS adapter -- K7-10
//! namespace mutation seam.
//! nlink-driven inode drop to VfsEngine.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::intent_record::encode_unlink_intent;
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId, RequestCtx};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

// -- UnlinkPlan ---

/// operation result for a kernel VFS unlink operation.
///
/// Captures the parent directory, entry name, and a domain-separated
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlinkPlan {
    /// Parent directory inode.
    pub parent: InodeId,
    /// Name of the entry being removed.
    pub name: crate::TideVec<u8>,
}

impl UnlinkPlan {
    /// Create an UnlinkPlan capturing the operation result fields.
    pub fn new(parent: InodeId, name: crate::TideVec<u8>) -> Self {
        Self { parent, name }
    }
}

// -- dispatch ---

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Kernel VFS `inode_operations::unlink` dispatch.
    ///
    /// Remove a directory entry from the parent directory. Delegates
    /// to VfsEngine::unlink for persistent removal with nlink-driven
    /// inode drop and intent-log crash safety.
    ///
    /// Returns an `UnlinkPlan` with operation result on
    /// success.
    ///
    /// # Errors
    /// - `ENOENT`: entry does not exist
    /// - `EPERM`: permission denied (sticky bit, etc.)
    /// - `EACCES`: search permission on parent
    /// - `EISDIR`: target is a directory (use rmdir)
    /// - `ENOTEMPTY`: directory not empty
    /// - `EIO`: storage error
    pub fn unlink(
        &self,
        parent: InodeId,
        name: &[u8],
        ctx: &RequestCtx,
    ) -> Result<UnlinkPlan, Errno> {
        // Look up the victim inode for intent record fidelity.
        let victim_attr = crate::dir_ops_bridge::bridge_lookup(&self.engine, parent, name, ctx)?;
        let entry = encode_unlink_intent(parent, name, victim_attr.inode_id);
        self.record_mutation_intent(&entry)?;
        crate::dir_ops_bridge::bridge_unlink(&self.engine, parent, name, ctx)?;
        Ok(UnlinkPlan::new(parent, name.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use alloc::vec; // Kbuild: use crate::TideVec;

    // -- Basic delegation tests (existing) ---

    #[test]
    fn unlink_works() {
        let mut e = MockEngine::new();
        e.unlink_fn = Box::new(|_, _, _| Ok(()));
        let plan = KmodPosixVfs::new(e)
            .unlink(InodeId::new(2), b"foo", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.parent, InodeId::new(2));
        assert_eq!(plan.name, b"foo");
    }

    #[test]
    fn unlink_enoent_propagates() {
        let mut e = MockEngine::new();
        e.unlink_fn = Box::new(|_, _, _| Err(Errno::ENOENT));
        assert_eq!(
            KmodPosixVfs::new(e)
                .unlink(InodeId::new(2), b"nonexistent", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    #[test]
    fn unlink_eacces_propagates() {
        let mut e = MockEngine::new();
        e.unlink_fn = Box::new(|_, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .unlink(InodeId::new(2), b"protected", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn unlink_enotempty_propagates() {
        let mut e = MockEngine::new();
        e.unlink_fn = Box::new(|_, _, _| Err(Errno::ENOTEMPTY));
        assert_eq!(
            KmodPosixVfs::new(e)
                .unlink(InodeId::new(2), b"nonempty_dir", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOTEMPTY,
        );
    }

    #[test]
    fn unlink_eperm_propagates() {
        let mut e = MockEngine::new();
        e.unlink_fn = Box::new(|_, _, _| Err(Errno::EPERM));
        assert_eq!(
            KmodPosixVfs::new(e)
                .unlink(InodeId::new(2), b"sticky_denied", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EPERM,
        );
    }

    #[test]
    fn unlink_preserves_parent_and_name() {
        let parent = InodeId::new(42);
        let name = b"target_file";
        let parent2 = parent;
        let mut e = MockEngine::new();
        e.unlink_fn = Box::new(move |p, n, _| {
            assert_eq!(p, parent2);
            assert_eq!(n, name);
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .unlink(parent, name, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.parent, parent);
        assert_eq!(plan.name, name);
    }

    #[test]
    fn unlink_eisdir_propagated() {
        let mut e = MockEngine::new();
        e.unlink_fn = Box::new(|_, _, _| Err(Errno::EISDIR));
        assert_eq!(
            KmodPosixVfs::new(e)
                .unlink(InodeId::new(2), b"a_dir", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EISDIR,
        );
    }

    #[test]
    fn unlink_eio_propagated() {
        let mut e = MockEngine::new();
        e.unlink_fn = Box::new(|_, _, _| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .unlink(InodeId::new(2), b"broken", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn unlink_empty_name_delegated() {
        let mut e = MockEngine::new();
        e.unlink_fn = Box::new(|_, _, _| Err(Errno::ENOENT));
        assert_eq!(
            KmodPosixVfs::new(e)
                .unlink(InodeId::new(5), b"", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    #[test]
    fn unlink_long_name_delegated() {
        let long = vec![b'x'; 255];
        let mut e = MockEngine::new();
        e.unlink_fn = Box::new(|_, _, _| Ok(()));
        let plan = KmodPosixVfs::new(e)
            .unlink(InodeId::new(5), &long, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.name.len(), 255);
    }
}
