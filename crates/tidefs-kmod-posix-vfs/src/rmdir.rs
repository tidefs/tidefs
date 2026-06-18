// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Directory removal mutation for the kernel VFS adapter -- K7-12
//! namespace mutation seam.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::intent_record::encode_rmdir_intent;
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId, RequestCtx};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

// -- RmdirPlan ---

/// operation result for a kernel VFS directory removal.
///
/// Captures the parent directory, entry name, and a domain-separated
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RmdirPlan {
    /// Parent directory inode.
    pub parent: InodeId,
    /// Name of the directory being removed.
    pub name: crate::TideVec<u8>,
}

impl RmdirPlan {
    /// Create an RmdirPlan capturing the operation result fields.
    pub fn new(parent: InodeId, name: crate::TideVec<u8>) -> Self {
        Self { parent, name }
    }
}

// -- dispatch ---

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Kernel VFS `inode_operations::rmdir` dispatch.
    ///
    /// Remove an empty directory entry from the parent directory.
    /// Delegates to VfsEngine::rmdir via the dir_ops_bridge for
    /// persistent removal with intent-log crash safety.
    ///
    /// Returns an `RmdirPlan` with operation result on
    /// success.
    ///
    /// # Errors
    /// - `ENOENT`: entry does not exist
    /// - `ENOTEMPTY`: directory is not empty
    /// - `ENOTDIR`: parent is not a directory
    /// - `EACCES` / `EPERM`: permission denied
    /// - `EBUSY`: directory is in use
    /// - `EROFS`: read-only filesystem
    /// - `EIO`: storage error
    pub fn rmdir(
        &self,
        parent: InodeId,
        name: &[u8],
        ctx: &RequestCtx,
    ) -> Result<RmdirPlan, Errno> {
        // Look up the victim inode for intent record fidelity.
        let victim_attr = crate::dir_ops_bridge::bridge_lookup(&self.engine, parent, name, ctx)?;
        let entry = encode_rmdir_intent(parent, name, victim_attr.inode_id);
        self.record_mutation_intent(&entry)?;
        crate::dir_ops_bridge::bridge_rmdir(&self.engine, parent, name, ctx)?;
        Ok(RmdirPlan::new(parent, name.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use alloc::vec; // Kbuild: use crate::TideVec;

    // -- Basic delegation tests ---

    #[test]
    fn rmdir_works() {
        let mut e = MockEngine::new();
        e.rmdir_fn = Box::new(|_, _, _| Ok(()));
        let plan = KmodPosixVfs::new(e)
            .rmdir(InodeId::new(2), b"subdir", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.parent, InodeId::new(2));
        assert_eq!(plan.name, b"subdir");
    }

    #[test]
    fn rmdir_enotempty_propagates() {
        let mut e = MockEngine::new();
        e.rmdir_fn = Box::new(|_, _, _| Err(Errno::ENOTEMPTY));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rmdir(InodeId::new(2), b"nonempty", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOTEMPTY,
        );
    }

    #[test]
    fn rmdir_enoent_propagates() {
        let mut e = MockEngine::new();
        e.rmdir_fn = Box::new(|_, _, _| Err(Errno::ENOENT));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rmdir(InodeId::new(2), b"nope", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    #[test]
    fn rmdir_eacces_propagates() {
        let mut e = MockEngine::new();
        e.rmdir_fn = Box::new(|_, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rmdir(InodeId::new(2), b"locked", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn rmdir_enotdir_propagates() {
        let mut e = MockEngine::new();
        e.rmdir_fn = Box::new(|_, _, _| Err(Errno::ENOTDIR));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rmdir(InodeId::new(2), b"notadir", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOTDIR,
        );
    }

    #[test]
    fn rmdir_erofs_propagates() {
        let mut e = MockEngine::new();
        e.rmdir_fn = Box::new(|_, _, _| Err(Errno::EROFS));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rmdir(InodeId::new(2), b"readonly", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EROFS,
        );
    }

    #[test]
    fn rmdir_preserves_parent_and_name() {
        let mut e = MockEngine::new();
        let parent = InodeId::new(42);
        let name: &[u8] = b"exact-name-match";
        e.rmdir_fn = Box::new(move |p, n, _| {
            assert_eq!(p, parent);
            assert_eq!(n, name);
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .rmdir(parent, name, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.parent, parent);
        assert_eq!(plan.name, name);
    }

    #[test]
    fn rmdir_eio_propagated() {
        let mut e = MockEngine::new();
        e.rmdir_fn = Box::new(|_, _, _| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rmdir(InodeId::new(2), b"broken", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn rmdir_empty_name_delegated() {
        let mut e = MockEngine::new();
        e.rmdir_fn = Box::new(|_, _, _| Err(Errno::ENOENT));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rmdir(InodeId::new(5), b"", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    #[test]
    fn rmdir_long_name_delegated() {
        let long = vec![b'x'; 255];
        let mut e = MockEngine::new();
        e.rmdir_fn = Box::new(|_, _, _| Ok(()));
        let plan = KmodPosixVfs::new(e)
            .rmdir(InodeId::new(5), &long, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.name.len(), 255);
    }
}
