//! File creation mutation for the kernel VFS adapter -- K7-07 mutation seam.
//! Provides create (regular file allocation in a directory) with

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::intent_record::encode_create_intent;
use crate::{KmodPosixVfs, OpenFileState};
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeAttr, InodeId, RequestCtx};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

// -- CreatePlan ---

/// operation result for a kernel VFS file creation.
///
/// Captures the parent directory, entry name, mode, flags, the
/// all inputs plus the outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatePlan {
    /// Parent directory inode.
    pub parent: InodeId,
    /// Name of the new file.
    pub name: crate::TideVec<u8>,
    /// Creation mode (permission bits + type).
    pub mode: u32,
    /// Open flags (O_CREAT, O_EXCL, etc.).
    pub flags: u32,
    /// The newly created inode's attributes.
    pub attr: InodeAttr,
}

impl CreatePlan {
    /// Create a CreatePlan capturing the operation result fields.
    pub fn new(
        parent: InodeId,
        name: crate::TideVec<u8>,
        mode: u32,
        flags: u32,
        attr: InodeAttr,
    ) -> Self {
        Self {
            parent,
            name,
            mode,
            flags,
            attr,
        }
    }
}

// -- dispatch ---

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Kernel VFS `inode_operations::create` dispatch.
    ///
    /// Create a regular file in the parent directory. Delegates to
    /// VfsEngine::create for inode allocation and directory entry
    /// insertion. Returns a `CreatePlan`
    /// with the new inode attributes and open file state.
    ///
    /// # Errors
    /// - `EEXIST`: entry already exists
    /// - `ENOSPC`: no space left on device
    /// - `EACCES` / `EPERM`: permission denied
    /// - `EIO`: storage error
    pub fn create(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(CreatePlan, OpenFileState), Errno> {
        let (attr, handle) =
            crate::dir_ops_bridge::bridge_create(&self.engine, parent, name, mode, flags, ctx)?;
        // Record create-intent after engine call so the real inode is known.
        let entry = encode_create_intent(parent, name, mode, attr.inode_id);
        self.record_mutation_intent(&entry)?;
        let plan = CreatePlan::new(parent, name.to_vec(), mode, flags, attr);
        let state = OpenFileState {
            handle,
            inode: plan.attr.inode_id,
            flags,
        };
        Ok((plan, state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, FileHandleId};

    fn fh(ino: u64, id: u64) -> EngineFileHandle {
        EngineFileHandle {
            inode_id: InodeId::new(ino),
            open_flags: 0,
            fh_id: FileHandleId::new(id),
            lock_owner: 0,
        }
    }

    // -- Basic delegation tests (existing) ---

    #[test]
    fn create_works() {
        let a = MockEngine::file_attr(20, 0);
        let h = fh(20, 1);
        let a2 = a;
        let h2 = h;
        let mut e = MockEngine::new();
        e.create_fn = Box::new(move |_, _, _, _, _| Ok((a2, h2)));
        let (plan, state) = KmodPosixVfs::new(e)
            .create(InodeId::new(2), b"foo", 0o644, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.attr.inode_id, InodeId::new(20));
        assert_eq!(state.inode, InodeId::new(20));
    }

    #[test]
    fn create_eexist_propagates() {
        let mut e = MockEngine::new();
        e.create_fn = Box::new(|_, _, _, _, _| Err(Errno::EEXIST));
        assert_eq!(
            KmodPosixVfs::new(e)
                .create(
                    InodeId::new(2),
                    b"existing",
                    0o644,
                    0,
                    &MockEngine::test_ctx()
                )
                .unwrap_err(),
            Errno::EEXIST,
        );
    }

    #[test]
    fn create_enospc_propagates() {
        let mut e = MockEngine::new();
        e.create_fn = Box::new(|_, _, _, _, _| Err(Errno::ENOSPC));
        assert_eq!(
            KmodPosixVfs::new(e)
                .create(InodeId::new(2), b"bar", 0o644, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSPC,
        );
    }

    #[test]
    fn create_eacces_propagates() {
        let mut e = MockEngine::new();
        e.create_fn = Box::new(|_, _, _, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .create(InodeId::new(2), b"bar", 0o644, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn create_preserves_mode() {
        let mode: u32 = 0o600;
        let mut e = MockEngine::new();
        e.create_fn = Box::new(move |_, _, m, _, _| {
            assert_eq!(m, mode);
            let a = MockEngine::file_attr(30, 0);
            let h = fh(30, 2);
            Ok((a, h))
        });
        let (plan, _state) = KmodPosixVfs::new(e)
            .create(
                InodeId::new(2),
                b"private",
                mode,
                0,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.mode, mode);
    }

    #[test]
    fn create_preserves_flags() {
        let flags: u32 = 0o100;
        let mut e = MockEngine::new();
        e.create_fn = Box::new(move |_, _, _, f, _| {
            assert_eq!(f, flags);
            let a = MockEngine::file_attr(30, 0);
            let h = fh(30, 2);
            Ok((a, h))
        });
        let (plan, state) = KmodPosixVfs::new(e)
            .create(
                InodeId::new(2),
                b"flagged",
                0o644,
                flags,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.flags, flags);
        assert_eq!(state.flags, flags);
    }

    #[test]
    fn create_eperm_propagated() {
        let mut e = MockEngine::new();
        e.create_fn = Box::new(|_, _, _, _, _| Err(Errno::EPERM));
        assert_eq!(
            KmodPosixVfs::new(e)
                .create(InodeId::new(2), b"nope", 0o644, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EPERM,
        );
    }

    #[test]
    fn create_eio_propagated() {
        let mut e = MockEngine::new();
        e.create_fn = Box::new(|_, _, _, _, _| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .create(
                    InodeId::new(2),
                    b"broken",
                    0o644,
                    0,
                    &MockEngine::test_ctx()
                )
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn create_preserves_parent_in_plan() {
        let a = MockEngine::file_attr(50, 0);
        let h = fh(50, 1);
        let a2 = a;
        let h2 = h;
        let mut e = MockEngine::new();
        e.create_fn = Box::new(move |_, _, _, _, _| Ok((a2, h2)));
        let (plan, _) = KmodPosixVfs::new(e)
            .create(
                InodeId::new(99),
                b"child",
                0o644,
                0,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.parent, InodeId::new(99));
    }
}
