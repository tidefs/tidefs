// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Exclusive file creation (O_EXCL|O_CREAT) for the kernel VFS adapter.
//!
//! Delegates atomic exclusive create to VfsEngine::create_excl, which
//! guarantees that the name does not exist before creation.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::intent_record::encode_create_intent;
use crate::{KmodPosixVfs, OpenFileState};
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeAttr, InodeId, RequestCtx};

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Atomically create a regular file in `parent` directory, failing
    /// with `EEXIST` if the name already exists.
    pub fn create_excl(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        ctx: &RequestCtx,
    ) -> Result<(InodeAttr, OpenFileState), Errno> {
        #[cfg(not(CONFIG_RUST))]
        let (attr, handle) = self.engine.create_excl(parent, name, mode, 0, ctx)?;
        #[cfg(CONFIG_RUST)]
        let (attr, handle) = self.engine.create_excl(parent, name, mode, ctx)?;
        // Record create-intent after engine call so the real inode is known.
        let entry = encode_create_intent(parent, name, mode, attr.inode_id);
        self.record_mutation_intent(&entry)?;
        let state = OpenFileState {
            handle,
            inode: attr.inode_id,
            flags: 0,
        };
        Ok((attr, state))
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

    #[test]
    fn create_excl_works() {
        let a = MockEngine::file_attr(30, 0);
        let h = fh(30, 1);
        let a2 = a;
        let h2 = h;
        let mut e = MockEngine::new();
        e.create_excl_fn = Box::new(move |_, _, _, _, _| Ok((a2, h2)));
        let (attr, state) = KmodPosixVfs::new(e)
            .create_excl(InodeId::new(2), b"newfile", 0o644, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(attr.inode_id, InodeId::new(30));
        assert_eq!(state.inode, InodeId::new(30));
    }

    #[test]
    fn create_excl_eexist_propagates() {
        let mut e = MockEngine::new();
        e.create_excl_fn = Box::new(|_, _, _, _, _| Err(Errno::EEXIST));
        assert_eq!(
            KmodPosixVfs::new(e)
                .create_excl(InodeId::new(2), b"existing", 0o644, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EEXIST,
        );
    }

    #[test]
    fn create_excl_eacces_propagates() {
        let mut e = MockEngine::new();
        e.create_excl_fn = Box::new(|_, _, _, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .create_excl(InodeId::new(2), b"bar", 0o644, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn create_excl_enospc_propagates() {
        let mut e = MockEngine::new();
        e.create_excl_fn = Box::new(|_, _, _, _, _| Err(Errno::ENOSPC));
        assert_eq!(
            KmodPosixVfs::new(e)
                .create_excl(InodeId::new(2), b"bar", 0o644, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSPC,
        );
    }

    #[test]
    fn create_excl_enoent_propagates() {
        let mut e = MockEngine::new();
        e.create_excl_fn = Box::new(|_, _, _, _, _| Err(Errno::ENOENT));
        assert_eq!(
            KmodPosixVfs::new(e)
                .create_excl(InodeId::new(2), b"bar", 0o644, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    #[test]
    fn create_excl_preserves_mode() {
        let mode: u32 = 0o600;
        let mut e = MockEngine::new();
        e.create_excl_fn = Box::new(move |_, _, m, _flags, _| {
            assert_eq!(m, mode);
            let a = MockEngine::file_attr(31, 0);
            let h = fh(31, 2);
            Ok((a, h))
        });
        KmodPosixVfs::new(e)
            .create_excl(InodeId::new(2), b"private", mode, &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn create_excl_preserves_ctx() {
        let mut e = MockEngine::new();
        e.create_excl_fn = Box::new(move |_, _, _, _flags, ctx| {
            assert_eq!(ctx.uid, 1000);
            assert_eq!(ctx.gid, 1000);
            let a = MockEngine::file_attr(33, 0);
            let h = fh(33, 4);
            Ok((a, h))
        });
        KmodPosixVfs::new(e)
            .create_excl(InodeId::new(2), b"ctxcheck", 0o644, &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn create_excl_enotdir_propagates() {
        let mut e = MockEngine::new();
        e.create_excl_fn = Box::new(|_, _, _, _, _| Err(Errno::ENOTDIR));
        assert_eq!(
            KmodPosixVfs::new(e)
                .create_excl(InodeId::new(2), b"bar", 0o644, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOTDIR,
        );
    }
}
