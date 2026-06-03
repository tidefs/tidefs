//! Directory operations for the kernel VFS adapter — clean-read seam.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;
use crate::TideVec as Vec;

use crate::{KmodPosixVfs, OpenDirState};
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{DirEntry, Errno, InodeId, RequestCtx};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

impl<E: VfsEngine> KmodPosixVfs<E> {
    pub fn opendir(&self, inode: InodeId, ctx: &RequestCtx) -> Result<OpenDirState, Errno> {
        let handle = self.engine.opendir(inode, ctx)?;
        Ok(OpenDirState { handle, inode })
    }
    pub fn readdir(
        &self,
        state: &OpenDirState,
        offset: u64,
        ctx: &RequestCtx,
    ) -> Result<(Vec<DirEntry>, bool), Errno> {
        self.engine.readdir(&state.handle, offset, ctx)
    }
    pub fn releasedir(&self, state: &OpenDirState) -> Result<(), Errno> {
        self.engine.releasedir(&state.handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use alloc::vec; // Kbuild: use crate::TideVec;
    use tidefs_kmod_bridge::kernel_types::{
        DirEntry as Vde, DirHandleId, EngineDirHandle, Generation, NodeKind,
    };

    fn de(ino: u64, name: &[u8], cookie: u64) -> Vde {
        Vde {
            name: name.to_vec(),
            inode_id: InodeId::new(ino),
            kind: NodeKind::File,
            generation: Generation::new(1),
            cookie,
        }
    }
    fn dh(ino: u64, id: u64) -> EngineDirHandle {
        EngineDirHandle {
            inode_id: InodeId::new(ino),
            dh_id: DirHandleId::new(id),
        }
    }

    #[test]
    fn opendir_works() {
        let h = dh(1, 1);
        let h2 = h;
        let mut e = MockEngine::new();
        e.opendir_fn = Box::new(move |_, _| Ok(h2));
        assert_eq!(
            KmodPosixVfs::new(e)
                .opendir(InodeId::new(1), &MockEngine::test_ctx())
                .unwrap()
                .inode,
            InodeId::new(1)
        );
    }

    #[test]
    fn readdir_returns_entries() {
        let es = vec![de(2, b".", 1), de(2, b"..", 2), de(10, b"foo.txt", 3)];
        let es2 = es.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((es2.clone(), false)));
        let s = OpenDirState {
            handle: dh(1, 1),
            inode: InodeId::new(1),
        };
        let (r, more) = KmodPosixVfs::new(e)
            .readdir(&s, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.len(), 3);
        assert!(!more);
    }

    #[test]
    fn readdir_more_flag() {
        let es = vec![de(10, b"a", 1)];
        let es2 = es.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((es2.clone(), true)));
        let s = OpenDirState {
            handle: dh(1, 1),
            inode: InodeId::new(1),
        };
        assert!(
            KmodPosixVfs::new(e)
                .readdir(&s, 1, &MockEngine::test_ctx())
                .unwrap()
                .1
        );
    }

    #[test]
    fn releasedir_works() {
        KmodPosixVfs::new(MockEngine::new())
            .releasedir(&OpenDirState {
                handle: dh(1, 1),
                inode: InodeId::new(1),
            })
            .unwrap();
    }
}
