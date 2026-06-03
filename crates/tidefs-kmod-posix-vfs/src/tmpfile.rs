//! O_TMPFILE unnamed temporary file creation for the kernel VFS adapter.
//!
//! Delegates to VfsEngine::tmpfile, which creates an unnamed regular file
//! in `parent` directory that can later be linked into the namespace via
//! linkat(AT_FCHDIR, ..., AT_EMPTY_PATH).
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::intent_record::encode_create_intent;
use crate::{KmodPosixVfs, OpenFileState};
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeAttr, InodeId, RequestCtx};

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Create an unnamed temporary regular file in `parent` directory.
    ///
    /// The resulting file has no directory entry.
    pub fn tmpfile(
        &self,
        parent: InodeId,
        mode: u32,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(InodeAttr, OpenFileState), Errno> {
        let (attr, handle) = self.engine.tmpfile(parent, mode, flags, ctx)?;
        // Record tmpfile-intent after engine call so the real inode is known.
        let entry = encode_create_intent(parent, b".tmpfile", mode, attr.inode_id);
        self.record_mutation_intent(&entry)?;
        let state = OpenFileState {
            handle,
            inode: attr.inode_id,
            flags,
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
    fn tmpfile_creates_unnamed_file() {
        let a = MockEngine::file_attr(40, 0);
        let h = fh(40, 1);
        let a2 = a;
        let h2 = h;
        let mut e = MockEngine::new();
        e.tmpfile_fn = Box::new(move |_, _, _, _| Ok((a2, h2)));
        let (attr, state) = KmodPosixVfs::new(e)
            .tmpfile(InodeId::new(2), 0o644, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(attr.inode_id, InodeId::new(40));
        assert_eq!(state.inode, InodeId::new(40));
    }

    #[test]
    fn tmpfile_rejects_non_directory() {
        let mut e = MockEngine::new();
        e.tmpfile_fn = Box::new(|_, _, _, _| Err(Errno::ENOTDIR));
        assert_eq!(
            KmodPosixVfs::new(e)
                .tmpfile(InodeId::new(20), 0o644, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOTDIR,
        );
    }

    #[test]
    fn tmpfile_rejects_missing_parent() {
        let mut e = MockEngine::new();
        e.tmpfile_fn = Box::new(|_, _, _, _| Err(Errno::ENOENT));
        assert_eq!(
            KmodPosixVfs::new(e)
                .tmpfile(InodeId::new(99), 0o644, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    #[test]
    fn tmpfile_returns_valid_file_handle() {
        let a = MockEngine::file_attr(42, 0);
        let h = fh(42, 3);
        let a2 = a;
        let h2 = h;
        let mut e = MockEngine::new();
        e.tmpfile_fn = Box::new(move |_, _, _, _| Ok((a2, h2)));
        let (_, state) = KmodPosixVfs::new(e)
            .tmpfile(InodeId::new(2), 0o644, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(state.handle.fh_id, FileHandleId::new(3));
        assert_eq!(state.inode, InodeId::new(42));
    }

    #[test]
    fn tmpfile_eacces_propagates() {
        let mut e = MockEngine::new();
        e.tmpfile_fn = Box::new(|_, _, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .tmpfile(InodeId::new(2), 0o644, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn tmpfile_eperm_propagates() {
        let mut e = MockEngine::new();
        e.tmpfile_fn = Box::new(|_, _, _, _| Err(Errno::EPERM));
        assert_eq!(
            KmodPosixVfs::new(e)
                .tmpfile(InodeId::new(2), 0o644, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EPERM,
        );
    }

    #[test]
    fn tmpfile_enospc_propagates() {
        let mut e = MockEngine::new();
        e.tmpfile_fn = Box::new(|_, _, _, _| Err(Errno::ENOSPC));
        assert_eq!(
            KmodPosixVfs::new(e)
                .tmpfile(InodeId::new(2), 0o644, 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSPC,
        );
    }

    #[test]
    fn tmpfile_preserves_mode() {
        let mode: u32 = 0o600;
        let mut e = MockEngine::new();
        e.tmpfile_fn = Box::new(move |_, m, _, _| {
            assert_eq!(m, mode);
            let a = MockEngine::file_attr(43, 0);
            let h = fh(43, 4);
            Ok((a, h))
        });
        KmodPosixVfs::new(e)
            .tmpfile(InodeId::new(2), mode, 0, &MockEngine::test_ctx())
            .unwrap();
    }
}
