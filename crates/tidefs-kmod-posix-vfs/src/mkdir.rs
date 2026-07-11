// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Directory creation mutation for the kernel VFS adapter -- K7-11
//! namespace mutation seam.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::intent_record::encode_mkdir_intent;
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeAttr, InodeId, RequestCtx};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

// -- MkdirPlan ---

/// operation result for a kernel VFS directory creation.
///
/// Captures the parent directory, entry name, mode, the
/// resulting directory inode attributes, and a domain-separated
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MkdirPlan {
    /// Parent directory inode.
    pub parent: InodeId,
    /// Name of the new directory.
    pub name: crate::TideVec<u8>,
    /// Creation mode (permission bits + type).
    pub mode: u32,
    /// The newly created directory's attributes.
    pub attr: InodeAttr,
}

impl MkdirPlan {
    /// Create a MkdirPlan capturing the operation result fields.
    pub fn new(parent: InodeId, name: crate::TideVec<u8>, mode: u32, attr: InodeAttr) -> Self {
        Self {
            parent,
            name,
            mode,
            attr,
        }
    }
}

// -- dispatch ---

/// S_IFMT mask: isolates the file type bits from a mode value.
const S_IFMT: u32 = 0o170000;
/// S_IFDIR: directory type bits.
const S_IFDIR: u32 = 0o040000;

/// Check that `mode` encodes a directory (or has no type bits set, allowing
/// the engine to default to S_IFDIR). Returns Errno::EINVAL if the caller
/// set non-directory type bits.
fn validate_mkdir_mode(mode: u32) -> Result<(), Errno> {
    let type_bits = mode & S_IFMT;
    if type_bits != 0 && type_bits != S_IFDIR {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Kernel VFS `inode_operations::mkdir` dispatch.
    ///
    /// Create a directory in the parent directory. Delegates to
    /// VfsEngine::mkdir via the dir_ops_bridge for inode allocation
    /// and directory entry insertion. Returns a `MkdirPlan` with
    /// operation result.
    ///
    /// # Errors
    /// - `EEXIST`: entry already exists
    /// - `ENOSPC`: no space left on device
    /// - `EACCES` / `EPERM`: permission denied
    /// - `ENOTDIR`: parent is not a directory
    /// - `EINVAL`: non-directory type bits in mode
    /// - `EIO`: storage error
    pub fn mkdir(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        ctx: &RequestCtx,
    ) -> Result<MkdirPlan, Errno> {
        validate_mkdir_mode(mode)?;
        let attr = crate::dir_ops_bridge::bridge_mkdir(&self.engine, parent, name, mode, ctx)?;
        // Record mkdir-intent after engine call so the real inode is known.
        let entry = encode_mkdir_intent(parent, name, mode, attr.inode_id);
        self.record_mutation_intent(&entry)?;
        Ok(MkdirPlan::new(parent, name.to_vec(), mode, attr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::Generation;

    // -- Basic delegation tests ---

    #[test]
    fn mkdir_works() {
        let mut e = MockEngine::new();
        let expected_attr = MockEngine::dir_attr(42);
        let attr_clone = expected_attr;
        e.mkdir_fn = Box::new(move |_, _, _, _| Ok(attr_clone));
        let plan = KmodPosixVfs::new(e)
            .mkdir(InodeId::new(2), b"newdir", 0o755, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.attr.inode_id, InodeId::new(42));
        assert_eq!(plan.attr.posix.mode, 0o40755);
    }

    #[test]
    fn mkdir_preserves_engine_generation() {
        let mut attr = MockEngine::dir_attr(50);
        attr.generation = Generation::new(4321);
        let mut e = MockEngine::new();
        e.mkdir_fn = Box::new(move |_, _, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .mkdir(
                InodeId::new(2),
                b"generated",
                0o755,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.attr.generation, Generation::new(4321));
    }

    #[test]
    fn mkdir_preserves_mode() {
        let mode: u32 = 0o700;
        let mut e = MockEngine::new();
        e.mkdir_fn = Box::new(move |_, _, m, _| {
            assert_eq!(m, mode);
            Ok(MockEngine::dir_attr(50))
        });
        let plan = KmodPosixVfs::new(e)
            .mkdir(InodeId::new(2), b"secret", mode, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.mode, mode);
    }

    #[test]
    fn mkdir_eexist_propagates() {
        let mut e = MockEngine::new();
        e.mkdir_fn = Box::new(|_, _, _, _| Err(Errno::EEXIST));
        assert_eq!(
            KmodPosixVfs::new(e)
                .mkdir(InodeId::new(2), b"existing", 0o755, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EEXIST,
        );
    }

    #[test]
    fn mkdir_enospc_propagates() {
        let mut e = MockEngine::new();
        e.mkdir_fn = Box::new(|_, _, _, _| Err(Errno::ENOSPC));
        assert_eq!(
            KmodPosixVfs::new(e)
                .mkdir(InodeId::new(2), b"bar", 0o755, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSPC,
        );
    }

    #[test]
    fn mkdir_enotdir_propagates() {
        let mut e = MockEngine::new();
        e.mkdir_fn = Box::new(|_, _, _, _| Err(Errno::ENOTDIR));
        assert_eq!(
            KmodPosixVfs::new(e)
                .mkdir(InodeId::new(2), b"baz", 0o755, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOTDIR,
        );
    }

    #[test]
    fn mkdir_eacces_propagates() {
        let mut e = MockEngine::new();
        e.mkdir_fn = Box::new(|_, _, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .mkdir(InodeId::new(2), b"nope", 0o755, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn mkdir_rejects_non_directory_type_bits() {
        // S_IFREG in mode -> EINVAL
        let mode = 0o100644; // S_IFREG | 0644
        let mut e = MockEngine::new();
        e.mkdir_fn = Box::new(|_, _, _, _| panic!("engine should not be called"));
        assert_eq!(
            KmodPosixVfs::new(e)
                .mkdir(InodeId::new(2), b"bad", mode, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EINVAL,
        );
    }

    #[test]
    fn mkdir_root_parent() {
        let mut e = MockEngine::new();
        e.mkdir_fn = Box::new(|parent, _, _, _| {
            assert_eq!(parent, InodeId::new(0));
            Ok(MockEngine::dir_attr(100))
        });
        let plan = KmodPosixVfs::new(e)
            .mkdir(InodeId::new(0), b"toplevel", 0o755, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.attr.inode_id, InodeId::new(100));
    }

    #[test]
    fn mkdir_allows_zero_type_bits() {
        // Mode without S_IFDIR set should be allowed (engine defaults it).
        let mut e = MockEngine::new();
        e.mkdir_fn = Box::new(|_, _, _, _| Ok(MockEngine::dir_attr(60)));
        let plan = KmodPosixVfs::new(e)
            .mkdir(
                InodeId::new(2),
                b"defaulted",
                0o755,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.attr.inode_id, InodeId::new(60));
    }

    #[test]
    fn mkdir_eio_propagated() {
        let mut e = MockEngine::new();
        e.mkdir_fn = Box::new(|_, _, _, _| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .mkdir(InodeId::new(2), b"broken", 0o755, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn mkdir_preserves_parent_in_plan() {
        let a = MockEngine::dir_attr(50);
        let a2 = a;
        let mut e = MockEngine::new();
        e.mkdir_fn = Box::new(move |_, _, _, _| Ok(a2));
        let plan = KmodPosixVfs::new(e)
            .mkdir(InodeId::new(99), b"child", 0o755, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.parent, InodeId::new(99));
    }
}
