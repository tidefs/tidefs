// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Symlink creation and readlink resolution for the kernel VFS adapter --
//! K7-13 namespace mutation seam.
//!
//! Provides input validation for symlink names and targets before
//! delegating to VfsEngine. Rejects empty names, dot/dotdot entries,
//! NUL bytes, forward slashes, and overlong names (>255 bytes).
//! Target validation rejects empty targets and targets exceeding
//! PATH_MAX (4096 bytes).
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;
use crate::TideVec as Vec;

use crate::intent_record::encode_symlink_intent;
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeAttr, InodeId, RequestCtx};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

// -- SymlinkPlan ---

/// operation result for a kernel VFS symlink creation.
///
/// Captures the parent directory, symlink name, symlink target path,
/// and the resulting symlink inode attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymlinkPlan {
    /// Parent directory inode.
    pub parent: InodeId,
    /// Name of the symlink entry.
    pub name: crate::TideVec<u8>,
    /// Symlink target path.
    pub target: crate::TideVec<u8>,
    /// The newly created symlinks attributes.
    pub attr: InodeAttr,
}

impl SymlinkPlan {
    /// Create a SymlinkPlan.
    pub fn new(
        parent: InodeId,
        name: crate::TideVec<u8>,
        target: crate::TideVec<u8>,
        attr: InodeAttr,
    ) -> Self {
        Self {
            parent,
            name,
            target,
            attr,
        }
    }
}

/// Maximum length of a single symlink-name component in bytes
/// (POSIX NAME_MAX on Linux).
const MAX_NAME_BYTES: usize = 255;

/// Maximum length of a symlink target path in bytes.
/// Linux PATH_MAX is 4096.
const MAX_TARGET_BYTES: usize = 4096;

/// Validate a symlink name (the last path component).
///
/// Returns Err(Errno::EINVAL) when the name is empty, ".", "..",
/// contains a NUL byte, or contains a forward slash.
///
/// Returns Err(Errno::ENAMETOOLONG) when the name exceeds
/// MAX_NAME_BYTES.
///
/// Returns Ok(()) on success.
fn validate_symlink_name(name: &[u8]) -> Result<(), Errno> {
    if name.is_empty() {
        return Err(Errno::EINVAL);
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(Errno::ENAMETOOLONG);
    }
    if name == b"." || name == b".." {
        return Err(Errno::EINVAL);
    }
    if name.contains(&0) {
        return Err(Errno::EINVAL);
    }
    if name.contains(&b'/') {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Validate a symlink target path.
///
/// Returns Err(Errno::ENOENT) when the target is empty.
///
/// Returns Err(Errno::ENAMETOOLONG) when the target exceeds
/// MAX_TARGET_BYTES.
///
/// Returns Ok(()) on success.
fn validate_symlink_target(target: &[u8]) -> Result<(), Errno> {
    if target.is_empty() {
        return Err(Errno::ENOENT);
    }
    if target.len() > MAX_TARGET_BYTES {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(())
}

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Kernel VFS `inode_operations::symlink` dispatch.
    ///
    /// Create a symbolic link in the parent directory. Delegates to
    /// VfsEngine::symlink via the dir_ops_bridge for persistent
    /// symlink creation with intent-log crash safety.
    /// Returns a `SymlinkPlan` with operation result on success.
    ///
    /// # Errors
    /// - `EINVAL`: empty name, dot/dotdot, NUL byte, or forward slash in name
    /// - `ENAMETOOLONG`: name exceeds 255 bytes or target exceeds 4096 bytes
    /// - `ENOENT`: empty target path
    /// - `EEXIST`: name already exists in parent directory
    /// - `ENOSPC`: no space left on device
    /// - `EACCES`: permission denied
    /// - `ENOTDIR`: parent is not a directory
    /// - `EIO`: storage error
    pub fn symlink(
        &self,
        parent: InodeId,
        name: &[u8],
        target: &[u8],
        ctx: &RequestCtx,
    ) -> Result<SymlinkPlan, Errno> {
        validate_symlink_name(name)?;
        validate_symlink_target(target)?;
        let attr = crate::dir_ops_bridge::bridge_symlink(&self.engine, parent, name, target, ctx)?;
        // Record symlink-intent after engine call so the real inode is known.
        let entry = encode_symlink_intent(parent, name, target, attr.inode_id);
        self.record_mutation_intent(&entry)?;
        Ok(SymlinkPlan::new(
            parent,
            name.to_vec(),
            target.to_vec(),
            attr,
        ))
    }

    /// Read the target of symbolic link inode.
    /// Delegates to VfsEngine::readlink.
    pub fn readlink(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
        self.engine.readlink(inode, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use alloc::vec; // Kbuild: use crate::TideVec;
    use tidefs_kmod_bridge::kernel_types::{Generation, InodeFlags, InodeId, NodeKind, PosixAttrs};

    fn symlink_attr(ino: u64) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::Symlink,
            posix: PosixAttrs {
                mode: 0o120777,
                uid: 1000,
                gid: 1000,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 10,
                blocks_512: 1,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        }
    }

    #[test]
    fn symlink_works() {
        let attr = symlink_attr(100);
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(move |_, _, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .symlink(InodeId::new(2), b"link", b"target", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.attr.inode_id, InodeId::new(100));
        assert_eq!(plan.attr.kind, NodeKind::Symlink);
    }

    #[test]
    fn symlink_preserves_engine_generation() {
        let mut attr = symlink_attr(91);
        attr.generation = Generation::new(8642);
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(move |_, _, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .symlink(
                InodeId::new(2),
                b"generated",
                b"target",
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.attr.generation, Generation::new(8642));
    }

    #[test]
    fn symlink_eexist_propagates() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, _, _| Err(Errno::EEXIST));
        assert_eq!(
            KmodPosixVfs::new(e)
                .symlink(InodeId::new(2), b"link", b"target", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EEXIST,
        );
    }

    #[test]
    fn symlink_enospc_propagates() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, _, _| Err(Errno::ENOSPC));
        assert_eq!(
            KmodPosixVfs::new(e)
                .symlink(InodeId::new(2), b"link", b"target", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSPC,
        );
    }

    #[test]
    fn symlink_eacces_propagates() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .symlink(InodeId::new(2), b"link", b"target", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn symlink_enotdir_propagates() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, _, _| Err(Errno::ENOTDIR));
        assert_eq!(
            KmodPosixVfs::new(e)
                .symlink(InodeId::new(2), b"link", b"target", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOTDIR,
        );
    }

    #[test]
    fn symlink_preserves_args() {
        let parent = InodeId::new(42);
        let name = b"my_link";
        let target = b"/absolute/path";
        let parent2 = parent;
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(move |p, n, t, _| {
            assert_eq!(p, parent2);
            assert_eq!(n, name);
            assert_eq!(t, target);
            Ok(symlink_attr(200))
        });
        let plan = KmodPosixVfs::new(e)
            .symlink(parent, name, target, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.parent, parent2);
        assert_eq!(plan.name, name);
        assert_eq!(plan.target, target);
    }

    #[test]
    fn readlink_works() {
        let mut e = MockEngine::new();
        let target = crate::TideVec::from(b"/target/file".as_slice());
        let target2 = target.clone();
        e.readlink_fn = Box::new(move |_, _| Ok(target2.clone()));
        let result = KmodPosixVfs::new(e)
            .readlink(InodeId::new(100), &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn readlink_enoent_propagates() {
        let mut e = MockEngine::new();
        e.readlink_fn = Box::new(|_, _| Err(Errno::ENOENT));
        assert_eq!(
            KmodPosixVfs::new(e)
                .readlink(InodeId::new(999), &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    #[test]
    fn readlink_einval_propagates() {
        let mut e = MockEngine::new();
        e.readlink_fn = Box::new(|_, _| Err(Errno::EINVAL));
        assert_eq!(
            KmodPosixVfs::new(e)
                .readlink(InodeId::new(100), &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EINVAL,
        );
    }

    // --- name validation tests ---

    #[test]
    fn symlink_rejects_empty_name() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, _, _| panic!("engine should not be called"));
        assert_eq!(
            KmodPosixVfs::new(e)
                .symlink(InodeId::new(2), b"", b"target", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EINVAL,
        );
    }

    #[test]
    fn symlink_rejects_dot_name() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, _, _| panic!("engine should not be called"));
        assert_eq!(
            KmodPosixVfs::new(e)
                .symlink(InodeId::new(2), b".", b"target", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EINVAL,
        );
    }

    #[test]
    fn symlink_rejects_dotdot_name() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, _, _| panic!("engine should not be called"));
        assert_eq!(
            KmodPosixVfs::new(e)
                .symlink(InodeId::new(2), b"..", b"target", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EINVAL,
        );
    }

    #[test]
    fn symlink_rejects_nul_in_name() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, _, _| panic!("engine should not be called"));
        let bad_name: &[u8] = &[b'b', b'a', b'd', 0, b'n', b'a', b'm', b'e'];
        assert_eq!(
            KmodPosixVfs::new(e)
                .symlink(
                    InodeId::new(2),
                    bad_name,
                    b"target",
                    &MockEngine::test_ctx()
                )
                .unwrap_err(),
            Errno::EINVAL,
        );
    }

    #[test]
    fn symlink_rejects_slash_in_name() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, _, _| panic!("engine should not be called"));
        assert_eq!(
            KmodPosixVfs::new(e)
                .symlink(
                    InodeId::new(2),
                    b"bad/name",
                    b"target",
                    &MockEngine::test_ctx()
                )
                .unwrap_err(),
            Errno::EINVAL,
        );
    }

    #[test]
    fn symlink_rejects_overlong_name() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, _, _| panic!("engine should not be called"));
        let long_name = vec![b'a'; 256];
        assert_eq!(
            KmodPosixVfs::new(e)
                .symlink(
                    InodeId::new(2),
                    &long_name,
                    b"target",
                    &MockEngine::test_ctx()
                )
                .unwrap_err(),
            Errno::ENAMETOOLONG,
        );
    }

    #[test]
    fn symlink_accepts_255_byte_name() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, n, _, _| {
            assert_eq!(n.len(), 255);
            Ok(symlink_attr(500))
        });
        let name_255 = vec![b'b'; 255];
        let plan = KmodPosixVfs::new(e)
            .symlink(
                InodeId::new(2),
                &name_255,
                b"target",
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.attr.inode_id, InodeId::new(500));
    }

    // --- target validation tests ---

    #[test]
    fn symlink_rejects_empty_target() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, _, _| panic!("engine should not be called"));
        assert_eq!(
            KmodPosixVfs::new(e)
                .symlink(InodeId::new(2), b"link", b"", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    #[test]
    fn symlink_rejects_overlong_target() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, _, _| panic!("engine should not be called"));
        let long_target = vec![b'x'; MAX_TARGET_BYTES + 1];
        assert_eq!(
            KmodPosixVfs::new(e)
                .symlink(
                    InodeId::new(2),
                    b"link",
                    &long_target,
                    &MockEngine::test_ctx()
                )
                .unwrap_err(),
            Errno::ENAMETOOLONG,
        );
    }

    #[test]
    fn symlink_accepts_4096_byte_target() {
        let mut e = MockEngine::new();
        e.symlink_fn = Box::new(|_, _, t, _| {
            assert_eq!(t.len(), 4096);
            Ok(symlink_attr(600))
        });
        let target_4096 = vec![b'y'; MAX_TARGET_BYTES];
        let plan = KmodPosixVfs::new(e)
            .symlink(
                InodeId::new(2),
                b"link",
                &target_4096,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.attr.inode_id, InodeId::new(600));
    }

    #[test]
    fn symlink_readlink_roundtrip() {
        let target_data = b"/some/target/path";
        let target_vec = crate::TideVec::from(target_data.as_slice());
        let target_vec2 = target_vec.clone();
        let mut e = MockEngine::new();
        // symlink succeeds, readlink returns the same target
        e.symlink_fn = Box::new(|_, _, _, _| Ok(symlink_attr(300)));
        e.readlink_fn = Box::new(move |_, _| Ok(target_vec2.clone()));
        let vfs = KmodPosixVfs::new(e);
        let plan = vfs
            .symlink(
                InodeId::new(2),
                b"roundtrip",
                target_data,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.attr.inode_id, InodeId::new(300));
        let resolved = vfs
            .readlink(plan.attr.inode_id, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(resolved, target_vec);
    }
}
