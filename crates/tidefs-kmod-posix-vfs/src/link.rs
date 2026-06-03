//! Hard-link creation mutation for the kernel VFS adapter -- K7-13
//! namespace mutation seam.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::intent_record::encode_link_intent;
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeAttr, InodeId, RequestCtx};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

// -- LinkPlan ---

/// operation result for a kernel VFS hard-link creation.
///
/// Captures the target inode, new parent directory, new entry name,
/// the target's updated attributes (with incremented nlink), and a
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkPlan {
    /// Target inode being linked.
    pub target: InodeId,
    /// Parent directory inode for the new link.
    pub new_parent: InodeId,
    /// Name of the new hard-link entry.
    pub new_name: crate::TideVec<u8>,
    /// Target inode attributes after link count increment.
    pub attr: InodeAttr,
}

impl LinkPlan {
    /// Create a LinkPlan capturing the operation result fields.
    pub fn new(
        target: InodeId,
        new_parent: InodeId,
        new_name: crate::TideVec<u8>,
        attr: InodeAttr,
    ) -> Self {
        Self {
            target,
            new_parent,
            new_name,
            attr,
        }
    }
}

// -- dispatch ---

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Kernel VFS `inode_operations::link` dispatch.
    ///
    /// Create a hard link from `target` to `new_name` in `new_parent`.
    /// Delegates to VfsEngine::link via the dir_ops_bridge for persistent
    /// hard-link creation with nlink accounting and intent-log crash safety.
    /// Returns a `LinkPlan` with operation result on success.
    ///
    /// # Errors
    /// - `ENOENT`: target or parent does not exist
    /// - `EEXIST`: new_name already exists
    /// - `EMLINK`: link count limit exceeded
    /// - `EPERM`: permission denied (directory hard link, sticky bit, etc.)
    /// - `EXDEV`: cross-device link not permitted
    /// - `EACCES`: search permission on parent
    /// - `EIO`: storage error
    pub fn link(
        &self,
        target: InodeId,
        new_parent: InodeId,
        new_name: &[u8],
        ctx: &RequestCtx,
    ) -> Result<LinkPlan, Errno> {
        // Record hardlink-intent before committing the namespace mutation.
        let entry = encode_link_intent(target, new_parent, new_name);
        self.record_mutation_intent(&entry)?;
        let attr =
            crate::dir_ops_bridge::bridge_link(&self.engine, target, new_parent, new_name, ctx)?;
        Ok(LinkPlan::new(target, new_parent, new_name.to_vec(), attr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;

    // -- Basic delegation tests ---

    #[test]
    fn link_works() {
        let mut e = MockEngine::new();
        let expected_attr = MockEngine::file_attr(31, 0);
        let attr_clone = expected_attr;
        e.link_fn = Box::new(move |_, _, _, _| Ok(attr_clone));
        let plan = KmodPosixVfs::new(e)
            .link(
                InodeId::new(31),
                InodeId::new(2),
                b"hardlink",
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.attr.inode_id, InodeId::new(31));
        assert_eq!(plan.target, InodeId::new(31));
        assert_eq!(plan.new_parent, InodeId::new(2));
        assert_eq!(plan.new_name, b"hardlink");
    }

    #[test]
    fn link_eexist_propagates() {
        let mut e = MockEngine::new();
        e.link_fn = Box::new(|_, _, _, _| Err(Errno::EEXIST));
        assert_eq!(
            KmodPosixVfs::new(e)
                .link(
                    InodeId::new(31),
                    InodeId::new(2),
                    b"existing",
                    &MockEngine::test_ctx(),
                )
                .unwrap_err(),
            Errno::EEXIST,
        );
    }

    #[test]
    fn link_enoent_propagates() {
        let mut e = MockEngine::new();
        e.link_fn = Box::new(|_, _, _, _| Err(Errno::ENOENT));
        assert_eq!(
            KmodPosixVfs::new(e)
                .link(
                    InodeId::new(99),
                    InodeId::new(2),
                    b"nofile",
                    &MockEngine::test_ctx(),
                )
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    #[test]
    fn link_eacces_propagates() {
        let mut e = MockEngine::new();
        e.link_fn = Box::new(|_, _, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .link(
                    InodeId::new(31),
                    InodeId::new(2),
                    b"denied",
                    &MockEngine::test_ctx(),
                )
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn link_emlink_propagates() {
        let mut e = MockEngine::new();
        e.link_fn = Box::new(|_, _, _, _| Err(Errno::EMLINK));
        assert_eq!(
            KmodPosixVfs::new(e)
                .link(
                    InodeId::new(31),
                    InodeId::new(2),
                    b"toomany",
                    &MockEngine::test_ctx(),
                )
                .unwrap_err(),
            Errno::EMLINK,
        );
    }

    #[test]
    fn link_exdev_propagates() {
        let mut e = MockEngine::new();
        e.link_fn = Box::new(|_, _, _, _| Err(Errno::EXDEV));
        assert_eq!(
            KmodPosixVfs::new(e)
                .link(
                    InodeId::new(31),
                    InodeId::new(2),
                    b"crossfs",
                    &MockEngine::test_ctx(),
                )
                .unwrap_err(),
            Errno::EXDEV,
        );
    }

    #[test]
    fn link_eperm_propagates() {
        let mut e = MockEngine::new();
        e.link_fn = Box::new(|_, _, _, _| Err(Errno::EPERM));
        assert_eq!(
            KmodPosixVfs::new(e)
                .link(
                    InodeId::new(31),
                    InodeId::new(2),
                    b"sticky_denied",
                    &MockEngine::test_ctx(),
                )
                .unwrap_err(),
            Errno::EPERM,
        );
    }

    #[test]
    fn link_eio_propagated() {
        let mut e = MockEngine::new();
        e.link_fn = Box::new(|_, _, _, _| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .link(
                    InodeId::new(31),
                    InodeId::new(2),
                    b"broken",
                    &MockEngine::test_ctx(),
                )
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn link_preserves_target_and_parent_in_plan() {
        let target_id = InodeId::new(100);
        let parent_id = InodeId::new(42);
        let target_id2 = target_id;
        let parent_id2 = parent_id;
        let attrs = MockEngine::file_attr(100, 1);
        let attrs2 = attrs;
        let mut e = MockEngine::new();
        e.link_fn = Box::new(move |t, np, _, _| {
            assert_eq!(t, target_id2);
            assert_eq!(np, parent_id2);
            Ok(attrs2)
        });
        let plan = KmodPosixVfs::new(e)
            .link(target_id, parent_id, b"alias", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.target, target_id);
        assert_eq!(plan.new_parent, parent_id);
        assert_eq!(plan.new_name, b"alias");
    }

    #[test]
    fn link_reflects_nlink_increment() {
        let mut attr = MockEngine::file_attr(33, 0);
        attr.posix.nlink = 2;
        let attr2 = attr;
        let mut e = MockEngine::new();
        e.link_fn = Box::new(move |_, _, _, _| Ok(attr2));
        let plan = KmodPosixVfs::new(e)
            .link(
                InodeId::new(33),
                InodeId::new(2),
                b"second_link",
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.attr.posix.nlink, 2);
    }
}
