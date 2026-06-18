// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Inode operations for the kernel VFS adapter -- clean-read seam.
//! delegation, and negative dentry tracking with generation
//! validation.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::errno::KernelErrno;
use crate::{KmodPosixVfs, LookupResult, NegativeDentry};
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeAttr, InodeId, RequestCtx};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

// -- LookupPlan ---

/// operation result for a kernel VFS lookup operation.
///
/// Captures the parent directory, entry name, lookup result (found
/// inode or negative dentry), mount generation, and a domain-separated
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupPlan {
    /// Parent directory inode.
    pub parent: InodeId,
    /// Name looked up.
    pub name: crate::TideVec<u8>,
    /// Lookup result: Found(inode) or Negative(dentry).
    pub result: LookupResult,
    /// Mount generation at time of lookup.
    pub generation: u64,
}

impl LookupPlan {
    /// Create a LookupPlan with field-preserving construction.
    pub fn new(
        parent: InodeId,
        name: crate::TideVec<u8>,
        result: LookupResult,
        generation: u64,
    ) -> Self {
        Self {
            parent,
            name,
            result,
            generation,
        }
    }
}

// -- dispatch ---

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Kernel VFS `inode_operations::lookup` dispatch.
    ///
    /// Resolves a directory entry name within the parent directory.
    /// Returns a `LookupPlan` with operation result on
    /// success, or an error code on failure.
    ///
    /// - `Ok(plan)` with `LookupResult::Found(attr)` when the entry exists.
    /// - `Ok(plan)` with `LookupResult::Negative(dentry)` when the entry
    ///   does not exist (ENOENT from engine).
    /// - `Err(e)` for all other engine errors (EACCES, EIO, etc.).
    pub fn lookup(
        &self,
        parent: InodeId,
        name: &[u8],
        ctx: &RequestCtx,
    ) -> Result<LookupPlan, Errno> {
        let result = match crate::dir_ops_bridge::bridge_lookup(&self.engine, parent, name, ctx) {
            Ok(attr) => LookupResult::Found(attr),
            Err(KernelErrno::NS_NOT_FOUND) => LookupResult::Negative(NegativeDentry {
                parent,
                name: name.to_vec(),
                generation: self.generation,
            }),
            Err(e) => return Err(e),
        };
        Ok(LookupPlan::new(
            parent,
            name.to_vec(),
            result,
            self.generation,
        ))
    }

    pub fn is_generation_valid(&self, _attr: &InodeAttr) -> bool {
        true
    }

    pub fn revalidate_negative(&self, neg: &NegativeDentry) -> bool {
        neg.generation == self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::KernelErrno;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use alloc::vec; // Kbuild: use crate::TideVec;

    // -- Basic delegation tests (existing) ---

    #[test]
    fn lookup_returns_found() {
        let a = MockEngine::file_attr(10, 4096);
        let a2 = a;
        let mut e = MockEngine::new();
        e.lookup_fn = Box::new(move |_, _, _| Ok(a2));
        let plan = KmodPosixVfs::new(e)
            .lookup(InodeId::new(1), b"foo", &MockEngine::test_ctx())
            .unwrap();
        match &plan.result {
            LookupResult::Found(attr) => {
                assert_eq!(attr.inode_id, InodeId::new(10));
                assert_eq!(attr.posix.size, 4096);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn lookup_returns_negative() {
        let mut e = MockEngine::new();
        e.lookup_fn = Box::new(|_, _, _| Err(KernelErrno::NS_NOT_FOUND));
        let plan = KmodPosixVfs::new(e)
            .lookup(InodeId::new(1), b"nope", &MockEngine::test_ctx())
            .unwrap();
        match &plan.result {
            LookupResult::Negative(n) => {
                assert_eq!(n.parent, InodeId::new(1));
                assert_eq!(n.name, b"nope".to_vec());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn lookup_propagates_errors() {
        let mut e = MockEngine::new();
        e.lookup_fn = Box::new(|_, _, _| Err(KernelErrno::PERM_DENIED));
        assert_eq!(
            KmodPosixVfs::new(e)
                .lookup(InodeId::new(1), b"x", &MockEngine::test_ctx())
                .unwrap_err(),
            KernelErrno::PERM_DENIED,
        );
    }

    #[test]
    fn getattr_delegates() {
        let a = MockEngine::file_attr(7, 1024);
        let a2 = a;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(a2));
        let r = KmodPosixVfs::new(e)
            .getattr(InodeId::new(7), None, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.inode_id, InodeId::new(7));
        assert_eq!(r.posix.size, 1024);
    }

    #[test]
    fn revalidate_negative() {
        let kmod = KmodPosixVfs::new(MockEngine::new());
        assert!(kmod.revalidate_negative(&NegativeDentry {
            parent: InodeId::new(1),
            name: b"s".to_vec(),
            generation: 0,
        }));
        assert!(!kmod.revalidate_negative(&NegativeDentry {
            parent: InodeId::new(1),
            name: b"s".to_vec(),
            generation: 1,
        }));
    }

    #[test]
    fn lookup_eio_propagated() {
        let mut e = MockEngine::new();
        e.lookup_fn = Box::new(|_, _, _| Err(KernelErrno::STORAGE_IO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .lookup(InodeId::new(1), b"broken", &MockEngine::test_ctx())
                .unwrap_err(),
            KernelErrno::STORAGE_IO,
        );
    }

    #[test]
    fn lookup_estale_propagated() {
        let mut e = MockEngine::new();
        e.lookup_fn = Box::new(|_, _, _| Err(KernelErrno::STALE_GENERATION));
        assert_eq!(
            KmodPosixVfs::new(e)
                .lookup(InodeId::new(1), b"stale", &MockEngine::test_ctx())
                .unwrap_err(),
            KernelErrno::STALE_GENERATION,
        );
    }

    #[test]
    fn lookup_preserves_generation() {
        let a = MockEngine::file_attr(10, 0);
        let a2 = a;
        let mut e = MockEngine::new();
        e.lookup_fn = Box::new(move |_, _, _| Ok(a2));
        let mut kmod = KmodPosixVfs::new(e);
        kmod.generation = 42;
        let plan = kmod
            .lookup(InodeId::new(1), b"gen42", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.generation, 42);
    }

    #[test]
    fn lookup_empty_name_delegated() {
        let mut e = MockEngine::new();
        e.lookup_fn = Box::new(|_, _, _| Err(KernelErrno::NS_NOT_FOUND));
        let plan = KmodPosixVfs::new(e)
            .lookup(InodeId::new(1), b"", &MockEngine::test_ctx())
            .unwrap();
        match &plan.result {
            LookupResult::Negative(_) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn lookup_long_name_delegated() {
        let long = vec![b'x'; 255];
        let a = MockEngine::file_attr(99, 1);
        let a2 = a;
        let mut e = MockEngine::new();
        e.lookup_fn = Box::new(move |_, _, _| Ok(a2));
        let plan = KmodPosixVfs::new(e)
            .lookup(InodeId::new(1), &long, &MockEngine::test_ctx())
            .unwrap();
        match &plan.result {
            LookupResult::Found(attr) => assert_eq!(attr.inode_id, InodeId::new(99)),
            _ => panic!(),
        }
    }
}
