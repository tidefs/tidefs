#![allow(unused_variables)]
//! Atomic rename mutation for the kernel VFS adapter -- K7 mutation seam.
//! Bridges the kernel VFS rename(2) / renameat2(2) system calls to the
//! canonical VfsEngine, supporting `RENAME_NOREPLACE`, `RENAME_EXCHANGE`,
//! and `RENAME_WHITEOUT` flags with cross-directory nlink adjustment and
//! intent-log crash safety delegated to the engine.
//! # VfsEngine bridge contract
//! The engine's [`VfsEngine::rename`] method is responsible for:
//! - Source existence validation (ENOENT if missing).
//! - `RENAME_NOREPLACE` enforcement (EEXIST if target exists).
//! - `RENAME_EXCHANGE` atomic swap (ENOENT if either side is missing).
//! - `RENAME_WHITEOUT` creation for overlayfs upper-layer whiteout.
//! - Target-type checks: file-over-directory (EISDIR),
//!   directory-over-file (ENOTDIR), non-empty directory overwrite
//!   (ENOTEMPTY).
//! - Cross-directory subdirectory nlink adjustment: decrement old
//!   parent's link count, increment new parent's link count.
//! - `..` entry update for moved directories.
//! - Self-rename detection (same inode and name) as no-op.
//! - Intent-log transaction boundary wrapping all mutations for
//!   crash-consistent replay.
//!
//! This module delegates to the engine through
//! [`dir_ops_bridge::bridge_rename`] and wraps the result in a
//! namespace mutation integrity verification.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::intent_record::encode_rename_intent;
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId, RequestCtx};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

// -- Rename flags ------------------------------------------------------------

/// `RENAME_NOREPLACE`: Fail with EEXIST if the destination already exists.
pub const RENAME_NOREPLACE: u32 = 1;

/// `RENAME_EXCHANGE`: Atomically swap source and destination entries.
pub const RENAME_EXCHANGE: u32 = 2;

/// `RENAME_WHITEOUT`: Create a whiteout device at the source location
/// (overlayfs upper-layer).
pub const RENAME_WHITEOUT: u32 = 4;

// -- RenameArgs --------------------------------------------------------------

/// Argument bundle for a rename mutation.
///
/// Mirrors the kernel VFS `struct renamedata` fields, providing a
/// single structured parameter for the rename dispatch functions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenameArgs {
    /// Source parent directory inode.
    pub old_parent: InodeId,
    /// Source entry name.
    pub old_name: crate::TideVec<u8>,
    /// Destination parent directory inode.
    pub new_parent: InodeId,
    /// Destination entry name.
    pub new_name: crate::TideVec<u8>,
    /// `RENAME_*` flags (0 for plain rename).
    pub flags: u32,
}

impl RenameArgs {
    /// Create a new `RenameArgs` with the given parameters.
    pub fn new(
        old_parent: InodeId,
        old_name: crate::TideVec<u8>,
        new_parent: InodeId,
        new_name: crate::TideVec<u8>,
        flags: u32,
    ) -> Self {
        Self {
            old_parent,
            old_name,
            new_parent,
            new_name,
            flags,
        }
    }
}

// -- RenamePlan --------------------------------------------------------------

/// operation result for a kernel VFS rename operation.
///
/// Captures source/destination parents and names, rename flags, and
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenamePlan {
    /// Source parent directory inode.
    pub old_parent: InodeId,
    /// Source entry name.
    pub old_name: crate::TideVec<u8>,
    /// Destination parent directory inode.
    pub new_parent: InodeId,
    /// Destination entry name.
    pub new_name: crate::TideVec<u8>,
    /// `RENAME_*` flags used.
    pub flags: u32,
}

impl RenamePlan {
    /// Create a `RenamePlan` capturing the operation result fields.
    pub fn new(
        old_parent: InodeId,
        old_name: crate::TideVec<u8>,
        new_parent: InodeId,
        new_name: crate::TideVec<u8>,
        flags: u32,
    ) -> Self {
        Self {
            old_parent,
            old_name,
            new_parent,
            new_name,
            flags,
        }
    }
}

// -- dispatch ----------------------------------------------------------------

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Kernel VFS `inode_operations::rename` dispatch.
    ///
    /// Atomically renames a filesystem entry from `old_parent`/`old_name`
    /// to `new_parent`/`new_name`. The engine handles all rename semantics
    /// including nlink adjustment for cross-directory subdirectory moves,
    /// `..` entry updates, target-type validation, and intent-log crash
    /// safety.
    ///
    /// `flags` is a bitmask of `RENAME_NOREPLACE`, `RENAME_EXCHANGE`,
    /// and `RENAME_WHITEOUT` (see the module-level constants).
    ///
    /// Returns a [`RenamePlan`] with operation result on
    /// success.
    ///
    /// # Errors
    /// - `ENOENT`: source does not exist (or destination missing for EXCHANGE)
    /// - `EEXIST`: `RENAME_NOREPLACE` is set and destination exists
    /// - `EACCES`: search or write permission denied on parent
    /// - `ENOTDIR`: directory renamed over file (or parent is not a directory)
    /// - `EISDIR`: file renamed over directory
    /// - `ENOTEMPTY`: directory renamed over non-empty directory
    /// - `EXDEV`: cross-device rename not supported
    /// - `EINVAL`: invalid flag combination
    /// - `EIO`: storage error
    pub fn rename(
        &self,
        old_parent: InodeId,
        old_name: &[u8],
        new_parent: InodeId,
        new_name: &[u8],
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<RenamePlan, Errno> {
        // Look up source and target for intent record fidelity.
        let source_attr =
            crate::dir_ops_bridge::bridge_lookup(&self.engine, old_parent, old_name, ctx)?;
        let overwrite_attr =
            crate::dir_ops_bridge::bridge_lookup(&self.engine, new_parent, new_name, ctx).ok();

        // Reject file-over-directory and directory-over-file renames
        // before delegating to the engine, guarding against engine
        // implementations that skip these target-type checks.
        if let Some(ref target) = overwrite_attr {
            use tidefs_kmod_bridge::kernel_types::NodeKind;
            let src_is_dir = matches!(source_attr.kind, NodeKind::Dir);
            let tgt_is_dir = matches!(target.kind, NodeKind::Dir);
            if !src_is_dir && tgt_is_dir {
                return Err(Errno::EISDIR);
            }
            if src_is_dir && !tgt_is_dir {
                return Err(Errno::ENOTDIR);
            }
        }
        let entry = encode_rename_intent(
            old_parent,
            old_name,
            new_parent,
            new_name,
            source_attr.inode_id,
            overwrite_attr.map(|a| a.inode_id),
        );
        self.record_mutation_intent(&entry)?;
        crate::dir_ops_bridge::bridge_rename(
            &self.engine,
            old_parent,
            old_name,
            new_parent,
            new_name,
            flags,
            ctx,
        )?;
        Ok(RenamePlan::new(
            old_parent,
            old_name.to_vec(),
            new_parent,
            new_name.to_vec(),
            flags,
        ))
    }

    /// Convenience alias dispatching rename via a [`RenameArgs`] bundle.
    ///
    /// Equivalent to:
    /// ```ignore
    /// self.rename(args.old_parent, &args.old_name, args.new_parent,
    ///             &args.new_name, args.flags, ctx)
    /// ```
    pub fn dispatch_rename(
        &self,
        args: &RenameArgs,
        ctx: &RequestCtx,
    ) -> Result<RenamePlan, Errno> {
        self.rename(
            args.old_parent,
            &args.old_name,
            args.new_parent,
            &args.new_name,
            args.flags,
            ctx,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use alloc::vec; // Kbuild: use crate::TideVec;

    fn p(ino: u64) -> InodeId {
        InodeId::new(ino)
    }

    // -- Basic delegation tests ----------------------------------------------

    #[test]
    fn rename_works() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|old_p, old_n, new_p, new_n, flags, _| {
            assert_eq!(old_p, p(1));
            assert_eq!(old_n, b"old");
            assert_eq!(new_p, p(2));
            assert_eq!(new_n, b"new");
            assert_eq!(flags, 0);
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .rename(p(1), b"old", p(2), b"new", 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.old_parent, p(1));
        assert_eq!(plan.old_name, b"old");
        assert_eq!(plan.new_parent, p(2));
        assert_eq!(plan.new_name, b"new");
        assert_eq!(plan.flags, 0);
    }

    #[test]
    fn rename_noreplace_flag() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, flags, _| {
            assert_eq!(flags, RENAME_NOREPLACE);
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .rename(
                p(1),
                b"a",
                p(1),
                b"b",
                RENAME_NOREPLACE,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.flags, RENAME_NOREPLACE);
    }

    #[test]
    fn rename_exchange_flag() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, flags, _| {
            assert_eq!(flags, RENAME_EXCHANGE);
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .rename(
                p(1),
                b"a",
                p(1),
                b"b",
                RENAME_EXCHANGE,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.flags, RENAME_EXCHANGE);
    }

    #[test]
    fn rename_whiteout_flag() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, flags, _| {
            assert_eq!(flags, RENAME_WHITEOUT);
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .rename(
                p(1),
                b"src",
                p(1),
                b"dst",
                RENAME_WHITEOUT,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.flags, RENAME_WHITEOUT);
    }

    #[test]
    fn rename_noreplace_exchange_combined() {
        let flags = RENAME_NOREPLACE | RENAME_EXCHANGE;
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(move |_, _, _, _, f, _| {
            assert_eq!(f, flags);
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .rename(p(1), b"a", p(1), b"b", flags, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.flags, flags);
    }

    // -- Error propagation tests ---------------------------------------------

    #[test]
    fn rename_enoent_propagates() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Err(Errno::ENOENT));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rename(p(1), b"x", p(2), b"y", 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    #[test]
    fn rename_eacces_propagates() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rename(p(1), b"x", p(2), b"y", 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn rename_enotdir_propagates() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Err(Errno::ENOTDIR));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rename(p(1), b"x", p(2), b"y", 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOTDIR,
        );
    }

    #[test]
    fn rename_eisdir_propagates() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Err(Errno::EISDIR));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rename(p(1), b"x", p(2), b"y", 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EISDIR,
        );
    }

    #[test]
    fn rename_enotempty_propagates() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Err(Errno::ENOTEMPTY));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rename(p(1), b"x", p(2), b"y", 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOTEMPTY,
        );
    }

    #[test]
    fn rename_eexist_propagates() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Err(Errno::EEXIST));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rename(
                    p(1),
                    b"x",
                    p(2),
                    b"y",
                    RENAME_NOREPLACE,
                    &MockEngine::test_ctx()
                )
                .unwrap_err(),
            Errno::EEXIST,
        );
    }

    #[test]
    fn rename_exdev_propagates() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Err(Errno::EXDEV));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rename(p(1), b"x", p(2), b"y", 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EXDEV,
        );
    }

    #[test]
    fn rename_einval_propagates() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Err(Errno::EINVAL));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rename(p(1), b"x", p(2), b"y", 0xFF, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EINVAL,
        );
    }

    #[test]
    fn rename_eio_propagates() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rename(p(1), b"x", p(2), b"y", 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn rename_erofs_propagates() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Err(Errno::EROFS));
        assert_eq!(
            KmodPosixVfs::new(e)
                .rename(p(1), b"x", p(2), b"y", 0, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EROFS,
        );
    }

    // -- Cross-directory tests -----------------------------------------------

    #[test]
    fn rename_cross_directory() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|old_p, _, new_p, _, _, _| {
            assert_ne!(old_p, new_p);
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .rename(p(10), b"file", p(20), b"file", 0, &MockEngine::test_ctx())
            .unwrap();
        assert_ne!(plan.old_parent, plan.new_parent);
    }

    #[test]
    fn rename_cross_directory_preserves_name() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, new_n, _, _| {
            assert_eq!(new_n, b"renamed.txt");
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .rename(
                p(10),
                b"old.txt",
                p(20),
                b"renamed.txt",
                0,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.old_name, b"old.txt");
        assert_eq!(plan.new_name, b"renamed.txt");
    }

    // -- RenameArgs / dispatch_rename tests -----------------------------------

    #[test]
    fn dispatch_rename_works() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|old_p, old_n, new_p, new_n, flags, _| {
            assert_eq!(old_p, p(1));
            assert_eq!(old_n, b"src");
            assert_eq!(new_p, p(2));
            assert_eq!(new_n, b"dst");
            assert_eq!(flags, RENAME_NOREPLACE);
            Ok(())
        });
        let args = RenameArgs::new(
            p(1),
            b"src".to_vec(),
            p(2),
            b"dst".to_vec(),
            RENAME_NOREPLACE,
        );
        let plan = KmodPosixVfs::new(e)
            .dispatch_rename(&args, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.old_parent, p(1));
        assert_eq!(plan.new_parent, p(2));
        assert_eq!(plan.flags, RENAME_NOREPLACE);
    }

    #[test]
    fn dispatch_rename_same_as_rename() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Ok(()));
        let kmod = KmodPosixVfs::new(e);
        let plan1 = kmod
            .rename(
                p(3),
                b"a",
                p(4),
                b"b",
                RENAME_EXCHANGE,
                &MockEngine::test_ctx(),
            )
            .unwrap();

        let args = RenameArgs::new(p(3), b"a".to_vec(), p(4), b"b".to_vec(), RENAME_EXCHANGE);
        let mut e2 = MockEngine::new();
        e2.rename_fn = Box::new(|_, _, _, _, _, _| Ok(()));
        let plan2 = KmodPosixVfs::new(e2)
            .dispatch_rename(&args, &MockEngine::test_ctx())
            .unwrap();

        assert_eq!(plan1.old_parent, plan2.old_parent);
        assert_eq!(plan1.new_parent, plan2.new_parent);
    }

    #[test]
    fn dispatch_rename_error_propagation() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Err(Errno::ENOENT));
        let args = RenameArgs::new(p(1), b"x".to_vec(), p(2), b"y".to_vec(), 0);
        assert_eq!(
            KmodPosixVfs::new(e)
                .dispatch_rename(&args, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOENT,
        );
    }

    // -- Edge case tests -----------------------------------------------------

    #[test]
    fn rename_preserves_old_and_new_in_plan() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, _, _| Ok(()));
        let plan = KmodPosixVfs::new(e)
            .rename(
                p(10),
                b"old_name",
                p(20),
                b"new_name",
                0,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.old_parent, p(10));
        assert_eq!(plan.old_name, b"old_name");
        assert_eq!(plan.new_parent, p(20));
        assert_eq!(plan.new_name, b"new_name");
    }

    #[test]
    fn rename_empty_name_delegated() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, old_n, _, new_n, _, _| {
            assert_eq!(old_n, b"");
            assert_eq!(new_n, b"new");
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .rename(p(1), b"", p(2), b"new", 0, &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn rename_long_name_delegated() {
        let long_old = vec![b'x'; 255];
        let long_new = vec![b'y'; 255];
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, old_n, _, new_n, _, _| {
            assert_eq!(old_n.len(), 255);
            assert_eq!(new_n.len(), 255);
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .rename(p(5), &long_old, p(6), &long_new, 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.old_name.len(), 255);
        assert_eq!(plan.new_name.len(), 255);
    }

    #[test]
    fn rename_same_directory_preserves_parent() {
        let mut e = MockEngine::new();
        let parent = p(42);
        e.rename_fn = Box::new(move |old_p, _, new_p, _, _, _| {
            assert_eq!(old_p, parent);
            assert_eq!(new_p, parent);
            Ok(())
        });
        let plan = KmodPosixVfs::new(e)
            .rename(parent, b"a", parent, b"b", 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.old_parent, plan.new_parent);
    }

    // -- RenameArgs tests ----------------------------------------------------

    #[test]
    fn rename_args_construction() {
        let args = RenameArgs::new(
            p(1),
            b"old".to_vec(),
            p(2),
            b"new".to_vec(),
            RENAME_NOREPLACE | RENAME_WHITEOUT,
        );
        assert_eq!(args.old_parent, p(1));
        assert_eq!(args.old_name, b"old");
        assert_eq!(args.new_parent, p(2));
        assert_eq!(args.new_name, b"new");
        assert_eq!(args.flags, RENAME_NOREPLACE | RENAME_WHITEOUT);
    }

    // -- Flag constant tests -------------------------------------------------

    #[test]
    fn rename_flag_constants_are_powers_of_two() {
        assert_eq!(RENAME_NOREPLACE, 1);
        assert_eq!(RENAME_EXCHANGE, 2);
        assert_eq!(RENAME_WHITEOUT, 4);
    }

    #[test]
    fn rename_flag_zero_is_plain() {
        let mut e = MockEngine::new();
        e.rename_fn = Box::new(|_, _, _, _, flags, _| {
            assert_eq!(flags, 0);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .rename(p(1), b"a", p(2), b"b", 0, &MockEngine::test_ctx())
            .unwrap();
    }
}
