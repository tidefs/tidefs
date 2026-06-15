//! setattr mutation for the kernel VFS adapter -- K7 mutation seam.
//!
//! Delegates attribute mutations (truncate, chmod, chown, utimes) to the
//! VfsEngine through the canonical bridge dispatch, returning a SetattrPlan
//! with the operation result and engine-level outcome details.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::intent_record::encode_truncate_intent;
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::{
    EngineFileHandle, Errno, InodeAttr, InodeId, RequestCtx, SetAttr,
};
use tidefs_kmod_bridge::kernel_types::{SetattrOutcome, VfsEngine};

// -- SetattrPlan ------------------------------------------------------------

/// Operation result for a kernel VFS setattr attribute mutation.
///
/// Captures the target inode, the attribute-change mask (valid flags),
/// the updated inode attributes, and whether a truncate-size change
/// triggered block allocation or freeing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetattrPlan {
    /// Target inode whose attributes were mutated.
    pub inode: InodeId,
    /// Bitmask of changed attribute flags (FATTR_MODE, FATTR_UID, etc.).
    pub valid: u32,
    /// New mode if FATTR_MODE was set.
    pub mode: u32,
    /// New uid if FATTR_UID was set.
    pub uid: u32,
    /// New gid if FATTR_GID was set.
    pub gid: u32,
    /// New size if FATTR_SIZE was set.
    pub size: u64,
    /// New atime in nanoseconds if FATTR_ATIME was set.
    pub atime_ns: i64,
    /// New mtime in nanoseconds if FATTR_MTIME was set.
    pub mtime_ns: i64,
    /// Updated inode attributes after the mutation.
    pub attr: InodeAttr,
    /// Whether a size change required block allocation or freeing.
    pub truncate_block_change: bool,
}

impl SetattrPlan {
    /// Create a SetattrPlan from the setattr input and engine outcome.
    pub fn new(inode: InodeId, attr_req: &SetAttr, outcome: SetattrOutcome) -> Self {
        Self {
            inode,
            valid: attr_req.valid,
            mode: attr_req.mode,
            uid: attr_req.uid,
            gid: attr_req.gid,
            size: attr_req.size,
            atime_ns: attr_req.atime_ns,
            mtime_ns: attr_req.mtime_ns,
            attr: outcome.attr,
            truncate_block_change: outcome.truncate_block_change,
        }
    }
}

// -- bridge_setattr ---------------------------------------------------------

/// Delegate attribute mutation to the [`VfsEngine`].
///
/// Translates kernel VFS setattr parameters into the engine call and
/// returns a [`SetattrOutcome`] with the updated attributes and
/// truncate-block-change flag. The engine records the mutation in the
/// intent log for crash-safety.
///
/// # Errors
/// - `EPERM`: immutable attribute or unsupported flag
/// - `EACCES`: permission denied
/// - `EINVAL`: invalid attribute combination
/// - `ENOSPC`: truncate-extend allocation failure
/// - `EIO`: storage error
/// - `ESTALE`: inode generation mismatch
pub fn bridge_setattr<E: VfsEngine + ?Sized>(
    engine: &E,
    inode: InodeId,
    attr: &SetAttr,
    handle: Option<&EngineFileHandle>,
    ctx: &RequestCtx,
) -> Result<SetattrOutcome, Errno> {
    let updated_attr = engine.setattr(inode, attr, handle, ctx)?;
    // Detect truncate block change: size changed and either grew (needs
    // allocation) or shrank (may need freeing). The engine signals this
    // through the returned attr; for now we infer from whether ATTR_SIZE
    // was in the valid mask.
    let truncate_block_change = (attr.valid & tidefs_kmod_bridge::kernel_types::FATTR_SIZE) != 0;
    Ok(SetattrOutcome::new(updated_attr, truncate_block_change))
}

// -- dispatch ---------------------------------------------------------------

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Kernel VFS `inode_operations::setattr` dispatch.
    ///
    /// Apply attribute mutations (mode, uid, gid, size/truncate,
    /// atime/mtime) to `inode`. The `valid` bitmask in `attr` controls
    /// which fields are applied.
    ///
    /// Returns a [`SetattrPlan`] with the operation result on success.
    ///
    /// The truncate path (ATTR_SIZE) delegates block allocation/free to
    /// the existing extent-allocation path through the engine. Time
    /// updates (ATTR_MTIME/ATIME) and owner/group/mode changes are
    /// dispatched directly. Each attribute mutation is recorded in the
    /// intent log by the engine for crash-safe replay.
    ///
    /// # Errors
    /// - `EPERM`: immutable attribute or unsupported flag
    /// - `EACCES`: permission denied
    /// - `EINVAL`: invalid attribute combination
    /// - `ENOSPC`: truncate-extend allocation failure
    /// - `EIO`: storage error
    pub fn setattr(
        &mut self,
        inode: InodeId,
        attr: &SetAttr,
        handle: Option<&EngineFileHandle>,
        ctx: &RequestCtx,
    ) -> Result<SetattrPlan, Errno> {
        // Record truncate-intent before size change for crash-safety.
        if (attr.valid & tidefs_kmod_bridge::kernel_types::FATTR_SIZE) != 0 {
            let entry = encode_truncate_intent(inode, attr.size);
            self.record_mutation_intent(&entry)?;
        }
        let outcome = bridge_setattr(&self.engine, inode, attr, handle, ctx)?;

        // Rust source-model truncation coordination: when the file shrank,
        // clean up model dirty-writeback tracking and page-authority entries
        // beyond the new EOF. The mounted C truncate path uses Linux
        // filemap write-and-wait, unmap, invalidate, and truncate_setsize
        // helpers for live folios before/while applying the engine size.
        if (attr.valid & tidefs_kmod_bridge::kernel_types::FATTR_SIZE) != 0 {
            let new_size = attr.size;
            let page_threshold = crate::page_authority::page_index(new_size);
            // Remove source-model dirty ranges beyond the new EOF.
            self.dirty_folio_tracker.truncate_down(inode, new_size);
            // Invalidate source-model engine copies and clear page-authority
            // entries for all pages at or beyond the new EOF page.
            self.page_authority
                .truncate_down(&self.engine, inode, page_threshold);
        }

        Ok(SetattrPlan::new(inode, attr, outcome))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page_authority::PageOwnership;
    use crate::test_util::MockEngine;
    use crate::writeback::DirtyRange;
    use crate::TideBox as Box;
    use alloc::vec::Vec;
    use tidefs_kmod_bridge::kernel_types::{
        FileHandleId, Generation, InodeFlags, NodeKind, PosixAttrs, FATTR_ATIME, FATTR_GID,
        FATTR_MODE, FATTR_MTIME, FATTR_SIZE, FATTR_UID,
    };

    fn fh(ino: u64, id: u64) -> EngineFileHandle {
        EngineFileHandle {
            inode_id: InodeId::new(ino),
            open_flags: 0,
            fh_id: FileHandleId::new(id),
            lock_owner: 0,
        }
    }

    fn file_attr(ino: u64) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        }
    }

    // -- SetattrPlan unit tests ---------------------------------------------

    #[test]
    fn plan_construction_chmod() {
        let base = file_attr(10);
        let expected_mode = 0o100600;
        let mut updated = base;
        updated.posix.mode = expected_mode;
        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = expected_mode;
        let outcome = SetattrOutcome::new(updated, false);
        let plan = SetattrPlan::new(InodeId::new(10), &set, outcome);
        assert_eq!(plan.inode, InodeId::new(10));
        assert_eq!(plan.valid, FATTR_MODE);
        assert_eq!(plan.mode, expected_mode);
        assert_eq!(plan.attr.posix.mode, expected_mode);
        assert!(!plan.truncate_block_change);
    }

    #[test]
    fn plan_construction_truncate() {
        let base = file_attr(11);
        let new_size: u64 = 8192;
        let mut updated = base;
        updated.posix.size = new_size;
        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = new_size;
        let outcome = SetattrOutcome::new(updated, true);
        let plan = SetattrPlan::new(InodeId::new(11), &set, outcome);
        assert_eq!(plan.inode, InodeId::new(11));
        assert_eq!(plan.valid, FATTR_SIZE);
        assert_eq!(plan.size, new_size);
        assert_eq!(plan.attr.posix.size, new_size);
        assert!(plan.truncate_block_change);
    }

    #[test]
    fn plan_construction_chown() {
        let base = file_attr(12);
        let new_uid: u32 = 42;
        let new_gid: u32 = 99;
        let mut updated = base;
        updated.posix.uid = new_uid;
        updated.posix.gid = new_gid;
        let mut set = SetAttr::new();
        set.valid = FATTR_UID | FATTR_GID;
        set.uid = new_uid;
        set.gid = new_gid;
        let outcome = SetattrOutcome::new(updated, false);
        let plan = SetattrPlan::new(InodeId::new(12), &set, outcome);
        assert_eq!(plan.valid, FATTR_UID | FATTR_GID);
        assert_eq!(plan.uid, new_uid);
        assert_eq!(plan.gid, new_gid);
        assert!(!plan.truncate_block_change);
    }

    #[test]
    fn plan_construction_utimes() {
        let base = file_attr(13);
        let atime: i64 = 1_700_000_000_000_000_000;
        let mtime: i64 = 1_700_000_001_000_000_000;
        let mut updated = base;
        updated.posix.atime_ns = atime;
        updated.posix.mtime_ns = mtime;
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME | FATTR_MTIME;
        set.atime_ns = atime;
        set.mtime_ns = mtime;
        let outcome = SetattrOutcome::new(updated, false);
        let plan = SetattrPlan::new(InodeId::new(13), &set, outcome);
        assert_eq!(plan.valid, FATTR_ATIME | FATTR_MTIME);
        assert_eq!(plan.atime_ns, atime);
        assert_eq!(plan.mtime_ns, mtime);
        assert!(!plan.truncate_block_change);
    }

    // -- bridge_setattr unit tests ------------------------------------------

    #[test]
    fn bridge_setattr_chmod_works() {
        let base = file_attr(10);
        let expected_mode = 0o100600;
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |ino, attr, h, _| {
            assert_eq!(ino, InodeId::new(10));
            assert_eq!(attr.valid, FATTR_MODE);
            assert_eq!(attr.mode, expected_mode);
            assert!(h.is_none());
            let mut r = base;
            r.posix.mode = expected_mode;
            Ok(r)
        });
        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = expected_mode;
        let outcome =
            bridge_setattr(&e, InodeId::new(10), &set, None, &MockEngine::test_ctx()).unwrap();
        assert_eq!(outcome.attr.posix.mode, expected_mode);
        assert!(!outcome.truncate_block_change);
    }

    #[test]
    fn bridge_setattr_truncate_detects_block_change() {
        let base = file_attr(11);
        let new_size: u64 = 8192;
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |ino, attr, h, _ctx| {
            assert_eq!(ino, InodeId::new(11));
            assert_eq!(attr.valid, FATTR_SIZE);
            assert_eq!(attr.size, new_size);
            assert!(h.is_some());
            let mut r = base;
            r.posix.size = new_size;
            Ok(r)
        });
        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = new_size;
        let h = fh(11, 1);
        let outcome = bridge_setattr(
            &e,
            InodeId::new(11),
            &set,
            Some(&h),
            &MockEngine::test_ctx(),
        )
        .unwrap();
        assert_eq!(outcome.attr.posix.size, new_size);
        assert!(outcome.truncate_block_change);
    }

    #[test]
    fn bridge_setattr_chown_works() {
        let base = file_attr(12);
        let new_uid: u32 = 42;
        let new_gid: u32 = 99;
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |ino, attr, h, _| {
            assert_eq!(ino, InodeId::new(12));
            assert_eq!(attr.valid, FATTR_UID | FATTR_GID);
            assert_eq!(attr.uid, new_uid);
            assert_eq!(attr.gid, new_gid);
            assert!(h.is_none());
            let mut r = base;
            r.posix.uid = new_uid;
            r.posix.gid = new_gid;
            Ok(r)
        });
        let mut set = SetAttr::new();
        set.valid = FATTR_UID | FATTR_GID;
        set.uid = new_uid;
        set.gid = new_gid;
        let outcome =
            bridge_setattr(&e, InodeId::new(12), &set, None, &MockEngine::test_ctx()).unwrap();
        assert_eq!(outcome.attr.posix.uid, new_uid);
        assert_eq!(outcome.attr.posix.gid, new_gid);
        assert!(!outcome.truncate_block_change);
    }

    #[test]
    fn bridge_setattr_utimes_works() {
        let base = file_attr(13);
        let atime: i64 = 1_700_000_000_000_000_000;
        let mtime: i64 = 1_700_000_001_000_000_000;
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |ino, attr, h, _| {
            assert_eq!(ino, InodeId::new(13));
            assert_eq!(attr.valid, FATTR_ATIME | FATTR_MTIME);
            assert_eq!(attr.atime_ns, atime);
            assert_eq!(attr.mtime_ns, mtime);
            assert!(h.is_none());
            let mut r = base;
            r.posix.atime_ns = atime;
            r.posix.mtime_ns = mtime;
            Ok(r)
        });
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME | FATTR_MTIME;
        set.atime_ns = atime;
        set.mtime_ns = mtime;
        let outcome =
            bridge_setattr(&e, InodeId::new(13), &set, None, &MockEngine::test_ctx()).unwrap();
        assert_eq!(outcome.attr.posix.atime_ns, atime);
        assert_eq!(outcome.attr.posix.mtime_ns, mtime);
        assert!(!outcome.truncate_block_change);
    }

    // -- KmodPosixVfs::setattr dispatch tests -------------------------------

    #[test]
    fn setattr_chmod_returns_updated_mode() {
        let base = file_attr(10);
        let expected_mode = 0o100600;
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |ino, attr, h, _| {
            assert_eq!(ino, InodeId::new(10));
            assert_eq!(attr.valid, FATTR_MODE);
            assert_eq!(attr.mode, expected_mode);
            assert!(h.is_none());
            let mut r = base;
            r.posix.mode = expected_mode;
            Ok(r)
        });
        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = expected_mode;
        let mut kmod = KmodPosixVfs::new(e);
        let plan = kmod
            .setattr(InodeId::new(10), &set, None, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.attr.posix.mode, expected_mode);
    }

    #[test]
    fn setattr_truncate_works() {
        let base = file_attr(11);
        let new_size: u64 = 8192;
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |ino, attr, h, _ctx| {
            assert_eq!(ino, InodeId::new(11));
            assert_eq!(attr.valid, FATTR_SIZE);
            assert_eq!(attr.size, new_size);
            assert!(h.is_some());
            let mut r = base;
            r.posix.size = new_size;
            Ok(r)
        });
        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = new_size;
        let h = fh(11, 1);
        let mut kmod = KmodPosixVfs::new(e);
        let plan = kmod
            .setattr(InodeId::new(11), &set, Some(&h), &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.attr.posix.size, new_size);
        assert!(plan.truncate_block_change);
    }

    #[test]
    fn setattr_chown_works() {
        let base = file_attr(12);
        let new_uid: u32 = 42;
        let new_gid: u32 = 99;
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |ino, attr, h, _| {
            assert_eq!(ino, InodeId::new(12));
            assert_eq!(attr.valid, FATTR_UID | FATTR_GID);
            assert_eq!(attr.uid, new_uid);
            assert_eq!(attr.gid, new_gid);
            assert!(h.is_none());
            let mut r = base;
            r.posix.uid = new_uid;
            r.posix.gid = new_gid;
            Ok(r)
        });
        let mut set = SetAttr::new();
        set.valid = FATTR_UID | FATTR_GID;
        set.uid = new_uid;
        set.gid = new_gid;
        let mut kmod = KmodPosixVfs::new(e);
        let plan = kmod
            .setattr(InodeId::new(12), &set, None, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.attr.posix.uid, new_uid);
        assert_eq!(plan.attr.posix.gid, new_gid);
    }

    #[test]
    fn setattr_utimes_works() {
        let base = file_attr(13);
        let atime: i64 = 1_700_000_000_000_000_000;
        let mtime: i64 = 1_700_000_001_000_000_000;
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |ino, attr, h, _| {
            assert_eq!(ino, InodeId::new(13));
            assert_eq!(attr.valid, FATTR_ATIME | FATTR_MTIME);
            assert_eq!(attr.atime_ns, atime);
            assert_eq!(attr.mtime_ns, mtime);
            assert!(h.is_none());
            let mut r = base;
            r.posix.atime_ns = atime;
            r.posix.mtime_ns = mtime;
            Ok(r)
        });
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME | FATTR_MTIME;
        set.atime_ns = atime;
        set.mtime_ns = mtime;
        let mut kmod = KmodPosixVfs::new(e);
        let plan = kmod
            .setattr(InodeId::new(13), &set, None, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.attr.posix.atime_ns, atime);
        assert_eq!(plan.attr.posix.mtime_ns, mtime);
    }

    // -- Error propagation tests --------------------------------------------

    #[test]
    fn setattr_eacces_propagates() {
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(|_, _, _, _| Err(Errno::EACCES));
        let mut kmod = KmodPosixVfs::new(e);
        assert_eq!(
            kmod.setattr(
                InodeId::new(20),
                &SetAttr::new(),
                None,
                &MockEngine::test_ctx()
            )
            .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn setattr_eperm_propagates() {
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(|_, _, _, _| Err(Errno::EPERM));
        let mut kmod = KmodPosixVfs::new(e);
        assert_eq!(
            kmod.setattr(
                InodeId::new(20),
                &SetAttr::new(),
                None,
                &MockEngine::test_ctx()
            )
            .unwrap_err(),
            Errno::EPERM,
        );
    }

    #[test]
    fn setattr_einval_propagates() {
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(|_, _, _, _| Err(Errno::EINVAL));
        let mut kmod = KmodPosixVfs::new(e);
        assert_eq!(
            kmod.setattr(
                InodeId::new(20),
                &SetAttr::new(),
                None,
                &MockEngine::test_ctx()
            )
            .unwrap_err(),
            Errno::EINVAL,
        );
    }

    #[test]
    fn setattr_eio_propagates() {
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(|_, _, _, _| Err(Errno::EIO));
        let mut kmod = KmodPosixVfs::new(e);
        assert_eq!(
            kmod.setattr(
                InodeId::new(20),
                &SetAttr::new(),
                None,
                &MockEngine::test_ctx()
            )
            .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn setattr_enospc_propagates() {
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(|_, _, _, _| Err(Errno::ENOSPC));
        let mut kmod = KmodPosixVfs::new(e);
        assert_eq!(
            kmod.setattr(
                InodeId::new(20),
                &SetAttr::new(),
                None,
                &MockEngine::test_ctx()
            )
            .unwrap_err(),
            Errno::ENOSPC,
        );
    }

    #[test]
    fn bridge_setattr_mode_truncate_combined() {
        let base = file_attr(15);
        let expected_mode = 0o100400;
        let new_size: u64 = 4096;
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |ino, attr, h, _| {
            assert_eq!(ino, InodeId::new(15));
            assert_eq!(attr.valid, FATTR_MODE | FATTR_SIZE);
            assert_eq!(attr.mode, expected_mode);
            assert_eq!(attr.size, new_size);
            assert!(h.is_none());
            let mut r = base;
            r.posix.mode = expected_mode;
            r.posix.size = new_size;
            Ok(r)
        });
        let mut set = SetAttr::new();
        set.valid = FATTR_MODE | FATTR_SIZE;
        set.mode = expected_mode;
        set.size = new_size;
        let outcome =
            bridge_setattr(&e, InodeId::new(15), &set, None, &MockEngine::test_ctx()).unwrap();
        assert_eq!(outcome.attr.posix.mode, expected_mode);
        assert_eq!(outcome.attr.posix.size, new_size);
        assert!(outcome.truncate_block_change);
    }

    // ── Truncation-down coordination tests ────────────────────────

    /// setattr with FATTR_SIZE shrink cleans dirty ranges beyond new EOF.
    #[test]
    fn setattr_truncate_down_cleans_dirty_tracker() {
        let base = file_attr(11);
        let new_size: u64 = 4096;
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |ino, attr, h, _ctx| {
            assert_eq!(ino, InodeId::new(11));
            assert_eq!(attr.valid, FATTR_SIZE);
            assert_eq!(attr.size, new_size);
            assert!(h.is_some());
            let mut r = base;
            r.posix.size = new_size;
            Ok(r)
        });
        let mut kmod = KmodPosixVfs::new(e);

        // Pre-populate dirty ranges at various offsets
        kmod.dirty_folio_tracker.add(InodeId::new(11), 0, 8192);
        kmod.dirty_folio_tracker.add(InodeId::new(11), 12288, 4096);

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = new_size;
        let h = fh(11, 1);
        let plan = kmod
            .setattr(InodeId::new(11), &set, Some(&h), &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.attr.posix.size, new_size);

        // Dirty range [0, 8192) straddles the 4096 threshold:
        // should be trimmed to [0, 4096).
        // Dirty range [12288, 16384) is fully beyond: should be removed.
        let ranges: Vec<_> = kmod.dirty_folio_tracker.iter().collect();
        assert_eq!(
            ranges.len(),
            1,
            "expected 1 trimmed dirty range, got {ranges:?}"
        );
        assert_eq!(
            ranges[0],
            (InodeId::new(11), DirtyRange::new(0, 4096)),
            "expected trimmed range [0, 4096), got {:?}",
            ranges[0]
        );
    }

    /// setattr truncate to zero clears all dirty ranges for the inode.
    #[test]
    fn setattr_truncate_to_zero_clears_all_dirty_ranges() {
        let base = file_attr(11);
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |_ino, attr, _h, _ctx| {
            assert_eq!(attr.size, 0);
            let mut r = base;
            r.posix.size = 0;
            Ok(r)
        });
        let mut kmod = KmodPosixVfs::new(e);

        kmod.dirty_folio_tracker.add(InodeId::new(11), 0, 4096);
        kmod.dirty_folio_tracker.add(InodeId::new(11), 8192, 4096);

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 0;
        let _ = kmod
            .setattr(InodeId::new(11), &set, None, &MockEngine::test_ctx())
            .unwrap();

        assert!(
            kmod.dirty_folio_tracker.is_empty(),
            "all dirty ranges should be cleared on truncate to zero"
        );
    }

    /// setattr truncate-down clears page-authority for pages beyond new EOF.
    #[test]
    fn setattr_truncate_down_clears_page_authority() {
        let base = file_attr(11);
        let new_size: u64 = 4096;
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |_ino, _attr, _h, _ctx| {
            let mut r = base;
            r.posix.size = new_size;
            Ok(r)
        });
        let mut kmod = KmodPosixVfs::new(e);

        // Populate page authority entries for pages 0, 1, 2, 3
        kmod.page_authority
            .insert(InodeId::new(11), 0, PageOwnership::KernelOwned);
        kmod.page_authority
            .insert(InodeId::new(11), 1, PageOwnership::KernelOwned);
        kmod.page_authority
            .insert(InodeId::new(11), 2, PageOwnership::KernelOwned);
        kmod.page_authority
            .insert(InodeId::new(11), 3, PageOwnership::Shared);

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = new_size; // page_index(4096) = 1
        let _ = kmod
            .setattr(InodeId::new(11), &set, None, &MockEngine::test_ctx())
            .unwrap();

        // Page 0 should still be KernelOwned (below threshold)
        assert_eq!(
            kmod.page_authority.get(InodeId::new(11), 0),
            PageOwnership::KernelOwned,
            "page 0 should survive truncate-down"
        );

        // Pages 1, 2, 3 should be cleared (at or beyond page_threshold=1)
        assert_eq!(
            kmod.page_authority.get(InodeId::new(11), 1),
            PageOwnership::EngineOwned,
            "page 1 should be cleared on truncate-down"
        );
        assert_eq!(
            kmod.page_authority.get(InodeId::new(11), 2),
            PageOwnership::EngineOwned,
            "page 2 should be cleared on truncate-down"
        );
        assert_eq!(
            kmod.page_authority.get(InodeId::new(11), 3),
            PageOwnership::EngineOwned,
            "page 3 should be cleared on truncate-down"
        );
    }

    /// setattr without FATTR_SIZE does not disturb dirty tracking.
    #[test]
    fn setattr_no_truncate_does_not_clean_dirty_tracker() {
        let base = file_attr(11);
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |_ino, _attr, _h, _ctx| {
            let mut r = base;
            r.posix.mode = 0o100600;
            Ok(r)
        });
        let mut kmod = KmodPosixVfs::new(e);

        kmod.dirty_folio_tracker.add(InodeId::new(11), 0, 8192);
        kmod.dirty_folio_tracker.add(InodeId::new(11), 12288, 4096);

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o100600;
        let _ = kmod
            .setattr(InodeId::new(11), &set, None, &MockEngine::test_ctx())
            .unwrap();

        // Dirty ranges should be untouched
        assert_eq!(kmod.dirty_folio_tracker.len(), 2);
    }

    /// setattr truncate to zero with page_authority entries populated.
    #[test]
    fn setattr_truncate_to_zero_clears_all_page_authority() {
        let base = file_attr(11);
        let mut e = MockEngine::new();
        e.setattr_fn = Box::new(move |_ino, _attr, _h, _ctx| {
            let mut r = base;
            r.posix.size = 0;
            Ok(r)
        });
        let mut kmod = KmodPosixVfs::new(e);

        kmod.page_authority
            .insert(InodeId::new(11), 0, PageOwnership::KernelOwned);
        kmod.page_authority
            .insert(InodeId::new(11), 5, PageOwnership::Shared);
        kmod.page_authority
            .insert(InodeId::new(42), 0, PageOwnership::KernelOwned);

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 0;
        let _ = kmod
            .setattr(InodeId::new(11), &set, None, &MockEngine::test_ctx())
            .unwrap();

        // All pages for inode 11 should be cleared (page_threshold=0)
        assert_eq!(
            kmod.page_authority.get(InodeId::new(11), 0),
            PageOwnership::EngineOwned
        );
        assert_eq!(
            kmod.page_authority.get(InodeId::new(11), 5),
            PageOwnership::EngineOwned
        );
        // Other inode should be untouched
        assert_eq!(
            kmod.page_authority.get(InodeId::new(42), 0),
            PageOwnership::KernelOwned
        );
    }
}
