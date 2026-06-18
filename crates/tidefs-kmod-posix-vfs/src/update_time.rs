// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! inode_operations update_time dispatch for the kernel VFS adapter --
//! K7 timestamp bridge.
//! This module closes the last "Missing" gap from the #5637 VFS dispatch
//! completeness audit.  It bridges the Linux 7.0 `inode_operations::update_time`
//! callback through VfsEngine::setattr so that kernel-driven atime/mtime/ctime
//! updates are persisted through VfsEngine attribute storage instead of being
//! written directly into `struct inode` fields and lost on eviction.
//! The Linux 7.0 signature is:
//! ```c
//! int (*update_time)(struct inode *inode, struct timespec64 *time, int flags);
//! ```
//! where `flags` encodes `S_ATIME`, `S_MTIME`, `S_CTIME` (the `S_VERSION`
//! flag is out of scope).
//! POSIX semantics: when atime or mtime is explicitly updated, ctime is
//! automatically bumped to the same value unless ctime was also explicitly
//! supplied.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{
    Errno, InodeId, RequestCtx, SetAttr, FATTR_ATIME, FATTR_CTIME, FATTR_MTIME,
};

// -- Linux VFS update_time flag constants ---

/// atime update requested.
pub const S_ATIME: u32 = 1 << 0;
/// mtime update requested.
pub const S_MTIME: u32 = 1 << 1;
/// ctime update requested.
pub const S_CTIME: u32 = 1 << 2;

// -- UpdateTimePlan ---

/// operation result for a kernel-driven timestamp update.
///
/// Captures the inode, requested flags, the time(s) applied, a pre-update
/// covering all inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateTimePlan {
    /// The inode whose timestamps were updated.
    pub inode: InodeId,
    /// The flag mask that was evaluated (S_ATIME | S_MTIME | S_CTIME).
    pub flags: u32,
    /// The atime value that was applied (in nanoseconds).
    pub atime_ns: i64,
    /// The mtime value that was applied (in nanoseconds).
    pub mtime_ns: i64,
    /// The ctime value that was applied (in nanoseconds).
    pub ctime_ns: i64,
    /// Pre-update atime snapshot (in nanoseconds).
    pub pre_atime_ns: i64,
    /// Pre-update mtime snapshot (in nanoseconds).
    pub pre_mtime_ns: i64,
    /// Pre-update ctime snapshot (in nanoseconds).
    pub pre_ctime_ns: i64,
}

impl UpdateTimePlan {
    /// Create an UpdateTimePlan with field-preserving construction.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inode: InodeId,
        flags: u32,
        atime_ns: i64,
        mtime_ns: i64,
        ctime_ns: i64,
        pre_atime_ns: i64,
        pre_mtime_ns: i64,
        pre_ctime_ns: i64,
    ) -> Self {
        Self {
            inode,
            flags,
            atime_ns,
            mtime_ns,
            ctime_ns,
            pre_atime_ns,
            pre_mtime_ns,
            pre_ctime_ns,
        }
    }
}

// -- update_time dispatch ---

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Kernel VFS `inode_operations::update_time` dispatch.
    ///
    /// Called by the Linux VFS layer when timestamp updates are needed
    /// (e.g. on read for atime, write for mtime/ctime, or explicit utimes).
    ///
    /// # Parameters
    ///
    /// * `inode` - the inode whose timestamps to update.
    /// * `time_ns` - the time to apply, in signed nanoseconds since epoch.
    ///   When `None`, `current_time()` is used (the caller must supply the
    ///   resolved value; the kernel adapter resolves this before calling).
    /// * `flags` - bitmask of `S_ATIME`, `S_MTIME`, `S_CTIME`.
    ///
    /// # POSIX ctime semantics
    ///
    /// When atime or mtime is explicitly set in `flags` and ctime is not
    /// also in `flags`, ctime is automatically bumped to the same time
    /// value to reflect the metadata change.
    ///
    /// # Returns
    ///
    /// * `Ok(UpdateTimePlan)` with the result shape.
    /// * `Err(Errno::EIO)` on VfsEngine failure.
    /// * `Err(Errno::EROFS)` on read-only filesystem (propagated).
    pub fn update_time(
        &self,
        inode: InodeId,
        time_ns: Option<i64>,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<UpdateTimePlan, Errno> {
        // No-op: nothing requested.
        if flags == 0 {
            return Ok(UpdateTimePlan::new(inode, 0, 0, 0, 0, 0, 0, 0));
        }

        // Resolve the time value.
        let now_ns = time_ns.unwrap_or(0);

        // Capture pre-update timestamp snapshot via getattr.
        let pre_attr = self.engine.getattr(inode, None, ctx)?;
        let pre_atime_ns = pre_attr.posix.atime_ns;
        let pre_mtime_ns = pre_attr.posix.mtime_ns;
        let pre_ctime_ns = pre_attr.posix.ctime_ns;

        // Decode flags -- only S_ATIME, S_MTIME, S_CTIME are recognized.
        let want_atime = (flags & S_ATIME) != 0;
        let want_mtime = (flags & S_MTIME) != 0;
        let want_ctime = (flags & S_CTIME) != 0;

        // Prepare the SetAttr mask.
        let mut set = SetAttr::new();
        let mut effective_atime = pre_atime_ns;
        let mut effective_mtime = pre_mtime_ns;
        let mut effective_ctime = pre_ctime_ns;

        let mut timestamp_changed = false;
        if want_atime {
            set.valid |= FATTR_ATIME;
            set.atime_ns = now_ns;
            if pre_atime_ns != now_ns {
                effective_atime = now_ns;
                timestamp_changed = true;
            }
        }
        if want_mtime {
            set.valid |= FATTR_MTIME;
            set.mtime_ns = now_ns;
            if pre_mtime_ns != now_ns {
                effective_mtime = now_ns;
                timestamp_changed = true;
            }
        }

        // POSIX ctimen update: if atime or mtime is being set and
        // ctime was not explicitly included in the flags, bump ctime too.
        let auto_ctime = timestamp_changed && !want_ctime;
        if want_ctime || auto_ctime {
            set.valid |= FATTR_CTIME;
            set.ctime_ns = now_ns;
            if pre_ctime_ns != now_ns {
                effective_ctime = now_ns;
                timestamp_changed = true;
            }
        }

        // Delegate to VfsEngine::setattr (timestamp fields only).
        if set.valid != 0 && (timestamp_changed || want_ctime) {
            self.engine.setattr(inode, &set, None, ctx)?;
        }

        Ok(UpdateTimePlan::new(
            inode,
            flags,
            effective_atime,
            effective_mtime,
            effective_ctime,
            pre_atime_ns,
            pre_mtime_ns,
            pre_ctime_ns,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::{
        Generation, InodeAttr, InodeFlags, NodeKind, PosixAttrs,
    };

    fn make_attr(ino: u64, atime_ns: i64, mtime_ns: i64, ctime_ns: i64) -> InodeAttr {
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
                atime_ns,
                mtime_ns,
                ctime_ns,
                btime_ns: 0,
                size: 4096,
                blocks_512: 8,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        }
    }

    const T0: i64 = 1_700_000_000_000_000_000;
    const T1: i64 = 1_700_000_001_000_000_000;
    const T2: i64 = 1_700_000_002_000_000_000;

    // -- Single-flag updates ---

    #[test]
    fn atime_only_update() {
        let attr = make_attr(10, T0, T0, T0);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(move |ino, set, _, _| {
            assert_eq!(ino, InodeId::new(10));
            assert_eq!(set.valid, FATTR_ATIME | FATTR_CTIME);
            assert_eq!(set.atime_ns, T1);
            let mut r = attr;
            r.posix.atime_ns = T1;
            r.posix.ctime_ns = T1;
            Ok(r)
        });
        let plan = KmodPosixVfs::new(e)
            .update_time(InodeId::new(10), Some(T1), S_ATIME, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.atime_ns, T1);
        assert_eq!(plan.mtime_ns, T0);
        assert_eq!(plan.ctime_ns, T1);
        assert_eq!(plan.pre_atime_ns, T0);
    }

    #[test]
    fn mtime_only_update() {
        let attr = make_attr(11, T0, T0, T0);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(move |_, set, _, _| {
            assert_eq!(set.valid, FATTR_MTIME | FATTR_CTIME);
            assert_eq!(set.mtime_ns, T2);
            let mut r = attr;
            r.posix.mtime_ns = T2;
            r.posix.ctime_ns = T2;
            Ok(r)
        });
        let plan = KmodPosixVfs::new(e)
            .update_time(InodeId::new(11), Some(T2), S_MTIME, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.atime_ns, T0);
        assert_eq!(plan.mtime_ns, T2);
        assert_eq!(plan.ctime_ns, T2);
    }

    #[test]
    fn ctime_only_update_no_auto_bump() {
        let attr = make_attr(12, T0, T0, T0);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(move |_, set, _, _| {
            assert_eq!(set.valid, FATTR_CTIME);
            assert_eq!(set.ctime_ns, T1);
            let mut r = attr;
            r.posix.ctime_ns = T1;
            Ok(r)
        });
        let plan = KmodPosixVfs::new(e)
            .update_time(InodeId::new(12), Some(T1), S_CTIME, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.atime_ns, T0);
        assert_eq!(plan.mtime_ns, T0);
        assert_eq!(plan.ctime_ns, T1);
    }

    // -- Multi-flag updates ---

    #[test]
    fn atime_and_mtime_update() {
        let attr = make_attr(13, T0, T0, T0);
        let t = T1;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(move |_, set, _, _| {
            assert_eq!(set.valid, FATTR_ATIME | FATTR_MTIME | FATTR_CTIME);
            assert_eq!(set.atime_ns, t);
            assert_eq!(set.mtime_ns, t);
            let mut r = attr;
            r.posix.atime_ns = t;
            r.posix.mtime_ns = t;
            r.posix.ctime_ns = t;
            Ok(r)
        });
        let plan = KmodPosixVfs::new(e)
            .update_time(
                InodeId::new(13),
                Some(T1),
                S_ATIME | S_MTIME,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.atime_ns, T1);
        assert_eq!(plan.mtime_ns, T1);
        assert_eq!(plan.ctime_ns, T1);
    }

    #[test]
    fn all_three_explicit() {
        let attr = make_attr(14, T0, T0, T0);
        let t = T2;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(move |_, set, _, _| {
            assert_eq!(set.valid, FATTR_ATIME | FATTR_MTIME | FATTR_CTIME);
            let mut r = attr;
            r.posix.atime_ns = t;
            r.posix.mtime_ns = t;
            r.posix.ctime_ns = t;
            Ok(r)
        });
        let plan = KmodPosixVfs::new(e)
            .update_time(
                InodeId::new(14),
                Some(T2),
                S_ATIME | S_MTIME | S_CTIME,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.atime_ns, T2);
        assert_eq!(plan.mtime_ns, T2);
        assert_eq!(plan.ctime_ns, T2);
    }

    // -- current_time() fallback ---

    #[test]
    fn none_time_uses_current_time() {
        let attr = make_attr(15, T0, T0, T0);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(move |_, set, _, _| {
            assert_eq!(set.atime_ns, 0);
            let mut r = attr;
            r.posix.atime_ns = 0;
            r.posix.ctime_ns = 0;
            Ok(r)
        });
        let plan = KmodPosixVfs::new(e)
            .update_time(InodeId::new(15), None, S_ATIME, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.atime_ns, 0);
    }

    // -- Error propagation ---

    #[test]
    fn erofs_propagated() {
        let attr = make_attr(16, T0, T0, T0);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(|_, _, _, _| Err(Errno::EROFS));
        let err = KmodPosixVfs::new(e)
            .update_time(InodeId::new(16), Some(T1), S_ATIME, &MockEngine::test_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::EROFS);
    }

    #[test]
    fn eio_propagated() {
        let attr = make_attr(17, T0, T0, T0);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(|_, _, _, _| Err(Errno::EIO));
        let err = KmodPosixVfs::new(e)
            .update_time(InodeId::new(17), Some(T1), S_ATIME, &MockEngine::test_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::EIO);
    }

    #[test]
    fn getattr_failure_propagates() {
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(|_, _, _| Err(Errno::ESTALE));
        let err = KmodPosixVfs::new(e)
            .update_time(InodeId::new(18), Some(T1), S_ATIME, &MockEngine::test_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::ESTALE);
    }

    // -- Empty flags ---

    #[test]
    fn empty_flags_noop() {
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(|_, _, _| panic!("getattr should not be called"));
        e.setattr_fn = Box::new(|_, _, _, _| panic!("setattr should not be called"));
        let plan = KmodPosixVfs::new(e)
            .update_time(InodeId::new(19), Some(T1), 0, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan.flags, 0);
        assert_eq!(plan.atime_ns, 0);
        assert_eq!(plan.mtime_ns, 0);
        assert_eq!(plan.ctime_ns, 0);
    }

    #[test]
    fn unchanged_atime_does_not_call_setattr_or_bump_ctime() {
        let attr = make_attr(20, T1, T0, T2);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(|_, _, _, _| panic!("setattr should not be called"));

        let plan = KmodPosixVfs::new(e)
            .update_time(InodeId::new(20), Some(T1), S_ATIME, &MockEngine::test_ctx())
            .unwrap();

        assert_eq!(plan.atime_ns, T1);
        assert_eq!(plan.mtime_ns, T0);
        assert_eq!(plan.ctime_ns, T2);
        assert_eq!(plan.pre_ctime_ns, T2);
    }

    // -- Concurrent isolation ---

    #[test]
    fn concurrent_isolation_two_inodes() {
        let attr_a = make_attr(30, T0, T0, T0);
        let attr_b = make_attr(31, T0, T0, T0);

        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |ino, _, _| {
            if ino == InodeId::new(30) {
                Ok(attr_a)
            } else {
                Ok(attr_b)
            }
        });
        e.setattr_fn = Box::new(move |ino, set, _, _| {
            let mut r = if ino == InodeId::new(30) {
                make_attr(30, T0, T0, T0)
            } else {
                make_attr(31, T0, T0, T0)
            };
            if (set.valid & FATTR_ATIME) != 0 {
                r.posix.atime_ns = set.atime_ns;
            }
            if (set.valid & FATTR_MTIME) != 0 {
                r.posix.mtime_ns = set.mtime_ns;
            }
            if (set.valid & FATTR_CTIME) != 0 {
                r.posix.ctime_ns = set.ctime_ns;
            }
            Ok(r)
        });

        let plan_a = KmodPosixVfs::new(e)
            .update_time(InodeId::new(30), Some(T1), S_ATIME, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan_a.pre_atime_ns, T0);
        assert_eq!(plan_a.atime_ns, T1);
        assert_eq!(plan_a.mtime_ns, T0);

        let attr_b2 = make_attr(31, T0, T0, T0);
        let mut e2 = MockEngine::new();
        e2.getattr_fn = Box::new(move |_, _, _| Ok(attr_b2));
        e2.setattr_fn = Box::new(move |_, set, _, _| {
            let mut r = make_attr(31, T0, T0, T0);
            if (set.valid & FATTR_MTIME) != 0 {
                r.posix.mtime_ns = set.mtime_ns;
            }
            if (set.valid & FATTR_CTIME) != 0 {
                r.posix.ctime_ns = set.ctime_ns;
            }
            Ok(r)
        });

        let plan_b = KmodPosixVfs::new(e2)
            .update_time(InodeId::new(31), Some(T2), S_MTIME, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(plan_b.pre_mtime_ns, T0);
        assert_eq!(plan_b.mtime_ns, T2);
    }

    // -- Pre-update snapshot captured ---

    #[test]
    fn pre_update_snapshot_captured() {
        let attr = make_attr(40, 1000, 2000, 3000);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(move |_, _, _, _| {
            let mut r = attr;
            r.posix.atime_ns = 9999;
            r.posix.ctime_ns = 9999;
            Ok(r)
        });
        let plan = KmodPosixVfs::new(e)
            .update_time(
                InodeId::new(40),
                Some(9999),
                S_ATIME,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.pre_atime_ns, 1000);
        assert_eq!(plan.pre_mtime_ns, 2000);
        assert_eq!(plan.pre_ctime_ns, 3000);
        assert_eq!(plan.atime_ns, 9999);
        assert_eq!(plan.ctime_ns, 9999);
    }

    // -- Explicit ctime with atime+mtime ---

    #[test]
    fn explicit_ctime_with_atime_mtime() {
        let attr = make_attr(50, T0, T0, T0);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(move |_, set, _, _| {
            assert_eq!(set.valid, FATTR_ATIME | FATTR_MTIME | FATTR_CTIME);
            let mut r = attr;
            r.posix.atime_ns = T1;
            r.posix.mtime_ns = T1;
            r.posix.ctime_ns = T1;
            Ok(r)
        });
        let plan = KmodPosixVfs::new(e)
            .update_time(
                InodeId::new(50),
                Some(T1),
                S_ATIME | S_MTIME | S_CTIME,
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(plan.atime_ns, T1);
        assert_eq!(plan.mtime_ns, T1);
        assert_eq!(plan.ctime_ns, T1);
    }
}
