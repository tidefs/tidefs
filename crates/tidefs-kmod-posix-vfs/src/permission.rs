// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! inode_operations permission check for the kernel VFS adapter --
//! K7-17 access-control seam.
//!
//! This module provides the `inode_permission` dispatch that bridges
//! VFS access-control decisions through VfsEngine getattr, performing
//! UNIX-style permission evaluation. Without this handler, cached
//! dentries could bypass VfsEngine capability state, creating a
//! correctness divergence between userspace and kernel-mounted
//! operation.
//!
//! The handler accepts the kernel VFS permission mask (MAY_READ,
//! MAY_WRITE, MAY_EXEC, MAY_NOT_BLOCK) and evaluates the calling task's
//! uid/gid against the inode's owner/group/other mode bits.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId, RequestCtx, S_IFDIR, S_IFMT};

// -- Permission mask constants (Linux VFS may_access values) ---

/// Read access requested.
pub const MAY_READ: u32 = 0x04;
/// Write access requested.
pub const MAY_WRITE: u32 = 0x02;
/// Execute / search access requested.
pub const MAY_EXEC: u32 = 0x01;
/// Non-blocking hint -- the caller must not sleep.
pub const MAY_NOT_BLOCK: u32 = 0x80;

// -- POSIX permission bit helpers ---

/// Owner read.
const S_IRUSR: u32 = 0o0400;
/// Owner write.
const S_IWUSR: u32 = 0o0200;
/// Owner execute.
const S_IXUSR: u32 = 0o0100;
/// Group read.
const S_IRGRP: u32 = 0o0040;
/// Group write.
const S_IWGRP: u32 = 0o0020;
/// Group execute.
const S_IXGRP: u32 = 0o0010;
/// Other read.
const S_IROTH: u32 = 0o0004;
/// Other write.
const S_IWOTH: u32 = 0o0002;
/// Other execute.
const S_IXOTH: u32 = 0o0001;

// -- PermissionPlan ---

/// Result of a permission check: an allow/deny decision with the
/// inode, permission mask, and caller attributes that were
/// evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionPlan {
    /// Whether access is granted.
    pub allowed: bool,
    /// The inode that was checked.
    pub inode: InodeId,
    /// The permission mask that was evaluated.
    pub mask: u32,
    /// The caller's uid used for the check.
    pub caller_uid: u32,
    /// The caller's gid used for the check.
    pub caller_gid: u32,
    /// The inode's mode at check time.
    pub inode_mode: u32,
    /// The inode's uid at check time.
    pub inode_uid: u32,
    /// The inode's gid at check time.
    pub inode_gid: u32,
}

/// Input fields captured by a permission-plan decision.
pub struct PermissionPlanInput {
    pub allowed: bool,
    pub inode: InodeId,
    pub mask: u32,
    pub caller_uid: u32,
    pub caller_gid: u32,
    pub inode_mode: u32,
    pub inode_uid: u32,
    pub inode_gid: u32,
}

impl PermissionPlan {
    /// Create a PermissionPlan capturing the operation result fields.
    pub fn new(input: PermissionPlanInput) -> Self {
        Self {
            allowed: input.allowed,
            inode: input.inode,
            mask: input.mask,
            caller_uid: input.caller_uid,
            caller_gid: input.caller_gid,
            inode_mode: input.inode_mode,
            inode_uid: input.inode_uid,
            inode_gid: input.inode_gid,
        }
    }
}

// -- Permission evaluation ---

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Evaluate whether the caller (identified by `ctx`) may perform
    /// the access described by `mask` on `inode`.
    ///
    /// Implements standard UNIX discretionary access control:
    ///
    /// 1.  If the caller is root (uid 0) -- grant, except execute
    ///     requires at least one execute bit to be set.
    /// 2.  If the caller's uid matches the inode's uid -- owner bits.
    /// 3.  Else if the caller's gid matches the inode's gid or the
    ///     inode's gid is in the caller's supplemental groups -- group
    ///     bits.
    /// 4.  Else -- other bits.
    ///
    /// Returns `Ok(PermissionPlan)` with `allowed: true` when access is
    /// granted, or `Err(Errno::EACCES)` when access is denied.
    pub fn check_permission(
        &self,
        inode: InodeId,
        mask: u32,
        ctx: &RequestCtx,
    ) -> Result<PermissionPlan, Errno> {
        let attr = self.engine.getattr(inode, None, ctx)?;
        let mode = attr.posix.mode;
        let f_uid = attr.posix.uid;
        let f_gid = attr.posix.gid;

        let wanted = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
        if wanted == 0 {
            // No access bits requested -- trivially allowed.
            return Ok(PermissionPlan::new(PermissionPlanInput {
                allowed: true,
                inode,
                mask,
                caller_uid: ctx.uid,
                caller_gid: ctx.gid,
                inode_mode: mode,
                inode_uid: f_uid,
                inode_gid: f_gid,
            }));
        }

        let allowed = if ctx.uid == 0 {
            // Root: grant read/write, grant execute only if at least
            // one execute bit is set somewhere or target is a directory.
            let need_exec = (wanted & MAY_EXEC) != 0;
            if need_exec {
                let is_dir = (mode & S_IFMT) == S_IFDIR;
                if is_dir {
                    true
                } else {
                    (mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0
                }
            } else {
                true
            }
        } else if ctx.uid == f_uid {
            // Owner access.
            check_bits(wanted, mode, S_IRUSR, S_IWUSR, S_IXUSR)
        } else if is_in_group(ctx, f_gid) {
            // Group access.
            check_bits(wanted, mode, S_IRGRP, S_IWGRP, S_IXGRP)
        } else {
            // Other access.
            check_bits(wanted, mode, S_IROTH, S_IWOTH, S_IXOTH)
        };

        let plan = PermissionPlan::new(PermissionPlanInput {
            allowed,
            inode,
            mask,
            caller_uid: ctx.uid,
            caller_gid: ctx.gid,
            inode_mode: mode,
            inode_uid: f_uid,
            inode_gid: f_gid,
        });

        if allowed {
            Ok(plan)
        } else {
            Err(Errno::EACCES)
        }
    }
}

// -- Helpers ---

/// Map the MAY_* wanted bits onto the triad-specific permission bits.
fn check_bits(wanted: u32, mode: u32, r_bit: u32, w_bit: u32, x_bit: u32) -> bool {
    if (wanted & MAY_READ) != 0 && (mode & r_bit) == 0 {
        return false;
    }
    if (wanted & MAY_WRITE) != 0 && (mode & w_bit) == 0 {
        return false;
    }
    if (wanted & MAY_EXEC) != 0 && (mode & x_bit) == 0 {
        return false;
    }
    true
}

/// Returns true if the caller is considered to be in the file's group.
///
/// The caller is in the group if the caller's effective gid matches
/// the file's gid, or if the file's gid appears in the caller's
/// supplemental group list.
fn is_in_group(ctx: &RequestCtx, file_gid: u32) -> bool {
    if ctx.gid == file_gid {
        return true;
    }
    ctx.groups.contains(&file_gid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::{
        Generation, InodeAttr, InodeFlags, NodeKind, PosixAttrs, S_IFDIR, S_IFREG,
    };

    fn make_attr(ino: u64, mode: u32, uid: u32, gid: u32) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode,
                uid,
                gid,
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

    fn ctx(uid: u32, gid: u32) -> RequestCtx {
        RequestCtx::new(
            uid,
            gid,
            1000,
            0o022,
            crate::TideVec::from([gid].as_slice()),
        )
    }

    // -- Owner tests ---

    #[test]
    fn owner_read_granted() {
        let attr = make_attr(10, S_IFREG | 0o400, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_READ, &ctx(1000, 100))
            .unwrap();
        assert!(plan.allowed);
    }

    #[test]
    fn owner_read_denied() {
        let attr = make_attr(10, S_IFREG | 0o200, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let err = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_READ, &ctx(1000, 100))
            .unwrap_err();
        assert_eq!(err, Errno::EACCES);
    }

    #[test]
    fn owner_write_granted() {
        let attr = make_attr(10, S_IFREG | 0o600, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_WRITE, &ctx(1000, 100))
            .unwrap();
        assert!(plan.allowed);
    }

    #[test]
    fn owner_write_denied() {
        let attr = make_attr(10, S_IFREG | 0o400, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let err = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_WRITE, &ctx(1000, 100))
            .unwrap_err();
        assert_eq!(err, Errno::EACCES);
    }

    #[test]
    fn owner_exec_granted() {
        let attr = make_attr(10, S_IFREG | 0o700, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_EXEC, &ctx(1000, 100))
            .unwrap();
        assert!(plan.allowed);
    }

    // -- Group tests ---

    #[test]
    fn group_read_granted() {
        let attr = make_attr(10, S_IFREG | 0o040, 1000, 200);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_READ, &ctx(200, 200))
            .unwrap();
        assert!(plan.allowed);
    }

    #[test]
    fn group_read_denied() {
        let attr = make_attr(10, S_IFREG | 0o020, 1000, 200);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let err = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_READ, &ctx(300, 200))
            .unwrap_err();
        assert_eq!(err, Errno::EACCES);
    }

    // -- Other tests ---

    #[test]
    fn other_read_granted() {
        let attr = make_attr(10, S_IFREG | 0o004, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_READ, &ctx(999, 888))
            .unwrap();
        assert!(plan.allowed);
    }

    #[test]
    fn other_all_denied() {
        let attr = make_attr(10, S_IFREG | 0o700, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let err = KmodPosixVfs::new(e)
            .check_permission(
                InodeId::new(10),
                MAY_READ | MAY_WRITE | MAY_EXEC,
                &ctx(999, 888),
            )
            .unwrap_err();
        assert_eq!(err, Errno::EACCES);
    }

    // -- Root tests ---

    #[test]
    fn root_read_write_granted() {
        let attr = make_attr(10, S_IFREG, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_READ | MAY_WRITE, &ctx(0, 0))
            .unwrap();
        assert!(plan.allowed);
    }

    #[test]
    fn root_exec_denied_no_exec_bits() {
        let attr = make_attr(10, S_IFREG | 0o600, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let err = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_EXEC, &ctx(0, 0))
            .unwrap_err();
        assert_eq!(err, Errno::EACCES);
    }

    #[test]
    fn root_exec_granted_any_exec_bit() {
        let attr = make_attr(10, S_IFREG | 0o601, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_EXEC, &ctx(0, 0))
            .unwrap();
        assert!(plan.allowed);
    }

    #[test]
    fn root_search_dir_always_granted() {
        let attr = make_attr(10, S_IFDIR | 0o700, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_EXEC, &ctx(0, 0))
            .unwrap();
        assert!(plan.allowed);
    }

    // -- MAY_NOT_BLOCK propagation ---

    #[test]
    fn may_not_block_propagated() {
        let attr = make_attr(10, S_IFREG | 0o400, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_READ | MAY_NOT_BLOCK, &ctx(1000, 100))
            .unwrap();
        assert!(plan.allowed);
        assert_eq!(plan.mask & MAY_NOT_BLOCK, MAY_NOT_BLOCK);
    }

    // -- No mask bits ---

    #[test]
    fn zero_mask_trivially_allowed() {
        let attr = make_attr(10, S_IFREG, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let plan = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), 0, &ctx(999, 888))
            .unwrap();
        assert!(plan.allowed);
    }

    // -- Supplemental group check ---

    #[test]
    fn supplemental_group_granted() {
        let attr = make_attr(10, S_IFREG | 0o040, 1000, 200);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let ctx_with_groups = RequestCtx::new(
            999,
            999,
            1000,
            0o022,
            crate::TideVec::from([999, 200, 300].as_slice()),
        );
        let plan = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_READ, &ctx_with_groups)
            .unwrap();
        assert!(plan.allowed);
    }

    // -- Writer cross-check: denied other blocks access ---

    #[test]
    fn denied_permission_prevents_access() {
        let attr = make_attr(10, S_IFREG | 0o600, 1000, 100);
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let err = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_READ | MAY_WRITE, &ctx(999, 888))
            .unwrap_err();
        assert_eq!(err, Errno::EACCES);
    }

    // -- Error propagation from getattr ---

    #[test]
    fn getattr_failure_propagates() {
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(|_, _, _| Err(Errno::ESTALE));
        let err = KmodPosixVfs::new(e)
            .check_permission(InodeId::new(10), MAY_READ, &ctx(1000, 100))
            .unwrap_err();
        assert_eq!(err, Errno::ESTALE);
    }
}
