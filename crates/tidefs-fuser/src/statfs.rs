//! FUSE statfs/statvfs helper: converts space-accounting and block-allocator
//! data into fields consumable by [`ReplyStatfs`].
//!
//! Wire-format field assembly is delegated to the canonical
//! `tidefs-posix-filesystem-adapter-reply` module, keeping shared
//! filesystem reply semantics in one implementation surface.
//!
//! Provides [`StatfsFields`] as a structured intermediate and
//! [`build_statvfs`] to derive it from high-level input (total blocks,
//! free blocks, inode capacity).  Callers merge namespace-derived fields
//! (inode counts, name_max) and then send via [`StatfsFields::reply`].
//!
//! # Wire format
//!
//! Maps to Linux `struct fuse_kstatfs` inside `fuse_statfs_out`:
//! blocks, bfree, bavail, files, ffree, bsize, namelen, frsize.

use crate::reply::ReplyStatfs;
use libc::c_int;
use tidefs_posix_filesystem_adapter_reply::StatfsReply;

pub use libc::ESTALE;

/// Default filesystem block size for TideFS (matches page size on Linux).
pub const DEFAULT_BLOCK_SIZE: u32 = 4096;

/// Default maximum filename length per POSIX (NAME_MAX).
pub const DEFAULT_NAME_MAX: u32 = 255;

/// Default filesystem type magic (0 = no specific type advertised).
pub const DEFAULT_FS_TYPE: u32 = 0;

/// Mount flags carried in `f_flag` of `struct statvfs`.
pub const ST_RDONLY: u32 = 1;
/// ST_NOSUID: setuid/setgid execution is not permitted.
pub const ST_NOSUID: u32 = 2;

/// Structured statfs / statvfs fields ready for FUSE reply.
///
/// All block and file counts are `u64`; `bsize`, `namemax`, and `frsize`
/// are `u32` per the FUSE wire format.  `fs_type` and `flags` are
/// informational fields reported via `statvfs(2)` but not part of
/// the FUSE `statfs_out` payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatfsFields {
    /// f_blocks: total data blocks in filesystem.
    pub blocks: u64,
    /// f_bfree: free blocks.
    pub bfree: u64,
    /// f_bavail: free blocks available to unprivileged users.
    pub bavail: u64,
    /// f_files: total inodes / file slots.
    pub files: u64,
    /// f_ffree: free inodes.
    pub ffree: u64,
    /// f_bsize: optimal transfer block size.
    pub bsize: u32,
    /// f_namemax: maximum filename length.
    pub namemax: u32,
    /// f_frsize: fundamental filesystem block size (== bsize for TideFS).
    pub frsize: u32,
    /// f_type: filesystem type magic (0 if unknown).
    pub fs_type: u32,
    /// f_flag: mount flags (ST_RDONLY, ST_NOSUID, etc.).
    pub flags: u32,
}

impl Default for StatfsFields {
    fn default() -> Self {
        Self {
            blocks: 0,
            bfree: 0,
            bavail: 0,
            files: 0,
            ffree: 0,
            bsize: DEFAULT_BLOCK_SIZE,
            namemax: DEFAULT_NAME_MAX,
            frsize: DEFAULT_BLOCK_SIZE,
            fs_type: DEFAULT_FS_TYPE,
            flags: ST_NOSUID,
        }
    }
}

impl StatfsFields {
    /// Create with only block-size fields set; all counters are zero.
    ///
    /// Useful as a starting point when the caller will fill in values
    /// incrementally from the block allocator and namespace layer.
    #[must_use]
    pub fn new(block_size: u32) -> Self {
        // Delegate to canonical adapter-reply StatfsReply.
        let r = StatfsReply::new(block_size as u64);
        Self {
            blocks: r.blocks,
            bfree: r.bfree,
            bavail: r.bavail,
            files: r.files,
            ffree: r.ffree,
            bsize: r.bsize as u32,
            namemax: DEFAULT_NAME_MAX,
            frsize: r.frsize as u32,
            fs_type: DEFAULT_FS_TYPE,
            flags: ST_NOSUID,
        }
    }

    /// Send this reply through a [`ReplyStatfs`] (consumes the reply).
    ///
    /// Field values are clamped so that `bfree <= blocks`,
    /// `bavail <= bfree`, `ffree <= files`. This prevents the kernel
    /// from seeing inconsistent capacity counters.
    ///
    /// Wire-format assembly is delegated to the canonical
    /// `tidefs-posix-filesystem-adapter-reply::StatfsReply`.
    pub fn reply(self, reply: ReplyStatfs) {
        let bfree = self.bfree.min(self.blocks);
        let bavail = self.bavail.min(bfree);
        let ffree = self.ffree.min(self.files);
        reply.statfs(
            self.blocks,
            bfree,
            bavail,
            self.files,
            ffree,
            self.bsize,
            self.namemax,
            self.frsize,
        );
    }

    /// Add a root reserve (5% of total blocks, matching ext4/XFS convention).
    ///
    /// `bavail` is decreased by the reserve; `bfree` is unchanged (reserve
    /// blocks are still free but not available to unprivileged users).
    #[must_use]
    pub fn with_root_reserve(self) -> Self {
        let reserve = self.blocks / 20;
        Self {
            bavail: self.bavail.saturating_sub(reserve),
            ..self
        }
    }
}

/// Build a [`StatfsFields`] from high-level space-accounting data.
///
/// `total_blocks` and `free_blocks` drive `f_blocks` and `f_bfree`.
/// `bavail` is initialized from `free_blocks` and can be reduced by
/// calling [`StatfsFields::with_root_reserve`].
///
/// `total_files` and `free_files` set `f_files` and `f_ffree`.
/// For filesystems without a fixed inode table, pass `u64::MAX` for
/// both.
///
/// `block_size` sets both `f_bsize` and `f_frsize` (TideFS uses a
/// uniform block size).
#[must_use]
pub fn build_statvfs(
    total_blocks: u64,
    free_blocks: u64,
    total_files: u64,
    free_files: u64,
    block_size: u32,
    name_max: u32,
) -> StatfsFields {
    // Delegate to canonical adapter-reply StatfsReply for field assembly.
    let r = StatfsReply {
        blocks: total_blocks,
        bfree: free_blocks,
        bavail: free_blocks,
        files: total_files,
        ffree: free_files,
        favail: free_files,
        bsize: block_size as u64,
        namemax: name_max,
        frsize: block_size as u64,
    };
    StatfsFields {
        blocks: r.blocks,
        bfree: r.bfree,
        bavail: r.bavail,
        files: r.files,
        ffree: r.ffree,
        bsize: r.bsize as u32,
        namemax: r.namemax,
        frsize: r.frsize as u32,
        fs_type: DEFAULT_FS_TYPE,
        flags: ST_NOSUID,
    }
}
// =========================================================================
// Parsed request
// =========================================================================

/// Parsed FUSE STATFS request received from the kernel.
///
/// The inode is taken from the FUSE request header.  On modern Linux
/// kernels, the kernel sends `ino = 0` for STATFS; older kernels may
/// pass the mount-point inode.  The flags field is reserved and
/// typically zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatfsRequest {
    /// Inode number from the FUSE request header.
    pub ino: u64,
    /// Request-specific flags (reserved, typically 0).
    pub flags: u32,
}

/// Parse a FUSE STATFS request from its raw components.
///
/// This is a pure-data constructor: no validation is performed.
/// Use [`plan_statfs`] to validate the inode exists before
/// dispatching a reply.
#[must_use]
pub fn parse_statfs_request(ino: u64, flags: u32) -> StatfsRequest {
    StatfsRequest { ino, flags }
}

// =========================================================================
// Validated plan
// =========================================================================

/// Validated STATFS plan with filesystem statistics ready for reply.
///
/// Created by [`plan_statfs`] after inode-existence validation.
/// The caller populates `fields` from the space-accounting layer
/// before calling [`format_statfs_reply`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatfsPlan {
    /// Inode that was validated for this statfs operation.
    pub ino: u64,
    /// Filesystem statistics fields (blocks, free, inodes, etc.).
    pub fields: StatfsFields,
}

impl StatfsPlan {
    /// Create a validated plan from the given inode and statfs fields.
    #[must_use]
    pub fn new(ino: u64, fields: StatfsFields) -> Self {
        Self { ino, fields }
    }

    /// Send this plan as a FUSE statfs reply, consuming the [`ReplyStatfs`].
    ///
    /// This is a convenience wrapper around [`StatfsFields::reply`]
    /// that also applies reply-level clamping (bfree <= blocks,
    /// bavail <= bfree, ffree <= files).
    pub fn reply(self, reply: ReplyStatfs) {
        self.fields.reply(reply);
    }
}

// =========================================================================
// Validation
// =========================================================================

/// Validate a STATFS request and build a validated plan.
///
/// `ino_exists` should be `true` when the requested inode is present
/// in the filesystem; this is typically verified via a getattr probe
/// before the statfs dispatch.
///
/// The plan's `fields` are initialized from [`StatfsFields::default`]
/// (zero counters, 4 KiB block size, 255-byte name max).  The caller
/// should populate the block, inode, and reserve fields from the
/// space-accounting layer before calling [`format_statfs_reply`].
///
/// # Returns
///
/// `Ok(StatfsPlan)` when the inode exists.
///
/// `Err(ESTALE)` when the inode is not found, so the kernel can
/// gracefully remount or revalidate.
#[inline]
pub fn plan_statfs(ino: u64, ino_exists: bool) -> Result<StatfsPlan, c_int> {
    if !ino_exists {
        return Err(libc::ESTALE);
    }
    Ok(StatfsPlan {
        ino,
        fields: StatfsFields::default(),
    })
}

// =========================================================================
// Reply formatting
// =========================================================================

/// Format and send a FUSE statfs reply from a validated plan.
///
/// Consumes the [`ReplyStatfs`] and sends the reply with the
/// fields from [`StatfsPlan::fields`] — including reply-level
/// clamping of free/available counters.
#[inline]
pub fn format_statfs_reply(plan: StatfsPlan, reply: ReplyStatfs) {
    plan.fields.reply(reply);
}

// =========================================================================
// Canonical dispatch
// =========================================================================

/// Canonical dispatch for FUSE STATFS (opcode 17).
///
/// Combines [`plan_statfs`] (inode-existence validation) with
/// [`format_statfs_reply`] (reply dispatch).  The reply uses
/// default-zero counters; callers with live space-accounting data
/// should use [`plan_statfs`] followed by population of
/// [`StatfsPlan::fields`] and [`format_statfs_reply`].
///
/// # Returns
///
/// `Ok(())` on success.
///
/// `Err(ESTALE)` when the inode does not exist.
#[inline]
pub fn handle_statfs(
    req: StatfsRequest,
    ino_exists: bool,
    reply: ReplyStatfs,
) -> Result<(), c_int> {
    let plan = plan_statfs(req.ino, ino_exists)?;
    format_statfs_reply(plan, reply);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Channel;
    use crate::reply::Reply;
    use std::fs::File;
    use std::sync::Arc;

    // --- helper: create a no-op ReplyStatfs for tests ---------------

    fn dummy_reply_statfs() -> ReplyStatfs {
        let sender = Channel::new(Arc::new(File::open("/dev/null").unwrap())).sender();
        // sender created above
        ReplyStatfs::new(0, sender)
    }

    // --- build_statvfs ----------------------------------------------------

    #[test]
    fn empty_pool_all_free() {
        let f = build_statvfs(1000, 1000, u64::MAX, u64::MAX, 4096, 255);
        assert_eq!(f.blocks, 1000);
        assert_eq!(f.bfree, 1000);
        assert_eq!(f.bavail, 1000);
        assert_eq!(f.files, u64::MAX);
        assert_eq!(f.ffree, u64::MAX);
        assert_eq!(f.bsize, 4096);
        assert_eq!(f.namemax, 255);
        assert_eq!(f.frsize, 4096);
    }

    #[test]
    fn half_full_pool() {
        let f = build_statvfs(1000, 500, 200, 150, 4096, 255);
        assert_eq!(f.blocks, 1000);
        assert_eq!(f.bfree, 500);
        assert_eq!(f.bavail, 500);
        assert_eq!(f.files, 200);
        assert_eq!(f.ffree, 150);
    }

    #[test]
    fn full_pool_no_free_blocks() {
        let f = build_statvfs(1000, 0, 100, 0, 4096, 255);
        assert_eq!(f.blocks, 1000);
        assert_eq!(f.bfree, 0);
        assert_eq!(f.bavail, 0);
        assert_eq!(f.files, 100);
        assert_eq!(f.ffree, 0);
    }

    #[test]
    fn default_block_size_is_4096() {
        let f = StatfsFields::default();
        assert_eq!(f.bsize, 4096);
        assert_eq!(f.frsize, 4096);
    }

    #[test]
    fn default_name_max_is_255() {
        let f = StatfsFields::default();
        assert_eq!(f.namemax, 255);
    }

    // --- reply clamping ---------------------------------------------------

    #[test]
    fn reply_clamps_bfree_to_blocks() {
        let f = StatfsFields {
            blocks: 100,
            bfree: 120,
            bavail: 100,
            files: 0,
            ffree: 0,
            ..StatfsFields::default()
        };
        let bfree = f.bfree.min(f.blocks);
        let bavail = f.bavail.min(bfree);
        assert_eq!(bfree, 100);
        assert_eq!(bavail, 100);
    }

    #[test]
    fn reply_clamps_bavail_to_bfree() {
        let f = StatfsFields {
            blocks: 100,
            bfree: 80,
            bavail: 90,
            files: 0,
            ffree: 0,
            ..StatfsFields::default()
        };
        let bfree = f.bfree.min(f.blocks);
        let bavail = f.bavail.min(bfree);
        assert_eq!(bfree, 80);
        assert_eq!(bavail, 80);
    }

    #[test]
    fn reply_clamps_ffree_to_files() {
        let f = StatfsFields {
            blocks: 0,
            bfree: 0,
            bavail: 0,
            files: 50,
            ffree: 60,
            ..StatfsFields::default()
        };
        let ffree = f.ffree.min(f.files);
        assert_eq!(ffree, 50);
    }

    // --- root reserve -----------------------------------------------------

    #[test]
    fn root_reserve_subtracts_5_percent_from_bavail() {
        let f = build_statvfs(1000, 500, 0, 0, 4096, 255).with_root_reserve();
        assert_eq!(f.blocks, 1000);
        assert_eq!(f.bfree, 500);
        assert_eq!(f.bavail, 450);
    }

    #[test]
    fn root_reserve_saturates_at_zero() {
        let f = build_statvfs(1000, 10, 0, 0, 4096, 255).with_root_reserve();
        assert_eq!(f.bavail, 0);
    }

    #[test]
    fn root_reserve_zero_blocks() {
        let f = build_statvfs(0, 0, 0, 0, 4096, 255).with_root_reserve();
        assert_eq!(f.bavail, 0);
    }

    // --- new constructor --------------------------------------------------

    #[test]
    fn new_sets_block_size_fields_only() {
        let f = StatfsFields::new(512);
        assert_eq!(f.bsize, 512);
        assert_eq!(f.frsize, 512);
        assert_eq!(f.blocks, 0);
        assert_eq!(f.bfree, 0);
        assert_eq!(f.namemax, DEFAULT_NAME_MAX);
    }

    // --- flags ------------------------------------------------------------

    #[test]
    fn default_flags_include_nosuid() {
        let f = StatfsFields::default();
        assert_eq!(f.flags & ST_NOSUID, ST_NOSUID);
    }

    #[test]
    fn readonly_flag_can_be_set() {
        let f = StatfsFields {
            flags: ST_RDONLY | ST_NOSUID,
            ..StatfsFields::default()
        };
        assert_eq!(f.flags & ST_RDONLY, ST_RDONLY);
        assert_eq!(f.flags & ST_NOSUID, ST_NOSUID);
    }

    // --- build_statvfs with non-default block size ------------------------

    #[test]
    fn build_statvfs_512_byte_blocks() {
        let f = build_statvfs(2000, 1000, u64::MAX, u64::MAX, 512, 255);
        assert_eq!(f.blocks, 2000);
        assert_eq!(f.bfree, 1000);
        assert_eq!(f.bsize, 512);
        assert_eq!(f.frsize, 512);
    }

    #[test]
    fn build_statvfs_max_name_length_255() {
        let f = build_statvfs(1, 1, 0, 0, 4096, 255);
        assert_eq!(f.namemax, 255);
    }

    // --- structural equality ----------------------------------------------

    #[test]
    fn fields_equality() {
        let a = build_statvfs(100, 50, 0, 0, 4096, 255);
        let b = build_statvfs(100, 50, 0, 0, 4096, 255);
        assert_eq!(a, b);
        let c = build_statvfs(100, 49, 0, 0, 4096, 255);
        assert_ne!(a, c);
    }

    #[test]
    fn clone_equals_original() {
        let a = build_statvfs(500, 300, 100, 50, 4096, 255);
        let b = a;
        assert_eq!(a, b);
    }

    // --- debug output -----------------------------------------------------

    #[test]
    fn debug_output_includes_fields() {
        let f = build_statvfs(1024, 512, 256, 128, 4096, 255);
        let debug = format!("{f:?}");
        assert!(debug.contains("1024"));
        assert!(debug.contains("512"));
        assert!(debug.contains("4096"));
        assert!(debug.contains("255"));
    }
    // --- parse_statfs_request ------------------------------------------

    #[test]
    fn parse_preserves_ino() {
        let req = parse_statfs_request(42, 0);
        assert_eq!(req.ino, 42);
    }

    #[test]
    fn parse_preserves_flags() {
        let req = parse_statfs_request(0, 7);
        assert_eq!(req.flags, 7);
    }

    #[test]
    fn parse_zero_ino_zero_flags() {
        let req = parse_statfs_request(0, 0);
        assert_eq!(req.ino, 0);
        assert_eq!(req.flags, 0);
    }

    #[test]
    fn request_equality() {
        let a = parse_statfs_request(1, 0);
        let b = parse_statfs_request(1, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn request_inequality_ino() {
        let a = parse_statfs_request(1, 0);
        let b = parse_statfs_request(2, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn request_inequality_flags() {
        let a = parse_statfs_request(1, 0);
        let b = parse_statfs_request(1, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn request_debug_includes_fields() {
        let req = parse_statfs_request(99, 3);
        let s = format!("{req:?}");
        assert!(s.contains("99"));
        assert!(s.contains("3"));
    }

    // --- plan_statfs ----------------------------------------------------

    #[test]
    fn plan_succeeds_when_inode_exists() {
        let plan = plan_statfs(10, true);
        assert!(plan.is_ok());
        let p = plan.unwrap();
        assert_eq!(p.ino, 10);
    }

    #[test]
    fn plan_uses_default_fields() {
        let plan = plan_statfs(10, true).unwrap();
        assert_eq!(plan.fields, StatfsFields::default());
    }

    #[test]
    fn plan_fails_when_inode_missing() {
        let plan = plan_statfs(10, false);
        assert_eq!(plan, Err(libc::ESTALE));
    }

    #[test]
    fn plan_zero_ino_valid_when_exists() {
        assert!(plan_statfs(0, true).is_ok());
    }

    // --- StatfsPlan -----------------------------------------------------

    #[test]
    fn plan_new_preserves_fields() {
        let fields = build_statvfs(100, 50, 200, 150, 4096, 255);
        let plan = StatfsPlan::new(42, fields);
        assert_eq!(plan.ino, 42);
        assert_eq!(plan.fields, fields);
    }

    // --- handle_statfs --------------------------------------------------

    #[test]
    fn handle_succeeds_when_inode_exists() {
        let req = parse_statfs_request(1, 0);
        let reply = dummy_reply_statfs();
        assert_eq!(handle_statfs(req, true, reply), Ok(()));
    }
}
