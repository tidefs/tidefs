//! Statx rendering for the kernel VFS adapter.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use tidefs_kmod_bridge::kernel_types::{split_posix_time_ns, InodeAttr};

/// statx mask bits matching Linux `STATX_*` from uapi/linux/stat.h.
pub mod mask {
    pub const STATX_TYPE: u64 = 0x0001;
    pub const STATX_MODE: u64 = 0x0002;
    pub const STATX_NLINK: u64 = 0x0004;
    pub const STATX_UID: u64 = 0x0008;
    pub const STATX_GID: u64 = 0x0010;
    pub const STATX_ATIME: u64 = 0x0020;
    pub const STATX_MTIME: u64 = 0x0040;
    pub const STATX_CTIME: u64 = 0x0080;
    pub const STATX_INO: u64 = 0x0100;
    pub const STATX_SIZE: u64 = 0x0200;
    pub const STATX_BLOCKS: u64 = 0x0400;
    pub const STATX_BASIC_STATS: u64 = 0x07ff;
    pub const STATX_BTIME: u64 = 0x0800;
    pub const STATX_MNT_ID: u64 = 0x1000;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
}

#[derive(Clone, Debug, Default)]
pub struct KmodStatx {
    pub stx_mask: u64,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
}

impl KmodStatx {
    /// All statx fields this implementation populates from `InodeAttr`.
    ///
    /// Covers basic POSIX stats plus birthtime.  Does not include `MNT_ID`
    /// or `DIOALIGN` (those require superblock context that the caller must
    /// fill after construction).
    pub const SUPPORTED_MASK: u64 = mask::STATX_BASIC_STATS | mask::STATX_BTIME;

    /// STATX_ATTR_* file-attribute values from Linux uapi/linux/stat.h.
    const STATX_ATTR_IMMUTABLE: u64 = 0x0000_0010;
    const STATX_ATTR_APPEND: u64 = 0x0000_0020;
    const STATX_ATTR_NODUMP: u64 = 0x0000_0040;

    fn split_ns(ns: i64) -> StatxTimestamp {
        let (tv_sec, tv_nsec) = split_posix_time_ns(ns);
        StatxTimestamp { tv_sec, tv_nsec }
    }

    /// Build a statx result from committed inode attributes.
    ///
    /// `stx_mask` reports exactly the fields this implementation populated
    /// (`SUPPORTED_MASK`), matching the Linux kernel convention where
    /// `stx_mask` describes what was provided rather than what was requested.
    ///
    /// `stx_attributes` is derived from `InodeFlags`, mapping
    /// immutable/append-only/nodump to the corresponding `STATX_ATTR_*` bits.
    ///
    /// The caller is responsible for filling `stx_dev_major`, `stx_dev_minor`,
    /// and `stx_mnt_id` from superblock context after construction.
    pub fn from_inode_attr(attr: &InodeAttr) -> Self {
        let p = &attr.posix;
        KmodStatx {
            stx_mask: Self::SUPPORTED_MASK,
            stx_blksize: p.blksize,
            stx_nlink: p.nlink,
            stx_uid: p.uid,
            stx_gid: p.gid,
            stx_mode: (p.mode & 0o177777) as u16,
            stx_ino: attr.inode_id.get(),
            stx_size: p.size,
            stx_blocks: p.blocks_512,
            stx_rdev_major: (p.rdev >> 8) & 0xFFF,
            stx_rdev_minor: (p.rdev & 0xFF) | ((p.rdev >> 12) & 0xFFF00),
            stx_atime: Self::split_ns(p.atime_ns),
            stx_mtime: Self::split_ns(p.mtime_ns),
            stx_ctime: Self::split_ns(p.ctime_ns),
            stx_btime: Self::split_ns(p.btime_ns),
            stx_attributes: statx_attrs_from_flags(&attr.flags),
            ..Default::default()
        }
    }
}

// ── InodeFlags → stx_attributes bridge ───────────────────────────────
//
// Under cargo (non-Kbuild), tidefs-kmod-bridge re-exports the userspace
// `InodeFlags` struct with named bool fields.  Under Kbuild, the bridge
// uses a raw `InodeFlags(pub u32)` wrapper.  Both paths are handled here
// so the kernel module compiles in either environment without divergence.

#[cfg(CONFIG_RUST)]
fn statx_attrs_from_flags(flags: &tidefs_kmod_bridge::kernel_types::InodeFlags) -> u64 {
    let raw = flags.0;
    let mut attrs: u64 = 0;
    // Flag bit constants matching tidefs-types-vfs-core InodeFlags.
    const FLAG_IMMUTABLE: u32 = 0x0000_0010;
    const FLAG_APPEND_ONLY: u32 = 0x0000_0020;
    const FLAG_NODUMP: u32 = 0x0000_0040;
    if raw & FLAG_IMMUTABLE != 0 {
        attrs |= KmodStatx::STATX_ATTR_IMMUTABLE;
    }
    if raw & FLAG_APPEND_ONLY != 0 {
        attrs |= KmodStatx::STATX_ATTR_APPEND;
    }
    if raw & FLAG_NODUMP != 0 {
        attrs |= KmodStatx::STATX_ATTR_NODUMP;
    }
    attrs
}

#[cfg(not(CONFIG_RUST))]
fn statx_attrs_from_flags(flags: &tidefs_kmod_bridge::kernel_types::InodeFlags) -> u64 {
    let mut attrs: u64 = 0;
    if flags.immutable {
        attrs |= KmodStatx::STATX_ATTR_IMMUTABLE;
    }
    if flags.append_only {
        attrs |= KmodStatx::STATX_ATTR_APPEND;
    }
    if flags.nodump {
        attrs |= KmodStatx::STATX_ATTR_NODUMP;
    }
    attrs
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_kmod_bridge::kernel_types::{Generation, InodeFlags, InodeId, NodeKind, PosixAttrs};

    fn ma(ino: u64, posix: PosixAttrs, kind: NodeKind) -> InodeAttr {
        InodeAttr {
            inode_id: InodeId::new(ino),
            generation: Generation::new(1),
            kind,
            posix,
            flags: InodeFlags::default(),
            subtree_rev: 0,
            dir_rev: 0,
        }
    }

    #[test]
    fn statx_from_file() {
        let a = ma(
            42,
            PosixAttrs {
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                nlink: 1,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 8192,
                blocks_512: 16,
                blksize: 4096,
            },
            NodeKind::File,
        );
        let s = KmodStatx::from_inode_attr(&a);
        assert_eq!(s.stx_ino, 42);
        assert_eq!(s.stx_size, 8192);
        assert_eq!(s.stx_blocks, 16);
        assert_eq!(s.stx_mode & 0o170000, 0o100000);
        assert_eq!(s.stx_mask, KmodStatx::SUPPORTED_MASK);
    }

    #[test]
    fn statx_from_dir() {
        let a = ma(
            1,
            PosixAttrs {
                mode: 0o40755,
                uid: 0,
                gid: 0,
                nlink: 2,
                rdev: 0,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            NodeKind::Dir,
        );
        let s = KmodStatx::from_inode_attr(&a);
        assert_eq!(s.stx_mode & 0o170000, 0o040000);
        assert_eq!(s.stx_nlink, 2);
    }

    #[test]
    fn statx_timestamps() {
        let a = ma(
            1,
            PosixAttrs {
                mode: 0o100644,
                uid: 0,
                gid: 0,
                nlink: 1,
                rdev: 0,
                atime_ns: 1_699_999_999_123_456_789,
                mtime_ns: 1_700_000_000_987_654_321,
                ctime_ns: 1_700_000_001_111_111_111,
                btime_ns: 1_699_000_000_000_000_000,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            NodeKind::File,
        );
        let s = KmodStatx::from_inode_attr(&a);
        assert_eq!(s.stx_atime.tv_sec, 1699999999);
        assert_eq!(s.stx_atime.tv_nsec, 123456789);
        assert_eq!(s.stx_mtime.tv_sec, 1700000000);
        assert_eq!(s.stx_mtime.tv_nsec, 987654321);
        assert_eq!(s.stx_btime.tv_sec, 1699000000);
        assert_eq!(s.stx_btime.tv_nsec, 0);
    }

    #[test]
    fn statx_pre_epoch_timestamps() {
        let a = ma(
            2,
            PosixAttrs {
                mode: 0o100644,
                uid: 0,
                gid: 0,
                nlink: 1,
                rdev: 0,
                atime_ns: -1,
                mtime_ns: -315_619_198_876_543_211,
                ctime_ns: -315_619_200_000_000_000,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            NodeKind::File,
        );
        let s = KmodStatx::from_inode_attr(&a);
        assert_eq!(s.stx_atime.tv_sec, -1);
        assert_eq!(s.stx_atime.tv_nsec, 999_999_999);
        assert_eq!(s.stx_mtime.tv_sec, -315_619_199);
        assert_eq!(s.stx_mtime.tv_nsec, 123_456_789);
        assert_eq!(s.stx_ctime.tv_sec, -315_619_200);
        assert_eq!(s.stx_ctime.tv_nsec, 0);
    }

    #[test]
    fn statx_device_numbers() {
        let a = ma(
            10,
            PosixAttrs {
                mode: 0o020666,
                uid: 0,
                gid: 0,
                nlink: 1,
                rdev: 0x103,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                btime_ns: 0,
                size: 0,
                blocks_512: 0,
                blksize: 4096,
            },
            NodeKind::CharDev,
        );
        let s = KmodStatx::from_inode_attr(&a);
        assert_eq!(s.stx_rdev_major, 1);
        assert_eq!(s.stx_rdev_minor, 3);
    }

    #[test]
    fn statx_mask_reports_supported_mask() {
        let a = ma(
            1,
            PosixAttrs {
                mode: 0o100644,
                uid: 0,
                gid: 0,
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
            NodeKind::File,
        );
        let s = KmodStatx::from_inode_attr(&a);
        assert_eq!(
            s.stx_mask,
            KmodStatx::SUPPORTED_MASK,
            "stx_mask must report what was actually filled, not the request_mask"
        );
    }

    #[test]
    fn statx_attributes_from_flags() {
        let mut a = ma(
            1,
            PosixAttrs {
                mode: 0o100644,
                uid: 0,
                gid: 0,
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
            NodeKind::File,
        );
        a.flags = InodeFlags {
            immutable: true,
            append_only: true,
            noatime: false,
            nodump: false,
        };
        let s = KmodStatx::from_inode_attr(&a);
        assert_eq!(
            s.stx_attributes,
            KmodStatx::STATX_ATTR_IMMUTABLE | KmodStatx::STATX_ATTR_APPEND,
            "IMMUTABLE + APPEND_ONLY flags must map to STATX_ATTR bits"
        );
    }

    #[test]
    fn statx_attributes_nodump() {
        let mut a = ma(
            1,
            PosixAttrs {
                mode: 0o100644,
                uid: 0,
                gid: 0,
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
            NodeKind::File,
        );
        a.flags = InodeFlags {
            immutable: false,
            append_only: false,
            noatime: false,
            nodump: true,
        };
        let s = KmodStatx::from_inode_attr(&a);
        assert_eq!(s.stx_attributes, KmodStatx::STATX_ATTR_NODUMP);
    }

    #[test]
    fn statx_attributes_no_flags_is_zero() {
        let mut a = ma(
            1,
            PosixAttrs {
                mode: 0o100644,
                uid: 0,
                gid: 0,
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
            NodeKind::File,
        );
        a.flags = InodeFlags {
            immutable: false,
            append_only: false,
            noatime: false,
            nodump: false,
        };
        let s = KmodStatx::from_inode_attr(&a);
        assert_eq!(s.stx_attributes, 0);
    }

    #[test]
    fn statx_basic_stats_in_supported_mask() {
        assert_eq!(
            KmodStatx::SUPPORTED_MASK & mask::STATX_BASIC_STATS,
            mask::STATX_BASIC_STATS,
            "SUPPORTED_MASK must include all STATX_BASIC_STATS bits"
        );
    }
}
