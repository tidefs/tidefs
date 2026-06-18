// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Portable `alloc`-backed VFS owned mirrors.
//!
//! This crate intentionally owns the variable-sized values that are not legal in
//! the `core`-only VFS crate, keeping the `environment_boundary` split explicit.

extern crate alloc;

use alloc::vec::Vec;
use tidefs_types_vfs_core::{Generation, InodeId, NodeKind};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RequestCtx {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub umask: u32,
    pub groups: Vec<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub inode_id: InodeId,
    pub kind: NodeKind,
    pub generation: Generation,
    pub cookie: u64,
}

impl DirEntry {
    #[must_use]
    pub const fn new(
        name: Vec<u8>,
        inode_id: InodeId,
        kind: NodeKind,
        generation: Generation,
        cookie: u64,
    ) -> Self {
        Self {
            name,
            inode_id,
            kind,
            generation,
            cookie,
        }
    }
}

// TURN3_HUMAN_VFS_OWNED_ALIASES
/// Human-named module for alloc-backed VFS owned values.
pub mod vfs_owned {
    pub const FAMILY_NAME: &str = "VFS Owned Values";
    pub const ROLE: &str = "alloc-backed names, contexts, and directory entries for VFS operations";

    pub use crate::{DirEntry, RequestCtx};
}

/// Human alias namespace. Prefer `human::vfs_owned::*` in new examples.
pub mod human {
    pub mod vfs_owned {
        pub use crate::vfs_owned::*;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};

    #[test]
    fn request_ctx_keeps_all_groups() {
        let ctx = RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: vec![10, 20, 30],
        };
        assert_eq!(ctx.groups, vec![10, 20, 30]);
    }

    #[test]
    fn dir_entry_preserves_raw_name_bytes() {
        let entry = DirEntry::new(
            vec![0xff, b'a'],
            InodeId::new(3),
            NodeKind::File,
            Generation::new(7),
            9,
        );
        assert_eq!(entry.name, vec![0xff, b'a']);
    }
    #[test]
    fn request_ctx_default_has_empty_groups_and_zero_ids() {
        let ctx = RequestCtx::default();
        assert_eq!(ctx.uid, 0);
        assert_eq!(ctx.gid, 0);
        assert_eq!(ctx.pid, 0);
        assert_eq!(ctx.umask, 0);
        assert!(ctx.groups.is_empty());
    }

    #[test]
    fn dir_entry_default_has_zero_fields() {
        let entry = DirEntry::default();
        assert_eq!(entry.inode_id, InodeId::new(0));
        assert_eq!(entry.kind, NodeKind::File);
        assert_eq!(entry.generation, Generation::new(0));
        assert_eq!(entry.cookie, 0);
        assert!(entry.name.is_empty());
    }

    #[test]
    fn request_ctx_with_many_groups_preserves_all() {
        let groups: Vec<u32> = (0..50).collect();
        let ctx = RequestCtx {
            uid: 1,
            gid: 2,
            pid: 3,
            umask: 0,
            groups: groups.clone(),
        };
        assert_eq!(ctx.groups, groups);
        assert_eq!(ctx.uid, 1);
        assert_eq!(ctx.gid, 2);
    }

    #[test]
    fn dir_entry_with_every_node_kind_matches_kind() {
        let kinds = [
            NodeKind::Dir,
            NodeKind::File,
            NodeKind::Symlink,
            NodeKind::CharDev,
            NodeKind::BlockDev,
            NodeKind::Fifo,
            NodeKind::Socket,
            NodeKind::Whiteout,
        ];
        for &k in &kinds {
            let entry = DirEntry {
                name: vec![],
                inode_id: InodeId::new(1),
                kind: k,
                generation: Generation::new(0),
                cookie: 0,
            };
            assert_eq!(entry.kind, k);
        }
    }

    #[test]
    fn dir_entry_cookie_values_preserved() {
        let entry = DirEntry::new(
            vec![b't', b'e', b's', b't'],
            InodeId::new(5),
            NodeKind::Dir,
            Generation::new(3),
            0xDEAD_BEEF_CAFE_BABE,
        );
        assert_eq!(entry.cookie, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(entry.name, b"test".to_vec());
        assert_eq!(entry.generation, Generation::new(3));
    }

    #[test]
    fn request_ctx_clone_is_field_identical() {
        let ctx = RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: vec![10, 20, 30],
        };
        let cloned = ctx.clone();
        assert_eq!(cloned.uid, ctx.uid);
        assert_eq!(cloned.gid, ctx.gid);
        assert_eq!(cloned.pid, ctx.pid);
        assert_eq!(cloned.groups, ctx.groups);
    }

    #[test]
    fn dir_entry_non_utf8_name_bytes_round_trip() {
        let raw_name = vec![0x00, 0xFF, 0x80, 0xFE, b'/'];
        let entry = DirEntry::new(
            raw_name.clone(),
            InodeId::new(7),
            NodeKind::File,
            Generation::new(1),
            0,
        );
        assert_eq!(entry.name, raw_name);
    }

    #[test]
    fn dir_entry_clone_preserves_all_fields() {
        let entry = DirEntry::new(
            vec![b'x'],
            InodeId::new(9),
            NodeKind::Symlink,
            Generation::new(5),
            123,
        );
        let cloned = entry.clone();
        assert_eq!(cloned.inode_id, entry.inode_id);
        assert_eq!(cloned.kind, entry.kind);
        assert_eq!(cloned.generation, entry.generation);
        assert_eq!(cloned.cookie, entry.cookie);
        assert_eq!(cloned.name, entry.name);
    }

    // ── Ownership semantics: clone is a deep copy ─────────────────────────

    #[test]
    fn request_ctx_clone_deep_copies_groups_ownership() {
        let mut original = RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: vec![10, 20, 30],
        };
        let cloned = original.clone();
        original.groups.push(99);
        original.groups[0] = 999;
        assert_eq!(cloned.groups, vec![10, 20, 30]);
        assert_eq!(original.groups, vec![999, 20, 30, 99]);
    }

    #[test]
    fn dir_entry_clone_deep_copies_name_ownership() {
        let mut original = DirEntry::new(
            vec![b'h', b'e', b'l', b'l', b'o'],
            InodeId::new(1),
            NodeKind::File,
            Generation::new(2),
            0,
        );
        let cloned = original.clone();
        original.name[0] = b'X';
        original.name.push(b'!');
        assert_eq!(cloned.name, vec![b'h', b'e', b'l', b'l', b'o']);
        assert_eq!(original.name, vec![b'X', b'e', b'l', b'l', b'o', b'!']);
    }

    #[test]
    fn request_ctx_clone_scalar_independence() {
        let original = RequestCtx {
            uid: 1,
            gid: 2,
            pid: 3,
            umask: 4,
            groups: vec![5],
        };
        let cloned = original.clone();
        let mut modified = original.clone();
        modified.uid = 99;
        modified.gid = 99;
        modified.pid = 99;
        modified.umask = 99;
        assert_eq!(cloned, original);
        assert_ne!(modified, original);
    }

    #[test]
    fn dir_entry_clone_scalar_independence() {
        let original = DirEntry::new(
            vec![b'a'],
            InodeId::new(1),
            NodeKind::File,
            Generation::new(2),
            3,
        );
        let cloned = original.clone();
        let mut modified = original.clone();
        modified.inode_id = InodeId::new(99);
        modified.cookie = 99;
        assert_eq!(cloned, original);
        assert_ne!(modified, original);
    }

    // ── Roundtrip through construction / clone ────────────────────────────

    #[test]
    fn request_ctx_all_fields_roundtrip_through_construction() {
        let ctx = RequestCtx {
            uid: 0xFFFF_FFFF,
            gid: 0xAAAA_BBBB,
            pid: 0xCCCC_DDDD,
            umask: 0o777,
            groups: vec![0, 1, u32::MAX],
        };
        assert_eq!(ctx.uid, 0xFFFF_FFFF);
        assert_eq!(ctx.gid, 0xAAAA_BBBB);
        assert_eq!(ctx.pid, 0xCCCC_DDDD);
        assert_eq!(ctx.umask, 0o777);
        assert_eq!(ctx.groups, vec![0, 1, u32::MAX]);
    }

    #[test]
    fn dir_entry_new_constructor_roundtrips_all_fields() {
        let entry = DirEntry::new(
            vec![0x00, 0xFF, 0x80],
            InodeId::new(u64::MAX),
            NodeKind::Whiteout,
            Generation::new(u64::MAX),
            u64::MAX,
        );
        assert_eq!(entry.name, vec![0x00, 0xFF, 0x80]);
        assert_eq!(entry.inode_id, InodeId::new(u64::MAX));
        assert_eq!(entry.kind, NodeKind::Whiteout);
        assert_eq!(entry.generation, Generation::new(u64::MAX));
        assert_eq!(entry.cookie, u64::MAX);
    }

    // ── Boundary and edge case tests ──────────────────────────────────────

    #[test]
    fn request_ctx_empty_groups_preserved() {
        let ctx = RequestCtx {
            uid: 1,
            gid: 1,
            pid: 1,
            umask: 0,
            groups: vec![],
        };
        assert!(ctx.groups.is_empty());
        let cloned = ctx.clone();
        assert!(cloned.groups.is_empty());
    }

    #[test]
    fn request_ctx_max_u32_fields() {
        let ctx = RequestCtx {
            uid: u32::MAX,
            gid: u32::MAX,
            pid: u32::MAX,
            umask: u32::MAX,
            groups: vec![u32::MAX, u32::MAX],
        };
        assert_eq!(ctx.uid, u32::MAX);
        assert_eq!(ctx.gid, u32::MAX);
        assert_eq!(ctx.pid, u32::MAX);
        assert_eq!(ctx.umask, u32::MAX);
        assert_eq!(ctx.groups, vec![u32::MAX, u32::MAX]);
    }

    #[test]
    fn dir_entry_long_name_preserved() {
        let long: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
        let entry = DirEntry::new(
            long.clone(),
            InodeId::new(1),
            NodeKind::File,
            Generation::new(0),
            0,
        );
        assert_eq!(entry.name, long);
        assert_eq!(entry.name.len(), 4096);
    }

    #[test]
    fn dir_entry_minimal_name() {
        let entry = DirEntry::new(
            vec![],
            InodeId::new(0),
            NodeKind::Dir,
            Generation::new(0),
            0,
        );
        assert!(entry.name.is_empty());
    }

    #[test]
    fn dir_entry_max_cookie_value() {
        let entry = DirEntry::new(
            vec![b'x'],
            InodeId::new(0),
            NodeKind::File,
            Generation::new(0),
            u64::MAX,
        );
        assert_eq!(entry.cookie, u64::MAX);
    }

    // ── PartialEq inequality ──────────────────────────────────────────────

    #[test]
    fn request_ctx_partial_eq_detects_uid_difference() {
        let a = RequestCtx {
            uid: 1,
            gid: 0,
            pid: 0,
            umask: 0,
            groups: vec![],
        };
        let b = RequestCtx {
            uid: 2,
            gid: 0,
            pid: 0,
            umask: 0,
            groups: vec![],
        };
        assert_ne!(a, b);
    }

    #[test]
    fn request_ctx_partial_eq_detects_groups_difference() {
        let a = RequestCtx {
            uid: 0,
            gid: 0,
            pid: 0,
            umask: 0,
            groups: vec![1],
        };
        let b = RequestCtx {
            uid: 0,
            gid: 0,
            pid: 0,
            umask: 0,
            groups: vec![2],
        };
        assert_ne!(a, b);
    }

    #[test]
    fn request_ctx_partial_eq_equal_when_all_fields_match() {
        let a = RequestCtx {
            uid: 1,
            gid: 2,
            pid: 3,
            umask: 4,
            groups: vec![5, 6],
        };
        let b = RequestCtx {
            uid: 1,
            gid: 2,
            pid: 3,
            umask: 4,
            groups: vec![5, 6],
        };
        assert_eq!(a, b);
    }

    #[test]
    fn dir_entry_partial_eq_detects_kind_difference() {
        let a = DirEntry::new(
            vec![],
            InodeId::new(1),
            NodeKind::File,
            Generation::new(0),
            0,
        );
        let b = DirEntry::new(
            vec![],
            InodeId::new(1),
            NodeKind::Dir,
            Generation::new(0),
            0,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn dir_entry_partial_eq_detects_inode_id_difference() {
        let a = DirEntry::new(
            vec![],
            InodeId::new(1),
            NodeKind::File,
            Generation::new(0),
            0,
        );
        let b = DirEntry::new(
            vec![],
            InodeId::new(2),
            NodeKind::File,
            Generation::new(0),
            0,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn dir_entry_partial_eq_detects_name_difference() {
        let a = DirEntry::new(
            vec![b'a'],
            InodeId::new(1),
            NodeKind::File,
            Generation::new(0),
            0,
        );
        let b = DirEntry::new(
            vec![b'b'],
            InodeId::new(1),
            NodeKind::File,
            Generation::new(0),
            0,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn dir_entry_partial_eq_equal_when_all_fields_match() {
        let a = DirEntry::new(
            vec![b'x'],
            InodeId::new(42),
            NodeKind::Symlink,
            Generation::new(7),
            99,
        );
        let b = DirEntry::new(
            vec![b'x'],
            InodeId::new(42),
            NodeKind::Symlink,
            Generation::new(7),
            99,
        );
        assert_eq!(a, b);
    }

    // ── Debug output ──────────────────────────────────────────────────────

    #[test]
    fn request_ctx_debug_includes_groups_and_scalar_fields() {
        let ctx = RequestCtx {
            uid: 42,
            gid: 7,
            pid: 1,
            umask: 0o022,
            groups: vec![10, 20],
        };
        let debug = format!("{ctx:?}");
        assert!(debug.contains("42"));
        assert!(debug.contains("7"));
        assert!(debug.contains("10"));
        assert!(debug.contains("20"));
    }

    #[test]
    fn dir_entry_debug_includes_inode_id_and_name() {
        let entry = DirEntry::new(
            vec![b't', b'e', b's', b't'],
            InodeId::new(42),
            NodeKind::File,
            Generation::new(1),
            0,
        );
        let debug = format!("{entry:?}");
        assert!(debug.contains("116"));
        assert!(debug.contains("42"));
    }

    // ── Human alias module ────────────────────────────────────────────────

    #[test]
    fn human_vfs_owned_aliases_re_export_canonical_types() {
        use human::vfs_owned::{DirEntry as HumanDirEntry, RequestCtx as HumanRequestCtx};
        let ctx = HumanRequestCtx {
            uid: 1,
            gid: 1,
            pid: 1,
            umask: 0,
            groups: vec![],
        };
        assert_eq!(ctx.uid, 1);
        let entry = HumanDirEntry::new(
            vec![],
            InodeId::new(0),
            NodeKind::File,
            Generation::new(0),
            0,
        );
        assert_eq!(entry.inode_id, InodeId::new(0));
    }

    #[test]
    fn vfs_owned_constants_accessible_via_human_alias() {
        use human::vfs_owned::{FAMILY_NAME, ROLE};
        assert_eq!(FAMILY_NAME, "VFS Owned Values");
        assert_eq!(
            ROLE,
            "alloc-backed names, contexts, and directory entries for VFS operations"
        );
        assert_eq!(crate::vfs_owned::FAMILY_NAME, FAMILY_NAME);
        assert_eq!(crate::vfs_owned::ROLE, ROLE);
    }
}
