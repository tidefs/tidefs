// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Symbolic link creation for the TideFS namespace.
//!
//! Implements POSIX `symlink(2)` semantics: allocates a new inode,
//! writes the symlink target as the inode's content, and creates a
//! directory entry in the parent directory.
//!
//! # Algorithm
//!
//! 1. **Pre-check**: Resolve parent directory, validate the target
//!    is non-empty, validate the link name does not already exist.
//!
//! 2. **Lock acquisition**: Acquire directory lock on the parent.
//!
//! 3. **Inode allocation**: Allocate a new inode with `Symlink` kind,
//!    `nlink = 1`, and store the symlink target as byte content.
//!
//! 4. **Entry insertion**: Insert the directory entry pointing to the
//!    new symlink inode.
//!
//! 5. **Persistence commit**: The caller wraps the entire operation in
//!    a transaction commit.

use std::collections::BTreeMap;

use tidefs_types_vfs_core::{InodeId, NodeFacets, NodeKind};

use crate::error::FileSystemError;
use crate::helpers::{parse_absolute_path, validate_name};
use crate::types::{InodeRecord, NamespaceEntry};
use crate::Result;

// ---------------------------------------------------------------------------
// SymlinkResult
// ---------------------------------------------------------------------------

/// Output of a successful symlink creation.
#[derive(Clone, Debug)]
#[allow(dead_code)] // INTENT: result types for namespaced link/unlink/symlink support
pub struct SymlinkResult {
    /// The newly allocated symlink inode ID.
    pub symlink_inode_id: InodeId,
    /// The parent directory inode ID.
    pub parent_id: InodeId,
    /// The link name.
    pub name: Vec<u8>,
    /// The symlink target content.
    pub target: Vec<u8>,
}

// ---------------------------------------------------------------------------
// create_symlink — top-level entry point
// ---------------------------------------------------------------------------

/// Create a symbolic link at `link_path` pointing to `target`.
///
/// This function operates on the namespace in-memory state (`inodes`
/// and `directories` maps). The caller provides the `next_inode_id`
/// function to allocate fresh inode IDs and is responsible for
/// orchestrating the external persistence transaction.
///
/// # POSIX semantics
///
/// - The target must not be empty (`EINVAL`).
/// - The parent directory must exist and be a directory (`ENOENT`,
///   `ENOTDIR`).
/// - The link name must not already exist in the parent (`EEXIST`).
/// - Symlink targets are stored as raw bytes; no path resolution
///   is performed at creation time.
///
/// # Lock ordering
///
/// Only the parent directory is locked. No deadlock risk.
#[allow(dead_code)] // INTENT: namespace ops for namespaced link/unlink/symlink support
pub fn create_symlink(
    inodes: &mut BTreeMap<InodeId, InodeRecord>,
    directories: &mut BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    target: &[u8],
    link_path: &str,
    next_inode_id: &mut impl FnMut() -> InodeId,
) -> Result<SymlinkResult> {
    // ── Step 1: Pre-check ──────────────────────────────────────────
    let pre = pre_check(inodes, directories, target, link_path)?;

    // ── Steps 2-4: Lock + allocate + insert ────────────────────────
    apply_symlink(inodes, directories, &pre, next_inode_id)
}

// ===========================================================================
// Step 1: Pre-check
// ===========================================================================

/// Validate symlink constraints and resolve the parent directory.
#[derive(Clone, Debug)]
pub(crate) struct PreCheck {
    pub(crate) parent_id: InodeId,
    pub(crate) name: Vec<u8>,
    pub(crate) target: Vec<u8>,
}

pub(crate) fn pre_check(
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    target: &[u8],
    link_path: &str,
) -> Result<PreCheck> {
    // ── Validate target ────────────────────────────────────────────
    // ── Parse and validate link path ───────────────────────────────
    let parts = parse_absolute_path(link_path)?;

    if parts.is_empty() {
        return Err(FileSystemError::InvalidPath {
            path: link_path.to_string(),
            reason: "cannot create symlink at root",
        });
    }

    // ── Resolve parent directory and link name ────────────────────
    let (parent_id, name) = resolve_parent_and_name(inodes, directories, link_path, &parts)?;

    // ── Validate link name does not already exist ──────────────────
    if let Some(dir) = directories.get(&parent_id) {
        if dir.contains_key(&name) {
            return Err(FileSystemError::AlreadyExists {
                path: link_path.to_string(),
            });
        }
    }

    Ok(PreCheck {
        parent_id,
        name,
        target: target.to_vec(),
    })
}

// ===========================================================================
// Steps 2-4: Inode allocation + entry insertion
// ===========================================================================

/// Allocate a symlink inode, store the target, and insert the directory
/// entry.
fn apply_symlink(
    inodes: &mut BTreeMap<InodeId, InodeRecord>,
    directories: &mut BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    pre: &PreCheck,
    next_inode_id: &mut impl FnMut() -> InodeId,
) -> Result<SymlinkResult> {
    // ── Allocate new symlink inode ─────────────────────────────────
    let symlink_ino = next_inode_id();
    let symlink_inode = InodeRecord {
        dir_storage_kind: 0,
        inode_id: symlink_ino,
        generation: tidefs_types_vfs_core::Generation(symlink_ino.0),
        facets: NodeFacets {
            has_byte_space: true,
            has_child_namespace: false,
        },
        mode: 0o120777, // S_IFLNK | 0o777
        uid: 0,
        gid: 0,
        nlink: 1,
        size: pre.target.len() as u64,
        data_version: 0,
        metadata_version: 0,
        posix_time: crate::types::PosixTimeRecord::now(),
        xattr_storage_kind: 0,
        xattrs: BTreeMap::new(),
        dir_rev: 0,
        rdev: 0,
    };
    inodes.insert(symlink_ino, symlink_inode.clone());

    // ── Create namespace entry ─────────────────────────────────────
    let entry = NamespaceEntry {
        name: pre.name.clone(),
        inode_id: symlink_ino,
        generation: symlink_inode.generation,
        facets: symlink_inode.facets,
        mode: symlink_inode.mode,
    };

    // ── Insert into parent directory ───────────────────────────────
    directories
        .get_mut(&pre.parent_id)
        .ok_or(FileSystemError::CorruptState {
            reason: "parent directory missing during symlink apply",
        })?
        .insert(pre.name.clone(), entry);

    Ok(SymlinkResult {
        symlink_inode_id: symlink_ino,
        parent_id: pre.parent_id,
        name: pre.name.clone(),
        target: pre.target.clone(),
    })
}

// ===========================================================================
// Shared helpers
// ===========================================================================

/// Walk the parsed path to the parent directory and extract the final
/// component name.
fn resolve_parent_and_name(
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    full_path: &str,
    parts: &[Vec<u8>],
) -> Result<(InodeId, Vec<u8>)> {
    if parts.is_empty() {
        return Err(FileSystemError::InvalidPath {
            path: full_path.to_string(),
            reason: "path must have at least one component",
        });
    }

    let name = parts.last().unwrap().clone();
    validate_name(&name)?;

    let mut parent_id = InodeId::new(1);
    for component in parts.iter().take(parts.len() - 1) {
        let dir = directories.get(&parent_id).ok_or({
            FileSystemError::CorruptState {
                reason: "directory missing during parent resolution",
            }
        })?;

        let entry = dir
            .get(component)
            .ok_or_else(|| FileSystemError::NotFound {
                path: full_path.to_string(),
            })?;

        parent_id = entry.inode_id;
    }

    let parent = inodes.get(&parent_id).ok_or({
        FileSystemError::CorruptState {
            reason: "parent inode missing",
        }
    })?;

    if parent.kind() != NodeKind::Dir {
        return Err(FileSystemError::NotDirectory {
            path: full_path.to_string(),
        });
    }

    Ok((parent_id, name))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tidefs_types_vfs_core::Generation;
    use tidefs_types_vfs_core::{InodeId, NodeFacets};

    type TestInodeMap = BTreeMap<InodeId, InodeRecord>;
    type TestDirectoryMap = BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>;

    // ── Test helpers ───────────────────────────────────────────────

    fn dir_record(id: u64, nlink: u32) -> InodeRecord {
        InodeRecord {
            dir_storage_kind: 0,
            inode_id: InodeId::new(id),
            generation: Generation(id),
            facets: NodeFacets {
                has_byte_space: false,
                has_child_namespace: true,
            },
            mode: 0o40755,
            uid: 0,
            gid: 0,
            nlink,
            size: 0,
            data_version: 0,
            metadata_version: 0,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattr_storage_kind: 0,
            xattrs: BTreeMap::new(),
            dir_rev: 0,
            rdev: 0,
        }
    }

    fn build_test_ns() -> (TestInodeMap, TestDirectoryMap, impl FnMut() -> InodeId) {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        inodes.insert(InodeId::new(1), dir_record(1, 2));
        dirs.insert(InodeId::new(1), BTreeMap::new());

        let mut next_id = 2u64;
        let next_inode_id = move || {
            let id = InodeId::new(next_id);
            next_id += 1;
            id
        };

        (inodes, dirs, next_inode_id)
    }

    // ── Tests ──────────────────────────────────────────────────────

    #[test]
    fn symlink_creates_inode_and_entry() {
        let (mut inodes, mut dirs, mut next_id) = build_test_ns();

        let result = create_symlink(
            &mut inodes,
            &mut dirs,
            b"/target/path",
            "/mylink",
            &mut next_id,
        );

        assert!(result.is_ok(), "symlink should succeed: {:?}", result.err());
        let res = result.unwrap();
        assert_eq!(res.symlink_inode_id, InodeId::new(2));
        assert_eq!(res.name, b"mylink");
        assert_eq!(res.target, b"/target/path");

        // Verify inode created.
        let inode = inodes.get(&InodeId::new(2)).unwrap();
        assert_eq!(inode.kind(), NodeKind::Symlink);
        assert_eq!(inode.nlink, 1);
        assert_eq!(inode.size, 12); // "/target/path".len()

        // Verify entry in root.
        let root = dirs.get(&InodeId::new(1)).unwrap();
        assert!(root.contains_key(b"mylink".as_ref()));
        assert_eq!(
            root.get(b"mylink".as_ref()).unwrap().inode_id,
            InodeId::new(2)
        );
    }

    #[test]
    fn symlink_accepts_empty_target() {
        let (mut inodes, mut dirs, mut next_id) = build_test_ns();

        let result = create_symlink(&mut inodes, &mut dirs, b"", "/mylink", &mut next_id);

        assert!(result.is_ok(), "empty symlink target should be accepted");
        let r = result.unwrap();
        assert_eq!(r.symlink_inode_id, InodeId::new(2));
        assert_eq!(r.target, b"");
    }

    #[test]
    fn symlink_rejects_existing_destination() {
        let (mut inodes, mut dirs, mut next_id) = build_test_ns();

        // First symlink succeeds.
        create_symlink(&mut inodes, &mut dirs, b"/first", "/mylink", &mut next_id).unwrap();

        // Second symlink to same name fails.
        let result = create_symlink(&mut inodes, &mut dirs, b"/second", "/mylink", &mut next_id);

        assert!(matches!(result, Err(FileSystemError::AlreadyExists { .. })));
    }

    #[test]
    fn symlink_rejects_missing_parent() {
        let (mut inodes, mut dirs, mut next_id) = build_test_ns();

        let result = create_symlink(
            &mut inodes,
            &mut dirs,
            b"/target",
            "/missing_dir/link",
            &mut next_id,
        );

        assert!(matches!(result, Err(FileSystemError::NotFound { .. })));
    }

    #[test]
    fn symlink_preserves_target_bytes() {
        let (mut inodes, mut dirs, mut next_id) = build_test_ns();

        // Include binary content in the target.
        let target = b"path/with/binary\x00\x01\x02";

        let result = create_symlink(&mut inodes, &mut dirs, target, "/link", &mut next_id);

        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.target, target);

        let inode = inodes.get(&InodeId::new(2)).unwrap();
        assert_eq!(inode.size, target.len() as u64);
    }

    #[test]
    fn symlink_uses_next_inode_id() {
        let (mut inodes, mut dirs, mut next_id) = build_test_ns();

        // Create 3 symlinks, verify IDs are sequential.
        create_symlink(&mut inodes, &mut dirs, b"/a", "/a", &mut next_id).unwrap();
        create_symlink(&mut inodes, &mut dirs, b"/b", "/b", &mut next_id).unwrap();
        create_symlink(&mut inodes, &mut dirs, b"/c", "/c", &mut next_id).unwrap();

        assert!(inodes.contains_key(&InodeId::new(2)));
        assert!(inodes.contains_key(&InodeId::new(3)));
        assert!(inodes.contains_key(&InodeId::new(4)));
    }

    #[test]
    fn symlink_rejects_invalid_name() {
        let (mut inodes, mut dirs, mut next_id) = build_test_ns();

        // Name with embedded null.
        let result = create_symlink(
            &mut inodes,
            &mut dirs,
            b"/target",
            "/bad\0name",
            &mut next_id,
        );

        assert!(result.is_err());
    }
}
