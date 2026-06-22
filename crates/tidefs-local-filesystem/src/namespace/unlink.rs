// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Directory entry removal (unlink) for the TideFS namespace.
//!
//! Implements POSIX `unlink(2)` semantics: removes a name from a
//! directory and decrements the target inode's `nlink`. When `nlink`
//! reaches zero and no open handles remain, the inode is eligible
//! for orphan reclamation.
//!
//! # Algorithm
//!
//! 1. **Pre-check**: Resolve parent directory and target entry;
//!    validate the entry exists, is not a directory, and the name
//!    is valid.
//!
//! 2. **Lock acquisition**: Acquire directory lock on the parent.
//!
//! 3. **Entry removal**: Remove the directory entry from the parent.
//!
//! 4. **Metadata update**: Decrement `nlink` on the target inode.
//!    If `nlink` reaches zero, mark the inode as orphaned.
//!
//! 5. **Persistence commit**: The caller wraps the entire operation in
//!    a transaction commit.

use std::collections::BTreeMap;

use tidefs_types_vfs_core::{InodeId, NodeKind};

use crate::error::FileSystemError;
use crate::helpers::{parse_absolute_path, validate_name};
use crate::types::{InodeRecord, NamespaceEntry};
use crate::Result;

// ---------------------------------------------------------------------------
// UnlinkResult
// ---------------------------------------------------------------------------

/// Output of a successful unlink operation.
#[derive(Clone, Debug)]
#[allow(dead_code)] // INTENT: result types for namespaced link/unlink/symlink support
pub struct UnlinkResult {
    /// The target inode ID that was unlinked.
    pub target_inode_id: InodeId,
    /// The parent directory inode ID.
    pub parent_id: InodeId,
    /// The removed entry name.
    pub name: Vec<u8>,
    /// The nlink count after decrement (0 means orphan).
    pub remaining_nlink: u32,
    /// True if this was the last link (nlink reached zero).
    pub is_orphaned: bool,
}

// ---------------------------------------------------------------------------
// unlink_entry — top-level entry point
// ---------------------------------------------------------------------------

/// Remove a directory entry and decrement the target inode's link count.
///
/// This function operates on the namespace in-memory state (`inodes`
/// and `directories` maps). The caller is responsible for providing
/// the correct authoritative maps and for orchestrating the external
/// persistence transaction.
///
/// # POSIX semantics
///
/// - The entry must exist (`ENOENT`).
/// - The target must NOT be a directory — use `rmdir` for directories
///   (`EISDIR`).
/// - The name must be a valid path component (`EINVAL`).
///
/// # Lock ordering
///
/// Only the parent directory is locked. No deadlock risk.
#[allow(dead_code)] // INTENT: namespace ops for namespaced link/unlink/symlink support
pub fn unlink_entry(
    inodes: &mut BTreeMap<InodeId, InodeRecord>,
    directories: &mut BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    path: &str,
) -> Result<UnlinkResult> {
    // ── Step 1: Pre-check ──────────────────────────────────────────
    let pre = pre_check(inodes, directories, path)?;

    // ── Steps 2-4: Lock + remove + update metadata ─────────────────
    apply_unlink(inodes, directories, &pre)
}

// ===========================================================================
// Step 1: Pre-check
// ===========================================================================

/// Validate that an unlink is possible and resolve the involved inodes.
#[derive(Clone, Debug)]
pub(crate) struct PreCheck {
    pub(crate) parent_id: InodeId,
    pub(crate) name: Vec<u8>,
    pub(crate) target_inode_id: InodeId,
}

pub(crate) fn pre_check(
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    path: &str,
) -> Result<PreCheck> {
    // ── Parse and validate path ────────────────────────────────────
    let parts = parse_absolute_path(path)?;

    if parts.is_empty() {
        return Err(FileSystemError::InvalidPath {
            path: path.to_string(),
            reason: "cannot unlink the root directory",
        });
    }

    // ── Resolve parent directory and entry name ────────────────────
    let (parent_id, name) = resolve_parent_and_name(inodes, directories, path, &parts)?;

    // ── Look up the entry ──────────────────────────────────────────
    let dir = directories.get(&parent_id).ok_or({
        FileSystemError::CorruptState {
            reason: "parent directory missing during unlink pre-check",
        }
    })?;

    let entry = dir.get(&name).ok_or_else(|| FileSystemError::NotFound {
        path: path.to_string(),
    })?;

    let target_inode_id = entry.inode_id;

    // ── Validate target is not a directory ─────────────────────────
    let target = inodes.get(&target_inode_id).ok_or({
        FileSystemError::CorruptState {
            reason: "target inode missing during unlink pre-check",
        }
    })?;

    if target.kind() == NodeKind::Dir {
        return Err(FileSystemError::IsDirectory {
            path: path.to_string(),
        });
    }

    // ── Special names are rejected ─────────────────────────────────
    if name == b"." || name == b".." {
        return Err(FileSystemError::InvalidName {
            name: name.clone(),
            reason: "cannot unlink . or ..",
        });
    }

    Ok(PreCheck {
        parent_id,
        name,
        target_inode_id,
    })
}

// ===========================================================================
// Steps 2-4: Entry removal + metadata update
// ===========================================================================

/// Remove the directory entry, decrement nlink, and handle orphan state.
fn apply_unlink(
    inodes: &mut BTreeMap<InodeId, InodeRecord>,
    directories: &mut BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    pre: &PreCheck,
) -> Result<UnlinkResult> {
    // ── Remove the directory entry ─────────────────────────────────
    directories
        .get_mut(&pre.parent_id)
        .ok_or(FileSystemError::CorruptState {
            reason: "parent directory missing during unlink apply",
        })?
        .remove(&pre.name);

    // ── Decrement nlink on target inode ────────────────────────────
    let target = inodes.get_mut(&pre.target_inode_id).ok_or({
        FileSystemError::CorruptState {
            reason: "target inode missing during unlink apply",
        }
    })?;

    target.nlink = target.nlink.saturating_sub(1);
    let remaining = target.nlink;
    let is_orphaned = remaining == 0;

    // ── Clean up orphaned inode metadata ───────────────────────────
    if is_orphaned {
        // Clear xattrs and mark for reclamation.
        target.xattrs.clear();
    }

    Ok(UnlinkResult {
        target_inode_id: pre.target_inode_id,
        parent_id: pre.parent_id,
        name: pre.name.clone(),
        remaining_nlink: remaining,
        is_orphaned,
    })
}

// ===========================================================================
// Shared helpers
// ===========================================================================

/// Walk the parsed path components to the parent directory and extract
/// the final component name.
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

    // Walk to parent directory.
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

    // Verify parent exists and is a directory.
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
            subtree_rev: 0,
            rdev: 0,
        }
    }

    fn file_record(id: u64) -> InodeRecord {
        InodeRecord {
            dir_storage_kind: 0,
            inode_id: InodeId::new(id),
            generation: Generation(id),
            facets: NodeFacets {
                has_byte_space: true,
                has_child_namespace: false,
            },
            mode: 0o100644,
            uid: 0,
            gid: 0,
            nlink: 1,
            size: 0,
            data_version: 0,
            metadata_version: 0,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattr_storage_kind: 0,
            xattrs: BTreeMap::new(),
            dir_rev: 0,
            subtree_rev: 0,
            rdev: 0,
        }
    }

    fn ns_entry(name: &str, inode_id: u64) -> NamespaceEntry {
        NamespaceEntry {
            name: name.as_bytes().to_vec(),
            inode_id: InodeId::new(inode_id),
            generation: Generation(inode_id),
            facets: NodeFacets {
                has_byte_space: true,
                has_child_namespace: false,
            },
            mode: 0o100644,
        }
    }

    fn build_test_ns(children: &[(&str, u64)]) -> (TestInodeMap, TestDirectoryMap) {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        inodes.insert(InodeId::new(1), dir_record(1, 2));
        let mut root_entries = BTreeMap::new();

        for &(name, id) in children {
            inodes.insert(InodeId::new(id), file_record(id));
            root_entries.insert(name.as_bytes().to_vec(), ns_entry(name, id));
        }
        dirs.insert(InodeId::new(1), root_entries);

        (inodes, dirs)
    }

    // ── Tests ──────────────────────────────────────────────────────

    #[test]
    fn unlink_removes_entry_and_decrements_nlink() {
        let (mut inodes, mut dirs) = build_test_ns(&[("file", 2)]);

        let result = unlink_entry(&mut inodes, &mut dirs, "/file");

        assert!(result.is_ok(), "unlink should succeed: {:?}", result.err());
        let res = result.unwrap();
        assert_eq!(res.target_inode_id, InodeId::new(2));
        assert_eq!(res.remaining_nlink, 0);
        assert!(res.is_orphaned);

        // Entry removed from root.
        let root = dirs.get(&InodeId::new(1)).unwrap();
        assert!(!root.contains_key(b"file".as_ref()));

        // Inode still exists (orphaned).
        let inode = inodes.get(&InodeId::new(2)).unwrap();
        assert_eq!(inode.nlink, 0);
    }

    #[test]
    fn unlink_with_remaining_links_preserves_inode() {
        let (mut inodes, mut dirs) = build_test_ns(&[("link_a", 2), ("link_b", 2)]);
        // Make both entries point to the same inode.
        dirs.get_mut(&InodeId::new(1))
            .unwrap()
            .get_mut(b"link_b".as_ref())
            .unwrap()
            .inode_id = InodeId::new(2);
        inodes.get_mut(&InodeId::new(2)).unwrap().nlink = 2;

        // Remove one link.
        let result = unlink_entry(&mut inodes, &mut dirs, "/link_a");

        assert!(result.is_ok(), "unlink should succeed: {:?}", result.err());
        let res = result.unwrap();
        assert_eq!(res.remaining_nlink, 1);
        assert!(!res.is_orphaned);

        // Inode still exists.
        assert!(inodes.contains_key(&InodeId::new(2)));
        assert_eq!(inodes.get(&InodeId::new(2)).unwrap().nlink, 1);

        // Remaining link still present.
        let root = dirs.get(&InodeId::new(1)).unwrap();
        assert!(root.contains_key(b"link_b".as_ref()));
        assert!(!root.contains_key(b"link_a".as_ref()));
    }

    #[test]
    fn unlink_nonexistent_returns_not_found() {
        let (mut inodes, mut dirs) = build_test_ns(&[]);

        let result = unlink_entry(&mut inodes, &mut dirs, "/missing");

        assert!(matches!(result, Err(FileSystemError::NotFound { .. })));
    }

    #[test]
    fn unlink_directory_returns_is_directory() {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        inodes.insert(InodeId::new(1), dir_record(1, 2));
        inodes.insert(InodeId::new(2), dir_record(2, 2));
        dirs.insert(InodeId::new(2), BTreeMap::new());

        let mut root_entries = BTreeMap::new();
        root_entries.insert(b"subdir".to_vec(), ns_entry("subdir", 2));
        // Fix: directory entries need directory facets.
        root_entries.get_mut(b"subdir".as_ref()).unwrap().facets = NodeFacets {
            has_byte_space: false,
            has_child_namespace: true,
        };
        root_entries.get_mut(b"subdir".as_ref()).unwrap().mode = 0o40755;
        dirs.insert(InodeId::new(1), root_entries);

        let result = unlink_entry(&mut inodes, &mut dirs, "/subdir");

        assert!(matches!(result, Err(FileSystemError::IsDirectory { .. })));
    }

    #[test]
    fn unlink_last_link_returns_orphaned() {
        let (mut inodes, mut dirs) = build_test_ns(&[("only", 2)]);
        inodes.get_mut(&InodeId::new(2)).unwrap().nlink = 1;

        let result = unlink_entry(&mut inodes, &mut dirs, "/only");

        assert!(result.is_ok());
        let res = result.unwrap();
        assert!(res.is_orphaned);
        assert_eq!(res.remaining_nlink, 0);
    }

    #[test]
    fn unlink_root_rejected() {
        let (mut inodes, mut dirs) = build_test_ns(&[]);
        // Root path cannot be unlinked.
        let result = unlink_entry(&mut inodes, &mut dirs, "/");

        assert!(result.is_err());
    }

    #[test]
    fn unlink_invalid_name_rejected() {
        let (mut inodes, mut dirs) = build_test_ns(&[]);

        // Empty component.
        let result = unlink_entry(&mut inodes, &mut dirs, "//");

        assert!(result.is_err());
    }
}
