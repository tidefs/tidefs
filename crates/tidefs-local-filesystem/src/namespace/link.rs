//! Hard link creation for the TideFS namespace.
//!
//! Implements POSIX `link(2)` semantics: creates a new directory entry
//! pointing to an existing inode, atomically increments `nlink`, and
//! validates cross-directory constraints.
//!
//! # Algorithm
//!
//! 1. **Pre-check**: Resolve target inode and new-parent directory;
//!    validate the target is not a directory, nlink does not overflow,
//!    the new-parent exists and is a directory, and the destination
//!    name is not already in use.
//!
//! 2. **Lock acquisition**: Acquire directory lock on the new parent
//!    directory. (Single-directory operation, no deadlock risk.)
//!
//! 3. **Entry insertion**: Insert the new directory entry pointing to
//!    the target inode.
//!
//! 4. **Metadata update**: Increment `nlink` on the target inode.
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
// LinkResult
// ---------------------------------------------------------------------------

/// Output of a successful hard-link operation.
#[derive(Clone, Debug)]
#[allow(dead_code)]
// INTENT: link helpers for planned namespaced link/unlink/symlink support
pub struct LinkResult {
    /// The target inode ID (unchanged).
    pub target_inode_id: InodeId,
    /// The new-parent directory inode ID.
    pub new_parent_id: InodeId,
    /// The new entry name.
    pub new_name: Vec<u8>,
    /// The updated nlink count on the target inode.
    pub new_nlink: u32,
}

// ---------------------------------------------------------------------------
// link_file — top-level entry point
// ---------------------------------------------------------------------------

/// Create a hard link from an existing target inode to a new name in a
/// (possibly different) parent directory.
///
/// This function operates on the namespace in-memory state (`inodes`
/// and `directories` maps). The caller is responsible for providing
/// the correct authoritative maps and for orchestrating the external
/// persistence transaction.
///
/// # POSIX semantics
///
/// - The target inode must exist and must NOT be a directory (`EPERM`).
/// - `nlink` must not overflow `u32::MAX` (`EMLINK`).
/// - The new-parent directory must exist and must be a directory
///   (`ENOENT`, `ENOTDIR`).
/// - The new name must not already exist in the new parent (`EEXIST`).
/// - The name must be a valid path component (`EINVAL`).
///
/// # Lock ordering
///
/// Only one directory is locked, so no deadlock risk exists. The lock
/// order follows the convention: the parent directory lock is acquired
/// before any entry manipulation.
#[allow(dead_code)] // INTENT: namespace ops for namespaced link/unlink/symlink support
pub fn link_file(
    inodes: &mut BTreeMap<InodeId, InodeRecord>,
    directories: &mut BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    target_path: &str,
    new_path: &str,
) -> Result<LinkResult> {
    // ── Step 1: Pre-check ──────────────────────────────────────────
    let pre = pre_check(inodes, directories, target_path, new_path)?;

    // ── Step 2: Lock acquisition ───────────────────────────────────
    // Single-directory operation: only the new parent needs locking.
    // (Documented for future multi-threaded work.)

    // ── Steps 3 & 4: Entry insertion + metadata update ─────────────
    apply_link(inodes, directories, &pre)
}

// ===========================================================================
// Step 1: Pre-check
// ===========================================================================

/// Validate that a hard link is possible and resolve the involved inodes.
#[derive(Clone, Debug)]
pub(crate) struct PreCheck {
    pub(crate) target_inode_id: InodeId,
    pub(crate) new_parent_id: InodeId,
    pub(crate) new_name: Vec<u8>,
}

pub(crate) fn pre_check(
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    target_path: &str,
    new_path: &str,
) -> Result<PreCheck> {
    // ── Parse and validate paths ───────────────────────────────────
    let target_parts = parse_absolute_path(target_path)?;
    let new_parts = parse_absolute_path(new_path)?;

    if target_parts.is_empty() || new_parts.is_empty() {
        return Err(FileSystemError::Unsupported {
            operation: "link",
            reason: "root inode cannot be the target of a hard link",
        });
    }

    // ── Resolve target inode ───────────────────────────────────────
    let target_inode_id = resolve_inode(inodes, directories, &target_parts, target_path)?;

    // ── Validate target: must not be a directory ───────────────────
    let target_record = inodes.get(&target_inode_id).ok_or({
        FileSystemError::CorruptState {
            reason: "target inode missing from inode table during link pre-check",
        }
    })?;

    if target_record.kind() == NodeKind::Dir {
        return Err(FileSystemError::Unsupported {
            operation: "link",
            reason: "cannot hard-link a directory",
        });
    }

    // ── Validate nlink does not overflow ───────────────────────────
    if target_record.nlink == u32::MAX {
        return Err(FileSystemError::Unsupported {
            operation: "link",
            reason: "link count would overflow",
        });
    }

    // ── Resolve new-parent directory ───────────────────────────────
    let (new_parent_id, new_name) =
        resolve_parent_and_name(inodes, directories, new_path, &new_parts)?;

    // ── Validate new parent is a directory ─────────────────────────
    let new_parent = inodes.get(&new_parent_id).ok_or({
        FileSystemError::CorruptState {
            reason: "new parent inode missing during link pre-check",
        }
    })?;

    if new_parent.kind() != NodeKind::Dir {
        return Err(FileSystemError::NotDirectory {
            path: new_path.to_string(),
        });
    }

    // ── Validate new name does not already exist ───────────────────
    if let Some(dir) = directories.get(&new_parent_id) {
        if dir.contains_key(&new_name) {
            return Err(FileSystemError::AlreadyExists {
                path: new_path.to_string(),
            });
        }
    }

    Ok(PreCheck {
        target_inode_id,
        new_parent_id,
        new_name,
    })
}

// ===========================================================================
// Steps 3 & 4: Entry insertion + metadata update
// ===========================================================================

/// Insert the new directory entry and increment the target's nlink.
fn apply_link(
    inodes: &mut BTreeMap<InodeId, InodeRecord>,
    directories: &mut BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    pre: &PreCheck,
) -> Result<LinkResult> {
    // ── Increment nlink on target inode ────────────────────────────
    let target = inodes.get_mut(&pre.target_inode_id).ok_or({
        FileSystemError::CorruptState {
            reason: "target inode missing during link apply",
        }
    })?;

    target.nlink = target.nlink.saturating_add(1);
    let new_nlink = target.nlink;

    // ── Create namespace entry ─────────────────────────────────────
    let entry = NamespaceEntry {
        name: pre.new_name.clone(),
        inode_id: pre.target_inode_id,
        generation: target.generation,
        facets: target.facets,
        mode: target.mode,
    };

    // ── Insert into parent directory ───────────────────────────────
    directories
        .get_mut(&pre.new_parent_id)
        .ok_or(FileSystemError::CorruptState {
            reason: "new parent directory missing during link apply",
        })?
        .insert(pre.new_name.clone(), entry);

    Ok(LinkResult {
        target_inode_id: pre.target_inode_id,
        new_parent_id: pre.new_parent_id,
        new_name: pre.new_name.clone(),
        new_nlink,
    })
}

// ===========================================================================
// Shared helpers
// ===========================================================================

/// Walk the parsed path components to resolve the final inode ID.
fn resolve_inode(
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    parts: &[Vec<u8>],
    full_path: &str,
) -> Result<InodeId> {
    // Start from root (inode 1).
    let mut current_id = InodeId::new(1);

    for component in parts.iter() {
        let dir = directories.get(&current_id).ok_or({
            FileSystemError::CorruptState {
                reason: "directory missing during path resolution",
            }
        })?;

        let entry = dir
            .get(component)
            .ok_or_else(|| FileSystemError::NotFound {
                path: full_path.to_string(),
            })?;

        current_id = entry.inode_id;
    }

    // Verify the resolved ID exists in the inode table.
    if !inodes.contains_key(&current_id) {
        return Err(FileSystemError::CorruptState {
            reason: "resolved inode missing from inode table",
        });
    }

    Ok(current_id)
}

/// Resolve the parent directory ID and final component name from a path.
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

    // Walk to the parent directory.
    let mut parent_id = InodeId::new(1); // root
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

    // Verify the parent exists and is a directory.
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
            posix_time: crate::types::PosixTimeRecord::from_generation(id),
            xattr_storage_kind: 0,
            xattrs: BTreeMap::new(),
            dir_rev: 0,
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
            posix_time: crate::types::PosixTimeRecord::from_generation(id),
            xattr_storage_kind: 0,
            xattrs: BTreeMap::new(),
            dir_rev: 0,
            rdev: 0,
        }
    }

    fn ns_entry(name: &str, inode_id: u64, is_dir: bool) -> NamespaceEntry {
        NamespaceEntry {
            name: name.as_bytes().to_vec(),
            inode_id: InodeId::new(inode_id),
            generation: Generation(inode_id),
            facets: if is_dir {
                NodeFacets {
                    has_byte_space: false,
                    has_child_namespace: true,
                }
            } else {
                NodeFacets {
                    has_byte_space: true,
                    has_child_namespace: false,
                }
            },
            mode: if is_dir { 0o40755 } else { 0o100644 },
        }
    }

    fn build_test_ns(children: &[(&str, u64, bool)]) -> (TestInodeMap, TestDirectoryMap) {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        // Root directory (inode 1)
        inodes.insert(InodeId::new(1), dir_record(1, 2));
        let mut root_entries = BTreeMap::new();

        for &(name, id, is_dir) in children {
            if is_dir {
                inodes.insert(InodeId::new(id), dir_record(id, 2));
                dirs.insert(InodeId::new(id), BTreeMap::new());
            } else {
                inodes.insert(InodeId::new(id), file_record(id));
            }
            root_entries.insert(name.as_bytes().to_vec(), ns_entry(name, id, is_dir));
        }
        dirs.insert(InodeId::new(1), root_entries);

        (inodes, dirs)
    }

    // ── Tests ──────────────────────────────────────────────────────

    #[test]
    fn link_creates_second_name_and_bumps_nlink() {
        let (mut inodes, mut dirs) = build_test_ns(&[("file", 2, false)]);
        let initial_nlink = inodes.get(&InodeId::new(2)).unwrap().nlink;

        let result = link_file(&mut inodes, &mut dirs, "/file", "/hardlink");

        assert!(result.is_ok(), "link should succeed: {:?}", result.err());
        let res = result.unwrap();
        assert_eq!(res.target_inode_id, InodeId::new(2));
        assert_eq!(res.new_nlink, initial_nlink + 1);

        // Verify nlink was incremented.
        let file = inodes.get(&InodeId::new(2)).unwrap();
        assert_eq!(file.nlink, initial_nlink + 1);

        // Verify the new entry exists in root.
        let root = dirs.get(&InodeId::new(1)).unwrap();
        assert!(root.contains_key(b"hardlink".as_ref()));
        assert_eq!(
            root.get(b"hardlink".as_ref()).unwrap().inode_id,
            InodeId::new(2)
        );

        // Original entry still exists.
        assert!(root.contains_key(b"file".as_ref()));
    }

    #[test]
    fn link_rejects_directory_target() {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        inodes.insert(InodeId::new(1), dir_record(1, 2));
        inodes.insert(InodeId::new(2), dir_record(2, 2));
        dirs.insert(InodeId::new(2), BTreeMap::new());

        let mut root_entries = BTreeMap::new();
        root_entries.insert(b"subdir".to_vec(), ns_entry("subdir", 2, true));
        dirs.insert(InodeId::new(1), root_entries);

        let result = link_file(&mut inodes, &mut dirs, "/subdir", "/link_to_dir");

        assert!(matches!(result, Err(FileSystemError::Unsupported { .. })));
    }

    #[test]
    fn link_rejects_existing_destination_name() {
        let (mut inodes, mut dirs) = build_test_ns(&[("a", 2, false), ("b", 3, false)]);

        let result = link_file(&mut inodes, &mut dirs, "/a", "/b");

        assert!(matches!(result, Err(FileSystemError::AlreadyExists { .. })));
    }

    #[test]
    fn link_rejects_missing_target() {
        let (mut inodes, mut dirs) = build_test_ns(&[]);

        let result = link_file(&mut inodes, &mut dirs, "/missing", "/link");

        assert!(matches!(result, Err(FileSystemError::NotFound { .. })));
    }

    #[test]
    fn link_rejects_missing_new_parent() {
        let (mut inodes, mut dirs) = build_test_ns(&[("file", 2, false)]);

        let result = link_file(&mut inodes, &mut dirs, "/file", "/missing/link");

        assert!(matches!(result, Err(FileSystemError::NotFound { .. })));
    }

    #[test]
    fn link_across_directories() {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        // Root (1) contains subdir (2) and file (3).
        inodes.insert(InodeId::new(1), dir_record(1, 3));
        inodes.insert(InodeId::new(2), dir_record(2, 2));
        inodes.insert(InodeId::new(3), file_record(3));

        let mut root_entries = BTreeMap::new();
        root_entries.insert(b"subdir".to_vec(), ns_entry("subdir", 2, true));
        root_entries.insert(b"file".to_vec(), ns_entry("file", 3, false));
        dirs.insert(InodeId::new(1), root_entries);
        dirs.insert(InodeId::new(2), BTreeMap::new());

        // Link /file → /subdir/linked
        let result = link_file(&mut inodes, &mut dirs, "/file", "/subdir/linked");

        assert!(
            result.is_ok(),
            "cross-directory link should succeed: {:?}",
            result.err()
        );

        // Verify entry in subdir.
        let subdir = dirs.get(&InodeId::new(2)).unwrap();
        assert!(subdir.contains_key(b"linked".as_ref()));
        assert_eq!(
            subdir.get(b"linked".as_ref()).unwrap().inode_id,
            InodeId::new(3)
        );

        // Verify nlink bumped.
        assert_eq!(inodes.get(&InodeId::new(3)).unwrap().nlink, 2);
    }

    #[test]
    fn link_preserves_original_after_unlink_of_one_name() {
        let (mut inodes, mut dirs) = build_test_ns(&[("file", 2, false)]);

        // Create hard link.
        link_file(&mut inodes, &mut dirs, "/file", "/link2").unwrap();
        assert_eq!(inodes.get(&InodeId::new(2)).unwrap().nlink, 2);

        // Remove the original name (simulate unlink).
        dirs.get_mut(&InodeId::new(1))
            .unwrap()
            .remove(b"file".as_ref());
        inodes.get_mut(&InodeId::new(2)).unwrap().nlink -= 1;

        // Inode should still exist with nlink 1.
        assert!(inodes.contains_key(&InodeId::new(2)));
        assert_eq!(inodes.get(&InodeId::new(2)).unwrap().nlink, 1);

        // The remaining link should still be in the root directory.
        let root = dirs.get(&InodeId::new(1)).unwrap();
        assert!(root.contains_key(b"link2".as_ref()));
    }

    #[test]
    fn link_nlink_overflow_rejected() {
        let (mut inodes, mut dirs) = build_test_ns(&[("file", 2, false)]);
        // Set nlink to u32::MAX.
        inodes.get_mut(&InodeId::new(2)).unwrap().nlink = u32::MAX;

        let result = link_file(&mut inodes, &mut dirs, "/file", "/hardlink");

        assert!(matches!(result, Err(FileSystemError::Unsupported { .. })));
    }

    #[test]
    fn link_rejects_invalid_destination_name() {
        let (mut inodes, mut dirs) = build_test_ns(&[("file", 2, false)]);

        // Name with a slash is invalid.
        let result = link_file(&mut inodes, &mut dirs, "/file", "/bad/name");

        // This should fail - the parent /bad doesn't exist.
        assert!(result.is_err());
    }

    #[test]
    fn link_to_self_is_rejected() {
        // Hard-linking an inode to the same name should fail with EEXIST.
        let (mut inodes, mut dirs) = build_test_ns(&[("file", 2, false)]);

        let result = link_file(&mut inodes, &mut dirs, "/file", "/file");

        assert!(matches!(result, Err(FileSystemError::AlreadyExists { .. })));
    }
}
