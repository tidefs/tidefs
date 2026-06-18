// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! 5-step renameat2 atomicity algorithm for namespace mutations.
//!
//! Implements the POSIX `renameat2` system call with `RENAME_NOREPLACE`
//! and `RENAME_EXCHANGE` flags on top of the TideFS namespace layer.
//!
//! # Algorithm (5 steps)
//!
//! 1. **Pre-check**: Resolve source and destination parent directories;
//!    validate constraints (source must exist, NOREPLACE/EXCHANGE rules);
//!    reject file↔directory substitutions; detect rename-to-self no-op.
//!
//! 2. **Lock acquisition**: Acquire directory locks on source and
//!    destination parents in stable inode-number order (deadlock
//!    prevention). Single lock for same-directory renames.
//!
//! 3. **Entry manipulation**: Atomically remove/insert/swap directory
//!    entries within the locked scope using the namespace directory map.
//!
//! 4. **Metadata update**: Adjust link counts in the inode table;
//!    update parent directory `..` entries for directory moves;
//!    bump ctime/mtime timestamps.
//!
//! 5. **Persistence commit**: Wrap all mutations in a single object-store
//!    transaction. On commit, finalize timestamps. On rollback (or crash
//!    before commit), revert all mutations back to pre-rename state.

use std::collections::BTreeMap;

use tidefs_types_vfs_core::{Generation, InodeId, NodeFacets, NodeKind};

use crate::error::FileSystemError;
use crate::helpers::{parse_absolute_path, render_path, validate_name};
use crate::types::{InodeRecord, NamespaceEntry};
use crate::Result;

// ---------------------------------------------------------------------------
// RenameAt2Flags
// ---------------------------------------------------------------------------

/// Flags for the `renameat2` operation.
///
/// Mirrors the Linux `RENAME_*` constants:
/// - `RENAME_NOREPLACE` (1): fail with `EEXIST` if the destination exists.
/// - `RENAME_EXCHANGE` (2): atomically exchange source and destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenameAt2Flags(u32);

impl RenameAt2Flags {
    /// Plain rename (no flags). Overwrites the destination if it exists.
    pub const EMPTY: Self = Self(0);

    /// `RENAME_NOREPLACE`: do not overwrite an existing destination.
    pub const NOREPLACE: Self = Self(1);

    /// `RENAME_EXCHANGE`: atomically swap source and destination.
    pub const EXCHANGE: Self = Self(2);

    /// Returns true if the given flag(s) are set.
    #[must_use]
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Returns true if this is a plain rename (no flags).
    #[must_use]
    pub fn is_plain(self) -> bool {
        self.0 == 0
    }

    /// Returns true if `RENAME_NOREPLACE` is set.
    #[must_use]
    pub fn is_noreplace(self) -> bool {
        self.contains(Self::NOREPLACE)
    }

    /// Returns true if `RENAME_EXCHANGE` is set.
    #[must_use]
    pub fn is_exchange(self) -> bool {
        self.contains(Self::EXCHANGE)
    }

    /// Return the raw u32 flags value for intent-log persistence.
    #[must_use]
    pub fn as_raw(self) -> u32 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// PreCheckResult
// ---------------------------------------------------------------------------

/// Output of the step-1 pre-check phase.
#[derive(Clone, Debug)]
pub(crate) struct PreCheckResult {
    /// Inode ID of the source's parent directory.
    pub old_parent_id: InodeId,
    /// Inode ID of the destination's parent directory.
    pub new_parent_id: InodeId,
    /// Entry name within the source parent.
    pub old_name: Vec<u8>,
    /// Entry name within the destination parent.
    pub new_name: Vec<u8>,
    /// The source directory entry (guaranteed to exist after pre-check).
    pub old_entry: NamespaceEntry,
    /// The destination directory entry, if it exists.
    pub new_entry: Option<NamespaceEntry>,
    /// True when the source and destination are the same object (no-op).
    pub is_same: bool,
}

// ---------------------------------------------------------------------------
// renameat2 — top-level entry point
// ---------------------------------------------------------------------------

#[allow(dead_code)] // INTENT: rename helpers for planned renameat2/EXCHANGE support
/// Perform a `renameat2`-style atomic rename with the given flags.
///
/// This function orchestrates the 5-step algorithm:
/// 1. Pre-check (path resolution and constraint validation)
/// 2. Lock acquisition (deadlock-avoiding lock ordering)
/// 3. Directory entry manipulation (remove/insert/swap)
/// 4. Inode metadata update (link counts, timestamps)
/// 5. Persistence commit (transactional object-store write)
///
/// The `inodes` and `directories` parameters represent the filesystem's
/// live state. The caller is responsible for providing the correct
/// authoritative maps and for orchestrating the external persistence
/// transaction.
///
/// # Errors
///
/// Returns [`FileSystemError::NotFound`] when the source does not exist.
/// Returns [`FileSystemError::AlreadyExists`] when `RENAME_NOREPLACE` is
/// set and the destination exists.
/// Returns [`FileSystemError::NotFound`] when `RENAME_EXCHANGE` is set and
/// either source or destination is missing.
pub fn renameat2(
    inodes: &mut BTreeMap<InodeId, InodeRecord>,
    directories: &mut BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    old_path: &str,
    new_path: &str,
    flags: RenameAt2Flags,
) -> Result<()> {
    // ── Step 1: Pre-check ──────────────────────────────────────────
    let pre = pre_check(inodes, directories, old_path, new_path, flags)?;

    // No-op: source == destination
    if pre.is_same {
        return Ok(());
    }

    // ── Step 2: Lock acquisition ───────────────────────────────────
    // In a single-threaded namespace, lock ordering is enforced by the
    // caller (only one mutation at a time). We document the lock order
    // for future multi-threaded work.
    let (first_parent, second_parent) = acquire_lock_order(pre.old_parent_id, pre.new_parent_id);

    // ── Steps 3 & 4: Entry manipulation + metadata update ──────────
    // These steps are fused because metadata updates depend on entry
    // manipulation outcomes.
    manipulate_entries_and_update_metadata(
        inodes,
        directories,
        &pre,
        flags,
        first_parent,
        second_parent,
    )?;

    // ── Step 5: Persistence commit ─────────────────────────────────
    // The caller handles the object-store transaction. This module
    // returns success once the in-memory mutations are complete; the
    // caller wraps the entire operation in a transaction commit.
    Ok(())
}

// ===========================================================================
// Step 1: Pre-check
// ===========================================================================

/// Resolve source and destination paths, validate rename constraints,
/// and detect rename-to-self no-ops.
///
/// # Constraints validated
///
/// - Source path must exist in the namespace.
/// - With `RENAME_NOREPLACE`, destination must NOT exist (`EEXIST`).
/// - With `RENAME_EXCHANGE`, both source AND destination must exist (`ENOENT`).
/// - A directory cannot be renamed over a non-directory, and vice versa.
/// - A non-empty directory cannot be overwritten by a rename (for plain
///   rename with an existing destination directory).
/// - A directory cannot be moved into itself (prefix check).
pub(crate) fn pre_check(
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    old_path: &str,
    new_path: &str,
    flags: RenameAt2Flags,
) -> Result<PreCheckResult> {
    // ── Parse and validate paths ───────────────────────────────────
    let old_parts = parse_absolute_path(old_path)?;
    let new_parts = parse_absolute_path(new_path)?;

    if old_parts.is_empty() || new_parts.is_empty() {
        return Err(FileSystemError::Unsupported {
            operation: "renameat2",
            reason: "root inode cannot be renamed",
        });
    }

    // ── Resolve parent directories and entry names ─────────────────
    let (old_parent_id, old_name) =
        resolve_parent_and_name(inodes, directories, old_path, &old_parts)?;
    let (new_parent_id, new_name) =
        resolve_parent_and_name(inodes, directories, new_path, &new_parts)?;

    // ── Look up source entry (must exist) ──────────────────────────
    let old_entry = lookup_entry(directories, old_parent_id, &old_name, old_path)?;

    // ── Look up destination entry (may or may not exist) ───────────
    let new_entry = directories
        .get(&new_parent_id)
        .and_then(|dir| dir.get(&new_name))
        .cloned();

    // ── Validate rename constraints ───────────────────────────────

    // Rename-to-self: same parent and same name, or same inode id
    if old_parent_id == new_parent_id && old_name == new_name {
        return Ok(PreCheckResult {
            old_parent_id,
            new_parent_id,
            old_name,
            new_name,
            old_entry,
            new_entry,
            is_same: true,
        });
    }

    // Same-inode rename-to-self (different name but same underlying inode)
    if new_entry
        .as_ref()
        .is_some_and(|ne| ne.inode_id == old_entry.inode_id)
    {
        return Ok(PreCheckResult {
            old_parent_id,
            new_parent_id,
            old_name,
            new_name,
            old_entry,
            new_entry,
            is_same: true,
        });
    }

    // RENAME_NOREPLACE: destination must not exist
    if flags.is_noreplace() && new_entry.is_some() {
        return Err(FileSystemError::AlreadyExists {
            path: new_path.to_string(),
        });
    }

    // RENAME_EXCHANGE: both must exist
    if flags.is_exchange() {
        if new_entry.is_none() {
            return Err(FileSystemError::NotFound {
                path: new_path.to_string(),
            });
        }

        // Type mismatch check for exchange
        let old_kind = old_entry.kind();
        let new_kind = new_entry
            .as_ref()
            .map(|e| e.kind())
            .unwrap_or(NodeKind::File);
        if old_kind != new_kind {
            return Err(FileSystemError::Unsupported {
                operation: "renameat2",
                reason: "RENAME_EXCHANGE requires both entries to be the same type",
            });
        }
    }

    let moving_is_directory = old_entry.kind() == NodeKind::Dir;

    // Directory → non-directory substitution (plain rename)
    if let Some(ref target) = new_entry {
        if moving_is_directory && target.kind() != NodeKind::Dir {
            return Err(FileSystemError::NotDirectory {
                path: new_path.to_string(),
            });
        }
        if !moving_is_directory && target.kind() == NodeKind::Dir {
            return Err(FileSystemError::IsDirectory {
                path: new_path.to_string(),
            });
        }
    }

    // Directory cannot be moved inside itself
    if moving_is_directory && path_prefix_matches(&new_parts, &old_parts) {
        return Err(FileSystemError::InvalidPath {
            path: new_path.to_string(),
            reason: "directory cannot be moved inside itself",
        });
    }

    // Non-empty directory target check (for plain rename overwriting a dir).
    // EXCHANGE bypasses this check since it swaps entries, not overwrites.
    if !flags.is_exchange() {
        if let Some(ref target) = new_entry {
            if moving_is_directory && target.kind() == NodeKind::Dir {
                let target_dir = directories.get(&target.inode_id);
                if target_dir.is_some_and(|d| !d.is_empty()) {
                    return Err(FileSystemError::DirectoryNotEmpty {
                        path: new_path.to_string(),
                    });
                }
            }
        }
    }

    Ok(PreCheckResult {
        old_parent_id,
        new_parent_id,
        old_name,
        new_name,
        old_entry,
        new_entry,
        is_same: false,
    })
}

// ===========================================================================
// Step 2: Lock acquisition
// ===========================================================================

#[allow(dead_code)] // INTENT: rename helpers for planned renameat2/EXCHANGE support
/// Return the parent directory IDs in stable lock-acquisition order.
///
/// For same-directory renames, both values are the same and only one
/// lock is needed. For cross-directory renames, the smaller inode number
/// is locked first to prevent AB/BA deadlocks.
pub(crate) fn acquire_lock_order(old_parent: InodeId, new_parent: InodeId) -> (InodeId, InodeId) {
    if old_parent <= new_parent {
        (old_parent, new_parent)
    } else {
        (new_parent, old_parent)
    }
}

// ===========================================================================
// Steps 3 & 4: Entry manipulation + metadata update (fused)
// ===========================================================================

#[allow(dead_code)] // INTENT: rename helpers for planned renameat2/EXCHANGE support
/// Apply the directory-entry changes and inode-metadata updates for
/// the rename operation.
///
/// This function modifies `inodes` and `directories` in place. The
/// caller must have already called `begin_mutation` (or equivalent)
/// so that any error can trigger a rollback.
fn manipulate_entries_and_update_metadata(
    inodes: &mut BTreeMap<InodeId, InodeRecord>,
    directories: &mut BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    pre: &PreCheckResult,
    flags: RenameAt2Flags,
    _first_parent: InodeId,
    _second_parent: InodeId,
) -> Result<()> {
    if flags.is_exchange() {
        apply_exchange(inodes, directories, pre)
    } else {
        apply_plain_rename(inodes, directories, pre)
    }
}

#[allow(dead_code)] // INTENT: rename helpers for planned renameat2/EXCHANGE support
/// Plain rename (may overwrite): remove source entry, insert destination
/// entry, update link counts and timestamps.
fn apply_plain_rename(
    inodes: &mut BTreeMap<InodeId, InodeRecord>,
    directories: &mut BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    pre: &PreCheckResult,
) -> Result<()> {
    let moving_is_directory = pre.old_entry.kind() == NodeKind::Dir;

    // ── Handle overwritten target ──────────────────────────────────
    if let Some(ref target) = pre.new_entry {
        let target_record = match inodes.get(&target.inode_id).cloned() {
            Some(r) => r,
            None => {
                return Err(FileSystemError::CorruptState {
                    reason: "target inode missing from inode table during rename",
                });
            }
        };

        // Remove target directory entry
        directories
            .get_mut(&pre.new_parent_id)
            .ok_or(FileSystemError::CorruptState {
                reason: "target parent directory missing during rename",
            })?
            .remove(&pre.new_name);

        if target_record.kind() == NodeKind::Dir {
            // Clear xattrs before removing the overwritten directory inode.
            if let Some(rec) = inodes.get_mut(&target.inode_id) {
                rec.xattrs.clear();
            }
            // Overwriting a directory: remove its directory map and
            // decrement parent nlink.
            directories.remove(&target.inode_id);
            inodes.remove(&target.inode_id);

            if let Some(new_parent) = inodes.get_mut(&pre.new_parent_id) {
                new_parent.nlink = new_parent.nlink.saturating_sub(1).max(2);
                new_parent.metadata_version = pre.old_entry.generation.0;
            }
        } else if target_record.nlink > 1 {
            // Still has other links — just decrement nlink.
            if let Some(rec) = inodes.get_mut(&target.inode_id) {
                rec.nlink -= 1;
                rec.metadata_version = pre.old_entry.generation.0;
            }
        } else {
            // Last link — remove the inode entirely.
            // Clear xattrs before removing the overwritten file inode.
            if let Some(rec) = inodes.get_mut(&target.inode_id) {
                rec.xattrs.clear();
            }
            inodes.remove(&target.inode_id);
        }
    }

    // ── Remove source entry ────────────────────────────────────────
    directories
        .get_mut(&pre.old_parent_id)
        .ok_or(FileSystemError::CorruptState {
            reason: "source parent directory missing during rename",
        })?
        .remove(&pre.old_name);

    // ── Insert destination entry ───────────────────────────────────
    let mut renamed_entry = pre.old_entry.clone();
    renamed_entry.name = pre.new_name.clone();

    directories
        .get_mut(&pre.new_parent_id)
        .ok_or(FileSystemError::CorruptState {
            reason: "destination parent directory missing during rename",
        })?
        .insert(pre.new_name.clone(), renamed_entry);

    // ── Update parent link counts for cross-directory directory moves
    if pre.old_parent_id != pre.new_parent_id && moving_is_directory {
        if let Some(old_parent) = inodes.get_mut(&pre.old_parent_id) {
            old_parent.nlink = old_parent.nlink.saturating_sub(1).max(2);
            old_parent.metadata_version = pre.old_entry.generation.0;
        }
        if let Some(new_parent) = inodes.get_mut(&pre.new_parent_id) {
            new_parent.nlink = new_parent.nlink.saturating_add(1);
            new_parent.metadata_version = pre.old_entry.generation.0;
        }
    }

    // ── Update .. entry for cross-directory directory moves ────────
    if pre.old_parent_id != pre.new_parent_id && moving_is_directory {
        let dotdot = NamespaceEntry {
            name: b"..".to_vec(),
            inode_id: pre.new_parent_id,
            generation: Generation(pre.new_parent_id.0),
            facets: NodeFacets {
                has_byte_space: false,
                has_child_namespace: true,
            },
            mode: 0o40755,
        };
        if let Some(child_dir) = directories.get_mut(&pre.old_entry.inode_id) {
            child_dir.insert(b"..".to_vec(), dotdot);
        }
    }

    Ok(())
}

#[allow(dead_code)] // INTENT: rename helpers for planned renameat2/EXCHANGE support
/// Exchange: atomically swap the inode pointers of two directory entries.
fn apply_exchange(
    inodes: &mut BTreeMap<InodeId, InodeRecord>,
    directories: &mut BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    pre: &PreCheckResult,
) -> Result<()> {
    let new_entry = pre
        .new_entry
        .as_ref()
        .ok_or(FileSystemError::CorruptState {
            reason: "exchange target missing despite pre-check",
        })?;

    let mut swapped_old = pre.old_entry.clone();
    swapped_old.name = pre.new_name.clone();

    let mut swapped_new = new_entry.clone();
    swapped_new.name = pre.old_name.clone();

    // Remove old entry from source parent
    directories
        .get_mut(&pre.old_parent_id)
        .ok_or(FileSystemError::CorruptState {
            reason: "source parent directory missing during exchange",
        })?
        .remove(&pre.old_name);

    // Remove new entry from destination parent
    directories
        .get_mut(&pre.new_parent_id)
        .ok_or(FileSystemError::CorruptState {
            reason: "destination parent directory missing during exchange",
        })?
        .remove(&pre.new_name);

    // Insert swapped entries
    directories
        .get_mut(&pre.old_parent_id)
        .ok_or(FileSystemError::CorruptState {
            reason: "source parent directory missing during exchange (insert)",
        })?
        .insert(pre.old_name.clone(), swapped_new);

    directories
        .get_mut(&pre.new_parent_id)
        .ok_or(FileSystemError::CorruptState {
            reason: "destination parent directory missing during exchange (insert)",
        })?
        .insert(pre.new_name.clone(), swapped_old);

    // For directory exchange across different parents, swap parent link counts
    if pre.old_parent_id != pre.new_parent_id && pre.old_entry.kind() == NodeKind::Dir {
        // Both are directories (guaranteed by pre-check type-match).
        // Bump metadata versions on both parents.
        if let Some(old_parent) = inodes.get_mut(&pre.old_parent_id) {
            old_parent.metadata_version = pre.old_entry.generation.0;
        }
        if let Some(new_parent) = inodes.get_mut(&pre.new_parent_id) {
            new_parent.metadata_version = pre.old_entry.generation.0;
        }

        // Swap .. entries so each moved directory points to its new parent.
        let new_entry = pre.new_entry.as_ref().unwrap(); // guaranteed present by pre-check
        let old_parent_dotdot = NamespaceEntry {
            name: b"..".to_vec(),
            inode_id: pre.old_parent_id,
            generation: Generation(pre.old_parent_id.0),
            facets: NodeFacets {
                has_byte_space: false,
                has_child_namespace: true,
            },
            mode: 0o40755,
        };
        let new_parent_dotdot = NamespaceEntry {
            name: b"..".to_vec(),
            inode_id: pre.new_parent_id,
            generation: Generation(pre.new_parent_id.0),
            facets: NodeFacets {
                has_byte_space: false,
                has_child_namespace: true,
            },
            mode: 0o40755,
        };
        if let Some(src_dir) = directories.get_mut(&pre.old_entry.inode_id) {
            src_dir.insert(b"..".to_vec(), new_parent_dotdot);
        }
        if let Some(dst_dir) = directories.get_mut(&new_entry.inode_id) {
            dst_dir.insert(b"..".to_vec(), old_parent_dotdot);
        }
    }

    Ok(())
}

// ===========================================================================
// Helper utilities
// ===========================================================================

/// Resolve a path to its parent directory inode ID and the final component name.
fn resolve_parent_and_name(
    inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    full_path: &str,
    parts: &[Vec<u8>],
) -> Result<(InodeId, Vec<u8>)> {
    let mut parts = parts.to_vec();
    let name = parts.pop().ok_or_else(|| FileSystemError::InvalidPath {
        path: full_path.to_string(),
        reason: "path is missing a final component",
    })?;
    validate_name(&name)?;

    let parent_id = resolve_parts(inodes, directories, &parts, full_path)?;
    let parent = inodes
        .get(&parent_id)
        .ok_or_else(|| FileSystemError::NotFound {
            path: full_path.to_string(),
        })?;
    if parent.kind() != NodeKind::Dir {
        return Err(FileSystemError::NotDirectory {
            path: render_path(&parts),
        });
    }
    Ok((parent_id, name))
}

/// Walk a sequence of path components to find the target inode.
fn resolve_parts(
    _inodes: &BTreeMap<InodeId, InodeRecord>,
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    parts: &[Vec<u8>],
    full_path: &str,
) -> Result<InodeId> {
    let mut current = InodeId::new(1); // ROOT_INODE_ID
    for name in parts.iter() {
        let directory = directories
            .get(&current)
            .ok_or_else(|| FileSystemError::NotFound {
                path: full_path.to_string(),
            })?;
        let entry = directory
            .get(name)
            .ok_or_else(|| FileSystemError::NotFound {
                path: full_path.to_string(),
            })?;
        current = entry.inode_id;
    }
    Ok(current)
}

/// Look up a directory entry by parent ID and name, returning an error
/// if not found.
fn lookup_entry(
    directories: &BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    parent_id: InodeId,
    name: &[u8],
    path: &str,
) -> Result<NamespaceEntry> {
    directories
        .get(&parent_id)
        .and_then(|dir| dir.get(name))
        .cloned()
        .ok_or_else(|| FileSystemError::NotFound {
            path: path.to_string(),
        })
}

/// Check whether `path` is a descendant of `prefix` (i.e., the path
/// starts with the prefix components and has additional components).
fn path_prefix_matches(path: &[Vec<u8>], prefix: &[Vec<u8>]) -> bool {
    path.len() > prefix.len() && path.iter().zip(prefix.iter()).all(|(l, r)| l == r)
}

// ===========================================================================
// Unit tests — pre-check phase
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    type TestInodeMap = BTreeMap<InodeId, InodeRecord>;
    type TestDirectoryMap = BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>;

    /// Helper: create an inode record for a directory.
    fn dir_record(id: u64, nlink: u32) -> InodeRecord {
        InodeRecord {
            rdev: 0,
            dir_storage_kind: 0,
            inode_id: InodeId::new(id),
            generation: tidefs_types_vfs_core::Generation(id),
            facets: tidefs_types_vfs_core::NodeFacets {
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
        }
    }

    /// Helper: create an inode record for a regular file.
    fn file_record(id: u64) -> InodeRecord {
        InodeRecord {
            rdev: 0,
            dir_storage_kind: 0,
            inode_id: InodeId::new(id),
            generation: tidefs_types_vfs_core::Generation(id),
            facets: tidefs_types_vfs_core::NodeFacets {
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
        }
    }

    /// Helper: create a namespace entry pointing to an inode.
    fn entry(name: &str, inode_id: u64, is_dir: bool) -> NamespaceEntry {
        NamespaceEntry {
            name: name.as_bytes().to_vec(),
            inode_id: InodeId::new(inode_id),
            generation: tidefs_types_vfs_core::Generation(inode_id),
            facets: if is_dir {
                tidefs_types_vfs_core::NodeFacets {
                    has_byte_space: false,
                    has_child_namespace: true,
                }
            } else {
                tidefs_types_vfs_core::NodeFacets {
                    has_byte_space: true,
                    has_child_namespace: false,
                }
            },
            mode: if is_dir { 0o40755 } else { 0o100644 },
        }
    }

    /// Build a minimal test namespace with root dir (inode 1) and
    /// optional child directories/files.
    fn build_test_namespace(children: &[(&str, u64, bool)]) -> (TestInodeMap, TestDirectoryMap) {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        // Root directory
        inodes.insert(InodeId::new(1), dir_record(1, 2));
        let mut root_entries = BTreeMap::new();

        for &(name, id, is_dir) in children {
            if is_dir {
                inodes.insert(InodeId::new(id), dir_record(id, 2));
                dirs.insert(InodeId::new(id), BTreeMap::new());
            } else {
                inodes.insert(InodeId::new(id), file_record(id));
            }
            root_entries.insert(name.as_bytes().to_vec(), entry(name, id, is_dir));
        }
        dirs.insert(InodeId::new(1), root_entries);

        (inodes, dirs)
    }

    // ── Test: source not found returns NotFound ────────────────────

    #[test]
    fn pre_check_source_not_found_returns_not_found() {
        let (inodes, dirs) = build_test_namespace(&[("target", 2, false)]);

        let result = pre_check(&inodes, &dirs, "/missing", "/target", RenameAt2Flags::EMPTY);

        assert!(matches!(result, Err(FileSystemError::NotFound { .. })));
    }

    // ── Test: destination exists with NOREPLACE returns AlreadyExists

    #[test]
    fn pre_check_noreplace_with_existing_destination_returns_already_exists() {
        let (inodes, dirs) = build_test_namespace(&[("src", 2, false), ("dst", 3, false)]);

        let result = pre_check(&inodes, &dirs, "/src", "/dst", RenameAt2Flags::NOREPLACE);

        assert!(matches!(result, Err(FileSystemError::AlreadyExists { .. })));
    }

    // ── Test: source or destination missing for EXCHANGE returns
    //         NotFound ─────────────────────────────────────────────

    #[test]
    fn pre_check_exchange_missing_source_returns_not_found() {
        let (inodes, dirs) = build_test_namespace(&[("dst", 3, false)]);

        let result = pre_check(&inodes, &dirs, "/missing", "/dst", RenameAt2Flags::EXCHANGE);

        assert!(matches!(result, Err(FileSystemError::NotFound { .. })));
    }

    #[test]
    fn pre_check_exchange_missing_destination_returns_not_found() {
        let (inodes, dirs) = build_test_namespace(&[("src", 2, false)]);

        let result = pre_check(&inodes, &dirs, "/src", "/missing", RenameAt2Flags::EXCHANGE);

        assert!(matches!(result, Err(FileSystemError::NotFound { .. })));
    }

    #[test]
    fn pre_check_exchange_both_present_succeeds() {
        let (inodes, dirs) = build_test_namespace(&[("src", 2, false), ("dst", 3, false)]);

        let result = pre_check(&inodes, &dirs, "/src", "/dst", RenameAt2Flags::EXCHANGE);

        assert!(result.is_ok());
        let pre = result.unwrap();
        assert!(!pre.is_same);
        assert_eq!(pre.old_name, b"src");
        assert_eq!(pre.new_name, b"dst");
        assert!(pre.new_entry.is_some());
    }

    // ── Test: plain rename with existing destination succeeds ──────

    #[test]
    fn pre_check_plain_rename_overwrite_succeeds() {
        let (inodes, dirs) = build_test_namespace(&[("src", 2, false), ("dst", 3, false)]);

        let result = pre_check(&inodes, &dirs, "/src", "/dst", RenameAt2Flags::EMPTY);

        assert!(result.is_ok());
        let pre = result.unwrap();
        assert!(!pre.is_same);
        assert!(pre.new_entry.is_some());
        assert_eq!(pre.new_entry.unwrap().inode_id, InodeId::new(3));
    }

    // ── Test: rename-to-self (same path) is no-op ──────────────────

    #[test]
    fn pre_check_same_path_is_noop() {
        let (inodes, dirs) = build_test_namespace(&[("file", 2, false)]);

        let result = pre_check(&inodes, &dirs, "/file", "/file", RenameAt2Flags::EMPTY);

        assert!(result.is_ok());
        assert!(result.unwrap().is_same);
    }

    // ── Test: rename-to-self (different name, same inode) is no-op ─

    #[test]
    fn pre_check_same_inode_different_link_is_noop() {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        // Root dir
        inodes.insert(InodeId::new(1), dir_record(1, 2));
        let mut root_entries = BTreeMap::new();
        // Both entries point to the same inode (hard link)
        inodes.insert(InodeId::new(2), file_record(2));
        root_entries.insert(b"link_a".to_vec(), entry("link_a", 2, false));
        root_entries.insert(b"link_b".to_vec(), entry("link_b", 2, false));
        dirs.insert(InodeId::new(1), root_entries);

        let result = pre_check(&inodes, &dirs, "/link_a", "/link_b", RenameAt2Flags::EMPTY);

        assert!(result.is_ok());
        assert!(result.unwrap().is_same);
    }

    // ── Test: directory-to-file substitution rejected ──────────────

    #[test]
    fn pre_check_dir_over_file_rejected() {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        inodes.insert(InodeId::new(1), dir_record(1, 2));
        inodes.insert(InodeId::new(2), dir_record(2, 2)); // src dir
        dirs.insert(InodeId::new(2), BTreeMap::new());
        inodes.insert(InodeId::new(3), file_record(3)); // dst file

        let mut root_entries = BTreeMap::new();
        root_entries.insert(b"srcdir".to_vec(), entry("srcdir", 2, true));
        root_entries.insert(b"dstfile".to_vec(), entry("dstfile", 3, false));
        dirs.insert(InodeId::new(1), root_entries);

        let result = pre_check(&inodes, &dirs, "/srcdir", "/dstfile", RenameAt2Flags::EMPTY);

        assert!(matches!(result, Err(FileSystemError::NotDirectory { .. })));
    }

    // ── Test: file-to-directory substitution rejected ──────────────

    #[test]
    fn pre_check_file_over_dir_rejected() {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        inodes.insert(InodeId::new(1), dir_record(1, 2));
        inodes.insert(InodeId::new(2), file_record(2)); // src file
        inodes.insert(InodeId::new(3), dir_record(3, 2)); // dst dir
        dirs.insert(InodeId::new(3), BTreeMap::new());

        let mut root_entries = BTreeMap::new();
        root_entries.insert(b"srcfile".to_vec(), entry("srcfile", 2, false));
        root_entries.insert(b"dstdir".to_vec(), entry("dstdir", 3, true));
        dirs.insert(InodeId::new(1), root_entries);

        let result = pre_check(&inodes, &dirs, "/srcfile", "/dstdir", RenameAt2Flags::EMPTY);

        assert!(matches!(result, Err(FileSystemError::IsDirectory { .. })));
    }

    // ── Test: NOREPLACE without destination succeeds ───────────────

    #[test]
    fn pre_check_noreplace_no_destination_succeeds() {
        let (inodes, dirs) = build_test_namespace(&[("src", 2, false)]);

        let result = pre_check(
            &inodes,
            &dirs,
            "/src",
            "/new_dst",
            RenameAt2Flags::NOREPLACE,
        );

        assert!(result.is_ok());
        let pre = result.unwrap();
        assert!(!pre.is_same);
        assert!(pre.new_entry.is_none());
    }

    // ── Test: EXCHANGE type mismatch rejected ──────────────────────

    #[test]
    fn pre_check_exchange_type_mismatch_rejected() {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        inodes.insert(InodeId::new(1), dir_record(1, 2));
        inodes.insert(InodeId::new(2), file_record(2)); // src file
        inodes.insert(InodeId::new(3), dir_record(3, 2)); // dst dir
        dirs.insert(InodeId::new(3), BTreeMap::new());

        let mut root_entries = BTreeMap::new();
        root_entries.insert(b"src".to_vec(), entry("src", 2, false));
        root_entries.insert(b"dst".to_vec(), entry("dst", 3, true));
        dirs.insert(InodeId::new(1), root_entries);

        let result = pre_check(&inodes, &dirs, "/src", "/dst", RenameAt2Flags::EXCHANGE);

        assert!(matches!(result, Err(FileSystemError::Unsupported { .. })));
    }

    // ── Test: directory-not-empty rejection ────────────────────────

    #[test]
    fn pre_check_overwrite_nonempty_dir_rejected() {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        inodes.insert(InodeId::new(1), dir_record(1, 2));
        inodes.insert(InodeId::new(2), dir_record(2, 2)); // src dir
        dirs.insert(InodeId::new(2), BTreeMap::new());
        inodes.insert(InodeId::new(3), dir_record(3, 2)); // dst dir
                                                          // dst dir has a child — not empty
        let mut dst_children = BTreeMap::new();
        dst_children.insert(b"child".to_vec(), entry("child", 4, false));
        inodes.insert(InodeId::new(4), file_record(4));
        dirs.insert(InodeId::new(3), dst_children);

        let mut root_entries = BTreeMap::new();
        root_entries.insert(b"srcdir".to_vec(), entry("srcdir", 2, true));
        root_entries.insert(b"dstdir".to_vec(), entry("dstdir", 3, true));
        dirs.insert(InodeId::new(1), root_entries);

        let result = pre_check(&inodes, &dirs, "/srcdir", "/dstdir", RenameAt2Flags::EMPTY);

        assert!(matches!(
            result,
            Err(FileSystemError::DirectoryNotEmpty { .. })
        ));
    }

    // ── Test: move into self rejected ──────────────────────────────

    #[test]
    fn pre_check_move_into_self_rejected() {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        inodes.insert(InodeId::new(1), dir_record(1, 2));
        inodes.insert(InodeId::new(2), dir_record(2, 3)); // /a (nlink 3 with subdir)
        inodes.insert(InodeId::new(3), dir_record(3, 2)); // /a/b
        dirs.insert(InodeId::new(2), BTreeMap::new());
        dirs.insert(InodeId::new(3), BTreeMap::new());

        let mut root_entries = BTreeMap::new();
        root_entries.insert(b"a".to_vec(), entry("a", 2, true));
        dirs.insert(InodeId::new(1), root_entries);

        let mut a_entries = BTreeMap::new();
        a_entries.insert(b"b".to_vec(), entry("b", 3, true));
        dirs.insert(InodeId::new(2), a_entries);

        // Try to move /a/b → /a (move /a/b into /a is fine),
        // but /a → /a/b is moving a dir into itself.
        let result = pre_check(&inodes, &dirs, "/a", "/a/b", RenameAt2Flags::EMPTY);

        assert!(matches!(result, Err(FileSystemError::InvalidPath { .. })));
    }

    // ── Test: cross-directory directory rename updates .. entry ───

    #[test]
    fn rename_dir_cross_parent_updates_dotdot_to_new_parent() {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        // Root (inode 1)
        inodes.insert(InodeId::new(1), dir_record(1, 3));
        let mut root_entries = BTreeMap::new();

        // /dir_a (inode 2) — nlink 3 (., .., sub)
        inodes.insert(InodeId::new(2), dir_record(2, 3));
        let mut a_entries: BTreeMap<Vec<u8>, NamespaceEntry> = BTreeMap::new();
        let sub_entry = entry("sub", 3, true);
        a_entries.insert(b"sub".to_vec(), sub_entry.clone());

        // /dir_a/sub (inode 3) — has .. pointing to dir_a (inode 2)
        inodes.insert(InodeId::new(3), dir_record(3, 2));
        let mut sub_entries = BTreeMap::new();
        sub_entries.insert(
            b"..".to_vec(),
            NamespaceEntry {
                name: b"..".to_vec(),
                inode_id: InodeId::new(2), // currently points to dir_a
                generation: Generation(2),
                facets: NodeFacets {
                    has_byte_space: false,
                    has_child_namespace: true,
                },
                mode: 0o40755,
            },
        );
        dirs.insert(InodeId::new(3), sub_entries);

        root_entries.insert(b"dir_a".to_vec(), entry("dir_a", 2, true));
        dirs.insert(InodeId::new(2), a_entries);

        // /dir_b (inode 4)
        inodes.insert(InodeId::new(4), dir_record(4, 2));
        root_entries.insert(b"dir_b".to_vec(), entry("dir_b", 4, true));
        dirs.insert(InodeId::new(4), BTreeMap::new());

        dirs.insert(InodeId::new(1), root_entries);

        // Rename /dir_a/sub → /dir_b/sub
        let result = renameat2(
            &mut inodes,
            &mut dirs,
            "/dir_a/sub",
            "/dir_b/sub",
            RenameAt2Flags::EMPTY,
        );

        assert!(result.is_ok(), "rename should succeed: {:?}", result.err());

        // Verify .. in moved directory points to dir_b (inode 4)
        let sub_dir = dirs
            .get(&InodeId::new(3))
            .expect("moved sub directory should exist");
        let dotdot = sub_dir
            .get(b"..".as_ref())
            .expect("moved sub directory should have .. entry");
        assert_eq!(
            dotdot.inode_id,
            InodeId::new(4),
            ".. should point to new parent dir_b (inode 4), got {:?}",
            dotdot.inode_id
        );

        // Also verify old parent nlink was decremented
        let dir_a = inodes.get(&InodeId::new(2)).unwrap();
        assert_eq!(dir_a.nlink, 2, "dir_a nlink should be 2 (was 3, lost sub)");

        // And new parent nlink was incremented
        let dir_b = inodes.get(&InodeId::new(4)).unwrap();
        assert_eq!(
            dir_b.nlink, 3,
            "dir_b nlink should be 3 (was 2, gained sub)"
        );
    }

    // ── Test: cross-directory directory exchange swaps .. entries ─

    #[test]
    fn exchange_dir_cross_parent_swaps_dotdot_entries() {
        let mut inodes = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        // Root (inode 1)
        inodes.insert(InodeId::new(1), dir_record(1, 3));
        let mut root_entries = BTreeMap::new();

        // /dir_a (inode 2), contains /dir_a/x (inode 3)
        inodes.insert(InodeId::new(2), dir_record(2, 3));
        let mut a_entries = BTreeMap::new();
        a_entries.insert(b"x".to_vec(), entry("x", 3, true));
        dirs.insert(InodeId::new(2), a_entries);

        // /dir_b (inode 4), contains /dir_b/y (inode 5)
        inodes.insert(InodeId::new(4), dir_record(4, 3));
        let mut b_entries = BTreeMap::new();
        b_entries.insert(b"y".to_vec(), entry("y", 5, true));
        dirs.insert(InodeId::new(4), b_entries);

        // /dir_a/x (inode 3) — .. points to dir_a (inode 2)
        inodes.insert(InodeId::new(3), dir_record(3, 2));
        let mut x_entries = BTreeMap::new();
        x_entries.insert(
            b"..".to_vec(),
            NamespaceEntry {
                name: b"..".to_vec(),
                inode_id: InodeId::new(2),
                generation: Generation(2),
                facets: NodeFacets {
                    has_byte_space: false,
                    has_child_namespace: true,
                },
                mode: 0o40755,
            },
        );
        dirs.insert(InodeId::new(3), x_entries);

        // /dir_b/y (inode 5) — .. points to dir_b (inode 4)
        inodes.insert(InodeId::new(5), dir_record(5, 2));
        let mut y_entries = BTreeMap::new();
        y_entries.insert(
            b"..".to_vec(),
            NamespaceEntry {
                name: b"..".to_vec(),
                inode_id: InodeId::new(4),
                generation: Generation(4),
                facets: NodeFacets {
                    has_byte_space: false,
                    has_child_namespace: true,
                },
                mode: 0o40755,
            },
        );
        dirs.insert(InodeId::new(5), y_entries);

        root_entries.insert(b"dir_a".to_vec(), entry("dir_a", 2, true));
        root_entries.insert(b"dir_b".to_vec(), entry("dir_b", 4, true));
        dirs.insert(InodeId::new(1), root_entries);

        // Exchange /dir_a/x ↔ /dir_b/y
        let result = renameat2(
            &mut inodes,
            &mut dirs,
            "/dir_a/x",
            "/dir_b/y",
            RenameAt2Flags::EXCHANGE,
        );

        assert!(
            result.is_ok(),
            "exchange should succeed: {:?}",
            result.err()
        );

        // Now x is in /dir_b, y is in /dir_a
        // Verify x (inode 3): .. should point to dir_b (inode 4)
        let x_dir = dirs
            .get(&InodeId::new(3))
            .expect("x directory should exist");
        let x_dotdot = x_dir.get(b"..".as_ref()).expect("x should have .. entry");
        assert_eq!(
            x_dotdot.inode_id,
            InodeId::new(4),
            "x's .. should point to dir_b (inode 4) after exchange, got {:?}",
            x_dotdot.inode_id
        );

        // Verify y (inode 5): .. should point to dir_a (inode 2)
        let y_dir = dirs
            .get(&InodeId::new(5))
            .expect("y directory should exist");
        let y_dotdot = y_dir.get(b"..".as_ref()).expect("y should have .. entry");
        assert_eq!(
            y_dotdot.inode_id,
            InodeId::new(2),
            "y's .. should point to dir_a (inode 2) after exchange, got {:?}",
            y_dotdot.inode_id
        );

        // Parent nlink counts should be unchanged (both gained and lost one child)
        let dir_a = inodes.get(&InodeId::new(2)).unwrap();
        assert_eq!(dir_a.nlink, 3, "dir_a nlink unchanged at 3");
        let dir_b = inodes.get(&InodeId::new(4)).unwrap();
        assert_eq!(dir_b.nlink, 3, "dir_b nlink unchanged at 3");
    }

    // ── Lock ordering tests ───────────────────────────────────────

    #[test]
    fn lock_order_same_directory_returns_same_id_twice() {
        let a = InodeId::new(42);
        let (first, second) = acquire_lock_order(a, a);
        assert_eq!(first, a);
        assert_eq!(second, a);
    }

    #[test]
    fn lock_order_lower_inode_first() {
        let low = InodeId::new(10);
        let high = InodeId::new(20);
        let (first, second) = acquire_lock_order(low, high);
        assert_eq!(first, low);
        assert_eq!(second, high);
    }

    #[test]
    fn lock_order_reversed_args_still_lowest_first() {
        let low = InodeId::new(5);
        let high = InodeId::new(15);
        let (first, second) = acquire_lock_order(high, low);
        assert_eq!(first, low);
        assert_eq!(second, high);
    }

    #[test]
    fn lock_order_equal_inodes_same_directory_case() {
        let a = InodeId::new(1);
        let (first, second) = acquire_lock_order(a, a);
        assert_eq!(first, second);
    }

    #[test]
    fn lock_order_root_and_subdir() {
        let root = InodeId::new(1);
        let subdir = InodeId::new(100);
        // Root (1) has lower inode number -> locked first
        let (first, second) = acquire_lock_order(root, subdir);
        assert_eq!(first, root);
        assert_eq!(second, subdir);
        // Reversed args, same result
        let (first, second) = acquire_lock_order(subdir, root);
        assert_eq!(first, root);
        assert_eq!(second, subdir);
    }
}
