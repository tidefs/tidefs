// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mount-time orphan cleanup triggered during LocalFileSystem::open recovery.
//!
//! After intent log replay, inodes that reached nlink==0 before an unclean
//! shutdown remain in the persistent orphan index. `cleanup_orphans` removes
//! their namespace, inode, and extent-map state, then removes the orphan index
//! entry. The mounted caller queues exact content keys separately through
//! strict Pool authority before invoking this metadata cleanup.
//!
//! ## Design
//!
//! - Runs synchronously at mount, before background services start.
//! - Iterates all orphan index entries (O(orphans), not O(total inodes)).
//! - Handles both the normal case (inode removed from inode table) and the
//!   recovery case (inode still present with nlink==0 after intent log
//!   replay).
//! - Complements the incremental `BackgroundOrphanReclamation` service which
//!   handles runtime orphans under per-tick budget.
//!
use std::sync::{Arc, Mutex};

use tidefs_orphan_index::OrphanIndex;
use tidefs_types_vfs_core::InodeId;

use crate::Result;

/// Statistics from a mount-time orphan cleanup pass.
#[derive(Clone, Debug, Default)]
pub(crate) struct OrphanCleanupStats {
    /// Total orphaned inodes found in the index before cleanup.
    pub orphans_found: usize,
    /// Inodes successfully cleaned and removed from the index.
    pub orphans_cleaned: usize,
    /// Inodes that were still present in the inode table (nlink==0)
    /// and were removed during cleanup.
    pub inodes_removed_from_state: usize,
    /// Stale directory entries removed (entries pointing to orphaned inodes).
    pub directory_entries_removed: usize,
    /// Extent maps freed.
    pub extent_maps_freed: usize,
    /// Exact content/inode reclaim entries queued by the mounted caller before
    /// metadata cleanup. This module never scans or deletes mounted content.
    pub reclaim_entries_queued: usize,
}

impl OrphanCleanupStats {
    /// Return `true` when no orphans were found and no work was done.
    #[must_use]
    #[allow(dead_code)] // INTENT: orphan cleanup stats helper for planned inode cleanup
    pub fn is_idle(&self) -> bool {
        self.orphans_found == 0
    }
}

/// Synchronously clean up all orphaned inodes in the persistent orphan index.
///
/// Called from `LocalFileSystem::open` after intent log replay and before
/// background services start.  For each orphaned inode:
///
/// 1. If the inode still exists in the inode table with nlink > 0, treat only
///    the orphan-index entry as stale. The committed inode and namespace own
///    reachability; this index is a reconstructible cleanup accelerator.
/// 2. If the inode still exists in the inode table with nlink==0, remove it.
/// 3. Scan all directories for stale entries pointing to this inode and
///    remove them.
/// 4. Free the extent map if present.
/// 5. Remove the orphan index entry.
///
/// Inodes with nlink > 0 that appear in the orphan index are inconsistent.
/// Cleanup leaves the committed inode and namespace untouched and removes only
/// the stale index entry. An auxiliary index must never overrule a committed
/// live inode and delete reachable data.
pub(crate) fn cleanup_orphans(
    state: &mut crate::FileSystemState,
    orphan_index: &Arc<Mutex<OrphanIndex>>,
) -> Result<OrphanCleanupStats> {
    let mut stats = OrphanCleanupStats::default();

    let orphan_ids: Vec<u64> = {
        let idx = orphan_index.lock().unwrap();
        idx.collect_inode_ids()
    };

    stats.orphans_found = orphan_ids.len();
    if orphan_ids.is_empty() {
        return Ok(stats);
    }

    eprintln!(
        "orphan-cleanup: found {} orphaned inode(s); reclaiming",
        orphan_ids.len()
    );

    for &inode_id_raw in &orphan_ids {
        let inode_id = InodeId(inode_id_raw);

        // 1. If the inode still exists in the inode table, handle it.
        //    Normal path: nlink==0 on an inode that should have been
        //    removed. The mounted caller already queued exact content and
        //    inode keys through Pool authority; remove only metadata here.
        if let Some(record) = state.inodes.get(&inode_id) {
            if record.nlink == 0 {
                let was_directory = record.carries_child_namespace();

                Arc::make_mut(&mut state.inodes).remove(&inode_id);
                state.last_inode_write_tx.remove(&inode_id);
                state.last_dir_write_tx.remove(&inode_id);
                state.last_extent_map_write_tx.remove(&inode_id);
                state.known_inode_ids.remove(&inode_id);
                state.dirty_inodes.insert(inode_id);
                if was_directory {
                    Arc::make_mut(&mut state.directories).remove(&inode_id);
                    state.dirty_dirs.remove(&inode_id);
                }
                stats.inodes_removed_from_state += 1;
            } else {
                // A live committed inode always wins over a stale derivative
                // orphan marker, whether or not a directory entry is visible.
                orphan_index.lock().unwrap().remove(inode_id_raw);
                stats.orphans_cleaned += 1;
                continue;
            }
        }

        // 2. Remove any stale directory entries pointing to this inode.
        //    Collect directory IDs first to avoid borrow issues.
        let dir_ids: Vec<InodeId> = state.directories.keys().copied().collect();
        for dir_id in dir_ids {
            let dirs = Arc::make_mut(&mut state.directories);
            if let Some(dir) = dirs.get_mut(&dir_id) {
                let stale_names: Vec<Vec<u8>> = dir
                    .iter()
                    .filter(|(_, entry)| entry.inode_id == inode_id)
                    .map(|(name, _)| name.clone())
                    .collect();
                for name in &stale_names {
                    dir.remove(name);
                    stats.directory_entries_removed += 1;
                }
                if !stale_names.is_empty() {
                    state.dirty_dirs.insert(dir_id);
                    // Update parent directory size.
                    if let Some(parent_inode) = Arc::make_mut(&mut state.inodes).get_mut(&dir_id) {
                        parent_inode.size = dir.len() as u64;
                        state.dirty_inodes.insert(dir_id);
                    }
                }
            }
            let _ = dirs;
        }

        // 3. Remove extent map if present.
        if state
            .extent_maps
            .lock()
            .unwrap()
            .remove(&inode_id)
            .is_some()
        {
            stats.extent_maps_freed += 1;
            state.dirty_inodes.insert(inode_id);
        }
        state.dirty_extent_maps.remove(&inode_id);

        // 4. Remove the orphan index entry. Content remains owned by the
        // mounted queue until retained-root and receipt preflight authorizes
        // logical Pool deletion.
        orphan_index.lock().unwrap().remove(inode_id_raw);
        stats.orphans_cleaned += 1;
    }

    if stats.inodes_removed_from_state > 0 || stats.directory_entries_removed > 0 {
        reconcile_directory_topology(state);
    }

    eprintln!(
        "orphan-cleanup: reconciled {} orphans ({} state inodes, {} dir \
         entries, {} extent maps)",
        stats.orphans_cleaned,
        stats.inodes_removed_from_state,
        stats.directory_entries_removed,
        stats.extent_maps_freed,
    );

    Ok(stats)
}

fn reconcile_directory_topology(state: &mut crate::FileSystemState) {
    let updates: Vec<(InodeId, u64, u32)> = state
        .directories
        .iter()
        .map(|(dir_id, entries)| {
            let child_directories = entries
                .values()
                .filter(|entry| entry.carries_child_namespace())
                .count() as u64;
            let nlink = 2_u64.saturating_add(child_directories);
            (
                *dir_id,
                entries.len() as u64,
                nlink.min(u32::MAX as u64) as u32,
            )
        })
        .collect();
    let inodes = Arc::make_mut(&mut state.inodes);
    for (dir_id, size, nlink) in updates {
        if let Some(inode) = inodes.get_mut(&dir_id) {
            if inode.carries_child_namespace() {
                inode.size = size;
                inode.nlink = nlink;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc as StdArc;

    use tidefs_orphan_index::OrphanIndex;
    use tidefs_types_vfs_core::{Generation, InodeId, NodeKind, ROOT_INODE_ID};

    use crate::types::{ContentCompressionPolicy, InodeRecord, NamespaceEntry};
    use crate::{DatasetInodeAuthority, FileSystemState, ROOT_DATASET_ID};

    fn make_cleanup_state() -> FileSystemState {
        let inode_authority = DatasetInodeAuthority::fresh_root(ROOT_DATASET_ID);
        let root_inode_id = inode_authority.root_inode_id();
        let root = InodeRecord {
            rdev: 0,
            inode_id: root_inode_id,
            generation: Generation::new(1),
            facets: NodeKind::Dir.to_facets(),
            mode: 0o755,
            uid: 0,
            gid: 0,
            nlink: 2,
            size: 0,
            data_version: 1,
            metadata_version: 1,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs: BTreeMap::new(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
            subtree_rev: 0,
        };
        let mut inodes = BTreeMap::new();
        inodes.insert(root_inode_id, root);
        let mut directories = BTreeMap::new();
        directories.insert(root_inode_id, BTreeMap::new());
        FileSystemState {
            inode_authority,
            generation: 1,
            inodes: StdArc::new(inodes),
            directories: StdArc::new(directories),
            snapshots: BTreeMap::new(),
            dirty_content: Default::default(),
            dirty_inodes: Default::default(),
            dirty_dirs: Default::default(),
            quota_table: Default::default(),
            space_accounting: Default::default(),
            last_inode_write_tx: BTreeMap::new(),
            last_dir_write_tx: BTreeMap::new(),
            known_inode_ids: {
                let mut ids = std::collections::BTreeSet::new();
                ids.insert(root_inode_id);
                ids
            },
            corrupted_inodes: Default::default(),
            change_streams: BTreeMap::new(),
            extent_maps: Arc::new(Mutex::new(BTreeMap::new())),
            dirty_extent_maps: Default::default(),
            last_extent_map_write_tx: BTreeMap::new(),
            content_compression_policy: ContentCompressionPolicy::default(),
        }
    }

    // ── basic unit tests ────────────────────────────────────────────

    #[test]
    fn empty_orphan_index_returns_idle() {
        let mut state = make_cleanup_state();
        let orphan_index = Arc::new(Mutex::new(OrphanIndex::new()));

        let stats = cleanup_orphans(&mut state, &orphan_index)
            .expect("cleanup should succeed on empty index");

        assert!(stats.is_idle());
        assert_eq!(stats.orphans_found, 0);
        assert_eq!(stats.orphans_cleaned, 0);
    }

    #[test]
    fn orphan_not_in_state_is_cleaned() {
        let mut state = make_cleanup_state();
        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            idx.insert(999);
            idx
        }));
        let stats = cleanup_orphans(&mut state, &orphan_index).expect("cleanup should succeed");

        assert_eq!(stats.orphans_found, 1);
        assert_eq!(stats.orphans_cleaned, 1);
        assert_eq!(stats.inodes_removed_from_state, 0);
        assert!(orphan_index.lock().unwrap().is_empty());
    }

    #[test]
    fn orphan_still_in_state_with_nlink_zero_is_removed() {
        let mut state = make_cleanup_state();
        let orphan_inode_id = InodeId::new(42);
        let orphan_inode = InodeRecord {
            rdev: 0,
            inode_id: orphan_inode_id,
            generation: Generation::new(10),
            facets: NodeKind::File.to_facets(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            nlink: 0,
            size: 4096,
            data_version: 5,
            metadata_version: 5,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs: BTreeMap::new(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
            subtree_rev: 0,
        };
        Arc::make_mut(&mut state.inodes).insert(orphan_inode_id, orphan_inode);
        state.observe_explicit_inode_id(orphan_inode_id);

        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            idx.insert(42);
            idx
        }));
        let stats = cleanup_orphans(&mut state, &orphan_index).expect("cleanup should succeed");

        assert_eq!(stats.orphans_found, 1);
        assert_eq!(stats.orphans_cleaned, 1);
        assert_eq!(stats.inodes_removed_from_state, 1);
        assert!(orphan_index.lock().unwrap().is_empty());
        assert!(!state.inodes.contains_key(&orphan_inode_id));
    }

    #[test]
    fn stale_orphan_marker_does_not_delete_linked_inode() {
        let mut state = make_cleanup_state();
        let orphan_inode_id = InodeId::new(77);
        let orphan_inode = InodeRecord {
            rdev: 0,
            inode_id: orphan_inode_id,
            generation: Generation::new(10),
            facets: NodeKind::File.to_facets(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            nlink: 1,
            size: 1024,
            data_version: 3,
            metadata_version: 3,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs: BTreeMap::new(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
            subtree_rev: 0,
        };
        Arc::make_mut(&mut state.inodes).insert(orphan_inode_id, orphan_inode);
        state.observe_explicit_inode_id(orphan_inode_id);
        Arc::make_mut(&mut state.directories)
            .get_mut(&ROOT_INODE_ID)
            .unwrap()
            .insert(
                b"linked.txt".to_vec(),
                NamespaceEntry {
                    name: b"linked.txt".to_vec(),
                    inode_id: orphan_inode_id,
                    generation: Generation::new(10),
                    facets: NodeKind::File.to_facets(),
                    mode: 0o644,
                },
            );

        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            idx.insert(77);
            idx
        }));
        let stats = cleanup_orphans(&mut state, &orphan_index).expect("cleanup should succeed");

        assert_eq!(stats.orphans_found, 1);
        assert_eq!(stats.orphans_cleaned, 1);
        assert_eq!(stats.inodes_removed_from_state, 0);
        assert_eq!(stats.directory_entries_removed, 0);
        assert!(state.inodes.contains_key(&orphan_inode_id));
        let root_dir = state.directories.get(&ROOT_INODE_ID).unwrap();
        assert_eq!(
            root_dir
                .get(b"linked.txt".as_slice())
                .expect("linked entry must survive stale orphan marker")
                .inode_id,
            orphan_inode_id
        );
        assert!(orphan_index.lock().unwrap().is_empty());
    }

    #[test]
    fn stale_orphan_marker_does_not_delete_linked_directory() {
        let mut state = make_cleanup_state();
        let orphan_inode_id = InodeId::new(88);
        let orphan_inode = InodeRecord {
            rdev: 0,
            inode_id: orphan_inode_id,
            generation: Generation::new(12),
            facets: NodeKind::Dir.to_facets(),
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            nlink: 2,
            size: 0,
            data_version: 4,
            metadata_version: 4,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs: BTreeMap::new(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
            subtree_rev: 0,
        };
        Arc::make_mut(&mut state.inodes)
            .get_mut(&ROOT_INODE_ID)
            .unwrap()
            .nlink = 3;
        Arc::make_mut(&mut state.inodes).insert(orphan_inode_id, orphan_inode);
        state.observe_explicit_inode_id(orphan_inode_id);
        Arc::make_mut(&mut state.directories).insert(orphan_inode_id, BTreeMap::new());
        Arc::make_mut(&mut state.directories)
            .get_mut(&ROOT_INODE_ID)
            .unwrap()
            .insert(
                b"stale-dir".to_vec(),
                NamespaceEntry {
                    name: b"stale-dir".to_vec(),
                    inode_id: orphan_inode_id,
                    generation: Generation::new(12),
                    facets: NodeKind::Dir.to_facets(),
                    mode: 0o755,
                },
            );

        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            idx.insert(88);
            idx
        }));
        let stats = cleanup_orphans(&mut state, &orphan_index).expect("cleanup should succeed");

        assert_eq!(stats.inodes_removed_from_state, 0);
        assert_eq!(stats.directory_entries_removed, 0);
        assert!(state.inodes.contains_key(&orphan_inode_id));
        assert!(state.directories.contains_key(&orphan_inode_id));
        let root = state.inodes.get(&ROOT_INODE_ID).unwrap();
        assert_eq!(root.nlink, 3);
        assert_eq!(
            state.directories[&ROOT_INODE_ID]
                .get(b"stale-dir".as_slice())
                .expect("linked directory must survive stale orphan marker")
                .inode_id,
            orphan_inode_id
        );
        assert!(orphan_index.lock().unwrap().is_empty());
    }

    #[test]
    fn orphan_with_nlink_positive_without_directory_entry_is_left_alone() {
        let mut state = make_cleanup_state();
        let orphan_inode_id = InodeId::new(78);
        let orphan_inode = InodeRecord {
            rdev: 0,
            inode_id: orphan_inode_id,
            generation: Generation::new(11),
            facets: NodeKind::File.to_facets(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            nlink: 1,
            size: 1024,
            data_version: 3,
            metadata_version: 3,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs: BTreeMap::new(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
            subtree_rev: 0,
        };
        Arc::make_mut(&mut state.inodes).insert(orphan_inode_id, orphan_inode);
        state.observe_explicit_inode_id(orphan_inode_id);

        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            idx.insert(78);
            idx
        }));
        let stats = cleanup_orphans(&mut state, &orphan_index).expect("cleanup should succeed");

        assert_eq!(stats.orphans_found, 1);
        assert_eq!(stats.orphans_cleaned, 1);
        assert_eq!(stats.inodes_removed_from_state, 0);
        assert_eq!(stats.directory_entries_removed, 0);
        assert!(state.inodes.contains_key(&orphan_inode_id));
        assert!(orphan_index.lock().unwrap().is_empty());
    }

    #[test]
    fn stale_directory_entries_are_removed() {
        let mut state = make_cleanup_state();
        let orphan_inode_id = InodeId::new(55);

        // Insert a stale dir entry in root.
        Arc::make_mut(&mut state.directories)
            .get_mut(&ROOT_INODE_ID)
            .unwrap()
            .insert(
                b"stale.txt".to_vec(),
                NamespaceEntry {
                    name: b"stale.txt".to_vec(),
                    inode_id: orphan_inode_id,
                    generation: Generation::new(1),
                    facets: NodeKind::File.to_facets(),
                    mode: 0o644,
                },
            );

        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            idx.insert(55);
            idx
        }));
        let stats = cleanup_orphans(&mut state, &orphan_index).expect("cleanup should succeed");

        assert_eq!(stats.directory_entries_removed, 1);
        assert!(orphan_index.lock().unwrap().is_empty());
        // Verify the stale entry is gone.
        let root_dir = state.directories.get(&ROOT_INODE_ID).unwrap();
        assert!(!root_dir.contains_key(b"stale.txt".as_slice()));
    }

    #[test]
    fn extent_map_is_freed() {
        let mut state = make_cleanup_state();
        let orphan_inode_id = InodeId::new(33);

        let emap = tidefs_extent_map::ExtentMap::new();
        state
            .extent_maps
            .lock()
            .unwrap()
            .insert(orphan_inode_id, emap);
        state.dirty_extent_maps.insert(orphan_inode_id);

        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            idx.insert(33);
            idx
        }));
        let stats = cleanup_orphans(&mut state, &orphan_index).expect("cleanup should succeed");

        assert_eq!(stats.extent_maps_freed, 1);
        assert!(!state
            .extent_maps
            .lock()
            .unwrap()
            .contains_key(&orphan_inode_id));
        assert!(!state.dirty_extent_maps.contains(&orphan_inode_id));
    }

    #[test]
    fn multiple_orphans_all_cleaned() {
        let mut state = make_cleanup_state();
        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            for i in 1..=50u64 {
                idx.insert(i);
            }
            idx
        }));
        let stats = cleanup_orphans(&mut state, &orphan_index).expect("cleanup should succeed");

        assert_eq!(stats.orphans_found, 50);
        assert_eq!(stats.orphans_cleaned, 50);
        assert!(orphan_index.lock().unwrap().is_empty());
    }

    #[test]
    fn cleanup_is_idempotent() {
        let mut state = make_cleanup_state();
        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            idx.insert(1);
            idx.insert(2);
            idx
        }));
        let stats1 = cleanup_orphans(&mut state, &orphan_index).expect("first cleanup");
        assert_eq!(stats1.orphans_cleaned, 2);

        let stats2 = cleanup_orphans(&mut state, &orphan_index).expect("second cleanup");
        assert!(stats2.is_idle());
        assert_eq!(stats2.orphans_cleaned, 0);
    }

    #[test]
    fn metadata_cleanup_does_not_delete_raw_content() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let mut store =
            tidefs_local_object_store::LocalObjectStore::open(tmp.path()).expect("open store");
        let mut state = make_cleanup_state();
        let inode_id = InodeId::new(42);

        // Raw content is not an orphan-cleanup authority. The mounted caller
        // queues exact keys separately after strict Pool receipt validation.
        let content_key = crate::object_keys::content_object_key_for_version(inode_id, 1);
        store
            .put(content_key, b"test content")
            .expect("put content");
        store.sync_all().expect("sync");

        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            idx.insert(42);
            idx
        }));
        let stats = cleanup_orphans(&mut state, &orphan_index).expect("cleanup should succeed");

        assert_eq!(stats.reclaim_entries_queued, 0);
        assert!(orphan_index.lock().unwrap().is_empty());

        let found = store.get(content_key).expect("get after cleanup");
        assert_eq!(
            found,
            Some(b"test content".to_vec()),
            "metadata cleanup must not inspect or delete raw mounted content"
        );
    }
}
