// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mount-time orphan cleanup triggered during LocalFileSystem::open recovery.
//!
//! After intent log replay, inodes that reached nlink==0 before an unclean
//! shutdown remain in the persistent orphan index. `cleanup_orphans` reclaims
//! their content objects, extent maps, directory entries, and block allocator
//! space, then removes the orphan index entry.
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
//! ## Comparison to ZFS / Ceph
//!
//! - **ZFS**: `zfs_unlinked_drain()` blocks mount, restarts from scratch on
//!   crash, limited to ~100K entries.
//! - **CephFS**: relies on full-dataset scrub after MDS journal replay.
//! - **TideFS**: O(orphans) synchronous cleanup at mount with cursor-based
//!   resumption and per-tick background budget.

use std::sync::{Arc, Mutex};

use tidefs_local_object_store::LocalObjectStore;
use tidefs_orphan_index::OrphanIndex;
use tidefs_reclaim_queue_core::BPlusTreeReclaimQueue;
use tidefs_types_reclaim_queue_core::ObjectKey as ReclaimObjectKey;
use tidefs_types_reclaim_queue_core::QueueFamily as ReclaimQueueFamily;
use tidefs_types_reclaim_queue_core::ReclaimQueueEntry;
use tidefs_types_vfs_core::InodeId;

use crate::object_keys::{content_object_key, content_object_key_for_version};
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
    /// Content objects deleted from the object store.
    pub content_objects_deleted: usize,
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
/// 1. If the inode still exists in the inode table with nlink > 0 but no
///    directory entry points at it, treat only the orphan-index entry as stale.
/// 2. If the inode still exists in the inode table with nlink==0, remove it
///    and record a reclaim delta for its content size.
/// 3. Scan all directories for stale entries pointing to this inode and
///    remove them.
/// 4. Free the extent map if present.
/// 5. Delete content objects (legacy and per-version keys) from the object
///    store.
/// 6. Remove the orphan index entry.
///
/// Inodes with nlink > 0 that appear in the orphan index are inconsistent.
/// If they still have directory entries, the orphan index wins and the entries
/// are stale unlink remnants. If they have no directory entry, cleanup leaves
/// the inode content alone to avoid destroying an unreachable but still-linked
/// record and removes only the orphan index entry.
pub(crate) fn cleanup_orphans(
    store: &mut LocalObjectStore,
    state: &mut crate::FileSystemState,
    orphan_index: &Arc<Mutex<OrphanIndex>>,
    reclaim_queue: &Arc<Mutex<BPlusTreeReclaimQueue>>,
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
        //    removed. Record a reclaim delta and remove the inode record.
        if let Some(record) = state.inodes.get(&inode_id) {
            let has_directory_entry = state
                .directories
                .values()
                .any(|dir| dir.values().any(|entry| entry.inode_id == inode_id));

            if record.nlink == 0 || has_directory_entry {
                let freed_bytes = record.size;
                let was_directory = record.carries_child_namespace();
                let mut key = [0u8; 32];
                key[..8].copy_from_slice(&inode_id_raw.to_be_bytes());
                let rq_entry = ReclaimQueueEntry::new(
                    ReclaimObjectKey(key),
                    -((freed_bytes as i64).saturating_abs()),
                    ReclaimQueueFamily::Extent,
                );
                reclaim_queue.lock().unwrap().insert(rq_entry);

                Arc::make_mut(&mut state.inodes).remove(&inode_id);
                state.last_inode_write_tx.remove(&inode_id);
                state.last_dir_write_tx.remove(&inode_id);
                if was_directory {
                    Arc::make_mut(&mut state.directories).remove(&inode_id);
                    state.dirty_dirs.remove(&inode_id);
                }
                stats.inodes_removed_from_state += 1;
            } else {
                // nlink > 0 with no directory entry: inconsistent but no
                // reachable stale name exists. Remove only the orphan marker.
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
                    // Update parent directory size.
                    if let Some(parent_inode) = Arc::make_mut(&mut state.inodes).get_mut(&dir_id) {
                        parent_inode.size = dir.len() as u64;
                    }
                }
            }
            let _ = dirs;
        }

        // 3. Remove extent map if present.
        if state.extent_maps.lock().unwrap().remove(&inode_id).is_some() {
            stats.extent_maps_freed += 1;
        }
        state.dirty_extent_maps.remove(&inode_id);

        // 4. Delete content objects from the object store.
        //    Legacy format key.
        let legacy_key = content_object_key(inode_id);
        if store.delete(legacy_key).unwrap_or(false) {
            stats.content_objects_deleted += 1;
        }
        // Versioned content object keys.  Walk forward until we see
        // two consecutive misses to avoid scanning u64::MAX versions.
        let mut misses = 0_u64;
        for dv in 0_u64.. {
            let version_key = content_object_key_for_version(inode_id, dv);
            match store.delete(version_key) {
                Ok(true) => {
                    stats.content_objects_deleted += 1;
                    misses = 0;
                }
                Ok(false) => {
                    misses += 1;
                    if misses >= 2 {
                        break;
                    }
                }
                Err(_) => {
                    misses += 1;
                    if misses >= 2 {
                        break;
                    }
                }
            }
        }

        // 5. Per-chunk dedup refcount cleanup (#6167).
        //    A crash after record_reclaim_delta's synchronous deletes could
        //    leave orphaned per-chunk keys that reference canonical dedup
        //    objects.  Walk chunk keys to find redirects, decrement refcounts,
        //    and delete canonical data/refcount objects when refcount reaches 0.
        {
            let mut dv = 0_u64;
            let mut dv_misses = 0_u64;
            while dv_misses < 2 {
                let mut ci = 0_u64;
                let mut ci_misses = 0_u64;
                while ci_misses < 2 {
                    let ckey =
                        crate::object_keys::content_chunk_object_key_for_version(inode_id, dv, ci);
                    if let Ok(Some(payload)) = store.get(ckey) {
                        ci_misses = 0;
                        if crate::encoding::is_dedup_redirect(&payload) {
                            if let Ok(canonical_key) =
                                crate::encoding::decode_dedup_redirect(&payload)
                            {
                                if let Ok(Some(canon_data)) = store.get(canonical_key) {
                                    if let Ok(chunk) =
                                        crate::encoding::decode_content_chunk(&canon_data)
                                    {
                                        let fp = crate::encoding::compute_content_fingerprint(
                                            &chunk.bytes,
                                        );
                                        if let Ok(true) =
                                            crate::dedup_refcount::DedupRefCount::decrement(
                                                store, &fp,
                                            )
                                        {
                                            let canon_data_key =
                                                crate::object_keys::content_dedup_object_key(&fp);
                                            let rq_entry = ReclaimQueueEntry::new(
                                                ReclaimObjectKey(*canon_data_key.as_bytes()),
                                                -1,
                                                ReclaimQueueFamily::Extent,
                                            );
                                            reclaim_queue.lock().unwrap().insert(rq_entry);
                                            // Refcount key already deleted by DedupRefCount::decrement
                                            // when the count reached zero.
                                        }
                                    }
                                }
                            }
                        }
                        let _ = store.delete(ckey);
                        stats.content_objects_deleted += 1;
                    } else {
                        ci_misses += 1;
                        if ci_misses >= 2 {
                            break;
                        }
                    }
                    ci = ci.saturating_add(1);
                }
                dv += 1;
                dv_misses += 1;
                if dv > 16 {
                    break;
                }
            }
        }

        // 6. Remove the orphan index entry.
        orphan_index.lock().unwrap().remove(inode_id_raw);
        stats.orphans_cleaned += 1;
    }

    if stats.inodes_removed_from_state > 0 || stats.directory_entries_removed > 0 {
        reconcile_directory_topology(state);
    }

    eprintln!(
        "orphan-cleanup: reclaimed {} orphans ({} state inodes, {} dir \
         entries, {} extent maps, {} content objects)",
        stats.orphans_cleaned,
        stats.inodes_removed_from_state,
        stats.directory_entries_removed,
        stats.extent_maps_freed,
        stats.content_objects_deleted,
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
    use tidefs_orphan_index::{OrphanEntry, OrphanEntryFlags};

    fn orphan_entry(inode_id: u64) -> OrphanEntry {
        OrphanEntry::new(inode_id, inode_id, 0, OrphanEntryFlags::NONE)
    }
    use std::collections::BTreeMap;
    use std::sync::Arc as StdArc;

    use tidefs_orphan_index::OrphanIndex;
    use tidefs_reclaim_queue_core::BPlusTreeReclaimQueue;
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

    fn make_temp_store() -> (tempfile::TempDir, LocalObjectStore) {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = LocalObjectStore::open(tmp.path()).expect("open store");
        (tmp, store)
    }

    // ── basic unit tests ────────────────────────────────────────────

    #[test]
    fn empty_orphan_index_returns_idle() {
        let (_tmp, mut store) = make_temp_store();
        let mut state = make_cleanup_state();
        let orphan_index = Arc::new(Mutex::new(OrphanIndex::new()));
        let reclaim_queue = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));

        let stats = cleanup_orphans(&mut store, &mut state, &orphan_index, &reclaim_queue)
            .expect("cleanup should succeed on empty index");

        assert!(stats.is_idle());
        assert_eq!(stats.orphans_found, 0);
        assert_eq!(stats.orphans_cleaned, 0);
    }

    #[test]
    fn orphan_not_in_state_is_cleaned() {
        let (_tmp, mut store) = make_temp_store();
        let mut state = make_cleanup_state();
        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            idx.insert(999, orphan_entry(999));
            idx
        }));
        let reclaim_queue = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));

        let stats = cleanup_orphans(&mut store, &mut state, &orphan_index, &reclaim_queue)
            .expect("cleanup should succeed");

        assert_eq!(stats.orphans_found, 1);
        assert_eq!(stats.orphans_cleaned, 1);
        assert_eq!(stats.inodes_removed_from_state, 0);
        assert!(orphan_index.lock().unwrap().is_empty());
    }

    #[test]
    fn orphan_still_in_state_with_nlink_zero_is_removed() {
        let (_tmp, mut store) = make_temp_store();
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
            idx.insert(42, orphan_entry(42));
            idx
        }));
        let reclaim_queue = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));

        let stats = cleanup_orphans(&mut store, &mut state, &orphan_index, &reclaim_queue)
            .expect("cleanup should succeed");

        assert_eq!(stats.orphans_found, 1);
        assert_eq!(stats.orphans_cleaned, 1);
        assert_eq!(stats.inodes_removed_from_state, 1);
        assert!(orphan_index.lock().unwrap().is_empty());
        assert!(!state.inodes.contains_key(&orphan_inode_id));
        // Reclaim delta recorded.
        assert!(!reclaim_queue.lock().unwrap().is_empty());
    }

    #[test]
    fn orphan_with_nlink_positive_and_directory_entry_is_reclaimed() {
        let (_tmp, mut store) = make_temp_store();
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
            nlink: 1, // stale positive nlink; orphan index is authoritative
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
            idx.insert(77, orphan_entry(77));
            idx
        }));
        let reclaim_queue = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));

        let stats = cleanup_orphans(&mut store, &mut state, &orphan_index, &reclaim_queue)
            .expect("cleanup should succeed");

        assert_eq!(stats.orphans_found, 1);
        assert_eq!(stats.orphans_cleaned, 1);
        assert_eq!(stats.inodes_removed_from_state, 1);
        assert_eq!(stats.directory_entries_removed, 1);
        assert!(!state.inodes.contains_key(&orphan_inode_id));
        let root_dir = state.directories.get(&ROOT_INODE_ID).unwrap();
        assert!(!root_dir.contains_key(b"linked.txt".as_slice()));
        assert!(!reclaim_queue.lock().unwrap().is_empty());
        assert!(orphan_index.lock().unwrap().is_empty());
    }

    #[test]
    fn orphan_directory_reconciles_parent_link_count() {
        let (_tmp, mut store) = make_temp_store();
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
            idx.insert(88, orphan_entry(88));
            idx
        }));
        let reclaim_queue = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));

        let stats = cleanup_orphans(&mut store, &mut state, &orphan_index, &reclaim_queue)
            .expect("cleanup should succeed");

        assert_eq!(stats.directory_entries_removed, 1);
        assert!(!state.inodes.contains_key(&orphan_inode_id));
        assert!(!state.directories.contains_key(&orphan_inode_id));
        let root = state.inodes.get(&ROOT_INODE_ID).unwrap();
        assert_eq!(root.size, 0);
        assert_eq!(root.nlink, 2);
    }

    #[test]
    fn orphan_with_nlink_positive_without_directory_entry_is_left_alone() {
        let (_tmp, mut store) = make_temp_store();
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
            idx.insert(78, orphan_entry(78));
            idx
        }));
        let reclaim_queue = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));

        let stats = cleanup_orphans(&mut store, &mut state, &orphan_index, &reclaim_queue)
            .expect("cleanup should succeed");

        assert_eq!(stats.orphans_found, 1);
        assert_eq!(stats.orphans_cleaned, 1);
        assert_eq!(stats.inodes_removed_from_state, 0);
        assert_eq!(stats.directory_entries_removed, 0);
        assert!(state.inodes.contains_key(&orphan_inode_id));
        assert!(reclaim_queue.lock().unwrap().is_empty());
        assert!(orphan_index.lock().unwrap().is_empty());
    }

    #[test]
    fn stale_directory_entries_are_removed() {
        let (_tmp, mut store) = make_temp_store();
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
            idx.insert(55, orphan_entry(55));
            idx
        }));
        let reclaim_queue = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));

        let stats = cleanup_orphans(&mut store, &mut state, &orphan_index, &reclaim_queue)
            .expect("cleanup should succeed");

        assert_eq!(stats.directory_entries_removed, 1);
        assert!(orphan_index.lock().unwrap().is_empty());
        // Verify the stale entry is gone.
        let root_dir = state.directories.get(&ROOT_INODE_ID).unwrap();
        assert!(!root_dir.contains_key(b"stale.txt".as_slice()));
    }

    #[test]
    fn extent_map_is_freed() {
        let (_tmp, mut store) = make_temp_store();
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
            idx.insert(33, orphan_entry(33));
            idx
        }));
        let reclaim_queue = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));

        let stats = cleanup_orphans(&mut store, &mut state, &orphan_index, &reclaim_queue)
            .expect("cleanup should succeed");

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
        let (_tmp, mut store) = make_temp_store();
        let mut state = make_cleanup_state();
        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            for i in 1..=50u64 {
                idx.insert(i, orphan_entry(i));
            }
            idx
        }));
        let reclaim_queue = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));

        let stats = cleanup_orphans(&mut store, &mut state, &orphan_index, &reclaim_queue)
            .expect("cleanup should succeed");

        assert_eq!(stats.orphans_found, 50);
        assert_eq!(stats.orphans_cleaned, 50);
        assert!(orphan_index.lock().unwrap().is_empty());
    }

    #[test]
    fn cleanup_is_idempotent() {
        let (_tmp, mut store) = make_temp_store();
        let mut state = make_cleanup_state();
        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            idx.insert(1, orphan_entry(1));
            idx.insert(2, orphan_entry(2));
            idx
        }));
        let reclaim_queue = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));

        let stats1 = cleanup_orphans(&mut store, &mut state, &orphan_index, &reclaim_queue)
            .expect("first cleanup");
        assert_eq!(stats1.orphans_cleaned, 2);

        let stats2 = cleanup_orphans(&mut store, &mut state, &orphan_index, &reclaim_queue)
            .expect("second cleanup");
        assert!(stats2.is_idle());
        assert_eq!(stats2.orphans_cleaned, 0);
    }

    #[test]
    fn content_objects_are_deleted() {
        let (_tmp, mut store) = make_temp_store();
        let mut state = make_cleanup_state();
        let inode_id = InodeId::new(42);

        // Write a content object that should be deleted.
        let content_key = content_object_key_for_version(inode_id, 1);
        store
            .put(content_key, b"test content")
            .expect("put content");
        store.sync_all().expect("sync");

        let orphan_index = Arc::new(Mutex::new({
            let mut idx = OrphanIndex::new();
            idx.insert(42, orphan_entry(42));
            idx
        }));
        let reclaim_queue = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));

        let stats = cleanup_orphans(&mut store, &mut state, &orphan_index, &reclaim_queue)
            .expect("cleanup should succeed");

        assert!(stats.content_objects_deleted >= 1);
        assert!(orphan_index.lock().unwrap().is_empty());

        // Verify content was deleted.
        let found = store.get(content_key).expect("get after delete");
        assert!(found.is_none(), "content object should have been deleted");
    }
}
