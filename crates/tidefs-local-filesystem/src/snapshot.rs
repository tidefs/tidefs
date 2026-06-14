//! Snapshot lifecycle extensions: clones, bookmarks, and holds.
//!
//! ZFS snapshot management is richer than basic create/delete/rollback.
//! This module adds:
//! - **Clones**: Writable snapshot forks that share blocks with an origin.
//!   Fundamental for VM/container provisioning (test environments, CI, dev workspaces).
//! - **Bookmarks**: Lightweight snapshot references without data retention.
//!   Used as anchors for incremental replication.
//! - **Holds**: Temporary deletion-prevention locks for backup windows.
//!
//! Implementation note: clones and bookmarks are stored as `SnapshotRecord`
//! entries with `SnapshotKind::Clone` / `SnapshotKind::Bookmark` in the
//! existing snapshot catalog. This exposes the current local lifecycle surface
//! while TFR-010 still tracks the unfinished deadlist, send/receive, and
//! reclaim authority model.

use crate::error::FileSystemError;
use crate::helpers::snapshot_name_bytes;
use crate::records::{SnapshotKind, SnapshotRecord};
use crate::types::SnapshotSummary;
use crate::LocalFileSystem;
use crate::Result;
use crate::ROOT_INODE_ID;
use tidefs_dataset_lifecycle::{
    BlockPointer, DatasetCatalog, DatasetFlags, DatasetId, DatasetType, SyncGuarantee,
    TraversalRoot, TraversalRootType,
};

// ---------------------------------------------------------------------------
// Public summary types
// ---------------------------------------------------------------------------

/// Summary returned by clone operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloneSummary {
    pub name: String,
    pub origin: String,
    pub source_transaction_id: u64,
    pub source_generation: u64,
    pub created_at_generation: u64,
}

/// Summary returned by bookmark operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookmarkSummary {
    pub name: String,
    pub source_snapshot: String,
    pub source_transaction_id: u64,
    pub source_generation: u64,
    pub created_at_generation: u64,
}

/// Lightweight hold descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldInfo {
    pub snapshot_name: String,
    pub hold_count: u32,
    pub kind: SnapshotKind,
}

/// Result of promoting a clone to an independent snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromoteReport {
    pub name: String,
    pub previous_origin: String,
    pub generation: u64,
}

/// Retention policy for regular local snapshots.
///
/// Clones and bookmarks are catalog entries, but retention pruning only applies
/// to `SnapshotKind::Snapshot` records. Held snapshots are reported and skipped.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SnapshotRetentionPolicy {
    /// Keep at most this many newest regular snapshots. Older held snapshots
    /// remain protected and can make the effective count exceed this value.
    pub max_count: Option<usize>,
    /// Delete regular snapshots older than this many filesystem generations.
    pub max_age_generations: Option<u64>,
}

impl SnapshotRetentionPolicy {
    pub const fn keep_all() -> Self {
        Self {
            max_count: None,
            max_age_generations: None,
        }
    }

    pub const fn retain_latest(max_count: usize) -> Self {
        Self {
            max_count: Some(max_count),
            max_age_generations: None,
        }
    }

    pub const fn retain_generations(max_age_generations: u64) -> Self {
        Self {
            max_count: None,
            max_age_generations: Some(max_age_generations),
        }
    }
}

/// Result returned by snapshot retention pruning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotRetentionReport {
    pub policy: SnapshotRetentionPolicy,
    pub evaluated_at_generation: u64,
    pub published_generation: u64,
    pub pruned_snapshots: Vec<SnapshotSummary>,
    pub retained_snapshots: Vec<SnapshotSummary>,
    pub skipped_held_snapshots: Vec<SnapshotSummary>,
    pub excluded_catalog_entries: usize,
}

pub(crate) fn snapshot_record_retains_data(record: &SnapshotRecord) -> bool {
    matches!(record.kind, SnapshotKind::Snapshot | SnapshotKind::Clone)
}

pub(crate) fn snapshot_record_display_name(record: &SnapshotRecord) -> String {
    String::from_utf8_lossy(&record.name).into_owned()
}

pub(crate) fn snapshot_record_catalog_name(record: &SnapshotRecord) -> String {
    format!("root@{}", snapshot_record_display_name(record))
}

pub(crate) fn snapshot_record_dataset_id(record: &SnapshotRecord) -> DatasetId {
    let display_name = snapshot_record_display_name(record);
    let mut id_bytes = [0u8; 16];
    let hash = blake3::hash(display_name.as_bytes());
    id_bytes.copy_from_slice(&hash.as_bytes()[..16]);
    DatasetId::from_bytes(id_bytes)
}

pub(crate) fn snapshot_record_catalog_flags(record: &SnapshotRecord) -> DatasetFlags {
    if record.kind == SnapshotKind::Clone {
        DatasetFlags::NONE.union(DatasetFlags::CLONE)
    } else {
        DatasetFlags::NONE
    }
}

pub(crate) fn snapshot_record_traversal_root(record: &SnapshotRecord) -> TraversalRoot {
    TraversalRoot::new(
        TraversalRootType::SnapshotCatalog,
        BlockPointer(record.root.transaction_id),
        record.root.generation,
    )
}

pub(crate) fn snapshot_catalog_entry_matches(
    catalog: &DatasetCatalog,
    record: &SnapshotRecord,
) -> bool {
    if !snapshot_record_retains_data(record) {
        return true;
    }

    let catalog_name = snapshot_record_catalog_name(record);
    let Ok(dataset_id) = catalog.snapshot_lookup(&catalog_name) else {
        return false;
    };
    let Some((path, _parent, dataset_type, creation_txg, flags, _lifecycle_state)) =
        catalog.get_by_id(&dataset_id)
    else {
        return false;
    };

    dataset_id == snapshot_record_dataset_id(record)
        && path == catalog_name
        && dataset_type == DatasetType::Snapshot
        && creation_txg == record.root.generation
        && flags.contains(DatasetFlags::CLONE)
            == snapshot_record_catalog_flags(record).contains(DatasetFlags::CLONE)
}

pub(crate) fn reconcile_snapshot_record_catalog_entry(
    catalog: &mut DatasetCatalog,
    record: &SnapshotRecord,
) -> Result<bool> {
    if !snapshot_record_retains_data(record) {
        return Ok(false);
    }

    let catalog_name = snapshot_record_catalog_name(record);
    let mut changed = false;

    if catalog.contains(&catalog_name) && !snapshot_catalog_entry_matches(catalog, record) {
        catalog
            .destroy(&catalog_name)
            .map_err(|_| FileSystemError::CorruptState {
                reason: "snapshot authority catalog entry could not be replaced",
            })?;
        changed = true;
    }

    if !catalog.contains(&catalog_name) {
        catalog
            .create(
                &catalog_name,
                snapshot_record_dataset_id(record),
                DatasetType::Snapshot,
                record.root.generation,
                vec![],
                snapshot_record_catalog_flags(record),
                SyncGuarantee::default(),
            )
            .map_err(|_| FileSystemError::CorruptState {
                reason: "snapshot authority catalog entry could not be created",
            })?;
        changed = true;
    }

    Ok(changed)
}

pub(crate) fn remove_snapshot_record_catalog_entry(
    catalog: &mut DatasetCatalog,
    record: &SnapshotRecord,
) -> Result<bool> {
    if !snapshot_record_retains_data(record) {
        return Ok(false);
    }

    let catalog_name = snapshot_record_catalog_name(record);
    if !catalog.contains(&catalog_name) {
        return Ok(false);
    }
    catalog
        .destroy(&catalog_name)
        .map_err(|_| FileSystemError::CorruptState {
            reason: "snapshot authority catalog entry could not be removed",
        })?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Clone operations
// ---------------------------------------------------------------------------

impl LocalFileSystem {
    pub(crate) fn ensure_snapshot_authority_consistent(&self) -> Result<()> {
        let mut expected_catalog_names = Vec::new();
        let mut expected_roots = Vec::<(TraversalRoot, u32)>::new();

        for record in self.state.snapshots.values() {
            if !snapshot_record_retains_data(record) {
                continue;
            }

            if !snapshot_catalog_entry_matches(&self.dataset_catalog, record) {
                return Err(FileSystemError::CorruptState {
                    reason: "snapshot authority catalog entry does not match snapshot state",
                });
            }

            expected_catalog_names.push(snapshot_record_catalog_name(record));
            let root = snapshot_record_traversal_root(record);
            if let Some((_existing, count)) = expected_roots
                .iter_mut()
                .find(|(existing_root, _count)| *existing_root == root)
            {
                *count = count.saturating_add(1);
            } else {
                expected_roots.push((root, 1));
            }
        }

        expected_catalog_names.sort();
        let catalog_entries =
            self.dataset_catalog
                .list_children("")
                .map_err(|_| FileSystemError::CorruptState {
                    reason: "snapshot authority catalog could not be inspected",
                })?;
        for (entry_name, _dataset_id) in catalog_entries {
            if entry_name.starts_with("root@")
                && expected_catalog_names.binary_search(&entry_name).is_err()
            {
                return Err(FileSystemError::CorruptState {
                    reason: "snapshot authority catalog contains an orphan snapshot entry",
                });
            }
        }

        let expected_pin_total = expected_roots
            .iter()
            .map(|(_root, count)| *count)
            .sum::<u32>();
        if self
            .lifecycle
            .gc_pin_set()
            .pin_count_by_type(TraversalRootType::SnapshotCatalog)
            != expected_pin_total
        {
            return Err(FileSystemError::CorruptState {
                reason: "snapshot authority lifecycle pin count does not match snapshot state",
            });
        }

        for (root, expected_count) in expected_roots {
            if self.lifecycle.gc_pin_set().pin_count(root) != expected_count {
                return Err(FileSystemError::CorruptState {
                    reason:
                        "snapshot authority lifecycle pin refcount does not match snapshot state",
                });
            }
        }

        Ok(())
    }

    pub(crate) fn ensure_snapshot_record_authority(&self, record: &SnapshotRecord) -> Result<()> {
        if !snapshot_record_retains_data(record) {
            return Err(FileSystemError::CorruptState {
                reason: "snapshot authority record does not retain data",
            });
        }
        if !snapshot_catalog_entry_matches(&self.dataset_catalog, record) {
            return Err(FileSystemError::CorruptState {
                reason: "snapshot authority catalog entry does not match snapshot record",
            });
        }
        if self
            .lifecycle
            .gc_pin_set()
            .pin_count(snapshot_record_traversal_root(record))
            == 0
        {
            return Err(FileSystemError::CorruptState {
                reason: "snapshot authority lifecycle pin is missing for snapshot record",
            });
        }
        Ok(())
    }

    fn pin_snapshot_record_root(&mut self, record: &SnapshotRecord) -> Result<()> {
        if !snapshot_record_retains_data(record) {
            return Ok(());
        }
        self.lifecycle
            .pin_root(snapshot_record_traversal_root(record))
            .map_err(|_| FileSystemError::CorruptState {
                reason: "snapshot authority lifecycle pin set is full",
            })
    }

    fn unpin_snapshot_record_root(&mut self, record: &SnapshotRecord) {
        if snapshot_record_retains_data(record) {
            self.lifecycle
                .unpin_root(snapshot_record_traversal_root(record));
        }
    }

    fn reconcile_snapshot_record_catalog_entry(&mut self, record: &SnapshotRecord) -> Result<()> {
        if reconcile_snapshot_record_catalog_entry(&mut self.dataset_catalog, record)? {
            self.persist_dataset_catalog()?;
        }
        Ok(())
    }

    fn remove_snapshot_record_catalog_entry(&mut self, record: &SnapshotRecord) -> Result<()> {
        if remove_snapshot_record_catalog_entry(&mut self.dataset_catalog, record)? {
            self.persist_dataset_catalog()?;
        }
        Ok(())
    }

    /// Create a writable clone from a source snapshot.
    ///
    /// The clone shares blocks with the origin snapshot. Writes to the clone
    /// are copy-on-write and do not affect the origin.
    ///
    /// The clone name is validated like a snapshot name.
    pub fn create_clone(
        &mut self,
        clone_name: impl AsRef<str>,
        source_snapshot: impl AsRef<str>,
    ) -> Result<CloneSummary> {
        let clone_name = clone_name.as_ref();
        let source_snapshot = source_snapshot.as_ref();

        let clone_name_bytes = snapshot_name_bytes(clone_name)?;
        let source_name_bytes = snapshot_name_bytes(source_snapshot)?;

        if clone_name_bytes == source_name_bytes {
            return Err(FileSystemError::Unsupported {
                operation: "create clone",
                reason: "clone name must differ from source snapshot name",
            });
        }

        self.ensure_snapshot_authority_consistent()?;

        // Verify the source snapshot exists and is protected by the snapshot
        // catalog plus lifecycle-pin authority before sharing its root.
        let source_record = self
            .state
            .snapshots
            .get(&source_name_bytes)
            .cloned()
            .ok_or_else(|| FileSystemError::SnapshotNotFound {
                name: source_snapshot.to_string(),
            })?;
        if !snapshot_record_retains_data(&source_record) {
            return Err(FileSystemError::Unsupported {
                operation: "create clone",
                reason: "clone source must be a data-retaining snapshot or clone",
            });
        }
        self.ensure_snapshot_record_authority(&source_record)?;
        let source = source_record.summary();

        // Ensure no snapshot/clone/bookmark already has this name
        if self.state.snapshots.contains_key(&clone_name_bytes) {
            return Err(FileSystemError::SnapshotAlreadyExists {
                name: clone_name.to_string(),
            });
        }

        self.begin_mutation();
        let created_at_generation = self.bump_generation();

        let record = SnapshotRecord {
            name: clone_name_bytes.clone(),
            root: source.source_root.clone(),
            created_at_generation,
            kind: SnapshotKind::Clone,
            origin: Some(source_name_bytes),
            hold_count: 0,
        };

        let summary = record.summary();
        let clone_summary = CloneSummary {
            name: clone_name.to_string(),
            origin: source_snapshot.to_string(),
            source_transaction_id: summary.source_transaction_id,
            source_generation: summary.source_generation,
            created_at_generation: summary.created_at_generation,
        };
        self.state
            .snapshots
            .insert(clone_name_bytes, record.clone());
        self.mark_inode_metadata_dirty(ROOT_INODE_ID);
        self.mark_dir_dirty(ROOT_INODE_ID);
        let summary_snapshot = summary.clone();
        self.commit_mutation(summary_snapshot)?;
        self.pin_snapshot_record_root(&record)?;
        self.reconcile_snapshot_record_catalog_entry(&record)?;

        Ok(clone_summary)
    }

    /// Delete a clone. This also removes the underlying snapshot data.
    ///
    /// Unlike ZFS (where deleting an origin snapshot that has clones requires
    /// promotion), TideFS clones are independent snapshot entries. Deleting a
    /// clone only removes the clone entry — the origin is unaffected.
    pub fn delete_clone(&mut self, name: impl AsRef<str>) -> Result<SnapshotSummary> {
        let name = name.as_ref();
        let name_bytes = snapshot_name_bytes(name)?;
        let record = self
            .state
            .snapshots
            .get(&name_bytes)
            .cloned()
            .ok_or_else(|| FileSystemError::SnapshotNotFound {
                name: name.to_string(),
            })?;

        if record.kind != SnapshotKind::Clone {
            return Err(FileSystemError::NotAClone {
                name: name.to_string(),
            });
        }

        if record.hold_count > 0 {
            return Err(FileSystemError::SnapshotHeld {
                name: name.to_string(),
                hold_count: record.hold_count,
            });
        }

        self.ensure_snapshot_authority_consistent()?;

        self.begin_mutation();
        self.bump_generation();
        self.state.snapshots.remove(&name_bytes);
        self.mark_inode_metadata_dirty(ROOT_INODE_ID);
        self.mark_dir_dirty(ROOT_INODE_ID);
        let summary = self.commit_mutation(record.summary())?;
        self.unpin_snapshot_record_root(&record);
        self.remove_snapshot_record_catalog_entry(&record)?;
        Ok(summary)
    }

    /// Promote a clone to an independent snapshot, severing the origin link.
    ///
    /// After promotion, the clone becomes a regular snapshot. Its data remains
    /// on disk (or in the object store) independent of the origin.
    /// The origin snapshot can be deleted safely after promotion.
    pub fn promote_clone(&mut self, name: impl AsRef<str>) -> Result<PromoteReport> {
        let name = name.as_ref();
        let name_bytes = snapshot_name_bytes(name)?;
        let record = self
            .state
            .snapshots
            .get(&name_bytes)
            .cloned()
            .ok_or_else(|| FileSystemError::SnapshotNotFound {
                name: name.to_string(),
            })?;

        if record.kind != SnapshotKind::Clone {
            return Err(FileSystemError::NotAClone {
                name: name.to_string(),
            });
        }

        let origin_name = record
            .origin
            .clone()
            .ok_or(FileSystemError::CloneOriginRequired {
                operation: "promote clone",
            })?;

        let origin_str = String::from_utf8_lossy(&origin_name).into_owned();
        self.ensure_snapshot_authority_consistent()?;
        let origin_record = self.state.snapshots.get(&origin_name).cloned().ok_or(
            FileSystemError::CorruptState {
                reason: "clone promotion origin snapshot is missing",
            },
        )?;
        if !snapshot_record_retains_data(&origin_record) {
            return Err(FileSystemError::CorruptState {
                reason: "clone promotion origin is not data-retaining",
            });
        }
        self.ensure_snapshot_record_authority(&record)?;
        self.ensure_snapshot_record_authority(&origin_record)?;

        self.begin_mutation();
        let generation = self.bump_generation();

        let promoted = SnapshotRecord {
            name: record.name.clone(),
            root: record.root,
            created_at_generation: record.created_at_generation,
            kind: SnapshotKind::Snapshot,
            origin: None,
            hold_count: record.hold_count,
        };

        self.state.snapshots.insert(name_bytes, promoted);
        self.mark_inode_metadata_dirty(ROOT_INODE_ID);
        self.mark_dir_dirty(ROOT_INODE_ID);
        self.commit_mutation(())?;
        let promoted = self.state.snapshots.get(&record.name).cloned().ok_or(
            FileSystemError::CorruptState {
                reason: "promoted snapshot record disappeared before catalog reconciliation",
            },
        )?;
        self.reconcile_snapshot_record_catalog_entry(&promoted)?;

        Ok(PromoteReport {
            name: name.to_string(),
            previous_origin: origin_str,
            generation,
        })
    }

    /// List all clones in the snapshot catalog.
    pub fn list_clones(&self) -> Vec<CloneSummary> {
        self.state
            .snapshots
            .values()
            .filter(|r| r.kind == SnapshotKind::Clone)
            .map(|r| {
                let origin = r
                    .origin
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(o).into_owned())
                    .unwrap_or_default();
                CloneSummary {
                    name: String::from_utf8_lossy(&r.name).into_owned(),
                    origin,
                    source_transaction_id: r.root.transaction_id,
                    source_generation: r.root.generation,
                    created_at_generation: r.created_at_generation,
                }
            })
            .collect()
    }

    /// Return the origin snapshot name for a clone, if it is one.
    pub fn clone_origin(&self, name: impl AsRef<str>) -> Result<Option<String>> {
        let name_bytes = snapshot_name_bytes(name.as_ref())?;
        let record = self.state.snapshots.get(&name_bytes).ok_or_else(|| {
            FileSystemError::SnapshotNotFound {
                name: name.as_ref().to_string(),
            }
        })?;

        if record.kind != SnapshotKind::Clone {
            return Ok(None);
        }

        Ok(record
            .origin
            .as_ref()
            .map(|o| String::from_utf8_lossy(o).into_owned()))
    }
}

// ---------------------------------------------------------------------------
// Bookmark operations
// ---------------------------------------------------------------------------

impl LocalFileSystem {
    /// Create a lightweight bookmark that references a snapshot without
    /// retaining data blocks.
    ///
    /// Bookmarks serve as anchors for incremental replication. They can be
    /// created and deleted without affecting snapshot data retention.
    pub fn create_bookmark(
        &mut self,
        bookmark_name: impl AsRef<str>,
        source_snapshot: impl AsRef<str>,
    ) -> Result<BookmarkSummary> {
        let bookmark_name = bookmark_name.as_ref();
        let source_snapshot = source_snapshot.as_ref();

        let bookmark_bytes = snapshot_name_bytes(bookmark_name)?;
        let source_bytes = snapshot_name_bytes(source_snapshot)?;

        // Verify the source snapshot exists
        let source = self.snapshot_summary(source_snapshot)?;

        // Ensure no duplicate bookmark name
        if self.state.snapshots.contains_key(&bookmark_bytes) {
            return Err(FileSystemError::SnapshotAlreadyExists {
                name: bookmark_name.to_string(),
            });
        }

        self.begin_mutation();
        let created_at_generation = self.bump_generation();

        let record = SnapshotRecord {
            name: bookmark_bytes.clone(),
            root: source.source_root.clone(),
            created_at_generation,
            kind: SnapshotKind::Bookmark,
            origin: Some(source_bytes),
            hold_count: 0,
        };

        let summary = record.summary();
        let bookmark_summary = BookmarkSummary {
            name: bookmark_name.to_string(),
            source_snapshot: source_snapshot.to_string(),
            source_transaction_id: summary.source_transaction_id,
            source_generation: summary.source_generation,
            created_at_generation: summary.created_at_generation,
        };
        self.state.snapshots.insert(bookmark_bytes, record);
        self.mark_inode_metadata_dirty(ROOT_INODE_ID);
        self.mark_dir_dirty(ROOT_INODE_ID);
        let summary_snapshot = summary.clone();
        self.commit_mutation(summary_snapshot)?;

        Ok(bookmark_summary)
    }

    /// Delete a bookmark.
    pub fn delete_bookmark(&mut self, name: impl AsRef<str>) -> Result<SnapshotSummary> {
        let name = name.as_ref();
        let name_bytes = snapshot_name_bytes(name)?;
        let record = self
            .state
            .snapshots
            .get(&name_bytes)
            .cloned()
            .ok_or_else(|| FileSystemError::BookmarkNotFound {
                name: name.to_string(),
            })?;

        if record.kind != SnapshotKind::Bookmark {
            return Err(FileSystemError::BookmarkNotFound {
                name: name.to_string(),
            });
        }

        self.begin_mutation();
        self.bump_generation();
        self.state.snapshots.remove(&name_bytes);
        self.mark_inode_metadata_dirty(ROOT_INODE_ID);
        self.mark_dir_dirty(ROOT_INODE_ID);
        self.commit_mutation(record.summary())
    }

    /// List all bookmarks in the snapshot catalog.
    pub fn list_bookmarks(&self) -> Vec<BookmarkSummary> {
        self.state
            .snapshots
            .values()
            .filter(|r| r.kind == SnapshotKind::Bookmark)
            .map(|r| {
                let source = r
                    .origin
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(o).into_owned())
                    .unwrap_or_default();
                BookmarkSummary {
                    name: String::from_utf8_lossy(&r.name).into_owned(),
                    source_snapshot: source,
                    source_transaction_id: r.root.transaction_id,
                    source_generation: r.root.generation,
                    created_at_generation: r.created_at_generation,
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Hold operations
// ---------------------------------------------------------------------------

impl LocalFileSystem {
    /// Place a temporary hold on a snapshot or clone, preventing its deletion.
    ///
    /// Holds are reference-counted. Each `hold_snapshot` call increments the
    /// count; `release_snapshot` decrements it. A snapshot cannot be deleted
    /// while `hold_count > 0`.
    ///
    /// Bookmarks cannot be held — they are already lightweight.
    pub fn hold_snapshot(&mut self, name: impl AsRef<str>) -> Result<HoldInfo> {
        let name = name.as_ref();
        let name_bytes = snapshot_name_bytes(name)?;
        let record = self
            .state
            .snapshots
            .get(&name_bytes)
            .cloned()
            .ok_or_else(|| FileSystemError::SnapshotNotFound {
                name: name.to_string(),
            })?;

        if record.kind == SnapshotKind::Bookmark {
            return Err(FileSystemError::HoldOnBookmark {
                name: name.to_string(),
            });
        }

        self.begin_mutation();
        self.bump_generation();

        let mut updated = record;
        updated.hold_count += 1;
        let info = HoldInfo {
            snapshot_name: name.to_string(),
            hold_count: updated.hold_count,
            kind: updated.kind,
        };

        self.state.snapshots.insert(name_bytes, updated);
        self.mark_inode_metadata_dirty(ROOT_INODE_ID);
        self.mark_dir_dirty(ROOT_INODE_ID);
        self.commit_mutation(())?;

        Ok(info)
    }

    /// Release a previously placed hold.
    ///
    /// When hold_count reaches 0 (and no other active holds exist), the
    /// snapshot or clone can be deleted.
    pub fn release_snapshot(&mut self, name: impl AsRef<str>) -> Result<HoldInfo> {
        let name = name.as_ref();
        let name_bytes = snapshot_name_bytes(name)?;
        let record = self
            .state
            .snapshots
            .get(&name_bytes)
            .cloned()
            .ok_or_else(|| FileSystemError::SnapshotNotFound {
                name: name.to_string(),
            })?;

        if record.kind == SnapshotKind::Bookmark {
            return Err(FileSystemError::HoldOnBookmark {
                name: name.to_string(),
            });
        }

        if record.hold_count == 0 {
            return Err(FileSystemError::Unsupported {
                operation: "release hold",
                reason: "no active holds to release",
            });
        }

        self.begin_mutation();
        self.bump_generation();

        let mut updated = record;
        updated.hold_count -= 1;
        let info = HoldInfo {
            snapshot_name: name.to_string(),
            hold_count: updated.hold_count,
            kind: updated.kind,
        };

        self.state.snapshots.insert(name_bytes, updated);
        self.mark_inode_metadata_dirty(ROOT_INODE_ID);
        self.mark_dir_dirty(ROOT_INODE_ID);
        self.commit_mutation(())?;

        Ok(info)
    }

    /// Query hold state for a snapshot or clone.
    pub fn hold_info(&self, name: impl AsRef<str>) -> Result<HoldInfo> {
        let name_bytes = snapshot_name_bytes(name.as_ref())?;
        let record = self.state.snapshots.get(&name_bytes).ok_or_else(|| {
            FileSystemError::SnapshotNotFound {
                name: name.as_ref().to_string(),
            }
        })?;

        Ok(HoldInfo {
            snapshot_name: name.as_ref().to_string(),
            hold_count: record.hold_count,
            kind: record.kind,
        })
    }

    /// List all held snapshots and clones.
    pub fn list_holds(&self) -> Vec<HoldInfo> {
        self.state
            .snapshots
            .values()
            .filter(|r| r.hold_count > 0)
            .map(|r| HoldInfo {
                snapshot_name: String::from_utf8_lossy(&r.name).into_owned(),
                hold_count: r.hold_count,
                kind: r.kind,
            })
            .collect()
    }

    /// Guard deletion: returns Ok(()) if the snapshot/clone can be deleted,
    /// Err(SnapshotHeld) if holds are active.
    pub fn check_deletable(&self, name: impl AsRef<str>) -> Result<()> {
        let name_bytes = snapshot_name_bytes(name.as_ref())?;
        let record = self.state.snapshots.get(&name_bytes).ok_or_else(|| {
            FileSystemError::SnapshotNotFound {
                name: name.as_ref().to_string(),
            }
        })?;

        if record.hold_count > 0 {
            return Err(FileSystemError::SnapshotHeld {
                name: name.as_ref().to_string(),
                hold_count: record.hold_count,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Extended snapshot listing (includes kind in summary)
// ---------------------------------------------------------------------------

/// Extended snapshot descriptor that includes kind and origin information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotDescriptor {
    pub name: String,
    pub kind: SnapshotKind,
    pub origin: Option<String>,
    pub hold_count: u32,
    pub source_transaction_id: u64,
    pub source_generation: u64,
    pub created_at_generation: u64,
}

impl LocalFileSystem {
    /// List all snapshot catalog entries with kind, origin, and hold metadata.
    pub fn list_snapshots_extended(&self) -> Vec<SnapshotDescriptor> {
        self.state
            .snapshots
            .values()
            .map(|r| SnapshotDescriptor {
                name: String::from_utf8_lossy(&r.name).into_owned(),
                kind: r.kind,
                origin: r
                    .origin
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(o).into_owned()),
                hold_count: r.hold_count,
                source_transaction_id: r.root.transaction_id,
                source_generation: r.root.generation,
                created_at_generation: r.created_at_generation,
            })
            .collect()
    }

    /// Prune regular snapshots according to a local retention policy.
    ///
    /// Retention applies only to `SnapshotKind::Snapshot` records. Clones and
    /// bookmarks are excluded from policy selection, and held snapshots are
    /// reported without being deleted.
    pub fn prune_snapshots(
        &mut self,
        policy: SnapshotRetentionPolicy,
    ) -> Result<SnapshotRetentionReport> {
        let evaluated_at_generation = self.state.generation;
        let regular_snapshots = self.regular_snapshots_by_age();
        let excluded_catalog_entries = self
            .state
            .snapshots
            .len()
            .saturating_sub(regular_snapshots.len());

        let mut prune_names = Vec::<Vec<u8>>::new();

        if let Some(max_count) = policy.max_count {
            let prune_count = regular_snapshots.len().saturating_sub(max_count);
            for (name, _) in regular_snapshots.iter().take(prune_count) {
                insert_sorted_snapshot_name(&mut prune_names, name.clone());
            }
        }

        if let Some(max_age_generations) = policy.max_age_generations {
            for (name, record) in &regular_snapshots {
                let age_generations =
                    evaluated_at_generation.saturating_sub(record.created_at_generation);
                if age_generations > max_age_generations {
                    insert_sorted_snapshot_name(&mut prune_names, name.clone());
                }
            }
        }

        let mut prune_snapshot_names = Vec::new();
        let mut skipped_held_snapshots = Vec::new();

        for name in prune_names {
            let Some(record) = self.state.snapshots.get(&name) else {
                continue;
            };
            if record.hold_count > 0 {
                skipped_held_snapshots.push(record.summary());
            } else {
                prune_snapshot_names.push(String::from_utf8_lossy(&name).into_owned());
            }
        }

        sort_snapshot_summaries(&mut skipped_held_snapshots);

        let mut pruned_snapshots = Vec::new();
        for name in prune_snapshot_names {
            pruned_snapshots.push(self.delete_snapshot(&name)?);
        }
        sort_snapshot_summaries(&mut pruned_snapshots);

        let published_generation = if pruned_snapshots.is_empty() {
            evaluated_at_generation
        } else {
            self.state.generation
        };

        let mut retained_snapshots = self.regular_snapshot_summaries();
        sort_snapshot_summaries(&mut retained_snapshots);

        let report = SnapshotRetentionReport {
            policy,
            evaluated_at_generation,
            published_generation,
            pruned_snapshots,
            retained_snapshots,
            skipped_held_snapshots,
            excluded_catalog_entries,
        };

        Ok(report)
    }

    fn regular_snapshots_by_age(&self) -> Vec<(Vec<u8>, SnapshotRecord)> {
        let mut snapshots = self
            .state
            .snapshots
            .iter()
            .filter(|(_, record)| record.kind == SnapshotKind::Snapshot)
            .map(|(name, record)| (name.clone(), record.clone()))
            .collect::<Vec<_>>();
        snapshots.sort_by(|(left_name, left), (right_name, right)| {
            left.created_at_generation
                .cmp(&right.created_at_generation)
                .then_with(|| left_name.cmp(right_name))
        });
        snapshots
    }

    fn regular_snapshot_summaries(&self) -> Vec<SnapshotSummary> {
        self.state
            .snapshots
            .values()
            .filter(|record| record.kind == SnapshotKind::Snapshot)
            .map(SnapshotRecord::summary)
            .collect()
    }
}

fn insert_sorted_snapshot_name(names: &mut Vec<Vec<u8>>, name: Vec<u8>) {
    match names.binary_search(&name) {
        Ok(_) => {}
        Err(index) => names.insert(index, name),
    }
}

fn sort_snapshot_summaries(summaries: &mut [SnapshotSummary]) {
    summaries.sort_by(|left, right| {
        left.created_at_generation
            .cmp(&right.created_at_generation)
            .then_with(|| left.name.cmp(&right.name))
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tidefs_types_dataset_lifecycle_core::TraversalRootType;

    fn setup_auth_env() {
        env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
    }

    fn temp_dir() -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "tidefs-clone-test-{}-{}",
            std::process::id(),
            nanos
        ))
    }

    fn new_fs(dir: &std::path::Path) -> LocalFileSystem {
        use crate::LocalFileSystem;
        use tidefs_local_object_store::StoreOptions;
        setup_auth_env();
        let _ = std::fs::remove_dir_all(dir);
        LocalFileSystem::open_with_options(dir, StoreOptions::default()).expect("open fs")
    }

    fn reopen_fs(dir: &std::path::Path) -> LocalFileSystem {
        use crate::LocalFileSystem;
        use tidefs_local_object_store::StoreOptions;
        setup_auth_env();
        LocalFileSystem::open_with_options(dir, StoreOptions::default()).expect("reopen fs")
    }
    fn seed_file(fs: &mut LocalFileSystem, path: &str, content: &[u8]) {
        use crate::DEFAULT_FILE_PERMISSIONS;
        fs.create_file(path, DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        if !content.is_empty() {
            fs.write_file(path, 0, content).expect("write file");
        }
    }

    fn summary_names(summaries: &[SnapshotSummary]) -> Vec<String> {
        summaries
            .iter()
            .map(|summary| summary.name.clone())
            .collect()
    }

    fn snapshot_catalog_pin_count(fs: &LocalFileSystem) -> u32 {
        fs.lifecycle().stats().per_root_pins[TraversalRootType::SnapshotCatalog.to_u8() as usize]
    }

    fn snapshot_root(summary: &SnapshotSummary) -> TraversalRoot {
        TraversalRoot::new(
            TraversalRootType::SnapshotCatalog,
            BlockPointer(summary.source_transaction_id),
            summary.source_generation,
        )
    }

    fn catalog_clone_flag(fs: &LocalFileSystem, name: &str) -> bool {
        let catalog_name = format!("root@{name}");
        let dataset_id = fs
            .dataset_catalog()
            .snapshot_lookup(&catalog_name)
            .expect("snapshot catalog lookup");
        let (path, _parent, dataset_type, _creation_txg, flags, _state) = fs
            .dataset_catalog()
            .get_by_id(&dataset_id)
            .expect("snapshot catalog entry");
        assert_eq!(path, catalog_name);
        assert_eq!(dataset_type, DatasetType::Snapshot);
        flags.contains(DatasetFlags::CLONE)
    }

    fn assert_snapshot_authority_error(err: FileSystemError) {
        match err {
            FileSystemError::CorruptState { reason } => assert!(
                reason.contains("snapshot authority"),
                "unexpected corrupt-state reason: {reason}"
            ),
            other => panic!("expected snapshot authority corrupt state, got {other:?}"),
        }
    }

    #[test]
    fn clone_create_delete() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        seed_file(&mut fs, "/test.txt", b"hello");

        let snap = fs.create_snapshot("snap1").expect("create snapshot");
        assert_eq!(snap.name, "snap1");
        assert!(fs.dataset_catalog().contains("root@snap1"));
        assert!(!catalog_clone_flag(&fs, "snap1"));
        assert_eq!(snapshot_catalog_pin_count(&fs), 1);

        let clone = fs.create_clone("clone1", "snap1").expect("create clone");
        assert_eq!(clone.origin, "snap1");
        assert_eq!(clone.name, "clone1");
        assert!(fs.dataset_catalog().contains("root@clone1"));
        assert!(catalog_clone_flag(&fs, "clone1"));
        assert_eq!(snapshot_catalog_pin_count(&fs), 2);

        // Verify clone appears in extended listing
        let ext = fs.list_snapshots_extended();
        let clone_entry = ext
            .iter()
            .find(|d| d.name == "clone1")
            .expect("clone in listing");
        assert_eq!(clone_entry.kind, SnapshotKind::Clone);
        assert_eq!(clone_entry.origin.as_deref(), Some("snap1"));

        // Delete clone
        let summary = fs.delete_clone("clone1").expect("delete clone");
        assert_eq!(summary.name, "clone1");
        assert!(!fs.dataset_catalog().contains("root@clone1"));
        assert!(fs.dataset_catalog().contains("root@snap1"));
        assert_eq!(snapshot_catalog_pin_count(&fs), 1);

        // Clone gone but snapshot remains
        assert!(fs.delete_snapshot("snap1").is_ok());
        assert_eq!(snapshot_catalog_pin_count(&fs), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clone_promote() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        seed_file(&mut fs, "/data.bin", b"original");

        fs.create_snapshot("origin").expect("snapshot");
        let clone = fs.create_clone("myclone", "origin").expect("clone");
        assert_eq!(clone.origin, "origin");
        assert!(catalog_clone_flag(&fs, "myclone"));
        assert_eq!(snapshot_catalog_pin_count(&fs), 2);

        // Promote
        let report = fs.promote_clone("myclone").expect("promote");
        assert_eq!(report.previous_origin, "origin");
        assert!(!catalog_clone_flag(&fs, "myclone"));
        assert_eq!(snapshot_catalog_pin_count(&fs), 2);

        // Now it's a regular snapshot
        let ext = fs.list_snapshots_extended();
        let entry = ext
            .iter()
            .find(|d| d.name == "myclone")
            .expect("still exists");
        assert_eq!(entry.kind, SnapshotKind::Snapshot);
        assert!(entry.origin.is_none());

        // Can delete both now
        fs.delete_snapshot("myclone").expect("delete promoted");
        assert_eq!(snapshot_catalog_pin_count(&fs), 1);
        fs.delete_snapshot("origin").expect("delete origin");
        assert_eq!(snapshot_catalog_pin_count(&fs), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clone_reopen_reconciles_missing_catalog_entry_and_pins() {
        let dir = temp_dir();
        {
            let mut fs = new_fs(&dir);
            seed_file(&mut fs, "/data.bin", b"clone-reconcile");
            fs.create_snapshot("snap1").expect("snapshot");
            fs.create_clone("clone1", "snap1").expect("clone");
            fs.dataset_catalog_mut()
                .destroy("root@clone1")
                .expect("remove clone catalog entry");
            fs.persist_dataset_catalog()
                .expect("persist missing clone catalog entry");
            assert!(!fs.dataset_catalog().contains("root@clone1"));
        }

        let fs = reopen_fs(&dir);
        assert!(fs.dataset_catalog().contains("root@snap1"));
        assert!(fs.dataset_catalog().contains("root@clone1"));
        assert!(catalog_clone_flag(&fs, "clone1"));
        assert_eq!(snapshot_catalog_pin_count(&fs), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rollback_rejects_snapshot_catalog_authority_mismatch() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        seed_file(&mut fs, "/data.bin", b"catalog-mismatch");
        fs.create_snapshot("snap1").expect("snapshot");
        fs.dataset_catalog_mut()
            .destroy("root@snap1")
            .expect("remove snapshot catalog entry");

        let err = fs.rollback_to_snapshot("snap1").unwrap_err();
        assert_snapshot_authority_error(err);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn send_export_rejects_snapshot_pin_authority_mismatch() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        seed_file(&mut fs, "/data.bin", b"pin-mismatch");
        let snap = fs.create_snapshot("snap1").expect("snapshot");
        fs.lifecycle_mut().unpin_root(snapshot_root(&snap));

        let err = fs.export_changed_records().unwrap_err();
        assert_snapshot_authority_error(err);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clone_rejects_duplicate_name() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        fs.create_snapshot("snap1").expect("snapshot");
        fs.create_clone("clone1", "snap1").expect("first clone");

        let err = fs.create_clone("clone1", "snap1").unwrap_err();
        assert!(matches!(err, FileSystemError::SnapshotAlreadyExists { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clone_rejects_self_reference() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        fs.create_snapshot("snap1").expect("snapshot");
        let err = fs.create_clone("snap1", "snap1").unwrap_err();
        assert!(matches!(err, FileSystemError::Unsupported { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hold_and_release() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        fs.create_snapshot("important").expect("snapshot");

        // Hold it
        let info = fs.hold_snapshot("important").expect("hold");
        assert_eq!(info.hold_count, 1);

        // Cannot delete while held
        let err = fs.delete_snapshot("important").unwrap_err();
        assert!(matches!(err, FileSystemError::SnapshotHeld { .. }));

        // Release
        let info = fs.release_snapshot("important").expect("release");
        assert_eq!(info.hold_count, 0);

        // Now deletable
        fs.delete_snapshot("important")
            .expect("delete after release");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hold_on_clone() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        fs.create_snapshot("origin").expect("snapshot");
        fs.create_clone("myclone", "origin").expect("clone");

        fs.hold_snapshot("myclone").expect("hold clone");

        let err = fs.delete_clone("myclone").unwrap_err();
        assert!(matches!(err, FileSystemError::SnapshotHeld { .. }));

        fs.release_snapshot("myclone").expect("release");
        fs.delete_clone("myclone").expect("delete clone");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bookmark_create_delete() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        fs.create_snapshot("snap1").expect("snapshot");

        let bm = fs
            .create_bookmark("repl-anchor", "snap1")
            .expect("bookmark");
        assert_eq!(bm.name, "repl-anchor");
        assert_eq!(bm.source_snapshot, "snap1");

        let bookmarks = fs.list_bookmarks();
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].name, "repl-anchor");

        // Cannot hold a bookmark
        let err = fs.hold_snapshot("repl-anchor").unwrap_err();
        assert!(matches!(err, FileSystemError::HoldOnBookmark { .. }));

        // Delete bookmark
        fs.delete_bookmark("repl-anchor").expect("delete bookmark");
        assert!(fs.list_bookmarks().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn multiple_holds() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        fs.create_snapshot("critical").expect("snapshot");

        fs.hold_snapshot("critical").expect("hold 1");
        fs.hold_snapshot("critical").expect("hold 2");
        fs.hold_snapshot("critical").expect("hold 3");

        let info = fs.hold_info("critical").expect("hold info");
        assert_eq!(info.hold_count, 3);

        // One release doesn't free it
        fs.release_snapshot("critical").expect("release 1");
        let err = fs.delete_snapshot("critical").unwrap_err();
        assert!(matches!(err, FileSystemError::SnapshotHeld { .. }));

        // Release all
        fs.release_snapshot("critical").expect("release 2");
        fs.release_snapshot("critical").expect("release 3");

        fs.delete_snapshot("critical")
            .expect("delete after all releases");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clone_origin_tracking() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        fs.create_snapshot("base").expect("snapshot");
        fs.create_clone("fork", "base").expect("clone");

        let origin = fs.clone_origin("fork").expect("origin query");
        assert_eq!(origin, Some("base".to_string()));

        // Non-clone has no origin
        assert_eq!(fs.clone_origin("base").unwrap(), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_prunes_oldest_regular_snapshots_by_count() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        fs.create_snapshot("old").expect("old snapshot");
        fs.create_snapshot("middle").expect("middle snapshot");
        fs.create_snapshot("new").expect("new snapshot");

        let report = fs
            .prune_snapshots(SnapshotRetentionPolicy::retain_latest(2))
            .expect("prune snapshots");

        assert_eq!(summary_names(&report.pruned_snapshots), vec!["old"]);
        assert_eq!(
            summary_names(&report.retained_snapshots),
            vec!["middle", "new"]
        );
        assert!(report.skipped_held_snapshots.is_empty());
        assert!(fs.snapshot_summary("old").is_err());
        assert!(fs.snapshot_summary("middle").is_ok());
        assert!(fs.snapshot_summary("new").is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_prune_removes_dataset_catalog_entry_and_snapshot_pin() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        fs.create_snapshot("old").expect("old snapshot");
        fs.create_snapshot("middle").expect("middle snapshot");
        fs.create_snapshot("new").expect("new snapshot");

        assert!(fs.dataset_catalog().contains("root@old"));
        assert!(fs.dataset_catalog().contains("root@middle"));
        assert!(fs.dataset_catalog().contains("root@new"));
        assert_eq!(snapshot_catalog_pin_count(&fs), 3);

        let report = fs
            .prune_snapshots(SnapshotRetentionPolicy::retain_latest(2))
            .expect("prune snapshots");

        assert_eq!(summary_names(&report.pruned_snapshots), vec!["old"]);
        assert!(fs.snapshot_summary("old").is_err());
        assert!(!fs.dataset_catalog().contains("root@old"));
        assert!(fs.dataset_catalog().contains("root@middle"));
        assert!(fs.dataset_catalog().contains("root@new"));
        assert_eq!(snapshot_catalog_pin_count(&fs), 2);
        fs.sync_all().expect("sync pruned snapshot state");
        drop(fs);

        let fs = reopen_fs(&dir);
        assert!(fs.snapshot_summary("old").is_err());
        assert!(!fs.dataset_catalog().contains("root@old"));
        assert!(fs.dataset_catalog().contains("root@middle"));
        assert!(fs.dataset_catalog().contains("root@new"));
        assert_eq!(snapshot_catalog_pin_count(&fs), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_prunes_regular_snapshots_by_generation_age() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        fs.create_snapshot("old").expect("old snapshot");
        fs.create_snapshot("middle").expect("middle snapshot");
        fs.create_snapshot("new").expect("new snapshot");

        let report = fs
            .prune_snapshots(SnapshotRetentionPolicy::retain_generations(1))
            .expect("prune snapshots");

        assert_eq!(summary_names(&report.pruned_snapshots), vec!["old"]);
        assert_eq!(
            summary_names(&report.retained_snapshots),
            vec!["middle", "new"]
        );
        assert!(report.skipped_held_snapshots.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_skips_held_snapshots_that_match_policy() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        fs.create_snapshot("held-old").expect("old snapshot");
        fs.create_snapshot("middle").expect("middle snapshot");
        fs.create_snapshot("new").expect("new snapshot");
        fs.hold_snapshot("held-old").expect("hold old snapshot");

        let report = fs
            .prune_snapshots(SnapshotRetentionPolicy::retain_latest(1))
            .expect("prune snapshots");

        assert_eq!(summary_names(&report.pruned_snapshots), vec!["middle"]);
        assert_eq!(
            summary_names(&report.skipped_held_snapshots),
            vec!["held-old"]
        );
        assert_eq!(
            summary_names(&report.retained_snapshots),
            vec!["held-old", "new"]
        );
        assert!(fs.snapshot_summary("held-old").is_ok());
        assert!(fs.snapshot_summary("middle").is_err());
        assert!(fs.snapshot_summary("new").is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_excludes_clones_and_bookmarks() {
        let dir = temp_dir();
        let mut fs = new_fs(&dir);

        fs.create_snapshot("base").expect("base snapshot");
        fs.create_snapshot("extra").expect("extra snapshot");
        fs.create_clone("base-clone", "base").expect("clone");
        fs.create_bookmark("base-bookmark", "base")
            .expect("bookmark");

        let report = fs
            .prune_snapshots(SnapshotRetentionPolicy::retain_latest(0))
            .expect("prune snapshots");

        assert_eq!(
            summary_names(&report.pruned_snapshots),
            vec!["base", "extra"]
        );
        assert_eq!(report.excluded_catalog_entries, 2);
        assert!(report.retained_snapshots.is_empty());

        let entries = fs.list_snapshots_extended();
        assert!(entries
            .iter()
            .any(|entry| entry.name == "base-clone" && entry.kind == SnapshotKind::Clone));
        assert!(entries
            .iter()
            .any(|entry| entry.name == "base-bookmark" && entry.kind == SnapshotKind::Bookmark));
        assert!(!entries
            .iter()
            .any(|entry| entry.name == "base" || entry.name == "extra"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Clone divergence: writable snapshot data integrity ────────────────

    /// Full clone-divergence lifecycle test.
    ///
    /// 1. Write original data, sync, take a snapshot, create a writable clone.
    /// 2. Overwrite — the current state diverges from the snapshot/clone.
    /// 3. Roll back to the clone and verify the clone preserved the original
    ///    snapshot data (in-memory rollback works).
    /// 4. Write brand-new data into the activated clone, diverging from the
    ///    now-abandoned current state.
    ///
    /// Tier 3 crate validation: clone writable lifecycle correctly separates
    /// origin, snapshot, and clone contents during in-memory divergence.
    ///
    /// Known limitation: rollback_to_snapshot committed state does not persist
    /// across close/reopen (separate rollback-persistence issue).
    #[test]
    fn clone_writable_divergence() {
        let dir = temp_dir();
        let og_data = b"original-snapshot-data-v1";
        let overwrite_data = b"overwritten-after-snapshot";
        let clone_data = b"clone-diverged-write-data";

        {
            let mut fs = new_fs(&dir);
            seed_file(&mut fs, "/doc.txt", og_data);
            let readback = fs.read_file("/doc.txt").expect("read original");
            assert_eq!(readback, og_data);

            fs.sync_all().expect("sync before snapshot");

            let snap = fs.create_snapshot("origin-snap").expect("snapshot");
            assert_eq!(snap.name, "origin-snap");

            let clone = fs
                .create_clone("writable-clone", "origin-snap")
                .expect("clone");
            assert_eq!(clone.origin, "origin-snap");
            assert_eq!(clone.source_transaction_id, snap.source_transaction_id);

            // Diverge: current state overwrites, diverging from snapshot/clone
            fs.write_file("/doc.txt", 0, overwrite_data)
                .expect("overwrite");
            fs.sync_all().expect("sync after overwrite");
            let diverged = fs.read_file("/doc.txt").expect("read diverged");
            assert_eq!(
                diverged, overwrite_data,
                "current state must diverge from clone with overwrite"
            );

            // Rollback to clone restores original snapshot data
            let report = fs
                .rollback_to_snapshot("writable-clone")
                .expect("rollback to clone");
            assert_eq!(report.snapshot.name, "writable-clone");

            let restored = fs.read_file("/doc.txt").expect("read after rollback");
            assert_eq!(
                restored, og_data,
                "rollback to clone must restore snapshot data"
            );

            // Clone is writable: writes diverge from original snapshot
            fs.write_file("/doc.txt", 0, clone_data)
                .expect("write clone data");
            fs.sync_all().expect("sync clone data");
            let clone_readback = fs.read_file("/doc.txt").expect("read clone write");
            assert_eq!(clone_readback, clone_data, "clone writes must persist");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Clone divergence: writable snapshot data integrity across remount ──

    /// Full clone-divergence lifecycle test with cross-remount persistence.
    ///
    /// 1. Write original data, sync, take a snapshot, create a writable clone.
    /// 2. Overwrite — the current state diverges from the snapshot/clone.
    /// 3. Roll back to the clone and verify the clone preserved the original
    ///    snapshot data.
    /// 4. Write brand-new data into the activated clone (diverging from the
    ///    now-abandoned current state).
    /// 5. Close and reopen — verify the clone's written data survived remount.
    ///
    /// Tier 3 crate validation: clone writable lifecycle correctly separates
    /// origin, snapshot, and clone contents across remount.
    #[test]
    fn clone_writable_divergence_across_remount() {
        let dir = temp_dir();
        let og_data = b"original-snapshot-data-v1";
        let overwrite_data = b"overwritten-after-snapshot";
        let clone_data = b"clone-diverged-write-data";

        // Phase 1 — create origin, snapshot, clone, overwrite, rollback, write clone data.
        {
            let mut fs = new_fs(&dir);
            seed_file(&mut fs, "/doc.txt", og_data);
            let readback = fs.read_file("/doc.txt").expect("read original");
            assert_eq!(readback, og_data);
            fs.sync_all().expect("sync before snapshot");

            let snap = fs.create_snapshot("origin-snap").expect("snapshot");
            assert_eq!(snap.name, "origin-snap");

            let clone = fs
                .create_clone("writable-clone", "origin-snap")
                .expect("clone");
            assert_eq!(clone.origin, "origin-snap");
            assert_eq!(clone.source_transaction_id, snap.source_transaction_id);

            // Current state diverges from snapshot/clone
            fs.write_file("/doc.txt", 0, overwrite_data)
                .expect("overwrite");
            fs.sync_all().expect("sync after overwrite");
            let diverged = fs.read_file("/doc.txt").expect("read diverged");
            assert_eq!(
                diverged, overwrite_data,
                "current state must show overwritten data, diverging from clone"
            );

            // Rollback to clone restores snapshot-preserved data
            let report = fs
                .rollback_to_snapshot("writable-clone")
                .expect("rollback to clone");
            assert_eq!(report.snapshot.name, "writable-clone");

            let restored = fs.read_file("/doc.txt").expect("read after rollback");
            assert_eq!(
                restored, og_data,
                "rollback to clone must restore origin snapshot data"
            );

            // Clone is writable: new writes diverge from the original snapshot
            fs.write_file("/doc.txt", 0, clone_data)
                .expect("write clone data");
            fs.sync_all().expect("sync clone data");
            let clone_readback = fs.read_file("/doc.txt").expect("read clone write");
            assert_eq!(
                clone_readback, clone_data,
                "clone writes must persist in current state"
            );
            // Drop commits via Drop::do_commit + store.sync_all
        }

        // Phase 2 — reopen: clone-written data survived.
        {
            let fs = reopen_fs(&dir);

            let after_remount = fs.read_file("/doc.txt").expect("read after remount");
            assert_eq!(
                after_remount, clone_data,
                "clone-written data must survive close/reopen"
            );

            // Snapshot and clone metadata also survived
            let ext = fs.list_snapshots_extended();
            let clone_entry = ext
                .iter()
                .find(|d| d.name == "writable-clone")
                .expect("clone must survive remount");
            assert_eq!(clone_entry.kind, SnapshotKind::Clone);
            assert_eq!(clone_entry.origin.as_deref(), Some("origin-snap"));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Snapshot and clone metadata integrity across close/reopen.
    #[test]
    fn snapshot_and_clone_metadata_survive_remount() {
        let dir = temp_dir();
        let data = b"metadata-persistence-data";

        {
            let mut fs = new_fs(&dir);
            seed_file(&mut fs, "/data.bin", data);
            fs.sync_all().expect("sync after write");

            let snap = fs.create_snapshot("snap1").expect("snapshot");
            assert_eq!(snap.name, "snap1");

            let clone = fs.create_clone("clone1", "snap1").expect("clone");
            assert_eq!(clone.origin, "snap1");
        }

        // Reopen and verify snapshot/clone metadata survived.
        {
            let fs = reopen_fs(&dir);

            let snaps = fs.list_snapshots();
            assert_eq!(snaps.len(), 2, "snapshot and clone must survive remount");
            let snap_names: Vec<&str> = snaps.iter().map(|s| s.name.as_str()).collect();
            assert!(
                snap_names.contains(&"snap1"),
                "snap1 must be present: {snap_names:?}"
            );
            assert!(
                snap_names.contains(&"clone1"),
                "clone1 must be present: {snap_names:?}"
            );

            let clones = fs.list_clones();
            assert_eq!(clones.len(), 1, "clone must survive remount");
            assert_eq!(clones[0].name, "clone1");
            assert_eq!(clones[0].origin, "snap1");

            let origin = fs.clone_origin("clone1").expect("origin query");
            assert_eq!(origin, Some("snap1".to_string()));

            // The file data should also survive remount
            let readback = fs.read_file("/data.bin").expect("read after remount");
            assert_eq!(readback, data);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
