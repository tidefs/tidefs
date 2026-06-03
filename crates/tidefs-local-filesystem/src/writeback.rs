//! ## Authority Classification (per docs/cache-authority-model.md)
//!
//! This DirtySet is **Authoritative** for dirty-state classification and
//! commit-group triggers.  It is the single source of truth for "what is
//! dirty" at the writeback accounting layer.  Every mutation falls into
//! exactly one dirty category (Data/Metadata/Catalog).
//!
// writeback.rs — dirty buffer lifecycle and accounting
//
// §4 of the writeback/transaction/durability design spec (#1190).
// The DirtySet is the single source of truth for "what is dirty."
// It tracks dirty state at per-inode granularity and accounts
// dirty bytes across data extents, metadata records, and catalog
// mutations.  The commit_group state machine reads dirty accounting from
// this layer when evaluating auto-sync triggers.

use std::collections::{BTreeMap, BTreeSet};

use tidefs_types_vfs_core::InodeId;

use crate::commit_group::DurabilityClass;

/// Centralised dirty-state index for the writeback layer.
///
/// Every mutation to a filesystem object falls into exactly one of
/// three dirty categories (Data, Metadata, Catalog).  Categories
/// are tracked separately because they drive different durability
/// paths:
///
/// - Data-only dirty: triggers full data+metadata commit (steps 1-7)
/// - Metadata-only dirty: triggers metadata-only commit (steps 3-7)
/// - Catalog dirty: always forces pool-map commit
/// - None dirty: do_commit() returns immediately (unless intent log
///   is non-empty)
#[derive(Clone, Debug, Default)]
pub(crate) struct DirtySet {
    /// Total data dirty bytes (padded record bytes) since last commit.
    pub data_bytes: u64,

    /// Count of metadata mutations (inode attrs, dir ops, etc.) since
    /// last commit.
    pub metadata_ops: u64,

    /// Inodes with any dirty flags (data_dirty, attr_dirty, xattr_dirty,
    /// or is_new).
    pub dirty_inodes: BTreeSet<InodeId>,

    /// Directories with dirty entry mutations (add/remove/rename).
    pub dirty_dirs: BTreeSet<InodeId>,

    /// Whether the derived catalog or pool-map needs a commit.
    pub catalog_dirty: bool,

    /// Total mutation count since last commit (coarse-grain trigger).
    pub dirty_op_count: u64,

    /// Per-inode cumulative dirty byte counts, keyed by InodeId.
    pub per_inode_bytes: BTreeMap<InodeId, u64>,
}

impl DirtySet {
    /// Cache authority classification per docs/cache-authority-model.md.
    /// This DirtySet is Authoritative for dirty-state classification.
    #[allow(dead_code)]
    pub(crate) const CACHE_AUTHORITY_CLASS: &str = "Authoritative";
    /// Return the cache authority classification at runtime.
    #[allow(dead_code)]
    pub fn cache_authority_class(&self) -> &'static str {
        Self::CACHE_AUTHORITY_CLASS
    }

    /// True when no dirty state is tracked.
    pub fn is_clean(&self) -> bool {
        self.data_bytes == 0
            && self.metadata_ops == 0
            && self.dirty_inodes.is_empty()
            && self.dirty_dirs.is_empty()
            && !self.catalog_dirty
            && self.dirty_op_count == 0
    }

    /// Reset all dirty tracking to the empty state.
    /// Called after a successful SYNC phase completes.
    pub fn clear(&mut self) {
        self.data_bytes = 0;
        self.metadata_ops = 0;
        self.dirty_inodes.clear();
        self.dirty_dirs.clear();
        self.catalog_dirty = false;
        self.dirty_op_count = 0;
        self.per_inode_bytes.clear();
    }

    #[allow(dead_code)] // INTENT: writeback/dirty-set types for planned writeback daemon integration
    /// Derive the durability class from the current dirty profile.
    ///
    /// - Data bytes present or catalog dirty → DataAndMetadata
    /// - Only metadata operations          → MetadataOnly
    /// - Clean (caller gates on is_clean() + intent log separately)
    pub fn durability_class(&self) -> DurabilityClass {
        if self.is_clean() {
            return DurabilityClass::MetadataOnly;
        }
        if self.data_bytes > 0 || self.catalog_dirty {
            return DurabilityClass::DataAndMetadata;
        }
        DurabilityClass::MetadataOnly
    }

    // ── mutation accounting helpers ────────────────────────────
    #[allow(dead_code)] // INTENT: writeback/dirty-set types for planned writeback daemon integration
    /// Record a data write (write(2), truncate, fallocate).
    /// `bytes` is the padded record size written to the data
    /// SegmentStore.
    pub fn record_data_write(&mut self, inode_id: InodeId, bytes: u64) {
        self.data_bytes = self.data_bytes.saturating_add(bytes);
        self.dirty_inodes.insert(inode_id);
        self.dirty_op_count = self.dirty_op_count.saturating_add(1);
        let entry = self.per_inode_bytes.entry(inode_id).or_insert(0);
        *entry = entry.saturating_add(bytes);
    }
    #[allow(dead_code)] // INTENT: writeback/dirty-set types for planned writeback daemon integration
    /// Record a metadata mutation (chmod, chown, utimes, setxattr,
    /// snapshot create, etc.) on `inode_id`.
    pub fn record_metadata_op(&mut self, inode_id: InodeId) {
        self.metadata_ops = self.metadata_ops.saturating_add(1);
        self.dirty_inodes.insert(inode_id);
        self.dirty_op_count = self.dirty_op_count.saturating_add(1);
    }
    #[allow(dead_code)] // INTENT: writeback/dirty-set types for planned writeback daemon integration
    /// Record a directory-entry mutation (mkdir, unlink, rename)
    /// on the parent directory `inode_id`.
    pub fn record_dir_op(&mut self, inode_id: InodeId) {
        self.metadata_ops = self.metadata_ops.saturating_add(1);
        self.dirty_dirs.insert(inode_id);
        self.dirty_op_count = self.dirty_op_count.saturating_add(1);
    }
    #[allow(dead_code)] // INTENT: writeback/dirty-set types for planned writeback daemon integration
    /// Record a content mutation (truncate that frees extents,
    /// punch_hole) without byte count change.
    pub fn record_content_mutation(&mut self, inode_id: InodeId) {
        self.dirty_inodes.insert(inode_id);
        self.dirty_op_count = self.dirty_op_count.saturating_add(1);
    }
    #[allow(dead_code)] // INTENT: writeback/dirty-set types for planned writeback daemon integration
    /// Mark the catalog as needing a pool-map commit.
    pub fn mark_catalog_dirty(&mut self) {
        self.catalog_dirty = true;
        self.dirty_op_count = self.dirty_op_count.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> InodeId {
        InodeId::new(n)
    }

    #[test]
    fn dirty_set_starts_clean() {
        let ds = DirtySet::default();
        assert!(ds.is_clean());
        assert_eq!(ds.durability_class(), DurabilityClass::MetadataOnly);
    }

    #[test]
    fn data_write_makes_dirty() {
        let mut ds = DirtySet::default();
        ds.record_data_write(id(1), 4096);
        assert!(!ds.is_clean());
        assert_eq!(ds.data_bytes, 4096);
        assert!(ds.dirty_inodes.contains(&id(1)));
        assert_eq!(ds.dirty_op_count, 1);
        assert_eq!(ds.per_inode_bytes[&id(1)], 4096);
    }

    #[test]
    fn data_write_yields_data_and_metadata_class() {
        let mut ds = DirtySet::default();
        ds.record_data_write(id(1), 4096);
        assert_eq!(ds.durability_class(), DurabilityClass::DataAndMetadata);
    }

    #[test]
    fn metadata_only_yields_metadata_only_class() {
        let mut ds = DirtySet::default();
        ds.record_metadata_op(id(2));
        assert!(ds.dirty_inodes.contains(&id(2)));
        assert_eq!(ds.metadata_ops, 1);
        assert_eq!(ds.durability_class(), DurabilityClass::MetadataOnly);
    }

    #[test]
    fn dir_op_tracks_dirty_dirs() {
        let mut ds = DirtySet::default();
        ds.record_dir_op(id(3));
        assert!(ds.dirty_dirs.contains(&id(3)));
        assert_eq!(ds.metadata_ops, 1);
        assert_eq!(ds.dirty_op_count, 1);
    }

    #[test]
    fn catalog_dirty_forces_data_and_metadata() {
        let mut ds = DirtySet::default();
        ds.mark_catalog_dirty();
        assert!(ds.catalog_dirty);
        assert_eq!(ds.durability_class(), DurabilityClass::DataAndMetadata);
    }

    #[test]
    fn clear_resets_everything() {
        let mut ds = DirtySet::default();
        ds.record_data_write(id(1), 4096);
        ds.record_metadata_op(id(2));
        ds.record_dir_op(id(3));
        ds.mark_catalog_dirty();
        assert!(!ds.is_clean());
        ds.clear();
        assert!(ds.is_clean());
        assert_eq!(ds.data_bytes, 0);
        assert_eq!(ds.metadata_ops, 0);
        assert!(ds.dirty_inodes.is_empty());
        assert!(ds.dirty_dirs.is_empty());
        assert!(!ds.catalog_dirty);
        assert_eq!(ds.dirty_op_count, 0);
        assert!(ds.per_inode_bytes.is_empty());
    }

    #[test]
    fn saturation_handles_extreme_counts() {
        let mut ds = DirtySet {
            data_bytes: u64::MAX,
            ..DirtySet::default()
        };
        ds.record_data_write(id(1), 1);
        assert_eq!(ds.data_bytes, u64::MAX);
    }
}

// ── WritebackPolicy ────────────────────────────────────────────────

use std::time::Duration;

#[derive(Clone, Debug)]
pub(crate) struct WritebackPolicy {
    pub dirty_age_threshold: Duration,
    pub dirty_page_count_high_watermark: usize,
    pub max_concurrent_flushes: usize,
}

impl Default for WritebackPolicy {
    fn default() -> Self {
        Self {
            dirty_age_threshold: Duration::from_secs(5),
            dirty_page_count_high_watermark: 512,
            max_concurrent_flushes: 4,
        }
    }
}

impl WritebackPolicy {
    #[allow(dead_code)] // INTENT: writeback/dirty-set types for planned writeback daemon integration
    pub fn new(t: Duration, w: usize, c: usize) -> Self {
        Self {
            dirty_age_threshold: t,
            dirty_page_count_high_watermark: w,
            max_concurrent_flushes: c,
        }
    }

    pub fn select_pages(
        &self,
        dirty_ranges: &[(InodeId, Vec<crate::dirty_page_tracker::DirtyRange>)],
    ) -> Vec<(InodeId, crate::dirty_page_tracker::DirtyRange)> {
        let total: usize = dirty_ranges.iter().map(|(_, rs)| rs.len()).sum();
        let mut all: Vec<_> = dirty_ranges
            .iter()
            .flat_map(|(ino, rs)| rs.iter().map(move |r| (*ino, r.clone())))
            .collect();
        all.sort_by_key(|(_, r)| r.dirty_since);

        let cap = self.max_concurrent_flushes;
        let mut sel = Vec::with_capacity(cap);
        if total >= self.dirty_page_count_high_watermark {
            for (ino, r) in all {
                if sel.len() >= cap {
                    break;
                }
                sel.push((ino, r));
            }
        } else {
            for (ino, r) in all {
                if sel.len() >= cap {
                    break;
                }
                if r.older_than(self.dirty_age_threshold) {
                    sel.push((ino, r));
                }
            }
        }
        sel
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::dirty_page_tracker::DirtyRange;
    fn id(n: u64) -> InodeId {
        InodeId::new(n)
    }
    fn rng(off: u64, len: u64, age: u64) -> DirtyRange {
        DirtyRange {
            offset: off,
            length: len,
            dirty_since: std::time::Instant::now()
                .checked_sub(Duration::from_secs(age))
                .unwrap(),
        }
    }
    #[test]
    fn selects_older_pages() {
        let p = WritebackPolicy::new(Duration::from_secs(5), 512, 4);
        assert_eq!(
            p.select_pages(&[(id(1), vec![rng(0, 4096, 10), rng(4096, 4096, 1)])])
                .len(),
            1
        );
    }
    #[test]
    fn skips_young_pages() {
        let p = WritebackPolicy::new(Duration::from_secs(30), 512, 4);
        assert!(p
            .select_pages(&[(id(1), vec![rng(0, 4096, 10)])])
            .is_empty());
    }
    #[test]
    fn high_watermark_flushes_all() {
        let p = WritebackPolicy::new(Duration::from_secs(60), 2, 4);
        assert_eq!(
            p.select_pages(&[(id(1), vec![rng(0, 4096, 1), rng(4096, 4096, 2)])])
                .len(),
            2
        );
    }
    #[test]
    fn respects_max_concurrent() {
        let p = WritebackPolicy::new(Duration::from_secs(1), 1, 2);
        assert_eq!(
            p.select_pages(&[(
                id(1),
                vec![rng(0, 4096, 10), rng(4096, 4096, 11), rng(8192, 4096, 12)]
            )])
            .len(),
            2
        );
    }
    #[test]
    fn oldest_first() {
        let p = WritebackPolicy::new(Duration::from_secs(1), 10, 3);
        let s = p.select_pages(&[
            (id(1), vec![rng(0, 4096, 5)]),
            (id(2), vec![rng(0, 4096, 20)]),
            (id(3), vec![rng(0, 4096, 10)]),
        ]);
        assert_eq!(s[0].0, id(2));
        assert_eq!(s[1].0, id(3));
        assert_eq!(s[2].0, id(1));
    }
    #[test]
    fn empty_returns_empty() {
        assert!(WritebackPolicy::default().select_pages(&[]).is_empty());
    }
}
