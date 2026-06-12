#![forbid(unsafe_code)]

//! Reclaim queue runtime for TideFS: B+tree-backed refcount-delta
//! deferred reclamation plus the writeback engine that drains dirty
//! page-cache extents to the object store.
//!
//! ## Modules
//!
//! - **B+tree reclaim queue** ([`BPlusTreeReclaimQueue`]): persistent,
//!   deterministic key-order queue for [`ReclaimQueueEntry`] values.
//! - **Writeback engine** ([`ReclaimQueue`], [`ReclaimScanner`],
//!   [`ReclaimFlush`], [`ReclaimLoop`]): collects dirty page-cache
//!   extents, sorts them by (object, offset), flushes batches to an
//!   object store via the [`WriteSink`] trait, and transitions extents
//!   to clean on completion.

extern crate alloc;

use alloc::vec::Vec;

use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};
use tidefs_btree::{BPlusTree, BTreeError};
use tidefs_types_reclaim_queue_core::{
    ObjectKey, QueueFamily, ReclaimQueueEntry, RECLAIM_QUEUE_SPEC,
};

pub mod writeback;

pub mod evacuation;
/// Segment liveness tracking for dead-segment reclamation.
pub mod segment_liveness;

/// Dead-object reclaim queue with commit_group-anchored reclamation eligibility.
pub mod dead_object_queue;

/// Persistent freed-extent reclaim-queue ledger for the space allocator.
pub mod freed_extent_ledger;

// Re-export writeback engine types at crate root for convenient access.
pub use writeback::{
    DirtyExtent, DirtyExtentKey, DirtyPageCounter, ReclaimConfig, ReclaimFlush, ReclaimLoop,
    ReclaimQueue, ReclaimScanner, WriteSink,
};

// Re-export segment liveness types at crate root.
pub use segment_liveness::{
    ReclaimQueueStorage, SegmentLivenessDeserializeError, SegmentLivenessEntry,
    SegmentLivenessPersistError, SegmentLivenessQueue,
};

// Re-export dead-object queue types at crate root.
pub use dead_object_queue::{
    dead_object_entry_with_placement_ref, dead_object_policy_from_placement_ref,
    replacement_receipt_from_placement_ref, DeadObjectQueueDecodeError, DeadObjectReclaimQueue,
    PlacementReceiptRefReclaimError,
};

// Re-export freed-extent ledger types at crate root.
pub use freed_extent_ledger::{
    FreedExtent, PersistenceMode, ReclaimQueueLedger, ReclaimQueueLedgerConfig,
    ReclaimQueueLedgerDecodeError,
};
/// Design spec reference constant for runtime assertions.
pub const RECLAIM_QUEUE_SPEC_REF: &str = RECLAIM_QUEUE_SPEC;

/// Branching factor for internal B+tree nodes.
const INTERNAL_FANOUT: usize = 64;

/// Branching factor for leaf B+tree nodes.
const LEAF_FANOUT: usize = 64;

// ---------------------------------------------------------------------------
// ReclaimQueueStats
// ---------------------------------------------------------------------------

/// Per-family entry counts for a reclaim queue.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReclaimQueueStats {
    pub total_entries: usize,
    pub extent_entries: usize,
    pub locator_entries: usize,
    pub rebake_entries: usize,
    pub inode_tombstone_entries: usize,
}

impl ReclaimQueueStats {
    pub const ZERO: Self = ReclaimQueueStats {
        total_entries: 0,
        extent_entries: 0,
        locator_entries: 0,
        rebake_entries: 0,
        inode_tombstone_entries: 0,
    };

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.total_entries == 0
    }

    #[must_use]
    pub fn family_sum(self) -> usize {
        self.extent_entries
            + self.locator_entries
            + self.rebake_entries
            + self.inode_tombstone_entries
    }

    #[must_use]
    pub const fn count_for_family(self, family: QueueFamily) -> usize {
        match family {
            QueueFamily::Extent => self.extent_entries,
            QueueFamily::Locator => self.locator_entries,
            QueueFamily::Rebake => self.rebake_entries,
            QueueFamily::InodeTombstone => self.inode_tombstone_entries,
        }
    }
}

// ---------------------------------------------------------------------------
// ReclaimQueueInsertOutcome
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReclaimQueueInsertOutcome {
    Inserted,
    Replaced { previous: ReclaimQueueEntry },
}

impl ReclaimQueueInsertOutcome {
    #[must_use]
    pub fn is_inserted(self) -> bool {
        matches!(self, Self::Inserted)
    }

    #[must_use]
    pub fn is_replaced(self) -> bool {
        matches!(self, Self::Replaced { .. })
    }

    #[must_use]
    pub fn previous_entry(self) -> Option<ReclaimQueueEntry> {
        match self {
            Self::Inserted => None,
            Self::Replaced { previous } => Some(previous),
        }
    }
}

// ---------------------------------------------------------------------------
// ReclaimQueueDrainPlan
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReclaimQueueDrainItem {
    pub object_key: ObjectKey,
    pub entry: ReclaimQueueEntry,
}

impl ReclaimQueueDrainItem {
    #[must_use]
    pub const fn new(object_key: ObjectKey, entry: ReclaimQueueEntry) -> Self {
        Self { object_key, entry }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReclaimQueueDrainPlan {
    pub requested_limit: usize,
    pub entries: Vec<ReclaimQueueDrainItem>,
    pub remaining_entries: usize,
}

impl ReclaimQueueDrainPlan {
    #[must_use]
    pub fn empty(requested_limit: usize, queued_entries: usize) -> Self {
        Self {
            requested_limit,
            entries: Vec::new(),
            remaining_entries: queued_entries,
        }
    }

    #[must_use]
    pub fn from_entries(
        requested_limit: usize,
        queued_entries: usize,
        entries: Vec<ReclaimQueueDrainItem>,
    ) -> Self {
        let remaining_entries = queued_entries.saturating_sub(entries.len());
        Self {
            requested_limit,
            entries,
            remaining_entries,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn last_key(&self) -> Option<ObjectKey> {
        self.entries.last().map(|item| item.object_key)
    }
}

// ---------------------------------------------------------------------------
// BPlusTreeReclaimQueue
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct BPlusTreeReclaimQueue {
    tree: BPlusTree<ObjectKey, ReclaimQueueEntry, LEAF_FANOUT, INTERNAL_FANOUT>,
}

impl BPlusTreeReclaimQueue {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: BPlusTree::new(),
        }
    }

    pub fn insert_with_outcome(&mut self, entry: ReclaimQueueEntry) -> ReclaimQueueInsertOutcome {
        match self.tree.insert(entry.object_key, entry) {
            None => ReclaimQueueInsertOutcome::Inserted,
            Some(previous) => ReclaimQueueInsertOutcome::Replaced { previous },
        }
    }

    pub fn insert(&mut self, entry: ReclaimQueueEntry) -> bool {
        self.insert_with_outcome(entry).is_inserted()
    }

    pub fn delete(&mut self, key: &ObjectKey) -> bool {
        self.tree.delete(key).is_some()
    }

    pub fn clear(&mut self) {
        self.tree.clear();
    }

    #[must_use]
    pub fn contains(&self, key: &ObjectKey) -> bool {
        self.tree.contains_key(key)
    }

    #[must_use]
    pub fn get(&self, key: &ObjectKey) -> Option<ReclaimQueueEntry> {
        self.tree.get(key).copied()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    #[must_use]
    pub fn entries(&self) -> Vec<(ObjectKey, ReclaimQueueEntry)> {
        self.tree.entries()
    }

    #[must_use]
    pub fn dequeue_next(
        &self,
        start_after: Option<&ObjectKey>,
    ) -> Option<(ObjectKey, ReclaimQueueEntry)> {
        if self.is_empty() {
            return None;
        }
        let all = self.tree.entries();
        let idx = match start_after {
            None => 0,
            Some(k) => match all.binary_search_by_key(&k, |(qk, _)| qk) {
                Ok(i) => i.saturating_add(1),
                Err(i) => i,
            },
        };
        if idx >= all.len() {
            None
        } else {
            Some(all[idx])
        }
    }

    #[must_use]
    pub fn dequeue_batch(
        &self,
        start_after: Option<&ObjectKey>,
        limit: usize,
    ) -> Vec<(ObjectKey, ReclaimQueueEntry)> {
        if self.is_empty() || limit == 0 {
            return Vec::new();
        }
        let all = self.tree.entries();
        let idx = match start_after {
            None => 0,
            Some(k) => match all.binary_search_by_key(&k, |(qk, _)| qk) {
                Ok(i) => i.saturating_add(1),
                Err(i) => i,
            },
        };
        if idx >= all.len() {
            return Vec::new();
        }
        let end = (idx.saturating_add(limit)).min(all.len());
        all[idx..end].to_vec()
    }

    #[must_use]
    pub fn plan_bounded_drain(&self, limit: usize) -> ReclaimQueueDrainPlan {
        self.plan_bounded_drain_after(None, limit)
    }

    #[must_use]
    pub fn plan_bounded_drain_after(
        &self,
        start_after: Option<&ObjectKey>,
        limit: usize,
    ) -> ReclaimQueueDrainPlan {
        let queued_entries = self.len();
        if queued_entries == 0 || limit == 0 {
            return ReclaimQueueDrainPlan::empty(limit, queued_entries);
        }

        let entries = self
            .dequeue_batch(start_after, limit)
            .into_iter()
            .map(|(object_key, entry)| ReclaimQueueDrainItem::new(object_key, entry))
            .collect();
        ReclaimQueueDrainPlan::from_entries(limit, queued_entries, entries)
    }

    #[must_use]
    pub fn dequeue_by_family(
        &self,
        family: QueueFamily,
        start_after: Option<&ObjectKey>,
        limit: usize,
    ) -> Vec<(ObjectKey, ReclaimQueueEntry)> {
        if self.is_empty() || limit == 0 {
            return Vec::new();
        }
        let all = self.tree.entries();
        let start_idx = match start_after {
            None => 0,
            Some(k) => match all.binary_search_by_key(&k, |(qk, _)| qk) {
                Ok(i) => i.saturating_add(1),
                Err(i) => i,
            },
        };

        let mut result = Vec::with_capacity(limit.min(16384));
        for &(key, entry) in &all[start_idx..] {
            if entry.family == family {
                result.push((key, entry));
                if result.len() >= limit {
                    break;
                }
            }
        }
        result
    }

    #[must_use]
    pub fn stats(&self) -> ReclaimQueueStats {
        let mut s = ReclaimQueueStats::ZERO;
        for (_, entry) in self.tree.entries().iter() {
            s.total_entries += 1;
            match entry.family {
                QueueFamily::Extent => s.extent_entries += 1,
                QueueFamily::Locator => s.locator_entries += 1,
                QueueFamily::Rebake => s.rebake_entries += 1,
                QueueFamily::InodeTombstone => s.inode_tombstone_entries += 1,
            }
        }
        s
    }

    #[must_use]
    pub fn entries_by_family(&self, family: QueueFamily) -> Vec<(ObjectKey, ReclaimQueueEntry)> {
        self.tree
            .entries()
            .iter()
            .filter(|(_, e)| e.family == family)
            .copied()
            .collect()
    }

    #[must_use]
    pub fn family_count(&self, family: QueueFamily) -> usize {
        self.tree
            .entries()
            .iter()
            .filter(|(_, e)| e.family == family)
            .count()
    }

    #[must_use]
    pub fn total_delta(&self) -> i64 {
        self.tree
            .entries()
            .iter()
            .fold(0i64, |acc, (_, e)| acc.saturating_add(e.delta))
    }

    #[must_use]
    pub fn total_delta_abs(&self) -> u64 {
        self.tree
            .entries()
            .iter()
            .fold(0u64, |acc, (_, e)| acc.saturating_add(e.delta_abs()))
    }

    pub fn compact_if_needed(&mut self, threshold: f64) -> bool {
        self.tree.maybe_compact(threshold)
    }

    #[must_use]
    pub fn fill_percent(&self) -> f64 {
        self.tree.fill_percent()
    }

    #[must_use]
    pub fn depth(&self) -> u8 {
        self.tree.depth()
    }

    #[must_use]
    pub fn node_count(&self) -> usize {
        self.tree.node_count()
    }

    pub fn validate(&self) -> Result<(), BTreeError> {
        self.tree.validate()
    }
    // ------------------------------------------------------------------
    // Binary encoding
    // ------------------------------------------------------------------

    /// Magic bytes identifying a reclaim-queue payload.
    const MAGIC: &'static [u8; 4] = b"RCLM";

    /// Current binary format version.
    const FORMAT_VERSION: u32 = 1;

    /// Schema family identifier for reclaim-queue BLAKE3 domain context.
    const FAMILY_ID: SchemaFamilyId = SchemaFamilyId(0x5243_4C4D_0000_0001);

    /// Schema type identifier for reclaim-queue format v1.
    const TYPE_ID: SchemaTypeId = SchemaTypeId(1);

    /// Schema version for reclaim-queue format v1.0.
    const VERSION: SchemaVersion = SchemaVersion::new(1, 0);

    /// Domain tag for reclaim-queue payload integrity.
    const DOMAIN_TAG: DomainTag = DomainTag::SectionBody;

    /// Encode the entire queue to a byte vector with a BLAKE3 integrity footer.
    ///
    /// Format (little-endian):
    /// - 4 bytes: magic `RCLM`
    /// - 4 bytes: format version (u32)
    /// - 4 bytes: entry count (u32)
    /// - N * 42 bytes: per-entry encoded records
    /// - 32 bytes: BLAKE3 domain-separated digest over all preceding bytes
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let entries = self.entries();
        let count = entries.len() as u32;

        // Header: magic (4) + version (4) + count (4) = 12 bytes
        // Entries: N * 42 bytes
        // Footer: 32 bytes BLAKE3
        let body_len = 12usize
            .checked_add(count as usize * ReclaimQueueEntry::ENCODED_SIZE)
            .expect("reclaim queue too large to encode");
        let mut buf = Vec::with_capacity(body_len + 32);

        // Header
        buf.extend_from_slice(Self::MAGIC);
        buf.extend_from_slice(&Self::FORMAT_VERSION.to_le_bytes());
        buf.extend_from_slice(&count.to_le_bytes());

        // Entries (key not serialized separately; it is embedded in the entry)
        for (_key, entry) in &entries {
            buf.extend_from_slice(&entry.encode());
        }

        // BLAKE3 integrity footer over all preceding bytes
        let digest = blake3_domain_digest(
            &buf,
            Self::FAMILY_ID,
            Self::TYPE_ID,
            Self::VERSION,
            Self::DOMAIN_TAG,
        );
        buf.extend_from_slice(&digest);

        buf
    }

    /// Decode a queue from bytes previously produced by [`encode`](Self::encode).
    ///
    /// # Errors
    ///
    /// Returns [`ReclaimQueueDecodeError`] if the buffer is truncated, has
    /// an invalid magic, an unsupported version, a corrupt entry, or a
    /// BLAKE3 integrity footer mismatch.
    pub fn decode(data: &[u8]) -> Result<Self, ReclaimQueueDecodeError> {
        // Minimum size: header (12) + footer (32) = 44 bytes
        if data.len() < 44 {
            return Err(ReclaimQueueDecodeError::Truncated);
        }

        // Verify magic
        let magic = &data[0..4];
        if magic != Self::MAGIC {
            return Err(ReclaimQueueDecodeError::InvalidMagic);
        }

        // Verify version
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != Self::FORMAT_VERSION {
            return Err(ReclaimQueueDecodeError::UnsupportedVersion {
                found: version,
                expected: Self::FORMAT_VERSION,
            });
        }

        // Verify BLAKE3 integrity footer
        let body_len = data.len() - 32;
        let expected_digest = blake3_domain_digest(
            &data[..body_len],
            Self::FAMILY_ID,
            Self::TYPE_ID,
            Self::VERSION,
            Self::DOMAIN_TAG,
        );
        let actual_digest: [u8; 32] = data[body_len..].try_into().unwrap();
        if expected_digest != actual_digest {
            return Err(ReclaimQueueDecodeError::IntegrityFooterMismatch);
        }

        // Parse entry count
        let count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let expected_body_len = 12usize
            .checked_add(
                count
                    .checked_mul(ReclaimQueueEntry::ENCODED_SIZE)
                    .ok_or(ReclaimQueueDecodeError::Truncated)?,
            )
            .ok_or(ReclaimQueueDecodeError::Truncated)?;

        if body_len < expected_body_len {
            return Err(ReclaimQueueDecodeError::Truncated);
        }

        // Parse entries
        let mut queue = Self::new();
        for i in 0..count {
            let offset = 12 + i * ReclaimQueueEntry::ENCODED_SIZE;
            let entry_bytes: &[u8; ReclaimQueueEntry::ENCODED_SIZE] = data
                [offset..offset + ReclaimQueueEntry::ENCODED_SIZE]
                .try_into()
                .map_err(|_| ReclaimQueueDecodeError::Truncated)?;
            let entry = ReclaimQueueEntry::decode(entry_bytes)
                .map_err(|e| ReclaimQueueDecodeError::EntryDecode(alloc::format!("{e}")))?;
            queue.insert(entry);
        }

        Ok(queue)
    }

    /// Estimate the serialized byte size without allocating.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let count = self.len();
        12 + count * ReclaimQueueEntry::ENCODED_SIZE + 32
    }
}

impl Default for BPlusTreeReclaimQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for BPlusTreeReclaimQueue {
    fn eq(&self, other: &Self) -> bool {
        self.entries() == other.entries()
    }
}

impl Eq for BPlusTreeReclaimQueue {}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ReclaimQueueDecodeError -- queue-level decode failure
// ---------------------------------------------------------------------------

/// Errors that can occur when decoding a [`BPlusTreeReclaimQueue`] from
/// its wire-format encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReclaimQueueDecodeError {
    /// Data is shorter than the minimum header + footer.
    Truncated,
    /// Magic bytes do not match the expected `RCLM`.
    InvalidMagic,
    /// Format version is not supported.
    UnsupportedVersion { found: u32, expected: u32 },
    /// A per-entry decode failed.
    EntryDecode(String),
    /// The BLAKE3 integrity footer did not verify.
    IntegrityFooterMismatch,
}

impl core::fmt::Display for ReclaimQueueDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated reclaim-queue data"),
            Self::InvalidMagic => f.write_str("invalid reclaim-queue magic bytes"),
            Self::UnsupportedVersion { found, expected } => {
                write!(
                    f,
                    "unsupported reclaim-queue version: found {found}, expected {expected}"
                )
            }
            Self::EntryDecode(msg) => write!(f, "reclaim-queue entry decode error: {msg}"),
            Self::IntegrityFooterMismatch => {
                f.write_str("reclaim-queue BLAKE3 integrity footer mismatch")
            }
        }
    }
}

// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u8, delta: i64, family: QueueFamily) -> ReclaimQueueEntry {
        let mut key = [0u8; 32];
        key[0] = id;
        ReclaimQueueEntry::new(ObjectKey(key), delta, family)
    }

    fn key(id: u8) -> ObjectKey {
        let mut k = [0u8; 32];
        k[0] = id;
        ObjectKey(k)
    }

    #[test]
    fn insert_and_lookup() {
        let mut q = BPlusTreeReclaimQueue::new();
        let e = entry(1, -1, QueueFamily::Extent);
        assert!(q.insert(e));
        assert!(q.contains(&e.object_key));
        assert_eq!(q.get(&e.object_key), Some(e));
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());
    }

    #[test]
    fn insert_duplicate_key_replaces() {
        let mut q = BPlusTreeReclaimQueue::new();
        let e1 = entry(42, -1, QueueFamily::Extent);
        let e2 = entry(42, -2, QueueFamily::Locator);
        assert!(q.insert(e1));
        assert!(!q.insert(e2));
        assert_eq!(q.len(), 1);
        assert_eq!(q.get(&key(42)), Some(e2));
    }

    #[test]
    fn insert_with_outcome_reports_replacement_entry() {
        let mut q = BPlusTreeReclaimQueue::new();
        let e1 = entry(42, -1, QueueFamily::Extent);
        let e2 = entry(42, -2, QueueFamily::Locator);

        assert_eq!(
            q.insert_with_outcome(e1),
            ReclaimQueueInsertOutcome::Inserted
        );

        let outcome = q.insert_with_outcome(e2);
        assert!(outcome.is_replaced());
        assert_eq!(outcome.previous_entry(), Some(e1));
        assert_eq!(q.len(), 1);
        assert_eq!(q.get(&key(42)), Some(e2));
    }

    #[test]
    fn duplicate_replacement_preserves_key_order_and_stats() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(30, -1, QueueFamily::Extent));
        q.insert(entry(10, -1, QueueFamily::Locator));
        q.insert(entry(20, -1, QueueFamily::Rebake));

        let replacement = entry(20, -4, QueueFamily::InodeTombstone);
        assert_eq!(
            q.insert_with_outcome(replacement),
            ReclaimQueueInsertOutcome::Replaced {
                previous: entry(20, -1, QueueFamily::Rebake)
            }
        );

        let ids: Vec<u8> = q.entries().iter().map(|(key, _)| key.0[0]).collect();
        assert_eq!(ids, [10, 20, 30]);
        assert_eq!(q.len(), 3);
        assert_eq!(q.get(&key(20)), Some(replacement));

        let stats = q.stats();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.locator_entries, 1);
        assert_eq!(stats.inode_tombstone_entries, 1);
        assert_eq!(stats.rebake_entries, 0);
    }

    #[test]
    fn delete_existing() {
        let mut q = BPlusTreeReclaimQueue::new();
        let e = entry(42, -5, QueueFamily::Locator);
        q.insert(e);
        assert!(q.delete(&e.object_key));
        assert!(!q.contains(&e.object_key));
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
    }

    #[test]
    fn delete_nonexistent() {
        let mut q = BPlusTreeReclaimQueue::new();
        assert!(!q.delete(&key(99)));
    }

    #[test]
    fn clear_empty() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.clear();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn clear_nonempty() {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 0..10u8 {
            q.insert(entry(i, -1, QueueFamily::Extent));
        }
        q.clear();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn get_nonexistent() {
        let q = BPlusTreeReclaimQueue::new();
        assert_eq!(q.get(&key(1)), None);
    }

    #[test]
    fn dequeue_next_empty() {
        let q = BPlusTreeReclaimQueue::new();
        assert_eq!(q.dequeue_next(None), None);
        assert_eq!(q.dequeue_next(Some(&key(1))), None);
    }

    #[test]
    fn dequeue_next_first() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(5, -1, QueueFamily::Extent));
        let result = q.dequeue_next(None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0 .0[0], 5);
    }

    #[test]
    fn dequeue_next_after_existing() {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 1..=10u8 {
            q.insert(entry(i, -1, QueueFamily::Extent));
        }
        let result = q.dequeue_next(Some(&key(5)));
        assert!(result.is_some());
        assert_eq!(result.unwrap().0 .0[0], 6);
    }

    #[test]
    fn dequeue_next_after_last() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -1, QueueFamily::Extent));
        assert_eq!(q.dequeue_next(Some(&key(1))), None);
    }

    #[test]
    fn dequeue_next_after_missing() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(10, -1, QueueFamily::Extent));
        let result = q.dequeue_next(Some(&key(5)));
        assert!(result.is_some());
        assert_eq!(result.unwrap().0 .0[0], 10);
    }

    #[test]
    fn dequeue_batch_empty() {
        let q = BPlusTreeReclaimQueue::new();
        assert!(q.dequeue_batch(None, 10).is_empty());
    }

    #[test]
    fn dequeue_batch_zero_limit() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -1, QueueFamily::Extent));
        assert!(q.dequeue_batch(None, 0).is_empty());
    }

    #[test]
    fn dequeue_batch_basic() {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 1..=10u8 {
            q.insert(entry(i, -1, QueueFamily::Extent));
        }
        let batch = q.dequeue_batch(None, 5);
        assert_eq!(batch.len(), 5);
        assert_eq!(batch[0].0 .0[0], 1);
        assert_eq!(batch[4].0 .0[0], 5);
    }

    #[test]
    fn dequeue_batch_after_cursor() {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 1..=10u8 {
            q.insert(entry(i, -1, QueueFamily::Extent));
        }
        let batch = q.dequeue_batch(Some(&key(5)), 5);
        assert_eq!(batch.len(), 5);
        assert_eq!(batch[0].0 .0[0], 6);
        assert_eq!(batch[4].0 .0[0], 10);
    }

    #[test]
    fn dequeue_batch_truncated() {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 1..=3u8 {
            q.insert(entry(i, -1, QueueFamily::Extent));
        }
        let batch = q.dequeue_batch(None, 10);
        assert_eq!(batch.len(), 3);
    }

    #[test]
    fn dequeue_batch_after_last() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -1, QueueFamily::Extent));
        assert!(q.dequeue_batch(Some(&key(1)), 5).is_empty());
    }

    #[test]
    fn dequeue_batch_large() {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 0..200u8 {
            q.insert(entry(i, -1, QueueFamily::Extent));
        }
        let batch = q.dequeue_batch(None, 150);
        assert_eq!(batch.len(), 150);
        assert_eq!(batch[0].0 .0[0], 0);
        assert_eq!(batch[149].0 .0[0], 149);
    }

    #[test]
    fn plan_bounded_drain_empty_queue_is_noop() {
        let q = BPlusTreeReclaimQueue::new();
        let plan = q.plan_bounded_drain(8);
        assert_eq!(plan.requested_limit, 8);
        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);
        assert_eq!(plan.remaining_entries, 0);
        assert_eq!(plan.last_key(), None);
    }

    #[test]
    fn plan_bounded_drain_zero_limit_selects_nothing() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(20, -1, QueueFamily::Extent));
        q.insert(entry(10, -1, QueueFamily::Locator));
        let plan = q.plan_bounded_drain(0);
        assert_eq!(plan.requested_limit, 0);
        assert!(plan.is_empty());
        assert_eq!(plan.remaining_entries, 2);
        assert_eq!(plan.last_key(), None);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn plan_bounded_drain_respects_limit_and_key_order() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(30, -1, QueueFamily::Extent));
        q.insert(entry(10, -2, QueueFamily::Locator));
        q.insert(entry(20, -3, QueueFamily::Rebake));
        let plan = q.plan_bounded_drain(2);
        let ids: Vec<u8> = plan
            .entries
            .iter()
            .map(|item| item.object_key.0[0])
            .collect();
        assert_eq!(ids, [10, 20]);
        assert_eq!(plan.requested_limit, 2);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.remaining_entries, 1);
        assert_eq!(plan.last_key(), Some(key(20)));
        assert_eq!(plan.entries[0].entry, entry(10, -2, QueueFamily::Locator));
        assert_eq!(plan.entries[1].entry, entry(20, -3, QueueFamily::Rebake));
    }

    #[test]
    fn plan_bounded_drain_after_cursor_uses_strictly_later_keys() {
        let mut q = BPlusTreeReclaimQueue::new();
        for id in [40, 10, 30, 20] {
            q.insert(entry(id, -1, QueueFamily::Extent));
        }
        let plan = q.plan_bounded_drain_after(Some(&key(20)), 2);
        let ids: Vec<u8> = plan
            .entries
            .iter()
            .map(|item| item.object_key.0[0])
            .collect();
        assert_eq!(ids, [30, 40]);
        assert_eq!(plan.requested_limit, 2);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.remaining_entries, 2);
        assert_eq!(plan.last_key(), Some(key(40)));
    }

    #[test]
    fn plan_bounded_drain_is_non_mutating_and_preserves_stats() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -1, QueueFamily::Extent));
        q.insert(entry(2, -1, QueueFamily::Locator));
        q.insert(entry(3, -1, QueueFamily::InodeTombstone));
        let before = q.stats();
        let plan = q.plan_bounded_drain(10);
        assert_eq!(plan.len(), 3);
        assert_eq!(plan.remaining_entries, 0);
        assert_eq!(q.len(), 3);
        assert_eq!(q.stats(), before);
        assert_eq!(q.stats().family_sum(), q.stats().total_entries);
    }

    #[test]
    fn dequeue_by_family_filters_correctly() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -1, QueueFamily::Extent));
        q.insert(entry(2, -2, QueueFamily::Locator));
        q.insert(entry(3, -1, QueueFamily::Extent));
        q.insert(entry(4, -1, QueueFamily::Rebake));
        q.insert(entry(5, -1, QueueFamily::Extent));
        let extents = q.dequeue_by_family(QueueFamily::Extent, None, 10);
        assert_eq!(extents.len(), 3);
        for (_, e) in &extents {
            assert_eq!(e.family, QueueFamily::Extent);
        }
        let locators = q.dequeue_by_family(QueueFamily::Locator, None, 10);
        assert_eq!(locators.len(), 1);
    }

    #[test]
    fn dequeue_by_family_limit() {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 1..=5u8 {
            q.insert(entry(i, -1, QueueFamily::Extent));
        }
        let batch = q.dequeue_by_family(QueueFamily::Extent, None, 2);
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn dequeue_by_family_start_after() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -1, QueueFamily::Extent));
        q.insert(entry(2, -1, QueueFamily::Locator));
        q.insert(entry(3, -1, QueueFamily::Extent));
        let batch = q.dequeue_by_family(QueueFamily::Extent, Some(&key(1)), 10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].0 .0[0], 3);
    }

    #[test]
    fn stats_empty() {
        let q = BPlusTreeReclaimQueue::new();
        let s = q.stats();
        assert_eq!(s, ReclaimQueueStats::ZERO);
        assert!(s.is_empty());
    }

    #[test]
    fn stats_mixed() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -1, QueueFamily::Extent));
        q.insert(entry(2, -2, QueueFamily::Locator));
        q.insert(entry(3, -1, QueueFamily::Rebake));
        q.insert(entry(4, -1, QueueFamily::InodeTombstone));
        q.insert(entry(5, -1, QueueFamily::Extent));
        let s = q.stats();
        assert_eq!(s.total_entries, 5);
        assert_eq!(s.extent_entries, 2);
        assert_eq!(s.locator_entries, 1);
        assert_eq!(s.rebake_entries, 1);
        assert_eq!(s.inode_tombstone_entries, 1);
        assert!(!s.is_empty());
        assert_eq!(s.family_sum(), s.total_entries);
    }

    #[test]
    fn stats_count_for_family() {
        let s = ReclaimQueueStats {
            total_entries: 10,
            extent_entries: 3,
            locator_entries: 2,
            rebake_entries: 4,
            inode_tombstone_entries: 1,
        };
        assert_eq!(s.count_for_family(QueueFamily::Extent), 3);
        assert_eq!(s.count_for_family(QueueFamily::Locator), 2);
        assert_eq!(s.count_for_family(QueueFamily::Rebake), 4);
        assert_eq!(s.count_for_family(QueueFamily::InodeTombstone), 1);
    }

    #[test]
    fn entries_by_family_empty() {
        let q = BPlusTreeReclaimQueue::new();
        assert!(q.entries_by_family(QueueFamily::Extent).is_empty());
    }

    #[test]
    fn entries_by_family_mixed() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -1, QueueFamily::Extent));
        q.insert(entry(2, -2, QueueFamily::Locator));
        q.insert(entry(3, -3, QueueFamily::Extent));
        q.insert(entry(4, -1, QueueFamily::Rebake));
        let ext = q.entries_by_family(QueueFamily::Extent);
        assert_eq!(ext.len(), 2);
        assert_eq!(q.family_count(QueueFamily::Extent), 2);
        assert_eq!(q.family_count(QueueFamily::Locator), 1);
        assert_eq!(q.family_count(QueueFamily::Rebake), 1);
        assert_eq!(q.family_count(QueueFamily::InodeTombstone), 0);
    }

    #[test]
    fn total_delta_empty() {
        let q = BPlusTreeReclaimQueue::new();
        assert_eq!(q.total_delta(), 0);
        assert_eq!(q.total_delta_abs(), 0);
    }

    #[test]
    fn total_delta_sum() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -5, QueueFamily::Extent));
        q.insert(entry(2, 3, QueueFamily::Extent));
        q.insert(entry(3, -1, QueueFamily::Locator));
        assert_eq!(q.total_delta(), -3);
    }

    #[test]
    fn total_delta_abs_sum() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -5, QueueFamily::Extent));
        q.insert(entry(2, 3, QueueFamily::Locator));
        assert_eq!(q.total_delta_abs(), 8);
    }

    #[test]
    fn total_delta_mixed_signs() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -4096, QueueFamily::Extent));
        q.insert(entry(2, 2048, QueueFamily::Extent));
        q.insert(entry(3, -1024, QueueFamily::Locator));
        assert_eq!(q.total_delta(), -3072);
        assert_eq!(q.total_delta_abs(), 7168);
    }

    #[test]
    fn validate_empty() {
        let q = BPlusTreeReclaimQueue::new();
        assert!(q.validate().is_ok());
    }

    #[test]
    fn validate_populated() {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 0..200u8 {
            q.insert(entry(i, -1, QueueFamily::Extent));
        }
        assert!(q.validate().is_ok());
        assert_eq!(q.len(), 200);
    }

    #[test]
    fn validate_after_mixed_inserts() {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in [50, 10, 90, 30, 70, 20, 80, 40, 60, 100] {
            q.insert(entry(i, -1, QueueFamily::Extent));
        }
        assert!(q.validate().is_ok());
        assert_eq!(q.len(), 10);
    }

    #[test]
    fn default_is_empty() {
        let q = BPlusTreeReclaimQueue::default();
        assert!(q.is_empty());
    }

    #[test]
    fn large_queue_insert_and_dequeue() {
        let mut q = BPlusTreeReclaimQueue::new();
        let n: u16 = 500;
        for i in 0..n {
            let byte = (i % 256) as u8;
            q.insert(entry(byte, -(i as i64 % 10 + 1), QueueFamily::Extent));
        }
        assert!(q.validate().is_ok());
        let batch = q.dequeue_batch(None, 100);
        assert_eq!(batch.len(), 100);
        let batch2 = q.dequeue_batch(Some(&batch[99].0), n as usize);
        assert!(!batch2.is_empty());
    }

    #[test]
    fn all_families_coexist() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -1, QueueFamily::Extent));
        q.insert(entry(2, -1, QueueFamily::Locator));
        q.insert(entry(3, -1, QueueFamily::Rebake));
        q.insert(entry(4, -1, QueueFamily::InodeTombstone));
        let s = q.stats();
        assert_eq!(s.total_entries, 4);
        assert_eq!(s.extent_entries, 1);
        assert_eq!(s.locator_entries, 1);
        assert_eq!(s.rebake_entries, 1);
        assert_eq!(s.inode_tombstone_entries, 1);
    }

    #[test]
    fn entries_come_back_in_sorted_order() {
        let mut q = BPlusTreeReclaimQueue::new();
        let ids = [99u8, 10, 50, 1, 75, 25];
        for &id in &ids {
            q.insert(entry(id, -1, QueueFamily::Extent));
        }
        let all = q.entries();
        for w in all.windows(2) {
            assert!(w[0].0 < w[1].0, "entries must be in sorted key order");
        }
    }

    #[test]
    fn spec_constant_is_correct() {
        assert_eq!(RECLAIM_QUEUE_SPEC_REF, RECLAIM_QUEUE_SPEC);
        assert_eq!(RECLAIM_QUEUE_SPEC, "tidefs-reclaim-queue-v1-design-1180");
    }

    // ------------------------------------------------------------------
    // ReclaimQueue binary encoding round-trip
    // ------------------------------------------------------------------

    #[test]
    fn encode_decode_empty_queue_roundtrip() {
        let q = BPlusTreeReclaimQueue::new();
        assert!(q.is_empty());

        let bytes = q.encode();
        let decoded = BPlusTreeReclaimQueue::decode(&bytes).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn encode_decode_single_entry_roundtrip() {
        let mut q = BPlusTreeReclaimQueue::new();
        let e = entry(42, -5, QueueFamily::Extent);
        q.insert(e);

        let bytes = q.encode();
        let decoded = BPlusTreeReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded.get(&e.object_key), Some(e));
    }

    #[test]
    fn encode_decode_many_entries_roundtrip() {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 0..100u8 {
            q.insert(entry(i, -(i as i64 % 10 + 1), QueueFamily::Extent));
        }
        q.insert(entry(200, -1, QueueFamily::Locator));
        q.insert(entry(201, -1, QueueFamily::Rebake));
        q.insert(entry(202, -1, QueueFamily::InodeTombstone));

        let bytes = q.encode();
        let decoded = BPlusTreeReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(decoded.len(), q.len());
        for (key, expected_entry) in q.entries() {
            let got = decoded.get(&key);
            assert_eq!(got, Some(expected_entry), "mismatch at key {key}");
        }
    }

    #[test]
    fn encode_decode_all_families_roundtrip() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -1, QueueFamily::Extent));
        q.insert(entry(2, -2, QueueFamily::Locator));
        q.insert(entry(3, -3, QueueFamily::Rebake));
        q.insert(entry(4, -4, QueueFamily::InodeTombstone));

        let bytes = q.encode();
        let decoded = BPlusTreeReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(decoded.len(), 4);
        assert_eq!(decoded.stats(), q.stats());
    }

    #[test]
    fn encode_decode_max_delta_entry_roundtrip() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, i64::MAX, QueueFamily::Extent));
        q.insert(entry(2, i64::MIN, QueueFamily::Locator));

        let bytes = q.encode();
        let decoded = BPlusTreeReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.get(&key(1)).unwrap().delta, i64::MAX);
        assert_eq!(decoded.get(&key(2)).unwrap().delta, i64::MIN);
    }

    #[test]
    fn encode_decode_large_queue() {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 0..500u16 {
            let byte = (i % 256) as u8;
            q.insert(entry(byte, -(i as i64 % 10 + 1), QueueFamily::Extent));
        }
        let bytes = q.encode();
        let decoded = BPlusTreeReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(decoded.len(), q.len());
    }

    #[test]
    fn encoded_len_matches_actual() {
        let q = BPlusTreeReclaimQueue::new();
        assert_eq!(q.encode().len(), q.encoded_len());

        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -1, QueueFamily::Extent));
        assert_eq!(q.encode().len(), q.encoded_len());

        let mut q = BPlusTreeReclaimQueue::new();
        for i in 0..50u8 {
            q.insert(entry(i, -1, QueueFamily::Extent));
        }
        assert_eq!(q.encode().len(), q.encoded_len());
    }

    #[test]
    fn encoded_len_formula() {
        let n = 10;
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 0..n {
            q.insert(entry(i as u8, -1, QueueFamily::Extent));
        }
        // 12 header + n*42 entries + 32 footer
        assert_eq!(q.encoded_len(), 12 + n * 42 + 32);
    }

    #[test]
    fn decode_empty_queue_roundtrip_with_footer() {
        let q = BPlusTreeReclaimQueue::new();
        let bytes = q.encode();
        // empty: 12 header + 0 entries + 32 footer = 44
        assert_eq!(bytes.len(), 44);
        let decoded = BPlusTreeReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(decoded, q);
    }

    // ------------------------------------------------------------------
    // Decode error conditions
    // ------------------------------------------------------------------

    #[test]
    fn decode_rejects_truncated_header() {
        let result = BPlusTreeReclaimQueue::decode(&[0u8; 8]);
        assert_eq!(result, Err(ReclaimQueueDecodeError::Truncated));
    }

    #[test]
    fn decode_rejects_truncated_at_43_bytes() {
        let result = BPlusTreeReclaimQueue::decode(&[0u8; 43]);
        assert_eq!(result, Err(ReclaimQueueDecodeError::Truncated));
    }

    #[test]
    fn decode_rejects_invalid_magic() {
        let mut data = vec![0u8; 44];
        data[0..4].copy_from_slice(b"XXXX");
        // Need a valid footer; compute BLAKE3 over the bad-magic body
        let body = &data[..12];
        let digest = blake3_domain_digest(
            body,
            BPlusTreeReclaimQueue::FAMILY_ID,
            BPlusTreeReclaimQueue::TYPE_ID,
            BPlusTreeReclaimQueue::VERSION,
            BPlusTreeReclaimQueue::DOMAIN_TAG,
        );
        data[12..44].copy_from_slice(&digest);
        let result = BPlusTreeReclaimQueue::decode(&data);
        assert_eq!(result, Err(ReclaimQueueDecodeError::InvalidMagic));
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let mut header = vec![0u8; 12];
        header[0..4].copy_from_slice(b"RCLM");
        header[4..8].copy_from_slice(&99u32.to_le_bytes());
        header[8..12].copy_from_slice(&0u32.to_le_bytes()); // count = 0

        let digest = blake3_domain_digest(
            &header,
            BPlusTreeReclaimQueue::FAMILY_ID,
            BPlusTreeReclaimQueue::TYPE_ID,
            BPlusTreeReclaimQueue::VERSION,
            BPlusTreeReclaimQueue::DOMAIN_TAG,
        );
        let mut data = header;
        data.extend_from_slice(&digest);

        let result = BPlusTreeReclaimQueue::decode(&data);
        assert_eq!(
            result,
            Err(ReclaimQueueDecodeError::UnsupportedVersion {
                found: 99,
                expected: 1,
            })
        );
    }

    #[test]
    fn decode_rejects_corrupted_integrity_footer() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(1, -1, QueueFamily::Extent));
        let mut bytes = q.encode();

        // Corrupt the last byte of the footer
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;

        let result = BPlusTreeReclaimQueue::decode(&bytes);
        assert_eq!(
            result,
            Err(ReclaimQueueDecodeError::IntegrityFooterMismatch)
        );
    }

    #[test]
    fn decode_rejects_truncated_entry_data() {
        // Valid header and footer, but entry count claims more entries than data provides
        let mut header = vec![0u8; 12];
        header[0..4].copy_from_slice(b"RCLM");
        header[4..8].copy_from_slice(&1u32.to_le_bytes()); // version 1
        header[8..12].copy_from_slice(&5u32.to_le_bytes()); // claims 5 entries

        let digest = blake3_domain_digest(
            &header,
            BPlusTreeReclaimQueue::FAMILY_ID,
            BPlusTreeReclaimQueue::TYPE_ID,
            BPlusTreeReclaimQueue::VERSION,
            BPlusTreeReclaimQueue::DOMAIN_TAG,
        );
        let mut data = header;
        data.extend_from_slice(&[0u8; 10]); // not enough entry data
        data.extend_from_slice(&digest); // footer is over truncated body, wrong

        // This will fail at the footer check since the footer was computed
        // over a different body. Recompute with correct body.
        data.truncate(12);
        data.extend_from_slice(&[0u8; 10]); // truncated entries (claims 5, provides ~0.2)
        let digest2 = blake3_domain_digest(
            &data,
            BPlusTreeReclaimQueue::FAMILY_ID,
            BPlusTreeReclaimQueue::TYPE_ID,
            BPlusTreeReclaimQueue::VERSION,
            BPlusTreeReclaimQueue::DOMAIN_TAG,
        );
        data.extend_from_slice(&digest2);

        let result = BPlusTreeReclaimQueue::decode(&data);
        assert_eq!(result, Err(ReclaimQueueDecodeError::Truncated));
    }

    #[test]
    fn decode_errors_display_non_empty() {
        let variants = [
            ReclaimQueueDecodeError::Truncated,
            ReclaimQueueDecodeError::InvalidMagic,
            ReclaimQueueDecodeError::UnsupportedVersion {
                found: 2,
                expected: 1,
            },
            ReclaimQueueDecodeError::EntryDecode("test error".into()),
            ReclaimQueueDecodeError::IntegrityFooterMismatch,
        ];
        for err in &variants {
            let s = alloc::format!("{err}");
            assert!(!s.is_empty(), "Display output empty for {err:?}");
        }
    }

    #[test]
    fn encode_does_not_panic_on_large_queue() {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 0..1000u16 {
            q.insert(entry(i as u8, -1, QueueFamily::Extent));
        }
        let bytes = q.encode();
        let decoded = BPlusTreeReclaimQueue::decode(&bytes).unwrap();
        assert_eq!(decoded.len(), q.len());
    }

    #[test]
    fn encode_then_decode_yields_deterministic_and_identical() {
        let mut q = BPlusTreeReclaimQueue::new();
        q.insert(entry(10, -1, QueueFamily::Locator));
        q.insert(entry(5, -1, QueueFamily::Extent));
        q.insert(entry(15, -3, QueueFamily::Rebake));

        let bytes1 = q.encode();
        let bytes2 = q.encode();
        assert_eq!(bytes1, bytes2, "encode must be deterministic");

        let decoded = BPlusTreeReclaimQueue::decode(&bytes1).unwrap();
        assert_eq!(decoded.len(), q.len());
        assert_eq!(decoded.entries(), q.entries());
    }
}
