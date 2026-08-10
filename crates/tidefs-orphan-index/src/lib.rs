// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Persistent orphan index with append-only log persistence.
//!
//! Tracks zero-link inodes for crash recovery. Uses an in-memory B+tree for
//! fast lookups and an append-only log format with BLAKE3 checksums for
//! durability. The committed inode and namespace state own reachability; this
//! index is a reconstructible cleanup accelerator.
//!
//! ## Design
//!
//! The in-memory index is a key-only B+tree of `OrphanKey` inode IDs.
//! Persistence uses an append-only log where each key is serialized with a
//! domain-separated BLAKE3 checksum.
//! On mount, `recover_from_log()` scans the log, verifies checksums, and
//! returns surviving entries. Corrupted log entries are detected and reported
//! but do not block recovery of intact entries.

use std::collections::BTreeSet;
#[cfg(any(feature = "policy-observation", test))]
use std::fmt;
use std::vec::Vec;

use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};
use tidefs_btree::{BPlusTree, BTreeError};
use tidefs_commit_group::store::CommitGroupStore;
#[cfg(any(feature = "policy-observation", test))]
use tidefs_performance_contract::{AdmissionPermit, ResourceDomain, WorkClass};
use tidefs_types_orphan_index_core::{
    OrphanCursor, OrphanKey, OrphanLogIncompleteTail, OrphanLogRecoveryReport,
    OrphanRecoveryBudget, OrphanRecoveryOutcome, OrphanRecoveryStats, OrphanReplayWatermark,
    ORPHAN_INDEX_SPEC,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum leaf entries for the orphan index B+tree.
const MAX_LEAF: usize = 128;

/// Maximum internal fanout for the orphan index B+tree.
const MAX_INTERNAL: usize = 128;

/// Design spec reference used for runtime compatibility assertions.
pub const ORPHAN_INDEX_SPEC_REF: &str = ORPHAN_INDEX_SPEC;

/// Schema identity for orphan log entries.
const ORPHAN_LOG_FAMILY: SchemaFamilyId = SchemaFamilyId::BINARY_SCHEMA;
const ORPHAN_LOG_TYPE: SchemaTypeId = SchemaTypeId(300);
const ORPHAN_LOG_VERSION: SchemaVersion = SchemaVersion::new(2, 0);
const ORPHAN_LOG_DOMAIN: DomainTag = DomainTag::ExternalPayload;

/// On-disk size of a single serialized orphan inode ID in bytes.
const ENTRY_ENCODED_SIZE: usize = 8;

/// Size of a BLAKE3-256 checksum in bytes.
const CHECKSUM_SIZE: usize = 32;

/// Total size of one log record: encoded entry + checksum.
const LOG_RECORD_SIZE: usize = ENTRY_ENCODED_SIZE + CHECKSUM_SIZE;

/// Orphan-index admission permit validation failure.
#[cfg(any(feature = "policy-observation", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrphanIndexAdmissionError {
    WrongWorkClass {
        expected: WorkClass,
        actual: WorkClass,
    },
    WrongResourceDomain {
        expected: ResourceDomain,
        actual: ResourceDomain,
    },
}

#[cfg(any(feature = "policy-observation", test))]
impl fmt::Display for OrphanIndexAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongWorkClass { expected, actual } => {
                write!(
                    f,
                    "orphan-index admission expected work class {expected}, got {actual}"
                )
            }
            Self::WrongResourceDomain { expected, actual } => {
                write!(
                    f,
                    "orphan-index admission expected resource domain {expected}, got {actual}"
                )
            }
        }
    }
}

#[cfg(any(feature = "policy-observation", test))]
impl std::error::Error for OrphanIndexAdmissionError {}

#[cfg(any(feature = "policy-observation", test))]
fn validate_orphan_index_permit(permit: &AdmissionPermit) -> Result<(), OrphanIndexAdmissionError> {
    let charge = permit.charge();
    if charge.work_class != WorkClass::MetadataMutation {
        return Err(OrphanIndexAdmissionError::WrongWorkClass {
            expected: WorkClass::MetadataMutation,
            actual: charge.work_class,
        });
    }
    if charge.primary_domain != ResourceDomain::Metadata {
        return Err(OrphanIndexAdmissionError::WrongResourceDomain {
            expected: ResourceDomain::Metadata,
            actual: charge.primary_domain,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OrphanIndex
// ---------------------------------------------------------------------------

/// admission: AdmissionPermit  service_curve: ServiceCurve
///
/// Queue root for the persistent orphan index. All insert/remove/recover
/// mutations that modify the durable orphan log must route through this index.
/// Persistent orphan index backed by a key-only B+tree.
///
/// The B+tree value is `()` because committed inode state, not this derivative
/// cleanup index, owns generation, link count, node kind, and reachability.
/// Persistence uses an append-only log of checksummed inode IDs.
#[derive(Clone, Debug)]
pub struct OrphanIndex {
    tree: BPlusTree<OrphanKey, (), MAX_LEAF, MAX_INTERNAL>,
    /// Set to true when the index has been mutated and needs persistence.
    dirty: bool,
    /// Inserts pending the current TXG commit. Tracked so abort_pending
    /// can roll them back.
    pending_inserts: BTreeSet<OrphanKey>,
    /// Removes pending the current TXG commit. Tracked so abort_pending
    /// can restore the removed entries.
    pending_removes: BTreeSet<OrphanKey>,
    /// Durably committed replay watermark. Advanced after each successful
    /// TXG commit to record the furthest inode_id whose orphan state has
    /// been replayed. Reclaim gates compare against this watermark before
    /// releasing dead objects or freed extents.
    watermark: OrphanReplayWatermark,
}

impl OrphanIndex {
    // -- constructors --

    /// Create an empty orphan index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: BPlusTree::new(),
            pending_inserts: BTreeSet::new(),
            pending_removes: BTreeSet::new(),
            dirty: false,
            watermark: OrphanReplayWatermark::NONE,
        }
    }

    /// Create an orphan index from a slice of inode IDs.
    ///
    /// Duplicate inode IDs coalesce into one key.
    #[must_use]
    pub fn from_inode_ids(inode_ids: &[u64]) -> Self {
        let mut idx = Self::new();
        for &inode_id in inode_ids {
            idx.insert(inode_id);
        }
        idx.clear_dirty();
        idx
    }

    // -- mutation --

    /// Insert an inode ID into the orphan index.
    ///
    /// Called when the committed inode's `nlink` reaches zero.
    ///
    /// Returns `true` if the entry was newly inserted (was not already
    /// present).
    ///
    pub fn insert(&mut self, inode_id: u64) -> bool {
        let key = OrphanKey::from_inode_id(inode_id);
        let is_new = self.tree.insert(key, ()).is_none();
        self.dirty |= is_new;
        is_new
    }

    /// Insert an inode ID after validating an orphan-index metadata permit.
    #[cfg(any(feature = "policy-observation", test))]
    pub fn insert_admitted(
        &mut self,
        inode_id: u64,
        permit: &AdmissionPermit,
    ) -> Result<bool, OrphanIndexAdmissionError> {
        validate_orphan_index_permit(permit)?;
        Ok(self.insert(inode_id))
    }

    /// Remove an inode from the orphan index after successful cleanup.
    ///
    /// Returns `true` if the inode was present and removed.
    pub fn remove(&mut self, inode_id: u64) -> bool {
        let key = OrphanKey::from_inode_id(inode_id);
        let was_present = self.tree.delete(&key).is_some();
        if was_present {
            self.dirty = true;
        }
        was_present
    }

    /// Remove an inode entry after validating an orphan-index metadata permit.
    #[cfg(any(feature = "policy-observation", test))]
    pub fn remove_admitted(
        &mut self,
        inode_id: u64,
        permit: &AdmissionPermit,
    ) -> Result<bool, OrphanIndexAdmissionError> {
        validate_orphan_index_permit(permit)?;
        Ok(self.remove(inode_id))
    }

    // -- lookup --

    /// Check whether an inode is currently in the orphan index.
    #[must_use]
    pub fn contains(&self, inode_id: u64) -> bool {
        let key = OrphanKey::from_inode_id(inode_id);
        self.tree.contains_key(&key)
    }

    /// Return the number of orphaned inodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Return `true` if the orphan index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Clear all entries from the orphan index.
    pub fn clear(&mut self) {
        self.tree.clear();
        self.pending_inserts.clear();
        self.pending_removes.clear();
        self.dirty = true;
    }

    /// Validate the internal B+tree structure.
    ///
    /// # Errors
    ///
    /// Returns `tidefs_btree::BTreeError` on structural violation.
    pub fn validate(&self) -> Result<(), BTreeError> {
        self.tree.validate()
    }

    // -- iteration --

    /// Iterate over all orphan inode IDs in order.
    pub fn iter(&self) -> impl Iterator<Item = u64> {
        self.tree
            .entries()
            .into_iter()
            .map(|(key, ())| key.to_inode_id())
    }

    /// Collect all orphaned inode IDs in order.
    #[must_use]
    pub fn collect_inode_ids(&self) -> Vec<u64> {
        self.iter().collect()
    }

    // -- persistence: append-only log --

    /// Compute the BLAKE3 domain-separated checksum for an encoded entry.
    fn entry_checksum(inode_bytes: &[u8; ENTRY_ENCODED_SIZE]) -> [u8; CHECKSUM_SIZE] {
        blake3_domain_digest(
            inode_bytes,
            ORPHAN_LOG_FAMILY,
            ORPHAN_LOG_TYPE,
            ORPHAN_LOG_VERSION,
            ORPHAN_LOG_DOMAIN,
        )
    }

    /// Encode the entire index as an append-only log buffer.
    ///
    /// Format: `[u32 LE entry_count][u64 LE watermark_position][entries...]`
    /// Each entry record: `[u64 LE inode_id][u8; 32 BLAKE3 checksum]`
    ///
    /// The log is designed to be written atomically via the object store.
    /// On crash, `recover_from_log()` scans and verifies each record.
    #[must_use]
    pub fn encode_log(&self) -> Vec<u8> {
        let inode_ids: Vec<u64> = self.iter().collect();
        // Format: 4-byte count | 8-byte watermark position | entries...
        let mut buf = Vec::with_capacity(12 + inode_ids.len() * LOG_RECORD_SIZE);
        let count: u32 = inode_ids.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());
        buf.extend_from_slice(&self.watermark.position.to_le_bytes());
        for inode_id in inode_ids {
            let enc = inode_id.to_le_bytes();
            buf.extend_from_slice(&enc);
            let csum = Self::entry_checksum(&enc);
            buf.extend_from_slice(&csum);
        }
        buf
    }

    /// Recover the orphan index from an append-only log buffer and return a
    /// classified replay report.
    ///
    /// Scans the log, verifies BLAKE3 checksums per entry, and returns
    /// the surviving index plus operator-visible evidence for checksum
    /// corruption and incomplete tail replay.
    ///
    /// Corrupted entries (those failing checksum verification) are skipped
    /// and reported in the returned [`OrphanLogRecoveryReport`]; they do not
    /// block recovery of intact entries.
    ///
    /// # Errors
    ///
    /// Returns `LogRecoverError` if the log header is truncated. Incomplete
    /// entries at the tail of the log (crash during append) are reported via
    /// [`OrphanLogRecoveryReport::incomplete_tail`].
    pub fn recover_from_log_report(
        data: &[u8],
    ) -> Result<(Self, OrphanLogRecoveryReport), LogRecoverError> {
        // Header: 4-byte count + 8-byte watermark position = 12 bytes
        if data.len() < 12 {
            return Err(LogRecoverError::TruncatedHeader);
        }
        let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let wm_pos = u64::from_le_bytes(data[4..12].try_into().unwrap());
        let mut idx = Self::new();
        idx.watermark = OrphanReplayWatermark { position: wm_pos };
        let mut report = OrphanLogRecoveryReport::new(count, idx.watermark);
        let mut offset: usize = 12;

        for record_index in 0..count {
            if offset + LOG_RECORD_SIZE > data.len() {
                let bytes_available = data.len().saturating_sub(offset);
                report.incomplete_tail = Some(OrphanLogIncompleteTail::new(
                    record_index,
                    bytes_available,
                    LOG_RECORD_SIZE,
                    count,
                ));
                idx.clear_dirty();
                return Ok((idx, report));
            }
            let entry_bytes: [u8; ENTRY_ENCODED_SIZE] = data[offset..offset + ENTRY_ENCODED_SIZE]
                .try_into()
                .unwrap();
            let expected_csum: [u8; CHECKSUM_SIZE] = data
                [offset + ENTRY_ENCODED_SIZE..offset + LOG_RECORD_SIZE]
                .try_into()
                .unwrap();
            let actual_csum = Self::entry_checksum(&entry_bytes);

            let inode_id = u64::from_le_bytes(entry_bytes);
            if actual_csum == expected_csum {
                idx.insert(inode_id);
                report.replayed_entries += 1;
            } else {
                report.corrupted_inodes.push(inode_id);
            }
            offset += LOG_RECORD_SIZE;
        }
        idx.clear_dirty();
        Ok((idx, report))
    }

    /// Recover the orphan index from an append-only log buffer.
    ///
    /// [`Self::recover_from_log_report`] additionally exposes the full
    /// operator-visible recovery classification.
    pub fn recover_from_log(data: &[u8]) -> Result<(Self, Vec<u64>), LogRecoverError> {
        Self::recover_from_log_report(data).map(|(idx, report)| (idx, report.corrupted_inodes))
    }

    // -- TXG commit pipeline integration --

    /// Returns `true` if the orphan index has unsaved mutations.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty || self.has_pending()
    }

    /// Clear the dirty flag after successful persistence.
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// Return the durably committed replay watermark.
    ///
    /// Reclaim gates compare object/extent inode_id against this watermark
    /// before releasing storage.  When the watermark is [`OrphanReplayWatermark::NONE`],
    /// no orphan state has been durably replayed and reclaim blocks everything.
    #[must_use]
    pub fn durable_watermark(&self) -> OrphanReplayWatermark {
        self.watermark
    }

    /// Advance the durably committed replay watermark past `position`.
    ///
    /// The watermark is monotonic: it never moves backwards.  Call this
    /// after a TXG commit has durably recorded that orphan state up to
    /// `position` has been replayed.
    pub fn advance_watermark(&mut self, position: u64) {
        self.watermark = self.watermark.advance_past(position);
        self.dirty = true;
    }

    /// Set the watermark from an [`OrphanCursor`].
    ///
    /// Convenience wrapper for [`advance_watermark`](Self::advance_watermark)
    /// when the caller already has a cursor from recovery scanning.
    pub fn set_watermark_from_cursor(&mut self, cursor: OrphanCursor) {
        self.advance_watermark(cursor.position);
    }

    /// Insert an inode ID into the orphan index within the current TXG.
    ///
    /// The inode is immediately visible to `contains()` and `iter()`. The
    /// insert is tracked as "pending commit" so that an
    /// abort before the next `commit_pending()` can roll it back.
    ///
    /// Returns `true` if the inode was newly inserted.
    pub fn insert_crash_safe(&mut self, inode_id: u64) -> bool {
        let key = OrphanKey::from_inode_id(inode_id);
        let cancelled_remove = self.pending_removes.remove(&key);
        let is_new = self.tree.insert(key, ()).is_none();
        if is_new {
            self.dirty = true;
            if !cancelled_remove {
                self.pending_inserts.insert(key);
            }
        }
        is_new
    }

    /// Remove an inode from the orphan index within the current TXG.
    ///
    /// The entry is immediately removed from the tree and no longer
    /// visible. The removal is tracked as "pending commit" so that an
    /// abort before the next `commit_pending()` can restore the entry.
    ///
    /// Returns `true` if the inode was present and removed.
    pub fn remove_crash_safe(&mut self, inode_id: u64) -> bool {
        let key = OrphanKey::from_inode_id(inode_id);
        if self.pending_inserts.remove(&key) {
            self.tree.delete(&key);
            return true;
        }
        if self.tree.delete(&key).is_some() {
            self.dirty = true;
            self.pending_removes.insert(key);
            return true;
        }
        false
    }

    /// Commit all pending operations: clears the dirty flag and pending
    /// tracking so subsequent `abort_pending()` will not roll them back.
    pub fn commit_pending(&mut self) {
        self.dirty = false;
        self.pending_inserts.clear();
        self.pending_removes.clear();
    }

    /// Abort all pending operations: rolls back inserts and restores
    /// removes to their pre-TXG state.
    pub fn abort_pending(&mut self) {
        let inserts: Vec<OrphanKey> = self.pending_inserts.iter().copied().collect();
        for key in &inserts {
            if self.pending_removes.contains(key) {
                continue;
            }
            self.tree.delete(key);
        }
        for &key in &self.pending_removes {
            self.tree.insert(key, ());
        }
        self.dirty = false;
        self.pending_inserts.clear();
        self.pending_removes.clear();
    }

    /// Returns `true` if there are any pending (uncommitted) operations.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending_inserts.is_empty() || !self.pending_removes.is_empty()
    }

    /// Number of pending operations (inserts + removes).
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_inserts.len() + self.pending_removes.len()
    }

    /// Persist the dirty orphan index into the TXG store.
    ///
    /// Encodes the full index as an append-only log and writes it
    /// through `CommitGroupStore::put_named`. After a successful write,
    /// pending tracking is cleared.
    ///
    /// # Errors
    ///
    /// Returns an error string from the store on I/O failure.
    pub fn commit_to_txg(
        &mut self,
        store: &mut dyn CommitGroupStore,
        key_name: &str,
    ) -> Result<tidefs_commit_group::store::CommitGroupKey, String> {
        let encoded = self.encode_log();
        let key = store.put_named(key_name, &encoded)?;
        self.commit_pending();
        Ok(key)
    }

    /// Recover the orphan index from the TXG store.
    ///
    /// Reads the persisted log from `CommitGroupStore::get_named`, verifies
    /// checksums, and returns the surviving index. Missing or corrupt
    /// data returns an empty index.
    ///
    /// Returns the recovered index plus a list of corrupted entry inode IDs.
    pub fn replay_from_txg(store: &dyn CommitGroupStore, key_name: &str) -> (Self, Vec<u64>) {
        match store.get_named(key_name) {
            Ok(Some(bytes)) => match Self::recover_from_log_report(&bytes) {
                Ok((idx, report)) => (idx, report.corrupted_inodes),
                Err(_) => (Self::new(), Vec::new()),
            },
            Ok(None) => (Self::new(), Vec::new()),
            Err(_) => (Self::new(), Vec::new()),
        }
    }

    // -- batch recovery (cursor-based) --

    /// Perform one batch of cursor-based orphan recovery.
    ///
    /// Scans up to `budget.max_orphans_per_tick` entries starting from
    /// `cursor`, returning the entries found and a new cursor position.
    /// The caller is responsible for actually reclaiming the extents
    /// and deleting the inode — this method only reads from the index.
    #[must_use]
    pub fn batch_recover(
        &self,
        cursor: OrphanCursor,
        budget: OrphanRecoveryBudget,
    ) -> OrphanRecoveryOutcome {
        let start_key = cursor.next_key();

        let (entries, scan_exhausted) = if self.is_empty() || cursor.is_exhausted() {
            (Vec::new(), true)
        } else {
            let all = self.tree.entries();
            let budget_count = budget.normal_budget();
            let start_idx = all
                .binary_search_by_key(
                    &&if cursor.is_at_start() {
                        OrphanKey::NONE
                    } else {
                        start_key
                    },
                    |(k, _)| k,
                )
                .unwrap_or_else(|idx| idx);
            let mut result =
                Vec::with_capacity(budget_count.min(all.len().saturating_sub(start_idx)));
            for (_key, _entry) in all.iter().skip(start_idx).take(budget_count) {
                result.push(_key.to_inode_id());
            }
            let exhausted = result.len() < budget_count || start_idx + result.len() >= all.len();
            (result, exhausted)
        };

        let scanned = entries.len();
        let exhausted = scanned == 0 || cursor.is_exhausted() || self.is_empty() || scan_exhausted;

        let last_position = entries.last().copied().unwrap_or(cursor.position);

        OrphanRecoveryOutcome::new(
            OrphanRecoveryStats {
                scanned,
                reclaimed: 0,
                stale: 0,
                already_freed: 0,
                commits: 0,
                integrity_errors: 0,
            },
            OrphanCursor {
                position: last_position,
            },
            exhausted,
            entries,
        )
    }
}

impl Default for OrphanIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LogRecoverError
// ---------------------------------------------------------------------------

/// Errors that can occur during orphan log recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogRecoverError {
    /// The log buffer is too short to contain the 12-byte count/watermark header.
    TruncatedHeader,
}

impl std::fmt::Display for LogRecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader => write!(f, "orphan log truncated: header missing"),
        }
    }
}

impl std::error::Error for LogRecoverError {}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_orphan_index_core::OrphanLogRecoveryClass;

    // ── OrphanIndex: basic CRUD ──────────────────────────────────────

    #[test]
    fn empty_index() {
        let idx = OrphanIndex::new();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
        assert!(idx.validate().is_ok());
        assert!(idx.collect_inode_ids().is_empty());
        assert_eq!(idx.iter().count(), 0);
    }

    #[test]
    fn insert_and_contains() {
        let mut idx = OrphanIndex::new();
        assert!(idx.insert(42));
        assert!(idx.contains(42));
        assert!(!idx.contains(99));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn admitted_insert_and_remove_accept_metadata_permits() {
        let mut state = tidefs_performance_contract::WriteAdmissionState::new(
            tidefs_performance_contract::WriteAdmissionConfig::new(0, 0, 0, 2),
        );
        let mut idx = OrphanIndex::new();

        let insert_permit = state
            .try_admit_metadata(0)
            .expect("metadata permit admitted");
        assert!(idx
            .insert_admitted(42, &insert_permit)
            .expect("insert admitted"));
        state.release(insert_permit).expect("release insert permit");

        let remove_permit = state
            .try_admit_metadata(1)
            .expect("metadata permit admitted");
        assert!(idx
            .remove_admitted(42, &remove_permit)
            .expect("remove admitted"));
        state.release(remove_permit).expect("release remove permit");
    }

    #[test]
    fn admitted_insert_rejects_non_metadata_permit() {
        let mut state = tidefs_performance_contract::WriteAdmissionState::new(
            tidefs_performance_contract::WriteAdmissionConfig::new(1024, 1, 8, 1),
        );
        let dirty_permit = state
            .try_admit(tidefs_performance_contract::AdmissionCharge::dirty_write(
                1, 1, 0,
            ))
            .expect("dirty permit admitted");
        let mut idx = OrphanIndex::new();

        let err = idx
            .insert_admitted(42, &dirty_permit)
            .expect_err("dirty permit must not admit orphan-index metadata");

        assert_eq!(
            err,
            OrphanIndexAdmissionError::WrongWorkClass {
                expected: WorkClass::MetadataMutation,
                actual: WorkClass::ForegroundWrite,
            }
        );
        state.release(dirty_permit).expect("release dirty permit");
    }

    #[test]
    fn insert_duplicate_rejected() {
        let mut idx = OrphanIndex::new();
        assert!(idx.insert(1));
        assert!(!idx.insert(1));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn remove_entry() {
        let mut idx = OrphanIndex::new();
        idx.insert(5);
        assert!(idx.contains(5));
        assert!(idx.remove(5));
        assert!(!idx.contains(5));
        assert!(idx.is_empty());
    }

    #[test]
    fn remove_nonexistent() {
        let mut idx = OrphanIndex::new();
        assert!(!idx.remove(999));
    }

    #[test]
    fn multiple_inserts_ordered() {
        let mut idx = OrphanIndex::new();
        let ids = [100u64, 50, 200, 150, 1];
        for &id in &ids {
            idx.insert(id);
        }
        assert_eq!(idx.len(), 5);
        let collected = idx.collect_inode_ids();
        assert_eq!(collected, vec![1, 50, 100, 150, 200]);
        assert!(idx.validate().is_ok());
    }

    #[test]
    fn iter_yields_ordered_entries() {
        let mut idx = OrphanIndex::new();
        idx.insert(30);
        idx.insert(10);
        idx.insert(20);
        let ids: Vec<u64> = idx.iter().collect();
        assert_eq!(ids, vec![10, 20, 30]);
    }

    #[test]
    fn clear_empties_index() {
        let mut idx = OrphanIndex::new();
        idx.insert(1);
        idx.insert(2);
        idx.clear();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn large_insert_and_iter() {
        let mut idx = OrphanIndex::new();
        let count = 1000u64;
        for i in (0..count).rev() {
            idx.insert(i + 1);
        }
        assert_eq!(idx.len(), count as usize);
        let collected: Vec<u64> = idx.iter().collect();
        assert_eq!(collected.len(), count as usize);
        for w in collected.windows(2) {
            assert!(w[0] < w[1]);
        }
        assert!(idx.validate().is_ok());
    }

    // ── Append-only log persistence ──────────────────────────────────

    #[test]
    fn encode_log_empty() {
        let idx = OrphanIndex::new();
        let log = idx.encode_log();
        // 4-byte count (0) + 8-byte watermark position = 12 bytes
        assert_eq!(log.len(), 12);
        assert_eq!(&log[0..4], &0u32.to_le_bytes());
        assert_eq!(&log[4..12], &0u64.to_le_bytes());
    }

    #[test]
    fn encode_log_single_entry() {
        let mut idx = OrphanIndex::new();
        idx.insert(42);
        let log = idx.encode_log();
        assert_eq!(log.len(), 12 + LOG_RECORD_SIZE);
        // Count
        assert_eq!(u32::from_le_bytes(log[0..4].try_into().unwrap()), 1);
        // Watermark at position 0 (NONE)
        assert_eq!(u64::from_le_bytes(log[4..12].try_into().unwrap()), 0);
    }

    #[test]
    fn durable_watermark_starts_at_none() {
        let idx = OrphanIndex::new();
        assert_eq!(idx.durable_watermark(), OrphanReplayWatermark::NONE);
    }

    #[test]
    fn advance_watermark_is_monotonic_and_marks_dirty() {
        let mut idx = OrphanIndex::new();
        idx.clear_dirty();

        idx.advance_watermark(42);
        assert_eq!(idx.durable_watermark().position, 42);
        assert!(idx.is_dirty());

        idx.advance_watermark(10);
        assert_eq!(idx.durable_watermark().position, 42);
    }

    #[test]
    fn set_watermark_from_cursor_advances_position() {
        let mut idx = OrphanIndex::new();
        idx.set_watermark_from_cursor(OrphanCursor { position: 77 });
        assert_eq!(idx.durable_watermark().position, 77);
    }

    #[test]
    fn encode_log_persists_watermark_position() {
        let mut idx = OrphanIndex::new();
        idx.insert(42);
        idx.advance_watermark(42);

        let log = idx.encode_log();
        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        assert!(recovered.contains(42));
        assert_eq!(recovered.durable_watermark().position, 42);
    }

    #[test]
    fn truncated_tail_recovery_preserves_watermark_header() {
        let mut idx = OrphanIndex::new();
        idx.insert(1);
        idx.insert(2);
        idx.advance_watermark(1);

        let mut log = idx.encode_log();
        log.truncate(12 + LOG_RECORD_SIZE + 1);

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        assert!(recovered.contains(1));
        assert!(!recovered.contains(2));
        assert_eq!(recovered.durable_watermark().position, 1);
    }

    #[test]
    fn roundtrip_log_single_entry() {
        let mut idx = OrphanIndex::new();
        idx.insert(42);
        let log = idx.encode_log();

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        assert_eq!(recovered.len(), 1);
        assert!(recovered.contains(42));
    }

    #[test]
    fn roundtrip_log_multiple_entries() {
        let mut idx = OrphanIndex::new();
        for i in 1..=50u64 {
            idx.insert(i);
        }
        let log = idx.encode_log();

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        assert_eq!(recovered.len(), 50);
        for i in 1..=50u64 {
            assert!(recovered.contains(i), "missing inode {i}");
        }
    }

    // -- Crash-safe insert/remove with commit/abort semantics ------

    #[test]
    fn insert_crash_safe_immediately_visible() {
        let mut idx = OrphanIndex::new();
        assert!(idx.insert_crash_safe(42));
        assert!(idx.contains(42));
        assert_eq!(idx.len(), 1);
        assert!(idx.is_dirty());
        assert!(idx.has_pending());
        assert_eq!(idx.pending_count(), 1);
    }

    #[test]
    fn insert_crash_safe_visible_after_commit() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(42);
        assert!(idx.contains(42));
        assert!(idx.has_pending());
        idx.commit_pending();
        assert!(idx.contains(42));
        assert_eq!(idx.len(), 1);
        assert!(!idx.is_dirty());
        assert!(!idx.has_pending());
    }

    #[test]
    fn insert_crash_safe_aborted_rolled_back() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(42);
        assert!(idx.contains(42));
        idx.abort_pending();
        assert!(!idx.contains(42));
        assert_eq!(idx.len(), 0);
        assert!(!idx.is_dirty());
        assert!(!idx.has_pending());
    }

    #[test]
    fn remove_crash_safe_immediately_removed() {
        let mut idx = OrphanIndex::new();
        idx.insert(42);
        idx.clear_dirty();
        assert!(!idx.is_dirty());
        assert!(idx.remove_crash_safe(42));
        assert!(!idx.contains(42));
        assert_eq!(idx.len(), 0);
        assert!(idx.is_dirty());
        assert!(idx.has_pending());
    }

    #[test]
    fn remove_crash_safe_gone_after_commit() {
        let mut idx = OrphanIndex::new();
        idx.insert(42);
        idx.remove_crash_safe(42);
        idx.commit_pending();
        assert!(!idx.contains(42));
        assert_eq!(idx.len(), 0);
        assert!(!idx.has_pending());
    }

    #[test]
    fn remove_crash_safe_cancels_pending_insert() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(42);
        assert!(idx.contains(42));
        assert!(idx.remove_crash_safe(42));
        assert!(!idx.contains(42));
        idx.commit_pending();
        assert!(!idx.contains(42));
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn remove_crash_safe_aborted_restores_entry() {
        let mut idx = OrphanIndex::new();
        idx.insert(42);
        idx.clear_dirty();
        idx.remove_crash_safe(42);
        assert!(!idx.contains(42));
        idx.abort_pending();
        assert!(idx.contains(42));
        assert_eq!(idx.len(), 1);
        assert!(!idx.is_dirty());
        assert!(!idx.has_pending());
    }

    #[test]
    fn concurrent_insert_and_commit() {
        let mut idx = OrphanIndex::new();
        for i in 1..=100u64 {
            idx.insert_crash_safe(i);
        }
        assert_eq!(idx.pending_count(), 100);
        assert_eq!(idx.len(), 100);
        for i in 1..=100u64 {
            assert!(idx.contains(i));
        }
        idx.commit_pending();
        assert_eq!(idx.len(), 100);
        assert!(!idx.has_pending());
        for i in 1..=100u64 {
            assert!(idx.contains(i));
        }
    }

    #[test]
    fn empty_index_has_no_pending() {
        let idx = OrphanIndex::new();
        assert!(!idx.has_pending());
        assert_eq!(idx.pending_count(), 0);
        assert!(!idx.is_dirty());
    }

    #[test]
    fn remove_crash_safe_after_insert_crash_safe_same_txg() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(5);
        assert!(idx.contains(5));
        idx.remove_crash_safe(5);
        assert!(!idx.contains(5));
        assert!(!idx.has_pending());
        idx.commit_pending();
        assert!(!idx.contains(5));
    }

    #[test]
    fn crash_simulated_recovery_insert_commit_then_kill() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(42);
        idx.commit_pending();
        let log = idx.encode_log();
        let (recovered, _) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(recovered.contains(42));
    }

    #[test]
    fn clear_also_clears_pending() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(1);
        idx.insert(2);
        idx.remove_crash_safe(2);
        assert!(idx.has_pending());
        idx.clear();
        assert!(!idx.has_pending());
        assert!(idx.is_dirty());
        assert!(idx.is_empty());
    }

    #[test]
    fn commit_to_txg_clears_pending() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(10);
        idx.insert_crash_safe(20);
        assert!(idx.has_pending());
        assert!(idx.is_dirty());

        struct MemStore {
            data: std::collections::BTreeMap<String, Vec<u8>>,
        }
        impl CommitGroupStore for MemStore {
            fn get_named(&self, name: &str) -> std::result::Result<Option<Vec<u8>>, String> {
                Ok(self.data.get(name).cloned())
            }
            fn put_named(
                &mut self,
                name: &str,
                data: &[u8],
            ) -> std::result::Result<tidefs_commit_group::store::CommitGroupKey, String>
            {
                self.data.insert(name.to_string(), data.to_vec());
                Ok(tidefs_commit_group::store::CommitGroupKey([0u8; 32]))
            }
        }

        let mut store = MemStore {
            data: std::collections::BTreeMap::new(),
        };
        idx.commit_to_txg(&mut store, "orphan_log").unwrap();
        assert!(!idx.has_pending());
        assert!(!idx.is_dirty());

        let log = store.get_named("orphan_log").unwrap().unwrap();
        let (recovered, _) = OrphanIndex::recover_from_log(&log).unwrap();
        assert_eq!(recovered.len(), 2);
        assert!(recovered.contains(10));
        assert!(recovered.contains(20));
    }

    #[test]
    fn crash_safe_insert_cancels_pending_remove() {
        let mut idx = OrphanIndex::new();
        idx.insert(42);
        idx.clear_dirty();
        idx.remove_crash_safe(42);
        assert!(idx.has_pending());
        assert!(idx.insert_crash_safe(42));
        assert!(!idx.has_pending());
        idx.abort_pending();
        assert!(idx.contains(42));
    }

    #[test]
    fn remove_clears_pending_sets() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(1);
        idx.insert(2);
        assert!(idx.contains(1));
        assert!(idx.contains(2));
        assert!(idx.remove(1));
        assert!(!idx.contains(1));
        assert!(idx.remove(2));
        assert!(!idx.contains(2));
    }

    #[test]
    fn recover_empty_log() {
        let log = OrphanIndex::new().encode_log();
        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        assert!(recovered.is_empty());
    }

    #[test]
    fn recover_truncated_header() {
        let log = vec![0u8, 1, 2]; // < 12 bytes (header is 12 bytes)
        let err = OrphanIndex::recover_from_log(&log).unwrap_err();
        assert_eq!(err, LogRecoverError::TruncatedHeader);
    }

    #[test]
    fn recover_truncated_entry_graceful() {
        // Create a valid log with 2 entries, then truncate the last entry
        let mut idx = OrphanIndex::new();
        idx.insert(1);
        idx.insert(2);
        let mut log = idx.encode_log();
        // Truncate halfway through the second entry
        let new_len = 12 + LOG_RECORD_SIZE + 10; // header(12) + first full entry + 10 bytes of second
        log.truncate(new_len);

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        // Only the first entry should survive
        assert_eq!(recovered.len(), 1);
        assert!(recovered.contains(1));
        assert!(!recovered.contains(2));
    }

    #[test]
    fn recover_report_classifies_incomplete_tail() {
        let mut idx = OrphanIndex::new();
        idx.insert(1);
        idx.insert(2);
        idx.advance_watermark(10);
        let mut log = idx.encode_log();
        log.truncate(12 + LOG_RECORD_SIZE + 7);

        let (recovered, report) = OrphanIndex::recover_from_log_report(&log).unwrap();
        assert_eq!(report.class(), OrphanLogRecoveryClass::IncompleteReplay);
        assert_eq!(report.expected_entries, 2);
        assert_eq!(report.replayed_entries, 1);
        assert_eq!(report.watermark.position, 10);
        let tail = report.incomplete_tail.unwrap();
        assert_eq!(tail.next_entry_index, 1);
        assert_eq!(tail.bytes_available, 7);
        assert_eq!(tail.missing_entries, 1);
        assert!(report.corrupted_inodes.is_empty());
        assert_eq!(recovered.collect_inode_ids(), vec![1]);
    }

    #[test]
    fn recover_corrupted_checksum() {
        let mut idx = OrphanIndex::new();
        idx.insert(1);
        idx.insert(2);
        idx.insert(3);
        let mut log = idx.encode_log();

        // Corrupt the checksum of the second entry after the 12-byte header.
        let second_csum_start = 12 + LOG_RECORD_SIZE + ENTRY_ENCODED_SIZE;
        log[second_csum_start] ^= 0xFF;

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert_eq!(corrupted, vec![2]);
        assert_eq!(recovered.len(), 2);
        assert!(recovered.contains(1));
        assert!(recovered.contains(3));
        assert!(!recovered.contains(2));
    }

    #[test]
    fn recover_report_classifies_corrupt_log() {
        let mut idx = OrphanIndex::new();
        idx.insert(1);
        idx.insert(2);
        let mut log = idx.encode_log();

        let second_csum_start = 12 + LOG_RECORD_SIZE + ENTRY_ENCODED_SIZE;
        log[second_csum_start] ^= 0xFF;

        let (recovered, report) = OrphanIndex::recover_from_log_report(&log).unwrap();
        assert_eq!(report.class(), OrphanLogRecoveryClass::CorruptOrphanLog);
        assert_eq!(report.expected_entries, 2);
        assert_eq!(report.replayed_entries, 1);
        assert_eq!(report.corrupted_inodes, vec![2]);
        assert!(report.incomplete_tail.is_none());
        assert_eq!(recovered.collect_inode_ids(), vec![1]);
    }

    #[test]
    fn recover_corrupted_entry_data() {
        let mut idx = OrphanIndex::new();
        idx.insert(10);
        idx.insert(20);
        let mut log = idx.encode_log();

        // Corrupt the first inode ID while leaving its checksum unchanged.
        let entry_data_start = 12; // after count (4) + watermark (8) header
        log[entry_data_start] ^= 0xFF;

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert_eq!(corrupted.len(), 1);
        assert_eq!(recovered.len(), 1);
        assert!(recovered.contains(20));
        assert!(!recovered.contains(10));
    }

    // ── Batch recovery (cursor-based) ────────────────────────────────

    #[test]
    fn batch_recover_from_start() {
        let mut idx = OrphanIndex::new();
        for i in 1..=50u64 {
            idx.insert(i);
        }

        let budget = OrphanRecoveryBudget {
            max_orphans_per_tick: 10,
            ..Default::default()
        };

        let outcome = idx.batch_recover(OrphanCursor::START, budget);
        assert_eq!(outcome.stats.scanned, 10);
        assert!(!outcome.exhausted);
        assert!(outcome.made_progress());
    }

    #[test]
    fn batch_recover_exhausts() {
        let mut idx = OrphanIndex::new();
        for i in 1..=5u64 {
            idx.insert(i);
        }
        let budget = OrphanRecoveryBudget {
            max_orphans_per_tick: 100,
            ..Default::default()
        };
        let outcome = idx.batch_recover(OrphanCursor::START, budget);
        assert_eq!(outcome.stats.scanned, 5);
        assert!(outcome.exhausted);
    }

    #[test]
    fn batch_recover_empty_index() {
        let idx = OrphanIndex::new();
        let budget = OrphanRecoveryBudget::default();
        let outcome = idx.batch_recover(OrphanCursor::START, budget);
        assert_eq!(outcome.stats.scanned, 0);
        assert!(outcome.exhausted);
        assert!(outcome.is_idle());
    }

    #[test]
    fn batch_recover_resumes_from_cursor() {
        let mut idx = OrphanIndex::new();
        for i in 1..=30u64 {
            idx.insert(i);
        }
        let budget = OrphanRecoveryBudget {
            max_orphans_per_tick: 10,
            ..Default::default()
        };
        let mut cursor = OrphanCursor::START;
        let mut total = 0;
        for _ in 0..3 {
            let outcome = idx.batch_recover(cursor, budget);
            total += outcome.stats.scanned;
            cursor = outcome.cursor;
        }
        assert_eq!(total, 30);
    }

    // ── from_inode_ids constructor ──────────────────────────────────

    #[test]
    fn from_inode_ids_constructs_correctly() {
        let idx = OrphanIndex::from_inode_ids(&[10, 20, 30]);
        assert_eq!(idx.len(), 3);
        assert!(idx.contains(10));
        assert!(idx.contains(20));
        assert!(idx.contains(30));
    }

    #[test]
    fn from_inode_ids_empty() {
        let idx = OrphanIndex::from_inode_ids(&[]);
        assert!(idx.is_empty());
    }

    // ── Structural validation ────────────────────────────────────────

    #[test]
    fn validate_large_tree() {
        let mut idx = OrphanIndex::new();
        for i in 0..500u64 {
            idx.insert(i);
        }
        assert!(idx.validate().is_ok());
    }

    #[test]
    fn leaf_boundary() {
        let mut idx = OrphanIndex::new();
        let count = MAX_LEAF + 10;
        for i in 0..count as u64 {
            idx.insert(i);
        }
        assert_eq!(idx.len(), count);
        assert!(idx.validate().is_ok());
    }

    #[test]
    fn multi_level_tree() {
        let mut idx = OrphanIndex::new();
        let count = MAX_LEAF as u64 * MAX_INTERNAL as u64 * 4;
        for i in 0..count {
            idx.insert(i);
        }
        assert_eq!(idx.len(), count as usize);
        assert!(idx.tree.depth() >= 2, "expected multi-level tree");
        assert!(idx.validate().is_ok());
    }

    #[test]
    fn insert_boundary_values() {
        let mut idx = OrphanIndex::new();
        idx.insert(u64::MAX);
        idx.insert(0);
        idx.insert(1);
        assert_eq!(idx.len(), 3);
        assert!(idx.contains(0));
        assert!(idx.contains(1));
        assert!(idx.contains(u64::MAX));
    }

    // ── Crash recovery: partial log resilience ───────────────────────

    #[test]
    fn crash_partial_write_last_entry_truncated() {
        // Simulate a crash where only the header and first 1.5 entries
        // made it to disk
        let mut idx = OrphanIndex::new();
        for i in 1..=5u64 {
            idx.insert(i);
        }
        let full_log = idx.encode_log();
        // Keep header + 3.5 entries
        let partial_len = 12 + 3 * LOG_RECORD_SIZE + LOG_RECORD_SIZE / 2;
        let partial = &full_log[..partial_len.min(full_log.len())];

        let (recovered, corrupted) = OrphanIndex::recover_from_log(partial).unwrap();
        assert!(corrupted.is_empty());
        // Should have 3 intact entries (the fourth is truncated and lost)
        assert_eq!(recovered.len(), 3);
        assert!(recovered.contains(1));
        assert!(recovered.contains(2));
        assert!(recovered.contains(3));
    }

    #[test]
    fn checksum_uniqueness_across_entries() {
        // Different entries must produce different checksums
        let c1 = OrphanIndex::entry_checksum(&1u64.to_le_bytes());
        let c2 = OrphanIndex::entry_checksum(&2u64.to_le_bytes());
        assert_ne!(c1, c2);
    }

    #[test]
    fn checksum_same_entry_same_checksum() {
        let encoded = 42u64.to_le_bytes();
        let c1 = OrphanIndex::entry_checksum(&encoded);
        let c2 = OrphanIndex::entry_checksum(&encoded);
        assert_eq!(c1, c2);
    }
    // ── TXG commit pipeline tests ──────────────────────────────────

    /// A simple in-memory CommitGroupStore for testing.
    struct MemCommitGroupStore {
        blobs: std::collections::HashMap<String, Vec<u8>>,
    }

    impl MemCommitGroupStore {
        fn new() -> Self {
            Self {
                blobs: std::collections::HashMap::new(),
            }
        }
    }

    impl CommitGroupStore for MemCommitGroupStore {
        fn put_named(
            &mut self,
            name: &str,
            payload: &[u8],
        ) -> Result<tidefs_commit_group::store::CommitGroupKey, String> {
            self.blobs.insert(name.to_string(), payload.to_vec());
            Ok(tidefs_commit_group::store::CommitGroupKey([0u8; 32]))
        }

        fn get_named(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.blobs.get(name).cloned())
        }
    }

    #[test]
    fn txg_roundtrip_empty_index() {
        let mut store = MemCommitGroupStore::new();
        let mut idx = OrphanIndex::new();
        assert!(!idx.is_dirty());

        idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
        assert!(!idx.is_dirty());

        let (recovered, corrupted) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert!(corrupted.is_empty());
        assert!(recovered.is_empty());
        assert!(!recovered.is_dirty());
    }

    #[test]
    fn txg_roundtrip_single_entry() {
        let mut store = MemCommitGroupStore::new();
        let mut idx = OrphanIndex::new();

        idx.insert_crash_safe(42);
        assert!(idx.is_dirty());
        assert!(idx.contains(42));

        idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
        assert!(!idx.is_dirty());

        let (recovered, corrupted) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert!(corrupted.is_empty());
        assert_eq!(recovered.len(), 1);
        assert!(recovered.contains(42));
    }

    #[test]
    fn txg_roundtrip_multiple_entries() {
        let mut store = MemCommitGroupStore::new();
        let mut idx = OrphanIndex::new();

        for i in 1..=50u64 {
            idx.insert_crash_safe(i);
        }
        assert!(idx.is_dirty());

        idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
        assert!(!idx.is_dirty());

        let (recovered, corrupted) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert!(corrupted.is_empty());
        assert_eq!(recovered.len(), 50);
        assert!(recovered.contains(3));
        assert!(recovered.contains(5));
    }

    #[test]
    fn txg_crash_simulated_insert_visible_after_commit() {
        let mut store = MemCommitGroupStore::new();
        let orphan_id = 99u64;

        {
            let mut idx = OrphanIndex::new();
            idx.insert_crash_safe(orphan_id);
            assert!(idx.contains(orphan_id));
            idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
        }

        let (recovered, _) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert!(
            recovered.contains(orphan_id),
            "orphan should be visible after replay (survived crash)"
        );
    }

    #[test]
    fn txg_crash_simulated_insert_not_committed_is_lost() {
        let store = MemCommitGroupStore::new();
        let orphan_id = 42u64;

        {
            let mut idx = OrphanIndex::new();
            idx.insert_crash_safe(orphan_id);
            assert!(idx.is_dirty());
        }

        let (recovered, _) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert!(
            recovered.is_empty(),
            "uncommitted orphan should NOT survive crash"
        );
    }

    #[test]
    fn txg_remove_then_commit_roundtrip() {
        let mut store = MemCommitGroupStore::new();

        {
            let mut idx = OrphanIndex::new();
            idx.insert_crash_safe(1);
            idx.insert_crash_safe(2);
            idx.insert_crash_safe(3);
            idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
        }

        {
            let (mut idx, _) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
            assert_eq!(idx.len(), 3);

            let removed = idx.remove_crash_safe(2);
            assert!(removed);
            assert!(idx.is_dirty());
            assert!(!idx.contains(2));

            idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
            assert!(!idx.is_dirty());
        }

        let (recovered, _) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert_eq!(recovered.len(), 2);
        assert!(recovered.contains(1));
        assert!(recovered.contains(3));
        assert!(!recovered.contains(2));
    }

    #[test]
    fn txg_replay_missing_key_returns_empty() {
        let store = MemCommitGroupStore::new();
        let (recovered, corrupted) = OrphanIndex::replay_from_txg(&store, "nonexistent");
        assert!(corrupted.is_empty());
        assert!(recovered.is_empty());
    }

    #[test]
    fn txg_clear_marks_dirty() {
        let mut idx = OrphanIndex::new();
        idx.insert(1);
        idx.clear_dirty();
        assert!(!idx.is_dirty());

        idx.clear();
        assert!(idx.is_dirty());
        assert!(idx.is_empty());
    }

    #[test]
    fn txg_remove_nonexistent_is_noop() {
        let mut idx = OrphanIndex::new();
        let removed = idx.remove_crash_safe(999);
        assert!(!removed);
        assert!(!idx.is_dirty());
    }

    #[test]
    fn txg_concurrent_insert_and_commit() {
        let mut store = MemCommitGroupStore::new();
        let mut idx = OrphanIndex::new();
        let count = 100u64;

        for i in 1..=count {
            idx.insert_crash_safe(i);
        }
        assert!(idx.is_dirty());
        assert_eq!(idx.len(), count as usize);

        idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
        assert!(!idx.is_dirty());

        let (recovered, corrupted) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert!(corrupted.is_empty());
        assert_eq!(recovered.len(), count as usize);
        for i in 1..=count {
            assert!(recovered.contains(i), "missing inode {i}");
        }
    }

    #[test]
    fn txg_corrupted_log_recovery_returns_partial() {
        let mut store = MemCommitGroupStore::new();
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(1);
        idx.insert_crash_safe(2);
        idx.insert_crash_safe(3);

        let mut encoded = idx.encode_log();
        let csum_start = 12 + super::LOG_RECORD_SIZE + super::ENTRY_ENCODED_SIZE;
        if csum_start < encoded.len() {
            encoded[csum_start] ^= 0xFF;
        }
        store.put_named("orphan-idx", &encoded).unwrap();

        let (recovered, corrupted) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert_eq!(corrupted, vec![2]);
        assert_eq!(recovered.len(), 2);
        assert!(recovered.contains(1));
        assert!(recovered.contains(3));
    }
}

// ---------------------------------------------------------------------------
// Orphan replay watermark persistence tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod watermark_tests {
    use super::*;
    use tidefs_types_orphan_index_core::{OrphanCursor, OrphanReplayWatermark};

    // -- watermark start state --

    #[test]
    fn new_index_has_none_watermark() {
        let idx = OrphanIndex::new();
        assert_eq!(idx.durable_watermark(), OrphanReplayWatermark::NONE);
    }

    #[test]
    fn watermark_is_none_after_new() {
        let idx = OrphanIndex::new();
        assert!(idx.durable_watermark().is_none());
    }

    // -- advance_watermark --

    #[test]
    fn advance_watermark_marks_dirty() {
        let mut idx = OrphanIndex::new();
        idx.clear_dirty();
        assert!(!idx.is_dirty());
        idx.advance_watermark(42);
        assert!(idx.is_dirty());
        assert_eq!(idx.durable_watermark().position, 42);
    }

    #[test]
    fn advance_watermark_is_monotonic() {
        let mut idx = OrphanIndex::new();
        idx.advance_watermark(100);
        idx.advance_watermark(50); // backwards: ignored
        assert_eq!(idx.durable_watermark().position, 100);
    }

    // -- set_watermark_from_cursor --

    #[test]
    fn set_watermark_from_cursor() {
        let mut idx = OrphanIndex::new();
        let cursor = OrphanCursor { position: 77 };
        idx.set_watermark_from_cursor(cursor);
        assert_eq!(idx.durable_watermark().position, 77);
        assert!(idx.is_dirty());
    }

    // -- encode_log includes watermark --

    #[test]
    fn encode_log_empty_preserves_watermark() {
        let idx = OrphanIndex::new();
        let log = idx.encode_log();
        assert_eq!(log.len(), 12);
        assert_eq!(&log[0..4], &0u32.to_le_bytes()); // count=0
        assert_eq!(&log[4..12], &0u64.to_le_bytes()); // watermark=NONE
    }

    #[test]
    fn encode_log_advanced_watermark() {
        let mut idx = OrphanIndex::new();
        idx.advance_watermark(12345);
        let log = idx.encode_log();
        assert_eq!(u64::from_le_bytes(log[4..12].try_into().unwrap()), 12345);
    }

    #[test]
    fn encode_log_with_entries_and_watermark() {
        let mut idx = OrphanIndex::new();
        idx.insert(10);
        idx.insert(20);
        idx.advance_watermark(30);
        let log = idx.encode_log();
        assert_eq!(u32::from_le_bytes(log[0..4].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(log[4..12].try_into().unwrap()), 30);
    }

    // -- recover_from_log restores watermark --

    #[test]
    fn recover_from_log_restores_watermark() {
        let mut idx = OrphanIndex::new();
        idx.insert(1);
        idx.advance_watermark(100);
        let log = idx.encode_log();

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        assert_eq!(recovered.durable_watermark().position, 100);
        assert_eq!(recovered.len(), 1);
    }

    #[test]
    fn recover_from_log_truncated_header_defaults_to_none() {
        // Less than 12 bytes header: watermark defaults to NONE
        let log = vec![0u8; 6]; // truncated header
        let err = OrphanIndex::recover_from_log(&log).unwrap_err();
        assert_eq!(err, LogRecoverError::TruncatedHeader);
    }

    #[test]
    fn recover_from_log_zero_watermark_is_none() {
        let mut idx = OrphanIndex::new();
        idx.insert(5);
        // watermark remains NONE (0)
        let log = idx.encode_log();

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        assert!(recovered.durable_watermark().is_none());
        assert_eq!(recovered.len(), 1);
    }

    // -- crash-during-append partial log recovery preserves watermark --

    #[test]
    fn recover_partial_log_half_entry_preserves_watermark() {
        let mut idx = OrphanIndex::new();
        idx.insert(1);
        idx.insert(2);
        idx.advance_watermark(42);
        let full_log = idx.encode_log();
        // Truncate halfway through the second entry
        let partial_len = 12 + super::LOG_RECORD_SIZE + super::LOG_RECORD_SIZE / 2;
        let partial = &full_log[..partial_len.min(full_log.len())];

        let (recovered, corrupted) = OrphanIndex::recover_from_log(partial).unwrap();
        assert_eq!(recovered.durable_watermark().position, 42);
        assert_eq!(recovered.len(), 1); // only first entry fully intact
        assert!(corrupted.is_empty()); // truncation, not corruption
    }

    // -- full pipeline: insert -> encode -> crash -> recover -> watermark ok --

    #[test]
    fn pipeline_insert_encode_recover_watermark() {
        let mut idx = OrphanIndex::new();
        // Simulate: orphan entries inserted, then watermark advanced after replay
        idx.insert(10);
        idx.insert(20);
        idx.advance_watermark(25);
        let log = idx.encode_log();

        // Simulate crash and recovery
        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        assert_eq!(recovered.len(), 2);
        // Watermark at 25 covers both inodes (10, 20)
        assert!(recovered.durable_watermark().covers(10));
        assert!(recovered.durable_watermark().covers(20));
        // But does NOT cover inode 30
        assert!(!recovered.durable_watermark().covers(30));
    }

    // -- watermark advance after recovery resumption --

    #[test]
    fn watermark_advance_after_recovery_incremental() {
        let mut idx = OrphanIndex::new();
        idx.insert(10);
        idx.insert(20);
        idx.insert(30);
        idx.advance_watermark(15);
        let log = idx.encode_log();

        let (mut recovered, _) = OrphanIndex::recover_from_log(&log).unwrap();
        assert_eq!(recovered.durable_watermark().position, 15);

        // Advance watermark further after re-processing more entries
        recovered.advance_watermark(35);
        assert!(recovered.durable_watermark().covers(30));
        assert!(recovered.is_dirty());
    }
}
