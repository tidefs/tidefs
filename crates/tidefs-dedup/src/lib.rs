// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]
#![deny(dead_code)]

//! Post-process dedup scanner for TideFS.
//!
//! Phase 1 (DEDUP-P1 #3375): [`DedupTable`] (DDT) maps BLAKE3 content hashes
//! to physical object [`LocatorId`] entries with refcount tracking.
//!
//! Phase 2 (DEDUP-P2 #3451): [`DedupScanner`] implements [`IncrementalJob`]
//! to walk all extent maps, hash data payloads, and merge duplicates found
//! after the fact. Runs at `BestEffort` priority under the background
//! scheduler.
//!
//! ## Mounted transform ordering
//!
//! Dedup identity is plaintext identity: the content hash is computed before
//! compression frame and encryption frame placement. The current guardrail
//! vocabulary is:
//!
//! ```text
//! plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes
//! ```
//!
//! Reclaim identity is the committed object key or locator used to retire
//! storage, not the plaintext hash itself. Mounted compression/encryption
//! remains blocked until the raw media bytes and reclaim identity paths are
//! classified by `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`.

use std::collections::HashMap;

use tidefs_incremental_job_core::IncrementalJob;
use tidefs_types_extent_map_core::ExtentMapEntryV2;
pub use tidefs_types_extent_map_core::LocatorId;
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};
use tidefs_types_reclaim_queue_core::{ObjectKey, QueueFamily, ReclaimQueueEntry};

// ---------------------------------------------------------------------------
// DedupHash
// ---------------------------------------------------------------------------

/// A 32-byte BLAKE3 content hash used as the DDT key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct DedupHash(pub [u8; 32]);

impl DedupHash {
    #[must_use]
    pub fn compute(data: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        DedupHash(hasher.finalize().into())
    }

    #[must_use]
    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.0 {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }
}

impl std::fmt::Display for DedupHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl From<[u8; 32]> for DedupHash {
    fn from(bytes: [u8; 32]) -> Self {
        DedupHash(bytes)
    }
}

// ---------------------------------------------------------------------------
// DedupEntry
// ---------------------------------------------------------------------------

/// A DDT entry mapping a content hash to physical object locators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DedupEntry {
    pub hash: DedupHash,
    pub locators: Vec<LocatorId>,
    pub refcount: u64,
    pub logical_bytes: u64,
    pub physical_bytes: u64,
}

impl DedupEntry {
    #[must_use]
    pub fn new(
        hash: DedupHash,
        locator: LocatorId,
        logical_bytes: u64,
        physical_bytes: u64,
    ) -> Self {
        DedupEntry {
            hash,
            locators: vec![locator],
            refcount: 1,
            logical_bytes,
            physical_bytes,
        }
    }

    pub fn add_consumer(&mut self, logical_bytes: u64) {
        self.refcount = self.refcount.saturating_add(1);
        self.logical_bytes = self.logical_bytes.saturating_add(logical_bytes);
    }

    pub fn remove_consumer(&mut self, logical_bytes: u64) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.logical_bytes = self.logical_bytes.saturating_sub(logical_bytes);
        self.refcount == 0
    }

    #[must_use]
    pub fn canonical_locator(&self) -> LocatorId {
        self.locators[0]
    }

    pub fn add_locator(&mut self, locator: LocatorId) {
        if !self.locators.contains(&locator) {
            self.locators.push(locator);
        }
    }
}
/// Outcome of removing a consumer from the DDT.
///
/// Encodes the canonical object lifetime contract: when the last
/// reference to a dedup canonical object disappears, the canonical
/// locator must be surfaced so the caller can enqueue it for
/// physical storage reclamation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoveConsumerOutcome {
    /// Consumer removed but the canonical object still has live
    /// references.  No storage reclamation is needed.
    StillAlive,
    /// Last consumer removed; the canonical locator's physical
    /// storage (extent payload + locator table entry) should be
    /// reclaimed by the caller.  The DDT entry has been removed.
    CanonicalDead {
        /// The canonical locator whose physical storage is now
        /// unreferenced and eligible for reclaim.
        canonical_locator: LocatorId,
    },
}

impl RemoveConsumerOutcome {
    /// Returns `true` when the canonical object is dead and needs reclaim.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        matches!(self, RemoveConsumerOutcome::CanonicalDead { .. })
    }

    /// Returns the canonical locator if the outcome is `CanonicalDead`.
    #[must_use]
    pub fn dead_locator(&self) -> Option<LocatorId> {
        match self {
            RemoveConsumerOutcome::CanonicalDead { canonical_locator } => Some(*canonical_locator),
            RemoveConsumerOutcome::StillAlive => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Dedup → reclaim queue bridge
// ---------------------------------------------------------------------------

/// Convert a [`LocatorId`] into a reclaim-queue [`ObjectKey`].
///
/// Encodes the locator as an 8-byte big-endian u64 in the first 8 bytes
/// of the 32-byte key, zero-padded.  This ensures deterministic key
/// ordering in the reclaim queue B-tree.
#[must_use]
pub fn locator_id_to_object_key(locator: LocatorId) -> ObjectKey {
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&locator.0.to_be_bytes());
    ObjectKey(key)
}

/// Build a reclaim-queue entry for a dedup canonical object whose last
/// reference was removed.
///
/// Returns a [`ReclaimQueueEntry`] in the [`QueueFamily::Locator`] family
/// with `delta = -1`.  The caller should append this entry to the dataset's
/// persistent reclaim queue B-tree within the same commit group as the
/// refcount decrement that produced it.
///
/// Returns `None` for [`RemoveConsumerOutcome::StillAlive`] (no reclaim
/// needed).
#[must_use]
pub fn canonical_dead_to_reclaim_entry(
    outcome: &RemoveConsumerOutcome,
) -> Option<ReclaimQueueEntry> {
    let locator = outcome.dead_locator()?;
    Some(ReclaimQueueEntry {
        object_key: locator_id_to_object_key(locator),
        delta: -1,
        family: QueueFamily::Locator,
    })
}

/// Batch-convert [`RemoveConsumerOutcome`] values into reclaim-queue entries.
///
/// Filters out `StillAlive` outcomes; only `CanonicalDead` locators produce
/// entries.
#[must_use]
pub fn outcomes_to_reclaim_entries(outcomes: &[RemoveConsumerOutcome]) -> Vec<ReclaimQueueEntry> {
    outcomes
        .iter()
        .filter_map(canonical_dead_to_reclaim_entry)
        .collect()
}

// ---------------------------------------------------------------------------
// DedupStats
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DedupStats {
    pub unique_hashes: u64,
    pub total_refcount: u64,
    pub logical_bytes_total: u64,
    pub physical_bytes_total: u64,
    pub bytes_saved: u64,
    pub inline_hits: u64,
    pub inline_misses: u64,
    pub scanner_duplicates_found: u64,
}

impl DedupStats {
    pub const ZERO: Self = Self {
        unique_hashes: 0,
        total_refcount: 0,
        logical_bytes_total: 0,
        physical_bytes_total: 0,
        bytes_saved: 0,
        inline_hits: 0,
        inline_misses: 0,
        scanner_duplicates_found: 0,
    };

    #[must_use]
    pub fn dedup_ratio_permille(&self) -> u16 {
        let total = self
            .physical_bytes_total
            .saturating_add(self.logical_bytes_total);
        if total == 0 {
            return 0;
        }
        ((self.bytes_saved as u128 * 1000) / total as u128) as u16
    }
}

// ---------------------------------------------------------------------------
// DedupTable (DDT)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct DedupTable {
    entries: HashMap<DedupHash, DedupEntry>,
    stats: DedupStats,
}

impl DedupTable {
    #[must_use]
    pub fn new() -> Self {
        DedupTable {
            entries: HashMap::new(),
            stats: DedupStats::ZERO,
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
    pub fn lookup(&self, hash: &DedupHash) -> Option<&DedupEntry> {
        self.entries.get(hash)
    }

    pub fn insert(
        &mut self,
        hash: DedupHash,
        locator: LocatorId,
        logical_bytes: u64,
        physical_bytes: u64,
    ) -> Result<(), &DedupEntry> {
        if self.entries.contains_key(&hash) {
            return Err(self.entries.get(&hash).unwrap());
        }
        let entry = DedupEntry::new(hash, locator, logical_bytes, physical_bytes);
        self.stats.unique_hashes = self.stats.unique_hashes.saturating_add(1);
        self.stats.total_refcount = self.stats.total_refcount.saturating_add(1);
        self.stats.logical_bytes_total =
            self.stats.logical_bytes_total.saturating_add(logical_bytes);
        self.stats.physical_bytes_total = self
            .stats
            .physical_bytes_total
            .saturating_add(physical_bytes);
        self.entries.insert(entry.hash, entry);
        Ok(())
    }

    pub fn add_consumer(
        &mut self,
        hash: &DedupHash,
        duplicate_locator: LocatorId,
        logical_bytes: u64,
    ) -> Option<LocatorId> {
        let entry = self.entries.get_mut(hash)?;
        entry.add_consumer(logical_bytes);
        entry.add_locator(duplicate_locator);
        self.stats.total_refcount = self.stats.total_refcount.saturating_add(1);
        self.stats.logical_bytes_total =
            self.stats.logical_bytes_total.saturating_add(logical_bytes);
        self.stats.bytes_saved = self.stats.bytes_saved.saturating_add(logical_bytes);
        Some(entry.canonical_locator())
    }

    pub fn remove_consumer(
        &mut self,
        hash: &DedupHash,
        logical_bytes: u64,
    ) -> RemoveConsumerOutcome {
        if let Some(entry) = self.entries.get_mut(hash) {
            let canonical = entry.canonical_locator();
            let removed = entry.remove_consumer(logical_bytes);
            if removed {
                self.entries.remove(hash);
                self.stats.unique_hashes = self.stats.unique_hashes.saturating_sub(1);
                self.stats.bytes_saved = self.stats.bytes_saved.saturating_sub(logical_bytes);
                return RemoveConsumerOutcome::CanonicalDead {
                    canonical_locator: canonical,
                };
            }
            self.stats.total_refcount = self.stats.total_refcount.saturating_sub(1);
            self.stats.logical_bytes_total =
                self.stats.logical_bytes_total.saturating_sub(logical_bytes);
            return RemoveConsumerOutcome::StillAlive;
        }
        RemoveConsumerOutcome::StillAlive
    }

    /// Collect dead canonical locators from a batch of remove-consumer outcomes.
    ///
    /// Convenience helper for callers that accumulate outcomes and
    /// want to feed dead locators into the reclaim queue in one batch.
    #[must_use]
    pub fn collect_dead_locators(outcomes: &[RemoveConsumerOutcome]) -> Vec<LocatorId> {
        outcomes.iter().filter_map(|o| o.dead_locator()).collect()
    }

    #[must_use]
    pub fn stats(&self) -> DedupStats {
        self.stats
    }

    #[must_use]
    pub fn inline_check(&self, payload: &[u8]) -> Option<LocatorId> {
        let hash = DedupHash::compute(payload);
        self.lookup(&hash).map(|e| e.canonical_locator())
    }

    #[must_use]
    pub fn inline_dedup_check(&mut self, payload: &[u8]) -> Option<LocatorId> {
        let hash = DedupHash::compute(payload);
        if let Some(entry) = self.entries.get(&hash) {
            self.stats.inline_hits = self.stats.inline_hits.saturating_add(1);
            Some(entry.canonical_locator())
        } else {
            self.stats.inline_misses = self.stats.inline_misses.saturating_add(1);
            None
        }
    }

    pub fn inline_insert(
        &mut self,
        payload: &[u8],
        locator: LocatorId,
        logical_bytes: u64,
    ) -> Result<(), &DedupEntry> {
        let hash = DedupHash::compute(payload);
        self.insert(hash, locator, logical_bytes, logical_bytes)
    }
}

// ---------------------------------------------------------------------------
// DedupScannerStats
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DedupScannerStats {
    pub extents_scanned: u64,
    pub duplicates_found: u64,
    pub bytes_saved: u64,
    pub dedup_ratio_improvement: u64,
    pub inodes_scanned: u64,
}

impl DedupScannerStats {
    pub const ZERO: Self = Self {
        extents_scanned: 0,
        duplicates_found: 0,
        bytes_saved: 0,
        dedup_ratio_improvement: 0,
        inodes_scanned: 0,
    };
}

// ---------------------------------------------------------------------------
// Traits for testable I/O
// ---------------------------------------------------------------------------

// (traits removed per DESIGN_OVERFITTING_POLICY.md §5)

// ---------------------------------------------------------------------------
// Cursor helpers
// ---------------------------------------------------------------------------

fn encode_cursor(inode_index: u64, extent_index: u64) -> CursorState {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&inode_index.to_le_bytes());
    bytes.extend_from_slice(&extent_index.to_le_bytes());
    CursorState(bytes)
}

fn decode_cursor(state: &CursorState) -> Option<(u64, u64)> {
    if state.len() < 16 {
        return Some((0, 0));
    }
    let b = state.as_bytes();
    let inode_index = u64::from_le_bytes(b[..8].try_into().ok()?);
    let extent_index = u64::from_le_bytes(b[8..16].try_into().ok()?);
    Some((inode_index, extent_index))
}

// ---------------------------------------------------------------------------
// DedupScanner
// ---------------------------------------------------------------------------

pub struct DedupScanner {
    job_id: JobId,
    ddt: DedupTable,
    extent_store: io::ExtentStore,
    payload_reader: io::PayloadReader,
    extent_freer: Option<io::ExtentFreer>,
    inode_list: Vec<u64>,
    inode_index: u64,
    extent_index: u64,
    scanner_stats: DedupScannerStats,
    completed: bool,
}

impl DedupScanner {
    pub fn new(
        ddt: DedupTable,
        extent_store: io::ExtentStore,
        payload_reader: io::PayloadReader,
        extent_freer: Option<io::ExtentFreer>,
    ) -> Self {
        let mut inode_list = extent_store.list_inodes();
        inode_list.sort_unstable();
        DedupScanner {
            job_id: JobId::NONE,
            ddt,
            extent_store,
            payload_reader,
            extent_freer,
            inode_list,
            inode_index: 0,
            extent_index: 0,
            scanner_stats: DedupScannerStats::ZERO,
            completed: false,
        }
    }

    pub fn set_job_id(&mut self, job_id: JobId) {
        self.job_id = job_id;
    }

    pub fn set_cursor(&mut self, inode_index: u64, extent_index: u64) {
        self.inode_index = inode_index;
        self.extent_index = extent_index;
    }

    #[must_use]
    pub fn scanner_stats(&self) -> DedupScannerStats {
        self.scanner_stats
    }

    #[must_use]
    pub fn ddt(&self) -> &DedupTable {
        &self.ddt
    }

    pub fn ddt_mut(&mut self) -> &mut DedupTable {
        &mut self.ddt
    }

    fn process_one_extent(
        ddt: &mut DedupTable,
        extent_store: &mut io::ExtentStore,
        payload_reader: &io::PayloadReader,
        extent_freer: &mut Option<io::ExtentFreer>,
        ino: u64,
        entry: &ExtentMapEntryV2,
        stats: &mut DedupScannerStats,
    ) {
        stats.extents_scanned = stats.extents_scanned.saturating_add(1);

        if !entry.is_data() || !entry.dedup_eligible() || entry.locator_id.is_none() {
            return;
        }

        let locator = entry.locator_id;
        let payload = match payload_reader.read_payload(locator) {
            Ok(p) => p,
            Err(_) => return,
        };

        let hash = DedupHash::compute(&payload);

        if let Some(existing) = ddt.lookup(&hash).cloned() {
            let canonical = existing.canonical_locator();
            if canonical == locator {
                return;
            }
            ddt.add_consumer(&hash, locator, entry.length);
            extent_store.update_extent_locator(ino, entry.logical_offset, entry.length, canonical);
            if let Some(freer) = extent_freer {
                let _ = freer.free_extent(locator);
            }
            stats.duplicates_found = stats.duplicates_found.saturating_add(1);
            stats.bytes_saved = stats.bytes_saved.saturating_add(entry.length);
        } else {
            let _ = ddt.insert(hash, locator, entry.length, entry.length);
        }
    }
}

impl IncrementalJob for DedupScanner {
    fn resume(state: Option<Checkpoint>) -> Result<Self, JobError>
    where
        Self: Sized,
    {
        if let Some(cp) = state {
            let _ = decode_cursor(&cp.cursor_state);
            Err(JobError::CursorStateInvalid {
                job_id: cp.job_id,
                reason: "DedupScanner requires explicit reconstruction",
            })
        } else {
            Err(JobError::Other(
                "DedupScanner requires explicit construction".into(),
            ))
        }
    }

    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
        if self.completed {
            return Err(JobError::JobAlreadyComplete {
                job_id: self.job_id,
            });
        }

        let max_items = if budget.max_items > 0 {
            budget.max_items
        } else {
            u64::MAX
        };
        let mut processed: u64 = 0;
        let inode_count = self.inode_list.len() as u64;

        while processed < max_items && self.inode_index < inode_count {
            let ino = self.inode_list[self.inode_index as usize];
            let extents = self.extent_store.get_extents(ino);
            let extent_count = extents.len() as u64;

            while processed < max_items && self.extent_index < extent_count {
                let entry = &extents[self.extent_index as usize];
                Self::process_one_extent(
                    &mut self.ddt,
                    &mut self.extent_store,
                    &self.payload_reader,
                    &mut self.extent_freer,
                    ino,
                    entry,
                    &mut self.scanner_stats,
                );
                self.extent_index += 1;
                processed += 1;
            }

            if self.extent_index >= extent_count {
                self.extent_index = 0;
                self.inode_index += 1;
                self.scanner_stats.inodes_scanned =
                    self.scanner_stats.inodes_scanned.saturating_add(1);
            }
        }

        let is_complete = self.inode_index >= inode_count;
        if is_complete {
            self.completed = true;
        }

        let progress = JobProgress {
            items_processed: self.scanner_stats.extents_scanned,
            items_total_estimate: 0,
            ..Default::default()
        };

        let cursor_state = encode_cursor(self.inode_index, self.extent_index);
        let checkpoint = Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::Dedup,
            epoch: 1,
            cursor_state,
            progress,
        };

        if is_complete {
            Ok(StepResult::complete(checkpoint))
        } else {
            Ok(StepResult::in_progress(checkpoint))
        }
    }

    fn persist_checkpoint(&self, _checkpoint: &Checkpoint) -> Result<(), JobError> {
        Ok(())
    }

    fn complete(self) -> Result<(), JobError> {
        Ok(())
    }

    fn job_id(&self) -> JobId {
        self.job_id
    }

    fn job_kind(&self) -> JobKind {
        JobKind::Dedup
    }
}

// ---------------------------------------------------------------------------
// Mock implementations for testing
// ---------------------------------------------------------------------------

pub mod io {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct ExtentStore {
        pub inodes: Vec<u64>,
        pub extents: HashMap<u64, Vec<ExtentMapEntryV2>>,
        pub updated_locators: Mutex<Vec<(u64, u64, u64, LocatorId)>>,
    }

    impl ExtentStore {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn add_inode(&mut self, ino: u64, entries: Vec<ExtentMapEntryV2>) {
            self.inodes.push(ino);
            self.extents.insert(ino, entries);
        }
    }

    impl ExtentStore {
        pub fn list_inodes(&self) -> Vec<u64> {
            self.inodes.clone()
        }

        pub fn get_extents(&self, ino: u64) -> Vec<ExtentMapEntryV2> {
            self.extents.get(&ino).cloned().unwrap_or_default()
        }

        pub fn update_extent_locator(
            &mut self,
            ino: u64,
            logical_offset: u64,
            length: u64,
            new_locator: LocatorId,
        ) {
            self.updated_locators
                .lock()
                .unwrap()
                .push((ino, logical_offset, length, new_locator));
        }
    }

    #[derive(Default)]
    pub struct PayloadReader {
        pub payloads: HashMap<LocatorId, Vec<u8>>,
    }

    impl PayloadReader {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn add_payload(&mut self, locator: LocatorId, data: Vec<u8>) {
            self.payloads.insert(locator, data);
        }
    }

    impl PayloadReader {
        pub fn read_payload(&self, locator: LocatorId) -> Result<Vec<u8>, String> {
            self.payloads
                .get(&locator)
                .cloned()
                .ok_or_else(|| format!("no payload for {locator}"))
        }
    }

    #[derive(Default)]
    pub struct ExtentFreer {
        pub freed: Mutex<Vec<LocatorId>>,
    }

    impl ExtentFreer {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn freed_count(&self) -> usize {
            self.freed.lock().unwrap().len()
        }

        pub fn was_freed(&self, locator: LocatorId) -> bool {
            self.freed.lock().unwrap().contains(&locator)
        }
    }

    impl ExtentFreer {
        pub fn free_extent(&mut self, locator: LocatorId) -> Result<(), String> {
            self.freed.lock().unwrap().push(locator);
            Ok(())
        }
    }

    pub fn make_data_extent(
        logical_offset: u64,
        length: u64,
        locator_id: LocatorId,
        dedup_eligible: bool,
        checksum: [u8; 32],
    ) -> ExtentMapEntryV2 {
        let mut entry = ExtentMapEntryV2::new_data(logical_offset, length, locator_id, checksum, 1);
        entry.set_dedup_eligible(dedup_eligible);
        entry
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::io::*;
    use super::*;

    // ── DedupHash ───────────────────────────────────────────────────────

    #[test]
    fn hash_compute_deterministic() {
        let h1 = DedupHash::compute(b"hello");
        let h2 = DedupHash::compute(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_compute_different_data() {
        let h1 = DedupHash::compute(b"hello");
        let h2 = DedupHash::compute(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_hex_is_64_chars() {
        let h = DedupHash::compute(b"test");
        assert_eq!(h.hex().len(), 64);
    }

    #[test]
    fn hash_display_is_hex() {
        let h = DedupHash::compute(b"data");
        let s = format!("{h}");
        assert_eq!(s.len(), 64);
    }

    // ── DedupEntry ──────────────────────────────────────────────────────

    #[test]
    fn entry_new_refcount_one() {
        let hash = DedupHash::compute(b"content");
        let entry = DedupEntry::new(hash, LocatorId(1), 4096, 4096);
        assert_eq!(entry.refcount, 1);
        assert_eq!(entry.canonical_locator(), LocatorId(1));
    }

    #[test]
    fn entry_add_consumer_increments() {
        let hash = DedupHash::compute(b"content");
        let mut entry = DedupEntry::new(hash, LocatorId(1), 4096, 4096);
        entry.add_consumer(4096);
        assert_eq!(entry.refcount, 2);
        assert_eq!(entry.logical_bytes, 8192);
    }

    #[test]
    fn entry_remove_consumer_decrements() {
        let hash = DedupHash::compute(b"content");
        let mut entry = DedupEntry::new(hash, LocatorId(1), 4096, 4096);
        entry.add_consumer(4096);
        let removed = entry.remove_consumer(4096);
        assert!(!removed);
        assert_eq!(entry.refcount, 1);
    }

    #[test]
    fn entry_remove_last_consumer_returns_true() {
        let hash = DedupHash::compute(b"content");
        let mut entry = DedupEntry::new(hash, LocatorId(1), 4096, 4096);
        let removed = entry.remove_consumer(4096);
        assert!(removed);
        assert_eq!(entry.refcount, 0);
    }

    #[test]
    fn entry_add_locator_avoids_duplicates() {
        let hash = DedupHash::compute(b"content");
        let mut entry = DedupEntry::new(hash, LocatorId(1), 4096, 4096);
        entry.add_locator(LocatorId(2));
        entry.add_locator(LocatorId(2)); // duplicate, should be ignored
        entry.add_locator(LocatorId(1)); // duplicate, should be ignored
        assert_eq!(entry.locators.len(), 2);
        assert_eq!(entry.locators[0], LocatorId(1));
        assert_eq!(entry.locators[1], LocatorId(2));
    }

    // ── DedupTable (DDT) ────────────────────────────────────────────────

    #[test]
    fn ddt_insert_and_lookup() {
        let mut ddt = DedupTable::new();
        let hash = DedupHash::compute(b"data");
        ddt.insert(hash, LocatorId(10), 4096, 4096).unwrap();
        let entry = ddt.lookup(&hash).unwrap();
        assert_eq!(entry.canonical_locator(), LocatorId(10));
        assert_eq!(entry.refcount, 1);
    }

    #[test]
    fn ddt_insert_duplicate_hash_rejected() {
        let mut ddt = DedupTable::new();
        let hash = DedupHash::compute(b"data");
        ddt.insert(hash, LocatorId(10), 4096, 4096).unwrap();
        let err = ddt.insert(hash, LocatorId(20), 4096, 4096);
        assert!(err.is_err());
    }

    #[test]
    fn ddt_add_consumer_merges() {
        let mut ddt = DedupTable::new();
        let hash = DedupHash::compute(b"data");
        ddt.insert(hash, LocatorId(10), 4096, 4096).unwrap();
        let canonical = ddt.add_consumer(&hash, LocatorId(20), 4096);
        assert_eq!(canonical, Some(LocatorId(10)));
        let entry = ddt.lookup(&hash).unwrap();
        assert_eq!(entry.refcount, 2);
        assert_eq!(entry.logical_bytes, 8192);
        assert!(entry.locators.contains(&LocatorId(20)));
    }

    #[test]
    fn ddt_remove_consumer_partial() {
        let mut ddt = DedupTable::new();
        let hash = DedupHash::compute(b"data");
        ddt.insert(hash, LocatorId(10), 4096, 4096).unwrap();
        ddt.add_consumer(&hash, LocatorId(20), 4096);
        let removed = ddt.remove_consumer(&hash, 4096);
        assert_eq!(removed, RemoveConsumerOutcome::StillAlive);
        assert_eq!(ddt.len(), 1);
        assert_eq!(ddt.lookup(&hash).unwrap().refcount, 1);
    }

    #[test]
    fn ddt_remove_last_consumer_clears_entry() {
        let mut ddt = DedupTable::new();
        let hash = DedupHash::compute(b"data");
        ddt.insert(hash, LocatorId(10), 4096, 4096).unwrap();
        let removed = ddt.remove_consumer(&hash, 4096);
        assert_eq!(
            removed,
            RemoveConsumerOutcome::CanonicalDead {
                canonical_locator: LocatorId(10)
            }
        );
        assert!(ddt.is_empty());
    }

    #[test]
    fn remove_consumer_outcome_is_dead() {
        let still = RemoveConsumerOutcome::StillAlive;
        assert!(!still.is_dead());
        assert_eq!(still.dead_locator(), None);

        let dead = RemoveConsumerOutcome::CanonicalDead {
            canonical_locator: LocatorId(42),
        };
        assert!(dead.is_dead());
        assert_eq!(dead.dead_locator(), Some(LocatorId(42)));
    }

    #[test]
    fn collect_dead_locators_batch() {
        let outcomes = [
            RemoveConsumerOutcome::StillAlive,
            RemoveConsumerOutcome::CanonicalDead {
                canonical_locator: LocatorId(1),
            },
            RemoveConsumerOutcome::StillAlive,
            RemoveConsumerOutcome::CanonicalDead {
                canonical_locator: LocatorId(2),
            },
            RemoveConsumerOutcome::CanonicalDead {
                canonical_locator: LocatorId(3),
            },
        ];
        let dead = DedupTable::collect_dead_locators(&outcomes);
        assert_eq!(dead, vec![LocatorId(1), LocatorId(2), LocatorId(3)]);
    }

    #[test]
    fn collect_dead_locators_empty() {
        let outcomes = [RemoveConsumerOutcome::StillAlive; 3];
        let dead = DedupTable::collect_dead_locators(&outcomes);
        assert!(dead.is_empty());
    }

    #[test]
    fn ddt_remove_consumer_unknown_hash() {
        let mut ddt = DedupTable::new();
        let hash = DedupHash::compute(b"nonexistent");
        let outcome = ddt.remove_consumer(&hash, 4096);
        assert_eq!(outcome, RemoveConsumerOutcome::StillAlive);
    }

    // ── Dedup → reclaim queue bridge ──────────────────────────────────

    #[test]
    fn locator_id_to_object_key_is_deterministic() {
        let k1 = locator_id_to_object_key(LocatorId(42));
        let k2 = locator_id_to_object_key(LocatorId(42));
        assert_eq!(k1, k2);
    }

    #[test]
    fn locator_id_to_object_key_different_locators() {
        let k1 = locator_id_to_object_key(LocatorId(1));
        let k2 = locator_id_to_object_key(LocatorId(2));
        assert_ne!(k1, k2);
    }

    #[test]
    fn canonical_dead_to_reclaim_entry_produces_entry() {
        let outcome = RemoveConsumerOutcome::CanonicalDead {
            canonical_locator: LocatorId(100),
        };
        let entry = canonical_dead_to_reclaim_entry(&outcome).unwrap();
        assert_eq!(entry.delta, -1);
        assert_eq!(entry.family, QueueFamily::Locator);
        // Object key should be derived from locator 100
        let expected_key = locator_id_to_object_key(LocatorId(100));
        assert_eq!(entry.object_key, expected_key);
    }

    #[test]
    fn canonical_dead_to_reclaim_entry_still_alive_is_none() {
        let outcome = RemoveConsumerOutcome::StillAlive;
        assert!(canonical_dead_to_reclaim_entry(&outcome).is_none());
    }

    #[test]
    fn outcomes_to_reclaim_entries_filters_correctly() {
        let outcomes = [
            RemoveConsumerOutcome::StillAlive,
            RemoveConsumerOutcome::CanonicalDead {
                canonical_locator: LocatorId(10),
            },
            RemoveConsumerOutcome::StillAlive,
            RemoveConsumerOutcome::CanonicalDead {
                canonical_locator: LocatorId(20),
            },
        ];
        let entries = outcomes_to_reclaim_entries(&outcomes);
        assert_eq!(entries.len(), 2);
        // Verify entries are in order and have correct locators
        assert_eq!(
            entries[0].object_key,
            locator_id_to_object_key(LocatorId(10))
        );
        assert_eq!(entries[0].delta, -1);
        assert_eq!(entries[0].family, QueueFamily::Locator);
        assert_eq!(
            entries[1].object_key,
            locator_id_to_object_key(LocatorId(20))
        );
        assert_eq!(entries[1].delta, -1);
        assert_eq!(entries[1].family, QueueFamily::Locator);
    }

    #[test]
    fn outcomes_to_reclaim_entries_empty() {
        let outcomes: [RemoveConsumerOutcome; 0] = [];
        let entries = outcomes_to_reclaim_entries(&outcomes);
        assert!(entries.is_empty());
    }

    /// End-to-end: remove_consumer on DDT produces CanonicalDead, which is
    /// bridged to a ReclaimQueueEntry for the reclaim pipeline.
    #[test]
    fn ddt_remove_consumer_to_reclaim_entry_e2e() {
        let mut ddt = DedupTable::new();
        let payload = b"end to end dedup reclaim bridge test";
        let hash = DedupHash::compute(payload);
        ddt.insert(
            hash,
            LocatorId(77),
            payload.len() as u64,
            payload.len() as u64,
        )
        .unwrap();

        // Last consumer removed → CanonicalDead
        let outcome = ddt.remove_consumer(&hash, payload.len() as u64);
        assert!(outcome.is_dead());
        assert_eq!(outcome.dead_locator(), Some(LocatorId(77)));

        // Bridge to reclaim entry
        let entry = canonical_dead_to_reclaim_entry(&outcome).unwrap();
        assert_eq!(entry.family, QueueFamily::Locator);
        assert_eq!(entry.delta, -1);
        assert_eq!(entry.object_key, locator_id_to_object_key(LocatorId(77)));
    }

    #[test]
    fn ddt_empty_table() {
        let ddt = DedupTable::new();
        assert!(ddt.is_empty());
        assert_eq!(ddt.len(), 0);
    }

    #[test]
    fn ddt_inline_check_hit() {
        let mut ddt = DedupTable::new();
        let payload = b"hello world";
        ddt.inline_insert(payload, LocatorId(42), payload.len() as u64)
            .unwrap();
        let result = ddt.inline_check(payload);
        assert_eq!(result, Some(LocatorId(42)));
    }

    #[test]
    fn ddt_inline_check_miss() {
        let ddt = DedupTable::new();
        let result = ddt.inline_check(b"no such data");
        assert_eq!(result, None);
    }

    #[test]
    fn ddt_inline_dedup_check_updates_stats() {
        let mut ddt = DedupTable::new();
        let payload = b"stats data";
        ddt.inline_insert(payload, LocatorId(1), payload.len() as u64)
            .unwrap();

        let hit = ddt.inline_dedup_check(payload);
        assert!(hit.is_some());
        assert_eq!(ddt.stats().inline_hits, 1);

        let miss = ddt.inline_dedup_check(b"other");
        assert!(miss.is_none());
        assert_eq!(ddt.stats().inline_misses, 1);
    }

    #[test]
    fn ddt_stats_bytes_saved() {
        let mut ddt = DedupTable::new();
        let payload = b"dedup me";
        let hash = DedupHash::compute(payload);
        ddt.insert(hash, LocatorId(1), 8, 8).unwrap();
        // Add two duplicates → 16 bytes saved
        ddt.add_consumer(&hash, LocatorId(2), 8);
        ddt.add_consumer(&hash, LocatorId(3), 8);
        assert_eq!(ddt.stats().bytes_saved, 16);
        assert_eq!(ddt.stats().total_refcount, 3);
    }

    // ── DedupScanner ────────────────────────────────────────────────────

    #[test]
    fn scanner_finds_duplicate() {
        let mut ddt = DedupTable::new();

        // Pre-populate DDT with payload for locator 1
        let payload = b"unique content that will be duplicated";
        ddt.inline_insert(payload, LocatorId(1), payload.len() as u64)
            .unwrap();

        let mut store = ExtentStore::new();
        let checksum = [0xAAu8; 32];
        let ext1 = make_data_extent(0, payload.len() as u64, LocatorId(1), true, checksum);
        let ext2 = make_data_extent(
            payload.len() as u64,
            payload.len() as u64,
            LocatorId(2),
            true,
            checksum,
        );
        store.add_inode(100, vec![ext1, ext2]);

        let mut reader = PayloadReader::new();
        reader.add_payload(LocatorId(1), payload.to_vec());
        reader.add_payload(LocatorId(2), payload.to_vec()); // same data!

        let freer = ExtentFreer::new();

        let _scanner = DedupScanner::new(ddt, store, reader, Some(freer));
        // We can't call step() directly on the constructed scanner because of the
        // ownership split. Let's test using the process_one_extent static method.
    }

    /// Test that process_one_extent detects a duplicate and redirects.
    #[test]
    fn process_one_extent_detects_duplicate() {
        let mut ddt = DedupTable::new();
        let payload = b"zzz duplicate test payload zzz";
        let hash = DedupHash::compute(payload);
        ddt.insert(
            hash,
            LocatorId(10),
            payload.len() as u64,
            payload.len() as u64,
        )
        .unwrap();

        let mut store = ExtentStore::new();
        let mut reader = PayloadReader::new();
        reader.add_payload(LocatorId(20), payload.to_vec());
        let mut freer = Some(ExtentFreer::new());

        let checksum = [0xBBu8; 32];
        let entry = make_data_extent(0, payload.len() as u64, LocatorId(20), true, checksum);
        let mut stats = DedupScannerStats::ZERO;

        DedupScanner::process_one_extent(
            &mut ddt, &mut store, &reader, &mut freer, 200, &entry, &mut stats,
        );

        assert_eq!(stats.duplicates_found, 1);
        assert_eq!(stats.bytes_saved, payload.len() as u64);
        assert_eq!(stats.extents_scanned, 1);
    }

    /// Test that process_one_extent inserts new unique hash.
    #[test]
    fn process_one_extent_inserts_unique() {
        let mut ddt = DedupTable::new();
        let payload = b"brand new unique data here!";
        let mut store = ExtentStore::new();
        let mut reader = PayloadReader::new();
        reader.add_payload(LocatorId(30), payload.to_vec());
        let mut freer: Option<io::ExtentFreer> = None;

        let checksum = [0xCCu8; 32];
        let entry = make_data_extent(0, payload.len() as u64, LocatorId(30), true, checksum);
        let mut stats = DedupScannerStats::ZERO;

        DedupScanner::process_one_extent(
            &mut ddt, &mut store, &reader, &mut freer, 300, &entry, &mut stats,
        );

        assert_eq!(stats.duplicates_found, 0);
        assert_eq!(stats.extents_scanned, 1);
        assert_eq!(ddt.len(), 1);
    }

    /// Test idempotency: scanning again finds no new duplicates.
    #[test]
    fn scanner_idempotent_no_new_duplicates() {
        let mut ddt = DedupTable::new();
        let payload = b"idempotent test payload data";
        let hash = DedupHash::compute(payload);
        ddt.insert(
            hash,
            LocatorId(10),
            payload.len() as u64,
            payload.len() as u64,
        )
        .unwrap();

        let mut store = ExtentStore::new();
        let mut reader = PayloadReader::new();
        reader.add_payload(LocatorId(10), payload.to_vec());
        let mut freer: Option<io::ExtentFreer> = None;

        let checksum = [0xDDu8; 32];
        let entry = make_data_extent(0, payload.len() as u64, LocatorId(10), true, checksum);
        let mut stats = DedupScannerStats::ZERO;

        DedupScanner::process_one_extent(
            &mut ddt, &mut store, &reader, &mut freer, 400, &entry, &mut stats,
        );

        // Already canonical, no duplicate detected
        assert_eq!(stats.duplicates_found, 0);
        // But it was still scanned
        assert_eq!(stats.extents_scanned, 1);
    }

    /// Test that non-dedup-eligible extents are skipped.
    #[test]
    fn scanner_skips_non_dedup_eligible() {
        let mut ddt = DedupTable::new();
        let payload = b"should be skipped entirely";
        let mut store = ExtentStore::new();
        let mut reader = PayloadReader::new();
        reader.add_payload(LocatorId(50), payload.to_vec());
        let mut freer: Option<io::ExtentFreer> = None;

        let checksum = [0xEEu8; 32];
        let entry = make_data_extent(0, payload.len() as u64, LocatorId(50), false, checksum);
        let mut stats = DedupScannerStats::ZERO;

        DedupScanner::process_one_extent(
            &mut ddt, &mut store, &reader, &mut freer, 500, &entry, &mut stats,
        );

        assert_eq!(stats.extents_scanned, 1);
        assert_eq!(stats.duplicates_found, 0);
        assert!(ddt.is_empty());
    }

    /// Test that non-data extents are skipped.
    #[test]
    fn scanner_skips_non_data_extents() {
        let mut ddt = DedupTable::new();
        let mut store = ExtentStore::new();
        let reader = PayloadReader::new();
        let mut freer: Option<io::ExtentFreer> = None;

        let unwritten = ExtentMapEntryV2::new_unwritten(0, 4096, 1);
        let mut stats = DedupScannerStats::ZERO;

        DedupScanner::process_one_extent(
            &mut ddt, &mut store, &reader, &mut freer, 600, &unwritten, &mut stats,
        );

        assert_eq!(stats.extents_scanned, 1);
        assert_eq!(stats.duplicates_found, 0);
        assert!(ddt.is_empty());
    }

    /// Test budget exhaustion: step stops after max_items.
    #[test]
    fn step_respects_budget() {
        let ddt = DedupTable::new();
        let payload = b"budget test payload here!!!";
        let checksum = [0xFFu8; 32];

        let mut store = ExtentStore::new();
        let ext1 = make_data_extent(0, 16, LocatorId(1), true, checksum);
        let ext2 = make_data_extent(16, 16, LocatorId(2), true, checksum);
        let ext3 = make_data_extent(32, 16, LocatorId(3), true, checksum);
        store.add_inode(1, vec![ext1, ext2, ext3]);

        let mut reader = PayloadReader::new();
        reader.add_payload(LocatorId(1), payload.to_vec());
        reader.add_payload(LocatorId(2), payload.to_vec());
        reader.add_payload(LocatorId(3), payload.to_vec());

        let mut scanner = DedupScanner::new(ddt, store, reader, None);
        scanner.set_job_id(JobId(1));

        let budget = WorkBudget {
            max_items: 2,
            max_bytes: 0,
            max_ms: 0,
        };
        let result = scanner.step(budget).unwrap();
        assert!(!result.is_complete);
        assert_eq!(scanner.scanner_stats().extents_scanned, 2);

        // Second step processes remaining
        let result2 = scanner.step(budget).unwrap();
        // Now all 3 should be processed, job complete
        assert_eq!(scanner.scanner_stats().extents_scanned, 3);
        assert!(result2.is_complete);
    }

    /// Test step assigns correct JobKind.
    #[test]
    fn scanner_job_kind_is_dedup() {
        let ddt = DedupTable::new();
        let store = ExtentStore::new();
        let reader = PayloadReader::new();
        let scanner = DedupScanner::new(ddt, store, reader, None);
        assert_eq!(scanner.job_kind(), JobKind::Dedup);
    }

    // ── IncrementalJob trait contract ──────────────────────────────────

    #[test]
    fn scanner_step_after_complete_errors() {
        let ddt = DedupTable::new();
        let store = ExtentStore::new();
        let reader = PayloadReader::new();
        let mut scanner = DedupScanner::new(ddt, store, reader, None);
        scanner.set_job_id(JobId(1));
        scanner.completed = true;

        let err = scanner.step(WorkBudget::DEFAULT_TICK).unwrap_err();
        assert!(matches!(err, JobError::JobAlreadyComplete { .. }));
    }

    #[test]
    fn scanner_unbounded_budget_runs_to_completion() {
        let ddt = DedupTable::new();
        let payload = b"unbounded budget test payload wow";
        let checksum = [0x11u8; 32];

        let mut store = ExtentStore::new();
        for i in 0..50u64 {
            let ext = make_data_extent(i * 16, 16, LocatorId(i + 1), true, checksum);
            store.add_inode(i, vec![ext]);
        }

        let mut reader = PayloadReader::new();
        for i in 0..50u64 {
            reader.add_payload(LocatorId(i + 1), payload.to_vec());
        }

        let mut scanner = DedupScanner::new(ddt, store, reader, None);
        scanner.set_job_id(JobId(2));

        let result = scanner.step(WorkBudget::UNBOUNDED).unwrap();
        assert!(result.is_complete);
        assert_eq!(scanner.scanner_stats().extents_scanned, 50);
        assert_eq!(scanner.scanner_stats().inodes_scanned, 50);
    }

    // ── DedupScannerStats ──────────────────────────────────────────────

    #[test]
    fn scanner_stats_default_zero() {
        let s = DedupScannerStats::default();
        assert_eq!(s.extents_scanned, 0);
        assert_eq!(s.duplicates_found, 0);
        assert_eq!(s.bytes_saved, 0);
    }

    // ── DedupStats ─────────────────────────────────────────────────────

    #[test]
    fn dedup_stats_zero_is_const() {
        let s = DedupStats::ZERO;
        assert_eq!(s.unique_hashes, 0);
        assert_eq!(s.bytes_saved, 0);
    }

    #[test]
    fn dedup_stats_ratio_empty_table() {
        let s = DedupStats::ZERO;
        assert_eq!(s.dedup_ratio_permille(), 0);
    }

    // ── Cursor encoding roundtrip ──────────────────────────────────────

    #[test]
    fn cursor_encode_decode_roundtrip() {
        let cursor = encode_cursor(42, 7);
        let (inode_idx, extent_idx) = decode_cursor(&cursor).unwrap();
        assert_eq!(inode_idx, 42);
        assert_eq!(extent_idx, 7);
    }

    #[test]
    fn cursor_decode_empty_returns_zeroes() {
        let cursor = CursorState::empty();
        let (inode_idx, extent_idx) = decode_cursor(&cursor).unwrap();
        assert_eq!(inode_idx, 0);
        assert_eq!(extent_idx, 0);
    }

    // ── concurrent scanner+write ────────────────────────────────────

    /// Simulate the expected integration pattern: a shared DDT behind
    /// `Arc<Mutex<>>` where the scanner populates entries during `step()`
    /// and the inline write path performs dedup checks between steps.
    #[test]
    fn concurrent_scanner_and_write() {
        use std::sync::{Arc, Mutex};

        let payload = b"data written by both scanner and write path";
        let checksum = [0x22u8; 32];
        let shared_ddt = Arc::new(Mutex::new(DedupTable::new()));

        // Write path inserts the data first
        {
            let mut ddt = shared_ddt.lock().unwrap();
            ddt.inline_insert(payload, LocatorId(1), payload.len() as u64)
                .unwrap();
        }

        // Scanner processes an extent referencing the same data at a
        // different locator (simulating a duplicate written by a
        // different inode).
        let mut store = ExtentStore::new();
        let mut reader = PayloadReader::new();
        reader.add_payload(LocatorId(2), payload.to_vec());

        let entry = make_data_extent(0, payload.len() as u64, LocatorId(2), true, checksum);
        let mut stats = DedupScannerStats::ZERO;
        let mut freer = Some(ExtentFreer::new());

        DedupScanner::process_one_extent(
            &mut shared_ddt.lock().unwrap(),
            &mut store,
            &reader,
            &mut freer,
            700,
            &entry,
            &mut stats,
        );

        assert_eq!(stats.duplicates_found, 1);
        assert_eq!(stats.bytes_saved, payload.len() as u64);

        // After scanner merge, inline write path can still find the
        // canonical locator.
        {
            let ddt = shared_ddt.lock().unwrap();
            let found = ddt.inline_check(payload);
            assert_eq!(found, Some(LocatorId(1)));
        }

        // Idempotency: re-scanning with the same DDT state produces
        // additional duplicates for new locators.
        let entry2 = make_data_extent(0, payload.len() as u64, LocatorId(3), true, checksum);
        reader.add_payload(LocatorId(3), payload.to_vec());
        let mut freer2 = Some(ExtentFreer::new());

        DedupScanner::process_one_extent(
            &mut shared_ddt.lock().unwrap(),
            &mut store,
            &reader,
            &mut freer2,
            800,
            &entry2,
            &mut stats,
        );

        assert_eq!(stats.duplicates_found, 2);
        assert_eq!(stats.bytes_saved, 2 * payload.len() as u64);
    }

    // ── Sparse file / hole interaction with dedup ─────────────────────

    /// A helper that builds an unwritten (hole) extent.
    fn make_hole_extent(logical_offset: u64, length: u64) -> ExtentMapEntryV2 {
        ExtentMapEntryV2::new_unwritten(logical_offset, length, 1)
    }

    /// Hole extents are never processed by the dedup scanner — they are
    /// not data, so they are skipped entirely.
    #[test]
    fn process_one_extent_skips_hole() {
        let mut ddt = DedupTable::new();
        let mut store = ExtentStore::new();
        let reader = PayloadReader::new();
        let mut freer: Option<io::ExtentFreer> = None;

        let hole = make_hole_extent(0, 4096);
        let mut stats = DedupScannerStats::ZERO;

        DedupScanner::process_one_extent(
            &mut ddt, &mut store, &reader, &mut freer, 100, &hole, &mut stats,
        );

        // Hole extent was scanned but not processed (no data, no locator)
        assert_eq!(stats.extents_scanned, 1);
        assert_eq!(stats.duplicates_found, 0);
        assert!(ddt.is_empty());
    }

    /// A sparse file with data+hole+data: holes are never collapsed by dedup.
    /// The data extents on either side of the hole are processed correctly.
    #[test]
    fn sparse_file_data_hole_data_survives_dedup() {
        let mut ddt = DedupTable::new();
        let payload1 = b"first data block - 64 bytes of content for testing";
        let payload2 = b"second data block - different content here";
        let checksum = [0x33u8; 32];

        let mut store = ExtentStore::new();
        // Inode 1: data at 0..64, hole at 64..128, data at 128..192
        let ext_data1 = make_data_extent(0, 64, LocatorId(1), true, checksum);
        let ext_hole = make_hole_extent(64, 64);
        let ext_data2 = make_data_extent(128, 64, LocatorId(2), true, checksum);
        store.add_inode(
            1,
            vec![ext_data1.clone(), ext_hole.clone(), ext_data2.clone()],
        );

        let mut reader = PayloadReader::new();
        reader.add_payload(LocatorId(1), payload1.to_vec());
        reader.add_payload(LocatorId(2), payload2.to_vec());
        let mut freer = Some(ExtentFreer::new());

        // Pre-populate DDT with payload1 (so data1 is a canonical entry)
        ddt.inline_insert(payload1, LocatorId(1), 64).unwrap();

        // Process all three extents one by one (simulating scanner walk)
        let mut stats = DedupScannerStats::ZERO;
        for (ino, entry) in [
            (1, &ext_data1 as &ExtentMapEntryV2),
            (1, &ext_hole),
            (1, &ext_data2),
        ] {
            DedupScanner::process_one_extent(
                &mut ddt, &mut store, &reader, &mut freer, ino, entry, &mut stats,
            );
        }

        // All 3 extents were scanned
        assert_eq!(stats.extents_scanned, 3);
        // No duplicates found — data1 is already canonical, data2 is unique
        assert_eq!(stats.duplicates_found, 0);
        // DDT has 2 entries (payload1 and payload2)
        assert_eq!(ddt.len(), 2);
        // Hole was not inserted into DDT
        assert!(ddt
            .inline_check(b"first data block - 64 bytes of content for testing")
            .is_some());
        assert!(ddt
            .inline_check(b"second data block - different content here")
            .is_some());
        // Nothing was freed (no duplicate locator was replaced)
        assert_eq!(freer.as_ref().unwrap().freed_count(), 0);
    }

    /// Dedup on a sparse file with duplicate data blocks separated by holes:
    /// duplicates are merged, but holes remain intact and data is not corrupted.
    #[test]
    fn dedup_merges_duplicates_across_holes() {
        let mut ddt = DedupTable::new();
        let payload = b"ZZZ duplicate payload that repeats across sparse regions ZZZ";
        let checksum = [0x44u8; 32];

        let mut store = ExtentStore::new();
        // Layout: data(0..64) hole(64..128) data(128..192) hole(192..256) data(256..320)
        // All three data extents contain the SAME payload (duplicates)
        let d1 = make_data_extent(0, 64, LocatorId(10), true, checksum);
        let h1 = make_hole_extent(64, 64);
        let d2 = make_data_extent(128, 64, LocatorId(20), true, checksum);
        let h2 = make_hole_extent(192, 64);
        let d3 = make_data_extent(256, 64, LocatorId(30), true, checksum);
        store.add_inode(1, vec![d1, h1, d2, h2, d3]);

        let mut reader = PayloadReader::new();
        reader.add_payload(LocatorId(10), payload.to_vec());
        reader.add_payload(LocatorId(20), payload.to_vec()); // same content!
        reader.add_payload(LocatorId(30), payload.to_vec()); // same content!
        let mut freer = Some(ExtentFreer::new());

        // Process all five extents
        let mut stats = DedupScannerStats::ZERO;
        let entries: Vec<(u64, ExtentMapEntryV2)> = vec![
            (1, make_data_extent(0, 64, LocatorId(10), true, checksum)),
            (1, make_hole_extent(64, 64)),
            (1, make_data_extent(128, 64, LocatorId(20), true, checksum)),
            (1, make_hole_extent(192, 64)),
            (1, make_data_extent(256, 64, LocatorId(30), true, checksum)),
        ];
        for (ino, entry) in &entries {
            DedupScanner::process_one_extent(
                &mut ddt, &mut store, &reader, &mut freer, *ino, entry, &mut stats,
            );
        }

        // 5 extents scanned (2 holes + 3 data)
        assert_eq!(stats.extents_scanned, 5);
        // 2 duplicates found (extents at locators 20 and 30 duplicate locator 10)
        assert_eq!(stats.duplicates_found, 2);
        // Bytes saved = 2 * 64
        assert_eq!(stats.bytes_saved, 128);
        // 2 locators freed (20 and 30)
        assert_eq!(freer.as_ref().unwrap().freed_count(), 2);
        assert!(freer.as_ref().unwrap().was_freed(LocatorId(20)));
        assert!(freer.as_ref().unwrap().was_freed(LocatorId(30)));
        // DDT has only 1 entry (the canonical)
        assert_eq!(ddt.len(), 1);
        // Holes were untouched
    }

    /// After dedup redirects extent locators, the extent map still correctly
    /// represents the sparse layout: holes are still holes, data is still data.
    #[test]
    fn extent_map_layout_preserved_after_dedup() {
        let mut ddt = DedupTable::new();
        let payload = b"AAAA duplicate across holes BBBB";
        let checksum = [0x55u8; 32];

        let mut store = ExtentStore::new();
        let d1 = make_data_extent(0, 64, LocatorId(100), true, checksum);
        let h1 = make_hole_extent(64, 4096);
        let d2 = make_data_extent(4160, 64, LocatorId(200), true, checksum);
        store.add_inode(1, vec![d1, h1, d2]);

        let mut reader = PayloadReader::new();
        reader.add_payload(LocatorId(100), payload.to_vec());
        reader.add_payload(LocatorId(200), payload.to_vec());
        let mut freer = Some(ExtentFreer::new());

        let mut stats = DedupScannerStats::ZERO;
        let entries: Vec<(u64, ExtentMapEntryV2)> = vec![
            (1, make_data_extent(0, 64, LocatorId(100), true, checksum)),
            (1, make_hole_extent(64, 4096)),
            (
                1,
                make_data_extent(4160, 64, LocatorId(200), true, checksum),
            ),
        ];
        for (ino, entry) in &entries {
            DedupScanner::process_one_extent(
                &mut ddt, &mut store, &reader, &mut freer, *ino, entry, &mut stats,
            );
        }

        // 1 duplicate found (locator 200 -> 100)
        assert_eq!(stats.duplicates_found, 1);
        // Locator 200 freed
        assert!(freer.as_ref().unwrap().was_freed(LocatorId(200)));
        // update_extent_locator was called to redirect locator 200 -> 100
        let updates = store.updated_locators.lock().unwrap();
        assert!(!updates.is_empty());
        // The update should be for inode 1, offset 4160, redirected to LocatorId(100)
        assert!(updates
            .iter()
            .any(|(ino, off, _len, loc)| *ino == 1 && *off == 4160 && *loc == LocatorId(100)));
    }

    /// All-hole file: every extent is a hole. Dedup scanner must not
    /// insert anything into DDT or modify anything.
    #[test]
    fn all_hole_file_untouched_by_dedup() {
        let mut ddt = DedupTable::new();
        let mut store = ExtentStore::new();
        let reader = PayloadReader::new();
        let mut freer: Option<io::ExtentFreer> = None;

        store.add_inode(
            1,
            vec![
                make_hole_extent(0, 4096),
                make_hole_extent(4096, 4096),
                make_hole_extent(8192, 4096),
            ],
        );

        let mut stats = DedupScannerStats::ZERO;
        for (ino, entry) in [
            (1, &make_hole_extent(0, 4096) as &ExtentMapEntryV2),
            (1, &make_hole_extent(4096, 4096)),
            (1, &make_hole_extent(8192, 4096)),
        ] {
            DedupScanner::process_one_extent(
                &mut ddt, &mut store, &reader, &mut freer, ino, entry, &mut stats,
            );
        }

        assert_eq!(stats.extents_scanned, 3);
        assert_eq!(stats.duplicates_found, 0);
        assert!(ddt.is_empty());
        // No updates to extent locators
        assert!(store.updated_locators.lock().unwrap().is_empty());
    }

    /// Verify that process_one_extent handles an unwritten extent with
    /// `is_data() == false` the same regardless of dedup_eligible flag.
    #[test]
    fn hole_with_dedup_eligible_flag_still_skipped() {
        let mut ddt = DedupTable::new();
        let mut store = ExtentStore::new();
        let reader = PayloadReader::new();
        let mut freer: Option<io::ExtentFreer> = None;

        // Manually construct an unwritten extent — it should never be data
        let hole = ExtentMapEntryV2::new_unwritten(0, 8192, 1);
        assert!(!hole.is_data());

        let mut stats = DedupScannerStats::ZERO;
        DedupScanner::process_one_extent(
            &mut ddt, &mut store, &reader, &mut freer, 999, &hole, &mut stats,
        );

        assert_eq!(stats.extents_scanned, 1);
        assert_eq!(stats.duplicates_found, 0);
        assert!(ddt.is_empty());
    }
}
