// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! SegmentCleanerService: **model / library surface** for segment-level GC.
//!
//! # Status
//!
//! This crate is a model IncrementalJob implementation. It is **not wired**
//! into the mounted product path (LocalFileSystem, LocalObjectStore, FUSE,
//! storage-node, or kernel-cutover runtime).
//!
//! Live mounted-pool physical reclaim requires the receipt-bound dead-object
//! drain in `tidefs-local-object-store`. `LocalObjectStore::drain_dead_segments`
//! only inspects the older reclaim queue and fails closed without committed
//! clearance evidence.
//!
//! `LocalObjectStore` implements `SegmentStore` for this crate's trait,
//! so `SegmentCleanerService` can be constructed with a real store in
//! tests, but it is not registered as a background job in the mounted
//! runtime.
//!
//! ## Model Architecture
//!
//! [`SegmentCleanerService`] implements [`IncrementalJob`] to identify dead
//! segments, free fully-dead segments back to the pool allocator, and hand
//! partially live/dead segments to the compaction authority.
//!
//! ## Resume limitation
//!
//! `IncrementalJob::resume()` rebuilds with `store: None`. Calling
//! `step()` without first calling `set_store()` will panic. Production
//! wiring must inject the store after resume or pass it through a
//! non-trait constructor.

use core::fmt;

use std::collections::BTreeMap;

use tidefs_cleanup_queue_core::CleanupQueue;
use tidefs_incremental_job_core::IncrementalJob;
use tidefs_reclaim_queue_core::{SegmentLivenessEntry, SegmentLivenessQueue};
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};

mod victim;
pub use victim::{VictimCandidate, VictimSelector};
mod candidate_selector;
mod cleaner;
pub use candidate_selector::{CandidateSelector, SegmentCandidate};
pub use cleaner::{CleaningCandidate, SegmentCleaner};

mod scanner;

mod policy;
pub use policy::{CleanerBackpressure, CleaningPolicy, SegmentScorer};

mod ledger;
pub use ledger::{
    CleanerLedger, CleanerLedgerRecord, CLEANER_LEDGER_MAGIC, CLEANER_LEDGER_RECORD_SIZE,
    CLEANER_LEDGER_VERSION,
};
mod physical_reclaim;
pub use physical_reclaim::{
    drain_receipt_bound_physical_reclaim, PhysicalReclaimAuthority, PhysicalReclaimConfig,
    PhysicalReclaimDrain,
};
pub use scanner::{
    CandidateRanker, CompactionCandidate, LivenessSource, ScannerConfig, SegmentLivenessScanner,
};

/// Identifies a live block within a segment that must be relocated during
/// compaction. The object-key, offset, and length together uniquely locate
/// the block's data in the segment log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockRef {
    pub object_key: [u8; 32],
    pub segment_id: u64,
    pub offset: u64,
    pub length: u64,
}

impl BlockRef {
    #[must_use]
    pub const fn new(object_key: [u8; 32], segment_id: u64, offset: u64, length: u64) -> Self {
        Self {
            object_key,
            segment_id,
            offset,
            length,
        }
    }
}

/// Cleaner-produced handoff for a partially live segment.
///
/// This is the explicit boundary between the segment cleaner and the
/// compaction authority. The cleaner may prove pressure eligibility,
/// liveness accounting, and pin-filtered reachability before creating this
/// record, but it does not rank, group, relocate, or publish partial live
/// segment merges.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PartialSegmentHandoff {
    pub segment_id: u64,
    pub live_bytes: u64,
    pub dead_bytes: u64,
    pub total_bytes: u64,
    pub dead_ratio: f64,
    pub creation_commit_group: u64,
}

impl PartialSegmentHandoff {
    #[must_use]
    pub fn new(
        segment_id: u64,
        live_bytes: u64,
        dead_bytes: u64,
        creation_commit_group: u64,
    ) -> Option<Self> {
        if live_bytes == 0 || dead_bytes == 0 {
            return None;
        }
        let total_bytes = live_bytes.saturating_add(dead_bytes);
        if total_bytes == 0 {
            return None;
        }
        Some(Self {
            segment_id,
            live_bytes,
            dead_bytes,
            total_bytes,
            dead_ratio: dead_bytes as f64 / total_bytes as f64,
            creation_commit_group,
        })
    }

    #[must_use]
    pub fn from_liveness_entry(entry: &SegmentLivenessEntry) -> Option<Self> {
        Self::new(
            entry.segment_id,
            entry.live_bytes,
            entry.dead_bytes,
            entry.creation_commit_group,
        )
    }

    #[must_use]
    pub fn estimated_write_amplification(self) -> f64 {
        if self.dead_bytes == 0 {
            f64::INFINITY
        } else {
            self.total_bytes as f64 / self.dead_bytes as f64
        }
    }
}

pub trait BlockIndex {
    type Error: core::fmt::Debug + core::fmt::Display;
    fn blocks_in_segment(&self, segment_id: u64) -> Result<Vec<BlockRef>, Self::Error>;
    fn update_block_location(&mut self, old: &BlockRef, new: &BlockRef) -> Result<(), Self::Error>;
}

pub trait BlockReader {
    type Error: core::fmt::Debug + core::fmt::Display;
    fn read_block(&self, block: &BlockRef) -> Result<Vec<u8>, Self::Error>;
}

pub trait BlockWriter {
    type Error: core::fmt::Debug + core::fmt::Display;
    fn write_block(&mut self, object_key: [u8; 32], data: &[u8]) -> Result<BlockRef, Self::Error>;
}

/// Combined capability for block enumeration, reading, and writing.
///
/// Implementations own all three facets; [`CompactExecutor::compact_store`]
/// uses this single-object form to avoid split-borrow conflicts.
pub trait BlockStore: BlockIndex + BlockReader + BlockWriter {}
impl<T: BlockIndex + BlockReader + BlockWriter> BlockStore for T {}

#[derive(Clone, Debug)]
pub struct SegmentCleanerConfig {
    pub min_dead_ratio: f64,
    pub max_compaction_budget: u64,
    /// Minimum number of transaction groups a segment must age before
    /// it is considered for cleaning. Prevents write amplification on
    /// recently-written segments. Default: 2.
    pub min_segment_age_txg: u64,
}

impl Default for SegmentCleanerConfig {
    fn default() -> Self {
        Self {
            min_dead_ratio: 0.3,
            max_compaction_budget: 64 * 1024 * 1024,
            min_segment_age_txg: 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SegmentCleanerStats {
    pub segments_scanned: u64,
    pub segments_compacted: u64,
    pub partial_segments_handed_off: u64,
    pub segments_freed: u64,
    pub bytes_compacted: u64,
    pub bytes_handed_to_compaction: u64,
    pub bytes_freed: u64,
}

impl fmt::Display for SegmentCleanerStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scanned={} compacted={} handed_off={} freed={} bytes_compacted={} bytes_handed_to_compaction={} bytes_freed={}",
            self.segments_scanned,
            self.segments_compacted,
            self.partial_segments_handed_off,
            self.segments_freed,
            self.bytes_compacted,
            self.bytes_handed_to_compaction,
            self.bytes_freed
        )
    }
}

#[derive(Clone, Debug, Default)]
struct SegmentCleanerCursor {
    last_segment_id: u64,
    tick_bytes_handed_off: u64,
    phase: u8,
    current_candidate: u64,
}

impl SegmentCleanerCursor {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        buf[0..8].copy_from_slice(&self.last_segment_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.tick_bytes_handed_off.to_le_bytes());
        buf[16] = self.phase;
        buf[17..25].copy_from_slice(&self.current_candidate.to_le_bytes());
        buf
    }
    #[allow(dead_code)]
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 25 {
            return None;
        }
        Some(Self {
            last_segment_id: u64::from_le_bytes(data[0..8].try_into().ok()?),
            tick_bytes_handed_off: u64::from_le_bytes(data[8..16].try_into().ok()?),
            phase: data[16],
            current_candidate: u64::from_le_bytes(data[17..25].try_into().ok()?),
        })
    }

    fn fresh() -> Self {
        Self::default()
    }
}

pub trait SegmentStore {
    fn liveness_queue(&self) -> &SegmentLivenessQueue;
    fn liveness_queue_mut(&mut self) -> &mut SegmentLivenessQueue;
    fn handoff_partial_segment(
        &mut self,
        victim: PartialSegmentHandoff,
    ) -> Result<(), SegmentCleanerError> {
        Err(SegmentCleanerError::CompactionHandoffFailed {
            segment_id: victim.segment_id,
            reason: "compaction authority handoff is not configured".into(),
        })
    }
    fn compact_segment(&mut self, segment_id: u64) -> Result<u64, SegmentCleanerError>;
    fn free_segment(&mut self, segment_id: u64) -> Result<(), SegmentCleanerError>;
}

fn cleaner_candidate_batch_from_queue(
    queue: &SegmentLivenessQueue,
    min_dead_ratio: f64,
    current_commit_group: u64,
    min_age_commit_groups: u64,
    limit: usize,
) -> Vec<u64> {
    if limit == 0 {
        return Vec::new();
    }

    let mut candidates: Vec<&SegmentLivenessEntry> = queue
        .entries()
        .filter(|e| {
            e.dead_ratio() >= min_dead_ratio
                && e.dead_bytes > 0
                && (e.is_fully_dead()
                    || e.is_old_enough(current_commit_group, min_age_commit_groups))
        })
        .collect();

    candidates.sort_by(|a, b| {
        b.is_fully_dead()
            .cmp(&a.is_fully_dead())
            .then_with(|| a.segment_id.cmp(&b.segment_id))
    });

    candidates
        .into_iter()
        .take(limit)
        .map(|e| e.segment_id)
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SegmentCleanerError {
    SegmentNotFound(u64),
    CompactionFailed(u64),
    FreeFailed(u64),
    CompactionHandoffFailed { segment_id: u64, reason: String },
    /// A block read, write, or index update failed during relocation.
    RelocationFailed(String),
}

impl fmt::Display for SegmentCleanerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SegmentNotFound(id) => write!(f, "segment {id} not found"),
            Self::CompactionFailed(id) => write!(f, "compaction failed for segment {id}"),
            Self::FreeFailed(id) => write!(f, "free failed for segment {id}"),
            Self::CompactionHandoffFailed { segment_id, reason } => {
                write!(
                    f,
                    "compaction handoff failed for segment {segment_id}: {reason}"
                )
            }
            Self::RelocationFailed(msg) => write!(f, "relocation failed: {msg}"),
        }
    }
}

pub struct SegmentCleanerService<S: SegmentStore> {
    job_id: JobId,
    store: Option<S>,
    config: SegmentCleanerConfig,
    stats: SegmentCleanerStats,
    cursor: SegmentCleanerCursor,
    /// Current transaction group, advanced externally by the caller.
    current_commit_group: u64,
}

impl<S: SegmentStore> SegmentCleanerService<S> {
    pub fn new(job_id: JobId, store: S, config: SegmentCleanerConfig) -> Self {
        Self {
            job_id,
            store: Some(store),
            config,
            stats: SegmentCleanerStats::default(),
            cursor: SegmentCleanerCursor::fresh(),
            current_commit_group: 0,
        }
    }

    /// Set or replace the backing store. Required after resume-from-checkpoint.
    pub fn set_store(&mut self, store: S) {
        self.store = Some(store);
    }

    fn store(&self) -> &S {
        self.store
            .as_ref()
            .expect("SegmentCleanerService: store not set")
    }
    fn store_mut(&mut self) -> &mut S {
        self.store
            .as_mut()
            .expect("SegmentCleanerService: store not set")
    }

    /// Advance the transaction group counter. Call when a new commit_group begins.
    pub fn advance_commit_group(&mut self, commit_group: u64) {
        self.current_commit_group = commit_group;
    }
    #[must_use]
    pub fn stats(&self) -> SegmentCleanerStats {
        self.stats
    }
    #[must_use]
    pub fn select_segment(&self) -> Option<u64> {
        cleaner_candidate_batch_from_queue(
            self.store().liveness_queue(),
            self.config.min_dead_ratio,
            self.current_commit_group,
            self.config.min_segment_age_txg,
            1,
        )
        .into_iter()
        .next()
    }
    fn do_handoff(
        &mut self,
        segment_id: u64,
    ) -> Result<PartialSegmentHandoff, SegmentCleanerError> {
        let victim = self
            .store()
            .liveness_queue()
            .get(segment_id)
            .and_then(PartialSegmentHandoff::from_liveness_entry)
            .ok_or_else(|| SegmentCleanerError::CompactionHandoffFailed {
                segment_id,
                reason: "candidate is not a partial live/dead segment".into(),
            })?;

        self.store_mut().handoff_partial_segment(victim)?;
        self.stats.partial_segments_handed_off =
            self.stats.partial_segments_handed_off.saturating_add(1);
        self.stats.bytes_handed_to_compaction = self
            .stats
            .bytes_handed_to_compaction
            .saturating_add(victim.live_bytes);
        Ok(victim)
    }
    fn do_free(&mut self, segment_id: u64) -> Result<(), SegmentCleanerError> {
        let dead_bytes = self
            .store()
            .liveness_queue()
            .get(segment_id)
            .map(|e| e.dead_bytes)
            .unwrap_or(0);
        self.store_mut().free_segment(segment_id)?;
        self.store_mut()
            .liveness_queue_mut()
            .commit_dead(segment_id);
        self.stats.segments_freed = self.stats.segments_freed.saturating_add(1);
        self.stats.bytes_freed = self.stats.bytes_freed.saturating_add(dead_bytes);
        Ok(())
    }
}

impl<S: SegmentStore + Send> IncrementalJob for SegmentCleanerService<S> {
    fn resume(state: Option<Checkpoint>) -> Result<Self, JobError> {
        match state {
            Some(cp) => {
                let cursor = SegmentCleanerCursor::from_bytes(cp.cursor_state.as_bytes())
                    .unwrap_or_else(SegmentCleanerCursor::fresh);
                Ok(SegmentCleanerService {
                    job_id: cp.job_id,
                    store: None,
                    config: SegmentCleanerConfig::default(),
                    stats: SegmentCleanerStats {
                        segments_scanned: cp.progress.items_processed,
                        segments_compacted: 0,
                        partial_segments_handed_off: cp.progress.items_total_estimate,
                        segments_freed: 0,
                        bytes_compacted: 0,
                        bytes_handed_to_compaction: cp.progress.bytes_processed,
                        bytes_freed: 0,
                    },
                    cursor,
                    current_commit_group: 0,
                })
            }
            None => Ok(SegmentCleanerService {
                job_id: JobId::NONE,
                store: None,
                config: SegmentCleanerConfig::default(),
                stats: SegmentCleanerStats::default(),
                cursor: SegmentCleanerCursor::fresh(),
                current_commit_group: 0,
            }),
        }
    }
    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
        let effective_max_bytes = if budget.max_bytes > 0 {
            budget.max_bytes.min(self.config.max_compaction_budget)
        } else {
            self.config.max_compaction_budget
        };
        let candidate_limit = if budget.max_items > 0 {
            budget.max_items as usize
        } else {
            self.store().liveness_queue().len()
        };
        let candidates = cleaner_candidate_batch_from_queue(
            self.store().liveness_queue(),
            self.config.min_dead_ratio,
            self.current_commit_group,
            self.config.min_segment_age_txg,
            candidate_limit,
        );
        let mut items_processed: u64 = 0;
        let mut tick_bytes: u64 = 0;
        for segment_id in candidates {
            // Respect max_items budget
            if budget.max_items > 0 && items_processed >= budget.max_items {
                break;
            }
            // Respect max_bytes budget
            if effective_max_bytes > 0 && tick_bytes >= effective_max_bytes {
                break;
            }
            self.stats.segments_scanned = self.stats.segments_scanned.saturating_add(1);
            items_processed = items_processed.saturating_add(1);
            self.cursor.current_candidate = segment_id;
            self.cursor.phase = 1;
            let is_fully_dead = self
                .store()
                .liveness_queue()
                .get(segment_id)
                .map(|e| e.is_fully_dead())
                .unwrap_or(false);
            if is_fully_dead {
                match self.do_free(segment_id) {
                    Ok(()) => self.cursor.last_segment_id = segment_id,
                    Err(_) => break,
                }
            } else {
                match self.do_handoff(segment_id) {
                    Ok(victim) => {
                        tick_bytes = tick_bytes.saturating_add(victim.live_bytes);
                        self.cursor.tick_bytes_handed_off = tick_bytes;
                        self.cursor.last_segment_id = segment_id;
                    }
                    Err(_) => break,
                }
            }
            self.cursor.phase = 0;
        }
        let checkpoint = Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::SegmentCleaner,
            epoch: 1,
            cursor_state: CursorState(self.cursor.to_bytes()),
            progress: JobProgress {
                items_processed: self.stats.segments_scanned,
                items_total_estimate: self.stats.partial_segments_handed_off,
                bytes_processed: self.stats.bytes_handed_to_compaction,
                bytes_total_estimate: 0,
                elapsed_ms: 0,
            },
        };
        Ok(StepResult::in_progress(checkpoint))
    }
    fn persist_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), JobError> {
        let cursor_bytes = self.cursor.to_bytes();
        if checkpoint.cursor_state.as_bytes() != cursor_bytes.as_slice() {
            return Err(JobError::CursorStateInvalid {
                job_id: self.job_id,
                reason: "checkpoint cursor does not match service cursor",
            });
        }
        if checkpoint.job_kind != JobKind::SegmentCleaner {
            return Err(JobError::Other("checkpoint job_kind mismatch".into()));
        }
        Ok(())
    }
    fn complete(self) -> Result<(), JobError> {
        Ok(())
    }
    fn job_id(&self) -> JobId {
        self.job_id
    }
    fn job_kind(&self) -> JobKind {
        JobKind::SegmentCleaner
    }
}

/// Low-level relocation helper retained for tests and future
/// compaction-authority callers.
///
/// [`SegmentCleanerService`] and [`SegmentCleanerDriver`] do not call this for
/// partially live victims. Production partial rewrites must enter through the
/// explicit [`SegmentStore::handoff_partial_segment`] boundary.
pub struct CompactExecutor;

impl CompactExecutor {
    /// Compact `segment_id` by relocating all its live blocks.
    ///
    /// Returns the total number of bytes relocated on success.
    ///
    /// # Errors
    ///
    /// Returns [`SegmentCleanerError::RelocationFailed`] if any read,
    /// write, or index-update operation fails.
    pub fn compact_store(
        store: &mut impl BlockStore,
        segment_id: u64,
    ) -> Result<u64, SegmentCleanerError> {
        let blocks = BlockIndex::blocks_in_segment(store, segment_id)
            .map_err(|e| SegmentCleanerError::RelocationFailed(format!("block index: {e}")))?;

        if blocks.is_empty() {
            return Ok(0);
        }

        let mut total_bytes: u64 = 0;

        for old_block in &blocks {
            let data = BlockReader::read_block(store, old_block)
                .map_err(|e| SegmentCleanerError::RelocationFailed(format!("read: {e}")))?;

            let new_block = BlockWriter::write_block(store, old_block.object_key, &data)
                .map_err(|e| SegmentCleanerError::RelocationFailed(format!("write: {e}")))?;

            BlockIndex::update_block_location(store, old_block, &new_block)
                .map_err(|e| SegmentCleanerError::RelocationFailed(format!("index update: {e}")))?;

            total_bytes = total_bytes.saturating_add(data.len() as u64);
        }

        Ok(total_bytes)
    }
}

// =========================================================================
// PerSegmentLiveness -- per-segment live/dead byte accounting
// =========================================================================

/// Per-segment live/dead byte counters for victim selection.
///
/// Tracks how many bytes in a segment are still referenced by live objects
/// vs. eligible for reclamation after overwrites or deletes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PerSegmentLiveness {
    pub segment_id: u64,
    pub live_bytes: u64,
    pub dead_bytes: u64,
    /// Transaction group when this segment was first written, or 0 if unknown.
    pub creation_commit_group: u64,
}

impl PerSegmentLiveness {
    #[must_use]
    pub const fn new(
        segment_id: u64,
        live_bytes: u64,
        dead_bytes: u64,
        creation_commit_group: u64,
    ) -> Self {
        Self {
            segment_id,
            live_bytes,
            dead_bytes,
            creation_commit_group,
        }
    }

    #[must_use]
    pub const fn total_bytes(self) -> u64 {
        self.live_bytes.saturating_add(self.dead_bytes)
    }

    #[must_use]
    pub fn dead_ratio(self) -> f64 {
        let total = self.total_bytes();
        if total == 0 {
            0.0
        } else {
            self.dead_bytes as f64 / total as f64
        }
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.live_bytes == 0 && self.dead_bytes == 0
    }

    #[must_use]
    pub const fn is_fully_dead(self) -> bool {
        self.live_bytes == 0 && self.dead_bytes > 0
    }

    #[must_use]
    pub const fn is_old_enough(
        self,
        current_commit_group: u64,
        min_age_commit_groups: u64,
    ) -> bool {
        if self.creation_commit_group == 0 {
            true
        } else {
            current_commit_group.saturating_sub(self.creation_commit_group) >= min_age_commit_groups
        }
    }
}

// =========================================================================
// DeadObjectTracker -- in-memory per-segment liveness aggregation
// =========================================================================

/// In-memory aggregation of per-segment live/dead byte counts.
///
/// Fed by local-object-store overwrite notifications (and later,
/// optionally persisted). Drives victim selection for the
/// segment cleaner background driver.
#[derive(Clone, Debug, Default)]
pub struct DeadObjectTracker {
    segments: BTreeMap<u64, PerSegmentLiveness>,
}

impl DeadObjectTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            segments: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    #[must_use]
    pub fn get(&self, segment_id: u64) -> Option<&PerSegmentLiveness> {
        self.segments.get(&segment_id)
    }

    #[must_use]
    pub fn contains(&self, segment_id: u64) -> bool {
        self.segments.contains_key(&segment_id)
    }

    pub fn entries(&self) -> impl Iterator<Item = &PerSegmentLiveness> {
        self.segments.values()
    }

    /// Record a write of `bytes` into `segment_id`, adding live bytes.
    pub fn record_write(&mut self, segment_id: u64, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let e = self.segments.entry(segment_id).or_default();
        e.segment_id = segment_id;
        e.live_bytes = e.live_bytes.saturating_add(bytes);
    }

    /// Record a write at a known transaction group.
    pub fn record_write_at_commit_group(&mut self, segment_id: u64, bytes: u64, commit_group: u64) {
        if bytes == 0 {
            return;
        }
        let existed = self.segments.contains_key(&segment_id);
        self.record_write(segment_id, bytes);
        if !existed {
            if let Some(e) = self.segments.get_mut(&segment_id) {
                e.creation_commit_group = commit_group;
            }
        }
    }

    /// Record that `old_bytes` in `segment_id` were overwritten.
    /// Transfers bytes from live to dead.
    pub fn record_overwrite(&mut self, segment_id: u64, old_bytes: u64) {
        if old_bytes == 0 {
            return;
        }
        let e = self.segments.entry(segment_id).or_default();
        e.segment_id = segment_id;
        e.live_bytes = e.live_bytes.saturating_sub(old_bytes);
        e.dead_bytes = e.dead_bytes.saturating_add(old_bytes);
    }

    /// Record a delete of `bytes` from `segment_id`.
    /// Transfers bytes from live to dead.
    pub fn record_delete(&mut self, segment_id: u64, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let e = self.segments.entry(segment_id).or_default();
        e.segment_id = segment_id;
        e.live_bytes = e.live_bytes.saturating_sub(bytes);
        e.dead_bytes = e.dead_bytes.saturating_add(bytes);
    }

    /// Remove a segment from tracking after it has been freed.
    pub fn remove(&mut self, segment_id: u64) -> bool {
        self.segments.remove(&segment_id).is_some()
    }

    /// Clear all tracked segments.
    pub fn clear(&mut self) {
        self.segments.clear();
    }
}

// =========================================================================
// BackgroundVictimSelector -- threshold + age-weighted victim selection
// =========================================================================

#[derive(Clone, Debug)]
pub struct BackgroundVictimConfig {
    /// Minimum dead-byte ratio (0.0-1.0) for a segment to be considered.
    pub dead_byte_ratio_threshold: f64,
    /// Maximum number of victim segments returned per selection.
    pub max_victims: usize,
    /// Minimum number of transaction groups a segment must age before
    /// it is considered (fully-dead segments bypass this).
    pub min_segment_age_txg: u64,
}

impl Default for BackgroundVictimConfig {
    fn default() -> Self {
        Self {
            dead_byte_ratio_threshold: 0.3,
            max_victims: 16,
            min_segment_age_txg: 2,
        }
    }
}

/// Selects cleaner-attention candidates from a [`DeadObjectTracker`].
///
/// Fully-dead segments (live_bytes=0, dead_bytes>0) are always
/// selected first regardless of age constraints.
/// Partially live candidates are returned only as compaction-authority
/// handoff records; their order is not a merge-policy decision.
pub struct BackgroundVictimSelector {
    config: BackgroundVictimConfig,
}

impl BackgroundVictimSelector {
    #[must_use]
    pub const fn new(config: BackgroundVictimConfig) -> Self {
        Self { config }
    }

    /// Select victim segments above the dead-byte-ratio threshold.
    ///
    /// Returns `(segment_id, dead_ratio)` pairs sorted only by cleaner
    /// ownership: fully-dead segments first, then by segment id for a
    /// stable handoff order. `tidefs-compaction` owns partial merge ordering.
    #[must_use]
    pub fn select(
        &self,
        tracker: &DeadObjectTracker,
        current_commit_group: u64,
    ) -> Vec<(u64, f64)> {
        let mut candidates: Vec<&PerSegmentLiveness> = tracker
            .entries()
            .filter(|e| {
                e.dead_bytes > 0
                    && e.dead_ratio() >= self.config.dead_byte_ratio_threshold
                    && (e.is_fully_dead()
                        || e.is_old_enough(current_commit_group, self.config.min_segment_age_txg))
            })
            .collect();

        // Sort by cleaner-owned work first. Partial ordering is intentionally
        // not a compaction policy; it is only a stable handoff order.
        candidates.sort_by(|a, b| {
            b.is_fully_dead()
                .cmp(&a.is_fully_dead())
                .then_with(|| a.segment_id.cmp(&b.segment_id))
        });

        candidates
            .into_iter()
            .take(self.config.max_victims)
            .map(|e| (e.segment_id, e.dead_ratio()))
            .collect()
    }
}

// =========================================================================
// SegmentCleanerDriver -- background cleaning loop
// =========================================================================

/// Background driver that periodically selects victim segments and
/// dispatches compaction or free operations via a [`SegmentStore`].
///
/// Uses its own [`DeadObjectTracker`] for liveness tracking and a
/// [`BackgroundVictimSelector`] for victim selection. The caller is responsible
/// for feeding overwrite/deletion events into the tracker via
/// [`tracker_mut`](Self::tracker_mut) and for calling [`tick`](Self::tick)
/// periodically (e.g. from a FUSE daemon or storage-node main loop).
pub struct SegmentCleanerDriver<S: SegmentStore> {
    store: S,
    tracker: DeadObjectTracker,
    selector: BackgroundVictimSelector,
    current_commit_group: u64,
    stats: SegmentCleanerStats,
    /// Persistent cleanup queue for durable scheduling of dead-segment
    /// reclamation. Segments are enqueued before processing and marked
    /// complete afterward so that a crash mid-tick does not lose work.
    cleanup_queue: CleanupQueue,
}

impl<S: SegmentStore> SegmentCleanerDriver<S> {
    #[must_use]
    pub fn new(store: S, selector_config: BackgroundVictimConfig) -> Self {
        Self {
            store,
            tracker: DeadObjectTracker::new(),
            selector: BackgroundVictimSelector::new(selector_config),
            current_commit_group: 0,
            stats: SegmentCleanerStats::default(),
            cleanup_queue: CleanupQueue::new(),
        }
    }

    /// Advance the transaction group counter.
    pub fn advance_commit_group(&mut self, commit_group: u64) {
        self.current_commit_group = commit_group;
    }

    #[must_use]
    pub fn stats(&self) -> SegmentCleanerStats {
        self.stats
    }

    /// Commit the persistent cleanup queue to the given [`CommitGroupStore`].
    ///
    /// Call this during transaction-group commit so that enqueued
    /// (but not yet completed) segment-cleanup entries survive a crash.
    ///
    /// # Errors
    ///
    /// Returns an error string if the store operation fails.
    pub fn commit_cleanup_queue(
        &mut self,
        store: &mut impl tidefs_commit_group::CommitGroupStore,
    ) -> Result<tidefs_cleanup_queue_core::CleanupQueueRoot, String> {
        self.cleanup_queue.commit(store)
    }

    /// Recover the persistent cleanup queue from a [`CommitGroupStore`].
    ///
    /// Call this during mount to restore the queue state from the
    /// last committed root.  After recovery, any entries that were
    /// enqueued but not yet completed should be re-processed.
    ///
    /// # Errors
    ///
    /// Returns an error string if the store operation fails.
    pub fn recover_cleanup_queue(
        &mut self,
        store: &impl tidefs_commit_group::CommitGroupStore,
    ) -> Result<(), String> {
        self.cleanup_queue = tidefs_cleanup_queue_core::CleanupQueue::open_or_empty(store)?;
        Ok(())
    }

    /// Re-process segments that were enqueued but not yet completed
    /// at the time of the last crash.  Returns the number of segments
    /// re-processed.
    ///
    /// Call this after [`recover_cleanup_queue`](Self::recover_cleanup_queue)
    /// and before entering the normal tick loop.
    pub fn replay_pending_cleanup(&mut self) -> Result<u64, SegmentCleanerError> {
        // Collect pending entries first to avoid borrow conflicts.
        let pending: Vec<(u64, u64)> = self
            .cleanup_queue
            .entries()
            .into_iter()
            .filter(|(_, item)| !item.is_complete())
            .map(|(entry_id, item)| (entry_id, item.inode_id))
            .collect();

        let count = pending.len() as u64;

        // Mark all pending entries as complete and re-enqueue for
        // processing in the next tick cycle.
        for (entry_id, seg_id) in &pending {
            self.cleanup_queue.mark_complete(*entry_id);
            if self.tracker.contains(*seg_id) {
                let item = tidefs_cleanup_queue_core::make_segment_cleanup_item(
                    *seg_id,
                    self.current_commit_group,
                );
                self.cleanup_queue.enqueue(item);
            }
        }
        Ok(count)
    }

    #[must_use]
    pub fn tracker(&self) -> &DeadObjectTracker {
        &self.tracker
    }

    #[must_use]
    pub fn tracker_mut(&mut self) -> &mut DeadObjectTracker {
        &mut self.tracker
    }

    #[must_use]
    pub fn cleanup_queue(&self) -> &CleanupQueue {
        &self.cleanup_queue
    }

    #[must_use]
    pub fn cleanup_queue_mut(&mut self) -> &mut CleanupQueue {
        &mut self.cleanup_queue
    }

    /// Run one cleaning tick.
    ///
    /// Fully-dead victims are enqueued in the cleaner cleanup queue and
    /// freed. Partially live victims are handed to the compaction authority
    /// and are not enqueued for source release until compaction publishes a
    /// verified relocation.
    ///
    /// Returns the number of victim segments processed (handed off or freed).
    ///
    /// # Errors
    ///
    /// Returns the first error encountered from the store.
    pub fn tick(&mut self) -> Result<u64, SegmentCleanerError> {
        let victims = self
            .selector
            .select(&self.tracker, self.current_commit_group);
        let mut processed: u64 = 0;

        for (seg_id, _dead_ratio) in &victims {
            self.stats.segments_scanned = self.stats.segments_scanned.saturating_add(1);

            let is_fully_dead = self
                .tracker
                .get(*seg_id)
                .map(|e| e.is_fully_dead())
                .unwrap_or(false);

            if is_fully_dead {
                // Enqueue segment in persistent cleanup queue for crash safety.
                // Uses segment_id as inode_id surrogate and SegmentCleanup kind.
                let item = tidefs_cleanup_queue_core::make_segment_cleanup_item(
                    *seg_id,
                    self.current_commit_group,
                );
                let entry_id = self.cleanup_queue.enqueue(item);

                self.store.free_segment(*seg_id)?;
                self.tracker.remove(*seg_id);
                self.stats.segments_freed = self.stats.segments_freed.saturating_add(1);

                // Mark the persistent queue entry as completed.
                self.cleanup_queue.mark_complete(entry_id);
            } else {
                let victim = self
                    .tracker
                    .get(*seg_id)
                    .and_then(|e| {
                        PartialSegmentHandoff::new(
                            e.segment_id,
                            e.live_bytes,
                            e.dead_bytes,
                            e.creation_commit_group,
                        )
                    })
                    .ok_or_else(|| SegmentCleanerError::CompactionHandoffFailed {
                        segment_id: *seg_id,
                        reason: "candidate is not a partial live/dead segment".into(),
                    })?;
                self.store.handoff_partial_segment(victim)?;
                self.stats.partial_segments_handed_off =
                    self.stats.partial_segments_handed_off.saturating_add(1);
                self.stats.bytes_handed_to_compaction = self
                    .stats
                    .bytes_handed_to_compaction
                    .saturating_add(victim.live_bytes);
            }

            processed = processed.saturating_add(1);
        }

        Ok(processed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct MockSegmentStore {
        liveness: SegmentLivenessQueue,
        compact_results: BTreeMap<u64, Result<u64, SegmentCleanerError>>,
        handoff_results: BTreeMap<u64, Result<(), SegmentCleanerError>>,
        free_results: BTreeMap<u64, Result<(), SegmentCleanerError>>,
        handoffs: Vec<PartialSegmentHandoff>,
        blocks: BTreeMap<u64, Vec<BlockRef>>,
        block_data: BTreeMap<([u8; 32], u64), Vec<u8>>,
        next_segment_id: u64,
    }

    impl MockSegmentStore {
        fn new() -> Self {
            Self {
                liveness: SegmentLivenessQueue::new(),
                compact_results: BTreeMap::new(),
                handoff_results: BTreeMap::new(),
                free_results: BTreeMap::new(),
                handoffs: Vec::new(),
                blocks: BTreeMap::new(),
                block_data: BTreeMap::new(),
                next_segment_id: 1000,
            }
        }
        fn add_segment(&mut self, id: u64, live: u64, dead: u64) {
            self.liveness.record_write(id, live.saturating_add(dead));
            if dead > 0 {
                self.liveness.record_overwrite(id, dead);
            }
        }

        fn add_block(&mut self, object_key: [u8; 32], segment_id: u64, offset: u64, data: &[u8]) {
            let block = BlockRef::new(object_key, segment_id, offset, data.len() as u64);
            self.blocks.entry(segment_id).or_default().push(block);
            self.block_data.insert((object_key, offset), data.to_vec());
            self.liveness
                .record_write_at_commit_group(segment_id, data.len() as u64, 0);
        }

        fn kill_block(&mut self, object_key: [u8; 32], offset: u64, segment_id: u64) {
            let len = self
                .block_data
                .get(&(object_key, offset))
                .map(|d| d.len() as u64)
                .unwrap_or(0);
            self.block_data.remove(&(object_key, offset));
            if let Some(blks) = self.blocks.get_mut(&segment_id) {
                blks.retain(|b| b.object_key != object_key || b.offset != offset);
            }
            if len > 0 {
                self.liveness.record_overwrite(segment_id, len);
            }
        }
    }

    impl SegmentStore for MockSegmentStore {
        fn liveness_queue(&self) -> &SegmentLivenessQueue {
            &self.liveness
        }
        fn liveness_queue_mut(&mut self) -> &mut SegmentLivenessQueue {
            &mut self.liveness
        }
        fn handoff_partial_segment(
            &mut self,
            victim: PartialSegmentHandoff,
        ) -> Result<(), SegmentCleanerError> {
            let result = self.handoff_results.remove(&victim.segment_id).unwrap_or(Ok(()));
            if result.is_ok() {
                self.handoffs.push(victim);
            }
            result
        }
        fn compact_segment(&mut self, segment_id: u64) -> Result<u64, SegmentCleanerError> {
            let result = self.compact_results.remove(&segment_id).unwrap_or(Ok(0));
            if result.is_ok() {
                if let Some(e) = self.liveness.get(segment_id) {
                    let live = e.live_bytes;
                    self.liveness.record_delete(segment_id, live);
                }
            }
            result
        }
        fn free_segment(&mut self, segment_id: u64) -> Result<(), SegmentCleanerError> {
            let result = self.free_results.remove(&segment_id).unwrap_or(Ok(()));
            if result.is_ok() {
                self.blocks.remove(&segment_id);
            }
            result
        }
    }

    impl BlockIndex for MockSegmentStore {
        type Error = String;
        fn blocks_in_segment(&self, segment_id: u64) -> Result<Vec<BlockRef>, Self::Error> {
            Ok(self.blocks.get(&segment_id).cloned().unwrap_or_default())
        }
        fn update_block_location(
            &mut self,
            old: &BlockRef,
            new: &BlockRef,
        ) -> Result<(), Self::Error> {
            // Data was already written to the new location by write_block;
            // update_block_location only updates the index mapping.
            if let Some(blks) = self.blocks.get_mut(&old.segment_id) {
                blks.retain(|b| b.object_key != old.object_key || b.offset != old.offset);
            }
            self.blocks.entry(new.segment_id).or_default().push(*new);
            Ok(())
        }
    }

    impl BlockReader for MockSegmentStore {
        type Error = String;
        fn read_block(&self, block: &BlockRef) -> Result<Vec<u8>, Self::Error> {
            self.block_data
                .get(&(block.object_key, block.offset))
                .cloned()
                .ok_or_else(|| "block not found".to_string())
        }
    }

    impl BlockWriter for MockSegmentStore {
        type Error = String;
        fn write_block(
            &mut self,
            object_key: [u8; 32],
            data: &[u8],
        ) -> Result<BlockRef, Self::Error> {
            let seg = self.next_segment_id;
            self.next_segment_id += 1;
            let block = BlockRef::new(object_key, seg, 0, data.len() as u64);
            self.block_data.insert((object_key, 0), data.to_vec());
            // Index update is the caller's responsibility via update_block_location.
            Ok(block)
        }
    }

    fn make_svc(store: MockSegmentStore) -> SegmentCleanerService<MockSegmentStore> {
        SegmentCleanerService::new(JobId(1), store, SegmentCleanerConfig::default())
    }

    #[test]
    fn select_lowest_eligible_segment_id() {
        let mut s = MockSegmentStore::new();
        s.add_segment(0, 30, 70);
        s.add_segment(1, 70, 30);
        s.add_segment(2, 50, 50);
        assert_eq!(make_svc(s).select_segment(), Some(0));
    }
    #[test]
    fn select_respects_min_dead_ratio() {
        let mut s = MockSegmentStore::new();
        s.add_segment(0, 80, 20);
        s.add_segment(1, 50, 50);
        let svc = SegmentCleanerService::new(
            JobId(1),
            s,
            SegmentCleanerConfig {
                min_dead_ratio: 0.3,
                ..Default::default()
            },
        );
        assert_eq!(svc.select_segment(), Some(1));
    }
    #[test]
    fn select_empty_pool_returns_none() {
        assert_eq!(make_svc(MockSegmentStore::new()).select_segment(), None);
    }
    #[test]
    fn partial_handoff_updates_stats() {
        let mut s = MockSegmentStore::new();
        s.add_segment(0, 4096, 8192);
        let mut svc = make_svc(s);
        svc.step(WorkBudget::UNBOUNDED).unwrap();
        assert_eq!(svc.stats().segments_compacted, 0);
        assert_eq!(svc.stats().partial_segments_handed_off, 1);
        assert_eq!(svc.stats().bytes_handed_to_compaction, 4096);
        assert_eq!(svc.store.as_ref().unwrap().handoffs.len(), 1);
    }
    #[test]
    fn partial_handoff_failure_preserves_stats() {
        let mut s = MockSegmentStore::new();
        s.add_segment(0, 4096, 8192);
        s.handoff_results.insert(
            0,
            Err(SegmentCleanerError::CompactionHandoffFailed {
                segment_id: 0,
                reason: "authority queue unavailable".into(),
            }),
        );
        let mut svc = make_svc(s);
        svc.step(WorkBudget::UNBOUNDED).unwrap();
        assert_eq!(svc.stats().segments_compacted, 0);
        assert_eq!(svc.stats().partial_segments_handed_off, 0);
    }
    #[test]
    fn fully_dead_segment_freed() {
        let mut s = MockSegmentStore::new();
        s.add_segment(0, 0, 100);
        s.free_results.insert(0, Ok(()));
        let mut svc = make_svc(s);
        svc.step(WorkBudget::UNBOUNDED).unwrap();
        assert_eq!(svc.stats().segments_freed, 1);
        assert_eq!(svc.stats().bytes_freed, 100);
    }
    #[test]
    fn partial_handoff_does_not_free_after_dispatch() {
        let mut s = MockSegmentStore::new();
        s.add_segment(0, 4096, 8192);
        s.free_results.insert(0, Ok(()));
        let mut svc = make_svc(s);
        svc.step(WorkBudget::UNBOUNDED).unwrap();
        assert_eq!(svc.stats().partial_segments_handed_off, 1);
        assert_eq!(svc.stats().segments_freed, 0);
    }
    #[test]
    fn free_failure_does_not_update_stats() {
        let mut s = MockSegmentStore::new();
        s.add_segment(0, 0, 100);
        s.free_results
            .insert(0, Err(SegmentCleanerError::FreeFailed(0)));
        let mut svc = make_svc(s);
        svc.step(WorkBudget::UNBOUNDED).unwrap();
        assert_eq!(svc.stats().segments_freed, 0);
        assert_eq!(svc.stats().bytes_freed, 0);
    }
    #[test]
    fn budget_items_exhausted() {
        let mut s = MockSegmentStore::new();
        for i in 0..5u64 {
            s.add_segment(i, 30, 70);
        }
        let mut svc = make_svc(s);
        svc.step(WorkBudget {
            max_items: 2,
            ..WorkBudget::default()
        })
        .unwrap();
        assert_eq!(svc.stats().segments_scanned, 2);
    }
    #[test]
    fn budget_bytes_exhausted() {
        let mut s = MockSegmentStore::new();
        s.add_segment(0, 500, 500);
        s.add_segment(1, 500, 500);
        let mut svc = make_svc(s);
        svc.step(WorkBudget {
            max_bytes: 400,
            ..WorkBudget::default()
        })
        .unwrap();
        assert_eq!(svc.stats().partial_segments_handed_off, 1);
    }
    #[test]
    fn config_budget_caps_unbounded() {
        let mut s = MockSegmentStore::new();
        s.add_segment(0, 1000, 1000);
        s.add_segment(1, 1000, 1000);
        let mut svc = SegmentCleanerService::new(
            JobId(1),
            s,
            SegmentCleanerConfig {
                min_dead_ratio: 0.3,
                max_compaction_budget: 500,
                min_segment_age_txg: 2,
            },
        );
        svc.step(WorkBudget::UNBOUNDED).unwrap();
        assert_eq!(svc.stats().partial_segments_handed_off, 1);
    }
    #[test]
    fn empty_pool_no_work() {
        let mut svc = make_svc(MockSegmentStore::new());
        svc.step(WorkBudget::UNBOUNDED).unwrap();
        assert_eq!(svc.stats().segments_scanned, 0);
    }
    #[test]
    fn no_candidates_idle() {
        let mut s = MockSegmentStore::new();
        s.add_segment(0, 80, 20);
        s.add_segment(1, 90, 10);
        let mut svc = SegmentCleanerService::new(
            JobId(1),
            s,
            SegmentCleanerConfig {
                min_dead_ratio: 0.3,
                ..Default::default()
            },
        );
        svc.step(WorkBudget::UNBOUNDED).unwrap();
        assert_eq!(svc.stats().segments_scanned, 0);
    }
    #[test]
    fn job_kind_and_id() {
        let svc = make_svc(MockSegmentStore::new());
        assert_eq!(svc.job_kind(), JobKind::SegmentCleaner);
        assert_eq!(svc.job_id(), JobId(1));
    }
    #[test]
    fn cursor_roundtrip() {
        let c = SegmentCleanerCursor {
            last_segment_id: 42,
            tick_bytes_handed_off: 8192,
            phase: 2,
            current_candidate: 7,
        };
        let b = c.to_bytes();
        let r = SegmentCleanerCursor::from_bytes(&b).unwrap();
        assert_eq!(r.last_segment_id, 42);
    }
    #[test]
    fn cursor_from_bytes_truncated() {
        assert!(SegmentCleanerCursor::from_bytes(&[0; 10]).is_none());
    }
    #[test]
    fn config_defaults() {
        let c = SegmentCleanerConfig::default();
        assert!((c.min_dead_ratio - 0.3).abs() < f64::EPSILON);
        assert_eq!(c.max_compaction_budget, 64 * 1024 * 1024);
        assert_eq!(c.min_segment_age_txg, 2);
    }
    #[test]
    fn job_kind_label() {
        assert_eq!(JobKind::SegmentCleaner.label(), "segment_cleaner");
    }
    #[test]
    fn error_display_nonempty() {
        assert!(!format!("{}", SegmentCleanerError::SegmentNotFound(1)).is_empty());
        assert!(!format!("{}", SegmentCleanerError::CompactionFailed(2)).is_empty());
        assert!(!format!("{}", SegmentCleanerError::FreeFailed(3)).is_empty());
        assert!(
            !format!(
                "{}",
                SegmentCleanerError::CompactionHandoffFailed {
                    segment_id: 4,
                    reason: "test".into()
                }
            )
            .is_empty()
        );
        assert!(!format!("{}", SegmentCleanerError::RelocationFailed("test".into())).is_empty());
    }
    #[test]
    fn stats_display_nonempty() {
        let s = SegmentCleanerStats {
            segments_scanned: 10,
            segments_compacted: 3,
            partial_segments_handed_off: 4,
            segments_freed: 2,
            bytes_compacted: 4096,
            bytes_handed_to_compaction: 2048,
            bytes_freed: 8192,
        };
        assert!(format!("{s}").contains("scanned=10"));
    }

    // -- Compaction / live-block relocation tests --

    #[test]
    fn compact_enumerates_and_relocates_live_blocks() {
        let mut store = MockSegmentStore::new();
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        store.add_block(key_a, 0, 0, &[0xAA; 100]);
        store.add_block(key_b, 0, 100, &[0xBB; 200]);
        store.kill_block(key_a, 0, 0);
        let relocated =
            CompactExecutor::compact_store(&mut store, 0).expect("compact should succeed");
        assert_eq!(relocated, 200);
        assert!(store.blocks.get(&0).map(|v| v.is_empty()).unwrap_or(true));
        let new_segs: Vec<_> = store
            .blocks
            .keys()
            .filter(|&&k| k >= 1000)
            .copied()
            .collect();
        assert!(!new_segs.is_empty());
        let relocated_block = store.blocks.get(&new_segs[0]).unwrap()[0];
        let read_back = store
            .read_block(&relocated_block)
            .expect("read relocated block");
        assert_eq!(read_back, vec![0xBB; 200]);
    }

    #[test]
    fn compact_empty_segment_returns_zero() {
        let mut store = MockSegmentStore::new();
        let key = [1u8; 32];
        store.add_block(key, 0, 0, &[0xAA; 50]);
        store.kill_block(key, 0, 0);
        let relocated =
            CompactExecutor::compact_store(&mut store, 0).expect("compact empty segment");
        assert_eq!(relocated, 0);
    }

    #[test]
    fn compact_unknown_segment_returns_zero() {
        let mut store = MockSegmentStore::new();
        let result = CompactExecutor::compact_store(&mut store, 99);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn compact_preserves_block_data_identity() {
        let mut store = MockSegmentStore::new();
        let key = [42u8; 32];
        let original = vec![0xDE, 0xAD, 0xBE, 0xEF];
        store.add_block(key, 5, 0, &original);
        CompactExecutor::compact_store(&mut store, 5).expect("compact");
        let relocated: Vec<_> = store
            .blocks
            .values()
            .flat_map(|v| v.iter())
            .filter(|b| b.object_key == key)
            .collect();
        assert_eq!(relocated.len(), 1, "block should exist exactly once");
        let data = store.read_block(relocated[0]).expect("read");
        assert_eq!(data, original);
    }

    #[test]
    fn compact_multiple_blocks_all_relocated() {
        let mut store = MockSegmentStore::new();
        let keys: Vec<[u8; 32]> = (0..5)
            .map(|i| {
                let mut k = [0u8; 32];
                k[0] = i;
                k
            })
            .collect();
        let mut total_bytes: u64 = 0;
        for (i, k) in keys.iter().enumerate() {
            let data = vec![i as u8; 100 + i * 50];
            total_bytes += data.len() as u64;
            store.add_block(*k, 1, i as u64 * 256, &data);
        }
        let relocated = CompactExecutor::compact_store(&mut store, 1).expect("compact");
        assert_eq!(relocated, total_bytes);
        let old_blocks = store.blocks.get(&1).map(|v| v.len()).unwrap_or(0);
        assert_eq!(old_blocks, 0, "old segment should be empty");
        for (i, k) in keys.iter().enumerate() {
            let found: Vec<_> = store
                .blocks
                .values()
                .flat_map(|v| v.iter())
                .filter(|b| b.object_key == *k)
                .collect();
            assert_eq!(found.len(), 1, "block {i} should exist exactly once");
            let data = store.read_block(found[0]).expect("read");
            assert_eq!(data, vec![i as u8; 100 + i * 50]);
        }
    }

    #[test]
    fn service_hands_partial_victim_to_compaction_authority() {
        let mut store = MockSegmentStore::new();
        let key = [99u8; 32];
        store.add_block(key, 7, 0, &[0xCC; 256]);
        store.add_block([88u8; 32], 7, 256, &[0xDD; 256]);
        store.kill_block([88u8; 32], 256, 7);
        let mut svc = SegmentCleanerService::new(
            JobId(1),
            store,
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
        );
        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_ok());
        assert_eq!(svc.stats().segments_compacted, 0);
        assert_eq!(svc.stats().partial_segments_handed_off, 1);
        assert_eq!(svc.store.as_ref().unwrap().handoffs[0].segment_id, 7);
        assert_eq!(svc.store.as_ref().unwrap().handoffs[0].live_bytes, 256);
    }

    #[test]
    fn compact_read_error_propagates() {
        // Composite mock: good index + failing reader + pass-through writer.
        struct ReadFailStore {
            idx: MockSegmentStore,
        }
        impl BlockIndex for ReadFailStore {
            type Error = String;
            fn blocks_in_segment(&self, id: u64) -> Result<Vec<BlockRef>, Self::Error> {
                self.idx.blocks_in_segment(id)
            }
            fn update_block_location(
                &mut self,
                old: &BlockRef,
                new: &BlockRef,
            ) -> Result<(), Self::Error> {
                self.idx.update_block_location(old, new)
            }
        }
        impl BlockReader for ReadFailStore {
            type Error = String;
            fn read_block(&self, _: &BlockRef) -> Result<Vec<u8>, Self::Error> {
                Err("simulated read failure".into())
            }
        }
        impl BlockWriter for ReadFailStore {
            type Error = String;
            fn write_block(&mut self, key: [u8; 32], data: &[u8]) -> Result<BlockRef, Self::Error> {
                self.idx.write_block(key, data)
            }
        }
        let mut store = ReadFailStore {
            idx: MockSegmentStore::new(),
        };
        store.idx.add_block([1u8; 32], 0, 0, &[0xAA; 100]);
        let result = CompactExecutor::compact_store(&mut store, 0);
        assert!(result.is_err());
        match result {
            Err(SegmentCleanerError::RelocationFailed(msg)) => {
                assert!(msg.contains("read"));
            }
            _ => panic!("expected RelocationFailed"),
        }
    }

    #[test]
    fn compact_write_error_propagates() {
        // Composite mock: good index + pass-through reader + failing writer.
        struct WriteFailStore {
            idx: MockSegmentStore,
        }
        impl BlockIndex for WriteFailStore {
            type Error = String;
            fn blocks_in_segment(&self, id: u64) -> Result<Vec<BlockRef>, Self::Error> {
                self.idx.blocks_in_segment(id)
            }
            fn update_block_location(
                &mut self,
                old: &BlockRef,
                new: &BlockRef,
            ) -> Result<(), Self::Error> {
                self.idx.update_block_location(old, new)
            }
        }
        impl BlockReader for WriteFailStore {
            type Error = String;
            fn read_block(&self, block: &BlockRef) -> Result<Vec<u8>, Self::Error> {
                self.idx.read_block(block)
            }
        }
        impl BlockWriter for WriteFailStore {
            type Error = String;
            fn write_block(&mut self, _: [u8; 32], _: &[u8]) -> Result<BlockRef, Self::Error> {
                Err("simulated write failure".into())
            }
        }
        let mut store = WriteFailStore {
            idx: MockSegmentStore::new(),
        };
        store.idx.add_block([1u8; 32], 0, 0, &[0xAA; 100]);
        let result = CompactExecutor::compact_store(&mut store, 0);
        assert!(result.is_err());
        match result {
            Err(SegmentCleanerError::RelocationFailed(msg)) => {
                assert!(msg.contains("write"));
            }
            _ => panic!("expected RelocationFailed"),
        }
    }

    #[test]
    fn compact_preserves_liveness_after_relocation() {
        let mut store = MockSegmentStore::new();
        let key = [7u8; 32];
        store.add_block(key, 3, 0, &[0xEE; 512]);
        let relocated = CompactExecutor::compact_store(&mut store, 3).expect("compact");
        assert_eq!(relocated, 512);
        let new_seg_ids: Vec<u64> = store
            .blocks
            .keys()
            .filter(|&&k| k >= 1000)
            .copied()
            .collect();
        assert!(!new_seg_ids.is_empty());
    }

    // -- Age guard tests --

    #[test]
    fn age_guard_skips_too_young_segments() {
        let mut s = MockSegmentStore::new();
        s.liveness.record_write_at_commit_group(0, 100, 5);
        s.liveness.record_overwrite(0, 70);
        s.liveness.record_write_at_commit_group(1, 100, 1);
        s.liveness.record_overwrite(1, 70);
        let mut svc = SegmentCleanerService::new(JobId(1), s, SegmentCleanerConfig::default());
        svc.advance_commit_group(3);
        assert_eq!(svc.select_segment(), Some(1));
    }

    #[test]
    fn age_guard_all_too_young_returns_none() {
        let mut s = MockSegmentStore::new();
        s.liveness.record_write_at_commit_group(0, 100, 10);
        s.liveness.record_overwrite(0, 70);
        s.liveness.record_write_at_commit_group(1, 100, 11);
        s.liveness.record_overwrite(1, 70);
        let mut svc = SegmentCleanerService::new(JobId(1), s, SegmentCleanerConfig::default());
        svc.advance_commit_group(11);
        assert_eq!(svc.select_segment(), None);
    }

    #[test]
    fn age_guard_min_age_zero_selects_all() {
        let mut s = MockSegmentStore::new();
        s.liveness.record_write_at_commit_group(0, 100, 100);
        s.liveness.record_overwrite(0, 70);
        s.liveness.record_write_at_commit_group(1, 100, 200);
        s.liveness.record_overwrite(1, 70);
        let svc = SegmentCleanerService::new(
            JobId(1),
            s,
            SegmentCleanerConfig {
                min_segment_age_txg: 0,
                ..Default::default()
            },
        );
        assert!(svc.select_segment().is_some());
    }

    #[test]
    fn age_guard_creation_txg_zero_always_old_enough() {
        let mut s = MockSegmentStore::new();
        s.liveness.record_write(0, 100);
        s.liveness.record_overwrite(0, 70);
        let mut svc = SegmentCleanerService::new(
            JobId(1),
            s,
            SegmentCleanerConfig {
                min_segment_age_txg: 100,
                ..Default::default()
            },
        );
        svc.advance_commit_group(50);
        assert_eq!(svc.select_segment(), Some(0));
    }

    #[test]
    fn age_guard_advance_txg_updates_selection() {
        let mut s = MockSegmentStore::new();
        s.liveness.record_write_at_commit_group(0, 100, 5);
        s.liveness.record_overwrite(0, 70);
        let mut svc = SegmentCleanerService::new(JobId(1), s, SegmentCleanerConfig::default());
        svc.advance_commit_group(5);
        assert_eq!(svc.select_segment(), None);
        svc.advance_commit_group(7);
        assert_eq!(svc.select_segment(), Some(0));
    }

    // =================================================================
    // DeadObjectTracker tests
    // =================================================================

    #[test]
    fn tracker_new_is_empty() {
        let t = DeadObjectTracker::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert_eq!(t.get(0), None);
        assert!(!t.contains(0));
    }

    #[test]
    fn tracker_record_write_adds_live_bytes() {
        let mut t = DeadObjectTracker::new();
        t.record_write(1, 4096);
        t.record_write(1, 4096);
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(1).unwrap().live_bytes, 8192);
        assert_eq!(t.get(1).unwrap().dead_bytes, 0);
    }

    #[test]
    fn tracker_record_write_zero_is_noop() {
        let mut t = DeadObjectTracker::new();
        t.record_write(1, 0);
        assert!(t.is_empty());
    }

    #[test]
    fn tracker_record_overwrite_transfers_live_to_dead() {
        let mut t = DeadObjectTracker::new();
        t.record_write(1, 4096);
        t.record_overwrite(1, 1024);
        assert_eq!(t.get(1).unwrap().live_bytes, 3072);
        assert_eq!(t.get(1).unwrap().dead_bytes, 1024);
    }

    #[test]
    fn tracker_record_overwrite_clamps_live_at_zero() {
        let mut t = DeadObjectTracker::new();
        t.record_write(1, 100);
        t.record_overwrite(1, 500);
        assert_eq!(t.get(1).unwrap().live_bytes, 0);
        assert_eq!(t.get(1).unwrap().dead_bytes, 500);
    }

    #[test]
    fn tracker_record_overwrite_unknown_segment_inserts() {
        let mut t = DeadObjectTracker::new();
        t.record_overwrite(42, 2048);
        assert_eq!(t.get(42).unwrap().live_bytes, 0);
        assert_eq!(t.get(42).unwrap().dead_bytes, 2048);
    }

    #[test]
    fn tracker_record_delete_transfers_to_dead() {
        let mut t = DeadObjectTracker::new();
        t.record_write(1, 4096);
        t.record_delete(1, 4096);
        let e = t.get(1).unwrap();
        assert_eq!(e.live_bytes, 0);
        assert_eq!(e.dead_bytes, 4096);
        assert!(e.is_fully_dead());
    }

    #[test]
    fn tracker_multi_segment_churn() {
        let mut t = DeadObjectTracker::new();
        for seg in 0..5u64 {
            t.record_write(seg, (seg + 1) * 1000);
        }
        t.record_overwrite(2, 1500);
        t.record_delete(4, 2500);
        assert_eq!(t.len(), 5);
        assert_eq!(t.get(2).unwrap().live_bytes, 1500);
        assert_eq!(t.get(2).unwrap().dead_bytes, 1500);
        assert_eq!(t.get(4).unwrap().live_bytes, 2500);
        assert_eq!(t.get(4).unwrap().dead_bytes, 2500);
    }

    #[test]
    fn tracker_remove_and_contains() {
        let mut t = DeadObjectTracker::new();
        t.record_write(7, 100);
        assert!(t.contains(7));
        assert!(t.remove(7));
        assert!(!t.contains(7));
        assert!(!t.remove(7));
    }

    #[test]
    fn tracker_clear_empties() {
        let mut t = DeadObjectTracker::new();
        t.record_write(1, 100);
        t.record_write(2, 200);
        t.clear();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn tracker_record_write_at_txg_sets_creation_txg_on_new() {
        let mut t = DeadObjectTracker::new();
        t.record_write_at_commit_group(10, 4096, 5);
        assert_eq!(t.get(10).unwrap().creation_commit_group, 5);
        t.record_write_at_commit_group(10, 4096, 99);
        assert_eq!(t.get(10).unwrap().creation_commit_group, 5);
    }

    // =================================================================
    // PerSegmentLiveness helper tests
    // =================================================================

    #[test]
    fn per_segment_dead_ratio_exact() {
        let e = PerSegmentLiveness::new(1, 300, 700, 0);
        assert!((e.dead_ratio() - 0.70).abs() < 0.001);
    }

    #[test]
    fn per_segment_dead_ratio_empty_returns_zero() {
        let e = PerSegmentLiveness::new(1, 0, 0, 0);
        assert_eq!(e.dead_ratio(), 0.0);
    }

    #[test]
    fn per_segment_is_empty() {
        assert!(PerSegmentLiveness::new(1, 0, 0, 0).is_empty());
        assert!(!PerSegmentLiveness::new(1, 1, 0, 0).is_empty());
        assert!(!PerSegmentLiveness::new(1, 0, 1, 0).is_empty());
    }

    #[test]
    fn per_segment_is_fully_dead() {
        assert!(PerSegmentLiveness::new(1, 0, 1, 0).is_fully_dead());
        assert!(!PerSegmentLiveness::new(1, 0, 0, 0).is_fully_dead());
        assert!(!PerSegmentLiveness::new(1, 1, 1, 0).is_fully_dead());
    }

    #[test]
    fn per_segment_is_old_enough() {
        let e = PerSegmentLiveness::new(1, 100, 50, 10);
        assert!(e.is_old_enough(12, 2));
        assert!(!e.is_old_enough(11, 2));
        assert!(e.is_old_enough(10, 0));
        let e0 = PerSegmentLiveness::new(2, 100, 50, 0);
        assert!(e0.is_old_enough(1, 100));
    }

    // =================================================================
    // BackgroundVictimSelector tests
    // =================================================================

    fn tracker_with_segments(entries: &[(u64, u64, u64, u64)]) -> DeadObjectTracker {
        let mut t = DeadObjectTracker::new();
        for &(seg, live, dead, commit_group) in entries {
            t.segments
                .insert(seg, PerSegmentLiveness::new(seg, live, dead, commit_group));
        }
        t
    }

    #[test]
    fn victim_selector_empty_tracker_returns_empty() {
        let t = DeadObjectTracker::new();
        let s = BackgroundVictimSelector::new(BackgroundVictimConfig::default());
        assert!(s.select(&t, 0).is_empty());
    }

    #[test]
    fn victim_selector_skips_empty_segments() {
        let t = tracker_with_segments(&[(1, 0, 0, 0), (2, 0, 0, 0)]);
        let s = BackgroundVictimSelector::new(BackgroundVictimConfig {
            dead_byte_ratio_threshold: 0.0,
            ..Default::default()
        });
        assert!(s.select(&t, 0).is_empty());
    }

    #[test]
    fn victim_selector_noop_when_below_threshold() {
        let t = tracker_with_segments(&[(1, 90, 10, 0), (2, 85, 15, 0)]);
        let s = BackgroundVictimSelector::new(BackgroundVictimConfig {
            dead_byte_ratio_threshold: 0.2,
            ..Default::default()
        });
        assert!(s.select(&t, 0).is_empty());
    }

    #[test]
    fn victim_selector_fully_dead_selected_first() {
        let t = tracker_with_segments(&[(1, 50, 50, 0), (2, 0, 100, 0), (3, 10, 90, 0)]);
        let s = BackgroundVictimSelector::new(BackgroundVictimConfig {
            dead_byte_ratio_threshold: 0.3,
            ..Default::default()
        });
        let victims = s.select(&t, 0);
        assert_eq!(victims.len(), 3);
        assert_eq!(victims[0].0, 2);
        assert!((victims[0].1 - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn victim_selector_uses_stable_handoff_order_for_partials() {
        let t = tracker_with_segments(&[(1, 10, 90, 0), (2, 50, 50, 0), (3, 20, 80, 0)]);
        let s = BackgroundVictimSelector::new(BackgroundVictimConfig {
            dead_byte_ratio_threshold: 0.0,
            ..Default::default()
        });
        let victims = s.select(&t, 0);
        assert_eq!(victims.len(), 3);
        let ids: Vec<u64> = victims.iter().map(|(segment_id, _)| *segment_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn victim_selector_ignores_dead_bytes_for_partial_handoff_order() {
        let t = tracker_with_segments(&[(50, 500, 500, 0), (10, 250, 250, 0), (20, 500, 500, 0)]);
        let s = BackgroundVictimSelector::new(BackgroundVictimConfig {
            dead_byte_ratio_threshold: 0.0,
            ..Default::default()
        });
        let victims = s.select(&t, 0);
        assert_eq!(victims.len(), 3);
        let ids: Vec<u64> = victims.iter().map(|(segment_id, _)| *segment_id).collect();
        assert_eq!(ids, vec![10, 20, 50]);
    }

    #[test]
    fn victim_selector_respects_max_victims() {
        let mut entries = Vec::new();
        for i in 0..10u64 {
            entries.push((i, 100, 900 + i * 10, 0));
        }
        let t = tracker_with_segments(&entries);
        let s = BackgroundVictimSelector::new(BackgroundVictimConfig {
            dead_byte_ratio_threshold: 0.0,
            max_victims: 3,
            ..Default::default()
        });
        let victims = s.select(&t, 0);
        assert_eq!(victims.len(), 3);
    }

    #[test]
    fn victim_selector_age_guard_skips_too_young() {
        let t = tracker_with_segments(&[(1, 100, 900, 100), (2, 100, 900, 5)]);
        let s = BackgroundVictimSelector::new(BackgroundVictimConfig::default());
        let victims = s.select(&t, 10);
        assert_eq!(victims.len(), 1);
        assert_eq!(victims[0].0, 2);
    }

    #[test]
    fn victim_selector_fully_dead_bypasses_age_guard() {
        let t = tracker_with_segments(&[(1, 0, 100, 100), (2, 50, 50, 5)]);
        let s = BackgroundVictimSelector::new(BackgroundVictimConfig::default());
        let victims = s.select(&t, 10);
        assert_eq!(victims.len(), 2);
        assert_eq!(victims[0].0, 1);
    }

    // =================================================================
    // SegmentCleanerDriver tests
    // =================================================================

    #[test]
    fn driver_tick_no_victims_returns_zero() {
        let store = MockSegmentStore::new();
        let mut driver = SegmentCleanerDriver::new(store, BackgroundVictimConfig::default());
        let processed = driver.tick().unwrap();
        assert_eq!(processed, 0);
    }

    #[test]
    fn driver_tick_frees_fully_dead_segment() {
        let mut s = MockSegmentStore::new();
        s.free_results.insert(1, Ok(()));
        let mut driver = SegmentCleanerDriver::new(
            s,
            BackgroundVictimConfig {
                dead_byte_ratio_threshold: 0.0,
                ..Default::default()
            },
        );
        driver.tracker_mut().record_write(1, 100);
        driver.tracker_mut().record_delete(1, 100);
        let processed = driver.tick().unwrap();
        assert_eq!(processed, 1);
        assert_eq!(driver.stats().segments_freed, 1);
    }

    #[test]
    fn driver_tick_hands_partial_segment_to_compaction_authority() {
        let s = MockSegmentStore::new();
        let mut driver = SegmentCleanerDriver::new(
            s,
            BackgroundVictimConfig {
                dead_byte_ratio_threshold: 0.3,
                ..Default::default()
            },
        );
        driver.tracker_mut().record_write(1, 4096);
        driver.tracker_mut().record_overwrite(1, 2048);
        let processed = driver.tick().unwrap();
        assert_eq!(processed, 1);
        assert_eq!(driver.stats().segments_compacted, 0);
        assert_eq!(driver.stats().partial_segments_handed_off, 1);
        assert_eq!(driver.stats().bytes_handed_to_compaction, 2048);
        assert_eq!(driver.cleanup_queue().len(), 0);
        assert_eq!(driver.store.handoffs[0].segment_id, 1);
    }

    #[test]
    fn driver_advance_txg_enables_age_gated_segments() {
        let s = MockSegmentStore::new();
        let mut driver = SegmentCleanerDriver::new(s, BackgroundVictimConfig::default());
        driver
            .tracker_mut()
            .record_write_at_commit_group(1, 1000, 1);
        driver.tracker_mut().record_overwrite(1, 700);
        driver.advance_commit_group(1);
        assert_eq!(driver.tick().unwrap(), 0);
        driver.advance_commit_group(4);
        assert_eq!(driver.tick().unwrap(), 1);
    }

    #[test]
    fn driver_tick_empty_tracker_returns_zero() {
        let store = MockSegmentStore::new();
        let mut driver = SegmentCleanerDriver::new(store, BackgroundVictimConfig::default());
        assert_eq!(driver.tick().unwrap(), 0);
        assert_eq!(driver.stats().segments_scanned, 0);
    }

    #[test]
    fn driver_stats_default_zero() {
        let store = MockSegmentStore::new();
        let driver = SegmentCleanerDriver::new(store, BackgroundVictimConfig::default());
        let stats = driver.stats();
        assert_eq!(stats.segments_scanned, 0);
        assert_eq!(stats.segments_compacted, 0);
        assert_eq!(stats.segments_freed, 0);
        assert_eq!(stats.bytes_compacted, 0);
        assert_eq!(stats.bytes_freed, 0);
    }

    #[test]
    fn driver_tracker_mut_allows_direct_feed() {
        let store = MockSegmentStore::new();
        let mut driver = SegmentCleanerDriver::new(store, BackgroundVictimConfig::default());
        driver.tracker_mut().record_write(1, 100);
        assert_eq!(driver.tracker().len(), 1);
        assert_eq!(driver.tracker().get(1).unwrap().live_bytes, 100);
    }

    // =================================================================
    // CleanupQueue integration tests
    // =================================================================

    /// A mock store that satisfies both [`SegmentStore`] and
    /// [`tidefs_commit_group::CommitGroupStore`].
    struct MockCleanupStore {
        inner: MockSegmentStore,
        blobs: std::collections::HashMap<String, Vec<u8>>,
    }

    impl MockCleanupStore {
        fn new() -> Self {
            Self {
                inner: MockSegmentStore::new(),
                blobs: std::collections::HashMap::new(),
            }
        }
    }

    impl SegmentStore for MockCleanupStore {
        fn liveness_queue(&self) -> &SegmentLivenessQueue {
            self.inner.liveness_queue()
        }
        fn liveness_queue_mut(&mut self) -> &mut SegmentLivenessQueue {
            self.inner.liveness_queue_mut()
        }
        fn compact_segment(&mut self, seg_id: u64) -> Result<u64, SegmentCleanerError> {
            self.inner.compact_segment(seg_id)
        }
        fn free_segment(&mut self, seg_id: u64) -> Result<(), SegmentCleanerError> {
            self.inner.free_segment(seg_id)
        }
    }

    impl tidefs_commit_group::CommitGroupStore for MockCleanupStore {
        fn put_named(
            &mut self,
            name: &str,
            payload: &[u8],
        ) -> Result<tidefs_commit_group::CommitGroupKey, String> {
            let key = tidefs_commit_group::CommitGroupKey::from_bytes32(
                blake3::hash(payload).as_bytes().to_owned(),
            );
            self.blobs.insert(name.to_string(), payload.to_vec());
            Ok(key)
        }

        fn get_named(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.blobs.get(name).cloned())
        }
    }

    // ── Enqueue + commit + recover ─────────────────────────────────

    #[test]
    fn cleanup_queue_enqueue_on_tick() {
        let mut store = MockCleanupStore::new();
        store.inner.free_results.insert(1, Ok(()));

        let mut driver = SegmentCleanerDriver::new(
            store,
            BackgroundVictimConfig {
                dead_byte_ratio_threshold: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
        );

        // Populate the driver's tracker so the victim selector finds segment 1.
        driver.tracker_mut().record_write(1, 100);
        driver.tracker_mut().record_delete(1, 100);

        assert_eq!(driver.cleanup_queue().len(), 0);

        let processed = driver.tick().expect("tick");
        assert_eq!(processed, 1);

        // After tick: segment was enqueued and marked complete.
        assert_eq!(driver.cleanup_queue().len(), 1);
        assert_eq!(driver.cleanup_queue().pending_count(), 0);
        assert_eq!(driver.cleanup_queue().completed_count(), 1);
    }

    #[test]
    fn cleanup_queue_commit_and_recover_roundtrip() {
        let mut store = MockCleanupStore::new();
        store.inner.free_results.insert(1, Ok(()));

        let mut driver = SegmentCleanerDriver::new(
            store,
            BackgroundVictimConfig {
                dead_byte_ratio_threshold: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
        );

        driver.tracker_mut().record_write(1, 100);
        driver.tracker_mut().record_delete(1, 100);

        driver.tick().expect("tick");

        // Commit the cleanup queue: temporarily extract the store
        // to avoid a double-borrow of driver.
        {
            let blob_snapshot = driver.store.blobs.clone();
            let mut temp_store = MockCleanupStore::new();
            temp_store.blobs = blob_snapshot;
            driver
                .commit_cleanup_queue(&mut temp_store)
                .expect("commit");

            // Recover into a new driver with the committed blobs.
            let mut store2 = MockCleanupStore::new();
            store2.blobs = temp_store.blobs.clone();

            let mut driver2 = SegmentCleanerDriver::new(store2, BackgroundVictimConfig::default());
            {
                let mut q = tidefs_cleanup_queue_core::CleanupQueue::open_or_empty(&driver2.store)
                    .expect("recover");
                core::mem::swap(driver2.cleanup_queue_mut(), &mut q);
            }
            assert!(!driver2.cleanup_queue().is_empty());
        }
    }

    #[test]
    fn cleanup_queue_crash_survival_entry_still_pending() {
        let mut store = MockCleanupStore::new();
        store.inner.liveness.record_write(1, 100);
        store.inner.liveness.record_delete(1, 100);
        store.inner.free_results.insert(1, Ok(()));

        let mut driver = SegmentCleanerDriver::new(
            store,
            BackgroundVictimConfig {
                dead_byte_ratio_threshold: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
        );

        // Manually enqueue a segment WITHOUT processing (simulates crash mid-tick).
        let item = tidefs_cleanup_queue_core::make_segment_cleanup_item(99, 0);
        driver.cleanup_queue_mut().enqueue(item);
        assert_eq!(driver.cleanup_queue().pending_count(), 1);

        // Commit the queue to a separate store.
        let mut commit_store = MockCleanupStore::new();
        driver
            .commit_cleanup_queue(&mut commit_store)
            .expect("commit");

        // Simulate crash + remount: recover into fresh store.
        let mut store2 = MockCleanupStore::new();
        store2.blobs = commit_store.blobs.clone();

        let mut driver2 = SegmentCleanerDriver::new(store2, BackgroundVictimConfig::default());
        {
            let mut q = tidefs_cleanup_queue_core::CleanupQueue::open_or_empty(&driver2.store)
                .expect("recover");
            core::mem::swap(driver2.cleanup_queue_mut(), &mut q);
        }

        // The pending entry survived the crash.
        assert_eq!(driver2.cleanup_queue().pending_count(), 1);
    }

    #[test]
    fn cleanup_queue_replay_pending_returns_count() {
        let store = MockCleanupStore::new();

        let mut driver = SegmentCleanerDriver::new(store, BackgroundVictimConfig::default());

        // Enqueue several segments without processing.
        for seg_id in [10u64, 20, 30] {
            let item = tidefs_cleanup_queue_core::make_segment_cleanup_item(seg_id, 0);
            driver.cleanup_queue_mut().enqueue(item);
        }
        assert_eq!(driver.cleanup_queue().pending_count(), 3);

        let mut commit_store = MockCleanupStore::new();
        driver
            .commit_cleanup_queue(&mut commit_store)
            .expect("commit");

        // Recover and replay.
        let mut store2 = MockCleanupStore::new();
        store2.blobs = commit_store.blobs.clone();

        let mut driver2 = SegmentCleanerDriver::new(store2, BackgroundVictimConfig::default());
        {
            let mut q = tidefs_cleanup_queue_core::CleanupQueue::open_or_empty(&driver2.store)
                .expect("recover");
            core::mem::swap(driver2.cleanup_queue_mut(), &mut q);
        }

        let replayed = driver2.replay_pending_cleanup().expect("replay");
        assert_eq!(replayed, 3);
    }
}
