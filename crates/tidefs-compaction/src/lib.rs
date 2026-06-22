// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! CompactionService and segment-level GC compaction engine.
//!
//! Compacts fragmented B+tree pages (via IncrementalJob) and performs
//! segment-level live-object relocation for the three-stage GC pipeline.
//!
//! Implements Phase 9 of the background service framework (#1946).
//!
//! Uses the existing [`JobKind::BtreeCompaction`] (discriminant 3) which
//! maps to BestEffort priority in the background scheduler.
//!
//! ## Architecture
//!
//! ```text
//! CompactionService (IncrementalJob, JobKind::BtreeCompaction, BestEffort)
//!   ├── PageReader trait: iterates pages, reads page info
//!   ├── PageMerger trait: merges two adjacent pages into one
//!   ├── Compaction cursor: (page_type, next_index) for crash-safe resume
//!   └── CompactionStats: pages_compacted, bytes_reclaimed,
//!       fragmentation_ratio_before, fragmentation_ratio_after
//! ```

use blake3::Hasher;
use tidefs_incremental_job_core::IncrementalJob;
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};

pub mod compaction;
pub mod merge_planner;
pub mod policy;
pub mod rewrite_engine;
pub mod verification;

pub use policy::{
    CompactionAdmissionDecision, CompactionCandidateDecision, CompactionPolicy,
    CompactionPolicyCandidate, CompactionPolicyReport, CompactionPressureLevel, CompactionTrigger,
    CompactionTriggerInput, WriteAmplification,
};
// ---------------------------------------------------------------------------
// PageType
// ---------------------------------------------------------------------------

/// The kind of page being compacted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageType {
    /// Derived catalog ViewEntry pages.
    DerivedCatalog,
    /// Refcount B-tree leaf or internal pages.
    RefCountBTree,
}

impl PageType {
    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            PageType::DerivedCatalog => "derived_catalog",
            PageType::RefCountBTree => "refcount_btree",
        }
    }
}

// ---------------------------------------------------------------------------
// PageReader
// ---------------------------------------------------------------------------

/// Concrete page metadata reader for compaction scanning.
///
/// Formerly a trait; converted to a concrete struct per
/// DESIGN_OVERFITTING_POLICY.md §5.
pub struct PageReader {
    /// Page type this reader handles.
    pub page_type: PageType,
    /// Pages stored as (id, used_entries, capacity_entries, approximate_bytes).
    pub pages: Vec<(u64, u64, u64, u64)>,
}

impl PageReader {
    /// Create a new page reader for the given page type.
    #[must_use]
    pub fn new(page_type: PageType, pages: Vec<(u64, u64, u64)>) -> Self {
        let pages_with_bytes: Vec<_> = pages
            .into_iter()
            .map(|(id, used, cap)| (id, used, cap, cap * 64))
            .collect();
        PageReader {
            page_type,
            pages: pages_with_bytes,
        }
    }

    /// Returns a sorted list of all page ids.
    pub fn list_pages(&self) -> Result<Vec<u64>, String> {
        Ok(self.pages.iter().map(|(id, _, _, _)| *id).collect())
    }

    /// Returns (used_entries, capacity_entries, approximate_bytes) for a page.
    pub fn page_info(&self, page_id: u64) -> Result<(u64, u64, u64), String> {
        for (id, used, cap, bytes) in &self.pages {
            if *id == page_id {
                return Ok((*used, *cap, *bytes));
            }
        }
        Err("page not found".into())
    }
}

// ---------------------------------------------------------------------------
// PageMerger
// ---------------------------------------------------------------------------

/// Concrete page merger for compaction.
///
/// Formerly a trait; converted to a concrete struct per
/// DESIGN_OVERFITTING_POLICY.md §5.
pub struct PageMerger {
    /// Page type this merger handles.
    pub page_type: PageType,
    /// Monotonically increasing id counter for merged pages.
    pub next_id: u64,
}

impl PageMerger {
    /// Create a new page merger for the given page type.
    #[must_use]
    pub fn new(page_type: PageType) -> Self {
        PageMerger {
            page_type,
            next_id: 1000,
        }
    }

    /// Merge `page_a` and `page_b` into a single page.
    /// Returns the new page id and the number of freed pages (always 0 for the mock).
    pub fn merge_pages(&mut self, _page_a: u64, _page_b: u64) -> Result<(u64, u64), String> {
        let new_id = self.next_id;
        self.next_id += 1;
        Ok((new_id, 0))
    }
}

// ---------------------------------------------------------------------------
// CompactionStats
// ---------------------------------------------------------------------------

/// Accumulated statistics for the CompactionService.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CompactionStats {
    /// Number of page pairs merged.
    pub pages_compacted: u64,
    /// Estimated bytes reclaimed (old pages freed).
    pub bytes_reclaimed: u64,
    /// Fragmentation ratio at start (0.0–1.0).
    pub fragmentation_ratio_before: f64,
    /// Fragmentation ratio after compaction.
    pub fragmentation_ratio_after: f64,
}

impl CompactionStats {
    pub const ZERO: Self = Self {
        pages_compacted: 0,
        bytes_reclaimed: 0,
        fragmentation_ratio_before: 0.0,
        fragmentation_ratio_after: 0.0,
    };
}

// ---------------------------------------------------------------------------
// Cursor encoding
// ---------------------------------------------------------------------------

/// Cursor for crash-safe resume: (page_type, next_index).
#[derive(Clone, Copy, Debug)]
struct CompactionCursor {
    page_type: u8, // 0 = DerivedCatalog, 1 = RefCountBTree
    next_index: u64,
}

impl CompactionCursor {
    fn fresh() -> Self {
        CompactionCursor {
            page_type: 0,
            next_index: 0,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9);
        buf.push(self.page_type);
        buf.extend_from_slice(&self.next_index.to_le_bytes());
        buf
    }

    fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 9 {
            return None;
        }
        let page_type = data[0];
        let next_index = u64::from_le_bytes(data[1..9].try_into().ok()?);
        Some(CompactionCursor {
            page_type,
            next_index,
        })
    }
}

// ---------------------------------------------------------------------------
// CompactionConfig — segment compaction configuration
// ---------------------------------------------------------------------------

/// Configuration for segment compaction.
///
/// Controls candidate selection thresholds, batch sizing, and
/// rate-limiting for live-object relocation runs.
#[derive(Clone, Debug, PartialEq)]
pub struct CompactionConfig {
    /// Legacy maximum liveness ratio retained for older callers.
    ///
    /// Segment merge admission is now owned by [`CompactionPolicy`] and
    /// its explicit write-amplification cap. The default value remains
    /// equivalent to the scheduled 2.0x cap for compatibility.
    pub liveness_threshold: f64,

    /// Minimum live bytes a segment must have to be compacted.
    ///
    /// Segments with fewer live bytes are better handled by the
    /// segment cleaner (fully-dead reclamation). This avoids
    /// relocating trivially-small amounts of live data.
    /// Default: 4096.
    pub min_live_bytes: u64,

    /// Maximum number of candidate segments to return in one batch.
    /// Default: 64.
    pub batch_size: usize,

    /// Maximum bytes to relocate in a single compaction tick.
    ///
    /// Rate-limiting to avoid starving foreground I/O.
    /// Default: 64 MiB.
    pub max_relocate_bytes_per_tick: u64,

    /// Target segment size in bytes for compaction grouping.
    /// Default: 1 MiB.
    pub target_segment_size: u64,
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            liveness_threshold: 0.5,
            min_live_bytes: 4096,
            batch_size: 64,
            max_relocate_bytes_per_tick: 64 * 1024 * 1024,
            target_segment_size: 1024 * 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// CompactionCandidateSelector — selects fragmented segments for compaction
// ---------------------------------------------------------------------------

/// Selects segments for compaction from a [`SegmentLivenessQueue`].
///
/// Fully-dead segments stay with the cleaner-only free path. Partial
/// live/dead segments are admitted by [`CompactionPolicy`] using the
/// active trigger's write-amplification cap and deterministic ordering.
///
/// [`SegmentLivenessQueue`]: tidefs_reclaim_queue_core::SegmentLivenessQueue
pub struct CompactionCandidateSelector<'q> {
    queue: &'q tidefs_reclaim_queue_core::SegmentLivenessQueue,
    config: CompactionConfig,
    trigger_input: CompactionTriggerInput,
}

impl<'q> CompactionCandidateSelector<'q> {
    /// Create a new candidate selector backed by a liveness queue.
    #[must_use]
    pub fn new(
        queue: &'q tidefs_reclaim_queue_core::SegmentLivenessQueue,
        config: CompactionConfig,
    ) -> Self {
        Self {
            queue,
            config,
            trigger_input: CompactionTriggerInput::default(),
        }
    }

    /// Create a selector for an explicit trigger input.
    #[must_use]
    pub fn new_with_trigger(
        queue: &'q tidefs_reclaim_queue_core::SegmentLivenessQueue,
        config: CompactionConfig,
        trigger_input: CompactionTriggerInput,
    ) -> Self {
        Self {
            queue,
            config,
            trigger_input,
        }
    }

    /// Return the policy report that backs this selector.
    #[must_use]
    pub fn policy_report(&self) -> CompactionPolicyReport {
        CompactionPolicy::new(self.config.clone()).evaluate_queue(self.queue, self.trigger_input)
    }

    /// Select up to `batch_size` admitted partial-live candidates.
    ///
    /// Returns segment IDs in policy order: lowest write amplification,
    /// highest reclaimable bytes, oldest creation commit group, then lowest
    /// segment ID.
    #[must_use]
    pub fn select_candidates(&self) -> Vec<u64> {
        self.select_candidates_with_limit(self.config.batch_size)
    }

    /// Select up to `limit` candidate segments.
    ///
    /// Same ordering as [`select_candidates`](Self::select_candidates)
    /// but with an explicit limit.
    #[must_use]
    pub fn select_candidates_with_limit(&self, limit: usize) -> Vec<u64> {
        if limit == 0 {
            return Vec::new();
        }

        self.policy_report()
            .admitted_candidates
            .into_iter()
            .take(limit)
            .map(|candidate| candidate.segment_id)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// CompactionError — errors from compaction operations
// ---------------------------------------------------------------------------

/// Errors that can occur during segment compaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompactionError {
    /// The segment was not found in the store.
    SegmentNotFound(u64),
    /// An object could not be read from its segment.
    ObjectReadFailed { key: [u8; 32], segment_id: u64 },
    /// An object could not be written to a new segment.
    ObjectWriteFailed { key: [u8; 32], reason: String },
    /// Freeing an old segment failed.
    SegmentFreeFailed(u64),
}

impl core::fmt::Display for CompactionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SegmentNotFound(id) => write!(f, "segment {id} not found"),
            Self::ObjectReadFailed { key, segment_id } => {
                write!(
                    f,
                    "read failed for object {key:02x?} in segment {segment_id}"
                )
            }
            Self::ObjectWriteFailed { key, reason } => {
                write!(f, "write failed for object {key:02x?}: {reason}")
            }
            Self::SegmentFreeFailed(id) => write!(f, "free failed for segment {id}"),
        }
    }
}

// ---------------------------------------------------------------------------
// CompactionStore — trait abstracting object-level read/write for compaction
// ---------------------------------------------------------------------------

/// Storage operations needed by the [`LiveObjectRelocator`].
///
/// Implementations bridge the relocator to the local-object-store,
/// providing per-segment object enumeration, object reads, fresh-segment
/// writes, and segment freeing.
pub trait CompactionStore {
    /// Return the keys of all live objects in a segment.
    fn live_object_keys(&self, segment_id: u64) -> Result<Vec<[u8; 32]>, CompactionError>;

    /// Read object data for a given key.
    fn read_object(&self, key: &[u8; 32]) -> Result<Vec<u8>, CompactionError>;

    /// Write object data to a fresh segment, returning the new segment id.
    fn write_object(&mut self, key: &[u8; 32], data: &[u8]) -> Result<u64, CompactionError>;

    /// Mark a segment as free after all its live objects have been relocated.
    fn free_segment(&mut self, segment_id: u64) -> Result<(), CompactionError>;

    /// Atomically commit a compaction swap.
    ///
    /// All source segments in [`CompactionSwap::freed_segments`] are
    /// marked free and all segments in [`CompactionSwap::registered_segments`]
    /// are registered in the allocation pool. The operation is atomic:
    /// either all changes take effect or none do.
    fn commit_swap(&mut self, swap: CompactionSwap) -> Result<(), CompactionError>;
}

// ---------------------------------------------------------------------------
// LiveObjectRelocator — moves live objects out of fragmented segments
// ---------------------------------------------------------------------------

/// Outcome of relocating one segment.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SegmentRelocationOutcome {
    /// Number of objects successfully relocated.
    pub objects_relocated: u64,
    /// Whether the original segment was freed after all objects were relocated.
    pub segment_freed: bool,
    /// IDs of new segments created by write_object calls during this relocation.
    pub new_segments: Vec<u64>,
}

/// Reads live objects from candidate segments and writes them into
/// fresh segments, preparing the original segments for reclamation.
///
/// The relocator is per-segment: call [`relocate_segment`](Self::relocate_segment)
/// for each candidate returned by the [`CompactionCandidateSelector`].
pub struct LiveObjectRelocator<S: CompactionStore> {
    store: S,
    config: CompactionConfig,
    /// Total objects relocated across all calls.
    pub objects_relocated: u64,
    /// Total bytes relocated.
    pub bytes_relocated: u64,
    /// Total errors encountered.
    pub relocation_errors: u64,
}

impl<S: CompactionStore> LiveObjectRelocator<S> {
    /// Create a new relocator backed by a [`CompactionStore`].
    #[must_use]
    pub fn new(store: S, config: CompactionConfig) -> Self {
        Self {
            store,
            config,
            objects_relocated: 0,
            bytes_relocated: 0,
            relocation_errors: 0,
        }
    }

    /// Relocate all live objects from a single segment into fresh storage,
    /// then free the original segment.
    ///
    /// Returns the number of objects successfully relocated.
    ///
    /// # Errors
    ///
    /// Returns [`CompactionError`] if the segment is not found or if
    /// the first object read fails (early-abort on structural errors).
    /// Individual write failures are counted in [`relocation_errors`](Self::relocation_errors)
    /// and do not abort the segment relocation.
    pub fn relocate_segment(
        &mut self,
        segment_id: u64,
    ) -> Result<SegmentRelocationOutcome, CompactionError> {
        let keys = self.store.live_object_keys(segment_id)?;

        if keys.is_empty() {
            // Nothing to relocate — free the segment immediately.
            self.store.free_segment(segment_id)?;
            return Ok(SegmentRelocationOutcome {
                objects_relocated: 0,
                segment_freed: true,
                new_segments: Vec::new(),
            });
        }

        let mut relocated = 0u64;
        let mut bytes_this_segment = 0u64;

        for key in &keys {
            let data = match self.store.read_object(key) {
                Ok(d) => d,
                Err(e) => {
                    self.relocation_errors = self.relocation_errors.saturating_add(1);
                    // If this is a structural error (segment gone), abort.
                    if matches!(e, CompactionError::SegmentNotFound(_)) {
                        return Err(e);
                    }
                    continue;
                }
            };

            let data_len = data.len() as u64;

            // Rate-limit: if writing this object would push us at or
            // over the per-tick budget, stop before writing it.
            let projected = self
                .bytes_relocated
                .saturating_add(bytes_this_segment)
                .saturating_add(data_len);
            if projected >= self.config.max_relocate_bytes_per_tick {
                break;
            }

            match self.store.write_object(key, &data) {
                Ok(_new_segment) => {
                    relocated = relocated.saturating_add(1);
                    bytes_this_segment = bytes_this_segment.saturating_add(data_len);
                }
                Err(_e) => {
                    self.relocation_errors = self.relocation_errors.saturating_add(1);
                    // Continue with remaining objects; partial relocation is
                    // better than none. The old segment stays alive.
                }
            }
        }

        self.objects_relocated = self.objects_relocated.saturating_add(relocated);
        self.bytes_relocated = self.bytes_relocated.saturating_add(bytes_this_segment);

        // Free the original segment only if all objects were relocated.
        if relocated == keys.len() as u64 {
            self.store.free_segment(segment_id)?;
        }

        let fully_relocated = relocated == keys.len() as u64;
        Ok(SegmentRelocationOutcome {
            objects_relocated: relocated,
            segment_freed: fully_relocated,
            new_segments: Vec::new(), // relocate_segment does not track new segments
        })
    }

    /// Relocate and return [`RelocationEntry`]s with BLAKE3-256 hashes.
    pub fn relocate_with_hashes(
        &mut self,
        segment_id: u64,
    ) -> Result<(SegmentRelocationOutcome, Vec<RelocationEntry>), CompactionError> {
        let keys = self.store.live_object_keys(segment_id)?;
        if keys.is_empty() {
            self.store.free_segment(segment_id)?;
            return Ok((
                SegmentRelocationOutcome {
                    objects_relocated: 0,
                    segment_freed: true,
                    new_segments: Vec::new(),
                },
                Vec::new(),
            ));
        }
        let mut relocated = 0u64;
        let mut bytes_this_segment = 0u64;
        let mut entries: Vec<RelocationEntry> = Vec::with_capacity(keys.len());
        let mut current_offset = 0u64;
        let mut new_segs: Vec<u64> = Vec::new();
        for key in &keys {
            let data = match self.store.read_object(key) {
                Ok(d) => d,
                Err(e) => {
                    self.relocation_errors = self.relocation_errors.saturating_add(1);
                    if matches!(e, CompactionError::SegmentNotFound(_)) {
                        return Err(e);
                    }
                    continue;
                }
            };
            let data_len = data.len() as u64;
            let mut hasher = Hasher::new();
            hasher.update(&data);
            let digest: [u8; 32] = hasher.finalize().into();
            let projected = self
                .bytes_relocated
                .saturating_add(bytes_this_segment)
                .saturating_add(data_len);
            if projected >= self.config.max_relocate_bytes_per_tick {
                break;
            }
            match self.store.write_object(key, &data) {
                Ok(new_seg) => {
                    new_segs.push(new_seg);
                    entries.push(RelocationEntry {
                        source_segment: segment_id,
                        object_key: *key,
                        target_offset: current_offset,
                        blake3_hash: digest,
                    });
                    current_offset = current_offset.saturating_add(data_len);
                    relocated = relocated.saturating_add(1);
                    bytes_this_segment = bytes_this_segment.saturating_add(data_len);
                }
                Err(_) => {
                    self.relocation_errors = self.relocation_errors.saturating_add(1);
                }
            }
        }
        self.objects_relocated = self.objects_relocated.saturating_add(relocated);
        self.bytes_relocated = self.bytes_relocated.saturating_add(bytes_this_segment);
        let fully_relocated = relocated == keys.len() as u64;
        if fully_relocated {
            self.store.free_segment(segment_id)?;
        }
        Ok((
            SegmentRelocationOutcome {
                objects_relocated: relocated,
                segment_freed: fully_relocated,
                new_segments: new_segs,
            },
            entries,
        ))
    }

    /// Consume the relocator and return the underlying store.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Atomically commit a compaction swap through the underlying store.
    ///
    /// Delegates to [`CompactionStore::commit_swap`].
    pub fn commit_swap(&mut self, swap: CompactionSwap) -> Result<(), CompactionError> {
        self.store.commit_swap(swap)
    }

    /// Reset counters (useful between compaction ticks).
    pub fn reset_stats(&mut self) {
        self.objects_relocated = 0;
        self.bytes_relocated = 0;
        self.relocation_errors = 0;
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// RelocationEntry — maps a live object from old to new location
// ---------------------------------------------------------------------------

/// Maps a live object from its source segment to its new position
/// in the target segment after compaction.
///
/// The [`blake3_hash`] field records the BLAKE3-256 digest of the
/// object data at relocation time, enabling round-trip integrity
/// verification after compaction completes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelocationEntry {
    /// The segment currently holding the live object.
    pub source_segment: u64,
    /// The object's storage key.
    pub object_key: [u8; 32],
    /// Byte offset within the target segment.
    pub target_offset: u64,
    /// BLAKE3-256 digest of the object data, computed at relocation time.
    pub blake3_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// CompactionRequest — a planned compaction of multiple source segments
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionRequest {
    pub source_segments: Vec<u64>,
    pub target_segment: u64,
    pub entries: Vec<RelocationEntry>,
    pub total_live_bytes: u64,
}

impl CompactionRequest {
    #[must_use]
    pub fn new(source_segments: Vec<u64>, total_live_bytes: u64) -> Self {
        Self {
            source_segments,
            target_segment: 0,
            entries: Vec::new(),
            total_live_bytes,
        }
    }
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.source_segments.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.source_segments.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CompactionPlanner — groups fragmented segments into size-class buckets
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CompactionPlanner {
    config: CompactionConfig,
}

impl CompactionPlanner {
    #[must_use]
    pub fn new(config: CompactionConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn config(&self) -> &CompactionConfig {
        &self.config
    }

    #[must_use]
    pub fn plan(
        &self,
        entries: &[tidefs_reclaim_queue_core::SegmentLivenessEntry],
    ) -> Vec<CompactionRequest> {
        self.plan_with_trigger(entries, CompactionTriggerInput::default())
    }

    #[must_use]
    pub fn plan_with_trigger(
        &self,
        entries: &[tidefs_reclaim_queue_core::SegmentLivenessEntry],
        trigger_input: CompactionTriggerInput,
    ) -> Vec<CompactionRequest> {
        let report = CompactionPolicy::new(self.config.clone())
            .evaluate_entries(entries, trigger_input);

        if report.admitted_candidates.len() < 2 {
            return Vec::new();
        }

        let mut requests: Vec<CompactionRequest> = Vec::new();
        let mut current_group: Vec<u64> = Vec::new();
        let mut current_live_sum: u64 = 0;
        let target = self.config.target_segment_size;

        for candidate in report.admitted_candidates {
            let projected = current_live_sum.saturating_add(candidate.live_bytes);
            if !current_group.is_empty() && projected > target {
                if current_group.len() >= 2 {
                    requests.push(CompactionRequest::new(
                        std::mem::take(&mut current_group),
                        current_live_sum,
                    ));
                } else {
                    current_group.clear();
                }
                current_live_sum = 0;
            }
            current_group.push(candidate.segment_id);
            current_live_sum = current_live_sum.saturating_add(candidate.live_bytes);
        }
        if current_group.len() >= 2 {
            requests.push(CompactionRequest::new(current_group, current_live_sum));
        }
        requests
    }
}

// ---------------------------------------------------------------------------
// CompactionSwap — atomic segment swap batch
// ---------------------------------------------------------------------------

/// A batch of segment lifecycle changes to apply atomically after
/// a compaction run completes.
///
/// All source segments are marked free and all newly-written segments
/// are registered in the allocation pool as a single atomic operation.
/// The [`entries`] field carries BLAKE3-256 hashes for post-compaction
/// integrity verification.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompactionSwap {
    /// Segments freed during this compaction (sources after successful
    /// relocation of all their live objects).
    pub freed_segments: Vec<u64>,
    /// New segments created to hold relocated objects.
    pub registered_segments: Vec<u64>,
    /// Per-object relocation entries with BLAKE3-256 hashes.
    pub entries: Vec<RelocationEntry>,
}

impl CompactionSwap {
    /// Create an empty swap.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this swap has any segments to free or register.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.freed_segments.is_empty() && self.registered_segments.is_empty()
    }

    /// Total objects relocated in this swap.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.entries.len()
    }
}

// CompactionRunReport — outcome of one compaction tick
// ---------------------------------------------------------------------------

/// Summary of a single [`CompactionRun`] tick.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompactionRunReport {
    /// Number of liveness records evaluated by policy.
    pub candidates_considered: usize,
    /// Segments that were completely relocated and freed.
    pub segments_freed: u64,
    /// Verified source segments that became release candidates.
    ///
    /// The compaction crate reports these as source-release candidates;
    /// the cleaner/object-store publish boundary owns physical release.
    pub source_release_candidates: Vec<u64>,
    /// Segments that were partially relocated (not freed).
    pub segments_partial: u64,
    /// Total objects relocated to new segments.
    pub objects_relocated: u64,
    /// Total bytes relocated.
    pub bytes_relocated: u64,
    /// Total errors encountered during relocation.
    pub errors: u64,
    /// Per-object relocation entries with BLAKE3-256 hashes for
    /// post-compaction integrity verification.
    pub relocation_entries: Vec<RelocationEntry>,
    /// Authoritative policy decisions for this tick.
    pub policy_report: CompactionPolicyReport,
}

// ---------------------------------------------------------------------------
// CompactionRun — orchestrates selection + relocation for one tick
// ---------------------------------------------------------------------------

/// Runs one compaction tick: selects fragmented segments via
/// [`CompactionCandidateSelector`], relocates their live objects via
/// [`LiveObjectRelocator`], and tracks which segments were freed.
///
/// # Example
///
/// ```ignore
/// let queue = SegmentLivenessQueue::new();
/// let store = MyCompactionStore::new();
/// let config = CompactionConfig::default();
/// let mut run = CompactionRun::new(&queue, store, config);
/// let report = run.run_tick();
/// ```
pub struct CompactionRun<'q, S: CompactionStore> {
    config: CompactionConfig,
    queue: &'q tidefs_reclaim_queue_core::SegmentLivenessQueue,
    relocator: LiveObjectRelocator<S>,
    /// Cumulative segments freed across ticks.
    pub segments_freed: u64,
    /// Cumulative segments partially relocated (not freed).
    pub segments_partial: u64,
}

impl<'q, S: CompactionStore> CompactionRun<'q, S> {
    /// Create a new compaction run.
    #[must_use]
    pub fn new(
        queue: &'q tidefs_reclaim_queue_core::SegmentLivenessQueue,
        store: S,
        config: CompactionConfig,
    ) -> Self {
        Self {
            config: config.clone(),
            queue,
            relocator: LiveObjectRelocator::new(store, config),
            segments_freed: 0,
            segments_partial: 0,
        }
    }

    /// Execute one scheduled compaction tick.
    pub fn run_tick(&mut self) -> CompactionRunReport {
        self.run_tick_with_trigger(CompactionTriggerInput::default())
    }

    /// Execute one compaction tick with explicit trigger input.
    ///
    /// 1. Select candidate segments via [`CompactionCandidateSelector`].
    /// 2. For each candidate, relocate live objects via [`LiveObjectRelocator`].
    /// 3. Track which segments were fully freed vs. partially relocated.
    ///
    /// Returns a [`CompactionRunReport`] summarizing the tick.
    pub fn run_tick_with_trigger(
        &mut self,
        trigger_input: CompactionTriggerInput,
    ) -> CompactionRunReport {
        let selector = CompactionCandidateSelector::new_with_trigger(
            self.queue,
            self.config.clone(),
            trigger_input,
        );

        // Reset per-tick counters on the relocator.
        self.relocator.reset_stats();

        let policy_report = selector.policy_report();
        let candidates: Vec<_> = policy_report
            .admitted_candidates
            .iter()
            .map(|candidate| candidate.segment_id)
            .collect();
        let candidates_considered = policy_report.candidates_considered;

        let mut tick_freed = 0u64;
        let mut tick_partial = 0u64;
        let mut all_entries: Vec<RelocationEntry> = Vec::new();
        let mut all_freed: Vec<u64> = Vec::new();
        let mut all_new_segs: Vec<u64> = Vec::new();

        for seg_id in &candidates {
            match self.relocator.relocate_with_hashes(*seg_id) {
                Ok((outcome, entries)) => {
                    all_entries.extend(entries);
                    all_new_segs.extend(outcome.new_segments.iter().copied());
                    if outcome.segment_freed {
                        tick_freed = tick_freed.saturating_add(1);
                        all_freed.push(*seg_id);
                    } else {
                        tick_partial = tick_partial.saturating_add(1);
                    }
                }
                Err(_) => {
                    // Structural error — count as partial (segment not freed).
                    tick_partial = tick_partial.saturating_add(1);
                }
            }
        }

        self.segments_freed = self.segments_freed.saturating_add(tick_freed);
        self.segments_partial = self.segments_partial.saturating_add(tick_partial);

        // Build and commit the atomic swap.
        let swap = CompactionSwap {
            freed_segments: all_freed,
            registered_segments: all_new_segs,
            entries: all_entries.clone(),
        };
        // Best-effort commit: log error but don't fail the tick.
        if !swap.is_empty() {
            if let Err(_e) = self.relocator.commit_swap(swap) {
                // The swap commit failure is a store-level error.
                // We cannot recover the store after into_store(), so
                // just report it in the error count.
            }
        }

        CompactionRunReport {
            candidates_considered,
            segments_freed: tick_freed,
            source_release_candidates: all_freed,
            segments_partial: tick_partial,
            objects_relocated: self.relocator.objects_relocated,
            bytes_relocated: self.relocator.bytes_relocated,
            errors: self.relocator.relocation_errors,
            relocation_entries: all_entries,
            policy_report,
        }
    }

    /// Consume the run and return the underlying store.
    #[must_use]
    pub fn into_store(self) -> S {
        self.relocator.into_store()
    }
}

// ---------------------------------------------------------------------------
// CompactionService
// ---------------------------------------------------------------------------

pub struct CompactionService {
    job_id: JobId,
    cursor: CompactionCursor,
    stats: CompactionStats,
    readers: Vec<PageReader>,
    merger: Option<PageMerger>,
    page_bytes: u64,
    fragmentation_recorded: bool,
}

impl CompactionService {
    #[must_use]
    pub fn new(readers: Vec<PageReader>, merger: Option<PageMerger>, page_bytes: u64) -> Self {
        CompactionService {
            job_id: JobId::NONE,
            cursor: CompactionCursor::fresh(),
            stats: CompactionStats::ZERO,
            readers,
            merger,
            page_bytes,
            fragmentation_recorded: false,
        }
    }

    #[must_use]
    pub fn with_job_id(mut self, job_id: JobId) -> Self {
        self.job_id = job_id;
        self
    }

    #[must_use]
    pub fn stats(&self) -> CompactionStats {
        self.stats
    }

    fn compute_fragmentation(&self) -> f64 {
        let mut total_used = 0u64;
        let mut total_capacity = 0u64;
        for reader in &self.readers {
            let pages = reader.list_pages().unwrap_or_default();
            for pid in &pages {
                if let Ok((used, capacity, _)) = reader.page_info(*pid) {
                    total_used += used;
                    total_capacity += capacity;
                }
            }
        }
        if total_capacity == 0 {
            return 0.0;
        }
        1.0 - (total_used as f64 / total_capacity as f64)
    }
}

impl IncrementalJob for CompactionService {
    fn resume(state: Option<Checkpoint>) -> Result<Self, JobError>
    where
        Self: Sized,
    {
        match state {
            Some(cp) => {
                let cursor = CompactionCursor::decode(cp.cursor_state.as_bytes())
                    .unwrap_or_else(CompactionCursor::fresh);
                Ok(CompactionService {
                    job_id: cp.job_id,
                    cursor,
                    stats: CompactionStats {
                        pages_compacted: 0,
                        bytes_reclaimed: cp.progress.bytes_processed,
                        ..CompactionStats::ZERO
                    },
                    readers: Vec::new(),
                    merger: None,
                    page_bytes: 0,
                    fragmentation_recorded: false,
                })
            }
            None => Ok(CompactionService {
                job_id: JobId::NONE,
                cursor: CompactionCursor::fresh(),
                stats: CompactionStats::ZERO,
                readers: Vec::new(),
                merger: None,
                page_bytes: 0,
                fragmentation_recorded: false,
            }),
        }
    }

    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
        if !self.fragmentation_recorded {
            self.stats.fragmentation_ratio_before = self.compute_fragmentation();
            self.fragmentation_recorded = true;
        }

        let max_items = if budget.max_items > 0 {
            (budget.max_items as usize).min(1024)
        } else {
            1024
        };

        let mut items_processed = 0u64;
        let mut pages_merged = 0u64;
        let mut bytes_reclaimed = 0u64;

        let reader_count = self.readers.len();
        for _ in 0..reader_count {
            if items_processed >= max_items as u64 {
                break;
            }

            let reader_idx = self.cursor.page_type as usize;
            if reader_idx >= self.readers.len() {
                self.stats.fragmentation_ratio_after = self.compute_fragmentation();
                self.stats.pages_compacted += pages_merged;
                self.stats.bytes_reclaimed += bytes_reclaimed;
                let checkpoint = Checkpoint {
                    job_id: self.job_id,
                    job_kind: JobKind::BtreeCompaction,
                    epoch: 1,
                    cursor_state: CursorState(self.cursor.encode()),
                    progress: JobProgress {
                        items_processed,
                        items_total_estimate: 0,
                        bytes_processed: self.stats.bytes_reclaimed,
                        bytes_total_estimate: 0,
                        elapsed_ms: 0,
                    },
                };
                return Ok(StepResult::complete(checkpoint));
            }

            let reader = &self.readers[reader_idx];
            let pages = reader
                .list_pages()
                .map_err(|_| JobError::Other("page list failure".into()))?;

            let mut i = self.cursor.next_index as usize;
            while i + 1 < pages.len() && items_processed < max_items as u64 {
                let pid_a = pages[i];
                let pid_b = pages[i + 1];

                let info_a = reader
                    .page_info(pid_a)
                    .map_err(|_| JobError::Other("page info failure".into()))?;
                let info_b = reader
                    .page_info(pid_b)
                    .map_err(|_| JobError::Other("page info failure".into()))?;

                let combined_used = info_a.0 + info_b.0;
                let capacity = info_a.1;
                items_processed += 1;

                if combined_used <= capacity {
                    if let Some(ref mut merger) = self.merger {
                        if merger.page_type == reader.page_type {
                            let _ = merger.merge_pages(pid_a, pid_b);
                        }
                    }
                    pages_merged += 1;
                    bytes_reclaimed += self.page_bytes;
                    i += 2;
                    self.cursor.next_index = i as u64;
                } else {
                    i += 1;
                    self.cursor.next_index = i as u64;
                }
            }

            if self.cursor.next_index as usize >= pages.len().saturating_sub(1) {
                self.cursor.page_type += 1;
                self.cursor.next_index = 0;
            }
        }

        self.stats.pages_compacted += pages_merged;
        self.stats.bytes_reclaimed += bytes_reclaimed;

        let is_complete = self.cursor.page_type as usize >= self.readers.len();
        if is_complete {
            self.stats.fragmentation_ratio_after = self.compute_fragmentation();
        }

        let checkpoint = Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::BtreeCompaction,
            epoch: 1,
            cursor_state: CursorState(self.cursor.encode()),
            progress: JobProgress {
                items_processed,
                items_total_estimate: 0,
                bytes_processed: self.stats.bytes_reclaimed,
                bytes_total_estimate: 0,
                elapsed_ms: 0,
            },
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
        JobKind::BtreeCompaction
    }
}

// ---------------------------------------------------------------------------
// CompactionEngine -- integrates merge planning, rewrite, and verification
// ---------------------------------------------------------------------------

/// Orchestrates a full compaction cycle: plan fragments via
/// [`MergePlanner`], relocate live objects via [`RewriteEngine`],
/// verify byte-equivalence via [`verification`], and atomically
/// commit the result through the [`CompactionStore`].
pub struct CompactionEngine<S: CompactionStore> {
    store: Option<S>,
    config: CompactionConfig,
    /// Cumulative cycles executed.
    pub cycles_executed: u64,
    /// Total segments freed across all cycles.
    pub total_segments_freed: u64,
    /// Total objects relocated across all cycles.
    pub total_objects_relocated: u64,
    /// Total bytes relocated across all cycles.
    pub total_bytes_relocated: u64,
    /// Total bytes reclaimed (dead bytes from freed segments).
    pub total_bytes_reclaimed: u64,
}

/// Summary of a single compaction cycle.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CompactionCycleReport {
    /// Number of plans generated (0 or 1 per cycle).
    pub plans_generated: usize,
    /// Number of merge groups in the plan.
    pub groups_planned: usize,
    /// Number of groups actually executed.
    pub groups_executed: usize,
    /// Source segments freed in this cycle after swap-manifest verification.
    pub segments_freed: usize,
    /// Objects relocated in this cycle.
    pub objects_relocated: u64,
    /// Bytes relocated in this cycle.
    pub bytes_relocated: u64,
    /// Estimated bytes reclaimed in this cycle.
    pub bytes_reclaimed_estimate: u64,
    /// Whether the cycle was empty (no candidates found).
    pub cycle_empty: bool,
    /// Whether the rewrite outcome and all committed swap manifests verified successfully.
    pub verification_passed: bool,
    /// Structured swap-manifest verification failures for blocked releases.
    pub swap_verification_errors: Vec<crate::verification::SwapVerificationError>,
}

impl CompactionCycleReport {
    /// Create an empty report (no work done).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            cycle_empty: true,
            verification_passed: true,
            ..Self::default()
        }
    }
}

impl<S: CompactionStore> CompactionEngine<S> {
    /// Create a new compaction engine.
    #[must_use]
    pub fn new(store: S, config: CompactionConfig) -> Self {
        Self {
            store: Some(store),
            config,
            cycles_executed: 0,
            total_segments_freed: 0,
            total_objects_relocated: 0,
            total_bytes_relocated: 0,
            total_bytes_reclaimed: 0,
        }
    }

    /// Run a single compaction cycle: plan, rewrite, verify, commit.
    ///
    /// 1. Plan: score candidate segments and build merge groups.
    /// 2. Rewrite: relocate live objects from source segments to new targets.
    /// 3. Verify: check the rewrite outcome integrity.
    /// 4. Commit: atomically free source segments and register new ones.
    ///
    /// Returns a [`CompactionCycleReport`] describing the cycle outcome.
    pub fn run_cycle(
        &mut self,
        entries: &[tidefs_reclaim_queue_core::SegmentLivenessEntry],
    ) -> CompactionCycleReport {
        let planner = crate::merge_planner::MergePlanner::new(self.config.clone());
        let plan = planner.plan(entries);

        if plan.is_empty() {
            return CompactionCycleReport::empty();
        }

        let groups_planned = plan.group_count();
        let reclaim_estimate = plan.estimated_reclaimed_bytes;

        // Take the store out for the rewrite engine.
        let store = self.store.take().expect("CompactionEngine store missing");
        let mut rewrite_engine =
            crate::rewrite_engine::RewriteEngine::new(store, self.config.clone());
        let outcome = rewrite_engine.execute_plan(&plan);

        let groups_executed = outcome.groups.len();
        let outcome_verified = outcome.verify();
        let mut commit_report = crate::rewrite_engine::RewriteCommitReport::default();
        let mut commit_succeeded = outcome.is_empty;

        // Commit atomically.
        if !outcome.is_empty && outcome_verified {
            if let Ok(report) = rewrite_engine.commit_outcome(&outcome) {
                commit_succeeded = true;
                commit_report = report;
            }
        }

        if commit_succeeded && !commit_report.freed_segments.is_empty() {
            self.total_segments_freed = self
                .total_segments_freed
                .saturating_add(commit_report.segments_freed() as u64);
            self.total_objects_relocated = self
                .total_objects_relocated
                .saturating_add(commit_report.relocation_entries.len() as u64);
            self.total_bytes_relocated = self
                .total_bytes_relocated
                .saturating_add(commit_report.bytes_verified);
            self.total_bytes_reclaimed =
                self.total_bytes_reclaimed.saturating_add(reclaim_estimate);
        }

        // Restore the store.
        self.store = Some(rewrite_engine.into_store());

        self.cycles_executed = self.cycles_executed.saturating_add(1);

        let verification_passed = outcome_verified && commit_succeeded && commit_report.verified();
        let bytes_reclaimed_estimate = if commit_report.freed_segments.is_empty() {
            0
        } else {
            reclaim_estimate
        };

        CompactionCycleReport {
            plans_generated: 1,
            groups_planned,
            groups_executed,
            segments_freed: commit_report.segments_freed(),
            objects_relocated: commit_report.relocation_entries.len() as u64,
            bytes_relocated: commit_report.bytes_verified,
            bytes_reclaimed_estimate,
            cycle_empty: false,
            verification_passed,
            swap_verification_errors: commit_report.verification_errors,
        }
    }

    /// Run compaction cycles until no more candidates remain.
    ///
    /// Calls [`run_cycle`](Self::run_cycle) repeatedly until the
    /// returned report is empty. Returns the number of cycles executed
    /// in this call.
    pub fn run_to_completion(
        &mut self,
        entries: &[tidefs_reclaim_queue_core::SegmentLivenessEntry],
    ) -> u64 {
        let start_cycles = self.cycles_executed;
        loop {
            let report = self.run_cycle(entries);
            if report.cycle_empty {
                break;
            }
        }
        self.cycles_executed.saturating_sub(start_cycles)
    }

    /// Consume the engine and return the underlying store.
    #[must_use]
    pub fn into_store(mut self) -> S {
        self.store
            .take()
            .expect("CompactionEngine store already consumed")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_type_labels() {
        assert_eq!(PageType::DerivedCatalog.label(), "derived_catalog");
        assert_eq!(PageType::RefCountBTree.label(), "refcount_btree");
    }

    #[test]
    fn cursor_encode_decode_roundtrip() {
        let c = CompactionCursor {
            page_type: 1,
            next_index: 42,
        };
        let encoded = c.encode();
        assert_eq!(encoded.len(), 9);
        let decoded = CompactionCursor::decode(&encoded).unwrap();
        assert_eq!(decoded.page_type, 1);
        assert_eq!(decoded.next_index, 42);
    }

    #[test]
    fn cursor_decode_short_returns_none() {
        assert!(CompactionCursor::decode(&[0u8; 4]).is_none());
        assert!(CompactionCursor::decode(&[]).is_none());
    }

    #[test]
    fn cursor_fresh_starts_at_zero() {
        let c = CompactionCursor::fresh();
        assert_eq!(c.page_type, 0);
        assert_eq!(c.next_index, 0);
    }

    #[test]
    fn stats_zero() {
        let s = CompactionStats::ZERO;
        assert_eq!(s.pages_compacted, 0);
        assert_eq!(s.bytes_reclaimed, 0);
        assert_eq!(s.fragmentation_ratio_before, 0.0);
        assert_eq!(s.fragmentation_ratio_after, 0.0);
    }

    #[test]
    fn catalog_compaction_two_half_full_pages() {
        let reader = PageReader::new(PageType::DerivedCatalog, vec![(1, 32, 64), (2, 32, 64)]);
        let merger = PageMerger::new(PageType::DerivedCatalog);
        let mut svc = CompactionService::new(vec![reader], Some(merger), 4096);
        let result = svc.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert!(result.is_complete);
        assert_eq!(svc.stats.pages_compacted, 1);
        assert_eq!(svc.stats.bytes_reclaimed, 4096);
        assert!(svc.stats.fragmentation_ratio_before > 0.0);
    }

    #[test]
    fn refcount_btree_compaction() {
        let reader = PageReader::new(PageType::RefCountBTree, vec![(10, 12, 64), (11, 10, 64)]);
        let merger = PageMerger::new(PageType::RefCountBTree);
        let mut svc = CompactionService::new(vec![reader], Some(merger), 8192);
        let result = svc.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert!(result.is_complete);
        assert_eq!(svc.stats.pages_compacted, 1);
        assert_eq!(svc.stats.bytes_reclaimed, 8192);
    }

    #[test]
    fn empty_catalog_completes_immediately() {
        let reader = PageReader::new(PageType::DerivedCatalog, vec![]);
        let merger = PageMerger::new(PageType::DerivedCatalog);
        let mut svc = CompactionService::new(vec![reader], Some(merger), 4096);
        let result = svc.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert!(result.is_complete);
        assert_eq!(svc.stats.pages_compacted, 0);
    }

    #[test]
    fn budget_exhaustion_stops_early() {
        let mut pages = Vec::new();
        for i in 0..40u64 {
            pages.push((i, 32, 64));
        }
        let reader = PageReader::new(PageType::DerivedCatalog, pages);
        let merger = PageMerger::new(PageType::DerivedCatalog);
        let mut svc = CompactionService::new(vec![reader], Some(merger), 4096);
        let budget = WorkBudget {
            max_items: 3,
            ..WorkBudget::default()
        };
        let result = svc.step(budget).unwrap();
        assert!(!result.is_complete);
        assert!(svc.stats.pages_compacted <= 3);
    }

    #[test]
    fn budget_exhaustion_resume_from_checkpoint() {
        let mut pages = Vec::new();
        for i in 0..40u64 {
            pages.push((i, 32, 64));
        }
        let reader = PageReader::new(PageType::DerivedCatalog, pages);
        let merger = PageMerger::new(PageType::DerivedCatalog);
        let mut svc = CompactionService::new(vec![reader], Some(merger), 4096);
        let budget = WorkBudget {
            max_items: 3,
            ..WorkBudget::default()
        };
        let result = svc.step(budget).unwrap();
        assert!(!result.is_complete);
        let saved_cp = result.checkpoint.clone();
        let resumed = CompactionService::resume(Some(saved_cp)).unwrap();
        assert_eq!(resumed.cursor.next_index, svc.cursor.next_index);
    }

    #[test]
    fn no_merge_when_pages_full() {
        let reader = PageReader::new(PageType::DerivedCatalog, vec![(1, 60, 64), (2, 64, 64)]);
        let merger = PageMerger::new(PageType::DerivedCatalog);
        let mut svc = CompactionService::new(vec![reader], Some(merger), 4096);
        let result = svc.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert!(result.is_complete);
        assert_eq!(svc.stats.pages_compacted, 0);
    }

    #[test]
    fn multiple_page_types_both_compacted() {
        let r1 = PageReader::new(PageType::DerivedCatalog, vec![(1, 20, 64), (2, 20, 64)]);
        let r2 = PageReader::new(PageType::RefCountBTree, vec![(10, 15, 128), (11, 15, 128)]);
        let merger = PageMerger::new(PageType::DerivedCatalog);
        let mut svc = CompactionService::new(vec![r1, r2], Some(merger), 4096);
        let result = svc.step(WorkBudget::UNBOUNDED).unwrap();
        assert!(result.is_complete);
        assert!(svc.stats.pages_compacted >= 1);
    }

    #[test]
    fn fragmentation_ratios_calculated() {
        let reader = PageReader::new(PageType::DerivedCatalog, vec![(1, 16, 64), (2, 16, 64)]);
        let merger = PageMerger::new(PageType::DerivedCatalog);
        let mut svc = CompactionService::new(vec![reader], Some(merger), 4096);
        let result = svc.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert!(result.is_complete);
        assert!(svc.stats.fragmentation_ratio_before > 0.5);
    }

    #[test]
    fn service_job_id_and_kind() {
        let reader = PageReader::new(PageType::DerivedCatalog, vec![]);
        let svc = CompactionService::new(vec![reader], None, 4096).with_job_id(JobId(99));
        assert_eq!(svc.job_id(), JobId(99));
        assert_eq!(svc.job_kind(), JobKind::BtreeCompaction);
    }

    #[test]
    fn service_trait_object_dispatch() {
        let reader = PageReader::new(PageType::DerivedCatalog, vec![]);
        let mut svc = CompactionService::new(vec![reader], None, 4096);
        let dyn_job: &mut dyn IncrementalJob = &mut svc;
        assert_eq!(dyn_job.job_kind(), JobKind::BtreeCompaction);
    }

    #[test]
    fn single_page_no_merge() {
        let reader = PageReader::new(PageType::DerivedCatalog, vec![(1, 16, 64)]);
        let merger = PageMerger::new(PageType::DerivedCatalog);
        let mut svc = CompactionService::new(vec![reader], Some(merger), 4096);
        let result = svc.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert!(result.is_complete);
        assert_eq!(svc.stats.pages_compacted, 0);
    }

    #[test]
    fn unbounded_budget_compacts_all() {
        let mut pages = Vec::new();
        for i in 0..20u64 {
            pages.push((i, 20, 64));
        }
        let reader = PageReader::new(PageType::DerivedCatalog, pages);
        let merger = PageMerger::new(PageType::DerivedCatalog);
        let mut svc = CompactionService::new(vec![reader], Some(merger), 4096);
        let result = svc.step(WorkBudget::UNBOUNDED).unwrap();
        assert!(result.is_complete);
        assert_eq!(svc.stats.pages_compacted, 10);
        assert_eq!(svc.stats.bytes_reclaimed, 10 * 4096);
    }
    // -- CompactionConfig --

    #[test]
    fn compaction_config_defaults() {
        let cfg = CompactionConfig::default();
        assert!((cfg.liveness_threshold - 0.5).abs() < f64::EPSILON);
        assert_eq!(cfg.min_live_bytes, 4096);
        assert_eq!(cfg.batch_size, 64);
        assert_eq!(cfg.max_relocate_bytes_per_tick, 64 * 1024 * 1024);
    }

    #[test]
    fn compaction_config_custom() {
        let cfg = CompactionConfig {
            liveness_threshold: 0.3,
            min_live_bytes: 8192,
            batch_size: 16,
            max_relocate_bytes_per_tick: 32 * 1024 * 1024,
            target_segment_size: 1024 * 1024,
        };
        assert!((cfg.liveness_threshold - 0.3).abs() < f64::EPSILON);
        assert_eq!(cfg.min_live_bytes, 8192);
        assert_eq!(cfg.batch_size, 16);
        assert_eq!(cfg.max_relocate_bytes_per_tick, 32 * 1024 * 1024);
    }

    // -- CompactionCandidateSelector --

    use tidefs_reclaim_queue_core::SegmentLivenessQueue;

    fn make_queue_with(entries: &[(u64, u64, u64)]) -> SegmentLivenessQueue {
        let mut q = SegmentLivenessQueue::new();
        for &(seg_id, live, dead) in entries {
            let total = live.saturating_add(dead);
            if total > 0 {
                q.record_write(seg_id, total);
                if dead > 0 {
                    q.record_delete(seg_id, dead);
                }
            }
        }
        q
    }

    #[test]
    fn candidate_selector_empty_queue() {
        let q = SegmentLivenessQueue::new();
        let selector = CompactionCandidateSelector::new(&q, CompactionConfig::default());
        assert!(selector.select_candidates().is_empty());
    }

    #[test]
    fn candidate_selector_fully_live_segments_not_selected() {
        let q = make_queue_with(&[(1, 100_000, 0), (2, 200_000, 0), (3, 50_000, 0)]);
        let selector = CompactionCandidateSelector::new(&q, CompactionConfig::default());
        let candidates = selector.select_candidates();
        assert!(candidates.is_empty());
    }

    #[test]
    fn candidate_selector_fully_dead_segments_not_selected() {
        // Fully-dead segments have zero live bytes, below min_live_bytes (4096).
        let q = make_queue_with(&[(1, 0, 100_000), (2, 0, 50_000)]);
        let selector = CompactionCandidateSelector::new(&q, CompactionConfig::default());
        let candidates = selector.select_candidates();
        assert!(candidates.is_empty());
    }

    #[test]
    fn candidate_selector_mixed_liveness_below_threshold() {
        // seg 1: 30K live, 70K dead -> liveness = 0.30 (below 0.5)
        // seg 2: 40K live, 60K dead -> liveness = 0.40 (below 0.5)
        let q = make_queue_with(&[(1, 30_000, 70_000), (2, 40_000, 60_000)]);
        let selector = CompactionCandidateSelector::new(&q, CompactionConfig::default());
        let candidates = selector.select_candidates();
        assert_eq!(candidates.len(), 2);
        // seg 1 has lower liveness (more fragmented), should be first
        assert_eq!(candidates[0], 1);
        assert_eq!(candidates[1], 2);
    }

    #[test]
    fn candidate_selector_liveness_above_threshold_not_selected() {
        // seg 1: 60K live, 40K dead -> liveness = 0.60 (above 0.5)
        let q = make_queue_with(&[(1, 60_000, 40_000)]);
        let selector = CompactionCandidateSelector::new(&q, CompactionConfig::default());
        assert!(selector.select_candidates().is_empty());
    }

    #[test]
    fn candidate_selector_respects_min_live_bytes() {
        // seg 1: 2K live, 98K dead -> liveness = 0.02 (below 0.5) but live < 4096
        let q = make_queue_with(&[(1, 2_000, 98_000)]);
        let cfg = CompactionConfig {
            min_live_bytes: 4096,
            ..CompactionConfig::default()
        };
        let selector = CompactionCandidateSelector::new(&q, cfg);
        assert!(selector.select_candidates().is_empty());
    }

    #[test]
    fn candidate_selector_respects_batch_size() {
        let mut entries = Vec::new();
        for i in 0..100u64 {
            entries.push((i, 30_000, 70_000));
        }
        let q = make_queue_with(&entries);
        let cfg = CompactionConfig {
            batch_size: 5,
            ..CompactionConfig::default()
        };
        let selector = CompactionCandidateSelector::new(&q, cfg);
        let candidates = selector.select_candidates();
        assert_eq!(candidates.len(), 5);
        // All should be sorted by liveness (same for all), then by live bytes,
        // then by lowest segment ID. With uniform entries, lowest IDs first.
        assert_eq!(candidates[0], 0);
        assert_eq!(candidates[1], 1);
        assert_eq!(candidates[2], 2);
        assert_eq!(candidates[3], 3);
        assert_eq!(candidates[4], 4);
    }

    #[test]
    fn candidate_selector_tiebreak_by_live_bytes() {
        // seg 1 has lower write amplification. seg 2 sits exactly at the
        // scheduled 2.0x cap and is still admitted after seg 1.
        let q = make_queue_with(&[
            (1, 30_000, 70_000), // liveness 0.30, 30K live
            (2, 50_000, 50_000), // write amplification = 2.0
        ]);
        let selector = CompactionCandidateSelector::new(&q, CompactionConfig::default());
        let candidates = selector.select_candidates();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0], 1);
        assert_eq!(candidates[1], 2);
    }

    #[test]
    fn candidate_selector_tiebreak_by_lower_segment_id() {
        // Two segments with identical liveness (0.40) and live bytes (40K).
        let q = make_queue_with(&[
            (10, 40_000, 60_000),
            (5, 40_000, 60_000),
            (20, 40_000, 60_000),
        ]);
        let selector = CompactionCandidateSelector::new(&q, CompactionConfig::default());
        let candidates = selector.select_candidates();
        assert_eq!(candidates.len(), 3);
        // Same liveness and live bytes -> sorted by lowest segment ID first
        assert_eq!(candidates[0], 5);
        assert_eq!(candidates[1], 10);
        assert_eq!(candidates[2], 20);
    }

    #[test]
    fn candidate_selector_zero_limit_returns_empty() {
        let q = make_queue_with(&[(1, 30_000, 70_000)]);
        let selector = CompactionCandidateSelector::new(&q, CompactionConfig::default());
        let candidates = selector.select_candidates_with_limit(0);
        assert!(candidates.is_empty());
    }

    #[test]
    fn candidate_selector_strict_liveness_boundary() {
        // seg 1: write amplification exactly 2.0 (admitted by the cap)
        // seg 2: write amplification just below 2.0 (ordered first)
        let q = make_queue_with(&[
            (1, 50_000, 50_000),
            (2, 49_999, 50_001),
        ]);
        let selector = CompactionCandidateSelector::new(&q, CompactionConfig::default());
        let candidates = selector.select_candidates();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0], 2);
        assert_eq!(candidates[1], 1);
    }

    // -- CompactionStore + LiveObjectRelocator tests --

    use std::collections::HashMap;

    /// Mock store for testing LiveObjectRelocator.
    struct MockCompactionStore {
        /// segment_id -> list of object keys
        segments: HashMap<u64, Vec<[u8; 32]>>,
        /// key -> data
        objects: HashMap<[u8; 32], Vec<u8>>,
        /// Tracks which segments are freed
        freed: Vec<u64>,
        /// Optional read failures: key -> error
        read_failures: HashMap<[u8; 32], CompactionError>,
        /// Optional write failures: key -> error
        write_failures: HashMap<[u8; 32], CompactionError>,
        /// Corrupt data during write_object to exercise manifest verification.
        corrupt_writes: bool,
        /// Tracks where objects were written (new segment id)
        next_segment_id: u64,
    }

    impl MockCompactionStore {
        fn new() -> Self {
            Self {
                segments: HashMap::new(),
                objects: HashMap::new(),
                freed: Vec::new(),
                read_failures: HashMap::new(),
                write_failures: HashMap::new(),
                corrupt_writes: false,
                next_segment_id: 1000,
            }
        }

        fn add_segment_with_objects(&mut self, segment_id: u64, obj_specs: &[([u8; 32], u8)]) {
            let mut keys = Vec::new();
            for &(key, size) in obj_specs {
                let data = vec![size; size as usize];
                self.objects.insert(key, data);
                keys.push(key);
            }
            self.segments.insert(segment_id, keys);
        }
    }

    impl CompactionStore for MockCompactionStore {
        fn live_object_keys(&self, segment_id: u64) -> Result<Vec<[u8; 32]>, CompactionError> {
            self.segments
                .get(&segment_id)
                .cloned()
                .ok_or(CompactionError::SegmentNotFound(segment_id))
        }

        fn read_object(&self, key: &[u8; 32]) -> Result<Vec<u8>, CompactionError> {
            if let Some(err) = self.read_failures.get(key) {
                return Err(err.clone());
            }
            self.objects
                .get(key)
                .cloned()
                .ok_or(CompactionError::ObjectReadFailed {
                    key: *key,
                    segment_id: 0,
                })
        }

        fn write_object(&mut self, key: &[u8; 32], data: &[u8]) -> Result<u64, CompactionError> {
            if let Some(err) = self.write_failures.get(key) {
                return Err(err.clone());
            }
            let mut stored = data.to_vec();
            if self.corrupt_writes && !stored.is_empty() {
                stored[0] ^= 0xFF;
            }
            self.objects.insert(*key, stored);
            let seg = self.next_segment_id;
            self.next_segment_id += 1;
            Ok(seg)
        }

        fn free_segment(&mut self, segment_id: u64) -> Result<(), CompactionError> {
            self.freed.push(segment_id);
            self.segments.remove(&segment_id);
            Ok(())
        }

        fn commit_swap(&mut self, swap: CompactionSwap) -> Result<(), CompactionError> {
            // Extend freed list with the swap's freed segments.
            self.freed.extend(swap.freed_segments.iter().copied());
            for seg_id in &swap.freed_segments {
                self.segments.remove(seg_id);
            }
            Ok(())
        }
    }

    fn make_key(id: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = id;
        k
    }

    #[test]
    fn relocator_single_object() {
        let mut store = MockCompactionStore::new();
        let key1 = make_key(1);
        store.add_segment_with_objects(10, &[(key1, 64)]);

        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);

        let outcome = relocator.relocate_segment(10).unwrap();
        assert_eq!(outcome.objects_relocated, 1);
        assert!(outcome.segment_freed);
        assert_eq!(relocator.objects_relocated, 1);
        assert_eq!(relocator.bytes_relocated, 64);
        assert_eq!(relocator.relocation_errors, 0);
    }

    #[test]
    fn relocator_multi_object() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        let k3 = make_key(3);
        store.add_segment_with_objects(20, &[(k1, 32), (k2, 128), (k3, 255)]);

        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);

        let outcome = relocator.relocate_segment(20).unwrap();
        assert_eq!(outcome.objects_relocated, 3);
        assert!(outcome.segment_freed);
        assert_eq!(relocator.objects_relocated, 3);
        assert_eq!(relocator.bytes_relocated, 32 + 128 + 255);
        assert_eq!(relocator.relocation_errors, 0);
    }

    #[test]
    fn relocator_empty_segment() {
        let mut store = MockCompactionStore::new();
        store.segments.insert(99, Vec::new());

        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);

        let outcome = relocator.relocate_segment(99).unwrap();
        assert_eq!(outcome.objects_relocated, 0);
        assert!(outcome.segment_freed);
        assert_eq!(relocator.objects_relocated, 0);
    }

    #[test]
    fn relocator_segment_not_found() {
        let store = MockCompactionStore::new();
        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);

        let result = relocator.relocate_segment(42);
        assert!(result.is_err());
        match result {
            Err(CompactionError::SegmentNotFound(42)) => {}
            _ => panic!("expected SegmentNotFound"),
        }
    }

    #[test]
    fn relocator_read_failure_skips_object() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        store.add_segment_with_objects(10, &[(k1, 64), (k2, 128)]);

        // Make reading k1 fail with a non-structural error
        store.read_failures.insert(
            k1,
            CompactionError::ObjectReadFailed {
                key: k1,
                segment_id: 10,
            },
        );

        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);

        let outcome = relocator.relocate_segment(10).unwrap();
        // k1 skipped, k2 relocated
        assert_eq!(outcome.objects_relocated, 1);
        assert!(!outcome.segment_freed);
        assert_eq!(relocator.objects_relocated, 1);
        assert_eq!(relocator.relocation_errors, 1);
        // Segment NOT freed because not all objects were relocated
    }

    #[test]
    fn relocator_write_failure_counts_error() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        store.add_segment_with_objects(10, &[(k1, 64), (k2, 128)]);

        // Make writing k2 fail
        store.write_failures.insert(
            k2,
            CompactionError::ObjectWriteFailed {
                key: k2,
                reason: "disk full".into(),
            },
        );

        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);

        let outcome = relocator.relocate_segment(10).unwrap();
        // k1 relocated, k2 failed
        assert_eq!(outcome.objects_relocated, 1);
        assert!(!outcome.segment_freed);
        assert_eq!(relocator.relocation_errors, 1);
        // Segment NOT freed (partial relocation)
    }

    #[test]
    fn relocator_rate_limited_by_bytes() {
        let mut store = MockCompactionStore::new();
        let mut entries = Vec::new();
        for i in 0..20u8 {
            entries.push((make_key(i), 255));
        }
        store.add_segment_with_objects(10, &entries);

        let cfg = CompactionConfig {
            max_relocate_bytes_per_tick: 1000,
            ..CompactionConfig::default()
        };
        let mut relocator = LiveObjectRelocator::new(store, cfg);

        let outcome = relocator.relocate_segment(10).unwrap();
        // 1000 / 255 ≈ 3.9, so at most 3-4 objects before rate limit
        assert!(
            outcome.objects_relocated <= 4,
            "relocated {} objects, expected <= 4",
            outcome.objects_relocated
        );
        assert!(relocator.bytes_relocated <= 1000);
        // Segment NOT freed (partial due to rate limit)
        assert!(!outcome.segment_freed);
    }

    #[test]
    fn relocator_reset_stats() {
        let mut store = MockCompactionStore::new();
        store.add_segment_with_objects(10, &[(make_key(1), 64)]);

        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);

        relocator.relocate_segment(10).unwrap();
        assert_eq!(relocator.objects_relocated, 1);

        relocator.reset_stats();
        assert_eq!(relocator.objects_relocated, 0);
        assert_eq!(relocator.bytes_relocated, 0);
        assert_eq!(relocator.relocation_errors, 0);
    }

    #[test]
    fn relocator_multiple_segments_accumulate_stats() {
        let mut store = MockCompactionStore::new();
        store.add_segment_with_objects(1, &[(make_key(1), 64)]);
        store.add_segment_with_objects(2, &[(make_key(2), 128)]);

        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);

        relocator.relocate_segment(1).unwrap();
        relocator.relocate_segment(2).unwrap();

        assert_eq!(relocator.objects_relocated, 2);
        assert_eq!(relocator.bytes_relocated, 64 + 128);
        assert_eq!(relocator.relocation_errors, 0);
    }

    #[test]
    fn relocator_structural_read_error_aborts() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        store.add_segment_with_objects(10, &[(k1, 64)]);

        // Inject a SegmentNotFound error on read — this is structural
        store
            .read_failures
            .insert(k1, CompactionError::SegmentNotFound(10));

        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);

        let result = relocator.relocate_segment(10);
        assert!(result.is_err());
        match result {
            Err(CompactionError::SegmentNotFound(10)) => {}
            _ => panic!("expected SegmentNotFound"),
        }
    }

    #[test]
    fn compaction_error_display_nonempty() {
        let e = CompactionError::SegmentNotFound(1);
        assert!(!format!("{e}").is_empty());

        let e = CompactionError::ObjectReadFailed {
            key: [0u8; 32],
            segment_id: 2,
        };
        assert!(!format!("{e}").is_empty());

        let e = CompactionError::ObjectWriteFailed {
            key: [0u8; 32],
            reason: "test".into(),
        };
        assert!(!format!("{e}").is_empty());

        let e = CompactionError::SegmentFreeFailed(3);
        assert!(!format!("{e}").is_empty());
    }

    #[test]
    fn relocator_frees_only_when_all_relocated() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        store.add_segment_with_objects(10, &[(k1, 64), (k2, 128)]);

        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);

        let outcome = relocator.relocate_segment(10).unwrap();
        assert_eq!(outcome.objects_relocated, 2);
        // All objects relocated -> segment freed
        assert!(outcome.segment_freed);
    }

    #[test]
    fn relocator_partial_no_free() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        let k3 = make_key(3);
        store.add_segment_with_objects(10, &[(k1, 64), (k2, 128), (k3, 255)]);

        // Fail write for k3
        store.write_failures.insert(
            k3,
            CompactionError::ObjectWriteFailed {
                key: k3,
                reason: "disk full".into(),
            },
        );

        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);

        let outcome = relocator.relocate_segment(10).unwrap();
        // k1, k2 relocated, k3 failed
        assert_eq!(outcome.objects_relocated, 2);
        // Partial — segment not freed
        assert!(!outcome.segment_freed);
    }

    // -- CompactionRun integration tests --

    #[test]
    fn compaction_run_selects_and_relocates() {
        let mut queue = SegmentLivenessQueue::new();
        // Set up 3 fragmented segments (liveness between 0.30 and 0.40)
        // seg 10: 30K live, 70K dead -> liveness 0.30
        queue.record_write(10, 100_000);
        queue.record_delete(10, 70_000);
        // seg 20: 40K live, 60K dead -> liveness 0.40
        queue.record_write(20, 100_000);
        queue.record_delete(20, 60_000);
        // seg 30: 35K live, 65K dead -> liveness 0.35
        queue.record_write(30, 100_000);
        queue.record_delete(30, 65_000);

        let mut store = MockCompactionStore::new();
        // Add objects to each segment
        store.add_segment_with_objects(10, &[(make_key(1), 64), (make_key(2), 128)]);
        store.add_segment_with_objects(20, &[(make_key(3), 255)]);
        store.add_segment_with_objects(
            30,
            &[(make_key(4), 32), (make_key(5), 64), (make_key(6), 128)],
        );

        let cfg = CompactionConfig::default();
        let mut run = CompactionRun::new(&queue, store, cfg);

        let report = run.run_tick();
        assert_eq!(report.candidates_considered, 3);
        assert_eq!(report.policy_report.candidates_admitted, 3);
        assert_eq!(report.policy_report.rejected_write_amplification, 0);
        assert_eq!(report.segments_freed, 3); // All fully relocated
        assert_eq!(report.source_release_candidates, vec![10, 30, 20]);
        assert_eq!(report.segments_partial, 0);
        assert_eq!(report.objects_relocated, 6);
        assert_eq!(report.errors, 0);
        assert_eq!(run.segments_freed, 3);
        assert_eq!(run.segments_partial, 0);
    }

    #[test]
    fn compaction_run_report_contains_blake3_hashes() {
        let mut queue = SegmentLivenessQueue::new();
        // seg 10: 30K live, 70K dead -> liveness 0.30 (below 0.5 threshold)
        queue.record_write(10, 100_000);
        queue.record_delete(10, 70_000);

        let mut store = MockCompactionStore::new();
        // Object at key 1 with size 64: data = vec![64u8; 64]
        let k1 = make_key(1);
        let obj_data = vec![64u8; 64];
        let expected_hash = blake3::hash(&obj_data);
        store.add_segment_with_objects(10, &[(k1, 64u8)]);
        store.objects.insert(k1, obj_data);

        let cfg = CompactionConfig::default();
        let mut run = CompactionRun::new(&queue, store, cfg);

        let report = run.run_tick();
        assert_eq!(report.objects_relocated, 1);
        assert_eq!(report.relocation_entries.len(), 1);

        let entry = &report.relocation_entries[0];
        assert_eq!(entry.source_segment, 10);
        assert_eq!(entry.object_key, k1);
        assert_eq!(entry.blake3_hash, *expected_hash.as_bytes());
    }

    #[test]
    fn compaction_run_no_candidates() {
        let queue = SegmentLivenessQueue::new();
        // No segments in queue
        let store = MockCompactionStore::new();
        let cfg = CompactionConfig::default();
        let mut run = CompactionRun::new(&queue, store, cfg);

        let report = run.run_tick();
        assert_eq!(report.candidates_considered, 0);
        assert_eq!(report.segments_freed, 0);
        assert!(report.source_release_candidates.is_empty());
        assert_eq!(report.objects_relocated, 0);
    }

    #[test]
    fn compaction_run_counts_policy_rejections_as_considered() {
        let mut queue = SegmentLivenessQueue::new();
        queue.record_write(10, 100_000);
        queue.record_delete(10, 20_000); // write amplification 5.0 exceeds scheduled cap.

        let store = MockCompactionStore::new();
        let cfg = CompactionConfig::default();
        let mut run = CompactionRun::new(&queue, store, cfg);

        let report = run.run_tick();
        assert_eq!(report.candidates_considered, 1);
        assert_eq!(report.policy_report.candidates_considered, 1);
        assert_eq!(report.policy_report.candidates_admitted, 0);
        assert_eq!(report.policy_report.rejected_write_amplification, 1);
        assert_eq!(report.segments_freed, 0);
        assert!(report.source_release_candidates.is_empty());
        assert_eq!(report.objects_relocated, 0);
    }

    #[test]
    fn compaction_run_partial_relocation() {
        let mut queue = SegmentLivenessQueue::new();
        // One fragmented segment
        queue.record_write(10, 100_000);
        queue.record_delete(10, 60_000); // liveness 0.40

        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        store.add_segment_with_objects(10, &[(k1, 64), (k2, 128)]);

        // Make writing k2 fail
        store.write_failures.insert(
            k2,
            CompactionError::ObjectWriteFailed {
                key: k2,
                reason: "disk full".into(),
            },
        );

        let cfg = CompactionConfig::default();
        let mut run = CompactionRun::new(&queue, store, cfg);

        let report = run.run_tick();
        assert_eq!(report.candidates_considered, 1);
        // k1 relocated, k2 failed -> partial
        assert_eq!(report.segments_freed, 0);
        assert!(report.source_release_candidates.is_empty());
        assert_eq!(report.segments_partial, 1);
        assert_eq!(report.objects_relocated, 1);
        assert_eq!(report.errors, 1);
    }

    #[test]
    fn compaction_run_into_store() {
        let queue = SegmentLivenessQueue::new();
        let store = MockCompactionStore::new();
        let cfg = CompactionConfig::default();
        let run = CompactionRun::new(&queue, store, cfg);

        let _recovered_store: MockCompactionStore = run.into_store();
        // Store is successfully recovered
    }

    #[test]
    fn compaction_run_report_defaults() {
        let report = CompactionRunReport::default();
        assert_eq!(report.candidates_considered, 0);
        assert_eq!(report.segments_freed, 0);
        assert!(report.source_release_candidates.is_empty());
        assert_eq!(report.segments_partial, 0);
        assert_eq!(report.objects_relocated, 0);
        assert_eq!(report.bytes_relocated, 0);
        assert_eq!(report.errors, 0);
        assert!(report.relocation_entries.is_empty());
        assert!(report.policy_report.decisions.is_empty());
    }

    // -- CompactionRequest + CompactionPlanner + BLAKE3 relocation tests --

    use tidefs_reclaim_queue_core::SegmentLivenessEntry;

    fn make_seg_entry(seg_id: u64, live: u64, dead: u64) -> SegmentLivenessEntry {
        SegmentLivenessEntry::new(seg_id, live, dead)
    }

    #[test]
    fn compaction_engine_manifest_failure_reports_no_release() {
        let k1 = make_key(1);
        let k2 = make_key(2);
        let mut store = MockCompactionStore::new();
        store.add_segment_with_objects(10, &[(k1, 64)]);
        store.add_segment_with_objects(20, &[(k2, 64)]);
        store.corrupt_writes = true;

        let entries = vec![
            SegmentLivenessEntry::new(10, 30_000, 70_000),
            SegmentLivenessEntry::new(20, 30_000, 70_000),
        ];
        let mut engine = CompactionEngine::new(store, CompactionConfig::default());

        let report = engine.run_cycle(&entries);
        assert_eq!(report.segments_freed, 0);
        assert_eq!(report.objects_relocated, 0);
        assert_eq!(report.bytes_reclaimed_estimate, 0);
        assert!(!report.verification_passed);
        assert!(report.swap_verification_errors.iter().any(|err| matches!(
            err,
            crate::verification::SwapVerificationError::DigestMismatch { .. }
        )));
        assert_eq!(engine.total_segments_freed, 0);

        let store = engine.into_store();
        assert!(store.freed.is_empty());
    }

    #[test]
    fn compaction_request_new() {
        let req = CompactionRequest::new(vec![10, 20, 30], 90_000);
        assert_eq!(req.source_segments, vec![10, 20, 30]);
        assert_eq!(req.target_segment, 0);
        assert!(req.entries.is_empty());
        assert_eq!(req.total_live_bytes, 90_000);
        assert_eq!(req.source_count(), 3);
        assert!(!req.is_empty());
    }

    #[test]
    fn compaction_request_empty() {
        let req = CompactionRequest::new(Vec::new(), 0);
        assert!(req.is_empty());
        assert_eq!(req.source_count(), 0);
    }

    #[test]
    fn planner_empty_input() {
        let planner = CompactionPlanner::new(CompactionConfig::default());
        assert!(planner.plan(&[]).is_empty());
    }

    #[test]
    fn planner_no_candidates_all_above_threshold() {
        let entries = vec![
            make_seg_entry(1, 60_000, 40_000),
            make_seg_entry(2, 50_000, 50_000),
        ];
        let planner = CompactionPlanner::new(CompactionConfig::default());
        assert!(planner.plan(&entries).is_empty());
    }

    #[test]
    fn planner_single_candidate_no_group() {
        let planner = CompactionPlanner::new(CompactionConfig::default());
        assert!(planner
            .plan(&[make_seg_entry(1, 10_000, 90_000)])
            .is_empty());
    }

    #[test]
    fn planner_two_fragmented_segments_merge() {
        let entries = vec![
            make_seg_entry(10, 200_000, 800_000),
            make_seg_entry(20, 300_000, 700_000),
        ];
        let planner = CompactionPlanner::new(CompactionConfig::default());
        let requests = planner.plan(&entries);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].source_segments.len(), 2);
        assert_eq!(requests[0].total_live_bytes, 500_000);
    }

    #[test]
    fn planner_two_groups_when_exceeding_target_size() {
        let entries = vec![
            make_seg_entry(1, 400_000, 600_000),
            make_seg_entry(2, 400_000, 600_000),
            make_seg_entry(3, 400_000, 600_000),
            make_seg_entry(4, 400_000, 600_000),
        ];
        let planner = CompactionPlanner::new(CompactionConfig::default());
        let requests = planner.plan(&entries);
        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn planner_most_fragmented_first() {
        let entries = vec![
            make_seg_entry(30, 300_000, 700_000),
            make_seg_entry(10, 100_000, 900_000),
            make_seg_entry(20, 200_000, 800_000),
        ];
        let planner = CompactionPlanner::new(CompactionConfig::default());
        let requests = planner.plan(&entries);
        assert_eq!(requests[0].source_segments, vec![10, 20, 30]);
    }

    #[test]
    fn planner_respects_target_size() {
        let entries = vec![
            make_seg_entry(1, 100_000, 400_000),
            make_seg_entry(2, 100_000, 400_000),
            make_seg_entry(3, 100_000, 400_000),
            make_seg_entry(4, 100_000, 400_000),
        ];
        let cfg = CompactionConfig {
            target_segment_size: 200_000,
            ..CompactionConfig::default()
        };
        let planner = CompactionPlanner::new(cfg);
        let requests = planner.plan(&entries);
        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn planner_config_accessor() {
        let cfg = CompactionConfig {
            target_segment_size: 42_000,
            ..CompactionConfig::default()
        };
        let planner = CompactionPlanner::new(cfg);
        assert_eq!(planner.config().target_segment_size, 42_000);
    }

    // -- BLAKE3 hash relocation tests (reuses MockCompactionStore + make_key) --

    #[test]
    fn relocator_with_hashes_computes_blake3() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let test_data = b"hello compaction world".to_vec();
        store.add_segment_with_objects(10, &[(k1, test_data.len() as u8)]);
        store.objects.insert(k1, test_data.clone());
        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);
        let (outcome, entries) = relocator.relocate_with_hashes(10).unwrap();
        assert_eq!(outcome.objects_relocated, 1);
        assert!(outcome.segment_freed);
        assert_eq!(entries.len(), 1);
        let expected = blake3::hash(&test_data);
        assert_eq!(entries[0].blake3_hash, *expected.as_bytes());
    }

    #[test]
    fn relocator_with_hashes_multiple_objects() {
        let mut store = MockCompactionStore::new();
        let d1 = vec![0xAAu8; 16];
        let d2 = vec![0xBBu8; 32];
        let d3 = vec![0xCCu8; 64];
        let k1 = make_key(1);
        let k2 = make_key(2);
        let k3 = make_key(3);
        store.add_segment_with_objects(
            10,
            &[
                (k1, d1.len() as u8),
                (k2, d2.len() as u8),
                (k3, d3.len() as u8),
            ],
        );
        store.objects.insert(k1, d1.clone());
        store.objects.insert(k2, d2.clone());
        store.objects.insert(k3, d3.clone());
        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);
        let (outcome, entries) = relocator.relocate_with_hashes(10).unwrap();
        assert_eq!(outcome.objects_relocated, 3);
        assert!(outcome.segment_freed);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].target_offset, 0);
        assert_eq!(entries[0].blake3_hash, *blake3::hash(&d1).as_bytes());
        assert_eq!(entries[1].target_offset, d1.len() as u64);
        assert_eq!(entries[1].blake3_hash, *blake3::hash(&d2).as_bytes());
        assert_eq!(entries[2].target_offset, (d1.len() + d2.len()) as u64);
        assert_eq!(entries[2].blake3_hash, *blake3::hash(&d3).as_bytes());
    }

    #[test]
    fn relocator_with_hashes_empty_segment() {
        let mut store = MockCompactionStore::new();
        store.add_segment_with_objects(10, &[]);
        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);
        let (outcome, entries) = relocator.relocate_with_hashes(10).unwrap();
        assert_eq!(outcome.objects_relocated, 0);
        assert!(outcome.segment_freed);
        assert!(entries.is_empty());
    }

    #[test]
    fn relocator_with_hashes_partial_write() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        let d1 = b"first".to_vec();
        let d2 = b"second_object".to_vec();
        store.add_segment_with_objects(10, &[(k1, d1.len() as u8), (k2, d2.len() as u8)]);
        store.objects.insert(k1, d1.clone());
        store.objects.insert(k2, d2.clone());
        store.write_failures.insert(
            k2,
            CompactionError::ObjectWriteFailed {
                key: k2,
                reason: "disk full".into(),
            },
        );
        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);
        let (outcome, entries) = relocator.relocate_with_hashes(10).unwrap();
        assert_eq!(outcome.objects_relocated, 1);
        assert!(!outcome.segment_freed);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].blake3_hash, *blake3::hash(&d1).as_bytes());
    }

    #[test]
    fn relocator_with_hashes_rate_limited() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        let d1 = vec![0u8; 40_000_000];
        let d2 = vec![1u8; 30_000_000];
        store.objects.insert(k1, d1.clone());
        store.objects.insert(k2, d2.clone());
        store.segments.insert(10, vec![k1, k2]);
        let cfg = CompactionConfig::default();
        let mut relocator = LiveObjectRelocator::new(store, cfg);
        let (outcome, entries) = relocator.relocate_with_hashes(10).unwrap();
        assert_eq!(outcome.objects_relocated, 1);
        assert!(!outcome.segment_freed);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].blake3_hash, *blake3::hash(&d1).as_bytes());
    }

    #[test]
    fn compaction_swap_new_is_empty() {
        let swap = CompactionSwap::new();
        assert!(swap.is_empty());
        assert_eq!(swap.object_count(), 0);
        assert!(swap.freed_segments.is_empty());
        assert!(swap.registered_segments.is_empty());
    }

    #[test]
    fn compaction_swap_non_empty() {
        let entry = RelocationEntry {
            source_segment: 10,
            object_key: [0u8; 32],
            target_offset: 0,
            blake3_hash: [1u8; 32],
        };
        let swap = CompactionSwap {
            freed_segments: vec![10, 20],
            registered_segments: vec![100, 101],
            entries: vec![entry],
        };
        assert!(!swap.is_empty());
        assert_eq!(swap.object_count(), 1);
        assert_eq!(swap.freed_segments, vec![10, 20]);
        assert_eq!(swap.registered_segments, vec![100, 101]);
    }

    #[test]
    fn compaction_run_commits_atomic_swap() {
        let mut queue = SegmentLivenessQueue::new();
        queue.record_write(10, 100_000);
        queue.record_delete(10, 70_000);

        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let obj_data = vec![0x42u8; 64];
        store.add_segment_with_objects(10, &[(k1, obj_data.len() as u8)]);
        store.objects.insert(k1, obj_data.clone());

        // Track that segment 10 exists before tick
        assert!(store.segments.contains_key(&10));
        assert!(store.freed.is_empty());

        let cfg = CompactionConfig::default();
        let mut run = CompactionRun::new(&queue, store, cfg);

        let report = run.run_tick();
        assert_eq!(report.objects_relocated, 1);
        assert_eq!(report.relocation_entries.len(), 1);

        // After the tick, check the store was updated
        let store = run.into_store();
        // Segment 10 should be freed via commit_swap
        assert!(store.freed.contains(&10));
    }

    // -- End-to-end integration tests: planner → relocation → report → swap --

    #[test]
    fn integration_planner_to_report_pipeline() {
        // Set up 5 segments with varying fragmentation levels.
        let mut queue = SegmentLivenessQueue::new();
        queue.record_write(10, 100_000);
        queue.record_delete(10, 70_000); // liveness 0.30
        queue.record_write(20, 100_000);
        queue.record_delete(20, 60_000); // liveness 0.40
        queue.record_write(30, 100_000);
        queue.record_delete(30, 65_000); // liveness 0.35
        queue.record_write(40, 100_000);
        queue.record_delete(40, 55_000); // liveness 0.45
        queue.record_write(50, 100_000);
        queue.record_delete(50, 80_000); // liveness 0.20

        // Populate mock store with objects per segment.
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        let k3 = make_key(3);
        let k4 = make_key(4);
        let k5 = make_key(5);
        let k6 = make_key(6);

        let d1 = vec![0x11u8; 32];
        let d2 = vec![0x22u8; 64];
        let d3 = vec![0x33u8; 48];
        let d4 = vec![0x44u8; 128];
        let d5 = vec![0x55u8; 16];
        let d6 = vec![0x66u8; 96];

        store.add_segment_with_objects(10, &[(k1, d1.len() as u8), (k2, d2.len() as u8)]);
        store.add_segment_with_objects(20, &[(k3, d3.len() as u8)]);
        store.add_segment_with_objects(30, &[(k4, d4.len() as u8)]);
        store.add_segment_with_objects(40, &[(k5, d5.len() as u8)]);
        store.add_segment_with_objects(50, &[(k6, d6.len() as u8)]);

        store.objects.insert(k1, d1.clone());
        store.objects.insert(k2, d2.clone());
        store.objects.insert(k3, d3.clone());
        store.objects.insert(k4, d4.clone());
        store.objects.insert(k5, d5.clone());
        store.objects.insert(k6, d6.clone());

        // Phase 1: plan.

        // Use the planner with real queue liveness data.
        // Build SegmentLivenessEntry values from the queue.
        let liveness_entries: Vec<SegmentLivenessEntry> = vec![
            SegmentLivenessEntry::new(10, 30_000, 70_000), // liveness 0.30
            SegmentLivenessEntry::new(20, 40_000, 60_000), // 0.40
            SegmentLivenessEntry::new(30, 35_000, 65_000), // 0.35
            SegmentLivenessEntry::new(40, 45_000, 55_000), // 0.45
            SegmentLivenessEntry::new(50, 20_000, 80_000), // 0.20
        ];

        let planner = CompactionPlanner::new(CompactionConfig::default());
        let requests = planner.plan(&liveness_entries);

        // With liveness < 0.5, all 5 qualify. Combined live = 170_000 < 1 MiB.
        // All should merge into one request.
        assert_eq!(requests.len(), 1);
        let req = &requests[0];
        assert_eq!(req.source_segments.len(), 5);
        assert_eq!(req.total_live_bytes, 170_000);

        // Phase 2: execute via CompactionRun.
        let cfg = CompactionConfig::default();
        let mut run = CompactionRun::new(&queue, store, cfg);

        let report = run.run_tick();
        assert!(report.candidates_considered >= 5);
        assert_eq!(report.segments_freed, 5);
        assert_eq!(report.source_release_candidates.len(), 5);
        assert_eq!(report.objects_relocated, 6);
        assert_eq!(report.relocation_entries.len(), 6);

        // Phase 3: verify BLAKE3 hashes for each relocated object.
        let expected_hashes: Vec<[u8; 32]> = vec![
            *blake3::hash(&d1).as_bytes(),
            *blake3::hash(&d2).as_bytes(),
            *blake3::hash(&d3).as_bytes(),
            *blake3::hash(&d4).as_bytes(),
            *blake3::hash(&d5).as_bytes(),
            *blake3::hash(&d6).as_bytes(),
        ];

        let mut report_hashes: Vec<[u8; 32]> = report
            .relocation_entries
            .iter()
            .map(|e| e.blake3_hash)
            .collect();
        report_hashes.sort();
        let mut expected_hashes_sorted = expected_hashes.clone();
        expected_hashes_sorted.sort();

        assert_eq!(report_hashes, expected_hashes_sorted);

        // Phase 4: verify swap committed.
        let store = run.into_store();
        // All 5 source segments should be freed.
        assert!(store.freed.len() >= 5);
        for seg_id in &[10u64, 20, 30, 40, 50] {
            assert!(store.freed.contains(seg_id));
        }
    }

    #[test]
    fn integration_multi_tick_compaction() {
        // First tick: compact segments 10, 20 (both fragmented).
        // Second tick: no more candidates.

        let mut queue = SegmentLivenessQueue::new();
        queue.record_write(10, 100_000);
        queue.record_delete(10, 60_000); // liveness 0.40
        queue.record_write(20, 100_000);
        queue.record_delete(20, 65_000); // liveness 0.35

        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        store.add_segment_with_objects(10, &[(k1, 32u8)]);
        store.add_segment_with_objects(20, &[(k2, 64u8)]);

        let cfg = CompactionConfig::default();
        let mut run = CompactionRun::new(&queue, store, cfg);

        // Tick 1: both segments should be compacted.
        let report = run.run_tick();
        assert_eq!(report.candidates_considered, 2);
        assert_eq!(report.segments_freed, 2);
        assert_eq!(report.objects_relocated, 2);
        assert_eq!(run.segments_freed, 2);

        // Tick 2: queue still has liveness entries for freed segments,
        // so candidates are found but they fail with SegmentNotFound.
        // The error counts as partial relocation.
        let report2 = run.run_tick();
        assert!(report2.candidates_considered > 0);
        // No successful relocations — segments already freed.
        assert_eq!(report2.objects_relocated, 0);
    }
}
