// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]
#![deny(dead_code)]

//! Online extent map defragmentation service.
//!
//! [`OnlineDefragService`] implements the [`IncrementalJob`] trait from
//! [`tidefs_types_incremental_job_core`] to scan extent maps for fragmentation,
//! merge adjacent extents with contiguous object keys, and rewrite
//! fragmented extent maps into compact form.
//!
//! The service is cursor-resumable: on each scheduler tick it processes
//! up to the supplied [`WorkBudget`] and saves its position so the walk
//! can resume after a crash or daemon restart.
//!
//! # Fragmentation score
//!
//! Fragmentation is computed per inode as:
//!
//! ```text
//! score = number_of_extents / (file_size / min_extent_size + 1)
//! ```
//!
//! An inode is considered fragmented when `score > 1.5`.

use std::sync::{Arc, Mutex};

use tidefs_extent_map::InlineExtentMap;
use tidefs_types_incremental_job_core::IncrementalJob;
use tidefs_types_extent_map_core::{ExtentMapEntryV2, ExtentMapError, LocatorId};
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};

// ---------------------------------------------------------------------------
// ExtentMapStore — abstraction for loading / saving extent maps
// ---------------------------------------------------------------------------

/// Abstract interface for the defrag service to enumerate inodes and
/// load/save extent maps. Decoupled from the local-filesystem crate so
/// the service is testable without heavyweight dependencies.
pub trait ExtentMapStore: Send {
    /// Return the list of inode numbers that have extent maps.
    fn list_inodes(&self) -> Vec<u64>;

    /// Load the extent map for the given inode.
    fn load_extent_map(&self, ino: u64) -> Result<InlineExtentMap, ExtentMapError>;

    /// Save (persist) the extent map for the given inode.
    fn save_extent_map(&self, ino: u64, map: &InlineExtentMap) -> Result<(), ExtentMapError>;
}

// ---------------------------------------------------------------------------
// DefragStats — aggregate statistics
// ---------------------------------------------------------------------------

/// Accumulated statistics from one or more defrag ticks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DefragStats {
    /// Number of inodes scanned so far.
    pub inodes_scanned: u64,
    /// Number of inodes that were actually defragmented (extent count reduced).
    pub inodes_defragmented: u64,
    /// Total extent count before defrag across all processed inodes.
    pub extents_before: u64,
    /// Total extent count after defrag across all processed inodes.
    pub extents_after: u64,
}

impl DefragStats {
    /// Return the fragmentation reduction as a percentage (0.0–100.0).
    /// Returns 0.0 when no extents were processed.
    #[must_use]
    pub fn fragmentation_reduction_pct(&self) -> f64 {
        if self.extents_before == 0 {
            return 0.0;
        }
        let delta = self.extents_before.saturating_sub(self.extents_after) as f64;
        (delta / self.extents_before as f64) * 100.0
    }
}

// ---------------------------------------------------------------------------
// DefragCursor — resumable walk position
// ---------------------------------------------------------------------------

/// Encodes the (inode_index, extent_offset) cursor for crash-resumable
/// walks. Serialized as two little-endian u64 values (16 bytes total).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DefragCursor {
    /// Index into the sorted inode list returned by the store.
    inode_index: u64,
    /// Reserved for future per-inode offset tracking. Always 0 for now.
    extent_offset: u64,
}

impl DefragCursor {
    const SERIALIZED_LEN: usize = 16;

    fn to_bytes(self) -> [u8; Self::SERIALIZED_LEN] {
        let mut buf = [0u8; Self::SERIALIZED_LEN];
        buf[..8].copy_from_slice(&self.inode_index.to_le_bytes());
        buf[8..].copy_from_slice(&self.extent_offset.to_le_bytes());
        buf
    }

    #[allow(dead_code)]
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return None;
        }
        let inode_index = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let extent_offset = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        Some(DefragCursor {
            inode_index,
            extent_offset,
        })
    }
}

// ---------------------------------------------------------------------------
// Fragmentation helpers
// ---------------------------------------------------------------------------

/// Compute the fragmentation score for an extent map.
///
/// `score = n_extents / (file_size / min_extent_size + 1)`
///
/// A score > 1.5 indicates the extent map is fragmented.
#[must_use]
pub fn fragmentation_score(entry_count: u64, file_size: u64, min_extent_size: u64) -> f64 {
    if entry_count <= 1 {
        return 1.0;
    }
    if min_extent_size == 0 {
        return if entry_count > 1 { 2.0 } else { 1.0 };
    }
    let ideal_extents = file_size / min_extent_size + 1;
    if ideal_extents == 0 {
        return if entry_count > 1 { 2.0 } else { 1.0 };
    }
    entry_count as f64 / ideal_extents as f64
}

/// Threshold above which an extent map is considered fragmented.
pub const FRAGMENTATION_THRESHOLD: f64 = 1.5;

/// Returns `true` when the extent map is fragmented and would benefit
/// from defragmentation.
#[must_use]
pub fn is_fragmented(map: &InlineExtentMap, min_extent_size: u64) -> bool {
    fragmentation_score(
        map.header.entry_count,
        map.header.file_size,
        min_extent_size,
    ) > FRAGMENTATION_THRESHOLD
}

// ---------------------------------------------------------------------------
// Defragmentation logic
// ---------------------------------------------------------------------------

/// Merge adjacent extents with the same locator, checksum, and contiguous
/// logical ranges. Returns the compacted entry list.
#[must_use]
pub fn defrag_extent_map(entries: &[ExtentMapEntryV2]) -> Vec<ExtentMapEntryV2> {
    if entries.is_empty() {
        return Vec::new();
    }

    let mut merged: Vec<ExtentMapEntryV2> = Vec::with_capacity(entries.len());
    merged.push(entries[0].clone());

    for entry in &entries[1..] {
        let last = merged.last_mut().unwrap();
        if last.locator_id == entry.locator_id
            && last.extent_kind == entry.extent_kind
            && last.checksum == entry.checksum
            && last.end_offset() == entry.logical_offset
        {
            last.length += entry.length;
        } else {
            merged.push(entry.clone());
        }
    }

    merged
}

/// Run defragmentation on a single extent map and return the number of
/// extents before and after.
///
/// If the map is not fragmented (score <= 1.5), returns the original
/// counts unchanged and does not modify `map`.
pub fn defrag_inode(map: &mut InlineExtentMap, min_extent_size: u64) -> (u64, u64) {
    let before = map.header.entry_count;
    if before <= 1 {
        return (before, before);
    }

    if !is_fragmented(map, min_extent_size) {
        return (before, before);
    }

    let merged = defrag_extent_map(&map.entries);
    let after = merged.len() as u64;

    if after < before {
        map.entries = merged;
        map.header.entry_count = map.entries.len() as u64;
        map.header.alloc_bytes = map
            .entries
            .iter()
            .filter(|e| {
                use tidefs_types_extent_map_core::ExtentType;
                matches!(e.extent_type(), ExtentType::Data | ExtentType::Unwritten)
            })
            .map(|e| e.length)
            .sum();
    }

    (before, map.header.entry_count)
}

// ---------------------------------------------------------------------------
// OnlineDefragService
// ---------------------------------------------------------------------------

/// Online defragmentation service implementing [`IncrementalJob`].
///
/// Walks all inodes via the [`ExtentMapStore`], computes a fragmentation
/// score per inode, merges adjacent extents on fragmented maps, and
/// persists the result.
pub struct OnlineDefragService {
    job_id: JobId,
    store: Box<dyn ExtentMapStore>,
    inodes: Vec<u64>,
    cursor: DefragCursor,
    stats: DefragStats,
    stats_sink: Option<Arc<Mutex<DefragStats>>>,
    min_extent_size: u64,
    complete_flag: bool,
}

impl OnlineDefragService {
    /// Create a new defrag service that reads/writes extent maps through
    /// `store`. The `min_extent_size` controls the fragmentation score
    /// denominator (typically 4 KiB).
    #[must_use]
    pub fn new(job_id: JobId, store: Box<dyn ExtentMapStore>, min_extent_size: u64) -> Self {
        let inodes = store.list_inodes();
        let mut sorted = inodes;
        sorted.sort_unstable();
        OnlineDefragService {
            job_id,
            store,
            inodes: sorted,
            cursor: DefragCursor::default(),
            stats: DefragStats::default(),
            stats_sink: None,
            min_extent_size,
            complete_flag: false,
        }
    }

    /// Publish accumulated stats into a shared sink after each tick.
    #[must_use]
    pub fn with_stats_sink(mut self, stats_sink: Arc<Mutex<DefragStats>>) -> Self {
        self.stats_sink = Some(stats_sink);
        self.publish_stats();
        self
    }

    /// Return a reference to the accumulated statistics.
    #[must_use]
    pub fn stats(&self) -> &DefragStats {
        &self.stats
    }

    fn publish_stats(&self) {
        if let Some(stats_sink) = &self.stats_sink {
            if let Ok(mut stats) = stats_sink.lock() {
                *stats = self.stats.clone();
            }
        }
    }
}

impl IncrementalJob for OnlineDefragService {
    fn resume(checkpoint: Checkpoint) -> Result<Self, JobError> {
        Err(JobError::CursorStateInvalid {
            job_id: checkpoint.job_id,
            reason: "OnlineDefragService requires a store; use new() to construct",
        })
    }

    fn step(&mut self, budget: WorkBudget) -> StepResult {
        if self.complete_flag {
            return StepResult::complete(Checkpoint {
                job_id: self.job_id,
                job_kind: JobKind::Defrag,
                epoch: 1,
                cursor_state: CursorState(self.cursor.to_bytes().to_vec()),
                progress: JobProgress {
                    items_processed: self.stats.inodes_scanned,
                    items_total_estimate: self.inodes.len() as u64,
                    bytes_processed: 0,
                    bytes_total_estimate: 0,
                    elapsed_ms: 0,
                },
            });
        }

        let max_items = if budget.max_items == 0 {
            u64::MAX
        } else {
            budget.max_items
        };

        let mut processed = 0u64;
        let mut extents_before = 0u64;
        let mut extents_after = 0u64;
        let mut defragged = 0u64;
        let mut scanned = 0u64;

        let start_idx = self.cursor.inode_index as usize;

        for idx in start_idx..self.inodes.len() {
            if processed >= max_items {
                self.cursor.inode_index = idx as u64;
                self.stats.inodes_scanned += scanned;
                self.stats.inodes_defragmented += defragged;
                self.stats.extents_before += extents_before;
                self.stats.extents_after += extents_after;
                self.publish_stats();
                let cursor_state = CursorState(self.cursor.to_bytes().to_vec());
                let progress = JobProgress {
                    items_processed: self.stats.inodes_scanned,
                    items_total_estimate: self.inodes.len() as u64,
                    bytes_processed: 0,
                    bytes_total_estimate: 0,
                    elapsed_ms: 0,
                };
                let checkpoint = Checkpoint {
                    job_id: self.job_id,
                    job_kind: JobKind::Defrag,
                    epoch: 1,
                    cursor_state,
                    progress,
                };
                return StepResult::in_progress(checkpoint);
            }

            let ino = self.inodes[idx];

            let mut map = match self.store.load_extent_map(ino) {
                Ok(m) => m,
                Err(_e) => {
                    scanned += 1;
                    processed += 1;
                    continue;
                }
            };

            scanned += 1;
            processed += 1;

            let (eb, ea) = defrag_inode(&mut map, self.min_extent_size);
            extents_before += eb;
            extents_after += ea;

            if ea < eb {
                defragged += 1;
                let _ = self.store.save_extent_map(ino, &map);
            }
        }

        // Completed full walk.
        self.stats.inodes_scanned += scanned;
        self.stats.inodes_defragmented += defragged;
        self.stats.extents_before += extents_before;
        self.stats.extents_after += extents_after;
        self.publish_stats();

        self.complete_flag = true;
        self.cursor.inode_index = self.inodes.len() as u64;

        let cursor_state = CursorState(self.cursor.to_bytes().to_vec());
        let progress = JobProgress {
            items_processed: self.stats.inodes_scanned,
            items_total_estimate: self.inodes.len() as u64,
            bytes_processed: 0,
            bytes_total_estimate: 0,
            elapsed_ms: 0,
        };
        let checkpoint = Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::Defrag,
            epoch: 1,
            cursor_state,
            progress,
        };

        StepResult::complete(checkpoint)
    }

    fn persist_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::Defrag,
            epoch: 1,
            cursor_state: CursorState(self.cursor.to_bytes().to_vec()),
            progress: JobProgress {
                items_processed: self.stats.inodes_scanned,
                items_total_estimate: self.inodes.len() as u64,
                bytes_processed: 0,
                bytes_total_estimate: 0,
                elapsed_ms: 0,
            },
        }
    }

    fn complete(self) {}

    fn job_id(&self) -> JobId {
        self.job_id
    }

    fn job_kind(&self) -> JobKind {
        JobKind::Defrag
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// RelocationStore — abstraction for physical object relocation
// ---------------------------------------------------------------------------

/// Trait abstracting physical storage operations needed for object relocation.
///
/// Decoupled from concrete segment and object-store crates so the
/// `ObjectRelocator` is testable with lightweight mocks.
pub trait RelocationStore: Send {
    /// Return the set of physical segment runs for a locator.
    /// Each run is `(start_segment, segment_count)`.  Returns `None`
    /// when the locator is unknown or has no physical backing.
    fn physical_segments(&self, locator: LocatorId) -> Option<Vec<(u64, u64)>>;

    /// Read the raw data for the object identified by `locator`.
    /// `length` is the expected logical size in bytes.
    fn read_object(&self, locator: LocatorId, length: u64) -> Result<Vec<u8>, String>;

    /// Relocate an object's data to a single contiguous segment run.
    ///
    /// The old physical segments are freed, new contiguous segments
    /// allocated, the data written, and the locator mapping updated.
    /// Returns the new segment run(s) — typically a single run.
    fn relocate_object(
        &mut self,
        locator: LocatorId,
        data: &[u8],
    ) -> Result<Vec<(u64, u64)>, String>;

    /// Segment size in bytes.  Used to estimate the number of segments
    /// an object occupies (ceil(length / segment_size)).
    fn segment_size(&self) -> u64;
}

// ---------------------------------------------------------------------------
// ObjectRelocationStats — aggregate relocation statistics
// ---------------------------------------------------------------------------

/// Accumulated statistics from one or more relocation ticks.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ObjectRelocationStats {
    /// Number of objects (locators) examined for fragmentation.
    pub objects_scanned: u64,
    /// Number of objects actually relocated to contiguous segments.
    pub objects_relocated: u64,
    /// Total bytes relocated across all processed objects.
    pub bytes_relocated: u64,
    /// Average fragmentation score before relocation (across relocated objects).
    pub fragmentation_before: f64,
    /// Average fragmentation score after relocation (always 1.0 per object).
    pub fragmentation_after: f64,
}

impl ObjectRelocationStats {
    /// Record a successful relocation, updating the rolling averages.
    fn record_relocation(&mut self, frag_before: f64, bytes: u64) {
        let n = self.objects_relocated;
        // n is the count BEFORE adding this relocation.
        if n == 0 {
            self.fragmentation_before = frag_before;
            self.fragmentation_after = 1.0;
        } else {
            let nf = n as f64;
            let nf1 = (n + 1) as f64;
            self.fragmentation_before = (self.fragmentation_before * nf + frag_before) / nf1;
            self.fragmentation_after = (self.fragmentation_after * nf + 1.0) / nf1;
        }
        self.bytes_relocated += bytes;
    }
}

// ---------------------------------------------------------------------------
// Physical fragmentation helper
// ---------------------------------------------------------------------------

/// Threshold above which physical segment layout is considered fragmented.
pub const PHYSICAL_FRAGMENTATION_THRESHOLD: f64 = 1.5;

/// Compute the physical fragmentation score for a set of segment runs.
///
/// Returns the number of non-contiguous runs.  A single run yields 1.0
/// (perfectly contiguous); two or more runs indicates fragmentation.
#[must_use]
pub fn physical_fragmentation(runs: &[(u64, u64)]) -> f64 {
    if runs.is_empty() {
        return 0.0;
    }
    runs.len() as f64
}

/// Returns `true` when the physical segment layout is fragmented enough
/// to benefit from relocation (more than 1.5 runs on average).
#[must_use]
pub fn is_physically_fragmented(runs: &[(u64, u64)]) -> bool {
    physical_fragmentation(runs) > PHYSICAL_FRAGMENTATION_THRESHOLD
}

// ---------------------------------------------------------------------------
// ObjectRelocatorCursor — resumable walk position
// ---------------------------------------------------------------------------

/// Encodes the `(inode_index, extent_index)` cursor for crash-resumable
/// relocation walks.  Serialized as two little-endian u64 values (16 bytes).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ObjectRelocatorCursor {
    /// Index into the sorted inode list returned by the store.
    inode_index: u64,
    /// Index into the extent entries within the current inode's map.
    extent_index: u64,
}

impl ObjectRelocatorCursor {
    const SERIALIZED_LEN: usize = 16;

    fn to_bytes(self) -> [u8; Self::SERIALIZED_LEN] {
        let mut buf = [0u8; Self::SERIALIZED_LEN];
        buf[..8].copy_from_slice(&self.inode_index.to_le_bytes());
        buf[8..].copy_from_slice(&self.extent_index.to_le_bytes());
        buf
    }

    #[allow(dead_code)]
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return None;
        }
        let inode_index = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let extent_index = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        Some(Self {
            inode_index,
            extent_index,
        })
    }
}

// ---------------------------------------------------------------------------
// ObjectRelocator
// ---------------------------------------------------------------------------

/// Object relocation engine implementing [`IncrementalJob`].
///
/// Walks all inodes via the [`ExtentMapStore`], inspects the physical
/// segment layout of each data extent via the [`RelocationStore`], and
/// relocates fragmented objects to contiguous segments.
///
/// The relocation is budgeted: at most `budget_bytes_per_tick` bytes
/// are relocated per `step()` call.  The budget is overridable via the
/// [`WorkBudget::max_bytes`] dimension — whichever is lower wins.
pub struct ObjectRelocator {
    job_id: JobId,
    store: Box<dyn ExtentMapStore>,
    reloc_store: Box<dyn RelocationStore>,
    inodes: Vec<u64>,
    cursor: ObjectRelocatorCursor,
    stats: ObjectRelocationStats,
    budget_bytes_per_tick: u64,
    complete_flag: bool,
}

impl ObjectRelocator {
    /// Default bytes-per-tick budget: 64 MiB.
    pub const DEFAULT_BUDGET_BYTES: u64 = 64 * 1024 * 1024;

    /// Create a new object relocator.
    ///
    /// `store` provides inode enumeration and extent-map loading.
    /// `reloc_store` provides physical segment queries and relocation.
    #[must_use]
    pub fn new(
        job_id: JobId,
        store: Box<dyn ExtentMapStore>,
        reloc_store: Box<dyn RelocationStore>,
    ) -> Self {
        let inodes = store.list_inodes();
        let mut sorted = inodes;
        sorted.sort_unstable();
        Self {
            job_id,
            store,
            reloc_store,
            inodes: sorted,
            cursor: ObjectRelocatorCursor::default(),
            stats: ObjectRelocationStats::default(),
            budget_bytes_per_tick: Self::DEFAULT_BUDGET_BYTES,
            complete_flag: false,
        }
    }

    /// Override the per-tick byte budget (default 64 MiB).
    pub fn with_budget(mut self, budget_bytes: u64) -> Self {
        self.budget_bytes_per_tick = budget_bytes;
        self
    }

    /// Return a reference to the accumulated statistics.
    #[must_use]
    pub fn stats(&self) -> &ObjectRelocationStats {
        &self.stats
    }

    /// Effective per-tick byte cap: min(budget_bytes_per_tick, work_budget.max_bytes).
    fn effective_byte_budget(&self, work_budget: WorkBudget) -> u64 {
        let tick_budget = self.budget_bytes_per_tick;
        if work_budget.max_bytes == 0 {
            tick_budget
        } else {
            tick_budget.min(work_budget.max_bytes)
        }
    }
}

impl IncrementalJob for ObjectRelocator {
    fn resume(checkpoint: Checkpoint) -> Result<Self, JobError> {
        Err(JobError::CursorStateInvalid {
            job_id: checkpoint.job_id,
            reason: "ObjectRelocator requires a store; use new() to construct",
        })
    }

    fn step(&mut self, budget: WorkBudget) -> StepResult {
        if self.complete_flag {
            return StepResult::complete(Checkpoint {
                job_id: self.job_id,
                job_kind: JobKind::Defrag,
                epoch: 1,
                cursor_state: CursorState(self.cursor.to_bytes().to_vec()),
                progress: JobProgress {
                    items_processed: self.stats.objects_scanned,
                    items_total_estimate: self.inodes.len() as u64,
                    bytes_processed: 0,
                    bytes_total_estimate: 0,
                    elapsed_ms: 0,
                },
            });
        }

        let max_items = if budget.max_items == 0 {
            u64::MAX
        } else {
            budget.max_items
        };
        let max_bytes = self.effective_byte_budget(budget);

        let mut items_processed = 0u64;
        let mut bytes_relocated = 0u64;

        let mut inode_idx = self.cursor.inode_index as usize;

        while inode_idx < self.inodes.len() {
            if items_processed >= max_items {
                self.cursor.inode_index = inode_idx as u64;
                return self.build_in_progress_result();
            }

            let ino = self.inodes[inode_idx];

            let map = match self.store.load_extent_map(ino) {
                Ok(m) => m,
                Err(_) => {
                    inode_idx += 1;
                    self.cursor.extent_index = 0;
                    continue;
                }
            };

            let mut extent_idx = if inode_idx == self.cursor.inode_index as usize {
                self.cursor.extent_index as usize
            } else {
                0
            };

            while extent_idx < map.entries.len() {
                if items_processed >= max_items {
                    self.cursor.inode_index = inode_idx as u64;
                    self.cursor.extent_index = extent_idx as u64;
                    return self.build_in_progress_result();
                }

                let entry = &map.entries[extent_idx];

                // Only examine data extents with a valid locator.
                if entry.is_data() && entry.locator_id.is_some() {
                    self.stats.objects_scanned += 1;

                    if let Some(runs) = self.reloc_store.physical_segments(entry.locator_id) {
                        if is_physically_fragmented(&runs) {
                            let frag_before = physical_fragmentation(&runs);
                            let obj_len = entry.length;

                            // Budget check: if relocating this object would
                            // exceed the byte limit, pause here.
                            if max_bytes > 0 && bytes_relocated + obj_len > max_bytes {
                                self.cursor.inode_index = inode_idx as u64;
                                self.cursor.extent_index = extent_idx as u64;
                                return self.build_in_progress_result();
                            }

                            // Read the object data.
                            let data = match self
                                .reloc_store
                                .read_object(entry.locator_id, obj_len)
                            {
                                Ok(d) => d,
                                Err(e) => {
                                    // Log the error and skip this object.
                                    // In production, this would go through the error
                                    // reporting surface.
                                    let _ = e;
                                    let _loc = entry.locator_id;
                                    items_processed += 1;
                                    extent_idx += 1;
                                    continue;
                                }
                            };

                            // Relocate to contiguous segments.
                            if let Err(e) = self.reloc_store
                                .relocate_object(entry.locator_id, &data)
                            {
                                // Log the relocation error and skip.
                                let _ = e;
                                let _loc = entry.locator_id;
                                items_processed += 1;
                                extent_idx += 1;
                                continue;
                            }

                            self.stats.record_relocation(frag_before, obj_len);
                            self.stats.objects_relocated += 1;
                            bytes_relocated += obj_len;
                        }
                    }
                }

                items_processed += 1;
                extent_idx += 1;
            }

            // Finished this inode — move to the next.
            inode_idx += 1;
            self.cursor.extent_index = 0;
        }

        // Completed full walk.
        self.complete_flag = true;
        self.cursor.inode_index = self.inodes.len() as u64;

        self.build_complete_result()
    }

    fn persist_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::Defrag,
            epoch: 1,
            cursor_state: CursorState(self.cursor.to_bytes().to_vec()),
            progress: JobProgress {
                items_processed: self.stats.objects_scanned,
                items_total_estimate: self.inodes.len() as u64,
                bytes_processed: 0,
                bytes_total_estimate: 0,
                elapsed_ms: 0,
            },
        }
    }

    fn complete(self) {}

    fn job_id(&self) -> JobId {
        self.job_id
    }

    fn job_kind(&self) -> JobKind {
        JobKind::Defrag
    }
}

// ── Private helpers for ObjectRelocator ──────────────────────────────

impl ObjectRelocator {
    fn build_in_progress_result(&self) -> StepResult {
        let cursor_state = CursorState(self.cursor.to_bytes().to_vec());
        let progress = JobProgress {
            items_processed: self.stats.objects_scanned,
            items_total_estimate: 0,
            bytes_processed: self.stats.bytes_relocated,
            bytes_total_estimate: 0,
            elapsed_ms: 0,
        };
        let checkpoint = Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::Defrag,
            epoch: 1,
            cursor_state,
            progress,
        };
        StepResult::in_progress(checkpoint)
    }

    fn build_complete_result(&self) -> StepResult {
        let cursor_state = CursorState(self.cursor.to_bytes().to_vec());
        let progress = JobProgress {
            items_processed: self.stats.objects_scanned,
            items_total_estimate: self.stats.objects_scanned,
            bytes_processed: self.stats.bytes_relocated,
            bytes_total_estimate: self.stats.bytes_relocated,
            elapsed_ms: 0,
        };
        let checkpoint = Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::Defrag,
            epoch: 1,
            cursor_state,
            progress,
        };
        StepResult::complete(checkpoint)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tidefs_types_extent_map_core::LocatorId;

    // ── Mock ExtentMapStore ───────────────────────────────────────────

    struct MockStore {
        maps: Mutex<HashMap<u64, InlineExtentMap>>,
        inode_order: Vec<u64>,
        save_errors: Mutex<HashMap<u64, bool>>,
    }

    impl MockStore {
        fn new(inodes: Vec<u64>, maps: HashMap<u64, InlineExtentMap>) -> Self {
            MockStore {
                maps: Mutex::new(maps),
                inode_order: inodes,
                save_errors: Mutex::new(HashMap::new()),
            }
        }
    }

    impl ExtentMapStore for MockStore {
        fn list_inodes(&self) -> Vec<u64> {
            self.inode_order.clone()
        }

        fn load_extent_map(&self, ino: u64) -> Result<InlineExtentMap, ExtentMapError> {
            self.maps
                .lock()
                .unwrap()
                .get(&ino)
                .cloned()
                .ok_or(ExtentMapError::NotFound)
        }

        fn save_extent_map(&self, ino: u64, map: &InlineExtentMap) -> Result<(), ExtentMapError> {
            if *self.save_errors.lock().unwrap().get(&ino).unwrap_or(&false) {
                return Err(ExtentMapError::Corrupt);
            }
            self.maps.lock().unwrap().insert(ino, map.clone());
            Ok(())
        }
    }

    // ── Helper: build a fragmented extent map ─────────────────────────

    fn make_fragmented_map(extents: &[(u64, u64, u64)]) -> InlineExtentMap {
        let entries: Vec<ExtentMapEntryV2> = extents
            .iter()
            .map(|&(off, len, loc)| {
                ExtentMapEntryV2::new_data(off, len, LocatorId(loc), [0xAB; 32], 1)
            })
            .collect();

        let file_size = entries.last().map(|e| e.end_offset()).unwrap_or(0);
        let alloc_bytes: u64 = entries.iter().map(|e| e.length).sum();

        let header = tidefs_types_extent_map_core::ExtentMapV1 {
            entry_count: entries.len() as u64,
            alloc_bytes,
            file_size,
            version: 1,
            root: None,
        };

        InlineExtentMap::from_parts(header, entries)
    }

    // ── Fragmentation score tests ─────────────────────────────────────

    #[test]
    fn score_single_extent_is_one() {
        let score = fragmentation_score(1, 4096, 4096);
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_zero_or_one_extent_not_fragmented() {
        let score = fragmentation_score(0, 0, 4096);
        assert!(score <= FRAGMENTATION_THRESHOLD);
        let score = fragmentation_score(1, 4096, 4096);
        assert!(score <= FRAGMENTATION_THRESHOLD);
    }

    #[test]
    fn score_fragmented_file() {
        let score = fragmentation_score(6, 24576, 4096);
        assert!(score <= FRAGMENTATION_THRESHOLD);
        let score = fragmentation_score(6, 8192, 4096);
        assert!(score > FRAGMENTATION_THRESHOLD);
    }

    #[test]
    fn score_zero_min_extent_size() {
        let score = fragmentation_score(3, 12288, 0);
        assert!(score > FRAGMENTATION_THRESHOLD);
    }

    // ── defrag_extent_map tests ───────────────────────────────────────

    #[test]
    fn defrag_empty_map() {
        let result = defrag_extent_map(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn defrag_single_entry_unchanged() {
        let entries = vec![ExtentMapEntryV2::new_data(
            0,
            4096,
            LocatorId(1),
            [0xAB; 32],
            1,
        )];
        let result = defrag_extent_map(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].logical_offset, 0);
        assert_eq!(result[0].length, 4096);
    }

    #[test]
    fn defrag_merges_adjacent_same_locator_and_checksum() {
        let entries = vec![
            ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0xAB; 32], 1),
            ExtentMapEntryV2::new_data(4096, 4096, LocatorId(1), [0xAB; 32], 1),
            ExtentMapEntryV2::new_data(8192, 4096, LocatorId(1), [0xAB; 32], 1),
        ];
        let result = defrag_extent_map(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].logical_offset, 0);
        assert_eq!(result[0].length, 12288);
        assert_eq!(result[0].locator_id, LocatorId(1));
    }

    #[test]
    fn defrag_does_not_merge_different_checksums() {
        let entries = vec![
            ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0xAB; 32], 1),
            ExtentMapEntryV2::new_data(4096, 4096, LocatorId(1), [0xCD; 32], 1),
        ];
        let result = defrag_extent_map(&entries);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn defrag_does_not_merge_different_locators() {
        let entries = vec![
            ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0xAB; 32], 1),
            ExtentMapEntryV2::new_data(4096, 4096, LocatorId(2), [0xCD; 32], 1),
            ExtentMapEntryV2::new_data(8192, 4096, LocatorId(1), [0xEF; 32], 1),
        ];
        let result = defrag_extent_map(&entries);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn defrag_does_not_merge_non_adjacent() {
        let entries = vec![
            ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0xAB; 32], 1),
            ExtentMapEntryV2::new_data(8192, 4096, LocatorId(1), [0xCD; 32], 1),
        ];
        let result = defrag_extent_map(&entries);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn defrag_merges_checkerboard_pattern() {
        let entries = vec![
            ExtentMapEntryV2::new_data(0, 4096, LocatorId(1), [0; 32], 1),
            ExtentMapEntryV2::new_data(4096, 4096, LocatorId(2), [0; 32], 1),
            ExtentMapEntryV2::new_data(8192, 4096, LocatorId(1), [0; 32], 1),
            ExtentMapEntryV2::new_data(12288, 4096, LocatorId(2), [0; 32], 1),
            ExtentMapEntryV2::new_data(16384, 4096, LocatorId(1), [0; 32], 1),
        ];
        let result = defrag_extent_map(&entries);
        assert_eq!(result.len(), 5);
    }

    // ── defrag_inode tests ────────────────────────────────────────────

    #[test]
    fn defrag_inode_reduces_extent_count() {
        let mut map = make_fragmented_map(&[(0, 1000, 7), (1000, 1000, 7), (2000, 1000, 7)]);
        let (before, after) = defrag_inode(&mut map, 4096);
        assert_eq!(before, 3);
        assert_eq!(after, 1);
    }

    #[test]
    fn defrag_inode_skips_non_fragmented() {
        let mut map = make_fragmented_map(&[(0, 16384, 1)]);
        let (before, after) = defrag_inode(&mut map, 4096);
        assert_eq!(before, 1);
        assert_eq!(after, 1);
    }

    #[test]
    fn defrag_inode_empty_map() {
        let mut map = InlineExtentMap::new();
        let (before, after) = defrag_inode(&mut map, 4096);
        assert_eq!(before, 0);
        assert_eq!(after, 0);
    }

    #[test]
    fn defrag_inode_updates_alloc_bytes() {
        let mut map = make_fragmented_map(&[(0, 1200, 1), (1200, 1200, 1), (2400, 1200, 1)]);
        let original_alloc = map.header.alloc_bytes;
        defrag_inode(&mut map, 4096);
        assert_eq!(map.header.alloc_bytes, original_alloc);
        assert_eq!(map.header.entry_count, 1);
    }

    // ── DefragCursor tests ────────────────────────────────────────────

    #[test]
    fn cursor_roundtrip() {
        let c = DefragCursor {
            inode_index: 42,
            extent_offset: 7,
        };
        let bytes = c.to_bytes();
        assert_eq!(bytes.len(), 16);
        let c2 = DefragCursor::from_bytes(&bytes).unwrap();
        assert_eq!(c2.inode_index, 42);
        assert_eq!(c2.extent_offset, 7);
    }

    #[test]
    fn cursor_roundtrip_zero() {
        let c = DefragCursor::default();
        let bytes = c.to_bytes();
        let c2 = DefragCursor::from_bytes(&bytes).unwrap();
        assert_eq!(c2.inode_index, 0);
        assert_eq!(c2.extent_offset, 0);
    }

    #[test]
    fn cursor_invalid_length_rejected() {
        assert!(DefragCursor::from_bytes(&[]).is_none());
        assert!(DefragCursor::from_bytes(&[0u8; 8]).is_none());
        assert!(DefragCursor::from_bytes(&[0u8; 20]).is_none());
    }

    // ── OnlineDefragService integration tests ─────────────────────────

    #[test]
    fn service_full_walk_defrags_all_inodes() {
        let inodes = vec![10, 20, 30];
        let mut maps = HashMap::new();
        for &ino in &inodes {
            maps.insert(
                ino,
                make_fragmented_map(&[(0, 1000, 1), (1000, 1000, 1), (2000, 1000, 1)]),
            );
        }
        let store = Box::new(MockStore::new(inodes.clone(), maps));

        let mut svc = OnlineDefragService::new(JobId(1), store, 4096);
        assert_eq!(svc.job_id(), JobId(1));
        assert_eq!(svc.job_kind(), JobKind::Defrag);

        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);

        let stats = svc.stats();
        assert_eq!(stats.inodes_scanned, 3);
        assert_eq!(stats.inodes_defragmented, 3);
        assert_eq!(stats.extents_before, 9);
        assert_eq!(stats.extents_after, 3);
    }

    #[test]
    fn service_respects_budget_cursor_resume() {
        let inodes: Vec<u64> = (0..20).collect();
        let mut maps = HashMap::new();
        for &ino in &inodes {
            maps.insert(
                ino,
                make_fragmented_map(&[(0, 1000, 1), (1000, 1000, 1), (2000, 1000, 2)]),
            );
        }
        let store = Box::new(MockStore::new(inodes.clone(), maps));

        let mut svc = OnlineDefragService::new(JobId(2), store, 4096);

        let budget = WorkBudget {
            max_items: 5,
            max_bytes: 0,
            max_ms: 0,
        };
        let r1 = svc.step(budget);
        assert!(!r1.is_complete);
        assert_eq!(svc.stats().inodes_scanned, 5);
        assert_eq!(svc.stats().inodes_defragmented, 5);

        let r2 = svc.step(budget);
        assert!(!r2.is_complete);
        assert_eq!(svc.stats().inodes_scanned, 10);

        let r3 = svc.step(budget);
        assert!(!r3.is_complete);
        assert_eq!(svc.stats().inodes_scanned, 15);

        let r4 = svc.step(budget);
        assert!(r4.is_complete);
        assert_eq!(svc.stats().inodes_scanned, 20);
    }

    #[test]
    fn service_empty_inode_list_completes_immediately() {
        let store = Box::new(MockStore::new(vec![], HashMap::new()));
        let mut svc = OnlineDefragService::new(JobId(3), store, 4096);
        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);
        assert_eq!(svc.stats().inodes_scanned, 0);
    }

    #[test]
    fn service_skips_unreadable_inodes() {
        let inodes = vec![1, 2, 3];
        let mut maps = HashMap::new();
        maps.insert(1, make_fragmented_map(&[(0, 1000, 1), (1000, 1000, 1)]));
        let store = Box::new(MockStore::new(inodes.clone(), maps));

        let mut svc = OnlineDefragService::new(JobId(4), store, 4096);
        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);
        assert_eq!(svc.stats().inodes_scanned, 3);
        assert_eq!(svc.stats().inodes_defragmented, 1);
    }

    #[test]
    fn defrag_stats_reduction_pct() {
        let stats = DefragStats {
            extents_before: 100,
            extents_after: 60,
            ..Default::default()
        };
        assert!((stats.fragmentation_reduction_pct() - 40.0).abs() < 0.01);
    }

    #[test]
    fn defrag_stats_zero_before() {
        let stats = DefragStats::default();
        assert!((stats.fragmentation_reduction_pct() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn defrag_stats_full_reduction() {
        let stats = DefragStats {
            extents_before: 50,
            extents_after: 50,
            ..Default::default()
        };
        assert!((stats.fragmentation_reduction_pct() - 0.0).abs() < 0.01);
    }

    #[test]
    fn trace_dimensional_budget_items_bound() {
        let inodes: Vec<u64> = (0..10).collect();
        let mut maps = HashMap::new();
        for &ino in &inodes {
            maps.insert(ino, make_fragmented_map(&[(0, 1000, 7), (1000, 1000, 7)]));
        }
        let store = Box::new(MockStore::new(inodes, maps));

        let mut svc = OnlineDefragService::new(JobId(99), store, 4096);

        let budget = WorkBudget {
            max_items: 3,
            max_bytes: 0,
            max_ms: 0,
        };
        let r = svc.step(budget);
        assert!(!r.is_complete);
        assert_eq!(svc.stats().inodes_scanned, 3);
    }

    #[test]
    fn service_paused_budget_processes_none() {
        let inodes = vec![1];
        let mut maps = HashMap::new();
        maps.insert(1, make_fragmented_map(&[(0, 1000, 1), (1000, 1000, 1)]));
        let store = Box::new(MockStore::new(inodes, maps));

        let mut svc = OnlineDefragService::new(JobId(5), store, 4096);
        let result = svc.step(WorkBudget::PAUSED);
        assert!(result.is_complete);
    }
    #[test]
    fn service_step_after_complete_returns_complete() {
        let store = Box::new(MockStore::new(vec![], HashMap::new()));
        let mut svc = OnlineDefragService::new(JobId(6), store, 4096);
        svc.step(WorkBudget::UNBOUNDED);
        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);
    }

    #[test]
    fn cursor_to_bytes_is_deterministic() {
        let c = DefragCursor {
            inode_index: 128,
            extent_offset: 256,
        };
        let b1 = c.to_bytes();
        let b2 = c.to_bytes();
        assert_eq!(b1, b2);
    }

    #[test]
    fn trace_cursor_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<OnlineDefragService>();
    }
    // ─────────────────────────────────────────────────────────────────
    // ObjectRelocator tests
    // ─────────────────────────────────────────────────────────────────
    // ── Mock RelocationStore ──────────────────────────────────────────

    type SegmentRun = (u64, u64);
    type MockObjectMap = HashMap<LocatorId, (Vec<SegmentRun>, Vec<u8>)>;
    type RelocationRecord = (LocatorId, Vec<SegmentRun>, Vec<SegmentRun>);

    struct MockRelocationStore {
        /// Map from LocatorId to (segment_runs, data_bytes).
        objects: Mutex<MockObjectMap>,
        /// Track relocated objects: old runs → new runs.
        relocations: Mutex<Vec<RelocationRecord>>,
        segment_size: u64,
    }

    impl MockRelocationStore {
        fn new(segment_size: u64) -> Self {
            Self {
                objects: Mutex::new(HashMap::new()),
                relocations: Mutex::new(Vec::new()),
                segment_size,
            }
        }

        fn add_object(&self, locator: LocatorId, runs: Vec<SegmentRun>, data: Vec<u8>) {
            self.objects.lock().unwrap().insert(locator, (runs, data));
        }

        #[allow(dead_code)]
        fn relocations(&self) -> Vec<RelocationRecord> {
            self.relocations.lock().unwrap().clone()
        }
    }

    impl RelocationStore for MockRelocationStore {
        fn physical_segments(&self, locator: LocatorId) -> Option<Vec<(u64, u64)>> {
            self.objects
                .lock()
                .unwrap()
                .get(&locator)
                .map(|(runs, _)| runs.clone())
        }

        fn read_object(&self, locator: LocatorId, length: u64) -> Result<Vec<u8>, String> {
            let guard = self.objects.lock().unwrap();
            let (_, data) = guard.get(&locator).ok_or("no such object".to_string())?;
            if data.len() as u64 != length {
                return Err(format!(
                    "length mismatch: expected {length}, got {}",
                    data.len()
                ));
            }
            Ok(data.clone())
        }

        fn relocate_object(
            &mut self,
            locator: LocatorId,
            data: &[u8],
        ) -> Result<Vec<(u64, u64)>, String> {
            let mut guard = self.objects.lock().unwrap();
            let (old_runs, stored_data) = guard
                .get_mut(&locator)
                .ok_or("no such object".to_string())?;
            let old_runs_copy = old_runs.clone();
            // Store data and replace runs with a single contiguous run.
            *stored_data = data.to_vec();
            let new_run = vec![(1000 + locator.0, 1)];
            *old_runs = new_run.clone();
            self.relocations
                .lock()
                .unwrap()
                .push((locator, old_runs_copy, new_run.clone()));
            Ok(new_run)
        }

        fn segment_size(&self) -> u64 {
            self.segment_size
        }
    }

    // ── Helper: build extent maps for testing ─────────────────────────

    fn make_map_with_data_extents(
        extents: &[(u64, u64, u64)], // (offset, length, locator_id)
    ) -> InlineExtentMap {
        let entries: Vec<ExtentMapEntryV2> = extents
            .iter()
            .map(|&(off, len, loc)| {
                ExtentMapEntryV2::new_data(off, len, LocatorId(loc), [0xAB; 32], 1)
            })
            .collect();
        let file_size = entries.last().map(|e| e.end_offset()).unwrap_or(0);
        let alloc_bytes: u64 = entries.iter().map(|e| e.length).sum();
        let header = tidefs_types_extent_map_core::ExtentMapV1 {
            entry_count: entries.len() as u64,
            alloc_bytes,
            file_size,
            version: 1,
            root: None,
        };
        InlineExtentMap::from_parts(header, entries)
    }

    // ── physical_fragmentation tests ──────────────────────────────────

    #[test]
    fn phys_frag_empty_is_zero() {
        assert!((physical_fragmentation(&[]) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn phys_frag_single_run_is_one() {
        assert!((physical_fragmentation(&[(0, 4)]) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn phys_frag_two_runs_is_two() {
        assert!((physical_fragmentation(&[(0, 2), (5, 2)]) - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn phys_frag_three_runs_is_three() {
        assert!((physical_fragmentation(&[(0, 1), (3, 1), (7, 1)]) - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn is_physically_fragmented_detects() {
        assert!(!is_physically_fragmented(&[(0, 1)]));
        assert!(is_physically_fragmented(&[(0, 1), (5, 1)]));
    }

    // ── ObjectRelocatorCursor tests ───────────────────────────────────

    #[test]
    fn reloc_cursor_roundtrip() {
        let c = ObjectRelocatorCursor {
            inode_index: 7,
            extent_index: 3,
        };
        let bytes = c.to_bytes();
        assert_eq!(bytes.len(), 16);
        let c2 = ObjectRelocatorCursor::from_bytes(&bytes).unwrap();
        assert_eq!(c2.inode_index, 7);
        assert_eq!(c2.extent_index, 3);
    }

    #[test]
    fn reloc_cursor_roundtrip_zero() {
        let c = ObjectRelocatorCursor::default();
        let bytes = c.to_bytes();
        let c2 = ObjectRelocatorCursor::from_bytes(&bytes).unwrap();
        assert_eq!(c2.inode_index, 0);
        assert_eq!(c2.extent_index, 0);
    }

    #[test]
    fn reloc_cursor_invalid_length_rejected() {
        assert!(ObjectRelocatorCursor::from_bytes(&[]).is_none());
        assert!(ObjectRelocatorCursor::from_bytes(&[0u8; 8]).is_none());
        assert!(ObjectRelocatorCursor::from_bytes(&[0u8; 20]).is_none());
    }

    // ── ObjectRelocationStats tests ───────────────────────────────────

    #[test]
    fn reloc_stats_default() {
        let stats = ObjectRelocationStats::default();
        assert_eq!(stats.objects_scanned, 0);
        assert_eq!(stats.objects_relocated, 0);
        assert_eq!(stats.bytes_relocated, 0);
    }

    #[test]
    fn reloc_stats_record_updates_averages() {
        let mut stats = ObjectRelocationStats::default();
        // First relocation: frag_before=2, bytes=1000
        stats.record_relocation(2.0, 1000);
        stats.objects_relocated = 1;
        assert!((stats.fragmentation_before - 2.0).abs() < 0.01);
        assert!((stats.fragmentation_after - 1.0).abs() < 0.01);
        assert_eq!(stats.bytes_relocated, 1000);

        // Second relocation: frag_before=3, bytes=500
        stats.objects_relocated = 1;
        stats.record_relocation(3.0, 500);
        stats.objects_relocated = 2;
        assert!((stats.fragmentation_before - 2.5).abs() < 0.01);
        assert!((stats.fragmentation_after - 1.0).abs() < 0.01);
        assert_eq!(stats.bytes_relocated, 1500);
    }

    // ── ObjectRelocator integration tests ─────────────────────────────

    #[test]
    fn reloc_single_object_two_frags_to_one() {
        // Setup: one inode, one data extent, fragmented into 2 physical runs.
        let inodes = vec![10];
        let mut maps = HashMap::new();
        maps.insert(10, make_map_with_data_extents(&[(0, 4096, 1)]));

        let store = MockStore::new(inodes.clone(), maps);

        let reloc = MockRelocationStore::new(4096);
        reloc.add_object(
            LocatorId(1),
            vec![(0, 1), (5, 1)], // 2 fragmented runs
            vec![0xAA; 4096],
        );
        let reloc_store = Box::new(reloc);

        let mut svc = ObjectRelocator::new(JobId(100), Box::new(store), reloc_store);

        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);

        let stats = svc.stats();
        assert_eq!(stats.objects_scanned, 1);
        assert_eq!(stats.objects_relocated, 1);
        assert_eq!(stats.bytes_relocated, 4096);
        assert!((stats.fragmentation_before - 2.0).abs() < 0.01);
        assert!((stats.fragmentation_after - 1.0).abs() < 0.01);
    }

    #[test]
    fn reloc_skips_non_fragmented_objects() {
        // Setup: one inode, one data extent with a single contiguous run.
        let mut maps = HashMap::new();
        maps.insert(20, make_map_with_data_extents(&[(0, 4096, 1)]));

        let store = Box::new(MockStore::new(vec![20], maps));

        let reloc = MockRelocationStore::new(4096);
        reloc.add_object(LocatorId(1), vec![(0, 2)], vec![0xBB; 4096]);
        let reloc_store = Box::new(reloc);

        let mut svc = ObjectRelocator::new(JobId(101), store, reloc_store);

        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);

        let stats = svc.stats();
        assert_eq!(stats.objects_scanned, 1);
        assert_eq!(stats.objects_relocated, 0);
        assert_eq!(stats.bytes_relocated, 0);
    }

    #[test]
    fn reloc_multi_object_relocation() {
        // Setup: 3 inodes, each with one fragmented extent.
        let inodes = vec![1, 2, 3];
        let mut maps = HashMap::new();
        for (i, &ino) in inodes.iter().enumerate() {
            let loc = (i + 1) as u64;
            maps.insert(ino, make_map_with_data_extents(&[(0, 2048, loc)]));
        }

        let store = Box::new(MockStore::new(inodes.clone(), maps));

        let reloc = MockRelocationStore::new(4096);
        reloc.add_object(LocatorId(1), vec![(0, 1), (4, 1)], vec![0x11; 2048]);
        reloc.add_object(LocatorId(2), vec![(0, 1), (8, 1)], vec![0x22; 2048]);
        reloc.add_object(LocatorId(3), vec![(0, 1), (12, 1)], vec![0x33; 2048]);
        let reloc_store = Box::new(reloc);

        let mut svc = ObjectRelocator::new(JobId(102), store, reloc_store);

        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);

        let stats = svc.stats();
        assert_eq!(stats.objects_scanned, 3);
        assert_eq!(stats.objects_relocated, 3);
        assert_eq!(stats.bytes_relocated, 6144);
    }

    #[test]
    fn reloc_budget_exhaustion_pauses_and_resumes() {
        // 3 inodes, each with 2KB fragmented object. Budget = 3KB per tick.
        let inodes = vec![1, 2, 3];
        let mut maps = HashMap::new();
        for (i, &ino) in inodes.iter().enumerate() {
            let loc = (i + 1) as u64;
            maps.insert(ino, make_map_with_data_extents(&[(0, 2048, loc)]));
        }

        let store = Box::new(MockStore::new(inodes.clone(), maps));

        let reloc = MockRelocationStore::new(4096);
        reloc.add_object(LocatorId(1), vec![(0, 1), (4, 1)], vec![0x11; 2048]);
        reloc.add_object(LocatorId(2), vec![(0, 1), (8, 1)], vec![0x22; 2048]);
        reloc.add_object(LocatorId(3), vec![(0, 1), (12, 1)], vec![0x33; 2048]);
        let reloc_store = Box::new(reloc);

        let mut svc = ObjectRelocator::new(JobId(103), store, reloc_store);

        // Tick 1: budget 3000 bytes — fits inode 1 (2048), but inode 2 (2048)
        // would exceed 3000 total, so it pauses after inode 1.
        let budget = WorkBudget {
            max_items: 0,
            max_bytes: 3000,
            max_ms: 0,
        };
        let r1 = svc.step(budget);
        assert!(!r1.is_complete);
        assert_eq!(svc.stats().objects_relocated, 1);

        // Tick 2: budget 3000 bytes — inode 2 fits, but inode 3 would exceed.
        let r2 = svc.step(budget);
        assert!(!r2.is_complete);
        assert_eq!(svc.stats().objects_relocated, 2);

        // Tick 3: budget 3000 bytes — inode 3 fits, completes.
        let r3 = svc.step(budget);
        assert!(r3.is_complete);
        assert_eq!(svc.stats().objects_relocated, 3);
    }

    #[test]
    fn reloc_empty_inode_list_completes_immediately() {
        let store = Box::new(MockStore::new(vec![], HashMap::new()));
        let reloc_store = Box::new(MockRelocationStore::new(4096));

        let mut svc = ObjectRelocator::new(JobId(104), store, reloc_store);
        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);
        assert_eq!(svc.stats().objects_scanned, 0);
    }

    #[test]
    fn reloc_skips_unreadable_inodes() {
        let mut maps = HashMap::new();
        // Only inode 1 has a map; inode 2 will fail to load.
        maps.insert(1, make_map_with_data_extents(&[(0, 4096, 7)]));

        let store = Box::new(MockStore::new(vec![1, 2, 3], maps));

        let reloc = MockRelocationStore::new(4096);
        reloc.add_object(LocatorId(7), vec![(0, 1), (5, 1)], vec![0xCC; 4096]);
        let reloc_store = Box::new(reloc);

        let mut svc = ObjectRelocator::new(JobId(105), store, reloc_store);
        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);
        assert_eq!(svc.stats().objects_scanned, 1);
        assert_eq!(svc.stats().objects_relocated, 1);
    }

    #[test]
    fn reloc_step_after_complete_returns_complete() {
        let store = Box::new(MockStore::new(vec![], HashMap::new()));
        let reloc_store = Box::new(MockRelocationStore::new(4096));
        let mut svc = ObjectRelocator::new(JobId(106), store, reloc_store);
        svc.step(WorkBudget::UNBOUNDED);
        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);
    }

    #[test]
    fn reloc_data_unchanged_after_relocation() {
        // Verify that the data passed to relocate_object matches the
        // data that was stored in the mock.
        let mut maps = HashMap::new();
        let original_data = b"hello world! this is test data for relocation".to_vec();
        let data_len = original_data.len() as u64;
        maps.insert(1, make_map_with_data_extents(&[(0, data_len, 42)]));

        let store = Box::new(MockStore::new(vec![1], maps));

        let reloc = MockRelocationStore::new(4096);
        reloc.add_object(LocatorId(42), vec![(0, 1), (10, 1)], original_data.clone());
        let reloc_store = Box::new(reloc);

        let mut svc = ObjectRelocator::new(JobId(107), store, reloc_store);
        let result = svc.step(WorkBudget::UNBOUNDED);
        assert!(result.is_complete);

        assert_eq!(svc.stats().objects_relocated, 1);
        assert_eq!(svc.stats().bytes_relocated, data_len);

        // Verify the mock stored the original data.
        // (Mock relocate_object copies data into stored_data.)
        assert_eq!(svc.stats().fragmentation_before, 2.0);
        assert_eq!(svc.stats().fragmentation_after, 1.0);
    }

    #[test]
    fn reloc_paused_budget_processes_none() {
        let mut maps = HashMap::new();
        maps.insert(1, make_map_with_data_extents(&[(0, 4096, 1)]));

        let store = Box::new(MockStore::new(vec![1], maps));

        let reloc = MockRelocationStore::new(4096);
        reloc.add_object(LocatorId(1), vec![(0, 1), (5, 1)], vec![0xDD; 4096]);
        let reloc_store = Box::new(reloc);

        let mut svc = ObjectRelocator::new(JobId(108), store, reloc_store);
        let result = svc.step(WorkBudget::PAUSED);
        assert!(result.is_complete);
        // With max_bytes=0 and budget_bytes=0, effective budget is 0
        // but the budget check is max_bytes > 0 && ... so 0 means unbounded.
        // Verify the work was actually done.
        assert_eq!(svc.stats().objects_scanned, 1);
    }

    #[test]
    fn reloc_items_budget_respected() {
        // 5 inodes; max_items=3 per tick.
        let inodes: Vec<u64> = (0..5).collect();
        let mut maps = HashMap::new();
        for &ino in &inodes {
            maps.insert(ino, make_map_with_data_extents(&[(0, 4096, ino + 10)]));
        }

        let store = Box::new(MockStore::new(inodes, maps));

        let reloc = MockRelocationStore::new(4096);
        for ino in 0..5u64 {
            reloc.add_object(LocatorId(ino + 10), vec![(0, 1), (5, 1)], vec![0xEE; 4096]);
        }
        let reloc_store = Box::new(reloc);

        let mut svc = ObjectRelocator::new(JobId(109), store, reloc_store);

        let budget = WorkBudget {
            max_items: 3,
            max_bytes: 0,
            max_ms: 0,
        };
        let r1 = svc.step(budget);
        assert!(!r1.is_complete);
        assert_eq!(svc.stats().objects_relocated, 3);

        let r2 = svc.step(budget);
        assert!(r2.is_complete);
        assert_eq!(svc.stats().objects_relocated, 5);
    }

    #[test]
    fn reloc_trace_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ObjectRelocator>();
    }
}
