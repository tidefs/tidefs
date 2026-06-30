// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Derived catalog view builder: IncrementalJob that walks the authoritative
//! directory B-tree, populates a ViewCache of directory entries, evicts cold
//! entries, and serves cached lookups.
//!
//! Implements a derived-catalog background job using the current scheduler
//! boundary summarized by [`docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`].
//!
//! # Architecture
//!
//! ```text
//! ViewBuilderService (IncrementalJob, JobKind::DerivedCatalog)
//!   ├── ViewCache: in-memory LRU with configurable max_entries
//!   ├── Build phase: walk authoritative dir B-tree, populate views
//!   ├── Maintenance phase: evict cold entries, rebuild stale views
//!   └── ViewBuilderStats: observability counters
//! ```

#![forbid(unsafe_code)]

extern crate alloc;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_incremental_job_core::IncrementalJob;
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};
use tidefs_types_polymorphic_directory_index_core::DirMicroEntry;

// ---------------------------------------------------------------------------
// DirEntryProjection — lightweight projected directory entry
// ---------------------------------------------------------------------------

/// Projection of a directory entry into a derived view.
///
/// Lighter than the full [`DirMicroEntry`]: stores only the hash of
/// the entry name, the target inode, and the entry's node kind.
/// Used inside [`ViewEntry`] to serve cached directory listings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntryProjection {
    /// FNV-1a hash of the entry name (deterministic, non-cryptographic).
    pub name_hash: u64,
    /// Target inode id.
    pub inode: u64,
    /// Node kind encoded as u32 (0=Dir, 1=File, 2=Symlink, …).
    /// Mirrors the `kind` field in [`DirMicroEntry`].
    pub entry_type: u32,
}

impl DirEntryProjection {
    /// Create a projection from a [`DirMicroEntry`].
    pub fn from_dir_entry(entry: &DirMicroEntry) -> Self {
        // FNV-1a 64-bit hash
        let mut hash: u64 = 0xcbf29ce484222325;
        for &byte in &entry.name {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        DirEntryProjection {
            name_hash: hash,
            inode: entry.inode_id,
            entry_type: entry.kind,
        }
    }
}

impl fmt::Display for DirEntryProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "proj(inode={}, type={}, hash={:016x})",
            self.inode, self.entry_type, self.name_hash
        )
    }
}

// ---------------------------------------------------------------------------
// ViewEntry — a single derived catalog view
// ---------------------------------------------------------------------------

/// A single derived catalog view entry.
///
/// Each entry represents a cached directory listing or index page
/// that can be served without walking the authoritative B-tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewEntry {
    /// Parent directory inode.
    pub dir_inode: u64,
    /// Opaque cursor into the authoritative B-tree for this view.
    pub btree_cursor: Vec<u8>,
    /// Sorted list of directory entries in this view page.
    pub entries: Vec<DirEntryProjection>,
    /// Monotonic generation number; incremented when the authoritative
    /// B-tree changes and the view is rebuilt.
    pub generation: u64,
    /// Last-access timestamp for eviction decisions (milliseconds since epoch).
    pub last_access_ms: u64,
    /// Whether this view is currently being rebuilt.
    pub rebuilding: bool,
}

impl ViewEntry {
    /// Create a new empty view entry for a directory.
    pub fn new(dir_inode: u64) -> Self {
        ViewEntry {
            dir_inode,
            btree_cursor: Vec::new(),
            entries: Vec::new(),
            generation: 0,
            last_access_ms: now_ms(),
            rebuilding: false,
        }
    }

    /// Mark this entry as accessed, updating the last-access timestamp.
    pub fn touch(&mut self) {
        self.last_access_ms = now_ms();
    }

    /// Mark this entry as stale (requiring rebuild).
    pub fn mark_stale(&mut self) {
        self.generation = 0;
    }

    /// Returns `true` if this view has any cached entries.
    pub fn is_populated(&self) -> bool {
        !self.entries.is_empty()
    }

    /// Returns `true` if the generation is zero (never built or stale).
    pub fn is_stale(&self) -> bool {
        self.generation == 0
    }
}

// ---------------------------------------------------------------------------
// ViewBuilderStats — observability counters
// ---------------------------------------------------------------------------

/// Statistics for the view builder service.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ViewBuilderStats {
    /// Number of cached view entries.
    pub cached_views: u64,
    /// Number of views rebuilt this cycle.
    pub views_rebuilt: u64,
    /// Number of views evicted this cycle.
    pub views_evicted: u64,
    /// Number of lookup hits served from cache.
    pub cache_hits: u64,
    /// Number of lookup misses requiring authoritative walk.
    pub cache_misses: u64,
}

impl ViewBuilderStats {
    /// Reset per-cycle counters (views_rebuilt, views_evicted).
    pub fn reset_cycle(&mut self) {
        self.views_rebuilt = 0;
        self.views_evicted = 0;
    }
}

impl fmt::Display for ViewBuilderStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cached={} rebuilt={} evicted={} hits={} misses={}",
            self.cached_views,
            self.views_rebuilt,
            self.views_evicted,
            self.cache_hits,
            self.cache_misses,
        )
    }
}

// ---------------------------------------------------------------------------
// ViewCache — in-memory LRU with configurable max_entries
// ---------------------------------------------------------------------------

/// Configuration for the view cache.
#[derive(Clone, Debug)]
pub struct ViewCacheConfig {
    /// Maximum number of view entries to keep in the cache.
    /// Beyond this limit, the least-recently-used entries are evicted.
    pub max_entries: usize,
    /// Age threshold in milliseconds for eviction.
    /// Entries not accessed for longer than this are eviction candidates.
    /// `0` disables age-based eviction.
    pub eviction_age_ms: u64,
    /// Maximum number of entries to evict per maintenance tick.
    pub max_evictions_per_tick: usize,
}

impl Default for ViewCacheConfig {
    fn default() -> Self {
        ViewCacheConfig {
            max_entries: 10_000,
            eviction_age_ms: 600_000, // 10 minutes
            max_evictions_per_tick: 256,
        }
    }
}

/// In-memory LRU cache for derived catalog views.
///
/// Tracks access order via a `VecDeque` of directory inodes. Eviction
/// removes the least-recently-used entry when the cache exceeds
/// `max_entries`.
#[derive(Clone, Debug)]
pub struct ViewCache {
    /// Configuration.
    config: ViewCacheConfig,
    /// The cached view entries, keyed by directory inode.
    entries: HashMap<u64, ViewEntry>,
    /// LRU ordering: front = most-recently-used, back = least-recently-used.
    lru_order: VecDeque<u64>,
}

impl ViewCache {
    /// Create a new view cache with the given configuration.
    pub fn new(config: ViewCacheConfig) -> Self {
        ViewCache {
            config,
            entries: HashMap::new(),
            lru_order: VecDeque::new(),
        }
    }

    /// Return the current configuration.
    pub fn config(&self) -> &ViewCacheConfig {
        &self.config
    }

    /// Number of cached view entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get a view entry by directory inode (updates LRU position).
    pub fn get(&mut self, dir_inode: u64) -> Option<&ViewEntry> {
        if self.entries.contains_key(&dir_inode) {
            self.move_to_front(dir_inode);
            if let Some(val) = self.entries.get_mut(&dir_inode) {
                val.touch();
            }
            Some(&self.entries[&dir_inode])
        } else {
            None
        }
    }

    /// Get a mutable view entry by directory inode (updates LRU position).
    pub fn get_mut(&mut self, dir_inode: u64) -> Option<&mut ViewEntry> {
        if self.entries.contains_key(&dir_inode) {
            self.move_to_front(dir_inode);
            let entry = self.entries.get_mut(&dir_inode).unwrap();
            entry.touch();
            Some(entry)
        } else {
            None
        }
    }

    /// Insert or update a view entry.
    pub fn insert(&mut self, entry: ViewEntry) {
        let dir_inode = entry.dir_inode;
        match self.entries.entry(dir_inode) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                // Update: move to front
                e.insert(entry);
                self.move_to_front(dir_inode);
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                // Insert: add to front, evict if needed
                e.insert(entry);
                self.lru_order.push_front(dir_inode);
                self.maybe_evict();
            }
        }
    }

    /// Remove a view entry by directory inode.
    pub fn remove(&mut self, dir_inode: u64) -> Option<ViewEntry> {
        let entry = self.entries.remove(&dir_inode);
        if entry.is_some() {
            self.lru_order.retain(|&id| id != dir_inode);
        }
        entry
    }

    /// Evict cold entries: remove up to `max_evictions_per_tick` entries
    /// that exceed the age threshold, or the least-recently-used entries
    /// if the cache exceeds `max_entries`.
    ///
    /// Returns the number of entries evicted.
    pub fn evict_cold(&mut self, now_ms: u64) -> usize {
        let max_evictions = self.config.max_evictions_per_tick;
        let age_threshold = self.config.eviction_age_ms;
        let max_entries = self.config.max_entries;
        let mut evicted = 0usize;

        // Phase 1: age-based eviction
        if age_threshold > 0 {
            let mut to_evict: Vec<u64> = Vec::new();
            for (&dir_inode, entry) in &self.entries {
                if evicted >= max_evictions {
                    break;
                }
                if now_ms.saturating_sub(entry.last_access_ms) > age_threshold {
                    to_evict.push(dir_inode);
                    evicted += 1;
                }
            }
            for dir_inode in to_evict {
                self.remove(dir_inode);
            }
        }

        // Phase 2: capacity-based eviction (LRU)
        while self.entries.len() > max_entries && evicted < max_evictions {
            if let Some(dir_inode) = self.lru_order.pop_back() {
                self.entries.remove(&dir_inode);
                evicted += 1;
            } else {
                break;
            }
        }

        evicted
    }

    /// Get all stale view entries (generation == 0).
    pub fn stale_entries(&self) -> Vec<u64> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.is_stale())
            .map(|(&dir_inode, _)| dir_inode)
            .collect()
    }

    /// Return a snapshot of all directory inodes currently cached.
    pub fn all_dirs(&self) -> Vec<u64> {
        self.entries.keys().copied().collect()
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.lru_order.clear();
    }

    // ── private helpers ──────────────────────────────────────────────

    fn maybe_evict(&mut self) {
        while self.entries.len() > self.config.max_entries {
            if let Some(dir_inode) = self.lru_order.pop_back() {
                self.entries.remove(&dir_inode);
            } else {
                break;
            }
        }
    }

    fn move_to_front(&mut self, dir_inode: u64) {
        self.lru_order.retain(|&id| id != dir_inode);
        self.lru_order.push_front(dir_inode);
    }
}

// ---------------------------------------------------------------------------
// ViewBuilderService — IncrementalJob for derived catalog views
// ---------------------------------------------------------------------------

/// Configuration for the view builder service.
#[derive(Clone, Debug)]
pub struct ViewBuilderConfig {
    /// Maximum number of synthetic directory entries to track.
    /// In production, this is bounded by the actual B-tree size.
    pub synthetic_dir_count: u64,
    /// Maximum entries per directory view.
    pub max_entries_per_view: usize,
    /// Cache configuration.
    pub cache_config: ViewCacheConfig,
}

impl Default for ViewBuilderConfig {
    fn default() -> Self {
        ViewBuilderConfig {
            synthetic_dir_count: 1000,
            max_entries_per_view: 64,
            cache_config: ViewCacheConfig::default(),
        }
    }
}

/// Cursor encoding for ViewBuilderService checkpoints.
///
/// The cursor encodes (next_dir_inode, generation_base) as two u64 LE values.
#[derive(Clone, Copy, Debug)]
struct ViewBuilderCursor {
    /// Next directory inode to build/rebuild.
    next_dir_inode: u64,
    /// Base generation number for fresh builds.
    generation_base: u64,
}

impl ViewBuilderCursor {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&self.next_dir_inode.to_le_bytes());
        buf.extend_from_slice(&self.generation_base.to_le_bytes());
        buf
    }

    fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            // Fresh start or empty cursor
            return None;
        }
        let next_dir_inode = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let generation_base = u64::from_le_bytes(data[8..16].try_into().ok()?);
        Some(ViewBuilderCursor {
            next_dir_inode,
            generation_base,
        })
    }
}

/// ViewBuilderService: walks the authoritative directory B-tree, populates
/// derived catalog views, evicts cold entries, and serves cached lookups.
///
/// Implements [`IncrementalJob`] for `JobKind::DerivedCatalog`.
/// Priority: LatencySensitive (cache misses directly increase user-facing
/// lookup latency).
#[derive(Debug)]
pub struct ViewBuilderService {
    /// Stable job identifier.
    id: JobId,
    /// Job kind discriminant.
    kind: JobKind,
    /// Epoch counter from the last persisted checkpoint.
    epoch: u64,
    /// Configuration.
    config: ViewBuilderConfig,
    /// The in-memory view cache.
    cache: ViewCache,
    /// Aggregate progress counters.
    progress: JobProgress,
    /// Statistics for the current cycle.
    stats: ViewBuilderStats,
    /// Current cursor position.
    cursor: ViewBuilderCursor,
    /// Whether the service has completed its initial build pass.
    cold_start: bool,
}

impl ViewBuilderService {
    /// Create a new ViewBuilderService from a checkpoint.
    ///
    /// On a fresh start (empty cursor), initializes the cache and begins
    /// building views for all synthetic directories.
    /// On resume, restores the cursor position and continues from where
    /// it left off.
    fn resume_inner(checkpoint: Checkpoint, config: ViewBuilderConfig) -> Result<Self, JobError> {
        let cold_start = checkpoint.cursor_state.is_empty();
        let cursor = if cold_start {
            ViewBuilderCursor {
                next_dir_inode: 1,
                generation_base: 1,
            }
        } else {
            ViewBuilderCursor::decode(checkpoint.cursor_state.as_bytes()).ok_or(
                JobError::CursorStateInvalid {
                    job_id: checkpoint.job_id,
                    reason: "cursor must be 16 bytes",
                },
            )?
        };

        let cache = ViewCache::new(config.cache_config.clone());

        Ok(ViewBuilderService {
            id: checkpoint.job_id,
            kind: checkpoint.job_kind,
            epoch: checkpoint.epoch,
            config,
            cache,
            progress: checkpoint.progress,
            stats: ViewBuilderStats::default(),
            cursor,
            cold_start,
        })
    }

    /// Build phase: populate views for directories that don't yet have them.
    ///
    /// Walks through synthetic directories in order, creating or rebuilding
    /// `ViewEntry` records for each one, capped by `budget`.
    fn build_phase(&mut self, budget: WorkBudget) -> u64 {
        let max_items = if budget.max_items == 0 {
            u64::MAX
        } else {
            budget.max_items
        };
        let mut processed = 0u64;
        let _now = now_ms();

        while processed < max_items {
            let dir_inode = self.cursor.next_dir_inode;

            // Check if this directory needs building
            let needs_build = match self.cache.get(dir_inode) {
                Some(entry) => entry.is_stale(),
                None => true,
            };

            if needs_build {
                // Build a synthetic view entry for this directory.
                // In production, this would walk the authoritative B-tree
                // and project DirMicroEntry values.
                let mut view = ViewEntry::new(dir_inode);
                view.generation = self.cursor.generation_base;

                // Populate with synthetic entries.
                let entry_count = (dir_inode % self.config.max_entries_per_view as u64)
                    .min(self.config.max_entries_per_view as u64)
                    .max(1);
                for i in 0..entry_count {
                    let name_hash = dir_inode.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(i);
                    view.entries.push(DirEntryProjection {
                        name_hash,
                        inode: dir_inode * 1000 + i + 1,
                        entry_type: if i == 0 { 0 } else { 1 },
                    });
                }

                self.cache.insert(view);
                self.stats.views_rebuilt += 1;
                self.stats.cached_views = self.cache.len() as u64;
            }

            self.cursor.next_dir_inode += 1;
            processed += 1;

            // Stop if we've processed all directories
            if self.cursor.next_dir_inode > self.config.synthetic_dir_count {
                // Wrap around: increment generation and start over
                self.cursor.next_dir_inode = 1;
                self.cursor.generation_base += 1;
                // Mark all entries as stale for the next pass
                for dir in self.cache.all_dirs() {
                    if let Some(entry) = self.cache.get_mut(dir) {
                        entry.mark_stale();
                    }
                }
                break;
            }
        }

        processed
    }

    /// Maintenance phase: evict cold entries, rebuild stale views.
    fn maintenance_phase(&mut self, budget: WorkBudget) -> u64 {
        let max_items = if budget.max_items == 0 {
            u64::MAX
        } else {
            budget.max_items / 2 // Split budget between eviction and rebuild
        };
        let mut processed = 0u64;
        let now = now_ms();

        // Phase 1: Eviction
        let evicted = self.cache.evict_cold(now) as u64;
        self.stats.views_evicted += evicted;
        self.stats.cached_views = self.cache.len() as u64;
        processed += evicted;

        // Phase 2: Rebuild stale views (remaining budget)
        let stale_dirs = self.cache.stale_entries();
        let rebuild_count = max_items.min(stale_dirs.len() as u64);
        for &dir_inode in stale_dirs.iter().take(rebuild_count as usize) {
            if let Some(entry) = self.cache.get_mut(dir_inode) {
                entry.generation = self.cursor.generation_base;
                entry.rebuilding = false;
                self.stats.views_rebuilt += 1;
            }
            processed += 1;
        }

        self.stats.cached_views = self.cache.len() as u64;
        processed
    }
}

impl IncrementalJob for ViewBuilderService {
    fn resume(state: Option<Checkpoint>) -> Result<Self, JobError>
    where
        Self: Sized,
    {
        let checkpoint =
            state.unwrap_or_else(|| Checkpoint::new_initial(JobId::NONE, JobKind::DerivedCatalog));
        Self::resume_inner(checkpoint, ViewBuilderConfig::default())
    }

    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
        let mut total_processed = 0u64;

        // Run build phase
        let build_processed = self.build_phase(budget);
        total_processed += build_processed;

        // Run maintenance phase
        let maint_processed = self.maintenance_phase(budget);
        total_processed += maint_processed;

        // Update progress
        self.progress.items_processed = self
            .progress
            .items_processed
            .saturating_add(total_processed);
        self.progress.items_total_estimate = self.config.synthetic_dir_count;

        // Determine completion. For a continuously-running service,
        // we never complete (always has_more). The scheduler calls
        // step() on every tick.
        let is_complete = false;

        let cursor_bytes = self.cursor.encode();
        let checkpoint = Checkpoint {
            job_id: self.id,
            job_kind: self.kind,
            epoch: self.epoch,
            cursor_state: CursorState(cursor_bytes),
            progress: self.progress,
        };

        Ok(StepResult {
            checkpoint,
            is_complete,
        })
    }

    fn persist_checkpoint(&self, _checkpoint: &Checkpoint) -> Result<(), JobError> {
        // In production, this would write to the dataset-scoped checkpoint area.
        // For now, the checkpoint is acknowledged but not externally persisted.
        Ok(())
    }

    fn complete(self) -> Result<(), JobError> {
        // ViewBuilderService runs continuously; complete() is a no-op.
        Ok(())
    }

    fn job_id(&self) -> JobId {
        self.id
    }

    fn job_kind(&self) -> JobKind {
        self.kind
    }
}

impl fmt::Display for ViewBuilderService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ViewBuilderService(id={}, cache_entries={}, cursor_dir={}, cold_start={})",
            self.id.0,
            self.cache.len(),
            self.cursor.next_dir_inode,
            self.cold_start,
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the current wall-clock time in milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── DirEntryProjection ──────────────────────────────────────────┐

    #[test]
    fn projection_from_dir_entry() {
        let entry = DirMicroEntry {
            name_len: 4,
            inode_id: 42,
            generation: 1,
            kind: 1, // File
            name: b"test".to_vec(),
        };
        let proj = DirEntryProjection::from_dir_entry(&entry);
        assert_eq!(proj.inode, 42);
        assert_eq!(proj.entry_type, 1);
    }

    #[test]
    fn projection_name_hash_deterministic() {
        let e1 = DirMicroEntry {
            name_len: 3,
            inode_id: 1,
            generation: 1,
            kind: 0,
            name: b"foo".to_vec(),
        };
        let e2 = DirMicroEntry {
            name_len: 3,
            inode_id: 2,
            generation: 1,
            kind: 0,
            name: b"foo".to_vec(),
        };
        let p1 = DirEntryProjection::from_dir_entry(&e1);
        let p2 = DirEntryProjection::from_dir_entry(&e2);
        assert_eq!(p1.name_hash, p2.name_hash, "same name => same hash");
    }

    #[test]
    fn projection_name_hash_differs() {
        let e1 = DirMicroEntry {
            name_len: 3,
            inode_id: 1,
            generation: 1,
            kind: 0,
            name: b"foo".to_vec(),
        };
        let e2 = DirMicroEntry {
            name_len: 3,
            inode_id: 2,
            generation: 1,
            kind: 0,
            name: b"bar".to_vec(),
        };
        let p1 = DirEntryProjection::from_dir_entry(&e1);
        let p2 = DirEntryProjection::from_dir_entry(&e2);
        assert_ne!(
            p1.name_hash, p2.name_hash,
            "different name => different hash"
        );
    }

    #[test]
    fn projection_display() {
        let proj = DirEntryProjection {
            name_hash: 0xdeadbeef,
            inode: 7,
            entry_type: 1,
        };
        let s = format!("{proj}");
        assert!(s.contains("inode=7"));
        assert!(s.contains("type=1"));
        assert!(s.contains("deadbeef"));
    }

    // ── ViewEntry ───────────────────────────────────────────────────┐

    #[test]
    fn view_entry_new_is_stale() {
        let entry = ViewEntry::new(1);
        assert_eq!(entry.dir_inode, 1);
        assert!(entry.is_stale());
        assert!(!entry.is_populated());
        assert!(!entry.rebuilding);
    }

    #[test]
    fn view_entry_touch_updates_timestamp() {
        let mut entry = ViewEntry::new(1);
        let ts1 = entry.last_access_ms;
        // Sleep a tiny bit to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(1));
        entry.touch();
        assert!(entry.last_access_ms >= ts1);
    }

    #[test]
    fn view_entry_mark_stale() {
        let mut entry = ViewEntry::new(1);
        entry.generation = 5;
        entry.mark_stale();
        assert!(entry.is_stale());
    }

    #[test]
    fn view_entry_is_populated() {
        let mut entry = ViewEntry::new(1);
        assert!(!entry.is_populated());
        entry.entries.push(DirEntryProjection {
            name_hash: 42,
            inode: 100,
            entry_type: 1,
        });
        assert!(entry.is_populated());
    }

    // ── ViewCache ───────────────────────────────────────────────────┐

    #[test]
    fn cache_insert_and_get() {
        let mut cache = ViewCache::new(ViewCacheConfig::default());
        let entry = ViewEntry::new(5);
        cache.insert(entry);
        assert_eq!(cache.len(), 1);
        let found = cache.get(5);
        assert!(found.is_some());
        assert_eq!(found.unwrap().dir_inode, 5);
    }

    #[test]
    fn cache_get_miss() {
        let mut cache = ViewCache::new(ViewCacheConfig::default());
        assert!(cache.get(42).is_none());
    }

    #[test]
    fn cache_evict_over_capacity() {
        let config = ViewCacheConfig {
            max_entries: 3,
            eviction_age_ms: 0,
            max_evictions_per_tick: 10,
        };
        let mut cache = ViewCache::new(config);
        for i in 0..5u64 {
            cache.insert(ViewEntry::new(i));
        }
        assert_eq!(cache.len(), 3);
        // The LRU entries (dirs 0 and 1) should have been evicted.
        assert!(cache.get(0).is_none());
        assert!(cache.get(1).is_none());
        assert!(cache.get(2).is_some());
        assert!(cache.get(3).is_some());
        assert!(cache.get(4).is_some());
    }

    #[test]
    fn cache_lru_ordering() {
        let config = ViewCacheConfig {
            max_entries: 3,
            eviction_age_ms: 0,
            max_evictions_per_tick: 10,
        };
        let mut cache = ViewCache::new(config);
        cache.insert(ViewEntry::new(1));
        cache.insert(ViewEntry::new(2));
        cache.insert(ViewEntry::new(3));
        // Access dir 1 to make it most-recently-used
        let _ = cache.get(1);
        // Now insert dir 4; should evict dir 2 (LRU)
        cache.insert(ViewEntry::new(4));
        assert_eq!(cache.len(), 3);
        assert!(cache.get(1).is_some(), "dir 1 was accessed recently");
        assert!(cache.get(2).is_none(), "dir 2 should be evicted");
        assert!(cache.get(3).is_some());
        assert!(cache.get(4).is_some());
    }

    #[test]
    fn cache_age_eviction() {
        let config = ViewCacheConfig {
            max_entries: 100,
            eviction_age_ms: 1, // 1ms age threshold
            max_evictions_per_tick: 100,
        };
        let mut cache = ViewCache::new(config);
        cache.insert(ViewEntry::new(1));
        cache.insert(ViewEntry::new(2));
        // Sleep to make entries old
        std::thread::sleep(std::time::Duration::from_millis(10));
        let now = now_ms();
        let evicted = cache.evict_cold(now);
        assert_eq!(evicted, 2);
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_remove() {
        let mut cache = ViewCache::new(ViewCacheConfig::default());
        cache.insert(ViewEntry::new(1));
        cache.insert(ViewEntry::new(2));
        let removed = cache.remove(1);
        assert!(removed.is_some());
        assert_eq!(cache.len(), 1);
        assert!(cache.get(1).is_none());
    }

    #[test]
    fn cache_stale_entries() {
        let mut cache = ViewCache::new(ViewCacheConfig::default());
        let mut e1 = ViewEntry::new(1);
        e1.generation = 1;
        cache.insert(e1);
        cache.insert(ViewEntry::new(2)); // stale (generation=0)
        cache.insert(ViewEntry::new(3)); // stale

        let stale = cache.stale_entries();
        assert_eq!(stale.len(), 2);
        assert!(stale.contains(&2));
        assert!(stale.contains(&3));
        assert!(!stale.contains(&1));
    }

    #[test]
    fn cache_all_dirs() {
        let mut cache = ViewCache::new(ViewCacheConfig::default());
        cache.insert(ViewEntry::new(10));
        cache.insert(ViewEntry::new(20));
        let dirs = cache.all_dirs();
        assert_eq!(dirs.len(), 2);
    }

    #[test]
    fn cache_clear() {
        let mut cache = ViewCache::new(ViewCacheConfig::default());
        cache.insert(ViewEntry::new(1));
        cache.clear();
        assert!(cache.is_empty());
    }

    // ── ViewBuilderStats ────────────────────────────────────────────┐

    #[test]
    fn stats_reset_cycle() {
        let mut stats = ViewBuilderStats {
            cached_views: 100,
            views_rebuilt: 10,
            views_evicted: 5,
            cache_hits: 200,
            cache_misses: 50,
        };
        stats.reset_cycle();
        assert_eq!(stats.cached_views, 100);
        assert_eq!(stats.views_rebuilt, 0);
        assert_eq!(stats.views_evicted, 0);
        assert_eq!(stats.cache_hits, 200);
        assert_eq!(stats.cache_misses, 50);
    }

    #[test]
    fn stats_display() {
        let stats = ViewBuilderStats {
            cached_views: 5,
            views_rebuilt: 2,
            views_evicted: 1,
            cache_hits: 42,
            cache_misses: 3,
        };
        let s = format!("{stats}");
        assert!(s.contains("cached=5"));
        assert!(s.contains("rebuilt=2"));
        assert!(s.contains("evicted=1"));
    }

    // ── ViewBuilderService ──────────────────────────────────────────┐

    #[test]
    fn service_cold_start_builds_views() {
        let ck = Checkpoint::new_initial(JobId(1), JobKind::DerivedCatalog);
        let config = ViewBuilderConfig {
            synthetic_dir_count: 10,
            ..Default::default()
        };
        let mut svc = ViewBuilderService::resume_inner(ck, config).unwrap();
        assert!(svc.cold_start);
        assert_eq!(svc.cache.len(), 0);

        let budget = WorkBudget {
            max_items: 5,
            ..WorkBudget::default()
        };
        let result = svc.step(budget).unwrap();
        assert!(!result.is_complete);
        // 5 items processed (build phase) + 0 (maintenance on empty cache)
        assert!(result.checkpoint.progress.items_processed > 0);
        assert!(!svc.cache.is_empty());
    }

    #[test]
    fn service_resume_from_checkpoint() {
        let config = ViewBuilderConfig {
            synthetic_dir_count: 100,
            ..Default::default()
        };

        // First run: process 10 items
        let ck = Checkpoint::new_initial(JobId(2), JobKind::DerivedCatalog);
        let mut svc = ViewBuilderService::resume_inner(ck, config.clone()).unwrap();
        let _ = svc
            .step(WorkBudget {
                max_items: 10,
                ..WorkBudget::default()
            })
            .unwrap();

        let checkpoint = Checkpoint {
            job_id: JobId(2),
            job_kind: JobKind::DerivedCatalog,
            epoch: 1,
            cursor_state: CursorState(svc.cursor.encode()),
            progress: svc.progress,
        };

        // Resume from checkpoint
        let svc2 = ViewBuilderService::resume_inner(checkpoint, config).unwrap();
        assert!(!svc2.cold_start);
        assert_eq!(svc2.cursor.next_dir_inode, 11); // 1 + 10 = 11
        assert!(svc2.progress.items_processed > 0);
    }

    #[test]
    fn service_budget_exhaustion_cursor_resume() {
        let config = ViewBuilderConfig {
            synthetic_dir_count: 50,
            ..Default::default()
        };
        let ck = Checkpoint::new_initial(JobId(3), JobKind::DerivedCatalog);
        let mut svc = ViewBuilderService::resume_inner(ck, config).unwrap();

        // Process small batches
        let budget = WorkBudget {
            max_items: 7,
            ..WorkBudget::default()
        };

        let mut steps = 0u32;
        loop {
            let _ = svc.step(budget).unwrap();
            steps += 1;
            // After enough small-budget steps, all 50 dirs should be cached
            if svc.cache.len() as u64 >= 50 || steps >= 20 {
                break;
            }
        }
        // Should have built views for all 50 directories
        assert!(svc.cache.len() as u64 >= 50);
    }

    #[test]
    fn service_stale_view_detection() {
        let config = ViewBuilderConfig {
            synthetic_dir_count: 20,
            ..Default::default()
        };
        let ck = Checkpoint::new_initial(JobId(4), JobKind::DerivedCatalog);
        let mut svc = ViewBuilderService::resume_inner(ck, config).unwrap();

        // Build all views
        let _ = svc.step(WorkBudget::UNBOUNDED).unwrap();

        // Manually mark some as stale
        for dir in &[3, 7, 11] {
            if let Some(entry) = svc.cache.get_mut(*dir) {
                entry.mark_stale();
            }
        }

        let stale = svc.cache.stale_entries();
        assert_eq!(stale.len(), 3);
        assert!(stale.contains(&3));
        assert!(stale.contains(&7));
        assert!(stale.contains(&11));
    }

    #[test]
    fn service_eviction_ordering() {
        let cache_config = ViewCacheConfig {
            max_entries: 5,
            eviction_age_ms: 0,
            max_evictions_per_tick: 10,
        };
        let config = ViewBuilderConfig {
            synthetic_dir_count: 20,
            cache_config,
            ..Default::default()
        };
        let ck = Checkpoint::new_initial(JobId(5), JobKind::DerivedCatalog);
        let mut svc = ViewBuilderService::resume_inner(ck, config).unwrap();

        // Build views; cache caps at 5
        let _ = svc.step(WorkBudget::UNBOUNDED).unwrap();
        assert_eq!(svc.cache.len(), 5);
        // The oldest inserted directories should be evicted
        assert!(svc.cache.get(0).is_none()); // dir 0 should be evicted
    }

    #[test]
    fn service_job_id_and_kind() {
        let ck = Checkpoint::new_initial(JobId(42), JobKind::DerivedCatalog);
        let svc = ViewBuilderService::resume_inner(ck, ViewBuilderConfig::default()).unwrap();
        assert_eq!(svc.job_id(), JobId(42));
        assert_eq!(svc.job_kind(), JobKind::DerivedCatalog);
    }

    #[test]
    fn service_complete_noop() {
        let ck = Checkpoint::new_initial(JobId(6), JobKind::DerivedCatalog);
        let svc = ViewBuilderService::resume_inner(ck, ViewBuilderConfig::default()).unwrap();
        assert!(svc.complete().is_ok());
    }

    #[test]
    fn service_incremental_rebuild() {
        let config = ViewBuilderConfig {
            synthetic_dir_count: 30,
            ..Default::default()
        };
        let ck = Checkpoint::new_initial(JobId(7), JobKind::DerivedCatalog);
        let mut svc = ViewBuilderService::resume_inner(ck, config).unwrap();

        // First pass: build all
        let _ = svc
            .step(WorkBudget {
                max_items: 50,
                ..WorkBudget::default()
            })
            .unwrap();
        let count_after_build = svc.cache.len();

        // Second pass: growth handled by rebuild
        let _ = svc
            .step(WorkBudget {
                max_items: 10,
                ..WorkBudget::default()
            })
            .unwrap();

        // Cache should still have entries
        assert!(!svc.cache.is_empty());
        assert!(count_after_build > 0);
    }

    #[test]
    fn service_display() {
        let ck = Checkpoint::new_initial(JobId(8), JobKind::DerivedCatalog);
        let svc = ViewBuilderService::resume_inner(ck, ViewBuilderConfig::default()).unwrap();
        let s = format!("{svc}");
        assert!(s.contains("ViewBuilderService"));
        assert!(s.contains("cache_entries=0"));
        assert!(s.contains("cold_start=true"));
    }

    // ── ViewBuilderCursor ───────────────────────────────────────────┐

    #[test]
    fn cursor_encode_decode_roundtrip() {
        let c = ViewBuilderCursor {
            next_dir_inode: 42,
            generation_base: 7,
        };
        let encoded = c.encode();
        assert_eq!(encoded.len(), 16);
        let decoded = ViewBuilderCursor::decode(&encoded).unwrap();
        assert_eq!(decoded.next_dir_inode, 42);
        assert_eq!(decoded.generation_base, 7);
    }

    #[test]
    fn cursor_decode_short_returns_none() {
        assert!(ViewBuilderCursor::decode(&[0u8; 8]).is_none());
        assert!(ViewBuilderCursor::decode(&[]).is_none());
    }
}

// ===========================================================================
// Snapshot-clone origin tracking — issue #5205
// ===========================================================================
//
// DerivedCatalog records the derivation chain linking clone datasets to
// their origin snapshots. Each DerivationEntry captures the relationship at
// clone-creation time. The in-memory index powers the HasClones and
// IsLiveDatasetOrigin guards in SnapshotPruner::validate_destroy_permission.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use tidefs_dataset_catalog::DatasetId;

// ---------------------------------------------------------------------------
// SnapshotId — stable snapshot identifier (UUID v4, 16 bytes)
// ---------------------------------------------------------------------------

/// Stable snapshot identifier (UUID v4, 16 bytes).
///
/// Mirrors the layout of [`DatasetId`] so both can share the same
/// binary-schema codec path.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotId([u8; 16]);

impl SnapshotId {
    /// Create a new `SnapshotId` from 16 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SnapshotId({self})")
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

// ---------------------------------------------------------------------------
// Conversion — DatasetId ↔ SnapshotId (same 16-byte layout)
// ---------------------------------------------------------------------------

impl From<DatasetId> for SnapshotId {
    fn from(id: DatasetId) -> Self {
        SnapshotId::from_bytes(*id.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// DerivationEntry — a single clone→origin relationship
// ---------------------------------------------------------------------------

/// Records that `derived_id` is a clone whose origin snapshot is
/// `origin_snapshot_id`, created at `creation_commit_group`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationEntry {
    /// The dataset that was cloned (the child).
    pub derived_id: DatasetId,
    /// The snapshot the clone was created from (the parent origin).
    pub origin_snapshot_id: SnapshotId,
    /// Transaction group at clone-creation time.
    pub creation_commit_group: u64,
}

impl DerivationEntry {
    /// Encode this entry to a 40-byte LE binary representation.
    ///
    /// Layout:  (16 bytes) |  (16 bytes)
    ///        |  (8 bytes LE, u64).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(self.derived_id.as_bytes());
        buf.extend_from_slice(self.origin_snapshot_id.as_bytes());
        buf.extend_from_slice(&self.creation_commit_group.to_le_bytes());
        buf
    }

    /// Decode a [] from a 40-byte LE binary slice.
    ///
    /// Returns  if the slice is too short.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }
        let derived_id = DatasetId::from_bytes(data[0..16].try_into().ok()?);
        let origin_snapshot_id = SnapshotId::from_bytes(data[16..32].try_into().ok()?);
        let creation_commit_group = u64::from_le_bytes(data[32..40].try_into().ok()?);
        Some(DerivationEntry {
            derived_id,
            origin_snapshot_id,
            creation_commit_group,
        })
    }
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// SnapshotAnchor — persistent snapshot metadata record
// ---------------------------------------------------------------------------

/// A persistent snapshot anchor stored in the derived catalog.
///
/// Records the committed root captured at snapshot-creation time so
/// the snapshot pruner and send/receive can enumerate snapshots and
/// resolve their object graphs without scanning the entire object store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotAnchor {
    /// Dataset that owns this snapshot.
    pub dataset_id: DatasetId,
    /// Human-readable snapshot name.
    pub name: String,
    /// Transaction group of the committed root at snapshot time.
    pub committed_root_txg: u64,
    /// Root handle within the committed root.
    pub root_handle: u64,
    /// Transaction group at snapshot-creation time.
    pub creation_commit_group: u64,
    /// Wall-clock creation timestamp (seconds since UNIX epoch).
    pub created_at_secs: u64,
}

impl SnapshotAnchor {
    /// Create a new snapshot anchor.
    #[must_use]
    pub fn new(
        dataset_id: DatasetId,
        name: String,
        committed_root_txg: u64,
        root_handle: u64,
        creation_commit_group: u64,
        created_at_secs: u64,
    ) -> Self {
        Self {
            dataset_id,
            name,
            committed_root_txg,
            root_handle,
            creation_commit_group,
            created_at_secs,
        }
    }

    /// Encode to a binary payload.
    ///
    /// Layout (little-endian):
    /// - dataset_id: 16 bytes
    /// - name_len: u16
    /// - name: UTF-8 bytes
    /// - committed_root_txg: u64
    /// - root_handle: u64
    /// - creation_commit_group: u64
    /// - created_at_secs: u64
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let name_bytes = self.name.as_bytes();
        let name_len = name_bytes.len().min(u16::MAX as usize) as u16;
        let mut buf = Vec::with_capacity(16 + 2 + name_bytes.len() + 32);
        buf.extend_from_slice(self.dataset_id.as_bytes());
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&self.committed_root_txg.to_le_bytes());
        buf.extend_from_slice(&self.root_handle.to_le_bytes());
        buf.extend_from_slice(&self.creation_commit_group.to_le_bytes());
        buf.extend_from_slice(&self.created_at_secs.to_le_bytes());
        buf
    }

    /// Decode from a binary payload.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 50 {
            return None;
        }
        let dataset_id = DatasetId::from_bytes(data[0..16].try_into().ok()?);
        let name_len = u16::from_le_bytes([data[16], data[17]]) as usize;
        if data.len() < 18 + name_len + 32 {
            return None;
        }
        let name = String::from_utf8(data[18..18 + name_len].to_vec()).ok()?;
        let off = 18 + name_len;
        let committed_root_txg = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
        let root_handle = u64::from_le_bytes(data[off + 8..off + 16].try_into().ok()?);
        let creation_commit_group = u64::from_le_bytes(data[off + 16..off + 24].try_into().ok()?);
        let created_at_secs = u64::from_le_bytes(data[off + 24..off + 32].try_into().ok()?);
        Some(Self {
            dataset_id,
            name,
            committed_root_txg,
            root_handle,
            creation_commit_group,
            created_at_secs,
        })
    }
}

// DerivedCatalog — in-memory clone-origin index
// ---------------------------------------------------------------------------

/// Tracks derivation relationships between clone datasets and their origin
/// snapshots.
///
/// Uses two [`BTreeMap`] indices for bidirectional lookup:
/// - `clone_index`: origin snapshot → list of clone dataset IDs
/// - `origin_index`: clone dataset ID → origin snapshot ID
///
/// The in-memory index will later be backed by persistent storage in the
/// local-object-store, using `tidefs-binary_schema-core` encode/decode.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DerivedCatalog {
    /// (dataset_id, snapshot_name) → snapshot anchor metadata.
    snapshot_index: BTreeMap<(DatasetId, String), SnapshotAnchor>,
    /// origin_snapshot_id → [derived dataset ids]
    clone_index: BTreeMap<SnapshotId, Vec<DatasetId>>,
    /// derived dataset id → origin_snapshot_id
    origin_index: BTreeMap<DatasetId, SnapshotId>,
    /// derived dataset id → creation commit_group
    txg_index: BTreeMap<DatasetId, u64>,
}

impl DerivedCatalog {
    /// Create an empty derivation catalog.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot_index: BTreeMap::new(),
            clone_index: BTreeMap::new(),
            origin_index: BTreeMap::new(),
            txg_index: BTreeMap::new(),
        }
    }

    /// Returns the number of derivation entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.origin_index.len()
    }

    /// Returns `true` if no derivations are recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.origin_index.is_empty()
    }

    // ------------------------------------------------------------------
    // Insert
    // ------------------------------------------------------------------

    /// Record a derivation: `derived_id` was cloned from `origin_snapshot_id`
    /// at `creation_commit_group`.
    ///
    /// If the entry already exists (same `derived_id`), it is replaced.
    pub fn insert(&mut self, entry: DerivationEntry) {
        // If this derived_id already had a different origin, remove it
        // from that origin's clone list first.
        if let Some(&old_origin) = self.origin_index.get(&entry.derived_id) {
            if old_origin != entry.origin_snapshot_id {
                if let Some(clones) = self.clone_index.get_mut(&old_origin) {
                    clones.retain(|id| *id != entry.derived_id);
                    if clones.is_empty() {
                        self.clone_index.remove(&old_origin);
                    }
                }
            }
        }

        // Update clone_index: add derived_id to the origin's clone list
        // Update clone_index: add derived_id to the origin's clone list
        // (avoid duplicates if the same entry is re-inserted)
        let clones = self
            .clone_index
            .entry(entry.origin_snapshot_id)
            .or_default();
        if !clones.contains(&entry.derived_id) {
            clones.push(entry.derived_id);
        }

        // Update origin_index: map derived_id → origin_snapshot_id
        self.origin_index
            .insert(entry.derived_id, entry.origin_snapshot_id);
        self.txg_index
            .insert(entry.derived_id, entry.creation_commit_group);
    }

    /// Convenience: record a derivation from its components.
    pub fn record_derivation(
        &mut self,
        derived_id: DatasetId,
        origin_snapshot_id: SnapshotId,
        creation_commit_group: u64,
    ) {
        self.insert(DerivationEntry {
            derived_id,
            origin_snapshot_id,
            creation_commit_group,
        });
    }

    // ------------------------------------------------------------------
    // Lifecycle-oriented mutation helpers (issue #5215)
    // ------------------------------------------------------------------

    /// Register a clone snapshot created from an origin dataset.
    ///
    /// The origin is identified by its `DatasetId` (converted to `SnapshotId`
    /// internally). This is the primary mutation path from dataset-lifecycle.
    pub fn insert_clone(
        &mut self,
        origin_dataset_id: DatasetId,
        clone_dataset_id: DatasetId,
        creation_commit_group: u64,
    ) {
        let origin_snapshot_id = SnapshotId::from(origin_dataset_id);
        self.record_derivation(clone_dataset_id, origin_snapshot_id, creation_commit_group);
    }

    /// Deregister a clone snapshot (by `DatasetId`) when it is destroyed.
    ///
    /// Returns the removed `DerivationEntry` if the clone was registered.
    pub fn remove_clone(&mut self, clone_dataset_id: &DatasetId) -> Option<DerivationEntry> {
        self.remove(clone_dataset_id)
    }

    /// Update the origin for a clone dataset (e.g., on promote/clone).
    ///
    /// Removes the old origin→clone relationship and registers the new one.
    /// Returns `true` if the clone was previously registered (under any origin).
    pub fn update_origin(
        &mut self,
        _old_origin_id: DatasetId,
        new_origin_id: DatasetId,
        clone_dataset_id: &DatasetId,
        creation_commit_group: u64,
    ) -> bool {
        let existed = self.remove(clone_dataset_id).is_some();
        self.insert_clone(new_origin_id, *clone_dataset_id, creation_commit_group);
        existed
    }

    // ------------------------------------------------------------------
    // Clone lookup (HasClones guard)
    // ------------------------------------------------------------------

    /// Return all dataset IDs cloned from `origin_snapshot_id`.
    ///
    /// An empty vector means the snapshot has no clones — it is safe to
    /// destroy (assuming the live-origin check also passes).
    #[must_use]
    pub fn lookup_clones(&self, origin_snapshot_id: &SnapshotId) -> Vec<DatasetId> {
        self.clone_index
            .get(origin_snapshot_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns `true` if the snapshot has at least one clone.
    #[must_use]
    pub fn has_clones(&self, origin_snapshot_id: &SnapshotId) -> bool {
        self.clone_index
            .get(origin_snapshot_id)
            .is_some_and(|v| !v.is_empty())
    }

    // ------------------------------------------------------------------
    // Origin lookup (IsLiveDatasetOrigin guard)
    // ------------------------------------------------------------------

    /// Return the origin snapshot for a derived dataset, if any.
    #[must_use]
    pub fn lookup_origin(&self, derived_id: &DatasetId) -> Option<SnapshotId> {
        self.origin_index.get(derived_id).copied()
    }

    /// Returns `true` if `derived_id` is a clone with a known origin.
    #[must_use]
    pub fn is_derived(&self, derived_id: &DatasetId) -> bool {
        self.origin_index.contains_key(derived_id)
    }

    // ------------------------------------------------------------------
    // Bulk / introspection
    // ------------------------------------------------------------------

    /// Return all derivation entries.
    #[must_use]
    pub fn entries(&self) -> Vec<DerivationEntry> {
        self.origin_index
            .iter()
            .map(|(&derived_id, &origin_snapshot_id)| DerivationEntry {
                derived_id,
                origin_snapshot_id,
                creation_commit_group: self.txg_index.get(&derived_id).copied().unwrap_or(0),
            })
            .collect()
    }

    /// Remove a derivation entry by derived dataset ID.
    ///
    /// Returns the removed entry (with `creation_commit_group = 0` since that field
    /// is not retained in the current in-memory index) or `None`.
    pub fn remove(&mut self, derived_id: &DatasetId) -> Option<DerivationEntry> {
        let origin_snapshot_id = self.origin_index.remove(derived_id)?;
        let creation_commit_group = self.txg_index.remove(derived_id).unwrap_or(0);

        // Clean up the clone_index entry
        if let Some(clones) = self.clone_index.get_mut(&origin_snapshot_id) {
            clones.retain(|id| id != derived_id);
            if clones.is_empty() {
                self.clone_index.remove(&origin_snapshot_id);
            }
        }

        Some(DerivationEntry {
            derived_id: *derived_id,
            origin_snapshot_id,
            creation_commit_group,
        })
    }

    // ------------------------------------------------------------------
    // Snapshot anchors (issue #5226)
    // ------------------------------------------------------------------

    /// Create a snapshot anchor: record the committed root captured at
    /// snapshot-creation time.
    ///
    /// Returns the created []. If a snapshot with the same
    /// dataset_id and name already exists, it is replaced.
    pub fn create_snapshot_anchor(
        &mut self,
        dataset_id: DatasetId,
        name: String,
        committed_root_txg: u64,
        root_handle: u64,
        creation_commit_group: u64,
        created_at_secs: u64,
    ) -> SnapshotAnchor {
        let anchor = SnapshotAnchor::new(
            dataset_id,
            name.clone(),
            committed_root_txg,
            root_handle,
            creation_commit_group,
            created_at_secs,
        );
        self.snapshot_index
            .insert((dataset_id, name), anchor.clone());
        anchor
    }

    /// List all snapshot anchors for a dataset, sorted by creation commit_group
    /// (oldest first).
    #[must_use]
    pub fn list_snapshot_anchors(&self, dataset_id: &DatasetId) -> Vec<SnapshotAnchor> {
        let mut anchors: Vec<SnapshotAnchor> = self
            .snapshot_index
            .iter()
            .filter(|((did, _), _)| did == dataset_id)
            .map(|(_, anchor)| anchor.clone())
            .collect();
        anchors.sort_by_key(|a| a.creation_commit_group);
        anchors
    }

    /// Remove a snapshot anchor by dataset id and name.
    ///
    /// Returns the removed [] if it existed.
    pub fn remove_snapshot_anchor(
        &mut self,
        dataset_id: &DatasetId,
        name: &str,
    ) -> Option<SnapshotAnchor> {
        self.snapshot_index.remove(&(*dataset_id, name.to_string()))
    }

    /// Returns  if a snapshot anchor exists for the given dataset and name.
    #[must_use]
    pub fn has_snapshot_anchor(&self, dataset_id: &DatasetId, name: &str) -> bool {
        self.snapshot_index
            .contains_key(&(*dataset_id, name.to_string()))
    }

    /// Number of snapshot anchors in the catalog.
    #[must_use]
    pub fn snapshot_anchor_count(&self) -> usize {
        self.snapshot_index.len()
    }

    /// Return all snapshot anchors.
    #[must_use]
    pub fn snapshot_anchors(&self) -> Vec<SnapshotAnchor> {
        self.snapshot_index.values().cloned().collect()
    }

    /// Remove all derivation entries.
    pub fn clear(&mut self) {
        self.snapshot_index.clear();
        self.clone_index.clear();
        self.origin_index.clear();
        self.txg_index.clear();
    }

    // ------------------------------------------------------------------
    // Binary persistence (issue #5205)
    // ------------------------------------------------------------------

    /// Encode the catalog to a binary blob for persistent storage.
    ///
    /// Layout:
    /// - derivation_count: u32 LE (4 bytes)
    /// - derivation entries: derivation_count × 40 bytes
    /// - snapshot_anchor_count: u32 LE (4 bytes)
    /// - snapshot anchors: variable bytes (each 50+name_len)
    ///
    /// An empty catalog encodes as 8 zero bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let dcount = self.origin_index.len() as u32;
        let scount = self.snapshot_index.len() as u32;
        let mut buf = Vec::with_capacity(8 + dcount as usize * 40 + scount as usize * 80);
        buf.extend_from_slice(&dcount.to_le_bytes());
        for entry in self.entries() {
            buf.extend_from_slice(&entry.encode());
        }
        buf.extend_from_slice(&scount.to_le_bytes());
        for anchor in self.snapshot_anchors() {
            buf.extend_from_slice(&anchor.encode());
        }
        buf
    }

    /// Decode a catalog from a binary blob produced by [](Self::encode).
    ///
    /// Returns  if the data is malformed (too short, truncated entries).
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let dcount = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        let mut cat = DerivedCatalog::new();
        let mut pos = 4usize;
        for _ in 0..dcount {
            if pos + 40 > data.len() {
                return None;
            }
            let entry = DerivationEntry::decode(&data[pos..pos + 40])?;
            cat.insert(entry);
            pos += 40;
        }
        // Read snapshot anchors
        if pos + 4 > data.len() {
            return None;
        }
        let scount = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        for _ in 0..scount {
            let anchor = SnapshotAnchor::decode(&data[pos..])?;
            let anchor_encoded = anchor.encode();
            pos += anchor_encoded.len();
            if pos > data.len() {
                return None;
            }
            cat.snapshot_index
                .insert((anchor.dataset_id, anchor.name.clone()), anchor);
        }
        Some(cat)
    }
}

impl fmt::Display for DerivedCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DerivedCatalog(derivations={}, snapshots={})",
            self.origin_index.len(),
            self.snapshot_index.len()
        )
    }
}

// ---------------------------------------------------------------------------
// DerivedCatalog tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod derived_catalog_tests {
    use super::*;

    /// Helper: create a DatasetId from a simple numeric pattern.
    fn did(n: u8) -> DatasetId {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        bytes[1] = n;
        bytes[2] = n;
        bytes[3] = n;
        bytes[4] = n;
        bytes[5] = n;
        bytes[6] = n;
        bytes[7] = n;
        bytes[8] = n;
        bytes[9] = n;
        bytes[10] = n;
        bytes[11] = n;
        bytes[12] = n;
        bytes[13] = n;
        bytes[14] = n;
        bytes[15] = n;
        DatasetId::from_bytes(bytes)
    }

    /// Helper: create a SnapshotId from a simple numeric pattern.
    fn sid(n: u8) -> SnapshotId {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        bytes[1] = n;
        bytes[2] = n;
        bytes[3] = n;
        bytes[4] = n;
        bytes[5] = n;
        bytes[6] = n;
        bytes[7] = n;
        bytes[8] = n;
        bytes[9] = n;
        bytes[10] = n;
        bytes[11] = n;
        bytes[12] = n;
        bytes[13] = n;
        bytes[14] = n;
        bytes[15] = n;
        SnapshotId::from_bytes(bytes)
    }

    // -- SnapshotId ---------------------------------------------------

    #[test]
    fn snapshot_id_display_roundtrip() {
        let id = sid(42);
        let s = id.to_string();
        // SnapshotId doesn't have from_uuid_str yet, but display is stable
        assert!(s.contains("2a2a2a2a"));
    }

    #[test]
    fn snapshot_id_equality() {
        let a = sid(1);
        let b = sid(1);
        let c = sid(2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn snapshot_id_ordering() {
        let a = sid(1);
        let b = sid(2);
        assert!(a < b);
    }

    // -- DerivedCatalog: insert and lookup_clones ---------------------

    #[test]
    fn insert_single_derivation_lookup_clones() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(10), sid(1), 100);

        let clones = cat.lookup_clones(&sid(1));
        assert_eq!(clones.len(), 1);
        assert_eq!(clones[0], did(10));
    }

    #[test]
    fn insert_multiple_clones_same_origin() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(10), sid(1), 100);
        cat.record_derivation(did(20), sid(1), 101);
        cat.record_derivation(did(30), sid(1), 102);

        let clones = cat.lookup_clones(&sid(1));
        assert_eq!(clones.len(), 3);
        assert!(clones.contains(&did(10)));
        assert!(clones.contains(&did(20)));
        assert!(clones.contains(&did(30)));
    }

    #[test]
    fn clones_from_different_origins() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(10), sid(1), 100);
        cat.record_derivation(did(20), sid(2), 200);
        cat.record_derivation(did(30), sid(1), 101);

        let clones_s1 = cat.lookup_clones(&sid(1));
        assert_eq!(clones_s1.len(), 2);
        assert!(clones_s1.contains(&did(10)));
        assert!(clones_s1.contains(&did(30)));

        let clones_s2 = cat.lookup_clones(&sid(2));
        assert_eq!(clones_s2.len(), 1);
        assert_eq!(clones_s2[0], did(20));
    }

    #[test]
    fn lookup_clones_empty_for_unknown_origin() {
        let cat = DerivedCatalog::new();
        let clones = cat.lookup_clones(&sid(99));
        assert!(clones.is_empty());
    }

    #[test]
    fn has_clones_true_and_false() {
        let mut cat = DerivedCatalog::new();
        assert!(!cat.has_clones(&sid(1)));

        cat.record_derivation(did(10), sid(1), 100);
        assert!(cat.has_clones(&sid(1)));
        assert!(!cat.has_clones(&sid(99)));
    }

    // -- DerivedCatalog: lookup_origin --------------------------------

    #[test]
    fn lookup_origin_returns_correct_snapshot() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(10), sid(5), 42);

        let origin = cat.lookup_origin(&did(10));
        assert_eq!(origin, Some(sid(5)));
    }

    #[test]
    fn lookup_origin_unknown_derived_returns_none() {
        let cat = DerivedCatalog::new();
        assert_eq!(cat.lookup_origin(&did(99)), None);
    }

    #[test]
    fn lookup_origin_after_insert_empty_result() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(1), sid(1), 1);
        // did(2) was never inserted
        assert_eq!(cat.lookup_origin(&did(2)), None);
    }

    #[test]
    fn is_derived_true_and_false() {
        let mut cat = DerivedCatalog::new();
        assert!(!cat.is_derived(&did(1)));

        cat.record_derivation(did(1), sid(1), 100);
        assert!(cat.is_derived(&did(1)));
        assert!(!cat.is_derived(&did(2)));
    }

    // -- DerivedCatalog: replace on duplicate insert ------------------

    #[test]
    fn insert_duplicate_derived_id_replaces_origin() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(10), sid(1), 100);

        // Re-insert same derived_id with different origin
        cat.record_derivation(did(10), sid(2), 200);

        // Origin should now be sid(2)
        assert_eq!(cat.lookup_origin(&did(10)), Some(sid(2)));

        // sid(1) should no longer have did(10) as a clone
        let clones_s1 = cat.lookup_clones(&sid(1));
        assert!(clones_s1.is_empty());

        // sid(2) should now have did(10) as a clone
        let clones_s2 = cat.lookup_clones(&sid(2));
        assert_eq!(clones_s2.len(), 1);
        assert_eq!(clones_s2[0], did(10));
    }

    // -- DerivedCatalog: len / is_empty / clear -----------------------

    #[test]
    fn catalog_len_and_is_empty() {
        let mut cat = DerivedCatalog::new();
        assert!(cat.is_empty());
        assert_eq!(cat.len(), 0);

        cat.record_derivation(did(1), sid(1), 1);
        assert!(!cat.is_empty());
        assert_eq!(cat.len(), 1);
    }

    #[test]
    fn catalog_clear() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(1), sid(1), 1);
        cat.record_derivation(did(2), sid(1), 2);
        assert_eq!(cat.len(), 2);

        cat.clear();
        assert!(cat.is_empty());
        assert_eq!(cat.len(), 0);
        assert!(cat.lookup_clones(&sid(1)).is_empty());
        assert_eq!(cat.lookup_origin(&did(1)), None);
    }

    // -- DerivedCatalog: remove ---------------------------------------

    #[test]
    fn remove_existing_entry() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(10), sid(1), 100);
        cat.record_derivation(did(20), sid(1), 101);

        let removed = cat.remove(&did(10));
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().origin_snapshot_id, sid(1));

        // did(10) should be gone
        assert_eq!(cat.lookup_origin(&did(10)), None);

        // did(20) should still be present
        assert_eq!(cat.lookup_origin(&did(20)), Some(sid(1)));

        // clone_index still has did(20) for sid(1)
        let clones = cat.lookup_clones(&sid(1));
        assert_eq!(clones.len(), 1);
        assert_eq!(clones[0], did(20));

        assert_eq!(cat.len(), 1);
    }

    #[test]
    fn remove_last_clone_cleans_clone_index() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(10), sid(1), 100);

        cat.remove(&did(10));
        assert!(cat.lookup_clones(&sid(1)).is_empty());
        assert!(!cat.has_clones(&sid(1)));
        assert!(cat.is_empty());
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut cat = DerivedCatalog::new();
        assert!(cat.remove(&did(99)).is_none());
    }

    // -- DerivedCatalog: entries --------------------------------------

    #[test]
    fn entries_returns_all_derivations() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(1), sid(10), 100);
        cat.record_derivation(did(2), sid(20), 200);

        let entries = cat.entries();
        assert_eq!(entries.len(), 2);

        let ids: Vec<DatasetId> = entries.iter().map(|e| e.derived_id).collect();
        assert!(ids.contains(&did(1)));
        assert!(ids.contains(&did(2)));

        let origins: Vec<SnapshotId> = entries.iter().map(|e| e.origin_snapshot_id).collect();
        assert!(origins.contains(&sid(10)));
        assert!(origins.contains(&sid(20)));
    }

    #[test]
    fn catalog_default_is_empty() {
        let cat = DerivedCatalog::default();
        assert!(cat.is_empty());
    }

    // -- Cross-index consistency --------------------------------------

    #[test]
    fn clone_and_origin_indices_are_consistent() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(1), sid(100), 1);
        cat.record_derivation(did(2), sid(100), 2);
        cat.record_derivation(did(3), sid(200), 3);

        // Every derived in origin_index must appear in clone_index
        for entry in cat.entries() {
            let clones = cat.lookup_clones(&entry.origin_snapshot_id);
            assert!(
                clones.contains(&entry.derived_id),
                "derived {:?} not in clone_index for snapshot {:?}",
                entry.derived_id,
                entry.origin_snapshot_id
            );
        }

        // Every clone list entry must map back to its origin
        for (snap_id, clones) in &cat.clone_index {
            for derived_id in clones {
                assert_eq!(
                    cat.lookup_origin(derived_id),
                    Some(*snap_id),
                    "origin mismatch for derived {derived_id:?}"
                );
            }
        }
    }

    // -- DerivationEntry encode/decode round-trip ---------------------

    #[test]
    fn derivation_entry_encode_decode_roundtrip() {
        let entry = DerivationEntry {
            derived_id: did(42),
            origin_snapshot_id: sid(7),
            creation_commit_group: 123456789,
        };
        let encoded = entry.encode();
        assert_eq!(encoded.len(), 40);
        let decoded = DerivationEntry::decode(&encoded).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn derivation_entry_decode_short_returns_none() {
        assert!(DerivationEntry::decode(&[0u8; 39]).is_none());
        assert!(DerivationEntry::decode(&[]).is_none());
    }

    // -- DerivedCatalog encode/decode round-trip ----------------------

    #[test]
    fn catalog_encode_decode_empty() {
        let cat = DerivedCatalog::new();
        let encoded = cat.encode();
        assert_eq!(encoded.len(), 8); // dcount=0 + scount=0
        assert_eq!(encoded, vec![0, 0, 0, 0, 0, 0, 0, 0]);
        let decoded = DerivedCatalog::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn catalog_encode_decode_single_entry() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(1), sid(10), 500);
        let encoded = cat.encode();
        let decoded = DerivedCatalog::decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded.lookup_origin(&did(1)), Some(sid(10)));
        assert!(decoded.has_clones(&sid(10)));
        assert!(!decoded.has_clones(&sid(99)));
    }

    #[test]
    fn catalog_encode_decode_preserves_txg() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(1), sid(10), 42);
        cat.record_derivation(did(2), sid(20), 999);
        let encoded = cat.encode();
        let decoded = DerivedCatalog::decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        // Verify commit_group is preserved through the encode/decode cycle
        let entries = decoded.entries();
        assert_eq!(entries.len(), 2);
        for e in &entries {
            if e.derived_id == did(1) {
                assert_eq!(e.creation_commit_group, 42);
            } else if e.derived_id == did(2) {
                assert_eq!(e.creation_commit_group, 999);
            }
        }
    }

    #[test]
    fn catalog_encode_decode_multiple_clones_same_origin() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(10), sid(1), 100);
        cat.record_derivation(did(20), sid(1), 200);
        cat.record_derivation(did(30), sid(1), 300);
        let encoded = cat.encode();
        let decoded = DerivedCatalog::decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 3);
        let clones = decoded.lookup_clones(&sid(1));
        assert_eq!(clones.len(), 3);
        assert!(clones.contains(&did(10)));
        assert!(clones.contains(&did(20)));
        assert!(clones.contains(&did(30)));
    }

    #[test]
    fn catalog_decode_malformed_truncated_header() {
        assert!(DerivedCatalog::decode(&[0x01, 0x00]).is_none()); // < 4 bytes
    }

    #[test]
    fn catalog_decode_truncated_entry() {
        // Header says 2 entries but data is too short
        let mut data = vec![0x02, 0x00, 0x00, 0x00]; // count = 2
        data.extend_from_slice(&[0u8; 50]); // Only 50 bytes (need 80)
        assert!(DerivedCatalog::decode(&data).is_none());
    }

    #[test]
    fn catalog_display() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(1), sid(1), 100);
        let s = format!("{cat}");
        assert!(s.contains("DerivedCatalog"));
        assert!(s.contains("derivations=1"));
        assert!(s.contains("snapshots=0"));
    }

    #[test]
    fn entries_preserves_creation_txg() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(1), sid(10), 9999);
        cat.record_derivation(did(2), sid(20), 8888);
        let entries = cat.entries();
        assert_eq!(entries.len(), 2);
        let e1 = entries.iter().find(|e| e.derived_id == did(1)).unwrap();
        assert_eq!(e1.creation_commit_group, 9999);
        let e2 = entries.iter().find(|e| e.derived_id == did(2)).unwrap();
        assert_eq!(e2.creation_commit_group, 8888);
    }

    #[test]
    fn remove_preserves_creation_txg() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(1), sid(10), 7777);
        let removed = cat.remove(&did(1)).unwrap();
        assert_eq!(removed.creation_commit_group, 7777);
        assert_eq!(removed.origin_snapshot_id, sid(10));
    }

    // -- SnapshotAnchor encode/decode ---------------------------------

    #[test]
    fn snapshot_anchor_encode_decode_roundtrip() {
        let anchor = SnapshotAnchor::new(did(42), "snap-2025".into(), 100, 7, 100, 1715000000);
        let encoded = anchor.encode();
        let decoded = SnapshotAnchor::decode(&encoded).unwrap();
        assert_eq!(decoded.dataset_id, did(42));
        assert_eq!(decoded.name, "snap-2025");
        assert_eq!(decoded.committed_root_txg, 100);
        assert_eq!(decoded.root_handle, 7);
        assert_eq!(decoded.creation_commit_group, 100);
        assert_eq!(decoded.created_at_secs, 1715000000);
    }

    #[test]
    fn snapshot_anchor_decode_short_rejected() {
        assert!(SnapshotAnchor::decode(&[]).is_none());
        assert!(SnapshotAnchor::decode(&[0u8; 49]).is_none());
    }

    #[test]
    fn snapshot_anchor_with_long_name_roundtrip() {
        let long_name = "a".repeat(200);
        let anchor = SnapshotAnchor::new(did(1), long_name.clone(), 1, 2, 3, 4);
        let encoded = anchor.encode();
        let decoded = SnapshotAnchor::decode(&encoded).unwrap();
        assert_eq!(decoded.name, long_name);
    }

    // -- DerivedCatalog snapshot anchor methods -------------------------

    #[test]
    fn create_snapshot_anchor_adds_entry() {
        let mut cat = DerivedCatalog::new();
        let anchor = cat.create_snapshot_anchor(did(10), "snap-a".into(), 100, 5, 100, 5000);
        assert_eq!(anchor.name, "snap-a");
        assert_eq!(cat.snapshot_anchor_count(), 1);
        assert!(cat.has_snapshot_anchor(&did(10), "snap-a"));
    }

    #[test]
    fn create_duplicate_snapshot_anchor_replaces() {
        let mut cat = DerivedCatalog::new();
        cat.create_snapshot_anchor(did(10), "snap-a".into(), 100, 5, 100, 5000);
        cat.create_snapshot_anchor(did(10), "snap-a".into(), 200, 6, 200, 6000);
        assert_eq!(cat.snapshot_anchor_count(), 1);
        let list = cat.list_snapshot_anchors(&did(10));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].committed_root_txg, 200);
    }

    #[test]
    fn list_snapshot_anchors_filters_by_dataset() {
        let mut cat = DerivedCatalog::new();
        cat.create_snapshot_anchor(did(1), "s1".into(), 10, 1, 10, 100);
        cat.create_snapshot_anchor(did(1), "s2".into(), 20, 2, 20, 200);
        cat.create_snapshot_anchor(did(2), "s3".into(), 30, 3, 30, 300);

        let ds1 = cat.list_snapshot_anchors(&did(1));
        assert_eq!(ds1.len(), 2);
        assert_eq!(ds1[0].name, "s1");
        assert_eq!(ds1[1].name, "s2");

        let ds2 = cat.list_snapshot_anchors(&did(2));
        assert_eq!(ds2.len(), 1);
        assert_eq!(ds2[0].name, "s3");

        let ds3 = cat.list_snapshot_anchors(&did(3));
        assert!(ds3.is_empty());
    }

    #[test]
    fn list_snapshot_anchors_sorted_by_creation_txg() {
        let mut cat = DerivedCatalog::new();
        cat.create_snapshot_anchor(did(1), "middle".into(), 20, 2, 20, 200);
        cat.create_snapshot_anchor(did(1), "oldest".into(), 10, 1, 10, 100);
        cat.create_snapshot_anchor(did(1), "newest".into(), 30, 3, 30, 300);

        let list = cat.list_snapshot_anchors(&did(1));
        assert_eq!(list[0].name, "oldest");
        assert_eq!(list[1].name, "middle");
        assert_eq!(list[2].name, "newest");
    }

    #[test]
    fn remove_snapshot_anchor_removes_entry() {
        let mut cat = DerivedCatalog::new();
        cat.create_snapshot_anchor(did(10), "snap-x".into(), 100, 5, 100, 5000);
        assert_eq!(cat.snapshot_anchor_count(), 1);

        let removed = cat.remove_snapshot_anchor(&did(10), "snap-x");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "snap-x");
        assert_eq!(cat.snapshot_anchor_count(), 0);
        assert!(!cat.has_snapshot_anchor(&did(10), "snap-x"));
    }

    #[test]
    fn remove_nonexistent_snapshot_anchor_returns_none() {
        let mut cat = DerivedCatalog::new();
        assert!(cat.remove_snapshot_anchor(&did(1), "no-such").is_none());
    }

    #[test]
    fn snapshot_anchor_count_reflects_all_entries() {
        let mut cat = DerivedCatalog::new();
        assert_eq!(cat.snapshot_anchor_count(), 0);
        cat.create_snapshot_anchor(did(1), "a".into(), 1, 1, 1, 1);
        cat.create_snapshot_anchor(did(2), "b".into(), 2, 2, 2, 2);
        assert_eq!(cat.snapshot_anchor_count(), 2);
    }

    #[test]
    fn clear_removes_snapshot_anchors() {
        let mut cat = DerivedCatalog::new();
        cat.create_snapshot_anchor(did(1), "s1".into(), 10, 1, 10, 100);
        cat.record_derivation(did(10), sid(1), 100);
        assert_eq!(cat.snapshot_anchor_count(), 1);
        assert!(!cat.is_empty());

        cat.clear();
        assert_eq!(cat.snapshot_anchor_count(), 0);
        assert!(cat.is_empty());
    }

    // -- encode/decode with snapshot anchors ----------------------------

    #[test]
    fn encode_decode_roundtrip_with_snapshot_anchors() {
        let mut cat = DerivedCatalog::new();
        cat.record_derivation(did(1), sid(10), 500);
        cat.create_snapshot_anchor(did(42), "snap-2025".into(), 100, 7, 100, 1715000000);

        let encoded = cat.encode();
        let decoded = DerivedCatalog::decode(&encoded).unwrap();

        // Derivations preserved
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded.lookup_origin(&did(1)), Some(sid(10)));

        // Snapshot anchors preserved
        assert_eq!(decoded.snapshot_anchor_count(), 1);
        assert!(decoded.has_snapshot_anchor(&did(42), "snap-2025"));
        let anchors = decoded.list_snapshot_anchors(&did(42));
        assert_eq!(anchors[0].committed_root_txg, 100);
        assert_eq!(anchors[0].root_handle, 7);
    }

    #[test]
    fn encode_decode_empty_catalog_still_works() {
        let cat = DerivedCatalog::new();
        let encoded = cat.encode();
        // 4 bytes derivation count (0) + 4 bytes snapshot count (0) = 8 bytes
        assert_eq!(encoded.len(), 8);
        let decoded = DerivedCatalog::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(decoded.snapshot_anchor_count(), 0);
    }

    #[test]
    fn encode_decode_multiple_snapshot_anchors() {
        let mut cat = DerivedCatalog::new();
        cat.create_snapshot_anchor(did(10), "s1".into(), 100, 1, 100, 1000);
        cat.create_snapshot_anchor(did(10), "s2".into(), 200, 2, 200, 2000);
        cat.create_snapshot_anchor(did(20), "s3".into(), 300, 3, 300, 3000);

        let encoded = cat.encode();
        let decoded = DerivedCatalog::decode(&encoded).unwrap();
        assert_eq!(decoded.snapshot_anchor_count(), 3);
        assert!(decoded.has_snapshot_anchor(&did(10), "s1"));
        assert!(decoded.has_snapshot_anchor(&did(10), "s2"));
        assert!(decoded.has_snapshot_anchor(&did(20), "s3"));
    }

    #[test]
    fn decode_truncated_snapshot_section_fails() {
        let mut cat = DerivedCatalog::new();
        cat.create_snapshot_anchor(did(1), "snap".into(), 1, 1, 1, 1);
        let mut encoded = cat.encode();
        // Truncate: remove last few bytes
        encoded.truncate(encoded.len() - 20);
        assert!(DerivedCatalog::decode(&encoded).is_none());
    }

    #[test]
    fn display_includes_snapshot_count() {
        let mut cat = DerivedCatalog::new();
        cat.create_snapshot_anchor(did(1), "s1".into(), 10, 1, 10, 100);
        let s = format!("{cat}");
        assert!(s.contains("snapshots=1"));
    }
}
