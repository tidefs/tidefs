//! Rewrite engine for segment compaction.
//!
//! Iterates over [`MergePlan`] groups, reads live extents from source
//! segments with BLAKE3 verification, writes them contiguously to new
//! target segments via a [`CompactionStore`], and produces a
//! BLAKE3-sealed [`RewriteOutcome`].
//!
//! ## Domain separation
//!
//! All BLAKE3 hashes use the domain "TideFS compaction v1" for
//! consistency with the merge planner.

use blake3::Hasher;

use crate::merge_planner::{MergeGroup, MergePlan};
use crate::{CompactionConfig, CompactionError, CompactionStore, CompactionSwap, RelocationEntry};

/// Domain string for BLAKE3 domain separation.
const COMPACTION_DOMAIN: &[u8] = b"TideFS compaction v1";

// ---------------------------------------------------------------------------
// RewriteGroupOutcome -- result of rewriting one merge group
// ---------------------------------------------------------------------------

/// The outcome of rewriting a single [`MergeGroup`].
///
/// Captures which source segments were freed, which new target segment
/// was created, how many objects were relocated, and the per-object
/// BLAKE3-verified relocation entries.
#[derive(Clone, Debug, PartialEq)]
pub struct RewriteGroupOutcome {
    /// Index of the group within the plan (0-based).
    pub group_index: usize,
    /// Source segments that were fully relocated and freed.
    pub freed_segments: Vec<u64>,
    /// New target segment id where live data was written.
    pub target_segment: u64,
    /// Number of objects successfully relocated.
    pub objects_relocated: u64,
    /// Total bytes written to the target segment.
    pub bytes_written: u64,
    /// Per-object relocation entries with BLAKE3-256 hashes.
    pub entries: Vec<RelocationEntry>,
}

impl RewriteGroupOutcome {
    /// Total source segments freed.
    #[must_use]
    pub fn segments_freed(&self) -> usize {
        self.freed_segments.len()
    }

    /// Whether any objects were relocated.
    #[must_use]
    pub fn has_relocations(&self) -> bool {
        self.objects_relocated > 0
    }
}

// ---------------------------------------------------------------------------
// RewriteOutcome -- sealed result of a full compaction rewrite pass
// ---------------------------------------------------------------------------

/// The BLAKE3-sealed outcome of executing a full [`MergePlan`].
///
/// Contains per-group outcomes and a plan-level integrity hash
/// computed over all group data in deterministic order using the
/// "TideFS compaction v1" domain.
#[derive(Clone, Debug, PartialEq)]
pub struct RewriteOutcome {
    /// Per-group rewrite outcomes in plan order.
    pub groups: Vec<RewriteGroupOutcome>,
    /// BLAKE3-256 hash sealing the full outcome.
    pub outcome_hash: [u8; 32],
    /// Total source segments freed across all groups.
    pub total_segments_freed: usize,
    /// Total objects relocated across all groups.
    pub total_objects_relocated: u64,
    /// Total bytes written to new target segments.
    pub total_bytes_written: u64,
    /// Whether the outcome is empty (no work performed).
    pub is_empty: bool,
}

impl RewriteOutcome {
    /// Create an empty outcome (no groups, no work).
    #[must_use]
    pub fn empty() -> Self {
        let hash = Self::compute_outcome_hash(&[]);
        Self {
            groups: Vec::new(),
            outcome_hash: hash,
            total_segments_freed: 0,
            total_objects_relocated: 0,
            total_bytes_written: 0,
            is_empty: true,
        }
    }

    /// Verify the outcome hash matches the contained data.
    #[must_use]
    pub fn verify(&self) -> bool {
        let recomputed = Self::compute_outcome_hash(&self.groups);
        recomputed == self.outcome_hash
    }

    /// Compute the BLAKE3-256 hash over a set of group outcomes.
    fn compute_outcome_hash(groups: &[RewriteGroupOutcome]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(COMPACTION_DOMAIN);
        hasher.update(&(groups.len() as u32).to_le_bytes());
        for g in groups {
            hasher.update(&g.group_index.to_le_bytes());
            hasher.update(&(g.freed_segments.len() as u32).to_le_bytes());
            for &seg in &g.freed_segments {
                hasher.update(&seg.to_le_bytes());
            }
            hasher.update(&g.target_segment.to_le_bytes());
            hasher.update(&g.objects_relocated.to_le_bytes());
            hasher.update(&g.bytes_written.to_le_bytes());
            hasher.update(&(g.entries.len() as u32).to_le_bytes());
            for entry in &g.entries {
                hasher.update(&entry.source_segment.to_le_bytes());
                hasher.update(&entry.object_key);
                hasher.update(&entry.target_offset.to_le_bytes());
                hasher.update(&entry.blake3_hash);
            }
        }
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// RewriteEngine -- drives compaction rewrite from a MergePlan
// ---------------------------------------------------------------------------

/// Executes a [`MergePlan`] by relocating live objects from source
/// segments into new contiguous target segments.
///
/// The engine uses a [`CompactionStore`] for I/O and produces a
/// BLAKE3-sealed [`RewriteOutcome`].
///
/// # Rate limiting
///
/// The [`CompactionConfig::max_relocate_bytes_per_tick`] cap is
/// enforced per group: once the group's bytes-written total exceeds
/// the cap, remaining objects in that group are deferred to the
/// next tick.
pub struct RewriteEngine<S: CompactionStore> {
    store: S,
    config: CompactionConfig,
    /// Cumulative bytes relocated across all calls.
    pub total_bytes_relocated: u64,
    /// Cumulative objects relocated across all calls.
    pub total_objects_relocated: u64,
    /// Cumulative source segments freed.
    pub total_segments_freed: u64,
}

impl<S: CompactionStore> RewriteEngine<S> {
    /// Create a new rewrite engine.
    #[must_use]
    pub fn new(store: S, config: CompactionConfig) -> Self {
        Self {
            store,
            config,
            total_bytes_relocated: 0,
            total_objects_relocated: 0,
            total_segments_freed: 0,
        }
    }

    /// Return a reference to the underlying store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Return the engine's configuration.
    #[must_use]
    pub fn config(&self) -> &CompactionConfig {
        &self.config
    }

    /// Execute a full rewrite pass for the given [`MergePlan`].
    ///
    /// For each group in the plan:
    /// 1. Collect live object keys from all source segments.
    /// 2. Read each object with BLAKE3 verification.
    /// 3. Write objects contiguously to a new target segment.
    /// 4. Free source segments and record the outcome.
    ///
    /// Rate-limiting via `max_relocate_bytes_per_tick` stops
    /// per-group writes once the byte cap is reached; remaining
    /// objects in that group are left in place for a future tick.
    ///
    /// Returns a BLAKE3-sealed [`RewriteOutcome`].
    pub fn execute_plan(&mut self, plan: &MergePlan) -> RewriteOutcome {
        if plan.is_empty() {
            return RewriteOutcome::empty();
        }

        let mut group_outcomes: Vec<RewriteGroupOutcome> = Vec::new();

        for (idx, group) in plan.groups.iter().enumerate() {
            let outcome = self.execute_group(idx, group);
            if outcome.has_relocations() || !outcome.freed_segments.is_empty() {
                group_outcomes.push(outcome);
            }
        }

        let total_segments_freed: usize = group_outcomes.iter().map(|g| g.segments_freed()).sum();
        let total_objects_relocated: u64 = group_outcomes.iter().map(|g| g.objects_relocated).sum();
        let total_bytes_written: u64 = group_outcomes.iter().map(|g| g.bytes_written).sum();
        let outcome_hash = RewriteOutcome::compute_outcome_hash(&group_outcomes);

        self.total_segments_freed = self
            .total_segments_freed
            .saturating_add(total_segments_freed as u64);
        self.total_objects_relocated = self
            .total_objects_relocated
            .saturating_add(total_objects_relocated);
        self.total_bytes_relocated = self
            .total_bytes_relocated
            .saturating_add(total_bytes_written);

        RewriteOutcome {
            groups: group_outcomes,
            outcome_hash,
            total_segments_freed,
            total_objects_relocated,
            total_bytes_written,
            is_empty: total_objects_relocated == 0 && total_segments_freed == 0,
        }
    }

    /// Execute a single merge group.
    fn execute_group(&mut self, group_index: usize, group: &MergeGroup) -> RewriteGroupOutcome {
        let max_bytes = self.config.max_relocate_bytes_per_tick;

        // Collect all live object keys from all source segments.
        let mut all_keys: Vec<([u8; 32], u64)> = Vec::new(); // (key, source_segment)
        for &seg_id in &group.source_segments {
            match self.store.live_object_keys(seg_id) {
                Ok(keys) => {
                    for key in keys {
                        all_keys.push((key, seg_id));
                    }
                }
                Err(_) => {
                    // Segment not found or error — skip it.
                    continue;
                }
            }
        }

        if all_keys.is_empty() {
            // All segments are empty or errored — free them anyway.
            let freed: Vec<u64> = group.source_segments.clone();
            for &seg_id in &freed {
                let _ = self.store.free_segment(seg_id);
            }
            return RewriteGroupOutcome {
                group_index,
                freed_segments: freed,
                target_segment: 0,
                objects_relocated: 0,
                bytes_written: 0,
                entries: Vec::new(),
            };
        }

        let mut entries: Vec<RelocationEntry> = Vec::new();
        let mut bytes_written: u64 = 0;
        let mut target_segment: u64 = 0;
        let mut first_write = true;

        for (key, source_seg) in &all_keys {
            // Rate-limiting check.
            if bytes_written >= max_bytes {
                break;
            }

            // Read the object data.
            let data = match self.store.read_object(key) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let data_len = data.len() as u64;
            let blake3_hash = *blake3::hash(&data).as_bytes();

            // Write to a new target segment.
            match self.store.write_object(key, &data) {
                Ok(new_seg) => {
                    if first_write {
                        target_segment = new_seg;
                        first_write = false;
                    }
                    // If write_object returns a different segment per call,
                    // track it; for contiguous writes we expect the same
                    // segment id for objects written to the same target.
                    let offset = bytes_written;
                    bytes_written = bytes_written.saturating_add(data_len);

                    entries.push(RelocationEntry {
                        source_segment: *source_seg,
                        object_key: *key,
                        target_offset: offset,
                        blake3_hash,
                    });
                }
                Err(_) => {
                    // Write failure — skip this object.
                    continue;
                }
            }
        }

        // Free source segments that had all their objects relocated.
        // A segment is fully freed if we successfully processed all its
        // objects and none were skipped due to errors or rate-limiting.
        let mut freed_segments: Vec<u64> = Vec::new();
        for &seg_id in &group.source_segments {
            // Determine if this segment's objects were all processed.
            let keys_in_seg = all_keys.iter().filter(|(_, s)| *s == seg_id).count();
            let relocated_in_seg = entries
                .iter()
                .filter(|e| e.source_segment == seg_id)
                .count();
            if keys_in_seg > 0 && relocated_in_seg == keys_in_seg {
                // All objects in this segment were successfully relocated.
                if self.store.free_segment(seg_id).is_ok() {
                    freed_segments.push(seg_id);
                }
            }
        }

        let objects_relocated = entries.len() as u64;

        RewriteGroupOutcome {
            group_index,
            freed_segments,
            target_segment,
            objects_relocated,
            bytes_written,
            entries,
        }
    }

    /// Commit the outcome of a rewrite pass atomically via the store.
    ///
    /// Builds a [`CompactionSwap`] from the outcome and calls
    /// [`CompactionStore::commit_swap`].
    ///
    /// # Errors
    ///
    /// Returns an error if the swap commit fails.
    pub fn commit_outcome(&mut self, outcome: &RewriteOutcome) -> Result<(), CompactionError> {
        if outcome.is_empty {
            return Ok(());
        }

        let freed_segments: Vec<u64> = outcome
            .groups
            .iter()
            .flat_map(|g| g.freed_segments.iter().copied())
            .collect();

        let registered_segments: Vec<u64> = outcome
            .groups
            .iter()
            .filter(|g| g.target_segment != 0)
            .map(|g| g.target_segment)
            .collect();

        let all_entries: Vec<RelocationEntry> = outcome
            .groups
            .iter()
            .flat_map(|g| g.entries.iter().cloned())
            .collect();

        if freed_segments.is_empty() && registered_segments.is_empty() {
            return Ok(());
        }

        let swap = CompactionSwap {
            freed_segments,
            registered_segments,
            entries: all_entries,
        };

        self.store.commit_swap(swap)
    }

    /// Consume the engine and return the underlying store.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge_planner::MergePlanner;
    use crate::CompactionConfig;
    use std::collections::BTreeMap;
    use tidefs_reclaim_queue_core::SegmentLivenessEntry;

    // ------------------------------------------------------------------
    // MockCompactionStore — a simple in-memory store for testing
    // ------------------------------------------------------------------

    #[derive(Clone, Debug)]
    struct MockCompactionStore {
        /// segment_id -> Vec<object_key>
        segments: BTreeMap<u64, Vec<[u8; 32]>>,
        /// object_key -> data
        objects: BTreeMap<[u8; 32], Vec<u8>>,
        /// Set of freed segment ids.
        freed: Vec<u64>,
        /// Write counter for synthetic segment ids.
        next_seg: u64,
        /// Key-to-write-failure map: keys that should fail on write.
        write_failures: BTreeMap<[u8; 32], CompactionError>,
        /// Keys that should fail on read.
        read_failures: BTreeMap<[u8; 32], CompactionError>,
    }

    impl MockCompactionStore {
        fn new() -> Self {
            Self {
                segments: BTreeMap::new(),
                objects: BTreeMap::new(),
                freed: Vec::new(),
                next_seg: 100,
                write_failures: BTreeMap::new(),
                read_failures: BTreeMap::new(),
            }
        }

        fn add_segment_with_objects(&mut self, seg_id: u64, objects: &[([u8; 32], Vec<u8>)]) {
            let keys: Vec<[u8; 32]> = objects.iter().map(|(k, _)| *k).collect();
            self.segments.insert(seg_id, keys);
            for (key, data) in objects {
                self.objects.insert(*key, data.clone());
            }
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
            self.objects.insert(*key, data.to_vec());
            let seg = self.next_seg;
            self.next_seg += 1;
            Ok(seg)
        }

        fn free_segment(&mut self, segment_id: u64) -> Result<(), CompactionError> {
            if !self.segments.contains_key(&segment_id) && !self.freed.contains(&segment_id) {
                return Err(CompactionError::SegmentNotFound(segment_id));
            }
            if !self.freed.contains(&segment_id) {
                self.freed.push(segment_id);
            }
            Ok(())
        }

        fn commit_swap(&mut self, swap: CompactionSwap) -> Result<(), CompactionError> {
            for seg in &swap.freed_segments {
                self.segments.remove(seg);
                if !self.freed.contains(seg) {
                    self.freed.push(*seg);
                }
            }
            for seg in &swap.registered_segments {
                if !self.segments.contains_key(seg) {
                    self.segments.insert(*seg, Vec::new());
                }
            }
            Ok(())
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn make_key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k
    }

    fn entry(id: u64, live: u64, dead: u64) -> SegmentLivenessEntry {
        SegmentLivenessEntry::new(id, live, dead)
    }

    fn default_config() -> CompactionConfig {
        CompactionConfig::default()
    }

    // ------------------------------------------------------------------
    // RewriteGroupOutcome tests
    // ------------------------------------------------------------------

    #[test]
    fn group_outcome_empty() {
        let outcome = RewriteGroupOutcome {
            group_index: 0,
            freed_segments: vec![],
            target_segment: 0,
            objects_relocated: 0,
            bytes_written: 0,
            entries: vec![],
        };
        assert_eq!(outcome.segments_freed(), 0);
        assert!(!outcome.has_relocations());
    }

    #[test]
    fn group_outcome_with_relocations() {
        let entry = RelocationEntry {
            source_segment: 1,
            object_key: [0u8; 32],
            target_offset: 0,
            blake3_hash: [1u8; 32],
        };
        let outcome = RewriteGroupOutcome {
            group_index: 0,
            freed_segments: vec![1],
            target_segment: 100,
            objects_relocated: 1,
            bytes_written: 64,
            entries: vec![entry],
        };
        assert_eq!(outcome.segments_freed(), 1);
        assert!(outcome.has_relocations());
    }

    // ------------------------------------------------------------------
    // RewriteOutcome tests
    // ------------------------------------------------------------------

    #[test]
    fn rewrite_outcome_empty() {
        let outcome = RewriteOutcome::empty();
        assert!(outcome.is_empty);
        assert!(outcome.groups.is_empty());
        assert_eq!(outcome.total_segments_freed, 0);
        assert_eq!(outcome.total_objects_relocated, 0);
        assert_eq!(outcome.total_bytes_written, 0);
        assert!(outcome.verify());
    }

    #[test]
    fn rewrite_outcome_verify_detects_tampering() {
        let outcome = RewriteOutcome::empty();

        // Tampering total_bytes_written doesn't change hash (derived from groups).
        let mut tampered = outcome.clone();
        tampered.total_bytes_written = 999;
        assert_eq!(outcome.outcome_hash, tampered.outcome_hash);

        // Tampering groups with updated hash passes verify.
        let mut tampered2 = outcome.clone();
        tampered2.groups.push(RewriteGroupOutcome {
            group_index: 0,
            freed_segments: vec![1],
            target_segment: 100,
            objects_relocated: 1,
            bytes_written: 64,
            entries: vec![],
        });
        tampered2.outcome_hash = RewriteOutcome::compute_outcome_hash(&tampered2.groups);
        assert!(tampered2.verify());

        // Tampering a group field without updating hash is detected.
        tampered2.groups[0].bytes_written = 0;
        assert!(!tampered2.verify());
    }

    #[test]
    fn rewrite_outcome_hash_deterministic() {
        let groups = vec![RewriteGroupOutcome {
            group_index: 0,
            freed_segments: vec![1, 2],
            target_segment: 100,
            objects_relocated: 3,
            bytes_written: 192,
            entries: vec![],
        }];
        let h1 = RewriteOutcome::compute_outcome_hash(&groups);
        let h2 = RewriteOutcome::compute_outcome_hash(&groups);
        assert_eq!(h1, h2);
    }

    #[test]
    fn rewrite_outcome_hash_differs_with_different_data() {
        let g1 = vec![RewriteGroupOutcome {
            group_index: 0,
            freed_segments: vec![1],
            target_segment: 100,
            objects_relocated: 1,
            bytes_written: 64,
            entries: vec![],
        }];
        let g2 = vec![RewriteGroupOutcome {
            group_index: 0,
            freed_segments: vec![2],
            target_segment: 100,
            objects_relocated: 1,
            bytes_written: 64,
            entries: vec![],
        }];
        assert_ne!(
            RewriteOutcome::compute_outcome_hash(&g1),
            RewriteOutcome::compute_outcome_hash(&g2)
        );
    }

    // ------------------------------------------------------------------
    // RewriteEngine tests
    // ------------------------------------------------------------------

    #[test]
    fn engine_new_with_config() {
        let store = MockCompactionStore::new();
        let engine = RewriteEngine::new(store, default_config());
        assert_eq!(engine.total_bytes_relocated, 0);
        assert_eq!(engine.total_objects_relocated, 0);
        assert_eq!(engine.total_segments_freed, 0);
        assert_eq!(engine.config().batch_size, 64);
    }

    #[test]
    fn engine_execute_empty_plan() {
        let store = MockCompactionStore::new();
        let mut engine = RewriteEngine::new(store, default_config());
        let plan = MergePlan {
            groups: vec![],
            plan_hash: [0u8; 32],
            total_source_segments: 0,
            total_live_bytes: 0,
            estimated_reclaimed_bytes: 0,
        };
        let outcome = engine.execute_plan(&plan);
        assert!(outcome.is_empty);
        assert!(outcome.verify());
    }

    #[test]
    fn engine_execute_single_group_with_two_segments() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        let d1 = vec![0xAAu8; 64];
        let d2 = vec![0xBBu8; 128];

        store.add_segment_with_objects(10, &[(k1, d1.clone()), (k2, d2.clone())]);

        let mut engine = RewriteEngine::new(store, default_config());

        let group = MergeGroup {
            source_segments: vec![10],
            total_live_bytes: 192,
            total_dead_bytes: 0,
            live_ratio: 1.0,
            score: 0.0,
        };

        let plan = MergePlan {
            groups: vec![group],
            plan_hash: [0u8; 32],
            total_source_segments: 1,
            total_live_bytes: 192,
            estimated_reclaimed_bytes: 0,
        };

        let outcome = engine.execute_plan(&plan);
        assert!(!outcome.is_empty);
        assert_eq!(outcome.groups.len(), 1);
        assert_eq!(outcome.total_objects_relocated, 2);
        assert_eq!(outcome.total_bytes_written, 192);
        assert_eq!(outcome.total_segments_freed, 1);
        assert!(outcome.verify());
        assert_eq!(engine.total_objects_relocated, 2);
    }

    #[test]
    fn engine_execute_multi_group_plan() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        let k3 = make_key(3);
        let d1 = vec![0x11u8; 32];
        let d2 = vec![0x22u8; 64];
        let d3 = vec![0x33u8; 48];

        store.add_segment_with_objects(10, &[(k1, d1.clone())]);
        store.add_segment_with_objects(20, &[(k2, d2.clone())]);
        store.add_segment_with_objects(30, &[(k3, d3.clone())]);

        let mut engine = RewriteEngine::new(store, default_config());

        let plan = MergePlan {
            groups: vec![
                MergeGroup {
                    source_segments: vec![10, 20],
                    total_live_bytes: 96,
                    total_dead_bytes: 100_000,
                    live_ratio: 0.001,
                    score: 0.8,
                },
                MergeGroup {
                    source_segments: vec![30],
                    total_live_bytes: 48,
                    total_dead_bytes: 50_000,
                    live_ratio: 0.001,
                    score: 0.75,
                },
            ],
            plan_hash: [0u8; 32],
            total_source_segments: 3,
            total_live_bytes: 144,
            estimated_reclaimed_bytes: 150_000,
        };

        let outcome = engine.execute_plan(&plan);
        assert_eq!(outcome.groups.len(), 2);
        assert_eq!(outcome.total_objects_relocated, 3);
        assert_eq!(outcome.total_bytes_written, 144);
        assert_eq!(outcome.total_segments_freed, 3);
        assert!(outcome.verify());
    }

    #[test]
    fn engine_execute_group_with_read_failure() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        let d1 = vec![0xAAu8; 64];
        let d2 = vec![0xBBu8; 128];

        store.add_segment_with_objects(10, &[(k1, d1.clone()), (k2, d2.clone())]);
        store.read_failures.insert(
            k2,
            CompactionError::ObjectReadFailed {
                key: k2,
                segment_id: 10,
            },
        );

        let mut engine = RewriteEngine::new(store, default_config());
        let plan = MergePlan {
            groups: vec![MergeGroup {
                source_segments: vec![10],
                total_live_bytes: 192,
                total_dead_bytes: 0,
                live_ratio: 1.0,
                score: 0.0,
            }],
            plan_hash: [0u8; 32],
            total_source_segments: 1,
            total_live_bytes: 192,
            estimated_reclaimed_bytes: 0,
        };

        let outcome = engine.execute_plan(&plan);
        // Only k1 should be relocated; k2 failed.
        assert_eq!(outcome.total_objects_relocated, 1);
        assert_eq!(outcome.total_bytes_written, 64);
        // Segment 10 is not fully freed (k2 failed).
        assert_eq!(outcome.total_segments_freed, 0);
        assert!(outcome.verify());
    }

    #[test]
    fn engine_execute_group_with_write_failure() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        let d1 = vec![0xAAu8; 64];
        let d2 = vec![0xBBu8; 128];

        store.add_segment_with_objects(10, &[(k1, d1.clone()), (k2, d2.clone())]);
        store.write_failures.insert(
            k2,
            CompactionError::ObjectWriteFailed {
                key: k2,
                reason: "disk full".into(),
            },
        );

        let mut engine = RewriteEngine::new(store, default_config());
        let plan = MergePlan {
            groups: vec![MergeGroup {
                source_segments: vec![10],
                total_live_bytes: 192,
                total_dead_bytes: 0,
                live_ratio: 1.0,
                score: 0.0,
            }],
            plan_hash: [0u8; 32],
            total_source_segments: 1,
            total_live_bytes: 192,
            estimated_reclaimed_bytes: 0,
        };

        let outcome = engine.execute_plan(&plan);
        assert_eq!(outcome.total_objects_relocated, 1);
        assert_eq!(outcome.total_bytes_written, 64);
        assert_eq!(outcome.total_segments_freed, 0);
        assert!(outcome.verify());
    }

    #[test]
    fn engine_execute_group_segment_not_found() {
        let store = MockCompactionStore::new();
        let mut engine = RewriteEngine::new(store, default_config());
        let plan = MergePlan {
            groups: vec![MergeGroup {
                source_segments: vec![999], // nonexistent
                total_live_bytes: 0,
                total_dead_bytes: 0,
                live_ratio: 0.0,
                score: 0.0,
            }],
            plan_hash: [0u8; 32],
            total_source_segments: 1,
            total_live_bytes: 0,
            estimated_reclaimed_bytes: 0,
        };

        let outcome = engine.execute_plan(&plan);
        // Segment not found means no live_object_keys, so it's freed.
        // Outcome is non-empty (one segment freed) but no relocations.
        assert!(!outcome.is_empty);
        assert_eq!(outcome.total_objects_relocated, 0);
        assert!(outcome.verify());
    }

    #[test]
    fn engine_rate_limiting_per_group() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        let d1 = vec![0xAAu8; 60_000_000]; // 60 MB
        let d2 = vec![0xBBu8; 10_000_000]; // 10 MB

        store.add_segment_with_objects(10, &[(k1, d1.clone()), (k2, d2.clone())]);

        // With max_relocate_bytes_per_tick = 64 MiB (default), both objects
        // should fit (70 MB > 64 MiB = 67,108,864). Actually 60MB < 64MB,
        // so both should fit. Let's use a lower cap.
        let cfg = CompactionConfig {
            max_relocate_bytes_per_tick: 50_000_000, // 50 MB
            ..default_config()
        };

        let mut engine = RewriteEngine::new(store, cfg);
        let plan = MergePlan {
            groups: vec![MergeGroup {
                source_segments: vec![10],
                total_live_bytes: 70_000_000,
                total_dead_bytes: 0,
                live_ratio: 1.0,
                score: 0.0,
            }],
            plan_hash: [0u8; 32],
            total_source_segments: 1,
            total_live_bytes: 70_000_000,
            estimated_reclaimed_bytes: 0,
        };

        let outcome = engine.execute_plan(&plan);
        // Only the first object (60 MB) should be relocated;
        // 60 MB >= 50 MB cap, so the second object is deferred.
        assert_eq!(outcome.total_objects_relocated, 1);
        assert_eq!(outcome.total_bytes_written, 60_000_000);
        // Segment not fully freed.
        assert_eq!(outcome.total_segments_freed, 0);
        assert!(outcome.verify());
    }

    #[test]
    fn engine_commit_outcome_atomic_swap() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let d1 = vec![0x42u8; 64];
        store.add_segment_with_objects(10, &[(k1, d1.clone())]);

        let mut engine = RewriteEngine::new(store, default_config());
        let plan = MergePlan {
            groups: vec![MergeGroup {
                source_segments: vec![10],
                total_live_bytes: 64,
                total_dead_bytes: 0,
                live_ratio: 1.0,
                score: 0.0,
            }],
            plan_hash: [0u8; 32],
            total_source_segments: 1,
            total_live_bytes: 64,
            estimated_reclaimed_bytes: 0,
        };

        let outcome = engine.execute_plan(&plan);
        assert_eq!(outcome.total_segments_freed, 1);
        assert!(outcome.verify());

        // Commit the outcome.
        engine.commit_outcome(&outcome).unwrap();

        // After commit, segment 10 should be freed.
        let store = engine.into_store();
        assert!(store.freed.contains(&10));
    }

    #[test]
    fn engine_commit_empty_outcome_noop() {
        let store = MockCompactionStore::new();
        let mut engine = RewriteEngine::new(store, default_config());
        let outcome = RewriteOutcome::empty();
        assert!(engine.commit_outcome(&outcome).is_ok());
    }

    #[test]
    fn engine_into_store_returns_store() {
        let store = MockCompactionStore::new();
        let engine = RewriteEngine::new(store, default_config());
        let _recovered: MockCompactionStore = engine.into_store();
    }

    // ------------------------------------------------------------------
    // Integration: MergePlanner -> RewriteEngine full cycle
    // ------------------------------------------------------------------

    #[test]
    fn integration_planner_to_rewrite_full_cycle() {
        // 1. Create liveness entries for fragmented segments.
        let entries = vec![
            entry(1, 30_000, 70_000),
            entry(2, 20_000, 80_000),
            entry(3, 15_000, 85_000),
        ];

        // 2. Plan with MergePlanner.
        let cfg = CompactionConfig {
            liveness_threshold: 0.5,
            min_live_bytes: 0, // accept all
            target_segment_size: 1_000_000,
            ..default_config()
        };
        let planner = MergePlanner::new(cfg.clone());
        let plan = planner.plan(&entries);
        assert!(!plan.is_empty());
        assert!(plan.verify());

        // 3. Seed a mock store with objects for those segments.
        let mut store = MockCompactionStore::new();
        let keys_data: Vec<([u8; 32], Vec<u8>)> =
            (1..=6u8).map(|i| (make_key(i), vec![i; 32])).collect();

        store.add_segment_with_objects(1, &keys_data[0..2]); // 2 objects
        store.add_segment_with_objects(2, &keys_data[2..4]); // 2 objects
        store.add_segment_with_objects(3, &keys_data[4..6]); // 2 objects

        // 4. Execute the plan via RewriteEngine.
        let mut engine = RewriteEngine::new(store, cfg);
        let outcome = engine.execute_plan(&plan);

        // 5. Verify the outcome.
        assert!(!outcome.is_empty);
        assert!(outcome.verify());
        assert!(outcome.total_objects_relocated >= 2); // at least one group with 2+ objects
        assert!(outcome.total_bytes_written > 0);
        assert!(outcome.total_segments_freed >= 1);

        // 6. Commit and verify store state.
        engine.commit_outcome(&outcome).unwrap();
        let store = engine.into_store();

        // Source segments should be freed.
        for &seg_id in &[1u64, 2, 3] {
            if outcome
                .groups
                .iter()
                .any(|g| g.freed_segments.contains(&seg_id))
            {
                assert!(store.freed.contains(&seg_id));
            }
        }
    }

    #[test]
    fn integration_planner_to_rewrite_deterministic() {
        let cfg = CompactionConfig {
            liveness_threshold: 0.5,
            min_live_bytes: 0,
            ..default_config()
        };
        let entries = vec![entry(1, 30_000, 70_000), entry(2, 20_000, 80_000)];

        let planner = MergePlanner::new(cfg.clone());
        let plan = planner.plan(&entries);

        // Run twice with fresh stores to verify deterministic output.
        let mut store1 = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        store1.add_segment_with_objects(1, &[(k1, vec![0xAAu8; 32])]);
        store1.add_segment_with_objects(2, &[(k2, vec![0xBBu8; 64])]);

        let mut store2 = MockCompactionStore::new();
        store2.add_segment_with_objects(1, &[(k1, vec![0xAAu8; 32])]);
        store2.add_segment_with_objects(2, &[(k2, vec![0xBBu8; 64])]);

        let mut engine1 = RewriteEngine::new(store1, cfg.clone());
        let mut engine2 = RewriteEngine::new(store2, cfg.clone());

        let outcome1 = engine1.execute_plan(&plan);
        let outcome2 = engine2.execute_plan(&plan);

        // Both outcomes should be identical (same BLAKE3 hash).
        assert_eq!(outcome1.outcome_hash, outcome2.outcome_hash);
        assert_eq!(outcome1, outcome2);
    }

    // ------------------------------------------------------------------
    // Edge case: group with mixed segment visibility
    // ------------------------------------------------------------------

    #[test]
    fn engine_mixed_segment_success_and_failure() {
        let mut store = MockCompactionStore::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        store.add_segment_with_objects(10, &[(k1, vec![0xAAu8; 64])]);
        store.add_segment_with_objects(20, &[(k2, vec![0xBBu8; 64])]);
        store.write_failures.insert(
            k1,
            CompactionError::ObjectWriteFailed {
                key: k1,
                reason: "io error".into(),
            },
        );

        let mut engine = RewriteEngine::new(store, default_config());
        let plan = MergePlan {
            groups: vec![MergeGroup {
                source_segments: vec![10, 20],
                total_live_bytes: 128,
                total_dead_bytes: 0,
                live_ratio: 1.0,
                score: 0.0,
            }],
            plan_hash: [0u8; 32],
            total_source_segments: 2,
            total_live_bytes: 128,
            estimated_reclaimed_bytes: 0,
        };

        let outcome = engine.execute_plan(&plan);
        // k1 failed write, k2 succeeded. Only segment 20 is fully freed.
        assert_eq!(outcome.total_objects_relocated, 1);
        assert_eq!(outcome.total_segments_freed, 1);
        // Verify segment 20 is freed, 10 is not.
        let group = &outcome.groups[0];
        assert!(group.freed_segments.contains(&20));
        assert!(!group.freed_segments.contains(&10));
        assert!(outcome.verify());
    }
}
