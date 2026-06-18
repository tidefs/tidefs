// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Merge planning for segment compaction.
//!
//! Selects fragmented segments by live-data ratio, forms merge groups
//! that fit within the target segment size, and produces a BLAKE3-verified
//! [`MergePlan`] that drives the rewrite engine.
//!
//! ## Domain separation
//!
//! All BLAKE3 hashes in this module use the domain "TideFS compaction v1"
//! for domain separation from other compaction subsystems.

use blake3::Hasher;

use crate::CompactionConfig;
use tidefs_reclaim_queue_core::SegmentLivenessEntry;

/// Domain string for BLAKE3 domain separation.
const COMPACTION_DOMAIN: &[u8] = b"TideFS compaction v1";

// ---------------------------------------------------------------------------
// MergeCandidate -- a segment evaluated for merge compaction
// ---------------------------------------------------------------------------

/// A candidate segment scored by live-data ratio for merge compaction.
///
/// Lower `live_ratio` means the segment is more fragmented and a better
/// candidate. The `score` normalises this into a [0.0, 1.0] range where
/// higher scores mean higher compaction priority.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MergeCandidate {
    /// The source segment identifier.
    pub segment_id: u64,
    /// Bytes still referenced by live objects.
    pub live_bytes: u64,
    /// Bytes eligible for reclamation.
    pub dead_bytes: u64,
    /// Ratio of live data to total (0.0 = all dead, 1.0 = all live).
    pub live_ratio: f64,
    /// Compaction desirability score in [0.0, 1.0]; higher is better.
    pub score: f64,
}

impl MergeCandidate {
    /// Create a new candidate from a liveness entry.
    #[must_use]
    pub fn from_entry(entry: &SegmentLivenessEntry) -> Self {
        let total = entry.total_bytes();
        let live_ratio = if total == 0 {
            0.0
        } else {
            entry.live_bytes as f64 / total as f64
        };
        // Score: 1.0 - live_ratio, clamped to [0.0, 1.0].
        let score = (1.0 - live_ratio).clamp(0.0, 1.0);
        Self {
            segment_id: entry.segment_id,
            live_bytes: entry.live_bytes,
            dead_bytes: entry.dead_bytes,
            live_ratio,
            score,
        }
    }

    /// Total accounted bytes in the segment.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.live_bytes.saturating_add(self.dead_bytes)
    }
}

// ---------------------------------------------------------------------------
// MergeGroup -- a group of source segments to merge into one target
// ---------------------------------------------------------------------------

/// A group of source segments whose combined live data fits within a
/// single target segment of size `target_segment_size`.
///
/// Groups are scored by the weighted-average candidate score so that
/// groups with more high-priority live data are compacted first.
#[derive(Clone, Debug, PartialEq)]
pub struct MergeGroup {
    /// Source segment IDs to merge.
    pub source_segments: Vec<u64>,
    /// Combined live bytes across all source segments.
    pub total_live_bytes: u64,
    /// Combined dead bytes across all source segments.
    pub total_dead_bytes: u64,
    /// Weighted live ratio (total_live / total_bytes).
    pub live_ratio: f64,
    /// Weighted-average compaction score for prioritisation.
    pub score: f64,
}

impl MergeGroup {
    /// Create an empty merge group.
    #[must_use]
    fn empty() -> Self {
        Self {
            source_segments: Vec::new(),
            total_live_bytes: 0,
            total_dead_bytes: 0,
            live_ratio: 0.0,
            score: 0.0,
        }
    }

    /// Returns true if the group is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.source_segments.is_empty()
    }

    /// Number of source segments in the group.
    #[must_use]
    pub fn len(&self) -> usize {
        self.source_segments.len()
    }

    /// Add a candidate to the group, updating weighted averages.
    fn add_candidate(&mut self, candidate: &MergeCandidate) {
        let old_total = self.total_bytes();
        let new_live = self.total_live_bytes.saturating_add(candidate.live_bytes);
        let new_dead = self.total_dead_bytes.saturating_add(candidate.dead_bytes);
        let new_total = new_live.saturating_add(new_dead);

        if new_total > 0 {
            self.score = if old_total == 0 {
                candidate.score
            } else {
                let old_weight = old_total as f64 / new_total as f64;
                let candidate_total = candidate.live_bytes.saturating_add(candidate.dead_bytes);
                let new_weight = candidate_total as f64 / new_total as f64;
                (self.score * old_weight) + (candidate.score * new_weight)
            };
        }

        self.source_segments.push(candidate.segment_id);
        self.total_live_bytes = new_live;
        self.total_dead_bytes = new_dead;
        self.live_ratio = if new_total == 0 {
            0.0
        } else {
            new_live as f64 / new_total as f64
        };
    }

    /// Total accounted bytes in the group.
    #[must_use]
    fn total_bytes(&self) -> u64 {
        self.total_live_bytes.saturating_add(self.total_dead_bytes)
    }

    /// Estimated reclaimable bytes after merging (dead bytes from source).
    #[must_use]
    pub fn reclaimable_bytes(&self) -> u64 {
        self.total_dead_bytes
    }
}

// ---------------------------------------------------------------------------
// MergePlan -- BLAKE3-verified compaction plan
// ---------------------------------------------------------------------------

/// A BLAKE3-verified merge plan describing which segments to compact,
/// how to group them, and the expected space reclamation.
///
/// The `plan_hash` is a BLAKE3-256 digest over all group data in
/// deterministic order, using the domain "TideFS compaction v1".
#[derive(Clone, Debug, PartialEq)]
pub struct MergePlan {
    /// Merge groups ordered by priority (highest score first).
    pub groups: Vec<MergeGroup>,
    /// BLAKE3-256 hash of the plan contents for integrity verification.
    pub plan_hash: [u8; 32],
    /// Total number of source segments across all groups.
    pub total_source_segments: usize,
    /// Combined live bytes across all groups.
    pub total_live_bytes: u64,
    /// Estimated bytes that will be reclaimed after merge.
    pub estimated_reclaimed_bytes: u64,
}

impl MergePlan {
    /// Returns true if the plan contains no groups.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Total number of merge groups.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Compute the BLAKE3-256 hash of a group for plan-integrity.
    fn hash_group(group: &MergeGroup, hasher: &mut Hasher) {
        hasher.update(&(group.source_segments.len() as u32).to_le_bytes());
        for &seg_id in &group.source_segments {
            hasher.update(&seg_id.to_le_bytes());
        }
        hasher.update(&group.total_live_bytes.to_le_bytes());
        hasher.update(&group.total_dead_bytes.to_le_bytes());
    }

    /// Verify that `plan_hash` matches the plan contents.
    #[must_use]
    pub fn verify(&self) -> bool {
        let recomputed = Self::compute_plan_hash(&self.groups);
        recomputed == self.plan_hash
    }

    /// Compute the BLAKE3-256 hash over the given groups with domain separation.
    fn compute_plan_hash(groups: &[MergeGroup]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(COMPACTION_DOMAIN);
        hasher.update(&(groups.len() as u32).to_le_bytes());
        for group in groups {
            Self::hash_group(group, &mut hasher);
        }
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// MergePlanner -- builds MergePlan from liveness data
// ---------------------------------------------------------------------------

/// Builds a [`MergePlan`] from segment-liveness data.
///
/// The planner performs three phases:
/// 1. **Candidate selection**: filter segments below the liveness threshold
///    and score them by dead ratio.
/// 2. **Group formation**: pack candidates into groups whose combined live
///    bytes fit within `target_segment_size`.
/// 3. **Plan sealing**: produce a BLAKE3-verified [`MergePlan`].
#[derive(Clone, Debug)]
pub struct MergePlanner {
    config: CompactionConfig,
}

impl MergePlanner {
    /// Create a new merge planner with the given configuration.
    #[must_use]
    pub fn new(config: CompactionConfig) -> Self {
        Self { config }
    }

    /// Return a reference to the planner's configuration.
    #[must_use]
    pub fn config(&self) -> &CompactionConfig {
        &self.config
    }

    /// Select and score candidate segments from liveness entries.
    ///
    /// Filters out segments whose live ratio is at or above
    /// `liveness_threshold`, or whose live bytes are below
    /// `min_live_bytes`. Returns candidates sorted by score descending
    /// (highest priority first), ties broken by live bytes descending,
    /// then by segment ID ascending for determinism.
    #[must_use]
    pub fn select_candidates(&self, entries: &[SegmentLivenessEntry]) -> Vec<MergeCandidate> {
        let mut candidates: Vec<MergeCandidate> = entries
            .iter()
            .filter(|e| {
                let total = e.total_bytes();
                if total == 0 {
                    return false;
                }
                let liveness = e.live_bytes as f64 / total as f64;
                liveness < self.config.liveness_threshold
                    && e.live_bytes >= self.config.min_live_bytes
            })
            .map(MergeCandidate::from_entry)
            .collect();

        candidates.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(core::cmp::Ordering::Equal)
                .then_with(|| b.live_bytes.cmp(&a.live_bytes))
                .then_with(|| a.segment_id.cmp(&b.segment_id))
        });

        candidates.truncate(self.config.batch_size);
        candidates
    }

    /// Form merge groups from scored candidates.
    ///
    /// Each group packs candidates whose combined live bytes fit within
    /// `target_segment_size`. Groups with fewer than 2 source segments
    /// are discarded (a single-segment group offers no merge benefit).
    #[must_use]
    pub fn form_groups(&self, candidates: &[MergeCandidate]) -> Vec<MergeGroup> {
        let target = self.config.target_segment_size;
        let mut groups: Vec<MergeGroup> = Vec::new();
        let mut current: MergeGroup = MergeGroup::empty();

        for candidate in candidates {
            let projected = current
                .total_live_bytes
                .saturating_add(candidate.live_bytes);

            if !current.is_empty() && projected > target {
                if current.len() >= 2 {
                    groups.push(current);
                }
                current = MergeGroup::empty();
            }

            current.add_candidate(candidate);
        }

        if current.len() >= 2 {
            groups.push(current);
        }

        groups.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(core::cmp::Ordering::Equal)
                .then_with(|| b.total_live_bytes.cmp(&a.total_live_bytes))
        });

        groups
    }

    /// Produce a full BLAKE3-verified [`MergePlan`] from liveness entries.
    #[must_use]
    pub fn plan(&self, entries: &[SegmentLivenessEntry]) -> MergePlan {
        let candidates = self.select_candidates(entries);
        let groups = self.form_groups(&candidates);
        let plan_hash = MergePlan::compute_plan_hash(&groups);

        let total_source_segments: usize = groups.iter().map(|g| g.len()).sum();
        let total_live_bytes: u64 = groups.iter().map(|g| g.total_live_bytes).sum();
        let estimated_reclaimed_bytes: u64 = groups.iter().map(|g| g.reclaimable_bytes()).sum();

        MergePlan {
            groups,
            plan_hash,
            total_source_segments,
            total_live_bytes,
            estimated_reclaimed_bytes,
        }
    }

    /// Verify a merge plan's integrity by recomputing its hash.
    #[must_use]
    pub fn verify_plan(&self, plan: &MergePlan) -> bool {
        plan.verify()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompactionConfig;

    fn entry(id: u64, live: u64, dead: u64) -> SegmentLivenessEntry {
        SegmentLivenessEntry::new(id, live, dead)
    }

    fn default_planner() -> MergePlanner {
        MergePlanner::new(CompactionConfig::default())
    }

    // --- MergeCandidate ---

    #[test]
    fn candidate_from_entry_fragmented() {
        let e = entry(10, 30_000, 70_000);
        let c = MergeCandidate::from_entry(&e);
        assert_eq!(c.segment_id, 10);
        assert_eq!(c.live_bytes, 30_000);
        assert_eq!(c.dead_bytes, 70_000);
        assert!((c.live_ratio - 0.30).abs() < 0.001);
        assert!((c.score - 0.70).abs() < 0.001);
        assert_eq!(c.total_bytes(), 100_000);
    }

    #[test]
    fn candidate_from_entry_all_live() {
        let c = MergeCandidate::from_entry(&entry(20, 50_000, 0));
        assert_eq!(c.live_ratio, 1.0);
        assert_eq!(c.score, 0.0);
    }

    #[test]
    fn candidate_from_entry_all_dead() {
        let c = MergeCandidate::from_entry(&entry(30, 0, 40_000));
        assert_eq!(c.live_ratio, 0.0);
        assert_eq!(c.score, 1.0);
        assert_eq!(c.total_bytes(), 40_000);
    }

    #[test]
    fn candidate_from_entry_zero_total() {
        let c = MergeCandidate::from_entry(&entry(40, 0, 0));
        assert_eq!(c.live_ratio, 0.0);
        assert_eq!(c.score, 1.0);
        assert_eq!(c.total_bytes(), 0);
    }

    // --- MergeGroup ---

    #[test]
    fn merge_group_empty() {
        let g = MergeGroup::empty();
        assert!(g.is_empty());
        assert_eq!(g.len(), 0);
        assert_eq!(g.total_live_bytes, 0);
        assert_eq!(g.total_dead_bytes, 0);
        assert_eq!(g.live_ratio, 0.0);
        assert_eq!(g.score, 0.0);
        assert_eq!(g.reclaimable_bytes(), 0);
    }

    #[test]
    fn merge_group_single_candidate() {
        let mut g = MergeGroup::empty();
        let c = MergeCandidate::from_entry(&entry(1, 30_000, 70_000));
        g.add_candidate(&c);
        assert_eq!(g.len(), 1);
        assert_eq!(g.total_live_bytes, 30_000);
        assert_eq!(g.total_dead_bytes, 70_000);
        assert!((g.live_ratio - 0.30).abs() < 0.001);
        assert!((g.score - 0.70).abs() < 0.001);
        assert_eq!(g.reclaimable_bytes(), 70_000);
    }

    #[test]
    fn merge_group_two_candidates_weighted_average() {
        let mut g = MergeGroup::empty();
        g.add_candidate(&MergeCandidate::from_entry(&entry(1, 30_000, 70_000)));
        g.add_candidate(&MergeCandidate::from_entry(&entry(2, 40_000, 10_000)));
        assert_eq!(g.len(), 2);
        assert_eq!(g.total_live_bytes, 70_000);
        assert_eq!(g.total_dead_bytes, 80_000);
        assert_eq!(g.reclaimable_bytes(), 80_000);
        let expected_score = 0.70 * (100_000.0 / 150_000.0) + 0.20 * (50_000.0 / 150_000.0);
        assert!((g.score - expected_score).abs() < 0.001);
        let expected_ratio = 70_000.0 / 150_000.0;
        assert!((g.live_ratio - expected_ratio).abs() < 0.001);
    }

    // --- select_candidates ---

    #[test]
    fn select_candidates_filters_by_liveness_threshold() {
        let planner = default_planner();
        let entries = vec![
            entry(1, 20_000, 80_000),
            entry(2, 60_000, 40_000),
            entry(3, 10_000, 90_000),
        ];
        let candidates = planner.select_candidates(&entries);
        assert_eq!(candidates.len(), 2);
        let ids: Vec<u64> = candidates.iter().map(|c| c.segment_id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&3));
        assert!(!ids.contains(&2));
    }

    #[test]
    fn select_candidates_filters_by_min_live_bytes() {
        let planner = default_planner();
        let entries = vec![
            entry(1, 30_000, 70_000),
            entry(2, 2_000, 80_000),
            entry(3, 5_000, 45_000),
        ];
        let candidates = planner.select_candidates(&entries);
        assert_eq!(candidates.len(), 2);
        let ids: Vec<u64> = candidates.iter().map(|c| c.segment_id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&3));
    }

    #[test]
    fn select_candidates_rejects_zero_total() {
        let planner = default_planner();
        let entries = vec![entry(1, 0, 0), entry(2, 30_000, 70_000)];
        let candidates = planner.select_candidates(&entries);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].segment_id, 2);
    }

    #[test]
    fn select_candidates_empty_input() {
        let planner = default_planner();
        assert!(planner.select_candidates(&[]).is_empty());
    }

    #[test]
    fn select_candidates_sorted_by_score_desc() {
        let planner = default_planner();
        let entries = vec![
            entry(1, 40_000, 60_000), // score 0.60
            entry(2, 10_000, 90_000), // score 0.90
            entry(3, 45_000, 55_000), // score 0.55 (live_ratio 0.45 < 0.5)
        ];
        let candidates = planner.select_candidates(&entries);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].segment_id, 2); // score 0.90
        assert_eq!(candidates[1].segment_id, 1); // score 0.60
        assert_eq!(candidates[2].segment_id, 3); // score 0.55
    }

    #[test]
    fn select_candidates_tiebreak_by_live_bytes_desc() {
        let planner = default_planner();
        let entries = vec![entry(10, 30_000, 70_000), entry(20, 60_000, 140_000)];
        let candidates = planner.select_candidates(&entries);
        assert_eq!(candidates[0].segment_id, 20);
        assert_eq!(candidates[1].segment_id, 10);
    }

    #[test]
    fn select_candidates_tiebreak_by_segment_id_asc() {
        let planner = default_planner();
        let entries = vec![entry(30, 20_000, 80_000), entry(10, 20_000, 80_000)];
        let candidates = planner.select_candidates(&entries);
        assert_eq!(candidates[0].segment_id, 10);
        assert_eq!(candidates[1].segment_id, 30);
    }

    #[test]
    fn select_candidates_respects_batch_size() {
        let cfg = CompactionConfig {
            batch_size: 2,
            ..CompactionConfig::default()
        };
        let planner = MergePlanner::new(cfg);
        let mut entries = Vec::new();
        for i in 0..10u64 {
            entries.push(entry(i, 10_000, 90_000 + i * 100));
        }
        let candidates = planner.select_candidates(&entries);
        assert_eq!(candidates.len(), 2);
    }

    // --- form_groups ---

    #[test]
    fn form_groups_basic_packing() {
        let planner = default_planner();
        let candidates = vec![
            MergeCandidate::from_entry(&entry(1, 400_000, 100_000)),
            MergeCandidate::from_entry(&entry(2, 300_000, 200_000)),
            MergeCandidate::from_entry(&entry(3, 500_000, 300_000)),
        ];
        let groups = planner.form_groups(&candidates);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 2);
        assert_eq!(groups[0].source_segments, vec![1, 2]);
        assert_eq!(groups[0].total_live_bytes, 700_000);
    }

    #[test]
    fn form_groups_exceeding_target_starts_new_group() {
        let planner = default_planner();
        let candidates = vec![
            MergeCandidate::from_entry(&entry(1, 600_000, 100_000)),
            MergeCandidate::from_entry(&entry(2, 500_000, 200_000)),
            // 600K + 500K > 1 MiB -> group boundary: segment 1 alone (discarded).
            // Segment 2 starts new group.
            MergeCandidate::from_entry(&entry(3, 300_000, 100_000)),
            // 500K + 300K = 800K fits.
            MergeCandidate::from_entry(&entry(4, 200_000, 300_000)),
            // 500K + 300K + 200K = 1M fits.
        ];
        let groups = planner.form_groups(&candidates);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].source_segments, vec![2, 3, 4]);
        assert_eq!(groups[0].total_live_bytes, 1_000_000);
    }

    #[test]
    fn form_groups_discards_singletons() {
        let planner = default_planner();
        let candidates = vec![
            MergeCandidate::from_entry(&entry(1, 900_000, 100_000)),
            MergeCandidate::from_entry(&entry(2, 200_000, 50_000)),
        ];
        assert!(planner.form_groups(&candidates).is_empty());
    }

    #[test]
    fn form_groups_empty_input() {
        let planner = default_planner();
        assert!(planner.form_groups(&[]).is_empty());
    }

    #[test]
    fn form_groups_single_candidate_discarded() {
        let planner = default_planner();
        let candidates = vec![MergeCandidate::from_entry(&entry(1, 100_000, 900_000))];
        assert!(planner.form_groups(&candidates).is_empty());
    }

    #[test]
    fn form_groups_all_in_one() {
        let planner = default_planner();
        let candidates = vec![
            MergeCandidate::from_entry(&entry(1, 100_000, 600_000)),
            MergeCandidate::from_entry(&entry(2, 200_000, 300_000)),
            MergeCandidate::from_entry(&entry(3, 150_000, 800_000)),
        ];
        let groups = planner.form_groups(&candidates);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 3);
    }

    // --- MergePlan ---

    #[test]
    fn merge_plan_empty() {
        let plan = MergePlan {
            groups: Vec::new(),
            plan_hash: MergePlan::compute_plan_hash(&[]),
            total_source_segments: 0,
            total_live_bytes: 0,
            estimated_reclaimed_bytes: 0,
        };
        assert!(plan.is_empty());
        assert_eq!(plan.group_count(), 0);
        assert!(plan.verify());
    }

    #[test]
    fn merge_plan_verify_detects_tampering() {
        let planner = default_planner();
        let entries = vec![entry(1, 30_000, 70_000), entry(2, 40_000, 60_000)];
        let mut plan = planner.plan(&entries);
        plan.groups[0].total_live_bytes = 0;
        assert!(!plan.verify());
    }

    #[test]
    fn merge_plan_hash_deterministic() {
        let planner = default_planner();
        let entries = vec![entry(1, 30_000, 70_000), entry(2, 40_000, 60_000)];
        let plan1 = planner.plan(&entries);
        let plan2 = planner.plan(&entries);
        assert_eq!(plan1.plan_hash, plan2.plan_hash);
        assert_eq!(plan1, plan2);
    }

    #[test]
    fn merge_plan_hash_differs_with_different_input() {
        let planner = default_planner();
        let p1 = planner.plan(&[entry(1, 30_000, 70_000), entry(2, 40_000, 60_000)]);
        let p2 = planner.plan(&[entry(10, 30_000, 70_000), entry(20, 40_000, 60_000)]);
        assert_ne!(p1.plan_hash, p2.plan_hash);
    }

    // --- plan integration ---

    #[test]
    fn plan_integrates_candidate_selection_and_grouping() {
        let planner = default_planner();
        let entries = vec![
            entry(1, 30_000, 70_000),
            entry(2, 40_000, 60_000),
            entry(3, 20_000, 80_000),
            entry(4, 80_000, 20_000),
        ];
        let plan = planner.plan(&entries);
        assert!(!plan.is_empty());
        assert!(plan.verify());
        assert!(plan.total_source_segments >= 3);
        assert_eq!(
            plan.total_source_segments,
            plan.groups.iter().map(|g| g.len()).sum::<usize>()
        );
        assert!(plan.total_live_bytes <= 170_000);
    }

    #[test]
    fn plan_empty_input() {
        let planner = default_planner();
        let plan = planner.plan(&[]);
        assert!(plan.is_empty());
        assert!(plan.verify());
        assert_eq!(plan.total_source_segments, 0);
        assert_eq!(plan.total_live_bytes, 0);
        assert_eq!(plan.estimated_reclaimed_bytes, 0);
    }

    #[test]
    fn plan_no_qualifying_candidates() {
        let planner = default_planner();
        let entries = vec![entry(1, 90_000, 10_000), entry(2, 95_000, 5_000)];
        let plan = planner.plan(&entries);
        assert!(plan.is_empty());
        assert!(plan.verify());
    }

    #[test]
    fn plan_with_custom_liveness_threshold() {
        let cfg = CompactionConfig {
            liveness_threshold: 0.75,
            ..CompactionConfig::default()
        };
        let planner = MergePlanner::new(cfg);
        let entries = vec![
            entry(1, 60_000, 40_000),
            entry(2, 70_000, 30_000),
            entry(3, 80_000, 20_000),
        ];
        let plan = planner.plan(&entries);
        assert_eq!(plan.total_source_segments, 2);
        let ids: Vec<u64> = plan
            .groups
            .iter()
            .flat_map(|g| g.source_segments.iter().copied())
            .collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
        assert!(!ids.contains(&3));
    }

    #[test]
    fn plan_with_custom_min_live_bytes() {
        let cfg = CompactionConfig {
            min_live_bytes: 20_000,
            ..CompactionConfig::default()
        };
        let planner = MergePlanner::new(cfg);
        let entries = vec![
            entry(1, 15_000, 85_000), // rejected: live < 20K (though live_ratio 0.15 qualifies)
            entry(2, 50_000, 70_000), // qualifies: live_ratio 0.416 < 0.5, live >= 20K
            entry(3, 25_000, 75_000), // qualifies: live_ratio 0.25 < 0.5, live >= 20K
        ];
        let plan = planner.plan(&entries);
        assert_eq!(plan.total_source_segments, 2);
    }

    #[test]
    fn plan_is_deterministic() {
        let planner = default_planner();
        let entries1 = vec![
            entry(3, 20_000, 80_000),
            entry(1, 30_000, 70_000),
            entry(2, 40_000, 60_000),
        ];
        let entries2 = vec![
            entry(2, 40_000, 60_000),
            entry(1, 30_000, 70_000),
            entry(3, 20_000, 80_000),
        ];
        assert_eq!(planner.plan(&entries1), planner.plan(&entries2));
    }

    // --- verify_plan ---

    #[test]
    fn verify_plan_valid() {
        let planner = default_planner();
        let entries = vec![entry(1, 30_000, 70_000), entry(2, 40_000, 60_000)];
        let plan = planner.plan(&entries);
        assert!(planner.verify_plan(&plan));
    }

    #[test]
    fn verify_plan_invalid_when_hash_mismatch() {
        let planner = default_planner();
        let entries = vec![entry(1, 30_000, 70_000), entry(2, 40_000, 60_000)];
        let mut plan = planner.plan(&entries);
        plan.plan_hash[0] ^= 0xFF;
        assert!(!planner.verify_plan(&plan));
    }
}
