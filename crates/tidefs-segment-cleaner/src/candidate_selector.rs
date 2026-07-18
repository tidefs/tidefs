// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pin-set-aware candidate filtering for segment cleaning.
//!
//! [`CandidateSelector`] extends the existing [`DeadObjectTracker`]-based
//! victim selection with gc-pin-set exclusion: segments containing blocks
//! reachable from pinned traversal roots (snapshots, in-progress destroy
//! jobs, active transaction groups) are filtered out before handoff.
//!
//! The selector produces a [`SegmentCandidate`] eligibility list. Fully-dead
//! segments stay cleaner-owned; partial live/dead candidates are handoff
//! records for the compaction authority, not a cleaner-local merge schedule.

use std::collections::HashSet;

use tidefs_gc_pin_set::GcPinSet;
use tidefs_types_dataset_lifecycle_core::TraversalRoot;

use crate::{DeadObjectTracker, PartialSegmentHandoff, PerSegmentLiveness, SegmentCleanerConfig};

// ---------------------------------------------------------------------------
// SegmentCandidate
// ---------------------------------------------------------------------------

/// A segment selected for potential cleaning, with liveness metadata.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SegmentCandidate {
    pub segment_id: u64,
    pub live_bytes: u64,
    pub dead_bytes: u64,
    pub total_bytes: u64,
    pub dead_ratio: f64,
    pub is_fully_dead: bool,
    pub creation_commit_group: u64,
}

impl SegmentCandidate {
    /// Construct a candidate from a per-segment liveness entry.
    #[must_use]
    pub fn from_liveness(entry: &PerSegmentLiveness) -> Self {
        let total = entry.total_bytes();
        let ratio = entry.dead_ratio();
        Self {
            segment_id: entry.segment_id,
            live_bytes: entry.live_bytes,
            dead_bytes: entry.dead_bytes,
            total_bytes: total,
            dead_ratio: ratio,
            is_fully_dead: entry.is_fully_dead(),
            creation_commit_group: entry.creation_commit_group,
        }
    }

    /// Estimated bytes reclaimable by cleaning this segment.
    #[must_use]
    pub const fn reclaimable_bytes(&self) -> u64 {
        self.dead_bytes
    }

    /// Whether this candidate meets a minimum dead-ratio threshold.
    #[must_use]
    pub fn meets_threshold(&self, min_ratio: f64) -> bool {
        self.dead_ratio >= min_ratio && self.dead_bytes > 0
    }

    #[must_use]
    pub fn partial_handoff(&self) -> Option<PartialSegmentHandoff> {
        PartialSegmentHandoff::new(
            self.segment_id,
            self.live_bytes,
            self.dead_bytes,
            self.creation_commit_group,
        )
    }
}

// ---------------------------------------------------------------------------
// CandidateSelector
// ---------------------------------------------------------------------------

/// Selects segment-cleaner candidates from [`DeadObjectTracker`] liveness
/// data, excluding pinned segments.
///
/// Pin-set exclusion operates in two modes:
///
/// 1. **Direct segment-id set**: pass `pinned_segments: &HashSet<u64>` to
///    `select()`. This is the primary API and the mode used in unit tests.
/// 2. **GcPinSet bridge**: use `select_with_pin_set()` with a mapping
///    closure that resolves each [`TraversalRoot`] to the set of segment
///    ids currently housing that root's blocks. The mapping closure is
///    supplied by the caller (typically [`SegmentCleanerDriver`]) which
///    owns the segment-to-block index.
///
/// [`SegmentCleanerDriver`]: crate::SegmentCleanerDriver
pub struct CandidateSelector {
    config: SegmentCleanerConfig,
    max_candidates: usize,
}

impl CandidateSelector {
    /// Create a new candidate selector.
    #[must_use]
    pub const fn new(config: SegmentCleanerConfig, max_candidates: usize) -> Self {
        Self {
            config,
            max_candidates,
        }
    }

    /// Maximum number of candidates returned per invocation.
    #[must_use]
    pub const fn max_candidates(&self) -> usize {
        self.max_candidates
    }

    /// Select candidate segments from the tracker, excluding any
    /// segments whose id appears in `pinned_segments`.
    ///
    /// Candidates are ordered by cleaner ownership only: fully-dead segments
    /// first, then by segment id for deterministic handoff. The result is
    /// capped at `max_candidates`. Partial merge ordering belongs to
    /// `tidefs-compaction`.
    ///
    /// Segments that fail the `min_dead_ratio` threshold or are too
    /// young (below `min_segment_age_txg`) are excluded. Fully-dead
    /// segments bypass the age guard.
    #[must_use]
    pub fn select(
        &self,
        tracker: &DeadObjectTracker,
        current_commit_group: u64,
        pinned_segments: &HashSet<u64>,
    ) -> Vec<SegmentCandidate> {
        let mut candidates: Vec<SegmentCandidate> = tracker
            .entries()
            .filter(|e| !e.is_empty())
            .filter(|e| !pinned_segments.contains(&e.segment_id))
            .filter(|e| {
                // Fully-dead segments always qualify; others must meet
                // the dead-ratio threshold and age guard.
                e.is_fully_dead()
                    || (e.dead_ratio() >= self.config.min_dead_ratio
                        && e.dead_bytes > 0
                        && e.is_old_enough(current_commit_group, self.config.min_segment_age_txg))
            })
            .map(SegmentCandidate::from_liveness)
            .collect();

        // Cleaner-owned freeing first, then stable handoff order. This is not
        // a partial merge ranking policy.
        candidates.sort_by(|a, b| {
            b.is_fully_dead
                .cmp(&a.is_fully_dead)
                .then_with(|| a.segment_id.cmp(&b.segment_id))
        });

        candidates.truncate(self.max_candidates);
        candidates
    }

    /// Select candidates using a [`GcPinSet`] to derive excluded
    /// segment ids via the `resolve` closure.
    ///
    /// The closure receives each pinned [`TraversalRoot`] and returns an
    /// iterator of segment ids that contain blocks reachable from that
    /// root. All such segments are excluded from candidate selection.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let selector = CandidateSelector::new(config, 32);
    /// let candidates = selector.select_with_pin_set(
    ///     &tracker,
    ///     7,
    ///     &pin_set,
    ///     |root| segment_index.segments_for_root(root).into_iter(),
    /// );
    /// ```
    #[must_use]
    pub fn select_with_pin_set<const N: usize, F, I>(
        &self,
        tracker: &DeadObjectTracker,
        current_commit_group: u64,
        pin_set: &GcPinSet<N>,
        resolve: F,
    ) -> Vec<SegmentCandidate>
    where
        F: Fn(&TraversalRoot) -> I,
        I: IntoIterator<Item = u64>,
    {
        let mut pinned: HashSet<u64> = HashSet::new();
        for root in pin_set.pinned_roots() {
            for seg_id in resolve(root) {
                pinned.insert(seg_id);
            }
        }
        self.select(tracker, current_commit_group, &pinned)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker_with_segments(entries: &[(u64, u64, u64, u64)]) -> DeadObjectTracker {
        let mut t = DeadObjectTracker::new();
        for &(seg, live, dead, commit_group) in entries {
            t.record_write_at_commit_group(seg, live + dead, commit_group);
            if dead > 0 {
                t.record_overwrite(seg, dead);
            }
        }
        t
    }

    fn default_selector() -> CandidateSelector {
        CandidateSelector::new(SegmentCleanerConfig::default(), 32)
    }

    // -- Live-data ratio computation --

    #[test]
    fn ratio_fully_live_is_zero() {
        let t = tracker_with_segments(&[(1, 1000, 0, 0)]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            32,
        );
        let candidates = s.select(&t, 0, &HashSet::new());
        assert_eq!(
            candidates.len(),
            0,
            "0% dead below min_dead_ratio=0.0 requires dead_bytes>0 for fully-dead bypass"
        );
    }

    #[test]
    fn ratio_fully_dead_is_one() {
        let t = tracker_with_segments(&[(1, 0, 1000, 0)]);
        let s = default_selector();
        let candidates = s.select(&t, 0, &HashSet::new());
        assert_eq!(candidates.len(), 1);
        assert!((candidates[0].dead_ratio - 1.0).abs() < f64::EPSILON);
        assert!(candidates[0].is_fully_dead);
    }

    #[test]
    fn ratio_equal_split_is_half() {
        let t = tracker_with_segments(&[(1, 500, 500, 0)]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            32,
        );
        let candidates = s.select(&t, 0, &HashSet::new());
        assert_eq!(candidates.len(), 1);
        let r = candidates[0].dead_ratio;
        assert!(r > 0.49 && r < 0.51, "expected ~0.50, got {r}");
    }

    // -- Pin-set exclusion --

    #[test]
    fn pinned_segment_filtered_out() {
        let t = tracker_with_segments(&[(1, 100, 900, 0), (2, 200, 800, 0)]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            32,
        );
        let mut pinned = HashSet::new();
        pinned.insert(1);
        let candidates = s.select(&t, 0, &pinned);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].segment_id, 2);
    }

    #[test]
    fn unpinned_segment_retained() {
        let t = tracker_with_segments(&[(1, 100, 900, 0)]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            32,
        );
        let candidates = s.select(&t, 0, &HashSet::new());
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].segment_id, 1);
    }

    #[test]
    fn all_pinned_yields_empty() {
        let t = tracker_with_segments(&[(1, 100, 900, 0), (2, 200, 800, 0), (3, 300, 700, 0)]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            32,
        );
        let pinned: HashSet<u64> = [1, 2, 3].into_iter().collect();
        let candidates = s.select(&t, 0, &pinned);
        assert!(candidates.is_empty());
    }

    // -- Handoff ordering --

    #[test]
    fn partial_candidates_use_stable_handoff_order() {
        let t = tracker_with_segments(&[
            (1, 900, 100, 0), // ratio 0.10
            (2, 500, 500, 0), // ratio 0.50
            (3, 100, 900, 0), // ratio 0.90
        ]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            32,
        );
        let candidates = s.select(&t, 0, &HashSet::new());
        assert_eq!(candidates.len(), 3);
        let ids: Vec<u64> = candidates.iter().map(|c| c.segment_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    // -- Empty sets --

    #[test]
    fn empty_tracker_yields_empty_candidates() {
        let t = DeadObjectTracker::new();
        let s = default_selector();
        assert!(s.select(&t, 0, &HashSet::new()).is_empty());
    }

    #[test]
    fn empty_segment_set_is_skipped() {
        let t = tracker_with_segments(&[(1, 0, 0, 0)]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            32,
        );
        assert!(s.select(&t, 0, &HashSet::new()).is_empty());
    }

    // -- Batch bounding --

    #[test]
    fn max_candidates_respected() {
        let mut entries = Vec::new();
        for i in 0..10u64 {
            entries.push((i, 100, 900 + i * 5, 0));
        }
        let t = tracker_with_segments(&entries);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            3,
        );
        let candidates = s.select(&t, 0, &HashSet::new());
        assert_eq!(candidates.len(), 3);
    }

    #[test]
    fn max_candidates_zero_returns_empty() {
        let t = tracker_with_segments(&[(1, 100, 900, 0)]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            0,
        );
        assert!(s.select(&t, 0, &HashSet::new()).is_empty());
    }

    #[test]
    fn max_candidates_larger_than_available_returns_all() {
        let t = tracker_with_segments(&[(1, 100, 900, 0), (2, 200, 800, 0)]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            100,
        );
        assert_eq!(s.select(&t, 0, &HashSet::new()).len(), 2);
    }

    // -- Age guard --

    #[test]
    fn age_guard_skips_too_young_segments() {
        let t = tracker_with_segments(&[
            (1, 100, 900, 100), // created at commit_group 100
            (2, 100, 900, 5),   // created at commit_group 5
        ]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.3,
                min_segment_age_txg: 2,
                ..Default::default()
            },
            32,
        );
        let candidates = s.select(&t, 10, &HashSet::new());
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].segment_id, 2);
    }

    #[test]
    fn fully_dead_bypasses_age_guard() {
        let t = tracker_with_segments(&[
            (1, 0, 1000, 100), // fully dead, too young
            (2, 50, 50, 5),    // partial, old enough
        ]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 2,
                ..Default::default()
            },
            32,
        );
        let candidates = s.select(&t, 10, &HashSet::new());
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0].segment_id, 1,
            "fully-dead should be first and bypass age"
        );
        assert_eq!(candidates[1].segment_id, 2);
    }

    // -- Threshold filtering --

    #[test]
    fn respects_min_dead_ratio() {
        let t = tracker_with_segments(&[
            (1, 900, 100, 0), // 0.10
            (2, 500, 500, 0), // 0.50
            (3, 100, 900, 0), // 0.90
        ]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.40,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            32,
        );
        let candidates = s.select(&t, 0, &HashSet::new());
        assert_eq!(candidates.len(), 2);
        let ids: Vec<u64> = candidates.iter().map(|c| c.segment_id).collect();
        assert!(ids.contains(&2));
        assert!(ids.contains(&3));
    }

    // -- Stable partial handoff order --

    #[test]
    fn partial_handoff_order_ignores_merge_policy_scores() {
        let t = tracker_with_segments(&[
            (50, 500, 500, 0), // ratio 0.50, dead 500
            (10, 500, 500, 0), // ratio 0.50, dead 500
            (20, 200, 800, 0), // ratio 0.80, dead 800
        ]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            32,
        );
        let candidates = s.select(&t, 0, &HashSet::new());
        let ids: Vec<u64> = candidates.iter().map(|c| c.segment_id).collect();
        assert_eq!(ids, vec![10, 20, 50]);
    }

    // -- GcPinSet bridge --

    #[test]
    fn select_with_pin_set_excludes_mapped_segments() {
        // Build a minimal GcPinSet with one InodeTable root pinned.
        let mut pin_set = GcPinSet::<6>::new();
        let root = TraversalRoot::new(
            tidefs_types_dataset_lifecycle_core::TraversalRootType::InodeTable,
            tidefs_types_dataset_lifecycle_core::LifecycleRootIdentityV1::new(42, 1).unwrap(),
            100,
        );
        pin_set.pin(root).unwrap();

        let t = tracker_with_segments(&[(1, 100, 900, 0), (2, 200, 800, 0)]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            32,
        );

        // Map the InodeTable root to segment 1.
        let candidates = s.select_with_pin_set(&t, 0, &pin_set, |root| {
            if root.root_type == tidefs_types_dataset_lifecycle_core::TraversalRootType::InodeTable
            {
                vec![1]
            } else {
                vec![]
            }
        });
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].segment_id, 2);
    }

    #[test]
    fn select_with_pin_set_empty_pin_set_returns_all() {
        let pin_set = GcPinSet::<6>::new();
        let t = tracker_with_segments(&[(1, 100, 900, 0), (2, 200, 800, 0)]);
        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.0,
                min_segment_age_txg: 0,
                ..Default::default()
            },
            32,
        );
        let candidates = s.select_with_pin_set(&t, 0, &pin_set, |_| vec![]);
        assert_eq!(candidates.len(), 2);
    }

    // -- SegmentCandidate helpers --

    #[test]
    fn candidate_reclaimable_bytes() {
        let c = SegmentCandidate {
            segment_id: 1,
            live_bytes: 300,
            dead_bytes: 700,
            total_bytes: 1000,
            dead_ratio: 0.70,
            is_fully_dead: false,
            creation_commit_group: 5,
        };
        assert_eq!(c.reclaimable_bytes(), 700);
    }

    #[test]
    fn candidate_meets_threshold() {
        let c = SegmentCandidate {
            segment_id: 1,
            live_bytes: 300,
            dead_bytes: 700,
            total_bytes: 1000,
            dead_ratio: 0.70,
            is_fully_dead: false,
            creation_commit_group: 5,
        };
        assert!(c.meets_threshold(0.0));
        assert!(c.meets_threshold(0.70));
        assert!(!c.meets_threshold(0.71));
    }

    #[test]
    fn candidate_meets_threshold_requires_dead_bytes() {
        let c = SegmentCandidate {
            segment_id: 1,
            live_bytes: 1000,
            dead_bytes: 0,
            total_bytes: 1000,
            dead_ratio: 0.0,
            is_fully_dead: false,
            creation_commit_group: 0,
        };
        assert!(!c.meets_threshold(0.0));
    }

    // -- Integration-like scenario --

    #[test]
    fn pin_aware_selection_pipeline() {
        let t = tracker_with_segments(&[
            (0, 10000, 90000, 3),
            (1, 30000, 70000, 3),
            (2, 50000, 50000, 3),
            (3, 70000, 30000, 3),
            (4, 90000, 10000, 3),
        ]);
        let mut pinned = HashSet::new();
        pinned.insert(0);
        pinned.insert(2);

        let s = CandidateSelector::new(
            SegmentCleanerConfig {
                min_dead_ratio: 0.3,
                min_segment_age_txg: 2,
                ..Default::default()
            },
            3,
        );
        let candidates = s.select(&t, 5, &pinned);
        assert_eq!(candidates.len(), 2); // 0 and 2 excluded, 4 below threshold
        assert_eq!(candidates[0].segment_id, 1); // 0.70 ratio
        assert_eq!(candidates[1].segment_id, 3); // 0.30 ratio
    }
}
