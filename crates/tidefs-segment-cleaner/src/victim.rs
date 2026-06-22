// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Liveness-based cleaner candidate selection.
//!
//! [`VictimSelector`] wraps a [`SegmentLivenessQueue`] and
//! [`SegmentCleanerConfig`] to produce cleaner-owned fully-dead candidates
//! and partial live/dead handoff records for the compaction authority.

use core::fmt;

use tidefs_reclaim_queue_core::SegmentLivenessQueue;

use crate::{PartialSegmentHandoff, SegmentCleanerConfig};

// ---------------------------------------------------------------------------
// VictimCandidate -- cleaner eligibility record
// ---------------------------------------------------------------------------

/// A segment identified as a cleaner candidate, together with
/// its liveness metadata.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VictimCandidate {
    /// Segment identifier.
    pub segment_id: u64,
    /// Bytes still referenced by live objects.
    pub live_bytes: u64,
    /// Bytes eligible for reclamation.
    pub dead_bytes: u64,
    /// Total accounted bytes in the segment.
    pub total_bytes: u64,
    /// Dead-byte fraction in [0.0, 1.0].
    pub dead_ratio: f64,
    /// Whether the segment is fully dead (zero live bytes).
    pub is_fully_dead: bool,
    /// Transaction group when this segment was first written.
    pub creation_commit_group: u64,
}

impl VictimCandidate {
    /// Construct a candidate from a segment-liveness entry.
    #[must_use]
    pub fn from_entry(
        segment_id: u64,
        live_bytes: u64,
        dead_bytes: u64,
        creation_commit_group: u64,
    ) -> Self {
        let total = live_bytes.saturating_add(dead_bytes);
        let ratio = if total == 0 {
            0.0
        } else {
            dead_bytes as f64 / total as f64
        };
        Self {
            segment_id,
            live_bytes,
            dead_bytes,
            total_bytes: total,
            dead_ratio: ratio,
            is_fully_dead: live_bytes == 0 && dead_bytes > 0,
            creation_commit_group,
        }
    }

    /// The estimated number of bytes that can be reclaimed by
    /// compacting this segment.
    #[must_use]
    pub const fn reclaimable_bytes(&self) -> u64 {
        self.dead_bytes
    }

    /// Returns `true` if this segment meets a minimum dead-ratio
    /// threshold.
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

impl fmt::Display for VictimCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "segment={} live={} dead={} ratio={:.4} fully_dead={}",
            self.segment_id, self.live_bytes, self.dead_bytes, self.dead_ratio, self.is_fully_dead
        )
    }
}

// ---------------------------------------------------------------------------
// VictimSelector
// ---------------------------------------------------------------------------

/// Selects segment-cleaner victims by liveness eligibility.
///
/// Fully-dead segments are cleaner-owned free work. Partially live segments
/// are returned as compaction-authority handoff records and are ordered by
/// segment id only to avoid local merge-policy ownership.
#[derive(Clone, Debug)]
pub struct VictimSelector {
    /// The liveness queue to query.
    pub queue: SegmentLivenessQueue,
    /// Cleaner configuration controlling thresholds.
    pub config: SegmentCleanerConfig,
}

impl VictimSelector {
    /// Create a new victim selector with the given liveness queue
    /// and cleaner configuration.
    #[must_use]
    pub const fn new(queue: SegmentLivenessQueue, config: SegmentCleanerConfig) -> Self {
        Self { queue, config }
    }

    /// Select the first eligible candidate above the configured
    /// `min_dead_ratio`, respecting the minimum segment age.
    ///
    /// Returns `None` when no segment meets the criteria.
    #[must_use]
    pub fn select(&self, current_commit_group: u64) -> Option<u64> {
        self.select_batch(current_commit_group, 1).into_iter().next()
    }

    /// Select up to `limit` candidates in cleaner-owned order, respecting
    /// the configured thresholds and minimum segment age.
    ///
    /// Returns an empty vector when no segment qualifies.
    #[must_use]
    pub fn select_batch(&self, current_commit_group: u64, limit: usize) -> Vec<u64> {
        if limit == 0 {
            return Vec::new();
        }
        let mut candidates: Vec<_> = self
            .queue
            .entries()
            .filter(|e| {
                e.dead_ratio() >= self.config.min_dead_ratio
                    && e.dead_bytes > 0
                    && (e.is_fully_dead()
                        || e.is_old_enough(current_commit_group, self.config.min_segment_age_txg))
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

    /// Return the first eligible candidate together with its full liveness
    /// metadata. Useful for logging and metrics.
    #[must_use]
    pub fn select_with_metadata(&self, current_commit_group: u64) -> Option<VictimCandidate> {
        let seg_id = self.select(current_commit_group)?;
        let entry = self.queue.get(seg_id)?;
        Some(VictimCandidate::from_entry(
            entry.segment_id,
            entry.live_bytes,
            entry.dead_bytes,
            entry.creation_commit_group,
        ))
    }

    /// Return a batch of candidates with full metadata.
    #[must_use]
    pub fn select_batch_with_metadata(
        &self,
        current_commit_group: u64,
        limit: usize,
    ) -> Vec<VictimCandidate> {
        self.select_batch(current_commit_group, limit)
            .into_iter()
            .filter_map(|id| {
                self.queue.get(id).map(|e| {
                    VictimCandidate::from_entry(
                        e.segment_id,
                        e.live_bytes,
                        e.dead_bytes,
                        e.creation_commit_group,
                    )
                })
            })
            .collect()
    }

    #[must_use]
    pub fn partial_handoffs(
        &self,
        current_commit_group: u64,
        limit: usize,
    ) -> Vec<PartialSegmentHandoff> {
        self.select_batch_with_metadata(current_commit_group, limit)
            .into_iter()
            .filter_map(|candidate| candidate.partial_handoff())
            .collect()
    }

    /// Return all candidates (up to a safety limit) in cleaner-owned order.
    ///
    /// The limit prevents unbounded memory use. The default value
    /// (1024) covers practical pool sizes.
    #[must_use]
    pub fn all_candidates(&self, current_commit_group: u64) -> Vec<u64> {
        self.select_batch(current_commit_group, 1024)
    }

    /// Number of segments currently tracked in the liveness queue.
    #[must_use]
    pub fn tracked_segments(&self) -> usize {
        self.queue.len()
    }

    /// Total live bytes across all tracked segments.
    #[must_use]
    pub fn total_live_bytes(&self) -> u64 {
        self.queue.total_live_bytes()
    }

    /// Total dead bytes across all tracked segments.
    #[must_use]
    pub fn total_dead_bytes(&self) -> u64 {
        self.queue.total_dead_bytes()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(min_dead_ratio: f64, min_age: u64) -> SegmentCleanerConfig {
        SegmentCleanerConfig {
            min_dead_ratio,
            min_segment_age_txg: min_age,
            ..SegmentCleanerConfig::default()
        }
    }

    fn make_selector() -> VictimSelector {
        VictimSelector::new(SegmentLivenessQueue::new(), SegmentCleanerConfig::default())
    }

    // -- Construction --

    #[test]
    fn new_selector_is_empty() {
        let s = make_selector();
        assert_eq!(s.tracked_segments(), 0);
        assert_eq!(s.total_live_bytes(), 0);
        assert_eq!(s.total_dead_bytes(), 0);
        assert_eq!(s.select(0), None);
    }

    // -- Single candidate selection --

    #[test]
    fn select_lowest_partial_segment_id() {
        let mut q = SegmentLivenessQueue::new();
        // seg 10: 900 live, 100 dead (ratio 0.10)
        q.record_write(10, 1000);
        q.record_overwrite(10, 100);
        // seg 20: 500 live, 500 dead (ratio 0.50)
        q.record_write(20, 1000);
        q.record_overwrite(20, 500);
        // seg 30: 100 live, 900 dead (ratio 0.90)
        q.record_write(30, 1000);
        q.record_overwrite(30, 900);

        let s = VictimSelector::new(q, make_config(0.0, 0));
        assert_eq!(s.select(0), Some(10));
    }

    #[test]
    fn select_fully_dead_before_partial_handoffs() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(10, 1000);
        q.record_overwrite(10, 900);
        q.record_write(50, 500);
        q.record_delete(50, 500);

        let s = VictimSelector::new(q, make_config(0.0, 0));
        assert_eq!(s.select(0), Some(50));
    }

    #[test]
    fn select_respects_min_dead_ratio() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 1000);
        q.record_overwrite(1, 200); // ratio 0.20
        q.record_write(2, 1000);
        q.record_overwrite(2, 500); // ratio 0.50

        let s = VictimSelector::new(q, make_config(0.30, 0));
        assert_eq!(s.select(0), Some(2));
    }

    #[test]
    fn select_below_threshold_is_none() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 1000);
        q.record_overwrite(1, 100); // ratio 0.10

        let s = VictimSelector::new(q, make_config(0.50, 0));
        assert_eq!(s.select(0), None);
    }

    #[test]
    fn select_empty_queue_is_none() {
        let s = make_selector();
        assert_eq!(s.select(0), None);
        assert_eq!(s.select(100), None);
    }

    // -- Tiebreaking --

    #[test]
    fn select_ignores_partial_dead_ratio_for_handoff_order() {
        let mut q = SegmentLivenessQueue::new();
        // Same dead ratio (0.50), same dead bytes
        q.record_write(50, 1000);
        q.record_overwrite(50, 500);
        q.record_write(10, 1000);
        q.record_overwrite(10, 500);

        let s = VictimSelector::new(q, make_config(0.0, 0));
        assert_eq!(s.select(0), Some(10)); // lower id wins

        // Now seg 50 has more dead bytes, but partial ordering stays stable.
        let mut q2 = SegmentLivenessQueue::new();
        q2.record_write(10, 1000);
        q2.record_overwrite(10, 500); // ratio 0.5, dead 500
        q2.record_write(50, 1000);
        q2.record_overwrite(50, 900); // ratio 0.9, dead 900

        let s2 = VictimSelector::new(q2, make_config(0.0, 0));
        assert_eq!(s2.select(0), Some(10));
    }

    // -- Batch selection --

    #[test]
    fn select_batch_returns_sorted_candidates() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write_at_commit_group(1, 1000, 0);
        q.record_overwrite(1, 900); // ratio 0.90
        q.record_write_at_commit_group(2, 1000, 0);
        q.record_overwrite(2, 200); // ratio 0.20
        q.record_write_at_commit_group(3, 1000, 0);
        q.record_overwrite(3, 500); // ratio 0.50
        q.record_write_at_commit_group(4, 1000, 0);
        q.record_overwrite(4, 800); // ratio 0.80
        q.record_write_at_commit_group(5, 1000, 0);
        q.record_overwrite(5, 100); // ratio 0.10

        let s = VictimSelector::new(q, make_config(0.0, 0));
        let batch = s.select_batch(0, 3);
        assert_eq!(batch, vec![1, 2, 3]);
    }

    #[test]
    fn select_batch_respects_threshold() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write_at_commit_group(1, 1000, 0);
        q.record_overwrite(1, 900); // 0.90
        q.record_write_at_commit_group(2, 1000, 0);
        q.record_overwrite(2, 200); // 0.20
        q.record_write_at_commit_group(3, 1000, 0);
        q.record_overwrite(3, 500); // 0.50

        let s = VictimSelector::new(q, make_config(0.40, 0));
        let batch = s.select_batch(0, 5);
        assert_eq!(batch, vec![1, 3]);
    }

    #[test]
    fn select_batch_limit_zero_is_empty() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 1000);
        q.record_overwrite(1, 500);

        let s = VictimSelector::new(q, make_config(0.0, 0));
        assert!(s.select_batch(0, 0).is_empty());
    }

    // -- Age guard --

    #[test]
    fn age_guard_skips_too_young_segments() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write_at_commit_group(0, 100, 5);
        q.record_overwrite(0, 70);
        q.record_write_at_commit_group(1, 100, 1);
        q.record_overwrite(1, 70);

        let s = VictimSelector::new(q, make_config(0.30, 2));
        assert_eq!(s.select(3), Some(1)); // seg 0 created at commit_group 5, too young at commit_group 3
    }

    #[test]
    fn age_guard_all_too_young_is_none() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write_at_commit_group(0, 100, 10);
        q.record_overwrite(0, 70);
        q.record_write_at_commit_group(1, 100, 11);
        q.record_overwrite(1, 70);

        let s = VictimSelector::new(q, make_config(0.30, 2));
        assert_eq!(s.select(11), None);
    }

    #[test]
    fn age_guard_creation_txg_zero_is_always_old_enough() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(0, 100);
        q.record_overwrite(0, 70);

        let s = VictimSelector::new(q, make_config(0.0, 100));
        assert_eq!(s.select(50), Some(0));
    }

    // -- Metadata selection --

    #[test]
    fn select_with_metadata_returns_full_candidate() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write_at_commit_group(7, 1000, 3);
        q.record_overwrite(7, 700);

        let s = VictimSelector::new(q, make_config(0.0, 0));
        let candidate = s.select_with_metadata(10).expect("should have candidate");
        assert_eq!(candidate.segment_id, 7);
        assert_eq!(candidate.live_bytes, 300);
        assert_eq!(candidate.dead_bytes, 700);
        assert_eq!(candidate.total_bytes, 1000);
        assert!((candidate.dead_ratio - 0.70).abs() < 0.001);
        assert!(!candidate.is_fully_dead);
        assert_eq!(candidate.creation_commit_group, 3);
        assert_eq!(candidate.reclaimable_bytes(), 700);
    }

    #[test]
    fn select_with_metadata_fully_dead() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 500);
        q.record_delete(1, 500);

        let s = VictimSelector::new(q, make_config(0.0, 0));
        let candidate = s.select_with_metadata(0).expect("should have candidate");
        assert!(candidate.is_fully_dead);
        assert_eq!(candidate.live_bytes, 0);
    }

    #[test]
    fn select_with_metadata_empty_is_none() {
        let s = make_selector();
        assert_eq!(s.select_with_metadata(0), None);
    }

    // -- Batch metadata selection --

    #[test]
    fn select_batch_with_metadata_returns_ordered_candidates() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write_at_commit_group(1, 1000, 0);
        q.record_overwrite(1, 900);
        q.record_write_at_commit_group(2, 1000, 0);
        q.record_overwrite(2, 500);
        q.record_write_at_commit_group(3, 1000, 0);
        q.record_overwrite(3, 100);

        let s = VictimSelector::new(q, make_config(0.0, 0));
        let batch = s.select_batch_with_metadata(0, 4);
        assert_eq!(batch.len(), 3);
        assert_eq!(
            batch
                .iter()
                .map(|candidate| candidate.segment_id)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn select_batch_with_metadata_empty_is_empty() {
        let s = make_selector();
        assert!(s.select_batch_with_metadata(0, 10).is_empty());
    }

    // -- all_candidates --

    #[test]
    fn all_candidates_returns_all_eligible() {
        let mut q = SegmentLivenessQueue::new();
        for i in 0..5u64 {
            q.record_write_at_commit_group(i, 1000, 0);
            q.record_overwrite(i, (i + 1) * 100);
        }
        let s = VictimSelector::new(q, make_config(0.0, 0));
        let all = s.all_candidates(0);
        assert_eq!(all.len(), 5);
        assert_eq!(all, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn all_candidates_respects_threshold() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(0, 1000);
        q.record_overwrite(0, 900); // 0.90
        q.record_write(1, 1000);
        q.record_overwrite(1, 200); // 0.20
        q.record_write(2, 1000);
        q.record_overwrite(2, 100); // 0.10

        let s = VictimSelector::new(q, make_config(0.50, 0));
        let all = s.all_candidates(0);
        assert_eq!(all, vec![0]);
    }

    // -- Totals --

    #[test]
    fn total_live_and_dead_bytes() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 1000);
        q.record_overwrite(1, 300);
        q.record_write(2, 2000);
        q.record_overwrite(2, 500);
        q.record_delete(3, 1500);

        let s = VictimSelector::new(q, make_config(0.0, 0));
        assert_eq!(s.total_live_bytes(), 2200); // 700 + 1500 + 0
        assert_eq!(s.total_dead_bytes(), 2300); // 300 + 500 + 1500
    }

    // -- VictimCandidate helpers --

    #[test]
    fn victim_candidate_meets_threshold() {
        let c = VictimCandidate::from_entry(1, 300, 700, 0);
        assert!(c.meets_threshold(0.0));
        assert!(c.meets_threshold(0.50));
        assert!(c.meets_threshold(0.70));
        assert!(!c.meets_threshold(0.71));
    }

    #[test]
    fn victim_candidate_meets_threshold_requires_dead_bytes() {
        let c = VictimCandidate::from_entry(1, 1000, 0, 0); // ratio 0.0
        assert!(!c.meets_threshold(0.0));
    }

    #[test]
    fn victim_candidate_display() {
        let c = VictimCandidate::from_entry(42, 300, 700, 5);
        let s = format!("{c}");
        assert!(s.contains("segment=42"));
        assert!(s.contains("live=300"));
        assert!(s.contains("dead=700"));
        assert!(s.contains("fully_dead=false"));
    }

    #[test]
    fn victim_candidate_fully_dead_display() {
        let c = VictimCandidate::from_entry(99, 0, 4096, 1);
        assert!(c.is_fully_dead);
        let s = format!("{c}");
        assert!(s.contains("fully_dead=true"));
    }

    // -- Integration scenario --

    #[test]
    fn cleaner_selection_pipeline() {
        let mut q = SegmentLivenessQueue::new();

        // 10 segments written at commit_group 3
        for seg in 0..10u64 {
            q.record_write_at_commit_group(seg, 100_000, 3);
        }
        // Overwrites and deletes from commit_group 3-5
        q.record_overwrite(0, 90_000);
        q.record_overwrite(1, 70_000);
        q.record_delete(2, 50_000);
        q.record_overwrite(3, 30_000);
        q.record_delete(4, 10_000);

        let s = VictimSelector::new(q, make_config(0.30, 2));

        // At commit_group 5: segs 0-4 are old enough (5-3=2 >= 2);
        // segment 0 is the lowest eligible partial segment id.
        assert_eq!(s.select(5), Some(0));

        // At commit_group 5 batch returns the first 3 eligible ids.
        let batch = s.select_batch(5, 3);
        assert_eq!(batch, vec![0, 1, 2]);

        // At commit_group 4: none are old enough (4-3=1 < 2)
        assert_eq!(s.select(4), None);
    }
}
