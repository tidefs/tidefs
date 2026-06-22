// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Segment cleaning decision engine: consumes [`SegmentLivenessQueue`]
//! dead/live byte accounting and emits cleaner-owned fully-dead work plus
//! partial live/dead handoff records for the compaction authority.
//!
//! # Persistence
//!
//! [`SegmentCleaner::persist_intent`] writes the current queue state to a
//! [`ReclaimQueueStorage`] backend so cleaning progress survives restarts.
//! [`SegmentCleaner::load_from_storage`] restores the persisted queue on
//! startup.

use tidefs_reclaim_queue_core::{
    ReclaimQueueStorage, SegmentLivenessEntry, SegmentLivenessPersistError, SegmentLivenessQueue,
};

use crate::{PartialSegmentHandoff, SegmentCleanerConfig};

// ---------------------------------------------------------------------------
// CleaningCandidate -- a single entry in the cleaning schedule
// ---------------------------------------------------------------------------

/// A segment identified for cleaning or compaction-authority handoff,
/// together with its liveness metadata and reclaimable-byte yield.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CleaningCandidate {
    pub segment_id: u64,
    pub live_bytes: u64,
    pub dead_bytes: u64,
    pub reclaimable_bytes: u64,
    pub dead_ratio: f64,
    pub is_fully_dead: bool,
    pub creation_commit_group: u64,
}

impl CleaningCandidate {
    #[must_use]
    pub fn from_entry(entry: &SegmentLivenessEntry) -> Self {
        let total = entry.live_bytes.saturating_add(entry.dead_bytes);
        let ratio = if total == 0 {
            0.0
        } else {
            entry.dead_bytes as f64 / total as f64
        };
        Self {
            segment_id: entry.segment_id,
            live_bytes: entry.live_bytes,
            dead_bytes: entry.dead_bytes,
            reclaimable_bytes: entry.dead_bytes,
            dead_ratio: ratio,
            is_fully_dead: entry.is_fully_dead(),
            creation_commit_group: entry.creation_commit_group,
        }
    }

    #[must_use]
    pub const fn meets_threshold(&self, min_reclaimable_bytes: u64) -> bool {
        self.reclaimable_bytes >= min_reclaimable_bytes && self.reclaimable_bytes > 0
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
// SegmentCleaner -- cleaning decision engine
// ---------------------------------------------------------------------------

pub struct SegmentCleaner {
    pub queue: SegmentLivenessQueue,
    pub config: SegmentCleanerConfig,
    pub min_reclaimable_bytes: u64,
}

impl SegmentCleaner {
    #[must_use]
    pub fn new(
        queue: SegmentLivenessQueue,
        config: SegmentCleanerConfig,
        min_reclaimable_bytes: u64,
    ) -> Self {
        Self {
            queue,
            config,
            min_reclaimable_bytes,
        }
    }

    #[must_use]
    pub fn empty(config: SegmentCleanerConfig, min_reclaimable_bytes: u64) -> Self {
        Self {
            queue: SegmentLivenessQueue::new(),
            config,
            min_reclaimable_bytes,
        }
    }

    #[must_use]
    pub fn tracked_segments(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    pub fn total_live_bytes(&self) -> u64 {
        self.queue.total_live_bytes()
    }

    #[must_use]
    pub fn total_dead_bytes(&self) -> u64 {
        self.queue.total_dead_bytes()
    }

    #[must_use]
    pub fn plan_cleaning(&self, current_commit_group: u64) -> Vec<CleaningCandidate> {
        let mut candidates: Vec<CleaningCandidate> = self
            .queue
            .entries()
            .filter(|e| {
                e.dead_bytes >= self.min_reclaimable_bytes
                    && e.dead_ratio() >= self.config.min_dead_ratio
                    && (e.is_fully_dead()
                        || e.is_old_enough(current_commit_group, self.config.min_segment_age_txg))
            })
            .map(CleaningCandidate::from_entry)
            .collect();

        candidates.sort_by(|a, b| {
            b.is_fully_dead
                .cmp(&a.is_fully_dead)
                .then_with(|| a.segment_id.cmp(&b.segment_id))
        });

        candidates
    }

    #[must_use]
    pub fn partial_compaction_handoffs(
        &self,
        current_commit_group: u64,
    ) -> Vec<PartialSegmentHandoff> {
        self.plan_cleaning(current_commit_group)
            .into_iter()
            .filter_map(|candidate| candidate.partial_handoff())
            .collect()
    }

    #[must_use]
    pub fn plan_cleaning_bounded(
        &self,
        current_commit_group: u64,
        max_candidates: usize,
    ) -> Vec<CleaningCandidate> {
        let mut plan = self.plan_cleaning(current_commit_group);
        plan.truncate(max_candidates);
        plan
    }

    pub fn commit_cleaned(&mut self, segment_id: u64) -> bool {
        self.queue.commit_dead(segment_id)
    }

    pub fn record_write(&mut self, segment_id: u64, bytes: u64, creation_commit_group: u64) {
        self.queue
            .record_write_at_commit_group(segment_id, bytes, creation_commit_group);
    }

    pub fn record_overwrite(&mut self, segment_id: u64, old_bytes: u64) {
        self.queue.record_overwrite(segment_id, old_bytes);
    }

    pub fn record_delete(&mut self, segment_id: u64, bytes: u64) {
        self.queue.record_delete(segment_id, bytes);
    }

    pub fn persist_intent(
        &self,
        storage: &mut impl ReclaimQueueStorage,
    ) -> Result<(), SegmentLivenessPersistError> {
        self.queue.flush_to(storage)
    }

    pub fn load_from_storage(
        storage: &impl ReclaimQueueStorage,
        config: SegmentCleanerConfig,
        min_reclaimable_bytes: u64,
    ) -> Result<Self, SegmentLivenessPersistError> {
        let queue = SegmentLivenessQueue::load_from(storage)?;
        Ok(Self {
            queue,
            config,
            min_reclaimable_bytes,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(min_dead_ratio: f64, min_age_commit_groups: u64) -> SegmentCleanerConfig {
        SegmentCleanerConfig {
            min_dead_ratio,
            min_segment_age_txg: min_age_commit_groups,
            ..SegmentCleanerConfig::default()
        }
    }

    fn populated_queue() -> SegmentLivenessQueue {
        let mut q = SegmentLivenessQueue::new();
        q.record_write_at_commit_group(1, 1000, 0);
        q.record_overwrite(1, 900);
        q.record_write_at_commit_group(2, 500, 0);
        q.record_delete(2, 500);
        q.record_write_at_commit_group(3, 1000, 0);
        q.record_overwrite(3, 500);
        q.record_write_at_commit_group(4, 1000, 0);
        q.record_overwrite(4, 200);
        q.record_write_at_commit_group(5, 1000, 0);
        q.record_overwrite(5, 50);
        q
    }

    #[test]
    fn new_cleaner_is_populated() {
        let q = populated_queue();
        let cleaner = SegmentCleaner::new(q, make_config(0.0, 0), 0);
        assert_eq!(cleaner.tracked_segments(), 5);
    }

    #[test]
    fn empty_cleaner_has_zero_tracked() {
        let cleaner = SegmentCleaner::empty(make_config(0.0, 0), 0);
        assert_eq!(cleaner.tracked_segments(), 0);
        assert!(cleaner.plan_cleaning(0).is_empty());
    }

    #[test]
    fn plan_cleaning_returns_cleaner_owned_handoff_order() {
        let cleaner = SegmentCleaner::new(populated_queue(), make_config(0.0, 0), 0);
        let schedule = cleaner.plan_cleaning(0);
        assert_eq!(schedule.len(), 5);
        assert_eq!(schedule[0].segment_id, 2);
        assert!(schedule[0].is_fully_dead);
        assert_eq!(schedule[1].segment_id, 1);
        assert_eq!(schedule[2].segment_id, 3);
        assert_eq!(schedule[3].segment_id, 4);
        assert_eq!(schedule[4].segment_id, 5);
    }

    #[test]
    fn partial_compaction_handoffs_exclude_fully_dead_segments() {
        let cleaner = SegmentCleaner::new(populated_queue(), make_config(0.0, 0), 0);
        let handoffs = cleaner.partial_compaction_handoffs(0);
        let ids: Vec<u64> = handoffs.iter().map(|handoff| handoff.segment_id).collect();
        assert_eq!(ids, vec![1, 3, 4, 5]);
        assert!(handoffs.iter().all(|handoff| handoff.live_bytes > 0));
        assert!(handoffs.iter().all(|handoff| handoff.dead_bytes > 0));
    }

    #[test]
    fn plan_cleaning_respects_min_reclaimable_bytes() {
        let cleaner = SegmentCleaner::new(populated_queue(), make_config(0.0, 0), 300);
        let schedule = cleaner.plan_cleaning(0);
        assert_eq!(schedule.len(), 3);
        let ids: Vec<u64> = schedule.iter().map(|c| c.segment_id).collect();
        assert_eq!(ids, vec![2, 1, 3]);
    }

    #[test]
    fn plan_cleaning_respects_min_dead_ratio() {
        let cleaner = SegmentCleaner::new(populated_queue(), make_config(0.40, 0), 0);
        let schedule = cleaner.plan_cleaning(0);
        let ids: Vec<u64> = schedule.iter().map(|c| c.segment_id).collect();
        assert_eq!(ids, vec![2, 1, 3]);
    }

    #[test]
    fn plan_cleaning_respects_age_guard() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write_at_commit_group(10, 1000, 5);
        q.record_overwrite(10, 700);
        q.record_write_at_commit_group(20, 1000, 1);
        q.record_overwrite(20, 700);

        let cleaner = SegmentCleaner::new(q, make_config(0.30, 2), 0);
        let schedule = cleaner.plan_cleaning(3);
        assert_eq!(schedule.len(), 1);
        assert_eq!(schedule[0].segment_id, 20);

        let schedule = cleaner.plan_cleaning(7);
        assert_eq!(schedule.len(), 2);
    }

    #[test]
    fn plan_cleaning_fully_dead_bypasses_age_guard() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write_at_commit_group(1, 1000, 100);
        q.record_delete(1, 1000);
        let cleaner = SegmentCleaner::new(q, make_config(0.0, 50), 0);
        let schedule = cleaner.plan_cleaning(101);
        assert_eq!(schedule.len(), 1);
        assert!(schedule[0].is_fully_dead);
    }

    #[test]
    fn plan_cleaning_bounded_respects_limit() {
        let cleaner = SegmentCleaner::new(populated_queue(), make_config(0.0, 0), 0);
        let schedule = cleaner.plan_cleaning_bounded(0, 2);
        assert_eq!(schedule.len(), 2);
        assert_eq!(schedule[0].segment_id, 2);
        assert_eq!(schedule[1].segment_id, 1);
    }

    #[test]
    fn plan_cleaning_bounded_zero_limit_returns_empty() {
        let cleaner = SegmentCleaner::new(populated_queue(), make_config(0.0, 0), 0);
        assert!(cleaner.plan_cleaning_bounded(0, 0).is_empty());
    }

    #[test]
    fn commit_cleaned_removes_segment() {
        let mut cleaner = SegmentCleaner::new(populated_queue(), make_config(0.0, 0), 0);
        assert_eq!(cleaner.tracked_segments(), 5);
        assert!(cleaner.commit_cleaned(2));
        assert_eq!(cleaner.tracked_segments(), 4);
        let schedule = cleaner.plan_cleaning(0);
        assert!(!schedule.iter().any(|c| c.segment_id == 2));
    }

    #[test]
    fn commit_cleaned_unknown_returns_false() {
        let mut cleaner = SegmentCleaner::empty(make_config(0.0, 0), 0);
        assert!(!cleaner.commit_cleaned(999));
    }

    #[test]
    fn commit_cleaned_idempotent() {
        let mut cleaner = SegmentCleaner::new(populated_queue(), make_config(0.0, 0), 0);
        assert!(cleaner.commit_cleaned(1));
        assert!(!cleaner.commit_cleaned(1));
    }

    #[test]
    fn record_write_adds_live_bytes() {
        let mut cleaner = SegmentCleaner::empty(make_config(0.0, 0), 0);
        cleaner.record_write(10, 4096, 1);
        cleaner.record_write(10, 4096, 1);
        assert_eq!(cleaner.tracked_segments(), 1);
        assert_eq!(cleaner.total_live_bytes(), 8192);
        assert_eq!(cleaner.total_dead_bytes(), 0);
    }

    #[test]
    fn record_overwrite_transfers_live_to_dead() {
        let mut cleaner = SegmentCleaner::empty(make_config(0.0, 0), 0);
        cleaner.record_write(1, 4096, 0);
        cleaner.record_overwrite(1, 1024);
        let schedule = cleaner.plan_cleaning(0);
        assert_eq!(schedule.len(), 1);
        assert_eq!(schedule[0].live_bytes, 3072);
        assert_eq!(schedule[0].dead_bytes, 1024);
    }

    #[test]
    fn record_delete_makes_fully_dead() {
        let mut cleaner = SegmentCleaner::empty(make_config(0.0, 0), 0);
        cleaner.record_write(1, 4096, 0);
        cleaner.record_delete(1, 4096);
        let schedule = cleaner.plan_cleaning(0);
        assert_eq!(schedule.len(), 1);
        assert!(schedule[0].is_fully_dead);
    }

    #[test]
    fn cleaning_candidate_from_entry() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write_at_commit_group(42, 1000, 7);
        q.record_overwrite(42, 700);
        let entry = q.get(42).unwrap();
        let candidate = CleaningCandidate::from_entry(entry);
        assert_eq!(candidate.segment_id, 42);
        assert_eq!(candidate.live_bytes, 300);
        assert_eq!(candidate.dead_bytes, 700);
        assert_eq!(candidate.reclaimable_bytes, 700);
        assert!((candidate.dead_ratio - 0.70).abs() < 0.001);
        assert!(!candidate.is_fully_dead);
        assert_eq!(candidate.creation_commit_group, 7);
    }

    #[test]
    fn cleaning_candidate_fully_dead() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 500);
        q.record_delete(1, 500);
        let candidate = CleaningCandidate::from_entry(q.get(1).unwrap());
        assert!(candidate.is_fully_dead);
        assert_eq!(candidate.live_bytes, 0);
        assert_eq!(candidate.dead_bytes, 500);
    }

    #[test]
    fn cleaning_candidate_meets_threshold() {
        let candidate = CleaningCandidate {
            segment_id: 1,
            live_bytes: 0,
            dead_bytes: 4096,
            reclaimable_bytes: 4096,
            dead_ratio: 1.0,
            is_fully_dead: true,
            creation_commit_group: 0,
        };
        assert!(candidate.meets_threshold(4096));
        assert!(candidate.meets_threshold(1));
        assert!(!candidate.meets_threshold(4097));
    }

    #[test]
    fn cleaning_candidate_meets_threshold_requires_positive() {
        let candidate = CleaningCandidate {
            segment_id: 1,
            live_bytes: 1000,
            dead_bytes: 0,
            reclaimable_bytes: 0,
            dead_ratio: 0.0,
            is_fully_dead: false,
            creation_commit_group: 0,
        };
        assert!(!candidate.meets_threshold(0));
    }

    /// In-memory storage for persistence tests.
    struct InMemoryStorage {
        data: Option<Vec<u8>>,
    }

    impl InMemoryStorage {
        fn new() -> Self {
            Self { data: None }
        }
    }

    impl ReclaimQueueStorage for InMemoryStorage {
        type Error = String;
        fn load_reclaim_queue(&self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.data.clone())
        }
        fn store_reclaim_queue(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.data = Some(data.to_vec());
            Ok(())
        }
    }

    #[test]
    fn persist_and_load_roundtrip() {
        let mut storage = InMemoryStorage::new();
        let q = populated_queue();
        let cleaner = SegmentCleaner::new(q, make_config(0.0, 0), 100);
        cleaner.persist_intent(&mut storage).expect("persist");
        let loaded =
            SegmentCleaner::load_from_storage(&storage, make_config(0.0, 0), 100).expect("load");
        assert_eq!(loaded.tracked_segments(), cleaner.tracked_segments());
        assert_eq!(loaded.total_live_bytes(), cleaner.total_live_bytes());
        assert_eq!(loaded.total_dead_bytes(), cleaner.total_dead_bytes());
        assert_eq!(loaded.plan_cleaning(0), cleaner.plan_cleaning(0));
    }

    #[test]
    fn load_from_empty_storage_returns_empty_cleaner() {
        let storage = InMemoryStorage::new();
        let cleaner = SegmentCleaner::load_from_storage(&storage, make_config(0.3, 2), 4096)
            .expect("load from empty");
        assert_eq!(cleaner.tracked_segments(), 0);
        assert!(cleaner.plan_cleaning(0).is_empty());
    }

    #[test]
    fn persist_after_commit_cleaned_preserves_state() {
        let mut storage = InMemoryStorage::new();
        let mut cleaner = SegmentCleaner::new(populated_queue(), make_config(0.0, 0), 0);
        assert_eq!(cleaner.tracked_segments(), 5);
        cleaner.commit_cleaned(2);
        assert_eq!(cleaner.tracked_segments(), 4);
        cleaner.persist_intent(&mut storage).expect("persist");
        let loaded =
            SegmentCleaner::load_from_storage(&storage, make_config(0.0, 0), 0).expect("load");
        assert_eq!(loaded.tracked_segments(), 4);
        let schedule = loaded.plan_cleaning(0);
        assert!(!schedule.iter().any(|c| c.segment_id == 2));
    }

    #[test]
    fn schedule_deterministic_across_calls() {
        let cleaner = SegmentCleaner::new(populated_queue(), make_config(0.0, 0), 0);
        let s1 = cleaner.plan_cleaning(0);
        let s2 = cleaner.plan_cleaning(0);
        assert_eq!(s1, s2);
    }

    #[test]
    fn schedule_deterministic_across_reloads() {
        let mut storage = InMemoryStorage::new();
        let cleaner = SegmentCleaner::new(populated_queue(), make_config(0.0, 0), 0);
        let s1 = cleaner.plan_cleaning(0);
        cleaner.persist_intent(&mut storage).expect("persist");
        let loaded =
            SegmentCleaner::load_from_storage(&storage, make_config(0.0, 0), 0).expect("load");
        let s2 = loaded.plan_cleaning(0);
        assert_eq!(s1, s2);
    }

    #[test]
    fn full_cleaning_pipeline_scenario() {
        let mut storage = InMemoryStorage::new();
        let mut cleaner = SegmentCleaner::empty(make_config(0.3, 2), 64 * 1024);
        for seg in 0..10u64 {
            cleaner.record_write(seg, 100_000, 3);
        }
        cleaner.record_overwrite(0, 90_000);
        cleaner.record_overwrite(1, 70_000);
        cleaner.record_delete(2, 50_000);
        cleaner.record_overwrite(3, 30_000);
        cleaner.record_delete(4, 10_000);

        let schedule = cleaner.plan_cleaning(3);
        assert!(
            schedule.is_empty(),
            "no segments old enough at commit_group 3"
        );

        let schedule = cleaner.plan_cleaning(5);
        assert!(!schedule.is_empty());
        assert_eq!(schedule[0].segment_id, 0);
        assert_eq!(schedule[0].dead_bytes, 90_000);

        cleaner.commit_cleaned(0);
        cleaner.persist_intent(&mut storage).expect("persist");

        let loaded = SegmentCleaner::load_from_storage(&storage, make_config(0.3, 2), 64 * 1024)
            .expect("load");
        let schedule = loaded.plan_cleaning(5);
        assert_eq!(schedule[0].segment_id, 1);
        assert!(!schedule.iter().any(|c| c.segment_id == 0));
    }

    #[test]
    fn totals_accurate_after_mutations() {
        let mut cleaner = SegmentCleaner::empty(make_config(0.0, 0), 0);
        cleaner.record_write(1, 1000, 0);
        cleaner.record_write(2, 2000, 0);
        cleaner.record_overwrite(1, 300);
        cleaner.record_delete(2, 500);
        assert_eq!(cleaner.total_live_bytes(), 2200);
        assert_eq!(cleaner.total_dead_bytes(), 800);
    }
}
