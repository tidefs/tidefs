//! Segment liveness scanner: computes per-segment live-byte ratios from a
//! segment-index reference, ranks segments by compaction efficiency
//! (highest dead-byte yield, lowest live-byte relocation cost), and
//! exposes a stateful [`SegmentLivenessScanner::next_candidate`] iterator
//! for the compaction engine.
// ---------------------------------------------------------------------------
// CompactionCandidate -- ranked candidate for compaction
// ---------------------------------------------------------------------------

use crate::{DeadObjectTracker, PerSegmentLiveness};
/// A segment identified for potential compaction, together with its
/// liveness metadata and computed reclaim efficiency.
///
/// Candidates are ranked: highest dead-byte yield first, with tie-breaking
/// on lowest live-byte relocation cost.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CompactionCandidate {
    /// Segment identifier.
    pub segment_id: u64,
    /// Total accounted bytes in the segment (live + dead).
    pub total_bytes: u64,
    /// Bytes still referenced by live objects.
    pub live_bytes: u64,
    /// Bytes eligible for reclamation (overwritten or deleted).
    pub dead_bytes: u64,
    /// Dead-byte fraction in [0.0, 1.0]. Higher means more reclaimable.
    pub liveness_ratio: f64,
    /// Transaction group when this segment was first written.
    pub creation_commit_group: u64,
}

impl CompactionCandidate {
    /// Construct a candidate from a [`PerSegmentLiveness`] entry.
    #[must_use]
    pub fn from_liveness(entry: &PerSegmentLiveness) -> Self {
        Self {
            segment_id: entry.segment_id,
            total_bytes: entry.total_bytes(),
            live_bytes: entry.live_bytes,
            dead_bytes: entry.dead_bytes,
            liveness_ratio: entry.dead_ratio(),
            creation_commit_group: entry.creation_commit_group,
        }
    }

    /// Whether this segment is fully dead (zero live bytes, positive
    /// dead bytes). Fully-dead segments can be freed without relocation.
    #[must_use]
    pub const fn is_fully_dead(&self) -> bool {
        self.live_bytes == 0 && self.dead_bytes > 0
    }

    /// Whether this candidate has any reclaimable bytes.
    #[must_use]
    pub const fn has_reclaimable(&self) -> bool {
        self.dead_bytes > 0
    }
}

// ---------------------------------------------------------------------------
// CandidateRanker -- sorts candidates by compaction efficiency
// ---------------------------------------------------------------------------

/// Ranks compaction candidates by descending dead-byte yield, with
/// tie-breaking on ascending live bytes (minimize relocation cost)
/// and then ascending segment id for deterministic ordering.
pub struct CandidateRanker;

impl CandidateRanker {
    /// Sort `candidates` in-place by compaction priority:
    ///
    /// 1. Higher `dead_bytes` first (maximize reclaim yield)
    /// 2. Lower `live_bytes` first (minimize relocation cost)
    /// 3. Lower `segment_id` first (deterministic tie-break)
    pub fn rank(candidates: &mut [CompactionCandidate]) {
        candidates.sort_by(|a, b| {
            b.dead_bytes
                .cmp(&a.dead_bytes)
                .then_with(|| a.live_bytes.cmp(&b.live_bytes))
                .then_with(|| a.segment_id.cmp(&b.segment_id))
        });
    }

    /// Rank and truncate to `max_candidates`, returning the ranked
    /// subset.
    #[must_use]
    pub fn rank_top(
        mut candidates: Vec<CompactionCandidate>,
        max_candidates: usize,
    ) -> Vec<CompactionCandidate> {
        Self::rank(&mut candidates);
        candidates.truncate(max_candidates);
        candidates
    }
}

// ---------------------------------------------------------------------------
// ScannerConfig
// ---------------------------------------------------------------------------

/// Configuration for [`SegmentLivenessScanner`].
#[derive(Clone, Debug)]
pub struct ScannerConfig {
    /// Only segments with at least this many dead bytes are considered.
    /// Default: 0 (consider all segments with any dead bytes).
    pub min_dead_bytes: u64,

    /// Maximum number of candidates to produce. The scanner stops
    /// returning candidates after this limit is reached. Default: 64.
    pub max_candidates: usize,

    /// Minimum dead-byte ratio (0.0-1.0) for a segment to be a
    /// candidate. Fully-dead segments bypass this threshold.
    /// Default: 0.0 (consider all segments with any dead bytes).
    pub min_dead_ratio: f64,

    /// Minimum transaction-group age for a segment to be considered.
    /// Fully-dead segments bypass this age guard. Default: 0.
    pub min_segment_age_txg: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            min_dead_bytes: 0,
            max_candidates: 64,
            min_dead_ratio: 0.0,
            min_segment_age_txg: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// LivenessSource trait -- abstracts over DeadObjectTracker and friends
// ---------------------------------------------------------------------------

/// Abstract source of per-segment liveness data.
///
/// Implementations provide an iterator of (segment_id, live_bytes,
/// dead_bytes, creation_commit_group) tuples for scanning.
pub trait LivenessSource {
    /// Visit each tracked segment. The closure receives
    /// (segment_id, live_bytes, dead_bytes, creation_commit_group).
    fn for_each_segment(&self, f: &mut dyn FnMut(u64, u64, u64, u64));

    /// Number of segments tracked by this source.
    fn segment_count(&self) -> usize;
}

/// Blanket implementation: any type that can iterate over
/// `PerSegmentLiveness` references is a liveness source.
impl LivenessSource for DeadObjectTracker {
    fn for_each_segment(&self, f: &mut dyn FnMut(u64, u64, u64, u64)) {
        for entry in self.entries() {
            f(
                entry.segment_id,
                entry.live_bytes,
                entry.dead_bytes,
                entry.creation_commit_group,
            );
        }
    }

    fn segment_count(&self) -> usize {
        self.len()
    }
}

// ---------------------------------------------------------------------------
// SegmentLivenessScanner -- stateful candidate iterator
// ---------------------------------------------------------------------------

/// Scans a liveness data source, ranks segments by compaction
/// efficiency, and exposes a stateful [`next_candidate`] method
/// for the compaction engine to consume.
///
/// [`next_candidate`]: SegmentLivenessScanner::next_candidate
///
/// # Example
///
/// ```ignore
/// let tracker = DeadObjectTracker::new();
/// // ... populate tracker ...
/// let config = ScannerConfig::default();
/// let mut scanner = SegmentLivenessScanner::new(&tracker, config);
/// while let Some(candidate) = scanner.next_candidate(0) {
///     println!("compact segment {}", candidate.segment_id);
/// }
/// ```
pub struct SegmentLivenessScanner<'a> {
    /// Ranked candidates ready for iteration.
    candidates: Vec<CompactionCandidate>,
    /// Current position in the candidate list.
    position: usize,
    /// Scanner configuration.
    config: ScannerConfig,
    /// Whether the initial scan has been performed.
    scanned: bool,
    /// Reference to the liveness data source.
    source: &'a dyn LivenessSource,
}

impl<'a> SegmentLivenessScanner<'a> {
    /// Create a new scanner wrapping a liveness data source.
    ///
    /// The initial scan is deferred until the first call to
    /// [`next_candidate`].
    ///
    /// [`next_candidate`]: SegmentLivenessScanner::next_candidate
    #[must_use]
    pub fn new(source: &'a dyn LivenessSource, config: ScannerConfig) -> Self {
        Self {
            candidates: Vec::new(),
            position: 0,
            config,
            scanned: false,
            source,
        }
    }

    /// Return the next compaction candidate, or `None` when all
    /// qualifying candidates have been returned.
    ///
    /// On the first call, this scans the liveness source, filters
    /// segments against the configured thresholds, ranks them by
    /// compaction efficiency, and caches the result.
    ///
    /// `current_commit_group` is used for age-gating; segments younger
    /// than `min_segment_age_txg` commit groups are excluded unless
    /// they are fully dead.
    #[must_use]
    pub fn next_candidate(&mut self, current_commit_group: u64) -> Option<CompactionCandidate> {
        if !self.scanned {
            self.scan(current_commit_group);
            self.scanned = true;
        }

        if self.position >= self.candidates.len() {
            return None;
        }

        let candidate = self.candidates[self.position];
        self.position += 1;
        Some(candidate)
    }

    /// Reset the scanner to begin iteration from the first candidate
    /// again. Does not re-scan the source; use [`rescan`] to rebuild
    /// the candidate list from the current source state.
    ///
    /// [`rescan`]: SegmentLivenessScanner::rescan
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// Re-scan the liveness source and rebuild the candidate list.
    /// Useful when the source has been updated after construction.
    pub fn rescan(&mut self, current_commit_group: u64) {
        self.candidates.clear();
        self.position = 0;
        self.scanned = false;
        // Trigger a fresh scan but reset position so iteration starts at 0
        self.scan(current_commit_group);
        self.scanned = true;
        self.position = 0;
    }

    /// The number of candidates remaining to be returned.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.candidates.len().saturating_sub(self.position)
    }

    /// The total number of candidates produced by the last scan.
    #[must_use]
    pub fn total_candidates(&self) -> usize {
        self.candidates.len()
    }

    /// Access the scanner configuration.
    #[must_use]
    pub const fn config(&self) -> &ScannerConfig {
        &self.config
    }

    /// Perform the initial scan: collect, filter, rank, and cache
    /// candidates.
    fn scan(&mut self, current_commit_group: u64) {
        let mut raw: Vec<CompactionCandidate> = Vec::new();

        self.source
            .for_each_segment(&mut |seg_id, live, dead, creation_txg| {
                // Skip segments with no dead bytes — nothing to reclaim
                if dead == 0 {
                    return;
                }

                // Fully-dead segments always qualify (bypass all thresholds)
                let is_fully_dead = live == 0;

                if !is_fully_dead {
                    // Skip segments below the minimum dead-bytes threshold
                    if dead < self.config.min_dead_bytes {
                        return;
                    }
                    // Check dead-ratio threshold
                    let total = live.saturating_add(dead);
                    if total == 0 {
                        return;
                    }
                    let ratio = dead as f64 / total as f64;
                    if ratio < self.config.min_dead_ratio {
                        return;
                    }

                    // Check age guard
                    if self.config.min_segment_age_txg > 0
                        && creation_txg > 0
                        && current_commit_group.saturating_sub(creation_txg)
                            < self.config.min_segment_age_txg
                    {
                        return;
                    }
                }

                raw.push(CompactionCandidate {
                    segment_id: seg_id,
                    total_bytes: live.saturating_add(dead),
                    live_bytes: live,
                    dead_bytes: dead,
                    liveness_ratio: if live + dead == 0 {
                        0.0
                    } else {
                        dead as f64 / (live + dead) as f64
                    },
                    creation_commit_group: creation_txg,
                });
            });

        CandidateRanker::rank(&mut raw);
        raw.truncate(self.config.max_candidates);
        self.candidates = raw;
        self.position = 0;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // CompactionCandidate tests
    // ------------------------------------------------------------------

    #[test]
    fn candidate_from_liveness() {
        let entry = PerSegmentLiveness::new(42, 300, 700, 5);
        let c = CompactionCandidate::from_liveness(&entry);
        assert_eq!(c.segment_id, 42);
        assert_eq!(c.total_bytes, 1000);
        assert_eq!(c.live_bytes, 300);
        assert_eq!(c.dead_bytes, 700);
        assert!((c.liveness_ratio - 0.70).abs() < 0.001);
        assert_eq!(c.creation_commit_group, 5);
        assert!(!c.is_fully_dead());
        assert!(c.has_reclaimable());
    }

    #[test]
    fn candidate_fully_dead() {
        let entry = PerSegmentLiveness::new(1, 0, 500, 0);
        let c = CompactionCandidate::from_liveness(&entry);
        assert!(c.is_fully_dead());
        assert!(c.has_reclaimable());
        assert_eq!(c.live_bytes, 0);
    }

    #[test]
    fn candidate_empty_has_no_reclaimable() {
        let entry = PerSegmentLiveness::new(1, 0, 0, 0);
        let c = CompactionCandidate::from_liveness(&entry);
        assert!(!c.is_fully_dead());
        assert!(!c.has_reclaimable());
    }

    // ------------------------------------------------------------------
    // CandidateRanker tests
    // ------------------------------------------------------------------

    fn make_candidate(seg_id: u64, live: u64, dead: u64) -> CompactionCandidate {
        CompactionCandidate {
            segment_id: seg_id,
            total_bytes: live + dead,
            live_bytes: live,
            dead_bytes: dead,
            liveness_ratio: if live + dead == 0 {
                0.0
            } else {
                dead as f64 / (live + dead) as f64
            },
            creation_commit_group: 0,
        }
    }

    #[test]
    fn rank_by_dead_bytes_desc() {
        let mut cs = vec![
            make_candidate(1, 100, 200),
            make_candidate(2, 100, 800),
            make_candidate(3, 100, 400),
        ];
        CandidateRanker::rank(&mut cs);
        assert_eq!(cs[0].segment_id, 2); // dead=800
        assert_eq!(cs[1].segment_id, 3); // dead=400
        assert_eq!(cs[2].segment_id, 1); // dead=200
    }

    #[test]
    fn rank_tiebreak_by_live_bytes_asc() {
        // Same dead bytes; lower live bytes (cheaper relocation) wins
        let mut cs = vec![
            make_candidate(1, 900, 100),
            make_candidate(2, 100, 100),
            make_candidate(3, 500, 100),
        ];
        CandidateRanker::rank(&mut cs);
        assert_eq!(cs[0].segment_id, 2); // live=100
        assert_eq!(cs[1].segment_id, 3); // live=500
        assert_eq!(cs[2].segment_id, 1); // live=900
    }

    #[test]
    fn rank_tiebreak_by_segment_id_asc() {
        // Same dead and live; lower segment id wins
        let mut cs = vec![
            make_candidate(50, 100, 500),
            make_candidate(10, 100, 500),
            make_candidate(30, 100, 500),
        ];
        CandidateRanker::rank(&mut cs);
        assert_eq!(cs[0].segment_id, 10);
        assert_eq!(cs[1].segment_id, 30);
        assert_eq!(cs[2].segment_id, 50);
    }

    #[test]
    fn rank_single_candidate() {
        let mut cs = vec![make_candidate(1, 0, 100)];
        CandidateRanker::rank(&mut cs);
        assert_eq!(cs.len(), 1);
    }

    #[test]
    fn rank_empty_is_noop() {
        let mut cs: Vec<CompactionCandidate> = vec![];
        CandidateRanker::rank(&mut cs);
        assert!(cs.is_empty());
    }

    #[test]
    fn rank_top_truncates() {
        let cs = vec![
            make_candidate(1, 100, 200),
            make_candidate(2, 100, 800),
            make_candidate(3, 100, 400),
        ];
        let ranked = CandidateRanker::rank_top(cs, 2);
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].segment_id, 2);
        assert_eq!(ranked[1].segment_id, 3);
    }

    #[test]
    fn rank_top_zero_returns_empty() {
        let cs = vec![make_candidate(1, 0, 100)];
        let ranked = CandidateRanker::rank_top(cs, 0);
        assert!(ranked.is_empty());
    }

    // ------------------------------------------------------------------
    // SegmentLivenessScanner tests
    // ------------------------------------------------------------------

    fn make_tracker(entries: &[(u64, u64, u64, u64)]) -> DeadObjectTracker {
        let mut t = DeadObjectTracker::new();
        for &(seg, live, dead, commit_group) in entries {
            t.record_write_at_commit_group(seg, live + dead, commit_group);
            if dead > 0 {
                t.record_overwrite(seg, dead);
            }
        }
        t
    }

    #[test]
    fn scanner_empty_source_returns_none() {
        let tracker = DeadObjectTracker::new();
        let config = ScannerConfig::default();
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        assert_eq!(scanner.next_candidate(0), None);
    }

    #[test]
    fn scanner_returns_ranked_candidates() {
        let tracker = make_tracker(&[(1, 100, 900, 0), (2, 200, 800, 0), (3, 900, 100, 0)]);
        let config = ScannerConfig::default();
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 1); // dead=900
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 2); // dead=800
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 3); // dead=100
        assert_eq!(scanner.next_candidate(0), None);
    }

    #[test]
    fn scanner_respects_max_candidates() {
        let mut entries = Vec::new();
        for i in 0..10u64 {
            entries.push((i, 100, 1000 + i * 10, 0));
        }
        let tracker = make_tracker(&entries);
        let config = ScannerConfig {
            max_candidates: 3,
            ..ScannerConfig::default()
        };
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        assert!(scanner.next_candidate(0).is_some());
        assert!(scanner.next_candidate(0).is_some());
        assert!(scanner.next_candidate(0).is_some());
        assert_eq!(scanner.next_candidate(0), None);
        assert_eq!(scanner.total_candidates(), 3);
    }

    #[test]
    fn scanner_respects_min_dead_bytes() {
        let tracker = make_tracker(&[(1, 9900, 100, 0), (2, 5000, 5000, 0), (3, 1000, 9000, 0)]);
        let config = ScannerConfig {
            min_dead_bytes: 1000,
            ..ScannerConfig::default()
        };
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        // seg 1: dead=100 < 1000 → excluded
        // seg 2: dead=5000, seg 3: dead=9000
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 3);
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 2);
        assert_eq!(scanner.next_candidate(0), None);
    }

    #[test]
    fn scanner_respects_min_dead_ratio() {
        let tracker = make_tracker(&[
            (1, 950, 50, 0),  // ratio 0.05
            (2, 500, 500, 0), // ratio 0.50
            (3, 200, 800, 0), // ratio 0.80
        ]);
        let config = ScannerConfig {
            min_dead_ratio: 0.40,
            ..ScannerConfig::default()
        };
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 3); // dead=800
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 2); // dead=500
        assert_eq!(scanner.next_candidate(0), None);
    }

    #[test]
    fn scanner_fully_dead_bypasses_thresholds() {
        let tracker = make_tracker(&[
            (1, 0, 50, 0),    // fully dead, dead=50 < min_dead_bytes=1000, ratio=1.0
            (2, 100, 900, 0), // ratio=0.90
        ]);
        let config = ScannerConfig {
            min_dead_bytes: 1000,
            min_dead_ratio: 0.95,
            ..ScannerConfig::default()
        };
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        // seg 2: ratio 0.90 < 0.95 → excluded
        // seg 1: fully dead → bypasses thresholds
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 1);
        assert_eq!(scanner.next_candidate(0), None);
    }

    #[test]
    fn scanner_respects_age_guard() {
        let tracker = make_tracker(&[
            (1, 100, 900, 100), // too young at commit_group 101
            (2, 200, 800, 5),   // old enough at commit_group 10
        ]);
        let config = ScannerConfig {
            min_segment_age_txg: 2,
            ..ScannerConfig::default()
        };
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        // At commit_group 101: seg 1 is only 1 txg old → excluded
        assert_eq!(scanner.next_candidate(101).unwrap().segment_id, 2);
        assert_eq!(scanner.next_candidate(101), None);
    }

    #[test]
    fn scanner_fully_dead_bypasses_age_guard() {
        let tracker = make_tracker(&[
            (1, 0, 1000, 100), // fully dead, too young
            (2, 50, 50, 5),    // partial, old enough
        ]);
        let config = ScannerConfig {
            min_segment_age_txg: 50,
            ..ScannerConfig::default()
        };
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        // seg 1 is fully dead → bypasses age, seg 2 is old enough (101-5=96≥50)
        assert_eq!(scanner.next_candidate(101).unwrap().segment_id, 1);
        assert_eq!(scanner.next_candidate(101).unwrap().segment_id, 2);
        assert_eq!(scanner.next_candidate(101), None);
    }

    #[test]
    fn scanner_reset_restarts_iteration() {
        let tracker = make_tracker(&[(1, 100, 900, 0), (2, 200, 800, 0)]);
        let config = ScannerConfig::default();
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 1);
        scanner.reset();
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 1);
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 2);
        assert_eq!(scanner.next_candidate(0), None);
    }

    #[test]
    fn scanner_remaining_and_total() {
        let tracker = make_tracker(&[(1, 100, 900, 0), (2, 200, 800, 0), (3, 300, 700, 0)]);
        let config = ScannerConfig::default();
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        // Not yet scanned
        assert_eq!(scanner.remaining(), 0);
        assert_eq!(scanner.total_candidates(), 0);
        // Trigger scan
        let _ = scanner.next_candidate(0);
        assert_eq!(scanner.total_candidates(), 3);
        assert_eq!(scanner.remaining(), 2);
        let _ = scanner.next_candidate(0);
        assert_eq!(scanner.remaining(), 1);
        let _ = scanner.next_candidate(0);
        assert_eq!(scanner.remaining(), 0);
    }

    #[test]
    fn scanner_rescan_restarts_iteration() {
        let tracker = make_tracker(&[(1, 100, 900, 0), (2, 200, 800, 0), (3, 300, 700, 0)]);
        let config = ScannerConfig::default();
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        // Consume first candidate
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 1);
        // Rescan should rebuild and restart iteration
        scanner.rescan(0);
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 1);
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 2);
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 3);
        assert_eq!(scanner.next_candidate(0), None);
    }
    #[test]
    fn scanner_fresh_instance_reflects_source_changes() {
        let mut tracker = make_tracker(&[(1, 100, 900, 0)]);
        let config = ScannerConfig::default();
        {
            let mut scanner = SegmentLivenessScanner::new(&tracker, config.clone());
            assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 1);
            assert_eq!(scanner.next_candidate(0), None);
        }
        // Add a new segment to the tracker after scanner is dropped
        tracker.record_write_at_commit_group(2, 1000, 0);
        tracker.record_overwrite(2, 800);

        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 1); // dead=900
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 2); // dead=800
        assert_eq!(scanner.next_candidate(0), None);
    }

    #[test]
    fn scanner_large_segment_count() {
        let mut entries = Vec::new();
        for i in 0..200u64 {
            entries.push((i, 500, 500 + i % 100, 0));
        }
        let tracker = make_tracker(&entries);
        let config = ScannerConfig {
            max_candidates: 200,
            ..ScannerConfig::default()
        };
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        let first = scanner.next_candidate(0).unwrap();
        assert!(first.dead_bytes >= 500);
        // Count all
        let mut count = 1;
        while scanner.next_candidate(0).is_some() {
            count += 1;
        }
        assert_eq!(count, 200);
    }

    #[test]
    fn scanner_uniform_live_segments_return_none() {
        // All segments are fully live (no dead bytes)
        let tracker = make_tracker(&[(1, 1000, 0, 0), (2, 2000, 0, 0), (3, 3000, 0, 0)]);
        let config = ScannerConfig::default();
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        assert_eq!(scanner.next_candidate(0), None);
    }

    #[test]
    fn scanner_mixed_segments_correct_ranking() {
        let tracker = make_tracker(&[
            (1, 100, 100, 0), // dead=100, live=100
            (2, 500, 100, 0), // dead=100, live=500
            (3, 100, 500, 0), // dead=500, live=100
            (4, 500, 500, 0), // dead=500, live=500
        ]);
        let config = ScannerConfig::default();
        let mut scanner = SegmentLivenessScanner::new(&tracker, config);
        // dead=500 segments first; tie-break by live asc
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 3); // dead=500, live=100
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 4); // dead=500, live=500
                                                                      // dead=100 segments next; tie-break by live asc
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 1); // dead=100, live=100
        assert_eq!(scanner.next_candidate(0).unwrap().segment_id, 2); // dead=100, live=500
        assert_eq!(scanner.next_candidate(0), None);
    }

    #[test]
    fn scanner_deterministic_ordering() {
        let tracker = make_tracker(&[(10, 200, 800, 0), (20, 100, 900, 0), (5, 300, 700, 0)]);
        let config = ScannerConfig::default();
        let mut s1 = SegmentLivenessScanner::new(&tracker, config.clone());
        let mut s2 = SegmentLivenessScanner::new(&tracker, config);
        let r1: Vec<_> = std::iter::from_fn(|| s1.next_candidate(0)).collect();
        let r2: Vec<_> = std::iter::from_fn(|| s2.next_candidate(0)).collect();
        assert_eq!(r1, r2);
    }

    #[test]
    fn scanner_config_defaults() {
        let cfg = ScannerConfig::default();
        assert_eq!(cfg.min_dead_bytes, 0);
        assert_eq!(cfg.max_candidates, 64);
        assert_eq!(cfg.min_dead_ratio, 0.0);
        assert_eq!(cfg.min_segment_age_txg, 0);
    }
}
