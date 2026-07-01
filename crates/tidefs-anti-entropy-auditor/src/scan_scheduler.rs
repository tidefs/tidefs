// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Scan scheduler for anti-entropy auditing — source-owned data_copy_8.
//!
//! Controls when and how anti-entropy scans are performed:
//! - Scan window policy: minimum interval, maximum interval, backoff after divergence
//! - Incremental frontier tracking: high-water mark prevents re-scanning
//! - Backpressure integration: throttle or defer under cluster load
//! - Scope selection: full scan vs. targeted scan (degraded replicas only)
//!
//! # Comparison to existing systems
//!
//! - Ceph: deep-scrub once per week, no incremental frontier, OSD-level only
//! - ZFS: scrub traverses entire pool, no incremental option, no backpressure
//! - Cassandra: incremental repair with merkle trees, but no scan scheduling policy
//! - TideFS: incremental frontier + adaptive scheduling + backpressure

use serde::{Deserialize, Serialize};

/// Policy controlling anti-entropy scan scheduling.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanSchedulePolicy {
    /// Minimum interval between full scans (ns).
    pub min_scan_interval_ns: u64,
    /// Maximum interval between full scans (ns) — scan forced after this.
    pub max_scan_interval_ns: u64,
    /// Maximum subjects to compare per scan batch.
    pub max_batch_size: u64,
    /// Backoff multiplier after divergence is found (reduces interval).
    /// 2.0 means scan half as often when no divergences.
    pub divergence_backoff_multiplier: f64,
    /// Maximum backpressure delay when cluster is under load.
    pub max_backpressure_delay_ns: u64,
    /// Throttle: minimum delay between comparison operations (ns).
    pub comparison_throttle_ns: u64,
}

impl Default for ScanSchedulePolicy {
    fn default() -> Self {
        ScanSchedulePolicy {
            min_scan_interval_ns: 300_000_000_000,   // 5 minutes
            max_scan_interval_ns: 3_600_000_000_000, // 1 hour
            max_batch_size: 10_000,
            divergence_backoff_multiplier: 2.0,
            max_backpressure_delay_ns: 60_000_000_000, // 1 minute
            comparison_throttle_ns: 1_000_000,         // 1ms
        }
    }
}

/// Tracks scan progress with an incremental frontier.
///
/// Instead of re-scanning all subjects every cycle (ZFS/Ceph approach),
/// the frontier tracks the high-water mark of scanned subjects. Only
/// subjects beyond the frontier or subjects known to be degraded are
/// rescanned.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanFrontier {
    /// Highest subject id that has been scanned and verified.
    pub high_water_mark: u64,
    /// Subjects that were degraded at last scan and need re-checking.
    pub degraded_subjects: Vec<u64>,
    /// Epoch when the last full scan cycle completed.
    pub last_full_scan_epoch: u64,
    /// When the last scan completed.
    pub last_scan_completed_ns: u64,
    /// When the current scan started.
    pub current_scan_started_ns: u64,
    /// Total subjects scanned in the current cycle.
    pub scanned_in_cycle: u64,
    /// Total divergences found in the current cycle.
    pub divergences_in_cycle: u64,
}

impl ScanFrontier {
    #[must_use]
    pub fn new(now_ns: u64) -> Self {
        ScanFrontier {
            high_water_mark: 0,
            degraded_subjects: Vec::new(),
            last_full_scan_epoch: 0,
            last_scan_completed_ns: 0,
            current_scan_started_ns: now_ns,
            scanned_in_cycle: 0,
            divergences_in_cycle: 0,
        }
    }

    /// Advance the frontier high-water mark.
    pub fn advance(&mut self, new_mark: u64) {
        if new_mark > self.high_water_mark {
            self.high_water_mark = new_mark;
        }
    }

    /// Register a degraded subject for re-scanning.
    pub fn register_degraded(&mut self, subject_ref: u64) {
        if !self.degraded_subjects.contains(&subject_ref) {
            self.degraded_subjects.push(subject_ref);
        }
    }

    /// Remove a subject from the degraded set (after successful repair).
    pub fn clear_degraded(&mut self, subject_ref: u64) {
        self.degraded_subjects.retain(|s| *s != subject_ref);
    }

    /// Get the next batch of subjects to scan.
    ///
    /// Returns subjects beyond the high-water mark and any degraded subjects
    /// that need re-checking. `max_count` caps the batch size.
    #[must_use]
    pub fn next_scan_batch(&self, max_count: u64) -> ScanBatch {
        let mut subjects = Vec::new();

        // Degraded subjects take priority
        let degraded_to_take = self.degraded_subjects.len().min(max_count as usize);
        subjects.extend_from_slice(&self.degraded_subjects[..degraded_to_take]);

        // Fill remaining slots with subjects beyond high-water mark
        let remaining = max_count.saturating_sub(subjects.len() as u64);
        let start = self.high_water_mark + 1;
        let end = start.saturating_add(remaining);
        for i in start..end {
            subjects.push(i);
        }

        ScanBatch {
            subjects,
            includes_degraded: degraded_to_take > 0,
            frontier_start: start,
            frontier_end: end.saturating_sub(1),
        }
    }

    /// Mark a scan cycle as complete.
    pub fn complete_cycle(&mut self, epoch: u64, now_ns: u64) {
        self.last_full_scan_epoch = epoch;
        self.last_scan_completed_ns = now_ns;
        self.scanned_in_cycle = 0;
        self.divergences_in_cycle = 0;
    }

    /// Whether a full scan cycle is pending (subjects exist beyond frontier).
    #[must_use]
    pub fn has_pending_work(&self, total_subjects: u64) -> bool {
        !self.degraded_subjects.is_empty() || self.high_water_mark < total_subjects
    }
}

/// A batch of subjects to scan in one anti-entropy comparison round.
#[derive(Clone, Debug)]
pub struct ScanBatch {
    /// Subject ids to compare.
    pub subjects: Vec<u64>,
    /// Whether this batch includes degraded subjects.
    pub includes_degraded: bool,
    /// Frontier range for new subjects (start, end inclusive).
    pub frontier_start: u64,
    pub frontier_end: u64,
}

/// Scheduler state for anti-entropy scans.
#[derive(Clone, Debug)]
pub struct ScanScheduler {
    pub policy: ScanSchedulePolicy,
    pub frontier: ScanFrontier,
    /// Whether a scan is currently in progress.
    pub scan_active: bool,
    /// When the next scan is eligible to start.
    next_scan_eligible_ns: u64,
}

impl ScanScheduler {
    #[must_use]
    pub fn new(policy: ScanSchedulePolicy, now_ns: u64) -> Self {
        ScanScheduler {
            policy,
            frontier: ScanFrontier::new(now_ns),
            scan_active: false,
            next_scan_eligible_ns: now_ns,
        }
    }

    /// Whether a scan should start now, given current time and cluster load.
    #[must_use]
    pub fn should_scan(&self, now_ns: u64, cluster_load_factor: f64) -> ScanDecision {
        if self.scan_active {
            return ScanDecision::AlreadyActive;
        }

        if now_ns < self.next_scan_eligible_ns {
            return ScanDecision::TooSoon {
                eligible_in_ns: self.next_scan_eligible_ns - now_ns,
            };
        }

        // Backpressure: if cluster load > 0.8, defer
        if cluster_load_factor > 0.8 {
            let delay = ((cluster_load_factor - 0.8)
                * 10.0
                * self.policy.max_backpressure_delay_ns as f64) as u64;
            return ScanDecision::BackpressureDeferred { delay_ns: delay };
        }

        ScanDecision::Proceed
    }

    /// Start a scan cycle. Returns the batch and updates state.
    #[must_use]
    pub fn start_scan(&mut self, now_ns: u64, _total_subjects: u64) -> Option<ScanBatch> {
        if self.scan_active {
            return None;
        }

        let batch = self.frontier.next_scan_batch(self.policy.max_batch_size);
        if batch.subjects.is_empty() {
            return None;
        }

        self.scan_active = true;
        self.frontier.current_scan_started_ns = now_ns;
        Some(batch)
    }

    /// Complete the current scan.
    pub fn complete_scan(&mut self, epoch: u64, now_ns: u64, divergences_found: u64) {
        self.scan_active = false;
        self.frontier.complete_cycle(epoch, now_ns);
        self.frontier.divergences_in_cycle = divergences_found;

        // Schedule next scan: sooner if divergences found (backoff multiplier)
        let interval = if divergences_found > 0 {
            (self.policy.min_scan_interval_ns as f64 / self.policy.divergence_backoff_multiplier)
                as u64
        } else {
            self.policy.max_scan_interval_ns
        };
        self.next_scan_eligible_ns = now_ns.saturating_add(interval);
    }

    /// Return the scheduler's next eligible scan timestamp.
    #[must_use]
    pub fn next_scan_eligible_ns(&self) -> u64 {
        self.next_scan_eligible_ns
    }
}

/// Decision returned by `should_scan`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanDecision {
    /// Proceed with scan — conditions are right.
    Proceed,
    /// A scan is already in progress.
    AlreadyActive,
    /// Too soon since last scan completed.
    TooSoon { eligible_in_ns: u64 },
    /// Cluster is under load — defer scan.
    BackpressureDeferred { delay_ns: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS_PER_SEC: u64 = 1_000_000_000;
    const NS_PER_MIN: u64 = 60 * NS_PER_SEC;

    fn policy() -> ScanSchedulePolicy {
        ScanSchedulePolicy {
            min_scan_interval_ns: 5 * NS_PER_MIN,
            max_scan_interval_ns: 60 * NS_PER_MIN,
            max_batch_size: 100,
            divergence_backoff_multiplier: 2.0,
            max_backpressure_delay_ns: 60 * NS_PER_SEC,
            comparison_throttle_ns: 1_000_000,
        }
    }

    #[test]
    fn frontier_batch_respects_max_count() {
        let frontier = ScanFrontier::new(0);
        let batch = frontier.next_scan_batch(10);
        assert_eq!(batch.subjects.len(), 10);
        assert_eq!(batch.subjects[0], 1);
        assert_eq!(batch.subjects[9], 10);
    }

    #[test]
    fn frontier_degraded_take_priority() {
        let mut frontier = ScanFrontier::new(0);
        frontier.register_degraded(42);
        frontier.register_degraded(99);

        let batch = frontier.next_scan_batch(5);
        // First 2 should be degraded subjects
        assert_eq!(batch.subjects[0], 42);
        assert_eq!(batch.subjects[1], 99);
        assert_eq!(batch.subjects.len(), 5);
    }

    #[test]
    fn scheduler_rejects_scan_when_active() {
        let mut sched = ScanScheduler::new(policy(), 0);
        let _ = sched.start_scan(0, 1000);
        assert_eq!(
            sched.should_scan(NS_PER_MIN, 0.5),
            ScanDecision::AlreadyActive
        );
    }

    #[test]
    fn scheduler_defers_under_backpressure() {
        let sched = ScanScheduler::new(policy(), 0);
        let decision = sched.should_scan(NS_PER_MIN, 0.95);
        assert!(matches!(
            decision,
            ScanDecision::BackpressureDeferred { .. }
        ));
    }

    #[test]
    fn scheduler_proceeds_when_eligible() {
        let sched = ScanScheduler::new(policy(), 10 * NS_PER_MIN);
        // Enough time has passed, load is low
        assert_eq!(
            sched.should_scan(10 * NS_PER_MIN, 0.3),
            ScanDecision::Proceed
        );
    }

    #[test]
    fn complete_scan_schedules_next_sooner_after_divergence() {
        let mut sched = ScanScheduler::new(policy(), 0);
        let batch = sched.start_scan(0, 1000);
        assert!(batch.is_some());

        // Complete with divergences -> next scan comes sooner
        sched.complete_scan(1, NS_PER_MIN, 5);
        // Should be ~2.5 min (min_interval / divergence_backoff)
        assert!(matches!(
            sched.should_scan(NS_PER_MIN + NS_PER_SEC, 0.5),
            ScanDecision::TooSoon { .. }
        ));

        // After 3 min, should be eligible
        assert_eq!(
            sched.should_scan(4 * NS_PER_MIN, 0.5),
            ScanDecision::Proceed
        );
    }

    #[test]
    fn frontier_has_pending_work() {
        let frontier = ScanFrontier::new(0);
        assert!(frontier.has_pending_work(100));
        let mut frontier = ScanFrontier::new(0);
        frontier.advance(100);
        assert!(!frontier.has_pending_work(100));
        // But degraded still needs work
        frontier.register_degraded(50);
        assert!(frontier.has_pending_work(100));
    }
}
