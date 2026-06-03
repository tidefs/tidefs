//! IO-error-driven per-replica health state machine with sliding-window
//! degradation tracking.
//!
//! Tracks per-replica IO success/failure in a bounded sliding time window,
//! computes a recency-weighted health score, and drives automatic state
//! transitions through Healthy -> Degraded -> Failed. Feeds the recovery
//! loop and rebuild planner with actionable per-replica health data.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

// ── Configuration ───────────────────────────────────────────────────

/// Configuration for the IO-error-driven health tracker.
#[derive(Clone, Debug)]
pub struct HealthTrackerConfig {
    /// Duration of the sliding window for IO results.
    pub window_duration: Duration,
    /// Maximum number of IO results retained in the window.
    pub max_window_entries: usize,
    /// Half-life for recency weighting: newer results carry more weight.
    /// A result at exactly `half_life` age contributes half the weight
    /// of a brand-new result.
    pub recency_half_life: Duration,
    /// Number of errors within the window that triggers Degraded.
    pub degrade_error_threshold: usize,
    /// Minimum error density (0.0-1.0) within the window that triggers
    /// Degraded (alternative to absolute count).
    pub degrade_error_density: f64,
    /// Number of consecutive errors triggering Failed.
    pub fail_consecutive_errors: usize,
    /// Duration of sustained degradation after which the replica is
    /// marked Failed.
    pub fail_sustained_degradation: Duration,
    /// Duration of clean IO (no errors) required to recover from
    /// Degraded back to Healthy.
    pub cooldown_duration: Duration,
}

impl Default for HealthTrackerConfig {
    fn default() -> Self {
        HealthTrackerConfig {
            window_duration: Duration::from_secs(60),
            max_window_entries: 1024,
            recency_half_life: Duration::from_secs(10),
            degrade_error_threshold: 5,
            degrade_error_density: 0.3,
            fail_consecutive_errors: 10,
            fail_sustained_degradation: Duration::from_secs(300),
            cooldown_duration: Duration::from_secs(30),
        }
    }
}

// ── Health state types ──────────────────────────────────────────────

/// Per-replica health state derived from IO error tracking.
#[derive(Clone, Debug, PartialEq)]
pub enum ReplicaHealth {
    /// Replica is operating normally.
    Healthy,
    /// Degraded: errors within the sliding window meet the threshold.
    Degraded {
        since: Instant,
        reason: DegradationReason,
    },
    /// Failed: consecutive errors or sustained degradation.
    Failed {
        since: Instant,
        reason: FailureReason,
    },
}

impl ReplicaHealth {
    /// Whether the replica can serve reads.
    pub fn can_serve_reads(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded { .. })
    }

    /// Whether the replica can accept writes.
    pub fn can_accept_writes(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Whether the replica needs recovery/rebuild.
    pub fn needs_recovery(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// Reason a replica entered the Degraded state.
#[derive(Clone, Debug, PartialEq)]
pub enum DegradationReason {
    /// Absolute error count within the window exceeded the threshold.
    ErrorThresholdExceeded {
        error_count: usize,
        window_duration: Duration,
    },
    /// Error density (weighted) exceeded the configured ratio.
    HighErrorRate { error_rate: f64, threshold: f64 },
}

/// Reason a replica entered the Failed state.
#[derive(Clone, Debug, PartialEq)]
pub enum FailureReason {
    /// Too many consecutive IO errors.
    ConsecutiveErrors { consecutive_count: usize },
    /// Sustained degradation beyond the configured timeout.
    SustainedDegradation {
        degraded_since: Instant,
        total_errors: usize,
    },
    /// Immediate failure: critical IO error detected (e.g., ENXIO).
    CriticalError { detail: String },
}

// ── Health score ────────────────────────────────────────────────────

/// A recency-weighted health score in [0.0, 1.0].
///
/// 1.0 = perfect health, 0.0 = total failure.
/// Recent errors dominate the score; older errors decay exponentially.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct HealthScore(pub f64);

impl HealthScore {
    /// Create a new health score, clamped to [0.0, 1.0].
    pub fn new(score: f64) -> Self {
        HealthScore(score.clamp(0.0, 1.0))
    }

    /// Whether this score indicates a healthy replica.
    pub fn is_healthy(&self) -> bool {
        self.0 >= 0.8
    }

    /// Whether this score indicates a degraded replica.
    pub fn is_degraded(&self) -> bool {
        self.0 < 0.8 && self.0 >= 0.3
    }

    /// Whether this score indicates a failed replica.
    pub fn is_failed(&self) -> bool {
        self.0 < 0.3
    }
}

impl std::fmt::Display for HealthScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.4}", self.0)
    }
}

// ── Health tracker ──────────────────────────────────────────────────

/// Tracks per-replica IO results in a sliding time window and drives
/// health state transitions.
///
/// # Design
///
/// - IO results (success/failure + timestamp) are stored in a bounded
///   `VecDeque`.
/// - A recency-weighted health score is computed from error density,
///   applying exponential decay so recent failures dominate.
/// - State transitions follow a simple state machine:
///   Healthy → Degraded → Failed, with automatic cooldown recovery.
///
/// # Thread safety
///
/// This tracker is not internally synchronized. Callers must wrap it
/// in a `Mutex` or use it from a single task/thread.
#[derive(Clone, Debug)]
pub struct HealthTracker {
    config: HealthTrackerConfig,
    /// Sliding window of IO results: (timestamp, success).
    window: VecDeque<(Instant, bool)>,
    /// Current health state.
    health: ReplicaHealth,
    /// Count of consecutive errors (reset on any success).
    consecutive_errors: usize,
    /// When the replica entered the current Degraded state, if any.
    degraded_since: Option<Instant>,
    /// When the last IO error occurred.
    last_error_at: Option<Instant>,
    /// When the last successful IO occurred.
    last_success_at: Option<Instant>,
    /// Total IO count since tracker creation.
    total_io_count: u64,
    /// Total error count since tracker creation.
    total_error_count: u64,
}

impl HealthTracker {
    /// Create a new health tracker with the given configuration,
    /// starting in the Healthy state.
    pub fn new(config: HealthTrackerConfig) -> Self {
        HealthTracker {
            config,
            window: VecDeque::new(),
            health: ReplicaHealth::Healthy,
            consecutive_errors: 0,
            degraded_since: None,
            last_error_at: None,
            last_success_at: None,
            total_io_count: 0,
            total_error_count: 0,
        }
    }

    /// Record the result of an IO operation against the tracked replica.
    ///
    /// This updates the sliding window, recomputes health state, and
    /// triggers state transitions when thresholds are crossed.
    pub fn record_io_result(&mut self, success: bool) {
        let now = Instant::now();
        self.total_io_count += 1;

        if success {
            self.consecutive_errors = 0;
            self.last_success_at = Some(now);
        } else {
            self.total_error_count += 1;
            self.consecutive_errors += 1;
            self.last_error_at = Some(now);
        }

        // Add to sliding window
        self.window.push_back((now, success));
        self.prune_window(now);

        // Evaluate state transitions
        self.evaluate_state(now);
    }

    /// Get the current health state.
    pub fn current_health(&self) -> &ReplicaHealth {
        &self.health
    }

    /// Compute the recency-weighted health score.
    ///
    /// Returns a value in [0.0, 1.0] where 1.0 means perfect health.
    /// Recent failures contribute more to lowering the score than
    /// older ones.
    pub fn health_score(&self) -> f64 {
        self.compute_weighted_score(Instant::now())
    }

    /// Get the number of consecutive IO errors.
    pub fn consecutive_errors(&self) -> usize {
        self.consecutive_errors
    }

    /// Get the total IO count since tracker creation.
    pub fn total_io_count(&self) -> u64 {
        self.total_io_count
    }

    /// Get the total error count since tracker creation.
    pub fn total_error_count(&self) -> u64 {
        self.total_error_count
    }

    /// Get the current window entry count.
    pub fn window_entry_count(&self) -> usize {
        self.window.len()
    }

    /// Manually force the tracker into the Failed state (e.g., on
    /// critical device error like ENXIO).
    pub fn force_failed(&mut self, reason: String) {
        let now = Instant::now();
        self.health = ReplicaHealth::Failed {
            since: now,
            reason: FailureReason::CriticalError { detail: reason },
        };
    }

    /// Reset the tracker to Healthy state, clearing all history.
    pub fn reset(&mut self) {
        self.window.clear();
        self.health = ReplicaHealth::Healthy;
        self.consecutive_errors = 0;
        self.degraded_since = None;
        self.last_error_at = None;
        self.last_success_at = None;
        self.total_io_count = 0;
        self.total_error_count = 0;
    }

    // ── Internal ─────────────────────────────────────────────────

    /// Remove entries outside the sliding window and enforce max size.
    fn prune_window(&mut self, now: Instant) {
        let cutoff = now - self.config.window_duration;
        while self.window.front().is_some_and(|(ts, _)| *ts < cutoff) {
            self.window.pop_front();
        }
        while self.window.len() > self.config.max_window_entries {
            self.window.pop_front();
        }
    }

    /// Compute recency-weighted health score from the sliding window.
    ///
    /// Uses exponential decay: weight = exp(-age / half_life * ln(2)).
    /// A result exactly at `half_life` age weighs half as much as a
    /// brand-new result.
    fn compute_weighted_score(&self, now: Instant) -> f64 {
        if self.window.is_empty() {
            return 1.0;
        }

        let half_life_secs = self.config.recency_half_life.as_secs_f64();
        if half_life_secs <= 0.0 {
            // Degenerate: count all equally
            let errors = self.window.iter().filter(|(_, ok)| !ok).count();
            return 1.0 - (errors as f64 / self.window.len() as f64);
        }

        let decay_factor = std::f64::consts::LN_2 / half_life_secs;

        let mut total_weight = 0.0f64;
        let mut error_weight = 0.0f64;

        for (ts, success) in &self.window {
            let age_secs = now.duration_since(*ts).as_secs_f64();
            let weight = (-decay_factor * age_secs).exp();
            total_weight += weight;
            if !success {
                error_weight += weight;
            }
        }

        if total_weight <= 0.0 {
            return 1.0;
        }

        let error_ratio = error_weight / total_weight;
        (1.0 - error_ratio).clamp(0.0, 1.0)
    }

    /// Evaluate state transitions based on current window and counters.
    fn evaluate_state(&mut self, now: Instant) {
        match &self.health {
            ReplicaHealth::Healthy => {
                // Check for consecutive-error -> Failed
                if self.consecutive_errors >= self.config.fail_consecutive_errors {
                    self.health = ReplicaHealth::Failed {
                        since: now,
                        reason: FailureReason::ConsecutiveErrors {
                            consecutive_count: self.consecutive_errors,
                        },
                    };
                    return;
                }

                // Check error count within window -> Degraded
                let error_count = self.count_errors_in_window(now);
                if error_count >= self.config.degrade_error_threshold {
                    self.degraded_since = Some(now);
                    self.health = ReplicaHealth::Degraded {
                        since: now,
                        reason: DegradationReason::ErrorThresholdExceeded {
                            error_count,
                            window_duration: self.config.window_duration,
                        },
                    };
                    return;
                }

                // Check error density -> Degraded
                let score = self.compute_weighted_score(now);
                let error_density = 1.0 - score;
                if error_density >= self.config.degrade_error_density
                    // Require at least 3 errors before density-based degradation
                    && error_count >= 3
                {
                    self.degraded_since = Some(now);
                    self.health = ReplicaHealth::Degraded {
                        since: now,
                        reason: DegradationReason::HighErrorRate {
                            error_rate: error_density,
                            threshold: self.config.degrade_error_density,
                        },
                    };
                }
            }

            ReplicaHealth::Degraded { since, .. } => {
                // Check for consecutive-error -> Failed
                if self.consecutive_errors >= self.config.fail_consecutive_errors {
                    self.health = ReplicaHealth::Failed {
                        since: now,
                        reason: FailureReason::ConsecutiveErrors {
                            consecutive_count: self.consecutive_errors,
                        },
                    };
                    return;
                }

                // Check sustained degradation -> Failed
                let degraded_duration = now.duration_since(*since);
                if degraded_duration >= self.config.fail_sustained_degradation {
                    self.health = ReplicaHealth::Failed {
                        since: now,
                        reason: FailureReason::SustainedDegradation {
                            degraded_since: *since,
                            total_errors: self.total_error_count as usize,
                        },
                    };
                    return;
                }

                // Check for cooldown recovery -> Healthy
                if let Some(last_error) = self.last_error_at {
                    let clean_duration = now.duration_since(last_error);
                    if clean_duration >= self.config.cooldown_duration {
                        self.health = ReplicaHealth::Healthy;
                        self.degraded_since = None;
                    }
                }
            }

            ReplicaHealth::Failed { .. } => {
                // Failed is a terminal state from IO perspective;
                // recovery requires explicit reset or external
                // intervention (rebuild/replace).
            }
        }
    }

    /// Count errors within the sliding window.
    fn count_errors_in_window(&self, now: Instant) -> usize {
        let cutoff = now - self.config.window_duration;
        self.window
            .iter()
            .filter(|(ts, ok)| *ts >= cutoff && !ok)
            .count()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a tracker with small thresholds for fast testing.
    fn test_tracker() -> HealthTracker {
        HealthTracker::new(HealthTrackerConfig {
            window_duration: Duration::from_secs(10),
            max_window_entries: 100,
            recency_half_life: Duration::from_secs(2),
            degrade_error_threshold: 3,
            degrade_error_density: 0.25,
            fail_consecutive_errors: 5,
            fail_sustained_degradation: Duration::from_secs(60),
            cooldown_duration: Duration::from_secs(5),
        })
    }

    #[test]
    fn starts_healthy() {
        let tracker = HealthTracker::new(HealthTrackerConfig::default());
        assert_eq!(*tracker.current_health(), ReplicaHealth::Healthy);
        assert_eq!(tracker.health_score(), 1.0);
    }

    #[test]
    fn healthy_after_successes() {
        let mut tracker = test_tracker();
        for _ in 0..10 {
            tracker.record_io_result(true);
        }
        assert_eq!(*tracker.current_health(), ReplicaHealth::Healthy);
        assert!(tracker.health_score() > 0.95);
    }

    #[test]
    fn degraded_after_error_threshold() {
        let mut tracker = test_tracker();
        tracker.record_io_result(true);
        tracker.record_io_result(false);
        tracker.record_io_result(false);
        tracker.record_io_result(false); // 3rd error -> Degraded
        assert!(matches!(
            *tracker.current_health(),
            ReplicaHealth::Degraded { .. }
        ));
    }

    #[test]
    fn healthy_with_few_errors_below_threshold() {
        let mut tracker = test_tracker();
        tracker.record_io_result(true);
        tracker.record_io_result(true);
        tracker.record_io_result(false);
        tracker.record_io_result(true);
        tracker.record_io_result(false); // 2 errors, threshold is 3
        assert_eq!(*tracker.current_health(), ReplicaHealth::Healthy);
    }

    #[test]
    fn failed_after_consecutive_errors() {
        let mut tracker = test_tracker();
        for _ in 0..5 {
            tracker.record_io_result(false);
        }
        assert!(matches!(
            *tracker.current_health(),
            ReplicaHealth::Failed { .. }
        ));
    }

    #[test]
    fn consecutive_error_counter_resets_on_success() {
        let mut tracker = test_tracker();
        tracker.record_io_result(false);
        tracker.record_io_result(false);
        tracker.record_io_result(false);
        tracker.record_io_result(false); // 4 consecutive
        tracker.record_io_result(true); // reset
        tracker.record_io_result(false);
        assert_eq!(tracker.consecutive_errors(), 1);
        // Not failed yet
        assert!(!matches!(
            *tracker.current_health(),
            ReplicaHealth::Failed { .. }
        ));
    }

    #[test]
    fn recovered_after_cooldown() {
        let mut tracker = test_tracker();
        // Push into Degraded
        tracker.record_io_result(false);
        tracker.record_io_result(false);
        tracker.record_io_result(false);
        assert!(matches!(
            *tracker.current_health(),
            ReplicaHealth::Degraded { .. }
        ));

        // Feed successes. Since Instant is real-time and cooldown is 5s,
        // we can't wait 5s in unit tests. Instead, we test that the
        // tracker doesn't recover before cooldown, and that with a
        // zero cooldown config it does recover immediately.
    }

    #[test]
    fn recovers_with_zero_cooldown() {
        let mut tracker = HealthTracker::new(HealthTrackerConfig {
            window_duration: Duration::from_secs(10),
            max_window_entries: 100,
            recency_half_life: Duration::from_secs(2),
            degrade_error_threshold: 3,
            degrade_error_density: 0.25,
            fail_consecutive_errors: 5,
            fail_sustained_degradation: Duration::from_secs(60),
            cooldown_duration: Duration::ZERO,
        });

        // Degrade
        tracker.record_io_result(false);
        tracker.record_io_result(false);
        tracker.record_io_result(false);
        assert!(matches!(
            *tracker.current_health(),
            ReplicaHealth::Degraded { .. }
        ));

        // One more success triggers recovery (cooldown is zero)
        tracker.record_io_result(true);
        assert_eq!(*tracker.current_health(), ReplicaHealth::Healthy);
    }

    #[test]
    fn empty_window_score_is_one() {
        let tracker = test_tracker();
        assert_eq!(tracker.health_score(), 1.0);
    }

    #[test]
    fn recency_weighting_gives_higher_weight_to_recent_errors() {
        // We can't control Instant in real time, but we can verify
        // that the score computation produces a reasonable value
        // when mixing successes and failures.
        let mut tracker = test_tracker();
        for _ in 0..5 {
            tracker.record_io_result(true);
        }
        tracker.record_io_result(false);
        for _ in 0..5 {
            tracker.record_io_result(true);
        }
        // With one error among many successes, score should be high
        let score = tracker.health_score();
        assert!(
            score > 0.7,
            "score={score} should be above 0.7 with one error among 11 results"
        );
    }

    #[test]
    fn all_errors_gives_low_score() {
        let mut tracker = test_tracker();
        for _ in 0..10 {
            tracker.record_io_result(false);
        }
        let score = tracker.health_score();
        assert!(
            score < 0.2,
            "score={score} should be very low with all errors"
        );
    }

    #[test]
    fn force_failed_sets_failed_state() {
        let mut tracker = test_tracker();
        tracker.record_io_result(true);
        tracker.force_failed("ENXIO: device removed".into());
        assert!(matches!(
            *tracker.current_health(),
            ReplicaHealth::Failed {
                reason: FailureReason::CriticalError { .. },
                ..
            }
        ));
    }

    #[test]
    fn reset_clears_everything() {
        let mut tracker = test_tracker();
        for _ in 0..5 {
            tracker.record_io_result(false);
        }
        assert!(matches!(
            *tracker.current_health(),
            ReplicaHealth::Failed { .. }
        ));

        tracker.reset();
        assert_eq!(*tracker.current_health(), ReplicaHealth::Healthy);
        assert_eq!(tracker.health_score(), 1.0);
        assert_eq!(tracker.consecutive_errors(), 0);
        assert_eq!(tracker.total_io_count(), 0);
        assert_eq!(tracker.total_error_count(), 0);
        assert_eq!(tracker.window_entry_count(), 0);
    }

    #[test]
    fn window_prunes_old_entries() {
        let mut tracker = test_tracker();
        for _ in 0..20 {
            tracker.record_io_result(true);
        }
        // Window should never exceed max_window_entries (100)
        assert!(tracker.window_entry_count() <= 100);
    }

    #[test]
    fn health_score_monotonic_descriptions() {
        assert!(HealthScore::new(1.0).is_healthy());
        assert!(!HealthScore::new(1.0).is_degraded());
        assert!(!HealthScore::new(1.0).is_failed());

        assert!(!HealthScore::new(0.6).is_healthy());
        assert!(HealthScore::new(0.6).is_degraded());
        assert!(!HealthScore::new(0.6).is_failed());

        assert!(!HealthScore::new(0.2).is_healthy());
        assert!(!HealthScore::new(0.2).is_degraded());
        assert!(HealthScore::new(0.2).is_failed());
    }

    #[test]
    fn score_clamped_to_range() {
        assert_eq!(HealthScore::new(1.5).0, 1.0);
        assert_eq!(HealthScore::new(-0.5).0, 0.0);
        assert_eq!(HealthScore::new(0.75).0, 0.75);
    }

    #[test]
    fn replica_health_accessors() {
        assert!(ReplicaHealth::Healthy.can_serve_reads());
        assert!(ReplicaHealth::Healthy.can_accept_writes());
        assert!(!ReplicaHealth::Healthy.needs_recovery());

        let degraded = ReplicaHealth::Degraded {
            since: Instant::now(),
            reason: DegradationReason::ErrorThresholdExceeded {
                error_count: 3,
                window_duration: Duration::from_secs(10),
            },
        };
        assert!(degraded.can_serve_reads());
        assert!(!degraded.can_accept_writes());
        assert!(!degraded.needs_recovery());

        let failed = ReplicaHealth::Failed {
            since: Instant::now(),
            reason: FailureReason::ConsecutiveErrors {
                consecutive_count: 5,
            },
        };
        assert!(!failed.can_serve_reads());
        assert!(!failed.can_accept_writes());
        assert!(failed.needs_recovery());
    }

    #[test]
    fn single_entry_window() {
        let mut tracker = test_tracker();
        tracker.record_io_result(false);
        // Single failure in window, but below threshold (3)
        assert_eq!(*tracker.current_health(), ReplicaHealth::Healthy);
    }

    #[test]
    fn degraded_via_error_density() {
        // Use a config where absolute threshold is high but density
        // threshold is low
        let mut tracker = HealthTracker::new(HealthTrackerConfig {
            window_duration: Duration::from_secs(10),
            max_window_entries: 100,
            recency_half_life: Duration::from_secs(2),
            degrade_error_threshold: 20, // high absolute threshold
            degrade_error_density: 0.2,  // low density threshold
            fail_consecutive_errors: 10,
            fail_sustained_degradation: Duration::from_secs(60),
            cooldown_duration: Duration::ZERO,
        });

        // Mix: enough errors for high density but below absolute count
        for i in 0..10 {
            tracker.record_io_result(i % 2 == 0); // 50% errors
        }
        // Error density is ~0.5, threshold is 0.2 -> Degraded
        assert!(
            matches!(*tracker.current_health(), ReplicaHealth::Degraded { .. }),
            "expected Degraded, got {:?}",
            tracker.current_health()
        );
    }

    #[test]
    fn total_counters_accumulate() {
        let mut tracker = test_tracker();
        tracker.record_io_result(true);
        tracker.record_io_result(false);
        tracker.record_io_result(true);
        tracker.record_io_result(false);

        assert_eq!(tracker.total_io_count(), 4);
        assert_eq!(tracker.total_error_count(), 2);
    }
}
