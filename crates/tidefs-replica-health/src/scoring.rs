//! Per-replica health scoring from I/O success/failure rates and latency.
//!
//! Computes rolling success/failure counters, average latency windows,
//! and BLAKE3 checksum mismatch counts to produce a health score
//! consumable by the placement planner (#5157) and rebuild planner (#5153).

use serde::{Deserialize, Serialize};

use crate::state_machine::DegradationState;

/// Rolling health score for a single replica.
///
/// Updated on every I/O completion (success or failure). The score is
/// a 0-100 integer where:
/// - 100: perfect health (no failures, low latency, zero mismatches)
/// - 70-99: minor issues (occasional failures or latency spikes)
/// - 40-69: degraded (elevated failures, needs investigation)
/// - 1-39: critical (approaching Dead, avoid for new placement)
/// - 0: dead or checksum-corrupted
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicaHealthScore {
    /// Rolling success count (recent window).
    pub recent_successes: u64,
    /// Rolling failure count (recent window).
    pub recent_failures: u64,
    /// Rolling average latency in microseconds.
    pub avg_latency_us: u64,
    /// P99 latency in microseconds.
    pub p99_latency_us: u64,
    /// Maximum latency observed in window.
    pub max_latency_us: u64,
    /// BLAKE3 checksum mismatch count (cumulative, reset on state change).
    pub checksum_mismatches: u32,
    /// Total I/O operations in window.
    pub total_ops: u64,
    /// Computed health score (0-100).
    pub score: u32,
    /// The degradation state derived from this score.
    pub degradation_state: DegradationState,
    /// When the score was last updated (ns).
    pub last_updated_ns: u64,
}

impl Default for ReplicaHealthScore {
    fn default() -> Self {
        ReplicaHealthScore {
            recent_successes: 0,
            recent_failures: 0,
            avg_latency_us: 0,
            p99_latency_us: 0,
            max_latency_us: 0,
            checksum_mismatches: 0,
            total_ops: 0,
            score: 100,
            degradation_state: DegradationState::Healthy,
            last_updated_ns: 0,
        }
    }
}

/// Rolling I/O scorer that maintains sliding-window stats.
///
/// Internally tracks recent I/O outcomes in a ring buffer. On each
/// update, recomputes the composite health score from success rate,
/// latency distribution, and checksum mismatch penalty.
#[derive(Clone, Debug)]
pub struct ReplicaHealthScorer {
    /// Configuration for scoring thresholds.
    config: ScoreConfig,
    /// Ring buffer of recent I/O outcomes.
    window: Vec<IoOutcome>,
    /// Write position in the ring buffer.
    cursor: usize,
    /// Whether the ring buffer is full.
    full: bool,
    /// Total lifetime I/O count.
    lifetime_ops: u64,
    /// Cumulative checksum mismatches (reset on state transitions).
    checksum_mismatches: u32,
    /// Current degradation state.
    degradation_state: DegradationState,
}

/// A single I/O outcome in the rolling window.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
struct IoOutcome {
    /// Whether the I/O was successful.
    success: bool,
    /// Latency in microseconds.
    latency_us: u64,
    /// Was a checksum mismatch detected?
    checksum_mismatch: bool,
    /// Was an unrecoverable error encountered?
    unrecoverable: bool,
}

/// Configuration for health score computation.
#[derive(Clone, Debug)]
pub struct ScoreConfig {
    /// Number of recent I/O operations to track.
    pub window_size: usize,
    /// Maximum latency (us) before an I/O is counted as slow.
    pub slow_threshold_us: u64,
    /// Maximum latency (us) before an I/O counts against health.
    pub max_latency_us: u64,
    /// Weight of success rate in the composite score (0.0-1.0).
    pub success_rate_weight: f64,
    /// Weight of latency in the composite score (0.0-1.0).
    pub latency_weight: f64,
    /// Weight of checksum mismatches in the composite score (0.0-1.0).
    pub checksum_weight: f64,
}

impl Default for ScoreConfig {
    fn default() -> Self {
        ScoreConfig {
            window_size: 256,
            slow_threshold_us: 10_000, // 10ms
            max_latency_us: 100_000,   // 100ms
            success_rate_weight: 0.5,
            latency_weight: 0.3,
            checksum_weight: 0.2,
        }
    }
}

impl ReplicaHealthScorer {
    /// Create a new scorer with default configuration.
    pub fn new(config: ScoreConfig) -> Self {
        ReplicaHealthScorer {
            window: vec![
                IoOutcome {
                    success: true,
                    latency_us: 0,
                    checksum_mismatch: false,
                    unrecoverable: false,
                };
                config.window_size
            ],
            cursor: 0,
            full: false,
            lifetime_ops: 0,
            checksum_mismatches: 0,
            degradation_state: DegradationState::Healthy,
            config,
        }
    }

    /// Record a successful I/O completion.
    pub fn record_success(&mut self, latency_us: u64) {
        self.push(IoOutcome {
            success: true,
            latency_us,
            checksum_mismatch: false,
            unrecoverable: false,
        });
    }

    /// Record a failed I/O completion.
    pub fn record_failure(&mut self, latency_us: u64, unrecoverable: bool) {
        self.push(IoOutcome {
            success: false,
            latency_us,
            checksum_mismatch: false,
            unrecoverable,
        });
    }

    /// Record a checksum mismatch on an I/O.
    pub fn record_checksum_mismatch(&mut self, latency_us: u64) {
        self.checksum_mismatches += 1;
        self.push(IoOutcome {
            success: false,
            latency_us,
            checksum_mismatch: true,
            unrecoverable: false,
        });
    }

    /// Reset checksum mismatch counter (e.g., after state transition).
    pub fn reset_checksum_mismatches(&mut self) {
        self.checksum_mismatches = 0;
    }

    /// Set the current degradation state (from the transition engine).
    pub fn set_degradation_state(&mut self, state: DegradationState) {
        if self.degradation_state != state {
            self.checksum_mismatches = 0;
        }
        self.degradation_state = state;
    }

    /// Compute the current health score.
    /// Returns a 0-100 score with full breakdown.
    pub fn compute_score(&self, now_ns: u64) -> ReplicaHealthScore {
        if self.lifetime_ops == 0 {
            return ReplicaHealthScore {
                degradation_state: self.degradation_state,
                last_updated_ns: now_ns,
                ..Default::default()
            };
        }

        let count = if self.full {
            self.config.window_size
        } else {
            self.cursor
        };

        if count == 0 {
            return ReplicaHealthScore {
                degradation_state: self.degradation_state,
                last_updated_ns: now_ns,
                ..Default::default()
            };
        }

        let successes = self.window[..count].iter().filter(|o| o.success).count() as u64;
        let failures = count as u64 - successes;

        // Compute latency statistics
        let mut latencies: Vec<u64> = self.window[..count].iter().map(|o| o.latency_us).collect();
        latencies.sort_unstable();

        let avg_latency_us = if count > 0 {
            latencies.iter().sum::<u64>() / count as u64
        } else {
            0
        };

        let p99_idx = ((count as f64) * 0.99) as usize;
        let p99_latency_us = if p99_idx < count {
            latencies[p99_idx]
        } else {
            latencies[count - 1]
        };
        let max_latency_us = latencies.last().copied().unwrap_or(0);

        // Composite score calculation
        let success_rate = if count > 0 {
            successes as f64 / count as f64
        } else {
            1.0
        };

        let latency_penalty = if self.config.max_latency_us > 0 {
            (avg_latency_us as f64 / self.config.max_latency_us as f64).min(1.0)
        } else {
            0.0
        };

        let checksum_penalty = if self.config.window_size > 0 {
            (self.checksum_mismatches as f64 / self.config.window_size as f64).min(1.0)
        } else {
            0.0
        };

        let raw_score = 100.0
            * (self.config.success_rate_weight * success_rate
                + self.config.latency_weight * (1.0 - latency_penalty)
                + self.config.checksum_weight * (1.0 - checksum_penalty));

        let score = (raw_score.clamp(0.0, 100.0)) as u32;

        ReplicaHealthScore {
            recent_successes: successes,
            recent_failures: failures,
            avg_latency_us,
            p99_latency_us,
            max_latency_us,
            checksum_mismatches: self.checksum_mismatches,
            total_ops: count as u64,
            score,
            degradation_state: self.degradation_state,
            last_updated_ns: now_ns,
        }
    }

    /// Return lifetime I/O count.
    pub fn lifetime_ops(&self) -> u64 {
        self.lifetime_ops
    }

    /// Current degradation state.
    pub fn degradation_state(&self) -> DegradationState {
        self.degradation_state
    }

    // ── Internal ────────────────────────────────────────────────────

    fn push(&mut self, outcome: IoOutcome) {
        self.window[self.cursor] = outcome;
        self.cursor += 1;
        self.lifetime_ops += 1;
        if self.cursor >= self.config.window_size {
            self.cursor = 0;
            self.full = true;
        }
    }
}

/// Metrics snapshot for export through the control-plane API.
///
/// Provides a single-point-in-time view of replica health for
/// placement planner and rebuild planner consumption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicaHealthMetrics {
    /// Identifier for the replica (NodeId as u64).
    pub replica_id: u64,
    /// Current computed health score (0-100).
    pub health_score: u32,
    /// Current degradation state.
    pub degradation_state: DegradationState,
    /// Success rate in the current window (0.0-1.0).
    pub success_rate: f64,
    /// Recent successes count.
    pub recent_successes: u64,
    /// Recent failures count.
    pub recent_failures: u64,
    /// Average latency in microseconds.
    pub avg_latency_us: u64,
    /// P99 latency in microseconds.
    pub p99_latency_us: u64,
    /// BLAKE3 checksum mismatch count.
    pub checksum_mismatches: u32,
    /// Total lifetime I/O operations.
    pub lifetime_ops: u64,
    /// Whether the replica is currently placeable.
    pub is_placeable: bool,
    /// Whether the replica is excluded from all I/O.
    pub is_excluded: bool,
}

impl ReplicaHealthMetrics {
    /// Create a metrics snapshot from a score.
    pub fn from_score(replica_id: u64, score: &ReplicaHealthScore, lifetime_ops: u64) -> Self {
        ReplicaHealthMetrics {
            replica_id,
            health_score: score.score,
            degradation_state: score.degradation_state,
            success_rate: if score.total_ops > 0 {
                score.recent_successes as f64 / score.total_ops as f64
            } else {
                1.0
            },
            recent_successes: score.recent_successes,
            recent_failures: score.recent_failures,
            avg_latency_us: score.avg_latency_us,
            p99_latency_us: score.p99_latency_us,
            checksum_mismatches: score.checksum_mismatches,
            lifetime_ops,
            is_placeable: score.degradation_state.is_placeable(),
            is_excluded: score.degradation_state.is_excluded(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Rolling window basics ───────────────────────────────────────

    #[test]
    fn new_scorer_starts_at_100() {
        let scorer = ReplicaHealthScorer::new(ScoreConfig::default());
        let score = scorer.compute_score(1000);
        assert_eq!(score.score, 100);
        assert_eq!(score.total_ops, 0);
    }

    #[test]
    fn all_successes_gives_perfect_score() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig {
            window_size: 100,
            ..Default::default()
        });
        for _ in 0..100 {
            scorer.record_success(100); // low latency
        }
        let score = scorer.compute_score(1000);
        assert_eq!(score.recent_successes, 100);
        assert_eq!(score.recent_failures, 0);
        assert!(
            score.score >= 95,
            "score should be near 100, got {}",
            score.score
        );
    }

    #[test]
    fn all_failures_gives_low_score() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig {
            window_size: 100,
            ..Default::default()
        });
        for _ in 0..100 {
            scorer.record_failure(1000, false);
        }
        let score = scorer.compute_score(1000);
        assert_eq!(score.recent_failures, 100);
        assert!(score.score < 60, "score should be low, got {}", score.score);
    }

    #[test]
    fn mixed_success_failure_score() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig {
            window_size: 100,
            ..Default::default()
        });
        for _ in 0..70 {
            scorer.record_success(100);
        }
        for _ in 0..30 {
            scorer.record_failure(5000, false);
        }
        let score = scorer.compute_score(1000);
        assert_eq!(score.recent_successes, 70);
        assert_eq!(score.recent_failures, 30);
        assert!(
            score.score > 50 && score.score < 90,
            "score should be moderate, got {}",
            score.score
        );
    }

    // ── Latency statistics ──────────────────────────────────────────

    #[test]
    fn latency_statistics_are_computed() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig {
            window_size: 100,
            ..Default::default()
        });
        for i in 0..100 {
            scorer.record_success((i * 10) as u64); // 0..990 us
        }
        let score = scorer.compute_score(1000);
        // Average of 0..990 = 495
        assert!(
            score.avg_latency_us >= 450 && score.avg_latency_us <= 550,
            "avg latency around 495, got {}",
            score.avg_latency_us
        );
        // P99 should be around 980
        assert!(
            score.p99_latency_us >= 950,
            "p99 around 980, got {}",
            score.p99_latency_us
        );
        assert_eq!(score.max_latency_us, 990);
    }

    #[test]
    fn high_latency_penalizes_score() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig {
            window_size: 100,
            max_latency_us: 10_000,
            ..Default::default()
        });
        // All ops have high latency (50ms) but succeed
        for _ in 0..100 {
            scorer.record_success(50_000);
        }
        let score = scorer.compute_score(1000);
        assert!(
            score.score < 80,
            "high latency should penalize, got {}",
            score.score
        );
    }

    // ── Checksum mismatch penalty ───────────────────────────────────

    #[test]
    fn checksum_mismatches_penalize_score() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig {
            window_size: 100,
            ..Default::default()
        });
        for _ in 0..95 {
            scorer.record_success(100);
        }
        for _ in 0..5 {
            scorer.record_checksum_mismatch(200);
        }
        let score = scorer.compute_score(1000);
        assert_eq!(score.checksum_mismatches, 5);
        // With weights 0.5+0.3+0.2 and 5 mismatches in window of 100,
        // score should be noticeably penalized but not catastrophic
        assert!(
            score.score < 97,
            "checksum mismatches should penalize, got {}",
            score.score
        );
    }

    #[test]
    fn reset_checksum_mismatches_clears_counter() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig::default());
        scorer.record_checksum_mismatch(100);
        scorer.record_checksum_mismatch(200);
        assert_eq!(scorer.compute_score(1000).checksum_mismatches, 2);

        scorer.reset_checksum_mismatches();
        assert_eq!(scorer.compute_score(2000).checksum_mismatches, 0);
    }

    // ── Ring-buffer wrapping ────────────────────────────────────────

    #[test]
    fn ring_buffer_wraps_correctly() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig {
            window_size: 4,
            ..Default::default()
        });

        // Fill buffer
        scorer.record_success(10);
        scorer.record_success(20);
        scorer.record_failure(30, false);
        scorer.record_success(40);
        assert_eq!(scorer.compute_score(1000).total_ops, 4);

        // Wrap: overwrite oldest
        scorer.record_failure(50, false);
        let score = scorer.compute_score(2000);
        assert_eq!(score.total_ops, 4); // still 4 (window_size)
        assert_eq!(score.recent_successes, 2); // 2 successes left
    }

    // ── Degradation state integration ───────────────────────────────

    #[test]
    fn set_degradation_state_reflects_in_score() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig::default());
        scorer.record_success(100);
        scorer.set_degradation_state(DegradationState::Degraded);

        let score = scorer.compute_score(1000);
        assert_eq!(score.degradation_state, DegradationState::Degraded);
    }

    #[test]
    fn state_change_resets_checksum_mismatches() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig::default());
        scorer.record_checksum_mismatch(100);
        scorer.record_checksum_mismatch(200);

        scorer.set_degradation_state(DegradationState::Degraded);
        assert_eq!(scorer.compute_score(1000).checksum_mismatches, 0);
    }

    // ── Metrics export ──────────────────────────────────────────────

    #[test]
    fn metrics_export_roundtrip() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig {
            window_size: 100,
            ..Default::default()
        });
        for _ in 0..50 {
            scorer.record_success(100);
        }
        for _ in 0..10 {
            scorer.record_failure(5000, false);
        }

        let score = scorer.compute_score(1000);
        let metrics = ReplicaHealthMetrics::from_score(42, &score, scorer.lifetime_ops());

        assert_eq!(metrics.replica_id, 42);
        assert_eq!(metrics.health_score, score.score);
        assert_eq!(metrics.recent_successes, 50);
        assert_eq!(metrics.recent_failures, 10);
        assert_eq!(metrics.lifetime_ops, 60);
        assert!(metrics.is_placeable);
        assert!(!metrics.is_excluded);
    }

    #[test]
    fn metrics_reflects_dead_exclusion() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig::default());
        scorer.set_degradation_state(DegradationState::Dead);
        scorer.record_failure(100, true);

        let score = scorer.compute_score(1000);
        let metrics = ReplicaHealthMetrics::from_score(1, &score, scorer.lifetime_ops());
        assert!(!metrics.is_placeable);
        assert!(metrics.is_excluded);
    }

    #[test]
    fn scorer_lifetime_count_is_correct() {
        let mut scorer = ReplicaHealthScorer::new(ScoreConfig {
            window_size: 10,
            ..Default::default()
        });
        for _ in 0..15 {
            scorer.record_success(100);
        }
        assert_eq!(scorer.lifetime_ops(), 15);
        // Window only holds 10, but lifetime tracks all
        let score = scorer.compute_score(1000);
        assert_eq!(score.total_ops, 10);
    }
}
