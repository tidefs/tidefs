// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Drift-adaptive timeout window widening.
//!
//! Static timeouts break under real network conditions. Ceph uses fixed
//! `osd_heartbeat_grace` (20s) and `mon_osd_down_out_interval` (300s).
//! etcd uses a static Raft election timeout. Both cause false positives
//! during network jitter and false negatives during genuine failures.
//!
//! TideFS's AdaptiveTimeout observes heartbeat inter-arrival times and
//! adjusts the window based on actual network behavior. When the network
//! is jittery, the window widens. When it stabilizes, the window tightens.
//! No operator tuning required.

use std::collections::VecDeque;
use std::time::Duration;

/// A drift-adaptive timeout that adjusts its window based on observed
/// heartbeat inter-arrival times.
///
/// # How it works
///
/// 1. Every heartbeat inter-arrival time is recorded.
/// 2. P99 inter-arrival time is computed from recent history.
/// 3. Median drift from baseline is tracked.
/// 4. Window multiplier adjusts: widens when P99 or drift is high,
///    tightens when both are low.
#[derive(Clone, Debug)]
pub struct AdaptiveTimeout {
    /// Baseline heartbeat interval (e.g., 500ms).
    baseline_interval: Duration,

    /// Current window multiplier — widens during instability.
    window_multiplier: f64,

    /// Recent heartbeat inter-arrival times.
    inter_arrival_history: VecDeque<Duration>,

    /// Maximum history to retain.
    max_history: usize,

    /// Multiplier bounds.
    min_multiplier: f64,
    max_multiplier: f64,

    /// Jitter from observed inter-arrival variance (P99).
    current_jitter_p99: Duration,

    /// Drift accumulation — how much the cluster's aggregate latency
    /// has changed relative to baseline.
    drift_estimate: f64,
}

impl AdaptiveTimeout {
    /// Create a new adaptive timeout.
    ///
    /// `baseline_interval` is the expected heartbeat interval under
    /// normal conditions. The timeout window will adapt around this.
    pub fn new(baseline_interval: Duration) -> Self {
        AdaptiveTimeout {
            baseline_interval,
            window_multiplier: 2.0, // start conservative
            inter_arrival_history: VecDeque::new(),
            max_history: 64,
            min_multiplier: 1.5,
            max_multiplier: 10.0,
            current_jitter_p99: Duration::ZERO,
            drift_estimate: 1.0,
        }
    }

    /// The current timeout window — how long to wait before escalating
    /// suspicion.
    pub fn current_window(&self) -> Duration {
        let base = self.baseline_interval.mul_f64(self.window_multiplier);
        base + self.current_jitter_p99
    }

    /// Feed a new heartbeat inter-arrival observation.
    ///
    /// Call this whenever a heartbeat arrives, passing the time since
    /// the previous heartbeat from the same node.
    pub fn observe(&mut self, inter_arrival: Duration) {
        self.inter_arrival_history.push_back(inter_arrival);
        if self.inter_arrival_history.len() > self.max_history {
            self.inter_arrival_history.pop_front();
        }

        // Compute P99 from recent history
        if !self.inter_arrival_history.is_empty() {
            let mut sorted: Vec<Duration> = self.inter_arrival_history.iter().copied().collect();
            sorted.sort();
            let p99_idx = ((sorted.len() as f64) * 0.99) as usize;
            self.current_jitter_p99 = sorted[p99_idx.min(sorted.len() - 1)];
        }

        // Compute drift: how much the median has shifted from baseline
        if !self.inter_arrival_history.is_empty() {
            let mut sorted: Vec<Duration> = self.inter_arrival_history.iter().copied().collect();
            sorted.sort();
            let median = sorted[sorted.len() / 2];
            self.drift_estimate =
                median.as_secs_f64() / self.baseline_interval.as_secs_f64().max(0.001);
        }

        // Widen multiplier if drift or jitter is high
        if self.drift_estimate > 2.0 || self.current_jitter_p99 > self.baseline_interval * 5 {
            self.window_multiplier = (self.window_multiplier * 1.5).min(self.max_multiplier);
        } else if self.drift_estimate < 1.2 && self.current_jitter_p99 < self.baseline_interval * 2
        {
            // Tighten during calm
            self.window_multiplier = (self.window_multiplier * 0.9).max(self.min_multiplier);
        }
    }

    /// Reset the timeout to its initial conservative state.
    pub fn reset(&mut self) {
        self.window_multiplier = 2.0;
        self.inter_arrival_history.clear();
        self.current_jitter_p99 = Duration::ZERO;
        self.drift_estimate = 1.0;
    }

    /// Current drift estimate (1.0 = exactly at baseline).
    pub fn drift_estimate(&self) -> f64 {
        self.drift_estimate
    }

    /// Current P99 jitter.
    pub fn jitter_p99(&self) -> Duration {
        self.current_jitter_p99
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_window_is_conservative() {
        let timeout = AdaptiveTimeout::new(Duration::from_millis(500));
        // baseline 500ms * 2.0 multiplier = 1000ms + 0 jitter
        assert_eq!(timeout.current_window(), Duration::from_millis(1000));
    }

    #[test]
    fn stable_network_tightens_window() {
        let mut timeout = AdaptiveTimeout::new(Duration::from_millis(500));
        // Feed many stable observations
        for _ in 0..50 {
            timeout.observe(Duration::from_millis(500));
        }
        // Should have tightened significantly from initial 2.0
        assert!(timeout.window_multiplier < 1.8);
    }

    #[test]
    fn jittery_network_widens_window() {
        let mut timeout = AdaptiveTimeout::new(Duration::from_millis(500));
        // Feed highly variable observations
        for i in 0..50 {
            let jitter = if i % 3 == 0 {
                Duration::from_millis(3000)
            } else {
                Duration::from_millis(500)
            };
            timeout.observe(jitter);
        }
        // Should have widened beyond initial 2.0
        assert!(timeout.window_multiplier > 2.0);
    }

    #[test]
    fn reset_restores_initial_state() {
        let mut timeout = AdaptiveTimeout::new(Duration::from_millis(500));
        for _ in 0..50 {
            timeout.observe(Duration::from_millis(2000));
        }
        assert!(timeout.window_multiplier > 2.0);
        timeout.reset();
        assert_eq!(timeout.window_multiplier, 2.0);
        assert!(timeout.inter_arrival_history.is_empty());
    }
}
