// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Drift estimation and classification (source-owned timing model).
//!
//! Estimates clock drift between nodes from observed remote/local clock
//! validation and classifies the drift into canonical drift/trust classes.
//! Drift estimates are used to derive deadline slack for leases and fences.

use alloc::vec::Vec;

use crate::types::{ClockClass, DriftClass, DriftSuspicionState};

/// A drift sample from a single observation.
#[derive(Debug, Clone, Copy)]
pub struct DriftSample {
    /// Estimated skew in nanoseconds (remote - local).
    pub skew_ns: i128,
    /// Observed jitter in nanoseconds.
    pub jitter_ns: u64,
    /// The clock class this sample was taken from.
    pub clock_class: ClockClass,
    /// Local time of observation (monotonic nanoseconds).
    pub observed_at_ns: u64,
}

/// A drift estimator that tracks observed skew and jitter across samples.
///
/// Maintains a sliding window of recent samples and classifies the current
/// drift class based on configured thresholds.
#[derive(Debug, Clone)]
pub struct DriftEstimator {
    /// Current drift classification.
    current_class: DriftClass,
    /// Current suspicion state.
    suspicion_state: DriftSuspicionState,
    /// Recent drift samples (sliding window, max `window_size`).
    samples: Vec<DriftSample>,
    /// Maximum number of samples to retain.
    window_size: usize,
    /// Skew threshold for `ElevatedCluster` (nanoseconds).
    elevated_skew_threshold_ns: u64,
    /// Skew threshold for `SevereCluster` (nanoseconds).
    severe_skew_threshold_ns: u64,
    /// Jitter threshold for elevated classification (nanoseconds).
    jitter_threshold_ns: u64,
    /// Number of consecutive nominal samples for recovery.
    recovery_samples: u32,
    recovery_counter: u32,
    /// Estimated skew from the most recent classification.
    estimated_skew_ns: i128,
    /// Estimated jitter from the most recent classification.
    estimated_jitter_ns: u64,
}

impl DriftEstimator {
    /// Create a new drift estimator with default thresholds.
    ///
    /// Default thresholds are sensible for LAN-connected nodes:
    /// - 1ms elevated skew threshold
    /// - 10ms severe skew threshold
    /// - 500us jitter threshold
    /// - Window of 64 samples
    /// - 16 consecutive nominal samples for recovery
    pub fn new() -> Self {
        DriftEstimator {
            current_class: DriftClass::TrustedLocal,
            suspicion_state: DriftSuspicionState::Nominal,
            samples: Vec::with_capacity(64),
            window_size: 64,
            elevated_skew_threshold_ns: 1_000_000, // 1ms
            severe_skew_threshold_ns: 10_000_000,  // 10ms
            jitter_threshold_ns: 500_000,          // 500us
            recovery_samples: 16,
            recovery_counter: 0,
            estimated_skew_ns: 0,
            estimated_jitter_ns: 0,
        }
    }

    /// Create an estimator with custom thresholds.
    pub fn with_thresholds(
        elevated_skew_ns: u64,
        severe_skew_ns: u64,
        jitter_ns: u64,
        window_size: usize,
        recovery_samples: u32,
    ) -> Self {
        DriftEstimator {
            current_class: DriftClass::TrustedLocal,
            suspicion_state: DriftSuspicionState::Nominal,
            samples: Vec::with_capacity(window_size),
            window_size,
            elevated_skew_threshold_ns: elevated_skew_ns,
            severe_skew_threshold_ns: severe_skew_ns,
            jitter_threshold_ns: jitter_ns,
            recovery_samples,
            recovery_counter: 0,
            estimated_skew_ns: 0,
            estimated_jitter_ns: 0,
        }
    }

    /// Return the current drift classification.
    pub fn drift_class(&self) -> DriftClass {
        self.current_class
    }

    /// Return the current suspicion state.
    pub fn suspicion_state(&self) -> DriftSuspicionState {
        self.suspicion_state
    }

    /// Return the most recent skew estimate.
    pub fn estimated_skew_ns(&self) -> i128 {
        self.estimated_skew_ns
    }

    /// Return the most recent jitter estimate.
    pub fn estimated_jitter_ns(&self) -> u64 {
        self.estimated_jitter_ns
    }

    /// Return the window of recent samples.
    pub fn samples(&self) -> &[DriftSample] {
        &self.samples
    }

    /// Record a drift observation and reclassify.
    ///
    /// Returns the new (possibly unchanged) drift class.
    pub fn observe(&mut self, sample: DriftSample) -> DriftClass {
        // Track whether this individual sample is nominal for recovery.
        let sample_is_nominal = sample.skew_ns.unsigned_abs().min(u64::MAX as u128) as u64
            <= self.elevated_skew_threshold_ns
            && sample.jitter_ns <= self.jitter_threshold_ns;
        // Maintain sliding window.
        self.samples.push(sample);
        if self.samples.len() > self.window_size {
            self.samples.remove(0);
        }

        // Compute aggregate skew and jitter from the window.
        let count = self.samples.len() as i128;
        if count == 0 {
            return self.current_class;
        }

        let total_skew: i128 = self.samples.iter().map(|s| s.skew_ns).sum();
        let avg_skew = total_skew / count;
        let max_jitter = self.samples.iter().map(|s| s.jitter_ns).max().unwrap_or(0);

        self.estimated_skew_ns = avg_skew;
        self.estimated_jitter_ns = max_jitter;

        // Track consecutive nominal samples for recovery.
        if sample_is_nominal {
            self.recovery_counter = self.recovery_counter.saturating_add(1);
        } else {
            self.recovery_counter = 0;
        }
        if self.recovery_counter >= self.recovery_samples {
            self.current_class = DriftClass::NominalCluster;
            self.suspicion_state = DriftSuspicionState::Recovered;
            self.recovery_counter = 0;
            return self.current_class;
        }

        let abs_skew: u64 = avg_skew.unsigned_abs().min(u64::MAX as u128) as u64;

        // Classify based on thresholds.
        let new_class = if abs_skew > self.severe_skew_threshold_ns {
            DriftClass::SevereCluster
        } else if abs_skew > self.elevated_skew_threshold_ns
            || max_jitter > self.jitter_threshold_ns
        {
            DriftClass::ElevatedCluster
        } else {
            DriftClass::NominalCluster
        };
        self.update_state(new_class);
        self.current_class
    }

    /// Explicitly set the drift class (e.g. from external detection).
    pub fn set_class(&mut self, class: DriftClass) {
        self.current_class = class;
        self.update_suspicion_from_class(class);
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn update_state(&mut self, new_class: DriftClass) {
        match new_class {
            DriftClass::TrustedLocal | DriftClass::NominalCluster => {
                self.current_class = new_class;
                self.suspicion_state = DriftSuspicionState::Nominal;
            }
            DriftClass::ElevatedCluster => {
                self.current_class = new_class;
                self.suspicion_state = DriftSuspicionState::Elevated;
            }
            DriftClass::SevereCluster => {
                self.current_class = new_class;
                self.suspicion_state = DriftSuspicionState::Severe;
            }
            DriftClass::UntrustedTime => {
                self.current_class = new_class;
                self.suspicion_state = DriftSuspicionState::HoldSensitiveActions;
            }
        }
    }

    fn update_suspicion_from_class(&mut self, class: DriftClass) {
        self.suspicion_state = match class {
            DriftClass::TrustedLocal | DriftClass::NominalCluster => DriftSuspicionState::Nominal,
            DriftClass::ElevatedCluster => DriftSuspicionState::Elevated,
            DriftClass::SevereCluster => DriftSuspicionState::Severe,
            DriftClass::UntrustedTime => DriftSuspicionState::HoldSensitiveActions,
        };
    }
}

impl Default for DriftEstimator {
    fn default() -> Self {
        DriftEstimator::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drift_sample(skew_ns: i128, jitter_ns: u64) -> DriftSample {
        DriftSample {
            skew_ns,
            jitter_ns,
            clock_class: ClockClass::HlcCluster,
            observed_at_ns: 1000,
        }
    }

    #[test]
    fn initial_state_trusted() {
        let est = DriftEstimator::new();
        assert_eq!(est.drift_class(), DriftClass::TrustedLocal);
        assert_eq!(est.suspicion_state(), DriftSuspicionState::Nominal);
    }

    #[test]
    fn nominal_drift_stays_trusted() {
        let mut est = DriftEstimator::new();
        assert_eq!(
            est.observe(drift_sample(500, 100)),
            DriftClass::NominalCluster
        );
        // After recovery window, should go to NominalCluster
        for _ in 0..16 {
            est.observe(drift_sample(500, 100));
        }
        assert_eq!(est.drift_class(), DriftClass::NominalCluster);
    }

    #[test]
    fn elevated_skew_detected() {
        let mut est = DriftEstimator::with_thresholds(1_000, 10_000, 500_000, 8, 4);
        assert_eq!(
            est.observe(drift_sample(5_000, 100)),
            DriftClass::ElevatedCluster
        );
        assert_eq!(est.suspicion_state(), DriftSuspicionState::Elevated);
    }

    #[test]
    fn severe_skew_detected() {
        let mut est = DriftEstimator::with_thresholds(1_000, 10_000, 500_000, 8, 4);
        assert_eq!(
            est.observe(drift_sample(50_000, 100)),
            DriftClass::SevereCluster
        );
        assert_eq!(est.suspicion_state(), DriftSuspicionState::Severe);
    }

    #[test]
    fn elevated_jitter_detected() {
        let mut est = DriftEstimator::with_thresholds(1_000, 10_000, 500, 8, 4);
        // skew is small but jitter is high
        assert_eq!(
            est.observe(drift_sample(100, 10_000)),
            DriftClass::ElevatedCluster
        );
    }

    #[test]
    fn recovery_after_elevated() {
        let mut est = DriftEstimator::with_thresholds(1_000, 10_000, 500_000, 8, 4);

        // Induce elevated
        est.observe(drift_sample(5_000, 100));
        assert_eq!(est.drift_class(), DriftClass::ElevatedCluster);

        // Feed nominal samples to recover
        for _ in 0..3 {
            est.observe(drift_sample(100, 50));
        }
        assert_eq!(est.drift_class(), DriftClass::ElevatedCluster); // still elevated

        // 4th nominal sample triggers recovery
        assert_eq!(
            est.observe(drift_sample(100, 50)),
            DriftClass::NominalCluster
        );
        assert_eq!(est.suspicion_state(), DriftSuspicionState::Recovered);
    }

    #[test]
    fn sliding_window_limits_samples() {
        let mut est = DriftEstimator::with_thresholds(1_000, 10_000, 500_000, 4, 4);
        for i in 0..10 {
            est.observe(drift_sample(i as i128 * 100, 50));
        }
        assert_eq!(est.samples().len(), 4);
    }

    #[test]
    fn set_class_override() {
        let mut est = DriftEstimator::new();
        assert_eq!(est.drift_class(), DriftClass::TrustedLocal);

        est.set_class(DriftClass::UntrustedTime);
        assert_eq!(est.drift_class(), DriftClass::UntrustedTime);
        assert_eq!(
            est.suspicion_state(),
            DriftSuspicionState::HoldSensitiveActions
        );
    }

    #[test]
    fn estimates_tracked() {
        let mut est = DriftEstimator::with_thresholds(1_000, 10_000, 500_000, 8, 4);
        est.observe(drift_sample(3000, 100));
        est.observe(drift_sample(5000, 200));

        // avg skew = (3000 + 5000) / 2 = 4000
        assert_eq!(est.estimated_skew_ns(), 4000);
        // max jitter = 200
        assert_eq!(est.estimated_jitter_ns(), 200);
    }

    #[test]
    fn recovery_counter_increments_by_one() {
        // With recovery_samples=2, recovery should fire after exactly
        // 2 consecutive nominal samples, verifying that each sample
        // increments the counter by 1 (not 2 as the pre-fix duplicate
        // code path caused).
        let mut est = DriftEstimator::with_thresholds(1_000, 10_000, 500_000, 16, 2);

        // Push into elevated state with a bad sample
        est.observe(drift_sample(5_000, 100));
        assert_eq!(est.drift_class(), DriftClass::ElevatedCluster);

        // 1st nominal: aggregate (5000+100)/2=2550 > 1000, so classification
        // is still ElevatedCluster. recovery_counter = 1 (< 2).
        let c1 = est.observe(drift_sample(100, 50));
        assert_eq!(
            c1,
            DriftClass::ElevatedCluster,
            "1 nominal sample should not trigger recovery with recovery_samples=2"
        );
        assert_ne!(est.suspicion_state(), DriftSuspicionState::Recovered);

        // 2nd nominal: aggregate (5000+200)/3=1733 > 1000, classification
        // still ElevatedCluster. recovery_counter = 2 (>= 2), triggers.
        let c2 = est.observe(drift_sample(100, 50));
        assert_eq!(
            c2,
            DriftClass::NominalCluster,
            "2nd nominal sample should trigger recovery"
        );
        assert_eq!(est.suspicion_state(), DriftSuspicionState::Recovered);
    }

    #[test]
    fn non_nominal_resets_recovery_counter() {
        // Verify that a non-nominal sample resets the recovery counter.
        let mut est = DriftEstimator::with_thresholds(1_000, 10_000, 500_000, 16, 5);

        est.observe(drift_sample(5_000, 100)); // elevated
        assert_eq!(est.drift_class(), DriftClass::ElevatedCluster);

        // Feed 2 nominal samples → counter = 2
        est.observe(drift_sample(100, 50));
        est.observe(drift_sample(100, 50));
        // Still elevated (counter = 2, < 5)
        assert_eq!(est.drift_class(), DriftClass::ElevatedCluster);

        // Feed a non-nominal → counter resets to 0
        est.observe(drift_sample(5_000, 100));
        assert_eq!(est.drift_class(), DriftClass::ElevatedCluster);

        // Now need 5 more nominal samples (not 3) to recover
        for _ in 0..4 {
            assert_eq!(
                est.observe(drift_sample(100, 50)),
                DriftClass::ElevatedCluster
            );
        }
        // 5th consecutive nominal triggers recovery
        assert_eq!(
            est.observe(drift_sample(100, 50)),
            DriftClass::NominalCluster
        );
        assert_eq!(est.suspicion_state(), DriftSuspicionState::Recovered);
    }

    #[test]
    fn default_equals_new() {
        let d1 = DriftEstimator::new();
        let d2 = DriftEstimator::default();
        assert_eq!(d1.drift_class(), d2.drift_class());
        assert_eq!(d1.suspicion_state(), d2.suspicion_state());
    }
}
