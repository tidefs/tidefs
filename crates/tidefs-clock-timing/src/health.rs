// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Clock source health monitoring for source-owned timing runtime components
//! (`clock_sampler`, `time_health_monitor`).
//!
//! The health monitor samples local clock sources and classifies their health
//! state. It detects step regressions, suspend anomalies, and jitter so that
//! dependent subsystems can widen deadlines or hold sensitive actions.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::types::{ClockClass, ClockSourceSample, FindingSeverity, TimeHealth, TimeHealthFinding};

/// Monotonic finding ID counter.
static FINDING_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn next_finding_id() -> u64 {
    FINDING_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// ClockSampler
// ---------------------------------------------------------------------------

/// Samples local clock sources and provides raw readings.
///
/// In production, this would use `clock_gettime` via libc for each clock class.
/// The sampler holds the last reading for anomaly detection.
#[derive(Debug, Clone)]
pub struct ClockSampler {
    last_sample: Option<ClockSourceSample>,
    sample_count: u64,
}

impl ClockSampler {
    /// Create a new clock sampler.
    pub fn new() -> Self {
        ClockSampler {
            last_sample: None,
            sample_count: 0,
        }
    }

    /// Take a sample of all clock sources.
    ///
    /// In production this calls `clock_gettime(CLOCK_MONOTONIC_RAW)`, etc.
    /// The testable variant accepts explicit values.
    pub fn sample(
        &mut self,
        mono_raw_ns: u64,
        mono_service_ns: u64,
        boottime_ns: u64,
        realtime_ns: u64,
    ) -> ClockSourceSample {
        let sample = ClockSourceSample {
            mono_raw_ns,
            mono_service_ns,
            boottime_ns,
            realtime_ns,
        };
        self.last_sample = Some(sample.clone());
        self.sample_count = self.sample_count.saturating_add(1);
        sample
    }

    /// Return the most recent sample, if any.
    pub fn last_sample(&self) -> Option<&ClockSourceSample> {
        self.last_sample.as_ref()
    }

    /// Return total number of samples taken.
    pub fn sample_count(&self) -> u64 {
        self.sample_count
    }
}

impl Default for ClockSampler {
    fn default() -> Self {
        ClockSampler::new()
    }
}

// ---------------------------------------------------------------------------
// TimeHealthMonitor
// ---------------------------------------------------------------------------

/// Monitors clock source health and classifies the current `TimeHealth` state.
///
/// Detects:
/// - Step regressions (backward jumps or excessive forward leaps)
/// - Suspend/resume anomalies (large gaps in monotonic time)
/// - Jitter above configured thresholds
#[derive(Debug, Clone)]
pub struct TimeHealthMonitor {
    current_health: TimeHealth,
    previous_sample: Option<ClockSourceSample>,
    /// Maximum acceptable forward jump in monotonic time (nanoseconds).
    max_forward_jump_ns: u64,
    /// Maximum acceptable backward jump in monotonic time (nanoseconds).
    #[allow(dead_code)]
    max_backward_jump_ns: u64,
    /// Jitter threshold (nanoseconds) before classifying as jittered.
    jitter_threshold_ns: u64,
    /// Consecutive healthy samples before recovery from degraded state.
    recovery_samples_needed: u32,
    recovery_counter: u32,
    findings: Vec<TimeHealthFinding>,
}

impl TimeHealthMonitor {
    /// Create a new monitor with default thresholds.
    ///
    /// Default thresholds are conservative for a 7.0 Linux host:
    /// - 100ms max forward jump before suspicion
    /// - Any backward jump triggers step regression
    /// - 1ms jitter threshold
    /// - 10 consecutive healthy samples needed for recovery
    pub fn new() -> Self {
        TimeHealthMonitor {
            current_health: TimeHealth::Healthy,
            previous_sample: None,
            max_forward_jump_ns: 100_000_000, // 100ms
            max_backward_jump_ns: 0,          // any backward = regression
            jitter_threshold_ns: 1_000_000,   // 1ms
            recovery_samples_needed: 10,
            recovery_counter: 0,
            findings: Vec::new(),
        }
    }

    /// Create a monitor with custom thresholds.
    pub fn with_thresholds(
        max_forward_jump_ns: u64,
        #[allow(dead_code)] max_backward_jump_ns: u64,
        jitter_threshold_ns: u64,
        recovery_samples_needed: u32,
    ) -> Self {
        TimeHealthMonitor {
            current_health: TimeHealth::Healthy,
            previous_sample: None,
            max_forward_jump_ns,
            max_backward_jump_ns,
            jitter_threshold_ns,
            recovery_samples_needed,
            recovery_counter: 0,
            findings: Vec::new(),
        }
    }

    /// Return the current health classification.
    pub fn health(&self) -> TimeHealth {
        self.current_health
    }

    /// Return all recorded findings.
    pub fn findings(&self) -> &[TimeHealthFinding] {
        &self.findings
    }

    /// Classify a new clock sample and update health state.
    ///
    /// Returns the new health classification (may be unchanged).
    pub fn classify(&mut self, sample: &ClockSourceSample) -> TimeHealth {
        let prev_sample = self.previous_sample.clone();
        let prev = match &prev_sample {
            Some(p) => p,
            None => {
                // First sample: assume healthy.
                self.previous_sample = Some(sample.clone());
                self.recovery_counter = 0;
                return self.current_health;
            }
        };

        let mono_delta = sample.mono_raw_ns as i128 - prev.mono_raw_ns as i128;

        if mono_delta < 0 {
            // Backward jump in monotonic clock: step regression.
            self.transition_to(TimeHealth::StepRegressed);
            self.emit_finding(
                ClockClass::MonoRawLocal,
                FindingSeverity::Critical,
                format!(
                    "monotonic_raw stepped backward: {}ns → {}ns (delta={}ns)",
                    prev.mono_raw_ns, sample.mono_raw_ns, mono_delta
                ),
            );
        } else if mono_delta > self.max_forward_jump_ns as i128 {
            // Excessive forward jump: possible suspend/resume.
            self.transition_to(TimeHealth::SuspendOrPauseSuspect);
            self.emit_finding(
                ClockClass::MonoRawLocal,
                FindingSeverity::Warning,
                format!(
                    "monotonic_raw forward jump {}ns exceeds threshold {}ns (suspend suspected)",
                    mono_delta, self.max_forward_jump_ns
                ),
            );
        } else {
            // Check boottime vs monotonic_raw correlation for suspend.
            let boot_delta = sample.boottime_ns as i128 - prev.boottime_ns as i128;
            let mono_raw_delta = sample.mono_raw_ns as i128 - prev.mono_raw_ns as i128;
            let delta_diff = (boot_delta - mono_raw_delta).abs();

            if delta_diff > self.jitter_threshold_ns as i128 * 100 {
                // Large discrepancy between boottime and monotonic_raw:
                // boottime advanced but monotonic_raw didn't — suspend confirmed.
                self.transition_to(TimeHealth::SuspendOrPauseSuspect);
                self.emit_finding(
                    ClockClass::BoottimeLocal,
                    FindingSeverity::Warning,
                    format!(
                        "boottime/monotonic_raw divergence: boot_delta={boot_delta}ns, mono_raw_delta={mono_raw_delta}ns, diff={delta_diff}ns (suspend confirmed)"
                    ),
                );
            } else if mono_delta.abs() > self.jitter_threshold_ns as i128 {
                // Jitter above threshold.
                self.transition_to(TimeHealth::Jittered);
                self.emit_finding(
                    ClockClass::MonoRawLocal,
                    FindingSeverity::Warning,
                    format!(
                        "jitter {}ns exceeds threshold {}ns",
                        mono_delta.abs(),
                        self.jitter_threshold_ns
                    ),
                );
            } else {
                // Healthy delta: attempt recovery.
                self.attempt_recovery();
            }
        }

        self.previous_sample = Some(sample.clone());
        self.current_health
    }

    /// Override the health state directly (e.g. from external validation).
    pub fn set_health(&mut self, health: TimeHealth) {
        self.current_health = health;
        self.recovery_counter = 0;
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn transition_to(&mut self, new_health: TimeHealth) {
        self.current_health = new_health;
        self.recovery_counter = 0;
    }

    fn attempt_recovery(&mut self) {
        if self.current_health == TimeHealth::Healthy {
            return;
        }
        self.recovery_counter = self.recovery_counter.saturating_add(1);
        if self.recovery_counter >= self.recovery_samples_needed {
            self.current_health = TimeHealth::Healthy;
            self.recovery_counter = 0;
            self.emit_finding(
                ClockClass::MonoRawLocal,
                FindingSeverity::Info,
                format!(
                    "time health recovered to healthy after {} consecutive clean samples",
                    self.recovery_samples_needed
                ),
            );
        }
    }

    fn emit_finding(
        &mut self,
        clock_class: ClockClass,
        severity: FindingSeverity,
        description: String,
    ) {
        let finding = TimeHealthFinding {
            finding_id: next_finding_id(),
            clock_class,
            severity,
            description,
            hlc_at_finding: crate::types::HlcValue::zero(), // caller sets real HLC
        };
        self.findings.push(finding);
    }
}

impl Default for TimeHealthMonitor {
    fn default() -> Self {
        TimeHealthMonitor::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(mono_raw: u64) -> ClockSourceSample {
        ClockSourceSample {
            mono_raw_ns: mono_raw,
            mono_service_ns: mono_raw,
            boottime_ns: mono_raw,
            realtime_ns: mono_raw,
        }
    }

    #[test]
    fn first_sample_healthy() {
        let mut monitor = TimeHealthMonitor::new();
        let s = sample(1000);
        assert_eq!(monitor.classify(&s), TimeHealth::Healthy);
        assert_eq!(monitor.health(), TimeHealth::Healthy);
    }

    #[test]
    fn normal_progression_stays_healthy() {
        let mut monitor = TimeHealthMonitor::new();
        monitor.classify(&sample(1000));
        assert_eq!(monitor.classify(&sample(1001)), TimeHealth::Healthy);
        assert_eq!(monitor.classify(&sample(1002)), TimeHealth::Healthy);
    }

    #[test]
    fn backward_jump_detected() {
        let mut monitor = TimeHealthMonitor::new();
        monitor.classify(&sample(1000));
        assert_eq!(monitor.classify(&sample(900)), TimeHealth::StepRegressed);
    }

    #[test]
    fn forward_jump_detected() {
        let mut monitor = TimeHealthMonitor::with_thresholds(1000, 0, 500, 5);
        monitor.classify(&sample(1000));
        assert_eq!(
            monitor.classify(&sample(3000)),
            TimeHealth::SuspendOrPauseSuspect
        );
    }

    #[test]
    fn jitter_detected() {
        let mut monitor = TimeHealthMonitor::with_thresholds(1_000_000, 0, 500, 5);
        monitor.classify(&sample(1000));
        // Delta = 600 > jitter threshold 500
        assert_eq!(monitor.classify(&sample(1600)), TimeHealth::Jittered);
    }

    #[test]
    fn recovery_after_clean_samples() {
        let mut monitor = TimeHealthMonitor::with_thresholds(1_000_000, 0, 500, 3);
        monitor.classify(&sample(1000));

        // Induce jitter
        assert_eq!(monitor.classify(&sample(1600)), TimeHealth::Jittered);

        // Recovery: 3 clean samples needed
        assert_eq!(monitor.classify(&sample(1601)), TimeHealth::Jittered);
        assert_eq!(monitor.classify(&sample(1602)), TimeHealth::Jittered);
        assert_eq!(monitor.classify(&sample(1603)), TimeHealth::Healthy);
    }

    #[test]
    fn suspend_detection_via_boottime_divergence() {
        let mut monitor = TimeHealthMonitor::new();
        monitor.classify(&ClockSourceSample {
            mono_raw_ns: 1000,
            mono_service_ns: 1000,
            boottime_ns: 1000,
            realtime_ns: 1000,
        });
        // boottime jumped 500ms, monotonic_raw only 1ms — suspend!
        assert_eq!(
            monitor.classify(&ClockSourceSample {
                mono_raw_ns: 1001,
                mono_service_ns: 1001,
                boottime_ns: 501_000_000,
                realtime_ns: 501_000_000,
            }),
            TimeHealth::SuspendOrPauseSuspect
        );
    }

    #[test]
    fn findings_recorded() {
        let mut monitor = TimeHealthMonitor::with_thresholds(1000, 0, 500, 5);
        monitor.classify(&sample(1000));
        monitor.classify(&sample(900)); // backward jump

        let findings = monitor.findings();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, FindingSeverity::Critical);
        assert!(findings[0].description.contains("backward"));
    }

    #[test]
    fn set_health_override() {
        let mut monitor = TimeHealthMonitor::new();
        monitor.classify(&sample(1000));
        assert_eq!(monitor.health(), TimeHealth::Healthy);

        monitor.set_health(TimeHealth::Untrusted);
        assert_eq!(monitor.health(), TimeHealth::Untrusted);
    }

    #[test]
    fn clock_sampler_tracks_samples() {
        let mut sampler = ClockSampler::new();
        assert!(sampler.last_sample().is_none());
        assert_eq!(sampler.sample_count(), 0);

        let s = sampler.sample(100, 101, 102, 103);
        assert_eq!(s.mono_raw_ns, 100);
        assert_eq!(sampler.sample_count(), 1);
        assert!(sampler.last_sample().is_some());
    }

    #[test]
    fn clock_sampler_default_equals_new() {
        let s1 = ClockSampler::new();
        let s2 = ClockSampler::default();
        assert_eq!(s1.sample_count(), s2.sample_count());
        assert!(s1.last_sample().is_none());
        assert!(s2.last_sample().is_none());
    }
}
