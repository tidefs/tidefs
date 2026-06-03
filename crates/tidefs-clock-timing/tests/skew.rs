//! Clock-skew estimation tests for DriftEstimator. Covers known-offset skew,
//! negative skew, large skew values without panic, jitter detection, and
//! drift-class escalation/de-escalation.

use tidefs_clock_timing::{
    ClockClass, DriftClass, DriftEstimator, DriftSample, DriftSuspicionState,
};

// ---------------------------------------------------------------------------
// known-offset tests
// ---------------------------------------------------------------------------

#[test]
fn zero_skew_stays_trusted() {
    let mut de = DriftEstimator::new();
    for i in 0..32 {
        de.observe(DriftSample {
            skew_ns: 0,
            jitter_ns: 0,
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: i * 1000,
        });
    }
    assert_eq!(de.drift_class(), DriftClass::NominalCluster);
    // suspicion_state may be Recovered if recovery triggered
    assert!(
        de.suspicion_state() == DriftSuspicionState::Nominal
            || de.suspicion_state() == DriftSuspicionState::Recovered
    );
}

#[test]
fn small_positive_skew_stays_trusted() {
    let mut de = DriftEstimator::new();
    for i in 0..32 {
        de.observe(DriftSample {
            skew_ns: 500,
            jitter_ns: 0,
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: i * 1000,
        });
    }
    assert_eq!(de.drift_class(), DriftClass::NominalCluster);
}

#[test]
fn negative_skew_within_bounds_stays_trusted() {
    let mut de = DriftEstimator::new();
    for i in 0..32 {
        de.observe(DriftSample {
            skew_ns: -500,
            jitter_ns: 0,
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: i * 1000,
        });
    }
    assert_eq!(de.drift_class(), DriftClass::NominalCluster);
}

#[test]
fn large_positive_skew_triggers_elevated() {
    let mut de = DriftEstimator::new();
    for _ in 0..32 {
        de.observe(DriftSample {
            skew_ns: 2_000_000, // 2ms > 1ms elevated threshold
            jitter_ns: 0,
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: 0,
        });
    }
    assert_eq!(de.drift_class(), DriftClass::ElevatedCluster);
}

#[test]
fn severe_skew_triggers_severe_class() {
    let mut de = DriftEstimator::new();
    for _ in 0..32 {
        de.observe(DriftSample {
            skew_ns: 20_000_000, // 20ms > 10ms severe threshold
            jitter_ns: 0,
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: 0,
        });
    }
    assert_eq!(de.drift_class(), DriftClass::SevereCluster);
}

#[test]
fn moderate_negative_skew_stays_trusted() {
    let mut de = DriftEstimator::new();
    for _ in 0..32 {
        de.observe(DriftSample {
            skew_ns: -500_000, // -0.5ms, abs < 1ms
            jitter_ns: 0,
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: 0,
        });
    }
    assert_eq!(de.drift_class(), DriftClass::NominalCluster);
}

// ---------------------------------------------------------------------------
// large skew values — no panic
// ---------------------------------------------------------------------------

#[test]
fn i128_max_skew_does_not_panic() {
    let mut de = DriftEstimator::new();
    de.observe(DriftSample {
        skew_ns: i128::MAX,
        jitter_ns: 0,
        clock_class: ClockClass::MonoRawLocal,
        observed_at_ns: 0,
    });
    assert_eq!(de.drift_class(), DriftClass::SevereCluster);
}

#[test]
fn i128_min_skew_does_not_panic() {
    let mut de = DriftEstimator::new();
    de.observe(DriftSample {
        skew_ns: i128::MIN,
        jitter_ns: 0,
        clock_class: ClockClass::MonoRawLocal,
        observed_at_ns: 0,
    });
    assert_eq!(de.drift_class(), DriftClass::SevereCluster);
}

#[test]
fn u64_max_jitter_does_not_panic() {
    let mut de = DriftEstimator::new();
    de.observe(DriftSample {
        skew_ns: 0,
        jitter_ns: u64::MAX,
        clock_class: ClockClass::MonoRawLocal,
        observed_at_ns: 0,
    });
    let cls = de.drift_class();
    assert!(cls as u8 >= DriftClass::ElevatedCluster as u8);
}

// ---------------------------------------------------------------------------
// jitter-triggered escalation
// ---------------------------------------------------------------------------

#[test]
fn high_jitter_triggers_elevated() {
    let mut de = DriftEstimator::new();
    for _ in 0..32 {
        de.observe(DriftSample {
            skew_ns: 0,
            jitter_ns: 1_000_000, // 1ms > 500us default threshold
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: 0,
        });
    }
    assert_eq!(de.drift_class(), DriftClass::ElevatedCluster);
}

#[test]
fn low_jitter_stays_trusted() {
    let mut de = DriftEstimator::new();
    for _ in 0..32 {
        de.observe(DriftSample {
            skew_ns: 0,
            jitter_ns: 100_000, // 100us < 500us default threshold
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: 0,
        });
    }
    assert_eq!(de.drift_class(), DriftClass::NominalCluster);
}

// ---------------------------------------------------------------------------
// suspicion states
// ---------------------------------------------------------------------------

#[test]
fn nominal_suspicion_under_trusted() {
    let de = DriftEstimator::new();
    assert_eq!(de.suspicion_state(), DriftSuspicionState::Nominal);
}

#[test]
fn elevated_skew_produces_suspicion() {
    let mut de = DriftEstimator::new();
    for _ in 0..32 {
        de.observe(DriftSample {
            skew_ns: 2_000_000,
            jitter_ns: 0,
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: 0,
        });
    }
    assert_ne!(de.suspicion_state(), DriftSuspicionState::Nominal);
}

// ---------------------------------------------------------------------------
// recovery
// ---------------------------------------------------------------------------

#[test]
fn recovery_after_clean_samples() {
    // Use a small window (4) so elevated samples are flushed quickly.
    // Recovery needs 3 consecutive nominal samples.
    let mut de = DriftEstimator::with_thresholds(1_000_000, 10_000_000, 500_000, 4, 3);
    for _ in 0..4 {
        de.observe(DriftSample {
            skew_ns: 2_000_000,
            jitter_ns: 0,
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: 0,
        });
    }
    assert_eq!(de.drift_class(), DriftClass::ElevatedCluster);

    // Feed 4 nominal samples: 3 trigger recovery, 4th flushes last elevated
    for _ in 0..4 {
        de.observe(DriftSample {
            skew_ns: 0,
            jitter_ns: 0,
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: 0,
        });
    }
    assert_eq!(de.drift_class(), DriftClass::NominalCluster);
}

// ---------------------------------------------------------------------------
// set_class override
// ---------------------------------------------------------------------------

#[test]
fn set_class_override_to_untrusted() {
    let mut de = DriftEstimator::new();
    de.set_class(DriftClass::UntrustedTime);
    assert_eq!(de.drift_class(), DriftClass::UntrustedTime);
}

#[test]
fn set_class_override_after_escalation() {
    let mut de = DriftEstimator::new();
    for _ in 0..32 {
        de.observe(DriftSample {
            skew_ns: 5_000_000,
            jitter_ns: 0,
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: 0,
        });
    }
    assert_eq!(de.drift_class(), DriftClass::ElevatedCluster);
    de.set_class(DriftClass::NominalCluster);
    assert_eq!(de.drift_class(), DriftClass::NominalCluster);
}

// ---------------------------------------------------------------------------
// sliding window
// ---------------------------------------------------------------------------

#[test]
fn sliding_window_respects_window_size() {
    let mut de = DriftEstimator::with_thresholds(1_000_000, 10_000_000, 500_000, 4, 8);
    for i in 0..20 {
        de.observe(DriftSample {
            skew_ns: i as i128 * 1000,
            jitter_ns: 0,
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: i * 1000,
        });
    }
    assert!(
        de.samples().len() <= 4,
        "window size 4 capped at {}",
        de.samples().len()
    );
}

// ---------------------------------------------------------------------------
// estimated values accessibility
// ---------------------------------------------------------------------------

#[test]
fn estimated_values_accessible() {
    let mut de = DriftEstimator::new();
    de.observe(DriftSample {
        skew_ns: 500_000,
        jitter_ns: 100_000,
        clock_class: ClockClass::MonoRawLocal,
        observed_at_ns: 0,
    });
    let _s = de.estimated_skew_ns();
    let _j = de.estimated_jitter_ns();
}
