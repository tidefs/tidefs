// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Combined-scenario integration tests: simulate a lease-acquire -> timeout ->
//! expire sequence using in-process time values. Verifies that clock sampling,
//! health monitoring, lease deadlines, drift estimation, and timeout escalation
//! compose without panics and produce correct state transitions.

use tidefs_clock_timing::{
    ClockClass, ClockSampler, DriftClass, DriftEstimator, DriftSample, EscalationAction, HlcValue,
    LeaseDeadline, LeaseDeadlineState, TimeHealth, TimeHealthMonitor, TimeoutEscalator,
};

#[test]
fn lease_acquire_timeout_expire_failover() {
    let mut sampler = ClockSampler::new();
    let s0 = sampler.sample(0, 0, 0, 0);

    let mut health = TimeHealthMonitor::new();
    assert_eq!(health.classify(&s0), TimeHealth::Healthy);

    let mut lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
    assert_eq!(lease.record().state, LeaseDeadlineState::Open);

    let s1 = sampler.sample(1200, 1200, 1200, 1200);
    assert_eq!(health.classify(&s1), TimeHealth::Healthy);
    assert_eq!(lease.evaluate(1200), LeaseDeadlineState::Open);

    let s2 = sampler.sample(1600, 1600, 1600, 1600);
    assert_eq!(health.classify(&s2), TimeHealth::Healthy);
    assert_eq!(lease.evaluate(1600), LeaseDeadlineState::Warning);

    lease.renew(2000, 500, 2000, 1000);
    assert_eq!(lease.record().state, LeaseDeadlineState::Open);
    assert_eq!(lease.record().opened_at_ns, 2000);

    assert_eq!(lease.evaluate(3000), LeaseDeadlineState::Warning);
    assert_eq!(lease.evaluate(4500), LeaseDeadlineState::Grace);
    assert_eq!(lease.evaluate(5500), LeaseDeadlineState::Expired);

    assert!(lease.stage_failover().is_some());
    assert_eq!(lease.record().state, LeaseDeadlineState::FailoverStaged);
}

#[test]
fn drift_estimator_feeds_lease_slack() {
    let mut de = DriftEstimator::new();
    for _ in 0..32 {
        de.observe(DriftSample {
            skew_ns: 5_000_000,
            jitter_ns: 0,
            clock_class: ClockClass::MonoRawLocal,
            observed_at_ns: 0,
        });
    }
    let drift_class = de.drift_class();
    let lease = LeaseDeadline::open(1, 0, 500, 2000, 1000, drift_class);
    let r = lease.record();
    assert!(
        r.expiry_deadline_ns > 2000,
        "drift-slacked expiry ({}) should exceed base 2000",
        r.expiry_deadline_ns
    );
}

#[test]
fn escalator_classifies_lease_expiry() {
    let lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
    let dd = lease.renew_deadline();
    let mut escalator = TimeoutEscalator::new(DriftClass::TrustedLocal);
    let hlc = HlcValue::zero();
    let action = escalator.classify_miss(&dd, 2000, hlc, "Open", "Warning");
    assert!(escalator.receipt_count() > 0);
    assert_ne!(action, EscalationAction::None);
}

#[test]
fn escalator_under_severe_drift_is_stricter() {
    let lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::SevereCluster);
    let dd = lease.renew_deadline();
    let mut escalator = TimeoutEscalator::new(DriftClass::SevereCluster);
    let hlc = HlcValue::zero();
    let action = escalator.classify_miss(&dd, 2000, hlc, "Open", "Warning");
    assert_ne!(action, EscalationAction::None);
    assert!(matches!(
        action,
        EscalationAction::Degrade | EscalationAction::Hold | EscalationAction::Stop
    ));
}

#[test]
fn full_lifecycle_health_and_lease_compose() {
    // Use explicit DriftClass::TrustedLocal to avoid estimator state ambiguity.
    let mut sampler = ClockSampler::new();
    let mut health = TimeHealthMonitor::new();

    let s0 = sampler.sample(0, 0, 0, 0);
    assert_eq!(health.classify(&s0), TimeHealth::Healthy);

    // renew=1000, expiry=3000, grace=1000
    // deadlines: renew=1000, expiry=3000, grace=4000
    let mut lease = LeaseDeadline::open(1, 0, 1000, 3000, 1000, DriftClass::TrustedLocal);

    // T=500: before renew -> Open
    let s1 = sampler.sample(500, 500, 500, 500);
    assert_eq!(health.classify(&s1), TimeHealth::Healthy);
    assert_eq!(lease.evaluate(500), LeaseDeadlineState::Open);

    // T=2000: past renew, before expiry -> Warning
    let s2 = sampler.sample(2000, 2000, 2000, 2000);
    assert_eq!(health.classify(&s2), TimeHealth::Healthy);
    assert_eq!(lease.evaluate(2000), LeaseDeadlineState::Warning);

    // T=3500: past expiry, before grace -> Grace
    let s3 = sampler.sample(3500, 3500, 3500, 3500);
    assert_eq!(health.classify(&s3), TimeHealth::Healthy);
    assert_eq!(lease.evaluate(3500), LeaseDeadlineState::Grace);

    // T=5000: past grace -> Expired
    assert_eq!(lease.evaluate(5000), LeaseDeadlineState::Expired);

    // Failover
    assert!(lease.stage_failover().is_some());
    assert_eq!(health.health(), TimeHealth::Healthy);
}

#[test]
fn clock_regression_detected_during_lease_lifecycle() {
    let mut sampler = ClockSampler::new();
    let mut health = TimeHealthMonitor::new();
    let mut lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);

    let s1 = sampler.sample(1000, 1000, 1000, 1000);
    assert_eq!(health.classify(&s1), TimeHealth::Healthy);
    lease.evaluate(1000);

    let s2 = sampler.sample(500, 500, 500, 500);
    assert_eq!(health.classify(&s2), TimeHealth::StepRegressed);

    let state = lease.evaluate(500);
    assert_eq!(
        state,
        LeaseDeadlineState::Open,
        "lease should not regress state on backward clock"
    );
}
