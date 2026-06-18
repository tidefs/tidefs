// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Boundary and edge-case tests for lease-timeout arithmetic using
//! LeaseDeadline. Covers zero-duration, 1 ns, large-duration (u64::MAX),
//! saturating arithmetic, drift-slack scaling, and timeout comparison helpers.

use tidefs_clock_timing::{ClockClass, DriftClass, LeaseDeadline, LeaseDeadlineState};

// ---------------------------------------------------------------------------
// zero-duration boundaries
// ---------------------------------------------------------------------------

#[test]
fn open_with_zero_periods_all_deadlines_equal_opened_at() {
    let lease = LeaseDeadline::open(1, 1000, 0, 0, 0, DriftClass::TrustedLocal);
    let r = lease.record();
    assert_eq!(r.renew_deadline_ns, 1000);
    assert_eq!(r.expiry_deadline_ns, 1000);
    assert_eq!(r.grace_deadline_ns, 1000);
    assert_eq!(r.state, LeaseDeadlineState::Open);
}

#[test]
fn zero_duration_triggers_immediate_expiry() {
    let mut lease = LeaseDeadline::open(1, 1000, 0, 0, 0, DriftClass::TrustedLocal);
    let state = lease.evaluate(1000);
    assert_eq!(state, LeaseDeadlineState::Expired);
}

// ---------------------------------------------------------------------------
// minimal durations
// ---------------------------------------------------------------------------

#[test]
fn one_ns_renew_one_ns_expiry() {
    let mut lease = LeaseDeadline::open(1, 1000, 1, 1, 0, DriftClass::TrustedLocal);
    let r = lease.record();
    assert_eq!(r.renew_deadline_ns, 1001);
    assert_eq!(r.expiry_deadline_ns, 1001);

    assert_eq!(lease.evaluate(1000), LeaseDeadlineState::Open);
    assert_eq!(lease.evaluate(1001), LeaseDeadlineState::Expired);
    assert_eq!(lease.evaluate(1002), LeaseDeadlineState::Expired);
}

#[test]
fn one_us_renew_ten_ms_expiry() {
    let mut lease =
        LeaseDeadline::open(1, 0, 1_000, 10_000_000, 1_000_000, DriftClass::TrustedLocal);
    let r = lease.record();
    assert!(r.renew_deadline_ns > 0);
    assert!(r.expiry_deadline_ns > r.renew_deadline_ns);
    let _ = lease.evaluate(r.expiry_deadline_ns);
}

#[test]
fn one_second_expiry() {
    let mut lease = LeaseDeadline::open(
        1,
        0,
        500_000_000,
        1_000_000_000,
        0,
        DriftClass::TrustedLocal,
    );
    let r = lease.record();
    assert_eq!(r.expiry_deadline_ns, 1_000_000_000);
    assert_eq!(lease.evaluate(999_000_000), LeaseDeadlineState::Warning);
    assert_eq!(lease.evaluate(1_000_000_000), LeaseDeadlineState::Expired);
}

#[test]
fn one_hour_expiry() {
    let hour_ns: u64 = 3_600_000_000_000;
    let lease = LeaseDeadline::open(
        1,
        0,
        hour_ns / 2,
        hour_ns,
        hour_ns / 4,
        DriftClass::TrustedLocal,
    );
    let r = lease.record();
    assert_eq!(r.expiry_deadline_ns, hour_ns);
    assert_eq!(r.grace_deadline_ns, hour_ns + hour_ns / 4);
}

// ---------------------------------------------------------------------------
// u64::MAX and saturating arithmetic
// ---------------------------------------------------------------------------

#[test]
fn open_at_u64_max_with_nonzero_periods_saturates() {
    let lease = LeaseDeadline::open(1, u64::MAX, 1000, 5000, 1000, DriftClass::TrustedLocal);
    let r = lease.record();
    assert_eq!(r.opened_at_ns, u64::MAX);
    assert_eq!(r.renew_deadline_ns, u64::MAX);
    assert_eq!(r.expiry_deadline_ns, u64::MAX);
    assert_eq!(r.grace_deadline_ns, u64::MAX);
}

#[test]
fn open_near_u64_max_with_periods() {
    let near = u64::MAX - 100_000;
    let lease = LeaseDeadline::open(1, near, 10_000, 50_000, 10_000, DriftClass::TrustedLocal);
    let r = lease.record();
    assert!(r.renew_deadline_ns >= near);
    assert!(r.expiry_deadline_ns >= r.renew_deadline_ns);
    assert!(r.grace_deadline_ns >= r.expiry_deadline_ns);
}

#[test]
fn evaluate_at_u64_max_does_not_panic() {
    let mut lease = LeaseDeadline::open(1, 0, 1000, 5000, 1000, DriftClass::TrustedLocal);
    let _ = lease.evaluate(u64::MAX);
    assert_eq!(lease.record().state, LeaseDeadlineState::Expired);
}

#[test]
fn renew_near_u64_max_saturates() {
    let near = u64::MAX - 100_000;
    let mut lease = LeaseDeadline::open(1, near, 1000, 5000, 1000, DriftClass::TrustedLocal);
    lease.evaluate(near + 6000);
    lease.renew(u64::MAX, 1000, 5000, 1000);
    let r = lease.record();
    assert_eq!(r.opened_at_ns, u64::MAX);
    assert_eq!(r.renew_deadline_ns, u64::MAX);
    assert_eq!(r.state, LeaseDeadlineState::Open);
}

// ---------------------------------------------------------------------------
// drift-slack scaling
// ---------------------------------------------------------------------------

#[test]
fn elevated_drift_increases_deadlines_vs_trusted() {
    let trusted = LeaseDeadline::open(1, 0, 1000, 5000, 1000, DriftClass::TrustedLocal);
    let elevated = LeaseDeadline::open(2, 0, 1000, 5000, 1000, DriftClass::ElevatedCluster);
    assert!(elevated.record().renew_deadline_ns > trusted.record().renew_deadline_ns);
    assert!(elevated.record().expiry_deadline_ns > trusted.record().expiry_deadline_ns);
}

#[test]
fn severe_drift_extends_further_than_elevated() {
    let elevated = LeaseDeadline::open(1, 0, 1000, 5000, 1000, DriftClass::ElevatedCluster);
    let severe = LeaseDeadline::open(2, 0, 1000, 5000, 1000, DriftClass::SevereCluster);
    assert!(severe.record().renew_deadline_ns > elevated.record().renew_deadline_ns);
}

#[test]
fn untrusted_drift_maximizes_deadlines() {
    let severe = LeaseDeadline::open(1, 0, 1000, 5000, 1000, DriftClass::SevereCluster);
    let untrusted = LeaseDeadline::open(2, 0, 1000, 5000, 1000, DriftClass::UntrustedTime);
    assert!(untrusted.record().renew_deadline_ns >= severe.record().renew_deadline_ns);
}

// ---------------------------------------------------------------------------
// derived deadlines
// ---------------------------------------------------------------------------

#[test]
fn derived_renew_deadline_reflects_record() {
    let lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
    let dd = lease.renew_deadline();
    assert_eq!(dd.clock_class, ClockClass::LeaseDeadline);
    assert_eq!(dd.base_deadline_ns, lease.record().renew_deadline_ns);
    assert!(dd.effective_deadline_ns >= dd.base_deadline_ns);
}

#[test]
fn derived_deadline_has_passed_detection() {
    let lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
    let dd = lease.renew_deadline();
    assert!(!dd.has_passed(1200));
    assert!(dd.has_passed(2000));
}

#[test]
fn derived_deadline_remaining_decreases() {
    let lease = LeaseDeadline::open(1, 1000, 500, 5000, 1000, DriftClass::TrustedLocal);
    let dd = lease.renew_deadline();
    let before = dd.remaining_ns(1000);
    let after = dd.remaining_ns(1200);
    assert!(after < before, "remaining should decrease as time advances");
}

// ---------------------------------------------------------------------------
// state-machine ordering
// ---------------------------------------------------------------------------

#[test]
fn expired_never_regresses() {
    let mut lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
    lease.evaluate(5000);
    assert_eq!(lease.record().state, LeaseDeadlineState::Expired);
    lease.evaluate(100);
    assert_eq!(lease.record().state, LeaseDeadlineState::Expired);
}

#[test]
fn failover_only_after_expiry() {
    let mut lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
    assert!(lease.stage_failover().is_none());
    lease.evaluate(5000);
    assert!(lease.stage_failover().is_some());
    assert_eq!(lease.record().state, LeaseDeadlineState::FailoverStaged);
}

#[test]
fn failover_staged_is_terminal() {
    let mut lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
    lease.evaluate(5000);
    lease.stage_failover();
    lease.evaluate(10000);
    assert_eq!(lease.record().state, LeaseDeadlineState::FailoverStaged);
}

#[test]
fn renewal_resets_state_to_open() {
    let mut lease = LeaseDeadline::open(1, 1000, 500, 2000, 1000, DriftClass::TrustedLocal);
    lease.evaluate(3100);
    assert_eq!(lease.record().state, LeaseDeadlineState::Grace);
    lease.renew(5000, 500, 2000, 1000);
    assert_eq!(lease.record().state, LeaseDeadlineState::Open);
    assert_eq!(lease.record().opened_at_ns, 5000);
}
