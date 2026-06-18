//! Integration tests for lease timeout computation and boundary conditions.
//!
//! Exercises LeaseGrant::is_expired, is_stale, should_renew, and renew with
//! edge-case durations including zero, near-overflow, and exact boundary
//! timestamps. All time values are passed as parameters (no wall-clock sleep).

use tidefs_lease::*;
use tidefs_membership_epoch::{EpochId, MemberId};

fn mid(v: u64) -> MemberId {
    MemberId::new(v)
}

fn make_grant(id: u64, term_millis: u64, granted_at_millis: u64) -> LeaseGrant {
    LeaseGrant::request(
        id,
        LeaseClass::Exclusive,
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        mid(1),
        0u64,
        term_millis,
        granted_at_millis,
        EpochId::new(1),
        id * 100,
        3,
        3,
    )
}

// ── Zero-duration lease ──────────────────────────────────────────────────

#[test]
fn zero_duration_lease_expires_immediately() {
    // term_millis=0 → expires_at = 0, grace = 0, expired at 0
    let grant = make_grant(1, 0, 0);
    assert!(grant.is_expired(0));
    assert!(grant.is_expired(1));
    assert!(grant.is_stale(0)); // stale_threshold = 0 + 0 + 0 = 0
}

#[test]
fn zero_duration_lease_renew_fails_expired() {
    let mut grant = make_grant(1, 0, 0);
    // Zero-term lease expires at t=0; renew at t=100_000 hits is_expired.
    let result = grant.renew(100_000);
    assert!(result.is_err());
    match result.unwrap_err() {
        LeaseError::Expired { lease_id } => assert_eq!(lease_id, 1),
        _ => panic!("expected Expired"),
    }
}

#[test]
fn zero_term_should_renew_before_expiry() {
    let grant = make_grant(1, 0, 0);
    // renew_by = 0 - 0 = 0, so should_renew(0) is true
    assert!(grant.should_renew(0));
}

// ── Near-overflow durations ──────────────────────────────────────────────

#[test]
fn near_max_term_does_not_panic() {
    // u64::MAX term: saturating arithmetic must not panic
    let grant = make_grant(1, u64::MAX, 0);
    // expires_at = u64::MAX (saturated)
    assert!(!grant.is_expired(0));
    assert!(!grant.is_expired(u64::MAX / 2));
    assert!(grant.is_expired(u64::MAX));
    assert!(grant.is_stale(u64::MAX));
}

#[test]
fn near_max_granted_at_does_not_panic() {
    let grant = make_grant(1, 60_000, u64::MAX - 1);
    // expires_at = u64::MAX (saturated)
    assert!(!grant.is_expired(u64::MAX - 2));
    assert!(grant.is_expired(u64::MAX));
}

#[test]
fn near_max_renew_does_not_panic_on_expired() {
    // granted_at = u64::MAX - 100, term = 60_000 => expires_at = u64::MAX (sat)
    // At now = u64::MAX, is_expired => true, renew returns Err.
    // This test verifies the code path does not panic.
    let mut grant = make_grant(1, 60_000, u64::MAX - 100);
    let result = grant.renew(u64::MAX);
    assert!(result.is_err());
}

// ── Exact boundary tests ─────────────────────────────────────────────────

#[test]
fn is_expired_at_exact_grace_boundary() {
    let grant = make_grant(1, 60_000, 0);
    // expires_at = 60_000, grace = 60_000/8 = 7_500, expired at 67_500
    assert!(!grant.is_expired(67_499));
    assert!(grant.is_expired(67_500));
}

#[test]
fn is_stale_at_exact_stale_threshold() {
    let grant = make_grant(1, 60_000, 0);
    // stale_threshold = 67_500 + 60_000 = 127_500
    assert!(!grant.is_stale(127_499));
    assert!(grant.is_stale(127_500));
}

#[test]
fn should_renew_at_exact_renew_by() {
    let grant = make_grant(1, 60_000, 0);
    // expires_at = 60_000, renew_by = 60_000 - 15_000 = 45_000
    assert!(!grant.should_renew(44_999));
    assert!(grant.should_renew(45_000));
}

// ── Renewal extends deadline correctly ───────────────────────────────────

#[test]
fn renew_extends_deadline_correctly() {
    let mut grant = make_grant(1, 60_000, 0);
    // expires_at = 60_000, renew_by = 45_000
    grant.renew(30_000).expect("renew at 30s");
    assert_eq!(grant.granted_at_millis, 30_000);
    assert_eq!(grant.expires_at_millis, 90_000);
    assert_eq!(grant.renew_by_millis, 75_000);

    // Renew again at 80s
    grant.renew(80_000).expect("renew at 80s");
    assert_eq!(grant.granted_at_millis, 80_000);
    assert_eq!(grant.expires_at_millis, 140_000);
    assert_eq!(grant.renew_by_millis, 125_000);
    assert_eq!(grant.version, 3);
}

// ── Renew after expiry fails ─────────────────────────────────────────────

#[test]
fn renew_after_expiry_fails() {
    let mut grant = make_grant(1, 60_000, 0);
    // expired at 67_500
    let result = grant.renew(67_500);
    assert!(result.is_err());
    match result.unwrap_err() {
        LeaseError::Expired { lease_id } => assert_eq!(lease_id, 1),
        _ => panic!("expected Expired"),
    }
}

#[test]
fn renew_just_before_expiry_succeeds() {
    let mut grant = make_grant(1, 60_000, 0);
    // expiry at 67_500, renew at 67_499 should work
    grant.renew(67_499).expect("renew just before expiry");
    assert_eq!(grant.version, 2);
}

// ── Terminal state ignores should_renew ─────────────────────────────────

#[test]
fn terminal_lease_should_not_renew() {
    let mut grant = make_grant(1, 60_000, 0);
    grant.fence().expect("fence");
    assert!(!grant.should_renew(50_000)); // past renew_by but terminal

    let mut grant2 = make_grant(2, 60_000, 0);
    grant2.release().expect("release");
    assert!(!grant2.should_renew(50_000));

    let mut grant3 = make_grant(3, 60_000, 0);
    grant3.lifecycle = LeaseLifecycle::Expired;
    assert!(!grant3.should_renew(50_000));
}
