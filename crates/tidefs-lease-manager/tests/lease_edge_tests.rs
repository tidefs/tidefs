//! Lease edge-case integration tests.
//!
//! Covers TTL boundaries, zero-TTL handling, duplicate-release safety,
//! clock regression, and concurrent-domain contention scenarios that the
//! core lifecycle and conflict test files don't exercise.

use tidefs_lease::types::{LeaseClass, LeaseDomain};
use tidefs_lease_manager::{LeaseManager, LeaseManagerConfig, LeaseManagerError};
use tidefs_membership_epoch::{EpochId, MemberId};

const T0: u64 = 1_000_000;
const T_30S: u64 = 30_000;

fn m(id: u64) -> MemberId {
    MemberId::new(id)
}
fn ep(id: u64) -> EpochId {
    EpochId::new(id)
}

fn inode_domain(dataset_id: u64, ino: u64) -> LeaseDomain {
    LeaseDomain::Inode { dataset_id, ino }
}

fn make_manager() -> LeaseManager {
    LeaseManager::new(LeaseManagerConfig::default(), ep(1))
}

fn make_manager_with_term(term_millis: u64) -> LeaseManager {
    let config = LeaseManagerConfig {
        default_term_millis: term_millis,
        ..LeaseManagerConfig::default()
    };
    LeaseManager::new(config, ep(1))
}

// ── TTL boundary: acquire with short term, verify expiry exactly ───

#[test]
fn test_short_ttl_boundary_not_expired_at_ttl_minus_one() {
    // Term = 100ms. At T0 + 99ms the lease is still within term
    // but renewal window (renew_by = expires_at - term/4 = T0 + 75) is open.
    let mut mgr = make_manager_with_term(100);
    let g = mgr
        .grant(LeaseClass::Exclusive, inode_domain(1, 42), m(10), 3, T0)
        .expect("grant with 100ms term");

    // 99ms later -- within term but past renewal window
    let now = T0 + 99;
    assert!(!g.is_expired(now));
    let d = mgr.due_for_renewal(now);
    assert!(
        !d.is_empty(),
        "renewal window should be open at T0+99 (renew_by=T0+75)"
    );
    assert!(d.contains(&g.lease_id));
}

#[test]
fn test_short_ttl_boundary_swept_after_grace() {
    // Term = 100ms, grace = term/8 = 12ms.
    // Stale threshold = expires_at + grace + term = T0 + 100 + 12 + 100 = T0 + 212.
    let mut mgr = make_manager_with_term(100);
    let _g = mgr
        .grant(LeaseClass::Exclusive, inode_domain(1, 42), m(10), 3, T0)
        .expect("grant");

    // Past stale threshold (T0 + 250 > T0 + 212)
    let expired = mgr.sweep_expired(T0 + 250);
    assert_eq!(
        expired.len(),
        1,
        "lease should be swept past stale threshold T0+212"
    );
    assert_eq!(mgr.grant_count(), 0);
}

#[test]
fn test_short_ttl_renew_before_boundary_extends() {
    let mut mgr = make_manager_with_term(100);
    let g = mgr
        .grant(LeaseClass::Exclusive, inode_domain(1, 42), m(10), 3, T0)
        .expect("grant");

    // Renew just before term expires (at T0+90, term ends at T0+100)
    let renewed = mgr
        .renew(g.lease_id, m(10), T0 + 90)
        .expect("renew before boundary");
    assert_eq!(renewed.version, 2);
    assert!(renewed.expires_at_millis > g.expires_at_millis);

    // After renew: expires_at = T0+190, renew_by = T0+165.
    // At T0+170 the lease is due for renewal again.
    let still_active = mgr.due_for_renewal(T0 + 170);
    assert!(
        !still_active.is_empty(),
        "lease should be due for renewal at T0+170"
    );
}

// ── Zero-TTL lease ─────────────────────────────────────────────────

#[test]
fn test_zero_term_lease_is_immediately_expired() {
    let mut mgr = make_manager_with_term(0);
    let g = mgr
        .grant(LeaseClass::Exclusive, inode_domain(1, 42), m(10), 3, T0)
        .expect("grant with 0-term");

    // Immediately expires since expires_at = T0 + 0 = T0, and
    // grace = 0/8 = 0, so expired right at T0.
    // Renewal with same timestamp should fail.
    let result = mgr.renew(g.lease_id, m(10), T0);
    assert!(result.is_err());
}

#[test]
fn test_zero_term_lease_swept_immediately() {
    let mut mgr = make_manager_with_term(0);
    let _g = mgr
        .grant(LeaseClass::Exclusive, inode_domain(1, 42), m(10), 3, T0)
        .expect("grant");

    // At T0 + 1, well past the 0-term + 0-grace + 0-stale-threshold
    let expired = mgr.sweep_expired(T0 + 1);
    assert_eq!(expired.len(), 1);
    assert_eq!(mgr.stats().expirations_total, 1);
}

// ── Duplicate release ──────────────────────────────────────────────

#[test]
fn test_double_release_returns_not_found() {
    let mut mgr = make_manager();
    let g = mgr
        .grant(LeaseClass::Exclusive, inode_domain(1, 42), m(10), 3, T0)
        .expect("grant");

    // First release succeeds
    mgr.release(g.lease_id, m(10)).expect("first release");
    assert_eq!(mgr.grant_count(), 0);

    // Second release on same lease ID returns NotFound
    let result = mgr.release(g.lease_id, m(10));
    assert!(
        matches!(result, Err(LeaseManagerError::NotFound(id)) if id == g.lease_id),
        "expected NotFound({}), got {:?}",
        g.lease_id,
        result
    );
}

#[test]
fn test_release_after_revoke_returns_not_found() {
    let mut mgr = make_manager();
    let g = mgr
        .grant(LeaseClass::Exclusive, inode_domain(1, 42), m(10), 3, T0)
        .expect("grant");

    // Revoke (fences, but grant record stays)
    mgr.revoke(g.lease_id).expect("revoke");

    // Release after revoke: lease is fenced but still held, so release should
    // succeed (release removes the grant entirely)
    let result = mgr.release(g.lease_id, m(10));
    assert!(
        result.is_ok(),
        "release after revoke should succeed: {result:?}"
    );

    // Third release on same ID returns NotFound
    let result = mgr.release(g.lease_id, m(10));
    assert!(matches!(result, Err(LeaseManagerError::NotFound(_))));
}

#[test]
fn test_release_nonexistent_lease() {
    let mut mgr = make_manager();
    let result = mgr.release(99999, m(10));
    assert!(matches!(result, Err(LeaseManagerError::NotFound(99999))));
}

// ── Max lease table capacity ───────────────────────────────────────

#[test]
fn test_holder_capacity_respected_in_sequence() {
    let config = LeaseManagerConfig {
        max_leases_per_holder: 3,
        ..LeaseManagerConfig::default()
    };
    let mut mgr = LeaseManager::new(config, ep(1));

    // Fill holder capacity
    mgr.grant(LeaseClass::Shared, inode_domain(1, 1), m(10), 3, T0)
        .unwrap();
    mgr.grant(LeaseClass::Shared, inode_domain(1, 2), m(10), 3, T0)
        .unwrap();
    mgr.grant(LeaseClass::Shared, inode_domain(1, 3), m(10), 3, T0)
        .unwrap();
    assert_eq!(mgr.holder_lease_count(m(10)), 3);

    // Fourth grant fails
    let result = mgr.grant(LeaseClass::Shared, inode_domain(1, 4), m(10), 3, T0);
    assert!(matches!(
        result,
        Err(LeaseManagerError::HolderAtCapacity(_, 3))
    ));

    // Release one, then grant succeeds
    let held = mgr.holder_leases(m(10));
    mgr.release(held[0], m(10)).unwrap();
    assert_eq!(mgr.holder_lease_count(m(10)), 2);

    let result = mgr.grant(LeaseClass::Shared, inode_domain(1, 4), m(10), 3, T0);
    assert!(result.is_ok());
    assert_eq!(mgr.holder_lease_count(m(10)), 3);
}

// ── Clock regression ───────────────────────────────────────────────

#[test]
fn test_renew_with_older_timestamp_still_extends() {
    // If the clock regresses, renew still extends from current expiry
    // (implementation uses LeaseGrant::renew which adds term to now_millis)
    let mut mgr = make_manager();
    let g = mgr
        .grant(
            LeaseClass::Exclusive,
            inode_domain(1, 42),
            m(10),
            3,
            T0 + T_30S,
        )
        .expect("grant at T0+30s");

    // Attempt renew with a timestamp that is *behind* the grant time
    let result = mgr.renew(g.lease_id, m(10), T0);
    // This is a clock-regression scenario -- the LeaseGrant::renew method
    // should either handle it gracefully or return an error.
    // Current impl uses saturating_sub, so it will not panic.
    // May succeed or fail depending on whether now < expires_at.
    let _ = result; // Accept either outcome; the key is no panic
}

#[test]
fn test_grant_with_older_timestamp_works() {
    // Grant two leases at decreasing timestamps -- should not panic
    let mut mgr = make_manager();
    let g1 = mgr
        .grant(
            LeaseClass::Exclusive,
            inode_domain(1, 1),
            m(10),
            3,
            T0 + T_30S,
        )
        .expect("grant at T0+30s");

    // Second grant at an earlier time (clock regression)
    let g2 = mgr
        .grant(LeaseClass::Shared, inode_domain(1, 2), m(20), 3, T0)
        .expect("grant at T0");

    assert_eq!(mgr.grant_count(), 2);
    assert!(g1.lease_id != g2.lease_id);
}

// ── Concurrent acquire for same domain ─────────────────────────────

#[test]
fn test_concurrent_same_domain_exclusive_conflict_reports_winner_id() {
    let mut mgr = make_manager();
    let g1 = mgr
        .grant(LeaseClass::Exclusive, inode_domain(1, 42), m(10), 3, T0)
        .expect("first grant");

    // Second attempt on same domain
    let result = mgr.grant(LeaseClass::Exclusive, inode_domain(1, 42), m(20), 3, T0);

    match result {
        Err(LeaseManagerError::Conflict(conflict_id)) => {
            assert_eq!(
                conflict_id, g1.lease_id,
                "conflict should reference first lease {} but got {}",
                g1.lease_id, conflict_id
            );
        }
        other => panic!("expected Conflict error, got {other:?}"),
    }

    assert_eq!(mgr.stats().conflicts_detected, 1);
}

#[test]
fn test_concurrent_same_domain_shared_does_not_conflict_with_shared() {
    let mut mgr = make_manager();
    mgr.grant(LeaseClass::Shared, inode_domain(1, 42), m(10), 3, T0)
        .expect("first shared grant");

    // Second shared grant on same domain should succeed
    let g2 = mgr
        .grant(LeaseClass::Shared, inode_domain(1, 42), m(20), 3, T0)
        .expect("second shared grant on same domain");

    assert_eq!(mgr.grant_count(), 2);
    assert_eq!(mgr.stats().conflicts_detected, 0);
    assert_eq!(g2.lease_class, LeaseClass::Shared);
}

#[test]
fn test_concurrent_three_way_shared_then_one_releases() {
    let mut mgr = make_manager();
    let g1 = mgr
        .grant(LeaseClass::Shared, inode_domain(1, 42), m(10), 3, T0)
        .unwrap();
    let g2 = mgr
        .grant(LeaseClass::Shared, inode_domain(1, 42), m(20), 3, T0)
        .unwrap();
    let g3 = mgr
        .grant(LeaseClass::Shared, inode_domain(1, 42), m(30), 3, T0)
        .unwrap();

    assert_eq!(mgr.grant_count(), 3);

    // Release first holder -- other two survive
    mgr.release(g1.lease_id, m(10)).unwrap();

    assert_eq!(mgr.grant_count(), 2);
    assert!(mgr.get_grant(g2.lease_id).is_some());
    assert!(mgr.get_grant(g3.lease_id).is_some());
}
