//! Lease lifecycle integration tests.
//!
//! Validate the full lifecycle of a lease: acquire, hold (epoch tracking),
//! renew (TTL extension), explicit release, and expiry.
//! Uses virtual time (u64 millis) for deterministic, sleep-free execution.

use tidefs_lease::types::{LeaseClass, LeaseDomain, LeaseGrant, LeaseLifecycle};
use tidefs_lease_manager::{LeaseManager, LeaseManagerConfig, LeaseManagerError};
use tidefs_membership_epoch::{EpochId, MemberId};

// ── Mock clock (virtual time, u64 milliseconds) ─────────────────────

const T0: u64 = 1_000_000;
const T_1S: u64 = 1_000;
const T_5S: u64 = 5_000;
const T_10S: u64 = 10_000;
const T_25S: u64 = 25_000;
const T_30S: u64 = 30_000;
const T_35S: u64 = 35_000;
const T_60S: u64 = 60_000;
const T_90S: u64 = 90_000;

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

fn acquire_exclusive(
    mgr: &mut LeaseManager,
    dataset_id: u64,
    ino: u64,
    holder: MemberId,
    now: u64,
) -> LeaseGrant {
    mgr.grant(
        LeaseClass::Exclusive,
        inode_domain(dataset_id, ino),
        holder,
        3,
        now,
    )
    .expect("acquire should succeed")
}

// ══════════════════════════════════════════════════════════════════════
// Acquire tests
// ══════════════════════════════════════════════════════════════════════

/// Invariant: acquire on an unheld resource returns a grant with
/// lifecycle=Granted and the correct holder.
#[test]
fn acquire_returns_granted_lease_with_correct_holder() {
    let mut mgr = make_manager();
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    assert_eq!(grant.lifecycle, LeaseLifecycle::Granted);
    assert_eq!(grant.holder_id, m(10));
    assert_eq!(grant.lease_id, 1);
    assert_eq!(mgr.grant_count(), 1);
}

/// Invariant: consecutive acquires on different domains receive
/// monotonically increasing lease IDs.
#[test]
fn acquire_assigns_monotonic_lease_ids() {
    let mut mgr = make_manager();
    let g1 = acquire_exclusive(&mut mgr, 1, 1, m(10), T0);
    let g2 = acquire_exclusive(&mut mgr, 1, 2, m(10), T0);
    let g3 = acquire_exclusive(&mut mgr, 1, 3, m(10), T0);
    assert!(g1.lease_id < g2.lease_id);
    assert!(g2.lease_id < g3.lease_id);
}

/// Invariant: acquire returns a grant whose epoch equals the manager's
/// current epoch.
#[test]
fn acquire_returns_grant_with_current_epoch() {
    let mut mgr = make_manager();
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    assert_eq!(grant.epoch, mgr.current_epoch());
    assert_eq!(grant.epoch, ep(1));
}

/// Invariant: acquire sets expires_at = now + term_millis.
#[test]
fn acquire_sets_correct_expiry() {
    let mut mgr = make_manager_with_term(T_30S);
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    assert_eq!(grant.expires_at_millis, T0 + T_30S);
    assert_eq!(grant.term_millis, T_30S);
}

/// Invariant: acquire records granted_at_millis as the provided now.
#[test]
fn acquire_records_grant_time() {
    let now = T0 + 42_000;
    let mut mgr = make_manager();
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), now);
    assert_eq!(grant.granted_at_millis, now);
}

/// Invariant: acquire fails with InsufficientWitnesses when below quorum.
#[test]
fn acquire_fails_with_insufficient_witnesses() {
    let mut mgr = make_manager();
    let result = mgr.grant(LeaseClass::Exclusive, inode_domain(1, 42), m(10), 1, T0);
    assert!(matches!(
        result,
        Err(LeaseManagerError::InsufficientWitnesses(1, 3))
    ));
}

/// Invariant: acquire fails with HolderAtCapacity when the holder has
/// reached max_leases_per_holder.
#[test]
fn acquire_fails_when_holder_at_capacity() {
    let config = LeaseManagerConfig {
        max_leases_per_holder: 2,
        ..LeaseManagerConfig::default()
    };
    let mut mgr = LeaseManager::new(config, ep(1));

    acquire_exclusive(&mut mgr, 1, 1, m(10), T0);
    acquire_exclusive(&mut mgr, 1, 2, m(10), T0);

    let result = mgr.grant(LeaseClass::Exclusive, inode_domain(1, 3), m(10), 3, T0);
    assert!(matches!(
        result,
        Err(LeaseManagerError::HolderAtCapacity(_, 2))
    ));
}

// ══════════════════════════════════════════════════════════════════════
// Renew tests
// ══════════════════════════════════════════════════════════════════════

/// Invariant: renew extends the TTL; expires_at shifts forward by the
/// full term from the renewal time.
#[test]
fn renew_extends_expiry() {
    let mut mgr = make_manager_with_term(T_30S);
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    let orig = grant.expires_at_millis;
    let renew_at = T0 + T_5S;

    let renewed = mgr.renew(grant.lease_id, m(10), renew_at).unwrap();
    assert!(renewed.expires_at_millis > orig);
    assert_eq!(renewed.expires_at_millis, renew_at + T_30S);
}

/// Invariant: renew increments the grant version monotonically.
#[test]
fn renew_increments_version() {
    let mut mgr = make_manager();
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    assert_eq!(grant.version, 1);

    let r1 = mgr.renew(grant.lease_id, m(10), T0 + T_5S).unwrap();
    assert_eq!(r1.version, 2);

    let r2 = mgr.renew(grant.lease_id, m(10), T0 + T_10S).unwrap();
    assert_eq!(r2.version, 3);
}

/// Invariant: renew fails with NotFound for a nonexistent lease.
#[test]
fn renew_fails_for_nonexistent_lease() {
    let mut mgr = make_manager();
    let result = mgr.renew(999, m(10), T0);
    assert!(matches!(result, Err(LeaseManagerError::NotFound(999))));
}

/// Invariant: renew fails when called by a holder different from the
/// original acquirer.
#[test]
fn renew_fails_for_wrong_holder() {
    let mut mgr = make_manager();
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    let result = mgr.renew(grant.lease_id, m(99), T0 + T_5S);
    assert!(result.is_err());
    assert_eq!(mgr.get_grant(grant.lease_id).unwrap().holder_id, m(10));
}

/// Invariant: renew fails after the full term + grace period has elapsed.
#[test]
fn renew_fails_after_expiry() {
    let mut mgr = make_manager_with_term(T_30S);
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    // Grace = 30_000/8 = 3_750. Expiry = T0+33_750.
    let result = mgr.renew(grant.lease_id, m(10), T0 + T_35S);
    assert!(matches!(result, Err(LeaseManagerError::Expired(_))));
}

/// Invariant: renew fails when the lease is in a terminal state.
#[test]
fn renew_fails_on_terminal_lease() {
    let mut mgr = make_manager();
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    mgr.revoke(grant.lease_id).unwrap();
    let result = mgr.renew(grant.lease_id, m(10), T0 + T_5S);
    assert!(matches!(result, Err(LeaseManagerError::Terminal(_, _))));
}

// ══════════════════════════════════════════════════════════════════════
// Release tests
// ══════════════════════════════════════════════════════════════════════

/// Invariant: explicit release frees the resource; the grant is removed
/// and the domain can be re-acquired.
#[test]
fn release_frees_resource() {
    let mut mgr = make_manager();
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    assert_eq!(mgr.grant_count(), 1);
    mgr.release(grant.lease_id, m(10)).unwrap();
    assert_eq!(mgr.grant_count(), 0);
    assert!(mgr.get_grant(grant.lease_id).is_none());
}

/// Invariant: release fails when called by a different holder.
#[test]
fn release_fails_for_wrong_holder() {
    let mut mgr = make_manager();
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    let result = mgr.release(grant.lease_id, m(99));
    assert!(result.is_err());
    assert_eq!(mgr.grant_count(), 1);
}

/// Invariant: release fails for a nonexistent lease.
#[test]
fn release_fails_for_nonexistent_lease() {
    let mut mgr = make_manager();
    let result = mgr.release(999, m(10));
    assert!(matches!(result, Err(LeaseManagerError::NotFound(999))));
}

// ══════════════════════════════════════════════════════════════════════
// Hold / epoch tracking
// ══════════════════════════════════════════════════════════════════════

/// Invariant: get_grant returns the lease with the epoch from acquisition
/// time.
#[test]
fn hold_returns_correct_epoch() {
    let mut mgr = make_manager();
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    let held = mgr.get_grant(grant.lease_id).unwrap();
    assert_eq!(held.epoch, ep(1));
    assert_eq!(held.lease_id, grant.lease_id);
    assert_eq!(held.holder_id, m(10));
}

/// Invariant: holder_leases returns all lease IDs held by a member.
#[test]
fn holder_leases_tracks_acquisitions() {
    let mut mgr = make_manager();
    let g1 = acquire_exclusive(&mut mgr, 1, 10, m(10), T0);
    let g2 = acquire_exclusive(&mut mgr, 1, 20, m(10), T0);
    let g3 = acquire_exclusive(&mut mgr, 1, 30, m(20), T0);

    let h10 = mgr.holder_leases(m(10));
    assert_eq!(h10.len(), 2);
    assert!(h10.contains(&g1.lease_id));
    assert!(h10.contains(&g2.lease_id));

    let h20 = mgr.holder_leases(m(20));
    assert_eq!(h20.len(), 1);
    assert!(h20.contains(&g3.lease_id));
}

// ══════════════════════════════════════════════════════════════════════
// Expiry tests
// ══════════════════════════════════════════════════════════════════════

/// Invariant: an unrenewed lease becomes stale past term+grace+term
/// and is swept by sweep_expired.
#[test]
fn expiry_fires_after_ttl_without_renewal() {
    let mut mgr = make_manager_with_term(T_30S);
    acquire_exclusive(&mut mgr, 1, 42, m(10), T0);

    let expired = mgr.sweep_expired(T0 + T_30S);
    assert_eq!(expired.len(), 0);
    assert_eq!(mgr.grant_count(), 1);

    let expired = mgr.sweep_expired(T0 + T_90S);
    assert_eq!(expired.len(), 1);
    assert_eq!(mgr.grant_count(), 0);
}

/// Invariant: a renewed lease survives past the original term but
/// eventually expires after its renewed stale threshold.
#[test]
fn renewed_lease_survives_past_original_term() {
    let mut mgr = make_manager_with_term(T_30S);
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    mgr.renew(grant.lease_id, m(10), T0 + T_25S).unwrap();

    // At T0+60s: past original term but before renewed stale threshold
    // (renewed at T0+25s, stale at T0+25s+30s+3_750+30s = T0+88_750)
    let expired = mgr.sweep_expired(T0 + T_60S);
    assert_eq!(expired.len(), 0);

    // At T0+90s: now past the renewed stale threshold
    let expired = mgr.sweep_expired(T0 + T_90S);
    assert_eq!(expired.len(), 1);
}

/// Invariant: is_stale returns true only when now exceeds
/// expires_at + grace_period + term_millis.
#[test]
fn stale_detection_uses_correct_threshold() {
    let mut mgr = make_manager_with_term(T_30S);
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    let held = mgr.get_grant(grant.lease_id).unwrap();

    // stale = T0+30_000 + 3_750 + 30_000 = T0+63_750
    assert!(!held.is_stale(T0 + T_30S));
    assert!(!held.is_stale(T0 + 33_750));
    assert!(!held.is_stale(T0 + 60_000));
    assert!(held.is_stale(T0 + 63_750));
    assert!(held.is_stale(T0 + T_90S));
}

/// Invariant: is_expired returns true when now >= expires_at + grace_period.
#[test]
fn expiry_detection_uses_correct_threshold() {
    let mut mgr = make_manager_with_term(T_30S);
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    let held = mgr.get_grant(grant.lease_id).unwrap();

    assert!(!held.is_expired(T0));
    assert!(!held.is_expired(T0 + T_30S));
    assert!(held.is_expired(T0 + 33_750));
    assert!(held.is_expired(T0 + T_35S));
}

/// Invariant: should_renew returns true when now >= renew_by and the
/// lease is active.
#[test]
fn due_for_renewal_tracks_renew_by() {
    let mut mgr = make_manager_with_term(T_30S);
    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    let held = mgr.get_grant(grant.lease_id).unwrap();

    // renew_by = expires_at - term/4 = T0+22_500
    assert!(!held.should_renew(T0 + 10_000));
    assert!(!held.should_renew(T0 + 22_000));
    assert!(held.should_renew(T0 + 22_500));
    assert!(held.should_renew(T0 + T_30S));
}

// ══════════════════════════════════════════════════════════════════════
// Configurable TTL
// ══════════════════════════════════════════════════════════════════════

/// Invariant: leases granted with a short TTL expire before those with a
/// long TTL.
#[test]
fn configurable_term_controls_expiry() {
    let mut short_mgr = make_manager_with_term(T_1S);
    let sg = acquire_exclusive(&mut short_mgr, 1, 42, m(10), T0);

    let mut long_mgr = make_manager_with_term(T_60S);
    let lg = acquire_exclusive(&mut long_mgr, 1, 42, m(10), T0);

    assert!(sg.expires_at_millis < lg.expires_at_millis);

    let se = short_mgr.sweep_expired(T0 + T_30S);
    assert_eq!(se.len(), 1);

    let le = long_mgr.sweep_expired(T0 + T_30S);
    assert_eq!(le.len(), 0);
}

// ══════════════════════════════════════════════════════════════════════
// Domain variety
// ══════════════════════════════════════════════════════════════════════

/// Invariant: acquires on different domain types (Inode, Subtree,
/// ByteRange) do not conflict with each other.
#[test]
fn different_domain_types_do_not_conflict() {
    let mut mgr = make_manager();
    acquire_exclusive(&mut mgr, 1, 42, m(10), T0);

    let r1 = mgr.grant(
        LeaseClass::Exclusive,
        LeaseDomain::Subtree {
            dataset_id: 1,
            prefix: "/a/".into(),
        },
        m(10),
        3,
        T0,
    );
    assert!(r1.is_ok());

    let r2 = mgr.grant(
        LeaseClass::Exclusive,
        LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 42,
            start: 0,
            end: 4095,
        },
        m(10),
        3,
        T0,
    );
    assert!(r2.is_ok());
}

// ══════════════════════════════════════════════════════════════════════
// Stats tracking
// ══════════════════════════════════════════════════════════════════════

/// Invariant: ManagerStats accurately reflects grant, renew, revoke, and
/// expiry counts over a full lifecycle.
#[test]
fn stats_track_full_lifecycle() {
    let mut mgr = make_manager_with_term(T_30S);
    assert_eq!(mgr.stats().grants_total, 0);
    assert_eq!(mgr.stats().grants_active, 0);

    let grant = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    assert_eq!(mgr.stats().grants_total, 1);
    assert_eq!(mgr.stats().grants_active, 1);

    mgr.renew(grant.lease_id, m(10), T0 + T_5S).unwrap();
    assert_eq!(mgr.stats().renewals_total, 1);

    mgr.revoke(grant.lease_id).unwrap();
    assert_eq!(mgr.stats().revocations_total, 1);
    assert_eq!(mgr.stats().grants_active, 0);

    acquire_exclusive(&mut mgr, 1, 43, m(10), T0);
    mgr.sweep_expired(T0 + T_90S);
    assert_eq!(mgr.stats().expirations_total, 1);
}
