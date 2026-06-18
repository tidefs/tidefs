// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Lease conflict detection integration tests.
//!
//! Validate conflict semantics between contending leaseholders:
//! first-claim-wins, exclusive-vs-shared rules, conflict notification on
//! denied acquisition, and successful re-acquisition after prior holder
//! releases or is revoked.

use tidefs_lease::types::{LeaseClass, LeaseDomain, LeaseGrant};
use tidefs_lease_manager::{LeaseManager, LeaseManagerConfig, LeaseManagerError};
use tidefs_membership_epoch::{EpochId, MemberId};

const T0: u64 = 1_000_000;
const T_5S: u64 = 5_000;

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

fn acquire_shared(
    mgr: &mut LeaseManager,
    dataset_id: u64,
    ino: u64,
    holder: MemberId,
    now: u64,
) -> LeaseGrant {
    mgr.grant(
        LeaseClass::Shared,
        inode_domain(dataset_id, ino),
        holder,
        3,
        now,
    )
    .expect("acquire shared should succeed")
}

// ══════════════════════════════════════════════════════════════════════
// First-claim-wins semantics
// ══════════════════════════════════════════════════════════════════════

/// Invariant: the first holder to claim a resource (exclusive) succeeds;
/// a second claimant receives a Conflict error containing the existing
/// lease ID.
#[test]
fn first_claim_wins_exclusive() {
    let mut mgr = make_manager();
    let g1 = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);

    let result = mgr.grant(LeaseClass::Exclusive, inode_domain(1, 42), m(20), 3, T0);
    assert!(matches!(result, Err(LeaseManagerError::Conflict(id)) if id == g1.lease_id));
    assert_eq!(mgr.grant_count(), 1);
}

/// Invariant: an exclusive holder blocks a shared acquisition on the same
/// domain.
#[test]
fn exclusive_blocks_shared() {
    let mut mgr = make_manager();
    acquire_exclusive(&mut mgr, 1, 42, m(10), T0);

    let result = mgr.grant(LeaseClass::Shared, inode_domain(1, 42), m(20), 3, T0);
    assert!(matches!(result, Err(LeaseManagerError::Conflict(_))));
    assert_eq!(mgr.grant_count(), 1);
}

/// Invariant: a shared holder does not block another shared acquisition
/// on the same domain.
#[test]
fn shared_does_not_block_shared() {
    let mut mgr = make_manager();
    acquire_shared(&mut mgr, 1, 42, m(10), T0);

    let result = mgr.grant(LeaseClass::Shared, inode_domain(1, 42), m(20), 3, T0);
    assert!(result.is_ok());
}

/// Invariant: conflict notification includes the existing lease ID so
/// the denied claimant can wait on or challenge the blocking lease.
#[test]
fn conflict_notification_includes_existing_lease_id() {
    let mut mgr = make_manager();
    let g1 = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);

    let result = mgr.grant(LeaseClass::Exclusive, inode_domain(1, 42), m(20), 3, T0);
    match result {
        Err(LeaseManagerError::Conflict(existing_id)) => {
            assert_eq!(existing_id, g1.lease_id);
            let existing = mgr.get_grant(existing_id).unwrap();
            assert_eq!(existing.holder_id, m(10));
        }
        other => panic!("expected Conflict error, got {other:?}"),
    }
}

/// Invariant: conflicts_detected stat increments on each conflict.
#[test]
fn conflicts_detected_stat_increments() {
    let mut mgr = make_manager();
    acquire_exclusive(&mut mgr, 1, 42, m(10), T0);

    assert_eq!(mgr.stats().conflicts_detected, 0);
    let _ = mgr.grant(LeaseClass::Exclusive, inode_domain(1, 42), m(20), 3, T0);
    assert_eq!(mgr.stats().conflicts_detected, 1);

    let _ = mgr.grant(LeaseClass::Shared, inode_domain(1, 42), m(30), 3, T0);
    assert_eq!(mgr.stats().conflicts_detected, 2);
}

// ══════════════════════════════════════════════════════════════════════
// Re-acquisition after release / revoke
// ══════════════════════════════════════════════════════════════════════

/// Invariant: after the prior holder releases, a new holder can acquire
/// the same domain without conflict.
#[test]
fn reacquire_after_release_succeeds() {
    let mut mgr = make_manager();
    let g1 = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);

    mgr.release(g1.lease_id, m(10)).unwrap();

    let g2 = mgr.grant(
        LeaseClass::Exclusive,
        inode_domain(1, 42),
        m(20),
        3,
        T0 + T_5S,
    );
    assert!(g2.is_ok(), "re-acquire after release should succeed");
    assert_eq!(mgr.grant_count(), 1);
}

/// Invariant: after the prior holder is revoked (fenced = terminal state),
/// the domain is immediately free for re-acquisition. The grant method
/// skips terminal-state leases during conflict checking.
#[test]
fn reacquire_after_revoke_succeeds() {
    let mut mgr = make_manager();
    let g1 = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    mgr.revoke(g1.lease_id).unwrap();

    let g2 = mgr.grant(
        LeaseClass::Exclusive,
        inode_domain(1, 42),
        m(20),
        3,
        T0 + T_5S,
    );
    assert!(g2.is_ok(), "re-acquire after revoke should succeed");
    assert_eq!(g2.unwrap().holder_id, m(20));
    assert_eq!(mgr.grant_count(), 2); // fenced + new active
}

/// Invariant: fenced (terminal) leases are not removed by sweep_expired
/// (it only sweeps non-terminal stale leases), but they do not block
/// re-acquisition because the conflict check skips terminal leases.
#[test]
fn fenced_lease_does_not_block_reacquire() {
    let mut mgr = make_manager();
    let g1 = acquire_exclusive(&mut mgr, 1, 42, m(10), T0);
    mgr.revoke(g1.lease_id).unwrap();

    // sweep_expired skips terminal leases
    let swept = mgr.sweep_expired(T0 + 90_000);
    assert_eq!(swept.len(), 0, "fenced lease not swept (terminal)");

    // But re-acquire still works
    let g2 = mgr.grant(
        LeaseClass::Exclusive,
        inode_domain(1, 42),
        m(20),
        3,
        T0 + 91_000,
    );
    assert!(
        g2.is_ok(),
        "re-acquire succeeds despite fenced lease in table"
    );
    assert_eq!(mgr.grant_count(), 2); // fenced + new active
}

// ══════════════════════════════════════════════════════════════════════
// Cross-domain non-conflict
// ══════════════════════════════════════════════════════════════════════

/// Invariant: holders of different inodes on the same dataset do not
/// conflict.
#[test]
fn different_inodes_do_not_conflict() {
    let mut mgr = make_manager();
    acquire_exclusive(&mut mgr, 1, 100, m(10), T0);

    let result = mgr.grant(LeaseClass::Exclusive, inode_domain(1, 200), m(20), 3, T0);
    assert!(result.is_ok());
    assert_eq!(mgr.grant_count(), 2);
}

/// Invariant: holders of the same inode on different datasets do not
/// conflict.
#[test]
fn different_datasets_do_not_conflict() {
    let mut mgr = make_manager();
    acquire_exclusive(&mut mgr, 1, 42, m(10), T0);

    let result = mgr.grant(LeaseClass::Exclusive, inode_domain(2, 42), m(20), 3, T0);
    assert!(result.is_ok());
    assert_eq!(mgr.grant_count(), 2);
}

// ══════════════════════════════════════════════════════════════════════
// Holder capacity edge
// ══════════════════════════════════════════════════════════════════════

/// Invariant: HolderAtCapacity is returned before domain-conflict checking;
/// the conflict stat is not incremented for capacity denials.
#[test]
fn holder_capacity_checked_before_conflict() {
    let config = LeaseManagerConfig {
        max_leases_per_holder: 1,
        ..LeaseManagerConfig::default()
    };
    let mut mgr = LeaseManager::new(config, ep(1));

    acquire_exclusive(&mut mgr, 1, 1, m(10), T0);

    let result = mgr.grant(
        LeaseClass::Exclusive,
        inode_domain(1, 2), // different domain, no conflict
        m(10),
        3,
        T0,
    );
    assert!(matches!(
        result,
        Err(LeaseManagerError::HolderAtCapacity(_, 1))
    ));
    assert_eq!(mgr.stats().conflicts_detected, 0);
}
