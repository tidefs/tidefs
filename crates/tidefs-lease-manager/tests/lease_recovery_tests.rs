// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Lease manager recovery and restart integration tests.
//!
//! Validate lease-manager behavior across restarts: re-initialization with
//! a partial lease table (snapshot replay), stale-lease detection on
//! restart, lease-table compaction after expired-leases are pruned, and
//! grant_with_id for restoring from Raft snapshots.

use tidefs_lease::types::{LeaseClass, LeaseDomain, LeaseLifecycle};
use tidefs_lease_manager::{LeaseManager, LeaseManagerConfig, LeaseManagerError};
use tidefs_membership_epoch::{EpochId, MemberId};

const T0: u64 = 1_000_000;
const T_30S: u64 = 30_000;
const T_90S: u64 = 90_000;
const T_1H: u64 = 3_600_000;

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

// ══════════════════════════════════════════════════════════════════════
// Re-initialization with partial lease table
// ══════════════════════════════════════════════════════════════════════

/// Invariant: a fresh manager initializes with zero grants, zero holders,
/// and epoch 1.
#[test]
fn fresh_manager_starts_empty() {
    let mgr = make_manager();
    assert_eq!(mgr.grant_count(), 0);
    assert_eq!(mgr.current_epoch(), ep(1));
    assert_eq!(mgr.stats().grants_total, 0);
    assert_eq!(mgr.stats().grants_active, 0);
    assert!(mgr.holder_leases(m(10)).is_empty());
}

/// Invariant: grant_with_id replays a lease from a snapshot with a
/// specific lease_id, restoring it into the manager's lease table.
#[test]
fn grant_with_id_restores_lease_from_snapshot() {
    let mut mgr = make_manager();
    let grant = mgr
        .grant_with_id(
            100,
            LeaseClass::Exclusive,
            inode_domain(1, 42),
            m(10),
            T_30S,
            3,
            T0,
        )
        .unwrap();

    assert_eq!(grant.lease_id, 100);
    assert_eq!(grant.holder_id, m(10));
    assert_eq!(grant.lifecycle, LeaseLifecycle::Granted);
    assert_eq!(mgr.grant_count(), 1);
    assert_eq!(mgr.holder_lease_count(m(10)), 1);
}

/// Invariant: grant_with_id fails with Duplicate if the lease_id already
/// exists.
#[test]
fn grant_with_id_rejects_duplicate() {
    let mut mgr = make_manager();
    mgr.grant_with_id(
        100,
        LeaseClass::Shared,
        inode_domain(1, 1),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();

    let result = mgr.grant_with_id(
        100,
        LeaseClass::Shared,
        inode_domain(1, 2),
        m(20),
        T_30S,
        3,
        T0,
    );
    assert!(matches!(result, Err(LeaseManagerError::Duplicate(100))));
}

/// Invariant: restoring multiple leases via grant_with_id produces a
/// consistent grant_count and holder index.
#[test]
fn restore_multiple_leases_via_grant_with_id() {
    let mut mgr = make_manager();

    mgr.grant_with_id(
        1,
        LeaseClass::Exclusive,
        inode_domain(1, 10),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();
    mgr.grant_with_id(
        2,
        LeaseClass::Shared,
        inode_domain(1, 20),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();
    mgr.grant_with_id(
        3,
        LeaseClass::Exclusive,
        inode_domain(1, 30),
        m(20),
        T_30S,
        3,
        T0,
    )
    .unwrap();

    assert_eq!(mgr.grant_count(), 3);
    assert_eq!(mgr.holder_lease_count(m(10)), 2);
    assert_eq!(mgr.holder_lease_count(m(20)), 1);

    // Verify each lease is retrievable
    assert!(mgr.get_grant(1).is_some());
    assert!(mgr.get_grant(2).is_some());
    assert!(mgr.get_grant(3).is_some());
}

/// Invariant: a re-initialized manager (new instance) that replays the
/// same set of lease grants produces identical grant_count and lease
/// retrievability.
#[test]
fn reinitialized_manager_matches_snapshot_state() {
    // Populate first manager
    let mut mgr1 = make_manager();
    mgr1.grant_with_id(
        10,
        LeaseClass::Exclusive,
        inode_domain(1, 100),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();
    mgr1.grant_with_id(
        20,
        LeaseClass::Shared,
        inode_domain(1, 200),
        m(20),
        T_30S,
        3,
        T0,
    )
    .unwrap();

    // "Restart": create a new manager and replay the same grants
    let mut mgr2 = make_manager();
    mgr2.grant_with_id(
        10,
        LeaseClass::Exclusive,
        inode_domain(1, 100),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();
    mgr2.grant_with_id(
        20,
        LeaseClass::Shared,
        inode_domain(1, 200),
        m(20),
        T_30S,
        3,
        T0,
    )
    .unwrap();

    assert_eq!(mgr2.grant_count(), mgr1.grant_count());
    assert_eq!(
        mgr2.holder_lease_count(m(10)),
        mgr1.holder_lease_count(m(10))
    );
    assert_eq!(
        mgr2.holder_lease_count(m(20)),
        mgr1.holder_lease_count(m(20))
    );

    // Retrieved grants match
    let g1 = mgr1.get_grant(10).unwrap();
    let g2 = mgr2.get_grant(10).unwrap();
    assert_eq!(g1.lease_id, g2.lease_id);
    assert_eq!(g1.holder_id, g2.holder_id);
    assert_eq!(g1.domain, g2.domain);
}

// ══════════════════════════════════════════════════════════════════════
// Stale-lease detection on restart
// ══════════════════════════════════════════════════════════════════════

/// Invariant: is_stale detects leases that have exceeded their full
/// lifecycle (term + grace + extra term) relative to a new "now".
/// After a restart, a lease granted far in the past is immediately stale.
#[test]
fn stale_lease_detected_after_restart() {
    let mut mgr = make_manager();
    mgr.grant_with_id(
        1,
        LeaseClass::Exclusive,
        inode_domain(1, 42),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();

    // Simulate restart at T0 + 1 hour (well past stale threshold)
    let held = mgr.get_grant(1).unwrap();
    assert!(held.is_stale(T0 + T_1H));
}

/// Invariant: an unexpired lease is NOT stale immediately after a short
/// restart.
#[test]
fn recent_lease_not_stale_after_short_restart() {
    let mut mgr = make_manager();
    mgr.grant_with_id(
        1,
        LeaseClass::Exclusive,
        inode_domain(1, 42),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();

    // Restart at T0 + 5s (well within term)
    let held = mgr.get_grant(1).unwrap();
    assert!(!held.is_stale(T0 + 5_000));
}

/// Invariant: sweep_expired removes stale leases and compacts the lease
/// table (grant_count decreases, holder index is updated).
#[test]
fn sweep_compacts_lease_table() {
    let mut mgr = make_manager();
    mgr.grant_with_id(
        1,
        LeaseClass::Exclusive,
        inode_domain(1, 10),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();
    mgr.grant_with_id(
        2,
        LeaseClass::Shared,
        inode_domain(1, 20),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();
    mgr.grant_with_id(
        3,
        LeaseClass::Exclusive,
        inode_domain(1, 30),
        m(20),
        T_30S,
        3,
        T0 + 5_000,
    )
    .unwrap();

    assert_eq!(mgr.grant_count(), 3);
    assert_eq!(mgr.holder_lease_count(m(10)), 2);
    assert_eq!(mgr.holder_lease_count(m(20)), 1);

    // Sweep at T0+90s: leases 1 and 2 are stale; lease 3 was granted at T0+5s,
    // so its stale threshold is (T0+5s) + 30s + 3_750 + 30s = T0+68_750.
    // At T0+90s, lease 3 is also stale.
    let swept = mgr.sweep_expired(T0 + T_90S);
    assert_eq!(swept.len(), 3);

    // Table is compacted
    assert_eq!(mgr.grant_count(), 0);
    assert_eq!(mgr.holder_lease_count(m(10)), 0);
    assert_eq!(mgr.holder_lease_count(m(20)), 0);
    assert!(mgr.holder_leases(m(10)).is_empty());
}

/// Invariant: after sweeping expired leases, the domain_index is cleared
/// for those domains, allowing re-acquisition.
#[test]
fn domain_reclaimable_after_sweep() {
    let mut mgr = make_manager();
    mgr.grant_with_id(
        1,
        LeaseClass::Exclusive,
        inode_domain(1, 42),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();

    // Sweep at far-future time
    let swept = mgr.sweep_expired(T0 + T_1H);
    assert_eq!(swept.len(), 1);

    // Domain is now free
    let g2 = mgr.grant_with_id(
        2,
        LeaseClass::Exclusive,
        inode_domain(1, 42),
        m(20),
        T_30S,
        3,
        T0 + T_1H + 1,
    );
    assert!(g2.is_ok(), "domain should be reclaimable after sweep");
    assert_eq!(mgr.grant_count(), 1);
}

// ══════════════════════════════════════════════════════════════════════
// Partial state + sweep selectivity
// ══════════════════════════════════════════════════════════════════════

/// Invariant: sweep_expired only removes expired leases; non-expired
/// leases survive compaction.
#[test]
fn sweep_removes_only_expired_leases() {
    let mut mgr = make_manager();

    // Lease 1: granted at T0, expires around T0+33_750 (term 30s + grace)
    mgr.grant_with_id(
        1,
        LeaseClass::Exclusive,
        inode_domain(1, 10),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();
    // Lease 2: granted at T0+80_000, expires around T0+113_750
    mgr.grant_with_id(
        2,
        LeaseClass::Shared,
        inode_domain(1, 20),
        m(10),
        T_30S,
        3,
        T0 + 80_000,
    )
    .unwrap();

    // At T0+90s, lease 1 is stale; lease 2 is still fresh
    let swept = mgr.sweep_expired(T0 + T_90S);
    assert_eq!(swept.len(), 1);
    assert!(swept.contains(&1));
    assert_eq!(mgr.grant_count(), 1);
    assert!(mgr.get_grant(2).is_some());
    assert!(mgr.get_grant(1).is_none());
}

/// Invariant: after partial sweep, the holder index correctly reflects
/// remaining leases.
#[test]
fn holder_index_correct_after_partial_sweep() {
    let mut mgr = make_manager();
    mgr.grant_with_id(
        1,
        LeaseClass::Exclusive,
        inode_domain(1, 10),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();
    mgr.grant_with_id(
        2,
        LeaseClass::Exclusive,
        inode_domain(1, 20),
        m(10),
        T_30S,
        3,
        T0 + 80_000,
    )
    .unwrap();
    mgr.grant_with_id(
        3,
        LeaseClass::Shared,
        inode_domain(1, 30),
        m(20),
        T_30S,
        3,
        T0,
    )
    .unwrap();

    // At T0+90s, leases 1 and 3 are stale; lease 2 survives
    mgr.sweep_expired(T0 + T_90S);

    assert_eq!(mgr.holder_lease_count(m(10)), 1);
    assert_eq!(mgr.holder_leases(m(10)), vec![2]);
    assert_eq!(mgr.holder_lease_count(m(20)), 0);
    assert!(mgr.holder_leases(m(20)).is_empty());
}

// ══════════════════════════════════════════════════════════════════════
// Epoch advance across restart
// ══════════════════════════════════════════════════════════════════════

/// Invariant: advance_epoch fences all active leases from prior epochs.
/// After restart into a higher epoch, old leases are fenced.
#[test]
fn advance_epoch_fences_prior_epoch_leases() {
    let mut mgr = make_manager();
    mgr.grant_with_id(
        1,
        LeaseClass::Exclusive,
        inode_domain(1, 42),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();
    mgr.grant_with_id(
        2,
        LeaseClass::Shared,
        inode_domain(1, 43),
        m(20),
        T_30S,
        3,
        T0,
    )
    .unwrap();

    assert_eq!(mgr.current_epoch(), ep(1));

    let fenced = mgr.advance_epoch(ep(5));
    assert_eq!(fenced.len(), 2);
    assert_eq!(mgr.current_epoch(), ep(5));

    // All leases are now fenced
    for &lid in &[1, 2] {
        let g = mgr.get_grant(lid).unwrap();
        assert_eq!(g.lifecycle, LeaseLifecycle::Fenced);
    }
}

/// Invariant: new grants in the advanced epoch use the new epoch value.
#[test]
fn new_grants_use_advanced_epoch() {
    let mut mgr = make_manager();
    mgr.grant_with_id(
        1,
        LeaseClass::Exclusive,
        inode_domain(1, 42),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();
    mgr.advance_epoch(ep(2));

    // New grant in epoch 2
    let g2 = mgr
        .grant_with_id(
            2,
            LeaseClass::Shared,
            inode_domain(1, 43),
            m(20),
            T_30S,
            3,
            T0,
        )
        .unwrap();
    assert_eq!(g2.epoch, ep(2));
}

// ══════════════════════════════════════════════════════════════════════
// Node failure recovery
// ══════════════════════════════════════════════════════════════════════

/// Invariant: handle_node_failure revokes all active leases held by the
/// failed node but leaves other holders untouched.
#[test]
fn node_failure_revokes_only_failed_node_leases() {
    let mut mgr = make_manager();
    mgr.grant_with_id(
        1,
        LeaseClass::Exclusive,
        inode_domain(1, 10),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();
    mgr.grant_with_id(
        2,
        LeaseClass::Exclusive,
        inode_domain(1, 20),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();
    mgr.grant_with_id(
        3,
        LeaseClass::Shared,
        inode_domain(1, 30),
        m(20),
        T_30S,
        3,
        T0,
    )
    .unwrap();

    let revoked = mgr.handle_node_failure(m(10));
    assert_eq!(revoked.len(), 2);
    assert!(revoked.contains(&1));
    assert!(revoked.contains(&2));

    assert_eq!(mgr.stats().node_failure_revocations, 2);

    // Lease 3 (m(20)) untouched
    assert_eq!(mgr.get_grant(3).unwrap().lifecycle, LeaseLifecycle::Granted);
}

/// Invariant: after node failure and sweep, the failed node's leases are
/// fully removed and their domains are reclaimable.
#[test]
fn failed_node_leases_reclaimable_after_sweep() {
    let mut mgr = make_manager();
    mgr.grant_with_id(
        1,
        LeaseClass::Exclusive,
        inode_domain(1, 42),
        m(10),
        T_30S,
        3,
        T0,
    )
    .unwrap();

    mgr.handle_node_failure(m(10));
    mgr.sweep_expired(T0 + T_90S);

    // Domain is free
    let g2 = mgr.grant_with_id(
        2,
        LeaseClass::Exclusive,
        inode_domain(1, 42),
        m(20),
        T_30S,
        3,
        T0 + T_90S + 1,
    );
    assert!(g2.is_ok());
    assert_eq!(mgr.grant_count(), 2); // fenced lease 1 + new lease 2
    assert_eq!(mgr.get_grant(2).unwrap().holder_id, m(20));
}
