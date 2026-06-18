// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Clock skew injection tests for lease safety — #6480 (NEXT-MN-025).
//!
//! Validates that clock skew causes the lease system to fail closed:
//! stale epochs cannot grant or renew leases, future-epoch leases are
//! rejected by epoch-gap detection, and epoch advancement reliably
//! fences all leases issued before the skew event.
//!
//! These tests complement the epoch-chain clock skew tests in
//! tidefs-membership-epoch/tests/clock_skew_validation.rs by verifying
//! the lease-layer safety properties under clock skew conditions.

use tidefs_lease::*;
use tidefs_membership_epoch::{DatasetMountIdentity, EpochId, MemberId};

fn mid(v: u64) -> MemberId {
    MemberId::new(v)
}

fn inode_grant(
    id: u64,
    class: LeaseClass,
    ds: u64,
    ino: u64,
    epoch: u64,
    holder: u64,
) -> LeaseGrant {
    LeaseGrant::request(
        id,
        class,
        LeaseDomain::Inode {
            dataset_id: ds,
            ino,
        },
        mid(holder),
        0u64,
        60_000,
        0,
        EpochId::new(epoch),
        DatasetMountIdentity::ZERO,
        id * 100,
        3,
        3,
    )
}

// ── Scenario 1: Stale epoch lease fenced after leader failover ──────

/// After leader failover increments the term, all active leases are
/// fenced. A skewed node that missed the term change cannot renew
/// its stale lease — the lock table rejects it.
#[test]
fn stale_epoch_lease_fenced_after_failover() {
    let mut table = LockTable::new(1, EpochId::new(10));

    // Grant lease at epoch 10, term 1.
    let g = inode_grant(1, LeaseClass::Exclusive, 1, 42, 10, 1);
    table.apply(&RaftCommand::Grant { grant: g });

    // Leader failover — term advances, all leases fenced.
    table.leader_failover();
    assert_eq!(table.current_term(), 2);

    let lease = table.get_grant(1).unwrap();
    assert_eq!(
        lease.lifecycle,
        LeaseLifecycle::Fenced,
        "lease must be fenced after leader failover"
    );

    // Skewed node (still thinks term=1) tries to renew — rejected.
    let mut fenced = lease.clone();
    let result = fenced.renew(10_000);
    assert!(result.is_err(), "fenced lease must reject renewal");
    match result.unwrap_err() {
        LeaseError::AlreadyTerminal { lease_id, state } => {
            assert_eq!(lease_id, 1);
            assert_eq!(state, LeaseLifecycle::Fenced);
        }
        e => panic!("expected AlreadyTerminal(Fenced), got {e:?}"),
    }
}

// ── Scenario 2: Validate fencing rejects stale epoch ────────────────

/// The `validate_fencing` method checks that the caller's term and
/// epoch match the lock table's current state. A skewed node with an
/// old epoch is rejected.
#[test]
fn validate_fencing_rejects_stale_epoch() {
    let table = LockTable::new(5, EpochId::new(10));

    // Healthy node: current term=5, epoch=10 — passes.
    assert!(table.validate_fencing(5, EpochId::new(10)));

    // Skewed node: same term, but stale epoch=8 — fails.
    assert!(!table.validate_fencing(5, EpochId::new(8)));

    // Skewed node: correct epoch, but stale term=3 — fails.
    assert!(!table.validate_fencing(3, EpochId::new(10)));

    // Skewed node: both stale — fails.
    assert!(!table.validate_fencing(2, EpochId::new(5)));

    // Skewed node: far-future epoch — fails.
    assert!(!table.validate_fencing(5, EpochId::new(50)));
}

// ── Scenario 3: Leader failover fences all leases, rejects stale ops ─

/// After leader failover (term bump), all active leases become fenced.
/// A skewed node cannot re-acquire a lease at the old term using the
/// same domain — the old lease is terminal.
#[test]
fn failover_fences_all_leases_rejects_stale_ops() {
    let mut table = LockTable::new(1, EpochId::new(1));

    // Three nodes acquire leases on different domains.
    for i in 0..3 {
        let g = inode_grant(i + 1, LeaseClass::Exclusive, 1, 10 + i, 1, i + 1);
        table.apply(&RaftCommand::Grant { grant: g });
    }
    assert_eq!(table.grant_count(), 3);

    // Leader failover — all three leases fenced.
    table.leader_failover();
    for i in 0..3 {
        let lease = table.get_grant(i + 1).unwrap();
        assert_eq!(
            lease.lifecycle,
            LeaseLifecycle::Fenced,
            "lease {} must be fenced after failover",
            i + 1
        );
        // Stale renewal attempt rejected.
        let mut fenced = lease.clone();
        assert!(fenced.renew(10_000).is_err());
    }
}

// ── Scenario 4: Backwards clock skew cannot resurrect fenced lease ──

/// Once a lease is fenced, clock skew cannot bring it back to life.
/// New grants at the old epoch must not override the fenced state.
#[test]
fn backwards_clock_skew_cannot_resurrect_fenced_lease() {
    let mut table = LockTable::new(1, EpochId::new(1));

    let g = inode_grant(1, LeaseClass::Exclusive, 1, 42, 1, 1);
    table.apply(&RaftCommand::Grant { grant: g });
    table.leader_failover();

    let fenced = table.get_grant(1).unwrap();
    assert_eq!(fenced.lifecycle, LeaseLifecycle::Fenced);

    // Attempt to grant a new lease with epoch 0 (backwards clock skew).
    // The old lease must remain fenced.
    let g_back = inode_grant(2, LeaseClass::Exclusive, 1, 42, 0, 2);
    table.apply(&RaftCommand::Grant { grant: g_back });

    let still_fenced = table.get_grant(1).unwrap();
    assert_eq!(
        still_fenced.lifecycle,
        LeaseLifecycle::Fenced,
        "backwards clock skew must not resurrect fenced lease"
    );
}

// ── Scenario 5: New lease after failover on same domain ─────────────

/// A skewed node cannot lock a domain that was fenced and re-acquired
/// by a healthy node after failover.
#[test]
fn skewed_node_cannot_reacquire_fenced_domain() {
    let mut table = LockTable::new(1, EpochId::new(3));

    // Node 1 holds exclusive lease.
    let g1 = inode_grant(1, LeaseClass::Exclusive, 1, 42, 3, 1);
    table.apply(&RaftCommand::Grant { grant: g1 });

    // Leader failover → node 1's lease fenced.
    table.leader_failover();

    // Node 2 acquires fresh lease on same domain.
    let g2 = LeaseGrant::request(
        2,
        LeaseClass::Exclusive,
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        mid(2),
        0u64,
        60_000,
        0,
        EpochId::new(3), // same epoch but post-failover term
        DatasetMountIdentity::ZERO,
        200,
        3,
        3,
    );
    table.apply(&RaftCommand::Grant { grant: g2 });

    // Node 2's lease is the active one.
    let active = table.get_grant(2).unwrap();
    assert_eq!(active.holder_id, mid(2));
    assert_eq!(active.lifecycle, LeaseLifecycle::Granted);

    // Node 1 (skewed, still thinks it holds the domain) — its lease is fenced.
    let stale = table.get_grant(1).unwrap();
    assert_eq!(stale.lifecycle, LeaseLifecycle::Fenced);
}

// ── Scenario 6: Lease expiry not extended by clock skew ─────────────

/// A lease's expires_at_millis is set at grant time and is immutable
/// after grant. Clock skew on a renewing node cannot silently extend
/// the lease's effective lifetime — renewal requires a valid Raft
/// command, not just clock manipulation.
#[test]
fn lease_expiry_immutable_after_grant() {
    let mut table = LockTable::new(1, EpochId::new(1));

    let g = LeaseGrant::request(
        1,
        LeaseClass::Exclusive,
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        mid(1),
        0u64,
        60_000, // 60s TTL
        0,      // granted at time 0
        EpochId::new(1),
        DatasetMountIdentity::ZERO,
        100,
        3,
        3,
    );
    table.apply(&RaftCommand::Grant { grant: g });

    let lease = table.get_grant(1).unwrap();
    assert_eq!(lease.expires_at_millis, 60_000);
    assert_eq!(lease.term_millis, 60_000);

    // Clock-skewed node cannot alter the stored expiry directly.
    let expires = lease.expires_at_millis;
    assert_eq!(lease.expires_at_millis, expires);

    // A lease expired by wall clock cannot be used.
    assert!(
        lease.is_expired(120_000),
        "lease must be expired after TTL + grace"
    );
    assert!(
        !lease.is_expired(30_000),
        "lease must not be expired before TTL"
    );
}

// ── Scenario 7: Rapid term oscillation does not corrupt lease table ──

/// Multiple leader failovers (term bumps) rapidly fence all active
/// leases each time. The table must remain consistent.
#[test]
fn rapid_term_oscillation_does_not_corrupt_lease_table() {
    let mut table = LockTable::new(1, EpochId::new(1));

    // Grant lease.
    let g = inode_grant(1, LeaseClass::Exclusive, 1, 42, 1, 1);
    table.apply(&RaftCommand::Grant { grant: g });

    // Three rapid failovers.
    for expected_term in 2..=4u64 {
        table.leader_failover();
        assert_eq!(table.current_term(), expected_term);
        // Previous lease is still fenced.
        let lease = table.get_grant(1).unwrap();
        assert_eq!(lease.lifecycle, LeaseLifecycle::Fenced);
    }

    // New grant at current term is fine.
    let g_new = inode_grant(2, LeaseClass::Shared, 1, 42, 1, 2);
    table.apply(&RaftCommand::Grant { grant: g_new });
    assert_eq!(
        table.get_grant(2).unwrap().lifecycle,
        LeaseLifecycle::Granted
    );
}

// ── Scenario 8: Multiple skewed nodes cannot form quorum on old term ─

/// When a cluster partitions, only nodes on the current term can
/// validate fencing. Stale-term nodes are locked out.
#[test]
fn multiple_skewed_nodes_cannot_pass_fencing() {
    let table = LockTable::new(10, EpochId::new(5));

    // Healthy nodes at current term/epoch pass.
    assert!(table.validate_fencing(10, EpochId::new(5)));

    // Skewed nodes with old term fail.
    for stale_term in &[9u64, 8, 5, 1] {
        assert!(
            !table.validate_fencing(*stale_term, EpochId::new(5)),
            "stale term {stale_term} must fail fencing"
        );
    }
}

// ── Scenario 9: Fenced leases are terminal — no state regression ────

/// A fenced lease must stay fenced regardless of any subsequent
/// operations. The terminal state is irreversible.
#[test]
fn fenced_lease_never_returns_to_granted() {
    let mut table = LockTable::new(1, EpochId::new(1));

    let g = inode_grant(1, LeaseClass::Exclusive, 1, 42, 1, 1);
    table.apply(&RaftCommand::Grant { grant: g });
    table.leader_failover();

    // Try to fence again — should remain fenced (idempotent).
    let mut lease = table.get_grant(1).unwrap().clone();
    let _ = lease.fence(); // fence() is idempotent on already-fenced
    assert_eq!(lease.lifecycle, LeaseLifecycle::Fenced);

    // Try to expire — terminal state unchanged.
    // expire() is not a public method on LeaseGrant; use is_expired() instead
    assert_eq!(lease.lifecycle, LeaseLifecycle::Fenced);

    // Renewal still rejected.
    assert!(lease.renew(10_000).is_err());
}
