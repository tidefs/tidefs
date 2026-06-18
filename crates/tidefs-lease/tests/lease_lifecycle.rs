// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for lease state transitions through the public API.
//!
//! Exercises LeaseGrant lifecycle methods (fence, release, renew) and
//! LockTable-driven lifecycle via RaftCommand application. Covers valid
//! transitions, invalid transition rejection, double-acquire safety, and
//! full lifecycle sequences.

use tidefs_lease::*;
use tidefs_membership_epoch::{DatasetMountIdentity, EpochId, MemberId};

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
        DatasetMountIdentity::ZERO,
        id * 100,
        3,
        3,
    )
}

// ── Full lifecycle sequence ──────────────────────────────────────────────

#[test]
fn full_lifecycle_requested_to_released() {
    let mut grant = make_grant(1, 60_000, 0);
    assert_eq!(grant.lifecycle, LeaseLifecycle::Granted);
    assert_eq!(grant.version, 1);

    grant.renew(10_000).expect("first renew");
    assert_eq!(grant.lifecycle, LeaseLifecycle::Renewing);
    assert_eq!(grant.version, 2);

    // Renew again (multiple renewals)
    grant.renew(20_000).expect("second renew");
    assert_eq!(grant.version, 3);

    grant.release().expect("release after renewals");
    assert_eq!(grant.lifecycle, LeaseLifecycle::Released);
}

#[test]
fn full_lifecycle_requested_to_fenced() {
    let mut grant = make_grant(2, 60_000, 0);
    grant.fence().expect("fence while granted");
    assert_eq!(grant.lifecycle, LeaseLifecycle::Fenced);
    assert!(grant.lifecycle.is_terminal());
}

// ── Double-acquire safety via LockTable ──────────────────────────────────

#[test]
fn double_grant_same_lease_id_overwrites_in_lock_table() {
    // LockTable::apply with Grant on existing lease_id overwrites.
    let mut table = LockTable::new(1, EpochId::new(1));
    let g1 = make_grant(100, 30_000, 0);
    table.apply(&RaftCommand::Grant { grant: g1 });
    assert_eq!(table.grant_count(), 1);

    let g2 = LeaseGrant::request(
        100,
        LeaseClass::Shared,
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 99,
        },
        mid(2),
        0u64,
        50_000,
        10_000,
        EpochId::new(1),
        DatasetMountIdentity::ZERO,
        200,
        3,
        3,
    );
    table.apply(&RaftCommand::Grant { grant: g2 });
    assert_eq!(table.grant_count(), 1);
    let existing = table.get_grant(100).expect("grant should exist");
    assert_eq!(existing.lease_class, LeaseClass::Shared);
    assert_eq!(existing.holder_id, mid(2));
}

// ── Slot reuse: grant → release → re-grant ──────────────────────────────

#[test]
fn slot_reuse_after_release() {
    let mut table = LockTable::new(1, EpochId::new(1));
    let g = make_grant(1, 30_000, 0);
    table.apply(&RaftCommand::Grant { grant: g });
    assert_eq!(table.grant_count(), 1);

    table.apply(&RaftCommand::Release { lease_id: 1 });
    assert_eq!(table.grant_count(), 0);

    let g2 = make_grant(1, 30_000, 0);
    table.apply(&RaftCommand::Grant { grant: g2 });
    assert_eq!(table.grant_count(), 1);
    assert_eq!(table.get_grant(1).unwrap().version, 1);
}

// ── Fenced lease rejects renew ──────────────────────────────────────────

#[test]
fn fenced_lease_rejects_renew() {
    let mut grant = make_grant(1, 60_000, 0);
    grant.fence().expect("fence should succeed");
    let result = grant.renew(10_000);
    assert!(result.is_err());
    match result.unwrap_err() {
        LeaseError::AlreadyTerminal { lease_id, state } => {
            assert_eq!(lease_id, 1);
            assert_eq!(state, LeaseLifecycle::Fenced);
        }
        _ => panic!("expected AlreadyTerminal"),
    }
}

// ── Double fence / double release rejected ──────────────────────────────

#[test]
fn double_fence_rejected() {
    let mut grant = make_grant(1, 60_000, 0);
    grant.fence().expect("first fence");
    let result = grant.fence();
    assert!(result.is_err());
    match result.unwrap_err() {
        LeaseError::AlreadyTerminal { lease_id, .. } => assert_eq!(lease_id, 1),
        _ => panic!("expected AlreadyTerminal"),
    }
}

#[test]
fn double_release_rejected() {
    let mut grant = make_grant(1, 60_000, 0);
    grant.release().expect("first release");
    let result = grant.release();
    assert!(result.is_err());
    match result.unwrap_err() {
        LeaseError::AlreadyTerminal { lease_id, .. } => assert_eq!(lease_id, 1),
        _ => panic!("expected AlreadyTerminal"),
    }
}

// ── Transition from each active state to Fenced ─────────────────────────

#[test]
fn transition_granted_to_fenced() {
    let mut grant = make_grant(1, 60_000, 0);
    assert_eq!(grant.lifecycle, LeaseLifecycle::Granted);
    grant.fence().expect("fence from Granted");
    assert_eq!(grant.lifecycle, LeaseLifecycle::Fenced);
}

#[test]
fn transition_renewing_to_fenced() {
    let mut grant = make_grant(1, 60_000, 0);
    grant.renew(10_000).expect("renew");
    assert_eq!(grant.lifecycle, LeaseLifecycle::Renewing);
    grant.fence().expect("fence from Renewing");
    assert_eq!(grant.lifecycle, LeaseLifecycle::Fenced);
}

// ── LockTable leader failover fences all ────────────────────────────────

#[test]
fn leader_failover_fences_all_active_leases() {
    let mut table = LockTable::new(1, EpochId::new(1));
    for i in 0..5 {
        let g = LeaseGrant::request(
            i,
            LeaseClass::Exclusive,
            LeaseDomain::Inode {
                dataset_id: 1,
                ino: 100 + i,
            },
            mid(i),
            0u64,
            60_000,
            0,
            EpochId::new(1),
        DatasetMountIdentity::ZERO,
            i * 100,
            3,
            3,
        );
        table.apply(&RaftCommand::Grant { grant: g });
    }
    assert_eq!(table.grant_count(), 5);

    // One is already released
    table.apply(&RaftCommand::Release { lease_id: 2 });
    assert_eq!(table.grant_count(), 4);

    table.leader_failover();
    assert_eq!(table.current_term(), 2);

    // All remaining active leases should be Fenced
    for (id, expected_fenced) in [(0, true), (1, true), (3, true), (4, true)] {
        let grant = table.get_grant(id).expect("grant should exist");
        assert_eq!(
            grant.lifecycle == LeaseLifecycle::Fenced,
            expected_fenced,
            "lease {id} should be Fenced"
        );
    }
}
