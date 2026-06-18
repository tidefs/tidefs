//! Integration tests for three-node lease expiry and fencing.
//!
//! Exercises the core correctness property for #6469 (NEXT-MN-014):
//! a partitioned node is fenced and stale writes cannot publish after
//! lease expiry. Uses the LockTable and LeaseProtocol APIs to simulate
//! a three-node cluster where one node's lease is fenced via leader
//! failover, after which the fenced node's renewal is rejected and a
//! new node can acquire a fresh lease for the same domain.
//!
//! These tests validate the fencing mechanism at the T1 (cargo/unit)
//! validation tier. T7 multi-process distributed validation requires a
//! real QEMU cluster and is tracked in the validation block below.
//!
//! ## Scenarios
//!
//! 1. leader_failover_fences_lease_and_rejects_renewal
//!    Node 1 holds lease → leader failover (partition) → Node 1's
//!    lease fenced → Node 1 renew rejected → Node 2 acquires fresh
//!    lease on same domain.
//!
//! 2. validate_fencing_rejects_stale_term
//!    Write gate rejects operations from a node with an old term.
//!
//! 3. epoch_advance_revokes_all_active_leases
//!    Epoch boundary fences every active lease, preventing split-brain
//!    writes across epochs.
//!
//! 4. fenced_lease_rejected_for_conflict_but_new_lease_accepted
//!    Fenced lease does not block a new lease for the same domain.

use tidefs_lease::*;
use tidefs_membership_epoch::{DatasetMountIdentity, EpochId, MemberId};

fn mid(v: u64) -> MemberId {
    MemberId::new(v)
}

fn inode_grant(id: u64, class: LeaseClass, ds: u64, ino: u64, epoch: u64) -> LeaseGrant {
    LeaseGrant::request(
        id,
        class,
        LeaseDomain::Inode {
            dataset_id: ds,
            ino,
        },
        mid(1),
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

// ── Scenario 1: Leader failover fences lease, rejects renewal, allows re-acquire ─

#[test]
fn leader_failover_fences_lease_and_rejects_renewal() {
    // Three-node cluster: nodes 1, 2, 3 in term 1, epoch 1.
    let mut table = LockTable::new(1, EpochId::new(1));

    // Node 1 acquires exclusive lease on (ds=1, ino=42).
    let g1 = inode_grant(100, LeaseClass::Exclusive, 1, 42, 1);
    table.apply(&RaftCommand::Grant { grant: g1 });
    assert_eq!(table.grant_count(), 1);
    let lease = table.get_grant(100).unwrap();
    assert_eq!(lease.lifecycle, LeaseLifecycle::Granted);
    assert_eq!(lease.holder_id, mid(1));

    // Simulate network partition: leader failover → term 2.
    // All active leases are fenced.
    table.leader_failover();
    assert_eq!(table.current_term(), 2);

    let fenced = table.get_grant(100).unwrap();
    assert_eq!(
        fenced.lifecycle,
        LeaseLifecycle::Fenced,
        "Node 1's lease must be fenced after leader failover"
    );

    // Node 1 attempts to renew its fenced lease — must be rejected.
    let mut g1_renew = fenced.clone();
    let result = g1_renew.renew(10_000);
    assert!(result.is_err(), "Fenced lease must reject renewal");
    match result.unwrap_err() {
        LeaseError::AlreadyTerminal { lease_id, state } => {
            assert_eq!(lease_id, 100);
            assert_eq!(state, LeaseLifecycle::Fenced);
        }
        e => panic!("expected AlreadyTerminal(Fenced), got {e:?}"),
    }

    // Node 2 can now acquire a new exclusive lease on the same domain.
    let g2 = LeaseGrant::request(
        200,
        LeaseClass::Exclusive,
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        mid(2),
        0u64,
        60_000,
        0,
        EpochId::new(1),
        DatasetMountIdentity::ZERO,
        200,
        3,
        3,
    );
    // The fenced lease (id=100) is terminal, so it should not block
    // a new lease from node 2 on the same domain.
    let conflict = table.check_conflict(
        &LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        LeaseClass::Exclusive,
    );
    assert!(
        conflict.is_none(),
        "Fenced lease should not block new lease on same domain"
    );

    table.apply(&RaftCommand::Grant { grant: g2 });
    assert_eq!(
        table.grant_count(),
        2,
        "Fenced lease remains in table; new lease added"
    );

    let new_lease = table.get_grant(200).unwrap();
    assert_eq!(new_lease.holder_id, mid(2));
    assert_eq!(new_lease.lifecycle, LeaseLifecycle::Granted);
    assert!(
        new_lease.lifecycle.is_active(),
        "Node 2's new lease must be active"
    );
}

// ── Scenario 2: Fencing gate rejects operations from stale term ──────────

#[test]
fn validate_fencing_rejects_operations_from_stale_term() {
    let mut table = LockTable::new(1, EpochId::new(1));
    let g = inode_grant(1, LeaseClass::Exclusive, 1, 42, 1);
    table.apply(&RaftCommand::Grant { grant: g });

    // After leader failover, term advances to 2.
    table.leader_failover();
    assert_eq!(table.current_term(), 2);

    // Node still holding term 1 credential cannot pass the fence gate.
    assert!(
        !table.validate_fencing(1, EpochId::new(1)),
        "Stale term 1 must fail fencing validation (current term is 2)"
    );

    // Node with current term and epoch can pass.
    assert!(
        table.validate_fencing(2, EpochId::new(1)),
        "Current term 2 + current epoch must pass fencing validation"
    );

    // Wrong epoch also fails.
    assert!(
        !table.validate_fencing(2, EpochId::new(2)),
        "Wrong epoch must fail fencing validation"
    );
}

// ── Scenario 3: Epoch advance revokes all active leases ──────────────────

#[test]
fn epoch_advance_revokes_all_active_leases() {
    // Three leases held by three different nodes in epoch 1.
    let mut proto = LeaseProtocol::new(EpochId::new(1), DatasetMountIdentity::ZERO);

    let g1 = proto
        .grant_lease(
            LeaseClass::Exclusive,
            LeaseDomain::Inode {
                dataset_id: 1,
                ino: 101,
            },
            mid(1),
            60_000,
            DatasetMountIdentity::ZERO,
        )
        .unwrap();
    let g2 = proto
        .grant_lease(
            LeaseClass::Shared,
            LeaseDomain::Inode {
                dataset_id: 1,
                ino: 102,
            },
            mid(2),
            60_000,
            DatasetMountIdentity::ZERO,
        )
        .unwrap();
    let g3 = proto
        .grant_lease(
            LeaseClass::Exclusive,
            LeaseDomain::Inode {
                dataset_id: 1,
                ino: 103,
            },
            mid(3),
            60_000,
            DatasetMountIdentity::ZERO,
        )
        .unwrap();

    assert_eq!(proto.active_count(), 3);

    // Epoch 2: all epoch-1 leases must be revoked.
    let revoked = proto.advance_epoch(EpochId::new(2)).unwrap();
    assert_eq!(
        revoked.len(),
        3,
        "All 3 active leases must be revoked on epoch advance"
    );
    assert!(revoked.contains(&g1.lease_id));
    assert!(revoked.contains(&g2.lease_id));
    assert!(revoked.contains(&g3.lease_id));
    assert_eq!(
        proto.active_count(),
        0,
        "No active leases after epoch advance"
    );

    // Verify each grant is fenced.
    for lid in &[g1.lease_id, g2.lease_id, g3.lease_id] {
        let grant = proto.get_grant(*lid).unwrap();
        assert_eq!(
            grant.lifecycle,
            LeaseLifecycle::Fenced,
            "Lease {lid} must be Fenced after epoch advance"
        );
        assert!(!proto.is_active(*lid));
    }
}

// ── Scenario 4: Fenced lease doesn't block re-acquisition ────────────────

#[test]
fn fenced_lease_does_not_block_reacquisition() {
    let mut table = LockTable::new(1, EpochId::new(1));

    // Node 1 holds exclusive lease → leader failover → fenced.
    let g1 = inode_grant(10, LeaseClass::Exclusive, 1, 42, 1);
    table.apply(&RaftCommand::Grant { grant: g1 });
    table.leader_failover();

    // Fenced lease should not block conflict check.
    let conflict = table.check_conflict(
        &LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        LeaseClass::Exclusive,
    );
    assert!(conflict.is_none());

    // Node 2 can acquire.
    let g2 = LeaseGrant::request(
        20,
        LeaseClass::Exclusive,
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        mid(2),
        0u64,
        60_000,
        0,
        EpochId::new(1),
        DatasetMountIdentity::ZERO,
        200,
        3,
        3,
    );
    table.apply(&RaftCommand::Grant { grant: g2 });
    assert_eq!(table.grant_count(), 2);
    assert!(table.get_grant(20).unwrap().lifecycle.is_active());
}

// ── Scenario 5: Expired lease through tick_all with three nodes ──────────

#[test]
fn three_node_lease_expiry_via_tick_all() {
    // Three nodes each hold a lease. Leases expire via tick_all.
    // Node 1's short-lived lease expires; other nodes' leases survive.
    let mut proto = LeaseProtocol::new(EpochId::new(1), DatasetMountIdentity::ZERO);

    // Node 1: very short lease (will expire after sleep)
    proto
        .grant_lease(
            LeaseClass::Exclusive,
            LeaseDomain::Inode {
                dataset_id: 1,
                ino: 1,
            },
            mid(1),
            1, // 1ms
            DatasetMountIdentity::ZERO,
        )
        .unwrap();

    // Node 2: long lease
    proto
        .grant_lease(
            LeaseClass::Shared,
            LeaseDomain::Inode {
                dataset_id: 1,
                ino: 2,
            },
            mid(2),
            60_000,
            DatasetMountIdentity::ZERO,
        )
        .unwrap();

    // Node 3: long lease
    proto
        .grant_lease(
            LeaseClass::Exclusive,
            LeaseDomain::Inode {
                dataset_id: 1,
                ino: 3,
            },
            mid(3),
            60_000,
            DatasetMountIdentity::ZERO,
        )
        .unwrap();

    assert_eq!(proto.active_count(), 3);

    // Wait for the 1ms lease to expire.
    std::thread::sleep(std::time::Duration::from_millis(5));

    let expired = proto.tick_all();
    assert_eq!(expired.len(), 1, "Only the 1ms lease should expire");
    assert_eq!(
        proto.active_count(),
        2,
        "Two long-lived leases should still be active"
    );

    // Node 1's expired lease cannot be renewed.
    let lid = expired[0];
    let result = proto.renew_lease(lid, mid(1), 60_000);
    assert!(result.is_err(), "Expired lease must reject renewal");
}

// ── Scenario 6: Full fencing lifecycle through LockTable API ─────────────

#[test]
fn full_fencing_lifecycle_three_nodes() {
    // Three-node scenario:
    // 1. Node 1 acquires exclusive lease on inode 42
    // 2. Node 2 acquires shared lease on inode 43
    // 3. Node 3 acquires exclusive byte-range lease on inode 44
    // 4. Leader failover (term 1 → term 2): all three leases fenced
    // 5. None of the fenced leases can be renewed
    // 6. All three domains can be re-acquired by new holders
    // 7. validate_fencing rejects operations from stale term

    let mut table = LockTable::new(1, EpochId::new(1));

    // Step 1-3: Three nodes acquire leases.
    let g1 = LeaseGrant::request(
        1,
        LeaseClass::Exclusive,
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        mid(1),
        0u64,
        60_000,
        0,
        EpochId::new(1),
        DatasetMountIdentity::ZERO,
        100,
        3,
        3,
    );
    table.apply(&RaftCommand::Grant { grant: g1 });

    let g2 = LeaseGrant::request(
        2,
        LeaseClass::Shared,
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 43,
        },
        mid(2),
        0u64,
        60_000,
        0,
        EpochId::new(1),
        DatasetMountIdentity::ZERO,
        200,
        3,
        3,
    );
    table.apply(&RaftCommand::Grant { grant: g2 });

    let g3 = LeaseGrant::request(
        3,
        LeaseClass::Exclusive,
        LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 44,
            start: 0,
            end: 4095,
        },
        mid(3),
        0u64,
        60_000,
        0,
        EpochId::new(1),
        DatasetMountIdentity::ZERO,
        300,
        3,
        3,
    );
    table.apply(&RaftCommand::Grant { grant: g3 });
    assert_eq!(table.grant_count(), 3);

    // Step 4: Leader failover fences all active leases.
    table.leader_failover();
    assert_eq!(table.current_term(), 2);

    for lid in &[1, 2, 3] {
        let grant = table.get_grant(*lid).unwrap();
        assert_eq!(
            grant.lifecycle,
            LeaseLifecycle::Fenced,
            "Lease {lid} must be fenced"
        );
    }

    // Step 5: Stale term 1 cannot pass the fence gate.
    assert!(!table.validate_fencing(1, EpochId::new(1)));
    // Current term 2 with correct epoch can pass.
    assert!(table.validate_fencing(2, EpochId::new(1)));

    // Step 6: All three domains can be re-acquired.
    let domains: Vec<LeaseDomain> = vec![
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 43,
        },
        LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 44,
            start: 0,
            end: 4095,
        },
    ];

    for (i, domain) in domains.iter().enumerate() {
        let conflict = table.check_conflict(domain, LeaseClass::Exclusive);
        assert!(
            conflict.is_none(),
            "Fenced leases should not block re-acquisition of domain {domain:?}"
        );

        let new_grant = LeaseGrant::request(
            10 + (i as u64),
            LeaseClass::Exclusive,
            domain.clone(),
            mid(10 + (i as u64)),
            0u64,
            60_000,
            0,
            EpochId::new(1),
        DatasetMountIdentity::ZERO,
            1000 + (i as u64) * 100,
            3,
            3,
        );
        table.apply(&RaftCommand::Grant { grant: new_grant });
    }

    // 3 original (fenced) + 3 new (active) = 6 total
    assert_eq!(table.grant_count(), 6);
}
