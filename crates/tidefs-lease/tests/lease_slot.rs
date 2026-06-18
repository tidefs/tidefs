//! Integration tests for concurrent lease slot allocation, deallocation,
//! interval tree operations, and pending lock queue behaviour.
//!
//! Exercises LockTable for many concurrent grants, slot reuse,
//! IntervalTree insert/remove/query cycles, and pending queue FIFO
//! ordering and timeout sweep.

use tidefs_lease::*;
use tidefs_membership_epoch::{DatasetMountIdentity, EpochId, MemberId};

fn mid(v: u64) -> MemberId {
    MemberId::new(v)
}

fn make_grant(id: u64, ds: u64, ino: u64) -> LeaseGrant {
    LeaseGrant::request(
        id,
        LeaseClass::Exclusive,
        LeaseDomain::Inode {
            dataset_id: ds,
            ino,
        },
        mid(id % 10),
        0u64,
        60_000,
        id * 1_000,
        EpochId::new(1),
        DatasetMountIdentity::ZERO,
        id * 100,
        3,
        3,
    )
}

// ── Many concurrent grants on distinct domains ───────────────────────────

#[test]
fn many_concurrent_grants_distinct_domains() {
    let mut table = LockTable::new(1, EpochId::new(1));
    let n: u64 = 200;
    for i in 0..n {
        let g = make_grant(i, i / 50, i); // spread across datasets
        table.apply(&RaftCommand::Grant { grant: g });
    }
    assert_eq!(table.grant_count(), n as usize);

    // Each grant should be findable
    for i in 0..n {
        assert!(table.get_grant(i).is_some(), "grant {i} should exist");
    }
}

// ── Slot reuse cycle ─────────────────────────────────────────────────────

#[test]
fn grant_release_grant_cycle_many_times() {
    let mut table = LockTable::new(1, EpochId::new(1));
    for cycle in 0..10 {
        let g = LeaseGrant::request(
            1,
            LeaseClass::Exclusive,
            LeaseDomain::Inode {
                dataset_id: 1,
                ino: 42,
            },
            mid(cycle),
            0u64,
            60_000,
            cycle * 60_000,
            EpochId::new(1),
        DatasetMountIdentity::ZERO,
            100,
            3,
            3,
        );
        table.apply(&RaftCommand::Grant { grant: g });
        assert_eq!(table.grant_count(), 1);
        table.apply(&RaftCommand::Release { lease_id: 1 });
        assert_eq!(table.grant_count(), 0);
    }
}

// ── Interval tree: remove all, reinsert ──────────────────────────────────

#[test]
fn interval_tree_remove_all_reinsert() {
    let mut tree = IntervalTree::new();
    // Insert 10 non-overlapping ranges
    for i in 0..10u64 {
        assert!(tree
            .insert(i * 100, i * 100 + 50, i, LeaseClass::Exclusive)
            .is_ok());
    }
    assert_eq!(tree.len(), 10);

    // Remove all
    for i in 0..10u64 {
        assert!(tree.remove(i), "remove {i} should succeed");
    }
    assert_eq!(tree.len(), 0);
    assert!(tree.is_empty());

    // Reinsert different ranges
    for i in 0..5u64 {
        assert!(tree
            .insert(i * 200, i * 200 + 100, i + 100, LeaseClass::Shared)
            .is_ok());
    }
    assert_eq!(tree.len(), 5);
}

// ── Interval tree: query_overlap returns all overlapping ─────────────────

#[test]
fn interval_tree_query_overlap_multiple() {
    let mut tree = IntervalTree::new();
    // Use Shared class so overlapping ranges can coexist
    tree.insert(0, 100, 1, LeaseClass::Shared).unwrap();
    tree.insert(50, 150, 2, LeaseClass::Shared).unwrap();
    tree.insert(200, 300, 3, LeaseClass::Shared).unwrap();

    // Query covering [0, 200)
    let results = tree.query_overlap(0, 200);
    assert_eq!(results.len(), 2); // entries 1 and 2 overlap

    // Query covering only [200, 300)
    let results2 = tree.query_overlap(200, 300);
    assert_eq!(results2.len(), 1); // only entry 3

    // Query covering [500, 600) — no overlap
    let results3 = tree.query_overlap(500, 600);
    assert!(results3.is_empty());
}

// ── Interval tree: shared leases don't conflict on overlap ───────────────

#[test]
fn interval_tree_shared_shared_no_conflict() {
    let mut tree = IntervalTree::new();
    tree.insert(0, 100, 1, LeaseClass::Shared).unwrap();
    tree.insert(50, 150, 2, LeaseClass::Shared).unwrap();
    assert_eq!(tree.len(), 2);

    // Query conflict with Shared lock type: should not conflict
    let conflict = tree.query_conflict(75, 125, RangeLockType::Read);
    assert!(
        conflict.is_none(),
        "shared+shared overlapping should not conflict"
    );
}

#[test]
fn interval_tree_exclusive_shared_conflict() {
    let mut tree = IntervalTree::new();
    tree.insert(0, 100, 1, LeaseClass::Exclusive).unwrap();

    // Shared lock query on overlapping range → conflict
    let conflict = tree.query_conflict(50, 150, RangeLockType::Read);
    assert!(conflict.is_some(), "exclusive should conflict with shared");

    // Write lock query → conflict
    let conflict2 = tree.query_conflict(50, 150, RangeLockType::Write);
    assert!(conflict2.is_some());
}

// ── Pending lock queue: FIFO ordering ────────────────────────────────────

#[test]
fn pending_queue_fifo_ordering() {
    let mut table = LockTable::new(1, EpochId::new(1));
    let owner = LockOwner::new(mid(1), 100, 1);

    for i in 0..5u64 {
        let req = PendingLockRequest {
            request_id: i,
            owner,
            domain: LeaseDomain::ByteRange {
                dataset_id: 1,
                ino: 5,
                start: i * 100,
                end: i * 100 + 50,
            },
            lease_class: LeaseClass::Exclusive,
            enqueued_at_millis: i * 1000,
            timeout_millis: 60_000,
            callback_node_id: mid(1),
            callback_opaque: i,
        };
        table
            .enqueue_pending(1, 5, req)
            .expect("enqueue should succeed");
    }

    // Dequeue in FIFO order
    for i in 0..5u64 {
        let req = table.dequeue_pending(1, 5).expect("should have entry");
        assert_eq!(req.request_id, i, "FIFO order violation");
    }
    assert!(table.dequeue_pending(1, 5).is_none());
}

// ── Pending lock sweep removes timed-out entries ─────────────────────────

#[test]
fn pending_sweep_removes_timed_out() {
    let mut table = LockTable::new(1, EpochId::new(1));
    let owner = LockOwner::new(mid(1), 100, 1);

    // Enqueue entries with varying timeouts
    for i in 0..3u64 {
        let req = PendingLockRequest {
            request_id: i,
            owner,
            domain: LeaseDomain::ByteRange {
                dataset_id: 1,
                ino: 5,
                start: i * 100,
                end: i * 100 + 50,
            },
            lease_class: LeaseClass::Exclusive,
            enqueued_at_millis: 0,
            timeout_millis: (i + 1) * 10_000, // 10s, 20s, 30s
            callback_node_id: mid(1),
            callback_opaque: i,
        };
        table.enqueue_pending(1, 5, req).expect("enqueue");
    }

    // Sweep at 15_000ms: only the 10s timeout should be swept
    let timeouts = table.sweep_pending(15_000);
    assert_eq!(timeouts.len(), 1);
    assert_eq!(timeouts[0].3, 0); // callback_opaque for request_id=0

    // Sweep at 25_000ms: the 20s timeout swept
    let timeouts2 = table.sweep_pending(25_000);
    assert_eq!(timeouts2.len(), 1);
    assert_eq!(timeouts2[0].3, 1);

    // One remaining
    assert!(table.peek_pending(1, 5).is_some());

    // Sweep at 35_000ms: the 30s timeout swept
    let timeouts3 = table.sweep_pending(35_000);
    assert_eq!(timeouts3.len(), 1);
    assert_eq!(timeouts3[0].3, 2);

    assert!(table.peek_pending(1, 5).is_none());
}

// ── LockTable upgrade/downgrade cycle ─────────────────────────────────────

#[test]
fn upgrade_downgrade_preserves_grant_count() {
    let mut table = LockTable::new(1, EpochId::new(1));
    let g = LeaseGrant::request(
        1,
        LeaseClass::Shared,
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
    table.apply(&RaftCommand::Grant { grant: g });
    assert_eq!(table.grant_count(), 1);

    table.apply(&RaftCommand::Upgrade { lease_id: 1 });
    assert_eq!(table.grant_count(), 1);
    assert_eq!(
        table.get_grant(1).unwrap().lease_class,
        LeaseClass::Exclusive
    );

    table.apply(&RaftCommand::Downgrade { lease_id: 1 });
    assert_eq!(table.grant_count(), 1);
    assert_eq!(table.get_grant(1).unwrap().lease_class, LeaseClass::Shared);

    // Repeat
    table.apply(&RaftCommand::Upgrade { lease_id: 1 });
    table.apply(&RaftCommand::Downgrade { lease_id: 1 });
    assert_eq!(table.grant_count(), 1);
}

// ── Validate fencing rejects stale term/epoch ────────────────────────────

#[test]
fn validate_fencing_rejects_stale_term() {
    let table = LockTable::new(5, EpochId::new(3));
    assert!(table.validate_fencing(5, EpochId::new(3)));
    assert!(!table.validate_fencing(4, EpochId::new(3))); // stale term
    assert!(!table.validate_fencing(5, EpochId::new(2))); // stale epoch
    assert!(!table.validate_fencing(4, EpochId::new(2))); // both stale
}

// ── RaftCommand::Renew applies correctly ──────────────────────────────────

#[test]
fn raft_renew_updates_expiry_and_version() {
    let mut table = LockTable::new(1, EpochId::new(1));
    let g = LeaseGrant::request(
        1,
        LeaseClass::Shared,
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
    table.apply(&RaftCommand::Grant { grant: g });

    table.apply(&RaftCommand::Renew {
        lease_id: 1,
        new_expires_at_millis: 120_000,
        version: 2,
    });

    let grant = table.get_grant(1).unwrap();
    assert_eq!(grant.expires_at_millis, 120_000);
    assert_eq!(grant.version, 2);
    assert_eq!(grant.lifecycle, LeaseLifecycle::Granted);
    assert_eq!(grant.renew_by_millis, 105_000); // 120_000 - 15_000
}
