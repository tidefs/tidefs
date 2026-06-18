//! Integration tests for lease conflict detection semantics.
//!
//! Exercises LockTable::check_conflict across domain types and lease classes:
//! shared-vs-shared non-conflict, exclusive-vs-shared conflict, byte-range
//! precision, subtree/inode hierarchy, and terminal-lease exclusion from
//! conflict checks.

use tidefs_lease::*;
use tidefs_membership_epoch::{EpochId, MemberId};

fn mid(v: u64) -> MemberId {
    MemberId::new(v)
}

fn inode_grant(id: u64, class: LeaseClass, ds: u64, ino: u64) -> LeaseGrant {
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
        EpochId::new(1),
        id * 100,
        3,
        3,
    )
}

fn byte_range_grant(
    id: u64,
    class: LeaseClass,
    ds: u64,
    ino: u64,
    start: u64,
    end: u64,
) -> LeaseGrant {
    LeaseGrant::request(
        id,
        class,
        LeaseDomain::ByteRange {
            dataset_id: ds,
            ino,
            start,
            end,
        },
        mid(1),
        0u64,
        60_000,
        0,
        EpochId::new(1),
        id * 100,
        3,
        3,
    )
}

fn subtree_grant(id: u64, class: LeaseClass, ds: u64, prefix: &str) -> LeaseGrant {
    LeaseGrant::request(
        id,
        class,
        LeaseDomain::Subtree {
            dataset_id: ds,
            prefix: prefix.to_string(),
        },
        mid(1),
        0u64,
        60_000,
        0,
        EpochId::new(1),
        id * 100,
        3,
        3,
    )
}

// ── Shared + Shared on same domain: no conflict ──────────────────────────

#[test]
fn shared_shared_inode_no_conflict() {
    let mut table = LockTable::new(1, EpochId::new(1));
    table.apply(&RaftCommand::Grant {
        grant: inode_grant(1, LeaseClass::Shared, 1, 42),
    });

    let conflict = table.check_conflict(
        &LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        LeaseClass::Shared,
    );
    assert!(
        conflict.is_none(),
        "two shared leases on same inode should not conflict"
    );
}

#[test]
fn shared_shared_byte_range_overlapping_no_conflict() {
    let mut table = LockTable::new(1, EpochId::new(1));
    table.apply(&RaftCommand::Grant {
        grant: byte_range_grant(1, LeaseClass::Shared, 1, 100, 0, 4096),
    });

    let conflict = table.check_conflict(
        &LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 100,
            start: 0,
            end: 2048,
        },
        LeaseClass::Shared,
    );
    assert!(
        conflict.is_none(),
        "overlapping shared byte ranges should not conflict"
    );
}

// ── Exclusive blocks shared on same domain ───────────────────────────────

#[test]
fn exclusive_blocks_shared_inode() {
    let mut table = LockTable::new(1, EpochId::new(1));
    table.apply(&RaftCommand::Grant {
        grant: inode_grant(1, LeaseClass::Exclusive, 1, 42),
    });

    let conflict = table.check_conflict(
        &LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        LeaseClass::Shared,
    );
    assert!(
        conflict.is_some(),
        "exclusive should block shared on same inode"
    );
}

#[test]
fn shared_does_not_block_exclusive_on_different_inode() {
    let mut table = LockTable::new(1, EpochId::new(1));
    table.apply(&RaftCommand::Grant {
        grant: inode_grant(1, LeaseClass::Shared, 1, 42),
    });

    let conflict = table.check_conflict(
        &LeaseDomain::Inode {
            dataset_id: 1,
            ino: 99,
        },
        LeaseClass::Exclusive,
    );
    assert!(
        conflict.is_none(),
        "shared on inode 42 should not block exclusive on inode 99"
    );
}

// ── Byte-range precision: non-overlapping → no conflict ──────────────────

#[test]
fn byte_range_non_overlapping_no_conflict() {
    let mut table = LockTable::new(1, EpochId::new(1));
    table.apply(&RaftCommand::Grant {
        grant: byte_range_grant(1, LeaseClass::Exclusive, 1, 100, 0, 4095),
    });

    // Adjacent range (4096-8191) does not overlap
    let conflict = table.check_conflict(
        &LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 100,
            start: 4096,
            end: 8191,
        },
        LeaseClass::Shared,
    );
    assert!(
        conflict.is_none(),
        "adjacent byte ranges should not conflict"
    );

    // Overlapping range does conflict
    let conflict2 = table.check_conflict(
        &LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 100,
            start: 2048,
            end: 6143,
        },
        LeaseClass::Shared,
    );
    assert!(
        conflict2.is_some(),
        "overlapping byte ranges should conflict"
    );
}

// ── Subtree hierarchy conflicts ──────────────────────────────────────────

#[test]
fn subtree_exclusive_blocks_child_inode() {
    let mut table = LockTable::new(1, EpochId::new(1));
    table.apply(&RaftCommand::Grant {
        grant: subtree_grant(1, LeaseClass::Exclusive, 1, "/data/"),
    });

    let conflict = table.check_conflict(
        &LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        LeaseClass::Shared,
    );
    assert!(
        conflict.is_some(),
        "exclusive subtree should block inode in same dataset"
    );
}

#[test]
fn subtree_exclusive_blocks_child_byte_range() {
    let mut table = LockTable::new(1, EpochId::new(1));
    table.apply(&RaftCommand::Grant {
        grant: subtree_grant(1, LeaseClass::Exclusive, 1, "/data/"),
    });

    let conflict = table.check_conflict(
        &LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 42,
            start: 0,
            end: 4096,
        },
        LeaseClass::Shared,
    );
    assert!(
        conflict.is_some(),
        "exclusive subtree should block byte range in same dataset"
    );
}

// ── Inode covers byte-range conflict ─────────────────────────────────────

#[test]
fn inode_exclusive_blocks_byte_range() {
    let mut table = LockTable::new(1, EpochId::new(1));
    table.apply(&RaftCommand::Grant {
        grant: inode_grant(1, LeaseClass::Exclusive, 1, 100),
    });

    let conflict = table.check_conflict(
        &LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 100,
            start: 0,
            end: 4096,
        },
        LeaseClass::Shared,
    );
    assert!(
        conflict.is_some(),
        "exclusive inode should block byte range on same inode"
    );
}

// ── Terminal leases are ignored in conflict detection ────────────────────

#[test]
fn expired_lease_ignored_in_conflict() {
    let mut table = LockTable::new(1, EpochId::new(1));
    let mut g = inode_grant(1, LeaseClass::Exclusive, 1, 42);
    g.lifecycle = LeaseLifecycle::Expired;
    table.apply(&RaftCommand::Grant { grant: g });

    let conflict = table.check_conflict(
        &LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        LeaseClass::Shared,
    );
    assert!(
        conflict.is_none(),
        "expired lease should not cause conflict"
    );
}

#[test]
fn fenced_lease_ignored_in_conflict() {
    let mut table = LockTable::new(1, EpochId::new(1));
    let mut g = inode_grant(1, LeaseClass::Exclusive, 1, 42);
    g.lifecycle = LeaseLifecycle::Fenced;
    table.apply(&RaftCommand::Grant { grant: g });

    let conflict = table.check_conflict(
        &LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        LeaseClass::Shared,
    );
    assert!(conflict.is_none(), "fenced lease should not cause conflict");
}

// ── Different datasets never conflict ────────────────────────────────────

#[test]
fn different_dataset_no_conflict() {
    let mut table = LockTable::new(1, EpochId::new(1));
    table.apply(&RaftCommand::Grant {
        grant: inode_grant(1, LeaseClass::Exclusive, 1, 42),
    });

    let conflict = table.check_conflict(
        &LeaseDomain::Inode {
            dataset_id: 2,
            ino: 42,
        },
        LeaseClass::Shared,
    );
    assert!(
        conflict.is_none(),
        "different datasets should never conflict"
    );
}
