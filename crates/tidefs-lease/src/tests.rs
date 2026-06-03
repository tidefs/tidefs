use super::*;
use tidefs_membership_epoch::{EpochId, MemberId, ReceiptId};

// ---------------------------------------------------------------------------
// Lease domain tests
// ---------------------------------------------------------------------------

#[test]
fn test_lease_domain_subtree() {
    let d = LeaseDomain::Subtree {
        dataset_id: 42,
        prefix: "/data/project/".to_string(),
    };
    assert_eq!(
        format!("{d:?}"),
        "Subtree { dataset_id: 42, prefix: \"/data/project/\" }"
    );
    // serde round-trip
    let json = serde_json::to_string(&d).unwrap();
    let d2: LeaseDomain = serde_json::from_str(&json).unwrap();
    assert_eq!(d, d2);
}

#[test]
fn test_lease_domain_inode() {
    let d = LeaseDomain::Inode {
        dataset_id: 7,
        ino: 1000,
    };
    assert_eq!(format!("{d:?}"), "Inode { dataset_id: 7, ino: 1000 }");
    let json = serde_json::to_string(&d).unwrap();
    let d2: LeaseDomain = serde_json::from_str(&json).unwrap();
    assert_eq!(d, d2);
}

#[test]
fn test_lease_domain_byte_range() {
    let d = LeaseDomain::ByteRange {
        dataset_id: 7,
        ino: 1000,
        start: 0,
        end: 4096,
    };
    assert_eq!(
        format!("{d:?}"),
        "ByteRange { dataset_id: 7, ino: 1000, start: 0, end: 4096 }"
    );
    let json = serde_json::to_string(&d).unwrap();
    let d2: LeaseDomain = serde_json::from_str(&json).unwrap();
    assert_eq!(d, d2);
}

#[test]
fn test_lease_grant_with_subtree_domain() {
    let domain = LeaseDomain::Subtree {
        dataset_id: 1,
        prefix: "/home/".to_string(),
    };
    let grant = LeaseGrant::request(
        100,
        LeaseClass::Exclusive,
        domain,
        MemberId::new(5),
        60_000,
        1_000_000,
        EpochId::new(1),
        200,
        3,
        3,
    );
    assert_eq!(grant.lease_id, 100);
    assert_eq!(grant.lease_class, LeaseClass::Exclusive);
    assert!(!grant.is_expired(1_000_000));
}

#[test]
fn test_lease_grant_with_byte_range_domain() {
    let domain = LeaseDomain::ByteRange {
        dataset_id: 3,
        ino: 42,
        start: 0,
        end: 1024,
    };
    let grant = LeaseGrant::request(
        200,
        LeaseClass::Shared,
        domain,
        MemberId::new(2),
        120_000,
        0,
        EpochId::new(2),
        300,
        3,
        3,
    );
    assert_eq!(grant.lease_id, 200);
    assert_eq!(grant.lease_class, LeaseClass::Shared);
    assert!(grant.should_renew(100_000)); // within renew window
}

// ---------------------------------------------------------------------------
// Lock service type tests
// ---------------------------------------------------------------------------

#[test]
fn test_lease_level_serde() {
    assert_eq!(
        serde_json::to_string(&LeaseLevel::Subtree).unwrap(),
        "\"Subtree\""
    );
    assert_eq!(
        serde_json::to_string(&LeaseLevel::Inode).unwrap(),
        "\"Inode\""
    );
    assert_eq!(
        serde_json::to_string(&LeaseLevel::ByteRange).unwrap(),
        "\"ByteRange\""
    );

    let l: LeaseLevel = serde_json::from_str("\"Inode\"").unwrap();
    assert_eq!(l, LeaseLevel::Inode);
}

#[test]
fn test_range_lock_type_serde() {
    let read = RangeLockType::Read;
    let write = RangeLockType::Write;
    assert_eq!(serde_json::to_string(&read).unwrap(), "\"Read\"");
    assert_eq!(serde_json::to_string(&write).unwrap(), "\"Write\"");

    let rt: RangeLockType = serde_json::from_str("\"Write\"").unwrap();
    assert_eq!(rt, RangeLockType::Write);
}

#[test]
fn test_lock_status_serde() {
    let statuses = vec![
        LockStatus::Granted,
        LockStatus::DeniedConflict,
        LockStatus::DeniedFenced,
        LockStatus::DeniedQuota,
        LockStatus::DeniedNotLeader,
        LockStatus::Queued,
    ];
    for s in &statuses {
        let json = serde_json::to_string(s).unwrap();
        let s2: LockStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, s2);
    }
}

#[test]
fn test_lock_owner_creation_and_serde() {
    let owner = LockOwner::new(MemberId::new(10), 1234, 0xABCD);
    assert_eq!(owner.node_id, MemberId::new(10));
    assert_eq!(owner.pid, 1234);
    assert_eq!(owner.owner_key, 0xABCD);

    let json = serde_json::to_string(&owner).unwrap();
    let owner2: LockOwner = serde_json::from_str(&json).unwrap();
    assert_eq!(owner, owner2);
}

#[test]
fn test_lock_owner_debug_format() {
    let owner = LockOwner::new(MemberId::new(1), 100, 999);
    let debug = format!("{owner:?}");
    assert!(debug.contains("node_id: MemberId(1)"));
    assert!(debug.contains("pid: 100"));
    assert!(debug.contains("owner_key: 999"));
}

#[test]
fn test_lease_domain_all_variants_serde_roundtrip() {
    let domains = vec![
        LeaseDomain::EpochTransition {
            epoch_id: EpochId::new(1),
        },
        LeaseDomain::ChunkRange {
            replica_set_id: 1,
            start_chunk: 0,
            end_chunk: 10,
        },
        LeaseDomain::Snapshot { snapshot_id: 5 },
        LeaseDomain::MembershipReconfig { config_id: 3 },
        LeaseDomain::Transfer {
            receipt_id: ReceiptId::ZERO,
        },
        LeaseDomain::Subtree {
            dataset_id: 1,
            prefix: "/".to_string(),
        },
        LeaseDomain::Inode {
            dataset_id: 2,
            ino: 99,
        },
        LeaseDomain::ByteRange {
            dataset_id: 3,
            ino: 100,
            start: 0,
            end: 512,
        },
    ];

    for d in &domains {
        let json = serde_json::to_string(d).unwrap();
        let d2: LeaseDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, d2);
    }
}

// ---------------------------------------------------------------------------
// LeaseClass unit tests
// ---------------------------------------------------------------------------

#[test]
fn test_lease_class_is_exclusive() {
    assert!(LeaseClass::Exclusive.is_exclusive());
    assert!(!LeaseClass::Shared.is_exclusive());
    assert!(!LeaseClass::Staging.is_exclusive());
}

#[test]
fn test_lease_class_allows_concurrent_holders() {
    assert!(!LeaseClass::Exclusive.allows_concurrent_holders());
    assert!(LeaseClass::Shared.allows_concurrent_holders());
    assert!(!LeaseClass::Staging.allows_concurrent_holders());
}

// ---------------------------------------------------------------------------
// LeaseLifecycle unit tests
// ---------------------------------------------------------------------------

#[test]
fn test_lease_lifecycle_is_terminal() {
    assert!(!LeaseLifecycle::Requested.is_terminal());
    assert!(!LeaseLifecycle::Granted.is_terminal());
    assert!(!LeaseLifecycle::Renewing.is_terminal());
    assert!(LeaseLifecycle::Fenced.is_terminal());
    assert!(LeaseLifecycle::Released.is_terminal());
    assert!(LeaseLifecycle::Expired.is_terminal());
    assert!(LeaseLifecycle::Revoked.is_terminal());
}

#[test]
fn test_lease_lifecycle_is_active() {
    assert!(!LeaseLifecycle::Requested.is_active());
    assert!(LeaseLifecycle::Granted.is_active());
    assert!(LeaseLifecycle::Renewing.is_active());
    assert!(!LeaseLifecycle::Fenced.is_active());
    assert!(!LeaseLifecycle::Released.is_active());
    assert!(!LeaseLifecycle::Expired.is_active());
    assert!(!LeaseLifecycle::Revoked.is_active());
}

// ---------------------------------------------------------------------------
// LeaseDomain helper method tests
// ---------------------------------------------------------------------------

#[test]
fn test_lease_domain_tier_all_variants() {
    assert_eq!(
        LeaseDomain::EpochTransition {
            epoch_id: EpochId::new(1)
        }
        .tier(),
        LeaseLevel::Inode
    );
    assert_eq!(
        LeaseDomain::ChunkRange {
            replica_set_id: 1,
            start_chunk: 0,
            end_chunk: 10
        }
        .tier(),
        LeaseLevel::Inode
    );
    assert_eq!(
        LeaseDomain::Snapshot { snapshot_id: 5 }.tier(),
        LeaseLevel::Inode
    );
    assert_eq!(
        LeaseDomain::MembershipReconfig { config_id: 3 }.tier(),
        LeaseLevel::Inode
    );
    assert_eq!(
        LeaseDomain::Transfer {
            receipt_id: ReceiptId::ZERO
        }
        .tier(),
        LeaseLevel::Inode
    );
    assert_eq!(
        LeaseDomain::Subtree {
            dataset_id: 1,
            prefix: "/".into()
        }
        .tier(),
        LeaseLevel::Subtree
    );
    assert_eq!(
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42
        }
        .tier(),
        LeaseLevel::Inode
    );
    assert_eq!(
        LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 42,
            start: 0,
            end: 4096
        }
        .tier(),
        LeaseLevel::ByteRange
    );
}

#[test]
fn test_lease_domain_dataset_id() {
    assert_eq!(
        LeaseDomain::Subtree {
            dataset_id: 7,
            prefix: "/".into()
        }
        .dataset_id(),
        Some(7)
    );
    assert_eq!(
        LeaseDomain::Inode {
            dataset_id: 42,
            ino: 1
        }
        .dataset_id(),
        Some(42)
    );
    assert_eq!(
        LeaseDomain::ByteRange {
            dataset_id: 99,
            ino: 1,
            start: 0,
            end: 1
        }
        .dataset_id(),
        Some(99)
    );
    assert_eq!(
        LeaseDomain::EpochTransition {
            epoch_id: EpochId::new(1)
        }
        .dataset_id(),
        None
    );
    assert_eq!(LeaseDomain::Snapshot { snapshot_id: 5 }.dataset_id(), None);
    assert_eq!(
        LeaseDomain::ChunkRange {
            replica_set_id: 1,
            start_chunk: 0,
            end_chunk: 10
        }
        .dataset_id(),
        None
    );
    assert_eq!(
        LeaseDomain::Transfer {
            receipt_id: ReceiptId::ZERO
        }
        .dataset_id(),
        None
    );
    assert_eq!(
        LeaseDomain::MembershipReconfig { config_id: 3 }.dataset_id(),
        None
    );
}

#[test]
fn test_lease_domain_ino() {
    assert_eq!(
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42
        }
        .ino(),
        Some(42)
    );
    assert_eq!(
        LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 100,
            start: 0,
            end: 4096
        }
        .ino(),
        Some(100)
    );
    assert_eq!(
        LeaseDomain::Subtree {
            dataset_id: 1,
            prefix: "/".into()
        }
        .ino(),
        None
    );
    assert_eq!(
        LeaseDomain::EpochTransition {
            epoch_id: EpochId::new(1)
        }
        .ino(),
        None
    );
    assert_eq!(LeaseDomain::Snapshot { snapshot_id: 5 }.ino(), None);
    assert_eq!(
        LeaseDomain::Transfer {
            receipt_id: ReceiptId::ZERO
        }
        .ino(),
        None
    );
}

#[test]
fn test_lease_domain_covers_edge_cases() {
    let subtree_a = LeaseDomain::Subtree {
        dataset_id: 1,
        prefix: "/a/".into(),
    };
    let subtree_b = LeaseDomain::Subtree {
        dataset_id: 1,
        prefix: "/a/b/".into(),
    };
    let subtree_unrelated = LeaseDomain::Subtree {
        dataset_id: 1,
        prefix: "/c/".into(),
    };

    assert!(subtree_a.covers(&subtree_b));
    assert!(!subtree_b.covers(&subtree_a));
    assert!(!subtree_a.covers(&subtree_unrelated));

    let range_0_4096 = LeaseDomain::ByteRange {
        dataset_id: 1,
        ino: 10,
        start: 0,
        end: 4096,
    };
    let range_0_2048 = LeaseDomain::ByteRange {
        dataset_id: 1,
        ino: 10,
        start: 0,
        end: 2048,
    };
    let range_4096_8192 = LeaseDomain::ByteRange {
        dataset_id: 1,
        ino: 10,
        start: 4096,
        end: 8192,
    };
    let range_other_ino = LeaseDomain::ByteRange {
        dataset_id: 1,
        ino: 20,
        start: 0,
        end: 4096,
    };
    let range_other_ds = LeaseDomain::ByteRange {
        dataset_id: 2,
        ino: 10,
        start: 0,
        end: 4096,
    };

    assert!(range_0_4096.covers(&range_0_2048));
    assert!(!range_0_2048.covers(&range_0_4096));
    assert!(!range_0_4096.covers(&range_4096_8192));
    assert!(!range_0_4096.covers(&range_other_ino));
    assert!(!range_0_4096.covers(&range_other_ds));

    let inode_10 = LeaseDomain::Inode {
        dataset_id: 1,
        ino: 10,
    };
    let inode_20 = LeaseDomain::Inode {
        dataset_id: 1,
        ino: 20,
    };
    assert!(inode_10.covers(&range_0_4096));
    assert!(!inode_10.covers(&range_other_ino));
    assert!(!inode_10.covers(&inode_20));

    // Cross-level: Subtree covers Inode and ByteRange on same dataset
    assert!(subtree_a.covers(&inode_10));
    assert!(subtree_a.covers(&range_0_4096));
    assert!(!subtree_a.covers(&range_other_ds));

    // Non-hierarchical domains don't cover anything
    let epoch = LeaseDomain::EpochTransition {
        epoch_id: EpochId::new(1),
    };
    assert!(!epoch.covers(&subtree_a));
    assert!(!epoch.covers(&inode_10));
    assert!(!epoch.covers(&range_0_4096));
}

// ---------------------------------------------------------------------------
// LeaseGrant state machine tests
// ---------------------------------------------------------------------------

fn make_grant(id: u64, term_millis: u64, granted_at_millis: u64) -> LeaseGrant {
    LeaseGrant::request(
        id,
        LeaseClass::Exclusive,
        LeaseDomain::Inode {
            dataset_id: 1,
            ino: 42,
        },
        MemberId::new(1),
        term_millis,
        granted_at_millis,
        EpochId::new(1),
        id * 100,
        3,
        3,
    )
}

#[test]
fn test_lease_grant_is_expired() {
    let grant = make_grant(1, 60_000, 0);
    // expires_at = 60_000, grace = 7_500, expired at 67_500
    assert!(!grant.is_expired(60_000));
    assert!(!grant.is_expired(67_400));
    assert!(grant.is_expired(67_500));
    assert!(grant.is_expired(100_000));
}

#[test]
fn test_lease_grant_is_stale() {
    let grant = make_grant(1, 60_000, 0);
    // expires_at = 60_000, grace = 7_500, stale_threshold = 67_500 + 60_000 = 127_500
    assert!(!grant.is_stale(120_000));
    assert!(!grant.is_stale(127_400));
    assert!(grant.is_stale(127_500));
    assert!(grant.is_stale(200_000));
}

#[test]
fn test_lease_grant_should_renew() {
    let grant = make_grant(1, 60_000, 0);
    // expires_at = 60_000, renew_by = 45_000
    assert!(!grant.should_renew(30_000));
    assert!(grant.should_renew(45_000));
    assert!(grant.should_renew(50_000));
}

#[test]
fn test_lease_grant_should_renew_when_terminal() {
    let mut grant = make_grant(1, 60_000, 0);
    grant.lifecycle = LeaseLifecycle::Released;
    assert!(!grant.should_renew(50_000));
}

#[test]
fn test_lease_grant_fence() {
    let mut grant = make_grant(1, 60_000, 0);
    assert_eq!(grant.lifecycle, LeaseLifecycle::Granted);
    grant.fence().expect("fence should succeed");
    assert_eq!(grant.lifecycle, LeaseLifecycle::Fenced);
}

#[test]
fn test_lease_grant_fence_already_terminal() {
    let mut grant = make_grant(1, 60_000, 0);
    grant.lifecycle = LeaseLifecycle::Released;
    let result = grant.fence();
    assert!(result.is_err());
    match result.unwrap_err() {
        LeaseError::AlreadyTerminal { lease_id, state } => {
            assert_eq!(lease_id, 1);
            assert_eq!(state, LeaseLifecycle::Released);
        }
        _ => panic!("expected AlreadyTerminal"),
    }
}

#[test]
fn test_lease_grant_release() {
    let mut grant = make_grant(1, 60_000, 0);
    assert_eq!(grant.lifecycle, LeaseLifecycle::Granted);
    grant.release().expect("release should succeed");
    assert_eq!(grant.lifecycle, LeaseLifecycle::Released);
}

#[test]
fn test_lease_grant_release_already_terminal() {
    let mut grant = make_grant(1, 60_000, 0);
    grant.lifecycle = LeaseLifecycle::Fenced;
    let result = grant.release();
    assert!(result.is_err());
    match result.unwrap_err() {
        LeaseError::AlreadyTerminal { lease_id, state } => {
            assert_eq!(lease_id, 1);
            assert_eq!(state, LeaseLifecycle::Fenced);
        }
        _ => panic!("expected AlreadyTerminal"),
    }
}

#[test]
fn test_lease_grant_renew() {
    let mut grant = make_grant(1, 60_000, 0);
    // expires_at = 60_000, renew before expiry
    grant.renew(30_000).expect("renew should succeed");
    assert_eq!(grant.lifecycle, LeaseLifecycle::Renewing);
    assert_eq!(grant.version, 2);
    assert_eq!(grant.granted_at_millis, 30_000);
    assert_eq!(grant.expires_at_millis, 90_000);
    assert_eq!(grant.renew_by_millis, 75_000);
}

#[test]
fn test_lease_grant_renew_already_terminal() {
    let mut grant = make_grant(1, 60_000, 0);
    grant.lifecycle = LeaseLifecycle::Fenced;
    let result = grant.renew(30_000);
    assert!(result.is_err());
    match result.unwrap_err() {
        LeaseError::AlreadyTerminal { lease_id, state } => {
            assert_eq!(lease_id, 1);
            assert_eq!(state, LeaseLifecycle::Fenced);
        }
        _ => panic!("expected AlreadyTerminal"),
    }
}

#[test]
fn test_lease_grant_renew_expired() {
    let mut grant = make_grant(1, 60_000, 0);
    // expires_at = 60_000, grace = 7_500, so expired at 67_500
    let result = grant.renew(70_000);
    assert!(result.is_err());
    match result.unwrap_err() {
        LeaseError::Expired { lease_id } => {
            assert_eq!(lease_id, 1);
        }
        _ => panic!("expected Expired"),
    }
}

// ---------------------------------------------------------------------------
// subtree_prefix_is_descendant edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_subtree_prefix_is_descendant_edge_cases() {
    // Root covers everything
    assert!(subtree_prefix_is_descendant("/", "/a/b/"));
    assert!(subtree_prefix_is_descendant("/", "/"));
    assert!(subtree_prefix_is_descendant("/", "/anything/"));

    // Direct descendant
    assert!(subtree_prefix_is_descendant("/a/", "/a/b/"));
    assert!(subtree_prefix_is_descendant("/a/b/", "/a/b/c/"));

    // Self (starts_with)
    assert!(subtree_prefix_is_descendant("/a/", "/a/"));

    // Siblings don't match
    assert!(!subtree_prefix_is_descendant("/a/", "/b/"));
    assert!(!subtree_prefix_is_descendant("/a/b/", "/a/c/"));

    // Partial prefix match without trailing separator
    assert!(!subtree_prefix_is_descendant("/a/", "/ab/"));

    // Deeper ancestor
    assert!(subtree_prefix_is_descendant("/a/b/", "/a/b/c/d/"));
    assert!(!subtree_prefix_is_descendant("/a/b/c/", "/a/b/"));
}

#[test]
fn test_subtree_overlap_fn() {
    assert!(subtree_overlap("/a/", "/a/b/"));
    assert!(subtree_overlap("/a/b/", "/a/"));
    assert!(!subtree_overlap("/a/", "/b/"));
    assert!(subtree_overlap("/", "/anything/"));
    assert!(subtree_overlap("/", "/"));
}

// ---------------------------------------------------------------------------
// LockMethod comprehensive tests
// ---------------------------------------------------------------------------

#[test]
fn test_lock_method_from_u8_all_valid() {
    // Test all 18 valid values
    for v in 0x00u8..=0x11u8 {
        let method = LockMethod::from_u8(v);
        assert!(method.is_some(), "value {v:#04x} should be valid");
        assert_eq!(method.unwrap().to_u8(), v);
    }
}

#[test]
fn test_lock_method_from_u8_invalid() {
    assert_eq!(LockMethod::from_u8(0x12), None);
    assert_eq!(LockMethod::from_u8(0x80), None);
    assert_eq!(LockMethod::from_u8(0xFE), None);
    assert_eq!(LockMethod::from_u8(0xFF), None);
}

#[test]
fn test_lock_method_service_id() {
    assert_eq!(LockMethod::SERVICE_ID, 0x0A);
    assert_eq!(LockMethod::Getlk.to_u8(), 0x0A);
}
