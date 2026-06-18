#[cfg(test)]
mod lease_manager_tests {
    use crate::manager::{LeaseManager, LeaseManagerConfig, LeaseManagerError};
    use crate::membership::{MembershipEvent, MembershipObserver};
    use tidefs_lease::types::{LeaseClass, LeaseDomain, LeaseLifecycle};
    use tidefs_membership_epoch::{EpochId, MemberId};

    fn m(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn epoch(id: u64) -> EpochId {
        EpochId::new(id)
    }

    fn make_manager() -> LeaseManager {
        LeaseManager::new(LeaseManagerConfig::default(), epoch(1))
    }

    fn inode_domain(dataset_id: u64, ino: u64) -> LeaseDomain {
        LeaseDomain::Inode { dataset_id, ino }
    }

    // ── Grant tests ──────────────────────────────────────────────────

    #[test]
    fn test_grant_basic() {
        let mut mgr = make_manager();
        let grant = mgr
            .grant(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(10),
                3,         // witness confirmations
                1_000_000, // now_millis
            )
            .expect("grant should succeed");

        assert_eq!(grant.lease_class, LeaseClass::Exclusive);
        assert_eq!(grant.holder_id, m(10));
        assert_eq!(grant.lifecycle, LeaseLifecycle::Granted);
        assert_eq!(mgr.grant_count(), 1);
        assert_eq!(mgr.holder_lease_count(m(10)), 1);
    }

    #[test]
    fn test_grant_insufficient_witnesses() {
        let mut mgr = make_manager();
        let result = mgr.grant(
            LeaseClass::Exclusive,
            inode_domain(1, 42),
            m(10),
            1, // only 1 confirmation, need 3
            1_000_000,
        );
        assert!(matches!(
            result,
            Err(LeaseManagerError::InsufficientWitnesses(1, 3))
        ));
    }

    #[test]
    fn test_grant_duplicate_domain_conflict() {
        let mut mgr = make_manager();
        mgr.grant(
            LeaseClass::Exclusive,
            inode_domain(1, 42),
            m(10),
            3,
            1_000_000,
        )
        .expect("first grant");

        // Second grant on same domain should conflict
        let result = mgr.grant(LeaseClass::Shared, inode_domain(1, 42), m(20), 3, 1_000_000);
        assert!(matches!(result, Err(LeaseManagerError::Conflict(_))));
    }

    #[test]
    fn test_grant_holder_capacity() {
        let config = LeaseManagerConfig {
            max_leases_per_holder: 2,
            ..LeaseManagerConfig::default()
        };

        let mut mgr = LeaseManager::new(config, epoch(1));
        mgr.grant(LeaseClass::Shared, inode_domain(1, 1), m(10), 3, 1_000_000)
            .unwrap();
        mgr.grant(LeaseClass::Shared, inode_domain(1, 2), m(10), 3, 1_000_000)
            .unwrap();

        let result = mgr.grant(LeaseClass::Shared, inode_domain(1, 3), m(10), 3, 1_000_000);
        assert!(matches!(
            result,
            Err(LeaseManagerError::HolderAtCapacity(_, 2))
        ));
    }

    // ── Renew tests ──────────────────────────────────────────────────

    #[test]
    fn test_renew_basic() {
        let mut mgr = make_manager();
        let g = mgr
            .grant(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(10),
                3,
                1_000_000,
            )
            .unwrap();

        // Renew before expiry
        let renewed = mgr.renew(g.lease_id, m(10), 1_020_000).unwrap();
        assert_eq!(renewed.version, 2);
        assert!(renewed.expires_at_millis > g.expires_at_millis);
        assert_eq!(mgr.stats().renewals_total, 1);
    }

    #[test]
    fn test_renew_wrong_holder() {
        let mut mgr = make_manager();
        let g = mgr
            .grant(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(10),
                3,
                1_000_000,
            )
            .unwrap();

        let result = mgr.renew(g.lease_id, m(99), 1_020_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_renew_not_found() {
        let mut mgr = make_manager();
        let result = mgr.renew(999, m(10), 1_000_000);
        assert!(matches!(result, Err(LeaseManagerError::NotFound(999))));
    }

    // ── Release tests ────────────────────────────────────────────────

    #[test]
    fn test_release_basic() {
        let mut mgr = make_manager();
        let g = mgr
            .grant(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(10),
                3,
                1_000_000,
            )
            .unwrap();

        mgr.release(g.lease_id, m(10)).unwrap();
        assert_eq!(mgr.grant_count(), 0);
        assert_eq!(mgr.holder_lease_count(m(10)), 0);
    }

    #[test]
    fn test_release_wrong_holder() {
        let mut mgr = make_manager();
        let g = mgr
            .grant(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(10),
                3,
                1_000_000,
            )
            .unwrap();

        let result = mgr.release(g.lease_id, m(99));
        assert!(result.is_err());
        assert_eq!(mgr.grant_count(), 1); // still held
    }

    // ── Revoke tests ─────────────────────────────────────────────────

    #[test]
    fn test_revoke_basic() {
        let mut mgr = make_manager();
        let g = mgr
            .grant(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(10),
                3,
                1_000_000,
            )
            .unwrap();

        mgr.revoke(g.lease_id).unwrap();
        let grant = mgr.get_grant(g.lease_id).unwrap();
        assert_eq!(grant.lifecycle, LeaseLifecycle::Fenced);
        assert_eq!(mgr.stats().revocations_total, 1);
    }

    #[test]
    fn test_revoke_not_found() {
        let mut mgr = make_manager();
        let result = mgr.revoke(999);
        assert!(matches!(result, Err(LeaseManagerError::NotFound(999))));
    }

    // ── Node failure tests ───────────────────────────────────────────

    #[test]
    fn test_handle_node_failure() {
        let mut mgr = make_manager();
        let g1 = mgr
            .grant(
                LeaseClass::Exclusive,
                inode_domain(1, 1),
                m(10),
                3,
                1_000_000,
            )
            .unwrap();
        let g2 = mgr
            .grant(LeaseClass::Shared, inode_domain(1, 2), m(10), 3, 1_000_000)
            .unwrap();
        let g3 = mgr
            .grant(LeaseClass::Shared, inode_domain(1, 3), m(20), 3, 1_000_000)
            .unwrap();

        let revoked = mgr.handle_node_failure(m(10));
        assert_eq!(revoked.len(), 2);
        assert!(revoked.contains(&g1.lease_id));
        assert!(revoked.contains(&g2.lease_id));

        // Node 10 leases are fenced
        assert_eq!(
            mgr.get_grant(g1.lease_id).unwrap().lifecycle,
            LeaseLifecycle::Fenced
        );
        // Node 20 lease is untouched
        assert_eq!(
            mgr.get_grant(g3.lease_id).unwrap().lifecycle,
            LeaseLifecycle::Granted
        );
        assert_eq!(mgr.stats().node_failure_revocations, 2);
    }

    // ── MembershipObserver impl tests ────────────────────────────────

    #[test]
    fn test_membership_observer_node_failed() {
        let mut mgr = make_manager();
        mgr.grant(
            LeaseClass::Exclusive,
            inode_domain(1, 1),
            m(10),
            3,
            1_000_000,
        )
        .unwrap();

        let event = MembershipEvent::NodeFailed { node_id: m(10) };
        let revoked = mgr.on_membership_event(&event);
        assert_eq!(revoked.len(), 1);
    }

    #[test]
    fn test_membership_observer_epoch_advanced() {
        let mut mgr = make_manager();
        mgr.grant(
            LeaseClass::Exclusive,
            inode_domain(1, 1),
            m(10),
            3,
            1_000_000,
        )
        .unwrap();

        let event = MembershipEvent::EpochAdvanced {
            new_epoch: epoch(5),
            old_epoch: epoch(1),
        };
        let fenced = mgr.on_membership_event(&event);
        assert_eq!(fenced.len(), 1);
        assert_eq!(mgr.current_epoch(), epoch(5));
    }

    // ── Sweep expired tests ──────────────────────────────────────────

    #[test]
    fn test_sweep_expired() {
        let mut mgr = make_manager();
        // Grant with 30s term starting at t=1_000_000
        let _g = mgr
            .grant(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(10),
                3,
                1_000_000,
            )
            .unwrap();

        // At t=1_100_000, far past term + grace + stale threshold
        let expired = mgr.sweep_expired(1_100_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(mgr.grant_count(), 0);
        assert_eq!(mgr.stats().expirations_total, 1);
    }

    #[test]
    fn test_sweep_not_expired_yet() {
        let mut mgr = make_manager();
        mgr.grant(
            LeaseClass::Exclusive,
            inode_domain(1, 42),
            m(10),
            3,
            1_000_000,
        )
        .unwrap();

        // At t=1_010_000, within term
        let expired = mgr.sweep_expired(1_010_000);
        assert_eq!(expired.len(), 0);
        assert_eq!(mgr.grant_count(), 1);
    }

    // ── Due for renewal tests ────────────────────────────────────────

    #[test]
    fn test_due_for_renewal() {
        let mut mgr = make_manager();
        mgr.grant(
            LeaseClass::Exclusive,
            inode_domain(1, 42),
            m(10),
            3,
            1_000_000,
        )
        .unwrap();

        // At 1_023_000 (past renew_by which is ~1_022_500)
        let due = mgr.due_for_renewal(1_023_000);
        assert_eq!(due.len(), 1);
    }

    // ── Epoch advance tests ──────────────────────────────────────────

    #[test]
    fn test_advance_epoch() {
        let mut mgr = make_manager();
        mgr.grant(
            LeaseClass::Exclusive,
            inode_domain(1, 42),
            m(10),
            3,
            1_000_000,
        )
        .unwrap();

        let fenced = mgr.advance_epoch(epoch(2));
        assert_eq!(fenced.len(), 1);
        assert_eq!(mgr.current_epoch(), epoch(2));
    }

    #[test]
    fn test_advance_epoch_noop_same_epoch() {
        let mut mgr = make_manager();
        mgr.grant(
            LeaseClass::Exclusive,
            inode_domain(1, 42),
            m(10),
            3,
            1_000_000,
        )
        .unwrap();

        let fenced = mgr.advance_epoch(epoch(1));
        assert_eq!(fenced.len(), 0);
    }

    // ── grant_with_id tests ──────────────────────────────────────────

    #[test]
    fn test_grant_with_id() {
        let mut mgr = make_manager();
        let grant = mgr
            .grant_with_id(
                100,
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(10),
                30_000,
                3,
                1_000_000,
            )
            .unwrap();

        assert_eq!(grant.lease_id, 100);
        assert_eq!(mgr.grant_count(), 1);
    }

    #[test]
    fn test_grant_with_id_duplicate() {
        let mut mgr = make_manager();
        mgr.grant_with_id(
            100,
            LeaseClass::Shared,
            inode_domain(1, 1),
            m(10),
            30_000,
            3,
            1_000_000,
        )
        .unwrap();

        let result = mgr.grant_with_id(
            100,
            LeaseClass::Shared,
            inode_domain(1, 2),
            m(20),
            30_000,
            3,
            1_000_000,
        );
        assert!(matches!(result, Err(LeaseManagerError::Duplicate(100))));
    }

    // ── Stats tests ──────────────────────────────────────────────────

    #[test]
    fn test_stats_tracking() {
        let mut mgr = make_manager();
        assert_eq!(mgr.stats().grants_total, 0);
        assert_eq!(mgr.stats().grants_active, 0);

        let g = mgr
            .grant(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(10),
                3,
                1_000_000,
            )
            .unwrap();
        assert_eq!(mgr.stats().grants_total, 1);
        assert_eq!(mgr.stats().grants_active, 1);

        mgr.revoke(g.lease_id).unwrap();
        assert_eq!(mgr.stats().revocations_total, 1);
        assert_eq!(mgr.stats().grants_active, 0);
    }

    #[test]
    fn test_grant_subtree_domain() {
        let mut mgr = make_manager();
        let domain = LeaseDomain::Subtree {
            dataset_id: 1,
            prefix: "/home/".into(),
        };
        let grant = mgr
            .grant(LeaseClass::Exclusive, domain, m(10), 3, 1_000_000)
            .unwrap();
        assert_eq!(mgr.grant_count(), 1);
        assert!(mgr.get_grant(grant.lease_id).is_some());
    }

    #[test]
    fn test_grant_byte_range_domain() {
        let mut mgr = make_manager();
        let domain = LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 42,
            start: 0,
            end: 4095,
        };
        let _grant = mgr
            .grant(LeaseClass::Exclusive, domain, m(10), 3, 1_000_000)
            .unwrap();
        assert_eq!(mgr.grant_count(), 1);
    }

    #[test]
    fn test_holder_leases_empty() {
        let mgr = make_manager();
        assert!(mgr.holder_leases(m(99)).is_empty());
        assert_eq!(mgr.holder_lease_count(m(99)), 0);
    }
}

// ── Protocol message integration tests ─────────────────────────

mod protocol_integration_tests {
    use crate::manager::{LeaseManager, LeaseManagerConfig};
    use tidefs_lease::types::{LeaseClass, LeaseDomain, LeaseGrant, LeaseLifecycle};
    use tidefs_lease::{LeaseMessage, LeaseProtocolError};
    use tidefs_membership_epoch::{EpochId, MemberId};

    fn m(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn epoch(id: u64) -> EpochId {
        EpochId::new(id)
    }

    fn inode_domain(dataset_id: u64, ino: u64) -> LeaseDomain {
        LeaseDomain::Inode { dataset_id, ino }
    }

    fn make_manager() -> LeaseManager {
        LeaseManager::new(LeaseManagerConfig::default(), epoch(1))
    }

    #[test]
    fn test_process_renew_message_success() {
        let mut mgr = make_manager();
        let g = mgr
            .grant(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(10),
                3,
                1_000_000,
            )
            .unwrap();

        let renew_msg = LeaseMessage::Renew {
            lease_id: g.lease_id,
            holder_id: m(10),
            epoch: epoch(1),
        };

        let response = mgr.process_message(&renew_msg, 1_020_000).unwrap();
        match response {
            LeaseMessage::Grant(renewed) => {
                assert_eq!(renewed.lease_id, g.lease_id);
                assert!(renewed.version >= 2);
                assert!(renewed.expires_at_millis > g.expires_at_millis);
            }
            _ => panic!("expected Grant response, got {response:?}"),
        }
    }

    #[test]
    fn test_process_renew_message_wrong_holder() {
        let mut mgr = make_manager();
        let g = mgr
            .grant(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(10),
                3,
                1_000_000,
            )
            .unwrap();

        let renew_msg = LeaseMessage::Renew {
            lease_id: g.lease_id,
            holder_id: m(99),
            epoch: epoch(1),
        };

        let result = mgr.process_message(&renew_msg, 1_020_000);
        assert!(matches!(
            result,
            Err(LeaseProtocolError::HolderMismatch(_, _))
        ));
    }

    #[test]
    fn test_process_renew_message_not_found() {
        let mut mgr = make_manager();
        let renew_msg = LeaseMessage::Renew {
            lease_id: 999,
            holder_id: m(10),
            epoch: epoch(1),
        };
        let result = mgr.process_message(&renew_msg, 1_000_000);
        assert!(matches!(result, Err(LeaseProtocolError::NotFound(999))));
    }

    #[test]
    fn test_process_revoke_message_success() {
        let mut mgr = make_manager();
        let g = mgr
            .grant(
                LeaseClass::Exclusive,
                inode_domain(1, 42),
                m(10),
                3,
                1_000_000,
            )
            .unwrap();

        let revoke_msg = LeaseMessage::Revoke {
            lease_id: g.lease_id,
            epoch: epoch(1),
            reason: tidefs_lease::RevokeReason::Admin,
        };

        let response = mgr.process_message(&revoke_msg, 1_000_000).unwrap();
        match response {
            LeaseMessage::Acknowledge {
                lease_id, success, ..
            } => {
                assert_eq!(lease_id, g.lease_id);
                assert!(success);
            }
            _ => panic!("expected Acknowledge response, got {response:?}"),
        }

        // Grant should now be fenced
        let grant = mgr.get_grant(g.lease_id).unwrap();
        assert_eq!(grant.lifecycle, LeaseLifecycle::Fenced);
    }

    #[test]
    fn test_process_revoke_message_not_found() {
        let mut mgr = make_manager();
        let revoke_msg = LeaseMessage::Revoke {
            lease_id: 999,
            epoch: epoch(1),
            reason: tidefs_lease::RevokeReason::Admin,
        };
        let result = mgr.process_message(&revoke_msg, 1_000_000);
        assert!(matches!(result, Err(LeaseProtocolError::NotFound(999))));
    }

    #[test]
    fn test_process_grant_message_with_id() {
        let mut mgr = make_manager();
        let grant = LeaseGrant::request(
            500,
            LeaseClass::Exclusive,
            inode_domain(1, 77),
            m(10),
            0u64,
            30_000,
            1_000_000,
            epoch(1),
            0,
            3,
            5,
        );
        let grant_msg = LeaseMessage::Grant(grant);

        let response = mgr.process_message(&grant_msg, 1_000_000).unwrap();
        match response {
            LeaseMessage::Grant(g) => {
                assert_eq!(g.lease_id, 500);
                assert_eq!(g.holder_id, m(10));
                assert_eq!(g.lifecycle, LeaseLifecycle::Granted);
            }
            _ => panic!("expected Grant response, got {response:?}"),
        }

        assert_eq!(mgr.grant_count(), 1);
        assert!(mgr.get_grant(500).is_some());
    }

    #[test]
    fn test_process_grant_duplicate_id() {
        let mut mgr = make_manager();
        let grant = LeaseGrant::request(
            100,
            LeaseClass::Exclusive,
            inode_domain(1, 1),
            m(10),
            0u64,
            30_000,
            1_000_000,
            epoch(1),
            0,
            3,
            5,
        );
        let msg = LeaseMessage::Grant(grant);

        // First grant succeeds
        mgr.process_message(&msg, 1_000_000).unwrap();
        // Second with same id fails
        let result = mgr.process_message(&msg, 1_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let grant = LeaseGrant::request(
            1,
            LeaseClass::Exclusive,
            inode_domain(1, 42),
            m(7),
            0u64,
            30_000,
            1_000_000,
            epoch(1),
            0,
            0,
            0,
        );
        let msg = LeaseMessage::Grant(grant);

        let encoded = LeaseManager::encode_message(&msg).unwrap();
        assert!(!encoded.is_empty());

        let decoded = LeaseManager::decode_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_encode_decode_renew_roundtrip() {
        let msg = LeaseMessage::Renew {
            lease_id: 42,
            holder_id: m(10),
            epoch: epoch(3),
        };
        let encoded = LeaseManager::encode_message(&msg).unwrap();
        let decoded = LeaseManager::decode_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_encode_decode_revoke_roundtrip() {
        let msg = LeaseMessage::Revoke {
            lease_id: 99,
            epoch: epoch(5),
            reason: tidefs_lease::RevokeReason::EpochAdvance,
        };
        let encoded = LeaseManager::encode_message(&msg).unwrap();
        let decoded = LeaseManager::decode_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_decode_rejects_tampered_message() {
        let msg = LeaseMessage::Renew {
            lease_id: 1,
            holder_id: m(7),
            epoch: epoch(1),
        };
        let mut encoded = LeaseManager::encode_message(&msg).unwrap();
        // Tamper with a byte in the payload
        if encoded.len() > 65 {
            encoded[65] ^= 0xFF;
        }
        let result = LeaseManager::decode_message(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_acknowledge_is_noop() {
        let mut mgr = make_manager();
        let ack = LeaseMessage::Acknowledge {
            lease_id: 1,
            success: true,
            detail: "ok".into(),
        };
        // Server should not process client acknowledgements
        let result = mgr.process_message(&ack, 1_000_000);
        assert!(result.is_err());
    }

    // ── Coherency bus integration tests ─────────────────────────────

    #[test]
    fn test_revoke_dispatches_byte_range_invalidation() {
        use std::sync::Arc;
        use tidefs_cache_coherency::CoherencyEventBus;

        // A test subscriber that records invalidation events
        struct RecordSub {
            events: std::sync::Mutex<Vec<(u64, u64, u64)>>,
        }
        impl tidefs_cache_coherency::CacheInvalidationSubscriber for RecordSub {
            fn on_invalidate_range(&self, inode: u64, start: u64, end: u64) -> usize {
                self.events.lock().unwrap().push((inode, start, end));
                1
            }
            fn on_invalidate_all(&self) -> usize {
                0
            }
            fn subscriber_name(&self) -> &'static str {
                "record-sub"
            }
        }

        let mut mgr = make_manager();
        let bus = Arc::new(CoherencyEventBus::new());
        let sub = Arc::new(RecordSub {
            events: std::sync::Mutex::new(Vec::new()),
        });
        bus.register(sub.clone());
        mgr.set_coherency_bus(bus);

        // Grant a byte-range lease
        let domain = LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 42,
            start: 0,
            end: 4096,
        };
        let grant = mgr
            .grant(LeaseClass::Exclusive, domain, m(10), 3, 1_000_000)
            .expect("grant should succeed");
        let lease_id = grant.lease_id;

        // Revoke should dispatch invalidation
        mgr.revoke(lease_id).expect("revoke should succeed");

        let events = sub.events.lock().unwrap();
        assert_eq!(events.len(), 1, "should have exactly 1 invalidation event");
        assert_eq!(events[0], (42, 0, 4096));
    }

    #[test]
    fn test_revoke_dispatches_inode_invalidation() {
        use std::sync::Arc;
        use tidefs_cache_coherency::CoherencyEventBus;

        struct RecordSub {
            inode_invals: std::sync::Mutex<Vec<u64>>,
        }
        impl tidefs_cache_coherency::CacheInvalidationSubscriber for RecordSub {
            fn on_invalidate_range(&self, _inode: u64, _start: u64, _end: u64) -> usize {
                0
            }
            fn on_invalidate_inode(&self, inode: u64) -> usize {
                self.inode_invals.lock().unwrap().push(inode);
                1
            }
            fn on_invalidate_all(&self) -> usize {
                0
            }
            fn subscriber_name(&self) -> &'static str {
                "record-sub"
            }
        }

        let mut mgr = make_manager();
        let bus = Arc::new(CoherencyEventBus::new());
        let sub = Arc::new(RecordSub {
            inode_invals: std::sync::Mutex::new(Vec::new()),
        });
        bus.register(sub.clone());
        mgr.set_coherency_bus(bus);

        // Grant an inode-level lease
        let domain = LeaseDomain::Inode {
            dataset_id: 1,
            ino: 99,
        };
        let grant = mgr
            .grant(LeaseClass::Exclusive, domain, m(10), 3, 1_000_000)
            .expect("grant should succeed");
        let lease_id = grant.lease_id;

        mgr.revoke(lease_id).expect("revoke should succeed");

        let invals = sub.inode_invals.lock().unwrap();
        assert_eq!(invals.len(), 1);
        assert_eq!(invals[0], 99);
    }

    #[test]
    fn test_revoke_without_bus_is_noop() {
        let mut mgr = make_manager();
        let domain = LeaseDomain::ByteRange {
            dataset_id: 1,
            ino: 42,
            start: 0,
            end: 4096,
        };
        let grant = mgr
            .grant(LeaseClass::Exclusive, domain, m(10), 3, 1_000_000)
            .expect("grant should succeed");

        // Revoke without a coherency bus configured — should not panic
        mgr.revoke(grant.lease_id).expect("revoke should succeed");
        // Verify revocation happened: trying to renew a revoked lease fails
        let result = mgr.renew(grant.lease_id, m(10), 2_000_000);
        assert!(result.is_err(), "renewing a revoked lease must fail");
    }
}
