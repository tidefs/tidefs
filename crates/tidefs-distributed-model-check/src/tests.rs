// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! Bounded model-check tests for distributed safety invariants.
//!
//! Each test constructs a small distributed system, injects a specific
//! scenario (stale epoch, duplicate writer, false quorum, rebuild race),
//! steps the model, and asserts on expected invariant violations.

#[cfg(test)]
mod bounded_model_tests {
    use crate::{
        DistributedSystem, CommittedObjectWrite,
        network::{DeliveryPolicy, DistributedMessage, MessageKind},
        lease::LeaseOutcome,
        quorum::{QuorumWriteRequest, QuorumWriteOutcome},
        placement::{PlacementReceiptState, RebuildPolicy},
    };

    // ── helper ──────────────────────────────────────────────────────────

    fn three_node_system() -> DistributedSystem {
        let mut sys = DistributedSystem::new(3);
        // Advance all nodes to epoch 1.
        for node_id in 0..3 {
            sys.nodes[node_id as usize].current_epoch = 1;
            sys.epoch_model.record_advance(node_id, 1);
        }
        sys
    }

    // ── I-1: no conflicting committed writers ──────────────────────────

    #[test]
    fn no_conflict_when_different_objects() {
        let mut sys = three_node_system();
        sys.nodes[0].committed_object_writes.push(CommittedObjectWrite {
            object_key: "obj/a".into(), epoch: 1,
            writer_node_id: 0, write_id: 1, placement_receipt_id: 1,
        });
        sys.nodes[1].committed_object_writes.push(CommittedObjectWrite {
            object_key: "obj/b".into(), epoch: 1,
            writer_node_id: 1, write_id: 2, placement_receipt_id: 2,
        });
        let violations = sys.step();
        let conflicts: Vec<_> = violations.iter()
            .filter(|v| v.invariant == "no_conflicting_committed_writers")
            .collect();
        assert!(conflicts.is_empty(), "different objects should not conflict");
    }

    #[test]
    fn conflict_detected_same_object_same_epoch() {
        let mut sys = three_node_system();
        sys.nodes[0].committed_object_writes.push(CommittedObjectWrite {
            object_key: "obj/x".into(), epoch: 1,
            writer_node_id: 0, write_id: 10, placement_receipt_id: 10,
        });
        sys.nodes[1].committed_object_writes.push(CommittedObjectWrite {
            object_key: "obj/x".into(), epoch: 1,
            writer_node_id: 1, write_id: 11, placement_receipt_id: 11,
        });
        let violations = sys.step();
        let conflicts: Vec<_> = violations.iter()
            .filter(|v| v.invariant == "no_conflicting_committed_writers")
            .collect();
        assert!(!conflicts.is_empty(), "same object/epoch with different writers must conflict");
    }

    #[test]
    fn no_conflict_same_object_different_epoch() {
        let mut sys = three_node_system();
        sys.nodes[0].committed_object_writes.push(CommittedObjectWrite {
            object_key: "obj/y".into(), epoch: 1,
            writer_node_id: 0, write_id: 20, placement_receipt_id: 20,
        });
        sys.nodes[1].committed_object_writes.push(CommittedObjectWrite {
            object_key: "obj/y".into(), epoch: 2,
            writer_node_id: 1, write_id: 21, placement_receipt_id: 21,
        });
        let violations = sys.step();
        let conflicts: Vec<_> = violations.iter()
            .filter(|v| v.invariant == "no_conflicting_committed_writers")
            .collect();
        assert!(conflicts.is_empty(), "different epochs on same object should not conflict");
    }

    // ── I-2: no stale-epoch commit ─────────────────────────────────────

    #[test]
    fn stale_epoch_commit_violation_detected() {
        let mut sys = three_node_system();
        // Node 0 advances to epoch 2.
        sys.nodes[0].current_epoch = 2;
        sys.epoch_model.record_advance(0, 2);
        // But has a committed write at epoch 1 (stale).
        sys.nodes[0].committed_object_writes.push(CommittedObjectWrite {
            object_key: "obj/s".into(), epoch: 1,
            writer_node_id: 0, write_id: 30, placement_receipt_id: 30,
        });
        let violations = sys.step();
        let stale: Vec<_> = violations.iter()
            .filter(|v| v.invariant == "no_stale_epoch_commit")
            .collect();
        assert!(!stale.is_empty(), "stale-epoch commit must be detected");
    }

    #[test]
    fn fresh_epoch_commit_no_violation() {
        let mut sys = three_node_system();
        sys.nodes[0].current_epoch = 1;
        sys.nodes[0].committed_object_writes.push(CommittedObjectWrite {
            object_key: "obj/f".into(), epoch: 1,
            writer_node_id: 0, write_id: 31, placement_receipt_id: 31,
        });
        let violations = sys.step();
        let stale: Vec<_> = violations.iter()
            .filter(|v| v.invariant == "no_stale_epoch_commit")
            .collect();
        assert!(stale.is_empty(), "fresh epoch commit must not be flagged");
    }

    // ── I-3: no false quorum success ───────────────────────────────────

    #[test]
    fn false_quorum_success_violation_detected() {
        let mut sys = three_node_system();
        sys.nodes[0].quorum_writes.push(crate::quorum::QuorumWriteState {
            write_id: 40, object_key: "obj/q".into(),
            coordinator: 0, participants: vec![0, 1, 2],
            epoch: 1, phase: crate::quorum::QuorumPhase::Committed,
            acks_received: 1, // only 1 ack, but quorum_size = 2
            quorum_size: 2, committed: true,
        });
        let violations = sys.step();
        let false_q: Vec<_> = violations.iter()
            .filter(|v| v.invariant == "no_false_quorum_success")
            .collect();
        assert!(!false_q.is_empty(), "false quorum success must be detected");
    }

    #[test]
    fn valid_quorum_success_no_violation() {
        let mut sys = three_node_system();
        sys.nodes[0].quorum_writes.push(crate::quorum::QuorumWriteState {
            write_id: 41, object_key: "obj/vq".into(),
            coordinator: 0, participants: vec![0, 1, 2],
            epoch: 1, phase: crate::quorum::QuorumPhase::Committed,
            acks_received: 2, // 2 acks >= quorum_size 2
            quorum_size: 2, committed: true,
        });
        let violations = sys.step();
        let false_q: Vec<_> = violations.iter()
            .filter(|v| v.invariant == "no_false_quorum_success")
            .collect();
        assert!(false_q.is_empty(), "valid quorum must not be flagged");
    }

    // ── I-4: no rebuild before receipt ─────────────────────────────────

    #[test]
    fn rebuild_without_receipt_is_refused() {
        let mut sys = three_node_system();
        sys.placement_model.policy = RebuildPolicy::RequireDurableReceipt;
        // No receipt recorded — rebuild must be refused.
        let allowed = sys.placement_model.try_rebuild("obj/r", 0, 1);
        assert!(!allowed, "rebuild without receipt must be refused");
        let violations = sys.step();
        let no_receipt: Vec<_> = violations.iter()
            .filter(|v| v.invariant == "no_rebuild_before_receipt")
            .collect();
        // No violation because the system correctly refused the rebuild.
        assert!(no_receipt.is_empty(), "refused rebuild must not be a violation");
    }

    #[test]
    fn rebuild_with_receipt_is_allowed() {
        let mut sys = three_node_system();
        sys.placement_model.policy = RebuildPolicy::RequireDurableReceipt;
        sys.placement_model.record_receipt(PlacementReceiptState {
            receipt_id: 1, object_key: "obj/rr".into(),
            node_id: 0, epoch: 1, durable: true,
        });
        sys.placement_model.try_rebuild("obj/rr", 0, 1);
        let violations = sys.step();
        let no_receipt: Vec<_> = violations.iter()
            .filter(|v| v.invariant == "no_rebuild_before_receipt")
            .collect();
        assert!(no_receipt.is_empty(), "rebuild with receipt must be allowed");
    }

    // ── lease model tests ──────────────────────────────────────────────

    #[test]
    fn lease_grant_and_revoke() {
        let mut model = crate::LeaseModel::new();
        let outcome = model.try_grant(1, "obj/l1", 0, 1, 1);
        assert_eq!(outcome, LeaseOutcome::Granted { lease_id: 1 });
        assert_eq!(model.leases.len(), 1);

        let outcome = model.revoke(1);
        assert_eq!(outcome, LeaseOutcome::Revoked { lease_id: 1 });
        assert!(model.leases[0].revoked);
    }

    #[test]
    fn lease_conflict_same_object() {
        let mut model = crate::LeaseModel::new();
        assert_eq!(model.try_grant(1, "obj/lc", 0, 1, 1), LeaseOutcome::Granted { lease_id: 1 });
        let outcome = model.try_grant(2, "obj/lc", 1, 1, 1);
        assert!(matches!(outcome, LeaseOutcome::Conflict { .. }));
    }

    #[test]
    fn lease_stale_epoch() {
        let mut model = crate::LeaseModel::new();
        let outcome = model.try_grant(1, "obj/ls", 0, 1, 2); // request_epoch 1 < current_epoch 2
        assert!(matches!(outcome, LeaseOutcome::StaleEpoch { .. }));
    }

    // ── quorum write model tests ───────────────────────────────────────

    #[test]
    fn quorum_write_refused_stale_epoch() {
        let mut model = crate::QuorumWriteModel::new();
        let req = QuorumWriteRequest {
            write_id: 1, object_key: "obj/qse".into(),
            coordinator: 0, participants: vec![0, 1, 2],
            epoch: 1, data_size: 64,
        };
        let leases = vec![crate::LeaseState {
            lease_id: 1, object_key: "obj/qse".into(),
            holder: 0, epoch: 1, granted: true, revoked: false,
        }];
        let outcome = model.submit(req, 2, &leases, &[(0, 2), (1, 2), (2, 2)]);
        assert!(matches!(outcome, QuorumWriteOutcome::RefusedStaleEpoch { .. }));
    }

    #[test]
    fn quorum_write_refused_no_lease() {
        let mut model = crate::QuorumWriteModel::new();
        let req = QuorumWriteRequest {
            write_id: 2, object_key: "obj/qnl".into(),
            coordinator: 0, participants: vec![0, 1, 2],
            epoch: 1, data_size: 64,
        };
        let outcome = model.submit(req, 1, &[], &[(0, 1), (1, 1), (2, 1)]);
        assert!(matches!(outcome, QuorumWriteOutcome::RefusedLeaseConflict { .. }));
    }

    #[test]
    fn quorum_write_committed_with_quorum() {
        let mut model = crate::QuorumWriteModel::new();
        let req = QuorumWriteRequest {
            write_id: 3, object_key: "obj/qok".into(),
            coordinator: 0, participants: vec![0, 1, 2],
            epoch: 1, data_size: 64,
        };
        let leases = vec![crate::LeaseState {
            lease_id: 1, object_key: "obj/qok".into(),
            holder: 0, epoch: 1, granted: true, revoked: false,
        }];
        let outcome = model.submit(req, 1, &leases, &[(0, 1), (1, 1), (2, 1)]);
        assert!(matches!(outcome, QuorumWriteOutcome::Committed { .. }));
        assert!(model.is_committed(3));
    }

    #[test]
    fn quorum_write_refused_no_quorum() {
        let mut model = crate::QuorumWriteModel::new();
        let req = QuorumWriteRequest {
            write_id: 4, object_key: "obj/qnq".into(),
            coordinator: 0, participants: vec![0, 1, 2],
            epoch: 1, data_size: 64,
        };
        let leases = vec![crate::LeaseState {
            lease_id: 1, object_key: "obj/qnq".into(),
            holder: 0, epoch: 1, granted: true, revoked: false,
        }];
        // Only 1 participant (node 0) at epoch 1, nodes 1 and 2 lag behind.
        let outcome = model.submit(req, 1, &leases, &[(0, 1), (1, 0), (2, 0)]);
        assert!(matches!(outcome, QuorumWriteOutcome::RefusedNoQuorum { .. }));
    }

    // ── network model tests ────────────────────────────────────────────

    #[test]
    fn network_drop_policy() {
        let mut sys = DistributedSystem::new(2);
        sys.network.enqueue(
            DistributedMessage {
                from: 0, to: 1,
                kind: MessageKind::EpochAdvance { new_epoch: 2 },
                epoch: 2,
            },
            DeliveryPolicy::Drop,
        );
        assert!(sys.network.is_empty());
    }

    #[test]
    fn network_delay_policy() {
        let mut sys = DistributedSystem::new(2);
        sys.network.enqueue(
            DistributedMessage {
                from: 0, to: 1,
                kind: MessageKind::EpochAdvance { new_epoch: 2 },
                epoch: 2,
            },
            DeliveryPolicy::Delay,
        );
        // After one step, delayed messages are promoted.
        let _ = sys.step();
        assert!(!sys.network.is_empty() || sys.nodes[1].current_epoch == 2);
    }

    #[test]
    fn network_duplicate_policy() {
        let mut sys = DistributedSystem::new(2);
        sys.network.enqueue(
            DistributedMessage {
                from: 0, to: 1,
                kind: MessageKind::EpochAdvance { new_epoch: 3 },
                epoch: 3,
            },
            DeliveryPolicy::Duplicate,
        );
        assert_eq!(sys.network.queued_count(), 2);
    }

    // ── epoch model tests ──────────────────────────────────────────────

    #[test]
    fn epoch_advancement_tracks_members() {
        let mut sys = DistributedSystem::new(3);
        sys.epoch_model.record_advance(0, 2);
        sys.epoch_model.record_advance(1, 2);
        assert_eq!(sys.epoch_model.epoch_of(0), 2);
        assert_eq!(sys.epoch_model.epoch_of(1), 2);
        assert_eq!(sys.epoch_model.epoch_of(2), 0);
        assert_eq!(sys.epoch_model.lagging_nodes(2), vec![2]);
        assert_eq!(sys.epoch_model.members_at(2).len(), 2);
    }

    // ── placement model tests ──────────────────────────────────────────

    #[test]
    fn placement_model_tracks_receipts() {
        let mut model = crate::PlacementModel::new(3);
        assert!(!model.has_durable_receipt("obj/p1"));
        model.record_receipt(PlacementReceiptState {
            receipt_id: 1, object_key: "obj/p1".into(),
            node_id: 0, epoch: 1, durable: true,
        });
        assert!(model.has_durable_receipt("obj/p1"));
        assert_eq!(model.object_placements.get("obj/p1").unwrap().len(), 1);
    }
}
