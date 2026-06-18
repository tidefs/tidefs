// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! Bounded model-check tests for distributed safety invariants.
//!
//! Each test constructs a small distributed system, injects a specific
//! scenario (stale epoch, duplicate writer, false quorum, rebuild race),
//! steps the model, and asserts on expected invariant violations.

#[cfg(test)]
mod bounded_model_tests {
    use crate::{
        lease::LeaseOutcome,
        network::{DeliveryPolicy, DistributedMessage, MessageKind},
        placement::{model_placement_receipt_ref, PlacementReceiptState, RebuildPolicy},
        quorum::{QuorumWriteOutcome, QuorumWriteRequest},
        CommittedObjectWrite, DistributedSafetyReceipt, DistributedSafetyReceiptError,
        DistributedSystem, LeaseState,
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

    /// Build a minimal placement receipt ref for a test object.
    fn test_receipt_ref(
        object_id: u64,
        object_key_str: &str,
        epoch: u64,
    ) -> crate::placement::PlacementReceiptRef {
        model_placement_receipt_ref(object_id, object_key_str, epoch)
    }

    fn passing_receipt_system() -> DistributedSystem {
        let mut sys = three_node_system();
        let lease = LeaseState {
            lease_id: 1,
            object_key: "obj/report".into(),
            holder: 0,
            epoch: 1,
            granted: true,
            revoked: false,
        };
        sys.lease_model.leases.push(lease.clone());
        sys.nodes[0].lease_grants.push(lease.clone());

        let req = QuorumWriteRequest {
            write_id: 11,
            object_key: "obj/report".into(),
            coordinator: 0,
            participants: vec![0, 1, 2],
            epoch: 1,
            data_size: 4096,
        };
        let leases = vec![lease];
        let outcome = sys
            .quorum_model
            .submit(req, 1, &leases, &[(0, 1), (1, 1), (2, 1)]);
        assert!(matches!(outcome, QuorumWriteOutcome::Committed { .. }));

        sys.placement_model
            .record_receipt(PlacementReceiptState::for_model(
                11,
                "obj/report",
                0,
                1,
                true,
            ));
        assert!(sys.placement_model.try_rebuild("obj/report", 1, 1));

        let violations = sys.step_n(2);
        assert!(
            violations.is_empty(),
            "passing receipt system must be clean"
        );
        sys
    }

    // ── I-1: no conflicting committed writers ──────────────────────────

    #[test]
    fn no_conflict_when_different_objects() {
        let mut sys = three_node_system();
        sys.nodes[0]
            .committed_object_writes
            .push(CommittedObjectWrite {
                object_key: "obj/a".into(),
                epoch: 1,
                writer_node_id: 0,
                write_id: 1,
                placement_receipt_ref: test_receipt_ref(1, "obj/a", 1),
            });
        sys.nodes[1]
            .committed_object_writes
            .push(CommittedObjectWrite {
                object_key: "obj/b".into(),
                epoch: 1,
                writer_node_id: 1,
                write_id: 2,
                placement_receipt_ref: test_receipt_ref(2, "obj/b", 1),
            });
        let violations = sys.step();
        let conflicts: Vec<_> = violations
            .iter()
            .filter(|v| v.invariant == "no_conflicting_committed_writers")
            .collect();
        assert!(
            conflicts.is_empty(),
            "different objects should not conflict"
        );
    }

    #[test]
    fn conflict_detected_same_object_same_epoch() {
        let mut sys = three_node_system();
        sys.nodes[0]
            .committed_object_writes
            .push(CommittedObjectWrite {
                object_key: "obj/x".into(),
                epoch: 1,
                writer_node_id: 0,
                write_id: 10,
                placement_receipt_ref: test_receipt_ref(10, "obj/x", 1),
            });
        sys.nodes[1]
            .committed_object_writes
            .push(CommittedObjectWrite {
                object_key: "obj/x".into(),
                epoch: 1,
                writer_node_id: 1,
                write_id: 11,
                placement_receipt_ref: test_receipt_ref(11, "obj/x", 1),
            });
        let violations = sys.step();
        let conflicts: Vec<_> = violations
            .iter()
            .filter(|v| v.invariant == "no_conflicting_committed_writers")
            .collect();
        assert!(
            !conflicts.is_empty(),
            "same object/epoch with different writers must conflict"
        );
    }

    #[test]
    fn no_conflict_same_object_different_epoch() {
        let mut sys = three_node_system();
        sys.nodes[0]
            .committed_object_writes
            .push(CommittedObjectWrite {
                object_key: "obj/y".into(),
                epoch: 1,
                writer_node_id: 0,
                write_id: 20,
                placement_receipt_ref: test_receipt_ref(20, "obj/y", 1),
            });
        sys.nodes[1]
            .committed_object_writes
            .push(CommittedObjectWrite {
                object_key: "obj/y".into(),
                epoch: 2,
                writer_node_id: 1,
                write_id: 21,
                placement_receipt_ref: test_receipt_ref(21, "obj/y", 2),
            });
        let violations = sys.step();
        let conflicts: Vec<_> = violations
            .iter()
            .filter(|v| v.invariant == "no_conflicting_committed_writers")
            .collect();
        assert!(
            conflicts.is_empty(),
            "different epochs on same object should not conflict"
        );
    }

    // ── I-2: no stale-epoch commit ─────────────────────────────────────

    #[test]
    fn stale_epoch_commit_violation_detected() {
        let mut sys = three_node_system();
        // Node 0 advances to epoch 2.
        sys.nodes[0].current_epoch = 2;
        sys.epoch_model.record_advance(0, 2);
        // But has a committed write at epoch 1 (stale).
        sys.nodes[0]
            .committed_object_writes
            .push(CommittedObjectWrite {
                object_key: "obj/s".into(),
                epoch: 1,
                writer_node_id: 0,
                write_id: 30,
                placement_receipt_ref: test_receipt_ref(30, "obj/s", 1),
            });
        let violations = sys.step();
        let stale: Vec<_> = violations
            .iter()
            .filter(|v| v.invariant == "no_stale_epoch_commit")
            .collect();
        assert!(!stale.is_empty(), "stale-epoch commit must be detected");
    }

    #[test]
    fn fresh_epoch_commit_no_violation() {
        let mut sys = three_node_system();
        sys.nodes[0].current_epoch = 1;
        sys.nodes[0]
            .committed_object_writes
            .push(CommittedObjectWrite {
                object_key: "obj/f".into(),
                epoch: 1,
                writer_node_id: 0,
                write_id: 40,
                placement_receipt_ref: test_receipt_ref(40, "obj/f", 1),
            });
        let violations = sys.step();
        let stale: Vec<_> = violations
            .iter()
            .filter(|v| v.invariant == "no_stale_epoch_commit")
            .collect();
        assert!(stale.is_empty(), "fresh epoch should not be stale");
    }

    // ── I-3: no active lease epoch conflict ────────────────────────────

    #[test]
    fn stale_active_lease_violation_detected() {
        let mut sys = three_node_system();
        sys.nodes[0].current_epoch = 2;
        sys.epoch_model.record_advance(0, 2);
        sys.lease_model.leases.push(LeaseState {
            lease_id: 30,
            object_key: "obj/lease-stale".into(),
            holder: 0,
            epoch: 1,
            granted: true,
            revoked: false,
        });

        let violations = sys.step();
        let lease_epoch: Vec<_> = violations
            .iter()
            .filter(|v| v.invariant == "no_active_lease_epoch_conflict")
            .collect();
        assert!(
            !lease_epoch.is_empty(),
            "stale active lease must be detected"
        );
    }

    // ── I-4: no false quorum success ───────────────────────────────────

    #[test]
    fn false_quorum_violation_detected() {
        let mut sys = three_node_system();
        // Inject a committed quorum write with fewer acks than quorum needs.
        let qw = crate::QuorumWriteState {
            write_id: 1,
            object_key: "obj/fq".into(),
            coordinator: 0,
            participants: vec![0, 1, 2],
            epoch: 1,
            phase: crate::quorum::QuorumPhase::Committed,
            acks_received: 1,
            quorum_size: 2,
            committed: true,
        };
        sys.nodes[0].quorum_writes.push(qw);
        let violations = sys.step();
        let fq: Vec<_> = violations
            .iter()
            .filter(|v| v.invariant == "no_false_quorum_success")
            .collect();
        assert!(!fq.is_empty(), "false quorum must be detected");
    }

    #[test]
    fn valid_quorum_no_violation() {
        let mut sys = three_node_system();
        let qw = crate::QuorumWriteState {
            write_id: 1,
            object_key: "obj/vq".into(),
            coordinator: 0,
            participants: vec![0, 1, 2],
            epoch: 1,
            phase: crate::quorum::QuorumPhase::Committed,
            acks_received: 2,
            quorum_size: 2,
            committed: true,
        };
        sys.nodes[0].quorum_writes.push(qw);
        let violations = sys.step();
        let fq: Vec<_> = violations
            .iter()
            .filter(|v| v.invariant == "no_false_quorum_success")
            .collect();
        assert!(fq.is_empty(), "valid quorum should not be flagged");
    }

    // ── I-5: no rebuild before receipt ─────────────────────────────────

    #[test]
    fn rebuild_without_receipt_violation() {
        let mut sys = three_node_system();
        sys.placement_model.policy = RebuildPolicy::RequireDurableReceipt;
        let allowed = sys.placement_model.try_rebuild("obj/r1", 2, 1);
        assert!(!allowed, "rebuild without receipt should be denied");
        let violations = sys.step();
        let rr: Vec<_> = violations
            .iter()
            .filter(|v| v.invariant == "no_rebuild_before_receipt")
            .collect();
        assert!(rr.is_empty(), "denied rebuild is not a violation");
    }

    #[test]
    fn rebuild_after_receipt_allowed() {
        let mut sys = three_node_system();
        sys.placement_model.policy = RebuildPolicy::RequireDurableReceipt;
        sys.placement_model
            .record_receipt(PlacementReceiptState::for_model(100, "obj/r2", 0, 1, true));
        let allowed = sys.placement_model.try_rebuild("obj/r2", 2, 1);
        assert!(allowed, "rebuild after durable receipt should be allowed");
        let violations = sys.step();
        let rr: Vec<_> = violations
            .iter()
            .filter(|v| v.invariant == "no_rebuild_before_receipt")
            .collect();
        assert!(rr.is_empty(), "allowed rebuild with receipt is safe");
    }

    #[test]
    fn nondurable_receipt_does_not_authorize_rebuild() {
        let mut sys = three_node_system();
        sys.placement_model.policy = RebuildPolicy::RequireDurableReceipt;
        sys.placement_model
            .record_receipt(PlacementReceiptState::for_model(101, "obj/r4", 0, 1, false));
        assert!(!sys.placement_model.has_durable_receipt("obj/r4"));
        let allowed = sys.placement_model.try_rebuild("obj/r4", 2, 1);
        assert!(!allowed, "nondurable receipt should not authorize rebuild");
    }

    #[test]
    fn rebuild_permit_without_receipt_policy() {
        let mut sys = three_node_system();
        sys.placement_model.policy = RebuildPolicy::PermitWithoutReceipt;
        let allowed = sys.placement_model.try_rebuild("obj/r3", 2, 1);
        assert!(allowed, "PermitWithoutReceipt policy should allow rebuild");
        let violations = sys.step();
        let rr: Vec<_> = violations
            .iter()
            .filter(|v| v.invariant == "no_rebuild_before_receipt")
            .collect();
        assert!(
            rr.is_empty(),
            "PermitWithoutReceipt rebuild is not a violation"
        );
    }

    // ── lease model tests ──────────────────────────────────────────────

    #[test]
    fn lease_granted_and_revoked() {
        let mut model = crate::LeaseModel::new();
        let outcome = model.try_grant(1, "obj/lease1", 0, 1, 1);
        assert!(matches!(outcome, LeaseOutcome::Granted { lease_id: 1 }));
        assert!(model.object_holders.contains_key("obj/lease1"));

        let outcome = model.revoke(1);
        assert!(matches!(outcome, LeaseOutcome::Revoked { lease_id: 1 }));
        assert!(!model.object_holders.contains_key("obj/lease1"));
    }

    #[test]
    fn lease_conflict_detected() {
        let mut model = crate::LeaseModel::new();
        let _ = model.try_grant(1, "obj/lc", 0, 1, 1);
        let outcome = model.try_grant(2, "obj/lc", 1, 1, 1);
        assert!(matches!(outcome, LeaseOutcome::Conflict { .. }));
    }

    #[test]
    fn lease_stale_epoch_rejected() {
        let mut model = crate::LeaseModel::new();
        let outcome = model.try_grant(1, "obj/lse", 0, 1, 2);
        assert!(matches!(outcome, LeaseOutcome::StaleEpoch { .. }));
    }

    // ── quorum write model tests ───────────────────────────────────────

    #[test]
    fn quorum_write_refused_stale_epoch() {
        let mut model = crate::QuorumWriteModel::new();
        let req = QuorumWriteRequest {
            write_id: 1,
            object_key: "obj/qse".into(),
            coordinator: 0,
            participants: vec![0, 1, 2],
            epoch: 1,
            data_size: 64,
        };
        // Coordinator at epoch 2 > request epoch 1.
        let outcome = model.submit(req, 2, &[], &[(0, 2), (1, 2), (2, 2)]);
        assert!(matches!(
            outcome,
            QuorumWriteOutcome::RefusedStaleEpoch { .. }
        ));
    }

    #[test]
    fn quorum_write_refused_no_lease() {
        let mut model = crate::QuorumWriteModel::new();
        let req = QuorumWriteRequest {
            write_id: 2,
            object_key: "obj/qnl".into(),
            coordinator: 0,
            participants: vec![0, 1, 2],
            epoch: 1,
            data_size: 64,
        };
        let outcome = model.submit(req, 1, &[], &[(0, 1), (1, 1), (2, 1)]);
        assert!(matches!(
            outcome,
            QuorumWriteOutcome::RefusedLeaseConflict { .. }
        ));
    }

    #[test]
    fn quorum_write_committed_with_quorum() {
        let mut model = crate::QuorumWriteModel::new();
        let req = QuorumWriteRequest {
            write_id: 3,
            object_key: "obj/qok".into(),
            coordinator: 0,
            participants: vec![0, 1, 2],
            epoch: 1,
            data_size: 64,
        };
        let leases = vec![crate::LeaseState {
            lease_id: 1,
            object_key: "obj/qok".into(),
            holder: 0,
            epoch: 1,
            granted: true,
            revoked: false,
        }];
        let outcome = model.submit(req, 1, &leases, &[(0, 1), (1, 1), (2, 1)]);
        assert!(matches!(outcome, QuorumWriteOutcome::Committed { .. }));
        assert!(model.is_committed(3));
    }

    #[test]
    fn quorum_write_refused_no_quorum() {
        let mut model = crate::QuorumWriteModel::new();
        let req = QuorumWriteRequest {
            write_id: 4,
            object_key: "obj/qnq".into(),
            coordinator: 0,
            participants: vec![0, 1, 2],
            epoch: 1,
            data_size: 64,
        };
        let leases = vec![crate::LeaseState {
            lease_id: 1,
            object_key: "obj/qnq".into(),
            holder: 0,
            epoch: 1,
            granted: true,
            revoked: false,
        }];
        // Only 1 participant (node 0) at epoch 1, nodes 1 and 2 lag behind.
        let outcome = model.submit(req, 1, &leases, &[(0, 1), (1, 0), (2, 0)]);
        assert!(matches!(
            outcome,
            QuorumWriteOutcome::RefusedNoQuorum { .. }
        ));
    }

    // ── network model tests ────────────────────────────────────────────

    #[test]
    fn network_drop_policy() {
        let mut sys = DistributedSystem::new(2);
        sys.network.enqueue(
            DistributedMessage {
                from: 0,
                to: 1,
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
                from: 0,
                to: 1,
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
                from: 0,
                to: 1,
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
        model.record_receipt(PlacementReceiptState::for_model(1, "obj/p1", 0, 1, true));
        assert!(model.has_durable_receipt("obj/p1"));
        assert_eq!(model.object_placements.get("obj/p1").unwrap().len(), 1);
    }

    #[test]
    fn placement_receipt_ref_round_trips_model_key() {
        let object_key_str = "obj/roundtrip";
        let receipt_ref = model_placement_receipt_ref(42, object_key_str, 3);
        let recovered = crate::placement::receipt_ref_to_model_key(&receipt_ref);
        assert_eq!(recovered, object_key_str);
    }

    #[test]
    fn placement_receipt_state_for_model_constructs_valid_ref() {
        let state = PlacementReceiptState::for_model(7, "obj/state", 2, 5, true);
        assert_eq!(state.node_id, 2);
        assert!(state.durable);
        assert_eq!(state.receipt_ref.object_id, 7);
        assert_eq!(state.receipt_ref.receipt_epoch.0, 5);
    }

    // ── distributed system integration tests ───────────────────────────

    #[test]
    fn distributed_system_step_count_increments() {
        let mut sys = DistributedSystem::new(2);
        assert_eq!(sys.step_count, 0);
        let _ = sys.step();
        assert_eq!(sys.step_count, 1);
    }

    #[test]
    fn distributed_system_drain_network_empties_queue() {
        let mut sys = DistributedSystem::new(2);
        sys.network.enqueue(
            DistributedMessage {
                from: 0,
                to: 1,
                kind: MessageKind::EpochAdvance { new_epoch: 1 },
                epoch: 1,
            },
            DeliveryPolicy::Normal,
        );
        assert!(!sys.network.is_empty());
        let _ = sys.drain_network();
        assert!(sys.network.is_empty());
    }

    // -- distributed safety receipt tests -------------------------------

    #[test]
    fn receipt_passing_bounded_model_records_combined_safety() {
        let sys = passing_receipt_system();
        let receipt = DistributedSafetyReceipt::for_system(&sys)
            .expect("complete combined receipt should build");

        assert!(receipt.outcome.passed);
        assert_eq!(receipt.outcome.violation_count, 0);
        assert_eq!(receipt.bounds.explored_nodes, 3);
        assert_eq!(receipt.bounds.explored_steps, 2);
        assert_eq!(receipt.bounds.active_lease_records, 2);
        assert!(receipt
            .checked_invariants
            .iter()
            .any(|invariant| { invariant.family == "epoch" }));
        assert!(receipt
            .checked_invariants
            .iter()
            .any(|invariant| { invariant.family == "lease" }));
        assert!(receipt
            .checked_invariants
            .iter()
            .any(|invariant| { invariant.family == "quorum" }));
        assert!(receipt
            .checked_invariants
            .iter()
            .any(|invariant| { invariant.family == "placement" }));
        assert_eq!(receipt.validation_tier, "bounded-model-only");
    }

    #[test]
    fn receipt_records_injected_quorum_violation() {
        let mut sys = three_node_system();
        sys.quorum_model.writes.push(crate::QuorumWriteState {
            write_id: 100,
            object_key: "obj/quorum-receipt".into(),
            coordinator: 0,
            participants: vec![0, 1, 2],
            epoch: 1,
            phase: crate::quorum::QuorumPhase::Committed,
            acks_received: 1,
            quorum_size: 2,
            committed: true,
        });

        let receipt = DistributedSafetyReceipt::for_system(&sys)
            .expect("complete combined receipt should build");
        assert!(!receipt.outcome.passed);
        assert!(receipt
            .outcome
            .violations
            .iter()
            .any(|violation| { violation.invariant == "no_false_quorum_success" }));
    }

    #[test]
    fn receipt_records_injected_lease_epoch_violation() {
        let mut sys = three_node_system();
        sys.nodes[0].current_epoch = 2;
        sys.epoch_model.record_advance(0, 2);
        sys.lease_model.leases.push(LeaseState {
            lease_id: 101,
            object_key: "obj/lease-receipt".into(),
            holder: 0,
            epoch: 1,
            granted: true,
            revoked: false,
        });

        let receipt = DistributedSafetyReceipt::for_system(&sys)
            .expect("complete combined receipt should build");
        assert!(!receipt.outcome.passed);
        assert!(receipt
            .outcome
            .violations
            .iter()
            .any(|violation| { violation.invariant == "no_active_lease_epoch_conflict" }));
    }

    #[test]
    fn combined_receipt_rejects_incomplete_invariant_set() {
        let sys = passing_receipt_system();
        let mut checked_invariants = crate::checked_combined_safety_invariants();
        checked_invariants.retain(|invariant| invariant.id != "no_false_quorum_success");

        let err = DistributedSafetyReceipt::new_combined(&sys, checked_invariants, Vec::new())
            .expect_err("combined safety evidence must require the full invariant set");

        assert!(matches!(
            err,
            DistributedSafetyReceiptError::IncompleteCombinedInvariantSet {
                missing_invariants
            } if missing_invariants == vec!["no_false_quorum_success"]
        ));
    }

    #[test]
    fn receipt_serialization_is_deterministic() {
        let sys = passing_receipt_system();
        let receipt = DistributedSafetyReceipt::for_system(&sys)
            .expect("complete combined receipt should build");
        let first = serde_json::to_string_pretty(&receipt).expect("receipt should serialize");
        let second = serde_json::to_string_pretty(&receipt)
            .expect("receipt should serialize deterministically");
        let fixture =
            include_str!("../../../validation/artifacts/distributed/combined-safety-receipt.json")
                .trim_end();

        assert_eq!(first, second);
        assert_eq!(first, fixture);
    }
}
