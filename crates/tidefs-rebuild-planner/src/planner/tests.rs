use super::*;
use std::collections::{BTreeMap, BTreeSet};
use tidefs_durability_layout::DurabilityLayoutV1;
use tidefs_membership_epoch::{DomainId, EpochId, HealthClass, MemberId};
use tidefs_replication_model::{PlacementReceiptRef, ReceiptRedundancyPolicy, ReplicatedSubjectId};

use crate::plan::ReconstructionTaskReceiptError;

fn make_input(layout: DurabilityLayoutV1) -> ReconstructionInput {
    ReconstructionInput {
        layout,
        member_health: BTreeMap::new(),
        failed_nodes: BTreeSet::new(),
        failed_device_count: 0,
        object_placement: BTreeMap::new(),
        in_flight_objects: BTreeSet::new(),
        failure_domains: BTreeMap::new(),
        plan_id: 1,
        now_ns: 1_000_000_000,
    }
}

fn member_set(ids: &[u64]) -> BTreeSet<MemberId> {
    ids.iter().copied().map(MemberId).collect()
}

fn receipt_ref(object_id: u64) -> PlacementReceiptRef {
    let mut object_key = [0u8; 32];
    object_key[..8].copy_from_slice(&object_id.to_le_bytes());
    let mut payload_digest = [0u8; 32];
    payload_digest[..8].copy_from_slice(&(object_id.wrapping_mul(31)).to_le_bytes());
    PlacementReceiptRef::replicated(
        object_id,
        object_key,
        EpochId::new(11),
        object_id + 1,
        2,
        8192 + object_id,
        payload_digest,
    )
}

fn placement(object_id: u64, members: &[u64]) -> ReceiptBackedObjectPlacement {
    ReceiptBackedObjectPlacement::new(receipt_ref(object_id), member_set(members)).unwrap()
}

fn insert_placement(input: &mut ReconstructionInput, object_id: u64, members: &[u64]) {
    input
        .object_placement
        .insert(object_id, placement(object_id, members));
}

fn unchecked_placement(
    placement_receipt_ref: PlacementReceiptRef,
    members: &[u64],
) -> ReceiptBackedObjectPlacement {
    ReceiptBackedObjectPlacement {
        placement_receipt_ref,
        members: member_set(members),
    }
}

fn malformed_policy_receipt_ref(object_id: u64) -> PlacementReceiptRef {
    let base = receipt_ref(object_id);
    PlacementReceiptRef::new(
        base.object_id,
        base.object_key,
        base.receipt_epoch,
        base.receipt_generation,
        ReceiptRedundancyPolicy::Replicated { copies: 0 },
        base.payload_len,
        base.payload_digest,
        0,
    )
}

fn under_width_receipt_ref(object_id: u64) -> PlacementReceiptRef {
    let base = receipt_ref(object_id);
    PlacementReceiptRef::new(
        base.object_id,
        base.object_key,
        base.receipt_epoch,
        base.receipt_generation,
        ReceiptRedundancyPolicy::Replicated { copies: 3 },
        base.payload_len,
        base.payload_digest,
        2,
    )
}

#[test]
fn plan_reconstruction_single_node_failure_2way_mirror() {
    let layout = DurabilityLayoutV1::mirror(2).unwrap();
    let mut input = make_input(layout);

    // 3 nodes: 1,2 healthy; 3 failed
    input
        .member_health
        .insert(MemberId(1), HealthClass::Healthy);
    input
        .member_health
        .insert(MemberId(2), HealthClass::Healthy);
    input.member_health.insert(MemberId(3), HealthClass::Down);
    input.failed_nodes.insert(MemberId(3));

    // Object 10: held by nodes 1 and 3 (node 3 failed -> only 1 healthy replica)
    insert_placement(&mut input, 10, &[1, 3]);

    // Failure domains: all distinct
    input.failure_domains.insert(MemberId(1), DomainId::new(1));
    input.failure_domains.insert(MemberId(2), DomainId::new(2));
    input.failure_domains.insert(MemberId(3), DomainId::new(3));

    let plan = plan_reconstruction(&input).unwrap();
    assert_eq!(plan.task_count(), 1, "object 10 should need reconstruction");
    let task = &plan.tasks[0];
    assert_eq!(task.object_id(), 10);
    assert_eq!(task.placement_receipt_ref, receipt_ref(10));
    assert_eq!(task.source_nodes, vec![1]); // node 1 is healthy source
    assert!(task.target_nodes.contains(&2)); // node 2 is target
    assert_eq!(task.priority, 1); // min_replicas(2) - healthy_count(1) = 1
}

#[test]
fn plan_reconstruction_dual_node_failure() {
    let layout = DurabilityLayoutV1::mirror(2).unwrap();
    let mut input = make_input(layout);

    // 4 nodes: 1,2 healthy; 3,4 failed
    input
        .member_health
        .insert(MemberId(1), HealthClass::Healthy);
    input
        .member_health
        .insert(MemberId(2), HealthClass::Healthy);
    input.member_health.insert(MemberId(3), HealthClass::Down);
    input.member_health.insert(MemberId(4), HealthClass::Down);
    input.failed_nodes.insert(MemberId(3));
    input.failed_nodes.insert(MemberId(4));

    // Object 10: held by nodes 1 and 3 (only 1 healthy)
    insert_placement(&mut input, 10, &[1, 3]);

    // Object 20: held by nodes 3 and 4 (0 healthy -> highest priority)
    insert_placement(&mut input, 20, &[3, 4]);

    // Object 30: held by nodes 1 and 2 (2 healthy -> no rebuild needed)
    insert_placement(&mut input, 30, &[1, 2]);

    input.failure_domains.insert(MemberId(1), DomainId::new(1));
    input.failure_domains.insert(MemberId(2), DomainId::new(2));
    input.failure_domains.insert(MemberId(3), DomainId::new(3));
    input.failure_domains.insert(MemberId(4), DomainId::new(4));

    let plan = plan_reconstruction(&input).unwrap();
    assert_eq!(
        plan.task_count(),
        2,
        "objects 10 and 20 need reconstruction; 30 does not"
    );

    // Object 20 (0 healthy) should come first (priority 0)
    assert_eq!(plan.tasks[0].object_id(), 20);
    assert_eq!(plan.tasks[0].priority, 0);

    // Object 10 (1 healthy) should come second (priority 1)
    assert_eq!(plan.tasks[1].object_id(), 10);
    assert_eq!(plan.tasks[1].priority, 1);
}

#[test]
fn plan_reconstruction_noop_all_satisfied() {
    let layout = DurabilityLayoutV1::mirror(2).unwrap();
    let mut input = make_input(layout);

    input
        .member_health
        .insert(MemberId(1), HealthClass::Healthy);
    input
        .member_health
        .insert(MemberId(2), HealthClass::Healthy);

    insert_placement(&mut input, 10, &[1, 2]);

    input.failure_domains.insert(MemberId(1), DomainId::new(1));
    input.failure_domains.insert(MemberId(2), DomainId::new(2));

    let plan = plan_reconstruction(&input).unwrap();
    assert!(plan.is_empty(), "all objects satisfy layout constraints");
}

#[test]
fn plan_reconstruction_empty_membership() {
    let layout = DurabilityLayoutV1::mirror(2).unwrap();
    let input = make_input(layout);

    let plan = plan_reconstruction(&input).unwrap();
    assert!(plan.is_empty());
}

#[test]
fn plan_reconstruction_failure_domain_separation() {
    let layout = DurabilityLayoutV1::mirror(2).unwrap();
    let mut input = make_input(layout);

    // 4 healthy nodes; nodes 1,2 in domain 10; nodes 3,4 in domain 20
    for i in 1..=4 {
        input
            .member_health
            .insert(MemberId(i), HealthClass::Healthy);
    }
    // Node 5 failed - holds object 10, along with node 1
    input.member_health.insert(MemberId(5), HealthClass::Down);
    input.failed_nodes.insert(MemberId(5));

    // Object 10 held by nodes 1 (domain 10) and 5 (failed)
    insert_placement(&mut input, 10, &[1, 5]);

    // Domains: 1,2 -> domain 10; 3,4 -> domain 20; 5 -> domain 30
    input.failure_domains.insert(MemberId(1), DomainId::new(10));
    input.failure_domains.insert(MemberId(2), DomainId::new(10));
    input.failure_domains.insert(MemberId(3), DomainId::new(20));
    input.failure_domains.insert(MemberId(4), DomainId::new(20));
    input.failure_domains.insert(MemberId(5), DomainId::new(30));

    let plan = plan_reconstruction(&input).unwrap();
    assert_eq!(plan.task_count(), 1);
    let task = &plan.tasks[0];
    assert_eq!(task.source_nodes, vec![1]);

    // Target should be from domain 20 (cross-domain from node 1's domain 10)
    // Not node 2 (same domain as node 1)
    assert!(
        task.target_nodes.iter().any(|n| *n == 3 || *n == 4),
        "target should prefer cross-domain nodes 3 or 4 over same-domain node 2"
    );
}

#[test]
fn plan_reconstruction_in_flight_filtered() {
    let layout = DurabilityLayoutV1::mirror(2).unwrap();
    let mut input = make_input(layout);

    input
        .member_health
        .insert(MemberId(1), HealthClass::Healthy);
    input
        .member_health
        .insert(MemberId(2), HealthClass::Healthy);
    input.member_health.insert(MemberId(3), HealthClass::Down);
    input.failed_nodes.insert(MemberId(3));

    // Object 10: held by nodes 1 and 3 (needs rebuild)
    insert_placement(&mut input, 10, &[1, 3]);

    // But object 10 is already in-flight
    input.in_flight_objects.insert(10);

    input.failure_domains.insert(MemberId(1), DomainId::new(1));
    input.failure_domains.insert(MemberId(2), DomainId::new(2));
    input.failure_domains.insert(MemberId(3), DomainId::new(3));

    let plan = plan_reconstruction(&input).unwrap();
    assert!(plan.is_empty(), "in-flight object should be filtered out");
}

#[test]
fn plan_reconstruction_plan_sealed_roundtrip() {
    let layout = DurabilityLayoutV1::mirror(2).unwrap();
    let mut input = make_input(layout);

    input
        .member_health
        .insert(MemberId(1), HealthClass::Healthy);
    input
        .member_health
        .insert(MemberId(2), HealthClass::Healthy);
    input.member_health.insert(MemberId(3), HealthClass::Down);
    input.failed_nodes.insert(MemberId(3));

    insert_placement(&mut input, 10, &[1, 3]);

    insert_placement(&mut input, 20, &[2, 3]);

    input.failure_domains.insert(MemberId(1), DomainId::new(1));
    input.failure_domains.insert(MemberId(2), DomainId::new(2));
    input.failure_domains.insert(MemberId(3), DomainId::new(3));

    let plan = plan_reconstruction(&input).unwrap();
    assert!(!plan.is_empty());

    let sealed = plan.seal();
    let decoded = crate::plan::RebuildPlan::verify_and_decode(&sealed).unwrap();
    assert_eq!(decoded, plan);
}

#[test]
fn plan_reconstruction_erasure_layout() {
    let layout = DurabilityLayoutV1::erasure(4, 2).unwrap(); // k=4 data, m=2 parity
    let mut input = make_input(layout);

    for i in 1..=6 {
        input
            .member_health
            .insert(MemberId(i), HealthClass::Healthy);
    }
    // Node 7, 8 failed
    input.member_health.insert(MemberId(7), HealthClass::Down);
    input.member_health.insert(MemberId(8), HealthClass::Down);
    input.failed_nodes.insert(MemberId(7));
    input.failed_nodes.insert(MemberId(8));

    // Object 100: held by nodes 1,2,3,4,7,8 (4 healthy out of needed 4 -> OK)
    // Actually: 4 data shards needed, 2 parity. Total 6.
    // 4 healthy out of 6 -> meets minimum of 4 data shards. No rebuild needed.
    insert_placement(&mut input, 100, &[1, 2, 3, 4, 7, 8]);

    // Object 200: held by nodes 7,8 only (0 healthy, need 4 data shards -> rebuild)
    insert_placement(&mut input, 200, &[7, 8]);

    for i in 1..=8 {
        input.failure_domains.insert(MemberId(i), DomainId::new(i));
    }

    let plan = plan_reconstruction(&input).unwrap();
    assert_eq!(plan.task_count(), 1, "only object 200 needs reconstruction");
    let task = &plan.tasks[0];
    assert_eq!(task.object_id(), 200);
    assert!(
        task.source_nodes.is_empty(),
        "no healthy sources for object 200"
    );
    assert_eq!(task.priority, 0);
}

#[test]
fn minimum_replicas_mirror3() {
    let layout = DurabilityLayoutV1::mirror(3).unwrap();
    assert_eq!(minimum_replicas(&layout), 3);
}

#[test]
fn minimum_replicas_erasure_8_3() {
    let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
    assert_eq!(minimum_replicas(&layout), 8);
}

#[test]
fn target_replica_count_mirror3() {
    let layout = DurabilityLayoutV1::mirror(3).unwrap();
    assert_eq!(target_replica_count(&layout), 3);
}

#[test]
fn target_replica_count_erasure_8_3() {
    let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
    assert_eq!(target_replica_count(&layout), 11);
}

#[test]
fn plan_reconstruction_no_healthy_members() {
    let layout = DurabilityLayoutV1::mirror(2).unwrap();
    let mut input = make_input(layout);

    input.member_health.insert(MemberId(1), HealthClass::Down);
    input.member_health.insert(MemberId(2), HealthClass::Down);
    input.failed_nodes.insert(MemberId(1));
    input.failed_nodes.insert(MemberId(2));

    insert_placement(&mut input, 10, &[1, 2]);

    let plan = plan_reconstruction(&input).unwrap();
    assert_eq!(plan.task_count(), 1);
    let task = &plan.tasks[0];
    assert!(task.source_nodes.is_empty());
    assert!(task.target_nodes.is_empty());
    assert_eq!(task.priority, 0);
}

#[test]
fn receipt_backed_object_placement_constructor_rejects_synthetic_refs() {
    let err = ReceiptBackedObjectPlacement::new(
        PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId::new(10)),
        member_set(&[1]),
    )
    .unwrap_err();
    assert_eq!(err, ReconstructionTaskReceiptError::SyntheticReceipt);
}

#[test]
fn plan_reconstruction_refuses_unauthoritative_receipt_refs() {
    let cases = [
        (
            10,
            receipt_ref(11),
            ReconstructionPlanningError::ReceiptObjectIdMismatch {
                object_id: 10,
                receipt_object_id: 11,
            },
        ),
        (
            10,
            PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId::new(10)),
            ReconstructionPlanningError::InvalidPlacementReceipt {
                object_id: 10,
                reason: ReconstructionTaskReceiptError::SyntheticReceipt,
            },
        ),
        (
            10,
            malformed_policy_receipt_ref(10),
            ReconstructionPlanningError::InvalidPlacementReceipt {
                object_id: 10,
                reason: ReconstructionTaskReceiptError::MalformedRedundancyPolicy,
            },
        ),
        (
            10,
            under_width_receipt_ref(10),
            ReconstructionPlanningError::InvalidPlacementReceipt {
                object_id: 10,
                reason: ReconstructionTaskReceiptError::UnderWidthReceipt {
                    target_count: 2,
                    required_count: 3,
                },
            },
        ),
    ];

    for (object_id, placement_receipt_ref, expected) in cases {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let mut input = make_input(layout);
        input
            .member_health
            .insert(MemberId(1), HealthClass::Healthy);
        input
            .member_health
            .insert(MemberId(2), HealthClass::Healthy);
        input
            .object_placement
            .insert(object_id, unchecked_placement(placement_receipt_ref, &[1]));

        assert_eq!(plan_reconstruction(&input).unwrap_err(), expected);
    }
}
