// Integration tests: multi-node witness accumulation across epoch boundaries,
// partition injection and heal with deterministic replay.
//
// These tests verify that WitnessSet behaves correctly when simulating
// distributed scenarios: mass ack across many nodes, epoch-roll forward
// semantics, partition simulation, and consistent behavior after repeated
// epoch transitions.

use std::collections::BTreeSet;
use tidefs_witness_set::witness_set::{QuorumThreshold, WitnessSet};
use tidefs_witness_set::WitnessSetCodec;

// -- Helpers ---------------------------------------------------------------

fn make_ws(count: usize, threshold: QuorumThreshold) -> WitnessSet {
    let mut ws = WitnessSet::new(threshold);
    for id in 1..=count as u64 {
        ws.add_witness(id);
    }
    ws
}

fn make_ws_with_epoch(count: usize, threshold: QuorumThreshold, epoch: u64) -> WitnessSet {
    let mut ws = WitnessSet::with_epoch(threshold, epoch);
    for id in 1..=count as u64 {
        ws.add_witness(id);
    }
    ws
}

// -- Multi-node witness accumulation across synthetic epoch boundaries ----

#[test]
fn test_accumulation_crosses_epoch_boundary() {
    let mut ws = make_ws_with_epoch(5, QuorumThreshold::StrictMajority, 0);
    // Majority: 3 of 5
    ws.ack(1, 100);
    ws.ack(2, 100);
    ws.ack(3, 100);
    assert!(ws.has_quorum(100));

    ws.advance_epoch(1);
    assert_eq!(ws.epoch(), 1);
    assert!(!ws.has_quorum(100));
    assert_eq!(ws.ack_count(100), 0);

    // Re-ack in epoch 1
    ws.ack(1, 200);
    ws.ack(2, 200);
    ws.ack(3, 200);
    ws.ack(4, 200);
    assert!(ws.has_quorum(200));
}

#[test]
fn test_consecutive_epoch_advances_preserve_membership() {
    let mut ws = make_ws(7, QuorumThreshold::SuperMajority);
    let members_before: Vec<u64> = ws.iter().collect();

    for e in 1..=5u64 {
        ws.advance_epoch(e);
        let members_after: Vec<u64> = ws.iter().collect();
        assert_eq!(members_after, members_before);
        assert_eq!(ws.epoch(), e);
        assert_eq!(ws.operation_count(), 0);
    }
}

#[test]
fn test_mass_ack_50_nodes() {
    let mut ws = make_ws(50, QuorumThreshold::StrictMajority);
    // Majority = 26 of 50
    for id in 1..=26u64 {
        ws.ack(id, 1);
    }
    assert!(ws.has_quorum(1));
    assert_eq!(ws.ack_count(1), 26);

    // Adding 27th is idempotent after quorum
    ws.ack(27, 1);
    assert_eq!(ws.ack_count(1), 27);
}

#[test]
fn test_mass_ack_100_nodes_super_majority() {
    let mut ws = make_ws(100, QuorumThreshold::SuperMajority);
    // Super-majority of 100 = ceil(200/3) = 67
    for id in 1..=66u64 {
        ws.ack(id, 1);
    }
    assert!(!ws.has_quorum(1));
    ws.ack(67, 1);
    assert!(ws.has_quorum(1));
}

#[test]
fn test_multiple_operations_across_epochs() {
    let mut ws = make_ws_with_epoch(5, QuorumThreshold::StrictMajority, 0);

    // Epoch 0: operations 10, 20, 30
    for op in [10u64, 20, 30] {
        ws.ack(1, op);
        ws.ack(2, op);
        ws.ack(3, op);
        assert!(ws.has_quorum(op));
    }
    assert_eq!(ws.operation_count(), 3);

    ws.advance_epoch(1);
    assert_eq!(ws.operation_count(), 0);

    // Epoch 1: new operations 40, 50
    for op in [40u64, 50] {
        ws.ack(1, op);
        ws.ack(2, op);
        ws.ack(3, op);
        assert!(ws.has_quorum(op));
    }
    assert_eq!(ws.operation_count(), 2);
}

// -- Partition injection and heal -----------------------------------------

#[test]
fn test_partition_independent_witness_sets() {
    // Two independent 5-node witness sets representing two partitions.
    // Each reaches quorum on different operations independently.
    let mut ws_a = make_ws_with_epoch(5, QuorumThreshold::StrictMajority, 0);
    let mut ws_b = make_ws_with_epoch(5, QuorumThreshold::StrictMajority, 0);

    // Partition A: quorum on op 100 (3 of 5)
    ws_a.ack(1, 100);
    ws_a.ack(2, 100);
    ws_a.ack(3, 100);
    assert!(ws_a.has_quorum(100));

    // Partition B: quorum on op 200 (3 of 5)
    ws_b.ack(1, 200);
    ws_b.ack(2, 200);
    ws_b.ack(3, 200);
    assert!(ws_b.has_quorum(200));

    // Neither partition saw the other's operation
    assert_eq!(ws_a.ack_count(200), 0);
    assert_eq!(ws_b.ack_count(100), 0);
}

#[test]
fn test_post_merge_quorum_requires_reack_for_new_ops() {
    // 5 initial witnesses, majority = 3.
    // Ack 4 for op 100 (headroom). Then add 2 more witnesses (total 7,
    // majority = 4) and verify old ops survive and new ops reach quorum
    // after sufficient re-acking.
    let mut ws = make_ws_with_epoch(5, QuorumThreshold::StrictMajority, 0);

    // Build headroom: 4 of 5 for op 100
    ws.ack(1, 100);
    ws.ack(2, 100);
    ws.ack(3, 100);
    ws.ack(4, 100);
    assert!(ws.has_quorum(100));

    // Merge: add 2 new witnesses (total now 7, majority = 4)
    ws.add_witness(6);
    ws.add_witness(7);

    // Op 100 still has 4 acks of 7 → quorum preserved
    assert!(ws.has_quorum(100));

    // New op 200: need 4 of 7. Ack 4 nodes.
    ws.ack(1, 200);
    ws.ack(2, 200);
    ws.ack(6, 200);
    ws.ack(7, 200);
    assert!(ws.has_quorum(200));
}

#[test]
fn test_heal_after_partition_single_leader() {
    // 7 nodes, 3 go silent, 4 remain and reach quorum.
    let mut ws = make_ws(7, QuorumThreshold::StrictMajority);

    // Pre-partition: quorum for op 1 (4 of 7)
    ws.ack(1, 1);
    ws.ack(2, 1);
    ws.ack(3, 1);
    ws.ack(4, 1);
    assert!(ws.has_quorum(1));

    // Post-heal: all 7 can ack new ops
    ws.ack(5, 2);
    ws.ack(6, 2);
    ws.ack(7, 2);
    ws.ack(1, 2);
    assert!(ws.has_quorum(2));
}

// -- Deterministic replay after epoch reset -------------------------------

#[test]
fn test_deterministic_behavior_after_epoch_reset() {
    let mut ws1 = make_ws_with_epoch(5, QuorumThreshold::StrictMajority, 0);
    let mut ws2 = make_ws_with_epoch(5, QuorumThreshold::StrictMajority, 0);

    for ws in [&mut ws1, &mut ws2] {
        ws.ack(1, 10);
        ws.ack(2, 10);
        ws.ack(3, 10);
        ws.advance_epoch(1);
        ws.ack(1, 20);
        ws.ack(2, 20);
        ws.advance_epoch(2);
        ws.ack(1, 30);
        ws.ack(2, 30);
        ws.ack(3, 30);
    }

    assert_eq!(ws1.epoch(), ws2.epoch());
    assert_eq!(ws1.len(), ws2.len());
    assert_eq!(ws1.operation_count(), ws2.operation_count());
    for op in ws1.operations() {
        assert_eq!(ws1.ack_count(op), ws2.ack_count(op));
        assert_eq!(ws1.has_quorum(op), ws2.has_quorum(op));
    }
}

// -- Codec round-trip for large witness sets -------------------------------

#[test]
fn test_codec_roundtrip_50_nodes_with_acks() {
    let mut ws = make_ws(50, QuorumThreshold::Exact(25));
    for id in 1..=30u64 {
        ws.ack(id, 1);
    }
    for id in 1..=20u64 {
        ws.ack(id, 2);
    }

    let enc = WitnessSetCodec::encode_to_vec(&ws);
    let dec = WitnessSetCodec::decode(&enc).unwrap();

    assert_eq!(dec.len(), 50);
    assert_eq!(dec.threshold(), QuorumThreshold::Exact(25));
    assert_eq!(dec.ack_count(1), 30);
    assert!(dec.has_quorum(1));
    assert_eq!(dec.ack_count(2), 20);
    assert!(!dec.has_quorum(2));

    let ids: Vec<u64> = dec.iter().collect();
    assert_eq!(ids.len(), 50);
    assert_eq!(ids[0], 1);
    assert_eq!(ids[49], 50);
}

#[test]
fn test_codec_roundtrip_with_epoch_preserved() {
    let ws = make_ws_with_epoch(10, QuorumThreshold::SuperMajority, 42);
    let enc = WitnessSetCodec::encode_to_vec(&ws);
    let dec = WitnessSetCodec::decode(&enc).unwrap();
    assert_eq!(dec.epoch(), 42);
    assert_eq!(dec.threshold(), QuorumThreshold::SuperMajority);
    assert_eq!(dec.len(), 10);
    assert_eq!(dec.operation_count(), 0);
}

// -- Edge cases ------------------------------------------------------------

#[test]
fn test_empty_set_never_reaches_quorum() {
    let ws = WitnessSet::new(QuorumThreshold::StrictMajority);
    assert!(!ws.has_quorum(0));
    assert!(!ws.has_quorum(1));
    assert!(!ws.has_quorum(u64::MAX));
}

#[test]
fn test_single_node_always_has_quorum_when_acked() {
    let mut ws = make_ws(1, QuorumThreshold::StrictMajority);
    ws.ack(1, 42);
    assert!(ws.has_quorum(42));
    ws.advance_epoch(1);
    assert!(!ws.has_quorum(42));
}

#[test]
fn test_large_operation_ids() {
    let mut ws = make_ws(3, QuorumThreshold::StrictMajority);
    let op_id = u64::MAX;
    ws.ack(1, op_id);
    ws.ack(2, op_id);
    ws.ack(3, op_id);
    assert!(ws.has_quorum(op_id));
    assert_eq!(ws.ack_count(op_id), 3);
}

#[test]
fn test_large_node_ids() {
    let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
    ws.add_witness(u64::MAX);
    ws.add_witness(u64::MAX - 1);
    ws.add_witness(0);
    assert_eq!(ws.len(), 3);
    ws.ack(u64::MAX, 1);
    ws.ack(u64::MAX - 1, 1);
    assert!(ws.has_quorum(1));
    let ids: Vec<u64> = ws.iter().collect();
    assert_eq!(ids, vec![0, u64::MAX - 1, u64::MAX]);
}

#[test]
fn test_remove_then_readd_witness() {
    let mut ws = make_ws(3, QuorumThreshold::StrictMajority);
    ws.ack(1, 100);
    ws.ack(2, 100);
    ws.ack(3, 100);
    assert!(ws.has_quorum(100));

    ws.remove_witness(2);
    assert_eq!(ws.len(), 2);
    assert_eq!(ws.ack_count(100), 2);

    ws.add_witness(2);
    assert_eq!(ws.len(), 3);
    assert_eq!(ws.ack_count(100), 2);
    assert!(ws.has_quorum(100));

    ws.ack(2, 100);
    assert_eq!(ws.ack_count(100), 3);
}

#[test]
fn test_unacked_single_node() {
    let mut ws = make_ws(1, QuorumThreshold::StrictMajority);
    assert_eq!(ws.unacked(100), vec![1]);
    ws.ack(1, 100);
    assert!(ws.unacked(100).is_empty());
}

#[test]
fn test_unacked_multi_node_partial() {
    let mut ws = make_ws(5, QuorumThreshold::StrictMajority);
    ws.ack(1, 100);
    ws.ack(3, 100);
    ws.ack(5, 100);
    assert_eq!(ws.unacked(100), vec![2, 4]);
}

// -- QuorumSelection integration ------------------------------------------

#[test]
fn test_read_write_quorum_overlap_guarantees_consensus() {
    let ws = make_ws(5, QuorumThreshold::StrictMajority);
    let read_q: BTreeSet<u64> = ws.select_read_quorum().into_iter().collect();
    let write_q: BTreeSet<u64> = ws.select_write_quorum().into_iter().collect();

    let overlap: Vec<u64> = read_q.intersection(&write_q).copied().collect();
    assert!(!overlap.is_empty(), "read and write quorums must overlap");

    let n = ws.len();
    let w = ws.threshold().required(n);
    let r = read_q.len();
    assert!(r + w > n, "R({r}) + W({w}) must exceed N({n})");
}

#[test]
fn test_healthy_read_quorum_excludes_unhealthy_and_preserves_overlap() {
    let ws = make_ws(7, QuorumThreshold::StrictMajority);
    let unhealthy: BTreeSet<u64> = [2, 4, 6].into_iter().collect();

    let read_q: BTreeSet<u64> = ws
        .select_read_quorum_healthy(&unhealthy)
        .into_iter()
        .collect();
    let write_q: BTreeSet<u64> = ws
        .select_write_quorum_healthy(&unhealthy)
        .into_iter()
        .collect();

    for id in &unhealthy {
        assert!(!read_q.contains(id), "unhealthy node {id} in read quorum");
        assert!(!write_q.contains(id), "unhealthy node {id} in write quorum");
    }

    let overlap: Vec<u64> = read_q.intersection(&write_q).copied().collect();
    assert!(!overlap.is_empty());
}
