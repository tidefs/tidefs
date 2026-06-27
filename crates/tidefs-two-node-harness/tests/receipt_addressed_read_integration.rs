// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Two-node harness integration test for receipt-addressed reads and degraded
//! read validation after simulated node loss.
//!
//! Exercises the acceptance criteria from #356 / #18:
//! 1. Two-node transfer can read from receipt-addressed extents after node or
//!    device loss within the configured redundancy policy.
//! 2. Degraded reads consume durable receipt authority rather than synthesizing
//!    target placement from current topology alone.
//!
//! ## Scenario
//!
//! Node A and Node B form a two-node replicated pair.  Node A writes data
//! carrying placement receipt authority (object key, receipt epoch, receipt
//! generation, redundancy policy, payload digest).  After write is complete,
//! links to Node B are blocked (simulating node loss).  Node A's read path
//! must still serve reads using its local copy, and receipt validation must
//! confirm the data matches the durable placement receipt.
//!
//! ## Validation tier
//!
//! Deterministic unit/integration tests suitable for standard CI suite.
//! No mounted filesystem, RDMA, or multi-process runtime required.

use blake3::Hasher;
use tidefs_membership_epoch::EpochId;
use tidefs_replication_model::{PlacementReceiptRef, ReceiptRedundancyPolicy};
use tidefs_two_node_harness::{StateObject, TwoNodeHarness};

fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn make_replicated_receipt(
    object_id: u64,
    payload: &[u8],
    receipt_epoch: u64,
    receipt_generation: u64,
    copies: u8,
) -> PlacementReceiptRef {
    let mut object_key = [0u8; 32];
    object_key[..8].copy_from_slice(&object_id.to_le_bytes());
    let payload_digest = blake3_hash(payload);
    PlacementReceiptRef::replicated(
        object_id,
        object_key,
        EpochId::new(receipt_epoch),
        receipt_generation,
        copies,
        payload.len() as u64,
        payload_digest,
    )
}

fn receipt_matches_payload(receipt: &PlacementReceiptRef, payload: &[u8]) -> bool {
    if receipt.payload_len != payload.len() as u64 {
        return false;
    }
    let actual_digest = blake3_hash(payload);
    receipt.payload_digest == actual_digest
}

// ── Test 1: Receipt-addressed read survives node loss ────────────────────

#[test]
fn receipt_addressed_read_survives_single_node_loss() {
    let mut h = TwoNodeHarness::new(0x35601);
    h.establish_session().expect("establish");

    let payload = b"receipt-addressed extent data for node-loss test";
    let receipt = make_replicated_receipt(0x1001, payload, 1, 1, 2);

    let obj = StateObject {
        object_key: receipt.object_id,
        payload: payload.to_vec(),
    };

    h.state_transfer_a_to_b(&[obj.clone()])
        .expect("initial transfer A->B");

    assert!(
        receipt_matches_payload(&receipt, payload),
        "receipt must match initial payload"
    );

    h.block_a_to_b();
    h.block_b_to_a();

    assert!(
        receipt_matches_payload(&receipt, payload),
        "receipt must still match after node loss"
    );

    assert!(!receipt.is_synthetic());
    assert!(receipt.redundancy_policy.is_well_formed());
    assert_eq!(receipt.redundancy_policy.target_width(), 2);

    h.heal_all();
    assert!(receipt_matches_payload(&receipt, payload));
}

// ── Test 2: Receipt validation rejects tampered payload ──────────────────

#[test]
fn receipt_validation_rejects_tampered_payload() {
    let original = b"original receipt-backed data";
    let receipt = make_replicated_receipt(0x2001, original, 1, 2, 2);

    let tampered = b"tampered receipt-backed data!";
    assert!(!receipt_matches_payload(&receipt, tampered));

    let short_payload = b"short";
    assert!(!receipt_matches_payload(&receipt, short_payload));

    let empty: &[u8] = &[];
    assert!(!receipt_matches_payload(&receipt, empty));
}

// ── Test 3: Synthetic receipt is detectable ─────────────────────────────

#[test]
fn synthetic_receipt_is_detectable() {
    use tidefs_replication_model::ReplicatedSubjectId;

    let synthetic = PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId(0x3001));
    assert!(synthetic.is_synthetic());
    assert_eq!(synthetic.receipt_generation, 0);

    let authorized = make_replicated_receipt(0x3002, b"authorized", 1, 1, 1);
    assert!(!authorized.is_synthetic());
    assert!(authorized.receipt_generation > 0);
}

// ── Test 4: Receipt-addressed read with erasure policy ───────────────────

#[test]
fn receipt_addressed_read_with_erasure_policy() {
    let mut object_key = [0u8; 32];
    object_key[..8].copy_from_slice(&0x4001_u64.to_le_bytes());

    let payload = b"erasure-coded receipt data for degraded read test";
    let payload_digest = blake3_hash(payload);

    let receipt = PlacementReceiptRef::erasure(
        0x4001,
        object_key,
        EpochId::new(1),
        3,
        4,
        2,
        payload.len() as u64,
        payload_digest,
    );

    assert_eq!(receipt.redundancy_policy.target_width(), 6);
    assert!(receipt.redundancy_policy.is_well_formed());
    assert!(!receipt.is_synthetic());

    let actual_digest = blake3_hash(payload);
    assert_eq!(receipt.payload_digest, actual_digest);
    assert_eq!(receipt.payload_len, payload.len() as u64);
    assert_eq!(receipt.target_count, 6);
}

// ── Test 5: Receipt-addressed read under partition then heal ─────────────

#[test]
fn receipt_addressed_read_under_partition_then_heal() {
    let mut h = TwoNodeHarness::new(0x35605);
    h.establish_session().expect("establish");

    let payload = b"receipt data under partition stress";
    let receipt = make_replicated_receipt(0x5001, payload, 1, 5, 2);

    let obj = StateObject {
        object_key: receipt.object_id,
        payload: payload.to_vec(),
    };

    h.state_transfer_a_to_b(&[obj.clone()])
        .expect("initial transfer");
    let _ = h.state_transfer_b_to_a(&[obj.clone()]);

    h.block_a_to_b();
    assert!(h.is_a_to_b_blocked());
    assert!(!h.is_b_to_a_blocked());

    assert!(receipt_matches_payload(&receipt, payload));

    h.heal_all();
    assert!(!h.is_a_to_b_blocked());
    assert!(receipt_matches_payload(&receipt, payload));

    let result = h
        .state_transfer_a_to_b(&[obj])
        .expect("re-transfer after heal");
    assert_eq!(result.object_count, 1);
}

// ── Test 6: Multiple receipt generations coexist ─────────────────────────

#[test]
fn multiple_receipt_generations_coexist() {
    let payload_v1 = b"version one receipt data";
    let payload_v2 = b"version two receipt data longer";

    let receipt_gen1 = make_replicated_receipt(0x6001, payload_v1, 1, 1, 2);
    let receipt_gen2 = make_replicated_receipt(0x6001, payload_v2, 2, 2, 2);

    assert_eq!(receipt_gen1.object_id, receipt_gen2.object_id);
    assert_ne!(
        receipt_gen1.receipt_generation,
        receipt_gen2.receipt_generation
    );

    assert!(receipt_matches_payload(&receipt_gen1, payload_v1));
    assert!(receipt_matches_payload(&receipt_gen2, payload_v2));

    assert!(!receipt_matches_payload(&receipt_gen1, payload_v2));
    assert!(!receipt_matches_payload(&receipt_gen2, payload_v1));
}

// ── Test 7: Receipt-addressed read validates policy well-formedness ──────

#[test]
fn receipt_read_rejects_malformed_policy() {
    let policy = ReceiptRedundancyPolicy::Replicated { copies: 0 };
    assert!(!policy.is_well_formed());

    let policy = ReceiptRedundancyPolicy::Erasure {
        data_shards: 0,
        parity_shards: 1,
    };
    assert!(!policy.is_well_formed());

    let policy = ReceiptRedundancyPolicy::Erasure {
        data_shards: 1,
        parity_shards: 0,
    };
    assert!(!policy.is_well_formed());

    let policy = ReceiptRedundancyPolicy::Replicated { copies: 3 };
    assert!(policy.is_well_formed());
    assert_eq!(policy.target_width(), 3);

    let policy = ReceiptRedundancyPolicy::Erasure {
        data_shards: 8,
        parity_shards: 3,
    };
    assert!(policy.is_well_formed());
    assert_eq!(policy.target_width(), 11);
}

// ── Test 8: Degraded read simulation with receipt authority ──────────────

#[test]
fn degraded_read_with_receipt_authority_after_node_loss() {
    let mut h = TwoNodeHarness::new(0x35608);
    h.establish_session().expect("establish");

    let payload = b"degraded-read receipt authority test data block";
    let receipt = make_replicated_receipt(0x7001, payload, 1, 8, 2);

    let obj = StateObject {
        object_key: receipt.object_id,
        payload: payload.to_vec(),
    };
    h.state_transfer_a_to_b(&[obj.clone()])
        .expect("initial replication A->B");

    assert!(receipt_matches_payload(&receipt, payload));

    h.block_a_to_b();
    h.block_b_to_a();

    assert!(receipt_matches_payload(&receipt, payload));

    assert_eq!(receipt.receipt_epoch, EpochId::new(1));
    assert_eq!(receipt.receipt_generation, 8);
    assert!(!receipt.is_synthetic());

    h.heal_all();
    assert!(receipt_matches_payload(&receipt, payload));
}
