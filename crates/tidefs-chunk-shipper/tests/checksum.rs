// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Checksum verification tests: digest derivation, correctness assertion,
//! mismatch rejection at staging-area level, and mismatch propagation
//! through the full pipeline.

use tidefs_chunk_shipper::*;
use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_replication_model::{
    lane_class_discriminant, FlowCommitClass, ObjectDigest, ReplicaTransferTicketRecord,
    ReplicatedReceiptId, ReplicatedSubjectId, TransferLinkAssignment, TransferScheduleRecord,
};

fn member(n: u64) -> MemberId {
    MemberId(n)
}
fn digest(v: u64) -> ObjectDigest {
    ObjectDigest(v)
}
fn rid(n: u64) -> ReplicatedReceiptId {
    ReplicatedReceiptId(n)
}
fn sid(n: u64) -> ReplicatedSubjectId {
    ReplicatedSubjectId(n)
}

// ═══════════════════════════════════════════════════
// derive_receive_digest correctness
// ═══════════════════════════════════════════════════

#[test]
fn test_derive_receive_digest_empty_payload_is_nonzero() {
    // BLAKE3 produces well-distributed output; even empty input has nonzero digest.
    let d = derive_receive_digest(b"");
    assert_ne!(d.0, 0);
}

#[test]
fn test_derive_receive_digest_single_byte_is_stable() {
    // Same input must produce the same digest every time.
    let d1 = derive_receive_digest(b"A");
    let d2 = derive_receive_digest(b"A");
    assert_eq!(d1, d2);
}

#[test]
fn test_derive_receive_digest_known_payload_is_stable() {
    let d1 = derive_receive_digest(b"hello");
    let d2 = derive_receive_digest(b"hello");
    assert_eq!(d1, d2);
}

#[test]
fn test_derive_receive_digest_deterministic() {
    let payload = b"tidefs checksum verification test";
    let d1 = derive_receive_digest(payload);
    let d2 = derive_receive_digest(payload);
    assert_eq!(d1, d2);
}

#[test]
fn test_derive_receive_digest_different_payloads_differ() {
    let d1 = derive_receive_digest(b"hello");
    let d2 = derive_receive_digest(b"world");
    assert_ne!(d1, d2);
}

#[test]
fn test_derive_receive_digest_identical_content_same_digest() {
    let a = vec![0xFFu8; 256];
    let b = vec![0xFFu8; 256];
    assert_eq!(derive_receive_digest(&a), derive_receive_digest(&b));
}

#[test]
fn test_derive_receive_digest_different_lengths_differ() {
    // Different payloads (even all-FF of different lengths) produce different digests.
    let d1 = derive_receive_digest(&[0xFFu8; 3]);
    let d2 = derive_receive_digest(&[0xFFu8; 4]);
    assert_ne!(d1, d2);
}

#[test]
fn test_derive_receive_digest_byte_order_sensitive() {
    // Changing byte order changes the digest.
    let d1 = derive_receive_digest(b"ab");
    let d2 = derive_receive_digest(b"ba");
    assert_ne!(d1, d2);
}

// ═══════════════════════════════════════════════════
// derive_anchor_hash
// ═══════════════════════════════════════════════════

#[test]
fn test_derive_anchor_hash_deterministic() {
    let h1 = derive_anchor_hash(100, 50);
    let h2 = derive_anchor_hash(100, 50);
    assert_eq!(h1, h2);
}

#[test]
fn test_derive_anchor_hash_different_inputs_differ() {
    let h1 = derive_anchor_hash(1, 2);
    let h2 = derive_anchor_hash(2, 1);
    assert_ne!(h1, h2);
}

#[test]
fn test_derive_anchor_hash_with_zero_seed() {
    let h = derive_anchor_hash(42, 0);
    assert_eq!(h, 42u64.wrapping_mul(0x9E37_79B9_7F4A_7C15));
}

// ═══════════════════════════════════════════════════
// ChunkAcceptResult for matching and mismatching digests
// ═══════════════════════════════════════════════════

#[test]
fn test_staging_area_accept_matching_digest() {
    let mut area = ChunkStagingArea::new();
    let chunk = ReceivedChunk {
        chunk_id: 1,
        subject_ref: sid(10),
        payload: b"data".to_vec(),
        source_digest: digest(100),
        received_digest: digest(100),
        range_start: 0,
        range_end: 4,
        verified: false,
    };
    let result = area.accept(chunk);
    assert_eq!(result, ChunkAcceptResult::Accepted);
    assert_eq!(area.pending_count(), 1);
    assert_eq!(area.total_bytes_staged, 4);
    assert!(area.rejected_chunks.is_empty());
}

#[test]
fn test_staging_area_accept_mismatching_digest() {
    let mut area = ChunkStagingArea::new();
    let chunk = ReceivedChunk {
        chunk_id: 2,
        subject_ref: sid(10),
        payload: b"corrupt".to_vec(),
        source_digest: digest(0xAAA),
        received_digest: digest(0xBBB),
        range_start: 0,
        range_end: 7,
        verified: false,
    };
    let result = area.accept(chunk);
    assert_eq!(result, ChunkAcceptResult::RejectedDigestMismatch);
    assert_eq!(area.pending_count(), 0);
    assert_eq!(area.total_bytes_staged, 0);
    assert_eq!(area.rejected_chunks, vec![2]);
}

#[test]
fn test_staging_area_mixed_accept_and_reject() {
    let mut area = ChunkStagingArea::new();

    area.accept(ReceivedChunk {
        chunk_id: 1,
        subject_ref: sid(10),
        payload: b"ok".to_vec(),
        source_digest: digest(10),
        received_digest: digest(10),
        range_start: 0,
        range_end: 2,
        verified: false,
    });
    area.accept(ReceivedChunk {
        chunk_id: 2,
        subject_ref: sid(10),
        payload: b"bad".to_vec(),
        source_digest: digest(20),
        received_digest: digest(99),
        range_start: 0,
        range_end: 3,
        verified: false,
    });
    area.accept(ReceivedChunk {
        chunk_id: 3,
        subject_ref: sid(10),
        payload: b"yes".to_vec(),
        source_digest: digest(30),
        received_digest: digest(30),
        range_start: 0,
        range_end: 3,
        verified: false,
    });

    assert_eq!(area.pending_count(), 2);
    assert_eq!(area.total_bytes_staged, 5);
    assert_eq!(area.rejected_chunks, vec![2]);
}

#[test]
fn test_staging_area_multiple_rejects_are_recorded() {
    let mut area = ChunkStagingArea::new();
    for i in 1u64..=5 {
        area.accept(ReceivedChunk {
            chunk_id: i,
            subject_ref: sid(10),
            payload: vec![i as u8],
            source_digest: digest(i),
            received_digest: digest(i + 100),
            range_start: 0,
            range_end: 1,
            verified: false,
        });
    }
    assert_eq!(area.pending_count(), 0);
    assert_eq!(area.rejected_chunks, vec![1, 2, 3, 4, 5]);
}

// ═══════════════════════════════════════════════════
// Mismatch propagation through the full pipeline
// ═══════════════════════════════════════════════════

#[test]
fn test_full_pipeline_with_matching_digests_all_accepted() {
    let sched = TransferScheduleRecord {
        ticket: ReplicaTransferTicketRecord {
            ticket_id: rid(1),
            intent_ref: rid(100),
            subject_refs: vec![sid(10), sid(20)],
            source_anchor_set: vec![member(1)],
            target_ref: member(2),
            pin_budget_ref: rid(200),
            freshness_fence_ref: 0,
            expiry: 500,
        },
        assignment: TransferLinkAssignment {
            source: member(1),
            target: member(2),
            lane_class: lane_class_discriminant::BACKGROUND,
            priority: 0,
        },
        flow_class: FlowCommitClass::Relocation,
    };

    let payloads = vec![
        (1u64, b"chunk-a".to_vec(), derive_receive_digest(b"chunk-a")),
        (2u64, b"chunk-b".to_vec(), derive_receive_digest(b"chunk-b")),
    ];

    let report = execute_chunk_shipping_pipeline(
        &sched,
        &payloads,
        EpochId(1),
        &[member(1)],
        3,
        false,
        true,
    );

    assert_eq!(report.chunks_succeeded, 2);
    assert_eq!(report.chunks_failed, 0);
    assert_eq!(report.bytes_received, 14);
}
