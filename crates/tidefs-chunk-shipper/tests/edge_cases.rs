//! Edge case tests: zero-length payloads, maximum-size payloads,
//! empty chunk sequences, single-chunk shipments.

use tidefs_chunk_shipper::*;
use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_replication_model::{
    lane_class_discriminant, FlowCommitClass, ObjectDigest, ReplicaChunkState,
    ReplicaChunkStateRecord, ReplicaTransferTicketRecord, ReplicatedReceiptId, ReplicatedSubjectId,
    TransferLinkAssignment, TransferScheduleRecord, VerificationStatus,
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

fn ticket(subjects: Vec<ReplicatedSubjectId>) -> ReplicaTransferTicketRecord {
    ReplicaTransferTicketRecord {
        ticket_id: rid(1),
        intent_ref: rid(100),
        subject_refs: subjects,
        source_anchor_set: vec![member(1)],
        target_ref: member(2),
        pin_budget_ref: rid(200),
        freshness_fence_ref: 0,
        expiry: 500,
    }
}

fn schedule(subjects: Vec<ReplicatedSubjectId>) -> TransferScheduleRecord {
    TransferScheduleRecord {
        ticket: ticket(subjects),
        assignment: TransferLinkAssignment {
            source: member(1),
            target: member(2),
            lane_class: lane_class_discriminant::BACKGROUND,
            priority: 0,
        },
        flow_class: FlowCommitClass::Relocation,
    }
}

// ═══════════════════════════════════════════════════
// Zero-length payloads
// ═══════════════════════════════════════════════════

#[test]
fn test_zero_length_payload_stages_and_streams() {
    let payloads = vec![(1u64, vec![], derive_receive_digest(b""))];
    let t = ticket(vec![sid(10)]);

    let buffers =
        stage_replica_chunks_for_transport(&t, &payloads, ChunkShippingTransport::TcpFallback);
    assert_eq!(buffers.len(), 1);
    assert_eq!(buffers[0].len(), 0);
    assert!(buffers[0].is_empty());

    let mut session = ChunkShippingSession::new(1, t, ChunkShippingTransport::TcpFallback, 3);
    let (transferred, bytes_moved) = stream_replica_chunks_under_ticket(&mut session, &buffers);
    assert_eq!(bytes_moved, 0);
    assert_eq!(transferred.len(), 1);
    assert!(transferred[0].1.is_empty());

    assert_eq!(session.progress[&1].bytes_total, 0);
    assert!((session.progress[&1].progress_ratio() - 1.0).abs() < 1e-9);
}

#[test]
fn test_zero_length_payload_receive_and_verify() {
    let t = ticket(vec![sid(10)]);
    let transferred = vec![(1u64, vec![], derive_receive_digest(b""))];

    let staging_area =
        receive_replica_chunks_and_stage_for_verification(&transferred, &t.subject_refs);

    assert_eq!(staging_area.pending_count(), 1);
    assert_eq!(staging_area.total_bytes_staged, 0);
    assert!(staging_area.rejected_chunks.is_empty());
}

#[test]
fn test_zero_bytes_total_progress() {
    let p = ChunkTransferProgress::new(1, sid(10), 0);
    assert!((p.progress_ratio() - 1.0).abs() < 1e-9);
}

#[test]
fn test_zero_length_payload_full_pipeline() {
    let sched = schedule(vec![sid(10)]);
    let payloads = vec![(1u64, vec![], derive_receive_digest(b""))];

    let report = execute_chunk_shipping_pipeline(
        &sched,
        &payloads,
        EpochId(1),
        &[member(1)],
        3,
        false,
        true,
    );

    assert_eq!(report.bytes_staged, 0);
    assert_eq!(report.bytes_streamed, 0);
    assert_eq!(report.bytes_received, 0);
    assert_eq!(report.chunks_succeeded, 1);
}

// ═══════════════════════════════════════════════════
// Single-chunk shipments
// ═══════════════════════════════════════════════════

#[test]
fn test_single_chunk_shipment_full_pipeline() {
    let sched = schedule(vec![sid(10)]);
    let payloads = vec![(42u64, b"single-chunk".to_vec(), digest(0x555))];

    let report = execute_chunk_shipping_pipeline(
        &sched,
        &payloads,
        EpochId(1),
        &[member(1)],
        3,
        false,
        true,
    );

    assert_eq!(report.chunks_succeeded, 1);
    assert_eq!(report.chunks_failed, 0);
    assert_eq!(report.bytes_staged, 12);
    assert_eq!(report.chunks_retried, 0);
    assert!(report.transfer_receipt.is_some());
}

// ═══════════════════════════════════════════════════
// Maximum-size payloads
// ═══════════════════════════════════════════════════

#[test]
fn test_max_size_payload_1mb() {
    let sched = schedule(vec![sid(10)]);
    let big_payload = vec![0xABu8; 1_048_576]; // 1 MiB
    let payloads = vec![(1u64, big_payload, digest(0xDEAD))];

    let report = execute_chunk_shipping_pipeline(
        &sched,
        &payloads,
        EpochId(1),
        &[member(1)],
        3,
        false,
        true,
    );

    assert_eq!(report.bytes_staged, 1_048_576);
    assert_eq!(report.bytes_streamed, 1_048_576);
    assert_eq!(report.chunks_succeeded, 1);
}

#[test]
fn test_max_size_payload_10mb() {
    let sched = schedule(vec![sid(10)]);
    let big_payload = vec![0xCDu8; 10_485_760]; // 10 MiB
    let payloads = vec![(1u64, big_payload, digest(0xBEEF))];

    let report = execute_chunk_shipping_pipeline(
        &sched,
        &payloads,
        EpochId(1),
        &[member(1)],
        3,
        false,
        true,
    );

    assert_eq!(report.bytes_staged, 10_485_760);
    assert_eq!(report.bytes_streamed, 10_485_760);
    assert_eq!(report.chunks_succeeded, 1);
}

// ═══════════════════════════════════════════════════
// Empty chunk sequences
// ═══════════════════════════════════════════════════

#[test]
fn test_empty_chunk_sequence_stage_produces_empty_vec() {
    let t = ticket(vec![]);
    let empty: Vec<(u64, Vec<u8>, ObjectDigest)> = vec![];

    let buffers =
        stage_replica_chunks_for_transport(&t, &empty, ChunkShippingTransport::TcpFallback);
    assert!(buffers.is_empty());
}

#[test]
fn test_empty_chunk_sequence_stream_produces_empty_vec() {
    let t = ticket(vec![]);
    let empty_buffers: Vec<ChunkStagingBuffer> = vec![];
    let mut session = ChunkShippingSession::new(1, t, ChunkShippingTransport::TcpFallback, 3);

    let (transferred, bytes_moved) =
        stream_replica_chunks_under_ticket(&mut session, &empty_buffers);

    assert!(transferred.is_empty());
    assert_eq!(bytes_moved, 0);
    assert_eq!(session.progress.len(), 0);
}

#[test]
fn test_empty_chunk_sequence_receive_produces_empty_area() {
    let empty: Vec<(u64, Vec<u8>, ObjectDigest)> = vec![];
    let staging_area = receive_replica_chunks_and_stage_for_verification(&empty, &[]);

    assert_eq!(staging_area.pending_count(), 0);
    assert_eq!(staging_area.total_bytes_staged, 0);
}

#[test]
fn test_empty_chunk_sequence_full_pipeline() {
    let sched = schedule(vec![]);
    let empty: Vec<(u64, Vec<u8>, ObjectDigest)> = vec![];

    let report =
        execute_chunk_shipping_pipeline(&sched, &empty, EpochId(1), &[member(1)], 3, false, true);

    assert_eq!(report.chunks_succeeded, 0);
    assert_eq!(report.bytes_staged, 0);
    assert_eq!(report.bytes_streamed, 0);
    assert_eq!(report.bytes_received, 0);
}

// ═══════════════════════════════════════════════════
// Session progress with zero total bytes (no chunks)
// ═══════════════════════════════════════════════════

#[test]
fn test_session_progress_ratio_zero_total_bytes() {
    let session =
        ChunkShippingSession::new(1, ticket(vec![]), ChunkShippingTransport::TcpFallback, 3);
    assert!((session.progress_ratio() - 0.0).abs() < 1e-9);
}

#[test]
fn test_session_total_bytes_with_no_progress() {
    let session =
        ChunkShippingSession::new(1, ticket(vec![]), ChunkShippingTransport::TcpFallback, 3);
    assert_eq!(session.total_bytes(), 0);
}

// ═══════════════════════════════════════════════════
// StagingBuffer is_empty / len
// ═══════════════════════════════════════════════════

#[test]
fn test_chunk_staging_buffer_is_empty_and_len() {
    let empty = ChunkStagingBuffer::new(
        1,
        sid(10),
        0,
        0,
        vec![],
        derive_receive_digest(b""),
        ChunkShippingTransport::TcpFallback,
    );
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);

    let nonempty = ChunkStagingBuffer::new(
        2,
        sid(10),
        0,
        5,
        b"hello".to_vec(),
        digest(1),
        ChunkShippingTransport::TcpFallback,
    );
    assert!(!nonempty.is_empty());
    assert_eq!(nonempty.len(), 5);
}

// ═══════════════════════════════════════════════════
// advance_chunks_after_verification edge cases
// ═══════════════════════════════════════════════════

#[test]
fn test_advance_chunks_empty_input() {
    let empty: Vec<ReplicaChunkStateRecord> = vec![];
    let result = advance_chunks_after_verification(&empty, VerificationStatus::Verified);
    assert!(result.is_empty());
}

#[test]
fn test_advance_chunks_committed_remains_committed() {
    let records = vec![ReplicaChunkStateRecord {
        chunk_id: 1,
        subject_ref: sid(10),
        source_ref: member(1),
        target_ref: member(2),
        range_ref: 100,
        digest: digest(0x500),
        state: ReplicaChunkState::Committed,
        transfer_ticket_ref: rid(1),
        verification_receipt_ref: rid(1),
    }];
    let result = advance_chunks_after_verification(&records, VerificationStatus::DigestMismatch);
    assert_eq!(result[0].state, ReplicaChunkState::Committed);
}

#[test]
fn test_advance_chunks_cancelled_remains_cancelled() {
    let records = vec![ReplicaChunkStateRecord {
        chunk_id: 1,
        subject_ref: sid(10),
        source_ref: member(1),
        target_ref: member(2),
        range_ref: 100,
        digest: digest(0x500),
        state: ReplicaChunkState::Cancelled,
        transfer_ticket_ref: rid(1),
        verification_receipt_ref: rid(1),
    }];
    let result = advance_chunks_after_verification(&records, VerificationStatus::Verified);
    assert_eq!(result[0].state, ReplicaChunkState::Cancelled);
}
