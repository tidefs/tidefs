//! Framing / pipeline state-machine tests: verify that phase transitions
//! through stage→stream→receive→complete are correct, session states
//! advance properly, and failure/expiry paths leave the session in
//! terminal states.

use tidefs_chunk_shipper::*;
use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_replication_model::{
    lane_class_discriminant, FlowCommitClass, ObjectDigest, ReplicaTransferTicketRecord,
    ReplicatedReceiptId, ReplicatedSubjectId, TransferLinkAssignment, TransferScheduleRecord,
    VerificationStatus,
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

fn test_ticket() -> ReplicaTransferTicketRecord {
    ReplicaTransferTicketRecord {
        ticket_id: rid(1),
        intent_ref: rid(100),
        subject_refs: vec![sid(10), sid(20)],
        source_anchor_set: vec![member(1)],
        target_ref: member(2),
        pin_budget_ref: rid(200),
        freshness_fence_ref: 0,
        expiry: 500,
    }
}

fn test_chunk_payloads() -> Vec<(u64, Vec<u8>, ObjectDigest)> {
    vec![
        (1, b"chunk-one".to_vec(), digest(0x100)),
        (2, b"chunk-two".to_vec(), digest(0x200)),
        (3, b"chunk-three".to_vec(), digest(0x300)),
    ]
}

fn test_schedule() -> TransferScheduleRecord {
    TransferScheduleRecord {
        ticket: test_ticket(),
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
// Session state transitions
// ═══════════════════════════════════════════════════

#[test]
fn test_session_starts_in_created_state() {
    let session =
        ChunkShippingSession::new(1, test_ticket(), ChunkShippingTransport::TcpFallback, 3);
    assert_eq!(session.state, ShippingSessionState::Created);
    assert_eq!(session.bytes_moved, 0);
    assert!(session.transfer_receipt.is_none());
    assert!(session.progress.is_empty());
}

#[test]
fn test_session_transitions_to_streaming_on_stream() {
    let ticket = test_ticket();
    let buffers = stage_replica_chunks_for_transport(
        &ticket,
        &test_chunk_payloads(),
        ChunkShippingTransport::TcpFallback,
    );
    let mut session = ChunkShippingSession::new(1, ticket, ChunkShippingTransport::TcpFallback, 3);

    let _ = stream_replica_chunks_under_ticket(&mut session, &buffers);
    assert_eq!(session.state, ShippingSessionState::Streaming);
}

#[test]
fn test_session_transitions_to_completed_on_complete() {
    let ticket = test_ticket();
    let buffers = stage_replica_chunks_for_transport(
        &ticket,
        &test_chunk_payloads(),
        ChunkShippingTransport::TcpFallback,
    );
    let mut session = ChunkShippingSession::new(1, ticket, ChunkShippingTransport::TcpFallback, 3);
    let _ = stream_replica_chunks_under_ticket(&mut session, &buffers);

    let receipt = session.complete(EpochId(42), &[member(1), member(2)]);
    assert_eq!(session.state, ShippingSessionState::Completed);
    assert!(session.transfer_receipt.is_some());
    assert_eq!(receipt.completion_epoch.0, 42);
}

#[test]
fn test_session_fail_transitions_to_failed() {
    let mut session =
        ChunkShippingSession::new(1, test_ticket(), ChunkShippingTransport::TcpFallback, 3);
    session.fail("connection refused".to_string());

    match &session.state {
        ShippingSessionState::Failed(reason) => assert_eq!(reason, "connection refused"),
        other => panic!("Expected Failed, got {other:?}"),
    }
}

#[test]
fn test_session_expire_transitions_to_expired() {
    let mut session =
        ChunkShippingSession::new(1, test_ticket(), ChunkShippingTransport::TcpFallback, 3);
    session.expire();
    assert_eq!(session.state, ShippingSessionState::Expired);
}

#[test]
fn test_session_failed_can_still_be_completed() {
    let mut session =
        ChunkShippingSession::new(1, test_ticket(), ChunkShippingTransport::TcpFallback, 3);
    session.fail("temporary issue".to_string());

    let receipt = session.complete(EpochId(99), &[member(1)]);
    assert_eq!(session.state, ShippingSessionState::Completed);
    assert!(session.transfer_receipt.is_some());
    assert_eq!(receipt.completion_epoch.0, 99);
}

// ═══════════════════════════════════════════════════
// Pipeline phase transitions
// ═══════════════════════════════════════════════════

#[test]
fn test_pipeline_stage_phase_is_staged() {
    let ticket = test_ticket();
    let buffers = stage_replica_chunks_for_transport(
        &ticket,
        &test_chunk_payloads(),
        ChunkShippingTransport::TcpFallback,
    );
    assert!(buffers.iter().all(|b| b.phase == ChunkStagingPhase::Staged));
}

#[test]
fn test_pipeline_staging_phase_transition_on_stream() {
    let ticket = test_ticket();
    let buffers = stage_replica_chunks_for_transport(
        &ticket,
        &test_chunk_payloads(),
        ChunkShippingTransport::TcpFallback,
    );

    let mut session =
        ChunkShippingSession::new(1, ticket.clone(), ChunkShippingTransport::TcpFallback, 3);
    assert_eq!(session.state, ShippingSessionState::Created);

    let _ = stream_replica_chunks_under_ticket(&mut session, &buffers);
    assert_eq!(session.state, ShippingSessionState::Streaming);
}

#[test]
fn test_pipeline_staging_buffers_not_staged_becomes_failed_in_progress() {
    use tidefs_chunk_shipper::ChunkStagingPhase;

    let ticket = test_ticket();
    let mut buffers = stage_replica_chunks_for_transport(
        &ticket,
        &test_chunk_payloads(),
        ChunkShippingTransport::TcpFallback,
    );
    buffers[1].phase = ChunkStagingPhase::Failed;

    let mut session = ChunkShippingSession::new(1, ticket, ChunkShippingTransport::TcpFallback, 3);
    let (transferred, _bytes_moved) = stream_replica_chunks_under_ticket(&mut session, &buffers);

    assert_eq!(transferred.len(), 2);
    assert_eq!(session.progress[&2].phase, ChunkTransferPhase::Failed);
    assert_eq!(session.progress[&1].phase, ChunkTransferPhase::Completed);
}

#[test]
fn test_pipeline_complete_transitions_state() {
    let sched = test_schedule();
    let report = execute_chunk_shipping_pipeline(
        &sched,
        &test_chunk_payloads(),
        EpochId(42),
        &[member(1), member(2)],
        3,
        false,
        true,
    );

    assert_eq!(report.chunks_succeeded, 3);
    assert!(report.transfer_receipt.is_some());
    assert_eq!(
        report.transfer_receipt.as_ref().unwrap().completion_epoch.0,
        42
    );
}

// ═══════════════════════════════════════════════════
// Transport selection in full pipeline
// ═══════════════════════════════════════════════════

#[test]
fn test_full_pipeline_rdma_cross_node() {
    let sched = test_schedule();
    let report = execute_chunk_shipping_pipeline(
        &sched,
        &test_chunk_payloads(),
        EpochId(1),
        &[member(1)],
        3,
        true,
        false,
    );
    assert_eq!(
        report.transport,
        ChunkShippingTransport::RdmaDirectDataPlacement
    );
}

#[test]
fn test_full_pipeline_io_uring_same_node() {
    let mut t = test_ticket();
    t.source_anchor_set = vec![member(1)];
    t.target_ref = member(1);
    let sched = TransferScheduleRecord {
        ticket: t,
        assignment: TransferLinkAssignment {
            source: member(1),
            target: member(1),
            lane_class: lane_class_discriminant::BACKGROUND,
            priority: 0,
        },
        flow_class: FlowCommitClass::Relocation,
    };
    let report = execute_chunk_shipping_pipeline(
        &sched,
        &test_chunk_payloads(),
        EpochId(1),
        &[member(1)],
        3,
        false,
        true,
    );
    assert_eq!(report.transport, ChunkShippingTransport::IoUringSplice);
}

// ═══════════════════════════════════════════════════
// Multiple sessions with different transport paths
// ═══════════════════════════════════════════════════

#[test]
fn test_multiple_chunk_sessions_independent_state() {
    let ticket = test_ticket();
    let payloads = test_chunk_payloads();
    let buffers =
        stage_replica_chunks_for_transport(&ticket, &payloads, ChunkShippingTransport::TcpFallback);

    let mut s1 =
        ChunkShippingSession::new(1, ticket.clone(), ChunkShippingTransport::TcpFallback, 3);
    let mut s2 = ChunkShippingSession::new(
        2,
        ticket,
        ChunkShippingTransport::RdmaDirectDataPlacement,
        5,
    );

    let _ = stream_replica_chunks_under_ticket(&mut s1, &buffers);
    assert_eq!(s1.state, ShippingSessionState::Streaming);
    assert_eq!(s2.state, ShippingSessionState::Created);

    s1.complete(EpochId(1), &[member(1)]);
    assert_eq!(s1.state, ShippingSessionState::Completed);
    assert_eq!(s2.state, ShippingSessionState::Created);

    s2.fail("test abort".to_string());
    match &s2.state {
        ShippingSessionState::Failed(reason) => assert_eq!(reason, "test abort"),
        _ => panic!(),
    }
}

#[test]
fn test_session_max_retries_preserved() {
    let session =
        ChunkShippingSession::new(1, test_ticket(), ChunkShippingTransport::TcpFallback, 7);
    assert_eq!(session.max_retries, 7);
}

// ═══════════════════════════════════════════════════
// advance_chunks_after_verification state transitions
// ═══════════════════════════════════════════════════

#[test]
fn test_advance_chunks_verifying_to_committed_on_verified() {
    use tidefs_replication_model::{ReplicaChunkState, ReplicaChunkStateRecord};

    let records = vec![ReplicaChunkStateRecord {
        chunk_id: 1,
        subject_ref: sid(10),
        source_ref: member(1),
        target_ref: member(2),
        range_ref: 100,
        digest: digest(0x500),
        state: ReplicaChunkState::Verifying,
        transfer_ticket_ref: rid(1),
        verification_receipt_ref: rid(1),
    }];
    let result = advance_chunks_after_verification(&records, VerificationStatus::Verified);
    assert_eq!(result[0].state, ReplicaChunkState::Committed);
}

#[test]
fn test_advance_chunks_verifying_to_failed_on_digest_mismatch() {
    use tidefs_replication_model::{ReplicaChunkState, ReplicaChunkStateRecord};

    let records = vec![ReplicaChunkStateRecord {
        chunk_id: 1,
        subject_ref: sid(10),
        source_ref: member(1),
        target_ref: member(2),
        range_ref: 100,
        digest: digest(0x500),
        state: ReplicaChunkState::Verifying,
        transfer_ticket_ref: rid(1),
        verification_receipt_ref: rid(1),
    }];
    let result = advance_chunks_after_verification(&records, VerificationStatus::DigestMismatch);
    assert_eq!(result[0].state, ReplicaChunkState::Failed);
}

#[test]
fn test_advance_chunks_transferring_to_committed_on_verified() {
    use tidefs_replication_model::{ReplicaChunkState, ReplicaChunkStateRecord};

    let records = vec![ReplicaChunkStateRecord {
        chunk_id: 1,
        subject_ref: sid(10),
        source_ref: member(1),
        target_ref: member(2),
        range_ref: 100,
        digest: digest(0x500),
        state: ReplicaChunkState::Transferring,
        transfer_ticket_ref: rid(1),
        verification_receipt_ref: rid(1),
    }];
    let result = advance_chunks_after_verification(&records, VerificationStatus::Verified);
    assert_eq!(result[0].state, ReplicaChunkState::Committed);
}

#[test]
fn test_advance_chunks_transferring_to_failed_on_witness_insufficient() {
    use tidefs_replication_model::{ReplicaChunkState, ReplicaChunkStateRecord};

    let records = vec![ReplicaChunkStateRecord {
        chunk_id: 1,
        subject_ref: sid(10),
        source_ref: member(1),
        target_ref: member(2),
        range_ref: 100,
        digest: digest(0x500),
        state: ReplicaChunkState::Transferring,
        transfer_ticket_ref: rid(1),
        verification_receipt_ref: rid(1),
    }];
    let result =
        advance_chunks_after_verification(&records, VerificationStatus::WitnessInsufficient);
    assert_eq!(result[0].state, ReplicaChunkState::Failed);
}

#[test]
fn test_advance_chunks_pending_to_cancelled() {
    use tidefs_replication_model::{ReplicaChunkState, ReplicaChunkStateRecord};

    let records = vec![ReplicaChunkStateRecord {
        chunk_id: 1,
        subject_ref: sid(10),
        source_ref: member(1),
        target_ref: member(2),
        range_ref: 100,
        digest: digest(0x500),
        state: ReplicaChunkState::Pending,
        transfer_ticket_ref: rid(1),
        verification_receipt_ref: rid(1),
    }];
    let result = advance_chunks_after_verification(&records, VerificationStatus::Verified);
    assert_eq!(result[0].state, ReplicaChunkState::Cancelled);
}

#[test]
fn test_advance_chunks_failed_remains_failed() {
    use tidefs_replication_model::{ReplicaChunkState, ReplicaChunkStateRecord};

    let records = vec![ReplicaChunkStateRecord {
        chunk_id: 1,
        subject_ref: sid(10),
        source_ref: member(1),
        target_ref: member(2),
        range_ref: 100,
        digest: digest(0x500),
        state: ReplicaChunkState::Failed,
        transfer_ticket_ref: rid(1),
        verification_receipt_ref: rid(1),
    }];
    let result = advance_chunks_after_verification(&records, VerificationStatus::Verified);
    assert_eq!(result[0].state, ReplicaChunkState::Failed);
}
