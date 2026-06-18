// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Serde round-trip tests: every public type in tidefs-chunk-shipper must
//! survive encode→decode symmetry.

use tidefs_chunk_shipper::*;
use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_replication_model::{
    ObjectDigest, ReplicaChunkState, ReplicaChunkStateRecord, ReplicaTransferReceipt,
    ReplicaTransferTicketRecord, ReplicatedReceiptId, ReplicatedSubjectId,
};

fn round_trip<T: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug + PartialEq>(
    val: &T,
) {
    let json = serde_json::to_string(val).expect("serialize failed");
    let back: T = serde_json::from_str(&json).expect("deserialize failed");
    assert_eq!(
        *val,
        back,
        "round-trip mismatch for {}: json={}",
        std::any::type_name::<T>(),
        json
    );
}

// ── Helper constructors ──

fn subject_id() -> ReplicatedSubjectId {
    ReplicatedSubjectId(42)
}
fn receipt_id() -> ReplicatedReceiptId {
    ReplicatedReceiptId(100)
}
fn digest(v: u64) -> ObjectDigest {
    ObjectDigest(v)
}
fn member(n: u64) -> MemberId {
    MemberId(n)
}

fn ticket_record() -> ReplicaTransferTicketRecord {
    ReplicaTransferTicketRecord {
        ticket_id: receipt_id(),
        intent_ref: ReplicatedReceiptId(200),
        subject_refs: vec![subject_id()],
        source_anchor_set: vec![member(1)],
        target_ref: member(2),
        pin_budget_ref: ReplicatedReceiptId(300),
        freshness_fence_ref: 0,
        expiry: 500,
    }
}

fn transfer_receipt() -> ReplicaTransferReceipt {
    ReplicaTransferReceipt {
        receipt_id: receipt_id(),
        ticket_ref: receipt_id(),
        bytes_moved: 1024,
        source_anchor_hash: 0xABCD,
        target_anchor_hash: 0xEF01,
        completion_epoch: EpochId(10),
        worker_refs: vec![member(1), member(2)],
    }
}

// Enum round-trip tests
// ═══════════════════════════════════════════════════

#[test]
fn rt_chunk_shipping_transport_all_variants() {
    round_trip(&ChunkShippingTransport::RdmaDirectDataPlacement);
    round_trip(&ChunkShippingTransport::IoUringSplice);
    round_trip(&ChunkShippingTransport::TcpFallback);
}

#[test]
fn rt_chunk_staging_phase_all_variants() {
    round_trip(&ChunkStagingPhase::Pending);
    round_trip(&ChunkStagingPhase::Staging);
    round_trip(&ChunkStagingPhase::Staged);
    round_trip(&ChunkStagingPhase::Failed);
    round_trip(&ChunkStagingPhase::Cancelled);
}

#[test]
fn rt_chunk_transfer_phase_all_variants() {
    round_trip(&ChunkTransferPhase::Pending);
    round_trip(&ChunkTransferPhase::Staged);
    round_trip(&ChunkTransferPhase::InFlight);
    round_trip(&ChunkTransferPhase::Completed);
    round_trip(&ChunkTransferPhase::Failed);
    round_trip(&ChunkTransferPhase::Retrying);
}

#[test]
fn rt_chunk_accept_result_all_variants() {
    round_trip(&ChunkAcceptResult::Accepted);
    round_trip(&ChunkAcceptResult::RejectedDigestMismatch);
}

#[test]
fn rt_shipping_session_state_all_variants() {
    round_trip(&ShippingSessionState::Created);
    round_trip(&ShippingSessionState::Staging);
    round_trip(&ShippingSessionState::Streaming);
    round_trip(&ShippingSessionState::Completed);
    round_trip(&ShippingSessionState::Failed("network timeout".into()));
    round_trip(&ShippingSessionState::Expired);
}

#[test]
fn rt_chunk_ship_failure_all_variants() {
    round_trip(&ChunkShipFailure::SourceUnreadable("disk fault".into()));
    round_trip(&ChunkShipFailure::TransportError("connection reset".into()));
    round_trip(&ChunkShipFailure::TargetUnwritable("ENOSPC".into()));
    round_trip(&ChunkShipFailure::DigestMismatch {
        expected: digest(0xAAA),
        received: digest(0xBBB),
    });
    round_trip(&ChunkShipFailure::TicketExpired {
        ticket_id: receipt_id(),
        expiry_epoch: 42,
        current_epoch: 50,
    });
    round_trip(&ChunkShipFailure::BudgetExhausted {
        budget_ref: receipt_id(),
    });
    round_trip(&ChunkShipFailure::Cancelled);
}

#[test]
fn rt_chunk_shipping_state_all_variants() {
    round_trip(&ChunkShippingState::Idle);
    round_trip(&ChunkShippingState::Staging);
    round_trip(&ChunkShippingState::Streaming);
    round_trip(&ChunkShippingState::Receiving);
    round_trip(&ChunkShippingState::Verifying);
    round_trip(&ChunkShippingState::Complete);
    round_trip(&ChunkShippingState::Failed);
}

// ═══════════════════════════════════════════════════
// Struct round-trip tests
// ═══════════════════════════════════════════════════

#[test]
fn rt_chunk_staging_buffer() {
    let buf = ChunkStagingBuffer::new(
        1,
        subject_id(),
        0,
        100,
        b"payload".to_vec(),
        digest(0x123),
        ChunkShippingTransport::TcpFallback,
    );
    round_trip(&buf);
}

#[test]
fn rt_chunk_transfer_progress() {
    let mut p = ChunkTransferProgress::new(7, subject_id(), 1000);
    p.bytes_staged = 500;
    p.bytes_transferred = 300;
    p.phase = ChunkTransferPhase::InFlight;
    p.failure_count = 2;
    p.failure_reason = Some("timeout".into());
    round_trip(&p);
}

#[test]
fn rt_received_chunk() {
    let rc = ReceivedChunk {
        chunk_id: 1,
        subject_ref: subject_id(),
        payload: b"data".to_vec(),
        source_digest: digest(0x100),
        received_digest: digest(0x100),
        range_start: 0,
        range_end: 4,
        verified: true,
    };
    round_trip(&rc);
}

#[test]
fn rt_chunk_staging_area() {
    let mut area = ChunkStagingArea::new();
    let rc = ReceivedChunk {
        chunk_id: 1,
        subject_ref: subject_id(),
        payload: b"data".to_vec(),
        source_digest: digest(0x100),
        received_digest: digest(0x100),
        range_start: 0,
        range_end: 4,
        verified: false,
    };
    area.accept(rc);
    area.accept(ReceivedChunk {
        chunk_id: 2,
        subject_ref: subject_id(),
        payload: b"more".to_vec(),
        source_digest: digest(0x200),
        received_digest: digest(0x999),
        range_start: 0,
        range_end: 4,
        verified: false,
    });
    round_trip(&area);
}

#[test]
fn rt_chunk_shipping_session() {
    let mut session = ChunkShippingSession::new(
        99,
        ticket_record(),
        ChunkShippingTransport::IoUringSplice,
        5,
    );
    let mut p = ChunkTransferProgress::new(1, subject_id(), 500);
    p.bytes_transferred = 250;
    session.progress.insert(1, p);
    session.bytes_moved = 250;
    session.transfer_receipt = Some(transfer_receipt());
    round_trip(&session);
}

#[test]
fn rt_chunk_shipping_report() {
    let report = ChunkShippingReport {
        session_id: 1,
        ticket_id: receipt_id(),
        bytes_staged: 1000,
        bytes_streamed: 800,
        bytes_received: 750,
        chunks_succeeded: 3,
        chunks_failed: 1,
        chunks_retried: 1,
        transport: ChunkShippingTransport::RdmaDirectDataPlacement,
        transfer_receipt: Some(transfer_receipt()),
        chunk_states: vec![ReplicaChunkStateRecord {
            chunk_id: 1,
            subject_ref: subject_id(),
            source_ref: member(1),
            target_ref: member(2),
            range_ref: 100,
            digest: digest(0x500),
            state: ReplicaChunkState::Committed,
            transfer_ticket_ref: receipt_id(),
            verification_receipt_ref: receipt_id(),
        }],
    };
    round_trip(&report);
}

#[test]
fn rt_empty_chunk_staging_area() {
    let area = ChunkStagingArea::new();
    round_trip(&area);
}

#[test]
fn rt_empty_chunk_shipping_session_created() {
    let session =
        ChunkShippingSession::new(1, ticket_record(), ChunkShippingTransport::TcpFallback, 3);
    round_trip(&session);
}
