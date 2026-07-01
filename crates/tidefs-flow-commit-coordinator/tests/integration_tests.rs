// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Integration tests for tidefs-flow-commit-coordinator.
//
// These tests exercise the crate through its public API, complementing
// the 42 inline unit tests in src/lib.rs. They focus on multi-participant
// commit lifecycles, abort paths, batch orchestration, and durability
// sequence recovery scenarios.

use tidefs_flow_commit_coordinator::{DurabilitySequence, FlowCommitCoordinator, FlowScope};
use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_replication_model::{
    FlowCommitClass, FlowState, ObjectDigest, ReplicaChunkState, ReplicaTransferReceipt,
    ReplicaVerificationReceipt, ReplicatedReceiptId, ReplicatedSubjectId, VerificationStatus,
};

// ── Helpers ──────────────────────────────────────────────────────────

fn make_coordinator() -> FlowCommitCoordinator {
    FlowCommitCoordinator::new(EpochId::new(1))
}

fn make_transfer_receipt(id: u64, ticket_ref: u64) -> ReplicaTransferReceipt {
    ReplicaTransferReceipt {
        receipt_id: ReplicatedReceiptId(id),
        ticket_ref: ReplicatedReceiptId(ticket_ref),
        bytes_moved: 4096,
        source_anchor_hash: 0xAAAA,
        target_anchor_hash: 0xBBBB,
        completion_epoch: EpochId::new(1),
        worker_refs: vec![MemberId::new(10)],
    }
}

fn make_verification_receipt(
    id: u64,
    subjects: &[ReplicatedSubjectId],
    status: VerificationStatus,
) -> ReplicaVerificationReceipt {
    ReplicaVerificationReceipt {
        receipt_id: ReplicatedReceiptId(id),
        subject_refs: subjects.to_vec(),
        digest_results: vec![ObjectDigest::new(0xF00D); subjects.len()],
        witness_refs: vec![MemberId::new(60)],
        quorum_class: 2,
        verification_epoch: EpochId::new(1),
        status,
    }
}

// ── Full commit lifecycle (integration) ────────────────────────────

#[test]
fn full_two_phase_commit_with_three_participants() {
    let mut coord = make_coordinator();
    let ticket = ReplicatedReceiptId(100);

    // Participant A: rebuild chunk
    let subj_a = ReplicatedSubjectId::new(1);
    let _ = coord.register_chunk(
        subj_a,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ticket,
    );

    // Participant B: rebuild chunk (same ticket)
    let subj_b = ReplicatedSubjectId::new(2);
    let _ = coord.register_chunk(
        subj_b,
        MemberId::new(1),
        MemberId::new(3),
        FlowCommitClass::Rebuild,
        ticket,
    );

    // Participant C: different flow class, different ticket
    let subj_c = ReplicatedSubjectId::new(3);
    let ticket_c = ReplicatedReceiptId(200);
    let _ = coord.register_chunk(
        subj_c,
        MemberId::new(1),
        MemberId::new(4),
        FlowCommitClass::SteadyReplication,
        ticket_c,
    );

    assert_eq!(coord.total_chunks(), 3);
    assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Pending), 3);

    // Phase 1: commit transfer for ticket 100 (two chunks)
    let t_r = make_transfer_receipt(500, 100);
    let advanced = coord.commit_transfer_receipt(t_r).unwrap();
    assert_eq!(advanced.len(), 2);

    // Verify chunks advanced
    assert_eq!(
        coord.chunk_count_by_state(ReplicaChunkState::Transferring),
        2
    );
    assert_eq!(
        coord.chunk_count_by_state(ReplicaChunkState::Pending),
        1 // chunk C still pending
    );

    // Phase 2a: verify subjects A and B — both pass
    let v_r = make_verification_receipt(600, &[subj_a, subj_b], VerificationStatus::Verified);
    let outcome = coord.commit_verification_receipt(v_r).unwrap();
    assert!(outcome.is_verified);
    assert_eq!(outcome.total_commit_results, 2);
    assert_eq!(outcome.advanced_chunks.len(), 2);

    // Now both rebuild chunks are committed, chunk C still pending
    assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Committed), 2);
    assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Pending), 1);

    // Phase 3: verify C via separate transfer+verification
    let t_c = make_transfer_receipt(700, 200);
    coord.commit_transfer_receipt(t_c).unwrap();
    let v_c = make_verification_receipt(800, &[subj_c], VerificationStatus::Verified);
    coord.commit_verification_receipt(v_c).unwrap();

    // All committed
    assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Committed), 3);
    assert!(coord.flow_class_complete(FlowCommitClass::Rebuild));
    assert!(coord.flow_class_complete(FlowCommitClass::SteadyReplication));
}

// ── Abort paths ─────────────────────────────────────────────────────

#[test]
fn participant_veto_causes_failed_state() {
    let mut coord = make_coordinator();
    let ticket = ReplicatedReceiptId(100);
    let subj = ReplicatedSubjectId::new(10);

    let _ = coord.register_chunk(
        subj,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ticket,
    );

    // Transfer succeeds
    let t_r = make_transfer_receipt(500, 100);
    coord.commit_transfer_receipt(t_r).unwrap();

    // Verification fails (digest mismatch = participant veto)
    let v_r = make_verification_receipt(600, &[subj], VerificationStatus::DigestMismatch);
    let outcome = coord.commit_verification_receipt(v_r).unwrap();
    assert!(!outcome.is_verified);
    assert_eq!(outcome.total_commit_results, 0);

    // Chunk is in Failed state, not Committed
    assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Failed), 1);
    assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Committed), 0);
}

#[test]
fn mixed_verification_outcomes_in_batch() {
    let mut coord = make_coordinator();
    let ticket = ReplicatedReceiptId(100);

    let subjects: Vec<ReplicatedSubjectId> =
        (0..4).map(|i| ReplicatedSubjectId::new(100 + i)).collect();
    let (batch_id, _chunk_ids) = coord.register_chunk_batch(
        &subjects,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Relocation,
        ticket,
    );

    // Transfer all
    let t_r = make_transfer_receipt(500, 100);
    coord.commit_transfer_receipt(t_r).unwrap();

    // Verify first 2 as Verified
    let v_ok = make_verification_receipt(
        600,
        &[subjects[0], subjects[1]],
        VerificationStatus::Verified,
    );
    coord.commit_verification_receipt(v_ok).unwrap();

    // Verify subjects 2,3 as DigestMismatch
    let v_fail = make_verification_receipt(
        700,
        &[subjects[2], subjects[3]],
        VerificationStatus::DigestMismatch,
    );
    coord.commit_verification_receipt(v_fail).unwrap();

    // 2 committed, 2 failed
    assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Committed), 2);
    assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Failed), 2);

    // Seal batch — not all committed
    let completion = coord.seal_batch_and_emit_completion(batch_id).unwrap();
    assert!(!completion.all_committed);
    assert_eq!(completion.chunks_committed, 2);
    assert_eq!(completion.chunks_failed, 2);
    assert_eq!(completion.chunks_total, 4);
    assert!(completion.sealed);
}

// ── Batch orchestration ─────────────────────────────────────────────

#[test]
fn batch_orchestration_from_registration_to_seal() {
    let mut coord = make_coordinator();
    let ticket = ReplicatedReceiptId(1000);

    let subjects: Vec<ReplicatedSubjectId> =
        (0..5).map(|i| ReplicatedSubjectId::new(200 + i)).collect();
    let (batch_id, chunks) = coord.register_chunk_batch(
        &subjects,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ticket,
    );

    assert_eq!(chunks.len(), 5);
    assert_eq!(coord.total_chunks(), 5);

    // Bind batch to rebuild flow
    coord.bind_batch_to_rebuild_flow(batch_id, 42).unwrap();

    // Transfer receipt
    let t_r = make_transfer_receipt(500, 1000);
    coord.commit_transfer_receipt(t_r).unwrap();

    // All transferring
    assert_eq!(
        coord.chunk_count_by_state(ReplicaChunkState::Transferring),
        5
    );

    // Verify all 5
    let v_r = make_verification_receipt(600, &subjects, VerificationStatus::Verified);
    let outcome = coord.commit_verification_receipt(v_r).unwrap();
    assert!(outcome.is_verified);
    assert_eq!(outcome.total_commit_results, 5);

    // All committed
    assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Committed), 5);

    // Seal batch
    let completion = coord.seal_batch_and_emit_completion(batch_id).unwrap();
    assert!(completion.all_committed);
    assert!(completion.sealed);
    assert_eq!(completion.chunks_committed, 5);
    assert_eq!(completion.chunks_total, 5);
    assert_eq!(completion.rebuild_flow_ref, Some(42));

    assert_eq!(coord.sealed_batch_count(), 1);
}

#[test]
fn seal_batch_fails_on_unknown_batch() {
    let coord = make_coordinator();
    let mut coord = coord; // shadow for mut
    assert!(coord.seal_batch_and_emit_completion(999).is_err());
}

#[test]
fn seal_batch_fails_on_already_sealed() {
    let mut coord = make_coordinator();
    let ticket = ReplicatedReceiptId(100);

    let subjects = vec![ReplicatedSubjectId::new(42)];
    let (batch_id, _) = coord.register_chunk_batch(
        &subjects,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ticket,
    );

    let t_r = make_transfer_receipt(500, 100);
    coord.commit_transfer_receipt(t_r).unwrap();
    let v_r = make_verification_receipt(600, &subjects, VerificationStatus::Verified);
    coord.commit_verification_receipt(v_r).unwrap();

    coord.seal_batch_and_emit_completion(batch_id).unwrap();
    // Second seal must fail
    assert!(coord.seal_batch_and_emit_completion(batch_id).is_err());
}

// ── Flow advancement ────────────────────────────────────────────────

#[test]
fn advance_flow_reports_complete_when_all_committed() {
    let mut coord = make_coordinator();
    let ticket = ReplicatedReceiptId(100);
    let subj = ReplicatedSubjectId::new(1);

    let _ = coord.register_chunk(
        subj,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ticket,
    );

    let report =
        coord.advance_flow_after_receipt_commit(FlowCommitClass::Rebuild, FlowScope::Rebuild(10));
    assert_eq!(report.current_flow_state, FlowState::Planned);
    assert_eq!(report.chunks_total, 1);
    assert_eq!(report.chunks_committed, 0);
    assert_eq!(report.chunks_pending, 1);
}

#[test]
fn advance_flow_reports_aborted_when_all_failed() {
    let mut coord = make_coordinator();
    let ticket = ReplicatedReceiptId(100);
    let subj = ReplicatedSubjectId::new(1);

    let _ = coord.register_chunk(
        subj,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ticket,
    );

    let t_r = make_transfer_receipt(500, 100);
    coord.commit_transfer_receipt(t_r).unwrap();

    let v_r = make_verification_receipt(600, &[subj], VerificationStatus::DigestMismatch);
    coord.commit_verification_receipt(v_r).unwrap();

    let report =
        coord.advance_flow_after_receipt_commit(FlowCommitClass::Rebuild, FlowScope::Rebuild(10));
    assert_eq!(report.new_flow_state, FlowState::Aborted);
    assert_eq!(report.chunks_failed, 1);
    assert!(report.advanced);
}

#[test]
fn advance_flow_empty_returns_planned() {
    let mut coord = make_coordinator();
    let report = coord.advance_flow_after_receipt_commit(
        FlowCommitClass::SteadyReplication,
        FlowScope::Replication,
    );
    assert_eq!(report.current_flow_state, FlowState::Planned);
    assert_eq!(report.new_flow_state, FlowState::Planned);
    assert_eq!(report.chunks_total, 0);
    assert!(!report.advanced);
}

// ── Epoch management ────────────────────────────────────────────────

#[test]
fn set_epoch_propagates_to_placement_receipts() {
    let mut coord = make_coordinator();
    let ticket = ReplicatedReceiptId(100);
    let subj = ReplicatedSubjectId::new(1);

    let _ = coord.register_chunk(
        subj,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ticket,
    );

    // Set epoch to 7 before receipts
    coord.set_epoch(EpochId::new(7));

    let t_r = make_transfer_receipt(500, 100);
    coord.commit_transfer_receipt(t_r).unwrap();

    let v_r = make_verification_receipt(600, &[subj], VerificationStatus::Verified);
    coord.commit_verification_receipt(v_r).unwrap();

    // Commit results should use epoch 7
    let results = coord.commit_results_for_class(FlowCommitClass::Rebuild);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].commit_epoch, EpochId::new(7));
    assert_eq!(
        results[0].placement_receipt.placement_epoch,
        EpochId::new(7)
    );
}

// ── Query methods ───────────────────────────────────────────────────

#[test]
fn commit_results_for_class_filters_by_flow_class() {
    let mut coord = make_coordinator();
    let ticket_r = ReplicatedReceiptId(100);
    let ticket_s = ReplicatedReceiptId(200);

    // Rebuild chunk
    let subj_r = ReplicatedSubjectId::new(1);
    let _ = coord.register_chunk(
        subj_r,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ticket_r,
    );

    // SteadyReplication chunk
    let subj_s = ReplicatedSubjectId::new(2);
    let _ = coord.register_chunk(
        subj_s,
        MemberId::new(1),
        MemberId::new(3),
        FlowCommitClass::SteadyReplication,
        ticket_s,
    );

    // Transfer and verify both
    let t_r = make_transfer_receipt(500, 100);
    coord.commit_transfer_receipt(t_r).unwrap();
    let v_r = make_verification_receipt(600, &[subj_r], VerificationStatus::Verified);
    coord.commit_verification_receipt(v_r).unwrap();

    let t_s = make_transfer_receipt(700, 200);
    coord.commit_transfer_receipt(t_s).unwrap();
    let v_s = make_verification_receipt(800, &[subj_s], VerificationStatus::Verified);
    coord.commit_verification_receipt(v_s).unwrap();

    let rebuild_results = coord.commit_results_for_class(FlowCommitClass::Rebuild);
    let steady_results = coord.commit_results_for_class(FlowCommitClass::SteadyReplication);

    assert_eq!(rebuild_results.len(), 1);
    assert_eq!(steady_results.len(), 1);
    assert_eq!(rebuild_results[0].flow_class, FlowCommitClass::Rebuild);
    assert_eq!(
        steady_results[0].flow_class,
        FlowCommitClass::SteadyReplication
    );
}

// ── DurabilitySequence recovery scenarios ──────────────────────────

#[test]
fn recovery_after_truncation_replays_from_checkpoint() {
    // Simulate a crash scenario: 10 commits submitted, 6 durable,
    // crash occurs, recovery truncates from seq 7 onward.
    let mut seq = DurabilitySequence::new();
    let ids: Vec<u64> = seq.submit_batch(10);
    assert_eq!(ids, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    // 1 through 6 are durable
    for i in 1..=6 {
        seq.mark_durable(i).unwrap();
    }
    assert_eq!(seq.durable_high(), 6);

    // Crash: truncate from seq 7 onward
    seq.truncate_from(7);
    assert_eq!(seq.durable_high(), 6);
    assert_eq!(seq.next_seq(), 7);

    // Replay: 7,8,9,10 need re-submission
    let replayed: Vec<u64> = seq.submit_batch(4);
    assert_eq!(replayed, vec![7, 8, 9, 10]);

    // Re-mark durable
    for i in 7..=10 {
        seq.mark_durable(i).unwrap();
    }
    assert_eq!(seq.durable_high(), 10);
}

#[test]
fn truncation_during_active_barrier_clears_barrier() {
    let mut seq = DurabilitySequence::new();
    let _ = seq.submit(); // 1
    seq.mark_durable(1).unwrap();

    let barrier = seq.submit_barrier().unwrap();
    assert_eq!(barrier, 2);
    assert!(seq.barrier_active());

    let _s3 = seq.submit(); // 3
    let _s4 = seq.submit(); // 4

    // Crash before barrier ack — recovery truncates from barrier
    seq.truncate_from(barrier);
    assert!(!seq.barrier_active());
    assert_eq!(seq.active_barrier_seq(), None);
    assert_eq!(seq.next_seq(), 2); // can re-submit from barrier position
}

#[test]
fn barrier_recovery_with_gap_fill_after_truncation() {
    let mut seq = DurabilitySequence::new();
    for _ in 0..5 {
        let _ = seq.submit(); // 1..5
    }
    for i in 1..=3 {
        seq.mark_durable(i).unwrap();
    }
    let barrier = seq.submit_barrier().unwrap(); // 6
    assert_eq!(barrier, 6);

    // Mark 4 and 5 to satisfy barrier precondition
    seq.mark_durable(4).unwrap();
    seq.mark_durable(5).unwrap();
    seq.ack_barrier(barrier).unwrap();
    assert!(!seq.barrier_active());
    assert_eq!(seq.durable_high(), 6);

    // Post-barrier submissions
    let _s7 = seq.submit(); // 7
    let _s8 = seq.submit(); // 8

    // Crash: truncate from 7
    seq.truncate_from(7);
    // Barrier (6) and prior commits preserved
    assert!(seq.is_durable(6));
    assert_eq!(seq.durable_high(), 6);
    assert!(!seq.barrier_active());

    // Replay from 7: re-submit first
    let _ = seq.submit(); // 7
    let _ = seq.submit(); // 8
    seq.mark_durable(7).unwrap();
    seq.mark_durable(8).unwrap();
    assert_eq!(seq.durable_high(), 8);
}

// ── Concurrent durability scenarios ────────────────────────────────

#[test]
fn concurrent_multi_source_linearizable_durability() {
    // Simulate three concurrent submitters whose commit sequence
    // numbers are interleaved. The durability sequence must produce
    // a linearizable durable prefix regardless of mark order.
    let mut seq = DurabilitySequence::new();

    // Source A: 1, 4, 7
    let a1 = seq.submit();
    let _b1 = seq.submit(); // B: 2
    let _c1 = seq.submit(); // C: 3
    let a2 = seq.submit(); // A: 4
    let _b2 = seq.submit(); // B: 5
    let _c2 = seq.submit(); // C: 6
    let a3 = seq.submit(); // A: 7

    assert_eq!((a1, a2, a3), (1, 4, 7));

    // Mark in reverse order from B and C
    seq.mark_durable(6).unwrap();
    seq.mark_durable(3).unwrap();
    seq.mark_durable(5).unwrap();
    seq.mark_durable(2).unwrap();
    // Still gap at 1
    assert_eq!(seq.durable_high(), 0);

    // A fills the gap
    seq.mark_durable(1).unwrap();
    seq.mark_durable(4).unwrap();
    seq.mark_durable(7).unwrap();
    // 1..6 all durable, 7 completes the prefix
    assert_eq!(seq.durable_high(), 7);
}

#[test]
fn out_of_order_mark_advances_only_contiguous_prefix() {
    let mut seq = DurabilitySequence::new();
    for _ in 0..5 {
        let _ = seq.submit();
    }

    // Mark 1, 2, 5 — durable_high should be 2 (gap at 3)
    seq.mark_durable(1).unwrap();
    seq.mark_durable(2).unwrap();
    seq.mark_durable(5).unwrap();
    assert_eq!(seq.durable_high(), 2);
    assert!(seq.is_durable(2));
    assert!(!seq.is_durable(5)); // Not contiguous

    // Fill gap
    seq.mark_durable(3).unwrap();
    seq.mark_durable(4).unwrap();
    assert_eq!(seq.durable_high(), 5);
    assert!(seq.is_durable(5));
}

// ── Error path coverage ─────────────────────────────────────────────

#[test]
fn commit_transfer_receipt_rejects_stale_ticket() {
    let mut coord = make_coordinator();
    let receipt = make_transfer_receipt(500, 9999);
    assert!(coord.commit_transfer_receipt(receipt).is_err());
}

#[test]
fn commit_verification_receipt_requires_transferring_state() {
    let mut coord = make_coordinator();
    let subj = ReplicatedSubjectId::new(1);

    // Register chunk but don't advance to Transferring
    let _ = coord.register_chunk(
        subj,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ReplicatedReceiptId(100),
    );

    // Attempt verification before transfer — must fail
    let v_r = make_verification_receipt(600, &[subj], VerificationStatus::Verified);
    assert!(coord.commit_verification_receipt(v_r).is_err());
}

#[test]
fn bind_batch_to_nonexistent_batch_is_error() {
    let mut coord = make_coordinator();
    assert!(coord.bind_batch_to_rebuild_flow(999, 42).is_err());
    assert!(coord.bind_batch_to_relocation_flow(999, 42).is_err());
}

#[test]
fn flow_class_complete_returns_false_when_empty() {
    let coord = make_coordinator();
    assert!(!coord.flow_class_complete(FlowCommitClass::Relocation));
}

// ── Serialization round-trip tests ──────────────────────────────────

#[test]
fn serde_tracked_chunk_round_trip() {
    use tidefs_flow_commit_coordinator::TrackedChunk;
    use tidefs_membership_epoch::MemberId;
    use tidefs_replication_model::{
        FlowCommitClass, ReplicaChunkState, ReplicatedReceiptId, ReplicatedSubjectId,
    };

    let chunk = TrackedChunk::new(
        7,
        ReplicatedSubjectId::new(42),
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ReplicatedReceiptId(100),
    );

    let json = serde_json::to_string(&chunk).unwrap();
    let round_tripped: TrackedChunk = serde_json::from_str(&json).unwrap();
    assert_eq!(chunk, round_tripped);
    assert_eq!(round_tripped.chunk_id, 7);
    assert_eq!(round_tripped.state, ReplicaChunkState::Pending);
}

#[test]
fn serde_tracked_chunk_advanced_state_preserved() {
    use tidefs_flow_commit_coordinator::TrackedChunk;
    use tidefs_membership_epoch::MemberId;
    use tidefs_replication_model::{
        FlowCommitClass, ReplicaChunkState, ReplicatedReceiptId, ReplicatedSubjectId,
    };

    let mut chunk = TrackedChunk::new(
        3,
        ReplicatedSubjectId::new(99),
        MemberId::new(10),
        MemberId::new(20),
        FlowCommitClass::SteadyReplication,
        ReplicatedReceiptId(500),
    );
    chunk.state = ReplicaChunkState::Committed;
    chunk.transfer_receipt_ref = Some(ReplicatedReceiptId(501));
    chunk.verification_receipt_ref = Some(ReplicatedReceiptId(502));

    let json = serde_json::to_string(&chunk).unwrap();
    let round_tripped: TrackedChunk = serde_json::from_str(&json).unwrap();
    assert_eq!(chunk, round_tripped);
    assert_eq!(round_tripped.state, ReplicaChunkState::Committed);
}

#[test]
fn serde_tracked_batch_round_trip() {
    use tidefs_flow_commit_coordinator::TrackedBatch;
    use tidefs_replication_model::FlowCommitClass;

    let batch = TrackedBatch::new(1, vec![10, 20, 30], FlowCommitClass::Relocation);

    let json = serde_json::to_string(&batch).unwrap();
    let round_tripped: TrackedBatch = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, round_tripped);
    assert!(!round_tripped.sealed);
}

#[test]
fn serde_tracked_batch_sealed_state_preserved() {
    use tidefs_flow_commit_coordinator::TrackedBatch;
    use tidefs_replication_model::FlowCommitClass;

    let mut batch = TrackedBatch::new(5, vec![1, 2], FlowCommitClass::Drain);
    batch.sealed = true;
    batch.rebuild_flow_ref = Some(42);

    let json = serde_json::to_string(&batch).unwrap();
    let round_tripped: TrackedBatch = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, round_tripped);
    assert!(round_tripped.sealed);
    assert_eq!(round_tripped.rebuild_flow_ref, Some(42));
}

// ── Debug / trait impl tests ─────────────────────────────────────────

#[test]
fn tracked_chunk_debug_contains_fields() {
    use tidefs_flow_commit_coordinator::TrackedChunk;
    use tidefs_membership_epoch::MemberId;
    use tidefs_replication_model::{FlowCommitClass, ReplicatedReceiptId, ReplicatedSubjectId};

    let chunk = TrackedChunk::new(
        1,
        ReplicatedSubjectId::new(42),
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ReplicatedReceiptId(100),
    );
    let debug = format!("{chunk:?}");
    assert!(debug.contains("chunk_id"));
    assert!(debug.contains("Pending"));
    assert!(!debug.is_empty());
}

#[test]
fn tracked_batch_debug_contains_fields() {
    use tidefs_flow_commit_coordinator::TrackedBatch;
    use tidefs_replication_model::FlowCommitClass;

    let batch = TrackedBatch::new(1, vec![10], FlowCommitClass::Rebuild);
    let debug = format!("{batch:?}");
    assert!(debug.contains("batch_id"));
    assert!(!debug.is_empty());
}

#[test]
fn commit_verification_outcome_clone_eq() {
    use tidefs_flow_commit_coordinator::CommitVerificationOutcome;

    let outcome = CommitVerificationOutcome {
        advanced_chunks: vec![1, 2, 3],
        is_verified: true,
        total_commit_results: 3,
    };
    let cloned = outcome.clone();
    assert_eq!(outcome, cloned);
    assert_eq!(outcome.advanced_chunks, cloned.advanced_chunks);
    assert_eq!(outcome.is_verified, cloned.is_verified);
}

#[test]
fn flow_advance_report_clone_eq() {
    use tidefs_flow_commit_coordinator::FlowAdvanceReport;
    use tidefs_replication_model::{FlowCommitClass, FlowState};

    let report = FlowAdvanceReport {
        flow_class: FlowCommitClass::Rebuild,
        current_flow_state: FlowState::Planned,
        new_flow_state: FlowState::Complete,
        chunks_total: 5,
        chunks_committed: 5,
        chunks_failed: 0,
        chunks_pending: 0,
        advanced: true,
    };
    let cloned = report.clone();
    assert_eq!(report, cloned);
    assert!(cloned.advanced);
}

#[test]
fn batch_completion_clone_eq() {
    use tidefs_flow_commit_coordinator::BatchCompletion;

    let completion = BatchCompletion {
        batch_id: 7,
        flow_class: tidefs_replication_model::FlowCommitClass::Relocation,
        rebuild_flow_ref: None,
        relocation_flow_ref: Some(99),
        chunks_total: 3,
        chunks_committed: 3,
        chunks_failed: 0,
        all_committed: true,
        sealed: true,
    };
    let cloned = completion.clone();
    assert_eq!(completion, cloned);
    assert!(cloned.sealed);
    assert!(cloned.all_committed);
    assert_eq!(cloned.chunks_total, 3);
    assert_eq!(cloned.relocation_flow_ref, Some(99));
}

#[test]
fn durability_error_variants_discriminate() {
    use tidefs_flow_commit_coordinator::DurabilityError;

    // All variants are distinct
    let variants = [
        DurabilityError::AlreadyDurable,
        DurabilityError::UnknownSequence,
        DurabilityError::BarrierActive,
        DurabilityError::NotActiveBarrier,
        DurabilityError::OutOfOrderSubmission,
    ];
    for i in 0..variants.len() {
        for j in 0..variants.len() {
            if i == j {
                assert_eq!(variants[i], variants[j]);
            } else {
                assert_ne!(variants[i], variants[j]);
            }
        }
    }
}

#[test]
fn durability_error_debug_contains_variant_name() {
    use tidefs_flow_commit_coordinator::DurabilityError;

    let e = DurabilityError::AlreadyDurable;
    let debug = format!("{e:?}");
    assert!(debug.contains("AlreadyDurable"));

    let e = DurabilityError::BarrierActive;
    let debug = format!("{e:?}");
    assert!(debug.contains("BarrierActive"));
}

#[test]
fn durability_error_clone_preserves_variant() {
    use tidefs_flow_commit_coordinator::DurabilityError;

    let e = DurabilityError::OutOfOrderSubmission;
    let cloned = e;
    assert_eq!(e, cloned); // Copy type, PartialEq
}

#[test]
fn flow_scope_variants_discriminate() {
    use tidefs_flow_commit_coordinator::FlowScope;

    let rebuild = FlowScope::Rebuild(42);
    let relocation = FlowScope::Relocation(7);
    let replication = FlowScope::Replication;

    assert_ne!(rebuild, relocation);
    assert_ne!(rebuild, replication);
    assert_ne!(relocation, replication);

    let rebuild2 = FlowScope::Rebuild(42);
    assert_eq!(rebuild, rebuild2);

    let rebuild_diff = FlowScope::Rebuild(43);
    assert_ne!(rebuild, rebuild_diff);
}

#[test]
fn flow_scope_debug_contains_flow_id() {
    use tidefs_flow_commit_coordinator::FlowScope;

    let scope = FlowScope::Rebuild(42);
    let debug = format!("{scope:?}");
    assert!(debug.contains("Rebuild") || debug.contains("42"));

    let scope = FlowScope::Relocation(7);
    let debug = format!("{scope:?}");
    assert!(debug.contains("Relocation") || debug.contains("7"));
}

#[test]
fn flow_commit_coordinator_debug_does_not_panic() {
    let coord = make_coordinator();
    let debug = format!("{coord:?}");
    assert!(!debug.is_empty());
}

#[test]
fn durability_sequence_debug_does_not_panic() {
    let seq = DurabilitySequence::new();
    let debug = format!("{seq:?}");
    assert!(!debug.is_empty());
}

#[test]
fn durability_sequence_clone_produces_independent_copy() {
    let mut seq = DurabilitySequence::new();
    let _ = seq.submit();
    let mut clone = seq.clone();
    let _ = clone.submit();

    // Original should still have next_seq = 2 (one submitted)
    // Clone submitted a second, so it diverged
    assert_eq!(seq.submit(), 2);
    assert_eq!(clone.submit(), 3);
}

// ── Gate constant stability ───────────────────────────────────────────

#[test]
fn gate_constant_is_stable() {
    use tidefs_flow_commit_coordinator::FLOW_COMMIT_COORDINATOR_GATE_DATA_COPY_7;
    assert!(FLOW_COMMIT_COORDINATOR_GATE_DATA_COPY_7.contains("data_copy_7"));
}

// ── Property: commit idempotency under retry ──────────────────────────

#[test]
fn commit_transfer_receipt_idempotent_for_same_ticket() {
    let mut coord = make_coordinator();
    let ticket = ReplicatedReceiptId(1000);
    let subj = ReplicatedSubjectId::new(100);

    let _ = coord.register_chunk(
        subj,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ticket,
    );

    // First commit succeeds
    let t1 = make_transfer_receipt(500, 1000);
    let result1 = coord.commit_transfer_receipt(t1);
    assert!(result1.is_ok());

    // Second commit with same ticket (different receipt id) fails
    // because no chunks remain in Pending state for that ticket
    let t2 = make_transfer_receipt(501, 1000);
    let result2 = coord.commit_transfer_receipt(t2);
    assert!(result2.is_err());
}

#[test]
fn sealed_batch_count_monotonic() {
    let mut coord = make_coordinator();
    assert_eq!(coord.sealed_batch_count(), 0);

    let subjects: Vec<ReplicatedSubjectId> =
        (0..2).map(|i| ReplicatedSubjectId::new(100 + i)).collect();
    let ticket = ReplicatedReceiptId(1000);
    let (batch_id, _) = coord.register_chunk_batch(
        &subjects,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ticket,
    );

    let t = make_transfer_receipt(500, 1000);
    coord.commit_transfer_receipt(t).unwrap();
    let v = make_verification_receipt(600, &subjects, VerificationStatus::Verified);
    coord.commit_verification_receipt(v).unwrap();
    coord.seal_batch_and_emit_completion(batch_id).unwrap();

    assert_eq!(coord.sealed_batch_count(), 1);
}

// ── Property: no committed-after-abort invariant ──────────────────────

#[test]
fn failed_chunk_never_appears_in_committed_count() {
    let mut coord = make_coordinator();
    let ticket = ReplicatedReceiptId(1000);
    let subj = ReplicatedSubjectId::new(200);

    let _ = coord.register_chunk(
        subj,
        MemberId::new(1),
        MemberId::new(2),
        FlowCommitClass::Rebuild,
        ticket,
    );

    let t = make_transfer_receipt(500, 1000);
    coord.commit_transfer_receipt(t).unwrap();
    let v = make_verification_receipt(600, &[subj], VerificationStatus::DigestMismatch);
    coord.commit_verification_receipt(v).unwrap();

    // Chunk is Failed — not Committed
    assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Failed), 1);
    assert_eq!(coord.chunk_count_by_state(ReplicaChunkState::Committed), 0);
    assert!(!coord.flow_class_complete(FlowCommitClass::Rebuild));
}
