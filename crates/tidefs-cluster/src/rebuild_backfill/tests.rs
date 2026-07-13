// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use crate::rebuild_backfill::{
    BackfillBatch, BackfillCommand, BackfillError, BackfillSession, BackfillState,
    RebuildBackfillInitiator, RebuildPlan, ReconstructionTask,
};
use crate::types::{DataPathCarrier, LeaseState};
use std::collections::BTreeMap;
use tidefs_membership_epoch::EpochId;
use tidefs_replication_model::{PlacementReceiptRef, ReceiptRedundancyPolicy, ReplicatedSubjectId};

// ── Helpers ───────────────────────────────────────────────────

fn eid(n: u64) -> EpochId {
    EpochId(n)
}

fn make_task(
    object_id: u64,
    sources: Vec<u64>,
    targets: Vec<u64>,
    priority: u8,
) -> ReconstructionTask {
    ReconstructionTask::new_full_with_receipt(
        object_id,
        receipt_ref(object_id, 1),
        sources,
        targets,
        priority,
    )
}

fn synthetic_task(
    object_id: u64,
    sources: Vec<u64>,
    targets: Vec<u64>,
    priority: u8,
) -> ReconstructionTask {
    ReconstructionTask::new_full_with_receipt(
        object_id,
        PlacementReceiptRef::synthetic_for_subject(ReplicatedSubjectId::new(object_id)),
        sources,
        targets,
        priority,
    )
}

fn receipt_ref(object_id: u64, generation: u64) -> PlacementReceiptRef {
    let mut object_key = [0xA5; 32];
    object_key[..8].copy_from_slice(&object_id.to_le_bytes());
    let mut digest = [0x5A; 32];
    digest[..8].copy_from_slice(&object_id.to_le_bytes());
    digest[8..16].copy_from_slice(&generation.to_le_bytes());
    PlacementReceiptRef::replicated(object_id, object_key, eid(1), generation, 2, 4096, digest)
}

fn malformed_policy_receipt_ref(object_id: u64) -> PlacementReceiptRef {
    let base = receipt_ref(object_id, 1);
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
    let base = receipt_ref(object_id, 1);
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

fn make_plan(plan_id: u64, tasks: Vec<ReconstructionTask>) -> RebuildPlan {
    RebuildPlan::new(plan_id, tasks, 0)
}

fn open_transferring(init: &mut RebuildBackfillInitiator, tasks: Vec<ReconstructionTask>) -> u64 {
    let id = init.open_backfill(make_plan(100, tasks), eid(1)).unwrap();
    init.initiate_backfill(id).unwrap();
    init.start_transferring(id).unwrap();
    id
}

fn make_command(
    source: u64,
    target: u64,
    object_ids: Vec<u64>,
    max_chunk_bytes: u64,
) -> BackfillCommand {
    let placement_receipt_refs = object_ids
        .iter()
        .copied()
        .map(|object_id| receipt_ref(object_id, 1))
        .collect();
    BackfillCommand::new_with_receipts(
        source,
        target,
        object_ids,
        placement_receipt_refs,
        max_chunk_bytes,
    )
}

// ── ReconstructionTask ────────────────────────────────────────

#[test]
fn reconstruction_task_has_viable_sources() {
    let t = make_task(1, vec![10], vec![20], 0);
    assert!(t.has_viable_sources());
    assert_eq!(t.target_count(), 1);
}

#[test]
fn reconstruction_task_no_sources() {
    let t = make_task(1, vec![], vec![20], 0);
    assert!(!t.has_viable_sources());
}

#[test]
fn reconstruction_task_range_with_receipt() {
    let t = ReconstructionTask::new_range_with_receipt(
        1,
        receipt_ref(1, 1),
        vec![10],
        vec![20],
        0,
        4096,
        0,
    );
    assert_eq!(t.data_range, Some((0, 4096)));
}

// ── RebuildPlan ───────────────────────────────────────────────

#[test]
fn rebuild_plan_empty() {
    let plan = make_plan(100, vec![]);
    assert!(plan.is_empty());
    assert_eq!(plan.task_count(), 0);
    assert_eq!(plan.total_target_replicas(), 0);
}

#[test]
fn rebuild_plan_with_tasks() {
    let plan = make_plan(
        100,
        vec![
            make_task(1, vec![10], vec![20], 0),
            make_task(2, vec![10], vec![20, 30], 0),
        ],
    );
    assert!(!plan.is_empty());
    assert_eq!(plan.task_count(), 2);
    assert_eq!(plan.total_target_replicas(), 3);
}

// ── BackfillCommand ───────────────────────────────────────────

#[test]
fn command_empty() {
    let cmd = BackfillCommand::new_with_receipts(1, 2, vec![], vec![], 4096);
    assert!(cmd.is_empty());
    assert_eq!(cmd.object_count(), 0);
}

#[test]
fn command_with_receipts() {
    let refs = vec![
        receipt_ref(100, 1),
        receipt_ref(200, 1),
        receipt_ref(300, 1),
    ];
    let cmd = BackfillCommand::new_with_receipts(10, 20, vec![100, 200, 300], refs.clone(), 65536);
    assert!(!cmd.is_empty());
    assert_eq!(cmd.object_count(), 3);
    assert_eq!(cmd.placement_receipt_refs, refs);
    assert!(cmd
        .placement_receipt_refs
        .iter()
        .all(|receipt| !receipt.is_synthetic()));
    assert_eq!(cmd.source_node, 10);
    assert_eq!(cmd.target_node, 20);
}

#[test]
fn command_preserves_object_receipt_alignment() {
    let refs = vec![receipt_ref(100, 1), receipt_ref(100, 2)];
    let cmd = BackfillCommand::new_with_receipts(10, 20, vec![100, 100], refs.clone(), 65536);
    assert_eq!(cmd.object_ids, vec![100, 100]);
    assert_eq!(cmd.placement_receipt_refs, refs);
}

// ── BackfillBatch ─────────────────────────────────────────────

#[test]
fn batch_empty() {
    let batch = BackfillBatch::new(5, eid(1), DataPathCarrier::Unknown);
    assert!(batch.is_empty());
    assert_eq!(batch.command_count(), 0);
    assert_eq!(batch.total_objects(), 0);
}

#[test]
fn batch_add_commands() {
    let mut batch = BackfillBatch::new(5, eid(1), DataPathCarrier::Unknown);
    batch.add_command(make_command(1, 5, vec![10, 20], 4096));
    batch.add_command(make_command(2, 5, vec![30], 4096));
    assert!(!batch.is_empty());
    assert_eq!(batch.command_count(), 2);
    assert_eq!(batch.total_objects(), 3);
}

// ── BackfillState ─────────────────────────────────────────────

#[test]
fn backfill_state_active_and_terminal() {
    assert!(BackfillState::Planning.is_active());
    assert!(BackfillState::Initiating.is_active());
    assert!(BackfillState::Transferring.is_active());
    assert!(BackfillState::Verifying.is_active());
    assert!(BackfillState::Complete.is_terminal());
    assert!(BackfillState::Failed.is_terminal());
    assert!(BackfillState::Aborted.is_terminal());
    assert!(!BackfillState::Idle.is_active());
    assert!(!BackfillState::Complete.is_active());
}

// ── RebuildBackfillInitiator ──────────────────────────────────

#[test]
fn new_initiator_empty() {
    let init = RebuildBackfillInitiator::new(eid(1));
    assert_eq!(init.current_epoch(), eid(1));
    assert_eq!(init.active_count(), 0);
    assert_eq!(init.completed_count(), 0);
    assert_eq!(init.total_pending_objects(), 0);
}

#[test]
fn open_backfill_empty_plan_errors() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![]);
    assert!(matches!(
        init.open_backfill(plan, eid(1)).unwrap_err(),
        BackfillError::EmptyPlan
    ));
}

#[test]
fn open_backfill_epoch_mismatch() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let err = init.open_backfill(plan, eid(2)).unwrap_err();
    assert!(matches!(err, BackfillError::EpochMismatch { .. }));
}

#[test]
fn open_backfill_rejects_synthetic_receipt_ref() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![synthetic_task(1, vec![10], vec![20], 0)]);

    let err = init.open_backfill(plan, eid(1)).unwrap_err();
    assert!(matches!(
        err,
        BackfillError::SyntheticReceiptRef { object_id: 1 }
    ));
    assert_eq!(init.session_ids().next(), None);

    let valid = make_plan(101, vec![make_task(2, vec![10], vec![20], 0)]);
    assert_eq!(init.open_backfill(valid, eid(1)).unwrap(), 1);
}

#[test]
fn open_backfill_rejects_malformed_receipt_policy() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let task = ReconstructionTask::new_full_with_receipt(
        1,
        malformed_policy_receipt_ref(1),
        vec![10],
        vec![20],
        0,
    );
    let plan = make_plan(100, vec![task]);

    let err = init.open_backfill(plan, eid(1)).unwrap_err();
    assert!(matches!(
        err,
        BackfillError::MalformedReceiptPolicy { object_id: 1 }
    ));
    assert_eq!(init.session_ids().next(), None);
}

#[test]
fn open_backfill_rejects_under_width_receipt() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let task = ReconstructionTask::new_full_with_receipt(
        1,
        under_width_receipt_ref(1),
        vec![10],
        vec![20],
        0,
    );
    let plan = make_plan(100, vec![task]);

    let err = init.open_backfill(plan, eid(1)).unwrap_err();
    assert!(matches!(
        err,
        BackfillError::InsufficientReceiptTargets {
            object_id: 1,
            required: 3,
            actual: 2
        }
    ));
    assert_eq!(init.session_ids().next(), None);
}

#[test]
fn open_backfill_single_task() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let id = init.open_backfill(plan, eid(1)).unwrap();
    assert_eq!(id, 1);
    assert_eq!(init.active_count(), 1);

    let session = init.session(1).unwrap();
    assert_eq!(session.state, BackfillState::Planning);
    assert_eq!(session.total_objects, 1);
    assert_eq!(session.batches.len(), 1);

    let batch = &session.batches[0];
    assert_eq!(batch.target_node, 20);
    assert_eq!(batch.commands.len(), 1);
    assert_eq!(batch.commands[0].source_node, 10);
    assert_eq!(batch.commands[0].object_ids, vec![1]);
}

#[test]
fn open_backfill_multi_target_partitioning() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(
        100,
        vec![
            make_task(1, vec![10], vec![20, 30], 0),
            make_task(2, vec![10], vec![20], 0),
            make_task(3, vec![15], vec![20], 1),
        ],
    );
    let id = init.open_backfill(plan, eid(1)).unwrap();

    let session = init.session(id).unwrap();
    assert_eq!(session.total_objects, 3);

    let mut targets: Vec<u64> = session.batches.iter().map(|b| b.target_node).collect();
    targets.sort();
    assert_eq!(targets, vec![20, 30]);

    let batch20 = session
        .batches
        .iter()
        .find(|b| b.target_node == 20)
        .unwrap();
    assert_eq!(batch20.commands.len(), 3);
    let total_obj_20: usize = batch20.commands.iter().map(|c| c.object_count()).sum();
    assert_eq!(total_obj_20, 3);

    let batch30 = session
        .batches
        .iter()
        .find(|b| b.target_node == 30)
        .unwrap();
    assert_eq!(batch30.commands.len(), 1);
    assert_eq!(batch30.commands[0].object_ids, vec![1]);
}

#[test]
fn partition_keeps_distinct_receipt_generations_separate() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(
        100,
        vec![
            ReconstructionTask::new_full_with_receipt(7, receipt_ref(7, 1), vec![10], vec![20], 0),
            ReconstructionTask::new_full_with_receipt(7, receipt_ref(7, 2), vec![10], vec![20], 0),
        ],
    );
    let id = init.open_backfill(plan, eid(1)).unwrap();
    let session = init.session(id).unwrap();
    assert_eq!(session.batches.len(), 1);
    assert_eq!(session.batches[0].commands.len(), 2);

    let mut generations: Vec<u64> = session.batches[0]
        .commands
        .iter()
        .map(|cmd| cmd.placement_receipt_refs[0].receipt_generation)
        .collect();
    generations.sort_unstable();
    assert_eq!(generations, vec![1, 2]);
}

#[test]
fn open_backfill_rejects_no_source_tasks_before_session_creation() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(
        100,
        vec![
            make_task(1, vec![], vec![20], 0),
            make_task(2, vec![10], vec![20], 0),
        ],
    );

    let err = init.open_backfill(plan, eid(1)).unwrap_err();
    assert_eq!(err, BackfillError::NoViableSource(1));
    assert_eq!(init.session_ids().next(), None);
    assert_eq!(init.active_count(), 0);
}

#[test]
fn initiate_and_transfer_lifecycle() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let id = init.open_backfill(plan, eid(1)).unwrap();

    init.initiate_backfill(id).unwrap();
    assert_eq!(init.session(id).unwrap().state, BackfillState::Initiating);

    init.start_transferring(id).unwrap();
    assert_eq!(init.session(id).unwrap().state, BackfillState::Transferring);

    init.record_progress(id, 1, 4096).unwrap();
    let s = init.session(id).unwrap();
    assert_eq!(s.objects_completed, 1);
    assert_eq!(s.bytes_transferred, 4096);
    assert!(s.is_complete());

    init.complete_transfer(id).unwrap();
    assert_eq!(init.session(id).unwrap().state, BackfillState::Verifying);

    init.finalize_backfill(id).unwrap();
    assert_eq!(init.session(id).unwrap().state, BackfillState::Complete);
    assert_eq!(init.active_count(), 0);
    assert_eq!(init.completed_count(), 1);
}

#[test]
fn complete_transfer_rejects_zero_progress() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let id = open_transferring(&mut init, vec![make_task(1, vec![10], vec![20], 0)]);

    let err = init.complete_transfer(id).unwrap_err();
    assert_eq!(
        err,
        BackfillError::IncompleteBackfill {
            backfill_id: id,
            completed_objects: 0,
            total_objects: 1
        }
    );
    assert_eq!(init.session(id).unwrap().state, BackfillState::Transferring);
    assert_eq!(init.active_count(), 1);
    assert_eq!(init.completed_count(), 0);
    assert_eq!(init.total_pending_objects(), 1);
}

#[test]
fn complete_transfer_rejects_partial_progress() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let id = open_transferring(
        &mut init,
        vec![
            make_task(1, vec![10], vec![20], 0),
            make_task(2, vec![10], vec![20], 0),
        ],
    );

    init.record_progress(id, 1, 4096).unwrap();
    let err = init.complete_transfer(id).unwrap_err();
    assert_eq!(
        err,
        BackfillError::IncompleteBackfill {
            backfill_id: id,
            completed_objects: 1,
            total_objects: 2
        }
    );
    assert_eq!(init.session(id).unwrap().state, BackfillState::Transferring);
    assert_eq!(init.active_count(), 1);
    assert_eq!(init.completed_count(), 0);
    assert_eq!(init.total_pending_objects(), 1);
}

#[test]
fn exact_completion_progress_reaches_complete() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let id = open_transferring(
        &mut init,
        vec![
            make_task(1, vec![10], vec![20], 0),
            make_task(2, vec![10], vec![20], 0),
        ],
    );

    init.record_progress(id, 2, 8192).unwrap();
    assert_eq!(init.total_pending_objects(), 0);
    init.complete_transfer(id).unwrap();
    assert_eq!(init.session(id).unwrap().state, BackfillState::Verifying);
    assert_eq!(init.active_count(), 1);
    assert_eq!(init.completed_count(), 0);

    init.finalize_backfill(id).unwrap();
    assert_eq!(init.session(id).unwrap().state, BackfillState::Complete);
    assert_eq!(init.active_count(), 0);
    assert_eq!(init.completed_count(), 1);
    assert_eq!(init.total_pending_objects(), 0);
}

#[test]
fn finalize_rechecks_completion_progress() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let id = open_transferring(
        &mut init,
        vec![
            make_task(1, vec![10], vec![20], 0),
            make_task(2, vec![10], vec![20], 0),
        ],
    );
    init.record_progress(id, 1, 4096).unwrap();
    init.session_mut(id).unwrap().state = BackfillState::Verifying;

    let err = init.finalize_backfill(id).unwrap_err();
    assert_eq!(
        err,
        BackfillError::IncompleteBackfill {
            backfill_id: id,
            completed_objects: 1,
            total_objects: 2
        }
    );
    assert_eq!(init.session(id).unwrap().state, BackfillState::Verifying);
    assert_eq!(init.active_count(), 1);
    assert_eq!(init.completed_count(), 0);
    assert_eq!(init.total_pending_objects(), 1);
}

#[test]
fn abort_from_transferring() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let id = init.open_backfill(plan, eid(1)).unwrap();
    init.initiate_backfill(id).unwrap();
    init.start_transferring(id).unwrap();

    init.abort_backfill(id).unwrap();
    assert_eq!(init.session(id).unwrap().state, BackfillState::Aborted);
}

#[test]
fn cannot_abort_completed() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let id = init.open_backfill(plan, eid(1)).unwrap();
    init.initiate_backfill(id).unwrap();
    init.start_transferring(id).unwrap();
    init.record_progress(id, 1, 4096).unwrap();
    init.complete_transfer(id).unwrap();
    init.finalize_backfill(id).unwrap();

    assert!(matches!(
        init.abort_backfill(id).unwrap_err(),
        BackfillError::InvalidState(..)
    ));
}

#[test]
fn invalid_state_transitions() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let id = init.open_backfill(plan, eid(1)).unwrap();

    assert!(matches!(
        init.complete_transfer(id).unwrap_err(),
        BackfillError::InvalidState(..)
    ));
    assert!(matches!(
        init.finalize_backfill(id).unwrap_err(),
        BackfillError::InvalidState(..)
    ));
}

#[test]
fn not_found_backfill() {
    let init = RebuildBackfillInitiator::new(eid(1));
    assert!(init.session(999).is_none());
    let mut init_mut = RebuildBackfillInitiator::new(eid(1));
    assert!(matches!(
        init_mut.initiate_backfill(999).unwrap_err(),
        BackfillError::NotFound(999)
    ));
}

#[test]
fn epoch_transition_aborts_active() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let id = init.open_backfill(plan, eid(1)).unwrap();
    init.initiate_backfill(id).unwrap();
    init.start_transferring(id).unwrap();
    assert_eq!(init.active_count(), 1);

    let aborted = init.on_epoch_transition(eid(2));
    assert_eq!(aborted, 1);
    assert_eq!(init.session(id).unwrap().state, BackfillState::Aborted);
    assert_eq!(init.current_epoch(), eid(2));
}

#[test]
fn epoch_transition_leaves_completed() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let id = init.open_backfill(plan, eid(1)).unwrap();
    init.initiate_backfill(id).unwrap();
    init.start_transferring(id).unwrap();
    init.record_progress(id, 1, 4096).unwrap();
    init.complete_transfer(id).unwrap();
    init.finalize_backfill(id).unwrap();

    let aborted = init.on_epoch_transition(eid(2));
    assert_eq!(aborted, 0);
    assert_eq!(init.session(id).unwrap().state, BackfillState::Complete);
}

#[test]
fn source_lease_gating() {
    assert!(RebuildBackfillInitiator::can_source_serve(LeaseState::Held));
    assert!(RebuildBackfillInitiator::can_source_serve(
        LeaseState::Renewing
    ));
    assert!(!RebuildBackfillInitiator::can_source_serve(
        LeaseState::Unleased
    ));
    assert!(!RebuildBackfillInitiator::can_source_serve(
        LeaseState::Acquiring
    ));
    assert!(!RebuildBackfillInitiator::can_source_serve(
        LeaseState::Expiring
    ));
    assert!(!RebuildBackfillInitiator::can_source_serve(
        LeaseState::Released
    ));
}

#[test]
fn validate_epoch_and_sources() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let id = init.open_backfill(plan, eid(1)).unwrap();

    let mut leases = BTreeMap::new();
    leases.insert(10, LeaseState::Held);
    assert!(init.validate_epoch_and_sources(id, &leases).is_ok());

    leases.insert(10, LeaseState::Expiring);
    let err = init.validate_epoch_and_sources(id, &leases).unwrap_err();
    assert!(matches!(
        err,
        BackfillError::SourceLeaseNotActive(10, LeaseState::Expiring)
    ));
}

#[test]
fn retry_backfill_resets_progress() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let id = init.open_backfill(plan, eid(1)).unwrap();
    init.initiate_backfill(id).unwrap();
    init.start_transferring(id).unwrap();
    init.record_progress(id, 1, 4096).unwrap();
    init.abort_backfill(id).unwrap();
    init.session_mut(id).unwrap().state = BackfillState::Failed;

    assert!(init.retry_backfill(id).is_ok());
    let s = init.session(id).unwrap();
    assert_eq!(s.state, BackfillState::Planning);
    assert_eq!(s.objects_completed, 0);
    assert_eq!(s.bytes_transferred, 0);
    assert_eq!(s.retry_count, 1);
}

#[test]
fn retries_exceeded() {
    let mut init = RebuildBackfillInitiator::with_config(eid(1), 1, 4096);
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let id = init.open_backfill(plan, eid(1)).unwrap();
    init.session_mut(id).unwrap().state = BackfillState::Failed;

    assert!(init.retry_backfill(id).is_ok());
    init.session_mut(id).unwrap().state = BackfillState::Failed;
    let err = init.retry_backfill(id).unwrap_err();
    assert!(matches!(err, BackfillError::RetriesExceeded(1, _)));
}

#[test]
fn session_ids_iteration() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let p1 = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let p2 = make_plan(200, vec![make_task(2, vec![30], vec![40], 0)]);
    init.open_backfill(p1, eid(1)).unwrap();
    init.open_backfill(p2, eid(1)).unwrap();

    let ids: Vec<u64> = init.session_ids().collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&1));
    assert!(ids.contains(&2));
}

#[test]
fn consecutive_ids_increment() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let p1 = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let p2 = make_plan(200, vec![make_task(2, vec![30], vec![40], 0)]);
    let id1 = init.open_backfill(p1, eid(1)).unwrap();
    let id2 = init.open_backfill(p2, eid(1)).unwrap();
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
}

#[test]
fn preview_batches() {
    let plan = make_plan(
        100,
        vec![
            make_task(1, vec![10], vec![20], 0),
            make_task(2, vec![10], vec![20], 0),
        ],
    );
    let batches = RebuildBackfillInitiator::preview_batches(&plan, eid(1), 65536).unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].target_node, 20);
    assert_eq!(batches[0].commands.len(), 2);
    let total_objects: usize = batches[0]
        .commands
        .iter()
        .map(|cmd| cmd.object_count())
        .sum();
    assert_eq!(total_objects, 2);
}

#[test]
fn preview_batches_rejects_no_source_tasks() {
    let plan = make_plan(
        100,
        vec![
            make_task(1, vec![], vec![20], 0),
            make_task(2, vec![10], vec![20], 0),
        ],
    );

    let err = RebuildBackfillInitiator::preview_batches(&plan, eid(1), 65536).unwrap_err();
    assert_eq!(err, BackfillError::NoViableSource(1));
}

#[test]
fn total_pending_objects() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let p1 = make_plan(
        100,
        vec![
            make_task(1, vec![10], vec![20], 0),
            make_task(2, vec![10], vec![20], 0),
        ],
    );
    let id = init.open_backfill(p1, eid(1)).unwrap();
    init.initiate_backfill(id).unwrap();
    init.start_transferring(id).unwrap();

    assert_eq!(init.total_pending_objects(), 2);

    init.record_progress(id, 1, 1024).unwrap();
    assert_eq!(init.total_pending_objects(), 1);

    init.record_progress(id, 2, 2048).unwrap();
    assert_eq!(init.total_pending_objects(), 0);
}

#[test]
fn fraction_complete() {
    let plan = make_plan(
        100,
        vec![
            make_task(1, vec![10], vec![20], 0),
            make_task(2, vec![10], vec![20], 0),
        ],
    );
    let mut session = BackfillSession::new(1, plan, vec![], 3, DataPathCarrier::Unknown);
    assert_eq!(session.fraction_complete(), 0.0);

    session.record_progress(1, 512);
    assert!((session.fraction_complete() - 0.5).abs() < 0.001);

    session.record_progress(2, 1024);
    assert!((session.fraction_complete() - 1.0).abs() < 0.001);
    assert!(session.is_complete());
}

#[test]
fn fraction_complete_empty_plan() {
    let plan = make_plan(100, vec![]);
    let session = BackfillSession::new(1, plan, vec![], 3, DataPathCarrier::Unknown);
    assert!((session.fraction_complete() - 1.0).abs() < 0.001);
}

#[test]
fn cannot_initiate_wrong_state() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let id = init.open_backfill(plan, eid(1)).unwrap();
    init.initiate_backfill(id).unwrap();
    let err = init.initiate_backfill(id).unwrap_err();
    assert!(matches!(err, BackfillError::InvalidState(..)));
}

#[test]
fn batches_for_backfill() {
    let mut init = RebuildBackfillInitiator::new(eid(1));
    let plan = make_plan(100, vec![make_task(1, vec![10], vec![20], 0)]);
    let id = init.open_backfill(plan, eid(1)).unwrap();

    let batches = init.batches_for(id).unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].target_node, 20);

    assert!(init.batches_for(999).is_none());
}

#[test]
fn backfill_command_accessors() {
    let cmd = make_command(10, 20, vec![100, 200], 65536);
    assert_eq!(cmd.source_node, 10);
    assert_eq!(cmd.target_node, 20);
    assert_eq!(cmd.object_ids, vec![100, 200]);
    assert_eq!(cmd.max_chunk_bytes, 65536);
    assert_eq!(cmd.object_count(), 2);
    assert!(!cmd.is_empty());
}
