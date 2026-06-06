//! Integration test: end-to-end backfill pipeline from degraded-replica
//! detection through scheduler ingestion to data-movement execution.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_object_io::{ObjectKey, ObjectStore};
use tidefs_rebuild_runtime::engine::{
    task_object_key, DataMovementEngine, EngineError, ReceiptSegmentSource,
};
use tidefs_rebuild_runtime::progress::{BackfillProgress, TaskState};
use tidefs_rebuild_runtime::quorum::{BackfillLeaseToken, QuorumAdmission, QuorumCoordinator};
use tidefs_rebuild_runtime::scheduler::{BackfillScheduler, DegradedReplicaReport};
use tidefs_rebuild_runtime::task::{BackfillTask, BackfillTaskInit};
use tidefs_replication_model::{
    ObjectDigest, PlacementReceiptRef, ReplicaMovementClass, ReplicatedSubjectId,
};

/// In-memory object store shared across integration tests.
#[derive(Clone, Debug, Default)]
struct MemStore {
    objects: HashMap<ObjectKey, Vec<u8>>,
}

#[derive(Debug)]
struct MemStoreError(String);

impl fmt::Display for MemStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemStoreError: {}", self.0)
    }
}

impl Error for MemStoreError {}

impl ObjectStore for MemStore {
    type Error = MemStoreError;

    fn put(&mut self, key: ObjectKey, data: &[u8]) -> std::result::Result<(), Self::Error> {
        self.objects.insert(key, data.to_vec());
        Ok(())
    }

    fn get(&self, key: &ObjectKey) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.objects.get(key).cloned())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiptFetchCall {
    source_member: MemberId,
    object_id: u64,
    segment_offset: u64,
    segment_length: u64,
}

#[derive(Clone, Debug, Default)]
struct MockReceiptSource {
    payloads: HashMap<[u8; 32], Vec<u8>>,
    calls: Vec<ReceiptFetchCall>,
}

impl MockReceiptSource {
    fn insert(&mut self, key: ObjectKey, payload: &[u8]) {
        self.payloads.insert(key.as_bytes32(), payload.to_vec());
    }
}

impl ReceiptSegmentSource for MockReceiptSource {
    type Error = String;

    fn fetch_segment_by_receipt(
        &mut self,
        source_member: MemberId,
        placement_receipt_ref: PlacementReceiptRef,
        segment_offset: u64,
        segment_length: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        self.calls.push(ReceiptFetchCall {
            source_member,
            object_id: placement_receipt_ref.object_id,
            segment_offset,
            segment_length,
        });

        let payload = self
            .payloads
            .get(&placement_receipt_ref.object_key)
            .ok_or_else(|| {
                format!(
                    "missing receipt key for object {}",
                    placement_receipt_ref.object_id
                )
            })?;
        let start = usize::try_from(segment_offset).map_err(|_| "offset too large".to_string())?;
        let len = usize::try_from(segment_length).map_err(|_| "length too large".to_string())?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| "range overflow".to_string())?;
        payload
            .get(start..end)
            .map(|slice| slice.to_vec())
            .ok_or_else(|| {
                format!(
                    "receipt segment out of range for object {}",
                    placement_receipt_ref.object_id
                )
            })
    }
}

fn make_report(
    subject: u64,
    source: u64,
    missing: &[u64],
    class: ReplicaMovementClass,
    payload: &[u8],
    now_ns: u64,
) -> DegradedReplicaReport {
    let digest = blake3::hash(payload);
    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(digest.as_bytes());
    let first_eight = u64::from_le_bytes(digest_bytes[..8].try_into().unwrap());

    DegradedReplicaReport {
        subject_ref: ReplicatedSubjectId::new(subject),
        placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
            ReplicatedSubjectId::new(subject),
        ),
        healthy_sources: vec![MemberId::new(source)],
        missing_targets: missing.iter().map(|&m| MemberId::new(m)).collect(),
        movement_class: class,
        payload_digest: ObjectDigest::new(first_eight),
        payload_len: payload.len() as u64,
        now_ns,
        deadline_offset_ns: 10_000_000_000,
    }
}

fn populate_source(
    store: &mut MemStore,
    subject: u64,
    digest: ObjectDigest,
    data: &[u8],
) -> ObjectKey {
    let key = task_object_key(&BackfillTask::new(BackfillTaskInit {
        subject_ref: ReplicatedSubjectId::new(subject),
        placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
            ReplicatedSubjectId::new(subject),
        ),
        source_member: MemberId::new(10),
        target_member: MemberId::new(20),
        movement_class: ReplicaMovementClass::BackfillLaggedCopy,
        payload_digest: digest,
        payload_len: data.len() as u64,
        created_at_ns: 0,
        deadline_ns: 0,
    }));
    store.put(key, data).unwrap();
    key
}

fn receipt_ref_for_payload(
    object_id: u64,
    object_key: ObjectKey,
    payload: &[u8],
    generation: u64,
) -> PlacementReceiptRef {
    PlacementReceiptRef::replicated(
        object_id,
        object_key.as_bytes32(),
        EpochId::new(7),
        generation,
        2,
        payload.len() as u64,
        *blake3::hash(payload).as_bytes(),
    )
}

fn task_from_receipt(receipt: PlacementReceiptRef, source: u64, target: u64) -> BackfillTask {
    let payload_digest_prefix = u64::from_le_bytes(receipt.payload_digest[..8].try_into().unwrap());
    BackfillTask::new(BackfillTaskInit {
        subject_ref: ReplicatedSubjectId::new(receipt.object_id),
        placement_receipt_ref: receipt,
        source_member: MemberId::new(source),
        target_member: MemberId::new(target),
        movement_class: ReplicaMovementClass::BackfillLaggedCopy,
        payload_digest: ObjectDigest::new(payload_digest_prefix),
        payload_len: receipt.payload_len,
        created_at_ns: 1000,
        deadline_ns: 5000,
    })
}

// ── Tests ──────────────────────────────────────────────────────────

#[test]
fn full_pipeline_single_object() {
    let data = b"integration test payload for backfill";
    let mut source_store = MemStore::default();
    let mut target_store = MemStore::default();

    // Simulate replica-health detecting degradation
    let report = make_report(
        42,
        10,
        &[20],
        ReplicaMovementClass::BackfillLaggedCopy,
        data,
        1000,
    );

    // Populate source store with the object
    populate_source(&mut source_store, 42, report.payload_digest, data);

    // Schedule the backfill
    let mut scheduler = BackfillScheduler::new();
    scheduler.ingest(&[report]);

    assert_eq!(scheduler.pending_count(), 1, "one task should be queued");

    let tasks = scheduler.drain_eligible();
    assert_eq!(tasks.len(), 1);
    let task = &tasks[0];

    // Quorum admission
    let epoch = EpochId(1);
    let mut coordinator = QuorumCoordinator::new(epoch);
    let lease = BackfillLeaseToken::issue(task.subject_ref, task.source_member, epoch);
    assert_eq!(coordinator.admit(task, &lease), QuorumAdmission::Admitted);

    // Execute the backfill
    let engine = DataMovementEngine::new();
    let mut progress = BackfillProgress::new(task.payload_len, 3);
    progress.schedule().unwrap();

    engine
        .execute(task, &source_store, &mut target_store, &mut progress)
        .unwrap();

    assert_eq!(progress.state, TaskState::Complete);

    // Verify target has the data
    let key = task_object_key(task);
    let target_data = target_store.get(&key).unwrap().unwrap();
    assert_eq!(target_data, data);

    // Clean up
    scheduler.mark_completed(task);
    coordinator.release(task.subject_ref);
    assert_eq!(coordinator.inflight_count(), 0);
    assert_eq!(scheduler.dedup_count(), 0);
}

#[test]
fn scheduler_dedup_prevents_duplicate_work() {
    let data = b"dedup test";
    let mut source_store = MemStore::default();
    let mut target_store = MemStore::default();

    // Two reports for the same (subject, target) pair
    let report1 = make_report(
        99,
        10,
        &[20],
        ReplicaMovementClass::BackfillLaggedCopy,
        data,
        1000,
    );
    let report2 = make_report(
        99,
        10,
        &[20],
        ReplicaMovementClass::BackfillLaggedCopy,
        data,
        2000,
    );

    populate_source(&mut source_store, 99, report1.payload_digest, data);

    let mut scheduler = BackfillScheduler::new();
    scheduler.ingest(&[report1, report2]);
    assert_eq!(
        scheduler.pending_count(),
        1,
        "duplicate reports should be deduplicated"
    );

    let tasks = scheduler.drain_eligible();
    assert_eq!(tasks.len(), 1);

    let engine = DataMovementEngine::new();
    let mut progress = BackfillProgress::new(tasks[0].payload_len, 3);
    progress.schedule().unwrap();
    engine
        .execute(&tasks[0], &source_store, &mut target_store, &mut progress)
        .unwrap();

    let key = task_object_key(&tasks[0]);
    assert_eq!(target_store.get(&key).unwrap().unwrap(), data);
}

#[test]
fn quorum_rejects_expired_lease() {
    let data = b"expired lease test";
    let mut source_store = MemStore::default();
    let target_store = MemStore::default();

    let report = make_report(
        7,
        10,
        &[20],
        ReplicaMovementClass::RebuildLostOrSuspectCopy,
        data,
        0,
    );
    populate_source(&mut source_store, 7, report.payload_digest, data);

    let mut scheduler = BackfillScheduler::new();
    scheduler.ingest(&[report]);
    let tasks = scheduler.drain_eligible();

    let mut coordinator = QuorumCoordinator::new(EpochId(10));
    let lease = BackfillLeaseToken::issue(tasks[0].subject_ref, tasks[0].source_member, EpochId(5));

    assert_eq!(
        coordinator.admit(&tasks[0], &lease),
        QuorumAdmission::LeaseRefused,
        "lease from epoch 5 should be refused in epoch 10"
    );

    // Verify no transfer happened
    let key = task_object_key(&tasks[0]);
    assert!(target_store.get(&key).unwrap().is_none());
}

#[test]
fn backfill_with_node_capacity_enforcement() {
    let data = b"capacity test";
    let mut source_store = MemStore::default();

    // Three objects all targeting node 20
    let reports = vec![
        make_report(
            1,
            10,
            &[20],
            ReplicaMovementClass::BackfillLaggedCopy,
            data,
            0,
        ),
        make_report(
            2,
            10,
            &[20],
            ReplicaMovementClass::BackfillLaggedCopy,
            data,
            0,
        ),
        make_report(
            3,
            10,
            &[20],
            ReplicaMovementClass::BackfillLaggedCopy,
            data,
            0,
        ),
    ];

    for (i, r) in reports.iter().enumerate() {
        populate_source(&mut source_store, (i + 1) as u64, r.payload_digest, data);
    }

    let mut scheduler = BackfillScheduler::new();
    scheduler.set_node_capacity(MemberId::new(20), 2);
    scheduler.ingest(&reports);

    let batch1 = scheduler.drain_eligible();
    assert_eq!(batch1.len(), 2, "node capacity 2 limits first batch");

    // Mark first two as completed
    for t in &batch1 {
        scheduler.mark_completed(t);
    }

    let batch2 = scheduler.drain_eligible();
    assert_eq!(
        batch2.len(),
        1,
        "third task should dispatch after capacity freed"
    );
}

#[test]
fn retry_exhaustion_pipeline() {
    let data = b"retry pipeline test";

    // Create a task with retry budget of 1
    let task = BackfillTask::new(BackfillTaskInit {
        subject_ref: ReplicatedSubjectId::new(55),
        placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
            ReplicatedSubjectId::new(55),
        ),
        source_member: MemberId::new(10),
        target_member: MemberId::new(20),
        movement_class: ReplicaMovementClass::BackfillLaggedCopy,
        payload_digest: ObjectDigest::new(0xBEEF),
        payload_len: data.len() as u64,
        created_at_ns: 0,
        deadline_ns: 10_000_000_000,
    })
    .with_retry_budget(1);

    let mut progress = BackfillProgress::new(task.payload_len, task.max_retries);

    // First attempt fails
    progress.schedule().unwrap();
    progress.start_transfer().unwrap();
    progress.record_progress(data.len() as u64).unwrap();
    progress.fail("network timeout");

    assert_eq!(progress.state, TaskState::Retry);
    assert_eq!(progress.retries_consumed, 1);

    // Retry
    progress.schedule().unwrap();
    progress.start_transfer().unwrap();
    progress.record_progress(data.len() as u64).unwrap();
    progress.fail("checksum mismatch");

    // Retries exhausted -> Failed
    assert_eq!(progress.state, TaskState::Failed);
    assert!(progress.is_done());
}

#[test]
fn task_priority_ordering_in_scheduler() {
    let data = b"priority";
    let reports = vec![
        make_report(
            1,
            10,
            &[20],
            ReplicaMovementClass::RebalanceCapacityPressure,
            data,
            0,
        ),
        make_report(
            2,
            10,
            &[21],
            ReplicaMovementClass::BackfillLaggedCopy,
            data,
            0,
        ),
        make_report(
            3,
            10,
            &[22],
            ReplicaMovementClass::RebuildLostOrSuspectCopy,
            data,
            0,
        ),
    ];

    let mut scheduler = BackfillScheduler::new();
    scheduler.ingest(&reports);

    let tasks = scheduler.drain_eligible();
    assert_eq!(tasks.len(), 3);
    // Rebuild (highest) → Backfill → Rebalance (lowest)
    assert_eq!(
        tasks[0].movement_class,
        ReplicaMovementClass::RebuildLostOrSuspectCopy
    );
    assert_eq!(
        tasks[1].movement_class,
        ReplicaMovementClass::BackfillLaggedCopy
    );
    assert_eq!(
        tasks[2].movement_class,
        ReplicaMovementClass::RebalanceCapacityPressure
    );
}

#[test]
fn engine_verifies_source_and_destination_checksums() {
    let data = b"checksum verification test";
    let mut source = MemStore::default();
    let mut target = MemStore::default();

    let task = BackfillTask::new(BackfillTaskInit {
        subject_ref: ReplicatedSubjectId::new(99),
        placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
            ReplicatedSubjectId::new(99),
        ),
        source_member: MemberId::new(10),
        target_member: MemberId::new(20),
        movement_class: ReplicaMovementClass::BackfillLaggedCopy,
        payload_digest: ObjectDigest::new(0xDEAD),
        payload_len: data.len() as u64,
        created_at_ns: 1000,
        deadline_ns: 5000,
    });

    populate_source(&mut source, 99, ObjectDigest::new(0xDEAD), data);

    let engine = DataMovementEngine::new();
    let mut progress = BackfillProgress::new(task.payload_len, 3);
    progress.schedule().unwrap();

    engine
        .execute(&task, &source, &mut target, &mut progress)
        .unwrap();

    assert_eq!(progress.state, TaskState::Complete);

    // Verify data integrity
    let key = task_object_key(&task);
    let source_data = source.get(&key).unwrap().unwrap();
    let target_data = target.get(&key).unwrap().unwrap();
    assert_eq!(source_data, target_data);

    let source_hash = blake3::hash(&source_data);
    let target_hash = blake3::hash(&target_data);
    assert_eq!(source_hash.as_bytes(), target_hash.as_bytes());
}

#[test]
fn receipt_source_execution_uses_receipt_key_not_logical_object_id() {
    let data = b"receipt source execution payload";
    let object_id = 7001u64;
    let receipt_key = ObjectKey::from_bytes32([0xA7; 32]);
    let legacy_key = ObjectKey::from_name(object_id.to_le_bytes());
    let receipt = receipt_ref_for_payload(object_id, receipt_key, data, 3);
    let task = task_from_receipt(receipt, 10, 20);
    let mut source = MockReceiptSource::default();
    let mut target = MemStore::default();
    let engine = DataMovementEngine::new();
    let mut progress = BackfillProgress::new(task.payload_len, task.max_retries);

    source.insert(receipt_key, data);
    target.put(legacy_key, b"legacy target bytes").unwrap();
    progress.schedule().unwrap();

    engine
        .execute_from_receipt_source(&task, &mut source, &mut target, &mut progress)
        .unwrap();

    assert_eq!(source.calls.len(), 1);
    assert_eq!(
        source.calls[0],
        ReceiptFetchCall {
            source_member: MemberId::new(10),
            object_id,
            segment_offset: 0,
            segment_length: data.len() as u64,
        }
    );
    assert_eq!(target.get(&receipt_key).unwrap(), Some(data.to_vec()));
    assert_eq!(
        target.get(&legacy_key).unwrap(),
        Some(b"legacy target bytes".to_vec())
    );
    assert_eq!(progress.state, TaskState::Complete);
}

#[test]
fn receipt_source_execution_rejects_synthetic_receipt_before_fetch() {
    let data = b"synthetic receipt must not fetch";
    let mut source = MockReceiptSource::default();
    let mut target = MemStore::default();
    let task = BackfillTask::new(BackfillTaskInit {
        subject_ref: ReplicatedSubjectId::new(7002),
        placement_receipt_ref: PlacementReceiptRef::synthetic_for_subject(
            ReplicatedSubjectId::new(7002),
        ),
        source_member: MemberId::new(10),
        target_member: MemberId::new(20),
        movement_class: ReplicaMovementClass::BackfillLaggedCopy,
        payload_digest: ObjectDigest::new(0x55),
        payload_len: data.len() as u64,
        created_at_ns: 1000,
        deadline_ns: 5000,
    });
    let engine = DataMovementEngine::new();
    let mut progress = BackfillProgress::new(task.payload_len, task.max_retries);

    progress.schedule().unwrap();
    let err = engine
        .execute_from_receipt_source(&task, &mut source, &mut target, &mut progress)
        .unwrap_err();

    assert!(matches!(
        err,
        EngineError::SyntheticReceiptRef { object_id: 7002 }
    ));
    assert!(source.calls.is_empty());
    assert!(target.objects.is_empty());
}
