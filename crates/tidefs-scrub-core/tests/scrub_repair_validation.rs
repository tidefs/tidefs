// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BLAKE3-verified scrub-repair validation harness.
//!
//! Domain: `tidefs-scrub-repair-v1`
//!
//! 10 integration tests covering single-block corruption repair,
//! multi-block repair, clean-block passthrough, repair-from-replication,
//! unrepairable failure paths, write-back failures, validation determinism,
//! ledger tamper detection, mixed batch outcomes, and empty ledger state.

use std::collections::HashMap;
use std::sync::Mutex;
use tidefs_local_object_store::SuspectEntry;
use tidefs_replication_model::{PlacementReceiptRef, ReceiptRedundancyPolicy};
use tidefs_scrub::repair_scheduling::{
    RepairAdmission, RepairAdmissionInput, RepairBlockKind, RepairCandidateIdentity,
    RepairEscalation, RepairEvidenceClass, RepairEvidenceRejection, RepairMountedChecksumEvidence,
    RepairMountedReceiptEvidenceStatus, RepairMountedScrubEvidence, ScrubToRepairBridge,
};
use tidefs_scrub::scrub_repair::{
    BlockReconstructor, ScrubRepairEngine, ScrubRepairLedger, ScrubRepairOutcome,
};
use tidefs_scrub::{
    ChecksumLayer, ComparisonClassification, CrossReplicaComparisonRecord, ScrubSubject,
    ScrubSubjectKind,
};

struct MockReconstructor {
    healthy_blocks: Mutex<HashMap<u64, Vec<u8>>>,
    written: Mutex<HashMap<u64, Vec<u8>>>,
    fail_reconstruct: Mutex<bool>,
    fail_write: Mutex<bool>,
}

impl MockReconstructor {
    fn new() -> Self {
        Self {
            healthy_blocks: Mutex::new(HashMap::new()),
            written: Mutex::new(HashMap::new()),
            fail_reconstruct: Mutex::new(false),
            fail_write: Mutex::new(false),
        }
    }

    fn set_healthy_block(&self, addr: u64, data: Vec<u8>) {
        self.healthy_blocks.lock().unwrap().insert(addr, data);
    }

    fn set_fail_reconstruct(&self, fail: bool) {
        *self.fail_reconstruct.lock().unwrap() = fail;
    }

    fn set_fail_write(&self, fail: bool) {
        *self.fail_write.lock().unwrap() = fail;
    }
}

impl BlockReconstructor for MockReconstructor {
    fn reconstruct(
        &self,
        block_address: u64,
        _expected_hash: &[u8; 32],
    ) -> Result<(Vec<u8>, Vec<u64>), String> {
        if *self.fail_reconstruct.lock().unwrap() {
            return Err("mock reconstruction failure".into());
        }
        let blocks = self.healthy_blocks.lock().unwrap();
        blocks
            .get(&block_address)
            .cloned()
            .map(|data| (data, vec![block_address + 1000]))
            .ok_or_else(|| format!("no healthy replica for block {block_address}"))
    }

    fn write_back(&self, block_address: u64, data: &[u8]) -> Result<(), String> {
        if *self.fail_write.lock().unwrap() {
            return Err("mock write failure".into());
        }
        self.written
            .lock()
            .unwrap()
            .insert(block_address, data.to_vec());
        Ok(())
    }
}

fn make_data(size: usize, pattern: u8) -> Vec<u8> {
    vec![pattern; size]
}

fn hash_data(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

fn make_suspect_entry(locator_id: u64) -> SuspectEntry {
    SuspectEntry {
        entry_id: locator_id,
        locator_id,
        segment_id: 7,
        offset: locator_id * 4096,
        record_type: 1,
        expected_hash: [0xAA; 32],
        actual_hash: [0xBB; 32],
        repair_attempts: 0,
        last_repair_attempt: 0,
        resolved: false,
        commit_group: 3,
        timestamp_secs: 10,
    }
}

fn receipt_for_entry(entry: &SuspectEntry) -> PlacementReceiptRef {
    let mut object_key = [0u8; 32];
    object_key[..8].copy_from_slice(&entry.locator_id.to_le_bytes());
    PlacementReceiptRef::replicated(
        entry.locator_id,
        object_key,
        Default::default(),
        entry.commit_group,
        2,
        4096,
        entry.expected_hash,
    )
}

fn receipt_with_target_count(entry: &SuspectEntry, target_count: u16) -> PlacementReceiptRef {
    let base = receipt_for_entry(entry);
    PlacementReceiptRef::new(
        base.object_id,
        base.object_key,
        base.receipt_epoch,
        base.receipt_generation,
        ReceiptRedundancyPolicy::Replicated { copies: 2 },
        base.payload_len,
        base.payload_digest,
        target_count,
    )
}

fn input_with_receipt(entry: SuspectEntry) -> RepairAdmissionInput {
    let receipt = receipt_for_entry(&entry);
    let identity = identity_for_entry(&entry);
    let comparison = comparison_record_for_entry(
        &entry,
        ComparisonClassification::SingleReplicaCorruption {
            corrupt_replica: 1,
            clean_sources: vec![2],
        },
    );
    input_with_receipt_ref_and_identity(entry, receipt, identity)
        .with_cross_replica_comparison(&comparison)
}

fn identity_for_entry(entry: &SuspectEntry) -> RepairCandidateIdentity {
    let kind = if entry.offset == 0 {
        RepairBlockKind::InlineContent
    } else {
        RepairBlockKind::ContentChunk {
            chunk_index: entry.offset,
        }
    };
    RepairCandidateIdentity::new(entry.locator_id, entry.segment_id, kind)
}

fn subject_kind_for_entry(entry: &SuspectEntry) -> ScrubSubjectKind {
    if entry.offset == 0 {
        ScrubSubjectKind::InlineContent
    } else {
        ScrubSubjectKind::ContentChunk {
            chunk_index: entry.offset,
        }
    }
}

fn checksum_layer_for_entry(entry: &SuspectEntry) -> ChecksumLayer {
    if entry.offset == 0 {
        ChecksumLayer::InlineContentBody
    } else {
        ChecksumLayer::EncodedContentChunk
    }
}

fn mounted_scrub_evidence_for_entry(
    entry: &SuspectEntry,
    receipt_generation: u64,
) -> RepairMountedScrubEvidence {
    RepairMountedScrubEvidence {
        subject: identity_for_entry(entry),
        expected_plaintext_len: 4096,
        observed_plaintext_len: Some(4096),
        checksum: RepairMountedChecksumEvidence {
            layer: checksum_layer_for_entry(entry),
            expected: Some(entry.expected_hash),
            actual: entry.actual_hash,
            encoded_len: 4096,
        },
        receipt_status: RepairMountedReceiptEvidenceStatus::ReceiptVerified {
            generation: receipt_generation,
        },
    }
}

fn input_with_receipt_ref(
    entry: SuspectEntry,
    receipt: PlacementReceiptRef,
) -> RepairAdmissionInput {
    input_with_receipt_ref_and_identity(entry, receipt, identity_for_entry(&entry))
}

fn input_with_receipt_ref_and_identity(
    entry: SuspectEntry,
    receipt: PlacementReceiptRef,
    identity: RepairCandidateIdentity,
) -> RepairAdmissionInput {
    let receipt_generation = receipt.receipt_generation;
    RepairAdmissionInput::with_receipt_and_identity(entry, receipt, identity)
        .with_mounted_scrub_evidence(mounted_scrub_evidence_for_entry(&entry, receipt_generation))
}

fn comparison_sets(classification: &ComparisonClassification) -> (Vec<u64>, Vec<u64>) {
    match classification {
        ComparisonClassification::SingleReplicaCorruption {
            corrupt_replica,
            clean_sources,
        }
        | ComparisonClassification::RemoteReplicaCorruption {
            corrupt_replica,
            clean_sources,
        } => (clean_sources.clone(), vec![*corrupt_replica]),
        _ => (Vec::new(), Vec::new()),
    }
}

fn comparison_record_for_entry(
    entry: &SuspectEntry,
    classification: ComparisonClassification,
) -> CrossReplicaComparisonRecord {
    let receipt = receipt_for_entry(entry);
    let (clean_source_set, corrupt_target_set) = comparison_sets(&classification);
    CrossReplicaComparisonRecord {
        subject: ScrubSubject {
            inode_id: entry.locator_id,
            data_version: entry.segment_id,
            kind: subject_kind_for_entry(entry),
        },
        object_key: receipt.object_key,
        checksum_layer: checksum_layer_for_entry(entry),
        redundancy_policy_id: 1,
        target_count: receipt.target_count,
        placement_receipt_epoch: receipt.receipt_epoch.0,
        placement_receipt_generation: receipt.receipt_generation,
        membership_epoch: 1,
        replica_outcomes: Vec::new(),
        classification,
        clean_source_set,
        corrupt_target_set,
    }
}

fn repair_comparison_record() -> CrossReplicaComparisonRecord {
    comparison_record_for_entry(
        &make_suspect_entry(1),
        ComparisonClassification::SingleReplicaCorruption {
            corrupt_replica: 1,
            clean_sources: vec![2],
        },
    )
}

// 1. Single-block corruption repaired
#[test]
fn single_block_corruption_repaired() {
    let recon = MockReconstructor::new();
    let healthy_data = make_data(256, 0xCA);
    let expected = hash_data(&healthy_data);
    recon.set_healthy_block(1, healthy_data.clone());

    let mut engine = ScrubRepairEngine::new(recon);
    let corrupt_data = make_data(256, 0xFE);
    let comparison = repair_comparison_record();
    let result = engine.repair_one_with_comparison(1, &expected, &corrupt_data, Some(&comparison));
    assert!(result.is_success());

    let ledger = engine.ledger();
    assert_eq!(ledger.repair_count, 1);
    assert_eq!(ledger.repair_failure_count, 0);
    assert_eq!(ledger.event_count(), 1);
    assert!(ledger.events()[0].success);
    assert_eq!(ledger.events()[0].rebuilt_hash, expected);
}

// 2. Clean block no action
#[test]
fn clean_block_no_action() {
    let recon = MockReconstructor::new();
    let mut engine = ScrubRepairEngine::new(recon);
    let data = make_data(128, 0x42);
    let expected = hash_data(&data);
    assert!(engine.repair_one(42, &expected, &data));
    assert_eq!(engine.ledger().repair_count, 0);
    assert_eq!(engine.ledger().event_count(), 0);
}

// 3. Multi-block corruption all repaired
#[test]
fn multi_block_corruption_all_repaired() {
    let recon = MockReconstructor::new();
    let mut expected_hashes = Vec::new();
    for i in 0..5 {
        let healthy = make_data(128, i as u8);
        let exp = hash_data(&healthy);
        recon.set_healthy_block(i, healthy);
        expected_hashes.push((i, exp));
    }
    let mut engine = ScrubRepairEngine::new(recon);
    for (addr, expected) in &expected_hashes {
        let corrupt = make_data(128, 0xFF);
        let comparison = repair_comparison_record();
        assert!(engine
            .repair_one_with_comparison(*addr, expected, &corrupt, Some(&comparison))
            .is_success());
    }
    assert_eq!(engine.ledger().repair_count, 5);
    assert_eq!(engine.ledger().repair_failure_count, 0);
}

// 4. Repair-from-replication
#[test]
fn repair_from_replication_reads_healthy_replica() {
    let recon = MockReconstructor::new();
    let healthy_data = make_data(512, 0xAB);
    let expected = hash_data(&healthy_data);
    recon.set_healthy_block(100, healthy_data);
    let mut engine = ScrubRepairEngine::new(recon);
    let corrupt_data = make_data(512, 0xCD);
    let comparison = repair_comparison_record();
    assert!(engine
        .repair_one_with_comparison(100, &expected, &corrupt_data, Some(&comparison))
        .is_success());
    assert_eq!(engine.ledger().events()[0].shard_sources, vec![1100]);
}

// 5. Unrepairable block records failure
#[test]
fn unrepairable_block_records_failure() {
    let recon = MockReconstructor::new();
    recon.set_fail_reconstruct(true);
    let mut engine = ScrubRepairEngine::new(recon);
    let corrupt_data = make_data(256, 0xDE);
    let expected = hash_data(&make_data(256, 0xAD));
    let comparison = repair_comparison_record();
    assert_eq!(
        engine.repair_one_with_comparison(999, &expected, &corrupt_data, Some(&comparison)),
        ScrubRepairOutcome::ReconstructionFailed
    );
    assert_eq!(engine.ledger().repair_failure_count, 1);
    assert_eq!(engine.ledger().repair_count, 0);
}

// 6. Ledger tampering changes validation digest
#[test]
fn ledger_tampering_changes_validation_digest() {
    let mut l1 = ScrubRepairLedger::new();
    l1.record_repair(tidefs_scrub::scrub_repair::ScrubRepairEvent {
        block_address: 1,
        expected_hash: [0x01; 32],
        corrupted_hash: [0x02; 32],
        rebuilt_hash: [0x01; 32],
        shard_sources: vec![100],
        timestamp_secs: 5000,
        success: true,
        integrity_outcome: None,
    });
    let digest1 = l1.validation_digest();
    l1.record_repair(tidefs_scrub::scrub_repair::ScrubRepairEvent {
        block_address: 2,
        expected_hash: [0x03; 32],
        corrupted_hash: [0x04; 32],
        rebuilt_hash: [0x03; 32],
        shard_sources: vec![200],
        timestamp_secs: 5001,
        success: true,
        integrity_outcome: None,
    });
    assert_ne!(digest1, l1.validation_digest());
}

// 7. BLAKE3 determinism
#[test]
fn deterministic_repair_sequence_same_digest() {
    let recon1 = MockReconstructor::new();
    let recon2 = MockReconstructor::new();
    let healthy = make_data(256, 0x77);
    let expected = hash_data(&healthy);
    recon1.set_healthy_block(10, healthy.clone());
    recon2.set_healthy_block(10, healthy.clone());
    let mut engine1 = ScrubRepairEngine::new(recon1);
    let mut engine2 = ScrubRepairEngine::new(recon2);
    let corrupt = make_data(256, 0x88);
    let comparison = repair_comparison_record();
    engine1.repair_one_with_comparison(10, &expected, &corrupt, Some(&comparison));
    engine2.repair_one_with_comparison(10, &expected, &corrupt, Some(&comparison));
    assert_eq!(
        engine1.ledger().validation_digest(),
        engine2.ledger().validation_digest()
    );
}

// 8. Empty ledger digest
#[test]
fn empty_ledger_digest_is_nonzero() {
    let ledger = ScrubRepairLedger::new();
    let digest = ledger.validation_digest();
    assert!(!digest.iter().all(|&b| b == 0));
}

// 9. Write-back failure
#[test]
fn write_back_failure_records_failure() {
    let recon = MockReconstructor::new();
    let healthy = make_data(256, 0x55);
    let expected = hash_data(&healthy);
    recon.set_healthy_block(1, healthy);
    recon.set_fail_write(true);
    let mut engine = ScrubRepairEngine::new(recon);
    let corrupt = make_data(256, 0x66);
    let comparison = repair_comparison_record();
    assert_eq!(
        engine.repair_one_with_comparison(1, &expected, &corrupt, Some(&comparison)),
        ScrubRepairOutcome::WritebackFailed
    );
    assert_eq!(engine.ledger().repair_failure_count, 1);
    assert_eq!(engine.ledger().repair_count, 0);
}

#[test]
fn missing_comparison_repair_refuses_before_reconstruction() {
    let recon = MockReconstructor::new();
    recon.set_fail_reconstruct(true);
    let mut engine = ScrubRepairEngine::new(recon);
    let expected = hash_data(&make_data(256, 0x55));
    let corrupt = make_data(256, 0x66);

    assert_eq!(
        engine.repair_one_with_comparison(1, &expected, &corrupt, None),
        ScrubRepairOutcome::MissingComparisonRecord
    );
    assert_eq!(engine.ledger().repair_count, 0);
    assert_eq!(engine.ledger().repair_failure_count, 0);
}

#[test]
fn disagreement_comparison_repair_refuses_before_reconstruction() {
    let recon = MockReconstructor::new();
    recon.set_fail_reconstruct(true);
    let mut engine = ScrubRepairEngine::new(recon);
    let expected = hash_data(&make_data(256, 0x55));
    let corrupt = make_data(256, 0x66);
    let mut comparison = repair_comparison_record();
    comparison.classification = ComparisonClassification::CrossReplicaDisagreement;
    comparison.clean_source_set.clear();
    comparison.corrupt_target_set.clear();

    assert_eq!(
        engine.repair_one_with_comparison(1, &expected, &corrupt, Some(&comparison)),
        ScrubRepairOutcome::CrossReplicaDisagreement
    );
    assert_eq!(engine.ledger().repair_count, 0);
    assert_eq!(engine.ledger().repair_failure_count, 0);
}

#[test]
fn remote_corruption_comparison_repair_refuses_before_reconstruction() {
    let recon = MockReconstructor::new();
    recon.set_fail_reconstruct(true);
    let mut engine = ScrubRepairEngine::new(recon);
    let expected = hash_data(&make_data(256, 0x55));
    let corrupt = make_data(256, 0x66);
    let mut comparison = comparison_record_for_entry(
        &make_suspect_entry(1),
        ComparisonClassification::RemoteReplicaCorruption {
            corrupt_replica: 2,
            clean_sources: vec![1],
        },
    );

    assert_eq!(
        engine.repair_one_with_comparison(1, &expected, &corrupt, Some(&comparison)),
        ScrubRepairOutcome::UnreconciledComparison {
            classification: "remote-replica-corruption"
        }
    );
    comparison.classification = ComparisonClassification::ChecksumAuthorityDisagreement;
    comparison.clean_source_set.clear();
    comparison.corrupt_target_set.clear();
    assert_eq!(
        engine.repair_one_with_comparison(1, &expected, &corrupt, Some(&comparison)),
        ScrubRepairOutcome::CrossReplicaDisagreement
    );
    assert_eq!(engine.ledger().repair_count, 0);
    assert_eq!(engine.ledger().repair_failure_count, 0);
}

#[test]
fn stale_comparison_repair_refuses_before_reconstruction() {
    let recon = MockReconstructor::new();
    recon.set_fail_reconstruct(true);
    let mut engine = ScrubRepairEngine::new(recon);
    let expected = hash_data(&make_data(256, 0x55));
    let corrupt = make_data(256, 0x66);
    let mut comparison = repair_comparison_record();
    comparison.classification = ComparisonClassification::StaleEvidence {
        stale_replicas: vec![1],
    };
    comparison.clean_source_set.clear();
    comparison.corrupt_target_set.clear();

    assert_eq!(
        engine.repair_one_with_comparison(1, &expected, &corrupt, Some(&comparison)),
        ScrubRepairOutcome::StaleComparisonRecord
    );
    assert_eq!(engine.ledger().repair_count, 0);
    assert_eq!(engine.ledger().repair_failure_count, 0);
}

// 10. repair_batch mixed outcomes
#[test]
fn repair_batch_mixed_outcomes() {
    let recon = MockReconstructor::new();
    let healthy_a = make_data(64, 0x01);
    recon.set_healthy_block(1, healthy_a.clone());
    let healthy_b = make_data(64, 0x02);
    recon.set_healthy_block(2, healthy_b.clone());
    let mut engine = ScrubRepairEngine::new(recon);
    let blocks = vec![
        (1, hash_data(&healthy_a), make_data(64, 0xFE)),
        (2, hash_data(&healthy_b), make_data(64, 0x02)),
        (3, [0x99; 32], make_data(64, 0xAB)),
        (4, hash_data(&make_data(64, 0x10)), make_data(64, 0x10)),
    ];
    let results = engine.repair_batch(&blocks);
    assert_eq!(results, vec![false, true, false, true]);
    assert_eq!(engine.ledger().repair_count, 0);
    assert_eq!(engine.ledger().repair_failure_count, 0);
}

#[test]
fn receipt_backed_repair_admission_records_evidence() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(700);
    let receipt = receipt_for_entry(&entry);
    let input = input_with_receipt(entry);

    let admissions = bridge.ingest_with_evidence(&[input], 2);

    assert_eq!(
        admissions,
        vec![RepairAdmission::Admitted {
            locator_id: 700,
            evidence_class: RepairEvidenceClass::PlacementReceipt,
        }]
    );
    let jobs = bridge.prioritized_jobs();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].entry.locator_id, 700);
    assert_eq!(jobs[0].candidate_identity, identity_for_entry(&entry));
    assert_eq!(
        jobs[0].evidence.class,
        RepairEvidenceClass::PlacementReceipt
    );
    assert_eq!(jobs[0].evidence.placement_receipt_ref, receipt);
    assert_eq!(bridge.stats().entries_admitted_with_receipt, 1);
    assert_eq!(bridge.stats().by_evidence_class[0], 1);
}

#[test]
fn missing_comparison_repair_admission_blocks_queueing() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(709);
    let receipt = receipt_for_entry(&entry);
    let input = input_with_receipt_ref(entry, receipt);

    let admissions = bridge.ingest_with_evidence(&[input], 2);

    assert_eq!(
        admissions,
        vec![RepairAdmission::Blocked {
            locator_id: 709,
            reason: RepairEvidenceRejection::MissingComparisonRecord,
        }]
    );
    assert_eq!(bridge.pending_count(), 0);
    assert_eq!(bridge.stats().entries_blocked_missing_comparison, 1);
}

#[test]
fn disagreement_comparison_repair_admission_blocks_queueing() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(710);
    let receipt = receipt_for_entry(&entry);
    let comparison =
        comparison_record_for_entry(&entry, ComparisonClassification::CrossReplicaDisagreement);
    let input = input_with_receipt_ref(entry, receipt).with_cross_replica_comparison(&comparison);

    let admissions = bridge.ingest_with_evidence(&[input], 2);

    assert_eq!(
        admissions,
        vec![RepairAdmission::Blocked {
            locator_id: 710,
            reason: RepairEvidenceRejection::CrossReplicaDisagreement,
        }]
    );
    assert_eq!(bridge.pending_count(), 0);
    assert_eq!(bridge.stats().entries_blocked_cross_replica_disagreement, 1);
}

#[test]
fn remote_corruption_comparison_repair_admission_blocks_queueing() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(712);
    let receipt = receipt_for_entry(&entry);
    let comparison = comparison_record_for_entry(
        &entry,
        ComparisonClassification::RemoteReplicaCorruption {
            corrupt_replica: 2,
            clean_sources: vec![1],
        },
    );
    let input = input_with_receipt_ref(entry, receipt).with_cross_replica_comparison(&comparison);

    let admissions = bridge.ingest_with_evidence(&[input], 2);

    assert_eq!(
        admissions,
        vec![RepairAdmission::Blocked {
            locator_id: 712,
            reason: RepairEvidenceRejection::UnreconciledComparison,
        }]
    );
    assert_eq!(bridge.pending_count(), 0);
    assert_eq!(bridge.stats().entries_blocked_unreconciled_comparison, 1);
}

#[test]
fn checksum_authority_comparison_repair_admission_blocks_as_disagreement() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(713);
    let receipt = receipt_for_entry(&entry);
    let comparison = comparison_record_for_entry(
        &entry,
        ComparisonClassification::ChecksumAuthorityDisagreement,
    );
    let input = input_with_receipt_ref(entry, receipt).with_cross_replica_comparison(&comparison);

    let admissions = bridge.ingest_with_evidence(&[input], 2);

    assert_eq!(
        admissions,
        vec![RepairAdmission::Blocked {
            locator_id: 713,
            reason: RepairEvidenceRejection::CrossReplicaDisagreement,
        }]
    );
    assert_eq!(bridge.pending_count(), 0);
    assert_eq!(bridge.stats().entries_blocked_cross_replica_disagreement, 1);
}

#[test]
fn stale_comparison_repair_admission_blocks_queueing() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(711);
    let receipt = receipt_for_entry(&entry);
    let mut comparison = comparison_record_for_entry(
        &entry,
        ComparisonClassification::SingleReplicaCorruption {
            corrupt_replica: 1,
            clean_sources: vec![2],
        },
    );
    comparison.placement_receipt_generation =
        comparison.placement_receipt_generation.saturating_sub(1);
    let input = input_with_receipt_ref(entry, receipt).with_cross_replica_comparison(&comparison);

    let admissions = bridge.ingest_with_evidence(&[input], 2);

    assert_eq!(
        admissions,
        vec![RepairAdmission::Blocked {
            locator_id: 711,
            reason: RepairEvidenceRejection::StaleComparisonRecord,
        }]
    );
    assert_eq!(bridge.pending_count(), 0);
    assert_eq!(bridge.stats().entries_blocked_stale_comparison, 1);
}

#[test]
fn missing_mounted_scrub_evidence_blocks_queueing() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(701);

    let admissions = bridge.ingest(&[entry], 2);

    assert_eq!(
        admissions,
        vec![RepairAdmission::Blocked {
            locator_id: 701,
            reason: RepairEvidenceRejection::MissingMountedScrubEvidence,
        }]
    );
    assert_eq!(bridge.pending_count(), 0);
    assert_eq!(
        bridge
            .stats()
            .entries_blocked_missing_mounted_scrub_evidence,
        1
    );
}

#[test]
fn missing_receipt_repair_admission_blocks_queueing() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(701);
    let mounted =
        mounted_scrub_evidence_for_entry(&entry, receipt_for_entry(&entry).receipt_generation);
    let input = RepairAdmissionInput::missing_receipt(entry).with_mounted_scrub_evidence(mounted);

    let admissions = bridge.ingest_with_evidence(&[input], 2);

    assert_eq!(
        admissions,
        vec![RepairAdmission::Blocked {
            locator_id: 701,
            reason: RepairEvidenceRejection::MissingReceipt,
        }]
    );
    assert_eq!(bridge.pending_count(), 0);
    assert_eq!(bridge.stats().entries_blocked_missing_receipt, 1);
}

#[test]
fn stale_receipt_repair_admission_blocks_queueing() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(702);
    let stale_receipt = receipt_for_entry(&make_suspect_entry(1702));
    let comparison = comparison_record_for_entry(
        &entry,
        ComparisonClassification::SingleReplicaCorruption {
            corrupt_replica: 1,
            clean_sources: vec![2],
        },
    );
    let input =
        input_with_receipt_ref(entry, stale_receipt).with_cross_replica_comparison(&comparison);

    let admissions = bridge.ingest_with_evidence(&[input], 2);

    assert_eq!(
        admissions,
        vec![RepairAdmission::Blocked {
            locator_id: 702,
            reason: RepairEvidenceRejection::StaleReceipt,
        }]
    );
    assert_eq!(bridge.pending_count(), 0);
    assert_eq!(bridge.stats().entries_blocked_stale_receipt, 1);
}

#[test]
fn stale_receipt_payload_digest_blocks_queueing() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(705);
    let mut stale_receipt = receipt_for_entry(&entry);
    stale_receipt.payload_digest = [0xEE; 32];
    let input = input_with_receipt_ref(entry, stale_receipt);

    let admissions = bridge.ingest_with_evidence(&[input], 2);

    assert_eq!(
        admissions,
        vec![RepairAdmission::Blocked {
            locator_id: 705,
            reason: RepairEvidenceRejection::StaleReceipt,
        }]
    );
    assert_eq!(bridge.pending_count(), 0);
    assert_eq!(bridge.stats().entries_blocked_stale_receipt, 1);
}

#[test]
fn policy_width_receipts_block_repair_admission() {
    for (locator_id, target_count) in [(707, 1u16), (708, 3u16)] {
        let mut bridge = ScrubToRepairBridge::new();
        let entry = make_suspect_entry(locator_id);
        let receipt = receipt_with_target_count(&entry, target_count);
        let input = input_with_receipt_ref(entry, receipt);

        let admissions = bridge.ingest_with_evidence(&[input], 2);

        assert_eq!(
            admissions,
            vec![RepairAdmission::Blocked {
                locator_id,
                reason: RepairEvidenceRejection::StaleReceipt,
            }]
        );
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.stats().entries_blocked_stale_receipt, 1);
    }
}

#[test]
fn mismatched_candidate_identity_blocks_queueing() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(706);
    let mismatched_identity = RepairCandidateIdentity::new(
        entry.locator_id,
        entry.segment_id + 1,
        RepairBlockKind::InlineContent,
    );
    let receipt = receipt_for_entry(&entry);
    let input = input_with_receipt_ref_and_identity(entry, receipt, mismatched_identity);

    let admissions = bridge.ingest_with_evidence(&[input], 2);

    assert_eq!(
        admissions,
        vec![RepairAdmission::Blocked {
            locator_id: 706,
            reason: RepairEvidenceRejection::CandidateIdentityMismatch,
        }]
    );
    assert_eq!(bridge.pending_count(), 0);
    assert_eq!(bridge.stats().entries_blocked_identity_mismatch, 1);
}

#[test]
fn degraded_read_escalates_with_receipt_evidence() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(703);
    let input = input_with_receipt(entry).with_degraded_read();

    bridge.ingest_with_evidence(&[input], 2);

    let jobs = bridge.jobs_at_level(RepairEscalation::Immediate);
    assert_eq!(jobs.len(), 1);
    assert!(jobs[0].degraded_read_active);
    assert_eq!(
        jobs[0].evidence.class,
        RepairEvidenceClass::PlacementReceipt
    );
}

#[test]
fn retry_escalation_preserves_receipt_evidence_identity() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(704);
    let input = input_with_receipt(entry);

    bridge.ingest_with_evidence(&[input], 2);
    let original_evidence = bridge.prioritized_jobs()[0].evidence;

    bridge.mark_failed(704);
    bridge.mark_failed(704);

    let jobs = bridge.jobs_at_level(RepairEscalation::Urgent);
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].evidence, original_evidence);
    assert_eq!(
        jobs[0].evidence.placement_receipt_ref,
        input.placement_receipt_ref.expect("receipt")
    );
}
