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
use tidefs_replication_model::PlacementReceiptRef;
use tidefs_scrub::repair_scheduling::{
    RepairAdmission, RepairAdmissionInput, RepairEscalation, RepairEvidenceClass,
    RepairEvidenceRejection, ScrubToRepairBridge,
};
use tidefs_scrub::scrub_repair::{BlockReconstructor, ScrubRepairEngine, ScrubRepairLedger};

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

fn input_with_receipt(entry: SuspectEntry) -> RepairAdmissionInput {
    RepairAdmissionInput::with_receipt(entry, receipt_for_entry(&entry))
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
    let result = engine.repair_one(1, &expected, &corrupt_data);
    assert!(result);

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
        assert!(engine.repair_one(*addr, expected, &corrupt));
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
    assert!(engine.repair_one(100, &expected, &corrupt_data));
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
    assert!(!engine.repair_one(999, &expected, &corrupt_data));
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
    engine1.repair_one(10, &expected, &corrupt);
    engine2.repair_one(10, &expected, &corrupt);
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
    assert!(!engine.repair_one(1, &expected, &corrupt));
    assert_eq!(engine.ledger().repair_failure_count, 1);
    assert_eq!(engine.ledger().repair_count, 0);
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
    assert_eq!(results, vec![true, true, false, true]);
    assert_eq!(engine.ledger().repair_count, 1);
    assert_eq!(engine.ledger().repair_failure_count, 1);
}

#[test]
fn receipt_backed_repair_admission_records_evidence() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(700);
    let receipt = receipt_for_entry(&entry);
    let input = RepairAdmissionInput::with_receipt(entry, receipt);

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
    assert_eq!(
        jobs[0].evidence.class,
        RepairEvidenceClass::PlacementReceipt
    );
    assert_eq!(jobs[0].evidence.placement_receipt_ref, receipt);
    assert_eq!(bridge.stats().entries_admitted_with_receipt, 1);
    assert_eq!(bridge.stats().by_evidence_class[0], 1);
}

#[test]
fn missing_receipt_repair_admission_blocks_queueing() {
    let mut bridge = ScrubToRepairBridge::new();
    let entry = make_suspect_entry(701);

    let admissions = bridge.ingest(&[entry], 2);

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
    let input = RepairAdmissionInput::with_receipt(entry, stale_receipt);

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
    let input = RepairAdmissionInput::with_receipt(entry, stale_receipt);

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
