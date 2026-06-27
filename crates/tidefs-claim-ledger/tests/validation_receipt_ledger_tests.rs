// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_claim_ledger::{ClaimEncoding, ValidationReceiptLedger, ValidationReceiptLedgerError};
use tidefs_types_claim_ledger_core::{
    ValidationArtifactDigest, ValidationReceiptDigest, ValidationReceiptProducer,
    ValidationReceiptRecord, ValidationReceiptText,
};

fn text(value: &str) -> ValidationReceiptText {
    ValidationReceiptText::from_str(value)
}

fn claim_id() -> ValidationReceiptText {
    text("local.vfs.write_fsync_crash.v1")
}

fn other_claim_id() -> ValidationReceiptText {
    text("local.vfs.readdir_crash.v1")
}

fn producer() -> ValidationReceiptProducer {
    ValidationReceiptProducer {
        producer_id: text("focused-rust"),
        producer_version: text("ci-v1"),
        run_id: text("github-run-12345"),
        produced_at_millis: 1_781_738_000_000,
    }
}

fn artifact_digest(seed: u8) -> ValidationArtifactDigest {
    let mut digest = [0_u8; 32];
    digest[0] = seed;
    digest[31] = seed.wrapping_mul(17);
    ValidationArtifactDigest::from_bytes(digest)
}

fn receipt(
    sequence: u64,
    previous_receipt_digest: ValidationReceiptDigest,
    status: &str,
) -> ValidationReceiptRecord {
    ValidationReceiptRecord::new(
        sequence,
        claim_id(),
        text("runtime-crash-oracle"),
        text("focused-rust"),
        text(status),
        artifact_digest(sequence as u8 + 1),
        previous_receipt_digest,
        producer(),
    )
}

fn receipt_for_claim(
    sequence: u64,
    cid: ValidationReceiptText,
    previous_receipt_digest: ValidationReceiptDigest,
    status: &str,
) -> ValidationReceiptRecord {
    ValidationReceiptRecord::new(
        sequence,
        cid,
        text("runtime-crash-oracle"),
        text("focused-rust"),
        text(status),
        artifact_digest(sequence as u8 + 1),
        previous_receipt_digest,
        producer(),
    )
}

// Empty ledger

#[test]
fn empty_chain_verifies_with_zero_head() {
    let ledger = ValidationReceiptLedger::new(claim_id());

    assert!(ledger.is_empty());
    assert_eq!(ledger.len(), 0);
    assert_eq!(ledger.claim_id(), claim_id());
    assert_eq!(ledger.head_digest(), ValidationReceiptDigest::ZERO);
    ledger.verify().unwrap();

    let rebuilt = ValidationReceiptLedger::from_parts(claim_id(), Vec::new(), Vec::new()).unwrap();
    assert!(rebuilt.is_empty());
    assert_eq!(rebuilt.head_digest(), ValidationReceiptDigest::ZERO);
    assert_eq!(rebuilt.claim_id(), claim_id());
}

// Deterministic iteration

#[test]
fn deterministic_iteration_yields_insertion_order() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());

    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    let second_digest = ledger.append(receipt(1, first_digest, "fail")).unwrap();
    ledger.append(receipt(2, second_digest, "pass")).unwrap();

    let collected: Vec<&ValidationReceiptRecord> = ledger.iter().collect();
    assert_eq!(collected.len(), 3);
    assert_eq!(collected[0].sequence, 0);
    assert_eq!(collected[1].sequence, 1);
    assert_eq!(collected[2].sequence, 2);
}

#[test]
fn iteration_on_empty_ledger_yields_nothing() {
    let ledger = ValidationReceiptLedger::new(claim_id());
    let collected: Vec<&ValidationReceiptRecord> = ledger.iter().collect();
    assert!(collected.is_empty());
}

#[test]
fn iter_after_into_parts_reconstruction() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    let first = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    ledger.append(receipt(1, first, "pass")).unwrap();
    let (cid, records, digests) = ledger.into_parts();

    let rebuilt = ValidationReceiptLedger::from_parts(cid, records, digests).unwrap();
    let iter_records: Vec<&ValidationReceiptRecord> = rebuilt.iter().collect();
    assert_eq!(iter_records.len(), 2);
    assert_eq!(iter_records[0].sequence, 0);
    assert_eq!(iter_records[1].sequence, 1);
}

// Increasing sequence append

#[test]
fn append_and_verify_hash_linked_receipts() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());

    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    assert!(!first_digest.is_zero());

    let second_digest = ledger.append(receipt(1, first_digest, "pass")).unwrap();

    assert_eq!(ledger.len(), 2);
    assert_eq!(ledger.head_digest(), second_digest);
    assert_eq!(
        ledger.records()[0].claim_id.as_str(),
        "local.vfs.write_fsync_crash.v1"
    );
    assert_eq!(ledger.records()[1].previous_receipt_digest, first_digest);
    ledger.verify().unwrap();

    let roundtrip = ValidationReceiptRecord::deserialize(&ledger.records()[0].serialize()).unwrap();
    assert_eq!(roundtrip, ledger.records()[0]);
}

// Duplicate sequence refusal

#[test]
fn duplicate_sequence_number_is_rejected() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();

    let err = ledger.append(receipt(0, first_digest, "pass")).unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::DuplicateSequenceNumber { sequence: 0 }
    ));
}

// Decreasing sequence refusal

#[test]
fn decreasing_sequence_number_is_rejected() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    let second_digest = ledger.append(receipt(1, first_digest, "pass")).unwrap();

    // Try to append with sequence 0 (already used).
    let err = ledger
        .append(receipt(0, second_digest, "pass"))
        .unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::DuplicateSequenceNumber { .. }
    ));
}

// Reordered chain refusal on load

#[test]
fn reordered_receipt_chain_is_rejected_on_load() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    ledger.append(receipt(1, first_digest, "pass")).unwrap();
    let (cid, mut records, mut digests) = ledger.into_parts();
    records.swap(0, 1);
    digests.swap(0, 1);

    let err = ValidationReceiptLedger::from_parts(cid, records, digests).unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::ReorderedReceiptChain {
            expected_sequence: 0,
            actual_sequence: 1
        }
    ));
}

// Historical mutation refusal

#[test]
fn mutated_historical_record_is_rejected_on_load() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    ledger.append(receipt(1, first_digest, "pass")).unwrap();
    let (cid, mut records, digests) = ledger.into_parts();
    records[0].status = text("product-fail");

    let err = ValidationReceiptLedger::from_parts(cid, records, digests).unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::HistoricalMutation { sequence: 0, .. }
    ));
}

// Head digest verification

#[test]
fn retained_head_digest_rejects_silent_chain_replacement() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    ledger.append(receipt(1, first_digest, "pass")).unwrap();
    let retained_head = ledger.head_digest();

    let mut replacement = ValidationReceiptLedger::new(claim_id());
    let first_digest = replacement
        .append(receipt(0, ValidationReceiptDigest::ZERO, "fail"))
        .unwrap();
    replacement
        .append(receipt(1, first_digest, "fail"))
        .unwrap();
    let (cid, records, digests) = replacement.into_parts();
    let rebuilt = ValidationReceiptLedger::from_parts(cid, records, digests).unwrap();

    let err = rebuilt.verify_head_digest(retained_head).unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::HeadDigestMismatch { .. }
    ));
}

// Mismatched claim_id refusal

#[test]
fn mismatched_claim_id_on_append_is_rejected() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());

    let wrong_receipt =
        receipt_for_claim(0, other_claim_id(), ValidationReceiptDigest::ZERO, "pass");
    let err = ledger.append(wrong_receipt).unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::ClaimIdMismatch { .. }
    ));
}

#[test]
fn mismatched_claim_id_on_load_is_rejected() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    ledger.append(receipt(1, first_digest, "pass")).unwrap();
    let (_cid, mut records, digests) = ledger.into_parts();

    // Corrupt the first record's claim_id.
    records[0] = ValidationReceiptRecord::new(
        0,
        other_claim_id(),
        text("runtime-crash-oracle"),
        text("focused-rust"),
        text("pass"),
        artifact_digest(1),
        ValidationReceiptDigest::ZERO,
        producer(),
    );

    let err = ValidationReceiptLedger::from_parts(claim_id(), records, digests).unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::ClaimIdMismatch { .. }
    ));
}

#[test]
fn mismatched_claim_id_on_replay_is_rejected() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());

    let wrong_receipt =
        receipt_for_claim(0, other_claim_id(), ValidationReceiptDigest::ZERO, "pass");
    let err = ledger.replay(wrong_receipt).unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::ClaimIdMismatch { .. }
    ));
}

// Idempotent replay

#[test]
fn replay_idempotent_accepts_identical_record() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    ledger.append(receipt(1, first_digest, "pass")).unwrap();

    // Replay the same records - should succeed silently.
    let r0 = ledger.replay(receipt(0, ValidationReceiptDigest::ZERO, "pass"));
    assert!(r0.is_ok());
    let r1 = ledger.replay(receipt(1, first_digest, "pass"));
    assert!(r1.is_ok());

    // Ledger should be unchanged.
    assert_eq!(ledger.len(), 2);
    ledger.verify().unwrap();
}

#[test]
fn replay_appends_new_record_at_frontier() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();

    // Replay first, then append second via replay.
    ledger
        .replay(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    let second_digest = ledger.replay(receipt(1, first_digest, "pass")).unwrap();

    assert_eq!(ledger.len(), 2);
    assert_eq!(ledger.head_digest(), second_digest);
    ledger.verify().unwrap();
}

#[test]
fn replay_rejects_conflicting_record_at_occupied_sequence() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();

    // Try to replay a different record at sequence 0.
    let err = ledger
        .replay(receipt(0, ValidationReceiptDigest::ZERO, "fail"))
        .unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::ConflictingReplay { sequence: 0 }
    ));
}

#[test]
fn replay_rejects_gap_in_sequence() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());

    // Try to replay sequence 5 on empty ledger.
    let err = ledger
        .replay(receipt(5, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::ReorderedReceiptChain {
            expected_sequence: 0,
            actual_sequence: 5
        }
    ));
}

#[test]
fn replay_preserves_deterministic_iteration() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    ledger.append(receipt(1, first_digest, "pass")).unwrap();

    // Replay both records.
    ledger
        .replay(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    ledger.replay(receipt(1, first_digest, "pass")).unwrap();

    let collected: Vec<&ValidationReceiptRecord> = ledger.iter().collect();
    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0].sequence, 0);
    assert_eq!(collected[1].sequence, 1);
}

// Normal append does not silently accept duplicates

#[test]
fn normal_append_rejects_duplicates_unlike_replay() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();

    // Normal append must reject the duplicate.
    let err = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap_err();
    assert!(matches!(
        err,
        ValidationReceiptLedgerError::DuplicateSequenceNumber { .. }
    ));

    // But replay accepts it.
    assert!(ledger
        .replay(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .is_ok());
}

// Length mismatch

#[test]
fn length_mismatch_is_rejected() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    ledger.append(receipt(1, first_digest, "pass")).unwrap();
    let (cid, records, mut digests) = ledger.into_parts();
    digests.pop(); // one fewer digest than records

    let err = ValidationReceiptLedger::from_parts(cid, records, digests).unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::LengthMismatch {
            record_count: 2,
            digest_count: 1
        }
    ));
}

// Previous digest mismatch on append

#[test]
fn previous_digest_mismatch_is_rejected() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();

    // Append with wrong previous digest (should link to head, but we give ZERO).
    let err = ledger
        .append(receipt(1, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::PreviousDigestMismatch { sequence: 1, .. }
    ));
}

// into_parts / from_parts round-trip

#[test]
fn into_parts_preserves_claim_id() {
    let mut ledger = ValidationReceiptLedger::new(claim_id());
    ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    let (cid, records, digests) = ledger.into_parts();

    assert_eq!(cid, claim_id());
    assert_eq!(records.len(), 1);
    assert_eq!(digests.len(), 1);

    let rebuilt = ValidationReceiptLedger::from_parts(cid, records, digests).unwrap();
    assert_eq!(rebuilt.claim_id(), claim_id());
    assert_eq!(rebuilt.len(), 1);
}

// Error display formatting

#[test]
fn error_display_includes_claim_id_details() {
    let err = ValidationReceiptLedgerError::ClaimIdMismatch {
        expected: claim_id(),
        actual: other_claim_id(),
    };
    let msg = err.to_string();
    assert!(msg.contains("claim_id mismatch"));
    assert!(msg.contains("local.vfs.write_fsync_crash.v1"));
    assert!(msg.contains("local.vfs.readdir_crash.v1"));
}

#[test]
fn error_display_conflicting_replay() {
    let err = ValidationReceiptLedgerError::ConflictingReplay { sequence: 3 };
    let msg = err.to_string();
    assert!(msg.contains("conflicting replay"));
    assert!(msg.contains("3"));
}
