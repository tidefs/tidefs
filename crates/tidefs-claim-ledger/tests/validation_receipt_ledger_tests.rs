// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_claim_ledger::{ClaimEncoding, ValidationReceiptLedger, ValidationReceiptLedgerError};
use tidefs_types_claim_ledger_core::{
    ValidationArtifactDigest, ValidationReceiptDigest, ValidationReceiptProducer,
    ValidationReceiptRecord, ValidationReceiptText,
};

fn text(value: &str) -> ValidationReceiptText {
    ValidationReceiptText::from_str(value)
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
        text("local.vfs.write_fsync_crash.v1"),
        text("runtime-crash-oracle"),
        text("focused-rust"),
        text(status),
        artifact_digest(sequence as u8 + 1),
        previous_receipt_digest,
        producer(),
    )
}

#[test]
fn empty_chain_verifies_with_zero_head() {
    let ledger = ValidationReceiptLedger::new();

    assert!(ledger.is_empty());
    assert_eq!(ledger.len(), 0);
    assert_eq!(ledger.head_digest(), ValidationReceiptDigest::ZERO);
    ledger.verify().unwrap();

    let rebuilt = ValidationReceiptLedger::from_parts(Vec::new(), Vec::new()).unwrap();
    assert!(rebuilt.is_empty());
    assert_eq!(rebuilt.head_digest(), ValidationReceiptDigest::ZERO);
}

#[test]
fn append_and_verify_hash_linked_receipts() {
    let mut ledger = ValidationReceiptLedger::new();

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

#[test]
fn duplicate_sequence_number_is_rejected() {
    let mut ledger = ValidationReceiptLedger::new();
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();

    let err = ledger.append(receipt(0, first_digest, "pass")).unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::DuplicateSequenceNumber { sequence: 0 }
    ));
}

#[test]
fn reordered_receipt_chain_is_rejected_on_load() {
    let mut ledger = ValidationReceiptLedger::new();
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    ledger.append(receipt(1, first_digest, "pass")).unwrap();
    let (mut records, mut digests) = ledger.into_parts();
    records.swap(0, 1);
    digests.swap(0, 1);

    let err = ValidationReceiptLedger::from_parts(records, digests).unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::ReorderedReceiptChain {
            expected_sequence: 0,
            actual_sequence: 1
        }
    ));
}

#[test]
fn mutated_historical_record_is_rejected_on_load() {
    let mut ledger = ValidationReceiptLedger::new();
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    ledger.append(receipt(1, first_digest, "pass")).unwrap();
    let (mut records, digests) = ledger.into_parts();
    records[0].status = text("product-fail");

    let err = ValidationReceiptLedger::from_parts(records, digests).unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::HistoricalMutation { sequence: 0, .. }
    ));
}

#[test]
fn retained_head_digest_rejects_silent_chain_replacement() {
    let mut ledger = ValidationReceiptLedger::new();
    let first_digest = ledger
        .append(receipt(0, ValidationReceiptDigest::ZERO, "pass"))
        .unwrap();
    ledger.append(receipt(1, first_digest, "pass")).unwrap();
    let retained_head = ledger.head_digest();

    let mut replacement = ValidationReceiptLedger::new();
    let first_digest = replacement
        .append(receipt(0, ValidationReceiptDigest::ZERO, "fail"))
        .unwrap();
    replacement
        .append(receipt(1, first_digest, "fail"))
        .unwrap();
    let (records, digests) = replacement.into_parts();
    let rebuilt = ValidationReceiptLedger::from_parts(records, digests).unwrap();

    let err = rebuilt.verify_head_digest(retained_head).unwrap_err();

    assert!(matches!(
        err,
        ValidationReceiptLedgerError::HeadDigestMismatch { .. }
    ));
}
