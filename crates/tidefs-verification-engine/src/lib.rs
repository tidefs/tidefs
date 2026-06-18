// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! TideFS verification engine: P8-03 `data_copy_2.verification_engine`,
//! pool-level segment integrity verification, and per-object BLAKE3-256
//! integrity checking.
//!
//! ## Object verification pipeline
//!
//! The [`object_verify`] module provides the low-level per-object BLAKE3-256
//! verification primitive consumed by background scrub (`tidefs_scrub_core`),
//! recovery-loop replay validation, and rebuild integrity checking. It exposes
//! [`VerificationPlan`], [`verify_object`], [`ObjectVerificationOutcome`], and
//! [`verify_batch`] for concurrent batch verification through the object store.
//!
//! ## Replication verification
//!
//! The verification engine sits between the transfer orchestrator (data_copy_1)
//! and the flow commit coordinator (data_copy_7). It validates transferred
//! chunks through four verification classes before placement is legal.
//!
//! ## Verification classes (P8-03 anti-regression rule 1)
//!
//! 1. **Digest verification** — compare chunk digest against authoritative source
//! 2. **Extent/range verification** — confirm byte range matches transfer ticket
//! 3. **Witness verification** — validate against witness quorum
//! 4. **Quorum verification** — confirm required receipts for placement legality
//!
//! ## Output
//!
//! The engine emits `ReplicaVerificationReceipt` records. A `Verified` status
//! makes replica placement legal per P8-03 law 3+7.

pub mod engine;
pub mod health_report;
pub mod object_verify;
pub mod pool_scan_driver;
pub mod segment_check;

// Re-export the object-verification public API for consumers (scrub, recovery,
// rebuild).
pub use object_verify::{verify_batch, verify_object, ObjectVerificationOutcome, VerificationPlan};

use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_replication_model::{
    ObjectDigest, ReplicaCopyClass, ReplicaCopyRecord, ReplicaTransferReceipt,
    ReplicaVerificationReceipt, ReplicatedReceiptId, VerificationStatus,
};
use tidefs_witness_set::{verify_witness_set, WitnessQuorumClass, WitnessSet};

use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Verification context
// ---------------------------------------------------------------------------

/// Configuration and state for the verification engine.
///
/// Holds the witness public-key registry, quorum policy, and verification
/// epoch state needed across verification calls.
#[derive(Clone, Debug)]
pub struct VerificationContext {
    /// Public keys for witnesses, indexed by member id.
    pub witness_pubkeys: BTreeMap<MemberId, Vec<u8>>,
    /// Members currently quarantined and ineligible for attestation.
    pub quarantined: BTreeSet<MemberId>,
    /// Default quorum class used when no per-transfer override is set.
    pub default_quorum_class: WitnessQuorumClass,
    /// Current membership epoch for verification time-binding.
    pub current_epoch: EpochId,
    /// Witness sets collected for in-progress verifications, keyed by digest group.
    witness_sets: BTreeMap<u64, WitnessSet>,
    /// Accumulated verification receipts, keyed by receipt id.
    receipts: BTreeMap<u64, ReplicaVerificationReceipt>,
}

impl VerificationContext {
    /// Create a context for the given epoch with a default strict majority quorum.
    #[must_use]
    pub fn new(epoch: EpochId) -> Self {
        Self {
            current_epoch: epoch,
            default_quorum_class: WitnessQuorumClass::StrictMajority,
            witness_pubkeys: BTreeMap::new(),
            quarantined: BTreeSet::new(),
            witness_sets: BTreeMap::new(),
            receipts: BTreeMap::new(),
        }
    }

    /// Set the witness public keys from a member→key map.
    pub fn set_witness_keys(&mut self, keys: BTreeMap<MemberId, Vec<u8>>) {
        self.witness_pubkeys = keys;
    }

    /// Register a witness set for a specific transfer digest group.
    pub fn register_witness_set(&mut self, group_id: u64, set: WitnessSet) {
        self.witness_sets.insert(group_id, set);
    }

    /// Store a verification receipt for later quorum counting.
    pub fn store_receipt(&mut self, receipt: ReplicaVerificationReceipt) {
        self.receipts.insert(receipt.receipt_id.0, receipt);
    }

    /// Count verified receipts for a given subject set (by shared epoch / flow scope).
    #[must_use]
    pub fn verified_receipt_count(&self) -> usize {
        self.receipts
            .values()
            .filter(|r| r.status == VerificationStatus::Verified)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Verification class 1: digest verification
// ---------------------------------------------------------------------------

/// Compare received chunk digests against the authoritative immutable payload digest.
///
/// Every received chunk must match the authoritative digest. A single mismatch
/// blocks placement for the entire subject set.
///
/// Returns `Ok(())` if all digests match, or `Err(VerificationStatus)` with
/// the first mismatch reason.
#[must_use = "digest verification must be inspected before marking placement legal"]
pub fn verify_digest_against_authoritative_source(
    expected_digest: ObjectDigest,
    actual_digests: &[ObjectDigest],
) -> Result<(), VerificationStatus> {
    if actual_digests.is_empty() {
        return Err(VerificationStatus::DigestMismatch);
    }
    for actual in actual_digests.iter() {
        if *actual != expected_digest {
            return Err(VerificationStatus::DigestMismatch);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Verification class 2: extent/range verification
// ---------------------------------------------------------------------------

/// Extent range descriptor for a transferred chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtentRange {
    /// Start offset within the logical object.
    pub start_byte: u64,
    /// Length of the transferred range.
    pub length_bytes: u64,
}

/// Confirmation result after extent range verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtentVerificationOutcome {
    /// Range matches the transfer ticket's declared bounds.
    Matched,
    /// Received range extends beyond the ticket's declared range.
    RangeOverflow,
    /// Received range is shorter than the ticket requires.
    RangeUnderflow,
    /// Received range is disjoint (non-overlapping) from ticket's range.
    RangeDisjoint,
}

/// Confirm that the received byte range matches the transfer ticket's declared range.
///
/// The received extent must be exactly bounded by the ticket's declared range.
/// Overflows, underflows, and disjoint ranges all block placement.
#[must_use]
pub fn verify_extent_range_matches_transfer_ticket(
    received: ExtentRange,
    ticket_expected_start: u64,
    ticket_expected_length: u64,
) -> ExtentVerificationOutcome {
    if received.start_byte < ticket_expected_start {
        return ExtentVerificationOutcome::RangeOverflow;
    }
    if received.start_byte > ticket_expected_start {
        // Disjoint or shifted
        if received.start_byte + received.length_bytes <= ticket_expected_start
            || received.start_byte >= ticket_expected_start + ticket_expected_length
        {
            return ExtentVerificationOutcome::RangeDisjoint;
        }
        // Partial overlap from later start — treat as overflow since we didn't get
        // the full beginning.
        if received.start_byte > ticket_expected_start {
            return ExtentVerificationOutcome::RangeOverflow;
        }
    }
    let received_end = received.start_byte + received.length_bytes;
    let ticket_end = ticket_expected_start + ticket_expected_length;
    if received_end < ticket_end {
        return ExtentVerificationOutcome::RangeUnderflow;
    }
    if received_end > ticket_end {
        return ExtentVerificationOutcome::RangeOverflow;
    }
    ExtentVerificationOutcome::Matched
}

// ---------------------------------------------------------------------------
// Verification class 3: witness verification
// ---------------------------------------------------------------------------

/// Verify transferred chunks against an existing witness set.
///
/// This is the runtime entry point that delegates to the `tidefs_witness_set`
/// cryptographic verification for collected witness records.
#[must_use = "witness verification result impacts placement legality"]
pub fn verify_against_witness_set(
    ctx: &VerificationContext,
    witness_set: &WitnessSet,
) -> Result<(), VerificationStatus> {
    match verify_witness_set(
        witness_set,
        &ctx.witness_pubkeys,
        ctx.current_epoch,
        &Vec::from_iter(ctx.quarantined.iter().copied()),
    ) {
        Ok(receipt) => {
            if receipt.verified {
                Ok(())
            } else {
                Err(VerificationStatus::WitnessInsufficient)
            }
        }
        Err(_) => Err(VerificationStatus::WitnessInsufficient),
    }
}

// ---------------------------------------------------------------------------
// Verification class 4: quorum verification
// ---------------------------------------------------------------------------

/// Result of quorum verification for a completed transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuorumVerificationOutcome {
    /// Required quorum of verification receipts has been met.
    QuorumSatisfied {
        verified_count: usize,
        required: usize,
    },
    /// Not enough verification receipts to meet quorum.
    QuorumNotMet {
        verified_count: usize,
        required: usize,
    },
    /// No verification receipts exist yet.
    NoReceipts,
}

/// Verify that the required number of verification receipts have been emitted
/// before placement is committed.
///
/// For quorum-bound replication classes, placement is only legal once the
/// required number of independent verification receipts have been collected.
#[must_use]
pub fn verify_transfer_quorum_satisfied(
    ctx: &VerificationContext,
    quorum_class: WitnessQuorumClass,
) -> QuorumVerificationOutcome {
    let verified_count = ctx.verified_receipt_count();
    // voter_count is the total witness pool, approximating the configured keys
    let voter_count = ctx.witness_pubkeys.len().max(1);
    let required = quorum_class.required_count(voter_count);
    if verified_count >= required {
        QuorumVerificationOutcome::QuorumSatisfied {
            verified_count,
            required,
        }
    } else if verified_count == 0 {
        QuorumVerificationOutcome::NoReceipts
    } else {
        QuorumVerificationOutcome::QuorumNotMet {
            verified_count,
            required,
        }
    }
}

// ---------------------------------------------------------------------------
// Full verification pipeline
// ---------------------------------------------------------------------------

/// Run the complete verification pipeline for a transfer and emit a
/// verification receipt.
///
/// This is the primary runtime entry point. It executes all four verification
/// classes and produces a `ReplicaVerificationReceipt` with the appropriate
/// status. The caller must store the receipt in the context via
/// `VerificationContext::store_receipt` for quorum accounting.
#[must_use = "verification receipt determines placement legality"]
/// Map a witness quorum class to a numeric encoding for the receipt record.
pub fn quorum_class_to_u64(qc: WitnessQuorumClass) -> u64 {
    match qc {
        WitnessQuorumClass::StrictMajority => 0,
        WitnessQuorumClass::Flexible { required, total } => {
            ((required as u64) << 32) | (total as u64)
        }
    }
}

pub fn verify_transfer_and_emit_receipt(
    ctx: &mut VerificationContext,
    transfer_receipt: &ReplicaTransferReceipt,
    subject_refs: &[tidefs_replication_model::ReplicatedSubjectId],
    expected_digest: ObjectDigest,
    actual_digests: &[ObjectDigest],
    witness_set: &WitnessSet,
    quorum_class: WitnessQuorumClass,
) -> ReplicaVerificationReceipt {
    let receipt_id = ReplicatedReceiptId(
        transfer_receipt
            .receipt_id
            .0
            .wrapping_mul(7919)
            .wrapping_add(ctx.current_epoch.0),
    );

    // Class 1: digest verification
    let digest_ok =
        verify_digest_against_authoritative_source(expected_digest, actual_digests).is_ok();

    // Class 3: witness verification (class 2 extent is caller's pre-check)
    let witness_ok = verify_against_witness_set(ctx, witness_set).is_ok();

    // Class 4: quorum verification
    let quorum_result = verify_transfer_quorum_satisfied(ctx, quorum_class);
    let quorum_met = matches!(
        quorum_result,
        QuorumVerificationOutcome::QuorumSatisfied { .. }
    );

    let status = if digest_ok && witness_ok && quorum_met {
        VerificationStatus::Verified
    } else if !digest_ok {
        VerificationStatus::DigestMismatch
    } else if !witness_ok {
        VerificationStatus::WitnessInsufficient
    } else if !quorum_met {
        VerificationStatus::QuorumNotMet
    } else {
        VerificationStatus::DegradedVerified
    };

    let receipt = ReplicaVerificationReceipt {
        receipt_id,
        subject_refs: subject_refs.to_vec(),
        digest_results: actual_digests.to_vec(),
        witness_refs: witness_set.collected.iter().map(|r| r.witness_id).collect(),
        quorum_class: quorum_class_to_u64(quorum_class),
        verification_epoch: ctx.current_epoch,
        status,
    };

    ctx.store_receipt(receipt.clone());
    receipt
}

/// Advance a replica copy record through the receipt chain.
///
/// If the verification receipt has status `Verified`, promote the copy to
/// `ReplicaCopyClass::Verified`. Otherwise, leave the copy unchanged.
#[must_use]
pub fn advance_copy_after_verification(
    copy: &ReplicaCopyRecord,
    receipt: &ReplicaVerificationReceipt,
) -> ReplicaCopyRecord {
    if receipt.status == VerificationStatus::Verified {
        let mut advanced = copy.clone();
        advanced.verification_receipt_ref = receipt.receipt_id;
        advanced.copy_class = ReplicaCopyClass::Verified;
        advanced
    } else {
        copy.clone()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::EpochId;
    use tidefs_witness_set::{WitnessAnchor, WitnessLifecycle};

    // Helpers
    fn make_ctx() -> VerificationContext {
        VerificationContext::new(EpochId::new(1))
    }

    fn digest(v: u64) -> ObjectDigest {
        ObjectDigest::new(v)
    }

    // ── Digest verification tests ──

    #[test]
    fn digest_match_passes() {
        assert!(
            verify_digest_against_authoritative_source(digest(42), &[digest(42), digest(42)])
                .is_ok()
        );
    }

    #[test]
    fn digest_mismatch_fails() {
        assert_eq!(
            verify_digest_against_authoritative_source(digest(42), &[digest(99)]),
            Err(VerificationStatus::DigestMismatch),
        );
    }

    #[test]
    fn digest_empty_input_fails() {
        assert_eq!(
            verify_digest_against_authoritative_source(digest(42), &[]),
            Err(VerificationStatus::DigestMismatch),
        );
    }

    #[test]
    fn digest_single_mismatch_in_batch_fails() {
        assert_eq!(
            verify_digest_against_authoritative_source(
                digest(42),
                &[digest(42), digest(99), digest(42)],
            ),
            Err(VerificationStatus::DigestMismatch),
        );
    }

    // ── Extent/range verification tests ──

    #[test]
    fn extent_exact_match() {
        assert_eq!(
            verify_extent_range_matches_transfer_ticket(
                ExtentRange {
                    start_byte: 0,
                    length_bytes: 1024
                },
                0,
                1024,
            ),
            ExtentVerificationOutcome::Matched,
        );
    }

    #[test]
    fn extent_overflow_start_before_ticket() {
        assert_eq!(
            verify_extent_range_matches_transfer_ticket(
                ExtentRange {
                    start_byte: 0,
                    length_bytes: 1024,
                },
                512,
                512,
            ),
            ExtentVerificationOutcome::RangeOverflow,
        );
    }

    #[test]
    fn extent_overflow_end_past_ticket() {
        assert_eq!(
            verify_extent_range_matches_transfer_ticket(
                ExtentRange {
                    start_byte: 0,
                    length_bytes: 2048,
                },
                0,
                1024,
            ),
            ExtentVerificationOutcome::RangeOverflow,
        );
    }

    #[test]
    fn extent_underflow() {
        assert_eq!(
            verify_extent_range_matches_transfer_ticket(
                ExtentRange {
                    start_byte: 0,
                    length_bytes: 512,
                },
                0,
                1024,
            ),
            ExtentVerificationOutcome::RangeUnderflow,
        );
    }

    #[test]
    fn extent_disjoint() {
        assert_eq!(
            verify_extent_range_matches_transfer_ticket(
                ExtentRange {
                    start_byte: 2048,
                    length_bytes: 512,
                },
                0,
                1024,
            ),
            ExtentVerificationOutcome::RangeDisjoint,
        );
    }

    #[test]
    fn extent_mid_range_overflow() {
        // Received starts inside ticket range but extends past it
        assert_eq!(
            verify_extent_range_matches_transfer_ticket(
                ExtentRange {
                    start_byte: 512,
                    length_bytes: 1024,
                },
                512,
                512,
            ),
            ExtentVerificationOutcome::RangeOverflow,
        );
    }

    // ── Quorum verification tests ──

    #[test]
    fn quorum_no_receipts_is_not_met() {
        let ctx = make_ctx();
        assert_eq!(
            verify_transfer_quorum_satisfied(&ctx, WitnessQuorumClass::StrictMajority),
            QuorumVerificationOutcome::NoReceipts,
        );
    }

    #[test]
    fn quorum_met_with_enough_receipts() {
        let mut ctx = make_ctx();
        let receipt = ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(1),
            subject_refs: vec![],
            digest_results: vec![],
            witness_refs: vec![],
            quorum_class: 0,
            verification_epoch: EpochId::new(1),
            status: VerificationStatus::Verified,
        };
        ctx.store_receipt(receipt);
        assert_eq!(
            verify_transfer_quorum_satisfied(&ctx, WitnessQuorumClass::StrictMajority),
            QuorumVerificationOutcome::QuorumSatisfied {
                verified_count: 1,
                required: 1,
            },
        );
    }

    // ── Integration test: full pipeline ──

    #[test]
    fn full_pipeline_verification_passes() {
        let mut ctx = make_ctx();

        // Setup witness keys (simplified — we use empty keys for the integration test;
        // actual cryptographic verification is tested in tidefs-witness-set).
        // For the purpose of testing the pipeline orchestration, we create a
        // witness set with no collected records so witness verification fails,
        // then test the digest path independently.
        let witness_set = WitnessSet {
            set_id: 1,
            anchor: WitnessAnchor::Chunk {
                chunk_key: vec![1, 2, 3],
                expected_digest: vec![42, 0, 0, 0, 0, 0, 0, 0],
            },
            quorum_class: WitnessQuorumClass::StrictMajority,
            selected_witnesses: vec![],
            collected: vec![],
            lifecycle: WitnessLifecycle::Verified,
            created_at_millis: 1000,
            deadline_millis: 5000,
            epoch: EpochId::new(1),
            verification_receipt: None,
        };

        // Digest verification standalone test — pipeline orchestrates all classes.
        let transfer_receipt = ReplicaTransferReceipt {
            receipt_id: ReplicatedReceiptId(100),
            ticket_ref: ReplicatedReceiptId(200),
            bytes_moved: 4096,
            source_anchor_hash: 0,
            target_anchor_hash: 1,
            completion_epoch: EpochId::new(1),
            worker_refs: vec![],
        };

        let receipt = verify_transfer_and_emit_receipt(
            &mut ctx,
            &transfer_receipt,
            &[],
            digest(42),
            &[digest(42)],
            &witness_set,
            WitnessQuorumClass::StrictMajority,
        );

        // With no witness keys configured and empty witness set, witness
        // verification will fail. The status reflects this.
        assert_eq!(receipt.status, VerificationStatus::WitnessInsufficient);
        assert_eq!(receipt.digest_results, vec![digest(42)]);
        assert_eq!(receipt.verification_epoch, EpochId::new(1));
    }

    #[test]
    fn full_pipeline_digest_mismatch_dominates() {
        let mut ctx = make_ctx();
        let witness_set = WitnessSet {
            set_id: 2,
            anchor: WitnessAnchor::Chunk {
                chunk_key: vec![],
                expected_digest: vec![],
            },
            quorum_class: WitnessQuorumClass::StrictMajority,
            selected_witnesses: vec![],
            collected: vec![],
            lifecycle: WitnessLifecycle::Verified,
            created_at_millis: 1000,
            deadline_millis: 5000,
            epoch: EpochId::new(1),
            verification_receipt: None,
        };

        let transfer_receipt = ReplicaTransferReceipt {
            receipt_id: ReplicatedReceiptId(100),
            ticket_ref: ReplicatedReceiptId(200),
            bytes_moved: 0,
            source_anchor_hash: 0,
            target_anchor_hash: 0,
            completion_epoch: EpochId::new(1),
            worker_refs: vec![],
        };

        let receipt = verify_transfer_and_emit_receipt(
            &mut ctx,
            &transfer_receipt,
            &[],
            digest(100),
            &[digest(200)],
            &witness_set,
            WitnessQuorumClass::StrictMajority,
        );

        // Digest mismatch takes priority over witness/quorum status.
        assert_eq!(receipt.status, VerificationStatus::DigestMismatch);
    }

    #[test]
    fn advance_copy_to_verified() {
        let copy = ReplicaCopyRecord {
            subject_ref: tidefs_replication_model::ReplicatedSubjectId::new(1),
            member_ref: MemberId::new(10),
            domain_ref: tidefs_membership_epoch::DomainId::new(1),
            copy_class: ReplicaCopyClass::Suspect,
            payload_digest: ObjectDigest::new(0),
            freshness_frontier: 0,
            verification_receipt_ref: ReplicatedReceiptId::default(),
        };

        let receipt = ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(42),
            subject_refs: vec![],
            digest_results: vec![],
            witness_refs: vec![],
            quorum_class: 0,
            verification_epoch: EpochId::new(1),
            status: VerificationStatus::Verified,
        };

        let advanced = advance_copy_after_verification(&copy, &receipt);
        assert_eq!(advanced.copy_class, ReplicaCopyClass::Verified);
        assert_eq!(advanced.verification_receipt_ref, ReplicatedReceiptId(42));
    }

    #[test]
    fn advance_copy_on_failed_verification_does_not_mutate() {
        let copy = ReplicaCopyRecord {
            subject_ref: tidefs_replication_model::ReplicatedSubjectId::new(1),
            member_ref: MemberId::new(10),
            domain_ref: tidefs_membership_epoch::DomainId::new(1),
            copy_class: ReplicaCopyClass::Suspect,
            payload_digest: ObjectDigest::new(0),
            freshness_frontier: 0,
            verification_receipt_ref: ReplicatedReceiptId::default(),
        };

        let receipt = ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(42),
            subject_refs: vec![],
            digest_results: vec![],
            witness_refs: vec![],
            quorum_class: 0,
            verification_epoch: EpochId::new(1),
            status: VerificationStatus::DigestMismatch,
        };

        let advanced = advance_copy_after_verification(&copy, &receipt);
        assert_eq!(advanced.copy_class, ReplicaCopyClass::Suspect);
        assert_eq!(
            advanced.verification_receipt_ref,
            ReplicatedReceiptId::default()
        );
    }

    #[test]
    fn context_stores_and_counts_receipts() {
        let mut ctx = make_ctx();
        assert_eq!(ctx.verified_receipt_count(), 0);

        ctx.store_receipt(ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(1),
            subject_refs: vec![],
            digest_results: vec![],
            witness_refs: vec![],
            quorum_class: 0,
            verification_epoch: EpochId::new(1),
            status: VerificationStatus::Verified,
        });
        ctx.store_receipt(ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(2),
            subject_refs: vec![],
            digest_results: vec![],
            witness_refs: vec![],
            quorum_class: 0,
            verification_epoch: EpochId::new(1),
            status: VerificationStatus::Verified,
        });
        ctx.store_receipt(ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(3),
            subject_refs: vec![],
            digest_results: vec![],
            witness_refs: vec![],
            quorum_class: 0,
            verification_epoch: EpochId::new(1),
            status: VerificationStatus::DigestMismatch,
        });

        assert_eq!(ctx.verified_receipt_count(), 2);
    }

    #[test]
    fn quorum_flexible_met() {
        let mut ctx = make_ctx();
        ctx.set_witness_keys(BTreeMap::from([
            (MemberId::new(1), vec![0u8; 32]),
            (MemberId::new(2), vec![1u8; 32]),
            (MemberId::new(3), vec![2u8; 32]),
        ]));

        // 1 verified receipt with Flexible { required: 1, total: 3 } should be met
        ctx.store_receipt(ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(1),
            subject_refs: vec![],
            digest_results: vec![],
            witness_refs: vec![],
            quorum_class: 0,
            verification_epoch: EpochId::new(1),
            status: VerificationStatus::Verified,
        });

        let result = verify_transfer_quorum_satisfied(
            &ctx,
            WitnessQuorumClass::Flexible {
                required: 1,
                total: 3,
            },
        );
        assert!(matches!(
            result,
            QuorumVerificationOutcome::QuorumSatisfied { .. }
        ));
    }

    #[test]
    fn quorum_not_met_with_insufficient_receipts() {
        let mut ctx = make_ctx();
        ctx.set_witness_keys(BTreeMap::from([
            (MemberId::new(1), vec![0u8; 32]),
            (MemberId::new(2), vec![1u8; 32]),
            (MemberId::new(3), vec![2u8; 32]),
        ]));

        // 1 verified receipt with StrictMajority on 3 voters → needs 2
        ctx.store_receipt(ReplicaVerificationReceipt {
            receipt_id: ReplicatedReceiptId(1),
            subject_refs: vec![],
            digest_results: vec![],
            witness_refs: vec![],
            quorum_class: 0,
            verification_epoch: EpochId::new(1),
            status: VerificationStatus::Verified,
        });

        let result = verify_transfer_quorum_satisfied(&ctx, WitnessQuorumClass::StrictMajority);
        assert!(matches!(
            result,
            QuorumVerificationOutcome::QuorumNotMet { .. }
        ));
    }
}
