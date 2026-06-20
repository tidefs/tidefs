// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Append-only integrity ledger for validation claim receipts.
//!
//! ## Relationship to claim-gate authority
//!
//! [`ValidationReceiptLedger`] proves that stored validation receipts were not
//! reordered, mutated, or silently replaced, but **it does not decide whether a
//! claim is validated**. Claim status remains authoritative in
//! `validation/claims.toml` and through `xtask validate-claim`.
//!
//! A valid receipt chain is integrity evidence only: the chain proves
//! append-order and mutation-resistance for the receipts it stores, but the
//! claim-gate pipeline (`validate-claim`, claim registry, and gating policy)
//! is the sole authority that maps receipts to validated/blocked/planned
//! claim outcomes. Receipt integrity without a matching claim-gate entry is
//! not product proof.
//!
//! Callers should retain the ledger head digest to detect wholesale
//! replacement and use [`verify_head_digest`](ValidationReceiptLedger::verify_head_digest)
//! after reloading from persistent storage.

use std::cmp::Ordering;
use std::fmt;

use tidefs_types_claim_ledger_core::{ValidationReceiptDigest, ValidationReceiptRecord, ValidationReceiptText};

use crate::ClaimEncoding;

/// Ordered, hash-linked validation receipt ledger for a single claim.
///
/// Each ledger is scoped to one `claim_id`. Every appended receipt must carry
/// the same `claim_id` or the append is rejected with
/// [`ValidationReceiptLedgerError::ClaimIdMismatch`].
///
/// The stream stores receipt records and their BLAKE3-256 record digests. It
/// proves append order and mutation resistance for receipt evidence only; it
/// does not decide whether a claim is validated. Callers that need to detect
/// wholesale replacement must retain and compare the ledger head digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationReceiptLedger {
    claim_id: ValidationReceiptText,
    records: Vec<ValidationReceiptRecord>,
    digests: Vec<ValidationReceiptDigest>,
}

impl ValidationReceiptLedger {
    /// Create an empty receipt ledger for a single claim.
    #[must_use]
    pub fn new(claim_id: ValidationReceiptText) -> Self {
        Self {
            claim_id,
            records: Vec::new(),
            digests: Vec::new(),
        }
    }

    /// Rebuild a receipt ledger from persisted identity, records, and stored
    /// digests.
    ///
    /// Every record must carry the given `claim_id`; a mismatched record
    /// produces [`ValidationReceiptLedgerError::ClaimIdMismatch`].
    pub fn from_parts(
        claim_id: ValidationReceiptText,
        records: Vec<ValidationReceiptRecord>,
        digests: Vec<ValidationReceiptDigest>,
    ) -> Result<Self, ValidationReceiptLedgerError> {
        Self::verify_parts(&claim_id, &records, &digests)?;
        Ok(Self { claim_id, records, digests })
    }

    /// Consume the ledger and return its parts for persistence.
    #[must_use]
    pub fn into_parts(self) -> (ValidationReceiptText, Vec<ValidationReceiptRecord>, Vec<ValidationReceiptDigest>) {
        (self.claim_id, self.records, self.digests)
    }

    /// Return the claim identity this ledger tracks.
    #[must_use]
    pub fn claim_id(&self) -> ValidationReceiptText {
        self.claim_id
    }

    /// Reference all stored receipt records in insertion order.
    #[must_use]
    pub fn records(&self) -> &[ValidationReceiptRecord] {
        &self.records
    }

    /// Reference all stored receipt digests in insertion order.
    #[must_use]
    pub fn digests(&self) -> &[ValidationReceiptDigest] {
        &self.digests
    }

    /// Deterministic insertion-order iterator over receipt records for
    /// audit and report generation.
    #[must_use]
    pub fn iter(&self) -> impl Iterator<Item = &ValidationReceiptRecord> {
        self.records.iter()
    }

    /// Number of receipts in the ledger.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True when no receipts have been appended.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Return the head digest, or [`ValidationReceiptDigest::ZERO`] when empty.
    #[must_use]
    pub fn head_digest(&self) -> ValidationReceiptDigest {
        self.digests
            .last()
            .copied()
            .unwrap_or(ValidationReceiptDigest::ZERO)
    }

    /// Append one receipt record after verifying the existing stored chain.
    ///
    /// Rejects duplicate sequence numbers, decreasing sequences, mismatched
    /// `claim_id`, and broken previous-digest linkage.
    pub fn append(
        &mut self,
        record: ValidationReceiptRecord,
    ) -> Result<ValidationReceiptDigest, ValidationReceiptLedgerError> {
        self.verify()?;
        self.check_claim_id(&record)?;
        let expected_sequence = self.records.len() as u64;
        validate_sequence(record.sequence, expected_sequence)?;

        let expected_previous = self.head_digest();
        if record.previous_receipt_digest != expected_previous {
            return Err(ValidationReceiptLedgerError::PreviousDigestMismatch {
                sequence: record.sequence,
                expected: expected_previous,
                actual: record.previous_receipt_digest,
            });
        }

        let digest = Self::record_digest(&record);
        self.records.push(record);
        self.digests.push(digest);
        Ok(digest)
    }

    /// Idempotent replay of a receipt record.
    ///
    /// Unlike [`append`](Self::append), this method silently accepts records
    /// that are already present at the correct sequence position (identical
    /// record equality). New records at the expected next sequence position
    /// are appended normally through the standard append path. Conflicting
    /// records at an already-occupied sequence position are rejected with
    /// [`ValidationReceiptLedgerError::ConflictingReplay`].
    ///
    /// This path exists so callers can re-feed a complete receipt set after
    /// a restart without tracking per-record already-seen state. Normal
    /// append must use [`append`](Self::append), which does not silently
    /// accept duplicates.
    pub fn replay(
        &mut self,
        record: ValidationReceiptRecord,
    ) -> Result<ValidationReceiptDigest, ValidationReceiptLedgerError> {
        self.verify()?;
        self.check_claim_id(&record)?;

        let expected_seq = self.records.len() as u64;
        match record.sequence.cmp(&expected_seq) {
            Ordering::Less => {
                // Already-seen sequence: require identical record.
                let idx = record.sequence as usize;
                let stored = self.records.get(idx).ok_or(
                    ValidationReceiptLedgerError::InternalInconsistency {
                        detail: "replay sequence index out of bounds",
                    },
                )?;
                if stored != &record {
                    return Err(ValidationReceiptLedgerError::ConflictingReplay {
                        sequence: record.sequence,
                    });
                }
                Ok(self.digests[idx])
            }
            Ordering::Equal => {
                // New record at the expected frontier: delegate to append.
                self.append(record)
            }
            Ordering::Greater => Err(ValidationReceiptLedgerError::ReorderedReceiptChain {
                expected_sequence: expected_seq,
                actual_sequence: record.sequence,
            }),
        }
    }

    /// Verify the in-memory chain against its stored digests.
    pub fn verify(&self) -> Result<(), ValidationReceiptLedgerError> {
        Self::verify_parts(&self.claim_id, &self.records, &self.digests)
    }

    /// Verify the chain and compare its current head against a retained anchor.
    pub fn verify_head_digest(
        &self,
        expected: ValidationReceiptDigest,
    ) -> Result<(), ValidationReceiptLedgerError> {
        self.verify()?;
        let actual = self.head_digest();
        if actual != expected {
            return Err(ValidationReceiptLedgerError::HeadDigestMismatch { expected, actual });
        }
        Ok(())
    }

    /// Compute the receipt digest for a single canonical receipt record.
    #[must_use]
    pub fn record_digest(record: &ValidationReceiptRecord) -> ValidationReceiptDigest {
        let hash = blake3::hash(&record.serialize());
        ValidationReceiptDigest::from_bytes(*hash.as_bytes())
    }

    fn check_claim_id(
        &self,
        record: &ValidationReceiptRecord,
    ) -> Result<(), ValidationReceiptLedgerError> {
        if record.claim_id != self.claim_id {
            return Err(ValidationReceiptLedgerError::ClaimIdMismatch {
                expected: self.claim_id,
                actual: record.claim_id,
            });
        }
        Ok(())
    }

    fn verify_parts(
        expected_claim_id: &ValidationReceiptText,
        records: &[ValidationReceiptRecord],
        digests: &[ValidationReceiptDigest],
    ) -> Result<(), ValidationReceiptLedgerError> {
        if records.len() != digests.len() {
            return Err(ValidationReceiptLedgerError::LengthMismatch {
                record_count: records.len(),
                digest_count: digests.len(),
            });
        }

        let mut expected_sequence = 0_u64;
        let mut previous_digest = ValidationReceiptDigest::ZERO;

        for (record, stored_digest) in records.iter().zip(digests.iter()) {
            if record.claim_id != *expected_claim_id {
                return Err(ValidationReceiptLedgerError::ClaimIdMismatch {
                    expected: *expected_claim_id,
                    actual: record.claim_id,
                });
            }
            validate_sequence(record.sequence, expected_sequence)?;
            if record.previous_receipt_digest != previous_digest {
                return Err(ValidationReceiptLedgerError::PreviousDigestMismatch {
                    sequence: record.sequence,
                    expected: previous_digest,
                    actual: record.previous_receipt_digest,
                });
            }

            let computed = Self::record_digest(record);
            if *stored_digest != computed {
                return Err(ValidationReceiptLedgerError::HistoricalMutation {
                    sequence: record.sequence,
                    stored: *stored_digest,
                    computed,
                });
            }

            previous_digest = computed;
            expected_sequence = expected_sequence.saturating_add(1);
        }

        Ok(())
    }
}

fn validate_sequence(actual: u64, expected: u64) -> Result<(), ValidationReceiptLedgerError> {
    if actual < expected {
        return Err(ValidationReceiptLedgerError::DuplicateSequenceNumber { sequence: actual });
    }
    if actual != expected {
        return Err(ValidationReceiptLedgerError::ReorderedReceiptChain {
            expected_sequence: expected,
            actual_sequence: actual,
        });
    }
    Ok(())
}

/// Validation receipt-chain verification errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationReceiptLedgerError {
    /// A record's `claim_id` does not match the ledger identity.
    ClaimIdMismatch {
        expected: ValidationReceiptText,
        actual: ValidationReceiptText,
    },
    /// Record and digest vectors have different lengths.
    LengthMismatch {
        record_count: usize,
        digest_count: usize,
    },
    /// A sequence number has already been used in this chain.
    DuplicateSequenceNumber {
        sequence: u64,
    },
    /// A receipt's sequence does not follow the previous record's sequence.
    ReorderedReceiptChain {
        expected_sequence: u64,
        actual_sequence: u64,
    },
    /// A replay at an occupied sequence position found a different record.
    ConflictingReplay {
        sequence: u64,
    },
    /// A receipt's `previous_receipt_digest` does not match the chain linkage.
    PreviousDigestMismatch {
        sequence: u64,
        expected: ValidationReceiptDigest,
        actual: ValidationReceiptDigest,
    },
    /// The ledger head digest does not match a retained anchor.
    HeadDigestMismatch {
        expected: ValidationReceiptDigest,
        actual: ValidationReceiptDigest,
    },
    /// A stored digest no longer matches its record (tampering or corruption).
    HistoricalMutation {
        sequence: u64,
        stored: ValidationReceiptDigest,
        computed: ValidationReceiptDigest,
    },
    /// Internal invariant violation (records/digests out of sync).
    InternalInconsistency {
        detail: &'static str,
    },
}

impl fmt::Display for ValidationReceiptLedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaimIdMismatch { expected, actual } => write!(
                f,
                "validation receipt claim_id mismatch: expected \"{}\", got \"{}\"",
                expected.as_str(),
                actual.as_str()
            ),
            Self::LengthMismatch {
                record_count,
                digest_count,
            } => write!(
                f,
                "validation receipt ledger length mismatch: {record_count} records, {digest_count} digests"
            ),
            Self::DuplicateSequenceNumber { sequence } => {
                write!(f, "duplicate validation receipt sequence number {sequence}")
            }
            Self::ReorderedReceiptChain {
                expected_sequence,
                actual_sequence,
            } => write!(
                f,
                "reordered validation receipt chain: expected sequence {expected_sequence}, got {actual_sequence}"
            ),
            Self::ConflictingReplay { sequence } => write!(
                f,
                "conflicting replay at sequence {sequence}: stored receipt differs from replay record"
            ),
            Self::PreviousDigestMismatch { sequence, .. } => write!(
                f,
                "validation receipt {sequence} does not link to the previous receipt digest"
            ),
            Self::HeadDigestMismatch { .. } => {
                f.write_str("validation receipt ledger head digest does not match the retained anchor")
            }
            Self::HistoricalMutation { sequence, .. } => {
                write!(f, "validation receipt {sequence} digest no longer matches its record")
            }
            Self::InternalInconsistency { detail } => {
                write!(f, "validation receipt ledger internal inconsistency: {detail}")
            }
        }
    }
}

impl std::error::Error for ValidationReceiptLedgerError {}
