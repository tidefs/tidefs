//! Append-only integrity ledger for validation claim receipts.

use std::fmt;

use tidefs_types_claim_ledger_core::{ValidationReceiptDigest, ValidationReceiptRecord};

use crate::ClaimEncoding;

/// Ordered, hash-linked validation receipt stream.
///
/// The stream stores receipt records and their BLAKE3-256 record digests. It
/// proves append order and mutation resistance for receipt evidence only; it
/// does not decide whether a claim is validated.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidationReceiptLedger {
    records: Vec<ValidationReceiptRecord>,
    digests: Vec<ValidationReceiptDigest>,
}

impl ValidationReceiptLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild a receipt ledger from persisted records and stored digests.
    pub fn from_parts(
        records: Vec<ValidationReceiptRecord>,
        digests: Vec<ValidationReceiptDigest>,
    ) -> Result<Self, ValidationReceiptLedgerError> {
        Self::verify_parts(&records, &digests)?;
        Ok(Self { records, digests })
    }

    #[must_use]
    pub fn into_parts(self) -> (Vec<ValidationReceiptRecord>, Vec<ValidationReceiptDigest>) {
        (self.records, self.digests)
    }

    #[must_use]
    pub fn records(&self) -> &[ValidationReceiptRecord] {
        &self.records
    }

    #[must_use]
    pub fn digests(&self) -> &[ValidationReceiptDigest] {
        &self.digests
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[must_use]
    pub fn head_digest(&self) -> ValidationReceiptDigest {
        self.digests
            .last()
            .copied()
            .unwrap_or(ValidationReceiptDigest::ZERO)
    }

    /// Append one receipt record after verifying the existing stored chain.
    pub fn append(
        &mut self,
        record: ValidationReceiptRecord,
    ) -> Result<ValidationReceiptDigest, ValidationReceiptLedgerError> {
        self.verify()?;
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

    /// Verify the in-memory chain against its stored digests.
    pub fn verify(&self) -> Result<(), ValidationReceiptLedgerError> {
        Self::verify_parts(&self.records, &self.digests)
    }

    /// Compute the receipt digest for a single canonical receipt record.
    #[must_use]
    pub fn record_digest(record: &ValidationReceiptRecord) -> ValidationReceiptDigest {
        let hash = blake3::hash(&record.serialize());
        ValidationReceiptDigest::from_bytes(*hash.as_bytes())
    }

    fn verify_parts(
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
    LengthMismatch {
        record_count: usize,
        digest_count: usize,
    },
    DuplicateSequenceNumber {
        sequence: u64,
    },
    ReorderedReceiptChain {
        expected_sequence: u64,
        actual_sequence: u64,
    },
    PreviousDigestMismatch {
        sequence: u64,
        expected: ValidationReceiptDigest,
        actual: ValidationReceiptDigest,
    },
    HistoricalMutation {
        sequence: u64,
        stored: ValidationReceiptDigest,
        computed: ValidationReceiptDigest,
    },
}

impl fmt::Display for ValidationReceiptLedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            Self::PreviousDigestMismatch { sequence, .. } => write!(
                f,
                "validation receipt {sequence} does not link to the previous receipt digest"
            ),
            Self::HistoricalMutation { sequence, .. } => {
                write!(f, "validation receipt {sequence} digest no longer matches its record")
            }
        }
    }
}

impl std::error::Error for ValidationReceiptLedgerError {}
