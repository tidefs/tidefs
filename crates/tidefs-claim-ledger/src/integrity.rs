// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Claim serialization and BLAKE3-256 integrity proofs.
//!
//! Every claim persisted by the local-filesystem write-dispatch path is
//! wrapped in a [`ClaimIntegrity`] envelope so silent corruption after
//! SIGKILL is detectable on read-back during crash recovery.
//!
//! ## Binary format
//!
//! The canonical format is compact and deterministic: every variable-length
//! field is length-prefixed (u32 LE), every integer is little-endian, and
//! every optional field uses a 1-byte presence flag. The format is designed
//! so that a single-byte flip in the payload produces a different BLAKE3
//! hash, which [`ClaimIntegrity::verify`] catches.

use std::fmt;

use tidefs_types_claim_ledger_core::StorageAuthorityToken;
use tidefs_types_claim_ledger_core::{
    BudgetDomainId, ClaimEntry, ClaimId, ClaimReason, ObligationLedger, ReserveEntry, ReserveId,
    ValidationArtifactDigest, ValidationReceiptDigest, ValidationReceiptProducer,
    ValidationReceiptRecord, ValidationReceiptText, WitnessReceipt,
};
use tidefs_types_vfs_core::InodeId;

use crate::{ClaimClass, ClaimEntryRecord, ClaimLedger, ClaimantRef, LeaseDeadlineRecord};

// ── Encoding trait ────────────────────────────────────────────────────────

/// Compact binary encoding for claim types.
pub trait ClaimEncoding: Sized {
    /// Serialize `self` into a compact deterministic byte vector.
    fn serialize(&self) -> Vec<u8>;

    /// Deserialize from bytes previously produced by [`serialize`](ClaimEncoding::serialize).
    fn deserialize(buf: &[u8]) -> Result<Self, EncodingError>;
}

// ── Encoding error ────────────────────────────────────────────────────────

/// Errors produced during claim serialization or deserialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodingError {
    /// Not enough bytes remaining in the buffer.
    UnexpectedEof { field: &'static str },
    /// A discriminant byte fell outside the valid range.
    InvalidDiscriminant { field: &'static str, value: u8 },
    /// A declared length exceeds the remaining buffer.
    InvalidLength {
        field: &'static str,
        declared: usize,
        remaining: usize,
    },
    /// A value failed higher-level validation (e.g. non-UTF-8 string).
    InvalidValue { field: &'static str, detail: String },
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { field } => write!(f, "unexpected EOF reading {field}"),
            Self::InvalidDiscriminant { field, value } => {
                write!(f, "invalid discriminant {value} for {field}")
            }
            Self::InvalidLength {
                field,
                declared,
                remaining,
            } => {
                write!(
                    f,
                    "invalid length for {field}: declared {declared}, remaining {remaining}"
                )
            }
            Self::InvalidValue { field, detail } => {
                write!(f, "invalid value for {field}: {detail}")
            }
        }
    }
}

impl std::error::Error for EncodingError {}

// ── Integrity wrapper ─────────────────────────────────────────────────────

/// A serialized claim payload with an embedded BLAKE3-256 integrity proof.
///
/// The [`hash`](ClaimIntegrity::hash) covers the entire [`payload`](ClaimIntegrity::payload).
/// Call [`verify`](ClaimIntegrity::verify) before deserializing to detect
/// corruption from an unclean shutdown or bit rot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimIntegrity {
    /// BLAKE3-256 hash of `payload`.
    pub hash: [u8; 32],
    /// The serialized claim payload (binary format).
    pub payload: Vec<u8>,
}

impl ClaimIntegrity {
    /// Create an integrity envelope for an already-serialized payload.
    pub fn seal(payload: Vec<u8>) -> Self {
        let hash = blake3::hash(&payload);
        Self {
            hash: hash.into(),
            payload,
        }
    }

    /// Serialize a claim and seal it in one step.
    pub fn seal_claim<C: ClaimEncoding>(claim: &C) -> Self {
        Self::seal(claim.serialize())
    }

    /// Check that the payload still hashes to the stored hash.
    ///
    /// Returns `Ok(())` if the payload is intact, or
    /// [`IntegrityError::HashMismatch`] if it has been corrupted.
    pub fn verify(&self) -> Result<(), IntegrityError> {
        let computed = blake3::hash(&self.payload);
        if computed.as_bytes() == &self.hash {
            Ok(())
        } else {
            Err(IntegrityError::HashMismatch {
                expected: self.hash,
                computed: *computed.as_bytes(),
            })
        }
    }

    /// Verify integrity and deserialize the payload in one step.
    pub fn verify_and_deserialize<C: ClaimEncoding>(&self) -> Result<C, IntegrityError> {
        self.verify()?;
        C::deserialize(&self.payload).map_err(IntegrityError::Encoding)
    }
}

// ── Integrity error ───────────────────────────────────────────────────────

/// Errors from integrity verification or payload deserialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegrityError {
    /// The BLAKE3 hash of the payload does not match the stored hash.
    HashMismatch {
        expected: [u8; 32],
        computed: [u8; 32],
    },
    /// Payload deserialization failed (after integrity check passed).
    Encoding(EncodingError),
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HashMismatch { expected, computed } => {
                write!(
                    f,
                    "integrity hash mismatch: stored={expected:02x?}, computed={computed:02x?}"
                )
            }
            Self::Encoding(e) => write!(f, "encoding error: {e}"),
        }
    }
}

impl std::error::Error for IntegrityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(e) => Some(e),
            _ => None,
        }
    }
}

// ── Primitive read/write helpers ──────────────────────────────────────────

fn read_u64(buf: &[u8], pos: &mut usize, field: &'static str) -> Result<u64, EncodingError> {
    if *pos + 8 > buf.len() {
        return Err(EncodingError::UnexpectedEof { field });
    }
    let bytes: [u8; 8] = buf[*pos..*pos + 8].try_into().unwrap();
    *pos += 8;
    Ok(u64::from_le_bytes(bytes))
}

fn write_u64(v: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn read_u32(buf: &[u8], pos: &mut usize, field: &'static str) -> Result<u32, EncodingError> {
    if *pos + 4 > buf.len() {
        return Err(EncodingError::UnexpectedEof { field });
    }
    let bytes: [u8; 4] = buf[*pos..*pos + 4].try_into().unwrap();
    *pos += 4;
    Ok(u32::from_le_bytes(bytes))
}

fn write_u32(v: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn read_u8(buf: &[u8], pos: &mut usize, field: &'static str) -> Result<u8, EncodingError> {
    if *pos >= buf.len() {
        return Err(EncodingError::UnexpectedEof { field });
    }
    let v = buf[*pos];
    *pos += 1;
    Ok(v)
}

fn write_u8(v: u8, out: &mut Vec<u8>) {
    out.push(v);
}

fn read_bytes(buf: &[u8], pos: &mut usize, field: &'static str) -> Result<Vec<u8>, EncodingError> {
    let len = read_u32(buf, pos, field)? as usize;
    if *pos + len > buf.len() {
        return Err(EncodingError::InvalidLength {
            field,
            declared: len,
            remaining: buf.len() - *pos,
        });
    }
    let slice = buf[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(slice)
}

fn write_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    write_u32(bytes.len() as u32, out);
    out.extend_from_slice(bytes);
}

fn read_string(buf: &[u8], pos: &mut usize, field: &'static str) -> Result<String, EncodingError> {
    let bytes = read_bytes(buf, pos, field)?;
    String::from_utf8(bytes).map_err(|_| EncodingError::InvalidValue {
        field,
        detail: "non-UTF-8 bytes in string field".into(),
    })
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    write_bytes(s.as_bytes(), out);
}

fn read_optional_u64(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<Option<u64>, EncodingError> {
    match read_u8(buf, pos, field)? {
        0 => Ok(None),
        1 => Ok(Some(read_u64(buf, pos, field)?)),
        v => Err(EncodingError::InvalidValue {
            field,
            detail: format!("optional flag must be 0 or 1, got {v}"),
        }),
    }
}

fn write_optional_u64(opt: Option<u64>, out: &mut Vec<u8>) {
    match opt {
        None => write_u8(0, out),
        Some(v) => {
            write_u8(1, out);
            write_u64(v, out);
        }
    }
}

// ── Field-level serialization helpers ─────────────────────────────────────

/// Serialize a ClaimId as its raw 16 bytes.
fn encode_claim_id(id: ClaimId, out: &mut Vec<u8>) {
    out.extend_from_slice(id.as_bytes());
}

/// Deserialize a ClaimId from 16 raw bytes.
fn decode_claim_id(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<ClaimId, EncodingError> {
    if *pos + 16 > buf.len() {
        return Err(EncodingError::UnexpectedEof { field });
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&buf[*pos..*pos + 16]);
    *pos += 16;
    // ClaimId([u8; 16]) has a public field, so direct construction works.
    Ok(ClaimId::from_bytes(bytes))
}

/// Serialize a BudgetDomainId as 1-byte length prefix + bytes.
fn encode_budget_domain_id(id: &BudgetDomainId, out: &mut Vec<u8>) {
    let s = id.as_str();
    write_u8(s.len() as u8, out);
    out.extend_from_slice(s.as_bytes());
}

/// Deserialize a BudgetDomainId from length-prefixed bytes.
fn decode_budget_domain_id(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<BudgetDomainId, EncodingError> {
    let len = read_u8(buf, pos, field)? as usize;
    if len > BudgetDomainId::MAX_LEN {
        return Err(EncodingError::InvalidLength {
            field,
            declared: len,
            remaining: BudgetDomainId::MAX_LEN,
        });
    }
    if *pos + len > buf.len() {
        return Err(EncodingError::UnexpectedEof { field });
    }
    let slice = &buf[*pos..*pos + len];
    let s = std::str::from_utf8(slice).map_err(|_| EncodingError::InvalidValue {
        field,
        detail: "BudgetDomainId bytes are not valid UTF-8".into(),
    })?;
    *pos += len;
    Ok(BudgetDomainId::from_str(s))
}

/// Serialize a StorageAuthorityToken as its raw 16 bytes.
fn encode_receipt_id(id: StorageAuthorityToken, out: &mut Vec<u8>) {
    // StorageAuthorityToken(pub [u8; 16])
    out.extend_from_slice(&id.0);
}

/// Deserialize a StorageAuthorityToken from 16 raw bytes.
fn decode_receipt_id(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<StorageAuthorityToken, EncodingError> {
    if *pos + 16 > buf.len() {
        return Err(EncodingError::UnexpectedEof { field });
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&buf[*pos..*pos + 16]);
    *pos += 16;
    Ok(StorageAuthorityToken(bytes))
}

fn encode_validation_receipt_text(text: &ValidationReceiptText, out: &mut Vec<u8>) {
    write_bytes(text.as_bytes(), out);
}

fn decode_validation_receipt_text(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<ValidationReceiptText, EncodingError> {
    let bytes = read_bytes(buf, pos, field)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| EncodingError::InvalidValue {
        field,
        detail: "validation receipt text is not UTF-8".into(),
    })?;
    ValidationReceiptText::try_from_str(text).map_err(|err| EncodingError::InvalidValue {
        field,
        detail: err.to_string(),
    })
}

fn encode_validation_artifact_digest(digest: ValidationArtifactDigest, out: &mut Vec<u8>) {
    out.extend_from_slice(digest.as_bytes());
}

fn decode_validation_artifact_digest(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<ValidationArtifactDigest, EncodingError> {
    if *pos + 32 > buf.len() {
        return Err(EncodingError::UnexpectedEof { field });
    }
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&buf[*pos..*pos + 32]);
    *pos += 32;
    Ok(ValidationArtifactDigest::from_bytes(bytes))
}

fn encode_validation_receipt_digest(digest: ValidationReceiptDigest, out: &mut Vec<u8>) {
    out.extend_from_slice(digest.as_bytes());
}

fn decode_validation_receipt_digest(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<ValidationReceiptDigest, EncodingError> {
    if *pos + 32 > buf.len() {
        return Err(EncodingError::UnexpectedEof { field });
    }
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&buf[*pos..*pos + 32]);
    *pos += 32;
    Ok(ValidationReceiptDigest::from_bytes(bytes))
}

fn encode_validation_receipt_producer(producer: &ValidationReceiptProducer, out: &mut Vec<u8>) {
    encode_validation_receipt_text(&producer.producer_id, out);
    encode_validation_receipt_text(&producer.producer_version, out);
    encode_validation_receipt_text(&producer.run_id, out);
    write_u64(producer.produced_at_millis, out);
}

fn decode_validation_receipt_producer(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<ValidationReceiptProducer, EncodingError> {
    Ok(ValidationReceiptProducer {
        producer_id: decode_validation_receipt_text(buf, pos, field)?,
        producer_version: decode_validation_receipt_text(buf, pos, field)?,
        run_id: decode_validation_receipt_text(buf, pos, field)?,
        produced_at_millis: read_u64(buf, pos, field)?,
    })
}

// /// Deserialize an InodeId from 8 bytes LE.
// ── ClaimantRef ──────────────────────────────────────────────────────────

fn encode_claimant_ref(r: &ClaimantRef, out: &mut Vec<u8>) {
    match r {
        ClaimantRef::Process { pid, name } => {
            write_u8(0, out);
            write_u64(*pid, out);
            write_string(name, out);
        }
        ClaimantRef::Cohort { cohort_id, label } => {
            write_u8(1, out);
            write_u64(*cohort_id, out);
            write_string(label, out);
        }
        ClaimantRef::Service { service_name } => {
            write_u8(2, out);
            write_string(service_name, out);
        }
    }
}

fn decode_claimant_ref(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<ClaimantRef, EncodingError> {
    match read_u8(buf, pos, field)? {
        0 => {
            let pid = read_u64(buf, pos, field)?;
            let name = read_string(buf, pos, field)?;
            Ok(ClaimantRef::Process { pid, name })
        }
        1 => {
            let cohort_id = read_u64(buf, pos, field)?;
            let label = read_string(buf, pos, field)?;
            Ok(ClaimantRef::Cohort { cohort_id, label })
        }
        2 => {
            let service_name = read_string(buf, pos, field)?;
            Ok(ClaimantRef::Service { service_name })
        }
        v => Err(EncodingError::InvalidDiscriminant { field, value: v }),
    }
}

// ── LeaseDeadlineRecord ──────────────────────────────────────────────────

fn encode_lease_deadline(r: &LeaseDeadlineRecord, out: &mut Vec<u8>) {
    write_u64(r.deadline_millis, out);
    write_u8(r.auto_reclaim as u8, out);
}

fn decode_lease_deadline(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<LeaseDeadlineRecord, EncodingError> {
    let deadline_millis = read_u64(buf, pos, field)?;
    let auto_reclaim = read_u8(buf, pos, field)? != 0;
    Ok(LeaseDeadlineRecord {
        deadline_millis,
        auto_reclaim,
    })
}

// ── ClaimClass ───────────────────────────────────────────────────────────

fn encode_claim_class(c: ClaimClass, out: &mut Vec<u8>) {
    write_u8(c.as_u8(), out);
}

fn decode_claim_class(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<ClaimClass, EncodingError> {
    let v = read_u8(buf, pos, field)?;
    ClaimClass::try_from(v).map_err(|_| EncodingError::InvalidDiscriminant { field, value: v })
}

// ── ClaimEntryRecord ─────────────────────────────────────────────────────

fn encode_entry(entry: &ClaimEntryRecord, out: &mut Vec<u8>) {
    encode_claim_id(entry.claim_id, out);
    encode_claimant_ref(&entry.claimant_ref, out);
    encode_claim_class(entry.claim_class, out);
    write_u64(entry.claimed_bytes, out);
    write_u64(entry.committed_bytes, out);
    write_optional_u64(entry.inode_id.map(|id| id.0), out);
    write_optional_u64(entry.freshness_fence_ref, out);
    encode_receipt_id(entry.claim_receipt_ref, out);
    match &entry.expiration_deadline {
        None => write_u8(0, out),
        Some(dl) => {
            write_u8(1, out);
            encode_lease_deadline(dl, out);
        }
    }
}

fn decode_entry(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<ClaimEntryRecord, EncodingError> {
    let claim_id = decode_claim_id(buf, pos, field)?;
    let claimant_ref = decode_claimant_ref(buf, pos, field)?;
    let claim_class = decode_claim_class(buf, pos, field)?;
    let claimed_bytes = read_u64(buf, pos, field)?;
    let committed_bytes = read_u64(buf, pos, field)?;
    let inode_id = read_optional_u64(buf, pos, field)?.map(InodeId::new);
    let freshness_fence_ref = read_optional_u64(buf, pos, field)?;
    let claim_receipt_ref = decode_receipt_id(buf, pos, field)?;
    let expiration_deadline = match read_u8(buf, pos, field)? {
        0 => None,
        1 => Some(decode_lease_deadline(buf, pos, field)?),
        v => {
            return Err(EncodingError::InvalidValue {
                field,
                detail: format!("expiration deadline flag must be 0 or 1, got {v}"),
            })
        }
    };
    Ok(ClaimEntryRecord {
        claim_id,
        claimant_ref,
        claim_class,
        claimed_bytes,
        committed_bytes,
        inode_id,
        freshness_fence_ref,
        claim_receipt_ref,
        expiration_deadline,
    })
}

// ── ValidationReceiptRecord ──────────────────────────────────────────────

const VALIDATION_RECEIPT_RECORD_VERSION: u32 = 1;

impl ClaimEncoding for ValidationReceiptRecord {
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(384);
        write_u32(VALIDATION_RECEIPT_RECORD_VERSION, &mut out);
        write_u64(self.sequence, &mut out);
        encode_validation_receipt_text(&self.claim_id, &mut out);
        encode_validation_receipt_text(&self.evidence_class, &mut out);
        encode_validation_receipt_text(&self.validation_tier, &mut out);
        encode_validation_receipt_text(&self.status, &mut out);
        encode_validation_artifact_digest(self.artifact_digest, &mut out);
        encode_validation_receipt_digest(self.previous_receipt_digest, &mut out);
        encode_validation_receipt_producer(&self.producer, &mut out);
        out
    }

    fn deserialize(buf: &[u8]) -> Result<Self, EncodingError> {
        let mut pos = 0_usize;
        let version = read_u32(buf, &mut pos, "validation_receipt.version")?;
        if version != VALIDATION_RECEIPT_RECORD_VERSION {
            return Err(EncodingError::InvalidValue {
                field: "validation_receipt.version",
                detail: format!("unsupported validation receipt version {version}"),
            });
        }
        let record = ValidationReceiptRecord::new(
            read_u64(buf, &mut pos, "validation_receipt.sequence")?,
            decode_validation_receipt_text(buf, &mut pos, "validation_receipt.claim_id")?,
            decode_validation_receipt_text(buf, &mut pos, "validation_receipt.evidence_class")?,
            decode_validation_receipt_text(buf, &mut pos, "validation_receipt.validation_tier")?,
            decode_validation_receipt_text(buf, &mut pos, "validation_receipt.status")?,
            decode_validation_artifact_digest(buf, &mut pos, "validation_receipt.artifact_digest")?,
            decode_validation_receipt_digest(
                buf,
                &mut pos,
                "validation_receipt.previous_receipt_digest",
            )?,
            decode_validation_receipt_producer(buf, &mut pos, "validation_receipt.producer")?,
        );
        if pos != buf.len() {
            return Err(EncodingError::InvalidValue {
                field: "validation_receipt",
                detail: format!("trailing bytes: expected {} consumed, got {pos}", buf.len()),
            });
        }
        Ok(record)
    }
}

// ── ClaimLedger ──────────────────────────────────────────────────────────

impl ClaimEncoding for ClaimLedger {
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.claim_entries.len() * 64);
        write_u64(self.ledger_id, &mut out);
        encode_budget_domain_id(&self.budget_domain_ref, &mut out);
        write_u64(self.total_claimed_bytes, &mut out);
        write_u64(self.total_committed_bytes, &mut out);
        write_u32(self.claim_entries.len() as u32, &mut out);
        for entry in &self.claim_entries {
            encode_entry(entry, &mut out);
        }
        encode_receipt_id(self.issuance_receipt_ref, &mut out);
        out
    }

    fn deserialize(buf: &[u8]) -> Result<Self, EncodingError> {
        let mut pos = 0_usize;
        let ledger_id = read_u64(buf, &mut pos, "ledger_id")?;
        let budget_domain_ref = decode_budget_domain_id(buf, &mut pos, "budget_domain_ref")?;
        let total_claimed_bytes = read_u64(buf, &mut pos, "total_claimed_bytes")?;
        let total_committed_bytes = read_u64(buf, &mut pos, "total_committed_bytes")?;
        let entry_count = read_u32(buf, &mut pos, "entry_count")? as usize;
        let mut claim_entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            claim_entries.push(decode_entry(buf, &mut pos, "claim_entry")?);
        }
        let issuance_receipt_ref = decode_receipt_id(buf, &mut pos, "issuance_receipt_ref")?;
        if pos != buf.len() {
            return Err(EncodingError::InvalidValue {
                field: "body",
                detail: format!("trailing bytes: expected {} consumed, got {pos}", buf.len()),
            });
        }
        Ok(ClaimLedger {
            ledger_id,
            budget_domain_ref,
            total_claimed_bytes,
            total_committed_bytes,
            claim_entries,
            issuance_receipt_ref,
        })
    }
}

// ── ObligationLedger encoding (no_std types from types-claim-ledger-core) ─
//
// The ObligationLedger tracks space claims per Design rule Rule 8. Only the
// active entries (up to claim_count / reserve_count / witness_count) are
// serialized; the fixed-size [Option<T>; N] arrays are decoded into on read.

// -- ClaimReason -----------------------------------------------------------

fn encode_claim_reason(r: ClaimReason, out: &mut Vec<u8>) {
    write_u32(r.as_u32(), out);
}

fn decode_claim_reason(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<ClaimReason, EncodingError> {
    let v = read_u32(buf, pos, field)?;
    ClaimReason::try_from(v).map_err(|_| EncodingError::InvalidDiscriminant {
        field,
        value: v as u8,
    })
}

// -- ReserveId -------------------------------------------------------------

fn encode_reserve_id(id: ReserveId, out: &mut Vec<u8>) {
    out.extend_from_slice(id.as_bytes());
}

fn decode_reserve_id(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<ReserveId, EncodingError> {
    if *pos + 16 > buf.len() {
        return Err(EncodingError::UnexpectedEof { field });
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&buf[*pos..*pos + 16]);
    *pos += 16;
    Ok(ReserveId::from_bytes(bytes))
}

// -- ClaimEntry (types-core, non-optional inode_id) ------------------------

fn encode_claim_entry(e: &ClaimEntry, out: &mut Vec<u8>) {
    encode_claim_id(e.claim_id, out);
    encode_budget_domain_id(&e.budget_domain, out);
    write_u64(e.blocks, out);
    write_u64(e.inode_id.0, out);
    encode_claim_reason(e.reason, out);
    encode_receipt_id(e.authorized_by, out);
    write_u64(e.generation, out);
}

fn decode_claim_entry(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<ClaimEntry, EncodingError> {
    let claim_id = decode_claim_id(buf, pos, field)?;
    let budget_domain = decode_budget_domain_id(buf, pos, field)?;
    let blocks = read_u64(buf, pos, field)?;
    let inode_id = InodeId::new(read_u64(buf, pos, field)?);
    let reason = decode_claim_reason(buf, pos, field)?;
    let authorized_by = decode_receipt_id(buf, pos, field)?;
    let generation = read_u64(buf, pos, field)?;
    Ok(ClaimEntry {
        claim_id,
        budget_domain,
        blocks,
        inode_id,
        reason,
        authorized_by,
        generation,
    })
}

// -- ReserveEntry ----------------------------------------------------------

fn encode_reserve_entry(e: &ReserveEntry, out: &mut Vec<u8>) {
    encode_reserve_id(e.reserve_id, out);
    encode_budget_domain_id(&e.budget_domain, out);
    write_u64(e.min_blocks, out);
    encode_claim_reason(e.reason, out);
    encode_receipt_id(e.authorized_by, out);
    write_u64(e.generation, out);
}

fn decode_reserve_entry(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<ReserveEntry, EncodingError> {
    let reserve_id = decode_reserve_id(buf, pos, field)?;
    let budget_domain = decode_budget_domain_id(buf, pos, field)?;
    let min_blocks = read_u64(buf, pos, field)?;
    let reason = decode_claim_reason(buf, pos, field)?;
    let authorized_by = decode_receipt_id(buf, pos, field)?;
    let generation = read_u64(buf, pos, field)?;
    Ok(ReserveEntry {
        reserve_id,
        budget_domain,
        min_blocks,
        reason,
        authorized_by,
        generation,
    })
}

// -- WitnessReceipt --------------------------------------------------------

fn encode_witness_receipt(w: &WitnessReceipt, out: &mut Vec<u8>) {
    encode_claim_id(w.claim_id, out);
    encode_receipt_id(w.receipt_id, out);
    out.extend_from_slice(&w.witness_bytes);
}

fn decode_witness_receipt(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<WitnessReceipt, EncodingError> {
    let claim_id = decode_claim_id(buf, pos, field)?;
    let receipt_id = decode_receipt_id(buf, pos, field)?;
    if *pos + 32 > buf.len() {
        return Err(EncodingError::UnexpectedEof { field });
    }
    let mut witness_bytes = [0u8; 32];
    witness_bytes.copy_from_slice(&buf[*pos..*pos + 32]);
    *pos += 32;
    Ok(WitnessReceipt {
        claim_id,
        receipt_id,
        witness_bytes,
    })
}

// -- ObligationLedger ------------------------------------------------------
//
// Serialization layout:
//   total_blocks: u64 LE
//   claim_count: u32 LE
//   [ClaimEntry; claim_count]
//   reserve_count: u32 LE
//   [ReserveEntry; reserve_count]
//   witness_count: u32 LE
//   [WitnessReceipt; witness_count]

impl ClaimEncoding for ObligationLedger {
    fn serialize(&self) -> Vec<u8> {
        let claim_count = self.claim_count() as u32;
        let reserve_count = self.reserve_count() as u32;
        let witness_count = self.witness_count() as u32;
        let est = 64
            + claim_count as usize * 80
            + reserve_count as usize * 80
            + witness_count as usize * 72;
        let mut out = Vec::with_capacity(est);
        write_u64(self.total_blocks(), &mut out);

        write_u32(claim_count, &mut out);
        for entry in self.claims_iter() {
            encode_claim_entry(entry, &mut out);
        }

        write_u32(reserve_count, &mut out);
        for entry in self.reserves_iter() {
            encode_reserve_entry(entry, &mut out);
        }

        write_u32(witness_count, &mut out);
        for entry in self.witnesses_iter() {
            encode_witness_receipt(entry, &mut out);
        }

        out
    }

    fn deserialize(buf: &[u8]) -> Result<Self, EncodingError> {
        let mut pos = 0_usize;
        let total_blocks = read_u64(buf, &mut pos, "total_blocks")?;

        let claim_count = read_u32(buf, &mut pos, "claim_count")? as usize;
        // Decode all entries into vecs first, then build the ledger via
        // its public API (all fields are private).
        let mut decoded_claims: Vec<ClaimEntry> = Vec::with_capacity(claim_count);
        for _ in 0..claim_count {
            decoded_claims.push(decode_claim_entry(buf, &mut pos, "claim_entry")?);
        }

        let reserve_count = read_u32(buf, &mut pos, "reserve_count")? as usize;
        let mut decoded_reserves: Vec<ReserveEntry> = Vec::with_capacity(reserve_count);
        for _ in 0..reserve_count {
            decoded_reserves.push(decode_reserve_entry(buf, &mut pos, "reserve_entry")?);
        }

        let witness_count = read_u32(buf, &mut pos, "witness_count")? as usize;
        let mut decoded_witnesses: Vec<WitnessReceipt> = Vec::with_capacity(witness_count);
        for _ in 0..witness_count {
            decoded_witnesses.push(decode_witness_receipt(buf, &mut pos, "witness_receipt")?);
        }

        if pos != buf.len() {
            return Err(EncodingError::InvalidValue {
                field: "obligation_ledger",
                detail: format!("trailing bytes: expected {} consumed, got {pos}", buf.len()),
            });
        }

        let mut ledger = ObligationLedger::new(total_blocks);
        for entry in decoded_claims {
            // Space check should pass for valid serializations; convert
            // ObligationLedgerError into EncodingError for safety.
            ledger
                .claim(entry)
                .map_err(|_| EncodingError::InvalidValue {
                    field: "obligation_ledger",
                    detail: "claim rejected by space check during deserialization".into(),
                })?;
        }
        for entry in decoded_reserves {
            ledger
                .reserve(entry)
                .map_err(|_| EncodingError::InvalidValue {
                    field: "obligation_ledger",
                    detail: "reserve rejected by space check during deserialization".into(),
                })?;
        }
        for receipt in decoded_witnesses {
            ledger
                .witness(receipt)
                .map_err(|_| EncodingError::InvalidValue {
                    field: "obligation_ledger",
                    detail: "witness rejected during deserialization".into(),
                })?;
        }

        Ok(ledger)
    }
}
// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClaimEntryRecord, ClaimLedger};

    fn test_domain() -> BudgetDomainId {
        BudgetDomainId::from_str("test_domain")
    }

    /// Build a test ledger with `n` entries, each claiming (i+1)*4096 bytes.
    fn make_ledger(n: usize) -> ClaimLedger {
        let mut ledger = ClaimLedger::new(42, test_domain());
        for i in 0..n {
            let claim_id = {
                let mut b = [0u8; 16];
                b[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                ClaimId::from_bytes(b)
            };
            let mut entry = ClaimEntryRecord::new(
                claim_id,
                ClaimantRef::Service {
                    service_name: format!("svc-{i}"),
                },
                match i % 4 {
                    0 => ClaimClass::Product,
                    1 => ClaimClass::Rebuild,
                    2 => ClaimClass::AntiEntropy,
                    _ => ClaimClass::Failover,
                },
                4096 * (i as u64 + 1),
            );
            entry.inode_id = Some(InodeId::new((100 + i) as u64));
            ledger.claim_entries.push(entry);
            ledger.total_claimed_bytes += 4096 * (i as u64 + 1);
        }
        ledger
    }

    // ── Round-trip tests ──────────────────────────────────────────────

    #[test]
    fn roundtrip_empty_ledger() {
        let ledger = ClaimLedger::new(1, test_domain());
        let bytes = ledger.serialize();
        let deser = ClaimLedger::deserialize(&bytes).unwrap();
        assert_eq!(deser.ledger_id, 1);
        assert_eq!(deser.budget_domain_ref.as_str(), "test_domain");
        assert_eq!(deser.total_claimed_bytes, 0);
        assert_eq!(deser.total_committed_bytes, 0);
        assert!(deser.claim_entries.is_empty());
    }

    #[test]
    fn roundtrip_single_entry() {
        let ledger = make_ledger(1);
        let bytes = ledger.serialize();
        let deser = ClaimLedger::deserialize(&bytes).unwrap();
        assert_eq!(deser.claim_entries.len(), 1);
        assert_eq!(deser.claim_entries[0].claimed_bytes, 4096);
        assert_eq!(
            deser.claim_entries[0].claimant_ref,
            ClaimantRef::Service {
                service_name: "svc-0".into()
            }
        );
        assert_eq!(deser.claim_entries[0].claim_class, ClaimClass::Product);
        assert_eq!(deser.claim_entries[0].inode_id, Some(InodeId::new(100)));
    }

    #[test]
    fn roundtrip_ten_entries() {
        let ledger = make_ledger(10);
        let bytes = ledger.serialize();
        let deser = ClaimLedger::deserialize(&bytes).unwrap();
        assert_eq!(deser.claim_entries.len(), 10);
        for (i, entry) in deser.claim_entries.iter().enumerate() {
            assert_eq!(entry.claimed_bytes, 4096 * (i as u64 + 1));
        }
    }

    #[test]
    fn roundtrip_claimant_ref_variants() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let variants = vec![
            ClaimantRef::Process {
                pid: 1234,
                name: "fuse-worker".into(),
            },
            ClaimantRef::Cohort {
                cohort_id: 99,
                label: "write-cohort".into(),
            },
            ClaimantRef::Service {
                service_name: "seg-writer".into(),
            },
        ];
        for (i, claimant) in variants.into_iter().enumerate() {
            let mut b = [0u8; 16];
            b[0] = i as u8;
            let entry = ClaimEntryRecord::new(
                ClaimId::from_bytes(b),
                claimant.clone(),
                ClaimClass::Product,
                1024,
            );
            ledger.claim_entries.push(entry);
            ledger.total_claimed_bytes += 1024;
        }
        let bytes = ledger.serialize();
        let deser = ClaimLedger::deserialize(&bytes).unwrap();
        assert_eq!(deser.claim_entries.len(), 3);
        assert_eq!(
            deser.claim_entries[0].claimant_ref,
            ClaimantRef::Process {
                pid: 1234,
                name: "fuse-worker".into()
            }
        );
        assert_eq!(
            deser.claim_entries[1].claimant_ref,
            ClaimantRef::Cohort {
                cohort_id: 99,
                label: "write-cohort".into()
            }
        );
        assert_eq!(
            deser.claim_entries[2].claimant_ref,
            ClaimantRef::Service {
                service_name: "seg-writer".into()
            }
        );
    }

    #[test]
    fn roundtrip_claim_classes() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        for (i, cls) in [
            ClaimClass::Product,
            ClaimClass::Rebuild,
            ClaimClass::AntiEntropy,
            ClaimClass::Failover,
        ]
        .iter()
        .enumerate()
        {
            let mut b = [0u8; 16];
            b[0] = i as u8;
            let entry = ClaimEntryRecord::new(
                ClaimId::from_bytes(b),
                ClaimantRef::Service {
                    service_name: format!("svc-{i}"),
                },
                *cls,
                1024,
            );
            ledger.claim_entries.push(entry);
            ledger.total_claimed_bytes += 1024;
        }
        let bytes = ledger.serialize();
        let deser = ClaimLedger::deserialize(&bytes).unwrap();
        assert_eq!(deser.claim_entries[0].claim_class, ClaimClass::Product);
        assert_eq!(deser.claim_entries[1].claim_class, ClaimClass::Rebuild);
        assert_eq!(deser.claim_entries[2].claim_class, ClaimClass::AntiEntropy);
        assert_eq!(deser.claim_entries[3].claim_class, ClaimClass::Failover);
    }

    #[test]
    fn roundtrip_with_lease_deadline() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let mut entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            4096,
        );
        entry.expiration_deadline = Some(LeaseDeadlineRecord {
            deadline_millis: 1715280000000,
            auto_reclaim: true,
        });
        ledger.claim_entries.push(entry);
        ledger.total_claimed_bytes = 4096;

        let bytes = ledger.serialize();
        let deser = ClaimLedger::deserialize(&bytes).unwrap();
        let dl = deser.claim_entries[0].expiration_deadline.unwrap();
        assert_eq!(dl.deadline_millis, 1715280000000);
        assert!(dl.auto_reclaim);
    }

    #[test]
    fn roundtrip_with_freshness_fence() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let mut entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            4096,
        );
        entry.freshness_fence_ref = Some(42);
        ledger.claim_entries.push(entry);
        ledger.total_claimed_bytes = 4096;

        let bytes = ledger.serialize();
        let deser = ClaimLedger::deserialize(&bytes).unwrap();
        assert_eq!(deser.claim_entries[0].freshness_fence_ref, Some(42));
    }

    #[test]
    fn roundtrip_with_receipt_id() {
        let mut ledger = ClaimLedger::new(1, test_domain());
        let mut entry = ClaimEntryRecord::new(
            ClaimId::new(),
            ClaimantRef::Service {
                service_name: "test".into(),
            },
            ClaimClass::Product,
            4096,
        );
        let mut rid_bytes = [0u8; 16];
        rid_bytes[0] = 0xAB;
        rid_bytes[15] = 0xCD;
        entry.claim_receipt_ref = StorageAuthorityToken(rid_bytes);
        ledger.claim_entries.push(entry);
        ledger.total_claimed_bytes = 4096;

        let bytes = ledger.serialize();
        let deser = ClaimLedger::deserialize(&bytes).unwrap();
        assert_eq!(deser.claim_entries[0].claim_receipt_ref.0[0], 0xAB);
        assert_eq!(deser.claim_entries[0].claim_receipt_ref.0[15], 0xCD);
    }

    // ── Integrity tests ───────────────────────────────────────────────

    #[test]
    fn integrity_verify_ok() {
        let ledger = make_ledger(3);
        let ci = ClaimIntegrity::seal_claim(&ledger);
        ci.verify().unwrap();
    }

    #[test]
    fn integrity_verify_and_deserialize_roundtrip() {
        let ledger = make_ledger(3);
        let ci = ClaimIntegrity::seal_claim(&ledger);
        let deser: ClaimLedger = ci.verify_and_deserialize().unwrap();
        assert_eq!(deser.claim_entries.len(), 3);
    }

    #[test]
    fn integrity_single_byte_tamper_rejected() {
        let ledger = make_ledger(3);
        let mut ci = ClaimIntegrity::seal_claim(&ledger);
        // Flip one bit in the payload
        ci.payload[0] ^= 0x01;
        assert!(ci.verify().is_err());
    }

    #[test]
    fn integrity_tampered_hash_rejected() {
        let ledger = make_ledger(3);
        let mut ci = ClaimIntegrity::seal_claim(&ledger);
        // Corrupt the hash, leave payload intact
        ci.hash[0] ^= 0xFF;
        assert!(ci.verify().is_err());
    }

    #[test]
    fn integrity_empty_payload() {
        let ci = ClaimIntegrity::seal(Vec::new());
        ci.verify().unwrap();
        assert_ne!(ci.hash, [0u8; 32]);
    }

    #[test]
    fn integrity_deterministic_hash() {
        let ledger = make_ledger(1);
        let ci1 = ClaimIntegrity::seal_claim(&ledger);
        let ci2 = ClaimIntegrity::seal_claim(&ledger);
        assert_eq!(ci1.hash, ci2.hash);
    }

    // ── Error-path tests ──────────────────────────────────────────────

    #[test]
    fn deserialize_truncated_header() {
        let bytes = vec![0u8; 4]; // too short for u64 ledger_id
        match ClaimLedger::deserialize(&bytes).unwrap_err() {
            EncodingError::UnexpectedEof { field } => assert_eq!(field, "ledger_id"),
            _ => panic!("expected UnexpectedEof"),
        }
    }

    #[test]
    fn deserialize_truncated_mid_entry() {
        let ledger = make_ledger(3);
        let mut bytes = ledger.serialize();
        bytes.truncate(bytes.len() - 40);
        assert!(ClaimLedger::deserialize(&bytes).is_err());
    }

    #[test]
    fn deserialize_trailing_bytes_error() {
        let ledger = make_ledger(1);
        let mut bytes = ledger.serialize();
        bytes.push(0xFF);
        assert!(ClaimLedger::deserialize(&bytes).is_err());
    }

    #[test]
    fn deserialize_invalid_claim_class() {
        let ledger = make_ledger(1);
        let mut bytes = ledger.serialize();
        // The claim_class byte is at a fixed offset.
        // Layout: ledger_id(8) + budget_domain(1+11=12) + total_claimed(8) +
        //         total_committed(8) + entry_count(4) + claim_id(16) +
        //         claimant_ref(1+4+5=10) = 66
        let claim_class_offset = 8 + 12 + 8 + 8 + 4 + 16 + 10;
        bytes[claim_class_offset] = 255;
        assert!(ClaimLedger::deserialize(&bytes).is_err());
    }

    #[test]
    fn deserialize_invalid_claimant_discriminant() {
        let ledger = make_ledger(1);
        let mut bytes = ledger.serialize();
        // claimant_ref discriminant is at offset 8+12+8+8+4+16 = 56
        bytes[56] = 99;
        assert!(ClaimLedger::deserialize(&bytes).is_err());
    }

    #[test]
    fn deserialize_invalid_utf8_budget_domain() {
        // Manually construct payload with invalid UTF-8 in budget domain
        let mut buf = Vec::new();
        write_u64(1, &mut buf); // ledger_id
        write_u8(3, &mut buf); // domain len
        buf.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // invalid UTF-8
        write_u64(0, &mut buf); // total_claimed
        write_u64(0, &mut buf); // total_committed
        write_u32(0, &mut buf); // entry_count
                                // receipt_id (16 bytes)
        buf.extend_from_slice(&[0u8; 16]);
        assert!(ClaimLedger::deserialize(&buf).is_err());
    }

    // ── Large ledger boundary test ────────────────────────────────────

    #[test]
    fn roundtrip_large_ledger_1000_entries() {
        let ledger = make_ledger(1000);
        let bytes = ledger.serialize();
        let deser = ClaimLedger::deserialize(&bytes).unwrap();
        assert_eq!(deser.claim_entries.len(), 1000);
        assert_eq!(deser.claim_entries[999].claimed_bytes, 4096 * 1000);
    }

    // ── ObligationLedger round-trip tests ──────────────────────────────

    fn make_obligation_ledger() -> ObligationLedger {
        use tidefs_types_claim_ledger_core::ClaimEntry as CEntry;
        let mut ledger = ObligationLedger::new(100_000);
        let domain = BudgetDomainId::from_str("authority_hot");
        let inode = InodeId::new(42);
        ledger
            .claim(CEntry {
                claim_id: ClaimId::new(),
                budget_domain: domain,
                blocks: 500,
                inode_id: inode,
                reason: ClaimReason::Write,
                authorized_by: StorageAuthorityToken::ABSENT,
                generation: 1,
            })
            .unwrap();
        ledger
            .claim(CEntry {
                claim_id: ClaimId::new(),
                budget_domain: BudgetDomainId::from_str("staging_dirty"),
                blocks: 300,
                inode_id: InodeId::new(43),
                reason: ClaimReason::Metadata,
                authorized_by: StorageAuthorityToken::ABSENT,
                generation: 2,
            })
            .unwrap();
        ledger
    }

    #[test]
    fn obligation_ledger_roundtrip_empty() {
        let ledger = ObligationLedger::new(0);
        let bytes = ledger.serialize();
        let deser = ObligationLedger::deserialize(&bytes).unwrap();
        assert_eq!(deser.total_blocks(), 0);
        assert_eq!(deser.claim_count(), 0);
        assert_eq!(deser.reserve_count(), 0);
    }

    #[test]
    fn obligation_ledger_roundtrip_with_claims() {
        let ledger = make_obligation_ledger();
        let bytes = ledger.serialize();
        let deser = ObligationLedger::deserialize(&bytes).unwrap();
        assert_eq!(deser.total_blocks(), ledger.total_blocks());
        assert_eq!(deser.claim_count(), ledger.claim_count());
        assert_eq!(deser.allocated_blocks(), ledger.allocated_blocks());
    }

    #[test]
    fn obligation_ledger_roundtrip_with_reserves() {
        let mut ledger = ObligationLedger::new(100_000);
        let domain = BudgetDomainId::from_str("authority_hot");
        ledger
            .reserve(ReserveEntry {
                reserve_id: ReserveId::new(),
                budget_domain: domain,
                min_blocks: 1000,
                reason: ClaimReason::Reserve,
                authorized_by: StorageAuthorityToken::ABSENT,
                generation: 1,
            })
            .unwrap();
        let bytes = ledger.serialize();
        let deser = ObligationLedger::deserialize(&bytes).unwrap();
        assert_eq!(deser.reserve_count(), 1);
        assert_eq!(deser.reserved_blocks(), 1000);
    }

    #[test]
    fn obligation_ledger_roundtrip_with_witnesses() {
        let mut ledger = ObligationLedger::new(100_000);
        let claim_id = ClaimId::new();
        ledger
            .witness(WitnessReceipt {
                claim_id,
                receipt_id: StorageAuthorityToken::ABSENT,
                witness_bytes: [0xCC; 32],
            })
            .unwrap();
        let bytes = ledger.serialize();
        let deser = ObligationLedger::deserialize(&bytes).unwrap();
        assert_eq!(deser.witness_count(), 1);
        let w = deser.witnesses_iter().next().unwrap();
        assert_eq!(w.claim_id, claim_id);
        assert_eq!(w.witness_bytes, [0xCC; 32]);
    }

    #[test]
    fn obligation_ledger_integrity_seal_verify() {
        let ledger = make_obligation_ledger();
        let ci = ClaimIntegrity::seal_claim(&ledger);
        ci.verify().unwrap();
        let deser: ObligationLedger = ci.verify_and_deserialize().unwrap();
        assert_eq!(deser.claim_count(), ledger.claim_count());
        assert_eq!(deser.allocated_blocks(), ledger.allocated_blocks());
    }

    #[test]
    fn obligation_ledger_integrity_tamper_rejected() {
        let ledger = make_obligation_ledger();
        let mut ci = ClaimIntegrity::seal_claim(&ledger);
        ci.payload[0] ^= 0x01;
        assert!(ci.verify().is_err());
    }

    #[test]
    fn obligation_ledger_truncated_rejected() {
        let ledger = make_obligation_ledger();
        let mut bytes = ledger.serialize();
        bytes.truncate(20);
        assert!(ObligationLedger::deserialize(&bytes).is_err());
    }
}
