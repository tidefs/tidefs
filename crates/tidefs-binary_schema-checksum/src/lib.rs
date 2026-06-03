#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Checksum and digest law per P2-03 §4.
//!
//! Implements the four canonical checksum/digest profile classes (`chk0`–`chk3`)
//! and domain-separated blake3 hashing.
//!
//! - `crc32c` via the `crc32c` crate (hardware-accelerated where available)
//! - `blake3` via the `blake3` crate (pure Rust, SIMD-accelerated)
//! - Domain-separated `blake3` with family, type, version, section, and role tags

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use tidefs_binary_schema_core::{
    BinarySchemaError, ChecksumProfile, DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion,
};

// ---------------------------------------------------------------------------
// CRC32C
// ---------------------------------------------------------------------------

/// Compute `crc32c` over `data` (Castagnoli polynomial, iSCSI/RDMA standard).
/// Returns the 4-byte LE digest.
#[inline]
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
}

/// Compute `crc32c` over `data` and append the digest as LE bytes.
pub fn crc32c_append(data: &[u8], buf: &mut Vec<u8>) {
    let csum = crc32c(data);
    buf.extend_from_slice(&csum.to_le_bytes());
}

/// Verify `crc32c` of `data` against expected LE bytes `expected_le`.
#[inline]
pub fn crc32c_verify(data: &[u8], expected_le: &[u8; 4]) -> Result<(), BinarySchemaError> {
    let expected = u32::from_le_bytes(*expected_le);
    if crc32c(data) != expected {
        Err(BinarySchemaError::ChecksumMismatch)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Blake3-256
// ---------------------------------------------------------------------------

/// Compute a domain-separated `blake3` 256-bit digest.
///
/// Per P2-03 §4.3, the hasher is keyed with a domain context built from:
/// - family id
/// - type id
/// - major.minor version
/// - domain tag (semantic role)
///
/// This prevents cross-type digest collisions from becoming semantic ambiguity.
#[inline]
pub fn blake3_domain_digest(
    data: &[u8],
    family: SchemaFamilyId,
    type_id: SchemaTypeId,
    version: SchemaVersion,
    tag: DomainTag,
) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key(&build_domain_context(family, type_id, version, tag));
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute blake3-256 of data with domain context, writing into `out`.
pub fn blake3_domain_digest_into(
    data: &[u8],
    family: SchemaFamilyId,
    type_id: SchemaTypeId,
    version: SchemaVersion,
    tag: DomainTag,
    out: &mut [u8; 32],
) {
    let mut hasher =
        blake3::Hasher::new_derive_key(&build_domain_context(family, type_id, version, tag));
    hasher.update(data);
    *out = hasher.finalize().into();
}

/// Verify a domain-separated blake3 digest against expected `[u8; 32]`.
pub fn blake3_domain_verify(
    data: &[u8],
    expected: &[u8; 32],
    family: SchemaFamilyId,
    type_id: SchemaTypeId,
    version: SchemaVersion,
    tag: DomainTag,
) -> Result<(), BinarySchemaError> {
    let actual = blake3_domain_digest(data, family, type_id, version, tag);
    if actual == *expected {
        Ok(())
    } else {
        Err(BinarySchemaError::DigestMismatch)
    }
}

// ---------------------------------------------------------------------------
// Domain context construction
// ---------------------------------------------------------------------------

/// Build a domain context key for blake3's derive_key mode.
///
/// Format: `"vbfs:fam={}:type={}:ver={}.{}:role={}"`
fn build_domain_context(
    family: SchemaFamilyId,
    type_id: SchemaTypeId,
    version: SchemaVersion,
    tag: DomainTag,
) -> String {
    use core::fmt::Write;
    let mut ctx = String::with_capacity(96);
    let _ = write!(
        ctx,
        "vbfs:fam={}:type={}:ver={}.{}:role={}",
        family.0,
        type_id.0,
        version.major,
        version.minor,
        tag.discriminant()
    );
    ctx
}

// ---------------------------------------------------------------------------
// Profile-driven checksum/digest sealing
// ---------------------------------------------------------------------------

/// A checksum/digest ticket produced by sealing a payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealTicket {
    pub profile: ChecksumProfile,
    pub crc32c_bytes: Option<[u8; 4]>,
    pub blake3_bytes: Option<[u8; 32]>,
}

/// Seal (fast check + strong digest) for a payload according to its profile.
pub fn seal_checksums(
    data: &[u8],
    profile: ChecksumProfile,
    family: SchemaFamilyId,
    type_id: SchemaTypeId,
    version: SchemaVersion,
    tag: DomainTag,
) -> SealTicket {
    match profile {
        ChecksumProfile::None => SealTicket {
            profile,
            crc32c_bytes: None,
            blake3_bytes: None,
        },
        ChecksumProfile::Crc32c => {
            let c = crc32c(data);
            SealTicket {
                profile,
                crc32c_bytes: Some(c.to_le_bytes()),
                blake3_bytes: None,
            }
        }
        ChecksumProfile::Blake3_256 => {
            let b = blake3_domain_digest(data, family, type_id, version, tag);
            SealTicket {
                profile,
                crc32c_bytes: None,
                blake3_bytes: Some(b),
            }
        }
        ChecksumProfile::Crc32cPlusBlake3_256 => {
            let c = crc32c(data);
            let b = blake3_domain_digest(data, family, type_id, version, tag);
            SealTicket {
                profile,
                crc32c_bytes: Some(c.to_le_bytes()),
                blake3_bytes: Some(b),
            }
        }
    }
}

/// Verify a seal ticket against data (returns Ok(()) or the appropriate error).
pub fn verify_seal(
    data: &[u8],
    ticket: &SealTicket,
    family: SchemaFamilyId,
    type_id: SchemaTypeId,
    version: SchemaVersion,
    tag: DomainTag,
) -> Result<(), BinarySchemaError> {
    match ticket.profile {
        ChecksumProfile::None => Ok(()),
        ChecksumProfile::Crc32c => {
            let expected = ticket
                .crc32c_bytes
                .as_ref()
                .ok_or(BinarySchemaError::ChecksumMismatch)?;
            crc32c_verify(data, expected)
        }
        ChecksumProfile::Blake3_256 => {
            let expected = ticket
                .blake3_bytes
                .as_ref()
                .ok_or(BinarySchemaError::DigestMismatch)?;
            blake3_domain_verify(data, expected, family, type_id, version, tag)
        }
        ChecksumProfile::Crc32cPlusBlake3_256 => {
            let c_expected = ticket
                .crc32c_bytes
                .as_ref()
                .ok_or(BinarySchemaError::ChecksumMismatch)?;
            crc32c_verify(data, c_expected)?;
            let b_expected = ticket
                .blake3_bytes
                .as_ref()
                .ok_or(BinarySchemaError::DigestMismatch)?;
            blake3_domain_verify(data, b_expected, family, type_id, version, tag)
        }
    }
}

// ---------------------------------------------------------------------------
// Header CRC32C (used during envelope encoding)
// ---------------------------------------------------------------------------

/// Compute the header-internal crc32c over a partially-written envelope header.
///
/// The layout is: `[0..60]` = header fields, `[60..64]` = header_crc32c.
/// Caller writes all header fields into bytes `[0..60]`, passes them here,
/// and receives the LE crc32c to write into `[60..64]`.
#[inline]
pub fn envelope_header_crc32c(header_prefix: &[u8; 60]) -> [u8; 4] {
    crc32c(header_prefix).to_le_bytes()
}

/// Verify an envelope header's embedded crc32c.
///
/// `header_bytes` is the full 64-byte envelope; the crc32c at `[60..64]`
/// must match `crc32c(&header_bytes[0..60])`.
pub fn verify_envelope_header_crc32c(header_bytes: &[u8; 64]) -> Result<(), BinarySchemaError> {
    let expected = u32::from_le_bytes([
        header_bytes[60],
        header_bytes[61],
        header_bytes[62],
        header_bytes[63],
    ]);
    let actual = crc32c(&header_bytes[0..60]);
    if actual != expected {
        Err(BinarySchemaError::ChecksumMismatch)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_deterministic() {
        let data = b"hello binary schema";
        let a = crc32c(data);
        let b = crc32c(data);
        assert_eq!(a, b);
        assert_eq!(crc32c_verify(data, &a.to_le_bytes()), Ok(()));
    }

    #[test]
    fn crc32c_verify_fails_on_flip() {
        let data = b"test";
        let csum = crc32c(data);
        let mut bad = data.to_vec();
        bad[0] ^= 0x01;
        assert!(crc32c_verify(&bad, &csum.to_le_bytes()).is_err());
    }

    #[test]
    fn blake3_domain_deterministic() {
        let data = b"payload";
        let fam = SchemaFamilyId(1);
        let typ = SchemaTypeId(42);
        let ver = SchemaVersion::new(1, 0);
        let tag = DomainTag::ReceiptBody;
        let d1 = blake3_domain_digest(data, fam, typ, ver, tag);
        let d2 = blake3_domain_digest(data, fam, typ, ver, tag);
        assert_eq!(d1, d2);
    }

    #[test]
    fn blake3_domain_separation_differs_by_tag() {
        let data = b"same";
        let fam = SchemaFamilyId(1);
        let typ = SchemaTypeId(42);
        let ver = SchemaVersion::new(1, 0);
        let d_sec = blake3_domain_digest(data, fam, typ, ver, DomainTag::SectionBody);
        let d_rec = blake3_domain_digest(data, fam, typ, ver, DomainTag::ReceiptBody);
        assert_ne!(d_sec, d_rec);
    }

    #[test]
    fn seal_and_verify_all_profiles() {
        let data = b"authoritative record payload";
        let fam = SchemaFamilyId(1);
        let typ = SchemaTypeId(1);
        let ver = SchemaVersion::new(1, 0);
        let tag = DomainTag::EnvelopeHeader;

        for profile in [
            ChecksumProfile::None,
            ChecksumProfile::Crc32c,
            ChecksumProfile::Blake3_256,
            ChecksumProfile::Crc32cPlusBlake3_256,
        ] {
            let ticket = seal_checksums(data, profile, fam, typ, ver, tag);
            verify_seal(data, &ticket, fam, typ, ver, tag).unwrap();

            // Tamper check
            if profile != ChecksumProfile::None {
                let mut bad = data.to_vec();
                bad[0] ^= 0xFF;
                assert!(verify_seal(&bad, &ticket, fam, typ, ver, tag).is_err());
            }
        }
    }

    #[test]
    fn envelope_header_crc32c_roundtrip() {
        let mut header = [0u8; 64];
        header[0..4].copy_from_slice(&0x5346_4256u32.to_le_bytes()); // magic
                                                                     // ... other fields as zero for test ...
        let csum = envelope_header_crc32c(&header[0..60].try_into().unwrap());
        header[60..64].copy_from_slice(&csum);
        verify_envelope_header_crc32c(&header).unwrap();

        header[0] ^= 1; // corrupt
        assert!(verify_envelope_header_crc32c(&header).is_err());
    }

    // ── crc32c_append ────────────────────────────────────────────────

    #[test]
    fn crc32c_append_writes_le_bytes() {
        let data = b"append test";
        let expected = crc32c(data);
        let mut buf = Vec::new();
        crc32c_append(data, &mut buf);
        assert_eq!(buf.len(), 4);
        let got = u32::from_le_bytes(buf.try_into().unwrap());
        assert_eq!(got, expected);
    }

    #[test]
    fn crc32c_empty() {
        let csum = crc32c(b"");
        assert_eq!(csum, 0);
        assert_eq!(crc32c_verify(b"", &csum.to_le_bytes()), Ok(()));
    }

    // ── blake3_domain_digest_into ────────────────────────────────────

    #[test]
    fn blake3_domain_digest_into_matches_digest() {
        let data = b"into test";
        let fam = SchemaFamilyId(3);
        let typ = SchemaTypeId(7);
        let ver = SchemaVersion::new(2, 1);
        let tag = DomainTag::SectionBody;

        let expected = blake3_domain_digest(data, fam, typ, ver, tag);
        let mut out = [0u8; 32];
        blake3_domain_digest_into(data, fam, typ, ver, tag, &mut out);
        assert_eq!(out, expected);
    }

    // ── blake3_domain_verify direct ──────────────────────────────────

    #[test]
    fn blake3_domain_verify_correct() {
        let data = b"verify me";
        let fam = SchemaFamilyId(1);
        let typ = SchemaTypeId(1);
        let ver = SchemaVersion::new(1, 0);
        let tag = DomainTag::EnvelopeHeader;
        let digest = blake3_domain_digest(data, fam, typ, ver, tag);
        assert_eq!(
            blake3_domain_verify(data, &digest, fam, typ, ver, tag),
            Ok(())
        );
    }

    #[test]
    fn blake3_domain_verify_tampered() {
        let data = b"verify me";
        let fam = SchemaFamilyId(1);
        let typ = SchemaTypeId(1);
        let ver = SchemaVersion::new(1, 0);
        let tag = DomainTag::EnvelopeHeader;
        let digest = blake3_domain_digest(data, fam, typ, ver, tag);

        let mut bad_data = data.to_vec();
        bad_data[0] ^= 1;
        assert!(blake3_domain_verify(&bad_data, &digest, fam, typ, ver, tag).is_err());
    }
}
