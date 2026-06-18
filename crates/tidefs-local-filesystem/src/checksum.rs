// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Block-level checksum encoding and verification.
//!
//! This module provides a `BlockChecksum` trait for computing and verifying
//! integrity digests on data blocks. It is consumed by the scrub pipeline
//! (#589) and corruption resolver (#590).
//!
//! Two implementations are provided:
//! - `FastBlockChecksum` — 64-bit FNV-1a variant, used for runtime integrity
//!   verification of content chunks in the local filesystem.
//! - `ProductionBlockChecksum` — BLAKE3-256, for cryptographic production
//!   integrity assurance (root authentication, long-term verification).

use tidefs_local_object_store::{checksum64, IntegrityDigest64, ProductionIntegrityDigest};

/// Trait for block-level checksum computation and verification.
///
/// Implementations range from fast runtime checksums (FNV-64) to
/// cryptographic production integrity digests (BLAKE3-256).
pub trait BlockChecksum {
    /// The digest type produced by this checksum.
    type Digest: Clone + Eq + core::fmt::Debug;

    #[allow(dead_code)] // INTENT: checksum traits for planned block-level integrity verification
    /// Length of the digest in bytes.
    const DIGEST_LEN: usize;

    /// Compute a checksum for `data`.
    fn compute(data: &[u8]) -> Self::Digest;

    #[allow(dead_code)] // INTENT: checksum traits for planned block-level integrity verification
    /// Verify that `data` produces the expected digest.
    fn verify(data: &[u8], expected: &Self::Digest) -> bool;
}

/// Fast 64-bit integrity checksum (FNV-1a variant).
///
/// Used for runtime integrity verification of content chunks and inline data
/// blocks. Not cryptographically strong — designed for corruption detection
/// with minimal CPU overhead.
pub struct FastBlockChecksum;

impl BlockChecksum for FastBlockChecksum {
    type Digest = IntegrityDigest64;

    const DIGEST_LEN: usize = 8;

    fn compute(data: &[u8]) -> IntegrityDigest64 {
        checksum64(data)
    }

    fn verify(data: &[u8], expected: &IntegrityDigest64) -> bool {
        checksum64(data) == *expected
    }
}

/// Cryptographic production integrity checksum (BLAKE3-256).
///
/// Used for root authentication and long-term production integrity
/// verification. Higher CPU cost than `FastBlockChecksum` but provides
/// strong cryptographic guarantees.
pub struct ProductionBlockChecksum;

impl BlockChecksum for ProductionBlockChecksum {
    type Digest = ProductionIntegrityDigest;

    const DIGEST_LEN: usize = 32;

    fn compute(data: &[u8]) -> ProductionIntegrityDigest {
        let hash = blake3::hash(data);
        ProductionIntegrityDigest::from_bytes32(*hash.as_bytes())
    }

    fn verify(data: &[u8], expected: &ProductionIntegrityDigest) -> bool {
        let actual = Self::compute(data);
        actual.as_bytes32() == expected.as_bytes32()
    }
}

impl Checksummed for crate::records::ContentChunkRef {
    type Digest = IntegrityDigest64;

    fn checksum(&self) -> &IntegrityDigest64 {
        &self.checksum
    }
}

/// Trait for checksum-verified data that carries its own digest.
///
/// Types implementing this trait embed a checksum that was computed over
/// their serialized form, enabling self-verification.
pub trait Checksummed {
    /// The type of checksum digest used.
    type Digest: Clone + Eq;

    #[allow(dead_code)] // INTENT: checksum traits for planned block-level integrity verification
    /// Return the stored checksum digest.
    fn checksum(&self) -> &Self::Digest;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── FastBlockChecksum tests ────────────────────────────────────────

    #[test]
    fn fast_deterministic() {
        let data = b"hello world";
        let a = FastBlockChecksum::compute(data);
        let b = FastBlockChecksum::compute(data);
        assert_eq!(a, b, "same input must produce same checksum");
    }

    #[test]
    fn fast_different_inputs() {
        let a = FastBlockChecksum::compute(b"alpha");
        let b = FastBlockChecksum::compute(b"alphb");
        assert_ne!(a, b, "different inputs must produce different checksums");
    }

    #[test]
    fn fast_empty_input() {
        let digest = FastBlockChecksum::compute(b"");
        assert!(!digest.is_zero(), "empty input checksum should be non-zero");
    }

    #[test]
    fn fast_zero_input() {
        let digest = FastBlockChecksum::compute(&[0u8; 256]);
        assert!(!digest.is_zero());
    }

    #[test]
    fn fast_verify_correct() {
        let data = b"verify this payload";
        let digest = FastBlockChecksum::compute(data);
        assert!(FastBlockChecksum::verify(data, &digest));
    }

    #[test]
    fn fast_verify_incorrect() {
        let data = b"original data";
        let digest = FastBlockChecksum::compute(data);
        assert!(!FastBlockChecksum::verify(b"tampered data", &digest));
    }

    #[test]
    fn fast_corruption_detection_single_bit_flip() {
        let mut data = vec![0xAB; 256];
        let original = FastBlockChecksum::compute(&data);
        data[128] ^= 0x01;
        let corrupted = FastBlockChecksum::compute(&data);
        assert_ne!(original, corrupted, "single bit flip must be detected");
    }

    #[test]
    fn fast_corruption_detection_byte_zeroed() {
        let mut data = vec![0x42; 512];
        let original = FastBlockChecksum::compute(&data);
        data[200] = 0;
        let corrupted = FastBlockChecksum::compute(&data);
        assert_ne!(original, corrupted, "zeroing a byte must be detected");
    }

    #[test]
    fn fast_corruption_detection_truncation() {
        let data = vec![0xFF; 1024];
        let original = FastBlockChecksum::compute(&data);
        let truncated = &data[..1023];
        let corrupted = FastBlockChecksum::compute(truncated);
        assert_ne!(original, corrupted, "truncation must be detected");
    }

    #[test]
    fn fast_corruption_detection_extension() {
        let data = vec![0xFF; 1024];
        let original = FastBlockChecksum::compute(&data);
        let mut extended = data.clone();
        extended.push(0x00);
        let corrupted = FastBlockChecksum::compute(&extended);
        assert_ne!(original, corrupted, "extension must be detected");
    }

    #[test]
    fn fast_large_input() {
        let data = vec![0xAC; 1_048_576]; // 1 MiB
        let digest = FastBlockChecksum::compute(&data);
        assert!(!digest.is_zero());
    }

    #[test]
    fn fast_consistent_with_store_checksum64() {
        let data = b"cross-check with store";
        let via_trait = FastBlockChecksum::compute(data);
        let via_store = checksum64(data);
        assert_eq!(
            via_trait, via_store,
            "trait must produce same result as raw checksum64"
        );
    }

    // ── ProductionBlockChecksum tests ──────────────────────────────────

    #[test]
    fn production_deterministic() {
        let data = b"cryptographic integrity";
        let a = ProductionBlockChecksum::compute(data);
        let b = ProductionBlockChecksum::compute(data);
        assert_eq!(a.as_bytes32(), b.as_bytes32());
    }

    #[test]
    fn production_different_inputs() {
        let a = ProductionBlockChecksum::compute(b"alpha");
        let b = ProductionBlockChecksum::compute(b"beta");
        assert_ne!(a.as_bytes32(), b.as_bytes32());
    }

    #[test]
    fn production_empty_input() {
        let digest = ProductionBlockChecksum::compute(b"");
        let expected = blake3::hash(b"");
        assert_eq!(digest.as_bytes32(), *expected.as_bytes());
    }

    #[test]
    fn production_verify_correct() {
        let data = b"verify blake3";
        let digest = ProductionBlockChecksum::compute(data);
        assert!(ProductionBlockChecksum::verify(data, &digest));
    }

    #[test]
    fn production_verify_incorrect() {
        let data = b"original";
        let digest = ProductionBlockChecksum::compute(data);
        assert!(!ProductionBlockChecksum::verify(b"tampered", &digest));
    }

    #[test]
    fn production_corruption_detection() {
        let mut data = vec![0x5A; 512];
        let original = ProductionBlockChecksum::compute(&data);
        data[256] ^= 0x80;
        let corrupted = ProductionBlockChecksum::compute(&data);
        assert_ne!(original.as_bytes32(), corrupted.as_bytes32());
    }

    // ── Trait constants ────────────────────────────────────────────────

    #[test]
    fn fast_digest_len_is_8() {
        assert_eq!(FastBlockChecksum::DIGEST_LEN, 8);
    }

    #[test]
    fn production_digest_len_is_32() {
        assert_eq!(ProductionBlockChecksum::DIGEST_LEN, 32);
    }
}
