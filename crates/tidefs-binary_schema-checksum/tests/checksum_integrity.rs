// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Comprehensive checksum integrity tests for tidefs-binary_schema-checksum.
//!
//! Covers empty/single-byte/page-aligned/large payload round-trips,
//! bit-flip detection, truncation detection, zeroed-payload detection,
//! collision resistance, and deterministic output across all four
//! ChecksumProfile variants.

use tidefs_binary_schema_checksum::{
    blake3_domain_digest, crc32c, crc32c_verify, seal_checksums, verify_seal,
};
use tidefs_binary_schema_core::{
    ChecksumProfile, DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn default_domain() -> (SchemaFamilyId, SchemaTypeId, SchemaVersion, DomainTag) {
    (
        SchemaFamilyId(1),
        SchemaTypeId(42),
        SchemaVersion::new(1, 0),
        DomainTag::SectionBody,
    )
}

/// A profile that exercises both CRC32C and BLAKE3 paths.
const DUAL_PROFILE: ChecksumProfile = ChecksumProfile::Crc32cPlusBlake3_256;

// ---------------------------------------------------------------------------
// 1. empty_payload_checksum_round_trip
// ---------------------------------------------------------------------------

#[test]
fn empty_payload_checksum_round_trip() {
    let (fam, typ, ver, tag) = default_domain();
    let data: &[u8] = b"";

    for profile in [
        ChecksumProfile::None,
        ChecksumProfile::Crc32c,
        ChecksumProfile::Blake3_256,
        ChecksumProfile::Crc32cPlusBlake3_256,
    ] {
        let ticket = seal_checksums(data, profile, fam, typ, ver, tag);
        verify_seal(data, &ticket, fam, typ, ver, tag)
            .expect("empty payload must verify under all profiles");

        // CRC32C of empty data is 0.
        if profile == ChecksumProfile::Crc32c || profile == ChecksumProfile::Crc32cPlusBlake3_256 {
            assert_eq!(crc32c(data), 0);
            let csum_bytes = ticket.crc32c_bytes.expect("crc32c bytes present");
            assert_eq!(csum_bytes, 0u32.to_le_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// 2. single_byte_round_trip
// ---------------------------------------------------------------------------

#[test]
fn single_byte_round_trip() {
    let (fam, typ, ver, tag) = default_domain();
    let data: &[u8] = &[0x42];

    for profile in [
        ChecksumProfile::Crc32c,
        ChecksumProfile::Blake3_256,
        ChecksumProfile::Crc32cPlusBlake3_256,
    ] {
        let ticket = seal_checksums(data, profile, fam, typ, ver, tag);
        verify_seal(data, &ticket, fam, typ, ver, tag).expect("single-byte payload must verify");

        // The ticket must carry the expected profile fields.
        match profile {
            ChecksumProfile::Crc32c => {
                assert!(ticket.crc32c_bytes.is_some());
                assert!(ticket.blake3_bytes.is_none());
            }
            ChecksumProfile::Blake3_256 => {
                assert!(ticket.crc32c_bytes.is_none());
                assert!(ticket.blake3_bytes.is_some());
            }
            ChecksumProfile::Crc32cPlusBlake3_256 => {
                assert!(ticket.crc32c_bytes.is_some());
                assert!(ticket.blake3_bytes.is_some());
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// 3. page_aligned_round_trip
// ---------------------------------------------------------------------------

#[test]
fn page_aligned_round_trip() {
    let (fam, typ, ver, tag) = default_domain();
    let data = vec![0xABu8; 4096];

    let ticket = seal_checksums(&data, DUAL_PROFILE, fam, typ, ver, tag);
    verify_seal(&data, &ticket, fam, typ, ver, tag).expect("4096-byte page payload must verify");
}

// ---------------------------------------------------------------------------
// 4. large_payload_round_trip
// ---------------------------------------------------------------------------

#[test]
fn large_payload_round_trip() {
    let (fam, typ, ver, tag) = default_domain();
    let data = vec![0xCDu8; 1024 * 1024]; // 1 MiB

    let ticket = seal_checksums(&data, DUAL_PROFILE, fam, typ, ver, tag);
    verify_seal(&data, &ticket, fam, typ, ver, tag).expect("1 MiB payload must verify");
}

// ---------------------------------------------------------------------------
// 5. bit_flip_detection
// ---------------------------------------------------------------------------

#[test]
fn bit_flip_detection() {
    let (fam, typ, ver, tag) = default_domain();
    let data = b"payload for bit-flip test";

    let ticket = seal_checksums(data, DUAL_PROFILE, fam, typ, ver, tag);

    // Flip bits at various positions and verify every one is detected.
    for flip_pos in [0, data.len() / 2, data.len() - 1] {
        let mut corrupted = data.to_vec();
        corrupted[flip_pos] ^= 0x01;
        assert!(
            verify_seal(&corrupted, &ticket, fam, typ, ver, tag).is_err(),
            "bit flip at position {flip_pos} must be detected"
        );
    }

    // Flip bits in the CRC32C field only, not the payload — verify still rejects
    // when the blake3 portion is intact (Crc32cPlusBlake3_256 verifies both).
    let mut bad_crc32c = ticket.clone();
    if let Some(ref mut c) = bad_crc32c.crc32c_bytes {
        c[0] ^= 0x01;
    }
    assert!(
        verify_seal(data, &bad_crc32c, fam, typ, ver, tag).is_err(),
        "flipped crc32c byte must be detected"
    );

    // Flip bits in the BLAKE3 field only.
    let mut bad_blake3 = ticket.clone();
    if let Some(ref mut b) = bad_blake3.blake3_bytes {
        b[0] ^= 0x01;
    }
    assert!(
        verify_seal(data, &bad_blake3, fam, typ, ver, tag).is_err(),
        "flipped blake3 byte must be detected"
    );
}

// ---------------------------------------------------------------------------
// 6. truncated_frame_detection
// ---------------------------------------------------------------------------

#[test]
fn truncated_frame_detection() {
    let (fam, typ, ver, tag) = default_domain();
    let data = b"original payload for truncation test";

    let ticket = seal_checksums(data, DUAL_PROFILE, fam, typ, ver, tag);

    // Truncate the payload to various lengths below the original.
    for trunc_len in [0, 1, data.len() / 2, data.len() - 1] {
        let truncated = &data[..trunc_len];
        assert!(
            verify_seal(truncated, &ticket, fam, typ, ver, tag).is_err(),
            "truncated payload len={trunc_len} must be rejected"
        );
    }

    // Truncate CRC32C bytes field (set to None) when profile expects them.
    let mut ticket_no_crc = ticket.clone();
    ticket_no_crc.crc32c_bytes = None;
    assert!(
        verify_seal(data, &ticket_no_crc, fam, typ, ver, tag).is_err(),
        "missing crc32c bytes must be rejected"
    );

    // Truncate BLAKE3 bytes field (set to None).
    let mut ticket_no_blake3 = ticket.clone();
    ticket_no_blake3.blake3_bytes = None;
    assert!(
        verify_seal(data, &ticket_no_blake3, fam, typ, ver, tag).is_err(),
        "missing blake3 bytes must be rejected"
    );
}

// ---------------------------------------------------------------------------
// 7. zeroed_payload_detection
// ---------------------------------------------------------------------------

#[test]
fn zeroed_payload_detection() {
    let (fam, typ, ver, tag) = default_domain();
    let original = b"non-zero payload for zeroing test";

    let ticket = seal_checksums(original, DUAL_PROFILE, fam, typ, ver, tag);

    // Zero the entire payload.
    let zeroed = vec![0u8; original.len()];
    assert!(
        verify_seal(&zeroed, &ticket, fam, typ, ver, tag).is_err(),
        "fully zeroed payload must be rejected"
    );

    // Zero a single byte at start, middle, and end.
    for pos in [0, original.len() / 2, original.len() - 1] {
        let mut partially_zeroed = original.to_vec();
        partially_zeroed[pos] = 0x00;
        assert!(
            verify_seal(&partially_zeroed, &ticket, fam, typ, ver, tag).is_err(),
            "zeroed byte at position {pos} must be detected"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. checksum_collision_resistance
// ---------------------------------------------------------------------------

#[test]
fn checksum_collision_resistance() {
    let (fam, typ, ver, tag) = default_domain();

    // Two payloads that differ by exactly one byte must produce different
    // CRC32C values, different BLAKE3 digests, and different seal tickets.
    let payload_a = b"collision resistance test payload AAAAA";
    let mut payload_b = payload_a.to_vec();
    let last = payload_b.len() - 1;
    payload_b[last] ^= 0x01;

    // CRC32C collision resistance.
    let crc_a = crc32c(payload_a);
    let crc_b = crc32c(&payload_b);
    assert_ne!(
        crc_a, crc_b,
        "CRC32C must differ for 1-byte-different payloads"
    );

    // BLAKE3 domain collision resistance.
    let blake_a = blake3_domain_digest(payload_a, fam, typ, ver, tag);
    let blake_b = blake3_domain_digest(&payload_b, fam, typ, ver, tag);
    assert_ne!(
        blake_a, blake_b,
        "BLAKE3 must differ for 1-byte-different payloads"
    );

    // Seal ticket collision resistance.
    let ticket_a = seal_checksums(payload_a, DUAL_PROFILE, fam, typ, ver, tag);
    let ticket_b = seal_checksums(&payload_b, DUAL_PROFILE, fam, typ, ver, tag);
    assert_ne!(
        ticket_a.crc32c_bytes, ticket_b.crc32c_bytes,
        "seal crc32c must differ"
    );
    assert_ne!(
        ticket_a.blake3_bytes, ticket_b.blake3_bytes,
        "seal blake3 must differ"
    );
    assert_ne!(ticket_a, ticket_b, "seal tickets must differ");

    // Cross-verify: ticket_a must not verify payload_b.
    assert!(
        verify_seal(&payload_b, &ticket_a, fam, typ, ver, tag).is_err(),
        "seal from payload_a must not verify payload_b"
    );
    assert!(
        verify_seal(payload_a, &ticket_b, fam, typ, ver, tag).is_err(),
        "seal from payload_b must not verify payload_a"
    );
}

// ---------------------------------------------------------------------------
// 9. deterministic_output
// ---------------------------------------------------------------------------

#[test]
fn deterministic_output() {
    let (fam, typ, ver, tag) = default_domain();
    let data = b"deterministic output test payload";

    // CRC32C determinism.
    let crc1 = crc32c(data);
    let crc2 = crc32c(data);
    assert_eq!(crc1, crc2, "CRC32C must be deterministic");
    crc32c_verify(data, &crc1.to_le_bytes()).expect("CRC32C self-verify must pass");

    // BLAKE3 domain determinism.
    let blake1 = blake3_domain_digest(data, fam, typ, ver, tag);
    let blake2 = blake3_domain_digest(data, fam, typ, ver, tag);
    assert_eq!(blake1, blake2, "BLAKE3 must be deterministic");

    // Seal determinism across all profiles.
    for profile in [
        ChecksumProfile::None,
        ChecksumProfile::Crc32c,
        ChecksumProfile::Blake3_256,
        ChecksumProfile::Crc32cPlusBlake3_256,
    ] {
        let ticket1 = seal_checksums(data, profile, fam, typ, ver, tag);
        let ticket2 = seal_checksums(data, profile, fam, typ, ver, tag);
        assert_eq!(
            ticket1, ticket2,
            "seal must be deterministic for profile {profile:?}"
        );
    }
}
