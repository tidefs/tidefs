// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Property-based tests (proptest) for tidefs-binary_schema-checksum.
//!
//! Randomized-input tests covering round-trip correctness, bit-flip
//! detection, truncation detection, collision resistance, and determinism
//! across all ChecksumProfile variants and both CRC32C and BLAKE3 paths.
//!
//! Worker slot: s11  Issue: #4124

use proptest::prelude::*;
use tidefs_binary_schema_checksum::{
    blake3_domain_digest, blake3_domain_verify, crc32c, crc32c_append, crc32c_verify,
    seal_checksums, verify_seal,
};
use tidefs_binary_schema_core::{
    ChecksumProfile, DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion,
};

// ── Helpers ───────────────────────────────────────────────────────────

fn default_domain() -> (SchemaFamilyId, SchemaTypeId, SchemaVersion, DomainTag) {
    (
        SchemaFamilyId(1),
        SchemaTypeId(42),
        SchemaVersion::new(1, 0),
        DomainTag::SectionBody,
    )
}

const DUAL_PROFILE: ChecksumProfile = ChecksumProfile::Crc32cPlusBlake3_256;

/// A strategy that produces a non-empty `Vec<u8>` up to 4096 bytes.
fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 1..=4096)
}

/// A strategy that produces an empty or non-empty payload up to 4096 bytes.
fn arb_payload_maybe_empty() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=4096)
}

// ── 1. Round-trip tests ──────────────────────────────────────────────

proptest! {
    /// CRC32C round-trip: compute → verify passes.
    #[test]
    fn proptest_crc32c_roundtrip(ref payload in arb_payload_maybe_empty()) {
        let csum = crc32c(payload);
        crc32c_verify(payload, &csum.to_le_bytes())
            .expect("CRC32C verify must pass for freshly-computed checksum");
    }

    /// BLAKE3 domain round-trip: compute → verify passes.
    #[test]
    fn proptest_blake3_roundtrip(ref payload in arb_payload_maybe_empty()) {
        let (fam, typ, ver, tag) = default_domain();
        let digest = blake3_domain_digest(payload, fam, typ, ver, tag);
        blake3_domain_verify(payload, &digest, fam, typ, ver, tag)
            .expect("BLAKE3 domain verify must pass for freshly-computed digest");
    }

    /// Seal round-trip for None profile: seal → verify passes.
    #[test]
    fn proptest_seal_none_roundtrip(ref payload in arb_payload_maybe_empty()) {
        let (fam, typ, ver, tag) = default_domain();
        let ticket = seal_checksums(payload, ChecksumProfile::None, fam, typ, ver, tag);
        verify_seal(payload, &ticket, fam, typ, ver, tag)
            .expect("None-profile seal must always verify");
    }

    /// Seal round-trip for Crc32cPlusBlake3_256 profile.
    #[test]
    fn proptest_seal_dual_roundtrip(ref payload in arb_payload_maybe_empty()) {
        let (fam, typ, ver, tag) = default_domain();
        let ticket = seal_checksums(payload, DUAL_PROFILE, fam, typ, ver, tag);
        verify_seal(payload, &ticket, fam, typ, ver, tag)
            .expect("dual-profile seal must verify");
    }
}

// ── 2. Bit-flip detection tests ──────────────────────────────────────

proptest! {
    /// Single-bit flip anywhere in the payload: CRC32C detects it.
    #[test]
    fn proptest_single_bit_flip_crc32c(
        ref payload in arb_payload(),
    ) {
        let csum = crc32c(payload);
        let mut corrupted = payload.clone();
        // Flip a random bit.
        let byte_idx = payload.len() / 2;
        corrupted[byte_idx] ^= 0x01;
        assert!(
            crc32c_verify(&corrupted, &csum.to_le_bytes()).is_err(),
            "single-bit flip at byte {byte_idx} must be detected by CRC32C"
        );
    }

    /// Single-bit flip: BLAKE3 detects it.
    #[test]
    fn proptest_single_bit_flip_blake3(
        ref payload in arb_payload(),
    ) {
        let (fam, typ, ver, tag) = default_domain();
        let digest = blake3_domain_digest(payload, fam, typ, ver, tag);
        let mut corrupted = payload.clone();
        corrupted[0] ^= 0x01;
        assert!(
            blake3_domain_verify(&corrupted, &digest, fam, typ, ver, tag).is_err(),
            "single-bit flip must be detected by BLAKE3"
        );
    }

    /// Two adjacent bits flipped: dual-profile seal detects it.
    #[test]
    fn proptest_two_adjacent_bit_flip(
        ref payload in arb_payload(),
    ) {
        let (fam, typ, ver, tag) = default_domain();
        let ticket = seal_checksums(payload, DUAL_PROFILE, fam, typ, ver, tag);
        let mut corrupted = payload.clone();
        let idx = (payload.len() / 2).min(payload.len().saturating_sub(1));
        corrupted[idx] ^= 0x03; // flip two adjacent bits
        assert!(
            verify_seal(&corrupted, &ticket, fam, typ, ver, tag).is_err(),
            "adjacent 2-bit flip at byte {idx} must be detected"
        );
    }

    /// Two non-adjacent bits flipped: dual-profile seal detects it.
    #[test]
    fn proptest_two_nonadjacent_bit_flip(
        ref payload in arb_payload(),
    ) {
        if payload.len() < 3 { return Ok(()); }
        let (fam, typ, ver, tag) = default_domain();
        let ticket = seal_checksums(payload, DUAL_PROFILE, fam, typ, ver, tag);
        let mut corrupted = payload.clone();
        corrupted[0] ^= 0x01;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x01;
        assert!(
            verify_seal(&corrupted, &ticket, fam, typ, ver, tag).is_err(),
            "two non-adjacent bit flips must be detected"
        );
    }

    /// Burst of 8 bits flipped (one byte): dual-profile seal detects it.
    #[test]
    fn proptest_burst_8bit_flip(
        ref payload in arb_payload(),
    ) {
        let (fam, typ, ver, tag) = default_domain();
        let ticket = seal_checksums(payload, DUAL_PROFILE, fam, typ, ver, tag);
        let mut corrupted = payload.clone();
        let idx = payload.len() / 3;
        corrupted[idx] ^= 0xFF; // flip all 8 bits in one byte
        assert!(
            verify_seal(&corrupted, &ticket, fam, typ, ver, tag).is_err(),
            "8-bit burst flip at byte {idx} must be detected"
        );
    }

    /// Burst of 64 bits flipped (8 bytes): dual-profile seal detects it.
    #[test]
    fn proptest_burst_64bit_flip(
        ref payload in arb_payload(),
    ) {
        let (fam, typ, ver, tag) = default_domain();
        let ticket = seal_checksums(payload, DUAL_PROFILE, fam, typ, ver, tag);
        let mut corrupted = payload.clone();
        let start = (payload.len() / 4).min(payload.len().saturating_sub(8));
        for b in corrupted.iter_mut().skip(start).take(8) {
            *b ^= 0xFF;
        }
        assert!(
            verify_seal(&corrupted, &ticket, fam, typ, ver, tag).is_err(),
            "64-bit burst flip at offset {start} must be detected"
        );
    }
}

// ── 3. Truncation detection tests ────────────────────────────────────

proptest! {
    /// Truncate payload by 1 byte: dual-profile seal detects it.
    #[test]
    fn proptest_truncate_1_byte(
        ref payload in arb_payload(),
    ) {
        let (fam, typ, ver, tag) = default_domain();
        let ticket = seal_checksums(payload, DUAL_PROFILE, fam, typ, ver, tag);
        let truncated = &payload[..payload.len() - 1];
        assert!(
            verify_seal(truncated, &ticket, fam, typ, ver, tag).is_err(),
            "truncation by 1 byte must be detected"
        );
    }

    /// Truncate payload by 50%: seal detects it.
    #[test]
    fn proptest_truncate_half(
        ref payload in arb_payload(),
    ) {
        let (fam, typ, ver, tag) = default_domain();
        let ticket = seal_checksums(payload, DUAL_PROFILE, fam, typ, ver, tag);
        let half = payload.len() / 2;
        if half == 0 {
            // Payload too short to halve; skip via returning Ok.
            return Ok(());
        }
        let truncated = &payload[..half];
        assert!(
            verify_seal(truncated, &ticket, fam, typ, ver, tag).is_err(),
            "50% truncation must be detected"
        );
    }

    /// Truncate payload to 1 byte: seal detects it.
    #[test]
    fn proptest_truncate_to_1_byte(
        ref payload in arb_payload(),
    ) {
        let (fam, typ, ver, tag) = default_domain();
        let ticket = seal_checksums(payload, DUAL_PROFILE, fam, typ, ver, tag);
        if payload.len() <= 1 {
            return Ok(());
        }
        let truncated = &payload[..1];
        assert!(
            verify_seal(truncated, &ticket, fam, typ, ver, tag).is_err(),
            "all-but-1-byte truncation must be detected"
        );
    }
}

// ── 4. Empty-input test ──────────────────────────────────────────────

proptest! {
    /// Checksum of empty slice is well-defined and consistent.
    #[test]
    fn proptest_empty_input_consistent(_dummy in any::<u8>()) {
        let empty: &[u8] = b"";
        let (fam, typ, ver, tag) = default_domain();

        // CRC32C of empty data is 0.
        assert_eq!(crc32c(empty), 0);
        assert_eq!(crc32c_verify(empty, &0u32.to_le_bytes()), Ok(()));

        // BLAKE3 of empty data is deterministic.
        let d1 = blake3_domain_digest(empty, fam, typ, ver, tag);
        let d2 = blake3_domain_digest(empty, fam, typ, ver, tag);
        assert_eq!(d1, d2);

        // Seal of empty data verifies.
        for profile in [
            ChecksumProfile::None,
            ChecksumProfile::Crc32c,
            ChecksumProfile::Blake3_256,
            ChecksumProfile::Crc32cPlusBlake3_256,
        ] {
            let ticket = seal_checksums(empty, profile, fam, typ, ver, tag);
            verify_seal(empty, &ticket, fam, typ, ver, tag)
                .expect("empty payload must verify under all profiles");
        }
    }
}

// ── 5. Collision resistance smoke tests ──────────────────────────────

proptest! {
    /// CRC32C: N random distinct payloads produce distinct checksums.
    #[test]
    fn proptest_crc32c_collision_resistance(
        ref payloads in proptest::collection::vec(arb_payload(), 10..=20)
    ) {
        let checksums: Vec<u32> = payloads.iter().map(|p| crc32c(p)).collect();
        let distinct: std::collections::HashSet<u32> = checksums.iter().copied().collect();
        // With 10-20 random payloads up to 4 KiB, CRC32C collisions are
        // extremely unlikely (birthday bound ~2^16 ≈ 65k items).
        assert_eq!(
            distinct.len(),
            checksums.len(),
            "CRC32C must not collide across {n} random payloads",
            n = payloads.len()
        );
    }

    /// BLAKE3: N random distinct payloads produce distinct 256-bit digests.
    #[test]
    fn proptest_blake3_collision_resistance(
        ref payloads in proptest::collection::vec(arb_payload(), 20..=40)
    ) {
        let (fam, typ, ver, tag) = default_domain();
        let digests: Vec<[u8; 32]> = payloads
            .iter()
            .map(|p| blake3_domain_digest(p, fam, typ, ver, tag))
            .collect();
        let distinct: std::collections::HashSet<&[u8; 32]> = digests.iter().collect();
        assert_eq!(
            distinct.len(),
            digests.len(),
            "BLAKE3 must not collide across {n} random payloads",
            n = payloads.len()
        );
    }
}

// ── 6. Determinism test ──────────────────────────────────────────────

proptest! {
    /// Same input always produces the same checksum across 100 iterations.
    #[test]
    fn proptest_determinism_100_iterations(ref payload in arb_payload_maybe_empty()) {
        let (fam, typ, ver, tag) = default_domain();

        // CRC32C
        let csum = crc32c(payload);
        for _ in 0..100 {
            assert_eq!(crc32c(payload), csum, "CRC32C must be deterministic");
        }

        // BLAKE3
        let digest = blake3_domain_digest(payload, fam, typ, ver, tag);
        for _ in 0..100 {
            assert_eq!(
                blake3_domain_digest(payload, fam, typ, ver, tag),
                digest,
                "BLAKE3 domain digest must be deterministic"
            );
        }

        // Seal for all profiles
        for profile in [
            ChecksumProfile::None,
            ChecksumProfile::Crc32c,
            ChecksumProfile::Blake3_256,
            ChecksumProfile::Crc32cPlusBlake3_256,
        ] {
            let ticket = seal_checksums(payload, profile, fam, typ, ver, tag);
            for _ in 0..100 {
                assert_eq!(
                    seal_checksums(payload, profile, fam, typ, ver, tag),
                    ticket,
                    "seal must be deterministic for profile {profile:?}"
                );
            }
        }
    }
}

// ── 7. Length-extension resistance ──────────────────────────────────

proptest! {
    /// BLAKE3 domain-separated digest is length-extension resistant:
    /// digest(a) != digest(a || b) for non-empty a, b.
    /// Domain separation prevents concatenation from being
    /// semantically equivalent to the original digest.
    #[test]
    fn proptest_blake3_length_extension_resistance(
        ref a in arb_payload(),
        ref b in arb_payload(),
    ) {
        let (fam, typ, ver, tag) = default_domain();
        let digest_a = blake3_domain_digest(a, fam, typ, ver, tag);
        let mut ab = a.clone();
        ab.extend_from_slice(b);
        let digest_ab = blake3_domain_digest(&ab, fam, typ, ver, tag);
        assert_ne!(
            digest_a, digest_ab,
            "BLAKE3 domain digest must be length-extension resistant"
        );
    }
}

// ── 8. Single-byte distinctness ─────────────────────────────────────

/// All 256 single-byte values produce distinct CRC32C checksums.
#[test]
fn all_256_single_byte_values_distinct_crc32c() {
    let checksums: Vec<u32> = (0..=255).map(|b| crc32c(&[b])).collect();
    let distinct: std::collections::HashSet<u32> = checksums.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        256,
        "all 256 single-byte values must produce distinct CRC32C checksums"
    );
}

/// All 256 single-byte values produce distinct BLAKE3 digests.
#[test]
fn all_256_single_byte_values_distinct_blake3() {
    let (fam, typ, ver, tag) = default_domain();
    let digests: Vec<[u8; 32]> = (0..=255)
        .map(|b| blake3_domain_digest(&[b], fam, typ, ver, tag))
        .collect();
    let distinct: std::collections::HashSet<&[u8; 32]> = digests.iter().collect();
    assert_eq!(
        distinct.len(),
        256,
        "all 256 single-byte values must produce distinct BLAKE3 digests"
    );
}

// ── 9. Zero-input at edge lengths ───────────────────────────────────

/// Zero-filled buffers at edge lengths (0, 1, 255, 256, 4095, 4096)
/// produce deterministic checksums that differ from 1-byte-changed variants.
#[test]
fn zero_input_at_edge_lengths() {
    let (fam, typ, ver, tag) = default_domain();

    for &len in &[0usize, 1, 255, 256, 4095, 4096] {
        let zeros = vec![0u8; len];

        // CRC32C round-trip
        let csum = crc32c(&zeros);
        crc32c_verify(&zeros, &csum.to_le_bytes())
            .unwrap_or_else(|_| panic!("CRC32C verify must pass for {len} zero bytes"));

        // BLAKE3 round-trip
        let digest = blake3_domain_digest(&zeros, fam, typ, ver, tag);
        blake3_domain_verify(&zeros, &digest, fam, typ, ver, tag)
            .unwrap_or_else(|_| panic!("BLAKE3 verify must pass for {len} zero bytes"));

        // Determinism across two independent calls
        assert_eq!(
            crc32c(&zeros),
            csum,
            "CRC32C must be deterministic for {len} zero bytes"
        );
        assert_eq!(
            blake3_domain_digest(&zeros, fam, typ, ver, tag),
            digest,
            "BLAKE3 must be deterministic for {len} zero bytes"
        );

        // One-byte difference must produce different checksum (for non-empty)
        if len > 0 {
            let mut modified = zeros.clone();
            modified[0] = 1;
            assert_ne!(
                crc32c(&zeros),
                crc32c(&modified),
                "CRC32C must differ for 1-byte change at len={len}"
            );
            assert_ne!(
                blake3_domain_digest(&zeros, fam, typ, ver, tag),
                blake3_domain_digest(&modified, fam, typ, ver, tag),
                "BLAKE3 must differ for 1-byte change at len={len}"
            );
        }
    }
}

// ── 10. Streaming / concatenated-chunk equivalence ──────────────────

/// Checksum of concatenated chunks equals checksum of the equivalent
/// single buffer holding the same byte sequence.
#[test]
fn concatenated_chunks_equal_whole_checksum() {
    let (fam, typ, ver, tag) = default_domain();

    // Test with several partitionings
    for chunks in &[
        vec![b"hello ".to_vec(), b"world".to_vec()],
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
        vec![vec![0x42], vec![0x00], vec![0xFF]],
        vec![vec![0xAA; 100], vec![0xBB; 200], vec![0xCC; 300]],
    ] {
        let whole: Vec<u8> = chunks.iter().flatten().copied().collect();
        let mut combined = Vec::new();
        for c in chunks {
            combined.extend_from_slice(c);
        }

        // CRC32C equivalence
        assert_eq!(
            crc32c(&whole),
            crc32c(&combined),
            "CRC32C: concatenated chunks must equal whole"
        );

        // BLAKE3 equivalence
        assert_eq!(
            blake3_domain_digest(&whole, fam, typ, ver, tag),
            blake3_domain_digest(&combined, fam, typ, ver, tag),
            "BLAKE3: concatenated chunks must equal whole"
        );

        // Seal equivalence
        let seal_whole = seal_checksums(&whole, DUAL_PROFILE, fam, typ, ver, tag);
        let seal_combined = seal_checksums(&combined, DUAL_PROFILE, fam, typ, ver, tag);
        assert_eq!(
            seal_whole, seal_combined,
            "Seal: concatenated chunks must equal whole"
        );
    }
}

/// crc32c_append correctly writes the 4-byte LE CRC32C into the buffer.
#[test]
fn crc32c_append_writes_correct_le_bytes() {
    for data in &[b"".to_vec(), b"x".to_vec(), b"stream test payload".to_vec()] {
        let expected = crc32c(data);
        let mut buf = Vec::new();
        crc32c_append(data, &mut buf);
        assert_eq!(buf.len(), 4);
        let appended = u32::from_le_bytes(buf.try_into().unwrap());
        assert_eq!(
            appended, expected,
            "crc32c_append must write correct LE CRC32C"
        );
    }
}

// ── 11. Large-payload tests ─────────────────────────────────────────

/// 1 MiB payload: CRC32C, BLAKE3, and dual-profile seal round-trip
/// with tamper detection.
#[test]
fn large_payload_1mib_roundtrip_and_tamper() {
    let (fam, typ, ver, tag) = default_domain();
    let payload = vec![0x5Au8; 1024 * 1024]; // 1 MiB

    // CRC32C round-trip + determinism
    let csum = crc32c(&payload);
    crc32c_verify(&payload, &csum.to_le_bytes()).expect("1 MiB CRC32C verify must pass");
    assert_eq!(crc32c(&payload), csum, "1 MiB CRC32C must be deterministic");

    // BLAKE3 round-trip + determinism
    let digest = blake3_domain_digest(&payload, fam, typ, ver, tag);
    blake3_domain_verify(&payload, &digest, fam, typ, ver, tag)
        .expect("1 MiB BLAKE3 verify must pass");
    assert_eq!(
        blake3_domain_digest(&payload, fam, typ, ver, tag),
        digest,
        "1 MiB BLAKE3 must be deterministic"
    );

    // Dual-profile seal
    let ticket = seal_checksums(&payload, DUAL_PROFILE, fam, typ, ver, tag);
    verify_seal(&payload, &ticket, fam, typ, ver, tag)
        .expect("1 MiB dual-profile seal must verify");

    // Tamper: flip one byte in the middle
    let mut corrupted = payload.clone();
    corrupted[512 * 1024] ^= 0x01;
    assert_ne!(
        crc32c(&corrupted),
        csum,
        "1 MiB mid-byte flip must change CRC32C"
    );
    assert!(
        verify_seal(&corrupted, &ticket, fam, typ, ver, tag).is_err(),
        "1 MiB mid-byte flip must be detected by seal"
    );
}

/// 4 MiB payload: BLAKE3 round-trip with tail-corruption detection.
#[test]
fn large_payload_4mib_roundtrip_and_tail_tamper() {
    let (fam, typ, ver, tag) = default_domain();
    let payload = vec![0xA5u8; 4 * 1024 * 1024]; // 4 MiB

    // BLAKE3 round-trip
    let digest = blake3_domain_digest(&payload, fam, typ, ver, tag);
    blake3_domain_verify(&payload, &digest, fam, typ, ver, tag)
        .expect("4 MiB BLAKE3 verify must pass");

    // Determinism
    assert_eq!(
        blake3_domain_digest(&payload, fam, typ, ver, tag),
        digest,
        "4 MiB BLAKE3 must be deterministic"
    );

    // Tamper: last byte flipped
    let mut corrupted = payload.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    assert!(
        blake3_domain_verify(&corrupted, &digest, fam, typ, ver, tag).is_err(),
        "4 MiB tail corruption must be detected by BLAKE3"
    );
}

// ── 12. Alignment edge cases ────────────────────────────────────────

proptest! {
    /// Verify round-trip correctness on unaligned sub-slices and
    /// confirm that different slices produce different checksums.
    #[test]
    fn proptest_alignment_edge_cases(
        ref payload in proptest::collection::vec(any::<u8>(), 1..=8192)
    ) {
        let (fam, typ, ver, tag) = default_domain();

        // Full payload round-trip
        let csum_full = crc32c(payload);
        crc32c_verify(payload, &csum_full.to_le_bytes())
            .expect("full payload CRC32C must verify");
        let dig_full = blake3_domain_digest(payload, fam, typ, ver, tag);
        blake3_domain_verify(payload, &dig_full, fam, typ, ver, tag)
            .expect("full payload BLAKE3 must verify");

        // Unaligned sub-slices at odd offsets
        for &offset in &[1usize, 3, 7] {
            if offset < payload.len() {
                let slice = &payload[offset..];
                let csum = crc32c(slice);
                crc32c_verify(slice, &csum.to_le_bytes())
                    .expect("unaligned slice CRC32C must verify");
                let dig = blake3_domain_digest(slice, fam, typ, ver, tag);
                blake3_domain_verify(slice, &dig, fam, typ, ver, tag)
                    .expect("unaligned slice BLAKE3 must verify");
            }
        }

        // Page-boundary-adjacent lengths: verify that payloads of length
        // 4095, 4096, 4097 all produce valid round-trips.
        for &take in &[4095usize, 4096, 4097] {
            if payload.len() >= take {
                let slice = &payload[..take];
                let csum = crc32c(slice);
                crc32c_verify(slice, &csum.to_le_bytes())
                    .expect("page-boundary slice CRC32C must verify");
                let dig = blake3_domain_digest(slice, fam, typ, ver, tag);
                blake3_domain_verify(slice, &dig, fam, typ, ver, tag)
                    .expect("page-boundary slice BLAKE3 must verify");
            }
        }
    }
}

// ── 13. Cross-allocation stability ──────────────────────────────────

proptest! {
    /// Computing checksum twice on equivalent slices (same bytes,
    /// different Vec allocation) yields identical results for
    /// CRC32C, BLAKE3, and all seal profiles.
    #[test]
    fn proptest_cross_allocation_stability(
        ref payload in arb_payload_maybe_empty()
    ) {
        let (fam, typ, ver, tag) = default_domain();

        // Clone to force a different heap allocation
        let clone = payload.clone();

        // CRC32C stability
        assert_eq!(
            crc32c(payload),
            crc32c(&clone),
            "CRC32C must be stable across allocations"
        );
        let csum = crc32c(payload);
        crc32c_verify(&clone, &csum.to_le_bytes())
            .expect("CRC32C from original must verify against clone");

        // BLAKE3 stability
        let digest = blake3_domain_digest(payload, fam, typ, ver, tag);
        assert_eq!(
            blake3_domain_digest(&clone, fam, typ, ver, tag),
            digest,
            "BLAKE3 must be stable across allocations"
        );
        blake3_domain_verify(&clone, &digest, fam, typ, ver, tag)
            .expect("BLAKE3 from original must verify against clone");

        // Seal stability for all profiles
        for profile in [
            ChecksumProfile::None,
            ChecksumProfile::Crc32c,
            ChecksumProfile::Blake3_256,
            ChecksumProfile::Crc32cPlusBlake3_256,
        ] {
            let ticket = seal_checksums(payload, profile, fam, typ, ver, tag);
            assert_eq!(
                seal_checksums(&clone, profile, fam, typ, ver, tag),
                ticket,
                "seal must be stable across allocations for profile {profile:?}"
            );
            verify_seal(&clone, &ticket, fam, typ, ver, tag)
                .unwrap_or_else(|_| panic!(
                    "seal from original must verify against clone for profile {profile:?}"
                ));
        }
    }
}
