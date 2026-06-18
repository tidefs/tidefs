// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Integration tests: property-based harness using proptest.
// Verifies:
//  - Valid headers survive encode→decode round-trip byte-for-byte.
//  - Multiple messages encoded in sequence decode to correct ordered messages.
//  - Arbitrary/malformed byte sequences fed to every public decode entry
//    point never panic — only Ok(decoded) or Err(well_typed).
//  - Corrupted valid frames are detected gracefully (no panic).
//  - Targeted edge cases: short input, discriminant overflows, all-zero /
//    all-0xFF buffers, multi-byte CRC corruption, misaligned offsets,
//    payload overflow.
//
// When the `fuzz` feature is enabled, iteration counts are raised to 1M
// and vector sizes are increased to the full 0..64 KiB range for CI
// nightly runs with `-Zsanitizer=address`.

use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;
use tidefs_binary_schema_core::{
    ChecksumProfile, ChunkFrameSizeClass, PayloadClass, SchemaFamilyId, SchemaTypeId,
    SchemaVersion, BINARY_SCHEMA_MAGIC,
};
use tidefs_binary_schema_framing::{ChunkFrameHeader, EnvelopeHeader, SectionHeader};

// ── Iteration counts & size caps ──────────────────────────────────────

#[cfg(not(feature = "fuzz"))]
const DEFAULT_CASES: u32 = 10_000;

#[cfg(feature = "fuzz")]
const DEFAULT_CASES: u32 = 1_000_000;

/// Max byte-vec length for arbitrary-slice fuzz (non-fuzz mode).
#[cfg(not(feature = "fuzz"))]
const SLICE_FUZZ_MAX_BYTES: usize = 512;

/// Max byte-vec length for arbitrary-slice fuzz (fuzz mode).
#[cfg(feature = "fuzz")]
const SLICE_FUZZ_MAX_BYTES: usize = 64 * 1024;

fn proptest_config() -> ProptestConfig {
    ProptestConfig::with_cases(DEFAULT_CASES)
}

// ── Strategy helpers for valid headers ────────────────────────────────

fn arb_checksum_profile() -> impl Strategy<Value = ChecksumProfile> {
    prop_oneof![
        Just(ChecksumProfile::None),
        Just(ChecksumProfile::Crc32c),
        Just(ChecksumProfile::Blake3_256),
        Just(ChecksumProfile::Crc32cPlusBlake3_256),
    ]
}

fn arb_schema_version() -> impl Strategy<Value = SchemaVersion> {
    (0u16..10u16, 0u16..10u16).prop_map(|(major, minor)| SchemaVersion::new(major, minor))
}

fn arb_envelope_header() -> impl Strategy<Value = EnvelopeHeader> {
    (
        any::<u64>(),
        any::<u64>(),
        arb_schema_version(),
        any::<u32>(),
        any::<u16>(),
        any::<u64>(),
        arb_checksum_profile(),
        arb_checksum_profile(),
        any::<u64>(),
    )
        .prop_map(
            |(
                family_id,
                type_id,
                version,
                flags,
                section_count,
                total_body_bytes,
                fast,
                strong,
                fingerprint,
            )| {
                EnvelopeHeader {
                    magic: BINARY_SCHEMA_MAGIC,
                    family_id: SchemaFamilyId(family_id),
                    type_id: SchemaTypeId(type_id),
                    version,
                    flags,
                    section_count,
                    total_body_bytes,
                    fast_checksum_profile: fast,
                    strong_digest_profile: strong,
                    schema_fingerprint_low: fingerprint,
                    header_crc32c: 0,
                }
            },
        )
}

fn arb_section_header() -> impl Strategy<Value = SectionHeader> {
    (
        prop::collection::vec(0u64..(u64::MAX >> 3), 1..2),
        any::<u64>(),
        any::<u16>(),
        any::<u32>(),
    )
        .prop_map(|(offset_vec, length, flags, omask)| SectionHeader {
            section_offset: offset_vec[0] * 8,
            section_length: length,
            payload_class: PayloadClass::FixedInline,
            section_flags: flags,
            optional_mask: omask,
        })
}

fn arb_chunk_frame_header() -> impl Strategy<Value = ChunkFrameHeader> {
    (
        any::<u64>(),
        0u64..(64 * 1024 + 1),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(
            |(frame_index, payload_bytes, crc, digest_marker)| ChunkFrameHeader {
                frame_index,
                payload_bytes,
                frame_size_class: ChunkFrameSizeClass::KiB64,
                payload_crc32c: crc,
                digest_continuation_marker: digest_marker,
            },
        )
}

// ── Proptests ─────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(proptest_config())]

    // ── Valid-header round-trip ─────────────────────────────────────

    #[test]
    fn proptest_envelope_roundtrip(header in arb_envelope_header()) {
        let enc = header.encode();
        let dec = EnvelopeHeader::decode(&enc).expect("proptest envelope decode");
        assert_eq!(dec.magic, header.magic);
        assert_eq!(dec.family_id, header.family_id);
        assert_eq!(dec.type_id, header.type_id);
        assert_eq!(dec.version, header.version);
        assert_eq!(dec.flags, header.flags);
        assert_eq!(dec.section_count, header.section_count);
        assert_eq!(dec.total_body_bytes, header.total_body_bytes);
        assert_eq!(dec.fast_checksum_profile, header.fast_checksum_profile);
        assert_eq!(dec.strong_digest_profile, header.strong_digest_profile);
        assert_eq!(dec.schema_fingerprint_low, header.schema_fingerprint_low);
    }

    #[test]
    fn proptest_section_roundtrip(sec in arb_section_header()) {
        let enc = sec.encode();
        let dec = SectionHeader::decode(&enc).expect("proptest section decode");
        assert_eq!(dec, sec);
    }

    #[test]
    fn proptest_chunk_frame_roundtrip(frame in arb_chunk_frame_header()) {
        let enc = frame.encode();
        let dec = ChunkFrameHeader::decode(&enc).expect("proptest chunk frame decode");
        assert_eq!(dec, frame);
    }

    #[test]
    fn proptest_encode_determinism_envelope(header in arb_envelope_header()) {
        let enc1 = header.encode();
        let enc2 = header.encode();
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn proptest_encode_determinism_section(sec in arb_section_header()) {
        let enc1 = sec.encode();
        let enc2 = sec.encode();
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn proptest_encode_determinism_chunk_frame(frame in arb_chunk_frame_header()) {
        let enc1 = frame.encode();
        let enc2 = frame.encode();
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn proptest_multi_envelope_roundtrip(
        headers in prop::collection::vec(arb_envelope_header(), 0..20)
    ) {
        for (i, header) in headers.iter().enumerate() {
            let enc = header.encode();
            let dec = EnvelopeHeader::decode(&enc)
                .unwrap_or_else(|e| panic!("decode envelope {i}: {e:?}"));
            assert_eq!(dec.family_id, header.family_id, "mismatch at index {i}");
            assert_eq!(dec.type_id, header.type_id, "mismatch at index {i}");
        }
    }

    #[test]
    fn proptest_multi_chunk_frame_roundtrip(
        frames in prop::collection::vec(arb_chunk_frame_header(), 0..20)
    ) {
        for (i, frame) in frames.iter().enumerate() {
            let enc = frame.encode();
            let dec = ChunkFrameHeader::decode(&enc)
                .unwrap_or_else(|e| panic!("decode chunk frame {i}: {e:?}"));
            assert_eq!(dec, *frame, "mismatch at index {i}");
        }
    }

    #[test]
    fn proptest_envelope_crc_verifies(header in arb_envelope_header()) {
        let enc = header.encode();
        EnvelopeHeader::decode(&enc).expect("CRC must verify for any valid header");
    }

    // ── Single-byte corruption detection ────────────────────────────

    #[test]
    fn proptest_corrupted_envelope_detected(
        header in arb_envelope_header(),
        byte_idx in 0usize..60,
    ) {
        let mut enc = header.encode();
        enc[byte_idx] ^= 0xFF;
        assert!(
            EnvelopeHeader::decode(&enc).is_err(),
            "corrupted envelope must be rejected"
        );
    }

    // ── Arbitrary byte-sequence fuzz (malformed input → no panic) ────

    #[test]
    fn proptest_arbitrary_64b_envelope_decode(raw in any::<[u8; 64]>()) {
        let _ = EnvelopeHeader::decode(&raw);
    }

    #[test]
    fn proptest_arbitrary_32b_section_decode(raw in any::<[u8; 32]>()) {
        let _ = SectionHeader::decode(&raw);
    }

    #[test]
    fn proptest_arbitrary_32b_chunk_frame_decode(raw in any::<[u8; 32]>()) {
        let _ = ChunkFrameHeader::decode(&raw);
    }

    #[test]
    fn proptest_arbitrary_slice_decode_from_slice(
        raw in prop::collection::vec(any::<u8>(), 0..SLICE_FUZZ_MAX_BYTES)
    ) {
        let _ = EnvelopeHeader::decode_from_slice(&raw);
    }

    // ── Mutate-valid-frame: multi-byte corruption must not panic ──────

    #[test]
    fn proptest_mutate_valid_envelope_multi_flip(
        header in arb_envelope_header(),
        flips in prop::collection::vec(0usize..64, 0..16)
    ) {
        let mut enc = header.encode();
        for &idx in &flips {
            enc[idx] ^= 0xFF;
        }
        let _ = EnvelopeHeader::decode(&enc);
    }

    #[test]
    fn proptest_mutate_valid_section_multi_flip(
        sec in arb_section_header(),
        flips in prop::collection::vec(0usize..32, 0..8)
    ) {
        let mut enc = sec.encode();
        for &idx in &flips {
            enc[idx] ^= 0xFF;
        }
        let _ = SectionHeader::decode(&enc);
    }

    #[test]
    fn proptest_mutate_valid_chunk_frame_multi_flip(
        frame in arb_chunk_frame_header(),
        flips in prop::collection::vec(0usize..32, 0..8)
    ) {
        let mut enc = frame.encode();
        for &idx in &flips {
            enc[idx] ^= 0xFF;
        }
        let _ = ChunkFrameHeader::decode(&enc);
    }

    // ── Targeted edge cases ──────────────────────────────────────────

    #[test]
    fn proptest_slice_short_lengths(len in 0usize..64) {
        let buf = vec![0u8; len];
        assert!(
            EnvelopeHeader::decode_from_slice(&buf).is_err(),
            "len={len} should be rejected by decode_from_slice"
        );
    }

    #[test]
    fn proptest_all_one_byte_values_envelope(byte_val in any::<u8>()) {
        let buf = [byte_val; 64];
        let _ = EnvelopeHeader::decode(&buf);
    }

    #[test]
    fn proptest_all_one_byte_values_section(byte_val in any::<u8>()) {
        let buf = [byte_val; 32];
        let _ = SectionHeader::decode(&buf);
    }

    #[test]
    fn proptest_all_one_byte_values_chunk_frame(byte_val in any::<u8>()) {
        let buf = [byte_val; 32];
        let _ = ChunkFrameHeader::decode(&buf);
    }

    #[test]
    fn proptest_section_discriminant_fuzz(pc_disc in any::<u16>()) {
        let mut buf = SectionHeader::default().encode();
        buf[16..18].copy_from_slice(&pc_disc.to_le_bytes());
        let _ = SectionHeader::decode(&buf);
    }

    #[test]
    fn proptest_chunk_frame_discriminant_fuzz(fsc_disc in any::<u16>()) {
        let mut buf = ChunkFrameHeader::default().encode();
        buf[16..18].copy_from_slice(&fsc_disc.to_le_bytes());
        let _ = ChunkFrameHeader::decode(&buf);
    }

    #[test]
    fn proptest_envelope_profile_discriminant_fuzz(profile_byte in any::<u8>()) {
        let header = EnvelopeHeader::default();
        let mut enc = header.encode();
        enc[40] = profile_byte;
        let _ = EnvelopeHeader::decode(&enc);
    }

    #[test]
    fn proptest_envelope_strong_profile_discriminant_fuzz(
        fast_byte in any::<u8>(),
        strong_byte in any::<u8>(),
    ) {
        let header = EnvelopeHeader::default();
        let mut enc = header.encode();
        enc[40] = fast_byte;
        enc[41] = strong_byte;
        let _ = EnvelopeHeader::decode(&enc);
    }

    #[test]
    fn proptest_section_offset_misalignment(
        offset_mod_8 in (0u64..8).prop_filter(
            "skip well-aligned offsets to test misalignment",
            |&v| v != 0
        ),
    ) {
        let mut buf = SectionHeader::default().encode();
        buf[0..8].copy_from_slice(&offset_mod_8.to_le_bytes());
        // Must error: either AlignmentViolation or InvalidPayloadClass
        // (default pc_disc might be valid, so could be either).
        assert!(
            SectionHeader::decode(&buf).is_err(),
            "misaligned offset {offset_mod_8} must be rejected"
        );
    }

    #[test]
    fn proptest_chunk_frame_payload_overflow(payload_bytes in (64 * 1024 + 1)..u64::MAX) {
        let mut buf = ChunkFrameHeader::default().encode();
        buf[8..16].copy_from_slice(&payload_bytes.to_le_bytes());
        assert!(
            ChunkFrameHeader::decode(&buf).is_err(),
            "oversize payload {payload_bytes} must be rejected"
        );
    }
}
