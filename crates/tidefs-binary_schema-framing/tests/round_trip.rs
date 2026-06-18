// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Integration tests: message encode/decode round-trip for all three header
// types and the envelope builder.

use tidefs_binary_schema_core::{
    ChecksumProfile, ChunkFrameSizeClass, PayloadClass, SchemaFamilyId, SchemaTypeId,
    SchemaVersion, BINARY_SCHEMA_MAGIC,
};
use tidefs_binary_schema_framing::{
    ChunkFrameHeader, EnvelopeBuilder, EnvelopeHeader, SectionHeader,
};

// ── EnvelopeHeader round-trip ───────────────────────────────────────

#[test]
fn envelope_roundtrip_default() {
    let header = EnvelopeHeader::default();
    let enc = header.encode();
    let dec = EnvelopeHeader::decode(&enc).expect("decode default envelope");
    assert_eq!(dec.magic, BINARY_SCHEMA_MAGIC);
    assert_eq!(dec.family_id, SchemaFamilyId::default());
    assert_eq!(dec.type_id, SchemaTypeId::default());
    assert_eq!(dec.version, SchemaVersion::default());
    assert_eq!(dec.flags, 0);
    assert_eq!(dec.section_count, 0);
    assert_eq!(dec.total_body_bytes, 0);
    assert_eq!(dec.fast_checksum_profile, ChecksumProfile::None);
    assert_eq!(dec.strong_digest_profile, ChecksumProfile::None);
    assert_eq!(dec.schema_fingerprint_low, 0);
}

#[test]
fn envelope_roundtrip_non_default_fields() {
    let header = EnvelopeHeader {
        magic: BINARY_SCHEMA_MAGIC,
        family_id: SchemaFamilyId(42),
        type_id: SchemaTypeId(99),
        version: SchemaVersion::new(3, 7),
        flags: 0xBEEF,
        section_count: 5,
        total_body_bytes: 65536,
        fast_checksum_profile: ChecksumProfile::Crc32c,
        strong_digest_profile: ChecksumProfile::Blake3_256,
        schema_fingerprint_low: 0x1122334455667788,
        header_crc32c: 0,
    };
    let enc = header.encode();
    let dec = EnvelopeHeader::decode(&enc).expect("decode non-default envelope");
    assert_eq!(dec.family_id.0, 42);
    assert_eq!(dec.type_id.0, 99);
    assert_eq!(dec.version, SchemaVersion::new(3, 7));
    assert_eq!(dec.flags, 0xBEEF);
    assert_eq!(dec.section_count, 5);
    assert_eq!(dec.total_body_bytes, 65536);
    assert_eq!(dec.fast_checksum_profile, ChecksumProfile::Crc32c);
    assert_eq!(dec.strong_digest_profile, ChecksumProfile::Blake3_256);
    assert_eq!(dec.schema_fingerprint_low, 0x1122334455667788);
}

#[test]
fn envelope_roundtrip_max_section_count() {
    let header = EnvelopeHeader {
        section_count: u16::MAX,
        ..Default::default()
    };
    let enc = header.encode();
    let dec = EnvelopeHeader::decode(&enc).expect("decode max section_count");
    assert_eq!(dec.section_count, u16::MAX);
}

#[test]
fn envelope_roundtrip_max_body_bytes() {
    let header = EnvelopeHeader {
        total_body_bytes: u64::MAX,
        ..Default::default()
    };
    let enc = header.encode();
    let dec = EnvelopeHeader::decode(&enc).expect("decode max total_body_bytes");
    assert_eq!(dec.total_body_bytes, u64::MAX);
}

#[test]
fn envelope_roundtrip_max_fingerprint() {
    let header = EnvelopeHeader {
        schema_fingerprint_low: u64::MAX,
        ..Default::default()
    };
    let enc = header.encode();
    let dec = EnvelopeHeader::decode(&enc).expect("decode max fingerprint");
    assert_eq!(dec.schema_fingerprint_low, u64::MAX);
}

#[test]
fn envelope_roundtrip_all_checksum_profiles() {
    let profiles = [
        ChecksumProfile::None,
        ChecksumProfile::Crc32c,
        ChecksumProfile::Blake3_256,
        ChecksumProfile::Crc32cPlusBlake3_256,
    ];
    for &fast in &profiles {
        for &strong in &profiles {
            let header = EnvelopeHeader {
                fast_checksum_profile: fast,
                strong_digest_profile: strong,
                ..Default::default()
            };
            let enc = header.encode();
            let dec = EnvelopeHeader::decode(&enc).expect("decode with checksum profiles");
            assert_eq!(dec.fast_checksum_profile, fast);
            assert_eq!(dec.strong_digest_profile, strong);
        }
    }
}

#[test]
fn envelope_decode_from_slice_aligned() {
    let header = EnvelopeHeader::default();
    let enc = header.encode();
    // Place in an 8-byte aligned wrapper
    #[repr(C, align(8))]
    struct AlignedBuf([u8; 128]);
    let mut buf = AlignedBuf([0u8; 128]);
    buf.0[8..72].copy_from_slice(&enc);
    let result = EnvelopeHeader::decode_from_slice(&buf.0[8..72]);
    assert!(result.is_ok());
}

// ── EnvelopeBuilder round-trip ──────────────────────────────────────

#[test]
fn envelope_builder_roundtrip_minimal() {
    let builder = EnvelopeBuilder::new(
        SchemaFamilyId(1),
        SchemaTypeId(100),
        SchemaVersion::new(1, 0),
    );
    let header = builder.build(2, 2048);
    let enc = header.encode();
    let dec = EnvelopeHeader::decode(&enc).expect("decode builder-built envelope");
    assert_eq!(dec.family_id.0, 1);
    assert_eq!(dec.type_id.0, 100);
    assert_eq!(dec.section_count, 2);
    assert_eq!(dec.total_body_bytes, 2048);
    assert_eq!(dec.fast_checksum_profile, ChecksumProfile::Crc32c);
    assert_eq!(dec.strong_digest_profile, ChecksumProfile::Blake3_256);
}

#[test]
fn envelope_builder_full_chain() {
    let header = EnvelopeBuilder::new(
        SchemaFamilyId(7),
        SchemaTypeId(255),
        SchemaVersion::new(4, 2),
    )
    .with_flags(0xCAFE)
    .with_fingerprint_low(0xDEADBEEFCAFEBABE)
    .with_checksum_profiles(
        ChecksumProfile::Crc32cPlusBlake3_256,
        ChecksumProfile::Blake3_256,
    )
    .build(8, 1_048_576);

    let enc = header.encode();
    let dec = EnvelopeHeader::decode(&enc).expect("decode full-chain envelope");
    assert_eq!(dec.family_id.0, 7);
    assert_eq!(dec.type_id.0, 255);
    assert_eq!(dec.version, SchemaVersion::new(4, 2));
    assert_eq!(dec.flags, 0xCAFE);
    assert_eq!(dec.schema_fingerprint_low, 0xDEADBEEFCAFEBABE);
    assert_eq!(
        dec.fast_checksum_profile,
        ChecksumProfile::Crc32cPlusBlake3_256
    );
    assert_eq!(dec.strong_digest_profile, ChecksumProfile::Blake3_256);
    assert_eq!(dec.section_count, 8);
    assert_eq!(dec.total_body_bytes, 1_048_576);
}

// ── SectionHeader round-trip ────────────────────────────────────────

#[test]
fn section_roundtrip_default() {
    let sec = SectionHeader::default();
    let enc = sec.encode();
    let dec = SectionHeader::decode(&enc).expect("decode default section");
    assert_eq!(dec, sec);
}

#[test]
fn section_roundtrip_non_default() {
    let sec = SectionHeader {
        section_offset: 128,
        section_length: 4096,
        payload_class: PayloadClass::ChunkFramed,
        section_flags: 0x42,
        optional_mask: 0xDEADBEEF,
    };
    let enc = sec.encode();
    let dec = SectionHeader::decode(&enc).expect("decode non-default section");
    assert_eq!(dec, sec);
}

#[test]
fn section_roundtrip_zero_offset() {
    let sec = SectionHeader {
        section_offset: 0,
        section_length: 512,
        ..Default::default()
    };
    let enc = sec.encode();
    let dec = SectionHeader::decode(&enc).expect("decode zero-offset section");
    assert_eq!(dec.section_offset, 0);
    assert_eq!(dec.section_length, 512);
}

#[test]
fn section_roundtrip_max_values() {
    let sec = SectionHeader {
        section_offset: u64::MAX & !7, // aligned to 8 bytes
        section_length: u64::MAX,
        payload_class: PayloadClass::FixedInline,
        section_flags: u16::MAX,
        optional_mask: u32::MAX,
    };
    let enc = sec.encode();
    let dec = SectionHeader::decode(&enc).expect("decode max-values section");
    assert_eq!(dec.section_offset, u64::MAX & !7);
    assert_eq!(dec.section_length, u64::MAX);
    assert_eq!(dec.section_flags, u16::MAX);
    assert_eq!(dec.optional_mask, u32::MAX);
}

// ── ChunkFrameHeader round-trip ─────────────────────────────────────

#[test]
fn chunk_frame_roundtrip_default() {
    let frame = ChunkFrameHeader::default();
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).expect("decode default chunk frame");
    assert_eq!(dec, frame);
}

#[test]
fn chunk_frame_roundtrip_non_default() {
    let frame = ChunkFrameHeader {
        frame_index: 42,
        payload_bytes: 63 * 1024,
        frame_size_class: ChunkFrameSizeClass::KiB64,
        payload_crc32c: 0xABCD1234,
        digest_continuation_marker: 1,
    };
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).expect("decode non-default chunk frame");
    assert_eq!(dec, frame);
}

#[test]
fn chunk_frame_roundtrip_zero_payload() {
    let frame = ChunkFrameHeader {
        frame_index: 0,
        payload_bytes: 0,
        frame_size_class: ChunkFrameSizeClass::KiB64,
        payload_crc32c: 0,
        digest_continuation_marker: 0,
    };
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).expect("decode zero-payload chunk frame");
    assert_eq!(dec.payload_bytes, 0);
}

#[test]
fn chunk_frame_roundtrip_exact_class_limit_kib64() {
    let frame = ChunkFrameHeader {
        frame_index: 1,
        payload_bytes: 64 * 1024,
        frame_size_class: ChunkFrameSizeClass::KiB64,
        payload_crc32c: 0,
        digest_continuation_marker: 0,
    };
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).expect("decode KiB64 at limit");
    assert_eq!(dec.payload_bytes, 64 * 1024);
    assert_eq!(dec.frame_size_class, ChunkFrameSizeClass::KiB64);
}

#[test]
fn chunk_frame_roundtrip_exact_class_limit_kib256() {
    let frame = ChunkFrameHeader {
        frame_index: 2,
        payload_bytes: 256 * 1024,
        frame_size_class: ChunkFrameSizeClass::KiB256,
        payload_crc32c: 0,
        digest_continuation_marker: 0,
    };
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).expect("decode KiB256 at limit");
    assert_eq!(dec.payload_bytes, 256 * 1024);
}

#[test]
fn chunk_frame_roundtrip_exact_class_limit_mib1() {
    let frame = ChunkFrameHeader {
        frame_index: 3,
        payload_bytes: 1024 * 1024,
        frame_size_class: ChunkFrameSizeClass::MiB1,
        payload_crc32c: 0,
        digest_continuation_marker: 0,
    };
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).expect("decode MiB1 at limit");
    assert_eq!(dec.payload_bytes, 1024 * 1024);
}

#[test]
fn chunk_frame_roundtrip_max_frame_index() {
    let frame = ChunkFrameHeader {
        frame_index: u64::MAX,
        payload_bytes: 0,
        frame_size_class: ChunkFrameSizeClass::KiB64,
        payload_crc32c: u32::MAX,
        digest_continuation_marker: u32::MAX,
    };
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).expect("decode max-index chunk frame");
    assert_eq!(dec.frame_index, u64::MAX);
    assert_eq!(dec.payload_crc32c, u32::MAX);
    assert_eq!(dec.digest_continuation_marker, u32::MAX);
}

// ── Multi-message stream round-trip ─────────────────────────────────

#[test]
fn multi_message_stream_envelope_section_chunk() {
    // Encode three distinct headers in sequence; decode and verify each.
    let env = EnvelopeHeader {
        magic: BINARY_SCHEMA_MAGIC,
        family_id: SchemaFamilyId(10),
        type_id: SchemaTypeId(20),
        version: SchemaVersion::new(1, 1),
        flags: 0,
        section_count: 1,
        total_body_bytes: 64 * 1024,
        fast_checksum_profile: ChecksumProfile::Crc32c,
        strong_digest_profile: ChecksumProfile::Blake3_256,
        schema_fingerprint_low: 0,
        header_crc32c: 0,
    };
    let sec = SectionHeader {
        section_offset: 64,
        section_length: 64 * 1024,
        payload_class: PayloadClass::ChunkFramed,
        section_flags: 0,
        optional_mask: 0,
    };
    let chunk = ChunkFrameHeader {
        frame_index: 0,
        payload_bytes: 64 * 1024,
        frame_size_class: ChunkFrameSizeClass::KiB64,
        payload_crc32c: 0,
        digest_continuation_marker: 0,
    };

    let env_enc = env.encode();
    let sec_enc = sec.encode();
    let chunk_enc = chunk.encode();

    let dec_env = EnvelopeHeader::decode(&env_enc).expect("decode envelope in stream");
    let dec_sec = SectionHeader::decode(&sec_enc).expect("decode section in stream");
    let dec_chunk = ChunkFrameHeader::decode(&chunk_enc).expect("decode chunk in stream");

    assert_eq!(dec_env.family_id.0, 10);
    assert_eq!(dec_sec.section_offset, 64);
    assert_eq!(dec_chunk.frame_index, 0);
    assert_eq!(dec_chunk.payload_bytes, 64 * 1024);
}

#[test]
fn multi_message_stream_ten_envelopes() {
    // Encode 10 envelopes with incrementing fields; all must round-trip.
    for i in 0..10 {
        let header = EnvelopeHeader {
            family_id: SchemaFamilyId(i),
            type_id: SchemaTypeId(i * 10),
            version: SchemaVersion::new(i as u16, (i * 2) as u16),
            section_count: i as u16,
            total_body_bytes: i * 1024,
            ..Default::default()
        };
        let enc = header.encode();
        let dec = EnvelopeHeader::decode(&enc).expect("decode envelope in multi-message stream");
        assert_eq!(dec.family_id.0, i);
        assert_eq!(dec.type_id.0, i * 10);
        assert_eq!(dec.version, SchemaVersion::new(i as u16, (i * 2) as u16));
        assert_eq!(dec.section_count, i as u16);
        assert_eq!(dec.total_body_bytes, i * 1024);
    }
}

#[test]
fn multi_message_stream_ten_chunk_frames() {
    // Encode 10 chunk frames with payloads near class boundaries.
    for i in 0..10 {
        let payload_bytes = 64 * 1024 - i;
        let frame = ChunkFrameHeader {
            frame_index: i,
            payload_bytes,
            frame_size_class: ChunkFrameSizeClass::KiB64,
            payload_crc32c: i as u32,
            digest_continuation_marker: 0,
        };
        let enc = frame.encode();
        let dec =
            ChunkFrameHeader::decode(&enc).expect("decode chunk frame in multi-message stream");
        assert_eq!(dec.frame_index, i);
        assert_eq!(dec.payload_bytes, payload_bytes);
        assert_eq!(dec.payload_crc32c, i as u32);
    }
}

// ── Encode determinism ──────────────────────────────────────────────

#[test]
fn encode_is_deterministic_envelope() {
    let header = EnvelopeHeader {
        family_id: SchemaFamilyId(123),
        type_id: SchemaTypeId(456),
        version: SchemaVersion::new(2, 5),
        section_count: 3,
        total_body_bytes: 10_000,
        ..Default::default()
    };
    let enc1 = header.encode();
    let enc2 = header.encode();
    assert_eq!(
        enc1, enc2,
        "encode must be deterministic for EnvelopeHeader"
    );
}

#[test]
fn encode_is_deterministic_section() {
    let sec = SectionHeader {
        section_offset: 256,
        section_length: 4096,
        payload_class: PayloadClass::FixedInline,
        section_flags: 7,
        optional_mask: 0x1234,
    };
    let enc1 = sec.encode();
    let enc2 = sec.encode();
    assert_eq!(enc1, enc2, "encode must be deterministic for SectionHeader");
}

#[test]
fn encode_is_deterministic_chunk_frame() {
    let frame = ChunkFrameHeader {
        frame_index: 99,
        payload_bytes: 32 * 1024,
        frame_size_class: ChunkFrameSizeClass::KiB64,
        payload_crc32c: 0xDEADBEEF,
        digest_continuation_marker: 2,
    };
    let enc1 = frame.encode();
    let enc2 = frame.encode();
    assert_eq!(
        enc1, enc2,
        "encode must be deterministic for ChunkFrameHeader"
    );
}
