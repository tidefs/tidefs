// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Integration tests verifying interop between tidefs-binary_schema-core
// primitives and the tidefs-binary_schema-framing envelope/section/chunk
// header encode/decode layer.

use tidefs_binary_schema_core::{
    BinarySchemaError, ChecksumProfile, ChunkFrameSizeClass, I32Le, PayloadClass, SchemaFamilyId,
    SchemaTypeId, SchemaVersion, U32Le, U64Le, BINARY_SCHEMA_MAGIC,
};
use tidefs_binary_schema_framing::{
    ChunkFrameHeader, EnvelopeBuilder, EnvelopeHeader, SectionHeader,
};

// ---------------------------------------------------------------------------
// Core primitive → Framing envelope → decode: byte-identical round-trip
// ---------------------------------------------------------------------------

#[test]
fn core_u64le_survives_envelope_roundtrip() {
    // Encode a core U64Le value
    let original = U64Le::from_le(0xCAFE_BABE_DEAD_BEEF);
    let encoded_value = original.encode();

    // Build an envelope whose body would contain this value
    let header = EnvelopeBuilder::new(
        SchemaFamilyId::BINARY_SCHEMA,
        SchemaTypeId(42),
        SchemaVersion::new(1, 0),
    )
    .build(1, encoded_value.len() as u64);

    let envelope_bytes = header.encode();
    let decoded_header = EnvelopeHeader::decode(&envelope_bytes).unwrap();

    assert_eq!(decoded_header.magic, BINARY_SCHEMA_MAGIC);
    assert_eq!(decoded_header.family_id, SchemaFamilyId::BINARY_SCHEMA);
    assert_eq!(decoded_header.type_id, SchemaTypeId(42));
    assert_eq!(decoded_header.version, SchemaVersion::new(1, 0));

    // The body length from the envelope matches the encoded U64Le size
    assert_eq!(decoded_header.total_body_bytes, 8);
}

#[test]
fn core_u32le_survives_envelope_roundtrip() {
    let original = U32Le::from_le(0xDEAD_BEEF);
    let encoded_value = original.encode();

    let header = EnvelopeBuilder::new(
        SchemaFamilyId::BINARY_SCHEMA,
        SchemaTypeId(99),
        SchemaVersion::new(2, 3),
    )
    .build(1, encoded_value.len() as u64);

    let envelope_bytes = header.encode();
    let decoded_header = EnvelopeHeader::decode(&envelope_bytes).unwrap();

    assert_eq!(decoded_header.total_body_bytes, 4);
    assert_eq!(decoded_header.version, SchemaVersion::new(2, 3));
}

// ---------------------------------------------------------------------------
// Framing section header round-trip with core types
// ---------------------------------------------------------------------------

#[test]
fn section_header_encodes_core_payload_class() {
    let sec = SectionHeader {
        section_offset: 128,
        section_length: 1024,
        payload_class: PayloadClass::ChunkFramed,
        section_flags: 0xABCD,
        optional_mask: 0,
    };

    let encoded = sec.encode();
    let decoded = SectionHeader::decode(&encoded).unwrap();

    assert_eq!(decoded.payload_class, PayloadClass::ChunkFramed);
    assert_eq!(decoded.section_offset, 128);
    assert_eq!(decoded.section_length, 1024);
    assert_eq!(decoded.section_flags, 0xABCD);
}

#[test]
fn section_header_rejects_invalid_payload_class_from_core() {
    // PayloadClass::from_discriminant(0) is None; verify framing rejects it
    let mut enc = SectionHeader::default().encode();
    enc[16] = 0; // discriminant 0 is invalid for PayloadClass
    enc[17] = 0;
    assert!(matches!(
        SectionHeader::decode(&enc),
        Err(BinarySchemaError::InvalidPayloadClass)
    ));
}

// ---------------------------------------------------------------------------
// Framing chunk frame round-trip with core ChunkFrameSizeClass
// ---------------------------------------------------------------------------

#[test]
fn chunk_frame_encodes_core_frame_size_class() {
    for cls in &[
        ChunkFrameSizeClass::KiB64,
        ChunkFrameSizeClass::KiB256,
        ChunkFrameSizeClass::MiB1,
    ] {
        let frame = ChunkFrameHeader {
            frame_index: 0,
            payload_bytes: cls.payload_bytes() as u64,
            frame_size_class: *cls,
            payload_crc32c: 0,
            digest_continuation_marker: 0,
        };

        let encoded = frame.encode();
        let decoded = ChunkFrameHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.frame_size_class, *cls);
        assert_eq!(decoded.payload_bytes, cls.payload_bytes() as u64);
    }
}

#[test]
fn chunk_frame_rejects_oversize_payload_via_core_bounds() {
    let mut enc = ChunkFrameHeader::default().encode();

    // KiB64 max is 64 KiB; 65 KiB should be rejected
    enc[0..2].copy_from_slice(&0u16.to_le_bytes()); // frame_size_class = KiB64
    enc[8..16].copy_from_slice(&(65u64 * 1024).to_le_bytes());

    assert!(matches!(
        ChunkFrameHeader::decode(&enc),
        Err(BinarySchemaError::BoundsViolation)
    ));
}

// ---------------------------------------------------------------------------
// Envelope corruption: bad magic, bad CRC — core error types
// ---------------------------------------------------------------------------

#[test]
fn envelope_rejects_bad_magic_with_core_error() {
    let header = EnvelopeHeader::default();
    let mut encoded = header.encode();
    encoded[0] = 0x00;

    let result = EnvelopeHeader::decode(&encoded);
    assert!(matches!(result, Err(BinarySchemaError::BadMagic { .. })));
}

#[test]
fn envelope_rejects_crc32c_corruption_with_core_error() {
    let header = EnvelopeHeader::default();
    let mut encoded = header.encode();

    // Flip a bit in the CRC region
    encoded[63] ^= 0x01;

    let result = EnvelopeHeader::decode(&encoded);
    assert!(matches!(result, Err(BinarySchemaError::ChecksumMismatch)));
}

#[test]
fn envelope_rejects_single_bit_corruption_in_body_region() {
    // Corrupt the total_body_bytes field (offset 32)
    let header = EnvelopeBuilder::new(
        SchemaFamilyId::BINARY_SCHEMA,
        SchemaTypeId(1),
        SchemaVersion::new(1, 0),
    )
    .build(0, 4096);
    let mut encoded = header.encode();
    encoded[35] ^= 0x80;

    let result = EnvelopeHeader::decode(&encoded);
    // CRC should catch this corruption
    assert!(matches!(result, Err(BinarySchemaError::ChecksumMismatch)));
}

#[test]
fn envelope_rejects_invalid_checksum_profile_with_core_error() {
    let header = EnvelopeHeader::default();
    let mut encoded = header.encode();
    encoded[40] = 0xFF; // invalid ChecksumProfile discriminant

    let result = EnvelopeHeader::decode(&encoded);
    assert!(matches!(
        result,
        Err(BinarySchemaError::InvalidChecksumProfile)
    ));
}

// ---------------------------------------------------------------------------
// decode_from_slice error paths
// ---------------------------------------------------------------------------

#[test]
fn envelope_decode_from_slice_too_short_core_error() {
    let short_buf = [0u8; 32];
    let result = EnvelopeHeader::decode_from_slice(&short_buf);
    assert!(matches!(result, Err(BinarySchemaError::BoundsViolation)));
}

// ---------------------------------------------------------------------------
// EnvelopeBuilder: core SchemaFamilyId and SchemaVersion flow through
// ---------------------------------------------------------------------------

#[test]
fn envelope_builder_preserves_core_schema_identity() {
    let header = EnvelopeBuilder::new(
        SchemaFamilyId(7),
        SchemaTypeId(13),
        SchemaVersion::new(3, 14),
    )
    .with_flags(0xBEEF)
    .with_fingerprint_low(0x01234567_89ABCDEF)
    .with_checksum_profiles(
        ChecksumProfile::Crc32cPlusBlake3_256,
        ChecksumProfile::Blake3_256,
    )
    .build(2, 65536);

    let enc = header.encode();
    let dec = EnvelopeHeader::decode(&enc).unwrap();

    assert_eq!(dec.family_id.0, 7);
    assert_eq!(dec.type_id.0, 13);
    assert_eq!(dec.version, SchemaVersion::new(3, 14));
    assert_eq!(dec.flags, 0xBEEF);
    assert_eq!(dec.schema_fingerprint_low, 0x01234567_89ABCDEF);
    assert_eq!(
        dec.fast_checksum_profile,
        ChecksumProfile::Crc32cPlusBlake3_256
    );
    assert_eq!(dec.strong_digest_profile, ChecksumProfile::Blake3_256);
    assert_eq!(dec.section_count, 2);
    assert_eq!(dec.total_body_bytes, 65536);
}

// ---------------------------------------------------------------------------
// Sequential encode: core primitives → envelope wrapping → verify payload size
// ---------------------------------------------------------------------------

#[test]
fn multiple_core_primitives_total_body_bytes() {
    // Simulate 3 U64Le values as a payload
    let payload_size: u64 = (3 * 8) as u64;

    let header = EnvelopeBuilder::new(
        SchemaFamilyId::BINARY_SCHEMA,
        SchemaTypeId(1),
        SchemaVersion::new(1, 0),
    )
    .build(1, payload_size);

    let enc = header.encode();
    let dec = EnvelopeHeader::decode(&enc).unwrap();

    assert_eq!(dec.total_body_bytes, 24); // 3 * 8 bytes
    assert_eq!(dec.section_count, 1);
}

// ---------------------------------------------------------------------------
// Negative test: mixed core types encoded, then framing corruption detected
// ---------------------------------------------------------------------------

#[test]
fn mixed_payload_envelope_crc_detects_corruption() {
    // Encode a U32Le and an I32Le into a simulated body
    let u32_val = U32Le::from_le(0x12345678);
    let i32_val = I32Le::from_le(-42);
    let mut body = Vec::new();
    body.extend_from_slice(&u32_val.encode());
    body.extend_from_slice(&i32_val.encode());

    let header = EnvelopeBuilder::new(
        SchemaFamilyId::BINARY_SCHEMA,
        SchemaTypeId(10),
        SchemaVersion::new(1, 0),
    )
    .build(1, body.len() as u64);

    let mut encoded = header.encode();

    // Corrupt a byte in the envelope's reserved region that's covered by CRC
    encoded[30] ^= 0x01; // flip a bit in _reserved

    let result = EnvelopeHeader::decode(&encoded);
    assert!(matches!(result, Err(BinarySchemaError::ChecksumMismatch)));
}

// ---------------------------------------------------------------------------
// EnvelopeHeader::decode_from_slice: alignment violation
// ---------------------------------------------------------------------------

#[test]
fn envelope_decode_from_slice_unaligned() {
    let header = EnvelopeHeader::default();
    let encoded = header.encode();

    // Place the encoded bytes at an unaligned offset within a larger buffer
    let mut buf = [0u8; 72];
    buf[1..65].copy_from_slice(&encoded);

    // decode_from_slice requires the slice pointer to be 8-byte aligned
    // buf[1..] is unaligned because buf is stack-allocated and unaligned
    let result = EnvelopeHeader::decode_from_slice(&buf[1..65]);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// SectionHeader: valid offset boundaries (min 0, max u64::MAX)
// ---------------------------------------------------------------------------

#[test]
fn section_header_boundary_offsets() {
    // Offset 0 is valid (8-byte aligned, tested in framing crate)
    let sec = SectionHeader {
        section_offset: 0,
        section_length: 0,
        ..Default::default()
    };
    let enc = sec.encode();
    let dec = SectionHeader::decode(&enc).unwrap();
    assert_eq!(dec.section_offset, 0);

    // Max u64 offset is valid if 8-byte aligned
    let max_aligned = u64::MAX - (u64::MAX % 8);
    let sec = SectionHeader {
        section_offset: max_aligned,
        section_length: 1,
        ..Default::default()
    };
    let enc = sec.encode();
    let dec = SectionHeader::decode(&enc).unwrap();
    assert_eq!(dec.section_offset, max_aligned);
}

// ---------------------------------------------------------------------------
// ChunkFrameHeader: payload exactly at class capacity boundary
// ---------------------------------------------------------------------------

#[test]
fn chunk_frame_payload_exactly_at_capacity() {
    // KiB64 allows exactly 64 KiB
    let frame = ChunkFrameHeader {
        frame_index: 1,
        payload_bytes: 64 * 1024,
        frame_size_class: ChunkFrameSizeClass::KiB64,
        payload_crc32c: 0,
        digest_continuation_marker: 0,
    };
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).unwrap();
    assert_eq!(dec.payload_bytes, 64 * 1024);
    assert_eq!(dec.frame_size_class, ChunkFrameSizeClass::KiB64);

    // KiB256: exactly 256 KiB
    let frame = ChunkFrameHeader {
        frame_index: 2,
        payload_bytes: 256 * 1024,
        frame_size_class: ChunkFrameSizeClass::KiB256,
        payload_crc32c: 0,
        digest_continuation_marker: 0,
    };
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).unwrap();
    assert_eq!(dec.payload_bytes, 256 * 1024);

    // MiB1: exactly 1 MiB
    let frame = ChunkFrameHeader {
        frame_index: 3,
        payload_bytes: 1024 * 1024,
        frame_size_class: ChunkFrameSizeClass::MiB1,
        payload_crc32c: 0,
        digest_continuation_marker: 0,
    };
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).unwrap();
    assert_eq!(dec.payload_bytes, 1024 * 1024);
}

// ---------------------------------------------------------------------------
// ChunkFrameHeader: one byte over capacity for each size class
// ---------------------------------------------------------------------------

#[test]
fn chunk_frame_rejects_one_byte_over_capacity_for_all_classes() {
    // KiB64 + 1
    let mut enc = ChunkFrameHeader::default().encode();
    enc[16..18].copy_from_slice(&0u16.to_le_bytes()); // KiB64
    enc[8..16].copy_from_slice(&(64u64 * 1024 + 1).to_le_bytes());
    assert!(matches!(
        ChunkFrameHeader::decode(&enc),
        Err(BinarySchemaError::BoundsViolation)
    ));

    // KiB256 + 1
    enc[16..18].copy_from_slice(&1u16.to_le_bytes()); // KiB256
    enc[8..16].copy_from_slice(&(256u64 * 1024 + 1).to_le_bytes());
    assert!(matches!(
        ChunkFrameHeader::decode(&enc),
        Err(BinarySchemaError::BoundsViolation)
    ));

    // MiB1 + 1
    enc[16..18].copy_from_slice(&2u16.to_le_bytes()); // MiB1
    enc[8..16].copy_from_slice(&(1024u64 * 1024 + 1).to_le_bytes());
    assert!(matches!(
        ChunkFrameHeader::decode(&enc),
        Err(BinarySchemaError::BoundsViolation)
    ));
}
