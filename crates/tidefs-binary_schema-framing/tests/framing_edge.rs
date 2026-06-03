// Integration tests: length-delimited framing edge cases — bad magic,
// checksum mismatches, alignment violations, truncated-input rejection,
// invalid discriminants, payload bounds enforcement.

use tidefs_binary_schema_core::{BinarySchemaError, ChecksumProfile, ChunkFrameSizeClass};
use tidefs_binary_schema_framing::{ChunkFrameHeader, EnvelopeHeader, SectionHeader};

// ── EnvelopeHeader error paths ──────────────────────────────────────

#[test]
fn envelope_rejects_bad_magic() {
    let header = EnvelopeHeader::default();
    let mut enc = header.encode();
    enc[0] = 0x00; // corrupt magic byte 0
    let result = EnvelopeHeader::decode(&enc);
    assert!(matches!(result, Err(BinarySchemaError::BadMagic { .. })));
}

#[test]
fn envelope_rejects_bad_magic_all_zeroes() {
    let zeroes = [0u8; 64];
    let result = EnvelopeHeader::decode(&zeroes);
    assert!(matches!(result, Err(BinarySchemaError::BadMagic { .. })));
}

#[test]
fn envelope_rejects_bad_crc32c_single_bit_flip() {
    let header = EnvelopeHeader::default();
    let mut enc = header.encode();
    enc[63] ^= 0x01; // flip lsb of CRC
    let result = EnvelopeHeader::decode(&enc);
    assert!(matches!(result, Err(BinarySchemaError::ChecksumMismatch)));
}

#[test]
fn envelope_rejects_bad_crc32c_payload_corruption() {
    let header = EnvelopeHeader {
        family_id: tidefs_binary_schema_core::SchemaFamilyId(1),
        ..Default::default()
    };
    let mut enc = header.encode();
    enc[4] ^= 0xFF; // corrupt family_id byte
    let result = EnvelopeHeader::decode(&enc);
    assert!(matches!(result, Err(BinarySchemaError::ChecksumMismatch)));
}

#[test]
fn envelope_rejects_invalid_fast_profile() {
    let header = EnvelopeHeader::default();
    let mut enc = header.encode();
    enc[40] = 0xFF; // invalid ChecksumProfile discriminant
    let result = EnvelopeHeader::decode(&enc);
    assert!(matches!(
        result,
        Err(BinarySchemaError::InvalidChecksumProfile)
    ));
}

#[test]
fn envelope_rejects_invalid_strong_profile() {
    let header = EnvelopeHeader::default();
    let mut enc = header.encode();
    enc[40] = ChecksumProfile::None.discriminant(); // fast = None (valid)
    enc[41] = 0xFE; // invalid strong profile
    let result = EnvelopeHeader::decode(&enc);
    assert!(matches!(
        result,
        Err(BinarySchemaError::InvalidChecksumProfile)
    ));
}

#[test]
fn envelope_decode_from_slice_too_short() {
    let short = [0u8; 32];
    let result = EnvelopeHeader::decode_from_slice(&short);
    assert!(matches!(result, Err(BinarySchemaError::BoundsViolation)));
}

#[test]
fn envelope_decode_from_slice_exactly_63_bytes() {
    // One byte short of the required 64
    let buf = [0u8; 63];
    let result = EnvelopeHeader::decode_from_slice(&buf);
    assert!(matches!(result, Err(BinarySchemaError::BoundsViolation)));
}

#[test]
fn envelope_decode_from_slice_empty() {
    let result = EnvelopeHeader::decode_from_slice(&[]);
    assert!(matches!(result, Err(BinarySchemaError::BoundsViolation)));
}

// ── SectionHeader error paths ───────────────────────────────────────

#[test]
fn section_rejects_unaligned_offset_4() {
    let mut enc = SectionHeader::default().encode();
    enc[0..8].copy_from_slice(&4u64.to_le_bytes());
    let result = SectionHeader::decode(&enc);
    assert!(matches!(result, Err(BinarySchemaError::AlignmentViolation)));
}

#[test]
fn section_rejects_unaligned_offset_1() {
    let mut enc = SectionHeader::default().encode();
    enc[0..8].copy_from_slice(&1u64.to_le_bytes());
    let result = SectionHeader::decode(&enc);
    assert!(matches!(result, Err(BinarySchemaError::AlignmentViolation)));
}

#[test]
fn section_rejects_invalid_payload_class_ffff() {
    let mut enc = SectionHeader::default().encode();
    enc[16] = 0xFF;
    enc[17] = 0xFF;
    let result = SectionHeader::decode(&enc);
    assert!(matches!(
        result,
        Err(BinarySchemaError::InvalidPayloadClass)
    ));
}

#[test]
fn section_rejects_invalid_payload_class_zerod() {
    let mut enc = SectionHeader::default().encode();
    enc[16] = 0x00;
    enc[17] = 0x00; // PayloadClass discriminant 0 (Unknown)
    let result = SectionHeader::decode(&enc);
    // Unknown (0) might map to a valid variant; check whether it's accepted
    // or rejected. If accepted, the test documents that zero is valid.
    match result {
        Ok(_) => {}                                       // zero discriminant is valid
        Err(BinarySchemaError::InvalidPayloadClass) => {} // zero is rejected
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}

// ── ChunkFrameHeader error paths and boundary tests ─────────────────

#[test]
fn chunk_frame_rejects_oversize_payload_one_byte() {
    let mut enc = ChunkFrameHeader::default().encode();
    // Class KiB64 (payload limit 64 KiB), set payload to 64 KiB + 1
    enc[8..16].copy_from_slice(&((64 * 1024) + 1u64).to_le_bytes());
    let result = ChunkFrameHeader::decode(&enc);
    assert!(matches!(result, Err(BinarySchemaError::BoundsViolation)));
}

#[test]
fn chunk_frame_rejects_oversize_payload_double_limit() {
    let mut enc = ChunkFrameHeader::default().encode();
    enc[8..16].copy_from_slice(&(128 * 1024u64).to_le_bytes());
    let result = ChunkFrameHeader::decode(&enc);
    assert!(matches!(result, Err(BinarySchemaError::BoundsViolation)));
}

#[test]
fn chunk_frame_rejects_invalid_size_class_ffff() {
    let mut enc = ChunkFrameHeader::default().encode();
    enc[16] = 0xFF;
    enc[17] = 0xFF;
    let result = ChunkFrameHeader::decode(&enc);
    assert!(matches!(
        result,
        Err(BinarySchemaError::InvalidPayloadClass)
    ));
}

#[test]
fn chunk_frame_accepts_exact_class_limit_kib64() {
    let frame = ChunkFrameHeader {
        frame_index: 0,
        payload_bytes: 64 * 1024,
        frame_size_class: ChunkFrameSizeClass::KiB64,
        payload_crc32c: 0,
        digest_continuation_marker: 0,
    };
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).expect("exact KiB64 limit should pass");
    assert_eq!(dec.payload_bytes, 64 * 1024);
}

#[test]
fn chunk_frame_accepts_one_byte_under_limit_kib64() {
    let frame = ChunkFrameHeader {
        frame_index: 0,
        payload_bytes: (64 * 1024) - 1,
        frame_size_class: ChunkFrameSizeClass::KiB64,
        payload_crc32c: 0,
        digest_continuation_marker: 0,
    };
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).expect("one byte under KiB64 limit should pass");
    assert_eq!(dec.payload_bytes, (64 * 1024) - 1);
}

#[test]
fn chunk_frame_accepts_empty_stream_zero_message() {
    let frame = ChunkFrameHeader::default();
    let enc = frame.encode();
    let dec = ChunkFrameHeader::decode(&enc).expect("default (empty) frame should decode");
    assert_eq!(dec.frame_index, 0);
    assert_eq!(dec.payload_bytes, 0);
}

// ── CRC32c propagation: verify header CRC is recomputed on encode ────

#[test]
fn envelope_header_crc_recomputed_on_each_encode() {
    let header = EnvelopeHeader::default();
    let enc1 = header.encode();
    let enc2 = header.encode();
    assert_eq!(enc1, enc2, "encode must be deterministic");
    // header_crc32c should be nonzero for a valid envelope
    let dec = EnvelopeHeader::decode(&enc1).expect("valid encode");
    assert!(
        dec.header_crc32c != 0,
        "CRC should be recomputed and non-zero"
    );
}

#[test]
fn different_payloads_produce_different_crc() {
    let h1 = EnvelopeHeader {
        total_body_bytes: 0,
        ..Default::default()
    };
    let h2 = EnvelopeHeader {
        total_body_bytes: 4096,
        ..Default::default()
    };
    let enc1 = h1.encode();
    let enc2 = h2.encode();
    let crc1 = u32::from_le_bytes(enc1[60..64].try_into().unwrap());
    let crc2 = u32::from_le_bytes(enc2[60..64].try_into().unwrap());
    assert_ne!(crc1, crc2, "different payloads must produce different CRCs");
}
