// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Integration tests for tidefs-binary_schema-core serialization
// primitives, exercising the public API from outside the crate.

use tidefs_binary_schema_core::{
    canonical_bool, decode_canonical_bool, Acceptance, BinarySchemaError, ChecksumProfile,
    ChunkFrameSizeClass, ContinuityWindow, DomainTag, FeatureBits, I32Le, I64Le, PayloadClass,
    SchemaFamilyId, SchemaFingerprint, SchemaTypeId, SchemaVersion, U16Le, U32Le, U64Le,
    BINARY_SCHEMA_MAGIC, CANONICAL_FALSE, CANONICAL_TRUE, CHUNK_FRAME_SIZE_1M,
    CHUNK_FRAME_SIZE_256K, CHUNK_FRAME_SIZE_64K, ENVELOPE_ALIGN, ENVELOPE_HEADER_BYTES,
    SECTION_HEADER_BYTES, SECTION_OFFSET_ALIGN_MIN,
};

// ---------------------------------------------------------------------------
// Round-trip: integer LE wrappers with boundary values
// ---------------------------------------------------------------------------

#[test]
fn u16le_roundtrip_boundary() {
    for v in [0u16, 1, 0xFF, 0xFFFF] {
        let le = U16Le::from_le(v);
        assert_eq!(le.as_raw(), v);
        assert_eq!(U16Le::from_le_bytes(le.encode()), le);
    }
}

#[test]
fn u32le_roundtrip_boundary() {
    for v in [0u32, 1, 0xFF, 0xFFFF, 0xFFFF_FFFF] {
        let le = U32Le::from_le(v);
        assert_eq!(le.as_raw(), v);
        assert_eq!(U32Le::from_le_bytes(le.encode()), le);
    }
}

#[test]
fn u64le_roundtrip_boundary() {
    for v in [0u64, 1, 0xFF, 0xFFFF, 0xFFFF_FFFF, u64::MAX] {
        let le = U64Le::from_le(v);
        assert_eq!(le.as_raw(), v);
        assert_eq!(U64Le::from_le_bytes(le.encode()), le);
    }
}

#[test]
fn i32le_roundtrip_boundary() {
    for v in [i32::MIN, -1i32, 0, 1, i32::MAX] {
        let le = I32Le::from_le(v);
        assert_eq!(le.as_raw(), v);
        assert_eq!(I32Le::from_le_bytes(le.encode()), le);
    }
}

#[test]
fn i64le_roundtrip_boundary() {
    for v in [i64::MIN, -1i64, 0, 1, i64::MAX] {
        let le = I64Le::from_le(v);
        assert_eq!(le.as_raw(), v);
        assert_eq!(I64Le::from_le_bytes(le.encode()), le);
    }
}

// ---------------------------------------------------------------------------
// Round-trip: SchemaVersion
// ---------------------------------------------------------------------------

#[test]
fn schema_version_boundary_roundtrip() {
    for (maj, min) in [(0u16, 0u16), (1, 0), (0, 1), (u16::MAX, u16::MAX), (42, 7)] {
        let v = SchemaVersion::new(maj, min);
        let decoded = SchemaVersion::decode(v.encode());
        assert_eq!(decoded, v);
    }
}

// ---------------------------------------------------------------------------
// Round-trip: SchemaFingerprint
// ---------------------------------------------------------------------------

#[test]
fn schema_fingerprint_boundary_roundtrip() {
    let fps: &[SchemaFingerprint] = &[
        SchemaFingerprint::ZERO,
        SchemaFingerprint([0xFFu8; 32]),
        SchemaFingerprint({
            let mut a = [0u8; 32];
            a[0] = 0xAB;
            a[31] = 0xCD;
            a
        }),
    ];
    for fp in fps {
        let decoded = SchemaFingerprint::decode(fp.encode());
        assert_eq!(*fp, decoded);
    }
}

// ---------------------------------------------------------------------------
// Round-trip: FeatureBits
// ---------------------------------------------------------------------------

#[test]
fn feature_bits_boundary_roundtrip() {
    for v in [0u64, u64::MAX, 0x0123_4567_89AB_CDEF] {
        let fb = FeatureBits(v);
        let bytes = fb.encode();
        assert_eq!(bytes, v.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Sequential heterogeneous encode/decode into a single buffer
// ---------------------------------------------------------------------------

#[test]
fn sequential_encode_decode_mixed_primitives() {
    // Encode a sequence of different types into one contiguous buffer
    let mut buf: Vec<u8> = Vec::new();

    let items: Vec<(&str, Vec<u8>)> = vec![
        ("u16le", U16Le::from_le(0xBEEF).encode().to_vec()),
        ("u32le", U32Le::from_le(0xDEAD_BEEF).encode().to_vec()),
        ("u64le", U64Le::from_le(0xCAFE_BABE).encode().to_vec()),
        ("i32le", I32Le::from_le(-42).encode().to_vec()),
        ("i64le", I64Le::from_le(-999).encode().to_vec()),
        ("version", SchemaVersion::new(3, 14).encode().to_vec()),
        (
            "fingerprint",
            SchemaFingerprint([0x77u8; 32]).encode().to_vec(),
        ),
    ];

    let expected_names: Vec<&str> = items.iter().map(|(n, _)| *n).collect();
    let mut offsets: Vec<(usize, usize)> = Vec::new(); // (start, len)

    let mut pos = 0;
    for (_, bytes) in &items {
        offsets.push((pos, bytes.len()));
        buf.extend_from_slice(bytes);
        pos += bytes.len();
    }

    // Decode each item and verify size
    assert_eq!(offsets.len(), expected_names.len());
    for (i, (start, len)) in offsets.iter().enumerate() {
        let name = expected_names[i];
        match name {
            "u16le" => assert_eq!(*len, 2),
            "u32le" => assert_eq!(*len, 4),
            "u64le" => assert_eq!(*len, 8),
            "i32le" => assert_eq!(*len, 4),
            "i64le" => assert_eq!(*len, 8),
            "version" => assert_eq!(*len, 4),
            "fingerprint" => assert_eq!(*len, 32),
            _ => panic!("unexpected item: {name}"),
        }

        // Decode from the buffer at the correct offset
        match name {
            "u16le" => {
                let mut arr = [0u8; 2];
                arr.copy_from_slice(&buf[*start..*start + 2]);
                assert_eq!(U16Le::from_le_bytes(arr).as_raw(), 0xBEEF);
            }
            "u32le" => {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&buf[*start..*start + 4]);
                assert_eq!(U32Le::from_le_bytes(arr).as_raw(), 0xDEAD_BEEF);
            }
            "u64le" => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&buf[*start..*start + 8]);
                assert_eq!(U64Le::from_le_bytes(arr).as_raw(), 0xCAFE_BABE);
            }
            "i32le" => {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&buf[*start..*start + 4]);
                assert_eq!(I32Le::from_le_bytes(arr).as_raw(), -42);
            }
            "i64le" => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&buf[*start..*start + 8]);
                assert_eq!(I64Le::from_le_bytes(arr).as_raw(), -999);
            }
            "version" => {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&buf[*start..*start + 4]);
                assert_eq!(SchemaVersion::decode(arr), SchemaVersion::new(3, 14));
            }
            "fingerprint" => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&buf[*start..*start + 32]);
                assert_eq!(
                    SchemaFingerprint::decode(arr),
                    SchemaFingerprint([0x77u8; 32])
                );
            }
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// CanonicalBool: encode/decode round-trip
// ---------------------------------------------------------------------------

#[test]
fn canonical_bool_integration() {
    assert_eq!(canonical_bool(false), CANONICAL_FALSE);
    assert_eq!(canonical_bool(true), CANONICAL_TRUE);
    assert_eq!(decode_canonical_bool(CANONICAL_FALSE), Some(false));
    assert_eq!(decode_canonical_bool(CANONICAL_TRUE), Some(true));

    // All non-0, non-1 values should return None
    for v in 2u8..=255u8 {
        assert_eq!(decode_canonical_bool(v), None);
    }
}

// ---------------------------------------------------------------------------
// Enum discriminants
// ---------------------------------------------------------------------------

#[test]
fn checksum_profile_discriminant_roundtrip_integration() {
    let profiles = [
        ChecksumProfile::None,
        ChecksumProfile::Crc32c,
        ChecksumProfile::Blake3_256,
        ChecksumProfile::Crc32cPlusBlake3_256,
    ];
    for p in &profiles {
        assert_eq!(
            ChecksumProfile::from_discriminant(p.discriminant()),
            Some(*p)
        );
    }
    // Invalid discriminants
    for d in 4u8..=255u8 {
        assert_eq!(ChecksumProfile::from_discriminant(d), None);
    }
}

#[test]
fn payload_class_discriminant_roundtrip_integration() {
    let classes = [
        PayloadClass::FixedInline,
        PayloadClass::VariableInline,
        PayloadClass::ChunkFramed,
        PayloadClass::ExternalRef,
    ];
    for cls in &classes {
        assert_eq!(
            PayloadClass::from_discriminant(cls.discriminant()),
            Some(*cls)
        );
    }
    // Invalid discriminants (0 and >4)
    assert_eq!(PayloadClass::from_discriminant(0), None);
    for d in 5u16..=255u16 {
        assert_eq!(PayloadClass::from_discriminant(d), None);
    }
}

#[test]
fn chunk_frame_size_class_roundtrip_integration() {
    let sizes = [
        ChunkFrameSizeClass::KiB64,
        ChunkFrameSizeClass::KiB256,
        ChunkFrameSizeClass::MiB1,
    ];
    for cls in &sizes {
        assert_eq!(
            ChunkFrameSizeClass::from_discriminant(*cls as u16),
            Some(*cls)
        );
    }
    // Invalid discriminants
    assert_eq!(ChunkFrameSizeClass::from_discriminant(3), None);
    assert_eq!(ChunkFrameSizeClass::from_discriminant(u16::MAX), None);
}

// ---------------------------------------------------------------------------
// ChecksumProfile predicates
// ---------------------------------------------------------------------------

#[test]
fn checksum_profile_predicates_integration() {
    assert!(!ChecksumProfile::None.has_crc32c());
    assert!(ChecksumProfile::Crc32c.has_crc32c());
    assert!(!ChecksumProfile::Blake3_256.has_crc32c());
    assert!(ChecksumProfile::Crc32cPlusBlake3_256.has_crc32c());

    assert!(!ChecksumProfile::None.has_blake3());
    assert!(!ChecksumProfile::Crc32c.has_blake3());
    assert!(ChecksumProfile::Blake3_256.has_blake3());
    assert!(ChecksumProfile::Crc32cPlusBlake3_256.has_blake3());
}

// ---------------------------------------------------------------------------
// FeatureBits with/has/subset integration
// ---------------------------------------------------------------------------

#[test]
fn feature_bits_with_has_integration() {
    let fb = FeatureBits::NONE;
    // Set bits 0, 31, 63
    let fb = fb.with(0).with(31).with(63);
    assert!(fb.has(0));
    assert!(fb.has(31));
    assert!(fb.has(63));
    assert!(!fb.has(1));
    assert!(!fb.has(62));

    // Check the raw value
    assert_eq!(fb.0, (1u64 << 0) | (1u64 << 31) | (1u64 << 63));
}

#[test]
fn feature_bits_subset_integration() {
    let fb_full = FeatureBits::NONE.with(0).with(1).with(2);
    let fb_part = FeatureBits::NONE.with(0).with(1);
    assert!(fb_part.is_subset_of(fb_full));
    assert!(!fb_full.is_subset_of(fb_part));
    assert!(FeatureBits::NONE.is_subset_of(fb_full));
    assert!(FeatureBits::NONE.is_subset_of(FeatureBits::NONE));
}

// ---------------------------------------------------------------------------
// ContinuityWindow acceptance integration
// ---------------------------------------------------------------------------

#[test]
fn continuity_window_acceptance_integration() {
    const FP: SchemaFingerprint = SchemaFingerprint([0x11u8; 32]);

    let window = ContinuityWindow {
        family_id: SchemaFamilyId::BINARY_SCHEMA,
        type_id: SchemaTypeId(42),
        major_version: 1,
        minor_min: 0,
        minor_max: 3,
        required_features: FeatureBits(0b011),
        accepted_fingerprints: &[FP],
    };

    // Perfect match
    assert_eq!(
        window.accepts(1, 2, FeatureBits(0b001), FP),
        Acceptance::Accepted
    );

    // Major mismatch
    assert_eq!(
        window.accepts(0, 2, FeatureBits(0b001), FP),
        Acceptance::RejectMajorMismatch
    );
    assert_eq!(
        window.accepts(2, 2, FeatureBits(0b001), FP),
        Acceptance::RejectMajorMismatch
    );

    // Minor out of window
    assert_eq!(
        window.accepts(1, 4, FeatureBits(0b001), FP),
        Acceptance::RejectMinorOutOfWindow
    );

    // Features unsupported (requester has bits window doesn't require)
    assert_eq!(
        window.accepts(1, 2, FeatureBits(0b111), FP),
        Acceptance::RejectFeaturesUnsupported
    );

    // Unknown fingerprint
    let other_fp = SchemaFingerprint([0xAAu8; 32]);
    assert_eq!(
        window.accepts(1, 2, FeatureBits(0b001), other_fp),
        Acceptance::RejectFingerprintUnknown
    );

    // Acceptance::is_accepted
    assert!(Acceptance::Accepted.is_accepted());
    assert!(!Acceptance::RejectMajorMismatch.is_accepted());
    assert!(!Acceptance::RejectMinorOutOfWindow.is_accepted());
    assert!(!Acceptance::RejectFeaturesUnsupported.is_accepted());
    assert!(!Acceptance::RejectFingerprintUnknown.is_accepted());
}

// ---------------------------------------------------------------------------
// BinarySchemaError: Debug and Display
// ---------------------------------------------------------------------------

#[test]
fn binary_schema_error_debug_display_integration() {
    let errors = [
        BinarySchemaError::BadMagic { got: 0xDEAD },
        BinarySchemaError::ChecksumMismatch,
        BinarySchemaError::DigestMismatch,
        BinarySchemaError::AlignmentViolation,
        BinarySchemaError::BoundsViolation,
        BinarySchemaError::InvalidBoolean,
        BinarySchemaError::InvalidChecksumProfile,
        BinarySchemaError::InvalidPayloadClass,
        BinarySchemaError::InvalidDomainTag,
        BinarySchemaError::ContinuityRejection(Acceptance::RejectMajorMismatch),
        BinarySchemaError::EncodeError,
    ];

    for e in &errors {
        let debug_str = format!("{e:?}");
        assert!(!debug_str.is_empty(), "Debug output empty for {e:?}");
        let display_str = format!("{e}");
        assert!(!display_str.is_empty(), "Display output empty for {e:?}");
    }
}

// ---------------------------------------------------------------------------
// Magic constant
// ---------------------------------------------------------------------------

#[test]
fn magic_constant_integration() {
    assert_eq!(BINARY_SCHEMA_MAGIC, 0x5346_4256);
    assert_eq!(&BINARY_SCHEMA_MAGIC.to_le_bytes(), b"VBFS");
}

// ---------------------------------------------------------------------------
// DomainTag discriminants
// ---------------------------------------------------------------------------

#[test]
fn domain_tag_discriminants_integration() {
    let tags = [
        (DomainTag::EnvelopeHeader, 1u32),
        (DomainTag::SectionBody, 2),
        (DomainTag::ChunkFrame, 3),
        (DomainTag::ExternalPayload, 4),
        (DomainTag::ReceiptBody, 5),
        (DomainTag::ValidationBundle, 6),
        (DomainTag::ArchiveBody, 7),
        (DomainTag::TransferStream, 8),
    ];
    for (tag, expected) in &tags {
        assert_eq!(tag.discriminant(), *expected);
    }
}

// ---------------------------------------------------------------------------
// ChunkFrameSizeClass payload sizes
// ---------------------------------------------------------------------------

#[test]
fn chunk_frame_size_class_payload_sizes_integration() {
    assert_eq!(ChunkFrameSizeClass::KiB64.payload_bytes(), 64 * 1024);
    assert_eq!(ChunkFrameSizeClass::KiB256.payload_bytes(), 256 * 1024);
    assert_eq!(ChunkFrameSizeClass::MiB1.payload_bytes(), 1024 * 1024);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_integration() {
    assert_eq!(ENVELOPE_ALIGN, 8);
    assert_eq!(SECTION_OFFSET_ALIGN_MIN, 8);
    assert_eq!(ENVELOPE_HEADER_BYTES, 64);
    assert_eq!(SECTION_HEADER_BYTES, 32);
    assert_eq!(CHUNK_FRAME_SIZE_64K, 64 * 1024);
    assert_eq!(CHUNK_FRAME_SIZE_256K, 256 * 1024);
    assert_eq!(CHUNK_FRAME_SIZE_1M, 1024 * 1024);
}

// ---------------------------------------------------------------------------
// LE wrapper interop: From/Into, Display, Clone, Eq
// ---------------------------------------------------------------------------

#[test]
fn le_wrapper_from_into_integration() {
    let u16v: U16Le = 0xCAFEu16.into();
    let raw: u16 = u16v.into();
    assert_eq!(raw, 0xCAFE);

    let i32v: I32Le = (-12345i32).into();
    let raw: i32 = i32v.into();
    assert_eq!(raw, -12345);
}

#[test]
fn le_wrapper_display_integration() {
    assert_eq!(format!("{}", U16Le::from_le(42)), "42");
    assert_eq!(format!("{}", U32Le::from_le(100)), "100");
    assert_eq!(format!("{}", I32Le::from_le(-5)), "-5");
}

#[test]
fn le_wrapper_clone_eq_integration() {
    let a = U64Le::from_le(0x1234);
    let b = a; // Clone (Copy)
    assert_eq!(a, b);
    assert_ne!(a, U64Le::from_le(0x5678));
}

// ---------------------------------------------------------------------------
// SchemaFamilyId and SchemaTypeId
// ---------------------------------------------------------------------------

#[test]
fn schema_family_id_integration() {
    assert_eq!(SchemaFamilyId::BINARY_SCHEMA.0, 1);
    assert_eq!(SchemaFamilyId::default().0, 0);
}

#[test]
fn schema_type_id_integration() {
    let id = SchemaTypeId(42);
    assert_eq!(id, SchemaTypeId(42));
    assert_ne!(id, SchemaTypeId(99));
    assert_eq!(SchemaTypeId::default().0, 0);
}

// ---------------------------------------------------------------------------
// LE wrapper defaults
// ---------------------------------------------------------------------------

#[test]
fn le_wrapper_defaults_are_zero() {
    assert_eq!(U16Le::default(), U16Le(0));
    assert_eq!(U32Le::default(), U32Le(0));
    assert_eq!(U64Le::default(), U64Le(0));
    assert_eq!(I32Le::default(), I32Le(0));
    assert_eq!(I64Le::default(), I64Le(0));
}
