// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Property-based round-trip and malformed-input rejection tests for
// tidefs-binary_schema-core serialization primitives.
//
// Exercises the crate's public encode/decode API with proptest so
// edge cases that unit tests and hand-picked boundary values miss
// are caught automatically.

use proptest::prelude::*;
use tidefs_binary_schema_core::{
    canonical_bool, decode_canonical_bool, Acceptance, BinarySchemaError, ChecksumProfile,
    ChunkFrameSizeClass, ContinuityWindow, DomainTag, FeatureBits, I32Le, I64Le, PayloadClass,
    SchemaFamilyId, SchemaFingerprint, SchemaTypeId, SchemaVersion, U16Le, U32Le, U64Le,
    BINARY_SCHEMA_MAGIC, CHUNK_FRAME_SIZE_1M, CHUNK_FRAME_SIZE_256K, CHUNK_FRAME_SIZE_64K,
    ENVELOPE_ALIGN, ENVELOPE_HEADER_BYTES, SECTION_HEADER_BYTES, SECTION_OFFSET_ALIGN_MIN,
};

// ── Strategy helpers ────────────────────────────────────────────────

fn arb_u16() -> impl Strategy<Value = u16> {
    any::<u16>()
}
fn arb_u32() -> impl Strategy<Value = u32> {
    any::<u32>()
}
fn arb_u64() -> impl Strategy<Value = u64> {
    any::<u64>()
}
fn arb_i32() -> impl Strategy<Value = i32> {
    any::<i32>()
}
fn arb_i64() -> impl Strategy<Value = i64> {
    any::<i64>()
}
fn arb_version() -> impl Strategy<Value = SchemaVersion> {
    (any::<u16>(), any::<u16>()).prop_map(|(m, n)| SchemaVersion::new(m, n))
}
fn arb_fingerprint() -> impl Strategy<Value = SchemaFingerprint> {
    any::<[u8; 32]>().prop_map(SchemaFingerprint)
}
fn arb_feature_bits() -> impl Strategy<Value = FeatureBits> {
    any::<u64>().prop_map(FeatureBits)
}
fn arb_checksum_profile() -> impl Strategy<Value = ChecksumProfile> {
    prop_oneof![
        Just(ChecksumProfile::None),
        Just(ChecksumProfile::Crc32c),
        Just(ChecksumProfile::Blake3_256),
        Just(ChecksumProfile::Crc32cPlusBlake3_256),
    ]
}
fn arb_payload_class() -> impl Strategy<Value = PayloadClass> {
    prop_oneof![
        Just(PayloadClass::FixedInline),
        Just(PayloadClass::VariableInline),
        Just(PayloadClass::ChunkFramed),
        Just(PayloadClass::ExternalRef),
    ]
}
fn arb_chunk_frame_size_class() -> impl Strategy<Value = ChunkFrameSizeClass> {
    prop_oneof![
        Just(ChunkFrameSizeClass::KiB64),
        Just(ChunkFrameSizeClass::KiB256),
        Just(ChunkFrameSizeClass::MiB1),
    ]
}

// ── LE wrapper round-trips ──────────────────────────────────────────

proptest! {
    #[test]
    fn u16le_arbitrary_roundtrip(v in arb_u16()) {
        let le = U16Le::from_le(v);
        let dec = U16Le::from_le_bytes(le.encode());
        assert_eq!(dec, le);
        assert_eq!(dec.as_raw(), v);
    }

    #[test]
    fn u32le_arbitrary_roundtrip(v in arb_u32()) {
        let le = U32Le::from_le(v);
        let dec = U32Le::from_le_bytes(le.encode());
        assert_eq!(dec, le);
        assert_eq!(dec.as_raw(), v);
    }

    #[test]
    fn u64le_arbitrary_roundtrip(v in arb_u64()) {
        let le = U64Le::from_le(v);
        let dec = U64Le::from_le_bytes(le.encode());
        assert_eq!(dec, le);
        assert_eq!(dec.as_raw(), v);
    }

    #[test]
    fn i32le_arbitrary_roundtrip(v in arb_i32()) {
        let le = I32Le::from_le(v);
        let dec = I32Le::from_le_bytes(le.encode());
        assert_eq!(dec, le);
        assert_eq!(dec.as_raw(), v);
    }

    #[test]
    fn i64le_arbitrary_roundtrip(v in arb_i64()) {
        let le = I64Le::from_le(v);
        let dec = I64Le::from_le_bytes(le.encode());
        assert_eq!(dec, le);
        assert_eq!(dec.as_raw(), v);
    }
}

// ── Schema struct encode/decode round-trips ─────────────────────────

proptest! {
    #[test]
    fn schema_version_arbitrary_roundtrip(v in arb_version()) {
        let bytes = v.encode();
        assert_eq!(bytes.len(), 4);
        let dec = SchemaVersion::decode(bytes);
        assert_eq!(dec, v);
    }

    #[test]
    fn schema_fingerprint_arbitrary_roundtrip(fp in arb_fingerprint()) {
        let bytes = fp.encode();
        assert_eq!(bytes.len(), 32);
        let dec = SchemaFingerprint::decode(bytes);
        assert_eq!(dec, fp);
    }

    #[test]
    fn feature_bits_arbitrary_roundtrip(fb in arb_feature_bits()) {
        let bytes = fb.encode();
        assert_eq!(bytes.len(), 8);
        assert_eq!(u64::from_le_bytes(bytes), fb.0);
    }
}

// ── CanonicalBool round-trip and malformed rejection ────────────────

proptest! {
    #[test]
    fn canonical_bool_valid_roundtrip(b in any::<bool>()) {
        let enc = canonical_bool(b);
        let dec = decode_canonical_bool(enc);
        assert_eq!(dec, Some(b));
    }

    #[test]
    fn canonical_bool_rejects_invalid(v in 2u8..=255u8) {
        assert_eq!(decode_canonical_bool(v), None);
    }
}

// ── Enum discriminant round-trips ───────────────────────────────────

proptest! {
    #[test]
    fn checksum_profile_discriminant_roundtrip(p in arb_checksum_profile()) {
        let d = p.discriminant();
        assert_eq!(ChecksumProfile::from_discriminant(d), Some(p));
    }

    #[test]
    fn payload_class_discriminant_roundtrip(cls in arb_payload_class()) {
        let d = cls.discriminant();
        assert_eq!(PayloadClass::from_discriminant(d), Some(cls));
    }

    #[test]
    fn chunk_frame_size_discriminant_roundtrip(cls in arb_chunk_frame_size_class()) {
        let d = cls as u16;
        let dec = ChunkFrameSizeClass::from_discriminant(d);
        assert_eq!(dec, Some(cls));
    }
}

// ── Invalid discriminant rejection (malformed input) ────────────────

proptest! {
    #[test]
    fn checksum_profile_rejects_out_of_range(d in 4u8..=255u8) {
        assert_eq!(ChecksumProfile::from_discriminant(d), None);
    }

    #[test]
    fn payload_class_rejects_zero(d in Just(0u16)) {
        assert_eq!(PayloadClass::from_discriminant(d), None);
    }

    #[test]
    fn payload_class_rejects_out_of_range(d in 5u16..=u16::MAX) {
        assert_eq!(PayloadClass::from_discriminant(d), None);
    }

    #[test]
    fn chunk_frame_size_rejects_out_of_range(d in 3u16..=u16::MAX) {
        assert_eq!(ChunkFrameSizeClass::from_discriminant(d), None);
    }
}

// ── FeatureBits: with / has / subset consistency ────────────────────

proptest! {
    #[test]
    fn feature_bits_with_has_consistency(fb in arb_feature_bits(), bit in 0u32..64u32) {
        let modified = fb.with(bit);
        assert!(modified.has(bit));
        if fb.has(bit) {
            assert_eq!(modified.0, fb.0);
        } else {
            assert_eq!(modified.0, fb.0 | (1u64 << bit));
        }
    }

    #[test]
    fn feature_bits_subset_reflexive(fb in arb_feature_bits()) {
        assert!(fb.is_subset_of(fb));
    }

    #[test]
    fn feature_bits_none_subset_of_any(fb in arb_feature_bits()) {
        assert!(FeatureBits::NONE.is_subset_of(fb));
    }

    #[test]
    fn feature_bits_subset_transitive(
        a in arb_feature_bits(),
        b in arb_feature_bits(),
        c in arb_feature_bits(),
    ) {
        // a ⊆ b ∧ b ⊆ c  ⇒  a ⊆ c
        if a.is_subset_of(b) && b.is_subset_of(c) {
            assert!(a.is_subset_of(c));
        }
    }

    #[test]
    fn feature_bits_disjoint_not_subset(
        a in arb_feature_bits(),
        b in arb_feature_bits(),
    ) {
        // If a and b have no bits in common and a is non-zero, a ⊄ b
        let disjoint = (a.0 & b.0) == 0;
        let a_nonzero = a.0 != 0;
        if disjoint && a_nonzero {
            assert!(!a.is_subset_of(b));
        }
    }
}

// ── Deterministic encoding ─────────────────────────────────────────

proptest! {
    #[test]
    fn u64le_encoding_deterministic(v in arb_u64()) {
        let a = U64Le::from_le(v);
        let b = U64Le::from_le(v);
        assert_eq!(a.encode(), b.encode());
        assert_eq!(a, b);
    }

    #[test]
    fn schema_version_encoding_deterministic(m in any::<u16>(), n in any::<u16>()) {
        let a = SchemaVersion::new(m, n);
        let b = SchemaVersion::new(m, n);
        assert_eq!(a.encode(), b.encode());
        assert_eq!(a, b);
    }

    #[test]
    fn schema_fingerprint_encoding_deterministic(bytes in any::<[u8; 32]>()) {
        let a = SchemaFingerprint(bytes);
        let b = SchemaFingerprint(bytes);
        assert_eq!(a.encode(), b.encode());
        assert_eq!(a, b);
    }

    #[test]
    fn feature_bits_encoding_deterministic(v in arb_u64()) {
        let a = FeatureBits(v);
        let b = FeatureBits(v);
        assert_eq!(a.encode(), b.encode());
    }
}

// ── Encode output sizes are fixed and match declared constants ─────

proptest! {
    #[test]
    fn u16le_encode_is_2_bytes(v in arb_u16()) {
        assert_eq!(U16Le::from_le(v).encode().len(), 2);
        assert_eq!(U16Le::BYTES, 2);
    }

    #[test]
    fn u32le_encode_is_4_bytes(v in arb_u32()) {
        assert_eq!(U32Le::from_le(v).encode().len(), 4);
        assert_eq!(U32Le::BYTES, 4);
    }

    #[test]
    fn u64le_encode_is_8_bytes(v in arb_u64()) {
        assert_eq!(U64Le::from_le(v).encode().len(), 8);
        assert_eq!(U64Le::BYTES, 8);
    }

    #[test]
    fn i32le_encode_is_4_bytes(v in arb_i32()) {
        assert_eq!(I32Le::from_le(v).encode().len(), 4);
        assert_eq!(I32Le::BYTES, 4);
    }

    #[test]
    fn i64le_encode_is_8_bytes(v in arb_i64()) {
        assert_eq!(I64Le::from_le(v).encode().len(), 8);
        assert_eq!(I64Le::BYTES, 8);
    }

    #[test]
    fn schema_version_encode_is_4_bytes(v in arb_version()) {
        assert_eq!(v.encode().len(), 4);
    }

    #[test]
    fn schema_fingerprint_encode_is_32_bytes(fp in arb_fingerprint()) {
        assert_eq!(fp.encode().len(), 32);
    }

    #[test]
    fn feature_bits_encode_is_8_bytes(fb in arb_feature_bits()) {
        assert_eq!(fb.encode().len(), 8);
    }
}

// ── SchemaVersion can_read properties ──────────────────────────────

proptest! {
    #[test]
    fn schema_version_can_read_reflexive(v in arb_version()) {
        if v.major != 0 {
            assert!(v.can_read(&v));
        }
    }

    #[test]
    fn schema_version_zero_major_never_reads(
        min in any::<u16>(),
        w_maj in any::<u16>(),
        w_min in any::<u16>(),
    ) {
        let reader = SchemaVersion::new(0, min);
        let writer = SchemaVersion::new(w_maj, w_min);
        assert!(!reader.can_read(&writer));
    }

    #[test]
    fn schema_version_zero_writer_never_read(
        r_maj in 1u16..=u16::MAX,
        r_min in any::<u16>(),
    ) {
        let reader = SchemaVersion::new(r_maj, r_min);
        let writer = SchemaVersion::new(0, 0);
        assert!(!reader.can_read(&writer));
    }

    #[test]
    fn schema_version_major_mismatch_rejects(
        r_maj in 1u16..=u16::MAX,
        r_min in any::<u16>(),
        delta in 1u16..=u16::MAX,
        w_min in any::<u16>(),
    ) {
        let w_maj = r_maj.wrapping_add(delta);
        // If wrapping_add didn't change the value, force a difference
        let w_maj = if w_maj == r_maj { r_maj.wrapping_add(1) } else { w_maj };
        let reader = SchemaVersion::new(r_maj, r_min);
        let writer = SchemaVersion::new(w_maj, w_min);
        assert!(!reader.can_read(&writer));
    }

    #[test]
    fn schema_version_same_major_reader_newer_minor_can_read(
        maj in 1u16..=u16::MAX,
        w_min in 0u16..=32767u16,
        delta in 0u16..=32767u16,
    ) {
        // w_min + delta fits in u16 (max 32767+32767=65534), avoids overflow
        let r_min = w_min + delta;
        let reader = SchemaVersion::new(maj, r_min);
        let writer = SchemaVersion::new(maj, w_min);
        assert!(reader.can_read(&writer));
    }

    #[test]
    fn schema_version_same_major_reader_older_minor_cannot_read(
        maj in 1u16..=u16::MAX,
        r_min in 0u16..=32767u16,
        delta in 1u16..=32767u16,
    ) {
        // r_min + delta fits in u16 (max 32767+32767=65534), avoids overflow
        let w_min = r_min + delta;
        assert!(r_min < w_min);
        let reader = SchemaVersion::new(maj, r_min);
        let writer = SchemaVersion::new(maj, w_min);
        assert!(!reader.can_read(&writer));
    }

    #[test]
    fn schema_version_can_be_read_by_symmetry(
        r in arb_version(),
        w in arb_version(),
    ) {
        assert_eq!(w.can_be_read_by(&r), r.can_read(&w));
    }
}

// ── Sequential mixed primitive encode/decode ───────────────────────

#[derive(Clone, Debug)]
enum TaggedPrimitive {
    U16(U16Le),
    U32(U32Le),
    U64(U64Le),
    I32(I32Le),
    I64(I64Le),
    Version(SchemaVersion),
    Fingerprint(SchemaFingerprint),
}

impl TaggedPrimitive {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            Self::U16(v) => buf.extend_from_slice(&v.encode()),
            Self::U32(v) => buf.extend_from_slice(&v.encode()),
            Self::U64(v) => buf.extend_from_slice(&v.encode()),
            Self::I32(v) => buf.extend_from_slice(&v.encode()),
            Self::I64(v) => buf.extend_from_slice(&v.encode()),
            Self::Version(v) => buf.extend_from_slice(&v.encode()),
            Self::Fingerprint(v) => buf.extend_from_slice(&v.encode()),
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::U16(_) => 2,
            Self::U32(_) | Self::I32(_) => 4,
            Self::Version(_) => 4,
            Self::U64(_) | Self::I64(_) => 8,
            Self::Fingerprint(_) => 32,
        }
    }
}

fn arb_tagged_primitive() -> impl Strategy<Value = TaggedPrimitive> {
    prop_oneof![
        arb_u16().prop_map(|v| TaggedPrimitive::U16(U16Le::from_le(v))),
        arb_u32().prop_map(|v| TaggedPrimitive::U32(U32Le::from_le(v))),
        arb_u64().prop_map(|v| TaggedPrimitive::U64(U64Le::from_le(v))),
        arb_i32().prop_map(|v| TaggedPrimitive::I32(I32Le::from_le(v))),
        arb_i64().prop_map(|v| TaggedPrimitive::I64(I64Le::from_le(v))),
        arb_version().prop_map(TaggedPrimitive::Version),
        arb_fingerprint().prop_map(TaggedPrimitive::Fingerprint),
    ]
}

fn arb_primitive_sequence() -> impl Strategy<Value = Vec<TaggedPrimitive>> {
    proptest::collection::vec(arb_tagged_primitive(), 0..64)
}

proptest! {
    #[test]
    fn sequential_mixed_roundtrip(primitives in arb_primitive_sequence()) {
        let mut encoded: Vec<u8> = Vec::new();
        for p in &primitives {
            p.encode_into(&mut encoded);
        }

        let expected_len: usize = primitives.iter().map(|p| p.encoded_len()).sum();
        assert_eq!(encoded.len(), expected_len);

        let mut offset: usize = 0;
        for p in &primitives {
            match p {
                TaggedPrimitive::U16(orig) => {
                    let mut arr = [0u8; 2];
                    arr.copy_from_slice(&encoded[offset..offset + 2]);
                    assert_eq!(U16Le::from_le_bytes(arr), *orig);
                    offset += 2;
                }
                TaggedPrimitive::U32(orig) => {
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(&encoded[offset..offset + 4]);
                    assert_eq!(U32Le::from_le_bytes(arr), *orig);
                    offset += 4;
                }
                TaggedPrimitive::U64(orig) => {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&encoded[offset..offset + 8]);
                    assert_eq!(U64Le::from_le_bytes(arr), *orig);
                    offset += 8;
                }
                TaggedPrimitive::I32(orig) => {
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(&encoded[offset..offset + 4]);
                    assert_eq!(I32Le::from_le_bytes(arr), *orig);
                    offset += 4;
                }
                TaggedPrimitive::I64(orig) => {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&encoded[offset..offset + 8]);
                    assert_eq!(I64Le::from_le_bytes(arr), *orig);
                    offset += 8;
                }
                TaggedPrimitive::Version(orig) => {
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(&encoded[offset..offset + 4]);
                    assert_eq!(SchemaVersion::decode(arr), *orig);
                    offset += 4;
                }
                TaggedPrimitive::Fingerprint(orig) => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&encoded[offset..offset + 32]);
                    assert_eq!(SchemaFingerprint::decode(arr), *orig);
                    offset += 32;
                }
            }
        }
        assert_eq!(offset, encoded.len());
    }
}

// ── ContinuityWindow acceptance properties ──────────────────────────

fn arb_acceptance() -> impl Strategy<Value = Acceptance> {
    prop_oneof![
        Just(Acceptance::Accepted),
        Just(Acceptance::RejectMajorMismatch),
        Just(Acceptance::RejectMinorOutOfWindow),
        Just(Acceptance::RejectFeaturesUnsupported),
        Just(Acceptance::RejectFingerprintUnknown),
    ]
}

proptest! {
    #[test]
    fn acceptance_is_accepted_only_for_accepted(a in arb_acceptance()) {
        let ok = a.is_accepted();
        if matches!(a, Acceptance::Accepted) {
            assert!(ok);
        } else {
            assert!(!ok);
        }
    }

    #[test]
    fn continuity_window_accepts_deterministic(
        maj in any::<u16>(),
        min in any::<u16>(),
        fb_val in arb_u64(),
        fp_bytes in any::<[u8; 32]>(),
    ) {
        let window = ContinuityWindow {
            family_id: SchemaFamilyId::BINARY_SCHEMA,
            type_id: SchemaTypeId(1),
            major_version: maj,
            minor_min: min,
            minor_max: min.saturating_add(10),
            required_features: FeatureBits(fb_val),
            accepted_fingerprints: &[],
        };
        let fp = SchemaFingerprint(fp_bytes);
        let r1 = window.accepts(maj, min, FeatureBits(fb_val), fp);
        let r2 = window.accepts(maj, min, FeatureBits(fb_val), fp);
        assert_eq!(r1, r2);
    }

    #[test]
    fn continuity_window_empty_fingerprints_always_rejects_fp(
        maj in any::<u16>(),
        min in any::<u16>(),
        fb_val in arb_u64(),
        fp_bytes in any::<[u8; 32]>(),
    ) {
        let window = ContinuityWindow {
            family_id: SchemaFamilyId::BINARY_SCHEMA,
            type_id: SchemaTypeId(1),
            major_version: maj,
            minor_min: min,
            minor_max: min.saturating_add(10),
            required_features: FeatureBits(fb_val),
            accepted_fingerprints: &[],
        };
        let fp = SchemaFingerprint(fp_bytes);
        // With empty fingerprint list, only major/minor/features can pass.
        // Fingerprint will always be rejected.
        let result = window.accepts(maj, min, FeatureBits(fb_val), fp);
        if result == Acceptance::Accepted {
            // Should never happen with empty fingerprint list
            panic!("Accepted with empty fingerprint list");
        }
    }

    #[test]
    fn continuity_window_major_mismatch_rejects(
        window_maj in any::<u16>(),
        delta in 1u16..=u16::MAX,
        min in any::<u16>(),
        fb_val in arb_u64(),
        fp_bytes in any::<[u8; 32]>(),
    ) {
        let input_maj = window_maj.wrapping_add(delta);
        let window = ContinuityWindow {
            family_id: SchemaFamilyId::BINARY_SCHEMA,
            type_id: SchemaTypeId(1),
            major_version: window_maj,
            minor_min: min,
            minor_max: min.saturating_add(10),
            required_features: FeatureBits(fb_val),
            accepted_fingerprints: &[],
        };
        let fp = SchemaFingerprint(fp_bytes);
        assert_eq!(
            window.accepts(input_maj, min, FeatureBits(fb_val), fp),
            Acceptance::RejectMajorMismatch
        );
    }

    #[test]
    fn continuity_window_minor_outside_range_rejects(
        maj in any::<u16>(),
        win_min in any::<u16>(),
        win_span in 0u16..=u16::MAX,
        below in any::<bool>(),
        fb_val in arb_u64(),
        fp_bytes in any::<[u8; 32]>(),
    ) {
        let win_max = win_min.wrapping_add(win_span);
        // input_min is either below win_min (with wrapping) or above win_max
        let input_min = if below {
            win_min.wrapping_sub(1)
        } else {
            win_max.wrapping_add(1)
        };
        let window = ContinuityWindow {
            family_id: SchemaFamilyId::BINARY_SCHEMA,
            type_id: SchemaTypeId(1),
            major_version: maj,
            minor_min: win_min,
            minor_max: win_max,
            required_features: FeatureBits(fb_val),
            accepted_fingerprints: &[],
        };
        let fp = SchemaFingerprint(fp_bytes);
        let result = window.accepts(maj, input_min, FeatureBits(fb_val), fp);
        // Must be a rejection; which kind depends on major match
        assert!(!result.is_accepted());
    }
}

// ── ChunkFrameSizeClass payload_bytes consistency ──────────────────

proptest! {
    #[test]
    fn chunk_frame_payload_bytes_consistent(cls in arb_chunk_frame_size_class()) {
        let bytes = cls.payload_bytes();
        match cls {
            ChunkFrameSizeClass::KiB64 => assert_eq!(bytes, 64 * 1024),
            ChunkFrameSizeClass::KiB256 => assert_eq!(bytes, 256 * 1024),
            ChunkFrameSizeClass::MiB1 => assert_eq!(bytes, 1024 * 1024),
        }
    }
}

// ── DomainTag discriminants are distinct and non-zero ──────────────

#[test]
fn domain_tag_all_discriminants_distinct_and_nonzero() {
    let tags = [
        DomainTag::EnvelopeHeader,
        DomainTag::SectionBody,
        DomainTag::ChunkFrame,
        DomainTag::ExternalPayload,
        DomainTag::ReceiptBody,
        DomainTag::ValidationBundle,
        DomainTag::ArchiveBody,
        DomainTag::TransferStream,
    ];
    for t in &tags {
        assert!(t.discriminant() > 0, "DomainTag discriminant must be > 0");
    }
    for i in 0..tags.len() {
        for j in (i + 1)..tags.len() {
            assert_ne!(tags[i].discriminant(), tags[j].discriminant());
        }
    }
}

// ── BinarySchemaError Display + Debug non-empty ────────────────────

proptest! {
    #[test]
    fn binary_schema_error_display_nonempty(a in arb_acceptance()) {
        let errors: &[BinarySchemaError] = &[
            BinarySchemaError::BadMagic { got: 0xDEAD },
            BinarySchemaError::ChecksumMismatch,
            BinarySchemaError::DigestMismatch,
            BinarySchemaError::AlignmentViolation,
            BinarySchemaError::BoundsViolation,
            BinarySchemaError::InvalidBoolean,
            BinarySchemaError::InvalidChecksumProfile,
            BinarySchemaError::InvalidPayloadClass,
            BinarySchemaError::InvalidDomainTag,
            BinarySchemaError::ContinuityRejection(a),
            BinarySchemaError::EncodeError,
        ];
        for e in errors {
            let display = format!("{e}");
            assert!(!display.is_empty(), "Display empty for {e:?}");
            let debug = format!("{e:?}");
            assert!(!debug.is_empty(), "Debug empty for {e:?}");
        }
    }
}

// ── Compatibility matrix consistency ──────────────────────────────

#[test]
fn compatibility_matrix_entries_consistent() {
    for &(reader, writer, expected) in tidefs_binary_schema_core::compatibility_matrix() {
        assert_eq!(
            reader.can_read(&writer),
            expected,
            "Matrix entry: reader {reader:?} writer {writer:?} expected {expected}"
        );
    }
}

// ── LE wrapper From/Into round-trip ────────────────────────────────

proptest! {
    #[test]
    fn u16le_from_into_roundtrip(v in arb_u16()) {
        let le: U16Le = v.into();
        let raw: u16 = le.into();
        assert_eq!(raw, v);
    }

    #[test]
    fn u32le_from_into_roundtrip(v in arb_u32()) {
        let le: U32Le = v.into();
        let raw: u32 = le.into();
        assert_eq!(raw, v);
    }

    #[test]
    fn u64le_from_into_roundtrip(v in arb_u64()) {
        let le: U64Le = v.into();
        let raw: u64 = le.into();
        assert_eq!(raw, v);
    }

    #[test]
    fn i32le_from_into_roundtrip(v in arb_i32()) {
        let le: I32Le = v.into();
        let raw: i32 = le.into();
        assert_eq!(raw, v);
    }

    #[test]
    fn i64le_from_into_roundtrip(v in arb_i64()) {
        let le: I64Le = v.into();
        let raw: i64 = le.into();
        assert_eq!(raw, v);
    }
}

// ── LE wrapper Display is non-empty ────────────────────────────────

proptest! {
    #[test]
    fn u16le_display_nonempty(v in arb_u16()) {
        let s = format!("{}", U16Le::from_le(v));
        assert!(!s.is_empty());
    }

    #[test]
    fn i32le_display_nonempty(v in arb_i32()) {
        let s = format!("{}", I32Le::from_le(v));
        assert!(!s.is_empty());
    }

    #[test]
    fn u64le_display_nonempty(v in arb_u64()) {
        let s = format!("{}", U64Le::from_le(v));
        assert!(!s.is_empty());
    }
}

// ── SchemaFingerprint Display ends with ".." ────────────────────────

proptest! {
    #[test]
    fn schema_fingerprint_display_ends_with_dots(fp in arb_fingerprint()) {
        let s = format!("{fp}");
        assert!(s.ends_with(".."), "Fingerprint Display must end with ..: {s}");
        assert!(s.len() > 2);
    }
}

// ── SchemaFingerprint low_u64 round-trip ───────────────────────────

#[test]
fn schema_fingerprint_low_u64_roundtrip() {
    // Encode a u64 into the low bytes, then verify low_u64 recovers it
    let val: u64 = 0x0123_4567_89AB_CDEF;
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&val.to_le_bytes());
    let fp = SchemaFingerprint(bytes);
    assert_eq!(fp.low_u64(), val);
}

// ── LE wrapper defaults are zero ───────────────────────────────────

#[test]
fn le_wrapper_defaults_are_zero() {
    assert_eq!(U16Le::default().as_raw(), 0);
    assert_eq!(U32Le::default().as_raw(), 0);
    assert_eq!(U64Le::default().as_raw(), 0);
    assert_eq!(I32Le::default().as_raw(), 0);
    assert_eq!(I64Le::default().as_raw(), 0);
}

// ── Constant sanity ────────────────────────────────────────────────

#[test]
fn alignment_constants_are_power_of_two() {
    assert!(ENVELOPE_ALIGN.is_power_of_two());
    assert!(SECTION_OFFSET_ALIGN_MIN.is_power_of_two());
}

#[test]
fn header_sizes_are_8_byte_aligned() {
    assert_eq!(ENVELOPE_HEADER_BYTES % 8, 0);
    assert_eq!(SECTION_HEADER_BYTES % 8, 0);
}

#[test]
fn magic_constant_is_vbfs() {
    assert_eq!(BINARY_SCHEMA_MAGIC, 0x5346_4256);
    assert_eq!(&BINARY_SCHEMA_MAGIC.to_le_bytes(), b"VBFS");
}

#[test]
fn chunk_frame_sizes_increasing() {
    let sizes = [
        CHUNK_FRAME_SIZE_64K,
        CHUNK_FRAME_SIZE_256K,
        CHUNK_FRAME_SIZE_1M,
    ];
    assert!(sizes.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn schema_family_id_binary_schema_is_1() {
    assert_eq!(SchemaFamilyId::BINARY_SCHEMA.0, 1);
}

#[test]
fn schema_type_id_default_is_zero() {
    assert_eq!(SchemaTypeId::default().0, 0);
}

#[test]
fn checksum_profile_has_crc32c_predicates() {
    assert!(ChecksumProfile::Crc32c.has_crc32c());
    assert!(!ChecksumProfile::None.has_crc32c());
    assert!(!ChecksumProfile::Blake3_256.has_crc32c());
    assert!(ChecksumProfile::Crc32cPlusBlake3_256.has_crc32c());
}

#[test]
fn checksum_profile_has_blake3_predicates() {
    assert!(!ChecksumProfile::None.has_blake3());
    assert!(!ChecksumProfile::Crc32c.has_blake3());
    assert!(ChecksumProfile::Blake3_256.has_blake3());
    assert!(ChecksumProfile::Crc32cPlusBlake3_256.has_blake3());
}

// ── FeatureBits encode/decode from known values ─────────────────────

proptest! {
    #[test]
    fn feature_bits_encode_matches_raw_le(v in arb_u64()) {
        let fb = FeatureBits(v);
        let encoded = fb.encode();
        assert_eq!(encoded, v.to_le_bytes());
    }
}

// ── SchemaFamilyId and SchemaTypeId derived traits ──────────────────

#[test]
fn schema_family_id_eq_and_ord() {
    assert_eq!(SchemaFamilyId(10), SchemaFamilyId(10));
    assert_ne!(SchemaFamilyId(1), SchemaFamilyId(2));
    assert!(SchemaFamilyId(5) < SchemaFamilyId(10));
}

#[test]
fn schema_type_id_eq_and_default() {
    assert_eq!(SchemaTypeId(42), SchemaTypeId(42));
    assert_ne!(SchemaTypeId(1), SchemaTypeId(2));
    assert_eq!(SchemaTypeId::default(), SchemaTypeId(0));
}

// ── ContinuityWindow fingerprint matching ──────────────────────────

/// A static fingerprint list for tests that need non-empty fingerprint matching.
static FP_STATIC_LIST: &[SchemaFingerprint] = &[
    SchemaFingerprint([0xAAu8; 32]),
    SchemaFingerprint([0xBBu8; 32]),
    SchemaFingerprint([0xCCu8; 32]),
];

#[test]
fn continuity_window_fingerprint_list_matching() {
    let window = ContinuityWindow {
        family_id: SchemaFamilyId::BINARY_SCHEMA,
        type_id: SchemaTypeId(99),
        major_version: 1,
        minor_min: 0,
        minor_max: 10,
        required_features: FeatureBits(0),
        accepted_fingerprints: FP_STATIC_LIST,
    };

    // Known fingerprint in list → Accepted
    let fp_match = SchemaFingerprint([0xBBu8; 32]);
    assert_eq!(
        window.accepts(1, 5, FeatureBits(0), fp_match),
        Acceptance::Accepted
    );

    // Known fingerprint, first entry
    let fp_first = SchemaFingerprint([0xAAu8; 32]);
    assert_eq!(
        window.accepts(1, 5, FeatureBits(0), fp_first),
        Acceptance::Accepted
    );

    // Known fingerprint, last entry
    let fp_last = SchemaFingerprint([0xCCu8; 32]);
    assert_eq!(
        window.accepts(1, 5, FeatureBits(0), fp_last),
        Acceptance::Accepted
    );

    // Unknown fingerprint (zero)
    let fp_unknown = SchemaFingerprint::ZERO;
    assert_eq!(
        window.accepts(1, 5, FeatureBits(0), fp_unknown),
        Acceptance::RejectFingerprintUnknown
    );

    // Unknown fingerprint (different pattern)
    let fp_other = SchemaFingerprint([0x11u8; 32]);
    assert_eq!(
        window.accepts(1, 5, FeatureBits(0), fp_other),
        Acceptance::RejectFingerprintUnknown
    );
}

// ── SchemaVersion boundary round-trips ─────────────────────────────

#[test]
fn schema_version_boundary_roundtrip() {
    // Zero
    let v0 = SchemaVersion::new(0, 0);
    assert_eq!(SchemaVersion::decode(v0.encode()), v0);

    // u16::MAX both fields
    let vmax = SchemaVersion::new(u16::MAX, u16::MAX);
    assert_eq!(SchemaVersion::decode(vmax.encode()), vmax);

    // Asymmetric edges
    let v_asym = SchemaVersion::new(u16::MAX, 0);
    assert_eq!(SchemaVersion::decode(v_asym.encode()), v_asym);

    let v_asym2 = SchemaVersion::new(0, u16::MAX);
    assert_eq!(SchemaVersion::decode(v_asym2.encode()), v_asym2);
}

// ── ChunkFrameSizeClass discriminant values ────────────────────────

#[test]
fn chunk_frame_size_class_discriminant_values() {
    assert_eq!(ChunkFrameSizeClass::KiB64 as u16, 0);
    assert_eq!(ChunkFrameSizeClass::KiB256 as u16, 1);
    assert_eq!(ChunkFrameSizeClass::MiB1 as u16, 2);
}

// ── PayloadClass discriminant values ───────────────────────────────

#[test]
fn payload_class_discriminant_values() {
    assert_eq!(PayloadClass::FixedInline as u16, 1);
    assert_eq!(PayloadClass::VariableInline as u16, 2);
    assert_eq!(PayloadClass::ChunkFramed as u16, 3);
    assert_eq!(PayloadClass::ExternalRef as u16, 4);
}

// ── ChecksumProfile predicate consistency ──────────────────────────

#[test]
fn checksum_profile_predicate_consistency() {
    // None has neither
    assert!(!ChecksumProfile::None.has_crc32c());
    assert!(!ChecksumProfile::None.has_blake3());
    // Crc32c has crc32c but not blake3
    assert!(ChecksumProfile::Crc32c.has_crc32c());
    assert!(!ChecksumProfile::Crc32c.has_blake3());
    // Blake3_256 has blake3 but not crc32c
    assert!(!ChecksumProfile::Blake3_256.has_crc32c());
    assert!(ChecksumProfile::Blake3_256.has_blake3());
    // Crc32cPlusBlake3_256 has both
    assert!(ChecksumProfile::Crc32cPlusBlake3_256.has_crc32c());
    assert!(ChecksumProfile::Crc32cPlusBlake3_256.has_blake3());
}

// ── SchemaVersion can_read with max values ─────────────────────────

#[test]
fn schema_version_can_read_max_values() {
    let v1 = SchemaVersion::new(1, u16::MAX);
    let v1_0 = SchemaVersion::new(1, 0);
    assert!(v1.can_read(&v1_0));
    assert!(!v1_0.can_read(&v1));

    // Max major, different minors
    let vmax = SchemaVersion::new(u16::MAX, u16::MAX);
    assert!(!vmax.can_read(&v1_0)); // different major
    assert!(vmax.can_read(&vmax));
}

// ── SchemaFingerprint zero is all zero bytes ───────────────────────

#[test]
fn schema_fingerprint_zero_all_zero() {
    assert_eq!(SchemaFingerprint::ZERO.0, [0u8; 32]);
    assert_eq!(SchemaFingerprint::ZERO.low_u64(), 0);
    assert_eq!(SchemaFingerprint::default(), SchemaFingerprint::ZERO);
}
