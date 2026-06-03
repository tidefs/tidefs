// Property-based tests for tidefs-binary_schema-core serialization
// primitives. Gated behind the `proptest` feature so default test
// builds stay fast.

extern crate std;

use super::*;
use proptest::prelude::*;
use std::vec::Vec;

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
    (any::<u16>(), any::<u16>()).prop_map(|(maj, min)| SchemaVersion::new(maj, min))
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

// ── LE wrapper round-trip for arbitrary values ──────────────────────

proptest! {
    #[test]
    fn u16le_arbitrary_roundtrip(v in arb_u16()) {
        let le = U16Le::from_le(v);
        let decoded = U16Le::from_le_bytes(le.encode());
        assert_eq!(decoded, le);
        assert_eq!(decoded.as_raw(), v);
    }

    #[test]
    fn u32le_arbitrary_roundtrip(v in arb_u32()) {
        let le = U32Le::from_le(v);
        let decoded = U32Le::from_le_bytes(le.encode());
        assert_eq!(decoded, le);
        assert_eq!(decoded.as_raw(), v);
    }

    #[test]
    fn u64le_arbitrary_roundtrip(v in arb_u64()) {
        let le = U64Le::from_le(v);
        let decoded = U64Le::from_le_bytes(le.encode());
        assert_eq!(decoded, le);
        assert_eq!(decoded.as_raw(), v);
    }

    #[test]
    fn i32le_arbitrary_roundtrip(v in arb_i32()) {
        let le = I32Le::from_le(v);
        let decoded = I32Le::from_le_bytes(le.encode());
        assert_eq!(decoded, le);
        assert_eq!(decoded.as_raw(), v);
    }

    #[test]
    fn i64le_arbitrary_roundtrip(v in arb_i64()) {
        let le = I64Le::from_le(v);
        let decoded = I64Le::from_le_bytes(le.encode());
        assert_eq!(decoded, le);
        assert_eq!(decoded.as_raw(), v);
    }
}

// ── Schema structs round-trip ───────────────────────────────────────

proptest! {
    #[test]
    fn schema_version_arbitrary_roundtrip(v in arb_version()) {
        let bytes = v.encode();
        let decoded = SchemaVersion::decode(bytes);
        assert_eq!(decoded, v);
    }

    #[test]
    fn schema_fingerprint_arbitrary_roundtrip(fp in arb_fingerprint()) {
        let bytes = fp.encode();
        let decoded = SchemaFingerprint::decode(bytes);
        assert_eq!(decoded, fp);
    }

    #[test]
    fn feature_bits_arbitrary_roundtrip(fb in arb_feature_bits()) {
        let bytes = fb.encode();
        let expected: [u8; 8] = fb.0.to_le_bytes();
        assert_eq!(bytes, expected);
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
        assert_eq!(ChunkFrameSizeClass::from_discriminant(d), Some(cls));
    }

    #[test]
    fn canonical_bool_roundtrip(b in any::<bool>()) {
        let enc = canonical_bool(b);
        assert_eq!(decode_canonical_bool(enc), Some(b));
    }
}

// ── FeatureBits: with / has / subset consistency ────────────────────

proptest! {
    #[test]
    fn feature_bits_with_has(fb in arb_feature_bits(), bit in 0u32..64u32) {
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
    fn feature_bits_none_is_subset_of_any(fb in arb_feature_bits()) {
        assert!(FeatureBits::NONE.is_subset_of(fb));
    }
}

// ── Deterministic encoding (same input → same output) ──────────────

proptest! {
    #[test]
    fn u64le_deterministic(v in arb_u64()) {
        let a = U64Le::from_le(v);
        let b = U64Le::from_le(v);
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn u32le_deterministic(v in arb_u32()) {
        let a = U32Le::from_le(v);
        let b = U32Le::from_le(v);
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn schema_version_deterministic(m in any::<u16>(), n in any::<u16>()) {
        let a = SchemaVersion::new(m, n);
        let b = SchemaVersion::new(m, n);
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn schema_fingerprint_deterministic(bytes in any::<[u8; 32]>()) {
        let a = SchemaFingerprint(bytes);
        let b = SchemaFingerprint(bytes);
        assert_eq!(a.encode(), b.encode());
    }
}

// ── Invalid discriminant rejection ─────────────────────────────────

proptest! {
    #[test]
    fn checksum_profile_rejects_out_of_range(d in 4u8..=255u8) {
        assert_eq!(ChecksumProfile::from_discriminant(d), None);
    }

    #[test]
    fn payload_class_rejects_out_of_range(d in (5u16..=u16::MAX).prop_filter(
        "skip valid 1..=4, skip 0",
        |x| *x != 0u16))
    {
        assert_eq!(PayloadClass::from_discriminant(d), None);
    }

    #[test]
    fn payload_class_rejects_zero(d in Just(0u16)) {
        assert_eq!(PayloadClass::from_discriminant(d), None);
    }

    #[test]
    fn chunk_frame_size_rejects_out_of_range(d in 3u16..=u16::MAX) {
        assert_eq!(ChunkFrameSizeClass::from_discriminant(d), None);
    }

    #[test]
    fn canonical_bool_rejects_invalid(v in 2u8..=255u8) {
        assert_eq!(decode_canonical_bool(v), None);
    }
}

// ── Sequential encode/decode of mixed primitives ───────────────────

/// Tagged primitive for sequential round-trip testing.
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
}

impl PartialEq for TaggedPrimitive {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::U16(a), Self::U16(b)) => a == b,
            (Self::U32(a), Self::U32(b)) => a == b,
            (Self::U64(a), Self::U64(b)) => a == b,
            (Self::I32(a), Self::I32(b)) => a == b,
            (Self::I64(a), Self::I64(b)) => a == b,
            (Self::Version(a), Self::Version(b)) => a == b,
            (Self::Fingerprint(a), Self::Fingerprint(b)) => a == b,
            _ => false,
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
    proptest::collection::vec(arb_tagged_primitive(), 0..32)
}

proptest! {
    #[test]
    fn sequential_mixed_roundtrip(primitives in arb_primitive_sequence()) {
        // Encode all primitives sequentially into one buffer
        let mut encoded: Vec<u8> = Vec::new();
        for p in &primitives {
            p.encode_into(&mut encoded);
        }

        // Decode each and compare against the original
        let mut offset: usize = 0;
        for p in &primitives {
            match p {
                TaggedPrimitive::U16(orig) => {
                    let mut arr = [0u8; 2];
                    arr.copy_from_slice(&encoded[offset..offset + 2]);
                    offset += 2;
                    assert_eq!(U16Le::from_le_bytes(arr), *orig);
                }
                TaggedPrimitive::U32(orig) => {
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(&encoded[offset..offset + 4]);
                    offset += 4;
                    assert_eq!(U32Le::from_le_bytes(arr), *orig);
                }
                TaggedPrimitive::U64(orig) => {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&encoded[offset..offset + 8]);
                    offset += 8;
                    assert_eq!(U64Le::from_le_bytes(arr), *orig);
                }
                TaggedPrimitive::I32(orig) => {
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(&encoded[offset..offset + 4]);
                    offset += 4;
                    assert_eq!(I32Le::from_le_bytes(arr), *orig);
                }
                TaggedPrimitive::I64(orig) => {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&encoded[offset..offset + 8]);
                    offset += 8;
                    assert_eq!(I64Le::from_le_bytes(arr), *orig);
                }
                TaggedPrimitive::Version(orig) => {
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(&encoded[offset..offset + 4]);
                    offset += 4;
                    assert_eq!(SchemaVersion::decode(arr), *orig);
                }
                TaggedPrimitive::Fingerprint(orig) => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&encoded[offset..offset + 32]);
                    offset += 32;
                    assert_eq!(SchemaFingerprint::decode(arr), *orig);
                }
            }
        }
        assert_eq!(offset, encoded.len());
    }
}

// ── ContinuityWindow property: accepts is deterministic ────────────

proptest! {
    #[test]
    fn continuity_window_accepts_deterministic(
        maj in any::<u16>(),
        min in any::<u16>(),
        fb_val in arb_u64(),
        fp_bytes in any::<[u8; 32]>(),
    ) {
        static DUMMY_FP: &[SchemaFingerprint] = &[];
        // Always use empty fingerprint list to avoid lifetime issues;
        // the Acceptance result depends only on maj/min/features,
        // and we only test determinism of the call.
        let window = ContinuityWindow {
            family_id: SchemaFamilyId::BINARY_SCHEMA,
            type_id: SchemaTypeId(100),
            major_version: maj,
            minor_min: min,
            minor_max: min.saturating_add(10),
            required_features: FeatureBits(fb_val),
            accepted_fingerprints: DUMMY_FP,
        };
        let fp = SchemaFingerprint(fp_bytes);
        let r1 = window.accepts(maj, min, FeatureBits(fb_val), fp);
        let r2 = window.accepts(maj, min, FeatureBits(fb_val), fp);
        assert_eq!(r1, r2);
    }
}

// ── ChunkFrameSizeClass::payload_bytes is consistent ────────────────

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

// ── SchemaVersion encode produces exactly 4 bytes ──────────────────

proptest! {
    #[test]
    fn schema_version_encodes_4_bytes(v in arb_version()) {
        assert_eq!(v.encode().len(), 4);
    }

    #[test]
    fn schema_version_byte_stability(
        maj in any::<u16>(),
        min in any::<u16>(),
        _alt_min in any::<u16>(),
    ) {
        // Same major+minor → identical output
        let a = SchemaVersion::new(maj, min);
        let b = SchemaVersion::new(maj, min);
        assert_eq!(a.encode(), b.encode());
    }
}

// ── CanonicalBool: 0 and 1 are the only valid values ──────────────

proptest! {
    #[test]
    fn canonical_bool_only_0_or_1(v in any::<u8>()) {
        let decoded = decode_canonical_bool(v);
        if v == 0 {
            assert_eq!(decoded, Some(false));
        } else if v == 1 {
            assert_eq!(decoded, Some(true));
        } else {
            assert_eq!(decoded, None);
        }
    }
}
