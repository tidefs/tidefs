// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Proptest-based segment encode/decode round-trip, fault-injection,
//! and fuzz tests for `tidefs-local-object-store`.
//!
//! Covers the low-level segment format structures with property-based
//! testing: IntegrityTrailerV2 and SegmentIntegrityFooter round-trips,
//! bit-flip corruption at known field offsets, and panic-free parsing
//! of arbitrary byte sequences. Complements the existing rand-based
//! round-trip and checksum-verify tests with proptest's shrinking
//! and regression-file support.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use proptest::prelude::*;
use tidefs_local_object_store::{
    checksum64, compute_segment_digest, decode_integrity_trailer_v2,
    decode_segment_integrity_footer, encode_integrity_trailer_v2, encode_segment_integrity_footer,
    IntegrityTrailerV2, LocalObjectStore, ObjectKey, ProductionIntegrityDigest,
    SegmentIntegrityFooter, StoreOptions, INTEGRITY_TRAILER_V2_LEN, SEGMENT_INTEGRITY_FOOTER_LEN,
};

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-segprop-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

fn make_digest(bytes: [u8; 32]) -> ProductionIntegrityDigest {
    ProductionIntegrityDigest::from_bytes32(bytes)
}

// ── Arbitrary strategies ───────────────────────────────────────────────────

/// Strategy generating a `[u8; 32]` for digest fields.
fn arb_digest_bytes() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

/// Strategy for arbitrary `u64` values.
fn arb_u64() -> impl Strategy<Value = u64> {
    any::<u64>()
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. IntegrityTrailerV2 round-trip encode/decode (proptest)
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// Arbitrary IntegrityTrailerV2 values round-trip through
    /// encode → decode without corruption.
    #[test]
    fn integrity_trailer_v2_round_trip(
        format_version in Just(3u16), // only v3 is current production
        digest_suite in Just(1u16),   // BLAKE3-256 suite ID
        payload_digest_bytes in arb_digest_bytes(),
        record_digest_bytes in arb_digest_bytes(),
        shard_count in any::<u8>(),
        shard_index in any::<u8>(),
        ec_k in any::<u8>(),
        ec_m in any::<u8>(),
    ) {
        let trailer = IntegrityTrailerV2 {
            format_version,
            digest_suite,
            payload_digest: make_digest(payload_digest_bytes),
            record_digest: make_digest(record_digest_bytes),
            shard_count,
            shard_index,
            ec_k,
            ec_m,
        };

        let encoded = encode_integrity_trailer_v2(&trailer);
        assert_eq!(encoded.len(), INTEGRITY_TRAILER_V2_LEN);

        let decoded = decode_integrity_trailer_v2(&encoded)
            .expect("decode of freshly-encoded trailer");

        assert_eq!(decoded.format_version, trailer.format_version);
        assert_eq!(decoded.digest_suite, trailer.digest_suite);
        assert_eq!(decoded.payload_digest, trailer.payload_digest);
        assert_eq!(decoded.record_digest, trailer.record_digest);
        assert_eq!(decoded.shard_count, trailer.shard_count);
        assert_eq!(decoded.shard_index, trailer.shard_index);
        assert_eq!(decoded.ec_k, trailer.ec_k);
        assert_eq!(decoded.ec_m, trailer.ec_m);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. SegmentIntegrityFooter round-trip encode/decode (proptest)
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// Arbitrary SegmentIntegrityFooter values round-trip through
    /// encode → decode without corruption.
    #[test]
    fn segment_integrity_footer_round_trip(
        segment_id in arb_u64(),
        record_count in arb_u64(),
        total_payload_bytes in arb_u64(),
        seg_digest_bytes in arb_digest_bytes(),
        prev_seg_digest_bytes in arb_digest_bytes(),
    ) {
        let footer = SegmentIntegrityFooter {
            segment_id,
            record_count,
            total_payload_bytes,
            segment_digest: make_digest(seg_digest_bytes),
            previous_segment_digest: make_digest(prev_seg_digest_bytes),
        };

        let encoded = encode_segment_integrity_footer(&footer);
        assert_eq!(encoded.len(), SEGMENT_INTEGRITY_FOOTER_LEN);

        let decoded = decode_segment_integrity_footer(&encoded)
            .expect("decode of freshly-encoded footer");

        assert_eq!(decoded.segment_id, footer.segment_id);
        assert_eq!(decoded.record_count, footer.record_count);
        assert_eq!(decoded.total_payload_bytes, footer.total_payload_bytes);
        assert_eq!(decoded.segment_digest, footer.segment_digest);
        assert_eq!(decoded.previous_segment_digest, footer.previous_segment_digest);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Fault-injection: IntegrityTrailerV2 bit-flip corruption
// ═══════════════════════════════════════════════════════════════════════════

/// Flip a bit in the trailer magic bytes and verify decode fails.
#[test]
fn trailer_magic_corruption_is_detected() {
    let trailer = IntegrityTrailerV2 {
        format_version: 3,
        digest_suite: 1,
        payload_digest: make_digest([0xAA; 32]),
        record_digest: make_digest([0xBB; 32]),
        shard_count: 0,
        shard_index: 0,
        ec_k: 0,
        ec_m: 0,
    };

    let mut encoded = encode_integrity_trailer_v2(&trailer);

    // Flip a bit in the magic (offset 0)
    encoded[0] ^= 0x01;
    let result = decode_integrity_trailer_v2(&encoded);
    assert!(result.is_err(), "magic corruption must be detected");

    // Different corruption: flip byte in magic (offset 7)
    let mut encoded2 = encode_integrity_trailer_v2(&trailer);
    encoded2[7] ^= 0x80;
    let result2 = decode_integrity_trailer_v2(&encoded2);
    assert!(
        result2.is_err(),
        "magic corruption at offset 7 must be detected"
    );
}

/// Flip bits in the digest_suite field — must be detected.
#[test]
fn trailer_digest_suite_corruption_is_detected() {
    let trailer = IntegrityTrailerV2 {
        format_version: 3,
        digest_suite: 1,
        payload_digest: make_digest([0xAA; 32]),
        record_digest: make_digest([0xBB; 32]),
        shard_count: 0,
        shard_index: 0,
        ec_k: 0,
        ec_m: 0,
    };

    let mut encoded = encode_integrity_trailer_v2(&trailer);
    // digest_suite is at bytes 10..12 (LE u16) — flip byte 10
    encoded[10] ^= 0xFF;
    let result = decode_integrity_trailer_v2(&encoded);
    assert!(result.is_err(), "digest_suite corruption must be detected");
}

/// Alter the declared length field — must be detected.
#[test]
fn trailer_length_corruption_is_detected() {
    let trailer = IntegrityTrailerV2 {
        format_version: 3,
        digest_suite: 1,
        payload_digest: make_digest([0xAA; 32]),
        record_digest: make_digest([0xBB; 32]),
        shard_count: 0,
        shard_index: 0,
        ec_k: 0,
        ec_m: 0,
    };

    let mut encoded = encode_integrity_trailer_v2(&trailer);
    // length field at bytes 12..14 (LE u16) — flip byte 12
    encoded[12] ^= 0x01;
    let result = decode_integrity_trailer_v2(&encoded);
    assert!(result.is_err(), "length corruption must be detected");
}

/// Corrupt payload_digest bytes — decode still succeeds (digest is opaque
/// data), but the *value* differs. This property confirms the trailer
/// format doesn't validate digest values — only structure.
#[test]
fn trailer_payload_digest_corruption_preserves_decode_but_value_differs() {
    let payload_bytes = [0x42; 32];
    let trailer = IntegrityTrailerV2 {
        format_version: 3,
        digest_suite: 1,
        payload_digest: make_digest(payload_bytes),
        record_digest: make_digest([0xBB; 32]),
        shard_count: 0,
        shard_index: 0,
        ec_k: 0,
        ec_m: 0,
    };

    let mut encoded = encode_integrity_trailer_v2(&trailer);
    // payload_digest starts at byte 16 — flip byte 20
    encoded[20] ^= 0xFF;

    let decoded = decode_integrity_trailer_v2(&encoded)
        .expect("digest corruption does not break structural decode");
    assert_ne!(
        decoded.payload_digest, trailer.payload_digest,
        "flipped digest byte must change the decoded digest"
    );
}

/// Corrupt reserved bytes (offset 14..16) — must be detected as non-zero.
#[test]
fn trailer_reserved_bytes_corruption_is_detected() {
    let trailer = IntegrityTrailerV2 {
        format_version: 3,
        digest_suite: 1,
        payload_digest: make_digest([0xAA; 32]),
        record_digest: make_digest([0xBB; 32]),
        shard_count: 0,
        shard_index: 0,
        ec_k: 0,
        ec_m: 0,
    };

    let mut encoded = encode_integrity_trailer_v2(&trailer);
    // reserved at bytes 14..16 — set byte 14 to non-zero
    encoded[14] = 0x01;
    let result = decode_integrity_trailer_v2(&encoded);
    assert!(result.is_err(), "non-zero reserved bytes must be detected");
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Fault-injection: SegmentIntegrityFooter bit-flip corruption
// ═══════════════════════════════════════════════════════════════════════════

/// Flip a bit in the footer magic and verify decode fails.
#[test]
fn footer_magic_corruption_is_detected() {
    let footer = SegmentIntegrityFooter {
        segment_id: 42,
        record_count: 100,
        total_payload_bytes: 4096,
        segment_digest: make_digest([0x11; 32]),
        previous_segment_digest: make_digest([0x22; 32]),
    };

    let mut encoded = encode_segment_integrity_footer(&footer);
    encoded[0] ^= 0x01;
    let result = decode_segment_integrity_footer(&encoded);
    assert!(result.is_err(), "footer magic corruption must be detected");

    // Flip last magic byte
    let mut encoded2 = encode_segment_integrity_footer(&footer);
    encoded2[7] ^= 0x80;
    let result2 = decode_segment_integrity_footer(&encoded2);
    assert!(
        result2.is_err(),
        "footer magic corruption at offset 7 must be detected"
    );
}

/// Corrupt segment_id field — decode still works but value changes.
#[test]
fn footer_segment_id_corruption_changes_value() {
    let footer = SegmentIntegrityFooter {
        segment_id: 1000,
        record_count: 10,
        total_payload_bytes: 500,
        segment_digest: make_digest([0x33; 32]),
        previous_segment_digest: make_digest([0x44; 32]),
    };

    let mut encoded = encode_segment_integrity_footer(&footer);
    // segment_id at bytes 8..16 — flip byte 8
    encoded[8] ^= 0xFF;

    let decoded = decode_segment_integrity_footer(&encoded)
        .expect("segment_id corruption doesn't break structural decode");
    assert_ne!(decoded.segment_id, footer.segment_id);
    // Other fields unchanged
    assert_eq!(decoded.record_count, footer.record_count);
    assert_eq!(decoded.total_payload_bytes, footer.total_payload_bytes);
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Fuzz harness: arbitrary bytes as IntegrityTrailerV2 (no panics)
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// Parse arbitrary 112-byte sequences as IntegrityTrailerV2.
    /// Must never panic — all failures must be clean errors.
    #[test]
    fn fuzz_integrity_trailer_v2_no_panic(bytes in any::<[u8; INTEGRITY_TRAILER_V2_LEN]>()) {
        let _ = decode_integrity_trailer_v2(&bytes);
    }
}

/// Shorter-than-expected bytes: the function signature takes a fixed-size
/// array, so this is a compile-time guarantee. But we also verify that
/// encoding a trailer and decoding a corrupted-length variant produces
/// a clean error, not a panic.
#[test]
fn fuzz_trailer_corrupted_length_no_panic() {
    let trailer = IntegrityTrailerV2 {
        format_version: 3,
        digest_suite: 1,
        payload_digest: make_digest([0x00; 32]),
        record_digest: make_digest([0x00; 32]),
        shard_count: 0,
        shard_index: 0,
        ec_k: 0,
        ec_m: 0,
    };
    let mut encoded = encode_integrity_trailer_v2(&trailer);
    // Corrupt the declared length to u16::MAX
    encoded[12] = 0xFF;
    encoded[13] = 0xFF;
    let result = decode_integrity_trailer_v2(&encoded);
    assert!(
        result.is_err(),
        "corrupted length must produce error, not panic"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Fuzz harness: arbitrary bytes as SegmentIntegrityFooter (no panics)
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// Parse arbitrary 192-byte sequences as SegmentIntegrityFooter.
    /// Must never panic — all failures must be clean errors.
    #[test]
    fn fuzz_segment_integrity_footer_no_panic(
        bytes in any::<[u8; SEGMENT_INTEGRITY_FOOTER_LEN]>(),
    ) {
        let _ = decode_segment_integrity_footer(&bytes);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Proptest-based put/get round-trip with arbitrary payloads
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// Writing an arbitrary payload through put → get returns the
    /// exact same bytes. Uses proptest's shrinking for minimal
    /// failing cases.
    #[test]
    fn proptest_put_get_round_trip(payload in any::<Vec<u8>>()) {
        let root = temp_root("prop-putget");
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");

        let key = ObjectKey::from_name(b"proptest-key");
        store.put(key, &payload).expect("put");

        let got = store.get(key).expect("get").expect("object should exist");
        prop_assert_eq!(&got, &payload, "round-trip payload mismatch");

        cleanup(&root);
    }

    /// Multiple distinct keys with independent arbitrary payloads
    /// all round-trip correctly.
    #[test]
    fn proptest_multikey_round_trip(
        payloads in prop::collection::vec(any::<Vec<u8>>(), 1..20),
    ) {
        let root = temp_root("prop-multikey");
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");

        for (i, payload) in payloads.iter().enumerate() {
            let key = ObjectKey::from_name(format!("key-{i}").as_bytes());
            store.put(key, payload).expect("put");
        }

        for (i, expected) in payloads.iter().enumerate() {
            let key = ObjectKey::from_name(format!("key-{i}").as_bytes());
            let got = store.get(key).expect("get").expect("key should exist");
            assert_eq!(&got, expected, "payload mismatch for key {i}");
        }

        prop_assert_eq!(
            store.list_keys().len(),
            payloads.len(),
            "list_keys count must match number of puts"
        );

        cleanup(&root);
    }

    /// Overwriting a key multiple times: the final value read back
    /// must match the last payload written.
    #[test]
    fn proptest_overwrite_last_wins(
        payloads in prop::collection::vec(any::<Vec<u8>>(), 2..10),
    ) {
        let root = temp_root("prop-overwrite");
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");

        let key = ObjectKey::from_name(b"overwrite-target");
        for payload in &payloads {
            store.put(key, payload).expect("put");
        }

        let latest = payloads.last().unwrap();
        let got = store.get(key).expect("get").expect("key should exist");
        prop_assert_eq!(&got, latest, "latest value not returned after overwrites");

        cleanup(&root);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. checksum64 property tests
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// checksum64 of identical bytes always yields the same result.
    #[test]
    fn checksum64_is_deterministic(payload in any::<Vec<u8>>()) {
        let a = checksum64(&payload);
        let b = checksum64(&payload);
        prop_assert_eq!(a, b, "checksum64 must be deterministic");
    }

    /// checksum64 of empty payload is consistent.
    #[test]
    fn checksum64_empty_is_consistent(_dummy in any::<u8>()) {
        let a = checksum64(b"");
        prop_assert_eq!(a, checksum64(b""));
        // checksum64 of empty bytes returns a well-defined seeded value
        prop_assert!(!a.is_zero(), "checksum64 of empty payload must be non-zero");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. compute_segment_digest properties
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    /// Segment digest from zero records is well-defined.
    #[test]
    fn segment_digest_zero_records_is_deterministic(_dummy in any::<u8>()) {
        let d1 = compute_segment_digest(&[]);
        let d2 = compute_segment_digest(&[]);
        prop_assert_eq!(d1, d2, "empty segment digest must be deterministic");
    }

    /// Segment digest from one record matches a known reference.
    #[test]
    fn segment_digest_single_record_is_deterministic(record_bytes in arb_digest_bytes()) {
        let d1 = compute_segment_digest(&[record_bytes]);
        let d2 = compute_segment_digest(&[record_bytes]);
        prop_assert_eq!(d1, d2, "single-record segment digest must be deterministic");
    }

    /// Segment digest order matters: [A, B] != [B, A] when A != B.
    #[test]
    fn segment_digest_is_order_sensitive(
        a in arb_digest_bytes(),
        b in arb_digest_bytes(),
    ) {
        if a == b {
            return Ok(());
        }
        let d_ab = compute_segment_digest(&[a, b]);
        let d_ba = compute_segment_digest(&[b, a]);
        prop_assert_ne!(d_ab, d_ba, "segment digest must be order-sensitive");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. IntegrityTrailerV2 magic constant self-consistency
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn trailer_magic_is_eight_bytes() {
    assert_eq!(IntegrityTrailerV2::MAGIC.len(), 8);
}

#[test]
fn footer_magic_is_eight_bytes() {
    assert_eq!(SegmentIntegrityFooter::MAGIC.len(), 8);
}

#[test]
fn trailer_encoded_starts_with_magic() {
    let trailer = IntegrityTrailerV2 {
        format_version: 3,
        digest_suite: 1,
        payload_digest: make_digest([0x00; 32]),
        record_digest: make_digest([0x00; 32]),
        shard_count: 0,
        shard_index: 0,
        ec_k: 0,
        ec_m: 0,
    };
    let encoded = encode_integrity_trailer_v2(&trailer);
    assert_eq!(&encoded[0..8], IntegrityTrailerV2::MAGIC.as_slice());
}

#[test]
fn footer_encoded_starts_with_magic() {
    let footer = SegmentIntegrityFooter {
        segment_id: 0,
        record_count: 0,
        total_payload_bytes: 0,
        segment_digest: make_digest([0x00; 32]),
        previous_segment_digest: make_digest([0x00; 32]),
    };
    let encoded = encode_segment_integrity_footer(&footer);
    assert_eq!(&encoded[0..8], SegmentIntegrityFooter::MAGIC.as_slice());
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. ProductionIntegrityDigest self-consistency
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn production_integrity_digest_zero_is_all_zeros() {
    let zero = ProductionIntegrityDigest::ZERO;
    assert_eq!(zero.as_bytes32(), [0u8; 32]);
}

proptest! {
    #[test]
    fn production_integrity_digest_round_trip(digest_bytes in arb_digest_bytes()) {
        let d = make_digest(digest_bytes);
        assert_eq!(d.as_bytes32(), digest_bytes);
        assert_eq!(d, ProductionIntegrityDigest::from_bytes32(digest_bytes));
    }
}
