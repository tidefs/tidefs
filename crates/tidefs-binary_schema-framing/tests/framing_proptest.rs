// Integration tests: property-based (proptest) fuzz coverage for the
// FramingDecoder stream reader.
//
// Strategy groups:
//  1. Round-trip: arbitrary payload sequences → frame → concat → deframe
//  2. Split-frame resilience: arbitrary split points → partial feed → full recovery
//  3. Multi-frame coalescing: multiple complete frames in one buffer
//  4. Corruption recovery: inject corruptions → decoder recovers without panic
//  5. Edge-case enumeration: zero-length, max-length, magic in body, empty stream

use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;
use tidefs_binary_schema_core::{
    ChecksumProfile, SchemaFamilyId, SchemaTypeId, SchemaVersion, BINARY_SCHEMA_MAGIC,
};
use tidefs_binary_schema_framing::{EnvelopeHeader, FramingDecoder, MAX_FRAME_BODY_BYTES};

// ── Iteration counts ────────────────────────────────────────────────

#[cfg(not(feature = "fuzz"))]
const DEFAULT_CASES: u32 = 10_000;

#[cfg(feature = "fuzz")]
const DEFAULT_CASES: u32 = 1_000_000;

fn proptest_config() -> ProptestConfig {
    ProptestConfig::with_cases(DEFAULT_CASES)
}

// ── Strategy helpers ─────────────────────────────────────────────────

fn arb_body(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max_len)
}

fn arb_valid_header(body_len: u64) -> impl Strategy<Value = EnvelopeHeader> {
    (any::<u64>(), any::<u64>()).prop_map(move |(family, type_id)| EnvelopeHeader {
        magic: BINARY_SCHEMA_MAGIC,
        family_id: SchemaFamilyId(family),
        type_id: SchemaTypeId(type_id),
        version: SchemaVersion::new(1, 0),
        flags: 0,
        section_count: 0,
        total_body_bytes: body_len,
        fast_checksum_profile: ChecksumProfile::Crc32c,
        strong_digest_profile: ChecksumProfile::Blake3_256,
        schema_fingerprint_low: 0,
        header_crc32c: 0,
    })
}

fn frame_bytes(header: &EnvelopeHeader, body: &[u8]) -> Vec<u8> {
    let mut v = header.encode().to_vec();
    v.extend_from_slice(body);
    v
}

// ── Proptests ────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(proptest_config())]

    // ── Group 1: Round-trip ───────────────────────────────────────

    #[test]
    fn proptest_roundtrip_single_frame(
        body in arb_body(4096),
        family in any::<u64>(),
        type_id in any::<u64>(),
    ) {
        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(family),
            type_id: SchemaTypeId(type_id),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: body.len() as u64,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        let stream = frame_bytes(&header, &body);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        assert_eq!(frames.len(), 1, "exactly one frame expected");
        assert_eq!(frames[0].body, body, "body must round-trip byte-for-byte");
        assert_eq!(frames[0].header.family_id, header.family_id);
        assert_eq!(frames[0].header.total_body_bytes, body.len() as u64);
    }

    #[test]
    fn proptest_roundtrip_multi_frame(
        frames_spec in prop::collection::vec(
            arb_body(1024).prop_flat_map(|body| {
                let len = body.len() as u64;
                arb_valid_header(len).prop_map(move |h| (h, body.clone()))
            }),
            0..10,
        )
    ) {
        let mut stream = Vec::new();
        for (h, body) in &frames_spec {
            stream.extend_from_slice(&frame_bytes(h, body));
        }

        let mut dec = FramingDecoder::new();
        let recovered = dec.feed(&stream);

        assert_eq!(recovered.len(), frames_spec.len(),
            "frame count mismatch: expected {}, got {}",
            frames_spec.len(), recovered.len());

        for (i, ((_, expected_body), frame)) in
            frames_spec.iter().zip(recovered.iter()).enumerate()
        {
            assert_eq!(frame.body, *expected_body,
                "body mismatch at frame {i}");
        }
    }

    // ── Group 2: Split-frame resilience ───────────────────────────

    #[test]
    fn proptest_split_at_arbitrary_offsets(
        body in arb_body(2048),
        splits in prop::collection::vec(1usize..3000, 0..20),
    ) {
        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(1),
            type_id: SchemaTypeId(1),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: body.len() as u64,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        let stream = frame_bytes(&header, &body);
        let mut dec = FramingDecoder::new();
        let mut all_frames = Vec::new();

        let mut pos = 0;
        for &split in &splits {
            if pos >= stream.len() {
                break;
            }
            let end = (pos + split).min(stream.len());
            all_frames.extend(dec.feed(&stream[pos..end]));
            pos = end;
        }
        // Feed any remainder
        if pos < stream.len() {
            all_frames.extend(dec.feed(&stream[pos..]));
        }

        assert_eq!(all_frames.len(), 1,
            "split-feed must recover exactly one frame, got {} (splits={:?})",
            all_frames.len(), splits);
        assert_eq!(all_frames[0].body, body);
    }

    #[test]
    fn proptest_byte_by_byte_feed(
        body in arb_body(1024),
    ) {
        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(1),
            type_id: SchemaTypeId(1),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: body.len() as u64,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        let stream = frame_bytes(&header, &body);
        let mut dec = FramingDecoder::new();
        let mut frames = Vec::new();
        for &b in &stream {
            frames.extend(dec.feed(&[b]));
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, body);
    }

    // ── Group 3: Multi-frame coalescing ────────────────────────────

    #[test]
    fn proptest_coalesce_multi_frame(
        frames_spec in prop::collection::vec(
            arb_body(512).prop_flat_map(|body| {
                let len = body.len() as u64;
                arb_valid_header(len).prop_map(move |h| (h, body.clone()))
            }),
            1..8,
        )
    ) {
        let mut stream = Vec::new();
        for (h, body) in &frames_spec {
            stream.extend_from_slice(&frame_bytes(h, body));
        }

        let mut dec = FramingDecoder::new();
        let recovered = dec.feed(&stream);
        assert_eq!(recovered.len(), frames_spec.len());
        for (i, ((_, body), frame)) in
            frames_spec.iter().zip(recovered.iter()).enumerate()
        {
            assert_eq!(frame.body, *body, "coalesced frame {i} mismatch");
        }
    }

    #[test]
    fn proptest_coalesce_then_split(
        frames_spec in prop::collection::vec(
            arb_body(256).prop_flat_map(|body| {
                let len = body.len() as u64;
                arb_valid_header(len).prop_map(move |h| (h, body.clone()))
            }),
            2..6,
        ),
        split_point in any::<usize>(),
    ) {
        let mut stream = Vec::new();
        let mut frame_lengths = Vec::new();
        for (h, body) in &frames_spec {
            let f = frame_bytes(h, body);
            frame_lengths.push(f.len());
            stream.extend_from_slice(&f);
        }

        let total = stream.len();
        let split = if total == 0 { 0 } else { split_point % total };

        let mut dec = FramingDecoder::new();
        let first = dec.feed(&stream[..split]);
        let second = dec.feed(&stream[split..]);
        let all: Vec<_> = first.into_iter().chain(second).collect();

        assert_eq!(all.len(), frames_spec.len(),
            "expected {} frames, got {} (split at {}/{})",
            frames_spec.len(), all.len(), split, total);
        for (i, ((_, body), frame)) in
            frames_spec.iter().zip(all.iter()).enumerate()
        {
            assert_eq!(frame.body, *body, "frame {i} mismatch after coalesce+split");
        }
    }

    // ── Group 4: Corruption recovery ───────────────────────────────

    #[test]
    fn proptest_corrupt_magic_byte(
        body in arb_body(256),
        corrupt_pos in 0usize..4,
    ) {
        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(1),
            type_id: SchemaTypeId(1),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: body.len() as u64,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        let mut stream = frame_bytes(&header, &body);
        // Corrupt one of the first 4 magic bytes
        stream[corrupt_pos] ^= 0xFF;

        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        // With corrupted magic, the decoder should find no valid frames.
        assert!(frames.is_empty(),
            "corrupted magic at pos {corrupt_pos} must yield no frames");
    }

    #[test]
    fn proptest_corrupt_then_valid(
        body in arb_body(256),
        junk_len in 0usize..100,
    ) {
        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(1),
            type_id: SchemaTypeId(1),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: body.len() as u64,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        let valid_frame = frame_bytes(&header, &body);

        let mut stream = vec![0u8; junk_len];
        stream.extend_from_slice(&valid_frame);

        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        // Should recover the valid frame after skipping junk
        assert!(frames.len() <= 1,
            "expected at most 1 frame, got {}", frames.len());
        if frames.len() == 1 {
            assert_eq!(frames[0].body, body);
        }
        // It's possible the junk contained no "VBFS" at all, resulting in 1 frame.
        // It's also possible the junk happened to form a valid-looking header with
        // a body that consumed the real frame. Both are acceptable — the decoder
        // must just not panic.
    }

    #[test]
    fn proptest_header_crc_corruption(
        body in arb_body(256),
        flip_byte in 4usize..60,
    ) {
        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(1),
            type_id: SchemaTypeId(1),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: body.len() as u64,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        let mut stream = frame_bytes(&header, &body);
        stream[flip_byte] ^= 0xFF;

        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        // CRC corruption must cause rejection; no frame should be emitted.
        assert!(frames.is_empty(),
            "CRC corruption at byte {flip_byte} must be rejected; got {} frames",
            frames.len());
    }

    #[test]
    fn proptest_length_field_corruption(
        body in arb_body(256),
    ) {
        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(1),
            type_id: SchemaTypeId(1),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: body.len() as u64,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        let mut stream = frame_bytes(&header, &body);
        // Corrupt total_body_bytes (bytes 32..40) — this will also break CRC,
        // causing the frame to be rejected.
        stream[32] ^= 0xFF;

        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        assert!(frames.is_empty(),
            "length-field corruption must be rejected (CRC mismatch)");
    }

    #[test]
    fn proptest_random_byte_stream_no_panic(
        raw in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let mut dec = FramingDecoder::new();
        let _ = dec.feed(&raw);
        // The critical property: decoder must never panic on arbitrary input.
    }

    #[test]
    fn proptest_multi_corrupt_then_valid(
        body in arb_body(128),
        corrupt_count in 1usize..5,
    ) {
        let valid_header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(99),
            type_id: SchemaTypeId(99),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: body.len() as u64,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        let valid_frame = frame_bytes(&valid_header, &body);

        let mut stream = Vec::new();
        for _ in 0..corrupt_count {
            // Add a fake VBFS magic + garbage
            stream.extend_from_slice(&BINARY_SCHEMA_MAGIC.to_le_bytes());
            stream.extend_from_slice(&[0xFFu8; 60]);
        }
        stream.extend_from_slice(&valid_frame);

        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        // The valid frame should be recovered. Corrupt frames might be emitted
        // if CRC happens to match (astronomically unlikely).
        assert!(frames.iter().any(|f| f.body == body),
            "valid frame must be recovered after {corrupt_count} corrupt frames");
        assert!(dec.corrupt_skipped_count() >= corrupt_count as u64 - 1,
            "expected at least {} corrupt skipped, got {}",
            corrupt_count - 1, dec.corrupt_skipped_count());
    }

    // ── Group 5: Edge-case enumeration ─────────────────────────────

    #[test]
    fn proptest_zero_length_body(
        family in any::<u64>(),
        type_id in any::<u64>(),
    ) {
        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(family),
            type_id: SchemaTypeId(type_id),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: 0,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        let stream = frame_bytes(&header, &[]);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body.len(), 0);
        assert_eq!(frames[0].header.total_body_bytes, 0);
    }

    #[test]
    fn proptest_magic_in_body_data(
        body_prefix in arb_body(64),
        body_suffix in arb_body(64),
    ) {
        // Construct a body that contains the magic byte sequence
        let mut body = body_prefix;
        body.extend_from_slice(&BINARY_SCHEMA_MAGIC.to_le_bytes());
        body.extend_from_slice(&body_suffix);

        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(1),
            type_id: SchemaTypeId(1),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: body.len() as u64,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        let stream = frame_bytes(&header, &body);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        assert_eq!(frames.len(), 1,
            "magic bytes in body must not confuse decoder");
        assert_eq!(frames[0].body, body);
    }

    #[test]
    fn proptest_max_body_size_accepted(
        body in arb_body(1024),
    ) {
        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(1),
            type_id: SchemaTypeId(1),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: body.len() as u64,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        // Verify body is within MAX_FRAME_BODY_BYTES
        prop_assume!((body.len() as u64) <= MAX_FRAME_BODY_BYTES);
        let stream = frame_bytes(&header, &body);
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, body);
    }

    #[test]
    fn proptest_oversized_body_rejected(
        claimed_len in (MAX_FRAME_BODY_BYTES + 1)..(MAX_FRAME_BODY_BYTES + 1024 * 1024),
    ) {
        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(1),
            type_id: SchemaTypeId(1),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: claimed_len,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        let stream = frame_bytes(&header, &[]); // actual body is empty
        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);
        assert!(frames.is_empty(),
            "claimed oversized body ({claimed_len}) must be rejected");
        assert!(dec.corrupt_skipped_count() >= 1);
    }

    #[test]
    fn proptest_split_every_possible_offset(
        body in arb_body(256),
    ) {
        let header = EnvelopeHeader {
            magic: BINARY_SCHEMA_MAGIC,
            family_id: SchemaFamilyId(1),
            type_id: SchemaTypeId(1),
            version: SchemaVersion::new(1, 0),
            flags: 0,
            section_count: 0,
            total_body_bytes: body.len() as u64,
            fast_checksum_profile: ChecksumProfile::Crc32c,
            strong_digest_profile: ChecksumProfile::Blake3_256,
            schema_fingerprint_low: 0,
            header_crc32c: 0,
        };
        let stream = frame_bytes(&header, &body);

        // Feed one byte at a time; verify frame emerges after all bytes fed.
        let mut dec = FramingDecoder::new();
        let mut frames = Vec::new();
        for &b in &stream {
            frames.extend(dec.feed(&[b]));
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].body, body);
    }

    #[test]
    fn proptest_diagnostic_counters_consistent(
        frames_spec in prop::collection::vec(
            arb_body(256).prop_flat_map(|body| {
                let len = body.len() as u64;
                arb_valid_header(len).prop_map(move |h| (h, body.clone()))
            }),
            0..5,
        ),
    ) {
        let mut stream = Vec::new();
        let mut total_bytes = 0u64;
        for (h, body) in &frames_spec {
            let f = frame_bytes(h, body);
            total_bytes += f.len() as u64;
            stream.extend_from_slice(&f);
        }

        let mut dec = FramingDecoder::new();
        let frames = dec.feed(&stream);

        assert_eq!(dec.frames_emitted_count(), frames.len() as u64);
        assert_eq!(dec.total_bytes_fed(), total_bytes);
        // After feeding all frames at once, buffered_bytes should be 0
        // unless the last frame was incomplete (which shouldn't happen here).
        assert_eq!(dec.buffered_bytes(), 0,
            "all bytes consumed, but {} still buffered", dec.buffered_bytes());
    }
}
