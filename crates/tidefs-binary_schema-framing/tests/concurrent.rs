// Integration tests: concurrent encode safety.
// Verifies that the encoding API can be called from multiple threads
// without internal state corruption, and that interleaved encode
// outputs produce valid independent frames.

use std::sync::Arc;
use std::thread;

use tidefs_binary_schema_core::{
    ChecksumProfile, ChunkFrameSizeClass, PayloadClass, SchemaFamilyId, SchemaTypeId,
    SchemaVersion, BINARY_SCHEMA_MAGIC,
};
use tidefs_binary_schema_framing::{ChunkFrameHeader, EnvelopeHeader, SectionHeader};

// ── EnvelopeHeader concurrent encode ────────────────────────────────

#[test]
fn concurrent_envelope_encode_different_headers() {
    let mut handles = Vec::new();
    for i in 0..16 {
        handles.push(thread::spawn(move || {
            let header = EnvelopeHeader {
                magic: BINARY_SCHEMA_MAGIC,
                family_id: SchemaFamilyId(i),
                type_id: SchemaTypeId(i * 10),
                version: SchemaVersion::new(i as u16, 0),
                flags: i as u32,
                section_count: i as u16,
                total_body_bytes: i * 1024,
                fast_checksum_profile: ChecksumProfile::Crc32c,
                strong_digest_profile: ChecksumProfile::Blake3_256,
                schema_fingerprint_low: i,
                header_crc32c: 0,
            };
            let enc = header.encode();
            let dec = EnvelopeHeader::decode(&enc).expect("concurrent envelope decode");
            assert_eq!(dec.family_id.0, i, "family_id mismatch in thread");
            assert_eq!(dec.section_count, i as u16);
            assert_eq!(dec.total_body_bytes, i * 1024);
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
}

#[test]
fn concurrent_envelope_encode_same_header() {
    let header = Arc::new(EnvelopeHeader {
        magic: BINARY_SCHEMA_MAGIC,
        family_id: SchemaFamilyId(42),
        type_id: SchemaTypeId(99),
        version: SchemaVersion::new(3, 1),
        flags: 0xCAFE,
        section_count: 7,
        total_body_bytes: 65536,
        fast_checksum_profile: ChecksumProfile::Crc32c,
        strong_digest_profile: ChecksumProfile::Blake3_256,
        schema_fingerprint_low: 0xABCD,
        header_crc32c: 0,
    });

    let mut handles = Vec::new();
    for _ in 0..16 {
        let h = Arc::clone(&header);
        handles.push(thread::spawn(move || {
            // Each thread encodes independently from a shared (immutable) header
            let enc = h.encode();
            let dec = EnvelopeHeader::decode(&enc).expect("concurrent same-header decode");
            assert_eq!(dec.family_id.0, 42);
            assert_eq!(dec.section_count, 7);
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
}

// ── SectionHeader concurrent encode ─────────────────────────────────

#[test]
fn concurrent_section_encode() {
    let mut handles = Vec::new();
    for i in 0..16 {
        handles.push(thread::spawn(move || {
            let sec = SectionHeader {
                section_offset: i * 64,
                section_length: 4096,
                payload_class: PayloadClass::ChunkFramed,
                section_flags: i as u16,
                optional_mask: i as u32,
            };
            let enc = sec.encode();
            let dec = SectionHeader::decode(&enc).expect("concurrent section decode");
            assert_eq!(dec.section_offset, i * 64);
            assert_eq!(dec.section_flags, i as u16);
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
}

// ── ChunkFrameHeader concurrent encode ──────────────────────────────

#[test]
fn concurrent_chunk_frame_encode() {
    let mut handles = Vec::new();
    for i in 0..16 {
        handles.push(thread::spawn(move || {
            let frame = ChunkFrameHeader {
                frame_index: i,
                payload_bytes: (64 * 1024) - i,
                frame_size_class: ChunkFrameSizeClass::KiB64,
                payload_crc32c: i as u32,
                digest_continuation_marker: 0,
            };
            let enc = frame.encode();
            let dec = ChunkFrameHeader::decode(&enc).expect("concurrent chunk frame decode");
            assert_eq!(dec.frame_index, i);
            assert_eq!(dec.payload_bytes, (64 * 1024) - i);
            assert_eq!(dec.payload_crc32c, i as u32);
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
}

// ── Mixed-type concurrent encode ────────────────────────────────────

#[test]
fn concurrent_mixed_encode_all_types() {
    // Spawn threads encoding different header types simultaneously
    let t1 = thread::spawn(|| {
        for i in 0..100 {
            let env = EnvelopeHeader {
                family_id: SchemaFamilyId(i),
                ..Default::default()
            };
            let enc = env.encode();
            EnvelopeHeader::decode(&enc).expect("envelope");
        }
    });
    let t2 = thread::spawn(|| {
        for i in 0..100 {
            let sec = SectionHeader {
                section_offset: i * 8,
                section_length: 256,
                ..Default::default()
            };
            let enc = sec.encode();
            SectionHeader::decode(&enc).expect("section");
        }
    });
    let t3 = thread::spawn(|| {
        for i in 0..100 {
            let frame = ChunkFrameHeader {
                frame_index: i,
                payload_bytes: i,
                ..Default::default()
            };
            let enc = frame.encode();
            ChunkFrameHeader::decode(&enc).expect("chunk frame");
        }
    });

    t1.join().expect("envelope thread panicked");
    t2.join().expect("section thread panicked");
    t3.join().expect("chunk frame thread panicked");
}

// ── Concurrent decode of pre-encoded frames ─────────────────────────

#[test]
fn concurrent_decode_pre_encoded() {
    let env = EnvelopeHeader {
        family_id: SchemaFamilyId(1),
        type_id: SchemaTypeId(2),
        version: SchemaVersion::new(1, 0),
        section_count: 3,
        total_body_bytes: 4096,
        ..Default::default()
    };
    let env_enc = Arc::new(env.encode());

    let mut handles = Vec::new();
    for _ in 0..16 {
        let enc = Arc::clone(&env_enc);
        handles.push(thread::spawn(move || {
            let dec = EnvelopeHeader::decode(&enc).expect("concurrent decode of shared buffer");
            assert_eq!(dec.family_id.0, 1);
            assert_eq!(dec.type_id.0, 2);
            assert_eq!(dec.section_count, 3);
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
}
