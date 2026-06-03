//! Round-trip and edge-case tests for BLAKE3-256 hash encoding/decoding
//! in tidefs-binary_schema-checksum.
//!
//! These tests exercise the public API: domain-separated hashing, digest
//! verification, seal/verify profiles, and SchemaFingerprint encode/decode
//! from tidefs-binary_schema-core.

use tidefs_binary_schema_checksum::{
    blake3_domain_digest, blake3_domain_digest_into, blake3_domain_verify, seal_checksums,
    verify_seal,
};
use tidefs_binary_schema_core::{
    ChecksumProfile, DomainTag, SchemaFamilyId, SchemaFingerprint, SchemaTypeId, SchemaVersion,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Default domain parameters used across tests.
fn default_domain() -> (SchemaFamilyId, SchemaTypeId, SchemaVersion) {
    (
        SchemaFamilyId(1),
        SchemaTypeId(42),
        SchemaVersion::new(1, 0),
    )
}

/// Attempt to decode a variable-length byte slice into a 32-byte hash.
/// Returns `None` if the slice length is not exactly 32.
fn try_decode_blake3(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Some(out)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Round-trip: hash → bytes → re-verify
// ---------------------------------------------------------------------------

#[test]
fn blake3_roundtrip_via_fingerprint_encode_decode() {
    let data = b"roundtrip payload for fingerprint test";
    let (fam, typ, ver) = default_domain();
    let tag = DomainTag::SectionBody;

    // Step 1: Compute the digest.
    let hash_bytes = blake3_domain_digest(data, fam, typ, ver, tag);

    // Step 2: Wrap in SchemaFingerprint, encode, decode.
    let fp = SchemaFingerprint(hash_bytes);
    let encoded = fp.encode();
    assert_eq!(encoded, hash_bytes);
    let decoded = SchemaFingerprint::decode(encoded);
    assert_eq!(decoded.0, hash_bytes);
}

#[test]
fn blake3_roundtrip_verify_after_rehash() {
    let data = b"roundtrip verify after rehash payload";
    let (fam, typ, ver) = default_domain();
    let tag = DomainTag::EnvelopeHeader;

    // Compute digest and verify it passes.
    let digest = blake3_domain_digest(data, fam, typ, ver, tag);
    blake3_domain_verify(data, &digest, fam, typ, ver, tag)
        .expect("digest should verify against same data");

    // Re-compute: same data, same params → same digest.
    let digest2 = blake3_domain_digest(data, fam, typ, ver, tag);
    assert_eq!(digest, digest2);
}

// ---------------------------------------------------------------------------
// Fixed-size encoding
// ---------------------------------------------------------------------------

#[test]
fn blake3_output_is_always_32_bytes() {
    let data = b"any payload";
    let (fam, typ, ver) = default_domain();

    let digest = blake3_domain_digest(data, fam, typ, ver, DomainTag::EnvelopeHeader);
    assert_eq!(digest.len(), 32);

    let digest = blake3_domain_digest(b"", fam, typ, ver, DomainTag::EnvelopeHeader);
    assert_eq!(digest.len(), 32);

    let digest = blake3_domain_digest(&[0u8; 1024], fam, typ, ver, DomainTag::ChunkFrame);
    assert_eq!(digest.len(), 32);
}

#[test]
fn fingerprint_encode_always_32_bytes() {
    let bytes = [0x42u8; 32];
    let fp = SchemaFingerprint(bytes);
    let encoded = fp.encode();
    assert_eq!(encoded.len(), 32);
    assert_eq!(encoded, bytes);

    let zero = SchemaFingerprint::ZERO;
    assert_eq!(zero.encode().len(), 32);
}

#[test]
fn blake3_domain_digest_into_writes_32_bytes() {
    let data = b"digest into test";
    let (fam, typ, ver) = default_domain();
    let mut out = [0xFFu8; 32];
    blake3_domain_digest_into(data, fam, typ, ver, DomainTag::ReceiptBody, &mut out);

    // Should have been overwritten (not all 0xFF anymore).
    assert_ne!(out, [0xFFu8; 32]);

    // Should match blake3_domain_digest.
    let expected = blake3_domain_digest(data, fam, typ, ver, DomainTag::ReceiptBody);
    assert_eq!(out, expected);
}

// ---------------------------------------------------------------------------
// Zero-hash round-trip
// ---------------------------------------------------------------------------

#[test]
fn zero_fingerprint_encode_decode() {
    let zero = SchemaFingerprint::ZERO;
    assert_eq!(zero.0, [0u8; 32]);

    let encoded = zero.encode();
    assert_eq!(encoded, [0u8; 32]);

    let decoded = SchemaFingerprint::decode(encoded);
    assert_eq!(decoded.0, [0u8; 32]);
    assert_eq!(decoded.0, SchemaFingerprint::ZERO.0);
}

#[test]
fn zero_hash_verify_detects_tamper() {
    let data = b"some data that doesn't hash to zero";
    let (fam, typ, ver) = default_domain();
    let zero_digest = [0u8; 32];

    // Verification with zero digest must fail for non-trivial data.
    let result = blake3_domain_verify(data, &zero_digest, fam, typ, ver, DomainTag::SectionBody);
    assert!(
        result.is_err(),
        "zero digest should not verify for non-trivial data"
    );
}

// ---------------------------------------------------------------------------
// Known-answer tests
// ---------------------------------------------------------------------------

#[test]
fn known_answer_envelope_header() {
    let data = b"tidefs-checksum-test-vector";
    let (fam, typ, ver) = default_domain();
    let tag = DomainTag::EnvelopeHeader;

    let digest = blake3_domain_digest(data, fam, typ, ver, tag);
    let expected: [u8; 32] =
        hex_decode("7f7b6f671a19a101f78629415823c2008bf3bef74afdf858080c39c6c6361819");
    assert_eq!(digest, expected);
}

#[test]
fn known_answer_section_body() {
    let data = b"tidefs-checksum-test-vector";
    let (fam, typ, ver) = default_domain();
    let tag = DomainTag::SectionBody;

    let digest = blake3_domain_digest(data, fam, typ, ver, tag);
    let expected: [u8; 32] =
        hex_decode("2301ba8cee75983da9454cdc8ce1d19eff4839062294b0a4d28f22855a26196e");
    assert_eq!(digest, expected);
}

#[test]
fn known_answer_receipt_body() {
    let data = b"tidefs-checksum-test-vector";
    let (fam, typ, ver) = default_domain();
    let tag = DomainTag::ReceiptBody;

    let digest = blake3_domain_digest(data, fam, typ, ver, tag);
    let expected: [u8; 32] =
        hex_decode("655ad5a64b87d66c9b122ad2482fa3a61e59840cae091b0957245e6f60050aea");
    assert_eq!(digest, expected);
}

#[test]
fn known_answer_chunk_frame() {
    let data = b"tidefs-checksum-test-vector";
    let (fam, typ, ver) = default_domain();
    let tag = DomainTag::ChunkFrame;

    let digest = blake3_domain_digest(data, fam, typ, ver, tag);
    let expected: [u8; 32] =
        hex_decode("eaf51f09f134ddca3dedc0dee074c3c720d7726705ea68a53368c34ba1067ddd");
    assert_eq!(digest, expected);
}

#[test]
fn known_answer_differs_by_domain_tag() {
    let data = b"tidefs-checksum-test-vector";
    let (fam, typ, ver) = default_domain();

    let d_env = blake3_domain_digest(data, fam, typ, ver, DomainTag::EnvelopeHeader);
    let d_sec = blake3_domain_digest(data, fam, typ, ver, DomainTag::SectionBody);
    let d_rec = blake3_domain_digest(data, fam, typ, ver, DomainTag::ReceiptBody);
    let d_chk = blake3_domain_digest(data, fam, typ, ver, DomainTag::ChunkFrame);

    assert_ne!(d_env, d_sec);
    assert_ne!(d_env, d_rec);
    assert_ne!(d_env, d_chk);
    assert_ne!(d_sec, d_rec);
    assert_ne!(d_sec, d_chk);
    assert_ne!(d_rec, d_chk);
}

// ---------------------------------------------------------------------------
// Invalid-input rejection
// ---------------------------------------------------------------------------

#[test]
fn try_decode_rejects_truncated_buffers() {
    for len in 0..32 {
        let buf = vec![0xABu8; len];
        assert!(
            try_decode_blake3(&buf).is_none(),
            "len={len} should be rejected"
        );
    }
}

#[test]
fn try_decode_rejects_oversized_buffers() {
    for len in 33..64 {
        let buf = vec![0xABu8; len];
        assert!(
            try_decode_blake3(&buf).is_none(),
            "len={len} should be rejected"
        );
    }
    // Also test a much larger buffer.
    let big = vec![0xABu8; 256];
    assert!(try_decode_blake3(&big).is_none());
}

#[test]
fn try_decode_accepts_valid_32_byte_buffer() {
    // All 0xFF is a valid hash byte pattern (no reserved values).
    let buf = [0xFFu8; 32];
    let decoded = try_decode_blake3(&buf);
    assert!(decoded.is_some());
    assert_eq!(decoded.unwrap(), [0xFFu8; 32]);

    // All zeros.
    let decoded = try_decode_blake3(&[0u8; 32]);
    assert!(decoded.is_some());

    // Mixed bytes.
    let mut buf = [0u8; 32];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = i as u8;
    }
    let decoded = try_decode_blake3(&buf);
    assert!(decoded.is_some());
}

#[test]
fn blake3_domain_verify_rejects_tampered_digest() {
    let data = b"integrity check";
    let (fam, typ, ver) = default_domain();
    let tag = DomainTag::EnvelopeHeader;

    let digest = blake3_domain_digest(data, fam, typ, ver, tag);

    // Flip one bit in the digest.
    let mut bad_digest = digest;
    bad_digest[0] ^= 0x01;
    assert!(blake3_domain_verify(data, &bad_digest, fam, typ, ver, tag).is_err());

    // Flip one bit in the data.
    let mut bad_data = data.to_vec();
    bad_data[0] ^= 0x01;
    assert!(blake3_domain_verify(&bad_data, &digest, fam, typ, ver, tag).is_err());
}

#[test]
fn seal_verify_rejects_truncated_fingerprint() {
    // Verify that a missing blake3 field in a Crc32cPlusBlake3_256 seal
    // ticket is rejected.
    let data = b"seal integrity";
    let (fam, typ, ver) = default_domain();
    let tag = DomainTag::EnvelopeHeader;

    let mut ticket = seal_checksums(
        data,
        ChecksumProfile::Crc32cPlusBlake3_256,
        fam,
        typ,
        ver,
        tag,
    );
    // Remove the blake3 field.
    ticket.blake3_bytes = None;
    assert!(verify_seal(data, &ticket, fam, typ, ver, tag).is_err());
}

// ---------------------------------------------------------------------------
// Concurrent safety
// ---------------------------------------------------------------------------

#[test]
fn concurrent_blake3_domain_digest_no_races() {
    use std::sync::Arc;
    use std::thread;

    let data = Arc::new(b"concurrent hash test payload".to_vec());
    let (fam, typ, ver) = default_domain();

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

    let mut handles = Vec::new();
    for &tag in &tags {
        let data = Arc::clone(&data);
        let handle = thread::spawn(move || {
            // Each thread computes digests for its tag many times.
            let mut results = Vec::new();
            for _ in 0..100 {
                let d = blake3_domain_digest(&data, fam, typ, ver, tag);
                results.push(d);
            }
            // Verify idempotency within the thread.
            for w in results.windows(2) {
                assert_eq!(w[0], w[1], "same inputs should produce same digest");
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }
}

#[test]
fn concurrent_seal_verify_no_races() {
    use std::sync::Arc;
    use std::thread;

    let data = Arc::new(b"concurrent seal test".to_vec());
    let (fam, typ, ver) = default_domain();

    let profiles = [
        ChecksumProfile::None,
        ChecksumProfile::Crc32c,
        ChecksumProfile::Blake3_256,
        ChecksumProfile::Crc32cPlusBlake3_256,
    ];

    let mut handles = Vec::new();
    for &profile in &profiles {
        let data = Arc::clone(&data);
        let handle = thread::spawn(move || {
            for _ in 0..50 {
                let ticket = seal_checksums(&data, profile, fam, typ, ver, DomainTag::SectionBody);
                verify_seal(&data, &ticket, fam, typ, ver, DomainTag::SectionBody)
                    .expect("seal/verify should succeed");
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }
}

// ---------------------------------------------------------------------------
// Helper: decode hex string to [u8; 32]
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "hex string must be 64 chars (32 bytes)");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[i * 2]);
        let lo = hex_nibble(s.as_bytes()[i * 2 + 1]);
        *byte = (hi << 4) | lo;
    }
    out
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex char: {b}"),
    }
}
