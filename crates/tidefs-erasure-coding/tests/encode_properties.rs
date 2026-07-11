// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_erasure_coding::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn config(k: usize, m: usize, shard_len: usize) -> StripeConfig {
    StripeConfig {
        data_shards: k,
        parity_shards: m,
        shard_len,
    }
}

fn sequential_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i & 0xFF) as u8).collect()
}

// ---------------------------------------------------------------------------
// Systematic encoding: first k shards carry the input data verbatim
// ---------------------------------------------------------------------------

#[test]
fn systematic_first_k_shards_equal_input() {
    for (k, m) in [(2, 1), (4, 2), (6, 3)] {
        let c = config(k, m, 16);
        let payload = sequential_payload(c.data_capacity());
        let enc = encode(&c, &payload).expect("encode");
        for i in 0..k {
            let expected_slice = &payload[i * c.shard_len..(i + 1) * c.shard_len];
            let shard_data = &enc.shards[i].bytes[..expected_slice.len()];
            assert_eq!(
                shard_data, expected_slice,
                "k={k} {m}: shard {i} data mismatch"
            );
            // Verify shard metadata
            assert_eq!(enc.shards[i].index, i);
            assert!(matches!(enc.shards[i].kind, ShardKind::Data));
        }
    }
}

#[test]
fn systematic_partial_last_shard_has_zero_padding() {
    // Input not aligned to shard boundary: last data shard should be zero-padded
    let c = config(3, 1, 8);
    let payload = b"hello world!!!!"; // 15 bytes, 3 shards * 8 = 24 capacity
    let enc = encode(&c, payload).expect("encode");
    // Shard 0: "hello wo" (8 bytes)
    assert_eq!(&enc.shards[0].bytes[..8], b"hello wo");
    // Shard 1: "rld!!!!!" — only 7 bytes of data, rest zeros
    assert_eq!(&enc.shards[1].bytes[..7], b"rld!!!!");
    assert!(enc.shards[1].bytes[7..].iter().all(|&b| b == 0));
    // Shard 2: all zeros
    assert!(enc.shards[2].bytes.iter().all(|&b| b == 0));
}

// ---------------------------------------------------------------------------
// Output shard count
// ---------------------------------------------------------------------------

#[test]
fn output_shard_count_equals_k_plus_m() {
    for (k, m) in [(1, 1), (3, 2), (8, 3), (4, 1)] {
        let c = config(k, m, 32);
        let payload = sequential_payload(c.data_capacity());
        let enc = encode(&c, &payload).expect("encode");
        assert_eq!(
            enc.shards.len(),
            c.stripe_width(),
            "k={k} {m}: shard count mismatch"
        );
    }
}

#[test]
fn output_shard_count_includes_parity_shards() {
    let c = config(4, 2, 16);
    let enc = encode(&c, &sequential_payload(c.data_capacity())).expect("encode");
    let data_count = enc
        .shards
        .iter()
        .filter(|s| matches!(s.kind, ShardKind::Data))
        .count();
    let parity_count = enc
        .shards
        .iter()
        .filter(|s| matches!(s.kind, ShardKind::Parity))
        .count();
    assert_eq!(data_count, 4);
    assert_eq!(parity_count, 2);
}

// ---------------------------------------------------------------------------
// Shard byte length
// ---------------------------------------------------------------------------

#[test]
fn all_shards_have_expected_byte_length() {
    for shard_len in [1, 8, 64, 4096] {
        let c = config(4, 2, shard_len);
        let payload = sequential_payload(c.data_capacity());
        let enc = encode(&c, &payload).expect("encode");
        for shard in &enc.shards {
            assert_eq!(
                shard.bytes.len(),
                shard_len,
                "shard_len={shard_len}: shard {} has wrong length",
                shard.index
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn encode_is_deterministic() {
    let c = config(4, 2, 32);
    let payload = sequential_payload(c.data_capacity());
    let enc1 = encode(&c, &payload).expect("first encode");
    let enc2 = encode(&c, &payload).expect("second encode");
    assert_eq!(enc1.shards.len(), enc2.shards.len());
    for i in 0..enc1.shards.len() {
        assert_eq!(
            enc1.shards[i].bytes, enc2.shards[i].bytes,
            "shard {i} differs between encode calls"
        );
        assert_eq!(enc1.shards[i].index, enc2.shards[i].index);
        assert_eq!(enc1.shards[i].kind, enc2.shards[i].kind);
    }
}

#[test]
fn different_payloads_produce_different_output() {
    let c = config(4, 2, 16);
    let p1 = sequential_payload(c.data_capacity());
    let mut p2 = p1.clone();
    p2[7] ^= 0xFF;
    let enc1 = encode(&c, &p1).expect("encode p1");
    let enc2 = encode(&c, &p2).expect("encode p2");
    let same = enc1
        .shards
        .iter()
        .zip(enc2.shards.iter())
        .all(|(a, b)| a.bytes == b.bytes);
    assert!(!same, "different payloads must produce different output");
}

// ---------------------------------------------------------------------------
// Original payload length tracking
// ---------------------------------------------------------------------------

#[test]
fn original_payload_len_preserved() {
    for len in [0, 1, 15, 32, 63, 64, 100] {
        let c = config(4, 1, 16);
        let payload = vec![0xABu8; len];
        if let Some(enc) = encode(&c, &payload) {
            assert_eq!(enc.original_payload_len, len);
        }
    }
}

#[test]
fn encoded_stripe_retains_config() {
    let c = config(4, 2, 32);
    let enc = encode(&c, &sequential_payload(c.data_capacity())).expect("encode");
    assert_eq!(enc.config, c);
}

// ---------------------------------------------------------------------------
// Receipt-tracked helpers
// ---------------------------------------------------------------------------

#[test]
fn receipt_encode_preserves_shards_and_original_payload_len() {
    let c = config(3, 2, 8);
    let payload = b"receipt payload";

    let enc = encode_receipt_stripe(&c, payload).expect("receipt encode");

    assert_eq!(enc.shards.len(), c.stripe_width());
    assert_eq!(enc.original_payload_len, payload.len());
    assert_eq!(enc.shards[0].kind, ShardKind::Data);
    assert_eq!(enc.shards[c.data_shards].kind, ShardKind::Parity);
}

#[test]
fn receipt_reconstruct_returns_rebuilt_missing_shard_evidence() {
    let c = config(2, 1, 8);
    let payload = b"receipt";
    let enc = encode_receipt_stripe(&c, payload).expect("receipt encode");
    let mut available: Vec<_> = enc.shards.iter().cloned().map(Some).collect();
    available[0] = None;

    let reconstructed = reconstruct_receipt_stripe(&c, &available).expect("receipt reconstruct");

    assert_eq!(&reconstructed.payload[..payload.len()], payload);
    assert_eq!(reconstructed.rebuilt_shards.len(), 1);
    assert_eq!(reconstructed.rebuilt_shards[0].index, 0);
}

#[test]
fn receipt_reconstruct_fails_closed_when_insufficient_shards() {
    let c = config(2, 1, 8);
    let enc = encode_receipt_stripe(&c, b"receipt").expect("receipt encode");
    let mut available: Vec<_> = enc.shards.iter().cloned().map(Some).collect();
    available[0] = None;
    available[2] = None;

    let err = reconstruct_receipt_stripe(&c, &available).unwrap_err();

    assert_eq!(
        err,
        ReceiptStripeError::InsufficientShards {
            available: 1,
            needed: 2
        }
    );
}

#[test]
fn receipt_reconstruct_rejects_invalid_available_set_width() {
    let c = config(2, 1, 8);
    let enc = encode_receipt_stripe(&c, b"receipt").expect("receipt encode");
    let available: Vec<_> = enc.shards.iter().take(2).cloned().map(Some).collect();

    let err = reconstruct_receipt_stripe(&c, &available).unwrap_err();

    assert_eq!(
        err,
        ReceiptStripeError::InvalidAvailableSet {
            slots: 2,
            expected: 3
        }
    );
}
