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

fn make_available(enc: &EncodedStripe, keep: &[usize]) -> Vec<Option<ErasureShard>> {
    let w = enc.config.stripe_width();
    let mut v: Vec<Option<ErasureShard>> = vec![None; w];
    for &idx in keep {
        v[idx] = Some(enc.shards[idx].clone());
    }
    v
}

// ---------------------------------------------------------------------------
// Zero-length input
// ---------------------------------------------------------------------------

#[test]
fn zero_length_payload_all_shards_zero() {
    let c = config(4, 2, 16);
    let payload: Vec<u8> = vec![];
    let enc = encode(&c, &payload).expect("encode empty payload");
    assert_eq!(enc.original_payload_len, 0);
    for shard in &enc.shards {
        assert!(
            shard.bytes.iter().all(|&b| b == 0),
            "shard {} should be all zeros for empty payload",
            shard.index
        );
    }
}

#[test]
fn zero_length_payload_roundtrip() {
    for (k, m) in [(1, 1), (4, 2), (6, 3)] {
        let c = config(k, m, 8);
        let payload: Vec<u8> = vec![];
        let enc = encode(&c, &payload).expect("encode");
        assert_eq!(enc.original_payload_len, 0);
        let keep: Vec<usize> = (0..c.stripe_width()).collect();
        let rec = reconstruct(&c, &make_available(&enc, &keep), None).expect("reconstruct");
        assert!(rec.payload.iter().all(|&b| b == 0));
        assert!(rec.rebuilt_shards.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Single-byte input
// ---------------------------------------------------------------------------

#[test]
fn single_byte_payload_roundtrip() {
    for (k, m) in [(2, 1), (4, 2), (6, 3)] {
        let c = config(k, m, 16);
        let payload = vec![0x7Fu8; 1];
        let enc = encode(&c, &payload).expect("encode");
        assert_eq!(enc.original_payload_len, 1);
        // First shard carries the byte, rest are zeros
        assert_eq!(enc.shards[0].bytes[0], 0x7F);
        assert!(enc.shards[0].bytes[1..].iter().all(|&b| b == 0));
        for i in 1..k {
            assert!(enc.shards[i].bytes.iter().all(|&b| b == 0));
        }
        // Roundtrip
        let keep: Vec<usize> = (0..k).collect();
        let rec = reconstruct(&c, &make_available(&enc, &keep), None).expect("reconstruct");
        assert_eq!(rec.payload[0], 0x7F);
        assert!(rec.payload[1..].iter().all(|&b| b == 0));
    }
}

// ---------------------------------------------------------------------------
// Payload exactly at data capacity boundary
// ---------------------------------------------------------------------------

#[test]
fn payload_at_exact_capacity_roundtrip() {
    for (k, m) in [(3, 1), (5, 2), (4, 3)] {
        let c = config(k, m, 16);
        let payload = sequential_payload(c.data_capacity());
        assert_eq!(payload.len(), c.data_capacity());
        let enc = encode(&c, &payload).expect("encode");
        assert_eq!(enc.original_payload_len, c.data_capacity());
        // No padding in any data shard
        for i in 0..k {
            let expected_slice = &payload[i * c.shard_len..(i + 1) * c.shard_len];
            assert_eq!(&enc.shards[i].bytes[..], expected_slice);
        }
        let keep: Vec<usize> = (0..k).collect();
        let rec = reconstruct(&c, &make_available(&enc, &keep), None).expect("reconstruct");
        assert_eq!(&rec.payload[..], &payload[..]);
    }
}

// ---------------------------------------------------------------------------
// Payload one byte below capacity
// ---------------------------------------------------------------------------

#[test]
fn payload_one_byte_below_capacity() {
    let c = config(4, 2, 8);
    let cap = c.data_capacity(); // 32
    let payload = sequential_payload(cap - 1);
    let enc = encode(&c, &payload).expect("encode");
    assert_eq!(enc.original_payload_len, cap - 1);
    // Last byte of last data shard should be zero-padded
    assert_eq!(enc.shards[3].bytes[7], 0);
    // All other bytes should carry payload data
    for i in 0..3 {
        assert_eq!(&enc.shards[i].bytes[..], &payload[i * 8..(i + 1) * 8]);
    }
    assert_eq!(&enc.shards[3].bytes[..7], &payload[24..31]);
}

// ---------------------------------------------------------------------------
// Minimum shard_len (1 byte), k=1
// ---------------------------------------------------------------------------

#[test]
fn shard_len_1_k1_m1() {
    let c = config(1, 1, 1);
    let payload = vec![0x42u8; 1];
    let enc = encode(&c, &payload).expect("encode");
    assert_eq!(enc.shards.len(), 2);
    assert_eq!(enc.shards[0].bytes, &[0x42]);
    assert_eq!(enc.shards[1].bytes, &[0x42]); // XOR parity = same as data
                                              // Reconstruct from either shard
    let rec = reconstruct(&c, &make_available(&enc, &[0]), None).expect("from data");
    assert_eq!(&rec.payload[..1], &[0x42]);
    let rec = reconstruct(&c, &make_available(&enc, &[1]), None).expect("from parity");
    assert_eq!(&rec.payload[..1], &[0x42]);
}

#[test]
fn shard_len_1_k1_m3() {
    let c = config(1, 3, 1);
    let payload = vec![0xA5u8; 1];
    let enc = encode(&c, &payload).expect("encode");
    assert_eq!(enc.shards.len(), 4);
    // Reconstruct from any single shard (data or any parity)
    let keep_opts: [&[usize]; 4] = [&[0], &[1], &[2], &[3]];
    for keep in &keep_opts {
        let rec = reconstruct(&c, &make_available(&enc, keep), None).expect("reconstruct");
        assert_eq!(&rec.payload[..1], &[0xA5]);
    }
}

// ---------------------------------------------------------------------------
// Large k value still within GF(2^8) range (k+m <= 255)
// ---------------------------------------------------------------------------

#[test]
fn large_k_single_parity_roundtrip() {
    let k = 64;
    let c = config(k, 1, 4);
    let payload = sequential_payload(c.data_capacity());
    let enc = encode(&c, &payload).expect("encode");
    assert_eq!(enc.shards.len(), k + 1);
    // Drop one data shard, keep all others including parity
    let keep: Vec<usize> = (0..c.stripe_width()).filter(|&i| i != 13).collect();
    let rec = reconstruct(&c, &make_available(&enc, &keep), None)
        .expect("reconstruct with single parity, k=64");
    assert_eq!(&rec.payload[..payload.len()], &payload);
    assert_eq!(rec.rebuilt_shards.len(), 1);
}

#[test]
fn large_k_triple_parity_roundtrip() {
    let k = 48;
    let c = config(k, 3, 8);
    let payload = sequential_payload(c.data_capacity());
    let enc = encode(&c, &payload).expect("encode");
    assert_eq!(enc.shards.len(), k + 3);
    // Drop three data shards, keep all others including parity
    let drops = [7, 22, 41];
    let keep: Vec<usize> = (0..c.stripe_width())
        .filter(|i| !drops.contains(i))
        .collect();
    let rec = reconstruct(&c, &make_available(&enc, &keep), None)
        .expect("reconstruct with triple parity, k=48, 3 drops");
    assert_eq!(&rec.payload[..payload.len()], &payload);
    assert_eq!(rec.rebuilt_shards.len(), 3);
}

// ---------------------------------------------------------------------------
// All possible byte values in payload
// ---------------------------------------------------------------------------

#[test]
fn all_byte_values_roundtrip() {
    let c = config(4, 2, 64);
    let payload: Vec<u8> = (0..=255).cycle().take(c.data_capacity()).collect();
    let enc = encode(&c, &payload).expect("encode");
    // Drop 2 shards at tolerance limit
    let rec = reconstruct(&c, &make_available(&enc, &[0, 1, 3, 5]), None)
        .expect("reconstruct all byte values");
    assert_eq!(&rec.payload[..payload.len()], &payload);
}

// ---------------------------------------------------------------------------
// Payload that stresses GF(2^8) wrap-around at 255
// ---------------------------------------------------------------------------

#[test]
fn payload_at_gf_boundary() {
    // Byte values 250..=255 near GF(2^8) wrap-around
    let c = config(4, 2, 16);
    let payload: Vec<u8> = (250u8..=255).cycle().take(c.data_capacity()).collect();
    let enc = encode(&c, &payload).expect("encode");
    let keep: Vec<usize> = (0..c.data_shards).collect();
    let rec = reconstruct(&c, &make_available(&enc, &keep), None).expect("reconstruct");
    assert_eq!(&rec.payload[..payload.len()], &payload);
}

// ---------------------------------------------------------------------------
// k=1, m=2: double parity on single data shard — edge of redundancy
// ---------------------------------------------------------------------------

#[test]
fn k1_m2_any_single_shard_recovers() {
    let c = config(1, 2, 32);
    let payload = sequential_payload(32);
    let enc = encode(&c, &payload).expect("encode");
    // Any 1 of 3 shards should reconstruct
    let keep_opts: [&[usize]; 3] = [&[0], &[1], &[2]];
    for keep in &keep_opts {
        let rec = reconstruct(&c, &make_available(&enc, keep), None).expect("reconstruct");
        assert_eq!(&rec.payload[..32], &payload);
    }
}

// ---------------------------------------------------------------------------
// k=2, m=3: triple parity on two data shards (more parity than data)
// ---------------------------------------------------------------------------

#[test]
fn k2_m3_more_parity_than_data() {
    let c = config(2, 3, 16);
    let payload = sequential_payload(c.data_capacity());
    let enc = encode(&c, &payload).expect("encode");
    assert_eq!(enc.shards.len(), 5); // 2 data + 3 parity
                                     // Drop 3 shards (max tolerance), recover from remaining 2
    let rec = reconstruct(&c, &make_available(&enc, &[1, 3]), None)
        .expect("reconstruct k=2,m=3 from 2 remaining");
    assert_eq!(&rec.payload[..payload.len()], &payload);
}
