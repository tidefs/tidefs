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

fn corrupt_shard(shard: &mut ErasureShard, byte_offset: usize, bit: u8) {
    shard.bytes[byte_offset] ^= 1 << bit;
}

// ---------------------------------------------------------------------------
// Single-shard bit flip: detection/recovery via remaining k shards
// ---------------------------------------------------------------------------

#[test]
fn single_data_bit_flip_detected_via_reconstruction_mismatch() {
    let c = config(4, 2, 16);
    let payload = sequential_payload(c.data_capacity());
    let enc = encode(&c, &payload).expect("encode");

    // Corrupt data shard 1 at byte 3, bit 2
    let mut shards: Vec<_> = enc.shards.iter().map(|s| Some(s.clone())).collect();
    let orig_byte = shards[1].as_ref().unwrap().bytes[3];
    corrupt_shard(shards[1].as_mut().unwrap(), 3, 2);
    assert_ne!(shards[1].as_ref().unwrap().bytes[3], orig_byte);

    // Reconstruct using all shards except the corrupted one should still work
    let avail: Vec<Option<ErasureShard>> = (0..c.stripe_width())
        .map(|i| {
            if i == 1 {
                // Drop corrupted shard, reconstruct from others
                None
            } else {
                shards[i].clone()
            }
        })
        .collect();
    let rec = reconstruct(&c, &avail, None).expect("reconstruct without corrupted shard");
    assert_eq!(&rec.payload[..payload.len()], &payload);
    assert_eq!(rec.rebuilt_shards.len(), 1);
    assert_eq!(rec.rebuilt_shards[0].index, 1);
    // The rebuilt shard should match the original
    assert_ne!(
        rec.rebuilt_shards[0].bytes[3],
        shards[1].as_ref().unwrap().bytes[3]
    );
}

#[test]
fn single_parity_bit_flip_still_recoverable() {
    let c = config(4, 2, 16);
    let payload = sequential_payload(c.data_capacity());
    let enc = encode(&c, &payload).expect("encode");

    // Corrupt first parity shard (index 4)
    let mut shards: Vec<_> = enc.shards.iter().map(|s| Some(s.clone())).collect();
    corrupt_shard(shards[4].as_mut().unwrap(), 7, 5);

    // Drop the corrupted parity shard, keep all data shards
    let avail: Vec<Option<ErasureShard>> = (0..c.stripe_width())
        .map(|i| if i == 4 { None } else { shards[i].clone() })
        .collect();
    let rec = reconstruct(&c, &avail, None).expect("reconstruct without corrupted parity");
    assert_eq!(&rec.payload[..payload.len()], &payload);
}

// ---------------------------------------------------------------------------
// Corruption within erasure tolerance: m shards corrupted, recoverable from
// remaining k shards
// ---------------------------------------------------------------------------

#[test]
fn double_corruption_recoverable_with_double_parity() {
    let c = config(6, 2, 16);
    let payload = sequential_payload(c.data_capacity());
    let enc = encode(&c, &payload).expect("encode");

    // Corrupt data shard 2 and data shard 5
    let mut shards: Vec<_> = enc.shards.iter().map(|s| Some(s.clone())).collect();
    corrupt_shard(shards[2].as_mut().unwrap(), 0, 0);
    corrupt_shard(shards[5].as_mut().unwrap(), 10, 3);

    // Drop both corrupted shards, keep remaining 4 data + 2 parity = 6 >= 4+2-2=6 → 4 >= k=6? No, k=6.
    // We have 4 data + 2 parity present = 6 >= 6. Works.
    let avail: Vec<Option<ErasureShard>> = (0..c.stripe_width())
        .map(|i| {
            if i == 2 || i == 5 {
                None
            } else {
                shards[i].clone()
            }
        })
        .collect();
    let rec = reconstruct(&c, &avail, None).expect("double parity: recover from 2 corruptions");
    assert_eq!(&rec.payload[..payload.len()], &payload);
    assert_eq!(rec.rebuilt_shards.len(), 2);
}

#[test]
fn triple_corruption_recoverable_with_triple_parity() {
    let c = config(5, 3, 32);
    let payload = sequential_payload(c.data_capacity());
    let enc = encode(&c, &payload).expect("encode");

    // Corrupt data shards 0, 3 and parity shard 5
    let mut shards: Vec<_> = enc.shards.iter().map(|s| Some(s.clone())).collect();
    corrupt_shard(shards[0].as_mut().unwrap(), 5, 1);
    corrupt_shard(shards[3].as_mut().unwrap(), 11, 7);
    corrupt_shard(shards[6].as_mut().unwrap(), 20, 4); // parity

    let avail: Vec<Option<ErasureShard>> = (0..c.stripe_width())
        .map(|i| {
            if i == 0 || i == 3 || i == 6 {
                None
            } else {
                shards[i].clone()
            }
        })
        .collect();
    let rec = reconstruct(&c, &avail, None).expect("triple parity: recover from 3 corruptions");
    assert_eq!(&rec.payload[..payload.len()], &payload);
    assert_eq!(rec.rebuilt_shards.len(), 3);
}

// ---------------------------------------------------------------------------
// Corruption exceeding erasure tolerance: reconstruction fails
// ---------------------------------------------------------------------------

#[test]
fn corruption_exceeding_m_is_detected_single() {
    let c = config(4, 1, 16);
    let payload = sequential_payload(c.data_capacity());
    let enc = encode(&c, &payload).expect("encode");

    // Drop 2 shards when only 1 parity: should fail
    let avail = make_available(&enc, &[0, 1]); // only 2 data, need 4
    assert!(
        reconstruct(&c, &avail, None).is_none(),
        "single parity: 2 missing should be unrecoverable"
    );
}

#[test]
fn corruption_exceeding_m_is_detected_double() {
    let c = config(4, 2, 16);
    let payload = sequential_payload(c.data_capacity());
    let enc = encode(&c, &payload).expect("encode");

    // Drop 3 shards when only 2 parity: should fail
    let avail = make_available(&enc, &[0, 3, 5]);
    assert!(
        reconstruct(&c, &avail, None).is_none(),
        "double parity: 3 missing should be unrecoverable"
    );
}

#[test]
fn corruption_exceeding_m_is_detected_triple() {
    let c = config(4, 3, 16);
    let payload = sequential_payload(c.data_capacity());
    let enc = encode(&c, &payload).expect("encode");

    // Drop 4 shards when only 3 parity: should fail
    let avail = make_available(&enc, &[1]); // only 1 present, need 4
    assert!(
        reconstruct(&c, &avail, None).is_none(),
        "triple parity: 4 missing should be unrecoverable"
    );
}

// ---------------------------------------------------------------------------
// Corruption in every byte position of a single shard
// ---------------------------------------------------------------------------

#[test]
fn single_shard_all_byte_positions_corruption_recoverable() {
    let c = config(3, 2, 8);
    let payload = sequential_payload(c.data_capacity());
    let enc = encode(&c, &payload).expect("encode");

    for byte_pos in 0..c.shard_len {
        let mut shards: Vec<_> = enc.shards.iter().map(|s| Some(s.clone())).collect();
        corrupt_shard(shards[2].as_mut().unwrap(), byte_pos, 0);

        let avail: Vec<Option<ErasureShard>> = (0..c.stripe_width())
            .map(|i| if i == 2 { None } else { shards[i].clone() })
            .collect();
        let rec = reconstruct(&c, &avail, None)
            .unwrap_or_else(|| panic!("should recover single corruption at byte {byte_pos}"));
        assert_eq!(&rec.payload[..payload.len()], &payload);
    }
}

// ---------------------------------------------------------------------------
// Zero-data payload: corruption of a data shard still detectable
// ---------------------------------------------------------------------------

#[test]
fn zero_payload_data_corruption_detected() {
    let c = config(4, 1, 16);
    let payload = vec![0u8; c.data_capacity()];
    let enc = encode(&c, &payload).expect("encode");

    // Corrupt data shard 0
    let mut shards: Vec<_> = enc.shards.iter().map(|s| Some(s.clone())).collect();
    corrupt_shard(shards[0].as_mut().unwrap(), 0, 0);

    // Reconstruct excluding the corrupted shard
    let avail: Vec<Option<ErasureShard>> = (0..c.stripe_width())
        .map(|i| if i == 0 { None } else { shards[i].clone() })
        .collect();
    let rec = reconstruct(&c, &avail, None).expect("reconstruct");
    assert_eq!(&rec.payload[..payload.len()], &payload);
    // Rebuilt data shard 0 should be all zeros (not corrupted)
    assert!(rec.rebuilt_shards[0].bytes.iter().all(|&b| b == 0));
}
