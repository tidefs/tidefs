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

/// Verify that reconstructing from exactly the given shard indices recovers
/// the original payload byte-for-byte.
fn assert_roundtrip(c: &StripeConfig, payload: &[u8], keep: &[usize]) {
    let enc = encode(c, payload).expect("encode");
    let avail = make_available(&enc, keep);
    let rec = reconstruct(c, &avail, None).expect("reconstruct");
    assert_eq!(
        &rec.payload[..payload.len()],
        payload,
        "roundtrip failed: keep={keep:?}"
    );
}

// ---------------------------------------------------------------------------
// First-k-shards reconstruction
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_from_first_k_shards() {
    for (k, m) in [(2, 1), (4, 2), (8, 3)] {
        let c = config(k, m, 16);
        let payload = sequential_payload(c.data_capacity());
        let keep: Vec<usize> = (0..k).collect();
        assert_roundtrip(&c, &payload, &keep);
    }
}

// ---------------------------------------------------------------------------
// Last-k-shards (parity-based) reconstruction
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_from_last_k_shards() {
    // When enough parity shards exist to reconstruct, we should be able to
    // recover from parity-only shards (the last k available).
    for (k, m) in [
        (2, 2), // 2 data + 2 parity → use 2 parity
        (3, 3), // 3 data + 3 parity → use 3 parity
        (4, 3), // can't: only 3 parity, need 4 → skip
    ] {
        let c = config(k, m, 16);
        let payload = sequential_payload(c.data_capacity());
        let w = c.stripe_width();
        // Use the last k shards (all parity)
        let keep: Vec<usize> = (w - k..w).collect();
        assert_roundtrip(&c, &payload, &keep);
    }
}

#[test]
fn single_parity_roundtrip_from_last_k_fails_when_k_gt_1() {
    // With single parity (m=1), we only have 1 parity shard. If k > 1 we cannot
    // reconstruct from parity-only shards.
    let c = config(3, 1, 16);
    let payload = sequential_payload(c.data_capacity());
    let enc = encode(&c, &payload).expect("encode");
    let w = c.stripe_width();
    let keep: Vec<usize> = (w - c.parity_shards..w).collect(); // parity-only
    let avail = make_available(&enc, &keep);
    assert!(
        reconstruct(&c, &avail, None).is_none(),
        "single parity cannot reconstruct k={} data shards from parity alone",
        c.data_shards
    );
}

// ---------------------------------------------------------------------------
// Random k-of-n shard subsets
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_from_random_k_of_n_subset_single_parity() {
    let c = config(6, 1, 16);
    let payload = sequential_payload(c.data_capacity());
    let w = c.stripe_width(); // 7
                              // Try every possible drop of 1 shard: any 6-of-7 should work
    for drop in 0..w {
        let keep: Vec<usize> = (0..w).filter(|&i| i != drop).collect();
        assert_roundtrip(&c, &payload, &keep);
    }
}

#[test]
fn roundtrip_from_random_k_of_n_subset_double_parity() {
    let c = config(5, 2, 16);
    let payload = sequential_payload(c.data_capacity());
    let w = c.stripe_width(); // 7
                              // Try drops of 2 shards: any 5-of-7 should work with double parity
    for d1 in 0..w {
        for d2 in (d1 + 1)..w {
            let keep: Vec<usize> = (0..w).filter(|&i| i != d1 && i != d2).collect();
            assert_roundtrip(&c, &payload, &keep);
        }
    }
}

#[test]
fn roundtrip_from_random_k_of_n_subset_triple_parity() {
    let c = config(4, 3, 16);
    let payload = sequential_payload(c.data_capacity());
    let w = c.stripe_width(); // 7
                              // Try drops of 3 shards: any 4-of-7 should work with triple parity
    for d1 in 0..w {
        for d2 in (d1 + 1)..w {
            for d3 in (d2 + 1)..w {
                let keep: Vec<usize> = (0..w).filter(|&i| i != d1 && i != d2 && i != d3).collect();
                assert_roundtrip(&c, &payload, &keep);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// All-data reconstruction (no shards lost, no parity needed)
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_all_shards_present_no_rebuild() {
    for (k, m) in [(1, 1), (4, 2), (6, 3)] {
        let c = config(k, m, 32);
        let payload = sequential_payload(c.data_capacity());
        let enc = encode(&c, &payload).expect("encode");
        let w = c.stripe_width();
        let keep: Vec<usize> = (0..w).collect();
        let avail = make_available(&enc, &keep);
        let rec = reconstruct(&c, &avail, None).expect("reconstruct");
        assert_eq!(&rec.payload[..payload.len()], &payload);
        assert!(
            rec.rebuilt_shards.is_empty(),
            "no shards should be rebuilt when all present"
        );
    }
}

// ---------------------------------------------------------------------------
// Short payload round-trip
// ---------------------------------------------------------------------------

#[test]
fn short_payload_roundtrip_different_sizes() {
    for len in [1, 2, 7, 15, 31] {
        let c = config(4, 2, 8);
        let payload = vec![0xCDu8; len];
        let enc = encode(&c, &payload).expect("encode");
        assert_eq!(enc.original_payload_len, len);
        let rec = reconstruct(&c, &make_available(&enc, &[0, 1, 2, 3]), None).expect("reconstruct");
        assert_eq!(&rec.payload[..len], &payload[..]);
        // Padding region beyond original length should be zeros
        assert!(rec.payload[len..].iter().all(|&b| b == 0));
    }
}

// ---------------------------------------------------------------------------
// k=1 edge cases (single data shard)
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_k1_m1() {
    let c = config(1, 1, 64);
    let payload = sequential_payload(c.data_capacity());
    assert_roundtrip(&c, &payload, &[0]); // data only
    assert_roundtrip(&c, &payload, &[1]); // parity only (mirror)
}

#[test]
fn roundtrip_k1_m2() {
    let c = config(1, 2, 32);
    let payload = sequential_payload(c.data_capacity());
    assert_roundtrip(&c, &payload, &[0]); // data only
    assert_roundtrip(&c, &payload, &[1]); // first parity
    assert_roundtrip(&c, &payload, &[2]); // second parity
}

#[test]
fn roundtrip_k1_m3() {
    let c = config(1, 3, 16);
    let payload = sequential_payload(c.data_capacity());
    assert_roundtrip(&c, &payload, &[0]); // data only
    assert_roundtrip(&c, &payload, &[1]); // first parity
    assert_roundtrip(&c, &payload, &[2]); // second parity
    assert_roundtrip(&c, &payload, &[3]); // third parity
}
