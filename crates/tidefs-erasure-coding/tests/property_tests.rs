use proptest::prelude::*;
use tidefs_erasure_coding::*;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Generate a valid `StripeConfig` for property testing.
fn arb_config() -> impl Strategy<Value = StripeConfig> {
    (1usize..=16, 1usize..=16, 1usize..=64).prop_map(|(k, shard_len_base, seed)| {
        let shard_len = std::cmp::max(1, shard_len_base);
        let m = match seed % 3 {
            0 => 1,
            1 => 2,
            _ => 3,
        };
        let actual_k = std::cmp::min(k, 12 - m);
        let actual_k = std::cmp::max(actual_k, 1);
        StripeConfig {
            data_shards: actual_k,
            parity_shards: m,
            shard_len: std::cmp::min(shard_len, 128),
        }
    })
}

/// Generate a (config, payload) pair.
fn arb_config_and_payload() -> impl Strategy<Value = (StripeConfig, Vec<u8>)> {
    arb_config()
        .prop_flat_map(|c| {
            let cap = c.data_capacity();
            (Just(c), 0..=cap)
        })
        .prop_flat_map(|(c, len)| {
            let payload = proptest::collection::vec(any::<u8>(), len);
            (Just(c), payload)
        })
}

// ---------------------------------------------------------------------------
// Encode-decode identity
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn encode_decode_identity((ref config, ref payload) in arb_config_and_payload()) {
        let enc = encode(config, payload)
            .unwrap_or_else(|| panic!("encode failed: k={} m={} shard_len={} payload_len={}",
                config.data_shards, config.parity_shards, config.shard_len, payload.len()));
        assert_eq!(enc.original_payload_len, payload.len());
        assert_eq!(enc.shards.len(), config.stripe_width());

        // Reconstruct from first k shards
        let keep: Vec<usize> = (0..config.data_shards).collect();
        let avail: Vec<Option<ErasureShard>> = (0..config.stripe_width())
            .map(|i| if keep.contains(&i) { Some(enc.shards[i].clone()) } else { None })
            .collect();
        let rec = reconstruct(config, &avail, None)
            .unwrap_or_else(|| panic!("reconstruct failed: k={} m={} shard_len={} payload_len={}",
                config.data_shards, config.parity_shards, config.shard_len, payload.len()));
        assert_eq!(&rec.payload[..payload.len()], payload.as_slice());
        // No shards rebuilt when all data shards present
        // Parity shards may be rebuilt since they are not in the keep set
    }

    #[test]
    fn encode_decode_identity_with_data_loss(
        (ref config, ref payload) in arb_config_and_payload(),
        drop_count in 1usize..=3,
    ) {
        let m = config.parity_shards;
        let drop_count = std::cmp::min(drop_count, m);
        if config.data_shards <= drop_count {
            return Ok(());
        }

        let enc = encode(config, payload)
            .unwrap_or_else(|| panic!("encode failed"));

        let w = config.stripe_width();
        let mut drops: Vec<usize> = (0..drop_count)
            .map(|i| (i * 3 + 1) % config.data_shards)
            .collect();
        drops.sort();
        drops.dedup();
        if drops.len() < drop_count {
            return Ok(());
        }

        let avail: Vec<Option<ErasureShard>> = (0..w)
            .map(|i| if drops.contains(&i) { None } else { Some(enc.shards[i].clone()) })
            .collect();

        if let Some(rec) = reconstruct(config, &avail, None) {
            assert_eq!(&rec.payload[..payload.len()], payload.as_slice());
            assert_eq!(rec.rebuilt_shards.len(), drops.len());
        }
    }

    #[test]
    fn any_k_distinct_shards_suffice_for_decoding(
        (ref config, ref payload) in arb_config_and_payload(),
    ) {
        let k = config.data_shards;
        let w = config.stripe_width();
        let enc = encode(config, payload)
            .unwrap_or_else(|| panic!("encode failed"));

        // Test reconstruction from first k indices (identity data shards)
        {
            let keep: Vec<usize> = (0..k).collect();
            let avail: Vec<Option<ErasureShard>> = (0..w)
                .map(|i| if keep.contains(&i) { Some(enc.shards[i].clone()) } else { None })
                .collect();
            let rec = reconstruct(config, &avail, None).expect("first k should always work");
            assert_eq!(&rec.payload[..payload.len()], payload.as_slice());
        }

        // Test reconstruction from a deterministic shuffled k-subset
        let seed = config.data_shards.wrapping_mul(31)
            .wrapping_add(config.parity_shards.wrapping_mul(17))
            .wrapping_add(config.shard_len);
        let mut shuffled: Vec<usize> = (0..w).collect();
        for i in (1..shuffled.len()).rev() {
            let j = (seed.wrapping_mul(i + 1)) % (i + 1);
            shuffled.swap(i, j);
        }
        let keep: Vec<usize> = shuffled.into_iter().take(k).collect();

        let avail: Vec<Option<ErasureShard>> = (0..w)
            .map(|i| if keep.contains(&i) { Some(enc.shards[i].clone()) } else { None })
            .collect();

        let rec = reconstruct(config, &avail, None)
            .unwrap_or_else(|| panic!(
                "k={k} w={w} keep={keep:?}: reconstruction should succeed for any k shards"
            ));
        assert_eq!(&rec.payload[..payload.len()], payload.as_slice());
    }
}

// ---------------------------------------------------------------------------
// Deterministic property: encode is idempotent
// ---------------------------------------------------------------------------

#[test]
fn encode_idempotent_across_three_calls() {
    let c = StripeConfig {
        data_shards: 4,
        parity_shards: 2,
        shard_len: 16,
    };
    let payload: Vec<u8> = (0..c.data_capacity())
        .map(|i| (i.wrapping_mul(17)) as u8)
        .collect();
    let enc1 = encode(&c, &payload).expect("first");
    let enc2 = encode(&c, &payload).expect("second");
    let enc3 = encode(&c, &payload).expect("third");
    for i in 0..enc1.shards.len() {
        assert_eq!(enc1.shards[i].bytes, enc2.shards[i].bytes);
        assert_eq!(enc2.shards[i].bytes, enc3.shards[i].bytes);
    }
}

// ---------------------------------------------------------------------------
// Deterministic property: reconstruction is deterministic
// ---------------------------------------------------------------------------

#[test]
fn reconstruct_deterministic() {
    let c = StripeConfig {
        data_shards: 4,
        parity_shards: 2,
        shard_len: 16,
    };
    let payload: Vec<u8> = (0..c.data_capacity())
        .map(|i| (i ^ (i >> 4)) as u8)
        .collect();
    let enc = encode(&c, &payload).expect("encode");
    let avail: Vec<Option<ErasureShard>> = (0..c.stripe_width())
        .map(|i| {
            if i == 1 || i == 5 {
                None
            } else {
                Some(enc.shards[i].clone())
            }
        })
        .collect();
    let rec1 = reconstruct(&c, &avail, None).expect("first");
    let rec2 = reconstruct(&c, &avail, None).expect("second");
    assert_eq!(rec1.payload, rec2.payload);
    for (a, b) in rec1.rebuilt_shards.iter().zip(rec2.rebuilt_shards.iter()) {
        assert_eq!(a.bytes, b.bytes);
    }
}

// ---------------------------------------------------------------------------
// Config validation invariants
// ---------------------------------------------------------------------------

#[test]
fn stripe_width_is_data_plus_parity() {
    for k in 1..=16 {
        for m in [1, 2, 3] {
            let c = StripeConfig {
                data_shards: k,
                parity_shards: m,
                shard_len: 8,
            };
            assert_eq!(c.stripe_width(), k + m);
        }
    }
}

#[test]
fn data_capacity_is_data_shards_times_shard_len() {
    for k in 1..=8 {
        for sl in [1, 8, 64, 4096] {
            let c = StripeConfig {
                data_shards: k,
                parity_shards: 1,
                shard_len: sl,
            };
            assert_eq!(c.data_capacity(), k * sl);
        }
    }
}
