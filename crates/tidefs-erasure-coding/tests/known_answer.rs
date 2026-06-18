// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_erasure_coding::*;

// ---------------------------------------------------------------------------
// Known-answer tests: pre-computed BLAKE3 hashes of encoded shards.
// These catch algorithmic regressions by verifying bit-identical encode output
// across compiler versions, platform differences, and refactoring.
// ---------------------------------------------------------------------------

fn hash_shard(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn encode_and_hash(k: usize, m: usize, shard_len: usize, payload: &[u8]) -> Vec<String> {
    let c = StripeConfig {
        data_shards: k,
        parity_shards: m,
        shard_len,
    };
    let enc = encode(&c, payload).expect("encode");
    enc.shards.iter().map(|s| hash_shard(&s.bytes)).collect()
}

// ---------------------------------------------------------------------------
// Config 1: k=4, Double parity, shard_len=16, sequential payload
// ---------------------------------------------------------------------------

#[test]
fn known_answer_k4_double_sequential() {
    let c = StripeConfig {
        data_shards: 4,
        parity_shards: 2,
        shard_len: 16,
    };
    let payload: Vec<u8> = (0..c.data_capacity()).map(|i| (i & 0xFF) as u8).collect();
    let hashes = encode_and_hash(c.data_shards, c.parity_shards, c.shard_len, &payload);

    let expected = [
        "a6a492965517a830cb75fdb713465aa465f2f098233896fea44c1d98268bf9e3",
        "ea5ff194405ece4f55ae7a150c5238841646a73bc86d659949a772bdcd1acde2",
        "ed008e954c2404a8070f75850c716d6ffa21de4bb4390262e616e0bcea41eb50",
        "d856baf6b85b57bc538158dec3936f3e585351fdb9ccd863913bf1a8c8985b76",
        "9afc645bf39a874857833e20793f1f0d1b7127dcef0ff3d6d51f3e4a12008c0e",
        "84233dd3e70581b7ec5ea055daafb83981ca748e91bae912670e6beae91def3f",
    ];
    assert_eq!(hashes.len(), expected.len());
    for (i, (h, e)) in hashes.iter().zip(expected.iter()).enumerate() {
        assert_eq!(h, e, "shard[{i}] hash mismatch for k=4,Double,shard_len=16");
    }
}

// ---------------------------------------------------------------------------
// Config 2: k=2, Single parity, shard_len=8, all-zeros payload
// ---------------------------------------------------------------------------

#[test]
fn known_answer_k2_single_zeros() {
    let c = StripeConfig {
        data_shards: 2,
        parity_shards: 1,
        shard_len: 8,
    };
    let payload = vec![0u8; c.data_capacity()];
    let hashes = encode_and_hash(c.data_shards, c.parity_shards, c.shard_len, &payload);

    let expected = [
        "71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb",
        "71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb",
        "71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb",
    ];
    assert_eq!(hashes.len(), expected.len());
    for (i, (h, e)) in hashes.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            h, e,
            "shard[{i}] hash mismatch for k=2,Single,shard_len=8,zeros"
        );
    }
}

// ---------------------------------------------------------------------------
// Config 3: k=6, Triple parity, shard_len=32, patterned payload
// ---------------------------------------------------------------------------

#[test]
fn known_answer_k6_triple_patterned() {
    let c = StripeConfig {
        data_shards: 6,
        parity_shards: 3,
        shard_len: 32,
    };
    let payload: Vec<u8> = (0..c.data_capacity())
        .map(|i| (i.wrapping_mul(17) ^ 0xA5) as u8)
        .collect();
    let hashes = encode_and_hash(c.data_shards, c.parity_shards, c.shard_len, &payload);

    let expected = [
        "8e46b5461f9afde25fc5dc8b336f6b9b4dfe2d83ca515091041e41e564952d23",
        "fec868dbc4a9dca0acb350e76a079763d2918f7503550085cc382b8dbb8c1f8f",
        "331f00c9af2558e5f90cdfd1e2efc3b01cf4b6e420c9426a78e36f561224afaf",
        "9185f88b8628ff89b7ee994fa8432b42c2592aacf7b81faa13f98e2f59fdc237",
        "61eca271fa3db3f0eadf866cef356f2f70c7d227cb6485d36214491123bbf79a",
        "6e5eacfc7945dbc3b31ebd28e2350bfa97396a6fc2e9fc900ff2a5b401152711",
        "40834911d2452be7ee4c9878042bf2b9d67cca8c00c3c0304cc5c38a36a7bd5a",
        "f8cd1a0c9be3b011a0273ff287466acaf33be925ed69f2535bc251402205f636",
        "f05ffee23adca35527ebafbfe9ff15a521784988cb435f27b19f7022ae50023f",
    ];
    assert_eq!(hashes.len(), expected.len());
    for (i, (h, e)) in hashes.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            h, e,
            "shard[{i}] hash mismatch for k=6,Triple,shard_len=32,patterned"
        );
    }
}

// ---------------------------------------------------------------------------
// Config 4: k=1, Triple parity, shard_len=64, single 0x42 byte
// ---------------------------------------------------------------------------

#[test]
fn known_answer_k1_triple_single_byte() {
    let c = StripeConfig {
        data_shards: 1,
        parity_shards: 3,
        shard_len: 64,
    };
    let payload = vec![0x42u8; 1];
    let hashes = encode_and_hash(c.data_shards, c.parity_shards, c.shard_len, &payload);

    let expected = [
        "9a8802e17e81e7f124bb3bae39ab8f8f373534d9dd4dd81a1735351fcce14514",
        "0f5d191245547fc92117f1e4d4ac5bbda697ec2af5b26c2ae6504429b54badc8",
        "d23867e880887f78e72e0915a69deb4963fd7784f6b2530fa41a4da8a3e4271b",
        "9a8802e17e81e7f124bb3bae39ab8f8f373534d9dd4dd81a1735351fcce14514",
    ];
    assert_eq!(hashes.len(), expected.len());
    for (i, (h, e)) in hashes.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            h, e,
            "shard[{i}] hash mismatch for k=1,Triple,shard_len=64,single 0x42"
        );
    }
}

// ---------------------------------------------------------------------------
// Config 5: k=3, Single parity, shard_len=1, diverse payload [0x0F, 0xF0, 0x55]
// ---------------------------------------------------------------------------

#[test]
fn known_answer_k3_single_diverse_bytes() {
    let c = StripeConfig {
        data_shards: 3,
        parity_shards: 1,
        shard_len: 1,
    };
    let payload = vec![0x0F, 0xF0, 0x55];
    let hashes = encode_and_hash(c.data_shards, c.parity_shards, c.shard_len, &payload);

    let expected = [
        "0bf6b955abb4968191ebf8869d03ae5f74aa0538ffdbddeafc970c507da7d71d",
        "e983e0a9e5530c2b7714e678e93dbc8196947cbe6fc33fa3d46a24f06ffb62c1",
        "e04188fed98bfc7ab50f3310b8558c54f19d24a6fc3506d16c270053404c07b5",
        "3afcdd8a9bd7b7458c2af708163c0a3259bef038576403af0d2c411a174c4b8f",
    ];
    assert_eq!(hashes.len(), expected.len());
    for (i, (h, e)) in hashes.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            h, e,
            "shard[{i}] hash mismatch for k=3,Single,shard_len=1,diverse"
        );
    }
}

// ---------------------------------------------------------------------------
// Config 6: k=12, Double parity, shard_len=4, reverse-bits payload
// ---------------------------------------------------------------------------

#[test]
fn known_answer_k12_double_reverse_bits() {
    let c = StripeConfig {
        data_shards: 12,
        parity_shards: 2,
        shard_len: 4,
    };
    let payload: Vec<u8> = (0..c.data_capacity())
        .map(|i| (i as u8).reverse_bits())
        .collect();
    let hashes = encode_and_hash(c.data_shards, c.parity_shards, c.shard_len, &payload);

    let expected = [
        "938fa0b368f2d5b4f7cd3e605937fe34ba55f46f5fc4869eeb6f05cea81a8131",
        "27e526b42c8a82b8348adc4f51679d99440a897cc2d471675f67c53da6a7e9fb",
        "b181b0e664061d7ffc6b7029e5ca26237df795159f0cb876771a30efbae1d0e7",
        "8877c89e8985e8ce00a2d372587ab534829cc50c942d9311d89991ea486f7560",
        "211a3b4824a09852e1deb4ef848dd7071fd4870682c10d09af497cb07d880969",
        "ae38a04b4bb76ac393d2870f72bf230fbd356e5daa857abbafde681f6a215760",
        "90c96955def2f0275042fa73d113546ce02f972b65a01cbbbc240f6e4237fb0f",
        "ddc1cc5d5229d10087583fb866381b3241380d89056b184be457cfef47b69627",
        "fcae7c34efca99a87c60508416c0443ca0f484dfaf5dca06fdeedd6155aeadb3",
        "c59d79febdf70ef9b32dd0e34d904302adb0fafb6ffb2bb431a041db9d3a1b0b",
        "f3d0910eb10f91c8ac1eaf79ebc99b172fe7c276548a42c452cede68b644d889",
        "ae269a718b96e99ac5e1ae7005db5eb66c6b6bb2e05ec15ec3a8d7a1ca758ced",
        "dc237198f1f03697fe2949ce6ba1aa7acc369d098751a876cefbf48645eea0d3",
        "1694a4ba3764a9c0036844aba3d51a26299d12109e57e2a35c1195473918715a",
    ];
    assert_eq!(hashes.len(), expected.len());
    for (i, (h, e)) in hashes.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            h, e,
            "shard[{i}] hash mismatch for k=12,Double,shard_len=4,reverse-bits"
        );
    }
}

// ---------------------------------------------------------------------------
// Cross-check: reconstructed payload after single-loss also has deterministic hash
// ---------------------------------------------------------------------------

#[test]
fn known_answer_reconstruction_after_single_loss() {
    let c = StripeConfig {
        data_shards: 4,
        parity_shards: 2,
        shard_len: 16,
    };
    let payload: Vec<u8> = (0..c.data_capacity()).map(|i| (i & 0xFF) as u8).collect();
    let enc = encode(&c, &payload).expect("encode");

    // Drop shard 1 and reconstruct
    let avail: Vec<Option<ErasureShard>> = (0..c.stripe_width())
        .map(|i| {
            if i == 1 {
                None
            } else {
                Some(enc.shards[i].clone())
            }
        })
        .collect();
    let rec = reconstruct(&c, &avail, None).expect("reconstruct");

    let payload_hash = blake3::hash(&rec.payload).to_hex().to_string();
    assert_eq!(
        payload_hash, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        "reconstructed payload hash after single loss"
    );
    assert_eq!(rec.rebuilt_shards.len(), 1);
    assert_eq!(rec.rebuilt_shards[0].index, 1);
    let rebuilt_hash = hash_shard(&rec.rebuilt_shards[0].bytes);
    assert_eq!(
        rebuilt_hash, "ea5ff194405ece4f55ae7a150c5238841646a73bc86d659949a772bdcd1acde2",
        "rebuilt shard hash should match original shard 1"
    );
}
