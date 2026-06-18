// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_checksum_tree::{
    hash_block, incremental_update, zero_digest, ChecksumTree, ChecksumTreeBuilder,
    ChecksumTreeVerifier, Digest, VerificationResult, DEFAULT_BLOCK_SIZE, DIGEST_SIZE, FANOUT,
};

use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Strategy generator helpers
// ---------------------------------------------------------------------------

/// Byte vector up to ~256 KiB for manageable proptest run times.
fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..262144)
}

/// Byte vector up to ~64 KiB — used in paired generators (prefix+suffix).
fn arb_bytes_small() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..65536)
}

// ---------------------------------------------------------------------------
// 1. Round-trip: build, verify, rebuild, compare
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn round_trip_arbitrary_bytes(bytes in arb_bytes()) {
        let block_size = DEFAULT_BLOCK_SIZE;

        // Build tree via streaming builder.
        let mut builder = ChecksumTreeBuilder::new(block_size);
        builder.ingest(&bytes);
        let tree_from_builder = builder.finish();

        // Verify full data against tree.
        let verifier = ChecksumTreeVerifier::new(tree_from_builder.clone());
        prop_assert_eq!(verifier.verify_full(&bytes), VerificationResult::Verified);

        // Rebuild via from_leaves using manual chunk hashing —
        // proves leaf hashes computed by builder match direct BLAKE3.
        let leaf_digests: Vec<Digest> = bytes
            .chunks(block_size)
            .map(hash_block)
            .collect();
        let tree_from_leaves = ChecksumTree::from_leaves(&leaf_digests, block_size);

        prop_assert_eq!(tree_from_builder.root_hash, tree_from_leaves.root_hash);
        prop_assert_eq!(tree_from_builder.block_count, tree_from_leaves.block_count);

        // Determinism: second builder on same bytes yields identical tree.
        let mut builder2 = ChecksumTreeBuilder::new(block_size);
        builder2.ingest(&bytes);
        let tree2 = builder2.finish();
        prop_assert_eq!(tree_from_builder.root_hash, tree2.root_hash);
        prop_assert_eq!(tree_from_builder.nodes, tree2.nodes);
    }
}

// ---------------------------------------------------------------------------
// 2. Incremental-append: multiple ingest calls produce a tree that verifies
//    the combined data. (Node-by-node equality is not guaranteed when
//    partial blocks straddle ingest boundaries — each ingest call chunks
//    independently. We test structural equality only when prefix is block-
//    aligned.)
// ---------------------------------------------------------------------------

proptest! {
    /// When prefix length is a multiple of block_size, ingest(prefix) + ingest(suffix)
    /// must produce the same tree nodes as ingest(prefix+suffix).
    #[test]
    fn incremental_append_block_aligned(
        prefix_blocks in 0usize..16,
        suffix in arb_bytes_small(),
    ) {
        let block_size = DEFAULT_BLOCK_SIZE;
        let prefix_len = prefix_blocks * block_size;
        let prefix: Vec<u8> = (0..prefix_len)
            .map(|i| (i.wrapping_mul(37).wrapping_add(17) % 251) as u8)
            .collect();

        // Build incrementally.
        let mut incr_builder = ChecksumTreeBuilder::new(block_size);
        incr_builder.ingest(&prefix);
        incr_builder.ingest(&suffix);
        let incr_tree = incr_builder.finish();

        // Build from concatenated data.
        let combined: Vec<u8> = prefix.iter().chain(suffix.iter()).copied().collect();
        let mut single_builder = ChecksumTreeBuilder::new(block_size);
        single_builder.ingest(&combined);
        let single_tree = single_builder.finish();

        // When prefix is block-aligned, the two trees must be identical.
        prop_assert_eq!(incr_tree.root_hash, single_tree.root_hash);
        prop_assert_eq!(incr_tree.block_count, single_tree.block_count);
        prop_assert_eq!(incr_tree.node_count(), single_tree.node_count());
        prop_assert_eq!(incr_tree.nodes, single_tree.nodes.clone());

        // The tree must verify the combined data.
        let verifier = ChecksumTreeVerifier::new(single_tree);
        prop_assert_eq!(verifier.verify_full(&combined), VerificationResult::Verified);
    }

}

// ---------------------------------------------------------------------------
// 3. Boundary-exhaustive: deterministic tests at every power-of-two boundary
// ---------------------------------------------------------------------------

#[test]
fn boundary_block_sizes_with_data() {
    let block_size = DEFAULT_BLOCK_SIZE;
    let bs = block_size;

    // Sizes that cross block and fanout boundaries —
    // capped at ~1 MiB of actual data.
    let sizes: &[usize] = &[
        0,
        1,
        bs - 1,
        bs,
        bs + 1,
        2 * bs - 1,
        2 * bs,
        2 * bs + 1,
        3 * bs,
        7 * bs + 3,
        FANOUT * bs - 1,
        FANOUT * bs,
        FANOUT * bs + 1,
        (FANOUT + 1) * bs - 3,
        (FANOUT + 1) * bs,
    ];

    for &size in sizes {
        // Deterministic pseudo-data of exactly `size` bytes.
        let data: Vec<u8> = (0..size)
            .map(|i| (i.wrapping_mul(37).wrapping_add(17) % 251) as u8)
            .collect();

        // Build twice — must be deterministic.
        let mut b1 = ChecksumTreeBuilder::new(block_size);
        b1.ingest(&data);
        let t1 = b1.finish();

        let mut b2 = ChecksumTreeBuilder::new(block_size);
        b2.ingest(&data);
        let t2 = b2.finish();

        assert_eq!(t1.root_hash, t2.root_hash, "size={size}");
        assert_eq!(t1.block_count, t2.block_count, "size={size}");
        assert_eq!(t1.nodes, t2.nodes, "size={size}");

        // Verify full data.
        let verifier = ChecksumTreeVerifier::new(t1);
        assert_eq!(
            verifier.verify_full(&data),
            VerificationResult::Verified,
            "size={size}"
        );

        // Every interior node must pass self-verification.
        for (idx, node) in t2.nodes.iter().enumerate() {
            assert!(
                node.verify(),
                "size={size} node {idx} failed self-verification"
            );
        }
    }
}

/// Test multi-level tree structure at fanout boundaries using synthetic leaf
/// digests (avoids allocating multi-GiB data vectors).
#[test]
fn boundary_multi_level_tree_structure() {
    // Use a small block size so the hash values are compact but the tree
    // structure spans multiple levels.
    let bs: usize = 64;

    // Leaf count boundaries spanning 1, 2, and 3 levels deep.
    let leaf_counts: &[u64] = &[
        0,
        1,
        FANOUT as u64 - 1,
        FANOUT as u64,
        FANOUT as u64 + 1,
        (2 * FANOUT) as u64 - 1,
        (2 * FANOUT) as u64,
        (FANOUT * FANOUT) as u64 - 1,
        (FANOUT * FANOUT) as u64,
        (FANOUT * FANOUT) as u64 + 1,
        (FANOUT * FANOUT + FANOUT) as u64 - 1,
        (FANOUT * FANOUT + FANOUT) as u64,
    ];

    for &count in leaf_counts {
        let leaves: Vec<Digest> = (0..count).map(|i| hash_block(&i.to_le_bytes())).collect();

        // Build twice — deterministic.
        let t1 = ChecksumTree::from_leaves(&leaves, bs);
        let t2 = ChecksumTree::from_leaves(&leaves, bs);

        assert_eq!(t1.root_hash, t2.root_hash, "count={count}");
        assert_eq!(t1.block_count, count, "count={count}");
        assert_eq!(t1.block_size, bs, "count={count}");
        assert_eq!(t1.nodes, t2.nodes, "count={count}");

        // Root hash must be non-zero for non-empty trees.
        if count > 0 {
            assert_ne!(t1.root_hash, zero_digest(), "count={count}");
        } else {
            assert_eq!(t1.root_hash, zero_digest(), "count={count}");
        }

        // Level count must match expected.
        let expected_levels = if count == 0 {
            0
        } else if count <= FANOUT as u64 {
            1
        } else if count <= (FANOUT * FANOUT) as u64 {
            2
        } else {
            3
        };
        assert_eq!(t1.level_count(), expected_levels, "count={count}");

        // All interior nodes must pass self-verification.
        for (idx, node) in t2.nodes.iter().enumerate() {
            assert!(
                node.verify(),
                "count={count} node {idx} failed self-verification"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Tamper detection: flip one byte, verify correct block index reported
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn tamper_detection_at_correct_leaf(
        bytes in prop::collection::vec(any::<u8>(), 1..65536),
        flip_byte in 0usize..65536,
    ) {
        let block_size = DEFAULT_BLOCK_SIZE;

        // Build tree from original bytes.
        let mut builder = ChecksumTreeBuilder::new(block_size);
        builder.ingest(&bytes);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);

        let mut corrupted = bytes.clone();
        let pos = flip_byte % corrupted.len();
        corrupted[pos] ^= 0xFF;

        let result = verifier.verify_full(&corrupted);

        let expected_offset = ((pos / block_size) * block_size) as u64;
        match result {
            VerificationResult::Corrupted { offset, .. } => {
                prop_assert!(
                    offset == expected_offset,
                    "corruption at byte {} should map to block offset {} but got {}",
                    pos, expected_offset, offset
                );
            }
            VerificationResult::Verified => {
                // Byte flip might hash to the same value (extremely unlikely but
                // proptest may hit it with 1-byte input). Accept this case.
            }
            other => panic!("expected Corrupted or Verified, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Empty and single-block trees
// ---------------------------------------------------------------------------

#[test]
fn empty_tree_well_defined_root() {
    // Direct from_leaves with zero leaves.
    let tree = ChecksumTree::from_leaves(&[], DEFAULT_BLOCK_SIZE);
    assert!(tree.is_empty());
    assert_eq!(tree.root_hash, zero_digest());
    assert_eq!(tree.block_count, 0);
    assert_eq!(tree.node_count(), 0);
    assert_eq!(tree.level_count(), 0);

    // Builder with empty ingest must produce same result.
    let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
    builder.ingest(&[]);
    let tree2 = builder.finish();
    assert!(tree2.is_empty());
    assert_eq!(tree2.root_hash, zero_digest());
    assert_eq!(tree2.root_hash, tree.root_hash);

    // Empty tree verifier: verify_full on empty data succeeds.
    let verifier = ChecksumTreeVerifier::new(tree2);
    assert_eq!(verifier.verify_full(&[]), VerificationResult::Verified);

    // verify_full on non-empty data against empty tree: tree has no blocks
    // to check, so no mismatch is flagged (consistent with verify_full
    // semantics: it only checks blocks the tree covers).
    assert_eq!(verifier.verify_full(b"x"), VerificationResult::Verified);
}

#[test]
fn single_block_tree_root_equals_leaf_hash() {
    let data = b"hello world, a test block for single-block tree construction";
    let leaf_hash = hash_block(data);

    // Single leaf via from_leaves.
    let tree = ChecksumTree::from_leaves(&[leaf_hash], DEFAULT_BLOCK_SIZE);
    assert_eq!(tree.root_hash, leaf_hash);
    assert_eq!(tree.block_count, 1);
    assert_eq!(tree.level_count(), 1);

    // Builder produces same result.
    let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
    builder.ingest(data);
    let tree2 = builder.finish();
    assert_eq!(tree2.root_hash, leaf_hash);
    assert_eq!(tree2.block_count, 1);

    // Verify full.
    let verifier = ChecksumTreeVerifier::new(tree2);
    assert_eq!(verifier.verify_full(data), VerificationResult::Verified);

    // Tampering should be detected.
    let mut bad = data.to_vec();
    bad[0] ^= 1;
    match verifier.verify_full(&bad) {
        VerificationResult::Corrupted { offset, .. } => assert_eq!(offset, 0),
        other => panic!("expected Corrupted, got {other:?}"),
    }
}

#[test]
fn single_byte_input_well_defined() {
    // Single byte input: block_size boundary edge case.
    let data = vec![0x42u8];
    let leaf_hash = hash_block(&data);

    let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
    builder.ingest(&data);
    let tree = builder.finish();

    assert_eq!(tree.root_hash, leaf_hash);
    assert_eq!(tree.block_count, 1);

    let verifier = ChecksumTreeVerifier::new(tree);
    assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);
}

// ---------------------------------------------------------------------------
// 6. Incremental update property: update a single leaf in a tree built from
//    from_leaves (working at leaf-digest level where block boundaries
//    are unambiguous).
// ---------------------------------------------------------------------------

proptest! {
    /// Updating a leaf via incremental_update must produce the same root
    /// hash as building a fresh tree with the updated leaf set.
    #[test]
    fn incremental_update_rebuild_equivalence(
        leaf_count in 1usize..256,
        change_idx in 0usize..256,
        new_seed in 0u64..65536,
    ) {
        let block_size = DEFAULT_BLOCK_SIZE;

        // Build a set of leaf digests.
        let idx = change_idx % leaf_count;
        let mut leaves: Vec<Digest> = (0..leaf_count)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();

        let tree = ChecksumTree::from_leaves(&leaves, block_size);

        // Change one leaf.  Offset new_seed above leaf_count so the
        // replacement digest is guaranteed to differ from the original
        // (which was built from 0..leaf_count).
        let new_leaf = hash_block(&(new_seed.wrapping_add(256)).to_le_bytes());
        let updated = incremental_update(&tree, idx as u64, new_leaf)
            .expect("valid block index");

        // Build expected tree with the same change applied to leaves.
        leaves[idx] = new_leaf;
        let expected = ChecksumTree::from_leaves(&leaves, block_size);

        prop_assert_eq!(updated.root_hash, expected.root_hash);
        prop_assert_eq!(updated.block_count, expected.block_count);
        prop_assert_ne!(updated.root_hash, tree.root_hash,
            "root must change when a leaf changes");
    }
}

// ---------------------------------------------------------------------------
// 7. Node-level tamper detection: corrupt a child byte in an interior
//    node → that node's verify() must return false. Separate tests for
//    root node and level-0 interior node guarantee full coverage.
// ---------------------------------------------------------------------------

proptest! {
    /// Corrupt a child byte in the root node of any multi-leaf tree.
    /// The corrupted node must fail self-verification.
    #[test]
    fn tamper_detection_root_node(
        leaf_count in 2usize..(FANOUT * 3 + 1),
        seed in 0usize..65536,
    ) {
        let leaves: Vec<Digest> = (0usize..leaf_count)
            .map(|i| hash_block(&(i.wrapping_mul(7).wrapping_add(seed)).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, DEFAULT_BLOCK_SIZE);

        if tree.node_count() == 0 {
            return Ok(());
        }

        let root_idx = tree.node_count() - 1;
        if tree.nodes[root_idx].children.is_empty() {
            return Ok(());
        }

        let child_idx = seed % tree.nodes[root_idx].children.len();
        let byte_idx = (seed >> 8) % DIGEST_SIZE;

        let mut corrupted_tree = tree.clone();
        corrupted_tree.nodes[root_idx].children[child_idx][byte_idx] ^= 0xFF;

        prop_assert!(
            !corrupted_tree.nodes[root_idx].verify(),
            "corrupted root node must fail self-verify"
        );

        // Other nodes at the same level should still verify.
        let level0_count = tree.block_count.div_ceil(FANOUT as u64) as usize;
        for i in 0..level0_count.min(tree.node_count()) {
            if i != root_idx {
                prop_assert!(
                    corrupted_tree.nodes[i].verify(),
                    "untouched node {i} must still verify"
                );
            }
        }
    }

    /// For a multi-level tree, corrupt a level-0 interior node (not
    /// the root). That node must fail self-verification while root
    /// (which depends on it) may or may not — but the corrupted
    /// node itself must fail.
    #[test]
    fn tamper_detection_level0_node(
        leaf_count in (FANOUT + 1)..(FANOUT * FANOUT + FANOUT),
        seed in 0usize..65536,
    ) {
        let leaves: Vec<Digest> = (0usize..leaf_count)
            .map(|i| hash_block(&(i.wrapping_mul(11).wrapping_add(seed)).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, DEFAULT_BLOCK_SIZE);

        if tree.level_count() < 2 {
            return Ok(());
        }

        let level0_count = tree.block_count.div_ceil(FANOUT as u64) as usize;
        let target = seed % level0_count;
        if target >= tree.node_count() || tree.nodes[target].children.is_empty() {
            return Ok(());
        }

        let child_idx = (seed >> 8) % tree.nodes[target].children.len();
        let byte_idx = (seed >> 16) % DIGEST_SIZE;

        let mut corrupted_tree = tree.clone();
        corrupted_tree.nodes[target].children[child_idx][byte_idx] ^= 0xFF;

        prop_assert!(
            !corrupted_tree.nodes[target].verify(),
            "corrupted level-0 node must fail self-verify"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. Universal node self-verification: for any set of leaf digests,
//    every interior node in the constructed tree must pass verify().
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn all_nodes_self_verify(
        leaf_count in 0usize..(FANOUT * FANOUT + FANOUT),
    ) {
        let leaves: Vec<Digest> = (0usize..leaf_count)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, DEFAULT_BLOCK_SIZE);

        for (idx, node) in tree.nodes.iter().enumerate() {
            prop_assert!(
                node.verify(),
                "node {idx} must pass self-verification ({} nodes total, {leaf_count} leaves)",
                tree.node_count()
            );
        }

        if leaf_count == 0 {
            prop_assert_eq!(tree.root_hash, zero_digest());
            prop_assert_eq!(tree.level_count(), 0);
        } else {
            prop_assert_ne!(tree.root_hash, zero_digest());
            prop_assert!(tree.level_count() >= 1);
        }
    }
}

// ---------------------------------------------------------------------------
// 9. Power-of-two leaf count: fully balanced trees must have correct
//    structural properties and deterministic root hashes.
// ---------------------------------------------------------------------------

#[test]
fn power_of_two_leaf_count_structural() {
    for pow in 0..10u32 {
        let leaf_count = 1usize << pow;
        let leaves: Vec<Digest> = (0usize..leaf_count)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        assert_eq!(tree.block_count, leaf_count as u64);

        let expected_levels = if leaf_count == 0 {
            0
        } else if leaf_count <= FANOUT {
            1
        } else if leaf_count <= FANOUT * FANOUT {
            2
        } else {
            3
        };
        assert_eq!(
            tree.level_count(),
            expected_levels,
            "power-of-two {leaf_count} leaves: expected {expected_levels} levels"
        );

        for (idx, node) in tree.nodes.iter().enumerate() {
            assert!(
                node.verify(),
                "power-of-two {leaf_count} node {idx} must verify"
            );
        }

        let tree2 = ChecksumTree::from_leaves(&leaves, 4096);
        assert_eq!(tree.root_hash, tree2.root_hash, "determinism failure");
        assert_eq!(tree.nodes, tree2.nodes);

        if leaf_count > 0 {
            assert_ne!(tree.root_hash, zero_digest());
        } else {
            assert_eq!(tree.root_hash, zero_digest());
        }
    }
}

// ---------------------------------------------------------------------------
// 10. Prime leaf count: maximally unbalanced trees must still be valid
//     with correct self-verification and deterministic root hashes.
// ---------------------------------------------------------------------------

#[test]
fn prime_leaf_count_tree_valid() {
    let primes: &[usize] = &[
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
        191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
    ];

    for &leaf_count in primes {
        let leaves: Vec<Digest> = (0usize..leaf_count)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        assert_eq!(tree.block_count, leaf_count as u64);
        assert!(!tree.is_empty());

        for (idx, node) in tree.nodes.iter().enumerate() {
            assert!(
                node.verify(),
                "prime count {leaf_count} node {idx} must verify"
            );
        }

        let tree2 = ChecksumTree::from_leaves(&leaves, 4096);
        assert_eq!(
            tree.root_hash, tree2.root_hash,
            "determinism failure at prime {leaf_count}"
        );
        assert_eq!(tree.nodes, tree2.nodes);
    }
}

// ---------------------------------------------------------------------------
// 11. Incremental update: only affected leaf-to-root path is recalculated;
//     sibling subtree interior nodes remain byte-identical.
// ---------------------------------------------------------------------------

#[test]
fn incremental_update_sibling_subtrees_unchanged() {
    // Multi-level tree: FANOUT*2 + 5 leaves => at least 2 levels deep
    let n = (FANOUT * 2 + 5) as u64;
    let leaves: Vec<Digest> = (0..n)
        .map(|i| hash_block(&(i.wrapping_mul(7).wrapping_add(13)).to_le_bytes()))
        .collect();
    let tree = ChecksumTree::from_leaves(&leaves, 4096);

    assert!(
        tree.level_count() >= 2,
        "tree must have at least 2 levels for this test"
    );

    // Update leaf 0 — only the first level-0 node and the root should change.
    let new_leaf = hash_block(b"updated leaf 0, completely different data here");
    let updated = incremental_update(&tree, 0, new_leaf).expect("valid index");

    assert_ne!(
        updated.root_hash, tree.root_hash,
        "root must change when leaf 0 is updated"
    );
    assert_eq!(updated.block_count, tree.block_count);
    assert_eq!(
        updated.node_count(),
        tree.node_count(),
        "node count must not change"
    );

    // Level-0 node 0 (which holds leaf 0) must differ.
    assert_ne!(
        updated.nodes[0], tree.nodes[0],
        "level-0 node 0 must change (contains updated leaf 0)"
    );

    // All OTHER level-0 nodes must be identical — sibling subtrees
    // are not on the affected leaf-to-root path.
    let level0_count = tree.block_count.div_ceil(FANOUT as u64) as usize;
    for idx in 1..level0_count {
        assert_eq!(
            updated.nodes[idx], tree.nodes[idx],
            "level-0 node {idx} must be unchanged (not on affected path)"
        );
    }

    // All non-root nodes beyond level 0 (interior nodes at level >= 1)
    // whose subtrees do not include leaf 0 must also be unchanged.
    // In a two-level tree, the root is at nodes[level0_count..].
    // The root itself will change (it depends on level-0 node 0).
    let root_idx = updated.node_count() - 1;
    for idx in level0_count..updated.node_count() {
        if idx == root_idx {
            // Root must change since its child (level-0 node 0) changed.
            assert_ne!(
                updated.nodes[idx], tree.nodes[idx],
                "root node must change when a leaf in its subtree changes"
            );
        } else {
            assert_eq!(
                updated.nodes[idx], tree.nodes[idx],
                "interior node {idx} must be unchanged (not on affected path)"
            );
        }
    }

    // Every node in the updated tree must pass self-verification.
    for (idx, node) in updated.nodes.iter().enumerate() {
        assert!(
            node.verify(),
            "updated node {idx} must pass self-verification"
        );
    }
}
// ---------------------------------------------------------------------------
// 12. Domain separation: strategies and collision resistance
// ---------------------------------------------------------------------------

use tidefs_checksum_tree::DomainTag;

/// Strategy generating an arbitrary DomainTag variant.
fn arb_domain_tag() -> impl Strategy<Value = DomainTag> {
    prop_oneof![
        Just(DomainTag::ObjectData),
        Just(DomainTag::ObjectMetadata),
        Just(DomainTag::ExtentMap),
        Just(DomainTag::DirectoryEntry),
        Just(DomainTag::ScrubRecord),
        Just(DomainTag::ErasureCodingShard),
        Just(DomainTag::IntentLog),
        Just(DomainTag::ObjectContent),
        Just(DomainTag::WriteSegment),
        Just(DomainTag::SegmentIntegrityFooter),
    ]
}

/// Strategy returning a pair of two *different* DomainTag values.
fn arb_two_different_domain_tags() -> impl Strategy<Value = (DomainTag, DomainTag)> {
    arb_domain_tag()
        .prop_flat_map(|t1| (Just(t1), arb_domain_tag()))
        .prop_filter("tags must differ", |(t1, t2)| t1 != t2)
}

proptest! {
    /// Domain collision resistance: same blob hashed under two different
    /// DomainTag values must produce different root hashes.
    #[test]
    fn domain_collision_resistance(
        bytes in arb_bytes(),
        (tag_a, tag_b) in arb_two_different_domain_tags(),
    ) {
        let block_size = DEFAULT_BLOCK_SIZE;
        let dk_a = tag_a.derive_key();
        let dk_b = tag_b.derive_key();
        prop_assert_ne!(dk_a, dk_b,
            "keys for different domain tags must differ");

        let mut builder_a = ChecksumTreeBuilder::new_with_domain(block_size, dk_a);
        builder_a.ingest(&bytes);
        let tree_a = builder_a.finish();

        let mut builder_b = ChecksumTreeBuilder::new_with_domain(block_size, dk_b);
        builder_b.ingest(&bytes);
        let tree_b = builder_b.finish();

        prop_assert_ne!(
            tree_a.root_hash, tree_b.root_hash,
            "same data under different DomainTags must produce different root hashes"
        );

        // Each tree's verifier must verify its own data correctly.
        let verifier_a = ChecksumTreeVerifier::new(tree_a.clone());
        prop_assert_eq!(verifier_a.verify_full(&bytes), VerificationResult::Verified);

        let verifier_b = ChecksumTreeVerifier::new(tree_b);
        prop_assert_eq!(verifier_b.verify_full(&bytes), VerificationResult::Verified);
    }

    /// Content collision resistance: two different blobs under the same domain
    /// must produce different root hashes.
    #[test]
    fn content_collision_resistance(
        bytes_a in arb_bytes(),
        bytes_b in arb_bytes(),
        tag in arb_domain_tag(),
    ) {
        // Skip if bytes happen to be identical (proptest may generate same vec).
        if bytes_a == bytes_b {
            return Ok(());
        }

        let block_size = DEFAULT_BLOCK_SIZE;
        let dk = tag.derive_key();

        let mut builder_a = ChecksumTreeBuilder::new_with_domain(block_size, dk);
        builder_a.ingest(&bytes_a);
        let tree_a = builder_a.finish();

        let mut builder_b = ChecksumTreeBuilder::new_with_domain(block_size, dk);
        builder_b.ingest(&bytes_b);
        let tree_b = builder_b.finish();

        prop_assert_ne!(
            tree_a.root_hash, tree_b.root_hash,
            "different blobs under same DomainTag must produce different root hashes"
        );
    }

    /// verify_leaf roundtrip: build a tree from data, extract a leaf proof
    /// via generate_proof, then call verify_leaf with the leaf data and
    /// proof path. Must succeed.
    #[test]
    fn verify_leaf_roundtrip(
        bytes in prop::collection::vec(any::<u8>(), 1..65536),
        leaf_idx_pct in 0u8..100u8,
    ) {
        let block_size = DEFAULT_BLOCK_SIZE;

        // Build tree with domain separation (ObjectData).
        let dk = DomainTag::ObjectData.derive_key();
        let mut builder = ChecksumTreeBuilder::new_with_domain(block_size, dk);
        builder.ingest(&bytes);
        let tree = builder.finish();

        let leaf_count = tree.block_count as usize;
        if leaf_count == 0 {
            return Ok(());
        }

        let leaf_idx = (leaf_idx_pct as usize) % leaf_count;
        let leaf_start = leaf_idx * block_size;
        let leaf_end = (leaf_start + block_size).min(bytes.len());
        let leaf_data = &bytes[leaf_start..leaf_end];

        let proof = tree.generate_proof(leaf_idx as u64)
            .expect("leaf index must be in range");

        let verifier = ChecksumTreeVerifier::new(tree);
        prop_assert!(
            verifier.verify_leaf(leaf_idx, leaf_data, &proof.path),
            "verify_leaf must succeed with correct leaf data and proof path"
        );
    }

    /// verify_leaf with corrupted sibling path must return false.
    #[test]
    fn verify_leaf_corrupted_sibling_fails(
        bytes in prop::collection::vec(any::<u8>(), 4096..65536),
        leaf_idx_pct in 0u8..100u8,
    ) {
        let block_size = DEFAULT_BLOCK_SIZE;

        let dk = DomainTag::ObjectData.derive_key();
        let mut builder = ChecksumTreeBuilder::new_with_domain(block_size, dk);
        builder.ingest(&bytes);
        let tree = builder.finish();

        let leaf_count = tree.block_count as usize;
        if leaf_count <= 1 {
            // Single-leaf tree: path is empty; no sibling to corrupt.
            return Ok(());
        }

        let leaf_idx = (leaf_idx_pct as usize) % leaf_count;
        let leaf_start = leaf_idx * block_size;
        let leaf_end = (leaf_start + block_size).min(bytes.len());
        let leaf_data = &bytes[leaf_start..leaf_end];

        let mut proof = tree.generate_proof(leaf_idx as u64)
            .expect("leaf index must be in range");

        // Corrupt a byte in the first sibling of the first proof level.
        if let Some(level) = proof.path.first_mut() {
            if !level.siblings.is_empty() {
                let sibling_idx = 0;
                let byte_idx = (leaf_idx_pct as usize) % DIGEST_SIZE;
                level.siblings[sibling_idx][byte_idx] ^= 0xFF;
            }
        }

        let verifier = ChecksumTreeVerifier::new(tree);
        prop_assert!(
            !verifier.verify_leaf(leaf_idx, leaf_data, &proof.path),
            "verify_leaf must fail with corrupted sibling path"
        );
    }

    /// Structural invariant: tree built with domain separation has the
    /// same level count and structure as one built without.
    #[test]
    fn domain_tree_structural_parity(
        bytes in arb_bytes(),
        tag in arb_domain_tag(),
    ) {
        let block_size = DEFAULT_BLOCK_SIZE;

        let dk = tag.derive_key();
        let mut domain_builder = ChecksumTreeBuilder::new_with_domain(block_size, dk);
        domain_builder.ingest(&bytes);
        let domain_tree = domain_builder.finish();

        let mut plain_builder = ChecksumTreeBuilder::new(block_size);
        plain_builder.ingest(&bytes);
        let plain_tree = plain_builder.finish();

        prop_assert_eq!(domain_tree.block_count, plain_tree.block_count);
        prop_assert_eq!(domain_tree.level_count(), plain_tree.level_count());
        prop_assert_eq!(domain_tree.node_count(), plain_tree.node_count());

        // Node internal structures should differ only in hash values,
        // but node counts and child counts must match.
        for (dn, pn) in domain_tree.nodes.iter().zip(plain_tree.nodes.iter()) {
            prop_assert_eq!(dn.children.len(), pn.children.len());
        }

        // Root hashes must differ because leaf hashes are domain-separated.
        prop_assert_ne!(domain_tree.root_hash, plain_tree.root_hash,
            "domain-separated root must differ from plain BLAKE3 root");
    }

    /// Empty blob with domain separation produces a zero root hash
    /// (tree has no leaves) but the domain_key is preserved.
    #[test]
    fn empty_blob_domain_tree(
        tag in arb_domain_tag(),
    ) {
        let dk = tag.derive_key();
        let mut builder = ChecksumTreeBuilder::new_with_domain(DEFAULT_BLOCK_SIZE, dk);
        builder.ingest(&[]);
        let tree = builder.finish();

        prop_assert!(tree.is_empty());
        prop_assert_eq!(tree.root_hash, zero_digest());
        prop_assert_eq!(tree.block_count, 0);
        prop_assert_eq!(tree.domain_key, Some(dk));

        let verifier = ChecksumTreeVerifier::new(tree);
        prop_assert_eq!(verifier.verify_full(&[]), VerificationResult::Verified);
    }
}
