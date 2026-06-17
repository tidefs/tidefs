//! Merkle tree exchange protocol for efficient anti-entropy comparison.
//!
//! Instead of shipping full datasets or all digests between nodes,
//! the Merkle exchange compares tree hashes level-by-level:
//!
//! 1. Exchange root hashes — if they match, data is consistent (O(1) data transfer).
//! 2. If roots differ, exchange child hashes to identify divergent subtrees.
//! 3. Recurse down to leaf level to pinpoint specific divergent blocks.
//!
//! This reduces transfer cost from O(N) digests to O(k * log N) where
//! k is the number of divergent blocks — typically k << N.
//!
//! # Protocol phases
//!
//! - **Root compare**: send root hash; match → done
//! - **Level walk**: for each divergent interior node, request child hashes
//! - **Leaf diverge**: at leaf level, record the specific divergent blocks
//! - **Proof request**: optionally request Merkle proofs for divergent leaves

use tidefs_checksum_tree::{ChecksumTree, Digest, SubtreeProof};

/// High-level outcome of a Merkle exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleExchangeStatus {
    /// Local and remote roots match.
    EqualRoots,
    /// Roots differ, but no complete remote leaf proof was provided.
    ProofNeededRootMismatch,
    /// A complete remote leaf proof identified divergent leaves.
    CompleteDivergentLeafProof,
    /// Remote proof data failed validation.
    CorruptProof,
    /// Witness digest disagreed with both primary and replica digests.
    WitnessTieBreakDisagreement,
}

/// Why remote Merkle proof data failed closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MerkleProofFailure {
    /// The requested range was not fully covered by remote proofs.
    MissingProof {
        leaf_index: u64,
        expected_count: u64,
        received_count: u64,
    },
    /// The remote sent more than one proof for the same leaf.
    DuplicateProof { leaf_index: u64 },
    /// A proof leaf did not belong to the requested/local range.
    OutOfRange { leaf_index: u64, leaf_count: u64 },
    /// The proof was anchored to a root other than the exchanged remote root.
    RootMismatch { leaf_index: u64 },
    /// The proof path did not recompute to the exchanged remote root.
    ChecksumMismatch { leaf_index: u64 },
}

/// Subject and leaf range covered by a remote Merkle proof response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleLeafRange {
    /// First subject reference covered by `leaf_start`.
    pub subject_start: u64,
    /// First Merkle leaf index covered by the proof response.
    pub leaf_start: u64,
    /// Number of contiguous leaves that must be proven.
    pub leaf_count: u64,
}

impl MerkleLeafRange {
    #[must_use]
    pub fn new(subject_start: u64, leaf_start: u64, leaf_count: u64) -> Self {
        Self {
            subject_start,
            leaf_start,
            leaf_count,
        }
    }

    #[must_use]
    pub fn end_leaf(self) -> Option<u64> {
        self.leaf_start.checked_add(self.leaf_count)
    }

    #[must_use]
    pub fn contains(self, leaf_index: u64) -> bool {
        self.end_leaf()
            .map(|end| leaf_index >= self.leaf_start && leaf_index < end)
            .unwrap_or(false)
    }

    #[must_use]
    pub fn subject_for_leaf(self, leaf_index: u64) -> Option<u64> {
        if !self.contains(leaf_index) {
            return None;
        }

        self.subject_start
            .checked_add(leaf_index.saturating_sub(self.leaf_start))
    }
}

/// A validated leaf-level divergence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleLeafDivergence {
    /// Subject that maps to the divergent leaf.
    pub subject_ref: u64,
    /// Divergent Merkle leaf index.
    pub leaf_index: u64,
    /// Local digest expected for this subject range.
    pub expected_digest: Digest,
    /// Remote digest proven against the remote root.
    pub actual_digest: Digest,
}

/// Witness disagreement evidence carried as a first-class exchange outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleWitnessDisagreement {
    pub primary_digest: Digest,
    pub replica_digest: Digest,
    pub witness_digest: Digest,
}

/// Result of a Merkle tree exchange comparison between two nodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleExchangeResult {
    /// Classified exchange outcome.
    pub status: MerkleExchangeStatus,
    /// Whether the two trees are fully consistent.
    pub consistent: bool,
    /// Number of leaf blocks compared (may be fewer than total if roots matched).
    pub blocks_compared: u64,
    /// Number of divergent leaf blocks found.
    pub divergent_blocks: u64,
    /// Indices of divergent leaf blocks (0-based).
    pub divergent_indices: Vec<u64>,
    /// Number of hash-exchange messages sent (proxy for bandwidth used).
    pub exchange_messages: u64,
    /// Total bytes of hash data exchanged.
    pub bytes_exchanged: u64,
    /// Validated leaf divergences, populated only for complete leaf proofs.
    pub leaf_divergences: Vec<MerkleLeafDivergence>,
    /// Proof failure evidence when `status` is [`MerkleExchangeStatus::CorruptProof`].
    pub proof_failure: Option<MerkleProofFailure>,
    /// Witness tie-break evidence when the witness disagrees with both sides.
    pub witness_disagreement: Option<MerkleWitnessDisagreement>,
}

impl MerkleExchangeResult {
    #[must_use]
    pub fn is_repair_evidence(&self) -> bool {
        self.status == MerkleExchangeStatus::CompleteDivergentLeafProof
            && !self.leaf_divergences.is_empty()
    }

    #[must_use]
    pub fn witness_tie_break_disagreement(
        primary_digest: Digest,
        replica_digest: Digest,
        witness_digest: Digest,
    ) -> Self {
        Self {
            status: MerkleExchangeStatus::WitnessTieBreakDisagreement,
            consistent: false,
            blocks_compared: 0,
            divergent_blocks: 0,
            divergent_indices: Vec::new(),
            exchange_messages: 0,
            bytes_exchanged: 0,
            leaf_divergences: Vec::new(),
            proof_failure: None,
            witness_disagreement: Some(MerkleWitnessDisagreement {
                primary_digest,
                replica_digest,
                witness_digest,
            }),
        }
    }
}

/// A Merkle exchange engine that compares two Merkle trees efficiently.
///
/// `local_tree` is the tree computed from local data; `remote_root` is
/// the root hash received from the remote node. Subsequent exchanges
/// refine the comparison.
#[derive(Clone, Debug)]
pub struct MerkleExchange {
    /// The local Merkle tree computed from local data.
    pub local_tree: ChecksumTree,
    /// Remote root hash (received from the peer).
    pub remote_root: Digest,
    /// Whether root comparison has been performed.
    pub root_compared: bool,
    /// Accumulated exchange statistics.
    pub bytes_exchanged: u64,
    pub messages_sent: u64,
}

impl MerkleExchange {
    /// Create a new Merkle exchange session.
    ///
    /// `local_tree` is the Merkle tree computed over local data blocks.
    /// `remote_root` is the root hash received from the remote node.
    #[must_use]
    pub fn new(local_tree: ChecksumTree, remote_root: Digest) -> Self {
        Self {
            local_tree,
            remote_root,
            root_compared: false,
            bytes_exchanged: 0,
            messages_sent: 0,
        }
    }

    /// Perform the full Merkle exchange: compare roots, walk divergent
    /// subtrees, and return a detailed result.
    ///
    /// This is the main entry point for anti-entropy comparison.
    #[must_use]
    pub fn compare(&mut self) -> MerkleExchangeResult {
        self.record_root_exchange();

        let local_root = self.local_tree.root_hash;

        if local_root == self.remote_root {
            return self.equal_roots_result();
        }

        self.proof_needed_result()
    }

    /// Compare against a remote tree directly (both trees available locally,
    /// for testing or when remote tree data has been transferred).
    ///
    /// Simulates the exchange protocol but with both trees present.
    #[must_use]
    pub fn compare_with_remote_tree(&mut self, remote_tree: &ChecksumTree) -> MerkleExchangeResult {
        self.remote_root = remote_tree.root_hash;
        let proofs: Vec<SubtreeProof> = (0..remote_tree.block_count)
            .filter_map(|leaf_index| remote_tree.generate_proof(leaf_index))
            .collect();
        let range = MerkleLeafRange::new(0, 0, self.local_tree.block_count);

        self.compare_with_remote_leaf_proofs(range, &proofs)
    }

    /// Validate a remote proof response for an exact subject/leaf range.
    #[must_use]
    pub fn compare_with_remote_leaf_proofs(
        &mut self,
        range: MerkleLeafRange,
        proofs: &[SubtreeProof],
    ) -> MerkleExchangeResult {
        self.record_root_exchange();

        if self.local_tree.root_hash == self.remote_root {
            return self.equal_roots_result();
        }

        if range.leaf_count == 0 {
            return self.proof_needed_result();
        }

        let Some(range_end) = range.end_leaf() else {
            return self.corrupt_proof_result(MerkleProofFailure::OutOfRange {
                leaf_index: range.leaf_start,
                leaf_count: self.local_tree.block_count,
            });
        };

        if range.leaf_start >= self.local_tree.block_count
            || range_end > self.local_tree.block_count
        {
            return self.corrupt_proof_result(MerkleProofFailure::OutOfRange {
                leaf_index: range.leaf_start,
                leaf_count: self.local_tree.block_count,
            });
        }

        self.messages_sent += proofs.len() as u64;
        self.bytes_exchanged += proofs.iter().map(Self::proof_wire_bytes).sum::<u64>();

        let expected_count = match usize::try_from(range.leaf_count) {
            Ok(count) => count,
            Err(_) => {
                return self.corrupt_proof_result(MerkleProofFailure::OutOfRange {
                    leaf_index: range.leaf_start,
                    leaf_count: self.local_tree.block_count,
                });
            }
        };

        let mut seen = vec![false; expected_count];
        let mut leaf_divergences = Vec::new();

        for proof in proofs {
            if !range.contains(proof.leaf_index) || proof.leaf_index >= self.local_tree.block_count
            {
                return self.corrupt_proof_result(MerkleProofFailure::OutOfRange {
                    leaf_index: proof.leaf_index,
                    leaf_count: self.local_tree.block_count,
                });
            }

            if proof.root_hash != self.remote_root {
                return self.corrupt_proof_result(MerkleProofFailure::RootMismatch {
                    leaf_index: proof.leaf_index,
                });
            }

            if !Self::verify_proof(proof) {
                return self.corrupt_proof_result(MerkleProofFailure::ChecksumMismatch {
                    leaf_index: proof.leaf_index,
                });
            }

            let seen_index = (proof.leaf_index - range.leaf_start) as usize;
            if seen[seen_index] {
                return self.corrupt_proof_result(MerkleProofFailure::DuplicateProof {
                    leaf_index: proof.leaf_index,
                });
            }
            seen[seen_index] = true;

            let Some(expected_digest) = self.local_tree.leaf_digest(proof.leaf_index) else {
                return self.corrupt_proof_result(MerkleProofFailure::OutOfRange {
                    leaf_index: proof.leaf_index,
                    leaf_count: self.local_tree.block_count,
                });
            };

            if expected_digest != proof.leaf_digest {
                let Some(subject_ref) = range.subject_for_leaf(proof.leaf_index) else {
                    return self.corrupt_proof_result(MerkleProofFailure::OutOfRange {
                        leaf_index: proof.leaf_index,
                        leaf_count: self.local_tree.block_count,
                    });
                };

                leaf_divergences.push(MerkleLeafDivergence {
                    subject_ref,
                    leaf_index: proof.leaf_index,
                    expected_digest,
                    actual_digest: proof.leaf_digest,
                });
            }
        }

        if let Some(missing_index) = seen.iter().position(|was_seen| !*was_seen) {
            return self.corrupt_proof_result(MerkleProofFailure::MissingProof {
                leaf_index: range.leaf_start + missing_index as u64,
                expected_count: range.leaf_count,
                received_count: proofs.len() as u64,
            });
        }

        if leaf_divergences.is_empty() {
            return self.proof_needed_result();
        }

        self.divergent_leaf_proof_result(range.leaf_count, leaf_divergences)
    }

    fn record_root_exchange(&mut self) {
        self.root_compared = true;
        self.messages_sent += 1;
        self.bytes_exchanged += 32;
    }

    fn proof_wire_bytes(proof: &SubtreeProof) -> u64 {
        let sibling_count: u64 = proof
            .path
            .iter()
            .map(|level| level.siblings.len() as u64)
            .sum();
        32 * (2 + sibling_count)
    }

    fn equal_roots_result(&self) -> MerkleExchangeResult {
        MerkleExchangeResult {
            status: MerkleExchangeStatus::EqualRoots,
            consistent: true,
            blocks_compared: 0,
            divergent_blocks: 0,
            divergent_indices: Vec::new(),
            exchange_messages: self.messages_sent,
            bytes_exchanged: self.bytes_exchanged,
            leaf_divergences: Vec::new(),
            proof_failure: None,
            witness_disagreement: None,
        }
    }

    fn proof_needed_result(&self) -> MerkleExchangeResult {
        MerkleExchangeResult {
            status: MerkleExchangeStatus::ProofNeededRootMismatch,
            consistent: false,
            blocks_compared: 0,
            divergent_blocks: 0,
            divergent_indices: Vec::new(),
            exchange_messages: self.messages_sent,
            bytes_exchanged: self.bytes_exchanged,
            leaf_divergences: Vec::new(),
            proof_failure: None,
            witness_disagreement: None,
        }
    }

    fn corrupt_proof_result(&self, failure: MerkleProofFailure) -> MerkleExchangeResult {
        MerkleExchangeResult {
            status: MerkleExchangeStatus::CorruptProof,
            consistent: false,
            blocks_compared: 0,
            divergent_blocks: 0,
            divergent_indices: Vec::new(),
            exchange_messages: self.messages_sent,
            bytes_exchanged: self.bytes_exchanged,
            leaf_divergences: Vec::new(),
            proof_failure: Some(failure),
            witness_disagreement: None,
        }
    }

    fn divergent_leaf_proof_result(
        &self,
        blocks_compared: u64,
        leaf_divergences: Vec<MerkleLeafDivergence>,
    ) -> MerkleExchangeResult {
        let divergent_indices = leaf_divergences
            .iter()
            .map(|divergence| divergence.leaf_index)
            .collect::<Vec<_>>();

        MerkleExchangeResult {
            status: MerkleExchangeStatus::CompleteDivergentLeafProof,
            consistent: false,
            blocks_compared,
            divergent_blocks: divergent_indices.len() as u64,
            divergent_indices,
            exchange_messages: self.messages_sent,
            bytes_exchanged: self.bytes_exchanged,
            leaf_divergences,
            proof_failure: None,
            witness_disagreement: None,
        }
    }

    /// Generate a Merkle proof for a specific leaf index.
    ///
    /// After identifying a divergent leaf, the proof can be sent to the
    /// remote node so it can verify which specific block is corrupt.
    #[must_use]
    pub fn generate_proof(&self, leaf_index: u64) -> Option<SubtreeProof> {
        self.local_tree.generate_proof(leaf_index)
    }

    /// Verify a Merkle proof against a known root hash.
    ///
    /// Returns true if the proof is valid for the given root.
    #[must_use]
    pub fn verify_proof(proof: &SubtreeProof) -> bool {
        tidefs_checksum_tree::verify_proof(proof)
    }

    /// Compute the number of leaf digests in the local tree.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.local_tree.leaf_digests().len()
    }

    /// Get the local tree's root hash.
    #[must_use]
    pub fn local_root(&self) -> Digest {
        self.local_tree.root_hash
    }
}

/// A single-level Merkle exchange snapshot used during incremental comparison.
///
/// When roots differ, the level walk produces a sequence of these snapshots
/// showing which subtrees diverged at each level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LevelExchangeSnapshot {
    /// Tree level being compared (0 = root).
    pub level: usize,
    /// Number of nodes at this level that were compared.
    pub nodes_compared: u64,
    /// Number of nodes at this level that diverged.
    pub nodes_diverged: u64,
    /// Bytes exchanged at this level.
    pub bytes_exchanged: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_checksum_tree::ChecksumTreeBuilder;

    fn build_tree(data_blocks: &[&[u8]]) -> ChecksumTree {
        let mut builder = ChecksumTreeBuilder::new(256);
        for block in data_blocks {
            builder.ingest(block);
        }
        builder.finish()
    }

    fn make_test_data(count: usize, base: u8) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                let mut block = vec![base; 64];
                block[0] = (i % 256) as u8;
                block[1] = ((i / 256) % 256) as u8;
                block
            })
            .collect()
    }

    fn proof_range(tree: &ChecksumTree, start: u64, count: u64) -> Vec<SubtreeProof> {
        (start..start + count)
            .map(|leaf_index| tree.generate_proof(leaf_index).expect("valid proof"))
            .collect()
    }

    #[test]
    fn identical_trees_root_match() {
        let data = make_test_data(100, b'A');
        let tree1 = build_tree(&data.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let tree2 = build_tree(&data.iter().map(|d| d.as_slice()).collect::<Vec<_>>());

        assert_eq!(tree1.root_hash, tree2.root_hash);

        let mut exchange = MerkleExchange::new(tree1.clone(), tree2.root_hash);
        let result = exchange.compare();

        assert_eq!(result.status, MerkleExchangeStatus::EqualRoots);
        assert!(result.consistent);
        assert_eq!(result.divergent_blocks, 0);
        assert_eq!(result.exchange_messages, 1); // Only root exchange
        assert_eq!(result.bytes_exchanged, 32); // Only root exchange
    }

    #[test]
    fn divergent_trees_found_with_full_comparison() {
        let data1 = make_test_data(10, b'A');
        let mut data2 = make_test_data(10, b'A');
        // Corrupt block 3
        data2[3][0] = 0xFF;

        let tree1 = build_tree(&data1.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let tree2 = build_tree(&data2.iter().map(|d| d.as_slice()).collect::<Vec<_>>());

        assert_ne!(tree1.root_hash, tree2.root_hash);

        let mut exchange = MerkleExchange::new(tree1.clone(), tree2.root_hash);
        let result = exchange.compare_with_remote_tree(&tree2);

        assert_eq!(
            result.status,
            MerkleExchangeStatus::CompleteDivergentLeafProof
        );
        assert!(!result.consistent);
        assert!(result.is_repair_evidence());
        assert_eq!(result.divergent_blocks, 1);
        assert_eq!(result.divergent_indices, vec![3]);
        assert_eq!(result.leaf_divergences.len(), 1);
        assert_eq!(result.leaf_divergences[0].subject_ref, 3);
        assert_eq!(
            result.leaf_divergences[0].expected_digest,
            tree1.leaf_digest(3).unwrap()
        );
        assert_eq!(
            result.leaf_divergences[0].actual_digest,
            tree2.leaf_digest(3).unwrap()
        );
    }

    #[test]
    fn multiple_divergent_blocks() {
        let data1 = make_test_data(500, b'X');
        let mut data2 = make_test_data(500, b'X');
        // Corrupt blocks 0, 127, 255, 499
        data2[0][0] = 0xAA;
        data2[127][0] = 0xBB;
        data2[255][0] = 0xCC;
        data2[499][0] = 0xDD;

        let tree1 = build_tree(&data1.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let tree2 = build_tree(&data2.iter().map(|d| d.as_slice()).collect::<Vec<_>>());

        let mut exchange = MerkleExchange::new(tree1.clone(), tree2.root_hash);
        let result = exchange.compare_with_remote_tree(&tree2);

        assert_eq!(
            result.status,
            MerkleExchangeStatus::CompleteDivergentLeafProof
        );
        assert!(!result.consistent);
        assert_eq!(result.divergent_blocks, 4);
        assert!(result.divergent_indices.contains(&0));
        assert!(result.divergent_indices.contains(&127));
        assert!(result.divergent_indices.contains(&255));
        assert!(result.divergent_indices.contains(&499));
    }

    #[test]
    fn empty_tree_comparison() {
        let tree1 = ChecksumTreeBuilder::new(256).finish();
        let tree2 = ChecksumTreeBuilder::new(256).finish();

        let mut exchange = MerkleExchange::new(tree1.clone(), tree2.root_hash);
        let result = exchange.compare();

        assert_eq!(result.status, MerkleExchangeStatus::EqualRoots);
        assert!(result.consistent);
        assert_eq!(result.divergent_blocks, 0);
    }

    #[test]
    fn size_mismatch_without_complete_remote_proof_fails_closed() {
        let data1 = make_test_data(100, b'A');
        let data2 = make_test_data(50, b'A'); // Smaller

        let tree1 = build_tree(&data1.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let tree2 = build_tree(&data2.iter().map(|d| d.as_slice()).collect::<Vec<_>>());

        let mut exchange = MerkleExchange::new(tree1.clone(), tree2.root_hash);
        let result = exchange.compare_with_remote_tree(&tree2);

        assert_eq!(result.status, MerkleExchangeStatus::CorruptProof);
        assert!(!result.consistent);
        assert_eq!(result.divergent_blocks, 0);
        assert_eq!(
            result.proof_failure,
            Some(MerkleProofFailure::MissingProof {
                leaf_index: 50,
                expected_count: 100,
                received_count: 50,
            })
        );
        assert!(!result.is_repair_evidence());
    }

    #[test]
    fn merkle_proof_generation() {
        let data = make_test_data(16, b'Z');
        let tree = build_tree(&data.iter().map(|d| d.as_slice()).collect::<Vec<_>>());

        let exchange = MerkleExchange::new(tree.clone(), tree.root_hash);

        let proof = exchange.generate_proof(5);
        assert!(proof.is_some());
        assert!(MerkleExchange::verify_proof(&proof.unwrap()));
    }

    #[test]
    fn exchange_efficiency_grows_logarithmically() {
        let data1 = make_test_data(1000, b'Q');
        let mut data2 = make_test_data(1000, b'Q');
        data2[500][0] = 0xFF; // Single corruption

        let tree1 = build_tree(&data1.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let tree2 = build_tree(&data2.iter().map(|d| d.as_slice()).collect::<Vec<_>>());

        let mut exchange = MerkleExchange::new(tree1.clone(), tree2.root_hash);
        let result = exchange.compare();

        assert_eq!(result.status, MerkleExchangeStatus::ProofNeededRootMismatch);
        assert!(!result.consistent);
        assert_eq!(result.exchange_messages, 1);
        assert_eq!(result.bytes_exchanged, 32);
        assert_eq!(result.divergent_blocks, 0);
        assert!(!result.is_repair_evidence());
    }

    #[test]
    fn valid_leaf_proof_records_exact_subject_range_and_digests() {
        let data1 = make_test_data(10, b'A');
        let mut data2 = make_test_data(10, b'A');
        data2[3][0] = 0xFF;

        let tree1 = build_tree(&data1.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let tree2 = build_tree(&data2.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let proofs = proof_range(&tree2, 3, 1);
        let range = MerkleLeafRange::new(1_000, 3, 1);

        let mut exchange = MerkleExchange::new(tree1.clone(), tree2.root_hash);
        let result = exchange.compare_with_remote_leaf_proofs(range, &proofs);

        assert_eq!(
            result.status,
            MerkleExchangeStatus::CompleteDivergentLeafProof
        );
        assert_eq!(result.blocks_compared, 1);
        assert_eq!(result.divergent_indices, vec![3]);
        assert_eq!(result.leaf_divergences[0].subject_ref, 1_000);
        assert_eq!(
            result.leaf_divergences[0].expected_digest,
            tree1.leaf_digest(3).unwrap()
        );
        assert_eq!(
            result.leaf_divergences[0].actual_digest,
            tree2.leaf_digest(3).unwrap()
        );
    }

    #[test]
    fn truncated_leaf_proof_fails_closed() {
        let data1 = make_test_data(10, b'A');
        let mut data2 = make_test_data(10, b'A');
        data2[1][0] = 0xFF;

        let tree1 = build_tree(&data1.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let tree2 = build_tree(&data2.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let proofs = proof_range(&tree2, 0, 1);
        let range = MerkleLeafRange::new(0, 0, 2);

        let mut exchange = MerkleExchange::new(tree1, tree2.root_hash);
        let result = exchange.compare_with_remote_leaf_proofs(range, &proofs);

        assert_eq!(result.status, MerkleExchangeStatus::CorruptProof);
        assert_eq!(
            result.proof_failure,
            Some(MerkleProofFailure::MissingProof {
                leaf_index: 1,
                expected_count: 2,
                received_count: 1,
            })
        );
        assert_eq!(result.divergent_blocks, 0);
    }

    #[test]
    fn out_of_range_leaf_proof_fails_closed() {
        let data1 = make_test_data(10, b'A');
        let mut data2 = make_test_data(10, b'A');
        data2[3][0] = 0xFF;

        let tree1 = build_tree(&data1.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let tree2 = build_tree(&data2.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let proofs = proof_range(&tree2, 3, 1);
        let range = MerkleLeafRange::new(0, 0, 1);

        let mut exchange = MerkleExchange::new(tree1, tree2.root_hash);
        let result = exchange.compare_with_remote_leaf_proofs(range, &proofs);

        assert_eq!(result.status, MerkleExchangeStatus::CorruptProof);
        assert_eq!(
            result.proof_failure,
            Some(MerkleProofFailure::OutOfRange {
                leaf_index: 3,
                leaf_count: 10,
            })
        );
        assert_eq!(result.divergent_blocks, 0);
    }

    #[test]
    fn oversized_leaf_range_fails_closed_before_tracking_allocation() {
        let data1 = make_test_data(10, b'A');
        let mut data2 = make_test_data(10, b'A');
        data2[3][0] = 0xFF;

        let tree1 = build_tree(&data1.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let tree2 = build_tree(&data2.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let range = MerkleLeafRange::new(0, 0, u64::MAX);

        let mut exchange = MerkleExchange::new(tree1, tree2.root_hash);
        let result = exchange.compare_with_remote_leaf_proofs(range, &[]);

        assert_eq!(result.status, MerkleExchangeStatus::CorruptProof);
        assert_eq!(
            result.proof_failure,
            Some(MerkleProofFailure::OutOfRange {
                leaf_index: 0,
                leaf_count: 10,
            })
        );
        assert_eq!(result.divergent_blocks, 0);
    }

    #[test]
    fn duplicate_leaf_proof_fails_closed() {
        let data1 = make_test_data(10, b'A');
        let mut data2 = make_test_data(10, b'A');
        data2[3][0] = 0xFF;

        let tree1 = build_tree(&data1.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let tree2 = build_tree(&data2.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let proof = tree2.generate_proof(3).unwrap();
        let proofs = vec![proof.clone(), proof];
        let range = MerkleLeafRange::new(0, 3, 1);

        let mut exchange = MerkleExchange::new(tree1, tree2.root_hash);
        let result = exchange.compare_with_remote_leaf_proofs(range, &proofs);

        assert_eq!(result.status, MerkleExchangeStatus::CorruptProof);
        assert_eq!(
            result.proof_failure,
            Some(MerkleProofFailure::DuplicateProof { leaf_index: 3 })
        );
        assert_eq!(result.divergent_blocks, 0);
    }

    #[test]
    fn root_mismatched_leaf_proof_fails_closed() {
        let data1 = make_test_data(10, b'A');
        let mut data2 = make_test_data(10, b'A');
        data2[3][0] = 0xFF;

        let tree1 = build_tree(&data1.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let tree2 = build_tree(&data2.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let mut proof = tree2.generate_proof(3).unwrap();
        proof.root_hash = tree1.root_hash;
        let range = MerkleLeafRange::new(0, 3, 1);

        let mut exchange = MerkleExchange::new(tree1, tree2.root_hash);
        let result = exchange.compare_with_remote_leaf_proofs(range, &[proof]);

        assert_eq!(result.status, MerkleExchangeStatus::CorruptProof);
        assert_eq!(
            result.proof_failure,
            Some(MerkleProofFailure::RootMismatch { leaf_index: 3 })
        );
        assert_eq!(result.divergent_blocks, 0);
    }

    #[test]
    fn checksum_mismatched_leaf_proof_fails_closed() {
        let data1 = make_test_data(10, b'A');
        let mut data2 = make_test_data(10, b'A');
        data2[3][0] = 0xFF;

        let tree1 = build_tree(&data1.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let tree2 = build_tree(&data2.iter().map(|d| d.as_slice()).collect::<Vec<_>>());
        let mut proofs = proof_range(&tree2, 3, 1);
        proofs[0].leaf_digest[0] ^= 0xAA;
        let range = MerkleLeafRange::new(0, 3, 1);

        let mut exchange = MerkleExchange::new(tree1, tree2.root_hash);
        let result = exchange.compare_with_remote_leaf_proofs(range, &proofs);

        assert_eq!(result.status, MerkleExchangeStatus::CorruptProof);
        assert_eq!(
            result.proof_failure,
            Some(MerkleProofFailure::ChecksumMismatch { leaf_index: 3 })
        );
        assert_eq!(result.divergent_blocks, 0);
    }

    #[test]
    fn witness_disagreement_is_distinct_exchange_result() {
        let primary = [1u8; 32];
        let replica = [2u8; 32];
        let witness = [3u8; 32];

        let result =
            MerkleExchangeResult::witness_tie_break_disagreement(primary, replica, witness);

        assert_eq!(
            result.status,
            MerkleExchangeStatus::WitnessTieBreakDisagreement
        );
        assert_eq!(
            result.witness_disagreement,
            Some(MerkleWitnessDisagreement {
                primary_digest: primary,
                replica_digest: replica,
                witness_digest: witness,
            })
        );
        assert!(!result.is_repair_evidence());
    }
}
