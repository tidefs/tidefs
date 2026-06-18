// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Read-path integrity verification against anchored BLAKE3 checksum proofs.
//!
//! Every object read that carries a checksum proof is verified before the
//! caller receives the buffer. Verification failures produce structured,
//! actionable errors rather than silent data corruption.
//!
//! The module delegates batch verification to
//! [`tidefs_checksum_tree::verify_batch`], which groups proofs by root
//! hash with an interior-node cache to avoid re-hashing shared subtrees.

use crate::ObjectKey;
use tidefs_checksum_tree::{
    verify_batch, BatchVerificationReport, ChecksumTree, Hash, MerkleProof,
};

// ---------------------------------------------------------------------------
// ReadIntegrityResult
// ---------------------------------------------------------------------------

/// Outcome of a read-path integrity check.
///
/// Every object read that carries a checksum proof passes through this
/// verification.  Callers higher in the stack (e.g. the FUSE daemon) map
/// these outcomes to errno values and `tracing` events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadIntegrityResult {
    /// All data blocks matched the expected checksums.
    Verified,

    /// One or more data blocks produced a different BLAKE3-256 hash than
    /// the proof expected.  The `expected` / `actual` fields report the
    /// *first* mismatch encountered.
    ChecksumMismatch {
        /// Expected hash from the anchored proof.
        expected: [u8; 32],
        /// Actual hash computed from the data on disk.
        actual: [u8; 32],
        /// The object whose data is corrupted.
        object_id: ObjectKey,
    },

    /// No checksum proof is available for this object (e.g. objects
    /// written before integrity tracking was enabled).  Callers decide
    /// the policy: log a warning and pass through, or fail closed.
    ProofMissing { object_id: ObjectKey },

    /// The proof could not be interpreted (e.g. invalid format, wrong
    /// number of leaves, missing interior nodes).
    ProofMalformed {
        /// Human-readable reason for the malformation.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// ChecksumProof
// ---------------------------------------------------------------------------

/// An anchored BLAKE3 checksum proof for a single object.
///
/// Wraps a [`ChecksumTree`] whose root hash was committed alongside the
/// object data on the write path.  The tree carries the expected leaf
/// digests and the Merkle structure needed to verify any data block.
#[derive(Clone, Debug)]
pub struct ChecksumProof {
    /// The expected Merkle tree over the object's data blocks.
    pub tree: ChecksumTree,
}

impl ChecksumProof {
    /// Create a new proof from a pre-built checksum tree.
    #[must_use]
    pub fn new(tree: ChecksumTree) -> Self {
        Self { tree }
    }

    /// Return the expected root hash.
    #[must_use]
    pub fn root_hash(&self) -> Hash {
        self.tree.root_hash
    }

    /// Number of data blocks the proof covers.
    #[must_use]
    pub fn block_count(&self) -> u64 {
        self.tree.block_count
    }
}
// ---------------------------------------------------------------------------
// verify_object_read
// ---------------------------------------------------------------------------

/// Verify object data against an optional checksum proof using batch
/// Merkle proof verification.
///
/// # Arguments
///
/// * `data` - The raw object payload bytes read from the store.
/// * `proof` - An optional anchored [`ChecksumProof`] for this object.
///   When `None`, the function returns `ProofMissing`.
/// * `object_id` - The [`ObjectKey`] identifying the object (for error
///   attribution).
///
/// # Returns
///
/// * `Verified` when every data block matches the proof.
/// * `ChecksumMismatch` on the first mismatched block.
/// * `ProofMissing` when no proof was supplied.
/// * `ProofMalformed` when the proof structure cannot be used (e.g. the
///   data does not cover the expected number of blocks, or a leaf index
///   is out of range).
pub fn verify_object_read(
    data: &[u8],
    proof: Option<&ChecksumProof>,
    object_id: ObjectKey,
) -> ReadIntegrityResult {
    let proof = match proof {
        Some(p) => p,
        None => return ReadIntegrityResult::ProofMissing { object_id },
    };

    let block_size = proof.tree.block_size;
    if block_size == 0 {
        // Degenerate: zero block size means we cannot split data.
        // An empty tree (0 blocks) is fine as long as data is also empty.
        if proof.tree.block_count == 0 && data.is_empty() {
            return ReadIntegrityResult::Verified;
        }
        return ReadIntegrityResult::ProofMalformed {
            reason: "checksum proof has zero block_size with non-empty tree".into(),
        };
    }

    let expected_block_count = proof.tree.block_count as usize;

    // Split the data into block_size chunks for length validation.
    let num_data_blocks = data.chunks(block_size).len();

    // Quick rejection: if the data supplies fewer blocks than the proof
    // expects, the read is truncated — treat as ProofMalformed.
    if num_data_blocks < expected_block_count {
        return ReadIntegrityResult::ProofMalformed {
            reason: format!("data covers {num_data_blocks} blocks but proof expects {expected_block_count} blocks"),
        };
    }

    // Empty tree + empty data: already handled above, but also handle the
    // case where `block_count == 0` with `block_size > 0`.
    if expected_block_count == 0 {
        return if data.is_empty() {
            ReadIntegrityResult::Verified
        } else {
            ReadIntegrityResult::ProofMalformed {
                reason: "proof is empty but data is non-empty".into(),
            }
        };
    }

    // Generate a MerkleProof for every expected block from the proof tree,
    // substituting the actual data hash for each block's leaf digest so
    // that verify_batch validates the real data against the anchored tree.
    let mut merkle_proofs: Vec<MerkleProof> = Vec::with_capacity(expected_block_count);
    for leaf_idx in 0..(expected_block_count as u64) {
        let block_start = leaf_idx as usize * block_size;
        let block_end = (block_start + block_size).min(data.len());
        let actual_hash: [u8; 32] = *blake3::hash(&data[block_start..block_end]).as_bytes();

        match proof.tree.generate_proof(leaf_idx) {
            Some(mut mp) => {
                mp.leaf_digest = actual_hash;
                merkle_proofs.push(mp);
            }
            None => {
                return ReadIntegrityResult::ProofMalformed {
                    reason: format!(
                "data covers {num_data_blocks} blocks but proof expects {expected_block_count} blocks"
                    ),
                };
            }
        }
    }

    // The expected root for every proof is the tree's root hash.
    let expected_roots: Vec<Hash> = vec![proof.tree.root_hash; expected_block_count];

    let report: BatchVerificationReport = match verify_batch(&merkle_proofs, &expected_roots) {
        Ok(r) => r,
        Err(e) => {
            return ReadIntegrityResult::ProofMalformed {
                reason: format!("batch verification setup failed: {e}"),
            };
        }
    };

    if report.all_passed() {
        ReadIntegrityResult::Verified
    } else if let Some(first_bad) = report.first_failure {
        // The Merkle proof failed, meaning the actual data hash did not
        // match the anchored checksum tree. Report the first mismatch
        // with the expected (tree) vs actual (data) hashes.
        let fi = first_bad as usize;
        let block_start = fi * block_size;
        let block_end = (block_start + block_size).min(data.len());
        let actual_hash: [u8; 32] = *blake3::hash(&data[block_start..block_end]).as_bytes();
        let expected_hash: [u8; 32] = proof
            .tree
            .leaf_digests()
            .get(fi)
            .copied()
            .unwrap_or([0u8; 32]);

        ReadIntegrityResult::ChecksumMismatch {
            expected: expected_hash,
            actual: actual_hash,
            object_id,
        }
    } else {
        // Should not happen: first_failure is None but failed > 0.
        ReadIntegrityResult::ProofMalformed {
            reason: "batch verification reported failures but no first_failure index".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_checksum_tree::{ChecksumTreeBuilder, DEFAULT_BLOCK_SIZE};

    /// Build a checksum proof from raw data bytes.
    fn proof_from_data(data: &[u8]) -> ChecksumProof {
        let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        builder.ingest(data);
        ChecksumProof::new(builder.finish())
    }

    // ── Happy path ───────────────────────────────────────────────────

    #[test]
    fn valid_object_correct_proof_returns_verified() {
        let data = b"Hello, TideFS! This is a test payload for read-path BLAKE3 verification.";
        let proof = proof_from_data(data);
        let object_id = ObjectKey::from_content(data);

        let result = verify_object_read(data, Some(&proof), object_id);
        assert_eq!(result, ReadIntegrityResult::Verified);
    }

    #[test]
    fn empty_data_empty_tree_proof_returns_verified() {
        let data: &[u8] = &[];
        let proof = proof_from_data(data);
        let object_id = ObjectKey::ZERO;

        let result = verify_object_read(data, Some(&proof), object_id);
        assert_eq!(result, ReadIntegrityResult::Verified);
    }

    // ── Error paths ──────────────────────────────────────────────────

    #[test]
    fn single_byte_corruption_returns_checksum_mismatch() {
        let data = b"Hello, TideFS! This is a test payload for read-path verification.";
        let proof = proof_from_data(data);

        let mut corrupted = data.to_vec();
        corrupted[7] ^= 0xFF;
        assert_ne!(&corrupted[..], data);

        let object_id = ObjectKey::from_content(data);
        let result = verify_object_read(&corrupted, Some(&proof), object_id);

        match result {
            ReadIntegrityResult::ChecksumMismatch {
                expected,
                actual,
                object_id: oid,
            } => {
                assert_ne!(expected, [0u8; 32]);
                assert_ne!(actual, [0u8; 32]);
                assert_ne!(expected, actual, "corrupted hash must differ from expected");
                assert_eq!(oid, object_id);
            }
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
    }

    #[test]
    fn truncated_data_with_valid_proof_returns_checksum_mismatch() {
        // Data that fits in a single block: truncation changes the hash
        // but keeps the same block count, so it surfaces as a checksum
        // mismatch rather than a malformed proof.
        let data = b"This payload is long enough to fill multiple 4 KiB blocks...";
        let proof = proof_from_data(data);

        let truncated = &data[..data.len() - 10];
        let object_id = ObjectKey::from_content(data);
        let result = verify_object_read(truncated, Some(&proof), object_id);

        match result {
            ReadIntegrityResult::ChecksumMismatch {
                expected, actual, ..
            } => {
                assert_ne!(expected, actual);
            }
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
    }

    #[test]
    fn proof_from_different_object_returns_checksum_mismatch() {
        let data_a = b"Object A: Hello, TideFS! This is the first test payload for integrity.";
        let data_b = b"Object B: This is a completely different payload for object B tests.";
        let proof = proof_from_data(data_a);
        let object_id = ObjectKey::from_content(data_b);

        let result = verify_object_read(data_b, Some(&proof), object_id);

        match result {
            ReadIntegrityResult::ChecksumMismatch {
                expected, actual, ..
            } => {
                assert_ne!(expected, actual);
            }
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
    }

    #[test]
    fn proof_missing_when_none_supplied() {
        let data = b"some data without a proof";
        let object_id = ObjectKey::from_content(data);

        let result = verify_object_read(data, None, object_id);
        assert_eq!(result, ReadIntegrityResult::ProofMissing { object_id });
    }

    #[test]
    fn proof_malformed_when_fewer_blocks_than_proof() {
        let big_data = vec![0xABu8; 16384]; // 4 blocks at DEFAULT_BLOCK_SIZE (4096)
        let proof = proof_from_data(&big_data);
        let small_data = &big_data[..100]; // fewer than one block

        let object_id = ObjectKey::from_content(&big_data);
        let result = verify_object_read(small_data, Some(&proof), object_id);

        assert!(
            matches!(result, ReadIntegrityResult::ProofMalformed { .. }),
            "expected ProofMalformed, got {result:?}"
        );
    }

    #[test]
    fn multi_block_roundtrip_exact_proof() {
        let size: usize = 4 * tidefs_checksum_tree::DEFAULT_BLOCK_SIZE;
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let proof = proof_from_data(&data);
        let object_id = ObjectKey::from_content(&data);

        let result = verify_object_read(&data, Some(&proof), object_id);
        assert_eq!(result, ReadIntegrityResult::Verified);
    }

    #[test]
    fn proof_is_none_trivially_returns_proof_missing() {
        let object_id = ObjectKey::default();
        let result = verify_object_read(b"hello", None, object_id);
        assert_eq!(result, ReadIntegrityResult::ProofMissing { object_id });
    }

    #[test]
    fn non_empty_data_with_empty_proof_returns_malformed() {
        let tree = tidefs_checksum_tree::ChecksumTree::from_leaves(&[], 4096);
        let proof = ChecksumProof::new(tree);
        let object_id = ObjectKey::default();

        let result = verify_object_read(b"non-empty", Some(&proof), object_id);
        assert!(
            matches!(result, ReadIntegrityResult::ProofMalformed { .. }),
            "expected ProofMalformed, got {result:?}"
        );
    }

    #[test]
    fn large_object_single_block_power_of_two_verified() {
        let data = vec![0xCDu8; tidefs_checksum_tree::DEFAULT_BLOCK_SIZE];
        let proof = proof_from_data(&data);
        let object_id = ObjectKey::from_content(&data);

        let result = verify_object_read(&data, Some(&proof), object_id);
        assert_eq!(result, ReadIntegrityResult::Verified);
    }
}
