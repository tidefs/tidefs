// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Checksum-tree scrub verification for object payloads.
//!
//! This module verifies a stored object's payload against a previously
//! captured checksum tree and returns a structured scrub report. It uses the
//! canonical checksum-tree leaf order instead of introducing a second tree
//! traversal implementation.

use tidefs_checksum_tree::{ChecksumTree, ChecksumTreeVerifier, Digest, VerificationResult};

/// Outcome of verifying a single checksum-tree leaf during scrub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeafScrubResult {
    /// Leaf checksum matches the recomputed payload-block hash.
    Clean { leaf_index: u64 },
    /// Stored tree checksum differs from the recomputed payload-block hash.
    Mismatch {
        leaf_index: u64,
        expected: Digest,
        actual: Digest,
    },
}

/// Aggregated report from checksum-tree scrub verification.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChecksumTreeScrubReport {
    /// Number of checksum-tree leaves examined.
    pub leaves_examined: u64,
    /// Number of leaves whose recomputed payload hash matched the tree.
    pub leaves_clean: u64,
    /// Per-leaf outcomes in canonical checksum-tree leaf order.
    pub leaf_results: Vec<LeafScrubResult>,
    /// Whether every tree node passed its embedded self-check.
    pub structure_valid: bool,
    /// Number of expected tree leaves whose payload block was missing.
    pub missing_data_blocks: u64,
    /// Payload bytes beyond the range covered by the checksum tree.
    pub extra_data_bytes: u64,
    /// Result from the checksum-tree verifier's whole-payload check.
    pub verifier_passed: bool,
}

impl ChecksumTreeScrubReport {
    /// True when structure, leaf checks, and whole-payload verification all pass.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.structure_valid
            && self.verifier_passed
            && self.leaves_examined == self.leaves_clean
            && self.missing_data_blocks == 0
            && self.extra_data_bytes == 0
    }
}

/// Verify `data` against `tree` and return a scrub report.
#[must_use]
pub fn scrub_checksum_tree(tree: &ChecksumTree, data: &[u8]) -> ChecksumTreeScrubReport {
    let mut report = ChecksumTreeScrubReport {
        structure_valid: tree.nodes.iter().all(|node| node.verify()),
        verifier_passed: ChecksumTreeVerifier::new(tree.clone()).verify_full(data)
            == VerificationResult::Verified,
        ..ChecksumTreeScrubReport::default()
    };

    let leaves = tree.leaf_digests();
    if leaves.is_empty() {
        report.extra_data_bytes = data.len() as u64;
        return report;
    }

    let block_size = tree.block_size;
    if block_size == 0 {
        report.leaves_examined = leaves.len() as u64;
        report.missing_data_blocks = leaves.len() as u64;
        for (idx, expected) in leaves.into_iter().enumerate() {
            report.leaf_results.push(LeafScrubResult::Mismatch {
                leaf_index: idx as u64,
                expected,
                actual: [0u8; 32],
            });
        }
        return report;
    }

    for (idx, expected) in leaves.iter().copied().enumerate() {
        report.leaves_examined += 1;
        let start = idx.saturating_mul(block_size);
        if start >= data.len() {
            report.missing_data_blocks += 1;
            report.leaf_results.push(LeafScrubResult::Mismatch {
                leaf_index: idx as u64,
                expected,
                actual: [0u8; 32],
            });
            continue;
        }

        let end = (start + block_size).min(data.len());
        let actual = *blake3::hash(&data[start..end]).as_bytes();
        if actual == expected {
            report.leaves_clean += 1;
            report.leaf_results.push(LeafScrubResult::Clean {
                leaf_index: idx as u64,
            });
        } else {
            report.leaf_results.push(LeafScrubResult::Mismatch {
                leaf_index: idx as u64,
                expected,
                actual,
            });
        }
    }

    let covered = leaves.len().saturating_mul(block_size);
    if data.len() > covered {
        report.extra_data_bytes = (data.len() - covered) as u64;
    }

    report
}
