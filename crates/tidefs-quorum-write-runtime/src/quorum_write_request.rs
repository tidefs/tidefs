// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! QuorumWriteRequest: bundles payload bytes, target replica set, quorum
//! threshold, and a BLAKE3 content hash into a single dispatch unit for
//! the quorum write runtime.

use tidefs_quorum_write::NodeId;

/// A self-contained quorum write dispatch request.
///
/// Created by the caller (e.g., CommitGroupCoordinator) and handed to
/// `QuorumWriteRuntime::submit()`.  The request carries the payload,
/// the target replica set (from placement decisions), the quorum
/// threshold, and a pre-computed BLAKE3 hash of the payload for
/// end-to-end integrity verification at each replica.
#[derive(Clone, Debug)]
pub struct QuorumWriteRequest {
    /// Raw payload bytes to replicate.
    pub payload: Vec<u8>,

    /// Ordered set of replica targets (from PlacementPlanner output).
    pub target_replicas: Vec<NodeId>,

    /// Minimum acknowledgements required for quorum (default: N/2 + 1).
    pub quorum_threshold: usize,

    /// BLAKE3 hash of `payload` (32 bytes).
    pub blake3_hash: [u8; 32],
}

impl QuorumWriteRequest {
    /// Build a request with an explicit quorum threshold and pre-computed
    /// BLAKE3 hash.
    #[must_use]
    pub fn new(
        payload: Vec<u8>,
        target_replicas: Vec<NodeId>,
        quorum_threshold: usize,
        blake3_hash: [u8; 32],
    ) -> Self {
        Self {
            payload,
            target_replicas,
            quorum_threshold,
            blake3_hash,
        }
    }

    /// Build a request, computing the BLAKE3 hash from `payload` and
    /// defaulting the quorum threshold to N/2 + 1 (majority).
    #[must_use]
    pub fn with_majority_quorum(payload: Vec<u8>, target_replicas: Vec<NodeId>) -> Self {
        let n = target_replicas.len();
        let threshold = if n == 0 { 0 } else { n / 2 + 1 };
        let hash = compute_blake3(&payload);
        Self {
            payload,
            target_replicas,
            quorum_threshold: threshold,
            blake3_hash: hash,
        }
    }

    /// Number of replica targets.
    #[must_use]
    pub fn replica_count(&self) -> usize {
        self.target_replicas.len()
    }

    /// Whether the quorum threshold is satisfiable given the target count.
    #[must_use]
    pub fn is_satisfiable(&self) -> bool {
        self.quorum_threshold <= self.target_replicas.len() && self.quorum_threshold > 0
    }
}

/// Compute the BLAKE3 hash of `data` and return the 32-byte output.
#[must_use]
pub fn compute_blake3(data: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(data);
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_with_explicit_threshold() {
        let payload = b"hello quorum".to_vec();
        let hash = compute_blake3(&payload);
        let targets = vec![NodeId::new(1), NodeId::new(2), NodeId::new(3)];
        let req = QuorumWriteRequest::new(payload.clone(), targets.clone(), 2, hash);
        assert_eq!(req.payload, payload);
        assert_eq!(req.target_replicas, targets);
        assert_eq!(req.quorum_threshold, 2);
        assert_eq!(req.blake3_hash, hash);
        assert_eq!(req.replica_count(), 3);
        assert!(req.is_satisfiable());
    }

    #[test]
    fn majority_quorum_defaults_to_n_over_2_plus_1() {
        let payload = b"majority test".to_vec();
        let targets = vec![NodeId::new(1), NodeId::new(2), NodeId::new(3)];
        let req = QuorumWriteRequest::with_majority_quorum(payload.clone(), targets.clone());
        assert_eq!(req.quorum_threshold, 2); // 3/2 + 1
        assert_eq!(req.replica_count(), 3);
        assert!(req.is_satisfiable());
    }

    #[test]
    fn majority_quorum_with_5_targets() {
        let payload = b"five".to_vec();
        let targets: Vec<NodeId> = (1..=5).map(NodeId::new).collect();
        let req = QuorumWriteRequest::with_majority_quorum(payload, targets);
        assert_eq!(req.quorum_threshold, 3); // 5/2 + 1
    }

    #[test]
    fn majority_quorum_single_target() {
        let payload = b"one".to_vec();
        let targets = vec![NodeId::new(1)];
        let req = QuorumWriteRequest::with_majority_quorum(payload, targets);
        assert_eq!(req.quorum_threshold, 1); // 1/2 + 1 = 1
        assert!(req.is_satisfiable());
    }

    #[test]
    fn empty_targets_not_satisfiable() {
        let payload = b"none".to_vec();
        let req = QuorumWriteRequest::with_majority_quorum(payload, vec![]);
        assert_eq!(req.quorum_threshold, 0);
        assert!(!req.is_satisfiable());
    }

    #[test]
    fn threshold_too_high_not_satisfiable() {
        let payload = b"too high".to_vec();
        let hash = compute_blake3(&payload);
        let targets = vec![NodeId::new(1), NodeId::new(2)];
        let req = QuorumWriteRequest::new(payload, targets, 3, hash);
        assert!(!req.is_satisfiable());
    }

    #[test]
    fn blake3_is_deterministic() {
        let data = b"deterministic payload";
        let h1 = compute_blake3(data);
        let h2 = compute_blake3(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake3_different_payloads_differ() {
        let h1 = compute_blake3(b"alpha");
        let h2 = compute_blake3(b"beta");
        assert_ne!(h1, h2);
    }
}
