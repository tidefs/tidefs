// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! BLAKE3-authenticated quorum-write commit path.
//!
//! `QuorumWriteCommit` bundles the object payload with a pre-computed BLAKE3
//! checksum, target replica set, and quorum threshold. `commit_quorum_write()`
//! fans the payload out to transport sessions via the `QuorumWriteTransport`
//! trait, collects per-replica BLAKE3 checksum acknowledgments, verifies
//! quorum has been reached, and returns the canonical checksum on success.

use std::fmt;

use blake3::Hash;
use tidefs_replication::QuorumWriteTransport;

// ═══════════════════════════════════════════════════════════════════════
// QuorumWriteError
// ═══════════════════════════════════════════════════════════════════════

/// Errors produced by `commit_quorum_write()`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuorumWriteError {
    /// No replica targets provided.
    ZeroReplicas,
    /// A replica returned a checksum that did not match the canonical checksum.
    ChecksumMismatch {
        replica_id: u64,
        expected: Hash,
        received: Hash,
    },
    /// Insufficient acknowledgments to meet the quorum threshold.
    InsufficientAcks {
        acks_collected: usize,
        quorum_required: usize,
        total_targets: usize,
        failed_targets: Vec<u64>,
    },
    /// Transport-level write failure to a specific replica.
    ReplicaWriteFailed { replica_id: u64, reason: String },
}

impl fmt::Display for QuorumWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroReplicas => write!(f, "quorum write: zero replica targets"),
            Self::ChecksumMismatch {
                replica_id,
                expected,
                received,
            } => write!(
                f,
                "quorum write: replica {replica_id} checksum mismatch (expected {expected}, received {received})"
            ),
            Self::InsufficientAcks {
                acks_collected,
                quorum_required,
                total_targets,
                failed_targets,
            } => write!(
                f,
                "quorum write: {acks_collected}/{quorum_required} acks collected (out of {total_targets} targets); failed: {failed_targets:?}"
            ),
            Self::ReplicaWriteFailed {
                replica_id,
                reason,
            } => write!(
                f,
                "quorum write: replica {replica_id} write failed: {reason}"
            ),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ReplicaWriteAck
// ═══════════════════════════════════════════════════════════════════════

/// Acknowledgment from a single replica after a quorum write dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicaWriteAck {
    /// Opaque replica identifier (e.g. node id or session index).
    pub replica_id: u64,
    /// BLAKE3 checksum of the payload as stored by the replica.
    pub checksum: Hash,
}

impl ReplicaWriteAck {
    #[must_use]
    pub fn new(replica_id: u64, checksum: Hash) -> Self {
        Self {
            replica_id,
            checksum,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// QuorumWriteCommit
// ═══════════════════════════════════════════════════════════════════════

/// A self-contained quorum write commit: payload, its BLAKE3 checksum,
/// target replica set, and the minimum acknowledgments required for quorum.
#[derive(Clone, Debug)]
pub struct QuorumWriteCommit {
    /// Object payload bytes.
    pub payload: Vec<u8>,
    /// Pre-computed BLAKE3 checksum of the payload.
    pub checksum: Hash,
    /// Opaque replica identifiers to fan the write out to.
    pub replica_targets: Vec<u64>,
    /// Minimum number of matching-checksum acknowledgments required for quorum.
    pub quorum_threshold: usize,
}

impl QuorumWriteCommit {
    /// Construct a new `QuorumWriteCommit` for the given payload and replica set.
    ///
    /// The BLAKE3 checksum is computed eagerly from `payload`. The caller
    /// supplies the replica targets and the quorum threshold (W).
    ///
    /// # Panics
    ///
    /// Panics if `replica_targets` is empty or `quorum_threshold` is 0 or
    /// exceeds `replica_targets.len()`.
    #[must_use]
    pub fn new(payload: Vec<u8>, replica_targets: Vec<u64>, quorum_threshold: usize) -> Self {
        assert!(
            !replica_targets.is_empty(),
            "QuorumWriteCommit: replica_targets must not be empty"
        );
        assert!(
            quorum_threshold > 0,
            "QuorumWriteCommit: quorum_threshold must be at least 1"
        );
        assert!(
            quorum_threshold <= replica_targets.len(),
            "QuorumWriteCommit: quorum_threshold ({quorum_threshold}) exceeds replica_targets.len() ({})",
            replica_targets.len()
        );

        let checksum = blake3::hash(&payload);
        Self {
            payload,
            checksum,
            replica_targets,
            quorum_threshold,
        }
    }

    /// Construct a `QuorumWriteCommit` from an already-hashed payload.
    ///
    /// Useful when the caller has already computed the checksum for other
    /// purposes (e.g. dedup, content-addressing).  The caller is responsible
    /// for ensuring `checksum == blake3::hash(&payload)`.
    #[must_use]
    pub fn from_prehashed(
        payload: Vec<u8>,
        checksum: Hash,
        replica_targets: Vec<u64>,
        quorum_threshold: usize,
    ) -> Self {
        assert!(
            !replica_targets.is_empty(),
            "QuorumWriteCommit: replica_targets must not be empty"
        );
        assert!(
            quorum_threshold > 0,
            "QuorumWriteCommit: quorum_threshold must be at least 1"
        );
        assert!(
            quorum_threshold <= replica_targets.len(),
            "QuorumWriteCommit: quorum_threshold ({quorum_threshold}) exceeds replica_targets.len() ({})",
            replica_targets.len()
        );
        Self {
            payload,
            checksum,
            replica_targets,
            quorum_threshold,
        }
    }

    /// Total number of replica targets.
    #[must_use]
    pub fn total_targets(&self) -> usize {
        self.replica_targets.len()
    }

    /// Whether `ack_count` acknowledgments satisfy the quorum threshold.
    #[must_use]
    pub fn is_quorum_met(&self, ack_count: usize) -> bool {
        ack_count >= self.quorum_threshold
    }

    /// Whether quorum is mathematically impossible given `alive_count`
    /// remaining reachable replicas.
    #[must_use]
    pub fn quorum_impossible(&self, alive_count: usize) -> bool {
        alive_count < self.quorum_threshold
    }
}

// ═══════════════════════════════════════════════════════════════════════
// QuorumWriteOutcome
// ═══════════════════════════════════════════════════════════════════════

/// Successful outcome of `commit_quorum_write()`.
#[derive(Clone, Debug)]
pub struct QuorumWriteOutcome {
    /// The canonical BLAKE3 checksum verified across the quorum.
    pub canonical_checksum: Hash,
    /// Total number of replicas that acknowledged with a matching checksum.
    pub acks_collected: usize,
    /// Total number of replica targets dispatched to.
    pub total_targets: usize,
    /// Quorum threshold that was required.
    pub quorum_threshold: usize,
    /// Per-replica acknowledgments received.
    pub acks: Vec<ReplicaWriteAck>,
    /// Replica ids that failed (transport error or checksum mismatch).
    pub failed_targets: Vec<u64>,
    /// Whether all targets acknowledged (fully committed, not degraded).
    pub fully_committed: bool,
}

// ═══════════════════════════════════════════════════════════════════════
// commit_quorum_write
// ═══════════════════════════════════════════════════════════════════════

/// Execute a BLAKE3-authenticated quorum write: fan out the payload to
/// every replica target via the provided `transport`, collect per-replica
/// BLAKE3 checksum acknowledgments, verify that at least `commit.quorum_threshold`
/// replicas returned the canonical checksum, and return the outcome.
///
/// # Errors
///
/// Returns `QuorumWriteError::ZeroReplicas` if `commit.replica_targets` is empty.
/// Returns `QuorumWriteError::InsufficientAcks` if fewer than
/// `commit.quorum_threshold` replicas acknowledged with the correct checksum.
/// Returns `QuorumWriteError::ChecksumMismatch` if a replica acknowledged but
/// with a different checksum (this counts as a failure toward quorum).
/// Returns `QuorumWriteError::ReplicaWriteFailed` only if transport errors
/// prevent quorum from being reached.
///
/// Replicas that fail with transport errors or checksum mismatches are
/// accumulated in `failed_targets` but do not by themselves cause an error
/// unless quorum becomes unreachable.
pub fn commit_quorum_write(
    commit: &QuorumWriteCommit,
    transport: &mut dyn QuorumWriteTransport,
) -> Result<QuorumWriteOutcome, QuorumWriteError> {
    if commit.replica_targets.is_empty() {
        return Err(QuorumWriteError::ZeroReplicas);
    }

    let mut acks: Vec<ReplicaWriteAck> = Vec::with_capacity(commit.replica_targets.len());
    let mut failed_targets: Vec<u64> = Vec::new();
    let mut acks_matching: usize = 0;
    let mut acks_total: usize = 0;

    for &replica_id in &commit.replica_targets {
        match transport.write_replica(replica_id, &commit.payload) {
            Ok(replica_checksum) => {
                acks_total += 1;
                if replica_checksum == commit.checksum {
                    acks_matching += 1;
                    acks.push(ReplicaWriteAck::new(replica_id, replica_checksum));
                } else {
                    // Checksum mismatch: treat as a failed target
                    failed_targets.push(replica_id);
                }
            }
            Err(_e) => {
                failed_targets.push(replica_id);
                // Check if quorum is now impossible
                let already_seen = acks_total + failed_targets.len();
                let unseen = commit.replica_targets.len().saturating_sub(already_seen);
                let max_possible = acks_matching + unseen;
                if max_possible < commit.quorum_threshold {
                    return Err(QuorumWriteError::InsufficientAcks {
                        acks_collected: acks_matching,
                        quorum_required: commit.quorum_threshold,
                        total_targets: commit.replica_targets.len(),
                        failed_targets,
                    });
                }
            }
        }
    }

    if acks_matching < commit.quorum_threshold {
        return Err(QuorumWriteError::InsufficientAcks {
            acks_collected: acks_matching,
            quorum_required: commit.quorum_threshold,
            total_targets: commit.replica_targets.len(),
            failed_targets,
        });
    }

    let fully_committed = acks_matching == commit.replica_targets.len();

    Ok(QuorumWriteOutcome {
        canonical_checksum: commit.checksum,
        acks_collected: acks_matching,
        total_targets: commit.replica_targets.len(),
        quorum_threshold: commit.quorum_threshold,
        acks,
        failed_targets,
        fully_committed,
    })
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock transport that returns the canonical checksum for every replica.
    struct MockHonestTransport {
        checksum: Hash,
    }

    impl QuorumWriteTransport for MockHonestTransport {
        fn write_replica(&mut self, _replica_id: u64, _payload: &[u8]) -> Result<Hash, String> {
            Ok(self.checksum)
        }
    }

    /// A mock transport where specific replicas return a wrong checksum.
    struct MockDivergentTransport {
        canonical: Hash,
        wrong: Hash,
        /// Replica ids that return the wrong checksum.
        divergent: Vec<u64>,
    }

    impl QuorumWriteTransport for MockDivergentTransport {
        fn write_replica(&mut self, replica_id: u64, _payload: &[u8]) -> Result<Hash, String> {
            if self.divergent.contains(&replica_id) {
                Ok(self.wrong)
            } else {
                Ok(self.canonical)
            }
        }
    }

    /// A mock transport where specific replicas fail with an error.
    struct MockFailingTransport {
        checksum: Hash,
        /// Replica ids that fail.
        failing: Vec<u64>,
    }

    impl QuorumWriteTransport for MockFailingTransport {
        fn write_replica(&mut self, replica_id: u64, _payload: &[u8]) -> Result<Hash, String> {
            if self.failing.contains(&replica_id) {
                Err(format!("replica {replica_id}: simulated failure"))
            } else {
                Ok(self.checksum)
            }
        }
    }

    fn test_payload() -> Vec<u8> {
        b"quorum-write-test-payload-v1".to_vec()
    }

    fn test_checksum() -> Hash {
        blake3::hash(b"quorum-write-test-payload-v1")
    }

    // ── Single-replica commit (quorum = 1) ───────────────────────────

    #[test]
    fn single_replica_commit_succeeds() {
        let payload = test_payload();
        let checksum = test_checksum();
        let commit = QuorumWriteCommit::new(payload, vec![1], 1);
        let mut transport = MockHonestTransport { checksum };

        let outcome = commit_quorum_write(&commit, &mut transport).unwrap();
        assert_eq!(outcome.canonical_checksum, checksum);
        assert_eq!(outcome.acks_collected, 1);
        assert_eq!(outcome.total_targets, 1);
        assert_eq!(outcome.quorum_threshold, 1);
        assert!(outcome.fully_committed);
        assert!(outcome.failed_targets.is_empty());
    }

    #[test]
    fn single_replica_checksum_mismatch_fails() {
        let payload = test_payload();
        let checksum = test_checksum();
        let wrong = blake3::hash(b"wrong-payload");
        let commit = QuorumWriteCommit::new(payload, vec![1], 1);
        let mut transport = MockDivergentTransport {
            canonical: checksum,
            wrong,
            divergent: vec![1],
        };

        let err = commit_quorum_write(&commit, &mut transport).unwrap_err();
        match err {
            QuorumWriteError::InsufficientAcks {
                acks_collected,
                quorum_required,
                ..
            } => {
                assert_eq!(acks_collected, 0);
                assert_eq!(quorum_required, 1);
            }
            other => panic!("expected InsufficientAcks, got {other:?}"),
        }
    }

    #[test]
    fn single_replica_transport_failure() {
        let payload = test_payload();
        let checksum = test_checksum();
        let commit = QuorumWriteCommit::new(payload, vec![1], 1);
        let mut transport = MockFailingTransport {
            checksum,
            failing: vec![1],
        };

        let err = commit_quorum_write(&commit, &mut transport).unwrap_err();
        match err {
            QuorumWriteError::InsufficientAcks {
                acks_collected,
                quorum_required,
                ..
            } => {
                assert_eq!(acks_collected, 0);
                assert_eq!(quorum_required, 1);
            }
            other => panic!("expected InsufficientAcks, got {other:?}"),
        }
    }

    // ── Multi-replica quorum satisfaction (2 of 3) ──────────────────

    #[test]
    fn two_of_three_quorum_succeeds() {
        let payload = test_payload();
        let checksum = test_checksum();
        let commit = QuorumWriteCommit::new(payload, vec![1, 2, 3], 2);
        let mut transport = MockHonestTransport { checksum };

        let outcome = commit_quorum_write(&commit, &mut transport).unwrap();
        assert_eq!(outcome.acks_collected, 3);
        assert_eq!(outcome.total_targets, 3);
        assert_eq!(outcome.quorum_threshold, 2);
        assert!(outcome.fully_committed);
        assert!(outcome.failed_targets.is_empty());
    }

    #[test]
    fn two_of_three_with_one_divergent_still_meets_quorum() {
        let payload = test_payload();
        let checksum = test_checksum();
        let wrong = blake3::hash(b"wrong");
        let commit = QuorumWriteCommit::new(payload, vec![1, 2, 3], 2);
        let mut transport = MockDivergentTransport {
            canonical: checksum,
            wrong,
            divergent: vec![3],
        };

        let outcome = commit_quorum_write(&commit, &mut transport).unwrap();
        assert_eq!(outcome.acks_collected, 2);
        assert_eq!(outcome.total_targets, 3);
        assert!(!outcome.fully_committed);
        assert_eq!(outcome.failed_targets, vec![3]);
    }

    #[test]
    fn two_of_three_with_one_failure_still_meets_quorum() {
        let payload = test_payload();
        let checksum = test_checksum();
        let commit = QuorumWriteCommit::new(payload, vec![1, 2, 3], 2);
        let mut transport = MockFailingTransport {
            checksum,
            failing: vec![3],
        };

        let outcome = commit_quorum_write(&commit, &mut transport).unwrap();
        assert_eq!(outcome.acks_collected, 2);
        assert!(!outcome.fully_committed);
        assert_eq!(outcome.failed_targets, vec![3]);
    }

    // ── Checksum mismatch rejection ─────────────────────────────────

    #[test]
    fn all_replicas_divergent_fails_quorum() {
        let payload = test_payload();
        let checksum = test_checksum();
        let wrong = blake3::hash(b"wrong");
        let commit = QuorumWriteCommit::new(payload, vec![1, 2, 3], 2);
        let mut transport = MockDivergentTransport {
            canonical: checksum,
            wrong,
            divergent: vec![1, 2, 3],
        };

        let err = commit_quorum_write(&commit, &mut transport).unwrap_err();
        match err {
            QuorumWriteError::InsufficientAcks {
                acks_collected,
                quorum_required,
                ..
            } => {
                assert_eq!(acks_collected, 0);
                assert_eq!(quorum_required, 2);
            }
            other => panic!("expected InsufficientAcks, got {other:?}"),
        }
    }

    #[test]
    fn partial_divergence_below_quorum_fails() {
        let payload = test_payload();
        let checksum = test_checksum();
        let wrong = blake3::hash(b"wrong");
        let commit = QuorumWriteCommit::new(payload, vec![1, 2, 3], 3); // full quorum
        let mut transport = MockDivergentTransport {
            canonical: checksum,
            wrong,
            divergent: vec![2, 3], // only replica 1 matches
        };

        let err = commit_quorum_write(&commit, &mut transport).unwrap_err();
        match err {
            QuorumWriteError::InsufficientAcks {
                acks_collected,
                quorum_required,
                ..
            } => {
                assert_eq!(acks_collected, 1);
                assert_eq!(quorum_required, 3);
            }
            other => panic!("expected InsufficientAcks, got {other:?}"),
        }
    }

    // ── Insufficient ack / timeout ──────────────────────────────────

    #[test]
    fn zero_replica_error() {
        let payload = test_payload();
        let commit = QuorumWriteCommit::new(payload.clone(), vec![1], 1);
        // Manually construct one with empty targets
        let bad = QuorumWriteCommit {
            payload,
            checksum: commit.checksum,
            replica_targets: vec![],
            quorum_threshold: 1,
        };
        let mut transport = MockHonestTransport {
            checksum: commit.checksum,
        };
        let err = commit_quorum_write(&bad, &mut transport).unwrap_err();
        assert!(matches!(err, QuorumWriteError::ZeroReplicas));
    }

    #[test]
    fn all_transport_failures_impossible_quorum() {
        let payload = test_payload();
        let checksum = test_checksum();
        let commit = QuorumWriteCommit::new(payload, vec![1, 2, 3], 2);
        let mut transport = MockFailingTransport {
            checksum,
            failing: vec![1, 2, 3],
        };

        let err = commit_quorum_write(&commit, &mut transport).unwrap_err();
        match err {
            QuorumWriteError::InsufficientAcks {
                acks_collected,
                quorum_required,
                ..
            } => {
                assert_eq!(acks_collected, 0);
                assert_eq!(quorum_required, 2);
            }
            other => panic!("expected InsufficientAcks, got {other:?}"),
        }
    }

    #[test]
    fn two_of_five_with_three_failures_early_exit() {
        let payload = test_payload();
        let checksum = test_checksum();
        let commit = QuorumWriteCommit::new(payload, vec![1, 2, 3, 4, 5], 2);
        let mut transport = MockFailingTransport {
            checksum,
            failing: vec![1, 2, 3, 4], // 4 failures, only 1 can succeed
        };

        // After 3 failures (1,2,3), unseen = [4,5], max_possible = 0 + 2 = 2
        // But replica 4 also fails, so after 4 failures, max_possible = 0 + 1 = 1 < 2
        let err = commit_quorum_write(&commit, &mut transport).unwrap_err();
        assert!(matches!(err, QuorumWriteError::InsufficientAcks { .. }));
    }

    // ── QuorumWriteCommit construction ──────────────────────────────

    #[test]
    fn commit_new_computes_checksum() {
        let payload = b"hello world".to_vec();
        let expected = blake3::hash(b"hello world");
        let commit = QuorumWriteCommit::new(payload, vec![1, 2], 2);
        assert_eq!(commit.checksum, expected);
        assert_eq!(commit.quorum_threshold, 2);
        assert_eq!(commit.total_targets(), 2);
    }

    #[test]
    fn commit_from_prehashed_preserves_checksum() {
        let payload = b"prehashed".to_vec();
        let checksum = blake3::hash(b"prehashed");
        let commit = QuorumWriteCommit::from_prehashed(payload.clone(), checksum, vec![1], 1);
        assert_eq!(commit.checksum, checksum);
        assert_eq!(commit.payload, payload);
    }

    #[test]
    #[should_panic(expected = "replica_targets must not be empty")]
    fn commit_new_panics_on_empty_targets() {
        let _ = QuorumWriteCommit::new(b"data".to_vec(), vec![], 1);
    }

    #[test]
    #[should_panic(expected = "quorum_threshold must be at least 1")]
    fn commit_new_panics_on_zero_threshold() {
        let _ = QuorumWriteCommit::new(b"data".to_vec(), vec![1], 0);
    }

    #[test]
    #[should_panic(expected = "quorum_threshold")]
    fn commit_new_panics_on_threshold_exceeding_targets() {
        let _ = QuorumWriteCommit::new(b"data".to_vec(), vec![1, 2], 3);
    }

    // ── Helper methods ──────────────────────────────────────────────

    #[test]
    fn is_quorum_met_and_impossible() {
        let commit = QuorumWriteCommit::new(b"data".to_vec(), vec![1, 2, 3, 4, 5], 3);
        assert!(!commit.is_quorum_met(2));
        assert!(commit.is_quorum_met(3));
        assert!(commit.is_quorum_met(5));
        assert!(!commit.quorum_impossible(3));
        assert!(commit.quorum_impossible(2));
    }

    // ── Display impls ───────────────────────────────────────────────

    #[test]
    fn quorum_write_error_display() {
        let e = QuorumWriteError::ZeroReplicas;
        assert!(e.to_string().contains("zero replica targets"));

        let e = QuorumWriteError::ChecksumMismatch {
            replica_id: 7,
            expected: blake3::hash(b"a"),
            received: blake3::hash(b"b"),
        };
        assert!(e.to_string().contains("replica 7"));
        assert!(e.to_string().contains("checksum mismatch"));

        let e = QuorumWriteError::InsufficientAcks {
            acks_collected: 1,
            quorum_required: 3,
            total_targets: 5,
            failed_targets: vec![2, 3, 4],
        };
        assert!(e.to_string().contains("1/3"));
        assert!(e.to_string().contains("out of 5"));

        let e = QuorumWriteError::ReplicaWriteFailed {
            replica_id: 9,
            reason: "connection reset".to_string(),
        };
        assert!(e.to_string().contains("replica 9"));
        assert!(e.to_string().contains("connection reset"));
    }

    #[test]
    fn quorum_write_outcome_fields() {
        let checksum = blake3::hash(b"outcome-test");
        let outcome = QuorumWriteOutcome {
            canonical_checksum: checksum,
            acks_collected: 3,
            total_targets: 5,
            quorum_threshold: 3,
            acks: vec![
                ReplicaWriteAck::new(1, checksum),
                ReplicaWriteAck::new(2, checksum),
                ReplicaWriteAck::new(3, checksum),
            ],
            failed_targets: vec![4, 5],
            fully_committed: false,
        };
        assert_eq!(outcome.canonical_checksum, checksum);
        assert!(!outcome.fully_committed);
        assert_eq!(outcome.failed_targets.len(), 2);
    }
}
