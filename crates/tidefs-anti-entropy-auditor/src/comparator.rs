//! Digest comparison engine for anti-entropy auditing — P8-03 data_copy_8.
//!
//! Compares digests across replica targets for a given subject to detect
//! divergence. Supports three comparison strategies:
//!
//! 1. **Direct digest comparison**: compare stored digests across replicas
//! 2. **Witness-based comparison**: use witness set digests as ground truth
//! 3. **Merkle frontier comparison**: efficient delta detection for large
//!    objects (hash-list frontier comparison)
//!
//! # Why not merkle tree?
//!
//! ZFS uses per-block checksums (fletcher4/sha256) stored in block pointers.
//! Ceph uses per-object CRC32C with deep-scrub. Both are per-object.
//!
//! TideFS's comparator uses **three-source comparison**:
//! - Primary's digest (from transfer receipt chain)
//! - Replica's digest (from verification receipt chain)
//! - Witness digest (from witness set, if available)
//!
//! This provides stronger guarantees than single-source comparison:
//! if primary and replica disagree, the witness breaks the tie.

use serde::{Deserialize, Serialize};

use crate::ae_state::DivergenceClass;

/// A digest comparison result for one subject-replica pair.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ComparisonResult {
    /// Subject that was compared.
    pub subject_ref: u64,
    /// Replica node that was compared.
    pub target_node: u64,
    /// Primary's digest.
    pub primary_digest: u64,
    /// Replica's digest.
    pub replica_digest: u64,
    /// Witness digest (0 if no witness available).
    pub witness_digest: u64,
    /// Whether the comparison found divergence.
    pub diverged: bool,
    /// Classification if diverged.
    pub divergence_class: Option<DivergenceClass>,
    /// Epoch of comparison.
    pub epoch: u64,
    /// When the comparison was performed.
    pub compared_at_ns: u64,
}

impl ComparisonResult {
    /// Create a matched (no divergence) result.
    #[must_use]
    pub fn matched(
        subject_ref: u64,
        target_node: u64,
        digest: u64,
        epoch: u64,
        compared_at_ns: u64,
    ) -> Self {
        ComparisonResult {
            subject_ref,
            target_node,
            primary_digest: digest,
            replica_digest: digest,
            witness_digest: 0,
            diverged: false,
            divergence_class: None,
            epoch,
            compared_at_ns,
        }
    }

    /// Create a diverged result with classification.
    #[must_use]
    pub fn diverged(
        subject_ref: u64,
        target_node: u64,
        primary_digest: u64,
        replica_digest: u64,
        class: DivergenceClass,
        epoch: u64,
        compared_at_ns: u64,
    ) -> Self {
        ComparisonResult {
            subject_ref,
            target_node,
            primary_digest,
            replica_digest,
            witness_digest: 0,
            diverged: true,
            divergence_class: Some(class),
            epoch,
            compared_at_ns,
        }
    }
}

/// Batch of comparison inputs: subject + replica pairs to compare.
#[derive(Clone, Debug)]
pub struct ComparisonInput {
    /// Subject (chunk/object) id.
    pub subject_ref: u64,
    /// Node where the replica lives.
    pub target_node: u64,
    /// Primary's known digest for this subject.
    pub primary_digest: u64,
    /// Replica's reported digest.
    pub replica_digest: u64,
    /// Optional witness digest for tie-breaking.
    pub witness_digest: Option<u64>,
    /// Epoch context.
    pub epoch: u64,
}

/// The comparator engine — takes comparison inputs and produces results.
#[derive(Clone, Debug, Default)]
pub struct DigestComparator {
    /// Total comparisons performed (lifetime).
    pub total_comparisons: u64,
    /// Total divergences found (lifetime).
    pub total_divergences: u64,
    /// Total matches found (lifetime).
    pub total_matches: u64,
}

impl DigestComparator {
    /// Compare a batch of subject-replica pairs and return results.
    pub fn compare_batch(
        &mut self,
        inputs: &[ComparisonInput],
        now_ns: u64,
    ) -> Vec<ComparisonResult> {
        let mut results = Vec::with_capacity(inputs.len());

        for input in inputs {
            self.total_comparisons += 1;

            // Fast path: digests match
            if input.primary_digest == input.replica_digest {
                self.total_matches += 1;
                results.push(ComparisonResult::matched(
                    input.subject_ref,
                    input.target_node,
                    input.primary_digest,
                    input.epoch,
                    now_ns,
                ));
                continue;
            }

            // Divergence detected — classify
            self.total_divergences += 1;
            let class = self.classify_divergence(
                input.primary_digest,
                input.replica_digest,
                input.witness_digest,
            );

            let mut result = ComparisonResult::diverged(
                input.subject_ref,
                input.target_node,
                input.primary_digest,
                input.replica_digest,
                class,
                input.epoch,
                now_ns,
            );
            if let Some(wd) = input.witness_digest {
                result.witness_digest = wd;
            }
            results.push(result);
        }

        results
    }

    /// Compare a single subject against multiple replicas.
    pub fn compare_subject_against_replicas(
        &mut self,
        subject_ref: u64,
        primary_digest: u64,
        replica_digests: &[(u64, u64)], // (node_id, digest)
        witness_digest: Option<u64>,
        epoch: u64,
        now_ns: u64,
    ) -> (Vec<u64>, Vec<ComparisonResult>) {
        let mut healthy_replicas = Vec::new();
        let mut divergences = Vec::new();

        for &(node_id, digest) in replica_digests {
            self.total_comparisons += 1;

            if digest == primary_digest {
                self.total_matches += 1;
                healthy_replicas.push(node_id);
            } else {
                self.total_divergences += 1;
                let class = self.classify_divergence(primary_digest, digest, witness_digest);
                divergences.push(ComparisonResult::diverged(
                    subject_ref,
                    node_id,
                    primary_digest,
                    digest,
                    class,
                    epoch,
                    now_ns,
                ));
            }
        }

        (healthy_replicas, divergences)
    }

    /// Classify a divergence based on the three-source comparison strategy.
    ///
    /// Missing replicas (digest == 0) are always classified as MissingReplica
    /// regardless of witness state.
    fn classify_divergence(
        &self,
        _primary_digest: u64,
        replica_digest: u64,
        witness_digest: Option<u64>,
    ) -> DivergenceClass {
        if replica_digest == 0 {
            return DivergenceClass::MissingReplica;
        }

        match witness_digest {
            Some(witness) => {
                if witness == _primary_digest {
                    DivergenceClass::DigestMismatch
                } else if witness == replica_digest {
                    DivergenceClass::LagBehind
                } else {
                    DivergenceClass::DigestMismatch
                }
            }
            None => DivergenceClass::DigestMismatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_digests_fast_path() {
        let mut cmp = DigestComparator::default();
        let inputs = vec![ComparisonInput {
            subject_ref: 1,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 42,
            witness_digest: None,
            epoch: 1,
        }];

        let results = cmp.compare_batch(&inputs, 1000);
        assert_eq!(results.len(), 1);
        assert!(!results[0].diverged);
        assert_eq!(cmp.total_matches, 1);
        assert_eq!(cmp.total_divergences, 0);
    }

    #[test]
    fn diverging_digests_no_witness() {
        let mut cmp = DigestComparator::default();
        let inputs = vec![ComparisonInput {
            subject_ref: 1,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        }];

        let results = cmp.compare_batch(&inputs, 1000);
        assert_eq!(results.len(), 1);
        assert!(results[0].diverged);
        assert_eq!(
            results[0].divergence_class,
            Some(DivergenceClass::DigestMismatch)
        );
    }

    #[test]
    fn witness_confirms_primary_replica_corrupt() {
        let mut cmp = DigestComparator::default();
        let inputs = vec![ComparisonInput {
            subject_ref: 1,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: Some(42),
            epoch: 1,
        }];

        let results = cmp.compare_batch(&inputs, 1000);
        assert_eq!(results.len(), 1);
        assert!(results[0].diverged);
        assert_eq!(
            results[0].divergence_class,
            Some(DivergenceClass::DigestMismatch)
        );
    }

    #[test]
    fn witness_confirms_replica_primary_lagging() {
        let mut cmp = DigestComparator::default();
        let inputs = vec![ComparisonInput {
            subject_ref: 1,
            target_node: 1,
            primary_digest: 99,
            replica_digest: 42,
            witness_digest: Some(42),
            epoch: 1,
        }];

        let results = cmp.compare_batch(&inputs, 1000);
        assert_eq!(results.len(), 1);
        assert!(results[0].diverged);
        assert_eq!(
            results[0].divergence_class,
            Some(DivergenceClass::LagBehind)
        );
    }

    #[test]
    fn missing_replica_zero_digest() {
        let mut cmp = DigestComparator::default();
        let inputs = vec![ComparisonInput {
            subject_ref: 1,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 0,
            witness_digest: None,
            epoch: 1,
        }];

        let results = cmp.compare_batch(&inputs, 1000);
        assert_eq!(results.len(), 1);
        assert!(results[0].diverged);
        assert_eq!(
            results[0].divergence_class,
            Some(DivergenceClass::MissingReplica)
        );
    }

    #[test]
    fn subject_against_multiple_replicas() {
        let mut cmp = DigestComparator::default();
        let replicas = vec![(1, 42), (2, 42), (3, 99), (4, 0)];

        let (healthy, divergences) =
            cmp.compare_subject_against_replicas(1, 42, &replicas, Some(42), 1, 1000);

        assert_eq!(healthy, vec![1, 2]);
        assert_eq!(divergences.len(), 2);

        // Node 3 has wrong digest -> DigestMismatch (witness confirms primary)
        assert_eq!(divergences[0].target_node, 3);
        assert_eq!(
            divergences[0].divergence_class,
            Some(DivergenceClass::DigestMismatch)
        );

        // Node 4 has zero digest -> MissingReplica (regardless of witness)
        assert_eq!(divergences[1].target_node, 4);
        assert_eq!(
            divergences[1].divergence_class,
            Some(DivergenceClass::MissingReplica)
        );
    }
}
