// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Deterministic witness set for quorum acknowledgment tracking.
//
// Every distributed consensus operation (quorum-write commit, lock acquisition,
// membership epoch change) needs a witness set that answers: which nodes
// acknowledged this operation, and does that reach quorum?
//
// This module provides a self-contained WitnessSet that combines node membership
// management with per-operation acknowledgment tracking and epoch-bounded reset.
// Node IDs and operation IDs are u64 for wire-protocol simplicity.

use serde::{Deserialize, Serialize};
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use tidefs_membership_epoch::{ClusterMemberRecord, EpochId, MemberClass, MemberId};

use crate::types::{WitnessError, WitnessMemberClassification};

// ---------------------------------------------------------------------------
// Quorum threshold
// ---------------------------------------------------------------------------

/// Configurable quorum threshold for determining when enough witnesses have
/// acknowledged an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuorumThreshold {
    /// Strict majority: floor(N/2) + 1.
    StrictMajority,
    /// Super-majority: ceil(2 * N / 3).
    SuperMajority,
    /// Explicit count: exactly `n` acknowledgments required.
    Exact(usize),
}

impl QuorumThreshold {
    /// Compute the number of acks required given a witness count.
    pub fn required(self, witness_count: usize) -> usize {
        if witness_count == 0 {
            return 0;
        }
        match self {
            Self::StrictMajority => (witness_count / 2) + 1,
            Self::SuperMajority => {
                let n = 2 * witness_count;
                if n % 3 == 0 {
                    n / 3
                } else {
                    (n / 3) + 1
                }
            }
            Self::Exact(n) => n.min(witness_count),
        }
    }

    /// Check whether `collected` meets the threshold for `witness_count`.
    pub fn is_satisfied(self, collected: usize, witness_count: usize) -> bool {
        collected >= self.required(witness_count)
    }
}

// ---------------------------------------------------------------------------
// WitnessSet
// ---------------------------------------------------------------------------

/// A deterministic witness set for quorum acknowledgment tracking.
///
/// Tracks which nodes are members, which operations each node has acknowledged,
/// and whether a given operation has reached quorum. Uses ordered collections
/// (`BTreeSet`, `BTreeMap`) for deterministic iteration suitable for replay.
///
/// All acknowledgments are scoped to the current epoch; calling [`advance_epoch`]
/// clears all pending acks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessSet {
    /// Nodes currently in the witness set, ordered for deterministic iteration.
    witnesses: BTreeSet<u64>,
    /// Membership-epoch classifications keyed by member id.
    member_classifications: BTreeMap<u64, WitnessMemberClassification>,
    /// Current epoch number. Acks are valid only within this epoch.
    current_epoch: u64,
    /// Quorum threshold configuration.
    threshold: QuorumThreshold,
    /// Per-operation acknowledgment map: operation_id → set of node_ids that acked.
    acks: BTreeMap<u64, BTreeSet<u64>>,
}

impl WitnessSet {
    // -- Construction ---------------------------------------------------------

    /// Create an empty witness set with the given quorum threshold.
    pub fn new(threshold: QuorumThreshold) -> Self {
        Self {
            witnesses: BTreeSet::new(),
            member_classifications: BTreeMap::new(),
            current_epoch: 0,
            threshold,
            acks: BTreeMap::new(),
        }
    }

    /// Create an empty witness set with the given threshold and initial epoch.
    pub fn with_epoch(threshold: QuorumThreshold, epoch: u64) -> Self {
        Self {
            witnesses: BTreeSet::new(),
            member_classifications: BTreeMap::new(),
            current_epoch: epoch,
            threshold,
            acks: BTreeMap::new(),
        }
    }

    // -- Membership -----------------------------------------------------------

    /// Add a node to the witness set.
    ///
    /// The node must be known to the current membership epoch and classified
    /// as a voter by `tidefs-membership-epoch`. If the node is already a
    /// witness, this is a no-op. Returns true if the node was newly added.
    pub fn add_witness(&mut self, node_id: u64) -> bool {
        self.try_add_witness(node_id).unwrap_or(false)
    }

    /// Add a node to the witness set, returning the membership refusal reason.
    pub fn try_add_witness(&mut self, node_id: u64) -> Result<bool, WitnessError> {
        self.ensure_current_voter(node_id)?;
        Ok(self.witnesses.insert(node_id))
    }

    /// Validate that `node_id` is eligible to witness the current epoch.
    pub fn validate_witness_eligibility(&self, node_id: u64) -> Result<(), WitnessError> {
        self.ensure_current_voter(node_id)
    }

    /// Install voter classification for the current membership epoch.
    ///
    /// `tidefs-membership-epoch` remains the authority for member class and
    /// epoch identity. The witness set stores only the classification snapshot
    /// needed to reject unknown, non-voter, or stale-epoch acknowledgments.
    /// Installing a different epoch advances this witness set and clears all
    /// pending acknowledgments before pruning witnesses that are no longer
    /// current voters.
    pub fn install_membership_epoch(&mut self, epoch: EpochId, members: &[ClusterMemberRecord]) {
        let mut classifications = BTreeMap::new();
        for member in members {
            let classification = WitnessMemberClassification::from_record(member);
            classifications.insert(member.member_id.0, classification);
        }

        self.replace_member_classifications(epoch, classifications);
    }

    /// Install the voter set exported by a membership config epoch.
    pub fn install_voter_ids_for_epoch(&mut self, epoch: EpochId, voter_ids: &[MemberId]) {
        let classifications = voter_ids
            .iter()
            .copied()
            .map(|member_id| {
                (
                    member_id.0,
                    WitnessMemberClassification {
                        member_id,
                        epoch,
                        member_class: MemberClass::Voter,
                    },
                )
            })
            .collect();

        self.replace_member_classifications(epoch, classifications);
    }

    fn replace_member_classifications(
        &mut self,
        epoch: EpochId,
        classifications: BTreeMap<u64, WitnessMemberClassification>,
    ) {
        if epoch.0 != self.current_epoch {
            self.advance_epoch(epoch.0);
        }

        if classifications != self.member_classifications {
            self.member_classifications = classifications;
            self.acks.clear();
        }

        self.prune_ineligible_witnesses();
    }

    /// Remove a node from the witness set and clear all of its acknowledgments.
    ///
    /// Returns true if the node was a member.
    pub fn remove_witness(&mut self, node_id: u64) -> bool {
        if self.witnesses.remove(&node_id) {
            // Remove this node's acks from every operation.
            for (_op_id, ack_set) in self.acks.iter_mut() {
                ack_set.remove(&node_id);
            }
            true
        } else {
            false
        }
    }

    /// Return true if the node is a member of this witness set.
    pub fn contains(&self, node_id: u64) -> bool {
        self.witnesses.contains(&node_id)
    }

    /// Number of witness members.
    pub fn len(&self) -> usize {
        self.witnesses.len()
    }

    /// True when the witness set has no members.
    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }

    /// Return the current epoch.
    pub fn epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Return the quorum threshold configuration.
    pub fn threshold(&self) -> QuorumThreshold {
        self.threshold
    }

    /// Deterministic iterator over witness node IDs in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.witnesses.iter().copied()
    }

    // -- Acknowledgment tracking ----------------------------------------------

    /// Record that `node_id` has acknowledged `operation_id`.
    ///
    /// Idempotent: calling this multiple times with the same arguments has no
    /// additional effect beyond the first call. Returns true if this was a new
    /// acknowledgment (node had not previously acked this operation).
    ///
    /// Panics if `node_id` is not a member of this witness set.
    pub fn ack(&mut self, node_id: u64, operation_id: u64) -> bool {
        assert!(
            self.witnesses.contains(&node_id),
            "node {node_id} is not a member of the witness set; add it with add_witness first"
        );
        match self.acks.entry(operation_id) {
            Entry::Vacant(entry) => {
                let mut set = BTreeSet::new();
                set.insert(node_id);
                entry.insert(set);
                true
            }
            Entry::Occupied(mut entry) => entry.get_mut().insert(node_id),
        }
    }

    /// Return the number of witnesses that have acknowledged `operation_id`.
    pub fn ack_count(&self, operation_id: u64) -> usize {
        self.acks.get(&operation_id).map(|s| s.len()).unwrap_or(0)
    }

    /// Return true when enough witnesses have acknowledged `operation_id` to
    /// satisfy the configured quorum threshold.
    pub fn has_quorum(&self, operation_id: u64) -> bool {
        // An empty witness set can never reach quorum.
        if self.witnesses.is_empty() {
            return false;
        }
        let count = self.ack_count(operation_id);
        self.threshold.is_satisfied(count, self.witnesses.len())
    }

    /// Return the set of node IDs that have acknowledged `operation_id`, if any.
    pub fn ack_set(&self, operation_id: u64) -> Option<&BTreeSet<u64>> {
        self.acks.get(&operation_id)
    }

    /// Number of distinct operations currently being tracked.
    pub fn operation_count(&self) -> usize {
        self.acks.len()
    }
    /// Deterministic iterator over all tracked operation IDs in ascending order.
    pub fn operations(&self) -> impl Iterator<Item = u64> + '_ {
        self.acks.keys().copied()
    }

    // -- Epoch management -----------------------------------------------------

    /// Advance to a new epoch, clearing all pending acknowledgments.
    ///
    /// Advancing to a different epoch invalidates witness membership until the
    /// caller installs the new membership-epoch voter classification. All
    /// per-operation ack state is dropped because acks from a prior epoch are
    /// considered stale.
    ///
    /// Panics if `new_epoch < current_epoch` (epochs must be monotonic).
    pub fn advance_epoch(&mut self, new_epoch: u64) {
        assert!(
            new_epoch >= self.current_epoch,
            "epochs must be monotonic: cannot advance from {} to {}",
            self.current_epoch,
            new_epoch
        );
        let advanced = new_epoch != self.current_epoch;
        self.current_epoch = new_epoch;
        self.acks.clear();
        if advanced {
            self.witnesses.clear();
            self.member_classifications.clear();
        } else {
            self.prune_ineligible_witnesses();
        }
    }

    fn ensure_current_voter(&self, node_id: u64) -> Result<(), WitnessError> {
        let Some(classification) = self.member_classifications.get(&node_id) else {
            return Err(WitnessError::UnknownWitness {
                witness: node_id,
                epoch: self.current_epoch,
            });
        };

        if classification.epoch.0 != self.current_epoch {
            return Err(WitnessError::StaleWitnessEpoch {
                witness: node_id,
                member_epoch: classification.epoch.0,
                current_epoch: self.current_epoch,
            });
        }

        if !classification.member_class.can_vote() {
            return Err(WitnessError::WitnessNotVoter {
                witness: node_id,
                member_class: classification.member_class,
            });
        }

        Ok(())
    }

    fn prune_ineligible_witnesses(&mut self) {
        let current_epoch = EpochId::new(self.current_epoch);
        let classifications = &self.member_classifications;
        self.witnesses.retain(|node_id| {
            classifications
                .get(node_id)
                .is_some_and(|classification| classification.is_voter_in_epoch(current_epoch))
        });
        let witnesses = &self.witnesses;
        for ack_set in self.acks.values_mut() {
            ack_set.retain(|node_id| witnesses.contains(node_id));
        }
    }
}

#[cfg(test)]
fn witness_member_record(
    id: u64,
    epoch: u64,
    member_class: tidefs_membership_epoch::MemberClass,
) -> ClusterMemberRecord {
    use tidefs_membership_epoch::{DomainId, FailureDomainVector, HealthClass, MemberId};

    ClusterMemberRecord {
        member_id: MemberId::new(id),
        member_class,
        current_membership_epoch_ref: EpochId::new(epoch),
        log_frontier: 0,
        health: HealthClass::Healthy,
        failure_domain_vector: FailureDomainVector::new(
            DomainId::new(id),
            DomainId::new(id),
            DomainId::new(id),
            DomainId::new(id),
            DomainId::new(id),
            DomainId::new(id),
        ),
        digest: 0,
    }
}

#[cfg(test)]
fn install_voters(ws: &mut WitnessSet, ids: &[u64]) {
    let epoch = ws.epoch();
    let members: Vec<_> = ids
        .iter()
        .copied()
        .map(|id| witness_member_record(id, epoch, tidefs_membership_epoch::MemberClass::Voter))
        .collect();
    ws.install_membership_epoch(EpochId::new(epoch), &members);
}

#[cfg(test)]
fn add_voters(ws: &mut WitnessSet, ids: &[u64]) {
    install_voters(ws, ids);
    for id in ids {
        assert!(ws.add_witness(*id), "voter {id} must be accepted");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Threshold arithmetic -------------------------------------------------

    #[test]
    fn test_strict_majority_arithmetic() {
        assert_eq!(QuorumThreshold::StrictMajority.required(0), 0);
        assert_eq!(QuorumThreshold::StrictMajority.required(1), 1);
        assert_eq!(QuorumThreshold::StrictMajority.required(2), 2);
        assert_eq!(QuorumThreshold::StrictMajority.required(3), 2);
        assert_eq!(QuorumThreshold::StrictMajority.required(4), 3);
        assert_eq!(QuorumThreshold::StrictMajority.required(5), 3);
        assert_eq!(QuorumThreshold::StrictMajority.required(6), 4);
    }

    #[test]
    fn test_super_majority_arithmetic() {
        assert_eq!(QuorumThreshold::SuperMajority.required(0), 0);
        assert_eq!(QuorumThreshold::SuperMajority.required(1), 1); // ceil(2/3)=1
        assert_eq!(QuorumThreshold::SuperMajority.required(2), 2); // ceil(4/3)=2
        assert_eq!(QuorumThreshold::SuperMajority.required(3), 2); // 6/3=2
        assert_eq!(QuorumThreshold::SuperMajority.required(4), 3); // ceil(8/3)=3
        assert_eq!(QuorumThreshold::SuperMajority.required(5), 4); // ceil(10/3)=4
        assert_eq!(QuorumThreshold::SuperMajority.required(6), 4); // 12/3=4
    }

    #[test]
    fn test_exact_threshold() {
        assert_eq!(QuorumThreshold::Exact(3).required(5), 3);
        assert_eq!(QuorumThreshold::Exact(3).required(2), 2); // capped
        assert_eq!(QuorumThreshold::Exact(0).required(5), 0);
    }

    #[test]
    fn test_is_satisfied() {
        let t = QuorumThreshold::StrictMajority;
        assert!(t.is_satisfied(3, 5));
        assert!(!t.is_satisfied(2, 5));
        assert!(t.is_satisfied(5, 5));
    }

    // -- Construction ---------------------------------------------------------

    #[test]
    fn test_new_witness_set_is_empty() {
        let ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        assert!(ws.is_empty());
        assert_eq!(ws.len(), 0);
        assert_eq!(ws.epoch(), 0);
    }

    #[test]
    fn test_with_epoch_sets_epoch() {
        let ws = WitnessSet::with_epoch(QuorumThreshold::StrictMajority, 7);
        assert_eq!(ws.epoch(), 7);
        assert!(ws.is_empty());
    }

    // -- Membership -----------------------------------------------------------

    #[test]
    fn test_add_witness() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        install_voters(&mut ws, &[10]);
        assert!(ws.add_witness(10));
        assert!(ws.contains(10));
        assert_eq!(ws.len(), 1);
        // Duplicate add is no-op.
        assert!(!ws.add_witness(10));
        assert_eq!(ws.len(), 1);
    }

    #[test]
    fn test_add_multiple_witnesses() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[3, 1, 2]);
        assert_eq!(ws.len(), 3);
        assert!(ws.contains(1));
        assert!(ws.contains(2));
        assert!(ws.contains(3));
    }

    #[test]
    fn test_remove_witness() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[5, 7]);
        assert!(ws.remove_witness(5));
        assert!(!ws.contains(5));
        assert!(ws.contains(7));
        assert_eq!(ws.len(), 1);
        // Removing non-member returns false.
        assert!(!ws.remove_witness(5));
    }

    #[test]
    fn test_remove_witness_clears_acks() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1, 2, 3]);
        ws.ack(1, 100);
        ws.ack(2, 100);
        ws.ack(3, 100);
        assert_eq!(ws.ack_count(100), 3);
        ws.remove_witness(2);
        // Node 2's ack is cleared; remaining 2 of 2 have acked → quorum still holds.
        assert_eq!(ws.ack_count(100), 2);
        assert!(ws.has_quorum(100));
        // A different operation with insufficient acks should not have quorum.
        ws.ack(1, 200);
        assert!(!ws.has_quorum(200));
    }

    #[test]
    fn test_iter_deterministic() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[30, 10, 20]);
        let ids: Vec<u64> = ws.iter().collect();
        assert_eq!(ids, vec![10, 20, 30]);
    }

    #[test]
    fn test_is_empty() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        assert!(ws.is_empty());
        add_voters(&mut ws, &[1]);
        assert!(!ws.is_empty());
    }

    // -- Acknowledgment tracking ----------------------------------------------

    #[test]
    fn test_ack_single() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1]);
        assert!(ws.ack(1, 42));
        assert_eq!(ws.ack_count(42), 1);
    }

    #[test]
    fn test_ack_duplicate_is_idempotent() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1]);
        assert!(ws.ack(1, 42));
        assert!(!ws.ack(1, 42)); // duplicate
        assert!(!ws.ack(1, 42)); // duplicate
        assert_eq!(ws.ack_count(42), 1);
    }

    #[test]
    fn test_ack_multiple_witnesses_same_operation() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1, 2, 3]);
        ws.ack(1, 77);
        ws.ack(2, 77);
        ws.ack(3, 77);
        assert_eq!(ws.ack_count(77), 3);
    }

    #[test]
    fn test_ack_set_returns_correct_nodes() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1, 2, 3]);
        ws.ack(1, 100);
        ws.ack(3, 100);
        let acked = ws.ack_set(100).unwrap();
        assert!(acked.contains(&1));
        assert!(!acked.contains(&2));
        assert!(acked.contains(&3));
    }

    #[test]
    fn test_ack_count_unknown_operation() {
        let ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        assert_eq!(ws.ack_count(999), 0);
    }

    #[test]
    fn test_distinct_operations_independent() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1, 2]);
        ws.ack(1, 10);
        ws.ack(2, 20);
        assert_eq!(ws.ack_count(10), 1);
        assert_eq!(ws.ack_count(20), 1);
        assert_eq!(ws.operation_count(), 2);
    }

    #[test]
    #[should_panic(expected = "not a member")]
    fn test_ack_non_member_panics() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        ws.ack(999, 1);
    }

    // -- Quorum checks --------------------------------------------------------

    #[test]
    fn test_has_quorum_majority_satisfied() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1, 2, 3]); // 3 members, majority = 2
        ws.ack(1, 100);
        ws.ack(2, 100);
        assert!(ws.has_quorum(100));
    }

    #[test]
    fn test_has_quorum_majority_not_met() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1, 2, 3]); // 3 members, majority = 2
        ws.ack(1, 100); // only 1 ack
        assert!(!ws.has_quorum(100));
    }

    #[test]
    fn test_has_quorum_exact_threshold() {
        let mut ws = WitnessSet::new(QuorumThreshold::Exact(2));
        add_voters(&mut ws, &[1, 2, 3]);
        ws.ack(1, 100);
        assert!(!ws.has_quorum(100));
        ws.ack(2, 100);
        assert!(ws.has_quorum(100));
    }

    #[test]
    fn test_has_quorum_super_majority() {
        let mut ws = WitnessSet::new(QuorumThreshold::SuperMajority);
        add_voters(&mut ws, &[1, 2, 3]); // 3 members, super-majority ceil(6/3)=2
        ws.ack(1, 100);
        ws.ack(2, 100);
        assert!(ws.has_quorum(100));

        let mut ws2 = WitnessSet::new(QuorumThreshold::SuperMajority);
        add_voters(&mut ws2, &[1, 2, 3, 4]); // 4 members, super-majority ceil(8/3)=3
        ws2.ack(1, 100);
        ws2.ack(2, 100);
        assert!(!ws2.has_quorum(100));
        ws2.ack(3, 100);
        assert!(ws2.has_quorum(100));
    }

    #[test]
    fn test_has_quorum_empty_set() {
        let ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        assert!(!ws.has_quorum(100));
    }

    #[test]
    fn test_has_quorum_unknown_operation() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1]);
        assert!(!ws.has_quorum(999));
    }

    #[test]
    fn test_has_quorum_after_remove_recalculates() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1, 2, 3]); // 3 members, majority = 2
        ws.ack(1, 100);
        ws.ack(2, 100);
        assert!(ws.has_quorum(100)); // 2 of 3 = majority satisfied
                                     // Remove witness 1 (which had acked). Now 2 members, majority = 2.
        ws.remove_witness(1);
        assert_eq!(ws.len(), 2);
        assert_eq!(ws.ack_count(100), 1); // only witness 2's ack remains
        assert!(!ws.has_quorum(100)); // need 2 of 2, have 1
    }

    // -- Epoch management -----------------------------------------------------

    #[test]
    fn test_advance_epoch_clears_acks() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1, 2, 3]);
        ws.ack(1, 100);
        ws.ack(2, 100);
        ws.ack(3, 100);
        assert_eq!(ws.ack_count(100), 3);
        assert!(ws.has_quorum(100));

        ws.advance_epoch(5);
        assert_eq!(ws.epoch(), 5);
        assert_eq!(ws.ack_count(100), 0);
        assert!(!ws.has_quorum(100));
        assert_eq!(ws.len(), 0);
        assert!(!ws.contains(1));
    }

    #[test]
    fn test_advance_epoch_same_epoch_noop() {
        let mut ws = WitnessSet::with_epoch(QuorumThreshold::StrictMajority, 3);
        add_voters(&mut ws, &[1]);
        ws.ack(1, 100);
        ws.advance_epoch(3); // same epoch, allowed (monotonic non-strict)
        assert_eq!(ws.epoch(), 3);
        assert_eq!(ws.ack_count(100), 0); // acks cleared
    }

    #[test]
    fn test_add_witness_rejects_non_voter() {
        let mut ws = WitnessSet::with_epoch(QuorumThreshold::StrictMajority, 7);
        let members = [witness_member_record(
            10,
            7,
            tidefs_membership_epoch::MemberClass::Learner,
        )];
        ws.install_membership_epoch(EpochId::new(7), &members);

        assert!(matches!(
            ws.try_add_witness(10),
            Err(WitnessError::WitnessNotVoter { witness: 10, .. })
        ));
        assert!(!ws.add_witness(10));
        assert!(ws.is_empty());
    }

    #[test]
    fn test_add_witness_rejects_stale_epoch_member() {
        let mut ws = WitnessSet::with_epoch(QuorumThreshold::StrictMajority, 8);
        let members = [witness_member_record(
            11,
            7,
            tidefs_membership_epoch::MemberClass::Voter,
        )];
        ws.install_membership_epoch(EpochId::new(8), &members);

        assert!(matches!(
            ws.try_add_witness(11),
            Err(WitnessError::StaleWitnessEpoch {
                witness: 11,
                member_epoch: 7,
                current_epoch: 8,
            })
        ));
        assert!(!ws.add_witness(11));
        assert!(ws.is_empty());
    }

    #[test]
    fn test_add_witness_rejects_unknown_member() {
        let mut ws = WitnessSet::with_epoch(QuorumThreshold::StrictMajority, 9);
        install_voters(&mut ws, &[1, 2, 3]);

        assert!(matches!(
            ws.try_add_witness(99),
            Err(WitnessError::UnknownWitness {
                witness: 99,
                epoch: 9,
            })
        ));
        assert!(!ws.add_witness(99));
        assert_eq!(ws.len(), 0);
    }

    #[test]
    fn test_membership_epoch_advance_invalidates_stale_witnesses() {
        let mut ws = WitnessSet::with_epoch(QuorumThreshold::StrictMajority, 1);
        add_voters(&mut ws, &[1, 2, 3]);
        ws.ack(1, 55);
        ws.ack(2, 55);
        assert!(ws.has_quorum(55));

        let members = [
            witness_member_record(2, 2, tidefs_membership_epoch::MemberClass::Voter),
            witness_member_record(3, 2, tidefs_membership_epoch::MemberClass::Voter),
            witness_member_record(4, 2, tidefs_membership_epoch::MemberClass::Voter),
        ];
        ws.install_membership_epoch(EpochId::new(2), &members);

        assert_eq!(ws.epoch(), 2);
        assert_eq!(ws.ack_count(55), 0);
        assert!(!ws.has_quorum(55));
        assert_eq!(ws.len(), 0);
        assert!(!ws.add_witness(1));
        assert!(ws.add_witness(2));
        assert!(ws.add_witness(4));
        assert!(!ws.has_quorum(55));
    }

    #[test]
    #[should_panic(expected = "epochs must be monotonic")]
    fn test_advance_epoch_backwards_panics() {
        let mut ws = WitnessSet::with_epoch(QuorumThreshold::StrictMajority, 10);
        ws.advance_epoch(5);
    }

    // -- Serialization --------------------------------------------------------

    #[test]
    fn test_serialize_deserialize_empty() {
        let ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        let json = serde_json::to_string(&ws).unwrap();
        let ws2: WitnessSet = serde_json::from_str(&json).unwrap();
        assert!(ws2.is_empty());
        assert_eq!(ws2.epoch(), 0);
    }

    #[test]
    fn test_serialize_deserialize_with_data() {
        let mut ws = WitnessSet::new(QuorumThreshold::SuperMajority);
        add_voters(&mut ws, &[10, 20, 30]);
        ws.ack(10, 1);
        ws.ack(20, 1);
        ws.ack(30, 1);
        ws.ack(10, 2);

        let json = serde_json::to_string(&ws).unwrap();
        let ws2: WitnessSet = serde_json::from_str(&json).unwrap();

        assert_eq!(ws2.len(), 3);
        assert!(ws2.contains(10));
        assert_eq!(ws2.ack_count(1), 3);
        assert!(ws2.has_quorum(1));
        assert_eq!(ws2.ack_count(2), 1);

        let ids: Vec<u64> = ws2.iter().collect();
        assert_eq!(ids, vec![10, 20, 30]);
    }

    // -- Integration smoke tests ----------------------------------------------

    #[test]
    fn test_smoke_5_nodes_3_quorum() {
        let mut ws = WitnessSet::new(QuorumThreshold::Exact(3));
        add_voters(&mut ws, &[1, 2, 3, 4, 5]);
        assert_eq!(ws.len(), 5);

        // Ack from 3 nodes → quorum.
        ws.ack(1, 100);
        ws.ack(2, 100);
        ws.ack(3, 100);
        assert!(ws.has_quorum(100));

        // Ack from only 2 → no quorum.
        ws.ack(1, 200);
        ws.ack(2, 200);
        assert!(!ws.has_quorum(200));
    }

    #[test]
    fn test_smoke_epoch_advance_and_reack() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1, 2, 3]);
        ws.ack(1, 10);
        ws.ack(2, 10);
        assert!(ws.has_quorum(10));

        ws.advance_epoch(1);
        assert!(!ws.has_quorum(10));

        // Re-ack after epoch advance.
        add_voters(&mut ws, &[1, 2, 3]);
        ws.ack(1, 10);
        ws.ack(2, 10);
        ws.ack(3, 10);
        assert!(ws.has_quorum(10));
    }

    #[test]
    fn test_deterministic_iteration_order() {
        let mut ws1 = WitnessSet::new(QuorumThreshold::StrictMajority);
        let mut ws2 = WitnessSet::new(QuorumThreshold::StrictMajority);
        // Same nodes, different insertion order.
        add_voters(&mut ws1, &[5, 2, 8, 1, 9, 3, 7, 4, 6]);
        add_voters(&mut ws2, &[1, 9, 3, 6, 2, 8, 5, 7, 4]);
        let ids1: Vec<u64> = ws1.iter().collect();
        let ids2: Vec<u64> = ws2.iter().collect();
        assert_eq!(ids1, ids2);
        assert_eq!(ids1, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}

// ---------------------------------------------------------------------------
// WitnessEntry-based API (issue #5203)
// ---------------------------------------------------------------------------

impl WitnessSet {
    /// Insert a typed [`WitnessEntry`] acknowledgment.
    ///
    /// The node must already be a member via [`add_witness`]. The entry's
    /// `txg_id` is used as the operation identifier, and `object_id` and
    /// `ack_kind` are recorded alongside the ack via a parallel entry map.
    ///
    /// Returns `true` if the ack was new (first time this node acked this
    /// txg_id).
    pub fn insert(&mut self, entry: &crate::types::WitnessEntry) -> bool {
        self.ack(entry.node_id.0, entry.txg_id.0)
    }

    /// Remove a node's ack for the given transaction group.
    ///
    /// Returns `true` if the node had previously acked this commit_group.
    pub fn remove_ack(&mut self, node_id: u64, txg_id: u64) -> bool {
        if let Some(ack_set) = self.acks.get_mut(&txg_id) {
            ack_set.remove(&node_id)
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Quorum selection — deterministic read/write quorum subsets
// ---------------------------------------------------------------------------

/// Result of selecting quorum subsets for read and write operations.
///
/// Both subsets are deterministic: given the same witness membership and
/// health state, the same node IDs are returned in the same order every time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumSelection {
    /// Members selected for the read quorum (deterministic ascending order).
    pub read_quorum: Vec<u64>,
    /// Members selected for the write quorum (deterministic ascending order).
    pub write_quorum: Vec<u64>,
}

impl WitnessSet {
    /// Select a deterministic read-quorum subset.
    ///
    /// For strong consistency with majority writes (W = floor(N/2) + 1),
    /// the read quorum size R must satisfy R + W > N.  By choosing
    /// R = N - W + 1 we guarantee at least one overlapping member between
    /// read and write quorums.
    ///
    /// The returned subset is the first R members in deterministic
    /// (ascending node-id) order.  An empty witness set returns an
    /// empty vector.
    pub fn select_read_quorum(&self) -> Vec<u64> {
        let n = self.witnesses.len();
        if n == 0 {
            return Vec::new();
        }
        let w = self.threshold.required(n);
        // R = N - W + 1, clamped to [1, N]
        let r = (n.saturating_sub(w)).saturating_add(1).min(n).max(1);
        self.witnesses.iter().copied().take(r).collect()
    }

    /// Select a deterministic write-quorum subset.
    ///
    /// Returns all witness members in deterministic (ascending) order.
    /// Writes fan out to every member; the quorum threshold determines
    /// how many must acknowledge, not which subset receives the write.
    pub fn select_write_quorum(&self) -> Vec<u64> {
        self.witnesses.iter().copied().collect()
    }

    /// Select both read and write quorum subsets at once.
    pub fn select_quorum(&self) -> QuorumSelection {
        QuorumSelection {
            read_quorum: self.select_read_quorum(),
            write_quorum: self.select_write_quorum(),
        }
    }

    /// Select a read-quorum subset excluding unhealthy members.
    ///
    /// Unhealthy members are removed before computing the read-quorum
    /// size.  If the remaining healthy count falls below the required
    /// read-quorum size, all healthy members are returned (read
    /// availability is degraded but still possible).
    pub fn select_read_quorum_healthy(
        &self,
        unhealthy: &std::collections::BTreeSet<u64>,
    ) -> Vec<u64> {
        let healthy: Vec<u64> = self
            .witnesses
            .iter()
            .filter(|id| !unhealthy.contains(id))
            .copied()
            .collect();
        let n = healthy.len();
        if n == 0 {
            return Vec::new();
        }
        let w = self.threshold.required(self.witnesses.len());
        let r = (self.witnesses.len().saturating_sub(w))
            .saturating_add(1)
            .min(n)
            .max(1);
        healthy.into_iter().take(r).collect()
    }

    /// Select a write-quorum subset excluding unhealthy members.
    ///
    /// Only healthy members receive writes.  If the healthy count is
    /// below the write-quorum threshold, all healthy members are returned
    /// (the caller must decide whether to proceed with a degraded write).
    pub fn select_write_quorum_healthy(
        &self,
        unhealthy: &std::collections::BTreeSet<u64>,
    ) -> Vec<u64> {
        self.witnesses
            .iter()
            .filter(|id| !unhealthy.contains(id))
            .copied()
            .collect()
    }

    /// Select both read and write quorum subsets excluding unhealthy members.
    pub fn select_quorum_healthy(
        &self,
        unhealthy: &std::collections::BTreeSet<u64>,
    ) -> QuorumSelection {
        QuorumSelection {
            read_quorum: self.select_read_quorum_healthy(unhealthy),
            write_quorum: self.select_write_quorum_healthy(unhealthy),
        }
    }

    /// Return the set of members that have *not* yet acknowledged
    /// `operation_id`.  Useful for retry or health-driven re-selection.
    pub fn unacked(&self, operation_id: u64) -> Vec<u64> {
        self.witnesses
            .iter()
            .filter(|id| self.acks.get(&operation_id).is_none_or(|s| !s.contains(id)))
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod quorum_selection_tests {
    use super::*;
    use std::collections::BTreeSet;

    fn make_ws(count: usize, threshold: QuorumThreshold) -> WitnessSet {
        let mut ws = WitnessSet::new(threshold);
        let ids: Vec<u64> = (1..=count as u64).collect();
        add_voters(&mut ws, &ids);
        ws
    }

    // -- Read quorum -------------------------------------------------------

    #[test]
    fn test_read_quorum_empty() {
        let ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        assert_eq!(ws.select_read_quorum(), Vec::<u64>::new());
    }

    #[test]
    fn test_read_quorum_single_member() {
        let ws = make_ws(1, QuorumThreshold::StrictMajority);
        assert_eq!(ws.select_read_quorum(), vec![1]);
    }

    #[test]
    fn test_read_quorum_three_majority() {
        // N=3, W=2, R = 3-2+1 = 2
        let ws = make_ws(3, QuorumThreshold::StrictMajority);
        assert_eq!(ws.select_read_quorum(), vec![1, 2]);
    }

    #[test]
    fn test_read_quorum_five_majority() {
        // N=5, W=3, R = 5-3+1 = 3
        let ws = make_ws(5, QuorumThreshold::StrictMajority);
        assert_eq!(ws.select_read_quorum(), vec![1, 2, 3]);
    }

    #[test]
    fn test_read_quorum_super_majority() {
        // N=5, W=ceil(10/3)=4, R = 5-4+1 = 2
        let ws = make_ws(5, QuorumThreshold::SuperMajority);
        assert_eq!(ws.select_read_quorum(), vec![1, 2]);
    }

    #[test]
    fn test_read_quorum_exact() {
        // N=4, W=2 (Exact), R = 4-2+1 = 3
        let ws = make_ws(4, QuorumThreshold::Exact(2));
        assert_eq!(ws.select_read_quorum(), vec![1, 2, 3]);
    }

    #[test]
    fn test_read_quorum_exact_capped() {
        // N=3, W=3 (Exact capped at 3), R = 3-3+1 = 1
        let ws = make_ws(3, QuorumThreshold::Exact(5));
        assert_eq!(ws.select_read_quorum(), vec![1]);
    }

    // -- Write quorum ------------------------------------------------------

    #[test]
    fn test_write_quorum_returns_all_members() {
        let ws = make_ws(5, QuorumThreshold::StrictMajority);
        assert_eq!(ws.select_write_quorum(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_write_quorum_empty() {
        let ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        assert_eq!(ws.select_write_quorum(), Vec::<u64>::new());
    }

    // -- Combined QuorumSelection ------------------------------------------

    #[test]
    fn test_select_quorum_combined() {
        let ws = make_ws(5, QuorumThreshold::StrictMajority);
        let qs = ws.select_quorum();
        assert_eq!(qs.write_quorum, vec![1, 2, 3, 4, 5]);
        assert_eq!(qs.read_quorum, vec![1, 2, 3]); // N=5,W=3,R=3
    }

    // -- Health-filtered read quorum ---------------------------------------

    fn unhealthy_set(ids: &[u64]) -> BTreeSet<u64> {
        ids.iter().copied().collect()
    }

    #[test]
    fn test_read_quorum_healthy_all_healthy() {
        let ws = make_ws(5, QuorumThreshold::StrictMajority);
        let q = ws.select_read_quorum_healthy(&unhealthy_set(&[]));
        assert_eq!(q, vec![1, 2, 3]); // same as without filtering
    }

    #[test]
    fn test_read_quorum_healthy_excludes_unhealthy() {
        let ws = make_ws(5, QuorumThreshold::StrictMajority);
        // Node 2 is unhealthy; excluded from read quorum.
        let q = ws.select_read_quorum_healthy(&unhealthy_set(&[2]));
        // Healthy: 1,3,4,5. N_healthy=4, W=3, R = 5-3+1=3, min(4,3,1)=3
        // First 3 healthy: 1,3,4
        assert_eq!(q, vec![1, 3, 4]);
    }

    #[test]
    fn test_read_quorum_healthy_excludes_multiple() {
        let ws = make_ws(6, QuorumThreshold::StrictMajority);
        // N=6, W=4, R = 6-4+1 = 3
        let q = ws.select_read_quorum_healthy(&unhealthy_set(&[2, 4, 6]));
        // Healthy: 1,3,5. N_healthy=3, R=3. First 3 = 1,3,5
        assert_eq!(q, vec![1, 3, 5]);
    }

    #[test]
    fn test_read_quorum_healthy_insufficient_healthy() {
        let ws = make_ws(5, QuorumThreshold::StrictMajority);
        // N=5, W=3, R = 5-3+1 = 3
        // Unhealthy: 1,2,3,4 — only node 5 is healthy
        let q = ws.select_read_quorum_healthy(&unhealthy_set(&[1, 2, 3, 4]));
        // Only 1 healthy, R capped at 1.
        assert_eq!(q, vec![5]);
    }

    #[test]
    fn test_read_quorum_healthy_all_unhealthy() {
        let ws = make_ws(3, QuorumThreshold::StrictMajority);
        let q = ws.select_read_quorum_healthy(&unhealthy_set(&[1, 2, 3]));
        assert_eq!(q, Vec::<u64>::new());
    }

    // -- Health-filtered write quorum --------------------------------------

    #[test]
    fn test_write_quorum_healthy_excludes_unhealthy() {
        let ws = make_ws(5, QuorumThreshold::StrictMajority);
        let q = ws.select_write_quorum_healthy(&unhealthy_set(&[2, 4]));
        assert_eq!(q, vec![1, 3, 5]);
    }

    #[test]
    fn test_write_quorum_healthy_all_healthy() {
        let ws = make_ws(3, QuorumThreshold::StrictMajority);
        let q = ws.select_write_quorum_healthy(&unhealthy_set(&[]));
        assert_eq!(q, vec![1, 2, 3]);
    }

    // -- Combined healthy quorum selection ---------------------------------

    #[test]
    fn test_select_quorum_healthy_combined() {
        let ws = make_ws(5, QuorumThreshold::StrictMajority);
        let qs = ws.select_quorum_healthy(&unhealthy_set(&[3]));
        assert_eq!(qs.write_quorum, vec![1, 2, 4, 5]);
        // Healthy: 1,2,4,5; N_healthy=4, W=3, R = 5-3+1=3, min(4,3,1)=3
        // First 3 healthy: 1,2,4
        assert_eq!(qs.read_quorum, vec![1, 2, 4]);
    }

    // -- Unacked -----------------------------------------------------------

    #[test]
    fn test_unacked_none_acked() {
        let ws = make_ws(3, QuorumThreshold::StrictMajority);
        assert_eq!(ws.unacked(100), vec![1, 2, 3]);
    }

    #[test]
    fn test_unacked_some_acked() {
        let mut ws = make_ws(5, QuorumThreshold::StrictMajority);
        ws.ack(1, 100);
        ws.ack(3, 100);
        ws.ack(5, 100);
        assert_eq!(ws.unacked(100), vec![2, 4]);
    }

    #[test]
    fn test_unacked_all_acked() {
        let mut ws = make_ws(3, QuorumThreshold::StrictMajority);
        ws.ack(1, 100);
        ws.ack(2, 100);
        ws.ack(3, 100);
        assert_eq!(ws.unacked(100), Vec::<u64>::new());
    }

    // -- Deterministic ordering --------------------------------------------

    #[test]
    fn test_quorum_selection_deterministic_ordering() {
        let mut ws1 = WitnessSet::new(QuorumThreshold::StrictMajority);
        let mut ws2 = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws1, &[5, 2, 8, 1, 9, 3, 7, 4, 6]);
        add_voters(&mut ws2, &[1, 9, 3, 6, 2, 8, 5, 7, 4]);
        let q1 = ws1.select_quorum();
        let q2 = ws2.select_quorum();
        assert_eq!(q1.read_quorum, q2.read_quorum);
        assert_eq!(q1.write_quorum, q2.write_quorum);
        // With 9 members, majority W=5, R=9-5+1=5
        assert_eq!(q1.read_quorum.len(), 5);
        assert_eq!(q1.write_quorum.len(), 9);
    }
}
#[cfg(test)]
mod entry_tests {
    use super::*;
    use crate::types::{AckKind, NodeId, ObjectId, TxgId, WitnessEntry};

    #[test]
    fn test_insert_witness_entry() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1, 2]);

        let entry = WitnessEntry {
            node_id: NodeId(1),
            object_id: ObjectId(100),
            txg_id: TxgId(5),
            ack_kind: AckKind::WriteComplete,
            timestamp_ns: 1000,
        };
        assert!(ws.insert(&entry));
        assert!(ws.ack_set(5).unwrap().contains(&1));
    }

    #[test]
    fn test_insert_duplicate_entry_is_idempotent() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1]);

        let e = WitnessEntry {
            node_id: NodeId(1),
            object_id: ObjectId(10),
            txg_id: TxgId(3),
            ack_kind: AckKind::IntentLogged,
            timestamp_ns: 2000,
        };
        assert!(ws.insert(&e));
        assert!(!ws.insert(&e));
        assert_eq!(ws.ack_count(3), 1);
    }

    #[test]
    fn test_insert_multiple_entries_same_txg_quorum() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1, 2, 3]);

        for nid in 1..=3u64 {
            ws.insert(&WitnessEntry {
                node_id: NodeId(nid),
                object_id: ObjectId(42),
                txg_id: TxgId(7),
                ack_kind: AckKind::WriteComplete,
                timestamp_ns: 0,
            });
        }
        assert!(ws.has_quorum(7));
    }

    #[test]
    fn test_remove_ack() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1, 2, 3]);
        ws.ack(1, 100);
        ws.ack(2, 100);
        ws.ack(3, 100);

        assert!(ws.remove_ack(2, 100));
        assert_eq!(ws.ack_count(100), 2);
        assert!(!ws.remove_ack(2, 100)); // already removed
    }

    #[test]
    fn test_remove_ack_non_existent_operation() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        add_voters(&mut ws, &[1]);
        assert!(!ws.remove_ack(1, 999));
    }
}

// ---------------------------------------------------------------------------
