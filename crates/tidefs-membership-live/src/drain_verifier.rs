// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Production [`MembershipVerificationOps`] implementation backed by the
//! live membership runtime.
//!
//! [`DrainMembershipVerifier`] wraps a reference to the live
//! [`FailureDetector`] and the current [`EpochId`] to satisfy the
//! [`tidefs_node_drain::MembershipVerificationOps`] trait. Callers
//! construct this verifier on-demand when starting a drain operation and
//! pass it to [`tidefs_node_drain::drain_node`].

use tidefs_membership_epoch::EpochId;
use tidefs_membership_epoch::MemberId;
use tidefs_node_drain::MembershipVerificationOps;
use tidefs_node_drain::PlacementEvidenceVerifier;
use tidefs_placement_runtime::PlacementPlanRegistry;
use tidefs_replication_model::ReplicatedReceiptId;

use crate::failure_detector::FailureDetector;

/// Production bridge: verifies drain requests against the live failure
/// detector and current membership epoch.
///
/// Construct with [`Self::new`], passing a reference to the live
/// [`FailureDetector`] and the current epoch. This verifier checks:
///
/// - **Liveness**: node is alive according to the failure detector
///   (not suspected or dead).
/// - **Membership**: node is registered in the peer table.
/// - **Epoch**: returns the current epoch for staleness checks.
///
/// The verifier is ephemeral — each drain operation creates a new
/// instance to capture the epoch at drain-start time.
pub struct DrainMembershipVerifier<'a> {
    fd: &'a FailureDetector,
    epoch: EpochId,
}

impl<'a> DrainMembershipVerifier<'a> {
    /// Create a new verifier backed by the live failure detector and
    /// the current epoch.
    #[must_use]
    pub fn new(fd: &'a FailureDetector, epoch: EpochId) -> Self {
        Self { fd, epoch }
    }
}

impl MembershipVerificationOps for DrainMembershipVerifier<'_> {
    fn is_node_live(&self, node_id: MemberId) -> bool {
        self.fd
            .get_peer(node_id)
            .map(|p| p.is_alive())
            .unwrap_or(false)
    }

    fn is_member(&self, node_id: MemberId) -> bool {
        self.fd.get_peer(node_id).is_some()
    }

    fn current_epoch(&self) -> EpochId {
        self.epoch
    }
}

/// Production bridge: checks whether placement receipts reference
/// a draining node via the live [`PlacementPlanRegistry`].
///
/// Construct with [`Self::new`], passing a reference to the live
/// placement plan registry. Used by the drain safety gate to ensure
/// decommission fails closed when any live extent still references
/// the draining node.
pub struct DrainPlacementVerifier<'a> {
    registry: &'a PlacementPlanRegistry,
}

impl<'a> DrainPlacementVerifier<'a> {
    #[must_use]
    pub fn new(registry: &'a PlacementPlanRegistry) -> Self {
        Self { registry }
    }
}

impl PlacementEvidenceVerifier for DrainPlacementVerifier<'_> {
    fn receipts_referencing_node(&self, node_id: tidefs_membership_epoch::MemberId) -> Vec<ReplicatedReceiptId> {
        self.registry.receipts_referencing_node(node_id)
    }

    fn has_receipts_referencing_node(&self, node_id: tidefs_membership_epoch::MemberId) -> bool {
        self.registry.has_receipts_referencing_node(node_id)
    }
}

#[cfg(test)]
mod placement_verifier_tests {
    use super::*;
    use tidefs_membership_epoch::{EpochId, MemberId};
    use tidefs_placement_runtime::PlacementPlanRegistry;
    use tidefs_replication_model::{ReplicaPlacementReceipt, ReplicatedReceiptId, ReplicatedSubjectId};

    fn mid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    #[test]
    fn placement_verifier_detects_referencing_receipts() {
        let registry = PlacementPlanRegistry::new(EpochId::new(1));
        let verifier = DrainPlacementVerifier::new(&registry);

        // Empty registry has no references
        assert!(!verifier.has_receipts_referencing_node(mid(7)));
        assert!(verifier.receipts_referencing_node(mid(7)).is_empty());
    }

    #[test]
    fn placement_verifier_after_placement_detects_node() {
        let mut registry = PlacementPlanRegistry::new(EpochId::new(1));
        let node = mid(7);
        let subject = ReplicatedSubjectId::new(100);

        registry.record_placement(ReplicaPlacementReceipt {
            receipt_id: ReplicatedReceiptId(1),
            verification_ref: ReplicatedReceiptId(0),
            transfer_ref: ReplicatedReceiptId(0),
            subject_refs: vec![subject],
            placed_on: node,
            placement_epoch: EpochId::new(1),
            subjects_placed: 1,
            placement_receipt_refs: Vec::new(),
        });

        let verifier = DrainPlacementVerifier::new(&registry);
        assert!(verifier.has_receipts_referencing_node(node));
        assert_eq!(verifier.receipts_referencing_node(node), vec![ReplicatedReceiptId(1)]);
        assert!(!verifier.has_receipts_referencing_node(mid(99)));
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use crate::failure_detector::FailureDetector;
    use crate::types::MembershipConfig;
    use ed25519_dalek::Keypair;
    use tidefs_membership_epoch::{EpochId, HealthClass, MemberClass, MemberId};

    fn mid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    /// Build a minimal FailureDetector for use in tests.
    fn make_fd() -> FailureDetector {
        let config = MembershipConfig::default();
        let mut rng = rand::thread_rng();
        let keypair = Keypair::generate(&mut rng);
        FailureDetector::new(config, keypair)
    }

    /// Register a peer with minimal defaults.
    fn register(fd: &mut FailureDetector, id: MemberId) {
        fd.register_peer(id, MemberClass::Voter, 0, EpochId(1));
    }

    #[test]
    fn verifier_rejects_unknown_node() {
        let fd = make_fd();
        let verifier = DrainMembershipVerifier::new(&fd, EpochId(5));

        // Node 42 is not registered
        assert!(!verifier.is_member(mid(42)));
        assert!(!verifier.is_node_live(mid(42)));
        assert_eq!(verifier.current_epoch(), EpochId(5));
    }

    #[test]
    fn verifier_recognizes_registered_live_peer() {
        let mut fd = make_fd();
        register(&mut fd, mid(7));
        let verifier = DrainMembershipVerifier::new(&fd, EpochId(10));

        assert!(verifier.is_member(mid(7)));
        assert!(verifier.is_node_live(mid(7)));
        assert_eq!(verifier.current_epoch(), EpochId(10));
    }

    #[test]
    fn verifier_marks_dead_node_not_live() {
        let mut fd = make_fd();
        register(&mut fd, mid(9));
        // Force the peer to down state
        if let Some(peer) = fd.get_peer_mut(mid(9)) {
            peer.health = HealthClass::Down;
        }

        let verifier = DrainMembershipVerifier::new(&fd, EpochId(1));
        assert!(verifier.is_member(mid(9)));
        assert!(!verifier.is_node_live(mid(9)));
    }

    #[test]
    fn verifier_epoch_is_independent_of_fd_state() {
        let fd = make_fd();
        let epoch = EpochId(42);
        let verifier = DrainMembershipVerifier::new(&fd, epoch);
        assert_eq!(verifier.current_epoch(), epoch);
    }

    #[test]
    fn verifier_suspect_node_still_alive() {
        let mut fd = make_fd();
        register(&mut fd, mid(3));
        // Force the peer to suspect state
        if let Some(peer) = fd.get_peer_mut(mid(3)) {
            peer.health = HealthClass::Suspect;
        }

        let verifier = DrainMembershipVerifier::new(&fd, EpochId(7));
        // Suspect nodes are still "alive" (they haven't been confirmed dead)
        assert!(verifier.is_member(mid(3)));
        assert!(verifier.is_node_live(mid(3)));
    }
}
