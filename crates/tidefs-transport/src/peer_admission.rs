//! Peer admission control gated by membership epoch member set.
//!
//! [`AdmissionGate`] consults the current membership epoch member set
//! from [`tidefs_membership_epoch::EpochMemberSet`] during transport
//! connection establishment, rejecting connections from peers not
//! present in the current epoch or in non-active member states.
//!
//! # Architecture
//!
//! - [`AdmissionGate`]: Holds the current epoch number, the epoch
//!   member set, and sets of non-active peers (Draining, Drained,
//!   Failed). Every [`admit`](AdmissionGate::admit) call checks the
//!   peer against these sets.
//! - [`AdmittedPeer`]: Returned on successful admission, carrying the
//!   peer's identity and the epoch stamp under which admission was
//!   granted. Downstream routing and message dispatch use this for
//!   epoch-bound authorization.
//! - [`AdmissionError`]: Enumerates rejection reasons: `NotAMember`,
//!   `Draining`, `Drained`, `Failed`, and `EpochAdvanced` for the
//!   epoch-generation stamp race.
//! - [`EpochStamp`]: A generation counter carried by in-flight
//!   connection attempts. When the handshake completes, the stamp is
//!   checked against the current epoch; if the epoch has advanced
//!   past the stamp, the connection is rejected.
//!
//! # Epoch-generation stamp race
//!
//! A connection attempt may begin under epoch N but complete under
//! epoch N+1 (or later). If the peer was evicted from the member set
//! by epoch N+1, admitting it under epoch N's rules is incorrect.
//! The [`EpochStamp`] mechanism captures the epoch at connection
//! initiation and rejects connections whose stamp is behind the
//! current epoch.
//!
//! # Integration point
//!
//! In the transport accept loop, after the join handshake (#5782)
//! establishes peer identity:
//!
//! ```text
//! let stamp = admission_gate.current_stamp();
//! let (conn, peer_addr) = backend.accept()?;
//! let peer_id = handshake(&mut conn, &stamp)?;
//! let admitted = admission_gate.admit_with_stamp(peer_id, &stamp)?;
//! ```
//!
//! The [`AdmissionGate`] is updated on every epoch transition via
//! [`update_epoch`](AdmissionGate::update_epoch), receiving the new
//! member set and sets of non-active peers from the membership layer.

use std::collections::BTreeSet;
use tidefs_membership_epoch::EpochMemberSet;

// ---------------------------------------------------------------------------
// EpochStamp
// ---------------------------------------------------------------------------

/// An epoch-generation stamp captured at connection initiation.
///
/// When a connection attempt begins, the transport accept loop captures
/// a stamp representing the current epoch. After the handshake completes,
/// the stamp is validated against the admission gate's current epoch.
/// If the epoch has advanced past the stamp, the connection is rejected
/// -- the peer may no longer be a member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochStamp {
    /// The epoch number at the time the stamp was issued.
    epoch: u64,
}

/// The captured epoch stamp does not match the current membership epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochStampMismatch;

impl EpochStamp {
    /// Create a new stamp for the given epoch.
    #[must_use]
    pub fn new(epoch: u64) -> Self {
        Self { epoch }
    }

    /// Return the epoch number this stamp represents.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Validate this stamp against a current epoch.
    ///
    /// Returns `Ok(())` if the stamp epoch equals the current epoch.
    /// Returns `Err(EpochStampMismatch)` if the epoch has advanced past the stamp.
    pub fn validate(&self, current_epoch: u64) -> Result<(), EpochStampMismatch> {
        if self.epoch == current_epoch {
            Ok(())
        } else {
            Err(EpochStampMismatch)
        }
    }
}

// ---------------------------------------------------------------------------
// AdmissionError
// ---------------------------------------------------------------------------

/// Why a peer was rejected at the admission gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// The peer is not present in the current epoch member set.
    NotAMember,
    /// The peer is in a Draining state and not accepting new connections.
    Draining,
    /// The peer has been fully drained from the cluster.
    Drained,
    /// The peer has been confirmed failed.
    Failed,
    /// The epoch advanced past the stamp under which the connection was
    /// initiated, so the admission decision is stale. The caller should
    /// retry with a fresh stamp.
    EpochAdvanced {
        /// The epoch that was stamped at initiation time.
        stamped_epoch: u64,
        /// The current epoch at validation time.
        current_epoch: u64,
    },
}

impl AdmissionError {
    /// Returns `true` for errors the caller can recover from by retrying.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, AdmissionError::EpochAdvanced { .. })
    }
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionError::NotAMember => write!(f, "peer is not a member of the current epoch"),
            AdmissionError::Draining => write!(f, "peer is in Draining state"),
            AdmissionError::Drained => write!(f, "peer has been drained from the cluster"),
            AdmissionError::Failed => write!(f, "peer has been confirmed failed"),
            AdmissionError::EpochAdvanced {
                stamped_epoch,
                current_epoch,
            } => write!(
                f,
                "epoch advanced from {stamped_epoch} to {current_epoch} during connection establishment"
            ),
        }
    }
}

impl std::error::Error for AdmissionError {}

// ---------------------------------------------------------------------------
// AdmittedPeer
// ---------------------------------------------------------------------------

/// A peer that has passed admission control.
///
/// Carries the peer's identity and the epoch stamp under which admission
/// was granted. Downstream subsystems (routing, message dispatch) use
/// this to verify epoch-bound authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedPeer {
    /// The admitted peer's node identifier.
    pub peer_id: u64,
    /// The epoch under which admission was granted.
    pub admitted_epoch: u64,
}

impl AdmittedPeer {
    /// Create a new [`AdmittedPeer`].
    #[must_use]
    pub fn new(peer_id: u64, admitted_epoch: u64) -> Self {
        Self {
            peer_id,
            admitted_epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// AdmissionGate
// ---------------------------------------------------------------------------

/// Peer admission gate that consults the membership epoch member set.
///
/// Holds the current epoch number, the epoch member set (from
/// [`tidefs_membership_epoch::EpochMemberSet`]), and sets of peers
/// in non-active states. Updated on every epoch transition via
/// [`update_epoch`](AdmissionGate::update_epoch).
#[derive(Clone, Debug)]
pub struct AdmissionGate {
    /// The current membership epoch number.
    current_epoch: u64,
    /// The current epoch member set (all active members).
    member_set: EpochMemberSet,
    /// Peers currently in the Draining state.
    draining_peers: BTreeSet<u64>,
    /// Peers that have been fully drained.
    drained_peers: BTreeSet<u64>,
    /// Peers that have been confirmed failed.
    failed_peers: BTreeSet<u64>,
}

impl AdmissionGate {
    /// Create a new admission gate for the given epoch and member set.
    #[must_use]
    pub fn new(current_epoch: u64, member_set: EpochMemberSet) -> Self {
        Self {
            current_epoch,
            member_set,
            draining_peers: BTreeSet::new(),
            drained_peers: BTreeSet::new(),
            failed_peers: BTreeSet::new(),
        }
    }

    /// Return the current epoch number.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Return a reference to the current member set.
    #[must_use]
    pub fn member_set(&self) -> &EpochMemberSet {
        &self.member_set
    }

    /// Issue an [`EpochStamp`] representing the current epoch.
    #[must_use]
    pub fn current_stamp(&self) -> EpochStamp {
        EpochStamp::new(self.current_epoch)
    }

    /// Admit a peer by its node identifier.
    ///
    /// Checks only that the peer is in the current member set and not
    /// in a non-active state. Does NOT verify an epoch stamp.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if the peer is not in the member set
    /// or is in a non-active state.
    pub fn admit(&self, peer_id: u64) -> Result<AdmittedPeer, AdmissionError> {
        self.check_membership(peer_id)?;
        self.check_non_active(peer_id)?;
        Ok(AdmittedPeer::new(peer_id, self.current_epoch))
    }

    /// Admit a peer with epoch-stamp validation.
    ///
    /// After the handshake completes, the captured [`EpochStamp`] is
    /// validated against the current epoch. If the epoch has advanced,
    /// the connection is rejected even if the peer is currently a
    /// member.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::EpochAdvanced`] if the stamp epoch
    /// is behind the current epoch. Otherwise returns the same errors
    /// as [`admit`](Self::admit).
    pub fn admit_with_stamp(
        &self,
        peer_id: u64,
        stamp: &EpochStamp,
    ) -> Result<AdmittedPeer, AdmissionError> {
        if stamp.epoch() != self.current_epoch {
            return Err(AdmissionError::EpochAdvanced {
                stamped_epoch: stamp.epoch(),
                current_epoch: self.current_epoch,
            });
        }
        self.admit(peer_id)
    }

    /// Update the admission gate for a new epoch.
    ///
    /// Replaces the member set and non-active peer sets.
    pub fn update_epoch(
        &mut self,
        new_epoch: u64,
        member_set: EpochMemberSet,
        draining: &BTreeSet<u64>,
        drained: &BTreeSet<u64>,
        failed: &BTreeSet<u64>,
    ) {
        self.current_epoch = new_epoch;
        self.member_set = member_set;
        self.draining_peers = draining.clone();
        self.drained_peers = drained.clone();
        self.failed_peers = failed.clone();
    }

    /// Mark a peer as Draining.
    pub fn set_draining(&mut self, peer_id: u64) {
        self.draining_peers.insert(peer_id);
        self.drained_peers.remove(&peer_id);
        self.failed_peers.remove(&peer_id);
    }

    /// Mark a peer as Drained.
    pub fn set_drained(&mut self, peer_id: u64) {
        self.draining_peers.remove(&peer_id);
        self.drained_peers.insert(peer_id);
        self.failed_peers.remove(&peer_id);
    }

    /// Mark a peer as Failed.
    pub fn set_failed(&mut self, peer_id: u64) {
        self.draining_peers.remove(&peer_id);
        self.drained_peers.remove(&peer_id);
        self.failed_peers.insert(peer_id);
    }

    /// Remove a peer from all non-active sets.
    pub fn clear_non_active(&mut self, peer_id: u64) {
        self.draining_peers.remove(&peer_id);
        self.drained_peers.remove(&peer_id);
        self.failed_peers.remove(&peer_id);
    }

    /// Return the set of draining peer IDs.
    #[must_use]
    pub fn draining_peers(&self) -> &BTreeSet<u64> {
        &self.draining_peers
    }

    /// Return the set of drained peer IDs.
    #[must_use]
    pub fn drained_peers(&self) -> &BTreeSet<u64> {
        &self.drained_peers
    }

    /// Return the set of failed peer IDs.
    #[must_use]
    pub fn failed_peers(&self) -> &BTreeSet<u64> {
        &self.failed_peers
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    fn check_membership(&self, peer_id: u64) -> Result<(), AdmissionError> {
        if self
            .member_set
            .contains(&tidefs_membership_types::NodeIdentity::new(peer_id))
        {
            Ok(())
        } else {
            Err(AdmissionError::NotAMember)
        }
    }

    fn check_non_active(&self, peer_id: u64) -> Result<(), AdmissionError> {
        if self.draining_peers.contains(&peer_id) {
            return Err(AdmissionError::Draining);
        }
        if self.drained_peers.contains(&peer_id) {
            return Err(AdmissionError::Drained);
        }
        if self.failed_peers.contains(&peer_id) {
            return Err(AdmissionError::Failed);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_types::NodeIdentity;

    fn make_gate(epoch: u64, members: &[u64]) -> AdmissionGate {
        let set = EpochMemberSet::new(members.iter().map(|&id| NodeIdentity::new(id)));
        AdmissionGate::new(epoch, set)
    }

    fn make_gate_with_non_active(
        epoch: u64,
        members: &[u64],
        draining: &[u64],
        drained: &[u64],
        failed: &[u64],
    ) -> AdmissionGate {
        let set = EpochMemberSet::new(members.iter().map(|&id| NodeIdentity::new(id)));
        let mut gate = AdmissionGate::new(epoch, set);
        for &id in draining {
            gate.set_draining(id);
        }
        for &id in drained {
            gate.set_drained(id);
        }
        for &id in failed {
            gate.set_failed(id);
        }
        gate
    }

    #[test]
    fn admit_valid_member() {
        let gate = make_gate(5, &[1, 2, 3]);
        let result = gate.admit(2);
        assert!(result.is_ok());
        let admitted = result.unwrap();
        assert_eq!(admitted.peer_id, 2);
        assert_eq!(admitted.admitted_epoch, 5);
    }

    #[test]
    fn reject_non_member() {
        let gate = make_gate(5, &[1, 2]);
        assert_eq!(gate.admit(3).unwrap_err(), AdmissionError::NotAMember);
    }

    #[test]
    fn reject_draining_peer() {
        let gate = make_gate_with_non_active(5, &[1, 2, 3], &[2], &[], &[]);
        assert_eq!(gate.admit(2).unwrap_err(), AdmissionError::Draining);
        assert!(gate.admit(1).is_ok());
        assert!(gate.admit(3).is_ok());
    }

    #[test]
    fn reject_drained_peer() {
        let gate = make_gate_with_non_active(5, &[1, 2], &[], &[2], &[]);
        assert_eq!(gate.admit(2).unwrap_err(), AdmissionError::Drained);
        assert!(gate.admit(1).is_ok());
    }

    #[test]
    fn reject_failed_peer() {
        let gate = make_gate_with_non_active(5, &[1, 2], &[], &[], &[1]);
        assert_eq!(gate.admit(1).unwrap_err(), AdmissionError::Failed);
        assert!(gate.admit(2).is_ok());
    }

    #[test]
    fn admit_with_matching_stamp() {
        let gate = make_gate(5, &[1, 2]);
        let stamp = EpochStamp::new(5);
        let result = gate.admit_with_stamp(1, &stamp);
        assert!(result.is_ok());
    }

    #[test]
    fn reject_when_epoch_advanced() {
        let gate = make_gate(7, &[1, 2]);
        let stamp = EpochStamp::new(5);
        let err = gate.admit_with_stamp(1, &stamp).unwrap_err();
        assert_eq!(
            err,
            AdmissionError::EpochAdvanced {
                stamped_epoch: 5,
                current_epoch: 7
            }
        );
        assert!(err.is_retryable());
    }

    #[test]
    fn epoch_advanced_rejection_even_for_valid_member() {
        let gate = make_gate(7, &[1, 2]);
        let stamp = EpochStamp::new(5);
        assert!(gate.admit_with_stamp(1, &stamp).is_err());
    }

    #[test]
    fn stamp_validation_same_epoch() {
        let stamp = EpochStamp::new(5);
        assert!(stamp.validate(5).is_ok());
    }

    #[test]
    fn stamp_validation_epoch_ahead() {
        let stamp = EpochStamp::new(5);
        assert!(stamp.validate(6).is_err());
    }

    #[test]
    fn stamp_validation_epoch_behind() {
        let stamp = EpochStamp::new(5);
        assert!(stamp.validate(4).is_err());
    }

    #[test]
    fn empty_member_set_rejects_all() {
        let gate = make_gate(0, &[]);
        assert_eq!(gate.admit(1).unwrap_err(), AdmissionError::NotAMember);
        assert_eq!(gate.admit(42).unwrap_err(), AdmissionError::NotAMember);
        assert_eq!(gate.admit(0).unwrap_err(), AdmissionError::NotAMember);
    }

    #[test]
    fn multi_peer_roster_accept_alive_reject_non_active() {
        let gate = make_gate_with_non_active(5, &[1, 2, 3, 4], &[2], &[3], &[4]);
        assert!(gate.admit(1).is_ok());
        assert_eq!(gate.admit(2).unwrap_err(), AdmissionError::Draining);
        assert_eq!(gate.admit(3).unwrap_err(), AdmissionError::Drained);
        assert_eq!(gate.admit(4).unwrap_err(), AdmissionError::Failed);
        assert_eq!(gate.admit(5).unwrap_err(), AdmissionError::NotAMember);
    }

    #[test]
    fn epoch_stamp_construction() {
        let stamp = EpochStamp::new(42);
        assert_eq!(stamp.epoch(), 42);
    }

    #[test]
    fn epoch_stamp_equality() {
        let s1 = EpochStamp::new(5);
        let s2 = EpochStamp::new(5);
        let s3 = EpochStamp::new(6);
        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
    }

    #[test]
    fn current_stamp_matches_epoch() {
        let gate = make_gate(10, &[1]);
        let stamp = gate.current_stamp();
        assert_eq!(stamp.epoch(), 10);
    }

    #[test]
    fn update_epoch_replaces_member_set_and_non_active() {
        let mut gate = make_gate_with_non_active(5, &[1, 2], &[3], &[4], &[]);

        let new_set = EpochMemberSet::new([NodeIdentity::new(10), NodeIdentity::new(20)]);
        let draining = BTreeSet::from([30u64]);
        let drained = BTreeSet::from([40u64]);
        let failed = BTreeSet::from([50u64]);

        gate.update_epoch(6, new_set.clone(), &draining, &drained, &failed);

        assert_eq!(gate.current_epoch(), 6);
        assert!(!gate.draining_peers().contains(&3));
        assert!(!gate.drained_peers().contains(&4));
        assert!(gate.draining_peers().contains(&30));
        assert!(gate.drained_peers().contains(&40));
        assert!(gate.failed_peers().contains(&50));
        assert!(gate.admit(10).is_ok());
        assert!(gate.admit(20).is_ok());
        assert_eq!(gate.admit(1).unwrap_err(), AdmissionError::NotAMember);
    }

    #[test]
    fn set_draining_moves_from_failed() {
        let mut gate = make_gate(5, &[1]);
        gate.set_failed(1);
        assert_eq!(gate.admit(1).unwrap_err(), AdmissionError::Failed);
        gate.set_draining(1);
        assert_eq!(gate.admit(1).unwrap_err(), AdmissionError::Draining);
    }

    #[test]
    fn set_drained_moves_from_draining() {
        let mut gate = make_gate(5, &[1]);
        gate.set_draining(1);
        assert_eq!(gate.admit(1).unwrap_err(), AdmissionError::Draining);
        gate.set_drained(1);
        assert_eq!(gate.admit(1).unwrap_err(), AdmissionError::Drained);
    }

    #[test]
    fn clear_non_active_restores_admission() {
        let mut gate = make_gate(5, &[1]);
        gate.set_failed(1);
        assert!(gate.admit(1).is_err());
        gate.clear_non_active(1);
        assert!(gate.admit(1).is_ok());
    }

    #[test]
    fn non_active_accessors() {
        let mut gate = make_gate(5, &[1, 2, 3]);
        gate.set_draining(1);
        gate.set_drained(2);
        gate.set_failed(3);
        assert!(gate.draining_peers().contains(&1));
        assert!(gate.drained_peers().contains(&2));
        assert!(gate.failed_peers().contains(&3));
    }

    #[test]
    fn admission_error_display() {
        assert!(format!("{}", AdmissionError::NotAMember).contains("not a member"));
        assert!(format!("{}", AdmissionError::Draining).contains("Draining"));
        assert!(format!("{}", AdmissionError::Drained).contains("drained"));
        assert!(format!("{}", AdmissionError::Failed).contains("failed"));
        let s = format!(
            "{}",
            AdmissionError::EpochAdvanced {
                stamped_epoch: 3,
                current_epoch: 5
            }
        );
        assert!(s.contains("epoch advanced"));
        assert!(s.contains("3"));
        assert!(s.contains("5"));
    }

    #[test]
    fn epoch_advanced_is_retryable() {
        assert!(AdmissionError::EpochAdvanced {
            stamped_epoch: 1,
            current_epoch: 2
        }
        .is_retryable());
    }

    #[test]
    fn non_epoch_advanced_errors_are_not_retryable() {
        assert!(!AdmissionError::NotAMember.is_retryable());
        assert!(!AdmissionError::Draining.is_retryable());
        assert!(!AdmissionError::Drained.is_retryable());
        assert!(!AdmissionError::Failed.is_retryable());
    }

    #[test]
    fn admitted_peer_construction() {
        let ap = AdmittedPeer::new(42, 7);
        assert_eq!(ap.peer_id, 42);
        assert_eq!(ap.admitted_epoch, 7);
    }

    #[test]
    fn large_member_set_all_members_admitted() {
        let members: Vec<u64> = (0..100).collect();
        let gate = make_gate(1, &members);
        for id in 0..100 {
            assert!(gate.admit(id).is_ok(), "peer {id} should be admitted");
        }
        assert_eq!(gate.admit(100).unwrap_err(), AdmissionError::NotAMember);
    }
}
