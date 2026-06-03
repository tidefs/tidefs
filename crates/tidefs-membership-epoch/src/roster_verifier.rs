//! Membership roster verification trait for transport session gating.
//!
//! [`MembershipRosterVerifier`] provides the interface that the transport
//! layer uses during inbound session establishment to check whether a
//! connecting peer is present in the current committed membership roster.
//!
//! # Architecture
//!
//! The trait lives in `tidefs-membership-epoch` so the verification contract
//! is defined by the membership layer. Transport depends on this trait
//! (clean dependency direction) and calls it after the connection handshake
//! completes but before message dispatch begins.
//!
//! # Integration
//!
//! ```ignore
//! use tidefs_membership_live::roster_verifier::MembershipRosterVerifier;
//!
//! // In the transport accept loop:
//! let peer_id = handshake_result.peer_id;
//! match roster_verifier.is_member(peer_id) {
//!     true => { /* proceed to epoch-version exchange and message dispatch */ }
//!     false => { /* reject connection */ }
//! }
//! ```

use crate::MemberId;

// ---------------------------------------------------------------------------
// MembershipRosterVerifier
// ---------------------------------------------------------------------------

/// Verifies whether a peer is present in the current committed membership
/// roster.
///
/// Implementations query the live roster (typically a
/// [`crate::roster::MembershipRoster`]) and return a boolean indicating
/// membership. The transport layer calls this during inbound session
/// establishment to gate connections before allowing message exchange.
///
/// # Thread safety
///
/// Implementations must be `Send + Sync` so they can be shared across
/// transport accept tasks.
pub trait MembershipRosterVerifier: Send + Sync {
    /// Check whether a peer, identified by its node GUID, is present in
    /// the current committed roster.
    ///
    /// Returns `true` if the peer is a member in good standing (Alive
    /// or Suspected state). Returns `false` if the peer is not in the
    /// roster, is Drained, or has Failed.
    fn is_member(&self, peer_id: MemberId) -> bool;

    /// Return the current committed epoch number.
    ///
    /// Used during the epoch-version exchange that follows roster
    /// verification. The transport accept loop sends this epoch in its
    /// [`crate::epoch_version_exchange::EpochVersionMessage`]
    /// and compares the remote peer's epoch to detect catch-up needs.
    fn current_epoch(&self) -> u64;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock verifier that uses an in-memory member set and epoch number.
    struct MockRosterVerifier {
        members: Vec<MemberId>,
        epoch: u64,
    }

    impl MockRosterVerifier {
        fn new(members: Vec<u64>, epoch: u64) -> Self {
            Self {
                members: members.into_iter().map(MemberId::new).collect(),
                epoch,
            }
        }
    }

    impl MembershipRosterVerifier for MockRosterVerifier {
        fn is_member(&self, peer_id: MemberId) -> bool {
            self.members.contains(&peer_id)
        }

        fn current_epoch(&self) -> u64 {
            self.epoch
        }
    }

    // ---- is_member ----

    #[test]
    fn member_present_in_roster() {
        let verifier = MockRosterVerifier::new(vec![1, 2, 3], 5);
        assert!(verifier.is_member(MemberId::new(1)));
        assert!(verifier.is_member(MemberId::new(2)));
        assert!(verifier.is_member(MemberId::new(3)));
    }

    #[test]
    fn non_member_rejected() {
        let verifier = MockRosterVerifier::new(vec![1, 2], 5);
        assert!(!verifier.is_member(MemberId::new(3)));
        assert!(!verifier.is_member(MemberId::new(42)));
    }

    #[test]
    fn empty_roster_rejects_all() {
        let verifier = MockRosterVerifier::new(vec![], 0);
        assert!(!verifier.is_member(MemberId::new(1)));
        assert!(!verifier.is_member(MemberId::new(0)));
    }

    #[test]
    fn single_member_roster() {
        let verifier = MockRosterVerifier::new(vec![42], 1);
        assert!(verifier.is_member(MemberId::new(42)));
        assert!(!verifier.is_member(MemberId::new(41)));
        assert!(!verifier.is_member(MemberId::new(43)));
    }

    // ---- current_epoch ----

    #[test]
    fn current_epoch_returns_configured_value() {
        let verifier = MockRosterVerifier::new(vec![1], 7);
        assert_eq!(verifier.current_epoch(), 7);
    }

    #[test]
    fn current_epoch_zero() {
        let verifier = MockRosterVerifier::new(vec![], 0);
        assert_eq!(verifier.current_epoch(), 0);
    }

    // ---- trait object safety ----

    #[test]
    fn trait_object_usable() {
        let verifier: Box<dyn MembershipRosterVerifier> =
            Box::new(MockRosterVerifier::new(vec![10, 20], 3));
        assert!(verifier.is_member(MemberId::new(10)));
        assert!(!verifier.is_member(MemberId::new(30)));
        assert_eq!(verifier.current_epoch(), 3);
    }
}
