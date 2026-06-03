#![forbid(unsafe_code)]

//! Structural constraint validation for membership roster changes.
//!
//! [`RosterConstraints`] defines the bounds within which a roster must
//! operate: a maximum peer count and a minimum number of peers required
//! to sustain quorum. The validation functions check proposed add and
//! remove operations against these constraints before the coordinator
//! records a transition journal entry or solicits quorum votes.
//!
//! ## Validation Rules
//!
//! | Function | Checks |
//! |----------|--------|
//! | [`validate_add_peer`] | PeerAlreadyPresent, TooManyPeers |
//! | [`validate_remove_peer`] | PeerNotFound, QuorumLost |
//! | [`validate_roster_invariants`] | DuplicatePeer, TooManyPeers, QuorumLost |
//!
//! ## Integration
//!
//! Callers (typically the coordinator transition journal prepare path)
//! invoke the appropriate validation function before recording a
//! transition. The journal's [`record_prepare_with_constraints`] method
//! wraps this as a single call.
//!
//! The validation functions are pure (no I/O, no allocation beyond the
//! error value) and run in O(N) time where N is the roster size.

use crate::MemberId;
use std::fmt;

// ── RosterConstraints ────────────────────────────────────────────────

/// Configuration for roster constraint validation.
///
/// Defines the structural bounds a roster must satisfy: a ceiling on
/// the total number of peers and a floor on the number of peers needed
/// to form a quorum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterConstraints {
    /// Maximum number of peers allowed in the roster.
    pub max_peers: usize,
    /// Minimum number of peers required to sustain quorum.
    ///
    /// Removing a peer must not drop the roster below this count.
    /// Roster-invariant checks also enforce that an existing roster
    /// meets this minimum.
    pub min_peers_for_quorum: usize,
}

impl Default for RosterConstraints {
    fn default() -> Self {
        Self {
            max_peers: 64,
            min_peers_for_quorum: 1,
        }
    }
}

impl RosterConstraints {
    /// Create constraints with the given bounds.
    #[must_use]
    pub const fn new(max_peers: usize, min_peers_for_quorum: usize) -> Self {
        Self {
            max_peers,
            min_peers_for_quorum,
        }
    }
}

// ── ConstraintValidationError ────────────────────────────────────────

/// Errors returned by roster constraint validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstraintValidationError {
    /// Removing the peer would cause the roster to drop below the
    /// minimum quorum threshold.
    QuorumLost,
    /// Adding the peer would exceed the maximum peer limit.
    TooManyPeers,
    /// The roster contains duplicate peer identifiers (invariant
    /// violation detected by [`validate_roster_invariants`]).
    DuplicatePeer,
    /// The peer targeted for removal is not present in the roster.
    PeerNotFound,
    /// The peer being added is already present in the roster.
    PeerAlreadyPresent,
}

impl fmt::Display for ConstraintValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QuorumLost => write!(f, "removal would lose quorum"),
            Self::TooManyPeers => write!(f, "addition would exceed max peers"),
            Self::DuplicatePeer => write!(f, "roster contains duplicate peer"),
            Self::PeerNotFound => write!(f, "peer not found in roster"),
            Self::PeerAlreadyPresent => write!(f, "peer already present in roster"),
        }
    }
}

// ── Validation Functions ─────────────────────────────────────────────

/// Validate adding `new_peer` to `current_roster`.
///
/// # Errors
///
/// * [`ConstraintValidationError::PeerAlreadyPresent`] if `new_peer`
///   already appears in `current_roster`.
/// * [`ConstraintValidationError::TooManyPeers`] if the roster would
///   exceed `constraints.max_peers` after addition.
pub fn validate_add_peer(
    current_roster: &[MemberId],
    new_peer: MemberId,
    constraints: &RosterConstraints,
) -> Result<(), ConstraintValidationError> {
    // Check if peer already exists
    for p in current_roster {
        if *p == new_peer {
            return Err(ConstraintValidationError::PeerAlreadyPresent);
        }
    }

    // Check if adding would exceed max peers
    if current_roster.len() >= constraints.max_peers {
        return Err(ConstraintValidationError::TooManyPeers);
    }

    Ok(())
}

/// Validate removing `departing_peer_id` from `current_roster`.
///
/// # Errors
///
/// * [`ConstraintValidationError::PeerNotFound`] if `departing_peer_id`
///   is not present in `current_roster`.
/// * [`ConstraintValidationError::QuorumLost`] if the roster would drop
///   below `constraints.min_peers_for_quorum` after removal.
pub fn validate_remove_peer(
    current_roster: &[MemberId],
    departing_peer_id: MemberId,
    constraints: &RosterConstraints,
) -> Result<(), ConstraintValidationError> {
    let mut found = false;
    let current_count = current_roster.len();

    for p in current_roster {
        if *p == departing_peer_id {
            found = true;
            break;
        }
    }

    if !found {
        return Err(ConstraintValidationError::PeerNotFound);
    }

    // Check quorum after removal
    if current_count.saturating_sub(1) < constraints.min_peers_for_quorum {
        return Err(ConstraintValidationError::QuorumLost);
    }

    Ok(())
}

/// Validate structural invariants of the roster itself.
///
/// Checks that the roster has no duplicate entries, does not exceed the
/// max peer count, and meets the minimum quorum requirement.
///
/// # Errors
///
/// * [`ConstraintValidationError::DuplicatePeer`] if any peer appears
///   more than once.
/// * [`ConstraintValidationError::TooManyPeers`] if the roster exceeds
///   `constraints.max_peers`.
/// * [`ConstraintValidationError::QuorumLost`] if the roster has fewer
///   peers than `constraints.min_peers_for_quorum` (or is empty).
pub fn validate_roster_invariants(
    roster: &[MemberId],
    constraints: &RosterConstraints,
) -> Result<(), ConstraintValidationError> {
    // Check max peers
    if roster.len() > constraints.max_peers {
        return Err(ConstraintValidationError::TooManyPeers);
    }

    // Check quorum floor
    if roster.len() < constraints.min_peers_for_quorum {
        return Err(ConstraintValidationError::QuorumLost);
    }

    // Check for duplicates (O(N^2) worst case, O(N) typical for sorted roster)
    for i in 0..roster.len() {
        for j in (i + 1)..roster.len() {
            if roster[i] == roster[j] {
                return Err(ConstraintValidationError::DuplicatePeer);
            }
        }
    }

    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn default_constraints() -> RosterConstraints {
        RosterConstraints::default()
    }

    fn small_constraints() -> RosterConstraints {
        RosterConstraints::new(3, 2)
    }

    // ── validate_add_peer tests ──────────────────────────────────────

    #[test]
    fn add_peer_to_non_full_roster_ok() {
        let roster = [mid(1), mid(2)];
        assert!(validate_add_peer(&roster, mid(3), &default_constraints()).is_ok());
    }

    #[test]
    fn add_peer_not_present_ok() {
        let roster = [mid(10), mid(20), mid(30)];
        assert!(validate_add_peer(&roster, mid(40), &default_constraints()).is_ok());
    }

    #[test]
    fn add_peer_already_present_rejected() {
        let roster = [mid(1), mid(2), mid(3)];
        let result = validate_add_peer(&roster, mid(2), &default_constraints());
        assert_eq!(result, Err(ConstraintValidationError::PeerAlreadyPresent));
    }

    #[test]
    fn add_peer_exceeds_max_peers_rejected() {
        let constraints = small_constraints(); // max_peers=3
        let roster = [mid(1), mid(2), mid(3)];
        let result = validate_add_peer(&roster, mid(4), &constraints);
        assert_eq!(result, Err(ConstraintValidationError::TooManyPeers));
    }

    #[test]
    fn add_peer_at_exact_max_rejected() {
        let constraints = small_constraints(); // max_peers=3
        let roster = [mid(1), mid(2), mid(3)];
        let result = validate_add_peer(&roster, mid(4), &constraints);
        assert_eq!(result, Err(ConstraintValidationError::TooManyPeers));
    }

    #[test]
    fn add_peer_one_below_max_ok() {
        let constraints = small_constraints(); // max_peers=3
        let roster = [mid(1), mid(2)];
        assert!(validate_add_peer(&roster, mid(3), &constraints).is_ok());
    }

    // ── validate_remove_peer tests ───────────────────────────────────

    #[test]
    fn remove_existing_peer_ok() {
        let roster = [mid(1), mid(2), mid(3), mid(4)];
        assert!(validate_remove_peer(&roster, mid(2), &default_constraints()).is_ok());
    }

    #[test]
    fn remove_peer_not_found_rejected() {
        let roster = [mid(1), mid(2)];
        let result = validate_remove_peer(&roster, mid(99), &default_constraints());
        assert_eq!(result, Err(ConstraintValidationError::PeerNotFound));
    }

    #[test]
    fn remove_peer_from_empty_roster_rejected() {
        let roster: [MemberId; 0] = [];
        let result = validate_remove_peer(&roster, mid(1), &default_constraints());
        assert_eq!(result, Err(ConstraintValidationError::PeerNotFound));
    }

    #[test]
    fn remove_last_peer_loses_quorum() {
        // min_peers_for_quorum=1 means removing the last peer in a
        // 1-member roster would drop to 0, losing quorum.
        let constraints = default_constraints(); // min=1
        let roster = [mid(1)];
        let result = validate_remove_peer(&roster, mid(1), &constraints);
        assert_eq!(result, Err(ConstraintValidationError::QuorumLost));
    }

    #[test]
    fn remove_peer_drops_below_min_quorum() {
        let constraints = small_constraints(); // min_peers_for_quorum=2
        let roster = [mid(1), mid(2)];
        let result = validate_remove_peer(&roster, mid(1), &constraints);
        assert_eq!(result, Err(ConstraintValidationError::QuorumLost));
    }

    #[test]
    fn remove_peer_stays_above_min_quorum_ok() {
        let constraints = small_constraints(); // min_peers_for_quorum=2
        let roster = [mid(1), mid(2), mid(3)];
        assert!(validate_remove_peer(&roster, mid(1), &constraints).is_ok());
    }

    // ── validate_roster_invariants tests ─────────────────────────────

    #[test]
    fn valid_roster_passes_invariants() {
        let roster = [mid(1), mid(2), mid(3)];
        assert!(validate_roster_invariants(&roster, &default_constraints()).is_ok());
    }

    #[test]
    fn empty_roster_below_min_quorum_rejected() {
        let roster: [MemberId; 0] = [];
        let result = validate_roster_invariants(&roster, &default_constraints());
        assert_eq!(result, Err(ConstraintValidationError::QuorumLost));
    }

    #[test]
    fn roster_below_min_quorum_rejected() {
        let constraints = small_constraints(); // min=2
        let roster = [mid(1)];
        let result = validate_roster_invariants(&roster, &constraints);
        assert_eq!(result, Err(ConstraintValidationError::QuorumLost));
    }

    #[test]
    fn roster_at_min_quorum_ok() {
        let constraints = small_constraints(); // min=2
        let roster = [mid(1), mid(2)];
        assert!(validate_roster_invariants(&roster, &constraints).is_ok());
    }

    #[test]
    fn roster_exceeds_max_peers_rejected() {
        let constraints = small_constraints(); // max=3
        let roster = [mid(1), mid(2), mid(3), mid(4)];
        let result = validate_roster_invariants(&roster, &constraints);
        assert_eq!(result, Err(ConstraintValidationError::TooManyPeers));
    }

    #[test]
    fn roster_at_max_peers_ok() {
        let constraints = small_constraints(); // max=3
        let roster = [mid(1), mid(2), mid(3)];
        assert!(validate_roster_invariants(&roster, &constraints).is_ok());
    }

    #[test]
    fn roster_with_duplicate_rejected() {
        let roster = [mid(1), mid(2), mid(1)];
        let result = validate_roster_invariants(&roster, &default_constraints());
        assert_eq!(result, Err(ConstraintValidationError::DuplicatePeer));
    }

    #[test]
    fn roster_multiple_duplicates_rejected_first_only() {
        let roster = [mid(1), mid(2), mid(1), mid(2)];
        let result = validate_roster_invariants(&roster, &default_constraints());
        assert_eq!(result, Err(ConstraintValidationError::DuplicatePeer));
    }

    // ── Boundary / edge tests ───────────────────────────────────────

    #[test]
    fn single_peer_roster_add_ok() {
        let roster = [mid(42)];
        assert!(validate_add_peer(&roster, mid(43), &default_constraints()).is_ok());
    }

    #[test]
    fn max_peers_zero_always_rejects_add() {
        let constraints = RosterConstraints::new(0, 0);
        let roster: [MemberId; 0] = [];
        let result = validate_add_peer(&roster, mid(1), &constraints);
        assert_eq!(result, Err(ConstraintValidationError::TooManyPeers));
    }

    #[test]
    fn min_quorum_zero_allows_empty_roster() {
        let constraints = RosterConstraints::new(64, 0);
        let roster: [MemberId; 0] = [];
        assert!(validate_roster_invariants(&roster, &constraints).is_ok());
    }

    #[test]
    fn display_formatting() {
        assert_eq!(
            format!("{}", ConstraintValidationError::QuorumLost),
            "removal would lose quorum"
        );
        assert_eq!(
            format!("{}", ConstraintValidationError::TooManyPeers),
            "addition would exceed max peers"
        );
        assert_eq!(
            format!("{}", ConstraintValidationError::DuplicatePeer),
            "roster contains duplicate peer"
        );
        assert_eq!(
            format!("{}", ConstraintValidationError::PeerNotFound),
            "peer not found in roster"
        );
        assert_eq!(
            format!("{}", ConstraintValidationError::PeerAlreadyPresent),
            "peer already present in roster"
        );
    }
}
