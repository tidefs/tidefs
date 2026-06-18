// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Roster-change proposal validation rules for pre-quorum well-formedness checking.
//!
//! Before a roster-change proposal enters the epoch-advance coordinator's quorum
//! collection path, it must pass well-formedness validation. This module provides
//! the validation engine that rejects malformed proposals — duplicate entries,
//! absent peers, last-member removal, empty proposals, and add-remove conflicts —
//! preventing them from consuming a quorum round and risking partition.
//!
//! ## Validation Rules
//!
//! | Rule | Condition |
//! |------|-----------|
//! | [`RosterChangeValidationRule::AddPeerPresent`] | A peer in `added` already exists in the current roster. |
//! | [`RosterChangeValidationRule::RemoveAbsentPeer`] | A peer in `removed` is not present in the current roster. |
//! | [`RosterChangeValidationRule::RemoveLastMember`] | The proposal would remove the last remaining member. |
//! | [`RosterChangeValidationRule::EmptyProposal`] | Both `added` and `removed` sets are empty. |
//! | [`RosterChangeValidationRule::DuplicateEntry`] | A peer id appears more than once within `added` or `removed`. |
//! | [`RosterChangeValidationRule::AddAndRemoveSamePeer`] | The same peer appears in both `added` and `removed`. |
//!
//! ## Pre-Quorum Contract
//!
//! Callers (typically the epoch-advance coordinator in `tidefs-membership-live`)
//! invoke [`validate_roster_change`] before feeding a proposal into quorum
//! collection. If validation fails, the proposal is rejected with a vector of
//! [`RosterChangeValidationError`] values describing each violation.
//!
//! The validation function is pure (no I/O, no allocation beyond the error
//! vector and internal `BTreeSet` lookups) and runs in O(N + M) time where
//! N is the current roster size and M is the proposal size.

use std::collections::BTreeSet;

// ── Validation Rule Enum ────────────────────────────────────────────

/// Well-formedness rules checked by [`validate_roster_change`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RosterChangeValidationRule {
    /// A peer in the `added` set is already present in the current roster.
    AddPeerPresent,
    /// A peer in the `removed` set is not present in the current roster.
    RemoveAbsentPeer,
    /// The proposal would remove the last remaining member from the roster.
    RemoveLastMember,
    /// The proposal contains no additions and no removals (no-op).
    EmptyProposal,
    /// A peer id appears more than once within the `added` or `removed` set.
    DuplicateEntry,
    /// The same peer appears in both the `added` and `removed` sets.
    AddAndRemoveSamePeer,
}

// ── RosterChangeProposal ────────────────────────────────────────────

/// A proposed roster change carrying the sets of peers to add and remove.
///
/// The caller populates `added` and `removed` from the membership delta
/// (e.g. from [`MembershipDelta`](crate::epoch_proposal::MembershipDelta)).
/// Duplicate entries within each set are tolerated at construction but
/// will be flagged by [`validate_roster_change`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RosterChangeProposal {
    /// Peer identifiers to add to the roster (may contain duplicates).
    pub added: Vec<u64>,
    /// Peer identifiers to remove from the roster (may contain duplicates).
    pub removed: Vec<u64>,
}

// ── Validation Error ────────────────────────────────────────────────

/// A single roster-change validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterChangeValidationError {
    /// Which rule was violated.
    pub rule: RosterChangeValidationRule,
    /// The peer identifier that triggered the violation, if applicable.
    ///
    /// `None` for [`RosterChangeValidationRule::EmptyProposal`] and
    /// [`RosterChangeValidationRule::RemoveLastMember`].
    pub peer_id: Option<u64>,
}

// ── Validation Entry Point ──────────────────────────────────────────

/// Validate a roster-change proposal against the current committed member set.
///
/// Checks each well-formedness rule. All violations are collected and returned
/// in a single `Err(Vec<RosterChangeValidationError>)` so the caller can log or
/// surface every problem at once.
///
/// # Arguments
///
/// * `proposal` - The proposed roster change (added/removed peer sets).
/// * `current_members` - The current roster's sorted, deduplicated member ids.
///
/// # Returns
///
/// `Ok(())` if the proposal is well-formed; `Err(errors)` with all violations
/// otherwise.
pub fn validate_roster_change(
    proposal: &RosterChangeProposal,
    current_members: &[u64],
) -> Result<(), Vec<RosterChangeValidationError>> {
    let mut errors: Vec<RosterChangeValidationError> = Vec::new();

    // ── Empty proposal check ──────────────────────────────────────
    if proposal.added.is_empty() && proposal.removed.is_empty() {
        errors.push(RosterChangeValidationError {
            rule: RosterChangeValidationRule::EmptyProposal,
            peer_id: None,
        });
        // No point checking further rules on an empty proposal.
        return Err(errors);
    }

    // ── Duplicate entry check (within each set) ───────────────────
    check_duplicates(&proposal.added, &mut errors);
    check_duplicates(&proposal.removed, &mut errors);

    // ── Add/remove same peer check ────────────────────────────────
    let added_set: BTreeSet<u64> = proposal.added.iter().copied().collect();
    let removed_set: BTreeSet<u64> = proposal.removed.iter().copied().collect();

    for id in added_set.intersection(&removed_set) {
        errors.push(RosterChangeValidationError {
            rule: RosterChangeValidationRule::AddAndRemoveSamePeer,
            peer_id: Some(*id),
        });
    }

    // ── Remove-last-member check ──────────────────────────────────
    // Compute the resulting member set: current plus additions, minus removals.
    let current_set: BTreeSet<u64> = current_members.iter().copied().collect();
    let mut result: BTreeSet<u64> = current_set.clone();
    for id in &proposal.added {
        result.insert(*id);
    }
    for id in &proposal.removed {
        result.remove(id);
    }
    if result.is_empty() {
        errors.push(RosterChangeValidationError {
            rule: RosterChangeValidationRule::RemoveLastMember,
            peer_id: None,
        });
    }

    // ── Add-peer-present check ────────────────────────────────────
    for id in &proposal.added {
        if current_set.contains(id) {
            errors.push(RosterChangeValidationError {
                rule: RosterChangeValidationRule::AddPeerPresent,
                peer_id: Some(*id),
            });
        }
    }

    // ── Remove-absent-peer check ──────────────────────────────────
    for id in &proposal.removed {
        if !current_set.contains(id) {
            errors.push(RosterChangeValidationError {
                rule: RosterChangeValidationRule::RemoveAbsentPeer,
                peer_id: Some(*id),
            });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// ── Internal Helpers ────────────────────────────────────────────────

/// Check for duplicate entries in a peer id slice and append errors.
fn check_duplicates(ids: &[u64], errors: &mut Vec<RosterChangeValidationError>) {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(*id) {
            errors.push(RosterChangeValidationError {
                rule: RosterChangeValidationRule::DuplicateEntry,
                peer_id: Some(*id),
            });
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Valid transitions ──────────────────────────────────────────

    #[test]
    fn valid_add_new_peer() {
        let proposal = RosterChangeProposal {
            added: vec![3],
            removed: vec![],
        };
        assert!(validate_roster_change(&proposal, &[1, 2]).is_ok());
    }

    #[test]
    fn valid_remove_existing_peer() {
        let proposal = RosterChangeProposal {
            added: vec![],
            removed: vec![2],
        };
        assert!(validate_roster_change(&proposal, &[1, 2, 3]).is_ok());
    }

    #[test]
    fn valid_add_and_remove_different_peers() {
        let proposal = RosterChangeProposal {
            added: vec![4],
            removed: vec![2],
        };
        assert!(validate_roster_change(&proposal, &[1, 2, 3]).is_ok());
    }

    #[test]
    fn valid_multiple_adds_and_removes() {
        let proposal = RosterChangeProposal {
            added: vec![4, 5],
            removed: vec![1, 2],
        };
        assert!(validate_roster_change(&proposal, &[1, 2, 3]).is_ok());
    }

    #[test]
    fn valid_remove_non_last_member() {
        let proposal = RosterChangeProposal {
            added: vec![],
            removed: vec![1],
        };
        // Two members, remove one leaves [2].
        assert!(validate_roster_change(&proposal, &[1, 2]).is_ok());
    }

    // ── AddPeerPresent ─────────────────────────────────────────────

    #[test]
    fn reject_add_peer_already_present() {
        let proposal = RosterChangeProposal {
            added: vec![2],
            removed: vec![],
        };
        let result = validate_roster_change(&proposal, &[1, 2, 3]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].rule, RosterChangeValidationRule::AddPeerPresent);
        assert_eq!(errors[0].peer_id, Some(2));
    }

    #[test]
    fn reject_multiple_adds_with_one_already_present() {
        let proposal = RosterChangeProposal {
            added: vec![4, 2, 5],
            removed: vec![],
        };
        let result = validate_roster_change(&proposal, &[1, 2, 3]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.rule == RosterChangeValidationRule::AddPeerPresent && e.peer_id == Some(2)));
    }

    // ── RemoveAbsentPeer ───────────────────────────────────────────

    #[test]
    fn reject_remove_peer_not_in_roster() {
        let proposal = RosterChangeProposal {
            added: vec![],
            removed: vec![99],
        };
        let result = validate_roster_change(&proposal, &[1, 2]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].rule, RosterChangeValidationRule::RemoveAbsentPeer);
        assert_eq!(errors[0].peer_id, Some(99));
    }

    #[test]
    fn reject_multiple_removes_with_one_absent() {
        let proposal = RosterChangeProposal {
            added: vec![],
            removed: vec![2, 99],
        };
        let result = validate_roster_change(&proposal, &[1, 2, 3]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(
            |e| e.rule == RosterChangeValidationRule::RemoveAbsentPeer && e.peer_id == Some(99)
        ));
    }

    // ── RemoveLastMember ───────────────────────────────────────────

    #[test]
    fn reject_remove_last_member() {
        let proposal = RosterChangeProposal {
            added: vec![],
            removed: vec![1],
        };
        let result = validate_roster_change(&proposal, &[1]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.rule == RosterChangeValidationRule::RemoveLastMember));
    }

    #[test]
    fn reject_remove_all_members() {
        let proposal = RosterChangeProposal {
            added: vec![],
            removed: vec![1, 2, 3],
        };
        let result = validate_roster_change(&proposal, &[1, 2, 3]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.rule == RosterChangeValidationRule::RemoveLastMember));
    }

    #[test]
    fn allow_remove_last_member_if_adding_replacement() {
        // Removing the last member but simultaneously adding one: roster stays non-empty.
        let proposal = RosterChangeProposal {
            added: vec![2],
            removed: vec![1],
        };
        assert!(validate_roster_change(&proposal, &[1]).is_ok());
    }

    // ── EmptyProposal ──────────────────────────────────────────────

    #[test]
    fn reject_empty_proposal() {
        let proposal = RosterChangeProposal {
            added: vec![],
            removed: vec![],
        };
        let result = validate_roster_change(&proposal, &[1, 2]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].rule, RosterChangeValidationRule::EmptyProposal);
        assert!(errors[0].peer_id.is_none());
    }

    // ── DuplicateEntry ─────────────────────────────────────────────

    #[test]
    fn reject_duplicate_in_added() {
        let proposal = RosterChangeProposal {
            added: vec![4, 5, 4],
            removed: vec![],
        };
        let result = validate_roster_change(&proposal, &[1, 2, 3]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.rule == RosterChangeValidationRule::DuplicateEntry && e.peer_id == Some(4)));
    }

    #[test]
    fn reject_duplicate_in_removed() {
        let proposal = RosterChangeProposal {
            added: vec![],
            removed: vec![1, 2, 1],
        };
        let result = validate_roster_change(&proposal, &[1, 2, 3]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.rule == RosterChangeValidationRule::DuplicateEntry && e.peer_id == Some(1)));
    }

    // ── AddAndRemoveSamePeer ───────────────────────────────────────

    #[test]
    fn reject_add_and_remove_same_peer() {
        let proposal = RosterChangeProposal {
            added: vec![3],
            removed: vec![3],
        };
        let result = validate_roster_change(&proposal, &[1, 2]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(
            |e| e.rule == RosterChangeValidationRule::AddAndRemoveSamePeer && e.peer_id == Some(3)
        ));
    }

    // ── Multiple simultaneous violations ───────────────────────────

    #[test]
    fn collect_multiple_violations() {
        let proposal = RosterChangeProposal {
            added: vec![2, 2], // AddPeerPresent (2 in roster) + DuplicateEntry
            removed: vec![99], // RemoveAbsentPeer
        };
        let result = validate_roster_change(&proposal, &[1, 2, 3]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.len() >= 3); // AddPeerPresent, DuplicateEntry, RemoveAbsentPeer
    }

    // ── Boundary: single-member roster ─────────────────────────────

    #[test]
    fn single_member_roster_removal_rejected() {
        let proposal = RosterChangeProposal {
            added: vec![],
            removed: vec![1],
        };
        let result = validate_roster_change(&proposal, &[1]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.rule == RosterChangeValidationRule::RemoveLastMember));
    }

    #[test]
    fn single_member_roster_add_ok() {
        let proposal = RosterChangeProposal {
            added: vec![2],
            removed: vec![],
        };
        assert!(validate_roster_change(&proposal, &[1]).is_ok());
    }

    // ── Edge: empty current roster ─────────────────────────────────

    #[test]
    fn empty_roster_add_is_ok() {
        let proposal = RosterChangeProposal {
            added: vec![1],
            removed: vec![],
        };
        assert!(validate_roster_change(&proposal, &[]).is_ok());
    }

    #[test]
    fn empty_roster_remove_absent_is_rejected() {
        let proposal = RosterChangeProposal {
            added: vec![],
            removed: vec![1],
        };
        let result = validate_roster_change(&proposal, &[]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.rule == RosterChangeValidationRule::RemoveAbsentPeer));
    }

    #[test]
    fn empty_roster_empty_proposal_rejected() {
        let proposal = RosterChangeProposal {
            added: vec![],
            removed: vec![],
        };
        let result = validate_roster_change(&proposal, &[]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors[0].rule, RosterChangeValidationRule::EmptyProposal);
    }
}
