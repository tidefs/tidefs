// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use blake3::Hasher;
use std::collections::BTreeMap;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// BLAKE3 domain separator for membership roster digests
// ---------------------------------------------------------------------------

const ROSTER_DOMAIN: &str = "tidefs-membership-roster-v1";

// ---------------------------------------------------------------------------
// RosterState: per-member state tracked by the roster
// ---------------------------------------------------------------------------

/// State of a member within the authoritative membership roster.
///
/// Transitions follow the SWIM-inspired life-cycle:
///   Active ──► Suspected ──► Failed
///   Active ──► Left
///
/// Invalid transitions (Failed→Active, Left→Active, Suspected→Active)
/// are rejected by [`MembershipRoster::transition_state`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosterState {
    /// Member is healthy and participating.
    Active,
    /// Member is under suspicion (unreachable, ping timeout).
    Suspected,
    /// Member has been confirmed failed (all indirect probes exhausted).
    Failed,
    /// Member has gracefully left the cluster.
    Left,
}

impl RosterState {
    /// Discriminant used for BLAKE3 digest preimage so different states
    /// produce distinct per-member hash contributions.
    pub fn discriminant(self) -> u8 {
        match self {
            RosterState::Active => 0,
            RosterState::Suspected => 1,
            RosterState::Failed => 2,
            RosterState::Left => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// RosterError
// ---------------------------------------------------------------------------

/// Errors returned by roster state-transition operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosterError {
    /// The member is not present in the roster.
    MemberNotFound,
    /// The requested state transition is not allowed.
    InvalidTransition {
        member_id: MemberId,
        from: RosterState,
        to: RosterState,
    },
    /// The member is already in the requested state (no-op).
    AlreadyInState {
        member_id: MemberId,
        state: RosterState,
    },
}

impl std::fmt::Display for RosterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MemberNotFound => write!(f, "member not found in roster"),
            Self::InvalidTransition {
                member_id,
                from,
                to,
            } => {
                write!(
                    f,
                    "invalid roster state transition for {}: {:?} -> {:?}",
                    member_id.0, from, to,
                )
            }
            Self::AlreadyInState { member_id, state } => {
                write!(f, "member {} is already in state {:?}", member_id.0, state,)
            }
        }
    }
}

impl std::error::Error for RosterError {}

// ---------------------------------------------------------------------------
// RosterSnapshot: point-in-time consistent snapshot with BLAKE3 digest
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of the membership roster.
///
/// The snapshot is immutable once created.  The embedded BLAKE3-256 digest
/// covers every member and its state, providing tamper validation for
/// consumers such as the epoch transition state machine and transport
/// peer manager.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterSnapshot {
    /// BLAKE3-256 domain-separated digest covering the full member set.
    pub digest: [u8; 32],
    /// Number of members in the snapshot.
    pub member_count: usize,
    /// Sorted list of (MemberId, RosterState) pairs for consistent iteration.
    entries: Vec<(MemberId, RosterState)>,
}

impl RosterSnapshot {
    /// Iterate over members in deterministic (MemberId) order.
    pub fn iter(&self) -> impl Iterator<Item = &(MemberId, RosterState)> {
        self.entries.iter()
    }

    /// Look up a member by id.  Returns `None` if not present.
    pub fn lookup(&self, member_id: MemberId) -> Option<RosterState> {
        self.entries
            .binary_search_by_key(&member_id, |(mid, _)| *mid)
            .ok()
            .map(|idx| self.entries[idx].1)
    }

    /// Return the number of members in this snapshot.
    pub fn len(&self) -> usize {
        self.member_count
    }

    /// Return true if the snapshot contains no members.
    pub fn is_empty(&self) -> bool {
        self.member_count == 0
    }
}

// ---------------------------------------------------------------------------
// MembershipRoster: authoritative member-set owner
// ---------------------------------------------------------------------------

/// The authoritative in-memory member set for the TideFS membership
/// subsystem.
///
/// `MembershipRoster` owns the canonical set of members and their
/// lifecycle states.  It consumes [`MembershipEvent`]s from the event
/// bridge (see [`crate::event_bridge`]) and produces consistent
/// [`RosterSnapshot`]s for consumers such as the epoch transition state
/// machine and transport peer manager.
///
/// ## State machine
///
/// | From       | To         | Valid? |
/// |------------|------------|--------|
/// | Active     | Suspected  | Yes    |
/// | Suspected  | Failed     | Yes    |
/// | Active     | Left       | Yes    |
/// | (none)     | Active     | add    |
///
/// All other transitions (Failed→Active, Left→Active, Suspected→Active,
/// Failed→Left, etc.) are rejected.
///
/// ## BLAKE3 integrity
///
/// Every snapshot carries a BLAKE3-256 domain-separated digest (domain
/// `tidefs-membership-roster-v1`) computed over the sorted member set.
/// Identical member sets produce identical digests; tampering is
/// detectable by consumers that re-compute against their own view.
pub struct MembershipRoster {
    members: BTreeMap<MemberId, RosterState>,
}

impl MembershipRoster {
    /// Create an empty roster.
    pub fn new() -> Self {
        Self {
            members: BTreeMap::new(),
        }
    }

    /// Return the number of members currently tracked.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Return true if the roster is empty.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    // ------------------------------------------------------------------
    // Membership mutators
    // ------------------------------------------------------------------

    /// Add a member in the `Active` state.
    ///
    /// If the member already exists, this is a no-op that returns the
    /// existing state (idempotent re-join).
    pub fn add_member(&mut self, member_id: MemberId) -> RosterState {
        self.members.entry(member_id).or_insert(RosterState::Active);
        self.members[&member_id]
    }

    /// Remove a member from the roster entirely.
    ///
    /// Returns the previous state if the member was present, or `None`.
    /// After removal the member must re-join via [`add_member`] to
    /// re-appear.
    pub fn remove_member(&mut self, member_id: MemberId) -> Option<RosterState> {
        self.members.remove(&member_id)
    }

    /// Transition a member to a new state, enforcing the valid state
    /// machine.
    ///
    /// # Valid transitions
    ///
    /// - `Active → Suspected`
    /// - `Suspected → Failed`
    /// - `Active → Left`
    ///
    /// # Errors
    ///
    /// - [`RosterError::MemberNotFound`] if the member is not in the roster.
    /// - [`RosterError::AlreadyInState`] if the member is already in `to`.
    /// - [`RosterError::InvalidTransition`] for all other transitions.
    pub fn transition_state(
        &mut self,
        member_id: MemberId,
        to: RosterState,
    ) -> Result<RosterState, RosterError> {
        let current = self
            .members
            .get(&member_id)
            .copied()
            .ok_or(RosterError::MemberNotFound)?;

        if current == to {
            return Err(RosterError::AlreadyInState {
                member_id,
                state: to,
            });
        }

        match (current, to) {
            (RosterState::Active, RosterState::Suspected)
            | (RosterState::Suspected, RosterState::Failed)
            | (RosterState::Active, RosterState::Left) => {
                self.members.insert(member_id, to);
                Ok(to)
            }
            _ => Err(RosterError::InvalidTransition {
                member_id,
                from: current,
                to,
            }),
        }
    }

    // ------------------------------------------------------------------
    // Lookup and iteration
    // ------------------------------------------------------------------

    /// Look up a member's current state.
    ///
    /// Returns `None` if the member is not in the roster.
    pub fn lookup(&self, member_id: MemberId) -> Option<RosterState> {
        self.members.get(&member_id).copied()
    }

    /// Return an iterator over all members and their states.
    ///
    /// Order is not guaranteed; use [`snapshot`] for deterministic
    /// iteration.
    pub fn iter(&self) -> impl Iterator<Item = (&MemberId, &RosterState)> {
        self.members.iter()
    }

    // ------------------------------------------------------------------
    // Snapshot and digest
    // ------------------------------------------------------------------

    /// Produce a point-in-time [`RosterSnapshot`] with BLAKE3-verified
    /// integrity.
    ///
    /// The snapshot's digest covers every `(MemberId, RosterState)` pair
    /// in sorted order.  Two rosters with identical member sets will
    /// produce identical digests.
    pub fn snapshot(&self) -> RosterSnapshot {
        let mut entries: Vec<(MemberId, RosterState)> = self
            .members
            .iter()
            .map(|(mid, state)| (*mid, *state))
            .collect();
        entries.sort_by_key(|(mid, _)| *mid);

        let digest = Self::compute_digest_from_entries(&entries);
        let member_count = entries.len();

        RosterSnapshot {
            digest,
            member_count,
            entries,
        }
    }

    /// Compute the BLAKE3-256 roster digest from a sorted slice of
    /// `(MemberId, RosterState)` pairs.
    pub fn compute_digest_from_entries(entries: &[(MemberId, RosterState)]) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(ROSTER_DOMAIN);
        for (member_id, state) in entries {
            hasher.update(&member_id.0.to_le_bytes());
            hasher.update(&[state.discriminant()]);
        }
        hasher.finalize().into()
    }

    /// Compute the BLAKE3-256 digest of the current live roster (without
    /// producing a snapshot).
    pub fn compute_digest(&self) -> [u8; 32] {
        self.snapshot().digest
    }
}

impl Default for MembershipRoster {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(n: u64) -> MemberId {
        MemberId::new(n)
    }

    // ----- add_member -----

    #[test]
    fn add_single_member() {
        let mut roster = MembershipRoster::new();
        assert_eq!(roster.add_member(mid(1)), RosterState::Active);
        assert_eq!(roster.lookup(mid(1)), Some(RosterState::Active));
        assert_eq!(roster.len(), 1);
    }

    #[test]
    fn add_multiple_members_digest_changes_predictably() {
        let mut roster = MembershipRoster::new();
        let d0 = roster.compute_digest();

        roster.add_member(mid(1));
        let d1 = roster.compute_digest();
        assert_ne!(d0, d1, "adding a member must change digest");

        roster.add_member(mid(2));
        let d2 = roster.compute_digest();
        assert_ne!(d1, d2, "adding another member must change digest");
        assert_ne!(d0, d2);
    }

    #[test]
    fn add_existing_member_is_idempotent() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        let state = roster.add_member(mid(1)); // re-insert
        assert_eq!(state, RosterState::Active);
        assert_eq!(roster.len(), 1);
    }

    // ----- remove_member -----

    #[test]
    fn remove_member_absent_from_snapshot() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster.add_member(mid(2));

        let removed = roster.remove_member(mid(1));
        assert_eq!(removed, Some(RosterState::Active));
        assert_eq!(roster.lookup(mid(1)), None);
        assert_eq!(roster.len(), 1);

        let snap = roster.snapshot();
        assert_eq!(snap.member_count, 1);
        assert_eq!(snap.lookup(mid(2)), Some(RosterState::Active));
        assert_eq!(snap.lookup(mid(1)), None);
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut roster = MembershipRoster::new();
        assert_eq!(roster.remove_member(mid(42)), None);
    }

    #[test]
    fn remove_changes_digest() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster.add_member(mid(2));
        let d_before = roster.compute_digest();

        roster.remove_member(mid(1));
        let d_after = roster.compute_digest();
        assert_ne!(d_before, d_after);
    }

    // ----- valid transitions -----

    #[test]
    fn transition_active_to_suspected() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        let result = roster.transition_state(mid(1), RosterState::Suspected);
        assert_eq!(result, Ok(RosterState::Suspected));
        assert_eq!(roster.lookup(mid(1)), Some(RosterState::Suspected));
    }

    #[test]
    fn transition_suspected_to_failed() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster
            .transition_state(mid(1), RosterState::Suspected)
            .unwrap();
        let result = roster.transition_state(mid(1), RosterState::Failed);
        assert_eq!(result, Ok(RosterState::Failed));
        assert_eq!(roster.lookup(mid(1)), Some(RosterState::Failed));
    }

    #[test]
    fn transition_active_to_left() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        let result = roster.transition_state(mid(1), RosterState::Left);
        assert_eq!(result, Ok(RosterState::Left));
        assert_eq!(roster.lookup(mid(1)), Some(RosterState::Left));
    }

    // ----- invalid transition rejection -----

    #[test]
    fn reject_failed_to_active() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster
            .transition_state(mid(1), RosterState::Suspected)
            .unwrap();
        roster
            .transition_state(mid(1), RosterState::Failed)
            .unwrap();
        let result = roster.transition_state(mid(1), RosterState::Active);
        assert!(matches!(result, Err(RosterError::InvalidTransition { .. })));
    }

    #[test]
    fn reject_left_to_active() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster.transition_state(mid(1), RosterState::Left).unwrap();
        let result = roster.transition_state(mid(1), RosterState::Active);
        assert!(matches!(result, Err(RosterError::InvalidTransition { .. })));
    }

    #[test]
    fn reject_suspected_to_active() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster
            .transition_state(mid(1), RosterState::Suspected)
            .unwrap();
        let result = roster.transition_state(mid(1), RosterState::Active);
        assert!(matches!(result, Err(RosterError::InvalidTransition { .. })));
    }

    #[test]
    fn reject_active_to_active_noop() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        let result = roster.transition_state(mid(1), RosterState::Active);
        assert!(matches!(result, Err(RosterError::AlreadyInState { .. })));
    }

    #[test]
    fn reject_left_to_suspected() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster.transition_state(mid(1), RosterState::Left).unwrap();
        let result = roster.transition_state(mid(1), RosterState::Suspected);
        assert!(matches!(result, Err(RosterError::InvalidTransition { .. })));
    }

    #[test]
    fn reject_left_to_failed() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster.transition_state(mid(1), RosterState::Left).unwrap();
        let result = roster.transition_state(mid(1), RosterState::Failed);
        assert!(matches!(result, Err(RosterError::InvalidTransition { .. })));
    }

    #[test]
    fn reject_failed_to_left() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster
            .transition_state(mid(1), RosterState::Suspected)
            .unwrap();
        roster
            .transition_state(mid(1), RosterState::Failed)
            .unwrap();
        let result = roster.transition_state(mid(1), RosterState::Left);
        assert!(matches!(result, Err(RosterError::InvalidTransition { .. })));
    }

    #[test]
    fn reject_transition_nonexistent_member() {
        let mut roster = MembershipRoster::new();
        let result = roster.transition_state(mid(42), RosterState::Suspected);
        assert_eq!(result, Err(RosterError::MemberNotFound));
    }

    // ----- BLAKE3 digest stability -----

    #[test]
    fn digest_stable_for_same_member_set() {
        let mut r1 = MembershipRoster::new();
        r1.add_member(mid(1));
        r1.add_member(mid(2));
        r1.transition_state(mid(1), RosterState::Suspected).unwrap();

        let mut r2 = MembershipRoster::new();
        // Insert in different order — digest must be identical
        r2.add_member(mid(2));
        r2.add_member(mid(1));
        r2.transition_state(mid(1), RosterState::Suspected).unwrap();

        assert_eq!(r1.snapshot().digest, r2.snapshot().digest);
    }

    #[test]
    fn digest_differs_for_different_member_set() {
        let mut r1 = MembershipRoster::new();
        r1.add_member(mid(1));
        r1.add_member(mid(2));

        let mut r2 = MembershipRoster::new();
        r2.add_member(mid(1));
        r2.add_member(mid(3));

        assert_ne!(r1.snapshot().digest, r2.snapshot().digest);
    }

    #[test]
    fn digest_differs_for_different_states() {
        let mut r1 = MembershipRoster::new();
        r1.add_member(mid(1));
        let d_active = r1.compute_digest();

        r1.transition_state(mid(1), RosterState::Suspected).unwrap();
        let d_suspected = r1.compute_digest();
        assert_ne!(d_active, d_suspected);
    }

    // ----- empty roster -----

    #[test]
    fn empty_roster_snapshot() {
        let roster = MembershipRoster::new();
        let snap = roster.snapshot();
        assert_eq!(snap.member_count, 0);
        assert!(snap.is_empty());
        assert_eq!(snap.len(), 0);
        // Empty digest is still a valid BLAKE3 output
        assert_eq!(snap.digest.len(), 32);
    }

    #[test]
    fn empty_roster_digest_is_deterministic() {
        let r1 = MembershipRoster::new();
        let r2 = MembershipRoster::new();
        assert_eq!(r1.snapshot().digest, r2.snapshot().digest);
        // Adding then removing a member restores empty, same digest
        let mut r3 = MembershipRoster::new();
        r3.add_member(mid(1));
        r3.remove_member(mid(1));
        assert_eq!(r1.snapshot().digest, r3.snapshot().digest);
    }

    // ----- snapshot iteration -----

    #[test]
    fn snapshot_iter_is_deterministic_order() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(3));
        roster.add_member(mid(1));
        roster.add_member(mid(2));

        let snap = roster.snapshot();
        let ids: Vec<u64> = snap.iter().map(|(mid, _)| mid.0).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn snapshot_lookup() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(10));
        roster.add_member(mid(20));
        roster
            .transition_state(mid(10), RosterState::Suspected)
            .unwrap();

        let snap = roster.snapshot();
        assert_eq!(snap.lookup(mid(10)), Some(RosterState::Suspected));
        assert_eq!(snap.lookup(mid(20)), Some(RosterState::Active));
        assert_eq!(snap.lookup(mid(99)), None);
    }

    // ----- multi-member state independence -----

    #[test]
    fn transitioning_one_member_does_not_affect_others() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster.add_member(mid(2));
        roster.add_member(mid(3));

        roster
            .transition_state(mid(2), RosterState::Suspected)
            .unwrap();

        assert_eq!(roster.lookup(mid(1)), Some(RosterState::Active));
        assert_eq!(roster.lookup(mid(2)), Some(RosterState::Suspected));
        assert_eq!(roster.lookup(mid(3)), Some(RosterState::Active));
    }

    #[test]
    fn transitioning_member_changes_digest_predictably() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster.add_member(mid(2));
        let d_before = roster.compute_digest();

        roster
            .transition_state(mid(1), RosterState::Suspected)
            .unwrap();
        let d_after_suspect = roster.compute_digest();
        assert_ne!(d_before, d_after_suspect);

        roster
            .transition_state(mid(1), RosterState::Failed)
            .unwrap();
        let d_after_failed = roster.compute_digest();
        assert_ne!(d_after_suspect, d_after_failed);
    }

    // ----- default impl -----

    #[test]
    fn default_roster_is_empty() {
        let roster = MembershipRoster::default();
        assert!(roster.is_empty());
        assert_eq!(roster.len(), 0);
    }

    // ----- snapshot is point-in-time copy -----

    #[test]
    fn snapshot_does_not_reflect_later_mutations() {
        let mut roster = MembershipRoster::new();
        roster.add_member(mid(1));
        roster.add_member(mid(2));

        let snap = roster.snapshot();
        assert_eq!(snap.member_count, 2);

        // Mutate after snapshot
        roster.remove_member(mid(1));
        roster.add_member(mid(3));

        assert_eq!(snap.member_count, 2, "snapshot must be immutable");
        assert_eq!(snap.lookup(mid(1)), Some(RosterState::Active));
        assert_eq!(snap.lookup(mid(3)), None);
    }

    // ----- RosterError display -----

    #[test]
    fn roster_error_display() {
        let e = RosterError::MemberNotFound;
        assert!(format!("{e}").contains("not found"));

        let e = RosterError::InvalidTransition {
            member_id: mid(7),
            from: RosterState::Failed,
            to: RosterState::Active,
        };
        let s = format!("{e}");
        assert!(s.contains("invalid"));
        assert!(s.contains("7"));

        let e = RosterError::AlreadyInState {
            member_id: mid(3),
            state: RosterState::Active,
        };
        let s = format!("{e}");
        assert!(s.contains("already"));
        assert!(s.contains("3"));
    }
}
