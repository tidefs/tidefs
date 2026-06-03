//! Session binding interface for transport lifecycle policy.
//!
//! Provides a membership-side type surface that the transport layer queries to
//! drive session lifecycle decisions (admit, route, drain, close) from current
//! membership peer state. This module is a pure membership type surface: it
//! does not import `tidefs-transport` or open a dependency edge toward transport.
//!
//! ## Integration
//!
//! Transport creates a [`PeerSessionBinding`] at connection-admission time and
//! inserts it into a shared [`SessionBindingTable`]. When membership state
//! changes (epoch advance, peer failure, drain), transport calls
//! [`binding_policy`] with the peer's current [`MemberState`] and applies the
//! returned [`SessionPolicy`] to all sessions bound to that peer.
//!
//! ## Policy Mapping
//!
//! | MemberState | SessionPolicy | Transport Action |
//! |-------------|---------------|------------------|
//! | Alive       | Route         | Normal routing |
//! | Suspected   | Drain         | Graceful drain |
//! | Failed      | Close         | Immediate teardown |

use std::collections::{btree_map::Entry, BTreeMap};
use tidefs_membership_epoch::{EpochId, MemberId};

use crate::gossip::MemberState;

// ---------------------------------------------------------------------------
// SessionId — transport-independent session identifier
// ---------------------------------------------------------------------------

/// Opaque session identifier owned by the membership layer.
///
/// Transport maps its own session identifiers to/from this type.
/// The membership layer does not interpret the value; it is an
/// opaque key for binding table operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub u64);

impl SessionId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

// ---------------------------------------------------------------------------
// SessionPolicy — lifecycle directive derived from membership state
// ---------------------------------------------------------------------------

/// Transport session lifecycle directive derived from peer membership state.
///
/// Transport queries this policy for each bound peer and applies the
/// corresponding action to all sessions associated with that peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPolicy {
    /// Admit the peer: allow new session establishment.
    Admit,
    /// Route traffic normally over established sessions.
    Route,
    /// Drain sessions: stop admitting new work, allow in-flight
    /// requests to complete, then close.
    Drain,
    /// Close sessions immediately: tear down without waiting for
    /// in-flight work.
    Close,
}

// ---------------------------------------------------------------------------
// PeerSessionBinding — opaque handle linking a transport session to a peer
// ---------------------------------------------------------------------------

/// Associates a transport session with a membership peer identity.
///
/// Created at admission time and held by transport for the lifetime
/// of the session. The binding is inserted into a [`SessionBindingTable`]
/// so transport can look up which peer a session belongs to and what
/// policy to apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerSessionBinding {
    /// Unique binding identifier.
    pub binding_id: u64,
    /// The membership peer this session is bound to.
    pub peer_id: MemberId,
    /// The transport session identifier (membership-side opaque key).
    pub session_id: SessionId,
    /// The epoch in which this binding was created.
    pub epoch: EpochId,
}

impl PeerSessionBinding {
    #[must_use]
    pub const fn new(
        binding_id: u64,
        peer_id: MemberId,
        session_id: SessionId,
        epoch: EpochId,
    ) -> Self {
        Self {
            binding_id,
            peer_id,
            session_id,
            epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// SessionBindingTable — collection of active session-to-peer bindings
// ---------------------------------------------------------------------------

/// Indexed collection of active [`PeerSessionBinding`] entries.
///
/// Supports lookup by peer ID (all sessions for a peer), lookup by
/// session ID (the peer a session belongs to), batch policy refresh
/// on epoch advance, and removal.
#[derive(Clone, Debug, Default)]
pub struct SessionBindingTable {
    /// Bindings indexed by peer ID. A peer may have multiple sessions.
    by_peer: BTreeMap<MemberId, Vec<PeerSessionBinding>>,
    /// Bindings indexed by session ID for O(log n) lookup.
    by_session: BTreeMap<SessionId, PeerSessionBinding>,
}

impl SessionBindingTable {
    /// Create an empty binding table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_peer: BTreeMap::new(),
            by_session: BTreeMap::new(),
        }
    }

    /// Number of active bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_session.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_session.is_empty()
    }

    /// Insert a binding. Returns `true` if inserted, `false` if a binding
    /// with the same session ID already exists.
    pub fn insert(&mut self, binding: PeerSessionBinding) -> bool {
        match self.by_session.entry(binding.session_id) {
            Entry::Vacant(entry) => {
                self.by_peer
                    .entry(binding.peer_id)
                    .or_default()
                    .push(binding);
                entry.insert(binding);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Look up the binding for a session ID.
    #[must_use]
    pub fn get_by_session(&self, session_id: SessionId) -> Option<&PeerSessionBinding> {
        self.by_session.get(&session_id)
    }

    /// Look up all bindings for a peer ID.
    #[must_use]
    pub fn get_by_peer(&self, peer_id: MemberId) -> &[PeerSessionBinding] {
        self.by_peer.get(&peer_id).map_or(&[], |v| v.as_slice())
    }

    /// Remove a binding by session ID. Returns the removed binding if found.
    pub fn remove(&mut self, session_id: SessionId) -> Option<PeerSessionBinding> {
        let binding = self.by_session.remove(&session_id)?;

        // Remove from by_peer index
        if let Some(peer_bindings) = self.by_peer.get_mut(&binding.peer_id) {
            peer_bindings.retain(|b| b.session_id != session_id);
            if peer_bindings.is_empty() {
                self.by_peer.remove(&binding.peer_id);
            }
        }

        Some(binding)
    }

    /// Remove all bindings for a peer. Returns the removed bindings.
    pub fn remove_all_for_peer(&mut self, peer_id: MemberId) -> Vec<PeerSessionBinding> {
        let bindings = self.by_peer.remove(&peer_id).unwrap_or_default();
        for binding in &bindings {
            self.by_session.remove(&binding.session_id);
        }
        bindings
    }

    /// Iterate over all peers that have active bindings, with a
    /// count of sessions per peer.
    pub fn peer_counts(&self) -> impl Iterator<Item = (MemberId, usize)> + '_ {
        self.by_peer
            .iter()
            .map(|(id, bindings)| (*id, bindings.len()))
    }

    /// Batch refresh: update the epoch on all bindings for peers that
    /// match the given predicate. Returns the set of peer IDs that
    /// were refreshed.
    ///
    /// This is called on epoch advance to re-derive policies for all
    /// currently-bound peers.
    pub fn refresh_epoch<F>(&mut self, new_epoch: EpochId, predicate: F) -> Vec<MemberId>
    where
        F: Fn(MemberId) -> bool,
    {
        let mut refreshed = Vec::new();
        for (peer_id, bindings) in &mut self.by_peer {
            if predicate(*peer_id) {
                for binding in bindings {
                    // Update both the by_peer copy and the by_session copy
                    binding.epoch = new_epoch;
                    if let Some(session_binding) = self.by_session.get_mut(&binding.session_id) {
                        session_binding.epoch = new_epoch;
                    }
                }
                refreshed.push(*peer_id);
            }
        }
        refreshed
    }
}

// ---------------------------------------------------------------------------
// binding_policy — derive SessionPolicy from MemberState
// ---------------------------------------------------------------------------

/// Derive the session lifecycle policy for a peer given its current
/// [`MemberState`].
///
/// This is a pure function with no side effects. Transport calls it
/// after membership state changes (epoch advance, failure detection,
/// drain notification) to decide what to do with sessions bound to
/// the affected peer.
///
/// ## Policy Mapping
///
/// - [`MemberState::Alive`] → [`SessionPolicy::Route`]
/// - [`MemberState::Suspected`] → [`SessionPolicy::Drain`]
/// - [`MemberState::Failed`] → [`SessionPolicy::Close`]
#[must_use]
pub fn binding_policy(state: MemberState) -> SessionPolicy {
    match state {
        MemberState::Alive => SessionPolicy::Route,
        MemberState::Suspected => SessionPolicy::Drain,
        MemberState::Failed => SessionPolicy::Close,
    }
}

/// Derive the admission policy for a peer that is not yet a member
/// (or is in the process of joining). This returns [`SessionPolicy::Admit`]
/// to signal that transport should allow new session establishment.
///
/// This is separate from [`binding_policy`] because admission is a
/// pre-membership decision; once a peer is an active member, transport
/// uses [`binding_policy`] with the peer's [`MemberState`].
#[must_use]
pub const fn admission_policy() -> SessionPolicy {
    SessionPolicy::Admit
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::MemberState;
    use tidefs_membership_epoch::{EpochId, MemberId};

    // ── binding_policy tests ──────────────────────────────────────

    #[test]
    fn alive_maps_to_route() {
        assert_eq!(binding_policy(MemberState::Alive), SessionPolicy::Route);
    }

    #[test]
    fn suspected_maps_to_drain() {
        assert_eq!(binding_policy(MemberState::Suspected), SessionPolicy::Drain);
    }

    #[test]
    fn failed_maps_to_close() {
        assert_eq!(binding_policy(MemberState::Failed), SessionPolicy::Close);
    }

    #[test]
    fn admission_policy_returns_admit() {
        assert_eq!(admission_policy(), SessionPolicy::Admit);
    }

    #[test]
    fn all_member_state_variants_covered() {
        // Every MemberState variant maps to a non-Admit policy.
        // Admit is only for pre-membership admission.
        let states = [
            MemberState::Alive,
            MemberState::Suspected,
            MemberState::Failed,
        ];
        for state in states {
            let policy = binding_policy(state);
            assert_ne!(
                policy,
                SessionPolicy::Admit,
                "{state:?} should not map to Admit"
            );
        }
    }

    // ── PeerSessionBinding tests ──────────────────────────────────

    #[test]
    fn binding_construction() {
        let b = PeerSessionBinding::new(1, MemberId::new(42), SessionId::new(100), EpochId::new(5));
        assert_eq!(b.binding_id, 1);
        assert_eq!(b.peer_id, MemberId::new(42));
        assert_eq!(b.session_id, SessionId::new(100));
        assert_eq!(b.epoch, EpochId::new(5));
    }

    // ── SessionBindingTable tests ─────────────────────────────────

    #[test]
    fn empty_table() {
        let table = SessionBindingTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn insert_and_lookup() {
        let mut table = SessionBindingTable::new();
        let b = PeerSessionBinding::new(1, MemberId::new(10), SessionId::new(200), EpochId::new(1));
        assert!(table.insert(b));
        assert_eq!(table.len(), 1);

        let found = table.get_by_session(SessionId::new(200));
        assert!(found.is_some());
        assert_eq!(found.unwrap().peer_id, MemberId::new(10));

        let peer_bindings = table.get_by_peer(MemberId::new(10));
        assert_eq!(peer_bindings.len(), 1);
        assert_eq!(peer_bindings[0].session_id, SessionId::new(200));
    }

    #[test]
    fn duplicate_session_id_rejected() {
        let mut table = SessionBindingTable::new();
        let b1 =
            PeerSessionBinding::new(1, MemberId::new(10), SessionId::new(200), EpochId::new(1));
        assert!(table.insert(b1));

        let b2 =
            PeerSessionBinding::new(2, MemberId::new(20), SessionId::new(200), EpochId::new(1));
        assert!(!table.insert(b2));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn multiple_sessions_per_peer() {
        let mut table = SessionBindingTable::new();
        for i in 0..3 {
            table.insert(PeerSessionBinding::new(
                i,
                MemberId::new(10),
                SessionId::new(100 + i),
                EpochId::new(1),
            ));
        }
        assert_eq!(table.len(), 3);
        assert_eq!(table.get_by_peer(MemberId::new(10)).len(), 3);

        // Peer with no bindings returns empty slice
        assert!(table.get_by_peer(MemberId::new(99)).is_empty());
    }

    #[test]
    fn remove_by_session() {
        let mut table = SessionBindingTable::new();
        table.insert(PeerSessionBinding::new(
            1,
            MemberId::new(10),
            SessionId::new(200),
            EpochId::new(1),
        ));

        let removed = table.remove(SessionId::new(200));
        assert!(removed.is_some());
        assert!(table.is_empty());
        assert!(table.get_by_session(SessionId::new(200)).is_none());
        assert!(table.get_by_peer(MemberId::new(10)).is_empty());

        // Removing non-existent is None
        assert!(table.remove(SessionId::new(999)).is_none());
    }

    #[test]
    fn remove_all_for_peer() {
        let mut table = SessionBindingTable::new();
        for i in 0..3 {
            table.insert(PeerSessionBinding::new(
                i,
                MemberId::new(10),
                SessionId::new(100 + i),
                EpochId::new(1),
            ));
        }
        // Add a binding for another peer
        table.insert(PeerSessionBinding::new(
            10,
            MemberId::new(20),
            SessionId::new(300),
            EpochId::new(1),
        ));
        assert_eq!(table.len(), 4);

        let removed = table.remove_all_for_peer(MemberId::new(10));
        assert_eq!(removed.len(), 3);
        assert_eq!(table.len(), 1);
        // Peer 10 bindings gone, peer 20 still present
        assert!(table.get_by_peer(MemberId::new(10)).is_empty());
        assert_eq!(table.get_by_peer(MemberId::new(20)).len(), 1);
    }

    #[test]
    fn peer_counts() {
        let mut table = SessionBindingTable::new();
        table.insert(PeerSessionBinding::new(
            1,
            MemberId::new(10),
            SessionId::new(100),
            EpochId::new(1),
        ));
        table.insert(PeerSessionBinding::new(
            2,
            MemberId::new(10),
            SessionId::new(101),
            EpochId::new(1),
        ));
        table.insert(PeerSessionBinding::new(
            3,
            MemberId::new(20),
            SessionId::new(200),
            EpochId::new(1),
        ));

        let counts: BTreeMap<MemberId, usize> = table.peer_counts().collect();
        assert_eq!(counts[&MemberId::new(10)], 2);
        assert_eq!(counts[&MemberId::new(20)], 1);
    }

    // ── Batch epoch refresh tests ─────────────────────────────────

    #[test]
    fn refresh_epoch_updates_matching_peers() {
        let mut table = SessionBindingTable::new();
        table.insert(PeerSessionBinding::new(
            1,
            MemberId::new(10),
            SessionId::new(100),
            EpochId::new(1),
        ));
        table.insert(PeerSessionBinding::new(
            2,
            MemberId::new(20),
            SessionId::new(200),
            EpochId::new(1),
        ));
        table.insert(PeerSessionBinding::new(
            3,
            MemberId::new(10),
            SessionId::new(101),
            EpochId::new(1),
        ));

        let new_epoch = EpochId::new(2);
        let refreshed = table.refresh_epoch(new_epoch, |peer_id| peer_id == MemberId::new(10));

        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0], MemberId::new(10));

        // Peer 10 bindings updated
        for sid in [100u64, 101u64] {
            let b = table.get_by_session(SessionId::new(sid)).unwrap();
            assert_eq!(b.epoch, EpochId::new(2));
        }
        // Peer 20 binding unchanged
        let b20 = table.get_by_session(SessionId::new(200)).unwrap();
        assert_eq!(b20.epoch, EpochId::new(1));
    }

    #[test]
    fn refresh_epoch_all_peers() {
        let mut table = SessionBindingTable::new();
        table.insert(PeerSessionBinding::new(
            1,
            MemberId::new(10),
            SessionId::new(100),
            EpochId::new(1),
        ));
        table.insert(PeerSessionBinding::new(
            2,
            MemberId::new(20),
            SessionId::new(200),
            EpochId::new(1),
        ));

        let refreshed = table.refresh_epoch(EpochId::new(3), |_| true);
        assert_eq!(refreshed.len(), 2);

        for sid in [100u64, 200u64] {
            let b = table.get_by_session(SessionId::new(sid)).unwrap();
            assert_eq!(b.epoch, EpochId::new(3));
        }
    }

    #[test]
    fn refresh_epoch_no_matches() {
        let mut table = SessionBindingTable::new();
        table.insert(PeerSessionBinding::new(
            1,
            MemberId::new(10),
            SessionId::new(100),
            EpochId::new(1),
        ));

        let refreshed = table.refresh_epoch(EpochId::new(5), |_| false);
        assert!(refreshed.is_empty());

        let b = table.get_by_session(SessionId::new(100)).unwrap();
        assert_eq!(b.epoch, EpochId::new(1));
    }

    // ── Integration scenario tests ────────────────────────────────

    #[test]
    fn admission_to_failure_lifecycle() {
        let mut table = SessionBindingTable::new();

        // Admit a peer
        let policy = admission_policy();
        assert_eq!(policy, SessionPolicy::Admit);

        // Insert binding after admission
        let peer = MemberId::new(42);
        table.insert(PeerSessionBinding::new(
            1,
            peer,
            SessionId::new(1000),
            EpochId::new(1),
        ));

        // Peer is alive → Route
        assert_eq!(binding_policy(MemberState::Alive), SessionPolicy::Route);

        // Peer becomes suspected → Drain
        assert_eq!(binding_policy(MemberState::Suspected), SessionPolicy::Drain);

        // Peer fails → Close, remove all sessions
        assert_eq!(binding_policy(MemberState::Failed), SessionPolicy::Close);
        let removed = table.remove_all_for_peer(peer);
        assert_eq!(removed.len(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn epoch_advance_policy_refresh() {
        let mut table = SessionBindingTable::new();

        // Create bindings for two peers in epoch 1
        table.insert(PeerSessionBinding::new(
            1,
            MemberId::new(10),
            SessionId::new(100),
            EpochId::new(1),
        ));
        table.insert(PeerSessionBinding::new(
            2,
            MemberId::new(20),
            SessionId::new(200),
            EpochId::new(1),
        ));

        // Epoch advances; refresh all bindings
        table.refresh_epoch(EpochId::new(2), |_| true);

        // Both bindings reflect new epoch
        assert_eq!(
            table.get_by_session(SessionId::new(100)).unwrap().epoch,
            EpochId::new(2)
        );
        assert_eq!(
            table.get_by_session(SessionId::new(200)).unwrap().epoch,
            EpochId::new(2)
        );
    }
}
