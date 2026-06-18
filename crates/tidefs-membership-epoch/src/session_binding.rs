// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport-session to membership-roster binding.
//!
//! When a transport session is established between two TideFS storage nodes,
//! [`SessionAcceptor`] verifies the peer identity against the current
//! committed roster and registers the binding in [`RosterSessionRegistry`].
//! Downstream subsystems (placement, replication, rebuild) resolve sessions
//! to cluster members through the registry.
//!
//! # Integration
//!
//! 1. Create a shared [`RosterSessionRegistry`] wrapped in
//!    `Arc<RwLock<...>>` and a [`SessionAcceptor`] that holds it.
//! 2. On transport connection accept, extract the peer node id and the
//!    current [`crate::epoch_commit_subscriber::CommittedRoster`], then
//!    call [`SessionAcceptor::accept`].
//! 3. On transport connection close, call
//!    [`SessionAcceptor::disconnect`].
//! 4. Placement, replication, and rebuild consumers call
//!    [`RosterSessionRegistry::lookup`] to map a session to its member.

use std::collections::{BTreeMap, BTreeSet};
use tidefs_membership_types::MemberIdentity;

// ---------------------------------------------------------------------------
// RosterSessionRegistry
// ---------------------------------------------------------------------------

/// Maps transport session ids to verified [`MemberIdentity`] entries.
///
/// The registry is the authoritative source for session-to-member mapping.
/// It rejects duplicate session registrations, supports bulk eviction of
/// stale-epoch bindings, and provides both forward (session→member) and
/// reverse (member→sessions) lookups.
#[derive(Clone, Debug, Default)]
pub struct RosterSessionRegistry {
    /// session_id → MemberIdentity
    sessions: BTreeMap<u64, MemberIdentity>,
    /// node_id → set of session ids
    member_sessions: BTreeMap<u64, BTreeSet<u64>>,
}

impl RosterSessionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a session-to-member binding.
    ///
    /// # Errors
    ///
    /// Returns `SessionBindingError::DuplicateSession` if `session_id` is
    /// already registered.
    pub fn register(
        &mut self,
        session_id: u64,
        identity: MemberIdentity,
    ) -> Result<(), SessionBindingError> {
        if self.sessions.contains_key(&session_id) {
            return Err(SessionBindingError::DuplicateSession { session_id });
        }
        self.sessions.insert(session_id, identity);
        self.member_sessions
            .entry(identity.node_id)
            .or_default()
            .insert(session_id);
        Ok(())
    }

    /// Remove a session binding (called on disconnect).
    ///
    /// Returns the identity that was bound, or `None` if not registered.
    pub fn unregister(&mut self, session_id: u64) -> Option<MemberIdentity> {
        let identity = self.sessions.remove(&session_id)?;
        if let Some(sessions) = self.member_sessions.get_mut(&identity.node_id) {
            sessions.remove(&session_id);
            if sessions.is_empty() {
                self.member_sessions.remove(&identity.node_id);
            }
        }
        Some(identity)
    }

    /// Look up the [`MemberIdentity`] bound to a session.
    #[must_use]
    pub fn lookup(&self, session_id: u64) -> Option<&MemberIdentity> {
        self.sessions.get(&session_id)
    }

    /// Find all session ids bound to a given member node.
    #[must_use]
    pub fn lookup_by_member(&self, node_id: u64) -> Vec<u64> {
        self.member_sessions
            .get(&node_id)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Remove all sessions bound to identities from the given epoch or older.
    ///
    /// This is called after an epoch transition to evict bindings that were
    /// established under a stale epoch.
    pub fn evict_stale_epoch(&mut self, current_epoch: u64) -> usize {
        let stale: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, id)| id.verified_epoch < current_epoch)
            .map(|(sid, _)| *sid)
            .collect();
        let count = stale.len();
        for sid in &stale {
            self.unregister(*sid);
        }
        count
    }

    /// Number of active session bindings.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Number of distinct members with active sessions.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.member_sessions.len()
    }
}

// ---------------------------------------------------------------------------
// SessionAcceptor
// ---------------------------------------------------------------------------

/// Verifies transport session identities against a committed roster and
/// manages the session-to-member registry.
///
/// The acceptor is intended to be called from the transport connection-accept
/// path. On each new connection it checks the peer identity against the
/// current roster and, if valid, registers the session binding. On disconnect
/// it unregisters.
#[derive(Clone, Debug)]
pub struct SessionAcceptor {
    /// Shared registry for session-to-member mappings.
    pub registry: std::sync::Arc<std::sync::RwLock<RosterSessionRegistry>>,
    /// Current committed member ids (sorted, deduplicated). Updated on
    /// epoch transitions via [`SessionAcceptor::update_roster`].
    roster_members: BTreeSet<u64>,
    /// Current epoch number.
    current_epoch: u64,
}

impl SessionAcceptor {
    /// Create a new acceptor with an empty roster.
    #[must_use]
    pub fn new(registry: std::sync::Arc<std::sync::RwLock<RosterSessionRegistry>>) -> Self {
        Self {
            registry,
            roster_members: BTreeSet::new(),
            current_epoch: 0,
        }
    }

    /// Update the known roster after an epoch transition.
    ///
    /// Member ids are sorted and deduplicated internally. This also evicts
    /// session bindings from prior epochs from the registry.
    pub fn update_roster(&mut self, epoch: u64, member_ids: &[u64]) {
        self.current_epoch = epoch;
        self.roster_members = member_ids.iter().copied().collect();
        // Evict bindings from older epochs
        if let Ok(mut reg) = self.registry.write() {
            reg.evict_stale_epoch(epoch);
        }
    }

    /// Accept a new transport session: verify the peer identity against the
    /// current roster and, if valid, register the binding.
    ///
    /// # Errors
    ///
    /// Returns [`SessionBindingError::MemberNotInRoster`] if the peer's
    /// node_id is not in the current committed roster.
    ///
    /// Returns [`SessionBindingError::StaleEpoch`] if the identity's
    /// verified_epoch is older than the current epoch.
    ///
    /// Returns [`SessionBindingError::DuplicateSession`] if the session_id
    /// is already registered.
    pub fn accept(
        &self,
        session_id: u64,
        identity: MemberIdentity,
    ) -> Result<(), SessionBindingError> {
        // Verify the peer is in the current roster
        if !self.roster_members.contains(&identity.node_id) {
            return Err(SessionBindingError::MemberNotInRoster {
                node_id: identity.node_id,
                epoch: self.current_epoch,
            });
        }

        // Verify the epoch is current
        if identity.verified_epoch < self.current_epoch {
            return Err(SessionBindingError::StaleEpoch {
                identity_epoch: identity.verified_epoch,
                current_epoch: self.current_epoch,
            });
        }

        let mut reg = self
            .registry
            .write()
            .expect("RosterSessionRegistry lock poisoned");
        reg.register(session_id, identity)
    }

    /// Unregister a session binding on disconnect.
    pub fn disconnect(&self, session_id: u64) -> Option<MemberIdentity> {
        let mut reg = self
            .registry
            .write()
            .expect("RosterSessionRegistry lock poisoned");
        reg.unregister(session_id)
    }

    /// Look up the member identity bound to a session.
    #[must_use]
    pub fn lookup(&self, session_id: u64) -> Option<MemberIdentity> {
        let reg = self
            .registry
            .read()
            .expect("RosterSessionRegistry lock poisoned");
        reg.lookup(session_id).copied()
    }

    /// Return the current epoch number.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Return the current roster member count.
    #[must_use]
    pub fn roster_size(&self) -> usize {
        self.roster_members.len()
    }
}

impl Default for SessionAcceptor {
    fn default() -> Self {
        Self::new(std::sync::Arc::new(std::sync::RwLock::new(
            RosterSessionRegistry::new(),
        )))
    }
}

// ---------------------------------------------------------------------------
// SessionBindingError
// ---------------------------------------------------------------------------

/// Errors from session-to-member binding operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionBindingError {
    /// The session id is already registered.
    DuplicateSession { session_id: u64 },
    /// The peer node id is not in the current committed roster.
    MemberNotInRoster { node_id: u64, epoch: u64 },
    /// The identity was verified in a stale epoch.
    StaleEpoch {
        identity_epoch: u64,
        current_epoch: u64,
    },
}

impl std::fmt::Display for SessionBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateSession { session_id } => {
                write!(f, "session {session_id} is already bound to a member")
            }
            Self::MemberNotInRoster { node_id, epoch } => {
                write!(
                    f,
                    "node {node_id} is not in the current roster (epoch {epoch})"
                )
            }
            Self::StaleEpoch {
                identity_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "identity epoch {identity_epoch} is stale (current epoch {current_epoch})"
                )
            }
        }
    }
}

impl std::error::Error for SessionBindingError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::RwLock;

    // ── RosterSessionRegistry ────────────────────────────────────────

    #[test]
    fn registry_register_and_lookup() {
        let mut reg = RosterSessionRegistry::new();
        let id = MemberIdentity::new(10, 5);
        reg.register(100, id).unwrap();
        assert_eq!(reg.lookup(100), Some(&id));
        assert_eq!(reg.session_count(), 1);
        assert_eq!(reg.member_count(), 1);
    }

    #[test]
    fn registry_lookup_by_member() {
        let mut reg = RosterSessionRegistry::new();
        reg.register(100, MemberIdentity::new(10, 5)).unwrap();
        reg.register(200, MemberIdentity::new(10, 5)).unwrap();
        reg.register(300, MemberIdentity::new(20, 5)).unwrap();

        let sessions_10 = reg.lookup_by_member(10);
        assert_eq!(sessions_10.len(), 2);
        assert!(sessions_10.contains(&100));
        assert!(sessions_10.contains(&200));

        let sessions_20 = reg.lookup_by_member(20);
        assert_eq!(sessions_20, vec![300]);
    }

    #[test]
    fn registry_lookup_by_member_unknown() {
        let reg = RosterSessionRegistry::new();
        assert!(reg.lookup_by_member(999).is_empty());
    }

    #[test]
    fn registry_unregister() {
        let mut reg = RosterSessionRegistry::new();
        let id = MemberIdentity::new(10, 5);
        reg.register(100, id).unwrap();

        let removed = reg.unregister(100);
        assert_eq!(removed, Some(id));
        assert_eq!(reg.lookup(100), None);
        assert_eq!(reg.session_count(), 0);
        assert_eq!(reg.member_count(), 0);
    }

    #[test]
    fn registry_unregister_unknown() {
        let mut reg = RosterSessionRegistry::new();
        assert_eq!(reg.unregister(999), None);
    }

    #[test]
    fn registry_unregister_preserves_other_sessions_for_same_member() {
        let mut reg = RosterSessionRegistry::new();
        reg.register(100, MemberIdentity::new(10, 5)).unwrap();
        reg.register(200, MemberIdentity::new(10, 5)).unwrap();

        reg.unregister(100);
        // Member 10 should still have session 200
        assert_eq!(reg.lookup_by_member(10), vec![200]);
        assert_eq!(reg.member_count(), 1);
    }

    #[test]
    fn registry_rejects_duplicate_session() {
        let mut reg = RosterSessionRegistry::new();
        reg.register(100, MemberIdentity::new(10, 5)).unwrap();
        let result = reg.register(100, MemberIdentity::new(20, 5));
        assert!(matches!(
            result,
            Err(SessionBindingError::DuplicateSession { session_id: 100 })
        ));
    }

    #[test]
    fn registry_lookup_after_unregister_returns_none() {
        let mut reg = RosterSessionRegistry::new();
        reg.register(100, MemberIdentity::new(10, 5)).unwrap();
        reg.unregister(100);
        assert_eq!(reg.lookup(100), None);
    }

    #[test]
    fn registry_evict_stale_epoch() {
        let mut reg = RosterSessionRegistry::new();
        reg.register(100, MemberIdentity::new(10, 1)).unwrap();
        reg.register(200, MemberIdentity::new(20, 3)).unwrap();
        reg.register(300, MemberIdentity::new(30, 5)).unwrap();

        let evicted = reg.evict_stale_epoch(4);
        assert_eq!(evicted, 2); // sessions from epoch 1 and 3
        assert_eq!(reg.lookup(100), None);
        assert_eq!(reg.lookup(200), None);
        assert_eq!(reg.lookup(300), Some(&MemberIdentity::new(30, 5)));
    }

    #[test]
    fn registry_evict_stale_epoch_none_when_all_current() {
        let mut reg = RosterSessionRegistry::new();
        reg.register(100, MemberIdentity::new(10, 5)).unwrap();
        reg.register(200, MemberIdentity::new(20, 5)).unwrap();

        let evicted = reg.evict_stale_epoch(5);
        assert_eq!(evicted, 0);
        assert_eq!(reg.session_count(), 2);
    }

    // ── SessionAcceptor ──────────────────────────────────────────────

    fn make_acceptor(epoch: u64, members: &[u64]) -> SessionAcceptor {
        let reg = Arc::new(RwLock::new(RosterSessionRegistry::new()));
        let mut acceptor = SessionAcceptor::new(reg);
        acceptor.update_roster(epoch, members);
        acceptor
    }

    #[test]
    fn acceptor_accept_valid_identity() {
        let acceptor = make_acceptor(5, &[10, 20, 30]);
        let id = MemberIdentity::new(10, 5);
        acceptor.accept(100, id).unwrap();
        assert_eq!(acceptor.lookup(100), Some(id));
    }

    #[test]
    fn acceptor_rejects_non_roster_member() {
        let acceptor = make_acceptor(5, &[10, 20]);
        let id = MemberIdentity::new(99, 5); // not in roster
        let result = acceptor.accept(100, id);
        assert!(matches!(
            result,
            Err(SessionBindingError::MemberNotInRoster {
                node_id: 99,
                epoch: 5,
            })
        ));
    }

    #[test]
    fn acceptor_rejects_stale_epoch() {
        let acceptor = make_acceptor(5, &[10, 20]);
        let id = MemberIdentity::new(10, 3); // stale epoch
        let result = acceptor.accept(100, id);
        assert!(matches!(
            result,
            Err(SessionBindingError::StaleEpoch {
                identity_epoch: 3,
                current_epoch: 5,
            })
        ));
    }

    #[test]
    fn acceptor_rejects_duplicate_session() {
        let acceptor = make_acceptor(5, &[10, 20]);
        acceptor.accept(100, MemberIdentity::new(10, 5)).unwrap();
        let result = acceptor.accept(100, MemberIdentity::new(20, 5));
        assert!(matches!(
            result,
            Err(SessionBindingError::DuplicateSession { session_id: 100 })
        ));
    }

    #[test]
    fn acceptor_disconnect_removes_binding() {
        let acceptor = make_acceptor(5, &[10, 20]);
        let id = MemberIdentity::new(10, 5);
        acceptor.accept(100, id).unwrap();

        let removed = acceptor.disconnect(100);
        assert_eq!(removed, Some(id));
        assert_eq!(acceptor.lookup(100), None);
    }

    #[test]
    fn acceptor_disconnect_unknown_session() {
        let acceptor = make_acceptor(5, &[10, 20]);
        assert_eq!(acceptor.disconnect(999), None);
    }

    #[test]
    fn acceptor_update_roster_evicts_stale_bindings() {
        let acceptor = make_acceptor(3, &[10, 20]);
        let id_old = MemberIdentity::new(10, 3);
        acceptor.accept(100, id_old).unwrap();

        // Advance epoch - should evict old binding
        let _acceptor_mut = make_acceptor(3, &[10, 20]);
        // Clone the Arc to share registry with the original
        let reg = acceptor.registry.clone();
        let mut acc2 = SessionAcceptor::new(reg);
        acc2.update_roster(4, &[10, 20, 30]);

        assert_eq!(acc2.lookup(100), None);
    }

    #[test]
    fn acceptor_roster_size() {
        let acceptor = make_acceptor(5, &[10, 20, 30, 40]);
        assert_eq!(acceptor.roster_size(), 4);
    }

    #[test]
    fn acceptor_current_epoch() {
        let acceptor = make_acceptor(7, &[10]);
        assert_eq!(acceptor.current_epoch(), 7);
    }

    #[test]
    fn acceptor_accept_future_epoch_is_ok() {
        // Identity verified at epoch 10 when current is 5: not stale
        let acceptor = make_acceptor(5, &[10]);
        let id = MemberIdentity::new(10, 10);
        // The identity epoch is ahead - this is accepted (optimistic)
        acceptor.accept(100, id).unwrap();
        assert_eq!(acceptor.lookup(100), Some(id));
    }

    // ── Multiple concurrent operations ───────────────────────────────

    #[test]
    fn registry_multiple_members_multiple_sessions() {
        let mut reg = RosterSessionRegistry::new();
        for i in 0..10 {
            reg.register(i, MemberIdentity::new(i / 2, 5)).unwrap();
        }
        assert_eq!(reg.session_count(), 10);
        assert_eq!(reg.member_count(), 5);

        for m in 0..5u64 {
            let sessions = reg.lookup_by_member(m);
            assert_eq!(sessions.len(), 2);
        }
    }
}
