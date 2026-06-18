// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport session binding for joined nodes.
//!
//! After a successful join handshake, the joining node needs transport
//! sessions to communicate with existing pool members. This module
//! manages session allocation, epoch binding, and health tracking for
//! newly joined nodes.
//!
//! # Integration
//!
//! [`SessionBindingManager`] wraps [`tidefs_transport::transport_session_set::TransportSessionSet`]
//! with node-join-specific semantics:
//! - Sessions are bound to the epoch accepted during the join handshake
//! - All sessions share the same epoch for consistency
//! - Health tracking propagates to the join phase promotion pipeline
//! - Session teardown is coordinated (all sessions for a node together)

use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_transport::transport_session_set::{SessionHealth, TransportSessionSet};
use tidefs_transport::types::SessionId;

// ── Session allocation ───────────────────────────────────────────────

/// A request to allocate a transport session for a joined node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionAllocationRequest {
    /// The node requesting session allocation.
    pub member_id: MemberId,
    /// The peer to establish a session with.
    pub peer_id: MemberId,
    /// The epoch the session should be bound to.
    pub epoch: EpochId,
}

/// Result of a session allocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionAllocationResult {
    /// The allocated session ID (None if allocation failed).
    pub session_id: Option<SessionId>,
    /// Whether the session was successfully bound to the epoch.
    pub epoch_bound: bool,
    /// Reason for failure, if any.
    pub error: Option<String>,
}

impl SessionAllocationResult {
    /// Create a successful allocation result.
    #[must_use]
    pub fn success(session_id: SessionId) -> Self {
        Self {
            session_id: Some(session_id),
            epoch_bound: true,
            error: None,
        }
    }

    /// Create a failed allocation result.
    #[must_use]
    pub fn failure(reason: impl Into<String>) -> Self {
        Self {
            session_id: None,
            epoch_bound: false,
            error: Some(reason.into()),
        }
    }

    /// Whether the allocation was successful.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.session_id.is_some() && self.epoch_bound
    }
}

// ── Session binding manager ─────────────────────────────────────────

/// Manages transport session bindings for a joined node.
///
/// Wraps [`TransportSessionSet`] with:
/// - Epoch binding: all sessions are bound to the same epoch
/// - Coordinated teardown: remove all sessions for a node together
/// - Health propagation: session health feeds into join phase promotion
/// - Consistency checks: prevents binding sessions from different epochs
///
/// # Example
///
/// ```ignore
/// use tidefs_node_join::session_binding::SessionBindingManager;
/// use tidefs_membership_epoch::{MemberId, EpochId};
///
/// let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
/// mgr.add_binding(MemberId::new(2), tidefs_transport::types::SessionId::new(100));
/// assert!(mgr.is_bound_to(MemberId::new(2)));
/// ```
#[derive(Clone, Debug)]
pub struct SessionBindingManager {
    /// The node that owns these session bindings.
    pub member_id: MemberId,
    /// The epoch all sessions are bound to.
    pub bound_epoch: EpochId,
    /// The underlying session set.
    sessions: TransportSessionSet,
    /// Whether all sessions have been established (health != Unknown for all).
    pub is_established: bool,
    /// The join session epoch binding that authorizes these sessions.
    /// Set from the handshake; state transfer and promotion gates
    /// require this to be present and valid.
    pub session_epoch: Option<crate::JoinSessionEpoch>,
}

impl SessionBindingManager {
    /// Create a new session binding manager for a joined node.
    #[must_use]
    pub fn new(member_id: MemberId, bound_epoch: EpochId) -> Self {
        Self {
            member_id,
            bound_epoch,
            sessions: TransportSessionSet::new(),
            is_established: false,
            session_epoch: None,
        }
    }

    /// Attach the join session epoch binding to this manager.
    ///
    /// This must be called after the handshake produces quorum evidence.
    /// Session operations verify this binding before allowing state transfer.
    pub fn set_session_epoch(&mut self, session: crate::JoinSessionEpoch) {
        self.session_epoch = Some(session);
    }

    /// Whether session bindings can proceed: checks that the session
    /// epoch is valid for the given member and current epoch.
    #[must_use]
    pub fn can_bind_sessions(
        &self,
        current_epoch: EpochId,
    ) -> Result<(), crate::JoinError> {
        let session = self
            .session_epoch
            .as_ref()
            .ok_or_else(|| crate::JoinError::MissingEpochEvidence(
                "no session epoch recorded".into(),
            ))?;

        let _ = session.is_valid_for(self.member_id, current_epoch).map_err(|status| match status {
            crate::JoinStatus::WaitingForQuorum => crate::JoinError::QuorumNotReached {
                epoch: session.epoch,
                approvals: session.quorum_evidence.as_ref().map_or(0, |qe| qe.quorum_approvals),
                threshold: session.quorum_evidence.as_ref().map_or(1, |qe| qe.quorum_threshold),
            },
            crate::JoinStatus::StaleEpoch { current_epoch, join_epoch } => crate::JoinError::StaleEpoch {
                session_epoch: join_epoch,
                current_epoch,
                reason: "session binding blocked: stale epoch".into(),
            },
            crate::JoinStatus::IdentityMismatch { expected, actual } => crate::JoinError::IdentityMismatch {
                session_member: expected,
                caller_member: actual,
            },
            _ => crate::JoinError::PreflightDenied(format!("session binding blocked: {:?}", status)),
        })?;

        Ok(())
    }

    /// Add a session binding to a peer.
    ///
    /// The session is initially in Unknown health and must be marked
    /// healthy/unhealthy after connectivity is confirmed.
    pub fn add_binding(&mut self, peer_id: MemberId, session_id: SessionId) {
        self.sessions.add_binding(peer_id.0, session_id);
    }

    /// Remove a session binding for a peer.
    pub fn remove_binding(&mut self, peer_id: MemberId) {
        self.sessions.remove_node(peer_id.0);
        self.update_establishment();
    }

    /// Get the session ID for a peer, if bound.
    #[must_use]
    pub fn get_session(&self, peer_id: MemberId) -> Option<SessionId> {
        self.sessions.get_session(peer_id.0)
    }

    /// Whether this node has a session binding to the given peer.
    #[must_use]
    pub fn is_bound_to(&self, peer_id: MemberId) -> bool {
        self.sessions.has_node(peer_id.0)
    }

    /// Return all peer IDs with active bindings.
    #[must_use]
    pub fn bound_peers(&self) -> Vec<MemberId> {
        self.sessions
            .node_ids()
            .iter()
            .map(|&n| MemberId::new(n))
            .collect()
    }

    /// Return the number of active bindings.
    #[must_use]
    pub fn binding_count(&self) -> usize {
        self.sessions.len()
    }

    /// Mark a session as healthy (connectivity confirmed).
    /// Uses the session ID lookup to find and update the binding.
    pub fn mark_healthy(&mut self, peer_id: MemberId) {
        if let Some(sid) = self.sessions.get_session(peer_id.0) {
            self.sessions.mark_healthy(sid);
        }
        self.update_establishment();
    }

    /// Mark a session as unhealthy (disconnected or timed out).
    pub fn mark_unhealthy(&mut self, peer_id: MemberId) {
        if let Some(sid) = self.sessions.get_session(peer_id.0) {
            self.sessions.mark_unhealthy(sid);
        }
        self.update_establishment();
    }

    /// Get the health status of a session.
    #[must_use]
    pub fn session_health(&self, peer_id: MemberId) -> Option<SessionHealth> {
        self.sessions.health(peer_id.0)
    }

    /// Whether all sessions are healthy.
    #[must_use]
    pub fn all_healthy(&self) -> bool {
        if self.sessions.is_empty() {
            return false;
        }
        self.sessions
            .node_ids()
            .iter()
            .all(|&n| self.sessions.health(n) == Some(SessionHealth::Healthy))
    }

    /// Whether any session is unhealthy.
    #[must_use]
    pub fn any_unhealthy(&self) -> bool {
        self.sessions
            .node_ids()
            .iter()
            .any(|&n| self.sessions.health(n) == Some(SessionHealth::Unhealthy))
    }

    /// Count healthy and unhealthy sessions.
    #[must_use]
    pub fn health_counts(&self) -> (usize, usize, usize) {
        let mut healthy = 0;
        let mut unhealthy = 0;
        let mut unknown = 0;
        for &n in self.sessions.node_ids().iter() {
            match self.sessions.health(n) {
                Some(SessionHealth::Healthy) => healthy += 1,
                Some(SessionHealth::Unhealthy) => unhealthy += 1,
                Some(SessionHealth::Unknown) | None => unknown += 1,
            }
        }
        (healthy, unhealthy, unknown)
    }

    /// Tear down all session bindings. Since `TransportSessionSet` has no
    /// `clear()`, we remove each node individually.
    pub fn teardown_all(&mut self) {
        let ids: Vec<u64> = self.sessions.node_ids();
        for id in ids {
            self.sessions.remove_node(id);
        }
        self.is_established = false;
    }

    /// Tear down sessions for a specific peer.
    pub fn teardown_peer(&mut self, peer_id: MemberId) {
        self.sessions.remove_node(peer_id.0);
        self.update_establishment();
    }

    /// Whether all sessions have been established (no Unknown health).
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.is_established
    }

    /// Whether the node has any session bindings at all.
    #[must_use]
    pub fn has_any_sessions(&self) -> bool {
        !self.sessions.is_empty()
    }

    /// Allocate sessions for a newly joined node to all current pool members.
    ///
    /// This is a convenience method that iterates over the given peer list,
    /// assigns session IDs, and binds them all to the same epoch.
    /// In production, session IDs come from the transport layer after a
    /// successful handshake; this method uses a deterministic assignment
    /// for testing.
    pub fn allocate_sessions(
        &mut self,
        peers: &[MemberId],
        base_session_id: u64,
    ) -> Vec<SessionAllocationResult> {
        let mut results = Vec::with_capacity(peers.len());
        for (i, &peer) in peers.iter().enumerate() {
            let session_id = SessionId::new(base_session_id + i as u64);
            self.add_binding(peer, session_id);
            results.push(SessionAllocationResult::success(session_id));
        }
        results
    }

    /// Verify that all sessions are bound to the expected epoch.
    ///
    /// Returns an error if the bound epoch does not match.
    pub fn verify_epoch_binding(&self, expected_epoch: EpochId) -> Result<(), String> {
        if self.bound_epoch != expected_epoch {
            Err(format!(
                "epoch binding mismatch: sessions bound to {:?}, expected {:?}",
                self.bound_epoch, expected_epoch
            ))
        } else {
            Ok(())
        }
    }

    /// Update the establishment flag based on current session health.
    fn update_establishment(&mut self) {
        if self.sessions.is_empty() {
            self.is_established = false;
            return;
        }
        // Established if all sessions have known health (not Unknown)
        self.is_established = self
            .sessions
            .node_ids()
            .iter()
            .all(|&n| self.sessions.health(n) != Some(SessionHealth::Unknown));
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_binding_manager_creation() {
        let mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        assert_eq!(mgr.member_id, MemberId::new(1));
        assert_eq!(mgr.bound_epoch, EpochId::new(5));
        assert!(!mgr.is_established);
        assert!(!mgr.has_any_sessions());
        assert_eq!(mgr.binding_count(), 0);
    }

    #[test]
    fn add_and_retrieve_binding() {
        let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        let sid = SessionId::new(100);

        mgr.add_binding(MemberId::new(2), sid);
        assert!(mgr.is_bound_to(MemberId::new(2)));
        assert_eq!(mgr.get_session(MemberId::new(2)), Some(sid));
        assert_eq!(mgr.binding_count(), 1);
        assert!(!mgr.is_bound_to(MemberId::new(3)));
    }

    #[test]
    fn remove_binding() {
        let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        let sid = SessionId::new(100);

        mgr.add_binding(MemberId::new(2), sid);
        assert_eq!(mgr.binding_count(), 1);

        mgr.remove_binding(MemberId::new(2));
        assert!(!mgr.is_bound_to(MemberId::new(2)));
        assert_eq!(mgr.binding_count(), 0);
    }

    #[test]
    fn bound_peers_returns_all() {
        let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        mgr.add_binding(MemberId::new(2), SessionId::new(100));
        mgr.add_binding(MemberId::new(3), SessionId::new(101));
        mgr.add_binding(MemberId::new(4), SessionId::new(102));

        let peers = mgr.bound_peers();
        assert_eq!(peers.len(), 3);
        assert!(peers.contains(&MemberId::new(2)));
        assert!(peers.contains(&MemberId::new(3)));
        assert!(peers.contains(&MemberId::new(4)));
    }

    #[test]
    fn session_health_tracking() {
        let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        mgr.add_binding(MemberId::new(2), SessionId::new(100));
        mgr.add_binding(MemberId::new(3), SessionId::new(101));

        // Both Unknown initially
        assert!(!mgr.all_healthy());
        assert!(!mgr.is_established());
        let (h, u, uk) = mgr.health_counts();
        assert_eq!((h, u, uk), (0, 0, 2));

        // Mark one healthy
        mgr.mark_healthy(MemberId::new(2));
        assert!(!mgr.all_healthy());
        assert!(!mgr.is_established());
        let (h, u, uk) = mgr.health_counts();
        assert_eq!((h, u, uk), (1, 0, 1));

        // Mark other healthy → all healthy, established
        mgr.mark_healthy(MemberId::new(3));
        assert!(mgr.all_healthy());
        assert!(mgr.is_established());
        let (h, u, uk) = mgr.health_counts();
        assert_eq!((h, u, uk), (2, 0, 0));
    }

    #[test]
    fn session_unhealthy_tracking() {
        let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        mgr.add_binding(MemberId::new(2), SessionId::new(100));
        mgr.add_binding(MemberId::new(3), SessionId::new(101));

        mgr.mark_healthy(MemberId::new(2));
        mgr.mark_unhealthy(MemberId::new(3));

        assert!(!mgr.all_healthy());
        assert!(mgr.any_unhealthy());
        assert!(mgr.is_established());
        let (h, u, uk) = mgr.health_counts();
        assert_eq!((h, u, uk), (1, 1, 0));
    }

    #[test]
    fn teardown_all_clears_bindings() {
        let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        mgr.add_binding(MemberId::new(2), SessionId::new(100));
        mgr.add_binding(MemberId::new(3), SessionId::new(101));
        mgr.mark_healthy(MemberId::new(2));
        mgr.mark_healthy(MemberId::new(3));
        assert!(mgr.is_established());

        mgr.teardown_all();
        assert!(!mgr.is_established());
        assert_eq!(mgr.binding_count(), 0);
        assert!(!mgr.has_any_sessions());
    }

    #[test]
    fn teardown_peer_removes_single() {
        let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        mgr.add_binding(MemberId::new(2), SessionId::new(100));
        mgr.add_binding(MemberId::new(3), SessionId::new(101));

        mgr.teardown_peer(MemberId::new(2));
        assert!(!mgr.is_bound_to(MemberId::new(2)));
        assert!(mgr.is_bound_to(MemberId::new(3)));
        assert_eq!(mgr.binding_count(), 1);
    }

    #[test]
    fn allocate_sessions_deterministic() {
        let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        let peers = vec![MemberId::new(2), MemberId::new(3), MemberId::new(4)];

        let results = mgr.allocate_sessions(&peers, 500);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.is_success()));

        assert_eq!(mgr.get_session(MemberId::new(2)), Some(SessionId::new(500)));
        assert_eq!(mgr.get_session(MemberId::new(3)), Some(SessionId::new(501)));
        assert_eq!(mgr.get_session(MemberId::new(4)), Some(SessionId::new(502)));
        assert_eq!(mgr.binding_count(), 3);
    }

    #[test]
    fn verify_epoch_binding_success() {
        let mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        assert!(mgr.verify_epoch_binding(EpochId::new(5)).is_ok());
    }

    #[test]
    fn verify_epoch_binding_mismatch() {
        let mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        let err = mgr.verify_epoch_binding(EpochId::new(10)).unwrap_err();
        assert!(err.contains("epoch binding mismatch"));
    }

    #[test]
    fn session_allocation_result_success_and_failure() {
        let success = SessionAllocationResult::success(SessionId::new(42));
        assert!(success.is_success());
        assert_eq!(success.session_id, Some(SessionId::new(42)));
        assert!(success.epoch_bound);

        let failure = SessionAllocationResult::failure("no capacity");
        assert!(!failure.is_success());
        assert_eq!(failure.session_id, None);
        assert!(!failure.epoch_bound);
        assert_eq!(failure.error, Some("no capacity".into()));
    }

    // ── Integration: session binding with handshake flow ───────────

    #[test]
    fn session_binding_after_successful_handshake() {
        use crate::discovery::{
            DiscoveryResponse, JoinHandshake, JoinHandshakeConfig, JoinHandshakeResponse,
        };
        use tidefs_membership_epoch::NodeIdentity;

        // Simulate a successful handshake
        let mut handshake =
            JoinHandshake::new(NodeIdentity::new(1), JoinHandshakeConfig::default(), 0);
        handshake.probe_sent(1000).unwrap();
        handshake
            .on_discovery_response(
                &DiscoveryResponse::new(EpochId::new(10), true, MemberId::new(2), 42),
                2000,
            )
            .unwrap();
        handshake
            .on_join_response(
                &JoinHandshakeResponse::accept(MemberId::new(1), EpochId::new(10)),
                3000,
            )
            .unwrap();
        assert!(handshake.is_active());

        // Now bind sessions for the joined node
        let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(10));
        let peers = vec![MemberId::new(2), MemberId::new(3)];
        let results = mgr.allocate_sessions(&peers, 1000);
        assert!(results.iter().all(|r| r.is_success()));

        // Verify epoch binding consistency
        assert!(mgr.verify_epoch_binding(EpochId::new(10)).is_ok());

        // Mark sessions healthy
        mgr.mark_healthy(MemberId::new(2));
        mgr.mark_healthy(MemberId::new(3));
        assert!(mgr.all_healthy());
        assert!(mgr.is_established());
    }

    #[test]
    fn session_binding_teardown_on_failed_join() {
        let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(10));
        let peers = vec![MemberId::new(2), MemberId::new(3)];
        mgr.allocate_sessions(&peers, 2000);
        mgr.mark_healthy(MemberId::new(2));
        mgr.mark_healthy(MemberId::new(3));
        assert!(mgr.is_established());

        // Join fails → tear down all sessions
        mgr.teardown_all();
        assert!(!mgr.is_established());
        assert!(!mgr.has_any_sessions());
    }

    #[test]
    fn session_binding_duplicate_join_prevention() {
        let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(10));
        let peers = vec![MemberId::new(2)];
        mgr.allocate_sessions(&peers, 100);

        // Adding the same peer again replaces the old binding
        mgr.add_binding(MemberId::new(2), SessionId::new(999));
        assert_eq!(mgr.get_session(MemberId::new(2)), Some(SessionId::new(999)));
        assert_eq!(mgr.binding_count(), 1);
    }

    #[test]
    fn session_binding_health_reset_on_rebind() {
        let mut mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(10));
        mgr.add_binding(MemberId::new(2), SessionId::new(100));
        mgr.mark_healthy(MemberId::new(2));
        assert!(mgr.all_healthy());

        // Rebind with new session ID — health resets to Unknown
        mgr.add_binding(MemberId::new(2), SessionId::new(200));
        assert!(!mgr.all_healthy());
        assert_eq!(
            mgr.session_health(MemberId::new(2)),
            Some(SessionHealth::Unknown)
        );
    }

    #[test]
    fn session_allocation_result_serialization() {
        let result = SessionAllocationResult::success(SessionId::new(42));
        let json = bincode::serialize(&result).unwrap();
        let back: SessionAllocationResult = bincode::deserialize(&json).unwrap();
        assert_eq!(back, result);
        assert!(back.is_success());

        let fail = SessionAllocationResult::failure("timeout");
        let json2 = bincode::serialize(&fail).unwrap();
        let back2: SessionAllocationResult = bincode::deserialize(&json2).unwrap();
        assert_eq!(back2, fail);
        assert!(!back2.is_success());
    }

    #[test]
    fn empty_manager_all_healthy_is_false() {
        let mgr = SessionBindingManager::new(MemberId::new(1), EpochId::new(5));
        // No bindings → all_healthy returns false
        assert!(!mgr.all_healthy());
        assert!(!mgr.any_unhealthy());
        let (h, u, uk) = mgr.health_counts();
        assert_eq!((h, u, uk), (0, 0, 0));
    }
}
