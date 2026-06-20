// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport session set: binds node identities to active transport sessions.
//!
//! [`TransportSessionSet`] maps node IDs to [`SessionId`] values and provides
//! basic health tracking. It is the integration point between the placement
//! planner's [`NodePlacement`] output and the transport layer's session
//! management: placement selects which nodes an object belongs on, and this
//! set maps those node IDs to the active sessions that carry the write/read
//! traffic.
//!
//! # Health tracking
//!
//! Each binding carries a health status. Sessions are marked healthy when
//! the transport layer confirms connectivity; they are marked unhealthy on
//! disconnection or timeout. The health status guides write quorum decisions
//! and read replica selection.

use crate::types::SessionId;
use std::collections::BTreeMap;

/// Health status of a session binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionHealth {
    /// Session is healthy and can carry traffic.
    Healthy,
    /// Session has been marked as unhealthy (disconnected, timed out).
    Unhealthy,
    /// Session connectivity is unknown (initial state).
    Unknown,
}

/// A binding between a node ID and a transport session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    /// The transport session identifier.
    pub session_id: SessionId,
    /// Current health status of this binding.
    pub health: SessionHealth,
    /// The membership epoch this binding was established at.
    pub epoch: u64,
}

/// Maps node identities to active transport sessions, with basic health
/// tracking for write quorum and read replica selection.
///
/// # Example
///
/// ```ignore
/// use tidefs_transport::transport_session_set::TransportSessionSet;
/// use tidefs_transport::types::SessionId;
///
/// let mut set = TransportSessionSet::new();
/// set.add_binding(1, SessionId::new(101));
/// set.add_binding(2, SessionId::new(102));
///
/// assert_eq!(set.get_session(1), Some(SessionId::new(101)));
/// assert!(set.has_node(1));
/// ```
#[derive(Debug, Clone, Default)]
pub struct TransportSessionSet {
    /// Node ID to session binding.
    bindings: BTreeMap<u64, SessionBinding>,
    /// Reverse index: session ID to node ID.
    session_to_node: BTreeMap<SessionId, u64>,
}

impl TransportSessionSet {
    /// Create an empty session set.
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
            session_to_node: BTreeMap::new(),
        }
    }

    /// Add or update a binding from a node ID to a transport session.
    ///
    /// If a binding already exists for this node, it is replaced and the
    /// old session is removed from the reverse index. If the session ID
    /// was previously bound to a different node, that old binding is also
    /// cleaned up.
    pub fn add_binding(&mut self, node_id: u64, session_id: SessionId) {
        self.add_binding_with_epoch(node_id, session_id, 0);
    }

    /// Add or update a binding and record the committed membership epoch.
    ///
    /// Runtime membership wiring should use this method once committed
    /// epoch evidence is available so session tracking does not default to
    /// epoch 0 on live paths.
    pub fn add_binding_with_epoch(&mut self, node_id: u64, session_id: SessionId, epoch: u64) {
        // Clean up old session-to-node binding if this session was
        // previously bound to a different node.
        if let Some(&old_node) = self.session_to_node.get(&session_id) {
            if old_node != node_id {
                self.bindings.remove(&old_node);
            }
        }

        // Clean up old node-to-session binding if this node had a
        // different session.
        if let Some(old_binding) = self.bindings.get(&node_id) {
            if old_binding.session_id != session_id {
                self.session_to_node.remove(&old_binding.session_id);
            }
        }

        self.bindings.insert(
            node_id,
            SessionBinding {
                session_id,
                health: SessionHealth::Unknown,
                epoch,
            },
        );
        self.session_to_node.insert(session_id, node_id);
    }

    /// Return the session ID bound to a node, if any.
    pub fn get_session(&self, node_id: u64) -> Option<SessionId> {
        self.bindings.get(&node_id).map(|b| b.session_id)
    }

    /// Return the binding (session + health) for a node, if any.
    pub fn get_binding(&self, node_id: u64) -> Option<&SessionBinding> {
        self.bindings.get(&node_id)
    }

    /// Return the node ID that owns a session, if any.
    pub fn lookup_node(&self, session_id: SessionId) -> Option<u64> {
        self.session_to_node.get(&session_id).copied()
    }

    /// Check whether a node has an active binding in this set.
    pub fn has_node(&self, node_id: u64) -> bool {
        self.bindings.contains_key(&node_id)
    }

    /// Return the number of bindings in this set.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Return whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Remove a node and its session binding.
    ///
    /// Returns the removed session ID if a binding existed.
    pub fn remove_node(&mut self, node_id: u64) -> Option<SessionId> {
        let binding = self.bindings.remove(&node_id)?;
        self.session_to_node.remove(&binding.session_id);
        Some(binding.session_id)
    }

    /// Mark a session as healthy.
    pub fn mark_healthy(&mut self, session_id: SessionId) {
        if let Some(&node_id) = self.session_to_node.get(&session_id) {
            if let Some(binding) = self.bindings.get_mut(&node_id) {
                binding.health = SessionHealth::Healthy;
            }
        }
    }

    /// Mark a session as unhealthy.
    pub fn mark_unhealthy(&mut self, session_id: SessionId) {
        if let Some(&node_id) = self.session_to_node.get(&session_id) {
            if let Some(binding) = self.bindings.get_mut(&node_id) {
                binding.health = SessionHealth::Unhealthy;
            }
        }
    }

    /// Return the health status of a node's session binding.
    pub fn health(&self, node_id: u64) -> Option<SessionHealth> {
        self.bindings.get(&node_id).map(|b| b.health)
    }

    /// Return a sorted list of all node IDs that have a session binding.
    pub fn node_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.bindings.keys().copied().collect();
        ids.sort();
        ids
    }

    /// Return the subset of node IDs whose sessions are healthy.
    pub fn healthy_node_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .bindings
            .iter()
            .filter(|(_, b)| b.health == SessionHealth::Healthy)
            .map(|(n, _)| *n)
            .collect();
        ids.sort();
        ids
    }

    /// Return the subset of node IDs whose sessions are unhealthy.
    pub fn unhealthy_node_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .bindings
            .iter()
            .filter(|(_, b)| b.health == SessionHealth::Unhealthy)
            .map(|(n, _)| *n)
            .collect();
        ids.sort();
        ids
    }

    /// Return an iterator over (node_id, &SessionBinding) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &SessionBinding)> {
        self.bindings.iter().map(|(k, v)| (*k, v))
    }

    /// Set the membership epoch for a session binding.
    ///
    /// Updated when the membership epoch advances and the
    /// session is still active for this peer.
    pub fn set_epoch(&mut self, session_id: SessionId, epoch: u64) {
        if let Some(node_id) = self.session_to_node.get(&session_id) {
            if let Some(binding) = self.bindings.get_mut(node_id) {
                binding.epoch = epoch;
            }
        }
    }

    /// Get the membership epoch for a session binding.
    ///
    /// Returns `None` if the session ID is not bound to any node.
    #[must_use]
    pub fn get_epoch(&self, session_id: SessionId) -> Option<u64> {
        let node_id = self.session_to_node.get(&session_id)?;
        self.bindings.get(node_id).map(|b| b.epoch)
    }

    /// Get the membership epoch for a node binding.
    ///
    /// Returns `None` if the node has no binding.
    #[must_use]
    pub fn get_epoch_for_node(&self, node_id: u64) -> Option<u64> {
        self.bindings.get(&node_id).map(|b| b.epoch)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(v: u64) -> SessionId {
        SessionId::new(v)
    }

    #[test]
    fn add_and_get() {
        let mut set = TransportSessionSet::new();
        set.add_binding(1, sid(100));
        assert_eq!(set.get_session(1), Some(sid(100)));
        assert_eq!(set.get_session(2), None);
    }

    #[test]
    fn add_binding_with_epoch_tracks_committed_epoch() {
        let mut set = TransportSessionSet::new();
        set.add_binding_with_epoch(1, sid(100), 7);
        assert_eq!(set.get_session(1), Some(sid(100)));
        assert_eq!(set.get_epoch(sid(100)), Some(7));
        assert_eq!(set.get_epoch_for_node(1), Some(7));
    }

    #[test]
    fn has_node() {
        let mut set = TransportSessionSet::new();
        assert!(!set.has_node(1));
        set.add_binding(1, sid(100));
        assert!(set.has_node(1));
    }

    #[test]
    fn lookup_node_reverse_index() {
        let mut set = TransportSessionSet::new();
        set.add_binding(1, sid(100));
        set.add_binding(2, sid(200));
        assert_eq!(set.lookup_node(sid(100)), Some(1));
        assert_eq!(set.lookup_node(sid(200)), Some(2));
        assert_eq!(set.lookup_node(sid(999)), None);
    }

    #[test]
    fn replace_binding() {
        let mut set = TransportSessionSet::new();
        set.add_binding(1, sid(100));
        set.add_binding(1, sid(200));
        assert_eq!(set.get_session(1), Some(sid(200)));
        assert_eq!(set.lookup_node(sid(100)), None);
        assert_eq!(set.lookup_node(sid(200)), Some(1));
    }

    #[test]
    fn reassign_session_to_new_node() {
        let mut set = TransportSessionSet::new();
        set.add_binding(1, sid(100));
        set.add_binding(2, sid(100)); // session 100 moves from node 1 to node 2
        assert_eq!(set.lookup_node(sid(100)), Some(2));
        assert_eq!(set.get_session(1), None);
        assert_eq!(set.get_session(2), Some(sid(100)));
    }

    #[test]
    fn remove_node() {
        let mut set = TransportSessionSet::new();
        set.add_binding(1, sid(100));
        set.add_binding(2, sid(200));
        assert_eq!(set.len(), 2);

        let removed = set.remove_node(1);
        assert_eq!(removed, Some(sid(100)));
        assert_eq!(set.len(), 1);
        assert!(!set.has_node(1));
        assert_eq!(set.lookup_node(sid(100)), None);
    }

    #[test]
    fn remove_nonexistent() {
        let mut set = TransportSessionSet::new();
        assert_eq!(set.remove_node(99), None);
    }

    #[test]
    fn health_tracking() {
        let mut set = TransportSessionSet::new();
        set.add_binding(1, sid(100));
        set.add_binding(2, sid(200));

        // Initial health is Unknown.
        assert_eq!(set.health(1), Some(SessionHealth::Unknown));
        assert_eq!(set.health(2), Some(SessionHealth::Unknown));

        set.mark_healthy(sid(100));
        assert_eq!(set.health(1), Some(SessionHealth::Healthy));
        assert_eq!(set.health(2), Some(SessionHealth::Unknown));

        set.mark_unhealthy(sid(200));
        assert_eq!(set.health(2), Some(SessionHealth::Unhealthy));
    }

    #[test]
    fn mark_healthy_nonexistent_session() {
        let mut set = TransportSessionSet::new();
        // Should not panic.
        set.mark_healthy(sid(999));
        set.mark_unhealthy(sid(999));
    }

    #[test]
    fn healthy_and_unhealthy_node_ids() {
        let mut set = TransportSessionSet::new();
        set.add_binding(1, sid(100));
        set.add_binding(2, sid(200));
        set.add_binding(3, sid(300));

        set.mark_healthy(sid(100));
        set.mark_healthy(sid(300));
        set.mark_unhealthy(sid(200));

        let expected_healthy: Vec<u64> = vec![1, 3];
        assert_eq!(set.healthy_node_ids(), expected_healthy);
        let expected_unhealthy: Vec<u64> = vec![2];
        assert_eq!(set.unhealthy_node_ids(), expected_unhealthy);
    }

    #[test]
    fn node_ids_sorted() {
        let mut set = TransportSessionSet::new();
        set.add_binding(3, sid(300));
        set.add_binding(1, sid(100));
        set.add_binding(2, sid(200));
        let expected: Vec<u64> = vec![1, 2, 3];
        assert_eq!(set.node_ids(), expected);
    }

    #[test]
    fn iterator() {
        let mut set = TransportSessionSet::new();
        set.add_binding(1, sid(100));
        set.add_binding(2, sid(200));

        let mut nodes: Vec<u64> = set.iter().map(|(n, _)| n).collect();
        nodes.sort();
        assert_eq!(nodes, vec![1, 2]);
    }

    #[test]
    fn empty_set() {
        let set = TransportSessionSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        let empty: Vec<u64> = vec![];
        assert_eq!(set.node_ids(), empty);
        let empty_healthy: Vec<u64> = vec![];
        assert_eq!(set.healthy_node_ids(), empty_healthy);
        let empty_unhealthy: Vec<u64> = vec![];
        assert_eq!(set.unhealthy_node_ids(), empty_unhealthy);
    }

    #[test]
    fn get_binding_returns_health() {
        let mut set = TransportSessionSet::new();
        set.add_binding(1, sid(100));
        set.mark_healthy(sid(100));

        let binding = set.get_binding(1).unwrap();
        assert_eq!(binding.session_id, sid(100));
        assert_eq!(binding.health, SessionHealth::Healthy);
    }

    #[test]
    fn multiple_operations_consistent() {
        let mut set = TransportSessionSet::new();

        // Add 5 nodes.
        for i in 0..5 {
            set.add_binding(i, sid(1000 + i));
        }
        assert_eq!(set.len(), 5);

        // Mark alternating health.
        for i in 0..5 {
            if i % 2 == 0 {
                set.mark_healthy(sid(1000 + i));
            } else {
                set.mark_unhealthy(sid(1000 + i));
            }
        }

        assert_eq!(set.healthy_node_ids(), vec![0, 2, 4]);
        assert_eq!(set.unhealthy_node_ids(), vec![1, 3]);

        // Remove a node and verify cleanup.
        set.remove_node(2);
        assert_eq!(set.len(), 4);
        assert_eq!(set.lookup_node(sid(1002)), None);
        assert_eq!(set.healthy_node_ids(), vec![0, 4]);
    }
}
