// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;

use crate::addr::TransportAddr;
use crate::session::Session;
use crate::types::SessionId;
use tidefs_types_transport_session::CohortClass;
use tidefs_types_transport_session::EndpointFamily;

// ---------------------------------------------------------------------------
// TransportCohortId — stable transport cohort identifier
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// Stable transport cohort identifier (u64 wrapper).
pub struct TransportCohortId(pub u64);

impl TransportCohortId {
    #[must_use]
    /// Return the zero cohort ID.
    pub const fn zero() -> Self {
        Self(0)
    }

    #[must_use]
    /// Create a new TransportCohortId from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for TransportCohortId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// SessionCohortGraph: cohort-based session population (P8-01 §6)
// ---------------------------------------------------------------------------

/// The session cohort graph tracks which nodes belong to which P8-01 cohort
/// classes (k0–k7).  `targeted_peers()` returns every other node that shares
/// at least one cohort class with the local node — the caller then decides
/// which session classes and lane budgets to open on each edge.
///
/// P8-01 §6.2 rule: "A session may not invent a one-off population label in
/// its payload body. If a path needs a population, it must attach to a
/// declared cohort class."
pub struct SessionCohortGraph {
    /// Registered nodes indexed by node ID.
    pub nodes: BTreeMap<u64, NodeInfo>,
    /// Active sessions keyed by (local_node, peer_node, endpoint_family).
    pub sessions: BTreeMap<(u64, u64, u32), Session>,
    next_session_id: u64,
}

impl SessionCohortGraph {
    #[must_use]
    /// Create a new empty session cohort graph.
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            sessions: BTreeMap::new(),
            next_session_id: 1,
        }
    }

    /// Add a node to the cohort graph.
    pub fn add_node(&mut self, info: NodeInfo) {
        self.nodes.insert(info.node_id, info);
    }

    /// Remove a node and close all its sessions.
    pub fn remove_node(&mut self, node_id: u64) {
        self.nodes.remove(&node_id);
        self.sessions
            .retain(|(local, peer, _ep), _| *local != node_id && *peer != node_id);
    }

    /// Generate a new session ID.
    pub fn next_session_id(&mut self) -> SessionId {
        let id = SessionId::new(self.next_session_id);
        self.next_session_id += 1;
        id
    }

    /// Return peers that share at least one cohort class with `node_id`.
    /// P8-01 §6.2: sessions must attach to declared cohort classes (k0–k7),
    /// not invent topology-driven populations.
    #[must_use]
    pub fn targeted_peers(&self, node_id: u64) -> Vec<u64> {
        let Some(local) = self.nodes.get(&node_id) else {
            return Vec::new();
        };

        if local.cohort_memberships.is_empty() {
            return Vec::new();
        }

        // P8-01 §6.2: A session must attach to a declared cohort class.
        // targeted_peers returns every other node that shares at least one
        // cohort class with the local node — the caller then decides which
        // session classes and lane budgets to open on each edge.
        self.nodes
            .iter()
            .filter(|(peer_id, peer_info)| {
                *peer_id != &node_id
                    && peer_info
                        .cohort_memberships
                        .iter()
                        .any(|c| local.cohort_memberships.contains(c))
            })
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }

    /// Count active sessions for a node.
    #[must_use]
    pub fn session_count(&self, node_id: u64) -> usize {
        self.sessions
            .keys()
            .filter(|(local, _peer, _ep)| *local == node_id)
            .count()
    }

    /// Whether a node can establish more sessions (cap enforced by the
    /// transport layer, not embedded in the cohort graph).
    #[must_use]
    pub fn can_establish_session(&self, node_id: u64) -> bool {
        // P8-01 migration: per-session-class budget is enforced at the
        // transport / lane-budget level.  The cohort graph itself no longer
        // carries a flat max_sessions policy.
        const DEFAULT_MAX: usize = 100;
        self.session_count(node_id) < DEFAULT_MAX
    }

    /// Find nodes that are in the same cohort(s) as `node_id` but are
    /// missing a session from the cohort graph perspective.
    #[must_use]
    pub fn missing_sessions(&self, node_id: u64) -> Vec<u64> {
        let targets = self.targeted_peers(node_id);
        targets
            .into_iter()
            .filter(|peer| {
                !self.sessions.contains_key(&(node_id, *peer, 0))
                    && !self.sessions.contains_key(&(*peer, node_id, 0))
            })
            .collect()
    }
}

impl Default for SessionCohortGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SessionCohortGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "SessionCohortGraph {{ nodes: {}, sessions: {} }}",
            self.nodes.len(),
            self.sessions.len()
        ))
    }
}

// ---------------------------------------------------------------------------
// NodeInfo: a node in the session cohort graph
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
/// Node metadata in the session cohort graph (P8-01 §6).
pub struct NodeInfo {
    pub node_id: u64,
    pub addresses: Vec<TransportAddr>,
    pub failure_domain_id: u64,
    /// Endpoint family (e0..e3 per P8-01 §4).
    pub endpoint_family: EndpointFamily,
    /// P8-01 cohort classes (k0–k7) this node belongs to.
    pub cohort_memberships: Vec<CohortClass>,
}

impl NodeInfo {
    /// Create a node with default k0 (PeerPair) cohort membership.
    #[must_use]
    pub fn new(node_id: u64, addresses: Vec<TransportAddr>, failure_domain_id: u64) -> Self {
        Self::with_cohorts(
            node_id,
            addresses,
            failure_domain_id,
            vec![CohortClass::PeerPair],
        )
    }

    /// Create a node with explicit cohort memberships.
    #[must_use]
    pub fn with_cohorts(
        node_id: u64,
        addresses: Vec<TransportAddr>,
        failure_domain_id: u64,
        cohort_memberships: Vec<CohortClass>,
    ) -> Self {
        Self {
            node_id,
            addresses,
            failure_domain_id,
            cohort_memberships,
            endpoint_family: EndpointFamily::LocalEmbed,
        }
    }

    /// Create a NodeInfo with an explicit endpoint family.
    #[must_use]
    pub fn with_endpoint(
        node_id: u64,
        addresses: Vec<TransportAddr>,
        failure_domain_id: u64,
        endpoint_family: EndpointFamily,
    ) -> Self {
        Self::with_cohorts(
            node_id,
            addresses,
            failure_domain_id,
            vec![CohortClass::PeerPair],
        )
        .with_endpoint_family(endpoint_family)
    }

    /// Set the endpoint family on an existing NodeInfo.
    #[must_use]
    pub fn with_endpoint_family(mut self, family: EndpointFamily) -> Self {
        self.endpoint_family = family;
        self
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::TransportBackendKind;

    #[test]
    fn targeted_peers_by_cohort() {
        let mut graph = SessionCohortGraph::new();

        // Nodes 1 & 2 share PeerPair and AuthorityDomainControl
        graph.add_node(NodeInfo::with_cohorts(
            1,
            vec![],
            0,
            vec![CohortClass::PeerPair, CohortClass::AuthorityDomainControl],
        ));
        graph.add_node(NodeInfo::with_cohorts(
            2,
            vec![],
            0,
            vec![CohortClass::PeerPair, CohortClass::AuthorityDomainControl],
        ));
        // Node 3 only in ReplicaSet
        graph.add_node(NodeInfo::with_cohorts(
            3,
            vec![],
            0,
            vec![CohortClass::ReplicaSet],
        ));

        // Node 1 sees node 2 (shared cohorts) but not node 3
        let peers = graph.targeted_peers(1);
        assert_eq!(peers, vec![2]);
    }

    #[test]
    fn targeted_peers_no_shared_cohorts() {
        let mut graph = SessionCohortGraph::new();
        graph.add_node(NodeInfo::with_cohorts(
            1,
            vec![],
            0,
            vec![CohortClass::PeerPair],
        ));
        graph.add_node(NodeInfo::with_cohorts(
            2,
            vec![],
            0,
            vec![CohortClass::ReplicaSet],
        ));

        assert!(graph.targeted_peers(1).is_empty());
        assert!(graph.targeted_peers(2).is_empty());
    }

    #[test]
    fn targeted_peers_unknown_node() {
        let graph = SessionCohortGraph::new();
        assert!(graph.targeted_peers(99).is_empty());
    }

    #[test]
    fn targeted_peers_multiple_cohort_overlap() {
        let mut graph = SessionCohortGraph::new();

        // Node 1: PeerPair
        graph.add_node(NodeInfo::with_cohorts(
            1,
            vec![],
            0,
            vec![CohortClass::PeerPair],
        ));
        // Node 2: PeerPair + AuthorityDomainControl
        graph.add_node(NodeInfo::with_cohorts(
            2,
            vec![],
            0,
            vec![CohortClass::PeerPair, CohortClass::AuthorityDomainControl],
        ));
        // Node 3: AuthorityDomainControl only
        graph.add_node(NodeInfo::with_cohorts(
            3,
            vec![],
            0,
            vec![CohortClass::AuthorityDomainControl],
        ));

        // Node 1 sees node 2 (shared PeerPair), not node 3
        assert_eq!(graph.targeted_peers(1), vec![2]);
        // Node 2 sees nodes 1 (PeerPair) and 3 (AuthorityDomainControl)
        let mut peers2 = graph.targeted_peers(2);
        peers2.sort();
        assert_eq!(peers2, vec![1, 3]);
    }

    #[test]
    fn node_with_empty_cohorts_sees_nothing() {
        let mut graph = SessionCohortGraph::new();
        graph.add_node(NodeInfo::with_cohorts(1, vec![], 0, vec![]));
        graph.add_node(NodeInfo::with_cohorts(
            2,
            vec![],
            0,
            vec![CohortClass::PeerPair],
        ));

        assert!(graph.targeted_peers(1).is_empty());
    }

    #[test]
    fn missing_sessions_excludes_established() {
        let mut graph = SessionCohortGraph::new();
        graph.add_node(NodeInfo::with_cohorts(
            1,
            vec![],
            0,
            vec![CohortClass::PeerPair],
        ));
        graph.add_node(NodeInfo::with_cohorts(
            2,
            vec![],
            0,
            vec![CohortClass::PeerPair],
        ));

        // Initially node 1 is missing a session to node 2
        assert_eq!(graph.missing_sessions(1), vec![2]);

        // Establish the session
        graph.sessions.insert(
            (1, 2, 0),
            Session::new(
                SessionId::new(1),
                1,
                2,
                TransportAddr::Tcp("127.0.0.1:9000".parse().unwrap()),
                EndpointFamily::LocalEmbed,
                TransportBackendKind::Tcp,
            ),
        );
        assert!(graph.missing_sessions(1).is_empty());
    }
}
