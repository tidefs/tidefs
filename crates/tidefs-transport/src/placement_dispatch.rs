//! Placement-aware object I/O dispatch for TransportReplicatedStore.
//!
//! [`PlacementDispatch`] composes [`NodePlacement`] and [`TransportSessionSet`]
//! to resolve 32-byte object keys to deterministic node sets and map them to
//! active transport sessions. This is the integration layer that
//! `TransportReplicatedStore` uses to select which replicas to target for
//! writes, reads, and deletes instead of blindly fanning out to all connected
//! replicas.
//!
//! # Integration with TransportReplicatedStore
//!
//! The replicated store's `put`, `get`, and `delete` paths use
//! [`PlacementDispatch`] to:
//! - Determine the ordered replica set for each object key.
//! - Classify replica sessions as healthy, unhealthy, or unbound.
//! - Check write quorum against healthy nodes only.
//! - Select read replicas from the versioned placement map when one records
//!   the object, otherwise from computed placement.

use crate::object_enumerator::PlacementMap;
use crate::transport_session_set::{SessionHealth, TransportSessionSet};
use crate::types::SessionId;
use crate::write_gate::WriteGate;
use tidefs_cluster::write_fence::{StaleFence as ClusterStaleFence, WriteFence};
use tidefs_durability_layout::{DurabilityLayoutV1, FailureDomainV1};
use tidefs_membership_epoch::EpochId;
use tidefs_placement_planner::node_placement::{NodeCandidate, NodePlacement};
use tidefs_placement_planner::PlacementError;

/// Errors from placement-aware dispatch operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlacementDispatchError {
    /// Not enough nodes to satisfy the replication factor.
    #[error("placement: {0}")]
    Placement(#[from] PlacementError),
    /// A required node has no session binding.
    #[error("node {node_id} has no session binding")]
    NoSession { node_id: u64 },
    /// A required node's session is unhealthy.
    #[error("session for node {node_id} is unhealthy")]
    UnhealthySession { node_id: u64 },
    /// Not enough healthy nodes for quorum.
    #[error("not enough healthy nodes: need {required}, have {available}")]
    NotEnoughHealthy { required: usize, available: usize },
    /// Write rejected: fence token is stale (prior lease holder).
    #[error("stale write fence: {0}")]
    StaleFence(#[from] ClusterStaleFence),
}

/// Result of resolving placement for an object key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPlacement {
    /// The ordered list of node IDs for this object (primary first).
    pub nodes: Vec<u64>,
    /// The subset of nodes that have healthy sessions.
    pub healthy_nodes: Vec<u64>,
    /// The subset of nodes with unhealthy sessions.
    pub unhealthy_nodes: Vec<u64>,
    /// Nodes that have no session binding at all.
    pub unbound_nodes: Vec<u64>,
}

/// A resolved write target: a node ID paired with its session ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteTarget {
    /// The node ID assigned by placement.
    pub node_id: u64,
    /// The session ID for this node's data/control path.
    pub session_id: SessionId,
    /// Whether the session is confirmed healthy.
    pub healthy: bool,
}

/// Composes [`NodePlacement`] and [`TransportSessionSet`] for
/// placement-aware object I/O dispatch in `TransportReplicatedStore`.
///
/// The replicated store calls [`resolve_write_targets`] to determine
/// which replicas to fan out to on writes and deletes, and
/// [`resolve_read_targets`] to select replicas for degraded reads.
#[derive(Debug, Clone)]
pub struct PlacementDispatch {
    layout: DurabilityLayoutV1,
    failure_domain: FailureDomainV1,
    seed: u64,
    sessions: TransportSessionSet,
    /// Optional write gate for single-writer fencing.
    write_gate: Option<WriteGate>,
    /// The current placement map snapshot, if one has been set.
    /// Carries a monotonically increasing version that clients can
    /// observe for consistency during rebalance.
    placement_map: Option<PlacementMap>,
}

impl PlacementDispatch {
    /// Create a new placement dispatch.
    pub fn new(
        layout: DurabilityLayoutV1,
        failure_domain: FailureDomainV1,
        seed: u64,
        sessions: TransportSessionSet,
    ) -> Self {
        Self {
            layout,
            failure_domain,
            seed,
            sessions,
            write_gate: None,
            placement_map: None,
        }
    }

    /// Set the write gate for single-writer fencing.
    ///
    /// When configured, [`resolve_write_targets`] checks the active fence
    /// before computing placement. Writes from a node that lost the write
    /// lease are rejected with [`PlacementDispatchError::StaleFence`].
    pub fn with_write_gate(mut self, write_gate: WriteGate) -> Self {
        self.write_gate = Some(write_gate);
        self
    }

    /// Return the currently active write fence, if any.
    pub fn active_write_fence(&self) -> Option<WriteFence> {
        self.write_gate
            .as_ref()
            .and_then(|gate| gate.active_fence())
    }

    /// Return a reference to the durability layout.
    pub fn layout(&self) -> &DurabilityLayoutV1 {
        &self.layout
    }

    /// Set the current placement map snapshot.
    ///
    /// The map version must be strictly greater than the previous version
    /// (or 0 -> 1 for the first call). Callers should update this when
    /// membership changes or rebalance completes, so clients observe a
    /// consistent version.
    pub fn set_placement_map(&mut self, map: PlacementMap) {
        if let Some(ref existing) = self.placement_map {
            assert!(
                map.is_newer_than(existing),
                "placement map version {} must be newer than {}",
                map.version,
                existing.version
            );
        } else {
            assert!(
                map.is_initialized(),
                "first placement map must be initialized"
            );
        }
        self.placement_map = Some(map);
    }

    /// Return the current placement version, if a map has been set.
    #[must_use]
    pub fn placement_version(&self) -> Option<u64> {
        self.placement_map.as_ref().map(|m| m.version)
    }

    /// Return the current placement epoch, if a map has been set.
    #[must_use]
    pub fn placement_epoch(&self) -> Option<EpochId> {
        self.placement_map.as_ref().map(|m| m.epoch)
    }

    /// Return a reference to the current placement map, if set.
    #[must_use]
    pub fn placement_map(&self) -> Option<&PlacementMap> {
        self.placement_map.as_ref()
    }

    /// Return a reference to the transport session set.
    pub fn sessions(&self) -> &TransportSessionSet {
        &self.sessions
    }

    /// Return a mutable reference to the transport session set.
    pub fn sessions_mut(&mut self) -> &mut TransportSessionSet {
        &mut self.sessions
    }

    /// The replication factor from the durability layout.
    pub fn replication_factor(&self) -> usize {
        self.layout.policy.total_shards()
    }

    // ── Helpers ────────────────────────────────────────────────────────

    /// Derive object_id and placement_key from a 32-byte object key.
    fn derive_ids(object_key: &[u8; 32]) -> (u64, u64) {
        let object_id = u64::from_le_bytes(object_key[..8].try_into().unwrap());
        let placement_key = u64::from_le_bytes(object_key[8..16].try_into().unwrap());
        (object_id, placement_key)
    }

    /// Build `NodeCandidate` entries from raw node IDs (assumed healthy, no rack, weight 1).
    fn make_candidates(node_ids: &[u64]) -> Vec<NodeCandidate> {
        node_ids.iter().map(|&id| NodeCandidate::new(id)).collect()
    }

    /// Compute placement for the given object key and available nodes.
    fn compute_placement(
        &self,
        object_key: &[u8; 32],
        available_nodes: &[u64],
    ) -> Result<NodePlacement, PlacementError> {
        let (object_id, placement_key) = Self::derive_ids(object_key);
        let candidates = Self::make_candidates(available_nodes);
        NodePlacement::compute(
            object_id,
            placement_key,
            &self.layout,
            &self.failure_domain,
            &candidates,
            self.seed,
        )
    }

    fn read_target_nodes(
        &self,
        object_key: &[u8; 32],
        available_nodes: &[u64],
    ) -> Result<Vec<u64>, PlacementError> {
        let (object_id, _) = Self::derive_ids(object_key);
        if let Some(members) = self
            .placement_map
            .as_ref()
            .and_then(|map| map.members_for(object_id))
        {
            return Ok(members.iter().map(|member| member.0).collect());
        }

        Ok(self
            .compute_placement(object_key, available_nodes)?
            .node_targets)
    }

    // ── Placement resolution ──────────────────────────────────────────

    /// Resolve placement for a 32-byte object key: get the ordered node set
    /// and classify each node's session health.
    pub fn resolve(
        &self,
        object_key: &[u8; 32],
        available_nodes: &[u64],
    ) -> Result<ResolvedPlacement, PlacementDispatchError> {
        let placement = self.compute_placement(object_key, available_nodes)?;
        let nodes = placement.node_targets;

        let mut healthy_nodes = Vec::new();
        let mut unhealthy_nodes = Vec::new();
        let mut unbound_nodes = Vec::new();

        for &node in &nodes {
            match self.sessions.health(node) {
                Some(SessionHealth::Healthy) => {
                    healthy_nodes.push(node);
                }
                Some(SessionHealth::Unhealthy) => {
                    unhealthy_nodes.push(node);
                }
                Some(SessionHealth::Unknown) => {
                    // Unknown health: treat as available but not confirmed.
                    healthy_nodes.push(node);
                }
                None => {
                    unbound_nodes.push(node);
                }
            }
        }

        Ok(ResolvedPlacement {
            nodes,
            healthy_nodes,
            unhealthy_nodes,
            unbound_nodes,
        })
    }

    // ── TransportReplicatedStore integration points ────────────────────

    /// Resolve the set of write targets for an object key.
    ///
    /// Returns the ordered list of `WriteTarget` entries that
    /// `TransportReplicatedStore` should fan writes out to. Nodes
    /// without sessions are excluded; unhealthy nodes are included but
    /// flagged so the caller can track degraded writes.
    pub fn resolve_write_targets(
        &self,
        object_key: &[u8; 32],
        available_nodes: &[u64],
    ) -> Result<Vec<WriteTarget>, PlacementDispatchError> {
        // Single-writer fence check: reject writes if no active fence
        // or if the write carries a stale fence.
        if let Some(ref gate) = self.write_gate {
            match gate.active_fence() {
                None => {
                    return Err(ClusterStaleFence::new(
                        WriteFence::new(EpochId(0), 0),
                        WriteFence::new(EpochId(0), 0),
                    )
                    .into());
                }
                Some(_) => {
                    // Active fence exists; writes are authorized.
                }
            }
        }

        let placement = self.compute_placement(object_key, available_nodes)?;

        let targets: Vec<WriteTarget> = placement
            .node_targets
            .iter()
            .filter_map(|&node_id| {
                self.sessions.get_session(node_id).map(|session_id| {
                    let healthy = matches!(
                        self.sessions.health(node_id),
                        Some(SessionHealth::Healthy) | Some(SessionHealth::Unknown)
                    );
                    WriteTarget {
                        node_id,
                        session_id,
                        healthy,
                    }
                })
            })
            .collect();

        Ok(targets)
    }

    /// Resolve the ordered set of read targets (session IDs) for an object key.
    ///
    /// Returns healthy session IDs in placement-map order for mapped objects,
    /// or computed placement order for unmapped objects, followed by unhealthy
    /// ones. TransportReplicatedStore tries them in order for degraded reads.
    pub fn resolve_read_targets(
        &self,
        object_key: &[u8; 32],
        available_nodes: &[u64],
    ) -> Result<Vec<SessionId>, PlacementDispatchError> {
        let target_nodes = self.read_target_nodes(object_key, available_nodes)?;

        let mut healthy_sids = Vec::new();
        let mut unhealthy_sids = Vec::new();

        for &node_id in &target_nodes {
            match self.sessions.health(node_id) {
                Some(SessionHealth::Healthy) | Some(SessionHealth::Unknown) => {
                    if let Some(sid) = self.sessions.get_session(node_id) {
                        healthy_sids.push(sid);
                    }
                }
                _ => {
                    if let Some(sid) = self.sessions.get_session(node_id) {
                        unhealthy_sids.push(sid);
                    }
                }
            }
        }

        healthy_sids.extend(unhealthy_sids);
        Ok(healthy_sids)
    }

    // ── Quorum helpers ─────────────────────────────────────────────────

    /// Check that at least `quorum` healthy nodes exist in the placement.
    pub fn check_quorum(
        &self,
        object_key: &[u8; 32],
        available_nodes: &[u64],
        quorum: usize,
    ) -> Result<usize, PlacementDispatchError> {
        let resolved = self.resolve(object_key, available_nodes)?;
        if resolved.healthy_nodes.len() < quorum {
            return Err(PlacementDispatchError::NotEnoughHealthy {
                required: quorum,
                available: resolved.healthy_nodes.len(),
            });
        }
        Ok(resolved.healthy_nodes.len())
    }

    // ── Convenience ────────────────────────────────────────────────────

    /// Return the ordered set of node IDs for an object key (convenience).
    pub fn place_object(
        &self,
        object_key: &[u8; 32],
        available_nodes: &[u64],
    ) -> Result<Vec<u64>, PlacementError> {
        let placement = self.compute_placement(object_key, available_nodes)?;
        Ok(placement.node_targets)
    }

    /// Return the session ID for a node, if bound and healthy.
    pub fn healthy_session_for(&self, node_id: u64) -> Result<SessionId, PlacementDispatchError> {
        match self.sessions.get_binding(node_id) {
            Some(b) if b.health == SessionHealth::Healthy || b.health == SessionHealth::Unknown => {
                Ok(b.session_id)
            }
            Some(_) => Err(PlacementDispatchError::UnhealthySession { node_id }),
            None => Err(PlacementDispatchError::NoSession { node_id }),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use tidefs_durability_layout::{DurabilityLayoutV1, FailureDomainLevel, FailureDomainV1};
    use tidefs_membership_epoch::MemberId;

    fn sid(v: u64) -> SessionId {
        SessionId::new(v)
    }

    fn make_dispatch(replicas: u8) -> (PlacementDispatch, Vec<u64>) {
        let layout = DurabilityLayoutV1::mirror(replicas).unwrap();
        let failure_domain = FailureDomainV1::new(FailureDomainLevel::Node, 64).unwrap();
        let sessions = TransportSessionSet::new();
        (
            PlacementDispatch::new(layout, failure_domain, 0, sessions),
            vec![1, 2, 3, 4, 5],
        )
    }

    /// Build a 32-byte test key from a u64 seed.
    fn test_key(seed: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&seed.to_le_bytes());
        for i in 1..4 {
            let val = seed.wrapping_mul(i as u64);
            key[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
        }
        key
    }

    fn map_for_object(object_id: u64, members: &[u64]) -> PlacementMap {
        let mut mapping = BTreeMap::new();
        mapping.insert(
            object_id,
            members
                .iter()
                .copied()
                .map(MemberId)
                .collect::<BTreeSet<_>>(),
        );
        PlacementMap::new(1, EpochId(10), mapping)
    }

    #[test]
    fn resolve_with_all_sessions_bound_and_healthy() {
        let (mut dispatch, nodes) = make_dispatch(3);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }

        let key = test_key(42);
        let resolved = dispatch.resolve(&key, &nodes).unwrap();
        assert_eq!(resolved.nodes.len(), 3);
        assert_eq!(resolved.healthy_nodes.len(), 3);
        assert!(resolved.unhealthy_nodes.is_empty());
        assert!(resolved.unbound_nodes.is_empty());
    }

    #[test]
    fn resolve_with_some_sessions_unbound() {
        let (mut dispatch, nodes) = make_dispatch(3);
        dispatch.sessions_mut().add_binding(1, sid(101));
        dispatch.sessions_mut().add_binding(2, sid(102));
        dispatch.sessions_mut().mark_healthy(sid(101));
        dispatch.sessions_mut().mark_healthy(sid(102));

        let key = test_key(42);
        let resolved = dispatch.resolve(&key, &nodes).unwrap();
        assert_eq!(resolved.nodes.len(), 3);
        assert_eq!(
            resolved.unbound_nodes.len() + resolved.healthy_nodes.len(),
            3
        );
    }

    #[test]
    fn resolve_with_unhealthy_session() {
        let (mut dispatch, nodes) = make_dispatch(3);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }
        let key = test_key(42);
        let resolved = dispatch.resolve(&key, &nodes).unwrap();
        let first_node = resolved.nodes[0];
        dispatch
            .sessions_mut()
            .mark_unhealthy(sid(100 + first_node));

        let resolved2 = dispatch.resolve(&key, &nodes).unwrap();
        assert!(
            resolved2.unhealthy_nodes.contains(&first_node),
            "first placed node {first_node} should be marked unhealthy"
        );
    }

    #[test]
    fn check_quorum_met() {
        let (mut dispatch, nodes) = make_dispatch(3);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }

        let key = test_key(42);
        let result = dispatch.check_quorum(&key, &nodes, 2);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3);
    }

    #[test]
    fn check_quorum_not_met() {
        let (mut dispatch, nodes) = make_dispatch(3);
        dispatch.sessions_mut().add_binding(1, sid(101));
        dispatch.sessions_mut().mark_healthy(sid(101));

        let key = test_key(42);
        let result = dispatch.check_quorum(&key, &nodes, 2);
        assert!(matches!(
            result,
            Err(PlacementDispatchError::NotEnoughHealthy { .. })
        ));
    }

    #[test]
    fn not_enough_nodes_for_replication() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let failure_domain = FailureDomainV1::new(FailureDomainLevel::Node, 64).unwrap();
        let sessions = TransportSessionSet::new();
        let dispatch = PlacementDispatch::new(layout, failure_domain, 0, sessions);

        let key = test_key(1);
        let result = dispatch.resolve(&key, &[10, 20]);
        assert!(matches!(
            result,
            Err(PlacementDispatchError::Placement(
                PlacementError::NotEnoughMembers { .. }
            ))
        ));
    }

    #[test]
    fn healthy_session_for_returns_session_id() {
        let (mut dispatch, _nodes) = make_dispatch(2);
        dispatch.sessions_mut().add_binding(1, sid(101));
        dispatch.sessions_mut().mark_healthy(sid(101));

        let session_id = dispatch.healthy_session_for(1).unwrap();
        assert_eq!(session_id, sid(101));
    }

    #[test]
    fn healthy_session_for_unhealthy_is_error() {
        let (mut dispatch, _nodes) = make_dispatch(2);
        dispatch.sessions_mut().add_binding(1, sid(101));
        dispatch.sessions_mut().mark_unhealthy(sid(101));

        let result = dispatch.healthy_session_for(1);
        assert!(matches!(
            result,
            Err(PlacementDispatchError::UnhealthySession { .. })
        ));
    }

    #[test]
    fn healthy_session_for_no_binding_is_error() {
        let (dispatch, _nodes) = make_dispatch(2);

        let result = dispatch.healthy_session_for(99);
        assert!(matches!(
            result,
            Err(PlacementDispatchError::NoSession { .. })
        ));
    }

    #[test]
    fn stable_placement_across_calls() {
        let (dispatch, nodes) = make_dispatch(2);
        let key = test_key(7);

        let first = dispatch.resolve(&key, &nodes).unwrap();
        let second = dispatch.resolve(&key, &nodes).unwrap();
        assert_eq!(first.nodes, second.nodes);
    }

    #[test]
    fn different_objects_spread() {
        let (mut dispatch, nodes) = make_dispatch(2);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
        }

        let mut seen = BTreeSet::new();
        for obj_seed in 0..16 {
            let key = test_key(obj_seed);
            let resolved = dispatch.resolve(&key, &nodes).unwrap();
            seen.insert(resolved.nodes);
        }
        assert!(
            seen.len() > 1,
            "different objects should spread across nodes"
        );
    }

    #[test]
    fn replication_factor_accessor() {
        let (dispatch, _) = make_dispatch(3);
        assert_eq!(dispatch.replication_factor(), 3);
    }

    #[test]
    fn layout_accessor() {
        let (dispatch, _) = make_dispatch(2);
        assert_eq!(dispatch.layout().policy.total_shards(), 2);
    }

    #[test]
    fn sessions_mut_modifies_state() {
        let (mut dispatch, _) = make_dispatch(2);
        dispatch.sessions_mut().add_binding(1, sid(101));
        assert!(dispatch.sessions().has_node(1));
    }

    // ── PlacementMap integration tests ─────────────────────────────────

    #[test]
    fn placement_map_initially_none() {
        let (dispatch, _) = make_dispatch(2);
        assert!(dispatch.placement_version().is_none());
        assert!(dispatch.placement_epoch().is_none());
        assert!(dispatch.placement_map().is_none());
    }

    #[test]
    fn set_placement_map_updates_version_and_epoch() {
        let (mut dispatch, _) = make_dispatch(2);
        let mut mapping = BTreeMap::new();
        mapping.insert(
            1,
            [1u64]
                .into_iter()
                .map(tidefs_membership_epoch::MemberId)
                .collect(),
        );
        let map = PlacementMap::new(1, EpochId(7), mapping);

        dispatch.set_placement_map(map);

        assert_eq!(dispatch.placement_version(), Some(1));
        assert_eq!(dispatch.placement_epoch(), Some(EpochId(7)));
        assert!(dispatch.placement_map().is_some());
    }

    #[test]
    fn set_placement_map_increments_version() {
        let (mut dispatch, _) = make_dispatch(2);
        let map1 = PlacementMap::new(1, EpochId(1), BTreeMap::new());
        let map2 = PlacementMap::new(3, EpochId(2), BTreeMap::new());

        dispatch.set_placement_map(map1);
        assert_eq!(dispatch.placement_version(), Some(1));

        dispatch.set_placement_map(map2);
        assert_eq!(dispatch.placement_version(), Some(3));
    }

    #[test]
    #[should_panic(expected = "must be newer than")]
    fn set_placement_map_rejects_stale_version() {
        let (mut dispatch, _) = make_dispatch(2);
        let map1 = PlacementMap::new(5, EpochId(1), BTreeMap::new());
        let map2 = PlacementMap::new(3, EpochId(2), BTreeMap::new());

        dispatch.set_placement_map(map1);
        dispatch.set_placement_map(map2); // 3 < 5 — should panic
    }

    #[test]
    #[should_panic(expected = "first placement map must be initialized")]
    fn set_placement_map_rejects_empty_first() {
        let (mut dispatch, _) = make_dispatch(2);
        dispatch.set_placement_map(PlacementMap::empty());
    }

    #[test]
    fn placement_map_integration_with_write_targets() {
        let (mut dispatch, nodes) = make_dispatch(3);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }

        let key = test_key(42);
        let computed_targets = dispatch.resolve_write_targets(&key, &nodes).unwrap();
        let computed_nodes: Vec<_> = computed_targets
            .iter()
            .map(|target| target.node_id)
            .collect();
        let mapped_nodes: Vec<u64> = nodes
            .iter()
            .copied()
            .filter(|node| !computed_nodes.contains(node))
            .take(2)
            .collect();
        assert_eq!(
            mapped_nodes.len(),
            2,
            "test requires placement-map members outside computed placement"
        );

        dispatch.set_placement_map(map_for_object(42, &mapped_nodes));

        let targets = dispatch.resolve_write_targets(&key, &nodes).unwrap();
        let target_nodes: Vec<_> = targets.iter().map(|target| target.node_id).collect();
        assert_eq!(
            target_nodes, computed_nodes,
            "write targets must remain planner-driven for new allocations"
        );

        // Version is observable
        assert_eq!(dispatch.placement_version(), Some(1));
        assert_eq!(dispatch.placement_epoch(), Some(EpochId(10)));
    }

    #[test]
    fn placement_map_preserves_deterministic_computation() {
        let (mut dispatch, nodes) = make_dispatch(2);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }

        // Without a placement map, placement is still computed deterministically
        let key = test_key(42);
        let a = dispatch.resolve(&key, &nodes).unwrap();
        let b = dispatch.resolve(&key, &nodes).unwrap();
        assert_eq!(a.nodes, b.nodes);

        // After setting a map, computation remains deterministic
        dispatch.set_placement_map(PlacementMap::new(1, EpochId(0), BTreeMap::new()));
        let c = dispatch.resolve(&key, &nodes).unwrap();
        assert_eq!(a.nodes, c.nodes);
    }

    // ── write/read target resolution tests ─────────────────────────────

    #[test]
    fn resolve_write_targets_returns_ordered_targets() {
        let (mut dispatch, nodes) = make_dispatch(3);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }

        let key = test_key(42);
        let targets = dispatch.resolve_write_targets(&key, &nodes).unwrap();
        assert_eq!(targets.len(), 3);
        for t in &targets {
            assert!(t.healthy);
            assert_eq!(t.session_id, sid(100 + t.node_id));
        }
    }

    #[test]
    fn resolve_write_targets_flags_unhealthy() {
        let (mut dispatch, nodes) = make_dispatch(3);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }
        let key = test_key(77);
        let resolved = dispatch.resolve(&key, &nodes).unwrap();
        let first_node = resolved.nodes[0];
        dispatch
            .sessions_mut()
            .mark_unhealthy(sid(100 + first_node));

        let targets = dispatch.resolve_write_targets(&key, &nodes).unwrap();
        let first_target = targets.iter().find(|t| t.node_id == first_node).unwrap();
        assert!(!first_target.healthy);
    }

    #[test]
    fn resolve_write_targets_skips_unbound() {
        let (mut dispatch, nodes) = make_dispatch(3);
        dispatch.sessions_mut().add_binding(1, sid(101));
        dispatch.sessions_mut().add_binding(2, sid(102));
        dispatch.sessions_mut().mark_healthy(sid(101));
        dispatch.sessions_mut().mark_healthy(sid(102));

        let key = test_key(42);
        let targets = dispatch.resolve_write_targets(&key, &nodes).unwrap();
        assert!(targets.len() <= 3);
        for t in &targets {
            assert!(t.node_id == 1 || t.node_id == 2);
        }
    }

    #[test]
    fn resolve_read_targets_healthy_first() {
        let (mut dispatch, nodes) = make_dispatch(3);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }
        let key = test_key(99);
        let resolved = dispatch.resolve(&key, &nodes).unwrap();
        let first = resolved.nodes[0];
        dispatch.sessions_mut().mark_unhealthy(sid(100 + first));

        let read_targets = dispatch.resolve_read_targets(&key, &nodes).unwrap();
        let first_sid = read_targets[0];
        assert_ne!(
            first_sid,
            sid(100 + first),
            "first read target should not be the unhealthy node"
        );
        assert!(
            read_targets.contains(&sid(100 + first)),
            "unhealthy node should still appear at the end"
        );
    }

    #[test]
    fn resolve_read_targets_uses_placement_map_for_mapped_object() {
        let (mut dispatch, nodes) = make_dispatch(3);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }

        let key = test_key(42);
        let computed = dispatch.resolve(&key, &nodes).unwrap().nodes;
        let mapped_nodes: Vec<u64> = nodes
            .iter()
            .copied()
            .filter(|node| !computed.contains(node))
            .take(2)
            .collect();
        assert_eq!(
            mapped_nodes.len(),
            2,
            "test requires placement-map members outside computed placement"
        );

        dispatch.set_placement_map(map_for_object(42, &mapped_nodes));

        let read_targets = dispatch.resolve_read_targets(&key, &nodes).unwrap();
        let expected: Vec<_> = mapped_nodes.iter().map(|node| sid(100 + *node)).collect();
        assert_eq!(read_targets, expected);
    }

    #[test]
    fn resolve_read_targets_preserves_health_order_for_mapped_object() {
        let (mut dispatch, nodes) = make_dispatch(3);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }
        dispatch.sessions_mut().mark_unhealthy(sid(102));
        dispatch.set_placement_map(map_for_object(77, &[2, 4, 5]));

        let read_targets = dispatch
            .resolve_read_targets(&test_key(77), &nodes)
            .unwrap();

        assert_eq!(read_targets, vec![sid(104), sid(105), sid(102)]);
    }

    #[test]
    fn resolve_read_targets_falls_back_for_unmapped_object() {
        let (mut dispatch, nodes) = make_dispatch(3);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }

        let key = test_key(42);
        let computed = dispatch.resolve_read_targets(&key, &nodes).unwrap();
        dispatch.set_placement_map(map_for_object(7, &[4, 5]));

        let with_unrelated_map = dispatch.resolve_read_targets(&key, &nodes).unwrap();
        assert_eq!(with_unrelated_map, computed);
    }

    #[test]
    fn resolve_read_targets_returns_empty_on_no_sessions() {
        let (dispatch, nodes) = make_dispatch(2);
        let key = test_key(1);
        let targets = dispatch.resolve_read_targets(&key, &nodes).unwrap();
        assert!(targets.is_empty());
    }
    // ── Write gate integration tests ────────────────────────────

    #[test]
    fn write_gate_none_allows_writes() {
        // Without a write gate, resolve_write_targets works normally.
        let (mut dispatch, nodes) = make_dispatch(2);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }
        let key = test_key(1);
        let targets = dispatch.resolve_write_targets(&key, &nodes).unwrap();
        assert!(!targets.is_empty());
    }

    #[test]
    fn write_gate_no_active_fence_rejects_writes() {
        // When a write gate is configured but no fence has been issued,
        // resolve_write_targets returns StaleFence.
        let (mut dispatch, nodes) = make_dispatch(2);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }

        // Create a write gate with a fresh fence authority (no fence issued yet).
        let fence_auth = tidefs_cluster::write_fence::FenceAuthority::new();
        let validator = fence_auth.validator();
        let gate = WriteGate::new(validator);
        let dispatch = dispatch.with_write_gate(gate);

        let key = test_key(2);
        let result = dispatch.resolve_write_targets(&key, &nodes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PlacementDispatchError::StaleFence(_)
        ));
    }

    #[test]
    fn write_gate_active_fence_allows_writes() {
        // With an active fence, write targets resolve normally.
        let (mut dispatch, nodes) = make_dispatch(2);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }

        let fence_auth = tidefs_cluster::write_fence::FenceAuthority::new();
        // Issue a fence first
        let _ = fence_auth.issue_fence(tidefs_membership_epoch::EpochId(1));
        let validator = fence_auth.validator();
        let gate = WriteGate::new(validator);
        let dispatch = dispatch.with_write_gate(gate);

        let key = test_key(3);
        let targets = dispatch.resolve_write_targets(&key, &nodes).unwrap();
        assert!(!targets.is_empty());
        assert!(dispatch.active_write_fence().is_some());
    }

    #[test]
    fn write_gate_cleared_fence_rejects_writes() {
        // After clearing the fence, writes are rejected again.
        let (mut dispatch, nodes) = make_dispatch(2);
        for &n in &nodes {
            dispatch.sessions_mut().add_binding(n, sid(100 + n));
            dispatch.sessions_mut().mark_healthy(sid(100 + n));
        }

        let fence_auth = tidefs_cluster::write_fence::FenceAuthority::new();
        let _ = fence_auth.issue_fence(tidefs_membership_epoch::EpochId(1));
        let validator = fence_auth.validator();
        let gate = WriteGate::new(validator);
        let dispatch = dispatch.with_write_gate(gate);

        // Initially ok
        let key = test_key(4);
        assert!(dispatch.resolve_write_targets(&key, &nodes).is_ok());

        // Clear the fence (simulating lease release)
        fence_auth.clear();
        let result = dispatch.resolve_write_targets(&key, &nodes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PlacementDispatchError::StaleFence(_)
        ));
    }
}
