// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Deterministic object-to-node placement via BLAKE3 keyed hashing.
//!
//! [`NodePlacement`] maps an object ID to a stable, ordered set of node IDs
//! using the pool's durability layout and failure-domain constraints. The
//! algorithm uses BLAKE3 keyed hashing so that the same (object_id, layout,
//! node set, seed) tuple always produces the same node targets.

use std::collections::BTreeSet;
use tidefs_durability_layout::{DurabilityLayoutV1, FailureDomainV1};

use crate::PlacementError;

/// Context string for BLAKE3 derive_key in node placement.
const NODE_PLACEMENT_CONTEXT: &str = "TideFS NodePlacement v1";

/// A deterministic mapping from an object ID to an ordered set of node IDs.
///
/// Produced by [`NodePlacement::compute`] using BLAKE3 keyed hashing with
/// the object ID, placement key, durability layout, and failure-domain
/// constraints. The node set is stable for a given input and respects
/// failure-domain anti-affinity at the level specified by the pool's layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePlacement {
    /// The object or chunk identifier being placed.
    pub object_id: u64,
    /// The placement key for deterministic hash positioning.
    pub placement_key: u64,
    /// Ordered list of node IDs selected to host replicas/shards.
    pub node_targets: Vec<u64>,
    /// How many replicas/shards the layout requires.
    pub required_count: usize,
    /// Whether failure-domain separation is guaranteed.
    pub failure_domain_separation: bool,
    /// The deterministic seed mixed into all hash computations.
    pub deterministic_seed: u64,
}

/// A node candidate for placement with optional failure-domain info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCandidate {
    /// Unique node identifier.
    pub node_id: u64,
    /// Whether this node is healthy and accepting placements.
    pub healthy: bool,
    /// Rack identifier for rack-level failure domains. `None` if unknown.
    pub rack_id: Option<u64>,
    /// Datacenter identifier for datacenter-level failure domains. `None` if unknown.
    pub datacenter_id: Option<u64>,
    /// Optional placement weight. Higher values bias placement toward this node.
    pub weight: u32,
}

impl NodeCandidate {
    /// Create a healthy node candidate with no topology info and default weight.
    /// The datacenter_id defaults to `None` — use [`with_datacenter`](Self::with_datacenter)
    /// to set it when datacenter-level failure domains are in use.
    #[must_use]
    pub fn new(node_id: u64) -> Self {
        Self {
            node_id,
            healthy: true,
            rack_id: None,
            datacenter_id: None,
            weight: 1,
        }
    }

    /// Set the node's rack identifier.
    #[must_use]
    pub fn with_rack(mut self, rack_id: u64) -> Self {
        self.rack_id = Some(rack_id);
        self
    }

    /// Set the node's datacenter identifier.
    #[must_use]
    pub fn with_datacenter(mut self, datacenter_id: u64) -> Self {
        self.datacenter_id = Some(datacenter_id);
        self
    }

    /// Set the node's placement weight.
    #[must_use]
    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Mark the node as unhealthy (excluded from placement).
    #[must_use]
    pub fn unhealthy(mut self) -> Self {
        self.healthy = false;
        self
    }
}

impl NodePlacement {
    /// Compute deterministic node placement for an object.
    ///
    /// Uses BLAKE3 keyed hashing to rank eligible nodes for each replica/shard
    /// slot. Respects failure-domain anti-affinity at the level specified by
    /// `failure_domain`:
    ///
    /// - `Device`: each node is its own domain (all nodes are selectable).
    /// - `Node`: same as Device for node-level placement.
    /// - `Rack`: nodes in the same rack share a domain.
    ///
    /// # Algorithm
    ///
    /// 1. Filter to healthy nodes.
    /// 2. For each replica/shard slot, compute a BLAKE3-derived score per node
    ///    (keyed by object_id, placement_key, slot index, and seed).
    /// 3. Select the highest-scoring node not yet used in this placement,
    ///    respecting failure-domain separation on the first pass.
    /// 4. If no unused domain is available, fall back to degraded placement
    ///    (reuse domains).
    ///
    /// # Errors
    ///
    /// Returns `PlacementError` if there are insufficient healthy nodes.
    pub fn compute(
        object_id: u64,
        placement_key: u64,
        layout: &DurabilityLayoutV1,
        failure_domain: &FailureDomainV1,
        nodes: &[NodeCandidate],
        seed: u64,
    ) -> Result<Self, PlacementError> {
        let required = layout.policy.total_shards();
        if required == 0 {
            return Err(PlacementError::NotEnoughMembers {
                required: 0,
                available: 0,
            });
        }

        let eligible: Vec<&NodeCandidate> = nodes.iter().filter(|n| n.healthy).collect();
        if eligible.is_empty() {
            return Err(PlacementError::AllMembersExcluded);
        }
        if eligible.len() < required {
            return Err(PlacementError::NotEnoughMembers {
                required,
                available: eligible.len(),
            });
        }

        // Determine failure-domain key for each node.
        let domain_key = |node: &NodeCandidate| -> u64 {
            use tidefs_durability_layout::FailureDomainLevel;
            match failure_domain.level {
                FailureDomainLevel::Device | FailureDomainLevel::Node => node.node_id,
                FailureDomainLevel::Rack => node.rack_id.unwrap_or(node.node_id),
                FailureDomainLevel::Datacenter => {
                    node.datacenter_id.or(node.rack_id).unwrap_or(node.node_id)
                }
            }
        };

        let mut node_targets: Vec<u64> = Vec::with_capacity(required);
        let mut used_nodes: BTreeSet<u64> = BTreeSet::new();
        let mut used_domains: BTreeSet<u64> = BTreeSet::new();
        let mut separation_maintained = true;

        for slot in 0..required {
            // Score every unused node for this slot.
            let mut scored: Vec<(u128, u64, u64)> = eligible
                .iter()
                .filter(|n| !used_nodes.contains(&n.node_id))
                .map(|n| {
                    let score = node_score(object_id, placement_key, slot as u64, n, seed);
                    (score, n.node_id, domain_key(n))
                })
                .collect();

            // Sort by score descending, break ties by node_id ascending.
            scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

            // First pass: strict domain separation.
            let mut found = false;
            for (_score, node_id, dom_key) in &scored {
                if !used_domains.contains(dom_key) {
                    node_targets.push(*node_id);
                    used_nodes.insert(*node_id);
                    used_domains.insert(*dom_key);
                    found = true;
                    break;
                }
            }

            // Second pass: allow domain reuse (degraded).
            if !found {
                if let Some((_score, node_id, _dom_key)) = scored.first() {
                    node_targets.push(*node_id);
                    used_nodes.insert(*node_id);
                    used_domains.insert(domain_key(
                        eligible.iter().find(|n| n.node_id == *node_id).unwrap(),
                    ));
                    separation_maintained = false;
                    found = true;
                }
            }

            if !found {
                break;
            }
        }

        if node_targets.len() < required {
            return Err(PlacementError::NotEnoughMembers {
                required,
                available: node_targets.len(),
            });
        }

        Ok(Self {
            object_id,
            placement_key,
            node_targets,
            required_count: required,
            failure_domain_separation: separation_maintained,
            deterministic_seed: seed,
        })
    }

    /// Return the primary node (first target). Valid when at least one target exists.
    #[must_use]
    pub fn primary_node(&self) -> Option<u64> {
        self.node_targets.first().copied()
    }

    /// Whether all requested replicas/shards were assigned.
    #[must_use]
    pub fn satisfied(&self) -> bool {
        self.node_targets.len() >= self.required_count
    }
}

// ---------------------------------------------------------------------------
// BLAKE3 keyed node scoring
// ---------------------------------------------------------------------------

/// Compute a deterministic BLAKE3-derived score for a node in a given
/// placement slot. Higher scores are preferred.
///
/// The score is 128-bit so ties are unlikely. Lower 64 bits are derived from
/// the weight to bias heavily-weighted nodes.
fn node_score(
    object_id: u64,
    placement_key: u64,
    slot: u64,
    node: &NodeCandidate,
    seed: u64,
) -> u128 {
    let mut hasher = blake3::Hasher::new_derive_key(NODE_PLACEMENT_CONTEXT);
    hasher.update(&object_id.to_le_bytes());
    hasher.update(&placement_key.to_le_bytes());
    hasher.update(&slot.to_le_bytes());
    hasher.update(&node.node_id.to_le_bytes());
    hasher.update(&seed.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();

    let hi = u64::from_le_bytes(digest[..8].try_into().unwrap());
    let lo = u64::from_le_bytes(digest[8..16].try_into().unwrap());

    // Weight factor: higher weight gives higher score.
    let w = u128::from(node.weight.max(1));
    u128::from(hi) * w * 2u128.pow(32) + u128::from(lo)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_durability_layout::{
        DurabilityLayoutV1, DurabilityPolicy, FailureDomainLevel, FailureDomainV1,
    };

    fn mirror_layout(copies: u8) -> DurabilityLayoutV1 {
        DurabilityLayoutV1::mirror(copies).unwrap()
    }

    fn erasure_layout(k: u8, m: u8) -> DurabilityLayoutV1 {
        DurabilityLayoutV1::erasure(k, m).unwrap()
    }

    fn node_fd() -> FailureDomainV1 {
        FailureDomainV1::new(FailureDomainLevel::Node, 64).unwrap()
    }

    fn rack_fd() -> FailureDomainV1 {
        FailureDomainV1::new(FailureDomainLevel::Rack, 64).unwrap()
    }

    fn node(id: u64) -> NodeCandidate {
        NodeCandidate::new(id)
    }

    fn node_with_rack(id: u64, rack: u64) -> NodeCandidate {
        NodeCandidate::new(id).with_rack(rack)
    }

    fn unhealthy_node(id: u64) -> NodeCandidate {
        NodeCandidate::new(id).unhealthy()
    }

    // -- Determinism --------------------------------------------------------

    #[test]
    fn same_input_same_output() {
        let layout = mirror_layout(3);
        let fd = node_fd();
        let nodes: Vec<_> = (1..=8).map(node).collect();

        let a = NodePlacement::compute(42, 7, &layout, &fd, &nodes, 0).unwrap();
        let b = NodePlacement::compute(42, 7, &layout, &fd, &nodes, 0).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.node_targets.len(), 3);
    }

    #[test]
    fn different_keys_produce_different_sets() {
        let layout = mirror_layout(2);
        let fd = node_fd();
        let nodes: Vec<_> = (1..=10).map(node).collect();

        let mut seen = BTreeSet::new();
        for key in 0..64 {
            let p = NodePlacement::compute(1, key, &layout, &fd, &nodes, 0).unwrap();
            seen.insert(p.node_targets.clone());
        }
        assert!(seen.len() > 1, "different keys should spread placements");
    }

    #[test]
    fn different_seeds_diverge() {
        let layout = mirror_layout(3);
        let fd = node_fd();
        let nodes: Vec<_> = (1..=6).map(node).collect();

        let a = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0).unwrap();
        let b = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0xDEAD).unwrap();
        assert_ne!(a.node_targets, b.node_targets);
    }

    #[test]
    fn different_objects_spread() {
        let layout = mirror_layout(2);
        let fd = node_fd();
        let nodes: Vec<_> = (1..=8).map(node).collect();

        let mut seen = BTreeSet::new();
        for obj_id in 0..64 {
            let p = NodePlacement::compute(obj_id, 0, &layout, &fd, &nodes, 0).unwrap();
            seen.insert(p.node_targets.clone());
        }
        assert!(seen.len() > 1, "different objects should spread placements");
    }

    // -- Failure-domain separation ------------------------------------------

    #[test]
    fn node_level_all_distinct_nodes() {
        let layout = mirror_layout(4);
        let fd = node_fd();
        let nodes: Vec<_> = (1..=8).map(node).collect();

        let p = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0).unwrap();
        let unique: BTreeSet<u64> = p.node_targets.iter().copied().collect();
        assert_eq!(unique.len(), 4);
        assert!(p.failure_domain_separation);
    }

    #[test]
    fn rack_level_separates_racks() {
        let layout = mirror_layout(3);
        let fd = rack_fd();
        let nodes = vec![
            node_with_rack(1, 100),
            node_with_rack(2, 200),
            node_with_rack(3, 300),
            node_with_rack(4, 100), // same rack as node 1
        ];

        let p = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0).unwrap();
        assert_eq!(p.node_targets.len(), 3);
        // Nodes from same rack should not both appear.
        let racks: Vec<u64> = p
            .node_targets
            .iter()
            .map(|id| {
                nodes
                    .iter()
                    .find(|n| n.node_id == *id)
                    .unwrap()
                    .rack_id
                    .unwrap()
            })
            .collect();
        let unique_racks: BTreeSet<u64> = racks.into_iter().collect();
        assert_eq!(unique_racks.len(), 3);
        assert!(p.failure_domain_separation);
    }

    #[test]
    fn degraded_when_insufficient_domains() {
        let layout = mirror_layout(3);
        let fd = rack_fd();
        // Only 2 distinct racks — must degrade for the 3rd replica.
        let nodes = vec![
            node_with_rack(1, 100),
            node_with_rack(2, 100),
            node_with_rack(3, 200),
            node_with_rack(4, 200),
        ];

        let p = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0).unwrap();
        assert_eq!(p.node_targets.len(), 3);
        assert!(!p.failure_domain_separation);
    }

    // -- Erasure coding -----------------------------------------------------

    #[test]
    fn erasure_placement_respects_shard_count() {
        let layout = erasure_layout(4, 2);
        let fd = node_fd();
        let nodes: Vec<_> = (1..=12).map(node).collect();

        let p = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0).unwrap();
        assert_eq!(p.node_targets.len(), 6);
        assert_eq!(p.required_count, 6);
    }

    // -- Edge cases ---------------------------------------------------------

    #[test]
    fn single_node_mirror_1() {
        let layout = mirror_layout(1);
        let fd = node_fd();
        let nodes = vec![node(42)];

        let p = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0).unwrap();
        assert_eq!(p.node_targets, vec![42]);
        assert_eq!(p.primary_node(), Some(42));
        assert!(p.satisfied());
    }

    #[test]
    fn not_enough_nodes_error() {
        let layout = mirror_layout(3);
        let fd = node_fd();
        let nodes = vec![node(1), node(2)];

        let err = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0).unwrap_err();
        assert!(matches!(err, PlacementError::NotEnoughMembers { .. }));
    }

    #[test]
    fn all_unhealthy_error() {
        let layout = mirror_layout(1);
        let fd = node_fd();
        let nodes = vec![unhealthy_node(1)];

        let err = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0).unwrap_err();
        assert!(matches!(err, PlacementError::AllMembersExcluded));
    }

    #[test]
    fn unhealthy_nodes_excluded() {
        let layout = mirror_layout(2);
        let fd = node_fd();
        let nodes = vec![unhealthy_node(1), node(2), node(3), node(4)];

        let p = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0).unwrap();
        assert!(!p.node_targets.contains(&1));
        assert_eq!(p.node_targets.len(), 2);
    }

    #[test]
    fn zero_shard_layout_errors() {
        // Impossible in practice, but defensive.
        let layout = DurabilityLayoutV1 {
            policy: DurabilityPolicy::Mirror { copies: 0 },
        };
        let fd = node_fd();
        let nodes = vec![node(1)];

        // Mirror(0) is rejected at construction, but we test the compute path
        // with a manually-created layout.
        let err = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0).unwrap_err();
        assert!(matches!(
            err,
            PlacementError::NotEnoughMembers { required: 0, .. }
        ));
    }

    #[test]
    fn primary_node_returns_first_target() {
        let layout = mirror_layout(3);
        let fd = node_fd();
        let nodes: Vec<_> = (1..=6).map(node).collect();

        let p = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0).unwrap();
        assert_eq!(p.primary_node(), Some(p.node_targets[0]));
    }

    #[test]
    fn weighted_nodes_biased() {
        let layout = mirror_layout(1);
        let fd = node_fd();
        let nodes = vec![
            NodeCandidate::new(1).with_weight(1),
            NodeCandidate::new(2).with_weight(16),
        ];

        let heavy_wins = (0..128)
            .filter(|key| {
                let p = NodePlacement::compute(1, *key, &layout, &fd, &nodes, 0).unwrap();
                p.node_targets[0] == 2
            })
            .count();

        assert!(
            heavy_wins > 96,
            "heavy node should win most keyed draws, won {heavy_wins}/128"
        );
    }

    #[test]
    fn large_topology_64_nodes() {
        let layout = mirror_layout(5);
        let fd = node_fd();
        let nodes: Vec<_> = (0..64).map(node).collect();

        let p = NodePlacement::compute(1, 1, &layout, &fd, &nodes, 0).unwrap();
        assert_eq!(p.node_targets.len(), 5);
        assert!(p.satisfied());
    }
}
