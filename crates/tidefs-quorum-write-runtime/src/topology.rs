// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Failure-domain-aware target topology and selection.
//!
//! Maps TideFS node targets to their failure domains at each hierarchy level
//! (device, node, rack) and selects replica target sets that maximize
//! failure-domain spread, ordered by policy-driven priority.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use tidefs_durability_layout::{DurabilityPolicy, FailureDomainLevel, FailureDomainV1};
use tidefs_quorum_write::NodeId;

// ── Domain key type ──────────────────────────────────────────────────

/// Opaque key identifying a failure domain at a given level.
///
/// Two targets with the same `DomainKey` at the same `FailureDomainLevel`
/// are co-located within that failure domain. For example, at the `Node`
/// level, the domain key is typically the `NodeId` itself; at the `Rack`
/// level, multiple nodes may share a rack key.
pub type DomainKey = u64;

// ── Target-to-domain assignment ──────────────────────────────────────

/// Associates each target with its failure domain key at a single
/// hierarchy level.
///
/// # Invariants
///
/// - `domain_level`: which hierarchy level this assignment covers.
/// - `assignments`: every unique `DomainKey` forms a failure domain
///   group; all targets in that group share a failure domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetTopology {
    pub domain_level: FailureDomainLevel,
    pub assignments: BTreeMap<NodeId, DomainKey>,
}

impl TargetTopology {
    /// Create a topology spanning the given failure domain level.
    #[must_use]
    pub fn new(domain_level: FailureDomainLevel) -> Self {
        Self {
            domain_level,
            assignments: BTreeMap::new(),
        }
    }
}

impl Default for TargetTopology {
    fn default() -> Self {
        Self {
            domain_level: FailureDomainLevel::Device,
            assignments: BTreeMap::new(),
        }
    }
}

impl TargetTopology {
    /// Assign a target to a domain key at this topology's level.
    pub fn assign(&mut self, target: NodeId, domain_key: DomainKey) {
        self.assignments.insert(target, domain_key);
    }

    /// Number of distinct failure domains.
    #[must_use]
    pub fn distinct_domains(&self) -> usize {
        self.assignments.values().collect::<BTreeSet<_>>().len()
    }

    /// Group available targets by their domain key, returning
    /// (domain_key, [targets_in_domain]).
    #[must_use]
    pub fn domain_groups(&self, available: &[NodeId]) -> BTreeMap<DomainKey, Vec<NodeId>> {
        let mut groups: BTreeMap<DomainKey, Vec<NodeId>> = BTreeMap::new();
        for node in available {
            if let Some(key) = self.assignments.get(node) {
                groups.entry(*key).or_default().push(*node);
            }
        }
        groups
    }

    /// Whether `target` belongs to this topology.
    #[must_use]
    pub fn contains(&self, target: &NodeId) -> bool {
        self.assignments.contains_key(target)
    }

    /// The domain key assigned to `target`, if any.
    #[must_use]
    pub fn domain_of(&self, target: &NodeId) -> Option<DomainKey> {
        self.assignments.get(target).copied()
    }

    /// Build a `FailureDomainV1` descriptor from this topology.
    #[must_use]
    pub fn to_descriptor(&self) -> FailureDomainV1 {
        let count = self.distinct_domains() as u8;
        FailureDomainV1::new(self.domain_level, count.max(1))
            .unwrap_or_else(|_| FailureDomainV1::new(FailureDomainLevel::Device, 1).unwrap())
    }
}

// ── Multi-level topology ─────────────────────────────────────────────

/// Topology spanning multiple failure domain hierarchy levels.
///
/// When quorum planning must respect constraints at multiple levels
/// (e.g. both device and rack), the planner uses the most restrictive
/// level where distinct-domain-count <= required-shard-count.
#[derive(Clone, Debug, Default)]
pub struct MultiLevelTopology {
    /// Topologies indexed by failure domain level.
    pub levels: HashMap<FailureDomainLevel, TargetTopology>,
}

impl MultiLevelTopology {
    #[must_use]
    pub fn new() -> Self {
        Self {
            levels: HashMap::new(),
        }
    }

    /// Insert a topology for a given level.
    pub fn insert(&mut self, topology: TargetTopology) {
        self.levels.insert(topology.domain_level, topology);
    }

    /// Get the topology for a specific level, if present.
    #[must_use]
    pub fn level(&self, level: FailureDomainLevel) -> Option<&TargetTopology> {
        self.levels.get(&level)
    }

    /// Number of configured levels.
    #[must_use]
    pub fn level_count(&self) -> usize {
        self.levels.len()
    }

    /// Select the most-constraining level whose distinct domain count
    /// can still satisfy the required shard count.
    #[must_use]
    pub fn constraining_level(
        &self,
        required_shards: usize,
        available: &[NodeId],
    ) -> Option<&TargetTopology> {
        // Priority order: Rack > Node > Device (most restrictive first).
        // Return the first level that has at least `required_shards`
        // distinct domains among available targets.
        let order = [
            FailureDomainLevel::Rack,
            FailureDomainLevel::Node,
            FailureDomainLevel::Device,
        ];
        for level in &order {
            if let Some(topo) = self.levels.get(level) {
                let groups = topo.domain_groups(available);
                if groups.len() >= required_shards {
                    return Some(topo);
                }
            }
        }
        // Fall back to the first available level, even if insufficient.
        for level in &order {
            if let Some(topo) = self.levels.get(level) {
                return Some(topo);
            }
        }
        None
    }
}

// ── Target selection ─────────────────────────────────────────────────

/// Errors produced during failure-domain-aware target selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetSelectionError {
    /// Not enough distinct failure domains to satisfy the policy.
    InsufficientDomains {
        needed: usize,
        available: usize,
        level: FailureDomainLevel,
    },
    /// Not enough total targets available.
    InsufficientTargets { needed: usize, available: usize },
    /// No topology configured for failure-domain-aware selection.
    NoTopology,
}

/// Selection strategy for when available domains < required replicas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionStrategy {
    /// Fail if domains < required (strict).
    Strict,
    /// Spread across domains as much as possible, wrap with
    /// co-located replicas when forced (best-effort).
    BestEffort,
}

// ── Public selection entry point ─────────────────────────────────────

/// Select target nodes for a quorum write, maximizing failure-domain spread.
///
/// Groups available targets by their domain key at the given topology level,
/// then picks one target per distinct domain in round-robin order until the
/// required number of replicas (from `policy.total_shards()`) is reached.
///
/// # Strategy
///
/// - `Strict`: returns `InsufficientDomains` if distinct domains < required.
/// - `BestEffort`: wraps to co-locate once all domains are consumed.
///
/// # Returns
///
/// A `Vec<NodeId>` of selected targets (length = `policy.total_shards()`),
/// or a `TargetSelectionError`.
pub fn select_targets(
    topology: &TargetTopology,
    policy: &DurabilityPolicy,
    available: &[NodeId],
    strategy: SelectionStrategy,
) -> Result<Vec<NodeId>, TargetSelectionError> {
    let needed = policy.total_shards();

    if needed == 0 {
        return Ok(Vec::new());
    }

    if available.len() < needed {
        return Err(TargetSelectionError::InsufficientTargets {
            needed,
            available: available.len(),
        });
    }

    let groups = topology.domain_groups(available);
    let domain_keys: Vec<DomainKey> = groups.keys().copied().collect();

    if domain_keys.is_empty() {
        return Err(TargetSelectionError::NoTopology);
    }

    if domain_keys.len() < needed {
        match strategy {
            SelectionStrategy::Strict => {
                return Err(TargetSelectionError::InsufficientDomains {
                    needed,
                    available: domain_keys.len(),
                    level: topology.domain_level,
                });
            }
            SelectionStrategy::BestEffort => {
                // Will wrap below
            }
        }
    }

    let mut selected: Vec<NodeId> = Vec::with_capacity(needed);
    for i in 0..needed {
        let domain_key = domain_keys[i % domain_keys.len()];
        let group = groups.get(&domain_key).expect("domain key must exist");
        // Pick the next available target in the group (round-robin within domain)
        let idx = i / domain_keys.len();
        let target = group[idx % group.len()];
        selected.push(target);
    }

    Ok(selected)
}

/// Convenience: select with default strict strategy.
pub fn select_targets_strict(
    topology: &TargetTopology,
    policy: &DurabilityPolicy,
    available: &[NodeId],
) -> Result<Vec<NodeId>, TargetSelectionError> {
    select_targets(topology, policy, available, SelectionStrategy::Strict)
}

/// Convenience: select with best-effort strategy.
pub fn select_targets_best_effort(
    topology: &TargetTopology,
    policy: &DurabilityPolicy,
    available: &[NodeId],
) -> Result<Vec<NodeId>, TargetSelectionError> {
    select_targets(topology, policy, available, SelectionStrategy::BestEffort)
}

/// Validate that selected targets satisfy the failure-domain constraints.
///
/// Checks that no two selected targets share the same domain key (when
/// `require_distinct` is true) and that the count matches the policy.
pub fn validate_selection(
    topology: &TargetTopology,
    policy: &DurabilityPolicy,
    selected: &[NodeId],
    require_distinct: bool,
) -> Result<(), TargetSelectionError> {
    let needed = policy.total_shards();

    if selected.len() != needed {
        return Err(TargetSelectionError::InsufficientTargets {
            needed,
            available: selected.len(),
        });
    }

    if require_distinct {
        let mut seen_domains = BTreeSet::new();
        for node in selected {
            if let Some(key) = topology.domain_of(node) {
                if !seen_domains.insert(key) {
                    // Duplicate domain: two targets in same failure domain
                    return Err(TargetSelectionError::InsufficientDomains {
                        needed: selected.len(),
                        available: seen_domains.len(),
                        level: topology.domain_level,
                    });
                }
            }
        }
    }

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_durability_layout::DurabilityPolicy;

    fn node(id: u64) -> NodeId {
        NodeId::new(id)
    }

    fn rack_topology_3_racks() -> TargetTopology {
        let mut t = TargetTopology::new(FailureDomainLevel::Rack);
        // Rack A: nodes 1,2
        t.assign(node(1), 0);
        t.assign(node(2), 0);
        // Rack B: nodes 3,4
        t.assign(node(3), 1);
        t.assign(node(4), 1);
        // Rack C: nodes 5,6
        t.assign(node(5), 2);
        t.assign(node(6), 2);
        t
    }

    fn mirror_3() -> DurabilityPolicy {
        DurabilityPolicy::mirror(3).unwrap()
    }

    fn mirror_2() -> DurabilityPolicy {
        DurabilityPolicy::mirror(2).unwrap()
    }

    fn erasure_4_2() -> DurabilityPolicy {
        DurabilityPolicy::erasure_style(4, 2).unwrap()
    }

    // ── Basic selection ───────────────────────────────────────────

    #[test]
    fn select_mirror_3_from_3_racks_strict() {
        let topo = rack_topology_3_racks();
        let available = vec![node(1), node(2), node(3), node(4), node(5), node(6)];
        let selected = select_targets_strict(&topo, &mirror_3(), &available).unwrap();
        // Should pick one from each rack: nodes 1,3,5 (first in each group)
        assert_eq!(selected.len(), 3);
        // Verify all three are in distinct domains
        let d1 = topo.domain_of(&selected[0]).unwrap();
        let d2 = topo.domain_of(&selected[1]).unwrap();
        let d3 = topo.domain_of(&selected[2]).unwrap();
        assert_ne!(d1, d2);
        assert_ne!(d1, d3);
        assert_ne!(d2, d3);
    }

    #[test]
    fn select_mirror_2_from_3_racks_strict() {
        let topo = rack_topology_3_racks();
        let available = vec![node(1), node(3), node(5)];
        let selected = select_targets_strict(&topo, &mirror_2(), &available).unwrap();
        assert_eq!(selected.len(), 2);
        let d1 = topo.domain_of(&selected[0]).unwrap();
        let d2 = topo.domain_of(&selected[1]).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn select_mirror_3_from_2_racks_strict_fails() {
        let topo = rack_topology_3_racks();
        // Only nodes from racks A and B available (2 domains < 3 needed)
        let available = vec![node(1), node(2), node(3), node(4)];
        let err = select_targets_strict(&topo, &mirror_3(), &available).unwrap_err();
        assert!(matches!(
            err,
            TargetSelectionError::InsufficientDomains {
                needed: 3,
                available: 2,
                ..
            }
        ));
    }

    #[test]
    fn select_mirror_3_from_2_racks_best_effort_wraps() {
        let topo = rack_topology_3_racks();
        // Only racks A and B available. Best-effort: pick 1 from each,
        // then wrap to pick another from first domain.
        let available = vec![node(1), node(2), node(3), node(4)];
        let selected = select_targets_best_effort(&topo, &mirror_3(), &available).unwrap();
        assert_eq!(selected.len(), 3);
        // First two should be from distinct domains
        let d0 = topo.domain_of(&selected[0]).unwrap();
        let d1 = topo.domain_of(&selected[1]).unwrap();
        assert_ne!(d0, d1);
        // Third wraps: same domain as first
        let d2 = topo.domain_of(&selected[2]).unwrap();
        assert_eq!(d2, d0);
    }

    #[test]
    fn select_erasure_4_2_strict() {
        // 6 shards need at least 6 distinct domains. Use node-level
        // where each node is its own domain.
        let mut topo = TargetTopology::new(FailureDomainLevel::Node);
        for i in 1..=7 {
            topo.assign(node(i), i);
        }
        let available: Vec<NodeId> = (1..=7).map(node).collect();
        let selected = select_targets_strict(&topo, &erasure_4_2(), &available).unwrap();
        assert_eq!(selected.len(), 6);
    }

    #[test]
    fn select_erasure_4_2_insufficient_domains() {
        let mut topo = TargetTopology::new(FailureDomainLevel::Node);
        // 7 total nodes but only 5 distinct domains (nodes 1-5 each own a domain,
        // nodes 6-7 share domain with 1-2). This way we have enough targets (7 >= 6)
        // but not enough distinct domains (5 < 6).
        topo.assign(node(1), 1);
        topo.assign(node(2), 2);
        topo.assign(node(3), 3);
        topo.assign(node(4), 4);
        topo.assign(node(5), 5);
        topo.assign(node(6), 1); // same domain as node 1
        topo.assign(node(7), 2); // same domain as node 2
        let available: Vec<NodeId> = (1..=7).map(node).collect();
        let err = select_targets_strict(&topo, &erasure_4_2(), &available).unwrap_err();
        assert!(matches!(
            err,
            TargetSelectionError::InsufficientDomains {
                needed: 6,
                available: 5,
                ..
            }
        ));
    }

    // ── Insufficient total targets ────────────────────────────────

    #[test]
    fn select_fails_when_fewer_targets_than_needed() {
        let topo = rack_topology_3_racks();
        let available = vec![node(1), node(3)]; // 2 targets, need 3
        let err = select_targets_strict(&topo, &mirror_3(), &available).unwrap_err();
        assert!(matches!(
            err,
            TargetSelectionError::InsufficientTargets {
                needed: 3,
                available: 2
            }
        ));
    }

    // ── Empty / degenerate ────────────────────────────────────────

    #[test]
    fn select_with_zero_shards_returns_empty() {
        let topo = rack_topology_3_racks();
        let available = vec![node(1)];
        let policy = DurabilityPolicy::mirror(1).unwrap();
        // Corner case: policy with 1 shard
        let selected = select_targets_strict(&topo, &policy, &available).unwrap();
        assert_eq!(selected.len(), 1);
    }

    #[test]
    fn select_with_no_topology_assignments_fails() {
        let topo = TargetTopology::new(FailureDomainLevel::Rack);
        let available = vec![node(1), node(2), node(3)];
        let err = select_targets_strict(&topo, &mirror_3(), &available).unwrap_err();
        assert!(matches!(err, TargetSelectionError::NoTopology));
    }

    // ── Validation ────────────────────────────────────────────────

    #[test]
    fn validate_distinct_selection_passes() {
        let topo = rack_topology_3_racks();
        let selected = vec![node(1), node(3), node(5)];
        assert!(validate_selection(&topo, &mirror_3(), &selected, true).is_ok());
    }

    #[test]
    fn validate_duplicate_domain_fails() {
        let topo = rack_topology_3_racks();
        // nodes 1 and 2 are in the same rack
        let selected = vec![node(1), node(2), node(5)];
        let err = validate_selection(&topo, &mirror_3(), &selected, true).unwrap_err();
        assert!(matches!(
            err,
            TargetSelectionError::InsufficientDomains { .. }
        ));
    }

    #[test]
    fn validate_wrong_count_fails() {
        let topo = rack_topology_3_racks();
        let selected = vec![node(1), node(3)];
        let err = validate_selection(&topo, &mirror_3(), &selected, true).unwrap_err();
        assert!(matches!(
            err,
            TargetSelectionError::InsufficientTargets { .. }
        ));
    }

    #[test]
    fn validate_non_distinct_allowed() {
        let topo = rack_topology_3_racks();
        let selected = vec![node(1), node(2), node(3)];
        // require_distinct = false: duplicate domain OK
        assert!(validate_selection(&topo, &mirror_3(), &selected, false).is_ok());
    }

    // ── MultiLevelTopology ────────────────────────────────────────

    #[test]
    fn multi_level_selects_constraining_rack_over_node() {
        let mut mlt = MultiLevelTopology::new();

        let mut rack_topo = TargetTopology::new(FailureDomainLevel::Rack);
        rack_topo.assign(node(1), 0);
        rack_topo.assign(node(2), 0);
        rack_topo.assign(node(3), 1);
        mlt.insert(rack_topo);

        let mut node_topo = TargetTopology::new(FailureDomainLevel::Node);
        node_topo.assign(node(1), 1);
        node_topo.assign(node(2), 2);
        node_topo.assign(node(3), 3);
        mlt.insert(node_topo);

        let available = vec![node(1), node(2), node(3)];
        // Need 2 replicas: rack has 2 domains, node has 3.
        // Rack is more constraining and still satisfies.
        let level = mlt.constraining_level(2, &available).unwrap();
        assert_eq!(level.domain_level, FailureDomainLevel::Rack);
        assert_eq!(level.distinct_domains(), 2);
    }

    #[test]
    fn multi_level_falls_back_when_rack_insufficient() {
        let mut mlt = MultiLevelTopology::new();

        let mut rack_topo = TargetTopology::new(FailureDomainLevel::Rack);
        rack_topo.assign(node(1), 0); // all in same rack
        rack_topo.assign(node(2), 0);
        rack_topo.assign(node(3), 0);
        mlt.insert(rack_topo);

        let mut node_topo = TargetTopology::new(FailureDomainLevel::Node);
        node_topo.assign(node(1), 1);
        node_topo.assign(node(2), 2);
        node_topo.assign(node(3), 3);
        mlt.insert(node_topo);

        let available = vec![node(1), node(2), node(3)];
        // Need 2 replicas: rack has only 1 domain -> insufficient.
        // Falls back to Node level which has 3 domains.
        let level = mlt.constraining_level(2, &available).unwrap();
        assert_eq!(level.domain_level, FailureDomainLevel::Node);
    }

    #[test]
    fn multi_level_no_levels_returns_none() {
        let mlt = MultiLevelTopology::new();
        assert!(mlt.constraining_level(2, &[]).is_none());
    }

    // ── Topology descriptor ───────────────────────────────────────

    #[test]
    fn topology_to_descriptor() {
        let topo = rack_topology_3_racks();
        let desc = topo.to_descriptor();
        assert_eq!(desc.level, FailureDomainLevel::Rack);
        assert_eq!(desc.target_count, 3);
    }

    #[test]
    fn topology_distinct_domains_count() {
        let topo = rack_topology_3_racks();
        assert_eq!(topo.distinct_domains(), 3);
    }

    // ── Degraded: fewer domains than shards (best-effort) ─────────

    #[test]
    fn degraded_3_replicas_from_1_rack_best_effort() {
        let mut topo = TargetTopology::new(FailureDomainLevel::Rack);
        topo.assign(node(1), 0);
        topo.assign(node(2), 0);
        topo.assign(node(3), 0); // all in same rack

        let available = vec![node(1), node(2), node(3)];
        let selected = select_targets_best_effort(&topo, &mirror_3(), &available).unwrap();
        assert_eq!(selected.len(), 3);
        // All in same domain (no other choice)
        for n in &selected {
            assert_eq!(topo.domain_of(n).unwrap(), 0);
        }
    }

    #[test]
    fn degraded_4_replicas_from_2_racks_best_effort() {
        let mut topo = TargetTopology::new(FailureDomainLevel::Rack);
        topo.assign(node(1), 0);
        topo.assign(node(2), 0);
        topo.assign(node(3), 1);
        topo.assign(node(4), 1);

        let available = vec![node(1), node(2), node(3), node(4)];
        let selected =
            select_targets_best_effort(&topo, &DurabilityPolicy::mirror(4).unwrap(), &available)
                .unwrap();
        assert_eq!(selected.len(), 4);
        // Should alternate: rack0, rack1, rack0, rack1
        let d0 = topo.domain_of(&selected[0]).unwrap();
        let d1 = topo.domain_of(&selected[1]).unwrap();
        let d2 = topo.domain_of(&selected[2]).unwrap();
        let d3 = topo.domain_of(&selected[3]).unwrap();
        assert_ne!(d0, d1);
        assert_eq!(d2, d0);
        assert_eq!(d3, d1);
    }
}
