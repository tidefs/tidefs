// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Failure-domain topology with node/rack/datacenter hierarchy.
//!
//! [`FailureDomainTopology`] models the cluster's physical topology:
//! devices belong to nodes, nodes to racks, racks to datacenters.
//! It provides failure simulation that determines whether a durability policy
//! can survive the loss of specific nodes, racks, or datacenters.

use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// FailureDomainTopology
// ---------------------------------------------------------------------------

/// A physical cluster topology for failure-domain simulation.
///
/// Tracks nodes, racks, datacenters, and device-to-node assignments.
/// Used by [`crate::LayoutValidator`] to determine whether a durability policy
/// can survive specific failure scenarios.
#[derive(Clone, Debug, Default)]
pub struct FailureDomainTopology {
    nodes: Vec<NodeEntry>,
    devices: Vec<DeviceEntry>,
    racks: BTreeSet<u64>,
    dcs: BTreeSet<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NodeEntry {
    node_id: u64,
    rack_id: u64,
    dc_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeviceEntry {
    device_id: u64,
    node_id: u64,
}

/// Result of a failure simulation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureSimulationResult {
    /// Whether the policy survives this failure scenario.
    pub survives: bool,
    /// Number of replicas that could survive in the worst-case placement.
    pub max_surviving_replicas: usize,
    /// Number of distinct failure domains that remain online.
    pub surviving_domains: usize,
    /// Total replicas required by the policy.
    pub total_replicas: usize,
    /// Minimum replicas required for survival (1 for mirror, k for erasure).
    pub min_required: usize,
}

impl FailureDomainTopology {
    /// Create an empty topology.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node with its rack and datacenter parents.
    ///
    /// Idempotent: if the node already exists, its rack/dc assignments are updated.
    pub fn add_node(&mut self, node_id: u64, rack_id: u64, dc_id: u64) {
        self.racks.insert(rack_id);
        self.dcs.insert(dc_id);
        if let Some(existing) = self.nodes.iter_mut().find(|n| n.node_id == node_id) {
            existing.rack_id = rack_id;
            existing.dc_id = dc_id;
        } else {
            self.nodes.push(NodeEntry {
                node_id,
                rack_id,
                dc_id,
            });
        }
    }

    /// Add a device assigned to a specific node.
    ///
    /// Idempotent: if the device already exists, its node assignment is updated.
    pub fn add_device(&mut self, device_id: u64, node_id: u64) {
        if let Some(existing) = self.devices.iter_mut().find(|d| d.device_id == device_id) {
            existing.node_id = node_id;
        } else {
            self.devices.push(DeviceEntry { device_id, node_id });
        }
    }

    /// Return the number of nodes in the topology.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return the number of racks in the topology.
    pub fn rack_count(&self) -> usize {
        self.racks.len()
    }

    /// Return the number of datacenters in the topology.
    pub fn dc_count(&self) -> usize {
        self.dcs.len()
    }

    /// Return the number of devices in the topology.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Get the node IDs belonging to a specific rack.
    pub fn nodes_in_rack(&self, rack_id: u64) -> Vec<u64> {
        self.nodes
            .iter()
            .filter(|n| n.rack_id == rack_id)
            .map(|n| n.node_id)
            .collect()
    }

    /// Get the node IDs belonging to a specific datacenter.
    pub fn nodes_in_dc(&self, dc_id: u64) -> Vec<u64> {
        self.nodes
            .iter()
            .filter(|n| n.dc_id == dc_id)
            .map(|n| n.node_id)
            .collect()
    }

    /// Get device IDs belonging to a specific node.
    pub fn devices_on_node(&self, node_id: u64) -> Vec<u64> {
        self.devices
            .iter()
            .filter(|d| d.node_id == node_id)
            .map(|d| d.device_id)
            .collect()
    }

    // ------------------------------------------------------------------
    // Failure simulation
    // ------------------------------------------------------------------

    /// Simulate failure of specific nodes.
    ///
    /// Uses worst-case replica distribution analysis: replicas are assumed to
    /// be distributed evenly across nodes, so each node hosts at most
    /// `ceil(total_replicas / node_count)` replicas. The maximum loss is the
    /// sum of that bound across all failed nodes, clamped to total_replicas.
    ///
    /// Returns a [`FailureSimulationResult`] indicating survival.
    pub fn simulate_node_failure(
        &self,
        failed_nodes: &[u64],
        total_replicas: usize,
        min_required: usize,
    ) -> FailureSimulationResult {
        let failed_set: BTreeSet<u64> = failed_nodes.iter().copied().collect();
        let surviving_nodes = self.node_count().saturating_sub(
            self.nodes
                .iter()
                .filter(|n| failed_set.contains(&n.node_id))
                .count(),
        );

        let nc = self.node_count();
        if nc == 0 {
            return FailureSimulationResult {
                survives: false,
                max_surviving_replicas: 0,
                surviving_domains: 0,
                total_replicas,
                min_required,
            };
        }

        // Worst case: replicas distributed evenly, each failed node hosts up to
        // ceil(total_replicas / node_count) replicas.
        let max_per_node = total_replicas.div_ceil(nc);
        let max_lost = (failed_nodes.len() * max_per_node).min(total_replicas);
        let max_surviving = total_replicas - max_lost;

        FailureSimulationResult {
            survives: max_surviving >= min_required,
            max_surviving_replicas: max_surviving,
            surviving_domains: surviving_nodes,
            total_replicas,
            min_required,
        }
    }

    /// Determine whether a mirror policy can survive any single-node failure.
    ///
    /// With at least 2 nodes, replicas can always be distributed so that no
    /// single node holds all replicas, guaranteeing at least 1 survivor.
    pub fn can_survive_any_single_node_failure(&self, copies: u8) -> bool {
        copies > 1 && self.node_count() >= 2
    }

    /// Determine whether a mirror policy can survive any single-rack failure.
    ///
    /// With at least 2 racks, replicas can be distributed across racks so
    /// that at least 1 replica survives the loss of any single rack.
    pub fn can_survive_any_single_rack_failure(&self, copies: u8) -> bool {
        copies > 1 && self.rack_count() >= 2
    }

    /// Determine whether a mirror policy can survive failure of
    /// `failed_node_count` nodes in the worst case.
    ///
    /// Uses ceil-based distribution: each node hosts at most
    /// `ceil(copies / node_count)` replicas. The worst-case loss is
    /// `failed_node_count * max_per_node`, clamped to copies.
    pub fn can_survive_n_node_failures(&self, copies: u8, failed_node_count: usize) -> bool {
        if copies == 0 || self.node_count() == 0 {
            return false;
        }
        let surviving_nodes = self.node_count().saturating_sub(failed_node_count);
        if surviving_nodes == 0 {
            return false;
        }
        let nc = self.node_count();
        let max_per_node = (copies as usize).div_ceil(nc);
        let max_lost = (failed_node_count * max_per_node).min(copies as usize);
        let surviving = (copies as usize) - max_lost;
        surviving >= 1
    }

    /// Return a list of all node IDs.
    pub fn node_ids(&self) -> Vec<u64> {
        self.nodes.iter().map(|n| n.node_id).collect()
    }

    /// Return a list of all rack IDs.
    pub fn rack_ids(&self) -> Vec<u64> {
        self.racks.iter().copied().collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn three_node_topology() -> FailureDomainTopology {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        topo.add_node(3, 20, 200);
        topo.add_device(101, 1);
        topo.add_device(102, 1);
        topo.add_device(201, 2);
        topo.add_device(202, 2);
        topo.add_device(301, 3);
        topo.add_device(302, 3);
        topo
    }

    #[test]
    fn topology_empty() {
        let topo = FailureDomainTopology::new();
        assert_eq!(topo.node_count(), 0);
        assert_eq!(topo.rack_count(), 0);
        assert_eq!(topo.device_count(), 0);
    }

    #[test]
    fn topology_add_node() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        assert_eq!(topo.node_count(), 1);
        assert_eq!(topo.rack_count(), 1);
        assert_eq!(topo.dc_count(), 1);
    }

    #[test]
    fn topology_add_device() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_device(101, 1);
        topo.add_device(102, 1);
        assert_eq!(topo.device_count(), 2);
        assert_eq!(topo.devices_on_node(1), vec![101, 102]);
    }

    #[test]
    fn topology_nodes_in_rack() {
        let topo = three_node_topology();
        let rack10 = topo.nodes_in_rack(10);
        assert_eq!(rack10.len(), 2);
        assert!(rack10.contains(&1));
        assert!(rack10.contains(&2));
    }

    #[test]
    fn topology_nodes_in_dc() {
        let topo = three_node_topology();
        assert_eq!(topo.nodes_in_dc(100).len(), 2);
        assert_eq!(topo.nodes_in_dc(200), vec![3]);
    }

    #[test]
    fn simulate_no_failure() {
        let topo = three_node_topology();
        let result = topo.simulate_node_failure(&[], 3, 1);
        assert!(result.survives);
        assert_eq!(result.max_surviving_replicas, 3);
    }

    #[test]
    fn simulate_one_node_failure_mirror3_3nodes() {
        let topo = three_node_topology();
        // ceil(3/3)=1 per node, losing 1 node loses at most 1
        let result = topo.simulate_node_failure(&[1], 3, 1);
        assert!(result.survives);
        assert_eq!(result.max_surviving_replicas, 2);
        assert_eq!(result.surviving_domains, 2);
    }

    #[test]
    fn simulate_two_node_failure_mirror3_3nodes_fails() {
        let topo = three_node_topology();
        // ceil(3/3)=1 per node, losing 2 nodes loses at most 2 -> 1 survives
        let result = topo.simulate_node_failure(&[1, 2], 3, 1);
        assert!(result.survives);
        assert_eq!(result.max_surviving_replicas, 1);
    }

    #[test]
    fn simulate_all_nodes_fail() {
        let topo = three_node_topology();
        let result = topo.simulate_node_failure(&[1, 2, 3], 3, 1);
        assert!(!result.survives);
        assert_eq!(result.max_surviving_replicas, 0);
    }

    #[test]
    fn can_survive_single_node_mirror3() {
        let topo = three_node_topology();
        assert!(topo.can_survive_any_single_node_failure(3));
    }

    #[test]
    fn cannot_survive_single_node_mirror1() {
        let topo = three_node_topology();
        assert!(!topo.can_survive_any_single_node_failure(1));
    }

    #[test]
    fn can_survive_single_node_mirror3_2nodes() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        topo.add_device(101, 1);
        topo.add_device(201, 2);
        // 3 replicas on 2 nodes: ceil(3/2)=2 per node. Losing 1 loses <=2, 1 survives.
        assert!(topo.can_survive_any_single_node_failure(3));
    }

    #[test]
    fn cannot_survive_single_node_one_node_topology() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_device(101, 1);
        // 2 replicas on 1 node: losing that node loses everything
        assert!(!topo.can_survive_any_single_node_failure(2));
    }

    #[test]
    fn can_survive_single_rack_mirror3_two_racks() {
        let topo = three_node_topology();
        // 2 racks, 3 replicas: can distribute across racks
        assert!(topo.can_survive_any_single_rack_failure(3));
    }

    #[test]
    fn cannot_survive_single_rack_one_rack() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        topo.add_device(101, 1);
        topo.add_device(201, 2);
        assert!(!topo.can_survive_any_single_rack_failure(2));
    }

    #[test]
    fn can_survive_n_node_failures_mirror3_1() {
        let topo = three_node_topology();
        assert!(topo.can_survive_n_node_failures(3, 1));
    }

    #[test]
    fn cannot_survive_n_node_failures_mirror3_3() {
        let topo = three_node_topology();
        assert!(!topo.can_survive_n_node_failures(3, 3));
    }

    #[test]
    fn can_survive_n_node_failures_mirror4_2nodes_1fail() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        topo.add_device(101, 1);
        topo.add_device(102, 1);
        topo.add_device(201, 2);
        topo.add_device(202, 2);
        // ceil(4/2)=2 per node. Losing 1 loses <=2, 2 survive.
        assert!(topo.can_survive_n_node_failures(4, 1));
    }

    #[test]
    fn cannot_survive_n_node_failures_mirror4_2nodes_2fail() {
        let mut topo = FailureDomainTopology::new();
        topo.add_node(1, 10, 100);
        topo.add_node(2, 10, 100);
        topo.add_device(101, 1);
        topo.add_device(201, 2);
        // Losing both nodes loses all 4 replicas
        assert!(!topo.can_survive_n_node_failures(4, 2));
    }

    #[test]
    fn node_ids_and_rack_ids() {
        let topo = three_node_topology();
        let mut node_ids = topo.node_ids();
        node_ids.sort();
        assert_eq!(node_ids, vec![1, 2, 3]);
        let mut rack_ids = topo.rack_ids();
        rack_ids.sort();
        assert_eq!(rack_ids, vec![10, 20]);
    }
}
