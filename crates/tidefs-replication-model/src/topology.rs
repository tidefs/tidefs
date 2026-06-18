// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Failure-domain topology model for TideFS durability layout.
//!
//! A [`FailureDomainTopology`] encodes the hierarchical containment
//! relationships between devices, nodes, racks, and datacenters. It is the
//! single source of truth consumed by [`PlacementConstraint`] evaluation,
//! the durability-layout policy engine, and placement-planner admission
//! decisions.
//!
//! # Hierarchy
//!
//! Device < Node < Rack < Datacenter: a device is contained in exactly one
//! node, a node in exactly one rack, and a rack in exactly one datacenter.
//! The topology supports partial knowledge -- missing levels are treated as
//! distinct domains at that level.
//!
//! # Design
//!
//! TideFS uses one durability layout mechanism for local and multi-node
//! failure domains. This topology model is the shared substrate: it
//! supports single-node pools (all devices on one node), multi-node pools
//! with rack/dc awareness, and edge cases like empty topologies or devices
//! without known node membership.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::failure_domain::FailureDomain;

// ---------------------------------------------------------------------------
// FailureDomainTopology
// ---------------------------------------------------------------------------

/// Hierarchical failure-domain containment map.
///
/// Stores the device->node, node->rack, and rack->datacenter containment
/// edges. Supports queries used by placement constraint evaluation and
/// durability-layout policy decisions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureDomainTopology {
    /// Device ID -> containing Node ID.
    device_to_node: BTreeMap<u64, u64>,
    /// Node ID -> containing Rack ID.
    node_to_rack: BTreeMap<u64, u64>,
    /// Rack ID -> containing Datacenter ID.
    rack_to_datacenter: BTreeMap<u64, u64>,
    /// Known device IDs (derived from device_to_node keys).
    #[serde(skip)]
    known_devices: BTreeSet<u64>,
    /// Known node IDs.
    #[serde(skip)]
    known_nodes: BTreeSet<u64>,
    /// Known rack IDs.
    #[serde(skip)]
    known_racks: BTreeSet<u64>,
}

impl FailureDomainTopology {
    /// Create an empty topology.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a device and its containing node.
    ///
    /// If the device is already registered, its node mapping is updated.
    pub fn add_device(&mut self, device_id: u64, node_id: u64) {
        self.device_to_node.insert(device_id, node_id);
        self.known_devices.insert(device_id);
        self.known_nodes.insert(node_id);
    }

    /// Register a node and its containing rack.
    pub fn add_node_to_rack(&mut self, node_id: u64, rack_id: u64) {
        self.node_to_rack.insert(node_id, rack_id);
        self.known_nodes.insert(node_id);
        self.known_racks.insert(rack_id);
    }

    /// Register a rack and its containing datacenter.
    pub fn add_rack_to_datacenter(&mut self, rack_id: u64, datacenter_id: u64) {
        self.rack_to_datacenter.insert(rack_id, datacenter_id);
        self.known_racks.insert(rack_id);
    }

    /// Number of known devices in the topology.
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.known_devices.len()
    }

    /// Number of known nodes in the topology.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.known_nodes.len()
    }

    /// Number of known racks in the topology.
    #[must_use]
    pub fn rack_count(&self) -> usize {
        self.known_racks.len()
    }

    /// Returns `true` if the topology is empty (no devices registered).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.known_devices.is_empty()
    }

    /// Returns the domain identifier for a device at the given level.
    ///
    /// Device: the device ID itself.
    /// Node: the containing node ID, or the device ID if unknown.
    /// Rack: the containing rack ID, or the node ID if unknown.
    /// Datacenter: the containing datacenter ID, or the rack ID if unknown.
    #[must_use]
    pub fn shared_ancestor_at_level(&self, device_id: u64, level: FailureDomain) -> u64 {
        match level {
            FailureDomain::Device => device_id,
            FailureDomain::Node => self
                .device_to_node
                .get(&device_id)
                .copied()
                .unwrap_or(device_id),
            FailureDomain::Rack => {
                let node_id = self
                    .device_to_node
                    .get(&device_id)
                    .copied()
                    .unwrap_or(device_id);
                self.node_to_rack.get(&node_id).copied().unwrap_or(node_id)
            }
            FailureDomain::Datacenter => {
                let node_id = self
                    .device_to_node
                    .get(&device_id)
                    .copied()
                    .unwrap_or(device_id);
                let rack_id = self.node_to_rack.get(&node_id).copied().unwrap_or(node_id);
                self.rack_to_datacenter
                    .get(&rack_id)
                    .copied()
                    .unwrap_or(rack_id)
            }
        }
    }

    /// Returns `true` when two devices share the same failure domain at
    /// the given level.
    #[must_use]
    pub fn same_domain(&self, device_a: u64, device_b: u64, level: FailureDomain) -> bool {
        self.shared_ancestor_at_level(device_a, level)
            == self.shared_ancestor_at_level(device_b, level)
    }

    /// Count how many distinct failure domains at `level` are spanned by
    /// the given device IDs.
    ///
    /// Devices not present in the topology map to themselves at each
    /// unknown level, so they are always counted as distinct.
    #[must_use]
    pub fn distinct_domain_count(&self, device_ids: &[u64], level: FailureDomain) -> usize {
        let domains: BTreeSet<u64> = device_ids
            .iter()
            .map(|&id| self.shared_ancestor_at_level(id, level))
            .collect();
        domains.len()
    }

    /// Return the node ID containing the given device, if known.
    #[must_use]
    pub fn node_for_device(&self, device_id: u64) -> Option<u64> {
        self.device_to_node.get(&device_id).copied()
    }

    /// Return the rack ID containing the given node, if known.
    #[must_use]
    pub fn rack_for_node(&self, node_id: u64) -> Option<u64> {
        self.node_to_rack.get(&node_id).copied()
    }

    /// Return the datacenter ID containing the given rack, if known.
    #[must_use]
    pub fn datacenter_for_rack(&self, rack_id: u64) -> Option<u64> {
        self.rack_to_datacenter.get(&rack_id).copied()
    }
}

// ---------------------------------------------------------------------------
// PlacementConstraint
// ---------------------------------------------------------------------------

/// A placement constraint encoding "replicas must span at least N distinct
/// failure domains at level L".
///
/// This is consumed by the durability-layout policy engine and the
/// placement-planner to ensure that replica placement satisfies
/// fault-tolerance requirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlacementConstraint {
    /// Minimum number of distinct failure domains required.
    pub min_distinct_domains: u8,
    /// The failure domain level at which distinctness is enforced.
    pub level: FailureDomain,
}

impl PlacementConstraint {
    /// Create a new placement constraint.
    #[must_use]
    pub const fn new(min_distinct_domains: u8, level: FailureDomain) -> Self {
        Self {
            min_distinct_domains,
            level,
        }
    }

    /// Returns `true` when `device_ids` satisfy the constraint -- i.e. the
    /// device set spans at least `min_distinct_domains` distinct failure
    /// domains at `level`.
    #[must_use]
    pub fn satisfied_by(&self, topology: &FailureDomainTopology, device_ids: &[u64]) -> bool {
        let distinct = topology.distinct_domain_count(device_ids, self.level);
        distinct >= self.min_distinct_domains as usize
    }

    /// Returns the number of additional distinct domains needed to satisfy
    /// the constraint. Saturates at 0.
    #[must_use]
    pub fn shortfall(&self, topology: &FailureDomainTopology, device_ids: &[u64]) -> u8 {
        let distinct = topology.distinct_domain_count(device_ids, self.level) as u8;
        self.min_distinct_domains.saturating_sub(distinct)
    }
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// Build a [`FailureDomainTopology`] from a flat device->node mapping.
///
/// Each tuple is `(device_id, node_id)`. This is the common builder for
/// single-node pools and simple multi-node configurations where rack and
/// datacenter containment is either absent or added later via
/// [`FailureDomainTopology::add_node_to_rack`] and
/// [`FailureDomainTopology::add_rack_to_datacenter`].
#[must_use]
pub fn topology_from_devices(devices: &[(u64, u64)]) -> FailureDomainTopology {
    let mut topo = FailureDomainTopology::new();
    for &(device_id, node_id) in devices {
        topo.add_device(device_id, node_id);
    }
    topo
}

/// Build a [`FailureDomainTopology`] from device->node, node->rack, and
/// rack->datacenter mappings.
///
/// This is the full-configuration builder for multi-node pools with rack
/// and datacenter awareness.
///
/// `devices`: `(device_id, node_id)` pairs.
/// `node_racks`: `(node_id, rack_id)` pairs (may be empty).
/// `rack_datacenters`: `(rack_id, datacenter_id)` pairs (may be empty).
#[must_use]
pub fn topology_from_config(
    devices: &[(u64, u64)],
    node_racks: &[(u64, u64)],
    rack_datacenters: &[(u64, u64)],
) -> FailureDomainTopology {
    let mut topo = topology_from_devices(devices);
    for &(node_id, rack_id) in node_racks {
        topo.add_node_to_rack(node_id, rack_id);
    }
    for &(rack_id, dc_id) in rack_datacenters {
        topo.add_rack_to_datacenter(rack_id, dc_id);
    }
    topo
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- topology_from_devices --

    #[test]
    fn empty_topology() {
        let topo = topology_from_devices(&[]);
        assert!(topo.is_empty());
        assert_eq!(topo.device_count(), 0);
        assert_eq!(topo.node_count(), 0);
    }

    #[test]
    fn single_device_topology() {
        let topo = topology_from_devices(&[(0, 1)]);
        assert!(!topo.is_empty());
        assert_eq!(topo.device_count(), 1);
        assert_eq!(topo.node_count(), 1);
        assert_eq!(topo.node_for_device(0), Some(1));
    }

    #[test]
    fn two_devices_same_node() {
        let devices = &[(0, 10), (1, 10)];
        let topo = topology_from_devices(devices);
        assert_eq!(topo.device_count(), 2);
        assert_eq!(topo.node_count(), 1);
    }

    #[test]
    fn two_devices_different_nodes() {
        let devices = &[(0, 10), (1, 20)];
        let topo = topology_from_devices(devices);
        assert_eq!(topo.device_count(), 2);
        assert_eq!(topo.node_count(), 2);
    }

    // -- same_domain --

    #[test]
    fn same_domain_device_level() {
        let topo = topology_from_devices(&[(0, 10), (1, 20)]);
        assert!(topo.same_domain(0, 0, FailureDomain::Device));
        assert!(!topo.same_domain(0, 1, FailureDomain::Device));
    }

    #[test]
    fn same_domain_node_level_same_node() {
        let topo = topology_from_devices(&[(0, 10), (1, 10)]);
        assert!(topo.same_domain(0, 1, FailureDomain::Node));
    }

    #[test]
    fn same_domain_node_level_different_nodes() {
        let topo = topology_from_devices(&[(0, 10), (1, 20)]);
        assert!(!topo.same_domain(0, 1, FailureDomain::Node));
    }

    #[test]
    fn same_domain_rack_level_with_rack_mapping() {
        let mut topo = topology_from_devices(&[(0, 10), (1, 20)]);
        topo.add_node_to_rack(10, 100);
        topo.add_node_to_rack(20, 100);
        assert!(topo.same_domain(0, 1, FailureDomain::Rack));
    }

    #[test]
    fn same_domain_rack_level_different_racks() {
        let mut topo = topology_from_devices(&[(0, 10), (1, 20)]);
        topo.add_node_to_rack(10, 100);
        topo.add_node_to_rack(20, 200);
        assert!(!topo.same_domain(0, 1, FailureDomain::Rack));
    }

    // -- shared_ancestor_at_level --

    #[test]
    fn ancestor_device_level_is_device_id() {
        let topo = topology_from_devices(&[(42, 10)]);
        assert_eq!(topo.shared_ancestor_at_level(42, FailureDomain::Device), 42);
    }

    #[test]
    fn ancestor_node_level_returns_node_id() {
        let topo = topology_from_devices(&[(42, 10)]);
        assert_eq!(topo.shared_ancestor_at_level(42, FailureDomain::Node), 10);
    }

    #[test]
    fn ancestor_unknown_device_falls_back_to_device_id() {
        let topo = topology_from_devices(&[]);
        assert_eq!(topo.shared_ancestor_at_level(99, FailureDomain::Device), 99);
        assert_eq!(topo.shared_ancestor_at_level(99, FailureDomain::Node), 99);
        assert_eq!(topo.shared_ancestor_at_level(99, FailureDomain::Rack), 99);
        assert_eq!(
            topo.shared_ancestor_at_level(99, FailureDomain::Datacenter),
            99
        );
    }

    #[test]
    fn ancestor_full_hierarchy() {
        let mut topo = topology_from_devices(&[(0, 10)]);
        topo.add_node_to_rack(10, 100);
        topo.add_rack_to_datacenter(100, 1000);
        assert_eq!(topo.shared_ancestor_at_level(0, FailureDomain::Device), 0);
        assert_eq!(topo.shared_ancestor_at_level(0, FailureDomain::Node), 10);
        assert_eq!(topo.shared_ancestor_at_level(0, FailureDomain::Rack), 100);
        assert_eq!(
            topo.shared_ancestor_at_level(0, FailureDomain::Datacenter),
            1000
        );
    }

    // -- distinct_domain_count --

    #[test]
    fn distinct_count_empty_set() {
        let topo = topology_from_devices(&[(0, 10)]);
        assert_eq!(topo.distinct_domain_count(&[], FailureDomain::Node), 0);
    }

    #[test]
    fn distinct_count_single_device() {
        let topo = topology_from_devices(&[(0, 10)]);
        assert_eq!(topo.distinct_domain_count(&[0], FailureDomain::Node), 1);
    }

    #[test]
    fn distinct_count_two_devices_same_node() {
        let topo = topology_from_devices(&[(0, 10), (1, 10)]);
        assert_eq!(topo.distinct_domain_count(&[0, 1], FailureDomain::Node), 1);
        assert_eq!(
            topo.distinct_domain_count(&[0, 1], FailureDomain::Device),
            2
        );
    }

    #[test]
    fn distinct_count_three_devices_two_nodes() {
        let topo = topology_from_devices(&[(0, 10), (1, 10), (2, 20)]);
        assert_eq!(
            topo.distinct_domain_count(&[0, 1, 2], FailureDomain::Node),
            2
        );
        assert_eq!(
            topo.distinct_domain_count(&[0, 1, 2], FailureDomain::Device),
            3
        );
    }

    #[test]
    fn distinct_count_rack_level() {
        let mut topo = topology_from_devices(&[(0, 10), (1, 20), (2, 30)]);
        topo.add_node_to_rack(10, 100);
        topo.add_node_to_rack(20, 100);
        topo.add_node_to_rack(30, 200);
        assert_eq!(
            topo.distinct_domain_count(&[0, 1, 2], FailureDomain::Rack),
            2
        );
    }

    // -- PlacementConstraint::satisfied_by --

    #[test]
    fn constraint_node_level_2_of_3() {
        let topo = topology_from_devices(&[(0, 10), (1, 10), (2, 20)]);
        let c = PlacementConstraint::new(2, FailureDomain::Node);

        // Same node -> rejected
        assert!(!c.satisfied_by(&topo, &[0, 1]));
        // Different nodes -> accepted
        assert!(c.satisfied_by(&topo, &[0, 2]));
        assert!(c.satisfied_by(&topo, &[0, 1, 2]));
    }

    #[test]
    fn constraint_satisfied_with_exact_count() {
        let topo = topology_from_devices(&[(0, 10), (1, 20), (2, 30)]);
        let c = PlacementConstraint::new(3, FailureDomain::Node);
        assert!(c.satisfied_by(&topo, &[0, 1, 2]));
    }

    #[test]
    fn constraint_rejected_insufficient_domains() {
        let topo = topology_from_devices(&[(0, 10), (1, 10), (2, 10)]);
        let c = PlacementConstraint::new(2, FailureDomain::Node);
        assert!(!c.satisfied_by(&topo, &[0, 1]));
    }

    #[test]
    fn constraint_device_level() {
        let topo = topology_from_devices(&[(0, 10), (1, 10)]);
        let c = PlacementConstraint::new(2, FailureDomain::Device);
        assert!(c.satisfied_by(&topo, &[0, 1]));
        assert!(!c.satisfied_by(&topo, &[0]));
    }

    #[test]
    fn constraint_rack_level() {
        let mut topo = topology_from_devices(&[(0, 10), (1, 20), (2, 30)]);
        topo.add_node_to_rack(10, 100);
        topo.add_node_to_rack(20, 100);
        topo.add_node_to_rack(30, 200);
        let c = PlacementConstraint::new(2, FailureDomain::Rack);
        assert!(!c.satisfied_by(&topo, &[0, 1]));
        assert!(c.satisfied_by(&topo, &[0, 2]));
    }

    #[test]
    fn constraint_empty_device_list() {
        let topo = topology_from_devices(&[(0, 10)]);
        let c = PlacementConstraint::new(1, FailureDomain::Node);
        assert!(!c.satisfied_by(&topo, &[]));
    }

    #[test]
    fn constraint_min_1_always_satisfied_with_any_device() {
        let topo = topology_from_devices(&[(0, 10)]);
        let c = PlacementConstraint::new(1, FailureDomain::Node);
        assert!(c.satisfied_by(&topo, &[0]));
    }

    // -- PlacementConstraint::shortfall --

    #[test]
    fn shortfall_zero_when_satisfied() {
        let topo = topology_from_devices(&[(0, 10), (1, 20)]);
        let c = PlacementConstraint::new(2, FailureDomain::Node);
        assert_eq!(c.shortfall(&topo, &[0, 1]), 0);
    }

    #[test]
    fn shortfall_positive_when_insufficient() {
        let topo = topology_from_devices(&[(0, 10), (1, 10)]);
        let c = PlacementConstraint::new(2, FailureDomain::Node);
        assert_eq!(c.shortfall(&topo, &[0, 1]), 1);
    }

    #[test]
    fn shortfall_2_when_no_devices() {
        let topo = topology_from_devices(&[(0, 10)]);
        let c = PlacementConstraint::new(2, FailureDomain::Node);
        assert_eq!(c.shortfall(&topo, &[]), 2);
    }

    // -- topology_from_config --

    #[test]
    fn config_with_racks_and_datacenters() {
        let devices = &[(0, 10), (1, 20)];
        let node_racks = &[(10, 100), (20, 200)];
        let rack_dcs = &[(100, 1000), (200, 2000)];

        let topo = topology_from_config(devices, node_racks, rack_dcs);

        assert_eq!(topo.device_count(), 2);
        assert_eq!(topo.node_count(), 2);
        assert_eq!(topo.rack_count(), 2);

        assert_eq!(topo.rack_for_node(10), Some(100));
        assert_eq!(topo.rack_for_node(20), Some(200));
        assert_eq!(topo.datacenter_for_rack(100), Some(1000));
        assert_eq!(topo.datacenter_for_rack(200), Some(2000));

        assert_eq!(
            topo.shared_ancestor_at_level(0, FailureDomain::Datacenter),
            1000
        );
        assert_eq!(
            topo.shared_ancestor_at_level(1, FailureDomain::Datacenter),
            2000
        );
    }

    #[test]
    fn config_with_only_devices() {
        let topo = topology_from_config(&[(0, 1), (2, 3)], &[], &[]);
        assert_eq!(topo.device_count(), 2);
        assert_eq!(topo.node_count(), 2);
        assert_eq!(topo.rack_count(), 0);
    }

    #[test]
    fn config_with_partial_racks() {
        let devices = &[(0, 10), (1, 20)];
        let node_racks = &[(10, 100)];
        let topo = topology_from_config(devices, node_racks, &[]);

        assert_eq!(topo.shared_ancestor_at_level(0, FailureDomain::Rack), 100);
        // Device 1's node has no rack -> falls back to node_id
        assert_eq!(topo.shared_ancestor_at_level(1, FailureDomain::Rack), 20);
    }

    // -- 3-node 2-device-per-node scenario --

    #[test]
    fn three_node_two_device_per_node_scenario() {
        let devices = &[(0, 10), (1, 10), (2, 20), (3, 20), (4, 30), (5, 30)];
        let topo = topology_from_devices(devices);

        let constraint = PlacementConstraint::new(2, FailureDomain::Node);

        // Same node -> rejected
        assert!(!constraint.satisfied_by(&topo, &[0, 1]));
        assert!(!constraint.satisfied_by(&topo, &[2, 3]));

        // Different nodes -> accepted
        assert!(constraint.satisfied_by(&topo, &[0, 2]));
        assert!(constraint.satisfied_by(&topo, &[0, 4]));
        assert!(constraint.satisfied_by(&topo, &[2, 4]));

        // 3 replicas across all 3 nodes
        let c3 = PlacementConstraint::new(3, FailureDomain::Node);
        assert!(c3.satisfied_by(&topo, &[0, 2, 4]));

        // 2 on same node -> only 2 distinct nodes -> rejected for N=3
        assert!(!c3.satisfied_by(&topo, &[0, 1, 2]));
    }

    // -- Single-node pool edge case --

    #[test]
    fn single_node_pool_constraint() {
        let devices = &[(0, 1), (1, 1), (2, 1)];
        let topo = topology_from_devices(devices);

        let c = PlacementConstraint::new(2, FailureDomain::Node);
        assert!(!c.satisfied_by(&topo, &[0, 1]));
        assert!(!c.satisfied_by(&topo, &[0, 1, 2]));

        let c_dev = PlacementConstraint::new(2, FailureDomain::Device);
        assert!(c_dev.satisfied_by(&topo, &[0, 1]));
    }

    // -- Serde round-trip --

    #[test]
    fn serde_topology_roundtrip() {
        let devices = &[(0, 10), (1, 20)];
        let node_racks = &[(10, 100)];
        let topo = topology_from_config(devices, node_racks, &[]);

        let json = serde_json::to_string(&topo).expect("serialize");
        let round: FailureDomainTopology = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(round.node_for_device(0), Some(10));
        assert_eq!(round.node_for_device(1), Some(20));
        assert_eq!(round.rack_for_node(10), Some(100));
        assert!(!round.same_domain(0, 1, FailureDomain::Node));
    }

    #[test]
    fn serde_empty_topology_roundtrip() {
        let topo = FailureDomainTopology::new();
        let json = serde_json::to_string(&topo).expect("serialize");
        let round: FailureDomainTopology = serde_json::from_str(&json).expect("deserialize");
        assert!(round.is_empty());
    }

    #[test]
    fn serde_constraint_roundtrip() {
        let c = PlacementConstraint::new(3, FailureDomain::Rack);
        let json = serde_json::to_string(&c).expect("serialize");
        let round: PlacementConstraint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(c, round);
    }

    // -- Multi-level domain hierarchies --

    #[test]
    fn multi_dc_hierarchy_distinct_count() {
        let devices = &[
            (0, 10),
            (1, 10),
            (2, 20),
            (3, 20),
            (4, 30),
            (5, 30),
            (6, 40),
            (7, 40),
        ];
        let node_racks = &[(10, 100), (20, 100), (30, 200), (40, 200)];
        let rack_dcs = &[(100, 1), (200, 2)];

        let topo = topology_from_config(devices, node_racks, rack_dcs);

        assert_eq!(
            topo.distinct_domain_count(&[0, 1, 2, 3, 4, 5, 6, 7], FailureDomain::Device),
            8
        );
        assert_eq!(
            topo.distinct_domain_count(&[0, 1, 2, 3, 4, 5, 6, 7], FailureDomain::Node),
            4
        );
        assert_eq!(
            topo.distinct_domain_count(&[0, 1, 2, 3, 4, 5, 6, 7], FailureDomain::Rack),
            2
        );
        assert_eq!(
            topo.distinct_domain_count(&[0, 1, 2, 3, 4, 5, 6, 7], FailureDomain::Datacenter),
            2
        );

        let c = PlacementConstraint::new(2, FailureDomain::Datacenter);
        assert!(!c.satisfied_by(&topo, &[0, 2])); // both in dc 1
        assert!(c.satisfied_by(&topo, &[0, 4])); // dc 1 and dc 2
    }

    // -- Rebuild after constraint check --

    #[test]
    fn placement_constraint_evolution() {
        let devices = &[(0, 10), (1, 20), (2, 30)];
        let topo = topology_from_devices(devices);
        let c = PlacementConstraint::new(2, FailureDomain::Node);

        assert!(c.satisfied_by(&topo, &[0, 1, 2]));
        assert!(c.satisfied_by(&topo, &[1, 2])); // lost device 0
        assert!(!c.satisfied_by(&topo, &[2])); // lost device 1 too
        assert_eq!(c.shortfall(&topo, &[2]), 1);
    }
}
