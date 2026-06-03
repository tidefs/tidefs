//! Placement planning from DurabilityLayoutV1 and FailureDomainV1 descriptors.
//!
//! This module implements [`PlacementPlan`], which consumes a
//! [`DurabilityLayoutV1`] (Mirror or Erasure) and a [`FailureDomainV1`]
//! (Device/Node/Rack) to produce concrete per-replica device assignments
//! across failure domains.
//!
//! # Algorithm
//!
//! 1. Group candidate devices by failure-domain key at the specified level.
//! 2. Sort domains by device count (least-loaded first).
//! 3. Select one unused device per unused domain until the required shard
//!    count is met.
//! 4. Assign shard indices: all Data for Mirror; Data then Parity for Erasure.
//!
//! # Error Cases
//!
//! Returns [`PlacementPlanError::NotEnoughDevices`] when the candidate list
//! is too short, and [`PlacementPlanError::NotEnoughFailureDomains`] when
//! there aren't enough distinct domains at the specified level.

use std::collections::{BTreeMap, BTreeSet};
use tidefs_durability_layout::{
    DurabilityLayoutV1, DurabilityPolicy, FailureDomainLevel, FailureDomainV1,
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A candidate device for placement with failure-domain annotations.
///
/// Each candidate supplies its own id and optional node/rack topology ids.
/// Missing topology information falls back to the next more-granular level
/// (rack → node → device) during failure-domain grouping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCandidate {
    /// Unique device identifier.
    pub device_id: u64,
    /// Node (host) identifier. `None` if unknown.
    pub node_id: Option<u64>,
    /// Rack identifier. `None` if unknown.
    pub rack_id: Option<u64>,
    /// Datacenter identifier for datacenter-level failure domains. `None` if unknown.
    pub datacenter_id: Option<u64>,
}

/// Whether a shard carries data or parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardRole {
    /// Data shard — Mirror replicas and Erasure data chunks.
    Data,
    /// Parity shard — Erasure parity chunks only.
    Parity,
}

/// A single device assignment in a placement plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardAssignment {
    /// The device selected to host this shard.
    pub device_id: u64,
    /// 0-based shard position in the object layout.
    pub shard_index: u8,
    /// Whether this shard is data or parity.
    pub shard_role: ShardRole,
}

/// Errors produced by placement planning.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlacementPlanError {
    /// Not enough total devices to satisfy the layout.
    #[error("not enough devices: need {required}, have {available}")]
    NotEnoughDevices { required: usize, available: usize },
    /// Not enough distinct failure domains at the specified level.
    #[error("not enough distinct failure domains at the required level: need {required}, have {available}")]
    NotEnoughFailureDomains { required: usize, available: usize },
}

// ---------------------------------------------------------------------------
// PlacementPlan
// ---------------------------------------------------------------------------

/// A placement plan that consumes a [`DurabilityLayoutV1`] and a
/// [`FailureDomainV1`] to produce per-replica device assignments across
/// failure domains.
///
/// # Example
///
/// ```ignore
/// use tidefs_placement_planner::placement_plan::{
///     DeviceCandidate, PlacementPlan,
/// };
/// use tidefs_durability_layout::{
///     DurabilityLayoutV1, FailureDomainLevel, FailureDomainV1,
/// };
///
/// let layout = DurabilityLayoutV1::mirror(2).unwrap();
/// let fd = FailureDomainV1::new(FailureDomainLevel::Device, 4).unwrap();
/// let plan = PlacementPlan::from_layout(layout, fd);
///
/// let candidates = vec![
///     DeviceCandidate { device_id: 1, node_id: Some(10), rack_id: Some(100) },
///     DeviceCandidate { device_id: 2, node_id: Some(20), rack_id: Some(200) },
///     DeviceCandidate { device_id: 3, node_id: Some(30), rack_id: Some(300) },
/// ];
///
/// let assignments = plan.assign_devices(&candidates).unwrap();
/// assert_eq!(assignments.len(), 2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementPlan {
    layout: DurabilityLayoutV1,
    failure_domain: FailureDomainV1,
}

impl PlacementPlan {
    /// Create a new placement plan from a durability layout and failure domain
    /// descriptor.
    ///
    /// The layout and failure domain are stored as-is; validation of
    /// availability against actual candidates happens during
    /// [`assign_devices`](Self::assign_devices).
    pub fn from_layout(layout: DurabilityLayoutV1, failure_domain: FailureDomainV1) -> Self {
        Self {
            layout,
            failure_domain,
        }
    }

    /// Return a reference to the durability layout.
    pub fn layout(&self) -> &DurabilityLayoutV1 {
        &self.layout
    }

    /// Return a reference to the failure domain descriptor.
    pub fn failure_domain(&self) -> &FailureDomainV1 {
        &self.failure_domain
    }

    /// Total shards required by this plan.
    ///
    /// Mirror: `copies`. ErasureStyle: `data_shards + parity_shards`.
    pub fn total_shards(&self) -> usize {
        self.layout.policy.total_shards()
    }

    /// Assign devices from the candidate set, respecting failure-domain
    /// anti-affinity at the level specified by this plan's
    /// [`FailureDomainV1`].
    ///
    /// # Algorithm
    ///
    /// 1. Group candidates by failure-domain key at the specified level
    ///    (rack → node → device fallback).
    /// 2. Sort domains by candidate count — domains with fewer devices are
    ///    preferred for better distribution.
    /// 3. Select one unused device per unused domain for each shard slot.
    /// 4. Assign shard roles: all Data for Mirror; Data indices 0..k-1 then
    ///    Parity indices k..k+m-1 for Erasure.
    ///
    /// # Errors
    ///
    /// - [`PlacementPlanError::NotEnoughDevices`] if the candidate list is
    ///   shorter than required.
    /// - [`PlacementPlanError::NotEnoughFailureDomains`] if there aren't
    ///   enough distinct failure domains at the specified level.
    pub fn assign_devices(
        &self,
        candidates: &[DeviceCandidate],
    ) -> Result<Vec<ShardAssignment>, PlacementPlanError> {
        let required = self.total_shards();
        if candidates.is_empty() {
            return Err(PlacementPlanError::NotEnoughDevices {
                required,
                available: 0,
            });
        }
        if candidates.len() < required {
            return Err(PlacementPlanError::NotEnoughDevices {
                required,
                available: candidates.len(),
            });
        }

        let domain_level = self.failure_domain.level;

        // Group candidates by failure-domain key.
        let mut domain_map: BTreeMap<u64, Vec<&DeviceCandidate>> = BTreeMap::new();
        for c in candidates {
            let key = failure_domain_key(c, domain_level);
            domain_map.entry(key).or_default().push(c);
        }

        let distinct_domains = domain_map.len();
        if distinct_domains < required {
            return Err(PlacementPlanError::NotEnoughFailureDomains {
                required,
                available: distinct_domains,
            });
        }

        // Sort domain entries: fewer devices per domain first (best spread).
        let mut domain_entries: Vec<(u64, Vec<&DeviceCandidate>)> =
            domain_map.into_iter().collect();
        domain_entries.sort_by_key(|(_, devs)| devs.len());

        let mut assignments: Vec<ShardAssignment> = Vec::with_capacity(required);
        let mut used_device_ids: BTreeSet<u64> = BTreeSet::new();
        let mut used_domain_keys: BTreeSet<u64> = BTreeSet::new();

        for slot in 0..required {
            // Find first unused domain that still has an unused device.
            let picked = domain_entries.iter().find(|(domain_key, devs)| {
                !used_domain_keys.contains(domain_key)
                    && devs.iter().any(|d| !used_device_ids.contains(&d.device_id))
            });

            let Some((domain_key, devs)) = picked else {
                // No unused domain with an unused device remains.
                return Err(PlacementPlanError::NotEnoughFailureDomains {
                    required,
                    available: assignments.len(),
                });
            };

            let device = devs
                .iter()
                .find(|d| !used_device_ids.contains(&d.device_id))
                .expect("domain passed filter but no unused device found");

            used_device_ids.insert(device.device_id);
            used_domain_keys.insert(*domain_key);

            let (shard_role, shard_index) = match &self.layout.policy {
                DurabilityPolicy::Mirror { .. } => (ShardRole::Data, slot as u8),
                DurabilityPolicy::ErasureStyle { data_shards, .. } => {
                    if (slot as u8) < *data_shards {
                        (ShardRole::Data, slot as u8)
                    } else {
                        (ShardRole::Parity, slot as u8)
                    }
                }
                DurabilityPolicy::Hybrid { data_shards, .. } => {
                    let shard_within_copy = slot % (*data_shards as usize + 1);
                    if shard_within_copy < *data_shards as usize {
                        (ShardRole::Data, (shard_within_copy & 0xFF) as u8)
                    } else {
                        (ShardRole::Parity, (shard_within_copy & 0xFF) as u8)
                    }
                }
            };

            assignments.push(ShardAssignment {
                device_id: device.device_id,
                shard_index,
                shard_role,
            });
        }

        Ok(assignments)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the failure-domain key for a candidate at the given level.
///
/// Falls back to the next more-granular level when topology information is
/// missing: rack → node → device.
fn failure_domain_key(candidate: &DeviceCandidate, level: FailureDomainLevel) -> u64 {
    match level {
        FailureDomainLevel::Device => candidate.device_id,
        FailureDomainLevel::Node => candidate.node_id.unwrap_or(candidate.device_id),
        FailureDomainLevel::Rack => candidate
            .rack_id
            .or(candidate.node_id)
            .unwrap_or(candidate.device_id),
        FailureDomainLevel::Datacenter => candidate
            .datacenter_id
            .or(candidate.rack_id)
            .or(candidate.node_id)
            .unwrap_or(candidate.device_id),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_durability_layout::{DurabilityLayoutV1, FailureDomainLevel, FailureDomainV1};

    // -- Helpers ------------------------------------------------------------

    fn dev_simple(id: u64) -> DeviceCandidate {
        DeviceCandidate {
            device_id: id,
            node_id: None,
            rack_id: None,
            datacenter_id: None,
        }
    }

    fn dev_node(id: u64, node: u64) -> DeviceCandidate {
        DeviceCandidate {
            device_id: id,
            node_id: Some(node),
            rack_id: None,
            datacenter_id: None,
        }
    }

    fn dev_full(id: u64, node: u64, rack: u64) -> DeviceCandidate {
        DeviceCandidate {
            device_id: id,
            node_id: Some(node),
            rack_id: Some(rack),
            datacenter_id: None,
        }
    }

    // -- Mirror-2 across Device domains --------------------------------------

    #[test]
    fn mirror_2_device_level_selects_2_distinct_devices() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 4).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![
            dev_full(1, 10, 100),
            dev_full(2, 20, 200),
            dev_full(3, 30, 300),
        ];

        let assignments = plan.assign_devices(&candidates).unwrap();
        assert_eq!(assignments.len(), 2);
        // Both are data shards.
        assert!(assignments
            .iter()
            .all(|a| matches!(a.shard_role, ShardRole::Data)));
        // Distinct devices.
        let mut ids: Vec<u64> = assignments.iter().map(|a| a.device_id).collect();
        ids.sort();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn mirror_2_exact_devices() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_simple(10), dev_simple(20)];

        let assignments = plan.assign_devices(&candidates).unwrap();
        assert_eq!(assignments.len(), 2);
    }

    // -- Mirror-3 across Node domains ---------------------------------------

    #[test]
    fn mirror_3_node_level_selects_different_nodes() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 3).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        // 4 devices on 3 nodes — must pick one per node.
        let candidates = vec![
            dev_node(1, 10),
            dev_node(2, 10), // same node as 1
            dev_node(3, 20),
            dev_node(4, 30),
        ];

        let assignments = plan.assign_devices(&candidates).unwrap();
        assert_eq!(assignments.len(), 3);

        // No two assignments share the same node.
        let mut nodes: Vec<u64> = assignments
            .iter()
            .map(|a| {
                candidates
                    .iter()
                    .find(|c| c.device_id == a.device_id)
                    .unwrap()
                    .node_id
                    .unwrap()
            })
            .collect();
        nodes.sort();
        nodes.dedup();
        assert_eq!(nodes.len(), 3);
    }

    // -- Erasure 2+1 across Device domains ----------------------------------

    #[test]
    fn erasure_2_1_device_level() {
        let layout = DurabilityLayoutV1::erasure(2, 1).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 3).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_simple(1), dev_simple(2), dev_simple(3), dev_simple(4)];

        let assignments = plan.assign_devices(&candidates).unwrap();
        assert_eq!(assignments.len(), 3);

        // First 2 are data, last is parity.
        let data: Vec<_> = assignments
            .iter()
            .filter(|a| matches!(a.shard_role, ShardRole::Data))
            .collect();
        let parity: Vec<_> = assignments
            .iter()
            .filter(|a| matches!(a.shard_role, ShardRole::Parity))
            .collect();
        assert_eq!(data.len(), 2);
        assert_eq!(parity.len(), 1);
        // Shard indices should be 0,1 (data) and 2 (parity).
        assert_eq!(data[0].shard_index, 0);
        assert_eq!(data[1].shard_index, 1);
        assert_eq!(parity[0].shard_index, 2);
        // Distinct devices.
        let mut ids: Vec<u64> = assignments.iter().map(|a| a.device_id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 3);
    }

    // -- Erasure 4+2 across Node+Rack domains -------------------------------

    #[test]
    fn erasure_4_2_rack_level() {
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Rack, 6).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        // 6 devices across 6 distinct racks.
        let candidates = vec![
            dev_full(1, 10, 100),
            dev_full(2, 20, 200),
            dev_full(3, 30, 300),
            dev_full(4, 40, 400),
            dev_full(5, 50, 500),
            dev_full(6, 60, 600),
        ];

        let assignments = plan.assign_devices(&candidates).unwrap();
        assert_eq!(assignments.len(), 6);

        let data: Vec<_> = assignments
            .iter()
            .filter(|a| matches!(a.shard_role, ShardRole::Data))
            .collect();
        let parity: Vec<_> = assignments
            .iter()
            .filter(|a| matches!(a.shard_role, ShardRole::Parity))
            .collect();
        assert_eq!(data.len(), 4);
        assert_eq!(parity.len(), 2);

        // All distinct racks.
        let mut racks: Vec<u64> = assignments
            .iter()
            .map(|a| {
                candidates
                    .iter()
                    .find(|c| c.device_id == a.device_id)
                    .unwrap()
                    .rack_id
                    .unwrap()
            })
            .collect();
        racks.sort();
        racks.dedup();
        assert_eq!(racks.len(), 6);
    }

    // -- Erasure 4+2 across Node level with 2 devices per node --------------

    #[test]
    fn erasure_4_2_node_level_two_devices_per_node() {
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 6).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        // 12 devices: 2 per node, 6 nodes.
        let candidates: Vec<DeviceCandidate> = (0..6)
            .flat_map(|n| vec![dev_node(n * 10 + 1, n), dev_node(n * 10 + 2, n)])
            .collect();

        let assignments = plan.assign_devices(&candidates).unwrap();
        assert_eq!(assignments.len(), 6);

        // All on distinct nodes.
        let mut nodes: BTreeSet<u64> = BTreeSet::new();
        for a in &assignments {
            let node = candidates
                .iter()
                .find(|c| c.device_id == a.device_id)
                .unwrap()
                .node_id
                .unwrap();
            assert!(nodes.insert(node), "duplicate node {node}");
        }
        assert_eq!(nodes.len(), 6);
    }

    // -- Failure domain fallback --------------------------------------------

    #[test]
    fn rack_level_falls_back_to_node_when_rack_missing() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Rack, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        // Two devices: one with rack info, one without (same node, different
        // rack levels should NOT be collapsed).
        let candidates = vec![
            dev_full(1, 10, 100),
            dev_node(2, 10), // same node, no rack
        ];

        // At Rack level: dev 1 key = 100, dev 2 key = 10 (fallback to node).
        // Two distinct domains — should succeed.
        let assignments = plan.assign_devices(&candidates).unwrap();
        assert_eq!(assignments.len(), 2);
    }

    #[test]
    fn node_level_falls_back_to_device_when_node_missing() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        // Two devices with no node info — each becomes its own domain.
        let candidates = vec![dev_simple(1), dev_simple(2)];

        let assignments = plan.assign_devices(&candidates).unwrap();
        assert_eq!(assignments.len(), 2);
    }

    // -- Error: insufficient devices ----------------------------------------

    #[test]
    fn error_not_enough_devices() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 3).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_simple(1), dev_simple(2)];
        let err = plan.assign_devices(&candidates).unwrap_err();
        assert!(matches!(err, PlacementPlanError::NotEnoughDevices { .. }));
    }

    #[test]
    fn error_empty_candidates() {
        let layout = DurabilityLayoutV1::mirror(1).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 1).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let err = plan.assign_devices(&[]).unwrap_err();
        assert!(matches!(
            err,
            PlacementPlanError::NotEnoughDevices { available: 0, .. }
        ));
    }

    // -- Error: insufficient failure domains --------------------------------

    #[test]
    fn error_not_enough_failure_domains_node_level() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 3).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        // 3 devices but all on the same node.
        let candidates = vec![dev_node(1, 10), dev_node(2, 10), dev_node(3, 10)];

        let err = plan.assign_devices(&candidates).unwrap_err();
        assert!(matches!(
            err,
            PlacementPlanError::NotEnoughFailureDomains { .. }
        ));
    }

    // -- Edge cases ---------------------------------------------------------

    #[test]
    fn mirror_1_single_device_succeeds() {
        let layout = DurabilityLayoutV1::mirror(1).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 1).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_simple(42)];
        let assignments = plan.assign_devices(&candidates).unwrap();
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].device_id, 42);
        assert_eq!(assignments[0].shard_index, 0);
        assert!(matches!(assignments[0].shard_role, ShardRole::Data));
    }

    #[test]
    fn erasure_1_1_minimal() {
        let layout = DurabilityLayoutV1::erasure(1, 1).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates = vec![dev_simple(1), dev_simple(2)];
        let assignments = plan.assign_devices(&candidates).unwrap();
        assert_eq!(assignments.len(), 2);
        assert_eq!(assignments[0].shard_index, 0);
        assert!(matches!(assignments[0].shard_role, ShardRole::Data));
        assert_eq!(assignments[1].shard_index, 1);
        assert!(matches!(assignments[1].shard_role, ShardRole::Parity));
    }

    #[test]
    fn total_shards_mirror() {
        let plan = PlacementPlan::from_layout(
            DurabilityLayoutV1::mirror(3).unwrap(),
            FailureDomainV1::new(FailureDomainLevel::Device, 3).unwrap(),
        );
        assert_eq!(plan.total_shards(), 3);
    }

    #[test]
    fn total_shards_erasure() {
        let plan = PlacementPlan::from_layout(
            DurabilityLayoutV1::erasure(8, 3).unwrap(),
            FailureDomainV1::new(FailureDomainLevel::Node, 11).unwrap(),
        );
        assert_eq!(plan.total_shards(), 11);
    }

    #[test]
    fn layout_and_failure_domain_accessors() {
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Rack, 6).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);
        assert_eq!(*plan.layout(), layout);
        assert_eq!(*plan.failure_domain(), fd);
    }

    // -- Determinism --------------------------------------------------------

    #[test]
    fn same_input_same_output() {
        let layout = DurabilityLayoutV1::erasure(3, 2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 5).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        let candidates: Vec<DeviceCandidate> = (0..10).map(|i| dev_node(i, i / 2)).collect();

        let a = plan.assign_devices(&candidates).unwrap();
        let b = plan.assign_devices(&candidates).unwrap();
        assert_eq!(a, b);
    }

    // -- Device level with multiple devices per node ------------------------

    #[test]
    fn device_level_ignores_node_colocation() {
        // At Device level, each device is its own failure domain regardless
        // of node.
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        // Two devices on the same node — both should be selectable.
        let candidates = vec![dev_node(1, 10), dev_node(2, 10)];

        let assignments = plan.assign_devices(&candidates).unwrap();
        assert_eq!(assignments.len(), 2);
    }

    // -- Least-loaded domain preference -------------------------------------

    #[test]
    fn prefers_domains_with_fewer_devices() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 2).unwrap();
        let plan = PlacementPlan::from_layout(layout, fd);

        // Node 20 has 1 device, Node 10 has 3 devices.
        // Node 20 should be picked first (fewer devices = better spread).
        let candidates = vec![
            dev_node(1, 10),
            dev_node(2, 10),
            dev_node(3, 10),
            dev_node(4, 20),
        ];

        let assignments = plan.assign_devices(&candidates).unwrap();
        assert_eq!(assignments.len(), 2);
        // First assignment should be from node 20.
        assert_eq!(assignments[0].device_id, 4);
    }
}
