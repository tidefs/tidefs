//! Cluster pool configuration: device-to-node topology, failure domains,
//! placement policy, and redundancy for multi-node TideFS pools.
//!
//! This module defines the data model for clustered pool creation, import,
//! and mount.  It bridges the membership/node-identity layer with the
//! pool-scan device topology, so that pool operations can reason about
//! which node owns each device and how data placement respects failure
//! domains.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// FailureDomain — failure-domain vector for a device
// ---------------------------------------------------------------------------

/// Failure-domain vector locating a device in the cluster topology.
///
/// Mirrors [`tidefs_membership_types::FailureDomainVector`] with serde
/// support for pool configuration serialization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureDomain {
    /// Device-local domain id.
    pub device: u64,
    /// Node domain id.
    pub node: u64,
    /// Chassis domain id.
    pub chassis: u64,
    /// Rack domain id.
    pub rack: u64,
    /// Zone domain id.
    pub zone: u64,
    /// Region domain id.
    pub region: u64,
}

impl FailureDomain {
    /// Zero-value failure domain.
    pub const ZERO: Self = Self {
        device: 0,
        node: 0,
        chassis: 0,
        rack: 0,
        zone: 0,
        region: 0,
    };

    /// Create a failure domain with just the node id set.
    pub const fn for_node(node_id: u64) -> Self {
        Self {
            device: 0,
            node: node_id,
            chassis: 0,
            rack: 0,
            zone: 0,
            region: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// NodeDevice — a block device bound to a specific cluster node
// ---------------------------------------------------------------------------

/// A block device owned by a specific node, with its failure-domain
/// position in the cluster topology.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDevice {
    /// Absolute path to the block device on the owning node.
    pub device_path: PathBuf,
    /// Per-device GUID from the pool label.
    pub device_guid: [u8; 16],
    /// 0-based device index within this node's local device set.
    pub local_device_index: u32,
    /// Global device index across all nodes in the pool (assigned during
    /// pool creation to produce a stable ordering).
    pub global_device_index: u32,
    /// Total device capacity in bytes.
    pub capacity_bytes: u64,
    /// The node that owns and serves this device.
    pub node_id: u64,
    /// Failure-domain vector for this device.
    pub failure_domain: FailureDomain,
}

impl NodeDevice {
    /// Create a new node-device binding.
    pub fn new(
        device_path: PathBuf,
        device_guid: [u8; 16],
        local_device_index: u32,
        global_device_index: u32,
        capacity_bytes: u64,
        node_id: u64,
        failure_domain: FailureDomain,
    ) -> Self {
        Self {
            device_path,
            device_guid,
            local_device_index,
            global_device_index,
            capacity_bytes,
            node_id,
            failure_domain,
        }
    }
}

// ---------------------------------------------------------------------------
// ClusterRedundancy — redundancy policy for multi-node pools
// ---------------------------------------------------------------------------

/// Redundancy configuration for a clustered pool.
///
/// This is the multi-node analog of the single-node `RedundancyPolicy`
/// in [`tidefs_pool_import::create`].  Node-level mirroring places copies
/// on distinct nodes so that data survives the loss of any single node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterRedundancy {
    /// No redundancy — single copy of all data.
    None,
    /// N-way mirroring with each copy on a distinct node.
    MirrorAcrossNodes {
        /// Number of copies (1 = single device, 2+ = mirrored across nodes).
        copies: u8,
    },
    /// Erasure coding with data and parity shards distributed across nodes.
    ErasureCoded {
        /// Number of data shards.
        data_shards: u8,
        /// Number of parity shards.
        parity_shards: u8,
    },
}

impl ClusterRedundancy {
    /// Minimum number of nodes required for this redundancy policy.
    pub fn min_nodes(&self) -> usize {
        match self {
            Self::None => 1,
            Self::MirrorAcrossNodes { copies } => *copies as usize,
            Self::ErasureCoded {
                data_shards,
                parity_shards,
            } => (*data_shards + *parity_shards) as usize,
        }
    }

    /// Number of fault domains (nodes) that can fail without data loss.
    pub fn fault_tolerance(&self) -> usize {
        match self {
            Self::None => 0,
            Self::MirrorAcrossNodes { copies } => (*copies as usize).saturating_sub(1),
            Self::ErasureCoded { parity_shards, .. } => *parity_shards as usize,
        }
    }
}

// ---------------------------------------------------------------------------
// ClusterPlacementPolicy — data placement across nodes and devices
// ---------------------------------------------------------------------------

/// Placement policy for data across cluster nodes and devices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterPlacementPolicy {
    /// Data is striped across all devices with no redundancy.
    Stripe,
    /// Data is mirrored across N nodes (node-level mirroring).
    MirrorAcrossNodes {
        /// Number of node-level copies.
        copies: u8,
    },
    /// Data is placed with erasure coding across nodes.
    ErasureCoded {
        /// Number of data shards.
        data: u8,
        /// Number of parity shards.
        parity: u8,
    },
}

impl ClusterPlacementPolicy {
    /// Derive a placement policy from a redundancy configuration.
    pub fn from_redundancy(r: ClusterRedundancy) -> Self {
        match r {
            ClusterRedundancy::None => Self::Stripe,
            ClusterRedundancy::MirrorAcrossNodes { copies } => Self::MirrorAcrossNodes { copies },
            ClusterRedundancy::ErasureCoded {
                data_shards,
                parity_shards,
            } => Self::ErasureCoded {
                data: data_shards,
                parity: parity_shards,
            },
        }
    }

    /// Desired number of distinct nodes per object for this policy.
    ///
    /// For MirrorAcrossNodes, returns `copies`. For ErasureCoded,
    /// returns `data + parity` (all shards must be placed on distinct
    /// nodes). For Stripe, returns 1.
    pub fn desired_node_count(&self) -> usize {
        match self {
            Self::Stripe => 1,
            Self::MirrorAcrossNodes { copies } => *copies as usize,
            Self::ErasureCoded { data, parity } => (*data + *parity) as usize,
        }
    }

    /// Nodes that can be lost without data loss.
    pub fn fault_tolerance_nodes(&self) -> usize {
        match self {
            Self::Stripe => 0,
            Self::MirrorAcrossNodes { copies } => (*copies as usize).saturating_sub(1),
            Self::ErasureCoded { parity, .. } => *parity as usize,
        }
    }

    /// Minimum distinct failure domains required for safety.
    ///
    /// Returns the desired node count. Callers should ensure replicas
    /// span at least this many distinct failure-domain roots (typically
    /// node-level, but can be rack-level).
    pub fn min_distinct_failure_domains(&self) -> usize {
        self.desired_node_count()
    }
}

// ---------------------------------------------------------------------------
// ClusterPoolConfig — the canonical clustered pool definition
// ---------------------------------------------------------------------------

/// Configuration for a TideFS pool whose devices and services are spread
/// across multiple cluster nodes.
///
/// `ClusterPoolConfig` is the multi-node analog of
/// [`tidefs_pool_scan::PoolConfig`].  It records which node owns each
/// device, the failure-domain topology, and the placement/redundancy
/// policy so that pool import, mount, and data-path operations can
/// route I/O to the correct node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPoolConfig {
    /// Pool UUID (identical across all devices and nodes).
    pub pool_guid: [u8; 16],
    /// Human-readable pool name.
    pub pool_name: String,
    /// All devices in the pool, each bound to a specific node.
    pub devices: Vec<NodeDevice>,
    /// Sorted, deduplicated list of participating node IDs.
    pub node_ids: Vec<u64>,
    /// Placement policy for data across the cluster.
    pub placement: ClusterPlacementPolicy,
    /// Total raw capacity across all devices.
    pub total_capacity_bytes: u64,
    /// Topology generation — must match across all devices.
    pub topology_generation: u64,
    /// Redundancy policy.
    pub redundancy: ClusterRedundancy,
    /// Permit regular files as development pool media during cluster create.
    ///
    /// Production clustered pools use block devices. Regular files are
    /// accepted only when the initiating operator explicitly enables this
    /// development mode, matching local `pool create --file-devices`.
    pub allow_file_devices: bool,
}

impl ClusterPoolConfig {
    /// Create a new cluster pool configuration.
    ///
    /// Node IDs are derived from the device list, sorted, and deduplicated.
    /// Total capacity is summed from all devices.
    pub fn new(
        pool_guid: [u8; 16],
        pool_name: String,
        devices: Vec<NodeDevice>,
        placement: ClusterPlacementPolicy,
    ) -> Self {
        let redundancy = match placement {
            ClusterPlacementPolicy::Stripe => ClusterRedundancy::None,
            ClusterPlacementPolicy::MirrorAcrossNodes { copies } => {
                ClusterRedundancy::MirrorAcrossNodes { copies }
            }
            ClusterPlacementPolicy::ErasureCoded { data, parity } => {
                ClusterRedundancy::ErasureCoded {
                    data_shards: data,
                    parity_shards: parity,
                }
            }
        };
        let mut node_ids: Vec<u64> = devices.iter().map(|d| d.node_id).collect();
        node_ids.sort();
        node_ids.dedup();
        let total_capacity_bytes = devices.iter().map(|d| d.capacity_bytes).sum();
        Self {
            pool_guid,
            pool_name,
            devices,
            node_ids,
            placement,
            total_capacity_bytes,
            topology_generation: 0,
            redundancy,
            allow_file_devices: false,
        }
    }

    /// Return this config with explicit regular-file development media
    /// enabled or disabled.
    pub fn with_file_devices_for_development(mut self, allow: bool) -> Self {
        self.allow_file_devices = allow;
        self
    }

    /// Number of nodes participating in this pool.
    pub fn node_count(&self) -> usize {
        self.node_ids.len()
    }

    /// Number of devices in this pool.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Get devices for a specific node.
    pub fn devices_for_node(&self, node_id: u64) -> Vec<&NodeDevice> {
        self.devices
            .iter()
            .filter(|d| d.node_id == node_id)
            .collect()
    }

    /// Check that the pool has sufficient nodes for its redundancy policy.
    pub fn has_sufficient_nodes(&self) -> bool {
        self.node_ids.len() >= self.redundancy.min_nodes()
    }

    /// Return true if any two devices share the same global device index.
    ///
    /// Duplicate global indices would cause ambiguity in topology
    /// assignment and metadata addressing.
    pub fn has_duplicate_global_indices(&self) -> bool {
        let mut seen: Vec<u32> = Vec::with_capacity(self.devices.len());
        for d in &self.devices {
            if seen.contains(&d.global_device_index) {
                return true;
            }
            seen.push(d.global_device_index);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_device(node_id: u64, local_idx: u32, global_idx: u32) -> NodeDevice {
        NodeDevice::new(
            PathBuf::from(format!("/dev/node{node_id}-disk{local_idx}")),
            [local_idx as u8; 16],
            local_idx,
            global_idx,
            1024 * 1024 * 1024, // 1 GiB
            node_id,
            FailureDomain {
                device: local_idx as u64,
                node: node_id,
                chassis: 0,
                rack: 0,
                zone: 0,
                region: 0,
            },
        )
    }

    // -- NodeDevice tests --

    #[test]
    fn node_device_fields_preserved() {
        let dev = make_test_device(3, 1, 7);
        assert_eq!(dev.node_id, 3);
        assert_eq!(dev.local_device_index, 1);
        assert_eq!(dev.global_device_index, 7);
        assert_eq!(dev.capacity_bytes, 1024 * 1024 * 1024);
        assert_eq!(dev.failure_domain.node, 3);
    }

    // -- FailureDomain tests --

    #[test]
    fn failure_domain_zero() {
        assert_eq!(FailureDomain::ZERO.node, 0);
        assert_eq!(FailureDomain::ZERO.device, 0);
    }

    #[test]
    fn failure_domain_for_node() {
        let fd = FailureDomain::for_node(42);
        assert_eq!(fd.node, 42);
        assert_eq!(fd.device, 0);
    }

    // -- ClusterRedundancy tests --

    #[test]
    fn redundancy_none_min_nodes() {
        assert_eq!(ClusterRedundancy::None.min_nodes(), 1);
        assert_eq!(ClusterRedundancy::None.fault_tolerance(), 0);
    }

    #[test]
    fn redundancy_mirror_3_way() {
        let r = ClusterRedundancy::MirrorAcrossNodes { copies: 3 };
        assert_eq!(r.min_nodes(), 3);
        assert_eq!(r.fault_tolerance(), 2);
    }

    #[test]
    fn redundancy_erasure_4_2() {
        let r = ClusterRedundancy::ErasureCoded {
            data_shards: 4,
            parity_shards: 2,
        };
        assert_eq!(r.min_nodes(), 6);
        assert_eq!(r.fault_tolerance(), 2);
    }

    // -- ClusterPlacementPolicy tests --

    #[test]
    fn placement_from_redundancy_none() {
        let p = ClusterPlacementPolicy::from_redundancy(ClusterRedundancy::None);
        assert_eq!(p, ClusterPlacementPolicy::Stripe);
    }

    #[test]
    fn placement_from_redundancy_mirror() {
        let p = ClusterPlacementPolicy::from_redundancy(ClusterRedundancy::MirrorAcrossNodes {
            copies: 2,
        });
        assert_eq!(p, ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 });
    }

    #[test]
    fn placement_from_redundancy_erasure() {
        let p = ClusterPlacementPolicy::from_redundancy(ClusterRedundancy::ErasureCoded {
            data_shards: 3,
            parity_shards: 2,
        });
        assert_eq!(
            p,
            ClusterPlacementPolicy::ErasureCoded { data: 3, parity: 2 }
        );
    }

    // -- ClusterPoolConfig tests --

    #[test]
    fn cluster_pool_config_three_nodes() {
        let devices = vec![
            make_test_device(1, 0, 0),
            make_test_device(2, 0, 1),
            make_test_device(3, 0, 2),
        ];
        let config = ClusterPoolConfig::new(
            [0xAA; 16],
            "clusterpool".into(),
            devices,
            ClusterPlacementPolicy::Stripe,
        );
        assert_eq!(config.pool_name, "clusterpool");
        assert_eq!(config.pool_guid, [0xAA; 16]);
        assert_eq!(config.node_count(), 3);
        assert_eq!(config.device_count(), 3);
        assert_eq!(config.node_ids, vec![1, 2, 3]);
        assert_eq!(config.total_capacity_bytes, 3 * 1024 * 1024 * 1024);
        assert!(!config.allow_file_devices);
    }

    #[test]
    fn cluster_pool_config_file_devices_default_off_and_opt_in() {
        let devices = vec![make_test_device(1, 0, 0)];
        let config = ClusterPoolConfig::new(
            [0xAF; 16],
            "devmedia".into(),
            devices,
            ClusterPlacementPolicy::Stripe,
        );
        assert!(!config.allow_file_devices);

        let config = config.with_file_devices_for_development(true);
        assert!(config.allow_file_devices);
    }

    #[test]
    fn cluster_pool_config_two_nodes_four_devices() {
        let devices = vec![
            make_test_device(1, 0, 0),
            make_test_device(1, 1, 1),
            make_test_device(2, 0, 2),
            make_test_device(2, 1, 3),
        ];
        let config = ClusterPoolConfig::new(
            [0xBB; 16],
            "multidisk".into(),
            devices,
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 },
        );
        assert_eq!(config.node_count(), 2);
        assert_eq!(config.device_count(), 4);
        assert_eq!(config.node_ids, vec![1, 2]);
        assert_eq!(
            config.redundancy,
            ClusterRedundancy::MirrorAcrossNodes { copies: 2 }
        );
    }

    #[test]
    fn devices_for_node_filters_correctly() {
        let devices = vec![
            make_test_device(10, 0, 0),
            make_test_device(10, 1, 1),
            make_test_device(20, 0, 2),
        ];
        let config = ClusterPoolConfig::new(
            [0xCC; 16],
            "filtered".into(),
            devices,
            ClusterPlacementPolicy::Stripe,
        );
        let node10_devs = config.devices_for_node(10);
        assert_eq!(node10_devs.len(), 2);
        assert!(node10_devs.iter().all(|d| d.node_id == 10));

        let node20_devs = config.devices_for_node(20);
        assert_eq!(node20_devs.len(), 1);

        let node99_devs = config.devices_for_node(99);
        assert!(node99_devs.is_empty());
    }

    #[test]
    fn cluster_pool_config_dedup_node_ids() {
        let devices = vec![
            make_test_device(5, 0, 0),
            make_test_device(5, 1, 1),
            make_test_device(5, 2, 2),
            make_test_device(5, 3, 3),
        ];
        let config = ClusterPoolConfig::new(
            [0xDD; 16],
            "singlenode".into(),
            devices,
            ClusterPlacementPolicy::Stripe,
        );
        assert_eq!(config.node_ids.len(), 1);
        assert_eq!(config.node_ids, vec![5]);
    }

    #[test]
    fn cluster_pool_config_erasure_placement() {
        let devices = vec![
            make_test_device(1, 0, 0),
            make_test_device(2, 0, 1),
            make_test_device(3, 0, 2),
            make_test_device(4, 0, 3),
            make_test_device(5, 0, 4),
            make_test_device(6, 0, 5),
        ];
        let config = ClusterPoolConfig::new(
            [0xEE; 16],
            "erasure".into(),
            devices,
            ClusterPlacementPolicy::ErasureCoded { data: 4, parity: 2 },
        );
        assert_eq!(config.node_count(), 6);
        assert_eq!(
            config.redundancy,
            ClusterRedundancy::ErasureCoded {
                data_shards: 4,
                parity_shards: 2,
            }
        );
        assert_eq!(config.redundancy.min_nodes(), 6);
        assert_eq!(config.redundancy.fault_tolerance(), 2);
    }

    #[test]
    fn has_sufficient_nodes() {
        let devices_2 = vec![make_test_device(1, 0, 0), make_test_device(2, 0, 1)];
        let config = ClusterPoolConfig::new(
            [0xFF; 16],
            "sufficient".into(),
            devices_2,
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 },
        );
        assert!(config.has_sufficient_nodes());

        let devices_1 = vec![make_test_device(1, 0, 0)];
        let config = ClusterPoolConfig::new(
            [0x00; 16],
            "insufficient".into(),
            devices_1,
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 3 },
        );
        assert!(!config.has_sufficient_nodes());
    }

    // -- serde round-trip test --

    #[test]
    fn serde_roundtrip_cluster_pool_config() {
        let devices = vec![
            make_test_device(1, 0, 0),
            make_test_device(2, 0, 1),
            make_test_device(3, 0, 2),
        ];
        let config = ClusterPoolConfig::new(
            [0x42; 16],
            "serde_test".into(),
            devices,
            ClusterPlacementPolicy::Stripe,
        );

        let json = serde_json::to_string(&config).unwrap();
        let roundtripped: ClusterPoolConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, roundtripped);
    }

    #[test]
    fn mirror_requires_at_least_two_nodes() {
        let devices = vec![make_test_device(1, 0, 0)];
        let config = ClusterPoolConfig::new(
            [0xAA; 16],
            "lonenode".into(),
            devices,
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 },
        );
        assert!(
            !config.has_sufficient_nodes(),
            "mirror with 1 node must be insufficient"
        );
        assert_eq!(config.redundancy.min_nodes(), 2);
    }

    #[test]
    fn stripe_with_one_node_is_sufficient() {
        let devices = vec![make_test_device(1, 0, 0)];
        let config = ClusterPoolConfig::new(
            [0xBB; 16],
            "singlenode".into(),
            devices,
            ClusterPlacementPolicy::Stripe,
        );
        assert!(
            config.has_sufficient_nodes(),
            "stripe with 1 node must be sufficient"
        );
        assert_eq!(config.redundancy.min_nodes(), 1);
    }

    #[test]
    fn detects_duplicate_global_device_indices() {
        let mut d1 = make_test_device(1, 0, 0);
        d1.global_device_index = 5;
        let mut d2 = make_test_device(2, 0, 1);
        d2.global_device_index = 5; // duplicate
        let config = ClusterPoolConfig::new(
            [0xCC; 16],
            "dupglobal".into(),
            vec![d1, d2],
            ClusterPlacementPolicy::Stripe,
        );
        assert!(config.has_duplicate_global_indices());
    }

    #[test]
    fn unique_global_indices_not_flagged() {
        let d1 = make_test_device(1, 0, 0);
        let d2 = make_test_device(2, 0, 1);
        let config = ClusterPoolConfig::new(
            [0xDD; 16],
            "unique".into(),
            vec![d1, d2],
            ClusterPlacementPolicy::Stripe,
        );
        assert!(!config.has_duplicate_global_indices());
    }
}
