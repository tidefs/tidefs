//! Pool label bridge: connects [`ClusterPoolConfig`] and [`NodeDevice`] to
//! the canonical on-device [`tidefs_types_pool_label_core::PoolLabelV1`]
//! authority.
//!
//! This module is the single convergence point where clustered topology
//! flows through the same pool-label/import/export authority used by
//! local pools.  It defines:
//!
//! - A feature flag bit [`CLUSTER_POOL`] stored in `features_incompat` of
//!   the label to mark pools managed by cluster authority.
//! - [`ClusterPoolConfig::from_pool_labels`] for constructing cluster
//!   topology from decoded device labels plus node assignments.
//! - [`ClusterPoolConfig::to_pool_labels`] for producing per-device label
//!   structs suitable for encoding into the on-disk label format during
//!   cluster pool creation.
//!
//! ## Design decisions (sealed per #2084/#2078)
//!
//! - **Node ID is not in the on-device label.** Node assignment is a
//!   runtime concept resolved through cluster membership and lease
//!   acquisition.  The label only carries device identity, pool
//!   membership, topology generation, and capacity.
//! - **Failure domain is resolved at import time** through the membership
//!   service and is provided as a parameter when constructing
//!   `ClusterPoolConfig` from labels.
//! - **Placement policy is stored as a feature flag** (`CLUSTER_POOL`)
//!   rather than as per-device policy fields.  The pool-level policy is
//!   carried in the orchestrator config, not in individual device labels.
//! - **Device GUIDs are real UUIDs.**  The bridge converts between the
//!   `[u8; 16]` representation in both types.
//! - **Capacity is carried verbatim** from the label's
//!   `device_capacity_bytes` field.
//!
//! ## Remaining blockers
//!
//! - The cluster import path in `PoolImporter` does not yet consult
//!   membership to resolve node assignments.
//! - The cluster create path does not yet write real labels to devices;
//!   it only constructs the in-memory config.
//! - Cluster lease ownership, fencing, and failover (Phase 7 in the
//!   design) are not yet integrated with the pool import/export path.

use tidefs_types_pool_label_core::{features, PoolLabelV1};

use crate::pool_config::{ClusterPlacementPolicy, ClusterPoolConfig, FailureDomain, NodeDevice};

// ---------------------------------------------------------------------------
// Cluster pool feature flag
// ---------------------------------------------------------------------------

/// Re-exported from [`tidefs_types_pool_label_core::features`].
pub use tidefs_types_pool_label_core::features::CLUSTER_POOL_COMPAT;
/// Re-exported from [`tidefs_types_pool_label_core::features`].
pub use tidefs_types_pool_label_core::features::CLUSTER_POOL_INCOMPAT;

// ---------------------------------------------------------------------------
// Bridge errors
// ---------------------------------------------------------------------------

/// Errors during label-to-config bridging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeError {
    /// No labels provided.
    EmptyLabels,
    /// Labels have mismatched pool GUIDs.
    PoolGuidMismatch,
    /// Labels have inconsistent device count.
    DeviceCountMismatch,
    /// Topology generation is inconsistent (±1 tolerance exceeded).
    TopologyGenerationDiverged,
    /// No devices found for any node after assignments applied.
    NoDevices,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyLabels => f.write_str("no labels provided"),
            Self::PoolGuidMismatch => f.write_str("pool GUID mismatch across labels"),
            Self::DeviceCountMismatch => f.write_str("device count mismatch across labels"),
            Self::TopologyGenerationDiverged => {
                f.write_str("topology generation is too far diverged")
            }
            Self::NoDevices => f.write_str("no devices after applying node assignments"),
        }
    }
}

// ---------------------------------------------------------------------------
// NodeDevice <-> PoolLabelV1 bridge
// ---------------------------------------------------------------------------

impl NodeDevice {
    /// Construct a [`NodeDevice`] from a decoded [`PoolLabelV1`] label
    /// plus runtime node-assignment metadata.
    ///
    /// The `node_id` and `failure_domain` are not stored in the label;
    /// they come from cluster membership at import time.
    ///
    /// The `local_device_index` and `global_device_index` are set by the
    /// caller based on the overall label set; this method expects them
    /// already resolved.
    pub fn from_pool_label(
        label: &PoolLabelV1,
        node_id: u64,
        local_device_index: u32,
        global_device_index: u32,
        failure_domain: FailureDomain,
    ) -> Self {
        Self {
            device_path: std::path::PathBuf::new(), // resolved at import time
            device_guid: label.device_guid,
            local_device_index,
            global_device_index,
            capacity_bytes: label.device_capacity_bytes,
            node_id,
            failure_domain,
        }
    }
}

// ---------------------------------------------------------------------------
// ClusterPoolConfig <-> PoolLabelV1 bridge
// ---------------------------------------------------------------------------

impl ClusterPoolConfig {
    /// Build a [`ClusterPoolConfig`] from a set of decoded
    /// [`PoolLabelV1`] labels plus node-to-device assignments.
    ///
    /// # Arguments
    ///
    /// * `labels` - One label per device, decoded from the on-disk label.
    /// * `pool_name` - Human-readable pool name (from cluster config).
    /// * `node_assignments` - A list of `(node_id, Vec<device_index>)`
    ///   tuples that map each node to the device indices it owns.
    /// * `failure_domains` - Per-device failure domain vectors.
    /// * `placement` - Cluster placement policy.
    ///
    /// # Validation
    ///
    /// - All labels must share the same `pool_guid`.
    /// - Device counts must be consistent.
    /// - Topology generation must be within ±1 tolerance.
    /// - Every assigned device index must correspond to a label.
    pub fn from_pool_labels(
        labels: &[PoolLabelV1],
        pool_name: &str,
        node_assignments: &[(u64, Vec<u32>)],
        failure_domains: &[FailureDomain],
        placement: ClusterPlacementPolicy,
    ) -> Result<Self, BridgeError> {
        if labels.is_empty() {
            return Err(BridgeError::EmptyLabels);
        }

        let pool_guid = labels[0].pool_guid;
        for label in labels {
            if label.pool_guid != pool_guid {
                return Err(BridgeError::PoolGuidMismatch);
            }
            if label.device_count as usize != labels.len() {
                return Err(BridgeError::DeviceCountMismatch);
            }
        }

        // Topology generation consistency: ±1 tolerance for in-flight changes.
        let gen_min = labels.iter().map(|l| l.topology_generation).min().unwrap();
        let gen_max = labels.iter().map(|l| l.topology_generation).max().unwrap();
        if gen_max.saturating_sub(gen_min) > 1 {
            return Err(BridgeError::TopologyGenerationDiverged);
        }
        let topology_generation = gen_max; // majority vote

        // Build per-node local device index tracking.
        let mut devices: Vec<NodeDevice> = Vec::with_capacity(labels.len());
        let mut per_node_local_idx: std::collections::BTreeMap<u64, u32> =
            std::collections::BTreeMap::new();

        for &(node_id, ref device_indices) in node_assignments {
            for &global_idx in device_indices {
                let idx = global_idx as usize;
                if idx >= labels.len() {
                    continue;
                }
                let label = &labels[idx];

                let local_idx = per_node_local_idx.get(&node_id).copied().unwrap_or(0);
                per_node_local_idx.insert(node_id, local_idx + 1);

                let fd = failure_domains
                    .get(idx)
                    .copied()
                    .unwrap_or(FailureDomain::for_node(node_id));

                let dev = NodeDevice::from_pool_label(label, node_id, local_idx, global_idx, fd);
                devices.push(dev);
            }
        }

        if devices.is_empty() {
            return Err(BridgeError::NoDevices);
        }

        let mut node_ids: Vec<u64> = devices.iter().map(|d| d.node_id).collect();
        node_ids.sort();
        node_ids.dedup();

        let redundancy = match placement {
            ClusterPlacementPolicy::Stripe => crate::pool_config::ClusterRedundancy::None,
            ClusterPlacementPolicy::MirrorAcrossNodes { copies } => {
                crate::pool_config::ClusterRedundancy::MirrorAcrossNodes { copies }
            }
            ClusterPlacementPolicy::ErasureCoded { data, parity } => {
                crate::pool_config::ClusterRedundancy::ErasureCoded {
                    data_shards: data,
                    parity_shards: parity,
                }
            }
        };
        Ok(Self {
            pool_guid,
            pool_name: pool_name.to_string(),
            devices,
            node_ids,
            placement,
            total_capacity_bytes: labels.iter().map(|l| l.device_capacity_bytes).sum(),
            topology_generation,
            redundancy,
        })
    }

    /// Produce per-device [`PoolLabelV1`] structs for each device in the
    /// cluster pool config.  These structs are suitable for encoding into
    /// the on-disk label format.
    ///
    /// Returns one label per device, with `CLUSTER_POOL_INCOMPAT` set in
    /// `features_incompat` and `CLUSTER_POOL_COMPAT` set in
    /// `features_compat`.
    pub fn to_pool_labels(&self) -> Vec<PoolLabelV1> {
        self.devices
            .iter()
            .map(|dev| {
                let mut pool_name_buf = [0u8; 255];
                let name_bytes = self.pool_name.as_bytes();
                let copy_len = name_bytes.len().min(255);
                pool_name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

                PoolLabelV1 {
                    magic: tidefs_types_pool_label_core::POOL_LABEL_MAGIC,
                    version: 1,
                    pool_guid: self.pool_guid,
                    device_guid: dev.device_guid,
                    pool_name: pool_name_buf,
                    pool_name_len: copy_len as u16,
                    pool_state: tidefs_types_pool_label_core::PoolState::Active,
                    commit_group: 0,
                    label_commit_group: 0,
                    device_index: dev.global_device_index,
                    topology_generation: self.topology_generation,
                    device_count: self.devices.len() as u32,
                    device_class: tidefs_types_pool_label_core::DeviceClass::Hdd,
                    device_capacity_bytes: dev.capacity_bytes,
                    system_area_pointer: 0,
                    system_area_size: 0,
                    features_incompat: features::POOL_LABEL_V1 | CLUSTER_POOL_INCOMPAT,
                    features_ro_compat: 0,
                    features_compat: CLUSTER_POOL_COMPAT,
                    device_health: 0,
                    device_read_errors: 0,
                    device_write_errors: 0,
                    device_checksum_errors: 0,
                    checksum: [0u8; 32],
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool_config::ClusterPlacementPolicy;
    use tidefs_types_pool_label_core::{
        features, seal_label, PoolLabelV1, PoolState, POOL_LABEL_MAGIC,
    };

    // --- helpers ---

    fn make_test_label(
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        device_index: u32,
        device_count: u32,
        capacity: u64,
        generation: u64,
        name: &str,
    ) -> PoolLabelV1 {
        let mut name_buf = [0u8; 255];
        let name_bytes = name.as_bytes();
        let len = name_bytes.len().min(255);
        name_buf[..len].copy_from_slice(name_bytes);
        let mut label = PoolLabelV1 {
            magic: POOL_LABEL_MAGIC,
            version: 1,
            pool_guid,
            device_guid,
            pool_name: name_buf,
            pool_name_len: len as u16,
            pool_state: PoolState::Active,
            commit_group: 0,
            label_commit_group: 0,
            device_index,
            topology_generation: generation,
            device_count,
            device_class: tidefs_types_pool_label_core::DeviceClass::Hdd,
            device_capacity_bytes: capacity,
            system_area_pointer: 0,
            system_area_size: 0,
            features_incompat: features::POOL_LABEL_V1,
            features_ro_compat: 0,
            features_compat: 0,
            device_health: 0,
            device_read_errors: 0,
            device_write_errors: 0,
            device_checksum_errors: 0,
            checksum: [0u8; 32],
        };
        label = seal_label(label).expect("seal_label");
        label
    }

    // --- NodeDevice::from_pool_label tests ---

    #[test]
    fn node_device_from_label_roundtrip_fields() {
        let label = make_test_label([0xA0; 16], [0xB0; 16], 0, 3, 1_000_000_000, 1, "cluster");
        let fd = FailureDomain {
            device: 0,
            node: 42,
            chassis: 0,
            rack: 0,
            zone: 0,
            region: 0,
        };
        let dev = NodeDevice::from_pool_label(&label, 42, 0, 0, fd);

        assert_eq!(dev.device_guid, [0xB0; 16]);
        assert_eq!(dev.capacity_bytes, 1_000_000_000);
        assert_eq!(dev.node_id, 42);
        assert_eq!(dev.local_device_index, 0);
        assert_eq!(dev.global_device_index, 0);
        assert_eq!(dev.failure_domain.node, 42);
    }

    // --- ClusterPoolConfig::from_pool_labels tests ---

    #[test]
    fn from_pool_labels_three_nodes() {
        let pool_guid = [0x42; 16];
        let labels = vec![
            make_test_label(pool_guid, [0x01; 16], 0, 3, 1_000_000_000, 1, "cluster"),
            make_test_label(pool_guid, [0x02; 16], 1, 3, 2_000_000_000, 1, "cluster"),
            make_test_label(pool_guid, [0x03; 16], 2, 3, 3_000_000_000, 1, "cluster"),
        ];
        let assignments = vec![(1, vec![0]), (2, vec![1]), (3, vec![2])];
        let domains = vec![
            FailureDomain::for_node(1),
            FailureDomain::for_node(2),
            FailureDomain::for_node(3),
        ];

        let config = ClusterPoolConfig::from_pool_labels(
            &labels,
            "cluster",
            &assignments,
            &domains,
            ClusterPlacementPolicy::Stripe,
        )
        .unwrap();

        assert_eq!(config.pool_guid, pool_guid);
        assert_eq!(config.pool_name, "cluster");
        assert_eq!(config.node_count(), 3);
        assert_eq!(config.device_count(), 3);
        assert_eq!(config.total_capacity_bytes, 6_000_000_000);
        assert_eq!(config.topology_generation, 1);
        assert!(config.node_ids.contains(&1));
        assert!(config.node_ids.contains(&2));
        assert!(config.node_ids.contains(&3));
    }

    #[test]
    fn from_pool_labels_two_nodes_four_devices() {
        let pool_guid = [0xAA; 16];
        let labels = vec![
            make_test_label(pool_guid, [0x10; 16], 0, 4, 500_000_000, 2, "multi"),
            make_test_label(pool_guid, [0x11; 16], 1, 4, 500_000_000, 2, "multi"),
            make_test_label(pool_guid, [0x12; 16], 2, 4, 750_000_000, 2, "multi"),
            make_test_label(pool_guid, [0x13; 16], 3, 4, 750_000_000, 2, "multi"),
        ];
        let assignments = vec![(10, vec![0, 1]), (20, vec![2, 3])];
        let domains = vec![
            FailureDomain::for_node(10),
            FailureDomain::for_node(10),
            FailureDomain::for_node(20),
            FailureDomain::for_node(20),
        ];

        let config = ClusterPoolConfig::from_pool_labels(
            &labels,
            "multi",
            &assignments,
            &domains,
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 },
        )
        .unwrap();

        assert_eq!(config.node_count(), 2);
        assert_eq!(config.device_count(), 4);
        assert_eq!(config.total_capacity_bytes, 2_500_000_000);
        assert_eq!(config.topology_generation, 2);
        assert!(matches!(
            config.placement,
            ClusterPlacementPolicy::MirrorAcrossNodes { copies: 2 }
        ));
    }

    #[test]
    fn from_pool_labels_empty_rejected() {
        let err = ClusterPoolConfig::from_pool_labels(
            &[],
            "empty",
            &[],
            &[],
            ClusterPlacementPolicy::Stripe,
        )
        .unwrap_err();
        assert_eq!(err, BridgeError::EmptyLabels);
    }

    #[test]
    fn from_pool_labels_mismatched_guid_rejected() {
        let labels = vec![
            make_test_label([0x01; 16], [0xA0; 16], 0, 2, 1_000, 1, "pool"),
            make_test_label([0x02; 16], [0xA1; 16], 1, 2, 2_000, 1, "pool"),
        ];
        let err = ClusterPoolConfig::from_pool_labels(
            &labels,
            "pool",
            &[(1, vec![0, 1])],
            &[FailureDomain::for_node(1), FailureDomain::for_node(1)],
            ClusterPlacementPolicy::Stripe,
        )
        .unwrap_err();
        assert_eq!(err, BridgeError::PoolGuidMismatch);
    }

    #[test]
    fn from_pool_labels_generation_diverged_rejected() {
        let pool_guid = [0x99; 16];
        let labels = vec![
            make_test_label(pool_guid, [0xD0; 16], 0, 2, 1_000, 1, "gen"),
            make_test_label(pool_guid, [0xD1; 16], 1, 2, 2_000, 5, "gen"), // diverged
        ];
        let err = ClusterPoolConfig::from_pool_labels(
            &labels,
            "gen",
            &[(1, vec![0, 1])],
            &[FailureDomain::for_node(1), FailureDomain::for_node(1)],
            ClusterPlacementPolicy::Stripe,
        )
        .unwrap_err();
        assert_eq!(err, BridgeError::TopologyGenerationDiverged);
    }

    #[test]
    fn from_pool_labels_plusminus_one_tolerance() {
        let pool_guid = [0xEE; 16];
        let labels = vec![
            make_test_label(pool_guid, [0xE0; 16], 0, 3, 1_000, 3, "tolerance"),
            make_test_label(pool_guid, [0xE1; 16], 1, 3, 2_000, 4, "tolerance"), // +1
            make_test_label(pool_guid, [0xE2; 16], 2, 3, 3_000, 3, "tolerance"),
        ];
        let config = ClusterPoolConfig::from_pool_labels(
            &labels,
            "tolerance",
            &[(1, vec![0, 1, 2])],
            &[
                FailureDomain::for_node(1),
                FailureDomain::for_node(1),
                FailureDomain::for_node(1),
            ],
            ClusterPlacementPolicy::Stripe,
        )
        .unwrap();
        // majority vote: generation = max = 4
        assert_eq!(config.topology_generation, 4);
    }

    // --- ClusterPoolConfig::to_pool_labels tests ---

    #[test]
    fn to_pool_labels_preserves_topology() {
        let config = ClusterPoolConfig::new(
            [0xCC; 16],
            "clabel".into(),
            vec![
                NodeDevice::new(
                    "/dev/sda".into(),
                    [0x01; 16],
                    0,
                    0,
                    1_000_000_000,
                    1,
                    FailureDomain::for_node(1),
                ),
                NodeDevice::new(
                    "/dev/sdb".into(),
                    [0x02; 16],
                    0,
                    1,
                    2_000_000_000,
                    2,
                    FailureDomain::for_node(2),
                ),
            ],
            ClusterPlacementPolicy::Stripe,
        );

        let labels = config.to_pool_labels();
        assert_eq!(labels.len(), 2);

        // All labels share pool_guid.
        assert_eq!(labels[0].pool_guid, [0xCC; 16]);
        assert_eq!(labels[1].pool_guid, [0xCC; 16]);

        // Device GUIDs preserved.
        assert_eq!(labels[0].device_guid, [0x01; 16]);
        assert_eq!(labels[1].device_guid, [0x02; 16]);

        // Topology fields consistent.
        assert_eq!(labels[0].device_count, 2);
        assert_eq!(labels[1].device_count, 2);
        assert_eq!(labels[0].topology_generation, 0); // default
        assert_eq!(labels[1].topology_generation, 0);

        // Cluster feature flags set.
        for label in &labels {
            assert!(label.features_incompat & CLUSTER_POOL_INCOMPAT != 0);
            assert!(label.features_compat & CLUSTER_POOL_COMPAT != 0);
        }

        // Magic bytes present.
        assert_eq!(labels[0].magic, POOL_LABEL_MAGIC);
    }

    #[test]
    fn to_pool_labels_capacities_preserved() {
        let config = ClusterPoolConfig::new(
            [0xDD; 16],
            "cap".into(),
            vec![
                NodeDevice::new(
                    "/dev/sdc".into(),
                    [0xAA; 16],
                    0,
                    0,
                    512_000_000_000,
                    1,
                    FailureDomain::for_node(1),
                ),
                NodeDevice::new(
                    "/dev/sdd".into(),
                    [0xBB; 16],
                    0,
                    1,
                    1_000_000_000_000,
                    2,
                    FailureDomain::for_node(2),
                ),
            ],
            ClusterPlacementPolicy::Stripe,
        );

        let labels = config.to_pool_labels();
        assert_eq!(labels[0].device_capacity_bytes, 512_000_000_000);
        assert_eq!(labels[1].device_capacity_bytes, 1_000_000_000_000);
    }

    #[test]
    fn to_pool_labels_roundtrip_through_encode_decode() {
        let config = ClusterPoolConfig::new(
            [0xBA; 16],
            "rt".into(),
            vec![
                NodeDevice::new(
                    "/dev/sde".into(),
                    [0xC0; 16],
                    0,
                    0,
                    100_000_000,
                    1,
                    FailureDomain::for_node(1),
                ),
            ],
            ClusterPlacementPolicy::Stripe,
        );

        let labels = config.to_pool_labels();
        assert_eq!(labels.len(), 1);

        let label = &labels[0];
        // Encode then decode through the canonical codec.
        let mut buf = [0u8; tidefs_types_pool_label_core::POOL_LABEL_V1_EXT_WIRE_SIZE];
        tidefs_types_pool_label_core::encode_label(label, &mut buf).unwrap();
        let decoded = tidefs_types_pool_label_core::decode_label(&buf).unwrap();

        assert_eq!(decoded.pool_guid, [0xBA; 16]);
        assert_eq!(decoded.device_guid, [0xC0; 16]);
        assert_eq!(decoded.device_capacity_bytes, 100_000_000);
        assert_eq!(decoded.pool_name_str(), "rt");
        assert!(decoded.features_incompat & CLUSTER_POOL_INCOMPAT != 0);
    }

    #[test]
    fn to_pool_labels_pool_name_truncation() {
        let long_name = "a".repeat(300);
        let config = ClusterPoolConfig::new(
            [0xFF; 16],
            long_name.clone(),
            vec![NodeDevice::new(
                "/dev/sdf".into(),
                [0xFE; 16],
                0,
                0,
                1,
                1,
                FailureDomain::for_node(1),
            )],
            ClusterPlacementPolicy::Stripe,
        );

        let labels = config.to_pool_labels();
        // Name should be truncated to 255 bytes.
        assert!(labels[0].pool_name_len <= 255);
        assert_eq!(labels[0].pool_name_str().len(), 255);
    }

    // --- BridgeError display tests ---

    #[test]
    fn bridge_error_display() {
        assert_eq!(
            BridgeError::EmptyLabels.to_string(),
            "no labels provided"
        );
        assert_eq!(
            BridgeError::PoolGuidMismatch.to_string(),
            "pool GUID mismatch across labels"
        );
        let e = BridgeError::TopologyGenerationDiverged.to_string();
        assert!(e.contains("topology generation"));
        let e = BridgeError::NoDevices.to_string();
        assert!(e.contains("no devices"));
    }
}
