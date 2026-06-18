// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Rebuild scheduling from pool labels.
//!
//! When a pool is imported from device labels, missing or degraded
//! devices must be identified so that reconstruction can be scheduled.
//! This module provides [`RebuildScheduler`] which inspects the
//! assembled [`PoolConfig`] and produces [`RebuildAction`] items
//! describing what data reconstruction work is required.
//!
//! The scheduler is driven from imported pool authority: device
//! presence, health, and redundancy configuration all come from
//! labels, not from runtime topology guesses.

use serde::{Deserialize, Serialize};

use crate::{DeviceHealth, DeviceType, PoolConfig};
use tidefs_types_pool_label_core::PoolRedundancyPolicy;

// ---------------------------------------------------------------------------
// RebuildAction
// ---------------------------------------------------------------------------

/// A single reconstruction action required to restore pool health.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebuildAction {
    /// Kind of rebuild this action requires.
    pub kind: RebuildKind,
    /// Human-readable reason this rebuild is needed.
    pub reason: String,
    /// Affected device indices (missing or degraded).
    pub affected_device_indices: Vec<u32>,
    /// Index of the device that should receive rebuilt data,
    /// if a replacement has been selected.
    pub target_device_index: Option<u32>,
    /// Whether this rebuild is urgent (data-at-risk / no redundancy).
    pub urgent: bool,
}

/// Categories of rebuild work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RebuildKind {
    /// Replicated placement rebuild. The Rust variant name is retained for
    /// compatibility with older callers; new serde/display output uses
    /// pool-wide policy wording.
    #[serde(rename = "replicated-placement-rebuild", alias = "mirror-rebuild")]
    MirrorRebuild,
    /// Erasure placement rebuild. The Rust variant name is retained for
    /// compatibility with older callers; new serde/display output uses
    /// pool-wide policy wording.
    #[serde(rename = "erasure-placement-rebuild", alias = "parity-rebuild")]
    ParityRebuild,
    /// Device is degraded but still present; resilience-restore
    /// operation to bring it back to full health.
    ResilienceRestore,
    /// Device is faulted and must be replaced before any rebuild.
    DeviceReplace,
    /// No rebuild needed; device is healthy.
    NoAction,
}

impl std::fmt::Display for RebuildKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MirrorRebuild => f.write_str("replicated-placement-rebuild"),
            Self::ParityRebuild => f.write_str("erasure-placement-rebuild"),
            Self::ResilienceRestore => f.write_str("resilience-restore"),
            Self::DeviceReplace => f.write_str("device-replace"),
            Self::NoAction => f.write_str("no-action"),
        }
    }
}

// ---------------------------------------------------------------------------
// RebuildPlan
// ---------------------------------------------------------------------------

/// Result of inspecting pool labels for rebuild requirements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebuildPlan {
    /// Pool UUID from the labels.
    pub pool_uuid: [u8; 16],
    /// Pool name from the labels.
    pub pool_name: String,
    /// Current topology generation from the labels.
    pub topology_generation: u64,
    /// Total device count according to labels.
    pub device_count: u32,
    /// Number of missing devices detected.
    pub missing_count: u32,
    /// Number of degraded devices detected.
    pub degraded_count: u32,
    /// Actions required to restore pool health.
    pub actions: Vec<RebuildAction>,
    /// Whether any action is urgent (data at risk).
    pub any_urgent: bool,
    /// Summary message suitable for operator logging.
    pub summary: String,
}

impl RebuildPlan {
    /// Create an empty plan for a healthy pool.
    #[must_use]
    pub fn healthy(pool_uuid: [u8; 16], pool_name: &str, topology_generation: u64) -> Self {
        Self {
            pool_uuid,
            pool_name: pool_name.to_string(),
            topology_generation,
            device_count: 0,
            missing_count: 0,
            degraded_count: 0,
            actions: vec![],
            any_urgent: false,
            summary: "pool is healthy; no rebuild required".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// RebuildScheduler
// ---------------------------------------------------------------------------

/// Inspects an assembled [`PoolConfig`] from pool labels and schedules
/// rebuild actions for missing or degraded devices.
///
/// # Usage
///
/// ```ignore
/// let plan = RebuildScheduler::schedule(&pool_config);
/// for action in &plan.actions {
///     println!("Rebuild needed: {} ({})", action.reason, action.kind);
/// }
/// ```
pub struct RebuildScheduler;

impl RebuildScheduler {
    /// Inspect the pool config and produce a rebuild plan.
    ///
    /// The config must have been assembled from pool labels via
    /// [`crate::PoolAssembler::assemble`] so that `missing_indices`,
    /// device health, and topology are authoritative.
    #[must_use]
    pub fn schedule(config: &PoolConfig) -> RebuildPlan {
        let mut actions: Vec<RebuildAction> = Vec::new();
        let mut any_urgent = false;

        // 1. Missing devices: devices expected by device_count but
        //    not present in the tree.
        let present_indices = collect_present_indices(&config.device_tree);
        for expected_idx in 0..config.device_count {
            if !present_indices.contains(&expected_idx)
                || config.missing_indices.contains(&expected_idx)
            {
                let (kind, reason) = Self::action_for_missing(config, expected_idx);
                let urgent = kind != RebuildKind::NoAction;
                if urgent {
                    any_urgent = true;
                    actions.push(RebuildAction {
                        kind,
                        reason,
                        affected_device_indices: vec![expected_idx],
                        target_device_index: None,
                        urgent: true,
                    });
                }
            }
        }

        // 2. Degraded devices: present but health is Degraded or Faulted.
        for leaf in crate::DeviceRemovalPlanner::flatten_leaves(&config.device_tree) {
            let health = find_leaf_health(&config.device_tree, &leaf.device_path)
                .unwrap_or(DeviceHealth::Online);

            match health {
                DeviceHealth::Degraded => {
                    actions.push(RebuildAction {
                        kind: RebuildKind::ResilienceRestore,
                        reason: format!(
                            "device {} is degraded (index {})",
                            leaf.device_path.display(),
                            leaf.device_index
                        ),
                        affected_device_indices: vec![leaf.device_index],
                        target_device_index: Some(leaf.device_index),
                        urgent: false,
                    });
                }
                DeviceHealth::Faulted => {
                    any_urgent = true;
                    actions.push(RebuildAction {
                        kind: RebuildKind::DeviceReplace,
                        reason: format!(
                            "device {} is faulted (index {})",
                            leaf.device_path.display(),
                            leaf.device_index
                        ),
                        affected_device_indices: vec![leaf.device_index],
                        target_device_index: None,
                        urgent: true,
                    });
                }
                DeviceHealth::Online | DeviceHealth::Offline => {}
            }
        }

        let missing_count = config.missing_indices.len() as u32;
        let degraded_count = actions
            .iter()
            .filter(|a| matches!(a.kind, RebuildKind::ResilienceRestore))
            .count() as u32;

        let summary = if actions.is_empty() {
            "pool is healthy; no rebuild required".into()
        } else {
            format!(
                "{} rebuild action(s) required: {} missing, {} degraded{}",
                actions.len(),
                missing_count,
                degraded_count,
                if any_urgent { " (URGENT)" } else { "" }
            )
        };

        RebuildPlan {
            pool_uuid: config.pool_uuid,
            pool_name: config.pool_name.clone(),
            topology_generation: config.topology_generation,
            device_count: config.device_count,
            missing_count,
            degraded_count,
            actions,
            any_urgent,
            summary,
        }
    }

    /// Determine the rebuild action for a missing device.
    fn action_for_missing(config: &PoolConfig, device_index: u32) -> (RebuildKind, String) {
        let operational = operational_leaf_count(config);
        match config.redundancy_policy {
            PoolRedundancyPolicy::Replicated { copies } if copies > 1 && operational > 0 => (
                RebuildKind::MirrorRebuild,
                format!(
                    "device at index {device_index} is missing; pool-wide policy {} has \
                     {operational} operational source device(s); rebuild affected placement \
                     receipts from surviving replicas",
                    config.redundancy_policy
                ),
            ),
            PoolRedundancyPolicy::Erasure {
                data_shards,
                parity_shards: _,
            } if data_shards > 0 && operational >= data_shards as u16 => (
                RebuildKind::ParityRebuild,
                format!(
                    "device at index {device_index} is missing; pool-wide policy {} has \
                     {operational} operational source device(s); reconstruct affected placement \
                     receipts from surviving shards",
                    config.redundancy_policy
                ),
            ),
            policy => (
                RebuildKind::DeviceReplace,
                format!(
                    "device at index {device_index} is missing; pool-wide policy {policy} has \
                     {operational} operational source device(s), so affected placements require \
                     device replacement or external recovery"
                ),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Collect device indices present in the device tree.
fn collect_present_indices(tree: &DeviceType) -> Vec<u32> {
    let mut indices = Vec::new();
    collect_indices(tree, &mut indices);
    indices
}

fn collect_indices(node: &DeviceType, out: &mut Vec<u32>) {
    match node {
        DeviceType::Leaf { device_index, .. } => {
            out.push(*device_index);
        }
        DeviceType::PoolWideData { children }
        | DeviceType::Mirror { children }
        | DeviceType::ParityRaid { children, .. } => {
            for child in children {
                collect_indices(child, out);
            }
        }
    }
}

/// Look up the health of a leaf device by its path.
fn find_leaf_health(tree: &DeviceType, path: &std::path::Path) -> Option<DeviceHealth> {
    match tree {
        DeviceType::Leaf {
            device_path,
            health,
            ..
        } => {
            if device_path == path {
                Some(*health)
            } else {
                None
            }
        }
        DeviceType::PoolWideData { children }
        | DeviceType::Mirror { children }
        | DeviceType::ParityRaid { children, .. } => {
            children.iter().find_map(|c| find_leaf_health(c, path))
        }
    }
}

fn operational_leaf_count(config: &PoolConfig) -> u16 {
    config
        .device_tree
        .collect_leaves()
        .into_iter()
        .filter(|leaf| leaf.health.is_operational())
        .count() as u16
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceHealth, DeviceType, PoolConfig};
    use std::path::PathBuf;
    use tidefs_types_pool_label_core::{DeviceClass, PoolRedundancyPolicy, PoolState};

    fn make_leaf(path: &str, index: u32, guid: u8, health: DeviceHealth) -> DeviceType {
        DeviceType::Leaf {
            device_path: PathBuf::from(path),
            device_guid: [guid; 16],
            device_index: index,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        }
    }

    fn make_config(
        name: &str,
        policy: PoolRedundancyPolicy,
        device_tree: DeviceType,
        device_count: u32,
        missing_indices: Vec<u32>,
    ) -> PoolConfig {
        PoolConfig {
            pool_uuid: [0xABu8; 16],
            pool_name: name.into(),
            redundancy_policy: policy,
            device_tree,
            health: if missing_indices.is_empty() {
                DeviceHealth::Online
            } else {
                DeviceHealth::Degraded
            },
            state: PoolState::Active,
            total_capacity_bytes: device_count as u64 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count,
            missing_indices,
            removing_device_indices: vec![],
        }
    }

    fn assert_no_fixed_group_language(reason: &str) {
        let lower = reason.to_ascii_lowercase();
        assert!(!lower.contains("mirror"), "{reason}");
        assert!(!lower.contains("raidz"), "{reason}");
        assert!(!lower.contains("parity group"), "{reason}");
    }

    #[test]
    fn healthy_pool_has_no_actions() {
        let config = PoolConfig {
            pool_uuid: [0xAAu8; 16],
            pool_name: "healthy".into(),
            redundancy_policy: PoolRedundancyPolicy::replicated(1),
            device_tree: DeviceType::Mirror {
                children: vec![
                    make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online),
                    make_leaf("/dev/disk1", 1, 0x02, DeviceHealth::Online),
                ],
            },
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 2 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 2,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };

        let plan = RebuildScheduler::schedule(&config);
        assert!(plan.actions.is_empty());
        assert!(!plan.any_urgent);
        assert_eq!(plan.missing_count, 0);
        assert_eq!(plan.degraded_count, 0);
    }

    #[test]
    fn missing_device_in_replicated_policy_triggers_policy_rebuild() {
        let config = make_config(
            "missing-replicated",
            PoolRedundancyPolicy::replicated(2),
            DeviceType::ParityRaid {
                parity: 1,
                children: vec![
                    make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online),
                    make_leaf("/dev/disk1", 1, 0x02, DeviceHealth::Online),
                ],
            },
            3,
            vec![2],
        );

        let plan = RebuildScheduler::schedule(&config);
        assert_eq!(plan.missing_count, 1);
        assert_eq!(plan.actions.len(), 1);
        assert!(plan.any_urgent);

        let action = &plan.actions[0];
        assert_eq!(action.kind, RebuildKind::MirrorRebuild);
        assert_eq!(action.kind.to_string(), "replicated-placement-rebuild");
        assert!(action.reason.contains("replicated=2"));
        assert_no_fixed_group_language(&action.reason);
        assert!(action.urgent);
        assert_eq!(action.affected_device_indices, vec![2]);
    }

    #[test]
    fn degraded_device_triggers_resilience_restore() {
        let config = PoolConfig {
            pool_uuid: [0xCCu8; 16],
            pool_name: "degraded-device".into(),
            redundancy_policy: PoolRedundancyPolicy::replicated(1),
            device_tree: DeviceType::Mirror {
                children: vec![
                    make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online),
                    make_leaf("/dev/disk1", 1, 0x02, DeviceHealth::Degraded),
                ],
            },
            health: DeviceHealth::Degraded,
            state: PoolState::Active,
            total_capacity_bytes: 2 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 2,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };

        let plan = RebuildScheduler::schedule(&config);
        assert_eq!(plan.degraded_count, 1);

        let restore = plan
            .actions
            .iter()
            .find(|a| a.kind == RebuildKind::ResilienceRestore)
            .expect("should have resilience restore action");
        assert_eq!(restore.affected_device_indices, vec![1]);
        assert!(!restore.urgent);
    }

    #[test]
    fn faulted_device_triggers_replace() {
        let config = PoolConfig {
            pool_uuid: [0xDDu8; 16],
            pool_name: "faulted-device".into(),
            redundancy_policy: PoolRedundancyPolicy::replicated(1),
            device_tree: DeviceType::Mirror {
                children: vec![
                    make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online),
                    make_leaf("/dev/disk1", 1, 0x02, DeviceHealth::Faulted),
                ],
            },
            health: DeviceHealth::Degraded,
            state: PoolState::Active,
            total_capacity_bytes: 2 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 2,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };

        let plan = RebuildScheduler::schedule(&config);
        assert!(plan.any_urgent);

        let replace = plan
            .actions
            .iter()
            .find(|a| a.kind == RebuildKind::DeviceReplace)
            .expect("should have device replace action");
        assert_eq!(replace.affected_device_indices, vec![1]);
        assert!(replace.urgent);
    }

    #[test]
    fn missing_device_in_erasure_policy_triggers_erasure_rebuild() {
        let leaf0 = make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 1, 0x02, DeviceHealth::Online);
        let config = make_config(
            "erasure-missing",
            PoolRedundancyPolicy::erasure(2, 1),
            DeviceType::Mirror {
                children: vec![leaf0, leaf1],
            },
            3,
            vec![2],
        );

        let plan = RebuildScheduler::schedule(&config);
        assert!(plan.any_urgent);

        let action = &plan.actions[0];
        assert_eq!(action.kind, RebuildKind::ParityRebuild);
        assert_eq!(action.kind.to_string(), "erasure-placement-rebuild");
        assert!(action.reason.contains("erasure=2+1"));
        assert_no_fixed_group_language(&action.reason);
    }

    #[test]
    fn missing_device_in_single_policy_requires_replacement() {
        let config = make_config(
            "single-missing",
            PoolRedundancyPolicy::replicated(1),
            DeviceType::Mirror {
                children: vec![make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online)],
            },
            2,
            vec![1],
        );

        let plan = RebuildScheduler::schedule(&config);
        assert!(plan.any_urgent);
        let action = &plan.actions[0];
        assert_eq!(action.kind, RebuildKind::DeviceReplace);
        assert!(action.reason.contains("single"));
        assert_no_fixed_group_language(&action.reason);
    }

    #[test]
    fn erasure_policy_with_too_few_sources_requires_replacement() {
        let config = make_config(
            "erasure-too-few-sources",
            PoolRedundancyPolicy::erasure(2, 1),
            DeviceType::Mirror {
                children: vec![make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online)],
            },
            3,
            vec![1, 2],
        );

        let plan = RebuildScheduler::schedule(&config);
        assert_eq!(plan.actions.len(), 2);
        assert!(plan.any_urgent);
        for action in &plan.actions {
            assert_eq!(action.kind, RebuildKind::DeviceReplace);
            assert!(action.reason.contains("erasure=2+1"));
            assert_no_fixed_group_language(&action.reason);
        }
    }

    #[test]
    fn rebuild_plan_serde_roundtrip() {
        let plan = RebuildPlan {
            pool_uuid: [0x42u8; 16],
            pool_name: "test".into(),
            topology_generation: 5,
            device_count: 3,
            missing_count: 1,
            degraded_count: 0,
            actions: vec![RebuildAction {
                kind: RebuildKind::MirrorRebuild,
                reason: "missing policy placement".into(),
                affected_device_indices: vec![1],
                target_device_index: None,
                urgent: true,
            }],
            any_urgent: true,
            summary: "test summary".into(),
        };

        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("replicated-placement-rebuild"));
        assert!(!json.contains("mirror-rebuild"));
        let round: RebuildPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, round);
    }

    #[test]
    fn legacy_rebuild_kind_names_deserialize_as_policy_kinds() {
        assert_eq!(
            serde_json::from_str::<RebuildKind>("\"mirror-rebuild\"").unwrap(),
            RebuildKind::MirrorRebuild
        );
        assert_eq!(
            serde_json::from_str::<RebuildKind>("\"parity-rebuild\"").unwrap(),
            RebuildKind::ParityRebuild
        );
        assert_eq!(
            serde_json::to_string(&RebuildKind::MirrorRebuild).unwrap(),
            "\"replicated-placement-rebuild\""
        );
        assert_eq!(
            serde_json::to_string(&RebuildKind::ParityRebuild).unwrap(),
            "\"erasure-placement-rebuild\""
        );
    }

    #[test]
    fn healthy_plan_summary() {
        let plan = RebuildPlan::healthy([0xAAu8; 16], "healthypool", 1);
        assert!(plan.actions.is_empty());
        assert!(!plan.any_urgent);
        assert!(plan.summary.contains("healthy"));
    }
}
