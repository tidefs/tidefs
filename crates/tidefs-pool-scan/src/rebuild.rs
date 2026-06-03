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
    /// Mirror member missing: the missing device's copies must be
    /// recreated from surviving mirror members.
    MirrorRebuild,
    /// Parity RAID member missing: parity reconstruction is required
    /// to rebuild the missing data onto a replacement device.
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
            Self::MirrorRebuild => f.write_str("mirror-rebuild"),
            Self::ParityRebuild => f.write_str("parity-rebuild"),
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
        match &config.device_tree {
            DeviceType::Mirror { children } => {
                if !children.is_empty() {
                    (
                        RebuildKind::MirrorRebuild,
                        format!(
                            "mirror member at index {device_index} is missing; \
                             rebuild from surviving mirror members"
                        ),
                    )
                } else {
                    (
                        RebuildKind::NoAction,
                        format!(
                            "all mirror members missing at index {device_index}; \
                             pool is empty"
                        ),
                    )
                }
            }
            DeviceType::ParityRaid { parity, children } => {
                if children.len() >= *parity as usize {
                    (
                        RebuildKind::ParityRebuild,
                        format!(
                            "raidz member at index {device_index} is missing; \
                             reconstruct from parity and surviving data"
                        ),
                    )
                } else {
                    (
                        RebuildKind::NoAction,
                        format!(
                            "insufficient raidz members for index {device_index}; \
                             pool is faulted"
                        ),
                    )
                }
            }
            DeviceType::Leaf { .. } => {
                if config.device_count <= 1 {
                    (
                        RebuildKind::NoAction,
                        format!(
                            "sole device at index {device_index} is missing; \
                             pool is destroyed"
                        ),
                    )
                } else {
                    (
                        RebuildKind::DeviceReplace,
                        format!(
                            "device at index {device_index} is missing; \
                             replacement required"
                        ),
                    )
                }
            }
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
        DeviceType::Mirror { children } | DeviceType::ParityRaid { children, .. } => {
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
        DeviceType::Mirror { children } | DeviceType::ParityRaid { children, .. } => {
            children.iter().find_map(|c| find_leaf_health(c, path))
        }
    }
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
    use tidefs_types_pool_label_core::{DeviceClass, PoolState};

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

    #[test]
    fn healthy_pool_has_no_actions() {
        let config = PoolConfig {
            pool_uuid: [0xAAu8; 16],
            pool_name: "healthy".into(),
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
    fn missing_device_in_mirror_triggers_rebuild() {
        let config = PoolConfig {
            pool_uuid: [0xBBu8; 16],
            pool_name: "missing-mirror".into(),
            device_tree: DeviceType::Mirror {
                children: vec![
                    make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online),
                    make_leaf("/dev/disk1", 1, 0x02, DeviceHealth::Online),
                ],
            },
            health: DeviceHealth::Degraded,
            state: PoolState::Active,
            total_capacity_bytes: 2 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 3,
            missing_indices: vec![2],
            removing_device_indices: vec![],
        };

        let plan = RebuildScheduler::schedule(&config);
        assert_eq!(plan.missing_count, 1);
        assert_eq!(plan.actions.len(), 1);
        assert!(plan.any_urgent);

        let action = &plan.actions[0];
        assert_eq!(action.kind, RebuildKind::MirrorRebuild);
        assert!(action.urgent);
        assert_eq!(action.affected_device_indices, vec![2]);
    }

    #[test]
    fn degraded_device_triggers_resilience_restore() {
        let config = PoolConfig {
            pool_uuid: [0xCCu8; 16],
            pool_name: "degraded-device".into(),
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
    fn missing_device_in_raidz_triggers_parity_rebuild() {
        let leaf0 = make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online);
        let leaf1 = make_leaf("/dev/disk1", 1, 0x02, DeviceHealth::Online);
        let config = PoolConfig {
            pool_uuid: [0xEEu8; 16],
            pool_name: "raidz-missing".into(),
            device_tree: DeviceType::ParityRaid {
                parity: 1,
                children: vec![leaf0, leaf1],
            },
            health: DeviceHealth::Degraded,
            state: PoolState::Active,
            total_capacity_bytes: 2 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 3,
            missing_indices: vec![2],
            removing_device_indices: vec![],
        };

        let plan = RebuildScheduler::schedule(&config);
        assert!(plan.any_urgent);

        let action = &plan.actions[0];
        assert_eq!(action.kind, RebuildKind::ParityRebuild);
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
                reason: "missing mirror member".into(),
                affected_device_indices: vec![1],
                target_device_index: None,
                urgent: true,
            }],
            any_urgent: true,
            summary: "test summary".into(),
        };

        let json = serde_json::to_string(&plan).unwrap();
        let round: RebuildPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, round);
    }

    #[test]
    fn healthy_plan_summary() {
        let plan = RebuildPlan::healthy([0xAAu8; 16], "healthypool", 1);
        assert!(plan.actions.is_empty());
        assert!(!plan.any_urgent);
        assert!(plan.summary.contains("healthy"));
    }
}
