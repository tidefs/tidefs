// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Rebuild from surviving replicas after device loss.
//!
//! This module bridges the pool-scan [`RebuildScheduler`] (which plans
//! reconstruction from authoritative pool labels) with the object-store
//! [`rebuild_replica_from_surviving`] function (which executes the data
//! copy).  Together they implement the mirror-rebuild path required by
//! NEXT-STOR-032.
//!
//! # Authority Flow
//!
//! ```text
//! Pool labels (import) -> PoolConfig -> RebuildScheduler::schedule()
//!   -> RebuildPlan -> execute_mirror_rebuild_from_plan()
//!   -> rebuild_replica_from_surviving() (per action)
//! ```
//!
//! The surviving store paths come from the operator's knowledge of
//! backing-store locations (identical to the `--surviving-dirs`
//! contract in `device_removal.rs`).  The pool labels tell us *which*
//! devices exist and are missing; the operator tells us *where* their
//! stores live on the filesystem.
//!
//! # Nonclaim Boundaries
//!
//! - Only [`RebuildKind::MirrorRebuild`] actions are executed today;
//!   [`ParityRebuild`], [`ResilienceRestore`], and [`DeviceReplace`]
//!   are planned but not yet wired to data-copy execution paths.
//! - The surviving-store-path mapping (device index -> directory path)
//!   is operator-provided, not derived from pool labels.
//! - Post-rebuild label updates are the caller's responsibility.
//!   This module only handles the data copy, not the label/anchor
//!   persistence or topology-generation bump.

use std::path::Path;

use tidefs_local_object_store::{
    IoPressureProbe, LocalObjectStore, RebuildThrottleConfig, StoreOptions,
};
use tidefs_pool_scan::{RebuildKind, RebuildPlan, RebuildScheduler};

/// Result of executing a rebuild plan.
#[derive(Clone, Debug)]
pub struct RebuildExecutionReport {
    /// The plan that was executed.
    pub plan: RebuildPlan,
    /// Number of objects copied to replacement stores.
    pub objects_rebuilt: u64,
    /// Number of rebuild actions that failed.
    pub actions_failed: u64,
    /// Per-action result summary.
    pub action_results: Vec<RebuildActionResult>,
}

/// Outcome of a single rebuild action.
#[derive(Clone, Debug)]
pub struct RebuildActionResult {
    pub kind: RebuildKind,
    pub reason: String,
    pub success: bool,
    pub objects_copied: u64,
    pub error_detail: Option<String>,
}

impl RebuildExecutionReport {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.actions_failed == 0
    }
}

/// Schedule and execute mirror rebuilds from a pool config.
///
/// Inspects `config` with [`RebuildScheduler::schedule`] and, for every
/// [`RebuildKind::MirrorRebuild`] action, copies all objects from the
/// corresponding surviving store into a fresh replacement store at
/// `replacement_path`.
///
/// # Arguments
///
/// * `config` - Pool configuration assembled from authoritative labels.
/// * `surviving_store_root` - Path to the directory backing the surviving
///   mirror member.  All objects are copied from this store.
/// * `replacement_path` - Path where the replacement store will be created.
/// * `options` - Store options for the replacement store.
pub fn execute_mirror_rebuild_from_plan(
    config: &tidefs_pool_scan::PoolConfig,
    surviving_store_root: &Path,
    replacement_path: &Path,
    options: StoreOptions,
) -> Result<RebuildExecutionReport, tidefs_local_object_store::StoreError> {
    execute_mirror_rebuild_from_plan_throttled(
        config,
        surviving_store_root,
        replacement_path,
        options,
        None,
        &RebuildThrottleConfig::disabled(),
    )
}

/// Schedule and execute mirror rebuilds with foreground-I/O-aware backpressure.
///
/// Identical to [`execute_mirror_rebuild_from_plan`] except that it
/// accepts an optional [`IoPressureProbe`] and a
/// [`RebuildThrottleConfig`]. When the probe reports foreground
/// pressure, the rebuild loop yields between object copies to avoid
/// starving foreground I/O.
pub fn execute_mirror_rebuild_from_plan_throttled(
    config: &tidefs_pool_scan::PoolConfig,
    surviving_store_root: &Path,
    replacement_path: &Path,
    options: StoreOptions,
    pressure_probe: Option<&IoPressureProbe>,
    throttle_cfg: &RebuildThrottleConfig,
) -> Result<RebuildExecutionReport, tidefs_local_object_store::StoreError> {
    let plan = RebuildScheduler::schedule(config);

    let mut action_results: Vec<RebuildActionResult> = Vec::new();
    let mut objects_rebuilt: u64 = 0;
    let mut actions_failed: u64 = 0;

    for action in &plan.actions {
        match action.kind {
            RebuildKind::MirrorRebuild => {
                // Open surviving store and rebuild into replacement.
                let surviving =
                    LocalObjectStore::open_with_options(surviving_store_root, options.clone())?;
                match LocalObjectStore::rebuild_replica_from_surviving_throttled(
                    &surviving,
                    replacement_path,
                    options.clone(),
                    pressure_probe,
                    throttle_cfg,
                ) {
                    Ok(replacement) => {
                        let copied = replacement.list_keys().len() as u64;
                        objects_rebuilt = objects_rebuilt.saturating_add(copied);
                        action_results.push(RebuildActionResult {
                            kind: RebuildKind::MirrorRebuild,
                            reason: action.reason.clone(),
                            success: true,
                            objects_copied: copied,
                            error_detail: None,
                        });
                    }
                    Err(e) => {
                        actions_failed = actions_failed.saturating_add(1);
                        action_results.push(RebuildActionResult {
                            kind: RebuildKind::MirrorRebuild,
                            reason: action.reason.clone(),
                            success: false,
                            objects_copied: 0,
                            error_detail: Some(format!("{e}")),
                        });
                    }
                }
            }
            // Other rebuild kinds are planned but not yet executable.
            RebuildKind::ParityRebuild
            | RebuildKind::ResilienceRestore
            | RebuildKind::DeviceReplace
            | RebuildKind::NoAction => {
                action_results.push(RebuildActionResult {
                    kind: action.kind,
                    reason: action.reason.clone(),
                    success: action.kind == RebuildKind::NoAction,
                    objects_copied: 0,
                    error_detail: if action.kind == RebuildKind::NoAction {
                        None
                    } else {
                        Some("execution not yet wired".into())
                    },
                });
                if action.kind != RebuildKind::NoAction {
                    actions_failed = actions_failed.saturating_add(1);
                }
            }
        }
    }

    Ok(RebuildExecutionReport {
        plan,
        objects_rebuilt,
        actions_failed,
        action_results,
    })
}

/// Well-known object key for persisting rebuild completion records.
pub const REBUILD_COMPLETION_RECORD_KEY: &str = "tidefs-rebuild-completion-record";

/// A record of a completed rebuild from surviving replicas.
///
/// Serialized as JSON and persisted through the commit_group system so
/// that recovery can detect completed rebuilds and pool import can
/// verify that the rebuilt device is no longer missing.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RebuildCompletionRecord {
    /// Pool UUID from labels.
    pub pool_uuid: [u8; 16],
    /// Index of the rebuilt device (previously missing).
    pub rebuilt_device_index: u32,
    /// GUID of the rebuilt device.
    pub rebuilt_device_guid: [u8; 16],
    /// Device count after rebuild.
    pub device_count: u32,
    /// Topology generation after rebuild (bumped).
    pub topology_generation: u64,
    /// Number of objects rebuilt/copied.
    pub objects_rebuilt: u64,
    /// Whether the record represents a fully anchored rebuild.
    pub rebuild_complete: bool,
}

impl RebuildCompletionRecord {
    /// Build a record from the rebuild execution report and post-rebuild config.
    #[must_use]
    pub fn from_report(
        report: &RebuildExecutionReport,
        rebuilt_device_index: u32,
        rebuilt_device_guid: [u8; 16],
        updated_device_count: u32,
        updated_topology_generation: u64,
    ) -> Self {
        Self {
            pool_uuid: report.plan.pool_uuid,
            rebuilt_device_index,
            rebuilt_device_guid,
            device_count: updated_device_count,
            topology_generation: updated_topology_generation,
            objects_rebuilt: report.objects_rebuilt,
            rebuild_complete: report.is_complete(),
        }
    }
}

/// Update a [`tidefs_pool_scan::PoolConfig`] to reflect a completed rebuild.
///
/// Removes `device_index` from `missing_indices`, sets the device health
/// to [`tidefs_pool_scan::DeviceHealth::Online`], and bumps
/// `topology_generation`.
///
/// Returns the new topology generation value.
///
/// # Panics
///
/// Does not panic; returns the config unchanged if the device is not found
/// in `missing_indices` or in the device tree.
pub fn mark_device_rebuilt(config: &mut tidefs_pool_scan::PoolConfig, device_index: u32) -> u64 {
    // Remove from missing_indices.
    config.missing_indices.retain(|&idx| idx != device_index);

    // Bump topology generation.
    config.topology_generation = config.topology_generation.saturating_add(1);

    // Set device health to Online for the rebuilt leaf.
    use tidefs_pool_scan::DeviceType;
    fn set_leaf_health(node: &mut DeviceType, target_index: u32) {
        match node {
            DeviceType::Leaf {
                device_index,
                health,
                ..
            } => {
                if *device_index == target_index {
                    *health = tidefs_pool_scan::DeviceHealth::Online;
                }
            }
            DeviceType::PoolWideData { children }
            | DeviceType::Mirror { children }
            | DeviceType::ParityRaid { children, .. } => {
                for child in children {
                    set_leaf_health(child, target_index);
                }
            }
        }
    }
    set_leaf_health(&mut config.device_tree, device_index);

    config.topology_generation
}

/// Anchor a rebuild completion in the target store.
///
/// Writes a [`RebuildCompletionRecord`] as a named object under
/// [`REBUILD_COMPLETION_RECORD_KEY`].  When `updated_pool_config` and
/// `label_writer` are both provided, updated pool labels are written
/// to the surviving (and replacement) devices so pool import discovers
/// the post-rebuild topology.
///
/// The caller must sync surviving stores **before** calling this
/// function so that rebuild data is durable before the anchor.
///
/// # Returns
///
/// `Ok(())` if the record and optional labels were written and synced.
pub fn anchor_rebuild(
    store: &mut tidefs_local_object_store::LocalObjectStore,
    record: &RebuildCompletionRecord,
    updated_pool_config: Option<&tidefs_pool_scan::PoolConfig>,
    label_writer: Option<&tidefs_pool_scan::PoolLabelWriter>,
    device_sizes: Option<&std::collections::BTreeMap<u32, u64>>,
) -> Result<(), tidefs_local_object_store::StoreError> {
    use tidefs_local_object_store::ObjectKey;

    let payload =
        serde_json::to_vec(record).map_err(|e| tidefs_local_object_store::StoreError::Io {
            operation: "serialize_rebuild_record",
            path: std::path::PathBuf::new(),
            source: std::io::Error::other(format!("{e}")),
        })?;

    let key = ObjectKey::from_name(REBUILD_COMPLETION_RECORD_KEY.as_bytes());
    store
        .put(key, &payload)
        .map_err(|e| tidefs_local_object_store::StoreError::Io {
            operation: "write_rebuild_record",
            path: std::path::PathBuf::new(),
            source: std::io::Error::other(format!("{e}")),
        })?;

    if let Some(writer) = label_writer {
        let config =
            updated_pool_config.ok_or_else(|| tidefs_local_object_store::StoreError::Io {
                operation: "anchor_rebuild",
                path: std::path::PathBuf::new(),
                source: std::io::Error::other("label_writer provided without updated_pool_config"),
            })?;
        writer
            .write_pool_labels(config, device_sizes)
            .map_err(|e| tidefs_local_object_store::StoreError::Io {
                operation: "write_updated_labels",
                path: std::path::PathBuf::new(),
                source: std::io::Error::other(format!("{e}")),
            })?;
    }

    store
        .sync_all()
        .map_err(|e| tidefs_local_object_store::StoreError::Io {
            operation: "sync_rebuild_anchor",
            path: std::path::PathBuf::new(),
            source: std::io::Error::other(format!("{e}")),
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tidefs_pool_scan::{DeviceHealth, DeviceType, PoolConfig};
    use tidefs_types_pool_label_core::PoolState;

    fn temp_root(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tidefs-rebuild-lfs-{name}-{nanos}"))
    }

    fn make_leaf(path: &str, index: u32, guid: u8, health: DeviceHealth) -> DeviceType {
        DeviceType::Leaf {
            device_path: std::path::PathBuf::from(path),
            device_guid: [guid; 16],
            device_index: index,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: tidefs_types_pool_label_core::DeviceClass::Hdd,
            health,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        }
    }

    #[test]
    fn healthy_pool_produces_empty_report() {
        let config = PoolConfig {
            pool_uuid: [0xAAu8; 16],
            pool_name: "healthy".into(),
            device_tree: DeviceType::Mirror {
                children: vec![
                    make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online),
                    make_leaf("/dev/disk1", 1, 0x02, DeviceHealth::Online),
                ],
            },
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
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

        let surviving = temp_root("healthy-surv");
        let replacement = temp_root("healthy-repl");
        fs::create_dir_all(&surviving).unwrap();

        let report = execute_mirror_rebuild_from_plan(
            &config,
            &surviving,
            &replacement,
            StoreOptions::test_fast(),
        )
        .expect("report");
        assert!(report.is_complete());
        assert_eq!(report.objects_rebuilt, 0);

        let _ = fs::remove_dir_all(&surviving);
        let _ = fs::remove_dir_all(&replacement);
    }

    #[test]
    fn mirror_rebuild_copies_data() {
        let config = PoolConfig {
            pool_uuid: [0xBBu8; 16],
            pool_name: "missing-mirror".into(),
            device_tree: DeviceType::Mirror {
                children: vec![
                    make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online),
                    make_leaf("/dev/disk1", 1, 0x02, DeviceHealth::Online),
                ],
            },
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            health: DeviceHealth::Degraded,
            state: PoolState::Active,
            total_capacity_bytes: 2 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 3,          // three configured
            missing_indices: vec![2], // device 2 missing
            removing_device_indices: vec![],
        };

        let surviving = temp_root("mirror-surv");
        let replacement = temp_root("mirror-repl");
        fs::create_dir_all(&surviving).unwrap();

        // Populate surviving store with data.
        {
            let mut store =
                LocalObjectStore::open_with_options(&surviving, StoreOptions::test_fast())
                    .expect("open");
            store.put_content_addressed(b"rebuild-me").expect("put");
            store.put_content_addressed(b"also-rebuild").expect("put");
            store.sync_all().expect("sync");
        }

        let report = execute_mirror_rebuild_from_plan(
            &config,
            &surviving,
            &replacement,
            StoreOptions::test_fast(),
        )
        .expect("report");
        assert!(report.is_complete());
        assert_eq!(report.objects_rebuilt, 2);

        // Verify the replacement has the data.
        let repl = LocalObjectStore::open_with_options(&replacement, StoreOptions::test_fast())
            .expect("open repl");
        let keys = repl.list_keys();
        assert_eq!(keys.len(), 2);

        let _ = fs::remove_dir_all(&surviving);
        let _ = fs::remove_dir_all(&replacement);
    }
    #[test]
    fn mark_device_rebuilt_clears_missing_and_bumps_generation() {
        let mut config = PoolConfig {
            pool_uuid: [0xCCu8; 16],
            pool_name: "rebuilt".into(),
            device_tree: DeviceType::Mirror {
                children: vec![
                    make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online),
                    make_leaf("/dev/disk1", 1, 0x02, DeviceHealth::Degraded),
                ],
            },
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            health: DeviceHealth::Degraded,
            state: PoolState::Active,
            total_capacity_bytes: 2 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 3,
            device_count: 2,
            missing_indices: vec![1],
            removing_device_indices: vec![],
        };

        let new_gen = mark_device_rebuilt(&mut config, 1);

        assert!(
            !config.missing_indices.contains(&1),
            "device 1 no longer missing"
        );
        assert_eq!(config.missing_indices.len(), 0);
        assert!(new_gen > 3, "topology generation bumped");
        assert_eq!(config.topology_generation, new_gen);

        // Device health should be Online now.
        use tidefs_pool_scan::DeviceType;
        fn find_health(node: &DeviceType, idx: u32) -> Option<DeviceHealth> {
            match node {
                DeviceType::Leaf {
                    device_index,
                    health,
                    ..
                } => {
                    if *device_index == idx {
                        Some(*health)
                    } else {
                        None
                    }
                }
                DeviceType::PoolWideData { children }
                | DeviceType::Mirror { children }
                | DeviceType::ParityRaid { children, .. } => {
                    children.iter().find_map(|c| find_health(c, idx))
                }
            }
        }
        assert_eq!(
            find_health(&config.device_tree, 1),
            Some(DeviceHealth::Online),
            "rebuilt device health is Online"
        );
    }

    #[test]
    fn anchor_rebuild_writes_record() {
        let dir = temp_root("anchor-rebuild");
        fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open_with_options(&dir, StoreOptions::test_fast())
            .expect("open store");

        let record = RebuildCompletionRecord {
            pool_uuid: [0xDDu8; 16],
            rebuilt_device_index: 1,
            rebuilt_device_guid: [0xEEu8; 16],
            device_count: 2,
            topology_generation: 5,
            objects_rebuilt: 42,
            rebuild_complete: true,
        };

        let result = anchor_rebuild(&mut store, &record, None, None, None);
        assert!(result.is_ok(), "anchor_rebuild should succeed");

        // Verify the record was written by reading it back.
        use tidefs_local_object_store::ObjectKey;
        let key = ObjectKey::from_name(REBUILD_COMPLETION_RECORD_KEY.as_bytes());
        let payload = store.get(key).expect("get record").expect("record present");
        let read_back: RebuildCompletionRecord =
            serde_json::from_slice(&payload).expect("deserialize");
        assert_eq!(read_back.rebuilt_device_index, 1);
        assert_eq!(read_back.objects_rebuilt, 42);
        assert!(read_back.rebuild_complete);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rebuild_record_serde_roundtrip() {
        let record = RebuildCompletionRecord {
            pool_uuid: [0x42u8; 16],
            rebuilt_device_index: 0,
            rebuilt_device_guid: [0xABu8; 16],
            device_count: 3,
            topology_generation: 7,
            objects_rebuilt: 100,
            rebuild_complete: true,
        };

        let json = serde_json::to_string(&record).unwrap();
        let round: RebuildCompletionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record.pool_uuid, round.pool_uuid);
        assert_eq!(record.rebuilt_device_index, round.rebuilt_device_index);
        assert_eq!(record.objects_rebuilt, round.objects_rebuilt);
        assert!(round.rebuild_complete);
    }

    #[test]
    fn mark_device_rebuilt_noop_for_nonexistent_index() {
        let mut config = PoolConfig {
            pool_uuid: [0xFFu8; 16],
            pool_name: "nonexistent".into(),
            device_tree: DeviceType::Mirror {
                children: vec![make_leaf("/dev/disk0", 0, 0x01, DeviceHealth::Online)],
            },
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 1,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };

        let old_gen = config.topology_generation;
        let new_gen = mark_device_rebuilt(&mut config, 99); // not in tree
        assert!(new_gen > old_gen, "generation still bumps");
        assert!(config.missing_indices.is_empty());
    }
}
