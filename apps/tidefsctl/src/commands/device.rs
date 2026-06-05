//! `tidefsctl device` subcommands: operator-triggered device removal from a
//! TideFS pool with data evacuation and committed-root anchoring.
//!
//! ## Offline evacuation contract
//!
//! For imported pools, the pool name is routed to the live owner before this
//! module opens any store. The target-device backing directory and surviving
//! directories are only for exported/offline device removal when no live owner
//! interface exists for the pool.
//!
//! Offline device removal requires at least one surviving device backing
//! directory (--surviving-dirs). Evacuated objects are read from the target
//! device's store and persisted to the surviving device stores via round-robin
//! assignment consistent with the evacuation plan. The committed removal
//! record is only marked complete when all objects have been durably relocated,
//! pool labels have been updated, and the commit-group sync has succeeded.
//!
//! If no surviving directories are provided, the command refuses evacuation
//! and reports the planning failure (NoObjectsOnDevice when empty, or
//! WouldEmptyPool when objects exist but no survivors are available).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::Subcommand;

use tidefs_local_filesystem::device_removal::anchor_device_removal;
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};
use tidefs_pool_scan::device_removal::DeviceRemovalRun;
use tidefs_pool_scan::{
    run_device_removal, DeviceRemovalError, DeviceRemovalHooks, DeviceRemovalPlan,
    DeviceRemovalPlanner, DeviceRemovalResult, DeviceRemovalState, ObjectPlacement, PoolConfig,
};
use tidefs_replication_model::{FailureDomain, ReplicationIntent};

/// Device management subcommands.
#[derive(Subcommand, Debug)]
pub enum DeviceCommand {
    /// Remove a device from a pool.
    ///
    /// Imported pools route to the live owner. Exported/offline pools use
    /// --backing-dir and --surviving-dirs to run the local evacuation path.
    Remove {
        /// Pool name. If the pool is imported, the request is routed to its live owner.
        pool_name: String,

        /// Path to the block device to remove.
        device_path: PathBuf,

        /// Backing directory for exported/offline removal of the target device's store.
        #[arg(short = 'b', long = "backing-dir")]
        backing_dir: Option<PathBuf>,

        /// Comma-separated paths to surviving exported/offline backing directories.
        /// Each path must point to a distinct LocalObjectStore directory.
        /// At least one surviving dir is required for evacuation of
        /// populated target devices.
        #[arg(short = 'S', long = "surviving-dirs", value_delimiter = ',')]
        surviving_dirs: Vec<PathBuf>,

        /// Replication factor for failure-domain separation (default: 2).
        #[arg(long, default_value = "2")]
        replication_factor: u8,

        /// Failure domain level: device, node, rack, or datacenter.
        #[arg(long, default_value = "device")]
        failure_domain: String,

        /// Force removal even if evacuation partially fails.
        #[arg(long)]
        force: bool,
    },

    /// Rebuild a lost device from a surviving replica.
    ///
    /// Copies all objects from the surviving store into a fresh
    /// replacement store, restoring pool redundancy after device loss.
    Rebuild {
        /// Backing directory for the surviving mirror/replica store.
        #[arg(short = 'S', long = "surviving-dir")]
        surviving_dir: std::path::PathBuf,

        /// Path where the replacement store will be created.
        #[arg(short = 'r', long = "replacement-dir")]
        replacement_dir: std::path::PathBuf,
    },
}

/// Handle the `tidefsctl device` subcommand.
pub fn handle_device(cmd: DeviceCommand) {
    match cmd {
        DeviceCommand::Remove {
            pool_name,
            device_path,
            backing_dir,
            surviving_dirs,
            replication_factor,
            failure_domain,
            force,
        } => {
            if let Err(e) = handle_remove(
                &pool_name,
                &device_path,
                backing_dir.as_ref(),
                &surviving_dirs,
                replication_factor,
                &failure_domain,
                force,
            ) {
                eprintln!("tidefsctl device remove: {e}");
                std::process::exit(1);
            }
        }

        DeviceCommand::Rebuild {
            surviving_dir,
            replacement_dir,
        } => {
            if let Err(e) = handle_rebuild(&surviving_dir, &replacement_dir) {
                eprintln!("tidefsctl device rebuild: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// CLI-specific hooks for the device removal state machine.
struct CliRemovalHooks {
    target_device_path: PathBuf,
    _plan: Option<DeviceRemovalPlan>,
    force: bool,
    post_config: Option<PoolConfig>,
}

impl DeviceRemovalHooks for CliRemovalHooks {
    fn verify_empty(&mut self, state: &mut DeviceRemovalState) -> Result<(), DeviceRemovalError> {
        if state.objects_failed > 0 {
            return Err(DeviceRemovalError::DomainConstraintViolation {
                details: format!(
                    "{} objects failed evacuation from {}",
                    state.objects_failed,
                    self.target_device_path.display(),
                ),
            });
        }
        Ok(())
    }

    fn quiesce_device(
        &mut self,
        _state: &mut DeviceRemovalState,
    ) -> Result<(), DeviceRemovalError> {
        Ok(())
    }

    fn commit_removal(
        &mut self,
        _state: &mut DeviceRemovalState,
        result: &DeviceRemovalResult,
    ) -> Result<(), DeviceRemovalError> {
        if result.objects_failed > 0 && !self.force {
            return Err(DeviceRemovalError::DomainConstraintViolation {
                details: format!(
                    "{} objects failed evacuation; refusing to mark removal complete. \
                     Use --force to override.",
                    result.objects_failed,
                ),
            });
        }

        // The caller (handle_remove) handles anchoring, label persistence,
        // and sync of surviving stores. The hooks only validate readiness.
        let _ = self.post_config.as_ref().ok_or_else(|| {
            DeviceRemovalError::DomainConstraintViolation {
                details: "commit called without post_config".into(),
            }
        })?;

        Ok(())
    }
}

/// Build a post-removal PoolConfig by calling PoolConfig::remove_device on the
/// label-derived pre-removal config. This preserves pool UUID, name, feature
/// flags, device GUIDs, and topology generation from the authoritative pool
/// labels.
///
/// Returns an error if the target device is not found in the label-derived config.
fn build_post_removal_pool_config(
    pre_config: &PoolConfig,
    target_device_path: &std::path::Path,
) -> Result<PoolConfig, String> {
    let mut post_config = pre_config.clone();
    post_config
        .remove_device(target_device_path)
        .map_err(|e| format!("remove_device failed: {e}"))?;
    Ok(post_config)
}

/// Rebuild a lost device from a surviving replica store.
///
/// Copies all objects from `surviving_dir` to a fresh store at
/// `replacement_dir`.  Reports the number of objects copied.
fn handle_rebuild(
    surviving_dir: &std::path::PathBuf,
    replacement_dir: &std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    let surviving = LocalObjectStore::open_with_options(surviving_dir, StoreOptions::test_fast())
        .map_err(|e| {
        format!(
            "failed to open surviving store at {}: {e}",
            surviving_dir.display()
        )
    })?;

    let key_count = surviving.list_keys().len();
    eprintln!(
        "Opened surviving store at {} ({} live objects)",
        surviving_dir.display(),
        key_count,
    );

    if key_count == 0 {
        eprintln!("Surviving store is empty; nothing to rebuild.");
        let _replacement =
            LocalObjectStore::open_with_options(replacement_dir, StoreOptions::test_fast())
                .map_err(|e| {
                    format!(
                        "failed to create empty replacement at {}: {e}",
                        replacement_dir.display()
                    )
                })?;
        eprintln!(
            "Created empty replacement store at {}",
            replacement_dir.display()
        );
        return Ok(());
    }

    let replacement = LocalObjectStore::rebuild_replica_from_surviving(
        &surviving,
        replacement_dir,
        StoreOptions::test_fast(),
    )
    .map_err(|e| format!("rebuild failed: {e}"))?;

    let rebuilt_count = replacement.list_keys().len();
    eprintln!(
        "Rebuild complete: {} objects copied to {}",
        rebuilt_count,
        replacement_dir.display(),
    );

    Ok(())
}

fn handle_remove(
    pool_name: &str,
    device_path: &PathBuf,
    backing_dir: Option<&PathBuf>,
    surviving_dirs: &[PathBuf],
    replication_factor: u8,
    failure_domain: &str,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let live_args = serde_json::json!({
        "device_path": device_path.to_string_lossy(),
        "replication_factor": replication_factor,
        "failure_domain": failure_domain,
        "force": force,
    });

    let backing_dir = match backing_dir {
        Some(backing_dir) => backing_dir,
        None => {
            super::live_owner::route_if_owner_exists_with_args(
                "device", "remove", pool_name, live_args,
            );
            return Err(format!(
                "pool-name device removal for '{pool_name}' requires a reachable live owner; route through the kernel UAPI or userspace daemon owner. Use --backing-dir only for exported/offline device removal."
            )
            .into());
        }
    };

    // Read labels without creating or mutating the store. Cached labels are
    // recovery input; only a matching live owner manifest redirects this
    // offline evacuation request to live state.
    let pre_config = import_offline_pool_config(pool_name, backing_dir)?;

    super::live_owner::route_if_owner_exists_for_uuid_with_args(
        "device",
        "remove",
        pool_name,
        pre_config.pool_uuid,
        live_args,
    );

    let domain = match failure_domain {
        "device" => FailureDomain::Device,
        "node" => FailureDomain::Node,
        "rack" => FailureDomain::Rack,
        "datacenter" => FailureDomain::Datacenter,
        other => {
            eprintln!("tidefsctl: unknown failure domain '{other}', using 'device'");
            FailureDomain::Device
        }
    };

    let intent = ReplicationIntent::new_mirror(replication_factor, domain)
        .map_err(|e| format!("invalid replication intent: {e}"))?;

    let mut target_store = LocalObjectStore::open(backing_dir).map_err(|e| {
        format!(
            "failed to open target store at {}: {e}",
            backing_dir.display()
        )
    })?;

    eprintln!("Opened target store at {}", backing_dir.display());
    eprintln!("Replication intent: {intent}");
    eprintln!("Target device for removal: {}", device_path.display());

    // Derive target and surviving devices from the label-derived pool
    // membership. The target device path must match a leaf in that config.
    let target_in_config = pre_config
        .device_tree
        .find_leaf(device_path)
        .ok_or_else(|| {
            format!(
                "target device {} not found in label-derived pool config; pool has {} devices",
                device_path.display(),
                pre_config.device_count,
            )
        })?;

    let surviving_from_config: Vec<PathBuf> = pre_config
        .device_tree
        .all_leaf_paths()
        .into_iter()
        .filter(|p| p != device_path)
        .collect();

    // Require --surviving-dirs for multi-device pools. The pool config
    // provides device topology authority but not filesystem store paths;
    // the operator must provide actual LocalObjectStore directories.
    if surviving_dirs.is_empty() {
        if surviving_from_config.is_empty() {
            return Err("refusing to remove the only device in the pool;                         device removal requires at least one surviving device"
                .into());
        }
        return Err(
            "device removal requires --surviving-dirs for pools with              more than one device; provide paths to surviving device              backing directories"
                .into(),
        );
    }
    let effective_dirs: Vec<PathBuf> = surviving_dirs.to_vec();

    let all_keys = target_store.list_keys();
    // Compute known label keys and removal-record key so we can filter them
    // from the evacuation set without needing a reverse name lookup.
    let known_label_keys: Vec<ObjectKey> = (0u32..64u32)
        .map(|idx| {
            ObjectKey::from_name(
                format!(
                    "{}{idx}",
                    tidefs_local_filesystem::device_removal::POOL_LABEL_KEY_PREFIX
                )
                .as_bytes(),
            )
        })
        .collect();
    let removal_record_key = ObjectKey::from_name(
        tidefs_local_filesystem::device_removal::DEVICE_REMOVAL_RECORD_KEY.as_bytes(),
    );
    let data_keys: Vec<ObjectKey> = all_keys
        .iter()
        .filter(|k| {
            let kb = k.as_bytes();
            !known_label_keys.iter().any(|lk| lk.as_bytes() == kb)
                && kb != removal_record_key.as_bytes()
        })
        .cloned()
        .collect();
    let excluded = all_keys.len() - data_keys.len();
    eprintln!(
        "Target store contains {} objects ({} data, {} labels/records skipped)",
        all_keys.len(),
        data_keys.len(),
        excluded
    );

    // Pre-load all object data and preserve original ObjectKeys.
    let mut id_to_key: BTreeMap<u64, ObjectKey> = BTreeMap::new();
    let mut object_data: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    for (i, key) in data_keys.iter().enumerate() {
        let id = i as u64;
        if let Ok(Some(data)) = target_store.get(*key) {
            id_to_key.insert(id, *key);
            object_data.insert(id, data);
        }
    }

    let target_leaf_guid = target_in_config.device_guid;
    let device_tree = pre_config.device_tree.clone();

    // Object placements: everything is on the target device.
    let object_placements: Vec<ObjectPlacement> = object_data
        .keys()
        .map(|id| {
            let size = object_data.get(id).map_or(0, |d| d.len() as u64);
            ObjectPlacement::new(*id, device_path.clone(), size)
        })
        .collect();

    // Open surviving device stores (wrapped in RefCell to share with closure).
    let surviving_stores_raw: Vec<LocalObjectStore> = effective_dirs
        .iter()
        .map(|d| {
            LocalObjectStore::open(d)
                .map_err(|e| format!("failed to open surviving store at {}: {e}", d.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    eprintln!("Opened {} surviving stores", surviving_stores_raw.len());

    let surviving_stores = RefCell::new(surviving_stores_raw);

    // Build path -> store-index lookup for the write_object closure.
    let mut surviving_path_to_idx: BTreeMap<PathBuf, usize> = effective_dirs
        .iter()
        .enumerate()
        .map(|(i, p)| (p.clone(), i))
        .collect();

    // Compute the plan using the label-derived topology generation.
    let plan = DeviceRemovalPlanner::plan_removal(
        &device_tree,
        device_path,
        &object_placements,
        intent,
        pre_config.topology_generation,
    )
    .map_err(|e| format!("planning failed: {e}"))?;

    eprintln!(
        "Plan: {} objects to evacuate, {} bytes total",
        plan.object_count(),
        plan.total_evacuation_bytes,
    );
    eprintln!(
        "Surviving devices: {}",
        plan.surviving_devices
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!("Plan validated: {}", plan.plan_validated);

    let mut state = DeviceRemovalState::new(device_path.clone(), target_leaf_guid);

    // Build the post-removal config by calling remove_device on the label-derived config.
    let post_config = build_post_removal_pool_config(&pre_config, device_path)?;

    let mut hooks = CliRemovalHooks {
        target_device_path: device_path.clone(),
        _plan: Some(plan.clone()),
        force,
        post_config: Some(post_config.clone()),
    };

    // Map the plan's synthetic surviving device paths to store indices.
    // The plan derives surviving paths from the label-derived config (e.g. /dev/disk1),
    // but we need them to point to the actual store directories.
    {
        let surv_indices: Vec<u32> = pre_config
            .device_tree
            .all_leaf_paths()
            .iter()
            .filter_map(|p| pre_config.device_tree.find_leaf(p))
            .map(|r| r.device_index)
            .filter(|&idx| idx != target_in_config.device_index)
            .collect();
        for (i, idx) in surv_indices.iter().enumerate() {
            if i < effective_dirs.len() {
                let syn_path = PathBuf::from(format!("/dev/disk{idx}"));
                surviving_path_to_idx.entry(syn_path).or_insert(i);
            }
        }
    }

    // Clone maps for capture in closures.
    let id_to_key_for_write = id_to_key.clone();
    let surviving_path_to_idx_for_write = surviving_path_to_idx.clone();

    let result = match run_device_removal(
        &mut state,
        &mut hooks,
        DeviceRemovalRun {
            device_tree: &device_tree,
            object_placements: &object_placements,
            intent,
            topology_generation: pre_config.topology_generation,
        },
        // read_object: fetch from the pre-loaded in-memory map.
        |object_id| {
            object_data.get(&object_id).cloned().ok_or_else(|| {
                DeviceRemovalError::DomainConstraintViolation {
                    details: format!("object {object_id} not found in pre-loaded data"),
                }
            })
        },
        // write_object: persist to the correct surviving device store.
        |object_id, data, target_device| {
            let idx = surviving_path_to_idx_for_write
                .get(target_device)
                .ok_or_else(|| DeviceRemovalError::DomainConstraintViolation {
                    details: format!("no surviving store for path {}", target_device.display()),
                })?;
            let original_key = id_to_key_for_write.get(&object_id).ok_or_else(|| {
                DeviceRemovalError::DomainConstraintViolation {
                    details: format!("no original key for object {object_id}"),
                }
            })?;
            let mut stores = surviving_stores.borrow_mut();
            let store = &mut stores[*idx];
            store.put(*original_key, data).map_err(|e| {
                DeviceRemovalError::DomainConstraintViolation {
                    details: format!("write to {} failed: {e}", target_device.display()),
                }
            })?;
            Ok(())
        },
        // anchor_removal: only mark anchored when all objects succeeded.
        |result| result.objects_failed == 0,
    ) {
        Ok(r) => {
            eprintln!();
            eprintln!("=== Device Removal Result ===");
            eprintln!("Objects evacuated: {}", r.objects_evacuated);
            eprintln!("Bytes evacuated:   {}", r.bytes_evacuated);
            eprintln!("Objects failed:    {}", r.objects_failed);
            eprintln!("Phase:             {}", state.phase);
            eprintln!(
                "Committed root:    {}",
                if r.committed_root_anchored {
                    "anchored"
                } else {
                    "not anchored"
                }
            );

            if r.objects_failed > 0 && !force {
                eprintln!("Evacuation had failures; use --force to proceed anyway.");
                std::process::exit(1);
            }

            // Sync surviving stores BEFORE anchoring removal.
            // This ensures evacuation data is durable before the removal record
            // is written, so sync failure cannot leave a completed removal behind.
            let mut surv_stores = surviving_stores.borrow_mut();
            for (i, store) in surv_stores.iter_mut().enumerate() {
                store
                    .sync()
                    .map_err(|e| format!("surviving store {i} sync failed: {e}"))?;
            }
            drop(surv_stores);
            eprintln!("Surviving stores synced.");

            // Persist updated labels to surviving stores.
            // Each surviving store gets the post-removal labels so that pool
            // import from survivors-only discovers the updated topology.
            {
                let mut surv_stores = surviving_stores.borrow_mut();
                for (i, store) in surv_stores.iter_mut().enumerate() {
                    tidefs_local_filesystem::device_removal::persist_updated_labels(
                        store,
                        &post_config,
                    )?;
                    store
                        .sync()
                        .map_err(|e| format!("surviving store {i} post-label sync failed: {e}"))?;
                }
                eprintln!(
                    "Updated labels written to {} surviving stores.",
                    surv_stores.len()
                );
            }

            // Now anchor the removal on the target store.
            // The target store sync is the final commitment.
            anchor_device_removal(&mut target_store, &plan, &r, Some(&post_config), None, None)
                .map_err(|e| format!("anchor failed: {e}"))?;
            eprintln!("Removal anchored on target store.");
            r
        }
        Err(e) => {
            eprintln!("Device removal failed at phase {}: {e}", state.phase);
            if !force {
                return Err(Box::new(e));
            }
            DeviceRemovalResult {
                objects_evacuated: 0,
                bytes_evacuated: 0,
                objects_failed: 0,
                removed_device: device_path.clone(),
                surviving_devices: effective_dirs.clone(),
                topology_generation: pre_config.topology_generation + 1,
                committed_root_anchored: false,
            }
        }
    };

    eprintln!("Device removal complete (phase: {}).", state.phase);
    let _ = result;
    Ok(())
}

fn import_offline_pool_config(
    pool_name: &str,
    backing_dir: &std::path::Path,
) -> Result<PoolConfig, Box<dyn std::error::Error>> {
    let target_store =
        match LocalObjectStore::open_read_only_with_options(backing_dir, StoreOptions::default()) {
            Ok(Some(store)) => store,
            Ok(None) => {
                return Err(format!(
                    "no existing target store at {}; offline device removal requires authoritative pool labels",
                    backing_dir.display(),
                )
                .into())
            }
            Err(err) => {
                return Err(format!(
                    "failed to open target store at {} read-only for label discovery: {err}",
                    backing_dir.display(),
                )
                .into())
            }
        };

    let pre_config = match tidefs_local_filesystem::device_removal::import_pool_config_from_store(
        &target_store,
    )? {
        Some(cfg) => cfg,
        None => {
            return Err(format!(
                "no pool labels found in target store at {}; offline device removal requires authoritative pool labels. Create the pool with 'tidefsctl pool create' before removing devices.",
                backing_dir.display(),
            )
            .into());
        }
    };
    if pre_config.pool_name != pool_name {
        return Err(format!(
            "target device belongs to pool '{}', not '{pool_name}'",
            pre_config.pool_name
        )
        .into());
    }

    eprintln!(
        "Imported pool config from labels: pool={} uuid={:02x?} gen={} devices={}",
        pre_config.pool_name,
        &pre_config.pool_uuid[..4],
        pre_config.topology_generation,
        pre_config.device_count,
    );

    Ok(pre_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_pool_scan::DeviceRemovalPhase;

    // Helper: create a 3-device exported pool config with labels in the target store.
    fn setup_labeled_pool(
        target_dir: &std::path::Path,
        surv0_dir: &std::path::Path,
        surv1_dir: &std::path::Path,
    ) {
        use tidefs_local_filesystem::device_removal::persist_updated_labels;
        use tidefs_pool_scan::{DeviceHealth, DeviceType, PoolConfig};
        use tidefs_types_pool_label_core::{DeviceClass, PoolState};

        let leaf0 = DeviceType::Leaf {
            device_path: std::path::PathBuf::from("/dev/disk0"),
            device_guid: [0x01u8; 16],
            device_index: 0,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let leaf1 = DeviceType::Leaf {
            device_path: surv0_dir.to_path_buf(),
            device_guid: [0x02u8; 16],
            device_index: 1,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let leaf2 = DeviceType::Leaf {
            device_path: surv1_dir.to_path_buf(),
            device_guid: [0x03u8; 16],
            device_index: 2,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };

        let config = PoolConfig {
            pool_uuid: [0xAAu8; 16],
            pool_name: "testpool".to_string(),
            device_tree: DeviceType::Mirror {
                children: vec![leaf0, leaf1, leaf2],
            },
            health: DeviceHealth::Online,
            state: PoolState::Exported,
            total_capacity_bytes: 3 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 3,
            missing_indices: vec![],
            removing_device_indices: vec![],
        };

        let mut target = LocalObjectStore::open(target_dir).unwrap();
        persist_updated_labels(&mut target, &config).unwrap();
        target.sync().unwrap();
    }

    #[test]
    fn phase_progression_covers_all_four() {
        let mut state = DeviceRemovalState::new(PathBuf::from("/dev/test"), [0xAAu8; 16]);
        assert_eq!(state.phase, DeviceRemovalPhase::Quiesce);
        state.advance().unwrap();
        assert_eq!(state.phase, DeviceRemovalPhase::Evacuate);
        state.advance().unwrap();
        assert_eq!(state.phase, DeviceRemovalPhase::Verify);
        state.advance().unwrap();
        assert_eq!(state.phase, DeviceRemovalPhase::Commit);
        state.advance().unwrap();
        assert_eq!(state.phase, DeviceRemovalPhase::Complete);
    }

    #[test]
    fn removal_imports_labels_and_evacuates_to_survivors() {
        let dir = tempfile::tempdir().unwrap();
        let target_dir = dir.path().join("target");
        let surv0_dir = dir.path().join("surv0");
        let surv1_dir = dir.path().join("surv1");
        std::fs::create_dir_all(&target_dir).unwrap();
        std::fs::create_dir_all(&surv0_dir).unwrap();
        std::fs::create_dir_all(&surv1_dir).unwrap();

        // Create pool labels in the target store (authoritative config).
        setup_labeled_pool(&target_dir, &surv0_dir, &surv1_dir);

        // Write data objects into the target store.
        let keys: Vec<ObjectKey> = {
            let mut target = LocalObjectStore::open(&target_dir).unwrap();
            let mut keys = Vec::new();
            for i in 0u64..3u64 {
                let data = vec![i as u8; 512];
                let key = ObjectKey::from_name(format!("obj-{i}"));
                target.put(key, &data).unwrap();
                keys.push(key);
            }
            target.sync().unwrap();
            keys
        };

        let device_path = PathBuf::from("/dev/disk0");
        let result = handle_remove(
            "testpool",
            &device_path,
            Some(&target_dir),
            &[surv0_dir.clone(), surv1_dir.clone()],
            2,
            "device",
            false,
        );
        assert!(result.is_ok(), "handle_remove failed: {:?}", result.err());

        // Verify evacuated objects exist in surviving stores.
        let mut found_count = 0usize;
        {
            let s0 = LocalObjectStore::open(&surv0_dir).unwrap();
            let s1 = LocalObjectStore::open(&surv1_dir).unwrap();
            for key in &keys {
                if s0.get(*key).is_ok_and(|v| v.is_some()) {
                    found_count += 1;
                    continue;
                }
                if s1.get(*key).is_ok_and(|v| v.is_some()) {
                    found_count += 1;
                }
            }
        }
        assert_eq!(
            found_count, 3,
            "expected 3 data objects in surviving stores, found {found_count}",
        );

        // Verify updated labels exist in surviving stores.
        {
            let surv0 = LocalObjectStore::open(&surv0_dir).unwrap();
            let label_key = ObjectKey::from_name("tidefs-pool-label-1");
            let label_bytes = surv0.get(label_key).unwrap();
            assert!(
                label_bytes.is_some(),
                "updated labels not found in surviving store 0"
            );
            let decoded =
                tidefs_types_pool_label_core::decode_label(&label_bytes.unwrap()).unwrap();
            assert!(tidefs_types_pool_label_core::verify_label_checksum(
                &decoded
            ));
            assert_eq!(decoded.device_count, 2);
            assert_eq!(decoded.topology_generation, 2);
        }

        // Verify the removal record in target store is marked complete.
        {
            let target = LocalObjectStore::open(&target_dir).unwrap();
            let record_key = ObjectKey::from_name(
                tidefs_local_filesystem::device_removal::DEVICE_REMOVAL_RECORD_KEY,
            );
            let record_bytes = target.get(record_key).unwrap();
            assert!(
                record_bytes.is_some(),
                "device removal record not found in target store"
            );
            let record: tidefs_local_filesystem::device_removal::DeviceRemovalRecord =
                serde_json::from_slice(&record_bytes.unwrap()).unwrap();
            assert!(
                record.removal_complete,
                "removal record not marked complete"
            );
            assert!(
                record.objects_evacuated >= 3,
                "expected at least 3 objects evacuated, got {}",
                record.objects_evacuated
            );
            assert_eq!(record.objects_failed, 0);
            assert_eq!(record.device_count_before, 3);
            assert_eq!(record.device_count_after, 2);
        }

        // Verify import from survivors-only re-discovers the pool without
        // the removed device.
        {
            let imported = tidefs_local_filesystem::device_removal::import_pool_config_from_store(
                &LocalObjectStore::open(&surv0_dir).unwrap(),
            )
            .unwrap()
            .expect("import from survivor should find config");

            assert_eq!(imported.device_count, 2);
            assert_eq!(imported.topology_generation, 2);
            // The removed device /dev/target should not be in the imported tree.
            let all_paths = imported.device_tree.all_leaf_paths();
            assert!(
                !all_paths.contains(&PathBuf::from("/dev/disk0")),
                "removed device should not be in imported survivor config"
            );
        }
    }

    #[test]
    fn removal_refuses_when_no_labels_present() {
        let dir = tempfile::tempdir().unwrap();
        let target_dir = dir.path().join("target");
        std::fs::create_dir_all(&target_dir).unwrap();

        // Write objects but NO labels.
        {
            let mut target = LocalObjectStore::open(&target_dir).unwrap();
            let key = ObjectKey::from_name("test-obj");
            target.put(key, &vec![0u8; 256]).unwrap();
            target.sync().unwrap();
        }

        let device_path = PathBuf::from("/dev/disk0");
        let surv_dir = dir.path().join("surv");
        std::fs::create_dir_all(&surv_dir).unwrap();

        let result = handle_remove(
            "testpool",
            &device_path,
            Some(&target_dir),
            &[surv_dir],
            2,
            "device",
            false,
        );
        assert!(
            result.is_err(),
            "expected error when no pool labels present"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("no pool labels"), "unexpected error: {msg}",);
    }

    #[test]
    fn removal_refuses_when_target_not_in_config() {
        let dir = tempfile::tempdir().unwrap();
        let target_dir = dir.path().join("target");
        let surv_dir = dir.path().join("surv");
        std::fs::create_dir_all(&target_dir).unwrap();
        std::fs::create_dir_all(&surv_dir).unwrap();

        // Create labels that DON'T include /dev/nonexistent.
        setup_labeled_pool(&target_dir, &surv_dir, &dir.path().join("extra"));

        let result = handle_remove(
            "testpool",
            &PathBuf::from("/dev/nonexistent"),
            Some(&target_dir),
            &[surv_dir],
            2,
            "device",
            false,
        );
        assert!(
            result.is_err(),
            "expected error when target not in label-derived config"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not found in label-derived pool config"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn survivor_labels_updated_with_remove_device_call() {
        let dir = tempfile::tempdir().unwrap();
        let target_dir = dir.path().join("target");
        let surv0_dir = dir.path().join("surv0");
        let surv1_dir = dir.path().join("surv1");
        std::fs::create_dir_all(&target_dir).unwrap();
        std::fs::create_dir_all(&surv0_dir).unwrap();
        std::fs::create_dir_all(&surv1_dir).unwrap();

        setup_labeled_pool(&target_dir, &surv0_dir, &surv1_dir);

        // Write some data.
        {
            let mut target = LocalObjectStore::open(&target_dir).unwrap();
            target
                .put(ObjectKey::from_name("obj-0"), &vec![42u8; 256])
                .unwrap();
            target.sync().unwrap();
        }

        let device_path = PathBuf::from("/dev/disk0");
        let result = handle_remove(
            "testpool",
            &device_path,
            Some(&target_dir),
            &[surv0_dir.clone(), surv1_dir.clone()],
            2,
            "device",
            false,
        );
        assert!(result.is_ok(), "handle_remove failed: {:?}", result.err());

        // Verify surviving stores have labels with topology_generation bumped,
        // and device_count reduced by exactly remove_device() semantics.
        for surv_dir in &[&surv0_dir, &surv1_dir] {
            let store = LocalObjectStore::open(surv_dir).unwrap();
            // Try to read labels for device indices 0 and 2 (not 1, which was the target)
            for idx in [1u32, 2u32] {
                let key = ObjectKey::from_name(format!("tidefs-pool-label-{idx}"));
                let bytes = store.get(key).unwrap();
                assert!(
                    bytes.is_some(),
                    "label {idx} missing in {}",
                    surv_dir.display()
                );
                let decoded = tidefs_types_pool_label_core::decode_label(&bytes.unwrap()).unwrap();
                assert!(tidefs_types_pool_label_core::verify_label_checksum(
                    &decoded
                ));
                assert_eq!(decoded.device_count, 2);
                assert_eq!(decoded.topology_generation, 2);
            }
        }
    }

    #[test]
    fn write_to_nonexistent_surviving_dir_fails() {
        let dir = tempfile::tempdir().unwrap();
        let target_dir = dir.path().join("target");
        std::fs::create_dir_all(&target_dir).unwrap();

        // Create labels with a surviving dir that works for label creation.
        let ok_dir = dir.path().join("ok_surv");
        std::fs::create_dir_all(&ok_dir).unwrap();
        setup_labeled_pool(&target_dir, &ok_dir, &dir.path().join("extra"));

        // Write objects into the target store.
        {
            let mut target = LocalObjectStore::open(&target_dir).unwrap();
            for i in 0u64..3u64 {
                let key = ObjectKey::from_name(format!("obj-{i}"));
                target.put(key, &vec![0u8; 256]).unwrap();
            }
            target.sync().unwrap();
        }

        let device_path = PathBuf::from("/dev/disk0");

        // Pass a surviving dir that is a regular file -- open will fail.
        let bad_dir = dir.path().join("not-a-dir");
        std::fs::write(&bad_dir, b"not a directory").unwrap();

        let result = handle_remove(
            "testpool",
            &device_path,
            Some(&target_dir),
            &[bad_dir],
            2,
            "device",
            false,
        );
        assert!(
            result.is_err(),
            "expected error opening non-directory as store"
        );
    }

    #[test]
    fn removal_without_offline_backing_dir_requires_live_owner() {
        let result = handle_remove(
            "testpool",
            &PathBuf::from("/dev/disk0"),
            None,
            &[],
            2,
            "device",
            false,
        );

        assert!(
            result.is_err(),
            "pool-name-only removal should require a live owner"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("requires a reachable live owner"),
            "expected live-owner refusal, got {msg}"
        );
    }

    #[test]
    fn removal_label_probe_does_not_create_missing_target_store() {
        let dir = tempfile::tempdir().unwrap();
        let target_dir = dir.path().join("missing-target");

        let result = handle_remove(
            "testpool",
            &PathBuf::from("/dev/disk0"),
            Some(&target_dir),
            &[],
            2,
            "device",
            false,
        );

        assert!(result.is_err(), "missing target store should fail");
        assert!(
            !target_dir.exists(),
            "offline label probe must not create a missing target store"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no existing target store"),
            "unexpected error: {msg}"
        );
    }
}

#[test]
fn rebuild_command_copies_objects() {
    let dir = tempfile::tempdir().unwrap();
    let surviving_dir = dir.path().join("surviving");
    let replacement_dir = dir.path().join("replacement");
    std::fs::create_dir_all(&surviving_dir).unwrap();

    // Populate surviving store.
    {
        let mut store = tidefs_local_object_store::LocalObjectStore::open(&surviving_dir).unwrap();
        store.put_content_addressed(b"alpha").unwrap();
        store.put_content_addressed(b"beta").unwrap();
        store.put_content_addressed(b"gamma").unwrap();
        store.sync_all().unwrap();
    }

    let result = handle_rebuild(&surviving_dir, &replacement_dir);
    assert!(result.is_ok(), "handle_rebuild failed: {:?}", result.err());

    // Verify replacement has all objects.
    let replacement = tidefs_local_object_store::LocalObjectStore::open(&replacement_dir).unwrap();
    let keys = replacement.list_keys();
    assert_eq!(keys.len(), 3, "should have all 3 objects");

    // Verify payloads match.
    let surviving = tidefs_local_object_store::LocalObjectStore::open(&surviving_dir).unwrap();
    for key in &keys {
        let sp = surviving.get(*key).unwrap().unwrap();
        let rp = replacement.get(*key).unwrap().unwrap();
        assert_eq!(sp, rp, "payload mismatch for {key:?}");
    }
}

#[test]
fn rebuild_command_empty_store() {
    let dir = tempfile::tempdir().unwrap();
    let surviving_dir = dir.path().join("surviving-empty");
    let replacement_dir = dir.path().join("replacement-empty");
    std::fs::create_dir_all(&surviving_dir).unwrap();

    // Open empty surviving store.
    {
        let _store = tidefs_local_object_store::LocalObjectStore::open(&surviving_dir).unwrap();
    }

    let result = handle_rebuild(&surviving_dir, &replacement_dir);
    assert!(
        result.is_ok(),
        "rebuild empty should succeed: {:?}",
        result.err()
    );

    let replacement = tidefs_local_object_store::LocalObjectStore::open(&replacement_dir).unwrap();
    assert!(
        replacement.list_keys().is_empty(),
        "replacement should be empty"
    );
}
