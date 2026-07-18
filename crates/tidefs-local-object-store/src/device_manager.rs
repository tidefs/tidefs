// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Online device topology management: add, remove, and replace devices while
//! the pool is live.
//!
//! Implements online device topology operations summarized by
//! `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`.
//!
//! The `DeviceManager` coordinates label updates on device topology changes:
//! - Adding a device: writes label to new device, updates all existing device
//!   labels with incremented topology_generation and device_count.
//! - Removing a device: updates topology labels after evacuation completes.
//! - Replacing a device: add new → copy/rebuild → remove old.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use crate::device::{DeviceBacking, DeviceClass as DeviceDeviceClass, DeviceConfig};
use crate::pool_label::{
    decode_label, encode_label, features, seal_label, LabelDeviceClass, PoolLabelV1,
    PoolRedundancyPolicy, POOL_LABEL_SIZE, POOL_LABEL_V1_EXT_WIRE_SIZE, POOL_LABEL_V1_WIRE_SIZE,
};
use crate::pool_lifecycle_evidence::{
    PoolLifecycleAction, PoolLifecycleContext, PoolLifecycleEvidence,
};
use crate::{Result, StoreError};

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Maintenance and spare policy enums
// ---------------------------------------------------------------------------

/// Priority for rebuild and maintenance operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MaintenancePriority {
    /// Latency-sensitive rebuild; runs above foreground I/O.
    Critical,
    /// Elevated priority for degraded redundancy.
    High,
    /// Standard background rebuild.
    Normal,
    /// Low-impact rebuild when redundancy is healthy.
    Low,
    /// Best-effort rebuild; yields to all other I/O classes.
    Background,
}

/// Policy controlling when hot-spare devices are automatically activated.
///
/// When the pool health monitor detects a device entering FAULTED or
/// DEGRADED state, this policy determines whether a spare is activated
/// without operator intervention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SparePolicy {
    /// Never auto-activate spares; require operator intervention.
    Manual,
    /// Activate a spare when any non-spare device enters FAULTED state.
    AutoOnFault,
    /// Activate a spare when a non-spare device enters FAULTED or DEGRADED
    /// with persistent errors exceeding the given threshold.
    AutoOnDegraded { error_threshold: u64 },
}

pub struct DeviceReplacementRequest<'a> {
    pub existing_device_configs: &'a [DeviceConfig],
    pub replace_index: usize,
    pub new_device_config: &'a DeviceConfig,
    pub pool_guid: [u8; 16],
    pub device_guids: &'a [[u8; 16]],
    pub new_device_guid: [u8; 16],
    pub pool_name: &'a str,
    pub commit_group: u64,
    pub rebuild_priority: MaintenancePriority,
}

pub struct SpareActivationRequest<'a> {
    pub existing_device_configs: &'a [DeviceConfig],
    pub faulted_device_guid: [u8; 16],
    pub spare_device_config: &'a DeviceConfig,
    pub spare_device_guid: [u8; 16],
    pub policy: SparePolicy,
    pub pool_guid: [u8; 16],
    pub device_guids: &'a [[u8; 16]],
    pub pool_name: &'a str,
    pub commit_group: u64,
}

struct LabelWriteRequest<'a> {
    device_config: &'a DeviceConfig,
    pool_guid: [u8; 16],
    device_guid: [u8; 16],
    pool_name: &'a str,
    pool_state: crate::pool_label::LabelPoolState,
    commit_group: u64,
    label_commit_group: u64,
    device_index: u32,
    topology_generation: u64,
    device_count: u32,
    redundancy_policy: PoolRedundancyPolicy,
}

struct ExistingLabelUpdate<'a> {
    device_configs: &'a [DeviceConfig],
    pool_guid: [u8; 16],
    device_guids: &'a [[u8; 16]],
    pool_name: &'a str,
    commit_group: u64,
    label_commit_group: u64,
    new_topology_gen: u64,
    new_device_count: u32,
}

// DeviceManager
// ---------------------------------------------------------------------------

/// Coordinates online device topology changes with label consistency.
#[derive(Debug, Default)]
pub struct DeviceManager;

impl DeviceManager {
    /// Build source-backed lifecycle evidence for device topology changes.
    #[must_use]
    pub fn topology_lifecycle_evidence(
        action: PoolLifecycleAction,
        pool_guid: [u8; 16],
        pool_name: impl Into<String>,
        device_count: usize,
        expected_device_count: usize,
        capacity_bytes: u64,
        topology_generation: u64,
        commit_group: u64,
    ) -> PoolLifecycleEvidence {
        let context = PoolLifecycleContext {
            pool_guid: Some(pool_guid),
            pool_name: Some(pool_name.into()),
            device_count,
            expected_device_count,
            capacity_bytes,
            topology_generation,
            commit_group,
        };

        let topology_complete = context.topology_complete();

        match action {
            PoolLifecycleAction::AddDevice
            | PoolLifecycleAction::RemoveDevice
            | PoolLifecycleAction::ReplaceDevice => {
                PoolLifecycleEvidence::executed(action, context)
            }
            _ => PoolLifecycleEvidence::refused_fail_closed_with_authority(
                action,
                context,
                topology_complete,
                true,
                "unsupported device topology lifecycle action",
            ),
        }
    }

    /// Add a device to a pool. Writes a label to the new device and updates
    /// all existing device labels with an incremented topology_generation
    /// and device_count.
    ///
    /// # Arguments
    /// * `existing_device_configs` - Current device configurations in the pool.
    /// * `new_device_config` - Configuration for the device being added.
    /// * `pool_guid` - Pool GUID.
    /// * `device_guids` - GUIDs for existing devices (in order).
    /// * `new_device_guid` - GUID for the new device.
    /// * `pool_name` - Human-readable pool name.
    /// * `commit_group` - Current transaction group.
    pub fn add_device(
        existing_device_configs: &[DeviceConfig],
        new_device_config: &DeviceConfig,
        pool_guid: [u8; 16],
        device_guids: &[[u8; 16]],
        new_device_guid: [u8; 16],
        pool_name: &str,
        commit_group: u64,
    ) -> Result<()> {
        let old_device_count = existing_device_configs.len() as u32;
        let new_device_count = old_device_count + 1;
        let new_topology_gen = commit_group.wrapping_add(1);
        let label_commit_group = commit_group;
        let redundancy_policy =
            Self::topology_redundancy_policy(existing_device_configs, pool_guid)?;

        // 1. Write label to the new device.
        Self::write_single_device_label(LabelWriteRequest {
            device_config: new_device_config,
            pool_guid,
            device_guid: new_device_guid,
            pool_name,
            pool_state: crate::pool_label::LabelPoolState::Active,
            commit_group,
            label_commit_group,
            device_index: old_device_count, // device_index = old count (0-based)
            topology_generation: new_topology_gen,
            device_count: new_device_count,
            redundancy_policy,
        })?;

        // 2. Update labels on all existing devices with new topology_generation
        //    and device_count.
        Self::update_existing_labels(ExistingLabelUpdate {
            device_configs: existing_device_configs,
            pool_guid,
            device_guids,
            pool_name,
            commit_group,
            label_commit_group,
            new_topology_gen,
            new_device_count,
        })?;

        Ok(())
    }

    /// Remove a device from a pool. Updates all remaining device labels
    /// with an incremented topology_generation, decremented device_count,
    /// and updated device_index values.
    ///
    /// # Arguments
    /// * `remaining_device_configs` - Configs for devices staying in the pool.
    /// * `pool_guid` - Pool GUID.
    /// * `device_guids` - GUIDs for remaining devices.
    /// * `pool_name` - Human-readable pool name.
    /// * `commit_group` - Current transaction group.
    pub fn remove_device(
        remaining_device_configs: &[DeviceConfig],
        pool_guid: [u8; 16],
        device_guids: &[[u8; 16]],
        pool_name: &str,
        commit_group: u64,
    ) -> Result<()> {
        if remaining_device_configs.is_empty() {
            // All devices removed; nothing to label.
            return Ok(());
        }

        let new_device_count = remaining_device_configs.len() as u32;
        let new_topology_gen = commit_group.wrapping_add(1);
        let label_commit_group = commit_group;

        Self::update_existing_labels_with_reindex(ExistingLabelUpdate {
            device_configs: remaining_device_configs,
            pool_guid,
            device_guids,
            pool_name,
            commit_group,
            label_commit_group,
            new_topology_gen,
            new_device_count,
        })?;

        Ok(())
    }

    /// Replace a device: writes label to new device, updates existing labels
    /// to include the replacement in the topology.
    ///
    /// The caller is responsible for data evacuation/copy from old → new.
    pub fn replace_device(request: DeviceReplacementRequest<'_>) -> Result<()> {
        if request.replace_index >= request.existing_device_configs.len() {
            let _ = request.rebuild_priority; // deferred: wire-up rebuild scheduler
            return Err(StoreError::Io {
                operation: "replace_device",
                path: PathBuf::from(""),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("replace_index {} out of range", request.replace_index),
                ),
            });
        }

        let device_count = request.existing_device_configs.len() as u32;
        let new_topology_gen = request.commit_group.wrapping_add(1);
        let label_commit_group = request.commit_group;
        let redundancy_policy =
            Self::topology_redundancy_policy(request.existing_device_configs, request.pool_guid)?;

        // Write label to new device at the same index.
        Self::write_single_device_label(LabelWriteRequest {
            device_config: request.new_device_config,
            pool_guid: request.pool_guid,
            device_guid: request.new_device_guid,
            pool_name: request.pool_name,
            pool_state: crate::pool_label::LabelPoolState::Active,
            commit_group: request.commit_group,
            label_commit_group,
            device_index: request.replace_index as u32,
            topology_generation: new_topology_gen,
            device_count,
            redundancy_policy,
        })?;

        // Update labels on all existing devices (including the one being replaced).
        Self::update_existing_labels(ExistingLabelUpdate {
            device_configs: request.existing_device_configs,
            pool_guid: request.pool_guid,
            device_guids: request.device_guids,
            pool_name: request.pool_name,
            commit_group: request.commit_group,
            label_commit_group,
            new_topology_gen,
            new_device_count: device_count,
        })?;

        Ok(())
    }

    // -------------------------------------------------------------------
    /// Activate a hot-spare to replace a faulted or degraded device.
    ///
    /// Writes the spare's label at the faulted device's index, updates all
    /// existing device labels with an incremented topology_generation, and
    /// returns Ok. The caller is responsible for data evacuation/copy from
    /// the faulted device to the spare before calling this function, or for
    /// scheduling a rebuild after spare activation.
    pub fn activate_spare(request: SpareActivationRequest<'_>) -> Result<()> {
        // Validate spare policy.
        match request.policy {
            SparePolicy::Manual => {
                // Manual activation: always allowed when explicitly requested.
            }
            SparePolicy::AutoOnFault => {
                // Auto-activation on fault: caller verified FAULTED state.
            }
            SparePolicy::AutoOnDegraded { error_threshold: _ } => {
                // Auto-activation on degraded: caller verified error threshold.
            }
        }

        // Find the faulted device's index in the pool.
        let faulted_index =
            Self::find_device_index_by_guid(request.device_guids, &request.faulted_device_guid)?;

        let device_count = request.existing_device_configs.len() as u32;
        let new_topology_gen = request.commit_group.wrapping_add(1);
        let label_commit_group = request.commit_group;
        let redundancy_policy =
            Self::topology_redundancy_policy(request.existing_device_configs, request.pool_guid)?;

        // Write the spare's label at the faulted device's index.
        Self::write_single_device_label(LabelWriteRequest {
            device_config: request.spare_device_config,
            pool_guid: request.pool_guid,
            device_guid: request.spare_device_guid,
            pool_name: request.pool_name,
            pool_state: crate::pool_label::LabelPoolState::Active,
            commit_group: request.commit_group,
            label_commit_group,
            device_index: faulted_index as u32,
            topology_generation: new_topology_gen,
            device_count,
            redundancy_policy,
        })?;

        // Update all existing device labels with the new topology_generation.
        Self::update_existing_labels(ExistingLabelUpdate {
            device_configs: request.existing_device_configs,
            pool_guid: request.pool_guid,
            device_guids: request.device_guids,
            pool_name: request.pool_name,
            commit_group: request.commit_group,
            label_commit_group,
            new_topology_gen,
            new_device_count: device_count,
        })?;

        Ok(())
    }

    /// Find the index of a device by its GUID in the device GUIDs list.
    fn find_device_index_by_guid(
        device_guids: &[[u8; 16]],
        target_guid: &[u8; 16],
    ) -> Result<usize> {
        device_guids
            .iter()
            .position(|guid| guid == target_guid)
            .ok_or_else(|| StoreError::Io {
                operation: "activate_spare_find_device",
                path: PathBuf::from("<guid-lookup>"),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("faulted device guid {:02x?} not found in pool", target_guid),
                ),
            })
    }

    // Internal helpers
    // -------------------------------------------------------------------

    /// Write a label to a single device.
    fn write_single_device_label(request: LabelWriteRequest<'_>) -> Result<()> {
        let class = Self::map_device_class(request.device_config.class);
        let capacity = Self::get_device_capacity(request.device_config)?;

        let label = PoolLabelV1 {
            magic: crate::pool_label::POOL_LABEL_MAGIC,
            version: 1,
            pool_guid: request.pool_guid,
            device_guid: request.device_guid,
            pool_name_len: request.pool_name.len().min(255) as u16,
            pool_name: {
                let mut buf = [0u8; 255];
                let bytes = request.pool_name.as_bytes();
                let len = bytes.len().min(255);
                buf[..len].copy_from_slice(&bytes[..len]);
                buf
            },
            pool_state: request.pool_state,
            commit_group: request.commit_group,
            label_commit_group: request.label_commit_group,
            device_index: request.device_index,
            topology_generation: request.topology_generation,
            device_count: request.device_count,
            device_class: class,
            device_capacity_bytes: capacity,
            system_area_pointer: 0,
            system_area_size: 0,
            features_incompat: {
                let mut flags = features::POOL_LABEL_V1;
                if request.device_config.encryption.is_some() {
                    flags |= features::ENCRYPTION_INCOMPAT;
                }
                flags
            },
            features_ro_compat: 0,
            features_compat: 0,
            device_health: 0,
            device_read_errors: 0,
            device_write_errors: 0,
            device_checksum_errors: 0,
            redundancy_policy: request.redundancy_policy,
            checksum: [0u8; 32],
        };

        let sealed = seal_label(label).map_err(|e| StoreError::Io {
            operation: "device_manager_seal",
            path: request.device_config.path.clone(),
            source: std::io::Error::other(format!("{e:?}")),
        })?;

        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf).map_err(|e| StoreError::Io {
            operation: "device_manager_encode",
            path: request.device_config.path.clone(),
            source: std::io::Error::other(format!("{e:?}")),
        })?;

        Self::write_label_copies(request.device_config, &buf, capacity)?;

        Ok(())
    }

    /// Update labels on all existing devices with new topology_generation
    /// and device_count, preserving per-device fields.
    fn update_existing_labels(request: ExistingLabelUpdate<'_>) -> Result<()> {
        for (i, config) in request.device_configs.iter().enumerate() {
            let device_guid = if i < request.device_guids.len() {
                request.device_guids[i]
            } else {
                let mut dg = request.pool_guid;
                dg[0] ^= i as u8;
                dg
            };

            // Read existing label to get capacity and class.
            let existing = Self::read_device_label(&config.path, request.pool_guid)?;

            let class = existing.device_class;
            let capacity = existing.device_capacity_bytes;

            let label = PoolLabelV1 {
                magic: crate::pool_label::POOL_LABEL_MAGIC,
                version: 1,
                pool_guid: request.pool_guid,
                device_guid,
                pool_name_len: request.pool_name.len().min(255) as u16,
                pool_name: {
                    let mut buf = [0u8; 255];
                    let bytes = request.pool_name.as_bytes();
                    let len = bytes.len().min(255);
                    buf[..len].copy_from_slice(&bytes[..len]);
                    buf
                },
                pool_state: crate::pool_label::LabelPoolState::Active,
                commit_group: request.commit_group,
                label_commit_group: request.label_commit_group,
                device_index: i as u32,
                topology_generation: request.new_topology_gen,
                device_count: request.new_device_count,
                device_class: class,
                device_capacity_bytes: capacity,
                system_area_pointer: existing.system_area_pointer,
                system_area_size: existing.system_area_size,
                features_incompat: existing.features_incompat,
                features_ro_compat: existing.features_ro_compat,
                features_compat: existing.features_compat,
                device_health: existing.device_health,
                device_read_errors: existing.device_read_errors,
                device_write_errors: existing.device_write_errors,
                device_checksum_errors: existing.device_checksum_errors,
                redundancy_policy: existing.redundancy_policy,
                checksum: [0u8; 32],
            };

            let sealed = seal_label(label).map_err(|e| StoreError::Io {
                operation: "update_label_seal",
                path: config.path.clone(),
                source: std::io::Error::other(format!("{e:?}")),
            })?;

            let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut buf).map_err(|e| StoreError::Io {
                operation: "update_label_encode",
                path: config.path.clone(),
                source: std::io::Error::other(format!("{e:?}")),
            })?;

            Self::write_label_copies(config, &buf, capacity)?;
        }

        Ok(())
    }

    /// Update labels on remaining devices with reindexed device_index values
    /// after a device removal.
    fn update_existing_labels_with_reindex(request: ExistingLabelUpdate<'_>) -> Result<()> {
        for (i, config) in request.device_configs.iter().enumerate() {
            let device_guid = if i < request.device_guids.len() {
                request.device_guids[i]
            } else {
                let mut dg = request.pool_guid;
                dg[0] ^= i as u8;
                dg
            };

            // Read existing label to get capacity and class.
            let existing = Self::read_device_label(&config.path, request.pool_guid)?;

            let class = existing.device_class;
            let capacity = existing.device_capacity_bytes;

            let label = PoolLabelV1 {
                magic: crate::pool_label::POOL_LABEL_MAGIC,
                version: 1,
                pool_guid: request.pool_guid,
                device_guid,
                pool_name_len: request.pool_name.len().min(255) as u16,
                pool_name: {
                    let mut buf = [0u8; 255];
                    let bytes = request.pool_name.as_bytes();
                    let len = bytes.len().min(255);
                    buf[..len].copy_from_slice(&bytes[..len]);
                    buf
                },
                pool_state: crate::pool_label::LabelPoolState::Active,
                commit_group: request.commit_group,
                label_commit_group: request.label_commit_group,
                device_index: i as u32, // Reindexed
                topology_generation: request.new_topology_gen,
                device_count: request.new_device_count,
                device_class: class,
                device_capacity_bytes: capacity,
                system_area_pointer: existing.system_area_pointer,
                system_area_size: existing.system_area_size,
                features_incompat: existing.features_incompat,
                features_ro_compat: existing.features_ro_compat,
                features_compat: existing.features_compat,
                device_health: existing.device_health,
                device_read_errors: existing.device_read_errors,
                device_write_errors: existing.device_write_errors,
                device_checksum_errors: existing.device_checksum_errors,
                redundancy_policy: existing.redundancy_policy,
                checksum: [0u8; 32],
            };

            let sealed = seal_label(label).map_err(|e| StoreError::Io {
                operation: "reindex_label_seal",
                path: config.path.clone(),
                source: std::io::Error::other(format!("{e:?}")),
            })?;

            let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut buf).map_err(|e| StoreError::Io {
                operation: "reindex_label_encode",
                path: config.path.clone(),
                source: std::io::Error::other(format!("{e:?}")),
            })?;

            Self::write_label_copies(config, &buf, capacity)?;
        }

        Ok(())
    }

    /// Read a device label from the label file.
    fn read_device_label(device_path: &Path, pool_guid: [u8; 16]) -> Result<PoolLabelV1> {
        let label_path = if device_path.is_dir() {
            device_path.join(".tidefs_label")
        } else {
            device_path.to_path_buf()
        };

        let mut file = fs::OpenOptions::new()
            .read(true)
            .open(&label_path)
            .map_err(|e| StoreError::Io {
                operation: "read_device_label_open",
                path: label_path.clone(),
                source: e,
            })?;
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        file.read_exact(&mut buf[..POOL_LABEL_V1_WIRE_SIZE])
            .map_err(|e| StoreError::Io {
                operation: "read_device_label",
                path: label_path.clone(),
                source: e,
            })?;
        let mut len = POOL_LABEL_V1_WIRE_SIZE;
        while len < buf.len() {
            match file.read(&mut buf[len..]) {
                Ok(0) => break,
                Ok(read) => len += read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(source) => {
                    return Err(StoreError::Io {
                        operation: "read_device_label",
                        path: label_path.clone(),
                        source,
                    });
                }
            }
        }

        match decode_label(&buf[..len]) {
            Ok(label) if label.pool_guid == pool_guid => Ok(label),
            Ok(_) => Err(StoreError::Io {
                operation: "decode_device_label",
                path: label_path,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "pool label belongs to a different pool",
                ),
            }),
            Err(error) => Err(StoreError::Io {
                operation: "decode_device_label",
                path: label_path,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid pool label: {error:?}"),
                ),
            }),
        }
    }

    fn topology_redundancy_policy(
        device_configs: &[DeviceConfig],
        pool_guid: [u8; 16],
    ) -> Result<PoolRedundancyPolicy> {
        let Some(config) = device_configs.first() else {
            return Ok(PoolRedundancyPolicy::default());
        };
        Ok(Self::read_device_label(&config.path, pool_guid)?.redundancy_policy)
    }

    /// Write label bytes at a given offset.
    fn write_label_bytes(
        path: &Path,
        data: &[u8; POOL_LABEL_V1_EXT_WIRE_SIZE],
        offset: u64,
    ) -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .create(true)
            .open(path)
            .map_err(|e| StoreError::Io {
                operation: "dm_write_label_open",
                path: path.to_path_buf(),
                source: e,
            })?;

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| StoreError::Io {
                operation: "dm_write_label_seek",
                path: path.to_path_buf(),
                source: e,
            })?;

        file.write_all(data).map_err(|e| StoreError::Io {
            operation: "dm_write_label",
            path: path.to_path_buf(),
            source: e,
        })?;

        file.sync_all().map_err(|e| StoreError::Io {
            operation: "dm_write_label_sync",
            path: path.to_path_buf(),
            source: e,
        })?;

        Ok(())
    }

    /// Write the primary and canonical backup copies of a device label.
    fn write_label_copies(
        config: &DeviceConfig,
        data: &[u8; POOL_LABEL_V1_EXT_WIRE_SIZE],
        capacity: u64,
    ) -> Result<()> {
        let label_path = if config.path.is_dir() {
            config.path.join(".tidefs_label")
        } else {
            config.path.clone()
        };
        let backup_offset = Self::backup_label_offset(config, capacity)?;

        Self::write_label_bytes(&label_path, data, 0)?;
        Self::write_label_bytes(&label_path, data, backup_offset)
    }

    fn backup_label_offset(config: &DeviceConfig, capacity: u64) -> Result<u64> {
        if config.backing == DeviceBacking::DirectoryObjectStoreCompat {
            return Ok(POOL_LABEL_SIZE as u64);
        }

        let label_area_bytes = POOL_LABEL_SIZE as u64;
        capacity
            .checked_sub(label_area_bytes)
            .filter(|offset| *offset >= label_area_bytes)
            .ok_or_else(|| StoreError::Io {
                operation: "dm_label_backup_offset",
                path: config.path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("device capacity {capacity} cannot hold two pool label areas"),
                ),
            })
    }

    fn map_device_class(class: DeviceDeviceClass) -> LabelDeviceClass {
        match class {
            DeviceDeviceClass::Data => LabelDeviceClass::Hdd,
            DeviceDeviceClass::Metadata => LabelDeviceClass::Hdd,
            DeviceDeviceClass::IntentLog => LabelDeviceClass::LogDevice,
            DeviceDeviceClass::ReadCache => LabelDeviceClass::Cache,
            DeviceDeviceClass::Special => LabelDeviceClass::Special,
            DeviceDeviceClass::Spare => LabelDeviceClass::Spare,
            DeviceDeviceClass::Unknown(v) => {
                LabelDeviceClass::from_u8(v).unwrap_or(LabelDeviceClass::Hdd)
            }
        }
    }

    fn get_device_capacity(config: &DeviceConfig) -> Result<u64> {
        let path = &config.path;
        if config.backing == DeviceBacking::DirectoryObjectStoreCompat {
            Ok(1024u64 * 1024 * 1024 * 1024) // 1 TiB placeholder
        } else {
            Self::get_byte_device_capacity(path).map_err(|e| StoreError::Io {
                operation: "dm_get_capacity",
                path: path.to_path_buf(),
                source: e,
            })
        }
    }

    fn get_byte_device_capacity(path: &Path) -> std::io::Result<u64> {
        let metadata = fs::metadata(path)?;
        let file_type = metadata.file_type();
        if metadata.is_file() {
            return Ok(metadata.len());
        }
        if file_type.is_block_device() {
            let mut file = fs::File::open(path)?;
            return file.seek(SeekFrom::End(0));
        }
        let reason = if metadata.is_dir() {
            "pool device path is a directory; use a block device or regular file"
        } else {
            "pool device path is not a block device or regular file"
        };
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            reason,
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceBacking, DeviceClass, DeviceConfig, DeviceKind};
    use crate::pool_lifecycle_evidence::PoolLifecycleOutcome;

    #[test]
    fn topology_lifecycle_evidence_records_device_actions() {
        for action in [
            PoolLifecycleAction::AddDevice,
            PoolLifecycleAction::RemoveDevice,
            PoolLifecycleAction::ReplaceDevice,
        ] {
            let evidence = DeviceManager::topology_lifecycle_evidence(
                action,
                [0x55; 16],
                "topology",
                3,
                3,
                3 * 1024 * 1024 * 1024,
                9,
                8,
            );

            assert_eq!(evidence.action, action);
            assert_eq!(evidence.outcome, PoolLifecycleOutcome::Executed);
            assert_eq!(evidence.pool_guid, Some([0x55; 16]));
            assert_eq!(evidence.pool_name.as_deref(), Some("topology"));
            assert_eq!(evidence.device_count, 3);
            assert_eq!(evidence.expected_device_count, 3);
            assert_eq!(evidence.capacity_bytes, 3 * 1024 * 1024 * 1024);
            assert_eq!(evidence.topology_generation, 9);
            assert_eq!(evidence.commit_group, 8);
            assert!(evidence.topology_complete);
            assert!(evidence.owner_authorized);
            assert!(!evidence.is_fail_closed());
        }
    }

    #[test]
    fn topology_lifecycle_evidence_refuses_unsupported_action() {
        let evidence = DeviceManager::topology_lifecycle_evidence(
            PoolLifecycleAction::Export,
            [0x56; 16],
            "topology",
            1,
            1,
            1024 * 1024 * 1024,
            9,
            8,
        );

        assert_eq!(evidence.action, PoolLifecycleAction::Export);
        assert!(evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert!(evidence.summary().contains("action=export"));
        assert!(evidence.summary().contains("fail_closed=true"));
        assert!(evidence.reason.contains("unsupported"));
    }

    #[test]
    fn topology_lifecycle_evidence_refuses_unsupported_surplus_topology() {
        let evidence = DeviceManager::topology_lifecycle_evidence(
            PoolLifecycleAction::Export,
            [0x57; 16],
            "topology",
            4,
            3,
            4 * 1024 * 1024 * 1024,
            9,
            8,
        );

        assert_eq!(evidence.action, PoolLifecycleAction::Export);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.fail_closed);
        assert!(evidence.is_fail_closed());
        assert!(evidence.reason.contains("unsupported"));
    }

    #[test]
    fn topology_lifecycle_evidence_refuses_zero_generation_topology() {
        let evidence = DeviceManager::topology_lifecycle_evidence(
            PoolLifecycleAction::AddDevice,
            [0x58; 16],
            "topology",
            3,
            3,
            3 * 1024 * 1024 * 1024,
            0,
            8,
        );

        assert_eq!(evidence.action, PoolLifecycleAction::AddDevice);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.topology_generation, 0);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    #[test]
    fn topology_lifecycle_evidence_refuses_missing_capacity_topology() {
        let evidence = DeviceManager::topology_lifecycle_evidence(
            PoolLifecycleAction::RemoveDevice,
            [0x59; 16],
            "topology",
            3,
            3,
            0,
            9,
            8,
        );

        assert_eq!(evidence.action, PoolLifecycleAction::RemoveDevice);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.capacity_bytes, 0);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "tidefs-dm-{}-{}-{}",
            std::process::id(),
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn make_device_config(path: &Path) -> DeviceConfig {
        DeviceConfig {
            media_class: Default::default(),
            path: path.to_path_buf(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single {
                path: path.to_path_buf(),
            },
            compression: None,
            encryption: None,
        }
    }

    fn make_byte_device_config(path: &Path) -> DeviceConfig {
        DeviceConfig {
            media_class: Default::default(),
            path: path.to_path_buf(),
            backing: DeviceBacking::RegularFileDev,
            class: DeviceClass::Data,
            kind: DeviceKind::Block {
                path: path.to_path_buf(),
            },
            compression: None,
            encryption: None,
        }
    }

    fn read_label_at(path: &Path, offset: u64) -> PoolLabelV1 {
        let mut file = fs::File::open(path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        file.read_exact(&mut buf).unwrap();
        decode_label(&buf).unwrap()
    }

    #[test]
    fn add_device_writes_labels() {
        let dir1 = temp_dir("dm-add-1");
        let dir2 = temp_dir("dm-add-2");

        let config1 = make_device_config(&dir1);
        let config2 = make_device_config(&dir2);

        let pool_guid = [0x01u8; 16];
        let device_guids = [[0x11u8; 16]];
        let new_device_guid = [0x22u8; 16];

        // First, write label for existing device manually.
        {
            let label_path = dir1.join(".tidefs_label");
            let label = PoolLabelV1 {
                magic: crate::pool_label::POOL_LABEL_MAGIC,
                version: 1,
                pool_guid,
                device_guid: device_guids[0],
                pool_name_len: 4,
                pool_name: {
                    let mut buf = [0u8; 255];
                    buf[..4].copy_from_slice(b"test");
                    buf
                },
                pool_state: crate::pool_label::LabelPoolState::Active,
                commit_group: 1,
                label_commit_group: 1,
                device_index: 0,
                topology_generation: 1,
                device_count: 1,
                device_class: LabelDeviceClass::Hdd,
                device_capacity_bytes: 1024 * 1024 * 1024,
                system_area_pointer: 0,
                system_area_size: 0,
                features_incompat: features::POOL_LABEL_V1,
                features_ro_compat: 0,
                features_compat: 0,
                device_health: 0,
                device_read_errors: 0,
                device_write_errors: 0,
                device_checksum_errors: 0,
                redundancy_policy: PoolRedundancyPolicy::default(),
                checksum: [0u8; 32],
            };
            let sealed = seal_label(label).unwrap();
            let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
            encode_label(&sealed, &mut buf).unwrap();
            fs::write(&label_path, buf).unwrap();
        }

        let result = DeviceManager::add_device(
            &[config1],
            &config2,
            pool_guid,
            &device_guids,
            new_device_guid,
            "test",
            1,
        );
        assert!(result.is_ok());

        // Check new device has a label.
        let label2_path = dir2.join(".tidefs_label");
        assert!(label2_path.exists());

        let data = fs::read(&label2_path).unwrap();
        let decoded = decode_label(&data).unwrap();
        assert_eq!(decoded.pool_guid, pool_guid);
        assert_eq!(decoded.device_index, 1); // second device
        assert_eq!(decoded.device_count, 2);

        // Check existing device label was updated.
        let label1_path = dir1.join(".tidefs_label");
        let data1 = fs::read(&label1_path).unwrap();
        let decoded1 = decode_label(&data1).unwrap();
        assert_eq!(decoded1.device_count, 2);
        // topology_generation should have been bumped.
        assert!(decoded1.topology_generation > 1);

        let _ = fs::remove_dir_all(&dir1);
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn add_device_refuses_missing_existing_label_before_writing_new_device() {
        let existing_dir = temp_dir("dm-add-missing-existing-label");
        let new_dir = temp_dir("dm-add-missing-new-label");
        let existing_config = make_device_config(&existing_dir);
        let new_config = make_device_config(&new_dir);

        let result = DeviceManager::add_device(
            &[existing_config],
            &new_config,
            [0x21; 16],
            &[[0x22; 16]],
            [0x23; 16],
            "missing-label",
            1,
        );

        assert!(result.is_err());
        assert!(!new_dir.join(".tidefs_label").exists());

        let _ = fs::remove_dir_all(&existing_dir);
        let _ = fs::remove_dir_all(&new_dir);
    }

    #[test]
    fn add_device_updates_canonical_tail_labels_on_byte_devices() {
        let root = temp_dir("dm-add-byte-tail");
        let existing_path = root.join("existing.img");
        let new_path = root.join("new.img");
        let capacity = 4 * POOL_LABEL_SIZE as u64;
        let tail_offset = capacity - POOL_LABEL_SIZE as u64;

        for path in [&existing_path, &new_path] {
            let file = fs::File::create(path).unwrap();
            file.set_len(capacity).unwrap();
        }

        let existing_config = make_byte_device_config(&existing_path);
        let new_config = make_byte_device_config(&new_path);
        let pool_guid = [0x31u8; 16];
        let existing_guid = [0x32u8; 16];
        let new_guid = [0x33u8; 16];

        DeviceManager::write_single_device_label(LabelWriteRequest {
            device_config: &existing_config,
            pool_guid,
            device_guid: existing_guid,
            pool_name: "byte-tail",
            pool_state: crate::pool_label::LabelPoolState::Active,
            commit_group: 1,
            label_commit_group: 1,
            device_index: 0,
            topology_generation: 1,
            device_count: 1,
            redundancy_policy: PoolRedundancyPolicy::replicated(2),
        })
        .unwrap();

        let mut existing_label = read_label_at(&existing_path, 0);
        existing_label.device_health = 1;
        existing_label.device_read_errors = 17;
        existing_label.device_write_errors = 19;
        existing_label.device_checksum_errors = 23;
        let sealed = seal_label(existing_label).unwrap();
        let mut encoded = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut encoded).unwrap();
        DeviceManager::write_label_copies(&existing_config, &encoded, capacity).unwrap();

        DeviceManager::add_device(
            std::slice::from_ref(&existing_config),
            &new_config,
            pool_guid,
            &[existing_guid],
            new_guid,
            "byte-tail",
            7,
        )
        .unwrap();

        for (path, device_guid, device_index) in
            [(&existing_path, existing_guid, 0), (&new_path, new_guid, 1)]
        {
            let head = read_label_at(path, 0);
            let tail = read_label_at(path, tail_offset);

            for label in [head, tail] {
                assert_eq!(label.pool_guid, pool_guid);
                assert_eq!(label.device_guid, device_guid);
                assert_eq!(label.device_index, device_index);
                assert_eq!(label.device_count, 2);
                assert_eq!(label.topology_generation, 8);
                assert_eq!(label.device_capacity_bytes, capacity);
                assert_eq!(label.redundancy_policy, PoolRedundancyPolicy::replicated(2));
                if device_guid == existing_guid {
                    assert_eq!(label.device_health, 1);
                    assert_eq!(label.device_read_errors, 17);
                    assert_eq!(label.device_write_errors, 19);
                    assert_eq!(label.device_checksum_errors, 23);
                }
            }
            assert_eq!(fs::metadata(path).unwrap().len(), capacity);
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn remove_device_updates_labels() {
        use crate::pool_label::{encode_label, seal_label};

        let dir1 = temp_dir("dm-rm-1");
        let dir2 = temp_dir("dm-rm-2");

        let config1 = make_device_config(&dir1);

        let pool_guid = [0x05u8; 16];
        let device_guids = [[0xAAu8; 16], [0xBBu8; 16]];

        // Write labels for both devices.
        for (i, dir) in [&dir1, &dir2].iter().enumerate() {
            let label_path = dir.join(".tidefs_label");
            let label = PoolLabelV1 {
                magic: crate::pool_label::POOL_LABEL_MAGIC,
                version: 1,
                pool_guid,
                device_guid: device_guids[i],
                pool_name_len: 4,
                pool_name: {
                    let mut buf = [0u8; 255];
                    buf[..4].copy_from_slice(b"test");
                    buf
                },
                pool_state: crate::pool_label::LabelPoolState::Active,
                commit_group: 5,
                label_commit_group: 5,
                device_index: i as u32,
                topology_generation: 1,
                device_count: 2,
                device_class: LabelDeviceClass::Hdd,
                device_capacity_bytes: 1024 * 1024 * 1024,
                system_area_pointer: 0,
                system_area_size: 0,
                features_incompat: features::POOL_LABEL_V1,
                features_ro_compat: 0,
                features_compat: 0,
                device_health: 1,
                device_read_errors: 29,
                device_write_errors: 31,
                device_checksum_errors: 37,
                redundancy_policy: PoolRedundancyPolicy::replicated(2),
                checksum: [0u8; 32],
            };
            let sealed = seal_label(label).unwrap();
            let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut buf).unwrap();
            fs::write(&label_path, buf).unwrap();
        }

        // Remove device 1 (index 1) — only config1 remains.
        let result =
            DeviceManager::remove_device(&[config1], pool_guid, &[[0xAAu8; 16]], "test", 5);
        assert!(result.is_ok());

        // Check remaining device label is updated.
        let label_path = dir1.join(".tidefs_label");
        let data = fs::read(&label_path).unwrap();
        let decoded = decode_label(&data).unwrap();
        assert_eq!(decoded.device_count, 1);
        assert!(decoded.topology_generation > 1);
        assert_eq!(decoded.device_health, 1);
        assert_eq!(decoded.device_read_errors, 29);
        assert_eq!(decoded.device_write_errors, 31);
        assert_eq!(decoded.device_checksum_errors, 37);
        assert_eq!(
            decoded.redundancy_policy,
            PoolRedundancyPolicy::replicated(2)
        );

        let _ = fs::remove_dir_all(&dir1);
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn activate_spare_replaces_faulted_device() {
        use crate::pool_label::{encode_label, seal_label};

        let dir1 = temp_dir("dm-spare-1");
        let dir2 = temp_dir("dm-spare-2");
        let spare_dir = temp_dir("dm-spare-3");

        let config1 = make_device_config(&dir1);
        let config2 = make_device_config(&dir2);
        let spare_config = make_device_config(&spare_dir);

        let pool_guid = [0x10u8; 16];
        let device_guids = [[0xA1u8; 16], [0xA2u8; 16]];
        let spare_guid = [0xAAu8; 16];
        let faulted_guid = device_guids[1]; // device at index 1 is faulted

        // Write labels for both existing devices.
        for (i, dir) in [&dir1, &dir2].iter().enumerate() {
            let label_path = dir.join(".tidefs_label");
            let label = PoolLabelV1 {
                magic: crate::pool_label::POOL_LABEL_MAGIC,
                version: 1,
                pool_guid,
                device_guid: device_guids[i],
                pool_name_len: 4,
                pool_name: {
                    let mut buf = [0u8; 255];
                    buf[..4].copy_from_slice(b"test");
                    buf
                },
                pool_state: crate::pool_label::LabelPoolState::Active,
                commit_group: 10,
                label_commit_group: 10,
                device_index: i as u32,
                topology_generation: 2,
                device_count: 2,
                device_class: LabelDeviceClass::Hdd,
                device_capacity_bytes: 1024 * 1024 * 1024,
                system_area_pointer: 0,
                system_area_size: 0,
                features_incompat: features::POOL_LABEL_V1,
                features_ro_compat: 0,
                features_compat: 0,
                device_health: 0,
                device_read_errors: 0,
                device_write_errors: 0,
                device_checksum_errors: 0,
                redundancy_policy: PoolRedundancyPolicy::default(),
                checksum: [0u8; 32],
            };
            let sealed = seal_label(label).unwrap();
            let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
            encode_label(&sealed, &mut buf).unwrap();
            fs::write(&label_path, buf).unwrap();
        }

        let request = SpareActivationRequest {
            existing_device_configs: &[config1, config2],
            faulted_device_guid: faulted_guid,
            spare_device_config: &spare_config,
            spare_device_guid: spare_guid,
            policy: SparePolicy::Manual,
            pool_guid,
            device_guids: &device_guids,
            pool_name: "test",
            commit_group: 10,
        };

        let result = DeviceManager::activate_spare(request);
        assert!(result.is_ok(), "activate_spare failed: {:?}", result.err());

        // Check spare device has a label at the faulted device's index (1).
        let spare_label_path = spare_dir.join(".tidefs_label");
        assert!(spare_label_path.exists());
        let data = fs::read(&spare_label_path).unwrap();
        let decoded = decode_label(&data).unwrap();
        assert_eq!(decoded.pool_guid, pool_guid);
        assert_eq!(decoded.device_index, 1); // faulted device's index
        assert_eq!(decoded.device_count, 2);
        assert!(decoded.topology_generation > 2);

        // Check existing device labels were updated.
        let label1_path = dir1.join(".tidefs_label");
        let data1 = fs::read(&label1_path).unwrap();
        let decoded1 = decode_label(&data1).unwrap();
        assert!(decoded1.topology_generation > 2);

        let _ = fs::remove_dir_all(&dir1);
        let _ = fs::remove_dir_all(&dir2);
        let _ = fs::remove_dir_all(&spare_dir);
    }

    #[test]
    fn activate_spare_unknown_guid_returns_error() {
        let dir1 = temp_dir("dm-spare-err-1");
        let config1 = make_device_config(&dir1);

        let pool_guid = [0x20u8; 16];
        let device_guids = [[0xB1u8; 16]];

        // Write label for existing device.
        let label_path = dir1.join(".tidefs_label");
        let label = PoolLabelV1 {
            magic: crate::pool_label::POOL_LABEL_MAGIC,
            version: 1,
            pool_guid,
            device_guid: device_guids[0],
            pool_name_len: 4,
            pool_name: {
                let mut buf = [0u8; 255];
                buf[..4].copy_from_slice(b"test");
                buf
            },
            pool_state: crate::pool_label::LabelPoolState::Active,
            commit_group: 3,
            label_commit_group: 3,
            device_index: 0,
            topology_generation: 1,
            device_count: 1,
            device_class: LabelDeviceClass::Hdd,
            device_capacity_bytes: 1024 * 1024 * 1024,
            system_area_pointer: 0,
            system_area_size: 0,
            features_incompat: features::POOL_LABEL_V1,
            features_ro_compat: 0,
            features_compat: 0,
            device_health: 0,
            device_read_errors: 0,
            device_write_errors: 0,
            device_checksum_errors: 0,
            redundancy_policy: PoolRedundancyPolicy::default(),
            checksum: [0u8; 32],
        };
        let sealed = seal_label(label).unwrap();
        let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();
        fs::write(&label_path, buf).unwrap();

        let unknown_guid = [0xFFu8; 16];
        let spare_dir = temp_dir("dm-spare-err-2");
        let spare_config = make_device_config(&spare_dir);

        let request = SpareActivationRequest {
            existing_device_configs: &[config1],
            faulted_device_guid: unknown_guid,
            spare_device_config: &spare_config,
            spare_device_guid: [0xCCu8; 16],
            policy: SparePolicy::Manual,
            pool_guid,
            device_guids: &device_guids,
            pool_name: "test",
            commit_group: 3,
        };

        let result = DeviceManager::activate_spare(request);
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&dir1);
        let _ = fs::remove_dir_all(&spare_dir);
    }
}
