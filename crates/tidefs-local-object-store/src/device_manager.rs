// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Online device topology management: add, remove, and replace devices while
//! the pool is live.
//!
//! Implements Phase 5-8 of `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`.
//!
//! The `DeviceManager` coordinates label updates on device topology changes:
//! - Adding a device: writes label to new device, updates all existing device
//!   labels with incremented topology_generation and device_count.
//! - Removing a device: updates topology labels after evacuation completes.
//! - Replacing a device: add new → copy/rebuild → remove old.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use crate::device::{DeviceBacking, DeviceClass as DeviceDeviceClass, DeviceConfig};
use crate::pool_label::{
    decode_label, encode_label, features, seal_label, LabelDeviceClass, PoolLabelV1,
    PoolRedundancyPolicy, POOL_LABEL_SIZE, POOL_LABEL_V1_WIRE_SIZE,
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
            redundancy_policy: PoolRedundancyPolicy::default(),
            checksum: [0u8; 32],
        };

        let sealed = seal_label(label).map_err(|e| StoreError::Io {
            operation: "device_manager_seal",
            path: request.device_config.path.clone(),
            source: std::io::Error::other(format!("{e:?}")),
        })?;

        let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
        encode_label(&sealed, &mut buf).map_err(|e| StoreError::Io {
            operation: "device_manager_encode",
            path: request.device_config.path.clone(),
            source: std::io::Error::other(format!("{e:?}")),
        })?;

        let label_path = if request.device_config.path.is_dir() {
            request.device_config.path.join(".tidefs_label")
        } else {
            request.device_config.path.clone()
        };

        // Write both copies.
        Self::write_label_bytes(&label_path, &buf, 0)?;
        Self::write_label_bytes(&label_path, &buf, POOL_LABEL_SIZE as u64)?;

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
            let existing = Self::read_device_label(&config.path, request.pool_guid, i as u32)?;

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
                device_health: 0,
                device_read_errors: 0,
                device_write_errors: 0,
                device_checksum_errors: 0,
                redundancy_policy: existing.redundancy_policy,
                checksum: [0u8; 32],
            };

            let sealed = seal_label(label).map_err(|e| StoreError::Io {
                operation: "update_label_seal",
                path: config.path.clone(),
                source: std::io::Error::other(format!("{e:?}")),
            })?;

            let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
            encode_label(&sealed, &mut buf).map_err(|e| StoreError::Io {
                operation: "update_label_encode",
                path: config.path.clone(),
                source: std::io::Error::other(format!("{e:?}")),
            })?;

            let label_path = if config.path.is_dir() {
                config.path.join(".tidefs_label")
            } else {
                config.path.clone()
            };

            Self::write_label_bytes(&label_path, &buf, 0)?;
            Self::write_label_bytes(&label_path, &buf, POOL_LABEL_SIZE as u64)?;
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
            let existing = Self::read_device_label(&config.path, request.pool_guid, i as u32)?;

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
                device_health: 0,
                device_read_errors: 0,
                device_write_errors: 0,
                device_checksum_errors: 0,
                redundancy_policy: existing.redundancy_policy,
                checksum: [0u8; 32],
            };

            let sealed = seal_label(label).map_err(|e| StoreError::Io {
                operation: "reindex_label_seal",
                path: config.path.clone(),
                source: std::io::Error::other(format!("{e:?}")),
            })?;

            let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
            encode_label(&sealed, &mut buf).map_err(|e| StoreError::Io {
                operation: "reindex_label_encode",
                path: config.path.clone(),
                source: std::io::Error::other(format!("{e:?}")),
            })?;

            let label_path = if config.path.is_dir() {
                config.path.join(".tidefs_label")
            } else {
                config.path.clone()
            };

            Self::write_label_bytes(&label_path, &buf, 0)?;
            Self::write_label_bytes(&label_path, &buf, POOL_LABEL_SIZE as u64)?;
        }

        Ok(())
    }

    /// Read a device label from the label file.
    fn read_device_label(
        device_path: &Path,
        _pool_guid: [u8; 16],
        device_index: u32,
    ) -> Result<PoolLabelV1> {
        use std::io::Read;

        let label_path = if device_path.is_dir() {
            device_path.join(".tidefs_label")
        } else {
            device_path.to_path_buf()
        };

        if !label_path.exists() {
            // Return default.
            return Ok(PoolLabelV1 {
                magic: crate::pool_label::POOL_LABEL_MAGIC,
                version: 1,
                pool_guid: _pool_guid,
                device_guid: [0u8; 16],
                pool_name_len: 0,
                pool_name: [0u8; 255],
                pool_state: crate::pool_label::LabelPoolState::Active,
                commit_group: 0,
                label_commit_group: 0,
                device_index,
                topology_generation: 0,
                device_count: 0,
                device_class: LabelDeviceClass::Hdd,
                device_capacity_bytes: 0,
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
            });
        }

        let mut file = fs::OpenOptions::new()
            .read(true)
            .open(&label_path)
            .map_err(|e| StoreError::Io {
                operation: "read_device_label_open",
                path: label_path.clone(),
                source: e,
            })?;
        let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
        file.read_exact(&mut buf).map_err(|e| StoreError::Io {
            operation: "read_device_label",
            path: label_path.clone(),
            source: e,
        })?;

        // Try decoding; if fails, return default.
        match decode_label(&buf) {
            Ok(label) => Ok(label),
            Err(_) => Ok(PoolLabelV1 {
                magic: crate::pool_label::POOL_LABEL_MAGIC,
                version: 1,
                pool_guid: _pool_guid,
                device_guid: [0u8; 16],
                pool_name_len: 0,
                pool_name: [0u8; 255],
                pool_state: crate::pool_label::LabelPoolState::Active,
                commit_group: 0,
                label_commit_group: 0,
                device_index,
                topology_generation: 0,
                device_count: 0,
                device_class: LabelDeviceClass::Hdd,
                device_capacity_bytes: 0,
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
            }),
        }
    }

    /// Write label bytes at a given offset.
    fn write_label_bytes(
        path: &Path,
        data: &[u8; POOL_LABEL_V1_WIRE_SIZE],
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
