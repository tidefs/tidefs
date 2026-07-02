// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! # Device Removal Authority Map
//!
//! This module anchors device removal in a committed root on the target
//! [`LocalObjectStore`].  When a device is removed from a TideFS pool, the
//! removal must be anchored so that crash recovery can detect the change
//! and prevent the pool from being imported in an inconsistent state.
//!
//! ## Authority Flow
//!
//! The device-removal pipeline has seven stages.  Each stage draws authority
//! from a specific source.  The table below traces what is pool-authoritative
//! (imported from sealed [`PoolLabelV1`] records or derived from the resulting
//! [`PoolConfig`]) and what remains synthetic.
//!
//! | Stage | Function | Authority Source | Pool-Authoritative | Synthetic |
//! |-------|----------|-----------------|--------------------|-----------|
//! | 1. Config Import | [`import_pool_config_from_store`] | Sealed labels in `LocalObjectStore` at `tidefs-pool-label-{idx}` keys | pool UUID, pool name, device GUIDs, device indices, device count, topology generation, feature flags, pool state, device health | Device paths: labels carry `device_index` but not real block-device paths; the importer synthesises `/dev/disk{idx}` |
//! | 2. Target & Survivor Derivation | `PoolConfig::find_leaf` / `all_leaf_paths` | Imported `PoolConfig` | Which devices exist, their GUIDs, their indices, the pool-wide or legacy compatibility topology, health, and capacity | Device paths in the tree are the synthetic paths from stage 1, not real block devices |
//! | 3. Object Enumeration | CLI: target-store key listing → `ObjectPlacement` rows | `LocalObjectStore::list_keys` (all data keys filtered from label/record keys) | None (see nonclaim boundaries) | Every data key in the target store is marked resident on the target device; no canonical locator/placement/refcount authority is consulted |
//! | 4. Evacuation Plan | `DeviceRemovalPlanner::plan_removal` | Imported topology + synthetic placements + replication intent | topology generation, device GUIDs, device count | Round-robin target assignment per object; failure-domain validation uses synthetic PlacementEntry device/node/rack IDs |
//! | 5. Post-Removal Config | `build_post_removal_pool_config` → `PoolConfig::remove_device` | Imported pre-config, mutated in place | pool UUID, pool name, feature flags, device GUIDs, topology generation (bumped), device count (decremented), remaining device tree | Device paths remain synthetic |
//! | 6. Label Persistence | [`persist_updated_labels`] | Post-removal `PoolConfig` via `to_labels()` → seal → encode | All label fields: pool UUID, device GUIDs, device count, topology generation, health, feature flags | Device path in label is unused during import (labels are keyed by device_index) |
//! | 7. Removal Anchor | [`anchor_device_removal`] | [`DeviceRemovalRecord`] from plan + result, optional updated labels | Record fields: device GUID, device index, device count before/after, topology generation, evacuation counts | `removed_device` path is the CLI-provided target path (not label-authoritative) |
//!
//! ## Known Nonclaim Boundaries
//!
//! The following must **not** be used to close live runtime, mounted, QEMU,
//! distributed, or kernel-residency release gates:
//!
//! * **Synthetic device paths.**  Labels carry `device_index` and
//!   `device_guid` but not the real block-device path.  The import path
//!   synthesises `/dev/disk{idx}`.  This is sufficient for pool-topology
//!   operations within the store but does not authoritatively tie the
//!   logical device identity to a real kernel block-device node.
//!
//! * **Synthetic object placement.**  The CLI (and any caller that enumerates
//!   data keys from the target `LocalObjectStore`) marks every discovered
//!   object as resident on the target device.  There is no canonical
//!   locator, placement map, or refcount source backing this claim.
//!   Production device removal requires authoritative placement/refcount
//!   validation; the current path is a best-effort evacuation and must not
//!   be presented as pool-authoritative relocation.
//!
//! * **Operator-provided surviving directories.**  `--surviving-dirs` is
//!   operator input, not derived from pool labels.  The pool config tells
//!   you *which* devices exist; the operator tells you *where* their backing
//!   stores live on the filesystem.  This separation means that a
//!   misconfigured `--surviving-dirs` can direct evacuation data to the
//!   wrong store without the pool detecting it.
//!
//! * **Raw block-device label writing is not wired.**  [`PoolLabelWriter`]
//!   (`tidefs-pool-scan`) can write sealed labels to real block devices at
//!   the import-visible label locations (offset 0 and end-of-device).  The
//!   current CLI removal path does **not** call [`write_updated_labels_to_devices`]
//!   or pass a [`PoolLabelWriter`] to [`anchor_device_removal`].  Labels are
//!   persisted only as named objects in the `LocalObjectStore`.  A pool
//!   import that scans raw block-device labels will not see the post-removal
//!   topology unless the caller separately writes those labels to devices.
//!
//! * **Durable-survivor-sync ordering is caller responsibility.**
//!   [`anchor_device_removal`] syncs the target store after writing the
//!   removal record.  The caller must sync surviving stores **before**
//!   calling this function.  The current CLI path respects this order, but
//!   the guard is a code convention, not a type-state or commit_group fence.
//!
//! * **No canonical emptiness verification.**  After evacuation, the code
//!   trusts `objects_failed == 0` to mean the source device is empty.
//!   There is no authoritative placement/refcount query that proves zero
//!   live references still point at the removed device.
//!
//! ## Import-Authoritative Label Schema
//!
//! Pool labels are stored in the `LocalObjectStore` under deterministic
//! keys: `tidefs-pool-label-{device_index}` for indices 0..63.  Each label
//! is a sealed [`PoolLabelV1`] with a BLAKE3-256 checksum.  The import
//! function (`import_pool_config_from_store`) reads these labels, verifies
//! checksums, validates pool-membership consistency, and reconstructs a
//! [`PoolConfig`] suitable for feeding into `PoolConfig::remove_device`.
//!
//! Labels carry **device authority** fields:
//!
//! * `pool_guid` — identity of the pool (all devices in a pool share this)
//! * `device_guid` — identity of this specific device
//! * `device_index` — 0-based position in the pool topology
//! * `device_count` — total number of devices in the pool at label-write time
//! * `topology_generation` — monotonic counter bumped on every topology change
//! * `device_health` — per-device health state (Online/Degraded/Faulted)
//! * `pool_state` — pool lifecycle state (Active/Exported/Destroyed)
//! * `features_compat` — pool feature-flag bitmask
//!
//! Labels do **not** carry:
//! * The real block-device path or kernel name
//! * The backing-store filesystem directory path
//! * The canonical placement/refcount table for objects on this device
//! * The committed-root pointer (that lives in the system area, not the label)
//!
//! ## Integration with tidefsctl
//!
//! The `tidefsctl device remove` subcommand
//! (`apps/tidefsctl/src/commands/device.rs`) is the primary operator-facing
//! consumer of this module.  It follows the seven-stage authority path
//! described above and adds:
//!
//! * Pre-evacuation data loading into an in-memory map
//! * Surviving-store sync before anchoring (correct ordering)
//! * Label persistence to every surviving store
//! * Import-from-survivors-only verification after removal
//!
//! The CLI owns the operator-provided `--surviving-dirs` to backing-store
//! mapping and the evacuation read/write closures.  This module provides
//! the anchor, label, and import primitives that the CLI composes.

use std::path::{Path, PathBuf};

use tidefs_local_object_store::ObjectKey;
use tidefs_pool_scan::{DeviceRemovalPlan, DeviceRemovalResult, PoolConfig};
use tidefs_types_pool_label_core::{encode_label, seal_label, POOL_LABEL_V1_EXT_WIRE_SIZE};

/// Key prefix for persisting pool labels in the object store.
/// Each label is stored under `tidefs-pool-label-<device-index>`.
pub const POOL_LABEL_KEY_PREFIX: &str = "tidefs-pool-label-";

/// Well-known object key for persisting device removal records.
///
/// Stored under this deterministic name so the crash-recovery loop and
/// pool import path can find the latest removal record without scanning
/// all segments.
pub const DEVICE_REMOVAL_RECORD_KEY: &str = "tidefs-device-removal-record";

/// A record of a completed (or in-progress) device removal.
///
/// Encoded with the typed/versioned durable codec selected by this module and
/// persisted through the commit_group system so recovery can replay or finalize
/// the removal.
#[derive(Clone, Debug)]
pub struct DeviceRemovalRecord {
    /// Path of the removed device.
    pub removed_device: PathBuf,
    /// GUID of the removed device.
    pub device_guid: [u8; 16],
    /// Index of the removed device.
    pub device_index: u32,
    /// Surviving devices after removal.
    pub surviving_devices: Vec<PathBuf>,
    /// Device count before removal.
    pub device_count_before: u32,
    /// Device count after removal.
    pub device_count_after: u32,
    /// Objects successfully evacuated.
    pub objects_evacuated: u64,
    /// Total bytes evacuated.
    pub bytes_evacuated: u64,
    /// Objects that failed evacuation.
    pub objects_failed: u64,
    /// New topology generation.
    pub topology_generation: u64,
    /// Whether the record represents a fully anchored removal.
    pub removal_complete: bool,
}

impl DeviceRemovalRecord {
    /// Build a record from the plan and execution result.
    #[must_use]
    pub fn from_plan_and_result(plan: &DeviceRemovalPlan, result: &DeviceRemovalResult) -> Self {
        Self {
            removed_device: result.removed_device.clone(),
            device_guid: plan.target_device_guid,
            device_index: plan.target_device_index,
            surviving_devices: result.surviving_devices.clone(),
            device_count_before: plan.device_count_before,
            device_count_after: plan.device_count_after,
            objects_evacuated: result.objects_evacuated,
            bytes_evacuated: result.bytes_evacuated,
            objects_failed: result.objects_failed,
            topology_generation: result.topology_generation,
            removal_complete: result.objects_failed == 0 && result.committed_root_anchored,
        }
    }

    /// Encode this record as the durable device-removal record format.
    ///
    /// The format is intentionally local to the current source authority. It is
    /// not a compatibility promise for older pre-release JSON records.
    pub fn encode_durable(&self) -> Result<Vec<u8>, DeviceRemovalAnchorError> {
        encode_device_removal_record(self).map_err(DeviceRemovalAnchorError::Serialize)
    }

    /// Decode the durable device-removal record format.
    ///
    /// Unknown versions, malformed bytes, trailing bytes, and invalid field
    /// combinations return an explicit error.
    pub fn decode_durable(bytes: &[u8]) -> Result<Self, DeviceRemovalAnchorError> {
        decode_device_removal_record(bytes).map_err(DeviceRemovalAnchorError::Serialize)
    }
}

/// Well-known object key for persisting in-progress evacuation state.
///
/// Stored under this deterministic name so that an interrupted evacuation
/// can resume from durable progress rather than restarting from scratch.
pub const EVACUATION_PROGRESS_KEY: &str = "tidefs-evacuation-progress";

/// Durable record of an in-progress or completed evacuation.
///
/// Persisted at well-known key [`EVACUATION_PROGRESS_KEY`] so that crash
/// recovery can resume from the last committed checkpoint.  When all objects
/// have been processed this record is superseded by the final
/// [`DeviceRemovalRecord`].
#[derive(Clone, Debug)]
pub struct EvacuationProgressRecord {
    /// Path of the device being evacuated.
    pub target_device: std::path::PathBuf,
    /// GUID of the target device.
    pub target_device_guid: [u8; 16],
    /// Index of the target device in the pool.
    pub target_device_index: u32,
    /// Surviving device paths.
    pub surviving_devices: Vec<std::path::PathBuf>,
    /// Device count before removal began.
    pub device_count_before: u32,
    /// Device count after removal completes.
    pub device_count_after: u32,
    /// Target topology generation after removal.
    pub topology_generation: u64,
    /// Index of the next object to evacuate (0-based, == total when done).
    pub next_object_index: u64,
    /// Total number of objects that need evacuation.
    pub total_objects: u64,
    /// Objects successfully evacuated so far.
    pub objects_evacuated: u64,
    /// Bytes evacuated so far.
    pub bytes_evacuated: u64,
    /// Objects that failed evacuation so far.
    pub objects_failed: u64,
    /// Extent IDs successfully evacuated (for resume filtering).
    pub evacuated_object_ids: Vec<u64>,
    /// Extent IDs that failed evacuation (for resume filtering).
    pub failed_object_ids: Vec<u64>,
}

/// Inputs for a fresh evacuation progress record.
pub struct EvacuationProgressInit {
    pub target_device: std::path::PathBuf,
    pub target_device_guid: [u8; 16],
    pub target_device_index: u32,
    pub surviving_devices: Vec<std::path::PathBuf>,
    pub device_count_before: u32,
    pub device_count_after: u32,
    pub topology_generation: u64,
    pub total_objects: u64,
}

impl EvacuationProgressRecord {
    /// Create a fresh progress record at the start of evacuation.
    #[must_use]
    pub fn new(init: EvacuationProgressInit) -> Self {
        Self {
            target_device: init.target_device,
            target_device_guid: init.target_device_guid,
            target_device_index: init.target_device_index,
            surviving_devices: init.surviving_devices,
            device_count_before: init.device_count_before,
            device_count_after: init.device_count_after,
            topology_generation: init.topology_generation,
            next_object_index: 0,
            total_objects: init.total_objects,
            objects_evacuated: 0,
            bytes_evacuated: 0,
            objects_failed: 0,
            evacuated_object_ids: Vec::new(),
            failed_object_ids: Vec::new(),
        }
    }

    /// Record a successfully evacuated object.
    pub fn record_evacuated(&mut self, object_id: u64, bytes: u64) {
        self.next_object_index = self.next_object_index.saturating_add(1);
        self.objects_evacuated = self.objects_evacuated.saturating_add(1);
        self.bytes_evacuated = self.bytes_evacuated.saturating_add(bytes);
        self.evacuated_object_ids.push(object_id);
    }

    /// Record a failed evacuation.
    pub fn record_failed(&mut self, object_id: u64) {
        self.next_object_index = self.next_object_index.saturating_add(1);
        self.objects_failed = self.objects_failed.saturating_add(1);
        self.failed_object_ids.push(object_id);
    }

    /// Returns the number of objects remaining to evacuate.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.total_objects.saturating_sub(self.next_object_index)
    }

    /// Returns `true` when all objects have been processed (successfully or failed).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.next_object_index >= self.total_objects
    }

    /// Returns the set of object IDs already processed (evacuated + failed).
    #[must_use]
    pub fn processed_object_ids(&self) -> std::collections::HashSet<u64> {
        let mut set: std::collections::HashSet<u64> =
            self.evacuated_object_ids.iter().copied().collect();
        for id in &self.failed_object_ids {
            set.insert(*id);
        }
        set
    }

    /// Encode this record as the durable evacuation-progress format.
    ///
    /// The format is intentionally local to the current source authority. It is
    /// not a compatibility promise for older pre-release JSON records.
    pub fn encode_durable(&self) -> Result<Vec<u8>, DeviceRemovalAnchorError> {
        encode_evacuation_progress_record(self).map_err(DeviceRemovalAnchorError::Serialize)
    }

    /// Decode the durable evacuation-progress format.
    ///
    /// Unknown versions, malformed bytes, trailing bytes, and invalid field
    /// combinations return an explicit error.
    pub fn decode_durable(bytes: &[u8]) -> Result<Self, DeviceRemovalAnchorError> {
        decode_evacuation_progress_record(bytes).map_err(DeviceRemovalAnchorError::Serialize)
    }
}

const DEVICE_REMOVAL_RECORD_MAGIC: &[u8; 8] = b"TFSRMV\0\0";
const EVACUATION_PROGRESS_RECORD_MAGIC: &[u8; 8] = b"TFSEVAC\0";
const DURABLE_RECORD_VERSION: u16 = 1;
const MAX_DURABLE_RECORD_PATH_BYTES: usize = 4096;
const MAX_DURABLE_RECORD_ITEMS: usize = 1_000_000;

fn encode_device_removal_record(record: &DeviceRemovalRecord) -> Result<Vec<u8>, String> {
    validate_device_removal_record(record)?;

    let mut out = Vec::new();
    write_record_header(&mut out, DEVICE_REMOVAL_RECORD_MAGIC);
    write_path(&mut out, &record.removed_device)?;
    out.extend_from_slice(&record.device_guid);
    write_u32(&mut out, record.device_index);
    write_path_vec(&mut out, &record.surviving_devices)?;
    write_u32(&mut out, record.device_count_before);
    write_u32(&mut out, record.device_count_after);
    write_u64(&mut out, record.objects_evacuated);
    write_u64(&mut out, record.bytes_evacuated);
    write_u64(&mut out, record.objects_failed);
    write_u64(&mut out, record.topology_generation);
    write_bool(&mut out, record.removal_complete);
    Ok(out)
}

fn decode_device_removal_record(bytes: &[u8]) -> Result<DeviceRemovalRecord, String> {
    let mut cursor = DurableRecordCursor::new(bytes);
    read_record_header(&mut cursor, DEVICE_REMOVAL_RECORD_MAGIC, "device removal")?;
    let removed_device = cursor.read_path("removed_device")?;
    let device_guid = cursor.read_array_16("device_guid")?;
    let device_index = cursor.read_u32("device_index")?;
    let surviving_devices = cursor.read_path_vec("surviving_devices")?;
    let device_count_before = cursor.read_u32("device_count_before")?;
    let device_count_after = cursor.read_u32("device_count_after")?;
    let objects_evacuated = cursor.read_u64("objects_evacuated")?;
    let bytes_evacuated = cursor.read_u64("bytes_evacuated")?;
    let objects_failed = cursor.read_u64("objects_failed")?;
    let topology_generation = cursor.read_u64("topology_generation")?;
    let removal_complete = cursor.read_bool("removal_complete")?;
    cursor.finish("device removal")?;

    let record = DeviceRemovalRecord {
        removed_device,
        device_guid,
        device_index,
        surviving_devices,
        device_count_before,
        device_count_after,
        objects_evacuated,
        bytes_evacuated,
        objects_failed,
        topology_generation,
        removal_complete,
    };
    validate_device_removal_record(&record)?;
    Ok(record)
}

fn validate_device_removal_record(record: &DeviceRemovalRecord) -> Result<(), String> {
    validate_nonempty_path(&record.removed_device, "removed_device")?;
    if record.device_count_before == 0 {
        return Err("device_count_before must be nonzero".into());
    }
    if record.device_index >= record.device_count_before {
        return Err(format!(
            "device_index {} is outside device_count_before {}",
            record.device_index, record.device_count_before
        ));
    }
    if record.device_count_after > record.device_count_before {
        return Err(format!(
            "device_count_after {} exceeds device_count_before {}",
            record.device_count_after, record.device_count_before
        ));
    }
    if record.removal_complete && record.objects_failed != 0 {
        return Err("removal_complete record cannot report failed objects".into());
    }
    Ok(())
}

fn encode_evacuation_progress_record(record: &EvacuationProgressRecord) -> Result<Vec<u8>, String> {
    validate_evacuation_progress_record(record)?;

    let mut out = Vec::new();
    write_record_header(&mut out, EVACUATION_PROGRESS_RECORD_MAGIC);
    write_path(&mut out, &record.target_device)?;
    out.extend_from_slice(&record.target_device_guid);
    write_u32(&mut out, record.target_device_index);
    write_path_vec(&mut out, &record.surviving_devices)?;
    write_u32(&mut out, record.device_count_before);
    write_u32(&mut out, record.device_count_after);
    write_u64(&mut out, record.topology_generation);
    write_u64(&mut out, record.next_object_index);
    write_u64(&mut out, record.total_objects);
    write_u64(&mut out, record.objects_evacuated);
    write_u64(&mut out, record.bytes_evacuated);
    write_u64(&mut out, record.objects_failed);
    write_u64_vec(&mut out, &record.evacuated_object_ids)?;
    write_u64_vec(&mut out, &record.failed_object_ids)?;
    Ok(out)
}

fn decode_evacuation_progress_record(bytes: &[u8]) -> Result<EvacuationProgressRecord, String> {
    let mut cursor = DurableRecordCursor::new(bytes);
    read_record_header(
        &mut cursor,
        EVACUATION_PROGRESS_RECORD_MAGIC,
        "evacuation progress",
    )?;
    let target_device = cursor.read_path("target_device")?;
    let target_device_guid = cursor.read_array_16("target_device_guid")?;
    let target_device_index = cursor.read_u32("target_device_index")?;
    let surviving_devices = cursor.read_path_vec("surviving_devices")?;
    let device_count_before = cursor.read_u32("device_count_before")?;
    let device_count_after = cursor.read_u32("device_count_after")?;
    let topology_generation = cursor.read_u64("topology_generation")?;
    let next_object_index = cursor.read_u64("next_object_index")?;
    let total_objects = cursor.read_u64("total_objects")?;
    let objects_evacuated = cursor.read_u64("objects_evacuated")?;
    let bytes_evacuated = cursor.read_u64("bytes_evacuated")?;
    let objects_failed = cursor.read_u64("objects_failed")?;
    let evacuated_object_ids = cursor.read_u64_vec("evacuated_object_ids")?;
    let failed_object_ids = cursor.read_u64_vec("failed_object_ids")?;
    cursor.finish("evacuation progress")?;

    let record = EvacuationProgressRecord {
        target_device,
        target_device_guid,
        target_device_index,
        surviving_devices,
        device_count_before,
        device_count_after,
        topology_generation,
        next_object_index,
        total_objects,
        objects_evacuated,
        bytes_evacuated,
        objects_failed,
        evacuated_object_ids,
        failed_object_ids,
    };
    validate_evacuation_progress_record(&record)?;
    Ok(record)
}

fn validate_evacuation_progress_record(record: &EvacuationProgressRecord) -> Result<(), String> {
    validate_nonempty_path(&record.target_device, "target_device")?;
    if record.device_count_before == 0 {
        return Err("device_count_before must be nonzero".into());
    }
    if record.target_device_index >= record.device_count_before {
        return Err(format!(
            "target_device_index {} is outside device_count_before {}",
            record.target_device_index, record.device_count_before
        ));
    }
    if record.device_count_after > record.device_count_before {
        return Err(format!(
            "device_count_after {} exceeds device_count_before {}",
            record.device_count_after, record.device_count_before
        ));
    }
    if record.next_object_index > record.total_objects {
        return Err(format!(
            "next_object_index {} exceeds total_objects {}",
            record.next_object_index, record.total_objects
        ));
    }
    if record.objects_evacuated != record.evacuated_object_ids.len() as u64 {
        return Err("objects_evacuated does not match evacuated_object_ids length".into());
    }
    if record.objects_failed != record.failed_object_ids.len() as u64 {
        return Err("objects_failed does not match failed_object_ids length".into());
    }
    let processed = record
        .objects_evacuated
        .checked_add(record.objects_failed)
        .ok_or_else(|| "processed object counters overflow".to_string())?;
    if processed > record.next_object_index {
        return Err("processed object counters exceed next_object_index".into());
    }
    Ok(())
}

fn validate_nonempty_path(path: &Path, field: &str) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

fn write_record_header(out: &mut Vec<u8>, magic: &[u8; 8]) {
    out.extend_from_slice(magic);
    write_u16(out, DURABLE_RECORD_VERSION);
}

fn read_record_header(
    cursor: &mut DurableRecordCursor<'_>,
    magic: &[u8; 8],
    record_name: &str,
) -> Result<(), String> {
    let found_magic = cursor.read_exact(8, "record magic")?;
    if found_magic != magic.as_slice() {
        return Err(format!("{record_name} record magic mismatch"));
    }
    let version = cursor.read_u16("record version")?;
    if version != DURABLE_RECORD_VERSION {
        return Err(format!(
            "{record_name} record version {version} is not supported"
        ));
    }
    Ok(())
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

fn write_len(out: &mut Vec<u8>, len: usize, field: &str) -> Result<(), String> {
    let len = u32::try_from(len).map_err(|_| format!("{field} length exceeds u32"))?;
    write_u32(out, len);
    Ok(())
}

fn write_path(out: &mut Vec<u8>, path: &Path) -> Result<(), String> {
    let path = path
        .to_str()
        .ok_or_else(|| "path is not valid UTF-8".to_string())?;
    let bytes = path.as_bytes();
    if bytes.is_empty() {
        return Err("path must not be empty".into());
    }
    if bytes.len() > MAX_DURABLE_RECORD_PATH_BYTES {
        return Err(format!(
            "path is {} bytes, max {}",
            bytes.len(),
            MAX_DURABLE_RECORD_PATH_BYTES
        ));
    }
    write_len(out, bytes.len(), "path")?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn write_path_vec(out: &mut Vec<u8>, paths: &[PathBuf]) -> Result<(), String> {
    if paths.len() > MAX_DURABLE_RECORD_ITEMS {
        return Err(format!("path vector has {} items", paths.len()));
    }
    write_len(out, paths.len(), "path vector")?;
    for path in paths {
        write_path(out, path)?;
    }
    Ok(())
}

fn write_u64_vec(out: &mut Vec<u8>, values: &[u64]) -> Result<(), String> {
    if values.len() > MAX_DURABLE_RECORD_ITEMS {
        return Err(format!("u64 vector has {} items", values.len()));
    }
    write_len(out, values.len(), "u64 vector")?;
    for value in values {
        write_u64(out, *value);
    }
    Ok(())
}

struct DurableRecordCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DurableRecordCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, len: usize, field: &str) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| format!("{field} length overflows record offset"))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| format!("truncated {field}"))?;
        self.offset = end;
        Ok(slice)
    }

    fn read_u16(&mut self, field: &str) -> Result<u16, String> {
        let bytes = self.read_exact(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self, field: &str) -> Result<u32, String> {
        let bytes = self.read_exact(4, field)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self, field: &str) -> Result<u64, String> {
        let bytes = self.read_exact(8, field)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_bool(&mut self, field: &str) -> Result<bool, String> {
        let value = self.read_exact(1, field)?[0];
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(format!("{field} has invalid boolean value {value}")),
        }
    }

    fn read_array_16(&mut self, field: &str) -> Result<[u8; 16], String> {
        let bytes = self.read_exact(16, field)?;
        let mut array = [0u8; 16];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    fn read_len(&mut self, field: &str, max: usize) -> Result<usize, String> {
        let len = self.read_u32(field)? as usize;
        if len > max {
            return Err(format!("{field} length {len} exceeds max {max}"));
        }
        Ok(len)
    }

    fn read_path(&mut self, field: &str) -> Result<PathBuf, String> {
        let len = self.read_len(field, MAX_DURABLE_RECORD_PATH_BYTES)?;
        let bytes = self.read_exact(len, field)?;
        let value =
            std::str::from_utf8(bytes).map_err(|_| format!("{field} is not valid UTF-8"))?;
        if value.is_empty() {
            return Err(format!("{field} must not be empty"));
        }
        Ok(PathBuf::from(value))
    }

    fn read_path_vec(&mut self, field: &str) -> Result<Vec<PathBuf>, String> {
        let len = self.read_len(field, MAX_DURABLE_RECORD_ITEMS)?;
        let mut paths = Vec::with_capacity(len);
        for _ in 0..len {
            paths.push(self.read_path(field)?);
        }
        Ok(paths)
    }

    fn read_u64_vec(&mut self, field: &str) -> Result<Vec<u64>, String> {
        let len = self.read_len(field, MAX_DURABLE_RECORD_ITEMS)?;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(self.read_u64(field)?);
        }
        Ok(values)
    }

    fn finish(&self, record_name: &str) -> Result<(), String> {
        if self.offset != self.bytes.len() {
            return Err(format!(
                "{record_name} record has {} trailing bytes",
                self.bytes.len() - self.offset
            ));
        }
        Ok(())
    }
}

/// Persist in-progress evacuation state to the target store.
///
/// Writes the [`EvacuationProgressRecord`] under [`EVACUATION_PROGRESS_KEY`]
/// and syncs the store so the progress is durable.  Call this after each
/// batch of evacuated objects so a crash mid-evacuation can resume.
pub fn persist_evacuation_progress(
    store: &mut tidefs_local_object_store::LocalObjectStore,
    progress: &EvacuationProgressRecord,
) -> Result<(), DeviceRemovalAnchorError> {
    let payload = progress.encode_durable()?;
    let key = ObjectKey::from_name(EVACUATION_PROGRESS_KEY);
    store
        .put(key, &payload)
        .map_err(|e| DeviceRemovalAnchorError::StoreWrite(e.to_string()))?;
    store
        .sync()
        .map_err(|e| DeviceRemovalAnchorError::StoreSync(e.to_string()))?;
    Ok(())
}

/// Load a previously persisted evacuation progress record.
///
/// Returns `Ok(None)` when no prior progress exists (first attempt).
pub fn load_evacuation_progress(
    store: &tidefs_local_object_store::LocalObjectStore,
) -> Result<Option<EvacuationProgressRecord>, DeviceRemovalAnchorError> {
    let key = ObjectKey::from_name(EVACUATION_PROGRESS_KEY);
    let bytes = store
        .get(key)
        .map_err(|e| DeviceRemovalAnchorError::StoreWrite(format!("read progress: {e}")))?;
    match bytes {
        Some(data) => Ok(Some(EvacuationProgressRecord::decode_durable(&data)?)),
        None => Ok(None),
    }
}

/// Determine the next objects to evacuate when resuming from a prior checkpoint.
///
/// Given the full set of object IDs that need evacuation and a loaded
/// [`EvacuationProgressRecord`], returns the subset of object IDs that still
/// need processing.  Already-evacuated and already-failed IDs are excluded.
#[must_use]
pub fn resume_evacuation_from_progress(
    all_object_ids: &[u64],
    progress: &EvacuationProgressRecord,
) -> Vec<u64> {
    let processed = progress.processed_object_ids();
    all_object_ids
        .iter()
        .copied()
        .filter(|id| !processed.contains(id))
        .collect()
}

/// Verify that the target device store contains zero live data objects after
/// evacuation.
///
/// This is a best-effort safety check, not a canonical emptiness proof.
/// It filters out well-known label and record keys and checks whether any
/// remaining data keys exist.  Returns `Ok(())` when the store is empty of
/// data objects, or an error describing how many data objects remain.
pub fn verify_device_emptiness_after_evacuation(
    store: &tidefs_local_object_store::LocalObjectStore,
) -> Result<(), DeviceRemovalAnchorError> {
    let all_keys = store.list_keys();
    let known_label_keys: std::collections::BTreeSet<ObjectKey> = (0u32..64u32)
        .map(|idx| ObjectKey::from_name(format!("{POOL_LABEL_KEY_PREFIX}{idx}")))
        .collect();
    let removal_key = ObjectKey::from_name(DEVICE_REMOVAL_RECORD_KEY.as_bytes());
    let progress_key = ObjectKey::from_name(EVACUATION_PROGRESS_KEY.as_bytes());

    let data_keys: Vec<ObjectKey> = all_keys
        .iter()
        .filter(|k| !known_label_keys.contains(*k) && **k != removal_key && **k != progress_key)
        .cloned()
        .collect();

    if data_keys.is_empty() {
        Ok(())
    } else {
        Err(DeviceRemovalAnchorError::Serialize(format!(
            "target device still holds {} data objects after evacuation; \
             evacuation may be incomplete or objects were written after evacuation began",
            data_keys.len()
        )))
    }
}

/// Delete a previously persisted evacuation progress record.
///
/// Called after the evacuation is fully anchored as a completed
/// [`DeviceRemovalRecord`] so the stale progress record does not interfere
/// with future device removals.
pub fn delete_evacuation_progress(
    store: &mut tidefs_local_object_store::LocalObjectStore,
) -> Result<(), DeviceRemovalAnchorError> {
    let key = ObjectKey::from_name(EVACUATION_PROGRESS_KEY);
    store
        .delete(key)
        .map_err(|e| DeviceRemovalAnchorError::StoreWrite(e.to_string()))?;
    store
        .sync()
        .map_err(|e| DeviceRemovalAnchorError::StoreSync(e.to_string()))?;
    Ok(())
}
/// Import a [`PoolConfig`] from labels persisted in a [`LocalObjectStore`].
///
/// Scans for objects with keys matching [`POOL_LABEL_KEY_PREFIX`] by probing
/// device indices 0..64, decodes each label, verifies checksums, and
/// reconstructs the pool configuration.
///
/// Returns `Ok(None)` if no labels are found (unlabeled pool), or an error
/// if label decode/checksum validation fails.
pub fn import_pool_config_from_store(
    store: &tidefs_local_object_store::LocalObjectStore,
) -> Result<Option<PoolConfig>, DeviceRemovalAnchorError> {
    use tidefs_pool_scan::DeviceType;
    use tidefs_types_pool_label_core::{
        decode_label, verify_label_checksum, PoolRedundancyPolicy, PoolState,
    };

    let mut leaves: Vec<DeviceType> = Vec::new();
    let mut ref_uuid: Option<[u8; 16]> = None;
    let mut ref_gen: u64 = 0;
    let mut ref_count: u32 = 0;
    let mut pool_name = String::new();
    let mut pool_state = PoolState::Active;
    let mut feature_flags: u64 = 0;
    let mut redundancy_policy = PoolRedundancyPolicy::default();

    for idx in 0u32..64u32 {
        let label_key = ObjectKey::from_name(format!("{POOL_LABEL_KEY_PREFIX}{idx}"));
        let bytes = match store.get(label_key) {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(e) => {
                return Err(DeviceRemovalAnchorError::StoreWrite(format!(
                    "read label {idx}: {e}"
                )));
            }
        };

        if bytes.len() < tidefs_types_pool_label_core::POOL_LABEL_V1_EXT_WIRE_SIZE {
            continue;
        }

        let decoded = decode_label(&bytes).map_err(|e| {
            DeviceRemovalAnchorError::Serialize(format!("decode label {idx}: {e:?}"))
        })?;

        if !verify_label_checksum(&decoded) {
            return Err(DeviceRemovalAnchorError::Serialize(format!(
                "label checksum invalid for device index {idx}"
            )));
        }

        if ref_uuid.is_none() {
            ref_uuid = Some(decoded.pool_guid);
            ref_gen = decoded.topology_generation;
            ref_count = decoded.device_count;
            pool_name = String::from_utf8_lossy(
                &decoded.pool_name[..decoded.pool_name_len.min(255) as usize],
            )
            .into_owned();
            pool_state = decoded.pool_state;
            feature_flags = decoded.features_compat;
            redundancy_policy = decoded.redundancy_policy;
        } else if decoded.redundancy_policy != redundancy_policy {
            return Err(DeviceRemovalAnchorError::Serialize(format!(
                "label redundancy policy mismatch for device index {idx}"
            )));
        }

        let health = tidefs_pool_scan::DeviceHealth::from_label_health(decoded.device_health);

        leaves.push(DeviceType::Leaf {
            device_path: std::path::PathBuf::from(format!("/dev/disk{idx}")),
            device_guid: decoded.device_guid,
            device_index: idx,
            capacity_bytes: decoded.device_capacity_bytes,
            device_class: decoded.device_class,
            health,
            read_errors: decoded.device_read_errors,
            write_errors: decoded.device_write_errors,
            checksum_errors: decoded.device_checksum_errors,
        });
    }

    let pool_uuid = match ref_uuid {
        Some(u) => u,
        None => return Ok(None),
    };

    leaves.sort_by_key(|l| match l {
        DeviceType::Leaf { device_index, .. } => *device_index,
        _ => 0,
    });

    let device_tree = if leaves.len() == 1 {
        leaves.into_iter().next().unwrap()
    } else {
        DeviceType::PoolWideData { children: leaves }
    };

    let total_capacity = device_tree.total_capacity_bytes();

    Ok(Some(PoolConfig {
        pool_uuid,
        pool_name,
        device_tree,
        health: tidefs_pool_scan::DeviceHealth::Online,
        state: pool_state,
        total_capacity_bytes: total_capacity,
        allocated_bytes: 0,
        feature_flags,
        redundancy_policy,
        topology_generation: ref_gen,
        device_count: ref_count,
        missing_indices: vec![],
        removing_device_indices: vec![],
        completed_evacuations: vec![],
    }))
}

/// Anchor a device removal in a committed root on the target store.
///
/// Writes the removal record as a named object. When `updated_pool_config` is
/// provided, also persists sealed-and-checksummed [`PoolLabelV1`] labels for
/// every surviving device under `tidefs-pool-label-<index>` keys. A final
/// [`LocalObjectStore::sync`] commits all writes in a single commit_group, producing a
/// new committed root.
///
/// The caller must sync surviving stores **before** calling this function so
/// that evacuation data is durable before the removal anchor is written.
/// If the caller's sync here fails, the removal record is not committed.
///
/// The caller is responsible for calling [`PoolConfig::remove_device`] on the
/// config before passing it here so that `device_count`, `topology_generation`,
/// and the device tree reflect the post-removal state.
///
/// # Returns
///
/// `Ok(())` if the record (and optionally labels) were written and synced.
///
/// # Errors
///
/// Returns [`DeviceRemovalAnchorError`] on serialization, write, or sync
/// failure.
pub fn anchor_device_removal(
    store: &mut tidefs_local_object_store::LocalObjectStore,
    plan: &DeviceRemovalPlan,
    result: &DeviceRemovalResult,
    updated_pool_config: Option<&PoolConfig>,
    label_writer: Option<&tidefs_pool_scan::PoolLabelWriter>,
    device_sizes: Option<&std::collections::BTreeMap<u32, u64>>,
) -> Result<(), DeviceRemovalAnchorError> {
    let record = DeviceRemovalRecord::from_plan_and_result(plan, result);

    let payload = record.encode_durable()?;

    let key = ObjectKey::from_name(DEVICE_REMOVAL_RECORD_KEY);

    store
        .put(key, &payload)
        .map_err(|e| DeviceRemovalAnchorError::StoreWrite(e.to_string()))?;

    // Write updated labels to surviving raw block devices
    // so pool import discovers the post-removal topology.
    if let Some(writer) = label_writer {
        writer
            .write_pool_labels(
                updated_pool_config.ok_or_else(|| {
                    DeviceRemovalAnchorError::StoreWrite(
                        "label_writer provided without updated_pool_config".into(),
                    )
                })?,
                device_sizes,
            )
            .map_err(|e| {
                DeviceRemovalAnchorError::StoreWrite(format!(
                    "write updated labels to surviving devices: {e}"
                ))
            })?;
    }

    if let Some(config) = updated_pool_config {
        persist_updated_labels(store, config)?;
    }

    store
        .sync()
        .map_err(|e| DeviceRemovalAnchorError::StoreSync(e.to_string()))?;

    Ok(())
}

/// Persist sealed PoolLabelV1 records for every device in the config.
///
/// Each label is sealed (checksum computed via BLAKE3), encoded to wire
/// format, and stored under `tidefs-pool-label-<device-index>`.
pub fn persist_updated_labels(
    store: &mut tidefs_local_object_store::LocalObjectStore,
    config: &PoolConfig,
) -> Result<(), DeviceRemovalAnchorError> {
    let labels = config.to_labels();
    for (i, label) in labels.iter().enumerate() {
        let sealed = seal_label(label.clone())
            .map_err(|e| DeviceRemovalAnchorError::Serialize(format!("seal label {i}: {e}")))?;
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf)
            .map_err(|e| DeviceRemovalAnchorError::Serialize(format!("encode label {i}: {e}")))?;
        let key = ObjectKey::from_name(format!("{POOL_LABEL_KEY_PREFIX}{}", label.device_index));
        store
            .put(key, &buf)
            .map_err(|e| DeviceRemovalAnchorError::StoreWrite(format!("label {i}: {e}")))?;
    }
    Ok(())
}

/// Write updated pool labels to surviving raw block devices after
/// a device removal.
///
/// This function maps the updated [`PoolConfig`] to per-device
/// [`PoolLabelV1`] records, seals each with a BLAKE3 checksum, and
/// writes them at both primary (offset 0) and backup (end-of-device)
/// locations on each surviving device.
///
/// Should be called after [`PoolConfig::remove_device`] and before
/// [`anchor_device_removal`] so that import-visible device labels
/// reflect the post-removal topology, device count, and topology
/// generation.
///
/// When `device_sizes` is provided, each entry maps
/// `device_index -> size_bytes` and is used for backup-offset
/// computation.  When `None`, backup labels are written only if a
/// fixed `label1_offset` was configured on the writer.
pub fn write_updated_labels_to_devices(
    writer: &tidefs_pool_scan::PoolLabelWriter,
    config: &tidefs_pool_scan::PoolConfig,
    device_sizes: Option<&std::collections::BTreeMap<u32, u64>>,
) -> Result<(), tidefs_pool_scan::LabelWriteError> {
    writer.write_pool_labels(config, device_sizes)
}

/// Errors that can occur during device removal anchoring.
#[derive(Clone, Debug, thiserror::Error)]
pub enum DeviceRemovalAnchorError {
    /// Failed to encode or decode a durable removal/progress record.
    #[error("failed to encode or decode device removal record: {0}")]
    Serialize(String),

    /// Failed to write the removal record to the store.
    #[error("failed to write device removal record to store: {0}")]
    StoreWrite(String),

    /// Failed to sync the store (commit commit_group) after writing the record.
    #[error("failed to sync store for device removal: {0}")]
    StoreSync(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_pool_scan::{DeviceHealth, DeviceType};
    use tidefs_types_pool_label_core::{DeviceClass, PoolState};

    #[test]
    fn anchor_persists_labels_for_surviving_devices() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = tidefs_local_object_store::LocalObjectStore::open(dir.path()).unwrap();

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
            device_path: std::path::PathBuf::from("/dev/disk1"),
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
            device_path: std::path::PathBuf::from("/dev/disk2"),
            device_guid: [0x03u8; 16],
            device_index: 2,
            capacity_bytes: 1024 * 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };

        let mut config = PoolConfig {
            pool_uuid: [0x42u8; 16],
            pool_name: "testpool".to_string(),
            device_tree: DeviceType::PoolWideData {
                children: vec![leaf0, leaf1.clone(), leaf2],
            },
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 3 * 1024 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 3,
            missing_indices: vec![],
            removing_device_indices: vec![],
            completed_evacuations: vec![],
        };

        // Remove disk1 (index 1).
        config
            .remove_device(std::path::Path::new("/dev/disk1"))
            .unwrap();
        assert_eq!(config.device_count, 2);
        assert_eq!(config.topology_generation, 2);

        let plan = DeviceRemovalPlan {
            target_device: std::path::PathBuf::from("/dev/disk1"),
            target_device_guid: [0x02u8; 16],
            target_device_index: 1,
            surviving_devices: vec![
                std::path::PathBuf::from("/dev/disk0"),
                std::path::PathBuf::from("/dev/disk2"),
            ],
            device_count_before: 3,
            device_count_after: 2,
            objects_to_evacuate: vec![],
            total_evacuation_bytes: 0,
            object_count: 0,
            evacuation_outcome: tidefs_pool_scan::EvacuationPlanOutcome::EmptySuccess,
            topology_generation: 2,
            replication_intent: tidefs_replication_model::ReplicationIntent::new_mirror(
                2,
                tidefs_replication_model::FailureDomain::Device,
            )
            .unwrap(),
            plan_validated: true,
        };
        let result = DeviceRemovalResult {
            objects_evacuated: 0,
            bytes_evacuated: 0,
            objects_failed: 0,
            removed_device: std::path::PathBuf::from("/dev/disk1"),
            surviving_devices: vec![
                std::path::PathBuf::from("/dev/disk0"),
                std::path::PathBuf::from("/dev/disk2"),
            ],
            topology_generation: 2,
            committed_root_anchored: true,
        };

        anchor_device_removal(&mut store, &plan, &result, Some(&config), None, None).unwrap();

        // Verify the removal record was persisted.
        let record_key = ObjectKey::from_name(DEVICE_REMOVAL_RECORD_KEY);
        let record_bytes = store.get(record_key).unwrap().unwrap();
        let record = DeviceRemovalRecord::decode_durable(&record_bytes).unwrap();
        assert_eq!(
            record.removed_device,
            std::path::PathBuf::from("/dev/disk1")
        );
        assert_eq!(record.device_count_before, 3);
        assert_eq!(record.device_count_after, 2);
        assert!(record.removal_complete);

        // Verify surviving device labels were persisted with checksums.
        for idx in [0u32, 2u32] {
            let label_key = ObjectKey::from_name(format!("{POOL_LABEL_KEY_PREFIX}{idx}"));
            let label_bytes = store.get(label_key).unwrap().unwrap();
            assert_eq!(label_bytes.len(), POOL_LABEL_V1_EXT_WIRE_SIZE);

            let decoded = tidefs_types_pool_label_core::decode_label(&label_bytes).unwrap();
            assert_eq!(decoded.pool_guid, [0x42u8; 16]);
            assert_eq!(decoded.device_count, 2);
            assert_eq!(decoded.topology_generation, 2);
            assert_eq!(decoded.device_index, idx);

            // Checksum must be valid.
            assert!(
                tidefs_types_pool_label_core::verify_label_checksum(&decoded),
                "label checksum invalid for device index {idx}"
            );
        }

        // No label for the removed device (index 1).
        let removed_key = ObjectKey::from_name(format!("{POOL_LABEL_KEY_PREFIX}1"));
        assert!(store.get(removed_key).unwrap().is_none());
    }

    #[test]
    fn anchor_without_config_skips_labels() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = tidefs_local_object_store::LocalObjectStore::open(dir.path()).unwrap();

        let plan = DeviceRemovalPlan {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0x01u8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            objects_to_evacuate: vec![],
            total_evacuation_bytes: 0,
            object_count: 0,
            evacuation_outcome: tidefs_pool_scan::EvacuationPlanOutcome::EmptySuccess,
            topology_generation: 1,
            replication_intent: tidefs_replication_model::ReplicationIntent::new_mirror(
                2,
                tidefs_replication_model::FailureDomain::Device,
            )
            .unwrap(),
            plan_validated: false,
        };
        let result = DeviceRemovalResult {
            objects_evacuated: 0,
            bytes_evacuated: 0,
            objects_failed: 0,
            removed_device: std::path::PathBuf::from("/dev/disk0"),
            surviving_devices: vec![],
            topology_generation: 1,
            committed_root_anchored: false,
        };

        // Pass None for config — should still succeed without labels.
        anchor_device_removal(&mut store, &plan, &result, None, None, None).unwrap();

        let record_key = ObjectKey::from_name(DEVICE_REMOVAL_RECORD_KEY);
        assert!(store.get(record_key).unwrap().is_some());
    }

    #[test]
    fn device_removal_record_durable_codec_roundtrip() {
        let record = DeviceRemovalRecord {
            removed_device: std::path::PathBuf::from("/dev/disk1"),
            device_guid: [0x11u8; 16],
            device_index: 1,
            surviving_devices: vec![
                std::path::PathBuf::from("/dev/disk0"),
                std::path::PathBuf::from("/dev/disk2"),
            ],
            device_count_before: 3,
            device_count_after: 2,
            objects_evacuated: 7,
            bytes_evacuated: 4096,
            objects_failed: 0,
            topology_generation: 9,
            removal_complete: true,
        };

        let encoded = record.encode_durable().expect("encode");
        let decoded = DeviceRemovalRecord::decode_durable(&encoded).expect("decode");
        assert_eq!(decoded.removed_device, record.removed_device);
        assert_eq!(decoded.device_guid, record.device_guid);
        assert_eq!(decoded.device_index, record.device_index);
        assert_eq!(decoded.surviving_devices, record.surviving_devices);
        assert_eq!(decoded.objects_evacuated, record.objects_evacuated);
        assert_eq!(decoded.bytes_evacuated, record.bytes_evacuated);
        assert!(decoded.removal_complete);
    }

    #[test]
    fn device_removal_record_rejects_unknown_version() {
        let record = DeviceRemovalRecord {
            removed_device: std::path::PathBuf::from("/dev/disk1"),
            device_guid: [0x11u8; 16],
            device_index: 1,
            surviving_devices: vec![std::path::PathBuf::from("/dev/disk0")],
            device_count_before: 2,
            device_count_after: 1,
            objects_evacuated: 1,
            bytes_evacuated: 512,
            objects_failed: 0,
            topology_generation: 3,
            removal_complete: true,
        };

        let mut encoded = record.encode_durable().expect("encode");
        encoded[8..10].copy_from_slice(&2u16.to_le_bytes());
        let err = DeviceRemovalRecord::decode_durable(&encoded).unwrap_err();
        assert!(
            err.to_string().contains("version"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn device_removal_record_rejects_truncated_input() {
        let record = DeviceRemovalRecord {
            removed_device: std::path::PathBuf::from("/dev/disk1"),
            device_guid: [0x11u8; 16],
            device_index: 1,
            surviving_devices: vec![std::path::PathBuf::from("/dev/disk0")],
            device_count_before: 2,
            device_count_after: 1,
            objects_evacuated: 1,
            bytes_evacuated: 512,
            objects_failed: 0,
            topology_generation: 3,
            removal_complete: true,
        };

        let mut encoded = record.encode_durable().expect("encode");
        encoded.pop();
        let err = DeviceRemovalRecord::decode_durable(&encoded).unwrap_err();
        assert!(
            err.to_string().contains("truncated"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn device_removal_record_rejects_corrupt_bool_field() {
        let record = DeviceRemovalRecord {
            removed_device: std::path::PathBuf::from("/dev/disk1"),
            device_guid: [0x11u8; 16],
            device_index: 1,
            surviving_devices: vec![std::path::PathBuf::from("/dev/disk0")],
            device_count_before: 2,
            device_count_after: 1,
            objects_evacuated: 1,
            bytes_evacuated: 512,
            objects_failed: 0,
            topology_generation: 3,
            removal_complete: true,
        };

        let mut encoded = record.encode_durable().expect("encode");
        *encoded.last_mut().expect("bool byte") = 7;
        let err = DeviceRemovalRecord::decode_durable(&encoded).unwrap_err();
        assert!(
            err.to_string().contains("boolean"),
            "unexpected error: {err}"
        );
    }

    // ── EvacuationProgressRecord tests ──────────────────────────────

    #[test]
    fn evacuation_progress_record_new_starts_at_zero() {
        let progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0x42u8; 16],
            target_device_index: 0,
            surviving_devices: vec![std::path::PathBuf::from("/dev/disk1")],
            device_count_before: 3,
            device_count_after: 2,
            topology_generation: 5,
            total_objects: 100,
        });
        assert_eq!(progress.next_object_index, 0);
        assert_eq!(progress.total_objects, 100);
        assert_eq!(progress.objects_evacuated, 0);
        assert_eq!(progress.bytes_evacuated, 0);
        assert_eq!(progress.objects_failed, 0);
        assert!(progress.evacuated_object_ids.is_empty());
        assert!(progress.failed_object_ids.is_empty());
        assert_eq!(progress.remaining(), 100);
        assert!(!progress.is_complete());
    }

    #[test]
    fn evacuation_progress_record_evacuated_updates_counts() {
        let mut progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0x42u8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            topology_generation: 1,
            total_objects: 10,
        });
        progress.record_evacuated(0, 512);
        assert_eq!(progress.next_object_index, 1);
        assert_eq!(progress.objects_evacuated, 1);
        assert_eq!(progress.bytes_evacuated, 512);
        assert_eq!(progress.remaining(), 9);
        assert!(!progress.is_complete());
        assert_eq!(progress.evacuated_object_ids, vec![0]);
    }

    #[test]
    fn evacuation_progress_record_failed_updates_counts() {
        let mut progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0x42u8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            topology_generation: 1,
            total_objects: 10,
        });
        progress.record_failed(0);
        assert_eq!(progress.next_object_index, 1);
        assert_eq!(progress.objects_failed, 1);
        assert_eq!(progress.remaining(), 9);
        assert!(!progress.is_complete());
        assert_eq!(progress.failed_object_ids, vec![0]);
    }

    #[test]
    fn evacuation_progress_is_complete_when_all_processed() {
        let mut progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0x42u8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            topology_generation: 1,
            total_objects: 3,
        });
        progress.record_evacuated(0, 100);
        progress.record_evacuated(1, 200);
        progress.record_failed(2);
        assert!(progress.is_complete());
        assert_eq!(progress.remaining(), 0);
    }

    #[test]
    fn processed_object_ids_includes_both_evacuated_and_failed() {
        let mut progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0x42u8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            topology_generation: 1,
            total_objects: 10,
        });
        progress.record_evacuated(1, 100);
        progress.record_evacuated(3, 200);
        progress.record_failed(5);
        progress.record_failed(7);

        let processed = progress.processed_object_ids();
        assert_eq!(processed.len(), 4);
        assert!(processed.contains(&1));
        assert!(processed.contains(&3));
        assert!(processed.contains(&5));
        assert!(processed.contains(&7));
        // Unprocessed IDs are not in the set.
        assert!(!processed.contains(&0));
        assert!(!processed.contains(&2));
    }

    // ── Persist / load / resume tests ──────────────────────────────

    #[test]
    fn persist_and_load_evacuation_progress_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = tidefs_local_object_store::LocalObjectStore::open(dir.path()).unwrap();

        let progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0xABu8; 16],
            target_device_index: 1,
            surviving_devices: vec![std::path::PathBuf::from("/dev/disk2")],
            device_count_before: 3,
            device_count_after: 2,
            topology_generation: 7,
            total_objects: 50,
        });

        persist_evacuation_progress(&mut store, &progress).unwrap();

        let loaded = load_evacuation_progress(&store).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.target_device, progress.target_device);
        assert_eq!(loaded.target_device_guid, progress.target_device_guid);
        assert_eq!(loaded.target_device_index, progress.target_device_index);
        assert_eq!(loaded.device_count_before, progress.device_count_before);
        assert_eq!(loaded.total_objects, progress.total_objects);
        assert_eq!(loaded.topology_generation, progress.topology_generation);
    }

    #[test]
    fn evacuation_progress_durable_codec_roundtrip() {
        let mut progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0xABu8; 16],
            target_device_index: 0,
            surviving_devices: vec![std::path::PathBuf::from("/dev/disk1")],
            device_count_before: 2,
            device_count_after: 1,
            topology_generation: 7,
            total_objects: 3,
        });
        progress.record_evacuated(10, 1024);
        progress.record_failed(12);

        let encoded = progress.encode_durable().expect("encode");
        let decoded = EvacuationProgressRecord::decode_durable(&encoded).expect("decode");
        assert_eq!(decoded.target_device, progress.target_device);
        assert_eq!(decoded.target_device_guid, progress.target_device_guid);
        assert_eq!(decoded.next_object_index, progress.next_object_index);
        assert_eq!(decoded.objects_evacuated, progress.objects_evacuated);
        assert_eq!(decoded.failed_object_ids, progress.failed_object_ids);
    }

    #[test]
    fn evacuation_progress_rejects_unknown_version() {
        let progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0xABu8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            topology_generation: 7,
            total_objects: 0,
        });

        let mut encoded = progress.encode_durable().expect("encode");
        encoded[8..10].copy_from_slice(&2u16.to_le_bytes());
        let err = EvacuationProgressRecord::decode_durable(&encoded).unwrap_err();
        assert!(
            err.to_string().contains("version"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn evacuation_progress_rejects_truncated_input() {
        let progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0xABu8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            topology_generation: 7,
            total_objects: 0,
        });

        let mut encoded = progress.encode_durable().expect("encode");
        encoded.truncate(encoded.len() - 3);
        let err = EvacuationProgressRecord::decode_durable(&encoded).unwrap_err();
        assert!(
            err.to_string().contains("truncated"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn evacuation_progress_rejects_corrupt_counter_fields() {
        let mut progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("x"),
            target_device_guid: [0xABu8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            topology_generation: 7,
            total_objects: 0,
        });
        progress.objects_evacuated = 1;

        let err = progress.encode_durable().unwrap_err();
        assert!(
            err.to_string().contains("objects_evacuated"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_evacuation_progress_returns_none_when_no_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = tidefs_local_object_store::LocalObjectStore::open(dir.path()).unwrap();

        let loaded = load_evacuation_progress(&store).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn load_evacuation_progress_rejects_malformed_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = tidefs_local_object_store::LocalObjectStore::open(dir.path()).unwrap();
        let key = ObjectKey::from_name(EVACUATION_PROGRESS_KEY);
        store.put(key, b"not-a-durable-record").unwrap();
        store.sync().unwrap();

        let err = load_evacuation_progress(&store).unwrap_err();
        assert!(err.to_string().contains("magic"), "unexpected error: {err}");
    }

    #[test]
    fn resume_evacuation_from_progress_filters_processed_ids() {
        let mut progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0x42u8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            topology_generation: 1,
            total_objects: 100,
        });
        // Evacuated: 1, 3; Failed: 5.
        progress.record_evacuated(1, 100);
        progress.record_evacuated(3, 200);
        progress.record_failed(5);

        let all_ids = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let remaining = resume_evacuation_from_progress(&all_ids, &progress);

        // Should exclude 1, 3, 5.
        assert_eq!(remaining, vec![0, 2, 4, 6, 7, 8, 9]);
        assert_eq!(remaining.len(), 7);
    }

    #[test]
    fn resume_evacuation_with_empty_progress_returns_all_ids() {
        let progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0x42u8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            topology_generation: 1,
            total_objects: 100,
        });
        let all_ids = vec![10, 20, 30];
        let remaining = resume_evacuation_from_progress(&all_ids, &progress);
        assert_eq!(remaining, vec![10, 20, 30]);
    }

    // ── verify_device_emptiness_after_evacuation tests ─────────────

    #[test]
    fn verify_device_emptiness_empty_store_passes() {
        let dir = tempfile::tempdir().unwrap();
        let store = tidefs_local_object_store::LocalObjectStore::open(dir.path()).unwrap();
        let result = verify_device_emptiness_after_evacuation(&store);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_device_emptiness_with_data_objects_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = tidefs_local_object_store::LocalObjectStore::open(dir.path()).unwrap();

        // Put a data object.
        let key = ObjectKey::from_name("my-data-object");
        store.put(key, &vec![42u8; 256]).unwrap();
        store.sync().unwrap();

        let result = verify_device_emptiness_after_evacuation(&store);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("data objects after evacuation"));
    }

    #[test]
    fn verify_device_emptiness_ignores_label_and_record_keys() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = tidefs_local_object_store::LocalObjectStore::open(dir.path()).unwrap();

        // Write label and record keys (should be ignored).
        let label_key = ObjectKey::from_name("tidefs-pool-label-0");
        store.put(label_key, &vec![0u8; 1024]).unwrap();

        let record_key = ObjectKey::from_name(DEVICE_REMOVAL_RECORD_KEY);
        let record = DeviceRemovalRecord {
            removed_device: std::path::PathBuf::from("/dev/disk0"),
            device_guid: [0x01u8; 16],
            device_index: 0,
            surviving_devices: vec![std::path::PathBuf::from("/dev/disk1")],
            device_count_before: 2,
            device_count_after: 1,
            objects_evacuated: 0,
            bytes_evacuated: 0,
            objects_failed: 0,
            topology_generation: 2,
            removal_complete: true,
        };
        store
            .put(record_key, &record.encode_durable().unwrap())
            .unwrap();

        let progress_key = ObjectKey::from_name(EVACUATION_PROGRESS_KEY);
        let progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0x01u8; 16],
            target_device_index: 0,
            surviving_devices: vec![std::path::PathBuf::from("/dev/disk1")],
            device_count_before: 2,
            device_count_after: 1,
            topology_generation: 2,
            total_objects: 0,
        });
        store
            .put(progress_key, &progress.encode_durable().unwrap())
            .unwrap();

        store.sync().unwrap();

        // Store has label/record/progress keys only → should pass.
        let result = verify_device_emptiness_after_evacuation(&store);
        assert!(result.is_ok());
    }

    // ── delete_evacuation_progress tests ───────────────────────────

    #[test]
    fn delete_evacuation_progress_removes_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = tidefs_local_object_store::LocalObjectStore::open(dir.path()).unwrap();

        let progress = EvacuationProgressRecord::new(EvacuationProgressInit {
            target_device: std::path::PathBuf::from("/dev/disk0"),
            target_device_guid: [0x42u8; 16],
            target_device_index: 0,
            surviving_devices: vec![],
            device_count_before: 1,
            device_count_after: 0,
            topology_generation: 1,
            total_objects: 10,
        });
        persist_evacuation_progress(&mut store, &progress).unwrap();

        // Verify it exists.
        assert!(load_evacuation_progress(&store).unwrap().is_some());

        // Delete it.
        delete_evacuation_progress(&mut store).unwrap();

        // Verify it's gone.
        assert!(load_evacuation_progress(&store).unwrap().is_none());
    }
}

/// Prove that importing pool labels and calling remove_device preserves
/// every pool-authoritative field: pool UUID, pool name, feature flags,
/// device GUIDs, and surviving device indices.  Topology generation and
/// device count are updated by remove_device, not fabricated.
///
/// This test is the source guard for the authority map: a regression
/// here would mean the import or remove_device path fabricates config
/// instead of deriving it from authoritative labels.
#[test]
fn imported_config_preserves_authoritative_fields_through_remove_device() {
    use tidefs_pool_scan::{DeviceHealth, DeviceType, PoolConfig};
    use tidefs_types_pool_label_core::{features, DeviceClass, PoolState};

    let dir = tempfile::tempdir().unwrap();
    let mut store = tidefs_local_object_store::LocalObjectStore::open(dir.path()).unwrap();

    let pool_uuid = [0x7Fu8; 16];
    let pool_name = "auth-test-pool".to_string();
    let feature_flags = 0xFEED & !features::DEVICE_LAYOUT_V1;

    let leaf0 = DeviceType::Leaf {
        device_path: std::path::PathBuf::from("/dev/disk0"),
        device_guid: [0xA1u8; 16],
        device_index: 0,
        capacity_bytes: 1024 * 1024 * 1024,
        device_class: DeviceClass::Hdd,
        health: DeviceHealth::Online,
        read_errors: 0,
        write_errors: 0,
        checksum_errors: 0,
    };
    let leaf1 = DeviceType::Leaf {
        device_path: std::path::PathBuf::from("/dev/disk1"),
        device_guid: [0xA2u8; 16],
        device_index: 1,
        capacity_bytes: 1024 * 1024 * 1024,
        device_class: DeviceClass::Ssd,
        health: DeviceHealth::Online,
        read_errors: 0,
        write_errors: 0,
        checksum_errors: 0,
    };
    let leaf2 = DeviceType::Leaf {
        device_path: std::path::PathBuf::from("/dev/disk2"),
        device_guid: [0xA3u8; 16],
        device_index: 2,
        capacity_bytes: 1024 * 1024 * 1024,
        device_class: DeviceClass::Nvme,
        health: DeviceHealth::Online,
        read_errors: 0,
        write_errors: 0,
        checksum_errors: 0,
    };
    let pre_config = PoolConfig {
        pool_uuid,
        pool_name: pool_name.clone(),
        device_tree: DeviceType::Mirror {
            children: vec![leaf0.clone(), leaf1.clone(), leaf2.clone()],
        },
        redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
        health: DeviceHealth::Online,
        state: PoolState::Active,
        total_capacity_bytes: 3 * 1024 * 1024 * 1024,
        allocated_bytes: 0,
        feature_flags,
        topology_generation: 5,
        device_count: 3,
        missing_indices: vec![],
        removing_device_indices: vec![],
        completed_evacuations: vec![],
    };

    // Persist original labels into the store.
    persist_updated_labels(&mut store, &pre_config).unwrap();
    store.sync().unwrap();

    // Import and verify every authoritative field.
    let imported = import_pool_config_from_store(&store)
        .unwrap()
        .expect("labels should be imported");

    assert_eq!(
        imported.pool_uuid, pool_uuid,
        "pool UUID must survive import"
    );
    assert_eq!(
        imported.pool_name, pool_name,
        "pool name must survive import"
    );
    assert_eq!(
        imported.feature_flags, feature_flags,
        "feature flags must survive import"
    );
    assert_eq!(
        imported.topology_generation, 5,
        "topology generation must survive import"
    );
    assert_eq!(imported.device_count, 3, "device count must survive import");
    assert_eq!(
        imported.state,
        PoolState::Active,
        "pool state must survive import"
    );
    assert!(imported.missing_indices.is_empty());

    // Verify each device's GUID and index survived.
    let leaves = tidefs_pool_scan::DeviceRemovalPlanner::flatten_leaves(&imported.device_tree);
    assert_eq!(leaves.len(), 3);
    assert_eq!(leaves[0].device_guid, [0xA1u8; 16]);
    assert_eq!(leaves[1].device_guid, [0xA2u8; 16]);
    assert_eq!(leaves[2].device_guid, [0xA3u8; 16]);
    assert_eq!(leaves[0].device_index, 0);
    assert_eq!(leaves[1].device_index, 1);
    assert_eq!(leaves[2].device_index, 2);

    // Remove device at index 2 via PoolConfig::remove_device.
    let mut post_config = imported.clone();
    post_config
        .remove_device(std::path::Path::new("/dev/disk2"))
        .unwrap();

    // Pool UUID, name, and feature flags must be unchanged.
    assert_eq!(
        post_config.pool_uuid, pool_uuid,
        "pool UUID must survive remove_device"
    );
    assert_eq!(
        post_config.pool_name, pool_name,
        "pool name must survive remove_device"
    );
    assert_eq!(
        post_config.feature_flags, feature_flags,
        "feature flags must survive remove_device"
    );

    // Topology generation must be bumped, not fabricated.
    assert_eq!(
        post_config.topology_generation, 6,
        "topology generation must be bumped by exactly 1"
    );

    // Device count must be decremented, not fabricated.
    assert_eq!(
        post_config.device_count, 2,
        "device count must be decremented by exactly 1"
    );

    // Remaining leaves must be the survivors.
    let post_leaves =
        tidefs_pool_scan::DeviceRemovalPlanner::flatten_leaves(&post_config.device_tree);
    assert_eq!(post_leaves.len(), 2);
    assert_eq!(post_leaves[0].device_guid, [0xA1u8; 16]);
    assert_eq!(post_leaves[1].device_guid, [0xA2u8; 16]);

    // Persist post-removal labels and re-import from a fresh store.
    let dir2 = tempfile::tempdir().unwrap();
    let mut store2 = tidefs_local_object_store::LocalObjectStore::open(dir2.path()).unwrap();
    persist_updated_labels(&mut store2, &post_config).unwrap();
    store2.sync().unwrap();

    let reimported = import_pool_config_from_store(&store2)
        .unwrap()
        .expect("post-removal labels should be importable");

    assert_eq!(reimported.pool_uuid, pool_uuid);
    assert_eq!(reimported.device_count, 2);
    assert_eq!(reimported.topology_generation, 6);
    let re_leaves = tidefs_pool_scan::DeviceRemovalPlanner::flatten_leaves(&reimported.device_tree);
    assert_eq!(re_leaves.len(), 2);
    // Removed device (index 2, GUID A3) must not be present.
    let indices: Vec<u32> = re_leaves.iter().map(|l| l.device_index).collect();
    assert_eq!(indices, vec![0, 1]);
    let guids: Vec<[u8; 16]> = re_leaves.iter().map(|l| l.device_guid).collect();
    assert!(
        !guids.contains(&[0xA3u8; 16]),
        "removed device GUID must not appear in re-imported config"
    );
}
