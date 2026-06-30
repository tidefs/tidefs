// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool import: device activation, superblock verification, intent log
//! replay, dataset mount readiness, and pool activation.
//!
//! Builds on the device scan and pool assembly code in `tidefs-pool-scan`.
//! Pool import/export behavior is summarized by
//! [`docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`].

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use tidefs_local_object_store::device_layout::decode_device_layout_v1;
use tidefs_pool_scan::{DeviceType, PoolConfig};

use tidefs_intent_log::{
    replay::{IntentReplayEngine, IntentReplayHandler, SegmentReplayOutcome},
    IntentLogRecord,
};

mod committed_root;
pub mod create;
use committed_root::{recover_committed_root_from_file, CommittedRoot, CommittedRootError};
#[cfg(test)]
use tidefs_encryption::StoreKey;

// ---------------------------------------------------------------------------
// ── Device layout constants for intent-log replay ──────────────────

/// Offset from the start of the device where the data region begins
/// (after the pool label, commit-record region, and system area).
const DATA_REGION_OFFSET: u64 = 270336; // COMMIT_RECORD_REGION_OFFSET + COMMIT_RECORD_REGION_MAX

/// Index of the VRBT block within the system area (block 3, 4096-byte blocks).
const VRBT_BLOCK_INDEX: u32 = 3;

/// Wire size of the VRBT committed-root block (88 bytes).
const VRBT_WIRE_SIZE: usize = 88;

/// Minimum size of the system area needed to contain a VRBT block.
const VRBT_BLOCK_AREA_SIZE: u64 = (VRBT_BLOCK_INDEX as u64 + 1) * 4096;

/// VRBT magic bytes.
const VRBT_MAGIC: [u8; 4] = *b"VRBT";

/// VRBT header size (bytes 0..56, everything except the BLAKE3 hash).
const VRBT_HEADER_SIZE: usize = 56;

/// VRBT hash offset (bytes 56..88).
const VRBT_HASH_OFFSET: usize = 56;

// ── VrbtParsed ──────────────────────────────────────────────────────

/// Parsed VRBT committed-root block fields used by intent-log replay.
pub struct VrbtParsed {
    /// Commit-group ID at which this root was committed.
    pub committed_txg: u64,
    /// Opaque handle to the namespace root.
    pub namespace_root: u64,
    /// Opaque handle to the inode-table root.
    pub inode_table_root: u64,
    /// Opaque handle to the extent-map root.
    pub extent_map_root: u64,
    /// Byte offset within the data region where intent-log records begin.
    pub intent_log_head: u64,
    /// Total number of intent-log bytes in the data region.
    pub intent_log_tail: u64,
}

// ImportError
// ---------------------------------------------------------------------------

/// Errors that can occur during pool import.
#[derive(Debug)]
pub enum ImportError {
    /// A device path in the pool configuration does not exist or cannot
    /// be opened.
    DeviceOpen {
        /// Device path that failed to open.
        device_path: PathBuf,
        /// OS-level error message.
        msg: String,
    },
    /// Superblocks on different devices disagree on critical fields.
    SuperblockDisagreement {
        /// What field disagreed.
        field: String,
        /// Values found across devices.
        values: Vec<String>,
    },
    /// The pool state in the superblock does not permit import.
    BadPoolState {
        /// The pool state found.
        state: String,
    },
    /// One or more devices required by the topology are missing or
    /// faulted beyond the redundancy tolerance.
    UnavailableDevices {
        /// Indices of missing or faulted devices.
        missing: Vec<u32>,
    },
    /// An I/O error occurred during import.
    Io {
        /// Device path, if known.
        device_path: Option<PathBuf>,
        /// Error description.
        msg: String,
    },
    /// Another importer has already claimed this pool (import mutex).
    AlreadyImported {
        /// Pool UUID.
        pool_uuid: [u8; 16],
    },
    /// Feature flags in the label require a newer or different importer.
    IncompatibleFeatures {
        /// Bitmask of unsupported feature bits.
        unsupported: u64,
    },
    /// The intent log could not be replayed.
    IntentLogReplay {
        /// Error description.
        msg: String,
    },
    /// Pool assembly (label scanning or reconstruction) failed.
    Assembly {
        /// Error description.
        msg: String,
    },
    /// Committed-root recovery failed: the commit-record region is
    /// missing, truncated, or BLAKE3-verification failed.
    CommittedRootRecovery {
        /// Description of the recovery failure.
        msg: String,
    },
    /// A device removal is in progress and must be completed
    /// before the pool can be fully used.
    DeviceRemovalInProgress {
        /// Index of the device being removed.
        removing_device_index: u32,
    },
    /// The committed root could not be found on any device.
    CommittedRootNotFound,
    /// The recovered committed root is stale (epoch below the
    /// minimum acceptable epoch).  This prevents importing a pool
    /// whose committed root is behind the cluster's known epoch
    /// (split-brain prevention gate).
    StaleRoot {
        /// Epoch of the recovered committed root.
        recovered_epoch: u64,
        /// Minimum acceptable epoch for import.
        min_epoch: u64,
    },
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceOpen { device_path, msg } => {
                write!(f, "failed to open device {}: {msg}", device_path.display())
            }
            Self::SuperblockDisagreement { field, values } => {
                write!(f, "superblock disagreement on {field}: ")?;
                for (i, v) in values.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(v)?;
                }
                Ok(())
            }
            Self::BadPoolState { state } => {
                write!(f, "pool state {state} does not permit import")
            }
            Self::UnavailableDevices { missing } => {
                write!(f, "required devices unavailable: indices {missing:?}")
            }
            Self::Io { device_path, msg } => {
                if let Some(p) = device_path {
                    write!(f, "I/O error on {}: {msg}", p.display())
                } else {
                    write!(f, "I/O error: {msg}")
                }
            }
            Self::AlreadyImported { pool_uuid } => {
                write!(f, "pool {pool_uuid:02x?} is already imported")
            }
            Self::IncompatibleFeatures { unsupported } => {
                write!(
                    f,
                    "unsupported feature flags 0x{unsupported:016x} require a different importer"
                )
            }
            Self::IntentLogReplay { msg } => {
                write!(f, "intent log replay failed: {msg}")
            }
            Self::Assembly { msg } => {
                write!(f, "pool assembly failed: {msg}")
            }
            Self::CommittedRootRecovery { msg } => {
                write!(f, "committed-root recovery failed: {msg}")
            }
            Self::DeviceRemovalInProgress {
                removing_device_index,
            } => {
                write!(
                    f,
                    "device removal in progress for device index {removing_device_index}"
                )
            }
            Self::CommittedRootNotFound => {
                write!(f, "no committed root found on any device")
            }
            Self::StaleRoot {
                recovered_epoch,
                min_epoch,
            } => {
                write!(
                    f,
                    "stale committed root: recovered epoch {recovered_epoch} is below min epoch {min_epoch}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PoolImportStats
// ---------------------------------------------------------------------------

/// Statistics gathered during a pool import.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PoolImportStats {
    /// Number of leaf devices successfully opened.
    pub devices_opened: usize,
    /// Whether the superblock was verified consistent across all devices.
    pub superblock_verified: bool,
    /// Number of intent log records replayed.
    pub intent_log_replayed: u64,
    /// Number of datasets made available for mount.
    pub datasets_available: usize,
    /// Wall-clock import duration in milliseconds.
    pub import_time_ms: u64,
    /// Whether the import was read-only.
    pub read_only: bool,
    /// Whether the pool uses per-object encryption at rest.
    pub encrypted: bool,
    /// Whether a device removal is in progress.
    pub removal_in_progress: bool,
    /// Hex key fingerprint (first 8 bytes of BLAKE3 keyed hash) for
    /// operator verification.  `None` when the pool is unencrypted
    /// or no key was provided at import time.
    pub key_fingerprint: Option<String>,
    /// Committed-root epoch number recovered during import.
    /// `None` when no committed root was found (fresh pool).
    pub committed_root_epoch: Option<u64>,
}

// ---------------------------------------------------------------------------
// ImportedPool — the result of a successful import
// ---------------------------------------------------------------------------

/// The result of a successful pool import, holding the reconstructed
/// configuration and import statistics.
#[derive(Clone, Debug)]
pub struct ImportedPool {
    /// The pool configuration reconstructed from on-device labels.
    pub config: PoolConfig,
    /// Statistics gathered during the import.
    pub stats: PoolImportStats,
}

// ---------------------------------------------------------------------------
// LabelAgreementReport — bounded member-label authority evidence
// ---------------------------------------------------------------------------

/// Bounded label-agreement evidence gathered before replay or mount readiness.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LabelAgreementReport {
    /// One entry per candidate member device supplied for import.
    members: Vec<LabelAgreementMember>,
}

/// Import-critical authority read from one candidate member label.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LabelAgreementMember {
    /// Device path the evidence was read from.
    device_path: PathBuf,
    /// Pool UUID recorded in the label.
    pool_uuid: [u8; 16],
    /// Member UUID recorded in the label.
    member_uuid: [u8; 16],
    /// Device index recorded in the label.
    device_index: u32,
    /// Device capacity recorded in the label.
    device_capacity_bytes: u64,
    /// Topology generation recorded in the label.
    topology_generation: u64,
    /// Pool member count recorded in the label.
    device_count: u32,
    /// Committed txg recorded in the label.
    committed_txg: u64,
    /// Authenticated committed-root evidence recovered from the member.
    committed_root: Option<CommittedRoot>,
    /// Pool-wide redundancy policy recorded in the label.
    redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy,
    /// Device class recorded in the label.
    device_class: tidefs_types_pool_label_core::DeviceClass,
    /// Incompatible feature flags recorded in the label.
    features_incompat: u64,
    /// Read-only-compatible feature flags recorded in the label.
    features_ro_compat: u64,
    /// Compatible feature flags recorded in the label.
    features_compat: u64,
    /// Encoded DeviceLayoutV1 record read from the label header.
    device_layout_v1: Option<tidefs_types_pool_label_core::DeviceLayoutV1Bytes>,
    /// Pool state recorded in the label.
    pool_state: tidefs_types_pool_label_core::PoolState,
}

// ---------------------------------------------------------------------------
// pool_import — public entry point
// ---------------------------------------------------------------------------

/// Import a pool from one or more device paths.
///
/// This is the top-level entry point: it scans each device for TideFS
/// pool labels, reconstructs the pool configuration, verifies superblock
/// consistency, replays the intent log, mounts the namespace, and
/// activates the pool.
///
/// When  is true, devices are opened read-only, the intent log
/// is not replayed, and the pool is not activated.
pub fn pool_import(
    device_paths: &[PathBuf],
    lock_dir: &Path,
    read_only: bool,
    encryption_key: Option<tidefs_encryption::StoreKey>,
    min_epoch: Option<u64>,
) -> Result<ImportedPool, ImportError> {
    let label_agreement = build_label_agreement_report_for_paths(device_paths, min_epoch)?;
    verify_label_agreement(&label_agreement)?;

    let entries = tidefs_pool_scan::scan_labels(device_paths)
        .map_err(|e| ImportError::Assembly { msg: e.to_string() })?;
    let config = tidefs_pool_scan::PoolAssembler::assemble(&entries, None)
        .map_err(|e| ImportError::Assembly { msg: e.to_string() })?;
    let mut import = PoolImport::new(config, lock_dir, encryption_key, min_epoch);
    let stats = if read_only {
        import.import_readonly()?
    } else {
        import.import()?
    };
    Ok(ImportedPool {
        config: import.config().clone(),
        stats,
    })
}
// ---------------------------------------------------------------------------
// pool_export — public entry point
// ---------------------------------------------------------------------------

fn rollback_export_labels(devices: &mut [DeviceHandle], prior_labels: &[(u32, Vec<u8>)]) {
    for (written_index, prior_label) in prior_labels.iter().rev() {
        if let Some(rollback_device) = devices
            .iter_mut()
            .find(|candidate| candidate.device_index == *written_index)
        {
            let _ = rollback_device.write_label_bytes(prior_label);
        }
    }
}

/// Export (deactivate) a pool: transition it from Active to Exported state.
///
/// Reads the pool labels from the specified device paths, updates the
/// `pool_state` field to [`PoolState::Exported`] on every device, and
/// removes the import lock file.  After a successful export the pool is
/// safe to move or re-import.
///
/// When `force` is true, the export proceeds even if the labels already
/// show Exported state (idempotent re-export).
pub fn pool_export(
    device_paths: &[PathBuf],
    lock_dir: &Path,
    force: bool,
) -> Result<(), ImportError> {
    // 1. Scan and assemble the pool config.
    let entries = tidefs_pool_scan::scan_labels(device_paths)
        .map_err(|e| ImportError::Assembly { msg: e.to_string() })?;
    let config = tidefs_pool_scan::PoolAssembler::assemble(&entries, None)
        .map_err(|e| ImportError::Assembly { msg: e.to_string() })?;

    // 2. Open devices for read/write.
    let mut devices: Vec<DeviceHandle> = Vec::new();
    let leaves = collect_leaves(&config.device_tree);
    for leaf in &leaves {
        let handle = DeviceHandle::open_rw(&leaf.device_path, leaf.device_index)?;
        devices.push(handle);
    }

    // 3. For each device: read label, set Exported, reseal, write.
    // Preserve prior label bytes so a late write failure does not leave a
    // mixed ACTIVE/EXPORTED topology.
    let mut written_prior_labels: Vec<(u32, Vec<u8>)> = Vec::new();
    for device_idx in 0..devices.len() {
        let device = &mut devices[device_idx];
        let old_buf = device.read_label_bytes()?;
        let device_index = device.device_index;
        let device_path = device.device_path.clone();
        let old_label = match tidefs_types_pool_label_core::decode_label(&old_buf) {
            Ok(label) => label,
            Err(e) => {
                rollback_export_labels(&mut devices, &written_prior_labels);
                return Err(ImportError::Io {
                    device_path: Some(device_path),
                    msg: format!("decode label: {e}"),
                });
            }
        };

        // Skip if already Exported and not forced.
        if old_label.pool_state == tidefs_types_pool_label_core::PoolState::Exported && !force {
            continue;
        }

        // Clone the label, set Exported, reseal.
        let mut new_label = old_label;
        new_label.pool_state = tidefs_types_pool_label_core::PoolState::Exported;

        let out_buf = match encode_label_update_preserving_device_layout(
            new_label,
            &old_buf,
            &device_path,
            "export",
        ) {
            Ok(out_buf) => out_buf,
            Err(e) => {
                rollback_export_labels(&mut devices, &written_prior_labels);
                return Err(e);
            }
        };

        if let Err(err) = devices[device_idx].write_label_bytes(&out_buf) {
            let mut rollback_labels = written_prior_labels.clone();
            rollback_labels.push((device_index, old_buf));
            rollback_export_labels(&mut devices, &rollback_labels);
            return Err(err);
        }
        written_prior_labels.push((device_index, old_buf));
    }

    // 4. Remove the import lock file.
    let lock_path = lock_dir.join(hex_uuid(&config.pool_uuid));
    if lock_path.exists() {
        fs::remove_file(&lock_path).map_err(|e| ImportError::Io {
            device_path: Some(lock_path.clone()),
            msg: format!("remove import lock: {e}"),
        })?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// pool_destroy — public entry point
// ---------------------------------------------------------------------------

/// Destroy a pool: transition every device label to [`PoolState::Destroyed`].
///
/// When `zero_superblock` is true, the label area on each device is also
/// zeroed after the tombstone label is written, preventing accidental
/// re-import.  After a successful destroy the pool cannot be imported again.
pub fn pool_destroy(device_paths: &[PathBuf], zero_superblock: bool) -> Result<(), ImportError> {
    let entries = tidefs_pool_scan::scan_labels(device_paths)
        .map_err(|e| ImportError::Assembly { msg: e.to_string() })?;
    let config = tidefs_pool_scan::PoolAssembler::assemble(&entries, None)
        .map_err(|e| ImportError::Assembly { msg: e.to_string() })?;

    let mut devices: Vec<DeviceHandle> = Vec::new();
    let leaves = collect_leaves(&config.device_tree);
    for leaf in &leaves {
        let handle = DeviceHandle::open_rw(&leaf.device_path, leaf.device_index)?;
        devices.push(handle);
    }

    for device in &mut devices {
        let old_buf = device.read_label_bytes()?;
        let old_label =
            tidefs_types_pool_label_core::decode_label(&old_buf).map_err(|e| ImportError::Io {
                device_path: Some(device.device_path.clone()),
                msg: format!("decode label: {e}"),
            })?;

        let mut new_label = old_label;
        new_label.pool_state = tidefs_types_pool_label_core::PoolState::Destroyed;

        let out_buf = encode_label_update_preserving_device_layout(
            new_label,
            &old_buf,
            &device.device_path,
            "destroy",
        )?;

        device.write_label_bytes(&out_buf)?;

        if zero_superblock {
            let zeroes = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
            device.write_label_bytes(&zeroes)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// DeviceHandle — an open leaf device
// ---------------------------------------------------------------------------

/// An open handle to a leaf device (raw block device or file).
struct DeviceHandle {
    /// Absolute path to the device node.
    device_path: PathBuf,
    /// 0-based device index from the topology.
    device_index: u32,
    /// Opened file handle.
    file: File,
}

impl DeviceHandle {
    /// Open a leaf device for read/write.
    fn open_rw(device_path: &Path, device_index: u32) -> Result<Self, ImportError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)
            .map_err(|e| ImportError::DeviceOpen {
                device_path: device_path.to_path_buf(),
                msg: format!("{e}"),
            })?;
        Ok(Self {
            device_path: device_path.to_path_buf(),
            device_index,
            file,
        })
    }

    /// Open a leaf device for read-only.
    fn open_ro(device_path: &Path, device_index: u32) -> Result<Self, ImportError> {
        let file = File::open(device_path).map_err(|e| ImportError::DeviceOpen {
            device_path: device_path.to_path_buf(),
            msg: format!("{e}"),
        })?;
        Ok(Self {
            device_path: device_path.to_path_buf(),
            device_index,
            file,
        })
    }

    /// Read the first `POOL_LABEL_SIZE` bytes from this device.
    fn read_label_bytes(&mut self) -> Result<Vec<u8>, ImportError> {
        let mut buf = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| ImportError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("seek: {e}"),
            })?;
        self.file
            .read_exact(&mut buf)
            .map_err(|e| ImportError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("read label 0: {e}"),
            })?;
        Ok(buf)
    }

    /// Read `len` bytes from the device at `offset`.
    fn read_bytes_at(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, ImportError> {
        let len_usize = len as usize;
        let mut buf = vec![0u8; len_usize];
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| ImportError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("seek to {offset}: {e}"),
            })?;
        self.file
            .read_exact(&mut buf)
            .map_err(|e| ImportError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("read {len} bytes at {offset}: {e}"),
            })?;
        Ok(buf)
    }

    /// Write `bytes` to the device at `offset`.
    fn write_bytes_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), ImportError> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| ImportError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("seek to {offset} for write: {e}"),
            })?;
        self.file.write_all(bytes).map_err(|e| ImportError::Io {
            device_path: Some(self.device_path.clone()),
            msg: format!("write {} bytes at {offset}: {e}", bytes.len()),
        })?;
        self.file.flush().map_err(|e| ImportError::Io {
            device_path: Some(self.device_path.clone()),
            msg: format!("flush after write at {offset}: {e}"),
        })?;
        Ok(())
    }

    /// Rewrite the primary encoded pool label without clobbering the
    /// reserved commit-record/system area that shares the label region.
    fn write_label_bytes(&mut self, buf: &[u8]) -> Result<(), ImportError> {
        debug_assert_eq!(buf.len(), tidefs_types_pool_label_core::POOL_LABEL_SIZE);
        let features_compat = u64::from_le_bytes(buf[371..379].try_into().unwrap());
        let has_device_layout =
            features_compat & tidefs_types_pool_label_core::features::DEVICE_LAYOUT_V1 != 0;
        let write_len = if buf.iter().all(|b| *b == 0) {
            tidefs_types_pool_label_core::POOL_LABEL_SIZE
        } else if has_device_layout {
            tidefs_types_pool_label_core::POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE
        } else {
            tidefs_types_pool_label_core::POOL_LABEL_V1_EXT_WIRE_SIZE
        };
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| ImportError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("seek: {e}"),
            })?;
        self.file
            .write_all(&buf[..write_len])
            .map_err(|e| ImportError::Io {
                device_path: Some(self.device_path.clone()),
                msg: format!("write label 0: {e}"),
            })
    }
}

fn encode_label_update_preserving_device_layout(
    label: tidefs_types_pool_label_core::PoolLabelV1,
    source_label_buf: &[u8],
    device_path: &Path,
    operation: &'static str,
) -> Result<Vec<u8>, ImportError> {
    let device_layout_v1 = tidefs_types_pool_label_core::decode_device_layout_v1_bytes(
        source_label_buf,
    )
    .map_err(|e| ImportError::Io {
        device_path: Some(device_path.to_path_buf()),
        msg: format!("decode DeviceLayoutV1 during {operation}: {e}"),
    })?;
    let sealed = tidefs_types_pool_label_core::seal_label_with_device_layout(
        label,
        device_layout_v1.as_ref(),
    )
    .map_err(|e| ImportError::Io {
        device_path: Some(device_path.to_path_buf()),
        msg: format!("seal {operation} label: {e}"),
    })?;

    let mut out_buf = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
    tidefs_types_pool_label_core::encode_label_with_device_layout(
        &sealed,
        device_layout_v1.as_ref(),
        &mut out_buf,
    )
    .map_err(|e| ImportError::Io {
        device_path: Some(device_path.to_path_buf()),
        msg: format!("encode {operation} label: {e}"),
    })?;
    Ok(out_buf)
}

const SUPPORTED_INCOMPAT_FEATURES: u64 = tidefs_types_pool_label_core::features::POOL_LABEL_V1
    | tidefs_types_pool_label_core::features::ENCRYPTION_INCOMPAT
    | tidefs_types_pool_label_core::features::CLUSTER_POOL_INCOMPAT;
const SUPPORTED_RO_COMPAT_FEATURES: u64 = 0;
const SUPPORTED_COMPAT_FEATURES: u64 = tidefs_types_pool_label_core::features::DEVICE_CLASS_AWARE
    | tidefs_types_pool_label_core::features::SPARE_POLICY_SUPPORTED
    | tidefs_types_pool_label_core::features::DEVICE_HEALTH_STATE
    | tidefs_types_pool_label_core::features::CLUSTER_POOL_COMPAT
    | tidefs_types_pool_label_core::features::POOL_REDUNDANCY_POLICY
    | tidefs_types_pool_label_core::features::DEVICE_LAYOUT_V1;

fn build_label_agreement_report_for_paths(
    device_paths: &[PathBuf],
    min_epoch: Option<u64>,
) -> Result<LabelAgreementReport, ImportError> {
    let mut members = Vec::with_capacity(device_paths.len());

    for device_path in device_paths {
        let mut file = File::open(device_path).map_err(|e| ImportError::DeviceOpen {
            device_path: device_path.clone(),
            msg: e.to_string(),
        })?;
        let (label, device_layout_v1) = read_member_label_from_file(&mut file, device_path)?;
        ensure_supported_label_features(
            label.features_incompat,
            label.features_ro_compat,
            label.features_compat,
        )?;
        let committed_root = recover_member_committed_root(&mut file, device_path, min_epoch)?;
        members.push(label_agreement_member(
            device_path.clone(),
            label,
            device_layout_v1,
            committed_root,
        ));
    }

    Ok(LabelAgreementReport { members })
}

fn build_label_agreement_report_for_devices(
    devices: &mut [DeviceHandle],
    min_epoch: Option<u64>,
) -> Result<LabelAgreementReport, ImportError> {
    let mut members = Vec::with_capacity(devices.len());

    for device in devices {
        let label_buf = device.read_label_bytes()?;
        let label = tidefs_types_pool_label_core::decode_label(&label_buf).map_err(|e| {
            ImportError::Io {
                device_path: Some(device.device_path.clone()),
                msg: format!("decode label: {e}"),
            }
        })?;
        let device_layout_v1 = tidefs_types_pool_label_core::decode_device_layout_v1_bytes(
            &label_buf,
        )
        .map_err(|e| ImportError::Io {
            device_path: Some(device.device_path.clone()),
            msg: format!("decode DeviceLayoutV1 from label: {e}"),
        })?;
        ensure_supported_label_features(
            label.features_incompat,
            label.features_ro_compat,
            label.features_compat,
        )?;
        let committed_root =
            recover_member_committed_root(&mut device.file, &device.device_path, min_epoch)?;
        members.push(label_agreement_member(
            device.device_path.clone(),
            label,
            device_layout_v1,
            committed_root,
        ));
    }

    Ok(LabelAgreementReport { members })
}

fn read_member_label_from_file(
    file: &mut File,
    device_path: &Path,
) -> Result<
    (
        tidefs_types_pool_label_core::PoolLabelV1,
        Option<tidefs_types_pool_label_core::DeviceLayoutV1Bytes>,
    ),
    ImportError,
> {
    let mut label_buf = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
    file.seek(SeekFrom::Start(0)).map_err(|e| ImportError::Io {
        device_path: Some(device_path.to_path_buf()),
        msg: format!("seek to label 0: {e}"),
    })?;
    file.read_exact(&mut label_buf)
        .map_err(|e| ImportError::Io {
            device_path: Some(device_path.to_path_buf()),
            msg: format!("read label 0: {e}"),
        })?;
    let label =
        tidefs_types_pool_label_core::decode_label(&label_buf).map_err(|e| ImportError::Io {
            device_path: Some(device_path.to_path_buf()),
            msg: format!("decode label: {e}"),
        })?;
    let device_layout_v1 = tidefs_types_pool_label_core::decode_device_layout_v1_bytes(&label_buf)
        .map_err(|e| ImportError::Io {
            device_path: Some(device_path.to_path_buf()),
            msg: format!("decode DeviceLayoutV1 from label: {e}"),
        })?;
    Ok((label, device_layout_v1))
}

fn recover_member_committed_root(
    file: &mut File,
    device_path: &Path,
    min_epoch: Option<u64>,
) -> Result<Option<CommittedRoot>, ImportError> {
    recover_committed_root_from_file(file, min_epoch).map_err(|err| match err {
        CommittedRootError::StaleRoot {
            recovered_epoch,
            min_epoch,
        } => ImportError::StaleRoot {
            recovered_epoch,
            min_epoch,
        },
        err => ImportError::CommittedRootRecovery {
            msg: format!(
                "commit-record recovery failed on {}: {err}",
                device_path.display()
            ),
        },
    })
}

fn label_agreement_member(
    device_path: PathBuf,
    label: tidefs_types_pool_label_core::PoolLabelV1,
    device_layout_v1: Option<tidefs_types_pool_label_core::DeviceLayoutV1Bytes>,
    committed_root: Option<CommittedRoot>,
) -> LabelAgreementMember {
    LabelAgreementMember {
        device_path,
        pool_uuid: label.pool_guid,
        member_uuid: label.device_guid,
        device_index: label.device_index,
        device_capacity_bytes: label.device_capacity_bytes,
        topology_generation: label.topology_generation,
        device_count: label.device_count,
        committed_txg: label.commit_group,
        committed_root,
        redundancy_policy: label.redundancy_policy,
        device_class: label.device_class,
        features_incompat: label.features_incompat,
        features_ro_compat: label.features_ro_compat,
        features_compat: label.features_compat,
        device_layout_v1,
        pool_state: label.pool_state,
    }
}

fn verify_label_agreement(report: &LabelAgreementReport) -> Result<(), ImportError> {
    if report.members.is_empty() {
        return Err(ImportError::Io {
            device_path: None,
            msg: "no candidate member labels supplied for import".to_string(),
        });
    }

    for member in &report.members {
        ensure_supported_label_features(
            member.features_incompat,
            member.features_ro_compat,
            member.features_compat,
        )?;
    }

    ensure_pool_uuids_agree(report)?;
    ensure_topology_generations_agree(report)?;
    ensure_device_counts_agree(report)?;
    ensure_pool_states_agree(report)?;
    ensure_committed_roots_agree(report)?;
    ensure_redundancy_policies_agree(report)?;
    ensure_device_classes_agree(report)?;
    ensure_feature_flags_agree(report)?;
    ensure_device_layout_records_match_feature_flags(report)?;
    ensure_device_layout_records_decode(report)?;

    Ok(())
}

fn ensure_supported_label_features(
    features_incompat: u64,
    features_ro_compat: u64,
    features_compat: u64,
) -> Result<(), ImportError> {
    let unsupported = features_incompat & !SUPPORTED_INCOMPAT_FEATURES;
    if unsupported != 0 {
        return Err(ImportError::IncompatibleFeatures { unsupported });
    }

    let unsupported = features_ro_compat & !SUPPORTED_RO_COMPAT_FEATURES;
    if unsupported != 0 {
        return Err(ImportError::IncompatibleFeatures { unsupported });
    }

    let unsupported = features_compat & !SUPPORTED_COMPAT_FEATURES;
    if unsupported != 0 {
        return Err(ImportError::IncompatibleFeatures { unsupported });
    }

    Ok(())
}

fn ensure_pool_uuids_agree(report: &LabelAgreementReport) -> Result<(), ImportError> {
    let first = report.members[0].pool_uuid;
    if report
        .members
        .iter()
        .any(|member| member.pool_uuid != first)
    {
        return Err(ImportError::SuperblockDisagreement {
            field: "pool_uuid".to_string(),
            values: report
                .members
                .iter()
                .map(|member| hex_uuid(&member.pool_uuid))
                .collect(),
        });
    }
    Ok(())
}

fn ensure_topology_generations_agree(report: &LabelAgreementReport) -> Result<(), ImportError> {
    let first = report.members[0].topology_generation;
    if report
        .members
        .iter()
        .any(|member| member.topology_generation != first)
    {
        return Err(ImportError::SuperblockDisagreement {
            field: "topology_generation".to_string(),
            values: report
                .members
                .iter()
                .map(|member| member.topology_generation.to_string())
                .collect(),
        });
    }
    Ok(())
}

fn ensure_device_counts_agree(report: &LabelAgreementReport) -> Result<(), ImportError> {
    let first = report.members[0].device_count;
    if report
        .members
        .iter()
        .any(|member| member.device_count != first)
    {
        return Err(ImportError::SuperblockDisagreement {
            field: "device_count".to_string(),
            values: report
                .members
                .iter()
                .map(|member| member.device_count.to_string())
                .collect(),
        });
    }
    Ok(())
}

fn ensure_pool_states_agree(report: &LabelAgreementReport) -> Result<(), ImportError> {
    let first = report.members[0].pool_state;
    if report
        .members
        .iter()
        .any(|member| member.pool_state != first)
    {
        return Err(ImportError::SuperblockDisagreement {
            field: "pool_state".to_string(),
            values: report
                .members
                .iter()
                .map(|member| member.pool_state.to_string())
                .collect(),
        });
    }
    if !first.is_importable() {
        return Err(ImportError::BadPoolState {
            state: first.to_string(),
        });
    }
    Ok(())
}

fn ensure_committed_roots_agree(report: &LabelAgreementReport) -> Result<(), ImportError> {
    let first_txg = report.members[0].committed_txg;
    if report
        .members
        .iter()
        .any(|member| member.committed_txg != first_txg)
    {
        let min = report
            .members
            .iter()
            .map(|member| member.committed_txg)
            .min()
            .unwrap_or(0);
        let max = report
            .members
            .iter()
            .map(|member| member.committed_txg)
            .max()
            .unwrap_or(0);
        if min < max {
            return Err(ImportError::StaleRoot {
                recovered_epoch: min,
                min_epoch: max,
            });
        }
        return Err(ImportError::SuperblockDisagreement {
            field: "committed_txg".to_string(),
            values: report
                .members
                .iter()
                .map(|member| member.committed_txg.to_string())
                .collect(),
        });
    }

    let any_missing_required = report
        .members
        .iter()
        .any(|member| member.committed_txg > 0 && member.committed_root.is_none());
    if any_missing_required {
        return Err(ImportError::CommittedRootNotFound);
    }

    let first_root = &report.members[0].committed_root;
    if report
        .members
        .iter()
        .any(|member| &member.committed_root != first_root)
    {
        let mut epochs: Vec<u64> = report
            .members
            .iter()
            .filter_map(|member| member.committed_root.as_ref().map(|root| root.epoch_number))
            .collect();
        epochs.sort_unstable();
        if let (Some(min), Some(max)) = (epochs.first(), epochs.last()) {
            if min < max {
                return Err(ImportError::StaleRoot {
                    recovered_epoch: *min,
                    min_epoch: *max,
                });
            }
        }
        return Err(ImportError::SuperblockDisagreement {
            field: "committed_root".to_string(),
            values: report.members.iter().map(committed_root_value).collect(),
        });
    }

    for member in &report.members {
        if let Some(root) = &member.committed_root {
            if root.epoch_number != member.committed_txg {
                return Err(ImportError::SuperblockDisagreement {
                    field: "committed_root".to_string(),
                    values: report.members.iter().map(committed_root_value).collect(),
                });
            }
        }
    }

    Ok(())
}

fn ensure_redundancy_policies_agree(report: &LabelAgreementReport) -> Result<(), ImportError> {
    let first = report.members[0].redundancy_policy;
    if report
        .members
        .iter()
        .any(|member| member.redundancy_policy != first)
    {
        return Err(ImportError::SuperblockDisagreement {
            field: "redundancy_policy".to_string(),
            values: report
                .members
                .iter()
                .map(|member| member.redundancy_policy.to_string())
                .collect(),
        });
    }
    Ok(())
}

fn ensure_device_classes_agree(report: &LabelAgreementReport) -> Result<(), ImportError> {
    let first = report.members[0].device_class;
    if report
        .members
        .iter()
        .any(|member| member.device_class != first)
    {
        return Err(ImportError::SuperblockDisagreement {
            field: "device_class".to_string(),
            values: report
                .members
                .iter()
                .map(|member| member.device_class.to_string())
                .collect(),
        });
    }
    Ok(())
}

fn ensure_feature_flags_agree(report: &LabelAgreementReport) -> Result<(), ImportError> {
    let first = &report.members[0];
    if report.members.iter().any(|member| {
        member.features_incompat != first.features_incompat
            || member.features_ro_compat != first.features_ro_compat
            || member.features_compat != first.features_compat
    }) {
        return Err(ImportError::SuperblockDisagreement {
            field: "feature_flags".to_string(),
            values: report
                .members
                .iter()
                .map(|member| {
                    format!(
                        "incompat=0x{:016x},ro=0x{:016x},compat=0x{:016x}",
                        member.features_incompat, member.features_ro_compat, member.features_compat
                    )
                })
                .collect(),
        });
    }
    Ok(())
}

fn ensure_device_layout_records_match_feature_flags(
    report: &LabelAgreementReport,
) -> Result<(), ImportError> {
    let missing: Vec<String> = report
        .members
        .iter()
        .filter(|member| {
            member.features_compat & tidefs_types_pool_label_core::features::DEVICE_LAYOUT_V1 != 0
                && member.device_layout_v1.is_none()
        })
        .map(|member| member.device_path.display().to_string())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(ImportError::SuperblockDisagreement {
            field: "device_layout_v1".to_string(),
            values: missing,
        })
    }
}

fn ensure_device_layout_records_decode(report: &LabelAgreementReport) -> Result<(), ImportError> {
    for member in &report.members {
        let Some(device_layout_v1) = &member.device_layout_v1 else {
            continue;
        };
        let layout = decode_device_layout_v1(device_layout_v1).map_err(|e| ImportError::Io {
            device_path: Some(member.device_path.clone()),
            msg: format!("decode DeviceLayoutV1 from label: {e}"),
        })?;
        if layout.device_size_bytes != member.device_capacity_bytes {
            return Err(ImportError::Io {
                device_path: Some(member.device_path.clone()),
                msg: format!(
                    "DeviceLayoutV1 device size mismatch: label capacity {} bytes, layout {} bytes",
                    member.device_capacity_bytes, layout.device_size_bytes
                ),
            });
        }
    }
    Ok(())
}

fn committed_root_value(member: &LabelAgreementMember) -> String {
    match &member.committed_root {
        Some(root) => format!(
            "{}:member={} index={} txg={} root_epoch={} root_hash={}",
            member.device_path.display(),
            hex_uuid(&member.member_uuid),
            member.device_index,
            member.committed_txg,
            root.epoch_number,
            hex_digest_prefix(&root.commitment_hash),
        ),
        None => format!(
            "{}:member={} index={} txg={} root=none",
            member.device_path.display(),
            hex_uuid(&member.member_uuid),
            member.device_index,
            member.committed_txg
        ),
    }
}

fn hex_digest_prefix(digest: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &digest[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// PoolImport — the main import driver
// ---------------------------------------------------------------------------

/// Drives the pool import lifecycle: open devices, verify superblocks,
/// replay intent log, mount namespace, activate pool.
pub struct PoolImport {
    /// Assembled pool configuration from the scan phase.
    pool_config: PoolConfig,
    /// Open handles to all leaf devices.
    devices: Vec<DeviceHandle>,
    /// Import lock file path (import mutex).
    lock_path: PathBuf,
    /// Statistics accumulated during import.
    stats: PoolImportStats,
    /// Whether this is a read-only import.
    read_only: bool,
    /// Encryption key for the pool, obtained from a sealed envelope
    /// (secret-handle/key-lease boundary).  When the pool labels declare
    /// encryption, this key must be present and valid.
    encryption_key: Option<tidefs_encryption::StoreKey>,
    /// Minimum acceptable committed-root epoch for import.
    /// When set, recovered roots with a lower epoch number are
    /// rejected as stale (split-brain prevention gate).
    min_epoch: Option<u64>,
    /// Recovery commit_group (max across all device labels).
    recovery_commit_group: u64,
    /// The authenticated committed root recovered during import, if any.
    recovered_root: Option<CommittedRoot>,
}

impl PoolImport {
    /// Create a new `PoolImport` from an assembled `PoolConfig`.
    ///
    /// `lock_dir` is the directory for import mutex lock files
    /// (e.g. `/dev/tidefs/import`).
    #[must_use]
    pub fn new(
        pool_config: PoolConfig,
        lock_dir: &Path,
        encryption_key: Option<tidefs_encryption::StoreKey>,
        min_epoch: Option<u64>,
    ) -> Self {
        let lock_path = lock_dir.join(hex_uuid(&pool_config.pool_uuid));
        Self {
            pool_config,
            devices: Vec::new(),
            lock_path,
            stats: PoolImportStats::default(),
            read_only: false,
            encryption_key,
            min_epoch,
            recovery_commit_group: 0,
            recovered_root: None,
        }
    }

    /// Return a reference to the assembled pool configuration.
    #[must_use]
    pub fn config(&self) -> &PoolConfig {
        &self.pool_config
    }

    /// Import the pool read/write.  This is the primary entry point.
    pub fn import(&mut self) -> Result<PoolImportStats, ImportError> {
        let start = Instant::now();
        self.read_only = false;

        // 1. Acquire import mutex.
        self.acquire_import_lock()?;

        // 2. Open all leaf devices.
        self.open_devices()?;

        // 3. Verify superblock consistency.
        self.verify_superblock()?;

        // 3b. Recover committed root from commit-record region.
        self.recover_committed_root()?;
        self.stats.committed_root_epoch = self.recovered_root.as_ref().map(|r| r.epoch_number);
        // 4. Replay intent log.
        self.replay_intent_log()?;

        // 5. Mount namespace (dataset catalog).
        self.mount_namespace()?;

        // 6. Activate pool.
        self.activate_pool()?;

        self.stats.import_time_ms = start.elapsed().as_millis() as u64;

        // 7. Check for in-progress device removal.
        self.detect_in_progress_removal();
        Ok(self.stats.clone())
    }

    /// Import the pool read-only: open devices read-only, skip intent log
    /// replay, mount datasets read-only, do not activate.
    /// Check the pool configuration for an in-progress device removal.
    fn detect_in_progress_removal(&mut self) {
        let indices = self.pool_config.removing_device_ids();
        if !indices.is_empty() {
            self.stats.removal_in_progress = true;
        }
    }

    pub fn import_readonly(&mut self) -> Result<PoolImportStats, ImportError> {
        let start = Instant::now();
        self.read_only = true;
        self.stats.read_only = true;

        // 1. Acquire import mutex (shared / read-only variant).
        self.acquire_import_lock()?;

        // 2. Open all leaf devices read-only.
        self.open_devices_readonly()?;

        // 3. Verify superblock consistency.
        self.verify_superblock()?;

        // 3b. Recover committed root (read-only -- verification only).
        self.recover_committed_root()?;
        self.stats.committed_root_epoch = self.recovered_root.as_ref().map(|r| r.epoch_number);
        // 4. Skip intent log replay for read-only import.
        // 5. Mount namespace read-only.
        self.mount_namespace_readonly()?;

        // 6. Do NOT activate pool for read-only import.

        self.stats.import_time_ms = start.elapsed().as_millis() as u64;
        Ok(self.stats.clone())
    }

    // ------------------------------------------------------------------
    // Step 1: acquire import lock
    // ------------------------------------------------------------------

    /// Acquire an exclusive lock for this pool's import.
    ///
    /// Uses a lock file at `lock_path`.  If the file already exists and
    /// cannot be opened exclusively, another importer has claimed this
    /// pool.
    fn acquire_import_lock(&self) -> Result<(), ImportError> {
        // Ensure the lock directory exists.
        if let Some(parent) = self.lock_path.parent() {
            fs::create_dir_all(parent).map_err(|e| ImportError::Io {
                device_path: None,
                msg: format!("create lock dir: {e}"),
            })?;
        }

        // Try to create the lock file exclusively.
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.lock_path)
        {
            Ok(mut lock_file) => {
                // Write current PID so stale-lock detection works across crashes.
                let pid = std::process::id();
                let _ = writeln!(lock_file, "{pid}");
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Lock file exists. Check whether the owning process is still alive.
                if self.is_lock_stale() {
                    // Stale lock left by a crashed process: remove and retry.
                    let _ = fs::remove_file(&self.lock_path);
                    return self.acquire_import_lock();
                }
                Err(ImportError::AlreadyImported {
                    pool_uuid: self.pool_config.pool_uuid,
                })
            }
            Err(e) => Err(ImportError::Io {
                device_path: Some(self.lock_path.clone()),
                msg: format!("acquire lock: {e}"),
            }),
        }
    }

    /// Return true when the lock file exists but the owning process is dead.
    fn is_lock_stale(&self) -> bool {
        let Ok(content) = fs::read_to_string(&self.lock_path) else {
            return false;
        };
        let pid_str = content.trim();
        let Ok(pid) = pid_str.parse::<i32>() else {
            return false;
        };
        if pid <= 1 {
            return false;
        }
        // Check whether /proc/<pid> exists (Linux-only; TideFS is Linux-only).
        let proc_path = format!("/proc/{pid}");
        !Path::new(&proc_path).exists()
    }

    // ------------------------------------------------------------------
    // Step 2: open devices
    // ------------------------------------------------------------------

    /// Open all leaf devices for read/write.
    fn open_devices(&mut self) -> Result<(), ImportError> {
        let leaves = collect_leaves(&self.pool_config.device_tree);
        self.devices = leaves
            .iter()
            .map(|leaf| DeviceHandle::open_rw(&leaf.device_path, leaf.device_index))
            .collect::<Result<Vec<_>, _>>()?;
        self.stats.devices_opened = self.devices.len();
        Ok(())
    }

    /// Open all leaf devices for read-only.
    fn open_devices_readonly(&mut self) -> Result<(), ImportError> {
        let leaves = collect_leaves(&self.pool_config.device_tree);
        self.devices = leaves
            .iter()
            .map(|leaf| DeviceHandle::open_ro(&leaf.device_path, leaf.device_index))
            .collect::<Result<Vec<_>, _>>()?;
        self.stats.devices_opened = self.devices.len();
        Ok(())
    }

    // ------------------------------------------------------------------
    // Step 3: verify superblock
    // ------------------------------------------------------------------

    /// Read the superblock from each device and verify all agree on the
    /// critical fields: pool_uuid, pool_state, topology_generation,
    /// device_count, pool-wide redundancy policy, feature flags, and
    /// commit_group.
    fn verify_superblock(&mut self) -> Result<(), ImportError> {
        // Gate: refuse import if pool state is Destroyed.
        if !self.pool_config.state.is_importable() {
            return Err(ImportError::BadPoolState {
                state: format!("{}", self.pool_config.state),
            });
        }

        let report = build_label_agreement_report_for_devices(&mut self.devices, self.min_epoch)?;
        verify_label_agreement(&report)?;
        let first = &report.members[0];

        if first.redundancy_policy != self.pool_config.redundancy_policy {
            return Err(ImportError::SuperblockDisagreement {
                field: "redundancy_policy".to_string(),
                values: vec![
                    format!("config={}", self.pool_config.redundancy_policy),
                    format!("label={}", first.redundancy_policy),
                ],
            });
        }

        self.stats.superblock_verified = true;

        // Detect encrypted pool from label feature flags.
        self.stats.encrypted = (first.features_incompat
            & tidefs_types_pool_label_core::features::ENCRYPTION_INCOMPAT)
            != 0;

        // Validate encryption key against label flags.
        if self.stats.encrypted && self.encryption_key.is_none() {
            return Err(ImportError::Io {
                device_path: None,
                msg: "pool is encrypted but no encryption key was provided at import time".into(),
            });
        }

        // Compute key fingerprint for operator verification.
        self.stats.key_fingerprint = self.encryption_key.as_ref().map(|key| {
            use std::fmt::Write;
            let fp = blake3::keyed_hash(key.as_bytes(), b"tidefs-enc-fp");
            let mut hex = String::with_capacity(16);
            for b in &fp.as_bytes()[..8] {
                let _ = write!(hex, "{b:02x}");
            }
            hex
        });

        // Store the recovery commit_group for intent log replay.
        self.recovery_commit_group = first.committed_txg;

        Ok(())
    }

    // ------------------------------------------------------------------
    // Step 4: replay intent log
    // ------------------------------------------------------------------

    /// Recover the committed root from the commit-record region on each
    /// device, verifying the BLAKE3 hash chain.
    ///
    /// For read-only import, the committed root is still recovered
    /// (verification is cheap and provides confidence in pool integrity).
    fn recover_committed_root(&mut self) -> Result<(), ImportError> {
        let report = build_label_agreement_report_for_devices(&mut self.devices, self.min_epoch)?;
        verify_label_agreement(&report)?;
        let root = report.members[0].committed_root.clone();

        if root.is_none() && self.recovery_commit_group > 0 {
            return Err(ImportError::CommittedRootNotFound);
        }

        self.recovered_root = root;
        Ok(())
    }

    /// Replay uncommitted records from the newest valid intent log
    /// segment, bringing the pool up to the recovery commit_group.
    ///
    /// Reads the VRBT committed-root block from the system area on each
    /// device to locate the intent-log tail pointer, then reads intent-log
    /// segment data from the data region and replays records through a
    /// BLAKE3-verified replay engine.
    ///
    /// When no VRBT is present (fresh pool or pre-VRBT pool), or when
    /// `intent_log_tail` is zero, replay is a no-op with zero records
    /// replayed.
    ///
    /// For read-only import, this step is skipped entirely.
    fn replay_intent_log(&mut self) -> Result<(), ImportError> {
        if self.read_only {
            return Ok(());
        }
        // Device-level intent-log replay: when the commit-group pipeline
        // has written intent-log segments to the device data region,
        // import replays them here.  When no device-level data exists
        // (VRBT intent_log_tail is 0), replay is a no-op.
        //
        // Downstream layers also replay: LocalObjectStore::open replays
        // object-store WAL records; tidefs-local-filesystem replays
        // namespace intent-log records.  Those run after pool-import
        // completes, when the pool is mounted and data directories are
        // accessible.

        let mut total_replayed: u64 = 0;

        for device in &mut self.devices {
            // Read the pool label to get the system-area pointer.
            let label_buf = device.read_label_bytes()?;
            let Ok(label) = tidefs_types_pool_label_core::decode_label(&label_buf) else {
                continue;
            };

            let system_area_pointer = label.system_area_pointer;
            let system_area_size = label.system_area_size;

            if system_area_size == 0 || system_area_size < VRBT_BLOCK_AREA_SIZE {
                continue;
            }

            // Read the system area to find the VRBT block.
            let sa_buf = match device.read_bytes_at(system_area_pointer, system_area_size) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // VRBT block sits at block index 3 (offset 12 KiB) within
            // the system area.
            let vrbt_off = (VRBT_BLOCK_INDEX as u64) * 4096;
            if sa_buf.len() < (vrbt_off as usize) + VRBT_WIRE_SIZE {
                continue;
            }
            let vrbt_bytes = &sa_buf[vrbt_off as usize..(vrbt_off as usize) + VRBT_WIRE_SIZE];

            let vrbt = match decode_vrbt(vrbt_bytes) {
                Some(v) => v,
                None => continue,
            };

            if vrbt.intent_log_tail == 0 {
                continue;
            }

            // Read intent-log data from the data region.
            let data_start = vrbt.intent_log_head.max(DATA_REGION_OFFSET);
            let data_len = vrbt.intent_log_tail;
            if data_len == 0 {
                continue;
            }

            let ilog_data = match device.read_bytes_at(data_start, data_len) {
                Ok(b) => b,
                Err(_) => {
                    return Err(ImportError::IntentLogReplay {
                        msg: format!(
                            "failed to read intent-log data at offset {data_start}                              len {data_len} on {}",
                            device.device_path.display()
                        ),
                    });
                }
            };

            match replay_intent_log_data(&ilog_data, self.recovery_commit_group) {
                Ok(replayed) => {
                    total_replayed += replayed;
                }
                Err(e) => {
                    return Err(ImportError::IntentLogReplay {
                        msg: format!(
                            "intent-log replay failed on {}: {e}",
                            device.device_path.display()
                        ),
                    });
                }
            }
        }

        self.stats.intent_log_replayed = total_replayed;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Step 5: mount namespace
    // ------------------------------------------------------------------

    /// Load the dataset catalog and make datasets available for mount.
    fn mount_namespace(&mut self) -> Result<(), ImportError> {
        // Stub: namespace/dataset catalog loading is deferred to
        // namespace inode-table issues.  For phase 3 import, we
        // record that datasets are ready when the pool is activated.
        self.stats.datasets_available = 0;
        Ok(())
    }

    /// Read-only variant: load dataset catalog without write access.
    fn mount_namespace_readonly(&mut self) -> Result<(), ImportError> {
        self.stats.datasets_available = 0;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Step 6: activate pool
    // ------------------------------------------------------------------

    /// Transition the pool state to ACTIVE, making it ready for I/O.
    /// Transition the pool state to ACTIVE on every leaf device label.
    fn activate_pool(&mut self) -> Result<(), ImportError> {
        if self.read_only {
            return Ok(());
        }

        let recovery_cg = self.recovery_commit_group;
        let pool_name = self.pool_config.pool_name.clone();
        let topology_gen = self.pool_config.topology_generation;
        let device_count = self.pool_config.device_count;
        let redundancy_policy = self.pool_config.redundancy_policy;

        for device in &mut self.devices {
            // Read and decode the existing label.
            let old_buf = device.read_label_bytes()?;
            let old_label = tidefs_types_pool_label_core::decode_label(&old_buf).map_err(|e| {
                ImportError::Io {
                    device_path: Some(device.device_path.clone()),
                    msg: format!("decode existing label: {e}"),
                }
            })?;

            // Build a fresh label preserving identity fields.
            let mut new_label = tidefs_types_pool_label_core::PoolLabelV1::new(
                old_label.pool_guid,
                old_label.device_guid,
                &pool_name,
            );
            new_label.pool_state = tidefs_types_pool_label_core::PoolState::Active;
            new_label.commit_group = recovery_cg;
            new_label.label_commit_group = recovery_cg;
            new_label.topology_generation = topology_gen;
            new_label.device_count = device_count;
            new_label.device_index = old_label.device_index;
            new_label.device_class = old_label.device_class;
            new_label.device_capacity_bytes = old_label.device_capacity_bytes;
            new_label.system_area_pointer = old_label.system_area_pointer;
            new_label.system_area_size = old_label.system_area_size;
            new_label.features_incompat = old_label.features_incompat;
            new_label.features_ro_compat = old_label.features_ro_compat;
            new_label.features_compat = old_label.features_compat;
            new_label.device_health = old_label.device_health;
            new_label.device_read_errors = old_label.device_read_errors;
            new_label.device_write_errors = old_label.device_write_errors;
            new_label.device_checksum_errors = old_label.device_checksum_errors;
            new_label.redundancy_policy = redundancy_policy;

            // Seal (compute checksum), encode, and write.
            let out_buf = encode_label_update_preserving_device_layout(
                new_label,
                &old_buf,
                &device.device_path,
                "activate",
            )?;
            device.write_label_bytes(&out_buf)?;

            // Write the initial VRBT committed-root block to the system area
            // so that future intent-log replay can locate the intent-log region.
            // At activation time intent_log_tail is 0 (no intent-log records yet).
            let vrbt_bytes = encode_initial_vrbt(
                recovery_cg,
                old_label.system_area_pointer,
                old_label.system_area_size,
            );
            if let Some(vrbt) = vrbt_bytes {
                let vrbt_offset = old_label.system_area_pointer + (VRBT_BLOCK_INDEX as u64) * 4096;
                device.write_bytes_at(vrbt_offset, &vrbt)?;
            }
        }

        Ok(())
    }
}

// ── VRBT encoding ───────────────────────────────────────────────────

/// Encode an initial VRBT committed-root block (88 bytes) with
/// `intent_log_tail = 0` and `intent_log_head = DATA_REGION_OFFSET`.
///
/// Returns `None` if the system area is too small to hold a VRBT block.
fn encode_initial_vrbt(
    commit_group: u64,
    _system_area_pointer: u64,
    system_area_size: u64,
) -> Option<[u8; VRBT_WIRE_SIZE]> {
    if system_area_size < VRBT_BLOCK_AREA_SIZE {
        return None;
    }

    let mut vrbt = [0u8; VRBT_WIRE_SIZE];
    vrbt[0..4].copy_from_slice(&VRBT_MAGIC);
    vrbt[4..8].copy_from_slice(&1u32.to_le_bytes()); // version
    vrbt[8..16].copy_from_slice(&commit_group.to_le_bytes()); // committed_txg
                                                              // namespace_root: 0, inode_table_root: 0, extent_map_root: 0 (not yet populated)
    vrbt[40..48].copy_from_slice(&DATA_REGION_OFFSET.to_le_bytes()); // intent_log_head
    vrbt[48..56].copy_from_slice(&0u64.to_le_bytes()); // intent_log_tail = 0
    let hash = blake3::hash(&vrbt[..VRBT_HEADER_SIZE]);
    vrbt[VRBT_HASH_OFFSET..VRBT_WIRE_SIZE].copy_from_slice(hash.as_bytes());

    Some(vrbt)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A flattened leaf-device reference extracted from the device tree.
#[derive(Clone, Debug)]
struct LeafDevice {
    device_path: PathBuf,
    device_index: u32,
}

/// Walk the device tree and collect all leaf devices.
fn collect_leaves(tree: &DeviceType) -> Vec<LeafDevice> {
    let mut out = Vec::new();
    collect_leaves_impl(tree, &mut out);
    out
}

fn collect_leaves_impl(node: &DeviceType, out: &mut Vec<LeafDevice>) {
    match node {
        DeviceType::Leaf {
            device_path,
            device_index,
            ..
        } => {
            out.push(LeafDevice {
                device_path: device_path.clone(),
                device_index: *device_index,
            });
        }
        DeviceType::PoolWideData { children }
        | DeviceType::Mirror { children }
        | DeviceType::ParityRaid { children, .. } => {
            for child in children {
                collect_leaves_impl(child, out);
            }
        }
    }
}

/// Format a 16-byte UUID as a hex string.
fn hex_uuid(uuid: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in uuid {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ── VRBT decode helper ───────────────────────────────────────────────

/// Decode a VRBT committed-root block from 88 raw bytes.
///
/// Returns `None` if the magic, version, or BLAKE3 hash is invalid.
pub fn decode_vrbt(bytes: &[u8]) -> Option<VrbtParsed> {
    if bytes.len() < VRBT_WIRE_SIZE {
        return None;
    }
    let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
    if magic != VRBT_MAGIC {
        return None;
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if version != 1 {
        return None;
    }

    // Verify BLAKE3 hash: covers bytes 0..56.
    let stored: [u8; 32] = bytes[VRBT_HASH_OFFSET..VRBT_WIRE_SIZE].try_into().unwrap();
    let computed: [u8; 32] = blake3::hash(&bytes[..VRBT_HEADER_SIZE]).into();
    if stored != computed {
        return None;
    }

    let committed_txg = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let namespace_root = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let inode_table_root = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let extent_map_root = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let intent_log_head = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
    let intent_log_tail = u64::from_le_bytes(bytes[48..56].try_into().unwrap());

    Some(VrbtParsed {
        committed_txg,
        namespace_root,
        inode_table_root,
        extent_map_root,
        intent_log_head,
        intent_log_tail,
    })
}

// ── Public intent-log check ─────────────────────────────────────────

/// Result of checking a device's intent-log state for pending
/// (un-replayed) records.
#[derive(Clone, Debug)]
pub struct IntentLogCheckResult {
    /// The commit-group ID from the VRBT committed root.
    pub committed_txg: u64,
    /// Whether the VRBT was present and valid.
    pub vrbt_valid: bool,
    /// Whether the intent-log has pending records that need replay.
    pub intent_log_pending: bool,
    /// Byte count of pending intent-log records (head..tail).
    pub pending_bytes: u64,
    /// Human-readable description of the check outcome.
    pub description: String,
}

/// Check whether a device has pending (un-replayed) intent-log records.
///
/// Reads the device's system area to find the VRBT committed-root block,
/// then checks whether `intent_log_tail > intent_log_head`, which
/// indicates the pool was not cleanly shut down and intent-log replay is
/// required.
///
/// Returns `Err` on I/O or label-read failure.  Returns `Ok(None)` when
/// the device has no pool label or no system area.  Returns
/// `Ok(Some(result))` with the check details otherwise.
pub fn check_pool_intent_log_pending(
    device_path: &Path,
) -> Result<Option<IntentLogCheckResult>, ImportError> {
    use std::io::Read;

    let mut file = File::open(device_path).map_err(|e| ImportError::DeviceOpen {
        device_path: device_path.to_path_buf(),
        msg: e.to_string(),
    })?;

    // Read pool label at offset 0 to find the system-area pointer.
    let mut label_buf = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
    file.seek(SeekFrom::Start(0)).map_err(|e| ImportError::Io {
        device_path: Some(device_path.to_path_buf()),
        msg: format!("seek to label 0: {e}"),
    })?;
    file.read_exact(&mut label_buf)
        .map_err(|e| ImportError::Io {
            device_path: Some(device_path.to_path_buf()),
            msg: format!("read label 0: {e}"),
        })?;

    let label = match tidefs_types_pool_label_core::decode_label(&label_buf) {
        Ok(l) => l,
        Err(_) => return Ok(None),
    };

    let system_area_pointer = label.system_area_pointer;
    let system_area_size = label.system_area_size;

    if system_area_size == 0 || system_area_size < VRBT_BLOCK_AREA_SIZE {
        return Ok(None);
    }

    // Read the system area.
    file.seek(SeekFrom::Start(system_area_pointer))
        .map_err(|e| ImportError::Io {
            device_path: Some(device_path.to_path_buf()),
            msg: format!("seek to system area: {e}"),
        })?;
    let mut sa_buf = vec![0u8; system_area_size as usize];
    file.read_exact(&mut sa_buf).map_err(|e| ImportError::Io {
        device_path: Some(device_path.to_path_buf()),
        msg: format!("read system area: {e}"),
    })?;

    let vrbt_off = (VRBT_BLOCK_INDEX as u64) * 4096;
    let vrbt_bytes = &sa_buf[vrbt_off as usize..(vrbt_off as usize) + VRBT_WIRE_SIZE];

    let result = match decode_vrbt(vrbt_bytes) {
        Some(vrbt) => {
            let pending = vrbt.intent_log_tail > vrbt.intent_log_head;
            let pending_bytes = vrbt.intent_log_tail.saturating_sub(vrbt.intent_log_head);
            let desc = if pending {
                format!(
                    "intent-log has {} pending bytes (head={}, tail={}) on {}",
                    pending_bytes,
                    vrbt.intent_log_head,
                    vrbt.intent_log_tail,
                    device_path.display()
                )
            } else {
                format!(
                    "intent-log clean (head=tail={}) on {}",
                    vrbt.intent_log_tail,
                    device_path.display()
                )
            };
            IntentLogCheckResult {
                committed_txg: vrbt.committed_txg,
                vrbt_valid: true,
                intent_log_pending: pending,
                pending_bytes,
                description: desc,
            }
        }
        None => {
            // Distinguish all-zeros (fresh pool, VRBT never written)
            // from corrupted VRBT data.
            let all_zeros = vrbt_bytes.iter().all(|&b| b == 0);
            if all_zeros {
                IntentLogCheckResult {
                    committed_txg: 0,
                    vrbt_valid: true, // not invalid, just unwritten
                    intent_log_pending: false,
                    pending_bytes: 0,
                    description: format!(
                        "VRBT not yet written (fresh pool, no intent-log activity) on {}",
                        device_path.display()
                    ),
                }
            } else {
                IntentLogCheckResult {
                    committed_txg: 0,
                    vrbt_valid: false,
                    intent_log_pending: false,
                    pending_bytes: 0,
                    description: format!(
                        "VRBT block missing or invalid on {}",
                        device_path.display()
                    ),
                }
            }
        }
    };

    Ok(Some(result))
}

// ── Intent-log data replay ──────────────────────────────────────────

/// A replay handler that counts replayed records without applying
/// them to a filesystem.  Used during pool import when the storage
/// authority (mounted filesystem) is not yet available.
struct CountingReplayHandler {
    replayed: u64,
}

impl IntentReplayHandler for CountingReplayHandler {
    type Error = String;

    fn handle_record(&mut self, _record: &IntentLogRecord) -> Result<(), String> {
        self.replayed += 1;
        Ok(())
    }
}

/// Replay intent-log data from a byte buffer through the BLAKE3-verified
/// replay engine.  Returns the number of records successfully replayed.
///
/// Uses `IntentReplayEngine` for segment-level replay with a
/// `CountingReplayHandler` that tallies records without applying
/// them — the storage authority (mounted filesystem) is not yet
/// available during pool import.
///
/// Records with LSN <= `recovery_txg` are skipped (already committed).
fn replay_intent_log_data(data: &[u8], recovery_txg: u64) -> Result<u64, String> {
    if data.is_empty() {
        return Ok(0);
    }

    let mut engine = IntentReplayEngine::new(recovery_txg);
    let mut handler = CountingReplayHandler { replayed: 0 };

    match engine.replay_segment(data, &mut handler) {
        Ok(SegmentReplayOutcome::Replayed { replayed, .. }) => Ok(replayed),
        Ok(SegmentReplayOutcome::Skipped { reason }) => match reason {
            tidefs_intent_log::replay::SkippedReason::Corrupt => {
                Err("intent-log segment is corrupt and cannot be replayed".into())
            }
            _ => Ok(0),
        },
        Err(e) => Err(format!("intent-log segment replay error: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use tidefs_local_object_store::device_layout::{encode_device_layout_v1, DeviceLayoutPolicy};
    use tidefs_pool_scan::DeviceHealth;
    use tidefs_types_pool_label_core::{
        encode_label, encode_label_with_device_layout, seal_label, seal_label_with_device_layout,
        DeviceClass, DeviceLayoutV1Bytes, PoolLabelV1, PoolRedundancyPolicy, PoolState,
        POOL_LABEL_DEVICE_LAYOUT_V1_WIRE_SIZE, POOL_LABEL_SIZE, POOL_LABEL_V1_EXT_WIRE_SIZE,
    };

    /// Build a minimal single-device PoolConfig for testing.
    fn make_single_device_config(device_path: PathBuf) -> PoolConfig {
        let tree = DeviceType::Leaf {
            device_path,
            device_guid: [0x01u8; 16],
            device_index: 0,
            capacity_bytes: 1024 * 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        PoolConfig {
            pool_uuid: [0xAAu8; 16],
            pool_name: "testpool".to_string(),
            redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
            device_tree: tree,
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 1,
            missing_indices: Vec::new(),
            removing_device_indices: vec![],
            completed_evacuations: vec![],
        }
    }

    fn make_two_device_config(
        dev0: PathBuf,
        dev1: PathBuf,
        redundancy_policy: PoolRedundancyPolicy,
    ) -> PoolConfig {
        let tree = DeviceType::PoolWideData {
            children: vec![
                DeviceType::Leaf {
                    device_path: dev0,
                    device_guid: [0x10u8; 16],
                    device_index: 0,
                    capacity_bytes: 1024 * 1024,
                    device_class: DeviceClass::Hdd,
                    health: DeviceHealth::Online,
                    read_errors: 0,
                    write_errors: 0,
                    checksum_errors: 0,
                },
                DeviceType::Leaf {
                    device_path: dev1,
                    device_guid: [0x11u8; 16],
                    device_index: 1,
                    capacity_bytes: 1024 * 1024,
                    device_class: DeviceClass::Hdd,
                    health: DeviceHealth::Online,
                    read_errors: 0,
                    write_errors: 0,
                    checksum_errors: 0,
                },
            ],
        };
        PoolConfig {
            pool_uuid: [0xAAu8; 16],
            pool_name: "testpool".to_string(),
            redundancy_policy,
            device_tree: tree,
            health: DeviceHealth::Online,
            state: PoolState::Active,
            total_capacity_bytes: 2 * 1024 * 1024,
            allocated_bytes: 0,
            feature_flags: 0,
            topology_generation: 1,
            device_count: 2,
            missing_indices: Vec::new(),
            removing_device_indices: vec![],
            completed_evacuations: vec![],
        }
    }

    /// Write a valid TideFS pool label at the start of a file.
    fn write_test_label(file: &mut File, pool_name: &str) {
        write_test_label_with_authority(
            file,
            [0xAAu8; 16],
            [0x01u8; 16],
            pool_name,
            0,
            1,
            PoolState::Active,
            PoolRedundancyPolicy::replicated(1),
            DeviceClass::Hdd,
            0,
            0,
        );
    }

    fn write_test_label_for_device(
        file: &mut File,
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        pool_name: &str,
        device_index: u32,
        device_count: u32,
        state: PoolState,
    ) {
        write_test_label_for_device_with_policy(
            file,
            pool_guid,
            device_guid,
            pool_name,
            device_index,
            device_count,
            state,
            PoolRedundancyPolicy::replicated(1),
        );
    }

    fn write_test_label_for_device_with_policy(
        file: &mut File,
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        pool_name: &str,
        device_index: u32,
        device_count: u32,
        state: PoolState,
        redundancy_policy: PoolRedundancyPolicy,
    ) {
        write_test_label_with_authority(
            file,
            pool_guid,
            device_guid,
            pool_name,
            device_index,
            device_count,
            state,
            redundancy_policy,
            DeviceClass::Hdd,
            0,
            0,
        );
    }

    fn write_test_label_with_authority(
        file: &mut File,
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        pool_name: &str,
        device_index: u32,
        device_count: u32,
        state: PoolState,
        redundancy_policy: PoolRedundancyPolicy,
        device_class: DeviceClass,
        features_incompat: u64,
        committed_txg: u64,
    ) {
        let mut label = PoolLabelV1::new(pool_guid, device_guid, pool_name);
        label.pool_state = state;
        label.device_index = device_index;
        label.device_count = device_count;
        label.topology_generation = 1;
        label.redundancy_policy = redundancy_policy;
        label.device_class = device_class;
        label.features_incompat = features_incompat;
        label.commit_group = committed_txg;
        label.label_commit_group = committed_txg;
        let sealed = seal_label(label).unwrap();
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&buf).unwrap();
        let padding =
            vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE - POOL_LABEL_V1_EXT_WIRE_SIZE];
        file.write_all(&padding).unwrap();
        file.flush().unwrap();
    }

    fn write_test_label_with_device_layout(
        file: &mut File,
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        pool_name: &str,
        label_capacity_bytes: u64,
        layout_device_size_bytes: u64,
        mutate_layout: impl FnOnce(&mut DeviceLayoutV1Bytes),
    ) {
        let mut label = PoolLabelV1::new(pool_guid, device_guid, pool_name);
        label.pool_state = PoolState::Exported;
        label.device_index = 0;
        label.device_count = 1;
        label.topology_generation = 1;
        label.device_capacity_bytes = label_capacity_bytes;

        let layout = DeviceLayoutPolicy::Slice0Small
            .compute(layout_device_size_bytes)
            .unwrap();
        let mut layout_bytes = [0u8; POOL_LABEL_DEVICE_LAYOUT_V1_WIRE_SIZE];
        encode_device_layout_v1(&layout, &mut layout_bytes);
        mutate_layout(&mut layout_bytes);

        let sealed = seal_label_with_device_layout(label, Some(&layout_bytes)).unwrap();
        let mut buf = vec![0u8; POOL_LABEL_SIZE];
        encode_label_with_device_layout(&sealed, Some(&layout_bytes), &mut buf).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&buf).unwrap();
        file.set_len(label_capacity_bytes.max(POOL_LABEL_SIZE as u64))
            .unwrap();
        file.flush().unwrap();
    }

    fn write_committed_root_chain(file: &mut File, latest_epoch: u64) {
        let mut records = Vec::with_capacity(latest_epoch as usize);
        let mut prior_hash = None;
        for epoch in 1..=latest_epoch {
            let dirty_id = epoch * 11;
            let commit_hash = tidefs_commit_group::seal_commit_hash(
                epoch,
                tidefs_commit_group::CommitGroupId(epoch),
                prior_hash,
                &[dirty_id],
            );
            records.push(crate::committed_root::ParsedCommitRecord {
                epoch_number: epoch,
                commit_group_id: epoch,
                commit_hash,
                prior_epoch_hash: prior_hash,
                dirty_object_ids: vec![dirty_id],
            });
            prior_hash = Some(commit_hash);
        }
        let encoded = crate::committed_root::encode_commit_record_region(&records);
        file.seek(SeekFrom::Start(
            crate::committed_root::COMMIT_RECORD_REGION_OFFSET,
        ))
        .unwrap();
        file.write_all(&encoded).unwrap();
        file.flush().unwrap();
    }

    fn read_label_state(path: &Path) -> PoolState {
        let mut handle = DeviceHandle::open_ro(path, 0).unwrap();
        let label = tidefs_types_pool_label_core::decode_label(&handle.read_label_bytes().unwrap())
            .unwrap();
        label.pool_state
    }

    // -- open_devices tests --

    #[test]
    fn open_devices_single_device() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "testpool");
        }

        let config = make_single_device_config(dev_path);
        let lock_dir = dir.path().join("locks");
        let mut import = PoolImport::new(config, &lock_dir, None, None);

        import.open_devices().unwrap();
        assert_eq!(import.devices.len(), 1);
        assert_eq!(import.stats.devices_opened, 1);
    }

    #[test]
    fn open_devices_missing_device() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("nonexistent");

        let config = make_single_device_config(dev_path);
        let lock_dir = dir.path().join("locks");
        let mut import = PoolImport::new(config, &lock_dir, None, None);

        let result = import.open_devices();
        assert!(result.is_err());
        match result.unwrap_err() {
            ImportError::DeviceOpen { .. } => {}
            e => panic!("expected DeviceOpen, got {e}"),
        }
    }

    // -- superblock verification tests --

    #[test]
    fn verify_superblock_single_device_active() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "testpool");
        }

        let config = make_single_device_config(dev_path);
        let lock_dir = dir.path().join("locks");
        let mut import = PoolImport::new(config, &lock_dir, None, None);
        import.open_devices().unwrap();

        import.verify_superblock().unwrap();
        assert!(import.stats.superblock_verified);
    }

    #[test]
    fn verify_superblock_rejects_destroyed_pool() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "deadpool");
        }

        let mut config = make_single_device_config(dev_path);
        config.state = PoolState::Destroyed;
        let lock_dir = dir.path().join("locks");
        let mut import = PoolImport::new(config, &lock_dir, None, None);
        import.open_devices().unwrap();

        let result = import.verify_superblock();
        assert!(result.is_err());
        match result.unwrap_err() {
            ImportError::BadPoolState { .. } => {}
            e => panic!("expected BadPoolState, got {e}"),
        }
    }

    #[test]
    fn verify_superblock_rejects_redundancy_policy_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = dir.path().join("device0");
        let dev1 = dir.path().join("device1");
        {
            let mut f = File::create(&dev0).unwrap();
            write_test_label_for_device_with_policy(
                &mut f,
                [0xAAu8; 16],
                [0x10u8; 16],
                "testpool",
                0,
                2,
                PoolState::Active,
                PoolRedundancyPolicy::replicated(2),
            );
        }
        {
            let mut f = File::create(&dev1).unwrap();
            write_test_label_for_device_with_policy(
                &mut f,
                [0xAAu8; 16],
                [0x11u8; 16],
                "testpool",
                1,
                2,
                PoolState::Active,
                PoolRedundancyPolicy::erasure(1, 1),
            );
        }

        let config = make_two_device_config(
            dev0.clone(),
            dev1.clone(),
            PoolRedundancyPolicy::replicated(2),
        );
        let lock_dir = dir.path().join("locks");
        let mut import = PoolImport::new(config, &lock_dir, None, None);
        import.open_devices().unwrap();

        match import.verify_superblock().unwrap_err() {
            ImportError::SuperblockDisagreement { field, values } => {
                assert_eq!(field, "redundancy_policy");
                assert!(values.contains(&"replicated=2".to_string()));
                assert!(values.contains(&"erasure=1+1".to_string()));
            }
            err => panic!("expected redundancy policy disagreement, got {err}"),
        }
    }

    // -- import lock tests --

    #[test]
    fn acquire_import_lock_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = dir.path().join("locks");

        let config = make_single_device_config(dir.path().join("device0"));
        let import = PoolImport::new(config, &lock_dir, None, None);
        import.acquire_import_lock().unwrap();
        assert!(import.lock_path.exists());
    }

    #[test]
    fn double_import_refused() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = dir.path().join("locks");

        let config = make_single_device_config(dir.path().join("device0"));
        let import1 = PoolImport::new(config.clone(), &lock_dir, None, None);
        import1.acquire_import_lock().unwrap();

        let import2 = PoolImport::new(config, &lock_dir, None, None);
        let result = import2.acquire_import_lock();
        assert!(result.is_err());
        match result.unwrap_err() {
            ImportError::AlreadyImported { .. } => {}
            e => panic!("expected AlreadyImported, got {e}"),
        }
    }

    // -- read-only import tests --

    #[test]
    fn open_devices_readonly() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "ropool");
        }

        let config = make_single_device_config(dev_path);
        let lock_dir = dir.path().join("locks");
        let mut import = PoolImport::new(config, &lock_dir, None, None);

        import.open_devices_readonly().unwrap();
        assert_eq!(import.stats.devices_opened, 1);
    }

    // -- full import integration test --

    #[test]
    fn full_import_readwrite_single_device() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "fullimport");
        }

        let config = make_single_device_config(dev_path);
        let lock_dir = dir.path().join("locks");
        let mut import = PoolImport::new(config, &lock_dir, None, None);

        let stats = import.import().unwrap();
        assert_eq!(stats.devices_opened, 1);
        assert!(stats.superblock_verified);
        assert!(!stats.read_only);
        // import_time_ms can be 0 for sub-millisecond imports
    }

    #[test]
    fn full_import_readonly_single_device() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "roimport");
        }

        let config = make_single_device_config(dev_path);
        let lock_dir = dir.path().join("locks");
        let mut import = PoolImport::new(config, &lock_dir, None, None);

        let stats = import.import_readonly().unwrap();
        assert_eq!(stats.devices_opened, 1);
        assert!(stats.read_only);
        // import_time_ms can be 0 for sub-millisecond imports
    }

    // -- helper tests --

    #[test]
    fn collect_leaves_single_device() {
        let tree = DeviceType::Leaf {
            device_path: PathBuf::from("/dev/sda"),
            device_guid: [0x01u8; 16],
            device_index: 0,
            capacity_bytes: 1024,
            device_class: DeviceClass::Hdd,
            health: DeviceHealth::Online,
            read_errors: 0,
            write_errors: 0,
            checksum_errors: 0,
        };
        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].device_path, PathBuf::from("/dev/sda"));
    }

    #[test]
    fn collect_leaves_three_member_pool_wide_data() {
        let tree = DeviceType::PoolWideData {
            children: vec![
                DeviceType::Leaf {
                    device_path: PathBuf::from("/dev/sda"),
                    device_guid: [0x01u8; 16],
                    device_index: 0,
                    capacity_bytes: 1024,
                    device_class: DeviceClass::Hdd,
                    health: DeviceHealth::Online,
                    read_errors: 0,
                    write_errors: 0,
                    checksum_errors: 0,
                },
                DeviceType::Leaf {
                    device_path: PathBuf::from("/dev/sdb"),
                    device_guid: [0x02u8; 16],
                    device_index: 1,
                    capacity_bytes: 1024,
                    device_class: DeviceClass::Hdd,
                    health: DeviceHealth::Online,
                    read_errors: 0,
                    write_errors: 0,
                    checksum_errors: 0,
                },
                DeviceType::Leaf {
                    device_path: PathBuf::from("/dev/sdc"),
                    device_guid: [0x03u8; 16],
                    device_index: 2,
                    capacity_bytes: 1024,
                    device_class: DeviceClass::Hdd,
                    health: DeviceHealth::Online,
                    read_errors: 0,
                    write_errors: 0,
                    checksum_errors: 0,
                },
            ],
        };
        let leaves = collect_leaves(&tree);
        assert_eq!(leaves.len(), 3);
    }

    #[test]
    fn hex_uuid_format() {
        let uuid = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        assert_eq!(hex_uuid(&uuid), "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn import_error_display() {
        let err = ImportError::BadPoolState {
            state: "DESTROYED".to_string(),
        };
        assert!(format!("{err}").contains("DESTROYED"));

        let err = ImportError::DeviceOpen {
            device_path: PathBuf::from("/dev/sda"),
            msg: "permission denied".to_string(),
        };
        assert!(format!("{err}").contains("/dev/sda"));
        assert!(format!("{err}").contains("permission denied"));

        let err = ImportError::AlreadyImported {
            pool_uuid: [0xAAu8; 16],
        };
        assert!(format!("{err}").contains("already imported"));
    }

    // -- pool_import integration tests --

    #[test]
    fn pool_import_single_device_rw() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "import_rw");
        }
        let lock_dir = dir.path().join("locks");

        let result = pool_import(&[dev_path], &lock_dir, false, None, None).unwrap();
        assert_eq!(result.config.pool_name, "import_rw");
        assert_eq!(result.config.device_count, 1);
        assert!(result.stats.superblock_verified);
        assert!(!result.stats.read_only);
    }

    #[test]
    fn pool_import_label_agreement_accepts_clean_multi_device_import() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = dir.path().join("device0");
        let dev1 = dir.path().join("device1");
        for path in [&dev0, &dev1] {
            let f = File::create(path).unwrap();
            f.set_len(2 * 1024 * 1024).unwrap();
        }

        let config = crate::create::PoolCreateConfig {
            pool_name: "clean_multi".into(),
            pool_guid: Some([0xC1u8; 16]),
            redundancy: crate::create::RedundancyPolicy::replicated(2),
            encryption_key: None,
            clustered: false,
        };
        crate::create::PoolCreator::create_pool(&[dev0.clone(), dev1.clone()], &config).unwrap();

        let imported =
            pool_import(&[dev0, dev1], &dir.path().join("locks"), false, None, None).unwrap();
        assert_eq!(imported.config.device_count, 2);
        assert_eq!(imported.stats.committed_root_epoch, Some(1));
        assert!(imported.stats.superblock_verified);
    }

    #[test]
    fn pool_import_label_agreement_rejects_mixed_pool_uuid() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = dir.path().join("device0");
        let dev1 = dir.path().join("device1");
        {
            let mut f = File::create(&dev0).unwrap();
            write_test_label_with_authority(
                &mut f,
                [0xA0u8; 16],
                [0x10u8; 16],
                "mixed_uuid",
                0,
                2,
                PoolState::Exported,
                PoolRedundancyPolicy::replicated(1),
                DeviceClass::Hdd,
                0,
                0,
            );
        }
        {
            let mut f = File::create(&dev1).unwrap();
            write_test_label_with_authority(
                &mut f,
                [0xB0u8; 16],
                [0x11u8; 16],
                "mixed_uuid",
                1,
                2,
                PoolState::Exported,
                PoolRedundancyPolicy::replicated(1),
                DeviceClass::Hdd,
                0,
                0,
            );
        }

        match pool_import(
            &[dev0.clone(), dev1.clone()],
            &dir.path().join("locks"),
            false,
            None,
            None,
        )
        .unwrap_err()
        {
            ImportError::SuperblockDisagreement { field, values } => {
                assert_eq!(field, "pool_uuid");
                assert_eq!(values.len(), 2);
            }
            err => panic!("expected pool_uuid disagreement, got {err}"),
        }
        assert_eq!(read_label_state(&dev0), PoolState::Exported);
        assert_eq!(read_label_state(&dev1), PoolState::Exported);
    }

    #[test]
    fn pool_import_label_agreement_rejects_stale_committed_root() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = dir.path().join("device0");
        let dev1 = dir.path().join("device1");
        {
            let mut f = File::create(&dev0).unwrap();
            write_test_label_with_authority(
                &mut f,
                [0xA1u8; 16],
                [0x20u8; 16],
                "stale_root",
                0,
                2,
                PoolState::Exported,
                PoolRedundancyPolicy::replicated(1),
                DeviceClass::Hdd,
                0,
                2,
            );
            write_committed_root_chain(&mut f, 2);
        }
        {
            let mut f = File::create(&dev1).unwrap();
            write_test_label_with_authority(
                &mut f,
                [0xA1u8; 16],
                [0x21u8; 16],
                "stale_root",
                1,
                2,
                PoolState::Exported,
                PoolRedundancyPolicy::replicated(1),
                DeviceClass::Hdd,
                0,
                1,
            );
            write_committed_root_chain(&mut f, 1);
        }

        match pool_import(&[dev0, dev1], &dir.path().join("locks"), false, None, None).unwrap_err()
        {
            ImportError::StaleRoot {
                recovered_epoch,
                min_epoch,
            } => {
                assert_eq!(recovered_epoch, 1);
                assert_eq!(min_epoch, 2);
            }
            err => panic!("expected stale committed-root evidence, got {err}"),
        }
    }

    #[test]
    fn pool_import_label_agreement_rejects_redundancy_policy_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = dir.path().join("device0");
        let dev1 = dir.path().join("device1");
        {
            let mut f = File::create(&dev0).unwrap();
            write_test_label_with_authority(
                &mut f,
                [0xA2u8; 16],
                [0x30u8; 16],
                "bad_policy",
                0,
                2,
                PoolState::Exported,
                PoolRedundancyPolicy::replicated(2),
                DeviceClass::Hdd,
                0,
                0,
            );
        }
        {
            let mut f = File::create(&dev1).unwrap();
            write_test_label_with_authority(
                &mut f,
                [0xA2u8; 16],
                [0x31u8; 16],
                "bad_policy",
                1,
                2,
                PoolState::Exported,
                PoolRedundancyPolicy::erasure(1, 1),
                DeviceClass::Hdd,
                0,
                0,
            );
        }

        match pool_import(&[dev0, dev1], &dir.path().join("locks"), false, None, None).unwrap_err()
        {
            ImportError::SuperblockDisagreement { field, values } => {
                assert_eq!(field, "redundancy_policy");
                assert!(values.contains(&"replicated=2".to_string()));
                assert!(values.contains(&"erasure=1+1".to_string()));
            }
            err => panic!("expected redundancy-policy disagreement, got {err}"),
        }
    }

    #[test]
    fn pool_import_label_agreement_rejects_corrupt_device_layout_record() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 2 * 1024 * 1024;
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label_with_device_layout(
                &mut f,
                [0xD1u8; 16],
                [0x01u8; 16],
                "bad_layout",
                capacity,
                capacity,
                |layout| layout[0] ^= 0xFF,
            );
        }

        match pool_import(&[dev_path], &dir.path().join("locks"), false, None, None).unwrap_err() {
            ImportError::Io { msg, .. } => {
                assert!(msg.contains("decode DeviceLayoutV1"), "{msg}");
                assert!(msg.contains("bad magic"), "{msg}");
            }
            err => panic!("expected corrupt DeviceLayoutV1 rejection, got {err}"),
        }
    }

    #[test]
    fn pool_import_label_agreement_rejects_device_layout_size_drift() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        let capacity = 2 * 1024 * 1024;
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label_with_device_layout(
                &mut f,
                [0xD2u8; 16],
                [0x02u8; 16],
                "layout_drift",
                capacity,
                capacity + 1024 * 1024,
                |_| {},
            );
        }

        match pool_import(&[dev_path], &dir.path().join("locks"), false, None, None).unwrap_err() {
            ImportError::Io { msg, .. } => {
                assert!(msg.contains("DeviceLayoutV1 device size mismatch"), "{msg}");
            }
            err => panic!("expected DeviceLayoutV1 size-drift rejection, got {err}"),
        }
    }

    #[test]
    fn pool_import_label_agreement_rejects_device_class_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = dir.path().join("device0");
        let dev1 = dir.path().join("device1");
        {
            let mut f = File::create(&dev0).unwrap();
            write_test_label_with_authority(
                &mut f,
                [0xA3u8; 16],
                [0x40u8; 16],
                "bad_class",
                0,
                2,
                PoolState::Exported,
                PoolRedundancyPolicy::replicated(1),
                DeviceClass::Hdd,
                0,
                0,
            );
        }
        {
            let mut f = File::create(&dev1).unwrap();
            write_test_label_with_authority(
                &mut f,
                [0xA3u8; 16],
                [0x41u8; 16],
                "bad_class",
                1,
                2,
                PoolState::Exported,
                PoolRedundancyPolicy::replicated(1),
                DeviceClass::Ssd,
                0,
                0,
            );
        }

        match pool_import(&[dev0, dev1], &dir.path().join("locks"), false, None, None).unwrap_err()
        {
            ImportError::SuperblockDisagreement { field, values } => {
                assert_eq!(field, "device_class");
                assert!(values.contains(&"HDD".to_string()));
                assert!(values.contains(&"SSD".to_string()));
            }
            err => panic!("expected device-class disagreement, got {err}"),
        }
    }

    #[test]
    fn pool_import_label_agreement_rejects_destroyed_pool_state() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label_with_authority(
                &mut f,
                [0xA4u8; 16],
                [0x50u8; 16],
                "destroyed",
                0,
                1,
                PoolState::Destroyed,
                PoolRedundancyPolicy::replicated(1),
                DeviceClass::Hdd,
                0,
                0,
            );
        }

        match pool_import(&[dev_path], &dir.path().join("locks"), false, None, None).unwrap_err() {
            ImportError::BadPoolState { state } => assert_eq!(state, "DESTROYED"),
            err => panic!("expected destroyed pool-state rejection, got {err}"),
        }
    }

    #[test]
    fn pool_import_label_agreement_rejects_unsupported_feature_flags() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        let unsupported = 1u64 << 63;
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label_with_authority(
                &mut f,
                [0xA5u8; 16],
                [0x60u8; 16],
                "bad_feature",
                0,
                1,
                PoolState::Exported,
                PoolRedundancyPolicy::replicated(1),
                DeviceClass::Hdd,
                unsupported,
                0,
            );
            f.seek(SeekFrom::Start(
                crate::committed_root::COMMIT_RECORD_REGION_OFFSET,
            ))
            .unwrap();
            f.write_all(b"not a supported commit-record region")
                .unwrap();
            f.flush().unwrap();
        }

        match pool_import(&[dev_path], &dir.path().join("locks"), false, None, None).unwrap_err() {
            ImportError::IncompatibleFeatures { unsupported: found } => {
                assert_eq!(found, unsupported);
            }
            err => panic!("expected unsupported feature rejection, got {err}"),
        }
    }

    #[test]
    fn pool_import_replays_committed_root_and_intent_log() {
        use tidefs_commit_group::{seal_commit_hash, CommitGroupId, CommitRecord};
        use tidefs_intent_log::{IntentLogFrame, IntentLogRecord, IntentLogWriter};

        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        let system_area_pointer = 253_952u64;
        let system_area_size = 16_384u64;
        let recovery_commit_group = 2u64;

        let segment = {
            let mut writer = IntentLogWriter::new(1024 * 1024);
            let record = IntentLogRecord::Write {
                ino: 1,
                offset: 0,
                length: 0,
                data_hash: [0xAA; 32],
            };
            let frame = IntentLogFrame::new(record, 1, 5);
            writer.append_frame(&frame).unwrap();
            writer.finish().unwrap().unwrap()
        };

        {
            let mut f = File::create(&dev_path).unwrap();
            f.set_len(DATA_REGION_OFFSET + segment.len() as u64 + 4096)
                .unwrap();

            let mut label = PoolLabelV1::new([0xAAu8; 16], [0x01u8; 16], "import_replay");
            label.pool_state = PoolState::Active;
            label.commit_group = recovery_commit_group;
            label.label_commit_group = recovery_commit_group;
            label.topology_generation = 1;
            label.device_count = 1;
            label.system_area_pointer = system_area_pointer;
            label.system_area_size = system_area_size;
            let sealed = seal_label(label).unwrap();
            let mut label_buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut label_buf).unwrap();
            f.seek(SeekFrom::Start(0)).unwrap();
            f.write_all(&label_buf).unwrap();
            f.write_all(&vec![
                0u8;
                tidefs_types_pool_label_core::POOL_LABEL_SIZE
                    - POOL_LABEL_V1_EXT_WIRE_SIZE
            ])
            .unwrap();

            let record1 = CommitRecord {
                epoch_number: 1,
                commit_group_id: CommitGroupId(1),
                commit_hash: seal_commit_hash(1, CommitGroupId(1), None, &[11]),
                prior_epoch_hash: None,
                dirty_object_count: 1,
            };
            let record2 = CommitRecord {
                epoch_number: 2,
                commit_group_id: CommitGroupId(recovery_commit_group),
                commit_hash: seal_commit_hash(
                    2,
                    CommitGroupId(recovery_commit_group),
                    Some(record1.commit_hash),
                    &[22],
                ),
                prior_epoch_hash: Some(record1.commit_hash),
                dirty_object_count: 1,
            };
            let encoded_root_region = crate::committed_root::encode_commit_record_region(&[
                crate::committed_root::parsed_record_from_commit_record(&record1, &[11]),
                crate::committed_root::parsed_record_from_commit_record(&record2, &[22]),
            ]);
            f.seek(SeekFrom::Start(
                crate::committed_root::COMMIT_RECORD_REGION_OFFSET,
            ))
            .unwrap();
            f.write_all(&encoded_root_region).unwrap();

            let mut vrbt =
                encode_initial_vrbt(recovery_commit_group, system_area_pointer, system_area_size)
                    .unwrap();
            vrbt[48..56].copy_from_slice(&(segment.len() as u64).to_le_bytes());
            let hash = blake3::hash(&vrbt[..VRBT_HEADER_SIZE]);
            vrbt[VRBT_HASH_OFFSET..VRBT_WIRE_SIZE].copy_from_slice(hash.as_bytes());
            f.seek(SeekFrom::Start(
                system_area_pointer + (VRBT_BLOCK_INDEX as u64) * 4096,
            ))
            .unwrap();
            f.write_all(&vrbt).unwrap();

            f.seek(SeekFrom::Start(DATA_REGION_OFFSET)).unwrap();
            f.write_all(&segment).unwrap();
            f.flush().unwrap();
        }

        let lock_dir = dir.path().join("locks");
        let imported = pool_import(&[dev_path.clone()], &lock_dir, false, None, None).unwrap();

        println!(
            "pool_import_s1_s3 committed_root_epoch={} intent_log_replayed={}",
            imported.stats.committed_root_epoch.unwrap_or_default(),
            imported.stats.intent_log_replayed
        );

        assert_eq!(imported.config.pool_name, "import_replay");
        assert_eq!(imported.stats.committed_root_epoch, Some(2));
        assert_eq!(imported.stats.intent_log_replayed, 1);
        assert!(imported.stats.superblock_verified);
        assert!(!imported.stats.read_only);
    }

    #[test]
    fn pool_import_single_device_ro() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "import_ro");
        }
        let lock_dir = dir.path().join("locks");

        let result = pool_import(&[dev_path], &lock_dir, true, None, None).unwrap();
        assert_eq!(result.config.pool_name, "import_ro");
        assert!(result.stats.read_only);
    }

    #[test]
    fn pool_import_activation_preserves_created_committed_root() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let f = File::create(&dev_path).unwrap();
            f.set_len(2 * 1024 * 1024).unwrap();
        }
        let config = crate::create::PoolCreateConfig {
            pool_name: "preserve_root".into(),
            pool_guid: Some([0xBCu8; 16]),
            redundancy: crate::create::RedundancyPolicy::replicated(1),
            encryption_key: None,
            clustered: false,
        };
        crate::create::PoolCreator::create_pool(&[dev_path.clone()], &config).unwrap();

        pool_import(
            &[dev_path.clone()],
            &dir.path().join("locks1"),
            false,
            None,
            None,
        )
        .unwrap();
        let reopened =
            pool_import(&[dev_path], &dir.path().join("locks2"), false, None, None).unwrap();

        assert_eq!(reopened.config.pool_name, "preserve_root");
        assert_eq!(
            reopened.config.state,
            PoolState::Active,
            "activation must preserve the committed-root seed written by pool create",
        );
    }

    #[test]
    fn pool_import_encrypted_pool_preserves_encryption_flag() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let f = File::create(&dev_path).unwrap();
            f.set_len(2 * 1024 * 1024).unwrap();
        }

        // Generate a single key used for both create and import so
        // fingerprints match across the lifecycle.
        let pool_key = StoreKey::generate();
        let config = crate::create::PoolCreateConfig {
            pool_name: "encrypted_pool".into(),
            pool_guid: Some([0xECu8; 16]),
            redundancy: crate::create::RedundancyPolicy::replicated(1),
            encryption_key: Some(pool_key.clone()),
            clustered: false,
        };

        // Create encrypted pool — should set ENCRYPTION_INCOMPAT on labels.
        let outcome =
            crate::create::PoolCreator::create_pool(&[dev_path.clone()], &config).unwrap();
        assert!(
            outcome.encrypted,
            "PoolCreateOutcome.encrypted must be true"
        );
        assert!(
            outcome.encryption_key_fingerprint.is_some(),
            "encrypted pool must have a key fingerprint"
        );

        // Import — fingerprint must match the one from creation.
        let import_key = Some(pool_key.clone());
        let imported = pool_import(
            &[dev_path.clone()],
            &dir.path().join("locks1"),
            false,
            import_key,
            None,
        )
        .unwrap();
        assert!(
            imported.stats.encrypted,
            "PoolImportStats.encrypted must be true after importing encrypted pool"
        );
        assert_eq!(imported.config.pool_name, "encrypted_pool");
        assert_eq!(
            imported.stats.key_fingerprint, outcome.encryption_key_fingerprint,
            "import key fingerprint must match create key fingerprint"
        );

        // Re-import after activation — encryption and fingerprint must survive.
        let reopened = pool_import(
            &[dev_path],
            &dir.path().join("locks2"),
            false,
            Some(pool_key),
            None,
        )
        .unwrap();
        assert!(
            reopened.stats.encrypted,
            "encryption flag must survive re-import"
        );
        assert_eq!(
            reopened.stats.key_fingerprint, outcome.encryption_key_fingerprint,
            "re-import key fingerprint must match create key fingerprint"
        );
    }

    #[test]
    fn pool_import_preserves_erasure_policy_after_activation() {
        let dir = tempfile::tempdir().unwrap();
        let dev0 = dir.path().join("device0");
        let dev1 = dir.path().join("device1");
        let dev2 = dir.path().join("device2");
        for path in [&dev0, &dev1, &dev2] {
            let f = File::create(path).unwrap();
            f.set_len(2 * 1024 * 1024).unwrap();
        }

        let policy = PoolRedundancyPolicy::erasure(2, 1);
        let config = crate::create::PoolCreateConfig {
            pool_name: "erasure_import".into(),
            pool_guid: Some([0xE1u8; 16]),
            redundancy: policy,
            encryption_key: None,
            clustered: false,
        };
        crate::create::PoolCreator::create_pool(
            &[dev0.clone(), dev1.clone(), dev2.clone()],
            &config,
        )
        .unwrap();

        let imported = pool_import(
            &[dev0.clone(), dev1.clone(), dev2.clone()],
            &dir.path().join("locks1"),
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(imported.config.redundancy_policy, policy);

        for (path, expected_index) in [(&dev0, 0), (&dev1, 1), (&dev2, 2)] {
            let mut handle = DeviceHandle::open_ro(path, expected_index).unwrap();
            let label =
                tidefs_types_pool_label_core::decode_label(&handle.read_label_bytes().unwrap())
                    .unwrap();
            assert_eq!(label.pool_state, PoolState::Active);
            assert_eq!(label.redundancy_policy, policy);
        }

        let reopened = pool_import(
            &[dev0, dev1, dev2],
            &dir.path().join("locks2"),
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(reopened.config.redundancy_policy, policy);
    }

    #[test]
    fn pool_import_encrypted_pool_refuses_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let f = File::create(&dev_path).unwrap();
            f.set_len(2 * 1024 * 1024).unwrap();
        }
        let config = crate::create::PoolCreateConfig {
            pool_name: "enc_nokey".into(),
            pool_guid: Some([0xEDu8; 16]),
            redundancy: crate::create::RedundancyPolicy::replicated(1),
            encryption_key: Some(StoreKey::generate()),
            clustered: false,
        };
        crate::create::PoolCreator::create_pool(&[dev_path.clone()], &config).unwrap();

        // Import without a key must fail for an encrypted pool.
        let result = pool_import(&[dev_path], &dir.path().join("locks"), false, None, None);
        assert!(
            result.is_err(),
            "encrypted pool import without key must fail"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("encryption key"),
            "error must mention encryption key: {err}"
        );
    }

    #[test]
    fn pool_import_no_labels_fails() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("emptydev");
        File::create(&dev_path).unwrap();
        let lock_dir = dir.path().join("locks");

        let result = pool_import(&[dev_path], &lock_dir, false, None, None);
        assert!(result.is_err());
    }

    // -- activation tests --

    #[test]
    fn activate_pool_single_device_writes_active_label() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "activate_me");
        }

        let config = make_single_device_config(dev_path.clone());
        let lock_dir = dir.path().join("locks");
        let mut import = PoolImport::new(config, &lock_dir, None, None);

        // Run the full import (rw) — this calls activate_pool().
        let stats = import.import().unwrap();
        assert!(stats.superblock_verified);
        assert!(!stats.read_only);

        // Re-open the device and read back the label to verify activation.
        let mut handle = DeviceHandle::open_rw(&dev_path, 0).unwrap();
        let buf = handle.read_label_bytes().unwrap();
        let label = tidefs_types_pool_label_core::decode_label(&buf)
            .expect("re-read label should be valid");
        assert_eq!(
            label.pool_state,
            tidefs_types_pool_label_core::PoolState::Active,
            "label must show ACTIVE after activation"
        );
        // commit_group should be >= 0 and match what was recorded.
        assert!(label.commit_group <= import.recovery_commit_group);
    }

    #[test]
    fn activate_pool_preserves_device_identity() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        let device_guid: [u8; 16] = [0x42u8; 16];
        {
            let mut f = File::create(&dev_path).unwrap();
            // Write a label with a custom device_guid.
            let mut label = tidefs_types_pool_label_core::PoolLabelV1::new(
                [0xAAu8; 16],
                device_guid,
                "ident_test",
            );
            label.commit_group = 0;
            let sealed = tidefs_types_pool_label_core::seal_label(label).unwrap();
            let mut buf = [0u8; tidefs_types_pool_label_core::POOL_LABEL_V1_EXT_WIRE_SIZE];
            tidefs_types_pool_label_core::encode_label(&sealed, &mut buf).unwrap();
            let pad = vec![
                0u8;
                tidefs_types_pool_label_core::POOL_LABEL_SIZE
                    - tidefs_types_pool_label_core::POOL_LABEL_V1_EXT_WIRE_SIZE
            ];
            f.write_all(&buf).unwrap();
            f.write_all(&pad).unwrap();
            f.flush().unwrap();
        }

        let config = make_single_device_config(dev_path.clone());
        let lock_dir = dir.path().join("locks");
        let mut import = PoolImport::new(config, &lock_dir, None, None);
        import.import().unwrap();

        // Re-read and verify device_guid preserved.
        let mut handle = DeviceHandle::open_rw(&dev_path, 0).unwrap();
        let buf = handle.read_label_bytes().unwrap();
        let label = tidefs_types_pool_label_core::decode_label(&buf).unwrap();
        assert_eq!(label.device_guid, device_guid);
        assert_eq!(
            label.pool_state,
            tidefs_types_pool_label_core::PoolState::Active
        );
    }

    #[test]
    fn activate_pool_read_only_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "ro_skip");
        }

        let config = make_single_device_config(dev_path.clone());
        let lock_dir = dir.path().join("locks");
        let mut import = PoolImport::new(config, &lock_dir, None, None);
        let stats = import.import_readonly().unwrap();
        assert!(stats.read_only);

        // Re-open to verify label was NOT changed to Active.
        let mut handle = DeviceHandle::open_ro(&dev_path, 0).unwrap();
        let buf = handle.read_label_bytes().unwrap();
        let label = tidefs_types_pool_label_core::decode_label(&buf).unwrap();
        // The test label is created with Active by default in
        // write_test_label, so it starts Active.  The point is the
        // read-only path didn't re-write it.  The label is still valid.
        assert_eq!(
            label.pool_state,
            tidefs_types_pool_label_core::PoolState::Active
        );
    }

    #[test]
    fn write_label_bytes_preserves_reserved_label_area() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        // Create a file whose label-reserved suffix stands in for the
        // commit-record/system area sharing the primary label region.
        {
            let mut f = File::create(&dev_path).unwrap();
            f.write_all(&vec![0xAAu8; tidefs_types_pool_label_core::POOL_LABEL_SIZE])
                .unwrap();
            f.flush().unwrap();
        }

        let test_pattern: Vec<u8> = (0..tidefs_types_pool_label_core::POOL_LABEL_SIZE)
            .map(|i| (i % 251) as u8)
            .collect();

        // Write the pattern.
        let mut handle = DeviceHandle::open_rw(&dev_path, 0).unwrap();
        handle.write_label_bytes(&test_pattern).unwrap();

        let read_back = std::fs::read(&dev_path).unwrap();
        assert_eq!(
            &read_back[..tidefs_types_pool_label_core::POOL_LABEL_V1_EXT_WIRE_SIZE],
            &test_pattern[..tidefs_types_pool_label_core::POOL_LABEL_V1_EXT_WIRE_SIZE],
        );
        assert!(
            read_back[tidefs_types_pool_label_core::POOL_LABEL_V1_EXT_WIRE_SIZE..]
                .iter()
                .all(|b| *b == 0xAA),
            "nonzero label rewrites must not clobber reserved commit/system area",
        );

        let zeroes = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
        handle.write_label_bytes(&zeroes).unwrap();
        let cleared = std::fs::read(&dev_path).unwrap();
        assert!(cleared.iter().all(|b| *b == 0));
    }
    // -- pool_export tests --

    #[test]
    fn pool_export_transitions_to_exported() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "export_me");
        }
        let lock_dir = dir.path().join("locks");

        let result = pool_import(&[dev_path.clone()], &lock_dir, false, None, None).unwrap();
        assert_eq!(result.config.state, PoolState::Active);

        pool_export(&[dev_path.clone()], &lock_dir, false).unwrap();

        let mut handle = DeviceHandle::open_ro(&dev_path, 0).unwrap();
        let buf = handle.read_label_bytes().unwrap();
        let label = tidefs_types_pool_label_core::decode_label(&buf).unwrap();
        assert_eq!(
            label.pool_state,
            tidefs_types_pool_label_core::PoolState::Exported,
            "label must show Exported after pool_export"
        );
    }

    #[test]
    fn pool_export_force_on_already_exported() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "force_export");
        }
        let lock_dir = dir.path().join("locks");

        pool_import(&[dev_path.clone()], &lock_dir, false, None, None).unwrap();
        pool_export(&[dev_path.clone()], &lock_dir, false).unwrap();
        pool_export(&[dev_path.clone()], &lock_dir, true).unwrap();

        let mut handle = DeviceHandle::open_ro(&dev_path, 0).unwrap();
        let buf = handle.read_label_bytes().unwrap();
        let label = tidefs_types_pool_label_core::decode_label(&buf).unwrap();
        assert_eq!(
            label.pool_state,
            tidefs_types_pool_label_core::PoolState::Exported
        );
    }

    #[test]
    fn pool_export_removes_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "lock_remove");
        }
        let lock_dir = dir.path().join("locks");

        pool_import(&[dev_path.clone()], &lock_dir, false, None, None).unwrap();
        let entries = tidefs_pool_scan::scan_labels(&[dev_path.clone()]).unwrap();
        let config = tidefs_pool_scan::PoolAssembler::assemble(&entries, None).unwrap();
        let lock_path = lock_dir.join(hex_uuid(&config.pool_uuid));
        assert!(
            lock_path.exists(),
            "import lock file should exist after import"
        );

        pool_export(&[dev_path.clone()], &lock_dir, false).unwrap();
        assert!(
            !lock_path.exists(),
            "import lock file should be removed after export"
        );
    }

    #[test]
    fn pool_import_export_roundtrip_transitions_all_devices() {
        let dir = tempfile::tempdir().unwrap();
        let pool_guid = [0x5Au8; 16];
        let dev0 = dir.path().join("device0");
        let dev1 = dir.path().join("device1");
        {
            let mut f = File::create(&dev0).unwrap();
            write_test_label_for_device(
                &mut f,
                pool_guid,
                [0xA0u8; 16],
                "multi_export",
                0,
                2,
                PoolState::Exported,
            );
        }
        {
            let mut f = File::create(&dev1).unwrap();
            write_test_label_for_device(
                &mut f,
                pool_guid,
                [0xA1u8; 16],
                "multi_export",
                1,
                2,
                PoolState::Exported,
            );
        }
        let lock_dir = dir.path().join("locks");

        let imported =
            pool_import(&[dev0.clone(), dev1.clone()], &lock_dir, false, None, None).unwrap();
        assert_eq!(imported.config.device_count, 2);
        assert_eq!(imported.config.state, PoolState::Exported);

        for (path, expected_index) in [(&dev0, 0), (&dev1, 1)] {
            let mut handle = DeviceHandle::open_ro(path, expected_index).unwrap();
            let label =
                tidefs_types_pool_label_core::decode_label(&handle.read_label_bytes().unwrap())
                    .unwrap();
            assert_eq!(label.pool_state, PoolState::Active);
            assert_eq!(label.device_index, expected_index);
            assert_eq!(label.device_count, 2);
            assert_eq!(label.pool_guid, pool_guid);
        }

        pool_export(&[dev0.clone(), dev1.clone()], &lock_dir, false).unwrap();

        for (path, expected_index) in [(&dev0, 0), (&dev1, 1)] {
            let mut handle = DeviceHandle::open_ro(path, expected_index).unwrap();
            let label =
                tidefs_types_pool_label_core::decode_label(&handle.read_label_bytes().unwrap())
                    .unwrap();
            assert_eq!(label.pool_state, PoolState::Exported);
            assert_eq!(label.device_index, expected_index);
            assert_eq!(label.device_count, 2);
            assert_eq!(label.pool_guid, pool_guid);
        }
    }

    // -- pool_destroy tests --

    #[test]
    fn pool_destroy_transitions_to_destroyed() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "destroy_me");
        }

        pool_destroy(&[dev_path.clone()], false).unwrap();

        let mut handle = DeviceHandle::open_ro(&dev_path, 0).unwrap();
        let buf = handle.read_label_bytes().unwrap();
        let label = tidefs_types_pool_label_core::decode_label(&buf).unwrap();
        assert_eq!(
            label.pool_state,
            tidefs_types_pool_label_core::PoolState::Destroyed,
            "label must show Destroyed after pool_destroy"
        );
    }

    #[test]
    fn pool_destroy_zero_superblock_zeroes_label() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            write_test_label(&mut f, "zero_me");
        }

        pool_destroy(&[dev_path.clone()], true).unwrap();

        // After zero_superblock, the label area should be all zeros.
        let mut handle = DeviceHandle::open_ro(&dev_path, 0).unwrap();
        let buf = handle.read_label_bytes().unwrap();
        assert!(
            buf.iter().all(|&b| b == 0),
            "label area must be zeroed after pool_destroy with zero_superblock"
        );
    }

    // ── decode_vrbt tests ────────────────────────────────────────

    #[test]
    fn decode_vrbt_valid() {
        let mut vrbt = [0u8; 88];
        vrbt[0..4].copy_from_slice(b"VRBT");
        vrbt[4..8].copy_from_slice(&1u32.to_le_bytes());
        vrbt[8..16].copy_from_slice(&42u64.to_le_bytes());
        vrbt[16..24].copy_from_slice(&10u64.to_le_bytes());
        vrbt[24..32].copy_from_slice(&20u64.to_le_bytes());
        vrbt[32..40].copy_from_slice(&30u64.to_le_bytes());
        vrbt[40..48].copy_from_slice(&100u64.to_le_bytes());
        vrbt[48..56].copy_from_slice(&500u64.to_le_bytes());
        let hash = blake3::hash(&vrbt[..56]);
        vrbt[56..88].copy_from_slice(hash.as_bytes());

        let parsed = decode_vrbt(&vrbt).expect("valid VRBT should decode");
        assert_eq!(parsed.committed_txg, 42);
        assert_eq!(parsed.intent_log_head, 100);
        assert_eq!(parsed.intent_log_tail, 500);
    }

    #[test]
    fn decode_vrbt_bad_magic() {
        let mut vrbt = [0u8; 88];
        vrbt[0..4].copy_from_slice(b"BAD!");
        vrbt[4..8].copy_from_slice(&1u32.to_le_bytes());
        let hash = blake3::hash(&vrbt[..56]);
        vrbt[56..88].copy_from_slice(hash.as_bytes());
        assert!(decode_vrbt(&vrbt).is_none());
    }

    #[test]
    fn decode_vrbt_bad_hash() {
        let mut vrbt = [0u8; 88];
        vrbt[0..4].copy_from_slice(b"VRBT");
        vrbt[4..8].copy_from_slice(&1u32.to_le_bytes());
        // hash bytes are zero — invalid
        assert!(decode_vrbt(&vrbt).is_none());
    }

    #[test]
    fn decode_vrbt_buffer_too_short() {
        let short = [0u8; 40];
        assert!(decode_vrbt(&short).is_none());
    }

    #[test]
    fn decode_vrbt_unsupported_version() {
        let mut vrbt = [0u8; 88];
        vrbt[0..4].copy_from_slice(b"VRBT");
        vrbt[4..8].copy_from_slice(&99u32.to_le_bytes());
        let hash = blake3::hash(&vrbt[..56]);
        vrbt[56..88].copy_from_slice(hash.as_bytes());
        assert!(decode_vrbt(&vrbt).is_none());
    }

    #[test]
    fn decode_vrbt_zero_tail_is_valid() {
        let mut vrbt = [0u8; 88];
        vrbt[0..4].copy_from_slice(b"VRBT");
        vrbt[4..8].copy_from_slice(&1u32.to_le_bytes());
        vrbt[40..48].copy_from_slice(&0u64.to_le_bytes());
        vrbt[48..56].copy_from_slice(&0u64.to_le_bytes());
        let hash = blake3::hash(&vrbt[..56]);
        vrbt[56..88].copy_from_slice(hash.as_bytes());
        let parsed = decode_vrbt(&vrbt).expect("zero-tail VRBT should decode");
        assert_eq!(parsed.intent_log_tail, 0);
    }

    // ── replay_intent_log_data tests ──────────────────────────────

    #[test]
    fn replay_intent_log_data_empty() {
        let result = replay_intent_log_data(&[], 0).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn replay_intent_log_data_corrupt() {
        let corrupt = vec![0xFFu8; 256];
        let result = replay_intent_log_data(&corrupt, 0);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("corrupt") || msg.contains("segment"));
    }

    #[test]
    fn replay_intent_log_data_with_records() {
        use tidefs_intent_log::{IntentLogFrame, IntentLogRecord, IntentLogWriter};
        let mut writer = IntentLogWriter::new(1024 * 1024);
        let rec = IntentLogRecord::Write {
            ino: 1,
            offset: 0,
            length: 0,
            data_hash: [0xAA; 32],
        };
        // record_seq=5 is the LSN used for filtering.
        let frame = IntentLogFrame::new(rec, 1, 5);
        writer.append_frame(&frame).unwrap();
        let segment = writer.finish().unwrap().unwrap();

        // recovery_txg=5 → lsn=5 is not > 5, so skipped.
        assert_eq!(replay_intent_log_data(&segment, 5).unwrap(), 0);
        // recovery_txg=3 < lsn=5 → replayed.
        assert_eq!(replay_intent_log_data(&segment, 3).unwrap(), 1);
    }

    // ── VRBT readback from device ─────────────────────────────────

    #[test]
    fn read_vrbt_from_device_system_area() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            let mut label = tidefs_types_pool_label_core::PoolLabelV1::new(
                [0xAAu8; 16],
                [0xBBu8; 16],
                "vrbt_test",
            );
            label.commit_group = 1;
            label.system_area_pointer = 253952;
            label.system_area_size = 16384;
            let sealed = tidefs_types_pool_label_core::seal_label(label).unwrap();
            let mut label_buf = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
            tidefs_types_pool_label_core::encode_label(&sealed, &mut label_buf).unwrap();
            f.write_all(&label_buf).unwrap();

            // Extend the file so the system area read can succeed.
            // The system area spans [253952, 253952+16384) = [253952, 270336).
            let end_of_system_area = 253952u64 + 16384u64;
            let mut vrbt = [0u8; 88];
            vrbt[0..4].copy_from_slice(b"VRBT");
            vrbt[4..8].copy_from_slice(&1u32.to_le_bytes());
            vrbt[40..48].copy_from_slice(&DATA_REGION_OFFSET.to_le_bytes());
            let hash = blake3::hash(&vrbt[..56]);
            vrbt[56..88].copy_from_slice(hash.as_bytes());
            use std::io::Seek;
            // Write VRBT at its position (266240).
            f.seek(SeekFrom::Start(266240)).unwrap();
            f.write_all(&vrbt).unwrap();
            // Extend file to cover full system area read range.
            f.seek(SeekFrom::Start(end_of_system_area - 1)).unwrap();
            f.write_all(&[0u8]).unwrap();
            f.flush().unwrap();
        }

        let mut handle = DeviceHandle::open_rw(&dev_path, 0).unwrap();
        let sa_buf = handle.read_bytes_at(253952, 16384).unwrap();
        let vrbt_off = (VRBT_BLOCK_INDEX as u64) * 4096;
        let vrbt_bytes = &sa_buf[vrbt_off as usize..(vrbt_off as usize) + VRBT_WIRE_SIZE];
        let parsed = decode_vrbt(vrbt_bytes).expect("VRBT from device should be valid");
        assert_eq!(parsed.intent_log_tail, 0);
    }

    // ── encode_initial_vrbt tests ─────────────────────────────────

    #[test]
    fn encode_initial_vrbt_produces_valid_block() {
        let vrbt = encode_initial_vrbt(42, 253952, 16384).expect("should encode VRBT");
        assert_eq!(vrbt.len(), 88);
        // Verify it decodes back.
        let parsed = decode_vrbt(&vrbt).expect("encoded VRBT should be valid");
        assert_eq!(parsed.committed_txg, 42);
        assert_eq!(parsed.intent_log_head, DATA_REGION_OFFSET);
        assert_eq!(parsed.intent_log_tail, 0);
    }

    #[test]
    fn encode_initial_vrbt_system_area_too_small() {
        // system_area_size = 4096 (only 1 block), VRBT_BLOCK_INDEX=3 requires 4 blocks
        assert!(encode_initial_vrbt(1, 0, 4096).is_none());
    }

    #[test]
    fn activate_pool_writes_initial_vrbt() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        {
            let mut f = File::create(&dev_path).unwrap();
            // Write a label with system_area_pointer pointing past the label area.
            let mut label = tidefs_types_pool_label_core::PoolLabelV1::new(
                [0xAAu8; 16],
                [0xBBu8; 16],
                "vrbt_activate",
            );
            label.commit_group = 0;
            label.system_area_pointer = 253952;
            label.system_area_size = 16384;
            let sealed = tidefs_types_pool_label_core::seal_label(label).unwrap();
            let mut label_buf = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
            tidefs_types_pool_label_core::encode_label(&sealed, &mut label_buf).unwrap();
            f.write_all(&label_buf).unwrap();
            // Extend file so the system area write can succeed.
            use std::io::Seek;
            let vrbt_end = 253952u64 + (VRBT_BLOCK_INDEX as u64 + 1) * 4096;
            f.seek(SeekFrom::Start(vrbt_end - 1)).unwrap();
            f.write_all(&[0u8]).unwrap();
            f.flush().unwrap();
        }

        let config = make_single_device_config(dev_path.clone());
        let lock_dir = dir.path().join("locks");
        let mut import = PoolImport::new(config, &lock_dir, None, None);
        import.import().unwrap();

        // Read back the VRBT from the system area.
        let mut handle = DeviceHandle::open_rw(&dev_path, 0).unwrap();
        let sa_buf = handle.read_bytes_at(253952, 16384).unwrap();
        let vrbt_off = (VRBT_BLOCK_INDEX as u64) * 4096;
        let vrbt_bytes = &sa_buf[vrbt_off as usize..(vrbt_off as usize) + VRBT_WIRE_SIZE];
        let parsed =
            decode_vrbt(vrbt_bytes).expect("VRBT should have been written during activation");
        assert_eq!(parsed.intent_log_tail, 0);
        // committed_txg should match the recovery commit_group (1 after activation).
        // committed_txg matches the recovery commit_group (may be 0 for a fresh pool).
        assert!(parsed.committed_txg <= 1);
    }
}
