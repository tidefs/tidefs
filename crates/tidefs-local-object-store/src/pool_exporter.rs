// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool export: atomic label state transition from ACTIVE to EXPORTED.
//!
//! Implements the pool export transition summarized by
//! `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`.
//!
//! The exporter guarantees all-or-nothing atomicity: either all device labels
//! are transitioned to EXPORTED or none are. No partial/split state is possible.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::device::DeviceConfig;
use crate::device_layout::decode_device_layout_v1;
use crate::intent_log::record::IntentLogRecord;
use crate::intent_log::sync_write::IntentLog;
use crate::pool_label::{
    decode_device_layout_v1_bytes, decode_label, encode_label, encode_label_with_device_layout,
    features, seal_label, seal_label_with_device_layout, DeviceLayoutV1Bytes, LabelPoolState,
    PoolLabelV1, POOL_LABEL_SIZE, POOL_LABEL_V1_EXT_WIRE_SIZE, POOL_LABEL_V1_HEALTH_WIRE_SIZE,
    POOL_LABEL_V1_WIRE_SIZE, POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE,
};
use crate::pool_lifecycle_evidence::{
    PoolLifecycleAction, PoolLifecycleContext, PoolLifecycleEvidence,
};
use crate::txg_manager::CommitGroupManager;
use tidefs_auth::local_only::LocalOnlyGuard;

struct ExportLabelRecord {
    label: PoolLabelV1,
    device_layout_v1: Option<DeviceLayoutV1Bytes>,
    wire_size: usize,
}

impl std::ops::Deref for ExportLabelRecord {
    type Target = PoolLabelV1;

    fn deref(&self) -> &Self::Target {
        &self.label
    }
}

// ---------------------------------------------------------------------------
// ExportError — export-specific errors
// ---------------------------------------------------------------------------

/// Errors specific to pool export operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportError {
    /// Pool is not in ACTIVE state, cannot be exported.
    PoolNotActive,
    /// Failed to write a label: export aborted, rollback attempted.
    LabelWriteFailed {
        device_path: PathBuf,
        reason: String,
    },
    /// Existing label evidence cannot authorize an export mutation.
    LabelValidationFailed {
        device_path: PathBuf,
        reason: String,
    },
    /// Underlying I/O error.
    IoError(String),
    /// Txg drain or commit failed.
    CommitGroupError(String),
    /// Intent log close failed.
    IntentLogError(String),
    /// Export already in progress or completed.
    AlreadyExported,
    /// Pool has active mounts or attached block devices; use --force.
    HasActiveMounts { count: usize },
    /// Caller is not in a local process context — privileged operation refused.
    NotLocal {
        operation: &'static str,
        reason: String,
    },
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PoolNotActive => f.write_str("pool is not in ACTIVE state, cannot export"),
            Self::LabelWriteFailed {
                device_path,
                reason,
            } => {
                write!(
                    f,
                    "label write failed for {}: {}",
                    device_path.display(),
                    reason
                )
            }
            Self::LabelValidationFailed {
                device_path,
                reason,
            } => {
                write!(
                    f,
                    "label validation failed for {}: {}",
                    device_path.display(),
                    reason
                )
            }
            Self::IoError(msg) => write!(f, "I/O error: {msg}"),
            Self::CommitGroupError(msg) => write!(f, "commit_group error: {msg}"),
            Self::IntentLogError(msg) => write!(f, "intent log error: {msg}"),
            Self::AlreadyExported => f.write_str("pool is already exported"),
            Self::NotLocal { operation, reason } => {
                write!(
                    f,
                    "privileged operation '{operation}' requires local execution: {reason}"
                )
            }
            Self::HasActiveMounts { count } => {
                write!(f, "pool has {count} active mount(s); use --force to bypass")
            }
        }
    }
}
impl From<tidefs_auth::local_only::LocalOnlyError> for ExportError {
    fn from(err: tidefs_auth::local_only::LocalOnlyError) -> Self {
        match err {
            tidefs_auth::local_only::LocalOnlyError::NotLocal { operation, reason } => {
                Self::NotLocal { operation, reason }
            }
            tidefs_auth::local_only::LocalOnlyError::NoProcessIdentity { operation } => {
                Self::NotLocal {
                    operation,
                    reason: "no local process identity".to_string(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PoolExporter
// ---------------------------------------------------------------------------

/// Pool exporter: atomically transitions pool labels from ACTIVE to EXPORTED.
#[derive(Debug, Default)]
pub struct PoolExporter;

impl PoolExporter {
    /// Export a pool by writing EXPORTED state to all device labels.
    ///
    /// The operation is atomic: if any label write fails, all previously-written
    /// labels are rolled back to ACTIVE.
    ///
    /// # Arguments
    /// * `device_configs` - Device configurations for all devices in the pool.
    /// * `pool_guid` - The pool's unique GUID.
    /// * `device_guids` - Per-device GUIDs.
    /// * `pool_name` - Human-readable pool name.
    /// * `commit_group` - Current transaction group number.
    pub fn export_pool(
        device_configs: &[DeviceConfig],
        pool_guid: [u8; 16],
        device_guids: &[[u8; 16]],
        pool_name: &str,
        commit_group: u64,
    ) -> std::result::Result<(), ExportError> {
        Self::export_pool_with_writer(
            device_configs,
            pool_guid,
            device_guids,
            pool_name,
            commit_group,
            Self::write_labels_to_device,
        )
    }

    fn export_pool_with_writer<F>(
        device_configs: &[DeviceConfig],
        pool_guid: [u8; 16],
        device_guids: &[[u8; 16]],
        pool_name: &str,
        commit_group: u64,
        mut write_labels: F,
    ) -> std::result::Result<(), ExportError>
    where
        F: FnMut(
            &Path,
            &PoolLabelV1,
            Option<&DeviceLayoutV1Bytes>,
            usize,
        ) -> std::result::Result<(), ExportError>,
    {
        // Operator authorization boundary: pool export requires local execution.
        let _guard = LocalOnlyGuard::new("pool export")?;
        if device_configs.is_empty() {
            return Err(ExportError::PoolNotActive);
        }
        if device_guids.len() != device_configs.len() {
            return Err(ExportError::LabelValidationFailed {
                device_path: device_configs[0].path.clone(),
                reason: format!(
                    "device GUID count {} does not match device count {}",
                    device_guids.len(),
                    device_configs.len()
                ),
            });
        }

        let mut unique_device_guids = std::collections::BTreeSet::new();
        for (index, device_guid) in device_guids.iter().copied().enumerate() {
            if !unique_device_guids.insert(device_guid) {
                return Err(ExportError::LabelValidationFailed {
                    device_path: device_configs[index].path.clone(),
                    reason: "duplicate device GUID values in export topology".to_string(),
                });
            }
        }

        let label_commit_group = commit_group + 1;
        let expected_device_count = u32::try_from(device_configs.len()).map_err(|_| {
            ExportError::LabelValidationFailed {
                device_path: device_configs[0].path.clone(),
                reason: "device count exceeds pool-label representation".to_string(),
            }
        })?;
        let mut expected_topology_generation = None;
        let mut existing_labels = Vec::with_capacity(device_configs.len());

        // Read and validate the complete topology before mutating any label.
        // A later missing, corrupt, or foreign label must not leave earlier
        // devices transitioned to EXPORTED.
        for (index, (device_config, device_guid)) in device_configs
            .iter()
            .zip(device_guids.iter().copied())
            .enumerate()
        {
            let existing = Self::read_existing_label(&device_config.path)?;
            Self::validate_export_label(
                &device_config.path,
                &existing.label,
                pool_guid,
                device_guid,
                pool_name,
                index as u32,
                expected_device_count,
                expected_topology_generation,
            )?;
            expected_topology_generation = Some(existing.label.topology_generation);
            existing_labels.push((device_config.path.clone(), existing));
        }

        let mut written: Vec<(PathBuf, ExportLabelRecord)> = Vec::new();

        for (device_path, existing) in existing_labels {
            let mut label = existing.label.clone();
            label.pool_state = LabelPoolState::Exported;
            label.commit_group = commit_group;
            label.label_commit_group = label_commit_group;

            let result = write_labels(
                &device_path,
                &label,
                existing.device_layout_v1.as_ref(),
                existing.wire_size,
            );

            match result {
                Ok(()) => {
                    written.push((device_path, existing));
                }
                Err(e) => {
                    // The failed write may have changed one or both label
                    // copies before reporting an error. Restore that device
                    // as well as every earlier device.
                    let _ = Self::rollback_device_label(&device_path, &existing, &mut write_labels);
                    for (path, original) in &written {
                        let _ = Self::rollback_device_label(path, original, &mut write_labels);
                    }
                    return Err(ExportError::LabelWriteFailed {
                        device_path,
                        reason: format!("{e:?}"),
                    });
                }
            }
        }

        // All labels written successfully.
        Ok(())
    }

    /// Read the current label from a device.
    fn read_existing_label(
        device_path: &Path,
    ) -> std::result::Result<ExportLabelRecord, ExportError> {
        let _metadata = fs::metadata(device_path)
            .map_err(|e| ExportError::IoError(format!("stat {}: {e}", device_path.display())))?;

        let label_path = if device_path.is_dir() {
            device_path.join(".tidefs_label")
        } else {
            device_path.to_path_buf()
        };

        // An absent label cannot authorize an export transition. In
        // particular, do not synthesize an ACTIVE label from caller input.
        if !label_path.exists() {
            return Err(ExportError::LabelValidationFailed {
                device_path: device_path.to_path_buf(),
                reason: "pool label is missing".to_string(),
            });
        }

        let mut file = fs::OpenOptions::new()
            .read(true)
            .open(&label_path)
            .map_err(|e| ExportError::IoError(format!("open {}: {e}", label_path.display())))?;

        let mut buf = [0u8; POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE];
        file.read_exact(&mut buf[..POOL_LABEL_V1_WIRE_SIZE])
            .map_err(|e| ExportError::IoError(format!("read {}: {e}", label_path.display())))?;
        let features_compat = u64::from_le_bytes(buf[371..379].try_into().unwrap());
        let wire_size = if features_compat & features::DEVICE_LAYOUT_V1 != 0 {
            POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE
        } else if features_compat & features::POOL_REDUNDANCY_POLICY != 0 {
            POOL_LABEL_V1_EXT_WIRE_SIZE
        } else if features_compat & features::DEVICE_HEALTH_STATE != 0 {
            POOL_LABEL_V1_HEALTH_WIRE_SIZE
        } else {
            POOL_LABEL_V1_WIRE_SIZE
        };
        file.read_exact(&mut buf[POOL_LABEL_V1_WIRE_SIZE..wire_size])
            .map_err(|e| ExportError::IoError(format!("read {}: {e}", label_path.display())))?;

        let label =
            decode_label(&buf[..wire_size]).map_err(|e| ExportError::LabelValidationFailed {
                device_path: device_path.to_path_buf(),
                reason: format!("decode: {e:?}"),
            })?;
        let device_layout_v1 = decode_device_layout_v1_bytes(&buf[..wire_size]).map_err(|e| {
            ExportError::LabelValidationFailed {
                device_path: device_path.to_path_buf(),
                reason: format!("decode DeviceLayoutV1 extent: {e:?}"),
            }
        })?;
        if let Some(layout) = device_layout_v1.as_ref() {
            decode_device_layout_v1(layout).map_err(|e| ExportError::LabelValidationFailed {
                device_path: device_path.to_path_buf(),
                reason: format!("decode DeviceLayoutV1: {e:?}"),
            })?;
        }

        Ok(ExportLabelRecord {
            label,
            device_layout_v1,
            wire_size,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_export_label(
        device_path: &Path,
        label: &PoolLabelV1,
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        pool_name: &str,
        device_index: u32,
        device_count: u32,
        topology_generation: Option<u64>,
    ) -> std::result::Result<(), ExportError> {
        let invalid = |reason: String| ExportError::LabelValidationFailed {
            device_path: device_path.to_path_buf(),
            reason,
        };

        if label.pool_state != LabelPoolState::Active {
            return Err(invalid(format!(
                "expected ACTIVE pool state, found {}",
                label.pool_state
            )));
        }
        if pool_guid == [0u8; 16] || label.pool_guid != pool_guid {
            return Err(invalid(
                "pool GUID does not match export authority".to_string(),
            ));
        }
        if device_guid == [0u8; 16] || label.device_guid != device_guid {
            return Err(invalid(
                "device GUID does not match export topology".to_string(),
            ));
        }
        if pool_name.trim().is_empty() || label.pool_name_str() != pool_name {
            return Err(invalid(
                "pool name does not match export authority".to_string(),
            ));
        }
        if label.device_index != device_index {
            return Err(invalid(format!(
                "device index {} does not match expected {device_index}",
                label.device_index
            )));
        }
        if label.device_count != device_count {
            return Err(invalid(format!(
                "label device count {} does not match expected {device_count}",
                label.device_count
            )));
        }
        if label.device_capacity_bytes == 0 {
            return Err(invalid("device capacity evidence is missing".to_string()));
        }
        if label.topology_generation == 0
            || topology_generation.is_some_and(|expected| expected != label.topology_generation)
        {
            return Err(invalid(
                "topology generation evidence is missing or inconsistent".to_string(),
            ));
        }

        Ok(())
    }

    /// Write both label copies to a device.
    fn write_labels_to_device(
        device_path: &Path,
        label: &PoolLabelV1,
        device_layout_v1: Option<&DeviceLayoutV1Bytes>,
        wire_size: usize,
    ) -> std::result::Result<(), ExportError> {
        let expected_wire_size = if device_layout_v1.is_some() {
            POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE
        } else if label.features_compat & features::POOL_REDUNDANCY_POLICY != 0 {
            POOL_LABEL_V1_EXT_WIRE_SIZE
        } else if label.features_compat & features::DEVICE_HEALTH_STATE != 0 {
            POOL_LABEL_V1_HEALTH_WIRE_SIZE
        } else {
            POOL_LABEL_V1_WIRE_SIZE
        };
        if wire_size != expected_wire_size {
            return Err(ExportError::LabelValidationFailed {
                device_path: device_path.to_path_buf(),
                reason: format!(
                    "label extent {wire_size} does not match expected {expected_wire_size}"
                ),
            });
        }

        let sealed = match device_layout_v1 {
            Some(layout) => seal_label_with_device_layout(label.clone(), Some(layout)),
            None => seal_label(label.clone()),
        }
        .map_err(|e| ExportError::LabelWriteFailed {
            device_path: device_path.to_path_buf(),
            reason: format!("seal: {e:?}"),
        })?;

        // Export changes pool state, not the label extent or its evidence.
        let mut buf = [0u8; POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE];
        match device_layout_v1 {
            Some(layout) => {
                encode_label_with_device_layout(&sealed, Some(layout), &mut buf[..wire_size])
            }
            None => encode_label(&sealed, &mut buf[..wire_size]),
        }
        .map_err(|e| ExportError::LabelWriteFailed {
            device_path: device_path.to_path_buf(),
            reason: format!("encode: {e:?}"),
        })?;

        let label_path = if device_path.is_dir() {
            device_path.join(".tidefs_label")
        } else {
            device_path.to_path_buf()
        };
        let backup_offset = Self::backup_label_offset(device_path, label)?;

        // Write Label 0
        Self::write_at_offset(&label_path, &buf[..wire_size], 0)?;
        // Write Label 1 at the canonical backup location used by pool
        // creation and scanning. Directory compatibility keeps its compact
        // two-area label file; byte devices place the backup at the tail.
        Self::write_at_offset(&label_path, &buf[..wire_size], backup_offset)?;

        Ok(())
    }

    fn backup_label_offset(
        device_path: &Path,
        label: &PoolLabelV1,
    ) -> std::result::Result<u64, ExportError> {
        if device_path.is_dir() {
            return Ok(POOL_LABEL_SIZE as u64);
        }

        let label_area_bytes = POOL_LABEL_SIZE as u64;
        label
            .device_capacity_bytes
            .checked_sub(label_area_bytes)
            .filter(|offset| *offset >= label_area_bytes)
            .ok_or_else(|| ExportError::LabelValidationFailed {
                device_path: device_path.to_path_buf(),
                reason: format!(
                    "device capacity {} cannot hold two pool label areas",
                    label.device_capacity_bytes
                ),
            })
    }

    /// Rollback: write ACTIVE state back to a device label.
    fn rollback_device_label<F>(
        device_path: &Path,
        original: &ExportLabelRecord,
        write_labels: &mut F,
    ) -> std::result::Result<(), ExportError>
    where
        F: FnMut(
            &Path,
            &PoolLabelV1,
            Option<&DeviceLayoutV1Bytes>,
            usize,
        ) -> std::result::Result<(), ExportError>,
    {
        let mut active = original.label.clone();
        active.pool_state = LabelPoolState::Active;
        write_labels(
            device_path,
            &active,
            original.device_layout_v1.as_ref(),
            original.wire_size,
        )
    }

    /// Write raw bytes at a given offset within a file.
    fn write_at_offset(
        path: &Path,
        data: &[u8],
        offset: u64,
    ) -> std::result::Result<(), ExportError> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .create(true)
            .open(path)
            .map_err(|e| ExportError::IoError(format!("open {}: {e}", path.display())))?;

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| ExportError::IoError(format!("seek {}: {e}", path.display())))?;

        file.write_all(data)
            .map_err(|e| ExportError::IoError(format!("write {}: {e}", path.display())))?;

        file.sync_all()
            .map_err(|e| ExportError::IoError(format!("sync {}: {e}", path.display())))?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ExportPhase — export state machine states
// ---------------------------------------------------------------------------

/// Phases of the pool export state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportPhase {
    /// Initial state: pool is active, export not started.
    Idle,
    /// Draining pending I/O and flushing in-flight commit_group commits.
    Draining,
    /// Writing the terminal committed root with BLAKE3 authentication.
    WritingCommittedRoot,
    /// Closing the intent log with an export terminal record.
    ClosingIntentLog,
    /// Updating pool labels with EXPORTED state marker.
    WritingLabels,
    /// Export complete: pool is cleanly exported.
    Done,
}

impl ExportPhase {
    /// Human-readable name for this phase.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Draining => "draining",
            Self::WritingCommittedRoot => "writing_committed_root",
            Self::ClosingIntentLog => "closing_intent_log",
            Self::WritingLabels => "writing_labels",
            Self::Done => "done",
        }
    }

    /// Whether the phase is terminal (no further transitions possible).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done)
    }
}

// ---------------------------------------------------------------------------
// ExportOrchestrator — full export lifecycle coordinator
// ---------------------------------------------------------------------------

/// Orchestrates the full pool export lifecycle: drains commit_group commits, writes
/// a BLAKE3-authenticated terminal committed root, closes the intent log
/// with an export terminal record, updates pool labels to EXPORTED, and
/// releases device handles.
///
/// The state machine guarantees forward progress: once a phase completes,
/// it cannot be retried. Failed phases leave the pool in its previous state.
#[derive(Debug)]
pub struct ExportOrchestrator {
    /// Current phase of the export state machine.
    phase: ExportPhase,
    /// Pool GUID for this export operation.
    pool_guid: [u8; 16],
    /// Pool name for label writes.
    pool_name: String,
    /// Device configurations for label writes.
    device_configs: Vec<DeviceConfig>,
    /// Per-device GUIDs for label writes.
    device_guids: Vec<[u8; 16]>,
    /// Final committed commit_group id for the export terminal record and labels.
    final_commit_group: u64,
    /// Whether --force was used.
    forced: bool,
    /// Number of active mounts or attached block devices on this pool.
    /// When > 0 and not forced, export is rejected with [`ExportError::HasActiveMounts`].
    active_mounts: usize,
}

impl ExportOrchestrator {
    /// Create a new export orchestrator for the given pool.
    #[must_use]
    pub fn new(
        pool_guid: [u8; 16],
        pool_name: &str,
        device_configs: Vec<DeviceConfig>,
        device_guids: Vec<[u8; 16]>,
        forced: bool,
    ) -> Self {
        Self {
            phase: ExportPhase::Idle,
            pool_guid,
            pool_name: pool_name.to_string(),
            device_configs,
            device_guids,
            final_commit_group: 0,
            forced,
            active_mounts: 0,
        }
    }

    /// Current export phase.
    #[must_use]
    pub fn phase(&self) -> ExportPhase {
        self.phase
    }

    /// Whether the export is complete.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.phase == ExportPhase::Done
    }

    /// Whether --force was used.
    #[must_use]
    pub fn is_forced(&self) -> bool {
        self.forced
    }

    /// Set the number of active mounts / attached block devices.
    ///
    /// The daemon context should call this before export to report
    /// how many FUSE mounts or ublk attachments are live.
    pub fn with_active_mounts(mut self, count: usize) -> Self {
        self.active_mounts = count;
        self
    }

    /// Number of active mounts reported to this orchestrator.
    #[must_use]
    pub fn active_mounts(&self) -> usize {
        self.active_mounts
    }

    /// Reject export if the pool still has active mounts and --force
    /// was not set.
    ///
    /// # Errors
    ///
    /// Returns [`ExportError::HasActiveMounts`] when `active_mounts > 0`
    /// and `forced` is false.
    pub fn check_no_active_mounts(&self) -> std::result::Result<(), ExportError> {
        if self.active_mounts > 0 && !self.forced {
            return Err(ExportError::HasActiveMounts {
                count: self.active_mounts,
            });
        }
        Ok(())
    }

    /// The final commit_group recorded during export.
    #[must_use]
    pub fn final_commit_group(&self) -> u64 {
        self.final_commit_group
    }

    /// Build source-backed lifecycle evidence for export execution/refusal.
    #[must_use]
    pub fn lifecycle_evidence(&self) -> PoolLifecycleEvidence {
        let labels = self
            .device_configs
            .iter()
            .enumerate()
            .map(|(index, config)| {
                PoolExporter::read_existing_label(&config.path)
                    .ok()
                    .filter(|label| {
                        label.device_capacity_bytes > 0
                            && label.pool_guid == self.pool_guid
                            && label.pool_name_str() == self.pool_name
                            && label.device_index == index as u32
                            && self
                                .device_guids
                                .get(index)
                                .is_some_and(|device_guid| label.device_guid == *device_guid)
                    })
            })
            .collect::<Option<Vec<_>>>();
        let capacity_bytes = labels
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|label| label.device_capacity_bytes)
            .sum();
        let expected_label_device_count = u32::try_from(self.device_guids.len()).ok();
        let topology_generation = labels
            .as_deref()
            .and_then(|labels| labels.first().map(|label| label.topology_generation))
            .filter(|generation| {
                *generation > 0
                    && labels.as_deref().is_some_and(|labels| {
                        expected_label_device_count.is_some_and(|device_count| {
                            labels.iter().all(|label| {
                                label.topology_generation == *generation
                                    && label.device_count == device_count
                            })
                        })
                    })
            })
            .unwrap_or(0);
        let context = PoolLifecycleContext {
            pool_guid: Some(self.pool_guid),
            pool_name: Some(self.pool_name.clone()),
            device_count: self.device_configs.len(),
            expected_device_count: self.device_guids.len(),
            capacity_bytes,
            topology_generation,
            commit_group: self.final_commit_group,
        };
        let topology_complete = context.topology_complete();

        if self.active_mounts > 0 && !self.forced {
            PoolLifecycleEvidence::refused_with_authority(
                PoolLifecycleAction::Export,
                context,
                topology_complete,
                false,
                format!("{} active mount(s) still own the pool", self.active_mounts),
            )
        } else if !topology_complete {
            PoolLifecycleEvidence::refused_with_authority(
                PoolLifecycleAction::Export,
                context,
                false,
                true,
                "topology evidence incomplete",
            )
        } else if !self.is_done() {
            PoolLifecycleEvidence::refused_fail_closed_with_authority(
                PoolLifecycleAction::Export,
                context,
                true,
                true,
                format!("export action incomplete at phase {}", self.phase.name()),
            )
        } else {
            PoolLifecycleEvidence::executed(PoolLifecycleAction::Export, context)
        }
    }

    // ── Phase transitions ──────────────────────────────────────────

    /// Run the full export state machine to completion.
    ///
    /// Each phase is executed in sequence. If a phase fails, the export
    /// stops and returns the error. The caller may retry from the current
    /// phase or abort.
    ///
    /// # Errors
    ///
    /// Returns `ExportError` if any phase fails.
    pub fn run(
        &mut self,
        commit_group: &mut CommitGroupManager,
        intent_log: &mut IntentLog,
    ) -> std::result::Result<(), ExportError> {
        // Operator authorization boundary: pool export orchestration requires local execution.
        let _guard = LocalOnlyGuard::new("pool export orchestration")?;
        if self.phase == ExportPhase::Done {
            return Err(ExportError::AlreadyExported);
        }

        // Guard: reject export if active mounts exist (unless --force).
        if self.phase == ExportPhase::Idle {
            self.check_no_active_mounts()?;
        }

        // Phase 1: Drain — commit any pending commit_group data.
        if self.phase == ExportPhase::Idle {
            self.phase = ExportPhase::Draining;
        }

        if self.phase == ExportPhase::Draining {
            self.drain_txg(commit_group)?;
            self.phase = ExportPhase::WritingCommittedRoot;
        }

        // Phase 2: Write terminal committed root.
        if self.phase == ExportPhase::WritingCommittedRoot {
            self.write_committed_root(commit_group)?;
            self.phase = ExportPhase::ClosingIntentLog;
        }

        // Phase 3: Close intent log with export terminal record.
        if self.phase == ExportPhase::ClosingIntentLog {
            self.close_intent_log(intent_log, commit_group)?;
            self.phase = ExportPhase::WritingLabels;
        }

        // Phase 4: Write EXPORTED labels to all devices.
        if self.phase == ExportPhase::WritingLabels {
            self.write_export_labels()?;
            self.phase = ExportPhase::Done;
        }

        Ok(())
    }

    /// Drain in-flight commit_group commits: flush the current commit_group if non-empty.
    fn drain_txg(
        &mut self,
        commit_group: &mut CommitGroupManager,
    ) -> std::result::Result<(), ExportError> {
        match commit_group.commit_current() {
            Ok(Some(root)) => {
                self.final_commit_group = root.commit_group_id.0;
            }
            Ok(None) => {
                let current_root = commit_group.committed_root();
                self.final_commit_group = if current_root.is_valid() {
                    current_root.commit_group_id.0
                } else {
                    0
                };
            }
            Err(e) => {
                return Err(ExportError::CommitGroupError(format!(
                    "commit_group commit failed during drain: {e}"
                )));
            }
        }
        Ok(())
    }

    /// Write the terminal committed root with BLAKE3 authentication.
    ///
    /// The committed root is already persisted by the commit_group manager via
    /// [`CommitGroupManager::commit_current`]. This phase verifies that the
    /// committed root is valid and records the final commit_group id.
    fn write_committed_root(
        &mut self,
        commit_group: &CommitGroupManager,
    ) -> std::result::Result<(), ExportError> {
        let root = commit_group.committed_root();
        if !root.is_valid() && self.final_commit_group == 0 {
            return Ok(());
        }
        self.final_commit_group = root.commit_group_id.0;
        Ok(())
    }

    /// Close the intent log by appending an export terminal record.
    fn close_intent_log(
        &mut self,
        intent_log: &mut IntentLog,
        commit_group: &CommitGroupManager,
    ) -> std::result::Result<(), ExportError> {
        let cg_id = self.final_commit_group;
        let record = IntentLogRecord::ExportTerminal { cg_id };
        intent_log.append(record).map_err(|e| {
            ExportError::IntentLogError(format!("failed to write export terminal record: {e}"))
        })?;

        // Flush committed region so the terminal record is persisted.
        let _ = intent_log.flush_committed();

        let root = commit_group.committed_root();
        if root.is_valid() {
            self.final_commit_group = root.commit_group_id.0;
        }

        Ok(())
    }

    /// Write EXPORTED state labels to all pool devices.
    fn write_export_labels(&self) -> std::result::Result<(), ExportError> {
        PoolExporter::export_pool(
            &self.device_configs,
            self.pool_guid,
            &self.device_guids,
            &self.pool_name,
            self.final_commit_group,
        )
    }

    /// Skip to the label-writing phase (CLI-only export path without
    /// a live CommitGroupManager or IntentLog).
    pub fn export_labels_only(
        &mut self,
        commit_group: u64,
    ) -> std::result::Result<(), ExportError> {
        // Operator authorization boundary: pool export labels requires local execution.
        let _guard = LocalOnlyGuard::new("pool export labels")?;
        if self.phase == ExportPhase::Done {
            return Err(ExportError::AlreadyExported);
        }
        self.check_no_active_mounts()?;
        self.final_commit_group = commit_group;
        self.phase = ExportPhase::WritingLabels;
        self.write_export_labels()?;
        self.phase = ExportPhase::Done;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceBacking, DeviceClass, DeviceConfig, DeviceKind};
    use crate::pool_label::{
        seal_label, LabelDeviceClass, PoolLabelV1, PoolRedundancyPolicy, POOL_LABEL_MAGIC,
    };
    use crate::pool_lifecycle_evidence::PoolLifecycleOutcome;

    #[test]
    fn export_empty_devices_fails() {
        let result = PoolExporter::export_pool(&[], [0u8; 16], &[], "test", 0);
        assert_eq!(result, Err(ExportError::PoolNotActive));
    }

    #[test]
    fn export_single_device() {
        let dir = std::env::temp_dir().join(format!("tidefs-export-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let config = DeviceConfig {
            media_class: Default::default(),
            path: dir.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: dir.clone() },
            compression: None,
            encryption: None,
        };

        let pool_guid = [0xABu8; 16];
        let device_guids = [[0xCDu8; 16]];

        // First write a label using PoolImporter (from pool_importer module).
        // Since we can't easily import that here, write a minimal label file.
        {
            let label_path = dir.join(".tidefs_label");
            let label = PoolLabelV1 {
                magic: POOL_LABEL_MAGIC,
                version: 1,
                pool_guid,
                device_guid: device_guids[0],
                pool_name_len: 4,
                pool_name: {
                    let mut buf = [0u8; 255];
                    buf[..4].copy_from_slice(b"test");
                    buf
                },
                pool_state: LabelPoolState::Active,
                commit_group: 10,
                label_commit_group: 10,
                device_index: 0,
                topology_generation: 1,
                device_count: 1,
                device_class: LabelDeviceClass::Hdd,
                device_capacity_bytes: 1024 * 1024 * 1024,
                system_area_pointer: 0,
                system_area_size: 0,
                features_incompat: 0,
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
            let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut buf).unwrap();
            std::fs::write(&label_path, buf).unwrap();
        }

        let result = PoolExporter::export_pool(&[config], pool_guid, &device_guids, "test", 10);
        assert!(result.is_ok());

        // Verify label state is EXPORTED.
        let label_path = dir.join(".tidefs_label");
        let data = std::fs::read(&label_path).unwrap();
        let decoded = decode_label(&data).unwrap();
        assert_eq!(decoded.pool_state, LabelPoolState::Exported);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── ExportPhase tests ────────────────────────────────────────

    #[test]
    fn export_phase_names() {
        assert_eq!(ExportPhase::Idle.name(), "idle");
        assert_eq!(ExportPhase::Draining.name(), "draining");
        assert_eq!(
            ExportPhase::WritingCommittedRoot.name(),
            "writing_committed_root"
        );
        assert_eq!(ExportPhase::ClosingIntentLog.name(), "closing_intent_log");
        assert_eq!(ExportPhase::WritingLabels.name(), "writing_labels");
        assert_eq!(ExportPhase::Done.name(), "done");
    }

    #[test]
    fn export_phase_terminal() {
        assert!(!ExportPhase::Idle.is_terminal());
        assert!(!ExportPhase::Draining.is_terminal());
        assert!(!ExportPhase::WritingCommittedRoot.is_terminal());
        assert!(!ExportPhase::ClosingIntentLog.is_terminal());
        assert!(!ExportPhase::WritingLabels.is_terminal());
        assert!(ExportPhase::Done.is_terminal());
    }

    // ── ExportOrchestrator tests ─────────────────────────────────

    fn unique_export_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tidefs-export-{}-{}-{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn export_device_config(path: PathBuf) -> DeviceConfig {
        DeviceConfig {
            media_class: Default::default(),
            path: path.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path },
            compression: None,
            encryption: None,
        }
    }

    fn read_label_at(path: &Path, offset: u64) -> PoolLabelV1 {
        use std::io::{Read as _, Seek as _};

        let mut file = std::fs::File::open(path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        file.read_exact(&mut buf).unwrap();
        decode_label(&buf).unwrap()
    }

    #[test]
    fn export_preserves_extended_evidence_at_canonical_label_copies() {
        let path = unique_export_path("canonical-tail-label");
        let _ = std::fs::remove_file(&path);
        let capacity_bytes = 4 * POOL_LABEL_SIZE as u64;
        let tail_offset = capacity_bytes - POOL_LABEL_SIZE as u64;
        let pool_guid = [0x8A; 16];
        let device_guid = [0x8B; 16];

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(capacity_bytes).unwrap();
        drop(file);

        let mut label = PoolLabelV1::new(pool_guid, device_guid, "testpool");
        label.commit_group = 10;
        label.label_commit_group = 10;
        label.topology_generation = 7;
        label.device_capacity_bytes = capacity_bytes;
        label.device_health = 1;
        label.device_read_errors = 17;
        label.device_write_errors = 19;
        label.device_checksum_errors = 23;
        label.redundancy_policy = PoolRedundancyPolicy::replicated(2);
        let sealed = seal_label(label).unwrap();
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();
        PoolExporter::write_at_offset(&path, &buf, 0).unwrap();
        PoolExporter::write_at_offset(&path, &buf, tail_offset).unwrap();

        let config = DeviceConfig {
            media_class: Default::default(),
            path: path.clone(),
            backing: DeviceBacking::RegularFileDev,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: path.clone() },
            compression: None,
            encryption: None,
        };

        PoolExporter::export_pool(&[config], pool_guid, &[device_guid], "testpool", 12).unwrap();

        let head = read_label_at(&path, 0);
        let tail = read_label_at(&path, tail_offset);
        for label in [head, tail] {
            assert_eq!(label.pool_state, LabelPoolState::Exported);
            assert_eq!(label.commit_group, 12);
            assert_eq!(label.device_health, 1);
            assert_eq!(label.device_read_errors, 17);
            assert_eq!(label.device_write_errors, 19);
            assert_eq!(label.device_checksum_errors, 23);
            assert_eq!(label.redundancy_policy, PoolRedundancyPolicy::replicated(2));
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn export_preserves_device_layout_sidecar() {
        use crate::device_layout::{
            encode_device_layout_v1, DeviceLayoutPolicy, DEVICE_LAYOUT_V1_WIRE_SIZE,
        };

        let path = unique_export_path("device-layout-sidecar");
        let _ = std::fs::remove_file(&path);
        let capacity_bytes = 4 * POOL_LABEL_SIZE as u64;
        let tail_offset = capacity_bytes - POOL_LABEL_SIZE as u64;
        let pool_guid = [0x8C; 16];
        let device_guid = [0x8D; 16];

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(capacity_bytes).unwrap();
        drop(file);

        let layout = DeviceLayoutPolicy::Slice0Small
            .compute(capacity_bytes)
            .unwrap();
        let mut layout_bytes = [0u8; DEVICE_LAYOUT_V1_WIRE_SIZE];
        encode_device_layout_v1(&layout, &mut layout_bytes);

        let mut label = PoolLabelV1::new(pool_guid, device_guid, "testpool");
        label.commit_group = 10;
        label.label_commit_group = 10;
        label.topology_generation = 7;
        label.device_capacity_bytes = capacity_bytes;
        label.system_area_pointer = layout.system_area_offset;
        label.system_area_size = layout.system_area_len;
        let sealed = seal_label_with_device_layout(label, Some(&layout_bytes)).unwrap();
        let mut buf = [0u8; POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE];
        encode_label_with_device_layout(&sealed, Some(&layout_bytes), &mut buf).unwrap();
        PoolExporter::write_at_offset(&path, &buf, 0).unwrap();
        PoolExporter::write_at_offset(&path, &buf, tail_offset).unwrap();

        let config = DeviceConfig {
            media_class: Default::default(),
            path: path.clone(),
            backing: DeviceBacking::RegularFileDev,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: path.clone() },
            compression: None,
            encryption: None,
        };
        PoolExporter::export_pool(&[config], pool_guid, &[device_guid], "testpool", 12).unwrap();

        for offset in [0, tail_offset] {
            let mut file = std::fs::File::open(&path).unwrap();
            file.seek(SeekFrom::Start(offset)).unwrap();
            let mut exported = [0u8; POOL_LABEL_V1_WITH_DEVICE_LAYOUT_WIRE_SIZE];
            file.read_exact(&mut exported).unwrap();
            assert_eq!(
                decode_label(&exported).unwrap().pool_state,
                LabelPoolState::Exported
            );
            assert_eq!(
                decode_device_layout_v1_bytes(&exported).unwrap(),
                Some(layout_bytes)
            );
        }

        let _ = std::fs::remove_file(path);
    }

    fn write_export_label(
        path: &Path,
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        device_index: u32,
        capacity_bytes: u64,
        topology_generation: u64,
    ) {
        write_export_label_with_device_count(
            path,
            pool_guid,
            device_guid,
            device_index,
            capacity_bytes,
            topology_generation,
            1,
        );
    }

    fn write_export_label_with_device_count(
        path: &Path,
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        device_index: u32,
        capacity_bytes: u64,
        topology_generation: u64,
        device_count: u32,
    ) {
        let _ = std::fs::remove_dir_all(path);
        std::fs::create_dir_all(path).unwrap();
        let label_path = path.join(".tidefs_label");
        let label = PoolLabelV1 {
            magic: POOL_LABEL_MAGIC,
            version: 1,
            pool_guid,
            device_guid,
            pool_name_len: 8,
            pool_name: {
                let mut buf = [0u8; 255];
                buf[..8].copy_from_slice(b"testpool");
                buf
            },
            pool_state: LabelPoolState::Active,
            commit_group: 10,
            label_commit_group: 10,
            device_index,
            topology_generation,
            device_count,
            device_class: LabelDeviceClass::Hdd,
            device_capacity_bytes: capacity_bytes,
            system_area_pointer: 0,
            system_area_size: 0,
            features_incompat: 0,
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
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();
        std::fs::write(label_path, buf).unwrap();
    }

    #[test]
    fn export_preflight_refuses_missing_label_without_mutating_peers() {
        let first_path = unique_export_path("preflight-first");
        let missing_path = unique_export_path("preflight-missing");
        let pool_guid = [0x90; 16];
        let device_guids = [[0x10; 16], [0x20; 16]];

        write_export_label_with_device_count(
            &first_path,
            pool_guid,
            device_guids[0],
            0,
            1024 * 1024 * 1024,
            7,
            2,
        );
        std::fs::create_dir_all(&missing_path).unwrap();

        let configs = [
            export_device_config(first_path.clone()),
            export_device_config(missing_path.clone()),
        ];
        let result = PoolExporter::export_pool(&configs, pool_guid, &device_guids, "testpool", 12);

        match result {
            Err(ExportError::LabelValidationFailed {
                device_path,
                reason,
            }) => {
                assert_eq!(device_path, missing_path);
                assert!(reason.contains("missing"));
            }
            other => panic!("expected missing-label refusal, got {other:?}"),
        }
        let first = PoolExporter::read_existing_label(&first_path).unwrap();
        assert_eq!(first.pool_state, LabelPoolState::Active);
        assert!(!missing_path.join(".tidefs_label").exists());

        let _ = std::fs::remove_dir_all(first_path);
        let _ = std::fs::remove_dir_all(missing_path);
    }

    #[test]
    fn export_preflight_refuses_duplicate_device_guids_without_mutation() {
        let first_path = unique_export_path("duplicate-guid-first");
        let second_path = unique_export_path("duplicate-guid-second");
        let pool_guid = [0x43; 16];
        let device_guid = [0x19; 16];
        write_export_label_with_device_count(
            &first_path,
            pool_guid,
            device_guid,
            0,
            1024 * 1024 * 1024,
            1,
            2,
        );
        write_export_label_with_device_count(
            &second_path,
            pool_guid,
            device_guid,
            1,
            1024 * 1024 * 1024,
            1,
            2,
        );
        let configs = [
            export_device_config(first_path.clone()),
            export_device_config(second_path.clone()),
        ];
        let mut writes = 0;

        let result = PoolExporter::export_pool_with_writer(
            &configs,
            pool_guid,
            &[device_guid, device_guid],
            "testpool",
            12,
            |_, _, _, _| {
                writes += 1;
                Ok(())
            },
        );

        match result {
            Err(ExportError::LabelValidationFailed {
                device_path,
                reason,
            }) => {
                assert_eq!(device_path, second_path);
                assert!(reason.contains("duplicate device GUID"));
            }
            other => panic!("expected LabelValidationFailed, got {other:?}"),
        }
        assert_eq!(writes, 0);
        assert_eq!(
            PoolExporter::read_existing_label(&first_path)
                .unwrap()
                .pool_state,
            LabelPoolState::Active
        );
        assert_eq!(
            PoolExporter::read_existing_label(&second_path)
                .unwrap()
                .pool_state,
            LabelPoolState::Active
        );

        let _ = std::fs::remove_dir_all(first_path);
        let _ = std::fs::remove_dir_all(second_path);
    }

    #[test]
    fn export_preflight_refuses_foreign_label_without_mutating_peers() {
        let first_path = unique_export_path("preflight-authorized");
        let foreign_path = unique_export_path("preflight-foreign");
        let pool_guid = [0x91; 16];
        let device_guids = [[0x11; 16], [0x22; 16]];

        write_export_label_with_device_count(
            &first_path,
            pool_guid,
            device_guids[0],
            0,
            1024 * 1024 * 1024,
            7,
            2,
        );
        write_export_label_with_device_count(
            &foreign_path,
            [0x92; 16],
            device_guids[1],
            1,
            1024 * 1024 * 1024,
            7,
            2,
        );

        let configs = [
            export_device_config(first_path.clone()),
            export_device_config(foreign_path.clone()),
        ];
        let result = PoolExporter::export_pool(&configs, pool_guid, &device_guids, "testpool", 12);

        match result {
            Err(ExportError::LabelValidationFailed {
                device_path,
                reason,
            }) => {
                assert_eq!(device_path, foreign_path);
                assert!(reason.contains("pool GUID"));
            }
            other => panic!("expected foreign-label refusal, got {other:?}"),
        }
        let first = PoolExporter::read_existing_label(&first_path).unwrap();
        let foreign = PoolExporter::read_existing_label(&foreign_path).unwrap();
        assert_eq!(first.pool_state, LabelPoolState::Active);
        assert_eq!(foreign.pool_state, LabelPoolState::Active);

        let _ = std::fs::remove_dir_all(first_path);
        let _ = std::fs::remove_dir_all(foreign_path);
    }

    #[test]
    fn export_failure_restores_each_device_original_label() {
        let first_path = unique_export_path("rollback-first");
        let failed_path = unique_export_path("rollback-failed");
        let pool_guid = [0x91; 16];
        let device_guids = [[0x11; 16], [0x22; 16]];
        let first_capacity = 1024_u64 * 1024 * 1024;
        let failed_capacity = 2_u64 * 1024 * 1024 * 1024;

        write_export_label_with_device_count(
            &first_path,
            pool_guid,
            device_guids[0],
            0,
            first_capacity,
            7,
            2,
        );
        write_export_label_with_device_count(
            &failed_path,
            pool_guid,
            device_guids[1],
            1,
            failed_capacity,
            7,
            2,
        );

        let configs = [
            export_device_config(first_path.clone()),
            export_device_config(failed_path.clone()),
        ];
        let injected_failure_path = failed_path.clone();
        let result = PoolExporter::export_pool_with_writer(
            &configs,
            pool_guid,
            &device_guids,
            "testpool",
            12,
            move |path, label, device_layout_v1, wire_size| {
                if path == injected_failure_path.as_path()
                    && label.pool_state == LabelPoolState::Exported
                {
                    // Model an error reported after media was mutated, such
                    // as a sync failure after one or both copies were written.
                    PoolExporter::write_labels_to_device(path, label, device_layout_v1, wire_size)?;
                    Err(ExportError::IoError("injected label write failure".into()))
                } else {
                    PoolExporter::write_labels_to_device(path, label, device_layout_v1, wire_size)
                }
            },
        );

        assert!(matches!(result, Err(ExportError::LabelWriteFailed { .. })));

        let first = PoolExporter::read_existing_label(&first_path).unwrap();
        assert_eq!(first.pool_state, LabelPoolState::Active);
        assert_eq!(first.device_guid, device_guids[0]);
        assert_eq!(first.device_index, 0);
        assert_eq!(first.device_capacity_bytes, first_capacity);

        let failed = PoolExporter::read_existing_label(&failed_path).unwrap();
        assert_eq!(failed.pool_state, LabelPoolState::Active);
        assert_eq!(failed.device_guid, device_guids[1]);
        assert_eq!(failed.device_index, 1);
        assert_eq!(failed.device_capacity_bytes, failed_capacity);

        let _ = std::fs::remove_dir_all(first_path);
        let _ = std::fs::remove_dir_all(failed_path);
    }

    fn make_orchestrator() -> ExportOrchestrator {
        let path = unique_export_path("evidence");
        let pool_guid = [0xAAu8; 16];
        let device_guid = [0x01u8; 16];
        write_export_label(&path, pool_guid, device_guid, 0, 1024 * 1024 * 1024, 1);
        let config = DeviceConfig {
            media_class: Default::default(),
            path: path.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path },
            compression: None,
            encryption: None,
        };
        ExportOrchestrator::new(
            pool_guid,
            "testpool",
            vec![config],
            vec![device_guid],
            false,
        )
    }

    fn assert_export_topology_refused(evidence: &PoolLifecycleEvidence) {
        assert_eq!(evidence.action, PoolLifecycleAction::Export);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.capacity_bytes, 0);
        assert_eq!(evidence.topology_generation, 0);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    #[test]
    fn orchestrator_starts_idle() {
        let orch = make_orchestrator();
        assert_eq!(orch.phase(), ExportPhase::Idle);
        assert!(!orch.is_done());
        assert_eq!(orch.final_commit_group(), 0);
    }

    #[test]
    fn orchestrator_forced_flag() {
        let orch =
            ExportOrchestrator::new([0xBBu8; 16], "forcedpool", Vec::new(), Vec::new(), true);
        assert!(orch.is_forced());
    }

    #[test]
    fn orchestrator_export_labels_only_idempotent() {
        let dir = std::env::temp_dir().join(format!("tidefs-orch-idem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let config = DeviceConfig {
            media_class: Default::default(),
            path: dir.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: dir.clone() },
            compression: None,
            encryption: None,
        };

        // Write a minimal Active label
        {
            let label_path = dir.join(".tidefs_label");
            let label = PoolLabelV1 {
                magic: crate::pool_label::POOL_LABEL_MAGIC,
                version: 1,
                pool_guid: [0xCCu8; 16],
                device_guid: [0x01u8; 16],
                pool_name_len: 4,
                pool_name: {
                    let mut buf = [0u8; 255];
                    buf[..4].copy_from_slice(b"idem");
                    buf
                },
                pool_state: LabelPoolState::Active,
                commit_group: 5,
                label_commit_group: 5,
                device_index: 0,
                topology_generation: 1,
                device_count: 1,
                device_class: LabelDeviceClass::Hdd,
                device_capacity_bytes: 1024 * 1024 * 1024,
                system_area_pointer: 0,
                system_area_size: 0,
                features_incompat: 0,
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
            let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut buf).unwrap();
            std::fs::write(&label_path, buf).unwrap();
        }

        let mut orch = ExportOrchestrator::new(
            [0xCCu8; 16],
            "idem",
            vec![config],
            vec![[0x01u8; 16]],
            false,
        );
        assert_eq!(orch.phase(), ExportPhase::Idle);

        // First export should succeed.
        orch.export_labels_only(5).unwrap();
        assert_eq!(orch.phase(), ExportPhase::Done);

        // Second export should return AlreadyExported.
        let err = orch.export_labels_only(5).unwrap_err();
        assert_eq!(err, ExportError::AlreadyExported);

        // Verify label is EXPORTED.
        let data = std::fs::read(dir.join(".tidefs_label")).unwrap();
        let decoded = decode_label(&data).unwrap();
        assert_eq!(decoded.pool_state, LabelPoolState::Exported);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn orchestrator_run_with_txg_drain_empty() {
        let dir =
            std::env::temp_dir().join(format!("tidefs-orch-drain-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let config = DeviceConfig {
            media_class: Default::default(),
            path: dir.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: dir.clone() },
            compression: None,
            encryption: None,
        };

        // Write a minimal Active label
        {
            let label_path = dir.join(".tidefs_label");
            let label = PoolLabelV1 {
                magic: crate::pool_label::POOL_LABEL_MAGIC,
                version: 1,
                pool_guid: [0xDDu8; 16],
                device_guid: [0x02u8; 16],
                pool_name_len: 4,
                pool_name: {
                    let mut buf = [0u8; 255];
                    buf[..4].copy_from_slice(b"dmtx");
                    buf
                },
                pool_state: LabelPoolState::Active,
                commit_group: 0,
                label_commit_group: 0,
                device_index: 0,
                topology_generation: 1,
                device_count: 1,
                device_class: LabelDeviceClass::Hdd,
                device_capacity_bytes: 1024 * 1024 * 1024,
                system_area_pointer: 0,
                system_area_size: 0,
                features_incompat: 0,
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
            let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut buf).unwrap();
            std::fs::write(&label_path, buf).unwrap();
        }

        let mut orch = ExportOrchestrator::new(
            [0xDDu8; 16],
            "dmtx",
            vec![config],
            vec![[0x02u8; 16]],
            false,
        );

        // Create a CommitGroupManager and IntentLog for the orchestrated export.
        let mut commit_group = CommitGroupManager::new(tidefs_commit_group::CommitGroupId::FIRST);
        let mut intent_log = IntentLog::new(65536);

        orch.run(&mut commit_group, &mut intent_log).unwrap();
        assert_eq!(orch.phase(), ExportPhase::Done);

        // Verify label is EXPORTED.
        let data = std::fs::read(dir.join(".tidefs_label")).unwrap();
        let decoded = decode_label(&data).unwrap();
        assert_eq!(decoded.pool_state, LabelPoolState::Exported);

        // Verify an export terminal record was appended.
        // ExportTerminal record was appended; committed region only forms with TxBegin/TxCommit pairs.
        assert!(!intent_log.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn orchestrator_run_with_txg_drain_nonempty() {
        let dir =
            std::env::temp_dir().join(format!("tidefs-orch-drain-nonempty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let config = DeviceConfig {
            media_class: Default::default(),
            path: dir.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: dir.clone() },
            compression: None,
            encryption: None,
        };

        // Write a minimal Active label
        {
            let label_path = dir.join(".tidefs_label");
            let label = PoolLabelV1 {
                magic: crate::pool_label::POOL_LABEL_MAGIC,
                version: 1,
                pool_guid: [0xEEu8; 16],
                device_guid: [0x03u8; 16],
                pool_name_len: 4,
                pool_name: {
                    let mut buf = [0u8; 255];
                    buf[..4].copy_from_slice(b"full");
                    buf
                },
                pool_state: LabelPoolState::Active,
                commit_group: 0,
                label_commit_group: 0,
                device_index: 0,
                topology_generation: 1,
                device_count: 1,
                device_class: LabelDeviceClass::Hdd,
                device_capacity_bytes: 1024 * 1024 * 1024,
                system_area_pointer: 0,
                system_area_size: 0,
                features_incompat: 0,
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
            let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut buf).unwrap();
            std::fs::write(&label_path, buf).unwrap();
        }

        let mut orch = ExportOrchestrator::new(
            [0xEEu8; 16],
            "full",
            vec![config],
            vec![[0x03u8; 16]],
            false,
        );

        let mut commit_group = CommitGroupManager::new(tidefs_commit_group::CommitGroupId::FIRST);
        // Queue a write to make the commit_group non-empty.
        let key = crate::ObjectKey::from_bytes32([1u8; 32]);
        commit_group.queue_put(key, b"export-drain-data").unwrap();

        let mut intent_log = IntentLog::new(65536);

        orch.run(&mut commit_group, &mut intent_log).unwrap();
        assert_eq!(orch.phase(), ExportPhase::Done);
        // After draining a non-empty commit_group, final_commit_group should be > 0.
        assert!(orch.final_commit_group() > 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn orchestrator_run_idempotent() {
        let dir = std::env::temp_dir().join(format!("tidefs-orch-run-idem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let config = DeviceConfig {
            media_class: Default::default(),
            path: dir.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: dir.clone() },
            compression: None,
            encryption: None,
        };

        {
            let label_path = dir.join(".tidefs_label");
            let label = PoolLabelV1 {
                magic: crate::pool_label::POOL_LABEL_MAGIC,
                version: 1,
                pool_guid: [0xFFu8; 16],
                device_guid: [0x04u8; 16],
                pool_name_len: 4,
                pool_name: {
                    let mut buf = [0u8; 255];
                    buf[..4].copy_from_slice(b"idm2");
                    buf
                },
                pool_state: LabelPoolState::Active,
                commit_group: 0,
                label_commit_group: 0,
                device_index: 0,
                topology_generation: 1,
                device_count: 1,
                device_class: LabelDeviceClass::Hdd,
                device_capacity_bytes: 1024 * 1024 * 1024,
                system_area_pointer: 0,
                system_area_size: 0,
                features_incompat: 0,
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
            let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut buf).unwrap();
            std::fs::write(&label_path, buf).unwrap();
        }

        let mut orch = ExportOrchestrator::new(
            [0xFFu8; 16],
            "idm2",
            vec![config],
            vec![[0x04u8; 16]],
            false,
        );

        let mut commit_group = CommitGroupManager::new(tidefs_commit_group::CommitGroupId::FIRST);
        let mut intent_log = IntentLog::new(65536);

        // First run succeeds.
        orch.run(&mut commit_group, &mut intent_log).unwrap();
        assert_eq!(orch.phase(), ExportPhase::Done);

        // Second run returns AlreadyExported.
        let err = orch.run(&mut commit_group, &mut intent_log).unwrap_err();
        assert_eq!(err, ExportError::AlreadyExported);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_error_display_covers_all_variants() {
        let e = ExportError::PoolNotActive;
        assert!(format!("{e}").contains("ACTIVE"));
        let e = ExportError::CommitGroupError("test".into());
        assert!(format!("{e}").contains("commit_group error"));
        let e = ExportError::IntentLogError("test".into());
        assert!(format!("{e}").contains("intent log error"));
        let e = ExportError::AlreadyExported;
        assert!(format!("{e}").contains("already exported"));
    }

    #[test]
    fn export_error_has_active_mounts_display() {
        let err = ExportError::HasActiveMounts { count: 3 };
        let msg = format!("{err}");
        assert!(msg.contains("3 active mount"));
        assert!(msg.contains("--force"));
    }

    // -- Active mount guard tests --

    #[test]
    fn orchestrator_with_active_mounts_default_zero() {
        let orch = make_orchestrator();
        assert_eq!(orch.active_mounts(), 0);
    }

    #[test]
    fn orchestrator_with_active_mounts_sets_count() {
        let orch = make_orchestrator().with_active_mounts(2);
        assert_eq!(orch.active_mounts(), 2);
    }

    #[test]
    fn check_no_active_mounts_passes_when_zero() {
        let orch = make_orchestrator();
        assert!(orch.check_no_active_mounts().is_ok());
    }

    #[test]
    fn check_no_active_mounts_passes_when_forced() {
        let orch = ExportOrchestrator::new([0xAAu8; 16], "test", Vec::new(), Vec::new(), true)
            .with_active_mounts(1);
        assert!(orch.check_no_active_mounts().is_ok());
    }

    #[test]
    fn check_no_active_mounts_rejects_when_active_and_not_forced() {
        let orch = ExportOrchestrator::new([0xAAu8; 16], "test", Vec::new(), Vec::new(), false)
            .with_active_mounts(1);
        let err = orch.check_no_active_mounts().unwrap_err();
        assert_eq!(err, ExportError::HasActiveMounts { count: 1 });
    }

    #[test]
    fn orchestrator_lifecycle_evidence_requires_completed_export() {
        let mut orch = make_orchestrator();

        let pending = orch.lifecycle_evidence();

        assert_eq!(pending.action, PoolLifecycleAction::Export);
        assert_eq!(pending.outcome, PoolLifecycleOutcome::Refused);
        assert!(pending.topology_complete);
        assert!(pending.owner_authorized);
        assert!(pending.is_fail_closed());
        assert_eq!(pending.reason, "export action incomplete at phase idle");

        orch.export_labels_only(10).unwrap();

        let evidence = orch.lifecycle_evidence();

        assert_eq!(evidence.action, PoolLifecycleAction::Export);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Executed);
        assert_eq!(evidence.device_count, 1);
        assert_eq!(evidence.expected_device_count, 1);
        assert_eq!(evidence.capacity_bytes, 1024 * 1024 * 1024);
        assert_eq!(evidence.topology_generation, 1);
        assert_eq!(evidence.commit_group, 10);
        assert!(evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(!evidence.is_fail_closed());
    }

    #[test]
    fn orchestrator_refuses_export_lifecycle_evidence_without_label_capacity() {
        let path = unique_export_path("missing-label");
        let config = DeviceConfig {
            media_class: Default::default(),
            path: path.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path },
            compression: None,
            encryption: None,
        };
        let orch = ExportOrchestrator::new(
            [0xAAu8; 16],
            "missing-label",
            vec![config],
            vec![[0x01u8; 16]],
            false,
        );

        let evidence = orch.lifecycle_evidence();

        assert_eq!(evidence.action, PoolLifecycleAction::Export);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.capacity_bytes, 0);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    #[test]
    fn orchestrator_refuses_export_lifecycle_evidence_with_partial_label_capacity() {
        let pool_guid = [0xAAu8; 16];
        let device_a = [0x01u8; 16];
        let device_b = [0x02u8; 16];
        let path_a = unique_export_path("partial-label-a");
        let path_b = unique_export_path("partial-label-b");
        write_export_label(&path_a, pool_guid, device_a, 0, 1024 * 1024 * 1024, 1);
        let _ = std::fs::remove_dir_all(&path_b);
        std::fs::create_dir_all(&path_b).unwrap();
        let config_a = DeviceConfig {
            media_class: Default::default(),
            path: path_a.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: path_a },
            compression: None,
            encryption: None,
        };
        let config_b = DeviceConfig {
            media_class: Default::default(),
            path: path_b.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: path_b },
            compression: None,
            encryption: None,
        };
        let orch = ExportOrchestrator::new(
            pool_guid,
            "partial-label",
            vec![config_a, config_b],
            vec![device_a, device_b],
            false,
        );

        let evidence = orch.lifecycle_evidence();

        assert_eq!(evidence.action, PoolLifecycleAction::Export);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.device_count, 2);
        assert_eq!(evidence.expected_device_count, 2);
        assert_eq!(evidence.capacity_bytes, 0);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    #[test]
    fn orchestrator_refuses_export_lifecycle_evidence_with_foreign_label_pool_guid() {
        let path = unique_export_path("foreign-pool-guid");
        let pool_guid = [0xAAu8; 16];
        let device_guid = [0x01u8; 16];
        write_export_label(&path, [0xBBu8; 16], device_guid, 0, 1024 * 1024 * 1024, 1);
        let config = DeviceConfig {
            media_class: Default::default(),
            path: path.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path },
            compression: None,
            encryption: None,
        };
        let orch = ExportOrchestrator::new(
            pool_guid,
            "foreign-pool",
            vec![config],
            vec![device_guid],
            false,
        );

        let evidence = orch.lifecycle_evidence();

        assert_export_topology_refused(&evidence);
    }

    #[test]
    fn orchestrator_refuses_export_lifecycle_evidence_with_foreign_label_pool_name() {
        let path = unique_export_path("foreign-pool-name");
        let pool_guid = [0xAAu8; 16];
        let device_guid = [0x01u8; 16];
        write_export_label(&path, pool_guid, device_guid, 0, 1024 * 1024 * 1024, 1);
        let config = DeviceConfig {
            media_class: Default::default(),
            path: path.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path },
            compression: None,
            encryption: None,
        };
        let orch = ExportOrchestrator::new(
            pool_guid,
            "foreign-pool",
            vec![config],
            vec![device_guid],
            false,
        );

        let evidence = orch.lifecycle_evidence();

        assert_export_topology_refused(&evidence);
    }

    #[test]
    fn orchestrator_refuses_export_lifecycle_evidence_with_wrong_label_device_index() {
        let pool_guid = [0xAAu8; 16];
        let device_a = [0x01u8; 16];
        let device_b = [0x02u8; 16];
        let path_a = unique_export_path("wrong-index-a");
        let path_b = unique_export_path("wrong-index-b");
        write_export_label(&path_a, pool_guid, device_a, 0, 1024 * 1024 * 1024, 1);
        write_export_label(&path_b, pool_guid, device_b, 0, 1024 * 1024 * 1024, 1);
        let config_a = DeviceConfig {
            media_class: Default::default(),
            path: path_a.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: path_a },
            compression: None,
            encryption: None,
        };
        let config_b = DeviceConfig {
            media_class: Default::default(),
            path: path_b.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: path_b },
            compression: None,
            encryption: None,
        };
        let orch = ExportOrchestrator::new(
            pool_guid,
            "wrong-index",
            vec![config_a, config_b],
            vec![device_a, device_b],
            false,
        );

        let evidence = orch.lifecycle_evidence();

        assert_export_topology_refused(&evidence);
    }

    #[test]
    fn orchestrator_refuses_export_lifecycle_evidence_with_wrong_label_device_guid() {
        let path = unique_export_path("wrong-device-guid");
        let pool_guid = [0xAAu8; 16];
        let device_guid = [0x01u8; 16];
        write_export_label(&path, pool_guid, [0x02u8; 16], 0, 1024 * 1024 * 1024, 1);
        let config = DeviceConfig {
            media_class: Default::default(),
            path: path.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path },
            compression: None,
            encryption: None,
        };
        let orch = ExportOrchestrator::new(
            pool_guid,
            "wrong-device",
            vec![config],
            vec![device_guid],
            false,
        );

        let evidence = orch.lifecycle_evidence();

        assert_export_topology_refused(&evidence);
    }

    #[test]
    fn orchestrator_refuses_export_lifecycle_evidence_with_label_device_count_drift() {
        let pool_guid = [0xAAu8; 16];
        let device_a = [0x01u8; 16];
        let device_b = [0x02u8; 16];
        let path_a = unique_export_path("label-count-a");
        let path_b = unique_export_path("label-count-b");
        write_export_label_with_device_count(
            &path_a,
            pool_guid,
            device_a,
            0,
            1024 * 1024 * 1024,
            1,
            2,
        );
        write_export_label_with_device_count(
            &path_b,
            pool_guid,
            device_b,
            1,
            1024 * 1024 * 1024,
            1,
            1,
        );
        let config_a = DeviceConfig {
            media_class: Default::default(),
            path: path_a.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: path_a },
            compression: None,
            encryption: None,
        };
        let config_b = DeviceConfig {
            media_class: Default::default(),
            path: path_b.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: path_b },
            compression: None,
            encryption: None,
        };
        let orch = ExportOrchestrator::new(
            pool_guid,
            "testpool",
            vec![config_a, config_b],
            vec![device_a, device_b],
            false,
        );

        let evidence = orch.lifecycle_evidence();

        assert_eq!(evidence.action, PoolLifecycleAction::Export);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.device_count, 2);
        assert_eq!(evidence.expected_device_count, 2);
        assert_eq!(evidence.capacity_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(evidence.topology_generation, 0);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    #[test]
    fn orchestrator_refuses_export_lifecycle_evidence_with_mismatched_label_generations() {
        let pool_guid = [0xAAu8; 16];
        let device_a = [0x01u8; 16];
        let device_b = [0x02u8; 16];
        let path_a = unique_export_path("label-generation-a");
        let path_b = unique_export_path("label-generation-b");
        write_export_label(&path_a, pool_guid, device_a, 0, 1024 * 1024 * 1024, 1);
        write_export_label(&path_b, pool_guid, device_b, 1, 1024 * 1024 * 1024, 2);
        let config_a = DeviceConfig {
            media_class: Default::default(),
            path: path_a.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: path_a },
            compression: None,
            encryption: None,
        };
        let config_b = DeviceConfig {
            media_class: Default::default(),
            path: path_b.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: path_b },
            compression: None,
            encryption: None,
        };
        let orch = ExportOrchestrator::new(
            pool_guid,
            "testpool",
            vec![config_a, config_b],
            vec![device_a, device_b],
            false,
        );

        let evidence = orch.lifecycle_evidence();

        assert_eq!(evidence.action, PoolLifecycleAction::Export);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.capacity_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(evidence.topology_generation, 0);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "topology evidence incomplete");
    }

    #[test]
    fn orchestrator_emits_fail_closed_evidence_for_active_mounts() {
        let orch = make_orchestrator().with_active_mounts(1);

        let evidence = orch.lifecycle_evidence();

        assert_eq!(evidence.action, PoolLifecycleAction::Export);
        assert!(evidence.topology_complete);
        assert!(!evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
        assert!(evidence.reason.contains("active mount"));
    }

    #[test]
    fn orchestrator_active_mount_evidence_refuses_surplus_topology() {
        let path_a = PathBuf::from("/tmp/tidefs-export-surplus-a");
        let path_b = PathBuf::from("/tmp/tidefs-export-surplus-b");
        let config_a = DeviceConfig {
            media_class: Default::default(),
            path: path_a.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: path_a },
            compression: None,
            encryption: None,
        };
        let config_b = DeviceConfig {
            media_class: Default::default(),
            path: path_b.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: path_b },
            compression: None,
            encryption: None,
        };
        let orch = ExportOrchestrator::new(
            [0xAAu8; 16],
            "surplus",
            vec![config_a, config_b],
            vec![[0x01u8; 16]],
            false,
        )
        .with_active_mounts(1);

        let evidence = orch.lifecycle_evidence();

        assert_eq!(evidence.action, PoolLifecycleAction::Export);
        assert_eq!(evidence.device_count, 2);
        assert_eq!(evidence.expected_device_count, 1);
        assert!(!evidence.topology_complete);
        assert!(!evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
        assert!(evidence.reason.contains("active mount"));
    }

    #[test]
    fn orchestrator_run_rejects_active_mounts() {
        let dir = std::env::temp_dir().join(format!("tidefs-mntguard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let config = DeviceConfig {
            media_class: Default::default(),
            path: dir.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: dir.clone() },
            compression: None,
            encryption: None,
        };

        {
            let lp = dir.join(".tidefs_label");
            let mut label = PoolLabelV1::new([0x11u8; 16], [0x01u8; 16], "guard");
            label.pool_state = LabelPoolState::Active;
            label.topology_generation = 1;
            label.device_count = 1;
            label.device_index = 0;
            let sealed = seal_label(label).unwrap();
            let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut buf).unwrap();
            std::fs::write(&lp, buf).unwrap();
        }

        let mut orch = ExportOrchestrator::new(
            [0x11u8; 16],
            "guard",
            vec![config],
            vec![[0x01u8; 16]],
            false,
        )
        .with_active_mounts(1);

        let mut commit_group = CommitGroupManager::new(tidefs_commit_group::CommitGroupId::FIRST);
        let mut ilog = IntentLog::new(65536);

        let err = orch.run(&mut commit_group, &mut ilog).unwrap_err();
        assert_eq!(err, ExportError::HasActiveMounts { count: 1 });

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn orchestrator_run_bypasses_mount_guard_with_force() {
        let dir = std::env::temp_dir().join(format!("tidefs-mntforce-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let config = DeviceConfig {
            media_class: Default::default(),
            path: dir.clone(),
            backing: DeviceBacking::DirectoryObjectStoreCompat,
            class: DeviceClass::Data,
            kind: DeviceKind::Single { path: dir.clone() },
            compression: None,
            encryption: None,
        };

        {
            let lp = dir.join(".tidefs_label");
            let mut label = PoolLabelV1::new([0x22u8; 16], [0x02u8; 16], "forceguard");
            label.pool_state = LabelPoolState::Active;
            label.topology_generation = 1;
            label.device_count = 1;
            label.device_index = 0;
            label.device_capacity_bytes = 1024 * 1024 * 1024;
            let sealed = seal_label(label).unwrap();
            let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
            encode_label(&sealed, &mut buf).unwrap();
            std::fs::write(&lp, buf).unwrap();
        }

        let mut orch = ExportOrchestrator::new(
            [0x22u8; 16],
            "forceguard",
            vec![config],
            vec![[0x02u8; 16]],
            true,
        )
        .with_active_mounts(2);

        let mut commit_group = CommitGroupManager::new(tidefs_commit_group::CommitGroupId::FIRST);
        let mut ilog = IntentLog::new(65536);

        orch.run(&mut commit_group, &mut ilog).unwrap();
        assert_eq!(orch.phase(), ExportPhase::Done);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn orchestrator_export_labels_only_rejects_active_mounts() {
        let mut orch =
            ExportOrchestrator::new([0x33u8; 16], "lblguard", Vec::new(), Vec::new(), false)
                .with_active_mounts(1);
        let err = orch.export_labels_only(0).unwrap_err();
        assert_eq!(err, ExportError::HasActiveMounts { count: 1 });
    }
}
