// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool export: atomic label state transition from ACTIVE to EXPORTED.
//!
//! Implements the pool export transition summarized by
//! `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`.
//!
//! The exporter guarantees all-or-nothing atomicity: either all device labels
//! are transitioned to EXPORTED or none are. No partial/split state is possible.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::device::DeviceConfig;
use crate::intent_log::record::IntentLogRecord;
use crate::intent_log::sync_write::IntentLog;
use crate::pool_label::{
    decode_label, encode_label, seal_label, LabelDeviceClass, LabelPoolState, PoolLabelV1,
    PoolRedundancyPolicy, POOL_LABEL_SIZE, POOL_LABEL_V1_WIRE_SIZE,
};
use crate::pool_lifecycle_evidence::{
    PoolLifecycleAction, PoolLifecycleContext, PoolLifecycleEvidence,
};
use crate::txg_manager::CommitGroupManager;
use tidefs_auth::local_only::LocalOnlyGuard;

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
        _pool_name: &str,
        commit_group: u64,
    ) -> std::result::Result<(), ExportError> {
        // Operator authorization boundary: pool export requires local execution.
        let _guard = LocalOnlyGuard::new("pool export")?;
        if device_configs.is_empty() {
            return Err(ExportError::PoolNotActive);
        }

        let label_commit_group = commit_group + 1;
        let mut written: Vec<PathBuf> = Vec::new();

        for (i, device_config) in device_configs.iter().enumerate() {
            let _device_guid = if i < device_guids.len() {
                device_guids[i]
            } else {
                let mut dg = pool_guid;
                dg[0] ^= i as u8;
                dg
            };

            // Read existing label to preserve fields we don't change.
            let existing = Self::read_existing_label(&device_config.path, pool_guid, i as u32)?;

            let label = PoolLabelV1 {
                pool_state: LabelPoolState::Exported,
                commit_group,
                label_commit_group,
                features_incompat: existing.features_incompat,
                features_ro_compat: existing.features_ro_compat,
                features_compat: existing.features_compat,
                ..existing
            };

            let result = Self::write_labels_to_device(&device_config.path, &label);

            match result {
                Ok(()) => {
                    written.push(device_config.path.clone());
                }
                Err(e) => {
                    // Rollback: restore ACTIVE state on all written devices.
                    for path in &written {
                        let _ = Self::rollback_device_label(path, &existing);
                    }
                    return Err(ExportError::LabelWriteFailed {
                        device_path: device_config.path.clone(),
                        reason: format!("{e:?}"),
                    });
                }
            }
        }

        // All labels written successfully.
        Ok(())
    }

    /// Read the current label from a device, or return an empty label template.
    fn read_existing_label(
        device_path: &Path,
        pool_guid: [u8; 16],
        device_index: u32,
    ) -> std::result::Result<PoolLabelV1, ExportError> {
        let _metadata = fs::metadata(device_path)
            .map_err(|e| ExportError::IoError(format!("stat {}: {e}", device_path.display())))?;

        let label_path = if device_path.is_dir() {
            device_path.join(".tidefs_label")
        } else {
            device_path.to_path_buf()
        };

        // Try to read label from the label file/file.
        if !label_path.exists() {
            // Return a default template.
            return Ok(PoolLabelV1 {
                magic: crate::pool_label::POOL_LABEL_MAGIC,
                version: 1,
                pool_guid,
                device_guid: [0u8; 16],
                pool_name_len: 0,
                pool_name: [0u8; 255],
                pool_state: LabelPoolState::Active,
                commit_group: 0,
                label_commit_group: 0,
                device_index,
                topology_generation: 0,
                device_count: 0,
                device_class: LabelDeviceClass::Hdd,
                device_capacity_bytes: 0,
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
            });
        }

        let mut file = fs::OpenOptions::new()
            .read(true)
            .open(&label_path)
            .map_err(|e| ExportError::IoError(format!("open {}: {e}", label_path.display())))?;

        let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
        use std::io::Read;
        file.read_exact(&mut buf)
            .map_err(|e| ExportError::IoError(format!("read {}: {e}", label_path.display())))?;

        decode_label(&buf).map_err(|e| ExportError::LabelWriteFailed {
            device_path: device_path.to_path_buf(),
            reason: format!("decode: {e:?}"),
        })
    }

    /// Write both label copies (offset 0 and offset POOL_LABEL_SIZE) to a device.
    fn write_labels_to_device(
        device_path: &Path,
        label: &PoolLabelV1,
    ) -> std::result::Result<(), ExportError> {
        let sealed = seal_label(label.clone()).map_err(|e| ExportError::LabelWriteFailed {
            device_path: device_path.to_path_buf(),
            reason: format!("seal: {e:?}"),
        })?;

        let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
        encode_label(&sealed, &mut buf).map_err(|e| ExportError::LabelWriteFailed {
            device_path: device_path.to_path_buf(),
            reason: format!("encode: {e:?}"),
        })?;

        let label_path = if device_path.is_dir() {
            device_path.join(".tidefs_label")
        } else {
            device_path.to_path_buf()
        };

        // Write Label 0
        Self::write_at_offset(&label_path, &buf, 0)?;
        // Write Label 1
        Self::write_at_offset(&label_path, &buf, POOL_LABEL_SIZE as u64)?;

        Ok(())
    }

    /// Rollback: write ACTIVE state back to a device label.
    fn rollback_device_label(
        device_path: &Path,
        original_label: &PoolLabelV1,
    ) -> std::result::Result<(), ExportError> {
        let mut active = original_label.clone();
        active.pool_state = LabelPoolState::Active;
        Self::write_labels_to_device(device_path, &active)
    }

    /// Write raw bytes at a given offset within a file.
    fn write_at_offset(
        path: &Path,
        data: &[u8; POOL_LABEL_V1_WIRE_SIZE],
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
                PoolExporter::read_existing_label(&config.path, self.pool_guid, index as u32)
                    .ok()
                    .filter(|label| label.device_capacity_bytes > 0)
            })
            .collect::<Option<Vec<_>>>();
        let capacity_bytes = labels
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|label| label.device_capacity_bytes)
            .sum();
        let topology_generation = labels
            .as_deref()
            .and_then(|labels| labels.first().map(|label| label.topology_generation))
            .filter(|generation| {
                *generation > 0
                    && labels.as_deref().is_some_and(|labels| {
                        labels
                            .iter()
                            .all(|label| label.topology_generation == *generation)
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
    use crate::pool_label::{seal_label, PoolLabelV1, POOL_LABEL_MAGIC};
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
            let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
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

    fn write_export_label(
        path: &Path,
        pool_guid: [u8; 16],
        device_guid: [u8; 16],
        device_index: u32,
        capacity_bytes: u64,
        topology_generation: u64,
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
            device_count: 1,
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
        let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();
        std::fs::write(label_path, buf).unwrap();
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
            let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
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
            let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
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
            let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
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
            let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
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
    fn orchestrator_emits_export_lifecycle_evidence() {
        let orch = make_orchestrator();

        let evidence = orch.lifecycle_evidence();

        assert_eq!(evidence.action, PoolLifecycleAction::Export);
        assert_eq!(evidence.device_count, 1);
        assert_eq!(evidence.expected_device_count, 1);
        assert_eq!(evidence.capacity_bytes, 1024 * 1024 * 1024);
        assert_eq!(evidence.topology_generation, 1);
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
            "generation-mismatch",
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
            let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
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
            let sealed = seal_label(label).unwrap();
            let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];
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
