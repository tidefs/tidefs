// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Crash oracle for bounded TideFS persistence-boundary matrices.
//!
//! The model-first path evaluates the pure `tidefs-model-core` state machine
//! and records semantic crash boundaries with model recovery classifications.
//!
//! The `runtime_report` module adds a local runtime crash report schema and
//! verifier that is distinct from the model-only crash matrix reports.  A
//! passing schema verifier is necessary but not sufficient for establishing
//! production durability.

use std::fmt;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tidefs_model_core::{
    ContractModelContext, ContractNameBinding, ContractNameContext, ModelFs, ModelNodeKind,
    ModelOutput, ModelPath, ModelRequest,
};
use tidefs_types_vfs_core::{
    AdmissionIntent, BudgetIntent, ContractEpoch, Errno, FenceIntent, RequestEnvelope, RequestId,
    RequestMetadata, RetryIntent, TideRequest, TraceId, VfsNameToken, VfsRequest, WorkClass,
};

pub mod artifact_manifest;
pub mod runtime_report;

#[cfg(feature = "intent-log-replay")]
pub mod intent_log_replay_matrix;

pub const REPORT_VERSION: u64 = 1;
pub const MODEL_BACKEND: &str = "tidefs-model-core";
pub const WRITE_FSYNC_MATRIX_ID: &str = "model.write_fsync_crash_matrix.v1";
pub const RENAME_MATRIX_ID: &str = "model.rename_atomic_crash_matrix.v1";
pub const STORAGE_WRITE_FSYNC_CLAIM_ID: &str = "storage.write_fsync.crash_safety.v1";
pub const NAMESPACE_RENAME_CLAIM_ID: &str = "namespace.rename.atomicity.v1";
pub const LOCAL_VFS_WRITE_FSYNC_CLAIM_ID: &str = "local.vfs.write_fsync_crash.v1";
pub const LOCAL_VFS_RENAME_CLAIM_ID: &str = "local.vfs.rename_atomic_crash.v1";
pub const CACHE_DIRTY_CRASH_MATRIX_ID: &str = "cache.dirty_page_crash_matrix.v1";
pub const CACHE_COHERENCY_CLAIM_ID: &str = "cache.coherency.crash_safety.v1";
pub const CACHE_WRITEBACK_CRASH_CLAIM_ID: &str = "cache.writeback.crash_safety.v1";
pub const LOCAL_VFS_INJECTION_MATRIX_ID: &str = "local.vfs.crash_injection_matrix.v1";
const ISSUE_286_ARTIFACT_PATH: &str = "validation/artifacts/crash-oracle/model-crash-matrices.json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrashBoundary {
    IntentAppend,
    DataPublish,
    ExtentPublish,
    InodePublish,
    RootPublish,
    FsyncCommit,
    RecoveryReplay,
    /// Crash after a page is marked dirty in the cache but before
    /// writeback starts.  The dirty data exists only in the page
    /// cache; no log entry has been written.
    PageDirtyMark,
    /// Crash during active writeback.  Writeback is in flight;
    /// the page is pinned with the WRITEBACK flag.
    PageWritebackStart,
    /// Crash after writeback completes (page clean, log entry
    /// durable) but before the file-level fsync commits.
    PageWritebackComplete,
    /// Crash after a clean cached page is evicted.  The data was
    /// clean so no durability gap.
    CacheEvict,
}

impl CrashBoundary {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntentAppend => "intent-append",
            Self::DataPublish => "data-publish",
            Self::ExtentPublish => "extent-publish",
            Self::InodePublish => "inode-publish",
            Self::RootPublish => "root-publish",
            Self::FsyncCommit => "fsync-commit",
            Self::RecoveryReplay => "recovery-replay",
            Self::PageDirtyMark => "page-dirty-mark",
            Self::PageWritebackStart => "page-writeback-start",
            Self::PageWritebackComplete => "page-writeback-complete",
            Self::CacheEvict => "cache-evict",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrashClassification {
    Valid,
    LostUnfsynced,
    Forbidden,
    UnsupportedFailClosed,
}

impl CrashClassification {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::LostUnfsynced => "lost-unfsynced",
            Self::Forbidden => "forbidden",
            Self::UnsupportedFailClosed => "unsupported-fail-closed",
        }
    }
}

/// Crash injection points on the local filesystem write/fsync path.
///
/// These describe where in the runtime VFS adapter path a crash can be
/// injected. They are distinct from [`CrashBoundary`], which describes
/// model-level state-transition boundaries.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrashInjectionPoint {
    /// Crash after write syscall returns but before fsync is issued
    AfterWriteBeforeFsync,
    /// Crash after fsync completes but before unmount
    AfterFsyncBeforeUnmount,
    /// Crash during fsync execution (data may be partially durable)
    DuringFsync,
    /// Crash during a directory update (mkdir, rmdir, rename, link, unlink)
    DuringDirectoryUpdate,
    /// Crash during an inode attribute update (chmod, chown, utimes, etc.)
    DuringInodeAttributeUpdate,
}

impl CrashInjectionPoint {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AfterWriteBeforeFsync => "after-write-before-fsync",
            Self::AfterFsyncBeforeUnmount => "after-fsync-before-unmount",
            Self::DuringFsync => "during-fsync",
            Self::DuringDirectoryUpdate => "during-directory-update",
            Self::DuringInodeAttributeUpdate => "during-inode-attribute-update",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrashOracleReport {
    pub report_version: u64,
    pub generated_by: String,
    pub evidence_scope: String,
    pub runtime_claim_boundary: String,
    /// Model-level crash matrices (write/fsync, rename)
    pub matrices: Vec<CrashMatrix>,
    /// Local VFS crash injection matrices (runtime injection point definitions)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub injection_matrices: Vec<CrashInjectionMatrix>,
    pub runtime_claims: Vec<RuntimeClaimStatus>,
}

impl CrashOracleReport {
    #[must_use]
    pub fn case_count(&self) -> usize {
        self.matrices.iter().map(|matrix| matrix.cases.len()).sum()
    }

    #[must_use]
    pub fn injection_case_count(&self) -> usize {
        self.injection_matrices
            .iter()
            .map(|matrix| matrix.injection_points.len())
            .sum()
    }

    #[must_use]
    pub fn classification_count(&self, classification: CrashClassification) -> usize {
        let model_count = self
            .matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .filter(|case| case.classification == classification)
            .count();
        let injection_count = self
            .injection_matrices
            .iter()
            .flat_map(|matrix| &matrix.injection_points)
            .filter(|case| case.classification == classification)
            .count();
        model_count + injection_count
    }

    pub fn validate(&self) -> Result<(), CrashOracleError> {
        if self.report_version != REPORT_VERSION {
            return Err(CrashOracleError::Report(format!(
                "unsupported report version {}",
                self.report_version
            )));
        }
        if !self
            .matrices
            .iter()
            .any(|matrix| matrix.id == WRITE_FSYNC_MATRIX_ID)
        {
            return Err(CrashOracleError::Report(format!(
                "missing {WRITE_FSYNC_MATRIX_ID}"
            )));
        }
        if !self
            .matrices
            .iter()
            .any(|matrix| matrix.id == RENAME_MATRIX_ID)
        {
            return Err(CrashOracleError::Report(format!(
                "missing {RENAME_MATRIX_ID}"
            )));
        }

        // Validate injection matrices if present
        for matrix in &self.injection_matrices {
            if matrix.injection_points.is_empty() {
                return Err(CrashOracleError::Report(format!(
                    "injection matrix {} has no injection points",
                    matrix.id
                )));
            }
            let mut injection_ids = std::collections::BTreeSet::new();
            for case in &matrix.injection_points {
                if case.id.is_empty() {
                    return Err(CrashOracleError::Report(
                        "injection point with empty id".to_string(),
                    ));
                }
                if !injection_ids.insert(case.id.as_str()) {
                    return Err(CrashOracleError::Report(format!(
                        "duplicate injection point id {} in matrix {}",
                        case.id, matrix.id
                    )));
                }
                if case.evidence_class.is_empty() {
                    return Err(CrashOracleError::Report(format!(
                        "injection point {} has empty evidence_class",
                        case.id
                    )));
                }
            }
        }

        for case in self.matrices.iter().flat_map(|matrix| &matrix.cases) {
            if case.classification == CrashClassification::Forbidden {
                if case.recovered_state_diffs.is_empty() {
                    return Err(CrashOracleError::Report(format!(
                        "{} is forbidden but has no recovered-state diff",
                        case.id
                    )));
                }
                if case.minimized_trace.is_none() {
                    return Err(CrashOracleError::Report(format!(
                        "{} is forbidden but has no minimized trace",
                        case.id
                    )));
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeClaimStatus {
    pub claim_id: String,
    pub status: String,
    pub classification: CrashClassification,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrashMatrix {
    pub id: String,
    pub claim_ids: Vec<String>,
    pub backend: String,
    pub description: String,
    pub cases: Vec<CrashCase>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrashCase {
    pub id: String,
    pub operation: String,
    pub boundary: CrashBoundary,
    pub classification: CrashClassification,
    pub recovered_fingerprint: Option<String>,
    pub acceptable_fingerprints: Vec<AcceptableState>,
    pub recovered_state_diffs: Vec<RecoveredStateDiff>,
    pub minimized_trace: Option<MinimizedCrashTrace>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceptableState {
    pub label: String,
    pub classification: CrashClassification,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveredStateDiff {
    pub path: String,
    pub field: String,
    pub expected: String,
    pub recovered: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MinimizedCrashTrace {
    pub id: String,
    pub replay_hint: String,
    pub operations: Vec<CrashTraceOp>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrashTraceOp {
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<CrashBoundary>,
}

/// A single crash injection point definition for the local VFS path.
///
/// Each injection point defines where on the local filesystem write/fsync
/// path a crash can be injected and what the expected recovery outcome is.
/// These are definition-only entries; they do not contain runtime evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrashInjectionCase {
    /// Unique identifier, e.g. "vfs.after_write.before_fsync"
    pub id: String,
    /// Where on the VFS path the crash is injected
    pub injection_point: CrashInjectionPoint,
    /// The operation targeted (write, fsync, mkdir, chmod, etc.)
    pub operation: String,
    /// Expected recovery classification
    pub classification: CrashClassification,
    /// Human-readable description of expected behavior on recovery
    pub expected_outcome: String,
    /// Whether data must be present and correct after recovery
    pub data_correct_required: bool,
    /// Whether data may be absent after recovery (allowed for pre-fsync crashes)
    pub data_absent_allowed: bool,
    /// Whether torn/partial data after recovery is forbidden
    pub data_torn_forbidden: bool,
    /// Whether filesystem metadata must be internally consistent after recovery
    pub metadata_consistent_required: bool,
    /// Evidence tier requirement: T0 (model/definition), T1 (harness), T2 (runtime)
    pub evidence_class: String,
    /// Whether this injection point currently has runtime evidence collected
    #[serde(default)]
    pub has_runtime_evidence: bool,
    /// Reason if blocked from runtime evidence collection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
}

/// A local VFS crash injection matrix.
///
/// Defines the set of crash injection points on the local filesystem
/// write/fsync path, their expected recovery outcomes, and evidence-class
/// requirements. This is a definition artifact: it does not contain runtime
/// crash evidence. Each injection point has a unique identifier suitable
/// for later runtime artifact binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrashInjectionMatrix {
    pub id: String,
    pub claim_ids: Vec<String>,
    pub description: String,
    pub injection_points: Vec<CrashInjectionCase>,
}

#[derive(Debug)]
pub enum CrashOracleError {
    Io(std::io::Error),
    Json(serde_json::Error),
    ModelInvariant(String),
    ModelErrno { op: String, errno: Errno },
    Report(String),
}

impl fmt::Display for CrashOracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Json(err) => write!(f, "JSON error: {err}"),
            Self::ModelInvariant(err) => write!(f, "model invariant failed: {err}"),
            Self::ModelErrno { op, errno } => {
                write!(f, "model operation {op} failed with {}", errno.name())
            }
            Self::Report(err) => write!(f, "crash report error: {err}"),
        }
    }
}

impl std::error::Error for CrashOracleError {}

impl From<std::io::Error> for CrashOracleError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for CrashOracleError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

/// Build the cache dirty-page crash matrix.
///
/// This matrix classifies crash outcomes at each cache lifecycle boundary
/// for a dirty page.  The model writes data, then crashes at cache-specific
/// boundaries; the recovery classification reflects whether the write data
/// is durable after replay.
fn cache_dirty_page_matrix() -> Result<CrashMatrix, CrashOracleError> {
    let baseline = model_with_file("/file", b"initial")?;

    // State after write (dirty in cache, no fsync): page-dirty-mark boundary
    let mut after_write = baseline.clone();
    apply_success(
        &mut after_write,
        ModelRequest::Write {
            path: model_path("/file")?,
            offset: 0,
            bytes: b"dirty-data".to_vec(),
        },
        "write /file (dirty in cache)",
    )?;

    // State after fsync (clean, durable): page-writeback-complete boundary
    let mut after_fsync = after_write.clone();
    apply_success(
        &mut after_fsync,
        ModelRequest::Fsync {
            path: model_path("/file")?,
        },
        "fsync /file (writeback complete)",
    )?;

    Ok(CrashMatrix {
        id: CACHE_DIRTY_CRASH_MATRIX_ID.to_string(),
        claim_ids: vec![
            CACHE_COHERENCY_CLAIM_ID.to_string(),
            CACHE_WRITEBACK_CRASH_CLAIM_ID.to_string(),
        ],
        backend: MODEL_BACKEND.to_string(),
        description: "cache dirty-page crash matrix across writeback lifecycle boundaries"
            .to_string(),
        cases: vec![
            crash_case(
                "cache.page_dirty_mark",
                "page dirty mark",
                CrashBoundary::PageDirtyMark,
                CrashClassification::LostUnfsynced,
                &baseline,
                vec![acceptable(
                    "initial-data",
                    CrashClassification::LostUnfsynced,
                    &baseline,
                )],
                vec![],
                None,
            ),
            crash_case(
                "cache.page_writeback_start",
                "page writeback start",
                CrashBoundary::PageWritebackStart,
                CrashClassification::LostUnfsynced,
                &baseline,
                vec![acceptable(
                    "initial-data",
                    CrashClassification::LostUnfsynced,
                    &baseline,
                )],
                vec![],
                None,
            ),
            crash_case(
                "cache.page_writeback_complete",
                "page writeback complete",
                CrashBoundary::PageWritebackComplete,
                CrashClassification::Valid,
                &after_fsync,
                vec![acceptable(
                    "durable-data",
                    CrashClassification::Valid,
                    &after_fsync,
                )],
                vec![],
                None,
            ),
            crash_case(
                "cache.evict_clean_page",
                "clean page eviction",
                CrashBoundary::CacheEvict,
                CrashClassification::Valid,
                &baseline,
                vec![acceptable(
                    "initial-data",
                    CrashClassification::Valid,
                    &baseline,
                )],
                vec![],
                None,
            ),
        ],
    })
}

pub fn run_model_crash_matrices() -> Result<CrashOracleReport, CrashOracleError> {
    let report = CrashOracleReport {
        report_version: REPORT_VERSION,
        generated_by: format!("tidefs-crash-oracle-rust-v{}", env!("CARGO_PKG_VERSION")),
        evidence_scope: "bounded model-only crash matrix; no local runtime crash injection"
            .to_string(),
        runtime_claim_boundary:
            "model crash matrices remain model-only; local runtime crash claims require matching runtime artifacts before validation"
                .to_string(),
        matrices: vec![write_fsync_matrix()?, rename_matrix()?, cache_dirty_page_matrix()?],
        injection_matrices: vec![define_local_vfs_crash_injection_matrix()],
        runtime_claims: vec![
            RuntimeClaimStatus {
                claim_id: LOCAL_VFS_WRITE_FSYNC_CLAIM_ID.to_string(),
                status: "blocked".to_string(),
                classification: CrashClassification::UnsupportedFailClosed,
                reason: "model matrix is not runtime evidence; validate the local VFS write/fsync claim through the registered runtime-crash-oracle artifact".to_string(),
            },
            RuntimeClaimStatus {
                claim_id: LOCAL_VFS_RENAME_CLAIM_ID.to_string(),
                status: "blocked".to_string(),
                classification: CrashClassification::UnsupportedFailClosed,
                reason:
                    "local runtime rename crash evidence waits for runtime write-set clearance"
                        .to_string(),
            },
            RuntimeClaimStatus {
                claim_id: CACHE_COHERENCY_CLAIM_ID.to_string(),
                status: "proof-in-progress".to_string(),
                classification: CrashClassification::LostUnfsynced,
                reason:
                    "cache dirty-page crash matrix added; runtime crash injection deferred to runtime validation"
                        .to_string(),
            },
        ],
    };
    report.validate()?;
    Ok(report)
}

pub fn write_model_crash_report(path: &Path) -> Result<CrashOracleReport, CrashOracleError> {
    let report = run_model_crash_matrices()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&report)?;
    fs::write(path, format!("{json}\n"))?;
    Ok(report)
}

/// Define the local VFS crash injection matrix for the write/fsync path.
///
/// This matrix enumerates the crash injection points on the local filesystem
/// write/fsync path, their expected recovery outcomes, and evidence-class
/// requirements. Each injection point has a unique identifier suitable for
/// binding to runtime crash artifacts in later slices (e.g., issue #486).
///
/// This is a definition artifact: it does not contain or require runtime
/// crash evidence.
pub fn define_local_vfs_crash_injection_matrix() -> CrashInjectionMatrix {
    CrashInjectionMatrix {
        id: LOCAL_VFS_INJECTION_MATRIX_ID.to_string(),
        claim_ids: vec![
            LOCAL_VFS_WRITE_FSYNC_CLAIM_ID.to_string(),
            STORAGE_WRITE_FSYNC_CLAIM_ID.to_string(),
        ],
        description:
            "Local VFS crash injection matrix for the write/fsync path. Defines crash injection              points, expected recovery outcomes, and evidence-class requirements for the vertical              write-fsync-read-recover slice."
                .to_string(),
        injection_points: vec![
            // --- write path injection points ---
            CrashInjectionCase {
                id: "vfs.after_write.before_fsync".to_string(),
                injection_point: CrashInjectionPoint::AfterWriteBeforeFsync,
                operation: "write".to_string(),
                classification: CrashClassification::LostUnfsynced,
                expected_outcome:
                    "Data written but not fsynced: after recovery, data may be absent                      (lost-unfsynced is allowed). Data must not be torn or partially present."
                        .to_string(),
                data_correct_required: false,
                data_absent_allowed: true,
                data_torn_forbidden: true,
                metadata_consistent_required: true,
                evidence_class: "T2".to_string(),
                has_runtime_evidence: false,
                blocked_reason: Some(
                    "runtime crash evidence for local VFS write path requires issue #486                      write-fsync-read-recover vertical slice completion"
                        .to_string(),
                ),
            },
            // --- fsync path injection points ---
            CrashInjectionCase {
                id: "vfs.after_fsync.before_unmount".to_string(),
                injection_point: CrashInjectionPoint::AfterFsyncBeforeUnmount,
                operation: "fsync".to_string(),
                classification: CrashClassification::Valid,
                expected_outcome:
                    "Data fsynced before unmount: after recovery, data must be present,                      correct, and metadata must be consistent."
                        .to_string(),
                data_correct_required: true,
                data_absent_allowed: false,
                data_torn_forbidden: true,
                metadata_consistent_required: true,
                evidence_class: "T2".to_string(),
                has_runtime_evidence: false,
                blocked_reason: Some(
                    "runtime crash evidence for local VFS fsync path requires issue #486                      write-fsync-read-recover vertical slice completion"
                        .to_string(),
                ),
            },
            CrashInjectionCase {
                id: "vfs.during_fsync".to_string(),
                injection_point: CrashInjectionPoint::DuringFsync,
                operation: "fsync".to_string(),
                classification: CrashClassification::LostUnfsynced,
                expected_outcome:
                    "Crash during fsync: after recovery, data must not be torn. Data may                      be either fully present (fsync completed before crash) or absent                      (fsync did not complete). Metadata must be consistent."
                        .to_string(),
                data_correct_required: false,
                data_absent_allowed: true,
                data_torn_forbidden: true,
                metadata_consistent_required: true,
                evidence_class: "T2".to_string(),
                has_runtime_evidence: false,
                blocked_reason: Some(
                    "runtime crash evidence for during-fsync requires issue #486                      write-fsync-read-recover vertical slice completion"
                        .to_string(),
                ),
            },
            // --- directory update injection point ---
            CrashInjectionCase {
                id: "vfs.during_directory_update".to_string(),
                injection_point: CrashInjectionPoint::DuringDirectoryUpdate,
                operation: "mkdir".to_string(),
                classification: CrashClassification::LostUnfsynced,
                expected_outcome:
                    "Crash during directory update: after recovery, the directory entry                      may be absent (lost-unfsynced) but must not leave the directory in                      an inconsistent state (no dangling entries, no half-created entries).                      Metadata must be internally consistent."
                        .to_string(),
                data_correct_required: false,
                data_absent_allowed: true,
                data_torn_forbidden: true,
                metadata_consistent_required: true,
                evidence_class: "T2".to_string(),
                has_runtime_evidence: false,
                blocked_reason: Some(
                    "runtime crash evidence for directory update paths requires issue #486                      and issue #495 (rename atomicity) clearance"
                        .to_string(),
                ),
            },
            // --- inode attribute update injection point ---
            CrashInjectionCase {
                id: "vfs.during_inode_attribute_update".to_string(),
                injection_point: CrashInjectionPoint::DuringInodeAttributeUpdate,
                operation: "setattr".to_string(),
                classification: CrashClassification::LostUnfsynced,
                expected_outcome:
                    "Crash during inode attribute update: after recovery, the attribute                      update may be absent (lost-unfsynced) but the inode must not have                      torn attributes (e.g., half-updated mtime with stale size). Metadata                      must be internally consistent."
                        .to_string(),
                data_correct_required: false,
                data_absent_allowed: true,
                data_torn_forbidden: true,
                metadata_consistent_required: true,
                evidence_class: "T2".to_string(),
                has_runtime_evidence: false,
                blocked_reason: Some(
                    "runtime crash evidence for attribute update paths requires issue #486                      write-fsync-read-recover vertical slice completion"
                        .to_string(),
                ),
            },
        ],
    }
}

fn write_fsync_matrix() -> Result<CrashMatrix, CrashOracleError> {
    let baseline = model_with_file("/file", b"old")?;
    let mut after_write = baseline.clone();
    apply_success(
        &mut after_write,
        ModelRequest::Write {
            path: model_path("/file")?,
            offset: 0,
            bytes: b"new-data".to_vec(),
        },
        "write /file",
    )?;
    let mut after_fsync = after_write.clone();
    apply_success(
        &mut after_fsync,
        ModelRequest::Fsync {
            path: model_path("/file")?,
        },
        "fsync /file",
    )?;

    let acceptable_unfsynced = vec![
        acceptable("old-file", CrashClassification::LostUnfsynced, &baseline),
        acceptable("new-file", CrashClassification::Valid, &after_write),
    ];
    let acceptable_synced = vec![acceptable(
        "fsynced-new-file",
        CrashClassification::Valid,
        &after_fsync,
    )];
    let forbidden_diff = diff_paths(
        &after_fsync,
        &baseline,
        &["/file"],
        "new bytes after fsync boundary",
    )?;

    Ok(CrashMatrix {
        id: WRITE_FSYNC_MATRIX_ID.to_string(),
        claim_ids: vec![
            STORAGE_WRITE_FSYNC_CLAIM_ID.to_string(),
            LOCAL_VFS_WRITE_FSYNC_CLAIM_ID.to_string(),
        ],
        backend: MODEL_BACKEND.to_string(),
        description:
            "write/fsync matrix over model states at intent, data, inode, fsync, and recovery boundaries"
                .to_string(),
        cases: vec![
            crash_case(
                "write.intent_append.old_file",
                "write",
                CrashBoundary::IntentAppend,
                CrashClassification::LostUnfsynced,
                &baseline,
                acceptable_unfsynced.clone(),
                Vec::new(),
                None,
            ),
            crash_case(
                "write.data_publish.new_file",
                "write",
                CrashBoundary::DataPublish,
                CrashClassification::Valid,
                &after_write,
                acceptable_unfsynced.clone(),
                Vec::new(),
                None,
            ),
            crash_case(
                "write.extent_publish.new_file",
                "write",
                CrashBoundary::ExtentPublish,
                CrashClassification::Valid,
                &after_write,
                acceptable_unfsynced.clone(),
                Vec::new(),
                None,
            ),
            crash_case(
                "write.inode_publish.new_file",
                "write",
                CrashBoundary::InodePublish,
                CrashClassification::Valid,
                &after_write,
                acceptable_unfsynced,
                Vec::new(),
                None,
            ),
            crash_case(
                "fsync.fsync_commit.new_file",
                "write+fsync",
                CrashBoundary::FsyncCommit,
                CrashClassification::Valid,
                &after_fsync,
                acceptable_synced.clone(),
                Vec::new(),
                None,
            ),
            crash_case(
                "fsync.recovery_replay.new_file",
                "write+fsync",
                CrashBoundary::RecoveryReplay,
                CrashClassification::Valid,
                &after_fsync,
                acceptable_synced.clone(),
                Vec::new(),
                None,
            ),
            crash_case(
                "fsync.root_publish.old_file_forbidden",
                "write+fsync",
                CrashBoundary::RootPublish,
                CrashClassification::Forbidden,
                &baseline,
                acceptable_synced,
                forbidden_diff,
                Some(write_forbidden_trace()),
            ),
        ],
    })
}

fn rename_matrix() -> Result<CrashMatrix, CrashOracleError> {
    let baseline = model_with_file("/dir/source", b"rename-data")?;
    let mut after_rename = baseline.clone();
    apply_contract_rename_success(
        &mut after_rename,
        "/dir/source",
        "/dir/dest",
        "rename /dir/source /dir/dest",
    )?;

    let mut both_names = baseline.clone();
    apply_contract_link_success(
        &mut both_names,
        "/dir/source",
        "/dir/dest",
        "link /dir/source /dir/dest",
    )?;

    let mut neither_name = baseline.clone();
    apply_contract_unlink_success(&mut neither_name, "/dir/source", "unlink /dir/source")?;

    let acceptable_rename = vec![
        acceptable("old-name", CrashClassification::LostUnfsynced, &baseline),
        acceptable("new-name", CrashClassification::Valid, &after_rename),
    ];
    let both_diff = vec![RecoveredStateDiff {
        path: "/dir/source,/dir/dest".to_string(),
        field: "atomic-name-set".to_string(),
        expected: "exactly one name present".to_string(),
        recovered: "both names present".to_string(),
    }];
    let neither_diff = vec![RecoveredStateDiff {
        path: "/dir/source,/dir/dest".to_string(),
        field: "atomic-name-set".to_string(),
        expected: "exactly one name present".to_string(),
        recovered: "neither name present".to_string(),
    }];

    Ok(CrashMatrix {
        id: RENAME_MATRIX_ID.to_string(),
        claim_ids: vec![
            NAMESPACE_RENAME_CLAIM_ID.to_string(),
            LOCAL_VFS_RENAME_CLAIM_ID.to_string(),
        ],
        backend: MODEL_BACKEND.to_string(),
        description:
            "rename matrix over model namespace states at intent, root publication, and replay boundaries"
                .to_string(),
        cases: vec![
            crash_case(
                "rename.intent_append.old_name",
                "rename",
                CrashBoundary::IntentAppend,
                CrashClassification::LostUnfsynced,
                &baseline,
                acceptable_rename.clone(),
                Vec::new(),
                None,
            ),
            crash_case(
                "rename.root_publish.new_name",
                "rename",
                CrashBoundary::RootPublish,
                CrashClassification::Valid,
                &after_rename,
                acceptable_rename.clone(),
                Vec::new(),
                None,
            ),
            crash_case(
                "rename.recovery_replay.new_name",
                "rename",
                CrashBoundary::RecoveryReplay,
                CrashClassification::Valid,
                &after_rename,
                acceptable_rename.clone(),
                Vec::new(),
                None,
            ),
            crash_case(
                "rename.recovery_replay.both_names_forbidden",
                "rename",
                CrashBoundary::RecoveryReplay,
                CrashClassification::Forbidden,
                &both_names,
                acceptable_rename.clone(),
                both_diff,
                Some(rename_forbidden_trace(
                    "rename-both-names-forbidden",
                    "both names present",
                )),
            ),
            crash_case(
                "rename.recovery_replay.neither_name_forbidden",
                "rename",
                CrashBoundary::RecoveryReplay,
                CrashClassification::Forbidden,
                &neither_name,
                acceptable_rename,
                neither_diff,
                Some(rename_forbidden_trace(
                    "rename-neither-name-forbidden",
                    "neither name present",
                )),
            ),
        ],
    })
}

fn crash_case(
    id: &str,
    operation: &str,
    boundary: CrashBoundary,
    classification: CrashClassification,
    recovered: &ModelFs,
    acceptable_fingerprints: Vec<AcceptableState>,
    recovered_state_diffs: Vec<RecoveredStateDiff>,
    minimized_trace: Option<MinimizedCrashTrace>,
) -> CrashCase {
    CrashCase {
        id: id.to_string(),
        operation: operation.to_string(),
        boundary,
        classification,
        recovered_fingerprint: Some(recovered.fingerprint().to_hex()),
        acceptable_fingerprints,
        recovered_state_diffs,
        minimized_trace,
    }
}

fn acceptable(label: &str, classification: CrashClassification, fs: &ModelFs) -> AcceptableState {
    AcceptableState {
        label: label.to_string(),
        classification,
        fingerprint: fs.fingerprint().to_hex(),
    }
}

fn model_with_file(path: &str, bytes: &[u8]) -> Result<ModelFs, CrashOracleError> {
    let mut fs = ModelFs::new();
    let model_path = model_path(path)?;
    let components = model_path.components();
    if components.len() > 1 {
        let mut parent = Vec::new();
        for component in &components[..components.len() - 1] {
            parent.push(component.clone());
            let parent_path = ModelPath::from_components(parent.iter().map(String::as_str))
                .map_err(|errno| CrashOracleError::ModelErrno {
                    op: format!("parse parent for {path}"),
                    errno,
                })?;
            if matches!(fs.attr(&parent_path), Err(Errno::ENOENT)) {
                apply_contract_mkdir_path_success(&mut fs, &parent_path, "mkdir parent")?;
            }
        }
    }

    apply_contract_create_path_success(&mut fs, &model_path, "create file")?;
    apply_success(
        &mut fs,
        ModelRequest::Write {
            path: model_path.clone(),
            offset: 0,
            bytes: bytes.to_vec(),
        },
        "write file",
    )?;
    apply_success(
        &mut fs,
        ModelRequest::Fsync { path: model_path },
        "fsync file",
    )?;
    Ok(fs)
}

fn apply_contract_mkdir_path_success(
    fs: &mut ModelFs,
    path: &ModelPath,
    op: &str,
) -> Result<(), CrashOracleError> {
    let (parent_id, name) =
        fs.resolve_parent_inode(path)
            .map_err(|errno| CrashOracleError::ModelErrno {
                op: op.to_string(),
                errno,
            })?;
    let binding = name_binding(&name);
    let envelope = contract_envelope(
        op,
        TideRequest::Vfs(VfsRequest::Mkdir {
            parent_id,
            name: binding.token,
        }),
    );
    apply_contract_success(fs, &envelope, &[binding], op)
}

fn apply_contract_create_path_success(
    fs: &mut ModelFs,
    path: &ModelPath,
    op: &str,
) -> Result<(), CrashOracleError> {
    let (parent_id, name) =
        fs.resolve_parent_inode(path)
            .map_err(|errno| CrashOracleError::ModelErrno {
                op: op.to_string(),
                errno,
            })?;
    let binding = name_binding(&name);
    let envelope = contract_envelope(
        op,
        TideRequest::Vfs(VfsRequest::Create {
            parent_id,
            name: binding.token,
        }),
    );
    apply_contract_success(fs, &envelope, &[binding], op)
}

fn apply_contract_rename_success(
    fs: &mut ModelFs,
    from: &str,
    to: &str,
    op: &str,
) -> Result<(), CrashOracleError> {
    let from = model_path(from)?;
    let to = model_path(to)?;
    let (old_parent_id, old_name) =
        fs.resolve_parent_inode(&from)
            .map_err(|errno| CrashOracleError::ModelErrno {
                op: op.to_string(),
                errno,
            })?;
    let (new_parent_id, new_name) =
        fs.resolve_parent_inode(&to)
            .map_err(|errno| CrashOracleError::ModelErrno {
                op: op.to_string(),
                errno,
            })?;
    let old_binding = name_binding(&old_name);
    let new_binding = name_binding(&new_name);
    let envelope = contract_envelope(
        op,
        TideRequest::Vfs(VfsRequest::Rename {
            old_parent_id,
            old_name: old_binding.token,
            new_parent_id,
            new_name: new_binding.token,
        }),
    );
    apply_contract_success(fs, &envelope, &[old_binding, new_binding], op)
}

fn apply_contract_link_success(
    fs: &mut ModelFs,
    from: &str,
    to: &str,
    op: &str,
) -> Result<(), CrashOracleError> {
    let from = model_path(from)?;
    let to = model_path(to)?;
    let source_inode_id =
        fs.resolve_path_inode(&from)
            .map_err(|errno| CrashOracleError::ModelErrno {
                op: op.to_string(),
                errno,
            })?;
    let (target_parent_id, target_name) =
        fs.resolve_parent_inode(&to)
            .map_err(|errno| CrashOracleError::ModelErrno {
                op: op.to_string(),
                errno,
            })?;
    let binding = name_binding(&target_name);
    let envelope = contract_envelope(
        op,
        TideRequest::Vfs(VfsRequest::Link {
            source_inode_id,
            target_parent_id,
            target_name: binding.token,
        }),
    );
    apply_contract_success(fs, &envelope, &[binding], op)
}

fn apply_contract_unlink_success(
    fs: &mut ModelFs,
    path: &str,
    op: &str,
) -> Result<(), CrashOracleError> {
    let path = model_path(path)?;
    let (parent_id, name) =
        fs.resolve_parent_inode(&path)
            .map_err(|errno| CrashOracleError::ModelErrno {
                op: op.to_string(),
                errno,
            })?;
    let binding = name_binding(&name);
    let envelope = contract_envelope(
        op,
        TideRequest::Vfs(VfsRequest::Unlink {
            parent_id,
            name: binding.token,
        }),
    );
    apply_contract_success(fs, &envelope, &[binding], op)
}

fn apply_contract_success(
    fs: &mut ModelFs,
    envelope: &RequestEnvelope,
    name_bindings: &[ContractNameBinding<'_>],
    op: &str,
) -> Result<(), CrashOracleError> {
    let step = fs
        .apply_contract_with_names(
            envelope,
            ContractModelContext::empty(),
            ContractNameContext::new(name_bindings),
        )
        .map_err(|err| CrashOracleError::ModelInvariant(err.to_string()))?;
    if step.is_success() {
        Ok(())
    } else {
        Err(CrashOracleError::ModelErrno {
            op: op.to_string(),
            errno: step.errno(),
        })
    }
}

fn name_binding(component: &str) -> ContractNameBinding<'_> {
    ContractNameBinding::new(
        VfsNameToken::from_component_bytes(component.as_bytes()),
        component,
    )
}

fn contract_envelope(op: &str, request: TideRequest) -> RequestEnvelope {
    let mut metadata =
        RequestMetadata::new(request_id(op), ContractEpoch::new(0x317), trace_id(op));
    metadata.work_class = WorkClass::Foreground;
    metadata.admission = AdmissionIntent::RequirePermit;
    metadata.budget = BudgetIntent::Foreground;
    metadata.fence = FenceIntent::Write;
    metadata.retry = RetryIntent::None;
    RequestEnvelope::new(metadata, request)
}

fn request_id(op: &str) -> RequestId {
    let mut bytes = [0_u8; 16];
    mix_label_bytes(&mut bytes, op.as_bytes());
    bytes[15] ^= 0x31;
    RequestId::new(bytes)
}

fn trace_id(op: &str) -> TraceId {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&0x317_u64.to_le_bytes());
    mix_label_bytes(&mut bytes[8..], op.as_bytes());
    TraceId::new(bytes)
}

fn mix_label_bytes(out: &mut [u8], label: &[u8]) {
    let len = out.len();
    for (index, byte) in label.iter().enumerate() {
        out[index % len] ^= *byte;
    }
}

fn apply_success(
    fs: &mut ModelFs,
    request: ModelRequest,
    op: &str,
) -> Result<(), CrashOracleError> {
    let step = fs
        .apply(request)
        .map_err(|err| CrashOracleError::ModelInvariant(err.to_string()))?;
    if step.is_success() {
        Ok(())
    } else {
        Err(CrashOracleError::ModelErrno {
            op: op.to_string(),
            errno: step.errno(),
        })
    }
}

fn model_path(path: &str) -> Result<ModelPath, CrashOracleError> {
    ModelPath::parse_absolute(path).map_err(|errno| CrashOracleError::ModelErrno {
        op: format!("parse path {path}"),
        errno,
    })
}

fn diff_paths(
    expected: &ModelFs,
    recovered: &ModelFs,
    paths: &[&str],
    expectation: &str,
) -> Result<Vec<RecoveredStateDiff>, CrashOracleError> {
    let mut diffs = Vec::new();
    for path in paths {
        let expected_observation = observe_path(expected, path)?;
        let recovered_observation = observe_path(recovered, path)?;
        if expected_observation.exists != recovered_observation.exists {
            diffs.push(RecoveredStateDiff {
                path: (*path).to_string(),
                field: "exists".to_string(),
                expected: expectation.to_string(),
                recovered: recovered_observation.exists.to_string(),
            });
        }
        if expected_observation.kind != recovered_observation.kind {
            diffs.push(RecoveredStateDiff {
                path: (*path).to_string(),
                field: "kind".to_string(),
                expected: expected_observation
                    .kind
                    .unwrap_or_else(|| "missing".to_string()),
                recovered: recovered_observation
                    .kind
                    .unwrap_or_else(|| "missing".to_string()),
            });
        }
        if expected_observation.size != recovered_observation.size {
            diffs.push(RecoveredStateDiff {
                path: (*path).to_string(),
                field: "size".to_string(),
                expected: expected_observation
                    .size
                    .map(|size| size.to_string())
                    .unwrap_or_else(|| "missing".to_string()),
                recovered: recovered_observation
                    .size
                    .map(|size| size.to_string())
                    .unwrap_or_else(|| "missing".to_string()),
            });
        }
        if expected_observation.content_hex != recovered_observation.content_hex {
            diffs.push(RecoveredStateDiff {
                path: (*path).to_string(),
                field: "content-hex".to_string(),
                expected: expected_observation
                    .content_hex
                    .unwrap_or_else(|| "missing".to_string()),
                recovered: recovered_observation
                    .content_hex
                    .unwrap_or_else(|| "missing".to_string()),
            });
        }
    }
    Ok(diffs)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathObservation {
    exists: bool,
    kind: Option<String>,
    size: Option<u64>,
    content_hex: Option<String>,
}

fn observe_path(fs: &ModelFs, path: &str) -> Result<PathObservation, CrashOracleError> {
    let model_path = model_path(path)?;
    let attr = match fs.attr(&model_path) {
        Ok(attr) => attr,
        Err(Errno::ENOENT) => {
            return Ok(PathObservation {
                exists: false,
                kind: None,
                size: None,
                content_hex: None,
            });
        }
        Err(errno) => {
            return Err(CrashOracleError::ModelErrno {
                op: format!("observe {path}"),
                errno,
            });
        }
    };

    let content_hex = if attr.kind == ModelNodeKind::File {
        let mut clone = fs.clone();
        let step = clone
            .apply(ModelRequest::Read {
                path: model_path,
                offset: 0,
                length: attr.size,
            })
            .map_err(|err| CrashOracleError::ModelInvariant(err.to_string()))?;
        if !step.is_success() {
            return Err(CrashOracleError::ModelErrno {
                op: format!("read {path} for recovered-state diff"),
                errno: step.errno(),
            });
        }
        match step.output {
            ModelOutput::Bytes(bytes) => Some(bytes_to_hex(&bytes)),
            ModelOutput::None | ModelOutput::Attr(_) => None,
        }
    } else {
        None
    };

    Ok(PathObservation {
        exists: true,
        kind: Some(model_kind_name(attr.kind).to_string()),
        size: Some(attr.size),
        content_hex,
    })
}

fn model_kind_name(kind: ModelNodeKind) -> &'static str {
    match kind {
        ModelNodeKind::Directory => "directory",
        ModelNodeKind::File => "file",
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn write_forbidden_trace() -> MinimizedCrashTrace {
    MinimizedCrashTrace {
        id: "write-fsync-old-file-forbidden".to_string(),
        replay_hint: format!("cargo run -p tidefs-crash-oracle -- {ISSUE_286_ARTIFACT_PATH}"),
        operations: vec![
            op("create", Some("/file"), None, None, None, None),
            op(
                "write",
                Some("/file"),
                None,
                Some(0),
                Some(bytes_to_hex(b"old")),
                None,
            ),
            op("fsync", Some("/file"), None, None, None, None),
            op(
                "write",
                Some("/file"),
                None,
                Some(0),
                Some(bytes_to_hex(b"new-data")),
                None,
            ),
            op("fsync", Some("/file"), None, None, None, None),
            op(
                "crash_recover_at",
                None,
                None,
                None,
                None,
                Some(CrashBoundary::RootPublish),
            ),
        ],
    }
}

fn rename_forbidden_trace(id: &str, recovered: &str) -> MinimizedCrashTrace {
    MinimizedCrashTrace {
        id: id.to_string(),
        replay_hint: format!(
            "cargo run -p tidefs-crash-oracle -- {ISSUE_286_ARTIFACT_PATH}; recovered={recovered}"
        ),
        operations: vec![
            op("mkdir", Some("/dir"), None, None, None, None),
            op("create", Some("/dir/source"), None, None, None, None),
            op(
                "write",
                Some("/dir/source"),
                None,
                Some(0),
                Some(bytes_to_hex(b"rename-data")),
                None,
            ),
            op("fsync", Some("/dir/source"), None, None, None, None),
            op(
                "rename",
                Some("/dir/source"),
                Some("/dir/dest"),
                None,
                None,
                None,
            ),
            op(
                "crash_recover_at",
                None,
                None,
                None,
                None,
                Some(CrashBoundary::RecoveryReplay),
            ),
        ],
    }
}

fn op(
    name: &str,
    path: Option<&str>,
    to: Option<&str>,
    offset: Option<u64>,
    data_hex: Option<String>,
    boundary: Option<CrashBoundary>,
) -> CrashTraceOp {
    CrashTraceOp {
        op: name.to_string(),
        path: path.map(str::to_string),
        to: to.map(str::to_string),
        offset,
        data_hex,
        boundary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_crash_matrices_cover_required_classifications_and_boundaries() {
        let report = run_model_crash_matrices().expect("crash matrices");
        assert_eq!(report.report_version, REPORT_VERSION);
        assert!(report
            .matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .any(|case| case.boundary == CrashBoundary::IntentAppend));
        assert!(report
            .matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .any(|case| case.boundary == CrashBoundary::DataPublish));
        assert!(report
            .matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .any(|case| case.boundary == CrashBoundary::ExtentPublish));
        assert!(report
            .matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .any(|case| case.boundary == CrashBoundary::InodePublish));
        assert!(report
            .matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .any(|case| case.boundary == CrashBoundary::RootPublish));
        assert!(report
            .matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .any(|case| case.boundary == CrashBoundary::RecoveryReplay));
        assert!(report
            .matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .any(|case| case.boundary == CrashBoundary::PageDirtyMark));
        assert!(report
            .matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .any(|case| case.boundary == CrashBoundary::PageWritebackStart));
        assert!(report
            .matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .any(|case| case.boundary == CrashBoundary::PageWritebackComplete));
        assert!(report
            .matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .any(|case| case.boundary == CrashBoundary::CacheEvict));
        assert!(report.classification_count(CrashClassification::Valid) > 0);
        assert!(report.classification_count(CrashClassification::LostUnfsynced) > 0);
        assert!(report.classification_count(CrashClassification::Forbidden) > 0);
        assert!(report.runtime_claims.iter().any(|claim| {
            claim.classification == CrashClassification::UnsupportedFailClosed
                && claim.claim_id == LOCAL_VFS_WRITE_FSYNC_CLAIM_ID
        }));
    }

    #[test]
    fn forbidden_recoveries_include_minimized_traces_and_state_diffs() {
        let report = run_model_crash_matrices().expect("crash matrices");
        for case in report
            .matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .filter(|case| case.classification == CrashClassification::Forbidden)
        {
            assert!(!case.recovered_state_diffs.is_empty(), "{}", case.id);
            let trace = case.minimized_trace.as_ref().expect("minimized trace");
            assert!(!trace.operations.is_empty(), "{}", case.id);
            assert!(trace
                .operations
                .iter()
                .any(|op| op.op == "crash_recover_at"));
        }
    }

    #[test]
    fn rename_claim_new_name_state_comes_from_contract_replay() {
        let mut fs = model_with_file("/dir/source", b"rename-data").expect("baseline");
        apply_contract_rename_success(
            &mut fs,
            "/dir/source",
            "/dir/dest",
            "rename /dir/source /dir/dest",
        )
        .expect("contract rename");
        assert!(!observe_path(&fs, "/dir/source").unwrap().exists);
        assert!(observe_path(&fs, "/dir/dest").unwrap().exists);

        let report = run_model_crash_matrices().expect("crash matrices");
        let rename_case = report
            .matrices
            .iter()
            .find(|matrix| matrix.id == RENAME_MATRIX_ID)
            .and_then(|matrix| {
                matrix
                    .cases
                    .iter()
                    .find(|case| case.id == "rename.root_publish.new_name")
            })
            .expect("rename root-publish case");

        let expected = fs.fingerprint().to_hex();
        assert_eq!(
            rename_case.recovered_fingerprint.as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn cache_dirty_page_matrix_covers_writeback_lifecycle() {
        let report = run_model_crash_matrices().expect("crash matrices");
        let cache_matrix = report
            .matrices
            .iter()
            .find(|m| m.id == CACHE_DIRTY_CRASH_MATRIX_ID)
            .expect("cache dirty page matrix present");

        assert_eq!(cache_matrix.cases.len(), 4);
        assert!(cache_matrix
            .cases
            .iter()
            .any(|c| c.id == "cache.page_dirty_mark"
                && c.classification == CrashClassification::LostUnfsynced));
        assert!(cache_matrix
            .cases
            .iter()
            .any(|c| c.id == "cache.page_writeback_start"
                && c.classification == CrashClassification::LostUnfsynced));
        assert!(cache_matrix
            .cases
            .iter()
            .any(|c| c.id == "cache.page_writeback_complete"
                && c.classification == CrashClassification::Valid));
        assert!(cache_matrix
            .cases
            .iter()
            .any(|c| c.id == "cache.evict_clean_page"
                && c.classification == CrashClassification::Valid));
    }

    #[test]
    fn cache_crash_claim_is_recorded() {
        let report = run_model_crash_matrices().expect("crash matrices");
        assert!(report.runtime_claims.iter().any(|c| {
            c.claim_id == CACHE_COHERENCY_CLAIM_ID && c.status == "proof-in-progress"
        }));
    }

    #[test]
    fn model_report_json_round_trips() {
        let report = run_model_crash_matrices().expect("crash matrices");
        let json = serde_json::to_string_pretty(&report).expect("serialize report");
        let decoded: CrashOracleReport = serde_json::from_str(&json).expect("decode report");
        decoded.validate().expect("valid decoded report");
        assert_eq!(decoded, report);
    }

    // --- Injection matrix tests ---

    #[test]
    fn injection_matrix_has_all_required_injection_points() {
        let matrix = define_local_vfs_crash_injection_matrix();
        assert_eq!(matrix.id, LOCAL_VFS_INJECTION_MATRIX_ID);
        assert!(!matrix.injection_points.is_empty());

        let ids: Vec<&str> = matrix
            .injection_points
            .iter()
            .map(|case| case.id.as_str())
            .collect();

        assert!(
            ids.contains(&"vfs.after_write.before_fsync"),
            "missing after-write-before-fsync"
        );
        assert!(
            ids.contains(&"vfs.after_fsync.before_unmount"),
            "missing after-fsync-before-unmount"
        );
        assert!(ids.contains(&"vfs.during_fsync"), "missing during-fsync");
        assert!(
            ids.contains(&"vfs.during_directory_update"),
            "missing during-directory-update"
        );
        assert!(
            ids.contains(&"vfs.during_inode_attribute_update"),
            "missing during-inode-attribute-update"
        );
    }

    #[test]
    fn injection_matrix_every_case_has_unique_id() {
        let matrix = define_local_vfs_crash_injection_matrix();
        let mut seen = std::collections::HashSet::new();
        for case in &matrix.injection_points {
            assert!(
                seen.insert(&case.id),
                "duplicate injection point id: {}",
                case.id
            );
        }
    }

    #[test]
    fn injection_matrix_every_case_has_non_empty_fields() {
        let matrix = define_local_vfs_crash_injection_matrix();
        for case in &matrix.injection_points {
            assert!(!case.id.is_empty(), "empty id");
            assert!(!case.operation.is_empty(), "{}: empty operation", case.id);
            assert!(
                !case.expected_outcome.is_empty(),
                "{}: empty expected_outcome",
                case.id
            );
            assert!(
                !case.evidence_class.is_empty(),
                "{}: empty evidence_class",
                case.id
            );
        }
    }

    #[test]
    fn injection_matrix_pre_fsync_crashes_allow_data_absent() {
        let matrix = define_local_vfs_crash_injection_matrix();
        // Pre-fsync injection points must allow data to be absent
        let pre_fsync: Vec<&CrashInjectionCase> = matrix
            .injection_points
            .iter()
            .filter(|case| {
                matches!(
                    case.injection_point,
                    CrashInjectionPoint::AfterWriteBeforeFsync
                        | CrashInjectionPoint::DuringFsync
                        | CrashInjectionPoint::DuringDirectoryUpdate
                        | CrashInjectionPoint::DuringInodeAttributeUpdate
                )
            })
            .collect();
        assert!(!pre_fsync.is_empty());
        for case in &pre_fsync {
            assert!(
                case.data_absent_allowed,
                "{}: pre-fsync crash must allow data absent",
                case.id
            );
            assert!(
                !case.data_correct_required,
                "{}: pre-fsync crash must not require data correct",
                case.id
            );
        }
    }

    #[test]
    fn injection_matrix_all_cases_forbid_torn_data() {
        let matrix = define_local_vfs_crash_injection_matrix();
        for case in &matrix.injection_points {
            assert!(
                case.data_torn_forbidden,
                "{}: torn data must be forbidden",
                case.id
            );
        }
    }

    #[test]
    fn injection_matrix_all_cases_require_metadata_consistent() {
        let matrix = define_local_vfs_crash_injection_matrix();
        for case in &matrix.injection_points {
            assert!(
                case.metadata_consistent_required,
                "{}: metadata must be consistent",
                case.id
            );
        }
    }

    #[test]
    fn injection_matrix_post_fsync_crash_requires_data_correct() {
        let matrix = define_local_vfs_crash_injection_matrix();
        let post_fsync = matrix
            .injection_points
            .iter()
            .find(|case| case.id == "vfs.after_fsync.before_unmount")
            .expect("missing after-fsync-before-unmount case");
        assert!(post_fsync.data_correct_required);
        assert!(!post_fsync.data_absent_allowed);
        assert_eq!(post_fsync.classification, CrashClassification::Valid);
    }

    #[test]
    fn injection_matrix_no_case_has_runtime_evidence() {
        let matrix = define_local_vfs_crash_injection_matrix();
        for case in &matrix.injection_points {
            assert!(
                !case.has_runtime_evidence,
                "{}: must not claim runtime evidence in definition-only matrix",
                case.id
            );
            assert!(
                case.blocked_reason.is_some(),
                "{}: must have a blocked reason",
                case.id
            );
        }
    }

    #[test]
    fn injection_matrix_round_trips_through_json() {
        let matrix = define_local_vfs_crash_injection_matrix();
        let json = serde_json::to_string_pretty(&matrix).expect("serialize");
        let decoded: CrashInjectionMatrix = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, matrix);
    }

    #[test]
    fn report_includes_injection_matrix_and_validates() {
        let report = run_model_crash_matrices().expect("crash matrices");
        assert_eq!(
            report.injection_matrices.len(),
            1,
            "report must have one injection matrix"
        );
        let matrix = &report.injection_matrices[0];
        assert_eq!(matrix.id, LOCAL_VFS_INJECTION_MATRIX_ID);
        assert!(
            report.injection_case_count() >= 5,
            "must have at least 5 injection points"
        );
        report.validate().expect("report validates");
    }

    #[test]
    fn report_validation_rejects_duplicate_injection_ids() {
        let mut report = run_model_crash_matrices().expect("crash matrices");
        let duplicate = report.injection_matrices[0].injection_points[0].clone();
        report.injection_matrices[0]
            .injection_points
            .push(duplicate);

        let err = report
            .validate()
            .expect_err("duplicate injection id must fail validation");
        assert!(
            err.to_string().contains("duplicate injection point id"),
            "{err}"
        );
    }

    #[test]
    fn injection_point_as_str_round_trips() {
        for point in &[
            CrashInjectionPoint::AfterWriteBeforeFsync,
            CrashInjectionPoint::AfterFsyncBeforeUnmount,
            CrashInjectionPoint::DuringFsync,
            CrashInjectionPoint::DuringDirectoryUpdate,
            CrashInjectionPoint::DuringInodeAttributeUpdate,
        ] {
            let s = point.as_str();
            assert!(!s.is_empty());
            // Verify each serialized name is kebab-case and not empty
            assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
        }
    }

    #[test]
    fn injection_matrix_claim_ids_reference_existing_claims() {
        let matrix = define_local_vfs_crash_injection_matrix();
        assert!(matrix
            .claim_ids
            .contains(&LOCAL_VFS_WRITE_FSYNC_CLAIM_ID.to_string()));
        assert!(matrix
            .claim_ids
            .contains(&STORAGE_WRITE_FSYNC_CLAIM_ID.to_string()));
    }
}
