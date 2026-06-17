#![forbid(unsafe_code)]

//! Model-first crash oracle for bounded TideFS persistence-boundary matrices.
//!
//! This crate deliberately evaluates the pure `tidefs-model-core` state
//! machine only. It records semantic crash boundaries and model recovery
//! classifications, but it does not claim local runtime crash safety or
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrashOracleReport {
    pub report_version: u64,
    pub generated_by: String,
    pub evidence_scope: String,
    pub runtime_claim_boundary: String,
    pub matrices: Vec<CrashMatrix>,
    pub runtime_claims: Vec<RuntimeClaimStatus>,
}

impl CrashOracleReport {
    #[must_use]
    pub fn case_count(&self) -> usize {
        self.matrices.iter().map(|matrix| matrix.cases.len()).sum()
    }

    #[must_use]
    pub fn classification_count(&self, classification: CrashClassification) -> usize {
        self.matrices
            .iter()
            .flat_map(|matrix| &matrix.cases)
            .filter(|case| case.classification == classification)
            .count()
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
        description:
            "cache dirty-page crash matrix across writeback lifecycle boundaries"
                .to_string(),
        cases: vec![
            crash_case(
                "cache.page_dirty_mark",
                "page dirty mark",
                CrashBoundary::PageDirtyMark,
                CrashClassification::LostUnfsynced,
                &baseline,
                vec![
                    acceptable("initial-data", CrashClassification::LostUnfsynced, &baseline),
                ],
                vec![],
                None,
            ),
            crash_case(
                "cache.page_writeback_start",
                "page writeback start",
                CrashBoundary::PageWritebackStart,
                CrashClassification::LostUnfsynced,
                &baseline,
                vec![
                    acceptable("initial-data", CrashClassification::LostUnfsynced, &baseline),
                ],
                vec![],
                None,
            ),
            crash_case(
                "cache.page_writeback_complete",
                "page writeback complete",
                CrashBoundary::PageWritebackComplete,
                CrashClassification::Valid,
                &after_fsync,
                vec![
                    acceptable("durable-data", CrashClassification::Valid, &after_fsync),
                ],
                vec![],
                None,
            ),
            crash_case(
                "cache.evict_clean_page",
                "clean page eviction",
                CrashBoundary::CacheEvict,
                CrashClassification::Valid,
                &baseline,
                vec![
                    acceptable("initial-data", CrashClassification::Valid, &baseline),
                ],
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
            "local runtime write/fsync and rename claims stay planned/blocked until runtime evidence exists"
                .to_string(),
        matrices: vec![write_fsync_matrix()?, rename_matrix()?, cache_dirty_page_matrix()?],
        runtime_claims: vec![
            RuntimeClaimStatus {
                claim_id: LOCAL_VFS_WRITE_FSYNC_CLAIM_ID.to_string(),
                status: "blocked".to_string(),
                classification: CrashClassification::UnsupportedFailClosed,
                reason:
                    "local runtime crash injection is intentionally outside the model-first slice"
                        .to_string(),
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
            c.claim_id == CACHE_COHERENCY_CLAIM_ID
                && c.status == "proof-in-progress"
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
}
