// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use serde::Deserialize;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

use crate::validation_status::ValidationStatus;

pub const LOCAL_VFS_WRITE_FSYNC_RUNTIME_CRASH_EVIDENCE_CLASS: &str = "runtime-crash-oracle";
pub const LOCAL_VFS_WRITE_FSYNC_RUNTIME_CRASH_CLAIM_ID: &str = "local.vfs.write_fsync_crash.v1";
pub const LOCAL_VFS_RENAME_RUNTIME_CRASH_EVIDENCE_CLASS: &str = "runtime-namespace-crash-artifact";
pub const LOCAL_VFS_RENAME_RUNTIME_CRASH_CLAIM_ID: &str = "local.vfs.rename_atomic_crash.v1";
const LOCAL_VFS_RENAME_RUNTIME_SCENARIO: &str = "local-vfs-rename-fsync-read-crash-recover";
const MOUNTED_FUSE_WRITE_FSYNC_RUNTIME_SCENARIO: &str =
    "mounted-fuse-write-fsync-read-crash-recover";
const LOCAL_VFS_RUNTIME_PATH: &str = "local-vfs";
const MOUNTED_FUSE_RUNTIME_PATH: &str = "mounted-fuse";
const MOUNT_HARNESS_BACKEND: &str = "MountHarness";
const MOUNTED_FUSE_CRASH_TEST: &str = "mounted_write_fsync_read_crash_recover";
const PROCESS_EXIT_AFTER_READ: &str = "ProcessExitAfterRead";
const POWER_LOSS_CRASH_MODE: &str = "PowerLoss";
const POWER_LOSS_EXIT_CODE: i32 = 99;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalVfsRuntimeCrashArtifactSummary {
    pub event_count: usize,
    pub dependency_count: usize,
    pub recovered_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalVfsRuntimeCrashArtifactError {
    failures: Vec<String>,
}

impl LocalVfsRuntimeCrashArtifactError {
    #[must_use]
    pub fn failures(&self) -> &[String] {
        &self.failures
    }
}

impl fmt::Display for LocalVfsRuntimeCrashArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "local VFS runtime crash artifact validation failed:")?;
        for failure in &self.failures {
            writeln!(f, "- {failure}")?;
        }
        Ok(())
    }
}

impl Error for LocalVfsRuntimeCrashArtifactError {}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalVfsRuntimeCrashArtifact {
    report_version: u32,
    generated_by: String,
    claim_ids: Vec<String>,
    evidence_class: String,
    evidence_scope: String,
    scenario: String,
    runtime_path: String,
    run_id: String,
    source_ref: String,
    command: String,
    backend: String,
    output_location: String,
    observed_outcome: ValidationStatus,
    #[serde(default)]
    completed_fsync: Option<CompletedFsyncObservation>,
    #[serde(default)]
    crash: Option<MountedFuseCrashObservation>,
    #[serde(default)]
    recovery: Option<RecoveryObservation>,
    #[serde(default)]
    dependencies: Vec<RuntimeDependency>,
    non_claims: Vec<NonClaimBoundary>,
    #[serde(default)]
    events: Vec<RuntimeCrashEvent>,
    #[serde(default)]
    refusal: Option<RuntimeRefusal>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalVfsRenameRuntimeCrashArtifact {
    report_version: u32,
    generated_by: String,
    claim_ids: Vec<String>,
    evidence_class: String,
    evidence_scope: String,
    scenario: String,
    runtime_path: String,
    crash_injection_point: String,
    crash_mode: String,
    child_exit_code: i32,
    initial_file: RenameInitialObservation,
    renamed_file: RenamedFileObservation,
    recovery: RenameRecoveryObservation,
    dependencies: Vec<RuntimeDependency>,
    non_claims: Vec<NonClaimBoundary>,
    validation_hint: String,
    events: Vec<RuntimeCrashEvent>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NonClaimBoundary {
    category: String,
    claim_id: String,
    evidence_class: String,
    evidence_scope: String,
    excluded_product_claim: String,
    remaining_risk: String,
    blocking_issue: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedFsyncObservation {
    path: String,
    payload_label: String,
    content_digest: String,
    fsync_completed: bool,
    read_back_before_crash: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MountedFuseCrashObservation {
    signal: String,
    remount_succeeded: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRefusal {
    environment_primitive: String,
    reason: String,
    observed_free_bytes: u64,
    required_free_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryObservation {
    reopen_succeeded: bool,
    read_after_recovery_succeeded: bool,
    path: String,
    recovered_content_digest: String,
    classification: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeDependency {
    issue: u64,
    subject: String,
    status: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCrashEvent {
    sequence: u64,
    operation: String,
    path: Option<String>,
    result: String,
    source: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameInitialObservation {
    path: String,
    payload_label: String,
    content_digest: String,
    fsync_completed: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenamedFileObservation {
    old_path: String,
    new_path: String,
    payload_label: String,
    content_digest: String,
    rename_completed: bool,
    fsync_completed: bool,
    read_back_before_crash: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameRecoveryObservation {
    reopen_succeeded: bool,
    old_path_absent: bool,
    new_path: String,
    read_after_recovery_succeeded: bool,
    recovered_content_digest: String,
    classification: String,
}

#[must_use]
pub fn validate_local_vfs_runtime_crash_artifact_json(
    text: &str,
) -> Result<LocalVfsRuntimeCrashArtifactSummary, LocalVfsRuntimeCrashArtifactError> {
    let artifact = match serde_json::from_str::<LocalVfsRuntimeCrashArtifact>(text) {
        Ok(artifact) => artifact,
        Err(error) => {
            return Err(LocalVfsRuntimeCrashArtifactError {
                failures: vec![format!("artifact JSON does not match schema: {error}")],
            });
        }
    };
    validate_local_vfs_runtime_crash_artifact(artifact)
}

pub fn validate_local_vfs_runtime_crash_artifact_path(
    path: impl AsRef<Path>,
) -> Result<LocalVfsRuntimeCrashArtifactSummary, LocalVfsRuntimeCrashArtifactError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|error| LocalVfsRuntimeCrashArtifactError {
        failures: vec![format!("read `{}`: {error}", path.display())],
    })?;
    validate_local_vfs_runtime_crash_artifact_json(&text)
}

#[must_use]
pub fn validate_local_vfs_rename_runtime_crash_artifact_json(
    text: &str,
) -> Result<LocalVfsRuntimeCrashArtifactSummary, LocalVfsRuntimeCrashArtifactError> {
    let artifact = match serde_json::from_str::<LocalVfsRenameRuntimeCrashArtifact>(text) {
        Ok(artifact) => artifact,
        Err(error) => {
            return Err(LocalVfsRuntimeCrashArtifactError {
                failures: vec![format!("artifact JSON does not match schema: {error}")],
            });
        }
    };
    validate_local_vfs_rename_runtime_crash_artifact(artifact)
}

pub fn validate_local_vfs_rename_runtime_crash_artifact_path(
    path: impl AsRef<Path>,
) -> Result<LocalVfsRuntimeCrashArtifactSummary, LocalVfsRuntimeCrashArtifactError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|error| LocalVfsRuntimeCrashArtifactError {
        failures: vec![format!("read `{}`: {error}", path.display())],
    })?;
    validate_local_vfs_rename_runtime_crash_artifact_json(&text)
}

fn validate_local_vfs_runtime_crash_artifact(
    artifact: LocalVfsRuntimeCrashArtifact,
) -> Result<LocalVfsRuntimeCrashArtifactSummary, LocalVfsRuntimeCrashArtifactError> {
    let mut failures = Vec::new();
    validate_static_fields(&artifact, &mut failures);
    match artifact.observed_outcome {
        ValidationStatus::Pass => {
            validate_mounted_fuse_runtime_observations(&artifact, &mut failures)
        }
        ValidationStatus::EnvironmentRefusal => validate_runtime_refusal(&artifact, &mut failures),
        other => failures.push(format!(
            "observed_outcome must be `pass` or `environment-refusal`, found `{}`",
            other.label()
        )),
    }
    validate_non_claims(
        &artifact.non_claims,
        LOCAL_VFS_WRITE_FSYNC_RUNTIME_CRASH_CLAIM_ID,
        LOCAL_VFS_WRITE_FSYNC_RUNTIME_CRASH_EVIDENCE_CLASS,
        &artifact.evidence_scope,
        &[
            "production-crash-safety",
            "model-crash-matrix",
            "queue-depth-no-hidden-queue",
            "interrupted-fsync-durability",
        ],
        &mut failures,
    );

    if failures.is_empty() {
        Ok(LocalVfsRuntimeCrashArtifactSummary {
            event_count: artifact.events.len(),
            dependency_count: artifact.dependencies.len(),
            recovered_digest: artifact
                .recovery
                .as_ref()
                .map(|recovery| recovery.recovered_content_digest.clone())
                .unwrap_or_else(|| "environment-refusal".to_string()),
        })
    } else {
        Err(LocalVfsRuntimeCrashArtifactError { failures })
    }
}

fn validate_local_vfs_rename_runtime_crash_artifact(
    artifact: LocalVfsRenameRuntimeCrashArtifact,
) -> Result<LocalVfsRuntimeCrashArtifactSummary, LocalVfsRuntimeCrashArtifactError> {
    let mut failures = Vec::new();
    validate_rename_static_fields(&artifact, &mut failures);
    validate_rename_runtime_observations(&artifact, &mut failures);
    validate_rename_events(&artifact.events, &mut failures);
    validate_rename_dependencies(&artifact.dependencies, &mut failures);
    validate_non_claims(
        &artifact.non_claims,
        LOCAL_VFS_RENAME_RUNTIME_CRASH_CLAIM_ID,
        LOCAL_VFS_RENAME_RUNTIME_CRASH_EVIDENCE_CLASS,
        &artifact.evidence_scope,
        &[
            "production-crash-safety",
            "model-crash-matrix",
            "queue-depth-no-hidden-queue",
            "broader-namespace-atomicity",
        ],
        &mut failures,
    );

    if failures.is_empty() {
        Ok(LocalVfsRuntimeCrashArtifactSummary {
            event_count: artifact.events.len(),
            dependency_count: artifact.dependencies.len(),
            recovered_digest: artifact.recovery.recovered_content_digest,
        })
    } else {
        Err(LocalVfsRuntimeCrashArtifactError { failures })
    }
}

fn validate_static_fields(artifact: &LocalVfsRuntimeCrashArtifact, failures: &mut Vec<String>) {
    if artifact.report_version != 2 {
        failures.push(format!(
            "report_version must be 2, found {}",
            artifact.report_version
        ));
    }
    if artifact.generated_by.trim().is_empty() {
        failures.push("generated_by must not be empty".to_string());
    }
    if !artifact
        .claim_ids
        .iter()
        .any(|claim_id| claim_id == LOCAL_VFS_WRITE_FSYNC_RUNTIME_CRASH_CLAIM_ID)
    {
        failures.push(format!(
            "claim_ids must include `{LOCAL_VFS_WRITE_FSYNC_RUNTIME_CRASH_CLAIM_ID}`"
        ));
    }
    if artifact.evidence_class != LOCAL_VFS_WRITE_FSYNC_RUNTIME_CRASH_EVIDENCE_CLASS {
        failures.push(format!(
            "evidence_class must be `{LOCAL_VFS_WRITE_FSYNC_RUNTIME_CRASH_EVIDENCE_CLASS}`, found `{}`",
            artifact.evidence_class
        ));
    }
    let scope = artifact.evidence_scope.to_ascii_lowercase();
    for required in ["mounted", "fuse", "runtime", "write", "fsync", "crash"] {
        if !scope.contains(required) {
            failures.push(format!("evidence_scope must mention `{required}`"));
        }
    }
    if scope.contains("model-only") {
        failures.push("evidence_scope must not be model-only".to_string());
    }
    if artifact.scenario != MOUNTED_FUSE_WRITE_FSYNC_RUNTIME_SCENARIO {
        failures.push(format!(
            "scenario must be `{MOUNTED_FUSE_WRITE_FSYNC_RUNTIME_SCENARIO}`, found `{}`",
            artifact.scenario
        ));
    }
    if artifact.runtime_path != MOUNTED_FUSE_RUNTIME_PATH {
        failures.push(format!(
            "runtime_path must be `{MOUNTED_FUSE_RUNTIME_PATH}`, found `{}`",
            artifact.runtime_path
        ));
    }
    if artifact.run_id.trim().is_empty()
        || artifact.run_id.to_ascii_lowercase().contains("fixture")
        || artifact.run_id.to_ascii_lowercase().contains("placeholder")
    {
        failures.push(format!(
            "run_id must identify a non-fixture mounted runtime attempt, found `{}`",
            artifact.run_id
        ));
    }
    if artifact.source_ref.len() != 40
        || !artifact
            .source_ref
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        failures.push("source_ref must record the 40-hex source commit".to_string());
    }
    if !artifact.command.contains("cargo test")
        || !artifact.command.contains(MOUNTED_FUSE_CRASH_TEST)
        || !artifact.command.contains("--ignored")
    {
        failures.push(format!(
            "command must record the explicit Cargo invocation for `{MOUNTED_FUSE_CRASH_TEST}`"
        ));
    }
    if artifact.backend != MOUNT_HARNESS_BACKEND {
        failures.push(format!(
            "backend must be `{MOUNT_HARNESS_BACKEND}`, found `{}`",
            artifact.backend
        ));
    }
    if artifact.output_location.trim().is_empty() {
        failures.push("output_location must not be empty".to_string());
    }
    if [
        artifact.generated_by.as_str(),
        artifact.command.as_str(),
        artifact.backend.as_str(),
    ]
    .iter()
    .any(|value| value.to_ascii_lowercase().contains("localfilesystem"))
    {
        failures.push(
            "mounted runtime provenance must not name LocalFileSystem fixture execution"
                .to_string(),
        );
    }
}

fn validate_rename_static_fields(
    artifact: &LocalVfsRenameRuntimeCrashArtifact,
    failures: &mut Vec<String>,
) {
    if artifact.report_version != 1 {
        failures.push(format!(
            "report_version must be 1, found {}",
            artifact.report_version
        ));
    }
    if artifact.generated_by.trim().is_empty() {
        failures.push("generated_by must not be empty".to_string());
    }
    if !artifact
        .claim_ids
        .iter()
        .any(|claim_id| claim_id == LOCAL_VFS_RENAME_RUNTIME_CRASH_CLAIM_ID)
    {
        failures.push(format!(
            "claim_ids must include `{LOCAL_VFS_RENAME_RUNTIME_CRASH_CLAIM_ID}`"
        ));
    }
    if artifact.evidence_class != LOCAL_VFS_RENAME_RUNTIME_CRASH_EVIDENCE_CLASS {
        failures.push(format!(
            "evidence_class must be `{LOCAL_VFS_RENAME_RUNTIME_CRASH_EVIDENCE_CLASS}`, found `{}`",
            artifact.evidence_class
        ));
    }
    let scope = artifact.evidence_scope.to_ascii_lowercase();
    for required in ["local", "vfs", "runtime", "rename", "fsync", "crash"] {
        if !scope.contains(required) {
            failures.push(format!("evidence_scope must mention `{required}`"));
        }
    }
    if scope.contains("model-only") {
        failures.push("evidence_scope must not be model-only".to_string());
    }
    if artifact.scenario != LOCAL_VFS_RENAME_RUNTIME_SCENARIO {
        failures.push(format!(
            "scenario must be `{LOCAL_VFS_RENAME_RUNTIME_SCENARIO}`, found `{}`",
            artifact.scenario
        ));
    }
    if artifact.runtime_path != LOCAL_VFS_RUNTIME_PATH {
        failures.push(format!(
            "runtime_path must be `{LOCAL_VFS_RUNTIME_PATH}`, found `{}`",
            artifact.runtime_path
        ));
    }
    if artifact.crash_injection_point != PROCESS_EXIT_AFTER_READ {
        failures.push(format!(
            "crash_injection_point must be `{PROCESS_EXIT_AFTER_READ}`, found `{}`",
            artifact.crash_injection_point
        ));
    }
    if artifact.crash_mode != POWER_LOSS_CRASH_MODE {
        failures.push(format!(
            "crash_mode must be `{POWER_LOSS_CRASH_MODE}`, found `{}`",
            artifact.crash_mode
        ));
    }
    if artifact.child_exit_code != POWER_LOSS_EXIT_CODE {
        failures.push(format!(
            "child_exit_code must be {POWER_LOSS_EXIT_CODE} for PowerLoss crash mode, found {}",
            artifact.child_exit_code
        ));
    }
    if artifact.validation_hint.trim().is_empty() {
        failures.push("validation_hint must not be empty".to_string());
    }
}

fn validate_mounted_fuse_runtime_observations(
    artifact: &LocalVfsRuntimeCrashArtifact,
    failures: &mut Vec<String>,
) {
    let Some(completed_fsync) = artifact.completed_fsync.as_ref() else {
        failures.push("pass artifact must include completed_fsync".to_string());
        return;
    };
    let Some(crash) = artifact.crash.as_ref() else {
        failures.push("pass artifact must include crash".to_string());
        return;
    };
    let Some(recovery) = artifact.recovery.as_ref() else {
        failures.push("pass artifact must include recovery".to_string());
        return;
    };

    if artifact.refusal.is_some() {
        failures.push("pass artifact must not include a refusal record".to_string());
    }
    if completed_fsync.path != recovery.path {
        failures.push("completed_fsync and recovery must name the same path".to_string());
    }
    if !completed_fsync.fsync_completed {
        failures.push("completed_fsync.fsync_completed must be true".to_string());
    }
    if !completed_fsync.read_back_before_crash {
        failures.push("completed_fsync.read_back_before_crash must be true".to_string());
    }
    if crash.signal != "SIGKILL" || !crash.remount_succeeded {
        failures.push("crash must record SIGKILL followed by a successful remount".to_string());
    }
    if !recovery.reopen_succeeded || !recovery.read_after_recovery_succeeded {
        failures.push("recovery must reopen and read the target path successfully".to_string());
    }
    if recovery.recovered_content_digest != completed_fsync.content_digest {
        failures.push("recovery digest must match the last completed fsync digest".to_string());
    }
    if completed_fsync.payload_label.trim().is_empty()
        || completed_fsync.content_digest.trim().is_empty()
        || recovery.recovered_content_digest.trim().is_empty()
    {
        failures.push("payload labels and digests must not be empty".to_string());
    }
    if recovery.classification != "last-completed-fsync-survived" {
        failures
            .push("recovery.classification must be `last-completed-fsync-survived`".to_string());
    }
    validate_events(&artifact.events, failures);
    validate_dependencies(&artifact.dependencies, failures);
}

fn validate_runtime_refusal(artifact: &LocalVfsRuntimeCrashArtifact, failures: &mut Vec<String>) {
    let Some(refusal) = artifact.refusal.as_ref() else {
        failures.push("environment-refusal artifact must include refusal".to_string());
        return;
    };

    if artifact.completed_fsync.is_some()
        || artifact.crash.is_some()
        || artifact.recovery.is_some()
        || !artifact.events.is_empty()
        || !artifact.dependencies.is_empty()
    {
        failures.push(
            "environment-refusal must not include unobserved pass-only runtime fields".to_string(),
        );
    }
    if refusal.environment_primitive.trim().is_empty() || refusal.reason.trim().is_empty() {
        failures.push("refusal must name the environment primitive and reason".to_string());
    }
    if refusal.required_free_bytes == 0
        || refusal.observed_free_bytes >= refusal.required_free_bytes
    {
        failures.push(
            "refusal must show observed free space below the required free-space floor".to_string(),
        );
    }
}

fn validate_rename_runtime_observations(
    artifact: &LocalVfsRenameRuntimeCrashArtifact,
    failures: &mut Vec<String>,
) {
    if artifact.initial_file.path != artifact.renamed_file.old_path {
        failures.push("initial_file.path must match renamed_file.old_path".to_string());
    }
    if artifact.renamed_file.new_path != artifact.recovery.new_path {
        failures.push("renamed_file.new_path must match recovery.new_path".to_string());
    }
    if artifact.renamed_file.old_path == artifact.renamed_file.new_path {
        failures.push("rename old_path and new_path must differ".to_string());
    }
    if !artifact.initial_file.fsync_completed {
        failures.push("initial_file.fsync_completed must be true".to_string());
    }
    if !artifact.renamed_file.rename_completed {
        failures.push("renamed_file.rename_completed must be true".to_string());
    }
    if !artifact.renamed_file.fsync_completed {
        failures.push("renamed_file.fsync_completed must be true".to_string());
    }
    if !artifact.renamed_file.read_back_before_crash {
        failures.push("renamed_file.read_back_before_crash must be true".to_string());
    }
    if !artifact.recovery.reopen_succeeded
        || !artifact.recovery.read_after_recovery_succeeded
        || !artifact.recovery.old_path_absent
    {
        failures.push(
            "recovery must reopen, read the renamed path, and confirm the old path is absent"
                .to_string(),
        );
    }
    if artifact.initial_file.content_digest != artifact.renamed_file.content_digest {
        failures.push("renamed file digest must match the initial file digest".to_string());
    }
    if artifact.recovery.recovered_content_digest != artifact.renamed_file.content_digest {
        failures.push("recovery digest must match the renamed fsynced digest".to_string());
    }
    if artifact.initial_file.payload_label.trim().is_empty()
        || artifact.renamed_file.payload_label.trim().is_empty()
        || artifact.initial_file.content_digest.trim().is_empty()
        || artifact.renamed_file.content_digest.trim().is_empty()
        || artifact.recovery.recovered_content_digest.trim().is_empty()
    {
        failures.push("payload labels and digests must not be empty".to_string());
    }
    if artifact.recovery.classification != "renamed-fsynced-data-survived" {
        failures
            .push("recovery.classification must be `renamed-fsynced-data-survived`".to_string());
    }
}

fn validate_events(events: &[RuntimeCrashEvent], failures: &mut Vec<String>) {
    if events.is_empty() {
        failures.push("events must not be empty".to_string());
        return;
    }

    let mut last_sequence = None;
    let mut operations = BTreeSet::new();
    for event in events {
        if let Some(previous) = last_sequence {
            if event.sequence <= previous {
                failures.push(format!(
                    "event sequence {} is not strictly after previous sequence {previous}",
                    event.sequence
                ));
            }
        }
        last_sequence = Some(event.sequence);
        if event.operation.trim().is_empty() {
            failures.push(format!("event {} has empty operation", event.sequence));
        }
        if event.result.trim().is_empty() {
            failures.push(format!("event {} has empty result", event.sequence));
        }
        if event.source.trim().is_empty() {
            failures.push(format!("event {} has empty source", event.sequence));
        }
        if event.path.as_deref() == Some("") {
            failures.push(format!("event {} has empty path", event.sequence));
        }
        operations.insert(event.operation.as_str());
    }

    for required in [
        "mount",
        "write",
        "fsync",
        "read",
        "crash",
        "recover",
        "read_recovered",
    ] {
        if !operations.contains(required) {
            failures.push(format!("events must include `{required}` operation"));
        }
    }
    if !events
        .iter()
        .any(|event| event.source == MOUNT_HARNESS_BACKEND)
    {
        failures.push("events must include MountHarness provenance".to_string());
    }
    if events.iter().any(|event| {
        event
            .source
            .to_ascii_lowercase()
            .contains("localfilesystem")
    }) {
        failures.push("events must not cite LocalFileSystem fixture execution".to_string());
    }
}

fn validate_rename_events(events: &[RuntimeCrashEvent], failures: &mut Vec<String>) {
    validate_event_shape(events, failures);

    let operations = events
        .iter()
        .map(|event| event.operation.as_str())
        .collect::<BTreeSet<_>>();
    for required in [
        "rename",
        "fsync",
        "read",
        "crash",
        "recover",
        "read_recovered",
    ] {
        if !operations.contains(required) {
            failures.push(format!("events must include `{required}` operation"));
        }
    }
}

fn validate_event_shape(events: &[RuntimeCrashEvent], failures: &mut Vec<String>) {
    if events.is_empty() {
        failures.push("events must not be empty".to_string());
        return;
    }

    let mut last_sequence = None;
    for event in events {
        if let Some(previous) = last_sequence {
            if event.sequence <= previous {
                failures.push(format!(
                    "event sequence {} is not strictly after previous sequence {previous}",
                    event.sequence
                ));
            }
        }
        last_sequence = Some(event.sequence);
        if event.operation.trim().is_empty() {
            failures.push(format!("event {} has empty operation", event.sequence));
        }
        if event.result.trim().is_empty() {
            failures.push(format!("event {} has empty result", event.sequence));
        }
        if event.source.trim().is_empty() {
            failures.push(format!("event {} has empty source", event.sequence));
        }
        if event.path.as_deref() == Some("") {
            failures.push(format!("event {} has empty path", event.sequence));
        }
    }
}

fn validate_dependencies(dependencies: &[RuntimeDependency], failures: &mut Vec<String>) {
    let issues = dependencies
        .iter()
        .map(|dependency| dependency.issue)
        .collect::<BTreeSet<_>>();
    for required in [392_u64, 443, 445] {
        if !issues.contains(&required) {
            failures.push(format!("dependencies must record issue #{required}"));
        }
    }
    for dependency in dependencies {
        if dependency.subject.trim().is_empty() || dependency.status.trim().is_empty() {
            failures.push(format!(
                "dependency #{} must record a subject and status",
                dependency.issue
            ));
        }
    }
}

fn validate_rename_dependencies(dependencies: &[RuntimeDependency], failures: &mut Vec<String>) {
    let issues = dependencies
        .iter()
        .map(|dependency| dependency.issue)
        .collect::<BTreeSet<_>>();
    for required in [503_u64, 597] {
        if !issues.contains(&required) {
            failures.push(format!("dependencies must record issue #{required}"));
        }
    }
    for dependency in dependencies {
        if dependency.subject.trim().is_empty() || dependency.status.trim().is_empty() {
            failures.push(format!(
                "dependency #{} must record a subject and status",
                dependency.issue
            ));
        }
    }
}

fn validate_non_claims(
    non_claims: &[NonClaimBoundary],
    claim_id: &str,
    evidence_class: &str,
    evidence_scope: &str,
    required_categories: &[&str],
    failures: &mut Vec<String>,
) {
    let mut categories = BTreeSet::new();
    for non_claim in non_claims {
        if !categories.insert(non_claim.category.as_str()) {
            failures.push(format!(
                "non_claims must not duplicate category `{}`",
                non_claim.category
            ));
        }
        if non_claim.claim_id != claim_id {
            failures.push(format!(
                "non_claim `{}` must bind claim_id `{claim_id}`, found `{}`",
                non_claim.category, non_claim.claim_id
            ));
        }
        if non_claim.evidence_class != evidence_class {
            failures.push(format!(
                "non_claim `{}` must bind evidence_class `{evidence_class}`, found `{}`",
                non_claim.category, non_claim.evidence_class
            ));
        }
        if non_claim.evidence_scope != evidence_scope {
            failures.push(format!(
                "non_claim `{}` must bind the artifact evidence_scope",
                non_claim.category
            ));
        }
        if non_claim.excluded_product_claim.trim().is_empty() {
            failures.push(format!(
                "non_claim `{}` must name the excluded product claim",
                non_claim.category
            ));
        }
        if non_claim.remaining_risk.trim().is_empty() {
            failures.push(format!(
                "non_claim `{}` must record the remaining blocker or risk",
                non_claim.category
            ));
        }
        if non_claim.blocking_issue == Some(0) {
            failures.push(format!(
                "non_claim `{}` blocking_issue must be a nonzero issue number when present",
                non_claim.category
            ));
        }
    }
    for required in required_categories {
        if !categories.contains(required) {
            failures.push(format!(
                "non_claims must include structured category `{required}`"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{
      "report_version": 2,
      "generated_by": "apps/tidefs-posix-filesystem-adapter-daemon/tests/crash_recovery_ops.rs::mounted_write_fsync_read_crash_recover",
      "claim_ids": ["local.vfs.write_fsync_crash.v1"],
      "evidence_class": "runtime-crash-oracle",
      "evidence_scope": "bounded mounted FUSE runtime write/fsync/read crash/recover path",
      "scenario": "mounted-fuse-write-fsync-read-crash-recover",
      "runtime_path": "mounted-fuse",
      "run_id": "unit-mounted-fuse-2315",
      "source_ref": "0123456789abcdef0123456789abcdef01234567",
      "command": "cargo test -p tidefs-posix-filesystem-adapter-daemon --test crash_recovery_ops mounted_write_fsync_read_crash_recover -- --ignored --exact --nocapture",
      "backend": "MountHarness",
      "output_location": "/tmp/mounted-fuse-runtime.log",
      "observed_outcome": "pass",
      "completed_fsync": {
        "path": "/oracle.txt",
        "payload_label": "v1",
        "content_digest": "blake3:v1",
        "fsync_completed": true,
        "read_back_before_crash": true
      },
      "crash": {"signal": "SIGKILL", "remount_succeeded": true},
      "recovery": {
        "reopen_succeeded": true,
        "read_after_recovery_succeeded": true,
        "path": "/oracle.txt",
        "recovered_content_digest": "blake3:v1",
        "classification": "last-completed-fsync-survived"
      },
      "dependencies": [
        {"issue": 392, "subject": "fsync/syncfs", "status": "consumed"},
        {"issue": 443, "subject": "cache coherency", "status": "open"},
        {"issue": 445, "subject": "intent log", "status": "open"}
      ],
      "non_claims": [
        {
          "category": "production-crash-safety",
          "claim_id": "local.vfs.write_fsync_crash.v1",
          "evidence_class": "runtime-crash-oracle",
          "evidence_scope": "bounded mounted FUSE runtime write/fsync/read crash/recover path",
          "excluded_product_claim": "production crash safety",
          "remaining_risk": "storage-wide crash-safety coverage remains outside this bounded mounted FUSE artifact",
          "blocking_issue": 493
        },
        {
          "category": "model-crash-matrix",
          "claim_id": "local.vfs.write_fsync_crash.v1",
          "evidence_class": "runtime-crash-oracle",
          "evidence_scope": "bounded mounted FUSE runtime write/fsync/read crash/recover path",
          "excluded_product_claim": "model crash matrix replacement",
          "remaining_risk": "model crash matrix validation remains separate from this runtime artifact",
          "blocking_issue": null
        },
        {
          "category": "queue-depth-no-hidden-queue",
          "claim_id": "local.vfs.write_fsync_crash.v1",
          "evidence_class": "runtime-crash-oracle",
          "evidence_scope": "bounded mounted FUSE runtime write/fsync/read crash/recover path",
          "excluded_product_claim": "queue-depth and no-hidden-queue admission coverage",
          "remaining_risk": "runtime queue-depth evidence remains required before no-hidden-queue admission coverage can strengthen",
          "blocking_issue": null
        },
        {
          "category": "interrupted-fsync-durability",
          "claim_id": "local.vfs.write_fsync_crash.v1",
          "evidence_class": "runtime-crash-oracle",
          "evidence_scope": "bounded mounted FUSE runtime write/fsync/read crash/recover path",
          "excluded_product_claim": "interrupted fsync payload durability",
          "remaining_risk": "this row covers only a completed fsync before SIGKILL, not interruption during fsync",
          "blocking_issue": null
        }
      ],
      "events": [
        {"sequence": 1, "operation": "mount", "path": null, "result": "FUSE mount ready", "source": "MountHarness"},
        {"sequence": 2, "operation": "write", "path": "/oracle.txt", "result": "payload written through mounted path", "source": "MountHarness"},
        {"sequence": 3, "operation": "fsync", "path": "/oracle.txt", "result": "fsync completed", "source": "MountHarness"},
        {"sequence": 4, "operation": "read", "path": "/oracle.txt", "result": "payload read before crash", "source": "MountHarness"},
        {"sequence": 5, "operation": "crash", "path": null, "result": "daemon SIGKILL", "source": "MountHarness"},
        {"sequence": 6, "operation": "recover", "path": null, "result": "fresh daemon remounted the same store", "source": "MountHarness"},
        {"sequence": 7, "operation": "read_recovered", "path": "/oracle.txt", "result": "fsynced payload recovered", "source": "MountHarness"}
      ]
    }"#;

    const VALID_ENVIRONMENT_REFUSAL: &str = r#"{
      "report_version": 2,
      "generated_by": "apps/tidefs-posix-filesystem-adapter-daemon/tests/crash_recovery_ops.rs::mounted_write_fsync_read_crash_recover",
      "claim_ids": ["local.vfs.write_fsync_crash.v1"],
      "evidence_class": "runtime-crash-oracle",
      "evidence_scope": "bounded mounted FUSE runtime write/fsync/read crash/recover path",
      "scenario": "mounted-fuse-write-fsync-read-crash-recover",
      "runtime_path": "mounted-fuse",
      "run_id": "unit-mounted-fuse-refusal-2315",
      "source_ref": "0123456789abcdef0123456789abcdef01234567",
      "command": "cargo test -p tidefs-posix-filesystem-adapter-daemon --test crash_recovery_ops mounted_write_fsync_read_crash_recover -- --ignored --exact --nocapture",
      "backend": "MountHarness",
      "output_location": "/tmp/mounted-fuse-runtime-refusal.log",
      "observed_outcome": "environment-refusal",
      "refusal": {
        "environment_primitive": "root disk headroom",
        "reason": "the host cannot safely allocate the mounted runtime build closure",
        "observed_free_bytes": 10,
        "required_free_bytes": 50
      },
      "non_claims": [
        {
          "category": "production-crash-safety",
          "claim_id": "local.vfs.write_fsync_crash.v1",
          "evidence_class": "runtime-crash-oracle",
          "evidence_scope": "bounded mounted FUSE runtime write/fsync/read crash/recover path",
          "excluded_product_claim": "production crash safety",
          "remaining_risk": "the mounted runtime row was unavailable",
          "blocking_issue": 2315
        },
        {
          "category": "model-crash-matrix",
          "claim_id": "local.vfs.write_fsync_crash.v1",
          "evidence_class": "runtime-crash-oracle",
          "evidence_scope": "bounded mounted FUSE runtime write/fsync/read crash/recover path",
          "excluded_product_claim": "model crash matrix replacement",
          "remaining_risk": "model evidence remains separate",
          "blocking_issue": null
        },
        {
          "category": "queue-depth-no-hidden-queue",
          "claim_id": "local.vfs.write_fsync_crash.v1",
          "evidence_class": "runtime-crash-oracle",
          "evidence_scope": "bounded mounted FUSE runtime write/fsync/read crash/recover path",
          "excluded_product_claim": "queue-depth and no-hidden-queue admission coverage",
          "remaining_risk": "runtime queue-depth evidence remains required",
          "blocking_issue": null
        },
        {
          "category": "interrupted-fsync-durability",
          "claim_id": "local.vfs.write_fsync_crash.v1",
          "evidence_class": "runtime-crash-oracle",
          "evidence_scope": "bounded mounted FUSE runtime write/fsync/read crash/recover path",
          "excluded_product_claim": "interrupted fsync payload durability",
          "remaining_risk": "the mounted row did not execute",
          "blocking_issue": null
        }
      ]
    }"#;

    const VALID_RENAME: &str = r#"{
      "report_version": 1,
      "generated_by": "unit-test",
      "claim_ids": ["local.vfs.rename_atomic_crash.v1"],
      "evidence_class": "runtime-namespace-crash-artifact",
      "evidence_scope": "local VFS runtime rename/fsync/read crash/recover",
      "scenario": "local-vfs-rename-fsync-read-crash-recover",
      "runtime_path": "local-vfs",
      "crash_injection_point": "ProcessExitAfterRead",
      "crash_mode": "PowerLoss",
      "child_exit_code": 99,
      "initial_file": {
        "path": "/dir/source",
        "payload_label": "rename-payload",
        "content_digest": "sha256:rename",
        "fsync_completed": true
      },
      "renamed_file": {
        "old_path": "/dir/source",
        "new_path": "/dir/dest",
        "payload_label": "rename-payload",
        "content_digest": "sha256:rename",
        "rename_completed": true,
        "fsync_completed": true,
        "read_back_before_crash": true
      },
      "recovery": {
        "reopen_succeeded": true,
        "old_path_absent": true,
        "new_path": "/dir/dest",
        "read_after_recovery_succeeded": true,
        "recovered_content_digest": "sha256:rename",
        "classification": "renamed-fsynced-data-survived"
      },
      "dependencies": [
        {"issue": 503, "subject": "rename trace/oracle", "status": "consumed"},
        {"issue": 597, "subject": "rename no-hidden-queue", "status": "tracked separately"}
      ],
      "non_claims": [
        {
          "category": "production-crash-safety",
          "claim_id": "local.vfs.rename_atomic_crash.v1",
          "evidence_class": "runtime-namespace-crash-artifact",
          "evidence_scope": "local VFS runtime rename/fsync/read crash/recover",
          "excluded_product_claim": "production crash safety",
          "remaining_risk": "production crash-safety coverage remains outside this local VFS rename artifact",
          "blocking_issue": 493
        },
        {
          "category": "model-crash-matrix",
          "claim_id": "local.vfs.rename_atomic_crash.v1",
          "evidence_class": "runtime-namespace-crash-artifact",
          "evidence_scope": "local VFS runtime rename/fsync/read crash/recover",
          "excluded_product_claim": "model crash matrix replacement",
          "remaining_risk": "model crash matrix validation remains separate from this runtime artifact",
          "blocking_issue": null
        },
        {
          "category": "queue-depth-no-hidden-queue",
          "claim_id": "local.vfs.rename_atomic_crash.v1",
          "evidence_class": "runtime-namespace-crash-artifact",
          "evidence_scope": "local VFS runtime rename/fsync/read crash/recover",
          "excluded_product_claim": "queue-depth and no-hidden-queue admission coverage",
          "remaining_risk": "rename directory-entry, link/unlink, and orphan-index queue coverage remains tracked separately",
          "blocking_issue": 597
        },
        {
          "category": "broader-namespace-atomicity",
          "claim_id": "local.vfs.rename_atomic_crash.v1",
          "evidence_class": "runtime-namespace-crash-artifact",
          "evidence_scope": "local VFS runtime rename/fsync/read crash/recover",
          "excluded_product_claim": "broader namespace atomicity and distributed filesystem behavior",
          "remaining_risk": "kernel, distributed recovery, OpenZFS, and Ceph-class behavior remain outside this artifact",
          "blocking_issue": null
        }
      ],
      "validation_hint": "cargo test -p tidefs-local-filesystem",
      "events": [
        {"sequence": 1, "operation": "create", "path": "/dir/source", "result": "ok", "source": "test"},
        {"sequence": 2, "operation": "write", "path": "/dir/source", "result": "ok", "source": "test"},
        {"sequence": 3, "operation": "fsync", "path": "/dir/source", "result": "ok", "source": "test"},
        {"sequence": 4, "operation": "rename", "path": "/dir/dest", "result": "ok", "source": "child"},
        {"sequence": 5, "operation": "fsync", "path": "/dir/dest", "result": "ok", "source": "child"},
        {"sequence": 6, "operation": "read", "path": "/dir/dest", "result": "ok", "source": "child"},
        {"sequence": 7, "operation": "crash", "path": null, "result": "exit-99", "source": "child"},
        {"sequence": 8, "operation": "recover", "path": null, "result": "ok", "source": "test"},
        {"sequence": 9, "operation": "read_recovered", "path": "/dir/dest", "result": "ok", "source": "test"}
      ]
    }"#;

    #[test]
    fn validates_runtime_crash_artifact() {
        let summary = validate_local_vfs_runtime_crash_artifact_json(VALID).expect("valid");

        assert_eq!(summary.event_count, 7);
        assert_eq!(summary.dependency_count, 3);
        assert_eq!(summary.recovered_digest, "blake3:v1");
    }

    #[test]
    fn validates_mounted_runtime_environment_refusal() {
        let summary = validate_local_vfs_runtime_crash_artifact_json(VALID_ENVIRONMENT_REFUSAL)
            .expect("valid environment refusal");

        assert_eq!(summary.event_count, 0);
        assert_eq!(summary.dependency_count, 0);
        assert_eq!(summary.recovered_digest, "environment-refusal");
    }

    #[test]
    fn validates_rename_runtime_crash_artifact() {
        let summary =
            validate_local_vfs_rename_runtime_crash_artifact_json(VALID_RENAME).expect("valid");

        assert_eq!(summary.event_count, 9);
        assert_eq!(summary.dependency_count, 2);
        assert_eq!(summary.recovered_digest, "sha256:rename");
    }

    #[test]
    fn rejects_model_only_runtime_artifact() {
        let bad = VALID.replace(
            "bounded mounted FUSE runtime write/fsync/read crash/recover path",
            "model-only crash matrix",
        );
        let err = validate_local_vfs_runtime_crash_artifact_json(&bad).expect_err("invalid");

        assert!(err
            .failures()
            .iter()
            .any(|failure| failure.contains("model-only")));
    }

    #[test]
    fn rejects_rename_artifact_without_pre_crash_read() {
        let bad = VALID_RENAME.replace(
            r#""read_back_before_crash": true"#,
            r#""read_back_before_crash": false"#,
        );
        let err = validate_local_vfs_rename_runtime_crash_artifact_json(&bad).expect_err("invalid");

        assert!(err
            .failures()
            .iter()
            .any(|failure| failure.contains("read_back_before_crash")));
    }
}
