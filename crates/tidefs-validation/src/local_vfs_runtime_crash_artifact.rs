// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use serde::Deserialize;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

pub const LOCAL_VFS_WRITE_FSYNC_RUNTIME_CRASH_EVIDENCE_CLASS: &str = "runtime-crash-oracle";
pub const LOCAL_VFS_WRITE_FSYNC_RUNTIME_CRASH_CLAIM_ID: &str = "local.vfs.write_fsync_crash.v1";
pub const LOCAL_VFS_RENAME_RUNTIME_CRASH_EVIDENCE_CLASS: &str = "runtime-namespace-crash-artifact";
pub const LOCAL_VFS_RENAME_RUNTIME_CRASH_CLAIM_ID: &str = "local.vfs.rename_atomic_crash.v1";
const LOCAL_VFS_WRITE_FSYNC_RUNTIME_SCENARIO: &str = "local-vfs-write-fsync-read-crash-recover";
const LOCAL_VFS_RENAME_RUNTIME_SCENARIO: &str = "local-vfs-rename-fsync-read-crash-recover";
const LOCAL_VFS_RUNTIME_PATH: &str = "local-vfs";
const OP_FSYNC_BEFORE_FLUSH: &str = "OpFsyncBeforeFlush";
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
    crash_injection_point: String,
    crash_mode: String,
    hook_hit_count: u64,
    child_exit_code: i32,
    completed_fsync: CompletedFsyncObservation,
    interrupted_fsync: InterruptedFsyncObservation,
    recovery: RecoveryObservation,
    dependencies: Vec<RuntimeDependency>,
    non_claims: Vec<String>,
    validation_hint: String,
    events: Vec<RuntimeCrashEvent>,
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
    non_claims: Vec<String>,
    validation_hint: String,
    events: Vec<RuntimeCrashEvent>,
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
struct InterruptedFsyncObservation {
    path: String,
    payload_label: String,
    content_digest: String,
    fsync_attempted: bool,
    fsync_completed: bool,
    hook_hit: bool,
    crash_triggered: bool,
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
    validate_runtime_observations(&artifact, &mut failures);
    validate_events(&artifact.events, &mut failures);
    validate_dependencies(&artifact.dependencies, &mut failures);
    validate_non_claims(&artifact.non_claims, &mut failures);

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

fn validate_local_vfs_rename_runtime_crash_artifact(
    artifact: LocalVfsRenameRuntimeCrashArtifact,
) -> Result<LocalVfsRuntimeCrashArtifactSummary, LocalVfsRuntimeCrashArtifactError> {
    let mut failures = Vec::new();
    validate_rename_static_fields(&artifact, &mut failures);
    validate_rename_runtime_observations(&artifact, &mut failures);
    validate_rename_events(&artifact.events, &mut failures);
    validate_rename_dependencies(&artifact.dependencies, &mut failures);
    validate_non_claims(&artifact.non_claims, &mut failures);

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
    for required in ["local", "vfs", "runtime", "write", "fsync", "crash"] {
        if !scope.contains(required) {
            failures.push(format!("evidence_scope must mention `{required}`"));
        }
    }
    if scope.contains("model-only") {
        failures.push("evidence_scope must not be model-only".to_string());
    }
    if artifact.scenario != LOCAL_VFS_WRITE_FSYNC_RUNTIME_SCENARIO {
        failures.push(format!(
            "scenario must be `{LOCAL_VFS_WRITE_FSYNC_RUNTIME_SCENARIO}`, found `{}`",
            artifact.scenario
        ));
    }
    if artifact.runtime_path != LOCAL_VFS_RUNTIME_PATH {
        failures.push(format!(
            "runtime_path must be `{LOCAL_VFS_RUNTIME_PATH}`, found `{}`",
            artifact.runtime_path
        ));
    }
    if artifact.crash_injection_point != OP_FSYNC_BEFORE_FLUSH {
        failures.push(format!(
            "crash_injection_point must be `{OP_FSYNC_BEFORE_FLUSH}`, found `{}`",
            artifact.crash_injection_point
        ));
    }
    if artifact.crash_mode != POWER_LOSS_CRASH_MODE {
        failures.push(format!(
            "crash_mode must be `{POWER_LOSS_CRASH_MODE}`, found `{}`",
            artifact.crash_mode
        ));
    }
    if artifact.hook_hit_count == 0 {
        failures.push("hook_hit_count must be nonzero".to_string());
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

fn validate_runtime_observations(
    artifact: &LocalVfsRuntimeCrashArtifact,
    failures: &mut Vec<String>,
) {
    if artifact.completed_fsync.path != artifact.recovery.path
        || artifact.interrupted_fsync.path != artifact.recovery.path
    {
        failures.push(
            "completed_fsync, interrupted_fsync, and recovery must name the same path".to_string(),
        );
    }
    if !artifact.completed_fsync.fsync_completed {
        failures.push("completed_fsync.fsync_completed must be true".to_string());
    }
    if !artifact.completed_fsync.read_back_before_crash {
        failures.push("completed_fsync.read_back_before_crash must be true".to_string());
    }
    if !artifact.interrupted_fsync.fsync_attempted {
        failures.push("interrupted_fsync.fsync_attempted must be true".to_string());
    }
    if artifact.interrupted_fsync.fsync_completed {
        failures.push("interrupted_fsync.fsync_completed must be false".to_string());
    }
    if !artifact.interrupted_fsync.hook_hit || !artifact.interrupted_fsync.crash_triggered {
        failures
            .push("interrupted_fsync must record the fsync hook hit and crash trigger".to_string());
    }
    if !artifact.recovery.reopen_succeeded || !artifact.recovery.read_after_recovery_succeeded {
        failures.push("recovery must reopen and read the target path successfully".to_string());
    }
    if artifact.recovery.recovered_content_digest != artifact.completed_fsync.content_digest {
        failures.push("recovery digest must match the last completed fsync digest".to_string());
    }
    if artifact.interrupted_fsync.content_digest == artifact.completed_fsync.content_digest {
        failures.push(
            "interrupted fsync payload digest must differ from the completed fsync digest"
                .to_string(),
        );
    }
    if artifact.completed_fsync.payload_label.trim().is_empty()
        || artifact.interrupted_fsync.payload_label.trim().is_empty()
        || artifact.completed_fsync.content_digest.trim().is_empty()
        || artifact.interrupted_fsync.content_digest.trim().is_empty()
        || artifact.recovery.recovered_content_digest.trim().is_empty()
    {
        failures.push("payload labels and digests must not be empty".to_string());
    }
    if artifact.recovery.classification != "last-completed-fsync-survived" {
        failures
            .push("recovery.classification must be `last-completed-fsync-survived`".to_string());
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

fn validate_non_claims(non_claims: &[String], failures: &mut Vec<String>) {
    let text = non_claims.join("\n").to_ascii_lowercase();
    if !text.contains("production crash safety") {
        failures.push("non_claims must exclude production crash safety".to_string());
    }
    if !text.contains("model") {
        failures.push("non_claims must preserve the model/runtime boundary".to_string());
    }
    if !text.contains("queue-depth") {
        failures.push("non_claims must exclude queue-depth runtime evidence".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{
      "report_version": 1,
      "generated_by": "unit-test",
      "claim_ids": ["local.vfs.write_fsync_crash.v1"],
      "evidence_class": "runtime-crash-oracle",
      "evidence_scope": "local VFS runtime write/fsync/read crash/recover",
      "scenario": "local-vfs-write-fsync-read-crash-recover",
      "runtime_path": "local-vfs",
      "crash_injection_point": "OpFsyncBeforeFlush",
      "crash_mode": "PowerLoss",
      "hook_hit_count": 1,
      "child_exit_code": 99,
      "completed_fsync": {
        "path": "/oracle.txt",
        "payload_label": "v1",
        "content_digest": "sha256:v1",
        "fsync_completed": true,
        "read_back_before_crash": true
      },
      "interrupted_fsync": {
        "path": "/oracle.txt",
        "payload_label": "v2",
        "content_digest": "sha256:v2",
        "fsync_attempted": true,
        "fsync_completed": false,
        "hook_hit": true,
        "crash_triggered": true
      },
      "recovery": {
        "reopen_succeeded": true,
        "read_after_recovery_succeeded": true,
        "path": "/oracle.txt",
        "recovered_content_digest": "sha256:v1",
        "classification": "last-completed-fsync-survived"
      },
      "dependencies": [
        {"issue": 392, "subject": "fsync/syncfs", "status": "consumed"},
        {"issue": 443, "subject": "cache coherency", "status": "open"},
        {"issue": 445, "subject": "intent log", "status": "open"}
      ],
      "non_claims": [
        "This does not validate production crash safety.",
        "This is not model-only evidence.",
        "This does not provide queue-depth runtime evidence."
      ],
      "validation_hint": "cargo test -p tidefs-local-filesystem",
      "events": [
        {"sequence": 1, "operation": "write", "path": "/oracle.txt", "result": "ok", "source": "test"},
        {"sequence": 2, "operation": "fsync", "path": "/oracle.txt", "result": "ok", "source": "test"},
        {"sequence": 3, "operation": "read", "path": "/oracle.txt", "result": "ok", "source": "test"},
        {"sequence": 4, "operation": "write", "path": "/oracle.txt", "result": "ok", "source": "child"},
        {"sequence": 5, "operation": "fsync", "path": "/oracle.txt", "result": "interrupted", "source": "child"},
        {"sequence": 6, "operation": "crash", "path": null, "result": "exit-99", "source": "hook"},
        {"sequence": 7, "operation": "recover", "path": null, "result": "ok", "source": "open"},
        {"sequence": 8, "operation": "read_recovered", "path": "/oracle.txt", "result": "ok", "source": "test"}
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
        "This does not validate production crash safety.",
        "This is not model-only evidence.",
        "This does not provide queue-depth or no-hidden-queue evidence."
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

        assert_eq!(summary.event_count, 8);
        assert_eq!(summary.dependency_count, 3);
        assert_eq!(summary.recovered_digest, "sha256:v1");
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
            "local VFS runtime write/fsync/read crash/recover",
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
